//! Socket-native herdr JSON-RPC client.
//!
//! One persistent [`Stream`] (paired with a [`BufReader`] over a cloned
//! fd/handle) speaks herdr's newline-delimited JSON-RPC:
//!   request : `{"id":"<unique>","method":"<name>","params":{...}}\n`
//!   success : `{"id":..,"result":{"type":"<snake>",...}}`
//!   failure : `{"id":..,"error":{"code":..,"message":..}}`
//! Any non-`error` envelope is treated as success (mutations return
//! `{"type":"ok"}`). Method + param field names are verified against the running
//! host's own contract — `herdr api schema` prints it, so it is the authority for
//! whichever herdr is installed rather than a snapshot of one release's source.
//! The definitions this file mirrors are `PaneReportAgentParams`,
//! `PaneReleaseAgentParams`, `PaneReportMetadataParams`,
//! `WorkspaceReportMetadataParams`, and `NotificationShowParams`; last checked
//! against herdr 0.8.0 (protocol 19), unchanged since 0.7.5. This plugin only
//! reads workspace/pane/worktree lists (the git status itself comes from `git`,
//! not the socket) and writes the status onto a pane or workspace; [`bin_path`]
//! still exposes the `HERDR_BIN_PATH` CLI for a degraded fallback (e.g.
//! best-effort notifications without a socket).
//!
//! The socket path is resolved `HERDR_SOCKET_PATH` → `$XDG_CONFIG_HOME/herdr` →
//! `~/.config/herdr/herdr.sock`, or `%APPDATA%\herdr\herdr.sock` on Windows
//! (see [`crate::config::herdr_dir`]). On Unix that path IS the AF_UNIX socket.
//! On Windows,
//! herdr serves the same protocol over a NAMED PIPE: the `herdr.sock` on disk
//! is only a `pid:nonce` marker file, and the pipe's name is the socket path
//! mapped verbatim into the pipe namespace (`\\.\pipe\C:\...\herdr.sock` —
//! observed against herdr's Windows build), which std opens as a duplex
//! [`std::fs::File`]. Same wire format either way; only [`connect_stream`]
//! differs.

use std::io::{self, BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Transport to the herdr host: the Unix socket, or Windows' named pipe.
#[cfg(unix)]
type Stream = std::os::unix::net::UnixStream;
#[cfg(windows)]
type Stream = std::fs::File;

use serde::Serialize;
use serde_json::{json, Value};

use crate::model::{SessionSnapshot, SessionSnapshotResult, WorktreeListResult};

/// Read/write timeout for a single JSON-RPC round-trip. Generous — herdr answers
/// in milliseconds; this only guards against a wedged host hanging the plugin.
/// Unix sets it on the socket; Windows enforces it with [`Watchdog`].
const IO_TIMEOUT: Duration = Duration::from_secs(15);

/// A live JSON-RPC connection to the herdr host.
pub struct Herdr {
    /// Windows' stand-in for the socket read/write timeouts (see [`Watchdog`]).
    ///
    /// Declared FIRST on purpose: fields drop in declaration order, so the
    /// watchdog is retired while `stream` is still open — never the other way
    /// round, which would leave it holding a closed handle.
    #[cfg(windows)]
    watchdog: Watchdog,
    /// Write half — requests are written here and flushed.
    stream: Stream,
    /// Read half — a `BufReader` over a cloned fd/handle so we can `read_line`
    /// while the write half stays borrowable.
    reader: BufReader<Stream>,
    /// Socket path, retained so a broken connection can be re-opened.
    path: PathBuf,
    /// Monotonic request id counter (unique per connection, and across reconnects
    /// since it is never reset).
    next_id: u64,
}

/// Open a connection to the herdr socket.
pub fn connect() -> crate::Result<Herdr> {
    Herdr::open(socket_path()?)
}

impl Herdr {
    /// Connect to `path` and wire up the read/write halves.
    fn open(path: PathBuf) -> crate::Result<Herdr> {
        let stream = connect_stream(&path)
            .map_err(|e| format!("cannot connect to herdr socket {}: {e}", path.display()))?;
        let reader = BufReader::new(stream.try_clone()?);
        Ok(Herdr {
            #[cfg(windows)]
            watchdog: Watchdog::watching(&stream),
            stream,
            reader,
            path,
            next_id: 1,
        })
    }

    /// Re-open the connection after a broken pipe, replacing both halves.
    fn reconnect(&mut self) -> crate::Result<()> {
        let stream = connect_stream(&self.path).map_err(|e| {
            format!(
                "cannot reconnect to herdr socket {}: {e}",
                self.path.display()
            )
        })?;
        self.reader = BufReader::new(stream.try_clone()?);
        #[cfg(windows)]
        self.watchdog.now_watching(&stream);
        self.stream = stream;
        Ok(())
    }

    /// Next monotonic request id (plugin-prefixed for readability in herdr logs).
    fn next_request_id(&mut self) -> String {
        let n = self.next_id;
        self.next_id += 1;
        format!("ez-corp.git-status:{n}")
    }

    /// Send `method`/`params`, read exactly one reply line, and return its
    /// `result` object (or surface `error.message` as an `Err`). Reconnects once
    /// and retries on an I/O failure (a broken pipe from a restarted server).
    fn call(&mut self, method: &str, params: &Value) -> crate::Result<Value> {
        let id = self.next_request_id();
        let line = match self.round_trip(&id, method, params) {
            Ok(line) => line,
            Err(_) => {
                // A dropped connection surfaces as a write EPIPE or a read EOF.
                // Re-open once and retry before giving up.
                self.reconnect()?;
                self.round_trip(&id, method, params)?
            }
        };
        parse_envelope(&line)
    }

    /// Write one framed request and read exactly one reply line back. I/O errors
    /// (including a closed connection) are returned so [`call`] can reconnect.
    fn round_trip(&mut self, id: &str, method: &str, params: &Value) -> io::Result<String> {
        // Dropped at every exit from this function, including the `?`s below.
        #[cfg(windows)]
        let _deadline = self.watchdog.arm();

        let request = frame_request(id, method, params);
        self.stream.write_all(request.as_bytes())?;
        self.stream.flush()?;

        let mut line = String::new();
        if self.reader.read_line(&mut line)? == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "herdr closed the connection",
            ));
        }
        Ok(line)
    }

    // ---- read methods -------------------------------------------------------

    /// `session.snapshot` — every workspace and every pane in one atomic read.
    ///
    /// Replaces `workspace.list` + one `pane.list` per workspace. Those were
    /// separate round trips over a session that keeps moving, so a workspace
    /// closing between them answered `workspace_not_found` and failed the whole
    /// enumeration. One call cannot tear that way, and it costs 1 round trip
    /// instead of 1 + N. Pane order within a workspace is identical to
    /// `pane.list`, which is what keeps "the first pane's cwd wins" meaningful.
    pub fn session_snapshot(&mut self) -> crate::Result<SessionSnapshot> {
        let result = self.call("session.snapshot", &json!({}))?;
        Ok(serde_json::from_value::<SessionSnapshotResult>(result)?.snapshot)
    }

    /// `worktree.list` — errors when `workspace_id` is not a git repo. That error
    /// is returned as an ordinary (recoverable) `Err`; the caller folds it into
    /// "this workspace isn't a repo — leave it standalone".
    pub fn worktree_list(&mut self, workspace_id: &str) -> crate::Result<WorktreeListResult> {
        let result = self.call("worktree.list", &json!({ "workspace_id": workspace_id }))?;
        Ok(serde_json::from_value::<WorktreeListResult>(result)?)
    }

    // ---- mutation methods ---------------------------------------------------

    /// `pane.report_agent` — claim a pseudo-agent row (agents-panel mode).
    ///
    /// herdr 0.7.5 dropped the `custom_status` field from this call; the status
    /// text now rides a named metadata token (see [`Self::report_metadata_status`]),
    /// so this only claims the agent identity + state. The caller pushes the token
    /// separately onto the same pane.
    pub fn report_agent(
        &mut self,
        pane_id: &str,
        source: &str,
        agent: &str,
        state: &str,
    ) -> crate::Result<()> {
        self.call(
            "pane.report_agent",
            &json!({
                "pane_id": pane_id,
                "source": source,
                "agent": agent,
                "state": state,
            }),
        )?;
        Ok(())
    }

    /// `pane.release_agent` — drop a previously reported pseudo-agent.
    pub fn release_agent(&mut self, pane_id: &str, source: &str, agent: &str) -> crate::Result<()> {
        self.call(
            "pane.release_agent",
            &json!({ "pane_id": pane_id, "source": source, "agent": agent }),
        )?;
        Ok(())
    }

    /// `pane.report_metadata` — set a TTL'd named `token` to `value` on a pane.
    ///
    /// herdr 0.7.5 replaced the single `custom_status` field with a `tokens` map
    /// (`{name: value|null}`); the sidebar renders it wherever the configured
    /// `[sidebar.spaces]` / `[sidebar.agents]` rows reference `$<token>`. The TTL
    /// self-clears the value if the daemon dies.
    pub fn report_metadata_status(
        &mut self,
        pane_id: &str,
        source: &str,
        token: &str,
        value: &str,
        ttl_ms: u64,
    ) -> crate::Result<()> {
        self.call(
            "pane.report_metadata",
            &json!({
                "pane_id": pane_id,
                "source": source,
                "tokens": { token: value },
                "ttl_ms": ttl_ms,
            }),
        )?;
        Ok(())
    }

    /// `pane.report_metadata` clearing a named `token` (sets it to `null`).
    pub fn clear_metadata_status(
        &mut self,
        pane_id: &str,
        source: &str,
        token: &str,
    ) -> crate::Result<()> {
        self.call(
            "pane.report_metadata",
            &json!({
                "pane_id": pane_id,
                "source": source,
                "tokens": { token: Value::Null },
            }),
        )?;
        Ok(())
    }

    /// `workspace.report_metadata` — set a TTL'd named `token` on a WORKSPACE.
    ///
    /// The **spaces card** (`[ui.sidebar.spaces]`, `$<token>`) renders
    /// *workspace* tokens; a pane token (see [`Self::report_metadata_status`])
    /// only reaches the agents panel. So sidebar mode reports at the workspace
    /// level. The TTL self-clears the value if the daemon dies.
    pub fn workspace_report_metadata(
        &mut self,
        workspace_id: &str,
        source: &str,
        token: &str,
        value: &str,
        ttl_ms: u64,
    ) -> crate::Result<()> {
        self.call(
            "workspace.report_metadata",
            &json!({
                "workspace_id": workspace_id,
                "source": source,
                "tokens": { token: value },
                "ttl_ms": ttl_ms,
            }),
        )?;
        Ok(())
    }

    /// `workspace.report_metadata` clearing a named workspace `token`.
    pub fn workspace_clear_metadata(
        &mut self,
        workspace_id: &str,
        source: &str,
        token: &str,
    ) -> crate::Result<()> {
        self.call(
            "workspace.report_metadata",
            &json!({
                "workspace_id": workspace_id,
                "source": source,
                "tokens": { token: Value::Null },
            }),
        )?;
        Ok(())
    }

    /// `notification.show` — best-effort toast.
    pub fn notification_show(&mut self, title: &str, body: &str) -> crate::Result<()> {
        self.call(
            "notification.show",
            &json!({ "title": title, "body": body }),
        )?;
        Ok(())
    }
}

/// Resolve the herdr socket path (`HERDR_SOCKET_PATH` → XDG → `~/.config`).
pub fn socket_path() -> crate::Result<PathBuf> {
    Ok(socket_path_from(
        crate::config::non_empty_env("HERDR_SOCKET_PATH").as_deref(),
        &crate::config::herdr_dir(),
    ))
}

/// The herdr CLI binary (`HERDR_BIN_PATH`, else `herdr`) for the fallback path.
///
/// Deliberately retained but not yet wired: every method currently goes over the
/// socket, so this degraded CLI path has no caller. Kept as the documented
/// escape hatch for a socket-unavailable fallback (see the module docs).
#[allow(dead_code)]
pub fn bin_path() -> String {
    crate::config::non_empty_env("HERDR_BIN_PATH").unwrap_or_else(|| "herdr".to_string())
}

// ---- pure helpers (unit-tested) ---------------------------------------------

/// Serialize a request into one newline-terminated JSON line.
///
/// A dedicated struct fixes field order (`id`, `method`, `params`) independent of
/// serde_json's map feature, so framing is deterministic.
fn frame_request(id: &str, method: &str, params: &Value) -> String {
    #[derive(Serialize)]
    struct Wire<'a> {
        id: &'a str,
        method: &'a str,
        params: &'a Value,
    }
    let mut line = serde_json::to_string(&Wire { id, method, params })
        .expect("request serialization is infallible");
    line.push('\n');
    line
}

/// Parse one response line: `error` (non-null) → `Err(message)`, otherwise the
/// `result` object (or `{}` when a non-error envelope omits it).
fn parse_envelope(line: &str) -> crate::Result<Value> {
    let envelope: Value =
        serde_json::from_str(line.trim()).map_err(|e| format!("invalid herdr response: {e}"))?;
    if let Some(error) = envelope.get("error") {
        if !error.is_null() {
            let message = error
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("herdr error");
            return Err(message.into());
        }
    }
    Ok(envelope.get("result").cloned().unwrap_or_else(|| json!({})))
}

/// Socket path from an optional `HERDR_SOCKET_PATH` override and herdr's own
/// directory: the override wins, else `<herdr_dir>/herdr.sock`.
fn socket_path_from(explicit: Option<&str>, herdr_dir: &Path) -> PathBuf {
    match explicit {
        Some(path) => PathBuf::from(path),
        None => herdr_dir.join("herdr.sock"),
    }
}

/// Connect the Unix socket at `path` and apply the round-trip timeouts.
#[cfg(unix)]
fn connect_stream(path: &Path) -> io::Result<Stream> {
    let stream = Stream::connect(path)?;
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    Ok(stream)
}

/// Open herdr's Windows endpoint: the named pipe at [`pipe_name`]`(path)`,
/// read+write, giving a duplex byte stream. When every pipe instance is
/// momentarily taken the open fails with `ERROR_PIPE_BUSY`, so retry briefly
/// before giving up.
///
/// `security_qos_flags` is not optional. Opening a pipe without it leaves the
/// handle at the default impersonation level, so whatever is serving that name
/// may impersonate US — and `\\.\pipe\` is a flat namespace any local process
/// can create in, so "whatever is serving that name" is not necessarily herdr.
/// `SECURITY_IDENTIFICATION` lets the server check who we are but not act as us.
#[cfg(windows)]
fn connect_stream(path: &Path) -> io::Result<Stream> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::SECURITY_IDENTIFICATION;

    /// Win32 `ERROR_PIPE_BUSY` — all instances busy; retryable.
    const PIPE_BUSY: i32 = 231;
    let name = pipe_name(path);
    let mut attempts = 0;
    loop {
        match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .security_qos_flags(SECURITY_IDENTIFICATION)
            .open(&name)
        {
            Ok(file) => return Ok(file),
            Err(e) if e.raw_os_error() == Some(PIPE_BUSY) && attempts < 10 => {
                attempts += 1;
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            Err(e) => return Err(e),
        }
    }
}

/// Map the configured socket path into the pipe namespace exactly the way
/// herdr's Windows build does: `\\.\pipe\` + the path verbatim (backslashes,
/// drive colon and all). An explicit `HERDR_SOCKET_PATH` override that is
/// already a pipe name passes through untouched — matched case-insensitively,
/// since the pipe namespace is.
#[cfg(windows)]
fn pipe_name(path: &Path) -> std::ffi::OsString {
    const PREFIX: &str = r"\\.\pipe\";
    let raw = path.as_os_str();
    let bytes = raw.as_encoded_bytes();
    if bytes.len() >= PREFIX.len() && bytes[..PREFIX.len()].eq_ignore_ascii_case(PREFIX.as_bytes())
    {
        return raw.to_os_string();
    }
    let mut name = std::ffi::OsString::from(PREFIX);
    name.push(raw);
    name
}

/// Windows' stand-in for the Unix socket's read/write timeouts: a thread that
/// cancels a round trip still in flight after [`IO_TIMEOUT`].
///
/// A named-pipe `File` has no per-operation timeout to set, so without this a
/// wedged herdr blocks `read_line` **forever** — hanging a one-shot action, or
/// parking the daemon mid-refresh while it holds the tracked-status mutex, which
/// in turn leaves `--disable` unable to ever complete its shutdown. `CancelIoEx`
/// makes the blocked read fail instead, which [`Herdr::call`] already handles by
/// reconnecting and retrying, exactly as a Unix timeout would.
///
/// Only a genuine stall trips it: the deadline is armed for the duration of one
/// round trip and disarmed the moment it returns, and `CancelIoEx` against a
/// handle with no pending I/O is a no-op.
#[cfg(windows)]
struct Watchdog(std::sync::Arc<std::sync::Mutex<InFlight>>);

/// What the watchdog thread needs to know: which handle to cancel, and when.
///
/// Every read of `handle` — and the `CancelIoEx` it feeds — happens under this
/// mutex, which is what lets [`Watchdog::drop`] retire the handle safely: once
/// it has zeroed it, no cancel can name it again.
#[cfg(windows)]
#[derive(Default)]
struct InFlight {
    /// Raw pipe handle of the live connection, replaced on reconnect and zeroed
    /// on drop. Zero means "nothing to cancel".
    handle: isize,
    /// When the in-flight round trip must be cancelled; `None` while idle.
    deadline: Option<std::time::Instant>,
}

/// Disarms the deadline when the round trip ends, however it ends.
#[cfg(windows)]
struct Armed<'a>(&'a Watchdog);

#[cfg(windows)]
impl Drop for Armed<'_> {
    fn drop(&mut self) {
        if let Ok(mut state) = self.0 .0.lock() {
            state.deadline = None;
        }
    }
}

#[cfg(windows)]
impl Drop for Watchdog {
    /// Retire the handle *before* the connection that owns it is closed (see the
    /// field order on [`Herdr`]). Taking the lock also waits out a cancel already
    /// in progress, so the thread can never touch a closed handle.
    fn drop(&mut self) {
        if let Ok(mut state) = self.0.lock() {
            state.handle = 0;
            state.deadline = None;
        }
    }
}

#[cfg(windows)]
impl Watchdog {
    /// Start watching `stream`, spawning the thread that enforces the deadline.
    ///
    /// The thread holds only a `Weak`, so it retires on its own once the
    /// connection is dropped — short-lived `connect()`s do not leak threads.
    fn watching(stream: &Stream) -> Watchdog {
        use std::sync::{Arc, Mutex};
        let watchdog = Watchdog(Arc::new(Mutex::new(InFlight::default())));
        watchdog.now_watching(stream);

        let weak = Arc::downgrade(&watchdog.0);
        std::thread::spawn(move || {
            while let Some(shared) = weak.upgrade() {
                if let Ok(state) = shared.lock() {
                    let overdue = state
                        .deadline
                        .is_some_and(|deadline| std::time::Instant::now() >= deadline);
                    if overdue && state.handle != 0 {
                        // SAFETY: `handle` is only ever non-zero while the
                        // connection that owns it is open — `Watchdog::drop`
                        // zeroes it under this same lock beforehand. A handle
                        // with no pending I/O simply reports ERROR_NOT_FOUND.
                        unsafe {
                            windows_sys::Win32::System::IO::CancelIoEx(
                                state.handle as *mut std::ffi::c_void,
                                std::ptr::null(),
                            )
                        };
                    }
                }
                drop(shared); // do not pin the connection alive while sleeping
                std::thread::sleep(Duration::from_millis(500));
            }
        });
        watchdog
    }

    /// Point the watchdog at a freshly opened stream (initial connect/reconnect).
    fn now_watching(&self, stream: &Stream) {
        use std::os::windows::io::AsRawHandle;
        if let Ok(mut state) = self.0.lock() {
            state.handle = stream.as_raw_handle() as isize;
        }
    }

    /// Arm the deadline for one round trip; the returned guard disarms it.
    fn arm(&self) -> Armed<'_> {
        if let Ok(mut state) = self.0.lock() {
            state.deadline = Some(std::time::Instant::now() + IO_TIMEOUT);
        }
        Armed(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- request framing ----------------------------------------------------

    #[test]
    fn frames_request_as_one_json_line() {
        let line = frame_request("id-1", "worktree.list", &json!({ "workspace_id": "w1" }));
        assert!(line.ends_with('\n'));
        assert_eq!(
            line.matches('\n').count(),
            1,
            "exactly one trailing newline"
        );

        let v: Value = serde_json::from_str(line.trim()).unwrap();
        assert_eq!(v["id"], "id-1");
        assert_eq!(v["method"], "worktree.list");
        assert_eq!(v["params"]["workspace_id"], "w1");
    }

    #[test]
    fn frames_empty_params_as_object() {
        let line = frame_request("x", "session.snapshot", &json!({}));
        let v: Value = serde_json::from_str(line.trim()).unwrap();
        // params must be present and an (empty) object, not null — the server's
        // adjacently-tagged Method enum requires the `params` field.
        assert!(v["params"].is_object());
        assert!(v["params"].as_object().unwrap().is_empty());
    }

    #[test]
    fn frames_field_order_is_id_method_params() {
        let line = frame_request("7", "m", &json!({}));
        assert!(line.starts_with(r#"{"id":"7","method":"m","params":{"#));
    }

    // ---- envelope parsing ---------------------------------------------------

    #[test]
    fn parses_result_bearing_success() {
        let result = parse_envelope(
            r#"{"id":"1","result":{"type":"session_snapshot","snapshot":{"workspaces":[]}}}"#,
        )
        .unwrap();
        assert_eq!(result["type"], "session_snapshot");
        assert!(result["snapshot"]["workspaces"].is_array());
    }

    #[test]
    fn treats_ok_mutation_as_success() {
        let result = parse_envelope(r#"{"id":"1","result":{"type":"ok"}}"#).unwrap();
        assert_eq!(result["type"], "ok");
    }

    #[test]
    fn non_error_without_result_yields_empty_object() {
        let result = parse_envelope(r#"{"id":"1"}"#).unwrap();
        assert!(result.as_object().is_some_and(|m| m.is_empty()));
    }

    #[test]
    fn null_error_is_still_success() {
        let result = parse_envelope(r#"{"id":"1","error":null,"result":{"type":"ok"}}"#).unwrap();
        assert_eq!(result["type"], "ok");
    }

    #[test]
    fn surfaces_error_message() {
        let err = parse_envelope(
            r#"{"id":"1","error":{"code":"not_a_repo","message":"workspace is not a git repository"}}"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("not a git repository"));
    }

    #[test]
    fn error_without_message_falls_back() {
        let err = parse_envelope(r#"{"id":"1","error":{"code":"boom"}}"#).unwrap_err();
        assert_eq!(err.to_string(), "herdr error");
    }

    #[test]
    fn rejects_malformed_json() {
        assert!(parse_envelope("not json").is_err());
    }

    // ---- socket-path resolution ---------------------------------------------

    #[cfg(windows)]
    #[test]
    fn pipe_name_maps_socket_path_into_pipe_namespace() {
        // The mapping herdr's Windows build uses: prefix verbatim, path intact.
        assert_eq!(
            pipe_name(Path::new(r"C:\Users\u\AppData\Roaming\herdr\herdr.sock")),
            std::ffi::OsString::from(r"\\.\pipe\C:\Users\u\AppData\Roaming\herdr\herdr.sock"),
        );
        // An override that is already a pipe name must not be double-prefixed,
        // whatever it is cased as — the pipe namespace is case-insensitive.
        assert_eq!(
            pipe_name(Path::new(r"\\.\pipe\custom-herdr")),
            std::ffi::OsString::from(r"\\.\pipe\custom-herdr"),
        );
        assert_eq!(
            pipe_name(Path::new(r"\\.\PIPE\custom-herdr")),
            std::ffi::OsString::from(r"\\.\PIPE\custom-herdr"),
        );
    }

    #[test]
    fn socket_path_prefers_explicit_override() {
        let herdr_dir = Path::new("/home/u/.config/herdr");
        assert_eq!(
            socket_path_from(Some("/run/herdr/herdr.sock"), herdr_dir),
            PathBuf::from("/run/herdr/herdr.sock"),
        );
    }

    #[test]
    fn socket_path_falls_back_to_the_herdr_dir() {
        let herdr_dir = Path::new("/home/u/.config/herdr");
        assert_eq!(
            socket_path_from(None, herdr_dir),
            PathBuf::from("/home/u/.config/herdr/herdr.sock"),
        );
    }
}
