//! Sidebar status updater daemon and its enable/disable/toggle controls.
//!
//! The daemon refreshes each space's git status on a cadence, surfacing it either
//! as a "git" pseudo-agent (agents-panel mode) or as TTL'd display-only metadata
//! (sidebar mode). A pid file under the state dir enforces a single instance;
//! statuses self-clear via their TTL if the daemon dies. A fully clean repo
//! (nothing to commit, push, or pull) reports `✓` unless `clean_checkmark =
//! false`; a space with an empty status (non-repo, or clean-but-diverged) has
//! any previous status actively cleared so no stale row lingers. `enable` /
//! `disable` / `toggle` spawn or stop that daemon and sweep leftover statuses,
//! and `restore` (herdr's `[[startup]]` hook) brings it back after a herdr or
//! machine restart when an `enabled` marker alongside the pid file says it was
//! wanted. The stop request travels as SIGTERM on Unix and as a stop-marker
//! file the daemon polls on Windows, which has no signal to deliver.

use std::collections::{HashMap, HashSet};
#[cfg(unix)]
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

#[cfg(unix)]
use signal_hook::consts::{SIGINT, SIGTERM};
#[cfg(unix)]
use signal_hook::iterator::Signals;

use crate::collect::{self, PSEUDO_AGENT};
use crate::config::{self, Config, Mode};
use crate::git;
use crate::herdr::{self, Herdr};
use crate::model::Space;

/// Named metadata tokens the updater pushes, one per [`git::Severity`], so herdr
/// can colour each independently via its per-token sidebar style — green clean,
/// yellow dirty, red conflict. herdr renders a custom token's value as flat text
/// (no ANSI, no content-based colour), so severity has to live in the token
/// *name*: exactly one is set per space at a time and the other two are cleared.
/// Reference them in herdr's `config.toml` as `$git_clean` / `$git_dirty` /
/// `$git_conflict`.
pub const TOKEN_CLEAN: &str = "git_clean";
pub const TOKEN_DIRTY: &str = "git_dirty";
pub const TOKEN_CONFLICT: &str = "git_conflict";
/// Every status token name, for clearing the inactive ones (and sweeping on
/// shutdown/disable without needing to know which was active).
pub const STATUS_TOKENS: [&str; 3] = [TOKEN_CLEAN, TOKEN_DIRTY, TOKEN_CONFLICT];

/// Largest `ttl_ms` herdr accepts on `pane.report_metadata` /
/// `workspace.report_metadata` (24h — `ttl_ms.maximum` in `herdr api schema`).
/// Anything above it is rejected with `invalid_metadata_ttl`.
const MAX_TTL_MS: u64 = 86_400_000;

// The config bound and this cap live in different modules, so nothing stops a
// later edit from raising one and silently reintroducing the rejected-push bug.
// Tie them together at compile time: the longest cadence a user can configure
// must still produce a TTL herdr will accept.
const _: () = assert!(config::MAX_INTERVAL_SECONDS.saturating_mul(3_000) <= MAX_TTL_MS);

/// TTL for one refresh: three cycles, so a status rides out a missed refresh but
/// still self-clears shortly after the daemon dies.
///
/// [`config::MAX_INTERVAL_SECONDS`] already bounds the cadence so this cannot
/// exceed [`MAX_TTL_MS`]; the saturating multiply and clamp keep that true for
/// any caller, since overflowing or overshooting would make herdr reject every
/// push with `invalid_metadata_ttl` — silently, because the daemon ignores push
/// errors, leaving the sidebar blank with nothing to point at.
fn status_ttl_ms(interval_seconds: u64) -> u64 {
    interval_seconds.saturating_mul(3_000).min(MAX_TTL_MS)
}

/// The status token a non-empty status for `g` is pushed onto, chosen by
/// [`git::severity`] so the colour matches the terminal dashboard's cell.
fn status_token_name(g: &crate::model::GitStatus) -> &'static str {
    match git::severity(g) {
        git::Severity::Conflict => TOKEN_CONFLICT,
        git::Severity::Dirty => TOKEN_DIRTY,
        git::Severity::Clean => TOKEN_CLEAN,
    }
}

/// Panes/workspaces we have pushed status onto this run, so shutdown can clear
/// them. The stored value is the currently-set status token, so a severity flip
/// (e.g. dirty → conflict) clears the previous token before setting the new one.
#[derive(Debug, Default)]
pub struct Tracked {
    /// Panes carrying our pseudo-agent (released, not TTL'd).
    pub pseudo: HashSet<String>,
    /// Pane id → its active TTL'd status token (agents-panel mode).
    pub metadata: HashMap<String, &'static str>,
    /// Workspace id → its active TTL'd status token (sidebar mode → the spaces
    /// card, which renders workspace tokens rather than pane tokens).
    pub workspaces: HashMap<String, &'static str>,
}

/// PID of a live updater daemon, or `None` (missing pid file / dead process /
/// a pid that no longer belongs to us).
///
/// Reads `<state_dir>/updater.pid`, probes the process for liveness
/// ([`pid_alive`]), and then confirms the pid really is one of our processes.
/// That last check matters: the state dir outlives reboots, so an unclean
/// shutdown can leave a pid file pointing at a pid the kernel later recycled
/// for something else — and without it `--enable` would no-op forever against
/// that impostor, leaving the sidebar permanently blank.
pub fn daemon_pid() -> Option<u32> {
    let text = std::fs::read_to_string(config::pid_file()).ok()?;
    let pid: i32 = text.trim().parse().ok()?;
    if pid <= 0 {
        return None;
    }
    if !pid_alive(pid) {
        return None;
    }
    is_our_process(pid as u32).then_some(pid as u32)
}

/// Whether a process with `pid` currently exists — a probe with no delivery or
/// side effects.
#[cfg(unix)]
fn pid_alive(pid: i32) -> bool {
    // SAFETY: `kill` with signal 0 performs no delivery, only a liveness probe.
    unsafe { libc::kill(pid, 0) == 0 }
}

/// Windows liveness probe: open the process and check it has not exited.
///
/// `OpenProcess` alone is not enough — a pid whose process just exited can stay
/// openable while anything still holds a handle — so the exit code is compared
/// against `STILL_ACTIVE` too.
#[cfg(windows)]
fn pid_alive(pid: i32) -> bool {
    use windows_sys::Win32::Foundation::{CloseHandle, STILL_ACTIVE};
    use windows_sys::Win32::System::Threading::{
        GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    };
    // SAFETY: probes a handle we open and close ourselves; no memory is shared.
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid as u32);
        if handle.is_null() {
            return false;
        }
        let mut code: u32 = 0;
        let alive = GetExitCodeProcess(handle, &mut code) != 0 && code == STILL_ACTIVE as u32;
        CloseHandle(handle);
        alive
    }
}

/// `--daemon`: run the updater loop until asked to stop, then clear and exit.
///
/// Single-instance via the pid file; a watcher thread performs the shutdown
/// (clear tracked statuses, unlink pid, `exit(0)`) over its own socket
/// connection so it need not wait on the main loop's sleep. The stop request it
/// watches for is SIGINT/SIGTERM on Unix and the [`config::stop_flag`] marker
/// file on Windows. The loop shuts down after five consecutive failures (herdr
/// server likely gone).
pub fn run_daemon() -> crate::Result<()> {
    if daemon_pid().is_some() {
        return Ok(()); // another updater is already live
    }
    std::fs::create_dir_all(config::state_dir())?;
    std::fs::write(config::pid_file(), format!("{}\n", std::process::id()))?;

    let config = config::load_config();

    let mut client = match herdr::connect() {
        Ok(client) => client,
        Err(err) => {
            // Nothing to run without a host connection — don't leave a pid file
            // pointing at a process that is about to exit.
            let _ = std::fs::remove_file(config::pid_file());
            return Err(err);
        }
    };

    let stopping = Arc::new(AtomicBool::new(false));
    let tracked = Arc::new(Mutex::new(Tracked::default()));

    // Watcher thread: on the first stop request, win the shutdown race and clear
    // everything via a fresh connection, then exit. The main loop must not
    // re-report after this runs, so it parks once it observes `stopping`.
    #[cfg(unix)]
    {
        let mut signals = Signals::new([SIGINT, SIGTERM])?;
        let stopping = Arc::clone(&stopping);
        let tracked = Arc::clone(&tracked);
        thread::spawn(move || {
            if signals.forever().next().is_some() && !stopping.swap(true, Ordering::SeqCst) {
                shutdown(herdr::connect().ok().as_mut(), &tracked);
            }
        });
    }
    // Windows has no signal to wait on: `--disable` drops a stop-marker file in
    // the state dir instead, and this watcher polls for it once a second — same
    // shutdown, different delivery. The marker is consumed before shutting down
    // so a later daemon does not trip over it.
    #[cfg(windows)]
    {
        let stopping = Arc::clone(&stopping);
        let tracked = Arc::clone(&tracked);
        thread::spawn(move || loop {
            if config::stop_flag().exists() {
                let _ = std::fs::remove_file(config::stop_flag());
                if !stopping.swap(true, Ordering::SeqCst) {
                    shutdown(herdr::connect().ok().as_mut(), &tracked);
                }
            }
            thread::sleep(Duration::from_secs(1));
        });
    }

    let interval = Duration::from_secs(config.interval_seconds);
    let mut failures: u32 = 0;
    loop {
        match collect::snapshot(&mut client) {
            Ok(spaces) => {
                if stopping.load(Ordering::SeqCst) {
                    park(); // shutdown ran during the sample — do not re-report
                }
                {
                    let mut guard = tracked.lock().expect("tracked mutex poisoned");
                    push_statuses(&mut client, &spaces, &config, &mut guard);
                }
                failures = 0;
                thread::sleep(interval);
            }
            Err(_) => {
                failures += 1;
                if failures >= 5 && !stopping.swap(true, Ordering::SeqCst) {
                    shutdown(Some(&mut client), &tracked); // herdr server likely gone
                }
                thread::sleep(Duration::from_secs(1));
            }
        }
        if stopping.load(Ordering::SeqCst) {
            park();
        }
    }
}

/// `--enable`: record that the updater is wanted and spawn a detached `--daemon`
/// process (spawn is a no-op if one is already running).
pub fn enable_updater() -> crate::Result<()> {
    // Record the intent first, so the `[[startup]]` hook restores the updater
    // after a restart even if the spawn below fails.
    set_enabled(&config::enabled_flag(), true);

    if daemon_pid().is_some() {
        notify("git status updater already enabled");
        return Ok(());
    }
    spawn_daemon()?;
    notify("git status updater enabled");
    Ok(())
}

/// `--restore`: herdr's `[[startup]]` hook — bring the updater back after a herdr
/// or machine restart, but only if it was enabled when herdr went away.
///
/// Silent by design: a restart is not a user action, so it raises no toast. Both
/// gates are no-ops rather than errors — an updater that was never enabled stays
/// off, and a live one (herdr re-runs startup hooks on every live handoff too) is
/// left alone.
pub fn restore_updater() -> crate::Result<()> {
    if !enabled_flag_set(&config::enabled_flag()) || daemon_pid().is_some() {
        return Ok(());
    }
    spawn_daemon()
}

/// `--disable`: clear the wanted flag, signal the daemon, and sweep any leftover
/// statuses.
pub fn disable_updater() -> crate::Result<()> {
    // Clear the intent so the `[[startup]]` hook does not resurrect the updater
    // on the next herdr restart.
    set_enabled(&config::enabled_flag(), false);

    if let Some(pid) = daemon_pid() {
        // The daemon clears its own statuses on shutdown; best-effort.
        request_daemon_stop(pid);
        await_daemon_exit();
    }

    // Belt and braces: sweep every current pane in case the daemon died — release
    // pseudo-agents (no TTL) and clear metadata statuses. If herdr is
    // unavailable, metadata TTLs expire the statuses anyway.
    if let Ok(mut client) = herdr::connect() {
        if let Ok(spaces) = collect::collect_spaces(&mut client) {
            let mut sweep = Tracked::default();
            for sp in &spaces {
                sweep.pseudo.extend(sp.pseudo_panes.iter().cloned());
                // The stored token is a don't-care here: clear_all sweeps every
                // STATUS_TOKENS name per id, so a dead daemon's stale token of
                // any severity is cleared regardless of which we record.
                for pane in sp.agent_panes.iter().chain(&sp.spare_panes) {
                    sweep.metadata.insert(pane.clone(), TOKEN_DIRTY);
                }
                sweep.workspaces.insert(sp.id.clone(), TOKEN_DIRTY);
            }
            clear_all(&mut client, &sweep);
        }
    }

    notify("git status updater disabled");
    Ok(())
}

/// `--toggle`: disable if a daemon is live, else enable.
pub fn toggle_updater() -> crate::Result<()> {
    if daemon_pid().is_some() {
        disable_updater()
    } else {
        enable_updater()
    }
}

/// The status string pushed for a space: [`git::status_token`] — the dirty
/// token, or `✓` for a fully clean repo — unless the user opted out via
/// `clean_checkmark = false`, which restores the dirty-token-only behaviour.
fn space_status(sp: &Space, config: &Config) -> String {
    if config.clean_checkmark {
        git::status_token(&sp.git, &config.icons)
    } else {
        git::token(&sp.git, &config.icons)
    }
}

/// Push each space's git status onto a pane, mode-dependent, recording the
/// touched panes in `tracked`.
///
/// A space with an empty status — non-repo, clean-but-diverged, or any clean
/// tree when `clean_checkmark = false` — has its row withdrawn: in sidebar mode
/// any status we previously set is cleared; in agents-panel mode the
/// pseudo-agent is released. Everything else reports its status — the dirty
/// token, or `✓` for a fully clean repo.
///
/// The two modes are strictly separate about WHERE they write: agents-panel mode
/// only ever claims a spare pane as a "git" pseudo-agent and never writes
/// spaces-card metadata (a space with no spare pane simply shows nothing, so it
/// can't collide with a status-row plugin like space-usage); sidebar mode writes
/// TTL'd metadata on the first spare (else agent) pane.
pub fn push_statuses(client: &mut Herdr, spaces: &[Space], config: &Config, tracked: &mut Tracked) {
    let source = config::plugin_id();
    let ttl_ms = status_ttl_ms(config.interval_seconds);

    for sp in spaces {
        let status = space_status(sp, config);

        if config.mode == Mode::AgentsPanel {
            // Drop stale claims from earlier runs so a space keeps one entry.
            for extra in sp.pseudo_panes.iter().skip(1) {
                release_pseudo(client, extra, &source, tracked);
            }
            // agents-panel mode ONLY claims a spare pane as a "git" pseudo-agent;
            // it must NEVER write spaces-card metadata. A space with no spare
            // (agent-only) pane therefore surfaces nothing here — otherwise the
            // fallback would write onto an agent pane and fight the space-usage
            // plugin for the single status row, and the two would flip-flop every
            // refresh. So this branch always ends the iteration; the metadata
            // block below is sidebar-mode only.
            if let Some(pane) = sp.pseudo_panes.first().or_else(|| sp.spare_panes.first()) {
                if status.is_empty() {
                    release_pseudo(client, pane, &source, tracked); // clean → no entry
                    if let Some(prev) = tracked.metadata.remove(pane) {
                        let _ = client.clear_metadata_status(pane, &source, prev);
                    }
                } else if client
                    .report_agent(pane, &source, PSEUDO_AGENT, "idle")
                    .is_ok()
                {
                    tracked.pseudo.insert(pane.clone());
                    // 0.7.5: report_agent only claims the entry; the status text
                    // rides a severity-named token (`$git_clean` / `$git_dirty` /
                    // `$git_conflict`) so herdr can colour it. Named tokens are
                    // independent, so this never collides with the space-usage
                    // plugin's `usage` token.
                    let token = status_token_name(&sp.git);
                    clear_stale_pane_token(client, pane, &source, token, tracked);
                    if client
                        .report_metadata_status(pane, &source, token, &status, ttl_ms)
                        .is_ok()
                    {
                        tracked.metadata.insert(pane.clone(), token);
                    }
                }
                // A report_agent failure means the pane just closed; do nothing
                // this cycle (the next refresh re-evaluates) rather than falling
                // back to metadata on an agent pane.
            }
            continue;
        }

        // sidebar mode: release pseudo-agents left over from agents-panel mode.
        for pane_id in &sp.pseudo_panes {
            release_pseudo(client, pane_id, &source, tracked);
        }

        // 0.7.5: the spaces card renders WORKSPACE tokens (`[ui.sidebar.spaces]`
        // `$git_clean` / `$git_dirty` / `$git_conflict`), not pane tokens — so
        // report at the workspace level.
        if status.is_empty() {
            // clean → clear a token we previously set (idempotent; skip if we
            // never set one, so always-clean spaces cost no extra calls).
            if let Some(prev) = tracked.workspaces.remove(&sp.id) {
                let _ = client.workspace_clear_metadata(&sp.id, &source, prev);
            }
        } else {
            let token = status_token_name(&sp.git);
            clear_stale_workspace_token(client, &sp.id, &source, token, tracked);
            if client
                .workspace_report_metadata(&sp.id, &source, token, &status, ttl_ms)
                .is_ok()
            {
                tracked.workspaces.insert(sp.id.clone(), token);
            }
        }
    }
}

/// Release every pseudo-agent and clear every status token in `tracked`.
///
/// Each tracked pane/workspace gets ALL [`STATUS_TOKENS`] cleared, not just the
/// one recorded as active — cheap, idempotent, and robust to a severity that
/// flipped right before shutdown or a stale token left by a crashed prior run.
pub fn clear_all(client: &mut Herdr, tracked: &Tracked) {
    let source = config::plugin_id();
    for pane_id in &tracked.pseudo {
        let _ = client.release_agent(pane_id, &source, PSEUDO_AGENT);
    }
    for pane_id in tracked.metadata.keys() {
        for token in STATUS_TOKENS {
            let _ = client.clear_metadata_status(pane_id, &source, token);
        }
    }
    for workspace_id in tracked.workspaces.keys() {
        for token in STATUS_TOKENS {
            let _ = client.workspace_clear_metadata(workspace_id, &source, token);
        }
    }
}

/// Clear a pane's previously-set status token when this cycle's severity picks a
/// different one, so a dirty → conflict flip never leaves two tokens lit.
fn clear_stale_pane_token(
    client: &mut Herdr,
    pane: &str,
    source: &str,
    token: &str,
    tracked: &mut Tracked,
) {
    if let Some(prev) = tracked.metadata.get(pane).copied() {
        if prev != token {
            let _ = client.clear_metadata_status(pane, source, prev);
        }
    }
}

/// Workspace-level counterpart of [`clear_stale_pane_token`] (sidebar mode).
fn clear_stale_workspace_token(
    client: &mut Herdr,
    workspace_id: &str,
    source: &str,
    token: &str,
    tracked: &mut Tracked,
) {
    if let Some(prev) = tracked.workspaces.get(workspace_id).copied() {
        if prev != token {
            let _ = client.workspace_clear_metadata(workspace_id, source, prev);
        }
    }
}

// ---- helpers ----------------------------------------------------------------

/// Ask a live daemon to shut down.
///
/// Unix: post SIGTERM; the daemon's signal thread runs the shutdown. Windows:
/// drop the stop-marker file its watcher thread polls (~1s latency) — there is
/// no signal to send.
#[cfg(unix)]
fn request_daemon_stop(pid: u32) {
    // SAFETY: `kill` merely posts SIGTERM to the pid; failure is ignored.
    unsafe {
        libc::kill(pid as i32, SIGTERM);
    }
}

/// Windows delivery of [`request_daemon_stop`]: the stop-marker file.
#[cfg(windows)]
fn request_daemon_stop(_pid: u32) {
    let stop = config::stop_flag();
    if let Some(dir) = stop.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let _ = std::fs::write(stop, "1\n");
}

/// Wait (briefly) for a stopping daemon to actually be gone.
///
/// [`request_daemon_stop`] only *posts* the request: the pid file lives until the
/// daemon has finished clearing its statuses and unlinked it. An `--enable` — or
/// a second `--toggle` — landing inside that window sees a live pid, reports
/// "already enabled", and spawns nothing; moments later the old daemon exits,
/// leaving the updater marked wanted but not running, and the sidebar blank until
/// the next herdr restart. Windows widens the window to its watcher's ~1s poll,
/// so wait it out. Bounded: a daemon that never exits (host wedged mid-clear)
/// must not hang the disable the user asked for.
fn await_daemon_exit() {
    for _ in 0..30 {
        if daemon_pid().is_none() {
            return;
        }
        thread::sleep(Duration::from_millis(100));
    }
}

/// Re-exec ourselves as a detached `--daemon` process.
///
/// Fully detached — which is what lets the daemon outlive the short-lived
/// `--enable` / `--restore` command herdr spawned it from — with null stdio.
/// Detachment is a new session (setsid) on Unix and [`spawn_detached`]'s
/// creation flags on Windows.
fn spawn_daemon() -> crate::Result<()> {
    let exe = std::env::current_exe()?;
    let mut cmd = Command::new(exe);
    cmd.arg("--daemon")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    spawn_detached(cmd)
}

#[cfg(unix)]
fn spawn_detached(mut cmd: Command) -> crate::Result<()> {
    // SAFETY: `setsid` is async-signal-safe and the only action taken in the
    // forked child before exec; it starts a new session, detaching the daemon.
    unsafe {
        cmd.pre_exec(|| match libc::setsid() {
            -1 => Err(std::io::Error::last_os_error()),
            _ => Ok(()),
        });
    }
    cmd.spawn()?; // do not wait — the child outlives us and is reaped by init
    Ok(())
}

#[cfg(windows)]
fn spawn_detached(mut cmd: Command) -> crate::Result<()> {
    use std::os::windows::process::CommandExt;
    use windows_sys::Win32::System::Threading::{
        CREATE_BREAKAWAY_FROM_JOB, CREATE_NEW_PROCESS_GROUP, DETACHED_PROCESS,
    };

    // A stale stop marker from an earlier `--disable` must not fell the fresh
    // daemon the moment its watcher starts polling. Removed BEFORE the spawn so
    // a disable that lands after this still wins.
    let _ = std::fs::remove_file(config::stop_flag());

    // No console, own process group (a Ctrl+C aimed at the parent never reaches
    // it), and — should herdr run plugin commands inside a kill-on-close job
    // object — break away from that job so the daemon outlives the enable
    // command. Breakaway is *refused* by jobs that forbid it, so fall back to
    // plain detachment rather than failing the enable.
    let detached = DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP;
    cmd.creation_flags(detached | CREATE_BREAKAWAY_FROM_JOB)
        .spawn()
        .or_else(|_| cmd.creation_flags(detached).spawn())?;
    Ok(()) // do not wait — the child outlives us
}

/// Create (`true`) or remove (`false`) the "updater wanted" marker at `path`.
///
/// Best-effort: the marker only drives restart recovery, so a state dir we cannot
/// write must not fail the enable/disable the user actually asked for.
fn set_enabled(path: &std::path::Path, enabled: bool) {
    if !enabled {
        let _ = std::fs::remove_file(path);
        return;
    }
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let _ = std::fs::write(path, "1\n");
}

/// Whether the "updater wanted" marker at `path` exists.
fn enabled_flag_set(path: &std::path::Path) -> bool {
    path.exists()
}

/// Whether `pid` is one of *our* processes, compared via `/proc/<pid>/comm`
/// against our own.
///
/// Guards pid reuse behind a stale pid file. Anything unreadable — a vanished
/// process, or one owned by another user — reads as "not ours", which is the
/// safe answer: we then treat the updater as down and start a fresh one.
#[cfg(target_os = "linux")]
fn is_our_process(pid: u32) -> bool {
    match (
        comm_of(&format!("/proc/{pid}/comm")),
        comm_of("/proc/self/comm"),
    ) {
        (Some(theirs), Some(ours)) => theirs == ours,
        _ => false,
    }
}

/// Windows has no `/proc`, but it can answer the same question directly: compare
/// the process's image path against our own.
///
/// Worth doing rather than degrading to the liveness probe (as macOS does),
/// because Windows recycles pids aggressively and the failure is a dead end —
/// a recycled pid makes `--enable` and `--restore` no-op forever AND leaves a
/// stop marker nothing ever consumes, so the sidebar stays blank with no way out
/// short of deleting the state dir by hand. Anything unreadable — a vanished
/// process, or one owned by another user — reads as "not ours", the safe answer:
/// we treat the updater as down and start a fresh one.
#[cfg(windows)]
fn is_our_process(pid: u32) -> bool {
    match (image_path_of(pid), std::env::current_exe().ok()) {
        // Windows paths are case-insensitive, and the two APIs need not agree on
        // casing, so a case-sensitive compare would report our own daemon as an
        // impostor and start a second one.
        (Some(theirs), Some(ours)) => theirs
            .as_os_str()
            .as_encoded_bytes()
            .eq_ignore_ascii_case(ours.as_os_str().as_encoded_bytes()),
        _ => false,
    }
}

/// Full image path of `pid`, or `None` if it cannot be read.
#[cfg(windows)]
fn image_path_of(pid: u32) -> Option<std::path::PathBuf> {
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    // `QueryFullProcessImageNameW` is not bounded by MAX_PATH; size for the
    // extended limit so a deep install path cannot make us misjudge the pid.
    let mut buf = vec![0u16; 32_768];
    let mut len = buf.len() as u32;
    // SAFETY: opens, queries, and closes a handle we own; the API writes at most
    // `len` UTF-16 units into `buf` and updates `len` with what it wrote.
    let written = unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if handle.is_null() {
            return None;
        }
        let ok = QueryFullProcessImageNameW(handle, 0, buf.as_mut_ptr(), &mut len);
        CloseHandle(handle);
        (ok != 0).then_some(len as usize)?
    };
    Some(std::ffi::OsString::from_wide(&buf[..written]).into())
}

/// macOS has no `/proc` and no cheap image-path query, so the pid-reuse guard
/// degrades to the [`pid_alive`] liveness probe alone — the behaviour this plugin
/// has always had there.
#[cfg(not(any(target_os = "linux", windows)))]
fn is_our_process(_pid: u32) -> bool {
    true
}

/// Trimmed contents of a `/proc/<pid>/comm` path, or `None` if unreadable.
#[cfg(target_os = "linux")]
fn comm_of(path: &str) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|text| text.trim().to_string())
}

/// Clear tracked statuses, unlink the pid file, and `exit(0)`.
///
/// Shared by the signal thread (own connection) and the five-failure path (main
/// connection). `client` is `None` only when no socket could be opened, in which
/// case the pid file is still removed before exiting. Never returns.
fn shutdown(client: Option<&mut Herdr>, tracked: &Mutex<Tracked>) -> ! {
    if let Some(client) = client {
        if let Ok(tracked) = tracked.lock() {
            clear_all(client, &tracked);
        }
    }
    let _ = std::fs::remove_file(config::pid_file());
    std::process::exit(0);
}

/// Idle forever while the signal thread completes its shutdown and `exit(0)`s the
/// whole process; keeps the main loop from re-reporting or racing that exit.
fn park() -> ! {
    loop {
        thread::sleep(Duration::from_secs(3600));
    }
}

/// Best-effort release of our pseudo-agent on `pane_id` (a closed pane errors and
/// is ignored — nothing to release); drops it from `tracked` so shutdown won't
/// re-clear it.
fn release_pseudo(client: &mut Herdr, pane_id: &str, source: &str, tracked: &mut Tracked) {
    let _ = client.release_agent(pane_id, source, PSEUDO_AGENT);
    tracked.pseudo.remove(pane_id);
}

/// Best-effort "Git status" toast over a throwaway connection.
fn notify(body: &str) {
    if let Ok(mut client) = herdr::connect() {
        let _ = client.notification_show("Git status", body);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::GitStatus;

    fn dirty_space(id: &str, spare: &[&str]) -> Space {
        Space {
            id: id.to_string(),
            label: id.to_string(),
            spare_panes: spare.iter().map(|s| s.to_string()).collect(),
            git: GitStatus {
                is_repo: true,
                modified: 2,
                ..GitStatus::default()
            },
            ..Default::default()
        }
    }

    fn fully_clean_space(id: &str) -> Space {
        Space {
            id: id.to_string(),
            label: id.to_string(),
            git: GitStatus {
                is_repo: true,
                ..GitStatus::default()
            },
            ..Default::default()
        }
    }

    #[test]
    fn dirty_space_produces_a_token() {
        let sp = dirty_space("repo", &["pane-1"]);
        assert_eq!(space_status(&sp, &Config::default()), "~2");
    }

    #[test]
    fn status_token_name_maps_severity_to_a_coloured_token() {
        // Fully clean (the ✓) → the green clean token.
        let clean = fully_clean_space("repo");
        assert_eq!(status_token_name(&clean.git), TOKEN_CLEAN);
        // Dirty, no conflicts → the yellow dirty token.
        let dirty = dirty_space("repo", &[]);
        assert_eq!(status_token_name(&dirty.git), TOKEN_DIRTY);
        // A conflict → the red conflict token, outranking other changes.
        let conflict = Space {
            git: GitStatus {
                is_repo: true,
                staged: 1,
                conflicts: 2,
                ..GitStatus::default()
            },
            ..Default::default()
        };
        assert_eq!(status_token_name(&conflict.git), TOKEN_CONFLICT);
    }

    #[test]
    fn status_tokens_are_the_three_severity_names() {
        assert_eq!(STATUS_TOKENS, [TOKEN_CLEAN, TOKEN_DIRTY, TOKEN_CONFLICT]);
    }

    #[test]
    fn fully_clean_space_pushes_check_mark_by_default() {
        let sp = fully_clean_space("repo");
        assert_eq!(space_status(&sp, &Config::default()), git::CLEAN_MARK);
    }

    #[test]
    fn clean_checkmark_opt_out_restores_empty_status() {
        let sp = fully_clean_space("repo");
        let config = Config {
            clean_checkmark: false,
            ..Config::default()
        };
        assert!(space_status(&sp, &config).is_empty());
    }

    #[test]
    fn clean_but_diverged_space_status_is_empty() {
        // herdr's branch row owns the ↑/↓ story; the status is withdrawn, not ✓.
        let mut sp = fully_clean_space("repo");
        sp.git.ahead = 2;
        assert!(space_status(&sp, &Config::default()).is_empty());
    }

    #[test]
    fn non_repo_space_status_is_empty() {
        let sp = Space::default(); // is_repo = false
        assert!(space_status(&sp, &Config::default()).is_empty());
    }

    // ---- metadata TTL --------------------------------------------------------

    #[test]
    fn ttl_is_three_refresh_cycles() {
        assert_eq!(status_ttl_ms(Config::default().interval_seconds), 15_000);
        assert_eq!(status_ttl_ms(1), 3_000);
        assert_eq!(status_ttl_ms(60), 180_000);
    }

    #[test]
    fn ttl_is_clamped_to_the_herdr_maximum() {
        // 28_800s * 3 lands exactly on herdr's cap; anything longer must clamp
        // rather than be rejected as `invalid_metadata_ttl`.
        assert_eq!(status_ttl_ms(28_800), MAX_TTL_MS);
        assert_eq!(status_ttl_ms(28_801), MAX_TTL_MS);
        assert_eq!(status_ttl_ms(u64::MAX), MAX_TTL_MS); // saturates, never wraps
    }

    // ---- restart recovery ---------------------------------------------------

    /// Unique scratch dir under the system tmpdir, keyed by test name + pid so
    /// parallel test threads never collide.
    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "git-status-test-{name}-{}-{:?}",
            std::process::id(),
            thread::current().id(),
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch dir");
        dir
    }

    #[test]
    fn enabled_flag_round_trips_and_creates_missing_state_dir() {
        // Point at a *nested* dir that does not exist yet — enabling must create
        // it, mirroring a fresh install whose state dir herdr has not made.
        let flag = scratch("flag").join("nested").join("enabled");
        assert!(
            !enabled_flag_set(&flag),
            "absent before anything is written"
        );

        set_enabled(&flag, true);
        assert!(enabled_flag_set(&flag), "set after --enable");

        set_enabled(&flag, false);
        assert!(!enabled_flag_set(&flag), "cleared after --disable");

        // Clearing an already-absent flag is a no-op, not an error.
        set_enabled(&flag, false);
        assert!(!enabled_flag_set(&flag));
    }

    #[test]
    fn our_own_pid_is_recognised_as_ours() {
        assert!(is_our_process(std::process::id()));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn vanished_pid_is_not_ours() {
        // No `/proc/<pid>/comm` to read — the stale-pid-file case must read as
        // "not ours" so the caller starts a fresh daemon. Linux-only: without
        // `/proc` the guard degrades to the liveness probe alone.
        assert!(!is_our_process(u32::MAX));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn comm_of_unreadable_path_is_none() {
        assert_eq!(comm_of("/proc/nonexistent-pid/comm"), None);
    }
}
