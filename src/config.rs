//! Plugin config and env/state path resolution.
//!
//! - [`load_config`] parses `$HERDR_PLUGIN_CONFIG_DIR/config.toml` (flat
//!   `key = value` lines).
//! - The path helpers resolve the herdr-injected env (`HERDR_PLUGIN_*`) with the
//!   same `<tmpdir>/<id>` fallbacks the runtime uses.

use std::path::PathBuf;

/// Status-surfacing strategy (plugin `config.toml` `mode`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Stock herdr: a "git" pseudo-agent per space in the agents panel. This is
    /// the default — it works on any herdr build, no patch required.
    AgentsPanel,
    /// Opt-in for herdr builds patched with a spaces-card status row:
    /// display-only metadata rendered inside the spaces card.
    Sidebar,
}

/// Glyphs used in the compact sidebar status token.
///
/// Override any of these in `config.toml` (`icon_staged`, `icon_modified`,
/// `icon_untracked`, `icon_conflict`, `icon_clean`). Empty values are ignored
/// and keep the default.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Icons {
    /// Staged (index) changes. Default `+`.
    pub staged: String,
    /// Unstaged worktree modifications. Default `~`.
    pub modified: String,
    /// Untracked files. Default `?`.
    pub untracked: String,
    /// Conflicted / unmerged paths. Default `!`.
    pub conflict: String,
    /// Fully clean repo mark. Default `✓`.
    pub clean: String,
}

impl Default for Icons {
    fn default() -> Self {
        Self {
            staged: "+".to_string(),
            modified: "~".to_string(),
            untracked: "?".to_string(),
            conflict: "!".to_string(),
            clean: "✓".to_string(),
        }
    }
}

/// Plugin user config from `$HERDR_PLUGIN_CONFIG_DIR/config.toml`.
#[derive(Debug, Clone)]
pub struct Config {
    pub mode: Mode,
    pub interval_seconds: u64,
    /// Surface `✓` for fully clean repos (nothing to commit, push, or pull)
    /// instead of clearing the status. `false` restores the pre-1.1 behaviour
    /// where a clean space shows nothing at all.
    pub clean_checkmark: bool,
    /// Glyphs for staged / modified / untracked / conflict / clean marks.
    pub icons: Icons,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            mode: Mode::AgentsPanel,
            interval_seconds: 5,
            clean_checkmark: true,
            icons: Icons::default(),
        }
    }
}

/// Default plugin id when herdr does not inject `HERDR_PLUGIN_ID`.
const DEFAULT_PLUGIN_ID: &str = "ez-corp.git-status";

/// Upper bound on `interval_seconds` (8 hours).
///
/// The updater pushes each status with a TTL of three intervals, and herdr
/// rejects a metadata `ttl_ms` above 24h with `invalid_metadata_ttl` — so
/// 3 × this must stay inside that window, and 8h × 3 = 24h exactly. Clamping
/// the cadence rather than the TTL keeps the two in step: capping the TTL alone
/// would let it fall below the refresh interval, blinking every status out
/// between pushes.
pub const MAX_INTERVAL_SECONDS: u64 = 28_800;

/// Load the plugin's own `config.toml`, returning defaults if it is absent.
pub fn load_config() -> Config {
    match std::fs::read_to_string(config_dir().join("config.toml")) {
        Ok(text) => parse_config(&text),
        Err(_) => Config::default(), // no config file — defaults
    }
}

/// Plugin id (`HERDR_PLUGIN_ID`, else `ez-corp.git-status`).
pub fn plugin_id() -> String {
    non_empty_env("HERDR_PLUGIN_ID").unwrap_or_else(|| DEFAULT_PLUGIN_ID.to_string())
}

/// Durable state dir (`HERDR_PLUGIN_STATE_DIR`, else `<tmpdir>/<id>`).
pub fn state_dir() -> PathBuf {
    non_empty_env("HERDR_PLUGIN_STATE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::temp_dir().join(plugin_id()))
}

/// User config dir (`HERDR_PLUGIN_CONFIG_DIR`, else `<tmpdir>/<id>-config`).
pub fn config_dir() -> PathBuf {
    non_empty_env("HERDR_PLUGIN_CONFIG_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::temp_dir().join(format!("{}-config", plugin_id())))
}

/// Updater single-instance pid file (`<state_dir>/updater.pid`).
pub fn pid_file() -> PathBuf {
    state_dir().join("updater.pid")
}

/// Marker recording that the updater is *wanted* (`<state_dir>/enabled`).
///
/// The pid file says whether a daemon is live *right now*; this says whether the
/// user ever asked for one. `--restore` (the manifest `[[startup]]` hook) reads
/// it so the updater comes back after a herdr or machine restart instead of
/// silently staying off until someone re-invokes `status-enable`.
pub fn enabled_flag() -> PathBuf {
    state_dir().join("enabled")
}

/// Stop marker asking a running daemon to shut down (`<state_dir>/stop`).
///
/// Windows has no SIGTERM to post, so `--disable` writes this file instead and
/// the daemon's watcher thread polls for it (removing it) once a second.
#[cfg(windows)]
pub fn stop_flag() -> PathBuf {
    state_dir().join("stop")
}

// ---- env / path resolution --------------------------------------------------

/// Read `name` from the environment, treating unset AND empty as absent.
pub(crate) fn non_empty_env(name: &str) -> Option<String> {
    match std::env::var(name) {
        Ok(v) if !v.is_empty() => Some(v),
        _ => None,
    }
}

/// User home directory from `$HOME` — or `$USERPROFILE` on Windows, where `HOME`
/// is not a thing — or an empty path when neither is set.
fn home_dir() -> PathBuf {
    let home = std::env::var_os("HOME");
    #[cfg(windows)]
    let home = home.or_else(|| std::env::var_os("USERPROFILE"));
    home.map(PathBuf::from).unwrap_or_default()
}

/// XDG config base: `$XDG_CONFIG_HOME` if set (and non-empty), else `~/.config`.
#[cfg(not(windows))]
fn config_home() -> PathBuf {
    non_empty_env("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| home_dir().join(".config"))
}

/// herdr's own directory — where its socket (Windows: the socket *marker* whose
/// path names the pipe) lives: `<config_home>/herdr`.
#[cfg(not(windows))]
pub(crate) fn herdr_dir() -> PathBuf {
    config_home().join("herdr")
}

/// Windows counterpart: herdr keeps its socket under `%APPDATA%` (observed:
/// `C:\Users\<u>\AppData\Roaming\herdr\herdr.sock`), NOT in `~/.config`, which
/// does not exist there at all.
///
/// herdr injects `HERDR_SOCKET_PATH` for the commands it runs, so this fallback
/// only matters when the binary is invoked by hand — but resolving to a path
/// that can never exist turns that into a baffling "cannot connect" instead.
#[cfg(windows)]
pub(crate) fn herdr_dir() -> PathBuf {
    non_empty_env("APPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| home_dir().join("AppData").join("Roaming"))
        .join("herdr")
}

// ---- pure parser (hand-rolled, no `toml` crate) -----------------------------

/// Parse the plugin's flat `config.toml` text into a [`Config`], starting from
/// the documented defaults.
///
/// Recognised keys: `mode` (`agents-panel` | `sidebar`), `interval_seconds`
/// (numeric `>= 1`), `clean_checkmark` (`true` | `false`), and `icon_*`
/// (`icon_staged` / `icon_modified` / `icon_untracked` / `icon_conflict` /
/// `icon_clean`). Unknown keys are ignored.
fn parse_config(text: &str) -> Config {
    let mut cfg = Config::default();
    for line in text.split('\n') {
        if line.trim_start().starts_with('#') {
            continue;
        }
        let Some((key, value)) = parse_kv_line(line) else {
            continue;
        };
        match key {
            "mode" if value == "sidebar" => cfg.mode = Mode::Sidebar,
            "mode" if value == "agents-panel" => cfg.mode = Mode::AgentsPanel,
            "clean_checkmark" if value == "true" => cfg.clean_checkmark = true,
            "clean_checkmark" if value == "false" => cfg.clean_checkmark = false,
            // Accept any numeric >= 1; the struct stores whole seconds, so a
            // fractional value is truncated (the daemon uses it as a coarse
            // cadence). Clamped at [`MAX_INTERVAL_SECONDS`] so the derived TTL
            // cannot exceed what herdr accepts.
            "interval_seconds" => {
                if let Ok(n) = value.parse::<f64>() {
                    if n >= 1.0 {
                        cfg.interval_seconds = (n as u64).min(MAX_INTERVAL_SECONDS);
                    }
                }
            }
            "icon_staged" if !value.is_empty() => cfg.icons.staged = value.to_string(),
            "icon_modified" if !value.is_empty() => cfg.icons.modified = value.to_string(),
            "icon_untracked" if !value.is_empty() => cfg.icons.untracked = value.to_string(),
            "icon_conflict" if !value.is_empty() => cfg.icons.conflict = value.to_string(),
            "icon_clean" if !value.is_empty() => cfg.icons.clean = value.to_string(),
            _ => {}
        }
    }
    cfg
}

/// Split one flat `key = value` line into `(key, unquoted_value)`.
///
/// The key is one or more ASCII letters/underscores; the value is everything
/// after the FIRST `=` with surrounding whitespace trimmed (non-empty required)
/// and at most one leading and one trailing quote (`"` or `'`) removed. Inline
/// `#` comments are NOT stripped.
fn parse_kv_line(line: &str) -> Option<(&str, &str)> {
    let (key, value) = line.split_once('=')?;
    let key = key.trim();
    if key.is_empty() || !key.bytes().all(|b| b.is_ascii_alphabetic() || b == b'_') {
        return None;
    }
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    Some((key, strip_quotes(value)))
}

/// Remove at most one leading and one trailing quote (`"` or `'`), independently.
fn strip_quotes(s: &str) -> &str {
    let is_quote = |c: char| c == '"' || c == '\'';
    let s = s.strip_prefix(is_quote).unwrap_or(s);
    s.strip_suffix(is_quote).unwrap_or(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_empty_text_yields_documented_defaults() {
        let cfg = parse_config("");
        // agents-panel is the default: it works on stock herdr, no patch needed.
        assert_eq!(cfg.mode, Mode::AgentsPanel);
        assert_eq!(cfg.interval_seconds, 5);
        assert!(cfg.clean_checkmark);
    }

    #[test]
    fn config_clean_checkmark_only_accepts_booleans() {
        assert!(!parse_config("clean_checkmark = false").clean_checkmark);
        assert!(parse_config("clean_checkmark = true").clean_checkmark);
        assert!(parse_config("clean_checkmark = \"true\"").clean_checkmark);
        // Unknown value leaves the default (true) untouched.
        assert!(parse_config("clean_checkmark = maybe").clean_checkmark);
    }

    #[test]
    fn config_mode_only_accepts_known_values() {
        assert_eq!(parse_config("mode = sidebar").mode, Mode::Sidebar);
        assert_eq!(parse_config("mode = agents-panel").mode, Mode::AgentsPanel);
        // Unknown value leaves the default untouched.
        assert_eq!(parse_config("mode = bogus").mode, Mode::AgentsPanel);
    }

    #[test]
    fn config_quotes_are_stripped_from_values() {
        assert_eq!(
            parse_config("mode = \"agents-panel\"").mode,
            Mode::AgentsPanel
        );
        assert_eq!(
            parse_config("mode = 'agents-panel'").mode,
            Mode::AgentsPanel
        );
        // Mismatched leading/trailing quotes are stripped independently.
        assert_eq!(
            parse_config("mode = \"agents-panel'").mode,
            Mode::AgentsPanel
        );
    }

    #[test]
    fn config_interval_seconds_gates_on_ge_one() {
        assert_eq!(parse_config("interval_seconds = 12").interval_seconds, 12);
        assert_eq!(parse_config("interval_seconds = \"7\"").interval_seconds, 7);
        // Below 1, zero, non-numeric, and empty-after-quotes keep the default 5.
        assert_eq!(parse_config("interval_seconds = 0").interval_seconds, 5);
        assert_eq!(parse_config("interval_seconds = -3").interval_seconds, 5);
        assert_eq!(parse_config("interval_seconds = fast").interval_seconds, 5);
    }

    #[test]
    fn config_interval_seconds_is_capped() {
        // An absurd cadence would push the derived TTL (3 intervals) past the
        // 24h maximum herdr accepts, and every status write would be rejected.
        assert_eq!(
            parse_config("interval_seconds = 28800").interval_seconds,
            MAX_INTERVAL_SECONDS
        );
        assert_eq!(
            parse_config("interval_seconds = 999999").interval_seconds,
            MAX_INTERVAL_SECONDS
        );
    }

    #[test]
    fn config_skips_comments_and_malformed_lines() {
        let text = "\
            # mode = sidebar\n\
            not a config line\n\
            mode2 = sidebar\n\
            interval_seconds = 9\n";
        let cfg = parse_config(text);
        // The commented and digit-keyed `sidebar` lines are ignored (mode stays
        // the agents-panel default); the valid line applies.
        assert_eq!(cfg.mode, Mode::AgentsPanel);
        assert_eq!(cfg.interval_seconds, 9);
    }

    #[test]
    fn strip_quotes_matches_expected_semantics() {
        assert_eq!(strip_quotes("\"foo\""), "foo");
        assert_eq!(strip_quotes("'foo'"), "foo");
        assert_eq!(strip_quotes("\"foo"), "foo"); // leading only
        assert_eq!(strip_quotes("foo\""), "foo"); // trailing only
        assert_eq!(strip_quotes("\"foo'"), "foo"); // mismatched
        assert_eq!(strip_quotes("\""), ""); // lone quote collapses to empty
        assert_eq!(strip_quotes("bare"), "bare");
    }

    #[test]
    fn parse_kv_line_rejects_bad_keys_and_empty_values() {
        assert_eq!(parse_kv_line("mode = sidebar"), Some(("mode", "sidebar")));
        assert_eq!(parse_kv_line("  spaced  =  v  "), Some(("spaced", "v")));
        assert_eq!(parse_kv_line("mode2 = x"), None); // digit in key
        assert_eq!(parse_kv_line("a b = x"), None); // space in key
        assert_eq!(parse_kv_line("noeq"), None); // no '='
        assert_eq!(parse_kv_line("mode =   "), None); // empty value
    }

    #[test]
    fn config_icons_override_defaults() {
        let cfg = parse_config(
            "icon_staged = *\nicon_modified = M\nicon_untracked = U\nicon_conflict = X\nicon_clean = ok\n",
        );
        assert_eq!(cfg.icons.staged, "*");
        assert_eq!(cfg.icons.modified, "M");
        assert_eq!(cfg.icons.untracked, "U");
        assert_eq!(cfg.icons.conflict, "X");
        assert_eq!(cfg.icons.clean, "ok");
    }

    #[test]
    fn config_empty_icon_keeps_default() {
        let cfg = parse_config("icon_modified = \"\"");
        assert_eq!(cfg.icons.modified, "~");
    }

}
