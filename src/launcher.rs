//! Launching apps: plain or sandboxed (netns + nft + proxy bridge), with
//! process-group tracking so the UI can show/hide the running badge.

use crate::model::AppEntry;
use crate::output_log::{OutputLog, OutputLogRegistry};
use crate::proxy::AllowList;
use std::collections::HashMap;
use std::io::Read;
use std::os::unix::process::CommandExt as _;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

/// Handle for one running app instance.
pub struct RunningApp {
    pub app_id: String,
    #[allow(dead_code)] // exposed for future UI (pid display)
    pub pid: u32,
    #[allow(dead_code)] // informational
    pub sandboxed: bool,
    child: Option<Child>,
    /// host bridge socket path (sandboxed only); removed on exit
    pub bridge_path: Option<String>,
    /// rules file consumed by the bridge (sandboxed only); persists after
    /// exit — the UI rewrites it to make rule edits take effect dynamically
    #[allow(dead_code)] // read by the UI via RunningRegistry::get
    pub allow_path: Option<PathBuf>,
}

impl RunningApp {
    /// Non-blocking poll; returns true while the process is alive.
    pub fn is_alive(&mut self) -> bool {
        match self.child.as_mut() {
            Some(c) => c.try_wait().map(|s| s.is_none()).unwrap_or(true),
            None => true,
        }
    }

    /// Send SIGTERM to the app process (graceful shutdown request).
    /// Returns the pid when a signal was sent.
    pub fn terminate(&mut self) -> Option<u32> {
        let pid = self.child.as_ref()?.id();
        unsafe {
            libc::kill(pid as libc::pid_t, libc::SIGTERM);
        }
        Some(pid)
    }
}

/// Registry of running apps, shared between UI and watcher threads.
#[derive(Default)]
pub struct RunningRegistry {
    inner: Mutex<HashMap<String, Arc<Mutex<RunningApp>>>>,
}

impl RunningRegistry {
    pub fn insert(&self, running: RunningApp) -> Arc<Mutex<RunningApp>> {
        let arc = Arc::new(Mutex::new(running));
        let id = arc.lock().unwrap().app_id.clone();
        self.inner.lock().unwrap().insert(id, arc.clone());
        arc
    }

    pub fn remove(&self, app_id: &str) {
        self.inner.lock().unwrap().remove(app_id);
    }

    /// Terminate every running app (launcher shutdown): SIGTERM first, wait
    /// up to 2s for graceful exit, then SIGKILL the stragglers. Also removes
    /// each bridge socket file so bridges self-exit and relays (which watch
    /// the same file) follow.
    pub fn terminate_all(&self) {
        let mut pids: Vec<(u32, Option<String>)> = Vec::new();
        for handle in self.inner.lock().unwrap().values() {
            let mut guard = handle.lock().unwrap();
            if guard.is_alive() {
                if let Some(pid) = guard.terminate() {
                    pids.push((pid, guard.bridge_path.clone()));
                }
            } else if let Some(path) = &guard.bridge_path {
                let _ = std::fs::remove_file(path);
            }
        }
        if pids.is_empty() {
            return;
        }
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            let mut alive = 0usize;
            for handle in self.inner.lock().unwrap().values() {
                let mut guard = handle.lock().unwrap();
                if guard.is_alive() {
                    alive += 1;
                } else if let Some(path) = &guard.bridge_path {
                    let _ = std::fs::remove_file(path);
                }
            }
            if alive == 0 || std::time::Instant::now() >= deadline {
                break;
            }
            thread::sleep(std::time::Duration::from_millis(100));
        }
        // stragglers: SIGKILL
        for handle in self.inner.lock().unwrap().values() {
            let mut guard = handle.lock().unwrap();
            if guard.is_alive() {
                if let Some(child) = guard.child.as_mut() {
                    let _ = child.kill();
                }
            }
            if let Some(path) = &guard.bridge_path {
                let _ = std::fs::remove_file(path);
            }
        }
        thread::sleep(std::time::Duration::from_millis(100));
    }

    /// The running handle for an app, if any.
    #[allow(dead_code)] // used by the UI for dynamic rule updates
    pub fn get(&self, app_id: &str) -> Option<Arc<Mutex<RunningApp>>> {
        self.inner.lock().unwrap().get(app_id).cloned()
    }

    pub fn is_running(&self, app_id: &str) -> bool {
        self.inner
            .lock()
            .unwrap()
            .get(app_id)
            .map(|a| a.lock().unwrap().is_alive())
            .unwrap_or(false)
    }
}

#[derive(Debug)]
pub enum LaunchMode {
    /// Run the app directly, no sandbox.
    Plain,
    /// Run inside user+net+mount namespaces via the `--ns-child` helper.
    /// The app runs as the invoking user (non-root) inside the namespace.
    Sandboxed {
        /// JSON rules file consumed by the bridge + ns-child; the bridge
        /// re-reads it when the UI rewrites it (dynamic rule updates).
        allow_path: PathBuf,
        bridge_path: String,
        /// JSONL request log for this app (host side).
        log_path: PathBuf,
    },
}

#[derive(Debug)]
pub enum LaunchError {
    Spawn(std::io::Error),
    Sandbox(String),
}

impl std::fmt::Display for LaunchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LaunchError::Spawn(e) => write!(f, "启动进程失败: {e}"),
            LaunchError::Sandbox(m) => write!(f, "沙盒启动失败: {m}"),
        }
    }
}

/// The launcher's config directory (`~/.config/jail`): apps.json, per-app
/// request logs and per-app allowlist files live here.
pub fn config_base() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("jail")
}

/// Serialize the app's sandbox rules into the allowlist file consumed by the
/// host bridge (`config_base/allow/<app_id>.json`). Called on every launch
/// and whenever the UI changes the rules — the running bridge picks up the
/// new file within its poll interval, making edits take effect immediately.
/// Returns the file path.
pub fn write_allow_file(config_base: &std::path::Path, app: &AppEntry) -> PathBuf {
    let dir = config_base.join("allow");
    let _ = std::fs::create_dir_all(&dir);
    let allow = AllowList {
        mode: app.sandbox.allow_mode,
        entries: app
            .sandbox
            .allow_entries
            .iter()
            .map(|d| d.trim().to_string())
            .filter(|d| !d.is_empty())
            .collect(),
        loopback: app.sandbox.allow_loopback,
    };
    let path = dir.join(format!("{}.json", app.id));
    if let Ok(json) = serde_json::to_string(&allow) {
        let _ = std::fs::write(&path, json);
    }
    path
}

/// Resolve the sandbox config into a launch mode. The allowlist is enforced
/// by the host bridge on hostnames (no pre-launch DNS resolution needed);
/// `config_base` selects where the per-app request logs and allowlist files
/// live.
pub fn prepare_launch_in(config_base: &std::path::Path, app: &AppEntry) -> Result<LaunchMode, LaunchError> {
    if !app.sandbox.enabled {
        return Ok(LaunchMode::Plain);
    }
    let allow_path = write_allow_file(config_base, app);
    let logs_dir = config_base.join("logs");
    std::fs::create_dir_all(&logs_dir).map_err(|e| LaunchError::Sandbox(e.to_string()))?;
    let bridge_path = std::env::temp_dir().join(format!(
        "jail-bridge-{}-{}.sock",
        std::process::id(),
        &app.id[..8.min(app.id.len())]
    ));
    let _ = std::fs::remove_file(&bridge_path);
    Ok(LaunchMode::Sandboxed {
        allow_path,
        bridge_path: bridge_path.to_string_lossy().into_owned(),
        log_path: logs_dir.join(format!("{}.jsonl", app.id)),
    })
}

/// Default entry point using the real config directory.
pub fn prepare_launch(app: &AppEntry) -> Result<LaunchMode, LaunchError> {
    prepare_launch_in(&config_base(), app)
}

/// Strip one pair of spec-level double quotes from an Exec word (argument
/// delimiters per the freedesktop spec, not part of the argument). Shared by
/// `shell_quote_words` and the AppImage detection in `ns_child`.
pub(crate) fn strip_exec_quotes(word: &str) -> &str {
    word.strip_prefix('"')
        .and_then(|w| w.strip_suffix('"'))
        .filter(|w| !w.is_empty())
        .unwrap_or(word)
}

/// Quote each word of an Exec value for use inside `sh -c`.
///
/// Per the freedesktop Exec spec, double quotes are argument delimiters, not
/// part of the argument: `Exec="/opt/my app.appimage" %U` means the argument
/// is `/opt/my app.appimage`. `strip_field_codes` keeps them literally, so
/// each word has one pair of surrounding double quotes removed here — before
/// the word is single-quoted for the shell. (Words with embedded spaces are
/// still split by whitespace: a pre-existing limitation, unchanged.)
pub(crate) fn shell_quote_words(exec: &str) -> String {
    exec.split_whitespace()
        .map(|w| format!("'{}'", strip_exec_quotes(w).replace('\'', "'\\''")))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Write text to a temp file and return its path. The name is unique per
/// call (pid + sequence) so concurrent launches never clobber each other.
pub(crate) fn write_temp_file(prefix: &str, content: &str) -> std::io::Result<String> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!("{prefix}-{}-{n}.tmp", std::process::id()));
    std::fs::write(&path, content)?;
    Ok(path.to_string_lossy().into_owned())
}

/// Path of the jail binary used for --bridge / --ns-relay helpers.
/// When the running process is jail itself, reuse it directly. Under
/// `cargo test`, `current_exe()` is a test binary that may live several
/// directories deep — with cargo >= 1.100 integration tests land in
/// `target/debug/build/<pkg>/<hash>/out/` where no `jail` sibling exists
/// (older cargo used `target/debug/deps/e2e-xxxx`). Walk up the ancestor
/// directories to find the compiled `jail` binary; fall back to the current
/// executable (correct whenever the process is jail itself, e.g. installed
/// into PATH).
fn helper_exe() -> std::io::Result<std::path::PathBuf> {
    let exe = std::env::current_exe()?;
    if exe.file_stem() == Some(std::ffi::OsStr::new("jail")) {
        return Ok(exe);
    }
    let mut dir = exe.parent().map(std::path::Path::to_path_buf);
    while let Some(d) = dir {
        let candidate = d.join("jail");
        // is_file (not exists): an ancestor *directory* named `jail` (e.g.
        // target/debug/build/jail) must not be mistaken for the binary.
        if candidate.is_file() {
            return Ok(candidate);
        }
        dir = d.parent().map(std::path::Path::to_path_buf);
    }
    Ok(exe)
}

/// Spawn the app.
///
/// The app's stdout/stderr are captured into an in-memory ring buffer (1 MiB
/// cap, never written to disk) keyed by app id in `logs`; the previous run's
/// log is replaced on each launch.
///
/// Sandboxed layout: the launcher spawns `jail --ns-child <allow.json>
/// <bridge.sock> <exec...>`, which enters user+net+mount namespaces, maps
/// the invoking user's own uid into them, performs the privileged setup
/// (lo up, nftables ruleset, resolv.conf/nsswitch bind mounts) with raw
/// syscalls, forks the ns relay, drops to the user's uid and execs the app.
/// The app therefore runs as a NON-ROOT user inside the sandbox (Electron
/// apps refuse to run as root), with no capabilities.
///
/// The host side runs `--bridge <bridge.sock> <allowlist.json>` before spawn.
pub fn spawn_app(
    app: &AppEntry,
    mode: &LaunchMode,
    logs: &OutputLogRegistry,
) -> Result<RunningApp, LaunchError> {
    let self_exe = helper_exe().map_err(LaunchError::Spawn)?;
    let exec = &app.exec;
    let out_log = logs.reset(&app.id);

    let mut cmd = match mode {
        LaunchMode::Plain => {
            let mut c = Command::new("/bin/sh");
            c.arg("-c").arg(format!("exec {}", shell_quote_words(exec)));
            c
        }
        LaunchMode::Sandboxed {
            allow_path,
            bridge_path,
            log_path,
        } => {
            // 1. start the host bridge (reads the rules file, enforces it,
            //    writes the request log; re-reads the file on change)
            let allow_file = allow_path.to_string_lossy().into_owned();
            let bridge = Command::new(&self_exe)
                .args([
                    "--bridge",
                    bridge_path,
                    &allow_file,
                    &log_path.to_string_lossy(),
                ])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .map_err(LaunchError::Spawn)?;
            std::mem::forget(bridge); // detached; self-exits when the socket file is removed

            // 2. the ns-child process: namespaces + privileged setup +
            //    relay fork + uid drop + exec app. Proxy env vars are set
            //    here (they survive the exec chain into the app).
            let mut c = Command::new(&self_exe);
            c.args([
                "--ns-child",
                &allow_file,
                bridge_path,
                exec,
            ]);
            for (k, v) in [
                ("HTTP_PROXY", "http://127.0.0.1:8080"),
                ("HTTPS_PROXY", "http://127.0.0.1:8080"),
                ("http_proxy", "http://127.0.0.1:8080"),
                ("https_proxy", "http://127.0.0.1:8080"),
                ("ALL_PROXY", "http://127.0.0.1:8080"),
                ("all_proxy", "http://127.0.0.1:8080"),
                ("NO_PROXY", "localhost,127.0.0.1"),
                ("no_proxy", "localhost,127.0.0.1"),
            ] {
                c.env(k, v);
            }
            c
        }
    };
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    match cmd.spawn() {
        Ok(mut child) => {
            // Pump stdout/stderr into the in-memory ring buffer. Detached
            // threads: they hold only the OutputLog Arc (never the Child),
            // and exit at EOF — i.e. when the app (and any forked children
            // keeping the pipe open, such as the ns relay) are gone.
            if let Some(out) = child.stdout.take() {
                pipe_to_log(out, out_log.clone());
            }
            if let Some(err) = child.stderr.take() {
                pipe_to_log(err, out_log);
            }
            Ok(RunningApp {
                app_id: app.id.clone(),
                pid: child.id(),
                sandboxed: matches!(mode, LaunchMode::Sandboxed { .. }),
                child: Some(child),
                bridge_path: match mode {
                    LaunchMode::Sandboxed { bridge_path, .. } => Some(bridge_path.clone()),
                    LaunchMode::Plain => None,
                },
                allow_path: match mode {
                    LaunchMode::Sandboxed { allow_path, .. } => Some(allow_path.clone()),
                    LaunchMode::Plain => None,
                },
            })
        }
        Err(e) => Err(LaunchError::Spawn(e)),
    }
}

/// Read `r` to EOF in 8 KiB chunks, appending everything to `log`.
fn pipe_to_log<R: Read + Send + 'static>(mut r: R, log: Arc<OutputLog>) {
    thread::spawn(move || {
        let mut buf = [0u8; 8192];
        loop {
            match r.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => log.append(&buf[..n]),
            }
        }
    });
}

/// Spawn a watcher thread that polls the process and calls `on_exit`
/// when it exits.
pub fn watch(
    handle: Arc<Mutex<RunningApp>>,
    registry: Arc<RunningRegistry>,
    on_exit: Box<dyn FnOnce(String) + Send>,
) {
    thread::spawn(move || loop {
        thread::sleep(Duration::from_millis(500));
        let (alive, id, bridge) = {
            let mut guard = handle.lock().unwrap();
            (guard.is_alive(), guard.app_id.clone(), guard.bridge_path.clone())
        };
        if !alive {
            if let Some(path) = bridge {
                let _ = std::fs::remove_file(&path);
            }
            registry.remove(&id);
            on_exit(id);
            break;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quote_words() {
        assert_eq!(shell_quote_words("firefox"), "'firefox'");
        assert_eq!(
            shell_quote_words("app --flag 'a b'"),
            "'app' '--flag' ''\\''a' 'b'\\'''"
        );
    }

    #[test]
    fn quote_words_strips_double_quotes() {
        // desktop Exec uses double quotes as argument delimiters; the stored
        // exec keeps them literally (zcode case)
        assert_eq!(
            shell_quote_words("\"/opt/zcode.appimage\""),
            "'/opt/zcode.appimage'"
        );
        // a double-quoted word containing a space is split by whitespace first
        // (pre-existing limitation): each fragment keeps its unbalanced quote
        assert_eq!(
            shell_quote_words("\"/opt/my app.appimage\" --flag"),
            "'\"/opt/my' 'app.appimage\"' '--flag'"
        );
        // no quotes / single quotes / inner-only quotes: unchanged
        assert_eq!(shell_quote_words("/usr/bin/code"), "'/usr/bin/code'");
        assert_eq!(shell_quote_words("'quoted'"), "''\\''quoted'\\'''");
        assert_eq!(shell_quote_words("say\"hi\""), "'say\"hi\"'");
        // a bare pair of quotes with nothing inside is not a valid argument:
        // keep it literal rather than producing an empty word
        assert_eq!(shell_quote_words("\"\""), "'\"\"'");
    }

    #[test]
    fn strip_exec_quotes_variants() {
        assert_eq!(
            strip_exec_quotes("\"/opt/zcode.appimage\""),
            "/opt/zcode.appimage"
        );
        assert_eq!(strip_exec_quotes("/usr/bin/code"), "/usr/bin/code");
        // unbalanced or inner quotes are kept
        assert_eq!(strip_exec_quotes("\"unbalanced"), "\"unbalanced");
        assert_eq!(strip_exec_quotes("say\"hi\""), "say\"hi\"");
        // a bare pair of quotes is not a valid argument: keep literal
        assert_eq!(strip_exec_quotes("\"\""), "\"\"");
    }

    #[test]
    fn plain_launch_true_binary() {
        let app = AppEntry::new("t.desktop".into(), "t".into(), "i".into(), "/bin/true".into());
        let mode = prepare_launch(&app).unwrap();
        let logs = OutputLogRegistry::default();
        let mut running = spawn_app(&app, &mode, &logs).unwrap();
        std::thread::sleep(Duration::from_millis(300));
        assert!(!running.is_alive());
    }

    #[test]
    fn sandboxed_launch_sandboxed_flag() {
        let dir = std::env::temp_dir().join(format!("jail-sb-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut app =
            AppEntry::new("t.desktop".into(), "t".into(), "i".into(), "/bin/true".into());
        app.sandbox.enabled = true;
        app.sandbox.allow_entries = vec!["example.com".into()];
        let mode = prepare_launch_in(&dir, &app).unwrap();
        assert!(matches!(mode, LaunchMode::Sandboxed { .. }));
        if let LaunchMode::Sandboxed { allow_path, .. } = mode {
            // the rules file must exist and carry the sandbox config
            let text = std::fs::read_to_string(&allow_path).unwrap();
            let list: AllowList = serde_json::from_str(&text).unwrap();
            assert_eq!(list.entries, vec!["example.com"]);
            assert!(list.loopback);
            assert_eq!(list.mode, crate::model::AllowMode::Whitelist);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_allow_file_reflects_mode_and_edits() {
        let dir = std::env::temp_dir().join(format!("jail-af-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut app =
            AppEntry::new("t.desktop".into(), "t".into(), "i".into(), "/bin/true".into());
        app.sandbox.enabled = true;
        app.sandbox.allow_entries = vec!["a.com".into()];
        let path = write_allow_file(&dir, &app);
        assert!(path.starts_with(dir.join("allow")));
        let list: AllowList =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(list.entries, vec!["a.com"]);
        assert_eq!(list.mode, crate::model::AllowMode::Whitelist);

        // UI edits: switch to blacklist + new entries → rewrite reflects it
        app.sandbox.allow_mode = crate::model::AllowMode::Blacklist;
        app.sandbox.allow_entries = vec!["evil.com".into()];
        let path2 = write_allow_file(&dir, &app);
        assert_eq!(path, path2, "deterministic path per app");
        let list: AllowList =
            serde_json::from_str(&std::fs::read_to_string(&path2).unwrap()).unwrap();
        assert_eq!(list.mode, crate::model::AllowMode::Blacklist);
        assert_eq!(list.entries, vec!["evil.com"]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sandboxed_launch_sets_log_path() {
        let dir = std::env::temp_dir().join(format!("jail-lp-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut app =
            AppEntry::new("t.desktop".into(), "t".into(), "i".into(), "/bin/true".into());
        app.sandbox.enabled = true;
        app.sandbox.allow_entries = vec!["example.com".into()];
        let mode = prepare_launch_in(&dir, &app).unwrap();
        let LaunchMode::Sandboxed { log_path, .. } = mode else {
            panic!("expected sandboxed mode");
        };
        assert!(log_path.starts_with(dir.join("logs")));
        assert!(log_path.to_string_lossy().ends_with(".jsonl"));
        assert!(dir.join("logs").is_dir());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn plain_launch_has_no_log() {
        let app = AppEntry::new("t.desktop".into(), "t".into(), "i".into(), "/bin/true".into());
        match prepare_launch(&app).unwrap() {
            LaunchMode::Plain => {}
            other => panic!("expected plain mode, got {other:?}"),
        }
    }

    #[test]
    fn plain_launch_captures_output() {
        // A script file avoids shell quoting inside Exec: the launcher runs
        // each whitespace-separated word as its own argv entry.
        let dir = std::env::temp_dir().join(format!("jail-cap-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let script = dir.join("cap.sh");
        std::fs::write(&script, "#!/bin/sh\necho out-line\necho err-line >&2\n").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        let app = AppEntry::new(
            "t.desktop".into(),
            "t".into(),
            "i".into(),
            script.to_string_lossy().into_owned(),
        );
        let mode = prepare_launch(&app).unwrap();
        let logs = OutputLogRegistry::default();
        let mut running = spawn_app(&app, &mode, &logs).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while running.is_alive() && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(50));
        }
        // give the pump threads a moment to drain the pipes
        std::thread::sleep(Duration::from_millis(300));
        let log = logs.get(&app.id).expect("output log registered");
        let (buf, _) = log.snapshot();
        assert!(buf.contains("out-line"), "stdout captured: {buf:?}");
        assert!(buf.contains("err-line"), "stderr captured: {buf:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn relaunch_resets_output_log() {
        let app = AppEntry::new("t.desktop".into(), "t".into(), "i".into(), "/bin/true".into());
        let mode = prepare_launch(&app).unwrap();
        let logs = OutputLogRegistry::default();
        let mut first = spawn_app(&app, &mode, &logs).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while first.is_alive() && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(50));
        }
        let log = logs.get(&app.id).expect("log after first run");
        let (buf, total) = log.snapshot();
        assert_eq!((buf.is_empty(), total), (true, 0), "/bin/true is silent");

        // second launch: same registry, fresh buffer
        let mut second = spawn_app(&app, &mode, &logs).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while second.is_alive() && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(50));
        }
        let log2 = logs.get(&app.id).expect("log after second run");
        let (buf2, total2) = log2.snapshot();
        assert_eq!((buf2.is_empty(), total2), (true, 0), "reset each launch");
        assert!(!Arc::ptr_eq(&log, &log2), "new OutputLog per launch");
    }

    #[test]
    fn terminate_all_kills_children() {
        let app = AppEntry::new(
            "sleep.desktop".into(),
            "sleep".into(),
            "i".into(),
            "/bin/sleep 30".into(),
        );
        let mode = prepare_launch(&app).unwrap();
        let registry = RunningRegistry::default();
        let logs = OutputLogRegistry::default();
        let running = spawn_app(&app, &mode, &logs).unwrap();
        let handle = registry.insert(running);
        std::thread::sleep(Duration::from_millis(300));
        assert!(handle.lock().unwrap().is_alive(), "sleep app running");

        registry.terminate_all();

        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while handle.lock().unwrap().is_alive() && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(50));
        }
        assert!(!handle.lock().unwrap().is_alive(), "child terminated");
        assert!(!registry.is_running(&app.id), "registry entry reaped");
    }
}
