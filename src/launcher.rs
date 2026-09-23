//! Launching apps: plain or sandboxed (netns + nft + proxy bridge), with
//! process-group tracking so the UI can show/hide the running badge.

use crate::model::AppEntry;
use crate::proxy::AllowList;
use crate::sandbox;
use std::collections::HashMap;
use std::os::unix::process::CommandExt as _;
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
}

impl RunningApp {
    /// Non-blocking poll; returns true while the process is alive.
    pub fn is_alive(&mut self) -> bool {
        match self.child.as_mut() {
            Some(c) => c.try_wait().map(|s| s.is_none()).unwrap_or(true),
            None => true,
        }
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
    /// Run inside unshare with the nft script + proxy bridge.
    Sandboxed {
        nft_script: String,
        allow: AllowList,
        bridge_path: String,
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

/// Resolve the sandbox config into a launch mode. Domains are resolved
/// host-side at launch (for the preview + early failure detection).
pub fn prepare_launch(app: &AppEntry) -> Result<LaunchMode, LaunchError> {
    if !app.sandbox.enabled {
        return Ok(LaunchMode::Plain);
    }
    let (resolved, failed) = sandbox::resolve_domains(&app.sandbox.allow_domains);
    if !failed.is_empty() {
        eprintln!("app-launcher: could not resolve domains: {failed:?}");
    }
    let nft_script = sandbox::build_nft_script(&app.sandbox, &resolved);
    let allow = AllowList {
        domains: app
            .sandbox
            .allow_domains
            .iter()
            .map(|d| d.trim().to_ascii_lowercase())
            .filter(|d| !d.is_empty())
            .collect(),
        ips: app.sandbox.allow_ips.clone(),
        loopback: app.sandbox.allow_loopback,
    };
    let bridge_path = std::env::temp_dir().join(format!(
        "applauncher-bridge-{}-{}.sock",
        std::process::id(),
        &app.id[..8.min(app.id.len())]
    ));
    let _ = std::fs::remove_file(&bridge_path);
    Ok(LaunchMode::Sandboxed {
        nft_script,
        allow,
        bridge_path: bridge_path.to_string_lossy().into_owned(),
    })
}

/// Quote each word of an Exec value for use inside `sh -c`.
fn shell_quote_words(exec: &str) -> String {
    exec.split_whitespace()
        .map(|w| format!("'{}'", w.replace('\'', "'\\''")))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Write text to a temp file and return its path.
fn write_temp_file(prefix: &str, content: &str) -> std::io::Result<String> {
    let path = std::env::temp_dir().join(format!("{prefix}-{}.tmp", std::process::id()));
    std::fs::write(&path, content)?;
    Ok(path.to_string_lossy().into_owned())
}

/// Path of the app-launcher binary used for --bridge / --ns-relay helpers.
/// `current_exe()` points at the test binary under `cargo test`, so prefer
/// the sibling `app-launcher` binary when it exists.
fn helper_exe() -> std::io::Result<std::path::PathBuf> {
    let exe = std::env::current_exe()?;
    let dir = exe.parent().unwrap_or_else(|| std::path::Path::new("."));
    let candidate = dir.join("app-launcher");
    if candidate.exists() {
        return Ok(candidate);
    }
    // target/debug/deps/e2e-xxxx -> target/debug/app-launcher
    if let Some(deps) = dir.parent() {
        let candidate = deps.join("app-launcher");
        if candidate.exists() {
            return Ok(candidate);
        }
    }
    Ok(exe)
}

/// Spawn the app.
///
/// Sandboxed layout:
/// ```text
/// unshare -Urnm --map-root-user sh -c '
///   ip link set lo up
///   nft -f <rules>
///   mount --bind <resolv.conf> /etc/resolv.conf
///   app-launcher --ns-relay <bridge.sock> &     # proxy inside ns
///   exec <app>                                   # with proxy env vars
/// '
/// ```
/// The host side runs `--bridge <bridge.sock> <allowlist.json>` before spawn.
pub fn spawn_app(app: &AppEntry, mode: &LaunchMode) -> Result<RunningApp, LaunchError> {
    let self_exe = helper_exe().map_err(LaunchError::Spawn)?;
    let exec = &app.exec;

    let mut cmd = match mode {
        LaunchMode::Plain => {
            let mut c = Command::new("/bin/sh");
            c.arg("-c").arg(format!("exec {}", shell_quote_words(exec)));
            c
        }
        LaunchMode::Sandboxed {
            nft_script,
            allow,
            bridge_path,
        } => {
            // 1. start the host bridge (validates the allowlist)
            let allow_json = serde_json::to_string(allow)
                .map_err(|e| LaunchError::Sandbox(e.to_string()))?;
            let allow_file =
                write_temp_file("applauncher-allow", &allow_json).map_err(LaunchError::Spawn)?;
            let bridge = Command::new(&self_exe)
                .args(["--bridge", bridge_path, &allow_file])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .map_err(LaunchError::Spawn)?;
            std::mem::forget(bridge); // detached; exits when the socket is gone

            // 2. prepare ns-side files
            let nft_file = write_temp_file("applauncher-nft", nft_script)
                .map_err(LaunchError::Spawn)?;
            let resolv_file = write_temp_file("applauncher-resolv", "nameserver 127.0.0.1\n")
                .map_err(LaunchError::Spawn)?;

            // 3. inner script
            let inner = format!(
                "ip link set lo up                  && nft -f '{nft_file}'                  && mount --bind '{resolv_file}' /etc/resolv.conf                  && '{self_exe}' --ns-relay '{bridge_path}' & \
                 RELAY=$!; \
                 export HTTP_PROXY=http://127.0.0.1:8080 \
                 HTTPS_PROXY=http://127.0.0.1:8080 \
                 http_proxy=http://127.0.0.1:8080 \
                 https_proxy=http://127.0.0.1:8080 \
                 ALL_PROXY=socks5://127.0.0.1:8080 \
                 all_proxy=socks5://127.0.0.1:8080 \
                 NO_PROXY=localhost,127.0.0.1 \
                 no_proxy=localhost,127.0.0.1; \
                 sleep 0.5; \
                 exec {}",
                shell_quote_words(exec),
                self_exe = self_exe.display(),
            );
            let mut c = Command::new("unshare");
            c.args(["-Urnm", "--map-root-user", "/bin/sh", "-c", &inner]);
            c
        }
    };
    cmd.stdout(Stdio::null())
        .stderr(Stdio::null())
        .stdin(Stdio::null())
        .process_group(0);
    match cmd.spawn() {
        Ok(child) => Ok(RunningApp {
            app_id: app.id.clone(),
            pid: child.id(),
            sandboxed: matches!(mode, LaunchMode::Sandboxed { .. }),
            child: Some(child),
            bridge_path: match mode {
                LaunchMode::Sandboxed { bridge_path, .. } => Some(bridge_path.clone()),
                LaunchMode::Plain => None,
            },
        }),
        Err(e) => Err(LaunchError::Spawn(e)),
    }
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
    fn plain_launch_true_binary() {
        let app = AppEntry::new("t.desktop".into(), "t".into(), "i".into(), "/bin/true".into());
        let mode = prepare_launch(&app).unwrap();
        let mut running = spawn_app(&app, &mode).unwrap();
        std::thread::sleep(Duration::from_millis(300));
        assert!(!running.is_alive());
    }

    #[test]
    fn sandboxed_launch_sandboxed_flag() {
        let mut app =
            AppEntry::new("t.desktop".into(), "t".into(), "i".into(), "/bin/true".into());
        app.sandbox.enabled = true;
        app.sandbox.allow_domains = vec!["example.com".into()];
        let mode = prepare_launch(&app).unwrap();
        assert!(matches!(mode, LaunchMode::Sandboxed { .. }));
        if let LaunchMode::Sandboxed { allow, .. } = mode {
            assert_eq!(allow.domains, vec!["example.com"]);
            assert!(allow.loopback);
        }
    }
}
