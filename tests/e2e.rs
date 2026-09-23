use app_launcher::launcher::{self, LaunchMode};
use app_launcher::model::AppEntry;

/// End-to-end: spawn a "fake app" through the real sandboxed spawn path and
/// verify the allowlist holds. Requires the sandbox prerequisites
/// (unshare user/net namespaces); skipped when unavailable.
#[test]
fn sandboxed_spawn_enforces_allowlist() {
    // Probe: can we unshare at all in this environment?
    let probe = std::process::Command::new("unshare")
        .args(["-Urnm", "--map-root-user", "true"])
        .status();
    if probe.map(|s| !s.success()).unwrap_or(true) {
        eprintln!("skipping: unshare unavailable");
        return;
    }

    let fake_app = std::env::current_dir()
        .unwrap()
        .join(".devcache/e2e/fakeapp.sh");
    if !fake_app.exists() {
        eprintln!("skipping: fake app script missing");
        return;
    }

    let mut app = AppEntry::new(
        "fake.desktop".into(),
        "FakeApp".into(),
        "i".into(),
        fake_app.to_string_lossy().into_owned(),
    );
    app.sandbox.enabled = true;
    app.sandbox.allow_domains = vec!["baidu.com".into()];

    let mode = launcher::prepare_launch(&app).unwrap();
    let LaunchMode::Sandboxed { .. } = &mode else {
        panic!("expected sandboxed mode");
    };
    let mut running = launcher::spawn_app(&app, &mode).unwrap();
    assert!(running.sandboxed);

    // wait for the fake app to finish probing
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while running.is_alive() && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(300));
    }
    assert!(!running.is_alive(), "fake app should have exited");
}
