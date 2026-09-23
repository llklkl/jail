use jail::launcher::{self, LaunchMode};
use jail::model::AppEntry;
use jail::output_log::OutputLogRegistry;

/// End-to-end: spawn a "fake app" through the real sandboxed spawn path and
/// verify the allowlist holds AND the request log records the traffic.
/// Requires the sandbox prerequisites (unshare user/net namespaces); skipped
/// when unavailable.
#[test]
fn sandboxed_spawn_enforces_allowlist_and_logs() {
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

    // Use a private config dir so the request log lands somewhere we control.
    let cfg_dir = std::env::temp_dir().join(format!("jail-e2e-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&cfg_dir);

    let mut app = AppEntry::new(
        "fake.desktop".into(),
        "FakeApp".into(),
        "i".into(),
        fake_app.to_string_lossy().into_owned(),
    );
    app.sandbox.enabled = true;
    // exact entry for the CONNECT host + wildcard exercising subdomain match
    app.sandbox.allow_entries = vec!["www.baidu.com".into(), "*.baidu.com".into()];

    let mode = launcher::prepare_launch_in(&cfg_dir, &app).unwrap();
    let LaunchMode::Sandboxed { log_path, .. } = &mode else {
        panic!("expected sandboxed mode");
    };
    let logs = OutputLogRegistry::default();
    let mut running = launcher::spawn_app(&app, &mode, &logs).unwrap();
    assert!(running.sandboxed);

    // wait for the fake app to finish probing
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(45);
    while running.is_alive() && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(300));
    }
    assert!(!running.is_alive(), "fake app should have exited");

    // give the bridge a moment to flush the final events
    std::thread::sleep(std::time::Duration::from_millis(800));

    // 1. the fake app's own verdicts
    let result = std::fs::read_to_string(
        std::env::current_dir()
            .unwrap()
            .join(".devcache/e2e/fakeapp-result.txt"),
    )
    .expect("fake app result file");
    eprintln!("fakeapp: {result}");
    assert!(result.contains("allowed=2"), "allowed domain should work: {result}");
    assert!(result.contains("blocked=000"), "blocked domain must fail: {result}");

    // 2. the request log: allowed conn with bytes, denied conn, dns query
    let log = std::fs::read_to_string(log_path).expect("request log exists");
    eprintln!("--- request log ---\n{log}");
    assert!(log.contains("\"ev\":\"dns\""), "dns queries logged");
    assert!(log.contains("www.baidu.com"), "allowed host logged");
    assert!(log.contains("github.com"), "blocked host logged");
    assert!(
        log.contains("\"via\":\"domain\""),
        "domain match recorded: {log}"
    );
    // the allowed connection must have transferred bytes (end event)
    let end_line = log
        .lines()
        .find(|l| l.contains("\"ev\":\"end\"") && l.contains("\"down\":") )
        .expect("end event with byte counts");
    let v: serde_json::Value = serde_json::from_str(end_line).unwrap();
    assert!(
        v["down"].as_u64().unwrap_or(0) > 0,
        "allowed connection should have downloaded bytes: {end_line}"
    );

    // 3. connect-by-IP: the CONNECT for the bare IP must have been allowed
    //    via the DNS attribution (the remote's TLS behavior is out of our
    //    control, so we assert on the bridge verdict, not the HTTP code).
    let ip = result
        .lines()
        .find_map(|l| l.split_whitespace().find_map(|t| t.strip_prefix("ip=").map(|s| s.to_string())))
        .unwrap_or_default();
    assert!(!ip.is_empty(), "fake app resolved an ip: {result}");
    let ip_conn = log
        .lines()
        .find(|l| l.contains("\"ev\":\"conn\"") && l.contains(&ip))
        .unwrap_or_else(|| panic!("by-IP connect logged: {log}"));
    let v: serde_json::Value = serde_json::from_str(ip_conn).unwrap();
    assert!(
        v["ok"].as_bool().unwrap_or(false),
        "by-IP connect should be allowed via attribution: {ip_conn}"
    );
    assert!(
        ip_conn.contains("attr:") || ip_conn.contains("domain"),
        "by-IP connect matched through attribution: {ip_conn}"
    );

    // 4. run-output capture: the fake app's stdout/stderr landed in the
    //    in-memory ring buffer (never on disk)
    let out = logs.get(&app.id).expect("output log registered for fake app");
    let (buf, total) = out.snapshot();
    eprintln!("--- captured output ({total} bytes) ---\n{buf}");
    assert!(buf.contains("fakeapp-stdout-marker"), "stdout captured: {buf:?}");
    assert!(buf.contains("fakeapp-stderr-marker"), "stderr captured: {buf:?}");
    assert!(total > 0);

    let _ = std::fs::remove_dir_all(&cfg_dir);
}
