//! `--ns-child`: the in-namespace launcher process.
//!
//! Spawned by `launcher::spawn_app` via `std::process::Command` (so the
//! usual pipe/output-capture plumbing keeps working). Inside this process:
//!
//! 1. `unshare(CLONE_NEWUSER | CLONE_NEWNET | CLONE_NEWNS)` — the process
//!    holds a FULL capability set in the new user namespace from this point
//!    (user_namespaces(7)), regardless of its (unmapped) uid.
//! 2. Write single-line uid/gid maps `1000 1000 1`: the app will run as the
//!    SAME uid as the launcher user (files stay owned by the user; Electron
//!    refuses to run as root). A process may always map its own euid — no
//!    setuid newuidmap needed.
//! 3. Privileged setup with RAW SYSCALLS ONLY (any exec would drop the
//!    capabilities, because our in-ns uid is not 0):
//!      - bring `lo` up (rtnetlink RTM_NEWLINK)
//!      - load the nftables ruleset (rustables → nfnetlink)
//!      - bind-mount resolv.conf / nsswitch.conf overrides
//! 4. Fork the ns relay (`jail --ns-relay <sock>`), which runs as uid 1000
//!    with no capabilities (its exec drops them).
//! 5. `setresuid(1000)` and exec the app — the exec clears every capability.
//!
//! Any failure is reported on stderr (captured in the run log) and exits
//! non-zero.

use crate::proxy::AllowList;
use crate::sandbox;

/// Entry point for `jail --ns-child <allow_json> <bridge_sock> <exec...>`.
pub fn run(args: &[String]) -> Result<(), String> {
    let host_uid = unsafe { libc::getuid() };
    let [allow_file, bridge_sock, exec @ ..] = args else {
        return Err("usage: --ns-child <allow_json> <bridge_sock> <exec...>".into());
    };
    if exec.is_empty() {
        return Err("--ns-child: no exec command given".into());
    }
    let allow_json = std::fs::read_to_string(allow_file)
        .map_err(|e| format!("read allowlist: {e}"))?;
    let allow: AllowList =
        serde_json::from_str(&allow_json).map_err(|e| format!("parse allowlist: {e}"))?;

    // 1. enter user + net + mount namespaces
    unsafe {
        if libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNET | libc::CLONE_NEWNS) != 0 {
            return Err(format!(
                "unshare(user|net|mount): {}",
                std::io::Error::last_os_error()
            ));
        }
    }

    // 2. map our own euid to the same uid inside the namespace
    write_proc_file("/proc/self/setgroups", "deny\n")?;
    write_proc_file("/proc/self/uid_map", &format!("{host_uid} {host_uid} 1\n"))?;
    write_proc_file("/proc/self/gid_map", &format!("{host_uid} {host_uid} 1\n"))?;

    // 3. privileged setup — no exec before this point!
    bring_lo_up().map_err(|e| format!("bring lo up: {e}"))?;
    sandbox::apply_ruleset(allow.loopback)?;
    // The relay binds 127.0.0.1:53 (DNS) as a non-root uid; allow that by
    // lowering the per-netns unprivileged port floor (restored on ns teardown).
    write_proc_file("/proc/sys/net/ipv4/ip_unprivileged_port_start", "0")
        .map_err(|e| format!("lower unprivileged port start: {e}"))?;
    mount_file("/etc/resolv.conf", "nameserver 127.0.0.1\n", "jail-resolv")?;
    if let Some(nss) = nsswitch_override() {
        // best-effort: without it DNS may leak via nss-resolve, but the
        // sandbox still holds
        if let Err(e) = bind_mount(&nss, "/etc/nsswitch.conf") {
            eprintln!("jail ns-child: nsswitch bind-mount skipped: {e}");
        }
    }

    // 4. fork the ns relay (uid 1000, caps dropped at its exec)
    let relay = unsafe { libc::fork() };
    if relay < 0 {
        return Err(format!("fork relay: {}", std::io::Error::last_os_error()));
    }
    if relay == 0 {
        // child: exec the relay; on failure, _exit (never run the app twice)
        let sock = std::ffi::CString::new(bridge_sock.as_str()).unwrap();
        let exe = std::ffi::CString::new(
            std::env::current_exe()
                .unwrap_or_else(|_| std::path::PathBuf::from("/proc/self/exe"))
                .into_os_string()
                .into_string()
                .unwrap_or_else(|_| "/proc/self/exe".into()),
        )
        .unwrap();
        let flag = std::ffi::CString::new("--ns-relay").unwrap();
        unsafe {
            libc::execl(exe.as_ptr(), exe.as_ptr(), flag.as_ptr(), sock.as_ptr(), std::ptr::null::<libc::c_char>());
        }
        eprintln!(
            "jail ns-child: exec relay: {}",
            std::io::Error::last_os_error()
        );
        unsafe { libc::_exit(127) };
    }

    // 4b. wait for the relay to bind its listeners — the old shell script
    // slept 0.5s here; poll instead so slow machines don't start the app
    // before the proxy exists (curl would fail with connection refused).
    wait_for_relay();

    // 5. drop to the mapped uid and exec the app (caps die here)
    unsafe {
        if libc::setresgid(host_uid, host_uid, host_uid) != 0
            || libc::setresuid(host_uid, host_uid, host_uid) != 0
        {
            return Err(format!(
                "setresuid({host_uid}): {}",
                std::io::Error::last_os_error()
            ));
        }
    }
    // AppImages need FUSE (fusermount is setuid-root; the host root uid is
    // unmapped in this namespace, so the setuid bit is ignored and the mount
    // always fails). AppImageKit's official container mode extracts to /tmp
    // instead — enable it automatically for .appimage executables.
    if exec[0].ends_with(".appimage") {
        std::env::set_var("APPIMAGE_EXTRACT_AND_RUN", "1");
    }
    let quoted = crate::launcher::shell_quote_words(&exec.join(" "));
    let err = std::process::Command::new("/bin/sh")
        .arg("-c")
        .arg(format!("exec {quoted}"))
        .status();
    match err {
        Ok(status) if status.success() => Ok(()),
        Ok(status) => Err(format!("app exited with {status}")),
        Err(e) => Err(format!("exec app: {e}")),
    }
}

fn write_proc_file(path: &str, content: &str) -> Result<(), String> {
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .map_err(|e| format!("open {path}: {e}"))?;
    f.write_all(content.as_bytes())
        .map_err(|e| format!("write {path}: {e}"))
}

/// Bring the loopback interface up via rtnetlink (raw syscall, no exec).
fn bring_lo_up() -> Result<(), String> {
    unsafe {
        let fd = libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_ROUTE,
        );
        if fd < 0 {
            return Err(format!("socket: {}", std::io::Error::last_os_error()));
        }
        #[repr(C)]
        struct Req {
            nh: libc::nlmsghdr,
            ifi: libc::ifinfomsg,
        }
        let mut req: Req = std::mem::zeroed();
        req.nh.nlmsg_len = std::mem::size_of::<Req>() as u32;
        req.nh.nlmsg_type = libc::RTM_NEWLINK as u16;
        req.nh.nlmsg_flags = (libc::NLM_F_REQUEST | libc::NLM_F_ACK) as u16;
        req.ifi.ifi_family = libc::AF_UNSPEC as u8;
        req.ifi.ifi_index = 1; // lo
        req.ifi.ifi_flags = libc::IFF_UP as u32;
        req.ifi.ifi_change = libc::IFF_UP as u32;
        let mut sa: libc::sockaddr_nl = std::mem::zeroed();
        sa.nl_family = libc::AF_NETLINK as u16;
        let sent = libc::sendto(
            fd,
            &req as *const Req as *const libc::c_void,
            req.nh.nlmsg_len as usize,
            0,
            &sa as *const libc::sockaddr_nl as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_nl>() as u32,
        );
        if sent < 0 {
            let e = std::io::Error::last_os_error();
            libc::close(fd);
            return Err(format!("sendto: {e}"));
        }
        let mut buf = [0u8; 4096];
        let n = libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0);
        libc::close(fd);
        if n < 0 {
            return Err(format!("recv: {}", std::io::Error::last_os_error()));
        }
        let nh = buf.as_ptr() as *const libc::nlmsghdr;
        if (*nh).nlmsg_type == libc::NLMSG_ERROR as u16 {
            let err = (*(buf.as_ptr().add(std::mem::size_of::<libc::nlmsghdr>())
                as *const libc::nlmsgerr))
            .error;
            if err != 0 {
                return Err(format!("netlink: {}", std::io::Error::from_raw_os_error(-err)));
            }
        }
    }
    Ok(())
}

/// Poll until the relay's HTTP listener accepts on 127.0.0.1:8080 (or ~2s
/// elapse — the app will simply fail to proxy if the relay never comes up).
fn wait_for_relay() {
    use std::net::TcpStream;
    use std::time::{Duration, Instant};
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        if TcpStream::connect_timeout(
            &"127.0.0.1:8080".parse().unwrap(),
            Duration::from_millis(100),
        )
        .is_ok()
        {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    eprintln!("jail ns-child: relay did not become ready within 2s");
}

/// Write `content` to a temp file and bind-mount it over `target`.
fn mount_file(target: &str, content: &str, prefix: &str) -> Result<(), String> {
    let path = crate::launcher::write_temp_file(prefix, content)
        .map_err(|e| format!("write temp file: {e}"))?;
    bind_mount(&path, target)
}

/// Bind-mount `src` over `target` (both visible in this mount namespace).
fn bind_mount(src: &str, target: &str) -> Result<(), String> {
    let c_src = std::ffi::CString::new(src).unwrap();
    let c_target = std::ffi::CString::new(target).unwrap();
    unsafe {
        // bind mounts need a real file at both ends; MS_SILENT avoids dmesg noise
        if libc::mount(
            c_src.as_ptr(),
            c_target.as_ptr(),
            std::ptr::null(),
            libc::MS_BIND,
            std::ptr::null(),
        ) != 0
        {
            return Err(format!(
                "bind-mount {src} -> {target}: {}",
                std::io::Error::last_os_error()
            ));
        }
    }
    Ok(())
}

/// Rewrite the `hosts:` line of /etc/nsswitch.conf to `files dns` so glibc
/// resolves via our relayed resolv.conf instead of nss-resolve (which would
/// reach systemd-resolved through a host AF_UNIX socket). Returns the temp
/// file path, or None when the host has no nsswitch.conf.
fn nsswitch_override() -> Option<String> {
    let text = std::fs::read_to_string("/etc/nsswitch.conf").ok()?;
    let mut out = String::with_capacity(text.len());
    let mut replaced = false;
    for line in text.lines() {
        if line.trim_start().starts_with("hosts:") {
            out.push_str("hosts:       files dns\n");
            replaced = true;
        } else {
            out.push_str(line);
            out.push('\n');
        }
    }
    if !replaced {
        out.push_str("hosts:       files dns\n");
    }
    crate::launcher::write_temp_file("jail-nss", &out).ok()
}
