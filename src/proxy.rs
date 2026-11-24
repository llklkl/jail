//! Proxy-based network sandbox transport.
//!
//! A fresh network namespace has no external interfaces at all, so the only
//! path out is a host-side process. UNIX sockets are filesystem objects and
//! work across network namespaces, which gives us a clean bridge:
//!
//! ```text
//! [app] → 127.0.0.1:{随机端口} (HTTP CONNECT / absolute-URI)      → [ns relay] → AF_UNIX → [host bridge] → internet
//! [app] → 127.0.0.1:53 (DNS)                                     → [ns relay] → AF_UNIX → [host bridge] → resolver
//! ```
//!
//! The host bridge enforces the allowlist (domains + IPs + CIDR), logs every
//! connection and DNS query as JSONL, and learns IP→domain attributions from
//! forwarded DNS answers so "resolve then connect by IP" still matches the
//! domain rules. The nft rules inside the namespace allow loopback only, so
//! direct connections fail closed. Apps that ignore proxy env vars get no
//! network at all.

use crate::model::{classify_entry, EntryKind};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs as _};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Framing over the AF_UNIX bridge: 2-byte big-endian length + payload.
const MAX_FRAME: usize = 64 * 1024;
/// Rotate the log file at 5 MiB (single generation: `.jsonl` → `.jsonl.old`).
const LOG_ROTATE_BYTES: u64 = 5 * 1024 * 1024;
/// Upper bound for DNS-attribution cache entries (min(answer TTL, this)).
const ATTRIB_MAX_TTL: u64 = 300;

fn write_frame(w: &mut impl Write, payload: &[u8]) -> std::io::Result<()> {
    let len = payload.len() as u16;
    w.write_all(&len.to_be_bytes())?;
    w.write_all(payload)
}

fn read_frame(r: &mut impl Read) -> std::io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 2];
    r.read_exact(&mut len_buf)?;
    let len = u16::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAME {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "frame too large",
        ));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn truncate_str(s: &str, max_chars: usize) -> String {
    if s.chars().count() <= max_chars {
        s.to_string()
    } else {
        s.chars().take(max_chars).collect()
    }
}

// ---------------------------------------------------------------------------
// Allowlist
// ---------------------------------------------------------------------------

/// Allowlist shared with the host bridge. Entries are domains (wildcard
/// match), single IPs, or CIDR ranges — classified on demand via
/// `model::classify_entry`. The list is interpreted according to `mode`:
/// whitelist (entries allowed, rest denied) or blacklist (entries denied,
/// rest allowed).
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct AllowList {
    #[serde(default)]
    pub mode: crate::model::AllowMode,
    #[serde(default)]
    pub entries: Vec<String>,
    #[serde(default = "default_true")]
    pub loopback: bool,
}

fn default_true() -> bool {
    true
}

impl AllowList {
    /// Decide whether a host (name or IP) may connect; returns
    /// `(allowed, reason)`. The reason is recorded in the request log's
    /// `via` field:
    /// - allow: "loopback" | "domain" | "ip" | "cidr" | "default-allow"
    /// - deny:  "loopback-denied" | "blacklisted" | "not-in-whitelist"
    ///
    /// Domain entries match by label: `example.com` matches only itself;
    /// `*.example.com` matches the base itself and any depth of subdomains
    /// (api.example.com ✓, a.b.example.com ✓).
    pub fn decide(&self, host: &str) -> (bool, &'static str) {
        let host = host.trim_matches(['[', ']']).to_ascii_lowercase();
        if host == "localhost" || host.starts_with("127.") || host == "::1" {
            return (self.loopback, if self.loopback { "loopback" } else { "loopback-denied" });
        }
        let matched = self.entries.iter().find_map(|e| {
            match classify_entry(e) {
                Some(EntryKind::Domain) => domain_entry_matches(e.trim(), &host)
                    .then_some("domain"),
                Some(EntryKind::Ip) => host
                    .parse::<IpAddr>()
                    .ok()
                    .filter(|ip| e.trim().parse::<IpAddr>() == Ok(*ip))
                    .map(|_| "ip"),
                Some(EntryKind::Cidr { .. }) => host
                    .parse::<IpAddr>()
                    .ok()
                    .filter(|ip| cidr_entry_contains(e, *ip))
                    .map(|_| "cidr"),
                None => None,
            }
        });
        match (self.mode, matched) {
            (crate::model::AllowMode::Whitelist, Some(reason)) => (true, reason),
            (crate::model::AllowMode::Whitelist, None) => (false, "not-in-whitelist"),
            (crate::model::AllowMode::Blacklist, Some(reason)) => (false, reason_for_deny(reason)),
            (crate::model::AllowMode::Blacklist, None) => (true, "default-allow"),
        }
    }

    /// Whitelist-era API: the match reason when the host is allowed.
    #[allow(dead_code)] // convenience wrapper; decide is the primary API
    pub fn match_reason(&self, host: &str) -> Option<&'static str> {
        let (allowed, reason) = self.decide(host);
        allowed.then_some(reason)
    }

    #[allow(dead_code)] // convenience wrapper; decide is the primary API
    pub fn matches(&self, host: &str) -> bool {
        self.decide(host).0
    }

    /// Decide whether a DNS query for `qname` may be forwarded to the host
    /// resolver. Only Domain entries apply (IP/CIDR entries don't match
    /// names); the mode decides the polarity:
    /// - whitelist: listed → resolve, unlisted → refuse (anti-tunneling)
    /// - blacklist: listed → refuse, unlisted → resolve
    pub fn decide_dns(&self, qname: &str) -> bool {
        let qname = qname.trim_end_matches('.').to_ascii_lowercase();
        let listed = self.entries.iter().any(|e| {
            matches!(classify_entry(e), Some(EntryKind::Domain))
                && domain_entry_matches(e.trim(), &qname)
        });
        match self.mode {
            crate::model::AllowMode::Whitelist => listed,
            crate::model::AllowMode::Blacklist => !listed,
        }
    }
}

/// In blacklist mode the log's `via` field should say why the host was
/// denied: the entry kind that matched ("domain"/"ip"/"cidr") is ambiguous
/// with an allow reason, so map it to an explicit deny reason.
fn reason_for_deny(kind: &'static str) -> &'static str {
    match kind {
        "domain" => "blacklisted-domain",
        "ip" => "blacklisted-ip",
        "cidr" => "blacklisted-cidr",
        other => other,
    }
}

/// Domain entry vs host matching:
///   entry "example.com"    → host must equal "example.com"
///   entry "*.example.com"  → host is "example.com" itself or any subdomain
///                            at any depth (api.example.com ✓,
///                            a.b.example.com ✓)
/// Both sides are lowercased first. Entries are pre-validated by
/// `classify_entry`, so '*' can only appear as the whole first label.
fn domain_entry_matches(entry: &str, host: &str) -> bool {
    let entry = entry.to_ascii_lowercase();
    let host = host.to_ascii_lowercase();
    match entry.strip_prefix("*.") {
        Some(base) => {
            if base.is_empty() {
                return false;
            }
            host == base || host.ends_with(&format!(".{base}"))
        }
        None => entry == host,
    }
}

fn cidr_entry_contains(entry: &str, ip: IpAddr) -> bool {
    if let Some((net, plen)) = entry.trim().split_once('/') {
        if let (Ok(net_ip), Ok(p)) = (net.parse::<IpAddr>(), plen.parse::<u8>()) {
            return cidr_contains(net_ip, p, ip);
        }
    }
    false
}

fn cidr_contains(net: IpAddr, plen: u8, ip: IpAddr) -> bool {
    match (net, ip) {
        (IpAddr::V4(n), IpAddr::V4(i)) => {
            let p = plen.min(32);
            let mask = if p == 0 { 0 } else { u32::MAX << (32 - p) };
            u32::from(n) & mask == u32::from(i) & mask
        }
        (IpAddr::V6(n), IpAddr::V6(i)) => {
            let p = plen.min(128);
            let mask = if p == 0 { 0 } else { u128::MAX << (128 - p) };
            u128::from(n) & mask == u128::from(i) & mask
        }
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// Event log (JSONL, written by the host bridge)
// ---------------------------------------------------------------------------

/// Append-only JSONL event log. One file per sandboxed app; the UI tails it.
pub struct EventLogger {
    file: Mutex<Option<std::fs::File>>,
    path: PathBuf,
    pid: u32,
    seq: AtomicU64,
}

impl EventLogger {
    pub fn new(path: PathBuf) -> Self {
        if let Ok(meta) = std::fs::metadata(&path) {
            if meta.len() > LOG_ROTATE_BYTES {
                let old = path.with_extension("jsonl.old");
                let _ = std::fs::rename(&path, old);
            }
        }
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        Self {
            file: Mutex::new(None),
            path,
            pid: std::process::id(),
            seq: AtomicU64::new(0),
        }
    }

    /// A logger that drops every event (used when no log path was given).
    pub fn disabled() -> Self {
        Self {
            file: Mutex::new(None),
            path: PathBuf::new(),
            pid: 0,
            seq: AtomicU64::new(0),
        }
    }

    fn log_event(&self, event: serde_json::Value) {
        if self.path.as_os_str().is_empty() {
            return;
        }
        let mut guard = self.file.lock().unwrap();
        if guard.is_none() {
            match std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.path)
            {
                Ok(f) => *guard = Some(f),
                Err(_) => return,
            }
        }
        if let Some(f) = guard.as_mut() {
            let mut line = event.to_string();
            line.push('\n');
            let _ = f.write_all(line.as_bytes());
            let _ = f.flush();
        }
    }

    /// Log an established connection; returns its conn id for the `end` event.
    pub fn log_conn(&self, host: &str, port: u16, ok: bool, via: &str) -> String {
        let id = format!(
            "{}:{}",
            self.pid,
            self.seq.fetch_add(1, Ordering::Relaxed)
        );
        self.log_event(serde_json::json!({
            "ts": now_secs(),
            "ev": "conn",
            "id": id,
            "host": truncate_str(host, 120),
            "port": port,
            "ok": ok,
            "via": via,
        }));
        id
    }

    /// Log transfer totals when a connection closes.
    pub fn log_end(&self, id: &str, up: u64, down: u64, dur_ms: u128) {
        self.log_event(serde_json::json!({
            "ts": now_secs(),
            "ev": "end",
            "id": id,
            "up": up,
            "down": down,
            "dur_ms": dur_ms as u64,
        }));
    }

    /// Log cumulative transfer totals for a still-open connection, so long
    /// transfers (big downloads, streams) show up before they close. The
    /// counters are cumulative since connection start; consumers diff them
    /// against the previous progress event for the same id.
    pub fn log_progress(&self, id: &str, up: u64, down: u64) {
        self.log_event(serde_json::json!({
            "ts": now_secs(),
            "ev": "progress",
            "id": id,
            "up": up,
            "down": down,
        }));
    }

    /// Log one DNS query seen on the bridge. `blocked` marks queries that
    /// were refused by the rules without being forwarded.
    pub fn log_dns(&self, qname: &str, qtype: &str, blocked: bool) {
        self.log_event(serde_json::json!({
            "ts": now_secs(),
            "ev": "dns",
            "qname": truncate_str(qname, 120),
            "qtype": qtype,
            "blocked": blocked,
        }));
    }
}

// ---------------------------------------------------------------------------
// IP → domain attribution (learned from forwarded DNS answers)
// ---------------------------------------------------------------------------

#[derive(Default)]
pub struct Attribution {
    map: Mutex<HashMap<IpAddr, (String, Instant, u32)>>,
}

impl Attribution {
    fn learn(&self, ip: IpAddr, host: &str, ttl_secs: u32) {
        if ttl_secs == 0 {
            return;
        }
        let mut m = self.map.lock().unwrap();
        if m.len() > 4096 {
            m.clear(); // crude bound; entries are cheap to re-learn
        }
        m.insert(
            ip,
            (host.to_ascii_lowercase(), Instant::now(), ttl_secs),
        );
    }

    fn lookup(&self, ip: &IpAddr) -> Option<String> {
        let m = self.map.lock().unwrap();
        if let Some((host, at, ttl)) = m.get(ip) {
            let max = (*ttl as u64).min(ATTRIB_MAX_TTL) as u128;
            if at.elapsed().as_millis() < max * 1000 {
                return Some(host.clone());
            }
        }
        None
    }
}

// ---------------------------------------------------------------------------
// DNS message parsing
// ---------------------------------------------------------------------------

/// Parse the QNAME starting at offset 12 (after the fixed header), following
/// compression pointers. Returns (qname, offset after the name field).
fn parse_qname(msg: &[u8]) -> Option<(String, usize)> {
    if msg.len() < 13 {
        return None;
    }
    let mut labels: Vec<String> = Vec::new();
    let mut pos = 12;
    let mut jumps = 0;
    let mut end_after_ptr: Option<usize> = None;
    loop {
        let len = *msg.get(pos)?;
        if len & 0xC0 == 0xC0 {
            jumps += 1;
            if jumps > 4 {
                return None;
            }
            if end_after_ptr.is_none() {
                end_after_ptr = Some(pos + 2);
            }
            let ptr = (((len & 0x3F) as usize) << 8) | (*msg.get(pos + 1)? as usize);
            pos = ptr;
            continue;
        }
        pos += 1;
        if len == 0 {
            break;
        }
        let label = msg.get(pos..pos + len as usize)?;
        labels.push(String::from_utf8_lossy(label).into_owned());
        pos += len as usize;
    }
    if labels.is_empty() {
        return None; // root query — nothing to log
    }
    Some((labels.join(".").to_ascii_lowercase(), end_after_ptr.unwrap_or(pos)))
}

/// Skip a (possibly compressed) domain name field; returns the offset after
/// it. A compression pointer terminates the field (2 bytes).
fn skip_dns_name(msg: &[u8], mut pos: usize) -> Option<usize> {
    loop {
        let len = *msg.get(pos)?;
        if len & 0xC0 == 0xC0 {
            return Some(pos + 2);
        }
        pos += 1;
        if len == 0 {
            return Some(pos);
        }
        pos += len as usize;
    }
}

fn qtype_name(t: u16) -> String {
    match t {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        6 => "SOA",
        12 => "PTR",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        33 => "SRV",
        65 => "HTTPS",
        255 => "ANY",
        _ => return format!("TYPE{t}"),
    }
    .to_string()
}

/// Query type of a DNS message (after the QNAME).
fn dns_qtype(msg: &[u8]) -> String {
    if let Some((_, end)) = parse_qname(msg) {
        if end + 4 <= msg.len() {
            let t = u16::from_be_bytes([msg[end], msg[end + 1]]);
            return qtype_name(t);
        }
    }
    "?".into()
}

/// Extract A/AAAA records (ip, ttl) from a DNS response.
fn extract_answer_ips(msg: &[u8]) -> Vec<(IpAddr, u32)> {
    let mut out = Vec::new();
    let Some((_, qend)) = parse_qname(msg) else {
        return out;
    };
    if msg.len() < 12 || qend + 4 > msg.len() {
        return out;
    }
    let ancount = u16::from_be_bytes([msg[6], msg[7]]) as usize;
    let mut pos = qend + 4; // skip qtype + qclass
    for _ in 0..ancount {
        let Some(p) = skip_dns_name(msg, pos) else { return out };
        pos = p;
        if pos + 10 > msg.len() {
            return out; // type(2) class(2) ttl(4) rdlen(2)
        }
        let rtype = u16::from_be_bytes([msg[pos], msg[pos + 1]]);
        let ttl = u32::from_be_bytes([
            msg[pos + 4],
            msg[pos + 5],
            msg[pos + 6],
            msg[pos + 7],
        ]);
        let rdlen = u16::from_be_bytes([msg[pos + 8], msg[pos + 9]]) as usize;
        pos += 10;
        let Some(end) = pos.checked_add(rdlen) else { return out };
        if end > msg.len() {
            return out;
        }
        match rtype {
            1 if rdlen == 4 => out.push((
                IpAddr::V4(std::net::Ipv4Addr::new(
                    msg[pos],
                    msg[pos + 1],
                    msg[pos + 2],
                    msg[pos + 3],
                )),
                ttl,
            )),
            28 if rdlen == 16 => {
                let mut o = [0u8; 16];
                o.copy_from_slice(&msg[pos..pos + 16]);
                out.push((IpAddr::V6(o.into()), ttl));
            }
            _ => {}
        }
        pos = end;
    }
    out
}

// ---------------------------------------------------------------------------
// Byte counting
// ---------------------------------------------------------------------------

#[derive(Default, Clone)]
struct Counters {
    up: Arc<AtomicU64>,
    down: Arc<AtomicU64>,
}

/// Copy src → dst counting bytes into `n`.
fn copy_count(src: &mut impl Read, dst: &mut impl Write, n: &AtomicU64) {
    let mut buf = [0u8; 8192];
    loop {
        match src.read(&mut buf) {
            Ok(0) => break,
            Ok(k) => {
                if dst.write_all(&buf[..k]).is_err() {
                    break;
                }
                n.fetch_add(k as u64, Ordering::Relaxed);
            }
            Err(_) => break,
        }
    }
    let _ = dst.flush();
}

/// Bidirectional copy between the unix stream and the TCP stream, counting
/// upload (unix → tcp) and download (tcp → unix).
fn pump_bidir(a: &mut UnixStream, b: &mut TcpStream, ctr: Counters) {
    let mut a2 = match a.try_clone() {
        Ok(s) => s,
        Err(_) => return,
    };
    let mut b2 = match b.try_clone() {
        Ok(s) => s,
        Err(_) => return,
    };
    let up_ctr = ctr.clone();
    let t1 = std::thread::spawn(move || {
        copy_count(&mut a2, &mut b2, &up_ctr.up);
        let _ = b2.shutdown(std::net::Shutdown::Write);
    });
    copy_count(b, a, &ctr.down);
    let _ = t1.join();
}

/// Bidirectional copy between a TCP client and the unix bridge (ns side, no
/// counting needed there).
fn pump_bidir_tcp_unix(a: &mut TcpStream, b: &mut UnixStream) {
    let ctr = Counters::default();
    let mut a2 = match a.try_clone() {
        Ok(s) => s,
        Err(_) => return,
    };
    let mut b2 = match b.try_clone() {
        Ok(s) => s,
        Err(_) => return,
    };
    let up_ctr = ctr.clone();
    let t1 = std::thread::spawn(move || {
        copy_count(&mut a2, &mut b2, &up_ctr.up);
        let _ = b2.shutdown(std::net::Shutdown::Write);
    });
    copy_count(b, a, &ctr.down);
    let _ = t1.join();
}

// ---------------------------------------------------------------------------
// HOST SIDE
// ---------------------------------------------------------------------------

/// HOST SIDE: listen on `socket_path`, accept one bridge connection per
/// proxied stream. Protocol per connection:
///   client → frame("CONNECT host:port")   (or frame("DNS") + framed payloads)
///   host   → frame("OK") | frame("ERR reason")
///   then raw bidirectional byte stream (TCP) / framed datagrams (DNS).
///
/// `allow_path`: JSON file with the `AllowList`. Read at startup and
/// re-loaded automatically when the file's mtime changes (the UI rewrites it
/// on sandbox edits / log-viewer allow-deny actions), so rule changes take
/// effect on running apps within the poll interval.
///
/// `log_path` (optional): JSONL event log with conn/end/dns events.
pub fn run_host_bridge(
    socket_path: &str,
    allow_path: &std::path::Path,
    log_path: Option<String>,
) -> std::io::Result<()> {
    let listener = UnixListener::bind(socket_path)?;
    let logger = Arc::new(
        log_path
            .map(|p| EventLogger::new(PathBuf::from(p)))
            .unwrap_or_else(EventLogger::disabled),
    );
    let attribution = Arc::new(Attribution::default());
    let allow = Arc::new(std::sync::RwLock::new(read_allow_file(allow_path)));

    // Self-exit: the launcher's watcher deletes the socket file when the app
    // exits; poll for that so detached bridges don't linger forever. The same
    // poll reloads the allowlist when the UI rewrites the file.
    {
        let path = PathBuf::from(socket_path);
        let allow_path = PathBuf::from(allow_path);
        let allow = allow.clone();
        std::thread::spawn(move || {
            let mut mtime = file_mtime(&allow_path);
            loop {
                std::thread::sleep(Duration::from_secs(2));
                if !path.exists() {
                    std::process::exit(0);
                }
                let m = file_mtime(&allow_path);
                if m != mtime {
                    mtime = m;
                    match std::fs::read_to_string(&allow_path)
                        .map_err(|e| e.to_string())
                        .and_then(|s| serde_json::from_str::<AllowList>(&s).map_err(|e| e.to_string()))
                    {
                        Ok(list) => {
                            *allow.write().unwrap() = list;
                        }
                        Err(e) => {
                            // keep serving with the previous rules
                            eprintln!("jail bridge: allowlist reload failed: {e}");
                        }
                    }
                }
            }
        });
    }

    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        let allow = allow.clone();
        let logger = logger.clone();
        let attribution = attribution.clone();
        std::thread::spawn(move || {
            let _ = handle_bridge_conn(stream, allow, logger, attribution);
        });
    }
    Ok(())
}

fn file_mtime(path: &std::path::Path) -> Option<std::time::SystemTime> {
    std::fs::metadata(path).and_then(|m| m.modified()).ok()
}

/// Read + parse the allowlist file; a missing or invalid file yields an
/// empty whitelist (deny-all for non-loopback) so a broken file never
/// silently widens access.
fn read_allow_file(path: &std::path::Path) -> AllowList {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn handle_bridge_conn(
    mut stream: UnixStream,
    allow: Arc<std::sync::RwLock<AllowList>>,
    logger: Arc<EventLogger>,
    attribution: Arc<Attribution>,
) -> std::io::Result<()> {
    let req = read_frame(&mut stream)?;
    let req = String::from_utf8_lossy(&req).into_owned();
    if req == "DNS" {
        return handle_dns_bridge(stream, allow, logger, attribution);
    }
    let Some(target) = req.strip_prefix("CONNECT ") else {
        logger.log_conn(&truncate_str(&req, 120), 0, false, "bad-request");
        write_frame(&mut stream, b"ERR bad request")?;
        return Ok(());
    };
    let Some((host, port)) = parse_host_port(target.trim()) else {
        logger.log_conn(&truncate_str(target.trim(), 120), 0, false, "bad-target");
        write_frame(&mut stream, b"ERR bad target")?;
        return Ok(());
    };

    // Decide: direct rule match on the CONNECT host, or — when the app
    // connected by IP — a domain learned from its earlier DNS queries
    // (attribution). The lookup runs in BOTH modes: in blacklist mode a
    // bare-IP connect must still be denied when it resolves to a listed
    // domain, otherwise the list could be bypassed by connecting to the IP.
    let allow = allow.read().unwrap().clone();
    let mut decision = allow.decide(&host);
    let mut effective_host = host.clone();
    if !decision.0 {
        if let Ok(ip) = host.parse::<IpAddr>() {
            if let Some(domain) = attribution.lookup(&ip) {
                let d = allow.decide(&domain);
                if d.0 != decision.0 || d.0 {
                    // attribution changed the outcome (or confirmed allow
                    // with a better reason): use the domain view
                    decision = d;
                    effective_host = format!("{host} ({domain})");
                }
            }
        }
    }
    let (allowed, via) = decision;
    if !allowed {
        logger.log_conn(&host, port, false, via);
        write_frame(&mut stream, b"ERR denied by rules")?;
        return Ok(());
    }

    // resolve + connect on the host side
    let addrs: Vec<SocketAddr> = format!("{host}:{port}")
        .to_socket_addrs()
        .map(|it| it.collect())
        .unwrap_or_default();
    let mut upstream: Option<TcpStream> = None;
    for addr in addrs {
        if let Ok(s) = TcpStream::connect_timeout(&addr, Duration::from_secs(8)) {
            upstream = Some(s);
            break;
        }
    }
    let Some(mut upstream) = upstream else {
        logger.log_conn(&host, port, false, "connect-failed");
        write_frame(&mut stream, b"ERR connect failed")?;
        return Ok(());
    };
    let id = logger.log_conn(&effective_host, port, true, via);
    write_frame(&mut stream, b"OK")?;
    let started = Instant::now();
    let counters = Counters::default();

    // progress ticker: while the connection is open, emit cumulative byte
    // counts every second so long transfers are visible before they close
    {
        let logger = logger.clone();
        let id = id.clone();
        let counters = counters.clone();
        std::thread::spawn(move || {
            let mut last_up = 0u64;
            let mut last_down = 0u64;
            loop {
                std::thread::sleep(Duration::from_secs(1));
                let up = counters.up.load(Ordering::Relaxed);
                let down = counters.down.load(Ordering::Relaxed);
                if up == last_up && down == last_down {
                    continue; // idle connection: no noise
                }
                logger.log_progress(&id, up, down);
                last_up = up;
                last_down = down;
            }
        });
    }

    pump_bidir(&mut stream, &mut upstream, counters.clone());
    logger.log_end(
        &id,
        counters.up.load(Ordering::Relaxed),
        counters.down.load(Ordering::Relaxed),
        started.elapsed().as_millis(),
    );
    Ok(())
}

fn handle_dns_bridge(
    mut stream: UnixStream,
    allow: Arc<std::sync::RwLock<AllowList>>,
    logger: Arc<EventLogger>,
    attribution: Arc<Attribution>,
) -> std::io::Result<()> {
    // read framed DNS queries, answer with framed responses
    loop {
        let query = match read_frame(&mut stream) {
            Ok(q) => q,
            Err(_) => return Ok(()),
        };
        let qname_info = parse_qname(&query);
        // DNS interception: per the app's rules (mode + domain entries),
        // refuse queries for names that must not resolve. Decision happens
        // here on the host side so rule edits take effect dynamically.
        let blocked = qname_info
            .as_ref()
            .map(|(qname, _)| !allow.read().unwrap().decide_dns(qname))
            .unwrap_or(false); // unparseable queries: forward (conservative)
        if let Some((qname, _)) = &qname_info {
            logger.log_dns(qname, &dns_qtype(&query), blocked);
        }
        let resp = if blocked {
            build_dns_refused(&query)
        } else {
            let resp = forward_dns(&query);
            if !resp.is_empty() {
                if let Some((qname, _)) = &qname_info {
                    for (ip, ttl) in extract_answer_ips(&resp) {
                        attribution.learn(ip, qname, ttl);
                    }
                }
            }
            resp
        };
        write_frame(&mut stream, &resp)?;
    }
}

/// Build a DNS REFUSED (rcode 5) response by echoing the query with patched
/// flags: QR=1 (response), RA=1 (recursion available), RCODE=5. The question
/// section is preserved verbatim; zero answer records (the query carries
/// none, and ANCOUNT/NSCOUNT/ARCOUNT in the copied header stay 0).
fn build_dns_refused(query: &[u8]) -> Vec<u8> {
    let mut resp = query.to_vec();
    if resp.len() >= 4 {
        resp[2] |= 0x80; // QR = response
        resp[3] = (resp[3] & 0xF0) | 0x80 | 0x05; // RA=1, RCODE=REFUSED
    }
    resp
}

fn forward_dns(query: &[u8]) -> Vec<u8> {
    use std::net::UdpSocket;
    let resolvers = system_resolvers();
    for resolver in &resolvers {
        let addr = SocketAddr::new(*resolver, 53);
        if let Ok(sock) = UdpSocket::bind(if addr.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }) {
            if sock.set_read_timeout(Some(Duration::from_secs(3))).is_ok() {
                if sock.send_to(query, addr).is_ok() {
                    let mut buf = vec![0u8; 4096];
                    if let Ok(n) = sock.recv(&mut buf) {
                        buf.truncate(n);
                        return buf;
                    }
                }
            }
        }
    }
    Vec::new()
}

pub fn system_resolvers() -> Vec<IpAddr> {
    let mut out = Vec::new();
    if let Ok(text) = std::fs::read_to_string("/etc/resolv.conf") {
        for line in text.lines() {
            let line = line.trim();
            if let Some(ns) = line.strip_prefix("nameserver ") {
                if let Ok(ip) = ns.trim().parse::<IpAddr>() {
                    out.push(ip);
                }
            }
        }
    }
    if out.is_empty() {
        out.push("127.0.0.53".parse().unwrap());
    }
    out
}

pub fn parse_host_port(s: &str) -> Option<(String, u16)> {
    if let Some(rest) = s.strip_prefix('[') {
        // [v6]:port
        let (h, p) = rest.split_once("]:")?;
        return Some((h.to_string(), p.parse().ok()?));
    }
    let (h, p) = s.rsplit_once(':')?;
    Some((h.to_string(), p.parse().ok()?))
}

/// Parse the authority of an absolute URI in a plain-HTTP proxy request
/// (`GET http://example.com/path HTTP/1.1` → example.com:80).
fn parse_absolute_http(target: &str) -> Option<(String, u16)> {
    let rest = target.strip_prefix("http://")?;
    let authority = rest.split(['/', '?', '#']).next()?;
    if authority.is_empty() {
        return None;
    }
    Some(match parse_host_port(authority) {
        Some((h, p)) => (h, if p == 0 { 80 } else { p }),
        None => (authority.to_string(), 80),
    })
}

// ---------------------------------------------------------------------------
// NS SIDE
// ---------------------------------------------------------------------------

/// NS SIDE: HTTP proxy on 127.0.0.1:`http_port` (CONNECT + absolute-URI;
/// picked randomly per launch) and DNS on 127.0.0.1:53 (TCP + UDP — fixed,
/// resolv.conf points there), relaying everything over `bridge_path`.
pub fn run_ns_relay(bridge_path: String, http_port: u16) -> std::io::Result<()> {
    let http = TcpListener::bind(("127.0.0.1", http_port))?;
    let dns = TcpListener::bind("127.0.0.1:53")?;
    let bridge = Arc::new(bridge_path.clone());

    // Self-exit: when the app dies, the launcher removes the bridge socket
    // file; without this poll the relay (a child of the exec'd app) would
    // keep its netns alive forever.
    {
        let path = PathBuf::from(&bridge_path);
        std::thread::spawn(move || loop {
            std::thread::sleep(Duration::from_secs(2));
            if !path.exists() {
                std::process::exit(0);
            }
        });
    }

    // DNS-over-TCP relay (glibc falls back to TCP when UDP truncates/fails).
    {
        let bridge = bridge.clone();
        std::thread::spawn(move || {
            for stream in dns.incoming() {
                let Ok(stream) = stream else { continue };
                let bridge = bridge.clone();
                std::thread::spawn(move || {
                    let _ = relay_dns_tcp(stream, &bridge);
                });
            }
        });
    }
    // DNS UDP listener: one thread per query so slow resolvers never queue
    // unrelated lookups behind each other.
    {
        let bridge = bridge.clone();
        std::thread::spawn(move || {
            use std::net::UdpSocket;
            let Ok(sock) = UdpSocket::bind("127.0.0.1:53") else { return };
            let mut buf = [0u8; 4096];
            loop {
                let (n, src) = match sock.recv_from(&mut buf) {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                let Ok(peer) = sock.try_clone() else { continue };
                let query = buf[..n].to_vec();
                let path = bridge.clone();
                std::thread::spawn(move || {
                    handle_dns_udp_query(peer, src, query, &path);
                });
            }
        });
    }
    // HTTP proxy (CONNECT and absolute-URI forms)
    for stream in http.incoming() {
        let Ok(stream) = stream else { continue };
        let bridge = bridge.clone();
        std::thread::spawn(move || {
            let _ = relay_http(stream, &bridge);
        });
    }
    Ok(())
}

/// Send one framed DNS query over the bridge and send the answer back via
/// `sock`. Runs on its own thread per query.
fn handle_dns_udp_query(
    sock: std::net::UdpSocket,
    src: std::net::SocketAddr,
    query: Vec<u8>,
    bridge_path: &str,
) {
    let Ok(mut bridge) = UnixStream::connect(bridge_path) else { return };
    if write_frame(&mut bridge, b"DNS").is_err() {
        return;
    }
    if write_frame(&mut bridge, &query).is_err() {
        return;
    }
    if let Ok(resp) = read_frame(&mut bridge) {
        if !resp.is_empty() {
            let _ = sock.send_to(&resp, src);
        }
    }
}

fn bridge_connect(path: &str, request: &[u8]) -> std::io::Result<UnixStream> {
    let mut s = UnixStream::connect(path)?;
    write_frame(&mut s, request)?;
    let resp = read_frame(&mut s)?;
    if resp.starts_with(b"OK") {
        Ok(s)
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            String::from_utf8_lossy(&resp).into_owned(),
        ))
    }
}

/// Handle one client connection on the ns-side HTTP proxy. Supports both the
/// CONNECT method (TLS and arbitrary TCP) and the classic absolute-URI form
/// used for plain HTTP (`GET http://host/path HTTP/1.1`).
fn relay_http(mut client: TcpStream, bridge_path: &str) -> std::io::Result<()> {
    // read the request head (ends at the first \r\n\r\n)
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        let n = client.read(&mut chunk)?;
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        if buf.len() > 16 * 1024 {
            return Ok(());
        }
    }
    let head = String::from_utf8_lossy(&buf);
    let first = head.lines().next().unwrap_or("");
    let mut parts = first.split_whitespace();
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("");

    let (hostport, replay) = if method.eq_ignore_ascii_case("CONNECT") {
        (target.to_string(), None)
    } else {
        match parse_absolute_http(target) {
            Some((h, p)) => (format!("{h}:{p}"), Some(buf.clone())),
            None => {
                let _ = client.write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n");
                return Ok(());
            }
        }
    };

    let mut bridge = match bridge_connect(bridge_path, format!("CONNECT {hostport}").as_bytes()) {
        Ok(s) => s,
        Err(e) => {
            let _ = client.write_all(
                format!("HTTP/1.1 403 {e}\r\nContent-Length: 0\r\n\r\n").as_bytes(),
            );
            return Ok(());
        }
    };
    let _ = client.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n");
    if let Some(head_bytes) = replay {
        let _ = bridge.write_all(&head_bytes);
    }
    pump_bidir_tcp_unix(&mut client, &mut bridge);
    Ok(())
}

/// DNS over TCP: 2-byte length prefix + message (RFC 1035 4.2.2).
fn relay_dns_tcp(mut client: TcpStream, bridge_path: &str) -> std::io::Result<()> {
    let mut bridge = UnixStream::connect(bridge_path)?;
    write_frame(&mut bridge, b"DNS")?;
    loop {
        // read one DNS-over-TCP message from the client
        let mut len_buf = [0u8; 2];
        if client.read_exact(&mut len_buf).is_err() {
            return Ok(());
        }
        let len = u16::from_be_bytes(len_buf) as usize;
        let mut query = vec![0u8; len];
        if client.read_exact(&mut query).is_err() {
            return Ok(());
        }
        write_frame(&mut bridge, &query)?;
        let resp = read_frame(&mut bridge)?;
        if resp.is_empty() {
            client.write_all(&0u16.to_be_bytes())?;
            continue;
        }
        client.write_all(&(resp.len() as u16).to_be_bytes())?;
        client.write_all(&resp)?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::AllowMode;

    fn allow(entries: &[&str], loopback: bool) -> AllowList {
        AllowList {
            mode: AllowMode::Whitelist,
            entries: entries.iter().map(|s| s.to_string()).collect(),
            loopback,
        }
    }

    fn deny(entries: &[&str], loopback: bool) -> AllowList {
        AllowList {
            mode: AllowMode::Blacklist,
            entries: entries.iter().map(|s| s.to_string()).collect(),
            loopback,
        }
    }

    #[test]
    fn allowlist_domains() {
        // exact match: no implicit subdomains anymore
        let a = allow(&["example.com"], true);
        assert_eq!(a.decide("example.com"), (true, "domain"));
        assert_eq!(a.decide("api.example.com"), (false, "not-in-whitelist"));
        assert_eq!(a.decide("a.b.example.com"), (false, "not-in-whitelist"));
        assert_eq!(a.decide("notexample.com"), (false, "not-in-whitelist"));
        assert_eq!(a.decide("github.com"), (false, "not-in-whitelist"));
        assert_eq!(a.decide("localhost"), (true, "loopback"));
        assert_eq!(a.decide("127.0.0.1"), (true, "loopback"));
        // match_reason stays the whitelist-era convenience API
        assert_eq!(a.match_reason("example.com"), Some("domain"));
        assert_eq!(a.match_reason("github.com"), None);
    }

    #[test]
    fn allowlist_wildcard_domains() {
        // wildcard: base itself + any depth of subdomains
        let a = allow(&["*.example.com"], false);
        assert_eq!(a.decide("api.example.com"), (true, "domain"));
        assert_eq!(a.decide("API.Example.COM"), (true, "domain"));
        assert_eq!(a.decide("example.com"), (true, "domain")); // base covered
        assert_eq!(a.decide("a.b.example.com"), (true, "domain")); // any depth
        assert_eq!(a.decide("notexample.com"), (false, "not-in-whitelist"));
        // deeper wildcard: base + any depth below it
        let b = allow(&["*.api.example.com"], false);
        assert_eq!(b.decide("v1.api.example.com"), (true, "domain"));
        assert_eq!(b.decide("x.v1.api.example.com"), (true, "domain"));
        // base itself covered too (consistent with *.example.com → example.com)
        assert_eq!(b.decide("api.example.com"), (true, "domain"));
        // case-insensitive entry
        let c = allow(&["*.EXAMPLE.com"], false);
        assert_eq!(c.decide("api.example.com"), (true, "domain"));
    }

    #[test]
    fn allowlist_ips_and_cidr() {
        let a = allow(&["1.1.1.1", "10.0.0.0/8", "fd00::/8"], false);
        assert_eq!(a.decide("1.1.1.1"), (true, "ip"));
        assert_eq!(a.decide("10.20.30.40"), (true, "cidr"));
        assert_eq!(a.decide("11.1.1.1"), (false, "not-in-whitelist"));
        assert_eq!(a.decide("192.168.1.1"), (false, "not-in-whitelist"));
        assert_eq!(a.decide("fd12::1"), (true, "cidr"));
        assert_eq!(a.decide("localhost"), (false, "loopback-denied"));
    }

    #[test]
    fn blacklist_domains() {
        let b = deny(&["tracker.evil.com", "*.ads.example.com"], true);
        // listed → denied (with the entry kind in the reason)
        assert_eq!(b.decide("tracker.evil.com"), (false, "blacklisted-domain"));
        assert_eq!(b.decide("a.ads.example.com"), (false, "blacklisted-domain"));
        // everything else → allowed
        assert_eq!(b.decide("www.baidu.com"), (true, "default-allow"));
        assert_eq!(b.decide("api.example.com"), (true, "default-allow"));
        // loopback switch still applies independently of the mode
        assert_eq!(b.decide("localhost"), (true, "loopback"));
        let b2 = deny(&["evil.com"], false);
        assert_eq!(b2.decide("localhost"), (false, "loopback-denied"));
    }

    #[test]
    fn blacklist_ips_and_cidr() {
        let b = deny(&["10.0.0.0/8", "1.1.1.1"], false);
        assert_eq!(b.decide("10.1.2.3"), (false, "blacklisted-cidr"));
        assert_eq!(b.decide("1.1.1.1"), (false, "blacklisted-ip"));
        assert_eq!(b.decide("8.8.8.8"), (true, "default-allow"));
        assert_eq!(b.decide("example.com"), (true, "default-allow"));
    }

    #[test]
    fn dns_decision_follows_mode() {
        // whitelist: listed domains resolve, everything else is refused
        let w = allow(&["www.baidu.com", "*.baidu.com"], true);
        assert!(w.decide_dns("www.baidu.com"));
        assert!(w.decide_dns("a1.baidu.com")); // wildcard, one label
        assert!(w.decide_dns("baidu.com")); // base itself covered by *.baidu.com
        assert!(w.decide_dns("a.b.baidu.com")); // any depth covered
        assert!(!w.decide_dns("github.com")); // not listed → refused
        // case-insensitive + trailing dot tolerance
        assert!(w.decide_dns("WWW.Baidu.COM."));
        // IP/CIDR entries don't apply to qnames
        let ip_only = allow(&["1.1.1.1", "10.0.0.0/8"], true);
        assert!(!ip_only.decide_dns("anything.com"));

        // blacklist: listed domains are refused, everything else resolves
        let b = deny(&["tracker.evil.com"], true);
        assert!(!b.decide_dns("tracker.evil.com"));
        assert!(b.decide_dns("www.baidu.com"));
        // trailing-dot form of a listed name is still caught
        assert!(!b.decide_dns("tracker.evil.com."));
    }

    #[test]
    fn dns_refused_response_shape() {
        let q = build_query("Evil.Example.COM", 16); // TYPE16, odd case
        let mut resp = build_dns_refused(&q);
        assert_eq!(resp.len(), q.len(), "question echoed verbatim");
        assert_eq!(&resp[12..], &q[12..], "question section preserved");
        assert_ne!(resp[2] & 0x80, 0, "QR set");
        assert_eq!(resp[3] & 0x0F, 5, "RCODE = REFUSED");
        assert_ne!(resp[3] & 0x80, 0, "RA set");
        // the parser still sees the original question
        let (name, _) = parse_qname(&resp).unwrap();
        assert_eq!(name, "evil.example.com");
        // idempotent-ish: applying to a response must not corrupt rcode
        resp = build_dns_refused(&resp);
        assert_eq!(resp[3] & 0x0F, 5);
    }

    #[test]
    fn cidr_math() {
        assert!(cidr_contains(
            "10.0.0.0".parse().unwrap(),
            8,
            "10.255.1.2".parse().unwrap()
        ));
        assert!(!cidr_contains(
            "10.0.0.0".parse().unwrap(),
            8,
            "11.0.0.1".parse().unwrap()
        ));
        assert!(cidr_contains(
            "fd00::".parse().unwrap(),
            8,
            "fd12::1".parse().unwrap()
        ));
    }

    #[test]
    fn parse_host_port_works() {
        assert_eq!(
            parse_host_port("example.com:443"),
            Some(("example.com".into(), 443))
        );
        assert_eq!(
            parse_host_port("[2606:4700::1111]:443"),
            Some(("2606:4700::1111".into(), 443))
        );
        assert_eq!(parse_host_port("bogus"), None);
    }

    #[test]
    fn absolute_http_targets() {
        assert_eq!(
            parse_absolute_http("http://example.com/path?q=1"),
            Some(("example.com".into(), 80))
        );
        assert_eq!(
            parse_absolute_http("http://example.com:8080/"),
            Some(("example.com".into(), 8080))
        );
        assert_eq!(parse_absolute_http("https://example.com/"), None);
        assert_eq!(parse_absolute_http("/relative/path"), None);
    }

    // -- DNS message helpers for tests -------------------------------------

    fn build_query(qname: &str, qtype: u16) -> Vec<u8> {
        let mut m = vec![0u8; 12];
        m[4] = 0;
        m[5] = 1; // QDCOUNT = 1
        for label in qname.split('.') {
            m.push(label.len() as u8);
            m.extend_from_slice(label.as_bytes());
        }
        m.push(0);
        m.extend_from_slice(&qtype.to_be_bytes());
        m.extend_from_slice(&1u16.to_be_bytes()); // QCLASS = IN
        m
    }

    fn build_response(qname: &str, qtype: u16, ip: IpAddr, ttl: u32) -> Vec<u8> {
        let mut m = build_query(qname, qtype);
        m[2] = 0x81; // QR=1, RD=1
        m[3] = 0x80; // RA=1
        m[6] = 0;
        m[7] = 1; // ANCOUNT = 1
        // answer: name = compression pointer to offset 12
        m.extend_from_slice(&[0xC0, 0x0C]);
        m.extend_from_slice(&qtype.to_be_bytes());
        m.extend_from_slice(&1u16.to_be_bytes()); // class IN
        m.extend_from_slice(&ttl.to_be_bytes());
        match ip {
            IpAddr::V4(v4) => {
                m.extend_from_slice(&4u16.to_be_bytes());
                m.extend_from_slice(&v4.octets());
            }
            IpAddr::V6(v6) => {
                m.extend_from_slice(&16u16.to_be_bytes());
                m.extend_from_slice(&v6.octets());
            }
        }
        m
    }

    #[test]
    fn qname_parsing() {
        let q = build_query("WWW.Example.COM", 1);
        let (name, end) = parse_qname(&q).unwrap();
        assert_eq!(name, "www.example.com");
        assert_eq!(dns_qtype(&q), "A");
        // name field ends right before qtype (2 bytes) + qclass (2 bytes)
        assert_eq!(q.len() - end, 4);
    }

    #[test]
    fn answer_ip_extraction() {
        let resp = build_response("api.example.com", 1, "93.184.216.34".parse().unwrap(), 120);
        let ips = extract_answer_ips(&resp);
        assert_eq!(
            ips,
            vec![("93.184.216.34".parse().unwrap(), 120)]
        );
        let resp6 = build_response("api.example.com", 28, "2606::1".parse().unwrap(), 60);
        assert_eq!(
            extract_answer_ips(&resp6),
            vec![("2606::1".parse().unwrap(), 60)]
        );
    }

    #[test]
    fn attribution_learn_and_expire() {
        let a = Attribution::default();
        a.learn("93.184.216.34".parse().unwrap(), "Example.COM", 120);
        assert_eq!(
            a.lookup(&"93.184.216.34".parse().unwrap()),
            Some("example.com".into())
        );
        // ttl=0 is not cached
        a.learn("1.2.3.4".parse().unwrap(), "zero.com", 0);
        assert_eq!(a.lookup(&"1.2.3.4".parse().unwrap()), None);
        // unknown ip
        assert_eq!(a.lookup(&"8.8.8.8".parse().unwrap()), None);
    }

    #[test]
    fn event_logger_writes_jsonl() {
        let dir = std::env::temp_dir().join(format!("jail-logtest-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("app.jsonl");
        {
            let logger = EventLogger::new(path.clone());
            let id = logger.log_conn("api.example.com", 443, true, "domain");
            logger.log_end(&id, 123, 4567, 900);
            logger.log_dns("api.example.com", "A", false);
        }
        let text = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 3);
        let c: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(c["ev"], "conn");
        assert_eq!(c["host"], "api.example.com");
        assert_eq!(c["ok"], true);
        assert_eq!(c["via"], "domain");
        let e: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(e["ev"], "end");
        assert_eq!(e["up"], 123);
        assert_eq!(e["down"], 4567);
        let d: serde_json::Value = serde_json::from_str(lines[2]).unwrap();
        assert_eq!(d["ev"], "dns");
        assert_eq!(d["qname"], "api.example.com");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn event_logger_disabled_drops() {
        let logger = EventLogger::disabled();
        logger.log_dns("x.com", "A", false); // must not panic
        let id = logger.log_conn("x.com", 443, true, "domain");
        logger.log_end(&id, 1, 2, 3);
    }
}
