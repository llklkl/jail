//! Proxy-based network sandbox transport.
//!
//! A fresh network namespace has no external interfaces at all, so the only
//! path out is a host-side process. UNIX sockets are filesystem objects and
//! work across network namespaces, which gives us a clean bridge:
//!
//! ```text
//! [app] → 127.0.0.1:8080 (HTTP CONNECT) → [ns relay] → AF_UNIX → [host bridge] → internet
//! [app] → 127.0.0.1:53 (DNS)           → [ns relay] → AF_UNIX → [host bridge] → resolver
//! ```
//!
//! The host bridge enforces the allowlist (domains + IPs + CIDR); the nft
//! rules inside the namespace allow loopback only, so direct connections
//! fail closed. Apps that ignore proxy env vars get no network at all.

use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs as _};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::Arc;

/// Framing over the AF_UNIX bridge: 2-byte big-endian length + payload.
const MAX_FRAME: usize = 64 * 1024;

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

/// Allowlist shared with the host bridge.
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct AllowList {
    /// lowercase domain suffixes (e.g. "example.com" matches api.example.com)
    pub domains: Vec<String>,
    /// exact IPs and CIDR strings
    pub ips: Vec<String>,
    /// allow loopback destinations (host-side 127.0.0.1)
    pub loopback: bool,
}

impl AllowList {
    pub fn matches(&self, host: &str, port: u16) -> bool {
        let _ = port;
        let host = host.trim_matches(['[', ']']).to_ascii_lowercase();
        if host == "localhost" || host.starts_with("127.") || host == "::1" {
            return self.loopback;
        }
        // exact IP?
        if let Ok(ip) = host.parse::<IpAddr>() {
            return self.ip_allowed(&ip);
        }
        // domain suffix match
        self.domains
            .iter()
            .any(|d| host == *d || host.ends_with(&format!(".{d}")))
    }

    fn ip_allowed(&self, ip: &IpAddr) -> bool {
        for entry in &self.ips {
            if let Some((net, plen)) = entry.split_once('/') {
                if let (Ok(net_ip), Ok(p)) = (net.parse::<IpAddr>(), plen.parse::<u8>()) {
                    if cidr_contains(net_ip, p, *ip) {
                        return true;
                    }
                }
            } else if let Ok(e) = entry.parse::<IpAddr>() {
                if &e == ip {
                    return true;
                }
            }
        }
        false
    }
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

/// HOST SIDE: listen on `socket_path`, accept one bridge connection per
/// proxied stream. Protocol per connection:
///   client → frame("CONNECT host:port")   (or frame("DNS") + framed payloads)
///   host   → frame("OK") | frame("ERR reason")
///   then raw bidirectional byte stream (TCP) / framed datagrams (DNS).
pub fn run_host_bridge(socket_path: &str, allow: AllowList) -> std::io::Result<()> {
    let listener = UnixListener::bind(socket_path)?;
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        let allow = allow.clone();
        std::thread::spawn(move || {
            let _ = handle_bridge_conn(stream, allow);
        });
    }
    Ok(())
}

fn handle_bridge_conn(mut stream: UnixStream, allow: AllowList) -> std::io::Result<()> {
    let req = read_frame(&mut stream)?;
    let req = String::from_utf8_lossy(&req).into_owned();
    if req == "DNS" {
        return handle_dns_bridge(stream);
    }
    let Some(target) = req.strip_prefix("CONNECT ") else {
        write_frame(&mut stream, b"ERR bad request")?;
        return Ok(());
    };
    let Some((host, port)) = parse_host_port(target.trim()) else {
        write_frame(&mut stream, b"ERR bad target")?;
        return Ok(());
    };
    if !allow.matches(&host, port) {
        write_frame(&mut stream, b"ERR denied by allowlist")?;
        return Ok(());
    }
    // resolve + connect on the host side
    let addrs: Vec<SocketAddr> = format!("{host}:{port}")
        .to_socket_addrs()
        .map(|it| it.collect())
        .unwrap_or_default();
    let mut upstream: Option<TcpStream> = None;
    for addr in addrs {
        if !allow.matches(&addr.ip().to_string(), port) && !allow.matches(&host, port) {
            continue;
        }
        if let Ok(s) = TcpStream::connect_timeout(&addr, std::time::Duration::from_secs(8)) {
            upstream = Some(s);
            break;
        }
    }
    let Some(mut upstream) = upstream else {
        write_frame(&mut stream, b"ERR connect failed")?;
        return Ok(());
    };
    write_frame(&mut stream, b"OK")?;
    pump_bidir(&mut stream, &mut upstream);
    Ok(())
}

fn handle_dns_bridge(mut stream: UnixStream) -> std::io::Result<()> {
    // read framed DNS queries, answer with framed responses
    loop {
        let query = match read_frame(&mut stream) {
            Ok(q) => q,
            Err(_) => return Ok(()),
        };
        // forward to the first host resolver over UDP via a temporary socket
        let resp = forward_dns(&query);
        write_frame(&mut stream, &resp)?;
    }
}

fn forward_dns(query: &[u8]) -> Vec<u8> {
    use std::net::UdpSocket;
    let resolvers = system_resolvers();
    for resolver in &resolvers {
        let addr = SocketAddr::new(*resolver, 53);
        if let Ok(sock) = UdpSocket::bind(if addr.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }) {
            if sock.set_read_timeout(Some(std::time::Duration::from_secs(3))).is_ok() {
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

/// Bidirectional copy between the unix stream and the TCP stream.
fn pump_bidir(a: &mut UnixStream, b: &mut TcpStream) {
    let mut a2 = match a.try_clone() {
        Ok(s) => s,
        Err(_) => return,
    };
    let mut b2 = match b.try_clone() {
        Ok(s) => s,
        Err(_) => return,
    };
    let t1 = std::thread::spawn(move || {
        let _ = std::io::copy(&mut a2, &mut b2);
        let _ = b2.shutdown(std::net::Shutdown::Write);
    });
    let _ = std::io::copy(b, a);
    let _ = t1.join();
}

/// NS SIDE: HTTP CONNECT proxy on 127.0.0.1:8080 + DNS on 127.0.0.1:53,
/// relaying everything over `bridge_path`.
pub fn run_ns_relay(bridge_path: String) -> std::io::Result<()> {
    let http = TcpListener::bind("127.0.0.1:8080")?;
    let dns = TcpListener::bind("127.0.0.1:53")?;
    let bridge = Arc::new(bridge_path);

    // DNS-over-TCP relay (glibc falls back to TCP when UDP truncates/fails;
    // musl and most resolvers try TCP too. We also listen on UDP below.)
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
    // DNS UDP listener
    {
        let bridge = bridge.clone();
        std::thread::spawn(move || relay_dns_udp(&bridge));
    }
    // HTTP CONNECT
    for stream in http.incoming() {
        let Ok(stream) = stream else { continue };
        let bridge = bridge.clone();
        std::thread::spawn(move || {
            let _ = relay_http_connect(stream, &bridge);
        });
    }
    Ok(())
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

fn relay_http_connect(mut client: TcpStream, bridge_path: &str) -> std::io::Result<()> {
    // read the request head (CONNECT host:port HTTP/1.x\r\n...\r\n\r\n)
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
    let target = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .unwrap_or("")
        .to_string();

    let request = format!("CONNECT {target}");
    let mut bridge = match bridge_connect(bridge_path, request.as_bytes()) {
        Ok(s) => s,
        Err(e) => {
            let _ = client.write_all(
                format!("HTTP/1.1 403 {e}\r\nContent-Length: 0\r\n\r\n").as_bytes(),
            );
            return Ok(());
        }
    };
    let _ = client.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n");
    pump_bidir_tcp_unix(&mut client, &mut bridge);
    Ok(())
}

fn pump_bidir_tcp_unix(a: &mut TcpStream, b: &mut UnixStream) {
    let mut a2 = match a.try_clone() {
        Ok(s) => s,
        Err(_) => return,
    };
    let mut b2 = match b.try_clone() {
        Ok(s) => s,
        Err(_) => return,
    };
    let t1 = std::thread::spawn(move || {
        let _ = std::io::copy(&mut a2, &mut b2);
        let _ = b2.shutdown(std::net::Shutdown::Write);
    });
    let _ = std::io::copy(b, a);
    let _ = t1.join();
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

/// DNS over UDP: single socket, framed queries over the bridge.
fn relay_dns_udp(bridge_path: &str) -> std::io::Result<()> {
    use std::net::UdpSocket;
    let sock = UdpSocket::bind("127.0.0.1:53")?;
    let mut bridge: Option<UnixStream> = None;
    let mut buf = [0u8; 4096];
    loop {
        let (n, src) = match sock.recv_from(&mut buf) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let b = match bridge.as_mut() {
            Some(b) => b,
            None => {
                let Ok(mut s) = UnixStream::connect(bridge_path) else { continue };
                if write_frame(&mut s, b"DNS").is_err() {
                    continue;
                }
                bridge = Some(s);
                bridge.as_mut().unwrap()
            }
        };
        if write_frame(b, &buf[..n]).is_err() {
            bridge = None;
            continue;
        }
        match read_frame(b) {
            Ok(resp) if !resp.is_empty() => {
                let _ = sock.send_to(&resp, src);
            }
            _ => {
                bridge = None;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowlist_domains() {
        let a = AllowList {
            domains: vec!["example.com".into()],
            ips: vec![],
            loopback: true,
        };
        assert!(a.matches("example.com", 443));
        assert!(a.matches("api.example.com", 443));
        assert!(!a.matches("notexample.com", 443));
        assert!(!a.matches("github.com", 443));
        assert!(a.matches("localhost", 8080));
        assert!(a.matches("127.0.0.1", 9000));
    }

    #[test]
    fn allowlist_ips() {
        let a = AllowList {
            domains: vec![],
            ips: vec!["1.1.1.1".into(), "10.0.0.0/8".into()],
            loopback: false,
        };
        assert!(a.matches("1.1.1.1", 443));
        assert!(a.matches("10.20.30.40", 443));
        assert!(!a.matches("11.1.1.1", 443));
        assert!(!a.matches("192.168.1.1", 443));
        assert!(!a.matches("localhost", 80));
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
}
