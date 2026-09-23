//! Network sandbox: nftables ruleset generation and domain resolution.
//!
//! The app runs inside `unshare -Urn` (user + network namespace, no root
//! needed). Inside that namespace we are root, so nftables rules apply
//! without pkexec. The namespace has no external interfaces, so ALL direct
//! traffic fails; the only path out is the loopback proxy relay (see
//! `proxy.rs`), which the host bridge filters against the allowlist.

use crate::model::SandboxConfig;
use std::net::{IpAddr, ToSocketAddrs};

/// A validated IP or CIDR segment.
#[derive(Debug, Clone, PartialEq)]
#[allow(dead_code)] // reserved for future direct-IP nft mode
pub enum NetTarget {
    Ip(IpAddr),
    Cidr(String),
}

/// Parse the user-provided IP/CIDR list, skipping invalid entries.
#[allow(dead_code)] // reserved for future direct-IP nft mode
pub fn parse_ips(inputs: &[String]) -> Vec<NetTarget> {
    let mut out = Vec::new();
    for raw in inputs {
        let s = raw.trim();
        if s.is_empty() {
            continue;
        }
        if let Some((addr, plen)) = s.split_once('/') {
            if let Ok(ip) = addr.parse::<IpAddr>() {
                let max = if ip.is_ipv4() { 32 } else { 128 };
                if let Ok(p) = plen.parse::<u8>() {
                    if p as u32 <= max {
                        out.push(NetTarget::Cidr(format!("{ip}/{p}")));
                        continue;
                    }
                }
            }
        } else if let Ok(ip) = s.parse::<IpAddr>() {
            out.push(NetTarget::Ip(ip));
        }
    }
    out
}

/// Resolve domain names to IPs. Returns (resolved, failed).
/// Resolution uses the host resolver (works for VPN / private DNS before
/// the namespace is created).
pub fn resolve_domains(domains: &[String]) -> (Vec<IpAddr>, Vec<String>) {
    let mut ips = Vec::new();
    let mut failed = Vec::new();
    for d in domains {
        let d = d.trim();
        if d.is_empty() {
            continue;
        }
        // ToSocketAddrs needs host:port; use 443 as a dummy port.
        match format!("{d}:443").to_socket_addrs() {
            Ok(addrs) => {
                let mut any = false;
                for a in addrs {
                    if !ips.contains(&a.ip()) {
                        ips.push(a.ip());
                    }
                    any = true;
                }
                if !any {
                    failed.push(d.to_string());
                }
            }
            Err(_) => failed.push(d.to_string()),
        }
    }
    (ips, failed)
}

/// Build the complete nftables script for the sandbox.
///
/// Inside the namespace only loopback traffic is allowed (the proxy relay
/// lives on 127.0.0.1); everything else is dropped. The allowlist itself is
/// enforced by the host-side bridge, which sees real hostnames.
pub fn build_nft_script(cfg: &SandboxConfig, _resolved: &[IpAddr]) -> String {
    let mut lines = String::from(
        "add table inet applauncher\n\
         add chain inet applauncher output { type filter hook output priority 0; policy drop; }\n",
    );
    if cfg.allow_loopback {
        lines.push_str("add rule inet applauncher output oifname \"lo\" accept\n");
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ips_basic() {
        let ips = parse_ips(&[
            "10.0.0.1".into(),
            " 192.168.1.0/24 ".into(),
            "not-an-ip".into(),
            "fe80::1".into(),
            "10.0.0.2/33".into(), // invalid v4 prefix
            "".into(),
        ]);
        assert_eq!(
            ips,
            vec![
                NetTarget::Ip("10.0.0.1".parse().unwrap()),
                NetTarget::Cidr("192.168.1.0/24".into()),
                NetTarget::Ip("fe80::1".parse().unwrap()),
            ]
        );
    }

    #[test]
    fn nft_script_loopback_only() {
        let cfg = SandboxConfig {
            enabled: true,
            allow_domains: vec![],
            allow_ips: vec!["10.0.0.1".into(), "192.168.0.0/16".into()],
            allow_loopback: true,
        };
        let script = build_nft_script(&cfg, &["1.2.3.4".parse().unwrap()]);
        assert!(script.contains("add table inet applauncher"));
        assert!(script.contains("policy drop"));
        assert!(script.contains("oifname \"lo\" accept"));
        // allowlist lives in the host bridge, not in nft rules
        assert!(!script.contains("daddr"));
        assert!(!script.contains("dport"));
    }

    #[test]
    fn nft_script_no_loopback() {
        let cfg = SandboxConfig {
            enabled: true,
            allow_loopback: false,
            ..Default::default()
        };
        let script = build_nft_script(&cfg, &[]);
        assert!(!script.contains("oifname"));
    }

}
