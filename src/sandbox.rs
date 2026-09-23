//! Network sandbox: nftables ruleset.
//!
//! The app runs inside `unshare`-created user + network namespaces without
//! root. The ruleset is loaded with raw nfnetlink (via `rustables`) from the
//! privileged setup phase of the ns-child process — no `nft` binary exec,
//! which would drop capabilities in the non-root design. The namespace has
//! no external interfaces, so ALL direct traffic fails; the only path out is
//! the loopback proxy relay (see `proxy.rs`), which the host bridge filters
//! against the allowlist.

use rustables::{Batch, Chain, ChainPolicy, Hook, HookClass, MsgType, ProtocolFamily, Rule, Table};
use std::net::IpAddr;

/// Name of the nftables table created inside each app's namespace.
const TABLE_NAME: &str = "jail";
/// Name of the output chain (policy drop; loopback rule optional).
const CHAIN_NAME: &str = "output";

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

/// Build the batch messages for the sandbox ruleset (without sending).
///
/// Inside the namespace only loopback traffic is allowed (the proxy relay
/// lives on 127.0.0.1); everything else is dropped. The allowlist itself is
/// enforced by the host-side bridge, which sees real hostnames — no
/// pre-launch DNS resolution is involved.
fn build_batch(allow_loopback: bool) -> Batch {
    let mut batch = Batch::new();
    let table = Table::new(ProtocolFamily::Inet).with_name(TABLE_NAME);
    batch.add(&table, MsgType::Add);
    let chain = Chain::new(&table)
        .with_name(CHAIN_NAME)
        .with_hook(Hook::new(HookClass::Out, 0))
        .with_policy(ChainPolicy::Drop)
        .add_to_batch(&mut batch);
    if allow_loopback {
        if let Ok(rule) = Rule::new(&chain) {
            rule.oiface("lo")
                .expect("oiface builds")
                .accept()
                .add_to_batch(&mut batch);
        }
    }
    batch
}

/// Load the sandbox ruleset into the current network namespace. Must be
/// called while the caller still holds capabilities in the owning user
/// namespace (i.e. from the ns-child setup phase, before the uid drop).
pub fn apply_ruleset(allow_loopback: bool) -> Result<(), String> {
    build_batch(allow_loopback)
        .send()
        .map_err(|e| format!("load nftables ruleset: {e}"))
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
        // build_batch must not panic for either loopback setting; actual
        // ruleset delivery is exercised by the e2e test in a real namespace.
        let _ = build_batch(true);
        let _ = build_batch(false);
    }

}
