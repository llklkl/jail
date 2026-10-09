//! Parsing and aggregation for the per-app JSONL request logs.
//!
//! The host bridge appends events:
//!   {"ts":..,"ev":"conn","id":"..","host":"..","port":443,"ok":true,"via":"domain"}
//!   {"ts":..,"ev":"end","id":"..","up":123,"down":456,"dur_ms":789}
//!   {"ts":..,"ev":"progress","id":"..","up":123,"down":456}
//!   {"ts":..,"ev":"dns","qname":"..","qtype":"A","blocked":false}
//!
//! The UI aggregates them per host for the summary view and keeps the raw
//! lines for the detail view.

use std::collections::HashMap;
use std::net::IpAddr;

/// One host's aggregated traffic.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct HostSummary {
    pub host: String,
    pub allowed: u64,
    pub denied: u64,
    pub dns: u64,
    /// DNS queries refused by the rules without being forwarded.
    pub dns_blocked: u64,
    pub up: u64,
    pub down: u64,
    pub last_ts: u64,
}

impl HostSummary {
    fn key_for(host: &str) -> String {
        // Attribute an "IP (domain)" host (learned attribution) to the
        // domain entry so aggregates stay readable.
        if let Some((_, domain)) = host.split_once(" (") {
            let d = domain.trim_end_matches(')');
            if !d.is_empty() {
                return d.to_ascii_lowercase();
            }
        }
        if host.parse::<IpAddr>().is_ok() {
            host.to_string()
        } else {
            host.to_ascii_lowercase()
        }
    }
}

/// Aggregate a full log text into per-host summaries, ordered lexicographically
/// by host key, capped at `max_hosts`.
///
/// Byte accounting: `end` events carry the connection's final totals;
/// `progress` events carry cumulative totals for still-open connections.
/// Per connection id we track the highest seen cumulative total (progress
/// and end overlap — the last progress may equal the end values), so bytes
/// are counted exactly once.
pub fn summarize(text: &str, max_hosts: usize) -> Vec<HostSummary> {
    let mut hosts: HashMap<String, HostSummary> = HashMap::new();
    // conn id → (host key, allowed) so byte events land on the right host
    let mut conns: HashMap<String, (String, bool)> = HashMap::new();
    // conn id → highest cumulative (up, down) already added to the summary
    let mut counted: HashMap<String, (u64, u64)> = HashMap::new();

    for line in text.lines() {
        let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        let ts = v.get("ts").and_then(|t| t.as_u64()).unwrap_or(0);
        match v.get("ev").and_then(|e| e.as_str()) {
            Some("conn") => {
                let host = v.get("host").and_then(|h| h.as_str()).unwrap_or("?");
                let ok = v.get("ok").and_then(|o| o.as_bool()).unwrap_or(false);
                let key = HostSummary::key_for(host);
                let entry = hosts.entry(key.clone()).or_default();
                entry.host = key.clone();
                if ok {
                    entry.allowed += 1;
                } else {
                    entry.denied += 1;
                }
                entry.last_ts = entry.last_ts.max(ts);
                if let Some(id) = v.get("id").and_then(|i| i.as_str()) {
                    conns.insert(id.to_string(), (key, ok));
                }
            }
            Some("progress") | Some("end") => {
                let (up, down) = (
                    v.get("up").and_then(|u| u.as_u64()).unwrap_or(0),
                    v.get("down").and_then(|d| d.as_u64()).unwrap_or(0),
                );
                if let Some((key, ok)) = v
                    .get("id")
                    .and_then(|i| i.as_str())
                    .and_then(|id| conns.get(id))
                    .cloned()
                {
                    if let Some(entry) = hosts.get_mut(&key) {
                        if ok {
                            // count only the delta above what was already
                            // counted for this connection (progress events
                            // are cumulative; end repeats the final total)
                            let seen = counted.entry(id_key(&v)).or_insert((0, 0));
                            if up > seen.0 {
                                entry.up += up - seen.0;
                                seen.0 = up;
                            }
                            if down > seen.1 {
                                entry.down += down - seen.1;
                                seen.1 = down;
                            }
                        }
                        entry.last_ts = entry.last_ts.max(ts);
                    }
                }
            }
            Some("dns") => {
                let qname = v.get("qname").and_then(|q| q.as_str()).unwrap_or("?");
                let blocked = v.get("blocked").and_then(|b| b.as_bool()).unwrap_or(false);
                let key = HostSummary::key_for(qname);
                let entry = hosts.entry(key.clone()).or_default();
                entry.host = key;
                if blocked {
                    entry.dns_blocked += 1;
                } else {
                    entry.dns += 1;
                }
                entry.last_ts = entry.last_ts.max(ts);
            }
            _ => {}
        }
    }

    let mut out: Vec<HostSummary> = hosts.into_values().collect();
    // lexicographic order by host key (domains and IPs interleave in one
    // stable, predictable list)
    out.sort_by(|a, b| a.host.cmp(&b.host));
    out.truncate(max_hosts);
    out
}

/// The connection id of a progress/end event.
fn id_key(v: &serde_json::Value) -> String {
    v.get("id")
        .and_then(|i| i.as_str())
        .unwrap_or("")
        .to_string()
}

/// Human-readable byte count.
pub fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut v = n as f64;
    let mut unit = 0;
    while v >= 1024.0 && unit < UNITS.len() - 1 {
        v /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", UNITS[unit])
    }
}

/// The last N lines of a log text (for the raw view). The input is expected
/// to contain complete lines only (TailState drops partial lines).
pub fn tail_lines(text: &str, n: usize) -> Vec<&str> {
    let lines: Vec<&str> = text.lines().collect();
    let skip = lines.len().saturating_sub(n);
    lines.into_iter().skip(skip).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
{"ts":100,"ev":"conn","id":"1:0","host":"www.baidu.com","port":443,"ok":true,"via":"domain"}
{"ts":101,"ev":"end","id":"1:0","up":1826,"down":5552,"dur_ms":92}
{"ts":102,"ev":"conn","id":"1:1","host":"github.com","port":443,"ok":false,"via":"denied"}
{"ts":103,"ev":"dns","qname":"www.baidu.com","qtype":"A","blocked":false}
{"ts":104,"ev":"conn","id":"1:2","host":"183.2.172.177 (www.baidu.com)","port":443,"ok":true,"via":"domain"}
{"ts":105,"ev":"end","id":"1:2","up":100,"down":200,"dur_ms":50}
{"ts":106,"ev":"dns","qname":"github.com","qtype":"A","blocked":true}
{"ts":107,"ev":"dns","qname":"tracker.evil.com","qtype":"AAAA","blocked":true}
"#;

    #[test]
    fn summarize_aggregates_and_sorts() {
        let s = summarize(SAMPLE, 100);
        assert_eq!(s.len(), 3);
        // baidu: 2 allowed conns (one via attribution) + 1 dns + bytes
        let baidu = s.iter().find(|h| h.host == "www.baidu.com").unwrap();
        assert_eq!(baidu.allowed, 2);
        assert_eq!(baidu.dns, 1);
        assert_eq!(baidu.dns_blocked, 0);
        assert_eq!(baidu.up, 1926);
        assert_eq!(baidu.down, 5752);
        // github: denied connect + refused dns
        let gh = s.iter().find(|h| h.host == "github.com").unwrap();
        assert_eq!(gh.denied, 1);
        assert_eq!(gh.allowed, 0);
        assert_eq!(gh.dns_blocked, 1);
        assert_eq!(gh.dns, 0);
        assert_eq!(gh.up + gh.down, 0);
        // sorted lexicographically: github.com < tracker.evil.com < www.baidu.com
        assert_eq!(s[0].host, "github.com");
        assert_eq!(s[1].host, "tracker.evil.com");
        assert_eq!(s[2].host, "www.baidu.com");
    }

    #[test]
    fn summarize_cap() {
        let s = summarize(SAMPLE, 1);
        assert_eq!(s.len(), 1);
        // first in lexicographic order
        assert_eq!(s[0].host, "github.com");
    }

    #[test]
    fn human_bytes_units() {
        assert_eq!(human_bytes(0), "0 B");
        assert_eq!(human_bytes(999), "999 B");
        assert_eq!(human_bytes(1024), "1.0 KB");
        assert_eq!(human_bytes(1536), "1.5 KB");
        assert_eq!(human_bytes(5 * 1024 * 1024), "5.0 MB");
        assert_eq!(human_bytes(3 * 1024 * 1024 * 1024), "3.0 GB");
    }

    #[test]
    fn tail_keeps_last_lines() {
        let lines = tail_lines("a\nb\nc\nd", 2);
        assert_eq!(lines, vec!["c", "d"]);
        assert_eq!(tail_lines("", 5), Vec::<&str>::new());
        assert_eq!(tail_lines("x", 5), vec!["x"]);
    }

    #[test]
    fn progress_events_count_increments_live() {
        // a long download: progress events while open, end when closed —
        // bytes must be counted exactly once (deltas, not repeats)
        let text = r#"
{"ts":100,"ev":"conn","id":"9:0","host":"cdn.example.com","port":443,"ok":true,"via":"default-allow"}
{"ts":101,"ev":"progress","id":"9:0","up":100,"down":1000}
{"ts":102,"ev":"progress","id":"9:0","up":100,"down":5000}
{"ts":103,"ev":"progress","id":"9:0","up":100,"down":9000}
{"ts":104,"ev":"end","id":"9:0","up":100,"down":9000,"dur_ms":3000}
"#;
        let s = summarize(text, 10);
        let c = s.iter().find(|h| h.host == "cdn.example.com").unwrap();
        assert_eq!(c.allowed, 1);
        assert_eq!(c.up, 100);
        assert_eq!(c.down, 9000, "progress deltas counted once, end not double");
    }

    #[test]
    fn progress_only_open_connection_visible() {
        // no end event at all (still downloading): progress bytes still show
        let text = r#"
{"ts":100,"ev":"conn","id":"9:1","host":"cdn.example.com","port":443,"ok":true,"via":"default-allow"}
{"ts":101,"ev":"progress","id":"9:1","up":0,"down":42700000}
"#;
        let s = summarize(text, 10);
        let c = s.iter().find(|h| h.host == "cdn.example.com").unwrap();
        assert_eq!(c.down, 42_700_000);
    }
}
