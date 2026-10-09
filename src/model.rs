//! Data models for launcher entries and sandbox configuration.

use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// A sandbox allowlist entry: a domain (exact, or `*.example.com` wildcard
/// matching the base plus any depth of subdomains) or an IP / CIDR.
#[derive(Debug, Clone, PartialEq)]
pub enum EntryKind {
    /// domain name: `example.com` matches only itself;
    /// `*.example.com` matches `example.com` itself and ANY depth of
    /// subdomains (api.example.com ✓, a.b.example.com ✓)
    Domain,
    /// single IP address
    Ip,
    /// network in CIDR notation (net, prefix length)
    Cidr { plen: u8 },
}

/// Classify one user-provided allowlist entry. Returns None when invalid.
/// This is the single source of truth for entry syntax, shared by the UI
/// (validation) and the host bridge (matching).
pub fn classify_entry(raw: &str) -> Option<EntryKind> {
    let s = raw.trim();
    if s.is_empty() {
        return None;
    }
    if let Some((net, plen)) = s.split_once('/') {
        let ip = net.parse::<IpAddr>().ok()?;
        let p: u8 = plen.parse().ok()?;
        let max = match ip {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if p > max {
            return None;
        }
        Some(EntryKind::Cidr { plen: p })
    } else if s.parse::<IpAddr>().is_ok() {
        Some(EntryKind::Ip)
    } else {
        // A domain: letters/digits/hyphen labels separated by dots, with an
        // optional leftmost wildcard label (`*.example.com`). We keep this
        // permissive (no punycode validation) but reject whitespace,
        // slashes, ports and other obvious garbage.
        if s.chars().any(|c| {
            c.is_whitespace() || matches!(c, '/' | '\\' | ':' | '@' | '?' | '#' | '%' | ',')
        }) {
            return None;
        }
        let labels: Vec<&str> = s.split('.').collect();
        if labels.iter().any(|l| l.is_empty()) {
            return None;
        }
        let wildcard = labels.first() == Some(&"*");
        if wildcard && labels.len() < 2 {
            return None; // bare "*"
        }
        // '*' is only allowed as the entire first label (no a.*.com, no api*.com)
        if labels.iter().enumerate().any(|(i, l)| l.contains('*') && !(wildcard && i == 0)) {
            return None;
        }
        Some(EntryKind::Domain)
    }
}

/// How the entry list is interpreted by the proxy bridge.
///
/// - `Whitelist` (default): entries are allowed, everything else is denied.
/// - `Blacklist`: entries are denied, everything else is allowed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AllowMode {
    #[default]
    Whitelist,
    Blacklist,
}

impl AllowMode {
    #[allow(dead_code)] // reserved for mode-aware UI labels
    pub fn title(self) -> &'static str {
        match self {
            AllowMode::Whitelist => "白名单",
            AllowMode::Blacklist => "黑名单",
        }
    }
}

/// Raw shape of the persisted config, used to migrate the legacy
/// `allow_domains` + `allow_ips` fields into the unified `allow_entries`.
#[derive(Deserialize, Default)]
struct RawConfig {
    #[serde(default)]
    allow_domains: Vec<String>,
    #[serde(default)]
    allow_ips: Vec<String>,
    #[serde(default)]
    allow_entries: Vec<String>,
    #[serde(default)]
    allow_loopback: Option<bool>,
    #[serde(default)]
    allow_mode: Option<AllowMode>,
    #[serde(default)]
    enabled: bool,
}

impl From<RawConfig> for SandboxConfig {
    fn from(raw: RawConfig) -> Self {
        // Merge legacy fields first, then append modern entries, deduped.
        let mut entries: Vec<String> = Vec::new();
        for e in raw
            .allow_domains
            .into_iter()
            .chain(raw.allow_ips)
            .chain(raw.allow_entries)
        {
            let e = e.trim().to_string();
            if !e.is_empty() && !entries.iter().any(|x| x.eq_ignore_ascii_case(&e)) {
                entries.push(e);
            }
        }
        SandboxConfig {
            enabled: raw.enabled,
            allow_entries: entries,
            allow_loopback: raw.allow_loopback.unwrap_or(true),
            allow_mode: raw.allow_mode.unwrap_or_default(),
        }
    }
}

/// Per-application sandbox configuration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(from = "RawConfig")]
pub struct SandboxConfig {
    /// Whether sandboxing is enabled for this app.
    #[serde(default)]
    pub enabled: bool,
    /// Unified allowlist: domains (wildcard = any-depth suffix), IPs, CIDR ranges.
    #[serde(default)]
    pub allow_entries: Vec<String>,
    /// Allow loopback + DNS to the system resolver (default true).
    #[serde(default)]
    pub allow_loopback: bool,
    /// How `allow_entries` is interpreted (default: whitelist).
    #[serde(default)]
    pub allow_mode: AllowMode,
}

impl SandboxConfig {}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            allow_entries: Vec::new(),
            allow_loopback: true,
            allow_mode: AllowMode::default(),
        }
    }
}

/// One launcher entry, backed by a system .desktop file.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AppEntry {
    pub id: String,
    /// e.g. "org.mozilla.firefox.desktop"
    pub desktop_id: String,
    pub name: String,
    /// Icon name (freedesktop icon theme name) or absolute path.
    pub icon: String,
    /// Exec value with field codes (%f %u etc.) removed.
    pub exec: String,
    #[serde(default)]
    pub sandbox: SandboxConfig,
}

impl AppEntry {
    pub fn new(desktop_id: String, name: String, icon: String, exec: String) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            desktop_id,
            name,
            icon,
            exec,
            sandbox: SandboxConfig::default(),
        }
    }
}

/// Remove freedesktop Exec field codes (" %f", "%u", etc.).
/// Quoted "%%" is an escaped percent.
pub fn strip_field_codes(exec: &str) -> String {
    let mut out = String::with_capacity(exec.len());
    let mut chars = exec.chars().peekable();
    let mut in_single = false;
    let mut in_double = false;
    while let Some(c) = chars.next() {
        match c {
            '\'' if !in_double => in_single = !in_single,
            '"' if !in_single => in_double = !in_double,
            '\\' if in_double => {
                if let Some(&n) = chars.peek() {
                    if n == '%' || n == '"' || n == '\\' {
                        out.push('\\');
                        out.push(chars.next().unwrap());
                        continue;
                    }
                }
                out.push(c);
            }
            '%' if !in_single => {
                match chars.next() {
                    Some('%') => out.push('%'),
                    // deprecated field codes and modifiers: drop
                    Some(_) | None => {}
                }
                continue;
            }
            _ => {}
        }
        out.push(c);
    }
    out.trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_field_codes_basic() {
        assert_eq!(strip_field_codes("firefox %u"), "firefox");
        assert_eq!(strip_field_codes("code --open %F"), "code --open");
        assert_eq!(strip_field_codes("gedit %U"), "gedit");
    }

    #[test]
    fn strip_field_codes_keeps_percent() {
        // "%%" is an escaped literal percent
        assert_eq!(strip_field_codes("app --progress=50%%"), "app --progress=50%");
        assert_eq!(strip_field_codes("app %%(x)"), "app %(x)");
    }

    #[test]
    fn strip_field_codes_quoted() {
        // % inside single quotes is a literal percent sign per spec, kept as-is
        assert_eq!(strip_field_codes("sh -c 'echo %f'"), "sh -c 'echo %f'");
        // unquoted codes are removed
        assert_eq!(strip_field_codes("app %f"), "app");
    }

    #[test]
    fn sandbox_config_defaults() {
        let cfg = SandboxConfig::default();
        assert!(!cfg.enabled);
        assert!(cfg.allow_loopback);
        assert!(cfg.allow_entries.is_empty());
        assert_eq!(cfg.allow_mode, AllowMode::Whitelist);
    }

    #[test]
    fn allow_mode_serializes_lowercase() {
        assert_eq!(
            serde_json::to_string(&AllowMode::Whitelist).unwrap(),
            "\"whitelist\""
        );
        assert_eq!(
            serde_json::to_string(&AllowMode::Blacklist).unwrap(),
            "\"blacklist\""
        );
        let cfg: SandboxConfig =
            serde_json::from_str(r#"{"enabled":true,"allow_mode":"blacklist"}"#).unwrap();
        assert_eq!(cfg.allow_mode, AllowMode::Blacklist);
        // missing field → whitelist (backward compatible with old configs)
        let cfg: SandboxConfig = serde_json::from_str(r#"{"enabled":true}"#).unwrap();
        assert_eq!(cfg.allow_mode, AllowMode::Whitelist);
    }

    #[test]
    fn app_entry_serializes() {
        let e = AppEntry::new(
            "test.desktop".into(),
            "Test".into(),
            "test-icon".into(),
            "test".into(),
        );
        let s = serde_json::to_string(&e).unwrap();
        let back: AppEntry = serde_json::from_str(&s).unwrap();
        assert_eq!(e, back);
        // sandbox defaults survive roundtrip
        assert!(back.sandbox.allow_loopback);
    }

    #[test]
    fn classify_entries() {
        assert_eq!(classify_entry("example.com"), Some(EntryKind::Domain));
        assert_eq!(classify_entry(" EXAMPLE.com "), Some(EntryKind::Domain));
        assert_eq!(classify_entry("*.example.com"), Some(EntryKind::Domain));
        assert_eq!(classify_entry("*.api.example.com"), Some(EntryKind::Domain));
        assert_eq!(classify_entry("10.0.0.1"), Some(EntryKind::Ip));
        assert_eq!(classify_entry("fe80::1"), Some(EntryKind::Ip));
        assert_eq!(classify_entry("10.0.0.0/8"), Some(EntryKind::Cidr { plen: 8 }));
        assert_eq!(
            classify_entry("fd00::/8"),
            Some(EntryKind::Cidr { plen: 8 })
        );
        assert_eq!(classify_entry(""), None);
        assert_eq!(classify_entry("not an ip"), None); // space
        assert_eq!(classify_entry("10.0.0.1/33"), None); // bad v4 prefix
        assert_eq!(classify_entry("bad..com"), None); // empty label
        assert_eq!(classify_entry("host:443"), None); // port smuggled in
        assert_eq!(classify_entry("a/b/c"), None); // slash garbage
        assert_eq!(classify_entry("10.0.0.1:443"), None); // ip:port
        assert_eq!(classify_entry("*"), None); // bare wildcard
        assert_eq!(classify_entry("a.*.com"), None); // wildcard not leftmost
        assert_eq!(classify_entry("api*.com"), None); // partial wildcard label
        assert_eq!(classify_entry("*.*.com"), None); // double wildcard
    }

    #[test]
    fn legacy_config_migrates() {
        // old fields only
        let cfg: SandboxConfig =
            serde_json::from_str(r#"{"allow_domains":["a.com"],"allow_ips":["10.0.0.0/8"]}"#)
                .unwrap();
        assert_eq!(cfg.allow_entries, vec!["a.com", "10.0.0.0/8"]);
        assert!(cfg.allow_loopback); // default true
        // mixed old + new, dedup case-insensitively
        let cfg: SandboxConfig = serde_json::from_str(
            r#"{"allow_domains":["a.com"],"allow_entries":["A.com","b.org"]}"#,
        )
        .unwrap();
        assert_eq!(cfg.allow_entries, vec!["a.com", "b.org"]);
        // loopback default when absent
        let cfg: SandboxConfig = serde_json::from_str("{}").unwrap();
        assert!(cfg.allow_loopback);
        // serialization writes only the new field
        let cfg = SandboxConfig {
            enabled: true,
            allow_entries: vec!["x.com".into()],
            allow_loopback: false,
            allow_mode: AllowMode::Whitelist,
        };
        let text = serde_json::to_string(&cfg).unwrap();
        assert!(!text.contains("allow_domains"));
        assert!(!text.contains("allow_ips"));
        assert!(text.contains("allow_entries"));
    }
}
