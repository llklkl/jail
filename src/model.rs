//! Data models for launcher entries and sandbox configuration.

use serde::{Deserialize, Serialize};

/// Per-application sandbox configuration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SandboxConfig {
    /// Whether sandboxing is enabled for this app.
    #[serde(default)]
    pub enabled: bool,
    /// Domains the app may reach; resolved to IPs at launch time.
    #[serde(default)]
    pub allow_domains: Vec<String>,
    /// IPs or CIDR ranges the app may reach directly.
    #[serde(default)]
    pub allow_ips: Vec<String>,
    /// Allow loopback + DNS to the system resolver (default true).
    #[serde(default = "default_true")]
    pub allow_loopback: bool,
}

fn default_true() -> bool {
    true
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            allow_domains: Vec::new(),
            allow_ips: Vec::new(),
            allow_loopback: true,
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
        assert!(cfg.allow_domains.is_empty());
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
}
