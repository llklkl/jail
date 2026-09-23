//! Scanning of freedesktop .desktop entries from the standard XDG dirs,
//! including flatpak exports.

use freedesktop_desktop_entry::{DesktopEntry, Iter};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// One installable application found on the system.
#[derive(Debug, Clone, PartialEq)]
pub struct DesktopApp {
    pub desktop_id: String,
    pub name: String,
    pub icon: String,
    pub exec: String,
    pub path: PathBuf,
}

/// Directories to scan, in XDG precedence order.
pub fn data_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Some(home) = dirs::home_dir() {
        dirs.push(home.join(".local/share/applications"));
        dirs.push(home.join(".local/share/flatpak/exports/share/applications"));
    }
    if let Ok(xdg) = std::env::var("XDG_DATA_DIRS") {
        for d in xdg.split(':').filter(|s| !s.is_empty()) {
            dirs.push(PathBuf::from(d).join("applications"));
            dirs.push(PathBuf::from(d).join("flatpak/exports/share/applications"));
        }
    } else {
        dirs.push(PathBuf::from("/usr/local/share/applications"));
        dirs.push(PathBuf::from("/usr/share/applications"));
    }
    dirs
}

/// Whether the entry should be hidden from pickers (NoDisplay/Hidden/etc).
fn should_skip(entry: &DesktopEntry) -> bool {
    entry.no_display()
        || entry.hidden()
        || entry.exec().is_none()
        || entry.name(&LOCALES).is_none()
        // skip pure URL entries / non-app types
        || entry.type_().map(|t| t != "Application").unwrap_or(false)
}

const LOCALES: &[&str] = &["zh_CN", "zh", "en_US", "en"];

/// Scan all data dirs and return a deduplicated list of desktop apps.
/// First occurrence (per XDG precedence) wins.
pub fn scan_apps() -> Vec<DesktopApp> {
    let mut by_id: BTreeMap<String, DesktopApp> = BTreeMap::new();
    for dir in data_dirs() {
        if !dir.is_dir() {
            continue;
        }
        for path in Iter::new(std::iter::once(dir.clone())) {
            let Ok(entry) = DesktopEntry::from_path(&path, Some(&LOCALES)) else {
                continue;
            };
            if should_skip(&entry) {
                continue;
            }
            let id = entry.id().to_string();
            if by_id.contains_key(&id) {
                continue;
            }
            by_id.insert(
                id.clone(),
                DesktopApp {
                    desktop_id: id,
                    name: entry
                        .name(&LOCALES)
                        .map(|n| n.into_owned())
                        .unwrap_or_default(),
                    icon: entry
                        .icon()
                        .unwrap_or("application-x-executable")
                        .to_string(),
                    exec: entry.exec().unwrap_or_default().to_string(),
                    path: entry.path.clone(),
                },
            );
        }
    }
    by_id.into_values().collect()
}

/// Look up one desktop entry by id (e.g. after restart, to refresh names).
pub fn find_app(desktop_id: &str) -> Option<DesktopApp> {
    scan_apps().into_iter().find(|a| a.desktop_id == desktop_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_dirs_nonempty() {
        let dirs = data_dirs();
        assert!(!dirs.is_empty());
        assert!(dirs.iter().any(|d| d.ends_with("applications")));
    }

    #[test]
    fn scan_finds_some_apps_on_this_system() {
        let apps = scan_apps();
        assert!(
            apps.len() > 10,
            "expected a real desktop system to have many apps, got {}",
            apps.len()
        );
        // every entry has name+exec (should_skip guarantees exec/name present)
        assert!(apps.iter().all(|a| !a.name.is_empty() && !a.exec.is_empty()));
        // ids unique
        let mut ids: Vec<_> = apps.iter().map(|a| a.desktop_id.clone()).collect();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), apps.len());
    }
}
