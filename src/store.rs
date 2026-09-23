//! Persistence for the launcher's app list (`apps.json`), with atomic writes
//! and backup-on-corruption.

use crate::model::AppEntry;
use std::fs;
use std::path::{Path, PathBuf};

pub struct Store {
    path: PathBuf,
}

impl Store {
    pub fn new() -> Self {
        let base = dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("app-launcher");
        Self { path: base.join("apps.json") }
    }

    #[allow(dead_code)] // used by tests
    pub fn with_path(path: PathBuf) -> Self {
        Self { path }
    }

    #[allow(dead_code)] // used by tests
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Load the app list. On corruption, backs up the file to `.bak` and
    /// returns an empty list.
    pub fn load(&self) -> Vec<AppEntry> {
        match fs::read_to_string(&self.path) {
            Ok(text) => match serde_json::from_str(&text) {
                Ok(list) => list,
                Err(e) => {
                    eprintln!(
                        "app-launcher: corrupt {}: {e}; backing up and starting fresh",
                        self.path.display()
                    );
                    let _ = fs::rename(&self.path, self.path.with_extension("json.bak"));
                    Vec::new()
                }
            },
            Err(_) => Vec::new(),
        }
    }

    /// Atomically save: write to a temp file in the same directory, then rename.
    pub fn save(&self, apps: &[AppEntry]) -> std::io::Result<()> {
        if let Some(dir) = self.path.parent() {
            fs::create_dir_all(dir)?;
        }
        let tmp = self.path.with_extension("json.tmp");
        let text = serde_json::to_string_pretty(apps)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        fs::write(&tmp, text)?;
        fs::rename(&tmp, &self.path)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::AppEntry;

    fn entry(name: &str) -> AppEntry {
        AppEntry::new(
            format!("{name}.desktop"),
            name.into(),
            "icon".into(),
            name.into(),
        )
    }

    #[test]
    fn roundtrip() {
        let dir = std::env::temp_dir().join(format!("apptest-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Store::with_path(dir.join("apps.json"));
        assert!(store.load().is_empty());

        let apps = vec![entry("a"), entry("b")];
        store.save(&apps).unwrap();
        let loaded = store.load();
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0].name, "a");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn corrupt_file_backs_up() {
        let dir = std::env::temp_dir().join(format!("apptest-c-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("apps.json");
        std::fs::write(&path, "{not json").unwrap();

        let store = Store::with_path(path.clone());
        assert!(store.load().is_empty());
        assert!(!path.exists(), "corrupt file renamed away");
        assert!(dir.join("apps.json.bak").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn save_creates_dirs() {
        let dir = std::env::temp_dir().join(format!("apptest-d-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Store::with_path(dir.join("nested/deeper/apps.json"));
        store.save(&[entry("x")]).unwrap();
        assert!(dir.join("nested/deeper/apps.json").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
