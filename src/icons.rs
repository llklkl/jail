//! App icon assets and desktop integration.
//!
//! The icon PNGs are embedded into the binary so `jail --install-desktop`
//! works without external files, and the tray always has a pixmap fallback.

use std::path::{Path, PathBuf};

pub const APP_ID: &str = "top.llklkl.jail";
pub const APP_NAME: &str = "Jail 启动器";

pub const ICON_256_PNG: &[u8] = include_bytes!("../assets/icon-256.png");
pub const ICON_128_PNG: &[u8] = include_bytes!("../assets/icon-128.png");
pub const ICON_64_PNG: &[u8] = include_bytes!("../assets/icon-64.png");

/// All embedded icon sizes, largest first.
pub const ICONS: &[(u32, &[u8])] = &[(256, ICON_256_PNG), (128, ICON_128_PNG), (64, ICON_64_PNG)];

/// Decode an embedded PNG into raw RGBA pixels (row-major, top-down).
/// Returns (width, height, rgba). Used by the tray to build SNI ARGB pixmaps.
pub fn decode_png_rgba(bytes: &[u8]) -> Option<(u32, u32, Vec<u8>)> {
    let decoder = png::Decoder::new(std::io::Cursor::new(bytes));
    let mut reader = decoder.read_info().ok()?;
    let mut buf = vec![0u8; reader.output_buffer_size()];
    let info = reader.next_frame(&mut buf).ok()?;
    buf.truncate(info.buffer_size());
    Some((info.width, info.height, buf))
}

/// Where user-level desktop integration lives.
fn desktop_dir() -> PathBuf {
    dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from(".local/share"))
        .join("applications")
}

fn icon_dir(size: u32) -> PathBuf {
    dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from(".local/share"))
        .join(format!("icons/hicolor/{size}x{size}/apps"))
}

/// The desktop entry text for `jail`. `exe` is the jail binary path; the
/// entry launches it detached (no terminal) and matches it by WM class so
/// the taskbar groups it under this icon.
pub fn desktop_entry_text(exe: &Path) -> String {
    let exe = exe.display();
    format!(
        "[Desktop Entry]\n\
         Type=Application\n\
         Name={APP_NAME}\n\
         Comment=Linux 应用启动器：按应用限制网络访问（黑白名单沙盒）\n\
         Exec={exe}\n\
         TryExec={exe}\n\
         Icon={APP_ID}\n\
         Terminal=false\n\
         Categories=Utility;Security;\n\
         StartupWMClass={APP_ID}\n\
         Keywords=jail;sandbox;network;firewall;\n"
    )
}

/// Install the desktop entry + icon set into the user's data directories.
/// Returns the installed .desktop path. Safe to run repeatedly (idempotent).
pub fn install_desktop() -> std::io::Result<PathBuf> {
    let exe = std::env::current_exe()?;
    // best-effort: prefer a stable path over /tmp-style locations
    let exe = if exe.starts_with(std::env::temp_dir()) {
        PathBuf::from("/usr/local/bin/jail")
    } else {
        exe
    };

    for (size, bytes) in ICONS {
        let dir = icon_dir(*size);
        std::fs::create_dir_all(&dir)?;
        std::fs::write(dir.join(format!("{APP_ID}.png")), bytes)?;
    }

    let dir = desktop_dir();
    std::fs::create_dir_all(&dir)?;
    let desktop_path = dir.join(format!("{APP_ID}.desktop"));
    std::fs::write(&desktop_path, desktop_entry_text(&exe))?;

    // refresh the desktop database so the new entry shows up immediately
    let _ = std::process::Command::new("update-desktop-database")
        .arg(&dir)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();

    Ok(desktop_path)
}

/// Remove desktop integration (used by `--uninstall-desktop`).
pub fn uninstall_desktop() -> std::io::Result<PathBuf> {
    for (size, _) in ICONS {
        let _ = std::fs::remove_file(icon_dir(*size).join(format!("{APP_ID}.png")));
    }
    let path = desktop_dir().join(format!("{APP_ID}.desktop"));
    let existed = path.exists();
    let _ = std::fs::remove_file(&path);
    if existed {
        Ok(path)
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "desktop entry not installed",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_icons_decode() {
        for (size, bytes) in ICONS {
            let (w, h, rgba) = decode_png_rgba(bytes).expect("valid embedded png");
            assert_eq!(w, *size);
            assert_eq!(h, *size);
            assert_eq!(rgba.len(), (w * h * 4) as usize);
        }
    }

    #[test]
    fn desktop_entry_shape() {
        let text = desktop_entry_text(Path::new("/usr/local/bin/jail"));
        assert!(text.starts_with("[Desktop Entry]\n"));
        assert!(text.contains("Exec=/usr/local/bin/jail"));
        assert!(text.contains(&format!("Icon={APP_ID}")));
        assert!(text.contains(&format!("StartupWMClass={APP_ID}")));
        assert!(!text.contains("Terminal=true"));
    }

    #[test]
    fn rgba_to_argb_conversion() {
        // conversion helper used by the tray pixmap
        let rgba = [0x10, 0x20, 0x30, 0xFF, 0x40, 0x50, 0x60, 0x80];
        let argb = rgba_to_argb32(&rgba);
        assert_eq!(argb, [0xFF, 0x10, 0x20, 0x30, 0x80, 0x40, 0x50, 0x60]);
    }
}

/// Convert RGBA pixel data to SNI ARGB32 (alpha byte first, per pixel).
pub fn rgba_to_argb32(rgba: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(rgba.len());
    for px in rgba.chunks_exact(4) {
        out.push(px[3]); // A
        out.push(px[0]); // R
        out.push(px[1]); // G
        out.push(px[2]); // B
    }
    out
}
