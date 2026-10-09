//! In-memory capture of app process output (stdout + stderr).
//!
//! Output is kept in a bounded ring buffer (oldest lines dropped first) and
//! never written to disk. One `OutputLog` per launch; the registry maps app
//! ids to the log of their most recent run.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Hard cap of the retained output. Once exceeded, oldest lines are dropped.
pub const MAX_OUTPUT_BYTES: usize = 1024 * 1024;

/// Ring buffer of one app run's stdout/stderr, capped at 1 MiB.
#[derive(Default)]
pub struct OutputLog {
    inner: Mutex<OutputInner>,
}

#[derive(Default)]
struct OutputInner {
    /// Retained output (complete lines except possibly the newest one).
    buf: String,
    /// Total bytes ever appended (>= buf.len()); drives incremental reads.
    total: u64,
}

impl OutputLog {
    pub fn new() -> Self {
        Self::default()
    }

    /// Append raw process output. Invalid UTF-8 becomes replacement chars;
    /// the buffer is trimmed from the oldest line when over the cap.
    pub fn append(&self, bytes: &[u8]) {
        let mut g = self.inner.lock().unwrap();
        g.buf.push_str(&String::from_utf8_lossy(bytes));
        g.total += bytes.len() as u64;
        if g.buf.len() > MAX_OUTPUT_BYTES {
            // Byte offset — may land mid-UTF-8-character (app logs are often
            // multibyte), so snap forward to a char boundary before slicing;
            // a non-boundary index would panic the writer thread and poison
            // this lock (crashing the viewer on its next refresh).
            let mut cut = g.buf.len() - MAX_OUTPUT_BYTES;
            while cut < g.buf.len() && !g.buf.is_char_boundary(cut) {
                cut += 1;
            }
            // Drop whole lines: cut just after the first newline at/after the
            // boundary. If the newest line alone exceeds the cap, cut hard.
            let cut = g.buf[cut..]
                .find('\n')
                .map(|p| cut + p + 1)
                .unwrap_or(cut);
            g.buf.drain(..cut);
        }
    }

    /// Snapshot of the retained output plus the total bytes ever written.
    /// A reader that last saw `seen_total` bytes can derive the new tail as
    /// `total - seen_total` bytes from the end of `buf` (fall back to a full
    /// replace when that span covers the whole buffer).
    pub fn snapshot(&self) -> (String, u64) {
        let g = self.inner.lock().unwrap();
        (g.buf.clone(), g.total)
    }

    /// Bytes currently retained.
    pub fn len_bytes(&self) -> usize {
        self.inner.lock().unwrap().buf.len()
    }

    /// Drop all retained output (totals reset too, so incremental readers
    /// fall back to a full replace).
    pub fn clear(&self) {
        let mut g = self.inner.lock().unwrap();
        g.buf.clear();
        g.total = 0;
    }
}

/// All apps' current output logs, shared between the launcher and the UI.
#[derive(Default)]
pub struct OutputLogRegistry {
    inner: Mutex<HashMap<String, Arc<OutputLog>>>,
}

impl OutputLogRegistry {
    /// Drop any previous log and install a fresh one for this launch.
    pub fn reset(&self, app_id: &str) -> Arc<OutputLog> {
        let log = Arc::new(OutputLog::new());
        self.inner
            .lock()
            .unwrap()
            .insert(app_id.to_string(), log.clone());
        log
    }

    /// The log of the app's most recent run, if any.
    pub fn get(&self, app_id: &str) -> Option<Arc<OutputLog>> {
        self.inner.lock().unwrap().get(app_id).cloned()
    }

    /// Forget the app's log entirely (app removed from the launcher).
    pub fn remove(&self, app_id: &str) {
        self.inner.lock().unwrap().remove(app_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn append_and_snapshot() {
        let log = OutputLog::new();
        log.append(b"hello ");
        log.append(&[0xff, b'w', b'o', b'r', b'l', b'd']); // invalid byte
        let (buf, total) = log.snapshot();
        assert_eq!(buf, "hello \u{fffd}world");
        assert_eq!(total, 12);
        assert_eq!(log.len_bytes(), buf.len());
    }

    #[test]
    fn rotates_on_line_boundaries() {
        let log = OutputLog::new();
        // 4 lines of 307201 bytes = 1228804 > 1 MiB, so the oldest line(s)
        // must be dropped.
        let big_line = "y".repeat(300 * 1024) + "\n"; // 307201 bytes
        for _ in 0..4 {
            log.append(big_line.as_bytes());
        }
        let (buf, total) = log.snapshot();
        assert_eq!(total, 4 * 307_201);
        // only the last ~3 lines fit; buffer must stay under the cap
        assert!(buf.len() <= MAX_OUTPUT_BYTES);
        assert!(buf.starts_with('y'));
        assert_eq!(buf.matches('\n').count(), 3, "oldest line dropped");
    }

    #[test]
    fn single_line_over_cap_is_hard_trimmed() {
        let log = OutputLog::new();
        log.append(vec![b'z'; MAX_OUTPUT_BYTES + 4096].as_slice());
        let (buf, total) = log.snapshot();
        assert_eq!(buf.len(), MAX_OUTPUT_BYTES);
        assert_eq!(total, (MAX_OUTPUT_BYTES + 4096) as u64);
        assert!(!buf.contains('\n'));
    }

    #[test]
    fn multibyte_overflow_does_not_panic() {
        // regression: the rotation cut used to slice at an arbitrary byte
        // offset which can land mid-UTF-8-character (app logs with Chinese
        // text) — panicking the writer thread and poisoning the lock, which
        // crashed the log viewer on its next refresh.
        let log = OutputLog::new();
        let chunk = format!("{}\n", "中文字符日志输出".repeat(4000)); // multibyte
        let chunk_bytes = chunk.len() as u64;
        // push ~5 MiB through in 8 KiB-ish chunks, like the pipe pump does
        for _ in 0..50 {
            let bytes = chunk.as_bytes();
            for part in bytes.chunks(8192) {
                log.append(part);
            }
        }
        let (buf, total) = log.snapshot();
        assert!(buf.len() <= MAX_OUTPUT_BYTES);
        assert!(total > 4 * MAX_OUTPUT_BYTES as u64, "payload must exceed the cap");
        // the retained buffer must still be valid UTF-8 (it is a String, so
        // merely reaching this point without panicking proves the fix)
        assert!(buf.contains('\n'));
        // snapshot → view arithmetic: the tail slice must also be boundary-safe
        let new_total = total;
        let mut start = buf.len() - (new_total as usize).min(buf.len());
        while start < buf.len() && !buf.is_char_boundary(start) {
            start += 1;
        }
        let _tail = &buf[start..];
    }

    #[test]
    fn clear_resets_everything() {
        let log = OutputLog::new();
        log.append(b"some output\n");
        log.clear();
        let (buf, total) = log.snapshot();
        assert!(buf.is_empty());
        assert_eq!(total, 0);
    }

    #[test]
    fn registry_reset_get_remove() {
        let reg = OutputLogRegistry::default();
        assert!(reg.get("app1").is_none());
        let first = reg.reset("app1");
        first.append(b"run one\n");
        // reset installs a fresh log
        let second = reg.reset("app1");
        let (buf, _) = second.snapshot();
        assert!(buf.is_empty());
        // the old handle still sees its own data (detached reader threads)
        let (old, _) = first.snapshot();
        assert_eq!(old, "run one\n");
        // registry hands out the current one
        assert!(Arc::ptr_eq(&reg.get("app1").unwrap(), &second));
        reg.remove("app1");
        assert!(reg.get("app1").is_none());
    }
}
