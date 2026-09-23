//! Per-app access log viewer (AdwDialog): live summary per host + raw view.
//!
//! The log file is written by the host bridge process; this dialog tails it
//! incrementally (byte offset + partial-line buffer) and refreshes the
//! summary every second while open.

use super::log_data::{human_bytes, summarize, tail_lines};
use crate::model::AppEntry;
use adw::prelude::*;
use gtk::glib;
use std::cell::Cell;
use std::path::PathBuf;
use std::rc::Rc;

const MAX_SUMMARY_ROWS: usize = 200;
const RAW_VIEW_LINES: usize = 500;

pub fn present(win: &adw::ApplicationWindow, app: &AppEntry, log_path: PathBuf) {
    let dialog = adw::Dialog::builder()
        .title(format!("访问日志 — {}", app.name))
        .content_width(760)
        .content_height(620)
        .build();

    let toolbar = adw::ToolbarView::new();
    let header = adw::HeaderBar::new();
    toolbar.add_top_bar(&header);

    // --- summary page ------------------------------------------------------
    let summary_list = gtk::ListBox::new();
    summary_list.set_selection_mode(gtk::SelectionMode::None);
    summary_list.add_css_class("rich-list");
    let summary_scroll = gtk::ScrolledWindow::new();
    summary_scroll.set_child(Some(&summary_list));
    summary_scroll.set_vexpand(true);

    let status_label = gtk::Label::new(Some("加载中…"));
    status_label.set_halign(gtk::Align::Start);
    status_label.add_css_class("dimmed");
    status_label.add_css_class("caption");

    let summary_box = gtk::Box::new(gtk::Orientation::Vertical, 6);
    summary_box.set_margin_top(12);
    summary_box.set_margin_bottom(12);
    summary_box.set_margin_start(12);
    summary_box.set_margin_end(12);
    summary_box.append(&status_label);
    summary_box.append(&summary_scroll);

    // --- raw page ----------------------------------------------------------
    let raw_view = gtk::TextView::new();
    raw_view.set_editable(false);
    raw_view.set_cursor_visible(false);
    raw_view.set_monospace(true);
    raw_view.set_wrap_mode(gtk::WrapMode::None);
    raw_view.set_left_margin(8);
    raw_view.set_right_margin(8);
    let raw_scroll = gtk::ScrolledWindow::new();
    raw_scroll.set_child(Some(&raw_view));
    raw_scroll.set_vexpand(true);

    let stack = gtk::Stack::new();
    stack.add_titled(&summary_box, Some("summary"), "汇总");
    stack.add_titled(&raw_scroll, Some("raw"), "原始日志");
    stack.set_vexpand(true);

    // --- header buttons ----------------------------------------------------
    let clear_btn = gtk::Button::with_label("清空");
    clear_btn.add_css_class("flat");
    header.pack_start(&clear_btn);

    let content = gtk::Box::new(gtk::Orientation::Vertical, 0);
    content.append(&stack);
    toolbar.set_content(Some(&content));
    dialog.set_child(Some(&toolbar));

    // --- tailing state -----------------------------------------------------
    let tail = Rc::new(TailState {
        path: log_path,
        offset: Cell::new(0u64),
        pending: std::cell::RefCell::new(String::new()),
        full: std::cell::RefCell::new(String::new()),
    });

    let refresh = {
        let tail = tail.clone();
        let summary_list = summary_list.clone();
        let status_label = status_label.clone();
        let raw_view = raw_view.clone();
        move || {
            let text = tail.read_all();
            let last_ts = summarize(&text, 1)
                .first()
                .map(|h| h.last_ts)
                .unwrap_or(0);
            // rebuild summary
            let mut idx = 0;
            while let Some(child) = summary_list.row_at_index(idx) {
                summary_list.remove(&child);
                idx += 1;
            }
            let rows = summarize(&text, MAX_SUMMARY_ROWS);
            if rows.is_empty() {
                status_label.set_text("暂无记录 — 启动应用后，经过沙盒代理的连接和 DNS 查询会显示在这里");
            } else {
                status_label.set_text(&format!(
                    "{} 个主机 · 实时更新中 · 最近活动 {}",
                    rows.len(),
                    format_ts(last_ts)
                ));
            }
            for h in &rows {
                summary_list.append(&summary_row(h));
            }
            // raw view: last N lines
            let raw: String = tail_lines(&text, RAW_VIEW_LINES)
                .into_iter()
                .map(|l| format!("{l}\n"))
                .collect();
            raw_view.buffer().set_text(&raw);
            // scroll to the end
            let buf = raw_view.buffer();
            let insert = buf.get_insert();
            buf.move_mark_by_name("insert", &buf.end_iter());
            raw_view.scroll_mark_onscreen(&insert);
        }
    };

    // 1s refresh while open; stop when the dialog closes.
    let tick: std::rc::Rc<std::cell::RefCell<Option<glib::SourceId>>> =
        std::rc::Rc::new(std::cell::RefCell::new(Some(glib::timeout_add_local(
            std::time::Duration::from_millis(1000),
            {
                let refresh = refresh.clone();
                move || {
                    refresh();
                    glib::ControlFlow::Continue
                }
            },
        ))));
    dialog.connect_closed({
        let tick = tick.clone();
        move |_| {
            if let Some(id) = tick.borrow_mut().take() {
                id.remove();
            }
        }
    });
    // initial fill
    refresh();

    // clear button: truncate the file and reset the view
    {
        let tail = tail.clone();
        let refresh = refresh.clone();
        clear_btn.connect_clicked(move |_| {
            tail.clear();
            refresh();
        });
    }

    dialog.present(Some(win));
}

struct TailState {
    path: PathBuf,
    offset: Cell<u64>,
    /// partial line carried between reads
    pending: std::cell::RefCell<String>,
    full: std::cell::RefCell<String>,
}

impl TailState {
    /// Read new bytes from the last offset, append to the buffer, return the
    /// whole text. Recreates state when the file was truncated/cleared.
    fn read_all(&self) -> String {
        use std::io::{Read, Seek};
        let Ok(mut f) = std::fs::File::open(&self.path) else {
            // file may not exist yet
            return self.full.borrow().clone();
        };
        let len = f.metadata().map(|m| m.len()).unwrap_or(0);
        if (len as u64) < self.offset.get() {
            // truncated (cleared) — restart
            self.offset.set(0);
            self.pending.borrow_mut().clear();
            self.full.borrow_mut().clear();
        }
        if f.seek(std::io::SeekFrom::Start(self.offset.get())).is_err() {
            return self.full.borrow().clone();
        }
        let mut buf = Vec::new();
        if f.read_to_end(&mut buf).is_ok() && !buf.is_empty() {
            self.offset.set(self.offset.get() + buf.len() as u64);
            let mut pending = self.pending.borrow_mut();
            pending.push_str(&String::from_utf8_lossy(&buf));
            // keep only complete lines in `full`
            if let Some(pos) = pending.rfind('\n') {
                let complete: String = pending.drain(..=pos).collect();
                drop(pending);
                let mut full = self.full.borrow_mut();
                full.push_str(&complete);
                let max = 2 * 1024 * 1024;
                if full.len() > max {
                    // keep the tail of the buffer
                    let cut = full.len() - max;
                    let pos = full[cut..]
                        .find('\n')
                        .map(|p| cut + p + 1)
                        .unwrap_or(cut);
                    full.drain(..pos);
                }
            }
        }
        self.full.borrow().clone()
    }

    fn clear(&self) {
        self.offset.set(0);
        self.pending.borrow_mut().clear();
        self.full.borrow_mut().clear();
        let _ = std::fs::write(&self.path, b"");
    }
}

fn format_ts(ts: u64) -> String {
    if ts == 0 {
        return "—".into();
    }
    glib::DateTime::from_unix_local(ts as i64)
        .map(|d| d.format("%H:%M:%S").ok().unwrap_or_default().to_string())
        .unwrap_or_else(|_| ts.to_string())
}

fn summary_row(h: &super::log_data::HostSummary) -> gtk::ListBoxRow {
    let row = gtk::ListBoxRow::new();
    let hbox = gtk::Box::new(gtk::Orientation::Horizontal, 12);
    hbox.set_margin_top(6);
    hbox.set_margin_bottom(6);
    hbox.set_margin_start(8);
    hbox.set_margin_end(8);

    // host + verdict counts
    let left = gtk::Box::new(gtk::Orientation::Vertical, 2);
    left.set_valign(gtk::Align::Center);
    let name = gtk::Label::new(Some(&h.host));
    name.set_halign(gtk::Align::Start);
    name.set_ellipsize(gtk::pango::EllipsizeMode::Middle);
    name.add_css_class("heading");
    left.append(&name);
    let mut counts = Vec::new();
    if h.allowed > 0 {
        counts.push(format!("✓ {}", h.allowed));
    }
    if h.denied > 0 {
        counts.push(format!("✗ {}", h.denied));
    }
    if h.dns > 0 {
        counts.push(format!("DNS {}", h.dns));
    }
    let sub = gtk::Label::new(Some(&counts.join(" · ")));
    sub.set_halign(gtk::Align::Start);
    sub.add_css_class("dimmed");
    sub.add_css_class("caption");
    left.append(&sub);
    hbox.append(&left);

    // spacer
    let spacer = gtk::Box::new(gtk::Orientation::Horizontal, 0);
    spacer.set_hexpand(true);
    hbox.append(&spacer);

    // bytes + last activity
    let right = gtk::Box::new(gtk::Orientation::Vertical, 2);
    right.set_valign(gtk::Align::Center);
    let bytes = gtk::Label::new(Some(&format!("↑ {} ↓ {}", human_bytes(h.up), human_bytes(h.down))));
    bytes.set_halign(gtk::Align::End);
    bytes.add_css_class("monospace");
    right.append(&bytes);
    let last = gtk::Label::new(Some(&format_ts(h.last_ts)));
    last.set_halign(gtk::Align::End);
    last.add_css_class("dimmed");
    last.add_css_class("caption");
    right.append(&last);
    hbox.append(&right);

    row.set_child(Some(&hbox));
    row
}
