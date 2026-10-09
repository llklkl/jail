//! Per-app run-output viewer (AdwDialog): live tail of the app's captured
//! stdout/stderr.
//!
//! Output lives only in memory (1 MiB ring buffer, see `output_log.rs`) —
//! this dialog reads incremental slices from the shared `OutputLog` every
//! second while open. Nothing here touches the disk.

use crate::output_log::OutputLog;
use crate::model::AppEntry;
use adw::prelude::*;
use gtk::glib;
use std::cell::Cell;
use std::rc::Rc;
use std::sync::Arc;

/// Bytes retained by the ring buffer (shown in the status line).
use crate::output_log::MAX_OUTPUT_BYTES;

pub fn present(
    win: &adw::ApplicationWindow,
    app: &AppEntry,
    log: Option<Arc<OutputLog>>,
    running: impl Fn() -> bool + 'static,
) {
    let dialog = adw::Dialog::builder()
        .title(format!("运行日志 — {}", app.name))
        .content_width(760)
        .content_height(620)
        .build();

    let toolbar = adw::ToolbarView::new();
    let header = adw::HeaderBar::new();
    toolbar.add_top_bar(&header);

    // --- output view -------------------------------------------------------
    let view = gtk::TextView::new();
    view.set_editable(false);
    view.set_cursor_visible(false);
    view.set_monospace(true);
    view.set_wrap_mode(gtk::WrapMode::None);
    view.set_left_margin(8);
    view.set_right_margin(8);
    view.set_top_margin(6);
    view.set_bottom_margin(6);
    let scroll = gtk::ScrolledWindow::new();
    scroll.set_child(Some(&view));
    scroll.set_vexpand(true);
    scroll.set_hexpand(true);

    let status_label = gtk::Label::new(Some("…"));
    status_label.set_halign(gtk::Align::Start);
    status_label.set_hexpand(true);
    status_label.set_ellipsize(gtk::pango::EllipsizeMode::End);
    status_label.add_css_class("dimmed");
    status_label.add_css_class("caption");

    let content = gtk::Box::new(gtk::Orientation::Vertical, 0);
    content.append(&scroll);
    content.append(&status_label);
    toolbar.set_content(Some(&content));

    // --- header buttons ----------------------------------------------------
    let clear_btn = gtk::Button::with_label("清空");
    clear_btn.add_css_class("flat");
    header.pack_start(&clear_btn);

    dialog.set_child(Some(&toolbar));

    // --- incremental tail state -------------------------------------------
    // `seen` = total bytes already rendered; derived from the log's running
    // total so rotation and clears are handled by the same arithmetic.
    let seen = Rc::new(Cell::new(0u64));
    let log = Rc::new(log); // Option<Arc<OutputLog>>
    let running = Rc::new(running);

    let refresh = {
        let view = view.clone();
        let scroll = scroll.clone();
        let status_label = status_label.clone();
        let log = log.clone();
        let running = running.clone();
        let seen = seen.clone();
        move || {
            let Some(log) = log.as_ref() else {
                status_label.set_text("本次会话尚未启动过该应用 — 单击应用启动后，其输出会显示在这里");
                return;
            };
            let (buf, total) = log.snapshot();
            let new_total = total.saturating_sub(seen.get());
            if new_total == 0 {
                update_status(&status_label, &view, log, seen.get(), running());
                return;
            }
            let vadj = scroll.vadjustment();
            let at_bottom = vadj.value() + vadj.page_size() >= vadj.upper() - 30.0;
            let b = view.buffer();
            if new_total as usize >= buf.len() {
                // reader is behind the rotation window (or buffer cleared):
                // replace everything with what we still have
                b.set_text(&buf);
            } else {
                // snap to a char boundary — new_total is a byte count and may
                // land mid-character after rotation shifted the buffer
                let mut start = buf.len() - new_total as usize;
                while start < buf.len() && !buf.is_char_boundary(start) {
                    start += 1;
                }
                let tail = &buf[start..];
                let mut end = b.end_iter();
                b.insert(&mut end, tail);
            }
            seen.set(total);
            if at_bottom {
                let insert = b.get_insert();
                b.move_mark_by_name("insert", &b.end_iter());
                view.scroll_mark_onscreen(&insert);
            }
            update_status(&status_label, &view, log, seen.get(), running());
        }
    };

    // 1s refresh while open; stop when the dialog closes.
    let tick: Rc<std::cell::RefCell<Option<glib::SourceId>>> =
        Rc::new(std::cell::RefCell::new(Some(glib::timeout_add_local(
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

    // clear button: wipe the in-memory buffer and the view
    {
        let log = log.clone();
        let refresh = refresh.clone();
        let seen = seen.clone();
        clear_btn.connect_clicked(move |_| {
            if let Some(log) = log.as_ref() {
                log.clear();
            }
            seen.set(0);
            refresh();
        });
    }

    dialog.present(Some(win));
}

/// Status line: running state, retained size, and the no-disk promise.
/// `running` is polled from the caller's registry each refresh.
fn update_status(
    status_label: &gtk::Label,
    view: &gtk::TextView,
    log: &Arc<OutputLog>,
    seen: u64,
    running: bool,
) {
    let (_, total) = log.snapshot();
    let stale = if seen < total { "（有新输出）" } else { "" };
    let size = if log.len_bytes() >= MAX_OUTPUT_BYTES {
        "已到 1 MB 上限，最早的输出被丢弃".to_string()
    } else {
        format!("{} / 1 MB", human_bytes(log.len_bytes()))
    };
    let n_lines = view.buffer().line_count();
    let state_word = if running { "运行中" } else { "已退出" };
    status_label.set_text(&format!(
        "{state_word} · {size} · {n_lines} 行{stale} · 仅保留最近 1 MB，不写入磁盘"
    ));
}

fn human_bytes(n: usize) -> String {
    if n >= 1024 * 1024 {
        format!("{:.1} MB", n as f64 / (1024.0 * 1024.0))
    } else if n >= 1024 {
        format!("{:.1} KB", n as f64 / 1024.0)
    } else {
        format!("{n} B")
    }
}
