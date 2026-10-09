//! Per-app access log viewer (AdwDialog): live summary per host + raw view.
//!
//! The log file is written by the host bridge process; this dialog tails it
//! incrementally (byte offset + partial-line buffer) and refreshes the
//! summary every second while open. Each summary row has a context menu:
//! copy the host text, and (mode-dependent) allow/deny it — the action
//! rewrites the app's rules file so a running bridge picks it up.

use super::log_data::{human_bytes, summarize, tail_lines};
use crate::model::{AllowMode, AppEntry};
use adw::prelude::*;
use gtk::glib;
use std::cell::Cell;
use std::path::PathBuf;
use std::rc::Rc;

const MAX_SUMMARY_ROWS: usize = 200;
const RAW_VIEW_LINES: usize = 500;

pub fn present(
    win: &adw::ApplicationWindow,
    state: &Rc<super::AppState>,
    id: &str,
    log_path: PathBuf,
) {
    let id = id.to_string();
    let Some(app) = state.apps.borrow().iter().find(|a| a.id == id).cloned() else {
        return;
    };
    let app: AppEntry = app;
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
        let state = state.clone();
        let id = id.clone();
        // per-host row cache: rows are created once and updated in place —
        // rebuilding them every tick would destroy the attached context
        // menu (and an open popover with it). Rows are keyed by host and
        // kept in sorted position (the summary is lexicographic).
        let row_cache: Rc<std::cell::RefCell<Vec<(String, SummaryRow)>>> =
            Rc::new(std::cell::RefCell::new(Vec::new()));
        let last_status: Rc<std::cell::RefCell<Option<String>>> =
            Rc::new(std::cell::RefCell::new(None));
        let row_cache = row_cache.clone();
        let last_status = last_status.clone();
        move || {
            let text = tail.read_all();
            let rows = summarize(&text, MAX_SUMMARY_ROWS);
            let mode = current_mode(&state, &id);

            // status line (cheap, no menus attached)
            let status = if rows.is_empty() {
                "暂无记录 — 启动应用后，经过沙盒代理的连接和 DNS 查询会显示在这里".to_string()
            } else {
                let last_ts = rows.iter().map(|h| h.last_ts).max().unwrap_or(0);
                format!(
                    "{} · {} 个主机 · 字典序 · 最近活动 {}",
                    mode.title(),
                    rows.len(),
                    format_ts(last_ts)
                )
            };
            if last_status.borrow().as_deref() != Some(status.as_str()) {
                *last_status.borrow_mut() = Some(status.clone());
                status_label.set_text(&status);
            }

            // sync rows with the (lexicographically sorted) summary:
            // update existing rows in place, insert new ones at their sorted
            // position, drop rows whose host vanished.
            {
                let mut cache = row_cache.borrow_mut();
                let mut new_idx = 0usize;
                let mut kept = Vec::with_capacity(cache.len());
                for (host, mut row) in cache.drain(..) {
                    match rows.get(new_idx).filter(|h| h.host == host) {
                        Some(h) => {
                            // same host at the same sorted position: update
                            row.update(h, mode);
                            kept.push((host, row));
                            new_idx += 1;
                        }
                        None => {
                            // either the host vanished or moved: reinsert at
                            // its new sorted position
                            match rows.iter().position(|h| h.host == host) {
                                Some(_) => {
                                    summary_list.remove(&row.row);
                                    kept.push((host, row)); // re-added below
                                }
                                None => summary_list.remove(&row.row), // gone
                            }
                        }
                    }
                }
                // insert/update remaining hosts in sorted order
                for (at, h) in rows.iter().enumerate() {
                    let existing = kept.iter_mut().find(|(k, _)| *k == h.host);
                    match existing {
                        Some((_, row)) => {
                            row.update(h, mode);
                            // ensure it sits at position `at`
                            if row.row.index() != at as i32 {
                                summary_list.remove(&row.row);
                                summary_list.insert(&row.row, at as i32);
                            }
                        }
                        None => {
                            let row = SummaryRow::new(h, mode);
                            attach_row_menu(&row.row, &state, &id, &h.host, mode);
                            summary_list.insert(&row.row, at as i32);
                            kept.push((h.host.clone(), row));
                        }
                    }
                }
                kept.sort_by(|a, b| a.0.cmp(&b.0));
                *cache = kept;
            }

            // raw view: last N lines (no popovers attached — always refresh)
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

/// The widgets of one summary row that change with the data. Kept per host
/// so refreshes update labels in place — rebuilding rows would destroy the
/// attached context menu (and an open popover with it).
struct SummaryRow {
    row: gtk::ListBoxRow,
    chip: gtk::Label,
    counts: gtk::Label,
    bytes: gtk::Label,
    last: gtk::Label,
    /// the data currently rendered (to skip no-op updates)
    rendered: super::log_data::HostSummary,
    mode: AllowMode,
}

impl SummaryRow {
    fn new(h: &super::log_data::HostSummary, mode: AllowMode) -> Self {
        let row = gtk::ListBoxRow::new();
        let hbox = gtk::Box::new(gtk::Orientation::Horizontal, 12);
        hbox.set_margin_top(6);
        hbox.set_margin_bottom(6);
        hbox.set_margin_start(8);
        hbox.set_margin_end(8);

        let chip = gtk::Label::new(None);
        chip.set_valign(gtk::Align::Center);
        chip.add_css_class("log-chip");
        hbox.append(&chip);

        // host + verdict counts
        let left = gtk::Box::new(gtk::Orientation::Vertical, 2);
        left.set_valign(gtk::Align::Center);
        let name = gtk::Label::new(Some(&h.host));
        name.set_halign(gtk::Align::Start);
        name.set_ellipsize(gtk::pango::EllipsizeMode::Middle);
        name.add_css_class("heading");
        left.append(&name);
        let counts = gtk::Label::new(None);
        counts.set_halign(gtk::Align::Start);
        counts.add_css_class("dimmed");
        counts.add_css_class("caption");
        left.append(&counts);
        hbox.append(&left);

        // spacer
        let spacer = gtk::Box::new(gtk::Orientation::Horizontal, 0);
        spacer.set_hexpand(true);
        hbox.append(&spacer);

        // bytes + last activity
        let right = gtk::Box::new(gtk::Orientation::Vertical, 2);
        right.set_valign(gtk::Align::Center);
        let bytes = gtk::Label::new(None);
        bytes.set_halign(gtk::Align::End);
        bytes.add_css_class("monospace");
        right.append(&bytes);
        let last = gtk::Label::new(None);
        last.set_halign(gtk::Align::End);
        last.add_css_class("dimmed");
        last.add_css_class("caption");
        right.append(&last);
        hbox.append(&right);

        row.set_child(Some(&hbox));

        let mut r = SummaryRow {
            row,
            chip,
            counts,
            bytes,
            last,
            rendered: super::log_data::HostSummary::default(),
            mode,
        };
        r.update(h, mode);
        r
    }

    /// Refresh the row's labels from `h` (in place — the context menu
    /// attached to the row survives).
    fn update(&mut self, h: &super::log_data::HostSummary, mode: AllowMode) {
        if *h == self.rendered && mode == self.mode {
            return;
        }
        self.mode = mode;
        self.rendered = h.clone();

        let (chip_label, chip_class, chip_tooltip) = if h.denied > 0 && h.allowed > 0 {
            ("部分放行", "log-chip-mixed", "有放行也有拒绝的连接")
        } else if h.denied > 0 {
            (
                "已拒绝",
                "log-chip-denied",
                match mode {
                    AllowMode::Whitelist => "所有连接都被白名单拒绝",
                    AllowMode::Blacklist => "所有连接都被黑名单拒绝",
                },
            )
        } else {
            (
                "已放行",
                "log-chip-allowed",
                match mode {
                    AllowMode::Whitelist => "连接被白名单放行",
                    AllowMode::Blacklist => "连接未被黑名单命中，已放行",
                },
            )
        };
        self.chip.set_text(chip_label);
        for cls in ["log-chip-allowed", "log-chip-denied", "log-chip-mixed"] {
            self.chip.remove_css_class(cls);
        }
        self.chip.add_css_class(chip_class);
        self.chip.set_tooltip_text(Some(chip_tooltip));

        let mut counts = Vec::new();
        if h.allowed > 0 {
            counts.push(format!("✓ 放行 {}", h.allowed));
        }
        if h.denied > 0 {
            counts.push(format!("✗ 拒绝 {}", h.denied));
        }
        if h.dns > 0 {
            counts.push(format!("DNS {}", h.dns));
        }
        if h.dns_blocked > 0 {
            counts.push(format!("拦截 {}", h.dns_blocked));
        }
        self.counts.set_text(&counts.join(" · "));
        self.bytes
            .set_text(&format!("↑ {} ↓ {}", human_bytes(h.up), human_bytes(h.down)));
        self.last.set_text(&format_ts(h.last_ts));
    }
}

/// The app's current rule mode (read live so menu labels follow edits).
fn current_mode(state: &super::AppState, id: &str) -> AllowMode {
    state
        .apps
        .borrow()
        .iter()
        .find(|a| a.id == id)
        .map(|a| a.sandbox.allow_mode)
        .unwrap_or_default()
}

/// Attach a right-click / long-press context menu to a summary row:
/// 复制 (always), plus mode-dependent 允许访问 (whitelist) or 禁止访问
/// (blacklist). Actions rewrite the app's rules file; a running bridge
/// picks up the change within its poll interval.
fn attach_row_menu(
    row: &gtk::ListBoxRow,
    state: &Rc<super::AppState>,
    id: &str,
    host: &str,
    mode: AllowMode,
) {
    let popover = gtk::Popover::new();
    popover.add_css_class("context-menu");
    popover.set_autohide(true);

    let list = gtk::ListBox::new();
    list.set_selection_mode(gtk::SelectionMode::None);
    list.add_css_class("rich-list");
    list.set_margin_top(6);
    list.set_margin_bottom(6);

    let add_item = |list: &gtk::ListBox, icon: &str, label: &str| -> gtk::Button {
        let item_row = gtk::ListBoxRow::new();
        item_row.set_activatable(false);
        let btn = gtk::Button::new();
        btn.set_has_frame(false);
        let hbox = gtk::Box::new(gtk::Orientation::Horizontal, 10);
        hbox.set_margin_start(10);
        hbox.set_margin_end(10);
        hbox.set_margin_top(4);
        hbox.set_margin_bottom(4);
        let img = gtk::Image::from_icon_name(icon);
        hbox.append(&img);
        let lbl = gtk::Label::new(Some(label));
        lbl.set_halign(gtk::Align::Start);
        lbl.set_hexpand(true);
        hbox.append(&lbl);
        btn.set_child(Some(&hbox));
        item_row.set_child(Some(&btn));
        list.append(&item_row);
        btn
    };

    // 复制: copy the host text to the clipboard
    let pop = popover.clone();
    let host_text = host.to_string();
    let copy_btn = add_item(&list, "edit-copy-symbolic", "复制");
    copy_btn.connect_clicked(move |_| {
        let display = gtk::gdk::Display::default();
        if let Some(display) = display {
            display.clipboard().set_text(&host_text);
        }
        pop.popdown();
    });

    // mode-dependent allow/deny action
    let (action_label, action_icon) = match mode {
        AllowMode::Whitelist => ("允许访问", "list-add-symbolic"),
        AllowMode::Blacklist => ("禁止访问", "action-unavailable-symbolic"),
    };
    let pop = popover.clone();
    let state = state.clone();
    let id = id.to_string();
    let host_owned = host.to_string();
    let action_btn = add_item(&list, action_icon, action_label);
    action_btn.connect_clicked(move |_| {
        apply_rule_action(&state, &id, &host_owned);
        pop.popdown();
    });

    popover.set_child(Some(&list));
    popover.set_parent(row);

    // right click
    {
        let pop = popover.clone();
        let click = gtk::GestureClick::new();
        click.set_button(3);
        click.connect_pressed(move |_, _, x, y| {
            pop.set_pointing_to(Some(&gtk::gdk::Rectangle::new(
                x as i32 - 2,
                y as i32 - 2,
                4,
                4,
            )));
            pop.popup();
        });
        row.add_controller(click);
    }
    // long press (touch)
    {
        let pop = popover.clone();
        let lp = gtk::GestureLongPress::new();
        lp.connect_pressed(move |_, x, y| {
            pop.set_pointing_to(Some(&gtk::gdk::Rectangle::new(
                x as i32 - 2,
                y as i32 - 2,
                4,
                4,
            )));
            pop.popup();
        });
        row.add_controller(lp);
    }
}

/// Add `host` to the app's rule entries (deduped), persist the config and
/// rewrite the rules file so the change takes effect on running apps.
fn apply_rule_action(state: &super::AppState, id: &str, host: &str) {
    let app = {
        let mut apps = state.apps.borrow_mut();
        let Some(app) = apps.iter_mut().find(|a| a.id == id) else {
            return;
        };
        let dup = app
            .sandbox
            .allow_entries
            .iter()
            .any(|e| e.eq_ignore_ascii_case(host));
        if !dup {
            app.sandbox.allow_entries.push(host.to_string());
        }
        app.clone()
    };
    let _ = state.store.save(&state.apps.borrow());
    crate::launcher::write_allow_file(&crate::launcher::config_base(), &app);
}
