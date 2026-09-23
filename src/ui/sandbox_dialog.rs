//! Sandbox settings modal (AdwDialog) for one app entry.
//!
//! The allowlist is a single unified list of entries — domains (suffix
//! match), IPs, or CIDR ranges — edited one entry per row, GNOME style.

use super::{after_mutation, AppState};
use crate::model::{classify_entry, EntryKind};
use adw::prelude::*;
use std::rc::Rc;

fn entry_subtitle(e: &str) -> String {
    match classify_entry(e) {
        Some(EntryKind::Domain) => {
            if e.trim().starts_with("*.") {
                "通配 · 匹配一级子域名".into()
            } else {
                "域名 · 精确匹配".into()
            }
        }
        Some(EntryKind::Ip) => "单个 IP 地址".into(),
        Some(EntryKind::Cidr { plen }) => format!("网段 · CIDR /{plen}"),
        None => "无效条目".into(),
    }
}

pub fn present(win: &adw::ApplicationWindow, state: &Rc<AppState>, id: &str) {
    let id = id.to_string();
    let Some(index) = state.apps.borrow().iter().position(|a| a.id == id) else {
        return;
    };
    let app = state.apps.borrow()[index].clone();

    let dialog = adw::Dialog::builder()
        .title(format!("沙盒设置 — {}", app.name))
        .content_width(560)
        .content_height(640)
        .build();

    let toolbar = adw::ToolbarView::new();
    let header = adw::HeaderBar::new();
    toolbar.add_top_bar(&header);

    let page = adw::PreferencesPage::new();

    // --- enable group ------------------------------------------------------
    let enable_group = adw::PreferencesGroup::new();
    enable_group.set_title("网络沙盒");
    let enable_switch = adw::SwitchRow::builder()
        .title("启用沙盒")
        .subtitle("启动时创建独立网络命名空间，仅放行下方允许的地址")
        .active(app.sandbox.enabled)
        .build();
    enable_group.add(&enable_switch);
    page.add(&enable_group);

    // --- unified rules group -----------------------------------------------
    let allow_group = adw::PreferencesGroup::new();
    allow_group.set_title("访问规则");

    // mode switch: whitelist (default) vs blacklist
    let mode_switch = adw::SwitchRow::builder()
        .title("黑名单模式")
        .subtitle("开启后列表中的地址将被禁止，其余全部放行；关闭则为白名单（仅放行列表中的地址）")
        .active(app.sandbox.allow_mode == crate::model::AllowMode::Blacklist)
        .build();
    allow_group.add(&mode_switch);

    let entries_list = std::rc::Rc::new(std::cell::RefCell::new(app.sandbox.allow_entries.clone()));
    let rows_box = gtk::Box::new(gtk::Orientation::Vertical, 0);

    let group_ref = allow_group.clone();
    let update_description = move |blacklist: bool| {
        group_ref.set_description(Some(if blacklist {
            "黑名单：列表中的地址被禁止访问，其余全部放行。每行一条：域名精确匹配（example.com）；*.example.com 通配一级子域名；IP 或网段（10.0.0.0/8）。"
        } else {
            "白名单：仅列表中的地址允许访问，其余一律拒绝。每行一条：域名精确匹配（example.com）；*.example.com 通配一级子域名；IP 或网段（10.0.0.0/8）。"
        }));
    };
    update_description(mode_switch.is_active());
    {
        let switch_ref = mode_switch.clone();
        let update_description = update_description.clone();
        mode_switch.connect_active_notify(move |_| {
            update_description(switch_ref.is_active());
        });
    }

    let add_entry_row: std::rc::Rc<dyn Fn(String)> = std::rc::Rc::new({
        let rows_box = rows_box.clone();
        let entries_list = entries_list.clone();
        move |entry: String| {
            let row = adw::ActionRow::builder().title(&entry).build();
            row.set_subtitle(&entry_subtitle(&entry));
            let del = gtk::Button::new();
            del.set_icon_name("user-trash-symbolic");
            del.add_css_class("flat");
            del.add_css_class("destructive-action");
            del.set_valign(gtk::Align::Center);
            del.set_tooltip_text(Some("移除此条目"));
            row.add_suffix(&del);
            rows_box.append(&row);
            let entries_list = entries_list.clone();
            let row = row.clone();
            let rows_box = rows_box.clone();
            let entry_for_del = entry.clone();
            del.connect_clicked(move |_| {
                entries_list
                    .borrow_mut()
                    .retain(|e| !e.eq_ignore_ascii_case(&entry_for_del));
                rows_box.remove(&row);
            });
        }
    });
    for e in entries_list.borrow().iter() {
        add_entry_row(e.clone());
    }
    allow_group.add(&rows_box);

    // input row for adding a new entry
    let input_row = adw::EntryRow::builder()
        .title("添加条目")
        .show_apply_button(true)
        .build();
    input_row.set_tooltip_text(Some("例如: example.com、*.example.com、10.0.0.1、192.168.1.0/24"));
    allow_group.add(&input_row);

    let loopback_switch = adw::SwitchRow::builder()
        .title("允许本机回环与 DNS")
        .subtitle("访问 127.0.0.1/localhost 及向系统 DNS 解析器发起查询")
        .active(app.sandbox.allow_loopback)
        .build();
    allow_group.add(&loopback_switch);
    page.add(&allow_group);

    // validation feedback + add on apply (Enter key or apply button)
    {
        let input_row_ref = input_row.clone();
        let entries_list = entries_list.clone();
        let add_entry_row = add_entry_row.clone();
        input_row.connect_apply(move |_| {
            let input_row = &input_row_ref;
            let text = input_row.text().trim().to_string();
            if text.is_empty() {
                return;
            }
            match classify_entry(&text) {
                Some(_) => {
                    input_row.remove_css_class("error");
                    input_row.set_title("添加条目");
                    let dup = entries_list
                        .borrow()
                        .iter()
                        .any(|e| e.eq_ignore_ascii_case(&text));
                    if !dup {
                        entries_list.borrow_mut().push(text.clone());
                        add_entry_row(text);
                    }
                    input_row.set_text("");
                }
                None => {
                    input_row.add_css_class("error");
                    input_row.set_title("无效条目 — 域名、IP 或 CIDR（如 10.0.0.0/8）");
                }
            }
        });
    }

    // --- save --------------------------------------------------------------
    let save_btn = gtk::Button::with_label("保存");
    save_btn.add_css_class("suggested-action");
    save_btn.add_css_class("pill");
    let save_box = gtk::Box::new(gtk::Orientation::Vertical, 8);
    save_box.set_margin_top(6);
    save_box.set_margin_bottom(18);
    save_box.set_margin_start(12);
    save_box.set_margin_end(12);
    save_box.append(&save_btn);

    let content = gtk::Box::new(gtk::Orientation::Vertical, 0);
    content.append(&page);
    content.append(&save_box);
    toolbar.set_content(Some(&content));
    dialog.set_child(Some(&toolbar));

    // save
    {
        let state = state.clone();
        let win = win.clone();
        let dialog = dialog.clone();
        let enable_switch = enable_switch.clone();
        let entries_list = entries_list.clone();
        let mode_switch = mode_switch.clone();
        save_btn.connect_clicked(move |_| {
            let enabled = enable_switch.is_active();
            let loopback = loopback_switch.is_active();
            let entries = entries_list.borrow().clone();
            let mode = if mode_switch.is_active() {
                crate::model::AllowMode::Blacklist
            } else {
                crate::model::AllowMode::Whitelist
            };

            let app_id = {
                let mut apps = state.apps.borrow_mut();
                let Some(idx) = apps.iter().position(|a| a.id == id) else { return };
                let app = &mut apps[idx];
                app.sandbox.enabled = enabled;
                app.sandbox.allow_entries = entries;
                app.sandbox.allow_loopback = loopback;
                app.sandbox.allow_mode = mode;
                app.id.clone()
            };
            // rewrite the rules file so a running bridge picks up the change
            // within its poll interval (dynamic effect); if the app is not
            // running, the next launch reads the same file.
            let app = state
                .apps
                .borrow()
                .iter()
                .find(|a| a.id == app_id)
                .cloned();
            if let Some(app) = app {
                crate::launcher::write_allow_file(&crate::launcher::config_base(), &app);
            }
            after_mutation(&state, &win);
            dialog.close();
        });
    }

    dialog.present(Some(win));
}
