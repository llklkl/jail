//! Sandbox settings modal (AdwDialog) for one app entry.

use super::{after_mutation, AppState};
use adw::prelude::*;
use std::rc::Rc;

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

    // --- allowlist group ---------------------------------------------------
    let allow_group = adw::PreferencesGroup::new();
    allow_group.set_title("允许访问的地址");
    allow_group.set_description(
        Some("域名在启动时解析为 IP；多个用逗号分隔。未列出的地址将被拒绝。"),
    );

    let domains_row = adw::EntryRow::builder()
        .title("允许的域名")
        .text(app.sandbox.allow_domains.join(", "))
        .build();
    domains_row.set_tooltip_text(Some("例如: example.com, api.github.com"));
    allow_group.add(&domains_row);

    let ips_row = adw::EntryRow::builder()
        .title("允许的 IP / 网段")
        .text(app.sandbox.allow_ips.join(", "))
        .build();
    ips_row.set_tooltip_text(Some("例如: 10.0.0.1, 192.168.1.0/24"));
    allow_group.add(&ips_row);

    let loopback_switch = adw::SwitchRow::builder()
        .title("允许本机回环与 DNS")
        .subtitle("访问 127.0.0.1/localhost 及向系统 DNS 解析器发起查询")
        .active(app.sandbox.allow_loopback)
        .build();
    allow_group.add(&loopback_switch);
    page.add(&allow_group);

    // --- preview group -----------------------------------------------------
    let preview_group = adw::PreferencesGroup::new();
    preview_group.set_title("域名解析预览");
    let preview_label = gtk::Label::new(Some("点击下方按钮解析域名"));
    preview_label.set_halign(gtk::Align::Start);
    preview_label.set_wrap(true);
    preview_label.add_css_class("dimmed");
    preview_group.add(&preview_label);
    let preview_btn = gtk::Button::with_label("解析域名");
    preview_btn.add_css_class("flat");
    preview_group.add(&preview_btn);
    page.add(&preview_group);

    // --- notes group -------------------------------------------------------
    let notes_group = adw::PreferencesGroup::new();
    notes_group.set_title("说明");
    let notes = gtk::Label::new(Some(
        "· 沙盒仅限制网络访问（域名/IP 白名单），不隔离文件系统与设备。\n\
         · 启动器退出后，已启动的应用继续运行，沙盒规则随其网络命名空间保留。\n\
         · 若系统禁用用户命名空间，沙盒启动会失败并提示。",
    ));
    notes.set_halign(gtk::Align::Start);
    notes.set_wrap(true);
    notes.add_css_class("dimmed");
    notes.add_css_class("caption");
    notes_group.add(&notes);
    page.add(&notes_group);

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

    // preview button: resolve domains on a worker thread
    {
        let domains_row = domains_row.clone();
        let preview_label = preview_label.clone();
        preview_btn.connect_clicked(move |_| {
            let domains: Vec<String> = domains_row
                .text()
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            let label = preview_label.clone();
            preview_label.add_css_class("dimmed");
            // resolve on a worker thread; hop back with plain data only
            let (tx, rx) = std::sync::mpsc::channel::<String>();
            std::thread::spawn(move || {
                let (ips, failed) = crate::sandbox::resolve_domains(&domains);
                let text = if domains.is_empty() {
                    "未填写域名".to_string()
                } else if ips.is_empty() {
                    format!("解析失败: {}", failed.join(", "))
                } else {
                    let mut t = format!("解析到 {} 个地址:", ips.len());
                    for ip in &ips {
                        t.push_str(&format!(" {ip}"));
                    }
                    if !failed.is_empty() {
                        t.push_str(&format!("（失败: {}）", failed.join(", ")));
                    }
                    t
                };
                tx.send(text).ok();
            });
            gtk::glib::timeout_add_local(std::time::Duration::from_millis(200), move || {
                if let Ok(text) = rx.try_recv() {
                    label.set_text(&text);
                    return gtk::glib::ControlFlow::Break;
                }
                gtk::glib::ControlFlow::Continue
            });
        });
    }

    // save
    {
        let state = state.clone();
        let win = win.clone();
        let dialog = dialog.clone();
        let enable_switch = enable_switch.clone();
        let domains_row = domains_row.clone();
        let ips_row = ips_row.clone();
        let loopback_switch = loopback_switch.clone();
        save_btn.connect_clicked(move |_| {
            let enabled = enable_switch.is_active();
            let domains: Vec<String> = domains_row
                .text()
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            let ips: Vec<String> = ips_row
                .text()
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            let loopback = loopback_switch.is_active();

            {
                let mut apps = state.apps.borrow_mut();
                let Some(idx) = apps.iter().position(|a| a.id == id) else { return };
                let app = &mut apps[idx];
                app.sandbox.enabled = enabled;
                app.sandbox.allow_domains = domains;
                app.sandbox.allow_ips = ips;
                app.sandbox.allow_loopback = loopback;
            }
            after_mutation(&state, &win);
            dialog.close();
        });
    }

    dialog.present(Some(win));
}
