//! "Add app" dialog: searchable list of system desktop entries.

use super::{after_mutation, entry_from_desktop, AppState};
use crate::desktop_scan::{self, DesktopApp};
use adw::prelude::*;
use std::rc::Rc;

pub fn present(win: &adw::ApplicationWindow, state: &Rc<AppState>) {
    let dialog = adw::Dialog::builder()
        .title("添加应用")
        .content_width(520)
        .content_height(620)
        .build();

    let toolbar = adw::ToolbarView::new();

    // header with close
    let header = adw::HeaderBar::new();
    toolbar.add_top_bar(&header);

    // search entry
    let search = gtk::SearchEntry::new();
    search.set_placeholder_text(Some("搜索应用…"));
    let search_clamp = adw::Clamp::builder().child(&search).maximum_size(480).build();
    let search_box = gtk::Box::new(gtk::Orientation::Vertical, 6);
    search_box.set_margin_top(12);
    search_box.set_margin_bottom(6);
    search_box.set_margin_start(12);
    search_box.set_margin_end(12);
    search_box.append(&search_clamp);

    // list of apps
    let listbox = gtk::ListBox::new();
    listbox.set_selection_mode(gtk::SelectionMode::None);
    listbox.add_css_class("boxed-list");
    let scroll = gtk::ScrolledWindow::new();
    scroll.set_child(Some(&listbox));
    scroll.set_vexpand(true);
    scroll.set_policy(gtk::PolicyType::Never, gtk::PolicyType::Automatic);

    let content = gtk::Box::new(gtk::Orientation::Vertical, 0);
    content.append(&search_box);
    content.append(&scroll);
    toolbar.set_content(Some(&content));
    dialog.set_child(Some(&toolbar));

    // scan + populate
    let apps = desktop_scan::scan_apps();
    let rows: Rc<std::cell::RefCell<Vec<(String, gtk::ListBoxRow)>>> =
        Rc::new(std::cell::RefCell::new(Vec::new()));

    for app in &apps {
        let row = build_row(win, state, app, &dialog);
        listbox.append(&row);
        rows.borrow_mut().push((app.name.to_lowercase(), row));
    }

    // live filter
    {
        let rows = rows.clone();
        let listbox = listbox.clone();
        search.connect_search_changed(move |entry| {
            let q = entry.text().to_lowercase();
            for (name, row) in rows.borrow().iter() {
                let visible = q.is_empty() || name.contains(&q);
                row.set_visible(visible);
            }
            // jump to first visible for keyboard users
            let _ = &listbox;
        });
    }

    dialog.present(Some(win));
}

fn build_row(
    win: &adw::ApplicationWindow,
    state: &Rc<AppState>,
    app: &DesktopApp,
    dialog: &adw::Dialog,
) -> gtk::ListBoxRow {
    let row = gtk::ListBoxRow::new();
    let hbox = gtk::Box::new(gtk::Orientation::Horizontal, 12);
    hbox.set_margin_top(8);
    hbox.set_margin_bottom(8);
    hbox.set_margin_start(12);
    hbox.set_margin_end(12);

    let image = if app.icon.starts_with('/') {
        gtk::Image::from_file(&app.icon)
    } else {
        gtk::Image::from_icon_name(app.icon.as_str())
    };
    image.set_pixel_size(32);
    hbox.append(&image);

    let vbox = gtk::Box::new(gtk::Orientation::Vertical, 2);
    vbox.set_valign(gtk::Align::Center);
    vbox.set_hexpand(true);
    let name = gtk::Label::new(Some(&app.name));
    name.set_halign(gtk::Align::Start);
    name.set_ellipsize(gtk::pango::EllipsizeMode::End);
    vbox.append(&name);
    let id_label = gtk::Label::new(Some(&app.desktop_id));
    id_label.add_css_class("caption");
    id_label.add_css_class("dimmed");
    id_label.set_halign(gtk::Align::Start);
    id_label.set_ellipsize(gtk::pango::EllipsizeMode::Middle);
    vbox.append(&id_label);
    hbox.append(&vbox);

    let add_btn = gtk::Button::new();
    add_btn.set_icon_name("list-add-symbolic");
    add_btn.set_tooltip_text(Some("添加到启动器"));
    add_btn.add_css_class("flat");
    add_btn.set_valign(gtk::Align::Center);
    hbox.append(&add_btn);

    row.set_child(Some(&hbox));

    {
        let win = win.clone();
        let state = state.clone();
        let app = app.clone();
        let dialog = dialog.clone();
        let row = row.clone();
        let btn_ref = add_btn.clone();
        btn_ref.connect_clicked(move |_| {
            let entry = entry_from_desktop(&app);
            state.apps.borrow_mut().push(entry);
            after_mutation(&state, &win);
            // visual feedback: turn into a check and disable
            add_btn.set_icon_name("object-select-symbolic");
            add_btn.set_sensitive(false);
            row.set_sensitive(false);
            // close after a short delay so the user sees the feedback
            let dialog = dialog.clone();
            gtk::glib::timeout_add_seconds_local_once(1, move || {
                dialog.close();
            });
        });
    }

    row
}
