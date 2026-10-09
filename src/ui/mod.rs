//! UI assembly: main window, app grid, header bar, menus, dialogs, tray.

mod add_dialog;
mod log_data;
mod log_dialog;
mod output_log_dialog;
mod sandbox_dialog;
mod tray;

use crate::desktop_scan::{self, DesktopApp};
use crate::launcher::{self, LaunchMode, RunningRegistry};
use crate::model::{strip_field_codes, AppEntry};
use crate::output_log::OutputLogRegistry;
use crate::store::Store;
use gtk::{glib, gio};
use adw::prelude::*;
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc::{Receiver, Sender}, Arc};

/// Messages from worker threads back to the UI loop.
pub enum UiMsg {
    /// DNS resolution done; spawn on the main thread.
    LaunchReady(AppEntry, LaunchMode),
    /// Launch failed; show an error.
    LaunchFailed(String, String),
    /// A tracked app process exited.
    AppExited(String),
    /// Restore the main window (tray icon click / tray menu).
    ShowWindow,
    /// Real quit: terminate all sandboxed apps, then exit.
    Quit,
}

/// Whether the first minimize-to-tray hint notification was already sent.
static MINIMIZE_HINT_SENT: AtomicBool = AtomicBool::new(false);

/// Shared UI state.
pub struct AppState {
    pub store: Store,
    pub apps: RefCell<Vec<AppEntry>>,
    pub registry: Arc<RunningRegistry>,
    /// In-memory stdout/stderr capture per app (most recent run).
    pub logs: Arc<OutputLogRegistry>,
    /// badge widget per app id (refreshed on grid rebuild)
    pub badges: RefCell<HashMap<String, gtk::Widget>>,
    pub tx: Sender<UiMsg>,
}

/// Drain all pending UI messages without blocking.
fn drain_msgs(state: &Rc<AppState>, win: &adw::ApplicationWindow, rx: &Receiver<UiMsg>) {
    while let Ok(msg) = rx.try_recv() {
        handle_msg(state, win, msg);
    }
}

pub fn run() {
    let app = adw::Application::builder()
        .application_id("top.llklkl.jail")
        .flags(gio::ApplicationFlags::NON_UNIQUE)
        .build();
    // shared with build_ui so the post-run cleanup (below) can reach the
    // same registry
    let registry: Arc<RunningRegistry> = Arc::new(RunningRegistry::default());
    let registry_for_build = Arc::clone(&registry);
    app.connect_activate(move |app| build_ui(app, &registry_for_build));
    app.run();
    // every exit path (tray quit, no-tray close, signal-triggered quit)
    // funnels through here: make sure sandboxed apps don't outlive us
    registry.terminate_all();
}

fn load_css() {
    let css = r#"
    .running-badge {
        min-width: 12px; min-height: 12px;
        border-radius: 9999px;
        background: #2ecc71;
        border: 2px solid @window_bg_color;
    }
    .app-tile { border-radius: 16px; padding: 12px 6px; }
    .app-tile:hover { background: alpha(currentColor, 0.07); }
    .app-name { font-size: 13px; }
    .sandbox-chip { opacity: 0.8; }
    .context-menu { min-width: 170px; }
    .context-menu list { background: transparent; }
    .log-chip {
        border-radius: 9999px;
        padding: 2px 10px;
        font-size: 11px;
        font-weight: 700;
    }
    .log-chip-allowed { background: alpha(@success_color, 0.22); color: @success_color; }
    .log-chip-denied { background: alpha(@error_color, 0.22); color: @error_color; }
    .log-chip-mixed { background: alpha(@warning_color, 0.22); color: @warning_color; }
    .log-chip-dns { background: alpha(currentColor, 0.12); color: alpha(currentColor, 0.75); }
    "#;
    let provider = gtk::CssProvider::new();
    provider.load_from_string(css);
    if let Some(display) = gtk::gdk::Display::default() {
        gtk::style_context_add_provider_for_display(
            &display,
            &provider,
            gtk::STYLE_PROVIDER_PRIORITY_APPLICATION,
        );
    }
}

fn build_ui(app: &adw::Application, registry: &Arc<RunningRegistry>) {
    load_css();

    let store = Store::new();
    let apps = store.load();
    let logs: Arc<OutputLogRegistry> = Arc::new(OutputLogRegistry::default());

    // Channel from worker threads to the UI loop (std mpsc, drained by a
    // periodic source on the main loop). The tray and the signal listener
    // also send through it, marshalling their actions to the main thread.
    let (tx, rx) = std::sync::mpsc::channel::<UiMsg>();
    let rx = Arc::new(rx);

    // graceful shutdown on SIGTERM / SIGINT (e.g. systemctl --user stop,
    // kill <pid>): marshal to the UI thread so children die with us
    install_signal_quit(tx.clone());

    let state = Rc::new(AppState {
        store,
        apps: RefCell::new(apps),
        registry: registry.clone(),
        logs,
        badges: RefCell::new(HashMap::new()),
        tx,
    });

    let win = adw::ApplicationWindow::new(app);
    win.set_title(Some("Jail 启动器"));
    win.set_default_size(900, 640);
    // window/taskbar icon (resolved from the theme; `jail --install-desktop`
    // installs the icon into the user hicolor theme)
    win.set_icon_name(Some(crate::icons::APP_ID));

    // --- tray: clicking X hides to tray; real quit lives in the tray menu
    let tray_active = tray::spawn(state.tx.clone());
    // The guard must be dropped only at shutdown — hold() releases the
    // application if the guard is dropped early, so forget it (intentional).
    std::mem::forget(app.hold()); // keep running with no visible windows

    {
        // close → minimize (when a tray exists); the tray menu's 退出 is the
        // real exit. Without a tray, closing the window quits as before.
        let close_win = win.clone();
        let close_app = app.clone();
        win.connect_close_request(move |_| {
            if tray_active {
                close_win.set_visible(false);
                if !MINIMIZE_HINT_SENT.swap(true, Ordering::Relaxed) {
                    let n = gio::Notification::new("Jail 启动器");
                    n.set_title("Jail 仍在后台运行");
                    n.set_body(Some("沙盒应用不会被关闭。点击托盘图标恢复窗口，或从托盘菜单退出。"));
                    close_app.send_notification(Some("minimized"), &n);
                }
                glib::Propagation::Stop
            } else {
                glib::Propagation::Proceed
            }
        });
    }

    // --- header bar -------------------------------------------------------
    let header = adw::HeaderBar::new();
    let title = gtk::Label::new(Some("Jail 启动器"));
    title.add_css_class("title");
    header.set_title_widget(Some(&title));

    let add_btn = gtk::Button::new();
    add_btn.set_icon_name("list-add-symbolic");
    add_btn.set_tooltip_text(Some("添加应用"));
    add_btn.add_css_class("flat");
    header.pack_end(&add_btn);

    let menu_btn = gtk::MenuButton::new();
    menu_btn.set_icon_name("open-menu-symbolic");
    menu_btn.set_tooltip_text(Some("菜单"));
    menu_btn.set_menu_model(Some(&header_menu()));
    header.pack_end(&menu_btn);

    // --- content: grid / empty -------------------------------------------
    let flowbox = gtk::FlowBox::new();
    flowbox.set_valign(gtk::Align::Start);
    flowbox.set_selection_mode(gtk::SelectionMode::None);
    flowbox.set_min_children_per_line(3);
    flowbox.set_max_children_per_line(6);
    flowbox.set_column_spacing(12);
    flowbox.set_row_spacing(12);
    flowbox.set_margin_top(18);
    flowbox.set_margin_bottom(18);
    flowbox.set_margin_start(18);
    flowbox.set_margin_end(18);

    let grid_scroll = gtk::ScrolledWindow::new();
    grid_scroll.set_child(Some(&flowbox));
    grid_scroll.set_vexpand(true);

    let empty = build_empty_page(&win, &state);

    let stack = gtk::Stack::new();
    stack.add_named(&grid_scroll, Some("grid"));
    stack.add_named(&empty, Some("empty"));

    let view = adw::ToolbarView::new();
    view.add_top_bar(&header);
    view.set_content(Some(&stack));
    win.set_content(Some(&view));

    // --- window-level actions (context menu items target these) -----------
    install_actions(&win, &state);

    // --- header buttons ---------------------------------------------------
    {
        let win = win.clone();
        let state = state.clone();
        add_btn.connect_clicked(move |_| {
            add_dialog::present(&win, &state);
        });
    }
    {
        let state = state.clone();
        let win = win.clone();
        let refresh = gio::SimpleAction::new("refresh", None);
        refresh.connect_activate(move |_, _| {
            refresh_from_system(&state);
            redraw(&state, &win);
        });
        app.add_action(&refresh);
    }
    {
        let win = win.clone();
        let about = gio::SimpleAction::new("about", None);
        about.connect_activate(move |_, _| {
            let dlg = adw::AboutDialog::builder()
                .application_name("Jail 启动器")
                .application_icon(crate::icons::APP_ID)
                .developer_name("App Launcher")
                .version(env!("CARGO_PKG_VERSION"))
                .comments("Linux 应用启动器（top.llklkl.jail），支持按应用限制网络访问（域名 / IP）。")
                .license_type(gtk::License::MitX11)
                .build();
            dlg.present(Some(&win));
        });
        app.add_action(&about);
    }

    // --- UI message pump --------------------------------------------------
    {
        let state = state.clone();
        let win = win.clone();
        glib::timeout_add_local(std::time::Duration::from_millis(150), move || {
            drain_msgs(&state, &win, &rx);
            glib::ControlFlow::Continue
        });
    }

    redraw(&state, &win);
    win.present();
}

/// Block SIGTERM/SIGINT and spawn a watcher that turns them into a graceful
/// `UiMsg::Quit` (children terminated, then exit).
fn install_signal_quit(tx: Sender<UiMsg>) {
    use signal_hook::consts::{SIGINT, SIGTERM};
    let mut signals = signal_hook::iterator::Signals::new([SIGINT, SIGTERM])
        .expect("install signal handlers");
    std::thread::spawn(move || {
        for sig in signals.forever() {
            eprintln!("jail: received signal {sig}, shutting down");
            tx.send(UiMsg::Quit).ok();
        }
    });
}

fn header_menu() -> gio::Menu {
    let menu = gio::Menu::new();
    menu.append(Some("刷新应用列表"), Some("app.refresh"));
    menu.append(Some("关于"), Some("app.about"));
    menu
}

fn build_empty_page(win: &adw::ApplicationWindow, state: &Rc<AppState>) -> adw::StatusPage {
    let page = adw::StatusPage::builder()
        .icon_name("application-x-executable-symbolic")
        .title("还没有应用")
        .description("点击右上角 + 从系统应用列表中添加")
        .build();
    let btn = gtk::Button::with_label("添加应用");
    btn.add_css_class("pill");
    btn.add_css_class("suggested-action");
    {
        let win = win.clone();
        let state = state.clone();
        btn.connect_clicked(move |_| add_dialog::present(&win, &state));
    }
    page.set_child(Some(&btn));
    page
}

fn install_actions(win: &adw::ApplicationWindow, state: &Rc<AppState>) {
    let launch = gio::SimpleAction::new("launch", Some(glib::VariantTy::STRING));
    {
        let state = state.clone();
        let win = win.clone();
        launch.connect_activate(move |_, param| {
            if let Some(id) = param.and_then(|v| v.str()) {
                launch_app(&state, &win, id);
            }
        });
    }
    win.add_action(&launch);

    let sandbox = gio::SimpleAction::new("sandbox", Some(glib::VariantTy::STRING));
    {
        let state = state.clone();
        let win = win.clone();
        sandbox.connect_activate(move |_, param| {
            if let Some(id) = param.and_then(|v| v.str()) {
                sandbox_dialog::present(&win, &state, id);
            }
        });
    }
    win.add_action(&sandbox);

    let remove = gio::SimpleAction::new("remove", Some(glib::VariantTy::STRING));
    {
        let state = state.clone();
        let win = win.clone();
        remove.connect_activate(move |_, param| {
            if let Some(id) = param.and_then(|v| v.str()) {
                confirm_remove(&win, &state, id);
            }
        });
    }
    win.add_action(&remove);
}

fn confirm_remove(win: &adw::ApplicationWindow, state: &Rc<AppState>, id: &str) {
    let name = state
        .apps
        .borrow()
        .iter()
        .find(|a| a.id == id)
        .map(|a| a.name.clone())
        .unwrap_or_default();
    let id = id.to_string();
    let alert = adw::AlertDialog::builder()
        .heading(format!("删除「{name}」？"))
        .body("仅从启动器移除，不会卸载应用本身。")
        .build();
    alert.add_response("cancel", "取消");
    alert.add_response("delete", "删除");
    alert.set_response_appearance("delete", adw::ResponseAppearance::Destructive);
    alert.set_default_response(Some("cancel"));
    alert.set_close_response("cancel");
    {
        let state = state.clone();
        let win = win.clone();
        alert.connect_response(Some("delete"), move |_, _| {
            state.apps.borrow_mut().retain(|a| a.id != id);
            state.registry.remove(&id);
            state.logs.remove(&id);
            after_mutation(&state, &win);
        });
    }
    alert.present(Some(win));
}

/// Locate (flowbox, stack) through the window content.
fn find_grid(win: &adw::ApplicationWindow) -> Option<(gtk::FlowBox, gtk::Stack)> {
    let view = win.content()?.downcast::<adw::ToolbarView>().ok()?;
    let stack = view.content()?.downcast::<gtk::Stack>().ok()?;
    let scroll = stack
        .child_by_name("grid")?
        .downcast::<gtk::ScrolledWindow>()
        .ok()?;
    // GTK4 auto-wraps non-scrollable children in a GtkViewport; FlowBox does not
    // implement GtkScrollable, so the FlowBox lives inside the viewport.
    let inner = scroll.child()?;
    let flowbox = if inner.is::<gtk::Viewport>() {
        inner.downcast::<gtk::Viewport>().ok()?.child()?.downcast::<gtk::FlowBox>().ok()?
    } else {
        inner.downcast::<gtk::FlowBox>().ok()?
    };
    Some((flowbox, stack))
}

/// Rebuild the grid from state.apps and update the empty/grid stack page.
pub fn redraw(state: &Rc<AppState>, win: &adw::ApplicationWindow) {
    let Some((flowbox, stack)) = find_grid(win) else { return };
    while let Some(child) = flowbox.child_at_index(0) {
        flowbox.remove(&child);
    }
    state.badges.borrow_mut().clear();

    let apps = state.apps.borrow().clone();
    for app in &apps {
        flowbox.append(&build_tile(state, app, win));
    }
    stack.set_visible_child_name(if apps.is_empty() { "empty" } else { "grid" });
}

fn build_tile(
    state: &Rc<AppState>,
    app: &AppEntry,
    win: &adw::ApplicationWindow,
) -> gtk::FlowBoxChild {
    let child = gtk::FlowBoxChild::new();
    child.set_focusable(false);
    child.add_css_class("app-tile");

    let inner = gtk::Box::new(gtk::Orientation::Vertical, 8);

    // icon (top)
    let image = if app.icon.starts_with('/') {
        gtk::Image::from_file(&app.icon)
    } else {
        gtk::Image::from_icon_name(app.icon.as_str())
    };
    image.set_pixel_size(64);
    image.set_vexpand(true);
    image.set_valign(gtk::Align::Center);
    inner.append(&image);

    // name (bottom)
    let label = gtk::Label::new(Some(&app.name));
    label.add_css_class("app-name");
    label.set_ellipsize(gtk::pango::EllipsizeMode::End);
    label.set_justify(gtk::Justification::Center);
    label.set_width_chars(10);
    label.set_max_width_chars(14);
    inner.append(&label);

    // overlay: running badge (top-right), sandbox chip (bottom-right)
    let overlay = gtk::Overlay::new();
    overlay.set_child(Some(&inner));

    let badge = gtk::Label::new(None);
    badge.add_css_class("running-badge");
    badge.set_halign(gtk::Align::End);
    badge.set_valign(gtk::Align::Start);
    badge.set_margin_top(4);
    badge.set_margin_end(10);
    badge.set_visible(state.registry.is_running(&app.id));
    overlay.add_overlay(&badge);
    state
        .badges
        .borrow_mut()
        .insert(app.id.clone(), badge.upcast::<gtk::Widget>());

    if app.sandbox.enabled {
        let chip = gtk::Image::from_icon_name("security-high-symbolic");
        chip.add_css_class("sandbox-chip");
        chip.set_tooltip_text(Some("已启用网络沙盒"));
        chip.set_pixel_size(14);
        chip.set_halign(gtk::Align::End);
        chip.set_valign(gtk::Align::End);
        chip.set_margin_bottom(2);
        chip.set_margin_end(10);
        overlay.add_overlay(&chip);
    }

    child.set_child(Some(&overlay));

    // context menu (right click / long press)
    let popover = build_context_menu(state, win, &app.id);
    popover.set_parent(&child);

    // single click: launch, no confirmation
    {
        let state = state.clone();
        let win = win.clone();
        let id = app.id.clone();
        let click = gtk::GestureClick::new();
        click.set_button(1);
        click.connect_released(move |_, _, _, _| {
            launch_app(&state, &win, &id);
        });
        child.add_controller(click);
    }
    // right click: menu at pointer
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
        child.add_controller(click);
    }
    // long press (touch): menu
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
        child.add_controller(lp);
    }

    child
}

/// Build the tile context menu as a manual Popover with direct button
/// handlers. (A Gio MenuModel + PopoverMenu resolves item actions through the
/// widget action muxer, which proved unreliable for popped-up menus; direct
/// closures are always clickable.)
fn build_context_menu(
    state: &Rc<AppState>,
    win: &adw::ApplicationWindow,
    app_id: &str,
) -> gtk::Popover {
    let popover = gtk::Popover::new();
    popover.add_css_class("context-menu");
    popover.set_autohide(true);

    let list = gtk::ListBox::new();
    list.set_selection_mode(gtk::SelectionMode::None);
    list.add_css_class("rich-list");
    list.set_margin_top(6);
    list.set_margin_bottom(6);

    let add_item = |list: &gtk::ListBox, icon: &str, label: &str| -> gtk::Button {
        let row = gtk::ListBoxRow::new();
        row.set_activatable(false);
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
        row.set_child(Some(&btn));
        list.append(&row);
        btn
    };

    let pop = popover.clone();
    let launch_btn = add_item(&list, "media-playback-start-symbolic", "启动");
    {
        let state = state.clone();
        let win = win.clone();
        let id = app_id.to_string();
        launch_btn.connect_clicked(move |_| {
            pop.popdown();
            launch_app(&state, &win, &id);
        });
    }
    let pop = popover.clone();
    let sandbox_btn = add_item(&list, "security-high-symbolic", "设置沙盒…");
    {
        let state = state.clone();
        let win = win.clone();
        let id = app_id.to_string();
        sandbox_btn.connect_clicked(move |_| {
            pop.popdown();
            sandbox_dialog::present(&win, &state, &id);
        });
    }
    let pop = popover.clone();
    let log_btn = add_item(&list, "document-open-recent-symbolic", "访问日志…");
    {
        let state = state.clone();
        let win = win.clone();
        let id = app_id.to_string();
        log_btn.connect_clicked(move |_| {
            pop.popdown();
            open_log_dialog(&win, &state, &id);
        });
    }
    let pop = popover.clone();
    let output_btn = add_item(&list, "utilities-terminal-symbolic", "运行日志…");
    {
        let state = state.clone();
        let win = win.clone();
        let id = app_id.to_string();
        output_btn.connect_clicked(move |_| {
            pop.popdown();
            open_output_log_dialog(&win, &state, &id);
        });
    }
    let pop = popover.clone();
    let remove_btn = add_item(&list, "user-trash-symbolic", "删除…");
    {
        let state = state.clone();
        let win = win.clone();
        let id = app_id.to_string();
        remove_btn.connect_clicked(move |_| {
            pop.popdown();
            confirm_remove(&win, &state, &id);
        });
    }

    popover.set_child(Some(&list));
    popover
}

/// Open the access-log dialog for one app. The log lives in the config dir
/// next to apps.json; apps without a log file yet get an empty view.
fn open_log_dialog(win: &adw::ApplicationWindow, state: &Rc<AppState>, id: &str) {
    let Some(app) = state.apps.borrow().iter().find(|a| a.id == id).cloned() else {
        return;
    };
    let base = crate::launcher::config_base();
    let log_path = base.join("logs").join(format!("{}.jsonl", app.id));
    log_dialog::present(win, state, id, log_path);
}

/// Open the run-output dialog for one app: the in-memory capture of its most
/// recent run's stdout/stderr (empty view when it never ran this session).
fn open_output_log_dialog(win: &adw::ApplicationWindow, state: &Rc<AppState>, id: &str) {
    let Some(app) = state.apps.borrow().iter().find(|a| a.id == id).cloned() else {
        return;
    };
    let log = state.logs.get(id);
    let registry = state.registry.clone();
    let id = id.to_string();
    output_log_dialog::present(win, &app, log, move || registry.is_running(&id));
}

/// Kick off a launch: DNS resolution happens on a worker thread, then the
/// spawn + badge update happen on the UI thread via the message channel.
pub fn launch_app(state: &Rc<AppState>, win: &adw::ApplicationWindow, id: &str) {
    let Some(app) = state.apps.borrow().iter().find(|a| a.id == id).cloned() else {
        return;
    };
    let tx = state.tx.clone();
    std::thread::spawn(move || match launcher::prepare_launch(&app) {
        Ok(mode) => {
            tx.send(UiMsg::LaunchReady(app, mode)).ok();
        }
        Err(e) => {
            tx.send(UiMsg::LaunchFailed(app.id.clone(), e.to_string())).ok();
        }
    });
    let _ = win;
}

fn handle_msg(state: &Rc<AppState>, win: &adw::ApplicationWindow, msg: UiMsg) {
    match msg {
        UiMsg::LaunchReady(app, mode) => match launcher::spawn_app(&app, &mode, &state.logs) {
            Ok(running) => {
                let handle = state.registry.insert(running);
                if let Some(badge) = state.badges.borrow().get(&app.id) {
                    badge.set_visible(true);
                }
                let tx = state.tx.clone();
                let registry = state.registry.clone();
                launcher::watch(
                    handle,
                    registry,
                    Box::new(move |id| {
                        tx.send(UiMsg::AppExited(id)).ok();
                    }),
                );
            }
            Err(e) => show_error(win, &format!("启动「{}」失败", app.name), &e.to_string()),
        },
        UiMsg::LaunchFailed(id, err) => {
            let name = state
                .apps
                .borrow()
                .iter()
                .find(|a| a.id == id)
                .map(|a| a.name.clone())
                .unwrap_or_else(|| "应用".into());
            show_error(win, &format!("启动「{name}」失败"), &err);
        }
        UiMsg::AppExited(id) => {
            if let Some(badge) = state.badges.borrow().get(&id) {
                badge.set_visible(false);
            }
        }
        UiMsg::ShowWindow => {
            win.present();
        }
        UiMsg::Quit => {
            // terminating children + bridge socket cleanup happens after the
            // GTK main loop returns (ui::run), keeping this handler trivial
            if let Some(app) = win.application() {
                app.quit();
            }
        }
    }
}

fn show_error(win: &adw::ApplicationWindow, heading: &str, body: &str) {
    let alert = adw::AlertDialog::builder()
        .heading(heading)
        .body(body)
        .build();
    alert.add_response("ok", "确定");
    alert.set_default_response(Some("ok"));
    alert.present(Some(win));
}

/// Re-resolve added apps' metadata from their desktop files.
fn refresh_from_system(state: &Rc<AppState>) {
    let mut apps = state.apps.borrow_mut();
    for app in apps.iter_mut() {
        if let Some(found) = desktop_scan::find_app(&app.desktop_id) {
            app.name = found.name;
            app.icon = found.icon;
            app.exec = strip_field_codes(&found.exec);
        }
    }
    let _ = state.store.save(&apps);
}

/// Called after any state mutation: persist + redraw.
pub fn after_mutation(state: &Rc<AppState>, win: &adw::ApplicationWindow) {
    let _ = state.store.save(&state.apps.borrow());
    redraw(state, win);
}

/// Convert a scanned desktop app into a launcher entry.
pub fn entry_from_desktop(d: &DesktopApp) -> AppEntry {
    AppEntry::new(
        d.desktop_id.clone(),
        d.name.clone(),
        d.icon.clone(),
        strip_field_codes(&d.exec),
    )
}

