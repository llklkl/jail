//! System tray (StatusNotifierItem) for background running.
//!
//! Implemented with `ksni` (pure Rust, D-Bus SNI). Menu actions run on the
//! ksni D-Bus thread — GTK calls must NOT be made there, so everything is
//! marshalled to the UI thread through the existing `UiMsg` channel.

use crate::ui::UiMsg;
use ksni::menu::StandardItem;
use ksni::{menu::MenuItem, Tray};
use std::sync::mpsc::Sender;

pub struct JailTray {
    tx: Sender<UiMsg>,
}

impl JailTray {
    pub fn new(tx: Sender<UiMsg>) -> Self {
        Self { tx }
    }

    fn send(&self, msg: UiMsg) {
        self.tx.send(msg).ok();
    }
}

impl Tray for JailTray {
    fn id(&self) -> String {
        "top.llklkl.jail".into()
    }

    fn icon_name(&self) -> String {
        "application-x-executable".into()
    }

    fn title(&self) -> String {
        "Jail 启动器".into()
    }

    fn tool_tip(&self) -> ksni::ToolTip {
        ksni::ToolTip {
            icon_name: self.icon_name(),
            title: "Jail 启动器".into(),
            description: "沙盒应用后台运行中\n右键打开菜单".into(),
            ..ksni::ToolTip::default()
        }
    }

    /// Left click on the icon: show the main window.
    fn activate(&mut self, _x: i32, _y: i32) {
        self.send(UiMsg::ShowWindow);
    }

    fn menu(&self) -> Vec<MenuItem<Self>> {
        vec![
            MenuItem::Standard(StandardItem {
                label: "显示主窗口".into(),
                icon_name: "view-grid-symbolic".into(),
                activate: Box::new(|this: &mut Self| this.send(UiMsg::ShowWindow)),
                ..StandardItem::default()
            }),
            MenuItem::Separator,
            MenuItem::Standard(StandardItem {
                label: "退出（关闭所有沙盒应用）".into(),
                icon_name: "system-shutdown-symbolic".into(),
                activate: Box::new(|this: &mut Self| this.send(UiMsg::Quit)),
                ..StandardItem::default()
            }),
        ]
    }
}

/// Spawn the tray service. Returns true when the tray is available
/// (SNI host reachable); false means the environment has no tray —
/// callers should fall back to normal close-to-quit behavior.
pub fn spawn(tx: Sender<UiMsg>) -> bool {
    use ksni::blocking::TrayMethods;
    match JailTray::new(tx).spawn() {
        Ok(handle) => {
            // The handle must live as long as the tray: the service shuts
            // down when it is dropped. The tray lives until process exit.
            std::mem::forget(handle);
            true
        }
        Err(e) => {
            eprintln!("jail: tray unavailable: {e}");
            false
        }
    }
}
