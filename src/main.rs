mod desktop_scan;
mod icons;
mod launcher;
mod model;
mod ns_child;
mod output_log;
mod proxy;
mod sandbox;
mod store;
mod ui;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    // Desktop integration: install/remove the .desktop entry + icon set so
    // jail can be launched from the app grid.
    if args.len() >= 2 && args[1] == "--install-desktop" {
        match icons::install_desktop() {
            Ok(path) => {
                println!("已安装桌面入口与图标：{}", path.display());
                println!("应用图标 ID：{}", icons::APP_ID);
            }
            Err(e) => {
                eprintln!("安装失败：{e}");
                std::process::exit(1);
            }
        }
        return;
    }
    if args.len() >= 2 && args[1] == "--uninstall-desktop" {
        match icons::uninstall_desktop() {
            Ok(path) => println!("已移除桌面入口：{}", path.display()),
            Err(e) => {
                eprintln!("移除失败：{e}");
                std::process::exit(1);
            }
        }
        return;
    }

    // Headless subcommands for the sandbox plumbing.
    if args.len() >= 4 && args[1] == "--bridge" {
        let socket_path = args[2].clone();
        // rules file: read at startup, re-read when the UI rewrites it
        let allow_path = args[3].clone();
        // optional 4th arg: JSONL request log path
        let log_path = args.get(4).cloned();
        if let Err(e) = proxy::run_host_bridge(&socket_path, std::path::Path::new(&allow_path), log_path) {
            eprintln!("jail bridge: {e}");
            std::process::exit(1);
        }
        return;
    }
    if args.len() >= 3 && args[1] == "--ns-relay" {
        let socket_path = args[2].clone();
        if let Err(e) = proxy::run_ns_relay(socket_path) {
            eprintln!("jail ns-relay: {e}");
            std::process::exit(1);
        }
        return;
    }
    if args.len() >= 4 && args[1] == "--ns-child" {
        if let Err(e) = ns_child::run(&args[2..]) {
            eprintln!("jail ns-child: {e}");
            std::process::exit(1);
        }
        return;
    }

    ui::run();
}
