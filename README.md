# App Launcher

Linux 桌面应用启动器（Rust + GTK4/libadwaita，MD3 风格），支持按应用限制网络访问（域名 / IP 黑白名单）。

![tech](https://img.shields.io/badge/Rust-GTK4%20%2B%20libadwaita-orange)

## 功能

- **添加应用**：右上角 `+` 打开系统应用选择器（搜索、去重、过滤 NoDisplay/Hidden），来源包括
  `~/.local/share/applications`、`/usr/share/applications` 及 flatpak 导出目录
- **应用网格**：MD3 风格，图标在上、名称在下；运行中的应用图标右上角显示**绿色圆点**；
  启用了沙盒的应用显示盾牌角标
- **交互**：
  - 单击应用 = 直接启动（无确认）
  - 右键 / 长按 = 菜单：启动、设置沙盒…、访问日志…、运行日志…、删除…
  - 删除需弹窗确认（仅移除启动器条目，不卸载应用）
  - 访问日志（AdwDialog）：按主机汇总放行/拒绝/DNS 与流量（字典序排列），附原始 JSONL 视图；
    汇总行右键菜单：复制主机文本、允许访问（白名单）/ 禁止访问（黑名单）——修改即时生效
  - 运行日志（AdwDialog）：实时查看应用 stdout/stderr，内存环形缓冲上限 1 MB，
    自动丢弃最早输出，**不写入磁盘**；应用退出后仍可查看，下次启动时重置
  - 沙盒设置为应用内模态窗（AdwDialog）：启用开关、黑名单模式开关、规则条目、
    回环/DNS 开关
- **后台运行与托盘**：
  - 点击窗口 X = 最小化到系统托盘（沙盒应用继续运行），首次附桌面通知提醒；
    托盘左键恢复主窗口，托盘菜单「退出」才是彻底退出
  - **彻底退出时自动关闭所有由 jail 启动的沙盒应用**（SIGTERM → 等待 2s → SIGKILL），
    并清理 bridge/relay 进程（relay 监视 bridge socket 文件，自动跟随退出）
  - SIGTERM / Ctrl+C 同样触发优雅退出与清理；托盘不可用的环境自动降级为关窗即退出
- **网络沙盒**（每个应用独立配置）：
  - 应用运行在独立 user+network+mount 命名空间中（无需 root），且以**当前用户身份（非 root）**
    运行 —— 命名空间内不持有任何 capability，Electron 应用可正常运行
  - 命名空间内 nftables 策略为 `policy drop`，仅放行 loopback —— 直连一律失败（fail closed）
  - 唯一出口是代理链路：应用 → 127.0.0.1:8080（HTTP CONNECT）→ 命名空间内 relay
    → AF_UNIX 桥 → 宿主侧 bridge（执行域名/IP/CIDR 黑白名单校验）→ 互联网
  - DNS：`/etc/resolv.conf` 绑定挂载为 `nameserver 127.0.0.1`，由 relay 经桥转发到宿主解析器
    （宿主侧解析，兼容 VPN / 内网 DNS）
  - **DNS 拦截**：按黑白名单自动拦截——白名单下未列出的域名、黑名单下列出的域名，
    DNS 查询直接返回 REFUSED（不转发，防 DNS 隧道/外传）；拦截的查询在访问日志
    中计为「拦截 N」；名单内域名正常解析（归属学习不受影响）
  - **黑白名单**：白名单（默认，列表内放行/其余拒绝）或黑名单（列表内拒绝/其余放行）；
    匹配规则：域名精确匹配（`example.com`）、`*.example.com` 通配自身及任意深度子域名、
    精确 IP、CIDR 网段
  - **规则动态生效**：规则持久化在 `~/.config/jail/allow/<app_id>.json`，bridge 监视文件
    变化（≤2 秒轮询），设置保存或日志页允许/禁止操作后**立即生效**，无需重启应用；
    回环开关变更需重启应用（nft 层）
  - AppImage 应用自动以 extract-and-run 模式启动（命名空间内 FUSE 不可用）

## 构建

需要 Rust 1.75+。系统需安装 GTK4 / libadwaita 运行库与 `-devel` 开发包：

```bash
# Fedora
sudo dnf install gtk4-devel libadwaita-devel
# Debian/Ubuntu
sudo apt install libgtk-4-dev libadwaita-1-dev

./build.sh build          # debug
./build.sh release        # release (LTO + strip)
./build.sh test           # 单元测试 + 沙盒端到端测试
./build.sh run            # 构建并运行
```

> 本仓库的 `build.sh` 默认使用 `.devcache/sysroot`（从 Fedora RPM 解包的头文件 + pkg-config），
> 适用于无法安装 devel 包的环境；装有 devel 包的系统可直接 `cargo build`。

## 使用

1. 启动后点击右上角 `+`，搜索并添加系统应用
2. 右键应用 → 「设置沙盒…」→ 打开「启用沙盒」，填写允许的域名（如 `example.com`）
   或 IP/网段（如 `10.0.0.0/8`），保存
3. 单击应用启动。沙盒内应用只能访问白名单地址；未配置代理的应用程序将完全无法联网

## 沙盒能力边界（诚实声明）

- 这是**网络层白名单**：不隔离文件系统、设备、显示服务（那是 bubblewrap/flatpak 的领域）
- 依赖应用遵守 `HTTP_PROXY` / `HTTPS_PROXY` / `ALL_PROXY` 环境变量；不读代理变量的应用
  会被 nft 规则完全断网（fail closed，不会绕过白名单）
- 需要内核支持非特权 user namespace（`kernel.unprivileged_userns_clone=1`，主流发行版默认开启）

## 架构

```
src/
├── main.rs           入口：GUI / --bridge / --ns-relay / --ns-child 子命令
├── lib.rs            库 facade（供集成测试复用）
├── model.rs          AppEntry / SandboxConfig / Exec 字段码剥离
├── store.rs          ~/.config/jail/apps.json 原子读写
├── desktop_scan.rs   XDG + flatpak desktop 文件扫描
├── output_log.rs     应用输出内存环形缓冲（1 MB 上限，不落地）
├── sandbox.rs        nftables 规则（rustables/netlink 加载）
├── ns_child.rs       命名空间内启动器：uid 映射、特权 setup、降权 exec
├── proxy.rs          沙盒代理：宿主 bridge（白名单执行）+ ns relay（CONNECT/DNS）
├── launcher.rs       启动编排：进程跟踪、输出捕获、代理环境注入
└── ui/               主窗口、应用网格、添加对话框、沙盒模态窗、访问/运行日志、删除确认
```

## 测试

`./build.sh test` 包含 54 个测试：

- 单元测试：字段码剥离、store 读写/损坏恢复、IP/CIDR 解析、nft 批处理构建、
  黑白名单判定（精确/通配域名、IP、CIDR、回环、双模式）、DNS 拦截判定与
  REFUSED 响应、DNS 拦截计数、输出环形缓冲（轮转 / 硬截 / registry）、
  真实进程 spawn（含 stdout/stderr 捕获与重置）、Exec 双引号剥离、规则文件写入
- 端到端（`tests/e2e.rs`）：通过真实 `spawn_app` 路径启动沙盒内"假应用"，
  验证白名单域名可达（HTTP 200）、非白名单域名被拒、应用以非 root uid 运行、
  请求日志与输出捕获
