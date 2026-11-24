# jail RPM spec — 二进制直载打包。
# CI（Fedora 容器，matrix 覆盖受支持的发布版）编译 release 后，把暂存的
# usr/ 树打成 payload tar.gz 作为 Source0 交给本 spec；由流水线注入：
#   rpmbuild --define 'pkgver x.y.z' --define 'dist .fcNN'

Name:           jail
Version:        %{pkgver}
Release:        1%{?dist}
Summary:        Linux app launcher with per-app network sandboxing
License:        MIT

Source0:        jail-%{pkgver}-payload.tar.gz

%description
Linux 桌面应用启动器（Rust + GTK4/libadwaita，MD3 风格）。
每个应用运行于独立 user+network+mount 命名空间（无需 root、以当前用户身份
运行），所有流量经代理链路由宿主侧按域名 / 通配域名 / IP / CIDR 黑白名单
校验，DNS 按名单直接拦截（fail closed）。

%prep
# 不用 %setup：rpm 6.1 的 %setup -c + rpmuncompress 对顶层非 name-version
# 布局的 payload 会解出空目录（v0.1.0 CI 实测）。手动解包到 %{builddir}
# 下的固定位置，%install 用同一绝对路径取用，对 rpm 4.x/6.x 都成立。
mkdir -p %{builddir}/payload
tar -xzf %{SOURCE0} -C %{builddir}/payload

%install
mkdir -p %{buildroot}
cp -a %{builddir}/payload/usr/. %{buildroot}/

%files
%license /usr/share/licenses/jail/LICENSE
/usr/bin/jail
/usr/share/applications/top.llklkl.jail.desktop
/usr/share/icons/hicolor/64x64/apps/top.llklkl.jail.png
/usr/share/icons/hicolor/128x128/apps/top.llklkl.jail.png
/usr/share/icons/hicolor/256x256/apps/top.llklkl.jail.png

%changelog
* Tue Nov 24 2026 llklkl <llklkl@users.noreply.github.com> - %{pkgver}-1
- Automated package build; see the git log for changes.
