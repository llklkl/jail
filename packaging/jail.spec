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
# payload tarball 顶层为 %{name}-%{version}/（标准上游布局，CI 打包时生成）。
# 解包用 gzip|tar 管道形式（与 rpm >= 6.1 自身自动解包的管线一致，实测
# 可靠）；CI 容器内 GNU tar 的 tar -xzf FILE -C DIR --strip-components=1
# 组合出现过程序性解出空目录的问题（v0.1.0 run5/run7）。
mkdir -p %{builddir}/%{name}-%{version}
gzip -dc %{SOURCE0} | tar -xf - -C %{builddir}/%{name}-%{version} --strip-components=1

%install
mkdir -p %{buildroot}
# 整树拷贝 usr 目录本身（BUILDROOT/usr/...，与 %files 清单对齐；
# 勿用 usr/. 平铺内容 —— 那会把 bin/share 平铺到 BUILDROOT 根下）
cp -a %{builddir}/%{name}-%{version}/usr %{buildroot}/
# 边界自检：%install 与 %files 之间若发生内容丢失立即报错定位
test -f %{buildroot}/usr/bin/jail || {
    echo "ERROR: BUILDROOT/usr/bin/jail missing after install"
    ls -laR %{buildroot} | head -30
    exit 1
}

%files
%license /usr/share/licenses/jail/LICENSE
/usr/bin/jail
/usr/share/applications/top.llklkl.jail.desktop
/usr/share/doc/jail/copyright
/usr/share/icons/hicolor/64x64/apps/top.llklkl.jail.png
/usr/share/icons/hicolor/128x128/apps/top.llklkl.jail.png
/usr/share/icons/hicolor/256x256/apps/top.llklkl.jail.png

%changelog
* Tue Nov 24 2026 llklkl <llklkl@users.noreply.github.com> - %{pkgver}-1
- Automated package build; see the git log for changes.
