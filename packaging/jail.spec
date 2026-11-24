# jail RPM spec — 二进制直载打包。
# CI（Fedora 容器）编译 release 后，把暂存的 usr/ 树打成 payload tar.gz
# 作为 Source0 交给本 spec；版本由流水线注入：rpmbuild --define 'pkgver x.y.z'。
# 仓库尚无 LICENSE 文件，故暂不写 License 头（rpmbuild 不强制，rpmlint 会提示）。

Name:           jail
Version:        %{pkgver}
Release:        1%{?dist}
Summary:        Linux app launcher with per-app network sandboxing

Source0:        jail-%{pkgver}-payload.tar.gz

%description
Linux 桌面应用启动器（Rust + GTK4/libadwaita，MD3 风格）。
每个应用运行于独立 user+network+mount 命名空间（无需 root、以当前用户身份
运行），所有流量经代理链路由宿主侧按域名 / 通配域名 / IP / CIDR 黑白名单
校验，DNS 按名单直接拦截（fail closed）。

%prep
%setup -c -q

%install
mkdir -p %{buildroot}
cp -a usr/. %{buildroot}/

%files
/usr/bin/jail
/usr/share/applications/top.llklkl.jail.desktop
/usr/share/icons/hicolor/64x64/apps/top.llklkl.jail.png
/usr/share/icons/hicolor/128x128/apps/top.llklkl.jail.png
/usr/share/icons/hicolor/256x256/apps/top.llklkl.jail.png
