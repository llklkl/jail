#!/usr/bin/env bash
# Build script for jail (top.llklkl.jail).
#
# The system lacks gtk4/libadwaita -devel packages, so we use a local sysroot
# (extracted from Fedora RPMs) for headers + pkg-config, while linking against
# the host's runtime libraries (versions match exactly).
set -euo pipefail

DEVDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/.devcache"
SYSROOT="$DEVDIR/sysroot"

export PATH="/home/lam/.cargo/bin:$PATH"          # bypass mise shim
export CARGO_HOME="$DEVDIR/cargo-home"
export PKG_CONFIG_PATH="$SYSROOT/usr/lib64/pkgconfig:$SYSROOT/usr/share/pkgconfig"
export PKG_CONFIG_SYSROOT_DIR="$SYSROOT"
export RUSTFLAGS="-L $SYSROOT/usr/lib64"
# Wayland software rendering fallbacks for sandboxed/dev environments:
export GSK_RENDERER="${GSK_RENDERER:-cairo}"
export GDK_DISABLE="${GDK_DISABLE:-vulkan}"

cd "$(dirname "${BASH_SOURCE[0]}")"

case "${1:-build}" in
  build)
    cargo build "${@:2}"
    ;;
  release)
    cargo build --release
    ;;
  run)
    cargo build
    exec ./target/debug/jail
    ;;
  test)
    cargo test
    ;;
  *)
    cargo "$@"
    ;;
esac
