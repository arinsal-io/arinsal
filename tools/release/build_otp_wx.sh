#!/usr/bin/env bash
set -euo pipefail

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)
prefix=${HOME}/.cache/arinsal/otp-29.1.1-wx
otp_source="$repo/ref/otp-29"

if ! brew list wxwidgets >/dev/null 2>&1; then
    echo "build_otp_wx.sh: wxWidgets is missing; install it with: brew install wxwidgets" >&2
    exit 1
fi

wx_config="$(brew --prefix wxwidgets)/bin/wx-config"
if [ ! -x "$wx_config" ]; then
    echo "build_otp_wx.sh: wx-config is missing: $wx_config" >&2
    exit 1
fi

build=$(mktemp -d /private/tmp/otp-29.1.1-wx-build.XXXXXX)
trap 'rm -rf "$build"' EXIT HUP INT TERM
mkdir -p "$build/source"
git -C "$otp_source" archive OTP-29.1.1 | tar -x -C "$build/source"
cd "$build/source"

./configure \
    --prefix="$prefix" \
    --with-wx-config="$wx_config" \
    --with-odbc="$(brew --prefix unixodbc)" \
    --with-ssl="$(brew --prefix openssl@3)" \
    --enable-darwin-64bit
make -j"$(sysctl -n hw.ncpu)"
make install

otp_root="$prefix/lib/erlang"
if [ ! -x "$prefix/bin/erl" ] || \
    [ ! -f "$otp_root/lib/wx-2.7/priv/wxe_driver.so" ] || \
    [ ! -d "$otp_root/lib/observer-2.19/ebin" ]; then
    echo "build_otp_wx.sh: installed OTP tree is missing wx or observer: $otp_root" >&2
    exit 1
fi
printf 'Installed wx-enabled OTP 29.1.1 at %s\n' "$otp_root"
