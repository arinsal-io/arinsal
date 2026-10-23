#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 2 ]; then
    echo "usage: bundle_otp.sh <otp-root> <out-prefix>" >&2
    exit 2
fi

otp_root=$(cd "$1" 2>/dev/null && pwd -P) || {
    echo "bundle_otp.sh: OTP root is not a directory: $1" >&2
    exit 1
}
prefix=$2
mkdir -p "$prefix"
prefix=$(cd "$prefix" && pwd -P)

version_file="$otp_root/releases/29/OTP_VERSION"
if [ ! -f "$version_file" ] || [ "$(cat "$version_file")" != "29.1.1" ] || \
    [ ! -d "$otp_root/erts-17.1" ] || [ ! -d "$otp_root/lib/erts-17.1/ebin" ]; then
    echo "bundle_otp.sh: expected an installed Erlang/OTP 29.1.1 tree: $otp_root" >&2
    exit 1
fi

release_boots="$otp_root/releases/29"
if [ ! -f "$release_boots/start.boot" ] || [ ! -f "$otp_root/releases/start_erl.data" ]; then
    echo "bundle_otp.sh: required OTP boot files are missing from $otp_root" >&2
    exit 1
fi

bundle="$prefix/lib/arinsal/otp"
if [ -e "$bundle" ] || [ -L "$bundle" ]; then
    echo "bundle_otp.sh: bundle already exists: $bundle" >&2
    exit 1
fi

bundle_parent="$prefix/lib/arinsal"
mkdir -p "$bundle_parent"
staging=$(mktemp -d "$bundle_parent/.otp.bundle.XXXXXX")
trap 'rm -rf "$staging"' EXIT HUP INT TERM

# OTP applications are loaded from ebin and resolve their runtime data from priv.
while IFS= read -r -d '' app_root; do
    app_name=${app_root##*/}
    destination="$staging/lib/$app_name"
    for entry in ebin priv include; do
        if [ -d "$app_root/$entry" ]; then
            mkdir -p "$destination"
            cp -R "$app_root/$entry" "$destination/"
        fi
    done
done < <(find "$otp_root/lib" -mindepth 1 -maxdepth 1 -type d -print0)

# Arinsal loads the generated preloaded BEAMs from lib/erts-17.1/ebin.
# The installed tree has no erts-17.1/preloaded directory; its C runtime is replaced.
mkdir -p "$staging/erts-17.1" "$staging/usr"
if [ -d "$otp_root/erts-17.1/include" ]; then
    cp -R "$otp_root/erts-17.1/include" "$staging/erts-17.1/"
fi
for helper in erl_child_setup inet_gethost; do
    source="$otp_root/erts-17.1/bin/$helper"
    if [ ! -x "$source" ]; then
        echo "bundle_otp.sh: required OTP helper is missing: $source" >&2
        exit 1
    fi
    mkdir -p "$staging/erts-17.1/bin"
    cp -p "$source" "$staging/erts-17.1/bin/"
done
if [ -d "$otp_root/usr/include" ]; then
    cp -R "$otp_root/usr/include" "$staging/usr/"
fi

mkdir -p "$staging/releases/29"
for boot in "$release_boots"/*.boot; do
    [ -f "$boot" ] && cp "$boot" "$staging/releases/29/"
done
cp "$otp_root/releases/start_erl.data" "$staging/releases/"
if [ -f "$otp_root/bin/start.boot" ]; then
    mkdir -p "$staging/bin"
    cp "$otp_root/bin/start.boot" "$staging/bin/"
fi

mv "$staging" "$bundle"
echo "Bundled OTP 29.1.1 at $bundle"
du -sh "$bundle"
