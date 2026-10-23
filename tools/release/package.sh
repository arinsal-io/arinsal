#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 2 ]; then
    echo "usage: package.sh <target-triple> <version>" >&2
    exit 2
fi

target=$1
version=$2
if [[ "$target" == */* || "$version" == */* || -z "$target" || -z "$version" ]]; then
    echo "package.sh: target and version must be non-empty path-free values" >&2
    exit 2
fi

case "$target" in
    aarch64-apple-darwin|aarch64-unknown-linux-gnu) ;;
    *)
        echo "package.sh: unsupported target: $target (supported: aarch64-apple-darwin, aarch64-unknown-linux-gnu)" >&2
        exit 1
        ;;
esac

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)
cd "$repo"

host=$(rustc -vV | sed -n 's/^host: //p')
if [ "$host" != "$target" ]; then
    echo "package.sh: target $target does not match build host $host" >&2
    echo "package.sh: cross-target packaging requires a matching OTP installation and strip tool" >&2
    exit 1
fi

if [ -n "${ARINSAL_OTP_ROOT:-}" ]; then
    otp_root=$ARINSAL_OTP_ROOT
else
    erl_bin=$(command -v erl || true)
    if [ -z "$erl_bin" ]; then
        echo "package.sh: set ARINSAL_OTP_ROOT or put OTP 29.1.1 erl on PATH" >&2
        exit 1
    fi
    otp_root=$(timeout 30 "$erl_bin" -noshell -eval 'io:format("~s",[code:root_dir()]), halt().')
fi

ARINSAL_RELEASE_VERSION="$version" cargo build --release -p arinsal-cli --target "$target"
build_root=${CARGO_TARGET_DIR:-"$repo/target"}
case "$build_root" in
    /*) ;;
    *) build_root="$repo/$build_root" ;;
esac
binary="$build_root/$target/release/arinsal"
if [ ! -x "$binary" ]; then
    echo "package.sh: release executable is missing: $binary" >&2
    exit 1
fi

dist="$repo/dist"
mkdir -p "$dist"
stage=$(mktemp -d "${TMPDIR:-/tmp}/arinsal-package.XXXXXX")
trap 'rm -rf "$stage"' EXIT HUP INT TERM
prefix="$stage/prefix"
mkdir -p "$prefix/bin"
cp "$binary" "$prefix/bin/arinsal"

"$repo/tools/release/bundle_otp.sh" "$otp_root" "$prefix"
unstripped_binary_bytes=$(wc -c < "$prefix/bin/arinsal" | tr -d '[:space:]')

cat > "$prefix/bin/erl" <<'EOF'
#!/bin/sh
set -eu
self=$0
while [ -L "$self" ]; do
    dir=$(CDPATH='' cd -P "$(dirname "$self")" && pwd)
    link=$(readlink "$self")
    case "$link" in
        /*) self=$link ;;
        *) self=$dir/$link ;;
    esac
done
bin=$(CDPATH='' cd -P "$(dirname "$self")" && pwd)
root=$(CDPATH='' cd -P "$bin/../lib/arinsal/otp" && pwd)
ERL_ROOTDIR=$root
ROOTDIR=$root
BINDIR=$root/erts-17.1/bin
export ERL_ROOTDIR ROOTDIR BINDIR
exec "$bin/arinsal" "$@"
EOF

cat > "$prefix/bin/erlc" <<'EOF'
#!/bin/sh
set -eu
self=$0
while [ -L "$self" ]; do
    dir=$(CDPATH='' cd -P "$(dirname "$self")" && pwd)
    link=$(readlink "$self")
    case "$link" in
        /*) self=$link ;;
        *) self=$dir/$link ;;
    esac
done
bin=$(CDPATH='' cd -P "$(dirname "$self")" && pwd)
root=$(CDPATH='' cd -P "$bin/../lib/arinsal/otp" && pwd)
ERL_ROOTDIR=$root
ROOTDIR=$root
BINDIR=$root/erts-17.1/bin
export ERL_ROOTDIR ROOTDIR BINDIR
exec "$bin/arinsal" -noinput -noshell -mode minimal \
    -boot "$root/releases/29/no_dot_erlang" \
    -s erl_compile compile_cmdline -extra "$@"
EOF

cat > "$prefix/bin/escript" <<'EOF'
#!/bin/sh
set -eu
self=$0
while [ -L "$self" ]; do
    dir=$(CDPATH='' cd -P "$(dirname "$self")" && pwd)
    link=$(readlink "$self")
    case "$link" in
        /*) self=$link ;;
        *) self=$dir/$link ;;
    esac
done
bin=$(CDPATH='' cd -P "$(dirname "$self")" && pwd)
root=$(CDPATH='' cd -P "$bin/../lib/arinsal/otp" && pwd)
ERL_ROOTDIR=$root
ROOTDIR=$root
BINDIR=$root/erts-17.1/bin
export ERL_ROOTDIR ROOTDIR BINDIR
exec "$bin/arinsal" +B -noshell -boot "$root/releases/29/no_dot_erlang" \
    -run escript start -extra "$@"
EOF
chmod 755 "$prefix/bin/erl" "$prefix/bin/erlc" "$prefix/bin/escript"

# erlexec puts both bundled directories ahead of the caller's PATH. These
# relocatable entry points keep nested OTP tools from resolving a system erl.
bundle="$prefix/lib/arinsal/otp"
mkdir -p "$bundle/bin" "$bundle/erts-17.1/bin"
for tool in erl erlc escript; do
    ln -s "../../../../bin/$tool" "$bundle/bin/$tool"
    ln -s "../../../../../bin/$tool" "$bundle/erts-17.1/bin/$tool"
done

case "$(uname -s)" in
    Darwin)
        dsymutil "$prefix/bin/arinsal" -o "$stage/arinsal.dSYM"
        debug_item="$stage/arinsal.dSYM"
        strip -S "$prefix/bin/arinsal"
        ;;
    Linux)
        objcopy --only-keep-debug "$prefix/bin/arinsal" "$stage/arinsal.debug"
        debug_item="$stage/arinsal.debug"
        strip --strip-debug "$prefix/bin/arinsal"
        ;;
    *)
        echo "package.sh: unsupported packaging host: $(uname -s)" >&2
        exit 1
        ;;
esac
stripped_binary_bytes=$(wc -c < "$prefix/bin/arinsal" | tr -d '[:space:]')

cp "$repo/LICENSE" "$repo/NOTICE" "$prefix/"
(cd "$prefix" && find bin lib LICENSE NOTICE -type f -print | LC_ALL=C sort | while IFS= read -r file; do
    case "$(uname -s)" in
        Darwin) shasum -a 256 "$file" ;;
        Linux) sha256sum "$file" ;;
    esac
done > SHA256SUMS)

archive="arinsal-${version}-${target}.tar.gz"
debug_archive="arinsal-${version}-otp-29.1.1-${target}.debug.tar.gz"
tar -czf "$dist/$archive" -C "$prefix" bin lib LICENSE NOTICE SHA256SUMS
tar -czf "$dist/$debug_archive" -C "$stage" "${debug_item##*/}"
(
    cd "$dist"
    case "$(uname -s)" in
        Darwin) shasum -a 256 "$archive" > "$archive.sha256" ;;
        Linux) sha256sum "$archive" > "$archive.sha256" ;;
    esac
)

bin_size=$(du -sh "$prefix/bin" | awk '{print $1}')
otp_size=$(du -sh "$prefix/lib/arinsal/otp/lib" | awk '{print $1}')
tarball_size=$(du -sh "$dist/$archive" | awk '{print $1}')
debug_size=$(du -sh "$dist/$debug_archive" | awk '{print $1}')
printf 'Package: %s\n' "$dist/$archive"
printf 'Checksum: %s\n' "$dist/$archive.sha256"
printf 'Debug symbols: %s\n' "$dist/$debug_archive"
printf 'Binary bytes: unstripped=%s stripped=%s removed=%s\n' \
    "$unstripped_binary_bytes" "$stripped_binary_bytes" \
    "$((unstripped_binary_bytes - stripped_binary_bytes))"
printf 'Sizes: bin=%s OTP-libraries=%s tarball=%s debug-archive=%s\n' \
    "$bin_size" "$otp_size" "$tarball_size" "$debug_size"
