#!/usr/bin/env bash
set -euo pipefail

if [ "$(uname)" != Darwin ]; then
    echo "dylib probe requires macOS" >&2
    exit 2
fi

root=$(cd "$(dirname "$0")/../.." && pwd)
inc=${ERL_NIF_INCLUDE:-$(erl -noshell -eval 'io:format("~s/usr/include",[code:root_dir()]), halt().')}
crypto=$(find "$(dirname "$inc")/../lib" -path '*/crypto-*/priv/lib/crypto.so' -print -quit)
mkdir -p "$root/tmp"
awk -F, 'BEGIN { print "#include <stdlib.h>" } /^ERL_NIF_API_FUNC_DECL\(/ { gsub(/[[:space:]]/, "", $2); print "void " $2 "(void) { abort(); }" }' \
    "$root/spec/otp-29.1.1/erl_nif_api_funcs.h" > "$root/tmp/dylib_stubs.c"
cc -dynamiclib "$root/tmp/dylib_stubs.c" -o "$root/tmp/libnifhost.dylib"
cc -O2 -fPIC -bundle -undefined dynamic_lookup -I"$inc" "$root/bench/nif/nb.c" -o "$root/tmp/nb.so"
cc -I"$inc" "$root/tools/nif_spike/dylib_probe.c" -o "$root/tmp/dylib_probe"
"$root/tmp/dylib_probe" "$root/tmp/libnifhost.dylib" "$root/tmp/nb.so" "$crypto"
