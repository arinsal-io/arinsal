#!/usr/bin/env bash
# Build the experimental arinsal worktree and point shim-patched/erl at a copy.
set -euo pipefail
source "$(dirname "$0")/env.sh"
cd "$IP/arinsal-wt"
cargo build --release -p arinsal-cli 2>&1 | grep -E "^(error|warning: unused)|Finished|error\[" || true
test -x target/release/arinsal
mkdir -p "$IP/bin/patched/shim"
rm -f "$IP/bin/patched/arinsal"; cp target/release/arinsal "$IP/bin/patched/arinsal"
ln -sf ../arinsal "$IP/bin/patched/shim/erl"
git -C "$IP/arinsal-wt" diff --stat
