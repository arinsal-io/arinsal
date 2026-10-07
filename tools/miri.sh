#!/usr/bin/env bash
# Miri on term suites that can run without a live erl node, JIT, or C ABI.
# Mandatory before merging term, GC, or unsafe-core changes. Not part of tools/check.sh.
#
#   tools/miri.sh
#   tools/miri.sh gc
#   tools/miri.sh gc core
#
# Requires the nightly toolchain's miri component and GNU timeout(1).
# Artifacts go to target/miri so they do not share target/debug with Rust 1.98.1.
set -euo pipefail
cd "$(dirname "$0")/.."

if ! command -v timeout >/dev/null 2>&1; then
  echo "miri.sh: SKIP — timeout(1) is not on PATH (install GNU coreutils)" >&2
  exit 1
fi

if ! rustup toolchain list | grep -q '^nightly'; then
  echo "miri.sh: SKIP — the nightly toolchain is not installed" >&2
  echo "  rustup toolchain install nightly --component miri" >&2
  exit 1
fi

if ! rustup component list --toolchain nightly --installed | grep -q '^miri'; then
  echo "miri.sh: SKIP — the miri component is not installed for nightly" >&2
  echo "  rustup component add miri --toolchain nightly" >&2
  exit 1
fi

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$PWD/target/miri}"

echo "miri.sh: skip arinsal-vm and arinsal-jit — executable memory, sockets, and interpreter foreign calls"
echo "miri.sh: skip arinsal-nif, arinsal-nif-file, arinsal-nif-socket, arinsal-nif-tty, arinsal-nif-zlib, arinsal-re — C ABI"
echo "miri.sh: skip RefErl and live erl differentials — Miri does not host an Erlang node"
echo "miri.sh: skip arinsal-term --test term_ops — spawns erl and is not cfg-gated off under Miri"

usage() {
  echo "usage: tools/miri.sh [gc|core|region|hamt ...]" >&2
  exit 2
}

timeout_for() {
  case "$1" in
    gc) echo 240 ;;
    # A cold core run measured about 232s and nearly hit a 240s cap.
    core) echo 420 ;;
    region) echo 240 ;;
    hamt) echo 240 ;;
    *)
      echo "miri.sh: unknown suite '$1'" >&2
      usage
      ;;
  esac
}

if [[ $# -eq 0 ]]; then
  set -- gc core region hamt
fi

echo "miri.sh: cargo +nightly miri setup (timeout 600s)"
status=0
timeout 600 cargo +nightly miri setup || status=$?
if [[ "$status" -eq 124 ]]; then
  echo "miri.sh: FAIL miri setup timed out after 600s" >&2
  exit 1
fi
if [[ "$status" -ne 0 ]]; then
  echo "miri.sh: FAIL miri setup (exit ${status})" >&2
  exit "$status"
fi

for suite in "$@"; do
  secs="$(timeout_for "$suite")"
  echo "miri.sh: arinsal-term --test ${suite} (timeout ${secs}s)"
  status=0
  timeout "$secs" cargo +nightly miri test -p arinsal-term --test "$suite" || status=$?
  if [[ "$status" -eq 124 ]]; then
    echo "miri.sh: FAIL arinsal-term --test ${suite} timed out after ${secs}s" >&2
    exit 1
  fi
  if [[ "$status" -ne 0 ]]; then
    echo "miri.sh: FAIL arinsal-term --test ${suite} (exit ${status})" >&2
    exit "$status"
  fi
  echo "miri.sh: ok arinsal-term --test ${suite}"
done

echo "miri.sh: OK"
