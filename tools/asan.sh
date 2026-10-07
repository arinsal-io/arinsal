#!/usr/bin/env bash
# AddressSanitizer builds. Does not change rust-toolchain.toml (stable 1.98.1).
# Usage:
#   tools/asan.sh boot
#   tools/asan.sh test <cargo test args>
set -euo pipefail
cd "$(dirname "$0")/.."

# Commit date of the nightly used for -Zsanitizer=address. Install only if absent.
NIGHTLY=nightly-2026-09-24

if ! rustup toolchain list | grep -q "^${NIGHTLY}"; then
  rustup toolchain install "$NIGHTLY" --profile minimal --component rust-src
fi
if ! rustup component list --toolchain "$NIGHTLY" --installed | grep -q '^rust-src'; then
  rustup component add rust-src --toolchain "$NIGHTLY"
fi

HOST="$(rustc "+${NIGHTLY}" -vV | sed -n 's/^host: //p')"
if [[ -z "$HOST" ]]; then
  echo "asan.sh: cannot determine host triple for ${NIGHTLY}" >&2
  exit 1
fi

export RUSTUP_TOOLCHAIN="$NIGHTLY"
export RUSTFLAGS="-Zsanitizer=address${RUSTFLAGS:+ $RUSTFLAGS}"
export ASAN_OPTIONS="detect_leaks=0:abort_on_error=1"
export ARINSAL_VALIDATE=1
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$PWD/target/asan}"

usage() {
  echo "usage: tools/asan.sh boot | tools/asan.sh test <cargo test args>" >&2
  exit 2
}

# Kill a hung boot. `perl alarm` does not survive exec, so a watchdog is used.
run_timeout() {
  local secs=$1
  shift
  "$@" &
  local pid=$!
  (
    sleep "$secs"
    kill -ABRT "$pid" 2>/dev/null || true
  ) &
  local watchdog=$!
  local status=0
  wait "$pid" || status=$?
  kill "$watchdog" 2>/dev/null || true
  wait "$watchdog" 2>/dev/null || true
  return "$status"
}

cmd="${1:-}"
if [[ -z "$cmd" ]]; then
  usage
fi
shift

cargo_asan() {
  local subcommand=$1
  shift
  cargo "+${NIGHTLY}" -Zbuild-std "$subcommand" --target "$HOST" "$@"
}

case "$cmd" in
  boot)
    cargo_asan build -p arinsal-cli
    bin="$CARGO_TARGET_DIR/$HOST/debug/arinsal"
    fail=0
    for i in $(seq 1 20); do
      echo "=== boot run ${i}/20 ==="
      status=0
      run_timeout 120 "$bin" -noshell -eval 'io:format("ok~n"), halt().' || status=$?
      if [[ "$status" -ne 0 ]]; then
        echo "boot run ${i} exited ${status}"
        fail=$((fail + 1))
      fi
    done
    echo "boot failures: ${fail}/20"
    ;;
  test)
    # The selected package must define `validate-terms` (arinsal-term, arinsal-vm).
    cargo_asan test --features validate-terms "$@"
    ;;
  *)
    usage
    ;;
esac
