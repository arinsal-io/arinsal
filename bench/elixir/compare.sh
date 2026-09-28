#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$SCRIPT_DIR/../.." && pwd)"
DEMO="$REPO/examples/arinsal_demo"
SUITE=all
RUNTIME=erts
QUICK=0

while (($#)); do
  case "$1" in
    --suite) SUITE="$2"; shift 2 ;;
    --runtime) RUNTIME="$2"; shift 2 ;;
    --quick) QUICK=1; shift ;;
    -h|--help) echo "usage: compare.sh [--suite NAME|all] [--runtime erts|arinsal] [--quick]"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

case "$RUNTIME" in erts|arinsal) ;; *) echo "runtime must be erts or arinsal" >&2; exit 2 ;; esac
SUITES=(pure maps text binary cache work json)
if [[ "$SUITE" != all ]]; then
  found=0
  for name in "${SUITES[@]}"; do [[ "$name" == "$SUITE" ]] && found=1; done
  ((found)) || { echo "unknown suite: $SUITE" >&2; exit 2; }
  SUITES=("$SUITE")
fi

if [[ "$RUNTIME" == arinsal ]]; then
  SHIM="$REPO/target/release/arinsal-erl-shim"
  if [[ ! -x "$SHIM/erl" ]]; then
    echo "arinsal runtime not available yet"
    exit 0
  fi
  export PATH="$SHIM:$PATH"
fi

cd "$DEMO"
export RUNTIME
[[ "$QUICK" == 1 ]] && export BENCH_QUICK=1
for name in "${SUITES[@]}"; do
  unset COMPARE_WITH
  if [[ "$RUNTIME" == arinsal ]]; then
    baseline=""
    for candidate in bench/out/"$name"-erts*.benchee; do
      [[ -f "$candidate" ]] || continue
      if [[ -z "$baseline" || "$candidate" -nt "$baseline" ]]; then baseline="$candidate"; fi
    done
    [[ -n "$baseline" ]] || { echo "missing erts baseline for $name" >&2; exit 1; }
    export COMPARE_WITH="$baseline"
  fi
  MIX_ENV=bench mix run "bench/$name.exs"
done
