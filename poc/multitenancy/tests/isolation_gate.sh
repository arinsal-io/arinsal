#!/usr/bin/env bash
# Isolation gate: runs every `ns_*` test target of crates/vm/tests with BeamAsm and with
# ARINSAL_INTERP=1 and prints one pass/fail row per test.
#
#   poc/multitenancy/tests/isolation_gate.sh            # debug build
#   PROFILE=release poc/multitenancy/tests/isolation_gate.sh
#   ONLY=ns_attack poc/multitenancy/tests/isolation_gate.sh   # one target (substring match)
#
# Needs OTP 29 on PATH (erl and erlc, for the reference compiler of the tests). Exit status is
# non-zero when any test fails or a target does not build.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$ROOT"
export PATH="${ARINSAL_GATE_PATH:-/Users/sts/dev/sq/arinsal-prs/bin:/opt/homebrew/opt/erlang@29/bin:/opt/homebrew/opt/elixir/bin}:$PATH"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/../target-gate}"
PROFILE_FLAG=""
[ "${PROFILE:-debug}" = "release" ] && PROFILE_FLAG="--release"

TARGETS=()
for f in crates/vm/tests/ns_*.rs; do
  name="$(basename "$f" .rs)"
  case "$name" in *"${ONLY:-}"*) TARGETS+=("$name") ;; esac
done
[ "${#TARGETS[@]}" -gt 0 ] || { echo "no ns_* test targets found"; exit 1; }

TEST_ARGS=()
for t in "${TARGETS[@]}"; do TEST_ARGS+=(--test "$t"); done
echo "building ${#TARGETS[@]} targets: ${TARGETS[*]}"
if ! cargo test -p arinsal-vm $PROFILE_FLAG --no-run "${TEST_ARGS[@]}" >/tmp/isolation_gate_build.log 2>&1; then
  tail -30 /tmp/isolation_gate_build.log
  echo "GATE FAIL: build error (log: /tmp/isolation_gate_build.log)"
  exit 1
fi

# Some targets (ns_code) run the arinsal CLI that sits next to the test executables.
if ! cargo build -p arinsal-cli $PROFILE_FLAG >>/tmp/isolation_gate_build.log 2>&1; then
  tail -30 /tmp/isolation_gate_build.log
  echo "GATE FAIL: arinsal-cli build error (log: /tmp/isolation_gate_build.log)"
  exit 1
fi

RESULTS="$(mktemp "${TMPDIR:-/tmp}/isolation_gate.XXXXXX")"
trap 'rm -f "$RESULTS"' EXIT

for mode in jit interp; do
  for t in "${TARGETS[@]}"; do
    if [ "$mode" = interp ]; then export ARINSAL_INTERP=1; else unset ARINSAL_INTERP; fi
    names="$(cargo test -p arinsal-vm $PROFILE_FLAG --test "$t" -- --list 2>/dev/null | sed -n 's/^\(.*\): test$/\1/p')"
    out="$(cargo test -p arinsal-vm $PROFILE_FLAG --test "$t" -- --test-threads=1 2>&1)"
    # Test output can interleave with the result column, so read the failure list instead.
    failed="$(echo "$out" | awk '/^failures:$/{f=1; next} f && /^    [A-Za-z0-9_:]+$/{gsub(/^ +/,""); print}' | sort -u)"
    finished=0
    echo "$out" | grep -q '^test result: ' && finished=1
    for n in $names; do
      if [ $finished -eq 0 ] || echo "$failed" | grep -qx "$n"; then r=FAIL; else r=PASS; fi
      printf '%s\t%s\t%s\t%s\n' "$t" "$n" "$mode" "$r" >>"$RESULTS"
    done
    if [ -z "$names" ]; then printf '%s\t%s\t%s\t%s\n' "$t" "(no tests listed)" "$mode" FAIL >>"$RESULTS"; fi
  done
done
unset ARINSAL_INTERP

echo
printf '%-14s %-46s %-6s %-6s\n' target test jit interp
sort -u "$RESULTS" | awk -F'\t' '
  { key=$1 "\t" $2; res[key, $3]=$4; keys[key]=1 }
  END {
    for (k in keys) { split(k, p, "\t"); j=res[k,"jit"]; i=res[k,"interp"];
      if (j=="") j="-"; if (i=="") i="-";
      printf "%-14s %-46s %-6s %-6s\n", p[1], p[2], j, i }
  }' | sort
echo
fail="$(sort -u "$RESULTS" | awk -F'\t' '$4!="PASS" && $4!="IGNORED"{n++} END{print n+0}')"
total="$(sort -u "$RESULTS" | wc -l | tr -d ' ')"
if [ "$fail" -eq 0 ]; then echo "GATE PASS: $total results"; else echo "GATE FAIL: $fail of $total results failed"; exit 1; fi
