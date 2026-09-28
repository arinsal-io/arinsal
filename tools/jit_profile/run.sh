#!/usr/bin/env bash
set -euo pipefail

# Directory of this script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

echo "=== Building arinsal-cli (release) ==="
cargo build --release -p arinsal-cli

ARINSAL_BIN="$REPO_ROOT/target/release/arinsal"
if [ ! -x "$ARINSAL_BIN" ]; then
    echo "ERROR: arinsal binary not found at $ARINSAL_BIN"
    exit 1
fi

WORK_DIR="$(mktemp -d -t arinsal_jit_profile_XXXXXX)"
trap 'rm -rf "$WORK_DIR"' EXIT

echo "=== Locating and compiling kernels.erl ==="
KERNELS_SRC=""
for candidate in \
    "$REPO_ROOT/experiments/perf/pf_exec/kernels.erl" \
    "$HOME/dev/beam/.agents/gates/kb/kernels.erl"; do
    if [ -f "$candidate" ]; then
        KERNELS_SRC="$candidate"
        break
    fi
done

if [ -z "$KERNELS_SRC" ]; then
    echo "ERROR: Could not find kernels.erl"
    exit 1
fi

erlc -o "$WORK_DIR" "$KERNELS_SRC"

SAMPLES_DIR="${1:-$SCRIPT_DIR/samples}"
mkdir -p "$SAMPLES_DIR"

JIT_SAMPLE="$SAMPLES_DIR/jit_tail.sample"
INTERP_SAMPLE="$SAMPLES_DIR/interp_tail.sample"

echo "=== Profiling JIT run (tail, N=400,000,000, >= 5s) ==="
env ARINSAL_BEAMASM=1 ARINSAL_BEAMASM_MODULES=kernels "$ARINSAL_BIN" eval +S 1 -pa "$WORK_DIR" kernels tail 400000000 &
JIT_PID=$!
sleep 0.5
/usr/bin/sample "$JIT_PID" 5 -file "$JIT_SAMPLE"
wait "$JIT_PID"
echo "JIT sample captured at: $JIT_SAMPLE"

echo "=== Profiling Interpreter run (tail, N=800,000,000, >= 5s) ==="
"$ARINSAL_BIN" eval +S 1 -pa "$WORK_DIR" kernels tail 800000000 &
INTERP_PID=$!
sleep 0.5
/usr/bin/sample "$INTERP_PID" 5 -file "$INTERP_SAMPLE"
wait "$INTERP_PID"
echo "Interpreter sample captured at: $INTERP_SAMPLE"

echo ""
echo "=== Analyzing JIT Profile ==="
python3 "$SCRIPT_DIR/analyze.py" "$JIT_SAMPLE"

echo ""
echo "=== Analyzing Interpreter Profile ==="
python3 "$SCRIPT_DIR/analyze.py" "$INTERP_SAMPLE"

echo ""
echo "Profile complete. Sample files stored in: $SAMPLES_DIR"
