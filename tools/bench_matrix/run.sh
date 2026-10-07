#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BENCH_DIR="$ROOT/tools/bench_matrix"
BUILD_DIR="$ROOT/tmp/bench_matrix"

# Ensure output directories exist
mkdir -p "$ROOT/tmp"
mkdir -p "$BUILD_DIR/ebin"

# 1. Build arinsal-cli if not present
if [ ! -f "$ROOT/target/release/arinsal" ]; then
    echo "Building arinsal-cli in release mode..." >&2
    cargo build --release -p arinsal-cli
fi

# 2. Compile Erlang kernels and probes
erlc -o "$BUILD_DIR/ebin" "$BENCH_DIR/kernels.erl"
if [ -f "$BENCH_DIR/probes/spawn_probe.erl" ]; then
    erlc -o "$BUILD_DIR/ebin" "$BENCH_DIR/probes/spawn_probe.erl"
fi

# 3. Build Go harness
go build -o "$BUILD_DIR/gob" "$BENCH_DIR/bench.go"

# 4. Run benchmark matrix runner
exec python3 "$BENCH_DIR/runner.py" "$@"
