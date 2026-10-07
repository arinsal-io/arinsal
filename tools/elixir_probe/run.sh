#!/bin/bash
set -euo pipefail

export TMPDIR="/tmp"
export PYTHONDONTWRITEBYTECODE=1

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

cleanup() {
    rm -rf "$SCRIPT_DIR/__pycache__"
}
trap cleanup EXIT

if [ ! -f "$ROOT_DIR/target/release/arinsal" ]; then
    echo "Building arinsal release binary..."
    cargo build --release -p arinsal-cli
fi

python3 "$SCRIPT_DIR/probe.py" "$@"

