#!/usr/bin/env bash
# Local gate before every commit (no CI yet): unsafe census, fmt, clippy, tests.
set -euo pipefail
cd "$(dirname "$0")/.."

# About 4 seconds. Fails if any crate exceeds tools/unsafe_census/baseline.json.
python3 tools/unsafe_census/census.py --check

cargo fmt --all -- --check
# multiple_unsafe_ops_per_block is warn until those blocks are split.
# -D warnings would promote it, so keep that one lint at warn.
cargo clippy --workspace --all-targets -q -- -D warnings -A clippy::multiple_unsafe_ops_per_block
cargo test --workspace -q
echo "check.sh: OK"
