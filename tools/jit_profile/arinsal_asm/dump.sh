#!/bin/bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 <beam-directory> <dump-directory>" >&2
  exit 2
fi

script_dir=$(cd "$(dirname "$0")" && pwd)
repo_root=$(cd "$script_dir/../../.." && pwd)
beam_dir=$(cd "$1" && pwd)
dump_dir=$2
mkdir -p "$dump_dir"

ARINSAL_BEAMASM=1 \
ARINSAL_BEAMASM_MODULES=kernels \
ARINSAL_BEAMASM_DUMP="$dump_dir" \
timeout -s KILL 60 "$repo_root/target/release/arinsal" \
  -noshell -pa "$beam_dir" -eval 'kernels:tail(10), halt().'
