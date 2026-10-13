#!/usr/bin/env bash
# Start smolquery from the worktree on a chosen runtime, in the foreground.
#
#   scripts/server.sh <erts|arinsal|arinsal-patched> <data_dir> [mix_env]
#
# Same compiled beams for every runtime: mix runs with --no-compile and
# --no-deps-check, so the runtime under test never recompiles anything.
# Arinsal is selected by putting a directory whose `erl` is the arinsal binary
# first on PATH (what packages/arinsal does); Elixir's bin/elixir resolves erl
# through PATH.
set -euo pipefail
source "$(dirname "$0")/env.sh"

runtime=${1:?runtime}
data=${2:?data dir}
export MIX_ENV=${3:-prod}

case "$runtime" in
  erts) ;;
  arinsal) export PATH="$IP/bin/base/shim:$PATH" ;;
  arinsal-patched) export PATH="$IP/bin/patched/shim:$PATH" ;;
  arinsal-fast) export PATH="$IP/bin/fast/shim:$PATH" ;;
  *) echo "unknown runtime $runtime" >&2; exit 2 ;;
esac

mkdir -p "$data"
export SMOLQUERY_DATA_DIR="$data"
export SMOLQUERY_EXTENSION_DIRECTORY="$IP/duckdb-ext"
# Placeholder credentials for a local, throwaway benchmark instance; not real secrets.
export SMOLQUERY_API_KEY=${SMOLQUERY_API_KEY:-bench}
export SMOLQUERY_API_PORT=${SMOLQUERY_API_PORT:-14000}
export SMOLQUERY_ROLES=${SMOLQUERY_ROLES:-api,ingest,buffer,storage,query}
export SMOLQUERY_INSERT_MAX_NDJSON_BYTES=${SMOLQUERY_INSERT_MAX_NDJSON_BYTES:-32000000}
export SMOLQUERY_FLUSH_MAX_BYTES=${SMOLQUERY_FLUSH_MAX_BYTES:-32000000}
export SMOLQUERY_MAX_BUFFERED_BYTES=${SMOLQUERY_MAX_BUFFERED_BYTES:-256000000}
export SMOLQUERY_FLUSH_INTERVAL_MS=${SMOLQUERY_FLUSH_INTERVAL_MS:-1000}
export SMOLQUERY_SECRET_KEY_BASE=${SMOLQUERY_SECRET_KEY_BASE:-profprofprofprofprofprofprofprofprofprofprofprofprofprofprofprof}
export SMOLQUERY_WEB_USERNAME=smolquery SMOLQUERY_WEB_PASSWORD=smolquery

cd "$IP/smolquery-wt"
echo "runtime=$runtime erl=$(command -v erl) MIX_ENV=$MIX_ENV data=$data" >&2
exec elixir -S mix run --no-halt --no-compile --no-deps-check
