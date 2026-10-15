#!/usr/bin/env bash
# Idle CPU of the bench/rest app: warm every tenant, settle, then measure CPU time over a window.
# Usage: idle_cpu.sh <shim-dir> [tenants=1000] [window_s=60] [settle_s=20]
set -euo pipefail

SHIM=${1:?usage: idle_cpu.sh <shim-dir containing erl> [tenants] [window_s] [settle_s]}
TENANTS=${2:-1000}
WINDOW=${3:-60}
SETTLE=${4:-20}
PORT=${RT_PORT:-4400}
HERE=$(cd "$(dirname "$0")" && pwd)

to_ms() { awk -F'[:.]' '{ if (NF == 3) print ($1 * 60 + $2) * 1000 + $3 * 10; else print (($1 * 60 + $2) * 60 + $3) * 1000 + $4 * 10 }'; }
cpu_ms() { ps -o time= -p "$1" | tr -d ' ' | to_ms; }

cd "$HERE/rest"
PATH="$SHIM:$PATH" MIX_ENV=prod RT_PORT=$PORT RT_TENANTS=$TENANTS mix run --no-halt >"${TMPDIR:-/tmp}/idle_cpu_app.log" 2>&1 &
MIX=$!
trap 'kill $MIX 2>/dev/null || true; pkill -P $MIX 2>/dev/null || true; lsof -ti tcp:$PORT -sTCP:LISTEN | xargs kill 2>/dev/null || true' EXIT

for _ in $(seq 1 300); do
  curl -fs "http://127.0.0.1:$PORT/ready" >/dev/null 2>&1 && break
  sleep 1
done
PID=$(lsof -ti tcp:$PORT -sTCP:LISTEN | head -1)

id=1
while [ "$id" -le "$TENANTS" ]; do
  curl -fs "http://127.0.0.1:$PORT/t/$id/items/1" >/dev/null
  id=$((id + 1))
done
sleep "$SETTLE"

echo "load: $(uptime | sed 's/.*load averages*: //')"
A=$(cpu_ms "$PID")
sleep "$WINDOW"
B=$(cpu_ms "$PID")
echo "tenants=$TENANTS pid=$PID window=${WINDOW}s idle_cpu_ms_per_min=$(( (B - A) * 60 / WINDOW ))"
ps -M -p "$PID" | head -60
