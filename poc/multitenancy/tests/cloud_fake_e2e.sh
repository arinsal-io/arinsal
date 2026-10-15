#!/usr/bin/env bash
# End-to-end test of the manager (arinsal_cloud) with the fake backend, on the Arinsal runtime.
# Deploys poc/multitenancy/bench/rest as two tenants, curls both projects, lists, redeploys.
#
#   poc/multitenancy/tests/cloud_fake_e2e.sh
#
# Needs: Arinsal's `erl` shim first on PATH (default: <repo>/../mt-shim), Elixir, curl, and
# network or a warm Hex cache for the bench/rest dependencies.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
SHIM="${ARINSAL_SHIM:-$ROOT/../mt-shim}"
export PATH="$SHIM:/opt/homebrew/opt/elixir/bin:$PATH"
export ERL_ROOTDIR="${ERL_ROOTDIR:-/opt/homebrew/opt/erlang@29/lib/erlang}"

VERSION="$(elixir --version 2>&1)"
case "$VERSION" in *"arinsal "*) ;; *) { echo "FAIL: the node under test is not Arinsal (check PATH / ARINSAL_SHIM)"; exit 1; } ;; esac

WORK="$(mktemp -d "${TMPDIR:-/tmp}/cloud_e2e.XXXXXX")"
ADMIN_PORT="${ADMIN_PORT:-7011}"
ADMIN="http://127.0.0.1:$ADMIN_PORT"
MGR_PID=""

cleanup() {
  if [ -n "$MGR_PID" ]; then kill "$MGR_PID" 2>/dev/null || true; wait "$MGR_PID" 2>/dev/null || true; fi
  # projects started by the fake backend are OS processes of their release dir
  pkill -f "$WORK/data/" 2>/dev/null || true
  [ -n "${KEEP:-}" ] || rm -rf "$WORK"
}
trap cleanup EXIT

step() { echo "== $*"; }
fail() { echo "FAIL: $*"; echo "manager log:"; tail -30 "$WORK/manager.log" 2>/dev/null || true; exit 1; }
json_field() { sed -n "s/.*\"$1\":\([0-9]*\).*/\1/p" | head -1; }

step "compile the manager"
(cd "$ROOT/packages/arinsal_cloud" && mix compile >"$WORK/compile.log" 2>&1) || { cat "$WORK/compile.log"; exit 1; }
EBIN="$ROOT/packages/arinsal_cloud/_build/dev/lib/arinsal_cloud/ebin"
ELIXIR_LIB="$(elixir -e 'IO.puts(:code.lib_dir(:elixir))')"

step "build the bench/rest release (include_erts false: only lib/ and releases/ are shipped)"
cp -R "$ROOT/poc/multitenancy/bench/rest" "$WORK/rest"
rm -rf "$WORK/rest/_build" "$WORK/rest/deps"
# Build tooling runs on stock OTP: compiling hpax on Arinsal fails (NOTES-cloud.md, "Arinsal gaps").
STOCK_PATH="${STOCK_PATH:-/opt/homebrew/opt/erlang@29/bin:/opt/homebrew/opt/elixir/bin:/usr/bin:/bin}"
(cd "$WORK/rest" && env -u ERL_ROOTDIR PATH="$STOCK_PATH" sh -c \
  'mix deps.get && MIX_ENV=prod mix release --overwrite --path "$1"' _ "$WORK/rel" >"$WORK/build.log" 2>&1) \
  || { cat "$WORK/build.log"; exit 1; }
tar -C "$WORK/rel" -czf "$WORK/rest.tar.gz" lib releases

step "start the manager on $ADMIN (fake backend)"
erl -noshell -pa "$EBIN" -pa "$ELIXIR_LIB/ebin" -s arinsal_cloud \
  -arinsal_cloud admin_port "$ADMIN_PORT" \
  -arinsal_cloud data_dir "\"$WORK/data\"" \
  >"$WORK/manager.log" 2>&1 &
MGR_PID=$!
for _ in $(seq 1 50); do
  curl -sf "$ADMIN/projects" >/dev/null 2>&1 && break
  kill -0 "$MGR_PID" 2>/dev/null || fail "manager exited"
  sleep 0.2
done
[ "$(curl -s "$ADMIN/projects")" = "[]" ] || fail "expected an empty project list"

step "deploy acme/shop and globex/shop"
A="$(curl -sf -X PUT --data-binary @"$WORK/rest.tar.gz" "$ADMIN/projects/acme/shop")" || fail "deploy acme"
G="$(curl -sf -X PUT --data-binary @"$WORK/rest.tar.gz" "$ADMIN/projects/globex/shop")" || fail "deploy globex"
PA="$(echo "$A" | json_field port)"
PG="$(echo "$G" | json_field port)"
echo "acme on $PA, globex on $PG"
{ [ -n "$PA" ] && [ -n "$PG" ] && [ "$PA" != "$PG" ]; } || fail "ports not distinct"
echo "$A" | grep -q '"state":"running"' || fail "acme not running: $A"

step "curl both projects"
for P in "$PA" "$PG"; do
  OUT="$(curl -sf "http://127.0.0.1:$P/t/1/items/1")" || fail "project on port $P does not answer"
  echo "$OUT" | grep -q '"name":"item-1"' || fail "unexpected body from $P: $OUT"
  echo "port $P: $OUT"
done

step "list"
LIST="$(curl -sf "$ADMIN/projects")"
echo "$LIST"
[ "$(echo "$LIST" | grep -o '"state":"running"' | wc -l | tr -d ' ')" = "2" ] || fail "expected two running projects"

step "redeploy acme (same release): port is kept"
A2="$(curl -sf -X PUT --data-binary @"$WORK/rest.tar.gz" "$ADMIN/projects/acme/shop")" || fail "redeploy acme"
[ "$(echo "$A2" | json_field port)" = "$PA" ] || fail "port changed on redeploy"
curl -sf "http://127.0.0.1:$PA/t/1/items/1" >/dev/null || fail "acme does not answer after redeploy"
curl -sf "http://127.0.0.1:$PG/t/1/items/1" >/dev/null || fail "globex stopped by the acme redeploy"

step "bad input"
[ "$(curl -s -o /dev/null -w '%{http_code}' -X PUT --data-binary garbage "$ADMIN/projects/acme/bad")" = "400" ] || fail "garbage tarball should be 400"
[ "$(curl -s -o /dev/null -w '%{http_code}' --path-as-is -X PUT --data-binary @"$WORK/rest.tar.gz" "$ADMIN/projects/acme/..")" = "400" ] || fail "bad name should be 400"

echo "PASS"
