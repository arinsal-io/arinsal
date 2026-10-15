#!/usr/bin/env bash
# End-to-end test of the manager (arinsal_cloud) with the fake backend, on the Arinsal runtime.
# Uses the `mix arinsal.*` tasks: deploys poc/multitenancy/bench/rest as two tenants, curls both
# projects, lists, reads logs, stops, starts, redeploys and deletes.
#
# The manager, the projects, the client tasks and `mix arinsal.deploy` (which compiles bench/rest
# and its deps and builds the release) all run on Arinsal. Only `mix deps.get` runs on stock OTP:
# Hex on Arinsal would write a cache stock OTP cannot read.
# The manager is started with packages/arinsal_cloud/bin/arinsal-cloud.
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

# Stock OTP only fetches dependencies; everything else runs on Arinsal.
STOCK_PATH="${STOCK_PATH:-/opt/homebrew/opt/erlang@29/bin:/opt/homebrew/opt/elixir/bin:/usr/bin:/bin}"
stock() { env -u ERL_ROOTDIR -u HEX_HOME PATH="$STOCK_PATH" "$@"; }
# Client tasks run on Arinsal from packages/arinsal (it has no deps to compile).
arinsal_task() { (cd "$ROOT/packages/arinsal" && mix "$@"); }
# Arinsal's Hex gets its own state dir so it never touches the cache stock OTP uses.
export HEX_HOME="$WORK/hex_arinsal"

step "prepare a copy of bench/rest"
cp -R "$ROOT/poc/multitenancy/bench/rest" "$WORK/rest"
rm -rf "$WORK/rest/_build" "$WORK/rest/deps"
sed -i.bak "s#\"../../../../packages/arinsal\"#\"$ROOT/packages/arinsal\"#" "$WORK/rest/mix.exs"
(cd "$WORK/rest" && stock mix deps.get >"$WORK/deps.log" 2>&1) || { cat "$WORK/deps.log"; exit 1; }

step "start the manager on $ADMIN (fake backend); projects print a marker via ERL_AFLAGS"
"$ROOT/packages/arinsal_cloud/bin/arinsal-cloud" --admin "$ADMIN_PORT" --data-dir "$WORK/data" --backend fake \
  -- -arinsal_cloud project_env '[{"ERL_AFLAGS","-s erlang display project_says_hello"}]' \
  >"$WORK/manager.log" 2>&1 &
MGR_PID=$!
for _ in $(seq 1 50); do
  curl -sf "$ADMIN/projects" >/dev/null 2>&1 && break
  kill -0 "$MGR_PID" 2>/dev/null || fail "manager exited"
  sleep 0.2
done
[ "$(curl -s "$ADMIN/projects")" = "[]" ] || fail "expected an empty project list"
OUT="$(arinsal_task arinsal.list --url "$ADMIN")"
case "$OUT" in *"No projects"*) ;; *) fail "mix arinsal.list on an empty manager: $OUT" ;; esac

step "mix arinsal.deploy acme/shop and globex/shop"
(cd "$WORK/rest" && mix arinsal.deploy --tenant acme --project shop --url "$ADMIN" >"$WORK/deploy_acme.log" 2>&1) || { cat "$WORK/deploy_acme.log"; fail "deploy acme"; }
(cd "$WORK/rest" && mix arinsal.deploy --tenant globex --project shop --url "$ADMIN" >"$WORK/deploy_globex.log" 2>&1) || { cat "$WORK/deploy_globex.log"; fail "deploy globex"; }
tail -1 "$WORK/deploy_acme.log"
tail -1 "$WORK/deploy_globex.log"
PA="$(curl -sf "$ADMIN/projects/acme/shop" | json_field port)"
PG="$(curl -sf "$ADMIN/projects/globex/shop" | json_field port)"
echo "acme on $PA, globex on $PG"
{ [ -n "$PA" ] && [ -n "$PG" ] && [ "$PA" != "$PG" ]; } || fail "ports not distinct"

step "curl both projects"
for P in "$PA" "$PG"; do
  OUT="$(curl -sf "http://127.0.0.1:$P/t/1/items/1")" || fail "project on port $P does not answer"
  echo "$OUT" | grep -q '"name":"item-1"' || fail "unexpected body from $P: $OUT"
  echo "port $P: $OUT"
done

step "mix arinsal.list"
LIST="$(arinsal_task arinsal.list --url "$ADMIN")"
echo "$LIST"
[ "$(echo "$LIST" | grep -c ' running ')" = "2" ] || fail "expected two running projects"

step "mix arinsal.logs (manager lines and the project's own stdout)"
LOGS="$(arinsal_task arinsal.logs --tenant acme --project shop --url "$ADMIN")"
echo "$LOGS"
echo "$LOGS" | grep -q "\[manager\] starting version 0.1.0 on 127.0.0.1:$PA" || fail "manager line missing from logs"
echo "$LOGS" | grep -q "project_says_hello" || fail "project stdout not captured"
grep -q "project_says_hello" "$WORK/data/acme/shop/out.log" || fail "out.log missing the project's stdout"

step "mix arinsal.stop acme/shop: acme is down, globex untouched"
arinsal_task arinsal.stop --tenant acme --project shop --url "$ADMIN"
curl -sf -m 2 "http://127.0.0.1:$PA/t/1/items/1" >/dev/null 2>&1 && fail "acme still answers after stop"
curl -sf "http://127.0.0.1:$PG/t/1/items/1" >/dev/null || fail "globex stopped by the acme stop"
OUT="$(arinsal_task arinsal.list --url "$ADMIN")"
case "$OUT" in *"acme/shop  stopped"*) ;; *) fail "acme not listed as stopped: $OUT" ;; esac

step "mix arinsal.start acme/shop: same port, answers again"
arinsal_task arinsal.start --tenant acme --project shop --url "$ADMIN"
curl -sf "http://127.0.0.1:$PA/t/1/items/1" >/dev/null || fail "acme does not answer after start"
OUT="$(arinsal_task arinsal.logs --tenant acme --project shop --url "$ADMIN")"
case "$OUT" in *"[manager] stopping"*) ;; *) fail "stop line missing from logs: $OUT" ;; esac

step "redeploy acme with mix arinsal.deploy: port kept, globex untouched"
(cd "$WORK/rest" && mix arinsal.deploy --tenant acme --project shop --url "$ADMIN" >"$WORK/deploy_acme2.log" 2>&1) || { cat "$WORK/deploy_acme2.log"; fail "redeploy acme"; }
[ "$(curl -sf "$ADMIN/projects/acme/shop" | json_field port)" = "$PA" ] || fail "port changed on redeploy"
curl -sf "http://127.0.0.1:$PA/t/1/items/1" >/dev/null || fail "acme does not answer after redeploy"
curl -sf "http://127.0.0.1:$PG/t/1/items/1" >/dev/null || fail "globex stopped by the acme redeploy"

step "bad input"
[ "$(curl -s -o /dev/null -w '%{http_code}' -X PUT --data-binary garbage "$ADMIN/projects/acme/bad")" = "400" ] || fail "garbage tarball should be 400"
[ "$(curl -s -o /dev/null -w '%{http_code}' --path-as-is -X PUT --data-binary garbage "$ADMIN/projects/acme/..")" = "400" ] || fail "bad name should be 400"
[ "$(curl -s -o /dev/null -w '%{http_code}' "$ADMIN/projects/nobody/none")" = "404" ] || fail "unknown project should be 404"

step "a failed deploy stays listed as failed; mix arinsal.delete removes it too"
OUT="$(arinsal_task arinsal.list --url "$ADMIN")"
case "$OUT" in *"acme/bad  failed"*) ;; *) fail "acme/bad not listed as failed: $OUT" ;; esac
arinsal_task arinsal.delete --tenant acme --project bad --url "$ADMIN"

step "mix arinsal.delete the rest: processes gone, files gone"
arinsal_task arinsal.delete --tenant acme --project shop --url "$ADMIN"
arinsal_task arinsal.delete --tenant globex --project shop --url "$ADMIN"
curl -sf -m 2 "http://127.0.0.1:$PG/t/1/items/1" >/dev/null 2>&1 && fail "globex still answers after delete"
[ "$(curl -s "$ADMIN/projects")" = "[]" ] || fail "projects remain after delete"
[ -z "$(ls -A "$WORK/data")" ] || fail "data dir not empty after delete: $(ls -A "$WORK/data")"

echo "PASS"
