#!/usr/bin/env bash
# End-to-end test of the namespace backend: the manager (arinsal_cloud, backend ns) boots the
# poc/multitenancy/bench/rest release inside namespaces of one Arinsal node.
#
#   poc/multitenancy/tests/ns_boot_e2e.sh
#
# Deploys acme/shop and globex/shop (PUT of the release tarball), curls both, checks through a
# probe process in the manager node that each namespace has processes, that root's
# application_controller is still root's, and records the memory per project, then stops acme
# (globex keeps answering) and deletes both (the namespaces drain to 0 processes).
#
# Needs: Arinsal's `erl` shim with the namespace natives first on PATH (ARINSAL_SHIM, default
# <repo>/../mt-shim-boot), Elixir, curl. The release is built with stock OTP (bench/rest deps do
# not compile on Arinsal yet) unless REST_RELEASE points to a built one. KEEP=1 keeps the temp dir.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
SHIM="${ARINSAL_SHIM:-$ROOT/../mt-shim-boot}"
export PATH="$SHIM:/opt/homebrew/opt/elixir/bin:$PATH"
export ERL_ROOTDIR="${ERL_ROOTDIR:-/opt/homebrew/opt/erlang@29/lib/erlang}"
STOCK_PATH="${STOCK_PATH:-/opt/homebrew/opt/erlang@29/bin:/opt/homebrew/opt/elixir/bin:/usr/bin:/bin}"
stock() { env -u ERL_ROOTDIR PATH="$STOCK_PATH" "$@"; }

case "$(elixir --version 2>&1)" in *"arinsal "*) ;; *) echo "FAIL: the node under test is not Arinsal"; exit 1 ;; esac

WORK="$(mktemp -d "${TMPDIR:-/tmp}/ns_boot_e2e.XXXXXX")"
ADMIN_PORT="${ADMIN_PORT:-7021}"
ADMIN="http://127.0.0.1:$ADMIN_PORT"
MGR_PID=""
cleanup() {
  if [ -n "$MGR_PID" ]; then
    kill "$MGR_PID" 2>/dev/null || true
    for _ in 1 2 3 4 5 6 7 8 9 10; do kill -0 "$MGR_PID" 2>/dev/null || break; sleep 0.5; done
    kill -9 "$MGR_PID" 2>/dev/null || true
    wait "$MGR_PID" 2>/dev/null || true
  fi
  [ -n "${KEEP:-}" ] || rm -rf "$WORK"
}
trap cleanup EXIT
step() { echo "== $*"; }
fail() { echo "FAIL: $*"; echo "manager log:"; tail -40 "$WORK/manager.log" 2>/dev/null || true; exit 1; }
json_field() { sed -n "s/.*\"$1\":\([0-9]*\).*/\1/p" | head -1; }
probe() { cat "$WORK/probe.txt" 2>/dev/null || true; }

step "compile the manager and the probe"
(cd "$ROOT/packages/arinsal_cloud" && stock mix compile >"$WORK/compile.log" 2>&1) || { cat "$WORK/compile.log"; exit 1; }
cat >"$WORK/ns_boot_probe.erl" <<'EOF'
-module(ns_boot_probe).
-export([start/1]).
%% Writes the root view of the namespaces to a file every 200 ms, with prim_file (no file
%% server). A side process writes through root's file_server_2 as well; fs_stuck_ms reports how
%% long its current write has been pending.
start([File]) ->
    spawn(fun() -> loop(atom_to_list(File), undefined) end).
loop(File, Fs0) ->
    Fs = fs_writer(File, Fs0),
    try sample(File, Fs)
    catch C:E:S -> prim_file:write_file(File ++ ".err", io_lib:format("~p~n", [{C, E, S}]))
    end,
    receive after 200 -> loop(File, Fs) end.
fs_writer(File, {Pid, T0}) ->
    case is_process_alive(Pid) of
        true -> {Pid, T0};
        false -> fs_writer(File, undefined)
    end;
fs_writer(File, undefined) ->
    {spawn(fun() -> ok = file:write_file(File ++ ".fs", <<"x">>) end),
     erlang:monotonic_time(millisecond)}.
%% erlang:memory/0 has been seen to block in root while a namespace boots (NOTES-boot.md), so it
%% runs in a helper; after 1 s the last value is reused and mem_stuck counts the stalls.
memory() ->
    Self = self(),
    Pid = spawn(fun() -> Self ! {mem, self(), erlang:memory()} end),
    receive
        {mem, Pid, Mem} -> put(mem, Mem), Mem
    after 1000 ->
        put(mem_stuck, (case get(mem_stuck) of undefined -> 0; N -> N end) + 1),
        case get(mem) of undefined -> []; Last -> Last end
    end.
sample(File, {_, FsT0}) ->
    AC = whereis(application_controller),
    Mem = memory(),
    Ns = [{N, maps:with([processes, tenant, project], arinsal_ns:info(N))} || N <- arinsal_ns:list()],
    Line = io_lib:format("ac_ns=~p total=~p processes=~p code=~p ets=~p fs_stuck_ms=~p mem_stuck=~p ns=~0p~n",
                         [arinsal_ns:'of'(AC), proplists:get_value(total, Mem),
                          proplists:get_value(processes, Mem), proplists:get_value(code, Mem),
                          proplists:get_value(ets, Mem), erlang:monotonic_time(millisecond) - FsT0,
                          get(mem_stuck), Ns]),
    ok = prim_file:write_file(File ++ ".tmp", iolist_to_binary(Line)),
    ok = prim_file:rename(File ++ ".tmp", File).
EOF
(cd "$WORK" && stock erlc ns_boot_probe.erl) || fail "probe does not compile"

if [ -n "${REST_RELEASE:-}" ]; then
  REL="$REST_RELEASE"
else
  step "build bench/rest with stock OTP"
  cp -R "$ROOT/poc/multitenancy/bench/rest" "$WORK/rest"
  rm -rf "$WORK/rest/_build" "$WORK/rest/deps"
  sed -i.bak "s#\"../../../../packages/arinsal\"#\"$ROOT/packages/arinsal\"#" "$WORK/rest/mix.exs"
  (cd "$WORK/rest" && stock mix deps.get && MIX_ENV=prod stock mix release --overwrite --path "$WORK/rel") \
    >"$WORK/release.log" 2>&1 || { tail -30 "$WORK/release.log"; exit 1; }
  REL="$WORK/rel"
fi
tar -C "$REL" -czf "$WORK/rest.tar.gz" lib releases

step "start the manager on $ADMIN with the namespace backend"
"$ROOT/packages/arinsal_cloud/bin/arinsal-cloud" --admin "$ADMIN_PORT" --data-dir "$WORK/data" --backend ns \
  -- -pa "$WORK" -s ns_boot_probe start "$WORK/probe.txt" >"$WORK/manager.log" 2>&1 &
MGR_PID=$!
for _ in $(seq 1 100); do
  curl -sf "$ADMIN/projects" >/dev/null 2>&1 && break
  kill -0 "$MGR_PID" 2>/dev/null || fail "manager exited"
  sleep 0.2
done
sleep 0.5
BASE="$(probe)"
echo "before: $BASE"
case "$BASE" in *"ac_ns=0 "*) ;; *) fail "probe not running" ;; esac

deploy() {
  local t0 t1 code
  t0=$(date +%s)
  code="$(curl -s -o "$WORK/deploy_$1.json" -w '%{http_code}' -X PUT --data-binary @"$WORK/rest.tar.gz" "$ADMIN/projects/$1/shop")"
  t1=$(date +%s)
  [ "$code" = "200" ] || [ "$code" = "201" ] || { cat "$WORK/deploy_$1.json"; fail "deploy $1: HTTP $code"; }
  sleep 0.5
  echo "deployed $1 in $((t1 - t0)) s; $(probe)"
}

step "deploy acme/shop and globex/shop"
deploy acme
AFTER1="$(probe)"
deploy globex
AFTER2="$(probe)"
PA="$(curl -sf "$ADMIN/projects/acme/shop" | json_field port)"
PG="$(curl -sf "$ADMIN/projects/globex/shop" | json_field port)"
{ [ -n "$PA" ] && [ -n "$PG" ] && [ "$PA" != "$PG" ]; } || fail "ports not distinct: $PA $PG"

step "curl both projects"
for P in "$PA" "$PG"; do
  OUT="$(curl -sf "http://127.0.0.1:$P/t/1/items/1")" || fail "project on port $P does not answer"
  echo "$OUT" | grep -q '"name":"item-1"' || fail "unexpected body from $P: $OUT"
  echo "port $P: $OUT"
done

step "namespaces have processes, root's application_controller is root's"
P="$(probe)"
case "$P" in *"ac_ns=0 "*) ;; *) fail "root application_controller moved: $P" ;; esac
NPROC="$(echo "$P" | grep -o 'processes => [0-9]*' | awk '{print $3}')"
[ "$(echo "$NPROC" | wc -l | tr -d ' ')" = "2" ] || fail "expected two namespaces: $P"
for n in $NPROC; do [ "$n" -gt 0 ] || fail "a namespace has no processes: $P"; done
echo "processes per namespace: $(echo $NPROC)"
curl -sf "$ADMIN/projects/acme/shop" | grep -q '"processes":' || fail "details lack namespace info"

step "stop acme: globex keeps answering"
curl -sf -X POST "$ADMIN/projects/acme/shop/stop" >/dev/null || fail "stop acme"
sleep 0.5
curl -sf -m 2 "http://127.0.0.1:$PA/t/1/items/1" >/dev/null 2>&1 && fail "acme still answers after stop"
curl -sf "http://127.0.0.1:$PG/t/1/items/1" >/dev/null || fail "globex stopped by the acme stop"

step "delete both: namespaces drain"
curl -sf -X DELETE "$ADMIN/projects/acme/shop" >/dev/null || fail "delete acme"
curl -sf -X DELETE "$ADMIN/projects/globex/shop" >/dev/null || fail "delete globex"
sleep 1
P="$(probe)"
case "$P" in *"ns=[]"*) ;; *) fail "namespaces left after delete: $P" ;; esac
curl -sf -m 2 "http://127.0.0.1:$PG/t/1/items/1" >/dev/null 2>&1 && fail "globex still answers after delete"

field() { echo "$1" | sed -n "s/.*$2=\([0-9]*\).*/\1/p"; }
step "memory (bytes): first project includes the shared base modules it loaded into root"
for k in total processes code ets; do
  echo "$k: first $(( $(field "$AFTER1" $k) - $(field "$BASE" $k) )) second $(( $(field "$AFTER2" $k) - $(field "$AFTER1" $k) ))"
done
echo "root file_server_2 write pending at the end: $(probe | sed -n 's/.*fs_stuck_ms=\([0-9-]*\).*/\1/p') ms; erlang:memory stalls: $(probe | sed -n 's/.*mem_stuck=\([a-z0-9]*\).*/\1/p')"
echo "PASS"
