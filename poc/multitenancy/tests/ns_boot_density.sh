#!/usr/bin/env bash
# Boots N namespaces of the bench/rest release in one Arinsal node through arinsal_ns_boot
# (prepare/1 with the shared dep domain, arinsal_ns:create/3, start/3), curls each, and prints
# per project: boot time and its phases (prepare in root; load, kernel, apps in the namespace),
# processes, the code delta, the namespace's heap (as of each process's last GC) and ETS words
# from arinsal_ns:info/1; then p50/p99 and erlang:memory(total) after 0, 1, 10, 100 namespaces. Then checks that init:stop()
# inside one namespace destroys only that namespace.
#
#   REST_RELEASE=<built bench/rest release> poc/multitenancy/tests/ns_boot_density.sh [N]
#
# Needs Arinsal's `erl` shim first on PATH (ARINSAL_SHIM, default <repo>/../mt-shim-boot).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
SHIM="${ARINSAL_SHIM:-$ROOT/../mt-shim-boot}"
N="${1:-10}"
BASE_PORT="${BASE_PORT:-4830}"
: "${REST_RELEASE:?set REST_RELEASE to a built bench/rest release}"
export ERL_ROOTDIR="${ERL_ROOTDIR:-/opt/homebrew/opt/erlang@29/lib/erlang}"
STOCK_PATH="/opt/homebrew/opt/erlang@29/bin:/opt/homebrew/opt/elixir/bin:/usr/bin:/bin"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/ns_density.XXXXXX")"
trap '[ -n "${KEEP:-}" ] || rm -rf "$WORK"' EXIT

(cd "$ROOT/packages/arinsal_cloud" && env -u ERL_ROOTDIR PATH="$STOCK_PATH" mix compile >/dev/null)
ELIXIR_EBIN="$(env -u ERL_ROOTDIR PATH="$STOCK_PATH" elixir -e 'IO.puts(:code.lib_dir(:elixir))')/ebin"
cat >"$WORK/ns_density.erl" <<'EOF'
-module(ns_density).
-export([run/1]).
%% Row: {Ns, BootMs, PrepareMs, LoadMs, KernelMs, AppsMs, Processes, CodeKB, HeapKB, EtsKB, Curl}
run([Rel, NA, PortA]) ->
    N = list_to_integer(atom_to_list(NA)),
    Port0 = list_to_integer(atom_to_list(PortA)),
    {ok, Plan0} = arinsal_cloud_boot:boot_plan(atom_to_list(Rel)),
    erlang:garbage_collect(),
    Total0 = total(),
    {Rows, Marks} = lists:foldl(
        fun(I, {Acc, Ms}) ->
            Row = one(Plan0, I, Port0 + I),
            io:format("row ~p~n", [Row]),
            Ms1 = case lists:member(I, [1, 10, 100, N]) of
                      true -> erlang:garbage_collect(), [{I, total(), rss()} | Ms];
                      false -> Ms
                  end,
            {[Row | Acc], Ms1}
        end, {[], [{0, Total0, rss()}]}, lists:seq(1, N)),
    All = lists:reverse(Rows),
    io:format("~nns | boot ms | prepare | load | kernel | apps | processes | code KB | ns heap KB | ns ets KB | curl~n"),
    [io:format("~p | ~p | ~p | ~p | ~p | ~p | ~p | ~p | ~p | ~p | ~s~n", tuple_to_list(R)) || R <- All],
    Later = tl(All),
    Pct = fun(Pos, P) ->
                  Sorted = lists:sort([element(Pos, R) || R <- Later]),
                  lists:nth(max(1, min(length(Sorted), (P * length(Sorted) + 99) div 100)), Sorted)
          end,
    io:format("projects 2..~p: boot p50 ~p ms p99 ~p ms; prepare p50 ~p, load p50 ~p, kernel p50 ~p, "
              "apps p50 ~p; processes p50 ~p; code p50 ~p KB; ns heap p50 ~p KB; ns ets p50 ~p KB; "
              "curl 200: ~p/~p~n",
              [N, Pct(2, 50), Pct(2, 99), Pct(3, 50), Pct(4, 50), Pct(5, 50), Pct(6, 50),
               Pct(7, 50), Pct(8, 50), Pct(9, 50), Pct(10, 50),
               length([R || R <- All, element(11, R) =:= "200"]), N]),
    io:format("after K namespaces {K, erlang:memory(total) KB, RSS KB}: ~p~n",
              [[{K, delta(0, T), R} || {K, T, R} <- lists:reverse(Marks)]]),
    Ns = element(1, hd(All)),
    arinsal_ns:spawn(Ns, init, stop, []),
    timer:sleep(1000),
    Alive = arinsal_ns:list(),
    Left = maps:get(processes, arinsal_ns:info(Ns)),
    io:format("init:stop in ns ~p: listed ~p, processes left ~p, others alive ~p, root AC ns ~p~n",
              [Ns, lists:member(Ns, Alive), Left, length(Alive),
               arinsal_ns:'of'(whereis(application_controller))]),
    io:format("DONE~n").

one(Plan0, I, Port) ->
    M0 = code(),
    T0 = erlang:monotonic_time(microsecond),
    Env = [{"RT_PORT", integer_to_list(Port)}, {"PORT", integer_to_list(Port)}],
    {ok, CodeOpts, Plan} = arinsal_ns_boot:prepare(Plan0),
    T1 = erlang:monotonic_time(microsecond),
    {ok, Ns} = arinsal_ns:create(<<"t", (integer_to_binary(I))/binary>>, <<"rest">>,
                                 CodeOpts#{os_env => Env}),
    {ok, _} = arinsal_ns_boot:start(Ns, Plan, #{group_leader => group_leader(), os_env => Env}),
    T2 = erlang:monotonic_time(microsecond),
    #{load := Load, kernel := Kernel, apps := Apps} = get({arinsal_ns_boot, last_timing}),
    Curl = os:cmd("curl -s -m 5 -o /dev/null -w '%{http_code}' http://127.0.0.1:"
                  ++ integer_to_list(Port) ++ "/t/1/items/1"),
    timer:sleep(50),
    Info = #{processes := Procs} = arinsal_ns:info(Ns),
    Words = fun(K) -> maps:get(K, Info, 0) * erlang:system_info(wordsize) div 1024 end,
    {Ns, (T2 - T0) div 1000, (T1 - T0) div 1000, Load, Kernel, Apps, Procs,
     delta(M0, code()), Words(heap_words), Words(ets_words), Curl}.

total() -> memory(total).
code() -> memory(code).

%% erlang:memory/1 has been seen to block in root after a namespace boot; give up after 5 s and
%% stop asking.
memory(Kind) ->
    case get(mem_stalled) of
        true -> stalled;
        _ -> memory1(Kind)
    end.

memory1(Kind) ->
    Self = self(),
    Pid = spawn(fun() -> Self ! {mem, self(), erlang:memory(Kind)} end),
    receive {mem, Pid, V} -> V
    after 5000 -> io:format("erlang:memory(~p) stalled; not asked again~n", [Kind]),
                  put(mem_stalled, true),
                  stalled
    end.

delta(A, B) when is_integer(A), is_integer(B) -> (B - A) div 1024;
delta(_, _) -> stalled.

rss() ->
    list_to_integer(string:trim(os:cmd("ps -o rss= -p " ++ os:getpid()))).
EOF
(cd "$WORK" && env -u ERL_ROOTDIR PATH="$STOCK_PATH" erlc ns_density.erl)
# The node can hang in halt (root stall, NOTES-boot.md): it runs in the background and is
# killed with -9 at the end.
PATH="$SHIM:$PATH" erl -noshell -pa "$ROOT/packages/arinsal_cloud/_build/dev/lib/arinsal_cloud/ebin" \
  -pa "$ELIXIR_EBIN" -pa "$WORK" -eval "ns_density:run(['$REST_RELEASE', '$N', '$BASE_PORT']), halt()." \
  >"$WORK/out.log" 2>&1 &
NODE=$!
trap 'kill -9 $NODE 2>/dev/null; [ -n "${KEEP:-}" ] || rm -rf "$WORK"' EXIT
tail -f "$WORK/out.log" | grep --line-buffered -v '^\s*$' &
TAIL=$!
for _ in $(seq 1 "${TIMEOUT_S:-1800}"); do
  kill -0 $NODE 2>/dev/null || break
  grep -q '^DONE' "$WORK/out.log" && break
  sleep 1
done
sleep 1
kill $TAIL 2>/dev/null || true
kill -9 $NODE 2>/dev/null || true
