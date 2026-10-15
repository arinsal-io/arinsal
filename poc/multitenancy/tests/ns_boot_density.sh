#!/usr/bin/env bash
# Boots N namespaces of the bench/rest release in one Arinsal node through arinsal_ns_boot
# (prepare/1 with the shared dep domain, arinsal_ns:create/3, start/3), curls each, and prints
# per-project boot time, processes, erlang:memory and RSS deltas. Then checks that init:stop()
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
run([Rel, NA, PortA]) ->
    N = list_to_integer(atom_to_list(NA)),
    Port0 = list_to_integer(atom_to_list(PortA)),
    {ok, Plan0} = arinsal_cloud_boot:boot_plan(atom_to_list(Rel)),
    Rows = [one(Plan0, I, Port0 + I) || I <- lists:seq(1, N)],
    io:format("~nns | boot ms | processes | memory total KB | code KB | processes KB | ets KB | rss KB | curl~n"),
    [io:format("~p | ~p | ~p | ~p | ~p | ~p | ~p | ~p | ~s~n", tuple_to_list(R)) || R <- Rows],
    Later = tl(Rows),
    Med = fun(Pos) -> lists:nth((length(Later) + 1) div 2, lists:sort([element(Pos, R) || R <- Later])) end,
    io:format("median of projects 2..N: boot ~p ms, processes ~p, total ~p KB, code ~p KB, "
              "processes ~p KB, ets ~p KB, rss ~p KB~n",
              [Med(2), Med(3), Med(4), Med(5), Med(6), Med(7), Med(8)]),
    Ns = element(1, hd(Rows)),
    arinsal_ns:spawn(Ns, init, stop, []),
    timer:sleep(1000),
    Alive = arinsal_ns:list(),
    Left = maps:get(processes, arinsal_ns:info(Ns)),
    io:format("init:stop in ns ~p: listed ~p, processes left ~p, others alive ~p, root AC ns ~p~n",
              [Ns, lists:member(Ns, Alive), Left, length(Alive),
               arinsal_ns:'of'(whereis(application_controller))]),
    io:format("DONE~n").

one(Plan0, I, Port) ->
    erlang:garbage_collect(),
    M0 = erlang:memory(),
    R0 = rss(),
    T0 = erlang:monotonic_time(microsecond),
    Env = [{"RT_PORT", integer_to_list(Port)}, {"PORT", integer_to_list(Port)}],
    io:format("project ~p: prepare~n", [I]),
    {ok, CodeOpts, Plan} = arinsal_ns_boot:prepare(Plan0),
    io:format("project ~p: start ~p~n", [I, CodeOpts]),
    {ok, Ns} = arinsal_ns:create(<<"t", (integer_to_binary(I))/binary>>, <<"rest">>,
                                 CodeOpts#{os_env => Env}),
    {ok, _} = arinsal_ns_boot:start(Ns, Plan, #{group_leader => group_leader(), os_env => Env}),
    T1 = erlang:monotonic_time(microsecond),
    Curl = os:cmd("curl -s -m 5 -o /dev/null -w '%{http_code}' http://127.0.0.1:"
                  ++ integer_to_list(Port) ++ "/t/1/items/1"),
    timer:sleep(300),
    M1 = erlang:memory(),
    D = fun(K) -> (proplists:get_value(K, M1) - proplists:get_value(K, M0)) div 1024 end,
    #{processes := Procs} = arinsal_ns:info(Ns),
    {Ns, (T1 - T0) div 1000, Procs, D(total), D(code), D(processes), D(ets), rss() - R0, Curl}.

rss() ->
    list_to_integer(string:trim(os:cmd("ps -o rss= -p " ++ os:getpid()))).
EOF
(cd "$WORK" && env -u ERL_ROOTDIR PATH="$STOCK_PATH" erlc ns_density.erl)
PATH="$SHIM:$PATH" erl -noshell -pa "$ROOT/packages/arinsal_cloud/_build/dev/lib/arinsal_cloud/ebin" \
  -pa "$ELIXIR_EBIN" -pa "$WORK" -eval "ns_density:run(['$REST_RELEASE', '$N', '$BASE_PORT']), halt()." \
  2>&1 | grep -v '^\s*$' || true
