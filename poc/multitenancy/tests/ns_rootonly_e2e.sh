#!/usr/bin/env bash
# A namespace process on a booted Arinsal node reaches the introspection OTP code needs:
# module_info of modules the RootOnly list covers, code:ensure_loaded/1 of an OTP module not yet
# loaded (the first unloaded of a few stdlib modules) and
# application:load/1, with root's code_server and application_controller exposed.
#
#   poc/multitenancy/tests/ns_rootonly_e2e.sh
#
# Needs a built `arinsal` binary (ARINSAL_BIN, default <repo>/../target-mt-ns/debug/arinsal) and
# stock OTP 29 for erlc.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
BIN="${ARINSAL_BIN:-$ROOT/../target-mt-ns/debug/arinsal}"
export ERL_ROOTDIR="${ERL_ROOTDIR:-/opt/homebrew/opt/erlang@29/lib/erlang}"
STOCK_PATH="${STOCK_PATH:-/opt/homebrew/opt/erlang@29/bin:/usr/bin:/bin}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/ns_rootonly_e2e.XXXXXX")"
trap '[ -n "${KEEP:-}" ] || rm -rf "$WORK"' EXIT
[ -x "$BIN" ] || { echo "FAIL: no arinsal binary at $BIN"; exit 1; }
mkdir -p "$WORK/shim"
ln -s "$BIN" "$WORK/shim/erl"

cat >"$WORK/ns_rootonly_probe.erl" <<'ERL'
-module(ns_rootonly_probe).
-compile(nowarn_deprecated_catch).
-export([main/0, probe/3]).

main() ->
    {ok, Ns} = arinsal_ns:create(<<"acme">>, <<"shop">>, #{}),
    [ok = arinsal_ns:expose(P) || N <- [code_server, application_controller, error_handler, erl_prim_loader, file_server_2],
                                  P <- [whereis(N)], is_pid(P)],
    Alias = erlang:alias(),
    [Fresh | _] = [M || M <- [sofs, digraph_utils, qlc, dets, tar, zip], code:is_loaded(M) =:= false],
    _ = arinsal_ns:spawn(Ns, ?MODULE, probe, [Alias, persistent_term:get(), Fresh]),
    Result = receive {probe, R} -> R after 20000 -> timeout end,
    io:format("~p~n", [Result]),
    halt(case Result of #{ok := true} -> 0; _ -> 1 end).

%% The boot copies root's persistent terms into the namespace the same way: code_server and
%% friends keep state there.
probe(Alias, Terms, Fresh) ->
    [persistent_term:put(K, V) || {K, V} <- Terms],
    Info = [{M, catch M:module_info(module)} || M <- [erl_ddll, erts_debug, erts_internal, erl_debugger]],
    Loaded = catch code:ensure_loaded(Fresh),
    App = catch application:load(sasl),
    Map = catch maps:to_list(maps:iterator(#{a => 1})),
    Ok = Info =:= [{M, M} || {M, _} <- Info]
        andalso Loaded =:= {module, Fresh}
        andalso (App =:= ok orelse App =:= {error, {already_loaded, sasl}})
        andalso Map =:= [{a, 1}],
    Alias ! {probe, #{ok => Ok, info => Info, loaded => Loaded, app => App, map => Map}}.
ERL
env -u ERL_ROOTDIR PATH="$STOCK_PATH" erlc -o "$WORK" "$WORK/ns_rootonly_probe.erl"
PATH="$WORK/shim:$PATH" erl -noshell -pa "$WORK" -eval 'ns_rootonly_probe:main().' && echo "ok: ns_rootonly_e2e"
