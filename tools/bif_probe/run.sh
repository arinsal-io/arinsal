#!/usr/bin/env bash
set -euo pipefail

# Ensure standard temp directory
export TMPDIR="/tmp"
export PYTHONDONTWRITEBYTECODE=1

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

ARINSAL="$ROOT_DIR/target/release/arinsal"
ERL="erl"

if [ ! -x "$ARINSAL" ]; then
    echo "Building arinsal-cli release..."
    cargo build --release -p arinsal-cli --manifest-path "$ROOT_DIR/Cargo.toml"
fi

TMP_RUN_DIR=$(mktemp -d "${TMPDIR:-/tmp}/bif_probe.XXXXXX")
RESULTS_JSONL="$TMP_RUN_DIR/results.jsonl"
touch "$RESULTS_JSONL"

cleanup() {
    rm -f "$ROOT_DIR/erl_crash.dump"
    rm -rf "$TMP_RUN_DIR"
    rm -rf "$SCRIPT_DIR/__pycache__"
    # Clean up test files created in TMPDIR
    rm -f "${TMPDIR:-/tmp}/arinsal_probe.txt"
    rm -f "${TMPDIR:-/tmp}/gs_test."* "${TMPDIR:-/tmp}/gsm_test."* "${TMPDIR:-/tmp}/sup_test."*
}
trap cleanup EXIT

TOTAL=0
PASSED=0
MISMATCHES=0
declare -a SNIPPET_LIST=()
declare -a RETRY_QUEUE=()
declare -a ERTS_CODES=()

record_result() {
    local idx="$1"
    local snippet="$2"
    local arin_code="$3"
    local erts_code="$4"
    local arin_out_file="$5"
    local arin_err_file="$6"
    local erts_out_file="$7"
    local erts_err_file="$8"
    local retried="$9"

    python3 -c '
import json, re, sys

idx = sys.argv[1]
snippet = sys.argv[2]
arin_code = int(sys.argv[3])
erts_code = int(sys.argv[4])
arin_out_path = sys.argv[5]
arin_err_path = sys.argv[6]
erts_out_path = sys.argv[7]
erts_err_path = sys.argv[8]
retried = sys.argv[9].lower() == "true"
out_json_path = sys.argv[10]

with open(arin_out_path, "r", encoding="utf-8", errors="replace") as f:
    arin_out = f.read()
with open(arin_err_path, "r", encoding="utf-8", errors="replace") as f:
    arin_err = f.read()
with open(erts_out_path, "r", encoding="utf-8", errors="replace") as f:
    erts_out = f.read()
with open(erts_err_path, "r", encoding="utf-8", errors="replace") as f:
    erts_err = f.read()

bif_regex = re.compile(r"unsupported BIF\s+([^\s]+)\s+\(called from\s+([^)]+)\)")
unsupported = []
for m in bif_regex.finditer(arin_err):
    unsupported.append({"bif": m.group(1), "caller": m.group(2)})

record = {
    "idx": int(idx),
    "snippet": snippet,
    "arinsal_code": arin_code,
    "arinsal_out": arin_out,
    "arinsal_err": arin_err,
    "erts_code": erts_code,
    "erts_out": erts_out,
    "erts_err": erts_err,
    "unsupported_bifs": unsupported,
    "retried": retried,
}

with open(out_json_path, "w", encoding="utf-8") as f:
    json.dump(record, f)
' "$idx" "$snippet" "$arin_code" "$erts_code" "$arin_out_file" "$arin_err_file" "$erts_out_file" "$erts_err_file" "$retried" "$TMP_RUN_DIR/res_${idx}.json"
}

run_eval() {
    local snippet="$1"
    TOTAL=$((TOTAL + 1))
    SNIPPET_LIST[$TOTAL]="$snippet"

    local arin_out_file="$TMP_RUN_DIR/arin_${TOTAL}.stdout"
    local arin_err_file="$TMP_RUN_DIR/arin_${TOTAL}.stderr"
    local erts_out_file="$TMP_RUN_DIR/erts_${TOTAL}.stdout"
    local erts_err_file="$TMP_RUN_DIR/erts_${TOTAL}.stderr"

    # Run on Arinsal under timeout -s KILL 30
    local arin_code=0
    timeout -s KILL 30 "$ARINSAL" -noshell -eval "$snippet" > "$arin_out_file" 2> "$arin_err_file" || arin_code=$?
    rm -f "$ROOT_DIR/erl_crash.dump"

    # Run on ERTS under timeout -s KILL 30
    local erts_code=0
    timeout -s KILL 30 "$ERL" -noshell -eval "$snippet" > "$erts_out_file" 2> "$erts_err_file" || erts_code=$?
    rm -f "$ROOT_DIR/erl_crash.dump"
    ERTS_CODES[$TOTAL]="$erts_code"

    record_result "$TOTAL" "$snippet" "$arin_code" "$erts_code" "$arin_out_file" "$arin_err_file" "$erts_out_file" "$erts_err_file" "false"

    local arin_res
    arin_res=$(tr -d '\r\n' < "$arin_out_file" || true)
    local erts_res
    erts_res=$(tr -d '\r\n' < "$erts_out_file" || true)

    if [ "$arin_code" -eq "$erts_code" ] && [ "$arin_res" = "$erts_res" ]; then
        PASSED=$((PASSED + 1))
        echo "[$TOTAL] MATCH: ${snippet:0:60}..."
    else
        MISMATCHES=$((MISMATCHES + 1))
        # Check if Arinsal side failed by timeout/kill (exit 124/137 or no output)
        local needs_retry=0
        if [ "$arin_code" -eq 124 ] || [ "$arin_code" -eq 137 ]; then
            needs_retry=1
        else
            local err_meaningful
            err_meaningful=$(grep -v "Crash dump is being written to:" "$arin_err_file" | tr -d '[:space:]' || true)
            if [ -z "$arin_res" ] && [ -z "$err_meaningful" ]; then
                needs_retry=1
            fi
        fi

        if [ "$needs_retry" -eq 1 ]; then
            RETRY_QUEUE+=("$TOTAL")
            echo "[$TOTAL] TIMEOUT/KILL (will retry): ${snippet:0:50}..."
        elif grep -q "unsupported BIF" "$arin_err_file"; then
            local missing
            missing=$(grep -o 'unsupported BIF [^ ]* (called from [^)]*)' "$arin_err_file" | head -n 1)
            echo "[$TOTAL] BIF GAP ($missing): ${snippet:0:50}..."
        else
            echo "[$TOTAL] MISMATCH (erts_code=$erts_code arin_code=$arin_code): ${snippet:0:50}..."
        fi
    fi
}

echo "=== Running BIF gaps probe snippets ==="

# 1. receive/after
run_eval 'receive after 10 -> io:format("timeout~n") end, halt().'
run_eval 'receive _ -> io:format("msg~n") after 0 -> io:format("empty~n") end, halt().'
run_eval 'P = spawn(fun() -> receive M -> io:format("got_~p~n", [M]) end end), P ! hello, timer:sleep(50), halt().'

# 2. try/catch
run_eval 'try throw(foo) catch throw:X -> io:format("throw_~p~n", [X]) end, halt().'
run_eval 'try error(badarg) catch error:X -> io:format("error_~p~n", [X]) end, halt().'
run_eval 'try 42 of V -> io:format("val_~p~n", [V]) catch _:_ -> io:format("err~n") after io:format("after~n") end, halt().'
run_eval 'F = fun(X) -> try 1/X catch error:badarith -> div_zero; _:_ -> other end end, io:format("~p ~p~n", [F(0), F(1)]), halt().'

# 3. maps comprehensions
run_eval 'M = #{K => V * 2 || K := V <- #{a => 1, b => 2}}, io:format("~p~n", [lists:sort(maps:to_list(M))]), halt().'
run_eval 'M = #{K => true || K <- [x, y, z]}, io:format("~p~n", [lists:sort(maps:to_list(M))]), halt().'
run_eval 'M = #{K => V || K := V <- #{a => 1, b => 2, c => 3}, V > 1}, io:format("~p~n", [lists:sort(maps:to_list(M))]), halt().'

# 4. binary comprehensions
run_eval 'B = << <<(X*2)>> || <<X>> <= <<1, 2, 3>> >>, io:format("~p~n", [B]), halt().'
run_eval 'L = [X || <<X:16/little>> <= <<1,0, 2,0, 3,0>>], io:format("~p~n", [L]), halt().'
run_eval 'B = << <<X:4>> || <<X:4>> <= <<18:8>>, X > 1 >>, io:format("~p~n", [B]), halt().'

# 5. string/unicode functions
run_eval 'io:format("~ts~n", [string:uppercase("hello world")]), halt().'
run_eval 'io:format("~ts~n", [string:trim("  foo bar  ")]), halt().'
run_eval 'io:format("~p~n", [unicode:characters_to_binary("äöü", utf8, utf8)]), halt().'
run_eval 'io:format("~p~n", [unicode:characters_to_list(<<"hello"/utf8>>)]), halt().'

# 6. lists/proplists/dict/sets/gb_trees/queue
run_eval 'io:format("~p~n", [lists:sort([3, 1, 4, 1, 5, 9])]), halt().'
run_eval 'io:format("~p~n", [proplists:get_value(k, [{a, 1}, {k, 42}])]), halt().'
run_eval 'D = dict:store(k, v, dict:new()), io:format("~p~n", [dict:fetch(k, D)]), halt().'
run_eval 'S = sets:from_list([1, 2, 3], [{version, 2}]), io:format("~p~n", [sets:is_element(2, S)]), halt().'
run_eval 'T = gb_trees:insert(1, val, gb_trees:empty()), io:format("~p~n", [gb_trees:lookup(1, T)]), halt().'
run_eval 'Q = queue:in(b, queue:in(a, queue:new())), {{value, V}, _} = queue:out(Q), io:format("~p~n", [V]), halt().'

# 7. io_lib:format variants
run_eval 'io:format("~s~n", [lists:flatten(io_lib:format("~p ~s ~w ~b ~5.2f", [atom, "str", {1,2}, 42, 3.14159]))]), halt().'
run_eval 'io:format("~s~n", [lists:flatten(io_lib:format("~.4B", [15]))]), halt().'
run_eval 'io:format("~s~n", [lists:flatten(io_lib:format("~10.10s", ["center"]))]), halt().'

# 8. re:run/replace
run_eval '{match, [M]} = re:run("abc123xyz", "[0-9]+", [{capture, first, binary}]), io:format("~s~n", [M]), halt().'
run_eval 'Res = re:replace("banana", "a", "o", [global, {return, binary}]), io:format("~s~n", [Res]), halt().'

# 9. ets (all table types, select/match/fold)
run_eval 'T = ets:new(t1, [set]), ets:insert(T, {k, 1}), io:format("~p~n", [ets:lookup(T, k)]), halt().'
run_eval 'T = ets:new(t2, [ordered_set]), ets:insert(T, [{3, c}, {1, a}, {2, b}]), io:format("~p~n", [ets:first(T)]), halt().'
run_eval 'T = ets:new(t3, [bag]), ets:insert(T, [{k, 1}, {k, 2}, {k, 1}]), io:format("~p~n", [lists:sort(ets:lookup(T, k))]), halt().'
run_eval 'T = ets:new(t4, [duplicate_bag]), ets:insert(T, [{k, 1}, {k, 1}]), io:format("~p~n", [ets:lookup(T, k)]), halt().'
run_eval 'T = ets:new(t5, [set]), ets:insert(T, [{1, 10}, {2, 20}]), S = ets:match(T, {1, "$1"}), F = ets:foldl(fun({_, V}, Acc) -> Acc + V end, 0, T), io:format("~p ~p~n", [S, F]), halt().'

# 10. persistent_term
run_eval 'persistent_term:put(key1, hello), io:format("~p~n", [persistent_term:get(key1)]), halt().'
run_eval 'persistent_term:put(key2, 42), V = persistent_term:get(key2, default), persistent_term:erase(key2), io:format("~p ~p~n", [V, persistent_term:get(key2, missing)]), halt().'

# 11. atomics/counters
run_eval 'Ref = atomics:new(1, []), atomics:put(Ref, 1, 42), atomics:add(Ref, 1, 8), io:format("~p~n", [atomics:get(Ref, 1)]), halt().'
run_eval 'Ref = counters:new(1, []), counters:add(Ref, 1, 5), io:format("~p~n", [counters:get(Ref, 1)]), halt().'

# 12. erlang:system_info/process_info/statistics keys
run_eval 'io:format("~p ~p~n", [erlang:system_info(wordsize) > 0, is_integer(erlang:system_info(schedulers))]), halt().'
run_eval 'io:format("~p~n", [element(1, erlang:statistics(wall_clock)) >= 0]), halt().'
run_eval 'io:format("~p ~p~n", [is_tuple(erlang:statistics(runtime)), element(1, erlang:statistics(reductions)) >= 0]), halt().'
run_eval 'io:format("~p~n", [is_list(erlang:process_info(whereis(init)))]), halt().'

# 13. timers (send_after, start_timer, cancel_timer)
run_eval 'Ref = erlang:send_after(10000, whereis(init), foo), io:format("~p ~p~n", [is_reference(Ref), erlang:cancel_timer(Ref) > 0]), halt().'
run_eval 'Ref = erlang:start_timer(10000, whereis(init), bar), io:format("~p ~p~n", [is_reference(Ref), erlang:cancel_timer(Ref) > 0]), halt().'

# 14. monitors/links/exit
run_eval 'P = spawn(fun() -> receive exit -> ok end end), Ref = erlang:monitor(process, P), P ! exit, io:format("~p~n", [is_reference(Ref)]), halt().'
run_eval 'P = spawn(fun() -> receive exit -> ok end end), erlang:link(P), P ! exit, io:format("linked~n"), halt().'
run_eval 'P = spawn(fun() -> ok end), erlang:link(P), erlang:unlink(P), io:format("unlinked~n"), halt().'
run_eval 'try exit(test_exit) catch exit:R -> io:format("caught ~p~n", [R]) end, halt().'

# 15. gen_server/gen_statem/supervisor start+call+stop
run_eval 'Tmp = os:getenv("TMPDIR", "/tmp"), Src = filename:join(Tmp, "gs_test.erl"), ok = file:write_file(Src, <<"-module(gs_test).\n-behaviour(gen_server).\n-export([init/1,handle_call/3,handle_cast/2,terminate/2]).\ninit([]) -> {ok, state}.\nhandle_call(ping, _From, State) -> {reply, pong, State}.\nhandle_cast(_Msg, State) -> {noreply, State}.\nterminate(_Reason, _State) -> ok.\n">>), {ok, gs_test} = compile:file(Src, [{outdir, Tmp}]), code:add_pathz(Tmp), {ok, Pid} = gen_server:start_link(gs_test, [], []), Res = gen_server:call(Pid, ping), ok = gen_server:stop(Pid), io:format("gs_result ~p~n", [Res]), halt().'
run_eval 'Tmp = os:getenv("TMPDIR", "/tmp"), Src = filename:join(Tmp, "gsm_test.erl"), ok = file:write_file(Src, <<"-module(gsm_test).\n-behaviour(gen_statem).\n-export([init/1,callback_mode/0,handle_event/4,terminate/3]).\ncallback_mode() -> handle_event_function.\ninit([]) -> {ok, idle, data}.\nhandle_event({call, From}, ping, _State, Data) -> {keep_state, Data, [{reply, From, pong}]};\nhandle_event(_Type, _Content, _State, _Data) -> keep_state_and_data.\nterminate(_Reason, _State, _Data) -> ok.\n">>), {ok, gsm_test} = compile:file(Src, [{outdir, Tmp}]), code:add_pathz(Tmp), {ok, Pid} = gen_statem:start_link(gsm_test, [], []), Res = gen_statem:call(Pid, ping), ok = gen_statem:stop(Pid), io:format("gsm_result ~p~n", [Res]), halt().'
run_eval 'Tmp = os:getenv("TMPDIR", "/tmp"), Src = filename:join(Tmp, "sup_test.erl"), ok = file:write_file(Src, <<"-module(sup_test).\n-behaviour(supervisor).\n-export([init/1]).\ninit([]) -> {ok, {#{strategy => one_for_all, intensity => 1, period => 5}, []}}.\n">>), {ok, sup_test} = compile:file(Src, [{outdir, Tmp}]), code:add_pathz(Tmp), {ok, Pid} = supervisor:start_link(sup_test, []), Children = supervisor:which_children(Pid), io:format("sup_children ~p~n", [Children]), halt().'

# 16. file/filename basic ops in $TMPDIR
run_eval 'Tmp = os:getenv("TMPDIR", "/tmp"), Path = filename:join(Tmp, "arinsal_probe.txt"), ok = file:write_file(Path, <<"hello">>), {ok, <<"hello">>} = file:read_file(Path), file:delete(Path), io:format("file_ok~n"), halt().'
run_eval 'P = filename:join(["a", "b", "c.txt"]), io:format("~p ~p~n", [filename:split(P), filename:extension(P)]), halt().'
run_eval 'Tmp = os:getenv("TMPDIR", "/tmp"), io:format("~p~n", [is_list(element(2, file:list_dir(Tmp)))]), halt().'

# 17. os:getenv/timestamp
run_eval 'io:format("~p ~p~n", [os:getenv("PATH") =/= false, os:getenv("NON_EXISTENT_VAR_12345")]), halt().'
run_eval '{M, S, U} = os:timestamp(), io:format("~p~n", [is_integer(M) and is_integer(S) and is_integer(U)]), halt().'
run_eval 'io:format("~p~n", [is_integer(os:system_time(millisecond))]), halt().'

# 18. rand/crypto:hash (if available)
run_eval 'io:format("~p~n", [rand:uniform(100) >= 1]), halt().'
run_eval 'io:format("~s~n", [binary:encode_hex(crypto:hash(sha256, <<"test">>))]), halt().'

# 19. term_to_binary/binary_to_term
run_eval 'B = term_to_binary({foo, [1, 2, 3], #{a => 42}}), T = binary_to_term(B), io:format("~p~n", [T]), halt().'
run_eval 'B = term_to_binary(lists:seq(1, 100), [compressed]), T = binary_to_term(B), io:format("~p~n", [length(T)]), halt().'

# 20. calendar/erlang:localtime
run_eval '{Date, {H, M, S}} = erlang:localtime(), io:format("~p ~p~n", [is_tuple(Date), is_integer(H) and is_integer(M) and is_integer(S)]), halt().'
run_eval 'io:format("~p ~p~n", [calendar:is_leap_year(2024), calendar:day_of_the_week(2024, 1, 1)]), halt().'

RETRIED_COUNT=0
if [ ${#RETRY_QUEUE[@]} -gt 0 ]; then
    echo ""
    echo "=== Retrying ${#RETRY_QUEUE[@]} timed-out snippet(s) serially with 60s timeout ==="
    for id in "${RETRY_QUEUE[@]}"; do
        RETRIED_COUNT=$((RETRIED_COUNT + 1))
        snippet="${SNIPPET_LIST[$id]}"
        local_arin_out="$TMP_RUN_DIR/arin_${id}.stdout"
        local_arin_err="$TMP_RUN_DIR/arin_${id}.stderr"
        local_erts_out="$TMP_RUN_DIR/erts_${id}.stdout"
        local_erts_err="$TMP_RUN_DIR/erts_${id}.stderr"
        local_erts_code="${ERTS_CODES[$id]}"

        local_arin_code=0
        timeout -s KILL 60 "$ARINSAL" -noshell -eval "$snippet" > "$local_arin_out" 2> "$local_arin_err" || local_arin_code=$?
        rm -f "$ROOT_DIR/erl_crash.dump"

        record_result "$id" "$snippet" "$local_arin_code" "$local_erts_code" "$local_arin_out" "$local_arin_err" "$local_erts_out" "$local_erts_err" "true"

        local_arin_res=$(tr -d '\r\n' < "$local_arin_out" || true)
        local_erts_res=$(tr -d '\r\n' < "$local_erts_out" || true)

        if [ "$local_arin_code" -eq "$local_erts_code" ] && [ "$local_arin_res" = "$local_erts_res" ]; then
            PASSED=$((PASSED + 1))
            MISMATCHES=$((MISMATCHES - 1))
            echo "[$id] RETRY MATCH: ${snippet:0:60}..."
        else
            echo "[$id] RETRY FAILED (erts_code=$local_erts_code arin_code=$local_arin_code): ${snippet:0:50}..."
        fi
    done
fi

# Assemble results.jsonl in numerical order
rm -f "$RESULTS_JSONL"
for ((i=1; i<=TOTAL; i++)); do
    cat "$TMP_RUN_DIR/res_${i}.json" >> "$RESULTS_JSONL"
    echo "" >> "$RESULTS_JSONL"
done

echo ""
echo "=== Evaluation complete ==="
echo "Total snippets:   $TOTAL"
echo "Matches:          $PASSED"
echo "Mismatches:       $MISMATCHES"
echo "Retried snippets: $RETRIED_COUNT"

python3 "$SCRIPT_DIR/reporter.py" "$RESULTS_JSONL" "$SCRIPT_DIR/REPORT.md" "$RETRIED_COUNT"
