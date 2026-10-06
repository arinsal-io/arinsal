-module(spawn_breakdown).
-export([main/0, main/1, main/3, main/4, run/0, run/1, run/2, run/3,
         run_variant/1, run_variant/2, run_variant/3, run_variant/4]).
-export([exported_noop/0]).

-define(DEFAULT_N, 100000).
-define(DEFAULT_WARMUP, 1).
-define(DEFAULT_REPEATS, 5).

%% Exported noop function for variant (d)
exported_noop() -> ok.

%% ====================================================================
%% Probe Variants
%% ====================================================================

%% (a) spawn of fun() -> ok end (process exits immediately)
exec_variant_a(N) ->
    loop_a(N),
    N.

loop_a(0) -> ok;
loop_a(I) ->
    spawn(fun() -> ok end),
    loop_a(I - 1).

%% (b) spawn of a process that blocks in receive (measure spawn only, kill all at the end)
exec_variant_b(N) ->
    %% Timed: pure spawn of blocked processes
    {TimeUs, Pids} = timer:tc(fun() -> loop_b(N, []) end),
    %% Outside timer: cleanup all spawned processes
    cleanup_pids(Pids),
    {TimeUs, N}.

loop_b(0, Acc) -> Acc;
loop_b(I, Acc) ->
    Pid = spawn(fun() -> receive stop -> ok end end),
    loop_b(I - 1, [Pid | Acc]).

cleanup_pids(Pids) ->
    lists:foreach(fun(Pid) -> exit(Pid, kill) end, Pids).

%% (c1) spawn_link variant of (a)
exec_variant_c_link(N) ->
    loop_c_link(N),
    N.

loop_c_link(0) -> ok;
loop_c_link(I) ->
    spawn_link(fun() -> ok end),
    loop_c_link(I - 1).

%% (c2) spawn_monitor variant of (a)
exec_variant_c_monitor(N) ->
    loop_c_monitor(N),
    N.

loop_c_monitor(0) -> ok;
loop_c_monitor(I) ->
    spawn_monitor(fun() -> ok end),
    loop_c_monitor(I - 1).

%% (d) spawn(M, F, A) of an exported function vs a closure
exec_variant_d_mfa(N) ->
    loop_d_mfa(N),
    N.

loop_d_mfa(0) -> ok;
loop_d_mfa(I) ->
    spawn(?MODULE, exported_noop, []),
    loop_d_mfa(I - 1).

%% (e) (a) with {min_heap_size, 1000}
exec_variant_e_min_heap(N) ->
    loop_e(N),
    N.

loop_e(0) -> ok;
loop_e(I) ->
    spawn_opt(fun() -> ok end, [{min_heap_size, 1000}]),
    loop_e(I - 1).

%% (f) exit cost: time from exit(P, kill) to 'DOWN' for 100k blocked processes
exec_variant_f_exit(N) ->
    %% Outside timer: pre-spawn 100k monitored blocked processes
    Procs = setup_monitored_blocked(N, []),
    %% Timed: kill all and collect all DOWN messages
    {TimeUs, ok} = timer:tc(fun() ->
        kill_and_collect_down(Procs)
    end),
    {TimeUs, N}.

setup_monitored_blocked(0, Acc) -> Acc;
setup_monitored_blocked(I, Acc) ->
    {Pid, Ref} = spawn_monitor(fun() -> receive stop -> ok end end),
    setup_monitored_blocked(I - 1, [{Pid, Ref} | Acc]).

kill_and_collect_down(Procs) ->
    lists:foreach(fun({Pid, _Ref}) -> exit(Pid, kill) end, Procs),
    collect_downs(length(Procs)).

collect_downs(0) -> ok;
collect_downs(Remaining) ->
    receive
        {'DOWN', _Ref, process, _Pid, _Reason} ->
            collect_downs(Remaining - 1)
    end.

%% (g) erlang:processes() length after 100k live processes (sanity)
exec_variant_g_processes(N) ->
    %% Outside timer: pre-spawn 100k blocked processes
    Pids = loop_b(N, []),
    %% Timed: call erlang:processes() and measure length
    {TimeUs, Len} = timer:tc(fun() -> length(erlang:processes()) end),
    %% Outside timer: cleanup all processes
    cleanup_pids(Pids),
    if
        Len >= N -> ok;
        true -> erlang:error({insufficient_live_processes, Len, N})
    end,
    {TimeUs, Len}.

%% ====================================================================
%% Execution Harness & Timing
%% ====================================================================

timed_exec(SelfTimedFun, true) ->
    %% Fun manages its own internal timer:tc and cleanup outside timer
    Parent = self(),
    spawn(fun() ->
        {TimeUs, Res} = SelfTimedFun(),
        Parent ! {bench_result, TimeUs, Res}
    end),
    receive
        {bench_result, TimeUs, Res} -> {TimeUs, Res}
    end;
timed_exec(Fun, false) ->
    %% Generic wrapper: timer:tc wraps Fun
    Parent = self(),
    spawn(fun() ->
        {TimeUs, Res} = timer:tc(Fun),
        Parent ! {bench_result, TimeUs, Res}
    end),
    receive
        {bench_result, TimeUs, Res} -> {TimeUs, Res}
    end.

run_single_variant(Fun, IsSelfTimed, N, Warmup, Repeats) ->
    %% Warmup
    run_warmup(Fun, IsSelfTimed, Warmup),
    %% Repeats
    TimesUs = run_repeats(Fun, IsSelfTimed, Repeats, []),
    TimesNs = [T * 1000 || T <- TimesUs],
    NsPerOp = [T / N || T <- TimesNs],
    Sorted = lists:sort(NsPerOp),
    Median = lists:nth((length(Sorted) div 2) + 1, Sorted),
    Min = hd(Sorted),
    Max = lists:last(Sorted),
    {Median, Min, Max, NsPerOp}.

run_warmup(_Fun, _IsSelfTimed, 0) -> ok;
run_warmup(Fun, IsSelfTimed, Count) ->
    _ = timed_exec(Fun, IsSelfTimed),
    run_warmup(Fun, IsSelfTimed, Count - 1).

run_repeats(_Fun, _IsSelfTimed, 0, Acc) ->
    lists:reverse(Acc);
run_repeats(Fun, IsSelfTimed, Count, Acc) ->
    {TimeUs, _} = timed_exec(Fun, IsSelfTimed),
    run_repeats(Fun, IsSelfTimed, Count - 1, [TimeUs | Acc]).

get_variants(N) ->
    [
        {a_spawn_closure,
         "(a) spawn fun() -> ok end (exit immediately)",
         false,
         fun() -> exec_variant_a(N) end},
        {b_spawn_blocked,
         "(b) spawn fun() blocking in receive (spawn only)",
         true,
         fun() -> exec_variant_b(N) end},
        {c1_spawn_link,
         "(c1) spawn_link fun() -> ok end (exit immediately)",
         false,
         fun() -> exec_variant_c_link(N) end},
        {c2_spawn_monitor,
         "(c2) spawn_monitor fun() -> ok end (exit immediately)",
         false,
         fun() -> exec_variant_c_monitor(N) end},
        {d_spawn_mfa,
         "(d) spawn(M, F, A) exported noop (exit immediately)",
         false,
         fun() -> exec_variant_d_mfa(N) end},
        {e_min_heap_1000,
         "(e) spawn_opt with {min_heap_size, 1000}",
         false,
         fun() -> exec_variant_e_min_heap(N) end},
        {f_exit_to_down,
         "(f) exit(P, kill) to DOWN for 100k blocked",
         true,
         fun() -> exec_variant_f_exit(N) end},
        {g_processes_len,
         "(g) erlang:processes() length with 100k live",
         true,
         fun() -> exec_variant_g_processes(N) end}
    ].

run() ->
    run(?DEFAULT_N).

run(N) ->
    run(N, ?DEFAULT_WARMUP, ?DEFAULT_REPEATS).

run(N, Repeats) ->
    run(N, ?DEFAULT_WARMUP, Repeats).

run(N, Warmup, Repeats) ->
    Variants = get_variants(N),
    Results = [
        begin
            {Median, Min, Max, Samples} = run_single_variant(Fun, IsSelfTimed, N, Warmup, Repeats),
            {Id, Desc, Median, Min, Max, Samples}
        end
        || {Id, Desc, IsSelfTimed, Fun} <- Variants
    ],
    {ok, Results}.

run_variant(Id) ->
    run_variant(Id, ?DEFAULT_N).

run_variant(Id, N) ->
    run_variant(Id, N, ?DEFAULT_WARMUP, ?DEFAULT_REPEATS).

run_variant(Id, N, Repeats) ->
    run_variant(Id, N, ?DEFAULT_WARMUP, Repeats).

run_variant(Id, N, Warmup, Repeats) ->
    Variants = get_variants(N),
    case lists:keyfind(Id, 1, Variants) of
        {Id, Desc, IsSelfTimed, Fun} ->
            {Median, Min, Max, Samples} = run_single_variant(Fun, IsSelfTimed, N, Warmup, Repeats),
            {ok, {Id, Desc, Median, Min, Max, Samples}};
        false ->
            {error, {unknown_variant, Id}}
    end.

format_row({Id, Desc, Median, Min, Max, _Samples}) ->
    try io:format("| ~-24w | ~-50s | ~10.1f | ~10.1f..~-10.1f |~n",
                  [Id, Desc, Median, Min, Max])
    catch
        _:_ ->
            erlang:display({row, Id, Desc, Median, Min, Max})
    end.

main() ->
    main([]).

main(N, Warmup, Repeats) ->
    main([N, Warmup, Repeats]).

main(Variant, N, Warmup, Repeats) ->
    main([Variant, N, Warmup, Repeats]).

main(Args) ->
    {Target, N, Warmup, Repeats} = parse_args(Args),
    try
        io:format("Running spawn_breakdown with N=~p, Warmup=~p, Repeats=~p...~n~n", [N, Warmup, Repeats]),
        io:format("| ~-24s | ~-50s | ~10s | ~22s |~n", ["Variant", "Description", "Median ns", "Min..Max ns"]),
        io:format("| ~-24s | ~-50s | ~10s | ~22s |~n", [lists:duplicate(24, "-"), lists:duplicate(50, "-"), lists:duplicate(10, "-"), lists:duplicate(22, "-")])
    catch
        _:_ ->
            erlang:display({running_spawn_breakdown, N, Warmup, Repeats})
    end,
    case Target of
        all ->
            {ok, Results} = run(N, Warmup, Repeats),
            lists:foreach(fun format_row/1, Results);
        VariantId ->
            {ok, Row} = run_variant(VariantId, N, Warmup, Repeats),
            format_row(Row)
    end,
    halt().

to_int(X) when is_integer(X) -> X;
to_int(X) when is_list(X) -> list_to_integer(X).

to_atom(X) when is_atom(X) -> X;
to_atom(X) when is_list(X) -> list_to_atom(X).

parse_args([VariantStr, NStr, WarmupStr, RepeatStr]) ->
    {to_atom(VariantStr), to_int(NStr), to_int(WarmupStr), to_int(RepeatStr)};
parse_args([A1, A2, A3]) ->
    case is_integer(A1) of
        true ->
            {all, A1, to_int(A2), to_int(A3)};
        false ->
            case is_atom(A1) of
                true ->
                    {A1, to_int(A2), ?DEFAULT_WARMUP, to_int(A3)};
                false ->
                    try list_to_integer(A1) of
                        N -> {all, N, to_int(A2), to_int(A3)}
                    catch
                        _:_ -> {to_atom(A1), to_int(A2), ?DEFAULT_WARMUP, to_int(A3)}
                    end
            end
    end;
parse_args([NStr, RepeatStr]) ->
    try to_int(NStr) of
        N -> {all, N, ?DEFAULT_WARMUP, to_int(RepeatStr)}
    catch
        _:_ -> {to_atom(NStr), ?DEFAULT_N, ?DEFAULT_WARMUP, to_int(RepeatStr)}
    end;
parse_args([TargetStr]) ->
    try to_int(TargetStr) of
        N -> {all, N, ?DEFAULT_WARMUP, ?DEFAULT_REPEATS}
    catch
        _:_ -> {to_atom(TargetStr), ?DEFAULT_N, ?DEFAULT_WARMUP, ?DEFAULT_REPEATS}
    end;
parse_args(_) ->
    {all, ?DEFAULT_N, ?DEFAULT_WARMUP, ?DEFAULT_REPEATS}.
