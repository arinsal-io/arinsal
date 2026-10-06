-module(spawn_probe).
-export([main/0, main/1, main/3, run/0, run/1, run/2, run/3]).
-export([variant_a/1, variant_b/1, variant_c/1, variant_d/1,
         variant_e_child/2, variant_e_parent/2]).

%% Default benchmark settings
-define(DEFAULT_N, 100000).
-define(DEFAULT_WARMUP, 1).
-define(DEFAULT_REPEATS, 5).

%% ====================================================================
%% Probe Variants
%% ====================================================================

%% (a) spawn only, no message, processes exit immediately
variant_a(N) ->
    spawn_only_loop(0, N),
    N.

spawn_only_loop(N, N) -> ok;
spawn_only_loop(I, N) ->
    spawn(fun() -> ok end),
    spawn_only_loop(I + 1, N).

%% (b) spawn + message, parent receives each message right after each spawn (no backlog)
variant_b(N) ->
    spawn_recv_loop(0, N, 0).

spawn_recv_loop(N, N, Sum) -> Sum;
spawn_recv_loop(I, N, Sum) ->
    Parent = self(),
    spawn(fun() -> Parent ! 1 end),
    receive 1 -> spawn_recv_loop(I + 1, N, Sum + 1) end.

%% (c) the original backlog variant (spawn 100k sending 1, then receive 100k)
variant_c(N) ->
    Parent = self(),
    spawn_backlog_loop(0, N, Parent),
    spawn_collect_loop(0, N, 0).

spawn_backlog_loop(N, N, _) -> ok;
spawn_backlog_loop(I, N, Parent) ->
    spawn(fun() -> Parent ! 1 end),
    spawn_backlog_loop(I + 1, N, Parent).

spawn_collect_loop(N, N, Sum) -> Sum;
spawn_collect_loop(I, N, Sum) ->
    receive 1 -> spawn_collect_loop(I + 1, N, Sum + 1) end.

%% (d) (c) with process_flag(message_queue_data, off_heap) on the parent
variant_d(N) ->
    process_flag(message_queue_data, off_heap),
    variant_c(N).

%% (e) spawn_opt with {min_heap_size, Words}
%% (e1) Child processes spawned with min_heap_size
variant_e_child(N, MinHeap) ->
    Parent = self(),
    spawn_opt_loop(0, N, Parent, [{min_heap_size, MinHeap}]),
    spawn_collect_loop(0, N, 0).

spawn_opt_loop(N, N, _, _) -> ok;
spawn_opt_loop(I, N, Parent, Opts) ->
    spawn_opt(fun() -> Parent ! 1 end, Opts),
    spawn_opt_loop(I + 1, N, Parent, Opts).

%% (e2) Parent process running backlog variant with initial min_heap_size
variant_e_parent(N, MinHeap) ->
    Parent = self(),
    spawn_opt(fun() ->
        P = self(),
        {TimeUs, Res} = timer:tc(fun() ->
            spawn_backlog_loop(0, N, P),
            spawn_collect_loop(0, N, 0)
        end),
        Parent ! {bench_result, TimeUs, Res}
    end, [{min_heap_size, MinHeap}]),
    receive
        {bench_result, TimeUs, Res} -> {TimeUs, Res}
    end.

%% ====================================================================
%% Probe Execution & Statistics
%% ====================================================================

timed_exec(Fun) ->
    Parent = self(),
    spawn(fun() ->
        {TimeUs, Res} = timer:tc(Fun),
        Parent ! {bench_result, TimeUs, Res}
    end),
    receive
        {bench_result, TimeUs, Res} -> {TimeUs, Res}
    end.

run_single_variant(Fun, N, Warmup, Repeats) ->
    %% Warmup
    run_warmup(Fun, Warmup),
    %% Repeats
    TimesUs = run_repeats(Fun, Repeats, []),
    TimesNs = [T * 1000 || T <- TimesUs],
    NsPerOp = [T / N || T <- TimesNs],
    Sorted = lists:sort(NsPerOp),
    Median = lists:nth((length(Sorted) div 2) + 1, Sorted),
    Min = hd(Sorted),
    Max = lists:last(Sorted),
    {Median, Min, Max, NsPerOp}.

run_warmup(_Fun, 0) -> ok;
run_warmup(Fun, Count) ->
    _ = timed_exec(Fun),
    run_warmup(Fun, Count - 1).

run_repeats(_Fun, 0, Acc) ->
    lists:reverse(Acc);
run_repeats(Fun, Count, Acc) ->
    {TimeUs, _} = timed_exec(Fun),
    run_repeats(Fun, Count - 1, [TimeUs | Acc]).

get_variants(N) ->
    [
        {a_spawn_only,
         "spawn only, no message, exit immediately",
         fun() -> variant_a(N) end},
        {b_spawn_recv_nobacklog,
         "spawn + message, recv immediately (no backlog)",
         fun() -> variant_b(N) end},
        {c_backlog_on_heap,
         "original backlog (spawn 100k, then recv 100k)",
         fun() -> variant_c(N) end},
        {d_backlog_off_heap,
         "c with process_flag(message_queue_data, off_heap)",
         fun() -> variant_d(N) end},
        {e_child_min_heap_233,
         "spawn_opt child {min_heap_size, 233}",
         fun() -> variant_e_child(N, 233) end},
        {e_child_min_heap_1024,
         "spawn_opt child {min_heap_size, 1024}",
         fun() -> variant_e_child(N, 1024) end},
        {e_parent_min_heap_233,
         "spawn_opt parent {min_heap_size, 233}",
         fun() -> {_, Res} = variant_e_parent(N, 233), Res end},
        {e_parent_min_heap_large,
         "spawn_opt parent {min_heap_size, 262144}",
         fun() -> {_, Res} = variant_e_parent(N, 262144), Res end}
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
            {Median, Min, Max, Samples} = run_single_variant(Fun, N, Warmup, Repeats),
            {Id, Desc, Median, Min, Max, Samples}
        end
        || {Id, Desc, Fun} <- Variants
    ],
    {ok, Results}.

format_row({Id, Desc, Median, Min, Max, _Samples}) ->
    try io:format("| ~-24w | ~-48s | ~10.1f | ~10.1f..~-10.1f |~n",
                  [Id, Desc, Median, Min, Max])
    catch
        _:_ ->
            erlang:display({row, Id, Desc, Median, Min, Max})
    end.

main() ->
    main([]).

main(N, Warmup, Repeats) ->
    main([N, Warmup, Repeats]).

main(Args) ->
    {N, Warmup, Repeats} = parse_args(Args),
    try
        io:format("Running spawn_probe with N=~p, Warmup=~p, Repeats=~p...~n~n", [N, Warmup, Repeats]),
        io:format("| ~-24s | ~-48s | ~10s | ~22s |~n", ["Variant", "Description", "Median ns", "Min..Max ns"]),
        io:format("| ~-24s | ~-48s | ~10s | ~22s |~n", [lists:duplicate(24, "-"), lists:duplicate(48, "-"), lists:duplicate(10, "-"), lists:duplicate(22, "-")])
    catch
        _:_ ->
            erlang:display({running_spawn_probe, N, Warmup, Repeats})
    end,
    {ok, Results} = run(N, Warmup, Repeats),
    lists:foreach(fun format_row/1, Results),
    halt().

to_int(X) when is_integer(X) -> X;
to_int(X) when is_list(X) -> list_to_integer(X).

parse_args([NStr, WarmupStr, RepeatStr]) ->
    {to_int(NStr), to_int(WarmupStr), to_int(RepeatStr)};
parse_args([NStr, RepeatStr]) ->
    {to_int(NStr), ?DEFAULT_WARMUP, to_int(RepeatStr)};
parse_args([NStr]) ->
    {to_int(NStr), ?DEFAULT_WARMUP, ?DEFAULT_REPEATS};
parse_args(_) ->
    {?DEFAULT_N, ?DEFAULT_WARMUP, ?DEFAULT_REPEATS}.
