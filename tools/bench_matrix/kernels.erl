-module(kernels).
-behaviour(gen_server).
-export([run_bench/3, main/1]).
-export([int_loop_sum/0, fib_27/0, list_100k/0, tuple_loop/0, binary_scan/1,
         map_put_get/0, ets_insert_lookup/0, spawn_exit/0, spawn_exit_recv/0, ping_pong/0, fan_in/0,
         float_math/0, closure_calls/1, binary_build/0, record_update/0,
         string_atom_string/1, sort_100k/1, gen_server_call/0]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).

int_loop_sum() ->
    int_loop(10000000, 0).
int_loop(0, Sum) -> Sum;
int_loop(I, Sum) -> int_loop(I - 1, Sum + I).

fib(N) when N < 2 -> N;
fib(N) -> fib(N - 1) + fib(N - 2).

fib_27() ->
    fib(27).

list_100k() ->
    List = lists:seq(1, 100000),
    Mapped = lists:map(fun(X) -> X + 1 end, List),
    lists:foldl(fun(X, Acc) -> Acc + X end, 0, Mapped).

tuple_loop() ->
    tuple_loop(100000, {0, 0, 0}, 0).
tuple_loop(0, _Tuple, Sum) -> Sum;
tuple_loop(I, Tuple, Sum) ->
    Next = setelement(2, Tuple, I),
    tuple_loop(I - 1, Next, Sum + element(2, Next)).

binary_scan(Bin) ->
    binary_scan_loop(Bin, 0).
binary_scan_loop(<<>>, Count) -> Count;
binary_scan_loop(<<2, Rest/binary>>, Count) -> binary_scan_loop(Rest, Count + 1);
binary_scan_loop(<<_, Rest/binary>>, Count) -> binary_scan_loop(Rest, Count).

map_put_get() ->
    M = map_put_loop(0, 100000, #{}),
    map_get_loop(0, 100000, M, 0).
map_put_loop(N, N, M) -> M;
map_put_loop(I, N, M) -> map_put_loop(I + 1, N, maps:put(I, I + 1, M)).
map_get_loop(N, N, _M, Sum) -> Sum;
map_get_loop(I, N, M, Sum) -> map_get_loop(I + 1, N, M, Sum + maps:get(I, M)).

ets_insert_lookup() ->
    T = ets:new(bench_tab, [set, public]),
    ets_insert_loop(0, 100000, T),
    Sum = ets_lookup_loop(0, 100000, T, 0),
    ets:delete(T),
    Sum.
ets_insert_loop(N, N, _) -> ok;
ets_insert_loop(I, N, T) ->
    ets:insert(T, {I, I + 1}),
    ets_insert_loop(I + 1, N, T).
ets_lookup_loop(N, N, _, Sum) -> Sum;
ets_lookup_loop(I, N, T, Sum) ->
    [{I, Val}] = ets:lookup(T, I),
    ets_lookup_loop(I + 1, N, T, Sum + Val).

spawn_exit() ->
    Parent = self(),
    spawn_loop(0, 100000, Parent),
    spawn_collect(0, 100000, 0).
spawn_loop(N, N, _) -> ok;
spawn_loop(I, N, Parent) ->
    spawn(fun() -> Parent ! 1 end),
    spawn_loop(I + 1, N, Parent).
spawn_collect(N, N, Sum) -> Sum;
spawn_collect(I, N, Sum) ->
    receive 1 -> spawn_collect(I + 1, N, Sum + 1) end.

spawn_exit_recv() ->
    Parent = self(),
    spawn_exit_recv_loop(0, 100000, Parent, 0).
spawn_exit_recv_loop(N, N, _, Sum) -> Sum;
spawn_exit_recv_loop(I, N, Parent, Sum) ->
    spawn(fun() -> Parent ! 1 end),
    receive 1 -> spawn_exit_recv_loop(I + 1, N, Parent, Sum + 1) end.

ping_pong() ->
    Parent = self(),
    Peer = spawn(fun() -> ping_peer(Parent) end),
    ping_loop(Peer, 1000000),
    Peer ! stop,
    1000000.
ping_peer(Parent) ->
    receive
        ping -> Parent ! pong, ping_peer(Parent);
        stop -> ok
    end.
ping_loop(_, 0) -> ok;
ping_loop(Peer, N) ->
    Peer ! ping,
    receive pong -> ok end,
    ping_loop(Peer, N - 1).

fan_in() ->
    Parent = self(),
    Producers = 8,
    PerProd = 125000,
    Total = Producers * PerProd,
    [spawn(fun() -> fanin_prod(Parent, PerProd) end) || _ <- lists:seq(1, Producers)],
    fanin_consume(Total, 0).
fanin_prod(_, 0) -> ok;
fanin_prod(Parent, N) ->
    Parent ! 1,
    fanin_prod(Parent, N - 1).
fanin_consume(0, Sum) -> Sum;
fanin_consume(N, Sum) ->
    receive 1 -> fanin_consume(N - 1, Sum + 1) end.

float_math() ->
    float_math_loop(1000000, 0.0).
float_math_loop(0, X) ->
    trunc(X);
float_math_loop(N, X) ->
    float_math_loop(N - 1, X * 1.0000001 + 0.5).

closure_calls(List) ->
    K = 10,
    F = fun(X, Acc) -> Acc + X + K end,
    lists:foldl(F, 0, List).

binary_build() ->
    binary_build_loop(1048576, <<>>).
binary_build_loop(0, Acc) ->
    byte_size(Acc);
binary_build_loop(N, Acc) ->
    B = N rem 256,
    binary_build_loop(N - 1, <<Acc/binary, B>>).

record_update() ->
    record_update_loop(1000000, {rec5, 0, 0, 0, 0, 0}, 0).
record_update_loop(0, _Rec, Sum) ->
    Sum;
record_update_loop(I, Rec, Sum) ->
    Next = setelement(4, Rec, I),
    record_update_loop(I - 1, Next, Sum + element(4, Next)).

string_atom_string(List100k) ->
    string_atom_loop(List100k, 0).
string_atom_loop([], Sum) ->
    Sum;
string_atom_loop([S | Rest], Sum) ->
    A = list_to_atom(S),
    L = atom_to_list(A),
    string_atom_loop(Rest, Sum + length(L)).

sort_100k(List) ->
    Sorted = lists:sort(List),
    hd(Sorted) + lists:nth(50000, Sorted) + lists:last(Sorted).

gen_server_call() ->
    {ok, Pid} = gen_server:start_link(?MODULE, [], []),
    Res = gen_server_loop(Pid, 100000, 0),
    gen_server:stop(Pid),
    Res.

gen_server_loop(_Pid, 0, Last) ->
    Last;
gen_server_loop(Pid, N, _Last) ->
    Res = gen_server:call(Pid, ping),
    gen_server_loop(Pid, N - 1, Res).

%% gen_server callbacks
init([]) ->
    {ok, 0}.
handle_call(ping, _From, Count) ->
    {reply, Count + 1, Count + 1};
handle_call(_Req, _From, State) ->
    {reply, ok, State}.
handle_cast(_Msg, State) ->
    {noreply, State}.
handle_info(_Info, State) ->
    {noreply, State}.
terminate(_Reason, _State) ->
    ok.
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

expected_checksum(Kernel) ->
    case expected_checksum_1(Kernel) of
        not_found -> expected_checksum_2(Kernel);
        Val -> Val
    end.

expected_checksum_1(int_loop_sum)       -> 50000005000000;
expected_checksum_1(fib_27)             -> 196418;
expected_checksum_1(list_100k)          -> 5000150000;
expected_checksum_1(tuple_loop)         -> 5000050000;
expected_checksum_1(binary_scan)        -> 262144;
expected_checksum_1(map_put_get)        -> 5000050000;
expected_checksum_1(ets_insert_lookup)  -> 5000050000;
expected_checksum_1(ping_pong)          -> 1000000;
expected_checksum_1(_)                  -> not_found.

expected_checksum_2(fan_in)             -> 1000000;
expected_checksum_2(float_math)         -> 525854;
expected_checksum_2(closure_calls)      -> 500010500000;
expected_checksum_2(binary_build)       -> 1048576;
expected_checksum_2(record_update)      -> 500000500000;
expected_checksum_2(string_atom_string) -> 789000;
expected_checksum_2(sort_100k)          -> 3227487306;
expected_checksum_2(gen_server_call)    -> 100000;
expected_checksum_2(Other)              -> expected_checksum_spawn(Other).

expected_checksum_spawn(spawn_exit)      -> 100000;
expected_checksum_spawn(spawn_exit_recv) -> 100000.

prepare_fun(Kernel) ->
    case prepare_fun_1(Kernel) of
        not_found -> prepare_fun_2(Kernel);
        Fun -> Fun
    end.

prepare_fun_1(binary_scan) ->
    Bin = binary:copy(<<1, 2, 3, 4>>, 262144),
    fun() -> binary_scan(Bin) end;
prepare_fun_1(int_loop_sum)      -> fun() -> int_loop_sum() end;
prepare_fun_1(fib_27)            -> fun() -> fib_27() end;
prepare_fun_1(list_100k)         -> fun() -> list_100k() end;
prepare_fun_1(tuple_loop)        -> fun() -> tuple_loop() end;
prepare_fun_1(map_put_get)       -> fun() -> map_put_get() end;
prepare_fun_1(ets_insert_lookup) -> fun() -> ets_insert_lookup() end;
prepare_fun_1(ping_pong)         -> fun() -> ping_pong() end;
prepare_fun_1(_)                 -> not_found.

prepare_fun_2(fan_in)            -> fun() -> fan_in() end;
prepare_fun_2(float_math)        -> fun() -> float_math() end;
prepare_fun_2(closure_calls) ->
    List = lists:seq(1, 1000000),
    fun() -> closure_calls(List) end;
prepare_fun_2(binary_build) ->
    fun() -> binary_build() end;
prepare_fun_2(record_update) ->
    fun() -> record_update() end;
prepare_fun_2(string_atom_string) ->
    Pool = ["atom_" ++ integer_to_list(I) || I <- lists:seq(0, 999)],
    _ = [list_to_atom(S) || S <- Pool],
    List100k = lists:append(lists:duplicate(100, Pool)),
    fun() -> string_atom_string(List100k) end;
prepare_fun_2(sort_100k) ->
    Seq = lists:seq(1, 100000),
    List = lists:map(fun(I) -> (I * 1664525 + 1013904223) band 16#7FFFFFFF end, Seq),
    fun() -> sort_100k(List) end;
prepare_fun_2(gen_server_call) ->
    fun() -> gen_server_call() end;
prepare_fun_2(Other)             -> prepare_fun_spawn(Other).

prepare_fun_spawn(spawn_exit)      -> fun() -> spawn_exit() end;
prepare_fun_spawn(spawn_exit_recv) -> fun() -> spawn_exit_recv() end.

timed_exec(Fun) ->
    Parent = self(),
    {Pid, Mref} = spawn_monitor(fun() ->
        {TimeUs, Res} = timer:tc(Fun),
        Parent ! {bench_result, TimeUs, Res}
    end),
    receive
        {bench_result, TimeUs, Res} ->
            demonitor(Mref, [flush]),
            {TimeUs, Res};
        {'DOWN', Mref, process, Pid, Reason} ->
            erlang:error({bench_worker_died, Reason})
    end.

run_bench(KernelName, WarmupCount, RepeatCount) ->
    Expected = expected_checksum(KernelName),
    Fun = prepare_fun(KernelName),
    run_warmup(Fun, Expected, WarmupCount),
    {LastRes, TimesNs} = run_repeats(Fun, Expected, RepeatCount, []),
    {ok, LastRes, lists:reverse(TimesNs)}.

run_warmup(_Fun, _Expected, 0) -> ok;
run_warmup(Fun, Expected, Count) ->
    {_TimeUs, Res} = timed_exec(Fun),
    if
        Res =/= Expected -> erlang:error({mismatch, Res, Expected});
        true -> run_warmup(Fun, Expected, Count - 1)
    end.

run_repeats(_Fun, _Expected, 0, Acc) ->
    {0, Acc};
run_repeats(Fun, Expected, Count, Acc) ->
    {TimeUs, Res} = timed_exec(Fun),
    if
        Res =/= Expected -> erlang:error({mismatch, Res, Expected});
        true -> ok
    end,
    run_repeats_step(Fun, Expected, Count - 1, Res, [TimeUs * 1000 | Acc]).

run_repeats_step(_Fun, _Expected, 0, LastRes, Acc) ->
    {LastRes, Acc};
run_repeats_step(Fun, Expected, Count, _LastRes, Acc) ->
    {TimeUs, Res} = timed_exec(Fun),
    if
        Res =/= Expected -> erlang:error({mismatch, Res, Expected});
        true -> ok
    end,
    run_repeats_step(Fun, Expected, Count - 1, Res, [TimeUs * 1000 | Acc]).

main([KernelNameStr, WarmupStr, RepeatStr]) ->
    KernelName = list_to_atom(KernelNameStr),
    Warmup = list_to_integer(WarmupStr),
    Repeats = list_to_integer(RepeatStr),
    Res = run_bench(KernelName, Warmup, Repeats),
    io:format("~w~n", [Res]),
    halt().
