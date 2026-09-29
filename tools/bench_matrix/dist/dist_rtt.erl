-module(dist_rtt).
-export([run/1, server/0, id/1, payload/1]).

-define(COUNT, 5000).

id(X) -> X.

run([NodePrefix]) ->
    [_, Host] = string:split(atom_to_list(node()), "@"),
    Node = list_to_atom(NodePrefix ++ "@" ++ Host),
    %% Ensure the distribution channel is up before the first erpc:call.
    pong = net_adm:ping(Node),
    %% start server on remote node
    Pid = erpc:call(Node, erlang, spawn, [?MODULE, server, []]),
    erpc:call(Node, erlang, register, [dist_rtt_server, Pid]),
    AllPayloads = [small_atom, tuple_self, bin_1k, bin_64k, map_100, list_1000, nested_tuple_20],
    Payloads = case os:getenv("DIST_RTT_PAYLOADS") of
        false -> AllPayloads;
        Filter -> [list_to_atom(Filter)]
    end,
    Modes = [pid, name, erpc],
    
    %% Warmup
    io:format("Warming up...~n"),
    [bench_all(Node, Pid, Payload, Mode, 1000) || Payload <- Payloads, Mode <- Modes],
    
    io:format("Running benchmarks...~n"),
    Results = [ {Payload, Mode, run_5x(Node, Pid, Payload, Mode)} || Payload <- Payloads, Mode <- Modes ],
    
    %% Print results
    io:format("~n~-15s | ~-4s | ~10s | ~10s | ~10s | ~10s~n", 
              ["Payload", "Mode", "RTT Med", "RTT p99", "Tp 1", "Tp 16"]),
    io:format("~70c~n", [$-]),
    lists:foreach(fun({Payload, Mode, {MedR, P99R, Tp1, Tp16}}) ->
        io:format("~-15w | ~-4w | ~10w | ~10w | ~10w | ~10w~n", 
                  [Payload, Mode, MedR, P99R, round(Tp1), round(Tp16)])
    end, Results),
    
    erpc:cast(Node, init, stop, []),
    init:stop().

run_5x(Node, Pid, Payload, Mode) ->
    Runs = [bench_all(Node, Pid, Payload, Mode, 2000) || _ <- lists:seq(1, 5)],
    [Meds, P99s, Tp1s, Tp16s] = [lists:sort([element(I, R) || R <- Runs]) || I <- lists:seq(1, 4)],
    {lists:nth(3, Meds), lists:nth(3, P99s), lists:nth(3, Tp1s), lists:nth(3, Tp16s)}.

bench_all(Node, Pid, PayloadName, Mode, Count) ->
    Payload = payload(PayloadName),
    {Med, P99} = measure_rtt(Node, Pid, Payload, Mode, Count),
    Tp1 = measure_throughput(Node, Pid, Payload, Mode, 1, Count),
    Tp16 = measure_throughput(Node, Pid, Payload, Mode, 16, Count),
    {Med, P99, Tp1, Tp16}.

measure_rtt(Node, Pid, Payload, Mode, Count) ->
    Worker = fun() ->
        Times = [ping_pong(Node, Pid, Payload, Mode) || _ <- lists:seq(1, Count)],
        Sorted = lists:sort(Times),
        Med = lists:nth(Count div 2, Sorted),
        P99 = lists:nth(Count * 99 div 100, Sorted),
        {Med, P99}
    end,
    {_, Res} = timer:tc(Worker),
    Res.

measure_throughput(Node, Pid, Payload, Mode, InFlight, Count) ->
    PerWorker = Count div InFlight,
    ActualCount = PerWorker * InFlight,
    Parent = self(),
    T0 = erlang:system_time(microsecond),
    Workers = [spawn_link(fun() ->
        [ping_pong(Node, Pid, Payload, Mode) || _ <- lists:seq(1, PerWorker)],
        Parent ! {done, self()}
    end) || _ <- lists:seq(1, InFlight)],
    [receive {done, W} -> ok end || W <- Workers],
    T1 = erlang:system_time(microsecond),
    ActualCount * 1000000 / max(1, T1 - T0).

ping_pong(_Node, Pid, Payload, pid) ->
    Ref = make_ref(),
    T0 = erlang:system_time(microsecond),
    Pid ! {ping, self(), Ref, Payload},
    receive {pong, Ref, _} -> ok end,
    erlang:system_time(microsecond) - T0;
ping_pong(Node, _Pid, Payload, name) ->
    Ref = make_ref(),
    T0 = erlang:system_time(microsecond),
    {dist_rtt_server, Node} ! {ping, self(), Ref, Payload},
    receive {pong, Ref, _} -> ok end,
    erlang:system_time(microsecond) - T0;
ping_pong(Node, _Pid, Payload, erpc) ->
    T0 = erlang:system_time(microsecond),
    Payload = erpc:call(Node, ?MODULE, id, [Payload]),
    erlang:system_time(microsecond) - T0.

payload(small_atom) -> a;
payload(tuple_self) -> {self(), 42, <<"hi">>};
payload(bin_1k) -> <<0:8192>>;
payload(bin_64k) -> <<0:(65536*8)>>;
payload(map_100) -> maps:from_list([{I, I} || I <- lists:seq(1, 100)]);
payload(list_1000) -> lists:seq(1, 1000);
payload(nested_tuple_20) -> deep_tuple(20).

deep_tuple(0) -> a;
deep_tuple(N) -> {deep_tuple(N-1)}.

server() ->
    receive
        {ping, From, Ref, Msg} ->
            From ! {pong, Ref, Msg},
            server();
        stop ->
            ok
    end.
