-module(bench).
-export([main/1, fib/1, trees/1, nbody/1, idle/1, tasks/1,
         ring/2, pingpong/1, bigmsg/1, map_update/1, map_update_small/1,
         binary_parse/1, ets/1, fanin/1, fanout/1, forward/1, broadcast/1]).

fib(N) when N < 2 -> N;
fib(N) -> fib(N - 1) + fib(N - 2).

mk(0) -> nil;
mk(D) -> {mk(D - 1), mk(D - 1)}.
check(nil) -> 1;
check({L, R}) -> 1 + check(L) + check(R).
trees(Max) -> lists:sum([tree_loop(1 bsl (Max - D + 4), D, 0) || D <- lists:seq(4, Max, 2)]).
tree_loop(0, _, Sum) -> Sum;
tree_loop(I, D, Sum) -> tree_loop(I - 1, D, Sum + check(mk(D))).

nbody(N) ->
    Bodies = [{0.0,0.0,0.0,0.0,0.0,0.0,39.47},
              {4.84,-1.16,-0.10,0.60,2.81,-0.02,0.037},
              {8.34,4.12,-0.4,-1.01,1.82,0.008,0.011},
              {12.89,-15.11,-0.22,1.08,0.86,-0.01,0.0017},
              {15.37,-25.9,0.17,0.97,0.59,-0.03,0.002}],
    element(1, hd(steps(N, Bodies))).
steps(0, Bodies) -> Bodies;
steps(N, Bodies) -> steps(N - 1, [move(X) || X <- advance(Bodies)]).
move({X,Y,Z,VX,VY,VZ,M}) -> {X+0.01*VX,Y+0.01*VY,Z+0.01*VZ,VX,VY,VZ,M}.
advance([]) -> [];
advance([Head|Tail]) ->
    {NewHead, NewTail} = pair(Head, Tail, []),
    [NewHead | advance(NewTail)].
pair(Head, [], Acc) -> {Head, lists:reverse(Acc)};
pair({X1,Y1,Z1,VX1,VY1,VZ1,M1}, [{X2,Y2,Z2,VX2,VY2,VZ2,M2}|Tail], Acc) ->
    DX=X1-X2, DY=Y1-Y2, DZ=Z1-Z2, D2=DX*DX+DY*DY+DZ*DZ,
    Mag=0.01/(D2*math:sqrt(D2)),
    pair({X1,Y1,Z1,VX1-DX*M2*Mag,VY1-DY*M2*Mag,VZ1-DZ*M2*Mag,M1}, Tail,
         [{X2,Y2,Z2,VX2+DX*M1*Mag,VY2+DY*M1*Mag,VZ2+DZ*M1*Mag,M2}|Acc]).

idle(_) -> 0.
tasks(N) ->
    Pids = [spawn(fun() -> receive go -> ok end end) || _ <- lists:seq(1, N)],
    lists:foreach(fun(Pid) -> Pid ! go end, Pids),
    N.

ring(N, M) when N > 0 ->
    Parent = self(),
    Pids = [spawn(fun() -> ring_worker(Parent) end) || _ <- lists:seq(1, N)],
    Next = tl(Pids) ++ [hd(Pids)],
    lists:foreach(fun({Pid, Following}) -> Pid ! {next, Following} end, lists:zip(Pids, Next)),
    hd(Pids) ! {token, M},
    receive {ring_done, _} -> ok end,
    lists:foreach(fun(Pid) -> Pid ! stop end, Pids),
    M.
ring_worker(Parent) ->
    receive {next, Next} -> ring_loop(Parent, Next) end.
ring_loop(Parent, Next) ->
    receive
        {token, 0} -> Parent ! {ring_done, 0}, ring_loop(Parent, Next);
        {token, Remaining} ->
            case Remaining of
                1 -> Parent ! {ring_done, Remaining};
                _ -> Next ! {token, Remaining - 1}
            end,
            ring_loop(Parent, Next);
        stop -> ok
    end.

pingpong(N) ->
    Parent = self(),
    Peer = spawn(fun() -> ping_peer(Parent) end),
    ping_loop(Peer, N),
    Peer ! stop,
    N.
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

bigmsg(N) ->
    Parent = self(),
    Peer = spawn(fun() -> big_peer(Parent) end),
    Binary = binary:copy(<<7>>, 1048576),
    List = lists:duplicate(65536, 7),
    big_loop(Peer, Binary, List, N),
    Peer ! stop,
    N * (1048576 + 458752).
big_peer(Parent) ->
    receive
        {data, Payload} -> Parent ! {ack, size_of(Payload)}, big_peer(Parent);
        stop -> ok
    end.
size_of(Payload) when is_binary(Payload) -> byte_size(Payload);
size_of(Payload) -> lists:sum(Payload).
big_loop(_, _, _, 0) -> ok;
big_loop(Peer, Binary, List, N) ->
    Peer ! {data, Binary},
    receive {ack, 1048576} -> ok end,
    Peer ! {data, List},
    receive {ack, 458752} -> ok end,
    big_loop(Peer, Binary, List, N - 1).

map_update(N) -> map_update(N, 1000).
map_update_small(N) -> map_update(N, 32).
map_update(N, Size) ->
    Map = maps:from_list([{K, 0} || K <- lists:seq(0, Size - 1)]),
    Final = map_loop(0, N, Size, Map),
    maps:size(Final) + maps:get((N - 1) rem Size, Final).
map_loop(N, N, _, Map) -> Map;
map_loop(I, N, Size, Map) -> map_loop(I + 1, N, Size, maps:put(I rem Size, I + 1, Map)).

binary_parse(Megabytes) ->
    Payload = <<7, (binary:copy(<<0>>, 1022))/binary, 9>>,
    Frame = <<1024:32/big, Payload/binary>>,
    Stream = binary:copy(Frame, Megabytes * 1024),
    parse_frames(Stream, 0).
parse_frames(<<>>, Sum) -> Sum;
parse_frames(<<Len:32/big, Payload:Len/binary, Rest/binary>>, Sum) ->
    parse_frames(Rest, Sum + Len + lists:sum(binary:bin_to_list(Payload))).

ets(N) ->
    Table = ets:new(bench_table, [set, public, {read_concurrency, true}, {write_concurrency, true}]),
    ets:insert(Table, [{K, 0} || K <- lists:seq(0, 999)]),
    Parent = self(),
    [spawn(fun() -> ets_worker(Table, Parent, Worker, N div 4) end) || Worker <- lists:seq(0, 3)],
    Sum = collect(4, 0),
    ets:delete(Table),
    Sum.
ets_worker(Table, Parent, Worker, Count) ->
    Sum = ets_loop(Table, Worker, 0, Count, 0),
    Parent ! {done, Sum}.
ets_loop(_, _, Count, Count, Sum) -> Sum;
ets_loop(Table, Worker, I, Count, Sum) ->
    Key = (I * 4 + Worker) rem 1000,
    case I rem 4 of
        0 -> ets:insert(Table, {Key, I}), ets_loop(Table, Worker, I + 1, Count, Sum + 1);
        _ -> [{Key, _}] = ets:lookup(Table, Key), ets_loop(Table, Worker, I + 1, Count, Sum + 1)
    end.
collect(0, Sum) -> Sum;
collect(N, Sum) -> receive {done, Value} -> collect(N - 1, Sum + Value) end.

fanin(N) ->
    Parent = self(),
    [spawn(fun() -> producer(Parent, N div 1000) end) || _ <- lists:seq(1, 1000)],
    consume(N, 0).
producer(_, 0) -> ok;
producer(Parent, N) -> Parent ! one, producer(Parent, N - 1).
consume(0, Sum) -> Sum;
consume(N, Sum) -> receive one -> consume(N - 1, Sum + 1) end.

fanout(N) ->
    Parent = self(),
    Pids = [spawn(fun() -> fanout_worker(Parent, N div 1000) end) || _ <- lists:seq(1, 1000)],
    [Pid ! one || _ <- lists:seq(1, N div 1000), Pid <- Pids],
    collect(1000, 0).
fanout_worker(Parent, N) -> Parent ! {done, consume(N, 0)}.

%% forward N: a ~0.5 MB list travels through a chain of 10 processes N times.
%% Each hop is a send of the same term (erts copies it at every hop).
forward(N) ->
    Parent = self(),
    List = lists:duplicate(65536, 7),
    Last = spawn(fun() -> forward_last(Parent) end),
    First = lists:foldl(fun(_, Next) -> spawn(fun() -> forward_hop(Next) end) end,
                        Last, lists:seq(1, 9)),
    forward_loop(First, List, N),
    First ! stop,
    N * 458752.
forward_hop(Next) ->
    receive
        stop -> Next ! stop;
        {data, Payload} -> Next ! {data, Payload}, forward_hop(Next)
    end.
forward_last(Parent) ->
    receive
        stop -> ok;
        {data, Payload} -> Parent ! {ack, lists:sum(Payload)}, forward_last(Parent)
    end.
forward_loop(_, _, 0) -> ok;
forward_loop(First, List, N) ->
    First ! {data, List},
    receive {ack, 458752} -> ok end,
    forward_loop(First, List, N - 1).

%% broadcast N: the same ~0.5 MB list is sent to 1000 receivers, N rounds.
%% Receivers ack with the head only, so the benchmark measures message cost.
broadcast(N) ->
    Parent = self(),
    List = lists:duplicate(65536, 7),
    Receivers = [spawn(fun() -> broadcast_receiver(Parent) end) || _ <- lists:seq(1, 1000)],
    broadcast_loop(Receivers, List, N),
    [R ! stop || R <- Receivers],
    N * 1000 * 7.
broadcast_receiver(Parent) ->
    receive
        stop -> ok;
        {data, [Head | _]} -> Parent ! {ack, Head}, broadcast_receiver(Parent)
    end.
broadcast_loop(_, _, 0) -> ok;
broadcast_loop(Receivers, List, N) ->
    [R ! {data, List} || R <- Receivers],
    broadcast_collect(length(Receivers)),
    broadcast_loop(Receivers, List, N - 1).
broadcast_collect(0) -> ok;
broadcast_collect(K) -> receive {ack, 7} -> broadcast_collect(K - 1) end.

main([Name | Args]) ->
    Values = [list_to_integer(Arg) || Arg <- Args],
    Start = erlang:monotonic_time(microsecond),
    Result = apply(?MODULE, list_to_atom(Name), Values),
    Elapsed = (erlang:monotonic_time(microsecond) - Start) / 1000,
    io:format("~p~n~s ~.3fms~n", [Result, Name, Elapsed]),
    halt().
