-module(sock_race).
-export([accept/1, recvfrom/1, recv/1, send/1, connect/1]).

lo() -> #{family => inet, addr => {127,0,0,1}, port => 0}.

jitter() -> lists:foreach(fun(_) -> ok end, lists:seq(1, rand:uniform(1500))).

pair() ->
    {ok, L} = socket:open(inet, stream, tcp, #{use_registry => false}),
    ok = socket:bind(L, lo()),
    ok = socket:listen(L),
    {ok, #{port := P}} = socket:sockname(L),
    {ok, C} = socket:open(inet, stream, tcp, #{use_registry => false}),
    ok = socket:connect(C, #{family => inet, addr => {127,0,0,1}, port => P}),
    {ok, A} = socket:accept(L, 5000),
    ok = socket:close(L),
    {C, A}.

race(Work, Close) ->
    {W, WR} = spawn_monitor(fun() -> receive go -> ok end, jitter(), Work() end),
    {K, KR} = spawn_monitor(fun() -> receive go -> ok end, jitter(), Close() end),
    W ! go,
    K ! go,
    receive {'DOWN', WR, _, W, _} -> ok after 20000 -> exit(worker_hang) end,
    receive {'DOWN', KR, _, K, _} -> ok after 20000 -> exit(closer_hang) end.

accept(N) ->
    lists:foreach(fun(_) ->
        {ok, L} = socket:open(inet, stream, tcp, #{use_registry => false}),
        ok = socket:bind(L, lo()),
        ok = socket:listen(L),
        race(fun() -> _ = socket:accept(L, nowait) end,
             fun() -> _ = socket:close(L) end)
    end, lists:seq(1, N)).

recvfrom(N) ->
    lists:foreach(fun(_) ->
        {ok, S} = socket:open(inet, dgram, udp, #{use_registry => false}),
        ok = socket:bind(S, lo()),
        race(fun() -> _ = socket:recvfrom(S, 0, nowait) end,
             fun() -> _ = socket:close(S) end)
    end, lists:seq(1, N)).

recv(N) ->
    lists:foreach(fun(_) ->
        {C, A} = pair(),
        race(fun() -> _ = socket:recv(A, 0, nowait) end,
             fun() -> _ = socket:close(A) end),
        ok = socket:close(C)
    end, lists:seq(1, N)).

send(N) ->
    Big = binary:copy(<<0>>, 8000000),
    lists:foreach(fun(_) ->
        {C, A} = pair(),
        race(fun() -> _ = socket:send(C, Big, nowait) end,
             fun() -> _ = socket:close(C) end),
        ok = socket:close(A)
    end, lists:seq(1, N)).

connect(N) ->
    {ok, L} = socket:open(inet, stream, tcp, #{use_registry => false}),
    ok = socket:bind(L, lo()),
    ok = socket:listen(L),
    {ok, #{port := P}} = socket:sockname(L),
    lists:foreach(fun(_) ->
        {ok, C} = socket:open(inet, stream, tcp, #{use_registry => false}),
        race(fun() ->
                     _ = socket:connect(C, #{family => inet, addr => {127,0,0,1}, port => P}, nowait)
             end,
             fun() -> _ = socket:close(C) end)
    end, lists:seq(1, N)),
    ok = socket:close(L).
