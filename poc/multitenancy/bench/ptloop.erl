-module(ptloop).
-export([root/0, run/1, ns/1, probe/0]).
root() -> loop(root, 0).
run(Key) -> loop(Key, 0).
loop(Key, I) ->
    persistent_term:put(Key, {I, "Thu, 15 Oct 2026 16:25:00 GMT"}),
    receive after 1000 -> ok end,
    loop(Key, I + 1).
ns(N) ->
    Nss = [begin {ok, Ns} = arinsal_ns:create(integer_to_binary(K), <<"p">>, #{}),
                 arinsal_ns:spawn(Ns, ptloop, run, [clock]), Ns end || K <- lists:seq(1, N)],
    io:format("spawned ~p~n", [length(Nss)]),
    receive after infinity -> ok end.
probe() ->
    {ok, Ns} = arinsal_ns:create(<<"a">>, <<"p">>, #{}),
    P = arinsal_ns:spawn(Ns, ptloop, run, [clock]),
    receive after 3000 -> ok end,
    io:format("~p ~p~n", [maps:get(processes, arinsal_ns:info(Ns)), erlang:is_process_alive(P)]).
