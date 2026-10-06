-module(beamasm_hibernate).
-export([run/0]).
run() ->
    Me = self(),
    P = spawn(fun() ->
        receive go -> ok end,
        R = erlang:hibernate(),
        Me ! {woke, R},
        receive stop -> ok end
    end),
    P ! go,
    timer:sleep(50),
    P ! ping,
    receive {woke, X} -> io:format("woke ~p~n", [X]) after 2000 -> io:format("timeout~n") end,
    P ! stop.
