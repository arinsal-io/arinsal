-module(bench).
-export([run/0, run/1, make_ref_loop/1, empty_loop/1]).

timed(F) ->
    Start = erlang:monotonic_time(),
    Value = F(),
    Elapsed = erlang:convert_time_unit(erlang:monotonic_time() - Start, native, nanosecond),
    {Value, Elapsed}.

make_ref_loop(N) ->
    timed(fun() -> ref_loop(N, undefined) end).

ref_loop(0, Last) -> is_reference(Last);
ref_loop(N, _) -> ref_loop(N - 1, make_ref()).

empty_loop(N) ->
    timed(fun() -> no_ref_loop(N, undefined) end).

no_ref_loop(0, Last) -> is_reference(Last);
no_ref_loop(N, _) -> no_ref_loop(N - 1, undefined).

run() ->
    run(10000).

run(N) ->
    %% Warmup
    _ = make_ref_loop(min(N, 1000)),
    _ = empty_loop(min(N, 1000)),
    %% Measurements
    {_, RefNs} = make_ref_loop(N),
    {_, EmptyNs} = empty_loop(N),
    RefNsPerOp = RefNs / N,
    EmptyNsPerOp = EmptyNs / N,
    NetNsPerOp = (RefNs - EmptyNs) / N,
    io:format("N=~p: make_ref=~.1f ns/op, empty_loop=~.1f ns/op, net_make_ref=~.1f ns/op~n",
              [N, RefNsPerOp, EmptyNsPerOp, NetNsPerOp]),
    io:format("raw: {make_ref, ~p, ~p}~n", [N, RefNs]),
    io:format("raw: {empty_loop, ~p, ~p}~n", [N, EmptyNs]),
    ok.
