-module(ets4).
-export([run/0, t/2, g/1, h/1]).

g(X) -> h(X) + 1.
h(X) -> X * 2.

run() ->
    M0 = [{'_', [], []}],
    Mreturn = [{'_', [], [{return_trace}]}],
    Mexception = [{'_', [], [{exception_trace}]}],
    [{Flags, MatchSpec, t(MatchSpec, Flags)} ||
        Flags <- [[call], [call, return_to]],
        MatchSpec <- [M0, Mreturn, Mexception]].

t(Mprog, Flags) ->
    Tracer = spawn(fun() -> receive after infinity -> ok end end),
    OldGL = group_leader(),
    GL = spawn(fun Loop() ->
        receive
            {io_request, From, ReplyAs, _} ->
                From ! {io_reply, ReplyAs, ok},
                Loop();
            stop -> ok
        end
    end),
    true = group_leader(GL, self()),
    erlang:trace_pattern({ets4, '_', '_'}, Mprog, [local]),
    erlang:trace(self(), true, [{tracer, Tracer} | Flags]),
    A = g(3),
    R = try io:format("", []) of V -> V catch C:E -> {C, E} end,
    erlang:trace(self(), false, [{tracer, Tracer} | Flags]),
    erlang:trace_pattern({ets4, '_', '_'}, false, [local]),
    true = group_leader(OldGL, self()),
    GL ! stop,
    {A, R}.
