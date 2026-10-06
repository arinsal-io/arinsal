-module(mon).
-export([run/0]).
t(F, N) -> S = erlang:monotonic_time(nanosecond), F(N), (erlang:monotonic_time(nanosecond) - S) / N.
run() ->
    Peer = spawn(fun() -> receive stop -> ok end end),
    MonDemon = fun L(0) -> ok; L(N) -> R = erlang:monitor(process, Peer), erlang:demonitor(R, [flush]), L(N-1) end,
    SpawnOnly = fun L(0) -> ok; L(N) -> spawn(fun() -> ok end), L(N-1) end,
    SpawnMon = fun L(0) -> ok; L(N) -> {P, R} = spawn_monitor(fun() -> ok end), receive {'DOWN', R, process, P, _} -> L(N-1) end end,
    Dead = spawn(fun() -> ok end), timer:sleep(10),
    MonDead = fun L(0) -> ok; L(N) -> R = erlang:monitor(process, Dead), receive {'DOWN', R, _, _, _} -> L(N-1) end end,
    [begin _ = t(F, 20000), io:format("~-40s ~8.1f ns~n", [Name, t(F, 200000)]) end
     || {Name, F} <- [{"monitor+demonitor (live peer)", MonDemon},
                      {"monitor dead pid -> DOWN -> receive", MonDead},
                      {"spawn (no wait)", SpawnOnly},
                      {"spawn_monitor + exit + DOWN + receive", SpawnMon}]],
    Peer ! stop.
