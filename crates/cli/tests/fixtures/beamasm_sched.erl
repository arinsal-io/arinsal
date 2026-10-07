-module(beamasm_sched).
-export([run/0]).

%% Busy processes that keep yielding must not starve work queued for the
%% same scheduler from elsewhere, also while multi-scheduling is blocked.
count(0) -> ok;
count(N) -> count(N - 1).

hog() -> count(100000), hog().

server() ->
    receive
        {req, From, N} -> From ! {rep, N}, server();
        stop -> ok
    end.

run() ->
    Hogs = [spawn_opt(fun hog/0, [link, monitor]) || _ <- lists:seq(1, 8)],
    Blocked = erlang:system_flag(multi_scheduling, block),
    S = spawn(fun server/0),
    Replies = [begin
                   S ! {junk, N},
                   S ! {req, self(), N},
                   receive {rep, N} -> ok after 2000 -> {lost, N} end
               end || N <- lists:seq(1, 50)],
    io:format("~p ~p~n", [Blocked, lists:usort(Replies)]),
    S ! stop,
    Unblocked = erlang:system_flag(multi_scheduling, unblock),
    [begin unlink(P), exit(P, kill) end || {P, _} <- Hogs],
    [receive {'DOWN', M, process, P, _} -> ok end || {P, M} <- Hogs],
    io:format("~p~n", [Unblocked]).
