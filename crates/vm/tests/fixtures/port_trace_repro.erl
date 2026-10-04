-module(port_trace7_repro).
-export([run/2]).

run(Case, DriverDir) ->
    ok = erl_ddll:load_driver(DriverDir, echo_drv),
    Result = case Case of
        command -> command();
        connect -> connect();
        driver_remote_send_term -> remote_send_term();
        driver_send_term -> driver_send_term();
        open_close -> open_close();
        send_term -> send_term();
        set_timer -> set_timer()
    end,
    erlang:trace(new_ports, false, [all]),
    Trace = collect(),
    erl_ddll:unload_driver(echo_drv),
    {normalize(Result), normalize(Trace)}.

command() ->
    P = open([send, 'receive']),
    true = erlang:port_command(P, <<0>>),
    true = erlang:port_command(P, [0, <<0>>]),
    P ! {self(), {command, <<0>>}},
    P ! {self(), {command, <<0, 0:4096>>}},
    BeforeClose = collect(),
    erlang:port_close(P),
    BeforeClose ++ collect().

connect() ->
    _ = erlang:trace(new_ports, true, [send, 'receive', ports]),
    P = open(), S = self(),
    flush(),
    Parent = self(),
    {Pid, Ref} = spawn_monitor(fun() ->
        receive go ->
            P ! {self(), {connect, S}},
            receive {P, connected} -> unlink(P) end
        end
    end),
    1 = erlang:trace(Pid, true, [send, 'receive', procs]),
    true = erlang:port_connect(P, Pid),
    unlink(P),
    A = collect(),
    Pid ! go,
    receive {'DOWN', Ref, process, Pid, normal} -> ok after 1000 -> exit(down_timeout) end,
    B = collect(),
    erlang:port_close(P),
    C = collect(),
    {Parent, A ++ B ++ C}.

remote_send_term() ->
    P = open([send]), S = self(),
    true = erlang:port_command(P, <<15, 123456:32>>),
    receive {echo, P, <<123456:32>>} -> ok after 1000 -> exit(no_remote_term) end,
    A = collect(),
    Pid = spawn_link(fun() ->
        true = erlang:port_command(P, <<14>>),
        S ! ready,
        receive M -> S ! M end
    end),
    receive ready -> ok after 1000 -> exit(no_ready) end,
    1 = erlang:trace(Pid, true, ['receive']),
    true = erlang:port_command(P, <<15, 123456:32>>),
    receive {echo, P, <<123456:32>>} -> ok after 1000 -> exit(no_remote_term2) end,
    {Pid, A ++ collect(), close_port(P)}.

driver_send_term() ->
    P = open([send]),
    true = erlang:port_command(P, <<13, 123456:32>>),
    receive {echo, P, <<123456:32>>} -> ok after 1000 -> exit(no_term) end,
    A = collect(),
    Pid2 = spawn_monitor(fun() -> erlang:port_command(P, <<14>>) end),
    case Pid2 of {P2, Ref} -> receive {'DOWN', Ref, process, P2, normal} -> ok end end,
    true = erlang:port_command(P, <<12, 123456:32>>),
    B = collect(),
    erlang:port_close(P),
    A ++ B.

send_term() ->
    P = open([send]),
    true = erlang:port_command(P, <<12, 123456:32>>),
    receive {echo, P, <<123456:32>>} -> ok after 1000 -> exit(no_term) end,
    A = collect(),
    {Pid, Ref} = spawn_monitor(fun() -> erlang:port_command(P, <<14>>) end),
    receive {'DOWN', Ref, process, Pid, normal} -> ok after 1000 -> exit(down_timeout) end,
    true = erlang:port_command(P, <<12, 123456:32>>),
    B = collect(),
    erlang:port_close(P),
    A ++ B.

open_close() ->
    _ = erlang:trace(new_ports, true, [send, 'receive']),
    P1 = open(), erlang:port_close(P1), A = collect(),
    P2 = open(), P2 ! {self(), close},
    receive {P2, closed} -> ok after 1000 -> exit(no_closed) end,
    B = collect(),
    try erlang:port_close(P2) catch _:_ -> ok end,
    C = collect(),
    A ++ B ++ C.

set_timer() ->
    P = open([send, 'receive']),
    true = erlang:port_command(P, <<5>>),
    receive after 100 -> ok end,
    A = collect(), erlang:port_close(P), A ++ collect().

open() -> erlang:open_port({spawn, echo_drv}, [binary]).
open(Flags) -> P = open(), _ = erlang:trace(P, true, Flags), P.
close_port(P) -> erlang:port_close(P), collect().
collect() ->
    Ref = erlang:trace_delivered(all),
    receive {trace_delivered, all, Ref} -> ok after 1000 -> exit(trace_barrier_timeout) end,
    collect_messages([]).
collect_messages(Acc) ->
    receive M when element(1, M) =:= trace -> collect_messages([M | Acc])
    after 0 -> lists:reverse(Acc)
    end.
flush() -> receive _ -> flush() after 0 -> ok end.

normalize(Term) when is_pid(Term) -> pid;
normalize(Term) when is_port(Term) -> port;
normalize(Term) when is_tuple(Term) -> list_to_tuple([normalize(X) || X <- tuple_to_list(Term)]);
normalize([Head | Tail]) -> [normalize(Head) | normalize(Tail)];
normalize([]) -> [];
normalize(Term) -> Term.
