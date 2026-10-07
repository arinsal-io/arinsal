%% Differential smoke test for linked-in drivers (see smoke_drv.c).
%% `run(Dir)` returns a normalized trace of erl_ddll and port results.
-module(drv_smoke).
-export([run/1]).

run(Dir) ->
    Self = self(),
    {Pid, Ref} = spawn_monitor(fun() -> Self ! {self(), try body(Dir) catch C:R:S -> {crash, C, R, lists:sublist(S, 3)} end} end),
    receive
        {Pid, Result} ->
            erlang:demonitor(Ref, [flush]),
            normalize(Result);
        {'DOWN', Ref, process, Pid, Reason} ->
            {died, normalize(Reason)}
    end.

body(Dir) ->
    process_flag(trap_exit, true),
    Static = erl_ddll:loaded_drivers(),
    Load = [erl_ddll:load_driver(Dir, smoke_drv),
            erl_ddll:load_driver(Dir, "smoke_drv"),
            erl_ddll:load(Dir, smoke_v_drv),
            erl_ddll:try_load(Dir, smoke_drv, []),
            erl_ddll:try_load(Dir ++ "/other", smoke_drv, []),
            erl_ddll:try_load(Dir, tcp_inet, []),
            erl_ddll:try_unload(tcp_inet, []),
            erl_ddll:try_unload(no_such_drv, [])],
    Errors = [load_error(Dir, nonexistent_drv),
              load_error(Dir, smoke_badver_drv),
              load_error(Dir, smoke_badname_drv)],
    Loaded = erl_ddll:loaded_drivers(),
    Info = [erl_ddll:info(smoke_drv, Item)
            || Item <- [driver_options, port_count, linked_in_driver, permanent,
                        processes, awaiting_load, awaiting_unload]],
    StaticInfo = [catch erl_ddll:info(tcp_inet, I) || I <- [processes, port_count]],
    P = open_port({spawn_driver, "smoke_drv arg1"}, []),
    PortCount = erl_ddll:info(smoke_drv, port_count),
    Name = erlang:port_info(P, name),
    Echo = [cmd(P, "hello"), cmd(P, [<<"bin">>, $x, [<<"y">>]]), cmd(P, <<>>),
            cmd(P, "!hdrxyz"), cmd(P, "!nodata")],
    Badcmd = [bad_cmd(300), bad_cmd([a]), bad_cmd(5), bad_cmd([1 | 2])],
    Control = [port_control(P, 1, "abc"),
               port_control(P, 1, <<"xyz">>),
               port_control(P, 6, []),
               port_control(P, 3, "q"),
               port_control(P, 2, "ab"),
               port_control(P, 7, []),
               port_control(P, 5, []),
               port_control(P, 8, []),
               port_control(P, 5, []),
               catch port_control(P, 4, ""),
               catch port_control(P, 99, ""),
               catch port_control(P, -1, ""),
               catch port_control(P, 1, [300])],
    Call = [erlang:port_call(P, 7, {a, [1, 2], <<"b">>, 3.5}),
            erlang:port_call(P, 200, lists:seq(1, 120)),
            catch erlang:port_call(P, 0, x),
            catch erlang:port_call(P, 1, x),
            catch erlang:port_call(P, -1, x)],
    PB = open_port({spawn, smoke_drv}, [binary]),
    Binary = [cmd(PB, "abc"), cmd(PB, "!hdrxyz"), cmd(PB, "!nodata"),
              cmd(PB, lists:duplicate(100, $q))],
    PL = open_port({spawn_driver, smoke_drv}, [{line, 4}]),
    true = port_command(PL, "ab\ncdefgh\r\nij"),
    Lines1 = drain(PL),
    true = port_command(PL, "!eof"),
    Lines2 = drain(PL),
    PE = open_port({spawn_driver, smoke_drv}, [eof, binary]),
    true = port_command(PE, "!eof"),
    SoftEof = [drain(PE), erlang:port_info(PE, name) =/= undefined, port_close(PE)],
    Fail = [fail("!fail"), fail("!failcode"), fail("!posix"), fail("!exit"),
            fail("!exiterr")],
    StartErrors = [catch open_port({spawn_driver, "smoke_drv fail_start"}, []),
                   catch open_port({spawn_driver, "smoke_drv badarg_start"}, []),
                   catch open_port({spawn_driver, "smoke_drv general_start"}, []),
                   catch open_port({spawn_driver, "no_such_drv"}, []),
                   catch open_port({spawn_driver, smoke_drv}, [exit_status])],
    Stops1 = port_control(P, 6, []),
    Close = [port_close(P), catch port_command(P, "x"), catch port_control(P, 1, "a"),
             catch erlang:port_call(P, 7, x)],
    PV = open_port({spawn_driver, smoke_v_drv}, [binary]),
    Big = list_to_binary(lists:duplicate(100, $B)),
    Huge = list_to_binary(lists:duplicate(300, $H)),
    Vec = [vcmd(PV, [<<"ab">>, "cd", Big]),
           vcmd(PV, []),
           vcmd(PV, [Big, <<Big/binary, "2">>, "x", Huge]),
           vcmd(PV, [[<<Big/binary, N>>, $y] || N <- lists:seq(1, 10)] ++ [Huge])],
    PVStops = port_control(PV, 6, []),
    true = port_close(PV),
    U1 = erl_ddll:unload_driver(smoke_drv),
    U2 = erl_ddll:info(smoke_drv, port_count),
    U3 = erl_ddll:try_unload(smoke_drv, [kill_ports]),
    U4 = drain_exits(),
    U5 = erl_ddll:unload_driver(smoke_drv),
    U6 = erl_ddll:loaded_drivers(),
    %% erl 29.1.1 keeps smoke_v_drv loaded after this (no unloaded DOWN ever
    %% arrives once its port has used outputv); the list is taken before.
    U7 = erl_ddll:try_unload(smoke_v_drv, []),
    Unload = [U1, U2, U3, U4, U5, U6, U7],
    Mon = monitor_cases(Dir),
    Format = [erl_ddll:format_error_int(E)
              || E <- [inconsistent, linked_in_driver, permanent, not_loaded,
                       not_loaded_by_this_process, not_pending, already_loaded,
                       pending_reload, pending_process, no_driver_init,
                       driver_incorrect_version, bad_driver_name]],
    #{static => Static, load => Load, errors => Errors, loaded => Loaded,
      info => Info, static_info => StaticInfo, port_count => PortCount,
      name => Name, echo => Echo, badcmd => Badcmd, control => Control,
      call => Call, binary => Binary, lines => {Lines1, Lines2},
      soft_eof => SoftEof, fail => Fail, start_errors => StartErrors,
      stops => Stops1, close => Close, vec => Vec, pv_stops => PVStops,
      unload => Unload, monitor => Mon, format => Format,
      left => drain_all()}.

load_error(Dir, Name) ->
    case erl_ddll:load_driver(Dir, Name) of
        {error, {open_error, _} = E} ->
            {open_error, erl_ddll:format_error_int(E)};
        {error, E} ->
            {E, erl_ddll:format_error_int(E)};
        Other ->
            Other
    end.

cmd(P, Data) ->
    true = port_command(P, Data),
    receive {P, Msg} -> Msg after 2000 -> timeout end.

vcmd(P, Data) ->
    true = port_command(P, Data),
    drain(P).

drain(P) ->
    receive
        {P, Msg} -> [Msg | drain(P)];
        {'EXIT', P, Reason} -> [{exit, Reason}]
    after 200 -> []
    end.

drain_exits() ->
    receive {'EXIT', _, Reason} -> [Reason | drain_exits()] after 200 -> [] end.

drain_all() ->
    receive Msg -> [Msg | drain_all()] after 0 -> [] end.

bad_cmd(Data) ->
    P = open_port({spawn_driver, smoke_drv}, []),
    R = (catch port_command(P, Data)),
    Result = drain(P),
    {R, Result, erlang:port_info(P, name)}.

fail(Command) ->
    P = open_port({spawn_driver, smoke_drv}, []),
    true = port_command(P, Command),
    Result = drain(P),
    {Command, Result, erlang:port_info(P)}.

monitor_cases(Dir) ->
    R1 = erl_ddll:monitor(driver, {smoke_drv, loaded}),
    M1 = receive {_, R1, _, _, _} = A -> A after 200 -> none end,
    R2 = erl_ddll:monitor(driver, {tcp_inet, unloaded}),
    M2 = receive {_, R2, _, _, _} = B -> B after 200 -> none end,
    ok = erl_ddll:load_driver(Dir, smoke_drv),
    R3 = erl_ddll:monitor(driver, {"smoke_drv", loaded}),
    M3 = receive {_, R3, _, _, _} = C -> C after 200 -> none end,
    R4 = erl_ddll:monitor(driver, {smoke_drv, unloaded}),
    Waiting = erl_ddll:info(smoke_drv, awaiting_unload),
    P = open_port({spawn_driver, smoke_drv}, []),
    Pending = erl_ddll:try_unload(smoke_drv, []),
    Count = erl_ddll:info(smoke_drv, port_count),
    Killed = drain(P),
    M4 = receive {_, R4, _, _, _} = D -> D after 1000 -> none end,
    R5 = erl_ddll:monitor(driver, {smoke_drv, unloaded}),
    true = erl_ddll:demonitor(R5),
    %% erl 29.1.1 hangs on erl_ddll:monitor(process, _) and on
    %% erl_ddll:info(Unloaded, processes); those are left out.
    Bad = [catch erl_ddll:monitor(driver, {smoke_drv, other}),
           catch erl_ddll:try_load(Dir, smoke_drv, [bad]),
           catch erl_ddll:try_unload(smoke_drv, [bad]),
           catch erl_ddll:info(smoke_drv, port_count)],
    [M1, M2, M3, Waiting, Pending, Count, Killed, M4, Bad].

normalize({'EXIT', {Reason, [_ | _]}}) -> {'EXIT', normalize(Reason)};
normalize(T) when is_port(T) -> port;
normalize(T) when is_pid(T) -> pid;
normalize(T) when is_reference(T) -> ref;
normalize(T) when is_list(T) -> normalize_list(T);
normalize(T) when is_tuple(T) -> list_to_tuple(normalize(tuple_to_list(T)));
normalize(T) when is_map(T) -> maps:map(fun(_, V) -> normalize(V) end, T);
normalize(T) -> T.

normalize_list([H | T]) -> [normalize(H) | normalize_list(T)];
normalize_list([]) -> [];
normalize_list(T) -> normalize(T).
