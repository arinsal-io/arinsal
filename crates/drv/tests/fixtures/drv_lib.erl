%% Driver library API test: run against real erl and Arinsal, results compared.
-module(drv_lib).
-export([run/1, entries/1, busy/1, init_ack/1, monitors/1, noexit/1, lock/1, create_port/1]).

run(Dir) ->
    true = os:putenv("DRV_LIB_FROM_ERL", "from_erl"),
    ok = erl_ddll:load(Dir, "lib_drv"),
    ok = erl_ddll:load(Dir, "lib_noexit_drv"),
    P = open_port({spawn_driver, "lib_drv"}, [binary]),
    PL = open_port({spawn_driver, "lib_drv"}, []),
    PLine = open_port({spawn_driver, "lib_drv"}, [{line, 10}]),
    PLim = open_port({spawn_driver, "lib_drv"}, [{busy_limits_msgq, {100, 200}}]),
    Steps =
        [{alloc, step(P, 1)},
         {queue, step(P, 2)},
         {outputv_binary, step(P, 3)},
         {outputv_list, step(PL, 3)},
         {stash, stash(P)},
         {terms, step(P, 4)},
         {terms_list, step(PL, 4)},
         {monitors, monitors(P)},
         {noexit, noexit(Dir)},
         {info, step(P, 9)},
         {info_list, step(PL, 9)},
         {info_line, step(PLine, 9)},
         {info_limits, step(PLim, 9)},
         {threads, step(P, 10)},
         {pdl, pdl(P)},
         {env_time, env_time(P)},
         {dl, step(P, 13, list_to_binary(filename:join(Dir, "lib_drv")))},
         {busy, busy(P)},
         {entries, entries(P)},
         {create_port, create_port(P)},
         {init_ack, init_ack(Dir)},
         {qinfo, qinfo(P)},
         {lock, lock(P)}],
    [port_close(X) || X <- [P, PL, PLine, PLim]],
    maps:from_list(Steps).

%% One control call; the report text and the messages the driver sent meanwhile.
step(Port, Op) -> step(Port, Op, <<>>).

step(Port, Op, Data) ->
    Report = report(Port, Op, Data),
    {Report, drain()}.

report(Port, Op, Data) ->
    case catch port_control(Port, Op, Data) of
        {'EXIT', Reason} -> {error, element(1, Reason)};
        R -> fix_schedulers(iolist_to_binary(R))
    end.

%% The scheduler count differs between runtimes; compare it with the runtime's own.
fix_schedulers(Report) ->
    case binary:split(Report, <<"schedulers=">>) of
        [Before, Rest] ->
            [Num, After] = binary:split(Rest, <<";">>),
            Same = binary_to_integer(Num) =:= erlang:system_info(schedulers),
            iolist_to_binary([Before, <<"schedulers_ok=">>, atom_to_binary(Same), <<";">>, After]);
        [_] ->
            Report
    end.

drain() -> drain(150).

drain(Timeout) ->
    receive
        {'EXIT', _, _} -> drain(Timeout);
        M -> [norm(M) | drain(Timeout)]
    after Timeout -> []
    end.

norm(T) when is_pid(T) -> '$pid';
norm(T) when is_port(T) -> '$port';
norm(T) when is_reference(T) -> '$ref';
norm(T) when is_tuple(T) -> list_to_tuple([norm(E) || E <- tuple_to_list(T)]);
norm([H | T]) -> [norm(H) | norm(T)];
norm(T) when is_map(T) -> maps:from_list([{norm(K), norm(V)} || {K, V} <- maps:to_list(T)]);
norm(T) -> T.

in_helper(Fun) ->
    Self = self(),
    Pid = spawn(fun() -> Self ! {helper, self(), Fun()} end),
    receive {helper, Pid, R} -> R after 5000 -> helper_timeout end.

stash(P) ->
    in_helper(fun() -> report(P, 7, <<>>) end).

monitors(P) ->
    R5 = in_helper(fun() -> report(P, 5, <<>>) end),
    Exit5 = drain(),
    R6 = in_helper(fun() -> report(P, 6, <<>>) end),
    Exit6 = drain(),
    %% the stashed process is dead by now
    R8 = report(P, 8, <<>>),
    Exits = report(P, 20, <<>>),
    #{monitor_caller => {R5, Exit5}, demonitor => {R6, Exit6}, stash => R8, exits => Exits}.

noexit(_Dir) ->
    P = open_port({spawn_driver, "lib_noexit_drv"}, []),
    R = in_helper(fun() -> report(P, 5, <<>>) end),
    port_close(P),
    {R, drain()}.

pdl(P) ->
    step(P, 11).

env_time(P) ->
    {Report, Msgs} = step(P, 12),
    {ok, Value} = {ok, os:getenv("DRV_LIB_TEST")},
    Ns = erlang:monotonic_time(nanosecond),
    Off = erlang:time_offset(nanosecond),
    [Before, Rest] = binary:split(Report, <<"mono_ns=">>),
    [MonoS, Rest2] = binary:split(Rest, <<";">>),
    [_, OffS0] = binary:split(Rest2, <<"offset_ns=">>),
    [OffS, _] = binary:split(OffS0, <<";">>),
    Mono = binary_to_integer(MonoS),
    DrvOff = binary_to_integer(OffS),
    #{report => Before, msgs => Msgs, env => Value,
      mono_close => abs(Mono - Ns) < 2000000000,
      offset_close => abs(DrvOff - Off) < 100000000}.

busy(P) ->
    R14 = report(P, 14, <<>>),
    Nosuspend = port_command(P, <<"x">>, [nosuspend]),
    Force = (catch port_command(P, <<"y">>, [force])),
    ForceReason = case Force of {'EXIT', {Reason, _}} -> Reason; Other -> Other end,
    Self = self(),
    Blocked = spawn(fun() -> R = port_command(P, <<"z">>), Self ! {blocked_done, R} end),
    BlockedEarly = receive {blocked_done, _} -> done after 100 -> still_blocked end,
    R15 = report(P, 15, <<>>),
    BlockedLate = receive {blocked_done, R2} -> R2 after 2000 -> never end,
    _ = Blocked,
    After = port_command(P, <<"w">>),
    #{busy => R14, nosuspend => Nosuspend, force => ForceReason, early => BlockedEarly,
      unbusy => R15, late => BlockedLate, after_ => After, msgs => drain()}.

entries(P) ->
    Before = (catch open_port({spawn_driver, "lib_extra_drv"}, [])),
    BeforeNorm = case Before of {'EXIT', {R0, _}} -> R0; _ -> opened end,
    R16 = report(P, 16, <<>>),
    X = open_port({spawn_driver, "lib_extra_drv"}, []),
    true = port_command(X, <<"hi">>),
    Msgs = drain(),
    port_close(X),
    %% the driver must outlive the closed port's release (remove_driver_entry rule)
    timer:sleep(500),
    R17 = report(P, 17, <<>>),
    After = (catch open_port({spawn_driver, "lib_extra_drv"}, [])),
    AfterNorm = case After of {'EXIT', {R1, _}} -> R1; _ -> opened end,
    #{before => BeforeNorm, added => R16, msgs => Msgs, removed => R17, after_ => AfterNorm}.

create_port(P) ->
    R = report(P, 19, <<>>),
    Msgs = receive {child, Child} -> [ok | drain_child(Child)] after 1000 -> [no_child] end,
    {R, Msgs}.

drain_child(Child) ->
    Name = erlang:port_info(Child, name),
    Connected = erlang:port_info(Child, connected) =:= {connected, self()},
    true = port_command(Child, <<"zz">>),
    Echo = drain(),
    true = port_close(Child),
    Gone = erlang:port_info(Child),
    [Name, Connected, Echo, Gone].

init_ack(Dir) ->
    ok = erl_ddll:load(Dir, "lib_ack_drv"),
    T0 = erlang:monotonic_time(millisecond),
    Port = open_port({spawn_driver, "lib_ack_drv"}, []),
    Waited = erlang:monotonic_time(millisecond) - T0 >= 50,
    IsPort = is_port(Port),
    Echo = (catch begin true = port_command(Port, <<"ok">>), drain() end),
    port_close(Port),
    Failed = (catch open_port({spawn_driver, "lib_ack_drv fail"}, [])),
    FailedNorm = case Failed of {'EXIT', {R, _}} -> R; Other -> Other end,
    #{waited => Waited, is_port => IsPort, echo => Echo, failed => FailedNorm, msgs => drain()}.

qinfo(P) ->
    [{queue_size, QS}] = [erlang:port_info(P, queue_size)],
    OsPid = erlang:port_info(P, os_pid),
    {QS, OsPid}.

lock(P) ->
    R = report(P, 18, <<>>),
    Unload = erl_ddll:try_unload(lib_drv, []),
    {R, Unload}.
