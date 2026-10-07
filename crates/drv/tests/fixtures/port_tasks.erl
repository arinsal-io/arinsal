%% Port task scheduling scenarios (erl_port_task.c) on sched_drv.so; the result map is
%% compared with erl 29.1.1.
-module(port_tasks).
-export([run/1]).

run(Dir) ->
    ok = erl_ddll:load_driver(Dir, "sched_drv"),
    process_flag(trap_exit, true),
    Res = #{busy_suspend => timed(fun busy_suspend/0),
            nosuspend => timed(fun nosuspend/0),
            busy_queue_order => timed(fun busy_queue_order/0),
            exit_resumes => timed(fun exit_resumes/0),
            busy_msgq => timed(fun busy_msgq/0)},
    ok = erl_ddll:unload_driver("sched_drv"),
    Res.

%% Run a scenario in its own process so a hang reports `timeout` instead of blocking.
timed(Fun) ->
    Self = self(),
    {Pid, Ref} = spawn_monitor(fun () ->
                                       process_flag(trap_exit, true),
                                       Self ! {self(), Fun()}
                               end),
    receive
        {Pid, Res} -> erlang:demonitor(Ref, [flush]), Res;
        {'DOWN', Ref, process, Pid, Reason} -> {crashed, Reason}
    after 10000 ->
            exit(Pid, kill),
            timeout
    end.

open() ->
    open_port({spawn_driver, "sched_drv"}, [binary]).

%% Collect the data `stop` outputs and the closed/exit messages.
close_and_collect(Port) ->
    true = port_close(Port),
    receive {Port, {data, Data}} -> binary_to_list(Data)
    after 2000 -> no_data
    end.

wait_status(Pid, Status, N) when N > 0 ->
    case process_info(Pid, status) of
        {status, Status} -> Status;
        _ -> receive after 10 -> wait_status(Pid, Status, N - 1) end
    end;
wait_status(Pid, _Status, 0) ->
    element(2, process_info(Pid, status)).

%% A port_command to a busy port suspends the caller until the port is not busy.
busy_suspend() ->
    Port = open(),
    [] = port_control(Port, $B, []),
    Self = self(),
    P = spawn_link(fun () -> Self ! {self(), port_command(Port, [$C, 1])} end),
    Suspended = wait_status(P, suspended, 100),
    [] = port_control(Port, $N, []),
    Result = receive {P, R} -> R after 2000 -> timeout end,
    {Suspended, Result, close_and_collect(Port)}.

%% nosuspend port_command and send/3 on a busy port do not send.
nosuspend() ->
    Port = open(),
    [] = port_control(Port, $B, []),
    A = port_command(Port, [$C, 1], [nosuspend]),
    B = erlang:send(Port, {self(), {command, [$C, 2]}}, [nosuspend]),
    C = port_command(Port, [$C, 3], [force]),
    [] = port_control(Port, $N, []),
    D = erlang:send(Port, {self(), {command, [$C, 4]}}, [nosuspend]),
    {A, B, C, D, close_and_collect(Port)}.

%% Commands queued while the port executes a long command that makes it busy wait in
%% the busy queue; a later connect and close from the same sender wait behind them; a
%% forced command makes the port not busy and the queue runs in order.
busy_queue_order() ->
    Self = self(),
    Owner = spawn_link(fun () ->
                               Port = open(),
                               Self ! {port, Port},
                               owner_loop(Port)
                       end),
    Port = receive {port, P0} -> P0 end,
    Sender = spawn_link(fun () ->
                                receive go -> ok end,
                                [Port ! {Owner, {command, [$C, I]}} || I <- lists:seq(2, 20)],
                                Port ! {Owner, {connect, self()}},
                                Port ! {self(), close},
                                sender_loop(Port, Self)
                        end),
    Owner ! {cmd, [$L, 1, 25]},
    receive after 50 -> ok end,
    Sender ! go,
    receive after 400 -> ok end,
    true = port_command(Port, [$N], [force]),
    receive {sender, Msgs} -> {Msgs, receive {owner, O} -> O after 0 -> none end}
    after 3000 -> timeout
    end.

owner_loop(Port) ->
    receive
        {cmd, C} -> Port ! {self(), {command, C}}, owner_loop(Port);
        _ -> owner_loop(Port)
    end.

sender_loop(Port, Parent) ->
    receive
        {Port, connected} -> sender_loop(Port, Parent);
        {Port, {data, Data}} ->
            receive {Port, closed} -> Parent ! {sender, {binary_to_list(Data), closed}}
            after 2000 -> Parent ! {sender, {binary_to_list(Data), no_closed}}
            end
    after 3000 -> Parent ! {sender, timeout}
    end.

%% Killing a busy port resumes the processes suspended on it.
exit_resumes() ->
    Port = open(),
    [] = port_control(Port, $B, []),
    Self = self(),
    P = spawn(fun () ->
                      Res = try port_command(Port, [$C, 1]) catch error:E -> {E} end,
                      Self ! {self(), Res}
              end),
    Suspended = wait_status(P, suspended, 100),
    exit(Port, kill),
    Result = receive {P, R} -> element(1, R) after 2000 -> timeout end,
    {Suspended, Result}.

%% {busy_limits_msgq, ...}: scheduled command data above the high limit makes the port
%% busy for senders until the queue drains below the low limit. With {parallelism, true}
%% bang sends are always scheduled.
busy_msgq() ->
    Port = open_port({spawn_driver, "sched_drv"},
                     [binary, {busy_limits_msgq, {100, 200}}, {parallelism, true}]),
    Port ! {self(), {command, [$D, 1, 30]}},
    receive after 50 -> ok end,
    Big = [$C, 2 | lists:duplicate(300, 0)],
    Port ! {self(), {command, Big}},
    Busy = erlang:send(Port, {self(), {command, [$C, 3]}}, [nosuspend]),
    receive after 500 -> ok end,
    After = erlang:send(Port, {self(), {command, [$C, 4]}}, [nosuspend]),
    {Busy, After, close_and_collect(Port)}.
