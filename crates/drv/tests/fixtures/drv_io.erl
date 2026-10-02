%% Differential test for driver_select, timers, driver_async and timeslices (io_drv.c).
%% `run(Dir)` returns a map of scenario results.
-module(drv_io).
-export([run/1]).

run(Dir) ->
    Self = self(),
    {Pid, Ref} = spawn_monitor(fun() ->
        Self ! {self(), try body(Dir) catch C:R:S -> {crash, C, R, lists:sublist(S, 3)} end}
    end),
    receive
        {Pid, Result} -> erlang:demonitor(Ref, [flush]), Result;
        {'DOWN', Ref, process, Pid, Reason} -> {died, Reason}
    after 60000 -> timeout
    end.

open() -> open_port({spawn_driver, "io_drv"}, [binary]).

ctl(P, Cmd) -> ctl(P, Cmd, []).
ctl(P, Cmd, Arg) -> catch port_control(P, Cmd, Arg).

%% Messages from the port until it has been quiet for Ms.
flush(P, Ms) -> flush(P, Ms, []).
flush(P, Ms, Acc) ->
    receive
        {P, {data, D}} -> flush(P, Ms, [D | Acc]);
        {'EXIT', P, R} -> flush(P, Ms, [{exit, R} | Acc]);
        {P, Other} -> flush(P, Ms, [Other | Acc])
    after Ms -> lists:reverse(Acc)
    end.

body(Dir) ->
    process_flag(trap_exit, true),
    ok = erl_ddll:load_driver(Dir, io_drv),
    P = open(),
    %% persistent read select
    S1 = (fun() ->
        Ret = ctl(P, 1, "0"),
        port_command(P, "hello"),
        A = flush(P, 150),
        port_command(P, "abc"),
        B = flush(P, 150),
        D = ctl(P, 3),
        port_command(P, "zzz"),
        C = flush(P, 150),
        {Ret, A, B, D, C}
    end)(),
    %% a deselected fd selected again: the pending "zzz" is delivered
    S1b = (fun() ->
        Re = ctl(P, 1, "1"),
        X = flush(P, 150),
        port_command(P, "x"),
        Y = flush(P, 150),
        port_command(P, "y"),
        Z = flush(P, 150),
        {Re, X, Y, Z}
    end)(),
    %% select twice is one event
    S2 = (fun() ->
        Q = open(),
        T = ctl(Q, 8),
        port_command(Q, "dup"),
        R = flush(Q, 150),
        port_close(Q),
        {T, R}
    end)(),
    %% output select
    S3 = (fun() ->
        Q = open(),
        T = ctl(Q, 2),
        R = flush(Q, 200),
        port_close(Q),
        {T, R}
    end)(),
    %% ERL_DRV_USE deselect calls stop_select inside the call
    S4 = (fun() ->
        Q = open(),
        ctl(Q, 1, "0"),
        T = ctl(Q, 4),
        port_command(Q, "q"),
        R = flush(Q, 100),
        port_close(Q),
        {T, R}
    end)(),
    %% USE_NO_CALLBACK does not call stop_select
    S5 = (fun() ->
        Q = open(),
        ctl(Q, 1, "0"),
        T = ctl(Q, 7),
        port_close(Q),
        {T, ctl(P, 5)}
    end)(),
    %% a descriptor that was never selected: ERL_DRV_USE off calls stop_select
    S6 = (fun() ->
        Q = open(),
        T = ctl(Q, 70),
        port_close(Q),
        T
    end)(),
    %% end of file on the pipe
    S7 = (fun() ->
        Q = open(),
        ctl(Q, 1, "0"),
        ctl(Q, 9),
        R = flush(Q, 200),
        port_close(Q),
        R
    end)(),
    %% select on a descriptor that is not open: the driver finds out in ready_input
    S8 = (fun() ->
        Q = open(),
        T = ctl(Q, 40),
        R = flush(Q, 200),
        port_close(Q),
        {T, R}
    end)(),
    %% another port steals the read side
    S9 = (fun() ->
        A = open(),
        B = open(),
        ctl(A, 1, "0"),
        Fd = ctl(A, 50),
        T = ctl(B, 51, Fd),
        port_command(A, "stolen"),
        RA = flush(A, 200),
        RB = flush(B, 200),
        port_close(A),
        port_close(B),
        {T, RA, RB}
    end)(),
    %% port timers
    S10 = (fun() ->
        Q = open(),
        T1 = ctl(Q, 10, "40"),
        R1 = flush(Q, 200),
        T2 = ctl(Q, 10, "400"),
        Left = ctl(Q, 12),
        Cancel = ctl(Q, 11),
        None = ctl(Q, 12),
        R2 = flush(Q, 500),
        ctl(Q, 10, "0"),
        R3 = flush(Q, 100),
        ctl(Q, 10, "400"),
        ctl(Q, 10, "30"),
        R4 = flush(Q, 250),
        ctl(Q, 10, "100"),
        ctl(Q, 11),
        ctl(Q, 10, "100"),
        R5 = flush(Q, 300),
        port_close(Q),
        {T1, R1, T2, Left, Cancel, None, R2, R3, R4, R5}
    end)(),
    %% a pending timer is gone with the port
    S11 = (fun() ->
        Q = open(),
        ctl(Q, 10, "50"),
        port_close(Q),
        receive {Q, M} -> {unexpected, M} after 200 -> quiet end
    end)(),
    %% async jobs
    S12 = (fun() ->
        Q = open(),
        A1 = ctl(Q, 20, "21"),
        R1 = flush(Q, 200),
        K = ctl(Q, 21, "1"),
        ctl(Q, 21, "2"),
        ctl(Q, 21, "3"),
        R2 = flush(Q, 300),
        port_close(Q),
        {A1, R1, K, R2}
    end)(),
    %% async job whose port closes first: async_free releases the job
    S13 = (fun() ->
        Q = open(),
        Frees0 = ctl(P, 5),
        ctl(Q, 22, "5"),
        port_close(Q),
        timer:sleep(500),
        {Frees0, ctl(P, 5)}
    end)(),
    %% timeslice accounting inside a task
    S14 = (fun() ->
        Q = open(),
        ctl(Q, 30),
        R = flush(Q, 200),
        port_close(Q),
        R
    end)(),
    %% a port that dies with its fd still selected
    S15 = (fun() ->
        Q = open(),
        ctl(Q, 1, "0"),
        ctl(Q, 60),
        port_close(Q),
        timer:sleep(200),
        Q2 = open(),
        ctl(Q2, 1, "0"),
        port_command(Q2, "alive"),
        R = flush(Q2, 200),
        port_close(Q2),
        R
    end)(),
    port_close(P),
    #{select_read => S1, select_again => S1b, select_twice => S2, select_write => S3,
      use_stop_select => S4, use_no_callback => S5, use_unknown => S6, eof => S7,
      bad_fd => S8, steal => S9, timers => S10, timer_on_close => S11, async => S12,
      async_free => S13, timeslice => S14, stale => S15}.
