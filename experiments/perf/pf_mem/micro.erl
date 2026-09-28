-module(micro).
-export([cons/1, tuple/1, spawn_exit/1, monitor_down/1,
         pingpong/1, throw_catch/1, throw_conditional/1,
         try_no_throw/1, make_ref_loop/1, timer/1,
         gc_dead/1, gc_live/1, gen_call/1, monitor_backlog/1, monitor_windows/2,
         init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).

%% Each entry returns {work, elapsed_ns}; the same BEAM runs on both runtimes.
timed(F) ->
    Start = erlang:monotonic_time(),
    Value = F(),
    {Value, erlang:convert_time_unit(erlang:monotonic_time() - Start, native, nanosecond)}.

cons(N) -> timed(fun() -> hd(cons_loop(N, [])) end).
cons_loop(0, Acc) -> Acc;
cons_loop(N, Acc) -> cons_loop(N - 1, [N | Acc]).

tuple(N) -> timed(fun() -> element(1, tuple_loop(N, 0)) end).
tuple_loop(0, Acc) -> Acc;
tuple_loop(N, Acc) -> tuple_loop(N - 1, {N, Acc}).

spawn_exit(N) ->
    erlang:process_flag(trap_exit, true),
    timed(fun() -> spawn_loop(N) end).
spawn_loop(0) -> ok;
spawn_loop(N) ->
    Pid = spawn_link(fun() -> ok end),
    receive {'EXIT', Pid, normal} -> spawn_loop(N - 1) end.

monitor_down(N) -> timed(fun() -> monitor_loop(N) end).
monitor_loop(0) -> ok;
monitor_loop(N) ->
    {Pid, Ref} = spawn_monitor(fun() -> ok end),
    receive {'DOWN', Ref, process, Pid, normal} -> monitor_loop(N - 1) end.
monitor_backlog(N) ->
    monitor_loop(N),
    process_info(self(), [message_queue_len, monitors]).
monitor_windows(Windows, PerWindow) ->
    windows_loop(Windows, PerWindow, []).
windows_loop(0, _, Acc) -> lists:reverse(Acc);
windows_loop(N, PerWindow, Acc) ->
    {ok, Time} = timed(fun() -> monitor_loop(PerWindow) end),
    windows_loop(N - 1, PerWindow, [{Time, process_info(self(), message_queue_len)} | Acc]).

pingpong(N) -> timed(fun() ->
    Parent = self(),
    Peer = spawn(fun() -> peer(Parent) end),
    ping_loop(Peer, N),
    Peer ! stop,
    N
end).
peer(Parent) ->
    receive
        ping -> Parent ! pong, peer(Parent);
        stop -> ok
    end.
ping_loop(_, 0) -> ok;
ping_loop(Peer, N) ->
    Peer ! ping,
    receive pong -> ping_loop(Peer, N - 1) end.

throw_catch(N) ->
    timed(fun() -> throw_loop(N, 0) end).
throw_loop(0, Sum) -> Sum;
throw_loop(N, Sum) ->
    Value = try throw(1) catch throw:X -> X end,
    throw_loop(N - 1, Sum + Value).

throw_conditional(N) ->
    erlang:put(pf_mem_throw, true),
    Result = timed(fun() -> try_loop(N, 0) end),
    erlang:erase(pf_mem_throw),
    Result.
try_no_throw(N) ->
    erlang:put(pf_mem_throw, false),
    Result = timed(fun() -> try_loop(N, 0) end),
    erlang:erase(pf_mem_throw),
    Result.
try_loop(0, Sum) -> Sum;
try_loop(N, Sum) ->
    Value = try maybe_throw(N) catch throw:X -> X end,
    try_loop(N - 1, Sum + Value).
maybe_throw(N) ->
    case erlang:get(pf_mem_throw) of
        true -> throw(1);
        _ -> N
    end.

make_ref_loop(N) -> timed(fun() -> ref_loop(N, undefined) end).
ref_loop(0, Last) -> is_reference(Last);
ref_loop(N, _) -> ref_loop(N - 1, make_ref()).

timer(N) -> timed(fun() -> timer_loop(N) end).
timer_loop(0) -> ok;
timer_loop(N) ->
    Ref = erlang:send_after(60000, self(), timeout),
    _ = erlang:cancel_timer(Ref),
    timer_loop(N - 1).

gc_dead(N) -> timed(fun() -> gc_dead_loop(N) end).
gc_dead_loop(0) -> ok;
gc_dead_loop(N) ->
    _ = length(cons_loop(16384, [])),
    erlang:garbage_collect(),
    gc_dead_loop(N - 1).

gc_live(N) -> timed(fun() ->
    Live = cons_loop(16384, []),
    gc_live_loop(N, Live)
end).
gc_live_loop(0, Live) -> length(Live);
gc_live_loop(N, Live) ->
    erlang:garbage_collect(),
    gc_live_loop(N - 1, Live).

gen_call(N) ->
    {ok, Server} = gen_server:start_link(?MODULE, [], []),
    Result = timed(fun() -> gen_loop(Server, N) end),
    ok = gen_server:stop(Server),
    Result.
gen_loop(_, 0) -> ok;
gen_loop(Server, N) ->
    pong = gen_server:call(Server, ping),
    gen_loop(Server, N - 1).

init([]) -> {ok, undefined}.
handle_call(ping, _From, State) -> {reply, pong, State}.
handle_cast(_, State) -> {noreply, State}.
handle_info(_, State) -> {noreply, State}.
terminate(_, _) -> ok.
code_change(_, State, _) -> {ok, State}.
