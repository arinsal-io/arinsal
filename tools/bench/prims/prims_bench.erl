%% Usage: python3 tools/bench/prims/run.py --arinsal PATH
%% The runner compiles this module, then alternates seven in-process samples
%% on OTP 29.1.1 and the supplied Arinsal binary at K=1, 8, and 16 pairs.
%% Each runtime uses 2*K schedulers. Results and raw samples are written to
%% tmp/bench_prims/ as Markdown and JSON. Use --output-dir to change that path.
%% Selective-receive iterations enqueue unrelated messages before the target
%% and drain them afterward so every iteration scans a mailbox of fixed depth.
-module(prims_bench).
-behaviour(gen_server).

-export([run/3]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2,
         code_change/3]).

run(Runtime, K, Round) when is_atom(Runtime), is_integer(K), K > 0,
                            is_integer(Round), Round >= 0 ->
    Rows = run_ops(operations(), 1, K, Round, []),
    case Runtime of
        erts -> print_rows(Rows, Runtime, K, Round), ok;
        _ -> Rows
    end.

run_ops([], _Index, _K, _Round, Rows) ->
    lists:reverse(Rows);
run_ops([Op | Rest], Index, K, Round, Rows) ->
    N = iterations(Op),
    Warm = erlang:min(1000, N),
    _ = parallel(Op, empty, Warm, K),
    _ = parallel(Op, work, Warm, K),
    {EmptyNs, WorkNs} = case (Index + Round) rem 2 of
        0 ->
            {parallel(Op, empty, N, K), parallel(Op, work, N, K)};
        1 ->
            Work = parallel(Op, work, N, K),
            Empty = parallel(Op, empty, N, K),
            {Empty, Work}
    end,
    run_ops(Rest, Index + 1, K, Round, [{Op, N, EmptyNs, WorkNs} | Rows]).

print_rows([], _Runtime, _K, _Round) -> ok;
print_rows([{Op, N, EmptyNs, WorkNs} | Rest], Runtime, K, Round) ->
    io:format("PRIMS|~s|~B|~B|~s|~B|~B|~B~n",
              [atom_to_list(Runtime), K, Round, atom_to_list(Op), N,
               EmptyNs, WorkNs]),
    print_rows(Rest, Runtime, K, Round).

operations() ->
    [monitor_demonitor, link_unlink, spawn_link_exit, spawn_monitor_down,
     ping_atom, ping_tuple, ping_list_100, ping_binary_1k, ping_binary_64k,
     ping_map_20, selective_last_10, selective_last_100, make_ref_receive,
     send_after_cancel, gen_server_call, ets_lookup_insert_1000].

iterations(monitor_demonitor) -> 50000;
iterations(link_unlink) -> 50000;
iterations(spawn_link_exit) -> 5000;
iterations(spawn_monitor_down) -> 5000;
iterations(ping_atom) -> 20000;
iterations(ping_tuple) -> 20000;
iterations(ping_list_100) -> 5000;
iterations(ping_binary_1k) -> 5000;
iterations(ping_binary_64k) -> 16;
iterations(ping_map_20) -> 20000;
iterations(selective_last_10) -> 1000;
iterations(selective_last_100) -> 200;
iterations(make_ref_receive) -> 20000;
iterations(send_after_cancel) -> 2000;
iterations(gen_server_call) -> 5000;
iterations(ets_lookup_insert_1000) -> 20000.

parallel(Op, Mode, N, K) ->
    Parent = self(),
    Workers = [spawn(fun() -> worker(Parent, Op, Mode, N) end)
               || _ <- lists:seq(1, K)],
    wait_messages(ready, K),
    Start = erlang:monotonic_time(nanosecond),
    [Pid ! go || Pid <- Workers],
    wait_messages(done, K),
    Stop = erlang:monotonic_time(nanosecond),
    [Pid ! cleanup || Pid <- Workers],
    wait_messages(cleaned, K),
    Stop - Start.

worker(Parent, Op, Mode, N) ->
    State = setup(Op),
    Parent ! ready,
    receive
        go ->
            execute(Mode, Op, N, State),
            Parent ! done,
            receive cleanup ->
                teardown(Op, State),
                Parent ! cleaned
            end
    end.

wait_messages(_Message, 0) ->
    ok;
wait_messages(Message, Count) ->
    receive Message -> wait_messages(Message, Count - 1) end.

setup(monitor_demonitor) -> spawn(fun idle_peer/0);
setup(link_unlink) -> spawn(fun idle_peer/0);
setup(ping_atom) -> ping_setup(ping);
setup(ping_tuple) -> ping_setup({ping, 1, ok});
setup(ping_list_100) -> ping_setup(lists:seq(1, 100));
setup(ping_binary_1k) -> ping_setup(binary:copy(<<0>>, 1024));
setup(ping_binary_64k) -> ping_setup(binary:copy(<<0>>, 65536));
setup(ping_map_20) -> ping_setup(maps:from_list([{I, I} || I <- lists:seq(1, 20)]));
setup(spawn_link_exit) ->
    process_flag(trap_exit, true),
    undefined;
setup(gen_server_call) ->
    {ok, Pid} = gen_server:start_link(?MODULE, [], []),
    Pid;
setup(ets_lookup_insert_1000) ->
    Tab = ets:new(prims_bench, [set, public]),
    true = ets:insert(Tab, [{I, I} || I <- lists:seq(1, 1000)]),
    Tab;
setup(_Op) -> undefined.

ping_setup(Message) ->
    Parent = self(),
    Peer = spawn(fun() -> echo_peer(Parent) end),
    {Peer, Message}.

idle_peer() ->
    receive
        {bench_stop, Parent, Ref} -> Parent ! {bench_stopped, Ref};
        _ -> idle_peer()
    end.

echo_peer(Parent) ->
    receive
        {bench_stop, From, Ref} -> From ! {bench_stopped, Ref};
        Message ->
            Parent ! Message,
            echo_peer(Parent)
    end.

teardown(monitor_demonitor, Pid) -> stop_peer(Pid);
teardown(link_unlink, Pid) -> stop_peer(Pid);
teardown(ping_atom, {Pid, _}) -> stop_peer(Pid);
teardown(ping_tuple, {Pid, _}) -> stop_peer(Pid);
teardown(ping_list_100, {Pid, _}) -> stop_peer(Pid);
teardown(ping_binary_1k, {Pid, _}) -> stop_peer(Pid);
teardown(ping_binary_64k, {Pid, _}) -> stop_peer(Pid);
teardown(ping_map_20, {Pid, _}) -> stop_peer(Pid);
teardown(gen_server_call, Pid) -> gen_server:stop(Pid);
teardown(ets_lookup_insert_1000, Tab) -> ets:delete(Tab);
teardown(_Op, _State) -> ok.

stop_peer(Pid) ->
    Ref = make_ref(),
    Pid ! {bench_stop, self(), Ref},
    receive {bench_stopped, Ref} -> ok end.

execute(empty, _Op, N, _State) -> empty_loop(N);
execute(work, monitor_demonitor, N, Pid) -> monitor_demonitor_loop(N, Pid);
execute(work, link_unlink, N, Pid) -> link_unlink_loop(N, Pid);
execute(work, spawn_link_exit, N, _State) -> spawn_link_exit_loop(N);
execute(work, spawn_monitor_down, N, _State) -> spawn_monitor_down_loop(N);
execute(work, ping_atom, N, {Pid, Message}) -> ping_loop(N, Pid, Message);
execute(work, ping_tuple, N, {Pid, Message}) -> ping_loop(N, Pid, Message);
execute(work, ping_list_100, N, {Pid, Message}) -> ping_loop(N, Pid, Message);
execute(work, ping_binary_1k, N, {Pid, Message}) -> ping_loop(N, Pid, Message);
execute(work, ping_binary_64k, N, {Pid, Message}) -> ping_loop(N, Pid, Message);
execute(work, ping_map_20, N, {Pid, Message}) -> ping_loop(N, Pid, Message);
execute(work, selective_last_10, N, _State) -> selective_loop(N, 10);
execute(work, selective_last_100, N, _State) -> selective_loop(N, 100);
execute(work, make_ref_receive, N, _State) -> make_ref_loop(N);
execute(work, send_after_cancel, N, _State) -> send_after_loop(N);
execute(work, gen_server_call, N, Pid) -> gen_server_loop(N, Pid);
execute(work, ets_lookup_insert_1000, N, Tab) -> ets_loop(N, Tab).

empty_loop(0) -> ok;
empty_loop(N) -> empty_loop(N - 1).

monitor_demonitor_loop(0, _Pid) -> ok;
monitor_demonitor_loop(N, Pid) ->
    Ref = erlang:monitor(process, Pid),
    _ = erlang:demonitor(Ref, [flush]),
    monitor_demonitor_loop(N - 1, Pid).

link_unlink_loop(0, _Pid) -> ok;
link_unlink_loop(N, Pid) ->
    true = link(Pid),
    true = unlink(Pid),
    link_unlink_loop(N - 1, Pid).

spawn_link_exit_loop(0) -> ok;
spawn_link_exit_loop(N) ->
    Pid = spawn_link(fun() -> ok end),
    receive {'EXIT', Pid, normal} -> spawn_link_exit_loop(N - 1) end.

spawn_monitor_down_loop(0) -> ok;
spawn_monitor_down_loop(N) ->
    {Pid, Ref} = spawn_monitor(fun() -> ok end),
    receive {'DOWN', Ref, process, Pid, normal} -> spawn_monitor_down_loop(N - 1) end.

ping_loop(0, _Pid, _Message) -> ok;
ping_loop(N, Pid, Message) ->
    Pid ! Message,
    receive Message -> ping_loop(N - 1, Pid, Message) end.

selective_loop(0, _Count) -> ok;
selective_loop(N, Count) ->
    send_noise(Count - 1, N),
    self() ! {target, N},
    receive {target, N} -> ok end,
    drain_noise(Count - 1, N),
    selective_loop(N - 1, Count).

send_noise(0, _Tag) -> ok;
send_noise(Count, Tag) ->
    self() ! {noise, Tag, Count},
    send_noise(Count - 1, Tag).

drain_noise(0, _Tag) -> ok;
drain_noise(Count, Tag) ->
    receive {noise, Tag, _} -> drain_noise(Count - 1, Tag) end.

make_ref_loop(0) -> ok;
make_ref_loop(N) ->
    Ref = make_ref(),
    self() ! {Ref, ok},
    receive {Ref, ok} -> make_ref_loop(N - 1) end.

send_after_loop(0) -> ok;
send_after_loop(N) ->
    Timer = erlang:send_after(60000, self(), {bench_timeout, N}),
    _ = erlang:cancel_timer(Timer),
    send_after_loop(N - 1).

gen_server_loop(0, _Pid) -> ok;
gen_server_loop(N, Pid) ->
    ok = gen_server:call(Pid, ping),
    gen_server_loop(N - 1, Pid).

ets_loop(0, _Tab) -> ok;
ets_loop(N, Tab) ->
    Key = (N rem 1000) + 1,
    [{Key, Value}] = ets:lookup(Tab, Key),
    true = ets:insert(Tab, {Key, Value + 1}),
    ets_loop(N - 1, Tab).

init([]) -> {ok, 0}.
handle_call(ping, _From, State) -> {reply, ok, State + 1};
handle_call(_Request, _From, State) -> {reply, ok, State}.
handle_cast(_Request, State) -> {noreply, State}.
handle_info(_Info, State) -> {noreply, State}.
terminate(_Reason, _State) -> ok.
code_change(_OldVersion, State, _Extra) -> {ok, State}.
