//! Replies and DOWN/EXIT messages a BIF sends to its own caller go through the caller's
//! signal in-queue (`erts_queue_message`, `erts_proc_sig_send_monitor_down`,
//! `erts_proc_sig_send_link_exit`), never straight into its message queue: they land after
//! the messages the caller sent itself before, and after a receive marker reserved before the
//! call while unhandled signals sit in the middle queue. Each scenario runs in a fresh process
//! and its result is compared with erl 29.1.1.

use arinsal_difftest::{CallResult, RefErl};
use arinsal_term::Term;
use arinsal_vm::Vm;

const MODULE: &str = "selfpush_diff";
const SOURCE: &str = r#"
-module(selfpush_diff).
-export([all/0]).

run(S) ->
    Parent = self(),
    P = spawn(fun() -> Parent ! {self(), try scenario(S) catch C:E -> {C, E} end} end),
    receive {P, R} -> norm(R) end.

norm(T) when is_reference(T) -> ref;
norm(T) when is_port(T) -> port;
norm(T) when is_list(T) -> [norm(E) || E <- T];
norm(T) when is_tuple(T) -> list_to_tuple(norm(tuple_to_list(T)));
norm(T) -> T.


all() -> [{S, run(S)} || S <- [port_monitor_order, port_monitor_marker, port_monitor_tag, port_monitor_demonitor, port_link_order, port_link_prio, gc_async_marker, gc_async_order, cpc_dead_order, suspend_dead_order, suspend_dead_marker, timer_async_order, group_leader_self]].

dead_pid() -> P = spawn(fun() -> ok end), R = monitor(process, P), receive {'DOWN', R, _, _, _} -> P end.
dead_port() -> P = open_port({spawn, "true"}, []), true = unlink(P), true = port_close(P), P.

first(0) -> [];
first(N) -> receive M -> [M | first(N - 1)] after 1000 -> [timeout] end.

scenario(port_monitor_order) ->
    P = dead_port(), self() ! first, R = monitor(port, P),
    [first, {'DOWN', R, port, P, noproc}] = first(2), ok;
scenario(port_monitor_marker) ->
    P = dead_port(),
    with_pending_signals(fun() -> R = monitor(port, P), receive {'DOWN', R, port, P, Reason} -> Reason after 2000 -> lost end end);
scenario(port_monitor_tag) ->
    P = dead_port(), R = monitor(port, P, [{tag, mytag}]),
    receive {mytag, R, port, P, Reason} -> Reason after 2000 -> lost end;
scenario(port_monitor_demonitor) ->
    P = dead_port(), self() ! first, R = monitor(port, P), Info = demonitor(R, [info]),
    {Info, first(2)};
scenario(port_link_order) ->
    process_flag(trap_exit, true), P = dead_port(), self() ! first, true = link(P),
    first(2);
scenario(port_link_prio) ->
    process_flag(trap_exit, true), P = dead_port(), self() ! first, true = link(P, [priority]),
    first(2);
scenario(gc_async_marker) ->
    with_pending_signals(fun() -> R = make_ref(), async = erlang:garbage_collect(self(), [{async, R}]),
        receive {garbage_collect, R, Res} -> Res after 2000 -> lost end end);
scenario(gc_async_order) ->
    self() ! first, R = make_ref(), async = erlang:garbage_collect(self(), [{async, R}]),
    [first, {garbage_collect, R, true}] = first(2), ok;
scenario(cpc_dead_order) ->
    D = dead_pid(), self() ! first, R = make_ref(),
    async = erlang:check_process_code(D, lists, [{async, R}]),
    [first, {check_process_code, R, false}] = first(2), ok;
scenario(suspend_dead_order) ->
    D = dead_pid(), self() ! first, R = make_ref(),
    Res = try erlang:suspend_process(D, [{asynchronous, R}]) catch C:E -> {C, E} end,
    {Res, first(2)};
scenario(suspend_dead_marker) ->
    D = dead_pid(),
    with_pending_signals(fun() -> R = make_ref(), _ = try erlang:suspend_process(D, [{asynchronous, R}]) catch _:_ -> x end,
        receive {R, X} -> X after 2000 -> lost end end);
scenario(timer_async_order) ->
    TRef = binary_to_term(<<131,90,0,3,100,0,9,"other@foo",0,0,0,1,0,0,0,1,0,0,0,2,0,0,0,3>>),
    self() ! first, ok = erlang:cancel_timer(TRef, [{async, true}, {info, true}]),
    first(2);
scenario(group_leader_self) ->
    GL = group_leader(), R = make_ref(), self() ! first,
    Res = erts_internal:group_leader(GL, self(), R),
    {Res, first(2)}.

%% Exit signals still unhandled in the middle signal queue when the receive marker is
%% reserved: the marker is inserted there, not at the end of the message queue.
with_pending_signals(Fun) ->
    process_flag(trap_exit, true),
    Parent = self(),
    Table = ets:new(flag, [public]),
    spawn(fun() -> [exit(Parent, {x, I}) || I <- lists:seq(1, 20000)], ets:insert(Table, {done}) end),
    spin(Table),
    Res = Fun(),
    {Res, count_exits(0)}.

spin(Table) -> case ets:lookup(Table, done) of [] -> spin(Table); _ -> ok end.
count_exits(C) -> receive {'EXIT', _, {x, _}} -> count_exits(C + 1) after 0 -> C end.
"#;

#[test]
fn self_replies_go_through_the_signal_in_queue() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping self reply differential");
        return;
    };
    let beam = reference.compile_named(MODULE, SOURCE, &[]).unwrap();
    reference.load(MODULE, &beam).unwrap();
    let expected = reference.call(MODULE, "all", &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled(MODULE, "all", &[] as &[Term], 4, None)
        .unwrap_or_else(|error| panic!("{MODULE}:all: {error}"));
    assert_eq!(expected, CallResult::Ok(actual.term));
}
