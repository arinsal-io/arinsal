//! Native `loop_rec` fetches the outer signal queue before a receive waits or times out,
//! like erts_proc_sig_receive_helper.

use arinsal_difftest::{CallResult, RefErl};
use arinsal_vm::Vm;

const SOURCE: &str = r#"
-module(native_sig_fetch).
-export([self_after0/0, other_after0/0, selective_after_n/0, exit_pending/0,
         link_monitor_flood/0, trapped_exits/0, mixed_flood/0]).

self_after0() -> r2(hello, 0).

r2(Msg, T) ->
    self() ! Msg,
    receive Msg -> got after T -> timeout end.

%% Spin without receiving until N senders are done, so their signals sit in the outer queue.
spin(A, N) ->
    case atomics:get(A, 1) of
        N -> ok;
        _ -> spin(A, N)
    end.

%% The sender is done before the receive, so its message is in some queue of the receiver.
other_after0() ->
    Self = self(),
    A = atomics:new(1, []),
    spawn(fun() -> Self ! from_other, atomics:add(A, 1, 1) end),
    spin(A, 1),
    receive from_other -> got after 0 -> timeout end.

selective_after_n() ->
    Self = self(),
    A = atomics:new(1, []),
    self() ! first,
    [spawn(fun() -> Self ! {n, I}, atomics:add(A, 1, 1) end) || I <- lists:seq(1, 20)],
    spin(A, 20),
    Last = receive {n, 20} = M -> M after 10 -> timeout end,
    Rest = drain0([]),
    {Last, lists:sort(Rest)}.

drain0(Acc) ->
    receive M -> drain0([M | Acc]) after 0 -> Acc end.

exit_pending() ->
    Self = self(),
    A = atomics:new(1, []),
    {P, Ref} = spawn_monitor(fun() ->
        atomics:add(A, 1, 1),
        spin(A, 2),
        R = receive _ -> got after 0 -> timeout end,
        Self ! {result, R}
    end),
    spin(A, 1),
    P ! a_message,
    exit(P, die),
    atomics:add(A, 1, 1),
    Down = receive {'DOWN', Ref, process, P, Reason} -> Reason end,
    {Down, drain0([])}.

link_monitor_flood() ->
    Self = self(),
    A = atomics:new(1, []),
    N = 500,
    Before = {process_info(self(), links), process_info(self(), monitored_by)},
    [spawn(fun() ->
         link(Self),
         Ref = monitor(process, Self),
         unlink(Self),
         demonitor(Ref),
         Self ! {hi, I},
         atomics:add(A, 1, 1)
     end) || I <- lists:seq(1, N)],
    spin(A, N),
    Count = count(0),
    After = {process_info(self(), links), process_info(self(), monitored_by)},
    {Count, Before =:= After}.

count(C) ->
    receive {hi, _} -> count(C + 1) after 0 -> C end.

trapped_exits() ->
    process_flag(trap_exit, true),
    Self = self(),
    A = atomics:new(1, []),
    N = 100,
    [spawn(fun() -> link(Self), atomics:add(A, 1, 1), exit({bye, I}) end)
     || I <- lists:seq(1, N)],
    spin(A, N),
    %% The exits may still be in flight after the counter; wait for all of them.
    Exits = collect_exits(N, []),
    process_flag(trap_exit, false),
    {length(Exits), lists:sort(Exits) =:= [{bye, I} || I <- lists:seq(1, N)]}.

collect_exits(0, Acc) -> Acc;
collect_exits(N, Acc) ->
    receive {'EXIT', _, Reason} -> collect_exits(N - 1, [Reason | Acc])
    after 0 -> collect_exits_wait(N, Acc)
    end.

collect_exits_wait(N, Acc) ->
    receive {'EXIT', _, Reason} -> collect_exits(N - 1, [Reason | Acc])
    after 5000 -> {missing, N, Acc}
    end.

%% Non-message signals (link, unlink, monitor, demonitor) in front of a message in
%% the outer queue: a receive with `after 0` must still see the message.
mixed_flood() ->
    Self = self(),
    A = atomics:new(1, []),
    N = 200,
    [spawn(fun() ->
         [begin link(Self), unlink(Self) end || _ <- lists:seq(1, 10)],
         atomics:add(A, 1, 1)
     end) || _ <- lists:seq(1, N)],
    spin(A, N),
    self() ! last,
    receive last -> got after 0 -> timeout end.
"#;

fn compare(function: &str) {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping {function} native signal fetch test");
        return;
    };
    let beam = reference
        .compile_named("native_sig_fetch", SOURCE, &[])
        .unwrap();
    reference.load("native_sig_fetch", &beam).unwrap();
    let expected = reference.call("native_sig_fetch", function, &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled("native_sig_fetch", function, &[], 2, Some(0x5f37))
        .unwrap_or_else(|error| panic!("{function}: {error}"));
    assert_eq!(expected, CallResult::Ok(actual.term), "{function}");
}

#[test]
fn native_sig_fetch_self_send_after_zero() {
    compare("self_after0");
}

#[test]
fn native_sig_fetch_other_send_after_zero() {
    compare("other_after0");
}

#[test]
fn native_sig_fetch_selective_after_n() {
    compare("selective_after_n");
}

#[test]
fn native_sig_fetch_exit_signal_pending() {
    compare("exit_pending");
}

#[test]
fn native_sig_fetch_link_monitor_flood() {
    compare("link_monitor_flood");
}

#[test]
fn native_sig_fetch_trapped_exits() {
    compare("trapped_exits");
}

#[test]
fn native_sig_fetch_mixed_signal_flood() {
    compare("mixed_flood");
}
