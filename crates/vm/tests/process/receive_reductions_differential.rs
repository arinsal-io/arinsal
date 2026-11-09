//! Reductions charged by `receive`, signal handling at schedule-in and the spawn, monitor and
//! link signals a receive waits for, against OTP 29.1.1. Every case runs in a fresh process
//! with a heap large enough that no collection falls in the window, stays inside one
//! scheduler slice, and must match erts exactly.

use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_vm::Vm;
use similar_asserts::assert_eq;

const MODULE: &str = "receive_reductions_test";

const SOURCE: &str = r#"-module(receive_reductions_test).
-export([queued_1/0, queued_100/0, selective_skip_100/0, after0_empty/0, after0_hit/0,
         ping_pong_100/0, call_marker_100/0,
         spawn_monitor_down/0, spawn_monitor_down_x50/0, spawn_monitor_yield_down/0,
         link_exit_signal/0, link_exit_signal_x50/0, monitor_noproc/0, exit_signal_to_self/0,
         wait_for_second_message/0, two_sends/1]).

queued_1() -> measure(fun() -> fill(1) end, fun(N) -> drain(N) end).
queued_100() -> measure(fun() -> fill(100) end, fun(N) -> drain(N) end).

selective_skip_100() ->
    measure(fun() -> fill(100), self() ! target, ok end,
            fun(_) -> receive target -> ok end end).

after0_empty() ->
    measure(fun() -> ok end, fun(_) -> receive _ -> ok after 0 -> timeout end end).

after0_hit() ->
    measure(fun() -> self() ! x end, fun(_) -> receive _ -> ok after 0 -> timeout end end).

ping_pong_100() ->
    measure(fun() -> spawn(fun() -> echo() end) end,
            fun(P) -> ping_pong(P, 100), P ! stop end).

call_marker_100() ->
    measure(fun() -> spawn(fun() -> echo_ref() end) end,
            fun(P) -> call_loop(P, 100), P ! stop end).

spawn_monitor_down() ->
    measure(fun() -> ok end, fun(_) -> spawn_down() end).

spawn_monitor_down_x50() ->
    measure(fun() -> 50 end, fun(N) -> spawn_down_loop(N) end).

spawn_monitor_yield_down() ->
    measure(fun() -> ok end,
            fun(_) ->
                {_, Ref} = spawn_monitor(fun() -> ok end),
                erlang:yield(),
                receive {'DOWN', Ref, _, _, _} -> ok end
            end).

link_exit_signal() ->
    measure(fun() -> process_flag(trap_exit, true) end, fun(_) -> link_exit() end).

link_exit_signal_x50() ->
    measure(fun() -> process_flag(trap_exit, true), 50 end, fun(N) -> link_exit_loop(N) end).

monitor_noproc() ->
    measure(fun() -> ok end,
            fun(_) ->
                Ref = erlang:monitor(process, receive_reductions_unregistered),
                receive {'DOWN', Ref, _, _, _} -> ok end
            end).

exit_signal_to_self() ->
    measure(fun() -> process_flag(trap_exit, true) end,
            fun(_) ->
                P = spawn(fun() -> receive stop -> ok end end),
                link(P),
                exit(P, boom),
                receive {'EXIT', P, boom} -> ok end
            end).

wait_for_second_message() ->
    measure(fun() -> self() end,
            fun(Me) ->
                spawn(receive_reductions_test, two_sends, [Me]),
                receive a -> ok end,
                receive b -> ok end
            end).

fill(N) -> [self() ! {m, I} || I <- lists:seq(1, N)], N.

drain(0) -> ok;
drain(N) -> receive {m, _} -> drain(N - 1) end.

two_sends(Pid) -> Pid ! a, Pid ! b.

echo() -> receive {From, X} -> From ! X, echo(); stop -> ok end.

ping_pong(_, 0) -> ok;
ping_pong(P, N) -> P ! {self(), N}, receive N -> ping_pong(P, N - 1) end.

echo_ref() -> receive {From, Ref, X} -> From ! {Ref, X}, echo_ref(); stop -> ok end.

call_loop(_, 0) -> ok;
call_loop(P, N) ->
    Ref = make_ref(),
    P ! {self(), Ref, N},
    receive {Ref, _} -> call_loop(P, N - 1) end.

spawn_down() ->
    {_, Ref} = spawn_monitor(fun() -> ok end),
    receive {'DOWN', Ref, _, _, _} -> ok end.

spawn_down_loop(0) -> ok;
spawn_down_loop(N) -> spawn_down(), spawn_down_loop(N - 1).

link_exit() ->
    P = spawn_link(fun() -> exit(boom) end),
    receive {'EXIT', P, boom} -> ok end.

link_exit_loop(0) -> ok;
link_exit_loop(N) -> link_exit(), link_exit_loop(N - 1).

measure(Setup, Fun) ->
    Parent = self(),
    {Pid, Ref} =
        spawn_opt(fun() ->
            State = Setup(),
            erlang:yield(),
            {reductions, R0} = process_info(self(), reductions),
            _ = Fun(State),
            {reductions, R1} = process_info(self(), reductions),
            {reductions, E0} = process_info(self(), reductions),
            {reductions, E1} = process_info(self(), reductions),
            Parent ! {measured, self(), (R1 - R0) - (E1 - E0)}
        end, [monitor, {min_heap_size, 2000000}]),
    receive
        {measured, Pid, Reds} ->
            receive {'DOWN', Ref, _, _, _} -> ok end,
            Reds
    after 10000 -> timeout
    end.
"#;

const CASES: &[&str] = &[
    "queued_1",
    "queued_100",
    "selective_skip_100",
    "after0_empty",
    "after0_hit",
    "ping_pong_100",
    "call_marker_100",
    "spawn_monitor_down",
    "spawn_monitor_down_x50",
    "spawn_monitor_yield_down",
    "link_exit_signal",
    "link_exit_signal_x50",
    "monitor_noproc",
    "exit_signal_to_self",
    "wait_for_second_message",
];

fn reductions(term: &OwnedTerm) -> i64 {
    match term {
        OwnedTerm::Int(reds) => *reds,
        other => panic!("probe returned {other:?}"),
    }
}

#[test]
fn receive_and_signal_reductions_match_otp() {
    let reference = RefErl::start().expect("OTP 29.1.1 is required for this test");
    let beam = reference.compile_named(MODULE, SOURCE, &[]).unwrap();
    reference.load(MODULE, &beam).unwrap();
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();

    let mut mismatches = Vec::new();
    for (index, function) in CASES.iter().enumerate() {
        let CallResult::Ok(expected) = reference.call(MODULE, function, &[]) else {
            panic!("OTP {function} failed");
        };
        let actual = vm
            .eval_scheduled_reductions(MODULE, function, &[], 1, Some(0xB400 + index as u64), 4_000)
            .unwrap();
        let (expected, actual) = (reductions(&expected), reductions(&actual.term));
        if expected != actual {
            mismatches.push(format!("{function}: OTP {expected}, Arinsal {actual}"));
        }
    }
    assert_eq!(Vec::<String>::new(), mismatches);
}
