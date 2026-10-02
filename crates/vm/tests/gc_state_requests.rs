//! Asynchronous garbage_collect requests to a process with GC disabled and to unstarted processes.

use arinsal_difftest::{CallResult, RefErl};
use arinsal_vm::Vm;

const MODULE: &str = "gc_state_requests";
const SOURCE: &str = r#"
-module(gc_state_requests).
-export([deferred/0, unstarted/0]).
deferred() ->
    erts_debug:set_internal_state(available_internal_state, true),
    Master = self(),
    P = spawn(fun () ->
        true = erts_debug:set_internal_state(gc_state, false),
        Master ! {self(), gc_state, false},
        receive after 300 -> ok end,
        Master ! {self(), gc_state, true},
        false = erts_debug:set_internal_state(gc_state, true),
        receive after 100 -> ok end
    end),
    receive {P, gc_state, false} -> ok end,
    Ref = make_ref(),
    async = garbage_collect(P, [{async, Ref}]),
    First = receive
        {garbage_collect, Ref, R} -> {early_reply, R};
        {P, gc_state, true} -> reenabled
    end,
    Reply = receive {garbage_collect, Ref, true} -> true after 5000 -> timeout end,
    {First, Reply}.
tok() -> tok(200000).
tok(0) -> ok;
tok(N) -> tok(N - 1).
unstarted() ->
    process_flag(priority, high),
    Ps = [spawn_opt(fun tok/0, [{priority, low}, monitor]) || _ <- lists:seq(1, 10)],
    lists:foreach(fun ({P, _}) -> true = erlang:garbage_collect(P) end, Ps),
    [receive {'DOWN', M, process, P, Reason} -> Reason end || {P, M} <- Ps].
"#;

fn assert_equal(function: &str) {
    let reference = RefErl::start().expect("OTP 29.1.1");
    let beam = reference.compile_named(MODULE, SOURCE, &[]).unwrap();
    reference.load(MODULE, &beam).unwrap();
    let expected = reference.call(MODULE, function, &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled(MODULE, function, &[], 1, Some(82))
        .map(|outcome| CallResult::Ok(outcome.term))
        .unwrap_or_else(|error| CallResult::TransportError(format!("{error:?}")));
    assert_eq!(expected, actual, "{function}");
}

#[test]
fn async_gc_request_waits_for_gc_to_be_enabled() {
    assert_equal("deferred");
}

#[test]
fn gc_before_first_run_keeps_initial_fun_alive() {
    assert_equal("unstarted");
}
