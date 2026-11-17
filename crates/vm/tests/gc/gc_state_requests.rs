//! Asynchronous garbage_collect requests to a process with GC disabled and to unstarted processes.

use arinsal_difftest::{CallResult, RefErl};
use similar_asserts::assert_eq;

const MODULE: &str = "gc_state_requests";
const SOURCE: &str = r#"
-module(gc_state_requests).
-export([deferred/0, unstarted/0, drain_with_delayed/0]).
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
drain_with_delayed() ->
    erts_debug:set_internal_state(available_internal_state, true),
    Master = self(),
    P = spawn(fun () ->
        L = [{I, integer_to_list(I), make_ref()} || I <- lists:seq(1, 300)],
        Hash = erlang:phash2([{I, S} || {I, S, _} <- L]),
        true = erts_debug:set_internal_state(gc_state, false),
        Master ! {self(), gc_state, false},
        receive go -> ok end,
        false = erts_debug:set_internal_state(gc_state, true),
        %% process_info/2 drains the signal queue from a BIF with live registers while the
        %% delayed GC requests are due: they must wait for a scheduling point.
        Infos = [begin
                     {messages, _} = process_info(self(), messages),
                     {message_queue_len, _} = process_info(self(), message_queue_len),
                     I
                 end || I <- lists:seq(1, 200)],
        Ok = Hash =:= erlang:phash2([{I, S} || {I, S, _} <- L]),
        receive after 100 -> ok end,
        Master ! {self(), done, Ok, length(Infos), length(L)}
    end),
    receive {P, gc_state, false} -> ok end,
    Refs = [make_ref() || _ <- lists:seq(1, 20)],
    lists:foreach(fun (Ref) -> async = garbage_collect(P, [{async, Ref}]) end, Refs),
    P ! go,
    Replies = [receive {garbage_collect, Ref, R} -> R after 5000 -> timeout end || Ref <- Refs],
    Done = receive {P, done, Ok, N, M} -> {Ok, N, M} after 5000 -> timeout end,
    {Replies, Done}.
unstarted() ->
    process_flag(priority, high),
    Ps = [spawn_opt(fun() -> receive stop -> ok end end, [{priority, low}, monitor])
          || _ <- lists:seq(1, 10)],
    lists:foreach(fun ({P, _}) -> true = erlang:garbage_collect(P) end, Ps),
    lists:foreach(fun ({P, _}) -> P ! stop end, Ps),
    [receive {'DOWN', M, process, P, Reason} -> Reason end || {P, M} <- Ps].
"#;

fn assert_equal(function: &str) {
    assert_equal_with_flags(function, &[]);
}

fn assert_equal_with_flags(function: &str, flags: &[&str]) {
    let reference = RefErl::start_with_erl_args(flags).expect("OTP 29.1.1");
    let beam = reference.compile_named(MODULE, SOURCE, &[]).unwrap();
    reference.load(MODULE, &beam).unwrap();
    let expected = reference.call(MODULE, function, &[]);
    let actual = crate::common::peer_eval(flags, &[&beam], &format!("{MODULE}:{function}()"));
    assert_eq!(expected, CallResult::Ok(actual), "{function}");
}

#[test]
fn async_gc_request_waits_for_gc_to_be_enabled() {
    assert_equal("deferred");
}

#[test]
fn gc_before_first_run_keeps_initial_fun_alive() {
    assert_equal_with_flags("unstarted", &["+S", "1"]);
}

#[test]
fn bif_signal_drain_leaves_delayed_gc_to_scheduling_point() {
    assert_equal("drain_with_delayed");
}
