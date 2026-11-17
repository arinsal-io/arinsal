//! A collection that erts_schedule delays to a dirty scheduler at schedule-in sends the process
//! out at once: it runs no instruction on the normal scheduler. Compared with erts through the
//! scheduling, receive and GC trace (the dirty collection's reductions are time-based).
//!
//! The `in` event precedes the collection: erts_schedule calls `trace_schedule_in` (line 10292)
//! before the GC block, so a delayed collection yields `in`, then `out`, and no instruction runs
//! between them.
//!
//! Port of erts/emulator/beam/erl_process.c:10415-10428 (erts_schedule: `scheduler_gc_proc`,
//! `goto sched_out_proc` on F_DIRTY_MAJOR_GC/F_DIRTY_MINOR_GC), OTP-29.1.1.

use arinsal_difftest::{CallResult, RefErl};

const SOURCE: &str = r#"
-module(sched_in_dirty_gc).
-export([run/0]).

%% P waits with a heap over ERTS_POTENTIALLY_LONG_GC_HSIZE. A big on-heap message makes the
%% collection desired when P is scheduled in, and long, so it moves to a dirty CPU scheduler.
run() ->
    [case_(N) || N <- [150000, 300000]].

case_(N) ->
    Parent = self(),
    P = spawn_opt(fun() ->
        L = lists:seq(1, N),
        Parent ! ready,
        receive {big, M} ->
            spin(20000),
            {reductions, R} = process_info(self(), reductions),
            Parent ! {done, R, length(L), length(M) div 3}
        end,
        receive stop -> ok end
    end, [{message_queue_data, on_heap}]),
    receive ready -> ok end,
    receive after 50 -> ok end,
    {reductions, R0} = process_info(P, reductions),
    erlang:trace(P, true, ['receive', garbage_collection, running, {tracer, self()}]),
    P ! {big, lists:seq(1, 3 * N)},
    %% The request signal makes P handle its signals at schedule-in, so the big message is
    %% fetched there and the collection is desired before P runs.
    _ = process_info(P, message_queue_len),
    receive {done, R1, Len, MLen} ->
        receive after 50 -> ok end,
        erlang:trace(P, false, ['receive', garbage_collection, running]),
        Events = flush([]),
        P ! stop,
        {N, Len, MLen, R1 > R0, Events}
    end.

spin(0) -> ok;
spin(N) -> spin(N - 1).

flush(Acc) ->
    receive
        {trace, _, in, _} -> flush([in | Acc]);
        {trace, _, out, _} -> flush([out | Acc]);
        {trace, _, 'receive', _} -> flush(['receive' | Acc]);
        {trace, _, Gc, _} -> flush([Gc | Acc])
    after 0 -> lists:reverse(Acc)
    end.
"#;

#[test]
fn delayed_schedule_in_gc_runs_no_instruction_on_the_normal_scheduler() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping schedule-in dirty GC differential test");
        return;
    };
    let beam = reference
        .compile_named("sched_in_dirty_gc", SOURCE, &[])
        .expect("compile sched_in_dirty_gc");
    reference
        .load("sched_in_dirty_gc", &beam)
        .expect("load into erl");
    let expected = reference.call("sched_in_dirty_gc", "run", &[]);
    let actual = crate::common::peer_eval(&[], &[&beam], "sched_in_dirty_gc:run()");
    eprintln!("erl: {expected:?}\narinsal: {actual:?}");
    similar_asserts::assert_eq!(expected, CallResult::Ok(actual));
}
