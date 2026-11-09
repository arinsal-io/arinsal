//! `+S` scheduler counts: system_info and the scheduler bind checks match erl for the same flags.
use arinsal_difftest::{CallResult, RefErl};
use arinsal_vm::Vm;

const SOURCE: &str = r#"
-module(sched_online).
-export([counts/0, spawn_order/0]).

%% A child spawned before a process the parent then wakes runs first (FIFO run queue), so the
%% child has blocked in its receive before the woken process traces it.
spawn_order() ->
    lists:sum([spawn_order_one() || _ <- lists:seq(1, 100)]).

spawn_order_one() ->
    Me = self(),
    Tr = spawn(fun L() -> receive {apply, From, F} -> From ! {r, F()}, L() end end),
    timer:sleep(1),
    P = spawn_link(erlang, apply, [fun() -> receive _ -> ok end end, []]),
    Tr ! {apply, Me, fun() -> erlang:trace(P, true, [running, {tracer, Me}]) end},
    receive {r, _} -> ok end,
    P ! hi,
    R = receive {trace, P, in, {erlang, apply, 2}} -> 1; {trace, P, in, _} -> 0
        after 1000 -> 0 end,
    unlink(P), exit(P, kill), exit(Tr, kill), R.

counts() ->
    Self = self(),
    Total = erlang:system_info(schedulers),
    Spawn = fun(N) ->
        try spawn_opt(fun() -> Self ! {done, N} end, [{scheduler, N}]) of
            _ -> receive {done, N} -> ok after 5000 -> timeout end
        catch error:R -> R end
    end,
    {[erlang:system_info(K) || K <- [schedulers, schedulers_online,
                                     dirty_cpu_schedulers, dirty_cpu_schedulers_online,
                                     dirty_io_schedulers]],
     [Spawn(N) || N <- [0, 1, Total, Total + 1]]}.
"#;

#[test]
fn sched_online_spawned_child_runs_before_a_later_woken_process() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping spawn order test");
        return;
    };
    let beam = reference
        .compile_named("sched_online", SOURCE, &[])
        .expect("compile fixture");
    reference
        .load("sched_online", &beam)
        .expect("load reference");
    let expected = reference.call("sched_online", "spawn_order", &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).expect("load VM fixture");
    let actual = vm
        .eval_scheduled("sched_online", "spawn_order", &[], 4, None)
        .expect("eval");
    assert_eq!(expected, CallResult::Ok(actual.term));
}
