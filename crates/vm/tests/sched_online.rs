//! `+S` scheduler counts: system_info and the scheduler bind checks match erl for the same flags.
use arinsal_difftest::{CallResult, RefErl};
use arinsal_vm::Vm;

const SOURCE: &str = r#"
-module(sched_online).
-export([counts/0]).

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

fn compare(workers: usize, erl_args: &[&str]) {
    let Ok(reference) = RefErl::start_with_erl_args(erl_args) else {
        eprintln!("erl unavailable; skipping scheduler count test");
        return;
    };
    let beam = reference
        .compile_named("sched_online", SOURCE, &[])
        .expect("compile fixture");
    reference
        .load("sched_online", &beam)
        .expect("load reference");
    let expected = reference.call("sched_online", "counts", &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).expect("load VM fixture");
    let actual = vm
        .eval_scheduled("sched_online", "counts", &[], workers, None)
        .expect("eval");
    assert_eq!(expected, CallResult::Ok(actual.term), "{erl_args:?}");
}

#[test]
fn sched_online_plus_s_10_matches_erl() {
    compare(10, &["+S", "10"]);
}

#[test]
fn sched_online_plus_s_3_matches_erl() {
    compare(3, &["+S", "3"]);
}
