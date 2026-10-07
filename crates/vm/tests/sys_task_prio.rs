//! System tasks run at the requester's priority: a task requested by a high-priority
//! process on a low-priority target executes even while higher-priority processes keep
//! every scheduler busy (process_SUITE no_priority_inversion, no_priority_inversion2).

use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_term::Term;
use arinsal_vm::Vm;

const SOURCE: &str = r#"
-module(sys_task_prio).
-export([run/1]).
run(0) ->
    %% A max-priority caller gets check_process_code/GC answers from a starved
    %% low-priority process while high-priority hogs occupy every scheduler.
    Prio = process_flag(priority, max),
    Hogs = hogs(high, true),
    Low = spawn_opt(fun loop/0, [{priority, low}, link]),
    Cpc = erlang:check_process_code(Low, nonexisting_module),
    Gc = erlang:garbage_collect(Low),
    kill([Low | Hogs]),
    process_flag(priority, Prio),
    {Cpc, Gc};
run(1) ->
    %% Tasks below the hogs' priority wait; the max task runs at once.
    Prio = process_flag(priority, max),
    Hogs = hogs(max, true),
    Low = spawn_opt(fun loop/0, [{priority, low}, link]),
    [RL, RN, RH] = [request(Low, P) || P <- [low, normal, high]],
    Early = receive {system_task_test, _, _} -> early after 500 -> none end,
    RM = request(Low, max),
    Max = receive {system_task_test, RM, M} -> M end,
    kill(Hogs),
    Rest = [receive {system_task_test, R, V} -> V end || R <- [RH, RN, RL]],
    kill([Low]),
    process_flag(priority, Prio),
    {Early, Max, Rest};
run(2) ->
    %% process_flag(priority, _) changes scheduling: unbound max hogs do not starve
    %% a max caller.
    Prio = process_flag(priority, max),
    Hogs = hogs(max, false),
    Now = process_info(self(), priority),
    kill(Hogs),
    {Prio, Now, process_flag(priority, Prio)}.

hogs(Prio, Bound) ->
    Master = self(),
    Hogs = [spawn_opt(fun() -> Master ! {self(), running}, loop() end,
                      [{priority, Prio}, link | [{scheduler, S} || Bound]])
            || S <- lists:seq(1, erlang:system_info(schedulers_online))],
    [receive {H, running} -> ok end || H <- Hogs],
    Hogs.

request(Pid, Prio) ->
    Ref = make_ref(),
    ok = erts_internal:request_system_task(Pid, Prio, {system_task_test, Ref}),
    Ref.

kill(Pids) ->
    Ms = [begin unlink(P), M = monitor(process, P), exit(P, kill), {P, M} end || P <- Pids],
    [receive {'DOWN', M, process, P, killed} -> ok end || {P, M} <- Ms],
    ok.

loop() -> loop().
"#;

#[test]
fn system_tasks_run_at_requester_priority() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping system task priority differential test");
        return;
    };
    let beam = reference
        .compile_named("sys_task_prio", SOURCE, &[])
        .unwrap();
    reference.load("sys_task_prio", &beam).unwrap();
    // `schedulers_online` reports the host's cores, as on the reference node.
    let workers = std::thread::available_parallelism().map_or(2, usize::from);
    for scenario in 0..3 {
        let expected = reference.call("sys_task_prio", "run", &[OwnedTerm::Int(scenario)]);
        let mut vm = Vm::new([]);
        vm.load_bytes(&beam).unwrap();
        let actual = vm.eval_scheduled(
            "sys_task_prio",
            "run",
            &[Term::small(scenario).unwrap()],
            workers,
            None,
        );
        assert_eq!(
            expected,
            CallResult::Ok(
                actual
                    .unwrap_or_else(|error| panic!("scenario {scenario}: {error}"))
                    .term
            ),
            "scenario {scenario}"
        );
    }
}
