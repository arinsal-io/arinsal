//! Differential tests for dirty CPU and dirty I/O schedulers (task dirty_sched).

use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_term::Term;
use arinsal_vm::Vm;

const SOURCE: &str = r##"
-module(dirty_sched).
-export([run/1]).

err(F) ->
    try F() of
        Value -> {ok, Value}
    catch
        Class:Reason -> {Class, Reason}
    end.

run(0) ->
    {erts_debug:dirty_cpu(scheduler, type),
     erts_debug:dirty_io(scheduler, type),
     erts_debug:dirty(normal, scheduler, type),
     erts_debug:dirty(dirty_cpu, scheduler, type),
     erts_debug:dirty(dirty_io, scheduler, type),
     erlang:apply(erts_debug, dirty_cpu, [scheduler, type]),
     erlang:apply(erts_debug, dirty_io, [scheduler, type]),
     [erts_debug:dirty_io(scheduler, type) || _ <- lists:seq(1, 3)]};

run(1) ->
    {erlang:system_info(dirty_cpu_schedulers),
     erlang:system_info(dirty_cpu_schedulers_online),
     erlang:system_info(dirty_io_schedulers)};

run(2) ->
    Me = self(),
    P = spawn(fun() -> erts_debug:dirty_cpu(alive_waitexitingonly, Me) end),
    receive {alive, P} -> ok end,
    Dirty = erts_internal:is_process_executing_dirty(P),
    M = monitor(process, P),
    exit(P, kill),
    Down = receive {'DOWN', M, process, P, R} -> R after 5000 -> timeout end,
    {Dirty, Down, is_process_alive(P), erts_internal:is_process_executing_dirty(self())};

run(3) ->
    Me = self(),
    GL = group_leader(),
    Init = spawn(fun() -> receive stop -> ok end end),
    P = spawn(fun() -> erts_debug:dirty_io(alive_waitexiting, Me) end),
    receive {alive, P} -> ok end,
    Set1 = group_leader(Init, P),
    {group_leader, G1} = process_info(P, group_leader),
    Set2 = group_leader(GL, P),
    {group_leader, G2} = process_info(P, group_leader),
    M = monitor(process, P),
    exit(P, bang),
    Late = err(fun() -> group_leader(Init, P) end),
    Down = receive {'DOWN', M, process, P, R} -> R after 5000 -> timeout end,
    {Set1, G1 =:= Init, Set2, G2 =:= GL, Late, Down};

run(4) ->
    Me = self(),
    {erts_debug:dirty_cpu(wait, 10),
     erts_debug:dirty_io(wait, 10),
     err(fun() -> erts_debug:dirty_io(error, badarith) end),
     err(fun() -> erts_debug:dirty_cpu(error, notsup) end),
     err(fun() -> erts_debug:dirty_cpu(bogus, 1) end),
     length(erts_debug:dirty_cpu(copy, {a, [b]})),
     erts_debug:dirty_io(send, Me),
     receive {ok, Me} -> got after 1000 -> timeout end};

run(5) ->
    Online = erlang:system_info(dirty_cpu_schedulers_online),
    % erts applies the change asynchronously, so system_info may still show the old count.
    Prev = erlang:system_flag(dirty_cpu_schedulers_online, 1),
    Type = erts_debug:dirty_cpu(scheduler, type),
    Bad = err(fun() -> erlang:system_flag(dirty_cpu_schedulers_online, 0) end),
    Back = erlang:system_flag(dirty_cpu_schedulers_online, Online),
    {Prev =:= Online, Type, Bad, Back};

run(6) ->
    Before = statistics(scheduler_wall_time_all),
    false = erlang:system_flag(scheduler_wall_time, true),
    erts_debug:dirty_io(wait, 50),
    All = statistics(scheduler_wall_time_all),
    Normal = statistics(scheduler_wall_time),
    erlang:system_flag(scheduler_wall_time, false),
    Total = erlang:system_info(schedulers)
        + erlang:system_info(dirty_cpu_schedulers)
        + erlang:system_info(dirty_io_schedulers),
    {Before,
     lists:sort([Id || {Id, _, _} <- All]) =:= lists:seq(1, Total),
     length(Normal) =:= erlang:system_info(schedulers)
         + erlang:system_info(dirty_cpu_schedulers),
     lists:all(fun({_, A, T}) -> A =< T end, All)};

run(7) ->
    Old = erlang:system_flag(microstate_accounting, true),
    erts_debug:dirty_cpu(wait, 20),
    erts_debug:dirty_io(wait, 20),
    Stats = erlang:statistics(microstate_accounting),
    erlang:system_flag(microstate_accounting, Old),
    Rows = lists:sort([{T, I} || #{type := T, id := I} <- Stats,
                                 T =:= dirty_cpu_scheduler orelse T =:= dirty_io_scheduler]),
    Busy = [T || #{type := T, counters := #{emulator := E}} <- Stats,
                 T =:= dirty_cpu_scheduler orelse T =:= dirty_io_scheduler, E > 0],
    {Rows, lists:usort(Busy)}.
"##;

fn assert_scenario(reference: &RefErl, scenario: i64, simulation: Option<u64>) {
    let beam = reference
        .compile_named("dirty_sched", SOURCE, &[])
        .expect("compile dirty_sched");
    reference.load("dirty_sched", &beam).expect("load into erl");
    let expected = reference.call("dirty_sched", "run", &[OwnedTerm::Int(scenario)]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).expect("load into arinsal");
    let actual = vm
        .eval_scheduled(
            "dirty_sched",
            "run",
            &[Term::small(scenario).unwrap()],
            2,
            simulation,
        )
        .unwrap_or_else(|error| panic!("scenario {scenario}: {error}"));
    assert_eq!(expected, CallResult::Ok(actual.term), "scenario {scenario}");
}

macro_rules! scenario {
    ($name:ident, $index:expr) => {
        #[test]
        fn $name() {
            let Ok(reference) = RefErl::start() else {
                eprintln!("erl unavailable; skipping {}", stringify!($name));
                return;
            };
            assert_scenario(&reference, $index, None);
        }
    };
}

scenario!(dirty_sched_scheduler_type, 0);
scenario!(dirty_sched_system_info_counts, 1);
scenario!(dirty_sched_kill_while_dirty, 2);
scenario!(dirty_sched_signals_while_dirty, 3);
scenario!(dirty_sched_wait_errors_send, 4);
scenario!(dirty_sched_cpu_online_flag, 5);
scenario!(dirty_sched_wall_time_rows, 6);
scenario!(dirty_sched_msacc_rows, 7);

#[test]
fn dirty_sched_simulated_scheduler_type() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping dirty_sched_simulated_scheduler_type");
        return;
    };
    assert_scenario(&reference, 0, Some(15));
}
