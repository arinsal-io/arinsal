//! Differential tests for microstate accounting over every thread kind: structure and
//! invariants only, never raw timings.

use arinsal_difftest::{CallResult, RefErl};
use arinsal_term::Term;
use arinsal_vm::Vm;

const SOURCE: &str = r##"
-module(msacc_threads).
-export([run/1]).

%% The structure is deterministic; the ratios depend on the runner getting scheduled, so a
%% measurement that fails them is repeated (a starved machine) before it is reported.
run(Load) -> run(Load, 12).

run(Load, Left) ->
    {Kinds, Keys, Whole, Idle, Busy} = measure(Load),
    case Left > 1 andalso not (Whole andalso Idle andalso Busy) of
        true -> receive after 300 -> ok end, run(Load, Left - 1);
        false -> {Kinds, Keys, Whole, Idle, Busy}
    end.

measure(Load) ->
    erlang:system_flag(microstate_accounting, false),
    erlang:system_flag(microstate_accounting, reset),
    erlang:system_flag(microstate_accounting, true),
    work(Load),
    Stats = erlang:statistics(microstate_accounting),
    erlang:system_flag(microstate_accounting, false),
    States = [aux, check_io, emulator, gc, other, port, sleep],
    Expected = [{scheduler, erlang:system_info(schedulers)},
                {dirty_cpu_scheduler, erlang:system_info(dirty_cpu_schedulers)},
                {dirty_io_scheduler, erlang:system_info(dirty_io_schedulers)},
                {poll, 1}, {aux, 1}, {async, 1}],
    Kinds = [{T, length([x || #{type := T2} <- Stats, T2 =:= T]) =:= N}
             || {T, N} <- Expected],
    Total = fun(#{counters := C}) -> lists:sum(maps:values(C)) end,
    Sums = [Total(S) || S <- Stats],
    Max = lists:max(Sums),
    Keys = lists:usort([lists:sort(maps:keys(C)) || #{counters := C} <- Stats]),
    %% every thread accounts for the whole window, wherever it spent it
    Whole = lists:all(fun(S) -> S >= Max * 0.7 andalso S > 0 end, Sums),
    Idle = fun(Type) ->
                   [maps:get(sleep, C) >= Total(S) * 0.85
                    || #{type := T, counters := C} = S <- Stats, T =:= Type]
           end,
    IdleThreads = lists:all(fun(B) -> B end,
                            lists:append([Idle(poll), Idle(async), Idle(aux),
                                          Idle(dirty_cpu_scheduler)])),
    DirtyIoBusy = length([x || #{type := dirty_io_scheduler, counters := #{emulator := E}} <- Stats,
                               E > 0]) >= 1,
    {Kinds, Keys =:= [States], Whole, IdleThreads,
     case Load of idle -> true; dirty_io -> DirtyIoBusy end}.

work(idle) ->
    receive after 400 -> ok end;
work(dirty_io) ->
    [erts_debug:dirty_io(wait, 25) || _ <- lists:seq(1, 8)],
    ok.
"##;

fn assert_load(load: &str) {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping msacc thread test {load}");
        return;
    };
    let beam = reference
        .compile_named("msacc_threads", SOURCE, &[])
        .expect("compile msacc_threads");
    reference
        .load("msacc_threads", &beam)
        .expect("load into erl");
    let atom = arinsal_etf::OwnedTerm::atom(load);
    let expected = reference.call("msacc_threads", "run", &[atom]);
    let CallResult::Ok(expected_term) = &expected else {
        panic!("reference failed: {expected:?}");
    };
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).expect("load into arinsal");
    let arg = Term::atom(arinsal_term::global_atoms().intern(load).unwrap());
    // One worker per configured scheduler, as a booted node has.
    let workers = std::thread::available_parallelism().map_or(2, usize::from);
    let actual = vm
        .eval_scheduled("msacc_threads", "run", &[arg], workers, None)
        .unwrap_or_else(|error| panic!("{load}: {error}"));
    assert_eq!(
        &expected,
        &CallResult::Ok(actual.term),
        "{load}: reference {expected_term:?}"
    );
}

#[test]
fn msacc_threads_idle_matches_otp() {
    assert_load("idle");
}

#[test]
fn msacc_threads_dirty_io_load_matches_otp() {
    assert_load("dirty_io");
}
