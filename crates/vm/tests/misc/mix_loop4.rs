//! A monitored `exit/1` whose reason is a heap tuple must survive the
//! collection that builds the stacktrace. `elixir_erl_compiler:spawn/1`
//! waits for `{'DOWN', _, process, _, {ok, Result, Diagnostics}}`.

use arinsal_difftest::{CallResult, RefErl};
use arinsal_vm::Vm;

#[test]
fn monitored_exit_tuple_survives_gc() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping monitored exit-reason differential test");
        return;
    };
    let source = r#"
-module(mix_loop4_down).
-export([run/0]).
run() ->
    Waste = fun() ->
        [lists:seq(1, 400) || _ <- lists:seq(1, 30)]
    end,
    {Pid, Ref} = spawn_monitor(fun() ->
        Waste(),
        exit({ok, binary:copy(<<255>>, 8000), marker})
    end),
    One = receive
        {'DOWN', Ref, process, Pid, Reason} -> Reason
    after 2000 -> timeout
    end,
    {Pid2, Ref2} = spawn_monitor(fun() ->
        Waste(),
        exit({error, badarg, [], undefined})
    end),
    Two = receive
        {'DOWN', Ref2, process, Pid2, Reason2} -> Reason2
    after 2000 -> timeout
    end,
    {One, Two}.
"#;
    let beam = reference
        .compile_named("mix_loop4_down", source, &[])
        .unwrap();
    reference.load("mix_loop4_down", &beam).unwrap();
    let expected = reference.call("mix_loop4_down", "run", &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled("mix_loop4_down", "run", &[], 4, Some(81))
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(expected, CallResult::Ok(actual.term));
}

/// `sys_core_fold` reaches `erlang:make_fun/3` through `apply/3`, which has
/// no import slot for the intercept used by a direct call.
#[test]
fn apply_make_fun_matches_otp() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping apply make_fun differential test");
        return;
    };
    let source = r#"
-module(mix_loop4_fun).
-export([run/0]).
run() ->
    F = apply(erlang, make_fun, [erlang, abs, 1]),
    Bad = try apply(erlang, make_fun, [1, abs, 1]) catch error:badarg -> badarg end,
    {F(-4), erlang:fun_info(F, type), erlang:fun_info(F, arity), Bad}.
"#;
    let beam = reference
        .compile_named("mix_loop4_fun", source, &[])
        .unwrap();
    reference.load("mix_loop4_fun", &beam).unwrap();
    let expected = reference.call("mix_loop4_fun", "run", &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled("mix_loop4_fun", "run", &[], 2, Some(81))
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(expected, CallResult::Ok(actual.term));
}

/// `erlang:monitor/2` of a process that is still running, then exits, must
/// deliver `DOWN`. A signal buffered until the watcher's slice ended was
/// dropped when the target left the process table first, and
/// `Kernel.ErrorHandler.ensure_compiled/4` waited forever.
#[test]
fn monitor_of_running_process_delivers_down() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping monitor-of-running differential test");
        return;
    };
    let source = r#"
-module(mix_loop4_mon).
-export([run/0]).
run() ->
    lists:map(fun(N) ->
        P = spawn(fun() ->
            erlang:yield(),
            exit({marker, N})
        end),
        R = monitor(process, P),
        receive
            {'DOWN', R, process, P, {marker, N}} -> ok;
            {'DOWN', R, process, P, noproc} -> ok
        after 2000 -> timeout
        end
    end, lists:seq(1, 80)).
"#;
    let beam = reference
        .compile_named("mix_loop4_mon", source, &[])
        .unwrap();
    reference.load("mix_loop4_mon", &beam).unwrap();
    let expected = reference.call("mix_loop4_mon", "run", &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled("mix_loop4_mon", "run", &[], 4, Some(81))
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(expected, CallResult::Ok(actual.term));
}
