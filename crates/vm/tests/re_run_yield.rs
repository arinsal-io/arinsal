//! `re:run` yields between PCRE2 loop budgets, so a process stuck in a long match can be killed.

use arinsal_difftest::{CallResult, RefErl};
use arinsal_vm::Vm;

const MODULE: &str = "re_run_yield";
const SOURCE: &str = r#"
-module(re_run_yield).
-export([kill/0, same_result/0, kill_internal/0, internal_result/0]).
kill() ->
    Subject = binary:copy(<<"hejsan">>, 100000),
    {ok, Compiled} = re:compile(<<"\\w+\\d">>, []),
    [begin
         {Pid, MRef} = spawn_monitor(fun() -> re:run(Subject, RE) end),
         erlang:yield(),
         exit(Pid, kill),
         receive {'DOWN', MRef, process, Pid, Reason} -> Reason after 5000 -> timeout end
     end || RE <- [<<"\\w+\\d">>, Compiled]].
kill_internal() ->
    Subject = binary:copy(<<"hejsan">>, 100000),
    {Pid, MRef} = spawn_monitor(fun() -> re:internal_run(Subject, <<"\\w+\\d">>, [], true) end),
    erlang:yield(),
    exit(Pid, kill),
    receive {'DOWN', MRef, process, Pid, Reason} -> Reason after 5000 -> timeout end.
internal_result() ->
    S = binary:copy(<<"abc123 def456 ">>, 2000),
    [re:internal_run(S, <<"\\d+">>, [{capture, all, binary}], true),
     re:internal_run(S, <<"[a-z]+">>, [{offset, 40}], false),
     (try re:internal_run(S, <<"\\d+">>, [], unknown) catch error:E -> {caught, E} end)].
same_result() ->
    S = binary:copy(<<"abc123 def456 ">>, 2000),
    [re:run(S, <<"\\d+">>, [global, {capture, all, binary}]),
     re:run(S, <<"x*">>, [global]),
     re:run(S, <<"(?<n>[a-z]+)(\\d)">>, [{capture, all_names, list}])].
"#;

fn both(function: &str) -> (CallResult, CallResult) {
    let reference = RefErl::start().expect("OTP 29.1.1");
    let beam = reference.compile_named(MODULE, SOURCE, &[]).unwrap();
    reference.load(MODULE, &beam).unwrap();
    let expected = reference.call(MODULE, function, &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled(MODULE, function, &[], 2, Some(82))
        .map(|outcome| CallResult::Ok(outcome.term))
        .unwrap_or_else(|error| CallResult::TransportError(format!("{error:?}")));
    (expected, actual)
}

#[test]
fn a_long_match_can_be_killed() {
    let (expected, actual) = both("kill");
    assert_eq!(expected, actual);
}

#[test]
fn internal_run_traps_with_the_restart_state() {
    for function in ["kill_internal", "internal_result"] {
        let (expected, actual) = both(function);
        assert_eq!(expected, actual, "{function}");
    }
}

#[test]
fn sliced_matches_give_the_same_result() {
    let (expected, actual) = both("same_result");
    assert_eq!(expected, actual);
}
