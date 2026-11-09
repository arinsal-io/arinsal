use arinsal_difftest::{CallResult, RefErl};
use arinsal_vm::Vm;

const MODULE: &str = "gen_hibernate_diff";
const SOURCE: &str = r#"
-module(gen_hibernate_diff).
-behaviour(gen_server).
-export([explicit/0, automatic/0, suspended/0, init/1,
         handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).

explicit() ->
    {ok, Pid} = gen_server:start(gen_hibernate_diff, explicit, []),
    receive after 20 -> ok end,
    Info = process_info(Pid, current_function),
    ok = gen_server:stop(Pid),
    Info.

automatic() ->
    {ok, Pid} = gen_server:start(gen_hibernate_diff, automatic, [{hibernate_after, 20}]),
    receive after 50 -> ok end,
    Info = process_info(Pid, current_function),
    ok = gen_server:stop(Pid),
    Info.
suspended() ->
    {ok, Pid} = gen_server:start(gen_hibernate_diff, explicit, []),
    ok = gen_server:call(Pid, hibernate),
    ok = sys:suspend(Pid),
    Info = process_info(Pid, current_function),
    ok = sys:resume(Pid),
    ok = gen_server:stop(Pid),
    Info.
init(explicit) -> {ok, explicit, hibernate};
init(automatic) -> {ok, automatic};
init(ordinary) -> {ok, ordinary}.
handle_call(hibernate, _, State) -> {reply, ok, State, hibernate};
handle_call(_, _, State) -> {reply, ok, State}.
handle_cast(_, State) -> {noreply, State}.
handle_info(_, State) -> {noreply, State}.
terminate(_, _) -> ok.
code_change(_, State, _) -> {ok, State}.
"#;

fn both(function: &str) -> (CallResult, CallResult) {
    let reference = RefErl::start().expect("OTP 29.1.1");
    let beam = reference.compile_named(MODULE, SOURCE, &[]).unwrap();
    reference.load(MODULE, &beam).unwrap();
    let expected = reference.call(MODULE, function, &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled(MODULE, function, &[], 2, Some(83))
        .map(|outcome| CallResult::Ok(outcome.term))
        .unwrap_or_else(|error| CallResult::TransportError(format!("{error:?}")));
    (expected, actual)
}

#[test]
fn explicit_hibernate_reports_erts_current_function() {
    let (expected, actual) = both("explicit");
    similar_asserts::assert_eq!(expected, actual);
}

#[test]
fn auto_hibernate_reports_erts_current_function() {
    let (expected, actual) = both("automatic");
    similar_asserts::assert_eq!(expected, actual);
}

#[test]
fn suspended_explicit_hibernate_reports_erts_current_function() {
    let (expected, actual) = both("suspended");
    similar_asserts::assert_eq!(expected, actual);
}
