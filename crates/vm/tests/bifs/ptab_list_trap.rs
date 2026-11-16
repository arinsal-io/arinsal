use arinsal_difftest::{CallResult, RefErl};

const MODULE: &str = "ptab_list_trap";
const SOURCE: &str = r#"
-module(ptab_list_trap).
-export([many_processes/0, ports_are_listed/0]).

many_processes() ->
    Pids = [spawn(fun() -> receive stop -> ok end end) || _ <- lists:seq(1, 1500)],
    try
        Listed = erlang:processes(),
        lists:all(fun(Pid) -> lists:member(Pid, Listed) end, Pids)
    after
        lists:foreach(fun(Pid) -> exit(Pid, kill) end, Pids)
    end.

ports_are_listed() -> erlang:ports() =/= [].
"#;

fn both(function: &str) -> (CallResult, CallResult) {
    let reference = RefErl::start().expect("OTP 29.1.1");
    let beam = reference.compile_named(MODULE, SOURCE, &[]).unwrap();
    reference.load(MODULE, &beam).unwrap();
    let expected = reference.call(MODULE, function, &[]);
    let mut vm = crate::common::node();
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled(MODULE, function, &[], 2)
        .map(|outcome| CallResult::Ok(outcome.term))
        .unwrap_or_else(|error| CallResult::TransportError(format!("{error:?}")));
    (expected, actual)
}

#[test]
fn processes_with_many_live_processes_match_erts() {
    let (expected, actual) = both("many_processes");
    similar_asserts::assert_eq!(expected, actual);
}

#[test]
fn ports_matches_erts() {
    let (expected, actual) = both("ports_are_listed");
    similar_asserts::assert_eq!(expected, actual);
}
