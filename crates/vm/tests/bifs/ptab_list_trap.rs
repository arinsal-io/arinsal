use arinsal_difftest::{CallResult, RefErl};

const MODULE: &str = "ptab_list_trap";
const SOURCE: &str = r#"
-module(ptab_list_trap).
-export([many_processes/0, ports_are_listed/0, churn_during_processes/0]).

many_processes() ->
    Pids = [spawn(fun() -> receive stop -> ok end end) || _ <- lists:seq(1, 1500)],
    try
        Listed = erlang:processes(),
        lists:all(fun(Pid) -> lists:member(Pid, Listed) end, Pids)
    after
        lists:foreach(fun(Pid) -> exit(Pid, kill) end, Pids)
    end.

ports_are_listed() -> erlang:ports() =/= [].

churn_during_processes() ->
    Parent = self(),
    Existing = [spawn(fun wait/0) || _ <- lists:seq(1, 1600)],
    Churn = spawn(fun() ->
        receive
            {trace, _Scanner, call, {erlang, processes, []}} ->
                Fresh = [spawn(fun wait/0) || _ <- lists:seq(1, 800)],
                lists:foreach(fun(Pid) -> exit(Pid, kill) end,
                              lists:sublist(Existing, 800)),
                Parent ! {churned, Fresh},
                receive
                    {stop, From} ->
                        lists:foreach(fun(Pid) -> exit(Pid, kill) end, Fresh),
                        From ! {churn_stopped, self()}
                end
        end
    end),
    Pattern = {erlang, processes, 0},
    try
        1 = erlang:trace_pattern(Pattern, true, []),
        1 = erlang:trace(self(), true, [call, {tracer, Churn}]),
        Listed = erlang:processes(),
        erlang:trace(self(), false, [call]),
        1 = erlang:trace_pattern(Pattern, false, []),
        receive
            {churned, Fresh} ->
                lists:all(fun(Pid) -> lists:member(Pid, Listed) end, Existing)
                    andalso not lists:any(fun(Pid) -> lists:member(Pid, Listed) end, Fresh)
        after 5000 -> false
        end
    after
        erlang:trace(self(), false, [call]),
        erlang:trace_pattern(Pattern, false, []),
        Churn ! {stop, self()},
        receive {churn_stopped, Churn} -> ok after 100 -> exit(Churn, kill) end,
        lists:foreach(fun(Pid) -> exit(Pid, kill) end, Existing)
    end.

wait() -> receive stop -> ok end.
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

#[test]
fn processes_reconcile_deaths_and_spawns_while_trapped() {
    let (expected, actual) = both("churn_during_processes");
    assert!(
        matches!(&expected, CallResult::Ok(term) if format!("{term:?}") == "Atom(\"true\")"),
        "expected the reference scenario to return true, got {expected:?}"
    );
    similar_asserts::assert_eq!(expected, actual);
}
