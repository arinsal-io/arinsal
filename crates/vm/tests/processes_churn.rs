//! `erlang:processes/0` (a trapping, chunked scan of the process table) called repeatedly while
//! other processes spawn and exit: the result must be a duplicate-free snapshot that holds every
//! process alive for the whole call, and the call must neither hang nor crash.
use arinsal_difftest::{CallResult, CompareMode, RefErl, compare};
use arinsal_etf::OwnedTerm;
use arinsal_term::{VecHeap, from_owned};
use arinsal_vm::{Vm, VmError};

const SOURCE: &str = r#"
-module(vm_processes_churn).
-export([result/2]).
result(Rounds, Spawners) ->
    Stable = [spawn(fun() -> receive stop -> ok end end) || _ <- lists:seq(1, 20)],
    Me = self(),
    Churn = [spawn(fun() -> churn() end) || _ <- lists:seq(1, Spawners)],
    Res = loop(Rounds, Stable, Me, true),
    [exit(P, kill) || P <- Churn],
    [P ! stop || P <- Stable],
    Res.
churn() ->
    _ = [spawn(fun() -> ok end) || _ <- lists:seq(1, 10)],
    receive after 1 -> ok end,
    churn().
loop(0, _, _, Ok) -> Ok;
loop(N, Stable, Me, Ok) ->
    L = erlang:processes(),
    Unique = length(L) =:= length(lists:usort(L)),
    All = lists:all(fun(P) -> lists:member(P, L) end, [Me | Stable]),
    loop(N - 1, Stable, Me, Ok andalso Unique andalso All).
"#;

#[test]
fn processes_snapshot_under_spawn_churn_matches_otp() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping processes/0 churn differential test");
        return;
    };
    let beam = reference
        .compile_named("vm_processes_churn", SOURCE, &[])
        .unwrap();
    reference.load("vm_processes_churn", &beam).unwrap();
    let args = [OwnedTerm::Int(50), OwnedTerm::Int(3)];
    let expected = reference.call("vm_processes_churn", "result", &args);

    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let mut heap = VecHeap::new();
    let terms: Vec<_> = args
        .iter()
        .map(|arg| from_owned(arg, &mut heap).unwrap())
        .collect();
    let actual = match vm.eval_scheduled("vm_processes_churn", "result", &terms, 2, None) {
        Ok(outcome) => CallResult::Ok(outcome.term),
        Err(VmError::Raised(raised)) => CallResult::Exception {
            class: format!("{:?}", raised.class).to_lowercase(),
            reason: raised.reason,
            stack_top: Some(raised.stack),
        },
        Err(error) => CallResult::TransportError(error.to_string()),
    };
    compare(&expected, &actual, CompareMode::Exact)
        .unwrap_or_else(|error| panic!("processes/0 churn mismatch: {error}"));
}
