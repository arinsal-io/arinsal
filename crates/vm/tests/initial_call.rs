//! `process_info(Pid, initial_call)` reports the spawn MFA, not the current function.

use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_vm::Vm;

const SOURCE: &str = r#"
-module(initial_call_diff).
-export([initial/0, idle/0]).

idle() -> wait(), ok.

wait() -> receive stop -> ok end.

initial() ->
    P1 = spawn(initial_call_diff, idle, []),
    P2 = spawn(initial_call_diff, idle, []),
    receive after 100 -> ok end,
    R = {process_info(P1, initial_call), process_info(P2, initial_call),
         process_info(P1, current_function)},
    exit(P1, kill),
    exit(P2, kill),
    R.

"#;

fn run(reference: &RefErl, function: &str) -> (CallResult, OwnedTerm) {
    let beam = reference
        .compile_named("initial_call_diff", SOURCE, &[])
        .expect("compile fixture");
    reference
        .load("initial_call_diff", &beam)
        .expect("load reference");
    let expected = reference.call("initial_call_diff", function, &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).expect("load VM fixture");
    let actual = vm
        .eval_scheduled("initial_call_diff", function, &[], 1, None)
        .unwrap_or_else(|error| panic!("{function}: {error}"));
    (expected, actual.term)
}

#[test]
fn initial_call_is_the_spawn_mfa() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping initial_call test");
        return;
    };
    let (expected, actual) = run(&reference, "initial");
    assert_eq!(expected, CallResult::Ok(actual));
}
