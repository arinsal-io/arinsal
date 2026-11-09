use arinsal_difftest::{CallResult, CompareMode, RefErl, compare};
use arinsal_etf::OwnedTerm;
use arinsal_term::{VecHeap, from_owned};
use arinsal_vm::{Vm, VmError};

const SOURCE: &str = r#"
-module(vm_subtract_trap_diff).
-export([result/1]).
result(N) ->
    Lhs = lists:seq(1, N),
    Rhs = lists:seq(1, N, 2),
    length(Lhs -- Rhs).
"#;

#[test]
fn large_subtract_continuation_matches_otp() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping subtract continuation differential test");
        return;
    };
    let beam = reference
        .compile_named("vm_subtract_trap_diff", SOURCE, &[])
        .unwrap();
    reference.load("vm_subtract_trap_diff", &beam).unwrap();
    let args = [OwnedTerm::Int(50_000)];
    let expected = reference.call("vm_subtract_trap_diff", "result", &args);

    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let mut heap = VecHeap::new();
    let term = from_owned(&args[0], &mut heap).unwrap();
    let actual = match vm.eval_scheduled("vm_subtract_trap_diff", "result", &[term], 1, None) {
        Ok(outcome) => CallResult::Ok(outcome.term),
        Err(VmError::Raised(raised)) => CallResult::Exception {
            class: format!("{:?}", raised.class).to_lowercase(),
            reason: raised.reason,
            stack_top: Some(raised.stack),
        },
        Err(error) => CallResult::TransportError(error.to_string()),
    };
    compare(&expected, &actual, CompareMode::Exact)
        .unwrap_or_else(|error| panic!("large subtract continuation mismatch: {error}"));
}
