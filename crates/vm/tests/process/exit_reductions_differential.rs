//! A process exit costs the schedulers 100 reductions (erl_process.c, erts_do_exit_process:
//! `BUMP_REDS(p, 100)`), visible in `statistics(reductions)`, against OTP 29.1.1.

use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_vm::Vm;
use similar_asserts::assert_eq;

const MODULE: &str = "exit_reductions_test";

const SOURCE: &str = r#"-module(exit_reductions_test).
-export([per_exit/0]).

per_exit() ->
    N = 500,
    Ps = [spawn(fun() -> receive go -> ok end end) || _ <- lists:seq(1, N)],
    wait(30),
    {A, _} = statistics(reductions),
    [P ! go || P <- Ps],
    wait(50),
    {B, _} = statistics(reductions),
    (B - A + N * 5) div (N * 10).

wait(Ms) -> receive after Ms -> ok end.
"#;

#[test]
fn exit_reductions_match_otp() {
    let reference = RefErl::start().expect("OTP 29.1.1 is required for this test");
    let beam = reference.compile_named(MODULE, SOURCE, &[]).unwrap();
    reference.load(MODULE, &beam).unwrap();
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let CallResult::Ok(expected) = reference.call(MODULE, "per_exit", &[]) else {
        panic!("OTP per_exit failed");
    };
    let actual = vm
        .eval_scheduled_reductions(MODULE, "per_exit", &[], 1, Some(0xB500), 4_000)
        .unwrap();
    assert_eq!(expected, actual.term);
    assert!(matches!(expected, OwnedTerm::Int(reds) if reds >= 10));
}
