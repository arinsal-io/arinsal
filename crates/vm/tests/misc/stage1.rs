#![cfg(feature = "difftest")]

use arinsal_difftest::{RefErl, Vm as _, compare, suites};
use arinsal_vm::Vm;
use std::collections::HashSet;

#[test]
fn report_stage1_pass_rate() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping stage1");
        return;
    };
    let mut vm = Vm::new([]);
    let cases = suites::stage1();
    let mut functions = HashSet::new();
    let mut failed = HashSet::new();
    let mut passed = 0;
    for case in &cases {
        let function = (case.spec.module, case.spec.function);
        functions.insert(function);
        let expected = reference.call(case.spec.module, case.spec.function, &case.args);
        let actual = vm.call(case.spec.module, case.spec.function, &case.args);
        if compare(&expected, &actual, case.spec.mode).is_ok() {
            passed += 1;
        } else {
            eprintln!(
                "stage1 mismatch {}:{}/{} args={:?} expected={expected:?} actual={actual:?}",
                case.spec.module,
                case.spec.function,
                case.args.len(),
                case.args,
            );
            failed.insert(function);
        }
    }
    eprintln!(
        "stage1: {passed}/{} cases; {}/{} functions",
        cases.len(),
        functions.len() - failed.len(),
        functions.len()
    );
    assert_eq!(passed, cases.len(), "stage1 differential mismatch");
}
