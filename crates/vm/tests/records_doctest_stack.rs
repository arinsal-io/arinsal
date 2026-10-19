use arinsal_difftest::{CallResult, CompareMode, RefErl, compare};
use arinsal_vm::{Vm, VmError};

const SOURCE: &str = r#"
-module(records_doctest_stack).
-export([run/0]).

run() ->
    Expression = {call, 0, {remote, 0, {atom, 0, records}, {atom, 0, get_module}},
                  [{map, 0, []}]},
    try erl_eval:exprs([Expression], #{}) of
        Value -> Value
    catch
        Class:Reason:Stacktrace -> {Class, Reason, lists:sublist(Stacktrace, 3)}
    end.
"#;

#[test]
fn records_doctest_error_stack_matches_otp() {
    let reference = RefErl::start().expect("OTP 29.1.1");
    let beam = reference
        .compile_named("records_doctest_stack", SOURCE, &[])
        .expect("compile differential");
    reference
        .load("records_doctest_stack", &beam)
        .expect("load reference module");
    let expected = reference.call("records_doctest_stack", "run", &[]);

    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).expect("load VM module");
    let actual = match vm.eval_scheduled("records_doctest_stack", "run", &[], 1, None) {
        Ok(outcome) => CallResult::Ok(outcome.term),
        Err(VmError::Raised(raised)) => CallResult::Exception {
            class: format!("{:?}", raised.class).to_lowercase(),
            reason: raised.reason,
            stack_top: Some(raised.stack),
        },
        Err(error) => CallResult::TransportError(error.to_string()),
    };
    compare(&expected, &actual, CompareMode::Exact).unwrap_or_else(|diff| {
        panic!("records:get_module doctest: {diff}\nexpected: {expected:?}\nactual: {actual:?}")
    });
}
