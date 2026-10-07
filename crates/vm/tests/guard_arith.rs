use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_vm::Vm;

#[test]
fn bad_arithmetic_in_guard_uses_the_failure_label() {
    let reference = RefErl::start().expect("OTP 29.1.1 is required for this test");
    let beam = reference
        .compile_named(
            "guard_arith_regression",
            r#"-module(guard_arith_regression).
               -export([run/0]).
               bad(X, Y) when X + Y < 10 -> X + Y;
               bad(_, _) -> 10.
               run() -> {bad(1, infinity), bad(infinity, 1), bad(2, 3)}."#,
            &[],
        )
        .unwrap();
    reference.load("guard_arith_regression", &beam).unwrap();
    let expected = reference.call("guard_arith_regression", "run", &[]);

    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled("guard_arith_regression", "run", &[], 1, None)
        .unwrap();

    assert_eq!(expected, CallResult::Ok(actual.term.clone()));
    assert_eq!(
        actual.term,
        OwnedTerm::tuple(vec![
            OwnedTerm::Int(10),
            OwnedTerm::Int(10),
            OwnedTerm::Int(5),
        ])
    );
}

#[test]
fn float_register_conversion_rejects_bignum_overflow_like_otp() {
    let reference = RefErl::start().expect("OTP 29.1.1 is required for this test");
    let beam = reference
        .compile_named(
            "float_conversion_regression",
            r#"-module(float_conversion_regression).
               -export([run/0]).
               run() ->
                   I = trunc(1.7e308),
                   {attempt(fun() -> 1 / (2 * I) end),
                    attempt(fun() -> 2 / I end),
                    attempt(fun() -> 4 / (2 * I) end)}.
               attempt(F) ->
                   try F() of Value -> Value
                   catch error:badarith -> badarith
                   end."#,
            &[],
        )
        .unwrap();
    reference
        .load("float_conversion_regression", &beam)
        .unwrap();
    let expected = reference.call("float_conversion_regression", "run", &[]);

    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled("float_conversion_regression", "run", &[], 1, None)
        .unwrap();

    assert_eq!(expected, CallResult::Ok(actual.term.clone()));
}
