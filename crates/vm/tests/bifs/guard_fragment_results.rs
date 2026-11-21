use arinsal_difftest::{CallResult, RefErl};

#[test]
fn allocating_guard_bifs_match_erts_without_young_heap_updates() {
    let reference = RefErl::start().expect("OTP 29.1.1 is required for this test");
    let beam = reference
        .compile_named(
            "guard_fragment_results",
            r#"-module(guard_fragment_results).
               -export([run/0]).
               abs_guard(X) when abs(X) > 0 -> true;
               abs_guard(_) -> false.
               float_guard(X) when float(X) > 0.0 -> true;
               float_guard(_) -> false.
               trunc_guard(X) when trunc(X) > 0 -> true;
               trunc_guard(_) -> false.
               round_guard(X) when round(X) > 0 -> true;
               round_guard(_) -> false.
               ceil_guard(X) when ceil(X) > 0 -> true;
               ceil_guard(_) -> false.
               floor_guard(X) when floor(X) > 0 -> true;
               floor_guard(_) -> false.
               run() ->
                   Big = trunc(1.7e308),
                   NegBig = -Big,
                   {abs_guard(NegBig), float_guard(Big), trunc_guard(1.7e308),
                    round_guard(1.7e308), ceil_guard(1.7e308), floor_guard(1.7e308)}."#,
            &[],
        )
        .unwrap();
    reference.load("guard_fragment_results", &beam).unwrap();
    let expected = reference.call("guard_fragment_results", "run", &[]);

    let mut vm = crate::common::node();
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled("guard_fragment_results", "run", &[], 1)
        .unwrap();

    similar_asserts::assert_eq!(expected, CallResult::Ok(actual.term));
}
