use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_vm::Vm;
use similar_asserts::assert_eq;

#[test]
fn binary_to_list_one_megabyte_matches_otp_and_charges_reductions() {
    const MODULE: &str = "binary_to_list_trap_test";
    let reference = RefErl::start().expect("OTP 29.1.1 is required for this test");
    let source = r#"-module(binary_to_list_trap_test).
        -export([values/0, reductions/0, values3/0, reductions3/0]).
        subject() -> binary:copy(<<0, 1, 255, 17>>, 262144).
        values() ->
            List = erlang:binary_to_list(subject()),
            {length(List), lists:sum(List), hd(List), lists:last(List)}.
        reductions() ->
            List = erlang:binary_to_list(subject()),
            {_, Reds} = process_info(self(), reductions),
            {length(List), Reds}.
        values3() ->
            List = erlang:binary_to_list(subject(), 17, 528),
            {length(List), lists:sum(List), hd(List), lists:last(List)}.
        reductions3() ->
            List = erlang:binary_to_list(subject(), 17, 528),
            {_, Reds} = process_info(self(), reductions),
            {length(List), Reds}.
    "#;
    let beam = reference.compile_named(MODULE, source, &[]).unwrap();
    reference.load(MODULE, &beam).unwrap();
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();

    let expected_values = reference.call(MODULE, "values", &[]);
    let actual_values = vm
        .eval_scheduled_reductions(MODULE, "values", &[], 1, Some(0xB271), 4_000)
        .unwrap();
    assert_eq!(expected_values, CallResult::Ok(actual_values.term));

    let expected_values3 = reference.call(MODULE, "values3", &[]);
    let actual_values3 = vm
        .eval_scheduled_reductions(MODULE, "values3", &[], 1, Some(0xB273), 4_000)
        .unwrap();
    assert_eq!(expected_values3, CallResult::Ok(actual_values3.term));

    let CallResult::Ok(OwnedTerm::Tuple(ref expected)) = reference.call(MODULE, "reductions", &[])
    else {
        panic!("OTP reductions call did not return a tuple");
    };
    let actual = vm
        .eval_scheduled_reductions(MODULE, "reductions", &[], 1, Some(0xB272), 4_000)
        .unwrap();
    let OwnedTerm::Tuple(ref actual) = actual.term else {
        panic!("Arinsal reductions call did not return a tuple");
    };
    assert_eq!(expected[0], actual[0]);
    let (OwnedTerm::Int(expected_reds), OwnedTerm::Int(actual_reds)) = (&expected[1], &actual[1])
    else {
        panic!("reductions were not integers");
    };
    let slack = (expected_reds / 10).max(32);
    assert!(
        (expected_reds - slack..=expected_reds + slack).contains(actual_reds),
        "OTP reductions {expected_reds}, Arinsal reductions {actual_reds}, slack {slack}"
    );
    assert!(
        *actual_reds >= 4096,
        "large conversion did not charge per chunk"
    );

    let CallResult::Ok(OwnedTerm::Tuple(ref expected3)) =
        reference.call(MODULE, "reductions3", &[])
    else {
        panic!("OTP range reductions call did not return a tuple");
    };
    let actual3 = vm
        .eval_scheduled_reductions(MODULE, "reductions3", &[], 1, Some(0xB274), 4_000)
        .unwrap();
    let OwnedTerm::Tuple(ref actual3) = actual3.term else {
        panic!("Arinsal range reductions call did not return a tuple");
    };
    assert_eq!(expected3[0], actual3[0]);
    let (OwnedTerm::Int(expected_reds3), OwnedTerm::Int(actual_reds3)) =
        (&expected3[1], &actual3[1])
    else {
        panic!("range reductions were not integers");
    };
    let slack3 = (expected_reds3 / 10).max(32);
    assert!(
        (expected_reds3 - slack3..=expected_reds3 + slack3).contains(actual_reds3),
        "OTP range reductions {expected_reds3}, Arinsal range reductions {actual_reds3}, slack {slack3}"
    );
}
