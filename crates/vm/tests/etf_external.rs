use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_vm::Vm;
use similar_asserts::assert_eq;

const SOURCE: &str = r#"
-module(etf_external_error_info_diff).
-export([badopt/0]).
badopt() ->
    try binary_to_term(term_to_binary(ok), [bad]) of
        Value -> Value
    catch
        error:Reason:Stack ->
            [{_, _, _, Info} | _] = Stack,
            Cause = maps:get(cause, proplists:get_value(error_info, Info, #{}), none),
            {Reason, Cause}
    end.
"#;

#[test]
fn binary_to_term_badopt_error_info_matches_erts() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping binary_to_term error_info differential test");
        return;
    };
    let beam = reference
        .compile_named("etf_external_error_info_diff", SOURCE, &[])
        .unwrap();
    reference
        .load("etf_external_error_info_diff", &beam)
        .unwrap();
    let expected = reference.call("etf_external_error_info_diff", "badopt", &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled("etf_external_error_info_diff", "badopt", &[], 1, Some(73))
        .unwrap()
        .term;
    let CallResult::Ok(expected) = expected else {
        panic!("reference call failed: {expected:?}");
    };
    assert_eq!(
        actual,
        OwnedTerm::Tuple(vec![OwnedTerm::atom("badarg"), OwnedTerm::atom("badopt")])
    );
    assert_eq!(actual, expected);
}
