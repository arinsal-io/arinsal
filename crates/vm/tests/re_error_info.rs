use arinsal_difftest::{CallResult, RefErl};
use arinsal_vm::Vm;

const SOURCE: &str = r#"
-module(re_error_info_diff).
-export([bad_options/0]).

bad_options() ->
    try re:run({a, b}, ".*", bad_options) of
        Value -> {ok, Value}
    catch
        error:Reason:Stack ->
            [{Module, Function, Args, Location} | _] = Stack,
            {Reason, Module, Function, Args,
             proplists:get_value(error_info, Location, undefined)}
    end.
"#;

#[test]
fn invalid_run_options_preserve_badopt_error_info_like_otp() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping re error_info differential test");
        return;
    };
    let beam = reference
        .compile_named("re_error_info_diff", SOURCE, &[])
        .unwrap();
    reference.load("re_error_info_diff", &beam).unwrap();
    let expected = reference.call("re_error_info_diff", "bad_options", &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled("re_error_info_diff", "bad_options", &[], 1, Some(73))
        .unwrap_or_else(|error| panic!("Arinsal re:run/3 error_info: {error}"));
    let CallResult::Ok(expected) = expected else {
        panic!("reference error_info call failed: {expected:?}");
    };
    similar_asserts::assert_eq!(actual.term, expected);
}
