use arinsal_difftest::{CallResult, RefErl};
use arinsal_vm::Vm;
use similar_asserts::assert_eq;

const MODULE: &str = "lists_error_info";
const SOURCE: &str = r#"
-module(lists_error_info).
-export([badargs/0]).

badargs() ->
    Improper = [1 | tail],
    {capture(fun() -> lists:keyfind(key, 0, []) end),
     capture(fun() -> lists:keymember(key, 1, Improper) end),
     capture(fun() -> lists:keysearch(key, 1, not_a_list) end),
     capture(fun() -> lists:member(1, Improper) end),
     capture(fun() -> lists:reverse(Improper, []) end),
     capture(fun() -> erlang:length(Improper) end)}.

capture(Fun) ->
    try Fun() of
        Value -> {ok, Value}
    catch
        error:Reason:Stack ->
            [{Module, Function, Args, Location} | _] = Stack,
            {Reason, Module, Function, Args,
             proplists:get_value(error_info, Location, undefined)}
    end.
"#;

#[test]
fn list_bif_badarg_error_info_matches_otp_29() {
    let reference = RefErl::start().expect("OTP 29.1.1 reference");
    let beam = reference.compile_named(MODULE, SOURCE, &[]).unwrap();
    reference.load(MODULE, &beam).unwrap();
    let expected = reference.call(MODULE, "badargs", &[]);

    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled(MODULE, "badargs", &[], 1, Some(0x1157))
        .unwrap_or_else(|error| panic!("badargs: {error}"));

    assert_eq!(expected, CallResult::Ok(actual.term));
}
