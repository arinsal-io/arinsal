use arinsal_difftest::{CallResult, RefErl};
use arinsal_vm::Vm;
use similar_asserts::assert_eq;

const MODULE: &str = "binary_search_differential";
const SOURCE: &str = r#"
-module(binary_search_differential).
-export([results/0, badargs/0, large/0]).

results() ->
    Subject = <<"ababababx">>,
    Pattern = <<"ab">>,
    Compiled = binary:compile_pattern(Pattern),
    {binary:match(Subject, Pattern),
     binary:match(Subject, Compiled),
     binary:at(Subject, 3),
     binary:matches(Subject, Pattern),
     binary:matches(Subject, Compiled),
     binary:split(Subject, Pattern),
     binary:split(Subject, Compiled),
     binary:split(Subject, Compiled, [global]),
     binary:split(Subject, Compiled, [global, trim]),
     binary:split(Subject, Compiled, [global, trim_all])}.

badargs() ->
    {capture(fun() -> binary:match(<<"abc">>, <<>>) end),
     capture(fun() -> binary:split(<<"abc">>, <<>>, [global]) end),
     capture(fun() -> binary:at(<<"abc">>, 3) end)}.

capture(Fun) ->
    try Fun() of
        Value -> {ok, Value}
    catch
        error:Reason:Stack ->
            [{Module, Function, Args, Location} | _] = Stack,
            {Reason, Module, Function, Args,
             proplists:get_value(error_info, Location, undefined)}
    end.

large() ->
    Subject = binary:copy(<<0>>, 1048576),
    Pattern = binary:compile_pattern(<<255>>),
    {binary:match(Subject, Pattern),
     [byte_size(Part) || Part <- binary:split(Subject, Pattern)]}.
"#;

#[test]
fn binary_search_results_and_error_info_match_otp() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping binary search differential tests");
        return;
    };
    let beam = reference.compile_named(MODULE, SOURCE, &[]).unwrap();
    reference.load(MODULE, &beam).unwrap();
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();

    for function in ["results", "badargs"] {
        let expected = reference.call(MODULE, function, &[]);
        let actual = vm
            .eval_scheduled(MODULE, function, &[], 1, None)
            .unwrap_or_else(|error| panic!("{function}: {error}"));
        assert_eq!(expected, CallResult::Ok(actual.term), "{function}");
    }
}

#[test]
fn binary_search_large_subject_matches_otp_across_traps() {
    let reference = RefErl::start().expect("OTP 29.1.1 is required for this test");
    let beam = reference.compile_named(MODULE, SOURCE, &[]).unwrap();
    reference.load(MODULE, &beam).unwrap();
    let expected = reference.call(MODULE, "large", &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled_reductions(MODULE, "large", &[], 1, Some(0xB1F1), 4_000)
        .unwrap_or_else(|error| panic!("large binary search: {error}"));
    assert_eq!(CallResult::Ok(actual.term), expected);
}
