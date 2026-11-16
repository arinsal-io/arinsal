use arinsal_difftest::{CallResult, RefErl};
use similar_asserts::assert_eq;

const MODULE: &str = "pure_moved_differential";
const SOURCE: &str = r#"
-module(pure_moved_differential).
-export([cases/0]).

capture(Fun) ->
    try Fun() of
        Value -> {ok, Value}
    catch
        Class:Reason:Stack ->
            [{M, F, Args, Location} | _] = Stack,
            {error, Class, Reason, M, F, Args,
             proplists:get_value(error_info, Location, undefined)}
    end.

cases() ->
    Huge = (1 bsl 130) + 123456789,
    Fun0 = fun() -> ok end,
    [
        capture(fun() -> size({a, b, c}) end),
        capture(fun() -> size(<<1, 2, 3>>) end),
        capture(fun() -> size(<<7:3>>) end),
        capture(fun() -> size(not_a_tuple) end),
        capture(fun() -> node() end),
        capture(fun() -> node(self()) end),
        capture(fun() -> node(17) end),
        capture(fun() -> apply(erlang, phash, [foo, 1]) end),
        capture(fun() -> apply(erlang, phash, [#{a => 1}, 16#100000000]) end),
        capture(fun() -> apply(erlang, phash, [foo, 0]) end),
        capture(fun() -> atom_to_list('héllo') end),
        capture(fun() -> atom_to_list(not_an_atom) end),
        capture(fun() -> list_to_atom([104, 233, 108, 108, 111]) end),
        capture(fun() -> list_to_existing_atom("true") end),
        capture(fun() -> list_to_existing_atom("not_an_existing_atom") end),
        capture(fun() -> list_to_atom([16#d800]) end),
        capture(fun() -> atom_to_binary('på', latin1) end),
        capture(fun() -> atom_to_binary('på', utf8) end),
        capture(fun() -> atom_to_binary(på, nonsense) end),
        capture(fun() -> binary_to_atom(<<229>>, latin1) end),
        capture(fun() -> binary_to_existing_atom(<<"true">>, utf8) end),
        capture(fun() -> binary_to_existing_atom(<<"not_an_existing_atom">>, latin1) end),
        capture(fun() -> binary_to_atom(<<255>>, utf8) end),
        capture(fun() -> binary_to_atom(<<0:2048>>, utf8) end),
        capture(fun() -> binary_to_atom(<<0:4096, 255>>, utf8) end),
        capture(fun() -> float_to_list(0.0) end),
        capture(fun() -> float_to_list(-0.0, [short]) end),
        capture(fun() -> float_to_list(1.2345, [{decimals, 2}, compact]) end),
        capture(fun() -> float_to_list(1.2345, [{scientific, 4}]) end),
        capture(fun() -> float_to_list(1.0, [bad_option]) end),
        capture(fun() -> float_to_binary(-0.0, [short]) end),
        capture(fun() -> list_to_float("-0.0") end),
        capture(fun() -> list_to_float("1e2") end),
        capture(fun() -> binary_to_float(<<"2.5">>) end),
        capture(fun() -> binary_to_float(<<1:3>>) end),
        capture(fun() -> integer_to_binary(-12345678901234567890) end),
        capture(fun() -> integer_to_binary(Huge, 36) end),
        capture(fun() -> integer_to_binary(1, 1) end),
        capture(fun() -> is_integer(1, 0, 2) end),
        capture(fun() -> is_integer(Huge, -Huge, Huge) end),
        capture(fun() -> is_integer(not_integer, 0, 2) end),
        capture(fun() -> is_integer(1, 0, 1.0) end),
        capture(fun() -> is_function(Fun0, 0) end),
        capture(fun() -> is_function(Fun0, 1) end),
        capture(fun() -> is_function(Fun0, Huge) end),
        capture(fun() -> is_function(Fun0, -Huge) end),
        capture(fun() -> apply(erlang, is_builtin, [erlang, phash, 2]) end),
        capture(fun() -> apply(erlang, is_builtin, [erlang, apply, 2]) end),
        capture(fun() -> apply(erlang, is_builtin, [erlang, apply, 3]) end),
        capture(fun() -> apply(erlang, is_builtin, [erlang, yield, 0]) end),
        capture(fun() -> apply(erlang, is_builtin, [erlang, missing_builtin, -1]) end),
        capture(fun() -> apply(erlang, is_builtin, [not_an_atom, foo, 1]) end),
        capture(fun() -> error(explicit_reason, [first, second]) end),
        capture(fun() -> error(explicit_reason, [first], [{error_info, #{cause => detail}}]) end),
        capture(fun() -> error(explicit_reason, [first], [{error_info, not_a_map}]) end),
        capture(fun() -> erts_internal:cmp_term(1, 2) end),
        capture(fun() -> erts_internal:cmp_term(1, 1.0) end),
        capture(fun() -> erts_internal:cmp_term([-2], [-2.0]) end),
        capture(fun() -> erts_internal:cmp_term(1 bsl 62, 1.0) end),
        capture(fun() -> erts_internal:cmp_term({key, 5}, {key, 5.0}) end),
        capture(fun() -> erts_debug:copy_shared({a, [b]}, false) end),
        capture(fun() -> erts_debug:copy_shared(a, invalid_flag) end),
        capture(fun() -> erts_debug:flat_size({a, {b, c}}) end),
        capture(fun() -> erts_debug:same(1, 1) end),
        capture(fun() -> erts_debug:same(1, 1.0) end),
        capture(fun() -> unicode:bin_is_7bit(<<0, 127>>) end),
        capture(fun() -> unicode:bin_is_7bit(<<128>>) end),
        capture(fun() -> unicode:bin_is_7bit(<<5:3>>) end)
    ].
"#;

#[test]
fn remaining_pure_bifs_match_otp_29_at_vm_level() {
    let reference = RefErl::start().expect("OTP 29.1.1 reference");
    let beam = reference.compile_named(MODULE, SOURCE, &[]).unwrap();
    reference.load(MODULE, &beam).unwrap();
    let expected = reference.call(MODULE, "cases", &[]);

    let mut vm = crate::common::node();
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled(MODULE, "cases", &[], 1)
        .unwrap_or_else(|error| panic!("remaining pure BIF cases: {error}"));

    let CallResult::Ok(expected) = expected else {
        panic!("OTP reference did not return the captured case list: {expected:?}");
    };
    let actual = actual.term;
    let (
        arinsal_etf::OwnedTerm::List {
            elems: expected_cases,
            tail: expected_tail,
        },
        arinsal_etf::OwnedTerm::List {
            elems: actual_cases,
            tail: actual_tail,
        },
    ) = (&expected, &actual)
    else {
        panic!("case fixture must return proper lists");
    };
    assert_eq!(expected_tail.as_ref(), &arinsal_etf::OwnedTerm::Nil);
    assert_eq!(actual_tail.as_ref(), &arinsal_etf::OwnedTerm::Nil);
    assert_eq!(expected_cases.len(), actual_cases.len());
    for (index, (expected, actual)) in expected_cases.iter().zip(actual_cases.iter()).enumerate() {
        assert_eq!(expected, actual, "fixture case {}", index + 1);
    }
}
