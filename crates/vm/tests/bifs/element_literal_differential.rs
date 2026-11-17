//! Differential coverage, against OTP 29.1.1, of `element/2` on literal tuples (the
//! `emit_bif_element` literal-table branch of instr_guard_bifs.cpp) and of `setelement/3`
//! (bif.c `setelement_3`): positions in and out of range, bignum positions, a 40-tuple, error
//! frames and values that survive a collection.

use arinsal_difftest::{CallResult, CompareMode, RefErl, compare};
use arinsal_etf::OwnedTerm as O;

const MODULE: &str = "element_literal_differential";
const SOURCE: &str = r#"
-module(element_literal_differential).
-export([run/1]).

f1(N) -> element(1 + (N band 3), {a, b, c, d}).
f2(N) when is_integer(N) -> element(N, {a, b, c, d}).
f3(N) when is_integer(N) ->
    case N of _ when element(N, {1, 2, 3}) =:= 2 -> yes; _ -> no end.
f4(N) -> element(2 + (N band 1), {a, b, c, d}).
f5(N) when is_integer(N), N > 0, N < 4 -> element(N, {a, b, c, d}).
f6(N) when is_integer(N) -> element(N, {a}).

r(F) ->
    try F() of
        V -> {ok, V}
    catch
        C:E:S -> {C, E, hd(S)}
    end.

run(_) ->
    Big = 1 bsl 80,
    T = list_to_tuple(lists:seq(1, 40)),
    [[f1(I) || I <- lists:seq(0, 9)],
     [r(fun() -> f2(I) end) || I <- [-1, 0, 1, 4, 5, Big, -Big]],
     [f3(I) || I <- [0, 1, 2, 3, 4, Big]],
     [f4(I) || I <- [0, 1, 2]],
     [r(fun() -> f5(I) end) || I <- [1, 2, 3, 0, 4]],
     [r(fun() -> f6(I) end) || I <- [1, 2, 0, Big]],
     [r(fun() -> setelement(I, T, x) end) || I <- [1, 5, 40, 0, 41, -1, a, Big]],
     [r(fun() -> setelement(1, X, x) end) || X <- [{}, [], a, <<1>>]],
     [setelement(1, {1}, {y}), setelement(2, {1, 2}, z)],
     [begin X = setelement(2, {1, 2, 3}, I), erlang:garbage_collect(), X end
      || I <- lists:seq(1, 100000), I rem 20000 =:= 0]].
"#;

#[test]
fn element_literal_and_setelement_match_otp() {
    let reference = RefErl::start().expect("OTP 29.1.1 is required for this test");
    let beam = reference.compile_named(MODULE, SOURCE, &[]).unwrap();
    reference.load(MODULE, &beam).unwrap();
    let input = O::Nil;
    let expected = reference.call(MODULE, "run", std::slice::from_ref(&input));
    let mut vm = crate::common::node();
    vm.load_bytes(&beam).unwrap();
    let mut heap = arinsal_term::ProcessHeap::with_words(200_000);
    let input = arinsal_term::from_owned(&input, &mut heap).expect("allocate input");
    let actual = vm
        .eval_scheduled(MODULE, "run", &[input], 1)
        .unwrap_or_else(|error| panic!("VM evaluation failed: {error}"));
    let actual = CallResult::Ok(actual.term);
    assert!(
        compare(&expected, &actual, CompareMode::Exact).is_ok(),
        "expected {expected:?}, actual {actual:?}"
    );
}
