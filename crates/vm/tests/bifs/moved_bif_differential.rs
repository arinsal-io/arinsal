//! Cases of the retired arinsal-bifs differential tests whose BIF bodies live in the VM:
//! `erlang:length/1`, the `maps` BIFs of erl_map.c and `binary_to_list/1`, `binary:at/2`,
//! `binary:match/2`, `binary:split/2` on an unaligned sub-binary, against OTP 29.1.1.

use arinsal_difftest::{CallResult, CompareMode, RefErl, compare};
use arinsal_etf::OwnedTerm;

const MODULE: &str = "vm_moved_bif_diff";
const SOURCE: &str = r#"
-module(vm_moved_bif_diff).
-export([cases/0]).

r(F) -> try F() catch C:R -> {C, R} end.

cases() ->
    Seq = lists:seq(1, 7),
    Improper = [1 | tail],
    Backing = <<2#01000000, 2#11000000, 2#01000000>>,
    <<_:1, Sub:16/bitstring, _/bitstring>> = Backing,
    Needle = <<2#10000000>>,
    [r(F) || F <- [
        fun() -> length([]) end,
        fun() -> length(Seq) end,
        fun() -> length(Improper) end
    ]] ++
    [r(fun() -> M end) || N <- lists:seq(0, 999),
        Map <- [#{1 => N, 2 => N + 1}],
        M <- [maps:find(1, Map), maps:get(1, Map), maps:is_key(1, Map),
              maps:put(1, N + 5, Map), maps:remove(1, Map), maps:update(1, N + 5, Map),
              maps:take(1, Map), maps:merge(Map, Map), map_size(Map),
              map_get(1, Map), is_map_key(1, Map)]] ++
    [r(F) || F <- [
        fun() -> binary_to_list(Sub) end,
        fun() -> binary:at(Sub, 1) end,
        fun() -> binary:match(Sub, Needle) end,
        fun() -> binary:split(Sub, Needle) end
    ]].
"#;

#[test]
fn moved_bif_cases_match_otp() {
    let reference = RefErl::start().expect("OTP 29.1.1 is required for this test");
    let beam = reference.compile_named(MODULE, SOURCE, &[]).unwrap();
    reference.load(MODULE, &beam).unwrap();
    let CallResult::Ok(expected) = reference.call(MODULE, "cases", &[]) else {
        panic!("OTP cases/0 failed");
    };
    let OwnedTerm::List { elems: want, .. } = &expected else {
        panic!("OTP cases/0 did not return a list");
    };
    let mut vm = crate::common::node();
    vm.load_bytes(&beam).unwrap();
    let actual = vm.eval_scheduled(MODULE, "cases", &[], 1).unwrap().term;
    let OwnedTerm::List { elems: got, .. } = &actual else {
        panic!("cases/0 returned {actual:?}");
    };
    assert_eq!(want.len(), got.len());
    let mismatches: Vec<String> = want
        .iter()
        .zip(got)
        .enumerate()
        .filter_map(|(index, (want, got))| {
            compare(
                &CallResult::Ok(want.clone()),
                &CallResult::Ok(got.clone()),
                CompareMode::Exact,
            )
            .err()
            .map(|error| format!("case {index}: {error}"))
        })
        .collect();
    assert!(mismatches.is_empty(), "mismatches: {mismatches:#?}");
}
