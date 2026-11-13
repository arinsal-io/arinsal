//! Results and errors of the YCF map BIFs of erl_map.c against OTP 29.1.1: flatmaps, hashmaps
//! (above 32 keys), trapping sizes, duplicate keys, improper lists and non-map arguments.

use arinsal_difftest::{CallResult, CompareMode, RefErl, compare};
use arinsal_etf::OwnedTerm;
use arinsal_vm::{Vm, VmError};

const MODULE: &str = "vm_map_ycf_bifs_diff";
const SOURCE: &str = r#"
-module(vm_map_ycf_bifs_diff).
-export([cases/0]).

r(F) -> try F() catch C:R -> {C, R} end.

cases() ->
    Kv = fun(N) -> [{I, I * 10} || I <- lists:seq(1, N)] end,
    Big = maps:from_list(Kv(100000)),
    [r(F) || F <- [
        fun() -> maps:from_list([]) end,
        fun() -> maps:from_list(Kv(32)) end,
        fun() -> maps:from_list(Kv(33)) end,
        fun() -> maps:from_list([{a, 1}, {a, 2}, {b, 3}]) end,
        fun() -> maps:from_list([{I rem 40, I} || I <- lists:seq(1, 1000)]) end,
        fun() -> map_size(maps:from_list(Kv(100000))) end,
        fun() -> maps:from_list(Kv(5) ++ x) end,
        fun() -> maps:from_list([{a, 1}, {b}]) end,
        fun() -> maps:from_list([{a, 1, 2}]) end,
        fun() -> maps:from_list(not_a_list) end,
        fun() -> maps:from_list(Kv(100000) ++ [x]) end,
        fun() -> maps:from_keys([], v) end,
        fun() -> maps:from_keys([a, b, a], v) end,
        fun() -> maps:from_keys(lists:seq(1, 40), v) end,
        fun() -> map_size(maps:from_keys(lists:seq(1, 100000), v)) end,
        fun() -> maps:from_keys([a | b], v) end,
        fun() -> maps:from_keys(x, v) end,
        fun() -> maps:keys(#{}) end,
        fun() -> maps:keys(#{true => 1, false => 2}) end,
        fun() -> lists:sort(maps:keys(maps:from_list(Kv(40)))) end,
        fun() -> lists:sum(maps:keys(Big)) end,
        fun() -> maps:keys(not_a_map) end,
        fun() -> try maps:keys(make_ref()) catch error:{badmap, R} -> is_reference(R) end end,
        fun() -> maps:values(#{true => 1, false => 2}) end,
        fun() -> lists:sort(maps:values(maps:from_list(Kv(40)))) end,
        fun() -> lists:sum(maps:values(Big)) end,
        fun() -> maps:values([]) end,
        fun() -> maps:keys(Big) =:= [K || {K, _} <- maps:to_list(Big)] end
    ]].
"#;

#[test]
fn ycf_map_bifs_match_otp() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping map BIF differential test");
        return;
    };
    let beam = reference.compile_named(MODULE, SOURCE, &[]).unwrap();
    reference.load(MODULE, &beam).unwrap();
    let expected = reference.call(MODULE, "cases", &[]);

    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = match vm.eval_scheduled(MODULE, "cases", &[], 1) {
        Ok(outcome) => CallResult::Ok(outcome.term),
        Err(VmError::Raised(raised)) => CallResult::Exception {
            class: format!("{:?}", raised.class).to_lowercase(),
            reason: raised.reason,
            stack_top: Some(raised.stack),
        },
        Err(error) => CallResult::TransportError(error.to_string()),
    };
    let (
        CallResult::Ok(OwnedTerm::List { elems: want, .. }),
        CallResult::Ok(OwnedTerm::List { elems: got, .. }),
    ) = (&expected, &actual)
    else {
        panic!("cases/0 did not return a list: {actual:?}");
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
    assert!(mismatches.is_empty(), "map BIF mismatch: {mismatches:#?}");
}
