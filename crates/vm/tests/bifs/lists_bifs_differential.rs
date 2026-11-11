//! Results and errors of the erl_bif_lists.c BIFs against OTP 29.1.1: short and trapping lists,
//! improper lists, float/integer keys, compound keys and non-list arguments.

use arinsal_difftest::{CallResult, CompareMode, RefErl, compare};
use arinsal_etf::OwnedTerm;
use arinsal_vm::{Vm, VmError};

const MODULE: &str = "vm_lists_bifs_diff";
const SOURCE: &str = r#"
-module(vm_lists_bifs_diff).
-export([cases/0]).

r(F) -> try F() catch C:R -> {C, R} end.

cases() ->
    Seq = lists:seq(1, 7),
    Improper = [1 | tail],
    Tuples = [{1.0, a}, {2, b}, {c, d}],
    Key = {nested_key, #{payload => <<1, 2, 3>>}},
    Changed = {nested_key, #{payload => <<1, 2, 4>>}},
    Long = lists:seq(1, 300000),
    LongKv = [{I, I} || I <- Long],
    [r(F) || F <- [
        fun() -> [] ++ rhs end,
        fun() -> Seq ++ [] end,
        fun() -> Seq ++ [z] end,
        fun() -> Improper ++ [] end,
        fun() -> Improper ++ [x] end,
        fun() -> erlang:append(Seq, tail) end,
        fun() -> erlang:append(not_a_list, []) end,
        fun() -> length(Long ++ [x]) end,
        fun() -> length(Long ++ []) end,
        fun() -> (Long ++ improper_tail) =:= (Long ++ improper_tail) end,
        fun() -> (Seq ++ [Improper]) =:= Long end,
        fun() -> lists:reverse([], tail) end,
        fun() -> lists:reverse(Seq, tail) end,
        fun() -> lists:reverse(Improper, []) end,
        fun() -> lists:reverse(not_a_list, []) end,
        fun() -> hd(lists:reverse(Long, [])) end,
        fun() -> lists:reverse(Long ++ improper, []) end,
        fun() -> [lists:reverse(lists:seq(1, N), tail) || N <- [0, 1, 1024, 10000]] end,
        fun() -> lists:member(7, Seq) end,
        fun() -> lists:member(9, Seq) end,
        fun() -> lists:member(1.0, Seq) end,
        fun() -> lists:member(Key, [Changed, Key]) end,
        fun() -> lists:member(Key, [Changed]) end,
        fun() -> lists:member(1, [1.0]) end,
        fun() -> lists:member(1, Improper) end,
        fun() -> lists:member(0, Long) end,
        fun() -> lists:member(300000, Long) end,
        fun() -> lists:member(0, Long ++ x) end,
        fun() -> lists:member(0, x) end,
        fun() -> lists:keyfind(1, 1, Tuples) end,
        fun() -> lists:keyfind(2, 1, Tuples) end,
        fun() -> lists:keyfind(Key, 2, [{1, Changed}, {2, Key}]) end,
        fun() -> lists:keyfind(c, 1, Tuples) end,
        fun() -> lists:keyfind(9, 1, Tuples) end,
        fun() -> lists:keyfind(1, 0, Tuples) end,
        fun() -> lists:keyfind(1, a, Tuples) end,
        fun() -> lists:keyfind(1, 1, [{1} | x]) end,
        fun() -> lists:keyfind(0, 1, [{1} | x]) end,
        fun() -> lists:keyfind(0, 1, LongKv) end,
        fun() -> lists:keyfind(299999, 2, LongKv) end,
        fun() -> lists:keyfind(0, 1, LongKv ++ x) end,
        fun() -> lists:keymember(1, 1, Tuples) end,
        fun() -> lists:keymember(0, 1, LongKv) end,
        fun() -> lists:keysearch(2, 1, Tuples) end,
        fun() -> lists:keysearch(c, 3, Tuples) end,
        fun() -> lists:keysearch(299999, 1, LongKv) end,
        fun() -> Seq -- [2, 2.0, 4] end,
        fun() -> Seq -- Improper end,
        fun() -> Improper -- [1] end,
        fun() -> [] -- x end,
        fun() -> x -- [] end,
        fun() -> erlang:subtract(Seq, [7, 1]) end,
        fun() -> length(Long -- [1, 2, 3]) end,
        fun() -> length([1, 2, 3] -- Long) end,
        fun() -> length(Long -- [I || I <- Long, I rem 2 =:= 1]) end,
        fun() -> Long -- (Long ++ x) end,
        fun() -> (Long ++ x) -- Long end,
        fun() -> lists:seq(1, 20) -- [3, 3, 5 | lists:seq(30, 60)] end,
        fun() -> lists:keyfind({7, x}, 1, [{{7, x}, value}]) end,
        fun() -> lists:keysearch({7, x}, 1, [{{7, x}, value}]) end,
        fun() -> lists:keyfind(k, 0, []) end,
        fun() -> lists:keyfind(9, 1, Improper) end,
        fun() -> lists:keymember(k, 1, Improper) end,
        fun() -> lists:keysearch(k, pos, []) end
    ]] ++ [r(fun() -> lists:F(K, 1, L) end)
           || L <- [[{I, value} || I <- lists:seq(1, 5)],
                    [{I, a, b, c, d} || I <- lists:seq(1, 5)]],
              K <- [1, 5, 99],
              F <- [keyfind, keymember, keysearch]].
"#;

#[test]
fn list_bifs_match_otp() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping lists BIF differential test");
        return;
    };
    let beam = reference.compile_named(MODULE, SOURCE, &[]).unwrap();
    reference.load(MODULE, &beam).unwrap();
    let expected = reference.call(MODULE, "cases", &[]);

    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = match vm.eval_scheduled(MODULE, "cases", &[], 1, None) {
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
    assert!(mismatches.is_empty(), "lists BIF mismatch: {mismatches:#?}");
}
