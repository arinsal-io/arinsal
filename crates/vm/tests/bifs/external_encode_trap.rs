//! `term_to_binary/1,2`, `term_to_iovec/1,2` and `external_size/1,2` of external.c on big
//! terms: results against the real `erl` (reductions and schedule-ins of the same calls are
//! compared in `reds_overcharge_differential`).

use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_term::Term;
use similar_asserts::assert_eq;

const MODULE: &str = "external_encode_trap_test";

const SOURCE: &str = r#"-module(external_encode_trap_test).
-export([run/1]).
term(list) -> lists:seq(1, 1000000);
term(floats) -> [float(N) || N <- lists:seq(1, 200000)];
term(tuple) -> deep(100000, a);
term(binary) -> binary:copy(<<1, 2, 3>>, 500000);
term(small) -> {a, [1, 2, 3], <<"x">>};
term(mixed) -> [{N, <<N:32>>, #{N => N}} || N <- lists:seq(1, 20000)].
deep(0, T) -> T;
deep(N, T) -> deep(N - 1, {T}).
opts(0) -> [];
opts(1) -> [{compressed, 6}];
opts(2) -> [{minor_version, 1}];
opts(3) -> [{compressed, 1}, deterministic];
opts(4) -> [{compressed, 9}].
cases() ->
    [{ttb1, list, 0}, {ttb1, tuple, 0}, {ttb1, binary, 0}, {ttb1, small, 0},
     {ttb2, list, 1}, {ttb2, binary, 4}, {ttb2, floats, 2}, {ttb2, mixed, 3},
     {ttb2, small, 1}, {iov1, binary, 0}, {iov1, list, 0}, {iov2, mixed, 2},
     {iov2, list, 1}, {size1, list, 0}, {size2, tuple, 2}].
reds() -> element(2, process_info(self(), reductions)).
run(Index) ->
    {Kind, Term, Opts} = lists:nth(Index, cases()),
    T = term(Term),
    O = opts(Opts),
    erlang:garbage_collect(),
    R0 = reds(),
    Res = case Kind of
        ttb1 -> term_to_binary(T);
        ttb2 -> term_to_binary(T, O);
        iov1 -> term_to_iovec(T);
        iov2 -> term_to_iovec(T, O);
        size1 -> erlang:external_size(T);
        size2 -> erlang:external_size(T, O)
    end,
    R1 = reds(),
    Check = case Kind of
        K when K =:= size1; K =:= size2 -> Res;
        K when K =:= iov1; K =:= iov2 ->
            Bin = iolist_to_binary(Res),
            {binary_to_term(Bin) =:= T, is_list(Res)};
        _ ->
            {binary_to_term(Res) =:= T, byte_size(Res) > 0}
    end,
    SizeCheck = case Kind of
        ttb1 -> {byte_size(Res), erlang:phash2(Res)};
        ttb2 when Opts =:= 0; Opts =:= 2 -> {byte_size(Res), erlang:phash2(Res)};
        iov1 -> {iolist_size(Res), erlang:phash2(iolist_to_binary(Res))};
        iov2 when Opts =:= 0; Opts =:= 2 -> {iolist_size(Res), erlang:phash2(iolist_to_binary(Res))};
        _ -> none
    end,
    {Check, SizeCheck, R1 - R0}.
"#;

fn split(result: OwnedTerm) -> (OwnedTerm, OwnedTerm) {
    let OwnedTerm::Tuple(ref fields) = result else {
        panic!("not a tuple: {result:?}");
    };
    (fields[0].clone(), fields[1].clone())
}

#[test]
fn term_to_binary_family_matches_otp_on_big_terms() {
    let reference = RefErl::start().expect("OTP 29.1.1 is required for this test");
    let beam = reference.compile_named(MODULE, SOURCE, &[]).unwrap();
    reference.load(MODULE, &beam).unwrap();
    let mut vm = crate::common::node();
    vm.load_bytes(&beam).unwrap();
    for index in 1..=15i64 {
        let CallResult::Ok(expected) = reference.call(MODULE, "run", &[OwnedTerm::Int(index)])
        else {
            panic!("OTP failed case {index}");
        };
        let actual = vm
            .eval_scheduled_reductions(
                MODULE,
                "run",
                &[Term::small(index).unwrap()],
                1,
                4_000,
            )
            .unwrap_or_else(|error| panic!("Arinsal failed case {index}: {error:?}"))
            .term;
        let (expected_check, expected_size) = split(expected);
        let (actual_check, actual_size) = split(actual);
        assert_eq!(expected_check, actual_check, "case {index}");
        assert_eq!(expected_size, actual_size, "case {index}");
    }
}
