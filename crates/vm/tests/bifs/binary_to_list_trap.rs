use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use similar_asserts::assert_eq;

#[test]
fn binary_to_list_one_megabyte_matches_otp_and_charges_reductions() {
    const MODULE: &str = "binary_to_list_trap_test";
    let reference = RefErl::start().expect("OTP 29.1.1 is required for this test");
    let source = r#"-module(binary_to_list_trap_test).
        -export([values/0, reductions/0, values3/0, reductions3/0]).
        subject() -> binary:copy(<<0, 1, 255, 17>>, 262144).
        values() ->
            List = erlang:binary_to_list(subject()),
            {length(List), lists:sum(List), hd(List), lists:last(List)}.
        reductions() ->
            List = erlang:binary_to_list(subject()),
            {_, Reds} = process_info(self(), reductions),
            {length(List), Reds}.
        values3() ->
            List = erlang:binary_to_list(subject(), 17, 528),
            {length(List), lists:sum(List), hd(List), lists:last(List)}.
        reductions3() ->
            List = erlang:binary_to_list(subject(), 17, 528),
            {_, Reds} = process_info(self(), reductions),
            {length(List), Reds}.
    "#;
    let beam = reference.compile_named(MODULE, source, &[]).unwrap();
    reference.load(MODULE, &beam).unwrap();
    let mut vm = crate::common::node();
    vm.load_bytes(&beam).unwrap();

    let expected_values = reference.call(MODULE, "values", &[]);
    let actual_values = vm
        .eval_scheduled_reductions(MODULE, "values", &[], 1, 4_000)
        .unwrap();
    assert_eq!(expected_values, CallResult::Ok(actual_values.term));

    let expected_values3 = reference.call(MODULE, "values3", &[]);
    let actual_values3 = vm
        .eval_scheduled_reductions(MODULE, "values3", &[], 1, 4_000)
        .unwrap();
    assert_eq!(expected_values3, CallResult::Ok(actual_values3.term));

    let CallResult::Ok(OwnedTerm::Tuple(ref expected)) = reference.call(MODULE, "reductions", &[])
    else {
        panic!("OTP reductions call did not return a tuple");
    };
    let actual = vm
        .eval_scheduled_reductions(MODULE, "reductions", &[], 1, 4_000)
        .unwrap();
    let OwnedTerm::Tuple(ref actual) = actual.term else {
        panic!("Arinsal reductions call did not return a tuple");
    };
    assert_eq!(expected[0], actual[0]);
    let (OwnedTerm::Int(expected_reds), OwnedTerm::Int(actual_reds)) = (&expected[1], &actual[1])
    else {
        panic!("reductions were not integers");
    };
    let slack = (expected_reds / 10).max(32);
    assert!(
        (expected_reds - slack..=expected_reds + slack).contains(actual_reds),
        "OTP reductions {expected_reds}, Arinsal reductions {actual_reds}, slack {slack}"
    );
    assert!(
        *actual_reds >= 4096,
        "large conversion did not charge per chunk"
    );

    let CallResult::Ok(OwnedTerm::Tuple(ref expected3)) =
        reference.call(MODULE, "reductions3", &[])
    else {
        panic!("OTP range reductions call did not return a tuple");
    };
    let actual3 = vm
        .eval_scheduled_reductions(MODULE, "reductions3", &[], 1, 4_000)
        .unwrap();
    let OwnedTerm::Tuple(ref actual3) = actual3.term else {
        panic!("Arinsal range reductions call did not return a tuple");
    };
    assert_eq!(expected3[0], actual3[0]);
    let (OwnedTerm::Int(expected_reds3), OwnedTerm::Int(actual_reds3)) =
        (&expected3[1], &actual3[1])
    else {
        panic!("range reductions were not integers");
    };
    let slack3 = (expected_reds3 / 10).max(32);
    assert!(
        (expected_reds3 - slack3..=expected_reds3 + slack3).contains(actual_reds3),
        "OTP range reductions {expected_reds3}, Arinsal range reductions {actual_reds3}, slack {slack3}"
    );
}

/// A `binary_to_list/1,3` that reschedules before it reserves the list (erts
/// `ERTS_BIF_YIELD1/3`) may be followed by a collection while the process is switched out;
/// the retried call must read its binary from the argument register that collection updated.
/// The loop below puts many calls on the "few reductions left" window of short slices, with
/// plenty of garbage so that the switch-out collects.
#[test]
fn binary_to_list_yield_before_allocation_survives_collection() {
    const MODULE: &str = "binary_to_list_yield_gc_test";
    let reference = RefErl::start().expect("OTP 29.1.1 is required for this test");
    let source = r#"-module(binary_to_list_yield_gc_test).
        -export([run/0]).
        run() -> loop(400, 0).
        loop(0, Acc) -> Acc;
        loop(N, Acc) ->
            Bin = binary:copy(<<1, 2, 3, 4>>, 20000 + N),
            Pad = lists:seq(1, 3000 + N),
            L = erlang:binary_to_list(Bin),
            M = erlang:binary_to_list(Bin, 5, 20000),
            true = length(L) =:= 4 * (20000 + N),
            true = length(M) =:= 19996,
            loop(N - 1, Acc + lists:sum(L) rem 1000 + length(Pad) + lists:sum(M) rem 1000).
    "#;
    let beam = reference.compile_named(MODULE, source, &[]).unwrap();
    reference.load(MODULE, &beam).unwrap();
    let mut vm = crate::common::node();
    vm.load_bytes(&beam).unwrap();
    let expected = reference.call(MODULE, "run", &[]);
    for slice in [1_900u32, 2_500, 3_100, 4_000] {
        let actual = vm
            .eval_scheduled_reductions(MODULE, "run", &[], 1, slice)
            .unwrap();
        assert_eq!(expected, CallResult::Ok(actual.term), "slice {slice}");
    }
}

/// One loop per trapping BIF family under short slices, with garbage between the calls so
/// the switch-out collections move the data. Families that stay collectable while parked
/// (reverse, binary_to_list before allocation, utf8 conversion) and families that disable
/// collection (append, subtract, iolist, binary search, unicode list, term_to_binary,
/// length, member, keyfind) must all return what OTP returns.
#[test]
fn trap_families_survive_switch_out_collections() {
    const MODULE: &str = "trap_families_gc_test";
    let reference = RefErl::start().expect("OTP 29.1.1 is required for this test");
    let source = r#"-module(trap_families_gc_test).
        -export([run/0]).
        run() -> loop(120, 0).
        loop(0, Acc) -> Acc;
        loop(N, Acc) ->
            L = lists:seq(1, 30000 + N),
            Pad = [{I, I} || I <- lists:seq(1, 2000)],
            R = lists:reverse(L),
            A = L ++ R,
            S = A -- R,
            Bin = list_to_binary([<<I:8>> || I <- lists:seq(1, 255)] ++ lists:duplicate(20000, 7)),
            Io = iolist_to_binary([Bin, L2 = lists:duplicate(5000, 65), Bin]),
            Sz = iolist_size([Bin, L2, Bin]),
            M = binary:matches(Io, [<<7, 7, 7>>]),
            U = unicode:characters_to_binary(lists:duplicate(40000, 16#10FFFF)),
            UL = unicode:characters_to_list(U),
            T = term_to_binary({L, R, Pad}),
            true = length(R) =:= 30000 + N,
            true = lists:member(30000 + N, A),
            {value, _} = lists:keysearch(2000, 1, Pad),
            true = byte_size(Io) =:= 2 * byte_size(Bin) + 5000,
            true = Sz =:= byte_size(Io),
            true = length(UL) =:= 40000,
            true = binary_to_term(T) =:= {L, R, Pad},
            loop(N - 1, Acc + length(S) + length(M) + byte_size(U) rem 1000 + byte_size(T) rem 1000).
    "#;
    let beam = reference.compile_named(MODULE, source, &[]).unwrap();
    reference.load(MODULE, &beam).unwrap();
    let mut vm = crate::common::node();
    vm.load_bytes(&beam).unwrap();
    let expected = reference.call(MODULE, "run", &[]);
    for slice in [1_900u32, 2_700, 4_000] {
        let actual = vm
            .eval_scheduled_reductions(MODULE, "run", &[], 1, slice)
            .unwrap();
        assert_eq!(expected, CallResult::Ok(actual.term), "slice {slice}");
    }
}
