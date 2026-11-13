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
            measure(fun erlang:binary_to_list/1).
        values3() ->
            List = erlang:binary_to_list(subject(), 17, 528),
            {length(List), lists:sum(List), hd(List), lists:last(List)}.
        reductions3() ->
            measure(fun(Bin) -> erlang:binary_to_list(Bin, 17, 528) end).
        measure(Convert) ->
            Parent = self(),
            spawn_opt(fun() ->
                Bin = subject(),
                {reductions, R0} = process_info(self(), reductions),
                {garbage_collection, GC0} = process_info(self(), garbage_collection),
                List = Convert(Bin),
                {reductions, R1} = process_info(self(), reductions),
                {garbage_collection, GC1} = process_info(self(), garbage_collection),
                Gcs = proplists:get_value(minor_gcs, GC1) - proplists:get_value(minor_gcs, GC0),
                Parent ! {length(List), R1 - R0, Gcs}
            end, [{min_heap_size, 3000000}]),
            receive Result -> Result end.
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
    assert_eq!(
        expected[2],
        OwnedTerm::Int(0),
        "OTP collected in measured window"
    );
    assert_eq!(
        actual[2],
        OwnedTerm::Int(0),
        "Arinsal collected in measured window"
    );
    let slack = 32;
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
    assert_eq!(
        expected3[2],
        OwnedTerm::Int(0),
        "OTP collected in range window"
    );
    assert_eq!(
        actual3[2],
        OwnedTerm::Int(0),
        "Arinsal collected in range window"
    );
    let slack3 = 32;
    assert!(
        (expected_reds3 - slack3..=expected_reds3 + slack3).contains(actual_reds3),
        "OTP range reductions {expected_reds3}, Arinsal range reductions {actual_reds3}, slack {slack3}"
    );
}

#[test]
fn binary_to_list_delayed_gc_reductions_cover_gc_time() {
    const MODULE: &str = "binary_to_list_dirty_gc_test";
    let source = r#"-module(binary_to_list_dirty_gc_test).
        -export([dirty/0, baseline/0]).
        subject() -> binary:copy(<<0, 1, 255, 17>>, 262144).
        dirty() -> measure([], true).
        baseline() -> measure([{min_heap_size, 3000000}], false).
        measure(HeapOptions, Collect) ->
            Parent = self(),
            Pid = spawn_opt(fun() ->
                Bin = subject(),
                erlang:trace(self(), true, [{tracer, Parent}, garbage_collection, timestamp]),
                {reductions, R0} = process_info(self(), reductions),
                List = erlang:binary_to_list(Bin),
                case Collect of true -> erlang:garbage_collect(); false -> ok end,
                {reductions, R1} = process_info(self(), reductions),
                Parent ! {finished, length(List), R1 - R0}
            end, HeapOptions),
            Ref = monitor(process, Pid),
            collect(Pid, Ref, undefined, undefined, 0).
        collect(Pid, Ref, Result, Start, GcUs) ->
            receive
                {finished, _, _} = Value -> collect(Pid, Ref, Value, Start, GcUs);
                {trace_ts, Pid, gc_major_start, _, Ts} ->
                    collect(Pid, Ref, Result, Ts, GcUs);
                {trace_ts, Pid, gc_major_end, _, Ts} when Start =/= undefined ->
                    collect(Pid, Ref, Result, undefined, GcUs + timer:now_diff(Ts, Start));
                {'DOWN', Ref, process, Pid, _} ->
                    {Result, GcUs}
            after 30000 -> timeout
            end.
    "#;
    let reference = RefErl::start().expect("OTP 29.1.1 is required for this test");
    let beam = reference.compile_named(MODULE, source, &[]).unwrap();
    reference.load(MODULE, &beam).unwrap();
    let mut vm = crate::common::node();
    vm.load_bytes(&beam).unwrap();

    let baseline = vm.eval_scheduled(MODULE, "baseline", &[], 1).unwrap();
    let dirty = vm.eval_scheduled(MODULE, "dirty", &[], 1).unwrap();
    let OwnedTerm::Tuple(baseline) = &baseline.term else {
        panic!("baseline did not return a tuple");
    };
    let OwnedTerm::Tuple(dirty) = &dirty.term else {
        panic!("dirty GC probe did not return a tuple");
    };
    let (OwnedTerm::Tuple(baseline_result), OwnedTerm::Int(baseline_gc_us)) =
        (&baseline[0], &baseline[1])
    else {
        panic!("baseline returned {baseline:?}");
    };
    let (OwnedTerm::Tuple(dirty_result), OwnedTerm::Int(dirty_gc_us)) = (&dirty[0], &dirty[1])
    else {
        panic!("dirty GC probe returned {dirty:?}");
    };
    let (OwnedTerm::Int(baseline_len), OwnedTerm::Int(baseline_reds)) =
        (&baseline_result[1], &baseline_result[2])
    else {
        panic!("baseline result returned {baseline_result:?}");
    };
    let (OwnedTerm::Int(dirty_len), OwnedTerm::Int(dirty_reds)) =
        (&dirty_result[1], &dirty_result[2])
    else {
        panic!("dirty result returned {dirty_result:?}");
    };
    assert_eq!(baseline_len, dirty_len);
    assert_eq!(*dirty_len, 1_048_576);
    assert_eq!(
        *baseline_gc_us, 0,
        "preallocated baseline unexpectedly ran a major GC"
    );
    assert!(
        *dirty_gc_us > 0,
        "no major GC duration observed: baseline {baseline_gc_us} us, dirty {dirty_gc_us} us"
    );
    let charged = dirty_reds - baseline_reds;
    let minimum = dirty_gc_us * 4;
    assert!(
        charged >= minimum,
        "delayed major GC charged {charged} reductions over baseline, below 4 reds/us * {dirty_gc_us} us = {minimum}"
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
