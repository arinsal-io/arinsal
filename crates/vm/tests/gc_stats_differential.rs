//! `statistics(garbage_collection)` and `process_info` GC fields against OTP.
//!
//! Global collection counts include every scheduler. Explicit collections are
//! deterministic; allocation loops are compared within one order of magnitude.

use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_vm::Vm;

const MODULE: &str = "gc_stats_differential";
const SOURCE: &str = r#"
-module(gc_stats_differential).
-export([shape/0, explicit/0, minors/0, take/0, wide/0, bif/0, alloc/0]).

shape() ->
    process_flag(min_heap_size, 233),
    {_, _, Zero} = erlang:statistics(garbage_collection),
    {garbage_collection, Info} = process_info(self(), garbage_collection),
    {Zero,
     proplists:get_value(fullsweep_after, Info),
     proplists:get_value(min_heap_size, Info),
     proplists:get_value(min_bin_vheap_size, Info)}.

explicit() ->
    prepare(),
    {C0, W0, Z0} = erlang:statistics(garbage_collection),
    lists:foreach(fun(_) -> true = erlang:garbage_collect() end, lists:seq(1, 30)),
    {C1, W1, Z1} = erlang:statistics(garbage_collection),
    {C1 - C0, W1 - W0, Z0, Z1, minor()}.

minors() ->
    prepare(),
    {C0, W0, _} = erlang:statistics(garbage_collection),
    lists:foreach(fun(_) ->
                          true = erlang:garbage_collect(self(), [{type, minor}])
                  end, lists:seq(1, 8)),
    {C1, W1, Z} = erlang:statistics(garbage_collection),
    {C1 - C0, W1 - W0, Z, minor()}.

take() ->
    measured_take(233).

%% A large young heap makes BIF-epilogue collections the ones `statistics` sees.
wide() ->
    measured_take(10958).

measured_take(Min) ->
    Map = maps:from_list([{I, I} || I <- lists:seq(1, 32)]),
    process_flag(min_heap_size, Min),
    true = erlang:garbage_collect(),
    {C0, W0, _} = erlang:statistics(garbage_collection),
    Before = minor(),
    loop_take(4000, Map),
    {C1, W1, Z} = erlang:statistics(garbage_collection),
    {C1 - C0, W1 - W0, Z, Before, minor()}.

bif() ->
    prepare(),
    {C0, W0, _} = erlang:statistics(garbage_collection),
    Before = minor(),
    loop_put(2000, #{}),
    {C1, W1, Z} = erlang:statistics(garbage_collection),
    {C1 - C0, W1 - W0, Z, Before, minor()}.

alloc() ->
    prepare(),
    {C0, W0, _} = erlang:statistics(garbage_collection),
    Before = minor(),
    grow(8000, []),
    {C1, W1, Z} = erlang:statistics(garbage_collection),
    {C1 - C0, W1 - W0, Z, Before, minor()}.

%% The first scheduled process is created above the default minimum. Reset it
%% and collect so the measured heap matches a normal process.
prepare() ->
    process_flag(min_heap_size, 233),
    true = erlang:garbage_collect().

minor() ->
    proplists:get_value(minor_gcs,
                        element(2, process_info(self(), garbage_collection))).

loop_take(0, _) -> ok;
loop_take(N, Map) ->
    maps:take(1, Map),
    loop_take(N - 1, Map).

loop_put(0, Map) -> Map;
loop_put(N, Map) ->
    loop_put(N - 1, maps:put(N, N, Map)).

grow(0, Acc) -> Acc;
grow(N, Acc) ->
    grow(N - 1, [N | Acc]).
"#;

fn integer(term: &OwnedTerm) -> i64 {
    match term {
        OwnedTerm::Int(value) => *value,
        OwnedTerm::BigInt(value) => value.to_string().parse().expect("GC counter"),
        other => panic!("expected integer, got {other:?}"),
    }
}

fn fields(term: &OwnedTerm) -> Vec<i64> {
    let OwnedTerm::Tuple(values) = term else {
        panic!("expected tuple, got {term:?}");
    };
    values.iter().map(integer).collect()
}

fn call_both(reference: &RefErl, beam: &[u8], function: &str) -> (Vec<i64>, Vec<i64>) {
    let expected = match reference.call(MODULE, function, &[]) {
        CallResult::Ok(term) => fields(&term),
        other => panic!("reference {function} failed: {other:?}"),
    };
    let mut vm = Vm::new([]);
    vm.load_bytes(beam)
        .expect("load GC stats probe into Arinsal");
    let outcome = vm
        .eval_scheduled(MODULE, function, &[], 1, None)
        .unwrap_or_else(|error| panic!("Arinsal {function} failed: {error:?}"));
    (expected, fields(&outcome.term))
}

/// Explicit counts match; noisy loop counts stay within one order of magnitude.
fn assert_count(function: &str, index: usize, actual: i64, expected: i64, exact: bool) {
    if exact {
        let delta = (actual - expected).abs();
        assert!(
            delta <= 2,
            "{function} field {index}: Arinsal {actual} vs OTP {expected}"
        );
        return;
    }
    assert!(
        same_order(actual, expected),
        "{function} field {index}: Arinsal {actual} vs OTP {expected}"
    );
}

fn same_order(actual: i64, expected: i64) -> bool {
    // A handful of collections is scheduler noise, not a different order.
    if expected < 8 {
        return (actual - expected).abs() <= 4;
    }
    let lower = expected / 10;
    let upper = expected.saturating_mul(10);
    (lower..=upper).contains(&actual)
}

#[test]
fn garbage_collection_statistics_match_otp() {
    // `statistics(garbage_collection)` is VM-wide; match the single Arinsal worker below.
    let Ok(reference) = RefErl::start_with_erl_args(&["+S", "1"]) else {
        eprintln!("erl unavailable; skipping GC statistics differential test");
        return;
    };
    let beam = reference
        .compile_named(MODULE, SOURCE, &[])
        .expect("compile GC stats probe");
    reference.load(MODULE, &beam).expect("load GC stats probe");

    let (expected, actual) = call_both(&reference, &beam, "shape");
    similar_asserts::assert_eq!(expected.len(), 4);
    similar_asserts::assert_eq!(actual[0], 0, "statistics third element");
    similar_asserts::assert_eq!(actual[1], expected[1], "fullsweep_after");
    similar_asserts::assert_eq!(actual[2], expected[2], "min_heap_size");
    similar_asserts::assert_eq!(actual[3], expected[3], "min_bin_vheap_size");

    let (expected, actual) = call_both(&reference, &beam, "explicit");
    similar_asserts::assert_eq!(expected.len(), 5);
    // 30 major collections. Other schedulers may add a couple.
    assert_count("explicit", 0, actual[0], expected[0], true);
    assert!(
        actual[0] >= 30,
        "explicit collections {actual:?} expected at least 30 (OTP {expected:?})"
    );
    assert_count("explicit", 1, actual[1], expected[1], false);
    similar_asserts::assert_eq!(actual[2], 0, "statistics third element");
    similar_asserts::assert_eq!(actual[3], 0, "statistics third element");
    assert_count("explicit", 4, actual[4], expected[4], true);

    let (expected, actual) = call_both(&reference, &beam, "minors");
    similar_asserts::assert_eq!(expected.len(), 4);
    assert_count("minors", 0, actual[0], expected[0], true);
    assert!(
        actual[0] >= 8,
        "minor requests {actual:?} expected at least 8 (OTP {expected:?})"
    );
    assert_count("minors", 1, actual[1], expected[1], false);
    similar_asserts::assert_eq!(actual[2], 0, "statistics third element");
    assert_count("minors", 3, actual[3], expected[3], true);

    for function in ["take", "wide"] {
        let (expected, actual) = call_both(&reference, &beam, function);
        similar_asserts::assert_eq!(expected.len(), 5, "{function}");
        similar_asserts::assert_eq!(actual[2], 0, "{function} statistics third element");
        let exact = function == "wide";
        assert_count(function, 0, actual[0], expected[0], exact);
        assert_relative(function, 1, actual[1], expected[1]);
        assert_count(function, 3, actual[3], expected[3], true);
        assert_count(function, 4, actual[4], expected[4], exact);
    }

    let (expected, actual) = call_both(&reference, &beam, "bif");
    similar_asserts::assert_eq!(actual[2], 0, "bif statistics third element");
    assert_count("bif", 0, actual[0], expected[0], true);
    assert_count("bif", 1, actual[1], expected[1], true);
    assert_count("bif", 4, actual[4], expected[4], true);

    let (expected, actual) = call_both(&reference, &beam, "alloc");
    similar_asserts::assert_eq!(actual[2], 0, "alloc statistics third element");
    assert_count("alloc", 0, actual[0], expected[0], true);
    assert_count("alloc", 1, actual[1], expected[1], false);
    assert_count("alloc", 4, actual[4], expected[4], true);
}

fn assert_relative(function: &str, index: usize, actual: i64, expected: i64) {
    let tolerance = (expected.abs() / 100).max(50);
    assert!(
        (actual - expected).abs() <= tolerance,
        "{function} field {index}: Arinsal {actual} vs OTP {expected}"
    );
}
