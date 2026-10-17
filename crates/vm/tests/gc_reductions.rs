//! Reductions charged for garbage collection, compared with erts.
//!
//! erts adds the cost of every collection (`gc_cost`: one reduction per ten live words moved)
//! to the process reductions, from the heap test in generated code and from the BIF epilogue.
//! Each loop runs once with live data and `fullsweep_after` set to 0, so every collection is a
//! full sweep that moves it, and once with nothing live. The loop costs the same in both runs,
//! so the difference is the cost of the collections. A process that spends its slice stops
//! counting at zero, so the loops stay well inside one slice of 4000 reductions.
//! `erlang:garbage_collect/0` bumps the reductions by the cost of its collection too.

use std::sync::{Mutex, MutexGuard};

use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_vm::Vm;

const SOURCE: &str = r#"
-module(gc_reds_diff).
-export([heap_test/0, bif_epilogue/0, explicit_gc/0]).

heap_test() -> measure(fun heap_loop/2, 300, 1000).

bif_epilogue() -> measure(fun bif_loop/2, 300, 3000).

explicit_gc() -> measure(fun gc_loop/2, 5, 2000).

measure(Loop, Iterations, LiveCount) ->
    process_flag(fullsweep_after, 0),
    {Gcs, WithLive} = reductions(Loop, Iterations, lists:seq(1, LiveCount)),
    {_, Without} = reductions(Loop, Iterations, []),
    {Gcs, WithLive, Without}.

reductions(Loop, Iterations, Live) ->
    erlang:yield(),
    {G0, _, _} = erlang:statistics(garbage_collection),
    {reductions, R0} = process_info(self(), reductions),
    ok = Loop(Iterations, Live),
    {reductions, R1} = process_info(self(), reductions),
    {G1, _, _} = erlang:statistics(garbage_collection),
    _ = length(Live),
    {G1 - G0, R1 - R0}.

heap_loop(0, _) -> ok;
heap_loop(N, Live) ->
    _ = erlang:phash2({N,N,N,N,N,N,N,N,N,N,N,N,N,N,N,N,N,N,N,N,N,N,N,N,N,N,N,N,N,N,N,N,N,N,N,N,N,N,N,N}),
    heap_loop(N - 1, Live).

gc_loop(0, _) -> ok;
gc_loop(N, Live) ->
    true = erlang:garbage_collect(),
    gc_loop(N - 1, Live).

bif_loop(0, _) -> ok;
bif_loop(N, Live) ->
    _ = erlang:integer_to_list(1234567890123456789 + N - N),
    bif_loop(N - 1, Live).
"#;

fn guard() -> MutexGuard<'static, ()> {
    static LOCK: Mutex<()> = Mutex::new(());
    LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn run(reference: &RefErl, function: &str) -> (CallResult, OwnedTerm) {
    let beam = reference
        .compile_named("gc_reds_diff", SOURCE, &[])
        .expect("compile");
    reference.load("gc_reds_diff", &beam).expect("load");
    let expected = reference.call("gc_reds_diff", function, &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).expect("load bytes");
    let actual = vm
        .eval_scheduled("gc_reds_diff", function, &[], 1, None)
        .unwrap_or_else(|error| panic!("{function}: {error}"));
    (expected, actual.term)
}

fn triple(term: &OwnedTerm) -> (i64, i64, i64) {
    let OwnedTerm::Tuple(fields) = term else {
        panic!("expected a {{gcs, with live, without live}} tuple, got {term:?}");
    };
    let int = |term: &OwnedTerm| match term {
        OwnedTerm::Int(value) => *value,
        other => panic!("expected integer, got {other:?}"),
    };
    (int(&fields[0]), int(&fields[1]), int(&fields[2]))
}

fn check(function: &str, live_words: i64) {
    let _guard = guard();
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping GC reductions test");
        return;
    };
    let (expected, actual) = run(&reference, function);
    let CallResult::Ok(expected) = expected else {
        panic!("erl {function}: {expected:?}");
    };
    let (erl_gcs, erl_with, erl_without) = triple(&expected);
    let (gcs, with, without) = triple(&actual);
    assert!(
        erl_gcs >= 1 && gcs >= 1,
        "{function}: collections: erl {erl_gcs}, arinsal {gcs}"
    );
    let report = format!(
        "{function}: erl {erl_gcs} collections, {erl_with} reductions with live data, \
         {erl_without} without; arinsal {gcs} collections, {with} with, {without} without"
    );
    let cost = live_words / 10;
    assert!(
        erl_with - erl_without >= erl_gcs * cost / 2,
        "erl charges less than expected: {report}"
    );
    assert!(
        with - without >= gcs * cost / 2,
        "arinsal does not charge the collections: {report}"
    );
}

#[test]
fn gc_charged_to_reductions_from_the_heap_test() {
    check("heap_test", 1000 * 2);
}

#[test]
fn gc_charged_to_reductions_from_the_bif_epilogue() {
    check("bif_epilogue", 3000 * 2);
}

#[test]
fn gc_charged_to_reductions_from_erlang_garbage_collect() {
    check("explicit_gc", 2000 * 2);
}
