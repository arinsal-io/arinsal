//! A BIF epilogue collects at most once, compared with erts.
//!
//! erts decides in `erts_gc_after_bif_call_lhf` whether a BIF result needs a collection: heap
//! fragments larger than the free young area and an off-heap binary overhead above the virtual
//! binary heap limit are one test and one collection. `ets:lookup/2` of a row holding a long
//! list and a large reference-counted binary returns both in one fragment, so each call finds
//! both conditions at once.

use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_vm::Vm;

const MODULE: &str = "gc_bif_epilogue_once";
const ROUNDS: i64 = 20;
const SOURCE: &str = r#"
-module(gc_bif_epilogue_once).
-export([both/0, fragments/0]).

both() -> measure(4000, 500000).

fragments() -> measure(4000, 0).

%% Every round collects explicitly and then looks the row up, so the lookup epilogue is the
%% only other collection. The result is the collections beyond the explicit ones.
measure(Length, Size) ->
    Table = ets:new(rows, []),
    true = ets:insert(Table, {1, lists:seq(1, Length), binary:copy(<<1>>, Size)}),
    true = erlang:garbage_collect(),
    {C0, _, _} = erlang:statistics(garbage_collection),
    Sum = loop(20, Table, 0),
    {C1, _, _} = erlang:statistics(garbage_collection),
    true = Sum >= 0,
    C1 - C0 - 20.

loop(0, _, Acc) -> Acc;
loop(N, Table, Acc) ->
    true = erlang:garbage_collect(),
    [{1, List, Bin}] = ets:lookup(Table, 1),
    loop(N - 1, Table, Acc + length(List) + byte_size(Bin)).
"#;

fn collections(term: &OwnedTerm) -> i64 {
    match term {
        OwnedTerm::Int(value) => *value,
        other => panic!("expected integer, got {other:?}"),
    }
}

fn run(reference: &RefErl, beam: &[u8], function: &str) -> (i64, i64) {
    let expected = match reference.call(MODULE, function, &[]) {
        CallResult::Ok(term) => collections(&term),
        other => panic!("reference {function} failed: {other:?}"),
    };
    let mut vm = Vm::new([]);
    vm.load_bytes(beam).expect("load probe into Arinsal");
    let outcome = vm
        .eval_scheduled(MODULE, function, &[], 1, None)
        .unwrap_or_else(|error| panic!("Arinsal {function} failed: {error:?}"));
    (expected, collections(&outcome.term))
}

#[test]
fn bif_epilogue_collects_once_with_fragments_and_vheap() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping BIF epilogue collection test");
        return;
    };
    let beam = reference
        .compile_named(MODULE, SOURCE, &[])
        .expect("compile probe");
    reference.load(MODULE, &beam).expect("load probe");
    for function in ["both", "fragments"] {
        let (expected, actual) = run(&reference, &beam, function);
        eprintln!("{function}: erl {expected}, arinsal {actual}");
        assert!(
            (actual - expected).abs() <= 2,
            "{function}: Arinsal {actual} epilogue collections in {ROUNDS} rounds vs OTP {expected}"
        );
        assert!(
            (ROUNDS - 2..=ROUNDS + 2).contains(&actual),
            "{function}: {actual} epilogue collections in {ROUNDS} rounds, one each expected"
        );
    }
}
