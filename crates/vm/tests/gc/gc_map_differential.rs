//! GC and heap-size differential for a persistent map-building loop.

use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_vm::Vm;

const MODULE: &str = "gc_map_differential";
const SOURCE: &str = r#"
-module(gc_map_differential).
-export([run/0]).

run() ->
    {Count0, Words0, _} = erlang:statistics(garbage_collection),
    Info0 = process_info(self(), [heap_size, total_heap_size, garbage_collection]),
    Map = build(0, 100000, #{}),
    {Count1, Words1, _} = erlang:statistics(garbage_collection),
    Info1 = process_info(self(), [heap_size, total_heap_size, garbage_collection]),
    {Count0, Words0, Count1, Words1, Info0, Info1, map_size(Map)}.

build(N, N, Map) -> Map;
build(I, N, Map) -> build(I + 1, N, maps:put(I, I + 1, Map)).
"#;

#[derive(Clone, Copy, Debug)]
struct Snapshot {
    collections: i64,
    reclaimed_words: i64,
    heap_before: i64,
    total_before: i64,
    minor_gcs_before: i64,
    fullsweep_after_before: i64,
    min_heap_size_before: i64,
    heap_after: i64,
    total_after: i64,
    minor_gcs_after: i64,
    fullsweep_after_after: i64,
    min_heap_size_after: i64,
}

impl Snapshot {
    fn read(term: &OwnedTerm) -> Self {
        let OwnedTerm::Tuple(fields) = term else {
            panic!("expected snapshot tuple, got {term:?}");
        };
        assert_eq!(fields.len(), 7);
        let heap_before = info_size(&fields[4], "heap_size");
        let total_before = info_size(&fields[4], "total_heap_size");
        let heap_after = info_size(&fields[5], "heap_size");
        let total_after = info_size(&fields[5], "total_heap_size");
        assert_eq!(integer(&fields[6]), 100_000);
        Self {
            collections: integer(&fields[2]) - integer(&fields[0]),
            reclaimed_words: integer(&fields[3]) - integer(&fields[1]),
            heap_before,
            total_before,
            minor_gcs_before: info_size(&fields[4], "minor_gcs"),
            fullsweep_after_before: info_size(&fields[4], "fullsweep_after"),
            min_heap_size_before: info_size(&fields[4], "min_heap_size"),
            heap_after,
            total_after,
            minor_gcs_after: info_size(&fields[5], "minor_gcs"),
            fullsweep_after_after: info_size(&fields[5], "fullsweep_after"),
            min_heap_size_after: info_size(&fields[5], "min_heap_size"),
        }
    }
}

fn integer(term: &OwnedTerm) -> i64 {
    match term {
        OwnedTerm::Int(value) => *value,
        OwnedTerm::BigInt(value) => value.to_string().parse().expect("small GC counter"),
        other => panic!("expected integer, got {other:?}"),
    }
}

fn info_size(info: &OwnedTerm, name: &str) -> i64 {
    let OwnedTerm::List { elems, tail } = info else {
        panic!("expected process_info list, got {info:?}");
    };
    assert!(matches!(tail.as_ref(), OwnedTerm::Nil));
    let Some(OwnedTerm::Tuple(pair)) = elems.iter().find(|entry| {
        matches!(entry, OwnedTerm::Tuple(pair) if pair.first() == Some(&OwnedTerm::Atom(name.into())))
    }) else {
        if name != "heap_size"
            && name != "total_heap_size"
            && let Some(OwnedTerm::Tuple(pair)) = elems.iter().find(|entry| {
                matches!(entry, OwnedTerm::Tuple(pair) if pair.first() == Some(&OwnedTerm::Atom("garbage_collection".into())))
            })
        {
            return info_size(&pair[1], name);
        }
        panic!("missing process_info({name}): {info:?}");
    };
    integer(&pair[1])
}

fn call_reference(reference: &RefErl) -> Snapshot {
    match reference.call(MODULE, "run", &[]) {
        CallResult::Ok(term) => Snapshot::read(&term),
        other => panic!("reference map loop failed: {other:?}"),
    }
}

fn call_arinsal(vm: &mut Vm) -> Snapshot {
    let outcome = vm
        .eval_scheduled(MODULE, "run", &[], 1, None)
        .expect("Arinsal map loop");
    Snapshot::read(&outcome.term)
}

fn assert_within_otp_variance(actual: i64, references: &[Snapshot], field: &str) {
    let values = references.iter().map(|snapshot| match field {
        "collections" => snapshot.collections,
        "reclaimed_words" => snapshot.reclaimed_words,
        "heap_before" => snapshot.heap_before,
        "total_before" => snapshot.total_before,
        "minor_gcs_before" => snapshot.minor_gcs_before,
        "fullsweep_after_before" => snapshot.fullsweep_after_before,
        "min_heap_size_before" => snapshot.min_heap_size_before,
        "heap_after" => snapshot.heap_after,
        "total_after" => snapshot.total_after,
        "minor_gcs_after" => snapshot.minor_gcs_after,
        "fullsweep_after_after" => snapshot.fullsweep_after_after,
        "min_heap_size_after" => snapshot.min_heap_size_after,
        _ => unreachable!(),
    });
    let (minimum, maximum) = values.fold((i64::MAX, i64::MIN), |(min, max), value| {
        (min.min(value), max.max(value))
    });
    assert!(
        (minimum..=maximum).contains(&actual),
        "Arinsal {field}={actual} outside OTP run-to-run range {minimum}..={maximum}; OTP={references:?}"
    );
}

#[test]
#[ignore = "needs heap fragments + deferred GC (erl_gc.h ERTS_IS_GC_DESIRED), task gc_frag"]
fn map_building_gc_counts_and_heap_sizes_match_otp_variance() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping map GC differential test");
        return;
    };
    let beam = reference
        .compile_named(MODULE, SOURCE, &[])
        .expect("compile map GC probe");
    reference.load(MODULE, &beam).expect("load map GC probe");

    let references = (0..3)
        .map(|_| call_reference(&reference))
        .collect::<Vec<_>>();
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam)
        .expect("load map GC probe into Arinsal");
    let actual = call_arinsal(&mut vm);
    for field in [
        "collections",
        "reclaimed_words",
        "heap_before",
        "total_before",
        "minor_gcs_before",
        "fullsweep_after_before",
        "min_heap_size_before",
        "heap_after",
        "total_after",
        "minor_gcs_after",
        "fullsweep_after_after",
        "min_heap_size_after",
    ] {
        let value = match field {
            "collections" => actual.collections,
            "reclaimed_words" => actual.reclaimed_words,
            "heap_before" => actual.heap_before,
            "total_before" => actual.total_before,
            "minor_gcs_before" => actual.minor_gcs_before,
            "fullsweep_after_before" => actual.fullsweep_after_before,
            "min_heap_size_before" => actual.min_heap_size_before,
            "heap_after" => actual.heap_after,
            "total_after" => actual.total_after,
            "minor_gcs_after" => actual.minor_gcs_after,
            "fullsweep_after_after" => actual.fullsweep_after_after,
            "min_heap_size_after" => actual.min_heap_size_after,
            _ => unreachable!(),
        };
        assert_within_otp_variance(value, &references, field);
    }
}
