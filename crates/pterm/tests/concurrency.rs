use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Instant;

use arinsal_etf::OwnedTerm;
use arinsal_pterm::Store;
use arinsal_term::{Term, TermBuilder, VecHeap, to_owned};

fn tuple_pair(value: Term) -> (i64, i64) {
    let owned = to_owned(value).expect("persistent term");
    let OwnedTerm::Tuple(items) = &owned else {
        panic!("expected tuple");
    };
    let small = |item: &OwnedTerm| match item {
        OwnedTerm::Int(value) => *value,
        other => panic!("expected small integer, got {other:?}"),
    };
    (small(&items[0]), small(&items[1]))
}

#[test]
fn eight_readers_and_one_hundred_thousand_updates() {
    let store = Store::new();
    let key = Term::small(7).unwrap();
    let mut source = VecHeap::new();
    let initial = TermBuilder::new(&mut source)
        .tuple(&[Term::small(0).unwrap(), Term::small(0).unwrap()])
        .unwrap();
    store.put(key, initial).unwrap();
    let start = Arc::new(Barrier::new(9));
    let done = AtomicBool::new(false);
    thread::scope(|scope| {
        for _ in 0..8 {
            let start = Arc::clone(&start);
            let store = &store;
            let done = &done;
            scope.spawn(move || {
                let process = store.register_process();
                start.wait();
                while !done.load(Ordering::Acquire) {
                    let value = store.get(key).unwrap();
                    let (a, b) = tuple_pair(value);
                    assert_eq!(b, -a, "torn persistent-term read");
                }
                assert!(store.retired_areas(&process).is_empty());
            });
        }
        start.wait();
        for i in 1..=100_000 {
            let value = TermBuilder::new(&mut source)
                .tuple(&[Term::small(i).unwrap(), Term::small(-i).unwrap()])
                .unwrap();
            store.put(key, value).unwrap();
        }
        assert_eq!(
            store.retired_count(),
            100_000,
            "retired areas stay queued until the collector selects them"
        );
        done.store(true, Ordering::Release);
    });
    assert!(!store.collector_switch_area());
    assert_eq!(store.retired_count(), 0);
    let value = store.get(key).unwrap();
    assert_eq!(tuple_pair(value).0, 100_000);
}

#[test]
fn get_latency_nanoseconds_per_operation() {
    let store = Store::new();
    let process = store.register_process();
    let key = Term::small(99).unwrap();
    store.put(key, Term::small(123).unwrap()).unwrap();
    let iterations = 2_000_000;
    let begin = Instant::now();
    let mut checksum = 0_i64;
    for _ in 0..iterations {
        checksum += std::hint::black_box(
            store
                .get(std::hint::black_box(key))
                .unwrap()
                .as_small()
                .unwrap(),
        );
    }
    let ns = begin.elapsed().as_nanos() / iterations;
    let build = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    };
    eprintln!("persistent_term get/1: {ns} ns/op ({build} build), checksum={checksum}");
    assert_eq!(checksum, iterations as i64 * 123);
    drop(process);
}

#[test]
fn vm_test_double_copies_then_acknowledges_each_area() {
    let store = Store::new();
    let first = store.register_process();
    let second = store.register_process();
    let key = Term::small(1).unwrap();
    let mut source = VecHeap::new();
    let old = TermBuilder::new(&mut source)
        .tuple(&[Term::small(17).unwrap(), Term::small(23).unwrap()])
        .unwrap();
    store.put(key, old).unwrap();
    let borrowed = store.get(key).unwrap();
    store.put(key, Term::small(99).unwrap()).unwrap();
    assert_eq!(store.retired_count(), 1);
    assert!(store.collector_switch_area());
    let first_area = store.retired_areas(&first).pop().unwrap();
    let second_area = store.retired_areas(&second).pop().unwrap();
    assert!(first_area.contains(borrowed));
    let mut first_heap = VecHeap::new();
    let copied = first_area.copy_root(borrowed, &mut first_heap).unwrap();
    assert_ne!(copied, borrowed);
    assert!(!first_area.contains(copied));
    let id = first_area.id();
    drop(first_area);
    assert!(store.acknowledge(&first, id));
    assert_eq!(store.retired_count(), 1);
    let mut second_heap = VecHeap::new();
    second_area.copy_root(borrowed, &mut second_heap).unwrap();
    drop(second_area);
    assert!(store.acknowledge(&second, id));
    assert_eq!(store.retired_count(), 1);
    assert!(!store.collector_switch_area());
    assert_eq!(store.retired_count(), 0);
    assert_eq!(tuple_pair(copied), (17, 23));
}
