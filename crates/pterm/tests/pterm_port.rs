use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Instant;

use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_pterm::Store;
use arinsal_term::{Term, TermBuilder, VecHeap, to_owned};

fn pair(term: Term) -> (i64, i64) {
    let owned = to_owned(term).unwrap();
    let OwnedTerm::Tuple(items) = &owned else {
        panic!("expected tuple")
    };
    let OwnedTerm::Int(left) = &items[0] else {
        panic!("expected integer")
    };
    let OwnedTerm::Int(right) = &items[1] else {
        panic!("expected integer")
    };
    (*left, *right)
}

fn info_fields(result: CallResult) -> (i64, i64) {
    let CallResult::Ok(OwnedTerm::Map(items)) = &result else {
        panic!("expected persistent_term:info/0 map")
    };
    let field = |name: &str| {
        let (_, OwnedTerm::Int(value)) = items
            .iter()
            .find(|(key, _)| *key == OwnedTerm::atom(name))
            .unwrap()
        else {
            panic!("expected integer info field")
        };
        *value
    };
    (field("count"), field("memory"))
}

#[test]
fn get_is_lock_free_under_concurrent_put() {
    let store = Store::new();
    let key = Term::small(9001).unwrap();
    let mut source = VecHeap::new();
    let initial = TermBuilder::new(&mut source)
        .tuple(&[Term::small(0).unwrap(), Term::small(0).unwrap()])
        .unwrap();
    store.put(key, initial).unwrap();

    let start = Arc::new(Barrier::new(9));
    let finished = AtomicBool::new(false);
    thread::scope(|scope| {
        for _ in 0..8 {
            let store = &store;
            let start = Arc::clone(&start);
            let finished = &finished;
            scope.spawn(move || {
                let registration = store.register_process();
                start.wait();
                while !finished.load(Ordering::Acquire) {
                    let (left, right) = pair(store.get(key).unwrap());
                    assert_eq!(left, -right, "reader observed an incomplete publication");
                }
                drop(registration);
            });
        }
        start.wait();
        for value in 1..=20_000 {
            let term = TermBuilder::new(&mut source)
                .tuple(&[Term::small(value).unwrap(), Term::small(-value).unwrap()])
                .unwrap();
            store.put(key, term).unwrap();
        }
        finished.store(true, Ordering::Release);
    });
    assert_eq!(pair(store.get(key).unwrap()), (20_000, -20_000));
}

#[test]
fn erase_keeps_old_value_alive_for_readers() {
    let store = Store::new();
    let process = store.register_process();
    let key = Term::small(41).unwrap();
    let mut source = VecHeap::new();
    let value = TermBuilder::new(&mut source)
        .tuple(&[Term::small(17).unwrap(), Term::small(23).unwrap()])
        .unwrap();
    store.put(key, value).unwrap();
    let reader_value = store.get(key).unwrap();

    assert!(store.erase(key));
    assert_eq!(pair(reader_value), (17, 23));
    let retired = store.retired_areas(&process);
    assert_eq!(retired.len(), 1);
    assert!(retired[0].contains(reader_value));
    let id = retired[0].id();
    drop(retired);
    assert!(store.acknowledge(&process, id));
    assert!(!store.has_retired());
}

#[test]
fn info_matches_erl() {
    let reference = RefErl::start().expect("OTP 29.1.1 erl is required");
    let store = Store::new();
    let baseline = store.info();
    let ref_baseline = info_fields(reference.call("persistent_term", "info", &[]));
    let key = Term::small(81).unwrap();
    store.put(key, Term::small(82).unwrap()).unwrap();
    reference.call(
        "persistent_term",
        "put",
        &[OwnedTerm::Int(81), OwnedTerm::Int(82)],
    );
    let actual = store.info();
    let expected = info_fields(reference.call("persistent_term", "info", &[]));
    assert_eq!(
        actual.0 as i64 - baseline.0 as i64,
        expected.0 - ref_baseline.0
    );
    assert_eq!(
        actual.1 as i64 - baseline.1 as i64,
        expected.1 - ref_baseline.1
    );
}

#[test]
fn get_default_vs_erl() {
    let reference = RefErl::start().expect("OTP 29.1.1 erl is required");
    let store = Store::new();
    let key = Term::small(93).unwrap();
    let default = Term::small(94).unwrap();
    let actual = store.get(key).unwrap_or(default);
    assert_eq!(to_owned(actual).unwrap(), OwnedTerm::Int(94));
    assert_eq!(
        reference.call(
            "persistent_term",
            "get",
            &[OwnedTerm::Int(93), OwnedTerm::Int(94)]
        ),
        CallResult::Ok(OwnedTerm::Int(94))
    );
}

#[test]
fn put_same_value_is_noop_like_erl() {
    let reference = RefErl::start().expect("OTP 29.1.1 erl is required");
    let store = Store::new();
    let key = Term::small(101).unwrap();
    let value = Term::small(102).unwrap();
    store.put(key, value).unwrap();
    let after_first = store.info();
    store.put(key, value).unwrap();
    assert_eq!(store.info(), after_first);

    let args = [OwnedTerm::Int(101), OwnedTerm::Int(102)];
    assert_eq!(
        reference.call("persistent_term", "put", &args),
        CallResult::Ok(OwnedTerm::atom("ok"))
    );
    let after_first = info_fields(reference.call("persistent_term", "info", &[]));
    assert_eq!(
        reference.call("persistent_term", "put", &args),
        CallResult::Ok(OwnedTerm::atom("ok"))
    );
    assert_eq!(
        info_fields(reference.call("persistent_term", "info", &[])),
        after_first
    );
}

#[test]
fn release_get_10k_entries_reports_ns_per_op() {
    let store = Store::new();
    let _process = store.register_process();
    for index in 0..10_000 {
        store
            .put(Term::small(index).unwrap(), Term::small(index + 1).unwrap())
            .unwrap();
    }
    let iterations = 2_000_000_u64;
    let started = Instant::now();
    let mut checksum = 0_i64;
    for index in 0..iterations {
        let key = Term::small((index % 10_000) as i64).unwrap();
        checksum += std::hint::black_box(store.get(std::hint::black_box(key)).unwrap())
            .as_small()
            .unwrap();
    }
    let ns = started.elapsed().as_nanos() / u128::from(iterations);
    eprintln!("persistent_term get/1 (10k entries): {ns} ns/op");
    assert_eq!(checksum, 10_001_000_i64 * 1_000);
    if !cfg!(debug_assertions) {
        assert!(ns <= 30, "get latency {ns} ns/op exceeds 30 ns/op");
    }
}
