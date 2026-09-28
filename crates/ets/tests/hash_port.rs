use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_ets::{
    ConcurrentTable, Protection, Registry, TableOptions, TableType, WriteConcurrency,
};
use arinsal_term::{Term, TermBuilder, VecHeap, global_atoms, to_owned};
use std::sync::Arc;
use std::thread;

fn options(table_type: TableType, write_concurrency: WriteConcurrency) -> TableOptions {
    TableOptions {
        name: global_atoms().intern("ets_hash_port").unwrap(),
        named_table: false,
        table_type,
        keypos: 1,
        protection: Protection::Public,
        owner: Term::pid(1, 0).unwrap(),
        heir: None,
        read_concurrency: true,
        write_concurrency,
        decentralized_counters: false,
        compressed: false,
    }
}

fn object(heap: &mut VecHeap, key: i64, value: i64) -> Term {
    TermBuilder::new(heap)
        .tuple(&[Term::small(key).unwrap(), Term::small(value).unwrap()])
        .unwrap()
}

fn lookup_values(registry: &Registry, tid: arinsal_ets::Tid, key: i64) -> Vec<OwnedTerm> {
    let mut heap = VecHeap::new();
    registry
        .get(tid)
        .unwrap()
        .lookup(Term::small(key).unwrap(), &mut heap)
        .unwrap()
        .into_iter()
        .map(|term| to_owned(term).unwrap())
        .collect()
}

#[test]
fn grow_and_shrink() {
    let mut registry = Registry::new();
    let tid = registry
        .create(options(TableType::Set, WriteConcurrency::Disabled))
        .unwrap();
    let mut heap = VecHeap::new();
    for key in 0..6000 {
        if key % 1024 == 0 {
            heap = VecHeap::new();
        }
        let item = object(&mut heap, key, key);
        registry.get_mut(tid).unwrap().insert(&[item]).unwrap();
    }
    assert!(
        registry
            .get(tid)
            .unwrap()
            .slot(5000, &mut VecHeap::new())
            .is_ok()
    );
    assert_eq!(registry.get(tid).unwrap().len(), 6000);
    for key in 0..5900 {
        registry
            .get_mut(tid)
            .unwrap()
            .delete_key(Term::small(key).unwrap());
    }
    assert!(
        registry
            .get(tid)
            .unwrap()
            .slot(3000, &mut VecHeap::new())
            .is_err()
    );
    assert_eq!(registry.get(tid).unwrap().len(), 100);
}

#[test]
fn bag_semantics_vs_erl() {
    let Some(erl) = reference() else { return };
    let expected = erl.call("ets_hash_port_fixture", "bag", &[]);
    let CallResult::Ok(OwnedTerm::List { ref elems, .. }) = expected else {
        panic!("OTP bag lookup failed")
    };
    let expected = elems.clone();
    let mut registry = Registry::new();
    let tid = registry
        .create(options(TableType::Bag, WriteConcurrency::Disabled))
        .unwrap();
    let mut heap = VecHeap::new();
    for value in [10, 10, 20] {
        let item = object(&mut heap, 1, value);
        registry.get_mut(tid).unwrap().insert(&[item]).unwrap();
    }
    assert_eq!(lookup_values(&registry, tid, 1), expected);
}

#[test]
fn duplicate_bag_semantics_vs_erl() {
    let Some(erl) = reference() else { return };
    let CallResult::Ok(OwnedTerm::List { ref elems, .. }) =
        erl.call("ets_hash_port_fixture", "duplicate_bag", &[])
    else {
        panic!("OTP duplicate_bag lookup failed")
    };
    let expected = elems.clone();
    let mut registry = Registry::new();
    let tid = registry
        .create(options(TableType::DuplicateBag, WriteConcurrency::Disabled))
        .unwrap();
    let mut heap = VecHeap::new();
    for value in [10, 10, 20] {
        let item = object(&mut heap, 1, value);
        registry.get_mut(tid).unwrap().insert(&[item]).unwrap();
    }
    assert_eq!(lookup_values(&registry, tid, 1), expected);
}

#[test]
fn iteration_order_vs_erl() {
    let Some(erl) = reference() else { return };
    for (table_type, function) in [
        (TableType::Set, "iteration_set"),
        (TableType::Bag, "iteration_bag"),
        (TableType::DuplicateBag, "iteration_duplicate_bag"),
    ] {
        let CallResult::Ok(OwnedTerm::List { ref elems, .. }) =
            erl.call("ets_hash_port_fixture", function, &[])
        else {
            panic!("OTP iteration order failed for {table_type:?}")
        };
        let expected = elems.clone();
        let mut registry = Registry::new();
        let tid = registry
            .create(options(table_type, WriteConcurrency::Disabled))
            .unwrap();
        let mut heap = VecHeap::new();
        for index in 1..=1000_i64 {
            if index % 256 == 0 {
                heap = VecHeap::new();
            }
            let value = Term::small(index).unwrap();
            let key = match index % 4 {
                0 => value,
                1 => TermBuilder::new(&mut heap)
                    .tuple(&[Term::small(-index).unwrap(), value])
                    .unwrap(),
                2 => Term::atom(global_atoms().intern(&format!("hash_key_{index}")).unwrap()),
                _ => TermBuilder::new(&mut heap)
                    .float(index as f64 + 0.5)
                    .unwrap(),
            };
            let object = TermBuilder::new(&mut heap).tuple(&[key, value]).unwrap();
            registry.get_mut(tid).unwrap().insert(&[object]).unwrap();
        }
        let actual = registry
            .get(tid)
            .unwrap()
            .tab2list(&mut VecHeap::new())
            .unwrap()
            .into_iter()
            .map(|term| to_owned(term).unwrap())
            .collect::<Vec<_>>();
        let mismatch = actual
            .iter()
            .zip(&expected)
            .position(|(actual, expected)| actual != expected);
        assert!(
            mismatch.is_none(),
            "tab2list order for {table_type:?} first differs at {:?}: expected {:?}, got {:?}",
            mismatch,
            mismatch.map(|index| &expected[index]),
            mismatch.map(|index| &actual[index]),
        );
    }
}

#[test]
fn safe_fixtable_iteration() {
    let mut registry = Registry::new();
    let tid = registry
        .create(options(TableType::Set, WriteConcurrency::Disabled))
        .unwrap();
    let mut heap = VecHeap::new();
    for key in 0..16 {
        let item = object(&mut heap, key, key);
        registry.get_mut(tid).unwrap().insert(&[item]).unwrap();
    }
    let table = registry.get_mut(tid).unwrap();
    table.safe_fixtable(true).unwrap();
    for key in 0..16 {
        let key = Term::small(key).unwrap();
        table.delete_key(key);
        let _ = table.next(key, &mut VecHeap::new()).unwrap();
    }
    table.safe_fixtable(false).unwrap();
    assert_eq!(table.len(), 0);
}

#[test]
fn concurrent_insert_lookup() {
    let table = Arc::new(
        ConcurrentTable::new(options(TableType::Set, WriteConcurrency::Enabled), 8).unwrap(),
    );
    let mut workers = Vec::new();
    for worker in 0..8_i64 {
        let table = Arc::clone(&table);
        workers.push(thread::spawn(move || {
            let mut heap = VecHeap::new();
            for offset in 0..1000_i64 {
                let key = worker * 1000 + offset;
                let item = object(&mut heap, key, key * 2);
                table.insert_one(item).unwrap();
            }
        }));
    }
    for worker in workers {
        worker.join().unwrap();
    }
    for key in 0..8000_i64 {
        let found = table
            .lookup(Term::small(key).unwrap(), &mut VecHeap::new())
            .unwrap();
        assert_eq!(found.len(), 1, "missing key {key}");
    }
}

#[cfg(not(miri))]
fn reference() -> Option<&'static RefErl> {
    let erl = RefErl::shared().ok()?;
    let beam = erl
        .compile_named(
            "ets_hash_port_fixture",
            include_str!("fixtures/ets_hash_port.erl"),
            &[],
        )
        .ok()?;
    erl.load("ets_hash_port_fixture", &beam).ok()?;
    Some(erl)
}

#[cfg(miri)]
fn reference() -> Option<RefErl> {
    None
}
