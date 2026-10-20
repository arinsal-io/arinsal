use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_ets::{
    ConcurrentTable, Protection, Registry, Table, TableOptions, TableType, WriteConcurrency,
    match_spec::MatchProgram,
};
use arinsal_term::{Term, TermBuilder, VecHeap, cmp, from_owned, global_atoms, to_owned};
use std::sync::Arc;
use std::thread;

fn options(write_concurrency: WriteConcurrency) -> TableOptions {
    TableOptions {
        name: global_atoms().intern("ets_catree_port").unwrap(),
        named_table: false,
        table_type: TableType::OrderedSet,
        keypos: 1,
        protection: Protection::Public,
        owner: Term::pid(1, 0).unwrap(),
        heir: None,
        read_concurrency: false,
        write_concurrency,
        decentralized_counters: false,
        compressed: false,
    }
}

fn table(write_concurrency: WriteConcurrency) -> (Registry, arinsal_ets::Tid) {
    let mut registry = Registry::new();
    let tid = registry.create(options(write_concurrency)).unwrap();
    (registry, tid)
}

fn insert_range(table: &mut Table, low: i64, high: i64) {
    let mut heap = VecHeap::new();
    for key in low..high {
        let key = Term::small(key).unwrap();
        let object = TermBuilder::new(&mut heap).tuple(&[key, key]).unwrap();
        table.insert(&[object]).unwrap();
    }
}

fn force_split(table: &Table, key: i64) {
    assert!(table.catree_debug_adjust_contention(Term::small(key).unwrap(), 30_000));
    assert!(table.catree_debug_base_count().unwrap() > 1);
}

#[test]
fn split_under_contention() {
    let (registry, tid) = table(WriteConcurrency::Enabled);
    let mut stored = registry.get_mut(tid).unwrap();
    insert_range(&mut stored, 0, 512);
    assert_eq!(stored.catree_debug_base_count(), Some(1));
    force_split(&stored, 0);
    assert!(stored.avl_invariants_hold());
    assert_eq!(stored.len(), 512);
}

// Port of erts/emulator/beam/erl_db_catree.c (wlock_base_node): an uncontended write lowers the
// base node statistics, so a single writer never splits the tree.
#[test]
fn uncontended_writes_never_split() {
    let (registry, tid) = table(WriteConcurrency::Enabled);
    let mut stored = registry.get_mut(tid).unwrap();
    insert_range(&mut stored, 0, 3000);
    assert_eq!(stored.catree_debug_base_count(), Some(1));
    assert_eq!(stored.len(), 3000);
}

#[test]
fn join_when_quiet() {
    let (registry, tid) = table(WriteConcurrency::Enabled);
    let mut stored = registry.get_mut(tid).unwrap();
    insert_range(&mut stored, 0, 512);
    force_split(&stored, 0);
    assert!(stored.catree_debug_adjust_contention(Term::small(0).unwrap(), -1500));
    assert_eq!(stored.catree_debug_base_count(), Some(1));
    assert!(stored.avl_invariants_hold());
    assert_eq!(stored.len(), 512);
}

fn reference() -> Option<RefErl> {
    let erl = match RefErl::start() {
        Ok(erl) => erl,
        Err(error) => {
            eprintln!("skipping differential test: {error}");
            return None;
        }
    };
    let beam = erl
        .compile_named("ets_ops", include_str!("fixtures/ets_ops.erl"), &[])
        .unwrap();
    erl.load("ets_ops", &beam).unwrap();
    Some(erl)
}

#[test]
fn range_select_across_bases_vs_erl() {
    let (registry, tid) = table(WriteConcurrency::Enabled);
    let mut stored = registry.get_mut(tid).unwrap();
    insert_range(&mut stored, 0, 1000);
    force_split(&stored, 0);

    let spec = OwnedTerm::list(vec![OwnedTerm::Tuple(vec![
        OwnedTerm::Tuple(vec![
            OwnedTerm::Atom("$1".into()),
            OwnedTerm::Atom("$2".into()),
        ]),
        OwnedTerm::list(vec![OwnedTerm::Tuple(vec![
            OwnedTerm::Atom(">".into()),
            OwnedTerm::Atom("$1".into()),
            OwnedTerm::Int(450),
        ])]),
        OwnedTerm::list(vec![OwnedTerm::Atom("$1".into())]),
    ])]);
    let mut input = VecHeap::new();
    let program = MatchProgram::compile(from_owned(&spec, &mut input).unwrap()).unwrap();
    let mut output = VecHeap::new();
    let actual = stored
        .select_limit(&program, false, 41, &mut output)
        .unwrap()
        .into_iter()
        .map(|value| to_owned(value).unwrap())
        .collect::<Vec<_>>();
    let expected = (451..492).map(OwnedTerm::Int).collect::<Vec<_>>();
    assert_eq!(actual, expected);

    if let Some(erl) = reference() {
        let queries = OwnedTerm::list(vec![OwnedTerm::Tuple(vec![
            OwnedTerm::Atom(">".into()),
            OwnedTerm::Int(450),
            OwnedTerm::Int(41),
        ])]);
        let CallResult::Ok(OwnedTerm::List { ref elems, .. }) =
            erl.call("ets_ops", "run_select", &[queries])
        else {
            panic!("reference ETS select failed");
        };
        assert_eq!(elems.first().unwrap(), &OwnedTerm::list(expected));
    }
}

#[test]
fn concurrent_mixed_ops_8_threads() {
    let table = Arc::new(ConcurrentTable::new(options(WriteConcurrency::Enabled), 1).unwrap());
    let workers = (0..8)
        .map(|worker| {
            let table = Arc::clone(&table);
            thread::spawn(move || {
                let mut heap = VecHeap::new();
                for offset in 0..12_000 {
                    if offset % 128 == 0 {
                        heap = VecHeap::new();
                    }
                    let raw = (worker * 12_000 + offset) as i64;
                    let key = Term::small(raw).unwrap();
                    let object = TermBuilder::new(&mut heap).tuple(&[key, key]).unwrap();
                    table.insert_one(object).unwrap();
                    assert!(table.member(key));
                    let mut out = VecHeap::new();
                    assert_eq!(table.lookup(key, &mut out).unwrap().len(), 1);
                }
            })
        })
        .collect::<Vec<_>>();
    for worker in workers {
        worker.join().unwrap();
    }
    assert_eq!(table.len(), 96_000);
}

#[test]
fn order_matches_avl() {
    let (avl_registry, avl_tid) = table(WriteConcurrency::Disabled);
    let (ca_registry, ca_tid) = table(WriteConcurrency::Enabled);
    let mut avl = avl_registry.get_mut(avl_tid).unwrap();
    let mut ca = ca_registry.get_mut(ca_tid).unwrap();
    let mut heap = VecHeap::new();
    for key in (0..4096).rev() {
        if key % 128 == 0 {
            heap = VecHeap::new();
        }
        let key = Term::small(key).unwrap();
        let object = TermBuilder::new(&mut heap).tuple(&[key, key]).unwrap();
        avl.insert(&[object]).unwrap();
        ca.insert(&[object]).unwrap();
    }
    force_split(&ca, 0);
    for key in (0..4096).step_by(3) {
        let key = Term::small(key).unwrap();
        avl.delete_key(key);
        ca.delete_key(key);
    }
    let mut avl_out = VecHeap::new();
    let mut ca_out = VecHeap::new();
    let avl_rows = avl.tab2list(&mut avl_out).unwrap();
    let ca_rows = ca.tab2list(&mut ca_out).unwrap();
    assert_eq!(avl_rows.len(), ca_rows.len());
    assert!(
        avl_rows
            .iter()
            .zip(ca_rows)
            .all(|(left, right)| cmp(*left, right).is_eq())
    );
    assert!(ca.avl_invariants_hold());
}

/// `ets:slot/2` walks the base nodes with one table-wide stack: forward, backward, jumping and
/// after changes, it agrees with the plain AVL table.
#[test]
fn slot_walk_across_bases_matches_avl() {
    let (avl_registry, avl_tid) = table(WriteConcurrency::Disabled);
    let (ca_registry, ca_tid) = table(WriteConcurrency::Enabled);
    let mut avl = avl_registry.get_mut(avl_tid).unwrap();
    let mut ca = ca_registry.get_mut(ca_tid).unwrap();
    insert_range(&mut avl, 0, 300);
    insert_range(&mut ca, 0, 300);
    force_split(&ca, 0);
    force_split(&ca, 150);
    let slot = |table: &Table, index: usize| {
        let mut heap = VecHeap::new();
        table
            .slot(index, &mut heap)
            .map(|term| term.map(|term| arinsal_term::to_owned(term).unwrap()))
            .ok()
    };
    let check = |avl: &Table, ca: &Table, index: usize| {
        similar_asserts::assert_eq!(slot(avl, index), slot(ca, index), "slot {index}");
    };
    for index in (0..=300)
        .chain((0..300).rev())
        .chain([5, 250, 7, 299, 0, 120, 121, 119])
    {
        check(&avl, &ca, index);
    }
    check(&avl, &ca, 301);
    for key in (0..300).step_by(7) {
        avl.delete_key(Term::small(key).unwrap());
        ca.delete_key(Term::small(key).unwrap());
    }
    assert_eq!(avl.len(), ca.len());
    for index in 0..=avl.len() {
        check(&avl, &ca, index);
    }
}
