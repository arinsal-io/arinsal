use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_ets::{
    ConcurrentTable, Protection, Registry, Table, TableOptions, TableType, WriteConcurrency,
    match_spec::MatchProgram,
};
use arinsal_term::{Term, TermBuilder, VecHeap, cmp, from_owned, global_atoms, to_owned};
use similar_asserts::assert_eq;
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

fn neighbors(table: &Table, keys: &[(bool, i64)]) -> Vec<OwnedTerm> {
    keys.iter()
        .map(|(reverse, key)| {
            let mut output = VecHeap::new();
            let key = Term::small(*key).unwrap();
            let result = if *reverse {
                table.prev(key, &mut output)
            } else {
                table.next(key, &mut output)
            }
            .unwrap();
            result.map_or_else(
                || OwnedTerm::Atom("$end_of_table".into()),
                |value| to_owned(value).unwrap(),
            )
        })
        .collect()
}

fn walk_keys(table: &Table, reverse: bool) -> Vec<OwnedTerm> {
    let mut output = VecHeap::new();
    let mut current = table.edge(reverse, &mut output).unwrap();
    let mut keys = Vec::new();
    while let Some(key) = current {
        keys.push(to_owned(key).unwrap());
        current = if reverse {
            table.prev(key, &mut output)
        } else {
            table.next(key, &mut output)
        }
        .unwrap();
    }
    keys
}

fn op(name: &str, argument: OwnedTerm) -> OwnedTerm {
    OwnedTerm::Tuple(vec![OwnedTerm::Atom(name.into()), argument])
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

#[test]
fn next_prev_across_several_bases_vs_erl() {
    let erl = reference().expect("reference Erlang node");
    let (registry, tid) = table(WriteConcurrency::Enabled);
    let mut stored = registry.get_mut(tid).unwrap();
    insert_range(&mut stored, 0, 1024);

    force_split(&stored, 0);
    let mut split_heap = VecHeap::new();
    for start in [2000, 2200, 2400, 2600] {
        for raw_key in start..start + 2 {
            let key = Term::small(raw_key).unwrap();
            let object = TermBuilder::new(&mut split_heap)
                .tuple(&[key, key])
                .unwrap();
            stored.insert(&[object]).unwrap();
        }
        force_split(&stored, start);
    }
    assert!(stored.catree_debug_base_count().unwrap() >= 4);

    let before_keys = [
        (false, 63),
        (true, 63),
        (false, 64),
        (true, 64),
        (false, 1999),
        (true, 2000),
        (true, 0),
        (false, 511),
        (true, 512),
    ];
    let after_keys = [
        (false, 64),
        (true, 512),
        (false, 511),
        (true, 513),
        (false, 2700),
        (true, 2000),
        (true, 0),
    ];
    let before = neighbors(&stored, &before_keys);
    let before_walks = [walk_keys(&stored, false), walk_keys(&stored, true)];
    stored.delete_key(Term::small(64).unwrap());
    stored.delete_key(Term::small(512).unwrap());
    let mut input = VecHeap::new();
    for key in [65, 513] {
        let key = Term::small(key).unwrap();
        let object = TermBuilder::new(&mut input).tuple(&[key, key]).unwrap();
        stored.insert(&[object]).unwrap();
    }
    let after = neighbors(&stored, &after_keys);
    let after_walks = [walk_keys(&stored, false), walk_keys(&stored, true)];

    let expected = erl
        .eval(
            "T=ets:new(catree_next_prev,[ordered_set,{write_concurrency,true}]),\
             ets:insert(T,[{I,I} || I <- lists:seq(0,1023)]),\
             ets:insert(T,[{I,I} || Start <- [2000,2200,2400,2600],\
                                   I <- lists:seq(Start,Start+1)]),\
             Before=[ets:next(T,63),ets:prev(T,63),ets:next(T,64),ets:prev(T,64),\
                     ets:next(T,1999),ets:prev(T,2000),ets:prev(T,0),ets:next(T,511),\
                     ets:prev(T,512)],\
             ets:delete(T,64),ets:delete(T,512),ets:insert(T,[{65,65},{513,513}]),\
             After=[ets:next(T,64),ets:prev(T,512),ets:next(T,511),ets:prev(T,513),\
                    ets:next(T,2700),ets:prev(T,2000),ets:prev(T,0)], [Before,After]",
        )
        .unwrap();
    assert_eq!(
        expected,
        OwnedTerm::list(vec![OwnedTerm::list(before), OwnedTerm::list(after)])
    );

    let mut operations = (0..1024)
        .map(|key| {
            op(
                "insert",
                OwnedTerm::Tuple(vec![OwnedTerm::Int(key), OwnedTerm::Int(key)]),
            )
        })
        .collect::<Vec<_>>();
    for start in [2000, 2200, 2400, 2600] {
        for key in start..start + 2 {
            operations.push(op(
                "insert",
                OwnedTerm::Tuple(vec![OwnedTerm::Int(key), OwnedTerm::Int(key)]),
            ));
        }
    }
    operations.extend([
        op("walk_next", OwnedTerm::Atom("none".into())),
        op("walk_prev", OwnedTerm::Atom("none".into())),
        op("delete", OwnedTerm::Int(64)),
        op("delete", OwnedTerm::Int(512)),
        op(
            "insert",
            OwnedTerm::Tuple(vec![OwnedTerm::Int(65), OwnedTerm::Int(65)]),
        ),
        op(
            "insert",
            OwnedTerm::Tuple(vec![OwnedTerm::Int(513), OwnedTerm::Int(513)]),
        ),
        op("walk_next", OwnedTerm::Atom("none".into())),
        op("walk_prev", OwnedTerm::Atom("none".into())),
    ]);
    let CallResult::Ok(OwnedTerm::List { ref elems, .. }) = erl.call(
        "ets_ops",
        "run_ordered",
        &[OwnedTerm::Atom("true".into()), OwnedTerm::list(operations)],
    ) else {
        panic!("reference ordered walk failed");
    };
    let results = [1032, 1033, 1038, 1039].map(|index| {
        let OwnedTerm::Tuple(parts) = &elems[index] else {
            unreachable!()
        };
        parts[0].clone()
    });
    assert_eq!(
        OwnedTerm::list(vec![
            OwnedTerm::list(before_walks[0].clone()),
            OwnedTerm::list(before_walks[1].clone()),
            OwnedTerm::list(after_walks[0].clone()),
            OwnedTerm::list(after_walks[1].clone()),
        ]),
        OwnedTerm::list(results.to_vec()),
    );
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
