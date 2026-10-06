use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_ets::{
    Protection, Registry, TableOptions, TableType, WriteConcurrency, match_spec::MatchProgram,
};
use arinsal_term::{Term, TermBuilder, VecHeap, from_owned, global_atoms, to_owned};

fn options() -> TableOptions {
    TableOptions {
        name: global_atoms().intern("ets_tree_port").unwrap(),
        named_table: false,
        table_type: TableType::OrderedSet,
        keypos: 1,
        protection: Protection::Protected,
        owner: Term::pid(1, 0).unwrap(),
        heir: None,
        read_concurrency: false,
        write_concurrency: WriteConcurrency::Disabled,
        decentralized_counters: false,
        compressed: false,
    }
}

fn atom(name: &str) -> OwnedTerm {
    OwnedTerm::atom(name)
}

fn tuple(values: Vec<OwnedTerm>) -> OwnedTerm {
    OwnedTerm::Tuple(values)
}

fn list(values: Vec<OwnedTerm>) -> OwnedTerm {
    OwnedTerm::list(values)
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

fn run_local(ops: &[OwnedTerm]) -> Vec<OwnedTerm> {
    let mut registry = Registry::new();
    let tid = registry.create(options()).unwrap();
    let mut table = registry.get_mut(tid).unwrap();
    let mut results = Vec::new();
    for operation in ops {
        let OwnedTerm::Tuple(parts) = operation else {
            unreachable!()
        };
        let OwnedTerm::Atom(name) = &parts[0] else {
            unreachable!()
        };
        let mut input = VecHeap::new();
        let argument = from_owned(&parts[1], &mut input).unwrap();
        let mut output = VecHeap::new();
        let result = match name.as_str() {
            "insert" => {
                table.insert(&[argument]).unwrap();
                atom("true")
            }
            "next" | "prev" => {
                let found = if name == "next" {
                    table.next(argument, &mut output)
                } else {
                    table.prev(argument, &mut output)
                }
                .unwrap();
                found.map_or_else(|| atom("$end_of_table"), |term| to_owned(term).unwrap())
            }
            "slot" => table
                .slot(argument.as_small().unwrap() as usize, &mut output)
                .unwrap()
                .map_or_else(|| atom("$end_of_table"), |term| to_owned(term).unwrap()),
            "select" => {
                let program = MatchProgram::compile(argument).unwrap();
                list(
                    table
                        .select(&program, false, &mut output)
                        .unwrap()
                        .into_iter()
                        .map(|term| to_owned(term).unwrap())
                        .collect(),
                )
            }
            _ => unreachable!(),
        };
        results.push(tuple(vec![result, OwnedTerm::Int(table.len() as i64)]));
    }
    results
}

fn assert_reference(ops: Vec<OwnedTerm>) {
    let Some(erl) = reference() else { return };
    let expected = erl.call("ets_ops", "run", &[atom("ordered_set"), list(ops.clone())]);
    let CallResult::Ok(OwnedTerm::List { ref elems, .. }) = expected else {
        panic!("reference ETS call failed: {expected:?}");
    };
    assert_eq!(run_local(&ops).as_slice(), elems.as_slice());
}

#[test]
fn avl_balance_invariant() {
    let mut registry = Registry::new();
    let tid = registry.create(options()).unwrap();
    let mut table = registry.get_mut(tid).unwrap();
    let mut seed = 0x7a3d_19b6_d201_4f85_u64;
    let mut heap = VecHeap::new();
    for index in 0..100_000 {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        let key = Term::small((seed % 8192) as i64).unwrap();
        if seed & 3 == 0 {
            table.delete_key(key);
        } else {
            if index % 1024 == 0 {
                heap = VecHeap::new();
            }
            let object = TermBuilder::new(&mut heap)
                .tuple(&[key, Term::small(index).unwrap()])
                .unwrap();
            table.insert(&[object]).unwrap();
        }
        assert!(
            table.avl_invariants_hold(),
            "AVL invariant failed after op {index}"
        );
    }
}

#[test]
fn next_prev_order_vs_erl() {
    let mut ops: Vec<_> = (1..=100)
        .map(|key| {
            tuple(vec![
                atom("insert"),
                tuple(vec![OwnedTerm::Int(key), OwnedTerm::Int(-key)]),
            ])
        })
        .collect();
    for key in -1..=102 {
        ops.push(tuple(vec![atom("next"), OwnedTerm::Int(key)]));
        ops.push(tuple(vec![atom("prev"), OwnedTerm::Int(key)]));
    }
    assert_reference(ops);
}

#[test]
fn select_partly_bound_vs_erl() {
    let mut ops: Vec<_> = (1..=80)
        .map(|key| {
            tuple(vec![
                atom("insert"),
                tuple(vec![
                    tuple(vec![OwnedTerm::Int(key % 8), OwnedTerm::Int(key)]),
                    OwnedTerm::Int(key * 2),
                ]),
            ])
        })
        .collect();
    let spec = list(vec![tuple(vec![
        tuple(vec![tuple(vec![OwnedTerm::Int(3), atom("$1")]), atom("$2")]),
        list(vec![]),
        list(vec![atom("$_")]),
    ])]);
    ops.push(tuple(vec![atom("select"), spec]));
    assert_reference(ops);
}

#[test]
fn slot_vs_erl() {
    let mut registry = Registry::new();
    let tid = registry.create(options()).unwrap();
    let mut table = registry.get_mut(tid).unwrap();
    let mut heap = VecHeap::new();
    for key in (1..=1000).rev() {
        if key % 128 == 0 {
            heap = VecHeap::new();
        }
        let key_term = Term::small(key).unwrap();
        let value = Term::small(key * 2).unwrap();
        let object = TermBuilder::new(&mut heap)
            .tuple(&[key_term, value])
            .unwrap();
        table.insert(&[object]).unwrap();
    }
    let queries: Vec<_> = (0..=1000).map(OwnedTerm::Int).collect();
    let Some(erl) = reference() else { return };
    let expected = erl.call("ets_ops", "run_slots", &[list(queries)]);
    let CallResult::Ok(expected) = expected else {
        panic!("reference slot call failed: {expected:?}");
    };
    let mut output = VecHeap::new();
    let actual = list(
        (0..=1000)
            .map(|index| {
                table
                    .slot(index as usize, &mut output)
                    .unwrap()
                    .map_or_else(|| atom("$end_of_table"), |term| to_owned(term).unwrap())
            })
            .collect(),
    );
    assert_eq!(actual, expected);
}

#[test]
fn delete_rebalance() {
    let mut registry = Registry::new();
    let tid = registry.create(options()).unwrap();
    let mut table = registry.get_mut(tid).unwrap();
    let mut heap = VecHeap::new();
    for key in 0..30_000 {
        if key % 1024 == 0 {
            heap = VecHeap::new();
        }
        let key = Term::small(key).unwrap();
        let object = TermBuilder::new(&mut heap).tuple(&[key, key]).unwrap();
        table.insert(&[object]).unwrap();
    }
    for key in (0..30_000).step_by(2) {
        table.delete_key(Term::small(key).unwrap());
        assert!(
            table.avl_invariants_hold(),
            "deletion failed to rebalance at key {key}"
        );
    }
}
