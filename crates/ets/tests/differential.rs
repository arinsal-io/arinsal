use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_ets::{
    BigCounterOp, ConcurrentTable, CounterOp, Protection, Registry, Table, TableOptions, TableType,
    WriteConcurrency,
    match_spec::{MatchContext, MatchDialect, MatchProgram, match_spec_test},
};
use arinsal_term::{Term, TermBuilder, VecHeap, from_owned, global_atoms, to_owned};
use similar_asserts::assert_eq;

fn atom(name: &str) -> OwnedTerm {
    OwnedTerm::atom(name)
}
fn int(value: i64) -> OwnedTerm {
    OwnedTerm::Int(value)
}
fn unsigned(value: usize) -> OwnedTerm {
    if value <= i64::MAX as usize {
        int(value as i64)
    } else {
        let mut heap = VecHeap::new();
        let term = arinsal_term::TermBuilder::new(&mut heap)
            .int_from_i128(value as i128)
            .unwrap();
        to_owned(term).unwrap()
    }
}
fn tuple(values: Vec<OwnedTerm>) -> OwnedTerm {
    OwnedTerm::Tuple(values)
}
fn list(values: Vec<OwnedTerm>) -> OwnedTerm {
    OwnedTerm::list(values)
}

fn options(kind: TableType) -> TableOptions {
    TableOptions {
        name: global_atoms().intern("ets_ops").unwrap(),
        named_table: false,
        table_type: kind,
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

fn key(seed: u64) -> OwnedTerm {
    let n = ((seed >> 16) % 40) as i64;
    if seed & 8 == 0 {
        int(n)
    } else {
        OwnedTerm::Float(n as f64)
    }
}

fn operations(count: usize) -> Vec<OwnedTerm> {
    operations_from_seed(count, 0x9169_13db_74f0_00a1_u64)
}

fn operations_from_seed(count: usize, mut seed: u64) -> Vec<OwnedTerm> {
    (0..count)
        .map(|_| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            let k = key(seed);
            let value = tuple(vec![k.clone(), int(((seed >> 24) % 100) as i64)]);
            match seed % 24 {
                0 | 1 => tuple(vec![atom("insert"), value]),
                2 => tuple(vec![atom("insert_new"), value]),
                3 => tuple(vec![atom("lookup"), k]),
                4 => tuple(vec![atom("member"), k]),
                5 => tuple(vec![atom("delete"), k]),
                6 => tuple(vec![atom("take"), k]),
                7 => tuple(vec![atom("slot"), int(((seed >> 12) % 40) as i64)]),
                8 => tuple(vec![atom("first"), atom("none")]),
                9 => tuple(vec![atom("next"), k]),
                10 => tuple(vec![atom("info_size"), atom("none")]),
                11 => tuple(vec![atom("match"), tuple(vec![atom("$1"), atom("_")])]),
                12 => tuple(vec![
                    atom("select"),
                    list(vec![tuple(vec![
                        tuple(vec![atom("$1"), atom("$2")]),
                        list(vec![]),
                        list(vec![atom("$1")]),
                    ])]),
                ]),
                13 => tuple(vec![
                    atom("select"),
                    list(vec![tuple(vec![
                        tuple(vec![atom("$1"), atom("$2")]),
                        list(vec![]),
                        list(vec![tuple(vec![atom("unsupported"), atom("$1")])]),
                    ])]),
                ]),
                14 => tuple(vec![atom("counter"), k]),
                15 => tuple(vec![atom("counter_threshold"), k]),
                16 => tuple(vec![atom("counter_list"), k]),
                17 => tuple(vec![
                    atom("select_chunks"),
                    list(vec![tuple(vec![
                        tuple(vec![atom("$1"), atom("$2")]),
                        list(vec![]),
                        list(vec![atom("$_")]),
                    ])]),
                ]),
                18 => tuple(vec![atom("info_size"), atom("none")]),
                19 => tuple(vec![atom("update_element"), k]),
                21 => tuple(vec![atom("fix"), atom("none")]),
                22 => tuple(vec![atom("unfix"), atom("none")]),
                23 => tuple(vec![atom("info_fixed"), atom("none")]),
                _ => tuple(vec![
                    atom("insert_new_list"),
                    list(vec![
                        value,
                        tuple(vec![key(seed >> 3), int((seed % 100) as i64)]),
                    ]),
                ]),
            }
        })
        .collect()
}

#[test]
fn five_thousand_short_sequences_per_type_against_otp_29() {
    let Some(erl) = reference() else {
        return;
    };
    for (name, kind) in [
        ("set", TableType::Set),
        ("ordered_set", TableType::OrderedSet),
        ("bag", TableType::Bag),
        ("duplicate_bag", TableType::DuplicateBag),
    ] {
        for batch in 0..50 {
            let sequences: Vec<_> = (0..100)
                .map(|index| {
                    let id = batch * 100 + index;
                    operations_from_seed(
                        50,
                        0x9169_13db_74f0_00a1_u64
                            .wrapping_add((id as u64 + 1).wrapping_mul(0x9e37_79b9_7f4a_7c15)),
                    )
                })
                .collect();
            let expected = erl.call(
                "ets_ops",
                "run_sequences",
                &[
                    atom(name),
                    list(sequences.iter().cloned().map(list).collect()),
                ],
            );
            let actual = list(
                sequences
                    .iter()
                    .map(|sequence| list(run_local(kind, sequence)))
                    .collect(),
            );
            let CallResult::Ok(OwnedTerm::List {
                elems: ref expected_sequences,
                ..
            }) = expected
            else {
                panic!("reference failed for {name} batch {batch}");
            };
            let OwnedTerm::List {
                elems: ref actual_sequences,
                ..
            } = actual
            else {
                unreachable!()
            };
            for (sequence_index, (expected_sequence, actual_sequence)) in expected_sequences
                .iter()
                .zip(actual_sequences.iter())
                .enumerate()
            {
                let OwnedTerm::List {
                    elems: expected_ops,
                    ..
                } = expected_sequence
                else {
                    unreachable!()
                };
                let OwnedTerm::List {
                    elems: actual_ops, ..
                } = actual_sequence
                else {
                    unreachable!()
                };
                for (operation_index, (expected_op, actual_op)) in
                    expected_ops.iter().zip(actual_ops.iter()).enumerate()
                {
                    assert_eq!(
                        expected_op, actual_op,
                        "{name} batch {batch} sequence {sequence_index} operation {operation_index}: {:?}",
                        sequences[sequence_index][operation_index]
                    );
                }
            }
        }
    }
}

fn run_local(kind: TableType, operations: &[OwnedTerm]) -> Vec<OwnedTerm> {
    let mut registry = Registry::new();
    let tid = registry.create(options(kind)).unwrap();
    let mut table = registry.get_mut(tid).unwrap();
    let mut results = Vec::new();
    for op in operations {
        let OwnedTerm::Tuple(parts) = op else {
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
            "insert_new" => atom(if table.insert_new(&[argument]).unwrap() {
                "true"
            } else {
                "false"
            }),
            "insert_new_list" => {
                let mut items = Vec::new();
                let mut tail = argument;
                while tail != Term::NIL {
                    // SAFETY: the input heap remains live through this operation.
                    let (item, next) = unsafe { tail.cons_ref() }.unwrap();
                    items.push(item);
                    tail = next;
                }
                atom(if table.insert_new_list(&items).unwrap() {
                    "true"
                } else {
                    "false"
                })
            }
            "lookup" => list(
                table
                    .lookup(argument, &mut output)
                    .unwrap()
                    .into_iter()
                    .map(|t| to_owned(t).unwrap())
                    .collect(),
            ),
            "member" => atom(if table.member(argument) {
                "true"
            } else {
                "false"
            }),
            "delete" => {
                table.delete_key(argument);
                atom("true")
            }
            "delete_object" => {
                table.delete_object(argument).unwrap();
                atom("true")
            }
            "take" => list(
                table
                    .take(argument, &mut output)
                    .unwrap()
                    .into_iter()
                    .map(|t| to_owned(t).unwrap())
                    .collect(),
            ),
            "slot" => {
                let index = argument.as_small().unwrap() as usize;
                match table.slot(index, &mut output) {
                    Ok(Some(value)) => to_owned(value).unwrap(),
                    Ok(None) => atom("$end_of_table"),
                    Err(arinsal_ets::EtsError::BadArg | arinsal_ets::EtsError::BadArgCause(_)) => {
                        atom("badarg")
                    }
                    Err(error) => panic!("slot failed: {error:?}"),
                }
            }
            "first" => table
                .edge(false, &mut output)
                .unwrap()
                .map(|value| to_owned(value).unwrap())
                .unwrap_or_else(|| atom("$end_of_table")),
            "next" => match table.next(argument, &mut output) {
                Ok(Some(value)) => to_owned(value).unwrap(),
                Ok(None) => atom("$end_of_table"),
                Err(arinsal_ets::EtsError::BadArg | arinsal_ets::EtsError::BadArgCause(_)) => {
                    atom("badarg")
                }
                Err(error) => panic!("next failed: {error:?}"),
            },
            "info_size" => unsigned(table.info().size),
            "info_fixed" => atom(if table.fixation_count() > 0 {
                "true"
            } else {
                "false"
            }),
            "match" => list(
                table
                    .match_pattern(argument, &mut output)
                    .unwrap()
                    .into_iter()
                    .map(|value| to_owned(value).unwrap())
                    .collect(),
            ),
            "select" => match MatchProgram::compile(argument) {
                Ok(program) => list(
                    table
                        .select(&program, false, &mut output)
                        .unwrap()
                        .into_iter()
                        .map(|value| to_owned(value).unwrap())
                        .collect(),
                ),
                Err(arinsal_ets::EtsError::BadArg | arinsal_ets::EtsError::BadArgCause(_)) => {
                    atom("badarg")
                }
                Err(error) => panic!("match spec compile failed: {error:?}"),
            },
            "select_chunks" => {
                let program = MatchProgram::compile(argument).unwrap();
                let mut pages = Vec::new();
                let mut batch = table.select_chunk(&program, false, 2, &mut output).unwrap();
                loop {
                    if !batch.rows.is_empty() {
                        pages.push(list(
                            batch
                                .rows
                                .iter()
                                .map(|&row| to_owned(row).unwrap())
                                .collect(),
                        ));
                    }
                    let Some(continuation) = batch.continuation else {
                        break;
                    };
                    let encoded = continuation.to_term(&table, &mut output).unwrap();
                    let decoded =
                        arinsal_ets::SelectContinuation::from_term(&table, &program, encoded)
                            .unwrap();
                    batch = table
                        .select_chunk_continue(&program, decoded, &mut output)
                        .unwrap();
                }
                list(pages)
            }
            "counter" | "counter_threshold" | "counter_list" => {
                let default = arinsal_term::TermBuilder::new(&mut input)
                    .tuple(&[argument, Term::small(0).unwrap()])
                    .unwrap();
                let operations = match name.as_str() {
                    "counter" => vec![CounterOp {
                        position: 2,
                        increment: 1,
                        threshold: None,
                    }],
                    "counter_threshold" => vec![CounterOp {
                        position: 2,
                        increment: -1,
                        threshold: Some((-10, 0)),
                    }],
                    _ => vec![
                        CounterOp {
                            position: 2,
                            increment: 2,
                            threshold: None,
                        },
                        CounterOp {
                            position: 2,
                            increment: -1,
                            threshold: Some((-10, 0)),
                        },
                    ],
                };
                match table.update_counter(argument, &operations, Some(default)) {
                    Ok(values) if name == "counter_list" => list(
                        values
                            .into_iter()
                            .map(|value| to_owned(value).unwrap())
                            .collect(),
                    ),
                    Ok(values) => to_owned(values[0]).unwrap(),
                    Err(arinsal_ets::EtsError::BadArg | arinsal_ets::EtsError::BadArgCause(_)) => {
                        atom("badarg")
                    }
                    Err(error) => panic!("counter failed: {error:?}"),
                }
            }
            "update_element" => {
                match table.update_element(argument, &[Some((2, Term::small(7).unwrap()))], None) {
                    Ok(changed) => atom(if changed { "true" } else { "false" }),
                    Err(arinsal_ets::EtsError::BadArg | arinsal_ets::EtsError::BadArgCause(_)) => {
                        atom("badarg")
                    }
                    Err(error) => panic!("update_element failed: {error:?}"),
                }
            }
            "fix" | "unfix" => {
                table.safe_fixtable(name == "fix").unwrap();
                atom("true")
            }
            _ => unreachable!(),
        };
        results.push(tuple(vec![result, unsigned(table.len())]));
    }
    results
}

#[cfg(miri)]
fn reference() -> Option<&'static RefErl> {
    eprintln!("skipping external erl reference under Miri isolation");
    None
}

#[cfg(not(miri))]
fn reference() -> Option<&'static RefErl> {
    let erl = match RefErl::shared() {
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
fn table_memory_concurrency_options_match_otp() {
    let Some(erl) = reference() else { return };
    let schedulers = match erl.eval("erlang:system_info(schedulers)").unwrap() {
        OwnedTerm::Int(count) => count as usize,
        other => panic!("unexpected scheduler count: {other:?}"),
    };
    for (kind, name) in [
        (TableType::Set, "set"),
        (TableType::Bag, "bag"),
        (TableType::DuplicateBag, "duplicate_bag"),
        (TableType::OrderedSet, "ordered_set"),
    ] {
        for read_concurrency in [false, true] {
            for write_concurrency in [false, true] {
                for decentralized_counters in [false, true] {
                    let opts = format!(
                        "{{read_concurrency,{read_concurrency}}},{{write_concurrency,{write_concurrency}}},{{decentralized_counters,{decentralized_counters}}}"
                    );
                    let expected = erl
                        .eval(&format!(
                            "T=ets:new(t,[public,{name},{opts}]), M0=ets:info(T,memory), ets:insert(T,[{{I,I}} || I <- lists:seq(1,8)]), M1=ets:info(T,memory), ets:delete(T,2), ets:delete(T,4), [M0,M1,ets:info(T,memory)]"
                        ))
                        .unwrap();
                    let OwnedTerm::List {
                        elems: expected_values,
                        ..
                    } = &expected
                    else {
                        panic!("OTP returned non-list memory results: {expected:?}");
                    };
                    let settings = TableOptions {
                        name: global_atoms().intern("ets_memory_diff").unwrap(),
                        named_table: false,
                        table_type: kind,
                        keypos: 1,
                        protection: Protection::Public,
                        owner: Term::pid(1, 0).unwrap(),
                        heir: None,
                        read_concurrency,
                        write_concurrency: if write_concurrency {
                            WriteConcurrency::Enabled
                        } else {
                            WriteConcurrency::Disabled
                        },
                        decentralized_counters,
                        compressed: false,
                    };
                    let mut registry = Registry::new();
                    let tid = registry.create(settings).unwrap();
                    let table = registry.get(tid).unwrap();
                    let mut actual = vec![table.memory_words_for_schedulers(schedulers)];
                    drop(table);
                    for key in 1..=8 {
                        let mut heap = arinsal_term::VecHeap::new();
                        let object = arinsal_term::TermBuilder::new(&mut heap)
                            .tuple(&[Term::small(key).unwrap(), Term::small(key).unwrap()])
                            .unwrap();
                        registry.get_mut(tid).unwrap().insert(&[object]).unwrap();
                    }
                    actual.push(
                        registry
                            .get(tid)
                            .unwrap()
                            .memory_words_for_schedulers(schedulers),
                    );
                    for key in [2, 4] {
                        registry
                            .get_mut(tid)
                            .unwrap()
                            .delete_key(Term::small(key).unwrap());
                    }
                    actual.push(
                        registry
                            .get(tid)
                            .unwrap()
                            .memory_words_for_schedulers(schedulers),
                    );
                    assert_eq!(
                        expected_values,
                        &actual
                            .into_iter()
                            .map(|words| OwnedTerm::Int(words as i64))
                            .collect::<Vec<_>>(),
                        "{name}, read_concurrency={read_concurrency}, write_concurrency={write_concurrency}, decentralized_counters={decentralized_counters}"
                    );
                }
            }
        }
    }

    let expected = erl
        .eval("T=ets:new(t,[public,set,{write_concurrency,{debug_hash_fixed_number_of_locks,1024}}]), M0=ets:info(T,memory), ets:insert(T,[{I,I} || I <- lists:seq(1,8)]), M1=ets:info(T,memory), ets:delete(T,2), ets:delete(T,4), [M0,M1,ets:info(T,memory)]")
        .unwrap();
    let OwnedTerm::List {
        elems: expected_values,
        ..
    } = &expected
    else {
        panic!("OTP returned non-list fixed-lock memory results: {expected:?}");
    };
    let mut settings = options(TableType::Set);
    settings.protection = Protection::Public;
    settings.write_concurrency = WriteConcurrency::Fixed(1024);
    settings.decentralized_counters = true;
    let mut registry = Registry::new();
    let tid = registry.create(settings).unwrap();
    let table = registry.get(tid).unwrap();
    let mut actual = vec![table.memory_words_for_schedulers(schedulers)];
    drop(table);
    for key in 1..=8 {
        let mut heap = arinsal_term::VecHeap::new();
        let object = arinsal_term::TermBuilder::new(&mut heap)
            .tuple(&[Term::small(key).unwrap(), Term::small(key).unwrap()])
            .unwrap();
        registry.get_mut(tid).unwrap().insert(&[object]).unwrap();
    }
    actual.push(
        registry
            .get(tid)
            .unwrap()
            .memory_words_for_schedulers(schedulers),
    );
    for key in [2, 4] {
        registry
            .get_mut(tid)
            .unwrap()
            .delete_key(Term::small(key).unwrap());
    }
    actual.push(
        registry
            .get(tid)
            .unwrap()
            .memory_words_for_schedulers(schedulers),
    );
    assert_eq!(
        expected_values,
        &actual
            .into_iter()
            .map(|words| OwnedTerm::Int(words as i64))
            .collect::<Vec<_>>(),
        "set, fixed write concurrency locks=1024"
    );
}

#[test]
fn table_memory_counter_tracks_concurrent_writes_like_otp() {
    let Some(erl) = reference() else { return };
    let schedulers = match erl.eval("erlang:system_info(schedulers)").unwrap() {
        OwnedTerm::Int(count) => count as usize,
        other => panic!("unexpected scheduler count: {other:?}"),
    };
    const PER_WORKER: i64 = 256;
    const WORKERS: i64 = 4;
    let max_key = PER_WORKER * WORKERS;
    for (kind, name) in [
        (TableType::Set, "set"),
        (TableType::OrderedSet, "ordered_set"),
    ] {
        let expected = erl
            .eval(&format!(
                "T=ets:new(t,[public,{name},{{write_concurrency,true}},{{decentralized_counters,false}}]), ets:insert(T,[{{I,I}} || I <- lists:seq(1,{max_key})]), ets:info(T,memory)"
            ))
            .unwrap();
        let mut settings = options(kind);
        settings.protection = Protection::Public;
        settings.write_concurrency = WriteConcurrency::Enabled;
        let mut registry = Registry::new();
        let tid = registry.create(settings).unwrap();
        let shared = std::sync::Arc::clone(registry.shared(tid).unwrap());
        std::thread::scope(|scope| {
            for worker in 0..WORKERS {
                let shared = std::sync::Arc::clone(&shared);
                scope.spawn(move || {
                    for offset in 1..=PER_WORKER {
                        let key = worker * PER_WORKER + offset;
                        let mut heap = VecHeap::new();
                        let object = TermBuilder::new(&mut heap)
                            .tuple(&[Term::small(key).unwrap(), Term::small(key).unwrap()])
                            .unwrap();
                        let table = shared.read();
                        let prepared = Table::prepare_object(&table.options, object).unwrap();
                        assert!(table.insert_shared(prepared).is_none());
                    }
                });
            }
        });
        let actual = registry
            .get(tid)
            .unwrap()
            .memory_words_for_schedulers(schedulers);
        assert_eq!(expected, OwnedTerm::Int(actual as i64), "{name}");
    }
}

#[test]
fn concurrent_immediate_overwrite_owns_its_storage() {
    let table = ConcurrentTable::new(options(TableType::Set), 4).unwrap();
    for value in 0..100 {
        let mut source = VecHeap::new();
        let object = from_owned(&tuple(vec![int(1), int(value)]), &mut source).unwrap();
        table.insert_one(object).unwrap();
    }
    let mut output = VecHeap::new();
    let result = table.lookup(Term::small(1).unwrap(), &mut output).unwrap();
    assert_eq!(result.len(), 1);
    assert_eq!(to_owned(result[0]).unwrap(), tuple(vec![int(1), int(99)]));
}

#[test]
fn concurrent_pair_transitions_against_otp_29() {
    let Some(erl) = reference() else {
        return;
    };
    let ops = vec![
        tuple(vec![atom("insert"), tuple(vec![int(1), int(10)])]),
        tuple(vec![atom("lookup"), int(1)]),
        tuple(vec![atom("insert"), tuple(vec![int(1), int(11)])]),
        tuple(vec![atom("lookup"), int(1)]),
        tuple(vec![
            atom("insert"),
            tuple(vec![int(1), list(vec![int(5)])]),
        ]),
        tuple(vec![atom("lookup"), int(1)]),
        tuple(vec![atom("insert"), tuple(vec![int(1), int(12)])]),
        tuple(vec![atom("member"), int(1)]),
        tuple(vec![atom("delete"), int(1)]),
        tuple(vec![atom("lookup"), int(1)]),
        tuple(vec![atom("insert"), tuple(vec![int(1), int(13)])]),
        tuple(vec![atom("lookup"), int(1)]),
    ];
    let expected = erl.call("ets_ops", "run", &[atom("set"), list(ops.clone())]);
    let table = ConcurrentTable::new(options(TableType::Set), 4).unwrap();
    let mut actual = Vec::new();
    for op in ops {
        let OwnedTerm::Tuple(parts) = &op else {
            unreachable!()
        };
        let OwnedTerm::Atom(name) = &parts[0] else {
            unreachable!()
        };
        let mut source = VecHeap::new();
        let argument = from_owned(&parts[1], &mut source).unwrap();
        let mut output = VecHeap::new();
        let result = match name.as_str() {
            "insert" => {
                table.insert_one(argument).unwrap();
                atom("true")
            }
            "lookup" => list(
                table
                    .lookup(argument, &mut output)
                    .unwrap()
                    .into_iter()
                    .map(|term| to_owned(term).unwrap())
                    .collect(),
            ),
            "member" => atom(if table.member(argument) {
                "true"
            } else {
                "false"
            }),
            "delete" => {
                table.delete_key(argument);
                atom("true")
            }
            _ => unreachable!(),
        };
        actual.push(tuple(vec![result, unsigned(table.len())]));
    }
    assert_eq!(expected, CallResult::Ok(list(actual)));
}

#[test]
fn concurrent_pair_collisions_fall_back_without_losing_keys() {
    let table = ConcurrentTable::new(options(TableType::Set), 64).unwrap();
    let mut keys = Vec::new();
    for candidate in 0..10_000_i64 {
        let hash = (candidate as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15);
        if ((hash >> 32) as usize).is_multiple_of(64) {
            keys.push(candidate);
            if keys.len() == 40 {
                break;
            }
        }
    }
    assert_eq!(keys.len(), 40);
    for &key in &keys {
        let mut source = VecHeap::new();
        let object = arinsal_term::TermBuilder::new(&mut source)
            .tuple(&[Term::small(key).unwrap(), Term::small(key + 1).unwrap()])
            .unwrap();
        table.insert_one(object).unwrap();
    }
    assert_eq!(table.len(), 40);
    for &key in &keys {
        let mut output = VecHeap::new();
        let rows = table
            .lookup(Term::small(key).unwrap(), &mut output)
            .unwrap();
        assert_eq!(
            to_owned(rows[0]).unwrap(),
            tuple(vec![int(key), int(key + 1)])
        );
    }
    table.delete_key(Term::small(keys[0]).unwrap());
    assert_eq!(table.len(), 39);
    let mut source = VecHeap::new();
    let object = arinsal_term::TermBuilder::new(&mut source)
        .tuple(&[Term::small(keys[0]).unwrap(), Term::small(99).unwrap()])
        .unwrap();
    table.insert_one(object).unwrap();
    assert_eq!(table.len(), 40);
}

#[test]
fn concurrent_pair_readers_observe_whole_objects() {
    let table = std::sync::Arc::new(ConcurrentTable::new(options(TableType::Set), 4).unwrap());
    let key = Term::small(7).unwrap();
    let mut initial = VecHeap::new();
    let object = arinsal_term::TermBuilder::new(&mut initial)
        .tuple(&[key, Term::small(0).unwrap()])
        .unwrap();
    table.insert_one(object).unwrap();
    let iterations = if cfg!(miri) { 20 } else { 10_000 };
    std::thread::scope(|scope| {
        for worker in 0..2 {
            let table = &table;
            scope.spawn(move || {
                for index in 0..iterations {
                    let mut source = VecHeap::new();
                    let object = arinsal_term::TermBuilder::new(&mut source)
                        .tuple(&[key, Term::small(index * 2 + worker).unwrap()])
                        .unwrap();
                    table.insert_one(object).unwrap();
                }
            });
        }
        let table = &table;
        scope.spawn(move || {
            for _ in 0..iterations {
                let mut output = VecHeap::new();
                let rows = table.lookup(key, &mut output).unwrap();
                assert_eq!(rows.len(), 1);
                let owned = to_owned(rows[0]).unwrap();
                let OwnedTerm::Tuple(parts) = &owned else {
                    panic!("lookup returned a non-tuple");
                };
                assert_eq!(parts[0], int(7));
                assert!(matches!(&parts[1], OwnedTerm::Int(value) if (0..iterations * 2).contains(value)));
            }
        });
    });
    assert_eq!(table.len(), 1);
}

#[test]
fn concurrent_pair_respects_second_key_position() {
    let mut settings = options(TableType::Set);
    settings.keypos = 2;
    let table = ConcurrentTable::new(settings, 4).unwrap();
    for value in [10, 11] {
        let mut source = VecHeap::new();
        let object = arinsal_term::TermBuilder::new(&mut source)
            .tuple(&[Term::small(value).unwrap(), Term::small(1).unwrap()])
            .unwrap();
        table.insert_one(object).unwrap();
    }
    let mut output = VecHeap::new();
    let rows = table.lookup(Term::small(1).unwrap(), &mut output).unwrap();
    assert_eq!(to_owned(rows[0]).unwrap(), tuple(vec![int(11), int(1)]));
    assert_eq!(table.len(), 1);
}

#[test]
fn match_context_supplies_self() {
    struct Context;
    impl MatchContext for Context {
        fn self_pid(&self) -> Option<Term> {
            Term::pid(7, 0)
        }
    }
    let specification = list(vec![tuple(vec![
        atom("_"),
        list(vec![]),
        list(vec![tuple(vec![atom("self")])]),
    ])]);
    let mut source = VecHeap::new();
    let specification = from_owned(&specification, &mut source).unwrap();
    let program = MatchProgram::compile(specification).unwrap();
    let mut output = VecHeap::new();
    let result = program
        .run_with_context(Term::small(1).unwrap(), &mut output, &Context)
        .unwrap();
    assert_eq!(result, Term::pid(7, 0));
    let mut registry = Registry::new();
    let tid = registry.create(options(TableType::Set)).unwrap();
    let mut table = registry.get_mut(tid).unwrap();
    let object = arinsal_term::TermBuilder::new(&mut source)
        .tuple(&[Term::small(1).unwrap()])
        .unwrap();
    table.insert(&[object]).unwrap();
    let selected = table
        .select_with_context(&program, false, &mut output, &Context)
        .unwrap();
    assert_eq!(selected, vec![Term::pid(7, 0).unwrap()]);
    let page = table
        .select_chunk_with_context(&program, false, 1, &mut output, &Context)
        .unwrap();
    assert_eq!(page.rows, vec![Term::pid(7, 0).unwrap()]);
}

#[test]
fn random_sequences_against_otp_29() {
    let Some(erl) = reference() else {
        return;
    };
    for (name, kind) in [
        ("set", TableType::Set),
        ("ordered_set", TableType::OrderedSet),
        ("bag", TableType::Bag),
        ("duplicate_bag", TableType::DuplicateBag),
    ] {
        let operations = operations(20_000);
        let expected = erl.call("ets_ops", "run", &[atom(name), list(operations.clone())]);
        let actual = run_local(kind, &operations);
        let CallResult::Ok(OwnedTerm::List {
            ref elems,
            ref tail,
        }) = expected
        else {
            panic!("reference failed: {expected:?}")
        };
        assert_eq!(**tail, OwnedTerm::Nil);
        assert_eq!(elems.len(), actual.len());
        for (index, (reference, local)) in elems.iter().zip(actual.iter()).enumerate() {
            assert_eq!(
                reference,
                local,
                "{name} operation {index}: {:?}; recent {:?}",
                operations[index],
                &operations[index.saturating_sub(12)..=index]
            );
        }
    }
}

#[test]
fn fixed_bag_insert_new_forms_against_otp_29() {
    let Some(erl) = reference() else {
        return;
    };
    for insertion in [
        tuple(vec![atom("insert_new"), tuple(vec![int(13), int(0)])]),
        tuple(vec![
            atom("insert_new_list"),
            list(vec![tuple(vec![int(13), int(0)])]),
        ]),
    ] {
        let operations = vec![
            tuple(vec![atom("insert"), tuple(vec![int(13), int(0)])]),
            tuple(vec![atom("fix"), atom("none")]),
            tuple(vec![atom("take"), int(13)]),
            insertion.clone(),
            tuple(vec![atom("take"), int(13)]),
        ];
        let expected = erl.call("ets_ops", "run", &[atom("bag"), list(operations.clone())]);
        assert_eq!(
            expected,
            CallResult::Ok(list(run_local(TableType::Bag, &operations))),
            "insertion {insertion:?}"
        );
    }
}

#[test]
fn ordered_slots_and_guard_ranges_against_otp_29() {
    let Some(erl) = reference() else {
        return;
    };
    let mut registry = Registry::new();
    let tid = registry.create(options(TableType::OrderedSet)).unwrap();
    let mut table = registry.get_mut(tid).unwrap();
    let mut input = VecHeap::new();
    for index in 1..=1000 {
        let object = from_owned(&tuple(vec![int(index), int(index * 2)]), &mut input).unwrap();
        table.insert(&[object]).unwrap();
    }
    let mut seed = 0x9f4e_71ca_9005_1362_u64;
    let mut indexes = Vec::new();
    for _ in 0..1000 {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        indexes.push(int((seed % 1001) as i64));
    }
    let reference_slots = erl.call("ets_ops", "run_slots", &[list(indexes.clone())]);
    let CallResult::Ok(OwnedTerm::List { ref elems, .. }) = reference_slots else {
        panic!("reference slots failed: {reference_slots:?}");
    };
    for (index, expected) in indexes.iter().zip(elems) {
        let mut output = VecHeap::new();
        let slot = table
            .slot(
                match index {
                    OwnedTerm::Int(n) => *n as usize,
                    _ => unreachable!(),
                },
                &mut output,
            )
            .unwrap();
        let actual = slot
            .map(|term| to_owned(term).unwrap())
            .unwrap_or_else(|| atom("$end_of_table"));
        assert_eq!(&actual, expected);
    }
    let mut queries = Vec::new();
    for _ in 0..200 {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        let op = [">", ">=", "<", "=<"][(seed % 4) as usize];
        queries.push(tuple(vec![
            atom(op),
            int(((seed >> 10) % 1100) as i64),
            int(1 + ((seed >> 24) % 12) as i64),
        ]));
    }
    let CallResult::Ok(OwnedTerm::List { ref elems, .. }) =
        erl.call("ets_ops", "run_select", &[list(queries.clone())])
    else {
        panic!("reference select failed");
    };
    for (query, expected) in queries.iter().zip(elems) {
        let OwnedTerm::Tuple(parts) = query else {
            unreachable!()
        };
        let specification = list(vec![tuple(vec![
            tuple(vec![atom("$1"), atom("$2")]),
            list(vec![tuple(vec![
                parts[0].clone(),
                atom("$1"),
                parts[1].clone(),
            ])]),
            list(vec![atom("$1")]),
        ])]);
        let mut spec_heap = VecHeap::new();
        let spec = from_owned(&specification, &mut spec_heap).unwrap();
        let program = MatchProgram::compile(spec).unwrap();
        let mut output = VecHeap::new();
        let limit = match parts[2] {
            OwnedTerm::Int(n) => n as usize,
            _ => unreachable!(),
        };
        let actual = list(
            table
                .select_limit(&program, false, limit, &mut output)
                .unwrap()
                .into_iter()
                .map(|term| to_owned(term).unwrap())
                .collect(),
        );
        assert_eq!(&actual, expected, "query {query:?}");
    }
}

#[test]
fn lookup_element_preserves_bag_insertion_order_against_otp_29() {
    let Some(erl) = reference() else {
        return;
    };
    let mut registry = Registry::new();
    let mut source = VecHeap::new();
    let key = Term::atom(global_atoms().intern("key").unwrap());
    let first = Term::atom(global_atoms().intern("first").unwrap());
    let second = Term::atom(global_atoms().intern("second").unwrap());

    for (name, kind) in [
        ("bag", TableType::Bag),
        ("duplicate_bag", TableType::DuplicateBag),
    ] {
        let tid = registry.create(options(kind)).unwrap();
        let mut table = registry.get_mut(tid).unwrap();
        let objects = [first, second].map(|value| {
            arinsal_term::TermBuilder::new(&mut source)
                .tuple(&[key, value])
                .unwrap()
        });
        table.insert(&objects).unwrap();

        let values = table
            .lookup_element(key, 2, &mut source)
            .unwrap()
            .into_iter()
            .map(|value| to_owned(value).unwrap())
            .collect();
        let actual = list(values);
        let expected = erl.call("ets_ops", "run_lookup_element", &[atom(name)]);
        assert_eq!(expected, CallResult::Ok(actual.clone()));
        assert_eq!(actual, list(vec![atom("first"), atom("second")]));
        drop(table);
        registry.delete(tid).unwrap();
    }
}

#[test]
fn counter_variants_against_otp_29() {
    let Some(erl) = reference() else {
        return;
    };
    let mut registry = Registry::new();
    let tid = registry.create(options(TableType::Set)).unwrap();
    let mut table = registry.get_mut(tid).unwrap();
    let mut seed = 0x8f15_75aa_0083_d78d_u64;
    let mut queries = Vec::new();
    let mut local = Vec::new();
    for _ in 0..2000 {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        let key = (seed % 50) as i64;
        let increment = ((seed >> 9) % 7) as i64 - 3;
        let first = CounterOp {
            position: 2,
            increment,
            threshold: None,
        };
        let second = CounterOp {
            position: 2,
            increment: 1,
            threshold: Some((10, 0)),
        };
        let (update, operations, is_list) = match seed % 3 {
            0 => (int(increment), vec![first], false),
            1 => (
                tuple(vec![int(2), int(increment), int(10), int(0)]),
                vec![CounterOp {
                    threshold: Some((10, 0)),
                    ..first
                }],
                false,
            ),
            _ => (
                list(vec![
                    tuple(vec![int(2), int(increment)]),
                    tuple(vec![int(2), int(1), int(10), int(0)]),
                ]),
                vec![first, second],
                true,
            ),
        };
        queries.push(tuple(vec![int(key), update]));
        let mut input = VecHeap::new();
        let default = from_owned(&tuple(vec![int(key), int(0)]), &mut input).unwrap();
        let result = table
            .update_counter(Term::small(key).unwrap(), &operations, Some(default))
            .unwrap();
        let values = result
            .into_iter()
            .map(|term| to_owned(term).unwrap())
            .collect::<Vec<_>>();
        local.push(if is_list {
            list(values)
        } else {
            values[0].clone()
        });
    }
    let reference = erl.call("ets_ops", "run_counters", &[list(queries)]);
    let CallResult::Ok(OwnedTerm::List { ref elems, .. }) = reference else {
        panic!("reference counters failed: {reference:?}");
    };
    assert_eq!(elems.len(), local.len());
    for (index, (expected, actual)) in elems.iter().zip(local.iter()).enumerate() {
        assert_eq!(expected, actual, "counter operation {index}");
    }
}

#[test]
fn count_and_delete_only_true_results() {
    let Some(erl) = reference() else {
        return;
    };
    let expected = erl.call("ets_ops", "run_count_delete", &[]);
    let mut registry = Registry::new();
    let tid = registry.create(options(TableType::OrderedSet)).unwrap();
    let mut table = registry.get_mut(tid).unwrap();
    let mut source = VecHeap::new();
    for key in 1..=10 {
        let object = from_owned(&tuple(vec![int(key), int(key * 2)]), &mut source).unwrap();
        table.insert(&[object]).unwrap();
    }
    let make_program = |result: &str| {
        let specification = list(vec![tuple(vec![
            tuple(vec![atom("$1"), atom("_")]),
            list(vec![tuple(vec![atom(">"), atom("$1"), int(5)])]),
            list(vec![atom(result)]),
        ])]);
        let mut heap = VecHeap::new();
        let term = from_owned(&specification, &mut heap).unwrap();
        MatchProgram::compile(term).unwrap()
    };
    let yes = make_program("true");
    let no = make_program("false");
    let first = table.select_count(&yes).unwrap();
    let second = table.select_count(&no).unwrap();
    let third = table.select_delete(&no).unwrap();
    let fourth = table.select_delete(&yes).unwrap();
    let mut output = VecHeap::new();
    let objects = table
        .tab2list(&mut output)
        .unwrap()
        .into_iter()
        .map(|term| to_owned(term).unwrap())
        .collect();
    let actual = tuple(vec![
        int(first as i64),
        int(second as i64),
        int(third as i64),
        int(fourth as i64),
        list(objects),
    ]);
    assert_eq!(expected, CallResult::Ok(actual));
}

#[test]
fn select_replace_against_otp_29() {
    let Some(erl) = reference() else {
        return;
    };
    let expected = erl.call("ets_ops", "run_replace", &[]);
    let mut registry = Registry::new();
    let tid = registry.create(options(TableType::OrderedSet)).unwrap();
    let mut table = registry.get_mut(tid).unwrap();
    let mut source = VecHeap::new();
    for key in 1..=10 {
        let object = from_owned(&tuple(vec![int(key), atom("old")]), &mut source).unwrap();
        table.insert(&[object]).unwrap();
    }
    let specification = list(vec![tuple(vec![
        tuple(vec![atom("$1"), atom("$2")]),
        list(vec![tuple(vec![atom(">"), atom("$1"), int(5)])]),
        list(vec![tuple(vec![tuple(vec![atom("$1"), atom("changed")])])]),
    ])]);
    let spec = from_owned(&specification, &mut source).unwrap();
    let program = MatchProgram::compile(spec).unwrap();
    let count = table.select_replace(&program).unwrap();
    let mut output = VecHeap::new();
    let objects = table
        .tab2list(&mut output)
        .unwrap()
        .into_iter()
        .map(|term| to_owned(term).unwrap())
        .collect();
    assert_eq!(
        expected,
        CallResult::Ok(tuple(vec![int(count as i64), list(objects)]))
    );
}

#[test]
fn match_and_match_object_against_otp_29() {
    let Some(erl) = reference() else {
        return;
    };
    let expected = erl.call("ets_ops", "run_match", &[]);
    let mut registry = Registry::new();
    let tid = registry.create(options(TableType::OrderedSet)).unwrap();
    let mut table = registry.get_mut(tid).unwrap();
    let mut source = VecHeap::new();
    for key in 1..=10 {
        let object = from_owned(&tuple(vec![int(key), int(key % 3)]), &mut source).unwrap();
        table.insert(&[object]).unwrap();
    }
    let match_pattern = from_owned(&tuple(vec![atom("$1"), int(2)]), &mut source).unwrap();
    let object_pattern = from_owned(&tuple(vec![atom("_"), int(2)]), &mut source).unwrap();
    let mut output = VecHeap::new();
    let bindings = table
        .match_pattern(match_pattern, &mut output)
        .unwrap()
        .into_iter()
        .map(|term| to_owned(term).unwrap())
        .collect();
    let objects = table
        .match_object(object_pattern, &mut output)
        .unwrap()
        .into_iter()
        .map(|term| to_owned(term).unwrap())
        .collect();
    assert_eq!(
        expected,
        CallResult::Ok(tuple(vec![list(bindings), list(objects)]))
    );
}

#[test]
fn hash_traversal_against_otp_29() {
    let Some(erl) = reference() else {
        return;
    };
    for (name, kind) in [
        ("set", TableType::Set),
        ("bag", TableType::Bag),
        ("duplicate_bag", TableType::DuplicateBag),
    ] {
        for count in [255, 300] {
            let expected = erl.call("ets_ops", "run_hash_traversal", &[atom(name), int(count)]);
            let mut registry = Registry::new();
            let tid = registry.create(options(kind)).unwrap();
            let mut table = registry.get_mut(tid).unwrap();
            let mut source = VecHeap::new();
            for key in 1..=count {
                let object = from_owned(&tuple(vec![int(key), int(key)]), &mut source).unwrap();
                table.insert(&[object]).unwrap();
            }
            let mut output = VecHeap::new();
            let first = table.edge(false, &mut output).unwrap().unwrap();
            let mut walk = Vec::new();
            let mut key = Some(first);
            while let Some(current) = key {
                walk.push(to_owned(current).unwrap());
                key = table.next(current, &mut output).unwrap();
            }
            let slots: Vec<_> = (0..=count as usize + 256)
                .map(|index| {
                    table
                        .slot(index, &mut output)
                        .unwrap()
                        .map(|term| to_owned(term).unwrap())
                        .unwrap_or_else(|| atom("$end_of_table"))
                })
                .take_while(|slot| slot != &atom("$end_of_table"))
                .chain(std::iter::once(atom("$end_of_table")))
                .collect();
            let objects = table
                .tab2list(&mut output)
                .unwrap()
                .into_iter()
                .map(|term| to_owned(term).unwrap())
                .collect();
            let CallResult::Ok(OwnedTerm::Tuple(ref parts)) = expected else {
                panic!("reference hash iteration failed: {expected:?}");
            };
            assert_eq!(parts[0], to_owned(first).unwrap(), "{name} first");
            let OwnedTerm::List {
                elems: expected_walk,
                ..
            } = &parts[1]
            else {
                unreachable!()
            };
            assert_eq!(expected_walk, &walk, "{name} walk");
            let OwnedTerm::List {
                elems: expected_slots,
                ..
            } = &parts[2]
            else {
                unreachable!()
            };
            for (index, (expected, actual)) in expected_slots.iter().zip(slots).enumerate() {
                assert_eq!(expected, &actual, "{name} slot {index}");
            }
            assert_eq!(parts[3], list(objects), "{name} tab2list");
        }
    }
}

#[test]
fn fixed_hash_deleted_key_against_otp_29() {
    let Some(erl) = reference() else {
        return;
    };
    let expected = erl.call("ets_ops", "run_fixed", &[]);
    let mut registry = Registry::new();
    let tid = registry.create(options(TableType::Set)).unwrap();
    let mut table = registry.get_mut(tid).unwrap();
    let mut source = VecHeap::new();
    for key in 1..=255 {
        let object = from_owned(&tuple(vec![int(key), int(key)]), &mut source).unwrap();
        table.insert(&[object]).unwrap();
    }
    table.safe_fixtable(true).unwrap();
    let mut output = VecHeap::new();
    let first = table.edge(false, &mut output).unwrap().unwrap();
    table.delete_key(first);
    let next = table.next(first, &mut output).unwrap().unwrap();
    let slot = table.slot(0, &mut output).unwrap().unwrap();
    table.safe_fixtable(false).unwrap();
    assert_eq!(
        table.next(first, &mut output),
        Err(arinsal_ets::EtsError::BadArg)
    );
    assert_eq!(
        expected,
        CallResult::Ok(tuple(vec![
            to_owned(first).unwrap(),
            to_owned(next).unwrap(),
            to_owned(slot).unwrap(),
        ]))
    );
}

#[test]
fn hash_bag_history_against_otp_29() {
    let Some(erl) = reference() else {
        return;
    };
    let mut seed = 0x7a65_7791_b382_d175_u64;
    let mut objects = Vec::new();
    for index in 0..200 {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        objects.push(tuple(vec![int((seed % 20 + 1) as i64), int(index % 5)]));
    }
    for (name, kind) in [
        ("set", TableType::Set),
        ("bag", TableType::Bag),
        ("duplicate_bag", TableType::DuplicateBag),
    ] {
        let expected = erl.call(
            "ets_ops",
            "run_hash_history",
            &[atom(name), list(objects.clone())],
        );
        let mut registry = Registry::new();
        let tid = registry.create(options(kind)).unwrap();
        let mut table = registry.get_mut(tid).unwrap();
        let mut source = VecHeap::new();
        for object in &objects {
            let value = from_owned(object, &mut source).unwrap();
            table.insert(&[value]).unwrap();
        }
        let mut output = VecHeap::new();
        let mut current = table.edge(false, &mut output).unwrap();
        let mut walk = Vec::new();
        while let Some(key) = current {
            walk.push(to_owned(key).unwrap());
            current = table.next(key, &mut output).unwrap();
        }
        let mut slots = Vec::new();
        for index in 0..=512 {
            let slot = table.slot(index, &mut output).unwrap();
            match slot {
                Some(slot) => slots.push(to_owned(slot).unwrap()),
                None => {
                    slots.push(atom("$end_of_table"));
                    break;
                }
            }
        }
        let all = table
            .tab2list(&mut output)
            .unwrap()
            .into_iter()
            .map(|value| to_owned(value).unwrap())
            .collect();
        let lookups = (1..=20)
            .map(|key| {
                list(
                    table
                        .lookup(Term::small(key).unwrap(), &mut output)
                        .unwrap()
                        .into_iter()
                        .map(|value| to_owned(value).unwrap())
                        .collect(),
                )
            })
            .collect();
        assert_eq!(
            expected,
            CallResult::Ok(tuple(vec![
                list(walk),
                list(slots),
                list(all),
                list(lookups)
            ])),
            "{name} bag history"
        );
    }
}

#[test]
fn match_spec_validation_and_lists_against_otp_29() {
    let Some(erl) = reference() else {
        return;
    };
    let a = atom("$1");
    let head = tuple(vec![a.clone()]);
    let clause = |guards: Vec<OwnedTerm>, body: Vec<OwnedTerm>| {
        list(vec![tuple(vec![head.clone(), list(guards), list(body)])])
    };
    let cases = vec![
        clause(vec![], vec![list(vec![a.clone()])]),
        clause(
            vec![],
            vec![tuple(vec![atom("element"), int(99), a.clone()])],
        ),
        clause(vec![], vec![tuple(vec![atom("foo"), a.clone()])]),
        clause(vec![], vec![atom("$2")]),
        clause(
            vec![tuple(vec![atom("element"), int(99), a.clone()])],
            vec![atom("true")],
        ),
        clause(
            vec![],
            vec![tuple(vec![atom("hd"), list(vec![atom("hello")])])],
        ),
        clause(
            vec![],
            vec![tuple(vec![
                atom("map_size"),
                OwnedTerm::Map(vec![(atom("a"), int(1))]),
            ])],
        ),
    ];
    let expected = erl.call("ets_ops", "run_specs", &[list(cases.clone())]);
    let mut source = VecHeap::new();
    let object = from_owned(&tuple(vec![int(1)]), &mut source).unwrap();
    let mut actual = Vec::new();
    for case in cases {
        let mut spec_heap = VecHeap::new();
        let specification = from_owned(&case, &mut spec_heap).unwrap();
        let outcome = match MatchProgram::compile(specification) {
            Ok(program) => {
                let mut output = VecHeap::new();
                list(
                    program
                        .run(object, &mut output)
                        .unwrap()
                        .into_iter()
                        .map(|value| to_owned(value).unwrap())
                        .collect(),
                )
            }
            Err(_) => atom("badarg"),
        };
        actual.push(outcome);
    }
    assert_eq!(expected, CallResult::Ok(list(actual)));
}

#[test]
fn guard_bif_table_against_otp_29() {
    let Some(erl) = reference() else {
        return;
    };
    let binary = OwnedTerm::Binary(vec![1, 2, 3, 4]);
    let map = OwnedTerm::Map(vec![(atom("a"), int(7))]);
    let value_cases: &[(&str, Vec<OwnedTerm>)] = &[
        ("abs", vec![int(-7)]),
        ("element", vec![int(2), tuple(vec![atom("a"), int(8)])]),
        ("hd", vec![list(vec![int(1), int(2)])]),
        ("tl", vec![list(vec![int(1), int(2)])]),
        ("length", vec![list(vec![int(1), int(2)])]),
        ("map_get", vec![atom("a"), map.clone()]),
        ("map_size", vec![map.clone()]),
        ("is_map_key", vec![atom("a"), map.clone()]),
        ("is_atom", vec![atom("a")]),
        ("is_integer", vec![int(1)]),
        ("is_integer", vec![int(2), int(1), int(3)]),
        ("is_float", vec![OwnedTerm::Float(1.5)]),
        ("is_number", vec![int(1)]),
        ("is_tuple", vec![tuple(vec![int(1)])]),
        ("is_list", vec![list(vec![int(1)])]),
        ("is_map", vec![map.clone()]),
        ("is_binary", vec![binary.clone()]),
        ("is_bitstring", vec![binary.clone()]),
        ("is_boolean", vec![atom("true")]),
        ("is_reference", vec![int(1)]),
        ("is_pid", vec![int(1)]),
        ("is_port", vec![int(1)]),
        ("is_function", vec![int(1)]),
        ("is_function", vec![int(1), int(2)]),
        (
            "is_record",
            vec![tuple(vec![atom("tag"), int(3)]), atom("tag"), int(2)],
        ),
        ("bnot", vec![int(7)]),
        ("band", vec![int(7), int(3)]),
        ("bor", vec![int(7), int(8)]),
        ("bxor", vec![int(7), int(3)]),
        ("bsl", vec![int(7), int(2)]),
        ("bsr", vec![int(7), int(2)]),
        ("float", vec![int(7)]),
        ("round", vec![OwnedTerm::Float(2.5)]),
        ("trunc", vec![OwnedTerm::Float(-2.5)]),
        ("ceil", vec![OwnedTerm::Float(2.2)]),
        ("floor", vec![OwnedTerm::Float(-2.2)]),
        ("size", vec![tuple(vec![int(1)])]),
        ("byte_size", vec![binary.clone()]),
        ("bit_size", vec![binary.clone()]),
        ("binary_part", vec![binary.clone(), int(1), int(2)]),
        (
            "binary_part",
            vec![binary.clone(), tuple(vec![int(1), int(2)])],
        ),
        ("tuple_size", vec![tuple(vec![int(1), int(2)])]),
        ("+", vec![int(7)]),
        ("-", vec![int(7)]),
        ("+", vec![int(7), int(3)]),
        ("-", vec![int(7), int(3)]),
        ("*", vec![int(7), int(3)]),
        ("/", vec![int(7), int(2)]),
        ("div", vec![int(7), int(2)]),
        ("rem", vec![int(7), int(2)]),
        ("max", vec![int(7), int(3)]),
        ("min", vec![int(7), int(3)]),
        ("==", vec![int(1), OwnedTerm::Float(1.0)]),
        ("/=", vec![int(1), int(2)]),
        ("=:=", vec![int(1), OwnedTerm::Float(1.0)]),
        ("=/=", vec![int(1), OwnedTerm::Float(1.0)]),
        (">", vec![int(2), int(1)]),
        (">=", vec![int(2), int(2)]),
        ("<", vec![int(1), int(2)]),
        ("=<", vec![int(1), int(1)]),
        ("not", vec![atom("true")]),
        ("and", vec![atom("true"), atom("false")]),
        ("or", vec![atom("true"), atom("false")]),
        ("xor", vec![atom("true"), atom("false")]),
        (
            "andalso",
            vec![atom("false"), tuple(vec![atom("div"), int(1), int(0)])],
        ),
        (
            "orelse",
            vec![atom("true"), tuple(vec![atom("div"), int(1), int(0)])],
        ),
    ];
    let mut specs = Vec::new();
    for (name, args) in value_cases {
        let expression = tuple(
            std::iter::once(atom(name))
                .chain(args.iter().cloned())
                .collect(),
        );
        for guard in [false, true] {
            specs.push(list(vec![tuple(vec![
                tuple(vec![atom("$1")]),
                list(if guard {
                    vec![expression.clone()]
                } else {
                    Vec::new()
                }),
                list(vec![if guard {
                    atom("ok")
                } else {
                    expression.clone()
                }]),
            ])]));
        }
    }
    let expected = erl.call("ets_ops", "run_specs", &[list(specs.clone())]);
    let mut actual = Vec::new();
    let mut input = VecHeap::new();
    let object = from_owned(&tuple(vec![int(1)]), &mut input).unwrap();
    for (index, spec) in specs.iter().enumerate() {
        let mut source = VecHeap::new();
        let term = from_owned(spec, &mut source).unwrap();
        let result = match MatchProgram::compile(term) {
            Ok(program) => {
                let mut output = VecHeap::new();
                list(
                    program
                        .run(object, &mut output)
                        .unwrap()
                        .into_iter()
                        .map(|value| to_owned(value).unwrap())
                        .collect(),
                )
            }
            Err(_) => atom("badarg"),
        };
        actual.push(result);
        let _ = index;
    }
    let CallResult::Ok(OwnedTerm::List {
        elems: ref expected_values,
        ..
    }) = expected
    else {
        panic!("reference failed");
    };
    for (index, (expected, actual)) in expected_values.iter().zip(actual.iter()).enumerate() {
        assert_eq!(expected, actual, "guard case {index}: {:?}", specs[index]);
    }
}

#[test]
fn concurrent_ordered_writers_and_loose_numeric_keys() {
    let mut settings = options(TableType::OrderedSet);
    settings.write_concurrency = WriteConcurrency::Enabled;
    let table = std::sync::Arc::new(ConcurrentTable::new(settings, 64).unwrap());
    let per_worker = if cfg!(miri) { 50 } else { 5000 };
    let workers: Vec<_> = (0..4)
        .map(|worker| {
            let table = table.clone();
            std::thread::spawn(move || {
                let mut heap = VecHeap::new();
                for index in 0..per_worker {
                    if index % 1024 == 0 {
                        heap = VecHeap::new();
                    }
                    let key = Term::small((index * 4 + worker) as i64).unwrap();
                    let object = arinsal_term::TermBuilder::new(&mut heap)
                        .tuple(&[key, key])
                        .unwrap();
                    table.insert_one(object).unwrap();
                }
            })
        })
        .collect();
    for worker in workers {
        worker.join().unwrap();
    }
    assert_eq!(table.len(), per_worker * 4);
    let mut heap = VecHeap::new();
    let numeric_key = arinsal_term::TermBuilder::new(&mut heap)
        .float(42.0)
        .unwrap();
    let numeric_object = arinsal_term::TermBuilder::new(&mut heap)
        .tuple(&[numeric_key, Term::small(99).unwrap()])
        .unwrap();
    table.insert_one(numeric_object).unwrap();
    assert_eq!(table.len(), per_worker * 4);
    let mut output = VecHeap::new();
    let found = table.lookup(Term::small(42).unwrap(), &mut output).unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(
        to_owned(found[0]).unwrap(),
        tuple(vec![OwnedTerm::Float(42.0), int(99)])
    );
}

#[test]
fn bignum_counters_against_otp_29() {
    let Some(erl) = reference() else {
        return;
    };
    let expected = erl.call("ets_ops", "run_big_counters", &[]);
    let mut registry = Registry::new();
    let tid = registry.create(options(TableType::Set)).unwrap();
    let mut table = registry.get_mut(tid).unwrap();
    let mut input = VecHeap::new();
    let key = from_owned(&atom("k"), &mut input).unwrap();
    let big = arinsal_term::TermBuilder::new(&mut input)
        .int_from_bigint(&(num_bigint::BigInt::from(1_u8) << 80))
        .unwrap();
    let object = arinsal_term::TermBuilder::new(&mut input)
        .tuple(&[key, big])
        .unwrap();
    table.insert(&[object]).unwrap();
    let first = table
        .update_counter(
            key,
            &[CounterOp {
                position: 2,
                increment: 5,
                threshold: None,
            }],
            None,
        )
        .unwrap();
    let second = table
        .update_counter(
            key,
            &[
                CounterOp {
                    position: 2,
                    increment: -10,
                    threshold: None,
                },
                CounterOp {
                    position: 2,
                    increment: 1,
                    threshold: Some((0, 7)),
                },
            ],
            None,
        )
        .unwrap();
    let mut output = VecHeap::new();
    let rows = table.lookup(key, &mut output).unwrap();
    let actual = tuple(vec![
        to_owned(first[0]).unwrap(),
        list(
            second
                .into_iter()
                .map(|term| to_owned(term).unwrap())
                .collect(),
        ),
        list(
            rows.into_iter()
                .map(|term| to_owned(term).unwrap())
                .collect(),
        ),
    ]);
    assert_eq!(expected, CallResult::Ok(actual));
}

#[test]
fn bignum_counter_operands_and_default_key_against_otp_29() {
    let Some(erl) = reference() else {
        return;
    };
    let expected = erl.call("ets_ops", "run_big_counter_operands", &[]);
    let mut registry = Registry::new();
    let tid = registry.create(options(TableType::Set)).unwrap();
    let mut table = registry.get_mut(tid).unwrap();
    let mut input = VecHeap::new();
    let wanted = from_owned(&atom("wanted"), &mut input).unwrap();
    let other = from_owned(&atom("other"), &mut input).unwrap();
    let default = arinsal_term::TermBuilder::new(&mut input)
        .tuple(&[other, Term::small(0).unwrap()])
        .unwrap();
    let big = num_bigint::BigInt::from(1_u8) << 80_usize;
    let first = table
        .update_counter_big(
            wanted,
            &[Some(BigCounterOp {
                position: 2,
                increment: big.clone(),
                threshold: None,
            })],
            Some(default),
        )
        .unwrap();
    let second = table
        .update_counter_big(
            wanted,
            &[Some(BigCounterOp {
                position: 2,
                increment: -big,
                threshold: None,
            })],
            None,
        )
        .unwrap();
    let mut output = VecHeap::new();
    let found = table
        .lookup(wanted, &mut output)
        .unwrap()
        .into_iter()
        .map(|term| to_owned(term).unwrap())
        .collect();
    let absent = table
        .lookup(other, &mut output)
        .unwrap()
        .into_iter()
        .map(|term| to_owned(term).unwrap())
        .collect();
    let actual = tuple(vec![
        to_owned(first[0]).unwrap(),
        to_owned(second[0]).unwrap(),
        list(found),
        list(absent),
    ]);
    assert_eq!(expected, CallResult::Ok(actual));
}

#[test]
fn fixed_bag_reinsert_histories_against_otp_29() {
    let Some(erl) = reference() else {
        return;
    };
    for (name, kind) in [
        ("bag", TableType::Bag),
        ("duplicate_bag", TableType::DuplicateBag),
    ] {
        let mut seed = 0x8d61_7e2a_08f7_26c9_u64;
        let mut operations = Vec::new();
        for index in 0..2500 {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            let object = tuple(vec![
                int((seed % 20) as i64),
                int(((seed >> 11) % 5) as i64),
            ]);
            let operation = match index % 80 {
                0 => tuple(vec![atom("fix"), atom("none")]),
                79 => tuple(vec![atom("unfix"), atom("none")]),
                _ => match seed % 6 {
                    0 | 1 => tuple(vec![atom("insert"), object]),
                    2 => tuple(vec![atom("delete_object"), object]),
                    3 => tuple(vec![atom("delete"), int((seed % 20) as i64)]),
                    4 => tuple(vec![atom("lookup"), int((seed % 20) as i64)]),
                    _ => tuple(vec![atom("first"), atom("none")]),
                },
            };
            operations.push(operation);
        }
        let expected = erl.call("ets_ops", "run", &[atom(name), list(operations.clone())]);
        let actual = run_local(kind, &operations);
        let CallResult::Ok(OwnedTerm::List {
            elems: ref expected_values,
            ..
        }) = expected
        else {
            panic!("reference failed for {name}");
        };
        for (index, (expected, actual)) in expected_values.iter().zip(actual.iter()).enumerate() {
            assert_eq!(
                expected, actual,
                "{name} fixed history {index}: {:?}",
                operations[index]
            );
        }
    }
}

#[test]
fn large_hash_shrink_against_otp_29() {
    let Some(erl) = reference() else {
        return;
    };
    let expected = erl.call("ets_ops", "run_shrink", &[]);
    let mut registry = Registry::new();
    let tid = registry.create(options(TableType::Set)).unwrap();
    let mut table = registry.get_mut(tid).unwrap();
    let mut input = VecHeap::new();
    for key in 1..=5000 {
        let value = Term::small(key).unwrap();
        let object = arinsal_term::TermBuilder::new(&mut input)
            .tuple(&[value, value])
            .unwrap();
        table.insert(&[object]).unwrap();
    }
    for key in 1..=4500 {
        table.delete_key(Term::small(key).unwrap());
    }
    let mut output = VecHeap::new();
    let mut slots = Vec::new();
    for index in 0..=5001 {
        let value = table.slot(index, &mut output).unwrap();
        match value {
            Some(value) => slots.push(to_owned(value).unwrap()),
            None => {
                slots.push(atom("$end_of_table"));
                break;
            }
        }
    }
    let objects = table
        .tab2list(&mut output)
        .unwrap()
        .into_iter()
        .map(|value| to_owned(value).unwrap())
        .collect();
    let actual = tuple(vec![list(slots), list(objects)]);
    let CallResult::Ok(OwnedTerm::Tuple(ref parts)) = expected else {
        panic!("reference failed");
    };
    let OwnedTerm::Tuple(ref actual_parts) = actual else {
        unreachable!()
    };
    let OwnedTerm::List {
        elems: ref expected_slots,
        ..
    } = parts[0]
    else {
        unreachable!()
    };
    let OwnedTerm::List {
        elems: ref actual_slots,
        ..
    } = actual_parts[0]
    else {
        unreachable!()
    };
    assert_eq!(
        expected_slots.len(),
        actual_slots.len(),
        "hash slot count after shrink"
    );
    for (index, (expected, actual)) in expected_slots.iter().zip(actual_slots.iter()).enumerate() {
        assert_eq!(expected, actual, "shrunken slot {index}");
    }
    assert_eq!(parts[1], actual_parts[1], "shrunken tab2list");
}

#[test]
fn deterministic_info_keys_against_otp_29() {
    let Some(erl) = reference() else {
        return;
    };
    for (name, kind) in [
        ("set", TableType::Set),
        ("bag", TableType::Bag),
        ("duplicate_bag", TableType::DuplicateBag),
        ("ordered_set", TableType::OrderedSet),
    ] {
        let expected = erl.call("ets_ops", "run_info", &[atom(name)]);
        let mut settings = options(kind);
        settings.name = global_atoms().intern("info_probe").unwrap();
        let mut registry = Registry::new();
        let tid = registry.create(settings).unwrap();
        let table = registry.get(tid).unwrap();
        let node = Term::atom(global_atoms().intern("nonode@nohost").unwrap());
        let keys = [
            "name",
            "type",
            "keypos",
            "protection",
            "heir",
            "size",
            "node",
            "named_table",
            "read_concurrency",
            "write_concurrency",
            "decentralized_counters",
            "compressed",
            "fixed",
            "safe_fixed",
            "safe_fixed_monotonic_time",
            "stats",
        ];
        let mut output = VecHeap::new();
        let actual = list(
            keys.iter()
                .map(|key| {
                    tuple(vec![
                        atom(key),
                        to_owned(table.info_item(key, node, &mut output).unwrap()).unwrap(),
                    ])
                })
                .collect(),
        );
        assert_eq!(expected, CallResult::Ok(actual), "{name} info");
        let all = table.info_list(node, &mut output).unwrap();
        let OwnedTerm::List {
            elems: properties, ..
        } = &to_owned(all).unwrap()
        else {
            unreachable!()
        };
        assert_eq!(properties.len(), 15);
        assert!(table.memory_words() > 0);
    }
}

#[test]
fn fixed_info_uses_vm_time_and_per_process_counts() {
    let mut registry = Registry::new();
    let tid = registry.create(options(TableType::Set)).unwrap();
    let mut table = registry.get_mut(tid).unwrap();
    let owner = Term::pid(1, 0).unwrap();
    let other = Term::pid(2, 0).unwrap();
    let mut input = VecHeap::new();
    let system_time = arinsal_term::TermBuilder::new(&mut input)
        .tuple(&[
            Term::small(1790).unwrap(),
            Term::small(344260).unwrap(),
            Term::small(485075).unwrap(),
        ])
        .unwrap();
    let monotonic_time = arinsal_term::TermBuilder::new(&mut input)
        .int_from_i128(-576460751842834667)
        .unwrap();
    table
        .safe_fixtable_for_at(owner, true, system_time, monotonic_time)
        .unwrap();
    table
        .safe_fixtable_for_at(other, true, Term::NIL, Term::NIL)
        .unwrap();
    table
        .safe_fixtable_for_at(owner, true, Term::NIL, Term::NIL)
        .unwrap();
    let node = Term::atom(global_atoms().intern("nonode@nohost").unwrap());
    let mut output = VecHeap::new();
    let expected_counts = list(vec![
        tuple(vec![to_owned(owner).unwrap(), int(2)]),
        tuple(vec![to_owned(other).unwrap(), int(1)]),
    ]);
    for (key, time) in [
        ("safe_fixed", to_owned(system_time).unwrap()),
        (
            "safe_fixed_monotonic_time",
            to_owned(monotonic_time).unwrap(),
        ),
    ] {
        let actual = table.info_item(key, node, &mut output).unwrap();
        assert_eq!(
            to_owned(actual).unwrap(),
            tuple(vec![time, expected_counts.clone()])
        );
    }
    table.safe_fixtable_for(owner, false).unwrap();
    table.safe_fixtable_for(other, false).unwrap();
    assert_eq!(table.fixation_count(), 1);
    table.safe_fixtable_for(owner, false).unwrap();
    assert_eq!(
        to_owned(table.info_item("safe_fixed", node, &mut output).unwrap()).unwrap(),
        atom("false")
    );
}

#[test]
fn fixed_info_against_otp_29() {
    let Some(erl) = reference() else {
        return;
    };
    let expected = erl.call("ets_ops", "run_fixed_info", &[]);
    let CallResult::Ok(OwnedTerm::Tuple(ref values)) = expected else {
        panic!("reference fixed info failed: {expected:?}");
    };
    let OwnedTerm::Tuple(first) = &values[0] else {
        panic!("invalid reference safe_fixed");
    };
    let OwnedTerm::List {
        elems: processes, ..
    } = &first[1]
    else {
        panic!("invalid reference process list");
    };
    let OwnedTerm::Tuple(process) = &processes[0] else {
        panic!("invalid reference process");
    };
    let OwnedTerm::Tuple(monotonic) = &values[1] else {
        panic!("invalid reference monotonic info");
    };
    let mut source = VecHeap::new();
    let pid = from_owned(&process[0], &mut source).unwrap();
    let system_time = from_owned(&first[0], &mut source).unwrap();
    let monotonic_time = from_owned(&monotonic[0], &mut source).unwrap();
    let mut settings = options(TableType::Set);
    settings.owner = pid;
    let mut registry = Registry::new();
    let tid = registry.create(settings).unwrap();
    let mut table = registry.get_mut(tid).unwrap();
    let node = Term::atom(global_atoms().intern("nonode@nohost").unwrap());
    let mut output = VecHeap::new();
    table
        .safe_fixtable_for_at(pid, true, system_time, monotonic_time)
        .unwrap();
    let first_actual = to_owned(table.info_item("safe_fixed", node, &mut output).unwrap()).unwrap();
    let monotonic_actual = to_owned(
        table
            .info_item("safe_fixed_monotonic_time", node, &mut output)
            .unwrap(),
    )
    .unwrap();
    table.safe_fixtable_for(pid, true).unwrap();
    let second_actual =
        to_owned(table.info_item("safe_fixed", node, &mut output).unwrap()).unwrap();
    table.safe_fixtable_for(pid, false).unwrap();
    let third_actual = to_owned(table.info_item("safe_fixed", node, &mut output).unwrap()).unwrap();
    table.safe_fixtable_for(pid, false).unwrap();
    let final_actual = to_owned(table.info_item("safe_fixed", node, &mut output).unwrap()).unwrap();
    assert_eq!(
        expected,
        CallResult::Ok(tuple(vec![
            first_actual,
            monotonic_actual,
            second_actual,
            third_actual,
            final_actual,
        ]))
    );
}

#[test]
fn update_element_default_against_otp_29() {
    let Some(erl) = reference() else {
        return;
    };
    let expected = erl.call("ets_ops", "run_element_default", &[]);
    let mut registry = Registry::new();
    let tid = registry.create(options(TableType::Set)).unwrap();
    let mut table = registry.get_mut(tid).unwrap();
    let mut input = VecHeap::new();
    let key = from_owned(&atom("wanted"), &mut input).unwrap();
    let other = from_owned(&atom("other"), &mut input).unwrap();
    let default = arinsal_term::TermBuilder::new(&mut input)
        .tuple(&[other, Term::small(0).unwrap()])
        .unwrap();
    let first = table
        .update_element(key, &[Some((2, Term::small(9).unwrap()))], Some(default))
        .unwrap();
    let second = table
        .update_element(key, &[Some((2, Term::small(11).unwrap()))], Some(default))
        .unwrap();
    let mut output = VecHeap::new();
    let wanted = table
        .lookup(key, &mut output)
        .unwrap()
        .into_iter()
        .map(|value| to_owned(value).unwrap())
        .collect();
    let other = table
        .lookup(other, &mut output)
        .unwrap()
        .into_iter()
        .map(|value| to_owned(value).unwrap())
        .collect();
    let actual = tuple(vec![
        atom(if first { "true" } else { "false" }),
        atom(if second { "true" } else { "false" }),
        list(wanted),
        list(other),
    ]);
    assert_eq!(expected, CallResult::Ok(actual));
}

#[test]
fn randomized_guard_expressions_against_otp_29() {
    let Some(erl) = reference() else {
        return;
    };
    let functions: &[(&str, usize)] = &[
        ("abs", 1),
        ("element", 2),
        ("hd", 1),
        ("tl", 1),
        ("length", 1),
        ("map_get", 2),
        ("map_size", 1),
        ("is_map_key", 2),
        ("is_atom", 1),
        ("is_integer", 1),
        ("is_float", 1),
        ("is_number", 1),
        ("is_tuple", 1),
        ("is_list", 1),
        ("is_map", 1),
        ("is_binary", 1),
        ("is_boolean", 1),
        ("is_reference", 1),
        ("is_pid", 1),
        ("is_port", 1),
        ("is_function", 1),
        ("is_function", 2),
        ("is_record", 3),
        ("is_bitstring", 1),
        ("is_integer", 3),
        ("bnot", 1),
        ("band", 2),
        ("bor", 2),
        ("bxor", 2),
        ("bsl", 2),
        ("bsr", 2),
        ("float", 1),
        ("round", 1),
        ("trunc", 1),
        ("ceil", 1),
        ("floor", 1),
        ("size", 1),
        ("byte_size", 1),
        ("bit_size", 1),
        ("tuple_size", 1),
        ("binary_part", 2),
        ("binary_part", 3),
        ("node", 0),
        ("node", 1),
        ("self", 0),
        ("+", 2),
        ("-", 2),
        ("*", 2),
        ("/", 2),
        ("div", 2),
        ("rem", 2),
        ("max", 2),
        ("min", 2),
        ("==", 2),
        ("/=", 2),
        ("=:=", 2),
        ("=/=", 2),
        (">", 2),
        (">=", 2),
        ("<", 2),
        ("=<", 2),
        ("not", 1),
        ("and", 2),
        ("or", 2),
        ("xor", 2),
        ("andalso", 2),
        ("andthen", 2),
        ("orelse", 2),
    ];
    let values = [
        int(0),
        int(-7),
        OwnedTerm::Float(2.5),
        atom("true"),
        atom("a"),
        list(vec![int(1), int(2)]),
        tuple(vec![int(1), int(2)]),
        OwnedTerm::Map(vec![(atom("a"), int(3))]),
        OwnedTerm::Binary(vec![1, 2, 3]),
    ];
    let mut seed = 0x913e_35ab_4d66_7d09_u64;
    let mut specs = Vec::new();
    for index in 0..5000 {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        let (name, arity) = functions[index % functions.len()];
        let arity = if index % 7 == 0 { arity + 1 } else { arity };
        let mut args = Vec::new();
        for offset in 0..arity {
            let choice = ((seed >> ((offset % 6) * 8)) as usize) % values.len();
            args.push(values[choice].clone());
        }
        let expression = tuple(std::iter::once(atom(name)).chain(args).collect());
        let guard = index % 2 == 0 || name == "self";
        specs.push(list(vec![tuple(vec![
            tuple(vec![atom("$1")]),
            list(if guard {
                vec![expression.clone()]
            } else {
                Vec::new()
            }),
            list(vec![if guard { atom("ok") } else { expression }]),
        ])]));
    }
    let expected = erl.call("ets_ops", "run_specs", &[list(specs.clone())]);
    let CallResult::Ok(OwnedTerm::List {
        elems: ref expected_values,
        ..
    }) = expected
    else {
        panic!("reference failed");
    };
    let mut input = VecHeap::new();
    let object = from_owned(&tuple(vec![int(1)]), &mut input).unwrap();
    for (index, spec) in specs.iter().enumerate() {
        let mut source = VecHeap::new();
        let term = from_owned(spec, &mut source).unwrap();
        let actual = match MatchProgram::compile(term) {
            Ok(program) => {
                let mut output = VecHeap::new();
                list(
                    program
                        .run(object, &mut output)
                        .unwrap()
                        .into_iter()
                        .map(|result| to_owned(result).unwrap())
                        .collect(),
                )
            }
            Err(_) => atom("badarg"),
        };
        assert_eq!(
            expected_values[index], actual,
            "random spec {index}: {spec:?}"
        );
    }
}

#[test]
fn trace_operations_are_validated_and_dispatched() {
    struct Tracer(std::sync::Mutex<Vec<String>>);
    impl MatchContext for Tracer {
        fn trace_operation(
            &self,
            name: &str,
            _arguments: &[Term],
        ) -> Result<Term, arinsal_ets::EtsError> {
            self.0.lock().unwrap().push(name.to_owned());
            Ok(Term::atom(global_atoms().intern("true").unwrap()))
        }
    }
    let forms: &[(&str, usize)] = &[
        ("message", 1),
        ("return_trace", 0),
        ("exception_trace", 0),
        ("process_dump", 0),
        ("enable_trace", 1),
        ("disable_trace", 1),
        ("trace", 2),
        ("display", 1),
        ("caller", 0),
        ("caller_line", 0),
        ("current_stacktrace", 0),
        ("set_seq_token", 2),
        ("get_seq_token", 0),
        ("silent", 1),
        ("is_seq_trace", 0),
        ("set_tcw", 1),
    ];
    let tracer = Tracer(std::sync::Mutex::new(Vec::new()));
    for &(name, arity) in forms {
        let expression = tuple(
            std::iter::once(atom(name))
                .chain((0..arity).map(|_| int(1)))
                .collect(),
        );
        let spec = list(vec![tuple(vec![
            atom("$1"),
            list(vec![]),
            list(vec![expression]),
        ])]);
        let mut source = VecHeap::new();
        let term = from_owned(&spec, &mut source).unwrap();
        assert!(MatchProgram::compile(term).is_err(), "ETS accepted {name}");
        let program =
            MatchProgram::compile_trace(term).unwrap_or_else(|error| panic!("{name}: {error:?}"));
        let mut output = VecHeap::new();
        // The trace argument list `[1]`.
        let arguments = TermBuilder::new(&mut output)
            .list_from_slice(&[Term::small(1).unwrap()])
            .unwrap();
        let result = program
            .run_with_context(arguments, &mut output, &tracer)
            .unwrap();
        // `{message, X}` returns X; every other form leaves `true` as the result.
        let expected = if name == "message" {
            Term::small(1).unwrap()
        } else {
            Term::atom(global_atoms().intern("true").unwrap())
        };
        assert_eq!(result, Some(expected));
    }
    assert_eq!(tracer.0.lock().unwrap().len(), forms.len());
}

#[test]
fn miri_heap_paths() {
    let mut registry = Registry::new();
    let tid = registry.create(options(TableType::Set)).unwrap();
    let mut table = registry.get_mut(tid).unwrap();
    let mut input = VecHeap::new();
    let binary = arinsal_term::TermBuilder::new(&mut input)
        .binary(&[1, 2, 3])
        .unwrap();
    let object = arinsal_term::TermBuilder::new(&mut input)
        .tuple(&[Term::small(1).unwrap(), binary])
        .unwrap();
    table.insert(&[object]).unwrap();
    table.safe_fixtable(true).unwrap();
    let spec = list(vec![tuple(vec![
        tuple(vec![atom("$1"), atom("$2")]),
        list(vec![]),
        list(vec![tuple(vec![atom("byte_size"), atom("$2")])]),
    ])]);
    let spec_term = from_owned(&spec, &mut input).unwrap();
    let program = MatchProgram::compile(spec_term).unwrap();
    let mut output = VecHeap::new();
    let page = table.select_chunk(&program, false, 1, &mut output).unwrap();
    assert_eq!(to_owned(page.rows[0]).unwrap(), int(3));
    if let Some(continuation) = page.continuation {
        let term = continuation.to_term(&table, &mut output).unwrap();
        let decoded = arinsal_ets::SelectContinuation::from_term(&table, &program, term).unwrap();
        let next = table
            .select_chunk_continue(&program, decoded, &mut output)
            .unwrap();
        assert!(next.rows.is_empty());
    }
    let found = table.lookup(Term::small(1).unwrap(), &mut output).unwrap();
    assert_eq!(found.len(), 1);
    table.delete_key(Term::small(1).unwrap());
    table.safe_fixtable(false).unwrap();
}

#[test]
fn continuations_across_mutation_against_otp_29() {
    let Some(erl) = reference() else {
        return;
    };
    for (name, kind) in [
        ("set", TableType::Set),
        ("ordered_set", TableType::OrderedSet),
        ("bag", TableType::Bag),
        ("duplicate_bag", TableType::DuplicateBag),
    ] {
        for fixed in [false, true] {
            let expected = erl.call(
                "ets_ops",
                "run_mutating_chunks",
                &[atom(name), atom(if fixed { "true" } else { "false" })],
            );
            let mut registry = Registry::new();
            let tid = registry.create(options(kind)).unwrap();
            let mut table = registry.get_mut(tid).unwrap();
            let mut input = VecHeap::new();
            for key in 1..=50 {
                let value = Term::small(key).unwrap();
                let object = arinsal_term::TermBuilder::new(&mut input)
                    .tuple(&[value, value])
                    .unwrap();
                table.insert(&[object]).unwrap();
            }
            table.safe_fixtable(fixed).unwrap();
            let spec = list(vec![tuple(vec![
                tuple(vec![atom("$1"), atom("$2")]),
                list(vec![]),
                list(vec![atom("$_")]),
            ])]);
            let spec_term = from_owned(&spec, &mut input).unwrap();
            let program = MatchProgram::compile(spec_term).unwrap();
            let mut output = VecHeap::new();
            let mut batch = table.select_chunk(&program, false, 5, &mut output).unwrap();
            table.delete_key(Term::small(10).unwrap());
            let added = arinsal_term::TermBuilder::new(&mut input)
                .tuple(&[Term::small(100).unwrap(), Term::small(100).unwrap()])
                .unwrap();
            table.insert(&[added]).unwrap();
            let mut pages = Vec::new();
            loop {
                if !batch.rows.is_empty() {
                    pages.push(list(
                        batch
                            .rows
                            .iter()
                            .map(|&row| to_owned(row).unwrap())
                            .collect(),
                    ));
                }
                let Some(continuation) = batch.continuation else {
                    break;
                };
                let term = continuation.to_term(&table, &mut output).unwrap();
                let continuation =
                    arinsal_ets::SelectContinuation::from_term(&table, &program, term).unwrap();
                batch = table
                    .select_chunk_continue(&program, continuation, &mut output)
                    .unwrap();
            }
            table.safe_fixtable(false).unwrap();
            assert_eq!(
                expected,
                CallResult::Ok(list(pages)),
                "{name} fixed={fixed}"
            );
        }
    }
}

#[test]
fn select_count_continuations_against_otp_29() {
    let Some(erl) = reference() else {
        return;
    };
    for (name, kind) in [
        ("set", TableType::Set),
        ("ordered_set", TableType::OrderedSet),
        ("bag", TableType::Bag),
        ("duplicate_bag", TableType::DuplicateBag),
    ] {
        let expected = erl.call("ets_ops", "run_count_simple", &[atom(name)]);
        let mut registry = Registry::new();
        let tid = registry.create(options(kind)).unwrap();
        let mut table = registry.get_mut(tid).unwrap();
        let mut input = VecHeap::new();
        for key in 1..=100 {
            let value = Term::small(key).unwrap();
            let object = arinsal_term::TermBuilder::new(&mut input)
                .tuple(&[value, value])
                .unwrap();
            table.insert(&[object]).unwrap();
        }
        let spec = list(vec![tuple(vec![
            tuple(vec![atom("$1"), atom("_")]),
            list(vec![tuple(vec![atom(">"), atom("$1"), int(50)])]),
            list(vec![atom("true")]),
        ])]);
        let spec_term = from_owned(&spec, &mut input).unwrap();
        let program = MatchProgram::compile(spec_term).unwrap();
        let mut batch = table.select_count_chunk(&program, 7).unwrap();
        let mut output = VecHeap::new();
        while let Some(continuation) = batch.continuation {
            let term = continuation.to_term(&table, &mut output).unwrap();
            let decoded =
                arinsal_ets::CountContinuation::from_term(&table, &program, term).unwrap();
            batch = table.select_count_continue(&program, decoded, 7).unwrap();
        }
        assert_eq!(
            expected,
            CallResult::Ok(int(batch.count as i64)),
            "{name} select_count"
        );
    }
}

#[test]
fn hash_terminal_continuation_slot_against_otp_29() {
    let Some(erl) = reference() else {
        return;
    };
    let expected = erl.call("ets_ops", "run_continuation_slot", &[]);
    let mut registry = Registry::new();
    let tid = registry.create(options(TableType::Bag)).unwrap();
    let mut table = registry.get_mut(tid).unwrap();
    let mut input = VecHeap::new();
    for value in 1..=5 {
        let object = arinsal_term::TermBuilder::new(&mut input)
            .tuple(&[Term::small(1).unwrap(), Term::small(value).unwrap()])
            .unwrap();
        table.insert(&[object]).unwrap();
    }
    let spec = list(vec![tuple(vec![
        tuple(vec![atom("$1"), atom("$2")]),
        list(vec![]),
        list(vec![atom("$_")]),
    ])]);
    let spec_term = from_owned(&spec, &mut input).unwrap();
    let program = MatchProgram::compile(spec_term).unwrap();
    let mut output = VecHeap::new();
    let page = table.select_chunk(&program, false, 2, &mut output).unwrap();
    let encoded = page
        .continuation
        .unwrap()
        .to_term(&table, &mut output)
        .unwrap();
    // SAFETY: output retains the continuation tuple.
    let slot = unsafe { encoded.tuple_ref() }.unwrap().get(1).unwrap();
    assert_eq!(expected, CallResult::Ok(to_owned(slot).unwrap()));
}

#[test]
fn valid_match_spec_test_against_otp_29() {
    let Some(erl) = reference() else {
        return;
    };
    let cases = [
        list(vec![tuple(vec![
            tuple(vec![atom("$1")]),
            list(vec![]),
            list(vec![atom("$1")]),
        ])]),
        list(vec![tuple(vec![
            tuple(vec![atom("different")]),
            list(vec![]),
            list(vec![atom("ok")]),
        ])]),
        list(vec![tuple(vec![
            tuple(vec![atom("$1")]),
            list(vec![]),
            list(vec![tuple(vec![atom("element"), int(99), atom("$1")])]),
        ])]),
    ];
    let against = tuple(vec![int(1)]);
    for spec in cases {
        let expected = erl.call(
            "erlang",
            "match_spec_test",
            &[against.clone(), spec.clone(), atom("table")],
        );
        let mut input = VecHeap::new();
        let object = from_owned(&against, &mut input).unwrap();
        let specification = from_owned(&spec, &mut input).unwrap();
        let mut output = VecHeap::new();
        let actual = match_spec_test(object, specification, MatchDialect::Table, &mut output, &());
        let actual = actual.unwrap();
        assert_eq!(expected, CallResult::Ok(to_owned(actual).unwrap()));
    }
}

#[test]
fn map_head_bindings_against_otp_29() {
    let Some(erl) = reference() else {
        return;
    };
    let object = OwnedTerm::Map((0..40).map(|index| (int(index), int(index * 3))).collect());
    let pattern = OwnedTerm::Map(vec![(int(30), atom("$1"))]);
    let spec = list(vec![tuple(vec![
        pattern,
        list(vec![]),
        list(vec![atom("$1")]),
    ])]);
    let expected = erl.call("ets_ops", "run_map_specs", &[object.clone(), spec.clone()]);
    let mut source = VecHeap::new();
    let value = from_owned(&object, &mut source).unwrap();
    let spec_term = from_owned(&spec, &mut source).unwrap();
    let program = MatchProgram::compile(spec_term).unwrap();
    let mut output = VecHeap::new();
    let actual = list(
        program
            .run_many(&[value], &mut output)
            .unwrap()
            .into_iter()
            .map(|term| to_owned(term).unwrap())
            .collect(),
    );
    assert_eq!(expected, CallResult::Ok(actual));
}

#[test]
fn map_body_expressions_against_otp_29() {
    let Some(erl) = reference() else {
        return;
    };
    let object = tuple(vec![int(7)]);
    let mut large = (0..40)
        .map(|index| (int(index), int(index)))
        .collect::<Vec<_>>();
    large[30].1 = atom("$1");
    for body in [
        OwnedTerm::Map(vec![(atom("a"), atom("$1"))]),
        OwnedTerm::Map(vec![(atom("$1"), int(5))]),
        OwnedTerm::Map(large),
    ] {
        let spec = list(vec![tuple(vec![
            tuple(vec![atom("$1")]),
            list(vec![]),
            list(vec![body]),
        ])]);
        let expected = erl.call("ets_ops", "run_map_specs", &[object.clone(), spec.clone()]);
        let mut source = VecHeap::new();
        let value = from_owned(&object, &mut source).unwrap();
        let spec_term = from_owned(&spec, &mut source).unwrap();
        let program = MatchProgram::compile(spec_term).unwrap();
        let mut output = VecHeap::new();
        let actual = list(
            program
                .run_many(&[value], &mut output)
                .unwrap()
                .into_iter()
                .map(|term| to_owned(term).unwrap())
                .collect(),
        );
        let CallResult::Ok(OwnedTerm::List {
            elems: ref expected_rows,
            ..
        }) = expected
        else {
            panic!("reference failed");
        };
        let OwnedTerm::List {
            elems: actual_rows, ..
        } = &actual
        else {
            unreachable!()
        };
        let OwnedTerm::Map(expected_pairs) = &expected_rows[0] else {
            unreachable!()
        };
        let OwnedTerm::Map(actual_pairs) = &actual_rows[0] else {
            unreachable!()
        };
        // ETF map entry order follows each runtime's HAMT layout; map equality ignores it.
        assert_eq!(expected_pairs.len(), actual_pairs.len());
        for pair in expected_pairs {
            assert!(actual_pairs.contains(pair), "missing map entry {pair:?}");
        }
    }
}

#[test]
fn empty_trace_body_against_otp_29() {
    let Some(erl) = reference() else {
        return;
    };
    let against = list(vec![int(1)]);
    for (head, body) in [
        (list(vec![atom("$1")]), list(vec![])),
        (list(vec![atom("$1")]), list(vec![atom("$1")])),
        (tuple(vec![atom("$1")]), list(vec![atom("$1")])),
        (
            list(vec![atom("$1")]),
            list(vec![
                tuple(vec![atom("message"), atom("$1")]),
                tuple(vec![atom("return_trace")]),
                tuple(vec![atom("exception_trace")]),
            ]),
        ),
    ] {
        let spec = list(vec![tuple(vec![head, list(vec![]), body])]);
        let expected = erl.call(
            "erlang",
            "match_spec_test",
            &[against.clone(), spec.clone(), atom("trace")],
        );
        let mut input = VecHeap::new();
        let against_term = from_owned(&against, &mut input).unwrap();
        let spec_term = from_owned(&spec, &mut input).unwrap();
        let mut output = VecHeap::new();
        let actual = match_spec_test(
            against_term,
            spec_term,
            MatchDialect::Trace,
            &mut output,
            &(),
        )
        .unwrap();
        assert_eq!(
            expected,
            CallResult::Ok(to_owned(actual).unwrap()),
            "trace spec {spec:?}"
        );
    }
}

/// The in-place small counter update must agree with the general path, and must leave the
/// table untouched whenever it declines.
#[test]
fn in_place_counter_update_matches_general_path() {
    let op = |position, increment, threshold| CounterOp {
        position,
        increment,
        threshold,
    };
    let near_max = arinsal_term::MAX_SMALL - 1;
    let cases: Vec<(Vec<CounterOp>, bool)> = vec![
        (vec![op(2, 1, None)], true),
        (vec![op(3, -7, None)], true),
        (vec![op(2, 1, None), op(2, 1, None), op(3, -1, None)], true),
        (vec![op(2, 10, Some((5, 0)))], true),
        (vec![op(3, -50, Some((-5, 7)))], true),
        (vec![], true),
        // Declined: key position, past the tuple, a non-integer element, small overflow.
        (vec![op(1, 1, None)], false),
        (vec![op(2, 1, None), op(9, 1, None)], false),
        (vec![op(4, 1, None)], false),
        (vec![op(5, near_max, None)], false),
    ];
    for kind in [TableType::Set, TableType::OrderedSet] {
        for (pair, (operations, applies)) in [true, false]
            .into_iter()
            .flat_map(|pair| cases.iter().map(move |case| (pair, case)))
        {
            let mut registry = Registry::new();
            let fast_tid = registry.create(options(kind)).unwrap();
            let slow_tid = registry.create(options(kind)).unwrap();
            let mut input = VecHeap::new();
            let key = from_owned(&atom("k"), &mut input).unwrap();
            let object = if pair {
                from_owned(&tuple(vec![atom("k"), int(1)]), &mut input).unwrap()
            } else {
                let elements = vec![
                    atom("k"),
                    int(1),
                    int(40),
                    OwnedTerm::Binary(b"bin".to_vec()),
                    int(near_max - 1),
                ];
                from_owned(&tuple(elements), &mut input).unwrap()
            };
            registry
                .get_mut(slow_tid)
                .unwrap()
                .insert(&[object])
                .unwrap();
            let mut fast = registry.get_mut(fast_tid).unwrap();
            fast.insert(&[object]).unwrap();
            let mut output = VecHeap::new();
            let before = fast.lookup(key, &mut output).unwrap();
            let in_place = fast.update_counter_in_place(key, operations);
            let fast_rows = fast.lookup(key, &mut output).unwrap();
            let owned = |terms: &[Term]| -> Vec<OwnedTerm> {
                terms.iter().map(|term| to_owned(*term).unwrap()).collect()
            };
            let width = if pair { 2 } else { 5 };
            let applicable = *applies && operations.iter().all(|op| op.position <= width);
            match in_place {
                Some(values) => {
                    assert!(
                        applicable,
                        "{kind:?} pair={pair} {operations:?} applied in place"
                    );
                    let mut slow = registry.get_mut(slow_tid).unwrap();
                    let expected = slow.update_counter(key, operations, None).unwrap();
                    let slow_rows = slow.lookup(key, &mut output).unwrap();
                    assert_eq!(owned(&values), owned(&expected));
                    assert_eq!(owned(&fast_rows), owned(&slow_rows));
                }
                None => {
                    assert!(!applicable, "{kind:?} pair={pair} {operations:?} declined");
                    assert_eq!(owned(&fast_rows), owned(&before));
                }
            }
        }
    }
    let mut registry = Registry::new();
    let tid = registry.create(options(TableType::Bag)).unwrap();
    let mut table = registry.get_mut(tid).unwrap();
    let mut input = VecHeap::new();
    let key = from_owned(&atom("k"), &mut input).unwrap();
    let object = from_owned(&tuple(vec![atom("k"), int(1)]), &mut input).unwrap();
    table.insert(&[object]).unwrap();
    assert!(
        table
            .update_counter_in_place(key, &[op(2, 1, None)])
            .is_none()
    );
    drop(table);
    let missing = from_owned(&atom("missing"), &mut input).unwrap();
    let set = registry.create(options(TableType::Set)).unwrap();
    let mut table = registry.get_mut(set).unwrap();
    assert!(
        table
            .update_counter_in_place(missing, &[op(2, 1, None)])
            .is_none()
    );
}

/// `erts_internal:ets_raw_next/2` on a tree table is `db_next_tree`: a key that is gone is not
/// an error (checked against OTP 29.1.1: `ets_raw_next(Tree, 2)` on {1,3} gives 3).
#[test]
fn raw_next_on_a_missing_tree_key_returns_the_successor() {
    let mut registry = Registry::new();
    let tid = registry.create(options(TableType::OrderedSet)).unwrap();
    let mut table = registry.get_mut(tid).unwrap();
    let mut input = VecHeap::new();
    let one = from_owned(&tuple(vec![int(1), atom("a")]), &mut input).unwrap();
    let three = from_owned(&tuple(vec![int(3), atom("b")]), &mut input).unwrap();
    table.insert(&[one, three]).unwrap();
    let mut output = VecHeap::new();
    let next = table
        .raw_next(Term::small(2).unwrap(), &mut output)
        .unwrap()
        .unwrap();
    assert_eq!(next, Term::small(3).unwrap());
    assert_eq!(
        table.raw_next(Term::small(3).unwrap(), &mut output),
        Ok(None)
    );
}
