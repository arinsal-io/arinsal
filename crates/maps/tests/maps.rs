use arinsal_maps::{MapError, from_pairs, get, iter, merge, put, put_many, remove, size, update};
use arinsal_term::{LiteralArea, Term, VecHeap};
use std::process::Command;

fn small(n: i64) -> Term {
    Term::small(n).unwrap()
}
fn pairs(n: usize) -> Vec<(Term, Term)> {
    (1..=n)
        .map(|i| (small(i as i64), small(i as i64)))
        .collect()
}
fn reference(n: usize) -> Option<(Vec<i64>, usize)> {
    let eval = format!(
        "M=maps:from_list([{{I,I}}||I<-lists:seq(1,{n})]),lists:foreach(fun({{K,_}})->io:format(\"~B \",[K]) end,maps:to_list(M)),io:format(\"~n~B~n\",[erts_debug:flat_size(M)]),halt()."
    );
    let output = match Command::new("erl")
        .args(["-noshell", "-eval", &eval])
        .output()
    {
        Ok(output) => output,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            eprintln!("skipping differential test: erl not found");
            return None;
        }
        Err(e) => panic!("erl failed: {e}"),
    };
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let output = String::from_utf8(output.stdout).unwrap();
    let mut lines = output.lines();
    let keys = lines
        .next()
        .unwrap()
        .split_whitespace()
        .map(|s| s.parse().unwrap())
        .collect();
    let words = lines.next().unwrap().parse().unwrap();
    Some((keys, words))
}
fn map_words(node: Term) -> usize {
    if !node.is_hashmap() {
        return if size(node).unwrap() == 0 {
            3
        } else {
            4 + 2 * size(node).unwrap()
        };
    }
    fn count(node: Term) -> usize {
        // SAFETY: all map terms remain in the test's live VecHeap.
        unsafe {
            if node.raw_bits() & 3 == 1 {
                return 2;
            }
            let p = node.raw_ptr();
            let h = *p;
            if h & 63 == 0 {
                return 1
                    + (h >> 6) as usize
                    + (0..(h >> 6) as usize)
                        .map(|i| count(std::mem::transmute::<u64, Term>(*p.add(1 + i))))
                        .sum::<usize>();
            }
            let kind = (h >> 6) & 3;
            let n = ((h >> 16) & 0xffff).count_ones() as usize;
            let offset = if kind >= 2 { 2 } else { 1 };
            offset
                + n
                + (0..n)
                    .map(|i| count(std::mem::transmute::<u64, Term>(*p.add(offset + i))))
                    .sum::<usize>()
        }
    }
    count(node)
}

#[test]
fn differential_integer_maps_order_and_size() {
    let mut sizes = vec![0, 1, 2, 16, 32, 33, 34, 100, 1000, 2000];
    let mut state = 0x8451_1234_u64;
    for _ in 0..16 {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        sizes.push((state % 2001) as usize);
    }
    for n in sizes {
        let Some((expected, words)) = reference(n) else {
            return;
        };
        let mut heap = VecHeap::new();
        let map = from_pairs(&pairs(n), &mut heap).unwrap();
        assert_eq!(size(map), Ok(n));
        assert_eq!(map.is_hashmap(), n > 32, "n={n}");
        let actual: Vec<_> = iter(map)
            .unwrap()
            .map(|(k, _)| k.as_small().unwrap())
            .collect();
        assert_eq!(actual, expected, "n={n}");
        assert_eq!(map_words(map), words, "n={n}");
    }
}

#[test]
fn mutation_and_heap_full() {
    let mut heap = VecHeap::new();
    let mut map = from_pairs(&pairs(100), &mut heap).unwrap();
    for i in 1..=100 {
        map = update(map, small(i), small(i * 2), &mut heap).unwrap();
        assert_eq!(get(map, small(i)), Ok(Some(small(i * 2))));
    }
    for i in 1..=68 {
        map = remove(map, small(i), &mut heap).unwrap();
    }
    assert_eq!(size(map), Ok(32));
    assert!(!map.is_hashmap());
    assert_eq!(map_words(map), 68);
    assert_eq!(
        update(map, small(999), small(1), &mut heap),
        Err(MapError::Badkey(small(999)))
    );
    assert_eq!(get(small(42), small(1)), Err(MapError::Badmap(small(42))));
    let mut tiny = arinsal_term::ProcessHeap::with_words(2);
    assert_eq!(
        from_pairs(&[], &mut tiny),
        Err(MapError::HeapFull { need_words: 3 })
    );
    assert_eq!(tiny.used_words(), 0);
    let original = from_pairs(&pairs(32), &mut heap).unwrap();
    let mut tiny = arinsal_term::ProcessHeap::with_words(5);
    let result = put(original, small(33), small(33), &mut tiny);
    assert!(matches!(result, Err(MapError::HeapFull { need_words: _ })));
    assert_eq!(tiny.used_words(), 0);
    let large_key = from_pairs(&pairs(33), &mut heap).unwrap();
    let mut tiny = arinsal_term::ProcessHeap::with_words(1);
    let result = put(large_key, small(34), small(34), &mut tiny);
    assert!(matches!(result, Err(MapError::HeapFull { need_words: _ })));
    assert_eq!(tiny.used_words(), 0);
    let nested = from_pairs(&[(large_key, small(1))], &mut heap).unwrap();
    assert_eq!(get(nested, large_key), Ok(Some(small(1))));
}

#[test]
fn no_op_updates_and_empty_merge_preserve_map_identity() {
    let mut heap = VecHeap::new();
    let map = from_pairs(&pairs(4), &mut heap).unwrap();
    let empty = from_pairs(&[], &mut heap).unwrap();
    let unchanged = put_many(map, &[(small(2), small(2))], false, &mut heap).unwrap();
    assert_eq!(unchanged, map);
    assert_eq!(merge(empty, map, &mut heap).unwrap(), map);
    assert_eq!(merge(map, empty, &mut heap).unwrap(), map);
}

#[test]
fn merge_reuses_a_containing_map_or_its_key_tuple() {
    let mut heap = VecHeap::new();
    let left = from_pairs(&[(small(1), small(10)), (small(2), small(20))], &mut heap).unwrap();
    let right_subset = from_pairs(&[(small(2), small(22))], &mut heap).unwrap();
    let merged = merge(left, right_subset, &mut heap).unwrap();
    assert_eq!(merged.flatmap_keys_tuple(), left.flatmap_keys_tuple());
    assert_eq!(get(merged, small(2)), Ok(Some(small(22))));

    let right = from_pairs(
        &[
            (small(1), small(11)),
            (small(2), small(21)),
            (small(3), small(31)),
        ],
        &mut heap,
    )
    .unwrap();
    let left_subset = from_pairs(&[(small(2), small(200))], &mut heap).unwrap();
    assert_eq!(merge(left_subset, right, &mut heap), Ok(right));
}

#[test]
fn equal_key_merge_mutates_the_heap_map_to_use_literal_keys() {
    let source_pairs = [(small(1), small(10)), (small(2), small(20))];
    let mut source_heap = VecHeap::new();
    let source = from_pairs(&source_pairs, &mut source_heap).unwrap();
    let mut literals = LiteralArea::new();
    let literal_map = literals.copy_from(source).unwrap();
    let literal_keys = literal_map.flatmap_keys_tuple().unwrap();

    let mut heap = VecHeap::new();
    let right = from_pairs(&[(small(1), small(11)), (small(2), small(21))], &mut heap).unwrap();
    assert!(!right.flatmap_keys_tuple().unwrap().is_literal());

    let merged = merge(literal_map, right, &mut heap).unwrap();
    assert_eq!(merged, right);
    assert_eq!(merged.flatmap_keys_tuple(), Some(literal_keys));
}

#[test]
fn exact_multi_update_reports_the_first_sorted_missing_key() {
    let mut heap = VecHeap::new();
    let map = from_pairs(&[], &mut heap).unwrap();
    let float = arinsal_term::TermBuilder::new(&mut heap)
        .float(42.0)
        .unwrap();
    let result = put_many(
        map,
        &[(float, small(1)), (small(42), small(2))],
        true,
        &mut heap,
    );
    assert_eq!(result, Err(MapError::Badkey(small(42))));
}

#[test]
fn builder_preserves_last_duplicate() {
    let mut heap = VecHeap::new();
    let mut builder = arinsal_term::TermBuilder::new(&mut heap);
    let map = builder
        .flatmap_from_pairs(&[
            (small(1), small(8)),
            (small(2), small(2)),
            (small(1), small(9)),
        ])
        .unwrap();
    assert_eq!(get(map, small(1)), Ok(Some(small(9))));
    let zero = builder.float(0.0).unwrap();
    let nested_int = builder.tuple(&[small(2)]).unwrap();
    let nested_float = builder.tuple(&[zero]).unwrap();
    let map = builder
        .flatmap_from_pairs(&[
            (zero, small(1)),
            (small(2), small(2)),
            (nested_float, small(3)),
            (nested_int, small(4)),
        ])
        .unwrap();
    let ordered: Vec<_> = iter(map)
        .unwrap()
        .map(|(_, v)| v.as_small().unwrap())
        .collect();
    assert_eq!(ordered, vec![2, 1, 4, 3]);
}

fn reference_terms(eval: &str) -> Option<arinsal_etf::OwnedTerm> {
    let output = match Command::new("erl")
        .args(["-noshell", "-eval", eval])
        .output()
    {
        Ok(output) => output,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            eprintln!("skipping differential test: erl not found");
            return None;
        }
        Err(e) => panic!("erl failed: {e}"),
    };
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let hex = String::from_utf8(output.stdout).unwrap();
    let hex = hex.trim().as_bytes();
    let bytes: Vec<_> = hex
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect();
    Some(arinsal_etf::decode(&bytes).unwrap())
}

#[test]
fn differential_aliases_survive_existing_key_replacement() {
    use arinsal_etf::OwnedTerm as O;
    for n in [32, 33, 1000] {
        let eval = format!(
            "M0=maps:from_list([{{K,0}}||K<-lists:seq(1,{n})]),T={{M0}},F=fun()->M0 end,M1=maps:put(1,7,M0),M2=maps:put({n},9,M1),io:put_chars(binary:encode_hex(term_to_binary({{maps:get(1,M0),maps:get(1,element(1,T)),maps:get(1,F()),maps:get(1,M1),maps:get({n},M1),maps:get({n},M2)}}))),halt()."
        );
        let Some(expected) = reference_terms(&eval) else {
            return;
        };
        let mut heap = VecHeap::new();
        let entries: Vec<_> = (1..=n).map(|key| (small(key), small(0))).collect();
        let old = from_pairs(&entries, &mut heap).unwrap();
        let tuple_alias = arinsal_term::TermBuilder::new(&mut heap)
            .tuple(&[old])
            .unwrap();
        let fun_capture = old;
        let first = put(old, small(1), small(7), &mut heap).unwrap();
        let second = put(first, small(n), small(9), &mut heap).unwrap();
        // SAFETY: the tuple alias remains in the live VecHeap.
        let tuple_map = unsafe { tuple_alias.tuple_ref().unwrap().get(0).unwrap() };
        let actual = O::tuple(
            [
                get(old, small(1)).unwrap().unwrap(),
                get(tuple_map, small(1)).unwrap().unwrap(),
                get(fun_capture, small(1)).unwrap().unwrap(),
                get(first, small(1)).unwrap().unwrap(),
                get(first, small(n)).unwrap().unwrap(),
                get(second, small(n)).unwrap().unwrap(),
            ]
            .into_iter()
            .map(|value| O::Int(value.as_small().unwrap()))
            .collect(),
        );
        assert_eq!(actual, expected, "n={n}");
    }
}

#[test]
fn differential_mixed_flatmap_keys() {
    use arinsal_etf::OwnedTerm as O;
    let eval = "Keys=[list_to_atom(\"zzzz_s15c_unique\"),list_to_atom(\"aaaa_s15c_unique\"),1,1.0,0.0,-0.0,{1},[1],<<1>>],M=maps:from_list(lists:zip(Keys,lists:seq(1,length(Keys)))),io:put_chars(binary:encode_hex(term_to_binary(maps:to_list(M)))),halt().";
    let Some(expected) = reference_terms(eval) else {
        return;
    };
    let keys = [
        O::atom("zzzz_s15c_unique"),
        O::atom("aaaa_s15c_unique"),
        O::Int(1),
        O::Float(1.0),
        O::Float(0.0),
        O::Float(-0.0),
        O::tuple(vec![O::Int(1)]),
        O::list(vec![O::Int(1)]),
        O::Binary(vec![1]),
    ];
    let mut heap = VecHeap::new();
    let pairs: Vec<_> = keys
        .iter()
        .enumerate()
        .map(|(i, key)| {
            (
                arinsal_term::from_owned(key, &mut heap).unwrap(),
                small(i as i64 + 1),
            )
        })
        .collect();
    let map = from_pairs(&pairs, &mut heap).unwrap();
    let actual = O::list(
        iter(map)
            .unwrap()
            .map(|(k, v)| {
                O::tuple(vec![
                    arinsal_term::to_owned(k).unwrap(),
                    arinsal_term::to_owned(v).unwrap(),
                ])
            })
            .collect(),
    );
    assert_eq!(format!("{actual:?}"), format!("{expected:?}"));
}

#[test]
fn differential_random_integer_updates() {
    let mut state = 0x1234_5678_u64;
    let mut operations = Vec::new();
    for _ in 0..400 {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let key = (state % 95) as i64;
        let value = (state >> 16) as i64 % 10000;
        operations.push((key, value, state & 7 == 0));
    }
    let source = operations
        .iter()
        .map(|(key, value, remove)| {
            if *remove {
                format!("{{remove,{key},0}}")
            } else {
                format!("{{put,{key},{value}}}")
            }
        })
        .collect::<Vec<_>>()
        .join(",");
    let eval = format!(
        "Ops=[{source}],M=lists:foldl(fun({{remove,K,_}},A)->maps:remove(K,A);({{put,K,V}},A)->maps:put(K,V,A) end,#{{}},Ops),io:put_chars(binary:encode_hex(term_to_binary({{maps:to_list(M),erts_debug:flat_size(M)}}))),halt()."
    );
    let Some(expected) = reference_terms(&eval) else {
        return;
    };
    let mut heap = VecHeap::new();
    let mut map = from_pairs(&[], &mut heap).unwrap();
    for (key, value, is_remove) in operations {
        map = if is_remove {
            remove(map, small(key), &mut heap).unwrap()
        } else {
            put(map, small(key), small(value), &mut heap).unwrap()
        };
    }
    let actual = arinsal_etf::OwnedTerm::list(
        iter(map)
            .unwrap()
            .map(|(k, v)| {
                arinsal_etf::OwnedTerm::tuple(vec![
                    arinsal_etf::OwnedTerm::Int(k.as_small().unwrap()),
                    arinsal_etf::OwnedTerm::Int(v.as_small().unwrap()),
                ])
            })
            .collect(),
    );
    if let arinsal_etf::OwnedTerm::Tuple(parts) = &expected {
        assert_eq!(actual, parts[0]);
        assert_eq!(arinsal_etf::OwnedTerm::Int(map_words(map) as i64), parts[1]);
    } else {
        panic!("reference returned unexpected term");
    }
}

#[test]
fn iterator_protocol() {
    use arinsal_maps::{iterator_term, iterator_term_reversed, next_term};
    for n in [0, 2, 32, 33, 100] {
        let mut heap = VecHeap::new();
        let map = from_pairs(&pairs(n), &mut heap).unwrap();
        for ordered in [false, true] {
            let mut cursor = iterator_term(map, ordered, &mut heap).unwrap();
            // SAFETY: iterator and map live in heap throughout the loop.
            let (path, tail) = unsafe { cursor.cons_ref().unwrap() };
            assert_eq!(tail, map);
            if !ordered {
                assert_eq!(path.as_small(), Some(0));
            }
            let mut observed = Vec::new();
            loop {
                let next = next_term(cursor, &mut heap).unwrap();
                if next.classify() == arinsal_term::TermKind::Atom {
                    break;
                }
                // SAFETY: next_term returns a live three-element tuple.
                let tuple = unsafe { next.tuple_ref().unwrap() };
                observed.push(tuple.get(0).unwrap().as_small().unwrap());
                cursor = tuple.get(2).unwrap();
            }
            let mut expected: Vec<_> = iter(map)
                .unwrap()
                .map(|(k, _)| k.as_small().unwrap())
                .collect();
            if ordered {
                expected.sort();
            }
            assert_eq!(observed, expected, "n={n}, ordered={ordered}");
        }
        let mut cursor = iterator_term_reversed(map, &mut heap).unwrap();
        let mut reversed = Vec::new();
        loop {
            let next = next_term(cursor, &mut heap).unwrap();
            if next.classify() == arinsal_term::TermKind::Atom {
                break;
            }
            // SAFETY: next_term returns a live three-element tuple.
            let tuple = unsafe { next.tuple_ref().unwrap() };
            reversed.push(tuple.get(0).unwrap().as_small().unwrap());
            cursor = tuple.get(2).unwrap();
        }
        assert_eq!(reversed, (1..=n as i64).rev().collect::<Vec<_>>());
    }
}

#[test]
fn differential_mixed_hamt_keys() {
    use arinsal_etf::OwnedTerm as O;
    let eval = "Keys=lists:seq(1,40)++[1.0,0.0,-0.0,{1},[1],binary:copy(<<1>>)],M=maps:from_list(lists:zip(Keys,lists:seq(1,length(Keys)))),io:put_chars(binary:encode_hex(term_to_binary({maps:to_list(M),erts_debug:flat_size(M)}))),halt().";
    let Some(expected) = reference_terms(eval) else {
        return;
    };
    let mut keys: Vec<_> = (1..=40).map(O::Int).collect();
    keys.extend([
        O::Float(1.0),
        O::Float(0.0),
        O::Float(-0.0),
        O::tuple(vec![O::Int(1)]),
        O::list(vec![O::Int(1)]),
        O::Binary(vec![1]),
    ]);
    let mut heap = VecHeap::new();
    let pairs: Vec<_> = keys
        .iter()
        .enumerate()
        .map(|(i, key)| {
            (
                arinsal_term::from_owned(key, &mut heap).unwrap(),
                small(i as i64 + 1),
            )
        })
        .collect();
    let map = from_pairs(&pairs, &mut heap).unwrap();
    assert!(map.is_hashmap());
    let actual = O::list(
        iter(map)
            .unwrap()
            .map(|(k, v)| {
                O::tuple(vec![
                    arinsal_term::to_owned(k).unwrap(),
                    arinsal_term::to_owned(v).unwrap(),
                ])
            })
            .collect(),
    );
    if let O::Tuple(parts) = &expected {
        assert_eq!(format!("{actual:?}"), format!("{:?}", parts[0]));
        let nested: usize = pairs
            .iter()
            .map(|(k, v)| arinsal_term::flat_size(*k) + arinsal_term::flat_size(*v))
            .sum();
        assert_eq!(
            O::Int((map_words(map) + nested) as i64),
            parts[1],
            "map_words={}, nested={nested}",
            map_words(map)
        );
    } else {
        panic!("reference returned unexpected term");
    }
}

#[test]
fn differential_map_keys_500_cases() {
    use arinsal_etf::OwnedTerm as O;

    let eval = "Results=[begin L=maps:from_list([{J,I*1000+J}||J<-lists:seq(1,40)]),S=#{case_key=>I},M1=maps:put(L,I,#{}),V1=maps:get(L,M1),M2=maps:put(S,I+1,M1),V2=maps:get(S,M2),M3=maps:remove(L,M2),{V1,V2,maps:to_list(M3),maps:is_key(L,M3)} end||I<-lists:seq(1,500)],io:put_chars(binary:encode_hex(term_to_binary(Results))),halt().";
    let Some(expected) = reference_terms(eval) else {
        return;
    };

    let mut heap = VecHeap::new();
    let mut actual = Vec::with_capacity(500);
    for i in 1..=500_i64 {
        let large_owned = O::Map(
            (1..=40_i64)
                .map(|j| (O::Int(j), O::Int(i * 1000 + j)))
                .collect(),
        );
        let small_owned = O::Map(vec![(O::atom("case_key"), O::Int(i))]);
        let large = arinsal_term::from_owned(&large_owned, &mut heap).unwrap();
        let small_key = arinsal_term::from_owned(&small_owned, &mut heap).unwrap();
        assert!(large.is_hashmap());

        let empty = from_pairs(&[], &mut heap).unwrap();
        let one = put(empty, large, small(i), &mut heap).unwrap();
        let first = get(one, large).unwrap().unwrap();
        let two = put(one, small_key, small(i + 1), &mut heap).unwrap();
        let second = get(two, small_key).unwrap().unwrap();
        let three = remove(two, large, &mut heap).unwrap();
        let remaining = O::list(
            iter(three)
                .unwrap()
                .map(|(key, value)| {
                    O::tuple(vec![
                        arinsal_term::to_owned(key).unwrap(),
                        arinsal_term::to_owned(value).unwrap(),
                    ])
                })
                .collect(),
        );
        let has_large = arinsal_maps::is_key(three, large).unwrap();
        actual.push(O::tuple(vec![
            arinsal_term::to_owned(first).unwrap(),
            arinsal_term::to_owned(second).unwrap(),
            remaining,
            O::atom(if has_large { "true" } else { "false" }),
        ]));
    }
    assert_eq!(O::list(actual), expected);
}

#[test]
fn predefined_atom_indices_match_otp_hashes() {
    let eval = "erts_debug:set_internal_state(available_internal_state,true),lists:foreach(fun(A)->io:format(\"~B~n\",[erts_debug:get_internal_state({internal_hash,A})]) end,[false,true,error,undefined]),halt().";
    let output = match Command::new("erl")
        .args(["-noshell", "-eval", eval])
        .output()
    {
        Ok(output) => output,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            eprintln!("skipping differential test: erl not found");
            return;
        }
        Err(e) => panic!("erl failed: {e}"),
    };
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let expected: Vec<u64> = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .filter_map(|s| s.parse().ok())
        .collect();
    let atoms = arinsal_term::global_atoms();
    let actual: Vec<_> = ["false", "true", "error", "undefined"]
        .iter()
        .map(|name| arinsal_term::internal_hash(Term::atom(atoms.get(name).unwrap())))
        .collect();
    assert_eq!(actual, expected);
}

#[test]
fn differential_error_reasons_and_helpers() {
    use arinsal_etf::OwnedTerm as O;
    let eval = "Reasons=[try maps:update(9,1,#{}) catch error:R1->R1 end,try maps:get(1,42) catch error:R2->R2 end],io:put_chars(binary:encode_hex(term_to_binary(Reasons))),halt().";
    let Some(reasons) = reference_terms(eval) else {
        return;
    };
    assert_eq!(
        reasons,
        O::list(vec![
            O::tuple(vec![O::atom("badkey"), O::Int(9)]),
            O::tuple(vec![O::atom("badmap"), O::Int(42)])
        ])
    );
    let mut heap = VecHeap::new();
    let empty = from_pairs(&[], &mut heap).unwrap();
    assert_eq!(
        update(empty, small(9), small(1), &mut heap),
        Err(MapError::Badkey(small(9)))
    );
    assert_eq!(get(small(42), small(1)), Err(MapError::Badmap(small(42))));
    let left = from_pairs(&[(small(1), small(1)), (small(2), small(2))], &mut heap).unwrap();
    let right = from_pairs(&[(small(1), small(9)), (small(3), small(3))], &mut heap).unwrap();
    let merged = arinsal_maps::merge(left, right, &mut heap).unwrap();
    assert_eq!(
        arinsal_maps::to_list(merged).unwrap(),
        vec![
            (small(1), small(9)),
            (small(2), small(2)),
            (small(3), small(3))
        ]
    );
    assert_eq!(
        arinsal_maps::get_many(merged, &[small(1), small(7)]).unwrap(),
        vec![Some(small(9)), None]
    );
    assert_eq!(
        arinsal_maps::put_many(
            left,
            &[(small(1), small(3)), (small(3), small(4))],
            true,
            &mut heap
        ),
        Err(MapError::Badkey(small(3)))
    );
    let made =
        arinsal_maps::from_keys(&[small(2), small(1), small(2)], small(5), &mut heap).unwrap();
    assert_eq!(
        arinsal_maps::to_list(made).unwrap(),
        vec![(small(1), small(5)), (small(2), small(5))]
    );
}

#[test]
fn differential_flat_iterator_term_shape() {
    use arinsal_maps::{iterator_term, next_term};
    let eval = "M=maps:from_list([{1,10},{2,20}]),I=maps:iterator(M),O=maps:iterator(M,ordered),io:put_chars(binary:encode_hex(term_to_binary({I,maps:next(I),O,maps:next(O)}))),halt().";
    let Some(expected) = reference_terms(eval) else {
        return;
    };
    let mut heap = VecHeap::new();
    let map = from_pairs(&[(small(1), small(10)), (small(2), small(20))], &mut heap).unwrap();
    let native = iterator_term(map, false, &mut heap).unwrap();
    let ordered = iterator_term(map, true, &mut heap).unwrap();
    let native_next = next_term(native, &mut heap).unwrap();
    let ordered_next = next_term(ordered, &mut heap).unwrap();
    let actual = arinsal_etf::OwnedTerm::tuple(
        [native, native_next, ordered, ordered_next]
            .into_iter()
            .map(|t| arinsal_term::to_owned(t).unwrap())
            .collect(),
    );
    assert_eq!(format!("{actual:?}"), format!("{expected:?}"));
}

#[test]
fn differential_predefined_atoms_and_map_key_in_hamt() {
    use arinsal_etf::OwnedTerm as O;
    let eval = "Keys=lists:seq(1,40)++[false,true,error,undefined,#{false=>1}],M=maps:from_list(lists:zip(Keys,lists:seq(1,length(Keys)))),io:put_chars(binary:encode_hex(term_to_binary(maps:to_list(M)))),halt().";
    let Some(expected) = reference_terms(eval) else {
        return;
    };
    let mut keys: Vec<_> = (1..=40).map(O::Int).collect();
    keys.extend([
        O::atom("false"),
        O::atom("true"),
        O::atom("error"),
        O::atom("undefined"),
        O::Map(vec![(O::atom("false"), O::Int(1))]),
    ]);
    let mut heap = VecHeap::new();
    let pairs: Vec<_> = keys
        .iter()
        .enumerate()
        .map(|(i, key)| {
            (
                arinsal_term::from_owned(key, &mut heap).unwrap(),
                small(i as i64 + 1),
            )
        })
        .collect();
    let map = from_pairs(&pairs, &mut heap).unwrap();
    let actual = O::list(
        iter(map)
            .unwrap()
            .map(|(k, v)| {
                O::tuple(vec![
                    arinsal_term::to_owned(k).unwrap(),
                    arinsal_term::to_owned(v).unwrap(),
                ])
            })
            .collect(),
    );
    assert_eq!(format!("{actual:?}"), format!("{expected:?}"));
}

#[test]
fn differential_generated_flatmaps() {
    use arinsal_etf::OwnedTerm as O;
    use proptest::strategy::{Strategy, ValueTree};
    let mut runner = proptest::test_runner::TestRunner::deterministic();
    let strategy = arinsal_difftest::gens::any_term();
    for n in [0, 4, 16] {
        let keys: Vec<_> = (0..n)
            .map(|_| strategy.new_tree(&mut runner).unwrap().current())
            .collect();
        let encoded = arinsal_etf::encode(
            &O::list(keys.clone()),
            arinsal_etf::EncodeOptions::default(),
        );
        let hex = encoded
            .iter()
            .map(|byte| format!("{byte:02X}"))
            .collect::<String>();
        let eval = format!(
            "Keys=binary_to_term(binary:decode_hex(<<\"{hex}\">>)),M=maps:from_list(lists:zip(Keys,lists:seq(1,length(Keys)))),io:put_chars(binary:encode_hex(term_to_binary(maps:to_list(M)))),halt()."
        );
        let Some(expected) = reference_terms(&eval) else {
            return;
        };
        let mut heap = VecHeap::new();
        let pairs: Vec<_> = keys
            .iter()
            .enumerate()
            .map(|(i, key)| {
                (
                    arinsal_term::from_owned(key, &mut heap).unwrap(),
                    small(i as i64 + 1),
                )
            })
            .collect();
        let map = from_pairs(&pairs, &mut heap).unwrap();
        let actual = O::list(
            iter(map)
                .unwrap()
                .map(|(k, v)| {
                    O::tuple(vec![
                        arinsal_term::to_owned(k).unwrap(),
                        arinsal_term::to_owned(v).unwrap(),
                    ])
                })
                .collect(),
        );
        let normalized = arinsal_etf::decode(&arinsal_etf::encode(
            &actual,
            arinsal_etf::EncodeOptions::default(),
        ))
        .unwrap();
        assert_eq!(format!("{normalized:?}"), format!("{expected:?}"), "n={n}");
    }
}

#[test]
fn differential_generated_hamt_keys() {
    use arinsal_etf::OwnedTerm as O;
    use proptest::strategy::{Strategy, ValueTree};
    let mut runner = proptest::test_runner::TestRunner::deterministic();
    let numbers = arinsal_difftest::gens::integer();
    let floats = arinsal_difftest::gens::float();
    let binaries = arinsal_difftest::gens::binary();
    let keys: Vec<O> = (0..60)
        .map(|i| match i % 5 {
            0 => numbers.new_tree(&mut runner).unwrap().current(),
            1 => floats.new_tree(&mut runner).unwrap().current(),
            2 => binaries.new_tree(&mut runner).unwrap().current(),
            3 => O::tuple(vec![
                numbers.new_tree(&mut runner).unwrap().current(),
                O::Int(i),
            ]),
            _ => O::list(vec![
                floats.new_tree(&mut runner).unwrap().current(),
                O::Int(i),
            ]),
        })
        .collect();
    let encoded = arinsal_etf::encode(
        &O::list(keys.clone()),
        arinsal_etf::EncodeOptions::default(),
    );
    let hex = encoded
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<String>();
    let eval = format!(
        "Keys=binary_to_term(binary:decode_hex(<<\"{hex}\">>)),M=maps:from_list(lists:zip(Keys,lists:seq(1,length(Keys)))),io:put_chars(binary:encode_hex(term_to_binary(maps:to_list(M)))),halt()."
    );
    let Some(expected) = reference_terms(&eval) else {
        return;
    };
    let mut heap = VecHeap::new();
    let pairs: Vec<_> = keys
        .iter()
        .enumerate()
        .map(|(i, key)| {
            (
                arinsal_term::from_owned(key, &mut heap).unwrap(),
                small(i as i64 + 1),
            )
        })
        .collect();
    let map = from_pairs(&pairs, &mut heap).unwrap();
    assert!(map.is_hashmap());
    let actual = O::list(
        iter(map)
            .unwrap()
            .map(|(k, v)| {
                O::tuple(vec![
                    arinsal_term::to_owned(k).unwrap(),
                    arinsal_term::to_owned(v).unwrap(),
                ])
            })
            .collect(),
    );
    let normalized = arinsal_etf::decode(&arinsal_etf::encode(
        &actual,
        arinsal_etf::EncodeOptions::default(),
    ))
    .unwrap();
    assert_eq!(format!("{normalized:?}"), format!("{expected:?}"));
}

#[test]
fn differential_term_to_binary_integer_maps() {
    use arinsal_etf::OwnedTerm as O;
    for n in [0, 32, 33, 100] {
        let eval = format!(
            "M=maps:from_list([{{I,I}}||I<-lists:seq(1,{n})]),io:put_chars(binary:encode_hex(term_to_binary(M))),halt()."
        );
        let output = match Command::new("erl")
            .args(["-noshell", "-eval", &eval])
            .output()
        {
            Ok(output) => output,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                eprintln!("skipping differential test: erl not found");
                return;
            }
            Err(e) => panic!("erl failed: {e}"),
        };
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let hex = String::from_utf8(output.stdout).unwrap();
        let expected: Vec<_> = hex
            .trim()
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect();
        let mut heap = VecHeap::new();
        let map = from_pairs(&pairs(n), &mut heap).unwrap();
        let owned = O::Map(
            arinsal_maps::term_to_binary_pairs(map)
                .unwrap()
                .into_iter()
                .map(|(k, v)| (O::Int(k.as_small().unwrap()), O::Int(v.as_small().unwrap())))
                .collect(),
        );
        let actual = arinsal_etf::encode(&owned, arinsal_etf::EncodeOptions::default());
        assert_eq!(actual, expected, "n={n}");
    }
}

#[test]
fn differential_term_to_binary_mixed_hamt() {
    use arinsal_etf::OwnedTerm as O;
    let eval = "Keys=lists:seq(1,40)++[1.0,0.0,-0.0,{1},[1],binary:copy(<<1>>)],M=maps:from_list(lists:zip(Keys,lists:seq(1,length(Keys)))),io:put_chars(binary:encode_hex(term_to_binary(M))),halt().";
    let output = match Command::new("erl")
        .args(["-noshell", "-eval", eval])
        .output()
    {
        Ok(output) => output,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            eprintln!("skipping differential test: erl not found");
            return;
        }
        Err(e) => panic!("erl failed: {e}"),
    };
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let hex = String::from_utf8(output.stdout).unwrap();
    let expected: Vec<_> = hex
        .trim()
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect();
    let mut keys: Vec<_> = (1..=40).map(O::Int).collect();
    keys.extend([
        O::Float(1.0),
        O::Float(0.0),
        O::Float(-0.0),
        O::tuple(vec![O::Int(1)]),
        O::list(vec![O::Int(1)]),
        O::Binary(vec![1]),
    ]);
    let mut heap = VecHeap::new();
    let pairs: Vec<_> = keys
        .iter()
        .enumerate()
        .map(|(i, key)| {
            (
                arinsal_term::from_owned(key, &mut heap).unwrap(),
                small(i as i64 + 1),
            )
        })
        .collect();
    let map = from_pairs(&pairs, &mut heap).unwrap();
    let owned = O::Map(
        arinsal_maps::term_to_binary_pairs(map)
            .unwrap()
            .into_iter()
            .map(|(k, v)| {
                (
                    arinsal_term::to_owned(k).unwrap(),
                    arinsal_term::to_owned(v).unwrap(),
                )
            })
            .collect(),
    );
    let actual = arinsal_etf::encode(&owned, arinsal_etf::EncodeOptions::default());
    assert_eq!(actual, expected);
}
