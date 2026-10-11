#[cfg(not(miri))]
use arinsal_etf::OwnedTerm;
use arinsal_term::{
    Term, TermBuilder, TermKind, VecHeap, boxed_object_words, build_hamt_from_unique, copy_term,
    exact_eq, from_owned, internal_hash, size_object, to_owned,
};
#[cfg(not(miri))]
use arinsal_term::{cmp, loose_eq, make_hash2, phash};
#[cfg(not(miri))]
use std::process::Command;

#[cfg(not(miri))]
fn key(index: usize, builder: &mut TermBuilder<'_, VecHeap>) -> Term {
    let n = index as i64;
    match index % 6 {
        0 => Term::small(n + 100_000).unwrap(),
        1 => builder.float(n as f64 + 0.5).unwrap(),
        2 => builder.tuple(&[Term::small(n).unwrap()]).unwrap(),
        3 => builder.list_from_iter([Term::small(n).unwrap()]).unwrap(),
        4 => builder.binary(&(index as u32).to_be_bytes()).unwrap(),
        _ => Term::small(-n - 1).unwrap(),
    }
}

#[cfg(not(miri))]
fn count(case: usize) -> usize {
    match case % 991 {
        0 => 0,
        1 => 1,
        2 => 32,
        3 => 33,
        4 => 2_000,
        _ if case.is_multiple_of(20) => 33 + (case * 7_919 % 1_968),
        _ => 33 + (case * 37 % 112),
    }
}

fn node_shapes(map: Term) -> Vec<(u64, Vec<u8>)> {
    if !map.is_hashmap() {
        return Vec::new();
    }
    let mut result = Vec::new();
    let mut stack = vec![map];
    while let Some(node) = stack.pop() {
        let header = node.header().unwrap();
        // SAFETY: the map or collision tuple is live for this call.
        let ptr = unsafe { node.raw_ptr() };
        // SAFETY: the header and all node payload words are initialized.
        let words = unsafe { boxed_object_words(header, ptr) };
        let start = if node.classify() == TermKind::Tuple || (header >> 6) & 3 == 1 {
            1
        } else {
            2
        };
        let mut children = Vec::new();
        for i in start..words {
            // SAFETY: i indexes an initialized tagged term; Term is transparent over u64.
            let child = unsafe { std::mem::transmute::<u64, Term>(*ptr.add(i)) };
            match child.classify() {
                TermKind::List => children.push(0),
                TermKind::Map => {
                    children.push(1);
                    stack.push(child);
                }
                TermKind::Tuple => {
                    children.push(2);
                    stack.push(child);
                }
                other => panic!("unexpected HAMT child {other:?}"),
            }
        }
        result.push((header, children));
    }
    result
}

#[test]
#[cfg(not(miri))]
fn differential_5000_mixed_maps() {
    let expression = r#"erts_debug:set_internal_state(available_internal_state,true),
        F=fun(I)->case I rem 6 of
          0->I+100000; 1->I+0.5; 2->{I}; 3->[I];
          4->binary:copy(<<I:32>>); 5->-I-1 end end,
        N=fun(C)->case C rem 991 of
          0->0; 1->1; 2->32; 3->33; 4->2000;
          _->case C rem 20 of
            0->33+(C*7919 rem 1968);
            _->33+(C*37 rem 112) end end end,
        Cmp=fun(A,B)->if A<B->0; A>B->2; true->1 end end,
        lists:foreach(fun(C)->
          Num=case N(C)>32 of true->N(C)-2; false->N(C) end,
          P=[{F((I*37+C*977) rem 5000),I*3-C}||I<-lists:seq(0,Num-1)],
          Prefix=case N(C)>32 of true->[{1,17},{1.0,19}]; false->[] end,
          M=maps:from_list(Prefix++P),
          M2=maps:put(1.0,C,M),
          M3=maps:remove(1.0,maps:put(2.0,C,M)),
          Flat=#{1=>17,1.0=>19},
          io:format("~B ~B ~B ~B ~B ~B ~B ~B ~B ~B~n",[
            erlang:phash2(M,4294967296),
            erlang:phash(M,4294967296),
            erts_debug:get_internal_state({internal_hash,M}),
            erts_debug:flat_size(M),
            erlang:phash2(maps:to_list(M),4294967296),
            Cmp(M,M2),Cmp(M,M3),Cmp(M,Flat),
            if M==M2->1; true->0 end,
            if M=:=M2->1; true->0 end])
        end,lists:seq(0,4999)),halt()."#;
    let output = match Command::new("erl")
        .args(["-noshell", "-eval", expression])
        .output()
    {
        Ok(output) => output,
        Err(_) => {
            eprintln!("skipping differential_5000_mixed_maps: erl unavailable");
            return;
        }
    };
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let reference = String::from_utf8(output.stdout).unwrap();
    let rows = reference
        .lines()
        .filter_map(|line| {
            let numbers = line
                .split_whitespace()
                .map(str::parse::<u64>)
                .collect::<Result<Vec<_>, _>>()
                .ok()?;
            (numbers.len() == 10).then_some(numbers)
        })
        .collect::<Vec<_>>();
    assert_eq!(
        rows.len(),
        5_000,
        "erl output: {}",
        &reference[..reference.len().min(500)]
    );
    for (case, expected) in rows.iter().enumerate() {
        let mut heap = VecHeap::new();
        let mut builder = TermBuilder::new(&mut heap);
        let mut pairs = Vec::new();
        let float_one = builder.float(1.0).unwrap();
        if count(case) > 32 {
            pairs.push((Term::small(1).unwrap(), Term::small(17).unwrap()));
            pairs.push((float_one, Term::small(19).unwrap()));
        }
        let generated = if count(case) > 32 {
            count(case) - 2
        } else {
            count(case)
        };
        for index in 0..generated {
            let key_index = (index * 37 + case * 977) % 5_000;
            pairs.push((
                key(key_index, &mut builder),
                Term::small(index as i64 * 3 - case as i64).unwrap(),
            ));
        }
        let map = builder.flatmap_from_pairs(&pairs).unwrap();
        let owned_map = to_owned(map).unwrap();
        let OwnedTerm::Map(entries) = &owned_map else {
            unreachable!()
        };
        let ordered_owned = OwnedTerm::List {
            elems: entries
                .iter()
                .map(|(key, value)| OwnedTerm::Tuple(vec![key.clone(), value.clone()]))
                .collect(),
            tail: Box::new(OwnedTerm::Nil),
        };
        let mut ordered_heap = VecHeap::new();
        let ordered = from_owned(&ordered_owned, &mut ordered_heap).unwrap();
        assert_eq!(
            [
                make_hash2(map) as u64,
                phash(map, 1_u64 << 32).unwrap(),
                internal_hash(map),
                size_object(map) as u64,
                make_hash2(ordered) as u64
            ],
            &expected[..5],
            "case {case}, count {}",
            count(case)
        );
        let mut changed = pairs.clone();
        changed.push((float_one, Term::small(case as i64).unwrap()));
        let changed_map = builder.flatmap_from_pairs(&changed).unwrap();
        changed.retain(|(key, _)| !exact_eq(*key, float_one));
        changed.push((
            builder.float(2.0).unwrap(),
            Term::small(case as i64).unwrap(),
        ));
        let changed_key_map = builder.flatmap_from_pairs(&changed).unwrap();
        let flat = builder
            .flatmap_from_pairs(&[
                (Term::small(1).unwrap(), Term::small(17).unwrap()),
                (float_one, Term::small(19).unwrap()),
            ])
            .unwrap();
        let sign = |order: std::cmp::Ordering| match order {
            std::cmp::Ordering::Less => 0,
            std::cmp::Ordering::Equal => 1,
            std::cmp::Ordering::Greater => 2,
        };
        assert_eq!(
            [
                sign(cmp(map, changed_map)),
                sign(cmp(map, changed_key_map)),
                sign(cmp(map, flat)),
                u64::from(loose_eq(map, changed_map)),
                u64::from(exact_eq(map, changed_map)),
            ],
            expected[5..],
            "map comparison case {case}"
        );
        let mut copied_heap = VecHeap::new();
        let copied = copy_term(map, &mut copied_heap).unwrap();
        assert!(exact_eq(map, copied), "copy case {case}");
        assert_eq!(
            node_shapes(map),
            node_shapes(copied),
            "copy shape case {case}"
        );
        assert_eq!(
            size_object(map),
            copied_heap.used_words(),
            "copy size case {case}"
        );
        assert_eq!(
            to_owned(copied).unwrap(),
            owned_map.clone(),
            "copy order case {case}"
        );
        let mut rebuilt_heap = VecHeap::new();
        let rebuilt = from_owned(&owned_map, &mut rebuilt_heap).unwrap();
        assert!(exact_eq(map, rebuilt), "owned case {case}");
        assert_eq!(
            internal_hash(map),
            internal_hash(rebuilt),
            "owned structure case {case}"
        );
        assert_eq!(
            cmp(map, rebuilt),
            std::cmp::Ordering::Equal,
            "compare case {case}"
        );
    }
}

#[test]
fn nested_hamt_key_and_value() {
    let mut heap = VecHeap::new();
    let mut builder = TermBuilder::new(&mut heap);
    let inner_pairs = (1..=40)
        .map(|n| (Term::small(n).unwrap(), Term::small(n).unwrap()))
        .collect::<Vec<_>>();
    let inner = builder.flatmap_from_pairs(&inner_pairs).unwrap();
    let mut outer_pairs = inner_pairs.clone();
    outer_pairs.push((inner, inner));
    let outer = builder.flatmap_from_pairs(&outer_pairs).unwrap();
    assert!(inner.is_hashmap() && outer.is_hashmap());
    let mut copy_heap = VecHeap::new();
    let copy = copy_term(outer, &mut copy_heap).unwrap();
    assert_eq!(size_object(outer), copy_heap.used_words());
    assert_eq!(node_shapes(outer), node_shapes(copy));
    assert!(exact_eq(outer, copy));
    let owned = to_owned(outer).unwrap();
    let mut owned_heap = VecHeap::new();
    let rebuilt = from_owned(&owned, &mut owned_heap).unwrap();
    assert!(exact_eq(outer, rebuilt));
    assert_eq!(internal_hash(outer), internal_hash(rebuilt));

    #[cfg(not(miri))]
    {
        let expression = "erts_debug:set_internal_state(available_internal_state,true),I=maps:from_list([{N,N}||N<-lists:seq(1,40)]),O=maps:from_list([{N,N}||N<-lists:seq(1,40)]++[{I,I}]),io:format(\"~B ~B ~B ~B~n\",[erlang:phash2(O,4294967296),erlang:phash(O,4294967296),erts_debug:get_internal_state({internal_hash,O}),erts_debug:flat_size(O)]),halt().";
        let output = match Command::new("erl")
            .args(["-noshell", "-eval", expression])
            .output()
        {
            Ok(output) => output,
            Err(_) => {
                eprintln!("skipping nested HAMT differential: erl unavailable");
                return;
            }
        };
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let expected = String::from_utf8(output.stdout).unwrap();
        let expected = expected
            .lines()
            .find_map(|line| {
                let values = line
                    .split_whitespace()
                    .map(str::parse::<u64>)
                    .collect::<Result<Vec<_>, _>>()
                    .ok()?;
                (values.len() == 4).then_some(values)
            })
            .unwrap();
        assert_eq!(
            [
                make_hash2(outer) as u64,
                phash(outer, 1_u64 << 32).unwrap(),
                internal_hash(outer),
                size_object(outer) as u64,
            ],
            expected.as_slice()
        );
    }
}

#[test]
fn gc_boxed_word_counts_cover_all_subtags() {
    let mut object = [0_u64; 32];
    let ordinary = [
        (0x00, 4), // tuple or collision tuple
        (0x08, 4), // positive bignum
        (0x0c, 4), // negative bignum
        (0x10, 4), // local ref
        (0x18, 4), // float
        (0x1c, 4), // record
        (0x20, 4), // heap bits
        (0x24, 4), // sub bits, including match/writable base flags
        (0x28, 4), // bin ref
        (0x30, 4), // external pid
        (0x34, 4), // external port
        (0x38, 4), // external ref
    ];
    for (tag, words) in ordinary {
        let header = ((words - 1) << 6) | tag;
        object[0] = header;
        object[1] = 3; // SubBits flags live in the base pointer, not the header.
        // SAFETY: all four synthetic words are initialized and in bounds.
        let actual = unsafe { boxed_object_words(header, object.as_ptr()) };
        assert_eq!(actual, words as usize);
    }
    let header = 0x14 | (7 << 16);
    object[0] = header;
    // SAFETY: the synthetic fun header has seven in-bounds capture slots.
    assert_eq!(unsafe { boxed_object_words(header, object.as_ptr()) }, 9);
    object[1] = 11;
    assert_eq!(object[1], 11);
    // SAFETY: the synthetic flatmap declares eleven in-bounds values.
    // MAP_HEADER_FLATMAP is 0x12c (arity field 1); type 0 still reads the size word.
    assert_eq!(unsafe { boxed_object_words(0x12c, object.as_ptr()) }, 14);
    let bitmap = 0b1010_0000_0000_0101_u64;
    for (kind, words) in [(1, 5), (2, 18), (3, 6)] {
        let header = 0x2c | (kind << 6) | (bitmap << 16);
        // SAFETY: the synthetic HAMT node declares at most eighteen words.
        let actual = unsafe { boxed_object_words(header, object.as_ptr()) };
        assert_eq!(actual, words);
    }
}

#[test]
fn flatmap_and_hamt_with_identical_entries_compare_equal() {
    let mut heap = VecHeap::new();
    let pairs = [
        (Term::small(1).unwrap(), Term::small(17).unwrap()),
        (Term::small(2).unwrap(), Term::small(19).unwrap()),
    ];
    let flat = TermBuilder::new(&mut heap)
        .flatmap_from_pairs(&pairs)
        .unwrap();
    let hamt = build_hamt_from_unique(&pairs, &mut heap).unwrap();
    assert!(!flat.is_hashmap() && hamt.is_hashmap());
    assert!(exact_eq(flat, hamt));
    #[cfg(not(miri))]
    assert_eq!(make_hash2(flat), make_hash2(hamt));
    let mut copied_heap = VecHeap::new();
    let copied = copy_term(hamt, &mut copied_heap).unwrap();
    assert_eq!(node_shapes(hamt), node_shapes(copied));
    assert_eq!(to_owned(hamt).unwrap(), to_owned(copied).unwrap());
    assert_eq!(size_object(hamt), copied_heap.used_words());
}

/// The yielding constructor, run with a tiny budget so it yields inside every loop and sort,
/// builds the same trie as the straight-line one (hash ties are resolved by key, so the sort
/// order cannot leak into the result).
#[test]
#[cfg(not(miri))]
fn yielding_builder_matches_straight_line_builder() {
    use arinsal_term::{HashmapBuild, hashmap_key_hash, hashmap_leaves_hashed};
    for (case, n) in [33, 34, 100, 129, 700, 3_000].into_iter().enumerate() {
        for duplicates in [false, true] {
            let mut heap = VecHeap::new();
            let mut builder = TermBuilder::new(&mut heap);
            let entries: Vec<(Term, Term)> = (0..n)
                .map(|i| {
                    let k = if duplicates { i % (n / 2 + 1) } else { i };
                    (key(k + case, &mut builder), Term::small(i as i64).unwrap())
                })
                .collect();
            let mut expected_heap = VecHeap::new();
            let expected = {
                let keys: Vec<Term> = entries.iter().map(|e| e.0).collect();
                let values: Vec<Term> = entries.iter().map(|e| e.1).collect();
                arinsal_term::hashmap_from_ks_and_vs(&keys, &values, &mut expected_heap).unwrap()
            };
            let hashed: Vec<(u64, Term, Term)> = entries
                .iter()
                .map(|&(k, v)| (hashmap_key_hash(k), k, v))
                .collect();
            let mut heap = VecHeap::new();
            let mut build = HashmapBuild::new(hashmap_leaves_hashed(&hashed, &mut heap).unwrap());
            let mut yields = 0;
            let actual = loop {
                let mut reds = 7;
                if let Some(map) = build.step(&mut reds, &mut heap).unwrap() {
                    break map;
                }
                yields += 1;
            };
            assert!(yields > n / 20, "n={n} yielded {yields} times");
            assert_eq!(node_shapes(expected), node_shapes(actual), "n={n}");
            assert!(exact_eq(expected, actual), "n={n} duplicates={duplicates}");
        }
    }
}
