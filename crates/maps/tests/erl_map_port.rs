use arinsal_etf::OwnedTerm as O;
use arinsal_maps::{
    flatmap_next, from_list, from_pairs, get, iter, merge, put, remove, take, update,
};
use arinsal_term::{Term, VecHeap, internal_hash};
use std::process::Command;

fn small(value: i64) -> Term {
    Term::small(value).unwrap()
}

fn erl(eval: &str) -> O {
    let output = Command::new("erl")
        .args(["-noshell", "-eval", eval])
        .output()
        .expect("OTP 29.1.1 erl must be on PATH");
    assert!(
        output.status.success(),
        "erl failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let hex = String::from_utf8(output.stdout).unwrap();
    let bytes = hex
        .trim()
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect::<Vec<_>>();
    arinsal_etf::decode(&bytes).unwrap()
}

fn local_pairs(map: Term) -> O {
    O::list(
        iter(map)
            .unwrap()
            .map(|(key, value)| {
                O::tuple(vec![
                    arinsal_term::to_owned(key).unwrap(),
                    arinsal_term::to_owned(value).unwrap(),
                ])
            })
            .collect(),
    )
}

fn local_map(map: Term) -> O {
    O::Map(
        iter(map)
            .unwrap()
            .map(|(key, value)| {
                (
                    arinsal_term::to_owned(key).unwrap(),
                    arinsal_term::to_owned(value).unwrap(),
                )
            })
            .collect(),
    )
}

#[test]
fn to_list_order_small_vs_erl() {
    let expected = erl(
        "M=maps:from_list([{K,K*3}||K<-lists:seq(1,32)]),io:put_chars(binary:encode_hex(term_to_binary(maps:to_list(M)))),halt().",
    );
    let mut heap = VecHeap::new();
    let pairs = (1..=32)
        .map(|key| (small(key), small(key * 3)))
        .collect::<Vec<_>>();
    let map = from_pairs(&pairs, &mut heap).unwrap();
    assert_eq!(local_pairs(map), expected);
}

#[test]
fn to_list_order_large_vs_erl() {
    // Port of erts/emulator/beam/erl_map.c:764-911, OTP-29.1.1.
    let mut buckets: [Vec<i64>; 16] = std::array::from_fn(|_| Vec::new());
    for key in 0..100_000_i64 {
        let slot = (internal_hash(small(key)) & 15) as usize;
        if buckets[slot].len() < 64 {
            buckets[slot].push(key);
        }
        if buckets.iter().all(|keys| keys.len() == 64) {
            break;
        }
    }
    let keys = buckets.into_iter().flatten().take(1000).collect::<Vec<_>>();
    assert_eq!(keys.len(), 1000);
    let erl_keys = keys
        .iter()
        .map(i64::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let eval = format!(
        "Ks=[{erl_keys}],M=maps:from_list([{{K,K*2}}||K<-Ks]),io:put_chars(binary:encode_hex(term_to_binary(maps:to_list(M)))),halt()."
    );
    let expected = erl(&eval);
    let mut heap = VecHeap::new();
    let pairs = keys
        .iter()
        .map(|key| (small(*key), small(key * 2)))
        .collect::<Vec<_>>();
    let map = from_pairs(&pairs, &mut heap).unwrap();
    assert_eq!(local_pairs(map), expected);
}

#[test]
fn put_update_remove_sequences_vs_erl() {
    // Port of erts/emulator/beam/erl_map.c:2036-2234, OTP-29.1.1.
    let mut state = 0x2a83_9f17_45d1_u64;
    let mut operations = Vec::new();
    for _ in 0..10_000 {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let key = (state % 120) as i64;
        let value = ((state >> 16) % 100_000) as i64;
        let kind = (state >> 32) % 3;
        operations.push((kind, key, value));
    }
    let erl_ops = operations
        .iter()
        .map(|(kind, key, value)| format!("{{{kind},{key},{value}}}"))
        .collect::<Vec<_>>()
        .join(",");
    let eval = format!(
        "Ops=[{erl_ops}],M=lists:foldl(fun({{0,K,V}},A)->maps:put(K,V,A);({{1,K,V}},A)->case maps:is_key(K,A) of true->maps:update(K,V,A);false->A end;({{2,K,_}},A)->maps:remove(K,A) end,#{{}},Ops),io:put_chars(binary:encode_hex(term_to_binary(maps:to_list(M)))),halt()."
    );
    let expected = erl(&eval);
    let mut heap = VecHeap::new();
    let mut map = from_pairs(&[], &mut heap).unwrap();
    for (kind, key, value) in operations {
        map = match kind {
            0 => put(map, small(key), small(value), &mut heap).unwrap(),
            1 => match get(map, small(key)).unwrap() {
                Some(_) => update(map, small(key), small(value), &mut heap).unwrap(),
                None => map,
            },
            _ => remove(map, small(key), &mut heap).unwrap(),
        };
        if kind == 2 {
            let _ = iter(map).unwrap().count();
        }
    }
    assert_eq!(local_pairs(map), expected);
}

#[test]
fn merge_vs_erl() {
    // Port of erts/emulator/beam/erl_map.c:1558-1848, OTP-29.1.1.
    let expected = erl(
        "A=maps:from_list([{K,K}||K<-lists:seq(1,80)]),B=maps:from_list([{K,-K}||K<-lists:seq(41,120)]),io:put_chars(binary:encode_hex(term_to_binary(maps:to_list(maps:merge(A,B))))),halt().",
    );
    let mut heap = VecHeap::new();
    let left = (1..=80)
        .map(|key| (small(key), small(key)))
        .collect::<Vec<_>>();
    let right = (41..=120)
        .map(|key| (small(key), small(-key)))
        .collect::<Vec<_>>();
    let left = from_pairs(&left, &mut heap).unwrap();
    let right = from_pairs(&right, &mut heap).unwrap();
    assert_eq!(
        local_pairs(merge(left, right, &mut heap).unwrap()),
        expected
    );
}

#[test]
fn from_list_dups_vs_erl() {
    // Port of erts/emulator/beam/erl_map.c:3187-3240, OTP-29.1.1.
    let expected = erl(
        "P=[{1,a},{2,b},{1,c},{3,d},{2,e}],io:put_chars(binary:encode_hex(term_to_binary({maps:from_list(P),maps:to_list(maps:from_list(P))}))),halt().",
    );
    let pairs = [
        (
            small(1),
            Term::atom(arinsal_term::global_atoms().intern("a").unwrap()),
        ),
        (
            small(2),
            Term::atom(arinsal_term::global_atoms().intern("b").unwrap()),
        ),
        (
            small(1),
            Term::atom(arinsal_term::global_atoms().intern("c").unwrap()),
        ),
        (
            small(3),
            Term::atom(arinsal_term::global_atoms().intern("d").unwrap()),
        ),
        (
            small(2),
            Term::atom(arinsal_term::global_atoms().intern("e").unwrap()),
        ),
    ];
    let mut heap = VecHeap::new();
    let map = from_list(&pairs, &mut heap).unwrap();
    let actual = O::tuple(vec![arinsal_term::to_owned(map).unwrap(), local_pairs(map)]);
    assert_eq!(actual, expected);
}

#[test]
fn term_to_binary_roundtrip_vs_erl() {
    // Port of erts/emulator/beam/erl_map.c:2424-2474, OTP-29.1.1.
    let expected = erl(
        "M=maps:from_list([{K,K*5}||K<-lists:seq(1,200)]),B=term_to_binary(M),R=binary_to_term(B),io:put_chars(binary:encode_hex(term_to_binary({B,term_to_binary(R),maps:to_list(R)}))),halt().",
    );
    let mut heap = VecHeap::new();
    let pairs = (1..=200)
        .map(|key| (small(key), small(key * 5)))
        .collect::<Vec<_>>();
    let map = from_pairs(&pairs, &mut heap).unwrap();
    let encoded_order = arinsal_maps::term_to_binary_pairs(map).unwrap();
    let owned = O::Map(
        encoded_order
            .into_iter()
            .map(|(key, value)| {
                (
                    arinsal_term::to_owned(key).unwrap(),
                    arinsal_term::to_owned(value).unwrap(),
                )
            })
            .collect(),
    );
    let binary = arinsal_etf::encode(&owned, arinsal_etf::EncodeOptions::default());
    let decoded = arinsal_etf::decode(&binary).unwrap();
    assert_eq!(decoded, owned);
    let expected_parts = match &expected {
        O::Tuple(parts) => parts,
        other => panic!("unexpected erl response: {other:?}"),
    };
    assert_eq!(O::Binary(binary), expected_parts[0]);
    assert_eq!(expected_parts[0], expected_parts[1]);
}

#[test]
fn remove_take_without_and_empty_map_sizes_vs_erl() {
    // Port of erts/emulator/beam/erl_map.c:1910-2030 (erts_maps_take) and
    // 2881-3184 (hashmap_delete), OTP-29.1.1; maps:without/2 folds maps:remove/2.
    let expected = erl(
        "F=maps:from_list([{K,K*10}||K<-lists:seq(1,8)]),H=maps:from_list([{K,K*10}||K<-lists:seq(1,80)]),S=maps:from_list([{K,K*10}||K<-lists:seq(1,33)]),io:put_chars(binary:encode_hex(term_to_binary({maps:to_list(maps:remove(4,F)),{element(1,maps:take(4,F)),maps:to_list(element(2,maps:take(4,F)))},maps:to_list(maps:without([1,3,99],F)),maps:to_list(maps:remove(4,H)),maps:to_list(maps:without([1,3,99],H)),maps:to_list(maps:remove(1,S)),erts_debug:flat_size(#{}),erts_debug:size(#{}),term_to_binary(#{})}))),halt().",
    );

    let mut heap = VecHeap::new();
    let flat = from_pairs(
        &(1..=8)
            .map(|key| (small(key), small(key * 10)))
            .collect::<Vec<_>>(),
        &mut heap,
    )
    .unwrap();
    let large = from_pairs(
        &(1..=80)
            .map(|key| (small(key), small(key * 10)))
            .collect::<Vec<_>>(),
        &mut heap,
    )
    .unwrap();
    let shrinking = from_pairs(
        &(1..=33)
            .map(|key| (small(key), small(key * 10)))
            .collect::<Vec<_>>(),
        &mut heap,
    )
    .unwrap();

    let flat_remove = remove(flat, small(4), &mut heap).unwrap();
    let flat_take_map = remove(flat, small(4), &mut heap).unwrap();
    let mut flat_without = flat;
    for key in [1, 3, 99] {
        flat_without = remove(flat_without, small(key), &mut heap).unwrap();
    }
    let large_remove = remove(large, small(4), &mut heap).unwrap();
    let mut large_without = large;
    for key in [1, 3, 99] {
        large_without = remove(large_without, small(key), &mut heap).unwrap();
    }
    let shrinking_remove = remove(shrinking, small(1), &mut heap).unwrap();
    assert!(!shrinking_remove.is_hashmap());
    assert_eq!(arinsal_maps::size(shrinking_remove), Ok(32));

    let empty = arinsal_maps::new(&mut heap).unwrap();
    let encoded_empty =
        arinsal_etf::encode(&local_map(empty), arinsal_etf::EncodeOptions::default());
    let actual = O::Tuple(vec![
        local_pairs(flat_remove),
        O::Tuple(vec![
            arinsal_term::to_owned(small(40)).unwrap(),
            local_pairs(flat_take_map),
        ]),
        local_pairs(flat_without),
        local_pairs(large_remove),
        local_pairs(large_without),
        local_pairs(shrinking_remove),
        O::Int(arinsal_term::flat_size(empty) as i64),
        O::Int(arinsal_term::size_object(empty) as i64),
        O::Binary(encoded_empty),
    ]);
    assert_eq!(actual, expected);
}

#[test]
fn take_and_flatmap_next_vs_erl() {
    // Port of erts/emulator/beam/erl_map.c:1943-2041 (erts_maps_take) and :3710-3735
    // (erts_internal_map_next_3, flatmap branch), OTP-29.1.1.
    let expected = erl(
        "T=fun(K,M)->case maps:take(K,M) of {V,M2}->{V,maps:to_list(M2)};error->error end end,F=maps:from_list([{{K},K*10}||K<-lists:seq(1,8)]),H=maps:from_list([{K,K*10}||K<-lists:seq(1,80)]),S=maps:from_list([{K,K*10}||K<-lists:seq(1,33)]),O=#{{1}=>one},io:put_chars(binary:encode_hex(term_to_binary({T({4},F),T({9},F),T(4,H),T(99,H),T(1,S),T({1},O),T(x,#{}),erts_internal:map_next(0,F,iterator),erts_internal:map_next(0,F,[tail])}))),halt().",
    );

    let mut heap = VecHeap::new();
    let tuple_key = |key: i64, heap: &mut VecHeap| {
        arinsal_term::TermBuilder::new(heap)
            .tuple(&[small(key)])
            .unwrap()
    };
    let flat_pairs = (1..=8)
        .map(|key| (tuple_key(key, &mut heap), small(key * 10)))
        .collect::<Vec<_>>();
    let flat = from_pairs(&flat_pairs, &mut heap).unwrap();
    let large = from_pairs(
        &(1..=80)
            .map(|key| (small(key), small(key * 10)))
            .collect::<Vec<_>>(),
        &mut heap,
    )
    .unwrap();
    let shrinking = from_pairs(
        &(1..=33)
            .map(|key| (small(key), small(key * 10)))
            .collect::<Vec<_>>(),
        &mut heap,
    )
    .unwrap();
    let one_key = tuple_key(1, &mut heap);
    let one_atom = Term::atom(arinsal_term::global_atoms().intern("one").unwrap());
    let one = from_pairs(&[(one_key, one_atom)], &mut heap).unwrap();
    let empty = arinsal_maps::new(&mut heap).unwrap();

    let taken = |map: Term, key: Term, heap: &mut VecHeap| match take(map, key, heap).unwrap() {
        Some((value, rest)) => {
            assert!(remove(map, key, heap).is_ok_and(|removed| size_eq(removed, rest)));
            O::Tuple(vec![
                arinsal_term::to_owned(value).unwrap(),
                local_pairs(rest),
            ])
        }
        None => {
            assert_eq!(remove(map, key, heap), Ok(map));
            O::Atom("error".into())
        }
    };
    let k4 = tuple_key(4, &mut heap);
    let k9 = tuple_key(9, &mut heap);
    let k1 = tuple_key(1, &mut heap);
    let x = Term::atom(arinsal_term::global_atoms().intern("x").unwrap());
    let tail = Term::atom(arinsal_term::global_atoms().intern("tail").unwrap());
    let tail_list = arinsal_term::TermBuilder::new(&mut heap)
        .cons(tail, Term::NIL)
        .unwrap();
    let actual = O::Tuple(vec![
        taken(flat, k4, &mut heap),
        taken(flat, k9, &mut heap),
        taken(large, small(4), &mut heap),
        taken(large, small(99), &mut heap),
        taken(shrinking, small(1), &mut heap),
        taken(one, k1, &mut heap),
        taken(empty, x, &mut heap),
        arinsal_term::to_owned(flatmap_next(flat, false, Term::NIL, &mut heap).unwrap()).unwrap(),
        arinsal_term::to_owned(flatmap_next(flat, true, tail_list, &mut heap).unwrap()).unwrap(),
    ]);
    assert_eq!(actual, expected);
}

fn size_eq(a: Term, b: Term) -> bool {
    arinsal_maps::size(a) == arinsal_maps::size(b)
}
