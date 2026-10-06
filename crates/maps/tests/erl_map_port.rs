use arinsal_etf::OwnedTerm as O;
use arinsal_maps::{from_list, from_pairs, get, iter, merge, put, remove, update};
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
