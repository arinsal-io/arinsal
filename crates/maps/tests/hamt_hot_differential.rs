use arinsal_etf::OwnedTerm as O;
use arinsal_maps::{from_list, get, iter, put};
use arinsal_term::{Term, VecHeap, internal_hash};
use similar_asserts::assert_eq;
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
fn from_list_colliding_paths_duplicates_lookup_and_put_vs_erl() {
    // Concentrate keys in one root bitmap slot so lookup and insertion traverse shared HAMT paths.
    let keys = (1..=200_000_i64)
        .filter(|key| internal_hash(small(*key)) & 15 == 7)
        .take(160)
        .collect::<Vec<_>>();
    assert_eq!(keys.len(), 160);

    let mut pairs = keys
        .iter()
        .map(|&key| (small(key), small(key * 3)))
        .collect::<Vec<_>>();
    pairs.extend(keys.iter().take(30).map(|&key| (small(key), small(-key))));
    let erl_keys = keys
        .iter()
        .map(i64::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let erl_duplicate_pairs = keys
        .iter()
        .take(30)
        .map(|key| format!("{{{key},-{key}}}"))
        .collect::<Vec<_>>()
        .join(",");
    let update_key = keys[80];
    let eval = format!(
        "Ks=[{erl_keys}],P=[{{K,K*3}}||K<-Ks]++[{erl_duplicate_pairs}],M=maps:from_list(P),N=maps:put({update_key},123456,M),io:put_chars(binary:encode_hex(term_to_binary({{maps:to_list(M),maps:to_list(N),[maps:get(K,M)||K<-Ks],maps:get(-1,M,not_found)}}))),halt()."
    );
    let expected = erl(&eval);

    let mut heap = VecHeap::new();
    let map = from_list(&pairs, &mut heap).unwrap();
    let updated = put(map, small(update_key), small(123_456), &mut heap).unwrap();
    let actual = O::tuple(vec![
        local_pairs(map),
        local_pairs(updated),
        O::list(
            keys.iter()
                .enumerate()
                .map(|(index, &key)| O::Int(if index < 30 { -key } else { key * 3 }))
                .collect(),
        ),
        O::atom("not_found"),
    ]);

    assert_eq!(actual, expected);
    assert_eq!(get(map, small(update_key)), Ok(Some(small(update_key * 3))));
    assert_eq!(get(updated, small(update_key)), Ok(Some(small(123_456))));
    assert_eq!(
        arinsal_maps::get_with_hash(map, small(update_key), internal_hash(small(update_key))),
        Ok(Some(small(update_key * 3)))
    );
    assert_eq!(
        arinsal_maps::get_with_hash(updated, small(update_key), internal_hash(small(update_key))),
        Ok(Some(small(123_456)))
    );
}
