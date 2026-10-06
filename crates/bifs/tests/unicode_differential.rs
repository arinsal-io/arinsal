#[allow(dead_code)]
mod support;

use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm as O;
use support::call;

fn equivalent(actual: &CallResult, expected: &CallResult) -> bool {
    match (actual, expected) {
        (CallResult::Ok(a), CallResult::Ok(b)) => a == b,
        (
            CallResult::Exception {
                class: ac,
                reason: ar,
                ..
            },
            CallResult::Exception {
                class: ec,
                reason: er,
                ..
            },
        ) => ac == ec && ar == er,
        _ => false,
    }
}

fn encodings() -> [O; 9] {
    [
        O::atom("latin1"),
        O::atom("unicode"),
        O::atom("utf8"),
        O::atom("utf16"),
        O::atom("utf32"),
        O::Tuple(vec![O::atom("utf16"), O::atom("little")]),
        O::Tuple(vec![O::atom("utf32"), O::atom("little")]),
        O::Tuple(vec![O::atom("utf16"), O::atom("big")]),
        O::Tuple(vec![O::atom("utf32"), O::atom("big")]),
    ]
}

fn next(seed: &mut u64) -> u64 {
    *seed ^= *seed << 13;
    *seed ^= *seed >> 7;
    *seed ^= *seed << 17;
    *seed
}

fn leaf(seed: &mut u64) -> O {
    match next(seed) % 15 {
        0 => O::Int(-1),
        1 => O::Int(0xd800),
        2 => O::Int(0x110000),
        3 => O::Int(0x10ffff),
        4 => O::Int((next(seed) % 0x20000) as i64),
        5 => O::atom("invalid"),
        6 => O::BitString {
            bytes: vec![0xf0],
            bits: 3,
        },
        7 => O::Binary(vec![0xe2]),
        8 => O::Binary(vec![0xe2, 0x82]),
        9 => O::Binary(vec![0xe2, 0x82, 0xac]),
        10 => O::Binary(vec![0xff, 65]),
        11 => O::Binary(vec![0xd8, 0x00]),
        12 => O::Binary(vec![0x00, 0x41, 0x00]),
        13 => O::Binary(vec![0xf0, 0x90, 0x80, 0x80]),
        _ => O::Binary((0..(next(seed) % 7)).map(|_| next(seed) as u8).collect()),
    }
}

fn chardata(seed: &mut u64, depth: usize) -> O {
    if depth == 0 || next(seed).is_multiple_of(3) {
        return leaf(seed);
    }
    let count = (next(seed) % 5) as usize;
    let mut elems = Vec::with_capacity(count);
    for _ in 0..count {
        elems.push(chardata(seed, depth - 1));
    }
    if next(seed).is_multiple_of(8) {
        O::List {
            elems,
            tail: Box::new(leaf(seed)),
        }
    } else {
        O::list(elems)
    }
}

fn varied_input(seed: &mut u64, index: usize) -> O {
    let byte = next(seed) as u8;
    match next(seed) % 19 {
        0 => O::list(vec![
            O::Binary(vec![0xe2]),
            O::Binary(vec![0x82]),
            O::Binary(vec![0xac]),
            leaf(seed),
        ]),
        1 => O::list(vec![
            O::Binary(vec![0xd8, 0x3d]),
            O::Binary(vec![0xde, 0x00]),
            leaf(seed),
        ]),
        2 => O::list(vec![
            O::Int(0x1f600 + i64::from(byte)),
            O::Binary(vec![byte & 0x7f]),
            O::list(vec![O::Int(i64::from(byte))]),
        ]),
        3 => {
            let mut value = O::Binary(vec![0xf0, 0x90, 0x80, 0x80, byte]);
            for _ in 0..(16 + usize::from(byte % 16)) {
                value = O::list(vec![value]);
            }
            value
        }
        4 => {
            let mut data = "Erlang 🐈 € α".as_bytes().to_vec();
            data.push(byte);
            O::Binary(data)
        }
        5 => O::list(vec![
            O::Binary(vec![0xe0, 0x80]),
            O::Binary(vec![0x80]),
            leaf(seed),
        ]),
        6 => O::list(vec![
            O::Binary(vec![0xf4, 0x90]),
            O::Binary(vec![0x80, 0x80]),
            leaf(seed),
        ]),
        7 => O::list(vec![O::Int(i64::from(byte)), O::Int(0xd800), O::Int(66)]),
        8 => O::list(vec![O::Int(i64::from(byte)), O::Int(0x110000), O::Int(66)]),
        9 => O::List {
            elems: vec![O::Int(i64::from(byte))],
            tail: Box::new(O::Binary(vec![byte.wrapping_add(1)])),
        },
        _ => chardata(seed, if index.is_multiple_of(37) { 12 } else { 3 }),
    }
}

#[test]
fn unicode_random_differential() {
    let reference = RefErl::shared().expect("OTP 29 reference");
    let mut seed = 0x3141_5926_5358_9793;
    let mut mismatches = 0;
    let mut by_encoding = [0_usize; 9];
    let count = std::env::var("UNICODE_CASES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(50_000);
    for i in 0..count {
        let input = varied_input(&mut seed, i);
        for (encoding_index, encoding) in encodings().into_iter().enumerate() {
            for function in ["characters_to_binary", "characters_to_list"] {
                let args = [input.clone(), encoding.clone()];
                let actual = call("unicode", function, &args);
                let expected = reference.call("unicode", function, &args);
                if !equivalent(&actual, &expected) {
                    mismatches += 1;
                    by_encoding[encoding_index] += 1;
                    if mismatches <= 6 {
                        eprintln!(
                            "case {i} {function} {args:?}: actual={actual:?} expected={expected:?}"
                        );
                    }
                }
            }
        }
    }
    eprintln!("mismatches by encoding: {by_encoding:?}");
    assert_eq!(mismatches, 0);
}

#[test]
fn unicode_large_binary_boundaries() {
    let reference = RefErl::shared().expect("OTP 29 reference");
    let mut cases = vec![
        O::Binary(vec![b'a'; 16_385]),
        O::Binary([vec![b'a'; 8_191], vec![0xe2, 0x82, 0xac], vec![b'b'; 8_194]].concat()),
        O::Binary([vec![b'a'; 8_191], vec![0xe2, 0x82]].concat()),
        O::Binary([vec![b'a'; 8_191], vec![0xff, b'b']].concat()),
    ];
    let utf16 = [0, 65].repeat(5_000);
    let utf32 = [0, 0, 0, 65].repeat(3_000);
    cases.push(O::Binary(utf16));
    cases.push(O::Binary(utf32));
    for (index, input) in cases.into_iter().enumerate() {
        for encoding in encodings() {
            for function in ["characters_to_binary", "characters_to_list"] {
                let args = [input.clone(), encoding.clone()];
                let actual = call("unicode", function, &args);
                let expected = reference.call("unicode", function, &args);
                assert!(
                    equivalent(&actual, &expected),
                    "case {index} {function} {encoding:?}"
                );
            }
        }
    }
}

#[test]
fn unicode_deep_nesting() {
    let reference = RefErl::shared().expect("OTP 29 reference");
    for leaf in [O::Int(0x1f600), O::Binary(vec![0xe2, 0x82])] {
        let mut input = leaf;
        for _ in 0..128 {
            input = O::list(vec![input]);
        }
        for encoding in encodings() {
            for function in ["characters_to_binary", "characters_to_list"] {
                let args = [input.clone(), encoding.clone()];
                let actual = call("unicode", function, &args);
                let expected = reference.call("unicode", function, &args);
                assert!(equivalent(&actual, &expected), "{function} {encoding:?}");
            }
        }
    }
}
