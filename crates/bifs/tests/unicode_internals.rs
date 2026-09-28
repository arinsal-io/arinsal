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

fn next(seed: &mut u64) -> u64 {
    *seed ^= *seed << 13;
    *seed ^= *seed >> 7;
    *seed ^= *seed << 17;
    *seed
}

fn input(seed: &mut u64, index: usize) -> O {
    match index % 12 {
        0 => O::Binary(vec![]),
        1 => O::Binary(vec![0xff, 65]),
        2 => O::Binary(vec![65, 0, 66]),
        3 => O::Binary("e\u{301}".as_bytes().to_vec()),
        4 => O::Binary("A\u{30a}\u{301}".as_bytes().to_vec()),
        5 => O::BitString {
            bytes: vec![0xe0],
            bits: 3,
        },
        6 => O::atom("invalid"),
        7 => O::list(vec![O::Int(65), O::list(vec![O::Int(8364)])]),
        8 => O::list(vec![O::Int(65), O::Int(0xd800)]),
        9 => O::List {
            elems: vec![O::Int(65)],
            tail: Box::new(O::Binary(vec![66])),
        },
        10 => O::Binary((0..(next(seed) % 16)).map(|_| next(seed) as u8).collect()),
        _ => {
            let base = [65, 69, 79, 97, 101, 111];
            let marks = [0x30a, 0x301, 0x323, 0x304];
            let mut text = String::new();
            text.push(char::from_u32(base[(next(seed) % base.len() as u64) as usize]).unwrap());
            for _ in 0..(next(seed) % 3) {
                text.push(
                    char::from_u32(marks[(next(seed) % marks.len() as u64) as usize]).unwrap(),
                );
            }
            O::Binary(text.into_bytes())
        }
    }
}

#[test]
fn filename_and_console_bifs_match_otp() {
    let reference = RefErl::shared().expect("OTP 29 reference");
    let mut seed = 0x52ab_721c_9d86_3241;
    let mut mismatches = 0;
    for index in 0..1000 {
        let value = input(&mut seed, index);
        for (module, name) in [
            ("prim_file", "internal_name2native"),
            ("prim_file", "internal_native2name"),
            ("prim_file", "internal_normalize_utf8"),
            ("prim_file", "is_translatable"),
        ] {
            let args = [value.clone()];
            let actual = call(module, name, &args);
            let expected = reference.call(module, name, &args);
            if !equivalent(&actual, &expected) {
                mismatches += 1;
                if mismatches <= 8 {
                    eprintln!(
                        "{index} {module}:{name} {args:?}: actual={actual:?} expected={expected:?}"
                    );
                }
            }
        }
    }
    for (module, name) in [("file", "native_name_encoding"), ("io", "printable_range")] {
        let actual = call(module, name, &[]);
        let expected = reference.call(module, name, &[]);
        assert!(
            equivalent(&actual, &expected),
            "{module}:{name}: actual={actual:?} expected={expected:?}"
        );
    }
    assert_eq!(mismatches, 0);
}
