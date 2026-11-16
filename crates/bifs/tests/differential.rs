mod support;

use arinsal_bifs::{copy_bitstring_range, lookup};
use arinsal_difftest::RefErl;
use arinsal_etf::OwnedTerm as O;
use arinsal_term::{ProcessHeap, TermBuilder};
use similar_asserts::assert_eq;
use support::{call, equivalent};

fn atom(s: &str) -> O {
    O::atom(s)
}
fn list(xs: Vec<O>) -> O {
    O::list(xs)
}
fn term(n: usize) -> O {
    match n % 8 {
        0 => O::Int(n as i64 - 500),
        1 => O::Float(n as f64 / 3.0),
        2 => atom("true"),
        3 => O::Tuple(vec![O::Int(n as i64), atom("x")]),
        4 => list(vec![O::Int(n as i64), atom("a")]),
        5 => O::Binary(vec![(n % 256) as u8, 2]),
        6 => O::Map(vec![(atom("a"), O::Int(n as i64))]),
        _ => O::Nil,
    }
}
fn args(m: &str, f: &str, arity: u8, n: usize) -> Vec<O> {
    let x = O::Int((n % 100) as i64);
    let seq = list(vec![x.clone(), atom("a"), O::Int(3)]);
    let tup = O::Tuple(vec![atom("a"), x.clone(), atom("b")]);
    let bin = O::Binary(vec![1, (n % 255) as u8, 3, 4]);
    match (m, f, arity) {
        ("erlang", "length", 1) => vec![seq],
        ("erlang", "byte_size" | "bit_size" | "binary_to_list", 1) => vec![bin],
        ("erlang", "make_ref", 0) | ("erlang", "unique_integer", 0) => vec![],
        ("erlang", "++" | "append" | "--" | "subtract", 2) => vec![seq, list(vec![x])],
        ("lists", "reverse", 2) => vec![seq, term(n)],
        ("lists", "member", 2) => vec![x, seq],
        ("lists", "keyfind" | "keysearch" | "keymember", 3) => {
            vec![x.clone(), O::Int(2), list(vec![tup])]
        }
        ("erlang", "integer_to_list", 1) => {
            vec![O::Int(n as i64 - 500)]
        }
        ("erlang", "integer_to_list", 2) => {
            vec![O::Int(n as i64 - 500), O::Int((n % 35 + 2) as i64)]
        }
        ("erlang", "binary_to_list", 3) => vec![bin, O::Int(2), O::Int(3)],
        ("erlang" | "binary", "binary_part" | "part", 2) => {
            vec![bin, O::Tuple(vec![O::Int(1), O::Int(2)])]
        }
        ("erlang" | "binary", "binary_part" | "part", 3) => vec![bin, O::Int(1), O::Int(2)],
        ("binary", "first" | "last" | "referenced_byte_size", 1) => vec![bin],
        ("binary", "at", 2) => vec![bin, O::Int((n % 4) as i64)],
        ("binary", "copy", 1) => vec![bin],
        ("binary", "copy", 2) => vec![bin, O::Int((n % 5) as i64)],
        ("binary", "list_to_bin", 1) => vec![list(vec![O::Int(1), O::Int((n % 255) as i64)])],
        ("binary", "encode_unsigned", 1) => vec![O::Int((n * 1024) as i64)],
        ("binary", "encode_unsigned", 2) => vec![
            O::Int((n * 1024) as i64),
            atom(if n.is_multiple_of(2) { "little" } else { "big" }),
        ],
        ("binary", "decode_unsigned", 1) => vec![bin],
        ("binary", "decode_unsigned", 2) => vec![
            bin,
            atom(if n.is_multiple_of(2) { "little" } else { "big" }),
        ],
        ("binary", "longest_common_prefix", 1) => vec![list(vec![
            O::Binary(vec![1, 2, (n % 255) as u8]),
            O::Binary(vec![1, 2, 3]),
        ])],
        ("binary", "longest_common_suffix", 1) => vec![list(vec![
            O::Binary(vec![(n % 255) as u8, 2, 3]),
            O::Binary(vec![1, 2, 3]),
        ])],
        ("binary", "compile_pattern", 1) => vec![O::Binary(vec![1, (n % 255) as u8])],
        ("binary", "match" | "matches" | "split", 2) => vec![
            O::Binary(vec![1, 2, 1, 2, (n % 255) as u8]),
            if n.is_multiple_of(2) {
                O::Binary(vec![1, 2])
            } else {
                list(vec![O::Binary(vec![2]), O::Binary(vec![1, 2])])
            },
        ],
        ("binary", "match" | "matches", 3) => vec![
            O::Binary(vec![1, 2, 1, 2, (n % 255) as u8]),
            O::Binary(vec![1, 2]),
            list(vec![O::Tuple(vec![
                atom("scope"),
                O::Tuple(vec![O::Int(1), O::Int(4)]),
            ])]),
        ],
        ("binary", "split", 3) => vec![
            O::Binary(vec![1, 2, 1, 2, (n % 255) as u8]),
            O::Binary(vec![1, 2]),
            list(vec![atom(match n % 3 {
                0 => "global",
                1 => "trim",
                _ => "trim_all",
            })]),
        ],
        _ => vec![term(n); arity as usize],
    }
}

#[test]
fn differential_1000_per_stable_bif() {
    let reference = RefErl::shared().expect("OTP 29 reference");
    let mut cases = 0_usize;
    let mut mismatches = 0_usize;
    for spec in arinsal_spec::BIFS {
        if lookup(spec.module, spec.name, spec.arity).is_none() {
            continue;
        }
        if matches!(
            (spec.module, spec.name),
            ("erlang", "self") | ("binary", "compile_pattern") | ("os", "getpid" | "perf_counter")
        ) {
            continue;
        }
        let mut local_mismatches = 0;
        for i in 0..1000 {
            let mut input = args(spec.module, spec.name, spec.arity, i);
            if i.is_multiple_of(10) && !input.is_empty() {
                input[0] = atom("invalid");
            }
            let actual = call(spec.module, spec.name, &input);
            let expected = reference.call(spec.module, spec.name, &input);
            // Magic references identify resources and have intentionally
            // process-specific ids, so compare their type rather than ids.
            let matches_magic_ref = matches!(
                (spec.module, spec.name, &actual, &expected),
                (
                    "erts_internal",
                    "atomics_new" | "counters_new",
                    arinsal_difftest::CallResult::Ok(O::MagicRef(_)),
                    arinsal_difftest::CallResult::Ok(O::Ref { .. })
                )
            );
            if !matches_magic_ref && !equivalent(&actual, &expected) {
                local_mismatches += 1;
                if local_mismatches <= 2 {
                    eprintln!(
                        "mismatch {}:{}/{} input={input:?} actual={actual:?} expected={expected:?}",
                        spec.module, spec.name, spec.arity
                    );
                }
            }
        }
        println!(
            "{}:{}/{} | 1000 | {local_mismatches}",
            spec.module, spec.name, spec.arity
        );
        cases += 1000;
        mismatches += local_mismatches;
    }
    println!("total | {cases} | {mismatches}");
    assert_eq!(mismatches, 0);
}

#[test]
fn binary_reads_and_bit_copies_handle_unaligned_subbinary() {
    let mut heap = ProcessHeap::with_words(512);
    let mut builder = TermBuilder::new(&mut heap);
    let backing = builder
        .binary(&[0b0100_0000, 0b1100_0000, 0b0100_0000])
        .expect("backing");
    let subject = builder.sub_binary(backing, 1, 16).expect("subbinary");

    let mut unaligned_copy = [0];
    copy_bitstring_range(subject, 4, &mut unaligned_copy, 8).expect("unaligned copy");
    assert_eq!(unaligned_copy, [0b0001_1000]);
    let mut aligned_copy = [0];
    copy_bitstring_range(subject, 8, &mut aligned_copy, 8).expect("aligned copy");
    assert_eq!(aligned_copy, [0b1000_0000]);
    // The binary:at/match/split and binary_to_list bodies are VM bodies
    // (crates/vm/tests/bifs/moved_bif_differential.rs).
}
