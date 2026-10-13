mod support;

use arinsal_bifs::{Ctx, ProcessHeapHandle, copy_bitstring_range, lookup};
use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm as O;
use arinsal_term::{ProcessHeap, TermBuilder, from_owned, to_owned};
use num_traits::ToPrimitive;
use std::collections::HashSet;
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
        ("erlang", "length" | "hd" | "tl", 1) => vec![seq],
        ("erlang", "abs" | "float" | "trunc" | "round" | "ceil" | "floor", 1) => {
            if n.is_multiple_of(2) {
                vec![O::Int(n as i64 - 500)]
            } else {
                vec![O::Float(n as f64 / 7.0 - 70.0)]
            }
        }
        ("erlang", "tuple_size" | "tuple_to_list" | "size", 1) => vec![tup],
        ("erlang", "byte_size" | "bit_size" | "binary_to_list", 1) => vec![bin],
        ("erlang", "element", 2) => vec![O::Int((n % 3 + 1) as i64), tup],
        ("erlang", "setelement", 3) => vec![O::Int((n % 3 + 1) as i64), tup, term(n)],
        ("erlang", "node", 0) | ("erlang", "make_ref", 0) | ("erlang", "unique_integer", 0) => {
            vec![]
        }
        ("erlang", "node", 1) => vec![O::Pid {
            node: "nonode@nohost".into(),
            id: 3,
            serial: 0,
            creation: 0,
        }],
        ("erlang", "min" | "max" | "==" | "/=" | "=:=" | "=/=" | "<" | "=<" | ">" | ">=", 2) => {
            vec![term(n), term(n + 1)]
        }
        ("erlang", "not", 1) => vec![atom(if n.is_multiple_of(2) { "true" } else { "false" })],
        ("erlang", "and" | "or" | "xor", 2) => vec![
            atom(if n.is_multiple_of(2) { "true" } else { "false" }),
            atom(if n.is_multiple_of(3) { "true" } else { "false" }),
        ],
        ("erlang", "phash2", 1) => vec![term(n)],
        ("erlang", "phash2" | "phash", 2) => vec![term(n), O::Int((n % 1000 + 1) as i64)],
        ("erlang", "list_to_tuple", 1) => vec![seq],
        ("erlang", "make_tuple", 2) => vec![O::Int((n % 8) as i64), term(n)],
        ("erlang", "make_tuple", 3) => vec![
            O::Int(3),
            x.clone(),
            list(vec![O::Tuple(vec![O::Int(2), term(n)])]),
        ],
        ("erlang", "append_element", 2) => vec![tup, term(n)],
        ("erlang", "delete_element", 2) => vec![O::Int((n % 3 + 1) as i64), tup],
        ("erlang", "insert_element", 3) => vec![O::Int((n % 4 + 1) as i64), tup, term(n)],
        ("erlang", "++" | "append" | "--" | "subtract", 2) => vec![seq, list(vec![x])],
        ("lists", "reverse", 2) => vec![seq, term(n)],
        ("lists", "member", 2) => vec![x, seq],
        ("lists", "keyfind" | "keysearch" | "keymember", 3) => {
            vec![x.clone(), O::Int(2), list(vec![tup])]
        }
        ("erlang", "atom_to_list", 1) => {
            vec![atom(if n.is_multiple_of(2) { "true" } else { "hello" })]
        }
        ("erlang", "list_to_atom", 1) => vec![O::charlist(&format!("a{}", n))],
        ("erlang", "list_to_existing_atom", 1) => vec![O::charlist("true")],
        ("erlang", "atom_to_binary", 2) => vec![
            atom("hello"),
            atom(if n.is_multiple_of(2) {
                "utf8"
            } else {
                "latin1"
            }),
        ],
        ("erlang", "binary_to_atom", 2) => {
            vec![O::Binary(format!("a{}", n).into_bytes()), atom("utf8")]
        }
        ("erlang", "binary_to_existing_atom", 2) => vec![O::Binary(b"true".to_vec()), atom("utf8")],
        ("erlang", "float_to_list" | "float_to_binary", 1) => {
            vec![O::Float(n as f64 / 7.0 - 50.0)]
        }
        ("erlang", "float_to_list" | "float_to_binary", 2) => {
            let option = match n % 4 {
                0 => atom("short"),
                1 => atom("compact"),
                2 => O::Tuple(vec![atom("decimals"), O::Int(3)]),
                _ => O::Tuple(vec![atom("scientific"), O::Int(5)]),
            };
            vec![O::Float(n as f64 / 7.0 - 50.0), list(vec![option])]
        }
        ("erlang", "list_to_float", 1) => {
            vec![O::charlist(&format!("{}.{:02}", n % 1000, n % 100))]
        }
        ("erlang", "binary_to_float", 1) => {
            vec![O::Binary(
                format!("{}.{:02}", n % 1000, n % 100).into_bytes(),
            )]
        }
        ("erlang", "integer_to_list" | "integer_to_binary", 1) => {
            vec![O::Int(n as i64 - 500)]
        }
        ("erlang", "integer_to_list" | "integer_to_binary", 2) => {
            vec![O::Int(n as i64 - 500), O::Int((n % 35 + 2) as i64)]
        }
        ("erlang", "binary_to_list", 3) => vec![bin, O::Int(2), O::Int(3)],
        ("erlang", "bitstring_to_list", 1) => vec![O::BitString {
            bytes: vec![1, 2, ((n % 8) as u8) << 5],
            bits: 3,
        }],
        ("erlang", "list_to_bitstring", 1) => vec![list(vec![
            O::Int((n % 255) as i64),
            O::BitString {
                bytes: vec![0b1010_0000],
                bits: 3,
            },
            O::Binary(vec![2, 3]),
        ])],
        ("erlang", "list_to_binary" | "iolist_to_binary" | "iolist_size", 1) => vec![list(vec![
            O::Int(1),
            O::Binary(vec![2, 3]),
            list(vec![O::Int((n % 255) as i64)]),
        ])],
        ("erlang", "split_binary", 2) => vec![bin, O::Int((n % 5) as i64)],
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
        ("erlang", "is_function", 2) => vec![term(n), O::Int((n % 5) as i64)],
        ("erlang", "is_record", 1) => vec![term(n)],
        ("erlang", "is_record", 2) => vec![tup, atom("a")],
        ("erlang", "is_record", 3) => vec![tup, atom("a"), O::Int(3)],
        ("erts_internal", "cmp_term" | "same", 2) => vec![term(n), term(n + 1)],
        ("erts_debug", "same", 2) => vec![term(n), term(n + 1)],
        ("erts_debug", "flat_size", 1) => vec![term(n)],
        ("unicode", "bin_is_7bit", 1) => vec![bin],
        ("erlang", "is_builtin", 3) => vec![
            atom("erlang"),
            atom(if n.is_multiple_of(2) {
                "length"
            } else {
                "missing"
            }),
            O::Int(1),
        ],
        ("erlang", "is_map_key" | "map_get", 2) => vec![atom("a"), O::Map(vec![(atom("a"), x)])],
        ("erlang", "map_size", 1) => vec![O::Map(vec![(atom("a"), x)])],
        ("erlang", "error" | "exit" | "throw", 1) => vec![term(n)],
        ("erlang", "error", 2) => vec![term(n), list(vec![term(n + 1)])],
        ("erlang", "error", 3) => vec![term(n), list(vec![]), list(vec![])],
        ("erlang", "raise", 3) => vec![atom("error"), term(n), O::Nil],
        ("erlang", "unique_integer", 1) => vec![list(vec![atom("positive")])],
        ("math", "acos" | "asin" | "atanh", 1) => {
            vec![O::Float((n % 199) as f64 / 100.0 - 0.99)]
        }
        ("math", "acosh", 1) => vec![O::Float((n % 1000) as f64 / 100.0 + 1.0)],
        ("math", "log" | "log2" | "log10" | "sqrt", 1) => {
            vec![O::Float((n % 1000) as f64 / 100.0 + 0.01)]
        }
        ("math", _, 1) => vec![O::Float((n % 1000) as f64 / 100.0 - 5.0)],
        ("math", "pow", 2) => vec![
            O::Float((n % 100) as f64 / 10.0 + 0.1),
            O::Float((n % 20) as f64 / 10.0),
        ],
        ("math", "fmod", 2) => vec![
            O::Float((n % 100) as f64 / 10.0),
            O::Float((n % 20) as f64 / 10.0 + 0.1),
        ],
        ("math", _, 2) => vec![
            O::Float((n % 100) as f64 / 10.0),
            O::Float((n % 20) as f64 / 10.0),
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
            ("erlang", "make_ref" | "unique_integer" | "self")
                | ("binary", "compile_pattern")
                | ("erlang" | "os", "system_time")
                | (
                    "erlang",
                    "monotonic_time"
                        | "time_offset"
                        | "timestamp"
                        | "now"
                        | "time"
                        | "date"
                        | "localtime"
                        | "universaltime"
                )
                | ("os", "timestamp" | "getpid" | "perf_counter")
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
                    arinsal_difftest::CallResult::Ok(O::Ref { .. }),
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
fn nondeterministic_identity_bifs() {
    let reference = RefErl::shared().expect("OTP 29 reference");
    let mut refs = HashSet::new();
    let mut ints = HashSet::new();
    let mut negative = HashSet::new();
    for _ in 0..1000 {
        let local = call("erlang", "make_ref", &[]);
        let remote = reference.call("erlang", "make_ref", &[]);
        assert!(matches!(
            remote,
            arinsal_difftest::CallResult::Ok(O::Ref { .. })
        ));
        let arinsal_difftest::CallResult::Ok(O::Ref { ref ids, .. }) = local else {
            panic!("make_ref must produce a reference");
        };
        assert!(refs.insert(ids.clone()));
        let local = call("erlang", "unique_integer", &[list(vec![atom("positive")])]);
        let remote = reference.call("erlang", "unique_integer", &[list(vec![atom("positive")])]);
        assert!(matches!(remote, arinsal_difftest::CallResult::Ok(O::Int(v)) if v > 0));
        let arinsal_difftest::CallResult::Ok(O::Int(value)) = local else {
            panic!("positive unique_integer must produce an integer");
        };
        assert!(value > 0);
        assert!(ints.insert(value));
        let local = call("erlang", "unique_integer", &[]);
        let remote = reference.call("erlang", "unique_integer", &[]);
        assert!(matches!(remote, arinsal_difftest::CallResult::Ok(O::Int(v)) if v < 0));
        let arinsal_difftest::CallResult::Ok(O::Int(value)) = local else {
            panic!("unique_integer/0 must produce an integer");
        };
        assert!(value < 0);
        assert!(negative.insert(value));
    }
}

#[test]
fn compiled_patterns_match_plain_patterns() {
    let reference = RefErl::shared().expect("OTP 29 reference");
    for n in 0..1000 {
        let needle = O::Binary(vec![1, (n % 255) as u8]);
        let haystack = O::Binary(vec![0, 1, (n % 255) as u8, 1]);
        let mut heap = ProcessHeap::with_words(1024);
        let mut allocator = ProcessHeapHandle(&mut heap);
        let needle_term = from_owned(&needle, &mut allocator).expect("needle term");
        let haystack_term = from_owned(&haystack, &mut allocator).expect("haystack term");
        let compile = lookup("binary", "compile_pattern", 1).expect("compile_pattern/1");
        let compiled = {
            let mut ctx = Ctx::new(&mut allocator);
            compile(&mut ctx, &[needle_term]).expect("compile_pattern succeeds")
        };
        let matching = lookup("binary", "match", 2).expect("match/2");
        let mut ctx = Ctx::new(&mut allocator);
        let actual_term = matching(&mut ctx, &[haystack_term, compiled])
            .expect("compiled pattern must match in its owner heap");
        let actual =
            arinsal_difftest::CallResult::Ok(to_owned(actual_term).expect("owned match result"));
        let expected = reference.call("binary", "match", &[haystack, needle]);
        assert!(equivalent(&actual, &expected), "{actual:?} != {expected:?}");
    }
}

#[test]
fn bitstring_and_iolist_edges() {
    let reference = RefErl::shared().expect("OTP 29 reference");
    let improper = O::List {
        elems: vec![O::Int(1)],
        tail: Box::new(O::Int(2)),
    };
    let partial = O::BitString {
        bytes: vec![0b1010_0000],
        bits: 3,
    };
    for (name, value) in [
        ("list_to_binary", O::Binary(vec![1])),
        ("list_to_binary", improper.clone()),
        ("iolist_to_binary", improper.clone()),
        ("iolist_to_binary", O::Binary(vec![1])),
        ("iolist_size", improper),
        ("size", partial.clone()),
        ("byte_size", partial.clone()),
        ("bitstring_to_list", partial),
    ] {
        let actual = call("erlang", name, std::slice::from_ref(&value));
        let expected = reference.call("erlang", name, &[value]);
        assert!(
            equivalent(&actual, &expected),
            "{name}: {actual:?} != {expected:?}"
        );
    }
}

#[test]
fn wall_clock_bifs_track_otp() {
    fn value(result: &arinsal_difftest::CallResult) -> Option<i128> {
        match result {
            arinsal_difftest::CallResult::Ok(O::Int(n)) => Some(*n as i128),
            arinsal_difftest::CallResult::Ok(O::BigInt(n)) => n.to_i128(),
            _ => None,
        }
    }
    let reference = RefErl::shared().expect("OTP 29 reference");
    for module in ["erlang", "os"] {
        for unit in [
            None,
            Some("native"),
            Some("second"),
            Some("millisecond"),
            Some("microsecond"),
            Some("nanosecond"),
            Some("seconds"),
            Some("milli_seconds"),
            Some("micro_seconds"),
            Some("nano_seconds"),
        ] {
            for _ in 0..1000 {
                let arguments = unit.map_or_else(Vec::new, |name| vec![atom(name)]);
                let actual = call(module, "system_time", &arguments);
                let expected = reference.call(module, "system_time", &arguments);
                let (a, b) = (
                    value(&actual).expect("local integer"),
                    value(&expected).expect("OTP integer"),
                );
                let tolerance = match unit {
                    Some("second" | "seconds") => 2,
                    Some("millisecond" | "milli_seconds") => 2_000,
                    Some("microsecond" | "micro_seconds") => 2_000_000,
                    _ => 2_000_000_000,
                };
                assert!(
                    (a - b).abs() <= tolerance,
                    "{module}:system_time {unit:?}: {a} vs {b}"
                );
            }
        }
        for _ in 0..1000 {
            let input = [O::Int(1000)];
            let actual = call(module, "system_time", &input);
            let expected = reference.call(module, "system_time", &input);
            let (a, b) = (
                value(&actual).expect("local integer"),
                value(&expected).expect("OTP integer"),
            );
            assert!((a - b).abs() <= 2_000);
        }
        for (from, to, value, expected_value) in [
            ("seconds", "nano_seconds", 2, 2_000_000_000),
            ("milli_seconds", "microsecond", 3, 3_000),
            ("micro_seconds", "millisecond", 4_000, 4),
            ("nano_seconds", "second", 3_000_000_000, 3),
        ] {
            let input = [O::Int(value), atom(from), atom(to)];
            let actual = call("erlang", "convert_time_unit", &input);
            let expected = reference.call("erlang", "convert_time_unit", &input);
            assert!(
                equivalent(&actual, &expected),
                "convert_time_unit {input:?}: {actual:?} != {expected:?}"
            );
            assert!(
                equivalent(
                    &actual,
                    &arinsal_difftest::CallResult::Ok(O::Int(expected_value))
                ),
                "convert_time_unit {from}->{to} scale"
            );
        }
        let input = [
            O::Int(1_000_000_000),
            atom("perf_counter"),
            atom("microsecond"),
        ];
        let actual = call("erlang", "convert_time_unit", &input);
        let expected = reference.call("erlang", "convert_time_unit", &input);
        assert!(
            equivalent(&actual, &expected),
            "convert_time_unit perf_counter: {actual:?} != {expected:?}"
        );
    }
}

#[test]
fn referenced_byte_size_keeps_subbinary_owner() {
    let reference = RefErl::shared().expect("OTP 29 reference");
    let bytes = vec![7_u8; 1000];
    let expected = reference.call(
        "binary",
        "referenced_byte_size",
        &[O::Binary(bytes.clone())],
    );
    let mut heap = ProcessHeap::with_words(128);
    let mut builder = TermBuilder::new(&mut heap);
    let original = builder.binary(&bytes).expect("binary");
    let subbinary = builder
        .sub_binary(original, 100 * 8, 100 * 8)
        .expect("subbinary");
    let mut allocator = ProcessHeapHandle(&mut heap);
    let mut ctx = Ctx::new(&mut allocator);
    let bif = lookup("binary", "referenced_byte_size", 1).expect("BIF");
    let actual = arinsal_difftest::CallResult::Ok(
        to_owned(bif(&mut ctx, &[subbinary]).expect("size")).expect("term"),
    );
    assert!(equivalent(&actual, &expected), "{actual:?} != {expected:?}");
}

#[test]
fn new_bifs_valid_inputs_match_otp() {
    let reference = RefErl::shared().expect("OTP 29 reference");
    for n in 0..1000 {
        let data = O::Binary((0..n % 197).map(|i| ((i * 37 + n) % 256) as u8).collect());
        let map = O::Map(vec![(O::Int(1), O::Int(n)), (O::Int(2), O::Int(n + 1))]);
        let keys = list(vec![O::Int(1), O::Int(2), O::Int(1)]);
        let pairs = list(vec![
            O::Tuple(vec![O::Int(1), O::Int(n)]),
            O::Tuple(vec![O::Int(2), O::Int(n + 1)]),
        ]);
        let positive_cases = [
            ("erlang", "+", vec![O::Int(n), O::Int(n + 1)]),
            ("erlang", "div", vec![O::Int(n), O::Int(7)]),
            ("erlang", "bsl", vec![O::Int(n), O::Int(n % 20)]),
            ("erlang", "crc32", vec![data.clone()]),
            ("erlang", "adler32", vec![data.clone()]),
            ("erlang", "md5", vec![data.clone()]),
            ("maps", "from_list", vec![pairs]),
            ("maps", "from_keys", vec![keys, O::Int(n)]),
            ("maps", "find", vec![O::Int(1), map.clone()]),
            ("maps", "get", vec![O::Int(1), map.clone()]),
            ("maps", "is_key", vec![O::Int(1), map.clone()]),
            ("maps", "keys", vec![map.clone()]),
            ("maps", "values", vec![map.clone()]),
            ("maps", "put", vec![O::Int(1), O::Int(n + 5), map.clone()]),
            ("maps", "remove", vec![O::Int(1), map.clone()]),
            (
                "maps",
                "update",
                vec![O::Int(1), O::Int(n + 5), map.clone()],
            ),
            ("maps", "take", vec![O::Int(1), map.clone()]),
            ("maps", "merge", vec![map.clone(), map.clone()]),
            ("erlang", "map_size", vec![map.clone()]),
            ("erlang", "map_get", vec![O::Int(1), map.clone()]),
            ("erlang", "is_map_key", vec![O::Int(1), map]),
        ];
        for (module, name, input) in positive_cases {
            let actual = call(module, name, &input);
            let expected = reference.call(module, name, &input);
            assert!(
                equivalent(&actual, &expected),
                "{module}:{name} {input:?}: {actual:?} != {expected:?}"
            );
        }
        for algorithm in ["crc32", "adler32"] {
            let O::Binary(ref bytes) = data else {
                unreachable!()
            };
            let mid = bytes.len() / 2;
            let left = O::Binary(bytes[..mid].to_vec());
            let right = O::Binary(bytes[mid..].to_vec());
            let local_left = call("erlang", algorithm, std::slice::from_ref(&left));
            let local_right = call("erlang", algorithm, std::slice::from_ref(&right));
            let (
                arinsal_difftest::CallResult::Ok(sum_left),
                arinsal_difftest::CallResult::Ok(sum_right),
            ) = (local_left, local_right)
            else {
                panic!("checksum")
            };
            let input = [
                sum_left.clone(),
                sum_right,
                O::Int((bytes.len() - mid) as i64),
            ];
            let name = format!("{algorithm}_combine");
            let actual = call("erlang", &name, &input);
            let expected = reference.call("erlang", &name, &input);
            assert!(
                equivalent(&actual, &expected),
                "{name} {input:?}: {actual:?} != {expected:?}"
            );
            let input = [sum_left, right];
            let actual = call("erlang", algorithm, &input);
            let expected = reference.call("erlang", algorithm, &input);
            assert!(
                equivalent(&actual, &expected),
                "{algorithm}/2 {input:?}: {actual:?} != {expected:?}"
            );
        }
        let init = call("erlang", "md5_init", &[]);
        let remote_init = reference.call("erlang", "md5_init", &[]);
        assert!(
            equivalent(&init, &remote_init),
            "md5_init: {init:?} != {remote_init:?}"
        );
        let arinsal_difftest::CallResult::Ok(context) = init else {
            panic!("context")
        };
        let input = [context, data];
        let update = call("erlang", "md5_update", &input);
        let remote_update = reference.call("erlang", "md5_update", &input);
        assert!(
            equivalent(&update, &remote_update),
            "md5_update n={n}: {update:?} != {remote_update:?}"
        );
        let arinsal_difftest::CallResult::Ok(context) = update else {
            panic!("context")
        };
        let local_final = call("erlang", "md5_final", std::slice::from_ref(&context));
        let remote_final = reference.call("erlang", "md5_final", &[context]);
        assert!(
            equivalent(&local_final, &remote_final),
            "md5_final n={n}: {local_final:?} != {remote_final:?}"
        );
    }
}

#[test]
fn calendar_conversions_match_otp() {
    let reference = RefErl::shared().expect("OTP 29 reference");
    for n in 0..1000 {
        let secs = (n as i64 - 500) * 1_234_567;
        let input = [O::Int(secs)];
        let actual = call("erlang", "posixtime_to_universaltime", &input);
        let expected = reference.call("erlang", "posixtime_to_universaltime", &input);
        assert!(equivalent(&actual, &expected), "{actual:?} != {expected:?}");
        let arinsal_difftest::CallResult::Ok(datetime) = actual else {
            panic!("datetime")
        };
        let input = [datetime];
        for name in ["universaltime_to_posixtime", "universaltime_to_localtime"] {
            let actual = call("erlang", name, &input);
            let expected = reference.call("erlang", name, &input);
            assert!(
                equivalent(&actual, &expected),
                "{name} {input:?}: {actual:?} != {expected:?}"
            );
        }
        let input = [input[0].clone(), atom("undefined")];
        let actual = call("erlang", "localtime_to_universaltime", &input);
        let expected = reference.call("erlang", "localtime_to_universaltime", &input);
        assert!(
            equivalent(&actual, &expected),
            "localtime_to_universaltime {input:?}: {actual:?} != {expected:?}"
        );
    }
    let before_epoch = O::Tuple(vec![
        O::Tuple(vec![O::Int(1900), O::Int(7), O::Int(1)]),
        O::Tuple(vec![O::Int(12), O::Int(0), O::Int(0)]),
    ]);
    for name in ["universaltime_to_localtime", "localtime_to_universaltime"] {
        let mut input = vec![before_epoch.clone()];
        if name == "localtime_to_universaltime" {
            input.push(O::Atom("false".into()));
        }
        let actual = call("erlang", name, &input);
        let expected = reference.call("erlang", name, &input);
        assert!(
            equivalent(&actual, &expected),
            "{name}: {actual:?} != {expected:?}"
        );
    }
}

#[test]
fn clock_and_dst_behavior() {
    let reference = RefErl::shared().expect("OTP 29 reference");
    let as_i128 = |result: arinsal_difftest::CallResult| match result {
        arinsal_difftest::CallResult::Ok(O::Int(value)) => value as i128,
        arinsal_difftest::CallResult::Ok(O::BigInt(ref value)) => value.to_i128().unwrap(),
        other => panic!("expected integer, got {other:?}"),
    };
    let mut prior = as_i128(call("erlang", "monotonic_time", &[]));
    for _ in 0..1000 {
        let mono = as_i128(call("erlang", "monotonic_time", &[]));
        assert!(mono >= prior);
        prior = mono;
        let offset = as_i128(call("erlang", "time_offset", &[]));
        let wall = as_i128(call("erlang", "system_time", &[]));
        assert!((mono + offset - wall).abs() < 100_000_000);
        let unit = [atom("second")];
        let mono_seconds = as_i128(call("erlang", "monotonic_time", &unit));
        assert!((mono.div_euclid(1_000_000_000) - mono_seconds).abs() <= 1);
        let offset_seconds = as_i128(call("erlang", "time_offset", &unit));
        assert!((offset.div_euclid(1_000_000_000) - offset_seconds).abs() <= 1);
    }
    let offset = call("erlang", "time_offset", &[]);
    let native_offset = call("erlang", "time_offset", &[atom("native")]);
    assert_eq!(
        offset, native_offset,
        "time_offset unit results must share a snapshot"
    );
    for (date, hour) in [
        ((2020, 1, 1), 12),
        ((2020, 7, 1), 12),
        ((2020, 3, 29), 2),
        ((2020, 10, 25), 2),
    ] {
        let datetime = O::Tuple(vec![
            O::Tuple(vec![O::Int(date.0), O::Int(date.1), O::Int(date.2)]),
            O::Tuple(vec![O::Int(hour), O::Int(30), O::Int(0)]),
        ]);
        for flag in ["true", "false", "undefined"] {
            let input = [datetime.clone(), atom(flag)];
            let actual = call("erlang", "localtime_to_universaltime", &input);
            let expected = reference.call("erlang", "localtime_to_universaltime", &input);
            assert!(
                equivalent(&actual, &expected),
                "{date:?} {flag}: {actual:?} != {expected:?}"
            );
        }
    }
    for n in -500..500 {
        let input = [O::Int(n), atom("nanosecond"), atom("microsecond")];
        let actual = call("erlang", "convert_time_unit", &input);
        let expected = reference.call("erlang", "convert_time_unit", &input);
        assert!(
            equivalent(&actual, &expected),
            "convert_time_unit {input:?}: {actual:?} != {expected:?}"
        );
    }
    let timestamp_micros = |result: arinsal_difftest::CallResult| -> i64 {
        let arinsal_difftest::CallResult::Ok(O::Tuple(ref parts)) = result else {
            panic!("expected timestamp tuple")
        };
        let [O::Int(mega), O::Int(secs), O::Int(micros)] = parts.as_slice() else {
            panic!("expected timestamp integers")
        };
        mega * 1_000_000_000_000 + secs * 1_000_000 + micros
    };
    let mut previous_now = 0;
    for _ in 0..1000 {
        for (module, name) in [
            ("erlang", "timestamp"),
            ("os", "timestamp"),
            ("erlang", "now"),
        ] {
            let before = timestamp_micros(reference.call(module, name, &[]));
            let actual = timestamp_micros(call(module, name, &[]));
            let after = timestamp_micros(reference.call(module, name, &[]));
            assert!(actual >= before - 2_000_000 && actual <= after + 2_000_000);
            if name == "now" {
                assert!(actual > previous_now);
                previous_now = actual;
            }
        }
        for name in ["time", "date", "localtime", "universaltime"] {
            let before = reference.call("erlang", name, &[]);
            let actual = call("erlang", name, &[]);
            let after = reference.call("erlang", name, &[]);
            assert!(
                equivalent(&actual, &before) || equivalent(&actual, &after),
                "{name}: {actual:?} != {before:?} or {after:?}"
            );
        }
    }
    let mut heap = ProcessHeap::with_words(128);
    let mut allocator = ProcessHeapHandle(&mut heap);
    let mut ctx = Ctx::new(&mut allocator);
    let bif = lookup("erlang", "monotonic_time", 0).expect("monotonic_time BIF");
    let started = std::time::Instant::now();
    for _ in 0..1_000_000 {
        std::hint::black_box(bif(&mut ctx, &[]).expect("clock"));
    }
    println!(
        "monotonic_time BIF: {:.1} ns/call",
        started.elapsed().as_nanos() as f64 / 1_000_000.0
    );
}

#[test]
#[ignore = "performance measurement; run with --release --ignored --nocapture"]
fn binary_search_megabyte_benchmark() {
    let mut heap = ProcessHeap::with_words(1024);
    let mut subject = vec![b'a'; 1_000_000];
    subject[999_990..999_998].copy_from_slice(b"bbbbbbbb");
    let mut builder = TermBuilder::new(&mut heap);
    let haystack = builder.binary(&subject).expect("subject");
    let needle = builder.binary(b"bbbbbbbb").expect("needle");
    let second_needle = builder.binary(b"cccccccc").expect("second needle");
    let tail = builder
        .cons(second_needle, arinsal_term::Term::NIL)
        .expect("tail");
    let patterns = builder.cons(needle, tail).expect("patterns");
    let single = lookup("binary", "match", 2).expect("match BIF");
    let mut allocator = ProcessHeapHandle(&mut heap);
    let mut ctx = Ctx::new(&mut allocator);
    let started = std::time::Instant::now();
    for _ in 0..200 {
        std::hint::black_box(single(&mut ctx, &[haystack, needle]).expect("match"));
    }
    println!(
        "binary:match/2, 1 MB single pattern: {:.1} us/call",
        started.elapsed().as_secs_f64() * 1e6 / 200.0
    );
    let started = std::time::Instant::now();
    for _ in 0..200 {
        std::hint::black_box(single(&mut ctx, &[haystack, patterns]).expect("multi match"));
    }
    println!(
        "binary:match/2, 1 MB two patterns: {:.1} us/call",
        started.elapsed().as_secs_f64() * 1e6 / 200.0
    );
}

#[test]
fn map_bifs_handle_hamt() {
    let reference = RefErl::shared().expect("OTP 29 reference");
    let mut heap = ProcessHeap::with_words(4096);
    let pairs = (0..40)
        .map(|n| {
            (
                arinsal_term::Term::small(n).unwrap(),
                arinsal_term::Term::small(n * 10).unwrap(),
            )
        })
        .collect::<Vec<_>>();
    let map = arinsal_maps::from_pairs(&pairs, &mut heap).expect("HAMT");
    assert!(map.is_hashmap());
    let mut allocator = ProcessHeapHandle(&mut heap);
    let mut ctx = Ctx::new(&mut allocator);
    let bif = lookup("maps", "get", 2).expect("maps:get/2");
    for n in 0..40 {
        let key = arinsal_term::Term::small(n).unwrap();
        let actual = arinsal_difftest::CallResult::Ok(
            to_owned(bif(&mut ctx, &[key, map]).expect("value")).expect("term"),
        );
        let input = [
            O::Int(n),
            O::Map((0..40).map(|i| (O::Int(i), O::Int(i * 10))).collect()),
        ];
        let expected = reference.call("maps", "get", &input);
        assert!(
            equivalent(&actual, &expected),
            "n={n}: {actual:?} != {expected:?}"
        );
    }
}

#[test]
fn system_info_snifs_matches_otp() {
    let reference = RefErl::shared().expect("OTP 29 reference");
    let expected = reference.call("erlang", "system_info", &[atom("snifs")]);
    let mut heap = ProcessHeap::with_words(16_384);
    let mut allocator = ProcessHeapHandle(&mut heap);
    let selector = arinsal_term::from_owned(&atom("snifs"), &mut allocator).unwrap();
    let mut ctx = Ctx::new(&mut allocator);
    let actual = lookup("erlang", "system_info", 1).unwrap()(&mut ctx, &[selector]).unwrap();
    let actual = CallResult::Ok(to_owned(actual).unwrap());
    assert!(equivalent(&actual, &expected), "{actual:?} != {expected:?}");
}

#[test]
fn binary_to_atom_oversized_name_is_system_limit() {
    let reference = RefErl::shared().expect("OTP 29 reference");
    for mut bytes in [vec![0; 256], vec![0; 512]] {
        if bytes.len() == 512 {
            bytes.push(255);
        }
        let bytes = O::Binary(bytes);
        let expected = reference.call("erlang", "binary_to_atom", &[bytes.clone(), atom("utf8")]);
        let actual = call("erlang", "binary_to_atom", &[bytes, atom("utf8")]);
        assert!(
            matches!(actual, CallResult::Exception { reason: O::Atom(ref name), .. } if name == "system_limit"),
            "actual result: {actual:?}"
        );
        assert!(
            matches!(expected, CallResult::Exception { reason: O::Atom(ref name), .. } if name == "system_limit"),
            "OTP result: {expected:?}"
        );
    }
}

#[test]
fn is_builtin_includes_instruction_implemented_exports() {
    let reference = RefErl::shared().expect("OTP 29 reference");
    for (name, arity) in [("apply", 2), ("apply", 3), ("yield", 0)] {
        let input = [atom("erlang"), atom(name), O::Int(arity)];
        let expected = reference.call("erlang", "is_builtin", &input);
        let actual = call("erlang", "is_builtin", &input);
        assert!(equivalent(&actual, &expected), "{actual:?} != {expected:?}");
        assert_eq!(actual, CallResult::Ok(atom("true")));
    }
}

#[test]
fn iolist_to_iovec_preserves_large_binary_segments() {
    let reference = RefErl::shared().expect("OTP 29 reference");
    let input = O::List {
        elems: vec![
            O::Binary(vec![1]),
            O::Binary(vec![2; 1012]),
            O::Binary(vec![3; 1012]),
        ],
        tail: Box::new(O::Nil),
    };
    let expected = reference.call("erlang", "iolist_to_iovec", std::slice::from_ref(&input));
    let actual = call("erlang", "iolist_to_iovec", &[input]);
    assert!(equivalent(&actual, &expected), "{actual:?} != {expected:?}");
    let CallResult::Ok(O::List { elems, tail }) = &actual else {
        panic!("unexpected iovec result: {actual:?}");
    };
    assert_eq!(elems.len(), 3);
    assert_eq!(tail.as_ref(), &O::Nil);
}

#[test]
fn reverse_bulk_cons_matches_otp_29() {
    let reference = RefErl::shared().expect("OTP 29 reference");
    for size in [0, 1, 1_024, 10_000] {
        let input = O::list((0..size).map(O::Int).collect());
        let args = [input, atom("tail")];
        let actual = call("lists", "reverse", &args);
        let expected = reference.call("lists", "reverse", &args);
        assert!(equivalent(&actual, &expected), "size={size}: {actual:?}");
    }
    let args = [
        O::List {
            elems: vec![O::Int(1)],
            tail: Box::new(atom("improper")),
        },
        O::Nil,
    ];
    assert!(equivalent(
        &call("lists", "reverse", &args),
        &reference.call("lists", "reverse", &args)
    ));
}

#[test]
fn identity_bifs_are_unique_across_threads() {
    let threads = (0..8)
        .map(|_| {
            std::thread::spawn(|| {
                let mut integers = Vec::new();
                let mut references = Vec::new();
                for _ in 0..1000 {
                    let input = [list(vec![atom("positive"), atom("monotonic")])];
                    let arinsal_difftest::CallResult::Ok(O::Int(value)) =
                        call("erlang", "unique_integer", &input)
                    else {
                        panic!("integer")
                    };
                    integers.push(value);
                    let arinsal_difftest::CallResult::Ok(O::Ref { ref ids, .. }) =
                        call("erlang", "make_ref", &[])
                    else {
                        panic!("reference")
                    };
                    references.push(ids.clone());
                }
                (integers, references)
            })
        })
        .collect::<Vec<_>>();
    let mut all_integers = HashSet::new();
    let mut all_references = HashSet::new();
    for thread in threads {
        let (integers, references) = thread.join().expect("worker");
        assert!(integers.windows(2).all(|pair| pair[0] < pair[1]));
        for value in integers {
            assert!(all_integers.insert(value));
        }
        for value in references {
            assert!(all_references.insert(value));
        }
    }
    assert_eq!(all_integers.len(), 8000);
    assert_eq!(all_references.len(), 8000);
}

#[test]
fn map_error_reasons_match_otp() {
    let reference = RefErl::shared().expect("OTP 29 reference");
    let empty = O::Map(vec![]);
    for (module, name, input) in [
        ("maps", "get", vec![atom("missing"), empty.clone()]),
        ("maps", "get", vec![atom("missing"), atom("not_map")]),
        ("maps", "find", vec![atom("missing"), atom("not_map")]),
        (
            "maps",
            "update",
            vec![atom("missing"), O::Int(1), empty.clone()],
        ),
        ("maps", "remove", vec![atom("missing"), atom("not_map")]),
        ("maps", "take", vec![atom("missing"), atom("not_map")]),
        ("erlang", "map_get", vec![atom("missing"), empty.clone()]),
        ("erlang", "map_size", vec![atom("not_map")]),
    ] {
        let actual = call(module, name, &input);
        let expected = reference.call(module, name, &input);
        match (actual, expected) {
            (
                arinsal_difftest::CallResult::Exception {
                    class: a_class,
                    reason: a_reason,
                    ..
                },
                arinsal_difftest::CallResult::Exception {
                    class: e_class,
                    reason: e_reason,
                    ..
                },
            ) => {
                assert_eq!((a_class, a_reason), (e_class, e_reason), "{module}:{name}");
            }
            (actual, expected) => panic!("{module}:{name}: {actual:?} != {expected:?}"),
        }
    }
}

#[test]
fn one_byte_pattern_search_matches_otp_29() {
    let reference = RefErl::shared().expect("OTP 29 reference");
    let subject = O::Binary(b"abracadabra".to_vec());
    let aye = O::Binary(b"a".to_vec());
    let zee = O::Binary(b"z".to_vec());
    let dash = O::Binary(b"-".to_vec());
    let dashed = O::Binary(b"a-b-a".to_vec());
    let scope_hit = list(vec![O::Tuple(vec![
        atom("scope"),
        O::Tuple(vec![O::Int(3), O::Int(5)]),
    ])]);
    let scope_miss = list(vec![O::Tuple(vec![
        atom("scope"),
        O::Tuple(vec![O::Int(1), O::Int(2)]),
    ])]);
    let scope_dash = list(vec![O::Tuple(vec![
        atom("scope"),
        O::Tuple(vec![O::Int(2), O::Int(3)]),
    ])]);
    let cases = [
        ("match", vec![subject.clone(), aye.clone()]),
        ("match", vec![subject.clone(), zee.clone()]),
        (
            "match",
            vec![subject.clone(), aye.clone(), scope_hit.clone()],
        ),
        (
            "match",
            vec![subject.clone(), aye.clone(), scope_miss.clone()],
        ),
        ("matches", vec![subject.clone(), aye.clone()]),
        ("matches", vec![subject.clone(), zee.clone()]),
        (
            "matches",
            vec![subject.clone(), aye.clone(), scope_hit.clone()],
        ),
        ("matches", vec![O::Binary(Vec::new()), aye.clone()]),
        ("split", vec![dashed.clone(), dash.clone()]),
        ("split", vec![subject.clone(), zee.clone()]),
        (
            "split",
            vec![dashed.clone(), dash.clone(), scope_dash.clone()],
        ),
    ];
    for (name, args) in cases {
        let actual = call("binary", name, &args);
        let expected = reference.call("binary", name, &args);
        assert!(
            equivalent(&actual, &expected),
            "binary:{name} {args:?}: {actual:?} != {expected:?}"
        );
    }

    // A compiled 1-byte pattern is still Boyer–Moore (`words == 1` in
    // do_binary_match_compile). erl's compile_pattern result matches the raw pattern.
    let mut heap = ProcessHeap::with_words(1024);
    let mut allocator = ProcessHeapHandle(&mut heap);
    let subject_term = from_owned(&subject, &mut allocator).unwrap();
    let aye_term = from_owned(&aye, &mut allocator).unwrap();
    let dash_term = from_owned(&dash, &mut allocator).unwrap();
    let dashed_term = from_owned(&dashed, &mut allocator).unwrap();
    let scope_term = from_owned(&scope_hit, &mut allocator).unwrap();
    let mut ctx = Ctx::new(&mut allocator);
    let compile = lookup("binary", "compile_pattern", 1).unwrap();
    let aye_pattern = compile(&mut ctx, &[aye_term]).unwrap();
    let dash_pattern = compile(&mut ctx, &[dash_term]).unwrap();
    let compiled_cases: &[(&str, u8, Vec<_>, &str)] = &[
        (
            "match",
            2,
            vec![subject_term, aye_pattern],
            "binary:match(<<\"abracadabra\">>, binary:compile_pattern(<<\"a\">>))",
        ),
        (
            "matches",
            3,
            vec![subject_term, aye_pattern, scope_term],
            "binary:matches(<<\"abracadabra\">>, binary:compile_pattern(<<\"a\">>), [{scope,{3,5}}])",
        ),
        (
            "split",
            2,
            vec![dashed_term, dash_pattern],
            "binary:split(<<\"a-b-a\">>, binary:compile_pattern(<<\"-\">>))",
        ),
    ];
    for (name, arity, args, expr) in compiled_cases {
        let bif = lookup("binary", name, *arity).unwrap();
        let mut ctx = Ctx::new(&mut allocator);
        let actual = CallResult::Ok(to_owned(bif(&mut ctx, args).unwrap()).unwrap());
        let expected = CallResult::Ok(reference.eval(expr).unwrap());
        assert!(
            equivalent(&actual, &expected),
            "compiled binary:{name}: {actual:?} != {expected:?}"
        );
    }
}

#[test]
fn binary_match_accepts_unaligned_subbinary() {
    let reference = RefErl::shared().expect("OTP 29 reference");
    let mut heap = ProcessHeap::with_words(128);
    let mut builder = TermBuilder::new(&mut heap);
    let backing = builder
        .binary(&[0b0100_0000, 0b1100_0000])
        .expect("backing");
    let subject = builder.sub_binary(backing, 1, 8).expect("subbinary");
    let needle = builder.binary(&[0b1000_0001]).expect("needle");
    let mut allocator = ProcessHeapHandle(&mut heap);
    let mut ctx = Ctx::new(&mut allocator);
    let bif = lookup("binary", "match", 2).expect("BIF");
    let actual = arinsal_difftest::CallResult::Ok(
        to_owned(bif(&mut ctx, &[subject, needle]).expect("match")).expect("term"),
    );
    let expected = reference.call(
        "binary",
        "match",
        &[O::Binary(vec![0b1000_0001]), O::Binary(vec![0b1000_0001])],
    );
    assert!(equivalent(&actual, &expected), "{actual:?} != {expected:?}");
}

#[test]
fn binary_reads_and_bit_copies_handle_unaligned_subbinary() {
    let reference = RefErl::shared().expect("OTP 29 reference");
    let mut heap = ProcessHeap::with_words(512);
    let mut builder = TermBuilder::new(&mut heap);
    let backing = builder
        .binary(&[0b0100_0000, 0b1100_0000, 0b0100_0000])
        .expect("backing");
    let subject = builder.sub_binary(backing, 1, 16).expect("subbinary");
    let needle = builder.binary(&[0b1000_0000]).expect("needle");

    let mut unaligned_copy = [0];
    copy_bitstring_range(subject, 4, &mut unaligned_copy, 8).expect("unaligned copy");
    assert_eq!(unaligned_copy, [0b0001_1000]);
    let mut aligned_copy = [0];
    copy_bitstring_range(subject, 8, &mut aligned_copy, 8).expect("aligned copy");
    assert_eq!(aligned_copy, [0b1000_0000]);

    let mut allocator = ProcessHeapHandle(&mut heap);
    let reference_subject = O::Binary(vec![0b1000_0001, 0b1000_0000]);
    for (module, name, args) in [
        ("erlang", "binary_to_list", vec![subject]),
        (
            "binary",
            "at",
            vec![subject, arinsal_term::Term::small(1).unwrap()],
        ),
        ("binary", "match", vec![subject, needle]),
        ("binary", "split", vec![subject, needle]),
    ] {
        let bif = lookup(module, name, args.len() as u8).expect("BIF");
        let mut ctx = Ctx::new(&mut allocator);
        let actual = CallResult::Ok(to_owned(bif(&mut ctx, &args).expect("BIF succeeds")).unwrap());
        let remote_args = if name == "at" {
            vec![reference_subject.clone(), O::Int(1)]
        } else if name == "binary_to_list" {
            vec![reference_subject.clone()]
        } else {
            vec![reference_subject.clone(), O::Binary(vec![0b1000_0000])]
        };
        let expected = reference.call(module, name, &remote_args);
        assert!(
            equivalent(&actual, &expected),
            "{module}:{name}: {actual:?} != {expected:?}"
        );
    }
}

#[test]
fn make_tuple_rejects_arity_above_erts_limit() {
    let reference = RefErl::shared().expect("OTP 29 reference");
    let args = [O::Int(1 << 24), atom("value")];
    let actual = call("erlang", "make_tuple", &args);
    let expected = reference.call("erlang", "make_tuple", &args);
    match (actual, expected) {
        (
            arinsal_difftest::CallResult::Exception {
                class: actual_class,
                reason: actual_reason,
                ..
            },
            arinsal_difftest::CallResult::Exception {
                class: expected_class,
                reason: expected_reason,
                ..
            },
        ) => assert_eq!(
            (actual_class, actual_reason),
            (expected_class, expected_reason)
        ),
        (actual, expected) => panic!("{actual:?} != {expected:?}"),
    }
}

#[test]
fn cmp_term_uses_exact_numeric_order_inside_containers() {
    let reference = RefErl::shared().expect("OTP 29 reference");
    for (left, right) in [
        (O::list(vec![O::Int(-2)]), O::list(vec![O::Float(-2.0)])),
        (O::Int(1_i64 << 62), O::Float(1.0)),
        (
            O::Tuple(vec![atom("key"), O::Int(5)]),
            O::Tuple(vec![atom("key"), O::Float(5.0)]),
        ),
    ] {
        let args = [left, right];
        let actual = call("erts_internal", "cmp_term", &args);
        let expected = reference.call("erts_internal", "cmp_term", &args);
        assert_eq!(actual, expected);
    }
}

#[test]
fn list_bif_loops_match_otp_29() {
    let reference = RefErl::shared().expect("OTP 29 reference");
    let seq = O::list((1..8).map(O::Int).collect());
    let tuples = O::list(vec![
        O::Tuple(vec![O::Float(1.0), atom("a")]),
        O::Tuple(vec![O::Int(2), atom("b")]),
        O::Tuple(vec![atom("c"), atom("d")]),
    ]);
    let improper = O::List {
        elems: vec![O::Int(1)],
        tail: Box::new(atom("tail")),
    };
    let cases: &[(&str, &str, Vec<O>)] = &[
        ("erlang", "length", vec![O::Nil]),
        ("erlang", "length", vec![seq.clone()]),
        ("erlang", "length", vec![improper.clone()]),
        ("erlang", "++", vec![O::Nil, atom("rhs")]),
        ("erlang", "++", vec![seq.clone(), O::Nil]),
        ("erlang", "++", vec![seq.clone(), O::list(vec![atom("z")])]),
        ("erlang", "++", vec![improper.clone(), O::Nil]),
        ("lists", "reverse", vec![O::Nil, atom("tail")]),
        ("lists", "reverse", vec![seq.clone(), atom("tail")]),
        ("lists", "reverse", vec![improper.clone(), O::Nil]),
        ("lists", "member", vec![O::Int(7), seq.clone()]),
        ("lists", "member", vec![O::Int(9), seq.clone()]),
        ("lists", "member", vec![O::Float(1.0), seq.clone()]),
        ("lists", "member", vec![O::Int(1), improper.clone()]),
        (
            "lists",
            "keyfind",
            vec![O::Int(1), O::Int(1), tuples.clone()],
        ),
        (
            "lists",
            "keyfind",
            vec![O::Int(2), O::Int(1), tuples.clone()],
        ),
        (
            "lists",
            "keyfind",
            vec![atom("c"), O::Int(1), tuples.clone()],
        ),
        (
            "lists",
            "keyfind",
            vec![O::Int(9), O::Int(1), tuples.clone()],
        ),
        (
            "lists",
            "keyfind",
            vec![O::Int(1), O::Int(0), tuples.clone()],
        ),
        (
            "lists",
            "keymember",
            vec![O::Int(1), O::Int(1), tuples.clone()],
        ),
        ("lists", "keysearch", vec![O::Int(2), O::Int(1), tuples]),
        (
            "erlang",
            "--",
            vec![
                seq.clone(),
                O::list(vec![O::Int(2), O::Float(2.0), O::Int(4)]),
            ],
        ),
    ];
    for (module, name, args) in cases {
        let actual = call(module, name, args);
        let expected = reference.call(module, name, args);
        assert!(
            equivalent(&actual, &expected),
            "{module}:{name} {args:?}: {actual:?} != {expected:?}"
        );
    }
}
