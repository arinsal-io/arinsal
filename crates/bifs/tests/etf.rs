mod support;

use arinsal_bifs::{Ctx, FragmentingHeap, lookup};
use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::{EncodeOptions, OwnedTerm as O};
use arinsal_term::{ProcessHeap, Term, TermBuilder, exact_eq, from_owned, global_atoms, to_owned};
use proptest::strategy::{Strategy, ValueTree};
use proptest::test_runner::TestRunner;
use support::{call, equivalent};

fn opts() -> Vec<O> {
    vec![
        O::Nil,
        O::list(vec![O::atom("compressed")]),
        O::list(vec![O::Tuple(vec![O::atom("compressed"), O::Int(9)])]),
        O::list(vec![O::Tuple(vec![O::atom("minor_version"), O::Int(0)])]),
        O::list(vec![O::Tuple(vec![O::atom("minor_version"), O::Int(1)])]),
        O::list(vec![O::atom("deterministic")]),
    ]
}

#[test]
fn heap_etf_matches_otp_examples() {
    let reference = RefErl::shared().expect("OTP 29 reference");
    let terms = [
        O::Int(-1),
        O::Int(0),
        O::Int(255),
        O::Int(256),
        O::Float(-0.0),
        O::Float(1.25),
        O::atom("猫"),
        O::Nil,
        O::Tuple(vec![O::atom("a"), O::Int(42), O::Binary(vec![1, 2])]),
        O::list(vec![O::Int(1), O::Int(2), O::Int(3)]),
        O::List {
            elems: vec![O::Int(1)],
            tail: Box::new(O::atom("tail")),
        },
        O::Binary(Vec::new()),
        O::Binary(vec![7; 1000]),
        O::BitString {
            bytes: vec![0b1010_0000],
            bits: 3,
        },
        O::Map(vec![(O::Int(2), O::atom("b")), (O::Int(1), O::atom("a"))]),
    ];
    for term in terms {
        for option in opts() {
            let args = [term.clone(), option.clone()];
            let ours = call("erlang", "term_to_binary", &args);
            let otp = reference.call("erlang", "term_to_binary", &args);
            assert_eq!(ours, otp, "encode {term:?}, {option:?}");
            if let CallResult::Ok(binary) = otp {
                let decoded = call("erlang", "binary_to_term", std::slice::from_ref(&binary));
                let otp_decoded = reference.call("erlang", "binary_to_term", &[binary]);
                assert_decoded_same(&decoded, &otp_decoded, &format!("decode {term:?}"));
                let size = call("erlang", "external_size", &args);
                let expected_size = reference.call("erlang", "external_size", &args);
                assert_eq!(size, expected_size, "size {term:?}, {option:?}");
            }
        }
    }
}

#[test]
fn deterministic_map_order_compares_numeric_values_before_number_kind() {
    let reference = RefErl::shared().expect("OTP 29 reference");
    let term = O::Map(vec![
        (O::Int(3_811_614), O::Int(99)),
        (O::Float(1.0), O::atom("b")),
        (O::Int(1), O::atom("a")),
    ]);
    let args = [term, O::list(vec![O::atom("deterministic")])];
    assert_eq!(
        call("erlang", "term_to_binary", &args),
        reference.call("erlang", "term_to_binary", &args),
    );
}

#[test]
fn serialization_bif_reports_work_for_scheduler_accounting() {
    let mut heap = ProcessHeap::with_words(4096);
    let mut allocator = FragmentingHeap(&mut heap);
    let input = TermBuilder::new(&mut allocator).binary(&[7; 4096]).unwrap();
    let bif = lookup("erlang", "term_to_binary", 1).unwrap();
    let mut ctx = Ctx::new(&mut allocator);
    bif(&mut ctx, &[input]).unwrap();
    assert!(ctx.reductions() > 0);
}

#[test]
fn malformed_bytes_return_badarg() {
    let reference = RefErl::shared().expect("OTP 29 reference");
    for len in 0..80 {
        let mut data = vec![0; len];
        for (i, byte) in data.iter_mut().enumerate() {
            *byte = (len.wrapping_mul(79) + i.wrapping_mul(131)) as u8;
        }
        let args = [O::Binary(data)];
        let ours = call("erlang", "binary_to_term", &args);
        let otp = reference.call("erlang", "binary_to_term", &args);
        assert!(
            equivalent(&ours, &otp),
            "input length {len}: {ours:?} != {otp:?}"
        );
    }
}

#[test]
fn random_heap_terms_match_otp_bytes() {
    let reference = RefErl::shared().expect("OTP 29 reference");
    let mut runner = TestRunner::deterministic();
    let strategy = arinsal_difftest::gens::any_term();
    let local_fun = reference.eval("fun(X) -> X + 1 end").expect("local fun");
    for case in 0..20_000 {
        let mut term = strategy
            .new_tree(&mut runner)
            .expect("generated term")
            .current();
        term = match case % 97 {
            0 => O::Map(
                (0..33 + case % 70)
                    .map(|i| (O::Int(i as i64), O::Int((i * i) as i64)))
                    .collect(),
            ),
            1 => {
                let bits = (case % 8 + 1) as u8;
                if bits == 8 {
                    O::Binary(vec![0xa5])
                } else {
                    O::BitString {
                        bytes: vec![0xa5 & (0xff << (8 - bits))],
                        bits,
                    }
                }
            }
            2 => local_fun.clone(),
            3 => O::Pid {
                node: "nonode@nohost".into(),
                id: 7,
                serial: 0,
                creation: 0,
            },
            4 => O::Ref {
                node: "nonode@nohost".into(),
                creation: 0,
                ids: vec![1, 2, 3],
            },
            5 => (0..128).fold(O::Int(1), |inner, _| O::Tuple(vec![inner])),
            _ => term,
        };
        for option in opts() {
            let args = [term.clone(), option.clone()];
            let ours = call("erlang", "term_to_binary", &args);
            let otp = reference.call("erlang", "term_to_binary", &args);
            if ours != otp {
                match (&ours, &otp) {
                    (CallResult::Ok(O::Binary(a)), CallResult::Ok(O::Binary(b))) => {
                        let offset = a.iter().zip(b).position(|(x, y)| x != y);
                        panic!(
                            "case {case}, option {option:?}, length {} != {}, first mismatch {offset:?}, ours {:?}, otp {:?}, term {term:?}",
                            a.len(),
                            b.len(),
                            &a[..a.len().min(60)],
                            &b[..b.len().min(60)]
                        );
                    }
                    _ => panic!("case {case}, {ours:?} != {otp:?}"),
                }
            }
            if let CallResult::Ok(binary) = otp {
                let decoded = call("erlang", "binary_to_term", std::slice::from_ref(&binary));
                let expected = reference.call("erlang", "binary_to_term", &[binary]);
                assert_decoded_same(&decoded, &expected, &format!("decode case {case}"));
            }
        }
    }
}

fn assert_decoded_same(actual: &CallResult, expected: &CallResult, case: &str) {
    match (actual, expected) {
        (CallResult::Ok(a), CallResult::Ok(b)) => {
            let a = arinsal_etf::encode(
                &canonical(a),
                EncodeOptions {
                    deterministic: true,
                    ..EncodeOptions::default()
                },
            );
            let b = arinsal_etf::encode(
                &canonical(b),
                EncodeOptions {
                    deterministic: true,
                    ..EncodeOptions::default()
                },
            );
            assert_eq!(a, b, "{case}");
        }
        _ => assert!(
            equivalent(actual, expected),
            "{case}: {actual:?} != {expected:?}"
        ),
    }
}

fn canonical(term: &O) -> O {
    match term {
        O::BigInt(n) => n
            .to_string()
            .parse::<i64>()
            .map(O::Int)
            .unwrap_or_else(|_| term.clone()),
        O::Tuple(values) => O::Tuple(values.iter().map(canonical).collect()),
        O::List { elems, tail } => O::List {
            elems: elems.iter().map(canonical).collect(),
            tail: Box::new(canonical(tail)),
        },
        O::Map(pairs) => {
            let mut pairs: Vec<_> = pairs
                .iter()
                .map(|(k, v)| (canonical(k), canonical(v)))
                .collect();
            pairs.sort_by(|a, b| arinsal_etf::erl_cmp(&a.0, &b.0));
            O::Map(pairs)
        }
        _ => term.clone(),
    }
}

#[test]
fn ten_thousand_malformed_inputs_match_otp_errors() {
    let reference = RefErl::shared().expect("OTP 29 reference");
    let mut state = 0x7fc2_9198_3e5a_0011_u64;
    for case in 0..10_000 {
        let len = (case * 37 % 151) as usize;
        let mut bytes = vec![0; len];
        for byte in &mut bytes {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            *byte = state as u8;
        }
        if case % 2 == 0 && !bytes.is_empty() {
            bytes[0] = 131;
        }
        // Internal atom references use VM-local atom indexes, which differ between OTP and Arinsal.
        if bytes.len() > 1 && matches!(bytes[1], 73 | 75) {
            bytes[1] = 82;
        }
        let args = [O::Binary(bytes)];
        let ours = call("erlang", "binary_to_term", &args);
        let otp = reference.call("erlang", "binary_to_term", &args);
        assert!(
            equivalent(&ours, &otp),
            "case {case}, args {args:?}: {ours:?} != {otp:?}"
        );
    }
}

#[test]
fn large_maps_bitstrings_and_identities_match_otp() {
    let reference = RefErl::shared().expect("OTP 29 reference");
    let mut terms = vec![
        O::Pid {
            node: "nonode@nohost".into(),
            id: 7,
            serial: 0,
            creation: 0,
        },
        O::Port {
            node: "nonode@nohost".into(),
            id: 12,
            creation: 0,
        },
        O::Ref {
            node: "nonode@nohost".into(),
            creation: 0,
            ids: vec![1, 2, 3],
        },
        O::Export {
            module: "erlang".into(),
            function: "length".into(),
            arity: 1,
        },
    ];
    for bits in 1..8 {
        terms.push(O::BitString {
            bytes: vec![0xa5, 0xff << (8 - bits)],
            bits,
        });
    }
    for count in [33, 100, 1000] {
        terms.push(O::Map(
            (0..count).map(|i| (O::Int(i), O::Int(i * i))).collect(),
        ));
    }
    for (case, term) in terms.into_iter().enumerate() {
        for option in opts() {
            let args = [term.clone(), option.clone()];
            let ours = call("erlang", "term_to_binary", &args);
            let otp = reference.call("erlang", "term_to_binary", &args);
            assert_eq!(ours, otp, "case {case}, option {option:?}");
            if let CallResult::Ok(binary) = otp {
                let ours = call("erlang", "binary_to_term", std::slice::from_ref(&binary));
                let otp = reference.call("erlang", "binary_to_term", &[binary]);
                assert_decoded_same(&ours, &otp, &format!("decode case {case}"));
            }
        }
    }
}

#[test]
fn used_safe_and_iovec_match_otp() {
    let reference = RefErl::shared().expect("OTP 29 reference");
    let terms = [
        O::Int(42),
        O::Binary(vec![1; 65]),
        O::Tuple(vec![
            O::Binary(vec![0; 100]),
            O::atom("ok"),
            O::Binary(vec![2; 100]),
        ]),
    ];
    for term in terms {
        for option in [
            O::Nil,
            O::list(vec![O::atom("compressed")]),
            O::list(vec![O::Tuple(vec![O::atom("compressed"), O::Int(0)])]),
        ] {
            let args = [term.clone(), option];
            assert_eq!(
                call("erlang", "term_to_iovec", &args),
                reference.call("erlang", "term_to_iovec", &args)
            );
        }
    }
    let bytes = O::Binary(vec![131, 97, 42, 0, 1]);
    for option in [
        O::list(vec![O::atom("used")]),
        O::list(vec![O::atom("safe")]),
        O::list(vec![O::atom("safe"), O::atom("used")]),
    ] {
        let args = [bytes.clone(), option];
        assert_eq!(
            call("erlang", "binary_to_term", &args),
            reference.call("erlang", "binary_to_term", &args)
        );
    }
    let unknown = O::Binary(vec![
        131, 119, 15, b'u', b'n', b'k', b'n', b'o', b'w', b'n', b'_', b'e', b't', b'f', b'_', b'a',
        b't', b'm',
    ]);
    let args = [unknown, O::list(vec![O::atom("safe")])];
    assert!(equivalent(
        &call("erlang", "binary_to_term", &args),
        &reference.call("erlang", "binary_to_term", &args)
    ));
}

#[test]
fn million_deep_list_and_tuple_use_iterative_codec() {
    for tuple in [false, true] {
        let mut input_heap = ProcessHeap::with_words(2_100_000);
        let mut input = Term::small(1).unwrap();
        {
            let mut builder = TermBuilder::new(&mut input_heap);
            for _ in 0..1_000_000 {
                input = if tuple {
                    builder.tuple(&[input]).unwrap()
                } else {
                    builder.cons(input, Term::NIL).unwrap()
                };
            }
        }
        let mut input_alloc = FragmentingHeap(&mut input_heap);
        let binary = lookup("erlang", "term_to_binary", 1).unwrap()(
            &mut Ctx::new(&mut input_alloc),
            &[input],
        )
        .unwrap();
        let mut output_heap = ProcessHeap::with_words(2_100_000);
        let mut output_alloc = FragmentingHeap(&mut output_heap);
        let decoded = lookup("erlang", "binary_to_term", 1).unwrap()(
            &mut Ctx::new(&mut output_alloc),
            &[binary],
        )
        .unwrap();
        assert!(exact_eq(input, decoded), "tuple={tuple}");
    }
}

#[test]
fn local_fun_bytes_match_otp_when_transportable() {
    let reference = RefErl::shared().expect("OTP 29 reference");
    let fun = reference.eval("fun(X) -> X + 1 end").expect("local fun");
    let ours = call("erlang", "term_to_binary", std::slice::from_ref(&fun));
    let otp = reference.call("erlang", "term_to_binary", &[fun]);
    assert_eq!(ours, otp);
    if let CallResult::Ok(binary) = otp {
        let decoded = call("erlang", "binary_to_term", std::slice::from_ref(&binary));
        let expected = reference.call("erlang", "binary_to_term", &[binary]);
        assert_decoded_same(&decoded, &expected, "local fun decode");
    }
}

#[test]
fn native_record_bytes_match_otp() {
    let reference = RefErl::shared().expect("OTP 29 reference");
    let record = reference
        .eval("records:create(test_etf, sample, [{z,1},{a,[1,2]}], #{is_exported => true})")
        .expect("native record");
    for option in opts() {
        let otp = reference.call(
            "erlang",
            "term_to_binary",
            &[record.clone(), option.clone()],
        );
        let mut heap = ProcessHeap::with_words(1024);
        let mut allocator = FragmentingHeap(&mut heap);
        let option_term = from_owned(&option, &mut allocator).unwrap();
        let module = global_atoms().intern("test_etf").unwrap();
        let name = global_atoms().intern("sample").unwrap();
        let z = global_atoms().intern("z").unwrap();
        let a = global_atoms().intern("a").unwrap();
        let mut builder = TermBuilder::new(&mut allocator);
        let list = builder
            .list_from_iter([Term::small(1).unwrap(), Term::small(2).unwrap()])
            .unwrap();
        let native = builder
            .native_record(
                module,
                name,
                true,
                &[(z, Term::small(1).unwrap()), (a, list)],
            )
            .unwrap();
        let encoded = lookup("erlang", "term_to_binary", 2).unwrap()(
            &mut Ctx::new(&mut allocator),
            &[native, option_term],
        )
        .unwrap();
        let ours = CallResult::Ok(to_owned(encoded).unwrap());
        assert_eq!(ours, otp);
        if let CallResult::Ok(binary) = otp {
            let binary_term = from_owned(&binary, &mut allocator).unwrap();
            let decoded = lookup("erlang", "binary_to_term", 1).unwrap()(
                &mut Ctx::new(&mut allocator),
                &[binary_term],
            )
            .unwrap();
            let reencoded = lookup("erlang", "term_to_binary", 2).unwrap()(
                &mut Ctx::new(&mut allocator),
                &[decoded, option_term],
            )
            .unwrap();
            assert_eq!(to_owned(reencoded).unwrap(), binary);
        }
    }
}
