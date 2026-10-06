use arinsal_bifs::{BifError, Ctx};
use arinsal_difftest::{CallResult, CompareMode, RefErl, compare};
use arinsal_etf::OwnedTerm;
use arinsal_pterm::lookup;
use arinsal_term::{VecHeap, from_owned, to_owned};

fn local(name: &str, args: &[OwnedTerm]) -> CallResult {
    let mut heap = VecHeap::new();
    let args: Vec<_> = args
        .iter()
        .map(|arg| from_owned(arg, &mut heap).unwrap())
        .collect();
    let bif = lookup("persistent_term", name, args.len() as u8).unwrap();
    match bif(&mut Ctx::new(&mut heap), &args) {
        Ok(term) => CallResult::Ok(to_owned(term).unwrap()),
        Err(BifError::Badarg { .. }) => CallResult::Exception {
            class: "error".into(),
            reason: OwnedTerm::atom("badarg"),
            stack_top: None,
        },
        Err(other) => panic!("unexpected BIF error: {other:?}"),
    }
}

fn info_field(result: CallResult, field: &str) -> i64 {
    let CallResult::Ok(OwnedTerm::Map(pairs)) = &result else {
        panic!("expected info map")
    };
    pairs
        .iter()
        .find_map(|(key, value)| {
            if *key == OwnedTerm::atom(field) {
                if let OwnedTerm::Int(n) = value {
                    Some(*n)
                } else {
                    None
                }
            } else {
                None
            }
        })
        .expect("info field")
}
fn count(result: CallResult) -> i64 {
    info_field(result, "count")
}

fn contains_pair(result: CallResult, key: &OwnedTerm, value: &OwnedTerm) -> bool {
    let CallResult::Ok(OwnedTerm::List { elems, .. }) = &result else {
        panic!("expected get/0 list")
    };
    elems
        .iter()
        .any(|pair| pair == &OwnedTerm::Tuple(vec![key.clone(), value.clone()]))
}

fn next(seed: &mut u64) -> u64 {
    *seed = seed
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407);
    *seed >> 32
}

#[test]
fn random_sequences_match_otp_29() {
    let reference = match RefErl::start() {
        Ok(reference) => reference,
        Err(error) => {
            eprintln!("skipping differential test: erl unavailable: {error}");
            return;
        }
    };
    let ref_base = count(reference.call("persistent_term", "info", &[]));
    let local_base = count(local("info", &[]));
    let ref_memory = info_field(reference.call("persistent_term", "info", &[]), "memory");
    let local_memory = info_field(local("info", &[]), "memory");
    let probe_key = OwnedTerm::Tuple(vec![OwnedTerm::atom("s35b_probe"), OwnedTerm::Int(1)]);
    let probe_value = OwnedTerm::Tuple(vec![OwnedTerm::Int(3), OwnedTerm::Int(4)]);
    let probe = vec![probe_key.clone(), probe_value.clone()];
    compare(
        &local("put", &probe),
        &reference.call("persistent_term", "put", &probe),
        CompareMode::Exact,
    )
    .unwrap();
    assert!(contains_pair(local("get", &[]), &probe_key, &probe_value));
    assert!(contains_pair(
        reference.call("persistent_term", "get", &[]),
        &probe_key,
        &probe_value
    ));
    assert_eq!(info_field(local("info", &[]), "memory") - local_memory, 88);
    assert_eq!(
        info_field(reference.call("persistent_term", "info", &[]), "memory") - ref_memory,
        88
    );
    local("erase", std::slice::from_ref(&probe_key));
    reference.call("persistent_term", "erase", &[probe_key]);
    let mut values = vec![
        OwnedTerm::Int(42),
        OwnedTerm::Int(-77),
        OwnedTerm::BigInt("123456789123456789123456789".parse().unwrap()),
        OwnedTerm::Float(-0.0),
        OwnedTerm::atom("persistent_value"),
        OwnedTerm::Nil,
        OwnedTerm::list(vec![
            OwnedTerm::Int(1),
            OwnedTerm::atom("a"),
            OwnedTerm::Binary(vec![0, 255]),
        ]),
        OwnedTerm::Tuple(vec![OwnedTerm::atom("tuple"), OwnedTerm::Int(2)]),
        OwnedTerm::Map(vec![
            (OwnedTerm::Int(1), OwnedTerm::atom("one")),
            (OwnedTerm::atom("two"), OwnedTerm::Int(2)),
        ]),
        OwnedTerm::Map(
            (0..80)
                .map(|i| (OwnedTerm::Int(i), OwnedTerm::Binary(vec![i as u8; 40])))
                .collect(),
        ),
        OwnedTerm::Binary((0..4096).map(|i| i as u8).collect()),
        OwnedTerm::BitString {
            bytes: vec![0xf0, 0xa0],
            bits: 3,
        },
    ];
    for expr in [
        "self()",
        "make_ref()",
        "fun erlang:abs/1",
        "fun(X) -> X + 1 end",
    ] {
        values.push(reference.eval(expr).unwrap());
    }
    for (index, value) in values.iter().enumerate() {
        let key = OwnedTerm::Tuple(vec![
            OwnedTerm::atom("s35b_value_kind"),
            OwnedTerm::Int(index as i64),
        ]);
        let args = [key.clone(), value.clone()];
        compare(
            &local("put", &args),
            &reference.call("persistent_term", "put", &args),
            CompareMode::Exact,
        )
        .unwrap();
        compare(
            &local("get", std::slice::from_ref(&key)),
            &reference.call("persistent_term", "get", std::slice::from_ref(&key)),
            CompareMode::Exact,
        )
        .unwrap();
        compare(
            &local("erase", std::slice::from_ref(&key)),
            &reference.call("persistent_term", "erase", &[key]),
            CompareMode::Exact,
        )
        .unwrap();
    }
    let keys: Vec<_> = (0..128)
        .map(|i| {
            OwnedTerm::Tuple(vec![
                OwnedTerm::atom("s35b_differential"),
                OwnedTerm::Int(i),
            ])
        })
        .collect();
    let mut seed = 0x51f6_7e9a_23bc_d001;
    for step in 0..3_200 {
        let key = keys[(next(&mut seed) as usize) % keys.len()].clone();
        let choice = next(&mut seed) % 100;
        if choice < 8 {
            let actual = count(local("info", &[])) - local_base;
            let expected = count(reference.call("persistent_term", "info", &[])) - ref_base;
            assert_eq!(actual, expected, "info count at step {step}");
            continue;
        }
        let (name, args) = if choice < 48 {
            (
                "put",
                vec![
                    key,
                    values[(next(&mut seed) as usize) % values.len()].clone(),
                ],
            )
        } else if choice < 64 {
            ("get", vec![key])
        } else if choice < 80 {
            ("get", vec![key, OwnedTerm::atom("missing_default")])
        } else if choice < 95 {
            ("erase", vec![key])
        } else {
            (
                "put_new",
                vec![
                    key,
                    values[(next(&mut seed) as usize) % values.len()].clone(),
                ],
            )
        };
        let actual = local(name, &args);
        let expected = reference.call("persistent_term", name, &args);
        compare(&actual, &expected, CompareMode::Exact)
            .unwrap_or_else(|error| panic!("step {step} {name} {args:?}: {error}"));
    }
    let actual = count(local("info", &[])) - local_base;
    let expected = count(reference.call("persistent_term", "info", &[])) - ref_base;
    assert_eq!(actual, expected);
    for key in keys {
        local("erase", std::slice::from_ref(&key));
        reference.call("persistent_term", "erase", &[key]);
    }
}

#[test]
fn registry_has_all_otp_entries() {
    for (module, name, arity) in [
        ("persistent_term", "put", 2),
        ("persistent_term", "put_new", 2),
        ("persistent_term", "get", 0),
        ("persistent_term", "get", 1),
        ("persistent_term", "get", 2),
        ("persistent_term", "erase", 1),
        ("persistent_term", "info", 0),
        ("erts_internal", "erase_persistent_terms", 0),
    ] {
        assert!(lookup(module, name, arity).is_some());
    }
}
