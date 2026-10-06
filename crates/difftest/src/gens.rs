//! Property strategies for ETF representable Erlang terms.
use arinsal_etf::OwnedTerm;
use num_bigint::BigInt;
use proptest::prelude::*;

fn list(xs: Vec<OwnedTerm>) -> OwnedTerm {
    if xs.is_empty() {
        OwnedTerm::Nil
    } else {
        OwnedTerm::List {
            elems: xs,
            tail: Box::new(OwnedTerm::Nil),
        }
    }
}
/// Integers around immediate and machine word boundaries.
pub fn integer() -> impl Strategy<Value = OwnedTerm> {
    prop_oneof![
        prop::sample::select(vec![
            0,
            1,
            -1,
            (1_i64 << 59) - 1,
            1_i64 << 59,
            -(1_i64 << 59),
            i64::MAX,
            i64::MIN
        ])
        .prop_map(OwnedTerm::Int),
        any::<i64>().prop_map(OwnedTerm::Int),
        prop::sample::select(vec![
            BigInt::from(1_u64) << 63_usize,
            (BigInt::from(1_u64) << 64_usize) - 1,
            -(BigInt::from(1_u64) << 80_usize)
        ])
        .prop_map(OwnedTerm::BigInt)
    ]
}
/// Float bit patterns including both zero signs and finite extremes.
pub fn float() -> impl Strategy<Value = OwnedTerm> {
    prop_oneof![
        prop::sample::select(vec![0.0, -0.0, 1.0, -1.0, f64::MIN_POSITIVE, f64::MAX]),
        any::<f64>().prop_filter("finite", |x| x.is_finite())
    ]
    .prop_map(OwnedTerm::Float)
}
/// ASCII and Unicode atoms.
pub fn atom() -> impl Strategy<Value = OwnedTerm> {
    prop::sample::select(vec![
        "ok",
        "error",
        "true",
        "false",
        "",
        "å",
        "猫",
        "quoted atom",
        "nil",
    ])
    .prop_map(|s| OwnedTerm::Atom(s.to_owned()))
}
/// Byte and non-byte-aligned bitstrings.
pub fn binary() -> impl Strategy<Value = OwnedTerm> {
    prop_oneof![
        prop::collection::vec(any::<u8>(), 0..128).prop_map(OwnedTerm::Binary),
        (prop::collection::vec(any::<u8>(), 1..32), 1_u8..8).prop_map(|(mut bytes, bits)| {
            let last = bytes.last_mut().unwrap();
            *last &= 0xff << (8 - bits);
            OwnedTerm::BitString { bytes, bits }
        })
    ]
}
/// Recursive tuples, lists, improper lists and maps.
pub fn any_term() -> impl Strategy<Value = OwnedTerm> {
    let leaf = prop_oneof![integer(), float(), atom(), binary(), Just(OwnedTerm::Nil)];
    leaf.prop_recursive(5, 256, 12, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..8).prop_map(list),
            (prop::collection::vec(inner.clone(), 1..8), inner.clone()).prop_map(
                |(elems, tail)| OwnedTerm::List {
                    elems,
                    tail: Box::new(tail)
                }
            ),
            prop::collection::vec(inner.clone(), 0..8).prop_map(OwnedTerm::Tuple),
            prop::collection::vec((inner.clone(), inner), 0..8).prop_map(unique_map)
        ]
    })
}
/// Small map argument for maps BIFs.
pub fn small_map() -> impl Strategy<Value = OwnedTerm> {
    prop::collection::vec((atom(), integer()), 0..8).prop_map(unique_map)
}
/// Deep proper lists for traversal and stack edge cases.
pub fn deep_list() -> impl Strategy<Value = OwnedTerm> {
    (0_usize..300, integer()).prop_map(|(n, t)| list(vec![t; n]))
}
/// A PID returned by the reference endpoint.
pub fn pid(reference: &crate::RefErl) -> Result<OwnedTerm, crate::Error> {
    reference.eval("self()")
}
/// A reference returned by the reference endpoint.
pub fn reference(reference: &crate::RefErl) -> Result<OwnedTerm, crate::Error> {
    reference.eval("make_ref()")
}

/// Check generated arguments against two VM adapters.
pub fn diff_prop<S: Strategy<Value = Vec<OwnedTerm>>>(
    left: &mut impl crate::Vm,
    right: &mut impl crate::Vm,
    module: &str,
    function: &str,
    strategy: S,
    cases: u32,
) -> Result<(), crate::Mismatch> {
    use proptest::strategy::ValueTree;
    let mut runner = proptest::test_runner::TestRunner::default();
    for _ in 0..cases {
        let args = strategy
            .new_tree(&mut runner)
            .map_err(|e| crate::Mismatch {
                path: "generator".into(),
                left: e.to_string(),
                right: String::new(),
            })?
            .current();
        let a = left.call(module, function, &args);
        let b = right.call(module, function, &args);
        crate::compare(&a, &b, crate::CompareMode::Exact)?;
    }
    Ok(())
}

/// Construct argument strategies from a registered function's generator labels.
pub fn for_spec(spec: &crate::suites::FunctionSpec) -> BoxedStrategy<Vec<OwnedTerm>> {
    let mut args: BoxedStrategy<Vec<OwnedTerm>> = Just(Vec::new()).boxed();
    for label in spec.generators.split(',') {
        let next = by_label(label.trim());
        args = (args, next)
            .prop_map(|(mut xs, x)| {
                xs.push(x);
                xs
            })
            .boxed();
    }
    args
}
fn by_label(label: &str) -> BoxedStrategy<OwnedTerm> {
    match label {
        "integer" => integer().boxed(),
        "nonzero_integer"
        | "positive_integer"
        | "nonnegative_integer"
        | "offset"
        | "length"
        | "valid_index" => {
            let range = match label {
                "positive_integer" | "valid_index" => 1..32,
                "nonzero_integer" => 1..32,
                _ => 0..32,
            };
            range.prop_map(|n| OwnedTerm::Int(i64::from(n))).boxed()
        }
        "base" => (2_i64..37).prop_map(OwnedTerm::Int).boxed(),
        "number" => prop_oneof![integer(), float()].boxed(),
        "atom" | "existing_key" => atom().boxed(),
        "binary" | "nonempty_binary" | "utf8_binary" => binary().boxed(),
        "valid_etf_binary" => Just(OwnedTerm::Binary(vec![131, 97, 42])).boxed(),
        "small_map" => small_map().boxed(),
        "tuple" => prop::collection::vec(any_term(), 0..8)
            .prop_map(OwnedTerm::Tuple)
            .boxed(),
        "proper_list" | "nested_list" | "pair_list" => prop::collection::vec(any_term(), 0..8)
            .prop_map(list)
            .boxed(),
        "numeric_list" => prop::collection::vec(integer(), 0..8)
            .prop_map(list)
            .boxed(),
        "charlist" | "unicode_charlist" | "digit_list" => {
            prop::sample::select(vec!["", "abc", "héllo", "42", "ff", "  hi  "])
                .prop_map(|s| list(s.chars().map(|c| OwnedTerm::Int(c as i64)).collect()))
                .boxed()
        }
        "format_string" => prop::sample::select(vec![
            "~p", "~w", "~s", "~ts", "~b", "~.16B", "~e", "~f", "~g", "~c", "~-10s", "~10.3f",
            "~tp", "~P",
        ])
        .prop_map(|s| list(s.chars().map(|c| OwnedTerm::Int(c as i64)).collect()))
        .boxed(),
        "term_list" => prop::collection::vec(any_term(), 1..3)
            .prop_map(list)
            .boxed(),
        "any_term" => any_term().boxed(),
        other => panic!("unknown generator label: {other}"),
    }
}

/// PID strategy based on a reference value obtained from the server.
pub fn pid_strategy(reference: &crate::RefErl) -> Result<BoxedStrategy<OwnedTerm>, crate::Error> {
    Ok(Just(pid(reference)?).boxed())
}
/// Reference strategy based on a value obtained from the server.
pub fn reference_strategy(
    reference: &crate::RefErl,
) -> Result<BoxedStrategy<OwnedTerm>, crate::Error> {
    Ok(Just(self::reference(reference)?).boxed())
}

fn unique_map(entries: Vec<(OwnedTerm, OwnedTerm)>) -> OwnedTerm {
    let mut unique: Vec<(OwnedTerm, OwnedTerm)> = Vec::new();
    for (key, value) in entries {
        if let Some((_, prior)) = unique.iter_mut().find(|(old, _)| {
            crate::compare(
                &crate::CallResult::Ok(old.clone()),
                &crate::CallResult::Ok(key.clone()),
                crate::CompareMode::Exact,
            )
            .is_ok()
        }) {
            *prior = value;
        } else {
            unique.push((key, value));
        }
    }
    OwnedTerm::Map(unique)
}

/// Maps beyond the flatmap threshold, with distinct integer keys.
pub fn large_map() -> impl Strategy<Value = OwnedTerm> {
    prop::collection::btree_map(0_i64..1_000_000, any_term(), 33..65).prop_map(|map| {
        OwnedTerm::Map(
            map.into_iter()
                .map(|(k, v)| (OwnedTerm::Int(k), v))
                .collect(),
        )
    })
}
/// A port term obtained from the reference node.
pub fn port(reference: &crate::RefErl) -> Result<OwnedTerm, crate::Error> {
    reference.eval("hd(erlang:ports())")
}
/// An exported function term obtained from the reference node.
pub fn export(reference: &crate::RefErl) -> Result<OwnedTerm, crate::Error> {
    reference.eval("fun erlang:abs/1")
}
/// A local function term. It requires the full S0.5 codec.
pub fn local_fun(reference: &crate::RefErl) -> Result<OwnedTerm, crate::Error> {
    reference.eval("fun(X) -> X end")
}
/// Runtime identity terms generated by the reference node.
pub fn runtime_term_strategy(
    reference: &crate::RefErl,
) -> Result<BoxedStrategy<OwnedTerm>, crate::Error> {
    let values = vec![
        pid(reference)?,
        self::reference(reference)?,
        port(reference)?,
        export(reference)?,
    ];
    Ok(prop::sample::select(values).boxed())
}
