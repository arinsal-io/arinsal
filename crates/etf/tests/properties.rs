use arinsal_etf::{EncodeOptions, OwnedTerm, decode, encode};
use proptest::prelude::*;

fn arb_term() -> impl Strategy<Value = OwnedTerm> {
    let atom = "[a-z]{0,12}".prop_map(OwnedTerm::Atom);
    let bitstring =
        (prop::collection::vec(any::<u8>(), 1..40), 1_u8..8).prop_map(|(mut bytes, bits)| {
            let last = bytes.last_mut().unwrap();
            *last &= !((1_u8 << (8 - bits)) - 1);
            OwnedTerm::BitString { bytes, bits }
        });
    let leaf = prop_oneof![
        any::<i64>().prop_map(OwnedTerm::Int),
        any::<u64>().prop_map(|n| OwnedTerm::BigInt(
            num_bigint::BigInt::from(n) + (num_bigint::BigInt::from(1_u8) << 64)
        )),
        any::<u64>().prop_filter_map("finite float", |bits| {
            let f = f64::from_bits(bits);
            f.is_finite().then_some(OwnedTerm::Float(f))
        }),
        atom,
        Just(OwnedTerm::Nil),
        prop::collection::vec(any::<u8>(), 0..100).prop_map(OwnedTerm::Binary),
        bitstring,
        (any::<u32>(), any::<u32>(), any::<u32>()).prop_map(|(id, serial, creation)| {
            OwnedTerm::Pid {
                node: "remote@prop".into(),
                id,
                serial,
                creation,
            }
        }),
        (any::<u64>(), any::<u32>()).prop_map(|(id, creation)| OwnedTerm::Port {
            node: "remote@prop".into(),
            id,
            creation
        }),
        (any::<u32>(), prop::collection::vec(any::<u32>(), 1..6)).prop_map(|(creation, ids)| {
            OwnedTerm::Ref {
                node: "remote@prop".into(),
                creation,
                ids,
            }
        }),
        ("[a-z]{1,8}", "[a-z]{1,8}", any::<u8>()).prop_map(|(module, function, arity)| {
            OwnedTerm::Export {
                module,
                function,
                arity,
            }
        }),
    ];
    leaf.prop_recursive(6, 128, 8, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 1..8).prop_map(OwnedTerm::list),
            prop::collection::vec(inner.clone(), 0..8).prop_map(OwnedTerm::tuple),
            prop::collection::vec(inner.clone(), 0..10).prop_map(|values| OwnedTerm::Map(
                values
                    .into_iter()
                    .enumerate()
                    .map(|(i, v)| (OwnedTerm::Int(i as i64), v))
                    .collect()
            )),
            prop::collection::vec(inner, 0..6).prop_map(|values| OwnedTerm::Record {
                exported: true,
                module: "prop".into(),
                name: "item".into(),
                fields: values
                    .into_iter()
                    .enumerate()
                    .map(|(i, v)| (format!("f{i}"), v))
                    .collect()
            }),
        ]
    })
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 2000, .. ProptestConfig::default() })]
    #[test]
    fn owned_term_round_trip(term in arb_term()) {
        let opts = EncodeOptions::default();
        let bytes = encode(&term, opts);
        let decoded = decode(&bytes).unwrap();
        prop_assert_eq!(encode(&decoded, opts), bytes);
        if let (OwnedTerm::Float(a), OwnedTerm::Float(b)) = (&term, &decoded) {
            prop_assert_eq!(a.to_bits(), b.to_bits());
        }
        prop_assert_eq!(decoded, term);
    }
}
