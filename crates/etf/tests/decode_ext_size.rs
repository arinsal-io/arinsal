//! `decode_ext_size` accepts what `decode` accepts and rejects what `erts_decode_ext_size`
//! rejects.

use arinsal_etf::{EncodeOptions, OwnedTerm, decode, decode_ext_size, encode};

fn atom(name: &str) -> OwnedTerm {
    OwnedTerm::Atom(name.to_owned())
}

#[test]
fn valid_terms_have_a_size() {
    let samples = [
        OwnedTerm::Int(7),
        OwnedTerm::Nil,
        atom("a_long_enough_atom"),
        OwnedTerm::Binary(vec![1; 100]),
        OwnedTerm::Tuple(vec![
            atom("t"),
            OwnedTerm::Int(-70_000),
            OwnedTerm::Float(1.5),
        ]),
        OwnedTerm::List {
            elems: (0..50).map(OwnedTerm::Int).collect(),
            tail: Box::new(atom("tail")),
        },
        OwnedTerm::Map(vec![(atom("k"), OwnedTerm::Int(1))]),
    ];
    for sample in samples {
        let bytes = encode(&sample, EncodeOptions::default());
        assert!(decode(&bytes).is_ok());
        assert!(decode_ext_size(&bytes).is_ok(), "{sample:?}");
    }
}

#[test]
fn malformed_terms_have_none() {
    assert!(decode_ext_size(&[]).is_err());
    assert!(decode_ext_size(&[130, 97, 1]).is_err());
    assert!(decode_ext_size(&[131]).is_err());
    assert!(decode_ext_size(&[131, 104, 2, 97, 1]).is_err());
    assert!(decode_ext_size(&[131, 108, 0, 0, 0, 5, 97, 1]).is_err());
    assert!(decode_ext_size(&[131, 255]).is_err());
}

#[test]
fn bytes_after_the_term_are_not_looked_at() {
    assert!(decode_ext_size(&[131, 97, 1, 97, 2]).is_ok());
}
