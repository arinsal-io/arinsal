use arinsal_etf::{
    AtomCache, DistributionHeader, OwnedTerm, decode_dist_packet, decode_dist_packet_indexed,
    decode_dist_payload, encode_dist_continuation, encode_dist_packet,
    encode_dist_packet_terms_indexed,
};
use proptest::prelude::*;

#[test]
fn distribution_atom_cache_round_trip_and_reuse() {
    let term = OwnedTerm::tuple(vec![
        OwnedTerm::Atom("alpha".into()),
        OwnedTerm::list(vec![OwnedTerm::Atom("beta".into()), OwnedTerm::Int(7)]),
        OwnedTerm::Atom("alpha".into()),
    ]);
    let mut outgoing = AtomCache::new();
    let first = encode_dist_packet(&term, &mut outgoing, None);
    assert_eq!(&first[..2], &[131, 68]);
    assert_eq!(first[2], 2);

    let mut incoming = AtomCache::new();
    let packet = decode_dist_packet(&first, &mut incoming).unwrap();
    assert_eq!(decode_dist_payload(&packet).unwrap(), vec![term.clone()]);

    let second = encode_dist_packet(&term, &mut outgoing, None);
    let cached = decode_dist_packet(&second, &mut incoming).unwrap();
    assert_eq!(decode_dist_payload(&cached).unwrap(), vec![term]);
}

#[test]
fn indexed_outgoing_atom_cache_header_matches_erts_layout() {
    let term = OwnedTerm::tuple(vec![
        OwnedTerm::atom("a"),
        OwnedTerm::atom("b"),
        OwnedTerm::atom("c"),
        OwnedTerm::atom("d"),
    ]);
    let mut cache = AtomCache::new();
    let packet = encode_dist_packet_terms_indexed(&[&term], &mut cache, None, |name| {
        Some(match name {
            "a" => 1,    // 1 % 2039
            "b" => 2039, // 2039 % 2039
            "c" => 4095, // 4095 % 2039
            "d" => 2040, // collides with a and is sent inline
            _ => return None,
        })
    });

    // Port of external.c atom2cix/insert_acache_map/finalize: touched slots
    // are emitted in first-use order; the colliding atom is absent from the map.
    assert_eq!(
        &packet[..14],
        &[131, 68, 3, 0x88, 0x08, 1, 1, b'a', 0, 1, b'b', 17, 1, b'c']
    );
    assert_eq!(&packet[14..], &[104, 4, 82, 0, 82, 1, 82, 2, 119, 1, b'd']);

    let mut incoming = AtomCache::new();
    let atom_id = |name: &str| match name {
        "a" => Some(1),
        "b" => Some(2039),
        "c" => Some(4095),
        _ => None,
    };
    let atom_name = |index| match index {
        1 => Some("a".to_owned()),
        2039 => Some("b".to_owned()),
        4095 => Some("c".to_owned()),
        _ => None,
    };
    let decoded = decode_dist_packet_indexed(&packet, &mut incoming, atom_id, atom_name).unwrap();
    assert_eq!(decode_dist_payload(&decoded).unwrap(), vec![term.clone()]);
    assert_eq!(incoming.get(1), None); // Indexed cache entries retain no atom text.

    let reused = encode_dist_packet_terms_indexed(&[&term], &mut cache, None, atom_id);
    assert_eq!(&reused[..8], &[131, 68, 3, 0, 0, 1, 0, 17]);
    let decoded = decode_dist_packet_indexed(&reused, &mut incoming, atom_id, atom_name).unwrap();
    assert_eq!(decode_dist_payload(&decoded).unwrap(), vec![term]);
}

#[test]
fn distribution_long_atoms_and_fragment_headers() {
    let long_atom = "é".repeat(130);
    let term = OwnedTerm::Atom(long_atom);
    let mut outgoing = AtomCache::new();
    let bytes = encode_dist_packet(&term, &mut outgoing, Some((0x1020_3040, 3)));
    assert_eq!(&bytes[..2], &[131, 69]);
    assert_eq!(
        &bytes[2..18],
        &[0, 0, 0, 0, 0x10, 0x20, 0x30, 0x40, 0, 0, 0, 0, 0, 0, 0, 3]
    );
    let mut incoming = AtomCache::new();
    let packet = decode_dist_packet(&bytes, &mut incoming).unwrap();
    assert!(matches!(
        packet.header,
        DistributionHeader::Start {
            sequence_id: Some(0x1020_3040),
            fragment_id: Some(3),
            ..
        }
    ));
    assert_eq!(decode_dist_payload(&packet).unwrap(), vec![term]);

    let continuation = encode_dist_continuation(9, 2, &[1, 2, 3]);
    let packet = decode_dist_packet(&continuation, &mut incoming).unwrap();
    assert_eq!(packet.payload, [1, 2, 3]);
    assert_eq!(
        packet.header,
        DistributionHeader::Continuation {
            sequence_id: 9,
            fragment_id: 2
        }
    );
}

#[test]
fn atom_cache_reference_requires_translation_context() {
    let term = OwnedTerm::Atom("cached".into());
    let mut outgoing = AtomCache::new();
    let packet = encode_dist_packet(&term, &mut outgoing, None);
    let mut incoming = AtomCache::new();
    let decoded = decode_dist_packet(&packet, &mut incoming).unwrap();
    assert_eq!(decode_dist_payload(&decoded).unwrap(), vec![term]);

    assert!(arinsal_etf::decode(&[131, 82, 0]).is_err());
}

#[test]
fn distribution_atom_cache_resolves_atom_positions_in_identity_and_code_terms() {
    let pid = OwnedTerm::Pid {
        node: "node@host".into(),
        id: 7,
        serial: 2,
        creation: 4,
    };
    let term = OwnedTerm::Tuple(vec![
        pid.clone(),
        OwnedTerm::Port {
            node: "node@host".into(),
            id: 9,
            creation: 4,
        },
        OwnedTerm::Ref {
            node: "node@host".into(),
            creation: 4,
            ids: vec![11, 12],
        },
        OwnedTerm::Export {
            module: "sample_mod".into(),
            function: "run".into(),
            arity: 1,
        },
        OwnedTerm::Fun {
            arity: 1,
            uniq: [3; 16],
            index: 5,
            module: "sample_mod".into(),
            old_index: 6,
            old_uniq: 7,
            pid: Box::new(pid),
            free_vars: vec![OwnedTerm::Atom("captured".into())],
        },
        OwnedTerm::Record {
            exported: true,
            module: "sample_mod".into(),
            name: "record_name".into(),
            fields: vec![("field_name".into(), OwnedTerm::Atom("value".into()))],
        },
    ]);
    let mut outgoing = AtomCache::new();
    let bytes = encode_dist_packet(&term, &mut outgoing, None);
    let mut incoming = AtomCache::new();
    let decoded = decode_dist_packet(&bytes, &mut incoming).unwrap();
    assert_eq!(decode_dist_payload(&decoded).unwrap(), vec![term]);
}

#[test]
fn new_fun_size_includes_its_size_word_like_otp() {
    let term = OwnedTerm::Fun {
        arity: 1,
        uniq: [9; 16],
        index: 4,
        module: "sample_mod".into(),
        old_index: 5,
        old_uniq: 6,
        pid: Box::new(OwnedTerm::Pid {
            node: "node@host".into(),
            id: 7,
            serial: 2,
            creation: 4,
        }),
        free_vars: vec![OwnedTerm::atom("captured")],
    };
    let bytes = arinsal_etf::encode(&term, Default::default());
    assert_eq!(bytes[1], 112);
    let declared = u32::from_be_bytes(bytes[2..6].try_into().unwrap()) as usize;
    assert_eq!(declared, bytes.len() - 2);
    assert_eq!(arinsal_etf::decode(&bytes).unwrap(), term);
}

proptest! {
    #[test]
    fn dist_encode_decode_property(atoms in prop::collection::vec("[a-z]{1,16}", 1..20), value in any::<i64>()) {
        let term = OwnedTerm::tuple(atoms.into_iter().map(OwnedTerm::Atom).chain([OwnedTerm::Int(value)]).collect());
        let mut outgoing = AtomCache::new();
        let mut incoming = AtomCache::new();
        let bytes = encode_dist_packet(&term, &mut outgoing, None);
        let packet = decode_dist_packet(&bytes, &mut incoming).unwrap();
        prop_assert_eq!(decode_dist_payload(&packet).unwrap(), vec![term]);
    }
}
