use arinsal_bits::{
    MatchOps, SegFlags, SegSize, SegType, Segment, SegmentValue, create_bin, create_bin_size,
    start_match,
};
use arinsal_difftest::RefErl;
use arinsal_etf::OwnedTerm;
use arinsal_term::{Term, TermBuilder, VecHeap};

fn bytes_and_bits(term: Term) -> (Vec<u8>, usize) {
    let owned = arinsal_term::to_owned(term).unwrap();
    match &owned {
        OwnedTerm::Binary(bytes) => (bytes.clone(), bytes.len() * 8),
        OwnedTerm::BitString { bytes, bits } => {
            let len = (bytes.len() - 1) * 8 + usize::from(*bits);
            (bytes.clone(), len)
        }
        other => panic!("expected bitstring: {other:?}"),
    }
}

fn reference_bytes(term: OwnedTerm) -> (Vec<u8>, usize) {
    match &term {
        OwnedTerm::Binary(b) => {
            let bits = b.len() * 8;
            (b.clone(), bits)
        }
        OwnedTerm::BitString { bytes, bits } => {
            let len = (bytes.len() - 1) * 8 + usize::from(*bits);
            (bytes.clone(), len)
        }
        other => panic!("expected bitstring: {other:?}"),
    }
}

fn int(value: i64, bits: u64, flags: SegFlags) -> Segment<'static> {
    Segment {
        ty: SegType::Integer,
        index: 1,
        unit: 1,
        flags,
        value: SegmentValue::Term(Term::small(value).unwrap()),
        size: SegSize::Units(bits),
    }
}

#[test]
fn hundred_thousand_integer_constructions_against_erl() {
    let Ok(reference) = RefErl::shared() else {
        eprintln!("skipping: erl is unavailable");
        return;
    };
    let expression = r#"<< <<(case N rem 8 of
      0 -> <<V:32/little>>;
      1 -> <<V:3,V:13/little,V:16/signed-big>>;
      2 -> <<(-V):32/signed-little>>;
      3 -> <<V:1,V:31/big>>;
      4 -> <<V:17/little,V:15/big>>;
      5 -> <<V:32/big>>;
      6 -> <<V:4,V:24/little,V:4>>;
      7 -> <<V:16/signed-big,V:16/little>>
    end)/binary>> || N <- lists:seq(1,100000), V <- [N * 2654435761] >>"#;
    let (expected, bits) = reference_bytes(reference.eval(expression).unwrap());
    assert_eq!(bits, 100_000 * 32);
    let little = SegFlags {
        little: true,
        ..SegFlags::default()
    };
    let signed = SegFlags {
        signed: true,
        ..SegFlags::default()
    };
    let signed_little = SegFlags {
        little: true,
        signed: true,
        native: false,
    };
    let mut heap = VecHeap::new();
    for n in 1..=100_000i64 {
        let v = n * 2_654_435_761;
        let segments = match n % 8 {
            0 => vec![int(v, 32, little)],
            1 => vec![
                int(v, 3, SegFlags::default()),
                int(v, 13, little),
                int(v, 16, signed),
            ],
            2 => vec![int(-v, 32, signed_little)],
            3 => vec![
                int(v, 1, SegFlags::default()),
                int(v, 31, SegFlags::default()),
            ],
            4 => vec![int(v, 17, little), int(v, 15, SegFlags::default())],
            5 => vec![int(v, 32, SegFlags::default())],
            6 => vec![
                int(v, 4, SegFlags::default()),
                int(v, 24, little),
                int(v, 4, SegFlags::default()),
            ],
            _ => vec![int(v, 16, signed), int(v, 16, little)],
        };
        let got = create_bin(&segments, &mut heap).unwrap();
        let (bytes, count) = bytes_and_bits(got);
        assert_eq!(count, 32);
        assert_eq!(
            bytes,
            expected[(n as usize - 1) * 4..n as usize * 4],
            "case {n}"
        );
    }
}

#[test]
fn integer_widths_and_endianness_against_erl() {
    let Ok(reference) = RefErl::shared() else {
        eprintln!("skipping: erl is unavailable");
        return;
    };
    let mut heap = VecHeap::new();
    for bits in 1..=128u64 {
        for (suffix, flags) in [
            ("big", SegFlags::default()),
            (
                "little",
                SegFlags {
                    little: true,
                    ..SegFlags::default()
                },
            ),
            (
                "native",
                SegFlags {
                    native: true,
                    ..SegFlags::default()
                },
            ),
        ] {
            let value = -(bits as i64 * 139 + 1);
            let expression = format!("<<({value}):{bits}/signed-{suffix}>>");
            let expected = reference_bytes(reference.eval(&expression).unwrap());
            let got = create_bin(&[int(value, bits, flags)], &mut heap).unwrap();
            assert_eq!(bytes_and_bits(got), expected, "{bits} {suffix}");
            let ctx = start_match(got, &mut heap).unwrap().unwrap();
            let decoded = ctx
                .get_integer(
                    bits as usize,
                    SegFlags {
                        signed: true,
                        ..flags
                    },
                    &mut heap,
                )
                .unwrap()
                .unwrap();
            let mask = if bits >= 64 {
                value
            } else {
                (value << (64 - bits)) >> (64 - bits)
            };
            assert_eq!(decoded.as_small(), Some(mask), "match {bits} {suffix}");
            assert!(ctx.ensure_exactly(0));
        }
    }
}

#[test]
fn binary_utf_float_and_unaligned_slices() {
    let Ok(reference) = RefErl::shared() else {
        eprintln!("skipping: erl is unavailable");
        return;
    };
    let mut heap = VecHeap::new();
    let source = TermBuilder::new(&mut heap)
        .bitstring(&[0b1010_1010, 0b1100_0000], 10)
        .unwrap();
    let sub = TermBuilder::new(&mut heap)
        .sub_binary(source, 3, 7)
        .unwrap();
    let segments = [Segment {
        ty: SegType::Binary,
        index: 1,
        unit: 1,
        flags: SegFlags::default(),
        value: SegmentValue::Term(sub),
        size: SegSize::All,
    }];
    let got = create_bin(&segments, &mut heap).unwrap();
    assert_eq!(
        bytes_and_bits(got),
        reference_bytes(
            reference
                .eval("<<_:3,B:7/bitstring>> = <<5:3, 43:7>>, B")
                .unwrap()
        )
    );
    for (ty, suffix, value) in [
        (SegType::Utf8, "utf8", 0x1f984),
        (SegType::Utf16, "utf16-little", 0x1f984),
        (SegType::Utf32, "utf32-big", 0x1f984),
    ] {
        let flags = SegFlags {
            little: suffix.ends_with("little"),
            ..SegFlags::default()
        };
        let seg = Segment {
            ty,
            index: 1,
            unit: 1,
            flags,
            value: SegmentValue::Term(Term::small(value).unwrap()),
            size: SegSize::Units(0),
        };
        let expected = reference_bytes(reference.eval(&format!("<<16#1F984/{suffix}>>")).unwrap());
        let got = create_bin(&[seg], &mut heap).unwrap();
        assert_eq!(bytes_and_bits(got), expected, "{suffix}");
    }
    let float = TermBuilder::new(&mut heap).float(1.5).unwrap();
    for bits in [16, 32, 64] {
        let seg = Segment {
            ty: SegType::Float,
            index: 1,
            unit: 1,
            flags: SegFlags::default(),
            value: SegmentValue::Term(float),
            size: SegSize::Units(bits),
        };
        let got = create_bin(&[seg], &mut heap).unwrap();
        assert_eq!(
            bytes_and_bits(got),
            reference_bytes(reference.eval(&format!("<<1.5:{bits}/float>>")).unwrap())
        );
        let ctx = start_match(got, &mut heap).unwrap().unwrap();
        let extracted = ctx
            .get_float(bits as usize, SegFlags::default(), &mut heap)
            .unwrap()
            .unwrap();
        let owned = arinsal_term::to_owned(extracted).unwrap();
        assert!(matches!(&owned, OwnedTerm::Float(value) if *value == 1.5));
    }
    assert_eq!(
        create_bin_size(&[int(1, 8, SegFlags::default())])
            .unwrap()
            .bits,
        8
    );
}

#[test]
fn hundred_thousand_integer_matches_against_erl() {
    let Ok(reference) = RefErl::shared() else {
        eprintln!("skipping: erl is unavailable");
        return;
    };
    let expression = r#"<< <<(begin
      V = N * 2654435761,
      B = case N rem 8 of
        0 -> <<V:32/little>>;
        1 -> <<V:3,V:13/little,V:16/signed-big>>;
        2 -> <<(-V):32/signed-little>>;
        3 -> <<V:1,V:31/big>>;
        4 -> <<V:17/little,V:15/big>>;
        5 -> <<V:32/big>>;
        6 -> <<V:4,V:24/little,V:4>>;
        7 -> <<V:16/signed-big,V:16/little>>
      end,
      case N rem 8 of
        0 -> <<X:32/little>> = B;
        1 -> <<X:3,_:13/little,_:16>> = B;
        2 -> <<X:32/signed-little>> = B;
        3 -> <<X:1,_:31>> = B;
        4 -> <<X:17/little,_:15>> = B;
        5 -> <<X:32/big>> = B;
        6 -> <<X:4,_:24/little,_:4>> = B;
        7 -> <<X:16/signed-big,_:16/little>> = B
      end,
      X
    end):32/big>> || N <- lists:seq(1,100000) >>"#;
    let (expected, bits) = reference_bytes(reference.eval(expression).unwrap());
    assert_eq!(bits, 100_000 * 32);
    let mut heap = VecHeap::new();
    for n in 1..=100_000usize {
        let value = n as i64 * 2_654_435_761;
        let source = match n % 8 {
            0 => vec![int(
                value,
                32,
                SegFlags {
                    little: true,
                    ..SegFlags::default()
                },
            )],
            1 => vec![
                int(value, 3, SegFlags::default()),
                int(
                    value,
                    13,
                    SegFlags {
                        little: true,
                        ..SegFlags::default()
                    },
                ),
                int(value, 16, SegFlags::default()),
            ],
            2 => vec![int(
                -value,
                32,
                SegFlags {
                    little: true,
                    ..SegFlags::default()
                },
            )],
            3 => vec![
                int(value, 1, SegFlags::default()),
                int(value, 31, SegFlags::default()),
            ],
            4 => vec![
                int(
                    value,
                    17,
                    SegFlags {
                        little: true,
                        ..SegFlags::default()
                    },
                ),
                int(value, 15, SegFlags::default()),
            ],
            5 => vec![int(value, 32, SegFlags::default())],
            6 => vec![
                int(value, 4, SegFlags::default()),
                int(
                    value,
                    24,
                    SegFlags {
                        little: true,
                        ..SegFlags::default()
                    },
                ),
                int(value, 4, SegFlags::default()),
            ],
            _ => vec![
                int(value, 16, SegFlags::default()),
                int(
                    value,
                    16,
                    SegFlags {
                        little: true,
                        ..SegFlags::default()
                    },
                ),
            ],
        };
        let binary = create_bin(&source, &mut heap).unwrap();
        let ctx = start_match(binary, &mut heap).unwrap().unwrap();
        assert!(ctx.ensure_at_least(32, 1));
        let (size, flags) = match n % 8 {
            0 => (
                32,
                SegFlags {
                    little: true,
                    ..SegFlags::default()
                },
            ),
            1 => (3, SegFlags::default()),
            2 => (
                32,
                SegFlags {
                    little: true,
                    signed: true,
                    native: false,
                },
            ),
            3 => (1, SegFlags::default()),
            4 => (
                17,
                SegFlags {
                    little: true,
                    ..SegFlags::default()
                },
            ),
            5 => (32, SegFlags::default()),
            6 => (4, SegFlags::default()),
            _ => (
                16,
                SegFlags {
                    signed: true,
                    ..SegFlags::default()
                },
            ),
        };
        let got = ctx
            .get_integer(size, flags, &mut heap)
            .unwrap()
            .unwrap()
            .as_small()
            .unwrap();
        assert_eq!(
            (got as u32).to_be_bytes(),
            expected[(n - 1) * 4..n * 4],
            "case {n}"
        );
    }
}

#[test]
fn unsigned_widths_bignums_and_errors() {
    let Ok(reference) = RefErl::shared() else {
        eprintln!("skipping: erl is unavailable");
        return;
    };
    let mut heap = VecHeap::new();
    for bits in 1..=128u64 {
        let value = bits as i64 * 123_456_789;
        for (suffix, flags) in [
            ("big", SegFlags::default()),
            (
                "little",
                SegFlags {
                    little: true,
                    ..SegFlags::default()
                },
            ),
            (
                "native",
                SegFlags {
                    native: true,
                    ..SegFlags::default()
                },
            ),
        ] {
            let expected = reference_bytes(
                reference
                    .eval(&format!("<<{value}:{bits}/unsigned-{suffix}>>"))
                    .unwrap(),
            );
            let binary = create_bin(&[int(value, bits, flags)], &mut heap).unwrap();
            assert_eq!(bytes_and_bits(binary), expected, "unsigned {bits} {suffix}");
            let ctx = start_match(binary, &mut heap).unwrap().unwrap();
            let got = ctx
                .get_integer(bits as usize, flags, &mut heap)
                .unwrap()
                .unwrap();
            let reference_match = reference.eval(&format!("begin B = <<{value}:{bits}/unsigned-{suffix}>>, <<X:{bits}/unsigned-{suffix}>> = B, X end")).unwrap();
            let expected_number = match reference_match {
                OwnedTerm::Int(n) => n,
                other => panic!("unexpected {other:?}"),
            };
            assert_eq!(got.as_small(), Some(expected_number));
        }
    }
    let huge = (num_bigint::BigInt::from(1u8) << 140) + num_bigint::BigInt::from(12345u32);
    let big = TermBuilder::new(&mut heap).int_from_bigint(&huge).unwrap();
    for (suffix, flags) in [
        ("big", SegFlags::default()),
        (
            "little",
            SegFlags {
                little: true,
                ..SegFlags::default()
            },
        ),
    ] {
        let segment = Segment {
            ty: SegType::Integer,
            index: 1,
            unit: 1,
            flags,
            value: SegmentValue::Term(big),
            size: SegSize::Units(160),
        };
        let binary = create_bin(&[segment], &mut heap).unwrap();
        let expected = reference_bytes(
            reference
                .eval(&format!("<<((1 bsl 140)+12345):160/{suffix}>>"))
                .unwrap(),
        );
        assert_eq!(bytes_and_bits(binary), expected);
        let ctx = start_match(binary, &mut heap).unwrap().unwrap();
        let matched = ctx.get_integer(160, flags, &mut heap).unwrap().unwrap();
        let owned = arinsal_term::to_owned(matched).unwrap();
        assert_eq!(
            match &owned {
                OwnedTerm::BigInt(value) => value.clone(),
                OwnedTerm::Int(value) => num_bigint::BigInt::from(*value),
                other => panic!("expected integer: {other:?}"),
            },
            huge
        );
    }
    for ty in [SegType::Utf8, SegType::Utf16, SegType::Utf32] {
        for value in [-1, 0xd800, 0x110000] {
            let segment = Segment {
                ty,
                index: 7,
                unit: 1,
                flags: SegFlags::default(),
                value: SegmentValue::Term(Term::small(value).unwrap()),
                size: SegSize::Units(0),
            };
            assert_eq!(
                create_bin_size(&[segment]),
                Err(arinsal_bits::BitsError::BadArg { segment: 7 })
            );
        }
    }
    let bad_size = Segment {
        ty: SegType::Integer,
        index: 9,
        unit: 1,
        flags: SegFlags::default(),
        value: SegmentValue::Term(Term::small(1).unwrap()),
        size: SegSize::Term(Term::small(-1).unwrap()),
    };
    assert_eq!(
        create_bin_size(&[bad_size]),
        Err(arinsal_bits::BitsError::BadArg { segment: 9 })
    );
    let large_size = Segment {
        size: SegSize::Term(big),
        ..bad_size
    };
    assert_eq!(
        create_bin_size(&[large_size]),
        Err(arinsal_bits::BitsError::SystemLimit { segment: 9 })
    );
}

#[test]
fn matching_binary_tail_utf_and_float_rounding() {
    let Ok(reference) = RefErl::shared() else {
        eprintln!("skipping: erl is unavailable");
        return;
    };
    let mut heap = VecHeap::new();
    let binary = TermBuilder::new(&mut heap)
        .binary(&[0xaa, 0xbb, 0xcc, 0xdd])
        .unwrap();
    let ctx = start_match(binary, &mut heap).unwrap().unwrap();
    assert!(ctx.ensure_at_least(8, 8));
    assert_eq!(
        ctx.get_integer(8, SegFlags::default(), &mut heap)
            .unwrap()
            .unwrap()
            .as_small(),
        Some(0xaa)
    );
    let pos = ctx.position();
    let middle = ctx.get_binary(16, &mut heap).unwrap().unwrap();
    assert_eq!(
        bytes_and_bits(middle),
        reference_bytes(
            reference
                .eval("<<_:8,M:16/binary-unit:1,_:8>> = <<16#aa,16#bb,16#cc,16#dd>>, M")
                .unwrap()
        )
    );
    assert!(ctx.set_position(pos));
    let tail = ctx.get_tail_unit(8, &mut heap).unwrap().unwrap();
    assert_eq!(bytes_and_bits(tail), (vec![0xbb, 0xcc, 0xdd], 24));
    assert_eq!(ctx.position(), pos);
    assert!(ctx.skip(24));
    assert!(ctx.ensure_exactly(0));
    assert!(!ctx.skip(1));
    assert!(!ctx.set_position(33));

    for (expr, bits, value) in [
        ("<<0.333251953125:16/float>>", 16, 0.333251953125),
        ("<<-0.0:16/float-little>>", 16, -0.0),
        ("<<1.0e-10:32/float-little>>", 32, 1.0e-10),
        ("<<1.234567890123:64/float>>", 64, 1.234567890123),
    ] {
        let expected = reference_bytes(reference.eval(expr).unwrap());
        let float = TermBuilder::new(&mut heap).float(value).unwrap();
        let flags = SegFlags {
            little: expr.contains("little"),
            ..SegFlags::default()
        };
        let segment = Segment {
            ty: SegType::Float,
            index: 1,
            unit: 1,
            flags,
            value: SegmentValue::Term(float),
            size: SegSize::Units(bits),
        };
        let got = create_bin(&[segment], &mut heap).unwrap();
        assert_eq!(bytes_and_bits(got), expected, "{expr}");
        let ctx = start_match(got, &mut heap).unwrap().unwrap();
        assert!(
            ctx.get_float(bits as usize, flags, &mut heap)
                .unwrap()
                .is_some()
        );
    }
    let invalid = TermBuilder::new(&mut heap).binary(&[0xc0, 0xaf]).unwrap();
    let ctx = start_match(invalid, &mut heap).unwrap().unwrap();
    assert!(ctx.get_utf8().is_none());
    assert_eq!(ctx.position(), 0);
}

#[test]
fn utf_match_boundaries_against_erl() {
    let Ok(reference) = RefErl::shared() else {
        eprintln!("skipping: erl is unavailable");
        return;
    };
    let mut heap = VecHeap::new();
    for codepoint in [
        0, 0x7f, 0x80, 0x7ff, 0x800, 0xd7ff, 0xe000, 0xffff, 0x10000, 0x10ffff,
    ] {
        for (suffix, flags) in [
            ("utf8", SegFlags::default()),
            ("utf16", SegFlags::default()),
            (
                "utf16-little",
                SegFlags {
                    little: true,
                    ..SegFlags::default()
                },
            ),
            ("utf32", SegFlags::default()),
            (
                "utf32-little",
                SegFlags {
                    little: true,
                    ..SegFlags::default()
                },
            ),
        ] {
            let (bytes, count) = reference_bytes(
                reference
                    .eval(&format!("<<{codepoint}/{suffix}>>"))
                    .unwrap(),
            );
            let binary = TermBuilder::new(&mut heap)
                .bitstring(&bytes, count)
                .unwrap();
            let ctx = start_match(binary, &mut heap).unwrap().unwrap();
            let got = if suffix == "utf8" {
                ctx.get_utf8()
            } else if suffix.starts_with("utf16") {
                ctx.get_utf16(flags)
            } else {
                ctx.get_utf32(flags)
            };
            assert_eq!(
                got.unwrap().as_small(),
                Some(codepoint),
                "{suffix} {codepoint}"
            );
            assert_eq!(ctx.position(), count);
            assert!(ctx.ensure_exactly(0));
        }
    }
}
