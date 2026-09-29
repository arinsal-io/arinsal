use arinsal_bits::{
    MatchOps, SegFlags, SegSize, SegType, Segment, SegmentValue, create_bin, private_append,
    start_match,
};
use arinsal_difftest::RefErl;
use arinsal_etf::OwnedTerm;
use arinsal_term::{HeapAlloc, Term, TermBuilder, VecHeap, to_owned, writable_capacity};
use num_bigint::BigInt;
use num_traits::One;

fn erl() -> Option<&'static RefErl> {
    match RefErl::shared() {
        Ok(reference) => Some(reference),
        Err(_) => {
            eprintln!("skipping: erl is unavailable");
            None
        }
    }
}

fn byte_term(term: &OwnedTerm) -> (&[u8], usize) {
    match term {
        OwnedTerm::Binary(bytes) => (bytes, bytes.len() * 8),
        OwnedTerm::BitString { bytes, bits } => (bytes, (bytes.len() - 1) * 8 + usize::from(*bits)),
        other => panic!("expected bitstring, got {other:?}"),
    }
}

fn list(term: OwnedTerm) -> Vec<OwnedTerm> {
    match term {
        OwnedTerm::List {
            ref elems,
            ref tail,
        } if **tail == OwnedTerm::Nil => elems.clone(),
        OwnedTerm::Nil => Vec::new(),
        other => panic!("expected proper list, got {other:?}"),
    }
}

fn tuple(term: OwnedTerm) -> (OwnedTerm, OwnedTerm) {
    match term {
        OwnedTerm::Tuple(ref fields) if fields.len() == 2 => (fields[0].clone(), fields[1].clone()),
        other => panic!("expected pair, got {other:?}"),
    }
}

fn integer(term: &OwnedTerm) -> BigInt {
    match term {
        OwnedTerm::Int(value) => BigInt::from(*value),
        OwnedTerm::BigInt(value) => value.clone(),
        other => panic!("expected integer, got {other:?}"),
    }
}

fn term_from_owned<H: HeapAlloc>(value: &OwnedTerm, heap: &mut H) -> Term {
    let (bytes, bits) = byte_term(value);
    TermBuilder::new(heap).bitstring(bytes, bits).unwrap()
}

#[test]
fn get_integer_all_sizes_signed_unsigned_endian_vs_erl() {
    let Some(reference) = erl() else { return };
    let mut heap = VecHeap::new();
    for bits in 1..=130usize {
        for (signed, little) in [(false, false), (true, false), (false, true), (true, true)] {
            let kind = match (signed, little) {
                (false, false) => "unsigned-big",
                (true, false) => "signed-big",
                (false, true) => "unsigned-little",
                (true, true) => "signed-little",
            };
            let value: BigInt = if signed {
                -(BigInt::one() << (bits - 1))
            } else {
                (BigInt::one() << bits) - BigInt::one()
            };
            let expr =
                format!("[{{<<0:O,V:{bits}/{kind}>>,V}} || O <- lists:seq(0,7), V <- [{value}]]");
            for pair in list(reference.eval(&expr).unwrap()) {
                let (encoded, expected) = tuple(pair);
                let (bytes, total_bits) = byte_term(&encoded);
                let source = TermBuilder::new(&mut heap)
                    .bitstring(bytes, total_bits)
                    .unwrap();
                let context = start_match(source, &mut heap).unwrap().unwrap();
                let offset = total_bits - bits;
                assert!(context.skip(offset));
                let actual = context
                    .get_integer(
                        bits,
                        SegFlags {
                            signed,
                            little,
                            native: false,
                        },
                        &mut heap,
                    )
                    .unwrap()
                    .unwrap();
                assert_eq!(
                    integer(&to_owned(actual).unwrap()),
                    integer(&expected),
                    "{bits} {kind} offset {offset}"
                );
                assert_eq!(context.remaining(), 0);
            }
        }
    }
}

#[test]
fn match_string_unaligned_and_partial_fields_vs_erl() {
    let Some(reference) = erl() else { return };
    let bytes = [0xa5, 0xd3, 0x6c, 0xf0];
    let mut heap = VecHeap::new();

    for offset in 0..8usize {
        for bits in 1..=(32 - offset) {
            let mut expected = 0u64;
            for index in 0..bits {
                let position = offset + index;
                expected =
                    (expected << 1) | u64::from((bytes[position / 8] >> (7 - position % 8)) & 1);
            }
            for candidate in [expected, expected ^ (1 << (bits - 1))] {
                let source = TermBuilder::new(&mut heap).bitstring(&bytes, 32).unwrap();
                let context = start_match(source, &mut heap).unwrap().unwrap();
                assert!(context.skip(offset));

                let actual = context.match_string(&(candidate << (64 - bits)).to_be_bytes(), bits);
                let expression = format!(
                    "case <<{},{},{},{}>> of <<_:{offset},{candidate}:{bits},_/bitstring>> -> true; _ -> false end",
                    bytes[0], bytes[1], bytes[2], bytes[3]
                );
                let expected_match =
                    reference.eval(&expression).unwrap() == OwnedTerm::Atom("true".into());
                assert_eq!(actual, expected_match, "offset={offset} bits={bits}");
                assert_eq!(
                    context.position(),
                    offset + if expected_match { bits } else { 0 },
                    "cursor offset={offset} bits={bits} candidate={candidate}"
                );
            }
        }
    }
}

#[test]
fn put_integer_vs_erl() {
    let Some(reference) = erl() else { return };
    let mut heap = VecHeap::new();
    for bits in 1..=130usize {
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
            let value = BigInt::from(-987_654_321i64) * BigInt::from(bits + 1);
            let term = TermBuilder::new(&mut heap).int_from_bigint(&value).unwrap();
            let segment = Segment {
                ty: SegType::Integer,
                index: 1,
                unit: 1,
                flags,
                value: SegmentValue::Term(term),
                size: SegSize::Units(bits as u64),
            };
            let expected = reference
                .eval(&format!("<<({value}):{bits}/{suffix}>>"))
                .unwrap();
            let actual = to_owned(create_bin(&[segment], &mut heap).unwrap()).unwrap();
            assert_eq!(actual, expected, "{bits} {suffix}");
        }
    }
}

#[test]
fn utf8_16_32_roundtrip_vs_erl() {
    let Some(reference) = erl() else { return };
    let mut heap = VecHeap::new();
    for (ty, name, points) in [
        (
            SegType::Utf8,
            "utf8",
            vec![0, 0x7f, 0x80, 0x7ff, 0x800, 0x1f984, 0x10ffff],
        ),
        (
            SegType::Utf16,
            "utf16",
            vec![0, 0x7f, 0x800, 0xd7ff, 0xe000, 0x1f984, 0x10ffff],
        ),
        (
            SegType::Utf32,
            "utf32",
            vec![0, 0x7f, 0x800, 0x1f984, 0x10ffff],
        ),
    ] {
        for &point in &points {
            for little in [false, true] {
                let endian = if little { "little" } else { "big" };
                let suffix = if ty == SegType::Utf8 {
                    name.to_owned()
                } else {
                    format!("{name}-{endian}")
                };
                let expr = format!("<<16#{point:X}/{suffix}>>");
                let expected = reference.eval(&expr).unwrap();
                let term = Term::small(point).unwrap();
                let segment = Segment {
                    ty,
                    index: 1,
                    unit: 1,
                    flags: SegFlags {
                        little,
                        ..SegFlags::default()
                    },
                    value: SegmentValue::Term(term),
                    size: SegSize::Units(0),
                };
                let actual = to_owned(create_bin(&[segment], &mut heap).unwrap()).unwrap();
                assert_eq!(actual, expected, "{suffix} U+{point:04X}");
                let (bytes, bit_len) = byte_term(&expected);
                let source = TermBuilder::new(&mut heap)
                    .bitstring(bytes, bit_len)
                    .unwrap();
                let context = start_match(source, &mut heap).unwrap().unwrap();
                let decoded = match ty {
                    SegType::Utf8 => context.get_utf8(),
                    SegType::Utf16 => context.get_utf16(SegFlags {
                        little,
                        ..SegFlags::default()
                    }),
                    _ => context.get_utf32(SegFlags {
                        little,
                        ..SegFlags::default()
                    }),
                }
                .unwrap();
                assert_eq!(decoded.as_small(), Some(point));
            }
        }
    }
    for (ty, name, point) in [
        (SegType::Utf8, "utf8", 0xd800),
        (SegType::Utf16, "utf16", 0xd800),
        (SegType::Utf32, "utf32", 0x110000),
    ] {
        let segment = Segment {
            ty,
            index: 1,
            unit: 1,
            flags: SegFlags::default(),
            value: SegmentValue::Term(Term::small(point).unwrap()),
            size: SegSize::Units(0),
        };
        assert!(
            create_bin(&[segment], &mut heap).is_err(),
            "invalid {name} code point"
        );
        assert!(reference.eval(&format!("<<16#{point:X}/{name}>>")).is_err());
    }
}

#[test]
fn float_16_32_64_vs_erl() {
    let Some(reference) = erl() else { return };
    let mut heap = VecHeap::new();
    let value = TermBuilder::new(&mut heap).float(-13.375).unwrap();
    for bits in [16usize, 32, 64] {
        for little in [false, true] {
            let endian = if little { "little" } else { "big" };
            let expected = reference
                .eval(&format!("<<-13.375:{bits}/float-{endian}>>"))
                .unwrap();
            let segment = Segment {
                ty: SegType::Float,
                index: 1,
                unit: 1,
                flags: SegFlags {
                    little,
                    ..SegFlags::default()
                },
                value: SegmentValue::Term(value),
                size: SegSize::Units(bits as u64),
            };
            assert_eq!(
                to_owned(create_bin(&[segment], &mut heap).unwrap()).unwrap(),
                expected,
                "{bits} {endian}"
            );
        }
    }
}

#[test]
fn copy_bits_unaligned_vs_erl() {
    let Some(reference) = erl() else { return };
    let mut heap = VecHeap::new();
    for source_offset in 0..8usize {
        for dest_offset in 0..8usize {
            let source_expr = "<<5:3,16#A5C3:16,3:2>>".to_owned();
            let source_owned = reference.eval(&source_expr).unwrap();
            let source = term_from_owned(&source_owned, &mut heap);
            let sliced = TermBuilder::new(&mut heap)
                .sub_binary(source, source_offset, 13)
                .unwrap();
            let prefix = Segment {
                ty: SegType::Integer,
                index: 1,
                unit: 1,
                flags: SegFlags::default(),
                value: SegmentValue::Term(Term::small(0).unwrap()),
                size: SegSize::Units(dest_offset as u64),
            };
            let binary = Segment {
                ty: SegType::Binary,
                index: 2,
                unit: 1,
                flags: SegFlags::default(),
                value: SegmentValue::Term(sliced),
                size: SegSize::Units(13),
            };
            let actual = to_owned(create_bin(&[prefix, binary], &mut heap).unwrap()).unwrap();
            let expected_expr = format!(
                "<<_:{source_offset}, B:13/bitstring, _:{}>> = {source_expr}, <<0:{dest_offset},B/bitstring>>",
                8 - source_offset
            );
            let expected = reference.eval(&expected_expr).unwrap();
            assert_eq!(
                actual, expected,
                "source {source_offset}, dest {dest_offset}"
            );
        }
    }
}

#[test]
fn private_append_loop_is_amortised() {
    let mut heap = VecHeap::new();
    let mut binary = arinsal_bits::init_writable(&mut heap).unwrap();
    let mut capacity_changes = 0usize;
    let mut capacity = writable_capacity(binary).unwrap();
    for byte in 0..(1024 * 1024) {
        binary = private_append(binary, &[byte as u8], 8, &mut heap).unwrap();
        let next = writable_capacity(binary).unwrap();
        if next != capacity {
            capacity_changes += 1;
            capacity = next;
        }
    }
    assert!(
        capacity_changes <= 32,
        "capacity changed {capacity_changes} times"
    );
}
