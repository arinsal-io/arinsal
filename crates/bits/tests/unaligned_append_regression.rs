use arinsal_bits::{
    SegFlags, SegSize, SegType, Segment, SegmentValue, create_bin, init_writable, private_append,
};
use arinsal_difftest::RefErl;
use arinsal_etf::OwnedTerm;
use arinsal_term::{ProcessHeap, TermBuilder, to_owned};
use similar_asserts::assert_eq;

#[test]
fn private_append_preserves_unaligned_prefix_before_binary_suffix() {
    let reference = match RefErl::shared() {
        Ok(reference) => reference,
        Err(_) => {
            eprintln!("skipping: erl is unavailable");
            return;
        }
    };
    let expected = reference.eval("<<1:1, \"1\">>").unwrap();

    let mut heap = ProcessHeap::with_words(128);
    let empty = init_writable(&mut heap).unwrap();
    let prefix = TermBuilder::new(&mut heap).bitstring(&[0x80], 1).unwrap();
    let first = create_bin(
        &[
            Segment {
                ty: SegType::PrivateAppend,
                index: 1,
                unit: 1,
                flags: SegFlags::default(),
                value: SegmentValue::Term(empty),
                size: SegSize::All,
            },
            Segment {
                ty: SegType::Binary,
                index: 2,
                unit: 1,
                flags: SegFlags::default(),
                value: SegmentValue::Term(prefix),
                size: SegSize::All,
            },
        ],
        &mut heap,
    )
    .unwrap();
    let suffix = TermBuilder::new(&mut heap).binary(b"1").unwrap();
    let actual = create_bin(
        &[
            Segment {
                ty: SegType::PrivateAppend,
                index: 1,
                unit: 1,
                flags: SegFlags::default(),
                value: SegmentValue::Term(first),
                size: SegSize::All,
            },
            Segment {
                ty: SegType::Binary,
                index: 2,
                unit: 1,
                flags: SegFlags::default(),
                value: SegmentValue::Term(suffix),
                size: SegSize::All,
            },
        ],
        &mut heap,
    )
    .unwrap();

    assert_eq!(to_owned(actual).unwrap(), expected);
    assert_eq!(
        expected,
        OwnedTerm::BitString {
            bytes: vec![0x98, 0x80],
            bits: 1
        }
    );
}

#[test]
fn private_append_clears_zero_bits_in_a_dirty_destination_byte() {
    let reference = match RefErl::shared() {
        Ok(reference) => reference,
        Err(_) => {
            eprintln!("skipping: erl is unavailable");
            return;
        }
    };
    let expected = reference.eval("<<1:1, 0:7>>").unwrap();

    let mut heap = ProcessHeap::with_words(128);
    let writer = TermBuilder::new(&mut heap)
        .writable_binary(&[0xff], 1, 1024)
        .unwrap();
    let actual = private_append(writer, &[0], 7, &mut heap).unwrap();

    assert_eq!(to_owned(actual).unwrap(), expected);
    assert_eq!(expected, OwnedTerm::Binary(vec![0x80]));
}
