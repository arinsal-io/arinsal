//! Owner-borrowed match cursors: zero-length, short, and unaligned fields.
use arinsal_bits::{MatchOps, SegFlags, start_match};
use arinsal_etf::OwnedTerm;
use arinsal_term::{Term, TermBuilder, VecHeap, to_owned};

fn bit_len(term: Term) -> usize {
    let owned = to_owned(term).unwrap();
    match &owned {
        OwnedTerm::Binary(bytes) => bytes.len() * 8,
        OwnedTerm::BitString { bytes, bits } => (bytes.len() - 1) * 8 + usize::from(*bits),
        other => panic!("expected bitstring: {other:?}"),
    }
}

#[test]
fn zero_length_match_reads_nothing() {
    let mut heap = VecHeap::new();
    let binary = TermBuilder::new(&mut heap).bitstring(&[], 0).unwrap();
    let ctx = start_match(binary, &mut heap).unwrap().unwrap();
    assert_eq!(ctx.remaining(), 0);
    assert!(ctx.ensure_exactly(0));
    assert!(!ctx.ensure_at_least(1, 1));
    assert!(
        ctx.get_integer(1, SegFlags::default(), &mut heap)
            .unwrap()
            .is_none()
    );
    assert!(ctx.get_binary(1, &mut heap).unwrap().is_none());
    assert_eq!(ctx.remaining(), 0);
    assert_eq!(bit_len(ctx.get_tail(&mut heap).unwrap()), 0);
}

#[test]
fn short_read_leaves_the_cursor() {
    let mut heap = VecHeap::new();
    let binary = TermBuilder::new(&mut heap).binary(&[0xab]).unwrap();
    let ctx = start_match(binary, &mut heap).unwrap().unwrap();
    assert!(
        ctx.get_integer(16, SegFlags::default(), &mut heap)
            .unwrap()
            .is_none()
    );
    assert_eq!(ctx.remaining(), 8);
    assert_eq!(ctx.position(), 0);
    let value = ctx
        .get_integer(8, SegFlags::default(), &mut heap)
        .unwrap()
        .unwrap();
    assert_eq!(value.as_small(), Some(0xab));
    assert_eq!(ctx.remaining(), 0);
}

#[test]
fn unaligned_sub_binary_keeps_bit_offsets() {
    let mut heap = VecHeap::new();
    // MSB-first bits of 0b1011_0110 then 0b1100_0001. From bit 3, eight bits are
    // 1,0,1,1,0,1,1,0.
    let source = TermBuilder::new(&mut heap)
        .binary(&[0b1011_0110, 0b1100_0001])
        .unwrap();
    let slice = TermBuilder::new(&mut heap)
        .sub_binary(source, 3, 8)
        .unwrap();
    let ctx = start_match(slice, &mut heap).unwrap().unwrap();
    assert_eq!(ctx.remaining(), 8);
    let value = ctx
        .get_integer(8, SegFlags::default(), &mut heap)
        .unwrap()
        .unwrap();
    assert_eq!(value.as_small(), Some(0b1011_0110));
    assert!(
        ctx.get_integer(1, SegFlags::default(), &mut heap)
            .unwrap()
            .is_none()
    );
    assert_eq!(ctx.remaining(), 0);
}

#[test]
fn aligned_u32_rejects_a_short_tail() {
    let mut heap = VecHeap::new();
    let mut frame = vec![0u8; 6];
    frame[..4].copy_from_slice(&0x0102_0304u32.to_be_bytes());
    frame[4] = 0xaa;
    frame[5] = 0xbb;
    let binary = TermBuilder::new(&mut heap).binary(&frame).unwrap();
    let ctx = start_match(binary, &mut heap).unwrap().unwrap();
    assert_eq!(arinsal_bits::match_u32_be(ctx), Some(0x0102_0304));
    assert_eq!(ctx.remaining(), 16);
    assert!(
        ctx.get_integer(24, SegFlags::default(), &mut heap)
            .unwrap()
            .is_none()
    );
    assert_eq!(ctx.remaining(), 16);
    assert_eq!(
        ctx.get_integer(16, SegFlags::default(), &mut heap)
            .unwrap()
            .unwrap()
            .as_small(),
        Some(0xaabb)
    );
}

#[test]
fn zero_length_field_does_not_advance() {
    let mut heap = VecHeap::new();
    let binary = TermBuilder::new(&mut heap).binary(&[0xff]).unwrap();
    let ctx = start_match(binary, &mut heap).unwrap().unwrap();
    let empty = ctx.get_binary(0, &mut heap).unwrap().unwrap();
    assert_eq!(bit_len(empty), 0);
    assert_eq!(ctx.remaining(), 8);
    assert_eq!(
        ctx.get_integer(8, SegFlags::default(), &mut heap)
            .unwrap()
            .unwrap()
            .as_small(),
        Some(0xff)
    );
}
