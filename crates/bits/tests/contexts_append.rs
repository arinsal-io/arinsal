use arinsal_bits::{
    MatchOps, SegFlags, SegSize, SegType, Segment, SegmentValue, append, create_bin, get_position,
    init_writable, private_append, set_position_term, start_match,
};
use arinsal_etf::OwnedTerm;
use arinsal_term::{
    Term, TermBuilder, VecHeap, binary_offset_adjustment, copy_term, is_match_context,
    is_writable_binary, sub_bits_flags, to_owned, writable_capacity, writable_gc_visit,
};

fn payload(term: Term) -> (Vec<u8>, usize) {
    let owned = to_owned(term).unwrap();
    match &owned {
        OwnedTerm::Binary(bytes) => (bytes.clone(), bytes.len() * 8),
        OwnedTerm::BitString { bytes, bits } => {
            let len = (bytes.len() - 1) * 8 + usize::from(*bits);
            (bytes.clone(), len)
        }
        other => panic!("expected bitstring: {other:?}"),
    }
}
use std::time::Instant;

#[test]
fn bounded_byte_reads_reuse_one_context_without_heap_words() {
    let mut heap = VecHeap::new();
    let bytes = (0..4096).map(|n| n as u8).collect::<Vec<_>>();
    let source = TermBuilder::new(&mut heap).binary(&bytes).unwrap();
    let context = start_match(source, &mut heap).unwrap().unwrap();
    let allocated = heap.used_words();
    for &byte in &bytes {
        assert_eq!(
            arinsal_bits::match_uint_be(context, 8, 1, 8),
            Some(u32::from(byte))
        );
    }
    assert!(context.ensure_exactly(0));
    assert_eq!(
        heap.used_words(),
        allocated,
        "byte loop allocated heap words"
    );
    assert_eq!(arinsal_bits::match_uint_be(context, 8, 1, 8), None);
    assert_eq!(heap.used_words(), allocated);
}

#[test]
fn bounded_byte_read_preserves_unaligned_and_failed_match_positions() {
    let mut heap = VecHeap::new();
    let source = TermBuilder::new(&mut heap).binary(&[0xaa, 0xcc]).unwrap();
    let slice = TermBuilder::new(&mut heap)
        .sub_binary(source, 1, 9)
        .unwrap();
    let context = start_match(slice, &mut heap).unwrap().unwrap();
    assert_eq!(arinsal_bits::match_uint_be(context, 8, 1, 8), Some(0x55));
    let position = context.position();
    assert_eq!(arinsal_bits::match_uint_be(context, 8, 1, 8), None);
    assert_eq!(context.position(), position);
    assert_eq!(context.remaining(), 1);
}

#[test]
fn private_byte_append_reuses_writer_without_heap_words() {
    let mut heap = VecHeap::new();
    let mut writer = init_writable(&mut heap).unwrap();
    let allocated = heap.used_words();
    for byte in 0..4096 {
        writer = arinsal_bits::private_append_byte(writer, byte, &mut heap).unwrap();
    }
    assert_eq!(heap.used_words(), allocated);
    let (bytes, bits) = payload(writer);
    assert_eq!(bits, 4096 * 8);
    assert_eq!(bytes[0], 0);
    assert_eq!(bytes[255], 255);
    assert_eq!(bytes[256], 0);
}

#[test]
fn match_context_reuses_term_and_round_trips_absolute_positions() {
    let mut heap = VecHeap::new();
    let source = TermBuilder::new(&mut heap).binary(&[10; 80]).unwrap();
    let slice = TermBuilder::new(&mut heap)
        .sub_binary(source, 16, 40)
        .unwrap();
    let context = start_match(slice, &mut heap).unwrap().unwrap();
    assert!(is_match_context(context));
    let initial_position = 16 + binary_offset_adjustment(context) * 8;
    assert_eq!(context.position(), initial_position);
    assert_eq!(start_match(context, &mut heap).unwrap().unwrap(), context);
    assert!(context.skip(8));
    let position = context.position();
    let encoded = get_position(context, &mut heap).unwrap();
    assert_eq!(encoded.as_small(), Some(position as i64));
    assert_eq!(position, initial_position + 8);
    assert!(context.skip(8));
    assert!(set_position_term(context, encoded));
    assert_eq!(context.position(), initial_position + 8);
    assert_eq!(context.remaining(), 32);
    let tail = context.get_tail(&mut heap).unwrap();
    assert!(!is_match_context(tail));
    assert_eq!(payload(tail).1, 32);
    let mut copy_heap = VecHeap::new();
    let copied = copy_term(context, &mut copy_heap).unwrap();
    assert!(copied.skip(8));
    assert_eq!(copied.position(), initial_position + 16);
    assert_eq!(context.position(), initial_position + 8);
}

#[test]
fn writable_slices_survive_growth_and_force_copy_on_write() {
    let mut heap = VecHeap::new();
    let writer = init_writable(&mut heap).unwrap();
    assert!(is_writable_binary(writer));
    assert_eq!(sub_bits_flags(writer), 3);
    let writer = append(writer, &[11; 80], 640, &mut heap).unwrap();
    let old = writer;
    let writer = append(writer, &[12; 4_000], 32_000, &mut heap).unwrap();
    let (old_bytes, old_bits) = payload(old);
    assert_eq!(old_bits, 640);
    assert_eq!(old_bytes, [11; 80]);
    let slice = TermBuilder::new(&mut heap)
        .sub_binary(writer, 8, 80)
        .unwrap();
    assert!(!is_writable_binary(writer));
    assert_eq!(sub_bits_flags(writer), 0);
    let next = append(writer, &[13; 4_000], 32_000, &mut heap).unwrap();
    let (slice_bytes, slice_bits) = payload(slice);
    assert_eq!(slice_bits, 80);
    assert_eq!(slice_bytes, [11; 10]);
    assert_eq!(payload(next).1, (80 + 4_000 + 4_000) * 8);
}

#[test]
fn gc_visits_preserve_active_writer_and_shrink_inactive_capacity() {
    let mut heap = VecHeap::new();
    let writer = init_writable(&mut heap).unwrap();
    assert_eq!(writable_capacity(writer), Some(1024));
    // SAFETY: this stopped single-process test has no live binary view.
    unsafe { writable_gc_visit(writer) };
    assert_eq!(writable_capacity(writer), Some(1024));
    // SAFETY: the writer is inactive and no view is live.
    unsafe { writable_gc_visit(writer) };
    assert!(writable_capacity(writer).unwrap() < 1024);
    let writer = private_append(writer, b"x", 8, &mut heap).unwrap();
    // SAFETY: append finished and no view is live.
    unsafe { writable_gc_visit(writer) };
    assert!(is_writable_binary(writer));
}

#[test]
fn create_bin_append_segments_share_the_writable_path() {
    let mut heap = VecHeap::new();
    let initial_source = init_writable(&mut heap).unwrap();
    let initial = [
        Segment {
            ty: SegType::PrivateAppend,
            index: 1,
            unit: 8,
            flags: SegFlags::default(),
            value: SegmentValue::Term(initial_source),
            size: SegSize::All,
        },
        Segment {
            ty: SegType::String,
            index: 2,
            unit: 8,
            flags: SegFlags::default(),
            value: SegmentValue::String(b"abc"),
            size: SegSize::Units(3),
        },
    ];
    let source = create_bin(&initial, &mut heap).unwrap();
    assert_eq!(source, initial_source);
    assert!(is_writable_binary(source));
    let segments = [
        Segment {
            ty: SegType::Append,
            index: 1,
            unit: 8,
            flags: SegFlags::default(),
            value: SegmentValue::Term(source),
            size: SegSize::All,
        },
        Segment {
            ty: SegType::Binary,
            index: 2,
            unit: 8,
            flags: SegFlags::default(),
            value: SegmentValue::Term(source),
            size: SegSize::All,
        },
    ];
    let doubled = create_bin(&segments, &mut heap).unwrap();
    assert_eq!(payload(source).0, b"abc");
    assert_eq!(payload(doubled).0, b"abcabc");
}

#[test]
fn ten_megabyte_private_append_is_linear_and_matches_erl() {
    fn build(bytes: usize) -> (std::time::Duration, VecHeap, arinsal_term::Term) {
        let mut heap = VecHeap::new();
        let mut binary = init_writable(&mut heap).unwrap();
        let start = Instant::now();
        for _ in 0..bytes {
            binary = private_append(binary, &[42], 8, &mut heap).unwrap();
        }
        (start.elapsed(), heap, binary)
    }
    let (small_time, _small_heap, _small) = build(1_000_000);
    let (large_time, large_heap, large) = build(10_000_000);
    let (bytes, bits) = payload(large);
    assert_eq!(bits, 80_000_000);
    assert!(bytes.iter().all(|byte| *byte == 42));
    let ratio = large_time.as_secs_f64() / small_time.as_secs_f64();
    eprintln!(
        "Rust private append: 1 MB {:?}, 10 MB {:?}, ratio {:.2}; heap words {}",
        small_time,
        large_time,
        ratio,
        large_heap.used_words()
    );
    assert!(ratio < 15.0, "append growth ratio was {ratio:.2}");

    let scratch = std::env::temp_dir().join(format!("arinsal-append-{}", std::process::id()));
    std::fs::create_dir_all(&scratch).unwrap();
    let fixture = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/append_bench.erl"
    );
    let compile = match std::process::Command::new("erlc")
        .arg("-o")
        .arg(&scratch)
        .arg(fixture)
        .output()
    {
        Ok(output) => output,
        Err(_) => {
            eprintln!("skipping OTP comparison: erlc is unavailable");
            return;
        }
    };
    assert!(
        compile.status.success(),
        "{}",
        String::from_utf8_lossy(&compile.stderr)
    );
    let expression = "N=10000000, {Micros,B}=timer:tc(append_bench,run,[N]), io:format(\"~p ~p ~p~n\",[Micros,byte_size(B),B==binary:copy(<<42>>,N)]), halt().";
    let output = match std::process::Command::new("erl")
        .arg("-pa")
        .arg(&scratch)
        .args(["-noshell", "-eval", expression])
        .output()
    {
        Ok(output) => output,
        Err(_) => {
            eprintln!("skipping OTP comparison: erl is unavailable");
            return;
        }
    };
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result = String::from_utf8(output.stdout).unwrap();
    let fields: Vec<_> = result.split_whitespace().collect();
    assert_eq!(fields.len(), 3, "{result}");
    assert_eq!(&fields[1..], &["10000000", "true"]);
    eprintln!("OTP private append: {} us for 10 MB", fields[0]);
    std::fs::remove_dir_all(&scratch).unwrap();
}
