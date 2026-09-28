use arinsal_bits::{
    MatchOps, SegFlags, SegSize, SegType, Segment, SegmentValue, create_bin, init_writable,
    private_append, start_match,
};
use arinsal_term::{Term, TermBuilder, VecHeap};
use std::hint::black_box;
use std::time::Instant;

fn report(name: &str, iterations: usize, elapsed: std::time::Duration) {
    println!(
        "{name}: {:.1} ns/op",
        elapsed.as_nanos() as f64 / iterations as f64
    );
}

fn main() {
    const N: usize = 1_000_000;
    let mut heap = VecHeap::new();
    let source = TermBuilder::new(&mut heap)
        .binary(&[0x12, 0x34, 0x56, 0x78, 0, 0, 0, 0])
        .unwrap();
    for offset in [0usize, 3] {
        let context = start_match(source, &mut heap).unwrap().unwrap();
        let start = Instant::now();
        let mut sum = 0i64;
        for _ in 0..N {
            assert!(context.set_position(offset));
            sum += context
                .get_integer(32, SegFlags::default(), &mut heap)
                .unwrap()
                .unwrap()
                .as_small()
                .unwrap();
        }
        black_box(sum);
        report(&format!("get_integer offset={offset}"), N, start.elapsed());
    }
    let value = Term::small(0x1234_5678).unwrap();
    let segment = Segment {
        ty: SegType::Integer,
        index: 1,
        unit: 1,
        flags: SegFlags::default(),
        value: SegmentValue::Term(value),
        size: SegSize::Units(32),
    };
    let start = Instant::now();
    for _ in 0..N {
        black_box(create_bin(std::slice::from_ref(&segment), &mut heap).unwrap());
    }
    report("put_integer", N, start.elapsed());

    let mut writer = init_writable(&mut heap).unwrap();
    let start = Instant::now();
    for i in 0..N {
        writer = private_append(writer, &[i as u8], 8, &mut heap).unwrap();
    }
    black_box(writer);
    report("private_append byte", N, start.elapsed());
}
