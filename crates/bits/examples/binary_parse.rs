//! `cargo run -p arinsal-bits --release --example binary_parse`
//! Mirrors `tools/bench/kernels/bench.erl`'s 1024-byte frame payload and parsing steps.
use arinsal_bits::{MatchOps, SegFlags, start_match};
use arinsal_term::{TermBuilder, VecHeap};
use std::hint::black_box;
use std::time::Instant;

fn main() {
    const FRAMES: usize = 10_000;
    const ROUNDS: usize = 20;
    let mut heap = VecHeap::new();
    let mut frame = vec![0u8; 1028];
    frame[..4].copy_from_slice(&(1024u32).to_be_bytes());
    frame[4] = 7;
    frame[1027] = 9;
    let stream = TermBuilder::new(&mut heap)
        .binary(&frame.repeat(FRAMES))
        .unwrap();
    let begin = Instant::now();
    let mut checksum = 0usize;
    for _ in 0..ROUNDS {
        let ctx = start_match(stream, &mut heap).unwrap().unwrap();
        while ctx.remaining() != 0 {
            assert!(ctx.ensure_at_least(32, 8));
            let length = ctx
                .get_integer(32, SegFlags::default(), &mut heap)
                .unwrap()
                .unwrap()
                .as_small()
                .unwrap() as usize;
            let payload = ctx.get_binary(length * 8, &mut heap).unwrap().unwrap();
            let owned = arinsal_term::to_owned(payload).unwrap();
            let arinsal_etf::OwnedTerm::Binary(bytes) = &owned else {
                panic!("frame payload");
            };
            checksum += length + bytes.iter().map(|&b| usize::from(b)).sum::<usize>();
        }
    }
    black_box(checksum);
    assert_eq!(checksum, FRAMES * ROUNDS * (1024 + 7 + 9));
    println!(
        "frames={} rounds={} ns/frame={:.1} checksum={checksum}",
        FRAMES,
        ROUNDS,
        begin.elapsed().as_nanos() as f64 / (FRAMES * ROUNDS) as f64
    );
}
