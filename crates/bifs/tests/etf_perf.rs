use arinsal_bifs::{Ctx, FragmentingHeap, lookup};
use arinsal_term::{ProcessHeap, Term, TermBuilder};
use std::hint::black_box;
use std::time::Instant;

#[test]
#[ignore = "run separately in release mode for the ETF performance gate"]
fn one_megabyte_mixed_term() {
    let mut source_heap = ProcessHeap::with_words(50_000);
    let mut builder = TermBuilder::new(&mut source_heap);
    let mut parts = Vec::new();
    for i in 0..1000 {
        let data: Vec<u8> = (0..1024).map(|j| (i * 31 + j * 17) as u8).collect();
        let binary = builder.binary(&data).unwrap();
        parts.push(builder.tuple(&[Term::small(i).unwrap(), binary]).unwrap());
    }
    let term = builder.tuple(&parts).unwrap();
    let encode = lookup("erlang", "term_to_binary", 1).unwrap();
    let decode = lookup("erlang", "binary_to_term", 1).unwrap();
    let mut output_heap = ProcessHeap::with_words(256);
    let mut output_alloc = FragmentingHeap(&mut output_heap);
    let binary = encode(&mut Ctx::new(&mut output_alloc), &[term]).unwrap();
    // SAFETY: the output heap retains the binary and does not move during the benchmark.
    let size = unsafe { binary.binary_ref() }.unwrap().bit_len() / 8;
    assert!((1_000_000..1_100_000).contains(&size), "{size}");
    let rounds = 200;
    for _ in 0..10 {
        let mut heap = ProcessHeap::with_words(256);
        let mut alloc = FragmentingHeap(&mut heap);
        black_box(encode(&mut Ctx::new(&mut alloc), &[term]).unwrap());
    }
    let started = Instant::now();
    for _ in 0..rounds {
        let mut heap = ProcessHeap::with_words(256);
        let mut alloc = FragmentingHeap(&mut heap);
        black_box(encode(&mut Ctx::new(&mut alloc), &[term]).unwrap());
    }
    let encode_us = started.elapsed().as_micros() as f64 / rounds as f64;
    for _ in 0..10 {
        let mut heap = ProcessHeap::with_words(16_000);
        let mut alloc = FragmentingHeap(&mut heap);
        black_box(decode(&mut Ctx::new(&mut alloc), &[binary]).unwrap());
    }
    let started = Instant::now();
    for _ in 0..rounds {
        let mut heap = ProcessHeap::with_words(16_000);
        let mut alloc = FragmentingHeap(&mut heap);
        black_box(decode(&mut Ctx::new(&mut alloc), &[binary]).unwrap());
    }
    let decode_us = started.elapsed().as_micros() as f64 / rounds as f64;
    eprintln!(
        "ETF mixed term {size} bytes: encode {encode_us:.1} us, decode {decode_us:.1} us ({rounds} rounds)"
    );
}
