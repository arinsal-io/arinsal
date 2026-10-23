use arinsal_bifs::{Ctx, ProcessHeapHandle, lookup};
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
    let mut output_alloc = ProcessHeapHandle(&mut output_heap);
    let binary = encode(&mut Ctx::new(&mut output_alloc), &[term]).unwrap();
    // SAFETY: the output heap retains the binary and does not move during the benchmark.
    let size = unsafe { binary.binary_ref() }.unwrap().bit_len() / 8;
    assert!((1_000_000..1_100_000).contains(&size), "{size}");
    let rounds = 200;
    for _ in 0..10 {
        let mut heap = ProcessHeap::with_words(256);
        let mut alloc = ProcessHeapHandle(&mut heap);
        black_box(encode(&mut Ctx::new(&mut alloc), &[term]).unwrap());
    }
    let started = Instant::now();
    for _ in 0..rounds {
        let mut heap = ProcessHeap::with_words(256);
        let mut alloc = ProcessHeapHandle(&mut heap);
        black_box(encode(&mut Ctx::new(&mut alloc), &[term]).unwrap());
    }
    let encode_us = started.elapsed().as_micros() as f64 / rounds as f64;
    for _ in 0..10 {
        let mut heap = ProcessHeap::with_words(16_000);
        let mut alloc = ProcessHeapHandle(&mut heap);
        black_box(decode(&mut Ctx::new(&mut alloc), &[binary]).unwrap());
    }
    let started = Instant::now();
    for _ in 0..rounds {
        let mut heap = ProcessHeap::with_words(16_000);
        let mut alloc = ProcessHeapHandle(&mut heap);
        black_box(decode(&mut Ctx::new(&mut alloc), &[binary]).unwrap());
    }
    let decode_us = started.elapsed().as_micros() as f64 / rounds as f64;
    eprintln!(
        "ETF mixed term {size} bytes: encode {encode_us:.1} us, decode {decode_us:.1} us ({rounds} rounds)"
    );
}

#[test]
#[ignore = "run separately in release mode for the scalar ETF performance gate"]
fn requested_scalar_cases() {
    let make_ref = lookup("erlang", "make_ref", 0).unwrap();
    let mut ref_heap = ProcessHeap::with_words(256);
    let mut ref_alloc = ProcessHeapHandle(&mut ref_heap);
    let local_ref = make_ref(&mut Ctx::new(&mut ref_alloc), &[]).unwrap();

    let mut source_heap = ProcessHeap::with_words(4096);
    let mut builder = TermBuilder::new(&mut source_heap);
    let small_tuple = builder
        .tuple(&[
            Term::small(7).unwrap(),
            Term::small(42).unwrap(),
            Term::small(256).unwrap(),
        ])
        .unwrap();
    let map_pairs = (0..10)
        .map(|i| (Term::small(i).unwrap(), Term::small(i * 3).unwrap()))
        .collect::<Vec<_>>();
    let ten_key_map = builder.flatmap_from_pairs(&map_pairs).unwrap();
    let binary = builder.binary(&[0x5a; 1024]).unwrap();
    let list = builder
        .list_from_iter((0..100).map(|i| Term::small(i).unwrap()))
        .unwrap();
    let inner = builder
        .tuple(&[Term::small(1).unwrap(), Term::small(2).unwrap()])
        .unwrap();
    let middle = builder.tuple(&[Term::small(0).unwrap(), inner]).unwrap();
    let nested_tuple = builder.tuple(&[Term::small(9).unwrap(), middle]).unwrap();
    let cases = [
        ("small tuple", small_tuple, "{7,42,256}"),
        (
            "10-key map",
            ten_key_map,
            "maps:from_list([{I,I*3} || I <- lists:seq(0,9)])",
        ),
        ("1 KiB binary", binary, "binary:copy(<<16#5a>>,1024)"),
        ("local ref", local_ref, "make_ref()"),
        ("list of 100 ints", list, "lists:seq(0,99)"),
        ("nested tuple", nested_tuple, "{9,{0,{1,2}}}"),
    ];
    let encode = lookup("erlang", "term_to_binary", 1).unwrap();
    let rounds = 100_000;
    for (label, term, otp_term) in cases {
        let erlang_eval = format!(
            "T={otp_term}, L=fun F(_,0)->ok; F(X,N)->term_to_binary(X),F(X,N-1) end, S=[begin A=erlang:monotonic_time(nanosecond),L(T,{rounds}),erlang:monotonic_time(nanosecond)-A end || _ <- lists:seq(1,5)], N=lists:sort([X/{rounds} || X <- S]), io:format(\"OTP ETF {label}: median ~.2f ns/op, min-max ~.2f-~.2f ns/op~n\", [lists:nth(3,N),hd(N),lists:last(N)]), halt()."
        );
        let otp = std::process::Command::new("timeout")
            .args(["60", "erl", "-noshell", "-eval", &erlang_eval])
            .output()
            .expect("run one-shot OTP benchmark");
        assert!(
            otp.status.success(),
            "OTP benchmark failed: {}",
            String::from_utf8_lossy(&otp.stderr)
        );
        eprint!("{}", String::from_utf8_lossy(&otp.stdout));
        for _ in 0..10_000 {
            let mut heap = ProcessHeap::with_words(256);
            let mut alloc = ProcessHeapHandle(&mut heap);
            black_box(encode(&mut Ctx::new(&mut alloc), &[black_box(term)]).unwrap());
        }
        let mut samples = Vec::with_capacity(5);
        for _ in 0..5 {
            let started = Instant::now();
            for _ in 0..rounds {
                let mut heap = ProcessHeap::with_words(256);
                let mut alloc = ProcessHeapHandle(&mut heap);
                black_box(encode(&mut Ctx::new(&mut alloc), &[black_box(term)]).unwrap());
            }
            samples.push(started.elapsed().as_nanos() as f64 / rounds as f64);
        }
        samples.sort_by(f64::total_cmp);
        eprintln!(
            "ETF {label}: median {:.2} ns/op, min-max {:.2}-{:.2} ns/op ({rounds} rounds/sample)",
            samples[2], samples[0], samples[4]
        );
    }
}
