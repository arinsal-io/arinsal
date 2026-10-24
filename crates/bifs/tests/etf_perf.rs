use arinsal_bifs::{Ctx, EncodeWalk, ProcessHeapHandle, lookup};
use arinsal_term::{ProcessHeap, Term, TermBuilder, atoms, global_atoms};
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
        ("local pid", Term::pid(1, 2).unwrap(), "self()"),
        (
            "local port",
            Term::port(1).unwrap(),
            "open_port({spawn, \"cat\"}, [])",
        ),
        ("list of 100 ints", list, "lists:seq(0,99)"),
        ("nested tuple", nested_tuple, "{9,{0,{1,2}}}"),
    ];
    let encode = lookup("erlang", "term_to_binary", 1).unwrap();
    let decode = lookup("erlang", "binary_to_term", 1).unwrap();
    let rounds = 100_000;
    for (label, term, otp_term) in cases {
        if matches!(label, "local ref" | "local pid" | "local port") {
            encoder_phases(label, term, rounds);
        }
        let erlang_eval = format!(
            "T={otp_term}, B=term_to_binary(T), L=fun F(_,0)->ok; F(X,N)->term_to_binary(X),F(X,N-1) end, D=fun F(_,0)->ok; F(X,N)->binary_to_term(X),F(X,N-1) end, E=fun F(_,0)->ok; F(X,N)->F(X,N-1) end, L(T,{rounds}),D(B,{rounds}), S=[begin A=erlang:monotonic_time(nanosecond),L(T,{rounds}),erlang:monotonic_time(nanosecond)-A end || _ <- lists:seq(1,5)], ES=[begin A=erlang:monotonic_time(nanosecond),E(T,{rounds}),erlang:monotonic_time(nanosecond)-A end || _ <- lists:seq(1,5)], EN=lists:sort([X/{rounds} || X <- ES]), N=lists:sort([max(X/{rounds}-lists:nth(3,EN),0.0) || X <- S]), io:format(\"OTP ETF encode {label}: median ~.2f ns/op, min-max ~.2f-~.2f ns/op\", [lists:nth(3,N),hd(N),lists:last(N)]), S2=[begin A=erlang:monotonic_time(nanosecond),D(B,{rounds}),erlang:monotonic_time(nanosecond)-A end || _ <- lists:seq(1,5)], ES2=[begin A=erlang:monotonic_time(nanosecond),E(B,{rounds}),erlang:monotonic_time(nanosecond)-A end || _ <- lists:seq(1,5)], EN2=lists:sort([X/{rounds} || X <- ES2]), N2=lists:sort([max(X/{rounds}-lists:nth(3,EN2),0.0) || X <- S2]), io:format(\"~nOTP ETF decode {label}: median ~.2f ns/op, min-max ~.2f-~.2f ns/op~n\", [lists:nth(3,N2),hd(N2),lists:last(N2)]), halt()."
        );
        let otp = std::process::Command::new("timeout")
            .args(["60", "erl", "+S", "1:1", "-noshell", "-eval", &erlang_eval])
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
        let empty_started = Instant::now();
        for _ in 0..rounds {
            black_box(term);
        }
        let empty_ns = empty_started.elapsed().as_nanos() as f64 / rounds as f64;
        eprintln!(
            "ETF {label}: median {:.2} ns/op, min-max {:.2}-{:.2} ns/op ({rounds} rounds/sample)",
            samples[2] - empty_ns,
            samples[0] - empty_ns,
            samples[4] - empty_ns
        );
        let mut encoded_heap = ProcessHeap::with_words(256);
        let mut encoded_alloc = ProcessHeapHandle(&mut encoded_heap);
        let encoded = encode(&mut Ctx::new(&mut encoded_alloc), &[term]).unwrap();
        for _ in 0..10_000 {
            let mut heap = ProcessHeap::with_words(256);
            let mut alloc = ProcessHeapHandle(&mut heap);
            black_box(decode(&mut Ctx::new(&mut alloc), &[encoded]).unwrap());
        }
        let mut samples = Vec::with_capacity(5);
        for _ in 0..5 {
            let started = Instant::now();
            for _ in 0..rounds {
                let mut heap = ProcessHeap::with_words(256);
                let mut alloc = ProcessHeapHandle(&mut heap);
                black_box(decode(&mut Ctx::new(&mut alloc), &[encoded]).unwrap());
            }
            samples.push(started.elapsed().as_nanos() as f64 / rounds as f64);
        }
        samples.sort_by(f64::total_cmp);
        eprintln!(
            "ETF decode {label}: median {:.2} ns/op, min-max {:.2}-{:.2} ns/op ({rounds} rounds/sample)",
            samples[2] - empty_ns,
            samples[0] - empty_ns,
            samples[4] - empty_ns
        );
    }
}

fn encoder_phases(label: &str, term: Term, rounds: usize) {
    let node = global_atoms().get("nonode@nohost").unwrap_or(atoms::NONAME);
    let setup = measure(rounds, || {
        let mut encoder = EncodeWalk::new(&[term]).unwrap();
        encoder.set_local_node(node, 0);
        black_box(encoder);
    });
    let setup_size = measure(rounds, || {
        let mut encoder = EncodeWalk::new(&[term]).unwrap();
        encoder.set_local_node(node, 0);
        encoder.step_size(usize::MAX).unwrap();
        black_box(encoder);
    });
    let size = EncodeWalk::new(&[term]).unwrap();
    let mut sized = size;
    sized.set_local_node(node, 0);
    sized.step_size(usize::MAX).unwrap();
    let encoded_size = sized.encoded_size().unwrap();
    let allocation = measure(rounds, || {
        black_box(vec![0; encoded_size]);
    });
    let write_all = measure(rounds, || {
        let mut encoder = EncodeWalk::new(&[term]).unwrap();
        encoder.set_local_node(node, 0);
        encoder.step_size(usize::MAX).unwrap();
        let mut bytes = vec![0; encoded_size];
        encoder.step_into(&mut bytes, usize::MAX).unwrap();
        black_box(bytes);
    });
    eprintln!(
        "ETF phases {label}: setup {setup:.2} ns/op, size+setup {:.2} ns/op (increment {:.2}), buffer alloc {allocation:.2}, encode+setup+size+alloc {write_all:.2}",
        setup_size,
        setup_size - setup
    );
}

fn measure(rounds: usize, mut operation: impl FnMut()) -> f64 {
    for _ in 0..10_000 {
        operation();
    }
    let started = Instant::now();
    for _ in 0..rounds {
        operation();
    }
    let empty_started = Instant::now();
    for _ in 0..rounds {
        black_box(());
    }
    started.elapsed().as_nanos() as f64 / rounds as f64
        - empty_started.elapsed().as_nanos() as f64 / rounds as f64
}
