use arinsal_arith::{band, bsl, mul};
use arinsal_term::{Term, TermBuilder, VecHeap};
use num_bigint::BigInt;
use std::hint::black_box;
use std::time::Instant;

fn main() {
    let mut inputs = VecHeap::new();
    let a = TermBuilder::new(&mut inputs)
        .int_from_bigint(&(BigInt::from(1u64) << 1000usize))
        .unwrap();
    let b = TermBuilder::new(&mut inputs)
        .int_from_bigint(&BigInt::from(3u64).pow(700))
        .unwrap();
    let a_alt = TermBuilder::new(&mut inputs)
        .int_from_bigint(&((BigInt::from(1u64) << 1000usize) + 1))
        .unwrap();
    let x = TermBuilder::new(&mut inputs)
        .int_from_bigint(&((BigInt::from(1u64) << 4096usize) - 1))
        .unwrap();
    let y = TermBuilder::new(&mut inputs)
        .int_from_bigint(&((BigInt::from(1u64) << 4095usize) + 12345))
        .unwrap();
    let x_alt = TermBuilder::new(&mut inputs)
        .int_from_bigint(&((BigInt::from(1u64) << 4096usize) - 2))
        .unwrap();
    let shift = Term::small(31).unwrap();
    let mut output = VecHeap::new();
    let now = Instant::now();
    for i in 0..20_000 {
        black_box(mul([a, a_alt][i % 2], b, &mut output).unwrap());
    }
    println!(
        "mul_2pow1000_3pow700_20000_us={}",
        now.elapsed().as_micros()
    );
    let now = Instant::now();
    for i in 0..20_000 {
        black_box(bsl([x, x_alt][i % 2], shift, &mut output).unwrap());
    }
    println!("bsl_4096_20000_us={}", now.elapsed().as_micros());
    let now = Instant::now();
    for i in 0..20_000 {
        black_box(band([x, x_alt][i % 2], y, &mut output).unwrap());
    }
    println!("band_4096_20000_us={}", now.elapsed().as_micros());
    let now = Instant::now();
    for _ in 0..200 {
        let mut heap = VecHeap::new();
        let mut n = Term::small(1).unwrap();
        for k in 2..=1000 {
            n = mul(n, Term::small(k).unwrap(), &mut heap).unwrap();
        }
        black_box(n);
    }
    println!("factorial_1000_200_us={}", now.elapsed().as_micros());
}
