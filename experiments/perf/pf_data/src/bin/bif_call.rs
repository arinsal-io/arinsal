use arinsal_bifs::{Ctx, FragmentingHeap, lookup};
use arinsal_term::{ProcessHeap, Term};
use std::hint::black_box;
use std::time::Instant;

fn main() {
    let tail = Term::small(123).unwrap();
    let mut heap = ProcessHeap::with_words(1024);
    let mut allocator = FragmentingHeap(&mut heap);
    let mut ctx = Ctx::new(&mut allocator);
    let reverse = lookup("lists", "reverse", 2).unwrap();
    for _ in 0..3 {
        let start = Instant::now();
        for _ in 0..1_000_000 {
            black_box(tail);
        }
        println!("plain 1M: {:.3} ms", start.elapsed().as_secs_f64() * 1e3);
        let start = Instant::now();
        for _ in 0..1_000_000 {
            black_box(reverse(&mut ctx, &[Term::NIL, tail]).unwrap());
        }
        println!(
            "direct BIF 1M: {:.3} ms",
            start.elapsed().as_secs_f64() * 1e3
        );
    }
}
