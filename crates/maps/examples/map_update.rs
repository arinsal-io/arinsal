use arinsal_maps::{from_pairs, put};
use arinsal_term::{Term, VecHeap};
use std::hint::black_box;
use std::time::Instant;

fn small(value: i64) -> Term {
    Term::small(value).unwrap()
}

fn main() {
    let size: i64 = std::env::args()
        .nth(1)
        .map(|value| value.parse().expect("integer map size"))
        .unwrap_or(1000);
    let iterations: i64 = std::env::args()
        .nth(2)
        .map(|value| value.parse().expect("integer iteration count"))
        .unwrap_or(200_000);
    assert!(size > 0 && iterations > 0);
    let mut heap = VecHeap::new();
    let initial: Vec<_> = (0..size).map(|i| (small(i), small(i))).collect();
    let mut map = from_pairs(&initial, &mut heap).unwrap();
    let start = Instant::now();
    for i in 0..iterations {
        map = put(map, small(i % size), small(i + 1), &mut heap).unwrap();
    }
    let elapsed = start.elapsed();
    black_box(map);
    println!(
        "{iterations} updates over {size} keys: {:.3} ms, {:.1} ns/op, {} words allocated",
        elapsed.as_secs_f64() * 1000.,
        elapsed.as_nanos() as f64 / iterations as f64,
        heap.used_words()
    );
}
