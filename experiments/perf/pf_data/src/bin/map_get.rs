use arinsal_term::{Term, VecHeap};
use std::collections::HashMap;
use std::hint::black_box;
use std::time::Instant;

fn main() {
    let mut heap = VecHeap::new();
    let pairs = (1..=10_000)
        .map(|value| {
            let term = Term::small(value).unwrap();
            (term, term)
        })
        .collect::<Vec<_>>();
    let map = arinsal_maps::from_pairs(&pairs, &mut heap).unwrap();
    let hash = (1..=10_000)
        .map(|value| (value, value))
        .collect::<HashMap<_, _>>();
    for _ in 0..3 {
        let start = Instant::now();
        for value in 1..=1_000_000 {
            let key = Term::small(value % 10_000 + 1).unwrap();
            black_box(arinsal_maps::get(map, key).unwrap().unwrap());
        }
        println!(
            "Arinsal HAMT get: {:.2} ns",
            start.elapsed().as_nanos() as f64 / 1e6
        );

        let start = Instant::now();
        for value in 1..=1_000_000 {
            black_box(hash.get(&(value % 10_000 + 1)).unwrap());
        }
        println!(
            "Rust HashMap get: {:.2} ns",
            start.elapsed().as_nanos() as f64 / 1e6
        );
    }
}
