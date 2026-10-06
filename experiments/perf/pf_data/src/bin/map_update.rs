use arinsal_term::{Term, VecHeap};
use std::collections::HashMap;
use std::hint::black_box;
use std::time::Instant;

fn main() {
    const KEYS: i64 = 1_000;
    const UPDATES: i64 = 200_000;
    for _ in 0..3 {
        let mut heap = VecHeap::new();
        let pairs = (0..KEYS)
            .map(|value| {
                let term = Term::small(value).unwrap();
                (term, term)
            })
            .collect::<Vec<_>>();
        let mut persistent = arinsal_maps::from_pairs(&pairs, &mut heap).unwrap();
        let start = Instant::now();
        for value in 0..UPDATES {
            persistent = arinsal_maps::put(
                persistent,
                Term::small(value % KEYS).unwrap(),
                Term::small(value + 1).unwrap(),
                &mut heap,
            )
            .unwrap();
        }
        black_box(persistent);
        println!(
            "Arinsal HAMT put: {:.2} ns, {} heap words",
            start.elapsed().as_nanos() as f64 / UPDATES as f64,
            heap.used_words()
        );

        let mut editable = (0..KEYS)
            .map(|value| (value, value))
            .collect::<HashMap<_, _>>();
        let start = Instant::now();
        for value in 0..UPDATES {
            black_box(editable.insert(value % KEYS, value + 1));
        }
        black_box(editable);
        println!(
            "Rust mutable HashMap put: {:.2} ns",
            start.elapsed().as_nanos() as f64 / UPDATES as f64
        );
    }
}
