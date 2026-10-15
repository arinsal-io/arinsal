use arinsal_ets::{ConcurrentTable, Protection, TableOptions, TableType, WriteConcurrency};
use arinsal_term::{Term, TermBuilder, VecHeap, global_atoms};
use std::sync::Arc;
use std::thread;
use std::time::Instant;

const KEYS: usize = 1_000_000;
const KEY_SPACE: usize = 1 << 20;
const KEY_MULTIPLIER: usize = 0x9e37;
const KEY_OFFSET: usize = 0x51a2d;
const THREADS: usize = 8;
type Adaptation = (usize, usize, usize, usize, usize, Vec<i64>);

fn options(write_concurrency: WriteConcurrency) -> TableOptions {
    TableOptions {
        name: global_atoms().intern("catree_bench").unwrap(),
        named_table: false,
        table_type: TableType::OrderedSet,
        keypos: 1,
        protection: Protection::Public,
        owner: Term::pid(1, 0).unwrap(),
        arl_ns: 0,
        heir: None,
        read_concurrency: false,
        write_concurrency,
        decentralized_counters: false,
        compressed: false,
    }
}

fn run(write_concurrency: WriteConcurrency) -> (f64, Option<Adaptation>) {
    let stripes = if write_concurrency == WriteConcurrency::Disabled {
        1
    } else {
        64
    };
    let table = Arc::new(ConcurrentTable::new(options(write_concurrency), stripes).unwrap());
    let start = Instant::now();
    let workers = (0..THREADS)
        .map(|worker| {
            let table = Arc::clone(&table);
            thread::spawn(move || {
                let start = worker * (KEYS / THREADS);
                let end = start + KEYS / THREADS;
                let mut heap = VecHeap::new();
                let mut output = VecHeap::new();
                for raw in start..end {
                    if raw % 128 == 0 {
                        heap = VecHeap::new();
                        output = VecHeap::new();
                    }
                    let mixed_key =
                        raw.wrapping_mul(KEY_MULTIPLIER).wrapping_add(KEY_OFFSET) & (KEY_SPACE - 1);
                    let key = Term::small(mixed_key as i64).unwrap();
                    let object = TermBuilder::new(&mut heap).tuple(&[key, key]).unwrap();
                    table.insert_one(object).unwrap();
                    assert_eq!(table.lookup(key, &mut output).unwrap().len(), 1);
                }
            })
        })
        .collect::<Vec<_>>();
    for worker in workers {
        worker.join().unwrap();
    }
    assert_eq!(table.len(), KEYS);
    (
        start.elapsed().as_nanos() as f64 / (2 * KEYS) as f64,
        table.catree_debug_adaptation_counts(),
    )
}

fn main() {
    let (avl, _) = run(WriteConcurrency::Disabled);
    let (catree, adaptation) = run(WriteConcurrency::Enabled);
    println!("AVL 8 threads mixed insert/lookup, {KEYS} keys: {avl:.1} ns/op");
    println!("CA-tree 8 threads mixed insert/lookup, {KEYS} keys: {catree:.1} ns/op");
    println!(
        "CA-tree adaptation (bases, splits, joins, low-stat joins, gravity joins, final base statistics): {adaptation:?}"
    );
    if catree > avl {
        println!("REGRESSION: CA-tree is slower than AVL at 8 threads");
    }
}
