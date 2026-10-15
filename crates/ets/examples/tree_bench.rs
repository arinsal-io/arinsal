use arinsal_ets::{Protection, Registry, TableOptions, TableType, WriteConcurrency};
use arinsal_term::{Term, TermBuilder, VecHeap, global_atoms};
use std::time::Instant;

const KEYS: usize = 1_000_000;
const BASELINE_NS: [f64; 3] = [185.0, 114.9, 103.5];

fn run_once() -> [f64; 3] {
    let mut registry = Registry::new();
    let tid = registry
        .create(TableOptions {
            name: global_atoms().intern("tree_bench").unwrap(),
            named_table: false,
            table_type: TableType::OrderedSet,
            keypos: 1,
            protection: Protection::Public,
            owner: Term::pid(1, 0).unwrap(),
            ns: 0,
            heir: None,
            read_concurrency: false,
            write_concurrency: WriteConcurrency::Disabled,
            decentralized_counters: false,
            compressed: false,
        })
        .unwrap();
    let mut table = registry.get_mut(tid).unwrap();
    let mut heap = VecHeap::new();

    let start = Instant::now();
    for key in 0..KEYS {
        if key % 1024 == 0 {
            heap = VecHeap::new();
        }
        let key = Term::small(key as i64).unwrap();
        let object = TermBuilder::new(&mut heap).tuple(&[key, key]).unwrap();
        table.insert(&[object]).unwrap();
    }
    let insert = start.elapsed();

    let start = Instant::now();
    for key in 0..KEYS {
        if key % 1024 == 0 {
            heap = VecHeap::new();
        }
        let key = Term::small(key as i64).unwrap();
        assert_eq!(table.lookup(key, &mut heap).unwrap().len(), 1);
    }
    let lookup = start.elapsed();

    let start = Instant::now();
    for key in 0..KEYS - 1 {
        if key % 1024 == 0 {
            heap = VecHeap::new();
        }
        let key = Term::small(key as i64).unwrap();
        assert_eq!(
            table.next(key, &mut heap).unwrap().unwrap().as_small(),
            Some(key.as_small().unwrap() + 1)
        );
    }
    let next = start.elapsed();
    [
        insert.as_nanos() as f64 / KEYS as f64,
        lookup.as_nanos() as f64 / KEYS as f64,
        next.as_nanos() as f64 / (KEYS - 1) as f64,
    ]
}

fn median(mut values: [f64; 3]) -> f64 {
    values.sort_by(f64::total_cmp);
    values[1]
}

fn main() {
    let runs = [run_once(), run_once(), run_once()];
    let rates = [
        median([runs[0][0], runs[1][0], runs[2][0]]),
        median([runs[0][1], runs[1][1], runs[2][1]]),
        median([runs[0][2], runs[1][2], runs[2][2]]),
    ];
    for (name, rate, baseline) in [
        ("insert", rates[0], BASELINE_NS[0]),
        ("lookup", rates[1], BASELINE_NS[1]),
        ("next", rates[2], BASELINE_NS[2]),
    ] {
        println!("{name}: {rate:.1} ns/op (pre-port {baseline:.1})");
        if rate > baseline {
            println!("REGRESSION: {name} is slower than its pre-port baseline");
        }
    }
}
