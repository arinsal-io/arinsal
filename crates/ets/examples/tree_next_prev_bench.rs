use arinsal_ets::{Protection, Registry, Table, TableOptions, TableType, WriteConcurrency};
use arinsal_term::{Term, TermBuilder, VecHeap, global_atoms};
use std::time::Instant;

const SAMPLES: usize = 5;
const TARGET_CALLS: usize = 1_000_000;

fn options(write_concurrency: WriteConcurrency) -> TableOptions {
    TableOptions {
        name: global_atoms().intern("tree_next_prev_bench").unwrap(),
        named_table: false,
        table_type: TableType::OrderedSet,
        keypos: 1,
        protection: Protection::Public,
        owner: Term::pid(1, 0).unwrap(),
        heir: None,
        read_concurrency: false,
        write_concurrency,
        decentralized_counters: false,
        compressed: false,
    }
}

fn build_table(size: usize, write_concurrency: WriteConcurrency) -> (Registry, arinsal_ets::Tid) {
    let mut registry = Registry::new();
    let tid = registry.create(options(write_concurrency)).unwrap();
    let mut table = registry.get_mut(tid).unwrap();
    let mut heap = VecHeap::new();
    for index in 0..size {
        if index % 1024 == 0 {
            heap = VecHeap::new();
        }
        let key = Term::small(index as i64).unwrap();
        let object = TermBuilder::new(&mut heap).tuple(&[key, key]).unwrap();
        table.insert(&[object]).unwrap();
    }
    drop(table);
    (registry, tid)
}

fn walk(table: &Table, size: usize, reverse: bool, repetitions: usize) -> f64 {
    let mut output = VecHeap::new();
    let started = Instant::now();
    let mut calls = 0;
    for _ in 0..repetitions {
        let mut cursor = table.edge(reverse, &mut output).unwrap().unwrap();
        let mut visited = 0;
        loop {
            if calls % 1024 == 0 {
                output = VecHeap::new();
            }
            let next = if reverse {
                table.prev(cursor, &mut output)
            } else {
                table.next(cursor, &mut output)
            }
            .unwrap();
            calls += 1;
            let Some(next) = next else { break };
            cursor = next;
            visited += 1;
        }
        assert_eq!(visited, size - 1);
    }
    started.elapsed().as_nanos() as f64 / calls as f64
}

fn empty_loop(calls: usize) -> f64 {
    let started = Instant::now();
    for call in 0..calls {
        std::hint::black_box(call);
    }
    started.elapsed().as_nanos() as f64 / calls as f64
}

fn stats(values: &mut [f64; SAMPLES]) -> (f64, f64, f64) {
    values.sort_by(f64::total_cmp);
    (values[SAMPLES / 2], values[0], values[SAMPLES - 1])
}

fn main() {
    for size in [1_000, 100_000] {
        for (name, concurrency) in [
            ("plain", WriteConcurrency::Disabled),
            ("write_concurrency", WriteConcurrency::Enabled),
        ] {
            let (registry, tid) = build_table(size, concurrency);
            let table = registry.get(tid).unwrap();
            let repetitions = (TARGET_CALLS / size).max(1);
            let calls = size * repetitions;
            for (direction, reverse) in [("next", false), ("prev", true)] {
                let mut samples = [0.0; SAMPLES];
                for sample in &mut samples {
                    *sample = walk(&table, size, reverse, repetitions) - empty_loop(calls);
                }
                let (median, min, max) = stats(&mut samples);
                println!(
                    "{name} {direction} {size} keys: {median:.2} ns/call (min {min:.2}, max {max:.2})"
                );
            }
        }
    }
}
