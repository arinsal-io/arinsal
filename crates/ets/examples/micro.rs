use arinsal_ets::{ConcurrentTable, Protection, TableOptions, TableType, WriteConcurrency};
use arinsal_term::{Term, TermBuilder, VecHeap, global_atoms};
use std::time::Instant;

fn main() {
    let iterations = 2_000_000;
    let table = ConcurrentTable::new(
        TableOptions {
            name: global_atoms().intern("ets_micro").unwrap(),
            named_table: false,
            table_type: TableType::Set,
            keypos: 1,
            protection: Protection::Public,
            owner: Term::pid(1, 0).unwrap(),
            heir: None,
            read_concurrency: true,
            write_concurrency: WriteConcurrency::Enabled,
            decentralized_counters: false,
            compressed: false,
        },
        64,
    )
    .unwrap();
    let key = Term::small(1).unwrap();
    let mut heap = VecHeap::new();
    let object = TermBuilder::new(&mut heap)
        .tuple(&[key, Term::small(0).unwrap()])
        .unwrap();
    table.insert_one(object).unwrap();

    let start = Instant::now();
    for index in 0..iterations {
        if index % 1024 == 0 {
            heap = VecHeap::new();
        }
        let object = TermBuilder::new(&mut heap)
            .tuple(&[key, Term::small(index).unwrap()])
            .unwrap();
        table.insert_one(object).unwrap();
    }
    println!(
        "single-thread overwrite: {:.1} ns/op",
        start.elapsed().as_nanos() as f64 / iterations as f64
    );

    let start = Instant::now();
    for index in 0..iterations {
        if index % 1024 == 0 {
            heap = VecHeap::new();
        }
        let result = table.lookup(key, &mut heap).unwrap();
        assert_eq!(result.len(), 1);
    }
    println!(
        "single-thread lookup: {:.1} ns/op",
        start.elapsed().as_nanos() as f64 / iterations as f64
    );
}
