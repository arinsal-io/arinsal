use arinsal_ets::{ConcurrentTable, Protection, TableOptions, TableType, WriteConcurrency};
use arinsal_term::{Term, TermBuilder, VecHeap, global_atoms};
use std::sync::Arc;
use std::time::Instant;

fn main() {
    let operations: usize = std::env::args()
        .nth(1)
        .as_deref()
        .unwrap_or("1000000")
        .parse()
        .unwrap();
    let table = Arc::new(
        ConcurrentTable::new(
            TableOptions {
                name: global_atoms().intern("ordered_writers").unwrap(),
                named_table: false,
                table_type: TableType::OrderedSet,
                keypos: 1,
                protection: Protection::Public,
                owner: Term::pid(1, 0).unwrap(),
                heir: None,
                read_concurrency: false,
                write_concurrency: WriteConcurrency::Enabled,
                decentralized_counters: true,
                compressed: false,
            },
            64,
        )
        .unwrap(),
    );
    let started = Instant::now();
    let workers: Vec<_> = (0..4)
        .map(|worker| {
            let table = Arc::clone(&table);
            std::thread::spawn(move || {
                let mut heap = VecHeap::new();
                for index in 0..operations / 4 {
                    if index % 1024 == 0 {
                        heap = VecHeap::new();
                    }
                    let key = Term::small((index * 4 + worker) as i64).unwrap();
                    let object = TermBuilder::new(&mut heap).tuple(&[key, key]).unwrap();
                    table.insert_one(object).unwrap();
                }
            })
        })
        .collect();
    for worker in workers {
        worker.join().unwrap();
    }
    assert_eq!(table.len(), operations);
    println!(
        "ordered_set 4 writers: {:.3} ms",
        started.elapsed().as_secs_f64() * 1000.0
    );
}
