use arinsal_ets::{ConcurrentTable, Protection, TableOptions, TableType, WriteConcurrency};
use arinsal_term::{Term, TermBuilder, VecHeap, global_atoms};
use std::sync::Arc;
use std::time::Instant;

fn main() {
    let operations: usize = std::env::args()
        .nth(1)
        .as_deref()
        .unwrap_or("12000000")
        .parse()
        .unwrap();
    let stripes: usize = std::env::args()
        .nth(2)
        .as_deref()
        .unwrap_or("2048")
        .parse()
        .unwrap();
    let table = Arc::new(
        ConcurrentTable::new(
            TableOptions {
                name: global_atoms().intern("mixed_bench").unwrap(),
                named_table: false,
                table_type: TableType::Set,
                keypos: 1,
                protection: Protection::Public,
                owner: Term::pid(1, 0).unwrap(),
                arl_ns: 0,
                heir: None,
                read_concurrency: true,
                write_concurrency: WriteConcurrency::Enabled,
                decentralized_counters: false,
                compressed: false,
            },
            stripes,
        )
        .unwrap(),
    );
    let mut initial = VecHeap::new();
    for key in 0..1000 {
        let object = TermBuilder::new(&mut initial)
            .tuple(&[Term::small(key).unwrap(), Term::small(0).unwrap()])
            .unwrap();
        table.insert_one(object).unwrap();
    }
    let start = Instant::now();
    let handles: Vec<_> = (0..4)
        .map(|worker| {
            let table = Arc::clone(&table);
            std::thread::spawn(move || {
                let mut sum = 0_usize;
                let mut heap = VecHeap::new();
                for index in 0..operations / 4 {
                    if index % 1024 == 0 {
                        heap = VecHeap::new();
                    }
                    let key = ((index * 4 + worker) % 1000) as i64;
                    if index % 4 == 0 {
                        let object = TermBuilder::new(&mut heap)
                            .tuple(&[
                                Term::small(key).unwrap(),
                                Term::small(index as i64).unwrap(),
                            ])
                            .unwrap();
                        table.insert_one(object).unwrap();
                        sum += 1;
                    } else {
                        let result = table.lookup(Term::small(key).unwrap(), &mut heap).unwrap();
                        assert_eq!(result.len(), 1);
                        sum += 1;
                    }
                }
                sum
            })
        })
        .collect();
    let total: usize = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .sum();
    println!("{total}");
    println!(
        "ets mixed: {:.3} ms",
        start.elapsed().as_secs_f64() * 1000.0
    );
}
