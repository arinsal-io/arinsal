use arinsal_ets::{Protection, Registry, TableOptions, TableType, WriteConcurrency};
use arinsal_term::{Term, TermBuilder, VecHeap, global_atoms};
use std::hint::black_box;
use std::time::Instant;

fn main() {
    let rows: i64 = std::env::var("PF_ROWS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(2_000);
    let mut registry = Registry::new();
    let owner = Term::pid(1, 0).unwrap();
    let tid = registry
        .create(TableOptions {
            name: global_atoms().intern("pf_data_probe").unwrap(),
            named_table: false,
            table_type: TableType::Set,
            keypos: 1,
            protection: Protection::Public,
            owner,
            heir: None,
            read_concurrency: false,
            write_concurrency: WriteConcurrency::Disabled,
            decentralized_counters: false,
            compressed: false,
        })
        .unwrap();
    let mut input = VecHeap::new();
    for value in 1..=rows {
        let integer = Term::small(value).unwrap();
        let tuple = TermBuilder::new(&mut input)
            .tuple(&[integer, integer])
            .unwrap();
        registry.get_mut(tid).unwrap().insert(&[tuple]).unwrap();
    }
    let table = registry.get(tid).unwrap();
    for _ in 0..3 {
        let start = Instant::now();
        for _ in 0..2_000 {
            black_box(table.info().options.protection);
        }
        println!(
            "rows={rows} info 2000: {:.3} ms",
            start.elapsed().as_secs_f64() * 1e3
        );

        let start = Instant::now();
        for _ in 0..2_000 {
            black_box(table.options.protection);
        }
        println!(
            "rows={rows} flags 2000: {:.3} ms",
            start.elapsed().as_secs_f64() * 1e3
        );
    }
}
