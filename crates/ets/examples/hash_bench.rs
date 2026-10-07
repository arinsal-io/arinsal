use arinsal_ets::{
    ConcurrentTable, Protection, Registry, TableOptions, TableType, WriteConcurrency,
};
use arinsal_term::{Term, TermBuilder, VecHeap, global_atoms};
use std::sync::Arc;
use std::thread;
use std::time::Instant;

fn options() -> TableOptions {
    TableOptions {
        name: global_atoms().intern("hash_bench").unwrap(),
        named_table: false,
        table_type: TableType::Set,
        keypos: 1,
        protection: Protection::Public,
        owner: Term::pid(1, 0).unwrap(),
        heir: None,
        read_concurrency: false,
        write_concurrency: WriteConcurrency::Disabled,
        decentralized_counters: false,
        compressed: false,
    }
}

fn insert_range(table: &ConcurrentTable, start: i64, count: i64) {
    let mut heap = VecHeap::new();
    for offset in 0..count {
        if offset % 4096 == 0 {
            heap = VecHeap::new();
        }
        let key = start + offset;
        let value = Term::small(key).unwrap();
        let object = TermBuilder::new(&mut heap).tuple(&[value, value]).unwrap();
        table.insert_one(object).unwrap();
    }
}

fn main() {
    const N: i64 = 1_000_000;
    const ERL_INSERT_NS: f64 = 238.0;
    const ERL_LOOKUP_NS: f64 = 114.0;
    let mut best_insert = f64::INFINITY;
    let mut best_lookup = f64::INFINITY;
    let mut best_member = f64::INFINITY;

    for run in 0..3 {
        let mut registry = Registry::new();
        let table = registry.create(options()).unwrap();

        let mut table = registry.get_mut(table).unwrap();
        let mut heap = VecHeap::new();
        let start = Instant::now();
        for i in 0..N {
            if i % 4096 == 0 {
                heap = VecHeap::new();
            }
            let object = TermBuilder::new(&mut heap)
                .tuple(&[Term::small(i).unwrap(), Term::small(i).unwrap()])
                .unwrap();
            table.insert(&[object]).unwrap();
        }
        best_insert = best_insert.min(start.elapsed().as_nanos() as f64 / N as f64);

        let start = Instant::now();
        for i in 0..N {
            assert!(table.member(Term::small(i).unwrap()));
        }
        best_member = best_member.min(start.elapsed().as_nanos() as f64 / N as f64);

        let mut heap = VecHeap::new();
        let start = Instant::now();
        for i in 0..N {
            if i % 4096 == 0 {
                heap = VecHeap::new();
            }
            let key = Term::small(i).unwrap();
            assert!(table.lookup_one(key, &mut heap).unwrap().is_some());
        }
        best_lookup = best_lookup.min(start.elapsed().as_nanos() as f64 / N as f64);
        println!("run {run}: insert and lookup complete");
    }

    println!(
        "insert best_of_3_ns_per_op={best_insert:.1} baseline_erts_29_1_1_ns_per_op={ERL_INSERT_NS:.1} (ets:insert, 1M integer keys)"
    );
    println!(
        "lookup best_of_3_ns_per_op={best_lookup:.1} baseline_erts_29_1_1_ns_per_op={ERL_LOOKUP_NS:.1} (ets:lookup, 1M integer keys)"
    );
    println!("member diagnostic_best_of_3_ns_per_op={best_member:.1}");
    if best_insert > ERL_INSERT_NS {
        println!("REGRESSION insert {best_insert:.1} > {ERL_INSERT_NS:.1} ns/op");
    }
    if best_lookup > ERL_LOOKUP_NS {
        println!("REGRESSION lookup {best_lookup:.1} > {ERL_LOOKUP_NS:.1} ns/op");
    }

    const SCALE_OPS: i64 = 1_000_000;
    const ERL_PARALLEL_NS: f64 = 190.0;
    const ERL_SCALE: f64 = 1.15;
    let mut single_ns = f64::INFINITY;
    let mut parallel_ns = f64::INFINITY;
    for run in 0..5 {
        let mut concurrent_options = options();
        concurrent_options.write_concurrency = WriteConcurrency::Enabled;
        let single_table = ConcurrentTable::new(concurrent_options, 1).unwrap();
        let start = Instant::now();
        insert_range(&single_table, 0, SCALE_OPS);
        single_ns = single_ns.min(start.elapsed().as_nanos() as f64 / SCALE_OPS as f64);

        let parallel_table = Arc::new(ConcurrentTable::new(concurrent_options, 8).unwrap());
        let start = Instant::now();
        let mut workers = Vec::with_capacity(8);
        for worker in 0..8_i64 {
            let table = Arc::clone(&parallel_table);
            workers.push(thread::spawn(move || {
                insert_range(&table, worker * (SCALE_OPS / 8), SCALE_OPS / 8);
            }));
        }
        for worker in workers {
            worker.join().unwrap();
        }
        parallel_ns = parallel_ns.min(start.elapsed().as_nanos() as f64 / SCALE_OPS as f64);
        println!("8_process_insert run {run}: single and parallel complete");
    }
    let speedup = single_ns / parallel_ns;
    println!(
        "8_process_insert_best_of_5_ns_per_op={parallel_ns:.1} erts_baseline_ns_per_op={ERL_PARALLEL_NS:.1} scaling={speedup:.2}x erts_baseline_scaling={ERL_SCALE:.2} single_ns_op={single_ns:.1}"
    );
    if parallel_ns > ERL_PARALLEL_NS {
        println!("REGRESSION 8-process insert {parallel_ns:.1} > {ERL_PARALLEL_NS:.1} ns/op");
    }
    if speedup < ERL_SCALE {
        println!("REGRESSION 8-process scaling {speedup:.2}x < {ERL_SCALE:.2}x");
    }
}
