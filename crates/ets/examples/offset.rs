use arinsal_ets::{
    Protection, Registry, TableOptions, TableType, WriteConcurrency, match_spec::MatchProgram,
};
use arinsal_term::{Term, TermBuilder, VecHeap, global_atoms};
use std::time::Instant;

fn atom(name: &str) -> Term {
    Term::atom(global_atoms().intern(name).unwrap())
}

fn main() {
    let count: i64 = std::env::args()
        .nth(1)
        .as_deref()
        .unwrap_or("1000000")
        .parse()
        .unwrap();
    let mut registry = Registry::new();
    let tid = registry
        .create(TableOptions {
            name: global_atoms().intern("offset_bench").unwrap(),
            named_table: false,
            table_type: TableType::OrderedSet,
            keypos: 1,
            protection: Protection::Public,
            owner: Term::pid(1, 0).unwrap(),
            arl_ns: 0,
            heir: None,
            read_concurrency: false,
            write_concurrency: WriteConcurrency::Disabled,
            decentralized_counters: false,
            compressed: false,
        })
        .unwrap();
    let mut table = registry.get_mut(tid).unwrap();
    let mut input = VecHeap::new();
    let start = Instant::now();
    for index in 1..=count {
        let object = TermBuilder::new(&mut input)
            .tuple(&[Term::small(index).unwrap(), Term::small(index * 2).unwrap()])
            .unwrap();
        table.insert(&[object]).unwrap();
    }
    println!("insert {count}: {:.3} s", start.elapsed().as_secs_f64());
    let bound = count - 1000;
    let mut spec_heap = VecHeap::new();
    let mut builder = TermBuilder::new(&mut spec_heap);
    let head = builder.tuple(&[atom("$1"), atom("_")]).unwrap();
    let guard = builder
        .tuple(&[atom(">"), atom("$1"), Term::small(bound).unwrap()])
        .unwrap();
    let guards = builder.list_from_iter([guard]).unwrap();
    let body = builder.list_from_iter([atom("$1")]).unwrap();
    let clause = builder.tuple(&[head, guards, body]).unwrap();
    let spec = builder.list_from_iter([clause]).unwrap();
    let program = MatchProgram::compile(spec).unwrap();
    let mut output = VecHeap::new();
    let repeats = 1000;
    let start = Instant::now();
    for _ in 0..repeats {
        let _ = table.slot(bound as usize, &mut output).unwrap();
    }
    println!(
        "slot offset {bound}: {:.2} us/call",
        start.elapsed().as_secs_f64() * 1e6 / repeats as f64
    );
    let start = Instant::now();
    for _ in 0..repeats {
        let result = table.select_limit(&program, false, 5, &mut output).unwrap();
        assert_eq!(result.len(), 5);
    }
    println!(
        "select key > {bound}, limit 5: {:.2} us/call",
        start.elapsed().as_secs_f64() * 1e6 / repeats as f64
    );
}
