use arinsal_etf::OwnedTerm;
use arinsal_ets::match_spec::MatchProgram;
use arinsal_ets::{Protection, Registry, TableOptions, TableType, WriteConcurrency};
use arinsal_term::{Term, VecHeap, from_owned, global_atoms};
use std::hint::black_box;
use std::time::Instant;

fn atom(name: &str) -> OwnedTerm {
    OwnedTerm::atom(name)
}

fn int(value: i64) -> OwnedTerm {
    OwnedTerm::Int(value)
}

fn tuple(values: Vec<OwnedTerm>) -> OwnedTerm {
    OwnedTerm::Tuple(values)
}

fn list(values: Vec<OwnedTerm>) -> OwnedTerm {
    OwnedTerm::list(values)
}

fn main() {
    let options = TableOptions {
        name: global_atoms().intern("ms_bench").unwrap(),
        named_table: false,
        table_type: TableType::OrderedSet,
        keypos: 1,
        protection: Protection::Protected,
        owner: Term::pid(1, 0).unwrap(),
        heir: None,
        read_concurrency: false,
        write_concurrency: WriteConcurrency::Disabled,
        decentralized_counters: false,
        compressed: false,
    };
    let mut registry = Registry::new();
    let tid = registry.create(options).unwrap();
    let mut table = registry.get_mut(tid).unwrap();
    let mut input = VecHeap::new();
    for key in 0..100_000 {
        let object = from_owned(&tuple(vec![int(key), int(key % 1000)]), &mut input).unwrap();
        table.insert(&[object]).unwrap();
    }
    let specification = list(vec![tuple(vec![
        tuple(vec![atom("$1"), atom("$2")]),
        list(vec![tuple(vec![atom(">="), atom("$1"), int(50_000)])]),
        list(vec![atom("true")]),
    ])]);
    let program = MatchProgram::compile(from_owned(&specification, &mut input).unwrap()).unwrap();
    let mut output = VecHeap::new();
    let start = Instant::now();
    let results = black_box(table.select(&program, false, &mut output).unwrap());
    let elapsed = start.elapsed().as_nanos();
    println!(
        "{:.2} ns/object ({} results)",
        elapsed as f64 / 100_000.0,
        results.len()
    );
}
