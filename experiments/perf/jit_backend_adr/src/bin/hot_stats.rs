//! Map OTP function-entry counters to resolved Arinsal function lengths.

use std::collections::{BTreeSet, HashMap};
use std::io::{self, BufRead};

fn main() {
    let mut paths = BTreeSet::new();
    let mut calls = HashMap::new();
    for line in io::stdin().lock().lines().map_while(Result::ok) {
        if let Some(path) = line.strip_prefix("BEAM_LOADED ") {
            paths.insert(path.to_owned());
        }
        if let Some(record) = line.strip_prefix("HOT_FUNC\t") {
            let fields: Vec<_> = record.split('\t').collect();
            if let [module, function, arity, count] = fields.as_slice()
                && let (Ok(arity), Ok(count)) = (arity.parse::<u8>(), count.parse::<u64>())
            {
                calls.insert((module.to_string(), function.to_string(), arity), count);
            }
        }
    }
    let mut selected = [0_usize; 3];
    let mut functions = [0_usize; 3];
    let mut dynamic = 0_u64;
    let mut total = 0;
    for path in paths {
        if !path.ends_with(".beam") {
            continue;
        }
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        let Ok(beam) = arinsal_beam::parse(&bytes) else {
            continue;
        };
        let Ok(loaded) = arinsal_loader::load(&beam) else {
            continue;
        };
        let module = path.rsplit('/').next().unwrap().trim_end_matches(".beam");
        total += loaded.code.len();
        for (i, (start, name, arity)) in loaded.functions.iter().enumerate() {
            let end = loaded
                .functions
                .get(i + 1)
                .map_or(loaded.code.len() - 1, |next| next.0);
            let len = end.saturating_sub(*start + 1);
            let count = calls
                .get(&(module.to_owned(), name.clone(), *arity))
                .copied()
                .unwrap_or(0);
            dynamic = dynamic.saturating_add((len as u64).saturating_mul(count));
            for (index, threshold) in [1, 8, 1000].into_iter().enumerate() {
                if count >= threshold {
                    selected[index] += len;
                    functions[index] += 1;
                }
            }
        }
    }
    println!(
        "total_ops={total} traced_functions={} dynamic_entry_weighted_ops={dynamic}",
        calls.len()
    );
    for (index, threshold) in [1, 8, 1000].into_iter().enumerate() {
        println!(
            "threshold={threshold} functions={} static_ops={}",
            functions[index], selected[index]
        );
    }
}
