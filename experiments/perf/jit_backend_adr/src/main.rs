//! Count Arinsal resolved operations in the BEAM files loaded by a command.

use std::collections::BTreeSet;
use std::io::{self, BufRead};

fn main() {
    let mut paths = BTreeSet::new();
    for line in io::stdin().lock().lines().map_while(Result::ok) {
        if let Some(path) = line.strip_prefix("BEAM_LOADED ") {
            paths.insert(path.to_owned());
        }
    }
    let mut modules = 0;
    let mut ops = 0;
    let mut functions = 0;
    for path in paths {
        if !path.ends_with(".beam") {
            continue;
        }
        let Ok(bytes) = std::fs::read(&path) else {
            eprintln!("unreadable {path}");
            continue;
        };
        let Ok(beam) = arinsal_beam::parse(&bytes) else {
            eprintln!("parse failed {path}");
            continue;
        };
        let Ok(loaded) = arinsal_loader::load(&beam) else {
            eprintln!("load failed {path}");
            continue;
        };
        let name = path.rsplit('/').next().unwrap_or(&path);
        println!(
            "MODULE {name} ops={} functions={}",
            loaded.code.len(),
            loaded.functions.len()
        );
        modules += 1;
        ops += loaded.code.len();
        functions += loaded.functions.len();
    }
    println!("TOTAL modules={modules} ops={ops} functions={functions}");
}
