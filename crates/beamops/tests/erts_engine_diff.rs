//! Diagnostic: the engine that follows erts against the legacy engine on every module of the
//! code path. `BEAMOPS_DIFF_REPORT=1 cargo test --release -p arinsal-beamops --test
//! erts_engine_diff -- --nocapture` prints, per op name, how often the two outputs differ.

use arinsal_beam::parse;
use arinsal_beamops::{transform_module_typed, try_transform_module};
use std::collections::BTreeMap;
use std::path::Path;

fn erl_output(expression: &str) -> Option<String> {
    let output = std::process::Command::new("erl")
        .args(["-noshell", "-eval", expression])
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8(output.stdout).ok())
        .flatten()
}

fn flat(functions: Vec<Vec<arinsal_beamops::SpecificOp>>) -> Vec<String> {
    functions
        .into_iter()
        .flatten()
        .map(|op| format!("{op:?}"))
        .collect()
}

fn op_name(text: &str) -> &str {
    text.split('(').next().unwrap_or(text)
}

#[test]
fn engines_agree_up_to_the_known_differences() {
    if std::env::var_os("BEAMOPS_DIFF_REPORT").is_none() {
        return;
    }
    let dirs = erl_output(
        "io:format(\"~s\", [string:join([P || P <- code:get_path(), P =/= \".\"], \"\\n\")]), halt().",
    )
    .unwrap();
    let mut modules = 0;
    let mut identical = 0;
    let mut errors = BTreeMap::<String, usize>::new();
    let mut by_name = BTreeMap::<String, (usize, String)>::new();
    for dir in dirs.lines() {
        let Ok(entries) = std::fs::read_dir(Path::new(dir)) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_none_or(|e| e != "beam") {
                continue;
            }
            let Ok(beam) = parse(&std::fs::read(&path).unwrap()) else {
                continue;
            };
            modules += 1;
            let old = flat(transform_module_typed(&beam, false));
            let new = match try_transform_module(&beam, false, true) {
                Ok(functions) => flat(functions),
                Err(error) => {
                    eprintln!("error {}: {}", path.display(), error.0);
                    *errors.entry(error.0).or_default() += 1;
                    continue;
                }
            };
            if old == new {
                identical += 1;
                continue;
            }
            // Walk both with a one-op resync: report the ops that differ by name.
            let (mut i, mut j) = (0, 0);
            while i < old.len() && j < new.len() {
                if old[i] == new[j] {
                    i += 1;
                    j += 1;
                    continue;
                }
                let key = format!("{} -> {}", op_name(&old[i]), op_name(&new[j]));
                let entry = by_name.entry(key).or_insert((
                    0,
                    format!("{}\n    {}\n    {}", path.display(), old[i], new[j]),
                ));
                entry.0 += 1;
                // Resync: skip to the next equal pair within a window.
                let mut found = false;
                'search: for d in 1..8 {
                    for (di, dj) in [(d, 0), (0, d), (d, d)] {
                        if i + di < old.len() && j + dj < new.len() && old[i + di] == new[j + dj] {
                            i += di;
                            j += dj;
                            found = true;
                            break 'search;
                        }
                    }
                }
                if !found {
                    i += 1;
                    j += 1;
                }
            }
            if old.len() != new.len() {
                *by_name.entry("(length)".into()).or_default() = (0, String::new());
            }
        }
    }
    eprintln!("modules {modules}, identical {identical}, errors {errors:?}");
    let mut rows: Vec<_> = by_name.into_iter().collect();
    rows.sort_by_key(|(_, (count, _))| std::cmp::Reverse(*count));
    for (key, (count, example)) in rows.iter().take(60) {
        eprintln!("{count:7} {key}\n    e.g. {example}");
    }
}
