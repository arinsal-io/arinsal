//! Measure the production compiler's whole-function coverage over installed BEAM files.

use arinsal_jit::{CompileError, JitEngine, JitState};
use std::collections::HashMap;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::time::Instant;

extern "C" fn ensure(_: *mut JitState, _: u32, _: u32) -> u32 {
    1
}
extern "C" fn materialize(_: *mut JitState, _: u64, _: u64) -> u32 {
    1
}

fn visit(path: &Path, files: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(path) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            visit(&path, files);
        } else if path.extension() == Some(OsStr::new("beam")) {
            files.push(path);
        }
    }
}

fn main() {
    let roots: Vec<_> = std::env::args().skip(1).collect();
    if roots.is_empty() {
        eprintln!("usage: coverage OTP_ROOT ELIXIR_ROOT");
        std::process::exit(2);
    }
    for root in roots {
        let mut files = Vec::new();
        visit(Path::new(&root), &mut files);
        files.sort();
        let mut parse_ok = 0;
        let mut load_ok = 0;
        let mut fully_native = 0;
        let mut functions = 0;
        let mut compiled = 0;
        let mut ops = 0;
        let mut generic = 0;
        let mut compiled_ops = 0;
        let mut compile_nanos = 0;
        for file in &files {
            let Ok(data) = std::fs::read(file) else {
                continue;
            };
            let Ok(beam) = arinsal_beam::parse(&data) else {
                continue;
            };
            parse_ok += 1;
            let Ok(loaded) = arinsal_loader::load(&beam) else {
                continue;
            };
            load_ok += 1;
            ops += loaded.code.len();
            generic += loaded
                .code
                .iter()
                .filter(|op| {
                    matches!(
                        op,
                        arinsal_loader::Instr::Generic(_) | arinsal_loader::Instr::Unsupported(_)
                    )
                })
                .count();
            let Ok(mut engine) = JitEngine::new(ensure, materialize) else {
                continue;
            };
            let mut remaining: Vec<_> = loaded
                .functions
                .iter()
                .map(|(start, _, _)| start + 1)
                .collect();
            let lengths: HashMap<usize, usize> = remaining
                .iter()
                .copied()
                .zip(
                    loaded
                        .functions
                        .iter()
                        .skip(1)
                        .map(|(start, _, _)| *start)
                        .chain(std::iter::once(loaded.code.len() - 1)),
                )
                .map(|(entry, end)| (entry, end.saturating_sub(entry)))
                .collect();
            functions += remaining.len();
            // Native local dependencies may be declared after callers; retry pending bodies.
            for _ in 0..=remaining.len() {
                let before = remaining.len();
                remaining.retain(|entry| {
                    let started = Instant::now();
                    match engine.compile(0, &loaded, *entry) {
                        Ok(_) => {
                            compiled += 1;
                            compiled_ops += lengths[entry];
                            compile_nanos += started.elapsed().as_nanos();
                            false
                        }
                        Err(CompileError::PendingDependency { .. }) => true,
                        Err(_) => true,
                    }
                });
                if remaining.is_empty() || remaining.len() == before {
                    break;
                }
            }
            if remaining.is_empty() {
                fully_native += 1;
            }
        }
        println!(
            "{root}: beam_files={} parsed={} loaded={} current_jit_full_modules={} current_jit_functions={}/{} resolved_ops={} generic_or_unsupported={} successful_jit_ops={} successful_compile_us_per_1k={:.1}",
            files.len(),
            parse_ok,
            load_ok,
            fully_native,
            compiled,
            functions,
            ops,
            generic,
            compiled_ops,
            compile_nanos as f64 / compiled_ops.max(1) as f64
        );
    }
}
