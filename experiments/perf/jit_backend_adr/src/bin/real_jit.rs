//! Compile accepted real BEAM functions with the isolated JIT tuning copy.

use adr_jit_copy::{CompileError, JitEngine, JitState};
use std::time::Instant;

extern "C" fn ensure(_: *mut JitState, _: u32, _: u32) -> u32 {
    1
}

extern "C" fn materialize(_: *mut JitState, _: u64, _: u64) -> u32 {
    1
}

fn main() {
    let mut total_ops = 0;
    let mut total_code_bytes = 0;
    let mut total_functions = 0;
    let mut total_init_us = 0;
    let mut total_compile_us = 0;
    for path in std::env::args().skip(1) {
        let bytes = std::fs::read(&path).unwrap();
        let beam = arinsal_beam::parse(&bytes).unwrap();
        let loaded = arinsal_loader::load(&beam).unwrap();
        let init = Instant::now();
        let mut jit = JitEngine::new(ensure, materialize).unwrap();
        let init_us = init.elapsed().as_micros();
        let mut remaining: Vec<_> = loaded
            .functions
            .iter()
            .enumerate()
            .map(|(i, (start, _, _))| {
                let end = loaded
                    .functions
                    .get(i + 1)
                    .map_or(loaded.code.len() - 1, |(next, _, _)| *next);
                (start + 1, end.saturating_sub(start + 1))
            })
            .collect();
        let mut compiled = 0;
        let mut ops = 0;
        let mut compile_us = 0;
        for _ in 0..=remaining.len() {
            let before = remaining.len();
            remaining.retain(|(entry, len)| {
                let started = Instant::now();
                match jit.compile(0, &loaded, *entry) {
                    Ok(_) => {
                        compiled += 1;
                        ops += len;
                        compile_us += started.elapsed().as_micros();
                        false
                    }
                    Err(CompileError::PendingDependency { .. }) => true,
                    Err(_) => false,
                }
            });
            if remaining.is_empty() || remaining.len() == before {
                break;
            }
        }
        let name = path.rsplit('/').next().unwrap_or(&path);
        println!(
            "MODULE {name} accepted_functions={compiled} accepted_ops={ops} init_us={init_us} compile_us={compile_us} code_bytes={}",
            jit.code_bytes()
        );
        total_ops += ops;
        total_code_bytes += jit.code_bytes();
        total_functions += compiled;
        total_init_us += init_us;
        total_compile_us += compile_us;
    }
    println!(
        "TOTAL mode={} functions={total_functions} ops={total_ops} init_us={total_init_us} compile_us={total_compile_us} us_per_1k_ops={:.1} code_bytes={total_code_bytes} bytes_per_op={:.1}",
        std::env::var("ADR_JIT_MODE").unwrap_or_else(|_| "default".into()),
        total_compile_us as f64 * 1000.0 / total_ops.max(1) as f64,
        total_code_bytes as f64 / total_ops.max(1) as f64,
    );
}
