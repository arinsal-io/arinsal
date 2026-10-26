//! Timing of the generic-op transformation on OTP modules, the largest part of the JIT compile
//! of the boot modules: `cargo test --release -p arinsal-beamops --test transform_bench --
//! --ignored --nocapture`.

use arinsal_beamops::{NewLiteral, OpSink, SpecificOperand, TransformArena, load_code};
use std::time::Instant;

/// Takes the operations and drops them: what the transform costs without an assembler.
struct Null;

impl OpSink for Null {
    fn new_literal(&mut self, _index: u32, _literal: &NewLiteral) -> Result<(), String> {
        Ok(())
    }

    fn emit(&mut self, _op: u16, _operands: &[SpecificOperand]) -> Result<(), String> {
        Ok(())
    }
}

const MODULES: &[(&str, &str)] = &[
    ("stdlib", "erl_parse"),
    ("stdlib", "erl_lint"),
    ("stdlib", "lists"),
    ("stdlib", "erl_eval"),
    ("stdlib", "gen_server"),
    ("kernel", "inet"),
    ("kernel", "application_controller"),
    ("kernel", "global"),
];

fn lib_dir() -> Option<std::path::PathBuf> {
    let output = std::process::Command::new("erl")
        .args([
            "-noshell",
            "-eval",
            "io:format(\"~s\", [code:lib_dir()]), halt().",
        ])
        .output()
        .ok()?;
    Some(std::path::PathBuf::from(
        String::from_utf8(output.stdout).ok()?,
    ))
}

#[test]
#[ignore = "timing"]
fn transform_modules() {
    let Some(lib) = lib_dir() else {
        eprintln!("erl unavailable; skipping");
        return;
    };
    let mut beams = Vec::new();
    for (app, module) in MODULES {
        let dir = std::fs::read_dir(&lib)
            .expect("lib dir")
            .filter_map(Result::ok)
            .find(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(&format!("{app}-"))
            })
            .expect("application");
        let path = dir.path().join("ebin").join(format!("{module}.beam"));
        let bytes = std::fs::read(&path).expect("beam");
        beams.push(arinsal_beam::parse(&bytes).expect("parse"));
    }
    let instructions: usize = beams.iter().map(|beam| beam.code.instructions.len()).sum();
    let mut arena = TransformArena::new();
    let rounds: u32 = std::env::var("ROUNDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(20);
    let started = Instant::now();
    for _ in 0..rounds {
        for beam in &beams {
            load_code(beam, false, true, &mut arena, &mut Null).unwrap();
        }
    }
    let elapsed = started.elapsed();
    eprintln!(
        "{} instructions per round, {:.1} ms per round, {:.1} ns per instruction",
        instructions,
        elapsed.as_secs_f64() * 1000.0 / f64::from(rounds),
        elapsed.as_nanos() as f64 / (f64::from(rounds) * instructions as f64)
    );
}
