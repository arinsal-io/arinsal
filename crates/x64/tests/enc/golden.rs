//! Golden-byte checks against the system GNU assembler.
//!
//! Each [`Case`] pairs the Intel-syntax text of the encoding asmjit emits for an erts call with
//! the `Emitter` call that must produce it. [`check`] assembles all texts in one `as` run, splits
//! the `.text` bytes at a label placed after every instruction, and compares per case.
//!
//! Where GNU `as` would choose a different (equivalent) encoding than asmjit, write the text that
//! forces asmjit's: the operand that asmjit really encodes (`and eax, 0xff` for `and rax, 0xff`
//! under `kOptimizeForSize`), or GNU pseudo-prefixes `{load}`, `{store}`, `{disp8}`, `{disp32}`,
//! `{vex3}`. Such cases also document asmjit's choice.

use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

use arinsal_x64::enc::{Emitter, EncodeError};

/// An expected-assembly text and the emitter call that must encode to the same bytes.
pub type Case = (&'static str, fn(&mut Emitter) -> Result<(), EncodeError>);

static SEQ: AtomicUsize = AtomicUsize::new(0);

fn tool_ok(tool: &str, marker: &str) -> bool {
    Command::new(tool)
        .arg("--version")
        .output()
        .map(|out| String::from_utf8_lossy(&out.stdout).contains(marker))
        .unwrap_or(false)
}

fn run(cmd: &mut Command) -> Vec<u8> {
    let out = cmd.output().expect("spawn binutils tool");
    assert!(
        out.status.success(),
        "{cmd:?} failed:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    out.stdout
}

/// Assembles each line (one instruction, Intel syntax, no `ptr` prefix needed for registers) with
/// GNU `as --64` and returns the bytes of every line. `None` when GNU binutils are not installed.
pub fn assemble(lines: &[&str]) -> Option<Vec<Vec<u8>>> {
    if !tool_ok("as", "GNU assembler") || !tool_ok("objcopy", "GNU objcopy") {
        return None;
    }
    let dir: PathBuf = std::env::temp_dir().join(format!(
        "arinsal-x64-golden-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).expect("create golden dir");
    let mut src = String::from(".intel_syntax noprefix\n.text\n__golden_start:\n");
    for (i, line) in lines.iter().enumerate() {
        src.push_str(&format!("{line}\n__golden_{i}:\n"));
    }
    let (s, o, bin) = (dir.join("g.s"), dir.join("g.o"), dir.join("g.bin"));
    std::fs::write(&s, src).expect("write golden source");
    run(Command::new("as").arg("--64").arg("-o").arg(&o).arg(&s));
    run(Command::new("objcopy")
        .args(["-O", "binary", "-j", ".text"])
        .arg(&o)
        .arg(&bin));
    let text = std::fs::read(&bin).expect("read golden text");
    let syms = String::from_utf8(run(Command::new("nm").arg(&o))).expect("nm output");
    let mut ends = vec![0usize; lines.len()];
    for sym in syms.lines() {
        let mut parts = sym.split_whitespace();
        let (Some(addr), Some(_), Some(name)) = (parts.next(), parts.next(), parts.next()) else {
            continue;
        };
        if let Some(i) = name
            .strip_prefix("__golden_")
            .and_then(|n| n.parse::<usize>().ok())
        {
            ends[i] = usize::from_str_radix(addr, 16).expect("symbol address");
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
    let mut start = 0;
    Some(
        ends.into_iter()
            .map(|end| {
                let bytes = text[start..end].to_vec();
                start = end;
                bytes
            })
            .collect(),
    )
}

fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Encodes every case and compares with the assembler's bytes; panics listing all mismatches.
/// Without GNU binutils it prints why and checks only that every case encodes.
pub fn check(cases: &[Case]) {
    let texts: Vec<&str> = cases.iter().map(|(text, _)| *text).collect();
    let expected = assemble(&texts);
    if expected.is_none() {
        eprintln!("GNU as/objcopy not found: golden bytes not compared (encodings still checked)");
    }
    let mut failures = Vec::new();
    for (i, (text, encode)) in cases.iter().enumerate() {
        let mut e = Emitter::new();
        match encode(&mut e) {
            Err(err) => failures.push(format!("{text}: encoder error {err:?}")),
            Ok(()) => {
                if let Some(expected) = &expected
                    && e.bytes != expected[i]
                {
                    failures.push(format!(
                        "{text}:\n    as:      {}\n    emitter: {}",
                        hex(&expected[i]),
                        hex(&e.bytes)
                    ));
                }
            }
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {} golden cases differ:\n{}",
        failures.len(),
        cases.len(),
        failures.join("\n")
    );
}
