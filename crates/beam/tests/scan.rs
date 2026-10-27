//! The skim over the operand bytes agrees with the decoded instructions on which functions are
//! NIF stubs and on `-on_load`, and the decoded instructions give the register needs.

use arinsal_beam::{parse, read, scan};
use arinsal_spec::Opcode;
use std::{
    fs,
    path::{Path, PathBuf},
};

mod support;

fn files(path: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(path) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            files(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "beam") {
            out.push(path);
        }
    }
}

#[test]
fn scan_equals_the_decoded_instructions() {
    let mut paths = Vec::new();
    if let Some(otp) = support::otp_root() {
        files(&otp.join("lib"), &mut paths);
    }
    if paths.is_empty() {
        eprintln!("installed OTP corpus absent; skipping");
        return;
    }
    for path in &paths {
        let bytes = fs::read(path).unwrap();
        let Ok(decoded) = parse(&bytes) else { continue };
        let read = read(&bytes).unwrap();
        assert!(read.code.instructions.is_empty());
        assert_eq!(read.code.bytes, decoded.code.bytes, "{}", path.display());
        let mut stubs: Vec<bool> = Vec::new();
        let mut on_load = None;
        for instruction in &decoded.code.instructions {
            match instruction.op {
                Opcode::FuncInfo => {
                    stubs.push(false);
                }
                Opcode::NifStart => *stubs.last_mut().unwrap() = true,
                Opcode::OnLoad => on_load = Some(()),
                _ => {}
            }
        }
        let found = scan(&read.code.bytes, read.code.max_opcode).unwrap();
        assert_eq!(found.nif_stubs, stubs, "{}", path.display());
        assert_eq!(found.on_load, on_load.is_some(), "{}", path.display());
        assert_eq!(
            decoded.code.on_load.is_some(),
            found.on_load,
            "{}",
            path.display()
        );
        assert!((2..=1024).contains(&decoded.code.x_registers));
        assert!((1..=1024).contains(&decoded.code.float_registers));
    }
}
