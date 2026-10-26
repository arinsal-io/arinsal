//! The code summary (one pass over the operand bytes) equals what the decoded instructions
//! give: functions with their entry labels, the registers, the `-on_load` function.

use arinsal_beam::{Operand, parse, read};
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

fn scan(operand: &Operand, x: &mut usize, fr: &mut usize) {
    match operand {
        Operand::X(index) => *x = (*x).max(*index as usize + 1),
        Operand::FR(index) => *fr = (*fr).max(*index as usize + 1),
        Operand::List(items) => items.iter().for_each(|item| scan(item, x, fr)),
        Operand::TypedReg { reg, .. } => scan(reg, x, fr),
        _ => {}
    }
}

#[test]
fn summary_equals_the_decoded_instructions() {
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
        // The old derivations, from the decoded instructions.
        let mut x = 2;
        let mut fr = 1;
        let mut functions: Vec<(u32, u32, u32, bool)> = Vec::new();
        let mut on_load = None;
        let mut after_info = false;
        for instruction in &decoded.code.instructions {
            for operand in &instruction.args {
                scan(operand, &mut x, &mut fr);
            }
            let arity = match instruction.op {
                Opcode::FuncInfo => instruction.args.get(2),
                Opcode::Call
                | Opcode::CallLast
                | Opcode::CallOnly
                | Opcode::CallExt
                | Opcode::CallExtLast
                | Opcode::CallExtOnly => instruction.args.first(),
                Opcode::CallFun2 => instruction.args.get(1),
                _ => None,
            };
            if let Some(Operand::U(count)) = arity {
                x = x.max(*count as usize + 1);
            }
            match instruction.op {
                Opcode::FuncInfo => {
                    let (Some(Operand::Atom(name)), Some(Operand::U(arity))) =
                        (instruction.args.get(1), instruction.args.get(2))
                    else {
                        panic!("{}: func_info operands", path.display());
                    };
                    functions.push((*name, *arity as u32, 0, false));
                    after_info = true;
                }
                Opcode::Label if after_info => {
                    if let Some(Operand::U(label)) = instruction.args.first() {
                        functions.last_mut().unwrap().2 = *label as u32;
                    }
                    after_info = false;
                }
                Opcode::NifStart => functions.last_mut().unwrap().3 = true,
                Opcode::OnLoad if on_load.is_none() => on_load = functions.len().checked_sub(1),
                _ => {}
            }
        }
        let summary = &read.summary;
        assert_eq!(summary.x_registers, x.min(1024), "{}", path.display());
        assert_eq!(summary.float_registers, fr.min(1024), "{}", path.display());
        assert_eq!(summary.on_load, on_load, "{}", path.display());
        assert_eq!(summary.instructions, decoded.code.instructions.len());
        let got: Vec<_> = summary
            .functions
            .iter()
            .map(|f| (f.function_atom, f.arity, f.entry_label, f.nif_stub))
            .collect();
        assert_eq!(got, functions, "{}", path.display());
    }
}
