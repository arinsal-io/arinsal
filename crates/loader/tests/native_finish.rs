//! A module loaded for native code only (`load_native`, then `Module::finish_native` with what
//! the emitter found) has the tables of the module loaded with its instructions.

use arinsal_beam::Operand;
use arinsal_loader::NativeFunction;
use arinsal_spec::Opcode;
use std::path::{Path, PathBuf};

fn beams(root: &Path, files: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            beams(&path, files);
        } else if path.extension().is_some_and(|ext| ext == "beam") {
            files.push(path);
        }
    }
}

fn otp_root() -> Option<PathBuf> {
    if let Some(root) = std::env::var_os("ARINSAL_OTP_ROOT") {
        return Some(PathBuf::from(root));
    }
    let output = std::process::Command::new("erl")
        .args([
            "-noshell",
            "-eval",
            "io:format(\"~s\",[code:root_dir()]),halt().",
        ])
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8(output.stdout).ok())
        .flatten()
        .map(PathBuf::from)
}

/// What the emitter reports of each function, taken from the decoded instructions.
fn found(beam: &arinsal_beam::BeamFile) -> Vec<NativeFunction> {
    let mut functions: Vec<NativeFunction> = Vec::new();
    let mut after_info = false;
    for instruction in &beam.code.instructions {
        match instruction.op {
            Opcode::FuncInfo => {
                let (Some(Operand::Atom(name)), Some(Operand::U(arity))) =
                    (instruction.args.get(1), instruction.args.get(2))
                else {
                    panic!("func_info operands");
                };
                functions.push(NativeFunction {
                    atom: arinsal_term::global_atoms()
                        .intern(beam.atom(*name).unwrap())
                        .unwrap(),
                    arity: *arity as u8,
                    entry_label: 0,
                    nif_stub: false,
                });
                after_info = true;
            }
            Opcode::Label if after_info => {
                if let Some(Operand::U(label)) = instruction.args.first() {
                    functions.last_mut().unwrap().entry_label = *label as u32;
                }
                after_info = false;
            }
            Opcode::NifStart => functions.last_mut().unwrap().nif_stub = true,
            _ => {}
        }
    }
    functions
}

#[test]
fn native_only_module_has_the_tables_of_the_full_module() {
    let mut files = Vec::new();
    if let Some(root) = otp_root() {
        beams(&root.join("lib"), &mut files);
    }
    if files.is_empty() {
        eprintln!("installed OTP corpus absent; skipping");
        return;
    }
    for path in &files {
        let bytes = std::fs::read(path).unwrap();
        let beam = arinsal_beam::parse(&bytes).unwrap();
        let full = arinsal_loader::load(&beam).unwrap();
        let mut native = arinsal_loader::load_native(&beam).unwrap();
        assert!(native.awaits_native_functions(), "{}", path.display());
        native.finish_native(&beam, &found(&beam)).unwrap();
        assert!(!native.awaits_native_functions());
        let shown = path.display();
        assert_eq!(native.name, full.name, "{shown}");
        assert_eq!(native.name_atom, full.name_atom, "{shown}");
        let names = |module: &arinsal_loader::Module| {
            module
                .functions
                .iter()
                .map(|(_, name, arity)| (*name, *arity))
                .collect::<Vec<_>>()
        };
        assert_eq!(names(&native), names(&full), "{shown}");
        assert_eq!(native.function_atoms, full.function_atoms, "{shown}");
        let exports = |module: &arinsal_loader::Module| {
            module
                .exports
                .iter()
                .map(|export| (export.module_atom, export.function_atom, export.arity))
                .collect::<Vec<_>>()
        };
        assert_eq!(exports(&native), exports(&full), "{shown}");
        assert_eq!(native.export_atoms, full.export_atoms, "{shown}");
        // `erts_internal` is never loaded for native code only: the interpreter form adds an
        // import of its own to it (the debugger's `notify_breakpoint_hit`).
        if native.name != "erts_internal" {
            assert_eq!(native.imports.len(), full.imports.len(), "{shown}");
            for (a, b) in native.imports.iter().zip(&full.imports) {
                assert_eq!(
                    (a.module, a.function, a.arity),
                    (b.module, b.function, b.arity)
                );
            }
        }
        assert_eq!(native.funs.len(), full.funs.len(), "{shown}");
        assert_eq!(native.nif_stubs, full.nif_stubs, "{shown}");
        assert_eq!(native.record_defs.len(), full.record_defs.len(), "{shown}");
        assert_eq!(native.nif_bodies.len(), full.nif_bodies.len(), "{shown}");
    }
}
