//! Differential test for X registers above the BeamAsm register cache (X6+).
//!
//! erts BeamAsm addresses every X register through `getXRef`, so no instruction falls back to
//! the interpreter because of its register index. The fixtures keep live values in X6..X19
//! across most op families (arithmetic, guards, comparisons, construction, matching, maps,
//! bit syntax, floats, BIFs, funs, records, errors, try/catch, receive) and compare the result
//! with the reference `erl`.

use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::{EncodeOptions, OwnedTerm, decode, encode};
use arinsal_vm::Vm;
use std::path::PathBuf;
use std::process::Command;

const ERLANG_SOURCE: &str = include_str!("../../beamjit/tests/fixtures/jit_xmem.erl");
const ASM_SOURCE: &str = include_str!("../../beamjit/tests/fixtures/jit_xmem_asm.S");

fn run_both(reference: &RefErl, module: &str, beam: &[u8]) {
    reference.load(module, beam).unwrap();
    let expected = reference.call(module, "run", &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(beam).unwrap();
    let actual = vm.eval_scheduled(module, "run", &[], 2, None).unwrap();
    let canonical = decode(&encode(&actual.term, EncodeOptions::default())).unwrap();
    // Report the first differing case rather than the whole result list.
    if let (
        CallResult::Ok(OwnedTerm::List { elems: want, .. }),
        OwnedTerm::List { elems: got, .. },
    ) = (&expected, &canonical)
    {
        for (want, got) in want.iter().zip(got) {
            assert_eq!(want, got, "{module}:run/0 case differs from erl");
        }
    }
    assert_eq!(
        expected,
        CallResult::Ok(canonical),
        "{module}:run/0 differs from erl"
    );
}

#[test]
fn extended_x_registers_match_erl() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping jit_xmem differential test");
        return;
    };
    let beam = reference
        .compile_named("jit_xmem", ERLANG_SOURCE, &[])
        .unwrap();
    run_both(&reference, "jit_xmem", &beam);
}

/// Hand-written BEAM assembly for instructions the compiler never emits with X6+ operands
/// (receive markers, `raise`, `swap`, paired moves, `move_deallocate_return`, `call_fun2`).
#[test]
fn extended_x_registers_in_assembly_match_erl() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping jit_xmem_asm differential test");
        return;
    };
    let root = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("jit_xmem_asm");
    std::fs::create_dir_all(&root).unwrap();
    let source = root.join("jit_xmem_asm.S");
    std::fs::write(&source, ASM_SOURCE).unwrap();
    let output = Command::new("erlc")
        .arg("-o")
        .arg(&root)
        .arg(&source)
        .output()
        .expect("erlc must be on PATH");
    assert!(
        output.status.success(),
        "erlc failed: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let beam = std::fs::read(root.join("jit_xmem_asm.beam")).unwrap();
    run_both(&reference, "jit_xmem_asm", &beam);
}
