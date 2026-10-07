//! Differential test for `i_bs_match_test_heap` under BeamAsm.
//!
//! erts runs the heap test of a fused `bs_match` + `test_heap` after every match command, with
//! the instruction's `Live` (beam_jit_bs.cpp, beam_jit_opt_bsm_segments). `Live` counts the
//! registers live after a successful match, so X registers at or above it may still be live at
//! the fail label: Elixir's `OptionParser.next_with_config/2` lost its config argument when the
//! match context was parked over X1 before `ensure_exactly` failed.

use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::{EncodeOptions, decode, encode};
use arinsal_vm::Vm;
use std::path::PathBuf;
use std::process::Command;

const ERLANG_SOURCE: &str = include_str!("fixtures/jit_bs_match_heap.erl");
const ASM_SOURCE: &str = include_str!("fixtures/jit_bs_match_heap_asm.S");

fn run_both(reference: &RefErl, module: &str, beam: &[u8]) {
    reference.load(module, beam).unwrap();
    let expected = reference.call(module, "run", &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(beam).unwrap();
    let actual = vm.eval_scheduled(module, "run", &[], 2, None).unwrap();
    let canonical = decode(&encode(&actual.term, EncodeOptions::default())).unwrap();
    assert_eq!(
        expected,
        CallResult::Ok(canonical),
        "{module}:run/0 differs from erl"
    );
}

/// Bit-syntax clause families whose exact-size match fuses with the following heap test while
/// the fail path still reads arguments above the post-match live count.
#[test]
fn bs_match_test_heap_families_match_erl() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping jit_bs_match_heap differential test");
        return;
    };
    let beam = reference
        .compile_named("jit_bs_match_heap", ERLANG_SOURCE, &[])
        .unwrap();
    run_both(&reference, "jit_bs_match_heap", &beam);
}

/// Reduced hand-written form of the OptionParser pattern.
#[test]
fn bs_match_test_heap_keeps_registers_live_at_fail_label() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping jit_bs_match_heap_asm differential test");
        return;
    };
    let root = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("jit_bs_match_heap_asm");
    std::fs::create_dir_all(&root).unwrap();
    let source = root.join("jit_bs_match_heap_asm.S");
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
    let beam = std::fs::read(root.join("jit_bs_match_heap_asm.beam")).unwrap();
    run_both(&reference, "jit_bs_match_heap_asm", &beam);
}
