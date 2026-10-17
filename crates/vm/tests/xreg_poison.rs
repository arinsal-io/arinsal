//! `ARINSAL_XREG_POISON=1` fills every X register above the saved arity at schedule-in.
//!
//! erts copies exactly `c_p->arity` registers into the scheduler array (copy_in_registers) and
//! leaves the rest dirty. The validator never lets compiled code read a dead register, so the
//! fixture is patched after `erlc`: `probe/4` tests X3 (live, `[]`) and the patch moves the
//! operand to X7, which the process did not save. With the knob on that register must hold the
//! poison word, not the NIL the scheduler-side file used to leave there.

#![cfg(debug_assertions)]

use arinsal_etf::OwnedTerm;
use arinsal_term::Term;
use arinsal_vm::Vm;
use std::process::Command;

const ASM_SOURCE: &str = include_str!("fixtures/xreg_poison_asm.S");

fn compile() -> Vec<u8> {
    let root = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("xreg_poison");
    std::fs::create_dir_all(&root).unwrap();
    let source = root.join("xreg_poison_asm.S");
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
    std::fs::read(root.join("xreg_poison_asm.beam")).unwrap()
}

/// `is_nil` (52), fail label `{f,3}` (0x35), operand `{x,3}` (0x33) in the compact encoding.
const LIVE_TEST: [u8; 3] = [0x34, 0x35, 0x33];

fn patch_to_dead_register(beam: &mut [u8]) {
    let at: Vec<usize> = beam
        .windows(LIVE_TEST.len())
        .enumerate()
        .filter(|(_, window)| *window == LIVE_TEST)
        .map(|(index, _)| index)
        .collect();
    assert_eq!(at.len(), 1, "is_nil operand pattern must be unique");
    beam[at[0] + 2] = 0x73;
}

fn probe(beam: &[u8]) -> OwnedTerm {
    let mut vm = Vm::new([]);
    vm.load_bytes(beam).unwrap();
    let args = [Term::NIL; 4];
    let result = vm
        .eval_scheduled("xreg_poison_asm", "probe", &args, 1, None)
        .unwrap_or_else(|error| panic!("VM error {error:?}"));
    result.term
}

#[test]
fn dead_x_register_holds_poison_with_the_knob() {
    // SAFETY: the only test in this binary; nothing reads the environment concurrently.
    unsafe { std::env::set_var("ARINSAL_XREG_POISON", "1") };
    let mut beam = compile();
    let live = probe(&beam);
    patch_to_dead_register(&mut beam);
    let dead = probe(&beam);
    assert_eq!(live, OwnedTerm::Atom("stale".into()), "X3 is live and []");
    assert_eq!(
        dead,
        OwnedTerm::Atom("dead".into()),
        "X7 is dead and must hold the poison word, not []"
    );
}
