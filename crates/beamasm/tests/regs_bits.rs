#![cfg(target_arch = "aarch64")]

use arinsal_a64::enc::Gpr;
use arinsal_beamasm::{
    ExitReason, ProcessHeader, SchedulerRegisters, enter_native,
    float::{BigToFloat, emit_fconv},
    module::{ArgVal, BeamModuleAssembler},
};
use similar_asserts::assert_eq;
use std::cell::RefCell;

/// `erts_garbage_collect_nobump` of these cases: their heaps always have room.
extern "C" fn unreachable_gc() {
    unreachable!("no regs_bits case collects")
}

/// An assembler with the process-wide fragments (`ga`), built once as the VM builds them.
fn new_asm() -> BeamModuleAssembler {
    use arinsal_beamasm::yield_frag::YieldFragments;
    static FRAGMENTS: std::sync::OnceLock<YieldFragments> = std::sync::OnceLock::new();
    let fragments = FRAGMENTS
        .get_or_init(|| YieldFragments::new(unreachable_gc as *const () as usize, 0).unwrap());
    let mut asm = BeamModuleAssembler::new();
    asm.set_yield_fragments(fragments.entries());
    asm
}

thread_local! {
    static SEEN: RefCell<Vec<u64>> = const { RefCell::new(Vec::new()) };
}

extern "C" fn float_hook(_value: u64, resp: *mut f64) -> i32 {
    SEEN.with(|seen| *seen.borrow_mut() = vec![0xfeed]);
    // SAFETY: the fconv fragment passes the address of its temporary result slot.
    unsafe { resp.write(f64::from_bits(0x4009_21fb_5444_2d18)) };
    0
}

fn execute(asm: BeamModuleAssembler, values: &[u64]) -> SchedulerRegisters {
    let module = asm.finalize().unwrap();
    let mut heap = [0_u64; 128];
    let mut stack = [0_u64; 128];
    let mut registers = SchedulerRegisters::default();
    arinsal_beamasm::rt::set_fixture_words(&mut registers.x_reg_array[..values.len()], values);
    let mut header = ProcessHeader {
        htop: heap.as_mut_ptr(),
        heap: heap.as_mut_ptr(),
        hend: heap.as_mut_ptr().wrapping_add(heap.len()),
        stop: stack.as_mut_ptr().wrapping_add(stack.len()),
        fcalls: 100,
        ..ProcessHeader::default()
    };
    assert_eq!(
        enter_native(&mut header, &mut registers, &module.entry(1).unwrap()),
        ExitReason::Returned
    );
    registers
}

fn finish(asm: &mut BeamModuleAssembler) {
    asm.emit_leave_frame().unwrap();
    asm.emit_raw(|e| {
        e.mov_reg(Gpr::x(0), Gpr::xzr())?;
        e.ret(Gpr::x(30))
    })
    .unwrap();
    asm.emit_i_func_label(99).unwrap();
    asm.emit_leave_frame().unwrap();
    asm.emit_raw(|e| e.ret(Gpr::x(30))).unwrap();
}

#[test]
fn float_runtime_preserves_register_backed_values() {
    let mut bignum = [0_u64; 2];
    bignum[0] = (1 << 6) | 0x08;
    bignum[1] = 1;
    let term = bignum.as_mut_ptr() as u64 + 2;
    let mut asm = new_asm();
    asm.emit_i_func_label(1).unwrap();
    asm.emit_enter_frame().unwrap();
    emit_fconv(&mut asm, ArgVal::X(0), 0, float_hook as BigToFloat).unwrap();
    finish(&mut asm);
    let registers = execute(asm, &[term, 0x222, 0x333, 0x444, 0x555, 0x666]);
    SEEN.with(|seen| assert_eq!(&*seen.borrow(), &[0xfeed]));
    assert_eq!(
        arinsal_beamasm::rt::fixture_words(&registers.x_reg_array[1..6]),
        [0x222, 0x333, 0x444, 0x555, 0x666]
    );
}
