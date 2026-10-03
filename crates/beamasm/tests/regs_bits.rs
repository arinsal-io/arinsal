use arinsal_a64::enc::Gpr;
use arinsal_beamasm::{
    ExitReason, ProcessHeader, SchedulerRegisters,
    bs_construct::{BsCreateBinHelper, BsInitWritableHelper, BsSegment, BsSegmentKind},
    bs_match::BsMatchHelper,
    enter_native,
    float::{BigToFloat, emit_fconv},
    module::{ArgVal, BeamModuleAssembler},
};
use std::cell::RefCell;

thread_local! {
    static SEEN: RefCell<Vec<u64>> = const { RefCell::new(Vec::new()) };
}

extern "C" fn match_hook(
    _process: *mut ProcessHeader,
    op: u32,
    ctx: u64,
    size: u64,
    unit: u64,
) -> u64 {
    SEEN.with(|seen| *seen.borrow_mut() = vec![u64::from(op), ctx, size, unit]);
    1
}

extern "C" fn writable_hook(_process: *mut ProcessHeader, value: u64) -> u64 {
    SEEN.with(|seen| *seen.borrow_mut() = vec![value]);
    1
}

extern "C" fn segment_hook(_process: *mut ProcessHeader, count: u64, live: u64, alloc: u64) -> u64 {
    SEEN.with(|seen| *seen.borrow_mut() = vec![count, live, alloc]);
    1
}

extern "C" fn float_hook(_process: *mut ProcessHeader, _value: u64) -> u64 {
    SEEN.with(|seen| *seen.borrow_mut() = vec![0xfeed]);
    0x4009_21fb_5444_2d18
}

#[cfg(target_arch = "aarch64")]
fn execute(asm: BeamModuleAssembler, values: &[u64]) -> (ProcessHeader, SchedulerRegisters) {
    let module = asm.finalize().unwrap();
    let mut heap = [0_u64; 128];
    let mut stack = [0_u64; 128];
    let mut registers = SchedulerRegisters::default();
    registers.x_reg_array[..values.len()].copy_from_slice(values);
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
    (header, registers)
}

#[cfg(target_arch = "aarch64")]
fn finish(asm: &mut BeamModuleAssembler) {
    asm.emit_raw(|e| {
        e.mov_reg(Gpr::x(0), Gpr::xzr())?;
        e.ret(Gpr::x(30))
    })
    .unwrap();
    asm.emit_i_func_label(99).unwrap();
    asm.emit_raw(|e| e.ret(Gpr::x(30))).unwrap();
}

#[cfg(target_arch = "aarch64")]
#[test]
fn match_runtime_preserves_live_x_registers_and_arguments() {
    let mut asm = BeamModuleAssembler::new();
    asm.emit_i_func_label(1).unwrap();
    asm.emit_i_bs_match(ArgVal::X(0), 99, ArgVal::X(1), match_hook as BsMatchHelper)
        .unwrap();
    finish(&mut asm);
    let (_, regs) = execute(asm, &[0x111, 0x222, 0x333, 0x444, 0x555, 0x666]);
    SEEN.with(|seen| assert_eq!(&*seen.borrow(), &[1, 0x111, 0x222, 0]));
    assert_eq!(
        &regs.x_reg_array[..6],
        &[0x111, 0x222, 0x333, 0x444, 0x555, 0x666]
    );
}

#[cfg(target_arch = "aarch64")]
#[test]
fn writable_runtime_publishes_heap_and_stack_pointers() {
    let mut asm = BeamModuleAssembler::new();
    asm.emit_i_func_label(1).unwrap();
    asm.emit_bs_init_writable(ArgVal::X(0), writable_hook as BsInitWritableHelper)
        .unwrap();
    finish(&mut asm);
    let (header, regs) = execute(asm, &[0x1234, 2, 3, 4, 5, 6]);
    SEEN.with(|seen| assert_eq!(&*seen.borrow(), &[0x1234]));
    assert_eq!(header.htop, header.heap);
    assert_eq!(regs.x_reg_array[0], 1);
    assert_eq!(&regs.x_reg_array[1..4], &[2, 3, 4]);
}

#[cfg(target_arch = "aarch64")]
#[test]
fn construction_runtime_keeps_non_destination_x_registers() {
    let segment = BsSegment {
        kind: BsSegmentKind::Integer,
        index: 1,
        src: ArgVal::X(0),
        size: ArgVal::X(1),
        size_is_units: false,
        unit: 1,
        flags: 0,
    };
    let mut asm = BeamModuleAssembler::new();
    asm.emit_i_func_label(1).unwrap();
    asm.emit_i_bs_create_bin(
        0,
        3,
        2,
        ArgVal::X(2),
        &[segment],
        segment_hook as BsCreateBinHelper,
    )
    .unwrap();
    finish(&mut asm);
    let (_, regs) = execute(asm, &[0x123, 0x2f, 0xabc, 4, 5, 6]);
    SEEN.with(|seen| assert_eq!(&*seen.borrow(), &[1, 2, 3]));
    assert_eq!(&regs.x_reg_array[..2], &[0x123, 0x2f]);
    assert_eq!(&regs.x_reg_array[3..6], &[4, 5, 6]);
}

#[cfg(target_arch = "aarch64")]
#[test]
fn float_runtime_preserves_register_backed_values() {
    let mut bignum = [0_u64; 2];
    bignum[0] = (1 << 6) | 0x08;
    bignum[1] = 1;
    let term = bignum.as_mut_ptr() as u64 + 2;
    let mut asm = BeamModuleAssembler::new();
    asm.emit_i_func_label(1).unwrap();
    emit_fconv(&mut asm, ArgVal::X(0), 0, float_hook as BigToFloat).unwrap();
    finish(&mut asm);
    let (_, regs) = execute(asm, &[term, 0x222, 0x333, 0x444, 0x555, 0x666]);
    SEEN.with(|seen| assert_eq!(&*seen.borrow(), &[0xfeed]));
    assert_eq!(
        &regs.x_reg_array[1..6],
        &[0x222, 0x333, 0x444, 0x555, 0x666]
    );
}

#[cfg(target_arch = "aarch64")]
#[test]
fn match_string_runtime_keeps_the_argument_registers() {
    let mut asm = BeamModuleAssembler::new();
    asm.emit_i_func_label(1).unwrap();
    asm.emit_i_bs_match_string(
        ArgVal::X(0),
        99,
        ArgVal::Immediate((8 << 4) | 0xf),
        ArgVal::X(1),
        match_hook as BsMatchHelper,
    )
    .unwrap();
    finish(&mut asm);
    let (_, regs) = execute(asm, &[0x111, 0x222, 3, 4, 5, 6]);
    SEEN.with(|seen| assert_eq!(&*seen.borrow(), &[9, 0x111, 0x222, 8]));
    assert_eq!(&regs.x_reg_array[..6], &[0x111, 0x222, 3, 4, 5, 6]);
}
