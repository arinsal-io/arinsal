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
    (header, registers)
}

#[cfg(target_arch = "aarch64")]
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

#[cfg(target_arch = "aarch64")]
#[test]
fn writable_runtime_publishes_heap_and_stack_pointers() {
    let mut asm = BeamModuleAssembler::new();
    asm.emit_i_func_label(1).unwrap();
    asm.emit_enter_frame().unwrap();
    asm.emit_bs_init_writable(ArgVal::X(0), writable_hook as BsInitWritableHelper)
        .unwrap();
    finish(&mut asm);
    let (header, regs) = execute(asm, &[0x1234, 2, 3, 4, 5, 6]);
    SEEN.with(|seen| assert_eq!(&*seen.borrow(), &[0x1234]));
    assert_eq!(header.htop, header.heap);
    assert_eq!(regs.x_reg_array[0], arinsal_beamasm::rt::fixture_term(1));
    assert_eq!(
        arinsal_beamasm::rt::fixture_words(&regs.x_reg_array[1..4]),
        [2, 3, 4]
    );
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
    asm.emit_enter_frame().unwrap();
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
    assert_eq!(
        arinsal_beamasm::rt::fixture_words(&regs.x_reg_array[..2]),
        [0x123, 0x2f]
    );
    assert_eq!(
        arinsal_beamasm::rt::fixture_words(&regs.x_reg_array[3..6]),
        [4, 5, 6]
    );
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
    asm.emit_enter_frame().unwrap();
    emit_fconv(&mut asm, ArgVal::X(0), 0, float_hook as BigToFloat).unwrap();
    finish(&mut asm);
    let (_, regs) = execute(asm, &[term, 0x222, 0x333, 0x444, 0x555, 0x666]);
    SEEN.with(|seen| assert_eq!(&*seen.borrow(), &[0xfeed]));
    assert_eq!(
        arinsal_beamasm::rt::fixture_words(&regs.x_reg_array[1..6]),
        [0x222, 0x333, 0x444, 0x555, 0x666]
    );
}

#[cfg(target_arch = "aarch64")]
#[test]
fn match_string_runtime_keeps_the_argument_registers() {
    let mut asm = BeamModuleAssembler::new();
    asm.emit_i_func_label(1).unwrap();
    asm.emit_enter_frame().unwrap();
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
    assert_eq!(
        arinsal_beamasm::rt::fixture_words(&regs.x_reg_array[..6]),
        [0x111, 0x222, 3, 4, 5, 6]
    );
}

#[cfg(target_arch = "aarch64")]
fn small(value: u64) -> u64 {
    (value << 4) | 0xf
}

#[cfg(target_arch = "aarch64")]
fn execute_inline(
    asm: BeamModuleAssembler,
    values: &[u64],
) -> (Vec<u64>, ProcessHeader, SchedulerRegisters) {
    let module = asm.finalize().unwrap();
    let mut mem = vec![0_u64; 64];
    let base = mem.as_mut_ptr();
    let mut registers = SchedulerRegisters::default();
    arinsal_beamasm::rt::set_fixture_words(&mut registers.x_reg_array[..values.len()], values);
    let mut header = ProcessHeader {
        htop: base,
        heap: base,
        hend: base.wrapping_add(mem.len()),
        stop: base.wrapping_add(mem.len()),
        fcalls: 100,
        ..ProcessHeader::default()
    };
    assert_eq!(
        enter_native(&mut header, &mut registers, &module.entry(1).unwrap()),
        ExitReason::Returned
    );
    (mem, header, registers)
}

#[cfg(target_arch = "aarch64")]
#[test]
fn fixed_integer_construction_is_inline() {
    let segments = [
        BsSegment {
            kind: BsSegmentKind::Integer,
            index: 1,
            src: ArgVal::X(0),
            size: ArgVal::Immediate(small(8)),
            size_is_units: false,
            unit: 1,
            flags: 0,
        },
        BsSegment {
            kind: BsSegmentKind::Integer,
            index: 2,
            src: ArgVal::X(1),
            size: ArgVal::Immediate(small(16)),
            size_is_units: false,
            unit: 1,
            flags: 0,
        },
        BsSegment {
            kind: BsSegmentKind::Integer,
            index: 3,
            src: ArgVal::X(2),
            size: ArgVal::Immediate(small(32)),
            size_is_units: false,
            unit: 1,
            flags: 0,
        },
    ];
    let mut asm = BeamModuleAssembler::new();
    asm.emit_i_func_label(1).unwrap();
    asm.emit_enter_frame().unwrap();
    asm.emit_i_bs_create_bin(
        0,
        0,
        3,
        ArgVal::X(0),
        &segments,
        segment_hook as BsCreateBinHelper,
    )
    .unwrap();
    finish(&mut asm);
    let (mem, _, _) = execute_inline(asm, &[small(0x11), small(0x2233), small(0x4455_6677)]);
    SEEN.with(|seen| assert!(seen.borrow().is_empty()));
    assert_eq!(mem[0], 0xa0);
    assert_eq!(mem[1], 56);
    assert_eq!(mem[2] & 0x00ff_ffff_ffff_ffff, 0x0077_6655_4433_2211);
}

#[cfg(target_arch = "aarch64")]
#[test]
fn utf8_construction_is_inline() {
    let segment = BsSegment {
        kind: BsSegmentKind::Utf8,
        index: 1,
        src: ArgVal::X(0),
        size: ArgVal::Immediate(0),
        size_is_units: false,
        unit: 1,
        flags: 0,
    };
    let mut asm = BeamModuleAssembler::new();
    // Callee: the fun body. A real function saves LR (`i_breakpoint_trampoline`).
    // The UTF-8 path `bl`s the shared encoder the way BeamAsm does.
    asm.emit_i_func_label(2).unwrap();
    asm.emit_enter_frame().unwrap();
    asm.emit_i_bs_create_bin(
        0,
        0,
        1,
        ArgVal::X(0),
        &[segment],
        segment_hook as BsCreateBinHelper,
    )
    .unwrap();
    asm.emit_leave_frame().unwrap();
    asm.emit_raw(|e| e.ret(Gpr::x(30))).unwrap();
    // Caller: list-comprehension shape (`get_list` saves the tail in y0, then `call`).
    asm.emit_i_func_label(1).unwrap();
    asm.emit_enter_frame().unwrap();
    asm.allocate(1, 1).unwrap();
    asm.move_(ArgVal::Immediate(0x1111), ArgVal::Y(0)).unwrap();
    asm.call(2).unwrap();
    asm.move_(ArgVal::Y(0), ArgVal::X(1)).unwrap();
    asm.deallocate(1).unwrap();
    finish(&mut asm);
    let (mem, header, regs) = execute_inline(asm, &[small(0x20ac)]);
    SEEN.with(|seen| assert!(seen.borrow().is_empty()));
    assert_eq!(mem[0], 0xa0);
    assert_eq!(mem[1], 24);
    assert_eq!(mem[2], 0x00ac_82e2);
    assert_eq!(mem[3], 0, "construct wrote past the rounded heap bitstring");
    let advanced = (header.htop as usize).wrapping_sub(header.heap as usize);
    assert_eq!(
        advanced, 24,
        "HTOP advance {advanced:#x} is not the 3-word object"
    );
    assert_eq!(
        arinsal_beamasm::rt::fixture_words(&regs.x_reg_array[1..2]),
        [0x1111],
        "caller y0 (list tail) was clobbered"
    );
}

#[cfg(target_arch = "aarch64")]
#[test]
fn non_small_integer_construction_uses_the_helper() {
    let segment = BsSegment {
        kind: BsSegmentKind::Integer,
        index: 1,
        src: ArgVal::X(0),
        size: ArgVal::Immediate(small(8)),
        size_is_units: false,
        unit: 1,
        flags: 0,
    };
    let mut asm = BeamModuleAssembler::new();
    asm.emit_i_func_label(1).unwrap();
    asm.emit_enter_frame().unwrap();
    asm.emit_i_bs_create_bin(
        0,
        0,
        2,
        ArgVal::X(2),
        &[segment],
        segment_hook as BsCreateBinHelper,
    )
    .unwrap();
    finish(&mut asm);
    let (_, regs) = execute(asm, &[0x2, 0x22, 0x33, 4, 5, 6]);
    SEEN.with(|seen| assert_eq!(&*seen.borrow(), &[1, 2, 0]));
    assert_eq!(
        arinsal_beamasm::rt::fixture_words(&regs.x_reg_array[..2]),
        [0x2, 0x22]
    );
}
