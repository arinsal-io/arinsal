use arinsal_a64::enc::Gpr;
use arinsal_beamasm::{
    ExitReason, ProcessHeader, SchedulerRegisters, enter_native,
    module::{ArgVal, BeamModuleAssembler},
};

fn finish(
    asm: BeamModuleAssembler,
    entry_label: u32,
) -> (arinsal_beamasm::module::FinalizedModule, u32) {
    let module = asm.finalize().expect("module finalization");
    (module, entry_label)
}

fn run(
    module: &arinsal_beamasm::module::FinalizedModule,
    label: u32,
    stack: &mut [u64],
    fcalls: i32,
    regs: &mut SchedulerRegisters,
) -> (ProcessHeader, ExitReason) {
    let stack_end = stack.as_mut_ptr().wrapping_add(stack.len());
    let mut header = ProcessHeader {
        stop: stack_end,
        fcalls,
        ..ProcessHeader::default()
    };
    let result = enter_native(&mut header, regs, &module.entry(label).unwrap());
    (header, result)
}

#[cfg(target_arch = "aarch64")]
#[test]
fn move_return_local_call_frame_tail_yield_and_far_call() {
    // (a) f(X0) = X0 through a native move and return.
    let mut a = BeamModuleAssembler::new();
    a.emit_i_func_label(1).unwrap();
    a.emit_enter_frame().unwrap();
    a.move_(ArgVal::X(0), ArgVal::X(1)).unwrap();
    a.return_().unwrap();
    let (module_a, entry_a) = finish(a, 1);
    let mut regs = SchedulerRegisters::default();
    regs.x_reg_array[0] = arinsal_beamasm::rt::fixture_term(0x1234);
    let mut stack = [0u64; 128];
    let (_header, result) = run(&module_a, entry_a, &mut stack, 10, &mut regs);
    assert_eq!(result, ExitReason::Returned);
    assert_eq!(
        regs.x_reg_array[1],
        arinsal_beamasm::rt::fixture_term(0x1234)
    );
    drop(module_a);

    // (b) g calls h with a CP on the BEAM stack; h returns through its frame.
    let mut b = BeamModuleAssembler::new();
    b.emit_i_func_label(10).unwrap();
    b.emit_enter_frame().unwrap();
    b.call(11).unwrap();
    b.emit_leave_frame().unwrap();
    b.emit_raw(|e| {
        e.mov_reg(Gpr::x(0), Gpr::xzr())?;
        e.ret(Gpr::x(30))
    })
    .unwrap();
    b.emit_i_func_label(11).unwrap();
    b.emit_enter_frame().unwrap();
    b.allocate(1, 1).unwrap();
    b.move_(ArgVal::X(0), ArgVal::X(1)).unwrap();
    b.deallocate(1).unwrap();
    b.emit_leave_frame().unwrap();
    b.emit_raw(|e| e.ret(Gpr::x(30))).unwrap();
    let (module_b, entry_b) = finish(b, 10);
    regs.x_reg_array[0] = arinsal_beamasm::rt::fixture_term(0x55aa);
    let (header_b, result_b) = run(&module_b, entry_b, &mut stack, 100, &mut regs);
    assert_eq!(result_b, ExitReason::Returned);
    assert_eq!(
        regs.x_reg_array[1],
        arinsal_beamasm::rt::fixture_term(0x55aa)
    );
    let stack_end = stack.as_mut_ptr().wrapping_add(stack.len());
    assert_eq!(header_b.stop, stack_end);
    drop(module_b);

    // (c) Tail recursion consumes one reduction per iteration and resumes at entry.
    let mut c = BeamModuleAssembler::new();
    c.emit_i_func_label(20).unwrap();
    c.emit_enter_frame().unwrap();
    c.emit_raw(|e| e.subs_imm(Gpr::x(25), Gpr::x(25), 1, false))
        .unwrap();
    let done = 21;
    c.branch_if_zero(ArgVal::X(0), done).unwrap();
    c.call_only(20).unwrap();
    c.emit_i_func_label(done).unwrap();
    c.emit_leave_frame().unwrap();
    c.emit_raw(|e| {
        e.mov_reg(Gpr::x(0), Gpr::xzr())?;
        e.ret(Gpr::x(30))
    })
    .unwrap();
    let (module_c, entry_c) = finish(c, 20);
    regs.x_reg_array[0] = arinsal_beamasm::rt::fixture_term(1_000_000);
    let mut left = 1_000_000i32;
    let mut stack_depth = stack.len();
    loop {
        let (h, outcome) = run(&module_c, entry_c, &mut stack, left.min(4096), &mut regs);
        assert_eq!(stack_depth, stack.len(), "tail call changed stack depth");
        match outcome {
            ExitReason::Yield => left = h.fcalls.max(0) + 4096,
            ExitReason::Returned => break,
            other => panic!("unexpected native exit: {other:?}"),
        }
        stack_depth = stack.len();
        // The x-register countdown survives the scheduler boundary.
        if regs.x_reg_array[0] == arinsal_beamasm::rt::fixture_term(0) {
            break;
        }
    }
    assert_eq!(regs.x_reg_array[0], arinsal_beamasm::rt::fixture_term(0));
    drop(module_c);

    // (d) Shuffle all supported source/destination classes across X and Y.
    let mut d = BeamModuleAssembler::new();
    d.emit_i_func_label(30).unwrap();
    d.allocate(2, 0).unwrap();
    d.move_(ArgVal::X(0), ArgVal::Y(0)).unwrap();
    d.move_(ArgVal::Immediate(77), ArgVal::Y(1)).unwrap();
    d.swap(ArgVal::X(0), ArgVal::Y(0)).unwrap();
    d.swap(ArgVal::Y(0), ArgVal::Y(1)).unwrap();
    d.move_(ArgVal::Y(1), ArgVal::X(2)).unwrap();
    d.deallocate(2).unwrap();
    d.emit_raw(|e| {
        e.mov_reg(Gpr::x(0), Gpr::xzr())?;
        e.ret(Gpr::x(30))
    })
    .unwrap();
    let (module_d, entry_d) = finish(d, 30);
    regs.x_reg_array[0] = arinsal_beamasm::rt::fixture_term(99);
    let (_, result_d) = run(&module_d, entry_d, &mut stack, 10, &mut regs);
    assert_eq!(result_d, ExitReason::Returned);
    assert_eq!(regs.x_reg_array[2], arinsal_beamasm::rt::fixture_term(99));
    drop(module_d);

    // (e) A forward local call more than 1 MiB away is fixed up after padding.
    let mut e = BeamModuleAssembler::new();
    e.emit_i_func_label(40).unwrap();
    e.emit_enter_frame().unwrap();
    e.call(41).unwrap();
    e.return_().unwrap();
    for _ in 0..(1 << 18) {
        e.emit_raw(|enc| {
            enc.nop();
            Ok(())
        })
        .unwrap();
    }
    e.emit_i_func_label(41).unwrap();
    e.emit_enter_frame().unwrap();
    e.emit_leave_frame().unwrap();
    e.emit_raw(|enc| enc.ret(Gpr::x(30))).unwrap();
    let (module_e, entry_e) = finish(e, 40);
    let (_, result_e) = run(&module_e, entry_e, &mut stack, 10, &mut regs);
    assert_eq!(result_e, ExitReason::Returned);
    drop(module_e);
}

#[cfg(target_arch = "aarch64")]
#[test]
fn function_entries_are_eight_byte_aligned_behind_a_forty_byte_info_slot() {
    use arinsal_beamasm::module::FUNC_INFO_BYTES;

    let mut asm = BeamModuleAssembler::new();
    for label in [1u32, 2, 3] {
        asm.emit_i_func_label(label).unwrap();
        asm.emit_i_func_info(label, 0xa, 0xb, 1).unwrap();
        asm.emit_i_entry_label(label + 100).unwrap();
        asm.return_().unwrap();
        for _ in 0..label {
            asm.return_().unwrap();
        }
    }
    asm.emit_label(7).unwrap();
    asm.return_().unwrap();
    asm.emit_i_func_label(4).unwrap();
    let module = asm.finalize().unwrap();
    assert_eq!(FUNC_INFO_BYTES, 40);
    for label in [1u32, 2, 3, 4] {
        let info = module.entries[&label] as usize;
        assert_eq!(info % 8, 0, "info slot of {label}");
    }
    let first = module.entries[&1] as usize;
    assert_eq!(
        (first + FUNC_INFO_BYTES) % 8,
        0,
        "entry of the first function"
    );
    assert!(module.entries[&2] as usize - first > FUNC_INFO_BYTES);
}
