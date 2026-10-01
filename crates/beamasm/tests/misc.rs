use arinsal_a64::enc::Gpr;
use arinsal_beamasm::{
    ExitReason, ProcessHeader, SchedulerRegisters,
    dispatch::DispatchFragments,
    enter_native,
    misc::{self, ApplyKind, ApplyRuntime},
    module::{ArgVal, BeamModuleAssembler, FinalizedModule},
};

extern "C" fn light_bif_hook(_: *mut ProcessHeader, identity: u64) -> u64 {
    identity
}

extern "C" fn apply_hook(process: *mut ProcessHeader, arity: u32) -> usize {
    arinsal_beamasm::rt::process_header_mut(process, |header| header.fvalue = u64::from(arity));
    arinsal_beamasm::rt::process_header_mut(process, |header| header.self_pid as usize)
}

fn runtime() -> ApplyRuntime {
    ApplyRuntime {
        resolver: apply_hook,
        apply2_fragment: 0,
        apply3_fragment: 0,
    }
}

fn target(asm: &mut BeamModuleAssembler) {
    asm.emit_i_func_label(2).unwrap();
    asm.emit_raw(|e| {
        e.mov_const(Gpr::x(25), 0xabc)?;
        e.mov_reg(Gpr::x(0), Gpr::xzr())?;
        e.ret(Gpr::x(30))
    })
    .unwrap();
}

fn execute(
    module: &FinalizedModule,
    mut header: ProcessHeader,
    values: [u64; 3],
) -> (ProcessHeader, SchedulerRegisters, ExitReason) {
    let mut regs = SchedulerRegisters::default();
    regs.x_reg_array[..3].copy_from_slice(&values);
    let mut stack = [0_u64; 64];
    header.stop = stack.as_mut_ptr().wrapping_add(stack.len());
    header.fcalls = 100;
    let result = enter_native(&mut header, &mut regs, &module.entry(1).unwrap());
    (header, regs, result)
}

fn tagged(value: u64) -> u64 {
    (value << 4) | 15
}

#[cfg(target_arch = "aarch64")]
#[test]
fn native_send() {
    const IDENTITY: usize = 0x1234;
    let fragments = DispatchFragments::new(0, light_bif_hook as *const () as usize, 0).unwrap();
    let mut asm = BeamModuleAssembler::new();
    asm.emit_i_func_label(1).unwrap();
    asm.emit_enter_frame().unwrap();
    asm.emit_send(fragments.send(), IDENTITY).unwrap();
    asm.emit_leave_frame().unwrap();
    asm.emit_raw(|e| {
        e.mov_reg(Gpr::x(0), Gpr::xzr())?;
        e.ret(Gpr::x(30))
    })
    .unwrap();
    let module = asm.finalize().unwrap();
    let (_, _, outcome) = execute(&module, ProcessHeader::default(), [0x123, 0x456, 0]);
    assert_eq!(outcome, ExitReason::Returned);
}

#[cfg(target_arch = "aarch64")]
#[test]
fn native_apply() {
    let mut asm = BeamModuleAssembler::new();
    asm.emit_i_func_label(1).unwrap();
    asm.emit_enter_frame().unwrap();
    misc::emit_apply_call(&mut asm, ApplyKind::Fixed(1), runtime()).unwrap();
    asm.emit_leave_frame().unwrap();
    asm.emit_raw(|e| e.ret(Gpr::x(30))).unwrap();
    target(&mut asm);
    let module = asm.finalize().unwrap();
    let header = ProcessHeader {
        self_pid: module.entries[&2] as usize as u64,
        ..ProcessHeader::default()
    };
    let (header, regs, outcome) = execute(&module, header, [0x44, 1, 0]);
    assert_eq!(outcome, ExitReason::Returned);
    assert_eq!(regs.x_reg_array[0], 0xabc);
    assert_eq!(header.fvalue, 1);
}

#[cfg(target_arch = "aarch64")]
#[test]
fn native_apply_last() {
    let mut asm = BeamModuleAssembler::new();
    asm.emit_i_func_label(1).unwrap();
    asm.emit_enter_frame().unwrap();
    asm.allocate(2, 0).unwrap();
    misc::emit_apply_tail(&mut asm, ApplyKind::Fixed(1), runtime(), 2).unwrap();
    target(&mut asm);
    let module = asm.finalize().unwrap();
    let header = ProcessHeader {
        self_pid: module.entries[&2] as usize as u64,
        ..ProcessHeader::default()
    };
    let (_, regs, outcome) = execute(&module, header, [0x55, 1, 0]);
    assert_eq!(outcome, ExitReason::Returned);
    assert_eq!(regs.x_reg_array[0], 0xabc);
}

#[cfg(target_arch = "aarch64")]
#[test]
fn native_bs_set_position() {
    let mut asm = BeamModuleAssembler::new();
    asm.emit_i_func_label(1).unwrap();
    asm.emit_bs_set_position(ArgVal::X(0), ArgVal::X(1))
        .unwrap();
    asm.emit_raw(|e| {
        e.mov_reg(Gpr::x(0), Gpr::xzr())?;
        e.ret(Gpr::x(30))
    })
    .unwrap();
    let module = asm.finalize().unwrap();
    let mut context = [0_u64; 4];
    context[2] = 99;
    let ctx = context.as_mut_ptr() as u64 | 2;
    let (_, _, outcome) = execute(&module, ProcessHeader::default(), [ctx, tagged(7), 0]);
    assert_eq!(outcome, ExitReason::Returned);
    assert_eq!(context[2], 7);
}
