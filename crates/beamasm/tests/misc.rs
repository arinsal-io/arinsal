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
    arinsal_beamasm::rt::process_header_mut(process, |header| header.exc.fvalue = u64::from(arity));
    arinsal_beamasm::rt::process_header_mut(process, |header| header.self_pid as usize)
}

extern "C" fn apply3_hook(_: *mut ProcessHeader) -> usize {
    0
}

extern "C" fn fun_hook(_: *mut ProcessHeader, _: u64, _: u32) -> usize {
    0
}

fn runtime() -> ApplyRuntime {
    ApplyRuntime {
        resolver: apply_hook,
        apply3_resolver: apply3_hook,
        apply_fun_shared: 0,
        fun_resolver: fun_hook,
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
    arinsal_beamasm::rt::set_fixture_words(&mut regs.x_reg_array[..3], &values);
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
    let fragments = DispatchFragments::new(0, light_bif_hook as *const () as usize, 0, 0).unwrap();
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
    assert_eq!(
        regs.x_reg_array[0],
        arinsal_beamasm::rt::fixture_term(0xabc)
    );
    assert_eq!(header.exc.fvalue, 1);
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
    assert_eq!(
        regs.x_reg_array[0],
        arinsal_beamasm::rt::fixture_term(0xabc)
    );
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

extern "C" fn apply_fun_hook(process: *mut ProcessHeader, _fun: u64, arity: u32) -> usize {
    arinsal_beamasm::rt::process_header_mut(process, |header| header.exc.fvalue = u64::from(arity));
    arinsal_beamasm::rt::process_header_mut(process, |header| header.self_pid as usize)
}

fn apply_fun_module(fragments: &DispatchFragments) -> FinalizedModule {
    let runtime = ApplyRuntime {
        apply_fun_shared: fragments.apply_fun_shared(),
        fun_resolver: apply_fun_hook,
        apply2_fragment: fragments.apply2_unported(),
        ..runtime()
    };
    let mut asm = BeamModuleAssembler::new();
    asm.emit_i_func_label(1).unwrap();
    asm.emit_enter_frame().unwrap();
    misc::emit_apply_call(&mut asm, ApplyKind::Apply2, runtime).unwrap();
    asm.emit_leave_frame().unwrap();
    asm.emit_raw(|e| {
        e.mov_reg(Gpr::x(0), Gpr::xzr())?;
        e.ret(Gpr::x(30))
    })
    .unwrap();
    // The applied function returns its arguments untouched.
    asm.emit_i_func_label(2).unwrap();
    asm.emit_raw(|e| {
        e.mov_reg(Gpr::x(0), Gpr::xzr())?;
        e.ret(Gpr::x(30))
    })
    .unwrap();
    asm.finalize().unwrap()
}

// `apply/2` unpacks its argument list into X0.. and calls the fun with that arity.
#[cfg(target_arch = "aarch64")]
#[test]
fn native_apply_fun_unpacks_arguments() {
    let fragments = DispatchFragments::new(0, light_bif_hook as *const () as usize, 0, 0).unwrap();
    let module = apply_fun_module(&fragments);
    let header = ProcessHeader {
        self_pid: module.entries[&2] as usize as u64,
        ..ProcessHeader::default()
    };
    // [7, 8, 9] as three cons cells.
    let mut cells = [0_u64; 6];
    let base = cells.as_mut_ptr() as u64;
    cells[0] = tagged(7);
    cells[1] = (base + 16) | 1;
    cells[2] = tagged(8);
    cells[3] = (base + 32) | 1;
    cells[4] = tagged(9);
    cells[5] = 0x3b;
    // Native code reads the cells through `base`.
    std::hint::black_box(&cells);
    let (header, regs, outcome) = execute(&module, header, [tagged(1), base | 1, 0]);
    assert_eq!(outcome, ExitReason::Returned);
    assert_eq!(header.exc.fvalue, 3);
    for (index, value) in [7, 8, 9].into_iter().enumerate() {
        assert_eq!(
            regs.x_reg_array[index],
            arinsal_beamasm::rt::fixture_term(tagged(value))
        );
    }
}

// An improper argument list is applied by the interpreter, which raises, with X0/X1 intact.
#[cfg(target_arch = "aarch64")]
#[test]
fn native_apply_fun_improper_list_goes_to_interpreter() {
    let fragments = DispatchFragments::new(0, light_bif_hook as *const () as usize, 0, 0).unwrap();
    let module = apply_fun_module(&fragments);
    let cells = [tagged(7), tagged(8)];
    let list = cells.as_ptr() as u64 | 1;
    let (_, regs, outcome) = execute(&module, ProcessHeader::default(), [tagged(1), list, 0]);
    assert!(matches!(
        outcome,
        ExitReason::CallUnported {
            target_pc: arinsal_beamasm::dispatch::APPLY2_UNPORTED,
            ..
        }
    ));
    assert_eq!(
        regs.x_reg_array[0],
        arinsal_beamasm::rt::fixture_term(tagged(1))
    );
    assert_eq!(regs.x_reg_array[1], arinsal_beamasm::rt::fixture_term(list));
    assert_eq!(cells, [tagged(7), tagged(8)]);
}
