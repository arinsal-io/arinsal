use arinsal_a64::enc::Gpr;
use arinsal_beamasm::{
    ExitReason, ProcessHeader, SchedulerRegisters, enter_native,
    fun::{FunCallTag, FunResolver},
    guard::GuardHelper,
    module::{ArgVal, BeamModuleAssembler, FinalizedModule},
};
use arinsal_term::{ExportEntry, ProcessHeap, TermBuilder, global_atoms};

extern "C" fn resolve_normal(process: *mut ProcessHeader, fun: u64, arity: u32) -> usize {
    let target =
        arinsal_beamasm::rt::process_header_mut(process, |header| header.self_pid as usize);
    resolve(fun, arity, target)
}

extern "C" fn resolve_tail(process: *mut ProcessHeader, fun: u64, arity: u32) -> usize {
    let target =
        arinsal_beamasm::rt::process_header_mut(process, |header| header.self_pid as usize);
    resolve(fun, arity, target)
}

extern "C" fn resolve_export(process: *mut ProcessHeader, fun: u64, arity: u32) -> usize {
    let (expected, target) = arinsal_beamasm::rt::process_header_mut(process, |header| {
        (header.fvalue, header.self_pid as usize)
    });
    if arity == 1 && fun == expected {
        target
    } else {
        0
    }
}

fn resolve(fun: u64, arity: u32, target: usize) -> usize {
    if fun & 7 != 2 {
        return 0;
    }
    if arity != 1 {
        return 0;
    }
    target
}

extern "C" fn guard_helper(_: *mut ProcessHeader, op: u32, _: u64, _: u64) -> u64 {
    u64::from(op == 43)
}

fn target_code(asm: &mut BeamModuleAssembler, label: u32, pop_frame: bool, sum_captures: bool) {
    asm.emit_i_func_label(label).unwrap();
    if pop_frame {
        asm.emit_leave_frame().unwrap();
    }
    if sum_captures {
        asm.emit_raw(|e| {
            e.asr_imm(Gpr::x(10), Gpr::x(25), 4)?;
            e.asr_imm(Gpr::x(11), Gpr::x(26), 4)?;
            e.asr_imm(Gpr::x(12), Gpr::x(27), 4)?;
            e.add_reg(
                Gpr::x(10),
                Gpr::x(10),
                Gpr::x(11),
                arinsal_a64::enc::Shift::Lsl,
                0,
            )?;
            e.add_reg(
                Gpr::x(10),
                Gpr::x(10),
                Gpr::x(12),
                arinsal_a64::enc::Shift::Lsl,
                0,
            )?;
            e.lsl_imm(Gpr::x(25), Gpr::x(10), 4)?;
            e.orr_imm(Gpr::x(25), Gpr::x(25), 15)?;
            e.mov_reg(Gpr::x(0), Gpr::xzr())?;
            e.ret(Gpr::x(30))
        })
        .unwrap();
    } else {
        asm.emit_raw(|e| {
            e.mov_reg(Gpr::x(0), Gpr::xzr())?;
            e.ret(Gpr::x(30))
        })
        .unwrap();
    }
}

fn execute(
    module: &FinalizedModule,
    header: &mut ProcessHeader,
    regs: &mut SchedulerRegisters,
    stack: &mut [u64; 64],
) {
    header.stop = stack.as_mut_ptr().wrapping_add(stack.len());
    header.fcalls = 100;
    assert_eq!(
        enter_native(header, regs, &module.entry(1).unwrap()),
        ExitReason::Returned
    );
}

#[cfg(target_arch = "aarch64")]
#[test]
fn native_i_make_fun3() {
    let mut asm = BeamModuleAssembler::new();
    asm.emit_i_func_label(1).unwrap();
    asm.emit_i_make_fun3(
        ArgVal::X(1),
        0x1234,
        3,
        &[ArgVal::Immediate(79), ArgVal::Immediate(111)],
    )
    .unwrap();
    asm.emit_raw(|e| {
        e.mov_reg(Gpr::x(0), Gpr::xzr())?;
        e.ret(Gpr::x(30))
    })
    .unwrap();
    let module = asm.finalize().unwrap();
    let mut heap = [0u64; 16];
    let mut header = ProcessHeader {
        htop: heap.as_mut_ptr(),
        heap: heap.as_mut_ptr(),
        hend: heap.as_mut_ptr().wrapping_add(heap.len()),
        ..ProcessHeader::default()
    };
    let mut regs = SchedulerRegisters::default();
    let mut stack = [0u64; 64];
    execute(&module, &mut header, &mut regs, &mut stack);
    assert_eq!(regs.x_reg_array[1].tagged_word() & !7, heap.as_ptr() as u64);
    assert_eq!(&heap[..4], &[3 << 8 | 2 << 16 | 0x14, 0x1234, 79, 111]);
}

#[cfg(target_arch = "aarch64")]
#[test]
fn native_i_make_fun3_entry_matches_interpreter_layout() {
    extern "C" fn retain_owner_for_layout_test(_header: *mut ProcessHeader, _identity: u64) -> u64 {
        1
    }

    let entry = std::sync::Arc::new(arinsal_term::FunEntry {
        dispatch_target: Default::default(),
        module: arinsal_term::Atom(1),
        arity: 1,
        index: 0,
        uniq: [0; 16],
        old_uniq: 0,
        old_index: 0,
        pid: arinsal_term::Term::pid(0, 0).unwrap(),
        dispatch: Default::default(),
        dispatch_code: Default::default(),
        dispatch_epoch: Default::default(),
    });
    let entry_ptr = std::sync::Arc::as_ptr(&entry) as u64;
    let mut asm = BeamModuleAssembler::new();
    asm.emit_i_func_label(1).unwrap();
    asm.emit_i_make_fun3_entry(
        ArgVal::X(1),
        entry_ptr as usize,
        1,
        &[ArgVal::Immediate(79), ArgVal::Immediate(111)],
        retain_owner_for_layout_test as *const () as usize,
    )
    .unwrap();
    asm.emit_raw(|e| {
        e.mov_reg(Gpr::x(0), Gpr::xzr())?;
        e.ret(Gpr::x(30))
    })
    .unwrap();
    let module = asm.finalize().unwrap();
    let mut heap = [0u64; 16];
    let mut header = ProcessHeader {
        htop: heap.as_mut_ptr(),
        heap: heap.as_mut_ptr(),
        hend: heap.as_mut_ptr().wrapping_add(heap.len()),
        ..ProcessHeader::default()
    };
    let mut regs = SchedulerRegisters::default();
    let mut stack = [0u64; 64];
    execute(&module, &mut header, &mut regs, &mut stack);
    assert_eq!(regs.x_reg_array[1].tagged_word() & !7, heap.as_ptr() as u64);
    assert_eq!(&heap[..4], &[1 << 8 | 2 << 16 | 0x14, entry_ptr, 79, 111]);
    std::mem::forget(entry);
}

#[cfg(target_arch = "aarch64")]
#[test]
fn native_i_lambda_trampoline() {
    let mut asm = BeamModuleAssembler::new();
    asm.emit_i_func_label(1).unwrap();
    asm.emit_enter_frame().unwrap();
    asm.emit_i_make_fun3(
        ArgVal::X(1),
        0,
        3,
        &[ArgVal::Immediate(79), ArgVal::Immediate(111)],
    )
    .unwrap();
    asm.emit_i_call_fun2(FunCallTag::Lambda(2), 1, ArgVal::X(1), unused_resolver)
        .unwrap();
    asm.emit_leave_frame().unwrap();
    asm.emit_raw(|e| {
        e.mov_reg(Gpr::x(0), Gpr::xzr())?;
        e.ret(Gpr::x(30))
    })
    .unwrap();
    asm.emit_i_lambda_trampoline(2, 3, 3, 2).unwrap();
    target_code(&mut asm, 3, true, true);
    let module = asm.finalize().unwrap();
    let mut heap = [0u64; 16];
    let mut header = ProcessHeader {
        htop: heap.as_mut_ptr(),
        heap: heap.as_mut_ptr(),
        hend: heap.as_mut_ptr().wrapping_add(heap.len()),
        ..ProcessHeader::default()
    };
    let mut regs = SchedulerRegisters::default();
    regs.x_reg_array[0] = arinsal_beamasm::rt::fixture_term(31);
    let mut stack = [0u64; 64];
    execute(&module, &mut header, &mut regs, &mut stack);
    assert_eq!(regs.x_reg_array[0], arinsal_beamasm::rt::fixture_term(191));
}

extern "C" fn unused_resolver(_: *mut ProcessHeader, _: u64, _: u32) -> usize {
    0
}

#[cfg(target_arch = "aarch64")]
#[test]
fn native_i_call_fun() {
    let mut asm = BeamModuleAssembler::new();
    asm.emit_i_func_label(1).unwrap();
    asm.emit_enter_frame().unwrap();
    asm.emit_i_call_fun(1, resolve_normal).unwrap();
    asm.emit_leave_frame().unwrap();
    asm.emit_raw(|e| {
        e.mov_reg(Gpr::x(0), Gpr::xzr())?;
        e.ret(Gpr::x(30))
    })
    .unwrap();
    target_code(&mut asm, 2, true, false);
    let module = asm.finalize().unwrap();
    let mut header = ProcessHeader {
        self_pid: module.entries[&2] as usize as u64,
        ..ProcessHeader::default()
    };
    let mut thing = [0u64; 2];
    let mut dispatch = [0u64; 1];
    let fun = local_fun_words(&mut thing, &mut dispatch, module.entries[&2] as usize, 1);
    let mut regs = SchedulerRegisters::default();
    regs.x_reg_array[0] = arinsal_beamasm::rt::fixture_term(31);
    regs.x_reg_array[1] = arinsal_beamasm::rt::fixture_term(fun);
    let mut stack = [0u64; 64];
    execute(&module, &mut header, &mut regs, &mut stack);
    assert_eq!(regs.x_reg_array[0], arinsal_beamasm::rt::fixture_term(31));
}

#[cfg(target_arch = "aarch64")]
#[test]
fn native_i_call_fun_last() {
    let mut asm = BeamModuleAssembler::new();
    asm.emit_i_func_label(1).unwrap();
    asm.emit_enter_frame().unwrap();
    asm.emit_i_call_fun_last(1, 0, resolve_tail).unwrap();
    target_code(&mut asm, 2, false, false);
    let module = asm.finalize().unwrap();
    let mut header = ProcessHeader {
        self_pid: module.entries[&2] as usize as u64,
        ..ProcessHeader::default()
    };
    let mut thing = [0u64; 2];
    let mut dispatch = [0u64; 1];
    let fun = local_fun_words(&mut thing, &mut dispatch, module.entries[&2] as usize, 1);
    let mut regs = SchedulerRegisters::default();
    regs.x_reg_array[0] = arinsal_beamasm::rt::fixture_term(31);
    regs.x_reg_array[1] = arinsal_beamasm::rt::fixture_term(fun);
    let mut stack = [0u64; 64];
    execute(&module, &mut header, &mut regs, &mut stack);
    assert_eq!(regs.x_reg_array[0], arinsal_beamasm::rt::fixture_term(31));
}

#[cfg(target_arch = "aarch64")]
#[test]
fn native_i_call_fun2() {
    let mut asm = BeamModuleAssembler::new();
    asm.emit_i_func_label(1).unwrap();
    asm.emit_enter_frame().unwrap();
    asm.emit_i_call_fun2(FunCallTag::Dynamic, 1, ArgVal::X(1), resolve_normal)
        .unwrap();
    asm.emit_leave_frame().unwrap();
    asm.emit_raw(|e| {
        e.mov_reg(Gpr::x(0), Gpr::xzr())?;
        e.ret(Gpr::x(30))
    })
    .unwrap();
    target_code(&mut asm, 2, true, false);
    let module = asm.finalize().unwrap();
    let mut header = ProcessHeader {
        self_pid: module.entries[&2] as usize as u64,
        ..ProcessHeader::default()
    };
    let mut thing = [0u64; 2];
    let mut dispatch = [0u64; 1];
    let fun = local_fun_words(&mut thing, &mut dispatch, module.entries[&2] as usize, 1);
    let mut regs = SchedulerRegisters::default();
    regs.x_reg_array[0] = arinsal_beamasm::rt::fixture_term(31);
    regs.x_reg_array[1] = arinsal_beamasm::rt::fixture_term(fun);
    let mut stack = [0u64; 64];
    execute(&module, &mut header, &mut regs, &mut stack);
    assert_eq!(regs.x_reg_array[0], arinsal_beamasm::rt::fixture_term(31));
}

#[cfg(target_arch = "aarch64")]
#[test]
fn native_i_call_fun2_exported_fun_m_f_1() {
    let mut asm = BeamModuleAssembler::new();
    asm.emit_i_func_label(1).unwrap();
    asm.emit_enter_frame().unwrap();
    asm.emit_i_call_fun2(FunCallTag::Dynamic, 1, ArgVal::X(1), resolve_export)
        .unwrap();
    asm.emit_leave_frame().unwrap();
    asm.emit_raw(|e| {
        e.mov_reg(Gpr::x(0), Gpr::xzr())?;
        e.ret(Gpr::x(30))
    })
    .unwrap();
    target_code(&mut asm, 2, true, false);
    let module = asm.finalize().unwrap();

    let mut term_heap = ProcessHeap::with_words(8);
    let mut builder = TermBuilder::new(&mut term_heap);
    let module_atom = global_atoms().intern("m").unwrap();
    let function_atom = global_atoms().intern("f").unwrap();
    let export_term = builder
        .export_fun(std::sync::Arc::new(ExportEntry::new(
            module_atom,
            function_atom,
            1,
        )))
        .unwrap();
    let export_bits = arinsal_beamasm::rt::term_bits(export_term);

    let mut header = ProcessHeader {
        self_pid: module.entries[&2] as usize as u64,
        fvalue: export_bits,
        ..ProcessHeader::default()
    };
    let mut regs = SchedulerRegisters::default();
    regs.x_reg_array[0] = arinsal_beamasm::rt::fixture_term(31);
    regs.x_reg_array[1] = arinsal_beamasm::rt::fixture_term(export_bits);
    let mut stack = [0u64; 64];
    execute(&module, &mut header, &mut regs, &mut stack);
    assert_eq!(regs.x_reg_array[0], arinsal_beamasm::rt::fixture_term(31));
}

#[cfg(target_arch = "aarch64")]
#[test]
fn native_i_call_fun2_last() {
    let mut asm = BeamModuleAssembler::new();
    asm.emit_i_func_label(1).unwrap();
    asm.emit_enter_frame().unwrap();
    asm.emit_i_call_fun2_last(FunCallTag::Dynamic, 1, ArgVal::X(1), 0, resolve_tail)
        .unwrap();
    target_code(&mut asm, 2, false, false);
    let module = asm.finalize().unwrap();
    let mut header = ProcessHeader {
        self_pid: module.entries[&2] as usize as u64,
        ..ProcessHeader::default()
    };
    let mut thing = [0u64; 2];
    let mut dispatch = [0u64; 1];
    let fun = local_fun_words(&mut thing, &mut dispatch, module.entries[&2] as usize, 1);
    let mut regs = SchedulerRegisters::default();
    regs.x_reg_array[0] = arinsal_beamasm::rt::fixture_term(31);
    regs.x_reg_array[1] = arinsal_beamasm::rt::fixture_term(fun);
    let mut stack = [0u64; 64];
    execute(&module, &mut header, &mut regs, &mut stack);
    assert_eq!(regs.x_reg_array[0], arinsal_beamasm::rt::fixture_term(31));
}

#[cfg(target_arch = "aarch64")]
#[test]
fn native_is_function2() {
    let mut asm = BeamModuleAssembler::new();
    asm.emit_i_func_label(1).unwrap();
    arinsal_beamasm::fun::emit_is_function2(
        &mut asm,
        ArgVal::X(0),
        ArgVal::X(1),
        guard_helper as GuardHelper,
    )
    .unwrap();
    asm.emit_raw(|e| {
        e.mov_reg(Gpr::x(0), Gpr::xzr())?;
        e.ret(Gpr::x(30))
    })
    .unwrap();
    let module = asm.finalize().unwrap();
    let mut heap = [0u64; 2];
    heap[0] = 1 << 8 | 0x14;
    let mut header = ProcessHeader::default();
    let mut regs = SchedulerRegisters::default();
    regs.x_reg_array[0] = arinsal_beamasm::rt::fixture_term(heap.as_ptr() as u64 | 2);
    regs.x_reg_array[1] = arinsal_beamasm::rt::fixture_term(31);
    let mut stack = [0u64; 64];
    execute(&module, &mut header, &mut regs, &mut stack);
    assert_eq!(regs.x_reg_array[0], arinsal_beamasm::rt::fixture_term(1));
}

#[cfg(target_arch = "aarch64")]
#[test]
fn native_call_fun_errors_badfun_and_badarity() {
    let mut asm = BeamModuleAssembler::new();
    asm.emit_i_func_label(1).unwrap();
    asm.emit_i_call_fun(1, resolve_badfun).unwrap();
    let module = asm.finalize().unwrap();
    let mut header = ProcessHeader::default();
    let mut regs = SchedulerRegisters::default();
    regs.x_reg_array[1] = arinsal_beamasm::rt::fixture_term(15);
    let mut stack = [0u64; 64];
    execute(&module, &mut header, &mut regs, &mut stack);
    assert_eq!(header.freason, 1, "badfun");

    let mut asm = BeamModuleAssembler::new();
    asm.emit_i_func_label(1).unwrap();
    asm.emit_i_call_fun(2, resolve_badfun).unwrap();
    let module = asm.finalize().unwrap();
    header = ProcessHeader {
        fvalue: 2,
        ..ProcessHeader::default()
    };
    regs = SchedulerRegisters::default();
    let mut thing = [0u64; 2];
    let mut dispatch = [0u64; 1];
    regs.x_reg_array[2] =
        arinsal_beamasm::rt::fixture_term(local_fun_words(&mut thing, &mut dispatch, 0, 1));
    stack = [0u64; 64];
    execute(&module, &mut header, &mut regs, &mut stack);
    assert_eq!(header.freason, 2, "badarity");
}

extern "C" fn resolve_badfun(process: *mut ProcessHeader, fun: u64, arity: u32) -> usize {
    if fun & 7 != 2 {
        arinsal_beamasm::rt::process_header_mut(process, |header| {
            header.freason = 1;
            header.fvalue = fun;
        });
        return 0;
    }
    let badarity = arinsal_beamasm::rt::process_header_mut(process, |header| header.fvalue == 2);
    if arity != 1 || badarity {
        arinsal_beamasm::rt::process_header_mut(process, |header| {
            header.freason = 2;
            header.fvalue = fun;
        });
        return 0;
    }
    0
}

fn local_fun_words(thing: &mut [u64; 2], dispatch: &mut [u64; 1], target: usize, arity: u8) -> u64 {
    dispatch[0] = target as u64;
    thing[0] = (u64::from(arity) << 8) | 0x14;
    thing[1] = dispatch.as_ptr() as u64;
    thing.as_ptr() as u64 | 2
}

#[allow(dead_code)]
fn _resolver_contract(_: FunResolver) {}
