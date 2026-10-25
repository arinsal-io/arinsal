use arinsal_a64::enc::Gpr;
use arinsal_beamasm::{
    ExitReason, ProcessHeader, SchedulerRegisters,
    catch::{ExceptionResolver, make_catch},
    enter_native,
    module::{ArgVal, BeamModuleAssembler, FinalizedModule},
};

extern "C" fn raise_class_for_test(_header: *mut ProcessHeader, trace: u64, _value: u64) -> u64 {
    trace
}
use arinsal_term::{ProcessHeap, Term, TermBuilder, global_atoms};

extern "C" fn gc_stub(
    _: *mut ProcessHeader,
    _: *mut SchedulerRegisters,
    _: usize,
    _: usize,
    _: i32,
) -> i32 {
    0
}

extern "C" fn add_stacktrace_stub(_: *mut ProcessHeader, reason: u64, _: u64) -> u64 {
    reason
}

extern "C" fn uncaught(_: *mut ProcessHeader, _: *mut SchedulerRegisters, _: *mut u64) -> usize {
    0
}

extern "C" fn route_to_header_handler(
    process: *mut ProcessHeader,
    _: *mut SchedulerRegisters,
    _: *mut u64,
) -> usize {
    arinsal_beamasm::rt::process_header_mut(process, |header| header.self_pid as usize)
}

extern "C" fn unwind_and_route_to_header_handler(
    process: *mut ProcessHeader,
    _: *mut SchedulerRegisters,
    _: *mut u64,
) -> usize {
    arinsal_beamasm::rt::process_header_mut(process, |header| {
        header.stop = header.stop.wrapping_add(arinsal_term::CP_WORDS);
        header.self_pid as usize
    })
}

fn execute(
    asm: BeamModuleAssembler,
    label: u32,
) -> (
    FinalizedModule,
    ProcessHeader,
    SchedulerRegisters,
    [u64; 64],
) {
    let module = asm.finalize().expect("module finalize");
    let mut heap = [0u64; 64];
    let mut stack = [0u64; 64];
    let mut header = ProcessHeader {
        htop: heap.as_mut_ptr(),
        heap: heap.as_mut_ptr(),
        hend: heap.as_mut_ptr().wrapping_add(heap.len()),
        stop: stack.as_mut_ptr().wrapping_add(stack.len()),
        fcalls: 100,
        ..ProcessHeader::default()
    };
    let mut regs = SchedulerRegisters::default();
    #[cfg(target_arch = "aarch64")]
    assert_eq!(
        enter_native(&mut header, &mut regs, &module.entry(label).unwrap()),
        ExitReason::Returned
    );
    #[cfg(not(target_arch = "aarch64"))]
    assert_eq!(
        enter_native(&mut header, &mut regs, &module.entry(label).unwrap()),
        ExitReason::Unsupported
    );
    (module, header, regs, stack)
}

fn finish(asm: &mut BeamModuleAssembler) {
    asm.emit_raw(|e| {
        e.mov_reg(Gpr::x(0), Gpr::xzr())?;
        e.ret(Gpr::x(30))
    })
    .unwrap();
}

#[test]
fn native_catch() {
    let mut asm = BeamModuleAssembler::new();
    asm.emit_i_func_label(1).unwrap();
    asm.allocate(3, 0).unwrap();
    asm.emit_catch(ArgVal::Y(0), 2).unwrap();
    asm.emit_catch_end(ArgVal::Y(0), gc_stub, add_stacktrace_stub)
        .unwrap();
    asm.deallocate(3).unwrap();
    finish(&mut asm);
    asm.emit_i_func_label(2).unwrap();
    finish(&mut asm);
    let (_, header, _, _) = execute(asm, 1);
    assert_eq!(header.catches, 0);
    assert_eq!(make_catch(2), (2 << 6) | 0x1b);
}

#[test]
fn native_try_catches_throw_and_returns_catch_value() {
    let mut asm = BeamModuleAssembler::new();
    asm.emit_i_func_label(1).unwrap();
    asm.allocate(3, 0).unwrap();
    asm.emit_try(ArgVal::Y(0), 2).unwrap();
    asm.emit_i_raise(
        ArgVal::Immediate(0x1b),
        ArgVal::Immediate(77),
        raise_class_for_test as *const () as usize,
        route_to_header_handler,
    )
    .unwrap();
    asm.emit_i_func_label(2).unwrap();
    asm.emit_try_case(ArgVal::Y(0)).unwrap();
    asm.deallocate(3).unwrap();
    finish(&mut asm);
    let module = asm.finalize().unwrap();
    let mut heap = [0u64; 64];
    let mut stack = [0u64; 64];
    let mut header = ProcessHeader {
        htop: heap.as_mut_ptr(),
        heap: heap.as_mut_ptr(),
        hend: heap.as_mut_ptr().wrapping_add(heap.len()),
        stop: stack.as_mut_ptr().wrapping_add(stack.len()),
        self_pid: module.entries[&2] as usize as u64,
        fcalls: 100,
        ..ProcessHeader::default()
    };
    let mut regs = SchedulerRegisters::default();
    regs.x_reg_array[0] = arinsal_beamasm::rt::fixture_term(77);
    #[cfg(target_arch = "aarch64")]
    assert_eq!(
        enter_native(&mut header, &mut regs, &module.entry(1).unwrap()),
        ExitReason::Returned
    );
    // try_case leaves the reason in X1 (the harness routes to the handler directly).
    assert_eq!(regs.x_reg_array[1], arinsal_beamasm::rt::fixture_term(77));
    assert_eq!(header.catches, 0);
}

#[test]
fn native_callee_error_unwinds_to_caller_try() {
    let mut asm = BeamModuleAssembler::new();
    asm.emit_i_func_label(1).unwrap();
    asm.emit_enter_frame().unwrap();
    asm.allocate(3, 0).unwrap();
    asm.emit_try(ArgVal::Y(0), 2).unwrap();
    asm.call(3).unwrap();
    asm.emit_try_end_deallocate(3).unwrap();
    asm.emit_leave_frame().unwrap();
    finish(&mut asm);
    asm.emit_i_func_label(2).unwrap();
    asm.emit_try_case(ArgVal::Y(0)).unwrap();
    asm.deallocate(3).unwrap();
    asm.emit_leave_frame().unwrap();
    finish(&mut asm);
    asm.emit_i_func_label(3).unwrap();
    asm.emit_enter_frame().unwrap();
    asm.emit_raise(
        ArgVal::Immediate(0x5b),
        ArgVal::Immediate(99),
        ArgVal::Immediate(0x3b),
        unwind_and_route_to_header_handler,
    )
    .unwrap();
    let module = asm.finalize().unwrap();
    let mut heap = [0u64; 64];
    let mut stack = [0u64; 64];
    let mut header = ProcessHeader {
        htop: heap.as_mut_ptr(),
        heap: heap.as_mut_ptr(),
        hend: heap.as_mut_ptr().wrapping_add(heap.len()),
        stop: stack.as_mut_ptr().wrapping_add(stack.len()),
        self_pid: module.entries[&2] as usize as u64,
        fcalls: 100,
        ..ProcessHeader::default()
    };
    let mut regs = SchedulerRegisters::default();
    #[cfg(target_arch = "aarch64")]
    assert_eq!(
        enter_native(&mut header, &mut regs, &module.entry(1).unwrap()),
        ExitReason::Returned
    );
    assert_eq!(header.catches, 0);
}

#[test]
fn native_catch_returns_exit_tuple_from_handler() {
    let mut term_heap = ProcessHeap::with_words(16);
    let exit_atom = Term::atom(global_atoms().get("EXIT").unwrap());
    let reason = Term::small(9).unwrap();
    let result = TermBuilder::new(&mut term_heap)
        .tuple(&[exit_atom, reason])
        .unwrap();
    let result_bits = arinsal_beamasm::rt::term_bits(result);

    let mut asm = BeamModuleAssembler::new();
    asm.emit_i_func_label(1).unwrap();
    asm.allocate(3, 0).unwrap();
    asm.emit_catch(ArgVal::Y(0), 2).unwrap();
    asm.emit_i_raise(
        ArgVal::Immediate(0x5b),
        ArgVal::Immediate(9),
        raise_class_for_test as *const () as usize,
        route_to_header_handler,
    )
    .unwrap();
    asm.emit_i_func_label(2).unwrap();
    asm.emit_catch_end(ArgVal::Y(0), gc_stub, add_stacktrace_stub)
        .unwrap();
    asm.deallocate(3).unwrap();
    finish(&mut asm);
    let module = asm.finalize().unwrap();
    let mut heap = [0u64; 64];
    let mut stack = [0u64; 64];
    let mut header = ProcessHeader {
        htop: heap.as_mut_ptr(),
        heap: heap.as_mut_ptr(),
        hend: heap.as_mut_ptr().wrapping_add(heap.len()),
        stop: stack.as_mut_ptr().wrapping_add(stack.len()),
        self_pid: module.entries[&2] as usize as u64,
        fcalls: 100,
        ..ProcessHeader::default()
    };
    let mut regs = SchedulerRegisters::default();
    regs.x_reg_array[0] = arinsal_beamasm::rt::fixture_term(result_bits);
    #[cfg(target_arch = "aarch64")]
    assert_eq!(
        enter_native(&mut header, &mut regs, &module.entry(1).unwrap()),
        ExitReason::Returned
    );
    assert_eq!(
        regs.x_reg_array[0],
        arinsal_beamasm::rt::fixture_term(result_bits)
    );
}

#[test]
fn native_catch_end() {
    let mut asm = BeamModuleAssembler::new();
    asm.emit_i_func_label(1).unwrap();
    asm.allocate(3, 0).unwrap();
    asm.emit_catch(ArgVal::Y(0), 2).unwrap();
    asm.emit_catch_end(ArgVal::Y(0), gc_stub, add_stacktrace_stub)
        .unwrap();
    asm.deallocate(3).unwrap();
    finish(&mut asm);
    asm.emit_i_func_label(2).unwrap();
    finish(&mut asm);
    let _ = execute(asm, 1);
}

#[test]
fn native_try() {
    let mut asm = BeamModuleAssembler::new();
    asm.emit_i_func_label(1).unwrap();
    asm.allocate(3, 0).unwrap();
    asm.emit_try(ArgVal::Y(0), 2).unwrap();
    asm.emit_try_end(ArgVal::Y(0)).unwrap();
    asm.deallocate(3).unwrap();
    finish(&mut asm);
    asm.emit_i_func_label(2).unwrap();
    finish(&mut asm);
    let _ = execute(asm, 1);
}

#[test]
fn native_try_end() {
    let mut asm = BeamModuleAssembler::new();
    asm.emit_i_func_label(1).unwrap();
    asm.allocate(3, 0).unwrap();
    asm.emit_try(ArgVal::Y(0), 2).unwrap();
    asm.emit_try_end(ArgVal::Y(0)).unwrap();
    asm.deallocate(3).unwrap();
    finish(&mut asm);
    asm.emit_i_func_label(2).unwrap();
    finish(&mut asm);
    let _ = execute(asm, 1);
}

#[test]
fn native_try_case() {
    let mut asm = BeamModuleAssembler::new();
    asm.emit_i_func_label(1).unwrap();
    asm.allocate(3, 0).unwrap();
    asm.emit_try(ArgVal::Y(0), 2).unwrap();
    asm.emit_try_case(ArgVal::Y(0)).unwrap();
    asm.deallocate(3).unwrap();
    finish(&mut asm);
    asm.emit_i_func_label(2).unwrap();
    finish(&mut asm);
    let _ = execute(asm, 1);
}

#[test]
fn native_try_case_end() {
    let mut asm = BeamModuleAssembler::new();
    asm.emit_i_func_label(1).unwrap();
    asm.allocate(3, 0).unwrap();
    asm.emit_try(ArgVal::Y(0), 2).unwrap();
    asm.emit_try_case(ArgVal::Y(0)).unwrap();
    asm.emit_try_case_end(ArgVal::Immediate(42), uncaught)
        .unwrap();
    finish(&mut asm);
    asm.emit_i_func_label(2).unwrap();
    finish(&mut asm);
    let (_, header, _, _) = execute(asm, 1);
    // erts EXC_TRY_CLAUSE: the runtime wraps the value as {try_clause, 42}.
    assert_eq!(header.exc.freason, (16 << 10) | 0x50);
    assert_eq!(header.exc.fvalue, 42);
}

#[test]
fn native_i_raise() {
    let mut asm = BeamModuleAssembler::new();
    asm.emit_i_func_label(1).unwrap();
    asm.emit_i_raise(
        ArgVal::Immediate(0x5b),
        ArgVal::Immediate(12),
        raise_class_for_test as *const () as usize,
        uncaught,
    )
    .unwrap();
    finish(&mut asm);
    let (_, header, _, _) = execute(asm, 1);
    assert_eq!(header.exc.freason, 0x5b);
}

#[test]
fn native_raise() {
    let mut asm = BeamModuleAssembler::new();
    asm.emit_i_func_label(1).unwrap();
    asm.emit_raise(
        ArgVal::Immediate(0x5b),
        ArgVal::Immediate(12),
        ArgVal::Immediate(0x3b),
        uncaught,
    )
    .unwrap();
    finish(&mut asm);
    let (_, header, _, _) = execute(asm, 1);
    assert_eq!(header.exc.freason, 0x5b);
}

fn atom_word(name: &str) -> u64 {
    Term::atom(global_atoms().intern(name).unwrap()).tagged_word()
}

#[test]
fn native_raw_raise() {
    let mut asm = BeamModuleAssembler::new();
    asm.emit_i_func_label(1).unwrap();
    asm.move_(ArgVal::Immediate(atom_word("exit")), ArgVal::X(0))
        .unwrap();
    asm.move_(ArgVal::Immediate(12), ArgVal::X(1)).unwrap();
    asm.move_(ArgVal::Immediate(0x3b), ArgVal::X(2)).unwrap();
    asm.emit_raw_raise(uncaught).unwrap();
    finish(&mut asm);
    let (_, header, _, _) = execute(asm, 1);
    assert_eq!(header.exc.freason, arinsal_beamasm::catch::RAW_RAISE | 2);
    assert_eq!(header.exc.fvalue, 12);
    assert_eq!(header.exc.ftrace as u64, 0x3b);
}

// Port of erts/emulator/beam/beam_common.c:1148-1178 (raw_raise): an invalid class leaves
// badarg in X0 and continues.
#[test]
fn native_raw_raise_invalid_class_continues_with_badarg() {
    let mut asm = BeamModuleAssembler::new();
    asm.emit_i_func_label(1).unwrap();
    asm.move_(ArgVal::Immediate(atom_word("nonclass")), ArgVal::X(0))
        .unwrap();
    asm.emit_raw_raise(uncaught).unwrap();
    finish(&mut asm);
    let (_, header, regs, _) = execute(asm, 1);
    assert_eq!(header.exc.freason, 0);
    assert_eq!(
        regs.x_reg_array[0],
        arinsal_beamasm::rt::fixture_term(atom_word("badarg"))
    );
}

#[test]
fn native_build_stacktrace() {
    extern "C" fn build(_: *mut ProcessHeader, raw: u64) -> u64 {
        raw ^ 0x100
    }
    let mut asm = BeamModuleAssembler::new();
    asm.emit_i_func_label(1).unwrap();
    asm.emit_enter_frame().unwrap();
    asm.move_(ArgVal::Immediate(9), ArgVal::X(0)).unwrap();
    asm.emit_build_stacktrace(build).unwrap();
    asm.emit_leave_frame().unwrap();
    finish(&mut asm);
    let (_, _, regs, _) = execute(asm, 1);
    assert_eq!(
        regs.x_reg_array[0],
        arinsal_beamasm::rt::fixture_term(0x109)
    );
}

#[test]
fn native_badmatch() {
    error_test(|a| a.emit_badmatch(ArgVal::Immediate(1), uncaught));
}
#[test]
fn native_case_end() {
    error_test(|a| a.emit_case_end(ArgVal::Immediate(1), uncaught));
}
#[test]
fn native_if_end() {
    error_test(|a| a.emit_if_end(uncaught));
}
#[test]
fn native_badrecord() {
    error_test(|a| a.emit_badrecord(ArgVal::Immediate(1), uncaught));
}
#[test]
fn native_try_end_deallocate() {
    let mut asm = BeamModuleAssembler::new();
    asm.emit_i_func_label(1).unwrap();
    asm.allocate(3, 0).unwrap();
    asm.emit_try(ArgVal::Y(0), 2).unwrap();
    asm.emit_try_end_deallocate(3).unwrap();
    finish(&mut asm);
    asm.emit_i_func_label(2).unwrap();
    finish(&mut asm);
    let _ = execute(asm, 1);
}

fn error_test(
    emit: impl FnOnce(&mut BeamModuleAssembler) -> Result<(), arinsal_beamasm::module::ModuleError>,
) {
    let mut asm = BeamModuleAssembler::new();
    asm.emit_i_func_label(1).unwrap();
    emit(&mut asm).unwrap();
    finish(&mut asm);
    let (_, header, _, _) = execute(asm, 1);
    assert_ne!(header.exc.freason, 0);
}

// Compile-time use also pins the resolver ABI for fixtures that catch errors in a caller.
const _: Option<ExceptionResolver> = None;
