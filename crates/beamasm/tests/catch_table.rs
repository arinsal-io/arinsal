use arinsal_a64::enc::Gpr;
use arinsal_beamasm::{
    ExitReason, ProcessHeader, SchedulerRegisters,
    catch::make_catch,
    enter_native,
    module::{ArgVal, BeamModuleAssembler, FinalizedModule},
};
use arinsal_term::{Term, global_atoms};

fn atom(name: &str) -> u64 {
    Term::atom(global_atoms().get(name).unwrap()).tagged_word()
}

extern "C" fn build_trace(_: *mut ProcessHeader, _: u64, _: u64) -> u64 {
    Term::NIL.tagged_word()
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
    let module = asm.finalize().unwrap();
    let mut heap = [0u64; 64];
    let mut stack = [0u64; 64];
    let mut header = ProcessHeader {
        htop: heap.as_mut_ptr(),
        heap: heap.as_mut_ptr(),
        hend: heap.as_mut_ptr().wrapping_add(64),
        stop: stack.as_mut_ptr().wrapping_add(64),
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
    (module, header, regs, heap)
}

fn finish(asm: &mut BeamModuleAssembler) {
    asm.emit_raw(|e| {
        e.mov_reg(Gpr::x(0), Gpr::xzr())?;
        e.ret(Gpr::x(30))
    })
    .unwrap();
}

fn catch_module(
    class: u64,
    reason: u64,
) -> (
    FinalizedModule,
    ProcessHeader,
    SchedulerRegisters,
    [u64; 64],
) {
    let mut asm = BeamModuleAssembler::new();
    asm.emit_i_func_label(1).unwrap();
    asm.allocate(4, 0).unwrap();
    asm.emit_native_catch(ArgVal::Y(0), 2).unwrap();
    asm.emit_native_raise(
        ArgVal::Immediate(class),
        ArgVal::Immediate(reason),
        ArgVal::Immediate(0x3b),
    )
    .unwrap();
    asm.emit_i_func_label(2).unwrap();
    if class == atom("error") {
        asm.emit_catch_end_with_stacktrace(ArgVal::Y(0), build_trace)
            .unwrap();
    } else {
        asm.emit_catch_end(ArgVal::Y(0)).unwrap();
    }
    asm.deallocate(4).unwrap();
    finish(&mut asm);
    execute(asm, 1)
}

#[test]
fn native_catch_throw() {
    let (module, _, regs, _) = catch_module(atom("throw"), 77);
    assert_eq!(regs.x_reg_array[0], 77);
    assert_eq!(module.catch_table.len(), 1);
}

#[test]
fn native_catch_error_exit_tuple() {
    let (module, header, regs, _) = catch_module(atom("error"), atom("badarith"));
    assert_eq!(regs.x_reg_array[0] & 3, 2);
    assert_eq!(header.htop as usize - header.heap as usize, 48);
    assert_eq!(module.catch_table.len(), 1);
}

#[test]
fn native_catch_exit() {
    let (_, header, regs, _) = catch_module(atom("exit"), 9);
    assert_eq!(regs.x_reg_array[0] & 3, 2);
    assert_eq!(header.htop as usize - header.heap as usize, 24);
}

#[test]
fn native_nested_callee_unwind() {
    let mut asm = BeamModuleAssembler::new();
    asm.emit_i_func_label(1).unwrap();
    asm.emit_enter_frame().unwrap();
    asm.allocate(4, 0).unwrap();
    asm.emit_native_catch(ArgVal::Y(0), 2).unwrap();
    asm.call(3).unwrap();
    asm.emit_catch_end(ArgVal::Y(0)).unwrap();
    asm.deallocate(4).unwrap();
    asm.emit_leave_frame().unwrap();
    finish(&mut asm);
    asm.emit_i_func_label(2).unwrap();
    asm.emit_catch_end(ArgVal::Y(0)).unwrap();
    asm.deallocate(4).unwrap();
    asm.emit_leave_frame().unwrap();
    finish(&mut asm);
    asm.emit_i_func_label(3).unwrap();
    asm.emit_enter_frame().unwrap();
    asm.emit_enter_frame().unwrap();
    asm.emit_native_raise(
        ArgVal::Immediate(atom("throw")),
        ArgVal::Immediate(123),
        ArgVal::Immediate(0x3b),
    )
    .unwrap();
    let (module, header, regs, _) = execute(asm, 1);
    assert_eq!(regs.x_reg_array[0], 123);
    assert_eq!(module.catch_table.len(), 1);
    assert!(header.catches.is_null());
}

#[test]
fn native_two_modules_have_separate_catch_tables() {
    let (first, _, _, _) = catch_module(atom("throw"), 3);
    let (second, _, _, _) = catch_module(atom("throw"), 4);
    assert_eq!(first.catch_table.len(), 1);
    assert_eq!(second.catch_table.len(), 1);
    assert_ne!(first.catch_table[0], second.catch_table[0]);
}

#[test]
fn native_catch_numbers_are_module_local() {
    let mut asm = BeamModuleAssembler::new();
    asm.emit_i_func_label(1).unwrap();
    asm.allocate(8, 0).unwrap();
    asm.emit_native_catch(ArgVal::Y(0), 2).unwrap();
    asm.emit_native_catch(ArgVal::Y(1), 3).unwrap();
    finish(&mut asm);
    asm.emit_i_func_label(2).unwrap();
    finish(&mut asm);
    asm.emit_i_func_label(3).unwrap();
    finish(&mut asm);
    let module = asm.finalize().unwrap();
    assert_eq!(module.catch_table.len(), 2);
    assert_eq!(make_catch(0), 0x1b);
    assert_eq!(make_catch(1), 0x5b);
}
