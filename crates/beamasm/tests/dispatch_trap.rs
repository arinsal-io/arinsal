use std::sync::{
    Mutex,
    atomic::{AtomicUsize, Ordering},
};

use arinsal_a64::{buf::CodeBuffer, enc::Gpr, exec::CodeMemory};
use arinsal_beamasm::{
    ExitReason, ProcessHeader, SchedulerRegisters, dispatch::DispatchFragments, enter_native,
    module::BeamModuleAssembler,
};

const TRAP_REASON: u64 = 1 << 10;
static TARGET: AtomicUsize = AtomicUsize::new(0);
static TEST_LOCK: Mutex<()> = Mutex::new(());

extern "C" fn trap_bif(header: *mut ProcessHeader, _: u64) -> u64 {
    arinsal_beamasm::rt::process_header_mut(header, |header| {
        header.exc.freason = TRAP_REASON;
        header.i = TARGET.load(Ordering::Acquire) as *const u8 as *const _;
        header.arity = 2;
    });
    0 // THE_NON_VALUE in OTP's non-debug build.
}

extern "C" fn error_bif(header: *mut ProcessHeader, _: u64) -> u64 {
    arinsal_beamasm::rt::process_header_mut(header, |header| {
        header.exc.freason = 0x55;
        header.exc.fvalue = 0xfeed;
    });
    0 // THE_NON_VALUE in OTP's non-debug build.
}

extern "C" fn normal_bif(_: *mut ProcessHeader, _: u64) -> u64 {
    1
}

#[cfg(target_arch = "aarch64")]
fn target_code() -> CodeMemory {
    let mut code = CodeBuffer::new();
    code.emit(|encoder| {
        encoder.str_uoff(Gpr::x(25), Gpr::x(21), 48)?;
        encoder.str_uoff(Gpr::x(26), Gpr::x(21), 56)?;
        encoder.ret(Gpr::x(30))
    })
    .unwrap();
    let (words, _) = code.finish_with_labels().unwrap();
    let bytes = words
        .iter()
        .flat_map(|word| word.to_le_bytes())
        .collect::<Vec<_>>();
    let mut memory = CodeMemory::new(bytes.len()).unwrap();
    let offset = memory.alloc(bytes.len()).unwrap();
    memory.write_bytes(offset, &bytes).unwrap();
    memory.flush_all().unwrap();
    memory
}

#[cfg(target_arch = "aarch64")]
fn run(
    helper: usize,
    target: usize,
) -> (
    ExitReason,
    ProcessHeader,
    SchedulerRegisters,
    Box<[u64; 64]>,
) {
    TARGET.store(target, Ordering::Release);
    let fragments = DispatchFragments::new(0, helper, 0, 0).unwrap();
    let export = Box::leak(Box::new(arinsal_beamasm::bif::ExportEntry::with_addresses(
        arinsal_term::atoms::ERLANG,
        arinsal_term::atoms::ERLANG,
        0,
        0,
        0,
    )));
    let export_addr = std::ptr::from_ref(export) as u64;
    let mut assembler = BeamModuleAssembler::new();
    assembler.emit_i_func_label(1).unwrap();
    assembler
        .emit_raw(|encoder| {
            // ARG4 = export, ARG3 = entry. The fragment calls `helper(c_p, ...)`.
            encoder.mov_const(Gpr::x(3), export_addr)?;
            encoder.mov_reg(Gpr::x(2), Gpr::xzr())?;
            encoder.mov_const(Gpr::x(17), fragments.call_light_bif_helper() as u64)?;
            encoder.blr(Gpr::x(17))?;
            // `bl`/`blr` leaves x30 at this instruction. A real function saved the
            // scheduler bridge on E in the breakpoint trampoline; this caller did not,
            // so the continuation returns through the bridge slot enter_native published.
            encoder.ldr_uoff(Gpr::x(30), Gpr::x(19), 16_416)?;
            encoder.br(Gpr::x(30))
        })
        .unwrap();
    let module = assembler.finalize().unwrap();
    let mut header = ProcessHeader {
        fcalls: 100,
        ..ProcessHeader::default()
    };
    let mut registers = SchedulerRegisters::default();
    registers.x_reg_array[0] = arinsal_beamasm::rt::fixture_term(0x1234);
    registers.x_reg_array[1] = arinsal_beamasm::rt::fixture_term(0x5678);
    let mut stack = Box::new([0u64; 64]);
    header.stop = stack.as_mut_ptr().wrapping_add(stack.len());
    let outcome = enter_native(&mut header, &mut registers, &module.entry(1).unwrap());
    (outcome, header, registers, stack)
}

#[cfg(target_arch = "aarch64")]
#[test]
fn light_bif_trap_exits_to_target_with_saved_continuation_and_arguments() {
    let _guard = TEST_LOCK.lock().unwrap();
    let target = target_code();
    let address = target.ptr_at(0) as usize;
    let (outcome, header, registers, mut stack) = run(trap_bif as *const () as usize, address);
    let ExitReason::CallUnported {
        target_pc,
        resume_pc,
    } = outcome
    else {
        panic!("expected trap to exit native execution, got {outcome:?}");
    };
    assert_eq!(target_pc, address);
    assert_ne!(resume_pc, 0);
    assert_eq!(header.stop, stack.as_mut_ptr().wrapping_add(63));
    assert_eq!(stack[63], resume_pc as u64);
    assert_eq!(header.exc.freason, 0);
    assert_eq!(header.arity, 2);
    assert_eq!(
        arinsal_beamasm::rt::fixture_words(&registers.x_reg_array[..2]),
        [0x1234, 0x5678]
    );
}

#[cfg(target_arch = "aarch64")]
#[test]
fn light_bif_non_trap_error_keeps_master_return_behavior() {
    let _guard = TEST_LOCK.lock().unwrap();
    let target = target_code();
    let address = target.ptr_at(0) as usize;
    let (outcome, header, _, _) = run(error_bif as *const () as usize, address);
    assert_eq!(outcome, ExitReason::Returned);
    assert_eq!(header.exc.freason, 0x55);
    assert_eq!(header.exc.fvalue, 0xfeed);
}

#[cfg(target_arch = "aarch64")]
#[test]
fn light_bif_normal_return_uses_caller_continuation() {
    let _guard = TEST_LOCK.lock().unwrap();
    let target = target_code();
    let address = target.ptr_at(0) as usize;
    let (outcome, header, _, _) = run(normal_bif as *const () as usize, address);
    assert_eq!(outcome, ExitReason::Returned);
    assert_eq!(header.exc.freason, 0);
}

#[cfg(target_arch = "aarch64")]
#[test]
fn scheduler_entry_restores_xreg0_into_native_x0() {
    let _guard = TEST_LOCK.lock().unwrap();
    let mut assembler = BeamModuleAssembler::new();
    assembler.emit_i_func_label(1).unwrap();
    assembler
        .emit_raw(|encoder| {
            encoder.str_uoff(Gpr::x(0), Gpr::x(21), 48)?;
            encoder.mov_const(Gpr::x(0), 0)?;
            encoder.ret(Gpr::x(30))
        })
        .unwrap();
    let module = assembler.finalize().unwrap();
    let entry = module.entry(1).unwrap();
    let expected = 0x1234_5678_9abc_def0;
    let mut header = ProcessHeader {
        fcalls: 100,
        ..ProcessHeader::default()
    };
    let mut registers = SchedulerRegisters::default();
    registers.x_reg_array[0] = arinsal_beamasm::rt::fixture_term(expected);

    assert_eq!(
        enter_native(&mut header, &mut registers, &entry),
        ExitReason::Returned
    );
    assert_eq!(header.exc.fvalue, expected);
}
