use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use arinsal_a64::enc::Gpr;
use arinsal_beamasm::{
    ExitReason, ProcessHeader, SchedulerRegisters,
    arith::ArithHelper,
    bif::{ApplyResolver, BifTarget},
    enter_native,
    guard::GuardHelper,
    module::{ArgVal, BeamModuleAssembler},
};

static SCHEDULER_REGS: AtomicUsize = AtomicUsize::new(0);
static SEEN_HTOP: AtomicUsize = AtomicUsize::new(0);
static SEEN_STOP: AtomicUsize = AtomicUsize::new(0);
static SEEN_FCALLS: AtomicUsize = AtomicUsize::new(0);
static SEEN_XREGS: [AtomicUsize; 6] = [
    AtomicUsize::new(0),
    AtomicUsize::new(0),
    AtomicUsize::new(0),
    AtomicUsize::new(0),
    AtomicUsize::new(0),
    AtomicUsize::new(0),
];
static NATIVE_TEST_LOCK: Mutex<()> = Mutex::new(());

extern "C" fn bif_helper(
    process: *mut ProcessHeader,
    left: u64,
    right: u64,
    _: u64,
    _: u32,
) -> u64 {
    record(process);
    left.wrapping_add(right)
}

extern "C" fn guard_helper(process: *mut ProcessHeader, _: u32, left: u64, right: u64) -> u64 {
    record(process);
    u64::from(left < right)
}

extern "C" fn arith_helper(process: *mut ProcessHeader, _: u32, _: u64, _: u64) -> u64 {
    record(process);
    0xfeed
}

extern "C" fn resolve_helper(process: *mut ProcessHeader, _: u64, _: u32, _: u32) -> usize {
    record(process);
    0
}

fn record(process: *mut ProcessHeader) {
    arinsal_beamasm::rt::process_header_mut(process, |header| {
        SEEN_HTOP.store(header.htop as usize, Ordering::Relaxed);
        SEEN_STOP.store(header.stop as usize, Ordering::Relaxed);
        SEEN_FCALLS.store(header.fcalls as usize, Ordering::Relaxed);
    });
    let regs = SCHEDULER_REGS.load(Ordering::Relaxed) as *mut SchedulerRegisters;
    arinsal_beamasm::rt::scheduler_registers_mut(regs, |registers| {
        for (index, seen) in SEEN_XREGS.iter().enumerate() {
            seen.store(
                registers.x_reg_array[index].tagged_word() as usize,
                Ordering::Relaxed,
            );
        }
    });
}

fn execute(emit: impl FnOnce(&mut BeamModuleAssembler)) -> (ProcessHeader, SchedulerRegisters) {
    let mut assembler = BeamModuleAssembler::new();
    assembler.emit_i_func_label(1).unwrap();
    emit(&mut assembler);
    assembler
        .emit_raw(|e| {
            e.mov_reg(Gpr::x(0), Gpr::xzr())?;
            e.ret(Gpr::x(30))
        })
        .unwrap();
    let module = assembler.finalize().unwrap();
    let mut header = ProcessHeader::default();
    let mut registers = SchedulerRegisters::default();
    let mut heap = [0u64; 32];
    let mut stack = [0u64; 32];
    header.heap = heap.as_mut_ptr();
    header.htop = heap.as_mut_ptr().wrapping_add(4);
    header.hend = heap.as_mut_ptr().wrapping_add(heap.len());
    header.stop = stack.as_mut_ptr().wrapping_add(stack.len());
    header.fcalls = 77;
    for index in 0..6 {
        registers.x_reg_array[index] = arinsal_beamasm::rt::fixture_term(0x1000 + index as u64);
    }
    SCHEDULER_REGS.store(registers.x_reg_array.as_ptr() as usize, Ordering::Relaxed);
    SEEN_HTOP.store(0, Ordering::Relaxed);
    SEEN_STOP.store(0, Ordering::Relaxed);
    SEEN_FCALLS.store(0, Ordering::Relaxed);
    for seen in &SEEN_XREGS {
        seen.store(0, Ordering::Relaxed);
    }
    assert_eq!(
        enter_native(&mut header, &mut registers, &module.entry(1).unwrap()),
        ExitReason::Returned
    );
    (header, registers)
}

fn assert_registers(registers: &SchedulerRegisters, written_xreg: Option<usize>) {
    for index in 0..6 {
        if Some(index) != written_xreg {
            assert_eq!(
                registers.x_reg_array[index],
                arinsal_beamasm::rt::fixture_term(0x1000 + index as u64)
            );
        }
    }
    for (index, seen) in SEEN_XREGS.iter().enumerate() {
        assert_eq!(
            seen.load(Ordering::Relaxed),
            (0x1000 + index as u64) as usize
        );
    }
}

fn assert_runtime_state(header: &ProcessHeader) {
    assert_eq!(SEEN_HTOP.load(Ordering::Relaxed), header.htop as usize);
    assert_eq!(SEEN_STOP.load(Ordering::Relaxed), header.stop as usize);
    assert_eq!(SEEN_FCALLS.load(Ordering::Relaxed), header.fcalls as usize);
}

#[test]
fn bif2_runtime_call_preserves_register_state() {
    let _lock = NATIVE_TEST_LOCK.lock().unwrap();
    let (header, registers) = execute(|assembler| {
        assembler
            .emit_i_bif2(
                ArgVal::X(0),
                ArgVal::X(1),
                None,
                bif_helper as BifTarget,
                ArgVal::X(0),
            )
            .unwrap();
    });
    assert_runtime_state(&header);
    assert_registers(&registers, Some(0));
}

#[test]
fn light_bif_runtime_call_preserves_register_state() {
    let _lock = NATIVE_TEST_LOCK.lock().unwrap();
    let (header, registers) = execute(|assembler| {
        assembler
            .emit_call_light_bif(
                bif_helper as BifTarget,
                &[ArgVal::X(0), ArgVal::X(1)],
                ArgVal::X(0),
            )
            .unwrap();
    });
    assert_runtime_state(&header);
    assert_registers(&registers, Some(0));
}

#[test]
fn bif_mfa_runtime_call_preserves_register_state() {
    let _lock = NATIVE_TEST_LOCK.lock().unwrap();
    let (header, registers) = execute(|assembler| {
        assembler
            .emit_call_bif_mfa(
                bif_helper as BifTarget,
                &[ArgVal::X(0), ArgVal::X(1)],
                ArgVal::X(0),
            )
            .unwrap();
    });
    assert_runtime_state(&header);
    assert_registers(&registers, Some(0));
}

#[test]
fn guard_runtime_call_preserves_register_state() {
    let _lock = NATIVE_TEST_LOCK.lock().unwrap();
    let (header, registers) = execute(|assembler| {
        assembler
            .emit_is_lt(ArgVal::X(0), ArgVal::X(1), 99, guard_helper as GuardHelper)
            .unwrap();
        assembler.emit_i_func_label(99).unwrap();
    });
    assert_runtime_state(&header);
    assert_registers(&registers, None);
}

#[test]
fn arithmetic_runtime_call_preserves_register_state() {
    let _lock = NATIVE_TEST_LOCK.lock().unwrap();
    let (header, registers) = execute(|assembler| {
        assembler
            .emit_i_plus(
                ArgVal::X(0),
                ArgVal::X(1),
                ArgVal::X(0),
                arith_helper as ArithHelper,
            )
            .unwrap();
    });
    assert_runtime_state(&header);
    assert_registers(&registers, Some(0));
}

#[test]
fn apply_runtime_call_preserves_register_state() {
    let _lock = NATIVE_TEST_LOCK.lock().unwrap();
    let (header, registers) = execute(|assembler| {
        assembler
            .emit_i_apply(resolve_helper as ApplyResolver, 3)
            .unwrap();
    });
    assert_runtime_state(&header);
    assert_registers(&registers, None);
}

#[test]
fn guard_value_runtime_call_preserves_register_state() {
    let _lock = NATIVE_TEST_LOCK.lock().unwrap();
    let (header, registers) = execute(|assembler| {
        assembler
            .emit_bif_min(
                ArgVal::X(0),
                ArgVal::X(1),
                ArgVal::X(2),
                guard_helper as GuardHelper,
            )
            .unwrap();
    });
    assert_runtime_state(&header);
    assert_registers(&registers, Some(2));
}
