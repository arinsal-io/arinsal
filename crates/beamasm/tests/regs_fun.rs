#![cfg(target_arch = "aarch64")]

use std::sync::{
    Mutex,
    atomic::{AtomicPtr, Ordering},
};

use arinsal_a64::enc::Gpr;
use arinsal_beamasm::{
    ExitReason, ProcessHeader, SchedulerRegisters,
    dispatch::DispatchFragments,
    enter_native,
    fun::{FunCallTag, FunResolver},
    module::{ArgVal, BeamModuleAssembler, FinalizedModule, ModuleError},
    rt,
};
use similar_asserts::assert_eq;

const FCALLS: i32 = 73;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Seen {
    x: [u64; 6],
    htop: usize,
    stop: usize,
    fcalls: i32,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum TargetFrame {
    None,
    Pop,
    Keep,
}

static ACTIVE_REGS: AtomicPtr<u64> = AtomicPtr::new(std::ptr::null_mut());
static SEEN: Mutex<Option<Seen>> = Mutex::new(None);
static TEST_LOCK: Mutex<()> = Mutex::new(());
static ASSERTION_INDEX: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

fn observe(process: *mut ProcessHeader) {
    let regs = ACTIVE_REGS.load(Ordering::Relaxed);
    let x = rt::scheduler_registers_mut(regs, |regs| {
        rt::fixture_words(&regs.x_reg_array[..6])
            .try_into()
            .unwrap()
    });
    let seen = rt::process_header_mut(process, |header| Seen {
        x,
        htop: header.htop as usize,
        stop: header.stop as usize,
        fcalls: header.fcalls,
    });
    *SEEN.lock().unwrap() = Some(seen);
}

extern "C" fn resolve_fun(process: *mut ProcessHeader, _: u64, _: u32, _: *mut u64) -> usize {
    observe(process);
    rt::process_header_mut(process, |header| header.self_pid as usize)
}

fn run(
    emit: impl FnOnce(&mut BeamModuleAssembler) -> Result<(), ModuleError>,
    initial: [u64; 6],
    target_frame: TargetFrame,
) -> (Seen, [u64; 6], ProcessHeader) {
    run_with_literals(&[], emit, initial, target_frame)
}

fn run_with_literals(
    literals: &[(i64, u64)],
    emit: impl FnOnce(&mut BeamModuleAssembler) -> Result<(), ModuleError>,
    initial: [u64; 6],
    target_frame: TargetFrame,
) -> (Seen, [u64; 6], ProcessHeader) {
    *SEEN.lock().unwrap() = None;
    let mut asm = BeamModuleAssembler::new();
    for &(index, word) in literals {
        asm.set_beam_literal(index, word);
    }
    // Fragment calls clobber LR, so keep the return address in scratch memory (the stack
    // pointer is asserted) unless the case builds its own frame.
    let own_cp = target_frame == TargetFrame::None;
    let cp_slot = std::mem::offset_of!(SchedulerRegisters, tmp_mem) as u32 + 7 * 8;
    asm.emit_i_func_label(1).unwrap();
    if own_cp {
        asm.emit_raw(|e| e.str_uoff(Gpr::x(30), Gpr::x(19), cp_slot))
            .unwrap();
    }
    emit(&mut asm).unwrap();
    let capture_and_return = |e: &mut arinsal_a64::enc::Emitter| {
        // x19 is the start of the register file; X0 is at `x_reg_array`.
        let x0 = std::mem::offset_of!(SchedulerRegisters, x_reg_array) as i16;
        e.stp(Gpr::x(25), Gpr::x(26), Gpr::x(19), x0)?;
        e.stp(Gpr::x(27), Gpr::x(28), Gpr::x(19), x0 + 16)?;
        e.stp(Gpr::x(15), Gpr::x(16), Gpr::x(19), x0 + 32)?;
        e.mov_reg(Gpr::x(0), Gpr::xzr())?;
        if own_cp {
            e.ldr_uoff(Gpr::x(30), Gpr::x(19), cp_slot)?;
        }
        e.ret(Gpr::x(30))
    };
    asm.emit_raw(capture_and_return).unwrap();
    if target_frame != TargetFrame::None {
        asm.emit_i_func_label(2).unwrap();
        if target_frame == TargetFrame::Pop {
            asm.emit_leave_frame().unwrap();
        }
        asm.emit_raw(capture_and_return).unwrap();
    }
    asm.emit_i_func_label(90).unwrap();
    asm.emit_raw(|e| {
        e.mov_reg(Gpr::x(0), Gpr::xzr())?;
        if own_cp {
            e.ldr_uoff(Gpr::x(30), Gpr::x(19), cp_slot)?;
        }
        e.ret(Gpr::x(30))
    })
    .unwrap();
    let mut module: FinalizedModule = asm.finalize().unwrap();
    for &(index, word) in literals {
        module.patch_literal(index, word).unwrap();
    }
    let mut heap = [0_u64; 64];
    let base = heap.as_mut_ptr();
    let mut header = ProcessHeader {
        htop: base,
        heap: base,
        hend: base.wrapping_add(heap.len()),
        stop: base.wrapping_add(heap.len()),
        fcalls: FCALLS,
        self_pid: if target_frame != TargetFrame::None {
            module.entries[&2] as usize as u64
        } else {
            0
        },
        ..ProcessHeader::default()
    };
    let mut regs = SchedulerRegisters::default();
    rt::set_fixture_words(&mut regs.x_reg_array[..6], &initial);
    ACTIVE_REGS.store(SchedulerRegisters::reg_ptr(&mut regs), Ordering::Relaxed);
    assert_eq!(
        enter_native(&mut header, &mut regs, &module.entry(1).unwrap()),
        ExitReason::Returned
    );
    ACTIVE_REGS.store(std::ptr::null_mut(), Ordering::Relaxed);
    let seen = SEEN.lock().unwrap().unwrap();
    (
        seen,
        rt::fixture_words(&regs.x_reg_array[..6])
            .try_into()
            .unwrap(),
        header,
    )
}

/// A local fun of arity 1 whose entry has no loaded code: every code index enters the
/// unloaded_fun fragment, which asks the resolver (beam_jit_handle_unloaded_fun) where to
/// continue.
// Port of erts/emulator/beam/jit/arm/instr_fun.cpp:34-62 (emit_unloaded_fun), OTP-29.1.1: it
// only pushes a native frame (emit_enter_runtime_frame), so the runtime sees E as the call
// left it: with the caller's frame for `i_call_fun2`, without it for `i_call_fun2_last`,
// which deallocates before `br` (instr_fun.cpp:425-455).
fn unloaded_fun_term() -> u64 {
    let fragments: &'static DispatchFragments = Box::leak(Box::new(
        DispatchFragments::with_fun_helpers(0, 0, 0, 0, resolve_fun as *const () as usize, 0)
            .unwrap(),
    ));
    let dispatch: &'static [u64; 4] = Box::leak(Box::new([fragments.unloaded_fun() as u64; 4]));
    let thing: &'static [u64; 2] = Box::leak(Box::new([(1 << 8) | 0x14, dispatch.as_ptr() as u64]));
    thing.as_ptr() as u64 | 2
}

fn sentinels() -> [u64; 6] {
    [0x10f, 0x20f, 0x30f, 0x40f, 0x50f, 0x60f]
}

fn assert_seen(seen: Seen, initial: [u64; 6], header: &ProcessHeader) {
    assert_eq!(seen.x, initial);
    assert_eq!(seen.htop, header.htop as usize);
    assert_eq!(seen.stop, header.stop as usize);
    assert_eq!(seen.fcalls, FCALLS);
}

fn assert_seen_with_frame(seen: Seen, initial: [u64; 6], header: &ProcessHeader) {
    assert_eq!(seen.x, initial);
    assert_eq!(seen.htop, header.htop as usize);
    assert_eq!(seen.stop + arinsal_term::CP_WORDS * 8, header.stop as usize);
    assert_eq!(seen.fcalls, FCALLS);
}

fn assert_xregs(actual: [u64; 6], expected: [u64; 6]) {
    let index = ASSERTION_INDEX.fetch_add(1, Ordering::Relaxed);
    assert_eq!(actual, expected, "runtime case {index}");
}

#[cfg(target_arch = "aarch64")]
#[test]
fn runtime_calls_in_fun_keep_register_state() {
    let _guard = TEST_LOCK.lock().unwrap();
    let initial = sentinels();
    let resolver: FunResolver = resolve_fun;
    let mut initial = initial;
    initial[1] = unloaded_fun_term();
    for call in 0..4 {
        let (seen, after, header) = run(
            |asm| match call {
                0 => {
                    asm.emit_enter_frame()?;
                    asm.emit_i_call_fun(1, resolver)?;
                    asm.emit_leave_frame()
                }
                1 => {
                    asm.emit_enter_frame()?;
                    asm.emit_i_call_fun2(FunCallTag::Dynamic, 1, ArgVal::X(1), resolver)?;
                    asm.emit_leave_frame()
                }
                2 => {
                    asm.emit_enter_frame()?;
                    asm.emit_i_call_fun_last(1, 0, resolver)
                }
                _ => {
                    asm.emit_enter_frame()?;
                    asm.emit_i_call_fun2_last(FunCallTag::Dynamic, 1, ArgVal::X(1), 0, resolver)
                }
            },
            initial,
            if call < 2 {
                TargetFrame::Pop
            } else {
                TargetFrame::Keep
            },
        );
        if call < 2 {
            assert_seen_with_frame(seen, initial, &header);
        } else {
            assert_seen(seen, initial, &header);
        }
        assert_xregs(after, initial);
    }
}

#[cfg(target_arch = "aarch64")]
#[test]
fn dynamic_fun_resolver_restores_all_live_xregs() {
    let _guard = TEST_LOCK.lock().unwrap();
    let mut initial = sentinels();
    initial[1] = unloaded_fun_term();
    let resolver: FunResolver = resolve_fun;
    let (seen, after, header) = run(
        |asm| {
            asm.emit_enter_frame()?;
            asm.emit_i_call_fun2(FunCallTag::Dynamic, 1, ArgVal::X(1), resolver)?;
            asm.emit_leave_frame()
        },
        initial,
        TargetFrame::Pop,
    );
    assert_seen_with_frame(seen, initial, &header);
    assert_xregs(after, initial);
}
