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
    map::MapRuntime,
    module::{ArgVal, BeamModuleAssembler, FinalizedModule, ModuleError},
    records::RecordRuntime,
    rt,
};

const VALUE: u64 = 0x4f;
const REG_OUTPUT: u64 = 0x8f;
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

static ACTIVE_REGS: AtomicPtr<SchedulerRegisters> = AtomicPtr::new(std::ptr::null_mut());
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

extern "C" fn map_get(process: *mut ProcessHeader, _: u64, _: u64, _: u64) -> u64 {
    observe(process);
    VALUE
}

extern "C" fn map_get_elements(process: *mut ProcessHeader, _: u64, _: u64, _: u64, _: u64) -> u64 {
    observe(process);
    rt::scheduler_registers_mut(ACTIVE_REGS.load(Ordering::Relaxed), |regs| {
        regs.x_reg_array[0] = arinsal_beamasm::rt::fixture_term(REG_OUTPUT);
    });
    1
}

extern "C" fn map_update(process: *mut ProcessHeader, _: u64, _: u64, _: u64, _: u64) -> u64 {
    observe(process);
    VALUE
}

extern "C" fn record_get(process: *mut ProcessHeader, _: u64, _: u64, _: u64, _: u64) -> u64 {
    observe(process);
    VALUE
}

extern "C" fn record_create(
    process: *mut ProcessHeader,
    _: *mut SchedulerRegisters,
    _: u64,
    _: u64,
    _: u64,
    _: u64,
) -> u64 {
    observe(process);
    VALUE
}

extern "C" fn record_get_elements(
    process: *mut ProcessHeader,
    registers: *mut SchedulerRegisters,
    _: u64,
    _: u64,
    base: u64,
) -> u64 {
    observe(process);
    rt::scheduler_registers_mut(registers, |regs| {
        regs.x_reg_array[base as usize] = arinsal_beamasm::rt::fixture_term(REG_OUTPUT)
    });
    1
}

extern "C" fn record_update(
    process: *mut ProcessHeader,
    _: *mut SchedulerRegisters,
    _: u64,
    _: u64,
    _: u64,
    _: u64,
) -> u64 {
    observe(process);
    VALUE
}

extern "C" fn resolve_fun(process: *mut ProcessHeader, _: u64, _: u32) -> usize {
    observe(process);
    rt::process_header_mut(process, |header| header.self_pid as usize)
}

fn map_runtime() -> MapRuntime {
    let fragments = Box::leak(Box::new(
        arinsal_beamasm::map::MapFragments::new(map_get, map_update).unwrap(),
    ));
    MapRuntime {
        get_element_shared: fragments.get_element_shared(),
        get_element_hash_shared: fragments.get_element_hash_shared(),
        get: map_get,
        get_elements: map_get_elements,
        lookup_module: 0,
        new_map: map_update,
        update_assoc: map_update,
        update_exact: map_update,
        put_single: map_update,
        update_single_exact_shared: fragments.update_single_exact_shared(),
    }
}

fn record_runtime() -> RecordRuntime {
    RecordRuntime {
        get_field: record_get,
        get_local_field: record_get,
        create_local: record_create,
        create: record_create,
        get_elements: record_get_elements,
        update: record_update,
    }
}

fn run(
    emit: impl FnOnce(&mut BeamModuleAssembler) -> Result<(), ModuleError>,
    initial: [u64; 6],
    target_frame: TargetFrame,
) -> (Seen, [u64; 6], ProcessHeader) {
    *SEEN.lock().unwrap() = None;
    let mut asm = BeamModuleAssembler::new();
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
        e.stp(Gpr::x(25), Gpr::x(26), Gpr::x(19), 0)?;
        e.stp(Gpr::x(27), Gpr::x(28), Gpr::x(19), 16)?;
        e.stp(Gpr::x(15), Gpr::x(16), Gpr::x(19), 32)?;
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
    let module: FinalizedModule = asm.finalize().unwrap();
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
    ACTIVE_REGS.store(&mut regs, Ordering::Relaxed);
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
fn runtime_calls_in_fun_map_and_records_keep_register_state() {
    let _guard = TEST_LOCK.lock().unwrap();
    let initial = sentinels();
    let mut expected = initial;

    // A non-immediate key makes the shared fragment call the runtime lookup; the fragment
    // reads an immediate key's map directly, as erts does.
    let mut generic_initial = initial;
    generic_initial[1] = 0x208;
    let mut generic_expected = generic_initial;
    let (seen, after, header) = run(
        |asm| {
            asm.emit_i_get_map_element(90, ArgVal::X(0), ArgVal::X(1), ArgVal::X(2), map_runtime())
        },
        generic_initial,
        TargetFrame::None,
    );
    assert_seen(seen, generic_initial, &header);
    generic_expected[2] = VALUE;
    assert_xregs(after, generic_expected);
    expected[2] = VALUE;

    let (seen, after, header) = run(
        |asm| {
            asm.emit_i_get_map_element_hash(
                90,
                ArgVal::X(0),
                ArgVal::X(1),
                ArgVal::Immediate(17),
                ArgVal::X(2),
                map_runtime(),
            )
        },
        initial,
        TargetFrame::None,
    );
    assert_seen(seen, initial, &header);
    assert_xregs(after, expected);

    let map_args = [ArgVal::Literal(0x100), ArgVal::X(0), ArgVal::Immediate(0)];
    let (seen, after, header) = run(
        |asm| asm.emit_i_get_map_elements(90, ArgVal::X(5), &map_args, map_runtime()),
        initial,
        TargetFrame::None,
    );
    assert_seen(seen, initial, &header);
    expected = initial;
    expected[0] = REG_OUTPUT;
    assert_xregs(after, expected);

    // Only the first destination is wanted; the rest is OTP's scratch X register.
    let mut large_args = [ArgVal::Immediate(0); 24];
    for triplet in large_args.as_chunks_mut::<3>().0 {
        triplet[1] = ArgVal::XMemory(1023);
    }
    large_args[1] = ArgVal::X(0);
    let (seen, after, header) = run(
        |asm| asm.emit_i_get_map_elements(90, ArgVal::X(5), &large_args, map_runtime()),
        initial,
        TargetFrame::None,
    );
    assert_seen(seen, initial, &header);
    expected = initial;
    expected[0] = REG_OUTPUT;
    assert_xregs(after, expected);

    let (seen, after, header) = run(
        |asm| asm.emit_new_map(ArgVal::X(0), 2, &[], map_runtime()),
        initial,
        TargetFrame::None,
    );
    assert_seen(seen, initial, &header);
    expected = initial;
    expected[0] = VALUE;
    assert_xregs(after, expected);

    let (seen, after, header) = run(
        |asm| {
            asm.emit_update_map_assoc(
                ArgVal::X(1),
                ArgVal::X(0),
                2,
                &[ArgVal::Immediate(0x7f), ArgVal::Immediate(0x8f)],
                map_runtime(),
            )
        },
        initial,
        TargetFrame::None,
    );
    assert_seen(seen, initial, &header);
    expected = initial;
    expected[0] = VALUE;
    assert_xregs(after, expected);

    let (seen, after, header) = run(
        |asm| {
            asm.emit_update_map_exact(
                ArgVal::X(1),
                90,
                ArgVal::X(0),
                2,
                &[ArgVal::Immediate(0x7f), ArgVal::Immediate(0x8f)],
                map_runtime(),
            )
        },
        initial,
        TargetFrame::None,
    );
    assert_seen(seen, initial, &header);
    expected = initial;
    expected[0] = VALUE;
    assert_xregs(after, expected);

    let (seen, after, header) = run(
        |asm| {
            asm.emit_get_record_field(
                0,
                ArgVal::X(1),
                ArgVal::Immediate(0),
                ArgVal::Immediate(0x2f),
                ArgVal::X(2),
                record_runtime(),
            )
        },
        initial,
        TargetFrame::None,
    );
    assert_seen(seen, initial, &header);
    expected = initial;
    expected[2] = VALUE;
    assert_xregs(after, expected);

    let (seen, after, header) = run(
        |asm| {
            asm.emit_i_create_local_native_record(
                ArgVal::Immediate(0x3f),
                ArgVal::X(0),
                6,
                &[ArgVal::Immediate(0x4f)],
                record_runtime(),
            )
        },
        initial,
        TargetFrame::None,
    );
    assert_seen(seen, initial, &header);
    expected = initial;
    expected[0] = VALUE;
    assert_xregs(after, expected);

    let (seen, after, header) = run(
        |asm| {
            asm.emit_i_create_native_record(
                ArgVal::Immediate(0x3f),
                ArgVal::X(0),
                6,
                &[ArgVal::Immediate(0x4f)],
                record_runtime(),
            )
        },
        initial,
        TargetFrame::None,
    );
    assert_seen(seen, initial, &header);
    expected = initial;
    expected[0] = VALUE;
    assert_xregs(after, expected);

    let (seen, after, header) = run(
        |asm| {
            asm.emit_i_get_record_elements(
                90,
                ArgVal::X(5),
                &[ArgVal::Immediate(0x2f)],
                &[ArgVal::X(0)],
                record_runtime(),
            )
        },
        initial,
        TargetFrame::None,
    );
    assert_seen(seen, initial, &header);
    expected = initial;
    expected[0] = REG_OUTPUT;
    assert_xregs(after, expected);

    let (seen, after, header) = run(
        |asm| {
            asm.emit_i_update_native_record(
                ArgVal::X(1),
                ArgVal::X(0),
                2,
                &[ArgVal::X(3)],
                record_runtime(),
            )
        },
        initial,
        TargetFrame::None,
    );
    assert_seen(seen, initial, &header);
    expected = initial;
    expected[0] = VALUE;
    assert_xregs(after, expected);

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
fn map_runtime_call_restores_destination_and_other_xregs() {
    let _guard = TEST_LOCK.lock().unwrap();
    let initial = sentinels();
    let (seen, after, header) = run(
        |asm| asm.emit_new_map(ArgVal::X(0), 6, &[], map_runtime()),
        initial,
        TargetFrame::None,
    );
    assert_seen(seen, initial, &header);
    let mut expected = initial;
    expected[0] = VALUE;
    assert_xregs(after, expected);
}

#[cfg(target_arch = "aarch64")]
#[test]
fn record_elements_runtime_call_reloads_helper_written_xreg() {
    let _guard = TEST_LOCK.lock().unwrap();
    let initial = sentinels();
    let (seen, after, header) = run(
        |asm| {
            asm.emit_i_get_record_elements(
                90,
                ArgVal::X(5),
                &[ArgVal::Immediate(0x2f)],
                &[ArgVal::X(0)],
                record_runtime(),
            )
        },
        initial,
        TargetFrame::None,
    );
    assert_seen(seen, initial, &header);
    let mut expected = initial;
    expected[0] = REG_OUTPUT;
    assert_xregs(after, expected);
}

#[cfg(target_arch = "aarch64")]
#[test]
fn record_creation_uses_live_prefix_and_keeps_unused_xregs() {
    let _guard = TEST_LOCK.lock().unwrap();
    let initial = sentinels();
    let (seen, after, header) = run(
        |asm| {
            asm.emit_i_create_local_native_record(
                ArgVal::Immediate(0x3f),
                ArgVal::X(0),
                6,
                &[ArgVal::Immediate(0x4f)],
                record_runtime(),
            )
        },
        initial,
        TargetFrame::None,
    );
    assert_seen(seen, initial, &header);
    let mut expected = initial;
    expected[0] = VALUE;
    assert_xregs(after, expected);
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
