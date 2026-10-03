use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

use arinsal_a64::enc::Gpr;
use arinsal_beamasm::{
    ExitReason, ProcessHeader, SchedulerRegisters,
    bif::{BifTarget, ExportEntry},
    enter_native,
    module::{ArgVal, BeamModuleAssembler, FinalizedModule},
};

static LIVE_SEEN: [AtomicU32; 7] = [
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
];
static GC_CALLS: AtomicUsize = AtomicUsize::new(0);
static GC_HEAP_TOP: AtomicUsize = AtomicUsize::new(0);
static APPLY_TARGET: AtomicUsize = AtomicUsize::new(0);
static GC_RETURN_TARGET: AtomicUsize = AtomicUsize::new(0);
static MOVED_STACK: std::sync::Mutex<[u64; 8]> = std::sync::Mutex::new([0; 8]);
static MOVED_HEAP: std::sync::Mutex<[u64; 8]> = std::sync::Mutex::new([0; 8]);

extern "C" fn add_bif(_: *mut ProcessHeader, left: u64, right: u64, third: u64, live: u32) -> u64 {
    LIVE_SEEN[live.min(6) as usize].store(live, Ordering::Relaxed);
    tagged((left >> 4) + (right >> 4) + (third >> 4))
}

extern "C" fn error_bif(process: *mut ProcessHeader, _: u64, _: u64, _: u64, _: u32) -> u64 {
    arinsal_beamasm::rt::process_header_mut(process, |header| header.freason = 0x55);
    tagged(9)
}

extern "C" fn gc_bif(process: *mut ProcessHeader, value: u64, _: u64, _: u64, live: u32) -> u64 {
    LIVE_SEEN[live.min(6) as usize].store(live, Ordering::Relaxed);
    GC_CALLS.fetch_add(1, Ordering::Relaxed);
    let heap = Box::leak(Box::new([0u64; 2]));
    let new_htop = heap.as_mut_ptr().wrapping_add(1);
    arinsal_beamasm::rt::process_header_mut(process, |header| {
        header.htop = new_htop;
    });
    GC_HEAP_TOP.store(new_htop as usize, Ordering::Relaxed);
    value
}

extern "C" fn relocate_gc_bif(
    process: *mut ProcessHeader,
    value: u64,
    _: u64,
    _: u64,
    _: u32,
) -> u64 {
    let target = GC_RETURN_TARGET.load(Ordering::Acquire);
    let mut stack = MOVED_STACK.lock().unwrap();
    stack[0] = target as u64;
    let stack_top = stack.as_mut_ptr();
    let mut heap = MOVED_HEAP.lock().unwrap();
    let heap_base = heap.as_mut_ptr();
    arinsal_beamasm::rt::process_header_mut(process, |header| {
        header.stop = stack_top;
        header.heap = heap_base;
        header.htop = heap_base.wrapping_add(2);
        header.hend = heap_base.wrapping_add(heap.len());
    });
    value
}

extern "C" fn gc_add_bif(
    _: *mut ProcessHeader,
    left: u64,
    right: u64,
    third: u64,
    live: u32,
) -> u64 {
    LIVE_SEEN[live.min(6) as usize].store(live, Ordering::Relaxed);
    tagged((left >> 4) + (right >> 4) + (third >> 4))
}

extern "C" fn resolve_apply(_: *mut ProcessHeader, _: u64, _: u32, _: u32) -> usize {
    APPLY_TARGET.load(Ordering::Acquire)
}

#[cfg(target_arch = "aarch64")]
fn run(emit: impl FnOnce(&mut BeamModuleAssembler)) -> (u64, u64, u64) {
    let mut asm = BeamModuleAssembler::new();
    asm.emit_i_func_label(1).unwrap();
    emit(&mut asm);
    asm.emit_raw(|e| {
        e.mov_reg(Gpr::x(0), Gpr::xzr())?;
        e.ret(Gpr::x(30))
    })
    .unwrap();
    let module = asm.finalize().unwrap();
    execute(
        &module,
        1,
        ProcessHeader::default(),
        [tagged(5), tagged(7), tagged(11)],
    )
}

fn tagged(value: u64) -> u64 {
    (value << 4) | 15
}

#[cfg(target_arch = "aarch64")]
fn execute(
    module: &FinalizedModule,
    label: u32,
    mut header: ProcessHeader,
    values: [u64; 3],
) -> (u64, u64, u64) {
    let mut registers = SchedulerRegisters::default();
    registers.x_reg_array[..3].copy_from_slice(&values);
    let mut stack = [0u64; 64];
    header.stop = stack.as_mut_ptr().wrapping_add(stack.len());
    if header.fcalls == 0 {
        header.fcalls = 100;
    }
    let outcome = enter_native(&mut header, &mut registers, &module.entry(label).unwrap());
    assert_eq!(outcome, ExitReason::Returned);
    (
        registers.x_reg_array[0],
        header.stop as usize as u64,
        header.freason,
    )
}

#[cfg(target_arch = "aarch64")]
fn emit_binary(op: impl FnOnce(&mut BeamModuleAssembler, BifTarget)) -> u64 {
    run(|asm| op(asm, add_bif)).0
}

#[cfg(target_arch = "aarch64")]
#[test]
fn native_call_light_bif() {
    let result = emit_binary(|asm, bif| {
        asm.emit_call_light_bif(bif, &[ArgVal::X(0), ArgVal::X(1)], ArgVal::X(0))
            .unwrap();
    });
    assert_eq!(result, tagged(12));
}

#[cfg(target_arch = "aarch64")]
#[test]
fn light_bif_reloads_moved_heap_and_stack_before_returning() {
    let mut asm = BeamModuleAssembler::new();
    asm.emit_i_func_label(1).unwrap();
    asm.emit_raw(|e| e.stp_pre(Gpr::x(29), Gpr::x(30), Gpr::sp(), -16))
        .unwrap();
    asm.emit_call_light_bif(relocate_gc_bif, &[ArgVal::X(0)], ArgVal::X(0))
        .unwrap();
    asm.return_().unwrap();
    asm.emit_i_func_label(2).unwrap();
    asm.emit_raw(|e| {
        e.mov_reg(Gpr::x(25), Gpr::x(20))?;
        e.mov_reg(Gpr::x(26), Gpr::x(23))?;
        e.ldp_post(Gpr::x(29), Gpr::x(30), Gpr::sp(), 16)?;
        e.ret(Gpr::x(30))
    })
    .unwrap();
    asm.emit_i_func_label(3).unwrap();
    asm.emit_raw(|e| {
        e.mov_const(Gpr::x(25), 0)?;
        e.mov_const(Gpr::x(26), 0)?;
        e.ldp_post(Gpr::x(29), Gpr::x(30), Gpr::sp(), 16)?;
        e.ret(Gpr::x(30))
    })
    .unwrap();
    let module = asm.finalize().unwrap();
    GC_RETURN_TARGET.store(module.entries[&2] as usize, Ordering::Release);

    let mut old_stack = [0_u64; 8];
    old_stack[6] = 0;
    old_stack[7] = module.entries[&2] as u64;
    let mut header = ProcessHeader {
        stop: old_stack.as_mut_ptr().wrapping_add(6),
        fcalls: 100,
        ..ProcessHeader::default()
    };
    let mut registers = SchedulerRegisters::default();
    registers.x_reg_array[0] = tagged(5);
    assert_eq!(
        enter_native(&mut header, &mut registers, &module.entry(1).unwrap()),
        ExitReason::Returned
    );
    let stack = MOVED_STACK.lock().unwrap();
    let heap = MOVED_HEAP.lock().unwrap();
    assert_eq!(
        registers.x_reg_array[0],
        stack.as_ptr().wrapping_add(1) as u64
    );
    assert_eq!(
        registers.x_reg_array[1],
        heap.as_ptr().wrapping_add(2) as u64
    );
}

#[cfg(target_arch = "aarch64")]
#[test]
fn native_call_bif_mfa() {
    let result = emit_binary(|asm, bif| {
        asm.emit_call_bif_mfa(bif, &[ArgVal::X(0), ArgVal::X(1)], ArgVal::X(0))
            .unwrap();
    });
    assert_eq!(result, tagged(12));
}

#[cfg(target_arch = "aarch64")]
#[test]
fn native_i_bif1() {
    assert_eq!(
        run(|a| a
            .emit_i_bif1(ArgVal::X(0), None, add_bif, ArgVal::X(0))
            .unwrap())
        .0,
        tagged(5)
    );
}

#[cfg(target_arch = "aarch64")]
#[test]
fn native_i_bif2() {
    assert_eq!(
        run(|a| a
            .emit_i_bif2(ArgVal::X(0), ArgVal::X(1), None, add_bif, ArgVal::X(0))
            .unwrap())
        .0,
        tagged(12)
    );
}

#[cfg(target_arch = "aarch64")]
#[test]
fn native_i_bif3() {
    assert_eq!(
        run(|a| a
            .emit_i_bif3(
                ArgVal::X(0),
                ArgVal::X(1),
                ArgVal::X(2),
                None,
                add_bif,
                ArgVal::X(0)
            )
            .unwrap())
        .0,
        tagged(23)
    );
}

#[cfg(target_arch = "aarch64")]
#[test]
fn native_i_gc_bif1() {
    GC_CALLS.store(0, Ordering::Relaxed);
    let result = run(|a| {
        a.emit_i_gc_bif1(ArgVal::X(0), None, gc_bif, 1, ArgVal::X(0))
            .unwrap()
    })
    .0;
    assert_eq!(result, tagged(5));
    assert_eq!(GC_CALLS.load(Ordering::Relaxed), 1);
    assert_ne!(GC_HEAP_TOP.load(Ordering::Relaxed), 0);
    assert_eq!(LIVE_SEEN[1].load(Ordering::Relaxed), 1);
}

#[cfg(target_arch = "aarch64")]
#[test]
fn native_i_gc_bif2() {
    assert_eq!(
        run(|a| a
            .emit_i_gc_bif2(
                ArgVal::X(0),
                ArgVal::X(1),
                None,
                gc_add_bif,
                2,
                ArgVal::X(0)
            )
            .unwrap())
        .0,
        tagged(12)
    );
    assert_eq!(LIVE_SEEN[2].load(Ordering::Relaxed), 2);
}

#[cfg(target_arch = "aarch64")]
#[test]
fn native_i_gc_bif3() {
    assert_eq!(
        run(|a| a
            .emit_i_gc_bif3(
                ArgVal::X(0),
                ArgVal::X(1),
                ArgVal::X(2),
                None,
                gc_add_bif,
                3,
                ArgVal::X(0)
            )
            .unwrap())
        .0,
        tagged(23)
    );
    assert_eq!(LIVE_SEEN[3].load(Ordering::Relaxed), 3);
}

#[cfg(target_arch = "aarch64")]
#[test]
fn bif_error_sets_freason_and_reaches_error_fragment() {
    let mut asm = BeamModuleAssembler::new();
    asm.emit_i_func_label(1).unwrap();
    asm.emit_enter_frame().unwrap();
    asm.emit_i_bif1(ArgVal::X(0), None, error_bif, ArgVal::X(0))
        .unwrap();
    asm.return_().unwrap();
    let module = asm.finalize().unwrap();
    let header = ProcessHeader::default();
    let (result, _, reason) = execute(&module, 1, header, [tagged(5), 0, 0]);
    assert_eq!(result, tagged(5));
    assert_ne!(reason, 0);
}

#[cfg(target_arch = "aarch64")]
fn module_with_export(export: &'static ExportEntry, value: u64, tail_kind: u8) -> FinalizedModule {
    let mut asm = BeamModuleAssembler::new();
    asm.emit_i_func_label(1).unwrap();
    asm.emit_enter_frame().unwrap();
    if tail_kind != 0 {
        asm.call(4).unwrap();
        asm.return_().unwrap();
        asm.emit_i_func_label(4).unwrap();
        asm.emit_enter_frame().unwrap();
    }
    match tail_kind {
        0 => asm.emit_i_call_ext(export).unwrap(),
        1 => asm.emit_i_call_ext_only(export).unwrap(),
        _ => asm.emit_i_call_ext_last(export, 0).unwrap(),
    }
    if tail_kind == 0 {
        asm.return_().unwrap();
    }
    asm.emit_i_func_label(2).unwrap();
    asm.emit_enter_frame().unwrap();
    asm.emit_raw(|e| e.mov_const(Gpr::x(25), value)).unwrap();
    asm.return_().unwrap();
    asm.emit_i_func_label(3).unwrap();
    asm.emit_enter_frame().unwrap();
    asm.emit_raw(|e| e.mov_const(Gpr::x(25), tagged((value >> 4) + 1)))
        .unwrap();
    asm.return_().unwrap();
    asm.finalize().unwrap()
}

#[cfg(target_arch = "aarch64")]
#[test]
fn native_i_call_ext() {
    let export = Box::leak(Box::new(ExportEntry::new(0)));
    let module = module_with_export(export, tagged(31), 0);
    export.set_address(0, module.entries[&2] as usize);
    assert_eq!(
        execute(&module, 1, ProcessHeader::default(), [0; 3]).0,
        tagged(31)
    );
}

#[cfg(target_arch = "aarch64")]
#[test]
fn native_i_call_ext_last() {
    let export = Box::leak(Box::new(ExportEntry::new(0)));
    let module = module_with_export(export, tagged(32), 2);
    export.set_address(0, module.entries[&2] as usize);
    execute(&module, 1, ProcessHeader::default(), [0; 3]);
}

#[cfg(target_arch = "aarch64")]
#[test]
fn native_i_call_ext_only() {
    let export = Box::leak(Box::new(ExportEntry::new(0)));
    let module = module_with_export(export, tagged(33), 1);
    export.set_address(0, module.entries[&2] as usize);
    execute(&module, 1, ProcessHeader::default(), [0; 3]);
}

#[cfg(target_arch = "aarch64")]
#[test]
fn export_entry_repoints_between_calls() {
    let export = Box::leak(Box::new(ExportEntry::new(0)));
    let module = module_with_export(export, tagged(41), 0);
    export.set_address(0, module.entries[&2] as usize);
    assert_eq!(
        execute(&module, 1, ProcessHeader::default(), [0; 3]).0,
        tagged(41)
    );
    export.set_address(0, module.entries[&3] as usize);
    assert_eq!(
        execute(&module, 1, ProcessHeader::default(), [0; 3]).0,
        tagged(42)
    );
}

#[cfg(target_arch = "aarch64")]
#[test]
fn native_i_apply() {
    apply_case(|a| a.emit_i_apply(resolve_apply, 2).unwrap(), false);
}

#[cfg(target_arch = "aarch64")]
#[test]
fn native_i_apply_last() {
    apply_case(|a| a.emit_i_apply_last(resolve_apply, 2, 0).unwrap(), true);
}

#[cfg(target_arch = "aarch64")]
#[test]
fn native_i_apply_only() {
    apply_case(|a| a.emit_i_apply_only(resolve_apply, 2).unwrap(), true);
}

#[cfg(target_arch = "aarch64")]
#[test]
fn native_i_apply_fun() {
    apply_case(|a| a.emit_i_apply_fun(resolve_apply, 2).unwrap(), false);
}

#[cfg(target_arch = "aarch64")]
#[test]
fn native_i_apply_fun_last() {
    apply_case(
        |a| a.emit_i_apply_fun_last(resolve_apply, 2, 0).unwrap(),
        true,
    );
}

#[cfg(target_arch = "aarch64")]
#[test]
fn native_i_apply_fun_only() {
    apply_case(|a| a.emit_i_apply_fun_only(resolve_apply, 2).unwrap(), true);
}

#[cfg(target_arch = "aarch64")]
fn apply_case(emit: impl FnOnce(&mut BeamModuleAssembler), tail: bool) {
    let mut asm = BeamModuleAssembler::new();
    asm.emit_i_func_label(1).unwrap();
    asm.emit_enter_frame().unwrap();
    if tail {
        asm.call(4).unwrap();
        asm.return_().unwrap();
        asm.emit_i_func_label(4).unwrap();
        asm.emit_enter_frame().unwrap();
        emit(&mut asm);
    } else {
        emit(&mut asm);
        asm.return_().unwrap();
    }
    asm.emit_i_func_label(2).unwrap();
    asm.emit_enter_frame().unwrap();
    asm.emit_raw(|e| e.mov_const(Gpr::x(25), tagged(55)))
        .unwrap();
    asm.return_().unwrap();
    let module = asm.finalize().unwrap();
    APPLY_TARGET.store(module.entries[&2] as usize, Ordering::Release);
    assert_eq!(
        execute(&module, 1, ProcessHeader::default(), [tagged(0), 1, 0]).0,
        tagged(55)
    );
}

#[cfg(not(target_arch = "aarch64"))]
#[test]
fn native_ops_require_aarch64() {
    let _: Option<ApplyResolver> = None;
}
