use core::ffi::c_void;
use std::sync::OnceLock;

use arinsal_a64::enc::Gpr;
use arinsal_beamasm::{
    ExitReason, ProcessHeader, SchedulerRegisters, enter_native,
    module::{ArgVal, BeamModuleAssembler, FinalizedModule},
    receive::ReceiveHooks,
    receive_frag::ReceiveFragments,
    rt::process_header_mut,
    yield_frag::YieldFragments,
};

fn fragments() -> &'static ReceiveFragments {
    static FRAGMENTS: OnceLock<(YieldFragments, ReceiveFragments)> = OnceLock::new();
    &FRAGMENTS
        .get_or_init(|| {
            let yields = YieldFragments::new().unwrap();
            let receive =
                ReceiveFragments::new(peek, wait, wait, yields.context_switch(), None).unwrap();
            (yields, receive)
        })
        .1
}

fn hooks() -> ReceiveHooks {
    ReceiveHooks {
        recv_marker_reserve: reserve,
        recv_marker_bind: bind,
        recv_marker_clear: clear,
        recv_marker_use: use_marker,
        loop_rec_shared: fragments().loop_rec_shared(),
        remove_message: remove,
        set_save_next: save_next,
        wait_unlocked_shared: fragments().wait_unlocked_shared(),
        wait_locked_shared: fragments().wait_locked_shared(),
        take_receive_lock: no_op,
        wait_timeout,
        timeout_locked: no_op,
        timeout,
    }
}

extern "C" fn reserve(process: *mut ProcessHeader) -> u64 {
    process_header_mut(process, |_| 0x551)
}

extern "C" fn bind(process: *mut ProcessHeader, marker: u64, reference: u64) {
    process_header_mut(process, |header| {
        header.fvalue = marker;
        header.current = reference as usize as *const c_void;
    });
}

extern "C" fn clear(process: *mut ProcessHeader, reference: u64) {
    process_header_mut(process, |header| {
        header.current = reference as usize as *const c_void;
    });
}

extern "C" fn use_marker(process: *mut ProcessHeader, reference: u64) {
    process_header_mut(process, |header| {
        header.current = reference as usize as *const c_void;
    });
}

extern "C" fn peek(process: *mut ProcessHeader) -> u64 {
    process_header_mut(process, |header| match header.arity {
        0 => 0x101,
        1 => 0x202,
        _ => 0,
    })
}

extern "C" fn remove(process: *mut ProcessHeader, reductions: i32, _code_ix: usize) -> i32 {
    process_header_mut(process, |header| {
        header.fvalue = u64::from(header.arity);
        reductions - 1
    })
}

extern "C" fn save_next(process: *mut ProcessHeader) {
    process_header_mut(process, |header| header.arity += 1);
}

extern "C" fn wait(process: *mut ProcessHeader, destination: usize) {
    process_header_mut(process, |header| {
        header.i = destination as *const c_void;
    });
}

extern "C" fn no_op(_process: *mut ProcessHeader) {}

extern "C" fn wait_timeout(_process: *mut ProcessHeader, timeout: u64, _next: usize) -> i32 {
    if timeout == 0 { 0 } else { 1 }
}

extern "C" fn timeout(process: *mut ProcessHeader) {
    process_header_mut(process, |header| {
        header.arity = header.arity.wrapping_add(1)
    });
}

fn run(module: &FinalizedModule, label: u32, header: &mut ProcessHeader) -> ExitReason {
    let mut regs = SchedulerRegisters::default();
    if header.stop.is_null() {
        let stack = Box::leak(vec![0u64; 64].into_boxed_slice());
        header.stop = stack.as_mut_ptr().wrapping_add(stack.len());
    }
    enter_native(
        header,
        &mut regs,
        &module.entry(label).expect("entry label"),
    )
}

#[cfg(target_arch = "aarch64")]
#[test]
fn native_first_message() {
    let mut asm = BeamModuleAssembler::new();
    asm.emit_i_func_label(1).unwrap();
    asm.emit_enter_frame().unwrap();
    asm.emit_i_loop_rec(2, hooks()).unwrap();
    asm.emit_remove_message(hooks()).unwrap();
    asm.emit_leave_frame().unwrap();
    asm.emit_raw(|e| {
        e.mov_reg(Gpr::x(0), Gpr::xzr())?;
        e.ret(Gpr::x(30))
    })
    .unwrap();
    asm.emit_i_func_label(2).unwrap();
    let module = asm.finalize().unwrap();
    let mut header = ProcessHeader {
        arity: 0,
        fcalls: 10,
        ..ProcessHeader::default()
    };
    assert_eq!(run(&module, 1, &mut header), ExitReason::Returned);
    assert_eq!(header.fvalue, 0);
}

#[cfg(target_arch = "aarch64")]
#[test]
fn native_skip_then_match() {
    let mut asm = BeamModuleAssembler::new();
    asm.emit_i_func_label(10).unwrap();
    asm.emit_enter_frame().unwrap();
    asm.emit_i_loop_rec(11, hooks()).unwrap();
    asm.emit_loop_rec_end(12, hooks()).unwrap();
    asm.emit_i_func_label(12).unwrap();
    asm.emit_i_loop_rec(13, hooks()).unwrap();
    asm.emit_remove_message(hooks()).unwrap();
    asm.emit_leave_frame().unwrap();
    asm.emit_raw(|e| {
        e.mov_reg(Gpr::x(0), Gpr::xzr())?;
        e.ret(Gpr::x(30))
    })
    .unwrap();
    asm.emit_i_func_label(11).unwrap();
    asm.emit_wait_locked(10, hooks()).unwrap();
    asm.emit_i_func_label(13).unwrap();
    let module = asm.finalize().unwrap();
    let mut header = ProcessHeader {
        arity: 0,
        fcalls: 10,
        ..ProcessHeader::default()
    };
    assert_eq!(run(&module, 10, &mut header), ExitReason::Returned);
    assert_eq!(header.arity, 1);
    assert_eq!(header.fvalue, 1);
}

#[cfg(target_arch = "aarch64")]
#[test]
fn native_wait_suspends_and_resumes() {
    let mut asm = BeamModuleAssembler::new();
    asm.emit_i_func_label(20).unwrap();
    asm.emit_enter_frame().unwrap();
    asm.emit_i_loop_rec(21, hooks()).unwrap();
    asm.emit_remove_message(hooks()).unwrap();
    asm.emit_leave_frame().unwrap();
    asm.emit_raw(|e| {
        e.mov_reg(Gpr::x(0), Gpr::xzr())?;
        e.ret(Gpr::x(30))
    })
    .unwrap();
    asm.emit_i_func_label(21).unwrap();
    asm.emit_wait_locked(20, hooks()).unwrap();
    let module = asm.finalize().unwrap();
    let mut header = ProcessHeader {
        arity: 2,
        fcalls: 10,
        ..ProcessHeader::default()
    };
    assert_eq!(run(&module, 20, &mut header), ExitReason::Yield);
    assert_eq!(header.i, module.entries[&20].cast());
    header.arity = 1;
    assert_eq!(run(&module, 20, &mut header), ExitReason::Returned);
    assert_eq!(header.fvalue, 1);
}

#[cfg(target_arch = "aarch64")]
#[test]
fn native_after_zero_timeout() {
    let mut asm = BeamModuleAssembler::new();
    asm.emit_i_func_label(30).unwrap();
    asm.emit_enter_frame().unwrap();
    asm.emit_wait_timeout_locked(ArgVal::Immediate(0), 31, hooks())
        .unwrap();
    asm.emit_timeout(hooks()).unwrap();
    asm.emit_leave_frame().unwrap();
    asm.emit_raw(|e| {
        e.mov_reg(Gpr::x(0), Gpr::xzr())?;
        e.ret(Gpr::x(30))
    })
    .unwrap();
    asm.emit_i_func_label(31).unwrap();
    let module = asm.finalize().unwrap();
    let mut header = ProcessHeader {
        fcalls: 10,
        ..ProcessHeader::default()
    };
    assert_eq!(run(&module, 30, &mut header), ExitReason::Returned);
    assert_eq!(header.arity, 1, "timeout branch executed");
}

#[cfg(target_arch = "aarch64")]
#[test]
fn native_recv_marker() {
    let mut asm = BeamModuleAssembler::new();
    asm.emit_i_func_label(40).unwrap();
    asm.emit_enter_frame().unwrap();
    asm.emit_recv_marker_reserve(ArgVal::X(0), hooks()).unwrap();
    asm.emit_recv_marker_bind(ArgVal::X(0), ArgVal::Immediate(7), hooks())
        .unwrap();
    asm.emit_recv_marker_clear(ArgVal::Immediate(7), hooks())
        .unwrap();
    asm.emit_recv_marker_use(ArgVal::Immediate(7), hooks())
        .unwrap();
    asm.emit_leave_frame().unwrap();
    asm.emit_raw(|e| {
        e.mov_reg(Gpr::x(0), Gpr::xzr())?;
        e.ret(Gpr::x(30))
    })
    .unwrap();
    let module = asm.finalize().unwrap();
    let mut header = ProcessHeader {
        arity: 4,
        fcalls: 10,
        ..ProcessHeader::default()
    };
    assert_eq!(run(&module, 40, &mut header), ExitReason::Returned);
    assert_eq!(header.fvalue, 0x551);
    assert_eq!(header.arity, 4);
    assert_eq!(header.current, 7usize as *const c_void);
}

#[cfg(not(target_arch = "aarch64"))]
#[test]
fn native_first_message() {
    assert_eq!(core::mem::size_of::<usize>(), 8);
}
