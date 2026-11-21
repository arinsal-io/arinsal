#![cfg(target_arch = "aarch64")]

use core::ffi::c_void;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};

use arinsal_a64::enc::Gpr;
use arinsal_beamasm::{
    ErtsMessage, ExitReason, ProcessHeader, SchedulerRegisters, enter_native,
    module::{ArgVal, BeamModuleAssembler, FinalizedModule},
    receive::ReceiveHooks,
    receive_frag::{MsgOffsets, ReceiveFragments},
    rt::process_header_mut,
    yield_frag::YieldFragments,
};

extern "C" fn unreachable_gc() {
    unreachable!("no receive case collects")
}

fn fragments() -> &'static ReceiveFragments {
    static FRAGMENTS: OnceLock<(YieldFragments, ReceiveFragments)> = OnceLock::new();
    &FRAGMENTS
        .get_or_init(|| {
            // No case collects: `garbage_collect` is never entered.
            let yields = YieldFragments::new(unreachable_gc as *const () as usize, 0).unwrap();
            let receive = ReceiveFragments::new(
                receive_helper,
                decode_dist,
                wait,
                wait,
                yields.context_switch(),
                MsgOffsets {
                    sig_qs_save: std::mem::offset_of!(TestProcess, save) as u32,
                    message_term: 8,
                    state: 0,
                },
            )
            .unwrap();
            (yields, receive)
        })
        .1
}

/// A process block with `sig_qs.save` after the native prefix.
#[repr(C)]
struct TestProcess {
    header: ProcessHeader,
    /// `sig_qs.save`: this thread's [`SAVE_FIELD`].
    save: *const AtomicU64,
}

thread_local! {
    /// The `next` field `sig_qs.save` names: the address of a message node `[next, term]`, or 0
    /// at the end of the queue.
    static SAVE_FIELD: AtomicU64 = const { AtomicU64::new(0) };
}

/// A queue of message nodes `[next, term]` with the save pointer at the first.
fn queue(terms: &[u64]) -> TestProcess {
    let mut next = 0;
    for &term in terms.iter().rev() {
        let node: &'static [AtomicU64; 2] =
            Box::leak(Box::new([AtomicU64::new(next), AtomicU64::new(term)]));
        NODES.with(|nodes| nodes.borrow_mut().push(node));
        next = std::ptr::from_ref(node).expose_provenance() as u64;
    }
    SAVE_FIELD.with(|field| field.store(next, Ordering::Relaxed));
    TestProcess {
        header: ProcessHeader {
            fcalls: 10,
            ..ProcessHeader::default()
        },
        save: SAVE_FIELD.with(std::ptr::from_ref),
    }
}

/// The node at the save pointer.
fn save_node() -> Option<&'static [AtomicU64; 2]> {
    let address = SAVE_FIELD.with(|field| field.load(Ordering::Relaxed));
    (address != 0).then(|| node_ref(std::ptr::with_exposed_provenance(address as usize)))
}

fn node_ref(node: *const [AtomicU64; 2]) -> &'static [AtomicU64; 2] {
    let nodes = NODES.with(|nodes| nodes.borrow().clone());
    nodes
        .into_iter()
        .find(|known| std::ptr::eq(*known, node))
        .expect("a node of the queue")
}

thread_local! {
    static NODES: std::cell::RefCell<Vec<&'static [AtomicU64; 2]>> =
        const { std::cell::RefCell::new(Vec::new()) };
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
        header.exc.fvalue = marker;
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

/// The receive helper of an empty queue: no message, no reductions, on to the wait.
extern "C" fn receive_helper(
    _: *mut ProcessHeader,
    _: i32,
    _: i32,
    msgpp: *mut u64,
    get_outp: *mut i32,
) -> i32 {
    // SAFETY: the fragment passes the addresses of TMP_MEM2q and TMP_MEM3q.
    unsafe {
        msgpp.write(0);
        get_outp.write(0);
    }
    0
}

/// The term `decode_dist` gives an external message (term THE_NON_VALUE, 0).
const DECODED: u64 = 0x404;

thread_local! {
    /// External messages `decode_dist` still treats as corrupt.
    static CORRUPT: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}

/// `beam_jit_decode_dist`: writes [`DECODED`] as the term, or unlinks a corrupt message (the
/// save pointer moves to the next node) and returns NULL.
extern "C" fn decode_dist(_: *mut ProcessHeader, msgp: *mut ErtsMessage) -> *mut ErtsMessage {
    let node = node_ref(msgp.cast::<[AtomicU64; 2]>());
    assert_eq!(
        node[1].load(Ordering::Relaxed),
        0,
        "only external messages are decoded"
    );
    if CORRUPT.with(|corrupt| corrupt.replace(corrupt.get().saturating_sub(1))) > 0 {
        let next = node[0].load(Ordering::Relaxed);
        SAVE_FIELD.with(|field| field.store(next, Ordering::Relaxed));
        return std::ptr::null_mut();
    }
    node[1].store(DECODED, Ordering::Relaxed);
    msgp
}

/// Records the term of the message it removes in `fvalue`.
extern "C" fn remove(
    process: *mut ProcessHeader,
    reductions: i32,
    _htop: *mut u64,
    _e: *mut u64,
    _code_ix: u32,
) -> i32 {
    let term = save_node().expect("a message at the save pointer")[1].load(Ordering::Relaxed);
    process_header_mut(process, |header| {
        header.exc.fvalue = term;
        reductions - 1
    })
}

/// `erts_msgq_set_save_next`.
extern "C" fn save_next(_: *mut ProcessHeader) {
    let next = save_node().expect("a message at the save pointer")[0].load(Ordering::Relaxed);
    SAVE_FIELD.with(|field| field.store(next, Ordering::Relaxed));
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

fn run(module: &FinalizedModule, label: u32, process: &mut TestProcess) -> ExitReason {
    let header = &mut process.header;
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
    let mut process = queue(&[0x101]);
    assert_eq!(run(&module, 1, &mut process), ExitReason::Returned);
    assert_eq!(process.header.exc.fvalue, 0x101);
}

fn first_message_module() -> FinalizedModule {
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
    asm.finalize().unwrap()
}

/// An external message (term THE_NON_VALUE) is decoded by `beam_jit_decode_dist` before the
/// receive sees it, for ten reductions.
// Port of erts/emulator/beam/jit/arm/instr_msg.cpp (emit_i_loop_rec_shared,
// check_is_distributed), OTP-29.1.1.
#[cfg(target_arch = "aarch64")]
#[test]
fn native_decodes_external_message() {
    let module = first_message_module();
    let mut process = queue(&[0]);
    assert_eq!(run(&module, 1, &mut process), ExitReason::Returned);
    assert_eq!(process.header.exc.fvalue, DECODED);
    // 10 for the decode, 1 for the removal.
    assert_eq!(process.header.fcalls, 10 - 10 - 1);
}

/// A corrupt external message is removed by `beam_jit_decode_dist` and the loop restarts at the
/// next message.
#[cfg(target_arch = "aarch64")]
#[test]
fn native_restarts_after_corrupt_external_message() {
    let module = first_message_module();
    let mut process = queue(&[0, 0x505]);
    process.header.fcalls = 20;
    CORRUPT.with(|corrupt| corrupt.set(1));
    assert_eq!(run(&module, 1, &mut process), ExitReason::Returned);
    assert_eq!(process.header.exc.fvalue, 0x505);
    assert_eq!(process.header.fcalls, 20 - 10 - 1);
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
    let mut process = queue(&[0x101, 0x202]);
    assert_eq!(run(&module, 10, &mut process), ExitReason::Returned);
    assert_eq!(process.header.exc.fvalue, 0x202);
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
    let mut process = queue(&[]);
    assert_eq!(run(&module, 20, &mut process), ExitReason::Yield);
    assert_eq!(process.header.i, module.entries[&20].cast());
    // A message arrives at the save pointer.
    let arrived = queue(&[0x303]);
    assert_eq!(arrived.save, process.save);
    assert_eq!(run(&module, 20, &mut process), ExitReason::Returned);
    assert_eq!(process.header.exc.fvalue, 0x303);
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
    let mut process = queue(&[]);
    assert_eq!(run(&module, 30, &mut process), ExitReason::Returned);
    assert_eq!(process.header.arity, 1, "timeout branch executed");
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
    let mut process = queue(&[]);
    process.header.arity = 4;
    assert_eq!(run(&module, 40, &mut process), ExitReason::Returned);
    assert_eq!(process.header.exc.fvalue, 0x551);
    assert_eq!(process.header.arity, 4);
    assert_eq!(process.header.current, 7usize as *const c_void);
}

#[cfg(not(target_arch = "aarch64"))]
#[test]
fn native_first_message() {
    assert_eq!(core::mem::size_of::<usize>(), 8);
}
