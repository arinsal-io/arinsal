//! Intrusive later-op list: caller-owned nodes, first/last/list_len.
//!
//! Port of erts/emulator/beam/erl_thr_progress.h (`ErtsThrPrgrLaterOp`) and
//! erl_process.c (`enqueue_later_op`, `handle_thr_prgr_later_op`), OTP-29.1.1.
//! Every `unsafe` of the later-op links lives here.

use std::cell::UnsafeCell;
use std::ptr;
use std::sync::atomic::{AtomicPtr, Ordering};

thread_local! {
    /// Port of erts/emulator/beam/erl_threads.h (`erts_tse_fetch` / `ethr_get_ts_event`).
    static TSE: super::ThreadEvent = super::ThreadEvent::new();
}

/// Port of erts/emulator/beam/erl_threads.h (`erts_tse_fetch`), OTP-29.1.1.
///
/// The thread-local `erts_tse` lives until thread exit (`ethr_get_ts_event`).
pub(crate) fn erts_tse_fetch() -> &'static super::ThreadEvent {
    TSE.with(|event| {
        let p = ptr::from_ref(event);
        // SAFETY: `TSE` is this thread's `erts_tse`; erts keeps that object until the
        // thread is gone, so a `'static` borrow is the fetch's lifetime.
        unsafe { &*p }
    })
}

/// Port of erts/emulator/beam/erl_threads.h (`erts_tse_reset`), OTP-29.1.1.
pub(crate) fn erts_tse_reset(event: &super::ThreadEvent) {
    event.reset();
}

/// Port of erts/emulator/beam/erl_threads.h (`erts_tse_set`), OTP-29.1.1.
pub(crate) fn erts_tse_set(event: &super::ThreadEvent) {
    event.signal();
}

/// Port of erts/emulator/beam/erl_threads.h (`erts_tse_wait`), OTP-29.1.1.
pub(crate) fn erts_tse_wait(event: &super::ThreadEvent) {
    event.wait();
}

/// Port of erts/emulator/beam/erl_threads.h (`erts_tse_return`), OTP-29.1.1: the thread-local
/// event stays with the thread, as `ethr_leave_ts_event` of a fetch from `ethr_get_ts_event`.
pub(crate) fn erts_tse_return(_event: &super::ThreadEvent) {}

/// `intrnl->misc.data.blocker_event` load of a possibly-null tse.
pub(crate) fn blocker_event_load(
    slot: &AtomicPtr<super::ThreadEvent>,
) -> Option<&'static super::ThreadEvent> {
    tse_from_ptr(slot.load(Ordering::Relaxed))
}

/// `erts_atomic_set_nob(&intrnl->misc.data.blocker_event, event)`.
pub(crate) fn blocker_event_store(
    slot: &AtomicPtr<super::ThreadEvent>,
    event: &super::ThreadEvent,
) {
    slot.store(ptr::from_ref(event).cast_mut(), Ordering::Relaxed);
}

/// `erts_atomic_xchg` / read-and-clear of `blocker_event` in `erts_thr_progress_unblock`.
pub(crate) fn blocker_event_take(
    slot: &AtomicPtr<super::ThreadEvent>,
) -> Option<&'static super::ThreadEvent> {
    tse_from_ptr(slot.swap(ptr::null_mut(), Ordering::Relaxed))
}

fn tse_from_ptr(event: *mut super::ThreadEvent) -> Option<&'static super::ThreadEvent> {
    if event.is_null() {
        None
    } else {
        // SAFETY: stored by `blocker_event_store` from `erts_tse_fetch`; live until take.
        Some(unsafe { &*event })
    }
}

/// `esdp->aux_work_data` later-op fields: only the owning scheduler thread mutates them.
///
/// `UnsafeCell` is the erts `awdp` pointer: `&self` on the owning `esdp` yields `&mut` of
/// the inline later-op state.
#[expect(clippy::mut_from_ref)]
pub(crate) fn aux_work_later_mut(
    later: &UnsafeCell<super::AuxWorkLater>,
) -> &mut super::AuxWorkLater {
    // SAFETY: `later` is the inline `ErtsAuxWorkData` cell; the scheduler thread that owns
    // this `esdp` is the only mutator (`enqueue_later_op` asserts `esdp && !dirty`).
    unsafe { &mut *later.get() }
}

/// Shared read of the owning scheduler's later-op list (`later_op_ready`).
pub(crate) fn aux_work_later_ref(later: &UnsafeCell<super::AuxWorkLater>) -> &super::AuxWorkLater {
    // SAFETY: as `aux_work_later_mut`; readers are that same scheduler thread.
    unsafe { &*later.get() }
}

/// Port of erts/emulator/beam/erl_threads.h (`ERTS_THR_INSTRUCTION_BARRIER` /
/// `ETHR_INSTRUCTION_BARRIER`), OTP-29.1.1.
pub(crate) fn instruction_barrier() {
    #[cfg(target_arch = "aarch64")]
    {
        // SAFETY: `isb sy` is ETHR_INSTRUCTION_BARRIER on aarch64; it only serializes
        // instruction fetch on this thread.
        unsafe {
            core::arch::asm!("isb sy", options(nostack, preserves_flags));
        }
    }
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: `cpuid` with leaf 0 is ETHR_INSTRUCTION_BARRIER on x86_64; it serializes
        // instruction fetch. The intrinsic saves/restores rbx for LLVM.
        // `__cpuid` is a safe wrapper around the instruction; leaf 0 is ETHR_INSTRUCTION_BARRIER.
        let _ = core::arch::x86_64::__cpuid(0);
    }
}

/// A caller-owned later-op node (`ErtsThrPrgrLaterOp`).
///
/// Port of erts/emulator/beam/erl_thr_progress.h (`struct ErtsThrPrgrLaterOp_`), OTP-29.1.1.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ErtsThrPrgrLaterOp {
    /// `later`: the thread-progress value this op waits for.
    pub later: u64,
    /// `func`: runs `data` once progress has reached `later`.
    pub func: Option<fn(*mut ())>,
    /// `data`: the argument of `func`, usually the object that owns this node.
    pub data: *mut (),
    /// `next`: intrusive singly-linked list, owned by `ErtsAuxWorkData.later_op`.
    pub next: *mut ErtsThrPrgrLaterOp,
}

impl ErtsThrPrgrLaterOp {
    /// An unlinked node. `enqueue_later_op` fills every field.
    pub const fn new() -> Self {
        Self {
            later: 0,
            func: None,
            data: ptr::null_mut(),
            next: ptr::null_mut(),
        }
    }

    /// Address of this caller-owned node for `enqueue_later_op` (`&lop` in erts).
    pub fn as_list_node(&self) -> *mut Self {
        ptr::from_ref(self).cast_mut()
    }
}

impl Default for ErtsThrPrgrLaterOp {
    fn default() -> Self {
        Self::new()
    }
}

// SAFETY: erts treats the node as a plain C struct. The enqueueing thread owns it until
// `handle_thr_prgr_later_op` unlinks it and calls `func`; `func` may free the object that
// contains the node. The list is touched only by its scheduler.
unsafe impl Send for ErtsThrPrgrLaterOp {}
// SAFETY: as for `Send`: shared reads of an enqueued node are `later`/`func`/`data`/`next`
// while the node sits in a list the owner has not yet run.
unsafe impl Sync for ErtsThrPrgrLaterOp {}

/// `awdp->later_op.{first, last, list_len}`.
///
/// Port of erts/emulator/beam/erl_process.h (`ErtsAuxWorkData.later_op`), OTP-29.1.1.
pub(crate) struct LaterOpList {
    pub(crate) first: *mut ErtsThrPrgrLaterOp,
    pub(crate) last: *mut ErtsThrPrgrLaterOp,
    pub(crate) list_len: usize,
}

impl LaterOpList {
    pub(crate) const fn empty() -> Self {
        Self {
            first: ptr::null_mut(),
            last: ptr::null_mut(),
            list_len: 0,
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.first.is_null()
    }
}

impl Default for LaterOpList {
    fn default() -> Self {
        Self::empty()
    }
}

/// Result of looking at `later_op.first` the way `handle_thr_prgr_later_op` does.
pub(crate) enum PopReady {
    /// `first` is null.
    Empty,
    /// `!erts_thr_progress_has_reached_this(current, first->later)`.
    NotReached,
    /// Unlinked `first`; the caller runs it (and may free the node).
    Ready(LaterOpExec),
}

/// Result of draining later operations from `ErtsAuxWorkData`.
pub(crate) enum LaterOpHandle {
    /// The drain reached its limit and more nodes remain.
    More,
    /// The first node waits for a later progress value.
    Waiting,
    /// The list is empty.
    Empty,
}

/// An unlinked node whose `func` has not run yet.
pub(crate) struct LaterOpExec {
    lop: *mut ErtsThrPrgrLaterOp,
}

impl LaterOpExec {
    /// Port of `handle_thr_prgr_later_op`: `lop->func(lop->data)` after unlink.
    pub(crate) fn run(self) {
        exec(self.lop);
    }
}

/// Port of `handle_thr_prgr_later_op` without retaining a Rust borrow across `lop->func`.
/// The C callback may enqueue another operation on this same scheduler's list.
pub(crate) fn handle_thr_prgr_later_op(
    later: &UnsafeCell<super::AuxWorkLater>,
    current: u64,
    minimum: usize,
    cleanup_threshold: usize,
    has_reached_this: fn(u64, u64) -> bool,
) -> LaterOpHandle {
    let later = later.get();
    // SAFETY: the owning scheduler thread is the only mutator of its inline AuxWorkData. The
    // pointer is kept raw across callbacks so an op may enqueue on this list after unlink.
    let limit = unsafe { (*later).later_op.list.list_len / 8 + minimum };
    for _ in 0..limit {
        // SAFETY: `later` still names the scheduler's live AuxWorkData; `pop_ready` unlinks
        // the first node before returning and no reference to the list escapes this statement.
        let next = unsafe { pop_ready(&mut (*later).later_op.list, current, has_reached_this) };
        match next {
            PopReady::Ready(op) => {
                op.run();
                // SAFETY: the callback may have enqueued more nodes, so inspect the live list
                // only after it returns. The scheduler thread remains the sole mutator.
                if unsafe { (*later).later_op.list.is_empty() } {
                    // SAFETY: `later` is still the scheduler's live AuxWorkData.
                    unsafe { (*later).later_op.size = cleanup_threshold };
                    return LaterOpHandle::Empty;
                }
            }
            PopReady::NotReached => return LaterOpHandle::Waiting,
            PopReady::Empty => return LaterOpHandle::Empty,
        }
    }
    LaterOpHandle::More
}

/// Reset `current_thr_prgr` in the scheduler-owned `ErtsAuxWorkData`.
pub(crate) fn aux_work_later_current_reset(later: &UnsafeCell<super::AuxWorkLater>) {
    // SAFETY: only the scheduler that owns this inline AuxWorkData resets its cached value.
    unsafe { (*later.get()).current_thr_prgr = super::VAL_WAITING }
}

/// Read and cache `current_thr_prgr` in the scheduler-owned `ErtsAuxWorkData`.
pub(crate) fn aux_work_later_current(later: &UnsafeCell<super::AuxWorkLater>, current: u64) -> u64 {
    // SAFETY: only the scheduler that owns this inline AuxWorkData accesses its cached value.
    unsafe {
        let later = &mut *later.get();
        if later.current_thr_prgr == super::VAL_WAITING {
            later.current_thr_prgr = current;
        }
        later.current_thr_prgr
    }
}

/// Port of erts/emulator/beam/erl_process.c (`enqueue_later_op` list linking), OTP-29.1.1.
pub(crate) fn enqueue(
    list: &mut LaterOpList,
    later: u64,
    func: fn(*mut ()),
    data: *mut (),
    lop: &mut ErtsThrPrgrLaterOp,
) {
    lop.func = Some(func);
    lop.data = data;
    lop.later = later;
    lop.next = ptr::null_mut();
    let lop = ptr::from_mut(lop);
    if list.last.is_null() {
        list.first = lop;
    } else {
        // SAFETY: `last` is a live caller-owned node still in this list.
        unsafe { (*list.last).next = lop };
    }
    list.last = lop;
    list.list_len += 1;
}

/// Port of erts/emulator/beam/erl_process.c (`handle_thr_prgr_later_op` first-node test
/// and unlink), OTP-29.1.1.
pub(crate) fn pop_ready(
    list: &mut LaterOpList,
    current: u64,
    has_reached_this: impl Fn(u64, u64) -> bool,
) -> PopReady {
    if list.first.is_null() {
        return PopReady::Empty;
    }
    // SAFETY: `first` is a live caller-owned node still in this list.
    let later = unsafe { (*list.first).later };
    if !has_reached_this(current, later) {
        return PopReady::NotReached;
    }
    PopReady::Ready(LaterOpExec {
        lop: unlink_first(list),
    })
}

/// The `later` of `first`, if any (`handle_thr_prgr_later_op` / `later_op_ready`).
pub(crate) fn first_later(list: &LaterOpList) -> Option<u64> {
    if list.first.is_null() {
        return None;
    }
    // SAFETY: `first` is a live node in this list.
    Some(unsafe { (*list.first).later })
}

/// Port of the `awdp->later_op.first = lop->next` unlink in `handle_thr_prgr_later_op`.
fn unlink_first(list: &mut LaterOpList) -> *mut ErtsThrPrgrLaterOp {
    debug_assert!(!list.first.is_null());
    let lop = list.first;
    // SAFETY: `first` is a live node; `next` is either null or the next live node.
    unsafe {
        list.first = (*lop).next;
        if list.first.is_null() {
            list.last = ptr::null_mut();
        }
        list.list_len -= 1;
    }
    lop
}

/// Load `func`/`data` then call, so `func` may free the node (erts `lop->func(lop->data)`).
fn exec(lop: *mut ErtsThrPrgrLaterOp) {
    debug_assert!(!lop.is_null());
    // SAFETY: `lop` was just unlinked and is still the live caller-owned node. `func` and
    // `data` are copied before the call; `func` may free the object that contains `lop`.
    unsafe {
        let func = (*lop).func;
        let data = (*lop).data;
        func.expect("enqueue_later_op filled func")(data);
    }
}

/// Arguments of `enqueue_later_op` moved to a normal scheduler via
/// `erts_schedule_misc_aux_work` (erl_process.c: dirty / non-scheduler callers).
#[derive(Debug)]
pub(crate) struct LaterOpArgs {
    pub func: fn(*mut ()),
    pub data: *mut (),
    pub lop: *mut ErtsThrPrgrLaterOp,
    pub size: Option<usize>,
}

// SAFETY: the pointers are the same caller-owned node and `data` erts passes through
// `erts_schedule_misc_aux_work` onto a normal scheduler, which then enqueues them.
unsafe impl Send for LaterOpArgs {}

impl LaterOpArgs {
    /// Link this deferred node into the scheduler's later-op list (`enqueue_later_op`).
    pub(crate) fn enqueue(self, list: &mut LaterOpList, later: u64) {
        debug_assert!(!self.lop.is_null());
        // SAFETY: `lop` is the live caller-owned node stored when this `LaterOpArgs` was built.
        enqueue(list, later, self.func, self.data, unsafe { &mut *self.lop });
    }
}
