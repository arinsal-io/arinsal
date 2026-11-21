//! Raw code-table slots with ERTS-style grace-period reclamation.
//!
//! Port of code_ix.h (`erts_active_code_ix`), code_ix.c (`erts_commit_staging_code_ix`), and
//! erl_process.c (`erts_schedule_thr_prgr_later_cleanup_op`), OTP-29.1.1.

use std::sync::Arc;
use std::sync::atomic::{AtomicPtr, Ordering};

use arinsal_sched::{ErtsThrPrgrLaterOp, Scheduler};

use crate::Process;

// SAFETY: erts treats `ErtsCodeBarrier` as a plain C struct. The later-op node is enqueued
// only while the code-modification permission (or the NIF load) serializes reuse of the same
// barrier; `func` may run on another scheduler after unlink.
unsafe impl Send for super::ErtsCodeBarrier {}
// SAFETY: as for `Send`: shared access is the same serialized reuse of one barrier node.
unsafe impl Sync for super::ErtsCodeBarrier {}

/// One ownership reference to a replaced slot value, released after thread progress.
pub(crate) struct RetireOp {
    later_op: ErtsThrPrgrLaterOp,
    ptr: *const (),
    release: fn(*const ()),
}

// SAFETY: `ptr` is an owned `Arc` reference transferred from a slot, and `release` only drops it.
unsafe impl Send for RetireOp {}

impl RetireOp {
    /// Schedule `release` after thread progress, with the node in this object.
    // Port of erts/emulator/beam/code_ix.c (`erts_schedule_code_barrier` /
    // `erts_schedule_thr_prgr_later_op` of a caller-owned `ErtsThrPrgrLaterOp`), OTP-29.1.1.
    pub(crate) fn schedule(self, scheduler: &Scheduler<Process>) {
        let ptr = Box::into_raw(Box::new(self));
        scheduler.erts_schedule_thr_prgr_later_op(
            run_retire,
            ptr.cast(),
            // SAFETY: `ptr` is the live box; `run_retire` takes it back after unlink.
            unsafe { &raw mut (*ptr).later_op },
        );
    }

    /// Release the slot's former ownership reference.
    pub(crate) fn release(mut self) {
        let ptr = std::mem::replace(&mut self.ptr, std::ptr::null());
        if ptr.is_null() {
            return;
        }
        (self.release)(ptr);
    }
}

impl Drop for RetireOp {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            (self.release)(self.ptr);
        }
    }
}

/// An immutable `Arc` value published through one atomic code-index slot.
pub(crate) struct RawSlot<T> {
    ptr: AtomicPtr<T>,
}

impl<T> RawSlot<T> {
    /// Create a slot owning `value`.
    pub(crate) fn new(value: Arc<T>) -> Self {
        Self {
            ptr: AtomicPtr::new(Arc::into_raw(value).cast_mut()),
        }
    }

    /// Read an index-selected table like ERTS `module_tables[ix]`, `bccix[ix]`, and `r[ix]`:
    /// one acquire load and a plain borrow.
    ///
    /// The caller must run on a thread covered by the slot's thread-progress domain, or ensure
    /// that no concurrent publisher can retire the loaded value until `read` returns.
    #[inline(always)]
    pub(crate) fn read<R>(&self, read: impl FnOnce(&T) -> R) -> R {
        let ptr = self.ptr.load(Ordering::Acquire);
        assert!(!ptr.is_null(), "code table slot is empty");
        // SAFETY: publication transfers an Arc ownership reference to the slot. Replaced values
        // are released only by a later operation after every covered reader passed a progress
        // point; the returned reference cannot escape this closure.
        read(unsafe { &*ptr })
    }

    /// The published value as erts readers see `module_tables[ix]` / `export_tables[ix]`: a
    /// plain pointer load with no lock, no reference count and no guard.
    ///
    /// The value stays alive while the caller has not passed a thread-progress point since
    /// the load: a replaced value is released only by a thread-progress later operation
    /// ([`RetireOp`]), as erts frees an old code index generation only after
    /// `erts_commit_staging_code_ix` and thread progress.
    // Port of erts/emulator/beam/code_ix.h (erts_active_code_ix) and module.c / export.c
    // (`module_tables[code_ix]`, `export_tables[code_ix]` read without a lock), OTP-29.1.1.
    #[inline(always)]
    pub(crate) fn get(&self) -> &T {
        let ptr = self.ptr.load(Ordering::Acquire);
        assert!(!ptr.is_null(), "code table slot is empty");
        // SAFETY: publication transfers an Arc ownership reference to the slot; a replaced
        // value is released only by a thread-progress later operation, after every reader that
        // loaded it reached a progress point (erts' code index publication rule). Readers do
        // not keep the reference across a scheduler progress point.
        unsafe { &*ptr }
    }

    /// Clone the slot's `Arc` ownership while its table pointer is protected by the caller's
    /// reader lifetime. Used only by non-hot snapshot paths.
    #[inline]
    pub(crate) fn clone_arc(&self) -> Arc<T> {
        let ptr = self.ptr.load(Ordering::Acquire);
        assert!(!ptr.is_null(), "code table slot is empty");
        // SAFETY: the slot's owned Arc remains alive through the same reader lifetime required
        // by `read`, so its strong count can be incremented before constructing the new owner.
        unsafe { Arc::increment_strong_count(ptr) };
        // SAFETY: the preceding increment transfers one new Arc ownership reference to this call.
        unsafe { Arc::from_raw(ptr) }
    }

    /// Publish `value` and transfer the former slot ownership to a later operation.
    pub(crate) fn store(&self, value: Arc<T>) -> Option<RetireOp> {
        let next = Arc::into_raw(value).cast_mut();
        let old = self.ptr.swap(next, Ordering::AcqRel);
        (!old.is_null()).then_some(RetireOp {
            later_op: ErtsThrPrgrLaterOp::new(),
            ptr: old.cast(),
            release: release_arc::<T>,
        })
    }
}

impl<T> Drop for RawSlot<T> {
    fn drop(&mut self) {
        let ptr = self.ptr.swap(std::ptr::null_mut(), Ordering::AcqRel);
        if !ptr.is_null() {
            // SAFETY: dropping the slot means no slot reader can begin; its outstanding readers
            // must already have ended with the owning scope or scheduler.
            release_arc::<T>(ptr.cast());
        }
    }
}

fn release_arc<T>(ptr: *const ()) {
    // SAFETY: callers pass exactly one live Arc ownership reference transferred by `into_raw`.
    drop(unsafe { Arc::from_raw(ptr.cast::<T>()) });
}

fn run_retire(data: *mut ()) {
    // SAFETY: `data` is the `RetireOp` box `RetireOp::schedule` allocated; this later op runs once.
    drop(unsafe { Box::from_raw(data.cast::<RetireOp>()) });
}

/// Drop [`super::EndedStaging`] without committing its ticket.
pub(super) fn disarm_ended_staging(ended: super::EndedStaging) -> u64 {
    let mut this = std::mem::ManuallyDrop::new(ended);
    let ticket = this.ticket;
    // SAFETY: `Drop` for `EndedStaging` is skipped; the `Arc` is dropped here so it is not leaked.
    unsafe { std::ptr::drop_in_place(&mut this.code) };
    ticket
}

/// The live object `erts_schedule_thr_prgr_later_op` stored as `later_data`.
pub(crate) fn later_data<'a, T>(data: *mut ()) -> &'a T {
    debug_assert!(!data.is_null());
    // SAFETY: `data` is the object the later-op caller stored; it stays alive until `func`
    // returns (erts `lop->func(lop->data)`).
    unsafe { &*data.cast() }
}

/// `erts_bin_release` of a `Binary *` stored as later-op `data`.
pub(crate) fn magic_from_later_data(data: *mut ()) -> arinsal_term::MagicBin {
    debug_assert!(!data.is_null());
    // SAFETY: `data` is the magic binary the later-op caller retained; this later op runs once.
    unsafe { arinsal_term::MagicBin::from_raw_held(data.cast()) }
}

/// `ERTS_MAGIC_BIN_DATA` of a live counted magic binary.
pub(crate) fn magic_payload<T: arinsal_term::MagicPayload>(bin: &arinsal_term::MagicBin) -> &T {
    // SAFETY: `bin` holds a live `intern.refc`; the payload sits at `ERTS_MAGIC_BIN_DATA`.
    unsafe { &*arinsal_term::MagicBin::as_ptr(bin) }
        .downcast_ref::<T>()
        .expect("magic later-op payload type")
}

/// Port of erts/emulator/beam/code_ix.c:531 (`schedule_code_barrier_later_op`), OTP-29.1.1.
fn schedule_code_barrier_later_op(barrier: &super::ErtsCodeBarrier) {
    let (func, data, lop, size) = barrier_enqueue_args(barrier);
    let scheduled = if size == 0 {
        arinsal_sched::erts_schedule_thr_prgr_later_op_current::<crate::Process>(func, data, lop)
    } else {
        arinsal_sched::erts_schedule_thr_prgr_later_cleanup_op_current::<crate::Process>(
            func, data, lop, size,
        )
    };
    debug_assert!(
        scheduled,
        "issue_instruction_barrier runs on a normal scheduler (erts enqueue_later_op)"
    );
}

/// Port of erts/emulator/beam/code_ix.c:547 (`issue_instruction_barrier`), OTP-29.1.1.
fn issue_instruction_barrier(barrier: *mut super::ErtsCodeBarrier) {
    arinsal_sched::erts_thr_instruction_barrier();
    debug_assert!(!barrier.is_null());
    // SAFETY: `barrier` is the live `ErtsCodeBarrier` of this code-mod permission / NIF load;
    // `pending_schedulers` is the erts refc of remaining managed threads including this one.
    let pending = unsafe { &*barrier }
        .pending_schedulers
        .fetch_sub(1, Ordering::AcqRel)
        - 1;
    if pending == 0 {
        // SAFETY: last decrement; this thread schedules the later op as erts does.
        schedule_code_barrier_later_op(unsafe { &*barrier });
    }
}

fn issue_instruction_barrier_addr(barrier_addr: usize) {
    issue_instruction_barrier(barrier_addr as *mut super::ErtsCodeBarrier);
}

/// Port of erts/emulator/beam/code_ix.c:564 (`erts_schedule_code_barrier_cleanup`), OTP-29.1.1.
pub(super) fn erts_schedule_code_barrier_cleanup_on_scheduler(
    scheduler: &arinsal_sched::Scheduler<crate::Process>,
    barrier: &super::ErtsCodeBarrier,
    later_function: fn(*mut ()),
    later_data: *mut (),
    size: usize,
) {
    fill_code_barrier(barrier, later_function, later_data, size);
    let no_schedulers = scheduler.scheduler_count() as i32;
    barrier
        .pending_schedulers
        .store(no_schedulers, Ordering::Release);
    let barrier_addr = barrier as *const super::ErtsCodeBarrier as usize;
    scheduler.erts_schedule_multi_misc_aux_work_tids(
        true,
        1,
        scheduler.scheduler_count(),
        move || issue_instruction_barrier_addr(barrier_addr),
    );
    issue_instruction_barrier_addr(barrier_addr);
}

/// [`erts_schedule_code_barrier_cleanup_on_scheduler`] from `RunCtx`.
pub(super) fn erts_schedule_code_barrier_cleanup_from_ctx(
    ctx: &mut arinsal_sched::RunCtx<'_, crate::Process>,
    barrier: &super::ErtsCodeBarrier,
    later_function: fn(*mut ()),
    later_data: *mut (),
    size: usize,
) {
    fill_code_barrier(barrier, later_function, later_data, size);
    let no_schedulers = ctx.scheduler_count() as i32;
    barrier
        .pending_schedulers
        .store(no_schedulers, Ordering::Release);
    let barrier_addr = barrier as *const super::ErtsCodeBarrier as usize;
    ctx.erts_schedule_multi_misc_aux_work_tids(true, 1, ctx.scheduler_count(), move || {
        issue_instruction_barrier_addr(barrier_addr)
    });
    issue_instruction_barrier_addr(barrier_addr);
}

fn fill_code_barrier(
    barrier: &super::ErtsCodeBarrier,
    later_function: fn(*mut ()),
    later_data: *mut (),
    size: usize,
) {
    let ptr = barrier as *const super::ErtsCodeBarrier as *mut super::ErtsCodeBarrier;
    // SAFETY: the caller owns `barrier` for the duration of this later op; erts writes the
    // same fields from `erts_schedule_code_barrier_cleanup` before enqueue.
    unsafe {
        (*ptr).later_function = Some(later_function);
        (*ptr).later_data = later_data;
        (*ptr).size = size;
    }
}

fn barrier_enqueue_args(
    barrier: &super::ErtsCodeBarrier,
) -> (
    fn(*mut ()),
    *mut (),
    *mut arinsal_sched::ErtsThrPrgrLaterOp,
    usize,
) {
    (
        barrier
            .later_function
            .expect("fill_code_barrier stored later_function"),
        barrier.later_data,
        barrier.later_op.as_list_node(),
        barrier.size,
    )
}
