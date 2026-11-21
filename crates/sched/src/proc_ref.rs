//! Process structures: one fix_alloc block per process holding its reference count, and the
//! release of the process table's reference once thread progress has passed.
//!
//! Port of erts/emulator/beam/erl_process.c (alloc_process takes the struct with
//! `erts_alloc(ERTS_ALC_T_PROC)`, erts_free_proc gives it back), erl_process.h
//! (erts_proc_inc_refc, erts_proc_dec_refc on `common.refc`) and erl_ptab.c
//! (erts_ptab_delete_element hands the table's reference to release_process through
//! erts_schedule_thr_prgr_later_cleanup_op), OTP-29.1.1. Every `unsafe` of the process lifetime is
//! in this module.

use super::{Event, Incoming, Pid, ProcShared, Process, SignalMessage, Task};
use crate::ptab_slot::Progress;
use arinsal_alloc::typed::{ErtsAlcType, fix_alloc_payload_at, fix_free_payload_at};
use raw::ProcLockGuard;
use std::any::TypeId;
use std::marker::PhantomData;
use std::mem::{ManuallyDrop, MaybeUninit};
use std::ptr::NonNull;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering, fence};

pub(crate) mod raw;

/// The fix_alloc block of one process: `common.refc` and the process. The owning allocator
/// instance is read from the block's carrier on free, as erts does.
struct ProcessBlock<T: Task> {
    refc: AtomicUsize,
    /// `common.u.release`: the table's later-op node, used after `erts_ptab_delete_element`.
    later_op: crate::thr_progress::ErtsThrPrgrLaterOp,
    process: Process<T>,
}

/// A counted reference to a process (erts `Process *` with a reference taken by
/// erts_proc_inc_refc).
pub(crate) struct ProcRef<T: Task> {
    block: NonNull<ProcessBlock<T>>,
}

// SAFETY: a `ProcRef` is a counted shared reference to a `Process<T>`, like `Arc<Process<T>>`:
// the count is atomic and the process is only reached through `&Process<T>`, which may cross
// threads because `Process<T>` is `Sync` and `Send`.
unsafe impl<T: Task> Send for ProcRef<T> where Process<T>: Send + Sync {}
// SAFETY: as for `Send`: shared access goes through `&Process<T>` only.
unsafe impl<T: Task> Sync for ProcRef<T> where Process<T>: Send + Sync {}

impl<T: Task> ProcRef<T> {
    /// A new process struct with one reference, the caller's, holding the process `build`
    /// returns, written once into the allocated block.
    ///
    /// Port of erts/emulator/beam/erl_process.c (alloc_process: `erts_alloc(ERTS_ALC_T_PROC)`
    /// and `refc` 1), OTP-29.1.1.
    pub(crate) fn new_with<C, R>(
        alloc_ix: Option<usize>,
        prepare: impl FnOnce() -> Option<C>,
        build: impl FnOnce(&C) -> Process<T>,
        init: impl FnOnce(&mut Process<T>, &C) -> R,
    ) -> Option<(Self, R, C)> {
        assert!(
            std::mem::align_of::<ProcessBlock<T>>() <= std::mem::align_of::<u64>(),
            "allocator blocks are word aligned"
        );
        // erts allocates the Process with the scheduler's own allocator instance (`esdp`); a
        // caller that knows it passes it, any other caller looks the thread up.
        let ix = alloc_ix.unwrap_or_else(arinsal_alloc::thread_alloc_ix);
        let payload = fix_alloc_payload_at(
            ix,
            ErtsAlcType::PROC,
            std::mem::size_of::<ProcessBlock<T>>(),
        )
        .expect("process struct allocation");
        let block = NonNull::new(payload.cast::<ProcessBlock<T>>()).expect("allocated block");
        let context = match prepare() {
            Some(context) => context,
            None => {
                let _ = fix_free_payload_at(
                    ErtsAlcType::PROC,
                    payload,
                    std::mem::size_of::<ProcessBlock<T>>(),
                );
                return None;
            }
        };
        // SAFETY: `fix_alloc_at` returned a live, word-aligned block of
        // `size_of::<ProcessBlock<T>>()` bytes that nothing else refers to, and the alignment of
        // `ProcessBlock<T>` is at most a word (asserted above). `prepare` acquires the table lock
        // and reserves the id only after this allocation, matching alloc_process; the process is
        // initialized in the unpublished block and `init` has exclusive access before it escapes.
        let result = unsafe {
            let raw = block.as_ptr();
            (&raw mut (*raw).refc).write(AtomicUsize::new(1));
            (&raw mut (*raw).later_op).write(crate::thr_progress::ErtsThrPrgrLaterOp::new());
            (&raw mut (*raw).process).write(build(&context));
            init(&mut (*raw).process, &context)
        };
        Some((Self { block }, result, context))
    }

    fn block(&self) -> &ProcessBlock<T> {
        // SAFETY: this reference is counted in `refc`, so the block is alive.
        unsafe { self.block.as_ref() }
    }

    /// Give up this value and keep its reference in the returned address, for a process table
    /// slot or a later operation.
    pub(crate) fn into_raw(self) -> *mut () {
        let raw = self.block.as_ptr().cast();
        std::mem::forget(self);
        raw
    }

    /// Take back a reference given up by [`ProcRef::into_raw`].
    ///
    /// # Safety
    ///
    /// `raw` came from `ProcRef::<T>::into_raw` and its reference was not taken back before.
    pub(crate) unsafe fn from_raw(raw: *mut ()) -> Self {
        Self {
            // SAFETY: `into_raw` returned a non-null block address, per the caller's contract.
            block: unsafe { NonNull::new_unchecked(raw.cast()) },
        }
    }

    /// Run `f` on the process in `slot` for a caller that is a managed thread: the slot's
    /// reference is released only once every managed thread passed a progress point, and the
    /// caller passes none while `f` runs, so the block outlives the call. `None` for an empty
    /// slot.
    // Port of erts/emulator/beam/erl_process.h (erts_proc_lookup_raw), OTP-29.1.1.
    pub(crate) fn with_slot_managed<R>(
        slot: &std::sync::atomic::AtomicPtr<()>,
        f: impl FnOnce(&Self) -> R,
    ) -> Option<R> {
        let raw = slot.load(Ordering::Acquire);
        if raw.is_null() {
            return None;
        }
        // SAFETY: `raw` is the address a table slot held; per the contract above the slot's
        // reference outlives this call for a managed thread.
        Some(unsafe { Self::with_borrowed(raw, f) })
    }

    /// Run `f` on the process whose reference a table slot holds, without taking a reference.
    ///
    /// # Safety
    ///
    /// `raw` is the address in a slot that held it under the caller's thread progress delay:
    /// the slot's reference is released only after thread progress, so the block outlives `f`.
    pub(crate) unsafe fn with_borrowed<R>(raw: *mut (), f: impl FnOnce(&Self) -> R) -> R {
        // SAFETY: per the caller's contract the block is alive for the call; `ManuallyDrop`
        // keeps the borrowed value from giving back a reference it does not own.
        let borrowed = ManuallyDrop::new(unsafe { Self::from_raw(raw) });
        f(&borrowed)
    }

    /// Erase the process type, for values that cross the `Task`-generic boundary.
    pub(crate) fn erase(self) -> ErasedProcRef {
        ErasedProcRef {
            raw: self.into_raw(),
            type_id: TypeId::of::<T>(),
            retain: retain_raw::<T>,
            release: release_raw::<T>,
        }
    }

    /// Schedule `release_process` of the table's reference at `raw` after thread progress.
    ///
    /// Port of erts/emulator/beam/erl_ptab.c (`erts_ptab_delete_element`:
    /// `erts_schedule_thr_prgr_later_cleanup_op(release_element, ptab_el, &ptab_el->u.release,
    /// element_size)`), OTP-29.1.1.
    /// `ptab->r.o.element_size` (`sizeof(Process)`).
    pub(crate) const fn element_size() -> usize {
        std::mem::size_of::<ProcessBlock<T>>()
    }
}

impl<T: Task> Clone for ProcRef<T> {
    /// Port of erts/emulator/beam/erl_process.h (erts_proc_inc_refc), OTP-29.1.1.
    fn clone(&self) -> Self {
        self.block().refc.fetch_add(1, Ordering::Relaxed);
        Self { block: self.block }
    }
}

impl<T: Task> Drop for ProcRef<T> {
    /// Port of erts/emulator/beam/erl_process.h (erts_proc_dec_refc frees the struct with
    /// erts_free_proc when the count reaches zero), OTP-29.1.1.
    fn drop(&mut self) {
        if self.block().refc.fetch_sub(1, Ordering::Release) != 1 {
            return;
        }
        fence(Ordering::Acquire);
        // SAFETY: the count reached zero, so this was the last reference: no other thread can
        // reach the block, and the process is dropped exactly once before its block is freed.
        unsafe { std::ptr::drop_in_place(&raw mut (*self.block.as_ptr()).process) };
        let _ = fix_free_payload_at(
            ErtsAlcType::PROC,
            self.block.as_ptr().cast::<u64>(),
            std::mem::size_of::<ProcessBlock<T>>(),
        );
    }
}

impl<T: Task> std::ops::Deref for ProcRef<T> {
    type Target = Process<T>;

    fn deref(&self) -> &Process<T> {
        &self.block().process
    }
}

fn retain_raw<T: Task>(raw: *mut ()) {
    // SAFETY: `raw` belongs to a live `ErasedProcRef` of type `T`, whose reference keeps the
    // block alive while the count is raised.
    unsafe { ProcRef::<T>::with_borrowed(raw, |process| std::mem::forget(process.clone())) };
}

fn release_raw<T: Task>(raw: *mut ()) {
    // SAFETY: `raw` was produced by `ProcRef::<T>::erase` and is released once, by the
    // `ErasedProcRef` that owns it.
    drop(unsafe { ProcRef::<T>::from_raw(raw) });
}

/// A [`ProcRef`] whose process type is not named, as `SpawnedProcess` carries it.
pub(crate) struct ErasedProcRef {
    raw: *mut (),
    type_id: TypeId,
    retain: fn(*mut ()),
    release: fn(*mut ()),
}

impl Clone for ErasedProcRef {
    fn clone(&self) -> Self {
        (self.retain)(self.raw);
        Self {
            raw: self.raw,
            type_id: self.type_id,
            retain: self.retain,
            release: self.release,
        }
    }
}

// SAFETY: it owns one counted reference to a `Process<T>` that is `Send` and `Sync`, and only
// gives it back as a `ProcRef<T>` of the same type.
unsafe impl Send for ErasedProcRef {}
// SAFETY: shared access exposes nothing of the process.
unsafe impl Sync for ErasedProcRef {}

impl ErasedProcRef {
    /// Run `f` on the reference if the process type is `T`.
    pub(crate) fn with_typed<T: Task, R>(&self, f: impl FnOnce(&ProcRef<T>) -> R) -> Option<R> {
        if self.type_id != TypeId::of::<T>() {
            return None;
        }
        // SAFETY: the type matches, and this value owns a counted reference that keeps the
        // block alive for the call.
        Some(unsafe { ProcRef::with_borrowed(self.raw, f) })
    }

    /// The reference as a `ProcRef<T>`, if the process type is `T`.
    pub(crate) fn downcast<T: Task>(self) -> Option<ProcRef<T>> {
        if self.type_id != TypeId::of::<T>() {
            return None;
        }
        let raw = self.raw;
        std::mem::forget(self);
        // SAFETY: the type matches and the reference moves out of this value, which is
        // forgotten so it does not release it.
        Some(unsafe { ProcRef::from_raw(raw) })
    }
}

impl Drop for ErasedProcRef {
    fn drop(&mut self) {
        (self.release)(self.raw);
    }
}

/// What a process's own code reaches without a table lookup: its outer signal queue (erts
/// `sig_inq`), its state flags and receive timer, which live in its own process struct, and
/// the runtime's thread progress domain.
///
/// The probe is held only by the process it points into (set when the process is scheduled,
/// cleared in `delete_process` and at scheduler shutdown), so the struct outlives every access,
/// as erts code reaches `c_p->sig_inq` through `c_p` without a reference count. The progress
/// domain is the runtime's, which outlives its processes.
pub struct SignalProbe<M: SignalMessage> {
    input: NonNull<Incoming<Event<M>>>,
    flags: NonNull<AtomicU32>,
    timer: NonNull<crate::ReceiveTimer>,
    /// The thread progress domain the process's signal buffers are read through.
    progress: NonNull<Progress>,
    /// The process struct itself, for the scheduling fields its own BIFs change
    /// (`process_flag(priority | scheduler | message_queue_data, _)` on `c_p`).
    shared: NonNull<crate::ProcShared<M>>,
}

// SAFETY: the probe only gives shared access to the queue, flags and timer of its own process
// and to the runtime's progress domain; all are shared between threads already (`Incoming` is
// the cross-thread signal queue).
unsafe impl<M: SignalMessage> Send for SignalProbe<M> {}
// SAFETY: as for `Send`: every access is through `&`.
unsafe impl<M: SignalMessage> Sync for SignalProbe<M> {}

impl<M: SignalMessage> SignalProbe<M> {
    /// The probe of `process`, whose runtime's progress domain is `progress`.
    pub(crate) fn of(process: &crate::ProcShared<M>, progress: &Progress) -> Self {
        Self {
            input: NonNull::from(&process.input),
            flags: NonNull::from(&process.exit_flags),
            timer: NonNull::from(&process.rtimer),
            progress: NonNull::from(progress),
            shared: NonNull::from(process),
        }
    }

    /// Sets the process's user priority; it takes effect when the process is next queued.
    // Port of erts/emulator/beam/erl_process.c (erts_set_process_priority on `c_p`),
    // OTP-29.1.1.
    pub fn set_user_priority(&self, priority: crate::Priority) {
        self.field(self.shared).set_user_priority(priority);
    }

    /// Binds the process to the one-based scheduler `scheduler_id` (zero unbinds) and returns
    /// the previous binding, and whether the process runs on another scheduler than the new
    /// binding (the BIF then yields so the process moves).
    // Port of erts/emulator/beam/bif.c (process_flag_2: am_scheduler, erts_bind_runq_proc /
    // erts_set_runq_proc, `erts_proc_sched_data(BIF_P)->run_queue`), OTP-29.1.1.
    pub fn bind_scheduler(&self, scheduler_id: usize) -> (usize, bool) {
        let shared = self.field(self.shared);
        let target = scheduler_id.checked_sub(1).unwrap_or(crate::UNBOUND_WORKER);
        let previous = shared.bound_worker.swap(target, Ordering::AcqRel);
        let previous_id = if previous == crate::UNBOUND_WORKER {
            0
        } else {
            previous + 1
        };
        // `scheduler_id` stores worker + 1; `erts_set_runq_proc` compares run-queue indices.
        let current = shared.scheduler_worker();
        (
            previous_id,
            target != crate::UNBOUND_WORKER && current != target,
        )
    }

    /// Flush and remove the parallel sender buffers of the process's message queue; the
    /// buffer array is released after thread progress.
    // Port of erts/emulator/beam/erl_proc_sig_queue.c:10597
    // (erts_proc_sig_queue_flush_and_deinstall_buffers: erts_schedule_thr_prgr_later_cleanup_op
    // of the buffer array), OTP-29.1.1.
    pub fn flush_and_deinstall_buffers<S: Task>(&self, scheduler: &crate::Scheduler<S>) {
        if let Some(args) = self.input().flush_and_deinstall_buffers() {
            scheduler.schedule_later_op_args(args);
        }
    }

    fn field<U>(&self, field: NonNull<U>) -> &U {
        // SAFETY: every pointer of the probe is to a field of the process that holds the probe,
        // which is alive while the probe is reachable through it, or to the progress domain of
        // the runtime, which outlives that process (see the type's documentation).
        unsafe { field.as_ref() }
    }

    /// The process's outer signal queue.
    pub(crate) fn input(&self) -> &Incoming<Event<M>> {
        self.field(self.input)
    }

    /// The shared process struct this probe points into (`c_p` without the task cell).
    pub(crate) fn shared(&self) -> &crate::ProcShared<M> {
        self.field(self.shared)
    }

    /// The thread progress domain of the runtime the process lives in.
    pub(crate) fn progress(&self) -> &Progress {
        self.field(self.progress)
    }

    /// The process's state flags.
    pub(crate) fn flags(&self) -> &AtomicU32 {
        self.field(self.flags)
    }

    /// The process's receive timer.
    pub(crate) fn timer(&self) -> &crate::ReceiveTimer {
        self.field(self.timer)
    }
}

/// `Process *c_p`: the one pointer to the running process struct, which the scheduler derives
/// from the reference it holds while it holds the main lock. It reaches the task (the first
/// member, guarded by the lock) and the shared part of the same struct, so code given the
/// running process reaches every field of it, as erts code reaches any field from `c_p`. It
/// has no state of its own.
// Port of erts/emulator/beam/erl_process.c:9607 (erts_schedule returns the `Process *` that
// process_main runs, with ERTS_PROC_LOCK_MAIN held), OTP-29.1.1.
pub struct CP<'a, T: Task> {
    p: &'a Process<T>,
    /// The slice holds the main lock: the task is reached only through this handle for `'a`.
    _locked: PhantomData<&'a mut TaskCell<T>>,
}

impl<'a, T: Task> CP<'a, T> {
    /// `c_p` of `process`, whose main lock the caller holds in `locked` for `'a`.
    pub(crate) fn new(
        process: &'a Process<T>,
        locked: &'a mut ProcLockGuard<'_, TaskCell<T>>,
    ) -> Self {
        debug_assert!(std::ptr::eq(
            &**locked,
            process.cell.data_ptr().cast_const()
        ));
        Self {
            p: process,
            _locked: PhantomData,
        }
    }

    /// The task part of the process (the VM's `Process` fields).
    #[inline(always)]
    pub fn task(&mut self) -> &mut T {
        // SAFETY: `p` is a live `&Process<T>` for `'a`, and the cell is reached through its
        // `UnsafeCell` (`data_ptr`), so the shared provenance allows the write. The main
        // lock is held for `'a` and its guard is mutably borrowed by this handle, so no other
        // reference to the cell exists while the returned borrow of `self` lives.
        unsafe { (*self.p.cell.data_ptr()).task_mut() }
    }

    /// The scheduler-side part of the process (`p->state`, signal queues, flags).
    #[inline(always)]
    pub(crate) fn shared(&self) -> &'a ProcShared<T::Message> {
        &self.p.shared
    }

    /// `c_p->common.id`.
    #[inline(always)]
    pub fn pid(&self) -> Pid {
        self.shared().pid
    }

    /// `c_p->state` ([`crate::psflg`]).
    #[inline(always)]
    pub fn state(&self) -> &'a AtomicU32 {
        self.shared().input.state()
    }
}

/// The task of a process, written in place into the process struct after the struct is
/// allocated (erts alloc_process takes the struct, then the fields are set in place).
#[repr(C)]
pub(crate) struct TaskCell<T: Task> {
    /// First, so the task is at the start of the process struct (`c_p`).
    task: MaybeUninit<T>,
    initialized: bool,
}

impl<T: Task> TaskCell<T> {
    /// Offset of the task within the cell (zero: the task is first).
    pub(crate) const TASK_OFFSET: usize = std::mem::offset_of!(TaskCell<T>, task);

    /// A cell whose task [`TaskCell::init_with`] writes next.
    pub(crate) fn uninit() -> Self {
        Self {
            task: MaybeUninit::uninit(),
            initialized: false,
        }
    }

    /// Build the task after slot allocation and write it into its final storage once.
    #[inline(always)]
    pub(crate) fn init_with<E>(
        &mut self,
        pid: crate::Pid,
        init: impl FnOnce() -> Result<T, E>,
    ) -> Result<(), E> {
        assert!(!self.initialized, "a task is written once");
        self.task.write(init()?).init_in_place(pid);
        self.initialized = true;
        Ok(())
    }

    pub(crate) fn task(&self) -> &T {
        assert!(
            self.initialized,
            "a task is written before its process is reachable"
        );
        // SAFETY: `initialized` is set only after `init_with` saw the task written into this
        // slot.
        unsafe { self.task.assume_init_ref() }
    }

    pub(crate) fn task_mut(&mut self) -> &mut T {
        assert!(
            self.initialized,
            "a task is written before its process is reachable"
        );
        // SAFETY: as for `task`.
        unsafe { self.task.assume_init_mut() }
    }
}

impl<T: Task> Drop for TaskCell<T> {
    fn drop(&mut self) {
        if self.initialized {
            // SAFETY: the task was written (see `init_with`) and is dropped once, here.
            unsafe { self.task.assume_init_drop() };
        }
    }
}
