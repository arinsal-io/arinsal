use super::TaskCell;
use crate::Task;
use std::mem::MaybeUninit;

impl<T: Task> TaskCell<T> {
    // Port of erts/emulator/beam/erl_process.c (alloc_process), OTP-29.1.1.
    /// Let a raw constructor initialize the task in the cell's final process block.
    ///
    /// The returned reference must identify this cell's storage. The address check keeps a
    /// safe callback from marking some separate value initialized here.
    #[inline(always)]
    pub(crate) fn init_in_place(
        &mut self,
        init: impl for<'a> FnOnce(&'a mut MaybeUninit<T>) -> &'a mut T,
    ) {
        assert!(!self.initialized, "a task is written once");
        let slot = self.task.as_mut_ptr();
        let task = init(&mut self.task);
        assert!(std::ptr::eq(slot, task));
        task.init_in_place();
        self.initialized = true;
    }
}

/// The process main lock and the data it protects, data first.
///
/// Port of erts/emulator/beam/erl_process_lock.h (`ErtsProcLock lock` embedded in `Process`),
/// OTP-29.1.1: the lock lives in the process struct. The task is the first member so the
/// pointer generated code gets as `c_p` is the address of the process struct itself, and the
/// process state word is at a fixed offset from it (`offsetof(Process, state)`).
#[repr(C)]
pub(crate) struct ProcLock<C> {
    data: std::cell::UnsafeCell<C>,
    raw: parking_lot::RawMutex,
}

// SAFETY: the data is reached only through a guard that holds `raw`, or through `&mut self`;
// that is the contract of `parking_lot::Mutex`, which is `Send`/`Sync` for `C: Send`.
unsafe impl<C: Send> Send for ProcLock<C> {}
// SAFETY: as for `Send`.
unsafe impl<C: Send> Sync for ProcLock<C> {}

/// A held [`ProcLock`].
pub(crate) struct ProcLockGuard<'a, C> {
    lock: &'a ProcLock<C>,
}

impl<C> ProcLock<C> {
    /// Offset of the data from the start of the lock (zero: the data is first).
    pub(crate) const DATA_OFFSET: usize = std::mem::offset_of!(ProcLock<C>, data);

    pub(crate) fn new(data: C) -> Self {
        use parking_lot::lock_api::RawMutex as _;
        Self {
            data: std::cell::UnsafeCell::new(data),
            raw: parking_lot::RawMutex::INIT,
        }
    }

    pub(crate) fn lock(&self) -> ProcLockGuard<'_, C> {
        use parking_lot::lock_api::RawMutex as _;
        self.raw.lock();
        ProcLockGuard { lock: self }
    }

    pub(crate) fn try_lock(&self) -> Option<ProcLockGuard<'_, C>> {
        use parking_lot::lock_api::RawMutex as _;
        self.raw.try_lock().then(|| ProcLockGuard { lock: self })
    }

    pub(crate) fn get_mut(&mut self) -> &mut C {
        self.data.get_mut()
    }

    /// The data's address, with the lock's interior-mutable provenance; dereferencing it
    /// mutably requires that the caller holds the lock.
    pub(crate) fn data_ptr(&self) -> *mut C {
        self.data.get()
    }
}

/// The main lock of a process held past its guard: `erts_schedule` returns the process with
/// `ERTS_PROC_LOCK_MAIN` held, `process_main` runs the slice under it, and the next
/// `erts_schedule` releases it. Not `Send` (the raw pointer), so the lock is resumed on the
/// thread that holds it; dropping it without [`ProcLock::resume_locked`] leaves the lock held.
///
/// Port of erts/emulator/beam/erl_process.c:9607 (erts_schedule takes `p` and returns the next
/// process with ERTS_PROC_LOCK_MAIN held), OTP-29.1.1.
#[must_use = "the main lock stays held until it is resumed"]
pub(crate) struct HeldMainLock {
    lock: *const (),
}

impl<C> ProcLockGuard<'_, C> {
    /// Keep the lock held after this guard ends.
    pub(crate) fn keep_locked(self) -> HeldMainLock {
        let lock = std::ptr::from_ref(self.lock).cast::<()>();
        std::mem::forget(self);
        HeldMainLock { lock }
    }
}

impl<C> ProcLock<C> {
    /// The guard of this lock, which `held` (from [`ProcLockGuard::keep_locked`] of a guard of
    /// this lock) proves is held.
    pub(crate) fn resume_locked(&self, held: HeldMainLock) -> ProcLockGuard<'_, C> {
        assert!(
            std::ptr::eq(held.lock, std::ptr::from_ref(self).cast::<()>()),
            "a held main lock resumes on its own process"
        );
        ProcLockGuard { lock: self }
    }
}

impl<C> std::ops::Deref for ProcLockGuard<'_, C> {
    type Target = C;
    fn deref(&self) -> &C {
        // SAFETY: the guard holds the lock, so no other reference to the data exists.
        unsafe { &*self.lock.data.get() }
    }
}

impl<C> std::ops::DerefMut for ProcLockGuard<'_, C> {
    fn deref_mut(&mut self) -> &mut C {
        // SAFETY: as for `deref`; `&mut self` makes this the only guard reference.
        unsafe { &mut *self.lock.data.get() }
    }
}

impl<C> Drop for ProcLockGuard<'_, C> {
    fn drop(&mut self) {
        use parking_lot::lock_api::RawMutex as _;
        // SAFETY: this guard was created by a successful lock of `raw` and unlocks it once.
        unsafe { self.lock.raw.unlock() };
    }
}

/// `esdp->current_process` of a normal scheduler with the main lock its slice keeps: the `p`
/// a C call of `erts_schedule` passes (the generated process_main carries only the
/// `Process *` from one call to the next). Asserts that `p` is that process.
// Port of erts/emulator/beam/erl_process.c:9667 (erts_schedule: `ASSERT(esdp->current_process
// == p)` with ERTS_PROC_LOCK_MAIN held), OTP-29.1.1.
pub(crate) fn current_process_held<T: Task>(
    esdp: &crate::ErtsSchedulerData<T>,
    p: *mut T,
) -> (crate::ProcRef<T>, HeldMainLock) {
    assert!(esdp.worker.is_some(), "erts_schedule: a normal scheduler");
    let current = esdp
        .current_process
        .borrow()
        .clone()
        .expect("erts_schedule: p is esdp->current_process");
    let cell = current.cell.data_ptr();
    // SAFETY: `cell` addresses the live task cell of `current` (the reference above keeps the
    // block); the projection reads no data.
    let task = unsafe { (&raw mut (*cell).task).cast::<T>() };
    assert!(
        std::ptr::eq(task, p),
        "erts_schedule: p is esdp->current_process"
    );
    // `esdp` is the scheduler data of the calling thread (a reference to it cannot leave the
    // thread: it is not `Sync`). On a normal scheduler `current_process` is set just before the
    // schedule-in takes the main lock and cleared just before the schedule-out releases it, both
    // on this thread, so the lock is held here.
    let held = HeldMainLock {
        lock: std::ptr::from_ref(&current.cell).cast::<()>(),
    };
    (current, held)
}
