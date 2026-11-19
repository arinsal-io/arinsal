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
