//! Raw storage for data protected by an `erts_spinlock_t`.

use std::cell::UnsafeCell;
use std::ops::{Deref, DerefMut};

use arinsal_alloc::ethr::{ErtsSpinlock, erts_spin_lock, erts_spin_unlock};

// Port of erts/emulator/beam/erl_threads.h (erts_spinlock_t), OTP-29.1.1.
pub(super) struct LockedValue<T> {
    lock: ErtsSpinlock,
    value: UnsafeCell<T>,
}

// SAFETY: access to the value is serialized by the ERTS spinlock.
unsafe impl<T: Send> Sync for LockedValue<T> {}

impl<T> LockedValue<T> {
    // ErtsSpinlock::new initializes the same ethr spinlock state as erts_spinlock_init.
    pub(super) const fn new(value: T) -> Self {
        Self {
            lock: ErtsSpinlock::new(),
            value: UnsafeCell::new(value),
        }
    }

    pub(super) fn lock(&self) -> LockedValueGuard<'_, T> {
        erts_spin_lock(&self.lock);
        LockedValueGuard { locked: self }
    }
}

pub(super) struct LockedValueGuard<'a, T> {
    locked: &'a LockedValue<T>,
}

impl<T> Deref for LockedValueGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        // SAFETY: this guard holds the lock, excluding every other access to the value.
        unsafe { &*self.locked.value.get() }
    }
}

impl<T> DerefMut for LockedValueGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        // SAFETY: this guard holds the lock, excluding every other access to the value.
        unsafe { &mut *self.locked.value.get() }
    }
}

impl<T> Drop for LockedValueGuard<'_, T> {
    fn drop(&mut self) {
        erts_spin_unlock(&self.locked.lock);
    }
}
