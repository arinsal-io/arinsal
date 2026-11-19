//! Raw code-table slots with ERTS-style grace-period reclamation.
//!
//! Port of code_ix.h (`erts_active_code_ix`), code_ix.c (`erts_commit_staging_code_ix`), and
//! erl_process.c (`erts_schedule_thr_prgr_later_cleanup_op`), OTP-29.1.1.

use std::sync::Arc;
use std::sync::atomic::{AtomicPtr, Ordering};

/// One ownership reference to a replaced slot value, released after thread progress.
pub(crate) struct RetireOp {
    ptr: *const (),
    release: fn(*const ()),
}

// SAFETY: `ptr` is an owned `Arc` reference transferred from a slot, and `release` only drops it.
unsafe impl Send for RetireOp {}

impl RetireOp {
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
