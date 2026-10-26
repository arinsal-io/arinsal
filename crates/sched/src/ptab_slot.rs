//! Table slots whose elements are freed only after thread progress.
//!
//! Port of erts/emulator/beam/erl_ptab.h (erts_ptab_pix2intptr_ddrb, erts_ptab_pix2intptr_nob)
//! and erl_ptab.c (erts_ptab_delete_element hands the table's reference to a release function
//! through erts_schedule_thr_prgr_later_cleanup_op), OTP-29.1.1. A lookup is one load of the
//! slot and no reference count: the element stays valid while the reader is a managed thread
//! that passes no thread progress point, or an unmanaged thread that delays progress. The
//! slot's reference is dropped by a later operation once every managed thread passed a point.
//!
//! Every `unsafe` of this kind of table is in this module (the process table's is in
//! `proc_ref.rs`); users get a safe API.

use crate::thr_progress::{self, DelayHandle, LaterOp, ThrProgress};
use std::sync::Arc;
use std::sync::atomic::{AtomicPtr, Ordering};

/// The thread progress domain of one scheduler: what a slot's readers delay and what its
/// later operations wait for.
#[derive(Clone)]
pub struct Progress(pub(crate) Arc<ThrProgress>);

/// An unmanaged reader's delay of thread progress, ended when it drops.
struct Delay<'a> {
    progress: &'a ThrProgress,
    handle: Option<DelayHandle>,
}

impl<'a> Delay<'a> {
    /// A managed thread delays nothing: it passes no progress point while it reads.
    fn begin(progress: &'a ThrProgress, managed: bool) -> Self {
        let handle = if managed {
            debug_assert!(
                thr_progress::is_managed_thread_of(progress),
                "a managed lookup runs on a managed thread"
            );
            None
        } else {
            Some(thr_progress::unmanaged_delay(progress))
        };
        Self { progress, handle }
    }
}

impl Drop for Delay<'_> {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            thr_progress::unmanaged_continue(self.progress, handle);
        }
    }
}

/// One slot of a table: null, or the address of an `Arc<T>` the slot holds a reference to.
pub struct ProgressSlot<T: Send + Sync + 'static>(AtomicPtr<T>);

impl<T: Send + Sync + 'static> Default for ProgressSlot<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Send + Sync + 'static> ProgressSlot<T> {
    /// An empty slot.
    pub const fn new() -> Self {
        Self(AtomicPtr::new(std::ptr::null_mut()))
    }

    /// Whether the slot holds an element.
    pub fn is_occupied(&self) -> bool {
        !self.0.load(Ordering::Acquire).is_null()
    }

    /// Publish `value` in the empty slot; the slot keeps the reference. A value that was in
    /// the slot is released like a removed one (at once without a `progress` domain, where no
    /// reader can exist).
    pub fn store(&self, value: Arc<T>, progress: Option<&Progress>) {
        let old = self
            .0
            .swap(Arc::into_raw(value).cast_mut(), Ordering::AcqRel);
        if !old.is_null() {
            match progress {
                Some(progress) => schedule_release::<T>(old, progress),
                // SAFETY: `old` carries the slot's reference; without a progress domain nothing
                // reads the table concurrently.
                None => drop(unsafe { Arc::from_raw(old) }),
            }
        }
    }

    /// Run `f` on the element without taking a reference (`erts_ptab_pix2intptr_ddrb`).
    /// `managed` says the caller is a managed thread of `progress`; any other thread delays
    /// progress for the call.
    pub fn with<R>(
        &self,
        progress: &Progress,
        managed: bool,
        f: impl FnOnce(&T) -> R,
    ) -> Option<R> {
        let _delay = Delay::begin(&progress.0, managed);
        let raw = self.0.load(Ordering::Acquire);
        if raw.is_null() {
            return None;
        }
        // SAFETY: `raw` came from `Arc::into_raw` and the slot owns that reference. Dropping it
        // is deferred by `schedule_release` until every managed thread passed a progress point
        // after the slot was cleared; this thread passes none (managed) or delays progress
        // (`_delay`) until `f` returns, so the element outlives the borrow.
        Some(f(unsafe { &*raw }))
    }

    /// A counted reference to the element, for a caller that keeps it.
    pub fn load_arc(&self, progress: &Progress, managed: bool) -> Option<Arc<T>> {
        self.load_arc_if(progress, managed, |_| true)
    }

    /// [`ProgressSlot::load_arc`] when `keep` accepts the element.
    pub fn load_arc_if(
        &self,
        progress: &Progress,
        managed: bool,
        keep: impl FnOnce(&T) -> bool,
    ) -> Option<Arc<T>> {
        let _delay = Delay::begin(&progress.0, managed);
        let raw = self.0.load(Ordering::Acquire);
        if raw.is_null() {
            return None;
        }
        // SAFETY: as in `with`, the element is alive during the delay.
        if !keep(unsafe { &*raw }) {
            return None;
        }
        // SAFETY: as in `with`, the element is alive during the delay, and `raw` is the
        // address of an `Arc<T>` whose strong count the slot holds, so taking one more is sound.
        Some(unsafe {
            Arc::increment_strong_count(raw);
            Arc::from_raw(raw)
        })
    }

    /// Empty the slot and return a reference to the element; the slot's own reference is
    /// released after thread progress (`erts_ptab_delete_element`).
    pub fn take(&self, progress: &Progress) -> Option<Arc<T>> {
        let raw = self.0.swap(std::ptr::null_mut(), Ordering::AcqRel);
        if raw.is_null() {
            return None;
        }
        // SAFETY: the swap took the slot's reference out of the slot; it is still alive (it is
        // released only by the later operation scheduled below), so another count can be taken.
        let taken = unsafe {
            Arc::increment_strong_count(raw);
            Arc::from_raw(raw)
        };
        schedule_release::<T>(raw, progress);
        Some(taken)
    }
}

impl<T: Send + Sync + 'static> Drop for ProgressSlot<T> {
    fn drop(&mut self) {
        let raw = *self.0.get_mut();
        if !raw.is_null() {
            // SAFETY: `&mut self` means no reader exists; `raw` carries the slot's reference.
            drop(unsafe { Arc::from_raw(raw) });
        }
    }
}

/// Drop the slot's reference to the element at `raw` once thread progress has passed.
fn schedule_release<T: Send + Sync + 'static>(raw: *mut T, progress: &Progress) {
    thr_progress::schedule_later_op(
        &progress.0,
        LaterOp::Cleanup {
            release: release::<T>,
            data: raw as usize,
        },
    );
}

fn release<T: Send + Sync + 'static>(data: usize) {
    // SAFETY: `data` is a pointer scheduled by `schedule_release`, which came from
    // `Arc::into_raw` and carries the slot's reference; a later operation runs once.
    drop(unsafe { Arc::from_raw(data as *const T) });
}
