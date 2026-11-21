//! Table slots whose elements are freed only after thread progress.
//!
//! Port of erts/emulator/beam/erl_ptab.h (erts_ptab_pix2intptr_ddrb, erts_ptab_pix2intptr_nob)
//! and erl_ptab.c (erts_ptab_delete_element hands the table's reference to a release function
//! through erts_schedule_thr_prgr_later_cleanup_op), OTP-29.1.1. A lookup is one load of the
//! slot and no reference count: the element stays valid while the reader is a managed thread
//! that passes no thread progress point, or an unmanaged thread that delays progress. The
//! slot's reference is dropped by a later operation once every managed thread passed a point.
//!
//! Every `unsafe` of this kind of table is in `thr_progress/raw.rs`; users get a safe API.

use crate::thr_progress::{self, DelayHandle, ThrProgress, raw};
use crate::{Scheduler, Task};
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
            Some(Self::delay(progress))
        };
        Self { progress, handle }
    }

    /// The unmanaged side stays out of line: it reads the thread's own state, which a managed
    /// reader never does.
    #[cold]
    #[inline(never)]
    fn delay(progress: &ThrProgress) -> DelayHandle {
        thr_progress::unmanaged_delay(progress)
    }
}

impl Drop for Delay<'_> {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            thr_progress::unmanaged_continue(self.progress, handle);
        }
    }
}

/// One slot of a table: null, or a slot-owned header holding an `Arc<T>` reference and the
/// later-op node (`ptab_el->u.release`).
pub struct ProgressSlot<T: Send + Sync + 'static>(AtomicPtr<raw::ProgressHeld<T>>);

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
    pub fn store(&self, value: Arc<T>) {
        let held = raw::alloc_progress_held(Arc::into_raw(value));
        if self
            .0
            .compare_exchange(
                std::ptr::null_mut(),
                held,
                Ordering::Release,
                Ordering::Relaxed,
            )
            .is_err()
        {
            // `erts_ptab_new_element` publishes only into an empty slot.
            raw::drop_progress_held(held);
            panic!("ProgressSlot store requires an empty slot");
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
        // This thread passes no progress point (managed) or delays progress (`_delay`) until
        // `f` returns, which is what `with_managed` relies on.
        self.with_managed(f)
    }

    /// [`ProgressSlot::with`] for a managed thread: a bare load of the slot, which needs no
    /// progress domain (`erts_ptab_pix2intptr_ddrb` is a load and nothing else).
    pub fn with_managed<R>(&self, f: impl FnOnce(&T) -> R) -> Option<R> {
        let held = self.0.load(Ordering::Acquire);
        if held.is_null() {
            return None;
        }
        Some(f(raw::progress_held_value(held)))
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
        let held = self.0.load(Ordering::Acquire);
        if held.is_null() {
            return None;
        }
        let value = raw::progress_held_value(held);
        if !keep(value) {
            return None;
        }
        Some(raw::progress_held_clone_arc(held))
    }

    /// Empty the slot and return a reference to the element; the slot's own reference is
    /// released after thread progress (`erts_ptab_delete_element`).
    pub fn take<S: Task>(&self, scheduler: &Scheduler<S>) -> Option<Arc<T>> {
        let (taken, args) = self.take_deferred()?;
        scheduler.schedule_later_op_args(args);
        Some(taken)
    }

    /// Empty the slot and return the table reference plus the call arguments for
    /// `erts_schedule_thr_prgr_later_cleanup_op` to its scheduler-owned caller.
    pub(crate) fn take_deferred(&self) -> Option<(Arc<T>, raw::LaterOpArgs)> {
        let held = self.0.swap(std::ptr::null_mut(), Ordering::AcqRel);
        if held.is_null() {
            return None;
        }
        let taken = raw::progress_held_clone_arc(held);
        let args = raw::LaterOpArgs {
            func: raw::release_progress_held::<T>,
            data: held.cast(),
            lop: raw::progress_held_lop(held),
            size: Some(std::mem::size_of::<raw::ProgressHeld<T>>()),
        };
        Some((taken, args))
    }
}

impl<T: Send + Sync + 'static> Drop for ProgressSlot<T> {
    fn drop(&mut self) {
        let held = *self.0.get_mut();
        if !held.is_null() {
            raw::drop_progress_held(held);
        }
    }
}
