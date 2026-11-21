//! Slot-owned header and atomic slot ops for tables freed after thread progress.
//!
//! Port of erts/emulator/beam/erl_ptab.h (`ErtsPTabElementCommon.u.release`,
//! `erts_ptab_pix2intptr_ddrb`) and erl_ptab.c (`erts_ptab_delete_element` handing the
//! table's reference to `erts_schedule_thr_prgr_later_cleanup_op`), OTP-29.1.1.

use crate::thr_progress::raw::{ErtsThrPrgrLaterOp, LaterOpArgs};
use std::sync::Arc;
use std::sync::atomic::{AtomicPtr, Ordering};

/// Slot-owned header in front of an `Arc<T>` the table holds (`ptab_el->u.release`).
///
/// Port of erts/emulator/beam/erl_ptab.h (`ErtsPTabElementCommon.u.release`), OTP-29.1.1.
#[repr(C)]
pub(crate) struct ProgressHeld<T: Send + Sync + 'static> {
    later_op: ErtsThrPrgrLaterOp,
    ptr: *const T,
}

impl<T: Send + Sync + 'static> ProgressHeld<T> {
    fn from_arc(value: Arc<T>) -> Box<Self> {
        Box::new(Self {
            later_op: ErtsThrPrgrLaterOp::new(),
            ptr: Arc::into_raw(value),
        })
    }

    /// The element this header holds (`ptab_el` as the table's reference).
    pub(crate) fn value(&self) -> &T {
        // SAFETY: `ptr` is the `Arc::into_raw` address this header owns until Drop.
        unsafe { &*self.ptr }
    }

    /// One more strong count of the slot's `Arc` (`erts_ptab_pix2intptr` that keeps a ref).
    pub(crate) fn clone_arc(&self) -> Arc<T> {
        let ptr = self.ptr;
        // SAFETY: `ptr` is the `Arc::into_raw` address this header owns, so taking one more
        // strong count is the slot's `load_arc`.
        unsafe {
            Arc::increment_strong_count(ptr);
            Arc::from_raw(ptr)
        }
    }
}

impl<T: Send + Sync + 'static> Drop for ProgressHeld<T> {
    fn drop(&mut self) {
        // SAFETY: we own the `Arc::into_raw` strong count of `ptr`.
        drop(unsafe { Arc::from_raw(self.ptr) });
    }
}

/// Publish `value` in the empty slot (`erts_ptab_new_element`).
pub(crate) fn store<T: Send + Sync + 'static>(slot: &AtomicPtr<ProgressHeld<T>>, value: Arc<T>) {
    let held = Box::into_raw(ProgressHeld::from_arc(value));
    if slot
        .compare_exchange(
            std::ptr::null_mut(),
            held,
            Ordering::Release,
            Ordering::Relaxed,
        )
        .is_err()
    {
        // SAFETY: the CAS failed, so this header was never published; Drop releases the Arc.
        drop(unsafe { Box::from_raw(held) });
        panic!("ProgressSlot store requires an empty slot");
    }
}

/// Run `f` on the live header, if the slot holds one (`erts_ptab_pix2intptr_ddrb`).
pub(crate) fn with_held<T: Send + Sync + 'static, R>(
    slot: &AtomicPtr<ProgressHeld<T>>,
    f: impl FnOnce(&ProgressHeld<T>) -> R,
) -> Option<R> {
    let held = slot.load(Ordering::Acquire);
    if held.is_null() {
        return None;
    }
    // SAFETY: a non-null slot is a `Box<ProgressHeld<T>>` published by `store`. The caller
    // is a managed thread that passes no progress point, or delays progress, so the header
    // stays live for `f`.
    Some(f(unsafe { &*held }))
}

/// Empty the slot and hand the table's reference to a later cleanup op.
pub(crate) fn take_deferred<T: Send + Sync + 'static>(
    slot: &AtomicPtr<ProgressHeld<T>>,
) -> Option<(Arc<T>, LaterOpArgs)> {
    let held = slot.swap(std::ptr::null_mut(), Ordering::AcqRel);
    if held.is_null() {
        return None;
    }
    // SAFETY: the swapped-out pointer is the unpublished `Box` we still own until the later
    // op runs `release_progress_held`.
    let taken = unsafe { (*held).clone_arc() };
    Some((taken, release_args(held)))
}

/// Drop a still-occupied slot (`ProgressSlot` Drop; no reader can exist).
pub(crate) fn drop_occupied<T: Send + Sync + 'static>(slot: &mut AtomicPtr<ProgressHeld<T>>) {
    let held = *slot.get_mut();
    if !held.is_null() {
        *slot.get_mut() = std::ptr::null_mut();
        // SAFETY: exclusive drop of the slot; `held` is the live header `store` published.
        drop(unsafe { Box::from_raw(held) });
    }
}

fn release_args<T: Send + Sync + 'static>(held: *mut ProgressHeld<T>) -> LaterOpArgs {
    LaterOpArgs {
        func: release_progress_held::<T>,
        data: held.cast(),
        // SAFETY: `held` is the live header `take_deferred` swapped out; the node lives until
        // `release_progress_held` drops the Box.
        lop: unsafe { &raw mut (*held).later_op },
        size: Some(std::mem::size_of::<ProgressHeld<T>>()),
    }
}

fn release_progress_held<T: Send + Sync + 'static>(data: *mut ()) {
    // SAFETY: `data` is the `ProgressHeld<T>` `take_deferred` swapped out; this later op
    // runs once after unlink. Drop of the Box drops the slot's Arc.
    drop(unsafe { Box::from_raw(data.cast::<ProgressHeld<T>>()) });
}
