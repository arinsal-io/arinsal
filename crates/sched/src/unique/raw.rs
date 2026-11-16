//! Raw thread-local scheduler data access for reference and unique counters.
//!
//! Port of `erts_get_scheduler_data` from erts/emulator/beam/erl_process.c, OTP-29.1.1.

use super::ErtsSchedulerData;
use std::cell::Cell;

thread_local! {
    static CURRENT: Cell<*const ErtsSchedulerData> = const { Cell::new(std::ptr::null()) };
}

pub(super) fn replace(data: &ErtsSchedulerData) -> *const ErtsSchedulerData {
    CURRENT.with(|current| current.replace(std::ptr::from_ref(data)))
}

pub(super) fn restore(previous: *const ErtsSchedulerData) {
    CURRENT.with(|current| current.set(previous));
}

pub(super) fn with_current<R>(f: impl for<'a> FnOnce(&'a ErtsSchedulerData) -> R) -> Option<R> {
    CURRENT.with(|current| {
        let data = current.get();
        if data.is_null() {
            None
        } else {
            // SAFETY: `ErtsSchedulerData::bind` borrows `data` for the binding guard's
            // lifetime, and this thread-local slot is restored when that guard drops.
            Some(f(unsafe { &*data }))
        }
    })
}
