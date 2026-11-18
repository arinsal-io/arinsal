//! Raw thread-local scheduler data access for reference and unique counters.
//!
//! Port of `erts_get_scheduler_data` from erts/emulator/beam/erl_process.c, OTP-29.1.1.

use super::SchedRefUnique;
use std::cell::Cell;

thread_local! {
    static CURRENT: Cell<*const SchedRefUnique> = const { Cell::new(std::ptr::null()) };
}

pub(super) fn replace(data: &SchedRefUnique) -> *const SchedRefUnique {
    CURRENT.with(|current| current.replace(std::ptr::from_ref(data)))
}

pub(super) fn restore(previous: *const SchedRefUnique) {
    CURRENT.with(|current| current.set(previous));
}

pub(super) fn with_current<R>(f: impl for<'a> FnOnce(&'a SchedRefUnique) -> R) -> Option<R> {
    CURRENT.with(|current| {
        let data = current.get();
        if data.is_null() {
            None
        } else {
            // SAFETY: `SchedRefUnique::bind` keeps `data` alive (an `Rc` clone) for the
            // binding guard's lifetime, and the guard's drop restores this slot. The
            // counters are only read through shared references (`Cell`).
            Some(f(unsafe { &*data }))
        }
    })
}
