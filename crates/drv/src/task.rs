//! Driver callback invocation shared by port tasks, async completion and timers.

use std::ffi::c_void;

use crate::{DrvFn1, DrvFn2};

/// Call a `void (*)(void *)` driver callback.
pub(crate) fn call1(callback: DrvFn1, arg: *mut c_void) {
    // SAFETY: the callback comes from a loaded driver entry or a driver_async call whose
    // library stays loaded while the port or job exists; `arg` is that driver's own data.
    unsafe { callback(arg) }
}

/// Call a `void (*)(void *, void *)` driver callback.
pub(crate) fn call2(callback: DrvFn2, first: *mut c_void, second: *mut c_void) {
    // SAFETY: as for `call1`; the pointers are the driver's data and the event or job data.
    unsafe { callback(first, second) }
}

/// The `ErlDrvEvent` for descriptor `fd` (`(ErlDrvEvent)(long)fd` in drivers).
pub(crate) fn event_of(fd: i32) -> *mut c_void {
    fd as isize as usize as *mut c_void
}

/// The descriptor behind an `ErlDrvEvent`.
pub(crate) fn fd_of(event: *mut c_void) -> i32 {
    event as usize as isize as i32
}
