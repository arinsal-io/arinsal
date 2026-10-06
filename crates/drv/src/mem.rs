//! Borrowed views of memory a C driver passes to the driver API.
//!
//! Every pointer argument of an `erl_driver.h` function is a promise by the
//! driver that it is valid for the call; these helpers are the only places that
//! turn such pointers into references, so the rest of the crate stays safe code.

use std::ffi::{CStr, c_char};

/// `len` elements at `ptr`; NULL or zero length is empty.
pub(crate) fn slice<'a, T>(ptr: *const T, len: usize) -> &'a [T] {
    if ptr.is_null() || len == 0 {
        return &[];
    }
    // SAFETY: the driver passes `len` readable elements at `ptr` for the call.
    unsafe { std::slice::from_raw_parts(ptr, len) }
}

/// `len` writable elements at `ptr`; NULL or zero length is empty.
pub(crate) fn slice_mut<'a, T>(ptr: *mut T, len: usize) -> &'a mut [T] {
    if ptr.is_null() || len == 0 {
        return &mut [];
    }
    // SAFETY: the driver passes `len` writable elements at `ptr` for the call.
    unsafe { std::slice::from_raw_parts_mut(ptr, len) }
}

/// Shared view of the value at `ptr`, `None` for NULL.
pub(crate) fn deref<'a, T>(ptr: *const T) -> Option<&'a T> {
    // SAFETY: the driver passes NULL or a valid, initialised `T` for the call.
    unsafe { ptr.as_ref() }
}

/// Exclusive view of the value at `ptr`, `None` for NULL.
pub(crate) fn deref_mut<'a, T>(ptr: *mut T) -> Option<&'a mut T> {
    // SAFETY: the driver passes NULL or a valid, writable `T` for the call.
    unsafe { ptr.as_mut() }
}

/// NUL-terminated string at `ptr`, `None` for NULL.
pub(crate) fn cstr<'a>(ptr: *const c_char) -> Option<&'a CStr> {
    if ptr.is_null() {
        return None;
    }
    // SAFETY: the driver passes a NUL-terminated string for the call.
    Some(unsafe { CStr::from_ptr(ptr) })
}

/// Hand a value to C as an opaque heap handle (freed by [`free_handle`]).
pub(crate) fn new_handle<T>(value: T) -> *mut T {
    Box::into_raw(Box::new(value))
}

/// Free a handle from [`new_handle`].
pub(crate) fn free_handle<T>(ptr: *mut T) {
    // SAFETY: `ptr` came from `new_handle::<T>` and is freed once by its owner.
    drop(unsafe { Box::from_raw(ptr) });
}
