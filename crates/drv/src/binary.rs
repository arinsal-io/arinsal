//! `ErlDrvBinary` and `driver_alloc` memory.
//!
//! erts places `ErlDrvBinary` inside its `Binary` struct, after the flags and
//! the reference count (`ErlDrvBinary2Binary`, erts/emulator/beam/erl_binary.h).
//! Here the count is one word in front of the public `{orig_size, orig_bytes}` view.

use std::ffi::{c_char, c_void};
use std::sync::atomic::{AtomicIsize, Ordering};

use crate::layout;

/// Public `ErlDrvBinary` header; `orig_bytes` follows `orig_size`.
#[repr(C)]
pub struct ErlDrvBinary {
    /// Total length of the binary.
    pub orig_size: isize,
    orig_bytes: [c_char; 1],
}

const _: () =
    assert!(std::mem::offset_of!(ErlDrvBinary, orig_size) == layout::OFF_ErlDrvBinary_orig_size);
const _: () =
    assert!(std::mem::offset_of!(ErlDrvBinary, orig_bytes) == layout::OFF_ErlDrvBinary_orig_bytes);

const REFC_SIZE: usize = size_of::<AtomicIsize>();
const DATA_OFFSET: usize = layout::OFF_ErlDrvBinary_orig_bytes;

fn refc(bin: *mut ErlDrvBinary) -> &'static AtomicIsize {
    // SAFETY: every ErlDrvBinary handed out by this module sits REFC_SIZE bytes after
    // an aligned, initialised AtomicIsize that lives as long as the binary.
    unsafe { AtomicIsize::from_ptr(bin.cast::<u8>().sub(REFC_SIZE).cast::<isize>()) }
}

/// Port of erts/emulator/beam/io.c (driver_alloc_binary), OTP-29.1.1.
pub fn alloc_binary(size: usize) -> *mut ErlDrvBinary {
    let Some(total) = REFC_SIZE
        .checked_add(DATA_OFFSET)
        .and_then(|n| n.checked_add(size))
    else {
        return std::ptr::null_mut();
    };
    // SAFETY: malloc returns null or a block aligned for any word-sized type.
    let base = unsafe { libc::malloc(total) }.cast::<u8>();
    if base.is_null() {
        return std::ptr::null_mut();
    }
    // SAFETY: `base` holds `total` bytes; the count and header fit before the data.
    unsafe {
        base.cast::<AtomicIsize>().write(AtomicIsize::new(1));
        let bin = base.add(REFC_SIZE).cast::<ErlDrvBinary>();
        std::ptr::addr_of_mut!((*bin).orig_size).write(size as isize);
        bin
    }
}

/// Port of io.c (driver_realloc_binary).
pub fn realloc_binary(bin: *mut ErlDrvBinary, size: usize) -> *mut ErlDrvBinary {
    if bin.is_null() {
        return std::ptr::null_mut();
    }
    let Some(total) = REFC_SIZE
        .checked_add(DATA_OFFSET)
        .and_then(|n| n.checked_add(size))
    else {
        return std::ptr::null_mut();
    };
    // SAFETY: `bin` came from alloc_binary, so its block starts REFC_SIZE bytes earlier.
    let base = unsafe { libc::realloc(bin.cast::<u8>().sub(REFC_SIZE).cast(), total) }.cast::<u8>();
    if base.is_null() {
        return std::ptr::null_mut();
    }
    // SAFETY: the resized block keeps the count and header layout.
    unsafe {
        let bin = base.add(REFC_SIZE).cast::<ErlDrvBinary>();
        std::ptr::addr_of_mut!((*bin).orig_size).write(size as isize);
        bin
    }
}

/// Port of io.c (driver_free_binary): drop one reference, freeing at zero.
pub fn free_binary(bin: *mut ErlDrvBinary) {
    if bin.is_null() {
        return;
    }
    if refc(bin).fetch_sub(1, Ordering::AcqRel) == 1 {
        // SAFETY: the last reference is gone; the block started REFC_SIZE bytes earlier.
        unsafe { libc::free(bin.cast::<u8>().sub(REFC_SIZE).cast()) };
    }
}

pub(crate) fn get_refc(bin: *mut ErlDrvBinary) -> isize {
    refc(bin).load(Ordering::Acquire)
}

pub(crate) fn inc_refc(bin: *mut ErlDrvBinary) -> isize {
    refc(bin).fetch_add(1, Ordering::AcqRel) + 1
}

pub(crate) fn dec_refc(bin: *mut ErlDrvBinary) -> isize {
    refc(bin).fetch_sub(1, Ordering::AcqRel) - 1
}

/// Data pointer of a binary from this module.
pub(crate) fn bytes_ptr(bin: *mut ErlDrvBinary) -> *mut u8 {
    bin.cast::<u8>().wrapping_add(DATA_OFFSET)
}

/// Copy of the binary's bytes.
pub(crate) fn bytes(bin: *mut ErlDrvBinary) -> Vec<u8> {
    // SAFETY: `bin` is a live driver binary; orig_size bytes follow its header.
    unsafe {
        let len = usize::try_from((*bin).orig_size).unwrap_or(0);
        std::slice::from_raw_parts(bytes_ptr(bin), len).to_vec()
    }
}

/// New driver binary holding `data`.
pub(crate) fn from_bytes(data: &[u8]) -> *mut ErlDrvBinary {
    let bin = alloc_binary(data.len());
    if !bin.is_null() {
        // SAFETY: the binary has room for data.len() bytes and does not overlap `data`.
        unsafe { std::ptr::copy_nonoverlapping(data.as_ptr(), bytes_ptr(bin), data.len()) };
    }
    bin
}

/// `driver_alloc` (erts_alloc_fnf of ERTS_ALC_T_DRV).
pub fn alloc(size: usize) -> *mut c_void {
    arinsal_alloc::typed::driver_alloc(size).cast()
}

/// `driver_realloc`.
pub fn realloc(ptr: *mut c_void, size: usize) -> *mut c_void {
    arinsal_alloc::typed::driver_realloc(ptr.cast(), size).cast()
}

/// `driver_free`.
pub fn free(ptr: *mut c_void) {
    arinsal_alloc::typed::driver_free(ptr.cast());
}

/// Copy of `len` bytes at `offset` in the binary; the caller checked the bounds.
pub(crate) fn read(bin: *mut ErlDrvBinary, offset: usize, len: usize) -> Vec<u8> {
    crate::mem::slice(bytes_ptr(bin).wrapping_add(offset), len).to_vec()
}
