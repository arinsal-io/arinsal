//! C driver API implemented by the core host (see `api::DRIVER_API`).

use std::collections::HashMap;
use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::hint::black_box;
use std::sync::{Mutex, OnceLock};

use crate::binary::{self, ErlDrvBinary};
use crate::{ExitReason, errno_id, port_of};

/// Borrow `len` bytes at `ptr`; NULL or zero length is empty.
fn bytes<'a>(ptr: *const c_char, len: usize) -> &'a [u8] {
    if ptr.is_null() || len == 0 {
        return &[];
    }
    // SAFETY: the driver passes `len` readable bytes at `ptr` for the duration of the call.
    unsafe { std::slice::from_raw_parts(ptr.cast::<u8>(), len) }
}

fn c_string(ptr: *const c_char) -> String {
    if ptr.is_null() {
        return String::new();
    }
    // SAFETY: the driver passes a NUL-terminated string.
    unsafe { CStr::from_ptr(ptr) }
        .to_string_lossy()
        .into_owned()
}

/// Port of erts/emulator/beam/io.c:6436 (driver_output), OTP-29.1.1.
#[unsafe(no_mangle)]
pub extern "C" fn driver_output(port: *mut c_void, buf: *mut c_char, len: usize) -> c_int {
    driver_output2(port, std::ptr::null_mut(), 0, buf, len)
}

/// Port of io.c:6381 (driver_output2).
#[unsafe(no_mangle)]
pub extern "C" fn driver_output2(
    port: *mut c_void,
    hbuf: *mut c_char,
    hlen: usize,
    buf: *mut c_char,
    len: usize,
) -> c_int {
    let Some(port) = port_of(port) else {
        return -1;
    };
    let data = (!buf.is_null()).then(|| bytes(buf, len));
    port.output2(bytes(hbuf, hlen), data)
}

/// Port of io.c:7252 (driver_failure).
#[unsafe(no_mangle)]
pub extern "C" fn driver_failure(port: *mut c_void, code: c_int) -> c_int {
    let Some(port) = port_of(port) else {
        return -1;
    };
    port.failure(ExitReason::Code(code), code == 0)
}

/// Port of io.c:7257 (driver_failure_atom).
#[unsafe(no_mangle)]
pub extern "C" fn driver_failure_atom(port: *mut c_void, string: *mut c_char) -> c_int {
    let Some(port) = port_of(port) else {
        return -1;
    };
    port.failure(ExitReason::Atom(c_string(string)), false)
}

/// Port of io.c:7267 (driver_failure_posix).
#[unsafe(no_mangle)]
pub extern "C" fn driver_failure_posix(port: *mut c_void, err: c_int) -> c_int {
    let Some(port) = port_of(port) else {
        return -1;
    };
    port.failure(ExitReason::Atom(errno_id(err)), false)
}

/// Port of io.c:7272 (driver_failure_eof).
#[unsafe(no_mangle)]
pub extern "C" fn driver_failure_eof(port: *mut c_void) -> c_int {
    let Some(port) = port_of(port) else {
        return -1;
    };
    port.failure(ExitReason::Normal, true)
}

/// Port of io.c:7230 (driver_exit): unlink the connected process, then fail.
#[unsafe(no_mangle)]
pub extern "C" fn driver_exit(port: *mut c_void, err: c_int) -> c_int {
    let Some(port) = port_of(port) else {
        return -1;
    };
    port.host.unlink_connected(&port);
    if err == 0 {
        port.failure(ExitReason::Normal, false)
    } else {
        port.failure(ExitReason::Atom(errno_id(err)), false)
    }
}

/// Port of io.c:5312 (set_port_control_flags).
#[unsafe(no_mangle)]
pub extern "C" fn set_port_control_flags(port: *mut c_void, flags: c_int) {
    if let Some(port) = port_of(port) {
        port.control_flags
            .store(flags, std::sync::atomic::Ordering::Release);
    }
}

/// Port of erts/emulator/beam/erl_errno_str.c:1229 (erl_errno_id): strings live
/// for the runtime's lifetime.
#[unsafe(no_mangle)]
pub extern "C" fn erl_errno_id(error: c_int) -> *const c_char {
    static NAMES: OnceLock<Mutex<HashMap<c_int, &'static CStr>>> = OnceLock::new();
    let mut names = NAMES
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .unwrap();
    names
        .entry(error)
        .or_insert_with(|| {
            let name = CString::new(errno_id(error)).expect("errno names have no NUL");
            Box::leak(name.into_boxed_c_str())
        })
        .as_ptr()
}

/// `driver_alloc` (io.c, erts_alloc_fnf ERTS_ALC_T_DRV).
#[unsafe(no_mangle)]
pub extern "C" fn driver_alloc(size: usize) -> *mut c_void {
    binary::alloc(size)
}

/// `driver_realloc`.
#[unsafe(no_mangle)]
pub extern "C" fn driver_realloc(ptr: *mut c_void, size: usize) -> *mut c_void {
    binary::realloc(ptr, size)
}

/// `driver_free`.
#[unsafe(no_mangle)]
pub extern "C" fn driver_free(ptr: *mut c_void) {
    binary::free(ptr)
}

/// `driver_alloc_binary`.
#[unsafe(no_mangle)]
pub extern "C" fn driver_alloc_binary(size: usize) -> *mut ErlDrvBinary {
    binary::alloc_binary(size)
}

/// `driver_realloc_binary`.
#[unsafe(no_mangle)]
pub extern "C" fn driver_realloc_binary(bin: *mut ErlDrvBinary, size: usize) -> *mut ErlDrvBinary {
    binary::realloc_binary(bin, size)
}

/// `driver_free_binary`.
#[unsafe(no_mangle)]
pub extern "C" fn driver_free_binary(bin: *mut ErlDrvBinary) {
    binary::free_binary(bin)
}

/// `driver_binary_get_refc`.
#[unsafe(no_mangle)]
pub extern "C" fn driver_binary_get_refc(bin: *mut ErlDrvBinary) -> isize {
    binary::get_refc(bin)
}

/// `driver_binary_inc_refc`.
#[unsafe(no_mangle)]
pub extern "C" fn driver_binary_inc_refc(bin: *mut ErlDrvBinary) -> isize {
    binary::inc_refc(bin)
}

/// `driver_binary_dec_refc`.
#[unsafe(no_mangle)]
pub extern "C" fn driver_binary_dec_refc(bin: *mut ErlDrvBinary) -> isize {
    binary::dec_refc(bin)
}

/// Exported symbol addresses by name, for `api` checks.
pub(crate) fn exported() -> &'static [(&'static str, usize)] {
    static EXPORTS: OnceLock<Vec<(&'static str, usize)>> = OnceLock::new();
    EXPORTS.get_or_init(|| {
        vec![
            ("driver_output", driver_output as *const () as usize),
            ("driver_output2", driver_output2 as *const () as usize),
            ("driver_failure", driver_failure as *const () as usize),
            (
                "driver_failure_atom",
                driver_failure_atom as *const () as usize,
            ),
            (
                "driver_failure_posix",
                driver_failure_posix as *const () as usize,
            ),
            (
                "driver_failure_eof",
                driver_failure_eof as *const () as usize,
            ),
            ("driver_exit", driver_exit as *const () as usize),
            (
                "set_port_control_flags",
                set_port_control_flags as *const () as usize,
            ),
            ("erl_errno_id", erl_errno_id as *const () as usize),
            ("driver_alloc", driver_alloc as *const () as usize),
            ("driver_realloc", driver_realloc as *const () as usize),
            ("driver_free", driver_free as *const () as usize),
            (
                "driver_alloc_binary",
                driver_alloc_binary as *const () as usize,
            ),
            (
                "driver_realloc_binary",
                driver_realloc_binary as *const () as usize,
            ),
            (
                "driver_free_binary",
                driver_free_binary as *const () as usize,
            ),
            (
                "driver_binary_get_refc",
                driver_binary_get_refc as *const () as usize,
            ),
            (
                "driver_binary_inc_refc",
                driver_binary_inc_refc as *const () as usize,
            ),
            (
                "driver_binary_dec_refc",
                driver_binary_dec_refc as *const () as usize,
            ),
        ]
    })
}

pub(crate) fn retain_exports() {
    black_box(exported());
}
