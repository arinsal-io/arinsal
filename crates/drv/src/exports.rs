//! C driver API implemented by the core host (see `api::DRIVER_API`).

use std::collections::HashMap;
use std::ffi::{CStr, CString, c_char, c_int, c_long, c_uint, c_ulong, c_void};
use std::hint::black_box;
use std::sync::{Mutex, OnceLock};

use crate::binary::{self, ErlDrvBinary};
use crate::task::fd_of;
use crate::{DrvFn1, ExitReason, asyncq, errno_id, port_of, select};

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

/// Port of erts/emulator/sys/common/erl_check_io.c:988 (driver_select), OTP-29.1.1.
#[unsafe(no_mangle)]
pub extern "C" fn driver_select(
    port: *mut c_void,
    event: *mut c_void,
    mode: c_int,
    on: c_int,
) -> c_int {
    let Some(port) = port_of(port) else {
        return -1;
    };
    select::driver_select(&port, fd_of(event), mode, on != 0)
}

/// Port of io.c:6900 (driver_set_timer). A driver without `timeout` gets the default
/// no-op callback of io.c:7535, so this never fails for a valid port.
#[unsafe(no_mangle)]
pub extern "C" fn driver_set_timer(port: *mut c_void, time: c_ulong) -> c_int {
    let Some(port) = port_of(port) else {
        return -1;
    };
    port.set_timer(time as i64);
    0
}

/// Port of io.c:6919 (driver_cancel_timer).
#[unsafe(no_mangle)]
pub extern "C" fn driver_cancel_timer(port: *mut c_void) -> c_int {
    let Some(port) = port_of(port) else {
        return -1;
    };
    port.cancel_timer();
    0
}

/// Port of io.c:6930 (driver_read_timer).
#[unsafe(no_mangle)]
pub extern "C" fn driver_read_timer(port: *mut c_void, time_left: *mut c_ulong) -> c_int {
    let Some(port) = port_of(port) else {
        return -1;
    };
    // SAFETY: the driver passes NULL or a writable `unsigned long`.
    if let Some(out) = unsafe { time_left.as_mut() } {
        *out = port.read_timer() as c_ulong;
    }
    0
}

/// Port of erl_port_task.c:1282 (erl_drv_consume_timeslice).
#[unsafe(no_mangle)]
pub extern "C" fn erl_drv_consume_timeslice(port: *mut c_void, percent: c_int) -> c_int {
    let Some(port) = port_of(port) else {
        return -1;
    };
    c_int::from(port.consume_timeslice(percent))
}

/// Port of erl_async.c:518 (driver_async_port_key): the port number spreads ports
/// over the async queues.
#[unsafe(no_mangle)]
pub extern "C" fn driver_async_port_key(port: *mut c_void) -> c_uint {
    port_of(port).map_or(0, |port| port.id as c_uint)
}

/// Port of erl_async.c:541 (driver_async).
#[unsafe(no_mangle)]
pub extern "C" fn driver_async(
    port: *mut c_void,
    key: *mut c_uint,
    async_invoke: Option<DrvFn1>,
    async_data: *mut c_void,
    async_free: Option<DrvFn1>,
) -> c_long {
    let (Some(port), Some(invoke)) = (port_of(port), async_invoke) else {
        return -1;
    };
    // SAFETY: the driver passes NULL or a writable `unsigned int` key.
    asyncq::driver_async(
        port,
        unsafe { key.as_mut() },
        invoke,
        async_data,
        async_free,
    )
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
            ("driver_select", driver_select as *const () as usize),
            ("driver_set_timer", driver_set_timer as *const () as usize),
            (
                "driver_cancel_timer",
                driver_cancel_timer as *const () as usize,
            ),
            ("driver_read_timer", driver_read_timer as *const () as usize),
            (
                "erl_drv_consume_timeslice",
                erl_drv_consume_timeslice as *const () as usize,
            ),
            (
                "driver_async_port_key",
                driver_async_port_key as *const () as usize,
            ),
            ("driver_async", driver_async as *const () as usize),
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
