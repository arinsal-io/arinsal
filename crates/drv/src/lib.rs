//! Linked-in driver host: loads OTP 29 `erl_driver.h` drivers and runs their callbacks.
//!
//! [`Driver::load`] is `do_load_driver_entry` (erl_bif_ddll.c) plus `init_driver`
//! (io.c). A [`DriverPort`] is the driver side of one port: `start`, `output`/`outputv`,
//! `control`, `call` and `stop`. The VM supplies a [`PortHost`] that delivers port
//! messages and exits, and it owns the port table and the ddll bookkeeping.
//!
//! The final executable must link this crate, call [`ensure_exports`], and export
//! its symbols (`-Wl,-export_dynamic` on macOS, `-rdynamic` on Linux).
#![allow(clippy::not_unsafe_ptr_arg_deref)]

#[macro_use]
mod export_macro;
pub mod api;
mod asyncq;
mod binary;
mod exports;
mod exports_lib;
mod ext;
mod hooks;
mod linebuf;
mod lock;
mod poll;
mod select;
mod task;
mod timer;

pub use asyncq::set_async_threads;
pub use poll::{PollBackend, set_poll_backend};
mod mem;
mod queue;
mod termspec;
mod threads;

/// Layout constants generated from the installed `erl_driver.h`.
#[allow(non_upper_case_globals, dead_code)]
pub mod layout {
    include!(concat!(env!("OUT_DIR"), "/layout.rs"));
}
mod errno_table {
    include!(concat!(env!("OUT_DIR"), "/errno.rs"));
}

use std::collections::HashMap;
use std::ffi::{CStr, CString, c_char, c_int, c_uint, c_void};
use std::mem::offset_of;
use std::sync::atomic::{AtomicI32, AtomicI64, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};

pub use binary::ErlDrvBinary;
pub use ext::{BUSY_MSGQ_DISABLED, ErlDrvMonitor, InitAck};
pub use hooks::{SystemHooks, set_system_hooks};
use linebuf::LineBuf;
use lock::{ReentrantGuard, ReentrantLock};

// Port of erts/emulator/beam/global.h:172-181 (ERL_DE_* load error codes), OTP-29.1.1.
/// No error.
pub const ERL_DE_NO_ERROR: i32 = 0;
/// No `driver_init` in the library.
pub const ERL_DE_LOAD_ERROR_NO_INIT: i32 = -1;
/// `driver_init` returned NULL or the entry's `init` failed.
pub const ERL_DE_LOAD_ERROR_FAILED_INIT: i32 = -2;
/// Entry name differs from the requested name.
pub const ERL_DE_LOAD_ERROR_BAD_NAME: i32 = -3;
/// Entry name too long.
pub const ERL_DE_LOAD_ERROR_NAME_TO_LONG: i32 = -4;
/// Entry built for an unsupported `erl_driver.h`.
pub const ERL_DE_LOAD_ERROR_INCORRECT_VERSION: i32 = -5;
/// No dynamic loading on this platform.
pub const ERL_DE_ERROR_NO_DDLL_FUNCTIONALITY: i32 = -6;
/// Unspecified error.
pub const ERL_DE_ERROR_UNSPECIFIED: i32 = -7;
/// Symbol lookup failed.
pub const ERL_DE_LOOKUP_ERROR_NOT_FOUND: i32 = -8;
/// First code of the `dlerror` string table.
pub const ERL_DE_DYNAMIC_ERROR_OFFSET: i32 = -10;

/// `PORT_CONTROL_FLAG_BINARY`.
pub const PORT_CONTROL_FLAG_BINARY: i32 = layout::PORT_CONTROL_FLAG_BINARY as i32;
const ERL_DRV_FLAG_USE_PORT_LOCKING: i32 = layout::ERL_DRV_FLAG_USE_PORT_LOCKING as i32;
const DRIVER_CALL_KEEP_BUFFER: c_uint = layout::DRIVER_CALL_KEEP_BUFFER as c_uint;
/// `ERL_ONHEAP_BINARY_LIMIT` (erl_bits.h): binaries above it are reference counted.
pub const ERL_ONHEAP_BINARY_LIMIT: usize = 64;
// Port of erts/emulator/beam/io.c:106-107, OTP-29.1.1.
const ERL_SMALL_IO_BIN_LIMIT: usize = 4 * ERL_ONHEAP_BINARY_LIMIT;
const SMALL_WRITE_VEC: usize = 16;
// Port of erts/emulator/beam/erl_vm.h:53 (CONTEXT_REDS) and erl_port.h:362-366
// (ERTS_PORT_REDS_*), OTP-29.1.1.
const CONTEXT_REDS: i32 = 4000;
const REDS_EXECUTE: i32 = CONTEXT_REDS / 4;
const CALLBACK_VREDS: i32 = CONTEXT_REDS / 20;
const REDS_TIMEOUT: i32 = CONTEXT_REDS / 100;
const REDS_INPUT: i32 = CONTEXT_REDS / 100;

type DrvData = *mut c_void;
type DrvPortPtr = *mut c_void;

// Shared callback signatures: one `unsafe` site per signature instead of one per field.
type InitFn = unsafe extern "C" fn() -> c_int;
type VoidFn = unsafe extern "C" fn();
type StartFn = unsafe extern "C" fn(DrvPortPtr, *mut c_char) -> DrvData;
/// `void (*)(void *)`: `stop`, `timeout`, `flush`, `emergency_close`, `async_invoke`.
pub(crate) type DrvFn1 = unsafe extern "C" fn(*mut c_void);
/// `void (*)(void *, void *)`: `ready_input`, `ready_output`, `ready_async`,
/// `process_exit` and `stop_select` (data or event first, one opaque pointer second).
pub(crate) type DrvFn2 = unsafe extern "C" fn(*mut c_void, *mut c_void);
type OutputFn = unsafe extern "C" fn(DrvData, *mut c_char, usize);
type OutputvFn = unsafe extern "C" fn(DrvData, *mut ErlIOVec);
type ControlFn =
    unsafe extern "C" fn(DrvData, c_uint, *mut c_char, usize, *mut *mut c_char, usize) -> isize;
type CallFn = unsafe extern "C" fn(
    DrvData,
    c_uint,
    *mut c_char,
    usize,
    *mut *mut c_char,
    usize,
    *mut c_uint,
) -> isize;

/// `struct erl_drv_entry` from erl_driver.h (non-`ERL_SYS_DRV` variant).
#[repr(C)]
#[derive(Clone, Copy)]
struct ErlDrvEntry {
    init: Option<InitFn>,
    start: Option<StartFn>,
    stop: Option<DrvFn1>,
    output: Option<OutputFn>,
    ready_input: Option<DrvFn2>,
    ready_output: Option<DrvFn2>,
    driver_name: *const c_char,
    finish: Option<VoidFn>,
    handle: *mut c_void,
    control: Option<ControlFn>,
    timeout: Option<DrvFn1>,
    outputv: Option<OutputvFn>,
    ready_async: Option<DrvFn2>,
    flush: Option<DrvFn1>,
    call: Option<CallFn>,
    unused_event_callback: Option<VoidFn>,
    extended_marker: c_int,
    major_version: c_int,
    minor_version: c_int,
    driver_flags: c_int,
    handle2: *mut c_void,
    process_exit: Option<extern "C" fn(DrvData, *mut ErlDrvMonitor)>,
    stop_select: Option<DrvFn2>,
    emergency_close: Option<DrvFn1>,
}

const _: () = assert!(size_of::<ErlDrvEntry>() == layout::SIZE_ErlDrvEntry);
const _: () = assert!(offset_of!(ErlDrvEntry, driver_name) == layout::OFF_ErlDrvEntry_driver_name);
const _: () = assert!(offset_of!(ErlDrvEntry, control) == layout::OFF_ErlDrvEntry_control);
const _: () = assert!(offset_of!(ErlDrvEntry, call) == layout::OFF_ErlDrvEntry_call);
const _: () =
    assert!(offset_of!(ErlDrvEntry, extended_marker) == layout::OFF_ErlDrvEntry_extended_marker);
const _: () =
    assert!(offset_of!(ErlDrvEntry, driver_flags) == layout::OFF_ErlDrvEntry_driver_flags);
const _: () =
    assert!(offset_of!(ErlDrvEntry, emergency_close) == layout::OFF_ErlDrvEntry_emergency_close);

/// `SysIOVec` (`struct iovec` on Unix).
#[repr(C)]
pub struct SysIOVec {
    /// Segment start.
    pub iov_base: *mut c_char,
    /// Segment length.
    pub iov_len: usize,
}

/// `ErlIOVec` passed to `outputv`.
#[repr(C)]
pub struct ErlIOVec {
    /// Number of segments.
    pub vsize: c_int,
    /// Total size in bytes.
    pub size: usize,
    /// Segments.
    pub iov: *mut SysIOVec,
    /// Binary owning each segment.
    pub binv: *mut *mut ErlDrvBinary,
}

const _: () = assert!(size_of::<SysIOVec>() == layout::SIZE_SysIOVec);
const _: () = assert!(size_of::<ErlIOVec>() == layout::SIZE_ErlIOVec);
const _: () = assert!(offset_of!(ErlIOVec, binv) == layout::OFF_ErlIOVec_binv);

/// Callbacks of a loaded entry (`erts_driver_t`, io.c:7554 init_driver).
#[derive(Clone, Copy)]
pub(crate) struct Callbacks {
    start: Option<StartFn>,
    stop: Option<DrvFn1>,
    finish: Option<VoidFn>,
    output: Option<OutputFn>,
    outputv: Option<OutputvFn>,
    control: Option<ControlFn>,
    call: Option<CallFn>,
    pub(crate) ready_input: Option<DrvFn2>,
    pub(crate) ready_output: Option<DrvFn2>,
    pub(crate) timeout: Option<DrvFn1>,
    pub(crate) ready_async: Option<DrvFn2>,
    pub(crate) stop_select: Option<DrvFn2>,
    process_exit: Option<extern "C" fn(DrvData, *mut ErlDrvMonitor)>,
}

/// A loaded dynamic driver (`erts_driver_t` with its `DE_Handle` library).
pub struct Driver {
    name: String,
    flags: i32,
    pub(crate) callbacks: Callbacks,
    /// `dlopen` handle; zero once closed.
    library: Mutex<usize>,
    /// Driver lock for drivers without `ERL_DRV_FLAG_USE_PORT_LOCKING` (io.c:7567).
    lock: Option<ReentrantLock>,
    /// Address of the `ErlDrvEntry` (`erts_driver_t.entry`).
    entry_addr: usize,
}

fn dl_errcodes() -> &'static Mutex<Vec<String>> {
    static CODES: OnceLock<Mutex<Vec<String>>> = OnceLock::new();
    CODES.get_or_init(|| Mutex::new(Vec::new()))
}

// Port of erts/emulator/sys/unix/erl_unix_sys_ddll.c:63 (find_errcode), OTP-29.1.1.
fn find_errcode(text: &str) -> i32 {
    let mut codes = dl_errcodes().lock().unwrap();
    let index = codes.iter().position(|s| s == text).unwrap_or_else(|| {
        codes.push(text.to_owned());
        codes.len() - 1
    });
    ERL_DE_DYNAMIC_ERROR_OFFSET - index as i32
}

fn last_dlerror() -> Option<String> {
    // SAFETY: dlerror returns null or a NUL-terminated thread-local string.
    let text = unsafe { libc::dlerror() };
    (!text.is_null()).then(|| {
        // SAFETY: a non-null result is NUL terminated and valid until the next dl call.
        unsafe { CStr::from_ptr(text) }
            .to_string_lossy()
            .into_owned()
    })
}

/// Port of erts/emulator/beam/erl_bif_ddll.c:1219 (erts_ddll_error) and
/// erl_unix_sys_ddll.c:279 (erts_sys_ddll_error), OTP-29.1.1.
pub fn ddll_error(code: i32) -> String {
    match code {
        ERL_DE_NO_ERROR => "No error".into(),
        ERL_DE_LOAD_ERROR_NO_INIT => "No driver init in dynamic library".into(),
        ERL_DE_LOAD_ERROR_FAILED_INIT => "Driver init failed".into(),
        ERL_DE_LOAD_ERROR_BAD_NAME => "Bad driver name".into(),
        ERL_DE_LOAD_ERROR_NAME_TO_LONG => "Driver name to long".into(),
        ERL_DE_LOAD_ERROR_INCORRECT_VERSION => {
            "Driver compiled with incorrect version of erl_driver.h".into()
        }
        ERL_DE_ERROR_NO_DDLL_FUNCTIONALITY => {
            "DDLL functionality not available on this platform".into()
        }
        ERL_DE_ERROR_UNSPECIFIED => "Unspecified dynamic library error".into(),
        ERL_DE_LOOKUP_ERROR_NOT_FOUND => "Symbol not found in dynamic library".into(),
        code if code > ERL_DE_DYNAMIC_ERROR_OFFSET => "Unspecified error".into(),
        code => {
            let index = (ERL_DE_DYNAMIC_ERROR_OFFSET - code) as usize;
            dl_errcodes()
                .lock()
                .unwrap()
                .get(index)
                .cloned()
                .unwrap_or_else(|| "Unknown dlload error".into())
        }
    }
}

/// Port of erts/emulator/sys/unix/erl_unix_sys_ddll.c:107-148 (erts_sys_ddll_open,
/// erts_sys_ddll_open_noext), OTP-29.1.1.
pub(crate) fn dl_open(full_name: &str) -> Result<usize, i32> {
    let dlname = format!("{full_name}.so");
    let path = CString::new(dlname.clone()).map_err(|_| ERL_DE_ERROR_UNSPECIFIED)?;
    last_dlerror();
    // SAFETY: path is NUL terminated; loading runs the library's initialisers.
    let handle = unsafe { libc::dlopen(path.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
    if !handle.is_null() {
        return Ok(handle as usize);
    }
    let text = last_dlerror().unwrap_or_default();
    let mut shown = text.as_str();
    if let Some(rest) = text.strip_prefix(dlname.as_str()) {
        let rest = rest.trim_start_matches([':', ' ']);
        if !rest.is_empty() {
            shown = rest;
        }
    }
    Err(find_errcode(shown))
}

pub(crate) fn dl_sym(handle: usize, name: &CStr) -> Result<*mut c_void, i32> {
    last_dlerror();
    // SAFETY: handle is a live dlopen handle and name is NUL terminated.
    let sym = unsafe { libc::dlsym(handle as *mut c_void, name.as_ptr()) };
    match last_dlerror() {
        Some(text) => Err(find_errcode(&text)),
        None => Ok(sym),
    }
}

/// Port of erl_unix_sys_ddll.c:268 (erts_sys_ddll_close2): `0` or an error code.
pub(crate) fn dl_close(handle: usize) -> i32 {
    last_dlerror();
    // SAFETY: the handle came from dlopen and no code from it runs any more.
    if unsafe { libc::dlclose(handle as *mut c_void) } == 0 {
        return ERL_DE_NO_ERROR;
    }
    find_errcode(&last_dlerror().unwrap_or_default())
}

impl Driver {
    /// Port of erts/emulator/beam/erl_bif_ddll.c:1499 (do_load_driver_entry) and
    /// io.c:7554 (init_driver), OTP-29.1.1. `path` excludes the `.so` extension.
    pub fn load(path: &str, name: &str) -> Result<Arc<Driver>, i32> {
        ensure_exports();
        let handle = dl_open(path)?;
        let fail = |code: i32| {
            dl_close(handle);
            Err(code)
        };
        // Port of erl_unix_sys_ddll.c:226 (erts_sys_ddll_load_driver_init).
        let init = match dl_sym(handle, c"driver_init").or_else(|_| dl_sym(handle, c"_driver_init"))
        {
            Ok(init) if !init.is_null() => init,
            _ => return fail(ERL_DE_LOAD_ERROR_NO_INIT),
        };
        // SAFETY: `driver_init` has the DRIVER_INIT signature `ErlDrvEntry *(void)`.
        let init: unsafe extern "C" fn() -> *const ErlDrvEntry =
            unsafe { std::mem::transmute(init) };
        // SAFETY: the library is loaded; driver_init returns static entry data or NULL.
        let entry_ptr = unsafe { init() };
        let Some(entry) = mem::deref(entry_ptr).copied() else {
            return fail(ERL_DE_LOAD_ERROR_FAILED_INIT);
        };
        if entry.extended_marker as u32 != layout::ERL_DRV_EXTENDED_MARKER as u32
            || i64::from(entry.major_version) < layout::ERL_DRV_MIN_REQUIRED_MAJOR_VERSION_ON_LOAD
            || layout::ERL_DRV_EXTENDED_MAJOR_VERSION < i64::from(entry.major_version)
            || (layout::ERL_DRV_EXTENDED_MAJOR_VERSION == i64::from(entry.major_version)
                && layout::ERL_DRV_EXTENDED_MINOR_VERSION < i64::from(entry.minor_version))
        {
            return fail(ERL_DE_LOAD_ERROR_INCORRECT_VERSION);
        }
        if entry.driver_name.is_null() {
            return fail(ERL_DE_LOAD_ERROR_BAD_NAME);
        }
        // SAFETY: driver_name is a NUL-terminated static string of the loaded library.
        let entry_name = unsafe { CStr::from_ptr(entry.driver_name) }.to_bytes();
        if entry_name != name.as_bytes() {
            return fail(ERL_DE_LOAD_ERROR_BAD_NAME);
        }
        let flags = entry.driver_flags;
        let driver = Arc::new(Driver {
            name: name.to_owned(),
            flags,
            callbacks: Callbacks {
                start: entry.start,
                stop: entry.stop,
                finish: entry.finish,
                output: entry.output,
                outputv: entry.outputv,
                control: entry.control,
                call: entry.call,
                ready_input: entry.ready_input,
                ready_output: entry.ready_output,
                timeout: entry.timeout,
                ready_async: entry.ready_async,
                stop_select: entry.stop_select,
                process_exit: entry.process_exit,
            },
            library: Mutex::new(handle),
            lock: (flags & ERL_DRV_FLAG_USE_PORT_LOCKING == 0).then(ReentrantLock::default),
            entry_addr: entry_ptr as usize,
        });
        if let Some(init) = entry.init {
            // SAFETY: the entry's init takes no arguments and runs once after loading.
            if unsafe { init() } != 0 {
                *driver.library.lock().unwrap() = 0;
                return fail(ERL_DE_LOAD_ERROR_FAILED_INIT);
            }
        }
        Ok(driver)
    }

    /// Port of erts/emulator/beam/io.c:7554 (init_driver) for an entry that is
    /// not in a library: one registered by `add_driver_entry`. `Err` carries
    /// the `ERL_DE_*` code when the entry is unusable or its `init` fails.
    pub(crate) fn linked(entry_ptr: *const ErlDrvEntry) -> Result<Arc<Driver>, i32> {
        let entry = mem::deref(entry_ptr)
            .copied()
            .ok_or(ERL_DE_LOAD_ERROR_FAILED_INIT)?;
        let name = mem::cstr(entry.driver_name).ok_or(ERL_DE_LOAD_ERROR_BAD_NAME)?;
        let flags = entry.driver_flags;
        let driver = Arc::new(Driver {
            name: name.to_string_lossy().into_owned(),
            flags,
            callbacks: Callbacks {
                start: entry.start,
                stop: entry.stop,
                finish: entry.finish,
                output: entry.output,
                outputv: entry.outputv,
                control: entry.control,
                call: entry.call,
                ready_input: entry.ready_input,
                ready_output: entry.ready_output,
                timeout: entry.timeout,
                ready_async: entry.ready_async,
                stop_select: entry.stop_select,
                process_exit: entry.process_exit,
            },
            library: Mutex::new(0),
            lock: (flags & ERL_DRV_FLAG_USE_PORT_LOCKING == 0).then(ReentrantLock::default),
            entry_addr: entry_ptr as usize,
        });
        if let Some(init) = entry.init {
            // SAFETY: the entry's init takes no arguments and runs once when it is added.
            if unsafe { init() } != 0 {
                return Err(ERL_DE_LOAD_ERROR_FAILED_INIT);
            }
        }
        Ok(driver)
    }

    /// Address of the driver's `ErlDrvEntry`, to match `remove_driver_entry`.
    pub fn entry_addr(&self) -> usize {
        self.entry_addr
    }

    /// Driver name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// `driver_flags` of the entry.
    pub fn flags(&self) -> i32 {
        self.flags
    }

    /// Port of erl_bif_ddll.c:1569 (do_unload_driver_entry): `finish`, then `dlclose`.
    /// The caller guarantees no port of this driver is alive.
    pub fn unload(&self) {
        let handle = std::mem::take(&mut *self.library.lock().unwrap());
        if handle == 0 {
            return;
        }
        if let Some(finish) = self.callbacks.finish {
            // SAFETY: the library is still loaded and no callback runs concurrently.
            unsafe { finish() };
        }
        dl_close(handle);
    }
}

/// Exit reason given to [`PortHost::exit`] (`driver_failure_term`, io.c:7191).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExitReason {
    /// `normal`.
    Normal,
    /// An integer reason from `driver_failure`.
    Code(i32),
    /// An atom reason.
    Atom(String),
}

/// Error from the `start` callback (io.c:542 erts_open_driver error types).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StartError {
    /// `ERL_DRV_ERROR_GENERAL`: `open_port` fails with `einval`.
    General,
    /// `ERL_DRV_ERROR_ERRNO`: `open_port` fails with the errno atom.
    Errno(i32),
    /// `ERL_DRV_ERROR_BADARG`.
    Badarg,
}

/// One piece of an `iodata` command in order: list bytes and heap binaries are
/// copied, reference-counted binaries may become their own `outputv` segment.
#[derive(Clone, Copy, Debug)]
pub enum IoPiece<'a> {
    /// Bytes copied into the common binary.
    Copied(&'a [u8]),
    /// Bytes of a reference-counted binary.
    Refc(&'a [u8]),
}

/// Result of a `control` callback (io.c:4100 write_port_control_result).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ControlReply {
    /// NULL result buffer: `[]`.
    Nil,
    /// Byte list.
    List(Vec<u8>),
    /// Binary (`PORT_CONTROL_FLAG_BINARY`).
    Binary(Vec<u8>),
}

/// Message delivery and exit handling supplied by the VM for one port.
pub trait PortHost: Send + Sync {
    /// A port task (`op` is `timeout`, `input` or `output`) ran for `elapsed_ns`; the host
    /// reports it to `erlang:system_monitor` long_schedule (erl_port_task.c:1838).
    fn task_done(&self, _port: &DriverPort, _op: &str, _elapsed_ns: u64) {}
    /// `{Port, {data, Data}}` (io.c:3357 deliver_read_message) to the connected
    /// process. `line` is `Some(eol)` for `{line, N}` ports.
    fn deliver_data(
        &self,
        port: &DriverPort,
        header: &[u8],
        data: Option<&[u8]>,
        binary: bool,
        line: Option<bool>,
    );
    /// `{Port, eof}` to the connected process (soft EOF).
    fn deliver_eof(&self, port: &DriverPort);
    /// `erts_deliver_port_exit(prt, prt->id, reason, 0, 0)`: the VM removes the
    /// port, signals links and monitors, and calls [`DriverPort::terminate`].
    fn exit(&self, port: &DriverPort, reason: ExitReason);
    /// Unlink the connected process (`driver_exit`).
    fn unlink_connected(&self, port: &DriverPort);
    /// `erts_send_error_to_logger_nogl`: an error report from the runtime itself.
    fn log_error(&self, text: &str);
    /// `erts_ddll_reference_referenced_driver`: an async job keeps the driver library
    /// loaded until [`PortHost::ddll_dereference`].
    fn ddll_reference(&self, port: &DriverPort);
    /// `erts_ddll_dereference_driver`.
    fn ddll_dereference(&self, port: &DriverPort);
    /// Port of io.c:3496 (deliver_vec_message): `{Port, {data, Data}}` where `Data`
    /// is `header` followed by the segments (one binary each with `binary`, else all
    /// bytes as one flat list; a single binary segment is not wrapped in a list).
    fn deliver_vec(&self, port: &DriverPort, header: &[u8], segments: &[Vec<u8>], binary: bool);
    /// Port of io.c:5658 (driver_deliver_term end): queue `{Port, Term}`-less
    /// `term` as a message from the port to process `to` (process-table data) or
    /// the connected process. `false` when the receiver does not exist.
    fn deliver_term(
        &self,
        port: &DriverPort,
        to: Option<u64>,
        term: &arinsal_etf::OwnedTerm,
    ) -> bool;
    /// Process-table data of the connected process (`ERTS_PORT_GET_CONNECTED`).
    fn connected(&self, port: &DriverPort) -> u64;
    /// Port of io.c:5203 (set_busy_port): `ERTS_PTS_FLG_BUSY_PORT`.
    fn set_busy(&self, port: &DriverPort, on: bool);
    /// Port of io.c:7006 (do_driver_monitor_process): monitor process `pid` for
    /// `port` under `monitor`. `false` when the process does not exist. When it
    /// exits the VM calls [`DriverPort::process_exit`].
    fn monitor_process(&self, port: &DriverPort, pid: u64, monitor: u64) -> bool;
    /// Port of io.c:7059 (do_driver_demonitor_process).
    fn demonitor_process(&self, port: &DriverPort, monitor: u64);
    /// Port of io.c:7318 (driver_lock_driver): make the driver permanent.
    fn lock_driver(&self, port: &DriverPort) -> bool;
    /// Port of io.c:2912 (init_ack_send_reply): answer the pending `open_port`.
    fn init_ack(&self, port: &DriverPort, reply: InitAck);
    /// Port of io.c:781 (driver_create_port): a new port of `creator`'s driver
    /// owned by (and linked to) `owner`, with `drv_data` as its driver data.
    fn create_port(
        &self,
        creator: &DriverPort,
        owner: u64,
        name: &str,
        drv_data: usize,
    ) -> Option<Arc<DriverPort>>;
}

const SFLG_BINARY_IO: u32 = 1;
const SFLG_SOFT_EOF: u32 = 2;
const SFLG_LINEBUF_IO: u32 = 4;
const SFLG_TERMINATING: u32 = 8;
const SFLG_STARTED: u32 = 16;

/// The driver side of one port (`Port` fields used by drivers in erts).
pub struct DriverPort {
    driver: Arc<Driver>,
    id: u64,
    host: Box<dyn PortHost>,
    drv_data: AtomicUsize,
    control_flags: AtomicI32,
    state: AtomicU32,
    linebuf: Mutex<Option<LineBuf>>,
    /// Caller during a callback (`prt->caller`): the pid data with [`CALLER_SET`], else zero.
    caller: AtomicU64,
    lock: Option<ReentrantLock>,
    /// `open_port` name (`prt->name`), set by [`DriverPort::start`].
    name: Mutex<String>,
    /// `prt->reds`: reductions used by the running task (`erl_drv_consume_timeslice`).
    reds: AtomicI32,
    timer: Mutex<timer::PortTimer>,
    timer_epoch: AtomicU64,
    /// `prt->ioq`.
    queue: Mutex<queue::IoQueue>,
    /// `prt->port_data_lock` (a `threads::PortDataLock`), zero when none.
    pdl: AtomicUsize,
    /// Process monitors held by this port: monitor id to process-table data.
    monitors: Mutex<HashMap<u64, u64>>,
    msgq_limits: Mutex<ext::MsgqLimits>,
    os_pid: AtomicI64,
    /// An `open_port` is waiting for `erl_drv_init_ack`.
    async_open: std::sync::atomic::AtomicBool,
}

/// Set in `DriverPort::caller` while a callback has a caller (pid data 0 is a valid pid).
const CALLER_SET: u64 = 1 << 63;

fn registry() -> &'static Mutex<HashMap<usize, Weak<DriverPort>>> {
    static PORTS: OnceLock<Mutex<HashMap<usize, Weak<DriverPort>>>> = OnceLock::new();
    PORTS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Live port for a driver-side handle (`erts_drvport2port`).
pub(crate) fn port_of(handle: DrvPortPtr) -> Option<Arc<DriverPort>> {
    registry()
        .lock()
        .unwrap()
        .get(&(handle as usize))
        .and_then(Weak::upgrade)
}

/// Live port by VM port number (`erts_port_lookup_raw`).
pub(crate) fn port_by_id(id: u64) -> Option<Arc<DriverPort>> {
    registry()
        .lock()
        .unwrap()
        .values()
        .filter_map(Weak::upgrade)
        .find(|port| port.id == id)
}

impl DriverPort {
    /// A port of `driver` with VM port id `id`; [`DriverPort::start`] runs the driver.
    pub fn new(driver: Arc<Driver>, id: u64, host: Box<dyn PortHost>) -> Arc<DriverPort> {
        let lock = driver.lock.is_none().then(ReentrantLock::default);
        let port = Arc::new(DriverPort {
            driver,
            id,
            host,
            drv_data: AtomicUsize::new(0),
            control_flags: AtomicI32::new(0),
            state: AtomicU32::new(0),
            linebuf: Mutex::new(None),
            caller: AtomicU64::new(0),
            lock,
            name: Mutex::new(String::new()),
            reds: AtomicI32::new(0),
            timer: Mutex::new(timer::PortTimer::None),
            timer_epoch: AtomicU64::new(0),
            queue: Mutex::new(queue::IoQueue::default()),
            pdl: AtomicUsize::new(0),
            monitors: Mutex::new(HashMap::new()),
            msgq_limits: Mutex::new(ext::MSGQ_LIMITS_DEFAULT),
            os_pid: AtomicI64::new(-1),
            async_open: std::sync::atomic::AtomicBool::new(false),
        });
        registry()
            .lock()
            .unwrap()
            .insert(port.handle() as usize, Arc::downgrade(&port));
        port
    }

    /// VM port id.
    pub fn id(&self) -> u64 {
        self.id
    }

    /// The port's driver.
    pub fn driver(&self) -> &Arc<Driver> {
        &self.driver
    }

    /// Caller during a callback as pid data, zero otherwise (`prt->caller`).
    pub fn caller(&self) -> u64 {
        self.caller_data().unwrap_or(0)
    }

    /// Pid data of the caller during a callback.
    pub(crate) fn caller_data(&self) -> Option<u64> {
        let caller = self.caller.load(Ordering::Acquire);
        (caller & CALLER_SET != 0).then_some(caller & !CALLER_SET)
    }

    fn set_caller(&self, caller: u64) {
        self.caller.store(caller | CALLER_SET, Ordering::Release);
    }

    fn clear_caller(&self) {
        self.caller.store(0, Ordering::Release);
    }

    /// Whether the port is closing (`ERTS_PORT_SFLG_CLOSING`).
    pub(crate) fn terminating(&self) -> bool {
        self.state.load(Ordering::Acquire) & SFLG_TERMINATING != 0
    }

    /// `prt->control_flags`.
    pub fn control_flags(&self) -> i32 {
        self.control_flags.load(Ordering::Acquire)
    }

    pub(crate) fn handle(&self) -> DrvPortPtr {
        std::ptr::from_ref(self).cast_mut().cast()
    }

    fn data(&self) -> DrvData {
        self.drv_data.load(Ordering::Acquire) as DrvData
    }

    /// Run `f` with the port lock held: a port signal (monitor, link) takes effect after
    /// the callback that currently owns the port finishes, like erts port signals.
    pub fn serialized<R>(&self, f: impl FnOnce() -> R) -> R {
        let _guard = self.guard();
        f()
    }

    fn guard(&self) -> ReentrantGuard<'_> {
        self.lock
            .as_ref()
            .or(self.driver.lock.as_ref())
            .expect("port or driver lock")
            .lock()
    }

    /// Reductions at the first task of a batch: `ERTS_PORT_REDS_EXECUTE` plus the
    /// virtual reductions added before every task (erl_port_task.c:1730, :1851).
    fn start_task(&self) {
        self.reds
            .store(REDS_EXECUTE + CALLBACK_VREDS, Ordering::Release);
    }

    fn add_reds(&self, reds: i32) {
        self.reds.fetch_add(reds, Ordering::AcqRel);
    }

    /// Port of erl_port_task.c:1282 (erl_drv_consume_timeslice): `true` when the task
    /// has used up its slice.
    pub(crate) fn consume_timeslice(&self, percent: c_int) -> bool {
        let percent = percent.clamp(1, 100);
        let used = percent * ((CONTEXT_REDS + 99) / 100);
        let total = self.reds.fetch_add(used, Ordering::AcqRel) + used;
        if total < CONTEXT_REDS {
            return false;
        }
        self.reds.store(CONTEXT_REDS, Ordering::Release);
        true
    }

    fn live(&self) -> bool {
        let state = self.state.load(Ordering::Acquire);
        state & SFLG_STARTED != 0 && state & SFLG_TERMINATING == 0
    }

    /// Port of io.c:542 (erts_open_driver, the `start` call). `command` is the
    /// whole `open_port` name; `caller` the raw pid term of the opening process.
    pub fn start(&self, command: &str, caller: u64) -> Result<(), StartError> {
        *self.name.lock().unwrap() = command.to_owned();
        let mut command = CString::new(command)
            .map_err(|_| StartError::Badarg)?
            .into_bytes_with_nul();
        let _guard = self.guard();
        self.state.fetch_or(SFLG_STARTED, Ordering::AcqRel);
        let Some(start) = self.driver.callbacks.start else {
            return Ok(());
        };
        self.set_caller(caller);
        // SAFETY: the command buffer is NUL terminated and outlives the call; the
        // handle stays registered while the port exists.
        let data = unsafe { start(self.handle(), command.as_mut_ptr().cast()) };
        // erts saves errno right after `start` for ERL_DRV_ERROR_ERRNO.
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        self.clear_caller();
        match data as isize {
            -1 => Err(StartError::General),
            -2 => Err(StartError::Errno(errno)),
            -3 => Err(StartError::Badarg),
            _ => {
                self.drv_data.store(data as usize, Ordering::Release);
                Ok(())
            }
        }
    }

    /// Drop a port whose `start` failed (io.c:747 error cleanup, no `stop`).
    pub fn abandon(&self) {
        self.state.fetch_or(SFLG_TERMINATING, Ordering::AcqRel);
        registry().lock().unwrap().remove(&(self.handle() as usize));
        self.release_resources();
    }

    /// Port state flags set by `open_port` after `start` (erl_bif_port.c:1140).
    pub fn set_io_flags(&self, binary: bool, soft_eof: bool, line: Option<usize>) {
        let mut flags = 0;
        if binary {
            flags |= SFLG_BINARY_IO;
        }
        if soft_eof {
            flags |= SFLG_SOFT_EOF;
        }
        if let Some(size) = line {
            flags |= SFLG_LINEBUF_IO;
            *self.linebuf.lock().unwrap() = Some(LineBuf::new(size));
        }
        self.state.fetch_or(flags, Ordering::AcqRel);
    }

    /// Port of io.c:1715 (erts_port_output): `outputv` when the driver has it,
    /// else `output` with the flattened data. `false` when the port is gone.
    pub fn output(&self, pieces: &[IoPiece<'_>], caller: u64) -> bool {
        let _guard = self.guard();
        if !self.live() {
            return false;
        }
        self.set_caller(caller);
        if let Some(outputv) = self.driver.callbacks.outputv {
            self.call_outputv(outputv, pieces);
        } else if let Some(output) = self.driver.callbacks.output {
            let mut buf = Vec::new();
            for piece in pieces {
                let (IoPiece::Copied(bytes) | IoPiece::Refc(bytes)) = piece;
                buf.extend_from_slice(bytes);
            }
            // SAFETY: the buffer outlives the call; drv_data came from start.
            unsafe { output(self.data(), buf.as_mut_ptr().cast(), buf.len()) };
        }
        self.clear_caller();
        true
    }

    fn call_outputv(&self, outputv: OutputvFn, pieces: &[IoPiece<'_>]) {
        let segments = vec_segments(pieces);
        let csize: usize = segments
            .iter()
            .filter(|s| !s.own)
            .map(|s| s.bytes.len())
            .sum();
        let total: usize = segments.iter().map(|s| s.bytes.len()).sum();
        let cbin = if csize > 0 {
            binary::alloc_binary(csize)
        } else {
            std::ptr::null_mut()
        };
        let mut iov = vec![SysIOVec {
            iov_base: std::ptr::null_mut(),
            iov_len: 0,
        }];
        let mut binv: Vec<*mut ErlDrvBinary> = vec![std::ptr::null_mut()];
        let mut owned = Vec::new();
        let mut offset = 0;
        for segment in &segments {
            if segment.own {
                let bin = binary::from_bytes(&segment.bytes);
                owned.push(bin);
                iov.push(SysIOVec {
                    iov_base: binary::bytes_ptr(bin).cast(),
                    iov_len: segment.bytes.len(),
                });
                binv.push(bin);
            } else {
                let base = binary::bytes_ptr(cbin).wrapping_add(offset);
                // SAFETY: cbin holds csize bytes and the copied segments sum to csize.
                unsafe {
                    std::ptr::copy_nonoverlapping(segment.bytes.as_ptr(), base, segment.bytes.len())
                };
                offset += segment.bytes.len();
                iov.push(SysIOVec {
                    iov_base: base.cast(),
                    iov_len: segment.bytes.len(),
                });
                binv.push(cbin);
            }
        }
        let mut ev = ErlIOVec {
            vsize: iov.len() as c_int,
            size: total,
            iov: iov.as_mut_ptr(),
            binv: binv.as_mut_ptr(),
        };
        // SAFETY: the vectors and binaries outlive the call; drivers keep binaries
        // past it only through driver_binary_inc_refc.
        unsafe { outputv(self.data(), &mut ev) };
        binary::free_binary(cbin);
        for bin in owned {
            binary::free_binary(bin);
        }
    }

    /// Port of io.c:4018 (call_driver_control) and io.c:4268 (erts_port_control).
    /// `None` is `badarg`.
    pub fn control(&self, command: u32, data: &[u8], caller: u64) -> Option<ControlReply> {
        let _guard = self.guard();
        if !self.live() {
            return None;
        }
        let control = self.driver.callbacks.control?;
        let mut input = data.to_vec();
        let mut resp_buf = [0u8; ERL_ONHEAP_BINARY_LIMIT];
        let pre: *mut c_char = resp_buf.as_mut_ptr().cast();
        let mut rbuf = pre;
        self.set_caller(caller);
        // SAFETY: input and the preallocated reply buffer outlive the call.
        let cres = unsafe {
            control(
                self.data(),
                command,
                input.as_mut_ptr().cast(),
                input.len(),
                &mut rbuf,
                resp_buf.len(),
            )
        };
        self.clear_caller();
        if cres < 0 {
            return None;
        }
        let size = cres as usize;
        if rbuf.is_null() {
            return Some(ControlReply::Nil);
        }
        // Port of io.c:4100 (write_port_control_result).
        let reply = if self.control_flags() & PORT_CONTROL_FLAG_BINARY != 0 {
            if rbuf == pre {
                ControlReply::Binary(resp_buf[..size.min(resp_buf.len())].to_vec())
            } else {
                let bin = rbuf.cast::<ErlDrvBinary>();
                let bytes = binary::bytes(bin);
                binary::free_binary(bin);
                ControlReply::Binary(bytes)
            }
        } else if rbuf == pre {
            ControlReply::List(resp_buf[..size.min(resp_buf.len())].to_vec())
        } else {
            // SAFETY: the driver returned a driver_alloc buffer of at least cres bytes.
            let bytes = unsafe { std::slice::from_raw_parts(rbuf.cast::<u8>(), size) }.to_vec();
            binary::free(rbuf.cast());
            ControlReply::List(bytes)
        };
        Some(reply)
    }

    /// Port of io.c:4460 (call_driver_call) and io.c:4618 (erts_port_call). `data` is
    /// the external term format of the argument; the result is the reply in external
    /// format. `None` is `badarg`.
    pub fn call(&self, command: u32, data: &[u8], caller: u64) -> Option<Vec<u8>> {
        let _guard = self.guard();
        if !self.live() {
            return None;
        }
        let call = self.driver.callbacks.call?;
        let mut input = data.to_vec();
        let mut resp_buf = [0u8; 255];
        let pre: *mut c_char = resp_buf.as_mut_ptr().cast();
        let mut rbuf = pre;
        let mut ret_flags: c_uint = 0;
        self.set_caller(caller);
        // SAFETY: input and the preallocated reply buffer outlive the call.
        let cres = unsafe {
            call(
                self.data(),
                command,
                input.as_mut_ptr().cast(),
                input.len(),
                &mut rbuf,
                resp_buf.len(),
                &mut ret_flags,
            )
        };
        self.clear_caller();
        let reply = if cres <= 0 || rbuf.is_null() {
            None
        } else if rbuf == pre {
            Some(resp_buf[..(cres as usize).min(resp_buf.len())].to_vec())
        } else {
            // SAFETY: the driver returned a buffer of at least cres bytes.
            Some(unsafe { std::slice::from_raw_parts(rbuf.cast::<u8>(), cres as usize) }.to_vec())
        };
        if rbuf != pre && !rbuf.is_null() && ret_flags & DRIVER_CALL_KEEP_BUFFER == 0 {
            binary::free(rbuf.cast());
        }
        reply.filter(|bytes| bytes.first() == Some(&131))
    }

    /// Port of io.c:3698 (terminate_port): run `stop` once and invalidate the handle.
    /// `true` when this call terminated the port.
    pub fn terminate(&self) -> bool {
        let _guard = self.guard();
        let previous = self.state.fetch_or(SFLG_TERMINATING, Ordering::AcqRel);
        if previous & SFLG_TERMINATING != 0 {
            return false;
        }
        // io.c:3725: the timer is cancelled before `stop`.
        self.cancel_timer();
        if previous & SFLG_STARTED != 0
            && let Some(stop) = self.driver.callbacks.stop
        {
            // SAFETY: drv_data came from start and stop runs once.
            unsafe { stop(self.data()) };
        }
        registry().lock().unwrap().remove(&(self.handle() as usize));
        self.release_resources();
        true
    }

    /// `driver_failure_atom` from outside a callback (erl_bif_ddll.c:123
    /// kill_ports_driver_unloaded), under the port lock.
    pub fn fail_atom(&self, reason: &str) {
        let _guard = self.guard();
        if self.live() {
            self.failure(ExitReason::Atom(reason.to_owned()), false);
        }
    }

    /// Port of io.c:6381 (driver_output2).
    fn output2(&self, header: &[u8], data: Option<&[u8]>) -> c_int {
        let state = self.state.load(Ordering::Acquire);
        if state & SFLG_TERMINATING != 0 {
            return 0;
        }
        let binary = state & SFLG_BINARY_IO != 0;
        if state & SFLG_LINEBUF_IO != 0 {
            // Port of io.c:3460 (deliver_linebuf_message).
            let lines = match self.linebuf.lock().unwrap().as_mut() {
                Some(linebuf) => linebuf.read(data.unwrap_or_default()),
                None => Vec::new(),
            };
            for (line, eol) in lines {
                self.host
                    .deliver_data(self, header, Some(&line), binary, Some(eol));
            }
        } else {
            self.host.deliver_data(self, header, data, binary, None);
        }
        0
    }

    /// Port of io.c:7191 (driver_failure_term).
    fn failure(&self, reason: ExitReason, eof: bool) -> c_int {
        let state = self.state.load(Ordering::Acquire);
        if eof && state & SFLG_LINEBUF_IO != 0 {
            // Port of io.c:3478 (flush_linebuf_messages).
            let lines = match self.linebuf.lock().unwrap().as_mut() {
                Some(linebuf) => linebuf.flush(),
                None => Vec::new(),
            };
            let binary = state & SFLG_BINARY_IO != 0;
            for (line, eol) in lines {
                self.host
                    .deliver_data(self, &[], Some(&line), binary, Some(eol));
            }
        }
        if state & SFLG_TERMINATING != 0 {
            return 0;
        }
        if eof && state & SFLG_SOFT_EOF != 0 {
            self.host.deliver_eof(self);
        } else {
            self.host
                .exit(self, if eof { ExitReason::Normal } else { reason });
        }
        0
    }
}

/// One `outputv` segment before it is laid out.
struct Segment {
    bytes: Vec<u8>,
    /// Its own binary (a reference-counted binary) rather than the common one.
    own: bool,
}

/// Port of erts/emulator/beam/erl_io_queue.c:441 (erts_ioq_iolist_to_vec) with the
/// packing decision of io.c:1790 (erts_port_output, SMALL_WRITE_VEC), OTP-29.1.1.
fn vec_segments(pieces: &[IoPiece<'_>]) -> Vec<Segment> {
    // Port of erl_io_queue.c:568 (io_list_vec_count): unpacked segment count.
    let mut vsize = 0;
    let mut in_clist = false;
    for piece in pieces {
        match piece {
            IoPiece::Refc(_) => {
                vsize += 1;
                in_clist = false;
            }
            IoPiece::Copied(_) => {
                if !in_clist {
                    in_clist = true;
                    vsize += 1;
                }
            }
        }
    }
    let blimit = if vsize < SMALL_WRITE_VEC {
        0
    } else {
        ERL_SMALL_IO_BIN_LIMIT
    };
    let mut out = Vec::new();
    let mut run = Vec::new();
    for piece in pieces {
        match *piece {
            IoPiece::Refc(bytes) if bytes.len() >= blimit => {
                if !run.is_empty() {
                    out.push(Segment {
                        bytes: std::mem::take(&mut run),
                        own: false,
                    });
                }
                out.push(Segment {
                    bytes: bytes.to_vec(),
                    own: true,
                });
            }
            IoPiece::Copied(bytes) | IoPiece::Refc(bytes) => run.extend_from_slice(bytes),
        }
    }
    if !run.is_empty() {
        out.push(Segment {
            bytes: run,
            own: false,
        });
    }
    out
}

/// `erl_errno_id` names for this platform (erts/emulator/beam/erl_errno_str.c:1229).
pub fn errno_id(eno: i32) -> String {
    errno_table::ERRNO_NAMES
        .iter()
        .find(|(code, _)| *code == eno)
        .map(|(_, name)| (*name).to_owned())
        .unwrap_or_else(|| format!("errno_{eno}"))
}

/// Keep the C driver API in the final executable.
pub fn ensure_exports() {
    exports::retain_exports();
}
