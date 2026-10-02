//! Driver library API: queues, term output, monitors, threads, time, environment.
//!
//! Ports of the functions of erts/emulator/beam/io.c, erl_drv_thread.c and
//! erl_time_sup.c named in each doc comment (OTP-29.1.1).

use std::cell::Cell;
use std::collections::HashMap;
use std::ffi::{CStr, CString, c_char, c_int, c_ulong, c_void};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use crate::binary::{self, ErlDrvBinary};
use crate::exports::driver_output2;
use crate::hooks::hooks;
use crate::queue::skip_in_place;
use crate::termspec::{self, NIL};
use crate::{
    ErlDrvMonitor, ErlIOVec, SysIOVec, ddll_error, dl_close, dl_open, dl_sym, layout, mem, port_of,
    threads,
};

/// Whether `port` names a live port, for functions that return a default.
fn port_id_of(word: usize) -> Option<std::sync::Arc<crate::DriverPort>> {
    crate::port_by_id(termspec::port_id(word)?)
}

/// The segments of `ev` after `skip` leading bytes, as bytes (driver_outputv).
fn segments_after(ev: &ErlIOVec, skip: usize) -> Vec<Vec<u8>> {
    let Some(first) = skip_in_place(ev, skip) else {
        return Vec::new();
    };
    let count = usize::try_from(ev.vsize).unwrap_or(0);
    mem::slice(ev.iov.cast_const(), count)[first..]
        .iter()
        .map(|segment| {
            mem::slice(segment.iov_base.cast_const().cast::<u8>(), segment.iov_len).to_vec()
        })
        .collect()
}

/// Enqueue `len` bytes of `bin` at `offs` (driver_enq_bin, driver_pushq_bin).
fn enq_one(
    port: *mut c_void,
    bin: *mut ErlDrvBinary,
    offs: usize,
    len: usize,
    front: bool,
) -> c_int {
    if len == 0 {
        return 0;
    }
    let Some(port) = port_of(port) else {
        return -1;
    };
    let mut iov = SysIOVec {
        iov_base: binary::bytes_ptr(bin).wrapping_add(offs).cast(),
        iov_len: len,
    };
    let mut bin = bin;
    let ev = ErlIOVec {
        vsize: 1,
        size: len,
        iov: &mut iov,
        binv: &mut bin,
    };
    let mut queue = port.queue();
    if front {
        queue.pushqv(&ev, 0)
    } else {
        queue.enqv(&ev, 0)
    }
}

/// Copy `buf` into a fresh binary and queue it (driver_enq, driver_pushq).
fn enq_copy(port: *mut c_void, buf: *mut c_char, len: usize, front: bool) -> c_int {
    if len == 0 {
        return 0;
    }
    let bin = binary::from_bytes(mem::slice(buf.cast::<u8>(), len));
    if bin.is_null() {
        return -1;
    }
    let code = enq_one(port, bin, 0, len, front);
    binary::free_binary(bin);
    code
}

fn enq_vec(port: *mut c_void, ev: *mut ErlIOVec, skip: usize, front: bool) -> c_int {
    let (Some(port), Some(ev)) = (port_of(port), mem::deref(ev.cast_const())) else {
        return -1;
    };
    let mut queue = port.queue();
    if front {
        queue.pushqv(ev, skip)
    } else {
        queue.enqv(ev, skip)
    }
}

/// `ErlDrvSysInfo` (erl_drv_nif.h).
#[repr(C)]
pub struct ErlDrvSysInfo {
    driver_major_version: c_int,
    driver_minor_version: c_int,
    erts_version: *const c_char,
    otp_release: *const c_char,
    thread_support: c_int,
    smp_support: c_int,
    async_threads: c_int,
    scheduler_threads: c_int,
    nif_major_version: c_int,
    nif_minor_version: c_int,
    dirty_scheduler_support: c_int,
}

const _: () = assert!(size_of::<ErlDrvSysInfo>() == layout::SIZE_ErlDrvSysInfo);
const _: () = assert!(
    std::mem::offset_of!(ErlDrvSysInfo, scheduler_threads)
        == layout::OFF_ErlDrvSysInfo_scheduler_threads
);
const _: () = assert!(
    std::mem::offset_of!(ErlDrvSysInfo, dirty_scheduler_support)
        == layout::OFF_ErlDrvSysInfo_dirty_scheduler_support
);

/// `ERL_DRV_SYS_INFO_SIZE(field)`.
const fn info_size(offset: usize, size: usize) -> usize {
    offset + size
}

/// ERTS version and OTP release of the reference system (erts-17.1, OTP 29).
const ERTS_VERSION: &CStr = c"17.1";
const OTP_RELEASE: &CStr = c"29";

/// Port of io.c:7438 (driver_system_info): fields by the size the driver was built with.
fn system_info(sip: *mut ErlDrvSysInfo, si_size: usize) {
    let smp = info_size(layout::OFF_ErlDrvSysInfo_smp_support, size_of::<c_int>());
    let Some(info) = mem::deref_mut(sip).filter(|_| si_size >= smp) else {
        eprintln!("driver_system_info({sip:p}, {si_size}) called with invalid arguments");
        std::process::exit(1);
    };
    info.driver_major_version = layout::ERL_DRV_EXTENDED_MAJOR_VERSION as c_int;
    info.driver_minor_version = layout::ERL_DRV_EXTENDED_MINOR_VERSION as c_int;
    info.erts_version = ERTS_VERSION.as_ptr();
    info.otp_release = OTP_RELEASE.as_ptr();
    info.thread_support = 1;
    info.smp_support = 1;
    if si_size
        >= info_size(
            layout::OFF_ErlDrvSysInfo_scheduler_threads,
            size_of::<c_int>(),
        )
    {
        let hooks = hooks();
        info.async_threads = hooks.map_or(1, |h| h.async_threads()) as c_int;
        info.scheduler_threads = hooks.map_or_else(
            || std::thread::available_parallelism().map_or(1, usize::from),
            |h| h.scheduler_threads(),
        ) as c_int;
    }
    if si_size
        >= info_size(
            layout::OFF_ErlDrvSysInfo_nif_minor_version,
            size_of::<c_int>(),
        )
    {
        info.nif_major_version = layout::ERL_NIF_MAJOR_VERSION as c_int;
        info.nif_minor_version = layout::ERL_NIF_MINOR_VERSION as c_int;
    }
    if si_size
        >= info_size(
            layout::OFF_ErlDrvSysInfo_dirty_scheduler_support,
            size_of::<c_int>(),
        )
    {
        info.dirty_scheduler_support = 1;
    }
}

/// `ERTS_NAPI_TIME_ERROR__`.
const TIME_ERROR: i64 = i64::MIN;

fn unit_frequency(unit: c_int) -> Option<i128> {
    match unit {
        0 => Some(1),
        1 => Some(1_000),
        2 => Some(1_000_000),
        3 => Some(1_000_000_000),
        _ => None,
    }
}

/// Fallback clock when the VM installed no hooks: nanoseconds since first use.
fn local_monotonic() -> i128 {
    static START: OnceLock<Instant> = OnceLock::new();
    START.get_or_init(Instant::now).elapsed().as_nanos() as i128
}

fn scale(nanos: i128, unit: c_int) -> i64 {
    unit_frequency(unit).map_or(TIME_ERROR, |freq| {
        i64::try_from(nanos.div_euclid(1_000_000_000 / freq)).unwrap_or(TIME_ERROR)
    })
}

/// Port of erl_time_sup.c:2461 (erts_napi_convert_time_unit).
fn convert_time_unit(val: i64, from: c_int, to: c_int) -> i64 {
    let (Some(from), Some(to)) = (unit_frequency(from), unit_frequency(to)) else {
        return TIME_ERROR;
    };
    if to >= from {
        return val.wrapping_mul((to / from) as i64);
    }
    let denom = (from / to) as i64;
    if val >= 0 {
        val / denom
    } else {
        (val - (denom - 1)) / denom
    }
}

/// Port of io.c:6951 (driver_get_now): a `now()`-style strictly increasing timestamp.
fn now_micros() -> u64 {
    static LAST: AtomicU64 = AtomicU64::new(0);
    let wall = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros() as u64;
    let mut last = LAST.load(Ordering::Acquire);
    loop {
        let next = wall.max(last + 1);
        match LAST.compare_exchange(last, next, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return next,
            Err(seen) => last = seen,
        }
    }
}

thread_local! {
    /// The slot erts calls `driver_list_lock_status_key`: `driver_dl_sym` stores its
    /// error there and `driver_dl_error` reads it (io.c:7393, 7422).
    static DL_ERROR: Cell<Option<c_int>> = const { Cell::new(None) };
}

/// Message text of a `ddll` error code that lives for the process.
fn error_text(code: c_int) -> *mut c_char {
    static TEXTS: OnceLock<Mutex<HashMap<String, &'static CStr>>> = OnceLock::new();
    let message = ddll_error(code);
    let mut texts = TEXTS
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .unwrap();
    let text = texts.entry(message.clone()).or_insert_with(|| {
        Box::leak(
            CString::new(message.replace('\0', "?"))
                .expect("no NUL")
                .into_boxed_c_str(),
        )
    });
    text.as_ptr().cast_mut()
}

export! {
    table lib_table;

    /// Port of erl_port_task.c:772 (erl_drv_busy_msgq_limits).
    fn erl_drv_busy_msgq_limits(port: *mut c_void, lowp: *mut usize, highp: *mut usize) {
        match port_of(port) {
            Some(port) => port.busy_msgq_limits(mem::deref_mut(lowp), mem::deref_mut(highp)),
            None => {
                for limit in [mem::deref_mut(lowp), mem::deref_mut(highp)].into_iter().flatten() {
                    *limit = crate::ext::BUSY_MSGQ_DISABLED;
                }
            }
        }
    }

    /// Port of io.c:6333 (driver_output_binary).
    fn driver_output_binary(
        port: *mut c_void,
        hbuf: *mut c_char,
        hlen: usize,
        bin: *mut ErlDrvBinary,
        offs: usize,
        len: usize,
    ) -> c_int {
        let Some(port) = port_of(port) else {
            return -1;
        };
        port.output_vec(
            mem::slice(hbuf.cast::<u8>(), hlen),
            &[binary::read(bin, offs, len)],
        )
    }

    /// Port of io.c:6442 (driver_outputv).
    fn driver_outputv(
        port: *mut c_void,
        hbuf: *mut c_char,
        hlen: usize,
        vec: *mut ErlIOVec,
        skip: usize,
    ) -> c_int {
        let Some(ev) = mem::deref(vec.cast_const()) else {
            return -1;
        };
        if ev.size <= skip {
            return driver_output2(port, hbuf, hlen, std::ptr::null_mut(), 0);
        }
        let Some(port) = port_of(port) else {
            return -1;
        };
        port.output_vec(mem::slice(hbuf.cast::<u8>(), hlen), &segments_after(ev, skip))
    }

    /// Port of io.c:6504 (driver_vec_to_buf).
    fn driver_vec_to_buf(vec: *mut ErlIOVec, buf: *mut c_char, len: usize) -> usize {
        let Some(ev) = mem::deref(vec.cast_const()) else {
            return 0;
        };
        let out = mem::slice_mut(buf.cast::<u8>(), len);
        let mut remaining = len;
        for segment in mem::slice(ev.iov.cast_const(), usize::try_from(ev.vsize).unwrap_or(0)) {
            let bytes = mem::slice(segment.iov_base.cast_const().cast::<u8>(), segment.iov_len);
            let done = len - remaining;
            if bytes.len() < remaining {
                out[done..done + bytes.len()].copy_from_slice(bytes);
                remaining -= bytes.len();
            } else {
                out[done..].copy_from_slice(&bytes[..remaining]);
                return len;
            }
        }
        len - remaining
    }

    /// Port of io.c:6711 (driver_pdl_create).
    fn driver_pdl_create(port: *mut c_void) -> *mut c_void {
        let Some(port) = port_of(port) else {
            return std::ptr::null_mut();
        };
        let pdl = threads::pdl_new();
        match port.pdl.compare_exchange(0, pdl as usize, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => pdl.cast(),
            Err(_) => {
                threads::pdl_dec(pdl);
                std::ptr::null_mut()
            }
        }
    }

    /// Port of io.c:6731 (driver_pdl_lock).
    fn driver_pdl_lock(pdl: *mut c_void) {
        threads::pdl_lock(pdl.cast());
    }

    /// Port of io.c:6741 (driver_pdl_unlock).
    fn driver_pdl_unlock(pdl: *mut c_void) {
        threads::pdl_unlock(pdl.cast());
    }

    /// Port of io.c:6754 (driver_pdl_get_refc).
    fn driver_pdl_get_refc(pdl: *mut c_void) -> isize {
        threads::pdl_refc(pdl.cast())
    }

    /// Port of io.c:6760 (driver_pdl_inc_refc).
    fn driver_pdl_inc_refc(pdl: *mut c_void) -> isize {
        threads::pdl_inc(pdl.cast())
    }

    /// Port of io.c:6771 (driver_pdl_dec_refc).
    fn driver_pdl_dec_refc(pdl: *mut c_void) -> isize {
        threads::pdl_dec(pdl.cast())
    }

    /// Port of io.c:7037 (driver_monitor_process).
    fn driver_monitor_process(port: *mut c_void, process: usize, monitor: *mut ErlDrvMonitor) -> c_int {
        let (Some(port), Some(monitor)) = (port_of(port), mem::deref_mut(monitor)) else {
            return -1;
        };
        port.monitor_process(process, monitor)
    }

    /// Port of io.c:7077 (driver_demonitor_process).
    fn driver_demonitor_process(port: *mut c_void, monitor: *const ErlDrvMonitor) -> c_int {
        let (Some(port), Some(monitor)) = (port_of(port), mem::deref(monitor)) else {
            return -1;
        };
        port.demonitor_process(monitor)
    }

    /// Port of io.c:7115 (driver_get_monitored_process).
    fn driver_get_monitored_process(port: *mut c_void, monitor: *const ErlDrvMonitor) -> usize {
        let (Some(port), Some(monitor)) = (port_of(port), mem::deref(monitor)) else {
            return NIL;
        };
        port.monitored_word(monitor)
    }

    /// Port of io.c:7136 (driver_compare_monitors): a memcmp of the two monitors.
    fn driver_compare_monitors(first: *const ErlDrvMonitor, second: *const ErlDrvMonitor) -> c_int {
        match (mem::deref(first), mem::deref(second)) {
            (Some(a), Some(b)) => a.bytes().cmp(b.bytes()) as c_int,
            _ => 0,
        }
    }

    /// Port of io.c:5203 (set_busy_port).
    fn set_busy_port(port: *mut c_void, on: c_int) {
        if let Some(port) = port_of(port) {
            port.host.set_busy(&port, on != 0);
        }
    }

    /// Port of io.c:5319 (get_port_flags).
    fn get_port_flags(port: *mut c_void) -> c_int {
        port_of(port).map_or(0, |port| port.port_flags())
    }

    /// Port of io.c:6852 (driver_enq).
    fn driver_enq(port: *mut c_void, buf: *mut c_char, len: usize) -> c_int {
        enq_copy(port, buf, len, false)
    }

    /// Port of io.c:6886 (driver_pushq).
    fn driver_pushq(port: *mut c_void, buf: *mut c_char, len: usize) -> c_int {
        enq_copy(port, buf, len, true)
    }

    /// Port of io.c:6801 (driver_deq): the bytes left, `-1` for too many bytes.
    fn driver_deq(port: *mut c_void, size: usize) -> usize {
        let Some(port) = port_of(port) else {
            return usize::MAX;
        };
        let mut queue = port.queue();
        if queue.deq(size) {
            queue.size()
        } else {
            usize::MAX
        }
    }

    /// Port of io.c:6821 (driver_sizeq).
    fn driver_sizeq(port: *mut c_void) -> usize {
        port_of(port).map_or(usize::MAX, |port| port.queue().size())
    }

    /// Port of io.c:6834 (driver_enq_bin).
    fn driver_enq_bin(port: *mut c_void, bin: *mut ErlDrvBinary, offs: usize, len: usize) -> c_int {
        enq_one(port, bin, offs, len, false)
    }

    /// Port of io.c:6868 (driver_pushq_bin).
    fn driver_pushq_bin(port: *mut c_void, bin: *mut ErlDrvBinary, offs: usize, len: usize) -> c_int {
        enq_one(port, bin, offs, len, true)
    }

    /// Port of io.c:6810 (driver_peekqv).
    fn driver_peekqv(port: *mut c_void, ev: *mut ErlIOVec) -> usize {
        let (Some(port), Some(ev)) = (port_of(port), mem::deref_mut(ev)) else {
            return usize::MAX;
        };
        port.queue().peekqv(ev)
    }

    /// Port of io.c:6815 (driver_peekq).
    fn driver_peekq(port: *mut c_void, vlen: *mut c_int) -> *mut SysIOVec {
        let Some(port) = port_of(port) else {
            if let Some(vlen) = mem::deref_mut(vlen) {
                *vlen = -1;
            }
            return std::ptr::null_mut();
        };
        let (iov, count) = port.queue().peekq();
        if let Some(vlen) = mem::deref_mut(vlen) {
            *vlen = count;
        }
        iov
    }

    /// Port of io.c:6784 (driver_enqv).
    fn driver_enqv(port: *mut c_void, ev: *mut ErlIOVec, skip: usize) -> c_int {
        enq_vec(port, ev, skip, false)
    }

    /// Port of io.c:6791 (driver_pushqv).
    fn driver_pushqv(port: *mut c_void, ev: *mut ErlIOVec, skip: usize) -> c_int {
        enq_vec(port, ev, skip, true)
    }

    /// Port of io.c:7626 (add_driver_entry): the init result is ignored for drivers
    /// added by drivers, as in erts.
    fn add_driver_entry(entry: *mut c_void) {
        let (Some(hooks), Ok(driver)) = (hooks(), crate::Driver::linked(entry.cast())) else {
            return;
        };
        hooks.add_driver(driver);
    }

    /// Port of io.c:7684 (remove_driver_entry).
    fn remove_driver_entry(entry: *mut c_void) -> c_int {
        hooks().map_or(0, |hooks| hooks.remove_driver(entry as usize))
    }

    /// Port of io.c:7438 (driver_system_info).
    fn driver_system_info(sip: *mut ErlDrvSysInfo, si_size: usize) {
        system_info(sip, si_size);
    }

    /// Port of erl_drv_thread.c:154 (erl_drv_mutex_create).
    fn erl_drv_mutex_create(name: *mut c_char) -> *mut c_void {
        threads::mutex_create(name)
    }

    /// Port of erl_drv_thread.c:184 (erl_drv_mutex_destroy).
    fn erl_drv_mutex_destroy(mutex: *mut c_void) {
        threads::mutex_destroy(mutex);
    }

    /// Port of erl_drv_thread.c:198 (erl_drv_mutex_name).
    fn erl_drv_mutex_name(mutex: *mut c_void) -> *mut c_char {
        threads::mutex_name(mutex)
    }

    /// Port of erl_drv_thread.c:204 (erl_drv_mutex_trylock).
    fn erl_drv_mutex_trylock(mutex: *mut c_void) -> c_int {
        threads::mutex_trylock(mutex)
    }

    /// Port of erl_drv_thread.c:220 (erl_drv_mutex_lock).
    fn erl_drv_mutex_lock(mutex: *mut c_void) {
        threads::mutex_lock(mutex);
    }

    /// Port of erl_drv_thread.c:237 (erl_drv_mutex_unlock).
    fn erl_drv_mutex_unlock(mutex: *mut c_void) {
        threads::mutex_unlock(mutex);
    }

    /// Port of erl_drv_thread.c:251 (erl_drv_cond_create).
    fn erl_drv_cond_create(name: *mut c_char) -> *mut c_void {
        threads::cond_create(name)
    }

    /// Port of erl_drv_thread.c:274 (erl_drv_cond_destroy).
    fn erl_drv_cond_destroy(cond: *mut c_void) {
        threads::cond_destroy(cond);
    }

    /// Port of erl_drv_thread.c:283 (erl_drv_cond_name).
    fn erl_drv_cond_name(cond: *mut c_void) -> *mut c_char {
        threads::cond_name(cond)
    }

    /// Port of erl_drv_thread.c:289 (erl_drv_cond_signal).
    fn erl_drv_cond_signal(cond: *mut c_void) {
        threads::cond_signal(cond);
    }

    /// Port of erl_drv_thread.c:297 (erl_drv_cond_broadcast).
    fn erl_drv_cond_broadcast(cond: *mut c_void) {
        threads::cond_broadcast(cond);
    }

    /// Port of erl_drv_thread.c:306 (erl_drv_cond_wait).
    fn erl_drv_cond_wait(cond: *mut c_void, mutex: *mut c_void) {
        threads::cond_wait(cond, mutex);
    }

    /// Port of erl_drv_thread.c:327 (erl_drv_rwlock_create).
    fn erl_drv_rwlock_create(name: *mut c_char) -> *mut c_void {
        threads::rwlock_create(name)
    }

    /// Port of erl_drv_thread.c:352 (erl_drv_rwlock_destroy).
    fn erl_drv_rwlock_destroy(lock: *mut c_void) {
        threads::rwlock_destroy(lock);
    }

    /// Port of erl_drv_thread.c:365 (erl_drv_rwlock_name).
    fn erl_drv_rwlock_name(lock: *mut c_void) -> *mut c_char {
        threads::rwlock_name(lock)
    }

    /// Port of erl_drv_thread.c:371 (erl_drv_rwlock_tryrlock).
    fn erl_drv_rwlock_tryrlock(lock: *mut c_void) -> c_int {
        threads::rwlock_tryrlock(lock)
    }

    /// Port of erl_drv_thread.c:384 (erl_drv_rwlock_rlock).
    fn erl_drv_rwlock_rlock(lock: *mut c_void) {
        threads::rwlock_rlock(lock);
    }

    /// Port of erl_drv_thread.c:398 (erl_drv_rwlock_runlock).
    fn erl_drv_rwlock_runlock(lock: *mut c_void) {
        threads::rwlock_runlock(lock);
    }

    /// Port of erl_drv_thread.c:409 (erl_drv_rwlock_tryrwlock).
    fn erl_drv_rwlock_tryrwlock(lock: *mut c_void) -> c_int {
        threads::rwlock_tryrwlock(lock)
    }

    /// Port of erl_drv_thread.c:422 (erl_drv_rwlock_rwlock).
    fn erl_drv_rwlock_rwlock(lock: *mut c_void) {
        threads::rwlock_rwlock(lock);
    }

    /// Port of erl_drv_thread.c:436 (erl_drv_rwlock_rwunlock).
    fn erl_drv_rwlock_rwunlock(lock: *mut c_void) {
        threads::rwlock_rwunlock(lock);
    }

    /// Port of erl_drv_thread.c:447 (erl_drv_tsd_key_create).
    fn erl_drv_tsd_key_create(name: *mut c_char, key: *mut c_int) -> c_int {
        threads::tsd_key_create(name, key)
    }

    /// Port of erl_drv_thread.c:519 (erl_drv_tsd_key_destroy).
    fn erl_drv_tsd_key_destroy(key: c_int) {
        threads::tsd_key_destroy(key);
    }

    /// Port of erl_drv_thread.c:541 (erl_drv_tsd_set).
    fn erl_drv_tsd_set(key: c_int, data: *mut c_void) {
        threads::tsd_set(key, data);
    }

    /// Port of erl_drv_thread.c:569 (erl_drv_tsd_get).
    fn erl_drv_tsd_get(key: c_int) -> *mut c_void {
        threads::tsd_get(key)
    }

    /// Port of erl_drv_thread.c:596 (erl_drv_thread_opts_destroy).
    fn erl_drv_thread_opts_destroy(opts: *mut c_void) {
        threads::thread_opts_destroy(opts);
    }

    /// Port of erl_drv_thread.c:585 (erl_drv_thread_opts_create).
    fn erl_drv_thread_opts_create(name: *mut c_char) -> *mut c_void {
        threads::thread_opts_create(name)
    }

    /// Port of erl_drv_thread.c:604 (erl_drv_thread_create).
    fn erl_drv_thread_create(
        name: *mut c_char,
        tid: *mut *mut c_void,
        func: extern "C" fn(*mut c_void) -> *mut c_void,
        arg: *mut c_void,
        opts: *mut c_void,
    ) -> c_int {
        threads::thread_create(name, tid, func, arg, opts)
    }

    /// Port of erl_drv_thread.c:664 (erl_drv_thread_self).
    fn erl_drv_thread_self() -> *mut c_void {
        threads::thread_self()
    }

    /// Port of erl_drv_thread.c:687 (erl_drv_equal_tids).
    fn erl_drv_equal_tids(first: *mut c_void, second: *mut c_void) -> c_int {
        threads::equal_tids(first, second)
    }

    /// Port of erl_drv_thread.c:705 (erl_drv_thread_exit).
    fn erl_drv_thread_exit(result: *mut c_void) {
        threads::thread_exit(result)
    }

    /// Port of erl_drv_thread.c:716 (erl_drv_thread_join).
    fn erl_drv_thread_join(tid: *mut c_void, result: *mut *mut c_void) -> c_int {
        threads::thread_join(tid, result)
    }

    /// Port of erl_drv_thread.c:656 (erl_drv_thread_name).
    fn erl_drv_thread_name(tid: *mut c_void) -> *mut c_char {
        threads::thread_name(tid)
    }

    /// Port of erl_drv_thread.c:737 (erl_drv_stolen_main_thread_join).
    fn erl_drv_stolen_main_thread_join(tid: *mut c_void, result: *mut *mut c_void) -> c_int {
        threads::stolen_join(tid, result)
    }

    /// Port of erl_drv_thread.c:750 (erl_drv_steal_main_thread).
    fn erl_drv_steal_main_thread(
        name: *mut c_char,
        tid: *mut *mut c_void,
        func: extern "C" fn(*mut c_void) -> *mut c_void,
        arg: *mut c_void,
        opts: *mut c_void,
    ) -> c_int {
        threads::steal_main_thread(name, tid, func, arg, opts)
    }

    /// Port of io.c:7726 (null_func).
    fn null_func() -> c_int {
        0
    }

    /// Port of io.c:7279 (driver_mk_atom): `erts_atom_put` of Latin-1 text.
    fn driver_mk_atom(string: *mut c_char) -> usize {
        termspec::mk_atom(mem::cstr(string).map_or(&[][..], CStr::to_bytes))
    }

    /// Port of io.c:7289 (driver_mk_port).
    fn driver_mk_port(port: *mut c_void) -> usize {
        port_of(port).map_or(NIL, |port| termspec::mk_port(port.id()))
    }

    /// Port of io.c:7298 (driver_connected).
    fn driver_connected(port: *mut c_void) -> usize {
        port_of(port).map_or(NIL, |port| port.connected_word())
    }

    /// Port of io.c:7308 (driver_caller).
    fn driver_caller(port: *mut c_void) -> usize {
        port_of(port).map_or(NIL, |port| port.caller_word())
    }

    /// Port of io.c:5522 (driver_mk_term_nil).
    fn driver_mk_term_nil() -> usize {
        NIL
    }

    /// Port of io.c:781 (driver_create_port).
    fn driver_create_port(
        creator: *mut c_void,
        owner: usize,
        name: *mut c_char,
        drv_data: *mut c_void,
    ) -> *mut c_void {
        let (Some(creator), Some(owner), Some(name)) =
            (port_of(creator), termspec::pid_data(owner), mem::cstr(name))
        else {
            return usize::MAX as *mut c_void;
        };
        creator
            .create_port(owner, &name.to_string_lossy(), drv_data as usize)
            .map_or(usize::MAX as *mut c_void, |port| port.handle())
    }

    /// Port of io.c:6265 (driver_output_term).
    fn driver_output_term(port: *mut c_void, data: *mut usize, len: c_int) -> c_int {
        let Some(port) = port_of(port) else {
            return -1;
        };
        if port.terminating() {
            return 0;
        }
        port.send_spec(None, mem::slice(data.cast_const(), usize::try_from(len).unwrap_or(0)))
    }

    /// Port of io.c:6301 (driver_send_term).
    fn driver_send_term(port: *mut c_void, to: usize, data: *mut usize, len: c_int) -> c_int {
        let Some(port) = port_of(port) else {
            return -1;
        };
        if port.terminating() {
            return 0;
        }
        port.send_spec(Some(to), mem::slice(data.cast_const(), usize::try_from(len).unwrap_or(0)))
    }

    /// Port of io.c:6248 (erl_drv_output_term): the port is named by its id word.
    fn erl_drv_output_term(port_id: usize, data: *mut usize, len: c_int) -> c_int {
        let Some(port) = port_id_of(port_id) else {
            return -1;
        };
        if port.terminating() {
            return 0;
        }
        port.send_spec(None, mem::slice(data.cast_const(), usize::try_from(len).unwrap_or(0)))
    }

    /// Port of io.c:6283 (erl_drv_send_term).
    fn erl_drv_send_term(port_id: usize, to: usize, data: *mut usize, len: c_int) -> c_int {
        let Some(port) = port_id_of(port_id) else {
            return -1;
        };
        if port.terminating() {
            return 0;
        }
        port.send_spec(Some(to), mem::slice(data.cast_const(), usize::try_from(len).unwrap_or(0)))
    }

    /// Port of io.c:7318 (driver_lock_driver).
    fn driver_lock_driver(port: *mut c_void) -> c_int {
        match port_of(port) {
            Some(port) if port.host.lock_driver(&port) => 0,
            _ => -1,
        }
    }

    /// Port of io.c:6951 (driver_get_now).
    fn driver_get_now(now: *mut [c_ulong; 3]) -> c_int {
        let Some(now) = mem::deref_mut(now) else {
            return -1;
        };
        let micros = now_micros();
        *now = [
            (micros / 1_000_000_000_000) as c_ulong,
            (micros / 1_000_000 % 1_000_000) as c_ulong,
            (micros % 1_000_000) as c_ulong,
        ];
        0
    }

    /// Port of erl_time_sup.c:2388 (erts_napi_monotonic_time).
    fn erl_drv_monotonic_time(unit: c_int) -> i64 {
        let nanos = hooks().map_or_else(local_monotonic, |hooks| hooks.monotonic_nanos());
        scale(nanos, unit)
    }

    /// Port of erl_time_sup.c:2426 (erts_napi_time_offset).
    fn erl_drv_time_offset(unit: c_int) -> i64 {
        let nanos = hooks().map_or_else(
            || {
                let wall = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
                wall.as_nanos() as i128 - local_monotonic()
            },
            |hooks| hooks.time_offset_nanos(),
        );
        scale(nanos, unit)
    }

    /// Port of erl_time_sup.c:2461 (erts_napi_convert_time_unit).
    fn erl_drv_convert_time_unit(val: i64, from: c_int, to: c_int) -> i64 {
        convert_time_unit(val, from, to)
    }

    /// Port of io.c:7373 (driver_dl_open).
    fn driver_dl_open(path: *mut c_char) -> *mut c_void {
        let Some(path) = mem::cstr(path) else {
            return std::ptr::null_mut();
        };
        // erts stores this error in a thread-local nothing reads (io.c:7384).
        dl_open(&path.to_string_lossy()).map_or(std::ptr::null_mut(), |handle| handle as *mut c_void)
    }

    /// Port of io.c:7393 (driver_dl_sym).
    fn driver_dl_sym(handle: *mut c_void, name: *mut c_char) -> *mut c_void {
        let Some(name) = mem::cstr(name) else {
            return std::ptr::null_mut();
        };
        match dl_sym(handle as usize, name) {
            Ok(symbol) => symbol,
            Err(code) => {
                DL_ERROR.with(|error| error.set(Some(code)));
                std::ptr::null_mut()
            }
        }
    }

    /// Port of io.c:7413 (driver_dl_close).
    fn driver_dl_close(handle: *mut c_void) -> c_int {
        dl_close(handle as usize)
    }

    /// Port of io.c:7422 (driver_dl_error).
    fn driver_dl_error() -> *mut c_char {
        error_text(
            DL_ERROR
                .with(Cell::get)
                .unwrap_or(crate::ERL_DE_ERROR_UNSPECIFIED),
        )
    }

    /// Port of io.c:7732 (erl_drv_putenv) over erl_osenv.c:360 (put_native).
    fn erl_drv_putenv(key: *const c_char, value: *mut c_char) -> c_int {
        let (Some(key), Some(value), Some(hooks)) =
            (mem::cstr(key), mem::cstr(value.cast_const()), hooks())
        else {
            return -1;
        };
        hooks.putenv(key.to_bytes(), value.to_bytes());
        0
    }

    /// Port of io.c:7745 (erl_drv_getenv) over sys_env.c:85 (erts_sys_explicit_8bit_getenv):
    /// `0` found, `1` the buffer is too small, `-1` unset.
    fn erl_drv_getenv(key: *const c_char, value: *mut c_char, value_size: *mut usize) -> c_int {
        let (Some(key), Some(size), Some(hooks)) =
            (mem::cstr(key), mem::deref_mut(value_size), hooks())
        else {
            return -1;
        };
        let capacity = size.saturating_sub(1);
        let found = hooks.getenv(key.to_bytes());
        match found {
            Some(text) if text.len() <= capacity && *size > 0 => {
                let out = mem::slice_mut(value.cast::<u8>(), text.len() + 1);
                out[..text.len()].copy_from_slice(&text);
                out[text.len()] = 0;
                *size = text.len();
                0
            }
            Some(_) => {
                *size = capacity;
                1
            }
            None => {
                *size = capacity;
                -1
            }
        }
    }

    /// Port of io.c:2927 (erl_drv_init_ack).
    fn erl_drv_init_ack(port: *mut c_void, result: *mut c_void) {
        if let Some(port) = port_of(port) {
            port.init_ack(result as isize);
        }
    }

    /// Port of io.c:2965 (erl_drv_set_os_pid).
    fn erl_drv_set_os_pid(port: *mut c_void, pid: isize) {
        if let Some(port) = port_of(port) {
            port.os_pid.store(pid as i64, Ordering::Release);
        }
    }
}

export! {
    /// Port of io.c:78 (driver_term_nil).
    static driver_term_nil: usize = NIL;
}

/// `driver_term_nil` for the export table.
pub(crate) fn lib_statics() -> Vec<(&'static str, usize)> {
    vec![(
        "driver_term_nil",
        std::ptr::addr_of!(driver_term_nil) as usize,
    )]
}
