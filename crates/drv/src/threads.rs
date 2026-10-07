//! Threads and synchronisation for drivers: `erl_drv_mutex_*`, `erl_drv_cond_*`,
//! `erl_drv_rwlock_*`, `erl_drv_tsd_*` and `erl_drv_thread_*`.
//!
//! Port of erts/emulator/beam/erl_drv_thread.c, OTP-29.1.1. Locks are
//! hand-over-hand primitives (a driver may unlock on another thread than it
//! locked on, as with POSIX mutexes in erts) built on std's `Mutex` and
//! `Condvar`; threads are real pthreads so `erl_drv_thread_exit` can unwind
//! nothing but C frames.

use std::cell::Cell;
use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Condvar, Mutex, OnceLock};

use crate::mem;

/// Name erts gives to anonymous locks and threads (`no_name`).
const NO_NAME: &CStr = c"unknown";

/// Port of erl_drv_thread.c:39 (fatal_error): an invalid use is fatal.
pub(crate) fn fatal_error(err: c_int, func: &str) -> ! {
    let text = std::io::Error::from_raw_os_error(err);
    eprintln!("Fatal error in {func}: {text} [{err}]");
    std::process::abort()
}

fn name_of(name: *const c_char) -> CString {
    mem::cstr(name).map_or_else(|| NO_NAME.to_owned(), CStr::to_owned)
}

/// A lock that is not tied to the locking thread.
#[derive(Default)]
struct RawMutex {
    held: Mutex<bool>,
    freed: Condvar,
}

impl RawMutex {
    fn lock(&self) {
        let mut held = self.held.lock().unwrap();
        while *held {
            held = self.freed.wait(held).unwrap();
        }
        *held = true;
    }

    fn try_lock(&self) -> bool {
        let mut held = self.held.lock().unwrap();
        !std::mem::replace(&mut *held, true)
    }

    fn unlock(&self) {
        *self.held.lock().unwrap() = false;
        self.freed.notify_one();
    }
}

/// Port reference count and lock of `driver_pdl_create`.
pub(crate) struct PortDataLock {
    lock: RawMutex,
    refc: std::sync::atomic::AtomicIsize,
}

/// `ErlDrvMutex`.
struct DrvMutex {
    raw: RawMutex,
    name: CString,
}

/// `ErlDrvCond`: a generation counter, so a signal never gets lost between
/// the unlock and the wait of `erl_drv_cond_wait`.
struct DrvCond {
    generation: Mutex<u64>,
    wake: Condvar,
    name: CString,
}

/// `ErlDrvRWLock`: reader count and writer flag.
struct DrvRwLock {
    state: Mutex<(usize, bool)>,
    changed: Condvar,
    name: CString,
}

/// `struct ErlDrvTid_`.
struct DrvTid {
    thread: AtomicUsize,
    func: Option<extern "C" fn(*mut c_void) -> *mut c_void>,
    arg: usize,
    drv_thr: bool,
    tsd: Mutex<Vec<usize>>,
    name: CString,
}

thread_local! {
    /// The calling thread's `ErlDrvTid` (`tid_key`), zero when not created yet.
    static CURRENT: Cell<usize> = const { Cell::new(0) };
    static REAPER: Cell<Option<Reaper>> = const { Cell::new(None) };
}

/// Frees the `ErlDrvTid` of a thread not created by `erl_drv_thread_create`
/// when that thread ends (thread_exit_handler).
struct Reaper(usize);

impl Drop for Reaper {
    fn drop(&mut self) {
        mem::free_handle(self.0 as *mut DrvTid);
    }
}

fn tid_ref<'a>(tid: *mut c_void, func: &str) -> &'a DrvTid {
    mem::deref(tid.cast::<DrvTid>().cast_const()).unwrap_or_else(|| fatal_error(libc::EINVAL, func))
}

pub(crate) fn mutex_create(name: *mut c_char) -> *mut c_void {
    mem::new_handle(DrvMutex {
        raw: RawMutex::default(),
        name: name_of(name),
    })
    .cast()
}

fn mutex<'a>(handle: *mut c_void, func: &str) -> &'a DrvMutex {
    mem::deref(handle.cast::<DrvMutex>().cast_const())
        .unwrap_or_else(|| fatal_error(libc::EINVAL, func))
}

pub(crate) fn mutex_destroy(handle: *mut c_void) {
    mutex(handle, "erl_drv_mutex_destroy()");
    mem::free_handle(handle.cast::<DrvMutex>());
}

pub(crate) fn mutex_name(handle: *mut c_void) -> *mut c_char {
    mem::deref(handle.cast::<DrvMutex>().cast_const())
        .map_or(std::ptr::null_mut(), |m| m.name.as_ptr().cast_mut())
}

pub(crate) fn mutex_trylock(handle: *mut c_void) -> c_int {
    if mutex(handle, "erl_drv_mutex_trylock()").raw.try_lock() {
        0
    } else {
        libc::EBUSY
    }
}

pub(crate) fn mutex_lock(handle: *mut c_void) {
    mutex(handle, "erl_drv_mutex_lock()").raw.lock();
}

pub(crate) fn mutex_unlock(handle: *mut c_void) {
    mutex(handle, "erl_drv_mutex_unlock()").raw.unlock();
}

pub(crate) fn cond_create(name: *mut c_char) -> *mut c_void {
    mem::new_handle(DrvCond {
        generation: Mutex::new(0),
        wake: Condvar::new(),
        name: name_of(name),
    })
    .cast()
}

fn cond<'a>(handle: *mut c_void, func: &str) -> &'a DrvCond {
    mem::deref(handle.cast::<DrvCond>().cast_const())
        .unwrap_or_else(|| fatal_error(libc::EINVAL, func))
}

pub(crate) fn cond_destroy(handle: *mut c_void) {
    cond(handle, "erl_drv_cond_destroy()");
    mem::free_handle(handle.cast::<DrvCond>());
}

pub(crate) fn cond_name(handle: *mut c_void) -> *mut c_char {
    mem::deref(handle.cast::<DrvCond>().cast_const())
        .map_or(std::ptr::null_mut(), |c| c.name.as_ptr().cast_mut())
}

pub(crate) fn cond_signal(handle: *mut c_void) {
    let cond = cond(handle, "erl_drv_cond_signal()");
    *cond.generation.lock().unwrap() += 1;
    cond.wake.notify_one();
}

pub(crate) fn cond_broadcast(handle: *mut c_void) {
    let cond = cond(handle, "erl_drv_cond_broadcast()");
    *cond.generation.lock().unwrap() += 1;
    cond.wake.notify_all();
}

pub(crate) fn cond_wait(cond_handle: *mut c_void, mutex_handle: *mut c_void) {
    if cond_handle.is_null() || mutex_handle.is_null() {
        fatal_error(libc::EINVAL, "erl_drv_cond_wait()");
    }
    let cond = cond(cond_handle, "erl_drv_cond_wait()");
    let mutex = mutex(mutex_handle, "erl_drv_cond_wait()");
    let mut generation = cond.generation.lock().unwrap();
    let seen = *generation;
    mutex.raw.unlock();
    while *generation == seen {
        generation = cond.wake.wait(generation).unwrap();
    }
    drop(generation);
    mutex.raw.lock();
}

pub(crate) fn rwlock_create(name: *mut c_char) -> *mut c_void {
    mem::new_handle(DrvRwLock {
        state: Mutex::new((0, false)),
        changed: Condvar::new(),
        name: name_of(name),
    })
    .cast()
}

fn rwlock<'a>(handle: *mut c_void, func: &str) -> &'a DrvRwLock {
    mem::deref(handle.cast::<DrvRwLock>().cast_const())
        .unwrap_or_else(|| fatal_error(libc::EINVAL, func))
}

pub(crate) fn rwlock_destroy(handle: *mut c_void) {
    rwlock(handle, "erl_drv_rwlock_destroy()");
    mem::free_handle(handle.cast::<DrvRwLock>());
}

pub(crate) fn rwlock_name(handle: *mut c_void) -> *mut c_char {
    mem::deref(handle.cast::<DrvRwLock>().cast_const())
        .map_or(std::ptr::null_mut(), |l| l.name.as_ptr().cast_mut())
}

/// `try_` variants return `0` or `EBUSY`; the blocking ones wait for `free`.
fn rw_acquire(handle: *mut c_void, func: &str, write: bool, wait: bool) -> c_int {
    let lock = rwlock(handle, func);
    let mut state = lock.state.lock().unwrap();
    loop {
        let free = if write {
            state.0 == 0 && !state.1
        } else {
            !state.1
        };
        if free {
            if write {
                state.1 = true;
            } else {
                state.0 += 1;
            }
            return 0;
        }
        if !wait {
            return libc::EBUSY;
        }
        state = lock.changed.wait(state).unwrap();
    }
}

fn rw_release(handle: *mut c_void, func: &str, write: bool) {
    let lock = rwlock(handle, func);
    let mut state = lock.state.lock().unwrap();
    if write {
        state.1 = false;
    } else {
        state.0 = state.0.saturating_sub(1);
    }
    drop(state);
    lock.changed.notify_all();
}

pub(crate) fn rwlock_tryrlock(handle: *mut c_void) -> c_int {
    rw_acquire(handle, "erl_drv_rwlock_tryrlock()", false, false)
}

pub(crate) fn rwlock_rlock(handle: *mut c_void) {
    rw_acquire(handle, "erl_drv_rwlock_rlock()", false, true);
}

pub(crate) fn rwlock_runlock(handle: *mut c_void) {
    rw_release(handle, "erl_drv_rwlock_runlock()", false);
}

pub(crate) fn rwlock_tryrwlock(handle: *mut c_void) -> c_int {
    rw_acquire(handle, "erl_drv_rwlock_tryrwlock()", true, false)
}

pub(crate) fn rwlock_rwlock(handle: *mut c_void) {
    rw_acquire(handle, "erl_drv_rwlock_rwlock()", true, true);
}

pub(crate) fn rwlock_rwunlock(handle: *mut c_void) {
    rw_release(handle, "erl_drv_rwlock_rwunlock()", true);
}

/// Names of the live TSD keys, indexed by key (`used_tsd_keys`).
fn tsd_keys() -> &'static Mutex<Vec<Option<CString>>> {
    static KEYS: OnceLock<Mutex<Vec<Option<CString>>>> = OnceLock::new();
    KEYS.get_or_init(|| Mutex::new(Vec::new()))
}

fn check_key(key: c_int, func: &str) -> usize {
    let keys = tsd_keys().lock().unwrap();
    match usize::try_from(key) {
        Ok(index) if keys.get(index).is_some_and(Option::is_some) => index,
        _ => fatal_error(libc::EINVAL, func),
    }
}

/// Port of erl_drv_thread.c:447 (erl_drv_tsd_key_create): the lowest free key.
pub(crate) fn tsd_key_create(name: *mut c_char, key: *mut c_int) -> c_int {
    let Some(key) = mem::deref_mut(key) else {
        fatal_error(libc::EINVAL, "erl_drv_tsd_key_create()");
    };
    let mut keys = tsd_keys().lock().unwrap();
    let free = keys.iter().position(Option::is_none);
    let index = free.unwrap_or(keys.len());
    if index >= c_int::MAX as usize {
        *key = -1;
        return libc::ENOMEM;
    }
    if free.is_none() {
        keys.push(None);
    }
    keys[index] = Some(name_of(name));
    *key = index as c_int;
    0
}

pub(crate) fn tsd_key_destroy(key: c_int) {
    let index = check_key(key, "erl_drv_tsd_key_destroy()");
    tsd_keys().lock().unwrap()[index] = None;
}

/// The `ErlDrvTid` of the calling thread, created for foreign threads on demand.
fn current_tid() -> usize {
    CURRENT.with(|current| {
        if current.get() == 0 {
            let tid = mem::new_handle(DrvTid {
                thread: AtomicUsize::new(0),
                func: None,
                arg: 0,
                drv_thr: false,
                tsd: Mutex::new(Vec::new()),
                name: NO_NAME.to_owned(),
            });
            current.set(tid as usize);
            REAPER.with(|reaper| reaper.set(Some(Reaper(tid as usize))));
        }
        current.get()
    })
}

pub(crate) fn tsd_set(key: c_int, data: *mut c_void) {
    let index = check_key(key, "erl_drv_tsd_set()");
    let tid = tid_ref(current_tid() as *mut c_void, "erl_drv_tsd_set()");
    let mut tsd = tid.tsd.lock().unwrap();
    if tsd.len() <= index {
        tsd.resize(index + 10, 0);
    }
    tsd[index] = data as usize;
}

pub(crate) fn tsd_get(key: c_int) -> *mut c_void {
    let index = check_key(key, "erl_drv_tsd_get()");
    let current = CURRENT.with(Cell::get);
    if current == 0 {
        return std::ptr::null_mut();
    }
    let tid = tid_ref(current as *mut c_void, "erl_drv_tsd_get()");
    let tsd = tid.tsd.lock().unwrap();
    tsd.get(index).copied().unwrap_or(0) as *mut c_void
}

/// `ErlDrvThreadOpts`.
#[repr(C)]
pub(crate) struct ThreadOpts {
    suggested_stack_size: c_int,
}

pub(crate) fn thread_opts_create(_name: *mut c_char) -> *mut c_void {
    mem::new_handle(ThreadOpts {
        suggested_stack_size: -1,
    })
    .cast()
}

pub(crate) fn thread_opts_destroy(opts: *mut c_void) {
    if opts.is_null() {
        fatal_error(libc::EINVAL, "erl_drv_thread_opts_destroy()");
    }
    mem::free_handle(opts.cast::<ThreadOpts>());
}

/// Entry point of every driver thread (erl_drv_thread_wrapper).
extern "C" fn thread_wrapper(arg: *mut c_void) -> *mut c_void {
    CURRENT.with(|current| current.set(arg as usize));
    let tid = tid_ref(arg, "erl_drv_thread_wrapper()");
    match tid.func {
        Some(func) => func(tid.arg as *mut c_void),
        None => std::ptr::null_mut(),
    }
}

/// Port of erl_drv_thread.c:604 (erl_drv_thread_create); the suggested stack
/// size is in kilo words as for `ethr_thr_create`.
pub(crate) fn thread_create(
    name: *mut c_char,
    tid_out: *mut *mut c_void,
    func: extern "C" fn(*mut c_void) -> *mut c_void,
    arg: *mut c_void,
    opts: *mut c_void,
) -> c_int {
    let handle = mem::new_handle(DrvTid {
        thread: AtomicUsize::new(0),
        func: Some(func),
        arg: arg as usize,
        drv_thr: true,
        tsd: Mutex::new(Vec::new()),
        name: name_of(name),
    });
    let stack = mem::deref(opts.cast::<ThreadOpts>().cast_const())
        .and_then(|opts| usize::try_from(opts.suggested_stack_size).ok())
        .map(|kilo_words| kilo_words * 1024 * size_of::<usize>());
    let created = spawn_pthread(handle, stack);
    match created {
        Ok(thread) => {
            tid_ref(handle.cast(), "erl_drv_thread_create()")
                .thread
                .store(thread, Ordering::Release);
            if let Some(out) = mem::deref_mut(tid_out) {
                *out = handle.cast();
            }
            0
        }
        Err(errno) => {
            mem::free_handle(handle);
            errno
        }
    }
}

/// `pthread_create` of [`thread_wrapper`] for `handle`.
fn spawn_pthread(handle: *mut DrvTid, stack: Option<usize>) -> Result<usize, c_int> {
    let mut attr = std::mem::MaybeUninit::<libc::pthread_attr_t>::uninit();
    let mut thread = std::mem::MaybeUninit::<libc::pthread_t>::uninit();
    // SAFETY: `attr` is initialised before use and destroyed after; the new
    // thread only touches `handle`, which stays allocated until it is joined.
    unsafe {
        libc::pthread_attr_init(attr.as_mut_ptr());
        if let Some(size) = stack {
            libc::pthread_attr_setstacksize(attr.as_mut_ptr(), size.max(libc::PTHREAD_STACK_MIN));
        }
        let result = libc::pthread_create(
            thread.as_mut_ptr(),
            attr.as_ptr(),
            thread_wrapper,
            handle.cast(),
        );
        libc::pthread_attr_destroy(attr.as_mut_ptr());
        if result != 0 {
            return Err(result);
        }
        // pthread_t is an integer or a pointer, depending on the platform.
        #[allow(clippy::unnecessary_cast)]
        let id = thread.assume_init() as usize;
        Ok(id)
    }
}

pub(crate) fn thread_name(tid: *mut c_void) -> *mut c_char {
    mem::deref(tid.cast::<DrvTid>().cast_const())
        .map_or(std::ptr::null_mut(), |t| t.name.as_ptr().cast_mut())
}

pub(crate) fn thread_self() -> *mut c_void {
    current_tid() as *mut c_void
}

pub(crate) fn equal_tids(a: *mut c_void, b: *mut c_void) -> c_int {
    if a.is_null() || b.is_null() {
        fatal_error(libc::EINVAL, "erl_drv_equal_tids()");
    }
    c_int::from(a == b)
}

/// Port of erl_drv_thread.c:705 (erl_drv_thread_exit): only a driver thread may exit.
pub(crate) fn thread_exit(result: *mut c_void) -> ! {
    let current = CURRENT.with(Cell::get);
    if current == 0 || !tid_ref(current as *mut c_void, "erl_drv_thread_exit()").drv_thr {
        fatal_error(libc::EACCES, "erl_drv_thread_exit()");
    }
    // SAFETY: called on a thread created by `thread_create`, whose frames are C only.
    unsafe { libc::pthread_exit(result) }
}

pub(crate) fn thread_join(tid: *mut c_void, result: *mut *mut c_void) -> c_int {
    let dtid = tid_ref(tid, "erl_drv_thread_join()");
    if !dtid.drv_thr {
        return libc::EINVAL;
    }
    let mut value: *mut c_void = std::ptr::null_mut();
    // SAFETY: the thread id came from `pthread_create` and is joined once.
    let status = unsafe {
        libc::pthread_join(
            dtid.thread.load(Ordering::Acquire) as libc::pthread_t,
            &mut value,
        )
    };
    if status == 0 {
        if let Some(out) = mem::deref_mut(result) {
            *out = value;
        }
        mem::free_handle(tid.cast::<DrvTid>());
    }
    status
}

/// `driver_pdl_create` lock (`struct erl_drv_port_data_lock`).
pub(crate) fn pdl_new() -> *mut PortDataLock {
    mem::new_handle(PortDataLock {
        lock: RawMutex::default(),
        refc: std::sync::atomic::AtomicIsize::new(1),
    })
}

fn pdl<'a>(handle: *mut PortDataLock) -> Option<&'a PortDataLock> {
    mem::deref(handle.cast_const())
}

/// Port of io.c:6731 (driver_pdl_lock): take a reference, then the lock.
pub(crate) fn pdl_lock(handle: *mut PortDataLock) {
    if let Some(pdl) = pdl(handle) {
        pdl.refc.fetch_add(1, Ordering::AcqRel);
        pdl.lock.lock();
    }
}

/// Port of io.c:6741 (driver_pdl_unlock): unlock, then drop the reference.
pub(crate) fn pdl_unlock(handle: *mut PortDataLock) {
    if let Some(pdl) = pdl(handle) {
        pdl.lock.unlock();
        pdl_dec(handle);
    }
}

pub(crate) fn pdl_refc(handle: *mut PortDataLock) -> isize {
    pdl(handle).map_or(0, |pdl| pdl.refc.load(Ordering::Acquire))
}

pub(crate) fn pdl_inc(handle: *mut PortDataLock) -> isize {
    pdl(handle).map_or(0, |pdl| pdl.refc.fetch_add(1, Ordering::AcqRel) + 1)
}

/// Port of io.c:6771 (driver_pdl_dec_refc): the last reference destroys the lock.
pub(crate) fn pdl_dec(handle: *mut PortDataLock) -> isize {
    let Some(pdl) = pdl(handle) else { return 0 };
    let left = pdl.refc.fetch_sub(1, Ordering::AcqRel) - 1;
    if left == 0 {
        mem::free_handle(handle);
    }
    left
}

/// The thread `erl_drv_steal_main_thread` started, joined by `erl_drv_stolen_main_thread_join`.
static STOLEN: Mutex<usize> = Mutex::new(0);

/// Port of erl_drv_thread.c:750 (erl_drv_steal_main_thread). erts runs `func` on
/// the emulator's main thread (macOS only); this runtime keeps no such thread
/// parked, so `func` runs on a dedicated thread and `*tid` is NULL as in erts.
pub(crate) fn steal_main_thread(
    name: *mut c_char,
    tid: *mut *mut c_void,
    func: extern "C" fn(*mut c_void) -> *mut c_void,
    arg: *mut c_void,
    opts: *mut c_void,
) -> c_int {
    let mut created: *mut c_void = std::ptr::null_mut();
    let status = thread_create(name, &mut created, func, arg, opts);
    if status == 0 {
        *STOLEN.lock().unwrap() = created as usize;
    }
    if let Some(out) = mem::deref_mut(tid) {
        *out = std::ptr::null_mut();
    }
    status
}

/// Port of erl_drv_thread.c:737 (erl_drv_stolen_main_thread_join).
pub(crate) fn stolen_join(_tid: *mut c_void, result: *mut *mut c_void) -> c_int {
    let stolen = std::mem::take(&mut *STOLEN.lock().unwrap());
    if stolen == 0 {
        return libc::EINVAL;
    }
    thread_join(stolen as *mut c_void, result)
}
