//! Raw accesses for the erts `ESockDescriptor` layout.
//!
//! Mutexes are `ErlNifMutex*` (heap-allocated). The fields they protect sit next to them in
//! the descriptor, as in prim_socket_int.h. Every `unsafe` for that layout lives here.

use super::Requestor;
use super::esock_descriptor::{
    ESockDescriptor, ESockMonitor, ESockRequestQueue, ESockRequestQueueElement, ESockRequestor,
    ErlNifBinary, ErlNifMonitor, ErlNifPid, INVALID_SOCKET, Socket,
};
use arinsal_etf::OwnedTerm as O;
use arinsal_nif::{MonitoredResourcePayload, ResourceMonitors};
use arinsal_term::{Term, to_owned};
use socket2::SockRef;
use std::ffi::c_void;
use std::mem::size_of;
use std::os::fd::BorrowedFd;
use std::ptr;
use std::sync::Mutex;

// SAFETY: `readMtx`/`writeMtx` serialize every field access of an `ESockDescriptor` the same
// way erts `ErlNifMutex` does; `monitors` and `selector` have their own locks.
unsafe impl Send for ESockDescriptor {}
// SAFETY: same mutex split as the `Send` impl: threads only touch fields they locked.
unsafe impl Sync for ESockDescriptor {}

// SAFETY: `Handle::esock_dtor_prologue` checks this same field before dropping the descriptor;
// the field stays in the magic block until its monitor count is zero.
unsafe impl MonitoredResourcePayload for ESockDescriptor {
    fn monitor_state(&self) -> Option<&ResourceMonitors> {
        Some(&self.monitors)
    }
}

/// `MCREATE` for `descP->readMtx` / `writeMtx`.
pub(crate) fn create_mutex() -> *mut Mutex<()> {
    Box::into_raw(Box::new(Mutex::new(())))
}

/// The mutex `mtx` belongs to `owner` for the duration of that borrow.
pub(crate) fn mutex_ref(mtx: *mut Mutex<()>, owner: &ESockDescriptor) -> &Mutex<()> {
    let _ = owner;
    // SAFETY: `mtx` is a live mutex allocated in `esock_alloc_descriptor` and destroyed only
    // after `esock_dtor` has exclusive access to the payload, which outlives `owner`.
    unsafe { &*mtx }
}

/// `MDESTROY` for both descriptor mutexes.
pub(crate) fn destroy_mutexes(desc: &mut ESockDescriptor) {
    if !desc.write_mtx.is_null() {
        // SAFETY: destructor owns the payload; no other thread holds this mutex.
        drop(unsafe { Box::from_raw(desc.write_mtx) });
        desc.write_mtx = ptr::null_mut();
    }
    if !desc.read_mtx.is_null() {
        // SAFETY: destructor owns the payload; no other thread holds this mutex.
        drop(unsafe { Box::from_raw(desc.read_mtx) });
        desc.read_mtx = ptr::null_mut();
    }
}

pub(crate) fn read_u32(field: &u32) -> u32 {
    // SAFETY: the caller holds the erts mutex that covers this field.
    unsafe { ptr::from_ref(field).read() }
}
pub(crate) fn write_u32(field: &u32, value: u32) {
    // SAFETY: the caller holds the erts mutex that covers this field exclusively.
    unsafe { ptr::from_ref(field).cast_mut().write(value) }
}
pub(crate) fn read_i32(field: &i32) -> i32 {
    // SAFETY: the caller holds the erts mutex that covers this field, or the field is
    // constant after `esock_alloc_descriptor`.
    unsafe { ptr::from_ref(field).read() }
}
pub(crate) fn write_i32(field: &i32, value: i32) {
    // SAFETY: the caller holds the erts mutex that covers this field exclusively.
    unsafe { ptr::from_ref(field).cast_mut().write(value) }
}
pub(crate) fn read_u64(field: &u64) -> u64 {
    // SAFETY: the caller holds the erts mutex that covers this field.
    unsafe { ptr::from_ref(field).read() }
}
pub(crate) fn write_u64(field: &u64, value: u64) {
    // SAFETY: the caller holds the erts mutex that covers this field exclusively.
    unsafe { ptr::from_ref(field).cast_mut().write(value) }
}
pub(crate) fn add_u64(field: &u64, n: u64) {
    write_u64(field, read_u64(field) + n);
}
pub(crate) fn read_usize(field: &usize) -> usize {
    // SAFETY: the caller holds the erts mutex that covers this field.
    unsafe { ptr::from_ref(field).read() }
}
pub(crate) fn write_usize(field: &usize, value: usize) {
    // SAFETY: the caller holds the erts mutex that covers this field exclusively.
    unsafe { ptr::from_ref(field).cast_mut().write(value) }
}

pub(crate) fn monitor_init() -> ESockMonitor {
    ESockMonitor {
        mon: ErlNifMonitor {
            data: [0; size_of::<*mut c_void>() * 4],
        },
        is_active: 0,
    }
}

/// `esock_requestor_init`.
pub(crate) fn requestor_init() -> ESockRequestor {
    ESockRequestor {
        pid: ErlNifPid { pid: 0 },
        mon: monitor_init(),
        env: ptr::null_mut(),
        r#ref: 0,
        sock: INVALID_SOCKET,
        data_p: ptr::null_mut(),
    }
}

pub(crate) fn store_pid(slot: &ErlNifPid, pid: Option<&O>) {
    let word = pid.map(pid_word).unwrap_or(0);
    write_usize(&slot.pid, word);
}

pub(crate) fn load_pid(slot: ErlNifPid) -> Option<O> {
    pid_from_word(slot.pid)
}

fn pid_word(pid: &O) -> usize {
    let O::Pid { id, serial, .. } = pid else {
        return 0;
    };
    Term::pid(*id, *serial)
        .map(|term| term.word() as usize)
        .unwrap_or(0)
}

fn pid_from_word(word: usize) -> Option<O> {
    if word == 0 {
        return None;
    }
    // SAFETY: `word` is a local pid immediate stored by `store_pid`.
    to_owned(unsafe { Term::from_raw_bits(word as u64) }).ok()
}

pub(crate) fn store_monitor(slot: &ESockMonitor, mon: Option<u64>) {
    let data = slot.mon.data.as_ptr().cast_mut();
    // SAFETY: `ErlNifMonitor` is 32 bytes of opaque storage; the first 8 hold the handle.
    unsafe {
        data.cast::<u64>().write(mon.unwrap_or(0));
    }
    write_i32(&slot.is_active, i32::from(mon.is_some()));
}

pub(crate) fn load_monitor(slot: &ESockMonitor) -> Option<u64> {
    if read_i32(&slot.is_active) == 0 {
        return None;
    }
    // SAFETY: `isActive` is set only together with a monitor id in the first 8 bytes.
    let id = unsafe { slot.mon.data.as_ptr().cast::<u64>().read() };
    (id != 0).then_some(id)
}

struct TermEnv {
    term: O,
}

pub(crate) fn store_env_term(env: &*mut c_void, term: Option<&O>) {
    free_env(*env);
    let ptr = match term {
        Some(term) => Box::into_raw(Box::new(TermEnv { term: term.clone() })).cast(),
        None => ptr::null_mut(),
    };
    // SAFETY: `env` is an `ErlNifEnv*` field covered by the caller's descriptor mutex.
    unsafe { ptr::from_ref(env).cast_mut().write(ptr) }
}

pub(crate) fn load_env_term(env: *mut c_void) -> Option<O> {
    if env.is_null() {
        return None;
    }
    // SAFETY: `env` is a `TermEnv` allocated by `store_env_term` and still owned by the field.
    Some(unsafe { &*env.cast::<TermEnv>() }.term.clone())
}

pub(crate) fn free_env(env: *mut c_void) {
    if env.is_null() {
        return;
    }
    // SAFETY: `env` is a unique `TermEnv` allocated by `store_env_term`.
    drop(unsafe { Box::from_raw(env.cast::<TermEnv>()) });
}

fn store_requestor(dst: &mut ESockRequestor, req: Requestor, sock: Socket) {
    store_pid(&dst.pid, Some(&req.pid));
    store_monitor(&dst.mon, req.mon);
    store_env_term(&dst.env, Some(&req.reference));
    dst.r#ref = 0;
    dst.sock = sock;
    dst.data_p = ptr::null_mut();
}

fn load_requestor(src: &ESockRequestor) -> Option<Requestor> {
    if src.env.is_null() && src.pid.pid == 0 {
        return None;
    }
    Some(Requestor {
        pid: load_pid(src.pid)?,
        reference: load_env_term(src.env)?,
        mon: load_monitor(&src.mon),
    })
}

fn release_requestor(dst: &mut ESockRequestor) {
    free_env(dst.env);
    *dst = requestor_init();
}

pub(crate) fn load_current(
    requestor: &ESockRequestor,
    pointer: *mut ESockRequestor,
) -> Option<Requestor> {
    if pointer.is_null() {
        return None;
    }
    load_requestor(requestor)
}

pub(crate) fn store_current(
    requestor: &ESockRequestor,
    pointer: &*mut ESockRequestor,
    value: Option<Requestor>,
    sock: Socket,
) {
    let dst = ptr::from_ref(requestor).cast_mut();
    // SAFETY: the caller holds the mutex covering this requestor; the pointer is either null
    // or `&current*` of this same descriptor. Fields are updated with `ptr::write` so a
    // `&mut ESockRequestor` is never formed from the shared `requestor` borrow.
    unsafe {
        match value {
            Some(req) => {
                let mut slot = dst.read();
                store_requestor(&mut slot, req, sock);
                dst.write(slot);
                ptr::from_ref(pointer).cast_mut().write(dst);
            }
            None => {
                let mut slot = dst.read();
                release_requestor(&mut slot);
                dst.write(slot);
                ptr::from_ref(pointer).cast_mut().write(ptr::null_mut());
            }
        }
    }
}

pub(crate) fn queue_len(queue: *mut ESockRequestQueue) -> usize {
    // SAFETY: the caller holds the mutex covering this queue.
    unsafe {
        let mut n = 0;
        let mut cur = (*queue).first;
        while !cur.is_null() {
            n += 1;
            cur = (*cur).next_p;
        }
        n
    }
}

pub(crate) fn queue_search(queue: *mut ESockRequestQueue, pid: &O) -> bool {
    // SAFETY: the caller holds the mutex covering this queue.
    unsafe {
        let mut cur = (*queue).first;
        while !cur.is_null() {
            if let Some(req) = load_requestor(&(*cur).data)
                && req.pid == *pid
            {
                return true;
            }
            cur = (*cur).next_p;
        }
        false
    }
}

pub(crate) fn queue_push(queue: *mut ESockRequestQueue, req: Requestor, sock: Socket) {
    let mut element = Box::new(ESockRequestQueueElement {
        next_p: ptr::null_mut(),
        data: requestor_init(),
    });
    store_requestor(&mut element.data, req, sock);
    let raw = Box::into_raw(element);
    // SAFETY: the caller holds the mutex covering this queue; `raw` is a unique element.
    unsafe {
        if (*queue).last.is_null() {
            (*queue).first = raw;
        } else {
            (*(*queue).last).next_p = raw;
        }
        (*queue).last = raw;
    }
}

pub(crate) fn queue_pop(queue: *mut ESockRequestQueue) -> Option<Requestor> {
    // SAFETY: the caller holds the mutex covering this queue.
    unsafe {
        let first = (*queue).first;
        if first.is_null() {
            return None;
        }
        (*queue).first = (*first).next_p;
        if (*queue).first.is_null() {
            (*queue).last = ptr::null_mut();
        }
        let mut element = Box::from_raw(first);
        let req = load_requestor(&element.data);
        release_requestor(&mut element.data);
        req
    }
}

pub(crate) fn queue_unqueue(
    queue: *mut ESockRequestQueue,
    pid: &O,
    reference: Option<&O>,
) -> Option<Requestor> {
    // SAFETY: the caller holds the mutex covering this queue.
    unsafe {
        let mut prev: *mut ESockRequestQueueElement = ptr::null_mut();
        let mut cur = (*queue).first;
        while !cur.is_null() {
            let req = load_requestor(&(*cur).data);
            let matched = req.as_ref().is_some_and(|req| {
                req.pid == *pid && reference.is_none_or(|reference| reference == &req.reference)
            });
            if matched {
                let next = (*cur).next_p;
                if prev.is_null() {
                    (*queue).first = next;
                } else {
                    (*prev).next_p = next;
                }
                if (*queue).last == cur {
                    (*queue).last = prev;
                }
                let mut element = Box::from_raw(cur);
                let req = load_requestor(&element.data);
                release_requestor(&mut element.data);
                return req;
            }
            prev = cur;
            cur = (*cur).next_p;
        }
        None
    }
}

pub(crate) fn queue_drain(queue: *mut ESockRequestQueue) -> Vec<Requestor> {
    let mut out = Vec::new();
    while let Some(req) = queue_pop(queue) {
        out.push(req);
    }
    out
}

pub(crate) fn free_queue(queue: *mut ESockRequestQueue) {
    let _ = queue_drain(queue);
}

pub(crate) fn recv_alloc_buf(buf: &ErlNifBinary, size: usize) {
    let data = buf.data;
    let old = read_usize(&buf.size);
    if data.is_null() {
        let mut storage = vec![0u8; size];
        let ptr = storage.as_mut_ptr();
        std::mem::forget(storage);
        write_ptr(&buf.data, ptr);
        write_usize(&buf.size, size);
        return;
    }
    if old == size {
        return;
    }
    // SAFETY: `data` is the unique receive buffer allocated here.
    let mut storage = unsafe { Vec::from_raw_parts(data, old, old) };
    storage.resize(size, 0);
    storage.shrink_to_fit();
    let ptr = storage.as_mut_ptr();
    let len = storage.len();
    std::mem::forget(storage);
    write_ptr(&buf.data, ptr);
    write_usize(&buf.size, len);
}

fn write_ptr(field: &*mut u8, value: *mut u8) {
    // SAFETY: the caller holds `readMtx` covering `descP->buf`.
    unsafe { ptr::from_ref(field).cast_mut().write(value) }
}

pub(crate) fn recv_buf_ptr(buf: &ErlNifBinary) -> (*mut u8, usize) {
    (buf.data, read_usize(&buf.size))
}

pub(crate) fn recv_create_bin(buf: &ErlNifBinary, size: usize) -> Vec<u8> {
    let (data, buffer_size) = recv_buf_ptr(buf);
    if data.is_null() {
        return vec![0u8; size];
    }
    if size >= (buffer_size & !4095) || size >= (buffer_size >> 1) + (buffer_size >> 2) {
        // SAFETY: hand off the unique receive allocation.
        let mut binary = unsafe { Vec::from_raw_parts(data, buffer_size, buffer_size) };
        write_ptr(&buf.data, ptr::null_mut());
        write_usize(&buf.size, 0);
        binary.truncate(size);
        binary.shrink_to_fit();
        binary
    } else {
        // SAFETY: `readMtx` covers `buf`; copy out of the unique receive allocation.
        unsafe { std::slice::from_raw_parts(data, size) }.to_vec()
    }
}

pub(crate) fn free_buf(buf: &ErlNifBinary) {
    if buf.data.is_null() {
        return;
    }
    let size = read_usize(&buf.size);
    // SAFETY: destructor owns the receive allocation.
    drop(unsafe { Vec::from_raw_parts(buf.data, size, size) });
    write_ptr(&buf.data, ptr::null_mut());
    write_usize(&buf.size, 0);
}

/// `sock_close`: the errno of `close(2)`, or 0.
pub(crate) fn close_socket(fd: i32) -> i32 {
    if fd < 0 {
        return 0;
    }
    // SAFETY: `fd` is a uniquely owned descriptor taken from `descP->sock` or `sendfileHandle`.
    if unsafe { libc::close(fd) } < 0 {
        std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO)
    } else {
        0
    }
}

pub(crate) fn close_fd(fd: i32) {
    let _ = close_socket(fd);
}

/// Run `f` with a borrowed fd of a live socket without taking ownership.
pub(crate) fn with_fd<R>(fd: i32, f: impl FnOnce(BorrowedFd<'_>) -> R) -> R {
    // SAFETY: `fd` is a live socket owned by the descriptor for the duration of `f`.
    f(unsafe { BorrowedFd::borrow_raw(fd) })
}

/// Run `f` with a `SockRef` of `fd` without taking ownership.
pub(crate) fn with_sock<R>(fd: i32, f: impl FnOnce(SockRef<'_>) -> R) -> R {
    with_fd(fd, |borrowed| f(SockRef::from(&borrowed)))
}

/// `essio_dtor` resource cleanup of pointer fields after requestors are demonitored.
pub(crate) fn free_descriptor_storage(desc: &mut ESockDescriptor) {
    free_buf(&desc.buf);
    release_requestor(&mut desc.current_reader);
    desc.current_reader_p = ptr::null_mut();
    release_requestor(&mut desc.current_writer);
    desc.current_writer_p = ptr::null_mut();
    release_requestor(&mut desc.current_acceptor);
    desc.current_acceptor_p = ptr::null_mut();
    release_requestor(&mut desc.connector);
    desc.connector_p = ptr::null_mut();
    free_queue(&mut desc.readers_q);
    free_queue(&mut desc.writers_q);
    free_queue(&mut desc.acceptors_q);
    if !desc.sendfile_counters_p.is_null() {
        // SAFETY: unique sendfile counter block allocated with the descriptor.
        drop(unsafe { Box::from_raw(desc.sendfile_counters_p) });
        desc.sendfile_counters_p = ptr::null_mut();
    }
    if desc.sendfile_handle != INVALID_SOCKET {
        close_fd(desc.sendfile_handle);
        desc.sendfile_handle = INVALID_SOCKET;
    }
    free_env(desc.close_env);
    desc.close_env = ptr::null_mut();
    free_env(desc.meta.env);
    desc.meta.env = ptr::null_mut();
}
