//! Port of `ESockDescriptor` in erts/emulator/nifs/common/prim_socket_int.h, OTP-29.1.1.
//!
//! The socket NIF resource *is* this descriptor: `esock_alloc_descriptor` allocates it as
//! the `enif_alloc_resource` user data. Mutexes are the erts split (`readMtx`, `writeMtx`);
//! lock order is read, then write. `mb->orig_size` uses `sizeof(ESockDescriptor)` (the erts
//! prefix) plus the resource head and monitors block.

use super::raw;
use super::{Kind, Requestor, Sock, state_bits};
use crate::{atom, pair};
use arinsal_etf::OwnedTerm as O;
use arinsal_nif::ResourceMonitors;
use arinsal_term::MagicBin;
use std::ffi::c_void;
use std::mem::{offset_of, size_of};
use std::sync::Mutex;

/// `ErlNifPid`.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct ErlNifPid {
    pub pid: usize,
}

/// `ErlDrvMonitor` / `ErlNifMonitor`: `sizeof(void *)*4`.
#[repr(C)]
pub(crate) struct ErlNifMonitor {
    pub data: [u8; size_of::<*mut c_void>() * 4],
}

/// Public `ErlNifBinary`.
#[repr(C)]
pub(crate) struct ErlNifBinary {
    pub size: usize,
    pub data: *mut u8,
    pub ref_bin: *mut c_void,
    pub spare: [*mut c_void; 2],
}

/// `BOOLEAN_T` in socket_int.h.
pub(crate) type BooleanT = i32;
/// `SOCKET` / `HANDLE` on Unix.
pub(crate) type Socket = i32;
/// `ESOCK_COUNTER_SIZE` default 64.
pub(crate) type ESockCounter = u64;

/// `INVALID_SOCKET` / `INVALID_HANDLE`.
pub(crate) const INVALID_SOCKET: Socket = -1;
/// `ESOCK_DESC_PATTERN_CREATED`.
pub(crate) const PATTERN_CREATED: u32 = 0x0303_0303;
/// `ESOCK_DESC_PATTERN_DTOR`.
pub(crate) const PATTERN_DTOR: u32 = 0xC0C0_C0C0;
/// `ESOCK_RECV_BUFFER_SIZE_DEFAULT`.
pub(crate) const RECV_BUFFER_SIZE_DEFAULT: usize = 8 * 1024;
/// `ESOCK_RECV_CTRL_BUFFER_SIZE_DEFAULT`.
pub(crate) const RECV_CTRL_BUFFER_SIZE_DEFAULT: usize = 1024;
/// `ESOCK_SEND_CTRL_BUFFER_SIZE_DEFAULT`.
pub(crate) const SEND_CTRL_BUFFER_SIZE_DEFAULT: usize = 1024;

/// `ESockMonitor`.
#[repr(C)]
pub(crate) struct ESockMonitor {
    pub mon: ErlNifMonitor,
    pub is_active: BooleanT,
}

/// `ESockRequestor`.
#[repr(C)]
pub(crate) struct ESockRequestor {
    pub pid: ErlNifPid,
    pub mon: ESockMonitor,
    pub env: *mut c_void,
    pub r#ref: usize,
    pub sock: Socket,
    pub data_p: *mut c_void,
}

/// `ESockRequestQueueElement`.
#[repr(C)]
pub(crate) struct ESockRequestQueueElement {
    pub next_p: *mut ESockRequestQueueElement,
    pub data: ESockRequestor,
}

/// `ESockRequestQueue`.
#[repr(C)]
pub(crate) struct ESockRequestQueue {
    pub first: *mut ESockRequestQueueElement,
    pub last: *mut ESockRequestQueueElement,
}

/// `ESockMeta`.
#[repr(C)]
pub(crate) struct ESockMeta {
    pub env: *mut c_void,
    pub r#ref: usize,
}

/// `ESockSendfileCounters`.
#[repr(C)]
pub(crate) struct ESockSendfileCounters {
    pub cnt: ESockCounter,
    pub byte_cnt: ESockCounter,
    pub fails: ESockCounter,
    pub max: ESockCounter,
    pub max_cnt: ESockCounter,
    pub pkg: ESockCounter,
    pub pkg_max: ESockCounter,
    pub tries: ESockCounter,
    pub waits: ESockCounter,
}

/// Unix `ESockDescriptor` with `HAVE_SENDFILE`. The erts user-data prefix is 840 bytes on
/// 64-bit; `monitors` and `selector` follow it the way `ErtsResourceMonitors` and the
/// `enif_select` keep sit outside the descriptor.
#[repr(C)]
pub struct ESockDescriptor {
    pub(crate) pattern: u32,
    pub(crate) domain: i32,
    pub(crate) type_: i32,
    pub(crate) protocol: i32,
    pub(crate) write_mtx: *mut Mutex<()>,
    pub(crate) write_state: u32,
    pub(crate) current_writer: ESockRequestor,
    pub(crate) current_writer_p: *mut ESockRequestor,
    pub(crate) writers_q: ESockRequestQueue,
    pub(crate) write_pkg_cnt: ESockCounter,
    pub(crate) write_pkg_max: ESockCounter,
    pub(crate) write_pkg_max_cnt: ESockCounter,
    pub(crate) write_byte_cnt: ESockCounter,
    pub(crate) write_tries: ESockCounter,
    pub(crate) write_waits: ESockCounter,
    pub(crate) write_fails: ESockCounter,
    pub(crate) sendfile_handle: Socket,
    pub(crate) sendfile_counters_p: *mut ESockSendfileCounters,
    pub(crate) connector: ESockRequestor,
    pub(crate) connector_p: *mut ESockRequestor,
    pub(crate) w_ctrl_sz: usize,
    pub(crate) meta: ESockMeta,
    pub(crate) read_mtx: *mut Mutex<()>,
    pub(crate) read_state: u32,
    pub(crate) current_reader: ESockRequestor,
    pub(crate) current_reader_p: *mut ESockRequestor,
    pub(crate) buf: ErlNifBinary,
    pub(crate) readers_q: ESockRequestQueue,
    pub(crate) read_pkg_cnt: ESockCounter,
    pub(crate) read_pkg_max: ESockCounter,
    pub(crate) read_pkg_max_cnt: ESockCounter,
    pub(crate) read_byte_cnt: ESockCounter,
    pub(crate) read_tries: ESockCounter,
    pub(crate) read_waits: ESockCounter,
    pub(crate) read_fails: ESockCounter,
    pub(crate) current_acceptor: ESockRequestor,
    pub(crate) current_acceptor_p: *mut ESockRequestor,
    pub(crate) acceptors_q: ESockRequestQueue,
    pub(crate) acc_success: ESockCounter,
    pub(crate) acc_tries: ESockCounter,
    pub(crate) acc_waits: ESockCounter,
    pub(crate) acc_fails: ESockCounter,
    pub(crate) r_buf_sz: usize,
    pub(crate) r_num: u32,
    pub(crate) r_num_cnt: u32,
    pub(crate) r_ctrl_sz: usize,
    pub(crate) closer_pid: ErlNifPid,
    pub(crate) closer_mon: ESockMonitor,
    pub(crate) close_env: *mut c_void,
    pub(crate) close_ref: usize,
    pub(crate) iow: BooleanT,
    pub(crate) ctrl_pid: ErlNifPid,
    pub(crate) ctrl_mon: ESockMonitor,
    pub(crate) sock: Socket,
    pub(crate) orig_fd: Socket,
    pub(crate) close_on_close: BooleanT,
    pub(crate) select_read: BooleanT,
    pub(crate) dbg: BooleanT,
    pub(crate) use_reg: BooleanT,
    /// `resource->monitors`: origin halves of `enif_monitor_process`.
    pub(crate) monitors: ResourceMonitors,
    /// The `enif_select` keep until `esock_stop`.
    pub(crate) selector: Mutex<Option<MagicBin>>,
}

/// `sizeof(ESockDescriptor)` used as `enif_alloc_resource` `data_sz`.
pub const ESOCK_DESCRIPTOR_SIZE: usize = offset_of!(ESockDescriptor, monitors);

/// The socket resource payload. Same type as [`ESockDescriptor`].
pub(crate) type Handle = ESockDescriptor;

impl ESockDescriptor {
    /// `enif_keep_resource` for the select machinery, on the first selection.
    pub(crate) fn keep_for_select(&self, owner: &MagicBin) {
        let mut selector = self
            .selector
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if selector.is_none() {
            *selector = Some(owner.clone());
        }
    }

    /// `enif_release_resource` for the select machinery, when the stop callback has run.
    pub(crate) fn release_for_select(&self) {
        let selector = self
            .selector
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        drop(selector);
    }

    /// `MLOCK(descP->readMtx)`.
    pub(crate) fn lock_read(&self) -> DescLock<'_> {
        DescLock {
            _read: Some(
                raw::mutex_ref(self.read_mtx, self)
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner),
            ),
            _write: None,
            desc: self,
        }
    }

    /// `MLOCK(descP->writeMtx)`.
    pub(crate) fn lock_write(&self) -> DescLock<'_> {
        DescLock {
            _read: None,
            _write: Some(
                raw::mutex_ref(self.write_mtx, self)
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner),
            ),
            desc: self,
        }
    }

    /// Lock order: `readMtx`, `writeMtx`.
    pub(crate) fn lock_both(&self) -> DescLock<'_> {
        DescLock {
            _read: Some(
                raw::mutex_ref(self.read_mtx, self)
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner),
            ),
            _write: Some(
                raw::mutex_ref(self.write_mtx, self)
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner),
            ),
            desc: self,
        }
    }

    /// `descP->domain` as the OTP atom name.
    pub(crate) fn domain_name(&self) -> &'static str {
        match self.domain {
            libc::AF_INET => "inet",
            libc::AF_INET6 => "inet6",
            libc::AF_UNIX => "local",
            _ => "inet",
        }
    }

    /// `descP->type` as the OTP atom name.
    pub(crate) fn type_name(&self) -> &'static str {
        match self.type_ {
            libc::SOCK_STREAM => "stream",
            libc::SOCK_DGRAM => "dgram",
            libc::SOCK_SEQPACKET => "seqpacket",
            libc::SOCK_RAW => "raw",
            _ => "stream",
        }
    }

    /// `esock_socket_info_ctype`.
    pub(crate) fn ctype(&self) -> O {
        if self.orig_fd != INVALID_SOCKET {
            if self.close_on_close != 0 {
                pair(atom("fromfd"), O::Int(self.orig_fd.into()))
            } else {
                atom("fromfd")
            }
        } else {
            atom("normal")
        }
    }
}

impl Drop for ESockDescriptor {
    /// `esock_dtor`: `essio_dtor` then destroy the erts mutexes.
    fn drop(&mut self) {
        super::lifecycle::dtor(self);
        raw::destroy_mutexes(self);
    }
}

/// A held `readMtx` and/or `writeMtx`. Field access is the erts split: read-side fields
/// need `readMtx`, write-side fields need `writeMtx`, and closer/ctrl/sock need both to write.
pub(crate) struct DescLock<'a> {
    _read: Option<std::sync::MutexGuard<'a, ()>>,
    _write: Option<std::sync::MutexGuard<'a, ()>>,
    desc: &'a ESockDescriptor,
}

impl DescLock<'_> {
    fn has_read(&self) -> bool {
        self._read.is_some()
    }
    fn has_write(&self) -> bool {
        self._write.is_some()
    }
    fn has_both(&self) -> bool {
        self.has_read() && self.has_write()
    }

    pub(crate) fn read_state(&self) -> u32 {
        debug_assert!(self.has_read() || self.has_write());
        raw::read_u32(&self.desc.read_state)
    }
    pub(crate) fn set_read_state(&mut self, value: u32) {
        debug_assert!(self.has_read());
        raw::write_u32(&self.desc.read_state, value);
    }
    pub(crate) fn or_read_state(&mut self, bits: u32) {
        let value = self.read_state() | bits;
        self.set_read_state(value);
    }
    pub(crate) fn and_read_state(&mut self, bits: u32) {
        let value = self.read_state() & bits;
        self.set_read_state(value);
    }
    pub(crate) fn write_state(&self) -> u32 {
        debug_assert!(self.has_write() || self.has_read());
        raw::read_u32(&self.desc.write_state)
    }
    pub(crate) fn set_write_state(&mut self, value: u32) {
        debug_assert!(self.has_write());
        raw::write_u32(&self.desc.write_state, value);
    }
    pub(crate) fn or_write_state(&mut self, bits: u32) {
        let value = self.write_state() | bits;
        self.set_write_state(value);
    }
    pub(crate) fn and_write_state(&mut self, bits: u32) {
        let value = self.write_state() & bits;
        self.set_write_state(value);
    }

    pub(crate) fn sock(&self) -> Option<i32> {
        let fd = raw::read_i32(&self.desc.sock);
        (fd != INVALID_SOCKET).then_some(fd)
    }
    pub(crate) fn take_sock(&mut self) -> Option<i32> {
        debug_assert!(self.has_both());
        let fd = self.sock();
        raw::write_i32(&self.desc.sock, INVALID_SOCKET);
        fd
    }
    pub(crate) fn open_sock(&self, state: u32) -> Option<i32> {
        self.sock().filter(|_| state_bits::is_open(state))
    }

    pub(crate) fn ctrl_pid(&self) -> Option<O> {
        raw::load_pid(self.desc.ctrl_pid)
    }
    pub(crate) fn set_ctrl_pid(&mut self, pid: Option<&O>) {
        debug_assert!(self.has_both());
        raw::store_pid(&self.desc.ctrl_pid, pid);
    }
    pub(crate) fn ctrl_mon(&self) -> Option<u64> {
        raw::load_monitor(&self.desc.ctrl_mon)
    }
    pub(crate) fn set_ctrl_mon(&mut self, mon: Option<u64>) {
        debug_assert!(self.has_both());
        raw::store_monitor(&self.desc.ctrl_mon, mon);
    }
    pub(crate) fn take_ctrl_mon(&mut self) -> Option<u64> {
        let mon = self.ctrl_mon();
        self.set_ctrl_mon(None);
        mon
    }

    pub(crate) fn closer(&self) -> Option<O> {
        raw::load_pid(self.desc.closer_pid)
    }
    pub(crate) fn set_closer(&mut self, pid: Option<&O>) {
        debug_assert!(self.has_both());
        raw::store_pid(&self.desc.closer_pid, pid);
    }
    pub(crate) fn closer_mon(&self) -> Option<u64> {
        raw::load_monitor(&self.desc.closer_mon)
    }
    pub(crate) fn set_closer_mon(&mut self, mon: Option<u64>) {
        debug_assert!(self.has_both());
        raw::store_monitor(&self.desc.closer_mon, mon);
    }
    pub(crate) fn take_closer_mon(&mut self) -> Option<u64> {
        let mon = self.closer_mon();
        self.set_closer_mon(None);
        mon
    }
    pub(crate) fn close_ref(&self) -> Option<O> {
        raw::load_env_term(self.desc.close_env)
    }
    pub(crate) fn set_close_ref(&mut self, value: Option<&O>) {
        debug_assert!(self.has_both());
        raw::store_env_term(&self.desc.close_env, value);
    }
    pub(crate) fn take_close_ref(&mut self) -> Option<O> {
        let value = self.close_ref();
        self.set_close_ref(None);
        value
    }

    pub(crate) fn current(&self, kind: Kind) -> Option<Requestor> {
        match kind {
            Kind::Writer => {
                debug_assert!(self.has_write());
                raw::load_current(&self.desc.current_writer, self.desc.current_writer_p)
            }
            Kind::Reader => {
                debug_assert!(self.has_read());
                raw::load_current(&self.desc.current_reader, self.desc.current_reader_p)
            }
            Kind::Acceptor => {
                debug_assert!(self.has_read());
                raw::load_current(&self.desc.current_acceptor, self.desc.current_acceptor_p)
            }
        }
    }
    pub(crate) fn set_current(&mut self, kind: Kind, requestor: Option<Requestor>) {
        match kind {
            Kind::Writer => {
                debug_assert!(self.has_write());
                raw::store_current(
                    &self.desc.current_writer,
                    &self.desc.current_writer_p,
                    requestor,
                    self.desc.sock,
                );
            }
            Kind::Reader => {
                debug_assert!(self.has_read());
                raw::store_current(
                    &self.desc.current_reader,
                    &self.desc.current_reader_p,
                    requestor,
                    self.desc.sock,
                );
            }
            Kind::Acceptor => {
                debug_assert!(self.has_read());
                raw::store_current(
                    &self.desc.current_acceptor,
                    &self.desc.current_acceptor_p,
                    requestor,
                    self.desc.sock,
                );
            }
        }
    }
    pub(crate) fn take_current(&mut self, kind: Kind) -> Option<Requestor> {
        let current = self.current(kind);
        self.set_current(kind, None);
        current
    }
    pub(crate) fn current_writer(&self) -> Option<Requestor> {
        self.current(Kind::Writer)
    }
    pub(crate) fn current_reader(&self) -> Option<Requestor> {
        self.current(Kind::Reader)
    }
    pub(crate) fn current_acceptor(&self) -> Option<Requestor> {
        self.current(Kind::Acceptor)
    }
    pub(crate) fn connector(&self) -> Option<Requestor> {
        debug_assert!(self.has_write());
        raw::load_current(&self.desc.connector, self.desc.connector_p)
    }
    pub(crate) fn set_connector(&mut self, requestor: Option<Requestor>) {
        debug_assert!(self.has_write());
        raw::store_current(
            &self.desc.connector,
            &self.desc.connector_p,
            requestor,
            self.desc.sock,
        );
    }
    pub(crate) fn take_connector(&mut self) -> Option<Requestor> {
        let connector = self.connector();
        self.set_connector(None);
        connector
    }

    fn queue(&self, kind: Kind) -> *mut ESockRequestQueue {
        match kind {
            Kind::Writer => {
                debug_assert!(self.has_write());
                &self.desc.writers_q as *const _ as *mut _
            }
            Kind::Reader => {
                debug_assert!(self.has_read());
                &self.desc.readers_q as *const _ as *mut _
            }
            Kind::Acceptor => {
                debug_assert!(self.has_read());
                &self.desc.acceptors_q as *const _ as *mut _
            }
        }
    }
    pub(crate) fn queue_len(&self, kind: Kind) -> usize {
        raw::queue_len(self.queue(kind))
    }
    #[allow(dead_code)]
    pub(crate) fn queue_is_empty(&self, kind: Kind) -> bool {
        self.queue_len(kind) == 0
    }

    /// `esock_{acceptor,writer,reader}_search4pid`.
    pub(crate) fn search4pid(&self, kind: Kind, pid: &O) -> bool {
        raw::queue_search(self.queue(kind), pid)
    }
    /// `esock_{acceptor,writer,reader}_push`.
    pub(crate) fn push(&mut self, h: &Sock, kind: Kind, pid: &O, reference: &O) {
        let mon = super::monitor_process(h, pid);
        raw::queue_push(
            self.queue(kind),
            Requestor {
                pid: pid.clone(),
                reference: reference.clone(),
                mon,
            },
            self.desc.sock,
        );
    }
    /// `esock_requestor_pop`.
    pub(crate) fn pop(&mut self, kind: Kind) -> bool {
        let next = raw::queue_pop(self.queue(kind));
        let popped = next.is_some();
        self.set_current(kind, next);
        popped
    }
    /// `esock_{acceptor,writer,reader}_unqueue`.
    pub(crate) fn unqueue(&mut self, h: &Sock, kind: Kind, reference: Option<&O>, pid: &O) -> bool {
        match raw::queue_unqueue(self.queue(kind), pid, reference) {
            Some(req) => {
                super::demonitor_process(h, &req.pid, req.mon);
                true
            }
            None => false,
        }
    }
    pub(crate) fn drain_queue(&mut self, kind: Kind) -> Vec<Requestor> {
        raw::queue_drain(self.queue(kind))
    }

    pub(crate) fn r_num_cnt(&self) -> u32 {
        debug_assert!(self.has_read());
        raw::read_u32(&self.desc.r_num_cnt)
    }
    pub(crate) fn set_r_num_cnt(&mut self, value: u32) {
        debug_assert!(self.has_read());
        raw::write_u32(&self.desc.r_num_cnt, value);
    }
    pub(crate) fn r_num(&self) -> u32 {
        debug_assert!(self.has_read());
        raw::read_u32(&self.desc.r_num)
    }
    pub(crate) fn set_r_num(&mut self, value: u32) {
        debug_assert!(self.has_read());
        raw::write_u32(&self.desc.r_num, value);
    }
    pub(crate) fn r_buf_sz(&self) -> usize {
        debug_assert!(self.has_read());
        raw::read_usize(&self.desc.r_buf_sz)
    }
    pub(crate) fn set_r_buf_sz(&mut self, value: usize) {
        debug_assert!(self.has_read());
        raw::write_usize(&self.desc.r_buf_sz, value);
    }
    pub(crate) fn r_ctrl_sz(&self) -> usize {
        debug_assert!(self.has_read());
        raw::read_usize(&self.desc.r_ctrl_sz)
    }
    pub(crate) fn set_r_ctrl_sz(&mut self, value: usize) {
        debug_assert!(self.has_read());
        raw::write_usize(&self.desc.r_ctrl_sz, value);
    }
    pub(crate) fn w_ctrl_sz(&self) -> usize {
        debug_assert!(self.has_write());
        raw::read_usize(&self.desc.w_ctrl_sz)
    }
    pub(crate) fn set_w_ctrl_sz(&mut self, value: usize) {
        debug_assert!(self.has_write());
        raw::write_usize(&self.desc.w_ctrl_sz, value);
    }
    pub(crate) fn dbg(&self) -> bool {
        raw::read_i32(&self.desc.dbg) != 0
    }
    pub(crate) fn set_dbg(&mut self, value: bool) {
        debug_assert!(self.has_write());
        raw::write_i32(&self.desc.dbg, i32::from(value));
    }
    pub(crate) fn iow(&self) -> bool {
        raw::read_i32(&self.desc.iow) != 0
    }
    pub(crate) fn set_iow(&mut self, value: bool) {
        debug_assert!(self.has_write());
        raw::write_i32(&self.desc.iow, i32::from(value));
    }
    pub(crate) fn select_read(&self) -> bool {
        raw::read_i32(&self.desc.select_read) != 0
    }
    pub(crate) fn set_select_read(&mut self, value: bool) {
        debug_assert!(self.has_read());
        raw::write_i32(&self.desc.select_read, i32::from(value));
    }
    pub(crate) fn use_reg(&self) -> bool {
        raw::read_i32(&self.desc.use_reg) != 0
    }
    pub(crate) fn set_use_reg(&mut self, value: bool) {
        debug_assert!(self.has_write());
        raw::write_i32(&self.desc.use_reg, i32::from(value));
    }
    pub(crate) fn meta(&self) -> Option<O> {
        debug_assert!(self.has_write());
        raw::load_env_term(self.desc.meta.env)
    }
    pub(crate) fn set_meta(&mut self, value: Option<&O>) {
        debug_assert!(self.has_write());
        raw::store_env_term(&self.desc.meta.env, value);
    }
    pub(crate) fn clear_meta(&mut self) {
        self.set_meta(None);
    }

    pub(crate) fn recv_alloc_buf(&mut self, size: usize) {
        debug_assert!(self.has_read());
        raw::recv_alloc_buf(&self.desc.buf, size);
    }
    pub(crate) fn recv_buf_ptr(&self) -> (*mut u8, usize) {
        debug_assert!(self.has_read());
        raw::recv_buf_ptr(&self.desc.buf)
    }
    pub(crate) fn recv_buf_len(&self) -> usize {
        debug_assert!(self.has_read());
        raw::read_usize(&self.desc.buf.size)
    }
    pub(crate) fn recv_create_bin(&mut self, size: usize) -> Vec<u8> {
        debug_assert!(self.has_read());
        raw::recv_create_bin(&self.desc.buf, size)
    }

    pub(crate) fn sendfile_handle(&self) -> Option<i32> {
        debug_assert!(self.has_write());
        let fd = raw::read_i32(&self.desc.sendfile_handle);
        (fd != INVALID_SOCKET).then_some(fd)
    }
    pub(crate) fn set_sendfile_handle(&mut self, fd: Option<i32>) {
        debug_assert!(self.has_write());
        if let Some(prev) = self.sendfile_handle() {
            raw::close_fd(prev);
        }
        raw::write_i32(&self.desc.sendfile_handle, fd.unwrap_or(INVALID_SOCKET));
    }
    pub(crate) fn take_sendfile_handle(&mut self) -> Option<i32> {
        let fd = self.sendfile_handle();
        raw::write_i32(&self.desc.sendfile_handle, INVALID_SOCKET);
        fd
    }

    pub(crate) fn add_write_tries(&mut self, n: u64) {
        debug_assert!(self.has_write());
        raw::add_u64(&self.desc.write_tries, n);
    }
    pub(crate) fn add_write_waits(&mut self, n: u64) {
        debug_assert!(self.has_write());
        raw::add_u64(&self.desc.write_waits, n);
    }
    pub(crate) fn add_write_fails(&mut self, n: u64) {
        debug_assert!(self.has_write());
        raw::add_u64(&self.desc.write_fails, n);
    }
    pub(crate) fn add_write_pkg(&mut self, n: u64) {
        debug_assert!(self.has_write());
        raw::add_u64(&self.desc.write_pkg_cnt, n);
    }
    pub(crate) fn add_write_byte(&mut self, n: u64) {
        debug_assert!(self.has_write());
        raw::add_u64(&self.desc.write_byte_cnt, n);
    }
    pub(crate) fn add_write_pkg_max_cnt(&mut self, n: u64) {
        debug_assert!(self.has_write());
        raw::add_u64(&self.desc.write_pkg_max_cnt, n);
    }
    pub(crate) fn finish_write_pkg_max(&mut self) {
        debug_assert!(self.has_write());
        let cnt = raw::read_u64(&self.desc.write_pkg_max_cnt);
        let max = raw::read_u64(&self.desc.write_pkg_max);
        if cnt > max {
            raw::write_u64(&self.desc.write_pkg_max, cnt);
        }
        raw::write_u64(&self.desc.write_pkg_max_cnt, 0);
    }
    #[allow(dead_code)]
    pub(crate) fn write_tries(&self) -> u64 {
        raw::read_u64(&self.desc.write_tries)
    }
    #[allow(dead_code)]
    pub(crate) fn write_waits(&self) -> u64 {
        raw::read_u64(&self.desc.write_waits)
    }
    #[allow(dead_code)]
    pub(crate) fn write_fails(&self) -> u64 {
        raw::read_u64(&self.desc.write_fails)
    }
    #[allow(dead_code)]
    pub(crate) fn write_pkg(&self) -> u64 {
        raw::read_u64(&self.desc.write_pkg_cnt)
    }
    #[allow(dead_code)]
    pub(crate) fn write_byte(&self) -> u64 {
        raw::read_u64(&self.desc.write_byte_cnt)
    }
    pub(crate) fn add_read_tries(&mut self, n: u64) {
        debug_assert!(self.has_read());
        raw::add_u64(&self.desc.read_tries, n);
    }
    pub(crate) fn add_read_fails(&mut self, n: u64) {
        debug_assert!(self.has_read());
        raw::add_u64(&self.desc.read_fails, n);
    }
    pub(crate) fn add_read_pkg(&mut self, n: u64) {
        debug_assert!(self.has_read());
        raw::add_u64(&self.desc.read_pkg_cnt, n);
    }
    pub(crate) fn add_read_byte(&mut self, n: u64) {
        debug_assert!(self.has_read());
        raw::add_u64(&self.desc.read_byte_cnt, n);
    }
    pub(crate) fn add_read_pkg_max_cnt(&mut self, n: u64) {
        debug_assert!(self.has_read());
        raw::add_u64(&self.desc.read_pkg_max_cnt, n);
    }
    pub(crate) fn finish_read_pkg_max(&mut self) {
        debug_assert!(self.has_read());
        let cnt = raw::read_u64(&self.desc.read_pkg_max_cnt);
        let max = raw::read_u64(&self.desc.read_pkg_max);
        if cnt > max {
            raw::write_u64(&self.desc.read_pkg_max, cnt);
        }
        raw::write_u64(&self.desc.read_pkg_max_cnt, 0);
    }
    pub(crate) fn bump_read_pkg_max(&mut self, size: u64) {
        debug_assert!(self.has_read());
        let max = raw::read_u64(&self.desc.read_pkg_max);
        if size > max {
            raw::write_u64(&self.desc.read_pkg_max, size);
        }
    }
    pub(crate) fn set_pattern(&mut self, value: u32) {
        raw::write_u32(&self.desc.pattern, value);
    }
    pub(crate) fn add_acc_tries(&mut self, n: u64) {
        debug_assert!(self.has_read());
        raw::add_u64(&self.desc.acc_tries, n);
    }
    pub(crate) fn add_acc_fails(&mut self, n: u64) {
        debug_assert!(self.has_read());
        raw::add_u64(&self.desc.acc_fails, n);
    }
    pub(crate) fn add_acc_waits(&mut self, n: u64) {
        debug_assert!(self.has_read());
        raw::add_u64(&self.desc.acc_waits, n);
    }
    pub(crate) fn add_acc_success(&mut self, n: u64) {
        debug_assert!(self.has_read());
        raw::add_u64(&self.desc.acc_success, n);
    }
    pub(crate) fn counters_term(&self) -> O {
        debug_assert!(self.has_both());
        super::map(&[
            (
                "read_tries",
                O::Int(raw::read_u64(&self.desc.read_tries) as i64),
            ),
            (
                "read_pkg",
                O::Int(raw::read_u64(&self.desc.read_pkg_cnt) as i64),
            ),
            (
                "read_byte",
                O::Int(raw::read_u64(&self.desc.read_byte_cnt) as i64),
            ),
            (
                "read_fails",
                O::Int(raw::read_u64(&self.desc.read_fails) as i64),
            ),
            (
                "read_waits",
                O::Int(raw::read_u64(&self.desc.read_waits) as i64),
            ),
            (
                "read_pkg_max",
                O::Int(raw::read_u64(&self.desc.read_pkg_max) as i64),
            ),
            (
                "write_tries",
                O::Int(raw::read_u64(&self.desc.write_tries) as i64),
            ),
            (
                "write_pkg",
                O::Int(raw::read_u64(&self.desc.write_pkg_cnt) as i64),
            ),
            (
                "write_byte",
                O::Int(raw::read_u64(&self.desc.write_byte_cnt) as i64),
            ),
            (
                "write_fails",
                O::Int(raw::read_u64(&self.desc.write_fails) as i64),
            ),
            (
                "write_waits",
                O::Int(raw::read_u64(&self.desc.write_waits) as i64),
            ),
            (
                "write_pkg_max",
                O::Int(raw::read_u64(&self.desc.write_pkg_max) as i64),
            ),
            (
                "acc_tries",
                O::Int(raw::read_u64(&self.desc.acc_tries) as i64),
            ),
            (
                "acc_success",
                O::Int(raw::read_u64(&self.desc.acc_success) as i64),
            ),
            (
                "acc_fails",
                O::Int(raw::read_u64(&self.desc.acc_fails) as i64),
            ),
            (
                "acc_waits",
                O::Int(raw::read_u64(&self.desc.acc_waits) as i64),
            ),
        ])
    }
}

/// `esock_alloc_descriptor` plus domain/type/protocol and the open options.
#[allow(clippy::too_many_arguments)]
pub(crate) fn alloc(
    sock: i32,
    domain: i32,
    type_: i32,
    protocol: i32,
    orig_fd: i32,
    close_on_close: bool,
    dbg: bool,
    use_reg: bool,
) -> ESockDescriptor {
    let desc = ESockDescriptor {
        pattern: PATTERN_CREATED,
        domain,
        type_,
        protocol,
        write_mtx: raw::create_mutex(),
        write_state: 0,
        current_writer: raw::requestor_init(),
        current_writer_p: std::ptr::null_mut(),
        writers_q: ESockRequestQueue {
            first: std::ptr::null_mut(),
            last: std::ptr::null_mut(),
        },
        write_pkg_cnt: 0,
        write_pkg_max: 0,
        write_pkg_max_cnt: 0,
        write_byte_cnt: 0,
        write_tries: 0,
        write_waits: 0,
        write_fails: 0,
        sendfile_handle: INVALID_SOCKET,
        sendfile_counters_p: std::ptr::null_mut(),
        connector: raw::requestor_init(),
        connector_p: std::ptr::null_mut(),
        w_ctrl_sz: SEND_CTRL_BUFFER_SIZE_DEFAULT,
        meta: ESockMeta {
            env: std::ptr::null_mut(),
            r#ref: 0,
        },
        read_mtx: raw::create_mutex(),
        read_state: 0,
        current_reader: raw::requestor_init(),
        current_reader_p: std::ptr::null_mut(),
        buf: ErlNifBinary {
            size: 0,
            data: std::ptr::null_mut(),
            ref_bin: std::ptr::null_mut(),
            spare: [std::ptr::null_mut(); 2],
        },
        readers_q: ESockRequestQueue {
            first: std::ptr::null_mut(),
            last: std::ptr::null_mut(),
        },
        read_pkg_cnt: 0,
        read_pkg_max: 0,
        read_pkg_max_cnt: 0,
        read_byte_cnt: 0,
        read_tries: 0,
        read_waits: 0,
        read_fails: 0,
        current_acceptor: raw::requestor_init(),
        current_acceptor_p: std::ptr::null_mut(),
        acceptors_q: ESockRequestQueue {
            first: std::ptr::null_mut(),
            last: std::ptr::null_mut(),
        },
        acc_success: 0,
        acc_tries: 0,
        acc_waits: 0,
        acc_fails: 0,
        r_buf_sz: RECV_BUFFER_SIZE_DEFAULT,
        r_num: 0,
        r_num_cnt: 0,
        r_ctrl_sz: RECV_CTRL_BUFFER_SIZE_DEFAULT,
        closer_pid: ErlNifPid { pid: 0 },
        closer_mon: raw::monitor_init(),
        close_env: std::ptr::null_mut(),
        close_ref: 0,
        iow: 0,
        ctrl_pid: ErlNifPid { pid: 0 },
        ctrl_mon: raw::monitor_init(),
        sock,
        orig_fd,
        close_on_close: i32::from(close_on_close),
        select_read: 0,
        dbg: i32::from(dbg),
        use_reg: i32::from(use_reg),
        monitors: ResourceMonitors::new(),
        selector: Mutex::new(None),
    };
    debug_assert_eq!(ESOCK_DESCRIPTOR_SIZE, 840);
    desc
}

#[cfg(all(test, unix, target_pointer_width = "64"))]
mod tests {
    use super::{
        ESOCK_DESCRIPTOR_SIZE, ESockDescriptor, ESockMonitor, ESockRequestor, ErlNifBinary,
        ErlNifMonitor, ErlNifPid,
    };
    use std::mem::{align_of, offset_of, size_of};

    #[test]
    fn unix_64_layout_matches_otp_29() {
        assert_eq!(size_of::<ErlNifPid>(), 8);
        assert_eq!(size_of::<ErlNifMonitor>(), 32);
        assert_eq!(size_of::<ErlNifBinary>(), 40);
        assert_eq!(size_of::<ESockMonitor>(), 36);
        assert_eq!(size_of::<ESockRequestor>(), 80);
        assert_eq!(align_of::<ESockDescriptor>(), 8);
        assert_eq!(ESOCK_DESCRIPTOR_SIZE, 840);
        assert_eq!(offset_of!(ESockDescriptor, sendfile_handle), 192);
        assert_eq!(offset_of!(ESockDescriptor, sendfile_counters_p), 200);
        assert_eq!(offset_of!(ESockDescriptor, sock), 812);
        assert_eq!(offset_of!(ESockDescriptor, monitors), 840);
    }
}
