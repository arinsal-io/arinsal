//! Drivers written in Rust: the callbacks of an `ErlDrvEntry` as a trait.
//!
//! The inet drivers of erts are linked-in drivers (erts/emulator/drivers/common/inet_drv.c)
//! that run on the generic port machinery: port tasks, the port lock, `driver_select`,
//! port timers, `driver_set_busy_port`. A [`NativeDriver`] takes the place of the C entry
//! so such a driver runs on exactly that machinery without a C ABI in between. The
//! driver's state is the port's native data ([`DriverPort::native_data`]) instead of an
//! `ErlDrvData` pointer.

use std::any::Any;
use std::sync::Arc;

use parking_lot::Mutex;

use crate::PortRef;
use crate::lock::ReentrantLock;
use crate::{Callbacks, ControlReply, Driver, DriverPort, ERL_DRV_FLAG_USE_PORT_LOCKING};

/// The callbacks of a native driver. Every method runs with the port lock held, like
/// the C callbacks of `erts_driver_t`.
pub trait NativeDriver: Send + Sync + 'static {
    /// Whether this driver supplies `outputv` in its `ErlDrvEntry`.
    ///
    /// Port of erts/emulator/beam/io.c:7554 (`init_driver`), OTP-29.1.1.
    fn has_outputv(&self) -> bool {
        false
    }
    /// `stop`: the port terminates.
    fn stop(&self, _port: &DriverPort) {}
    /// `ready_async`: a job of [`DriverPort::driver_async`] finished.
    fn ready_async(&self, _port: &DriverPort) {}
    /// `flush`: the port closes with data left in its driver queue (io.c:3653 flush_port).
    fn flush(&self, _port: &DriverPort) {}
    /// `output`/`outputv` with the flattened command data.
    fn output(&self, _port: &DriverPort, _data: &[u8]) {}
    /// `output` with a buffer the driver may keep (`erts_port_output` hands a native driver the
    /// flattened command without a second copy).
    fn output_owned(&self, port: &DriverPort, data: Vec<u8>) {
        self.output(port, &data);
    }
    /// `outputv` with a command whose reference-counted binaries are referenced, not copied
    /// (the `ErlIOVec` with `binv`). The default flattens it for `output_owned`.
    fn outputv_owned(&self, port: &DriverPort, pieces: crate::CommandVector) {
        let mut data = Vec::new();
        for piece in &pieces {
            data.extend_from_slice(piece.bytes());
        }
        self.output_owned(port, data);
    }
    /// `control`; `None` is `badarg`.
    fn control(&self, _port: &DriverPort, _command: u32, _data: &[u8]) -> Option<ControlReply> {
        None
    }
    /// `ready_input` for descriptor `fd`.
    fn ready_input(&self, _port: &DriverPort, _fd: i32) {}
    /// `ready_output` for descriptor `fd`.
    fn ready_output(&self, _port: &DriverPort, _fd: i32) {}
    /// `timeout`: the port timer expired.
    fn timeout(&self, _port: &DriverPort) {}
    /// `stop_select`: nothing selects `fd` any more and the driver may close it.
    fn stop_select(&self, _fd: i32) {}
    /// `process_exit`: the process behind `monitor` exited.
    fn process_exit(&self, _port: &DriverPort, _monitor: u64) {}
}

impl Driver {
    /// A driver whose callbacks are `native` (`init_driver` of io.c:7554 for an entry
    /// that never lived in a library).
    pub fn native(name: &str, flags: i32, native: Arc<dyn NativeDriver>) -> Arc<Driver> {
        Arc::new(Driver {
            name: name.to_owned(),
            flags,
            callbacks: Callbacks::default(),
            library: Mutex::new(0),
            lock: (flags & ERL_DRV_FLAG_USE_PORT_LOCKING == 0).then(ReentrantLock::default),
            entry_addr: 0,
            native: Some(native),
        })
    }

    /// Whether this is a [`NativeDriver`] (it has no `ErlDrvEntry`).
    pub fn is_native(&self) -> bool {
        self.native.is_some()
    }

    /// Whether this driver has an `outputv` callback, as `erts_driver_t.outputv`.
    pub fn has_outputv(&self) -> bool {
        self.native
            .as_ref()
            .map_or(self.callbacks.outputv.is_some(), |native| {
                native.has_outputv()
            })
    }
}

impl DriverPort {
    /// Mark the port as started with `data` as its driver state; no `start` callback
    /// runs (the VM built the state while creating the port).
    pub fn start_native(&self, data: Arc<dyn Any + Send + Sync>) {
        let psd = self
            .psd
            .get_or_init(|| Box::new(super::PortSpecificData::new()));
        let _ = psd.native_data.set(data);
        self.state
            .fetch_or(crate::SFLG_STARTED, std::sync::atomic::Ordering::AcqRel);
    }

    /// The driver state set by [`DriverPort::start_native`].
    pub fn native_data<T: Any + Send + Sync>(&self) -> Option<Arc<T>> {
        let psd = self.psd.get()?;
        Arc::clone(psd.native_data.get()?).downcast::<T>().ok()
    }

    /// This port as an `Arc`, for APIs that keep a reference (`driver_select`, timers).
    pub fn arc(&self) -> PortRef {
        self.me.upgrade().expect("a live port is owned by an Arc")
    }
}

/// `ERL_DRV_READ`.
pub const SELECT_READ: i32 = crate::select::READ;
/// `ERL_DRV_WRITE`.
pub const SELECT_WRITE: i32 = crate::select::WRITE;
/// `ERL_DRV_USE`: `stop_select` runs when the last event is removed.
pub const SELECT_USE: i32 = crate::select::USE;
/// `ERL_DRV_USE_NO_CALLBACK`: the descriptor is released without `stop_select`.
pub const SELECT_USE_NO_CALLBACK: i32 = crate::select::USE_NO_CALLBACK;

impl DriverPort {
    /// `driver_select(port, fd, mode, on)` (erl_check_io.c:988).
    pub fn select(&self, fd: i32, mode: i32, on: bool) -> i32 {
        crate::select::driver_select(&self.arc(), fd, mode, on)
    }

    /// `driver_exit(port, 0)` (io.c:7230): unlink the connected process, then exit
    /// with reason `normal`.
    pub fn driver_exit(&self) {
        self.host.unlink_connected(self);
        self.failure(crate::ExitReason::Normal, false);
    }

    /// `set_busy_port(port, on)` (io.c:5203).
    pub fn set_busy(&self, on: bool) {
        self.set_busy_port(on);
    }

    /// `set_port_control_flags` (io.c:5312).
    pub fn set_control_flags(&self, flags: i32) {
        self.control_flags
            .store(flags, std::sync::atomic::Ordering::Release);
    }

    /// `driver_monitor_process` for the process with table data `pid`: the monitor id,
    /// `None` when the process does not exist.
    pub fn monitor(&self, pid: u64) -> Option<u64> {
        let mut monitor = crate::ErlDrvMonitor::new(0);
        (self.monitor_process(crate::termspec::mk_pid(pid), &mut monitor) == 0)
            .then(|| monitor.id())
    }

    /// `driver_demonitor_process`.
    pub fn demonitor(&self, monitor: u64) {
        self.demonitor_process(&crate::ErlDrvMonitor::new(monitor));
    }
}

/// The driver API of a native driver that erts drivers reach through `erl_driver.h`. Every
/// call is made from a driver callback, with the port lock held.
impl DriverPort {
    /// `driver_output(port, buf, len)` (io.c:6427).
    pub fn driver_output(&self, data: &[u8]) {
        self.output2(&[], Some(data));
    }

    /// `driver_failure_eof(port)` (io.c:7272).
    pub fn failure_eof(&self) {
        self.failure(crate::ExitReason::Normal, true);
    }

    /// `driver_failure_posix(port, errno)` (io.c:7267).
    pub fn failure_posix(&self, errno: i32) {
        self.failure(crate::ExitReason::Atom(crate::errno_id(errno)), false);
    }

    /// `driver_failure_atom(port, atom)` (io.c:7248).
    pub fn failure_atom(&self, atom: &str) {
        self.failure(crate::ExitReason::Atom(atom.to_owned()), false);
    }

    /// `driver_enq(port, buf, len)` (io.c:6852); `-1` on allocation failure.
    pub fn enq(&self, data: &[u8]) -> i32 {
        self.queue().enq_bytes(data)
    }

    /// `driver_deq(port, size)` (io.c:6801): the bytes left, `None` when fewer than `size`
    /// bytes are queued.
    pub fn deq(&self, size: usize) -> Option<usize> {
        let mut queue = self.queue();
        queue.deq(size).then(|| queue.size())
    }

    /// `driver_sizeq(port)` (io.c:6821).
    pub fn sizeq(&self) -> usize {
        self.queue_len()
    }

    /// `writev(fd, driver_peekq(port, &vsize))` with `vsize` capped at `max_vsize`
    /// (sys_drivers.c ready_output); the queue is left as it is.
    pub fn writev_queue(&self, fd: i32, max_vsize: usize) -> std::io::Result<usize> {
        self.queue().writev_head(fd, max_vsize)
    }

    /// `driver_peekq(port)[0]`: copy the start of the queue's head element into `out`; the
    /// bytes copied.
    pub fn peek_head(&self, out: &mut [u8]) -> usize {
        self.queue().copy_head(out)
    }

    /// `erl_drv_port_control(port, cmd, buf, len)` (io.c:4254) aimed at this port: an
    /// asynchronous control signal (`erts_schedule_port2port_signal` with
    /// `port_sig_control`). The driver's `control` runs under this port's lock as a port
    /// task and its reply is dropped. `false` when the port takes no more signals.
    pub fn port_control_async(&self, command: u32, data: Vec<u8>) -> bool {
        let target = self.arc();
        self.schedule_signal(crate::port_task::ProcSig {
            caller: crate::port_task::INVALID_CALLER,
            flags: 0,
            size: 0,
            deadline: None,
            callback: Box::new(move |op| {
                if op == crate::port_task::SigOp::Exec {
                    let _ = target.control(command, &data, crate::port_task::INVALID_CALLER);
                }
                0
            }),
        })
        .is_some()
    }

    /// `driver_async(port, key, invoke, ...)` (erl_async.c:541): `invoke` runs on the async
    /// thread of `key`, then [`NativeDriver::ready_async`] runs under the port lock.
    pub fn driver_async(&self, key: &mut u32, invoke: Box<dyn FnOnce() + Send>) {
        crate::asyncq::driver_async_native(self.arc(), Some(key), invoke);
    }

    /// `driver_async_port_key(port)` (erl_async.c:518).
    pub fn async_port_key(&self) -> u32 {
        self.id() as u32
    }

    /// `erl_drv_set_os_pid(port, pid)` (io.c:2965).
    pub fn set_os_pid(&self, pid: i64) {
        self.os_pid.store(pid, std::sync::atomic::Ordering::Release);
    }

    /// `erl_drv_init_ack(port, drv_data)` with a started driver (io.c:2927).
    pub fn init_ack_opened(&self) {
        self.init_ack(0);
    }

    /// `erl_drv_init_ack(port, ERL_DRV_ERROR_ERRNO)` with `errno` (io.c:2927).
    pub fn init_ack_errno(&self, errno: i32) {
        self.init_ack_failed(crate::StartError::Errno(errno));
    }
}
