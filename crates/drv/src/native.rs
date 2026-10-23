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

use crate::lock::ReentrantLock;
use crate::{Callbacks, ControlReply, Driver, DriverPort, ERL_DRV_FLAG_USE_PORT_LOCKING};

/// The callbacks of a native driver. Every method runs with the port lock held, like
/// the C callbacks of `erts_driver_t`.
pub trait NativeDriver: Send + Sync + 'static {
    /// `stop`: the port terminates.
    fn stop(&self, _port: &DriverPort) {}
    /// `output`/`outputv` with the flattened command data.
    fn output(&self, _port: &DriverPort, _data: &[u8]) {}
    /// `output` with a buffer the driver may keep (`erts_port_output` hands a native driver the
    /// flattened command without a second copy).
    fn output_owned(&self, port: &DriverPort, data: Vec<u8>) {
        self.output(port, &data);
    }
    /// `outputv` with a command whose reference-counted binaries are referenced, not copied
    /// (the `ErlIOVec` with `binv`). The default flattens it for `output_owned`.
    fn outputv_owned(&self, port: &DriverPort, pieces: Vec<crate::CommandPiece>) {
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
}

impl DriverPort {
    /// Mark the port as started with `data` as its driver state; no `start` callback
    /// runs (the VM built the state while creating the port).
    pub fn start_native(&self, data: Arc<dyn Any + Send + Sync>) {
        let _ = self.native_data.set(data);
        self.state
            .fetch_or(crate::SFLG_STARTED, std::sync::atomic::Ordering::AcqRel);
    }

    /// The driver state set by [`DriverPort::start_native`].
    pub fn native_data<T: Any + Send + Sync>(&self) -> Option<Arc<T>> {
        Arc::clone(self.native_data.get()?).downcast::<T>().ok()
    }

    /// This port as an `Arc`, for APIs that keep a reference (`driver_select`, timers).
    pub fn arc(&self) -> Arc<DriverPort> {
        self.me.upgrade().expect("a live port is owned by an Arc")
    }
}

/// `ERL_DRV_READ`.
pub const SELECT_READ: i32 = crate::select::READ;
/// `ERL_DRV_WRITE`.
pub const SELECT_WRITE: i32 = crate::select::WRITE;
/// `ERL_DRV_USE`: `stop_select` runs when the last event is removed.
pub const SELECT_USE: i32 = crate::select::USE;

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
