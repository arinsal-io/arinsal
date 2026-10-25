//! Driver-side port state used by the library API (`driver_enq`, process
//! monitors, term output, busy flags, init acknowledgement).

use parking_lot::MutexGuard;
use std::ffi::c_int;
use std::sync::atomic::{AtomicU64, Ordering};

use arinsal_etf::OwnedTerm;

use crate::queue::IoQueue;
use crate::{
    DriverPort, ExitReason, SFLG_BINARY_IO, SFLG_LINEBUF_IO, SFLG_STARTED, SFLG_TERMINATING,
    StartError, layout, threads,
};
use crate::{lock, termspec};

/// `ErlDrvMonitor`: here the first word is the monitor id, the rest zero, so
/// `driver_compare_monitors` is a plain byte comparison as in erts.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ErlDrvMonitor {
    data: [u8; 4 * size_of::<usize>()],
}

const _: () = assert!(size_of::<ErlDrvMonitor>() == layout::SIZE_ErlDrvMonitor);

impl ErlDrvMonitor {
    pub(crate) fn new(id: u64) -> Self {
        let mut data = [0; 4 * size_of::<usize>()];
        data[..8].copy_from_slice(&id.to_le_bytes());
        Self { data }
    }

    pub(crate) fn id(&self) -> u64 {
        u64::from_le_bytes(self.data[..8].try_into().expect("eight bytes"))
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        &self.data
    }
}

/// Reply of `erl_drv_init_ack` for a port opened with `ERL_DRV_FLAG_USE_INIT_ACK`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InitAck {
    /// The port is open: `open_port` returns the port.
    Opened,
    /// The start failed: `open_port` fails like the same [`StartError`] of `start`.
    Failed(StartError),
}

/// The process monitors of a port, monitor id to process-table data. Ports hold few, so they
/// are a plain vector that allocates on the first monitor (`prt->common.monitors` is a null tree
/// until then in erts).
#[derive(Default)]
pub(crate) struct PidMonitors(Vec<(u64, u64)>);

impl PidMonitors {
    pub(crate) fn insert(&mut self, id: u64, pid: u64) {
        match self.0.iter_mut().find(|(key, _)| *key == id) {
            Some(entry) => entry.1 = pid,
            None => self.0.push((id, pid)),
        }
    }

    pub(crate) fn remove(&mut self, id: &u64) -> Option<u64> {
        let index = self.0.iter().position(|(key, _)| key == id)?;
        Some(self.0.swap_remove(index).1)
    }

    pub(crate) fn get(&self, id: &u64) -> Option<&u64> {
        self.0.iter().find(|(key, _)| key == id).map(|(_, pid)| pid)
    }

    pub(crate) fn contains_key(&self, id: &u64) -> bool {
        self.0.iter().any(|(key, _)| key == id)
    }

    pub(crate) fn values(&self) -> impl Iterator<Item = &u64> {
        self.0.iter().map(|(_, pid)| pid)
    }

    pub(crate) fn clear(&mut self) {
        self.0 = Vec::new();
    }
}

/// Busy-port message queue limits of `erl_drv_busy_msgq_limits`.
#[derive(Clone, Copy)]
pub(crate) struct MsgqLimits {
    pub(crate) low: usize,
    pub(crate) high: usize,
    pub(crate) enabled: bool,
}

/// Defaults of `open_port` option `{busy_limits_msgq, ...}` (erl_port_task.c).
pub(crate) const MSGQ_LIMITS_DEFAULT: MsgqLimits = MsgqLimits {
    low: 4096,
    high: 8192,
    enabled: true,
};

/// `ERL_DRV_BUSY_MSGQ_DISABLED`.
pub const BUSY_MSGQ_DISABLED: usize = usize::MAX;
const BUSY_MSGQ_READ_ONLY: usize = 0;

static NEXT_MONITOR: AtomicU64 = AtomicU64::new(1);

impl DriverPort {
    /// The port's I/O queue (`prt->ioq`).
    pub(crate) fn queue(&self) -> MutexGuard<'_, IoQueue> {
        self.queue.lock()
    }

    /// Bytes in the driver queue (`erts_ioq_size`), for `port_info(queue_size)`.
    pub fn queue_size(&self) -> usize {
        self.queue().size()
    }

    /// `prt->os_pid` as set by `erl_drv_set_os_pid`, `-1` when unset.
    pub fn os_pid(&self) -> i64 {
        self.os_pid.load(Ordering::Acquire)
    }

    /// Process-table data of the processes this port monitors, for `port_info`.
    pub fn monitored(&self) -> Vec<u64> {
        let mut pids: Vec<u64> = self.monitors.lock().values().copied().collect();
        pids.sort_unstable();
        pids
    }

    /// Port of io.c:5319 (get_port_flags).
    pub(crate) fn port_flags(&self) -> c_int {
        let state = self.state.load(Ordering::Acquire);
        let mut flags = 0;
        if state & SFLG_BINARY_IO != 0 {
            flags |= layout::PORT_FLAG_BINARY as c_int;
        }
        if state & SFLG_LINEBUF_IO != 0 {
            flags |= layout::PORT_FLAG_LINE as c_int;
        }
        flags
    }

    /// Port of io.c:3496/6333 (deliver_vec_message, driver_output_binary): deliver
    /// the segments as one message; `0` when the port is closing.
    pub(crate) fn output_vec(&self, header: &[u8], segments: &[Vec<u8>]) -> c_int {
        let state = self.state.load(Ordering::Acquire);
        if state & SFLG_TERMINATING != 0 {
            return 0;
        }
        self.host
            .deliver_vec(self, header, segments, state & SFLG_BINARY_IO != 0);
        0
    }

    /// The pid word of the connected process (`driver_connected`).
    pub(crate) fn connected_word(&self) -> usize {
        termspec::mk_pid(self.host.connected(self))
    }

    /// The pid word of the caller (`driver_caller`), NIL outside a callback.
    pub(crate) fn caller_word(&self) -> usize {
        match self.caller_data() {
            Some(data) => termspec::mk_pid(data),
            None => termspec::NIL,
        }
    }

    /// Port of io.c:6265/6301 (driver_output_term, driver_send_term): `-1`
    /// for an invalid specification, `0` when the receiver is gone.
    pub(crate) fn send_spec(&self, to: Option<usize>, spec: &[usize]) -> c_int {
        let Some(term) = termspec::decode(spec) else {
            return -1;
        };
        self.deliver(to, &term)
    }

    /// Port of io.c:6044-6077 (deliver_term_check_port): a send is traced only from a
    /// thread that runs a callback of the port with the port locked, never from a
    /// driver thread.
    fn trace_deliver(&self) -> bool {
        self.caller_data().is_some()
            && self
                .lock
                .as_deref()
                .or(self.driver.lock.as_ref())
                .is_some_and(lock::ReentrantLock::held_here)
    }

    /// Hand a built term to the host: to `to` (a pid word) or the connected process.
    pub(crate) fn deliver(&self, to: Option<usize>, term: &OwnedTerm) -> c_int {
        let target = match to {
            Some(word) => match termspec::pid_data(word) {
                Some(data) => Some(data),
                None => return 0,
            },
            None => None,
        };
        c_int::from(
            self.host
                .deliver_term(self, target, term, self.trace_deliver()),
        )
    }

    /// Port of io.c:7006 (do_driver_monitor_process): `-1` without a
    /// `process_exit` callback, `1` when the process does not exist (or is not
    /// a pid), else `0` with the monitor in `monitor`.
    pub(crate) fn monitor_process(&self, process: usize, monitor: &mut ErlDrvMonitor) -> c_int {
        if self.driver.callbacks.process_exit.is_none() && self.driver.native.is_none() {
            return -1;
        }
        // erts_proc_sig_send_monitor fails for anything but an existing process.
        let Some(pid) = termspec::pid_data(process) else {
            return 1;
        };
        let id = NEXT_MONITOR.fetch_add(1, Ordering::Relaxed);
        // Registered first so an exit racing with the call finds the monitor.
        self.monitors.lock().insert(id, pid);
        if !self.host.monitor_process(self, pid, id) {
            self.monitors.lock().remove(&id);
            return 1;
        }
        *monitor = ErlDrvMonitor::new(id);
        0
    }

    /// Port of io.c:7059 (do_driver_demonitor_process): `1` for an unknown monitor.
    pub(crate) fn demonitor_process(&self, monitor: &ErlDrvMonitor) -> c_int {
        if self.monitors.lock().remove(&monitor.id()).is_none() {
            return 1;
        }
        self.host.demonitor_process(self, monitor.id());
        0
    }

    /// Port of io.c:7098 (do_driver_get_monitored_process): the pid word or NIL.
    pub(crate) fn monitored_word(&self, monitor: &ErlDrvMonitor) -> usize {
        match self.monitors.lock().get(&monitor.id()) {
            Some(pid) => termspec::mk_pid(*pid),
            None => termspec::NIL,
        }
    }

    /// Port of io.c:7143 (erts_fire_port_monitor): the process behind
    /// `monitor` exited. The VM calls this on the port's behalf; the
    /// `process_exit` callback runs once and the monitor is dropped after it.
    pub fn process_exit(&self, monitor: u64) {
        let _guard = self.guard();
        if let Some(native) = &self.driver.native {
            if self.monitors.lock().contains_key(&monitor) && self.live() {
                native.process_exit(self, monitor);
                self.monitors.lock().remove(&monitor);
            }
            return;
        }
        let Some(callback) = self.driver.callbacks.process_exit else {
            return;
        };
        if !self.monitors.lock().contains_key(&monitor) || !self.live() {
            return;
        }
        let mut drv_monitor = ErlDrvMonitor::new(monitor);
        callback(self.data(), &mut drv_monitor);
        self.monitors.lock().remove(&monitor);
    }

    /// Port of erl_port_task.c:772 (erl_drv_busy_msgq_limits). `low` and `high`
    /// are read-write: zero reads, other values write, `BUSY_MSGQ_DISABLED`
    /// disables the feature; the current limits come back in both.
    pub(crate) fn busy_msgq_limits(&self, low: Option<&mut usize>, high: Option<&mut usize>) {
        let mut limits = self.msgq_limits.lock();
        let mut new_low = low.as_deref().copied().unwrap_or(BUSY_MSGQ_READ_ONLY);
        let mut new_high = high.as_deref().copied().unwrap_or(BUSY_MSGQ_READ_ONLY);
        let written = limits.enabled
            && new_low != BUSY_MSGQ_DISABLED
            && new_high != BUSY_MSGQ_DISABLED
            && (new_low != BUSY_MSGQ_READ_ONLY || new_high != BUSY_MSGQ_READ_ONLY);
        let disabled =
            limits.enabled && (new_low == BUSY_MSGQ_DISABLED || new_high == BUSY_MSGQ_DISABLED);
        if !limits.enabled {
            (new_low, new_high) = (BUSY_MSGQ_DISABLED, BUSY_MSGQ_DISABLED);
        } else if new_low == BUSY_MSGQ_DISABLED || new_high == BUSY_MSGQ_DISABLED {
            // The inputs are reported back unchanged.
            limits.enabled = false;
        } else {
            if new_low == BUSY_MSGQ_READ_ONLY {
                new_low = limits.low;
            } else {
                if limits.high < new_low {
                    limits.high = new_low;
                }
                limits.low = new_low;
            }
            if new_high == BUSY_MSGQ_READ_ONLY {
                new_high = limits.high;
            } else {
                if new_low > new_high {
                    new_low = new_high;
                    limits.low = new_low;
                }
                limits.high = new_high;
            }
        }
        let (cur_low, cur_high) = (limits.low, limits.high);
        drop(limits);
        if disabled {
            self.bpq_disabled();
        } else if written {
            self.bpq_limits_written(cur_low, cur_high);
        }
        if let Some(low) = low {
            *low = new_low;
        }
        if let Some(high) = high {
            *high = new_high;
        }
    }

    /// Set the message queue limits from the `{busy_limits_msgq, ...}` option
    /// of `open_port` (io.c:683).
    pub fn set_msgq_limits(&self, mut low: usize, mut high: usize) {
        self.busy_msgq_limits(Some(&mut low), Some(&mut high));
    }

    /// Whether the VM must reply to the opening process after `start`
    /// (`ERL_DRV_FLAG_USE_INIT_ACK`, erl_bif_port.c:102): the VM calls this once
    /// the port is registered.
    pub fn expect_init_ack(&self) {
        self.async_open.store(true, Ordering::Release);
    }

    /// Port of io.c:2927 (erl_drv_init_ack): answer the pending `open_port`;
    /// a failure also ends the port with reason `normal`.
    pub(crate) fn init_ack(&self, start_result: isize) {
        if !self.async_open.swap(false, Ordering::AcqRel) {
            return;
        }
        let ack = match start_result {
            -1 => InitAck::Failed(StartError::General),
            -2 => InitAck::Failed(StartError::Errno(
                std::io::Error::last_os_error().raw_os_error().unwrap_or(0),
            )),
            -3 => InitAck::Failed(StartError::Badarg),
            _ => InitAck::Opened,
        };
        self.host.init_ack(self, ack);
        // erts ends the port before it records the start result as driver data,
        // so `stop` of a failed start still sees what `start` returned.
        if ack != InitAck::Opened {
            self.failure(ExitReason::Normal, false);
        }
        self.drv_data
            .store(start_result as usize, Ordering::Release);
    }

    /// Port of io.c:781 (driver_create_port) after the VM made the port.
    pub(crate) fn create_port(
        &self,
        owner: u64,
        name: &str,
        drv_data: usize,
    ) -> Option<std::sync::Arc<DriverPort>> {
        self.host.create_port(self, owner, name, drv_data)
    }

    /// Mark a port made by `driver_create_port` as started with `drv_data`
    /// (no `start` callback runs for it).
    pub fn adopt(&self, drv_data: usize) {
        self.state.fetch_or(SFLG_STARTED, Ordering::AcqRel);
        self.drv_data.store(drv_data, Ordering::Release);
    }

    /// Release the queue and the port data lock when the port goes away
    /// (io.c:489 port free, stopq).
    pub(crate) fn release_resources(&self) {
        self.queue().clear();
        let pdl = self.pdl.swap(0, Ordering::AcqRel) as *mut threads::PortDataLock;
        if !pdl.is_null() {
            // Port of io.c:507-514: lock, unlock, then drop the port's reference.
            threads::pdl_lock(pdl);
            threads::pdl_unlock(pdl);
            threads::pdl_dec(pdl);
        }
        self.monitors.lock().clear();
    }
}
