//! Port timers: `driver_set_timer`, `driver_cancel_timer`, `driver_read_timer`.
//!
//! Port of erts/emulator/beam/erl_hl_timer.c:3031 (erts_set_port_timer,
//! erts_cancel_port_timer, erts_read_port_timer) and :669 (get_timeout_pos,
//! get_time_left), with the timeout task of erl_port_task.c:1760, OTP-29.1.1. Time
//! is counted in 1 ms clock ticks like erts; one service thread expires timers and
//! queues a timeout port task that a scheduler executes.

use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Condvar, Mutex, OnceLock, Weak};
use std::thread;
use std::time::{Duration, Instant};

use crate::task::call1;
use crate::{DriverPort, REDS_TIMEOUT};

/// `c_p->common.timer` of a port (`ERTS_PTMR_NONE`, a timer, `ERTS_PTMR_TIMEDOUT`).
#[derive(Clone, Copy, Default)]
pub(crate) enum PortTimer {
    #[default]
    None,
    /// Armed for tick `pos` since the service origin.
    Armed { epoch: u64, pos: i128 },
    /// Expired; the timeout task is queued.
    TimedOut { epoch: u64 },
}

fn origin() -> Instant {
    static ORIGIN: OnceLock<Instant> = OnceLock::new();
    *ORIGIN.get_or_init(Instant::now)
}

fn now_ns() -> i128 {
    i128::try_from(origin().elapsed().as_nanos()).unwrap_or(i128::MAX)
}

/// `ERTS_MONOTONIC_TO_CLKTCKS(ns - 1)` with 1 ms ticks.
fn ticks_before(ns: i128) -> i128 {
    (ns - 1).div_euclid(1_000_000)
}

struct Entry {
    at: Instant,
    port: Weak<DriverPort>,
    epoch: u64,
}

impl PartialEq for Entry {
    fn eq(&self, other: &Self) -> bool {
        self.at == other.at && self.epoch == other.epoch
    }
}
impl Eq for Entry {}
impl PartialOrd for Entry {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for Entry {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.at.cmp(&other.at).then(self.epoch.cmp(&other.epoch))
    }
}

struct Service {
    heap: Mutex<BinaryHeap<Reverse<Entry>>>,
    wake: Condvar,
}

fn service() -> &'static Service {
    static SERVICE: OnceLock<&'static Service> = OnceLock::new();
    SERVICE.get_or_init(|| {
        let service: &'static Service = Box::leak(Box::new(Service {
            heap: Mutex::new(BinaryHeap::new()),
            wake: Condvar::new(),
        }));
        thread::Builder::new()
            .name("arinsal-drv-timers".into())
            .spawn(move || serve(service))
            .expect("start driver timer service");
        service
    })
}

fn serve(service: &Service) {
    let mut heap = service.heap.lock().unwrap();
    loop {
        let now = Instant::now();
        match heap.peek() {
            None => heap = service.wake.wait(heap).unwrap(),
            Some(Reverse(entry)) if entry.at > now => {
                let wait = entry.at - now;
                heap = service.wake.wait_timeout(heap, wait).unwrap().0;
            }
            Some(_) => {
                let Reverse(entry) = heap.pop().expect("peeked entry");
                drop(heap);
                if let Some(port) = entry.port.upgrade() {
                    port.timer_expired(entry.epoch);
                }
                heap = service.heap.lock().unwrap();
            }
        }
    }
}

impl DriverPort {
    /// Port of erl_hl_timer.c:3031 (erts_set_port_timer). `tmo` in ms.
    pub(crate) fn set_timer(self: &Arc<Self>, tmo: i64) {
        let mut timer = self.timer.lock().unwrap();
        let epoch = self.timer_epoch.fetch_add(1, Ordering::Relaxed) + 1;
        if tmo == 0 {
            *timer = PortTimer::TimedOut { epoch };
            drop(timer);
            self.schedule_timeout(epoch);
            return;
        }
        // get_timeout_pos: one tick beyond the requested time.
        let pos = if tmo < 0 {
            now_ns().div_euclid(1_000_000)
        } else {
            ticks_before(now_ns()) + i128::from(tmo) + 1
        };
        *timer = PortTimer::Armed { epoch, pos };
        let millis = u64::try_from(pos).unwrap_or(u64::MAX).min(1 << 50);
        let at = origin() + Duration::from_millis(millis);
        let service = service();
        service.heap.lock().unwrap().push(Reverse(Entry {
            at,
            port: Arc::downgrade(self),
            epoch,
        }));
        service.wake.notify_one();
    }

    /// Port of erl_hl_timer.c:3063 (erts_cancel_port_timer): an expired timer whose task
    /// is still queued is aborted too.
    pub(crate) fn cancel_timer(&self) {
        *self.timer.lock().unwrap() = PortTimer::None;
    }

    /// Port of erl_hl_timer.c:3082 (erts_read_port_timer) and io.c:6930
    /// (driver_read_timer): ms left, 0 without a timer.
    pub(crate) fn read_timer(&self) -> i64 {
        match *self.timer.lock().unwrap() {
            PortTimer::None | PortTimer::TimedOut { .. } => 0,
            PortTimer::Armed { pos, .. } => {
                // get_time_left
                let now = ticks_before(now_ns()) + 1;
                i64::try_from((pos - now).max(0)).unwrap_or(i64::MAX)
            }
        }
    }

    /// The timer service saw timer `epoch` expire (`port_timeout_callback`).
    fn timer_expired(self: &Arc<Self>, epoch: u64) {
        let mut timer = self.timer.lock().unwrap();
        if matches!(*timer, PortTimer::Armed { epoch: g, .. } if g == epoch) {
            *timer = PortTimer::TimedOut { epoch };
            drop(timer);
            self.schedule_timeout(epoch);
        }
    }

    /// Port of erl_port_task.c:1760 (ERTS_PORT_TASK_TIMEOUT) with the default callback of
    /// io.c:7535 (no_timeout_callback), run by the executing scheduler with the port locked.
    /// Returns the reductions of the task.
    pub(crate) fn run_timeout_task(&self, epoch: u64) -> i32 {
        {
            let mut timer = self.timer.lock().unwrap();
            if !matches!(*timer, PortTimer::TimedOut { epoch: g } if g == epoch) {
                return 0; // cancelled or replaced while queued
            }
            *timer = PortTimer::None;
        }
        if !self.live() {
            return REDS_TIMEOUT;
        }
        if let Some(callback) = self.driver.callbacks.timeout {
            self.host.trace_timeout(self);
            call1(callback, self.data());
        }
        REDS_TIMEOUT
    }
}
