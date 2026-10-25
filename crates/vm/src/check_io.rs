//! Shared descriptor readiness service.
//!
//! The descriptor-indexed state and one-shot scheduling follow
//! `erts/emulator/sys/common/erl_check_io.c` (OTP-29.1.1). `erl_poll` owns only
//! the mio syscall adapter; registrations are changed by their caller thread.

use crate::erl_poll::{
    ERTS_POLL_EV_ERR, ERTS_POLL_EV_IN, ERTS_POLL_EV_NONE, ERTS_POLL_EV_NVAL, ERTS_POLL_EV_OUT,
    ErtsPollEvent, ErtsPollOp, ErtsPollSet, PollSetKind, erts_poll_control, erts_poll_init,
    erts_poll_interrupt, erts_poll_max_fds, erts_poll_wait,
};
use std::io;
use std::os::fd::RawFd;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock, RwLock};
use std::thread;
use std::time::{Duration, Instant};

const EVENT_CAPACITY: usize = 512;
const FD_TABLE_MIN_LENGTH: usize = 1024;
const FD_TABLE_EXP_THRESHOLD: usize = 2048 * 1024;

#[derive(Clone, Copy)]
enum PollState {
    CheckIo,
    Sleep,
}

struct PollMsacc {
    enabled: bool,
    state: PollState,
    started: Instant,
    check_io_ns: u64,
    sleep_ns: u64,
    window_ns: u64,
}

impl PollMsacc {
    fn update(&mut self, now: Instant) {
        if self.enabled {
            let elapsed = u64::try_from(now.saturating_duration_since(self.started).as_nanos())
                .unwrap_or(u64::MAX);
            let counter = match self.state {
                PollState::CheckIo => &mut self.check_io_ns,
                PollState::Sleep => &mut self.sleep_ns,
            };
            *counter = counter.saturating_add(elapsed);
            self.window_ns = self.window_ns.saturating_add(elapsed);
        }
        self.started = now;
    }
}

static POLL_MSACC: OnceLock<Mutex<PollMsacc>> = OnceLock::new();

fn poll_msacc() -> &'static Mutex<PollMsacc> {
    POLL_MSACC.get_or_init(|| {
        Mutex::new(PollMsacc {
            enabled: false,
            state: PollState::Sleep,
            started: Instant::now(),
            check_io_ns: 0,
            sleep_ns: 0,
            window_ns: 0,
        })
    })
}

/// Enable or disable accounting for the dedicated poll thread.
// Port of erts/emulator/sys/common/erl_poll.c (erts_poll_wait), OTP-29.1.1.
pub(crate) fn set_msacc_enabled(enabled: bool) {
    let _ = poller();
    let mut msacc = poll_msacc().lock().expect("poll microstate");
    let now = Instant::now();
    msacc.update(now);
    msacc.enabled = enabled;
    msacc.started = now;
}

/// Snapshot the poll thread's check-I/O, sleep and accounted-time counters in nanoseconds.
// Port of erts/emulator/sys/common/erl_check_io.c (erts_check_io), OTP-29.1.1.
pub(crate) fn msacc_snapshot() -> [u64; 3] {
    let mut msacc = poll_msacc().lock().expect("poll microstate");
    msacc.update(Instant::now());
    [msacc.check_io_ns, msacc.sleep_ns, msacc.window_ns]
}

fn set_poll_state(state: PollState) {
    let mut msacc = poll_msacc().lock().expect("poll microstate");
    let now = Instant::now();
    msacc.update(now);
    msacc.state = state;
    msacc.started = now;
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct Ready {
    pub readable: bool,
    pub writable: bool,
    pub closed: bool,
    pub error: bool,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct InterestSet {
    pub readable: bool,
    pub writable: bool,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum RegistrationKind {
    Driver,
    Nif,
    Internal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Registration {
    fd: RawFd,
    id: usize,
}

type OneShotCallback = Box<dyn FnOnce(RawFd, Ready) + Send>;

struct Watch {
    id: usize,
    interests: InterestSet,
    kind: RegistrationKind,
    callback: Option<OneShotCallback>,
}

#[derive(Default)]
struct FdState {
    watches: Vec<Watch>,
    /// What the poll thread's set holds for this descriptor.
    main: SetState,
    /// What the scheduler pollset holds (the read interest once `scheduler` is set).
    sched: SetState,
    /// `ERTS_EV_FLAG_SCHEDULER`: the read interest has moved to the scheduler pollset.
    scheduler: bool,
    /// The descriptor lives in the `select(2)` fallback set (`ERTS_EV_FLAG_FALLBACK`).
    fallback: bool,
    /// `ErtsDrvEventState.count`: read interests registered, to decide the migration.
    count: u32,
}

#[derive(Default)]
struct SetState {
    events: InterestSet,
    registered: bool,
}

/// Port of erts/emulator/sys/common/erl_check_io.c (erts_io_notify_port_task_executed):
/// a read descriptor re-enabled more than this many times moves to the scheduler pollset.
const SCHEDULER_MIGRATION_COUNT: u32 = 10;

struct FdStateTable {
    slots: RwLock<Vec<parking_lot::Mutex<FdState>>>,
    max_fds: usize,
}

impl Default for FdStateTable {
    fn default() -> Self {
        Self {
            slots: RwLock::new(Vec::new()),
            max_fds: erts_poll_max_fds(),
        }
    }
}

impl FdStateTable {
    fn ensure_fd(&self, fd: RawFd) -> io::Result<usize> {
        let index = usize::try_from(fd)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "negative descriptor"))?;
        if index >= self.max_fds {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "descriptor exceeds the ERTS poll limit",
            ));
        }
        {
            let slots = self.slots.read().unwrap();
            if index < slots.len() {
                return Ok(index);
            }
        }
        let mut slots = self.slots.write().unwrap();
        if index >= slots.len() {
            let need_len = index + 1;
            let mut new_len = if need_len < FD_TABLE_MIN_LENGTH {
                FD_TABLE_MIN_LENGTH
            } else {
                slots.len().max(FD_TABLE_MIN_LENGTH)
            };
            while new_len < need_len {
                new_len = if new_len < FD_TABLE_EXP_THRESHOLD {
                    new_len.saturating_mul(2)
                } else {
                    new_len.saturating_add(FD_TABLE_EXP_THRESHOLD)
                };
            }
            slots.resize_with(new_len.min(self.max_fds), || {
                parking_lot::Mutex::new(FdState::default())
            });
        }
        Ok(index)
    }

    fn lock_slots(
        &self,
        fd: RawFd,
    ) -> io::Result<(
        usize,
        std::sync::RwLockReadGuard<'_, Vec<parking_lot::Mutex<FdState>>>,
    )> {
        let index = self.ensure_fd(fd)?;
        let slots = self.slots.read().unwrap();
        Ok((index, slots))
    }
}

struct Poller {
    next_registration: AtomicUsize,
    states: Arc<FdStateTable>,
}

static POLLER: OnceLock<Poller> = OnceLock::new();

/// A fallback-set descriptor became ready (erl_poll.c `erts_poll_wait__fallback` results go
/// through the same `erts_check_io` event handling).
fn fallback_event(fd: RawFd, events: u32) {
    if let Some(poller) = POLLER.get() {
        let event = ErtsPollEvent {
            fd: Some(fd),
            events,
            closed: false,
            error: false,
        };
        check_event(&poller.states, fd, event, PollSetKind::Main);
    }
}

fn poller() -> &'static Poller {
    POLLER.get_or_init(|| {
        let poll = erts_poll_init(PollSetKind::Main).expect("create shared ERTS poll set");

        crate::erl_poll::erts_poll_fallback_sink(fallback_event);
        let states = Arc::new(FdStateTable::default());
        let worker_states = Arc::clone(&states);
        thread::Builder::new()
            .name("arinsal-check-io".into())
            .spawn(move || poll_loop(poll, worker_states))
            .expect("start shared ERTS poll thread");
        Poller {
            next_registration: AtomicUsize::new(1),
            states,
        }
    })
}

/// `+IOs`: schedulers poll the descriptors that are re-enabled often (the default).
// Port of erts/emulator/sys/common/erl_check_io.c (erts_sched_poll_enabled), OTP-29.1.1.
pub(crate) fn sched_poll_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| {
        arinsal_args::active_emulator_flags()
            .scheduler_polling
            .unwrap_or(true)
    })
}

/// The scheduler pollset; only the scheduler that owns `doing_sys_schedule` waits on it.
static SCHED_POLLSET: OnceLock<Mutex<ErtsPollSet>> = OnceLock::new();

/// Install the scheduler pollset with the scheduler loop. The poll thread is started with the
/// first selection; the scheduler pollset is created with it.
pub(crate) fn install_scheduler_polling() {
    if sched_poll_enabled() {
        let _ = poller();
        static CREATE: std::sync::Once = std::sync::Once::new();
        CREATE.call_once(|| {
            let sched = erts_poll_init(PollSetKind::Scheduler).expect("create scheduler poll set");
            let _ = SCHED_POLLSET.set(Mutex::new(sched));
        });
        arinsal_sched::set_sched_poll(Arc::new(SchedPollHook));
    }
}

struct SchedPollHook;

impl arinsal_sched::SchedPoll for SchedPollHook {
    fn enabled(&self) -> bool {
        SCHED_POLLSET.get().is_some()
    }

    // Port of erts/emulator/sys/common/erl_check_io.c (erts_check_io on the scheduler pollset),
    // OTP-29.1.1.
    fn poll(&self, timeout: Option<Duration>) {
        let (Some(set), Some(poller)) = (SCHED_POLLSET.get(), POLLER.get()) else {
            return;
        };
        let mut events = Vec::with_capacity(EVENT_CAPACITY);
        {
            let mut poll = set.lock().unwrap();
            if erts_poll_wait(&mut poll, timeout, &mut events).is_err() {
                return;
            }
        }
        for event in events.drain(..) {
            if let Some(fd) = event.fd {
                check_event(&poller.states, fd, event, PollSetKind::Scheduler);
            }
        }
    }

    fn interrupt(&self) {
        let _ = erts_poll_interrupt(PollSetKind::Scheduler);
    }

    fn have_outstanding_io(&self) -> bool {
        arinsal_drv::port_task::have_outstanding_io_tasks()
    }
}

#[cfg(test)]
/// Wait on a set of descriptors through the shared one-shot poll set.
pub(crate) fn wait_any(fds: &[(RawFd, InterestSet)]) -> io::Result<Option<(RawFd, Ready)>> {
    wait_any_timeout(fds, None)
}

/// Wait with an optional deadline; timeout removes all registrations.
pub(crate) fn wait_any_timeout(
    fds: &[(RawFd, InterestSet)],
    timeout: Option<Duration>,
) -> io::Result<Option<(RawFd, Ready)>> {
    wait_any_timeout_kind(fds, timeout, RegistrationKind::Driver, None, None)
}

/// Like [`wait_any_timeout`], returning [`WAKE_FD`] when `waker` is woken.
pub(crate) fn wait_any_timeout_wake(
    fds: &[(RawFd, InterestSet)],
    timeout: Option<Duration>,
    waker: &Waker,
) -> io::Result<Option<(RawFd, Ready)>> {
    wait_any_timeout_kind(fds, timeout, RegistrationKind::Driver, None, Some(waker))
}

/// Wait for a NIF selection while sharing the single ERTS poll thread.
pub(crate) fn wait_any_nif_timeout_wake(
    fds: &[(RawFd, InterestSet)],
    timeout: Option<Duration>,
    wake: RawFd,
) -> io::Result<Option<(RawFd, Ready)>> {
    wait_any_timeout_kind(fds, timeout, RegistrationKind::Nif, Some(wake), None)
}

struct WaitResult {
    value: Mutex<Option<(RawFd, Ready)>>,
    changed: Condvar,
}

/// The `fd` a wake-up reports.
pub(crate) const WAKE_FD: RawFd = -1;

/// Wakes the one thread blocked in [`wait_any_timeout_wake`] on it, or the next wait.
///
/// The wake-up of a port's worker thread, in place of a pipe per port: erts wakes the
/// scheduler running a port task (`erts_port_task_schedule`), not a thread per port, and a
/// spawn port holds only its two pipe ends (sys_drivers.c `spawn_start`).
#[derive(Default)]
pub(crate) struct Waker {
    state: Mutex<WakerState>,
}

#[derive(Default)]
struct WakerState {
    pending: bool,
    waiter: Option<Arc<WaitResult>>,
}

impl Waker {
    /// Wake the waiter; with none waiting, the next wait returns at once.
    pub(crate) fn wake(&self) {
        let mut state = self.state.lock().unwrap();
        match state.waiter.as_ref() {
            Some(waiter) => {
                let mut value = waiter.value.lock().unwrap();
                if value.is_none() {
                    *value = Some((
                        WAKE_FD,
                        Ready {
                            readable: true,
                            writable: false,
                            closed: false,
                            error: false,
                        },
                    ));
                    waiter.changed.notify_one();
                }
            }
            None => state.pending = true,
        }
    }
}

fn wait_any_timeout_kind(
    fds: &[(RawFd, InterestSet)],
    timeout: Option<Duration>,
    kind: RegistrationKind,
    wake: Option<RawFd>,
    waker: Option<&Waker>,
) -> io::Result<Option<(RawFd, Ready)>> {
    if fds.is_empty() && waker.is_none() {
        return Ok(None);
    }
    let result = Arc::new(WaitResult {
        value: Mutex::new(None),
        changed: Condvar::new(),
    });
    if let Some(waker) = waker {
        let mut state = waker.state.lock().unwrap();
        if std::mem::take(&mut state.pending) {
            return Ok(Some((
                WAKE_FD,
                Ready {
                    readable: true,
                    writable: false,
                    closed: false,
                    error: false,
                },
            )));
        }
        state.waiter = Some(Arc::clone(&result));
    }
    let mut registrations = Vec::with_capacity(fds.len());
    for (fd, interests) in fds {
        let result_slot = Arc::clone(&result);
        let watch_kind = if Some(*fd) == wake {
            RegistrationKind::Internal
        } else {
            kind
        };
        match register_kind(*fd, *interests, watch_kind, move |ready_fd, ready| {
            let mut value = result_slot.value.lock().unwrap();
            if value.is_none() {
                *value = Some((ready_fd, ready));
                result_slot.changed.notify_one();
            }
        }) {
            Ok(registration) => registrations.push(registration),
            Err(error) => {
                for registration in registrations {
                    deregister(registration);
                }
                if let Some(waker) = waker {
                    waker.state.lock().unwrap().waiter = None;
                }
                return Err(error);
            }
        }
    }

    let mut value = result.value.lock().unwrap();
    let result_value = match timeout {
        Some(timeout) => {
            let deadline = Instant::now() + timeout;
            while value.is_none() {
                let now = Instant::now();
                if now >= deadline {
                    break;
                }
                let (next, wait) = result.changed.wait_timeout(value, deadline - now).unwrap();
                value = next;
                if wait.timed_out() && value.is_none() {
                    break;
                }
            }
            value
                .take()
                .map(Some)
                .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "poll timeout"))
        }
        None => {
            while value.is_none() {
                value = result.changed.wait(value).unwrap();
            }
            Ok(value.take())
        }
    };
    drop(value);
    if let Some(waker) = waker {
        waker.state.lock().unwrap().waiter = None;
    }
    for registration in registrations {
        deregister(registration);
    }
    result_value
}

/// Add an asynchronous one-shot selection to the shared poll set.
pub(crate) fn register(
    fd: RawFd,
    interests: InterestSet,
    ready: impl FnOnce(RawFd, Ready) + Send + 'static,
) -> io::Result<Registration> {
    register_kind(fd, interests, RegistrationKind::Nif, ready)
}

/// Add an asynchronous one-shot driver event to the shared poll set.
pub(crate) fn register_driver(
    fd: RawFd,
    interests: InterestSet,
    ready: impl FnOnce(RawFd, Ready) + Send + 'static,
) -> io::Result<Registration> {
    register_kind(fd, interests, RegistrationKind::Driver, ready)
}

fn register_kind(
    fd: RawFd,
    interests: InterestSet,
    kind: RegistrationKind,
    ready: impl FnOnce(RawFd, Ready) + Send + 'static,
) -> io::Result<Registration> {
    if !interests.readable && !interests.writable {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "empty poll interest",
        ));
    }
    let poller = poller();
    let id = poller.next_registration.fetch_add(1, Ordering::Relaxed);
    let registration = Registration { fd, id };
    let (index, slots) = poller.states.lock_slots(fd)?;
    let mut state = slots[index].lock();
    // Port of erts/emulator/sys/common/erl_poll.c (concurrent_update_pollset: ADD of fds 0-2
    // returns NVAL, so they live in the fallback set), OTP-29.1.1. A descriptor the owner
    // marked (a regular file, always ready under `select`) goes there as well.
    if fd <= 2 || fallback_marked(fd) {
        state.fallback = true;
    }
    // A descriptor has one watch most of the time; Vec's first growth step is four.
    if state.watches.capacity() == 0 {
        state.watches.reserve_exact(1);
    }
    state.watches.push(Watch {
        id,
        interests,
        kind,
        callback: Some(Box::new(ready)),
    });
    // Port of erl_check_io.c (erts_io_notify_port_task_executed): the read descriptor of a
    // driver that was re-enabled often moves to the scheduler pollset.
    if matches!(kind, RegistrationKind::Driver)
        && interests.readable
        && !state.scheduler
        && !state.fallback
        && SCHED_POLLSET.get().is_some()
        && state.count > SCHEDULER_MIGRATION_COUNT
    {
        state.scheduler = true;
    }
    let mut result = sync_pollset(fd, &mut state);
    if result.is_err() && !state.fallback {
        // Port of erl_poll.c (a kernel poller `ERTS_POLL_EV_NVAL` moves the descriptor to the
        // fallback set), OTP-29.1.1.
        state.fallback = true;
        state.main = SetState::default();
        result = sync_pollset(fd, &mut state);
    }
    match result {
        Ok(()) => Ok(registration),
        Err(error) => {
            state.watches.retain(|watch| watch.id != id);
            Err(error)
        }
    }
}

/// Remove a pending one-shot selection.
pub(crate) fn deregister(registration: Registration) {
    let poller = poller();
    let Ok((index, slots)) = poller.states.lock_slots(registration.fd) else {
        return;
    };
    let mut state = slots[index].lock();
    state.watches.retain(|watch| watch.id != registration.id);
    let _ = sync_pollset(registration.fd, &mut state);
}

/// Clear the pollset state for a descriptor whose owning driver is stopping.
///
/// Port of erl_check_io.c (`deselect`), OTP-29.1.1.
pub(crate) fn deselect_fd(fd: RawFd) {
    let poller = poller();
    let Ok((index, slots)) = poller.states.lock_slots(fd) else {
        return;
    };
    let mut state = slots[index].lock();
    state.watches.clear();
    if sync_pollset(fd, &mut state).is_err() {
        let _ = erts_poll_control(PollSetKind::Main, fd, ErtsPollOp::Del, ERTS_POLL_EV_NONE);
        let _ = erts_poll_control(
            PollSetKind::Scheduler,
            fd,
            ErtsPollOp::Del,
            ERTS_POLL_EV_NONE,
        );
    }
    state.main = SetState::default();
    state.sched = SetState::default();
    state.scheduler = false;
    state.fallback = false;
    state.count = 0;
}

fn poll_loop(mut poll: ErtsPollSet, states: Arc<FdStateTable>) {
    // Port of erts/emulator/sys/common/erl_check_io.c (erts_check_io), OTP-29.1.1.
    let mut events = Vec::with_capacity(EVENT_CAPACITY);
    loop {
        set_poll_state(PollState::Sleep);
        if let Err(error) = erts_poll_wait(&mut poll, None, &mut events) {
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            thread::sleep(Duration::from_millis(2));
            continue;
        }
        set_poll_state(PollState::CheckIo);
        for event in events.drain(..) {
            if let Some(fd) = event.fd {
                check_event(&states, fd, event, PollSetKind::Main);
            }
        }
    }
}

fn check_event(states: &FdStateTable, fd: RawFd, event: ErtsPollEvent, from: PollSetKind) {
    let Ok((index, slots)) = states.lock_slots(fd) else {
        return;
    };
    let mut state = slots[index].lock();
    let mut seen = InterestSet {
        readable: event.events & ERTS_POLL_EV_IN != 0,
        writable: event.events & ERTS_POLL_EV_OUT != 0,
    };
    if from == PollSetKind::Main && state.scheduler {
        // Port of erl_check_io.c (erts_check_io): "We are in a poll thread and the fd is
        // managed by a scheduler, we ignore the any IN events".
        seen.readable = false;
    }
    let poll_error = event.events & (ERTS_POLL_EV_ERR | ERTS_POLL_EV_NVAL) != 0;
    let mut callbacks = Vec::new();
    let mut triggered_driver_reads = 0u32;
    state.watches.retain_mut(|watch| {
        let fired = poll_error
            || (watch.interests.readable && seen.readable)
            || (watch.interests.writable && seen.writable);
        if fired {
            if let Some(callback) = watch.callback.take() {
                if watch.kind == RegistrationKind::Driver && watch.interests.readable {
                    triggered_driver_reads += 1;
                }
                callbacks.push((
                    callback,
                    Ready {
                        readable: watch.interests.readable && (seen.readable || poll_error),
                        writable: watch.interests.writable && (seen.writable || poll_error),
                        closed: event.closed,
                        error: event.error || poll_error,
                    },
                ));
            }
            false
        } else {
            true
        }
    });
    state.count = state.count.saturating_add(triggered_driver_reads);

    if sync_pollset(fd, &mut state).is_err() {
        // A failed re-arm is reported as NVAL by erts_check_io. Trigger every
        // remaining watch after removing the descriptor from the poll set.
        state.main = SetState::default();
        state.sched = SetState::default();
        let _ = erts_poll_control(PollSetKind::Main, fd, ErtsPollOp::Del, ERTS_POLL_EV_NONE);
        let _ = erts_poll_control(
            PollSetKind::Scheduler,
            fd,
            ErtsPollOp::Del,
            ERTS_POLL_EV_NONE,
        );
        callbacks.extend(state.watches.drain(..).filter_map(|mut watch| {
            watch.callback.take().map(|callback| {
                (
                    callback,
                    Ready {
                        readable: watch.interests.readable,
                        writable: watch.interests.writable,
                        closed: false,
                        error: true,
                    },
                )
            })
        }));
    }
    drop(state);
    for (callback, watch_ready) in callbacks {
        callback(fd, watch_ready);
    }
}

fn sync_pollset(fd: RawFd, state: &mut FdState) -> io::Result<()> {
    let next = watch_interests(&state.watches);
    let selected = !state.watches.is_empty();
    // Port of erts/emulator/sys/common/erl_check_io.c (erts_io_control_wakeup): a descriptor
    // that migrated keeps only its output interest in the poll thread's set; its read
    // interest lives in the scheduler pollset.
    let main_want = InterestSet {
        readable: next.readable && !state.scheduler,
        writable: next.writable,
    };
    let main_kind = if state.fallback {
        PollSetKind::Fallback
    } else {
        PollSetKind::Main
    };
    sync_set(main_kind, fd, main_want, selected, &mut state.main)?;
    if state.watches.is_empty() && !state.main.registered && fd > 2 && !fallback_marked(fd) {
        state.fallback = false;
    }
    if state.scheduler || state.sched.registered {
        let sched_want = InterestSet {
            readable: next.readable && state.scheduler,
            writable: false,
        };
        sync_set(
            PollSetKind::Scheduler,
            fd,
            sched_want,
            selected,
            &mut state.sched,
        )?;
    }
    Ok(())
}

fn sync_set(
    kind: PollSetKind,
    fd: RawFd,
    next: InterestSet,
    selected: bool,
    set: &mut SetState,
) -> io::Result<()> {
    if next == set.events {
        if !next.readable && !next.writable && set.registered && !selected {
            poll_control(kind, fd, ErtsPollOp::Del, ERTS_POLL_EV_NONE)?;
            set.registered = false;
        }
        return Ok(());
    }
    let flags = (if next.readable { ERTS_POLL_EV_IN } else { 0 })
        | (if next.writable { ERTS_POLL_EV_OUT } else { 0 });
    let op = if next.readable || next.writable {
        if set.registered {
            ErtsPollOp::Mod
        } else {
            ErtsPollOp::Add
        }
    } else if selected {
        ErtsPollOp::Mod
    } else if set.registered {
        ErtsPollOp::Del
    } else {
        set.events = next;
        return Ok(());
    };
    poll_control(kind, fd, op, flags)?;
    set.events = next;
    set.registered = op != ErtsPollOp::Del;
    Ok(())
}

fn watch_interests(watches: &[Watch]) -> InterestSet {
    watches
        .iter()
        .fold(InterestSet::default(), |events, watch| {
            union(events, watch.interests)
        })
}

fn poll_control(kind: PollSetKind, fd: RawFd, op: ErtsPollOp, events: u32) -> io::Result<()> {
    if erts_poll_control(kind, fd, op, events) & ERTS_POLL_EV_NVAL != 0 {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "ERTS poll control returned ERTS_POLL_EV_NVAL",
        ))
    } else {
        Ok(())
    }
}

fn union(left: InterestSet, right: InterestSet) -> InterestSet {
    InterestSet {
        readable: left.readable || right.readable,
        writable: left.writable || right.writable,
    }
}

pub(crate) struct DebugInfo {
    pub used_fds: usize,
    pub driver_selects: usize,
    pub nif_selects: usize,
}

/// Snapshot the active descriptors and selection counts exposed by check_io_debug.
pub(crate) fn debug_info() -> DebugInfo {
    let states = &poller().states;
    let slots = states.slots.read().unwrap();
    let mut info = DebugInfo {
        used_fds: 0,
        driver_selects: 0,
        nif_selects: 0,
    };
    for state in slots.iter() {
        let state = state.lock();
        // Port of erts/emulator/sys/common/erl_check_io.c (doit_erts_check_io_debug), OTP-29.1.1:
        // internal wake registrations do not contribute to the used-fd counter.
        if state
            .watches
            .iter()
            .any(|watch| !matches!(watch.kind, RegistrationKind::Internal))
        {
            info.used_fds += 1;
        }
        for watch in &state.watches {
            match watch.kind {
                RegistrationKind::Driver => info.driver_selects += 1,
                RegistrationKind::Nif => info.nif_selects += 1,
                RegistrationKind::Internal => {}
            }
        }
    }
    info
}

static FALLBACK_FDS: std::sync::LazyLock<RwLock<std::collections::HashSet<RawFd>>> =
    std::sync::LazyLock::new(|| RwLock::new(std::collections::HashSet::new()));

fn fallback_marked(fd: RawFd) -> bool {
    FALLBACK_FDS.read().unwrap().contains(&fd)
}

/// Put `fd` in the fallback set while `on`. The owner of a descriptor that `select` reports
/// ready but the kernel poller does not (a regular file) states it once at open, instead of
/// the poller classifying the descriptor on every selection.
pub(crate) fn mark_fallback(fd: RawFd, on: bool) {
    let mut marked = FALLBACK_FDS.write().unwrap();
    if on {
        marked.insert(fd);
    } else {
        marked.remove(&fd);
    }
}

/// Whether `fd` is a regular file, a block device or `/dev/null`: always ready for `select`.
pub(crate) fn is_always_ready(fd: RawFd) -> bool {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let Ok(metadata) = std::fs::metadata(format!("/dev/fd/{fd}")) else {
        return false;
    };
    let file_type = metadata.file_type();
    if file_type.is_file() || file_type.is_block_device() {
        return true;
    }
    file_type.is_char_device()
        && std::fs::metadata("/dev/null").is_ok_and(|null| null.rdev() == metadata.rdev())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::io::Write;
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;
    use std::sync::mpsc;

    /// Serializes tests that count the process-global poll set (`debug_info`).
    pub(crate) static TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn erl_poll_control_reports_invalid_fds_as_nval() {
        assert_ne!(
            erts_poll_control(PollSetKind::Main, -1, ErtsPollOp::Add, ERTS_POLL_EV_IN)
                & ERTS_POLL_EV_NVAL,
            0
        );
    }

    #[test]
    fn check_io_debug_excludes_internal_watches_from_used_fds() {
        let _guard = TEST_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let (reader, _writer) = UnixStream::pair().unwrap();
        let registration = register_kind(
            reader.as_raw_fd(),
            InterestSet {
                readable: true,
                writable: false,
            },
            RegistrationKind::Internal,
            |_, _| {},
        )
        .unwrap();
        similar_asserts::assert_eq!(debug_info().used_fds, 0);
        deregister(registration);
    }

    #[test]
    fn check_io_one_shot_rearms_after_delivery() {
        let _guard = TEST_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let (reader, mut writer) = UnixStream::pair().unwrap();
        writer.write_all(b"x").unwrap();
        let interest = InterestSet {
            readable: true,
            writable: false,
        };
        let (fd, ready) = wait_any(&[(reader.as_raw_fd(), interest)])
            .unwrap()
            .unwrap();
        assert_eq!(fd, reader.as_raw_fd());
        assert!(ready.readable);
        assert_eq!(debug_info().used_fds, 0);
        let (fd, ready) = wait_any(&[(reader.as_raw_fd(), interest)])
            .unwrap()
            .unwrap();
        assert_eq!(fd, reader.as_raw_fd());
        assert!(ready.readable);
    }

    #[test]
    fn regular_file_at_end_of_file_is_ready_in_the_fallback_set() {
        let _guard = TEST_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        // kqueue reports no read event for a regular file at end of file; select does.
        let path = std::env::temp_dir().join(format!("arinsal-fallback-{}", std::process::id()));
        std::fs::write(&path, b"x").unwrap();
        let mut file = std::fs::File::open(&path).unwrap();
        std::io::Read::read_to_end(&mut file, &mut Vec::new()).unwrap();
        let fd = file.as_raw_fd();
        assert!(is_always_ready(fd));
        mark_fallback(fd, true);
        let interest = InterestSet {
            readable: true,
            writable: false,
        };
        for _ in 0..2 {
            let ready = wait_any_timeout(&[(fd, interest)], Some(Duration::from_secs(5)))
                .unwrap()
                .expect("a regular file is ready");
            assert_eq!(ready.0, fd);
        }
        mark_fallback(fd, false);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn check_io_many_concurrent_sockets() {
        let _guard = TEST_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let mut pairs = (0..24)
            .map(|_| UnixStream::pair().unwrap())
            .collect::<Vec<_>>();
        for (_, writer) in &mut pairs {
            writer.write_all(b"x").unwrap();
        }
        let interest = InterestSet {
            readable: true,
            writable: false,
        };
        let fds = pairs
            .iter()
            .map(|(reader, _)| (reader.as_raw_fd(), interest))
            .collect::<Vec<_>>();
        for _ in 0..pairs.len() {
            let (fd, ready) = wait_any(&fds).unwrap().unwrap();
            assert!(fds.iter().any(|(candidate, _)| *candidate == fd));
            assert!(ready.readable);
        }
        assert_eq!(debug_info().used_fds, 0);
    }

    #[test]
    fn check_io_deselect_suppresses_delivery() {
        let _guard = TEST_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let (reader, mut writer) = UnixStream::pair().unwrap();
        let (tx, rx) = mpsc::channel();
        let registration = register(
            reader.as_raw_fd(),
            InterestSet {
                readable: true,
                writable: false,
            },
            move |_, event| {
                let _ = tx.send(event);
            },
        )
        .unwrap();
        deregister(registration);
        writer.write_all(b"x").unwrap();
        assert!(rx.recv_timeout(Duration::from_millis(30)).is_err());
        assert_eq!(debug_info().used_fds, 0);
    }

    #[test]
    fn check_io_stop_is_delivered_once() {
        let _guard = TEST_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let (reader, writer) = UnixStream::pair().unwrap();
        let (tx, rx) = mpsc::channel();
        let _registration = register(
            reader.as_raw_fd(),
            InterestSet {
                readable: true,
                writable: false,
            },
            move |_, event| {
                let _ = tx.send(event);
            },
        )
        .unwrap();
        drop(writer);
        let event = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(event.readable || event.closed || event.error);
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn check_io_deregister_after_ready_is_idempotent() {
        let _guard = TEST_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let (reader, mut writer) = UnixStream::pair().unwrap();
        writer.write_all(b"x").unwrap();
        let (tx, rx) = mpsc::channel();
        let registration = register(
            reader.as_raw_fd(),
            InterestSet {
                readable: true,
                writable: false,
            },
            move |_, event| {
                let _ = tx.send(event);
            },
        )
        .unwrap();
        assert!(rx.recv_timeout(Duration::from_secs(2)).unwrap().readable);
        deregister(registration);
        assert_eq!(debug_info().used_fds, 0);
    }

    #[test]
    fn check_io_read_and_write_share_one_socket_registration() {
        let _guard = TEST_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let (reader, mut writer) = UnixStream::pair().unwrap();
        let (read_tx, read_rx) = mpsc::channel();
        let (write_tx, write_rx) = mpsc::channel();
        let fd = reader.as_raw_fd();
        let read_registration = register(
            fd,
            InterestSet {
                readable: true,
                writable: false,
            },
            move |_, ready| {
                let _ = read_tx.send(ready.readable);
            },
        )
        .unwrap();
        let write_registration = register(
            fd,
            InterestSet {
                readable: false,
                writable: true,
            },
            move |_, ready| {
                let _ = write_tx.send(ready.writable);
            },
        )
        .unwrap();
        assert!(write_rx.recv_timeout(Duration::from_secs(2)).unwrap());
        writer.write_all(b"x").unwrap();
        assert!(read_rx.recv_timeout(Duration::from_secs(2)).unwrap());
        deregister(read_registration);
        deregister(write_registration);
        assert_eq!(debug_info().used_fds, 0);
    }

    #[test]
    fn check_io_one_shot_callback_runs_after_poll_set_update() {
        let _guard = TEST_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let (reader, mut writer) = UnixStream::pair().unwrap();
        writer.write_all(b"x").unwrap();
        let fd = reader.as_raw_fd();
        let readable = InterestSet {
            readable: true,
            writable: false,
        };
        let (tx, rx) = mpsc::channel();
        let _registration = register(fd, readable, move |_, _| {
            let tx = tx.clone();
            let _ = tx.send(());
        })
        .unwrap();
        assert!(rx.recv_timeout(Duration::from_secs(5)).is_ok());
    }
}
