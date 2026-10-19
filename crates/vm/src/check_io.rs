//! Shared descriptor readiness service.
//!
//! The descriptor-indexed state and one-shot scheduling follow
//! `erts/emulator/sys/common/erl_check_io.c` (OTP-29.1.1). `erl_poll` owns only
//! the mio syscall adapter; registrations are changed by their caller thread.

use crate::erl_poll::{
    ERTS_POLL_EV_ERR, ERTS_POLL_EV_IN, ERTS_POLL_EV_NONE, ERTS_POLL_EV_NVAL, ERTS_POLL_EV_OUT,
    ErtsPollEvent, ErtsPollOp, ErtsPollSet, erts_poll_control, erts_poll_init, erts_poll_max_fds,
    erts_poll_wait,
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

#[derive(Clone, Copy)]
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
struct DriverSelect {
    owner: Option<usize>,
    events: InterestSet,
    active_events: InterestSet,
    ready: Option<SelectCallback>,
}

#[derive(Default)]
struct FdState {
    driver: DriverSelect,
    watches: Vec<Watch>,
    poll_events: InterestSet,
    poll_registered: bool,
}

struct FdStateTable {
    slots: RwLock<Vec<Mutex<FdState>>>,
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
            slots.resize_with(new_len.min(self.max_fds), || Mutex::new(FdState::default()));
        }
        Ok(index)
    }

    fn lock_slots(
        &self,
        fd: RawFd,
    ) -> io::Result<(usize, std::sync::RwLockReadGuard<'_, Vec<Mutex<FdState>>>)> {
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

fn poller() -> &'static Poller {
    POLLER.get_or_init(|| {
        let poll = erts_poll_init().expect("create shared ERTS poll set");
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

#[cfg(test)]
/// Wait on a set of descriptors through the shared one-shot poll set.
pub(crate) fn wait_any(fds: &[(RawFd, InterestSet)]) -> io::Result<Option<(RawFd, Ready)>> {
    wait_any_timeout(fds, None)
}

#[cfg(test)]
/// Wait with an optional deadline; timeout removes all registrations.
pub(crate) fn wait_any_timeout(
    fds: &[(RawFd, InterestSet)],
    timeout: Option<Duration>,
) -> io::Result<Option<(RawFd, Ready)>> {
    wait_any_timeout_kind(fds, timeout, RegistrationKind::Driver, None)
}

/// Like [`wait_any_timeout`], with `wake` the caller's own wake-up descriptor.
pub(crate) fn wait_any_timeout_wake(
    fds: &[(RawFd, InterestSet)],
    timeout: Option<Duration>,
    wake: RawFd,
) -> io::Result<Option<(RawFd, Ready)>> {
    wait_any_timeout_kind(fds, timeout, RegistrationKind::Driver, Some(wake))
}

/// Wait for a NIF selection while sharing the single ERTS poll thread.
pub(crate) fn wait_any_nif_timeout_wake(
    fds: &[(RawFd, InterestSet)],
    timeout: Option<Duration>,
    wake: RawFd,
) -> io::Result<Option<(RawFd, Ready)>> {
    wait_any_timeout_kind(fds, timeout, RegistrationKind::Nif, Some(wake))
}

struct WaitResult {
    value: Mutex<Option<(RawFd, Ready)>>,
    changed: Condvar,
}

fn wait_any_timeout_kind(
    fds: &[(RawFd, InterestSet)],
    timeout: Option<Duration>,
    kind: RegistrationKind,
    wake: Option<RawFd>,
) -> io::Result<Option<(RawFd, Ready)>> {
    if fds.is_empty() {
        return Ok(None);
    }
    let result = Arc::new(WaitResult {
        value: Mutex::new(None),
        changed: Condvar::new(),
    });
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
    if always_ready_fd(fd) {
        ready(
            fd,
            Ready {
                readable: interests.readable,
                writable: interests.writable,
                closed: false,
                error: false,
            },
        );
        return Ok(registration);
    }
    let (index, slots) = poller.states.lock_slots(fd)?;
    let mut state = slots[index].lock().unwrap();
    state.watches.push(Watch {
        id,
        interests,
        kind,
        callback: Some(Box::new(ready)),
    });
    match sync_pollset(fd, &mut state) {
        Ok(()) => Ok(registration),
        Err(_error) if always_ready_fd(fd) => {
            let watch = state.watches.pop().expect("newly added watch");
            drop(state);
            (watch.callback.expect("pending watch"))(
                fd,
                Ready {
                    readable: interests.readable,
                    writable: interests.writable,
                    closed: false,
                    error: false,
                },
            );
            Ok(registration)
        }
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
    let mut state = slots[index].lock().unwrap();
    state.watches.retain(|watch| watch.id != registration.id);
    let _ = sync_pollset(registration.fd, &mut state);
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
                check_event(&states, fd, event);
            }
        }
    }
}

fn check_event(states: &FdStateTable, fd: RawFd, event: ErtsPollEvent) {
    let Ok((index, slots)) = states.lock_slots(fd) else {
        return;
    };
    let mut state = slots[index].lock().unwrap();
    let seen = InterestSet {
        readable: event.events & ERTS_POLL_EV_IN != 0,
        writable: event.events & ERTS_POLL_EV_OUT != 0,
    };
    let poll_error = event.events & (ERTS_POLL_EV_ERR | ERTS_POLL_EV_NVAL) != 0;
    let mut fired_driver = if poll_error {
        state.driver.active_events
    } else {
        intersect(state.driver.active_events, seen)
    };
    let ready = Ready {
        // ERTS converts an error to all active directions before it schedules
        // the corresponding input/output port task.
        readable: fired_driver.readable,
        writable: fired_driver.writable,
        closed: event.closed,
        error: event.error || poll_error,
    };
    state.driver.active_events = minus(state.driver.active_events, fired_driver);
    let mut driver_callback = (fired_driver.readable || fired_driver.writable)
        .then(|| state.driver.ready.clone())
        .flatten();

    let mut callbacks = Vec::new();
    state.watches.retain_mut(|watch| {
        let fired = poll_error
            || (watch.interests.readable && seen.readable)
            || (watch.interests.writable && seen.writable);
        if fired {
            if let Some(callback) = watch.callback.take() {
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

    let mut callback_ready = ready;
    if sync_pollset(fd, &mut state).is_err() {
        // A failed re-arm is reported as NVAL by erts_check_io. Trigger every
        // remaining active selection after removing the descriptor from mio.
        let remaining = state.driver.active_events;
        fired_driver = union(fired_driver, remaining);
        state.driver.active_events = InterestSet::default();
        state.poll_events = InterestSet::default();
        state.poll_registered = false;
        let _ = erts_poll_control(fd, ErtsPollOp::Del, ERTS_POLL_EV_NONE);
        if (fired_driver.readable || fired_driver.writable)
            && let Some(callback) = state.driver.ready.clone()
        {
            driver_callback = Some(callback);
        }
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
        callback_ready = Ready {
            readable: fired_driver.readable,
            writable: fired_driver.writable,
            closed: false,
            error: true,
        };
    }
    drop(state);
    if let Some(callback) = driver_callback {
        callback(fd, callback_ready);
    }
    for (callback, watch_ready) in callbacks {
        callback(fd, watch_ready);
    }
}

fn sync_pollset(fd: RawFd, state: &mut FdState) -> io::Result<()> {
    let next = union(state.driver.active_events, watch_interests(&state.watches));
    let selected =
        state.driver.events.readable || state.driver.events.writable || !state.watches.is_empty();
    if next == state.poll_events {
        if !next.readable && !next.writable && state.poll_registered && !selected {
            poll_control(fd, ErtsPollOp::Del, ERTS_POLL_EV_NONE)?;
            state.poll_registered = false;
        }
        return Ok(());
    }
    let flags = (if next.readable { ERTS_POLL_EV_IN } else { 0 })
        | (if next.writable { ERTS_POLL_EV_OUT } else { 0 });
    let op = if next.readable || next.writable {
        if state.poll_registered {
            ErtsPollOp::Mod
        } else {
            ErtsPollOp::Add
        }
    } else if selected {
        ErtsPollOp::Mod
    } else if state.poll_registered {
        ErtsPollOp::Del
    } else {
        state.poll_events = next;
        return Ok(());
    };
    poll_control(fd, op, flags)?;
    state.poll_events = next;
    state.poll_registered = op != ErtsPollOp::Del;
    Ok(())
}

fn watch_interests(watches: &[Watch]) -> InterestSet {
    watches
        .iter()
        .fold(InterestSet::default(), |events, watch| {
            union(events, watch.interests)
        })
}

fn poll_control(fd: RawFd, op: ErtsPollOp, events: u32) -> io::Result<()> {
    if erts_poll_control(fd, op, events) & ERTS_POLL_EV_NVAL != 0 {
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

fn intersect(left: InterestSet, right: InterestSet) -> InterestSet {
    InterestSet {
        readable: left.readable && right.readable,
        writable: left.writable && right.writable,
    }
}

fn minus(left: InterestSet, right: InterestSet) -> InterestSet {
    InterestSet {
        readable: left.readable && !right.readable,
        writable: left.writable && !right.writable,
    }
}

/// Readiness callback for a persistent driver selection.
pub(crate) type SelectCallback = Arc<dyn Fn(RawFd, Ready) + Send + Sync>;

/// Select or deselect `fd` for the driver identified by `owner`.
// Port of erts/emulator/sys/common/erl_check_io.c (driver_select), OTP-29.1.1.
pub(crate) fn driver_select(
    fd: RawFd,
    owner: usize,
    events: InterestSet,
    ready: SelectCallback,
) -> io::Result<()> {
    let poller = poller();
    let (index, slots) = poller.states.lock_slots(fd)?;
    let mut state = slots[index].lock().unwrap();
    if state.driver.owner.is_some_and(|current| current != owner) {
        state.driver = DriverSelect::default();
        sync_pollset(fd, &mut state)?;
    }
    if !events.readable && !events.writable && state.driver.owner.is_none() {
        return Ok(());
    }
    let old_events = state.driver.events;
    let added = minus(events, old_events);
    let removed = minus(old_events, events);
    state.driver.owner = (events.readable || events.writable).then_some(owner);
    state.driver.ready = (events.readable || events.writable).then_some(ready);
    state.driver.events = events;
    state.driver.active_events = minus(union(state.driver.active_events, added), removed);
    sync_pollset(fd, &mut state)
}

/// Re-arm the events whose port task has run.
// Port of erts/emulator/sys/common/erl_check_io.c (erts_io_notify_port_task_executed), OTP-29.1.1.
pub(crate) fn notify_executed(fd: RawFd, owner: usize, executed: InterestSet) {
    let poller = poller();
    let Ok((index, slots)) = poller.states.lock_slots(fd) else {
        return;
    };
    let mut state = slots[index].lock().unwrap();
    if state.driver.owner != Some(owner) {
        return;
    }
    let rearm = minus(
        intersect(executed, state.driver.events),
        state.driver.active_events,
    );
    if !rearm.readable && !rearm.writable {
        return;
    }
    state.driver.active_events = union(state.driver.active_events, rearm);
    if sync_pollset(fd, &mut state).is_err() {
        state.driver.active_events = InterestSet::default();
        state.poll_events = InterestSet::default();
        state.poll_registered = false;
        let _ = erts_poll_control(fd, ErtsPollOp::Del, ERTS_POLL_EV_NONE);
        if let Some(callback) = state.driver.ready.clone() {
            drop(state);
            callback(
                fd,
                Ready {
                    readable: rearm.readable,
                    writable: rearm.writable,
                    closed: false,
                    error: true,
                },
            );
        }
    }
}

/// Drop every selection `owner` holds on `fd` before the descriptor is closed.
pub(crate) fn driver_deselect(fd: RawFd, owner: usize) {
    let poller = poller();
    let Ok((index, slots)) = poller.states.lock_slots(fd) else {
        return;
    };
    let mut state = slots[index].lock().unwrap();
    if state.driver.owner != Some(owner) {
        return;
    }
    state.driver = DriverSelect::default();
    let _ = sync_pollset(fd, &mut state);
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
        let state = state.lock().unwrap();
        let driver_used = state.driver.events.readable || state.driver.events.writable;
        // Port of erts/emulator/sys/common/erl_check_io.c (doit_erts_check_io_debug), OTP-29.1.1:
        // internal wake registrations do not contribute to the used-fd counter.
        if driver_used
            || state
                .watches
                .iter()
                .any(|watch| !matches!(watch.kind, RegistrationKind::Internal))
        {
            info.used_fds += 1;
        }
        info.driver_selects += usize::from(driver_used);
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

fn always_ready_fd(fd: RawFd) -> bool {
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
            erts_poll_control(-1, ErtsPollOp::Add, ERTS_POLL_EV_IN) & ERTS_POLL_EV_NVAL,
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
    fn check_io_driver_select_is_one_shot_until_task_executed() {
        let _guard = TEST_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let (reader, mut writer) = UnixStream::pair().unwrap();
        let fd = reader.as_raw_fd();
        let (tx, rx) = mpsc::channel();
        let tx = Mutex::new(tx);
        let readable = InterestSet {
            readable: true,
            writable: false,
        };
        driver_select(
            fd,
            7,
            readable,
            Arc::new(move |_, ready| {
                let _ = tx.lock().unwrap().send(ready);
            }),
        )
        .unwrap();
        writer.write_all(b"x").unwrap();
        assert!(rx.recv_timeout(Duration::from_secs(2)).unwrap().readable);
        writer.write_all(b"y").unwrap();
        assert!(rx.recv_timeout(Duration::from_millis(50)).is_err());
        notify_executed(fd, 7, readable);
        assert!(rx.recv_timeout(Duration::from_secs(2)).unwrap().readable);
        assert_eq!(debug_info().driver_selects, 1);
        driver_deselect(fd, 7);
        notify_executed(fd, 7, readable);
        assert!(rx.recv_timeout(Duration::from_millis(50)).is_err());
        assert_eq!(debug_info().used_fds, 0);
    }

    #[test]
    fn check_io_driver_select_off_drops_event_and_other_owner_steals() {
        let _guard = TEST_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let (reader, mut writer) = UnixStream::pair().unwrap();
        let fd = reader.as_raw_fd();
        let (tx, rx) = mpsc::channel::<usize>();
        let callback = |owner: usize| -> SelectCallback {
            let tx = Mutex::new(tx.clone());
            Arc::new(move |_, _| {
                let _ = tx.lock().unwrap().send(owner);
            })
        };
        let readable = InterestSet {
            readable: true,
            writable: false,
        };
        let none = InterestSet::default();
        driver_select(fd, 1, readable, callback(1)).unwrap();
        driver_select(fd, 1, none, callback(1)).unwrap();
        writer.write_all(b"x").unwrap();
        assert!(rx.recv_timeout(Duration::from_millis(50)).is_err());
        driver_select(fd, 1, readable, callback(1)).unwrap();
        assert_eq!(rx.recv_timeout(Duration::from_secs(2)).unwrap(), 1);
        driver_select(fd, 2, readable, callback(2)).unwrap();
        assert_eq!(rx.recv_timeout(Duration::from_secs(2)).unwrap(), 2);
        driver_deselect(fd, 1);
        assert_eq!(debug_info().driver_selects, 1);
        driver_deselect(fd, 2);
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
        let _registration = register(fd, readable, move |fd, _| {
            let tx = tx.clone();
            driver_select(
                fd,
                7,
                readable,
                Arc::new(move |_, _| {
                    let _ = tx.send(());
                }),
            )
            .unwrap();
        })
        .unwrap();
        assert!(rx.recv_timeout(Duration::from_secs(5)).is_ok());
        driver_deselect(fd, 7);
    }
}
