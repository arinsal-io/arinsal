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

mod raw;

const EVENT_CAPACITY: usize = 512;

#[derive(Clone, Copy)]
enum PollState {
    CheckIo,
    Sleep,
}

fn set_poll_state(state: PollState) {
    arinsal_sched::erts_msacc_set_state(match state {
        PollState::CheckIo => arinsal_sched::MsaccState::CheckIo,
        PollState::Sleep => arinsal_sched::MsaccState::Sleep,
    });
}

/// Start the poll thread so it owns its unmanaged ErtsMsAcc entry.
// Port of erl_process.c:3356 (poll_thread calls erts_msacc_init_thread), OTP-29.1.1.
pub(crate) fn ensure_msacc_thread() {
    let _ = poller();
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
    /// The `driver_select` / `enif_select` state of the descriptor (`ErtsDrvEventState`): what the
    /// drivers armed is polled together with `watches`.
    sel: arinsal_drv::SelSlot,
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

type FdStateTable = raw::FdStateTable<FdState>;

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
        let (started, ready) = std::sync::mpsc::channel();
        thread::Builder::new()
            .name("arinsal-check-io".into())
            .spawn(move || poll_loop(poll, worker_states, started))
            .expect("start shared ERTS poll thread");
        ready
            .recv()
            .expect("poll thread initializes its msacc entry");
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

/// Run `f` on the `driver_select` state of `fd` under the descriptor lock, then bring the poll
/// set in line with the directions the drivers armed (`erts_io_control`). The result is the mask
/// of directions the poller rejected (`ERTS_POLL_EV_NVAL`).
pub(crate) fn with_sel(fd: RawFd, f: &mut dyn FnMut(&mut arinsal_drv::SelSlot)) -> i32 {
    // Port of erts/emulator/sys/common/erl_check_io.c:1007 (`driver_select`), OTP-29.1.1.
    let _msacc = arinsal_sched::erts_msacc_push_and_set_state(arinsal_sched::MsaccState::CheckIo);
    let poller = poller();
    let Ok(mut state) = poller.states.lock_slots(fd) else {
        // A descriptor the table cannot hold is never polled.
        let mut slot = None;
        f(&mut slot);
        return arinsal_drv::rejected(&mut slot);
    };
    f(&mut state.sel);
    let (read, write) = arinsal_drv::wanted(&state.sel);
    if read || write {
        // Port of erts/emulator/sys/common/erl_poll.c (concurrent_update_pollset: ADD of fds
        // 0-2 returns NVAL, so they live in the fallback set), OTP-29.1.1.
        if fd <= 2 || fallback_marked(fd) {
            state.fallback = true;
        }
        // Port of erl_check_io.c (erts_io_notify_port_task_executed): the read descriptor of a
        // driver that was re-enabled often moves to the scheduler pollset.
        if read
            && arinsal_drv::is_driver_selection(&state.sel)
            && !state.scheduler
            && !state.fallback
            && SCHED_POLLSET.get().is_some()
            && state.count > SCHEDULER_MIGRATION_COUNT
        {
            state.scheduler = true;
        }
    }
    let mut result = sync_pollset(fd, &mut state);
    if result.is_err() && !state.fallback {
        // Port of erl_poll.c (a kernel poller `ERTS_POLL_EV_NVAL` moves the descriptor to the
        // fallback set), OTP-29.1.1.
        state.fallback = true;
        state.main = SetState::default();
        result = sync_pollset(fd, &mut state);
    }
    if result.is_err() {
        let mask = arinsal_drv::rejected(&mut state.sel);
        let _ = sync_pollset(fd, &mut state);
        return mask;
    }
    0
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
    let mut state = poller.states.lock_slots(fd)?;
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
    let Ok(mut state) = poller.states.lock_slots(registration.fd) else {
        return;
    };
    state.watches.retain(|watch| watch.id != registration.id);
    let _ = sync_pollset(registration.fd, &mut state);
}

fn poll_loop(
    mut poll: ErtsPollSet,
    states: Arc<FdStateTable>,
    started: std::sync::mpsc::Sender<()>,
) {
    // Port of erts/emulator/sys/common/erl_check_io.c:1940 (`erts_check_io`) and
    // erl_poll.c:1956-2003 (`erts_poll_wait`), OTP-29.1.1.
    arinsal_sched::erts_msacc_init_thread("poll", 0, false);
    arinsal_sched::erts_msacc_set_state(arinsal_sched::MsaccState::Other);
    let _ = started.send(());
    let mut events = Vec::with_capacity(EVENT_CAPACITY);
    loop {
        set_poll_state(PollState::Sleep);
        if let Err(error) = erts_poll_wait(&mut poll, None, &mut events) {
            if error.kind() == io::ErrorKind::Interrupted {
                arinsal_sched::erts_msacc_set_state(arinsal_sched::MsaccState::Other);
                continue;
            }
            arinsal_sched::erts_msacc_set_state(arinsal_sched::MsaccState::Other);
            thread::sleep(Duration::from_millis(2));
            continue;
        }
        set_poll_state(PollState::CheckIo);
        for event in events.drain(..) {
            if let Some(fd) = event.fd {
                check_event(&states, fd, event, PollSetKind::Main);
            }
        }
        arinsal_sched::erts_msacc_set_state(arinsal_sched::MsaccState::Other);
    }
}

fn check_event(states: &FdStateTable, fd: RawFd, event: ErtsPollEvent, from: PollSetKind) {
    let mut state = match states.lock_slots(fd) {
        Ok(state) => state,
        Err(_) => return,
    };
    let mut seen = InterestSet {
        readable: event.events & ERTS_POLL_EV_IN != 0,
        writable: event.events & ERTS_POLL_EV_OUT != 0,
    };
    if from == PollSetKind::Main && state.scheduler {
        // Port of erl_check_io.c (erts_check_io): "We are in a poll thread and the fd is
        // managed by a scheduler, we ignore the any IN events".
        seen.readable = false;
    }
    // Port of erl_check_io.c (erts_check_io, ERTS_EV_TYPE_DRV_SEL / ERTS_EV_TYPE_NIF), OTP-29.1.1:
    // NVAL without IN, OUT or ERR calls no callback; the selection is reported and unmapped.
    if event.events & (ERTS_POLL_EV_IN | ERTS_POLL_EV_OUT | ERTS_POLL_EV_ERR) == 0
        && event.events & ERTS_POLL_EV_NVAL != 0
        && state.sel.is_some()
    {
        arinsal_drv::bad_fd_in_pollset(&mut state.sel, fd);
        let _ = sync_pollset(fd, &mut state);
        return;
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
    let (mut actions, driver_reads) =
        arinsal_drv::poll_event(&mut state.sel, fd, seen.readable, seen.writable, poll_error);
    state.count = state.count.saturating_add(driver_reads);

    if sync_pollset(fd, &mut state).is_err() {
        // A failed re-arm is reported as NVAL by erts_check_io. Trigger every
        // remaining watch after removing the descriptor from the poll set.
        state.main = SetState::default();
        state.sched = SetState::default();
        actions.extend(arinsal_drv::poll_event(&mut state.sel, fd, true, true, true).0);
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
    for action in actions {
        action();
    }
}

fn sync_pollset(fd: RawFd, state: &mut FdState) -> io::Result<()> {
    let (sel_read, sel_write) = arinsal_drv::wanted(&state.sel);
    let next = union(
        watch_interests(&state.watches),
        InterestSet {
            readable: sel_read,
            writable: sel_write,
        },
    );
    let selected = !state.watches.is_empty() || sel_read || sel_write;
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
    let mut info = DebugInfo {
        used_fds: 0,
        driver_selects: 0,
        nif_selects: 0,
    };
    states.with_all_states(|slots| {
        for state in slots {
            // Port of erts/emulator/sys/common/erl_check_io.c (doit_erts_check_io_debug), OTP-29.1.1:
            // internal wake registrations do not contribute to the used-fd counter.
            let (driver_dirs, nif_dirs) = arinsal_drv::selection_counts(&state.sel);
            if driver_dirs + nif_dirs > 0
                || state
                    .watches
                    .iter()
                    .any(|watch| !matches!(watch.kind, RegistrationKind::Internal))
            {
                info.used_fds += 1;
            }
            info.driver_selects += driver_dirs;
            info.nif_selects += nif_dirs;
            for watch in &state.watches {
                match watch.kind {
                    RegistrationKind::Driver => info.driver_selects += 1,
                    RegistrationKind::Nif => info.nif_selects += 1,
                    RegistrationKind::Internal => {}
                }
            }
        }
    });
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
