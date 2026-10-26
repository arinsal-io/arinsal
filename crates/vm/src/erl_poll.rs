//! Safe syscall adapter for the ERTS poll API.
//!
//! The event state and one-shot policy live in `check_io`; this module only
//! translates ERTS poll operations to mio's platform poller.

use mio::unix::SourceFd;
use mio::{Events, Interest, Poll, Registry, Token, Waker};
use std::io;
use std::os::fd::RawFd;
use std::sync::OnceLock;
use std::time::Duration;

/// No poll events are enabled.
pub(crate) const ERTS_POLL_EV_NONE: u32 = 0;
/// Read readiness.
pub(crate) const ERTS_POLL_EV_IN: u32 = 1;
/// Write readiness.
pub(crate) const ERTS_POLL_EV_OUT: u32 = 2;
/// Poller error or hangup.
pub(crate) const ERTS_POLL_EV_ERR: u32 = 4;
/// Invalid descriptor, returned for failed control operations.
pub(crate) const ERTS_POLL_EV_NVAL: u32 = 8;

/// The operation used to modify a poll set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ErtsPollOp {
    /// Add a descriptor and its requested interests.
    Add,
    /// Change interests or re-enable a disabled descriptor.
    Mod,
    /// Remove a descriptor.
    Del,
}

/// One result from the poller. `fd` is `None` for the internal wake event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ErtsPollEvent {
    pub fd: Option<RawFd>,
    pub events: u32,
    pub closed: bool,
    pub error: bool,
}

/// Poll state owned by the single ERTS-style poll thread.
pub(crate) struct ErtsPollSet {
    poll: Poll,
    events: Events,
}

struct PollControl {
    registry: Registry,
    waker: Waker,
}

/// Which poll set an operation addresses: the one the poll thread waits on, or the scheduler
/// pollset the schedulers poll themselves.
// Port of erts/emulator/sys/common/erl_check_io.c (pollsetv, sched_pollset), OTP-29.1.1.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PollSetKind {
    Main,
    Scheduler,
    /// The `select(2)` fallback set (`ps->fallback`): descriptors the kernel poller cannot
    /// take, and fds 0-2.
    Fallback,
}

impl PollSetKind {
    fn index(self) -> usize {
        match self {
            Self::Main => 0,
            Self::Scheduler => 1,
            Self::Fallback => unreachable!("the fallback set has no kernel poller"),
        }
    }
}

static POLL_CONTROL: [OnceLock<PollControl>; 2] = [OnceLock::new(), OnceLock::new()];
const WAKE_TOKEN: usize = usize::MAX;
const EVENT_CAPACITY: usize = 512;

/// Return the descriptor limit used to size `drv_ev_state`.
// Port of erts/emulator/sys/common/erl_poll.c (erts_poll_init), OTP-29.1.1.
pub(crate) fn erts_poll_max_fds() -> usize {
    // sysconf(_SC_OPEN_MAX) reports the soft limit on Unix. ERTS uses 24576
    // when macOS reports an unlimited descriptor count.
    rustix::process::getrlimit(rustix::process::Resource::Nofile)
        .current
        .and_then(|limit| usize::try_from(limit).ok())
        .unwrap_or(24_576)
        .max(1)
}

/// Initialize the sole poll set and its out-of-band interrupt.
// Port of erts/emulator/sys/common/erl_poll.c (erts_poll_init), OTP-29.1.1.
pub(crate) fn erts_poll_init(kind: PollSetKind) -> io::Result<ErtsPollSet> {
    let poll = Poll::new()?;
    let registry = poll.registry().try_clone()?;
    let waker = Waker::new(&registry, Token(WAKE_TOKEN))?;
    POLL_CONTROL[kind.index()]
        .set(PollControl { registry, waker })
        .map_err(|_| io::Error::new(io::ErrorKind::AlreadyExists, "ERTS poll set initialized"))?;
    Ok(ErtsPollSet {
        poll,
        events: Events::with_capacity(EVENT_CAPACITY),
    })
}

/// Apply `op` directly to the shared native poll set from the calling thread.
///
/// `ADD` maps to `Registry::register` (and to `reregister` if already present);
/// `MOD` maps to `reregister`. ERTS one-shot disable is a `MOD` with no active
/// interests, which mio represents by deregistering the source while
/// `check_io` retains its logical registration. A later `MOD` re-registers
/// that source and the edge-triggered backend reports readiness that persists.
/// `DEL` deregisters the source and clears the logical registration in
/// `check_io`. Successful control changes interrupt the poll thread, matching
/// the `wake_poller` path in ERTS.
// Port of erts/emulator/sys/common/erl_poll.c (erts_poll_control), OTP-29.1.1.
pub(crate) fn erts_poll_control(kind: PollSetKind, fd: RawFd, op: ErtsPollOp, events: u32) -> u32 {
    match erts_poll_control_inner(kind, fd, op, events) {
        Ok(()) => {
            // kqueue and epoll take changes while a thread waits (`concurrent_updates`), so
            // only the dedicated poll thread's set is interrupted, as before.
            if kind == PollSetKind::Main {
                let _ = erts_poll_interrupt(kind);
            }
            ERTS_POLL_EV_NONE
        }
        Err(_) => ERTS_POLL_EV_NVAL,
    }
}

fn erts_poll_control_inner(
    kind: PollSetKind,
    fd: RawFd,
    op: ErtsPollOp,
    events: u32,
) -> io::Result<()> {
    if kind == PollSetKind::Fallback {
        return fallback::control(fd, op, events);
    }
    if fd < 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "negative descriptor",
        ));
    }
    let control = POLL_CONTROL[kind.index()].get().ok_or_else(|| {
        io::Error::new(io::ErrorKind::NotConnected, "ERTS poll set not initialized")
    })?;
    let token = fd_token(fd)?;
    let mut source = SourceFd(&fd);
    let interest = interest(events)?;
    match op {
        ErtsPollOp::Add => match interest {
            Some(interest) => match control.registry.register(&mut source, token, interest) {
                Ok(()) => Ok(()),
                // kqueue EV_ADD also modifies an existing filter; epoll ADD is
                // only used for a new one. Preserve the common ERTS operation.
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    control.registry.reregister(&mut source, token, interest)
                }
                Err(error) => Err(error),
            },
            None => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "cannot add a descriptor without interests",
            )),
        },
        ErtsPollOp::Mod => match interest {
            Some(interest) => match control.registry.reregister(&mut source, token, interest) {
                Ok(()) => Ok(()),
                // A zero-interest MOD disables the source by deregistering it,
                // since mio has no empty Interest. Re-arming registers it again;
                // edge-triggered pollers report a descriptor that is already ready.
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    control.registry.register(&mut source, token, interest)
                }
                Err(error) => Err(error),
            },
            None => match control.registry.deregister(&mut source) {
                Ok(()) => Ok(()),
                Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
                Err(error) => Err(error),
            },
        },
        ErtsPollOp::Del => match control.registry.deregister(&mut source) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        },
    }
}

/// Wait for native readiness and copy the batch into a reusable result buffer.
// Port of erts/emulator/sys/common/erl_poll.c (erts_poll_wait), OTP-29.1.1.
pub(crate) fn erts_poll_wait(
    pollset: &mut ErtsPollSet,
    timeout: Option<Duration>,
    results: &mut Vec<ErtsPollEvent>,
) -> io::Result<()> {
    results.clear();
    pollset.poll.poll(&mut pollset.events, timeout)?;
    for event in &pollset.events {
        let token = event.token();
        if token == Token(WAKE_TOKEN) {
            results.push(ErtsPollEvent {
                fd: None,
                events: ERTS_POLL_EV_NONE,
                closed: false,
                error: false,
            });
            continue;
        }
        let fd = token_fd(token)?;
        let mut flags = ERTS_POLL_EV_NONE;
        if event.is_readable() {
            flags |= ERTS_POLL_EV_IN;
        }
        if event.is_writable() {
            flags |= ERTS_POLL_EV_OUT;
        }
        if event.is_error() || event.is_read_closed() || event.is_write_closed() {
            flags |= ERTS_POLL_EV_ERR;
        }
        results.push(ErtsPollEvent {
            fd: Some(fd),
            events: flags,
            closed: event.is_read_closed() || event.is_write_closed(),
            error: event.is_error(),
        });
    }
    Ok(())
}

/// Interrupt a thread blocked in [`erts_poll_wait`].
// Port of erts/emulator/sys/common/erl_poll.c (erts_poll_interrupt), OTP-29.1.1.
pub(crate) fn erts_poll_interrupt(kind: PollSetKind) -> io::Result<()> {
    POLL_CONTROL[kind.index()]
        .get()
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotConnected, "ERTS poll set not initialized")
        })?
        .waker
        .wake()
}

fn fd_token(fd: RawFd) -> io::Result<Token> {
    let token = usize::try_from(fd)
        .ok()
        .and_then(|fd| fd.checked_add(1))
        .filter(|token| *token != WAKE_TOKEN)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "descriptor token overflow"))?;
    Ok(Token(token))
}

fn token_fd(token: Token) -> io::Result<RawFd> {
    token
        .0
        .checked_sub(1)
        .and_then(|fd| i32::try_from(fd).ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid descriptor token"))
}

fn interest(events: u32) -> io::Result<Option<Interest>> {
    let readable = events & ERTS_POLL_EV_IN != 0;
    let writable = events & ERTS_POLL_EV_OUT != 0;
    Ok(match (readable, writable) {
        (true, true) => Some(Interest::READABLE.add(Interest::WRITABLE)),
        (true, false) => Some(Interest::READABLE),
        (false, true) => Some(Interest::WRITABLE),
        (false, false) if events & !(ERTS_POLL_EV_ERR | ERTS_POLL_EV_NVAL) == 0 => None,
        (false, false) => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "unsupported ERTS poll events",
            ));
        }
    })
}

/// Install the receiver of fallback events; the select thread starts with the first fd.
pub(crate) fn erts_poll_fallback_sink(sink: fn(RawFd, u32)) {
    fallback::SINK.get_or_init(|| sink);
}

/// The `select(2)` fallback poll set.
///
/// Port of erts/emulator/sys/common/erl_poll.c (the `ERTS_POLL_USE_FALLBACK` set, `ps->fallback`
/// with `erts_poll_wait__fallback`), OTP-29.1.1: a regular file is always ready under
/// `select`, which a kqueue read filter at end of file is not.
mod fallback {
    use super::{ERTS_POLL_EV_IN, ERTS_POLL_EV_OUT, ErtsPollOp};
    use std::collections::HashMap;
    use std::io;
    use std::os::fd::{BorrowedFd, OwnedFd, RawFd};
    use std::sync::{Mutex, OnceLock};

    pub(super) static SINK: OnceLock<fn(RawFd, u32)> = OnceLock::new();

    struct Set {
        fds: Mutex<HashMap<RawFd, u32>>,
        wake_write: OwnedFd,
    }

    static SET: OnceLock<Set> = OnceLock::new();

    fn set() -> io::Result<&'static Set> {
        if let Some(set) = SET.get() {
            return Ok(set);
        }
        let (read, write) = rustix::pipe::pipe()?;
        rustix::io::fcntl_setfd(&read, rustix::io::FdFlags::CLOEXEC)?;
        rustix::io::fcntl_setfd(&write, rustix::io::FdFlags::CLOEXEC)?;
        let mut created = false;
        let set = SET.get_or_init(|| {
            created = true;
            Set {
                fds: Mutex::new(HashMap::new()),
                wake_write: write,
            }
        });
        if created {
            let spawned = std::thread::Builder::new()
                .name("arinsal-poll-fallback".into())
                .spawn(move || run(set, read));
            spawned?;
        }
        Ok(set)
    }

    pub(super) fn control(fd: RawFd, op: ErtsPollOp, events: u32) -> io::Result<()> {
        if fd < 0 || fd as usize >= libc::FD_SETSIZE {
            return Err(io::Error::from(io::ErrorKind::InvalidInput));
        }
        let set = set()?;
        {
            let mut fds = set.fds.lock().unwrap();
            match op {
                ErtsPollOp::Add | ErtsPollOp::Mod
                    if events & (ERTS_POLL_EV_IN | ERTS_POLL_EV_OUT) != 0 =>
                {
                    fds.insert(fd, events & (ERTS_POLL_EV_IN | ERTS_POLL_EV_OUT));
                }
                _ => {
                    fds.remove(&fd);
                }
            }
        }
        // Wake the select thread so it sees the changed set (erts_poll_control wake_poller).
        let _ = rustix::io::write(&set.wake_write, &[1]);
        Ok(())
    }

    /// The selected descriptor for one `poll` call.
    fn borrow(fd: RawFd) -> BorrowedFd<'static> {
        // SAFETY: the owner keeps a selected descriptor open until it deselects it; a closed
        // one makes poll report POLLNVAL, which is delivered as ready, and nothing is read.
        unsafe { BorrowedFd::borrow_raw(fd) }
    }

    fn run(set: &'static Set, wake_read: OwnedFd) {
        use rustix::event::{PollFd, PollFlags, poll};
        loop {
            let watched: Vec<(RawFd, u32)> = set
                .fds
                .lock()
                .unwrap()
                .iter()
                .map(|(fd, events)| (*fd, *events))
                .collect();
            let borrowed: Vec<_> = watched.iter().map(|(fd, _)| borrow(*fd)).collect();
            let mut fds = vec![PollFd::new(&wake_read, PollFlags::IN)];
            for (borrowed, (_, events)) in borrowed.iter().zip(&watched) {
                let mut flags = PollFlags::empty();
                if events & ERTS_POLL_EV_IN != 0 {
                    flags |= PollFlags::IN;
                }
                if events & ERTS_POLL_EV_OUT != 0 {
                    flags |= PollFlags::OUT;
                }
                fds.push(PollFd::from_borrowed_fd(*borrowed, flags));
            }
            if poll(&mut fds, None).is_err() {
                std::thread::sleep(std::time::Duration::from_millis(2));
                continue;
            }
            if !fds[0].revents().is_empty() {
                let mut buf = [0u8; 64];
                let _ = rustix::io::read(&wake_read, &mut buf);
            }
            for (poll_fd, (fd, events)) in fds[1..].iter().zip(watched.iter()) {
                let revents = poll_fd.revents();
                if revents.is_empty() {
                    continue;
                }
                let mut ready = 0;
                if events & ERTS_POLL_EV_IN != 0
                    && revents.intersects(
                        PollFlags::IN | PollFlags::HUP | PollFlags::ERR | PollFlags::NVAL,
                    )
                {
                    ready |= ERTS_POLL_EV_IN;
                }
                if events & ERTS_POLL_EV_OUT != 0
                    && revents.intersects(
                        PollFlags::OUT | PollFlags::HUP | PollFlags::ERR | PollFlags::NVAL,
                    )
                {
                    ready |= ERTS_POLL_EV_OUT;
                }
                if ready == 0 {
                    continue;
                }
                // One-shot: the interest is gone until the owner re-arms it.
                {
                    let mut fds = set.fds.lock().unwrap();
                    if let Some(current) = fds.get_mut(fd) {
                        *current &= !ready;
                        if *current == 0 {
                            fds.remove(fd);
                        }
                    }
                }
                if let Some(sink) = SINK.get() {
                    sink(*fd, ready);
                }
            }
        }
    }
}
