//! Shared one-shot descriptor readiness service.
//!
//! Port of `erts_check_io` registration and wakeup semantics from
//! `erts/emulator/sys/common/erl_check_io.c` (OTP-29.1.1). `mio` selects the
//! native kqueue backend on macOS and keeps its descriptor operations behind
//! safe APIs.

use mio::unix::SourceFd;
use mio::{Events, Interest, Poll, Token, Waker};
use std::collections::HashMap;
use std::io;
use std::os::fd::RawFd;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, Sender, SyncSender};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::Instant;

const WAKE_TOKEN: Token = Token(0);
const EVENT_CAPACITY: usize = 1024;

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
        })
    })
}

/// Enable or disable accounting for the dedicated poll thread.
// Port of erts/emulator/sys/common/erl_poll.c:1956-2003, OTP-29.1.1.
pub(crate) fn set_msacc_enabled(enabled: bool) {
    let _ = poller();
    let mut msacc = poll_msacc().lock().expect("poll microstate");
    let now = Instant::now();
    msacc.update(now);
    msacc.enabled = enabled;
    msacc.started = now;
}

/// Snapshot the poll thread's check-I/O and sleep counters in nanoseconds.
// Port of erts/emulator/sys/common/erl_check_io.c:558-649, OTP-29.1.1.
pub(crate) fn msacc_snapshot() -> [u64; 2] {
    let mut msacc = poll_msacc().lock().expect("poll microstate");
    msacc.update(Instant::now());
    [msacc.check_io_ns, msacc.sleep_ns]
}

fn set_poll_state(state: PollState) {
    let mut msacc = poll_msacc().lock().expect("poll microstate");
    let now = Instant::now();
    msacc.update(now);
    msacc.state = state;
    msacc.started = now;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Ready {
    pub readable: bool,
    pub writable: bool,
    pub closed: bool,
    pub error: bool,
}

#[derive(Clone, Copy)]
pub(crate) struct InterestSet {
    pub readable: bool,
    pub writable: bool,
}

#[derive(Clone, Copy)]
enum RegistrationKind {
    Driver,
    Nif,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct Registration {
    fd: RawFd,
    id: Token,
}

struct Request {
    id: Token,
    fd: RawFd,
    interests: InterestSet,
    kind: RegistrationKind,
    ready: Box<dyn FnOnce(RawFd, Ready) + Send>,
    ack: SyncSender<io::Result<()>>,
}

enum Command {
    Register(Request),
    Deregister(Registration, SyncSender<()>),
}

type Callback = Box<dyn FnOnce(RawFd, Ready) + Send>;

struct ActiveRegistration {
    fd: RawFd,
    interests: InterestSet,
    watchers: HashMap<Token, (InterestSet, Callback)>,
}

struct Poller {
    tx: Sender<Command>,
    waker: Arc<Waker>,
    next_token: AtomicUsize,
    registrations: Arc<Mutex<HashMap<usize, (RawFd, RegistrationKind)>>>,
}

static POLLER: OnceLock<Poller> = OnceLock::new();

fn poller() -> &'static Poller {
    POLLER.get_or_init(|| {
        let poll = Poll::new().expect("create shared kqueue poller");
        let waker = Arc::new(Waker::new(poll.registry(), WAKE_TOKEN).expect("create poller waker"));
        let (tx, rx) = mpsc::channel();
        let registrations = Arc::new(Mutex::new(HashMap::new()));
        let worker_registrations = Arc::clone(&registrations);
        thread::Builder::new()
            .name("arinsal-check-io".into())
            .spawn(move || poll_loop(poll, rx, worker_registrations))
            .expect("start shared kqueue poller");
        Poller {
            tx,
            waker,
            next_token: AtomicUsize::new(1),
            registrations,
        }
    })
}

/// Wait on a set of descriptors through the shared, one-shot poll set.
///
/// The returned descriptor is removed from the poll set before this function
/// returns. Callers explicitly register it again after handling readiness.
pub(crate) fn wait_any(fds: &[(RawFd, InterestSet)]) -> io::Result<Option<(RawFd, Ready)>> {
    wait_any_timeout(fds, None)
}

/// Wait with an optional deadline; timeout removes all registrations.
pub(crate) fn wait_any_timeout(
    fds: &[(RawFd, InterestSet)],
    timeout: Option<std::time::Duration>,
) -> io::Result<Option<(RawFd, Ready)>> {
    wait_any_timeout_kind(fds, timeout, RegistrationKind::Driver)
}

/// Wait for one NIF selection with an optional deadline.
pub(crate) fn wait_any_nif_timeout(
    fds: &[(RawFd, InterestSet)],
    timeout: Option<std::time::Duration>,
) -> io::Result<Option<(RawFd, Ready)>> {
    wait_any_timeout_kind(fds, timeout, RegistrationKind::Nif)
}

fn wait_any_timeout_kind(
    fds: &[(RawFd, InterestSet)],
    timeout: Option<std::time::Duration>,
    kind: RegistrationKind,
) -> io::Result<Option<(RawFd, Ready)>> {
    if fds.is_empty() {
        return Ok(None);
    }
    let poller = poller();
    let (ready_tx, ready_rx) = mpsc::channel();
    let mut tokens = Vec::with_capacity(fds.len());
    for (fd, interests) in fds {
        let id = Token(poller.next_token.fetch_add(1, Ordering::Relaxed));
        let registration = Registration { fd: *fd, id };
        let (ack_tx, ack_rx) = mpsc::sync_channel(1);
        poller
            .tx
            .send(Command::Register(Request {
                id,
                fd: *fd,
                interests: *interests,
                kind,
                ready: Box::new({
                    let ready_tx = ready_tx.clone();
                    move |fd, ready| {
                        let _ = ready_tx.send((fd, ready));
                    }
                }),
                ack: ack_tx,
            }))
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "poller stopped"))?;
        poller.waker.wake()?;
        tokens.push(registration);
        if let Err(error) = ack_rx
            .recv()
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "poller stopped"))?
        {
            cancel(poller, &tokens);
            return Err(error);
        }
    }
    let result = match timeout {
        Some(timeout) => ready_rx
            .recv_timeout(timeout)
            .map(Some)
            .map_err(|error| match error {
                mpsc::RecvTimeoutError::Timeout => {
                    io::Error::new(io::ErrorKind::TimedOut, "poll timeout")
                }
                mpsc::RecvTimeoutError::Disconnected => {
                    io::Error::new(io::ErrorKind::BrokenPipe, "poller stopped")
                }
            }),
        None => ready_rx
            .recv()
            .map(Some)
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "poller stopped")),
    };
    cancel(poller, &tokens);
    result
}

/// Add an asynchronous one-shot selection to the shared poll set.
pub(crate) fn register(
    fd: RawFd,
    interests: InterestSet,
    ready: impl FnOnce(RawFd, Ready) + Send + 'static,
) -> io::Result<Registration> {
    let poller = poller();
    let id = Token(poller.next_token.fetch_add(1, Ordering::Relaxed));
    let (ack_tx, ack_rx) = mpsc::sync_channel(1);
    poller
        .tx
        .send(Command::Register(Request {
            id,
            fd,
            interests,
            kind: RegistrationKind::Nif,
            ready: Box::new(ready),
            ack: ack_tx,
        }))
        .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "poller stopped"))?;
    poller.waker.wake()?;
    ack_rx
        .recv()
        .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "poller stopped"))??;
    Ok(Registration { fd, id })
}

/// Remove a pending one-shot selection.
pub(crate) fn deregister(registration: Registration) {
    cancel(poller(), &[registration]);
}

fn cancel(poller: &Poller, tokens: &[Registration]) {
    let mut acknowledgements = Vec::with_capacity(tokens.len());
    for token in tokens {
        let (ack_tx, ack_rx) = mpsc::sync_channel(1);
        if poller.tx.send(Command::Deregister(*token, ack_tx)).is_ok() {
            acknowledgements.push(ack_rx);
        }
    }
    let _ = poller.waker.wake();
    for ack in acknowledgements {
        let _ = ack.recv();
    }
}

fn poll_loop(
    mut poll: Poll,
    rx: Receiver<Command>,
    registrations: Arc<Mutex<HashMap<usize, (RawFd, RegistrationKind)>>>,
) {
    // Port of erts/emulator/beam/erl_check_io.c:1933 (erts_check_io), OTP-29.1.1.
    let mut events = Events::with_capacity(EVENT_CAPACITY);
    let mut active = HashMap::<Token, ActiveRegistration>::new();
    let mut fd_tokens = HashMap::<RawFd, Token>::new();
    loop {
        set_poll_state(PollState::CheckIo);
        while let Ok(command) = rx.try_recv() {
            match command {
                Command::Register(request) => {
                    let ack = request.ack.clone();
                    let result = add_registration(
                        &mut poll,
                        &mut active,
                        &mut fd_tokens,
                        &registrations,
                        request,
                    );
                    let _ = ack.send(result);
                }
                Command::Deregister(registration, ack) => {
                    remove_registration(
                        &mut poll,
                        &mut active,
                        &mut fd_tokens,
                        &registrations,
                        registration,
                    );
                    let _ = ack.send(());
                }
            }
        }
        set_poll_state(PollState::Sleep);
        if poll.poll(&mut events, None).is_err() {
            thread::sleep(std::time::Duration::from_millis(2));
            set_poll_state(PollState::CheckIo);
            continue;
        }
        set_poll_state(PollState::CheckIo);
        for event in &events {
            if event.token() == WAKE_TOKEN {
                continue;
            }
            let token = event.token();
            let Some(active_registration) = active.get_mut(&token) else {
                continue;
            };
            let ready = Ready {
                readable: event.is_readable(),
                writable: event.is_writable(),
                closed: event.is_read_closed() || event.is_write_closed(),
                error: event.is_error(),
            };
            let fd = active_registration.fd;
            let mut callbacks = Vec::new();
            let mut fired_ids = Vec::new();
            active_registration
                .watchers
                .retain(|id, (interest, callback)| {
                    let fired = (interest.readable
                        && (ready.readable || ready.closed || ready.error))
                        || (interest.writable && (ready.writable || ready.closed || ready.error));
                    if fired {
                        fired_ids.push(*id);
                        callbacks.push(std::mem::replace(callback, Box::new(|_, _| {})));
                    }
                    !fired
                });
            {
                let mut registrations = registrations.lock().unwrap();
                for id in fired_ids {
                    registrations.remove(&id.0);
                }
            }
            for callback in callbacks {
                callback(fd, ready);
            }
            if active_registration.watchers.is_empty() {
                let source = SourceFd(&fd);
                let _ = poll.registry().deregister(&mut { source });
                active.remove(&token);
                fd_tokens.remove(&fd);
            } else {
                active_registration.interests = active_registration.watchers.values().fold(
                    InterestSet {
                        readable: false,
                        writable: false,
                    },
                    |mut union, (interest, _)| {
                        union.readable |= interest.readable;
                        union.writable |= interest.writable;
                        union
                    },
                );
                if let Some(interest) = poll_interest(active_registration.interests) {
                    let source = SourceFd(&fd);
                    let _ = poll.registry().reregister(&mut { source }, token, interest);
                }
            }
        }
    }
}

fn add_registration(
    poll: &mut Poll,
    active: &mut HashMap<Token, ActiveRegistration>,
    fd_tokens: &mut HashMap<RawFd, Token>,
    registrations: &Mutex<HashMap<usize, (RawFd, RegistrationKind)>>,
    request: Request,
) -> io::Result<()> {
    let interest = poll_interest(request.interests)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "empty poll interest"))?;
    if let Some(token) = fd_tokens.get(&request.fd).copied() {
        let registration = active.get_mut(&token).expect("fd token has registration");
        let next = InterestSet {
            readable: registration.interests.readable || request.interests.readable,
            writable: registration.interests.writable || request.interests.writable,
        };
        let source = SourceFd(&request.fd);
        poll.registry().reregister(
            &mut { source },
            token,
            poll_interest(next).expect("non-empty registration interest"),
        )?;
        registration.interests = next;
        registration
            .watchers
            .insert(request.id, (request.interests, request.ready));
    } else {
        if regular_file_fd(request.fd) {
            deliver_always_ready(request);
            return Ok(());
        }
        let source = SourceFd(&request.fd);
        if let Err(error) = poll
            .registry()
            .register(&mut { source }, request.id, interest)
        {
            // kqueue cannot watch regular files and some character devices such as
            // /dev/null. They are always ready, so deliver the one-shot event now.
            if matches!(
                error.kind(),
                io::ErrorKind::InvalidInput | io::ErrorKind::PermissionDenied
            ) && always_ready_fd(request.fd)
            {
                deliver_always_ready(request);
                return Ok(());
            }
            return Err(error);
        }
        fd_tokens.insert(request.fd, request.id);
        active.insert(
            request.id,
            ActiveRegistration {
                fd: request.fd,
                interests: request.interests,
                watchers: HashMap::from([(request.id, (request.interests, request.ready))]),
            },
        );
    }
    registrations
        .lock()
        .unwrap()
        .insert(request.id.0, (request.fd, request.kind));
    Ok(())
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

fn regular_file_fd(fd: RawFd) -> bool {
    use std::os::unix::fs::FileTypeExt;

    std::fs::metadata(format!("/dev/fd/{fd}")).is_ok_and(|metadata| {
        let file_type = metadata.file_type();
        file_type.is_file() || file_type.is_block_device()
    })
}

fn deliver_always_ready(request: Request) {
    (request.ready)(
        request.fd,
        Ready {
            readable: request.interests.readable,
            writable: request.interests.writable,
            closed: false,
            error: false,
        },
    );
}

fn poll_interest(interests: InterestSet) -> Option<Interest> {
    match (interests.readable, interests.writable) {
        (true, true) => Some(Interest::READABLE.add(Interest::WRITABLE)),
        (true, false) => Some(Interest::READABLE),
        (false, true) => Some(Interest::WRITABLE),
        (false, false) => None,
    }
}

fn remove_registration(
    poll: &mut Poll,
    active: &mut HashMap<Token, ActiveRegistration>,
    fd_tokens: &mut HashMap<RawFd, Token>,
    registrations: &Mutex<HashMap<usize, (RawFd, RegistrationKind)>>,
    registration: Registration,
) {
    let Some(token) = fd_tokens.get(&registration.fd).copied() else {
        registrations.lock().unwrap().remove(&registration.id.0);
        return;
    };
    let Some(current) = active.get_mut(&token) else {
        return;
    };
    current.watchers.remove(&registration.id);
    registrations.lock().unwrap().remove(&registration.id.0);
    if current.watchers.is_empty() {
        let fd = current.fd;
        let source = SourceFd(&fd);
        let _ = poll.registry().deregister(&mut { source });
        active.remove(&token);
        fd_tokens.remove(&fd);
    } else {
        let interests = current.watchers.values().fold(
            InterestSet {
                readable: false,
                writable: false,
            },
            |mut union, (interest, _)| {
                union.readable |= interest.readable;
                union.writable |= interest.writable;
                union
            },
        );
        current.interests = interests;
        let fd = current.fd;
        let source = SourceFd(&fd);
        if let Some(interest) = poll_interest(interests) {
            let _ = poll.registry().reregister(&mut { source }, token, interest);
        }
    }
}

pub(crate) struct DebugInfo {
    pub used_fds: usize,
    pub driver_selects: usize,
    pub nif_selects: usize,
}

pub(crate) fn debug_info() -> DebugInfo {
    let registrations = poller().registrations.lock().unwrap();
    let used_fds = registrations
        .values()
        .map(|(fd, _)| *fd)
        .collect::<std::collections::HashSet<_>>()
        .len();
    let mut driver_selects = 0;
    let mut nif_selects = 0;
    for (_, kind) in registrations.values() {
        match kind {
            RegistrationKind::Driver => driver_selects += 1,
            RegistrationKind::Nif => nif_selects += 1,
        }
    }
    DebugInfo {
        used_fds,
        driver_selects,
        nif_selects,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;
    use std::sync::mpsc;
    use std::time::Duration;

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn check_io_one_shot_rearms_after_delivery() {
        let _guard = TEST_LOCK.lock().unwrap();
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
        let _guard = TEST_LOCK.lock().unwrap();
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
        let _guard = TEST_LOCK.lock().unwrap();
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
        let _guard = TEST_LOCK.lock().unwrap();
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
        let _guard = TEST_LOCK.lock().unwrap();
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
        let _guard = TEST_LOCK.lock().unwrap();
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
}
