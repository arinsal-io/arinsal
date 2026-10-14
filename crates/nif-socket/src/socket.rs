use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use arinsal_bifs::BifError;
use arinsal_etf::OwnedTerm as O;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};

use crate::{Reactor, atom, errno, error, field, last_error, list, map, name, number, ok, pair};

mod lifecycle;
#[cfg(test)]
mod lifecycle_tests;
mod options;
use options::bool_atom;

const MAGIC: u32 = 0x534f_434b;
#[cfg(target_os = "macos")]
const ATMARK_REQUEST: u64 = 0x4004_7307;
#[cfg(target_os = "linux")]
const ATMARK_REQUEST: u64 = 0x8905;
static NEXT_ID: AtomicU64 = AtomicU64::new(1);
static HANDLES: OnceLock<Mutex<HashMap<u64, Arc<Handle>>>> = OnceLock::new();
static REACTOR: OnceLock<Mutex<Option<Arc<dyn Reactor>>>> = OnceLock::new();
static DEBUG: AtomicBool = AtomicBool::new(false);
static SOCKET_DEBUG: AtomicBool = AtomicBool::new(false);
static USE_REGISTRY: AtomicBool = AtomicBool::new(true);
static REGISTRY_PID: Mutex<Option<O>> = Mutex::new(None);
static NEXT_CLOSE_REF: AtomicU64 = AtomicU64::new(1);
static TOTALS: Mutex<Totals> = Mutex::new(Totals::new());

pub(super) fn reactor() -> &'static Mutex<Option<Arc<dyn Reactor>>> {
    REACTOR.get_or_init(|| Mutex::new(None))
}
fn handles() -> &'static Mutex<HashMap<u64, Arc<Handle>>> {
    HANDLES.get_or_init(|| Mutex::new(HashMap::new()))
}
/// Socket state bits, `ESOCK_STATE_*`.
#[allow(dead_code)]
pub(crate) mod state_bits {
    pub const BOUND: u32 = 0x0001;
    pub const LISTENING: u32 = 0x0002;
    pub const ACCEPTING: u32 = 0x0004;
    pub const CONNECTING: u32 = 0x0010;
    pub const CONNECTED: u32 = 0x0020;
    pub const SELECTED: u32 = 0x0100;
    pub const CLOSING: u32 = 0x0200;
    pub const CLOSED: u32 = 0x0400;
    pub const DTOR: u32 = 0x8000;

    /// `IS_OPEN`: neither closing nor closed.
    pub fn is_open(state: u32) -> bool {
        state & (CLOSED | CLOSING) == 0
    }
    /// `IS_CLOSING`.
    pub fn is_closing(state: u32) -> bool {
        state & CLOSING != 0
    }
    /// `IS_CLOSED`.
    pub fn is_closed(state: u32) -> bool {
        state & CLOSED != 0
    }
}

/// A process waiting for an operation on the socket, `ESockRequestor`.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Requestor {
    pub pid: O,
    pub reference: O,
    /// Monitor of `pid` from [`Reactor::monitor`], when the runtime has one.
    pub mon: Option<u64>,
}

/// Which request queue of a socket an operation concerns.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// Which request queue of a socket an operation concerns.
#[allow(dead_code)]
pub(crate) enum Kind {
    Acceptor,
    Writer,
    Reader,
}

/// The mutable part of `ESockDescriptor` shared by the NIFs.
#[derive(Default)]
pub(crate) struct State {
    pub read_state: u32,
    pub write_state: u32,
    pub ctrl_mon: Option<u64>,
    /// The process that called `close`, `closerPid`.
    pub closer: Option<O>,
    pub closer_mon: Option<u64>,
    /// `closeRef` while a scheduled stop has not run yet (`closeEnv != NULL`).
    pub close_ref: Option<O>,
    pub connector: Option<Requestor>,
    pub current_acceptor: Option<Requestor>,
    pub current_writer: Option<Requestor>,
    pub current_reader: Option<Requestor>,
    pub acceptors_q: VecDeque<Requestor>,
    pub writers_q: VecDeque<Requestor>,
    pub readers_q: VecDeque<Requestor>,
}

pub(crate) struct Handle {
    socket: Mutex<Option<Socket>>,
    reference: O,
    /// The controlling process, `ctrlPid` of `ESockDescriptor`.
    owner: Mutex<Option<O>>,
    /// Per-socket state shared with the requestors, see [`State`]. Lock order:
    /// `socket` first, then `state`.
    state: Mutex<State>,
    counters: Mutex<Counters>,
    otp_options: Mutex<HashMap<i32, O>>,
    sendfile_fd: Mutex<Option<OwnedFd>>,
    domain: &'static str,
    kind: &'static str,
    protocol: i32,
    /// How the socket was created, `ctype` of the socket info: `normal` or `{fromfd, Fd}`.
    ctype: O,
}
#[derive(Default)]
struct Counters {
    read_tries: u64,
    read_pkg: u64,
    read_byte: u64,
    read_fails: u64,
    read_waits: u64,
    read_pkg_max: u64,
    write_tries: u64,
    write_pkg: u64,
    write_byte: u64,
    write_fails: u64,
    write_waits: u64,
    write_pkg_max: u64,
    acc_tries: u64,
    acc_success: u64,
    acc_fails: u64,
    acc_waits: u64,
}
impl Counters {
    fn term(&self) -> O {
        map(&[
            ("read_tries", O::Int(self.read_tries as i64)),
            ("read_pkg", O::Int(self.read_pkg as i64)),
            ("read_byte", O::Int(self.read_byte as i64)),
            ("read_fails", O::Int(self.read_fails as i64)),
            ("read_waits", O::Int(self.read_waits as i64)),
            ("read_pkg_max", O::Int(self.read_pkg_max as i64)),
            ("write_tries", O::Int(self.write_tries as i64)),
            ("write_pkg", O::Int(self.write_pkg as i64)),
            ("write_byte", O::Int(self.write_byte as i64)),
            ("write_fails", O::Int(self.write_fails as i64)),
            ("write_waits", O::Int(self.write_waits as i64)),
            ("write_pkg_max", O::Int(self.write_pkg_max as i64)),
            ("acc_tries", O::Int(self.acc_tries as i64)),
            ("acc_success", O::Int(self.acc_success as i64)),
            ("acc_fails", O::Int(self.acc_fails as i64)),
            ("acc_waits", O::Int(self.acc_waits as i64)),
        ])
    }
}
fn handle_id(value: &O) -> Result<u64, BifError> {
    match value {
        O::Ref {
            node,
            creation,
            ids,
        } if node == "nonode@nohost" && *creation == 0 && ids.len() == 3 && ids[0] == MAGIC => {
            Ok(u64::from(ids[1]) | (u64::from(ids[2]) << 32))
        }
        _ => Err(BifError::BADARG),
    }
}
fn handle(value: &O) -> Result<Arc<Handle>, BifError> {
    handles()
        .lock()
        .unwrap()
        .get(&handle_id(value)?)
        .cloned()
        .ok_or(BifError::BADARG)
}
const OTP_OPT_DEBUG: i32 = 1001;
const OTP_OPT_IOW: i32 = 1002;
const OTP_OPT_CTRL_PROC: i32 = 1003;
const OTP_OPT_RCVBUF: i32 = 1004;
const OTP_OPT_RCVCTRLBUF: i32 = 1006;
const OTP_OPT_SNDCTRLBUF: i32 = 1007;
const OTP_OPT_FD: i32 = 1008;
const OTP_OPT_META: i32 = 1009;
const OTP_OPT_USE_REGISTRY: i32 = 1010;
const OTP_OPT_SELECT_READ: i32 = 1011;
const OTP_OPT_DOMAIN: i32 = 1999;
const RECV_BUFFER_SIZE_DEFAULT: i64 = 8 * 1024;
const RECV_CTRL_BUFFER_SIZE_DEFAULT: i64 = 1024;
const SEND_CTRL_BUFFER_SIZE_DEFAULT: i64 = 1024;

/// The global socket counters of `ESockData`.
struct Totals {
    sockets: u64,
    dgrams: u64,
    streams: u64,
    seqpkgs: u64,
    dom_local: u64,
    dom_inet: u64,
    dom_inet6: u64,
    proto_ip: u64,
    proto_tcp: u64,
    proto_udp: u64,
    proto_sctp: u64,
}
impl Totals {
    const fn new() -> Self {
        Self {
            sockets: 0,
            dgrams: 0,
            streams: 0,
            seqpkgs: 0,
            dom_local: 0,
            dom_inet: 0,
            dom_inet6: 0,
            proto_ip: 0,
            proto_tcp: 0,
            proto_udp: 0,
            proto_sctp: 0,
        }
    }
    /// `esock_inc_socket` and `esock_dec_socket`: erts counts `local` sockets in the
    /// `inet6` domain counter, and so does this.
    fn update(&mut self, domain: &str, kind: &str, protocol: i32, add: bool) {
        let step = |counter: &mut u64| {
            *counter = if add {
                *counter + 1
            } else {
                counter.saturating_sub(1)
            }
        };
        step(&mut self.sockets);
        match domain {
            "inet" => step(&mut self.dom_inet),
            "inet6" | "local" => step(&mut self.dom_inet6),
            _ => {}
        }
        match kind {
            "stream" => step(&mut self.streams),
            "dgram" => step(&mut self.dgrams),
            "seqpacket" => step(&mut self.seqpkgs),
            _ => {}
        }
        match protocol {
            libc::IPPROTO_IP => step(&mut self.proto_ip),
            libc::IPPROTO_TCP => step(&mut self.proto_tcp),
            libc::IPPROTO_UDP => step(&mut self.proto_udp),
            _ => {}
        }
    }
}
fn totals() -> std::sync::MutexGuard<'static, Totals> {
    TOTALS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}
/// `esock_alloc_descriptor` plus the bookkeeping `essio_open4` and
/// `essio_accept_accepted` do for a new descriptor: the controlling process is
/// monitored, the global counters count it and the registry hears about it.
fn reference(
    socket: Socket,
    domain: &'static str,
    kind: &'static str,
    protocol: i32,
    owner: Option<O>,
    options: HashMap<i32, O>,
    ctype: O,
) -> O {
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let reference = O::Ref {
        node: "nonode@nohost".into(),
        creation: 0,
        ids: vec![MAGIC, id as u32, (id >> 32) as u32],
    };
    let h = Arc::new(Handle {
        socket: Mutex::new(Some(socket)),
        reference: reference.clone(),
        owner: Mutex::new(owner.clone()),
        state: Mutex::new(State::default()),
        counters: Mutex::new(Counters::default()),
        otp_options: Mutex::new(options),
        sendfile_fd: Mutex::new(None),
        domain,
        kind,
        protocol,
        ctype,
    });
    handles().lock().unwrap().insert(id, Arc::clone(&h));
    if let Some(pid) = owner.as_ref() {
        let mon = monitor_process(&h, pid);
        h.state.lock().unwrap().ctrl_mon = mon;
    }
    totals().update(domain, kind, protocol, true);
    if use_reg(&h) {
        send_reg_msg("add", &h);
    }
    reference
}
/// `esock_get_bool_from_map`.
fn bool_from_map(map: &O, key: &str, default: bool) -> bool {
    match field(map, key).and_then(name) {
        Some("true") => true,
        Some("false") => false,
        _ => default,
    }
}
/// The `debug` and `use_registry` defaults a new descriptor takes from the open options
/// and the global settings.
fn initial_options(opts: Option<&O>) -> HashMap<i32, O> {
    let mut options = HashMap::new();
    let debug = SOCKET_DEBUG.load(Ordering::Relaxed);
    let registry = USE_REGISTRY.load(Ordering::Relaxed);
    let (debug, registry) = match opts {
        Some(opts) => (
            bool_from_map(opts, "debug", debug),
            bool_from_map(opts, "use_registry", registry),
        ),
        None => (debug, registry),
    };
    options.insert(OTP_OPT_DEBUG, bool_atom(debug));
    options.insert(OTP_OPT_USE_REGISTRY, bool_atom(registry));
    options
}
/// `descP->useReg`.
fn use_reg(h: &Handle) -> bool {
    h.otp_options.lock().unwrap().get(&OTP_OPT_USE_REGISTRY) == Some(&atom("true"))
}
/// `esock_send_reg_add_msg` and `esock_send_reg_del_msg`: `{'$socket', add | del, Socket}`.
fn send_reg_msg(tag: &str, h: &Handle) {
    let Some(registry) = REGISTRY_PID.lock().unwrap().clone() else {
        return;
    };
    if let Some(reactor) = active_reactor() {
        let message = O::tuple(vec![
            atom("$socket"),
            atom(tag),
            pair(atom("$socket"), h.reference.clone()),
        ]);
        reactor.send(&registry, &message);
    }
}
/// The part of the `load_nif` info map that the socket NIF reads on load: the registry
/// process and the global defaults.
pub(super) fn load_info(info: &O) {
    if let Some(pid @ O::Pid { .. }) = field(info, "registry") {
        *REGISTRY_PID.lock().unwrap() = Some(pid.clone());
    }
    USE_REGISTRY.store(
        bool_from_map(info, "use_registry", USE_REGISTRY.load(Ordering::Relaxed)),
        Ordering::Relaxed,
    );
    DEBUG.store(bool_from_map(info, "debug", false), Ordering::Relaxed);
    SOCKET_DEBUG.store(
        bool_from_map(info, "socket_debug", false),
        Ordering::Relaxed,
    );
}
pub(super) fn set_owner(value: &O, pid: O) -> Result<(), BifError> {
    if !matches!(pid, O::Pid { .. }) {
        return Err(BifError::BADARG);
    }
    let h = handle(value)?;
    let previous = h.owner.lock().unwrap().replace(pid.clone());
    let mut st = h.state.lock().unwrap();
    if previous.as_ref() != Some(&pid) {
        demonitor_process(st.ctrl_mon.take());
        st.ctrl_mon = monitor_process(&h, &pid);
    }
    Ok(())
}
/// A controlling process has exited: its monitor fires for every socket it owns.
pub(super) fn owner_died(pid: &O) {
    let owned: Vec<Arc<Handle>> = handles()
        .lock()
        .unwrap()
        .values()
        .filter(|h| h.owner.lock().unwrap().as_ref() == Some(pid))
        .cloned()
        .collect();
    for h in owned {
        let monitor = *h.state.lock().unwrap().ctrl_mon.get_or_insert(u64::MAX);
        lifecycle::down(&h.reference, pid, monitor);
    }
}
/// The resource destructor: the VM dropped its last reference to the socket.
pub(super) fn release(value: &O) -> Result<(), BifError> {
    let id = handle_id(value)?;
    let removed = handles().lock().unwrap().remove(&id);
    if let Some(h) = removed {
        lifecycle::dtor(&h);
    }
    Ok(())
}
pub(super) use lifecycle::{down, stop};
fn active_reactor() -> Option<Arc<dyn Reactor>> {
    reactor().lock().unwrap().clone()
}
/// The process making the NIF call, `enif_self`.
pub(crate) fn self_pid() -> Option<O> {
    active_reactor().and_then(|reactor| reactor.self_pid())
}
fn select_failed() -> i32 {
    i32::MIN | crate::SELECT_FAILED
}
/// `esock_select_read`: with `pid` `None` the select message goes to the calling
/// process, not to the controlling process.
pub(crate) fn select_read(h: &Handle, fd: i32, pid: Option<&O>, reference: &O) -> i32 {
    let Some(reactor) = active_reactor() else {
        return select_failed();
    };
    let Some(pid) = pid.cloned().or_else(|| reactor.self_pid()) else {
        return select_failed();
    };
    reactor.register_read(fd, &pid, &h.reference, reference)
}
/// `esock_select_write`; see [`select_read`].
pub(crate) fn select_write(h: &Handle, fd: i32, pid: Option<&O>, reference: &O) -> i32 {
    let Some(reactor) = active_reactor() else {
        return select_failed();
    };
    let Some(pid) = pid.cloned().or_else(|| reactor.self_pid()) else {
        return select_failed();
    };
    reactor.register_write(fd, &pid, &h.reference, reference)
}
/// `esock_select_stop`.
pub(crate) fn select_stop(fd: i32) -> i32 {
    active_reactor().map_or(crate::SELECT_STOP_CALLED, |reactor| reactor.stop(fd))
}
/// `esock_select_cancel`.
pub(crate) fn select_cancel(fd: i32, read: bool, reference: &O) -> i32 {
    active_reactor().map_or(0, |reactor| reactor.cancel(fd, read, reference))
}
/// `esock_cancel_mode_select`: `ok` when the select was cancelled, `select_sent`
/// when its message was already sent.
pub(crate) fn cancel_mode_select(fd: i32, read: bool, reference: &O) -> O {
    let cancelled = if read {
        crate::SELECT_READ_CANCELLED
    } else {
        crate::SELECT_WRITE_CANCELLED
    };
    let result = select_cancel(fd, read, reference);
    if result < 0 {
        atom("not_found")
    } else if result & cancelled != 0 {
        atom("ok")
    } else {
        atom("select_sent")
    }
}
/// `esock_cancel_read_select`.
pub(crate) fn cancel_read_select(fd: i32, reference: &O) -> O {
    cancel_mode_select(fd, true, reference)
}
/// `esock_cancel_write_select`.
pub(crate) fn cancel_write_select(fd: i32, reference: &O) -> O {
    cancel_mode_select(fd, false, reference)
}
/// The exception `{Tag, Sres}` raised when a select fails (`select_read`, `select_write`).
pub(crate) fn raise_select(tag: &str, sres: i32) -> BifError {
    crate::raise(pair(atom(tag), O::Int(sres.into())))
}
/// `esock_make_error_invalid`: `{error, {invalid, What}}`.
pub(crate) fn error_invalid(what: &str) -> O {
    pair(atom("error"), invalid(what))
}
/// `esock_raise_invalid`: raise `{invalid, What}`.
pub(crate) fn raise_invalid(what: &str) -> BifError {
    crate::raise(invalid(what))
}
/// `esock_send_abort_msg`: `{'$socket', Socket, abort, {Ref, Reason}}` to the requestor.
pub(crate) fn send_abort_msg(h: &Handle, req: &Requestor, reason: &O) {
    if let Some(reactor) = active_reactor() {
        let message = crate::abort_message(&h.reference, &req.reference, reason);
        reactor.send(&req.pid, &message);
    }
}
/// `esock_send_simple_abort_msg`: `{'$socket', Socket, abort, Reason}`.
#[allow(dead_code)]
pub(crate) fn send_simple_abort_msg(h: &Handle, pid: &O, reason: &O) {
    if let Some(reactor) = active_reactor() {
        let message = O::tuple(vec![
            atom("$socket"),
            pair(atom("$socket"), h.reference.clone()),
            atom("abort"),
            reason.clone(),
        ]);
        reactor.send(pid, &message);
    }
}
/// `MONP`: monitor `pid` for the socket.
pub(crate) fn monitor_process(h: &Handle, pid: &O) -> Option<u64> {
    active_reactor().and_then(|reactor| reactor.monitor(pid, &h.reference))
}
/// `DEMONP`.
pub(crate) fn demonitor_process(monitor: Option<u64>) {
    if let (Some(monitor), Some(reactor)) = (monitor, active_reactor()) {
        reactor.demonitor(monitor);
    }
}
impl State {
    fn queue(&mut self, kind: Kind) -> &mut VecDeque<Requestor> {
        match kind {
            Kind::Acceptor => &mut self.acceptors_q,
            Kind::Writer => &mut self.writers_q,
            Kind::Reader => &mut self.readers_q,
        }
    }
    fn current(&mut self, kind: Kind) -> &mut Option<Requestor> {
        match kind {
            Kind::Acceptor => &mut self.current_acceptor,
            Kind::Writer => &mut self.current_writer,
            Kind::Reader => &mut self.current_reader,
        }
    }
    /// `esock_{acceptor,writer,reader}_search4pid`.
    pub(crate) fn search4pid(&mut self, kind: Kind, pid: &O) -> bool {
        self.queue(kind).iter().any(|req| &req.pid == pid)
    }
    /// `esock_{acceptor,writer,reader}_push`.
    pub(crate) fn push(&mut self, h: &Handle, kind: Kind, pid: &O, reference: &O) {
        let mon = monitor_process(h, pid);
        self.queue(kind).push_back(Requestor {
            pid: pid.clone(),
            reference: reference.clone(),
            mon,
        });
    }
    /// `esock_requestor_pop`: the next requestor becomes the current one.
    pub(crate) fn pop(&mut self, kind: Kind) -> bool {
        let next = self.queue(kind).pop_front();
        let popped = next.is_some();
        *self.current(kind) = next;
        popped
    }
    /// `esock_{acceptor,writer,reader}_unqueue`: remove the element of `pid`, and when
    /// `reference` is given only if it matches.
    pub(crate) fn unqueue(&mut self, kind: Kind, reference: Option<&O>, pid: &O) -> bool {
        let queue = self.queue(kind);
        let Some(index) = queue.iter().position(|req| &req.pid == pid) else {
            return false;
        };
        if reference.is_some_and(|reference| reference != &queue[index].reference) {
            return false;
        }
        let removed = queue.remove(index);
        demonitor_process(removed.and_then(|req| req.mon));
        true
    }
}
/// `esock_requestor_release`.
pub(crate) fn requestor_release(requestor: &mut Option<Requestor>) {
    if let Some(req) = requestor.take() {
        demonitor_process(req.mon);
    }
}
/// `esock_activate_next_{acceptor,writer,reader}`: pop the queue and select for the
/// next requestor with its own pid. A failed select aborts that requestor with
/// `{select_failed, Sres}` and the next one is tried.
pub(crate) fn activate_next(h: &Handle, st: &mut State, fd: i32, kind: Kind) -> bool {
    loop {
        if !st.pop(kind) {
            return false;
        }
        let Some(req) = st.current(kind).clone() else {
            return false;
        };
        let sres = match kind {
            Kind::Acceptor | Kind::Reader => select_read(h, fd, Some(&req.pid), &req.reference),
            Kind::Writer => select_write(h, fd, Some(&req.pid), &req.reference),
        };
        if sres < 0 {
            let reason = pair(atom("select_failed"), O::Int(sres.into()));
            send_abort_msg(h, &req, &reason);
            demonitor_process(req.mon);
            *st.current(kind) = None;
        } else {
            match kind {
                Kind::Writer => st.write_state |= state_bits::SELECTED,
                _ => st.read_state |= state_bits::SELECTED,
            }
            return true;
        }
    }
}
/// A select that registers for the calling process and ignores failures.
/// Superseded by [`select_read`] and [`select_write`] (and the request queues)
/// in the send and receive paths.
fn selected(h: &Handle, fd: i32, reference: &O, read: bool) -> O {
    if read {
        select_read(h, fd, None, reference);
    } else {
        select_write(h, fd, None, reference);
    }
    atom("select")
}
fn fail(err: &io::Error) -> O {
    errno(err.raw_os_error().unwrap_or(libc::EINVAL))
}
fn io_result(result: io::Result<()>) -> O {
    match result {
        Ok(()) => atom("ok"),
        Err(e) => fail(&e),
    }
}
fn invalid(what: &str) -> O {
    pair(atom("invalid"), atom(what))
}
fn integer(value: &O) -> Result<i32, BifError> {
    number(value)
        .and_then(|n| i32::try_from(n).ok())
        .ok_or(BifError::BADARG)
}
fn u16_value(value: &O) -> Option<u16> {
    number(value).and_then(|n| u16::try_from(n).ok())
}
fn tuple_ip(value: &O) -> Option<IpAddr> {
    let O::Tuple(parts) = value else { return None };
    match parts.as_slice() {
        [a, b, c, d] => Some(IpAddr::V4(Ipv4Addr::new(
            u8::try_from(number(a)?).ok()?,
            u8::try_from(number(b)?).ok()?,
            u8::try_from(number(c)?).ok()?,
            u8::try_from(number(d)?).ok()?,
        ))),
        [a, b, c, d, e, f, g, h] => Some(IpAddr::V6(Ipv6Addr::new(
            u16_value(a)?,
            u16_value(b)?,
            u16_value(c)?,
            u16_value(d)?,
            u16_value(e)?,
            u16_value(f)?,
            u16_value(g)?,
            u16_value(h)?,
        ))),
        _ => None,
    }
}
pub(super) fn to_addr(value: &O) -> Option<SocketAddr> {
    // Port of erts/emulator/nifs/common/socket_util.c:484 (esock_decode_sockaddr), OTP-29.1.1.
    let family = name(field(value, "family")?)?;
    let unspecified = || match family {
        "inet" => Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
        "inet6" => Some(IpAddr::V6(Ipv6Addr::UNSPECIFIED)),
        _ => None,
    };
    let addr = match field(value, "addr") {
        None => unspecified()?,
        Some(O::Atom(s)) if s == "any" => unspecified()?,
        Some(O::Atom(s)) if s == "loopback" => match family {
            "inet" => IpAddr::V4(Ipv4Addr::LOCALHOST),
            "inet6" => IpAddr::V6(Ipv6Addr::LOCALHOST),
            _ => return None,
        },
        Some(O::Atom(s)) if s == "broadcast" && family == "inet" => IpAddr::V4(Ipv4Addr::BROADCAST),
        Some(value) => tuple_ip(value)?,
    };
    let port = match field(value, "port") {
        Some(value) => u16_value(value)?,
        None => 0,
    };
    match (family, addr) {
        ("inet", IpAddr::V4(ip)) => Some(SocketAddr::new(ip.into(), port)),
        ("inet6", IpAddr::V6(ip)) => Some(SocketAddr::V6(SocketAddrV6::new(
            ip,
            port,
            match field(value, "flowinfo") {
                Some(v) => u32::try_from(number(v)?).ok()?,
                None => 0,
            },
            match field(value, "scope_id") {
                Some(v) => u32::try_from(number(v)?).ok()?,
                None => 0,
            },
        ))),
        _ => None,
    }
}
pub(super) fn from_addr(addr: SocketAddr) -> O {
    match addr {
        SocketAddr::V4(a) => map(&[
            ("family", atom("inet")),
            (
                "addr",
                O::tuple(a.ip().octets().map(|x| O::Int(x.into())).into()),
            ),
            ("port", O::Int(a.port().into())),
        ]),
        SocketAddr::V6(a) => map(&[
            ("family", atom("inet6")),
            (
                "addr",
                O::tuple(a.ip().segments().map(|x| O::Int(x.into())).into()),
            ),
            ("port", O::Int(a.port().into())),
            ("flowinfo", O::Int(a.flowinfo().into())),
            ("scope_id", O::Int(a.scope_id().into())),
        ]),
    }
}
fn to_sock_addr(value: &O) -> Option<SockAddr> {
    if name(field(value, "family")?) == Some("local") {
        let O::Binary(bytes) = field(value, "path")? else {
            return None;
        };
        SockAddr::unix(std::path::Path::new(std::ffi::OsStr::from_bytes(bytes))).ok()
    } else {
        to_addr(value).map(SockAddr::from)
    }
}
fn from_sock_addr(value: &SockAddr) -> Option<O> {
    value.as_socket().map(from_addr).or_else(|| {
        value.as_pathname().map(|path| {
            map(&[
                ("family", atom("local")),
                ("path", O::Binary(path.as_os_str().as_bytes().to_vec())),
            ])
        })
    })
}

fn open(args: &[O]) -> Result<O, BifError> {
    // Port of erts/emulator/nifs/common/prim_socket_nif.c:5733 (nif_open), OTP-29.1.1.
    let owner = self_pid();
    let (domain, kind, protocol) = if args.len() == 4 {
        let domain = match name(&args[0]) {
            Some("inet") => Domain::IPV4,
            Some("inet6") => Domain::IPV6,
            Some("local") => Domain::UNIX,
            _ => return Ok(invalid("domain")),
        };
        let kind = match name(&args[1]) {
            Some("stream") => Type::STREAM,
            Some("dgram") => Type::DGRAM,
            Some("seqpacket") => Type::SEQPACKET,
            Some("raw") => Type::RAW,
            _ => return Ok(invalid("type")),
        };
        let protocol = integer(&args[2])?;
        if !matches!(args[3], O::Map(_)) {
            return Err(BifError::BADARG);
        }
        (domain, kind, protocol)
    } else {
        let fd = integer(&args[0])?;
        if fd < 0 {
            return Ok(error("ebadf"));
        }
        // SAFETY: dup creates a fresh descriptor; mark it close-on-exec before
        // transferring ownership to the Socket.
        let copied = unsafe {
            let copied = libc::dup(fd);
            if copied >= 0 && libc::fcntl(copied, libc::F_SETFD, libc::FD_CLOEXEC) < 0 {
                let error = io::Error::last_os_error();
                libc::close(copied);
                return Ok(fail(&error));
            }
            copied
        };
        if copied < 0 {
            return Ok(last_error());
        }
        // SAFETY: copied is a valid, uniquely owned descriptor from dup.
        let socket = unsafe { Socket::from_raw_fd(copied) };
        if let Err(e) = socket.set_nonblocking(true) {
            return Ok(fail(&e));
        }
        let domain = match socket.local_addr().map(|addr| i32::from(addr.family())) {
            Ok(libc::AF_INET6) => "inet6",
            Ok(libc::AF_UNIX) => "local",
            _ => "inet",
        };
        let kind = match socket.r#type() {
            Ok(t) if t == Type::DGRAM => "dgram",
            Ok(t) if t == Type::RAW => "raw",
            Ok(t) if t == Type::SEQPACKET => "seqpacket",
            _ => "stream",
        };
        let protocol = field(&args[1], "protocol")
            .and_then(number)
            .and_then(|n| i32::try_from(n).ok())
            .unwrap_or(match (domain, kind) {
                ("inet" | "inet6", "stream") => libc::IPPROTO_TCP,
                ("inet" | "inet6", "dgram") => libc::IPPROTO_UDP,
                _ => 0,
            });
        return Ok(ok(reference(
            socket,
            domain,
            kind,
            protocol,
            owner,
            initial_options(Some(&args[1])),
            pair(atom("fromfd"), O::Int(fd.into())),
        )));
    };
    let proto = (protocol != 0).then_some(Protocol::from(protocol));
    match Socket::new(domain, kind, proto) {
        Ok(socket) => {
            if let Err(e) = socket.set_nonblocking(true) {
                return Ok(fail(&e));
            }
            let d = if domain == Domain::IPV4 {
                "inet"
            } else if domain == Domain::IPV6 {
                "inet6"
            } else {
                "local"
            };
            let k = if kind == Type::STREAM {
                "stream"
            } else if kind == Type::DGRAM {
                "dgram"
            } else if kind == Type::SEQPACKET {
                "seqpacket"
            } else {
                "raw"
            };
            Ok(ok(reference(
                socket,
                d,
                k,
                protocol,
                owner,
                initial_options(Some(&args[3])),
                atom("normal"),
            )))
        }
        Err(e) => Ok(fail(&e)),
    }
}

fn bind(args: &[O]) -> Result<O, BifError> {
    if args.len() == 3 {
        return Err(crate::notsup());
    }
    let h = handle(&args[0])?;
    let Some(addr) = to_sock_addr(&args[1]) else {
        return Ok(invalid("sockaddr"));
    };
    let guard = h.socket.lock().unwrap();
    let mut st = h.state.lock().unwrap();
    Ok(match guard.as_ref() {
        Some(s) => {
            let result = io_result(s.bind(&addr));
            if result == atom("ok") {
                st.read_state |= state_bits::BOUND;
            }
            result
        }
        None => error("closed"),
    })
}
fn connect(args: &[O]) -> Result<O, BifError> {
    let h = handle(&args[0])?;
    let guard = h.socket.lock().unwrap();
    let target = if args.len() == 3 {
        if !matches!(args[1], O::Ref { .. }) {
            return Err(BifError::BADARG);
        }
        Some(to_sock_addr(&args[2]))
    } else {
        None
    };
    let mut st = h.state.lock().unwrap();
    let Some(s) = guard
        .as_ref()
        .filter(|_| state_bits::is_open(st.write_state))
    else {
        return Ok(error("closed"));
    };
    let Some(me) = self_pid() else {
        return Err(BifError::BADARG);
    };
    if st.current_writer.is_some() {
        return Ok(error_invalid("state"));
    }
    if let Some(connector) = st.connector.as_ref() {
        if connector.pid != me {
            return if target.is_some() {
                Ok(error("already"))
            } else {
                Err(raise_invalid("state"))
            };
        }
        requestor_release(&mut st.connector);
        st.write_state &= !state_bits::CONNECTING;
        let result = verify_is_connected(s);
        if result == atom("ok") {
            st.write_state |= state_bits::CONNECTED;
        }
        return Ok(result);
    }
    let Some(target) = target else {
        return Err(raise_invalid("state"));
    };
    let Some(addr) = target else {
        return Ok(invalid("sockaddr"));
    };
    match s.connect(&addr) {
        Ok(()) => {
            st.write_state |= state_bits::CONNECTED;
            Ok(atom("ok"))
        }
        Err(e) if e.raw_os_error() == Some(libc::EINPROGRESS) => {
            let sres = select_write(&h, s.as_raw_fd(), None, &args[1]);
            if sres < 0 {
                return Err(raise_select("select_write", sres));
            }
            let mon = monitor_process(&h, &me);
            st.connector = Some(Requestor {
                pid: me,
                reference: args[1].clone(),
                mon,
            });
            st.write_state |= state_bits::CONNECTING | state_bits::SELECTED;
            Ok(atom("select"))
        }
        Err(e) => Ok(fail(&e)),
    }
}
fn verify_is_connected(s: &Socket) -> O {
    let mut code = 0i32;
    let mut len = std::mem::size_of_val(&code) as libc::socklen_t;
    // SAFETY: code and len point to initialized writable stack storage.
    let status = unsafe {
        libc::getsockopt(
            s.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_ERROR,
            (&mut code as *mut i32).cast(),
            &mut len,
        )
    };
    if status < 0 {
        last_error()
    } else if code == 0 {
        atom("ok")
    } else {
        errno(code)
    }
}
fn is_would_block(e: &io::Error) -> bool {
    e.raw_os_error() == Some(libc::EAGAIN)
}
fn listen(args: &[O]) -> Result<O, BifError> {
    let h = handle(&args[0])?;
    let backlog = match integer(&args[1]) {
        Ok(backlog) => backlog,
        Err(_) if number(&args[1]).is_some() => {
            return Ok(invalid_integer_range(number(&args[1]).unwrap_or_default()));
        }
        Err(error) => return Err(error),
    };
    let guard = h.socket.lock().unwrap();
    let mut st = h.state.lock().unwrap();
    let Some(s) = guard.as_ref() else {
        return Ok(error("closed"));
    };
    Ok(match s.listen(backlog) {
        Ok(()) => {
            st.read_state |= state_bits::LISTENING;
            atom("ok")
        }
        Err(e) => fail(&e),
    })
}
fn invalid_integer_range(value: i64) -> O {
    pair(atom("invalid"), pair(atom("integer_range"), O::Int(value)))
}
fn accept(args: &[O]) -> Result<O, BifError> {
    let h = handle(&args[0])?;
    let guard = h.socket.lock().unwrap();
    let mut st = h.state.lock().unwrap();
    let Some(s) = guard
        .as_ref()
        .filter(|_| state_bits::is_open(st.read_state))
    else {
        return Ok(error("closed"));
    };
    let Some(caller) = self_pid() else {
        return Err(BifError::BADARG);
    };
    if st.current_reader.is_some() {
        return Ok(error_invalid("state"));
    }
    match st.current_acceptor.clone() {
        None => {
            h.counters.lock().unwrap().acc_tries += 1;
            match s.accept() {
                Err(e) => accept_listening_error(&h, &mut st, s, &args[1], &caller, &e),
                Ok((socket, _)) => Ok(accepted(&h, socket, &caller)),
            }
        }
        Some(current) if current.pid == caller => {
            accept_accepting_current(&h, &mut st, s, &args[1])
        }
        Some(_) => {
            if st.search4pid(Kind::Acceptor, &caller) {
                Err(raise_invalid("state"))
            } else {
                st.push(&h, Kind::Acceptor, &caller, &args[1]);
                Ok(atom("select"))
            }
        }
    }
}
fn accept_listening_error(
    h: &Arc<Handle>,
    st: &mut State,
    s: &Socket,
    reference: &O,
    caller: &O,
    e: &io::Error,
) -> Result<O, BifError> {
    if !is_would_block(e) {
        h.counters.lock().unwrap().acc_fails += 1;
        return Ok(fail(e));
    }
    let mon = monitor_process(h, caller);
    st.current_acceptor = Some(Requestor {
        pid: caller.clone(),
        reference: reference.clone(),
        mon,
    });
    accept_busy_retry(h, st, s.as_raw_fd(), reference, None)
}
fn accept_busy_retry(
    h: &Arc<Handle>,
    st: &mut State,
    fd: i32,
    reference: &O,
    pid: Option<&O>,
) -> Result<O, BifError> {
    let sres = select_read(h, fd, pid, reference);
    if sres < 0 {
        if let Some(current) = st.current_acceptor.as_ref() {
            demonitor_process(current.mon);
        }
        if !activate_next(h, st, fd, Kind::Acceptor) {
            st.read_state &= !state_bits::ACCEPTING;
            st.current_acceptor = None;
        }
        return Err(raise_select("select_read", sres));
    }
    st.read_state |= state_bits::ACCEPTING | state_bits::SELECTED;
    Ok(atom("select"))
}
fn accept_accepting_current(
    h: &Arc<Handle>,
    st: &mut State,
    s: &Socket,
    reference: &O,
) -> Result<O, BifError> {
    let fd = s.as_raw_fd();
    h.counters.lock().unwrap().acc_tries += 1;
    match s.accept() {
        Ok((socket, _)) => {
            let Some(current) = st.current_acceptor.clone() else {
                return Err(BifError::BADARG);
            };
            let result = accepted(h, socket, &current.pid);
            demonitor_process(current.mon);
            if !activate_next(h, st, fd, Kind::Acceptor) {
                st.read_state &= !state_bits::ACCEPTING;
                st.current_acceptor = None;
            }
            Ok(result)
        }
        Err(e) if is_would_block(&e) => {
            h.counters.lock().unwrap().acc_waits += 1;
            let Some(current) = st.current_acceptor.clone() else {
                return Err(BifError::BADARG);
            };
            let result = cancel_read_select(fd, &current.reference);
            if result != atom("ok") {
                return Ok(result);
            }
            send_abort_msg(h, &current, &atom("cancelled"));
            if let Some(current) = st.current_acceptor.as_mut() {
                current.reference = reference.clone();
            }
            accept_busy_retry(h, st, fd, reference, Some(&current.pid))
        }
        Err(e) => {
            h.counters.lock().unwrap().acc_fails += 1;
            requestor_release(&mut st.current_acceptor);
            let result = fail(&e);
            let reason = errno_reason(&e);
            while st.pop(Kind::Acceptor) {
                if let Some(request) = st.current_acceptor.take() {
                    send_abort_msg(h, &request, &reason);
                    demonitor_process(request.mon);
                }
            }
            st.current_acceptor = None;
            Ok(result)
        }
    }
}
fn errno_reason(err: &io::Error) -> O {
    match &fail(err) {
        O::Tuple(parts) if parts.len() == 2 => parts[1].clone(),
        other => other.clone(),
    }
}
fn accepted(h: &Arc<Handle>, socket: Socket, pid: &O) -> O {
    h.counters.lock().unwrap().acc_success += 1;
    if let Err(e) = socket.set_nonblocking(true) {
        return fail(&e);
    }
    let inherited = h
        .otp_options
        .lock()
        .unwrap()
        .iter()
        .filter(|(opt, _)| {
            matches!(
                **opt,
                OTP_OPT_RCVBUF
                    | OTP_OPT_RCVCTRLBUF
                    | OTP_OPT_SNDCTRLBUF
                    | OTP_OPT_IOW
                    | OTP_OPT_DEBUG
                    | OTP_OPT_USE_REGISTRY
            )
        })
        .map(|(opt, value)| (*opt, value.clone()))
        .collect();
    let accepted = reference(
        socket,
        h.domain,
        h.kind,
        h.protocol,
        Some(pid.clone()),
        inherited,
        atom("normal"),
    );
    if let Ok(new) = handle(&accepted) {
        new.state.lock().unwrap().write_state |= state_bits::CONNECTED;
    }
    ok(accepted)
}
fn send(args: &[O], destination: Option<&O>) -> Result<O, BifError> {
    // Port of erts/emulator/nifs/common/prim_socket_nif.c:6440 (nif_send), OTP-29.1.1.
    let h = handle(&args[0])?;
    let O::Binary(data) = &args[1] else {
        return Err(BifError::BADARG);
    };
    let (flags, reference) = if destination.is_some() {
        (integer(&args[3])?, &args[4])
    } else {
        (integer(&args[2])?, &args[3])
    };
    let guard = h.socket.lock().unwrap();
    let Some(s) = guard.as_ref() else {
        return Ok(error("closed"));
    };
    h.counters.lock().unwrap().write_tries += 1;
    let written = if let Some(address) = destination {
        let Some(sock_addr) = to_sock_addr(address) else {
            return Ok(invalid("sockaddr"));
        };
        // SAFETY: sock_addr and data are live for the call; lengths match their buffers.
        unsafe {
            libc::sendto(
                s.as_raw_fd(),
                data.as_ptr().cast(),
                data.len(),
                flags,
                sock_addr.as_ptr().cast(),
                sock_addr.len(),
            )
        }
    } else {
        // SAFETY: data is live for the duration of send and its length is correct.
        unsafe { libc::send(s.as_raw_fd(), data.as_ptr().cast(), data.len(), flags) }
    };
    Ok(if written < 0 {
        let e = io::Error::last_os_error();
        if e.kind() == io::ErrorKind::WouldBlock {
            h.counters.lock().unwrap().write_waits += 1;
            selected(&h, s.as_raw_fd(), reference, false)
        } else {
            h.counters.lock().unwrap().write_fails += 1;
            fail(&e)
        }
    } else {
        let mut counters = h.counters.lock().unwrap();
        counters.write_pkg += 1;
        counters.write_byte += written as u64;
        counters.write_pkg_max = counters.write_pkg_max.max(written as u64);
        if written as usize == data.len() {
            atom("ok")
        } else {
            ok(O::Int(written as i64))
        }
    })
}
fn vectors(value: &O) -> Option<Vec<libc::iovec>> {
    let items = list(value)?;
    items
        .iter()
        .take(1024)
        .map(|item| {
            let O::Binary(data) = item else { return None };
            Some(libc::iovec {
                iov_base: data.as_ptr().cast_mut().cast(),
                iov_len: data.len(),
            })
        })
        .collect()
}
fn send_vectors(args: &[O], message: bool) -> Result<O, BifError> {
    let h = handle(&args[0])?;
    let value = if message { &args[4] } else { &args[1] };
    let Some(mut iov) = vectors(value) else {
        return Ok(invalid("iov"));
    };
    let reference = if message { &args[3] } else { &args[2] };
    let mut address = None;
    let mut flags = 0;
    if message {
        flags = integer(&args[2])?;
        if let Some(addr) = field(&args[1], "addr") {
            let Some(a) = to_sock_addr(addr) else {
                return Ok(invalid("addr"));
            };
            address = Some(a);
        }
        if let Some(ctrl) = field(&args[1], "ctrl")
            && !list(ctrl).is_some_and(|c| c.is_empty())
        {
            return Err(BifError::Unsupported("ancillary send control messages"));
        }
    }
    let guard = h.socket.lock().unwrap();
    let Some(s) = guard.as_ref() else {
        return Ok(error("closed"));
    };
    h.counters.lock().unwrap().write_tries += 1;
    // SAFETY: zeroed msghdr is valid once its pointer and length fields are set.
    let mut header: libc::msghdr = unsafe { std::mem::zeroed() };
    header.msg_iov = iov.as_mut_ptr();
    header.msg_iovlen = iov.len() as _;
    if let Some(addr) = address.as_ref() {
        header.msg_name = addr.as_ptr().cast_mut().cast();
        header.msg_namelen = addr.len();
    }
    // SAFETY: iov points into live binary terms and address, if any, stays live through sendmsg.
    let written = unsafe { libc::sendmsg(s.as_raw_fd(), &header, flags) };
    Ok(if written < 0 {
        let e = io::Error::last_os_error();
        if e.kind() == io::ErrorKind::WouldBlock {
            h.counters.lock().unwrap().write_waits += 1;
            selected(&h, s.as_raw_fd(), reference, false)
        } else {
            h.counters.lock().unwrap().write_fails += 1;
            fail(&e)
        }
    } else {
        let mut counters = h.counters.lock().unwrap();
        counters.write_pkg += 1;
        counters.write_byte += written as u64;
        counters.write_pkg_max = counters.write_pkg_max.max(written as u64);
        let covered: usize = iov.iter().map(|i| i.iov_len).sum();
        if (written as usize) < covered {
            ok(O::Int(written as i64))
        } else if list(value).is_some_and(|v| v.len() > iov.len()) {
            pair(atom("iov"), O::Int(written as i64))
        } else {
            atom("ok")
        }
    })
}
#[cfg(target_os = "macos")]
fn sendfile_once(file: i32, socket: i32, offset: i64, count: usize) -> (i32, usize) {
    let mut sent = count as libc::off_t;
    // Port of erts/emulator/nifs/unix/unix_socket_syncio.c:9210 (essio_sendfile), OTP-29.1.1.
    // SAFETY: both fds are owned during the call and sent is a writable output count.
    let status = unsafe {
        libc::sendfile(
            file,
            socket,
            offset as libc::off_t,
            &mut sent,
            std::ptr::null_mut(),
            0,
        )
    };
    (status, sent.max(0) as usize)
}
#[cfg(target_os = "linux")]
fn sendfile_once(file: i32, socket: i32, offset: i64, count: usize) -> (i32, usize) {
    let mut offset = offset as libc::off_t;
    // Port of erts/emulator/nifs/unix/unix_socket_syncio.c:9186 (essio_sendfile), OTP-29.1.1.
    // SAFETY: both fds are owned during the call and offset is writable.
    let sent = unsafe { libc::sendfile(socket, file, &mut offset, count) };
    (if sent < 0 { -1 } else { 0 }, sent.max(0) as usize)
}
fn sendfile(args: &[O]) -> Result<O, BifError> {
    let h = handle(&args[0])?;
    if args.len() == 1 {
        return Ok(if h.sendfile_fd.lock().unwrap().take().is_some() {
            atom("ok")
        } else {
            pair(atom("error"), pair(atom("invalid"), atom("state")))
        });
    }
    let reference = &args[1];
    if !matches!(reference, O::Ref { .. }) {
        return Err(BifError::BADARG);
    }
    let offset = number(&args[2]).ok_or(BifError::BADARG)?;
    let requested = number(&args[3])
        .and_then(|n| usize::try_from(n).ok())
        .ok_or(BifError::BADARG)?;
    let socket_guard = h.socket.lock().unwrap();
    let Some(socket) = socket_guard.as_ref() else {
        return Ok(error("closed"));
    };
    let mut file_guard = h.sendfile_fd.lock().unwrap();
    if args.len() == 5 {
        if file_guard.is_some() {
            return Ok(pair(atom("error"), pair(atom("invalid"), atom("state"))));
        }
        let fd = integer(&args[4])?;
        // SAFETY: dup creates a fresh descriptor; mark it close-on-exec before
        // storing it on the socket handle.
        let owned = unsafe {
            let owned = libc::dup(fd);
            if owned >= 0 && libc::fcntl(owned, libc::F_SETFD, libc::FD_CLOEXEC) < 0 {
                let error = io::Error::last_os_error();
                libc::close(owned);
                return Ok(fail(&error));
            }
            owned
        };
        if owned < 0 {
            return Ok(last_error());
        }
        // SAFETY: owned is a unique descriptor returned by dup.
        *file_guard = Some(unsafe { OwnedFd::from_raw_fd(owned) });
    }
    let Some(file) = file_guard.as_ref() else {
        return Ok(pair(atom("error"), pair(atom("invalid"), atom("state"))));
    };
    let file_fd = file.as_raw_fd();
    let mut total = 0usize;
    for _ in 0..4 {
        let remaining = if requested == 0 {
            512 * 1024
        } else {
            requested.saturating_sub(total).min(512 * 1024)
        };
        if remaining == 0 {
            break;
        }
        let (status, sent) = sendfile_once(
            file_fd,
            socket.as_raw_fd(),
            offset + total as i64,
            remaining,
        );
        total += sent;
        if status < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::WouldBlock {
                h.counters.lock().unwrap().write_waits += 1;
                selected(&h, socket.as_raw_fd(), reference, false);
                return Ok(pair(atom("select"), O::Int(total as i64)));
            }
            file_guard.take();
            return Ok(fail(&err));
        }
        if sent == 0 || (requested > 0 && total >= requested) {
            file_guard.take();
            return Ok(ok(O::Int(total as i64)));
        }
    }
    selected(&h, socket.as_raw_fd(), reference, false);
    Ok(pair(atom("select"), O::Int(total as i64)))
}
/// `recv_check_entry`: a reader that is not the current reader waits its turn.
fn recv_check_entry(h: &Arc<Handle>, reference: &O, caller: &O) -> Option<Result<O, BifError>> {
    let mut st = h.state.lock().unwrap();
    if !state_bits::is_open(st.read_state) {
        return Some(Ok(error("closed")));
    }
    if st.current_acceptor.is_some() {
        return Some(Ok(error_invalid("state")));
    }
    if st
        .current_reader
        .as_ref()
        .is_some_and(|req| &req.pid != caller)
    {
        return Some(if st.search4pid(Kind::Reader, caller) {
            Err(raise_invalid("state"))
        } else if name(reference) == Some("zero") {
            Ok(atom("timeout"))
        } else {
            st.push(h, Kind::Reader, caller, reference);
            Ok(atom("select"))
        });
    }
    None
}
/// `recv_check_select`: select for more data and make the caller the current reader.
fn recv_select(h: &Arc<Handle>, fd: i32, reference: &O, caller: &O) -> Result<O, BifError> {
    let mut st = h.state.lock().unwrap();
    let sres = select_read(h, fd, None, reference);
    if sres < 0 {
        recv_update_current_reader_locked(h, &mut st, fd);
        return Err(raise_select("select_read", sres));
    }
    match st.current_reader.as_mut() {
        Some(current) => current.reference = reference.clone(),
        None => {
            let mon = monitor_process(h, caller);
            st.current_reader = Some(Requestor {
                pid: caller.clone(),
                reference: reference.clone(),
                mon,
            });
        }
    }
    st.read_state |= state_bits::SELECTED;
    Ok(atom("select"))
}
/// `recv_update_current_reader`: the current reader is done, the next one takes over.
fn recv_update_current_reader(h: &Arc<Handle>, fd: i32) {
    let mut st = h.state.lock().unwrap();
    recv_update_current_reader_locked(h, &mut st, fd);
}
fn recv_update_current_reader_locked(h: &Handle, st: &mut State, fd: i32) {
    if let Some(current) = st.current_reader.as_ref() {
        demonitor_process(current.mon);
        if !activate_next(h, st, fd, Kind::Reader) {
            st.current_reader = None;
        }
    }
}
/// `recv_error_current_reader`: the waiting readers are aborted with `reason`.
fn recv_error_current_reader(h: &Arc<Handle>, reason: &O) {
    let mut st = h.state.lock().unwrap();
    if st.current_reader.is_some() {
        requestor_release(&mut st.current_reader);
        while st.pop(Kind::Reader) {
            if let Some(request) = st.current_reader.take() {
                send_abort_msg(h, &request, reason);
                demonitor_process(request.mon);
            }
        }
        st.current_reader = None;
    }
}
fn recv(args: &[O], from: bool, msg: bool) -> Result<O, BifError> {
    // Port of erts/emulator/nifs/common/prim_socket_nif.c:7056 (nif_recv), OTP-29.1.1.
    let h = handle(&args[0])?;
    if msg && integer(&args[2])? > 0 {
        return Err(BifError::Unsupported("ancillary receive control messages"));
    }
    let requested = usize::try_from(integer(&args[1])?).map_err(|_| BifError::BADARG)?;
    let flags = integer(if msg { &args[3] } else { &args[2] })?;
    let reference = if msg { &args[4] } else { &args[3] };
    let mut data = vec![
        0u8;
        if requested == 0 {
            65536
        } else {
            requested.min(16 * 1024 * 1024)
        }
    ];
    let guard = h.socket.lock().unwrap();
    let Some(s) = guard.as_ref() else {
        return Ok(error("closed"));
    };
    let Some(caller) = self_pid() else {
        return Err(BifError::BADARG);
    };
    if let Some(early) = recv_check_entry(&h, reference, &caller) {
        return early;
    }
    h.counters.lock().unwrap().read_tries += 1;
    // SAFETY: zeroed storage is valid for a returned sockaddr, and size is initialized.
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    let mut returned_flags = 0;
    let received = if msg {
        let mut iov = libc::iovec {
            iov_base: data.as_mut_ptr().cast(),
            iov_len: data.len(),
        };
        // SAFETY: zeroed msghdr is valid after setting all buffers used by recvmsg.
        let mut header: libc::msghdr = unsafe { std::mem::zeroed() };
        header.msg_name = (&mut storage as *mut libc::sockaddr_storage).cast();
        header.msg_namelen = len;
        header.msg_iov = &mut iov;
        header.msg_iovlen = 1;
        // SAFETY: header points to writable data, iov, and address buffers with valid lengths.
        let value = unsafe { libc::recvmsg(s.as_raw_fd(), &mut header, flags) };
        len = header.msg_namelen;
        returned_flags = header.msg_flags;
        value
    } else {
        // SAFETY: data and storage are writable buffers with matching lengths.
        unsafe {
            libc::recvfrom(
                s.as_raw_fd(),
                data.as_mut_ptr().cast(),
                data.len(),
                flags,
                (&mut storage as *mut libc::sockaddr_storage).cast(),
                &mut len,
            )
        }
    };
    if received < 0 {
        let e = io::Error::last_os_error();
        if e.kind() == io::ErrorKind::WouldBlock {
            h.counters.lock().unwrap().read_waits += 1;
            return recv_select(&h, s.as_raw_fd(), reference, &caller);
        }
        h.counters.lock().unwrap().read_fails += 1;
        recv_error_current_reader(&h, &errno_reason(&e));
        return Ok(fail(&e));
    }
    if received == 0 && h.kind == "stream" && !from && !msg {
        recv_error_current_reader(&h, &atom("closed"));
    } else {
        recv_update_current_reader(&h, s.as_raw_fd());
    }
    {
        let mut counters = h.counters.lock().unwrap();
        counters.read_pkg += 1;
        counters.read_byte += received as u64;
        counters.read_pkg_max = counters.read_pkg_max.max(received as u64);
    }
    data.truncate(received as usize);
    let binary = O::Binary(data);
    let address = if len > 0 {
        sockaddr_storage_to_term(&storage)
    } else {
        None
    };
    Ok(if msg {
        let flags = [
            (libc::MSG_OOB, "oob"),
            (libc::MSG_PEEK, "peek"),
            (libc::MSG_DONTROUTE, "dontroute"),
            (libc::MSG_EOR, "eor"),
            (libc::MSG_TRUNC, "trunc"),
            (libc::MSG_CTRUNC, "ctrunc"),
        ]
        .into_iter()
        .filter(|(bit, _)| returned_flags & bit != 0)
        .map(|(_, name)| atom(name))
        .collect();
        let mut entries = vec![
            (atom("iov"), O::list(vec![binary])),
            (atom("ctrl"), O::Nil),
            (atom("flags"), O::list(flags)),
        ];
        if let Some(addr) = address {
            entries.push((atom("addr"), addr));
        }
        ok(O::Map(entries))
    } else if from {
        ok(pair(address.unwrap_or_else(|| atom("undefined")), binary))
    } else if received == 0 && h.kind == "stream" {
        error("closed")
    } else {
        ok(binary)
    })
}
fn sockaddr_storage_to_term(storage: &libc::sockaddr_storage) -> Option<O> {
    match i32::from(storage.ss_family) {
        libc::AF_INET => {
            // SAFETY: ss_family identifies sockaddr_in and storage has sufficient size.
            let a = unsafe { &*(storage as *const _ as *const libc::sockaddr_in) };
            Some(from_addr(SocketAddr::new(
                Ipv4Addr::from(a.sin_addr.s_addr.to_ne_bytes()).into(),
                u16::from_be(a.sin_port),
            )))
        }
        libc::AF_INET6 => {
            // SAFETY: ss_family identifies sockaddr_in6 and storage has sufficient size.
            let a = unsafe { &*(storage as *const _ as *const libc::sockaddr_in6) };
            Some(from_addr(SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::from(a.sin6_addr.s6_addr),
                u16::from_be(a.sin6_port),
                a.sin6_flowinfo,
                a.sin6_scope_id,
            ))))
        }
        libc::AF_UNIX => {
            // SAFETY: ss_family identifies sockaddr_un and storage has sufficient size.
            let a = unsafe { &*(storage as *const _ as *const libc::sockaddr_un) };
            let path: Vec<u8> = a
                .sun_path
                .iter()
                .map(|c| *c as u8)
                .take_while(|c| *c != 0)
                .collect();
            Some(map(&[("family", atom("local")), ("path", O::Binary(path))]))
        }
        _ => None,
    }
}
fn shutdown(args: &[O]) -> Result<O, BifError> {
    let h = handle(&args[0])?;
    let how = match name(&args[1]) {
        Some("read") => std::net::Shutdown::Read,
        Some("write") => std::net::Shutdown::Write,
        Some("read_write") => std::net::Shutdown::Both,
        _ => return Err(BifError::BADARG),
    };
    let guard = h.socket.lock().unwrap();
    Ok(match guard.as_ref() {
        Some(s) => io_result(s.shutdown(how)),
        None => error("closed"),
    })
}
fn ioctl(args: &[O]) -> Result<O, BifError> {
    let h = handle(&args[0])?;
    let request = number(&args[1])
        .and_then(|n| u64::try_from(n).ok())
        .ok_or(BifError::BADARG)?;
    let guard = h.socket.lock().unwrap();
    let Some(socket) = guard.as_ref() else {
        return Ok(error("closed"));
    };
    if args.len() == 2 && (request == libc::FIONREAD || request == ATMARK_REQUEST) {
        let mut value = 0i32;
        // SAFETY: value is writable and the ioctl request expects a pointer to an int.
        let status =
            unsafe { libc::ioctl(socket.as_raw_fd(), request as libc::c_ulong, &mut value) };
        return Ok(if status < 0 {
            last_error()
        } else if request == libc::FIONREAD {
            ok(O::Int(value.into()))
        } else {
            ok(bool_atom(value != 0))
        });
    }
    Err(BifError::Unsupported("interface ioctl request"))
}
/// The protocol database rows as `getprotoent(3)` yields them: name, number, aliases.
fn protocol_entries() -> Vec<(String, i64, Vec<String>)> {
    let Ok(text) = std::fs::read_to_string("/etc/protocols") else {
        return Vec::new();
    };
    text.lines()
        .filter_map(|line| {
            let line = line.split('#').next().unwrap_or("");
            let mut fields = line.split_whitespace();
            let name = fields.next()?;
            let number = fields.next()?.parse().ok()?;
            Some((name.to_owned(), number, fields.map(str::to_owned).collect()))
        })
        .collect()
}

// Port of erts/emulator/nifs/common/prim_socket_nif.c:5396 (esock_supports_protocols),
// OTP-29.1.1. Atoms are created in the C order (each entry's aliases, then its
// name) because their table indices are observable through map key order.
fn supports_protocols() -> O {
    let make_atom = |text: &str| {
        let _ = arinsal_term::global_atoms().intern(text);
        atom(text)
    };
    let mut protocols = Vec::new();
    for (name, number, aliases) in protocol_entries() {
        let mut names = Vec::new();
        for alias in &aliases {
            names.insert(0, make_atom(alias));
        }
        names.insert(0, make_atom(&name));
        protocols.insert(0, pair(O::list(names), O::Int(number)));
    }
    // Defaults prepended so that maps:from_list/2 keeps getprotoent's entries.
    let mut defaults = vec![
        ("ip", i64::from(libc::IPPROTO_IP)),
        ("ipv6", i64::from(libc::IPPROTO_IPV6)),
        ("tcp", i64::from(libc::IPPROTO_TCP)),
        ("udp", i64::from(libc::IPPROTO_UDP)),
        ("igmp", i64::from(libc::IPPROTO_IGMP)),
    ];
    if cfg!(target_os = "linux") {
        defaults.push(("mptcp", 262));
    }
    for (name, number) in defaults {
        protocols.insert(0, pair(O::list(vec![atom(name)]), O::Int(number)));
    }
    O::list(protocols)
}

fn supports(key: Option<&O>) -> O {
    // Snapshot of OTP 29.1.1's macOS NIF tables, captured via prim_socket:p_get/1.
    // These tables describe the OS ABI compiled into the reference runtime.
    let snapshot = arinsal_etf::decode(include_bytes!("../tests/fixtures/mac_otp29_supports.etf"))
        .expect("OTP support fixture");
    let O::Tuple(ref parts) = snapshot else {
        unreachable!()
    };
    if key.is_none() {
        return parts[0].clone();
    }
    let Some(tag) = key.and_then(name) else {
        return O::Nil;
    };
    if tag == "protocols" {
        return supports_protocols();
    }
    let Some((_, O::Map(entries))) = list(&parts[1]).and_then(|rows| {
        rows.iter().find_map(|row| {
            if let O::Tuple(pair) = row
                && pair.len() == 2
                && name(&pair[0]) == Some(tag)
            {
                Some((&pair[0], &pair[1]))
            } else {
                None
            }
        })
    }) else {
        return O::Nil;
    };
    match tag {
        "msg_flags" | "ioctl_requests" | "ioctl_flags" => O::list(
            entries
                .iter()
                .map(|(k, v)| pair(k.clone(), v.clone()))
                .collect(),
        ),
        "protocols" => O::list(
            entries
                .iter()
                .filter_map(|(k, v)| number(k).map(|n| pair(v.clone(), O::Int(n))))
                .collect(),
        ),
        "options" => {
            let mut groups: Vec<(O, O, Vec<O>)> = Vec::new();
            for (key, value) in entries {
                let O::Tuple(parts) = key else { continue };
                if parts.len() != 2 {
                    continue;
                }
                let level = parts[0].clone();
                let option = parts[1].clone();
                let (level_number, option) = if let O::Tuple(codes) = value {
                    if codes.len() != 2 {
                        continue;
                    }
                    (codes[0].clone(), pair(option, codes[1].clone()))
                } else {
                    (
                        match name(&level) {
                            Some("socket") => atom("socket"),
                            Some("ip") => O::Int(libc::IPPROTO_IP.into()),
                            Some("ipv6") => O::Int(libc::IPPROTO_IPV6.into()),
                            Some("tcp") => O::Int(libc::IPPROTO_TCP.into()),
                            Some("udp") => O::Int(libc::IPPROTO_UDP.into()),
                            _ => continue,
                        },
                        option,
                    )
                };
                if let Some((_, _, items)) = groups.iter_mut().find(|(l, _, _)| l == &level) {
                    items.push(option);
                } else {
                    groups.push((level, level_number, vec![option]));
                }
            }
            O::list(
                groups
                    .into_iter()
                    .map(|(level, number, items)| O::tuple(vec![level, number, O::list(items)]))
                    .collect(),
            )
        }
        _ => O::Nil,
    }
}
pub(super) fn dispatch(name: &str, args: &[O]) -> Result<O, BifError> {
    match (name, args.len()) {
        ("nif_open", 2 | 4) => open(args),
        ("nif_bind", 2 | 3) => bind(args),
        ("nif_connect", 1 | 3) => connect(args),
        ("nif_listen", 2) => listen(args),
        ("nif_accept", 2) => accept(args),
        ("nif_send", 4) => send(args, None),
        ("nif_sendto", 5) => send(args, Some(&args[2])),
        ("nif_sendmsg", 5) => send_vectors(args, true),
        ("nif_sendv", 3) => send_vectors(args, false),
        ("nif_recv", 4) => recv(args, false, false),
        ("nif_recvfrom", 4) => recv(args, true, false),
        ("nif_recvmsg", 5) => recv(args, false, true),
        ("nif_close", 1) => lifecycle::close(&args[0]),
        ("nif_finalize_close", 1) => lifecycle::finalize_close(&args[0]),
        ("nif_shutdown", 2) => shutdown(args),
        ("nif_setopt", 5) => options::option(args, true),
        ("nif_getopt", 3 | 5) => options::option(args, false),
        ("nif_sockname" | "nif_peername", 1) => {
            let h = handle(&args[0])?;
            let guard = h.socket.lock().unwrap();
            Ok(match guard.as_ref() {
                Some(s) => {
                    let result = if name == "nif_sockname" {
                        s.local_addr()
                    } else {
                        s.peer_addr()
                    };
                    match result {
                        Ok(a) => from_sock_addr(&a)
                            .map(ok)
                            .unwrap_or_else(|| error("eafnosupport")),
                        Err(e) => fail(&e),
                    }
                }
                None => error("closed"),
            })
        }
        ("nif_info", 1) => options::info(&args[0]),
        ("nif_cancel", 3) => lifecycle::cancel(args),
        ("nif_supports", 0) => Ok(supports(None)),
        ("nif_supports", 1) => Ok(supports(Some(&args[0]))),
        ("nif_info", 0) => Ok(options::global_info()),
        ("nif_command", 1) => options::command(&args[0]),
        (
            "nif_sendmmsg" | "nif_recvmmsg" | "nif_peeloff" | "nif_socknames" | "nif_peernames",
            _,
        ) => Err(crate::notsup()),
        ("nif_ioctl", 2..=4) => ioctl(args),
        ("nif_sendfile", 1 | 4 | 5) => sendfile(args),
        _ => Err(BifError::BADARG),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BlockingReactor, set_reactor};
    use arinsal_bifs::{Ctx, ProcessHeapHandle};
    use arinsal_term::{ProcessHeap, from_owned, to_owned};
    use std::os::fd::IntoRawFd;
    use std::process::Command;
    use std::time::Duration;

    use crate::TEST_REACTOR_LOCK as REACTOR_TEST_LOCK;

    fn test_ref(id: u32) -> O {
        O::Ref {
            node: "nonode@nohost".into(),
            creation: 0,
            ids: vec![id],
        }
    }

    fn caller_reactor() -> (std::sync::MutexGuard<'static, ()>, Arc<BlockingReactor>) {
        let lock = REACTOR_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let reactor = Arc::new(BlockingReactor::default());
        reactor.set_caller(O::Pid {
            node: "nonode@nohost".into(),
            id: 5,
            serial: 0,
            creation: 0,
        });
        set_reactor(Some(reactor.clone()));
        (lock, reactor)
    }

    fn result(value: O) -> O {
        let O::Tuple(parts) = &value else {
            panic!("expected tuple: {value:?}")
        };
        assert_eq!(parts[0], atom("ok"), "{value:?}");
        parts[1].clone()
    }
    fn invoke(op: &str, args: &[O]) -> O {
        dispatch(op, args).unwrap_or_else(|error| panic!("{op} {args:?}: {error:?}"))
    }
    fn invoke_bif(module: &str, op: &str, args: &[O]) -> O {
        let mut heap = ProcessHeap::with_words(2048);
        let mut alloc = ProcessHeapHandle(&mut heap);
        let terms = args
            .iter()
            .map(|arg| {
                from_owned(arg, &mut alloc)
                    .unwrap_or_else(|error| panic!("{op} arg {arg:?}: {error:?}"))
            })
            .collect::<Vec<_>>();
        let mut ctx = Ctx::new(&mut alloc);
        let entry = if module == "prim_file" {
            arinsal_nif_file::lookup(module, op, args.len() as u8)
        } else {
            crate::lookup(module, op, args.len() as u8)
        }
        .unwrap();
        to_owned(entry(&mut ctx, &terms).unwrap()).unwrap()
    }
    fn open_socket(domain: &str, kind: &str, protocol: i64) -> O {
        result(invoke(
            "nif_open",
            &[atom(domain), atom(kind), O::Int(protocol), O::Map(vec![])],
        ))
    }
    fn addr(family: &str, port: i64) -> O {
        map(&[
            ("family", atom(family)),
            (
                "addr",
                if family == "inet" {
                    O::tuple(vec![O::Int(127), O::Int(0), O::Int(0), O::Int(1)])
                } else {
                    O::tuple(vec![
                        O::Int(0),
                        O::Int(0),
                        O::Int(0),
                        O::Int(0),
                        O::Int(0),
                        O::Int(0),
                        O::Int(0),
                        O::Int(1),
                    ])
                },
            ),
            ("port", O::Int(port)),
        ])
    }
    fn io_round_trip(family: &str) {
        let listener = open_socket(family, "stream", 6);
        assert_eq!(
            invoke("nif_bind", &[listener.clone(), addr(family, 0)]),
            atom("ok")
        );
        assert_eq!(
            invoke("nif_listen", &[listener.clone(), O::Int(16)]),
            atom("ok")
        );
        let bound = result(invoke("nif_sockname", std::slice::from_ref(&listener)));
        let port = number(field(&bound, "port").unwrap()).unwrap();
        let client = open_socket(family, "stream", 6);
        let pid = O::Pid {
            node: "nonode@nohost".into(),
            id: 1,
            serial: 0,
            creation: 0,
        };
        set_owner(&client, pid.clone()).unwrap();
        let reactor = Arc::new(BlockingReactor::default());
        reactor.set_caller(pid.clone());
        set_reactor(Some(reactor.clone()));
        let select_ref = O::Ref {
            node: "nonode@nohost".into(),
            creation: 0,
            ids: vec![42],
        };
        let connected = invoke(
            "nif_connect",
            &[client.clone(), select_ref.clone(), addr(family, port)],
        );
        if connected == atom("select") {
            assert_eq!(
                reactor.wait(Duration::from_secs(2)),
                Some((pid, select_ref))
            );
            assert_eq!(
                invoke("nif_connect", std::slice::from_ref(&client)),
                atom("ok")
            );
        } else {
            assert_eq!(connected, atom("ok"));
        }
        let accepted = (0..100)
            .find_map(|_| {
                let value = invoke("nif_accept", &[listener.clone(), O::Int(1)]);
                if value == atom("select") {
                    std::thread::sleep(Duration::from_millis(1));
                    None
                } else {
                    Some(result(value))
                }
            })
            .expect("TCP connection was not accepted");
        assert_eq!(
            name(
                field(
                    &result(invoke("nif_peername", std::slice::from_ref(&accepted))),
                    "family"
                )
                .unwrap()
            ),
            Some(family)
        );
        let payload = vec![b'X'; 131072];
        assert_eq!(
            invoke(
                "nif_send",
                &[
                    client.clone(),
                    O::Binary(payload.clone()),
                    O::Int(0),
                    O::Int(2)
                ]
            ),
            atom("ok")
        );
        let peek = (0..100)
            .find_map(|_| {
                let value = invoke(
                    "nif_recv",
                    &[
                        accepted.clone(),
                        O::Int(4),
                        O::Int(libc::MSG_PEEK.into()),
                        O::Int(3),
                    ],
                );
                if value == atom("select") {
                    std::thread::sleep(Duration::from_millis(1));
                    None
                } else {
                    Some(result(value))
                }
            })
            .expect("TCP payload was not readable");
        assert_eq!(peek, O::Binary(vec![b'X'; 4]));
        let mut all = Vec::new();
        while all.len() < payload.len() {
            let got = invoke(
                "nif_recv",
                &[accepted.clone(), O::Int(0), O::Int(0), O::Int(4)],
            );
            if got == atom("select") {
                continue;
            }
            let value = result(got);
            let O::Binary(bytes) = &value else {
                panic!("expected binary")
            };
            all.extend_from_slice(bytes);
        }
        assert_eq!(all, payload);
        assert_eq!(
            invoke(
                "nif_sendv",
                &[
                    client.clone(),
                    O::list(vec![O::Binary(b"a".to_vec()), O::Binary(b"b".to_vec())]),
                    O::Int(5)
                ]
            ),
            atom("ok")
        );
        let vector_payload = (0..100)
            .find_map(|_| {
                let value = invoke(
                    "nif_recv",
                    &[accepted.clone(), O::Int(2), O::Int(0), O::Int(6)],
                );
                if value == atom("select") {
                    std::thread::sleep(Duration::from_millis(1));
                    None
                } else {
                    Some(result(value))
                }
            })
            .expect("vector payload was not readable");
        assert_eq!(vector_payload, O::Binary(b"ab".to_vec()));
        for sock in [accepted, client, listener] {
            assert_eq!(invoke("nif_close", &[sock]), atom("ok"));
        }
        set_reactor(None);
    }
    fn pid(id: u32) -> O {
        O::Pid {
            node: "nonode@nohost".into(),
            id,
            serial: 0,
            creation: 0,
        }
    }
    #[test]
    fn connect_is_finalized_by_the_connecting_process() {
        let (_lock, reactor) = caller_reactor();
        let listener = open_socket("inet", "stream", 6);
        assert_eq!(
            invoke("nif_bind", &[listener.clone(), addr("inet", 0)]),
            atom("ok")
        );
        assert_eq!(
            invoke("nif_listen", &[listener.clone(), O::Int(4)]),
            atom("ok")
        );
        let bound = result(invoke("nif_sockname", std::slice::from_ref(&listener)));
        let port = number(field(&bound, "port").unwrap()).unwrap();
        let client = open_socket("inet", "stream", 6);
        let target = addr("inet", port);
        assert!(dispatch("nif_connect", std::slice::from_ref(&client)).is_err());
        let first = invoke(
            "nif_connect",
            &[client.clone(), test_ref(7), target.clone()],
        );
        if first == atom("select") {
            assert_eq!(
                reactor.wait(Duration::from_secs(2)),
                Some((pid(5), test_ref(7)))
            );
            reactor.set_caller(pid(6));
            assert_eq!(
                invoke(
                    "nif_connect",
                    &[client.clone(), test_ref(8), target.clone()]
                ),
                error("already")
            );
            assert!(dispatch("nif_connect", std::slice::from_ref(&client)).is_err());
            assert_eq!(
                invoke(
                    "nif_cancel",
                    &[client.clone(), atom("connect"), test_ref(7)]
                ),
                error("not_found")
            );
            reactor.set_caller(pid(5));
            assert_eq!(
                invoke("nif_connect", &[client.clone(), test_ref(9), target]),
                atom("ok")
            );
            assert_eq!(
                invoke(
                    "nif_cancel",
                    &[client.clone(), atom("connect"), test_ref(7)]
                ),
                error("not_found")
            );
        } else {
            assert_eq!(first, atom("ok"));
        }
        assert_eq!(
            invoke(
                "nif_connect",
                &[client.clone(), test_ref(10), addr("inet", port)]
            ),
            error("eisconn")
        );
    }
    #[test]
    fn accept_requests_are_queued_per_process() {
        let (_lock, reactor) = caller_reactor();
        let listener = open_socket("inet", "stream", 6);
        assert_eq!(
            invoke("nif_bind", &[listener.clone(), addr("inet", 0)]),
            atom("ok")
        );
        assert_eq!(
            invoke("nif_listen", &[listener.clone(), O::Int(4)]),
            atom("ok")
        );
        let bound = result(invoke("nif_sockname", std::slice::from_ref(&listener)));
        let port = number(field(&bound, "port").unwrap()).unwrap();
        assert_eq!(
            invoke("nif_accept", &[listener.clone(), test_ref(1)]),
            atom("select")
        );
        reactor.set_caller(pid(6));
        assert_eq!(
            invoke("nif_accept", &[listener.clone(), test_ref(2)]),
            atom("select")
        );
        assert!(dispatch("nif_accept", &[listener.clone(), test_ref(3)]).is_err());
        assert_eq!(
            invoke(
                "nif_cancel",
                &[listener.clone(), atom("accept"), test_ref(9)]
            ),
            atom("not_found")
        );
        reactor.set_caller(pid(5));
        let client = open_socket("inet", "stream", 6);
        let _ = invoke("nif_connect", &[client, test_ref(4), addr("inet", port)]);
        let mut ready = Vec::new();
        while let Some(selection) = reactor.wait(Duration::from_millis(300)) {
            ready.push(selection);
        }
        assert!(ready.contains(&(pid(5), test_ref(1))), "{ready:?}");
        assert!(ready.contains(&(pid(5), test_ref(4))), "{ready:?}");
        let accepted = result(invoke("nif_accept", &[listener.clone(), test_ref(5)]));
        let info = invoke("nif_getopt", &[accepted, atom("otp"), O::Int(1003)]);
        assert_eq!(info, pair(atom("ok"), pid(5)));
        assert_eq!(
            reactor.wait(Duration::from_secs(1)).map(|(who, _)| who),
            None
        );
        assert_eq!(
            invoke("nif_cancel", &[listener, atom("accept"), test_ref(2)]),
            atom("not_found")
        );
    }
    #[test]
    fn tcp_ipv4_ipv6_and_options() {
        let (_lock, reactor) = caller_reactor();
        io_round_trip("inet");
        io_round_trip("inet6");
        set_reactor(Some(reactor));
        let sock = open_socket("inet", "stream", 6);
        for (level, opt, value) in [
            (libc::SOL_SOCKET, libc::SO_REUSEADDR, atom("true")),
            (libc::SOL_SOCKET, libc::SO_KEEPALIVE, atom("true")),
            (libc::IPPROTO_TCP, libc::TCP_NODELAY, atom("true")),
            (libc::SOL_SOCKET, libc::SO_RCVBUF, O::Int(32768)),
            (libc::SOL_SOCKET, libc::SO_SNDBUF, O::Int(32768)),
            (
                libc::SOL_SOCKET,
                libc::SO_LINGER,
                map(&[("onoff", atom("true")), ("linger", O::Int(2))]),
            ),
        ] {
            assert_eq!(
                invoke(
                    "nif_setopt",
                    &[
                        sock.clone(),
                        O::Int(level.into()),
                        O::Int(opt.into()),
                        value.clone(),
                        O::Int(0)
                    ]
                ),
                atom("ok")
            );
            let got = result(invoke(
                "nif_getopt",
                &[sock.clone(), O::Int(level.into()), O::Int(opt.into())],
            ));
            assert_eq!(got, value);
        }
        let native = result(invoke(
            "nif_getopt",
            &[
                sock.clone(),
                O::Int(libc::SOL_SOCKET.into()),
                O::Int(libc::SO_REUSEADDR.into()),
                atom("native"),
                O::Int(4),
            ],
        ));
        let O::Binary(bytes) = &native else {
            panic!("expected native option bytes")
        };
        assert_ne!(i32::from_ne_bytes(bytes.clone().try_into().unwrap()), 0);
        assert_eq!(
            invoke("nif_ioctl", &[sock.clone(), O::Int(libc::FIONREAD as i64)]),
            ok(O::Int(0))
        );
        assert_eq!(invoke("nif_close", &[sock]), atom("ok"));
    }
    #[test]
    fn udp_ipv4_ipv6() {
        let (_lock, _reactor) = caller_reactor();
        for family in ["inet", "inet6"] {
            let receiver = open_socket(family, "dgram", 17);
            assert_eq!(
                invoke("nif_bind", &[receiver.clone(), addr(family, 0)]),
                atom("ok")
            );
            let bound = result(invoke("nif_sockname", std::slice::from_ref(&receiver)));
            let port = number(field(&bound, "port").unwrap()).unwrap();
            let sender = open_socket(family, "dgram", 17);
            let data = O::Binary(b"hello".to_vec());
            assert_eq!(
                invoke(
                    "nif_sendto",
                    &[
                        sender.clone(),
                        data.clone(),
                        addr(family, port),
                        O::Int(0),
                        O::Int(1)
                    ]
                ),
                atom("ok")
            );
            let packet = (0..100)
                .find_map(|_| {
                    let received = invoke(
                        "nif_recvfrom",
                        &[receiver.clone(), O::Int(128), O::Int(0), O::Int(2)],
                    );
                    if received == atom("select") {
                        std::thread::sleep(Duration::from_millis(1));
                        None
                    } else {
                        Some(result(received))
                    }
                })
                .expect("UDP datagram was not delivered");
            let O::Tuple(parts) = &packet else {
                panic!("expected address and data")
            };
            assert_eq!(parts[1], data);
            assert_eq!(name(field(&parts[0], "family").unwrap()), Some(family));
            let msg = map(&[("addr", addr(family, port))]);
            assert_eq!(
                invoke(
                    "nif_sendmsg",
                    &[
                        sender.clone(),
                        msg,
                        O::Int(0),
                        O::Int(3),
                        O::list(vec![O::Binary(b"xyz".to_vec())])
                    ]
                ),
                atom("ok")
            );
            let received = (0..100)
                .find_map(|_| {
                    let value = invoke(
                        "nif_recvmsg",
                        &[
                            receiver.clone(),
                            O::Int(128),
                            O::Int(0),
                            O::Int(0),
                            O::Int(4),
                        ],
                    );
                    if value == atom("select") {
                        std::thread::sleep(Duration::from_millis(1));
                        None
                    } else {
                        Some(result(value))
                    }
                })
                .expect("message payload was not readable");
            let iov = field(&received, "iov").unwrap();
            assert_eq!(list(iov).unwrap(), &[O::Binary(b"xyz".to_vec())]);
            assert_eq!(field(&received, "ctrl"), Some(&O::Nil));
            assert_eq!(
                invoke(
                    "nif_sendto",
                    &[
                        sender.clone(),
                        O::Binary(vec![0; 100]),
                        addr(family, port),
                        O::Int(0),
                        O::Int(5)
                    ]
                ),
                atom("ok")
            );
            let truncated = (0..100)
                .find_map(|_| {
                    let value = invoke(
                        "nif_recvmsg",
                        &[
                            receiver.clone(),
                            O::Int(10),
                            O::Int(0),
                            O::Int(0),
                            O::Int(6),
                        ],
                    );
                    if value == atom("select") {
                        std::thread::sleep(Duration::from_millis(1));
                        None
                    } else {
                        Some(result(value))
                    }
                })
                .expect("truncated datagram was not readable");
            assert_eq!(
                list(field(&truncated, "flags").unwrap()).unwrap(),
                &[atom("trunc")]
            );
            assert_eq!(invoke("nif_close", &[sender]), atom("ok"));
            assert_eq!(invoke("nif_close", &[receiver]), atom("ok"));
        }
    }
    #[test]
    fn local_stream() {
        let (_lock, _reactor) = caller_reactor();
        let path = std::env::temp_dir().join(format!("arinsal_socket_{}", std::process::id()));
        let address = map(&[
            ("family", atom("local")),
            ("path", O::Binary(path.as_os_str().as_bytes().to_vec())),
        ]);
        let listener = open_socket("local", "stream", 0);
        assert_eq!(
            invoke("nif_bind", &[listener.clone(), address.clone()]),
            atom("ok")
        );
        assert_eq!(
            invoke("nif_listen", &[listener.clone(), O::Int(4)]),
            atom("ok")
        );
        let client = open_socket("local", "stream", 0);
        let connected = invoke("nif_connect", &[client.clone(), test_ref(1), address]);
        assert!(
            connected == atom("ok") || connected == atom("select"),
            "{connected:?}"
        );
        let accepted = (0..100)
            .find_map(|_| {
                let value = invoke("nif_accept", &[listener.clone(), O::Int(2)]);
                if value == atom("select") {
                    std::thread::sleep(Duration::from_millis(1));
                    None
                } else {
                    Some(result(value))
                }
            })
            .expect("local connection was not accepted");
        assert_eq!(
            invoke(
                "nif_send",
                &[
                    client.clone(),
                    O::Binary(b"local".to_vec()),
                    O::Int(0),
                    O::Int(3)
                ]
            ),
            atom("ok")
        );
        let got = (0..100)
            .find_map(|_| {
                let value = invoke(
                    "nif_recv",
                    &[accepted.clone(), O::Int(5), O::Int(0), O::Int(4)],
                );
                if value == atom("select") {
                    std::thread::sleep(Duration::from_millis(1));
                    None
                } else {
                    Some(result(value))
                }
            })
            .expect("local payload was not readable");
        assert_eq!(got, O::Binary(b"local".to_vec()));
        for sock in [accepted, client, listener] {
            assert_eq!(invoke("nif_close", &[sock]), atom("ok"));
        }
        std::fs::remove_file(path).unwrap();
    }
    #[test]
    fn partial_send_and_large_receive() {
        let (_lock, _reactor) = caller_reactor();
        let listener = open_socket("inet", "stream", 6);
        assert_eq!(
            invoke("nif_bind", &[listener.clone(), addr("inet", 0)]),
            atom("ok")
        );
        assert_eq!(
            invoke("nif_listen", &[listener.clone(), O::Int(2)]),
            atom("ok")
        );
        let bound = result(invoke("nif_sockname", std::slice::from_ref(&listener)));
        let port = number(field(&bound, "port").unwrap()).unwrap();
        let client = open_socket("inet", "stream", 6);
        let connected = invoke(
            "nif_connect",
            &[client.clone(), test_ref(1), addr("inet", port)],
        );
        assert!(connected == atom("ok") || connected == atom("select"));
        let accepted = (0..100)
            .find_map(|_| {
                let value = invoke("nif_accept", &[listener.clone(), O::Int(2)]);
                if value == atom("select") {
                    std::thread::sleep(Duration::from_millis(1));
                    None
                } else {
                    Some(result(value))
                }
            })
            .expect("connection was not accepted");
        assert_eq!(
            invoke(
                "nif_setopt",
                &[
                    client.clone(),
                    O::Int(libc::SOL_SOCKET.into()),
                    O::Int(libc::SO_SNDBUF.into()),
                    O::Int(4096),
                    O::Int(0)
                ]
            ),
            atom("ok")
        );
        let payload: Vec<u8> = (0..2_000_000).map(|n| (n % 251) as u8).collect();
        let first = invoke(
            "nif_send",
            &[
                client.clone(),
                O::Binary(payload.clone()),
                O::Int(0),
                O::Int(3),
            ],
        );
        let mut written = match &first {
            O::Tuple(parts) if parts[0] == atom("ok") => number(&parts[1]).unwrap() as usize,
            _ => panic!("expected partial send, got {first:?}"),
        };
        assert!(written > 0 && written < payload.len());
        let expected = payload.clone();
        let reader = std::thread::spawn(move || {
            let mut bytes = Vec::with_capacity(expected.len());
            while bytes.len() < expected.len() {
                let value = invoke(
                    "nif_recv",
                    &[accepted.clone(), O::Int(0), O::Int(0), O::Int(4)],
                );
                if value == atom("select") {
                    std::thread::yield_now();
                    continue;
                }
                let packet = result(value);
                let O::Binary(data) = &packet else {
                    panic!("expected binary")
                };
                bytes.extend_from_slice(data);
            }
            assert_eq!(bytes, expected);
            assert_eq!(invoke("nif_close", &[accepted]), atom("ok"));
        });
        while written < payload.len() {
            let value = invoke(
                "nif_send",
                &[
                    client.clone(),
                    O::Binary(payload[written..].to_vec()),
                    O::Int(0),
                    O::Int(5),
                ],
            );
            match &value {
                O::Atom(s) if s == "ok" => written = payload.len(),
                O::Atom(s) if s == "select" => std::thread::yield_now(),
                O::Tuple(parts) if parts[0] == atom("ok") => {
                    written += number(&parts[1]).unwrap() as usize
                }
                _ => panic!("send failed: {value:?}"),
            }
        }
        reader.join().unwrap();
        assert_eq!(invoke("nif_close", &[client]), atom("ok"));
        assert_eq!(invoke("nif_close", &[listener]), atom("ok"));
    }
    #[test]
    fn sendfile_over_loopback() {
        let (_lock, _reactor) = caller_reactor();
        let listener = open_socket("inet", "stream", 6);
        assert_eq!(
            invoke("nif_bind", &[listener.clone(), addr("inet", 0)]),
            atom("ok")
        );
        assert_eq!(
            invoke("nif_listen", &[listener.clone(), O::Int(2)]),
            atom("ok")
        );
        let bound = result(invoke("nif_sockname", std::slice::from_ref(&listener)));
        let port = number(field(&bound, "port").unwrap()).unwrap();
        let client = open_socket("inet", "stream", 6);
        let connected = invoke(
            "nif_connect",
            &[client.clone(), test_ref(1), addr("inet", port)],
        );
        assert!(connected == atom("ok") || connected == atom("select"));
        let accepted = (0..100)
            .find_map(|_| {
                let value = invoke("nif_accept", &[listener.clone(), O::Int(2)]);
                if value == atom("select") {
                    std::thread::sleep(Duration::from_millis(1));
                    None
                } else {
                    Some(result(value))
                }
            })
            .expect("connection was not accepted");
        let path = std::env::temp_dir().join(format!("arinsal_sendfile_{}", std::process::id()));
        let bytes: Vec<u8> = (0..4096).map(|n| (n % 251) as u8).collect();
        std::fs::write(&path, &bytes).unwrap();
        let file = std::fs::File::open(&path).unwrap();
        let reference = O::Ref {
            node: "nonode@nohost".into(),
            creation: 0,
            ids: vec![18, 0, 0],
        };
        let file_ref = result(invoke_bif(
            "prim_file",
            "file_desc_to_ref_nif",
            &[O::Int(file.into_raw_fd().into())],
        ));
        let sent = invoke_bif(
            "prim_socket",
            "nif_sendfile",
            &[
                client.clone(),
                reference,
                O::Int(0),
                O::Int(0),
                file_ref.clone(),
            ],
        );
        assert_eq!(sent, ok(O::Int(bytes.len() as i64)));
        assert_eq!(
            invoke_bif("prim_file", "close_nif", &[file_ref]),
            atom("ok")
        );
        let mut received = Vec::new();
        while received.len() < bytes.len() {
            let value = invoke(
                "nif_recv",
                &[accepted.clone(), O::Int(0), O::Int(0), O::Int(2)],
            );
            if value == atom("select") {
                std::thread::yield_now();
                continue;
            }
            let packet = result(value);
            let O::Binary(data) = &packet else {
                panic!("expected binary")
            };
            received.extend_from_slice(data);
        }
        assert_eq!(received, bytes);
        assert_eq!(invoke("nif_close", &[accepted]), atom("ok"));
        assert_eq!(invoke("nif_close", &[client]), atom("ok"));
        assert_eq!(invoke("nif_close", &[listener]), atom("ok"));
        std::fs::remove_file(path).unwrap();
    }
    #[test]
    fn sendfile_select_continuation() {
        let (_lock, _reactor) = caller_reactor();
        let listener = open_socket("inet", "stream", 6);
        assert_eq!(
            invoke("nif_bind", &[listener.clone(), addr("inet", 0)]),
            atom("ok")
        );
        assert_eq!(
            invoke("nif_listen", &[listener.clone(), O::Int(2)]),
            atom("ok")
        );
        let bound = result(invoke("nif_sockname", std::slice::from_ref(&listener)));
        let port = number(field(&bound, "port").unwrap()).unwrap();
        let client = open_socket("inet", "stream", 6);
        let connected = invoke(
            "nif_connect",
            &[client.clone(), test_ref(1), addr("inet", port)],
        );
        assert!(connected == atom("ok") || connected == atom("select"));
        let accepted = (0..100)
            .find_map(|_| {
                let value = invoke("nif_accept", &[listener.clone(), O::Int(2)]);
                if value == atom("select") {
                    std::thread::sleep(Duration::from_millis(1));
                    None
                } else {
                    Some(result(value))
                }
            })
            .expect("connection was not accepted");
        assert_eq!(
            invoke(
                "nif_setopt",
                &[
                    client.clone(),
                    O::Int(libc::SOL_SOCKET.into()),
                    O::Int(libc::SO_SNDBUF.into()),
                    O::Int(4096),
                    O::Int(0)
                ]
            ),
            atom("ok")
        );
        let path =
            std::env::temp_dir().join(format!("arinsal_sendfile_large_{}", std::process::id()));
        let bytes: Vec<u8> = (0..3_000_000).map(|n| (n % 251) as u8).collect();
        std::fs::write(&path, &bytes).unwrap();
        let file = std::fs::File::open(&path).unwrap();
        let reference = O::Ref {
            node: "nonode@nohost".into(),
            creation: 0,
            ids: vec![19],
        };
        let first = invoke(
            "nif_sendfile",
            &[
                client.clone(),
                reference.clone(),
                O::Int(0),
                O::Int(bytes.len() as i64),
                O::Int(file.as_raw_fd().into()),
            ],
        );
        let O::Tuple(parts) = &first else {
            panic!("expected sendfile progress")
        };
        let mut sent = number(&parts[1]).unwrap() as usize;
        assert_eq!(parts[0], atom("select"));
        assert!(sent > 0 && sent < bytes.len());
        let expected = bytes.clone();
        let reader = std::thread::spawn(move || {
            let mut received = Vec::with_capacity(expected.len());
            while received.len() < expected.len() {
                let value = invoke(
                    "nif_recv",
                    &[accepted.clone(), O::Int(0), O::Int(0), O::Int(2)],
                );
                if value == atom("select") {
                    std::thread::yield_now();
                    continue;
                }
                let packet = result(value);
                let O::Binary(data) = &packet else {
                    panic!("expected binary")
                };
                received.extend_from_slice(data);
            }
            assert_eq!(received, expected);
            assert_eq!(invoke("nif_close", &[accepted]), atom("ok"));
        });
        while sent < bytes.len() {
            let value = invoke(
                "nif_sendfile",
                &[
                    client.clone(),
                    reference.clone(),
                    O::Int(sent as i64),
                    O::Int((bytes.len() - sent) as i64),
                ],
            );
            let O::Tuple(parts) = &value else {
                panic!("expected sendfile progress: {value:?}")
            };
            let progress = number(&parts[1]).unwrap() as usize;
            sent += progress;
            assert!(parts[0] == atom("select") || parts[0] == atom("ok"));
            if progress == 0 {
                std::thread::yield_now();
            }
        }
        reader.join().unwrap();
        assert_eq!(invoke("nif_close", &[client]), atom("ok"));
        assert_eq!(invoke("nif_close", &[listener]), atom("ok"));
        std::fs::remove_file(path).unwrap();
    }
    #[test]
    fn support_snapshot_and_invalid_address() {
        assert_eq!(
            invoke("nif_supports", &[]),
            arinsal_etf::decode(include_bytes!("../tests/fixtures/mac_otp29_supports.etf"))
                .ok()
                .and_then(|o| match &o {
                    O::Tuple(p) => Some(p[0].clone()),
                    _ => None,
                })
                .unwrap()
        );
        assert!(
            !list(&invoke("nif_supports", &[atom("options")]))
                .unwrap()
                .is_empty()
        );
        let sock = open_socket("inet", "stream", 6);
        assert_eq!(
            invoke(
                "nif_bind",
                &[sock.clone(), map(&[("family", atom("bogus"))])]
            ),
            pair(atom("invalid"), atom("sockaddr"))
        );
        assert_eq!(invoke("nif_close", &[sock]), atom("ok"));
    }
    #[test]
    fn support_tables_reconstruct_otp_wrapper_maps() {
        let snapshot =
            arinsal_etf::decode(include_bytes!("../tests/fixtures/mac_otp29_supports.etf"))
                .unwrap();
        let O::Tuple(parts) = &snapshot else {
            panic!("support tuple")
        };
        let tables = list(&parts[1]).unwrap();
        for tag in [
            "protocols",
            "options",
            "ioctl_requests",
            "ioctl_flags",
            "msg_flags",
        ] {
            let expected = tables
                .iter()
                .find_map(|row| {
                    let O::Tuple(parts) = row else { return None };
                    (parts[0] == atom(tag)).then_some(&parts[1])
                })
                .unwrap();
            let O::Map(expected) = expected else {
                panic!("support map")
            };
            let raw = invoke("nif_supports", &[atom(tag)]);
            let mut rebuilt = Vec::new();
            for item in list(&raw).unwrap() {
                let O::Tuple(parts) = item else {
                    panic!("support pair")
                };
                match tag {
                    "protocols" => {
                        rebuilt.push((parts[1].clone(), parts[0].clone()));
                        for alias in list(&parts[0]).unwrap() {
                            rebuilt.push((alias.clone(), parts[1].clone()));
                        }
                    }
                    "options" => {
                        let level = &parts[0];
                        let level_number = &parts[1];
                        for option in list(&parts[2]).unwrap() {
                            if let O::Tuple(option_parts) = option {
                                let key = pair(level.clone(), option_parts[0].clone());
                                let numeric_level = if level == &atom("socket") {
                                    atom("socket")
                                } else {
                                    level_number.clone()
                                };
                                rebuilt.push((key, pair(numeric_level, option_parts[1].clone())));
                            } else {
                                rebuilt
                                    .push((pair(level.clone(), option.clone()), atom("undefined")));
                            }
                        }
                    }
                    _ => rebuilt.push((parts[0].clone(), parts[1].clone())),
                }
            }
            // prim_socket.erl merge_values/1: the last duplicate key wins,
            // except that two list values are appended.
            let mut merged: Vec<(O, O)> = Vec::new();
            for (key, value) in rebuilt.into_iter().rev() {
                match merged.iter_mut().find(|(k, _)| *k == key) {
                    Some((_, later)) => {
                        if let (
                            O::List { elems: first, .. },
                            O::List {
                                elems: second,
                                tail,
                            },
                        ) = (&value, &*later)
                        {
                            let mut elems = first.clone();
                            elems.extend(second.iter().cloned());
                            *later = O::List {
                                elems,
                                tail: tail.clone(),
                            };
                        }
                    }
                    None => merged.push((key, value)),
                }
            }
            let mut rebuilt: Vec<_> = merged
                .into_iter()
                .map(|(k, v)| format!("{k:?}={v:?}"))
                .collect();
            let mut expected: Vec<_> = expected
                .iter()
                .map(|(k, v)| format!("{k:?}={v:?}"))
                .collect();
            rebuilt.sort();
            expected.sort();
            let only_rebuilt: Vec<_> = rebuilt
                .iter()
                .filter(|x| !expected.contains(x))
                .take(8)
                .collect();
            let only_expected: Vec<_> = expected
                .iter()
                .filter(|x| !rebuilt.contains(x))
                .take(8)
                .collect();
            assert!(
                only_rebuilt.is_empty() && only_expected.is_empty(),
                "{tag}: rebuilt={only_rebuilt:?}, expected={only_expected:?}"
            );
        }
    }
    #[test]
    fn public_support_lists_match_otp() {
        let path = std::env::temp_dir().join(format!(
            "arinsal_socket_supports_{}.etf",
            std::process::id()
        ));
        let expression = format!(
            "Keys=[protocols,options,ioctl_requests,ioctl_flags,msg_flags,unknown],Levels=[socket,ip,ipv6,tcp,udp,sctp,unknown],R={{socket:supports(),[{{K,socket:supports(K)}}||K<-Keys],[{{L,socket:supports(options,L)}}||L<-Levels]}},ok=file:write_file(\"{}\",term_to_binary(R)),halt().",
            path.display()
        );
        let Ok(output) = Command::new("erl")
            .args(["-noshell", "-eval", &expression])
            .output()
        else {
            eprintln!("skipping socket:supports differential: erl not installed");
            return;
        };
        assert!(
            output.status.success(),
            "{:?}",
            String::from_utf8_lossy(&output.stderr)
        );
        let reference = arinsal_etf::decode(&std::fs::read(&path).unwrap()).unwrap();
        std::fs::remove_file(path).unwrap();
        let O::Tuple(ref parts) = reference else {
            panic!("supports fixture must be a tuple")
        };
        let derive = |tag: &str| -> Vec<O> {
            let raw = invoke("nif_supports", &[atom(tag)]);
            let mut values = Vec::new();
            for row in list(&raw).unwrap() {
                let O::Tuple(fields) = row else {
                    panic!("support row")
                };
                match tag {
                    "protocols" => {
                        for name in list(&fields[0]).unwrap() {
                            values.push(pair(name.clone(), atom("true")));
                        }
                    }
                    "options" => {
                        for option in list(&fields[2]).unwrap() {
                            let (name, supported) = if let O::Tuple(codes) = option {
                                (&codes[0], true)
                            } else {
                                (option, false)
                            };
                            let supported = supported
                                && !(fields[0] == atom("socket") && name == &atom("peek_off"));
                            values.push(pair(
                                pair(fields[0].clone(), name.clone()),
                                atom(if supported { "true" } else { "false" }),
                            ));
                        }
                    }
                    "ioctl_requests" => {
                        if matches!(fields[0], O::Atom(_)) {
                            values.push(pair(fields[0].clone(), atom("true")));
                        }
                    }
                    _ => values.push(pair(
                        fields[0].clone(),
                        atom(if number(&fields[1]).unwrap_or(0) == 0 {
                            "false"
                        } else {
                            "true"
                        }),
                    )),
                }
            }
            if tag == "protocols" {
                values.sort_by_key(|value| format!("{value:?}"));
                values.dedup();
            }
            values
        };
        let sorted = |items: &[O]| -> Vec<String> {
            let mut items: Vec<_> = items.iter().map(|value| format!("{value:?}")).collect();
            items.sort();
            items
        };
        let all = list(&parts[0]).unwrap();
        let keys = list(&parts[1]).unwrap();
        for (index, key) in [
            "ioctl_requests",
            "ioctl_flags",
            "options",
            "msg_flags",
            "protocols",
        ]
        .iter()
        .enumerate()
        {
            let O::Tuple(row) = &all[index] else {
                panic!("supports/0 row")
            };
            assert_eq!(row[0], atom(key));
            assert_eq!(
                sorted(list(&row[1]).unwrap()),
                sorted(&derive(key)),
                "{key}"
            );
        }
        assert_eq!(
            sorted(&all[5..]),
            sorted(list(&invoke("nif_supports", &[])).unwrap())
        );
        for row in keys {
            let O::Tuple(row) = row else {
                panic!("supports/1 row")
            };
            let tag = name(&row[0]).unwrap();
            assert_eq!(
                sorted(list(&row[1]).unwrap()),
                sorted(&derive(tag)),
                "{tag}"
            );
        }
        for row in list(&parts[2]).unwrap() {
            let O::Tuple(row) = row else {
                panic!("supports/2 row")
            };
            let level = &row[0];
            let expected: Vec<_> = derive("options")
                .into_iter()
                .filter_map(|entry| {
                    let O::Tuple(ref fields) = entry else {
                        return None;
                    };
                    let O::Tuple(option) = &fields[0] else {
                        return None;
                    };
                    (option[0] == *level).then(|| pair(option[1].clone(), fields[1].clone()))
                })
                .collect();
            assert_eq!(
                sorted(list(&row[1]).unwrap()),
                sorted(&expected),
                "{level:?}"
            );
        }
    }
    #[test]
    fn address_map_normalization_matches_otp() {
        let path =
            std::env::temp_dir().join(format!("arinsal_addresses_{}.etf", std::process::id()));
        let expression = format!(
            "Cases=[{{inet,any}},{{inet,loopback}},{{inet,{{127,0,0,1}}}},{{inet6,any}},{{inet6,loopback}},{{inet6,{{0,0,0,0,0,0,0,1}}}}],R=[begin {{ok,S}}=socket:open(D,dgram,default),ok=socket:bind(S,#{{family=>D,addr=>A,port=>0}}),{{ok,N}}=socket:sockname(S),socket:close(S),N#{{port:=0}} end || {{D,A}} <- Cases],ok=file:write_file(\"{}\",term_to_binary(R)),halt().",
            path.display()
        );
        let Ok(output) = Command::new("erl")
            .args(["-noshell", "-eval", &expression])
            .output()
        else {
            eprintln!("skipping address differential: erl not installed");
            return;
        };
        assert!(
            output.status.success(),
            "{:?}",
            String::from_utf8_lossy(&output.stderr)
        );
        let expected = arinsal_etf::decode(&std::fs::read(&path).unwrap()).unwrap();
        std::fs::remove_file(path).unwrap();
        let input = [
            map(&[("family", atom("inet")), ("addr", atom("any"))]),
            map(&[("family", atom("inet")), ("addr", atom("loopback"))]),
            map(&[
                ("family", atom("inet")),
                (
                    "addr",
                    O::tuple(vec![O::Int(127), O::Int(0), O::Int(0), O::Int(1)]),
                ),
            ]),
            map(&[("family", atom("inet6")), ("addr", atom("any"))]),
            map(&[("family", atom("inet6")), ("addr", atom("loopback"))]),
            map(&[
                ("family", atom("inet6")),
                (
                    "addr",
                    O::tuple(vec![
                        O::Int(0),
                        O::Int(0),
                        O::Int(0),
                        O::Int(0),
                        O::Int(0),
                        O::Int(0),
                        O::Int(0),
                        O::Int(1),
                    ]),
                ),
            ]),
        ];
        for (address, expected) in input.iter().zip(list(&expected).unwrap()) {
            let actual = from_addr(to_addr(address).unwrap());
            for key in ["family", "addr", "port", "flowinfo", "scope_id"] {
                assert_eq!(
                    field(&actual, key),
                    field(expected, key),
                    "{address:?}: {key}"
                );
            }
        }
        assert!(to_addr(&map(&[("family", atom("inet")), ("addr", atom("bogus"))])).is_none());
        assert!(to_addr(&map(&[("family", atom("inet")), ("port", O::Int(65536))])).is_none());
    }
    #[test]
    fn invalid_options_and_values_match_otp_704_cases() {
        let path = std::env::temp_dir().join(format!("arinsal_options_{}.etf", std::process::id()));
        let expression = format!(
            "{{ok,S}}=socket:open(inet,stream,tcp),Opts=[{{socket,reuseaddr}},{{tcp,nodelay}},{{socket,keepalive}},{{socket,rcvbuf}},{{socket,sndbuf}},{{socket,linger}}],Names=[list_to_atom(\"bad_\"++integer_to_list(I)) || I <- lists:seq(0,99)],R1=[socket:setopt(S,{{socket,N}},true) || N <- Names],R2=[socket:setopt(S,{{N,reuseaddr}},true) || N <- Names],R3=[socket:setopt(S,Opt,list_to_atom(\"bad_\"++integer_to_list(I))) || Opt <- Opts, I <- lists:seq(0,83)],ok=file:write_file(\"{}\",term_to_binary(R1++R2++R3)),socket:close(S),halt().",
            path.display()
        );
        let Ok(output) = Command::new("erl")
            .args(["-noshell", "-eval", &expression])
            .output()
        else {
            eprintln!("skipping 704-case OTP differential: erl not installed");
            return;
        };
        assert!(
            output.status.success(),
            "{:?}",
            String::from_utf8_lossy(&output.stderr)
        );
        let expected = arinsal_etf::decode(&std::fs::read(&path).unwrap()).unwrap();
        std::fs::remove_file(path).unwrap();
        let sock = open_socket("inet", "stream", 6);
        let options = [
            ("socket", "reuseaddr", libc::SOL_SOCKET, libc::SO_REUSEADDR),
            ("tcp", "nodelay", libc::IPPROTO_TCP, libc::TCP_NODELAY),
            ("socket", "keepalive", libc::SOL_SOCKET, libc::SO_KEEPALIVE),
            ("socket", "rcvbuf", libc::SOL_SOCKET, libc::SO_RCVBUF),
            ("socket", "sndbuf", libc::SOL_SOCKET, libc::SO_SNDBUF),
            ("socket", "linger", libc::SOL_SOCKET, libc::SO_LINGER),
        ];
        let mut actual = Vec::new();
        let supported = invoke("nif_supports", &[atom("options")]);
        for i in 0..100 {
            let option = pair(atom("socket"), atom(&format!("bad_{i}")));
            assert!(!format!("{supported:?}").contains(&format!("Atom(\"bad_{i}\")")));
            actual.push(pair(
                atom("error"),
                pair(atom("invalid"), pair(atom("socket_option"), option)),
            ));
        }
        for i in 0..100 {
            let option = pair(atom(&format!("bad_{i}")), atom("reuseaddr"));
            actual.push(pair(
                atom("error"),
                pair(atom("invalid"), pair(atom("socket_option"), option)),
            ));
        }
        for (level, opt_name, level_code, opt_code) in options {
            let option = pair(atom(level), atom(opt_name));
            for i in 0..84 {
                let value = atom(&format!("bad_{i}"));
                assert_eq!(
                    invoke(
                        "nif_setopt",
                        &[
                            sock.clone(),
                            O::Int(level_code.into()),
                            O::Int(opt_code.into()),
                            value.clone(),
                            O::Int(0)
                        ]
                    ),
                    pair(atom("invalid"), atom("value"))
                );
                actual.push(pair(
                    atom("error"),
                    pair(
                        atom("invalid"),
                        O::tuple(vec![atom("socket_option"), option.clone(), value]),
                    ),
                ));
            }
        }
        assert_eq!(actual.len(), 704);
        assert_eq!(O::list(actual), expected);
        assert_eq!(invoke("nif_close", &[sock]), atom("ok"));
    }
    #[test]
    fn selection_and_owner_death() {
        let _lock = REACTOR_TEST_LOCK.lock().unwrap();
        let socket = open_socket("inet", "dgram", 17);
        assert_eq!(
            invoke("nif_bind", &[socket.clone(), addr("inet", 0)]),
            atom("ok")
        );
        let bound = result(invoke("nif_sockname", std::slice::from_ref(&socket)));
        let port = number(field(&bound, "port").unwrap()).unwrap();
        let pid = O::Pid {
            node: "nonode@nohost".into(),
            id: 77,
            serial: 0,
            creation: 0,
        };
        set_owner(&socket, pid.clone()).unwrap();
        let reactor = Arc::new(BlockingReactor::default());
        reactor.set_caller(pid.clone());
        set_reactor(Some(reactor.clone()));
        let reference = O::Ref {
            node: "nonode@nohost".into(),
            creation: 0,
            ids: vec![999],
        };
        assert_eq!(
            invoke(
                "nif_recvfrom",
                &[socket.clone(), O::Int(10), O::Int(0), reference.clone()]
            ),
            atom("select")
        );
        let sender = open_socket("inet", "dgram", 17);
        assert_eq!(
            invoke(
                "nif_sendto",
                &[
                    sender.clone(),
                    O::Binary(b"ready".to_vec()),
                    addr("inet", port),
                    O::Int(0),
                    O::Int(1)
                ]
            ),
            atom("ok")
        );
        assert_eq!(
            reactor.wait(Duration::from_secs(1)),
            Some((pid.clone(), reference.clone()))
        );
        assert_eq!(
            crate::select_message(&socket, &reference),
            O::tuple(vec![
                atom("$socket"),
                pair(atom("$socket"), socket.clone()),
                atom("select"),
                reference.clone()
            ])
        );
        assert_eq!(
            crate::abort_message(&socket, &reference, &atom("closed")),
            O::tuple(vec![
                atom("$socket"),
                pair(atom("$socket"), socket.clone()),
                atom("abort"),
                pair(reference.clone(), atom("closed"))
            ])
        );
        let cancelled = invoke("nif_cancel", &[socket.clone(), atom("recvfrom"), reference]);
        assert!(
            [atom("ok"), atom("select_sent"), atom("not_found")].contains(&cancelled),
            "{cancelled:?}"
        );
        assert_eq!(invoke("nif_close", &[sender]), atom("ok"));
        owner_died(&pid);
        assert_eq!(
            invoke("nif_getopt", &[socket, atom("otp"), O::Int(1008)]),
            error("closed")
        );
        set_reactor(None);
    }
}
