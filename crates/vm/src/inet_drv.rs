//! `tcp_inet` / `tcp_inet6` port driver.
//!
//! Erlang `prim_inet` talks to this port with `port_control` (`INET_REQ_*`,
//! `TCP_REQ_*` in `inet_int.hrl`, plus `16#03f1a300`) and `port_command`.
//! Replies are `{inet_reply, …}`, `{inet_async, …}`, `{tcp, S, Data}`,
//! `{tcp_closed, S}` and `{tcp_passive, S}`.
//!
//! Port of `erts/emulator/drivers/common/inet_drv.c` (`tcp_inet_ctl`,
//! `tcp_inet_command`, `tcp_message`, `tcp_closed_message`), OTP-29.1.1.

use crate::port::PortHandle;
use crate::process::{Message, Runtime};
use crate::{Process, VmError};
use arinsal_packet::{
    HttpPacket, HttpUri, Packet, PacketOptions, PacketResult, PacketState, PacketType,
    parse_with_state,
};
use arinsal_sched::Pid;
use arinsal_term::{ProcessHeap, Term, TermBuilder, global_atoms};
use std::collections::{HashMap, VecDeque};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

// Port of inet_drv.c ERTS_INET_DRV_CONTROL_MAGIC_NUMBER, OTP-29.1.1.
// g_inet_udp
pub(crate) const MAGIC: i64 = 0x03f1_a300;
const INFINITY: u32 = 0xffff_ffff;
const TCP_MAX_PACKET: i32 = 0x400_0000;

const REQ_OPEN: i64 = 1;
const REQ_CLOSE: i64 = 2;
const REQ_CONNECT: i64 = 3;
const REQ_PEER: i64 = 4;
const REQ_NAME: i64 = 5;
const REQ_BIND: i64 = 6;
const REQ_SETOPTS: i64 = 7;
const REQ_GETOPTS: i64 = 8;
const REQ_GETSTAT: i64 = 11;
const REQ_GETTYPE: i64 = 15;
const REQ_GETSTATUS: i64 = 16;
const REQ_GETIFLIST: i64 = 21;
const REQ_IFGET: i64 = 22;
const REQ_SUBSCRIBE: i64 = 24;
const REQ_GETIFADDRS: i64 = 25;
const REQ_ACCEPT: i64 = 26;
const REQ_LISTEN: i64 = 27;
const TCP_REQ_RECV: i64 = 42;
const TCP_REQ_SHUTDOWN: i64 = 44;

const AF_INET_CODE: u8 = 1;
const AF_INET6_CODE: u8 = 2;
const AF_ANY: u8 = 3;
const AF_LOOPBACK: u8 = 4;
const AF_LOCAL_CODE: u8 = 5;

// Port of inet_drv.c:874 (INET_OPT_* / INET_LOPT_* / TCP_OPT_*), OTP-29.1.1.
const OPT_REUSEADDR: u8 = 0;
const OPT_KEEPALIVE: u8 = 1;
const OPT_LINGER: u8 = 3;
const OPT_SNDBUF: u8 = 6;
const OPT_RCVBUF: u8 = 7;
const OPT_PRIORITY: u8 = 8;
const OPT_TOS: u8 = 9;
const OPT_NODELAY: u8 = 10;
const OPT_V6ONLY: u8 = 16;
const OPT_REUSEPORT: u8 = 17;
const OPT_REUSEPORT_LB: u8 = 18;
const OPT_BUFFER: u8 = 20;
const OPT_HEADER: u8 = 21;
const OPT_ACTIVE: u8 = 22;
const OPT_PACKET: u8 = 23;
const OPT_MODE: u8 = 24;
const OPT_DELIVER: u8 = 25;
const OPT_EXIT: u8 = 26;
const OPT_HIGH: u8 = 27;
const OPT_LOW: u8 = 28;
const OPT_SEND_TIMEOUT: u8 = 30;
const OPT_DELAY_SEND: u8 = 31;
const OPT_PACKET_SIZE: u8 = 32;
const OPT_RAW: u8 = 34;
const OPT_SEND_TIMEOUT_CLOSE: u8 = 35;
const OPT_MSGQ_HIGH: u8 = 36;
const OPT_MSGQ_LOW: u8 = 37;
const OPT_NETNS: u8 = 38;
const OPT_SHOW_ECONNRESET: u8 = 39;
const OPT_LINE: u8 = 40;
const OPT_TCLASS: u8 = 41;
const OPT_BIND_TO_DEVICE: u8 = 42;
const OPT_RECVTOS: u8 = 43;
const OPT_TTL: u8 = 46;
const OPT_RECVTTL: u8 = 47;
const OPT_NOPUSH: u8 = 48;
const OPT_DEBUG: u8 = 99;

const IFOPT_ADDR: u8 = 1;
const IFOPT_BROADADDR: u8 = 2;
const IFOPT_DSTADDR: u8 = 3;
const IFOPT_NETMASK: u8 = 5;
const IFOPT_FLAGS: u8 = 6;
const IFOPT_HWADDR: u8 = 7;

const IFF_UP: i32 = 0x0001;
const IFF_BROADCAST: i32 = 0x0002;
const IFF_LOOPBACK: i32 = 0x0004;
const IFF_POINTTOPOINT: i32 = 0x0008;
const IFF_RUNNING: i32 = 0x0010;
const IFF_MULTICAST: i32 = 0x0020;

const DELIVER_PORT: i32 = 0;
const MAX_OPT_BUFFER: usize = 64 * 1024;

const F_OPEN: u32 = 0x0001;
const F_ACTIVE: u32 = 0x0004;
const F_LISTEN: u32 = 0x0008;
const F_CON: u32 = 0x0010;
const F_ACC: u32 = 0x0020;
const F_BUSY: u32 = 0x0080;

fn atom(name: &str) -> Term {
    Term::atom(global_atoms().intern(name).expect("inet atom"))
}

fn badarg() -> VmError {
    VmError::Trap(crate::exceptions::Trap::error(atom("badarg")))
}

/// Extra `Arc` so `PortHandle`'s scheduler is not the last reference dropped
/// on a scheduler worker (`Scheduler::drop` joins that worker).
///
/// The arc is released when the last inet port on that scheduler closes, and
/// the final drop runs on a helper thread once every other owner is gone.
struct SchedPin {
    sched: Arc<arinsal_sched::Scheduler<Process>>,
    ports: usize,
}

fn pins() -> &'static Mutex<Vec<SchedPin>> {
    static PINS: OnceLock<Mutex<Vec<SchedPin>>> = OnceLock::new();
    PINS.get_or_init(|| Mutex::new(Vec::new()))
}

fn pin_scheduler(sched: Arc<arinsal_sched::Scheduler<Process>>) {
    let mut pins = pins().lock().unwrap();
    let ptr = Arc::as_ptr(&sched);
    if let Some(pin) = pins.iter_mut().find(|pin| Arc::as_ptr(&pin.sched) == ptr) {
        pin.ports += 1;
        return;
    }
    pins.push(SchedPin { sched, ports: 1 });
}

fn unpin_scheduler(sched: &Arc<arinsal_sched::Scheduler<Process>>) {
    let release = {
        let mut pins = pins().lock().unwrap();
        let ptr = Arc::as_ptr(sched);
        let Some(pin) = pins.iter_mut().find(|pin| Arc::as_ptr(&pin.sched) == ptr) else {
            return;
        };
        pin.ports -= 1;
        if pin.ports > 0 {
            return;
        }
        let index = pins
            .iter()
            .position(|pin| Arc::as_ptr(&pin.sched) == ptr)
            .expect("pin");
        Some(pins.swap_remove(index).sched)
    };
    let Some(sched) = release else {
        return;
    };
    std::thread::Builder::new()
        .name("arinsal-inet-unpin".into())
        .spawn(move || {
            // Drop the last Arc off the worker. A re-pin owns the scheduler again.
            loop {
                if pins()
                    .lock()
                    .unwrap()
                    .iter()
                    .any(|pin| Arc::ptr_eq(&pin.sched, &sched))
                {
                    return;
                }
                if Arc::strong_count(&sched) == 1 {
                    drop(sched);
                    return;
                }
                std::thread::sleep(Duration::from_millis(2));
            }
        })
        .expect("inet unpin");
}

fn registry() -> &'static Mutex<HashMap<u64, Arc<Sock>>> {
    static REG: OnceLock<Mutex<HashMap<u64, Arc<Sock>>>> = OnceLock::new();
    REG.get_or_init(|| Mutex::new(HashMap::new()))
}

fn wake_writer() -> &'static OwnedFd {
    static WAKE: OnceLock<OwnedFd> = OnceLock::new();
    WAKE.get_or_init(|| {
        let (read, write) = pipe().expect("inet wake pipe");
        std::thread::Builder::new()
            .name("arinsal-inet".into())
            .spawn(move || io_loop(read))
            .expect("inet thread");
        write
    })
}

fn poke() {
    let fd = wake_writer().as_raw_fd();
    let byte = [1u8];
    // SAFETY: wake_writer owns the write end for the process lifetime.
    unsafe {
        libc::write(fd, byte.as_ptr().cast(), 1);
    }
}

// g_inet_udp
pub(crate) fn pipe() -> std::io::Result<(OwnedFd, OwnedFd)> {
    let fds = crate::port::cloexec_publish(|| {
        let mut fds = [0; 2];
        // SAFETY: pipe writes two fresh descriptors; set close-on-exec before publishing either.
        let rc = unsafe {
            let rc = libc::pipe(fds.as_mut_ptr());
            if rc == 0
                && (libc::fcntl(fds[0], libc::F_SETFD, libc::FD_CLOEXEC) < 0
                    || libc::fcntl(fds[1], libc::F_SETFD, libc::FD_CLOEXEC) < 0)
            {
                let error = std::io::Error::last_os_error();
                libc::close(fds[0]);
                libc::close(fds[1]);
                return Err(error);
            }
            rc
        };
        if rc != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(fds)
    })?;
    set_nonblock(fds[0]);
    set_nonblock(fds[1]);
    // SAFETY: both descriptors were just created and are not aliased.
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

// g_inet_udp
pub(crate) fn set_nonblock(fd: RawFd) {
    // SAFETY: fcntl only changes flags on a descriptor this driver owns.
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        if flags >= 0 {
            libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
        }
        libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC);
    }
}

// g_inet_udp
pub(crate) fn zeroed<T>() -> T {
    // SAFETY: callers use this for C structs whose all-zero bit pattern is valid.
    unsafe { std::mem::zeroed() }
}

// g_inet_udp
pub(crate) fn set_nosigpipe(fd: RawFd) {
    let one = 1i32;
    // SAFETY: the descriptor is a socket this driver just created.
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_NOSIGPIPE,
            (&one as *const i32).cast(),
            std::mem::size_of::<i32>() as libc::socklen_t,
        );
    }
}

/// Register a `tcp_inet` port created by `open_port({spawn_driver, …})`.
pub(crate) fn attach(runtime: Arc<Runtime>, id: u64, handle: Arc<PortHandle>) {
    let _ = wake_writer();
    pin_scheduler(handle.scheduler());
    let sock = Arc::new(Sock::new(id, runtime, handle));
    registry().lock().unwrap().insert(id, sock);
    poke();
}

/// True when `id` is a live TCP inet socket owned by this driver.
pub(crate) fn owns(id: u64) -> bool {
    registry().lock().unwrap().contains_key(&id)
}

/// Drop the socket behind a port. Waiters receive `{error, closed}`.
pub(crate) fn detach(id: u64) {
    let Some(sock) = registry().lock().unwrap().remove(&id) else {
        return;
    };
    // The port closed while owning a dist connection (its controller exited, e.g. through
    // `net_kernel:disconnect/1`): tear the connection down and deliver nodedown.
    // Port of erts/emulator/beam/dist.c (erts_do_net_exits via the dist port's exit), OTP-29.1.1.
    if crate::node_tables::is_dist_port(id) {
        let _ = crate::dist::port_connection_closed(&sock.runtime, id);
    }
    unpin_scheduler(&sock.handle.scheduler());
    let pending = {
        let mut inner = sock.inner.lock().unwrap();
        flush_send(&mut inner);
        inner.fd.take();
        inner.phase = Phase::Closed;
        std::mem::take(&mut inner.pending)
    };
    for (caller, aref) in pending {
        emit(
            &sock,
            Out::AsyncError {
                caller,
                aref,
                reason: "closed",
            },
        );
    }
    poke();
}

pub(crate) fn control(
    process: &mut Process,
    id: u64,
    caller: Pid,
    op: i64,
    data: &[u8],
) -> Result<Term, VmError> {
    let Some(sock) = registry().lock().unwrap().get(&id).cloned() else {
        return byte_list(process, &err_bytes("exbadport"));
    };
    // Port of inet_drv.c:11956 (tcp_inet_ctl subtracts the magic), OTP-29.1.1.
    let cmd = op.wrapping_sub(MAGIC);
    let reply = dispatch(&sock, caller, cmd, data);
    poke();
    byte_list(process, &reply)
}

pub(crate) fn command(id: u64, caller: Pid, data: &[u8]) -> Result<(), VmError> {
    let Some(sock) = registry().lock().unwrap().get(&id).cloned() else {
        return Err(badarg());
    };
    // Port of inet_drv.c:13736 (tcp_sendv) and :12629 (tcp_inet_command), OTP-29.1.1.
    let (ids, payload) = split_caller(data).ok_or_else(badarg)?;
    let outcome = {
        let mut inner = sock.inner.lock().unwrap();
        accept_send(&mut inner, caller, ids, payload)
    };
    match outcome {
        SendOutcome::Reply(error) => emit(&sock, Out::InetReply { caller, ids, error }),
        SendOutcome::Deferred => {}
        SendOutcome::Failed { error, active } => {
            emit(
                &sock,
                Out::InetReply {
                    caller,
                    ids,
                    error: Some(error),
                },
            );
            if active {
                let owner = sock.handle.owner_pid();
                if error == "econnreset" {
                    emit(
                        &sock,
                        Out::TcpError {
                            owner,
                            reason: "econnreset",
                        },
                    );
                }
                emit(&sock, Out::TcpClosed { owner });
                if sock.inner.lock().unwrap().exit_on_close {
                    crate::port::abandon_port(&sock.runtime, sock.id);
                }
            }
        }
    }
    emit_ready(&sock);
    poke();
    Ok(())
}

/// Write a raw distribution packet (no caller-ref prefix, no `inet_reply`).
///
/// Port of dist.c:3794 (`dist_port_command`) calling `tcp_inet_command` with
/// `prt->caller = NIL`, so `init_caller` skips the ref header, OTP-29.1.1.
pub(crate) fn dist_output(id: u64, data: &[u8]) -> Result<bool, VmError> {
    let Some(sock) = registry().lock().unwrap().get(&id).cloned() else {
        return Err(badarg());
    };
    let outcome = {
        let mut inner = sock.inner.lock().unwrap();
        // Dummy caller/ids: dist never waits on inet_reply for these writes.
        accept_send(&mut inner, Pid::new(0, 0), [0, 0, 0], data)
    };
    match outcome {
        SendOutcome::Reply(_) | SendOutcome::Deferred => {}
        SendOutcome::Failed { error, active } => {
            if active {
                let owner = sock.handle.owner_pid();
                if error == "econnreset" {
                    emit(
                        &sock,
                        Out::TcpError {
                            owner,
                            reason: "econnreset",
                        },
                    );
                }
                emit(&sock, Out::TcpClosed { owner });
                if sock.inner.lock().unwrap().exit_on_close {
                    crate::port::abandon_port(&sock.runtime, sock.id);
                }
            }
        }
    }
    emit_ready(&sock);
    poke();
    Ok(sock.inner.lock().unwrap().busy)
}

enum SendOutcome {
    Reply(Option<&'static str>),
    Deferred,
    Failed { error: &'static str, active: bool },
}

fn accept_send(inner: &mut Inner, caller: Pid, ids: [u32; 3], payload: &[u8]) -> SendOutcome {
    // Port of inet_drv.c:13736 (tcp_sendv), OTP-29.1.1.
    if inner.peer_closed {
        return SendOutcome::Reply(Some(close_atom(inner)));
    }
    if inner.phase != Phase::Connected {
        return SendOutcome::Reply(Some("enotconn"));
    }
    // Header widths are 1, 2 and 4; htype 3 is TCP_PB_4 (inet_drv.c:13745).
    let hlen = match inner.htype {
        1 => 1,
        2 => 2,
        3 => 4,
        _ => 0,
    };
    let frame = framed(inner.htype, payload);
    output_count(inner, frame.len());
    let before = inner.sendq.len();
    if before == 0 && hlen == 0 && payload.is_empty() {
        return SendOutcome::Reply(None);
    }
    if before == 0 && inner.delay_send {
        inner.sendq.extend(frame);
        return SendOutcome::Reply(None);
    }
    if before == 0 {
        inner.sendq.extend(frame);
        if let Some(err) = flush_send(inner) {
            return send_failed(inner, err);
        }
        return SendOutcome::Reply(None);
    }
    inner.sendq.extend(frame);
    let queued = before + payload.len() + hlen;
    if queued >= inner.high.max(0) as usize {
        if inner.send_timeout == 0 {
            return SendOutcome::Reply(Some("timeout"));
        }
        inner.busy = true;
        let deadline = if inner.send_timeout < 0 {
            None
        } else {
            Some(Instant::now() + Duration::from_millis(inner.send_timeout as u64))
        };
        inner.send_waits.push(SendWait {
            caller,
            ids,
            deadline,
        });
        return SendOutcome::Deferred;
    }
    SendOutcome::Reply(None)
}

fn framed(htype: i32, payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(payload.len() + 4);
    match htype {
        1 => buf.push(payload.len() as u8),
        2 => buf.extend_from_slice(&(payload.len() as u16).to_be_bytes()),
        3 => buf.extend_from_slice(&(payload.len() as u32).to_be_bytes()),
        _ => {}
    }
    buf.extend_from_slice(payload);
    buf
}

fn send_failed(inner: &mut Inner, err: i32) -> SendOutcome {
    // Port of inet_drv.c:13690 (tcp_send_error), OTP-29.1.1.
    let err = if err == libc::EPIPE {
        libc::ECONNRESET
    } else {
        err
    };
    let show = inner.show_econnreset && err == libc::ECONNRESET;
    inner.reset = show;
    inner.peer_closed = true;
    inner.sendq.clear();
    inner.busy = false;
    inner.send_waits.clear();
    inner.fd.take();
    let active = active_is(&inner.active);
    if active {
        inner.closed_sent = true;
    }
    SendOutcome::Failed {
        error: if show { "econnreset" } else { "closed" },
        active,
    }
}

fn dispatch(sock: &Arc<Sock>, caller: Pid, cmd: i64, data: &[u8]) -> Vec<u8> {
    let mut accept_now: Option<(OwnedFd, u16)> = None;
    let reply = {
        let mut inner = sock.inner.lock().unwrap();
        match cmd {
            REQ_OPEN => open_socket(&mut inner, data),
            REQ_CLOSE => {
                // inet_drv.c:11932 (tcp_desc_close) drops the fd. Write bytes
                // already accepted by tcp_sendv first so FIN cannot overtake them.
                let _ = flush_send(&mut inner);
                inner.fd.take();
                inner.phase = Phase::Closed;
                ok_bytes(&[])
            }
            REQ_BIND => bind_socket(&mut inner, data),
            REQ_LISTEN => listen_socket(&mut inner, data),
            REQ_CONNECT => connect_socket(sock, &mut inner, caller, data),
            REQ_ACCEPT => match accept_socket(sock, &mut inner, caller, data) {
                Accept::Reply(bytes) => bytes,
                Accept::Now(fd, aref, bytes) => {
                    accept_now = Some((fd, aref));
                    bytes
                }
            },
            REQ_NAME => sockname(&inner),
            REQ_PEER => peername(&inner),
            REQ_SETOPTS => setopts(&mut inner, data),
            REQ_GETOPTS => getopts(&inner, data),
            REQ_GETSTAT => getstat(&inner, data),
            REQ_GETIFLIST | REQ_IFGET | REQ_GETIFADDRS => interface_control(
                cmd,
                data,
                inner.phase != Phase::Closed && inner.fd.is_some(),
            )
            .unwrap_or_else(|| err_bytes("exbadport")),
            REQ_SUBSCRIBE => subscribe(&inner, data),
            REQ_GETTYPE => gettype(&inner),
            REQ_GETSTATUS => getstatus(&inner),
            TCP_REQ_RECV => recv_req(&mut inner, caller, data),
            TCP_REQ_SHUTDOWN => shutdown_sock(&inner, data),
            _ => err_bytes("exbadport"),
        }
    };
    if let Some((fd, aref)) = accept_now {
        install_accepted(sock, fd, caller, aref);
    }
    if cmd == TCP_REQ_RECV || cmd == REQ_SETOPTS || cmd == REQ_CONNECT {
        try_io(sock, false);
    }
    let passive = {
        let mut inner = sock.inner.lock().unwrap();
        if inner.emit_passive {
            inner.emit_passive = false;
            true
        } else {
            false
        }
    };
    if passive {
        emit(
            sock,
            Out::TcpPassive {
                owner: sock.handle.owner_pid(),
            },
        );
    }
    reply
}

// Port of erts/emulator/drivers/common/inet_drv.c:11067-11100,
// OTP-29.1.1. Both TCP and UDP inet ports handle these interface requests.
pub(crate) fn interface_control(cmd: i64, data: &[u8], open: bool) -> Option<Vec<u8>> {
    let reply = match cmd {
        REQ_GETIFLIST if open => getiflist(),
        REQ_IFGET if open => ifget(data),
        REQ_GETIFADDRS if open => getifaddrs_reply(),
        REQ_GETIFLIST | REQ_IFGET | REQ_GETIFADDRS => err_bytes("exbadport"),
        _ => return None,
    };
    Some(reply)
}

fn open_socket(inner: &mut Inner, data: &[u8]) -> Vec<u8> {
    // Port of inet_drv.c:11961 (INET_REQ_OPEN), OTP-29.1.1.
    if data.len() != 3 {
        return err_bytes("einval");
    }
    if inner.fd.is_some() {
        return err_bytes("einval");
    }
    let domain = match data[0] {
        AF_INET_CODE => libc::AF_INET,
        AF_INET6_CODE => libc::AF_INET6,
        AF_LOCAL_CODE => libc::AF_UNIX,
        _ => return err_bytes("eafnosupport"),
    };
    if data[1] != 1 {
        return err_bytes("einval");
    }
    if data[2] != 0 && data[2] != 1 {
        return err_bytes("eprotonosupport");
    }
    // SAFETY: socket returns a fresh descriptor; set close-on-exec before publishing it.
    let (fd, cloexec_error) = crate::port::cloexec_publish(|| unsafe {
        let fd = libc::socket(domain, libc::SOCK_STREAM, 0);
        if fd >= 0 && libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) < 0 {
            let error = last_errno();
            libc::close(fd);
            (-1, Some(error))
        } else {
            (fd, None)
        }
    });
    if let Some(error) = cloexec_error {
        return err_bytes(errno_name(error));
    }
    if fd < 0 {
        return err_bytes(errno_name(last_errno()));
    }
    set_nonblock(fd);
    set_nosigpipe(fd);
    // SAFETY: fd was just created and is moved into OwnedFd.
    inner.fd = Some(unsafe { OwnedFd::from_raw_fd(fd) });
    inner.domain = domain;
    inner.family_code = data[0];
    inner.phase = Phase::Open;
    apply_saved(inner);
    ok_bytes(&[])
}

fn bind_socket(inner: &mut Inner, data: &[u8]) -> Vec<u8> {
    // Port of inet_drv.c inet_ctl INET_REQ_BIND, OTP-29.1.1.
    if inner.fd.is_none() {
        return err_bytes("exbadport");
    }
    let dest = match parse_dest(inner.domain, data) {
        Ok(dest) => dest,
        Err(reason) => return err_bytes(reason),
    };
    let fd = inner.fd.as_ref().unwrap().as_raw_fd();
    let rc = dest.call(|ptr, len| {
        // SAFETY: ptr/len is the sockaddr this driver built; fd is its socket.
        unsafe { libc::bind(fd, ptr, len) }
    });
    if rc < 0 {
        return err_bytes(errno_name(last_errno()));
    }
    inner.phase = Phase::Bound;
    // Port of inet_drv.c:11444 (inet_address_port; AF_UNIX yields 0), OTP-29.1.1.
    if inner.domain == libc::AF_UNIX {
        return ok_bytes(&[0, 0]);
    }
    // Port of prim_inet.erl:309 (do_bind expects the bound port), OTP-29.1.1.
    match name_of(inner, true) {
        Ok(bytes) if bytes.len() >= 3 => ok_bytes(&bytes[1..3]),
        Ok(_) => err_bytes("einval"),
        Err(reason) => err_bytes(reason),
    }
}

fn listen_socket(inner: &mut Inner, data: &[u8]) -> Vec<u8> {
    // Port of inet_drv.c:12042 (INET_REQ_LISTEN), OTP-29.1.1.
    if inner.phase == Phase::Closed || inner.fd.is_none() {
        return err_bytes("exbadport");
    }
    if data.len() != 2 {
        return err_bytes("einval");
    }
    let backlog = i16::from_be_bytes([data[0], data[1]]) as i32;
    let fd = inner.fd.as_ref().unwrap().as_raw_fd();
    // SAFETY: fd is the socket this descriptor owns.
    let rc = unsafe { libc::listen(fd, backlog) };
    if rc < 0 {
        return err_bytes(errno_name(last_errno()));
    }
    inner.phase = Phase::Listening;
    inner.backlog = backlog;
    ok_bytes(&[])
}

fn connect_socket(sock: &Arc<Sock>, inner: &mut Inner, caller: Pid, data: &[u8]) -> Vec<u8> {
    // Port of inet_drv.c:12064 (INET_REQ_CONNECT), OTP-29.1.1.
    if inner.fd.is_none() || inner.phase == Phase::Closed {
        return err_bytes("exbadport");
    }
    if inner.phase == Phase::Connected {
        return err_bytes("eisconn");
    }
    if inner.phase == Phase::Connecting {
        return err_bytes("einval");
    }
    if data.len() < 6 {
        return err_bytes("einval");
    }
    let timeout = u32::from_be_bytes(data[0..4].try_into().unwrap());
    let dest = match parse_dest(inner.domain, &data[4..]) {
        Ok(dest) => dest,
        Err(reason) => return err_bytes(reason),
    };
    let fd = inner.fd.as_ref().unwrap().as_raw_fd();
    let rc = dest.call(|ptr, len| {
        // SAFETY: ptr/len is the sockaddr this driver built; fd is its socket.
        unsafe { libc::connect(fd, ptr, len) }
    });
    if rc == 0 {
        inner.phase = Phase::Connected;
        return ok_bytes(&[]);
    }
    let err = last_errno();
    // Port of inet_drv.c:12098-12114 (EINPROGRESS → sock_select FD_CONNECT and
    // driver_set_timer), OTP-29.1.1. Completion is tcp_inet_output when the
    // poll set reports the socket writable, not a wait inside this call.
    if err == libc::EINPROGRESS || err == libc::EAGAIN || err == libc::EWOULDBLOCK {
        let aref = alloc_async(inner);
        if timeout == 0 {
            // A zero timer is already due. erts closes the socket
            // (tcp_inet_timeout) and replies `{error, timeout}`.
            inner.fd.take();
            inner.phase = Phase::Closed;
            emit(
                sock,
                Out::AsyncError {
                    caller,
                    aref,
                    reason: "timeout",
                },
            );
        } else {
            inner.phase = Phase::Connecting;
            inner.connect = Some(Waiter {
                caller,
                aref,
                deadline: deadline(timeout),
            });
            inner.pending.push((caller, aref));
            // The inet thread may be blocked in a wait that does not include
            // this fd yet. Wake it so the next poll set selects FD_CONNECT.
            poke();
        }
        return ok_bytes(&aref.to_be_bytes());
    }
    err_bytes(errno_name(err))
}

enum Accept {
    Reply(Vec<u8>),
    Now(OwnedFd, u16, Vec<u8>),
}

fn accept_socket(sock: &Arc<Sock>, inner: &mut Inner, caller: Pid, data: &[u8]) -> Accept {
    // Port of inet_drv.c:12144 (INET_REQ_ACCEPT), OTP-29.1.1.
    if inner.phase != Phase::Listening || data.len() != 4 {
        return Accept::Reply(err_bytes("einval"));
    }
    let timeout = u32::from_be_bytes(data[0..4].try_into().unwrap());
    let aref = alloc_async(inner);
    match try_accept(inner) {
        Some(Ok(fd)) => {
            let bytes = ok_bytes(&aref.to_be_bytes());
            Accept::Now(fd, aref, bytes)
        }
        Some(Err(err)) => Accept::Reply(err_bytes(errno_name(err))),
        None => {
            if timeout == 0 {
                emit(
                    sock,
                    Out::AsyncError {
                        caller,
                        aref,
                        reason: "timeout",
                    },
                );
            } else {
                inner.accept_q.push_back(Waiter {
                    caller,
                    aref,
                    deadline: deadline(timeout),
                });
                inner.pending.push((caller, aref));
            }
            Accept::Reply(ok_bytes(&aref.to_be_bytes()))
        }
    }
}

fn try_accept(inner: &Inner) -> Option<Result<OwnedFd, i32>> {
    let fd = inner.fd.as_ref()?.as_raw_fd();
    let mut storage: libc::sockaddr_storage = zeroed();
    let mut len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    // SAFETY: accept returns a fresh descriptor; set close-on-exec before publishing it.
    let (got, cloexec_error) = crate::port::cloexec_publish(|| unsafe {
        let got = libc::accept(
            fd,
            (&mut storage as *mut libc::sockaddr_storage).cast(),
            &mut len,
        );
        if got >= 0 && libc::fcntl(got, libc::F_SETFD, libc::FD_CLOEXEC) < 0 {
            let error = last_errno();
            libc::close(got);
            (-1, Some(error))
        } else {
            (got, None)
        }
    });
    if let Some(error) = cloexec_error {
        return Some(Err(error));
    }
    if got >= 0 {
        set_nonblock(got);
        set_nosigpipe(got);
        // SAFETY: accept returned a fresh descriptor.
        Some(Ok(unsafe { OwnedFd::from_raw_fd(got) }))
    } else {
        let err = last_errno();
        if err == libc::EAGAIN || err == libc::EWOULDBLOCK || err == libc::EINTR {
            None
        } else {
            Some(Err(err))
        }
    }
}

fn install_accepted(listen: &Arc<Sock>, fd: OwnedFd, caller: Pid, aref: u16) {
    let runtime = Arc::clone(&listen.runtime);
    let name = listen.handle.port_name();
    let Ok((id, handle)) = crate::port::alloc_inet_port(&runtime, caller, name) else {
        emit(
            listen,
            Out::AsyncError {
                caller,
                aref,
                reason: "enomem",
            },
        );
        return;
    };
    // Port of inet_drv.c:11795 (tcp_inet_copy), OTP-29.1.1.
    // `active` is not copied here; prim_inet:accept_opts sets it afterwards.
    let born = {
        let inner = listen.inner.lock().unwrap();
        Inner {
            fd: Some(fd),
            domain: inner.domain,
            family_code: inner.family_code,
            phase: Phase::Connected,
            binary: inner.binary,
            htype: inner.htype,
            header: inner.header,
            buffer: inner.buffer,
            buffer_set: inner.buffer_set,
            deliver: inner.deliver,
            exit_on_close: inner.exit_on_close,
            packet_size: inner.packet_size,
            high: inner.high,
            low: inner.low,
            msgq_high: inner.msgq_high,
            msgq_low: inner.msgq_low,
            send_timeout: inner.send_timeout,
            send_timeout_close: inner.send_timeout_close,
            show_econnreset: inner.show_econnreset,
            ..Inner::default()
        }
    };
    pin_scheduler(handle.scheduler());
    let sock = Arc::new(Sock {
        id,
        runtime,
        handle,
        inner: Mutex::new(born),
        io: Mutex::new(()),
    });
    registry().lock().unwrap().insert(id, sock);
    // Port of inet_drv.c:2514 (send_async_ok_port), OTP-29.1.1.
    emit(
        listen,
        Out::AsyncPort {
            caller,
            aref,
            port: id,
        },
    );
    poke();
}

fn sockname(inner: &Inner) -> Vec<u8> {
    // Port of inet_drv.c:4890 (inet_get_address), OTP-29.1.1.
    match name_of(inner, true) {
        Ok(bytes) => ok_bytes(&bytes),
        Err(reason) => err_bytes(reason),
    }
}

fn peername(inner: &Inner) -> Vec<u8> {
    if inner.phase != Phase::Connected {
        return err_bytes("enotconn");
    }
    match name_of(inner, false) {
        Ok(bytes) => ok_bytes(&bytes),
        Err(reason) => err_bytes(reason),
    }
}

fn name_of(inner: &Inner, local: bool) -> Result<Vec<u8>, &'static str> {
    let Some(fd) = inner.fd.as_ref() else {
        return Err("einval");
    };
    let fd = fd.as_raw_fd();
    let mut storage: libc::sockaddr_storage = zeroed();
    let mut len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    // SAFETY: fd is a socket this driver owns; storage is a sockaddr buffer.
    let rc = unsafe {
        if local {
            libc::getsockname(
                fd,
                (&mut storage as *mut libc::sockaddr_storage).cast(),
                &mut len,
            )
        } else {
            libc::getpeername(
                fd,
                (&mut storage as *mut libc::sockaddr_storage).cast(),
                &mut len,
            )
        }
    };
    if rc < 0 {
        return Err(errno_name(last_errno()));
    }
    encode_addr(&storage).ok_or("einval")
}

fn encode_addr(storage: &libc::sockaddr_storage) -> Option<Vec<u8>> {
    // SAFETY: family discriminates the active member of this storage.
    unsafe {
        if storage.ss_family as i32 == libc::AF_INET {
            let addr = &*(storage as *const libc::sockaddr_storage).cast::<libc::sockaddr_in>();
            let port = u16::from_be(addr.sin_port);
            let ip = addr.sin_addr.s_addr.to_ne_bytes();
            let mut out = vec![AF_INET_CODE];
            out.extend_from_slice(&port.to_be_bytes());
            out.extend_from_slice(&ip);
            Some(out)
        } else if storage.ss_family as i32 == libc::AF_INET6 {
            let addr = &*(storage as *const libc::sockaddr_storage).cast::<libc::sockaddr_in6>();
            let port = u16::from_be(addr.sin6_port);
            let mut out = vec![AF_INET6_CODE];
            out.extend_from_slice(&port.to_be_bytes());
            out.extend_from_slice(&addr.sin6_addr.s6_addr);
            Some(out)
        } else if storage.ss_family as i32 == libc::AF_UNIX {
            // Port of inet_drv.c:4916 (inet_get_address AF_UNIX), OTP-29.1.1.
            let addr = &*(storage as *const libc::sockaddr_storage).cast::<libc::sockaddr_un>();
            let path = addr.sun_path;
            let mut n = 0;
            while n < path.len() && path[n] != 0 {
                n += 1;
            }
            let mut out = vec![AF_LOCAL_CODE, n as u8];
            out.extend(path[..n].iter().map(|c| *c as u8));
            Some(out)
        } else {
            None
        }
    }
}

fn setopts(inner: &mut Inner, data: &[u8]) -> Vec<u8> {
    // Port of inet_drv.c:6871 (inet_set_opts), OTP-29.1.1.
    let mut i = 0;
    while i < data.len() {
        let code = data[i];
        i += 1;
        if i + 4 > data.len() {
            return err_bytes("einval");
        }
        let val = i32::from_be_bytes(data[i..i + 4].try_into().unwrap());
        i += 4;
        if !apply_opt(inner, code, val, data, &mut i) {
            return err_bytes("einval");
        }
    }
    ok_bytes(&[])
}

fn apply_opt(inner: &mut Inner, code: u8, val: i32, data: &[u8], i: &mut usize) -> bool {
    match code {
        OPT_REUSEADDR => {
            inner.reuseaddr = val != 0;
            sock_bool(inner, libc::SOL_SOCKET, libc::SO_REUSEADDR, val != 0);
        }
        OPT_KEEPALIVE => {
            inner.keepalive = val != 0;
            sock_bool(inner, libc::SOL_SOCKET, libc::SO_KEEPALIVE, val != 0);
        }
        OPT_LINGER => {
            if *i + 4 > data.len() {
                return false;
            }
            let secs = i32::from_be_bytes(data[*i..*i + 4].try_into().unwrap());
            *i += 4;
            inner.linger_on = val != 0;
            inner.linger_secs = secs;
            sock_linger(inner);
        }
        OPT_SNDBUF => {
            inner.sndbuf = Some(val);
            sock_int(inner, libc::SOL_SOCKET, libc::SO_SNDBUF, val);
        }
        OPT_RCVBUF => {
            // Port of inet_drv.c:7321 (raise buffer when it was not set explicitly).
            inner.recbuf = Some(val);
            if !inner.buffer_set && val > inner.buffer {
                inner.buffer = val;
            }
            sock_int(inner, libc::SOL_SOCKET, libc::SO_RCVBUF, val);
        }
        // SO_PRIORITY is absent on macOS: inet_drv.c:7398 ignores the set.
        OPT_PRIORITY => {}
        OPT_TOS => {
            inner.tos = val;
            if !sock_set(inner, libc::IPPROTO_IP, libc::IP_TOS, val, true) {
                return false;
            }
        }
        OPT_TCLASS => {
            inner.tclass = val;
            if !sock_set(inner, libc::IPPROTO_IPV6, libc::IPV6_TCLASS, val, true) {
                return false;
            }
        }
        OPT_NODELAY => {
            inner.nodelay = val != 0;
            sock_bool(inner, libc::IPPROTO_TCP, libc::TCP_NODELAY, val != 0);
        }
        // TCP_NOPUSH is not wired on Darwin (inet_drv.c:1103). Set is a no-op.
        OPT_NOPUSH => {}
        OPT_BUFFER => {
            // Port of inet_drv.c:6963 (bufsz floored at INET_BUFFER_MIN).
            inner.buffer = val.max(1);
            inner.buffer_set = true;
        }
        OPT_HEADER => inner.header = val,
        OPT_ACTIVE => {
            // Port of inet_drv.c:6968 (any integer is stored; only 3 is {active,N}).
            inner.active_value = val;
            if val == 3 {
                if *i + 2 > data.len() {
                    return false;
                }
                let n = i16::from_be_bytes([data[*i], data[*i + 1]]);
                *i += 2;
                let sum = i32::from(inner.active_count) + i32::from(n);
                if sum > i32::from(i16::MAX) || sum < i32::from(i16::MIN) {
                    return false;
                }
                let mut count = sum as i16;
                if count < 0 {
                    count = 0;
                }
                inner.active_count = count;
                if count == 0 {
                    inner.active = Active::Passive;
                    inner.active_value = 0;
                    inner.emit_passive = true;
                } else {
                    inner.active = Active::Multi;
                }
            } else {
                inner.active_count = 0;
                inner.active = if val == 0 {
                    Active::Passive
                } else if val == 2 {
                    Active::Once
                } else {
                    Active::True
                };
            }
        }
        OPT_PACKET => inner.htype = val,
        OPT_MODE => inner.binary = val == 1,
        OPT_DELIVER => inner.deliver = val,
        OPT_EXIT => inner.exit_on_close = val != 0,
        OPT_HIGH => {
            let val = val.max(0);
            if inner.low > val {
                inner.low = val;
            }
            inner.high = val;
        }
        OPT_LOW => {
            let val = val.max(0);
            if inner.high < val {
                inner.high = val;
            }
            inner.low = val;
        }
        OPT_MSGQ_HIGH | OPT_MSGQ_LOW => {
            // Port of inet_drv.c:7071 (ERL_DRV_BUSY_MSGQ_LIM_MIN/MAX).
            if val < 1 {
                return false;
            }
            if code == OPT_MSGQ_HIGH {
                inner.msgq_high = val;
            } else {
                inner.msgq_low = val;
            }
        }
        OPT_SEND_TIMEOUT => inner.send_timeout = val,
        OPT_SEND_TIMEOUT_CLOSE => inner.send_timeout_close = val != 0,
        OPT_DELAY_SEND => inner.delay_send = val != 0,
        OPT_PACKET_SIZE => inner.packet_size = val as u32,
        OPT_SHOW_ECONNRESET => inner.show_econnreset = val != 0,
        OPT_LINE => inner.delimiter = val as u8,
        OPT_RECVTOS => {
            inner.recvtos = val != 0;
            if !sock_set(inner, libc::IPPROTO_IP, libc::IP_RECVTOS, val, true) {
                return false;
            }
        }
        OPT_TTL => {
            inner.ttl = val;
            if !sock_set(inner, libc::IPPROTO_IP, libc::IP_TTL, val, true) {
                return false;
            }
        }
        OPT_RECVTTL => {
            inner.recvttl = val != 0;
            if !sock_set(inner, libc::IPPROTO_IP, libc::IP_RECVTTL, val, true) {
                return false;
            }
        }
        OPT_REUSEPORT => {
            inner.reuseport = val != 0;
            sock_bool(inner, libc::SOL_SOCKET, libc::SO_REUSEPORT, val != 0);
        }
        // SO_REUSEPORT_LB is absent on macOS: inet_drv.c:7234 ignores the set.
        OPT_REUSEPORT_LB => {}
        OPT_V6ONLY => {
            inner.v6only = val != 0;
            if !sock_set(
                inner,
                libc::IPPROTO_IPV6,
                libc::IPV6_V6ONLY,
                i32::from(val != 0),
                true,
            ) {
                return false;
            }
        }
        // HAVE_SETNS is absent on macOS, so netns falls through to EINVAL.
        OPT_NETNS => return false,
        #[cfg(have_so_bindtodevice)]
        OPT_BIND_TO_DEVICE => {
            // Port of inet_drv.c:7848 (SO_BINDTODEVICE), OTP-29.1.1.
            if val < 0 || val as usize > libc::IFNAMSIZ || *i + val as usize > data.len() {
                return false;
            }
            let name = data[*i..*i + val as usize].to_vec();
            *i += val as usize;
            if !set_bind_device(inner, &name) {
                return false;
            }
        }
        OPT_RAW => {
            if *i + 8 > data.len() {
                return false;
            }
            let opt = i32::from_be_bytes(data[*i..*i + 4].try_into().unwrap());
            *i += 4;
            let size = i32::from_be_bytes(data[*i..*i + 4].try_into().unwrap());
            *i += 4;
            if size < 0 || *i + size as usize > data.len() {
                return false;
            }
            let bytes = &data[*i..*i + size as usize];
            *i += size as usize;
            if !sock_set_raw(inner, val, opt, bytes) {
                return false;
            }
        }
        OPT_DEBUG => inner.debug = val != 0,
        _ => return false,
    }
    true
}

fn getopts(inner: &Inner, data: &[u8]) -> Vec<u8> {
    // Port of inet_drv.c:9071 (inet_fill_opts), OTP-29.1.1.
    let mut out = Vec::new();
    let mut i = 0;
    while i < data.len() {
        let code = data[i];
        i += 1;
        if !push_opt(inner, code, data, &mut i, &mut out) {
            return err_bytes("einval");
        }
    }
    ok_bytes(&out)
}

fn push_opt(inner: &Inner, code: u8, data: &[u8], i: &mut usize, out: &mut Vec<u8>) -> bool {
    let write_i32 = |out: &mut Vec<u8>, value: i32| {
        out.push(code);
        put_i32(out, value);
    };
    match code {
        OPT_REUSEADDR => write_i32(
            out,
            i32::from(sock_get_bool(
                inner,
                libc::SOL_SOCKET,
                libc::SO_REUSEADDR,
                inner.reuseaddr,
            )),
        ),
        OPT_KEEPALIVE => write_i32(
            out,
            i32::from(sock_get_bool(
                inner,
                libc::SOL_SOCKET,
                libc::SO_KEEPALIVE,
                inner.keepalive,
            )),
        ),
        OPT_LINGER => {
            let (on, secs) = sock_get_linger(inner);
            out.push(code);
            put_i32(out, i32::from(on));
            put_i32(out, secs);
        }
        OPT_SNDBUF => {
            if let Some(value) = sock_get_int(inner, libc::SOL_SOCKET, libc::SO_SNDBUF) {
                write_i32(out, value);
            }
        }
        OPT_RCVBUF => {
            if let Some(value) = sock_get_int(inner, libc::SOL_SOCKET, libc::SO_RCVBUF) {
                write_i32(out, value);
            }
        }
        // inet_drv.c:9321 returns 0 when SO_PRIORITY is missing.
        OPT_PRIORITY => write_i32(out, 0),
        OPT_TOS => {
            if let Some(value) = sock_get_int(inner, libc::IPPROTO_IP, libc::IP_TOS) {
                write_i32(out, value);
            }
        }
        OPT_TCLASS => {
            if let Some(value) = sock_get_int(inner, libc::IPPROTO_IPV6, libc::IPV6_TCLASS) {
                write_i32(out, value);
            }
        }
        OPT_NODELAY => {
            if let Some(value) = sock_get_int(inner, libc::IPPROTO_TCP, libc::TCP_NODELAY) {
                write_i32(out, i32::from(value != 0));
            }
        }
        // inet_drv.c:9457 returns 0 when INET_TCP_NOPUSH is not defined.
        OPT_NOPUSH => write_i32(out, 0),
        OPT_BUFFER => write_i32(out, inner.buffer),
        OPT_HEADER => write_i32(out, inner.header),
        OPT_ACTIVE => {
            // Port of inet_drv.c:9176 (inet_fill_opts active), OTP-29.1.1.
            write_i32(out, inner.active_value);
            if inner.active_value == 3 {
                out.extend_from_slice(&inner.active_count.to_be_bytes());
            }
        }
        OPT_PACKET => write_i32(out, inner.htype),
        OPT_MODE => write_i32(out, i32::from(inner.binary)),
        OPT_DELIVER => write_i32(out, inner.deliver),
        OPT_EXIT => write_i32(out, i32::from(inner.exit_on_close)),
        OPT_HIGH => write_i32(out, inner.high),
        OPT_LOW => write_i32(out, inner.low),
        OPT_MSGQ_HIGH => write_i32(out, inner.msgq_high),
        OPT_MSGQ_LOW => write_i32(out, inner.msgq_low),
        OPT_SEND_TIMEOUT => write_i32(out, inner.send_timeout),
        OPT_SEND_TIMEOUT_CLOSE => write_i32(out, i32::from(inner.send_timeout_close)),
        OPT_DELAY_SEND => write_i32(out, i32::from(inner.delay_send)),
        OPT_PACKET_SIZE => write_i32(out, inner.packet_size as i32),
        OPT_SHOW_ECONNRESET => write_i32(out, i32::from(inner.show_econnreset)),
        // inet_fill_opts has no LINE_DELIM case, so getopts returns einval.
        OPT_LINE => return false,
        OPT_RECVTOS => {
            if let Some(value) = sock_get_int(inner, libc::IPPROTO_IP, libc::IP_RECVTOS) {
                write_i32(out, i32::from(value != 0));
            }
        }
        OPT_TTL => {
            if let Some(value) = sock_get_int(inner, libc::IPPROTO_IP, libc::IP_TTL) {
                write_i32(out, value);
            }
        }
        OPT_RECVTTL => {
            if let Some(value) = sock_get_int(inner, libc::IPPROTO_IP, libc::IP_RECVTTL) {
                write_i32(out, i32::from(value != 0));
            }
        }
        OPT_REUSEPORT => {
            if let Some(value) = sock_get_int(inner, libc::SOL_SOCKET, libc::SO_REUSEPORT) {
                write_i32(out, i32::from(value != 0));
            }
        }
        // inet_drv.c:9400 returns 0 when SO_REUSEPORT_LB is missing.
        OPT_REUSEPORT_LB => write_i32(out, 0),
        OPT_V6ONLY => {
            if let Some(value) = sock_get_int(inner, libc::IPPROTO_IPV6, libc::IPV6_V6ONLY) {
                write_i32(out, i32::from(value != 0));
            }
        }
        OPT_RAW => {
            if *i + 13 > data.len() {
                return false;
            }
            let proto = i32::from_be_bytes(data[*i..*i + 4].try_into().unwrap());
            *i += 4;
            let opt = i32::from_be_bytes(data[*i..*i + 4].try_into().unwrap());
            *i += 4;
            let provided = data[*i];
            *i += 1;
            let size = i32::from_be_bytes(data[*i..*i + 4].try_into().unwrap());
            *i += 4;
            if size < 0 || size as usize > MAX_OPT_BUFFER {
                return false;
            }
            if provided != 0 {
                if *i + size as usize > data.len() {
                    return false;
                }
                *i += size as usize;
            }
            // A failed getsockopt omits the option (inet_drv.c:9584).
            if let Some(bytes) = sock_get_raw(inner, proto, opt, size as usize) {
                out.push(code);
                put_i32(out, proto);
                put_i32(out, opt);
                put_i32(out, bytes.len() as i32);
                out.extend_from_slice(&bytes);
            }
        }
        OPT_DEBUG => write_i32(out, i32::from(inner.debug)),
        #[cfg(have_so_bindtodevice)]
        OPT_BIND_TO_DEVICE => {
            // Port of inet_drv.c:9599 (getsockopt SO_BINDTODEVICE), OTP-29.1.1.
            if let Some(name) = get_bind_device(inner) {
                out.push(code);
                put_i32(out, name.len() as i32);
                out.extend_from_slice(&name);
            }
        }
        OPT_NETNS => return false,
        _ => return false,
    }
    true
}

fn getstat(inner: &Inner, data: &[u8]) -> Vec<u8> {
    // Port of inet_drv.c:10732 (inet_fill_stat), OTP-29.1.1.
    let mut out = Vec::new();
    for &code in data {
        out.push(code);
        match code {
            1 => put_u32(&mut out, inner.recv_cnt),
            2 => put_u32(&mut out, inner.recv_max as u32),
            3 => put_u32(&mut out, trunc_stat(inner.recv_avg)),
            4 => put_u32(&mut out, trunc_stat(inner.recv_dvi.abs())),
            5 => put_u32(&mut out, inner.send_cnt),
            6 => put_u32(&mut out, inner.send_max as u32),
            7 => put_u32(&mut out, trunc_stat(inner.send_avg)),
            8 => put_u32(&mut out, inner.sendq.len() as u32),
            9 => put_u64(&mut out, inner.recv_oct),
            10 => put_u64(&mut out, inner.send_oct),
            _ => return err_bytes("einval"),
        }
    }
    ok_bytes(&out)
}

fn trunc_stat(value: f64) -> u32 {
    if value <= 0.0 {
        0
    } else if value >= u32::MAX as f64 {
        u32::MAX
    } else {
        value as u32
    }
}

fn gettype(inner: &Inner) -> Vec<u8> {
    // Port of inet_drv.c:11165 (INET_REQ_GETTYPE), OTP-29.1.1.
    if inner.fd.is_none() {
        return err_bytes("exbadport");
    }
    let mut out = Vec::with_capacity(8);
    put_u32(&mut out, u32::from(inner.family_code));
    put_u32(&mut out, 1);
    ok_bytes(&out)
}

fn getstatus(inner: &Inner) -> Vec<u8> {
    // Port of inet_drv.c:1026 (INET_STATE_*), OTP-29.1.1.
    let mut flags = 0u32;
    if inner.fd.is_some() {
        flags |= F_OPEN;
    }
    match inner.phase {
        Phase::Listening => flags |= F_LISTEN,
        Phase::Connecting => flags |= F_CON,
        Phase::Connected => flags |= F_ACTIVE,
        Phase::Closed | Phase::Open | Phase::Bound => {}
    }
    if !inner.accept_q.is_empty() {
        flags |= F_ACC;
    }
    if inner.busy {
        flags |= F_BUSY;
    }
    ok_bytes(&flags.to_be_bytes())
}

fn subscribe(inner: &Inner, data: &[u8]) -> Vec<u8> {
    // Port of prim_inet.erl subs_empty_out_q / inet_drv INET_REQ_SUBSCRIBE, OTP-29.1.1.
    let mut out = Vec::new();
    for &code in data {
        if code != 1 {
            return err_bytes("einval");
        }
        out.push(1);
        put_u32(&mut out, inner.sendq.len() as u32);
    }
    ok_bytes(&out)
}

pub(crate) fn getiflist() -> Vec<u8> {
    // Port of inet_drv.c:5671 (inet_ctl_getiflist), OTP-29.1.1.
    let Ok(buf) = ifconf_buf() else {
        return err_bytes("einval");
    };
    let mut out = Vec::new();
    let mut i = 0;
    let ifreq = std::mem::size_of::<libc::ifreq>();
    let name_len = libc::IFNAMSIZ;
    while i + name_len + 2 <= buf.len() {
        let sa_len = buf[i + name_len] as usize;
        let sa_size = sa_len.max(std::mem::size_of::<libc::sockaddr>());
        let mut n = name_len + sa_size;
        if n < ifreq {
            n = ifreq;
        }
        if i + n > buf.len() {
            break;
        }
        let family = i32::from(buf[i + name_len + 1]);
        if family == libc::AF_INET || family == libc::AF_INET6 {
            let name = &buf[i..i + name_len];
            let end = name.iter().position(|b| *b == 0).unwrap_or(name.len());
            out.extend_from_slice(&name[..end]);
            out.push(0);
        }
        i += n;
    }
    ok_bytes(&out)
}

fn ifconf_buf() -> Result<Vec<u8>, i32> {
    // SAFETY: a datagram socket is used only as an ioctl target; close-on-exec is
    // set before another scheduler can spawn a child while this descriptor is open.
    let fd = crate::port::cloexec_publish(|| unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
        if fd >= 0 && libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) < 0 {
            libc::close(fd);
            -2
        } else {
            fd
        }
    });
    if fd == -2 {
        return Err(libc::EIO);
    }
    if fd < 0 {
        return Err(last_errno());
    }
    let mut buflen = 100 * std::mem::size_of::<libc::ifreq>();
    let mut buf = vec![0u8; buflen];
    let mut prev = 0i32;
    let result = loop {
        let mut ifc = libc::ifconf {
            ifc_len: buf.len() as i32,
            ifc_ifcu: libc::__c_anonymous_ifc_ifcu {
                ifcu_buf: buf.as_mut_ptr().cast(),
            },
        };
        // SAFETY: fd is the socket just opened; ifc points at buf.
        let rc = unsafe { libc::ioctl(fd, libc::SIOCGIFCONF, &mut ifc) };
        if rc < 0 {
            let err = last_errno();
            if err != libc::EINVAL || prev != 0 {
                break Err(err);
            }
        } else if ifc.ifc_len == prev {
            buf.truncate(ifc.ifc_len as usize);
            break Ok(buf);
        } else {
            prev = ifc.ifc_len;
        }
        buflen += 10 * std::mem::size_of::<libc::ifreq>();
        buf.resize(buflen, 0);
    };
    // SAFETY: fd is the socket this function opened.
    unsafe { libc::close(fd) };
    result
}

pub(crate) fn ifget(data: &[u8]) -> Vec<u8> {
    // Port of inet_drv.c:5821 (inet_ctl_ifget), OTP-29.1.1.
    if data.is_empty() {
        return err_bytes("einval");
    }
    let namlen = data[0] as usize;
    if namlen + 1 > data.len() {
        return err_bytes("einval");
    }
    let name = &data[1..1 + namlen];
    let mut out = Vec::new();
    for &opt in &data[1 + namlen..] {
        match opt {
            IFOPT_ADDR => {
                if let Some(bytes) = ifreq_sockaddr(name, libc::SIOCGIFADDR) {
                    out.push(opt);
                    out.extend_from_slice(&bytes);
                }
            }
            IFOPT_BROADADDR => {
                if let Some(bytes) = ifreq_sockaddr(name, libc::SIOCGIFBRDADDR) {
                    out.push(opt);
                    out.extend_from_slice(&bytes);
                }
            }
            IFOPT_DSTADDR => {
                if let Some(bytes) = ifreq_sockaddr(name, libc::SIOCGIFDSTADDR) {
                    out.push(opt);
                    out.extend_from_slice(&bytes);
                }
            }
            IFOPT_NETMASK => {
                if let Some(bytes) = ifreq_sockaddr(name, libc::SIOCGIFNETMASK) {
                    out.push(opt);
                    out.extend_from_slice(&bytes);
                }
            }
            IFOPT_FLAGS => {
                if let Some(flags) = ifreq_flags(name) {
                    out.push(opt);
                    put_i32(&mut out, flags);
                }
            }
            IFOPT_HWADDR => {
                if let Some(hw) = hwaddr(name) {
                    out.push(opt);
                    put_i32(&mut out, hw.len() as i32);
                    // inet_drv.c:5911 writes a big-endian int16 length, not int32.
                    out.truncate(out.len() - 4);
                    out.extend_from_slice(&(hw.len() as u16).to_be_bytes());
                    out.extend_from_slice(&hw);
                }
            }
            _ => {}
        }
    }
    ok_bytes(&out)
}

fn ifreq_sockaddr(name: &[u8], req: u64) -> Option<Vec<u8>> {
    let mut storage = zeroed::<libc::sockaddr_storage>();
    ifreq_ioctl(name, req, |ifr| {
        // SAFETY: ioctl wrote a sockaddr into the ifreq union.
        unsafe {
            std::ptr::copy_nonoverlapping(
                (&ifr.ifr_ifru.ifru_addr as *const libc::sockaddr).cast::<u8>(),
                (&mut storage as *mut libc::sockaddr_storage).cast(),
                std::mem::size_of::<libc::sockaddr>(),
            );
        }
    })?;
    sockaddr_body(&storage)
}

fn ifreq_flags(name: &[u8]) -> Option<i32> {
    let mut flags = 0i16;
    ifreq_ioctl(name, libc::SIOCGIFFLAGS, |ifr| {
        // SAFETY: SIOCGIFFLAGS writes ifr_flags into the ifreq union.
        flags = unsafe { ifr.ifr_ifru.ifru_flags };
    })?;
    Some(ifget_flags(flags as u32))
}

fn ifreq_ioctl(name: &[u8], req: u64, read: impl FnOnce(libc::ifreq)) -> Option<()> {
    // SAFETY: a datagram socket is used only as an ioctl target; close-on-exec is
    // set before another scheduler can spawn a child while this descriptor is open.
    let fd = crate::port::cloexec_publish(|| unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
        if fd >= 0 && libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) < 0 {
            libc::close(fd);
            -2
        } else {
            fd
        }
    });
    if fd == -2 {
        return None;
    }
    if fd < 0 {
        return None;
    }
    let mut ifr = zeroed::<libc::ifreq>();
    let n = name.len().min(libc::IFNAMSIZ - 1);
    // SAFETY: ifr_name is IFNAMSIZ bytes and n leaves a trailing NUL.
    unsafe {
        std::ptr::copy_nonoverlapping(name.as_ptr(), ifr.ifr_name.as_mut_ptr().cast(), n);
    }
    // SAFETY: fd is the socket just opened; ifr is a writable ifreq.
    let rc = unsafe { libc::ioctl(fd, req, &mut ifr) };
    // SAFETY: fd is the socket just opened.
    unsafe { libc::close(fd) };
    if rc < 0 {
        return None;
    }
    read(ifr);
    Some(())
}

fn ifget_flags(cflags: u32) -> i32 {
    // Port of inet_drv.c:5476 (IFGET_FLAGS), OTP-29.1.1.
    let mut flags = 0i32;
    if cflags & libc::IFF_UP as u32 != 0 {
        flags |= IFF_UP | IFF_RUNNING;
    }
    if cflags & libc::IFF_BROADCAST as u32 != 0 {
        flags |= IFF_BROADCAST;
    }
    if cflags & libc::IFF_LOOPBACK as u32 != 0 {
        flags |= IFF_LOOPBACK;
    }
    if cflags & libc::IFF_POINTOPOINT as u32 != 0 {
        flags |= IFF_POINTTOPOINT;
    }
    if cflags & libc::IFF_MULTICAST as u32 != 0 {
        flags |= IFF_MULTICAST;
    }
    flags
}

fn hwaddr(name: &[u8]) -> Option<Vec<u8>> {
    // Port of inet_drv.c:5888 (HAVE_GETIFADDRS && AF_LINK), OTP-29.1.1.
    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs writes a list we free below.
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return None;
    }
    let mut found = None;
    let mut cur = head;
    while !cur.is_null() {
        // SAFETY: cur is a live ifaddrs node from getifaddrs.
        let ifa = unsafe { &*cur };
        let family = if ifa.ifa_addr.is_null() {
            -1
        } else {
            // SAFETY: ifa_addr is non-null.
            unsafe { (*ifa.ifa_addr).sa_family as i32 }
        };
        if family == libc::AF_LINK && name_eq(ifa.ifa_name, name) {
            found = link_addr(ifa.ifa_addr);
            break;
        }
        cur = ifa.ifa_next;
    }
    // SAFETY: head came from getifaddrs.
    unsafe { libc::freeifaddrs(head) };
    found.filter(|hw| hw.len() + 2 > 3)
}

fn name_eq(ptr: *const libc::c_char, name: &[u8]) -> bool {
    if ptr.is_null() {
        return false;
    }
    // SAFETY: getifaddrs names are NUL-terminated.
    let c = unsafe { std::ffi::CStr::from_ptr(ptr) };
    c.to_bytes() == name
}

fn link_addr(addr: *const libc::sockaddr) -> Option<Vec<u8>> {
    // SAFETY: AF_LINK sockaddr_dl begins with the fixed header before sdl_data.
    unsafe {
        let raw = addr.cast::<u8>();
        let alen = *raw.add(6) as usize;
        let nlen = *raw.add(5) as usize;
        let data = raw.add(8);
        let mut hw = vec![0u8; alen];
        std::ptr::copy_nonoverlapping(data.add(nlen), hw.as_mut_ptr(), alen);
        Some(hw)
    }
}

pub(crate) fn getifaddrs_reply() -> Vec<u8> {
    // Port of inet_drv.c:6611 (inet_ctl_getifaddrs), OTP-29.1.1.
    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs writes a list we free below.
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return err_bytes(errno_name(last_errno()));
    }
    let mut out = Vec::new();
    let mut cur = head;
    while !cur.is_null() {
        // SAFETY: cur is a live ifaddrs node from getifaddrs.
        let ifa = unsafe { &*cur };
        if !ifa.ifa_name.is_null() {
            // SAFETY: ifa_name is a NUL-terminated C string from getifaddrs.
            let name = unsafe { std::ffi::CStr::from_ptr(ifa.ifa_name) };
            out.extend_from_slice(name.to_bytes());
        }
        out.push(0);
        out.push(IFOPT_FLAGS);
        put_i32(&mut out, ifget_flags(ifa.ifa_flags));
        if !ifa.ifa_addr.is_null() {
            // SAFETY: ifa_addr is non-null.
            let family = unsafe { (*ifa.ifa_addr).sa_family as i32 };
            if family == libc::AF_INET || family == libc::AF_INET6 || family == 0 {
                push_ifaddr(&mut out, IFOPT_ADDR, ifa.ifa_addr);
                if !ifa.ifa_netmask.is_null() {
                    push_ifaddr(&mut out, IFOPT_NETMASK, ifa.ifa_netmask);
                }
                let p2p = ifa.ifa_flags & libc::IFF_POINTOPOINT as u32 != 0;
                let bcast = ifa.ifa_flags & libc::IFF_BROADCAST as u32 != 0;
                if p2p && !ifa.ifa_dstaddr.is_null() {
                    push_ifaddr(&mut out, IFOPT_DSTADDR, ifa.ifa_dstaddr);
                } else if bcast && !ifa.ifa_dstaddr.is_null() {
                    push_ifaddr(&mut out, IFOPT_BROADADDR, ifa.ifa_dstaddr);
                }
            } else if family == libc::AF_LINK
                && let Some(hw) = link_addr(ifa.ifa_addr)
                && hw.len() + 2 > 3
            {
                out.push(IFOPT_HWADDR);
                out.extend_from_slice(&(hw.len() as u16).to_be_bytes());
                out.extend_from_slice(&hw);
            }
        }
        out.push(0);
        cur = ifa.ifa_next;
    }
    // SAFETY: head came from getifaddrs.
    unsafe { libc::freeifaddrs(head) };
    ok_bytes(&out)
}

fn push_ifaddr(out: &mut Vec<u8>, opt: u8, addr: *const libc::sockaddr) {
    // SAFETY: addr is a non-null sockaddr from getifaddrs.
    let storage = unsafe {
        let mut storage = zeroed::<libc::sockaddr_storage>();
        std::ptr::copy_nonoverlapping(
            addr.cast::<u8>(),
            (&mut storage as *mut libc::sockaddr_storage).cast(),
            (*addr).sa_len as usize,
        );
        storage
    };
    if let Some(body) = sockaddr_body(&storage) {
        out.push(opt);
        out.extend_from_slice(&body);
    }
}

fn sockaddr_body(storage: &libc::sockaddr_storage) -> Option<Vec<u8>> {
    // Port of inet_drv.c:5373 (sockaddr_to_buf), OTP-29.1.1.
    // SAFETY: family discriminates the active member of this storage.
    unsafe {
        if storage.ss_family as i32 == libc::AF_INET || storage.ss_family == 0 {
            let addr = &*(storage as *const libc::sockaddr_storage).cast::<libc::sockaddr_in>();
            let mut out = vec![AF_INET_CODE];
            out.extend_from_slice(&addr.sin_addr.s_addr.to_ne_bytes());
            Some(out)
        } else if storage.ss_family as i32 == libc::AF_INET6 {
            let addr = &*(storage as *const libc::sockaddr_storage).cast::<libc::sockaddr_in6>();
            let mut out = vec![AF_INET6_CODE];
            out.extend_from_slice(&addr.sin6_addr.s6_addr);
            Some(out)
        } else {
            None
        }
    }
}

fn recv_req(inner: &mut Inner, caller: Pid, data: &[u8]) -> Vec<u8> {
    // Port of inet_drv.c:12268 (TCP_REQ_RECV), OTP-29.1.1.
    if inner.peer_closed {
        return err_bytes(close_atom(inner));
    }
    if inner.phase != Phase::Connected {
        return err_bytes("enotconn");
    }
    if active_is(&inner.active) || data.len() != 8 {
        return err_bytes("einval");
    }
    let timeout = u32::from_be_bytes(data[0..4].try_into().unwrap());
    let length = i32::from_be_bytes(data[4..8].try_into().unwrap());
    if inner.htype != 0 && length != 0 {
        return err_bytes("einval");
    }
    if !(0..=TCP_MAX_PACKET).contains(&length) {
        return err_bytes("enomem");
    }
    if inner.recv.is_some() {
        return err_bytes("ealready");
    }
    let aref = alloc_async(inner);
    inner.recv = Some(Recv {
        caller,
        aref,
        length: length as u32,
        deadline: deadline(timeout),
    });
    inner.pending.push((caller, aref));
    if timeout == 0 {
        inner.recv_timeout_if_empty = true;
    }
    ok_bytes(&aref.to_be_bytes())
}

fn shutdown_sock(inner: &Inner, data: &[u8]) -> Vec<u8> {
    // Port of inet_drv.c:12339 (TCP_REQ_SHUTDOWN), OTP-29.1.1.
    if inner.phase != Phase::Connected {
        return err_bytes("enotconn");
    }
    if data.len() != 1 || data[0] > 2 {
        return err_bytes("einval");
    }
    let fd = inner.fd.as_ref().unwrap().as_raw_fd();
    // SAFETY: fd is the connected socket this driver owns.
    let rc = unsafe { libc::shutdown(fd, i32::from(data[0])) };
    if rc < 0 {
        return err_bytes(errno_name(last_errno()));
    }
    ok_bytes(&[])
}

fn active_is(active: &Active) -> bool {
    !matches!(active, Active::Passive)
}

fn alloc_async(inner: &mut Inner) -> u16 {
    // Port of inet_drv.c:1549 (NEW_ASYNC_ID), OTP-29.1.1.
    let id = inner.op_ref;
    inner.op_ref = inner.op_ref.wrapping_add(1);
    id
}

fn deadline(timeout: u32) -> Option<Instant> {
    if timeout == INFINITY {
        None
    } else {
        Some(Instant::now() + Duration::from_millis(u64::from(timeout)))
    }
}

fn output_count(inner: &mut Inner, len: usize) {
    // Port of inet_drv.c:11560 (inet_output_count), OTP-29.1.1.
    let mut n = inner.send_cnt.wrapping_add(1);
    if n == 0 {
        n = 1;
    }
    let len = len as f64;
    let avg = inner.send_avg;
    inner.send_oct = inner.send_oct.wrapping_add(len as u64);
    inner.send_avg = avg + (len - avg) / f64::from(n);
    if len > inner.send_max as f64 {
        inner.send_max = len as u64;
    }
    inner.send_cnt = n;
}

fn input_count(inner: &mut Inner, len: usize) {
    // Port of inet_drv.c:11585 (inet_input_count), OTP-29.1.1.
    let mut n = inner.recv_cnt.wrapping_add(1);
    if n == 0 {
        n = 1;
    }
    let len_f = len as f64;
    let avg = inner.recv_avg + (len_f - inner.recv_avg) / f64::from(n);
    inner.recv_avg = avg;
    inner.recv_oct = inner.recv_oct.wrapping_add(len as u64);
    if len as u64 > inner.recv_max {
        inner.recv_max = len as u64;
    }
    let dvi = inner.recv_dvi;
    inner.recv_dvi = dvi + ((len_f - avg) - dvi) / f64::from(n);
    inner.recv_cnt = n;
}

fn flush_send(inner: &mut Inner) -> Option<i32> {
    let fd = inner.fd.as_ref()?;
    let fd = fd.as_raw_fd();
    while !inner.sendq.is_empty() {
        let buf: Vec<u8> = inner.sendq.iter().copied().collect();
        // SAFETY: fd is the connected socket this driver owns.
        let n = unsafe { libc::write(fd, buf.as_ptr().cast(), buf.len()) };
        if n > 0 {
            inner.sendq.drain(..n as usize);
        } else if n < 0 {
            let err = last_errno();
            if err == libc::EAGAIN || err == libc::EWOULDBLOCK || err == libc::EINTR {
                break;
            }
            inner.sendq.clear();
            return Some(err);
        } else {
            break;
        }
    }
    release_unbusy(inner);
    None
}

fn release_unbusy(inner: &mut Inner) {
    if inner.busy && inner.sendq.len() <= inner.low.max(0) as usize {
        inner.busy = false;
        inner.ready.append(&mut inner.send_waits);
    }
}

fn emit_ready(sock: &Sock) {
    let ready = {
        let mut inner = sock.inner.lock().unwrap();
        std::mem::take(&mut inner.ready)
    };
    for wait in ready {
        emit(
            sock,
            Out::InetReply {
                caller: wait.caller,
                ids: wait.ids,
                error: None,
            },
        );
    }
}

fn close_atom(inner: &Inner) -> &'static str {
    if inner.reset { "econnreset" } else { "closed" }
}

struct Sock {
    id: u64,
    runtime: Arc<Runtime>,
    handle: Arc<PortHandle>,
    inner: Mutex<Inner>,
    /// Serializes taking packets from the receive buffer with emitting them, which happens
    /// after `inner` is released.
    ///
    /// Port of erts/emulator/beam/erl_port_task.c:1677 (erts_port_task_execute), OTP-29.1.1:
    /// one thread at a time executes a port's tasks, so the packets a callback takes from
    /// the receive buffer reach the owner (or `erts_net_message`) in buffer order.
    io: Mutex<()>,
}

impl Sock {
    fn new(id: u64, runtime: Arc<Runtime>, handle: Arc<PortHandle>) -> Self {
        Self {
            id,
            runtime,
            handle,
            inner: Mutex::new(Inner::default()),
            io: Mutex::new(()),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Closed,
    Open,
    Bound,
    Listening,
    Connecting,
    Connected,
}

#[derive(Clone, Copy)]
enum Active {
    Passive,
    True,
    Once,
    Multi,
}

struct Waiter {
    caller: Pid,
    aref: u16,
    deadline: Option<Instant>,
}

struct Recv {
    caller: Pid,
    aref: u16,
    length: u32,
    deadline: Option<Instant>,
}

struct SendWait {
    caller: Pid,
    ids: [u32; 3],
    deadline: Option<Instant>,
}

struct Inner {
    fd: Option<OwnedFd>,
    domain: i32,
    family_code: u8,
    phase: Phase,
    // Port of inet_drv.c:10891 (inet_start defaults), OTP-29.1.1.
    binary: bool,
    active: Active,
    /// Raw `INET_LOPT_ACTIVE` value. Values other than 0..3 stay active.
    active_value: i32,
    active_count: i16,
    htype: i32,
    header: i32,
    buffer: i32,
    buffer_set: bool,
    deliver: i32,
    exit_on_close: bool,
    delimiter: u8,
    packet_size: u32,
    reuseaddr: bool,
    reuseport: bool,
    nodelay: bool,
    keepalive: bool,
    v6only: bool,
    sndbuf: Option<i32>,
    recbuf: Option<i32>,
    tos: i32,
    tclass: i32,
    ttl: i32,
    delay_send: bool,
    recvtos: bool,
    recvttl: bool,
    show_econnreset: bool,
    debug: bool,
    high: i32,
    low: i32,
    msgq_high: i32,
    msgq_low: i32,
    send_timeout: i32,
    send_timeout_close: bool,
    linger_on: bool,
    linger_secs: i32,
    backlog: i32,
    op_ref: u16,
    rbuf: Vec<u8>,
    sendq: VecDeque<u8>,
    recv: Option<Recv>,
    accept_q: VecDeque<Waiter>,
    connect: Option<Waiter>,
    pending: Vec<(Pid, u16)>,
    send_waits: Vec<SendWait>,
    ready: Vec<SendWait>,
    busy: bool,
    emit_passive: bool,
    peer_closed: bool,
    /// Read or send observed ECONNRESET (or show_econnreset mapped EPIPE).
    reset: bool,
    closed_sent: bool,
    recv_timeout_if_empty: bool,
    http: PacketState,
    recv_cnt: u32,
    send_cnt: u32,
    recv_max: u64,
    send_max: u64,
    recv_avg: f64,
    recv_dvi: f64,
    send_avg: f64,
    recv_oct: u64,
    send_oct: u64,
}

impl Default for Inner {
    fn default() -> Self {
        Self {
            fd: None,
            domain: libc::AF_INET,
            family_code: AF_INET_CODE,
            phase: Phase::Closed,
            binary: false,
            active: Active::Passive,
            active_value: 0,
            active_count: 0,
            htype: 0,
            header: 0,
            buffer: 9216,
            buffer_set: false,
            deliver: 1,
            exit_on_close: true,
            delimiter: b'\n',
            packet_size: 0,
            reuseaddr: false,
            reuseport: false,
            nodelay: false,
            keepalive: false,
            v6only: false,
            sndbuf: None,
            recbuf: None,
            tos: 0,
            tclass: 0,
            ttl: 0,
            delay_send: false,
            recvtos: false,
            recvttl: false,
            show_econnreset: false,
            debug: false,
            high: 8 * 1024,
            low: 4 * 1024,
            msgq_high: 8 * 1024,
            msgq_low: 8 * 1024,
            send_timeout: -1,
            send_timeout_close: false,
            linger_on: false,
            linger_secs: 0,
            backlog: 5,
            op_ref: 0,
            rbuf: Vec::new(),
            sendq: VecDeque::new(),
            recv: None,
            accept_q: VecDeque::new(),
            connect: None,
            pending: Vec::new(),
            send_waits: Vec::new(),
            ready: Vec::new(),
            busy: false,
            emit_passive: false,
            peer_closed: false,
            reset: false,
            closed_sent: false,
            recv_timeout_if_empty: false,
            http: PacketState::default(),
            recv_cnt: 0,
            send_cnt: 0,
            recv_max: 0,
            send_max: 0,
            recv_avg: 0.0,
            recv_dvi: 0.0,
            send_avg: 0.0,
            recv_oct: 0,
            send_oct: 0,
        }
    }
}

fn apply_saved(inner: &mut Inner) {
    let reuse = inner.reuseaddr;
    let keep = inner.keepalive;
    let nodelay = inner.nodelay;
    let snd = inner.sndbuf;
    let rcv = inner.recbuf;
    let tos = inner.tos;
    let ttl = inner.ttl;
    sock_bool(inner, libc::SOL_SOCKET, libc::SO_REUSEADDR, reuse);
    sock_bool(inner, libc::SOL_SOCKET, libc::SO_KEEPALIVE, keep);
    sock_bool(inner, libc::IPPROTO_TCP, libc::TCP_NODELAY, nodelay);
    if let Some(v) = snd {
        sock_int(inner, libc::SOL_SOCKET, libc::SO_SNDBUF, v);
    }
    if let Some(v) = rcv {
        sock_int(inner, libc::SOL_SOCKET, libc::SO_RCVBUF, v);
    }
    if tos != 0 {
        sock_int(inner, libc::IPPROTO_IP, libc::IP_TOS, tos);
    }
    if ttl != 0 {
        sock_int(inner, libc::IPPROTO_IP, libc::IP_TTL, ttl);
    }
    if inner.linger_on {
        sock_linger(inner);
    }
}

fn sock_bool(inner: &Inner, level: i32, name: i32, on: bool) {
    sock_int(inner, level, name, i32::from(on));
}

fn sock_int(inner: &Inner, level: i32, name: i32, val: i32) {
    let Some(fd) = inner.fd.as_ref() else {
        return;
    };
    // SAFETY: fd is a socket this driver owns. A failed setsockopt leaves the saved value.
    unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            level,
            name,
            (&val as *const i32).cast(),
            std::mem::size_of::<i32>() as libc::socklen_t,
        );
    }
}

fn sock_linger(inner: &Inner) {
    let Some(fd) = inner.fd.as_ref() else {
        return;
    };
    let lin = libc::linger {
        l_onoff: i32::from(inner.linger_on),
        l_linger: inner.linger_secs,
    };
    // SAFETY: fd is a socket this driver owns.
    unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_LINGER,
            (&lin as *const libc::linger).cast(),
            std::mem::size_of::<libc::linger>() as libc::socklen_t,
        );
    }
}

fn sock_get_int(inner: &Inner, level: i32, name: i32) -> Option<i32> {
    let fd = inner.fd.as_ref()?;
    let mut val = 0i32;
    let mut len = std::mem::size_of::<i32>() as libc::socklen_t;
    // SAFETY: fd is a socket this driver owns.
    let rc = unsafe {
        libc::getsockopt(
            fd.as_raw_fd(),
            level,
            name,
            (&mut val as *mut i32).cast(),
            &mut len,
        )
    };
    (rc == 0).then_some(val)
}

fn sock_set(inner: &Inner, level: i32, name: i32, val: i32, propagate: bool) -> bool {
    let Some(fd) = inner.fd.as_ref() else {
        return !propagate;
    };
    // SAFETY: fd is a socket this driver owns.
    let rc = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            level,
            name,
            (&val as *const i32).cast(),
            std::mem::size_of::<i32>() as libc::socklen_t,
        )
    };
    rc == 0 || !propagate
}

fn sock_set_raw(inner: &Inner, level: i32, name: i32, bytes: &[u8]) -> bool {
    let Some(fd) = inner.fd.as_ref() else {
        return false;
    };
    // SAFETY: fd is a socket this driver owns; bytes is the option payload.
    let rc = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            level,
            name,
            bytes.as_ptr().cast(),
            bytes.len() as libc::socklen_t,
        )
    };
    rc == 0
}

fn sock_get_raw(inner: &Inner, level: i32, name: i32, size: usize) -> Option<Vec<u8>> {
    let fd = inner.fd.as_ref()?;
    let mut buf = vec![0u8; size];
    let mut len = size as libc::socklen_t;
    // SAFETY: fd is a socket this driver owns; buf is writable for `len` bytes.
    let rc = unsafe {
        libc::getsockopt(
            fd.as_raw_fd(),
            level,
            name,
            buf.as_mut_ptr().cast(),
            &mut len,
        )
    };
    if rc != 0 {
        return None;
    }
    buf.truncate(len as usize);
    Some(buf)
}

fn sock_get_bool(inner: &Inner, level: i32, name: i32, fallback: bool) -> bool {
    sock_get_int(inner, level, name)
        .map(|value| value != 0)
        .unwrap_or(fallback)
}

fn sock_get_linger(inner: &Inner) -> (bool, i32) {
    let Some(fd) = inner.fd.as_ref() else {
        return (inner.linger_on, inner.linger_secs);
    };
    let mut lin = libc::linger {
        l_onoff: 0,
        l_linger: 0,
    };
    let mut len = std::mem::size_of::<libc::linger>() as libc::socklen_t;
    // SAFETY: fd is a socket this driver owns.
    let rc = unsafe {
        libc::getsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_LINGER,
            (&mut lin as *mut libc::linger).cast(),
            &mut len,
        )
    };
    if rc == 0 {
        (lin.l_onoff != 0, lin.l_linger)
    } else {
        (inner.linger_on, inner.linger_secs)
    }
}

enum Dest {
    V4(libc::sockaddr_in),
    V6(libc::sockaddr_in6),
    Local(libc::sockaddr_un, libc::socklen_t),
}

impl Dest {
    fn call(&self, f: impl FnOnce(*const libc::sockaddr, libc::socklen_t) -> i32) -> i32 {
        match self {
            Dest::V4(addr) => f(
                (addr as *const libc::sockaddr_in).cast(),
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            ),
            Dest::V6(addr) => f(
                (addr as *const libc::sockaddr_in6).cast(),
                std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
            ),
            Dest::Local(addr, len) => f((addr as *const libc::sockaddr_un).cast(), *len),
        }
    }
}

fn parse_dest(domain: i32, data: &[u8]) -> Result<Dest, &'static str> {
    // Port of inet_drv.c:4795 (inet_set_faddress), OTP-29.1.1.
    if data.is_empty() {
        return Err("einval");
    }
    let family = data[0];
    if family == AF_LOCAL_CODE {
        return parse_local(&data[1..]);
    }
    if data.len() < 3 {
        return Err("einval");
    }
    let port = u16::from_be_bytes([data[1], data[2]]);
    match family {
        AF_INET_CODE if domain == libc::AF_INET && data.len() >= 7 => {
            Ok(Dest::V4(v4(port, data[3..7].try_into().unwrap())))
        }
        AF_INET6_CODE if domain == libc::AF_INET6 && data.len() >= 19 => {
            Ok(Dest::V6(v6(port, data[3..19].try_into().unwrap())))
        }
        AF_ANY if domain == libc::AF_INET => Ok(Dest::V4(v4(port, [0, 0, 0, 0]))),
        AF_ANY if domain == libc::AF_INET6 => Ok(Dest::V6(v6(port, [0; 16]))),
        AF_LOOPBACK if domain == libc::AF_INET => Ok(Dest::V4(v4(port, [127, 0, 0, 1]))),
        AF_LOOPBACK if domain == libc::AF_INET6 => {
            let mut ip = [0u8; 16];
            ip[15] = 1;
            Ok(Dest::V6(v6(port, ip)))
        }
        AF_INET_CODE | AF_INET6_CODE | AF_ANY | AF_LOOPBACK => Err("einval"),
        _ => Err("eafnosupport"),
    }
}

fn parse_local(data: &[u8]) -> Result<Dest, &'static str> {
    // Port of inet_drv.c:4748 (AF_UNIX address), OTP-29.1.1.
    if data.is_empty() {
        return Err("einval");
    }
    let n = data[0] as usize;
    if data.len() < 1 + n {
        return Err("einval");
    }
    if n + 1
        > std::mem::size_of::<libc::sockaddr_un>()
            - std::mem::offset_of!(libc::sockaddr_un, sun_path)
    {
        return Err("einval");
    }
    let mut addr = zeroed::<libc::sockaddr_un>();
    addr.sun_family = libc::AF_UNIX as u8;
    for (i, byte) in data[1..1 + n].iter().enumerate() {
        addr.sun_path[i] = *byte as libc::c_char;
    }
    let len = (std::mem::offset_of!(libc::sockaddr_un, sun_path) + n) as libc::socklen_t;
    addr.sun_len = len as u8;
    Ok(Dest::Local(addr, len))
}

fn v4(port: u16, ip: [u8; 4]) -> libc::sockaddr_in {
    let mut addr: libc::sockaddr_in = zeroed();
    addr.sin_len = std::mem::size_of::<libc::sockaddr_in>() as u8;
    addr.sin_family = libc::AF_INET as u8;
    addr.sin_port = port.to_be();
    addr.sin_addr.s_addr = u32::from_ne_bytes(ip);
    addr
}

fn v6(port: u16, ip: [u8; 16]) -> libc::sockaddr_in6 {
    let mut addr: libc::sockaddr_in6 = zeroed();
    addr.sin6_len = std::mem::size_of::<libc::sockaddr_in6>() as u8;
    addr.sin6_family = libc::AF_INET6 as u8;
    addr.sin6_port = port.to_be();
    addr.sin6_addr.s6_addr = ip;
    addr
}

// g_inet_udp
pub(crate) fn ok_bytes(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + data.len());
    out.push(1);
    out.extend_from_slice(data);
    out
}

// g_inet_udp
pub(crate) fn err_bytes(reason: &str) -> Vec<u8> {
    // Port of inet_drv.c:2300 (ctl_error), OTP-29.1.1.
    let mut out = Vec::with_capacity(1 + reason.len());
    out.push(0);
    out.extend_from_slice(reason.as_bytes());
    out
}

fn put_i32(out: &mut Vec<u8>, val: i32) {
    out.extend_from_slice(&val.to_be_bytes());
}

fn put_u32(out: &mut Vec<u8>, val: u32) {
    out.extend_from_slice(&val.to_be_bytes());
}

fn put_u64(out: &mut Vec<u8>, val: u64) {
    out.extend_from_slice(&val.to_be_bytes());
}

// g_inet_udp
pub(crate) fn byte_list(process: &mut Process, bytes: &[u8]) -> Result<Term, VmError> {
    let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
    TermBuilder::new(&mut heap)
        .list_from_iter(bytes.iter().map(|b| Term::small(i64::from(*b)).unwrap()))
        .map_err(|error| VmError::Unsupported(format!("inet control reply: {error:?}")))
}

// g_inet_udp
pub(crate) fn split_caller(data: &[u8]) -> Option<([u32; 3], &[u8])> {
    if data.len() < 2 {
        return None;
    }
    let n = u16::from_be_bytes([data[0], data[1]]) as usize;
    if data.len() < 2 + n {
        return None;
    }
    let ids = decode_local_ref(&data[2..2 + n])?;
    Some((ids, &data[2 + n..]))
}

fn decode_local_ref(bytes: &[u8]) -> Option<[u32; 3]> {
    // Port of erts/emulator/beam/external.c LOCAL_EXT + NEW_REFERENCE_EXT, OTP-29.1.1.
    let mut i = 0;
    if bytes.first() == Some(&131) {
        i = 1;
    }
    if bytes.get(i) == Some(&121) {
        i += 5;
    }
    if bytes.get(i) != Some(&90) {
        return None;
    }
    i += 1;
    let n = u16::from_be_bytes([*bytes.get(i)?, *bytes.get(i + 1)?]) as usize;
    i += 2;
    if bytes.get(i) != Some(&106) {
        return None;
    }
    i += 1;
    i += 4;
    if n < 3 || bytes.len() < i + 12 {
        return None;
    }
    let mut ids = [0u32; 3];
    for id in &mut ids {
        *id = u32::from_be_bytes(bytes[i..i + 4].try_into().ok()?);
        i += 4;
    }
    Some(ids)
}

// g_inet_udp
pub(crate) fn last_errno() -> i32 {
    std::io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(libc::EINVAL)
}

// g_inet_udp
pub(crate) fn errno_name(code: i32) -> &'static str {
    // Names match erl_errno_id / prim_inet list_to_atom of the driver string.
    match code {
        libc::EAGAIN => "eagain",
        libc::EINPROGRESS => "einprogress",
        libc::EALREADY => "ealready",
        libc::EINVAL => "einval",
        libc::ENOTCONN => "enotconn",
        libc::EISCONN => "eisconn",
        libc::EADDRINUSE => "eaddrinuse",
        libc::EADDRNOTAVAIL => "eaddrnotavail",
        libc::ECONNREFUSED => "econnrefused",
        libc::ECONNRESET => "econnreset",
        libc::ETIMEDOUT => "etimedout",
        libc::EPIPE => "epipe",
        libc::EACCES => "eacces",
        libc::EPERM => "eperm",
        libc::ENOMEM => "enomem",
        libc::ENOBUFS => "enobufs",
        libc::EAFNOSUPPORT => "eafnosupport",
        libc::EPROTONOSUPPORT => "eprotonosupport",
        libc::ENETUNREACH => "enetunreach",
        libc::EHOSTUNREACH => "ehostunreach",
        libc::EMFILE | libc::ENFILE => "emfile",
        libc::ENOENT => "enoent",
        libc::EOPNOTSUPP => "eopnotsupp",
        libc::ENOPROTOOPT => "enoprotoopt",
        libc::EDESTADDRREQ => "edestaddrreq",
        libc::EMSGSIZE => "emsgsize",
        _ => "einval",
    }
}

enum Out {
    AsyncError {
        caller: Pid,
        aref: u16,
        reason: &'static str,
    },
    AsyncOk {
        caller: Pid,
        aref: u16,
    },
    AsyncPort {
        caller: Pid,
        aref: u16,
        port: u64,
    },
    AsyncData {
        caller: Pid,
        aref: u16,
        bytes: Vec<u8>,
    },
    InetReply {
        caller: Pid,
        ids: [u32; 3],
        error: Option<&'static str>,
    },
    Tcp {
        owner: Pid,
        bytes: Vec<u8>,
    },
    TcpClosed {
        owner: Pid,
    },
    TcpError {
        owner: Pid,
        reason: &'static str,
    },
    TcpPassive {
        owner: Pid,
    },
    Http {
        owner: Pid,
        packet: HttpPacket,
        binary: bool,
    },
    AsyncHttp {
        caller: Pid,
        aref: u16,
        packet: HttpPacket,
        binary: bool,
    },
    PortData {
        owner: Pid,
        bytes: Vec<u8>,
    },
}

fn emit(sock: &Sock, out: Out) {
    // Distribution ports feed the emulator decoder, not the port owner.
    // Port of inet_drv.c + dist.c:2017 (erts_net_message), OTP-29.1.1.
    if let Out::PortData { bytes, .. } = &out
        && crate::node_tables::is_dist_port(sock.id)
    {
        let _ = crate::dist::ingest_port_data(&sock.runtime, sock.id, bytes);
        return;
    }
    if let Out::TcpClosed { .. } = &out
        && crate::node_tables::is_dist_port(sock.id)
    {
        let _ = crate::dist::port_connection_closed(&sock.runtime, sock.id);
        // Still deliver tcp_closed to the connection ticker so it shuts down.
    }
    let sched = sock.handle.scheduler();
    let port = Term::port(sock.id).unwrap();
    let mut heap = ProcessHeap::with_words(128);
    let term = match &out {
        Out::AsyncError {
            caller,
            aref,
            reason,
        } => error_tuple(&mut heap, reason)
            .and_then(|status| message_async(&mut heap, port, *aref, status))
            .map(|term| (*caller, term)),
        Out::AsyncOk { caller, aref } => {
            message_async(&mut heap, port, *aref, atom("ok")).map(|term| (*caller, term))
        }
        Out::AsyncPort {
            caller,
            aref,
            port: born,
        } => {
            let born = Term::port(*born).unwrap();
            let status = TermBuilder::new(&mut heap).tuple(&[atom("ok"), born]).ok();
            status.and_then(|status| {
                message_async(&mut heap, port, *aref, status).map(|term| (*caller, term))
            })
        }
        Out::AsyncData {
            caller,
            aref,
            bytes,
        } => {
            let data = data_term(sock, &mut heap, bytes);
            let status =
                data.and_then(|data| TermBuilder::new(&mut heap).tuple(&[atom("ok"), data]).ok());
            status.and_then(|status| {
                message_async(&mut heap, port, *aref, status).map(|term| (*caller, term))
            })
        }
        Out::InetReply { caller, ids, error } => {
            let status = if let Some(reason) = error {
                error_tuple(&mut heap, reason)
            } else {
                Some(atom("ok"))
            };
            let tag = TermBuilder::new(&mut heap).local_ref(*ids).ok();
            match (status, tag) {
                (Some(status), Some(tag)) => TermBuilder::new(&mut heap)
                    .tuple(&[atom("inet_reply"), port, status, tag])
                    .ok()
                    .map(|term| (*caller, term)),
                _ => None,
            }
        }
        Out::Tcp { owner, bytes } => {
            // Port of inet_drv.c:3987 (tcp_message), OTP-29.1.1.
            data_term(sock, &mut heap, bytes)
                .and_then(|data| {
                    TermBuilder::new(&mut heap)
                        .tuple(&[atom("tcp"), port, data])
                        .ok()
                })
                .map(|term| (*owner, term))
        }
        Out::TcpClosed { owner } => TermBuilder::new(&mut heap)
            .tuple(&[atom("tcp_closed"), port])
            .ok()
            .map(|term| (*owner, term)),
        Out::TcpError { owner, reason } => TermBuilder::new(&mut heap)
            .tuple(&[atom("tcp_error"), port, atom(reason)])
            .ok()
            .map(|term| (*owner, term)),
        Out::TcpPassive { owner } => TermBuilder::new(&mut heap)
            .tuple(&[atom("tcp_passive"), port])
            .ok()
            .map(|term| (*owner, term)),
        Out::Http {
            owner,
            packet,
            binary,
        } => http_message(&mut heap, port, packet, *binary).map(|term| (*owner, term)),
        Out::AsyncHttp {
            caller,
            aref,
            packet,
            binary,
        } => http_value(&mut heap, packet, *binary)
            .and_then(|value| TermBuilder::new(&mut heap).tuple(&[atom("ok"), value]).ok())
            .and_then(|status| message_async(&mut heap, port, *aref, status))
            .map(|term| (*caller, term)),
        Out::PortData { owner, bytes } => data_term(sock, &mut heap, bytes)
            .and_then(|data| {
                TermBuilder::new(&mut heap)
                    .tuple(&[atom("data"), data])
                    .ok()
            })
            .and_then(|data| TermBuilder::new(&mut heap).tuple(&[port, data]).ok())
            .map(|term| (*owner, term)),
    };
    if let Some((to, term)) = term
        && let Ok(message) = Message::copy_from(term)
    {
        let _ = sched.send(to, to, message);
    }
}

fn message_async(heap: &mut ProcessHeap, port: Term, aref: u16, status: Term) -> Option<Term> {
    // Port of inet_drv.c:2493 (send_async_ok / send_async_error), OTP-29.1.1.
    TermBuilder::new(heap)
        .tuple(&[
            atom("inet_async"),
            port,
            Term::small(i64::from(aref)).unwrap(),
            status,
        ])
        .ok()
}

fn error_tuple(heap: &mut ProcessHeap, reason: &str) -> Option<Term> {
    TermBuilder::new(heap)
        .tuple(&[atom("error"), atom(reason)])
        .ok()
}

fn http_message(
    heap: &mut ProcessHeap,
    port: Term,
    packet: &HttpPacket,
    binary: bool,
) -> Option<Term> {
    // Port of inet_drv.c:2832 ({http, S, HttpTerm}), OTP-29.1.1.
    let value = http_value(heap, packet, binary)?;
    TermBuilder::new(heap)
        .tuple(&[atom("http"), port, value])
        .ok()
}

fn http_value(heap: &mut ProcessHeap, packet: &HttpPacket, binary: bool) -> Option<Term> {
    // Port of inet_drv.c:2811 (http_*_inetdrv), OTP-29.1.1.
    match packet {
        HttpPacket::Eoh => Some(atom("http_eoh")),
        HttpPacket::Error(line) => {
            let text = bytes_term(heap, line, binary)?;
            TermBuilder::new(heap)
                .tuple(&[atom("http_error"), text])
                .ok()
        }
        HttpPacket::Response {
            major,
            minor,
            status,
            phrase,
        } => {
            let version = TermBuilder::new(heap)
                .tuple(&[
                    Term::small(i64::from(*major)).unwrap(),
                    Term::small(i64::from(*minor)).unwrap(),
                ])
                .ok()?;
            let phrase = bytes_term(heap, phrase, binary)?;
            TermBuilder::new(heap)
                .tuple(&[
                    atom("http_response"),
                    version,
                    Term::small(i64::from(*status)).unwrap(),
                    phrase,
                ])
                .ok()
        }
        HttpPacket::Request {
            method,
            known_method,
            uri,
            major,
            minor,
        } => {
            let method = if *known_method {
                atom(std::str::from_utf8(method).unwrap_or("GET"))
            } else {
                bytes_term(heap, method, binary)?
            };
            let uri = uri_term(heap, uri, binary)?;
            let version = TermBuilder::new(heap)
                .tuple(&[
                    Term::small(i64::from(*major)).unwrap(),
                    Term::small(i64::from(*minor)).unwrap(),
                ])
                .ok()?;
            TermBuilder::new(heap)
                .tuple(&[atom("http_request"), method, uri, version])
                .ok()
        }
        HttpPacket::Header {
            index,
            known_name,
            name,
            original_name,
            value,
        } => {
            let name = if let Some(known) = known_name {
                atom(known)
            } else {
                bytes_term(heap, name, binary)?
            };
            let original = bytes_term(heap, original_name, binary)?;
            let value = bytes_term(heap, value, binary)?;
            TermBuilder::new(heap)
                .tuple(&[
                    atom("http_header"),
                    Term::small(*index as i64).unwrap(),
                    name,
                    original,
                    value,
                ])
                .ok()
        }
    }
}

fn uri_term(heap: &mut ProcessHeap, uri: &HttpUri, binary: bool) -> Option<Term> {
    // Port of inet_drv.c http_load_uri, OTP-29.1.1.
    match uri {
        HttpUri::Star => Some(atom("*")),
        HttpUri::String(s) => bytes_term(heap, s, binary),
        HttpUri::AbsPath(s) => {
            let path = bytes_term(heap, s, binary)?;
            TermBuilder::new(heap).tuple(&[atom("abs_path"), path]).ok()
        }
        HttpUri::Scheme { scheme, rest } => {
            let scheme = bytes_term(heap, scheme, binary)?;
            let rest = bytes_term(heap, rest, binary)?;
            TermBuilder::new(heap)
                .tuple(&[atom("scheme"), scheme, rest])
                .ok()
        }
        HttpUri::Absolute {
            scheme,
            host,
            port,
            path,
        } => {
            let host = bytes_term(heap, host, binary)?;
            let path = bytes_term(heap, path, binary)?;
            let port = match port {
                Some(p) => Term::small(i64::from(*p)).unwrap(),
                None => atom("undefined"),
            };
            TermBuilder::new(heap)
                .tuple(&[atom("absoluteURI"), atom(scheme), host, port, path])
                .ok()
        }
    }
}

fn bytes_term(heap: &mut ProcessHeap, bytes: &[u8], binary: bool) -> Option<Term> {
    let mut builder = TermBuilder::new(heap);
    if binary {
        builder.binary(bytes).ok()
    } else {
        builder
            .list_from_iter(bytes.iter().map(|b| Term::small(i64::from(*b)).unwrap()))
            .ok()
    }
}

fn data_term(sock: &Sock, heap: &mut ProcessHeap, bytes: &[u8]) -> Option<Term> {
    let (binary, hsz) = {
        let inner = sock.inner.lock().unwrap();
        (inner.binary, inner.header)
    };
    // Port of inet_drv.c:4000 (list, or [H1..Hsz | Binary]), OTP-29.1.1.
    let mut builder = TermBuilder::new(heap);
    let hsz = if hsz < 0 { bytes.len() } else { hsz as usize };
    if !binary || hsz > bytes.len() {
        return builder
            .list_from_iter(bytes.iter().map(|b| Term::small(i64::from(*b)).unwrap()))
            .ok();
    }
    let mut tail = builder.binary(&bytes[hsz..]).ok()?;
    for byte in bytes[..hsz].iter().rev() {
        tail = builder
            .cons(Term::small(i64::from(*byte)).unwrap(), tail)
            .ok()?;
    }
    Some(tail)
}

fn drop_pending(inner: &mut Inner, caller: Pid, aref: u16) {
    inner.pending.retain(|(c, r)| *c != caller || *r != aref);
}

fn try_io(sock: &Arc<Sock>, writable_ready: bool) {
    // Port of erts/emulator/sys/common/erl_check_io.c:2098-2109, OTP-29.1.1: oready
    // runs before iready for one fd.
    if writable_ready {
        tcp_inet_output(sock);
    }
    satisfy(sock);
    let eof = pull(sock);
    satisfy(sock);
    if eof {
        on_eof(sock);
    }
    let connect_done = {
        let mut inner = sock.inner.lock().unwrap();
        if writable_ready && inner.phase == Phase::Connecting {
            poll_connect(&mut inner)
        } else {
            None
        }
    };
    if let Some(out) = connect_done {
        emit(sock, out);
    }
    // A zero timeout is "try once" (inet_drv.c TCP_REQ_RECV timeout == 0).
    let timed_out = {
        let mut inner = sock.inner.lock().unwrap();
        if inner.recv_timeout_if_empty && inner.recv.is_some() {
            let recv = inner.recv.take().unwrap();
            inner.recv_timeout_if_empty = false;
            drop_pending(&mut inner, recv.caller, recv.aref);
            Some((recv.caller, recv.aref))
        } else {
            inner.recv_timeout_if_empty = false;
            None
        }
    };
    if let Some((caller, aref)) = timed_out {
        emit(
            sock,
            Out::AsyncError {
                caller,
                aref,
                reason: "timeout",
            },
        );
    }
    // Passive EOF is remembered; `{active, true}` must still emit `{tcp_closed,S}`.
    deliver_pending_close(sock);
    emit_ready(sock);
    let busy = sock.inner.lock().unwrap().busy;
    crate::dist::distribution_port_state_changed(&sock.runtime, sock.id, busy);
}

/// Write queued output once the poll set reports the connected socket writable.
///
/// Port of erts/emulator/drivers/common/inet_drv.c:14289-14361, OTP-29.1.1
/// (`tcp_inet_output`, connected branch): send from the driver queue until it is
/// empty or the socket would block, and drop the busy state at the low watermark
/// (`release_unbusy`; the deferred `inet_reply` goes out through `emit_ready`).
/// The output callback runs whether or not the owner has a receive pending, so a
/// passive socket whose owner is blocked in `gen_tcp:send/2` still drains. The
/// write selection follows the queue: `io_loop` selects for write only while
/// `sendq` is non-empty (inet_drv.c:14302-14303 deselects when it is empty).
fn tcp_inet_output(sock: &Arc<Sock>) {
    let failure = {
        let mut inner = sock.inner.lock().unwrap();
        if inner.phase != Phase::Connected || inner.sendq.is_empty() {
            return;
        }
        let Some(err) = flush_send(&mut inner) else {
            return;
        };
        // Port of inet_drv.c:13690-13720 (tcp_send_error) and :13613-13688
        // (tcp_send_or_shutdown_error), OTP-29.1.1: the blocked senders get the
        // error reply; an active socket also gets `tcp_closed`.
        let waits = std::mem::take(&mut inner.send_waits);
        match send_failed(&mut inner, err) {
            SendOutcome::Failed { error, active } => (waits, error, active),
            SendOutcome::Reply(_) | SendOutcome::Deferred => return,
        }
    };
    let (waits, error, active) = failure;
    for wait in waits {
        emit(
            sock,
            Out::InetReply {
                caller: wait.caller,
                ids: wait.ids,
                error: Some(error),
            },
        );
    }
    if active {
        let owner = sock.handle.owner_pid();
        if error == "econnreset" {
            emit(
                sock,
                Out::TcpError {
                    owner,
                    reason: "econnreset",
                },
            );
        }
        emit(sock, Out::TcpClosed { owner });
        if sock.inner.lock().unwrap().exit_on_close {
            crate::port::abandon_port(&sock.runtime, sock.id);
        }
    }
}

fn deliver_pending_close(sock: &Arc<Sock>) {
    // Port of inet_drv.c:7001 (inet_set_opts active while INET_STATE_CLOSED), OTP-29.1.1.
    let (owner, exit_on_close) = {
        let mut inner = sock.inner.lock().unwrap();
        if !inner.peer_closed || inner.closed_sent || !active_is(&inner.active) {
            return;
        }
        inner.closed_sent = true;
        (sock.handle.owner_pid(), inner.exit_on_close)
    };
    emit(sock, Out::TcpClosed { owner });
    if exit_on_close {
        crate::port::abandon_port(&sock.runtime, sock.id);
    }
}

fn satisfy(sock: &Arc<Sock>) {
    let _io = sock.io.lock().unwrap_or_else(|poison| poison.into_inner());
    let (outs, abandon) = {
        let mut inner = sock.inner.lock().unwrap();
        let mut outs = Vec::new();
        let abandon = take_packets(&sock.handle, &mut inner, &mut outs);
        (outs, abandon)
    };
    for out in outs {
        emit(sock, out);
    }
    if abandon {
        crate::port::abandon_port(&sock.runtime, sock.id);
    }
}

fn take_packets(handle: &PortHandle, inner: &mut Inner, outs: &mut Vec<Out>) -> bool {
    if inner.phase != Phase::Connected {
        return false;
    }
    if inner.recv.is_some() {
        if inner.htype == 0 {
            let recv = inner.recv.as_ref().unwrap();
            let ready = if recv.length == 0 {
                !inner.rbuf.is_empty()
            } else {
                inner.rbuf.len() >= recv.length as usize
            };
            if ready {
                let n = if recv.length == 0 {
                    inner.rbuf.len()
                } else {
                    recv.length as usize
                };
                let bytes: Vec<u8> = inner.rbuf.drain(..n).collect();
                let recv = inner.recv.take().unwrap();
                drop_pending(inner, recv.caller, recv.aref);
                input_count(inner, bytes.len());
                push_data(inner, outs, DataWho::Async(recv.caller, recv.aref), bytes);
            }
        } else {
            match next_frame(inner) {
                Read::Ready(frame, used) => {
                    let recv = inner.recv.take().unwrap();
                    drop_pending(inner, recv.caller, recv.aref);
                    input_count(inner, used);
                    push_frame(inner, outs, DataWho::Async(recv.caller, recv.aref), frame);
                }
                Read::Wait => {}
                Read::Bad => return packet_error(handle, inner, outs),
            }
        }
    }
    while active_is(&inner.active) {
        let owner = handle.owner_pid();
        if inner.htype == 0 {
            if inner.rbuf.is_empty() {
                break;
            }
            let bytes = std::mem::take(&mut inner.rbuf);
            input_count(inner, bytes.len());
            push_data(inner, outs, DataWho::Active(owner), bytes);
        } else {
            match next_frame(inner) {
                Read::Ready(frame, used) => {
                    input_count(inner, used);
                    push_frame(inner, outs, DataWho::Active(owner), frame);
                }
                Read::Wait => break,
                Read::Bad => return packet_error(handle, inner, outs),
            }
        }
        note_active(inner, owner, outs);
    }
    false
}

fn packet_error(handle: &PortHandle, inner: &mut Inner, outs: &mut Vec<Out>) -> bool {
    // Port of inet_drv.c:13170 (tcp_recv → tcp_recv_error EMSGSIZE), OTP-29.1.1.
    if let Some(recv) = inner.recv.take() {
        drop_pending(inner, recv.caller, recv.aref);
        outs.push(Out::AsyncError {
            caller: recv.caller,
            aref: recv.aref,
            reason: "emsgsize",
        });
    }
    inner.rbuf.clear();
    inner.fd.take();
    inner.phase = Phase::Closed;
    let active = active_is(&inner.active) && !inner.closed_sent;
    if active {
        inner.closed_sent = true;
        let owner = handle.owner_pid();
        outs.push(Out::TcpError {
            owner,
            reason: "emsgsize",
        });
        outs.push(Out::TcpClosed { owner });
    }
    active && inner.exit_on_close
}

enum DataWho {
    Active(Pid),
    Async(Pid, u16),
}

fn push_data(inner: &Inner, outs: &mut Vec<Out>, who: DataWho, bytes: Vec<u8>) {
    // Port of inet_drv.c:4287 (deliver == PORT skips packet_parse), OTP-29.1.1.
    if inner.deliver == DELIVER_PORT
        && let DataWho::Active(owner) = who
    {
        outs.push(Out::PortData { owner, bytes });
        return;
    }
    match who {
        DataWho::Active(owner) => outs.push(Out::Tcp { owner, bytes }),
        DataWho::Async(caller, aref) => outs.push(Out::AsyncData {
            caller,
            aref,
            bytes,
        }),
    }
}

fn push_frame(inner: &Inner, outs: &mut Vec<Out>, who: DataWho, frame: Frame) {
    let binary = inner.htype >= 13;
    match frame {
        Frame::Bytes(bytes) => push_data(inner, outs, who, bytes),
        Frame::Http(packet) => match who {
            DataWho::Active(owner) if inner.deliver != DELIVER_PORT => {
                outs.push(Out::Http {
                    owner,
                    packet,
                    binary,
                });
            }
            DataWho::Async(caller, aref) if inner.deliver != DELIVER_PORT => {
                outs.push(Out::AsyncHttp {
                    caller,
                    aref,
                    packet,
                    binary,
                });
            }
            _ => {}
        },
    }
}

enum Frame {
    Bytes(Vec<u8>),
    Http(HttpPacket),
}

enum Read {
    Ready(Frame, usize),
    Wait,
    Bad,
}

fn next_frame(inner: &mut Inner) -> Read {
    let Some(ty) = packet_type(inner.htype) else {
        return Read::Wait;
    };
    let opts = PacketOptions {
        packet_size: inner.packet_size,
        line_length: 0,
        line_delimiter: inner.delimiter,
    };
    let parsed = parse_with_state(ty, &inner.rbuf, opts, &mut inner.http);
    match parsed {
        PacketResult::Ok { packet, rest } => {
            let used = inner.rbuf.len() - rest.len();
            let frame = match packet {
                Packet::Bytes(bytes) => Frame::Bytes(bytes.to_vec()),
                Packet::Http(http) => Frame::Http(http),
                Packet::SslTls { data, .. } => Frame::Bytes(data),
            };
            inner.rbuf.drain(..used);
            Read::Ready(frame, used)
        }
        PacketResult::More(_) => Read::Wait,
        // Port of inet_drv.c:13033 (tcp_remain packet error), OTP-29.1.1.
        PacketResult::Error => Read::Bad,
    }
}

fn packet_type(htype: i32) -> Option<PacketType> {
    // Port of erts/emulator/beam/packet_parser.h TCP_PB_*, OTP-29.1.1.
    Some(match htype {
        1 => PacketType::Length1,
        2 => PacketType::Length2,
        3 => PacketType::Length4,
        4 => PacketType::Asn1,
        5 => PacketType::Sunrm,
        6 => PacketType::Cdr,
        7 => PacketType::Fcgi,
        8 => PacketType::Line,
        9 => PacketType::Tpkt,
        10 => PacketType::Http,
        11 => PacketType::Httph,
        13 => PacketType::HttpBin,
        14 => PacketType::HttphBin,
        _ => return None,
    })
}

fn note_active(inner: &mut Inner, owner: Pid, outs: &mut Vec<Out>) {
    // Port of inet_drv.c:1552 (INET_CHECK_ACTIVE_TO_PASSIVE), OTP-29.1.1.
    match inner.active {
        Active::Once => {
            inner.active = Active::Passive;
            inner.active_value = 0;
        }
        Active::Multi => {
            inner.active_count -= 1;
            if inner.active_count <= 0 {
                inner.active_count = 0;
                inner.active = Active::Passive;
                inner.active_value = 0;
                outs.push(Out::TcpPassive { owner });
            }
        }
        Active::True | Active::Passive => {}
    }
}

// Darwin's SO_BINDTODEVICE is 0x1134 (sys/socket.h); the libc crate does not name it there.
#[cfg(all(have_so_bindtodevice, target_os = "macos"))]
const SO_BINDTODEVICE: i32 = 0x1134;
#[cfg(all(have_so_bindtodevice, not(target_os = "macos")))]
const SO_BINDTODEVICE: i32 = libc::SO_BINDTODEVICE;

#[cfg(have_so_bindtodevice)]
fn set_bind_device(inner: &Inner, name: &[u8]) -> bool {
    let mut buf = [0u8; 16];
    let n = name.len().min(buf.len() - 1);
    buf[..n].copy_from_slice(&name[..n]);
    sock_set_raw(inner, libc::SOL_SOCKET, SO_BINDTODEVICE, &buf)
}

#[cfg(have_so_bindtodevice)]
fn get_bind_device(inner: &Inner) -> Option<Vec<u8>> {
    let bytes = sock_get_raw(inner, libc::SOL_SOCKET, SO_BINDTODEVICE, 16)?;
    let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    Some(bytes[..end].to_vec())
}

fn pull(sock: &Arc<Sock>) -> bool {
    let phase = sock.inner.lock().unwrap().phase;
    if phase == Phase::Listening {
        pull_accept(sock);
        return false;
    }
    let (eof, bytes_read) = {
        let mut inner = sock.inner.lock().unwrap();
        // Port of inet_drv.c:2819 (sock_select only while active or receiving).
        // A passive socket must leave the FIN unread so `{active, true}` still
        // observes it and emits `{tcp_closed, S}`.
        let want_read = inner.phase == Phase::Connected
            && inner.fd.is_some()
            && !inner.peer_closed
            && (active_is(&inner.active) || inner.recv.is_some());
        if !want_read {
            return false;
        }
        let fd = inner.fd.as_ref().unwrap().as_raw_fd();
        let mut buf = vec![0u8; inner.buffer.max(1) as usize];
        let mut eof = false;
        let mut bytes_read = 0;
        for _ in 0..32 {
            // SAFETY: fd is the connected socket this driver owns.
            let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
            if n > 0 {
                bytes_read += n as usize;
                inner.rbuf.extend_from_slice(&buf[..n as usize]);
            } else if n == 0 {
                eof = true;
                break;
            } else {
                let err = last_errno();
                if err == libc::ECONNRESET {
                    inner.reset = true;
                    eof = true;
                }
                break;
            }
        }
        let _ = flush_send(&mut inner);
        (eof, bytes_read)
    };
    if bytes_read > 0 && crate::node_tables::is_dist_port(sock.id) && crate::debug_env::trace_dist()
    {
        eprintln!("DIST_SOCKET_READ port={} bytes={bytes_read}", sock.id);
    }
    eof
}

fn pull_accept(sock: &Arc<Sock>) {
    loop {
        let accepted = {
            let inner = sock.inner.lock().unwrap();
            if inner.accept_q.is_empty() {
                return;
            }
            try_accept(&inner)
        };
        match accepted {
            Some(Ok(fd)) => {
                let waiter = {
                    let mut inner = sock.inner.lock().unwrap();
                    inner.accept_q.pop_front().inspect(|waiter| {
                        drop_pending(&mut inner, waiter.caller, waiter.aref);
                    })
                };
                if let Some(waiter) = waiter {
                    install_accepted(sock, fd, waiter.caller, waiter.aref);
                }
            }
            Some(Err(err)) => {
                let waiter = {
                    let mut inner = sock.inner.lock().unwrap();
                    inner.accept_q.pop_front().inspect(|waiter| {
                        drop_pending(&mut inner, waiter.caller, waiter.aref);
                    })
                };
                if let Some(waiter) = waiter {
                    emit(
                        sock,
                        Out::AsyncError {
                            caller: waiter.caller,
                            aref: waiter.aref,
                            reason: errno_name(err),
                        },
                    );
                }
            }
            None => return,
        }
    }
}

fn on_eof(sock: &Arc<Sock>) {
    // Port of inet_drv.c:12783 (tcp_recv_closed) and :12849 (tcp_recv_error), OTP-29.1.1.
    let (active, exit_on_close, owner, reason) = {
        let mut inner = sock.inner.lock().unwrap();
        if inner.peer_closed {
            return;
        }
        inner.peer_closed = true;
        inner.rbuf.clear();
        let active = active_is(&inner.active);
        let owner = sock.handle.owner_pid();
        let reason = close_atom(&inner);
        if !active {
            if inner.exit_on_close {
                inner.fd.take();
            }
            let recv = inner.recv.take();
            if let Some(recv) = recv {
                drop_pending(&mut inner, recv.caller, recv.aref);
                let caller = recv.caller;
                let aref = recv.aref;
                drop(inner);
                emit(
                    sock,
                    Out::AsyncError {
                        caller,
                        aref,
                        reason,
                    },
                );
                return;
            }
        } else if !inner.closed_sent {
            inner.closed_sent = true;
        }
        (active, inner.exit_on_close, owner, reason)
    };
    if active {
        if reason != "closed" {
            emit(sock, Out::TcpError { owner, reason });
        }
        emit(sock, Out::TcpClosed { owner });
        if exit_on_close {
            crate::port::abandon_port(&sock.runtime, sock.id);
        }
    }
}

/// Finish a non-blocking connect once the poll set reports the socket writable.
///
/// Port of inet_drv.c:14242-14287 (`tcp_inet_output` while `INET_STATE_CONNECTING`),
/// OTP-29.1.1: drop the write selection, cancel the connect timer by taking the
/// waiter, and read `SO_ERROR`.
fn poll_connect(inner: &mut Inner) -> Option<Out> {
    inner.connect.as_ref()?;
    let fd = inner.fd.as_ref()?.as_raw_fd();
    let mut err = 0i32;
    let mut len = std::mem::size_of::<i32>() as libc::socklen_t;
    // SAFETY: fd is the connecting socket this driver owns.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_ERROR,
            (&mut err as *mut i32).cast(),
            &mut len,
        )
    };
    if rc == 0 && (err == 0 || err == libc::EINPROGRESS || err == libc::EAGAIN) {
        if err != 0 {
            // Writable interest fired early. Keep FD_CONNECT selected.
            return None;
        }
        let waiter = inner.connect.take().unwrap();
        drop_pending(inner, waiter.caller, waiter.aref);
        inner.phase = Phase::Connected;
        return Some(Out::AsyncOk {
            caller: waiter.caller,
            aref: waiter.aref,
        });
    }
    let reason = errno_name(if rc == 0 { err } else { last_errno() });
    let waiter = inner.connect.take().unwrap();
    drop_pending(inner, waiter.caller, waiter.aref);
    inner.phase = Phase::Open;
    Some(Out::AsyncError {
        caller: waiter.caller,
        aref: waiter.aref,
        reason,
    })
}

fn io_loop(wake_r: OwnedFd) {
    // Port of inet_drv.c driver_select registrations through erl_check_io.c:988, OTP-29.1.1.
    let wake = wake_r.as_raw_fd();
    loop {
        let socks: Vec<Arc<Sock>> = registry().lock().unwrap().values().cloned().collect();
        let mut fds = vec![(
            wake,
            crate::check_io::InterestSet {
                readable: true,
                writable: false,
            },
        )];
        for sock in &socks {
            try_io(sock, false);
        }
        for sock in &socks {
            let inner = sock.inner.lock().unwrap();
            let Some(fd) = inner.fd.as_ref().map(AsRawFd::as_raw_fd) else {
                continue;
            };
            let readable = match inner.phase {
                Phase::Listening => !inner.accept_q.is_empty(),
                Phase::Connected => {
                    !inner.peer_closed && (active_is(&inner.active) || inner.recv.is_some())
                }
                _ => false,
            };
            let writable = inner.phase == Phase::Connecting || !inner.sendq.is_empty();
            if readable || writable {
                fds.push((fd, crate::check_io::InterestSet { readable, writable }));
            }
        }
        let timeout = next_timeout()
            .map(|timeout| Duration::new(timeout.tv_sec as u64, timeout.tv_nsec as u32));
        match crate::check_io::wait_any_timeout_wake(&fds, timeout, wake) {
            Ok(Some((fd, _))) if fd == wake => drain(wake),
            Ok(Some((fd, ready))) => {
                if let Some(sock) = socks.iter().find(|sock| {
                    sock.inner
                        .lock()
                        .unwrap()
                        .fd
                        .as_ref()
                        .is_some_and(|socket| socket.as_raw_fd() == fd)
                }) {
                    try_io(sock, ready.writable || ready.error || ready.closed);
                }
            }
            Ok(None) => {}
            Err(error) if error.kind() == std::io::ErrorKind::TimedOut => {}
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => continue,
        }
        // Read before timers: an RST already pending on the socket is
        // `econnreset` from recv, not the receive deadline (inet_drv.c
        // tcp_inet_input runs from erts_check_io before timer expiry).
        // A connect still in progress stays selected for write and finishes
        // in `poll_connect` when this wait, or the next one, reports it.
        for sock in &socks {
            try_io(sock, false);
        }
        fire_timeouts();
    }
}

fn next_timeout() -> Option<libc::timespec> {
    let socks: Vec<Arc<Sock>> = registry().lock().unwrap().values().cloned().collect();
    let mut soon: Option<Instant> = None;
    for sock in socks {
        let inner = sock.inner.lock().unwrap();
        for waiter in inner.accept_q.iter().chain(inner.connect.iter()) {
            if let Some(deadline) = waiter.deadline {
                soon = Some(soon.map_or(deadline, |cur| cur.min(deadline)));
            }
        }
        if let Some(recv) = inner.recv.as_ref()
            && let Some(deadline) = recv.deadline
        {
            soon = Some(soon.map_or(deadline, |cur| cur.min(deadline)));
        }
        for wait in &inner.send_waits {
            if let Some(deadline) = wait.deadline {
                soon = Some(soon.map_or(deadline, |cur| cur.min(deadline)));
            }
        }
    }
    let deadline = soon?;
    let dur = deadline.saturating_duration_since(Instant::now());
    Some(libc::timespec {
        tv_sec: dur.as_secs() as libc::time_t,
        tv_nsec: dur.subsec_nanos() as libc::c_long,
    })
}

fn fire_timeouts() {
    let socks: Vec<Arc<Sock>> = registry().lock().unwrap().values().cloned().collect();
    let now = Instant::now();
    for sock in socks {
        let (due, sends, close) = {
            let mut inner = sock.inner.lock().unwrap();
            let mut due = Vec::new();
            let mut keep = VecDeque::new();
            while let Some(waiter) = inner.accept_q.pop_front() {
                if waiter.deadline.is_some_and(|at| at <= now) {
                    drop_pending(&mut inner, waiter.caller, waiter.aref);
                    due.push((waiter.caller, waiter.aref));
                } else {
                    keep.push_back(waiter);
                }
            }
            inner.accept_q = keep;
            if let Some(recv) = inner.recv.as_ref()
                && recv.deadline.is_some_and(|at| at <= now)
            {
                let recv = inner.recv.take().unwrap();
                drop_pending(&mut inner, recv.caller, recv.aref);
                due.push((recv.caller, recv.aref));
            }
            if let Some(waiter) = inner.connect.as_ref()
                && waiter.deadline.is_some_and(|at| at <= now)
            {
                // Port of inet_drv.c:12569-12573 (tcp_inet_timeout): a connect
                // timer closes the socket, then replies `{error, timeout}`.
                let waiter = inner.connect.take().unwrap();
                drop_pending(&mut inner, waiter.caller, waiter.aref);
                inner.fd.take();
                inner.phase = Phase::Closed;
                due.push((waiter.caller, waiter.aref));
            }
            let mut sends = Vec::new();
            inner.send_waits.retain(|wait| {
                if wait.deadline.is_some_and(|at| at <= now) {
                    sends.push((wait.caller, wait.ids));
                    false
                } else {
                    true
                }
            });
            if !sends.is_empty() {
                inner.busy = false;
            }
            let close = if !sends.is_empty() && inner.send_timeout_close {
                inner.fd.take();
                inner.peer_closed = true;
                let owner = sock.handle.owner_pid();
                let active = active_is(&inner.active) && !inner.closed_sent;
                if active {
                    inner.closed_sent = true;
                }
                Some((owner, active, inner.exit_on_close))
            } else {
                None
            };
            (due, sends, close)
        };
        for (caller, aref) in due {
            emit(
                &sock,
                Out::AsyncError {
                    caller,
                    aref,
                    reason: "timeout",
                },
            );
        }
        for (caller, ids) in sends {
            emit(
                &sock,
                Out::InetReply {
                    caller,
                    ids,
                    error: Some("timeout"),
                },
            );
        }
        if let Some((owner, active, exit_on_close)) = close
            && active
        {
            emit(&sock, Out::TcpClosed { owner });
            if exit_on_close {
                crate::port::abandon_port(&sock.runtime, sock.id);
            }
        }
    }
}

fn drain(fd: RawFd) {
    let mut buf = [0u8; 64];
    loop {
        // SAFETY: fd is the wake pipe read end owned by the I/O thread.
        let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
        if n <= 0 {
            break;
        }
    }
}
