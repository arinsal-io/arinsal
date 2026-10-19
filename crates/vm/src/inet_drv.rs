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
use std::collections::VecDeque;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::{Arc, Condvar, Mutex, OnceLock, Weak};
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
const REQ_FDOPEN: i64 = 13;
const REQ_GETFD: i64 = 14;
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
const TCP_REQ_SENDFILE: i64 = 45;

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
const OPT_RECVTCLASS: u8 = 44;
const OPT_TTL: u8 = 46;
const OPT_RECVTTL: u8 = 47;
const OPT_NOPUSH: u8 = 48;
const OPT_READ_AHEAD: u8 = 49;
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

/// Port tasks waiting for the inet thread, which runs them for every `tcp_inet`
/// port: readiness from the poll set (`ready_input`/`ready_output`) and pokes
/// from control and command calls on a port.
///
/// Port of the I/O port task queue of erts/emulator/beam/erl_port_task.c and the
/// `iready`/`oready` scheduling of erts/emulator/sys/common/erl_check_io.c:1874-1908,
/// OTP-29.1.1.
#[derive(Default)]
struct Tasks {
    ready: Vec<(Arc<Sock>, RawFd, crate::check_io::Ready)>,
    poked: Vec<Arc<Sock>>,
    sockets: Vec<Weak<Sock>>,
}

fn tasks() -> &'static (Mutex<Tasks>, Condvar) {
    static TASKS: OnceLock<(Mutex<Tasks>, Condvar)> = OnceLock::new();
    TASKS.get_or_init(|| {
        std::thread::Builder::new()
            .name("arinsal-inet".into())
            .spawn(io_loop)
            .expect("inet thread");
        (Mutex::new(Tasks::default()), Condvar::new())
    })
}

/// Ask the inet thread to run port `id` (and recompute its selection).
fn register_sock(sock: &Arc<Sock>) {
    let (lock, _) = tasks();
    let mut tasks = lock.lock().unwrap();
    tasks.sockets.retain(|entry| entry.strong_count() > 0);
    tasks.sockets.push(Arc::downgrade(sock));
}

fn live_socks() -> Vec<Arc<Sock>> {
    let (lock, _) = tasks();
    let mut tasks = lock.lock().unwrap();
    tasks.sockets.retain(|entry| entry.strong_count() > 0);
    tasks.sockets.iter().filter_map(Weak::upgrade).collect()
}

fn poke(sock: &Arc<Sock>) {
    let (lock, wake) = tasks();
    let mut tasks = lock.lock().unwrap();
    if !tasks.poked.iter().any(|poked| Arc::ptr_eq(poked, sock)) {
        tasks.poked.push(Arc::clone(sock));
    }
    wake.notify_one();
}

/// `iready`/`oready`: schedule the port's I/O task on the inet thread.
fn schedule_ready(sock: Arc<Sock>, fd: RawFd, ready: crate::check_io::Ready) {
    let (lock, wake) = tasks();
    lock.lock().unwrap().ready.push((sock, fd, ready));
    wake.notify_one();
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
#[cfg(not(target_os = "macos"))]
pub(crate) fn set_nosigpipe(_fd: RawFd) {
    // Linux has no SO_NOSIGPIPE; erts ignores SIGPIPE process-wide and sends with MSG_NOSIGNAL.
}

#[cfg(target_os = "macos")]
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
    let _ = tasks();
    pin_scheduler(handle.scheduler());
    let sock = Arc::new(Sock::new(id, &runtime, &handle));
    handle.set_tcp_driver_data(Arc::clone(&sock));
    register_sock(&sock);
    poke(&sock);
}

/// Drop the socket behind a port. Waiters receive `{error, closed}`.
pub(crate) fn detach(handle: &Arc<PortHandle>) {
    let Some(sock) = handle.take_tcp_driver_data() else {
        return;
    };
    let id = sock.id;
    // The port closed while owning a dist connection (its controller exited, e.g. through
    // `net_kernel:disconnect/1`): tear the connection down and deliver nodedown.
    // Port of erts/emulator/beam/dist.c (erts_do_net_exits via the dist port's exit), OTP-29.1.1.
    if crate::node_tables::is_dist_port(id) {
        let _ = crate::dist::port_connection_closed(&sock.runtime(), id);
    }
    unpin_scheduler(&sock.handle().scheduler());
    let pending = {
        let mut inner = sock.inner.lock().unwrap();
        // Port of erts/emulator/drivers/common/inet_drv.c:12718-12725 (tcp_inet_flush)
        // and :11906-11918 (tcp_inet_stop), OTP-29.1.1: a port stopped during sendfile
        // discards its queue and closes the dup'ed file descriptor.
        if inner.sendfile.is_some() {
            inner.sendq.clear();
            inner.sendfile = None;
        } else {
            flush_send(&mut inner);
            inner.sendq.clear();
        }
        inner.fd.take();
        inner.phase = Phase::Closed;
        std::mem::take(&mut inner.pending)
    };
    send_empty_out_q_msgs(&sock);
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
    poke(&sock);
}

pub(crate) fn control(
    process: &mut Process,
    sock: &Arc<Sock>,
    caller: Pid,
    op: i64,
    data: &[u8],
) -> Result<Term, VmError> {
    // Port of inet_drv.c:11956 (tcp_inet_ctl subtracts the magic), OTP-29.1.1.
    let cmd = op.wrapping_sub(MAGIC);
    let reply = dispatch(sock, caller, cmd, data);
    poke(sock);
    byte_list(process, &reply)
}

pub(crate) fn command(sock: &Arc<Sock>, caller: Pid, data: Vec<u8>) -> Result<(), VmError> {
    // Port of inet_drv.c:13736 (tcp_sendv) and :12629 (tcp_inet_command), OTP-29.1.1.
    let (ids, payload) = split_caller(&data).ok_or_else(badarg)?;
    let start = data.len() - payload.len();
    let outcome = {
        let mut inner = sock.inner.lock().unwrap();
        accept_send(&mut inner, caller, ids, SendData::Owned(data, start))
    };
    match outcome {
        SendOutcome::Reply(error) => emit(sock, Out::InetReply { caller, ids, error }),
        SendOutcome::Deferred => {}
        SendOutcome::Failed { error, active } => {
            emit(
                sock,
                Out::InetReply {
                    caller,
                    ids,
                    error: Some(error),
                },
            );
            if active {
                let owner = sock.handle().owner_pid();
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
                    crate::port::abandon_port(&sock.runtime(), sock.id);
                }
            }
            send_empty_out_q_msgs(sock);
        }
    }
    emit_ready(sock);
    poke(sock);
    Ok(())
}

/// Write a raw distribution packet (no caller-ref prefix, no `inet_reply`).
///
/// Port of dist.c:3794 (`dist_port_command`) calling `tcp_inet_command` with
/// `prt->caller = NIL`, so `init_caller` skips the ref header, OTP-29.1.1.
pub(crate) fn dist_output(sock: &Arc<Sock>, data: &[u8]) -> Result<bool, VmError> {
    let outcome = {
        let mut inner = sock.inner.lock().unwrap();
        // Dummy caller/ids: dist never waits on inet_reply for these writes.
        accept_send(
            &mut inner,
            Pid::new(0, 0),
            [0, 0, 0],
            SendData::Borrowed(data),
        )
    };
    match outcome {
        SendOutcome::Reply(_) | SendOutcome::Deferred => {}
        SendOutcome::Failed { error, active } => {
            if active {
                let owner = sock.handle().owner_pid();
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
                    crate::port::abandon_port(&sock.runtime(), sock.id);
                }
            }
            send_empty_out_q_msgs(sock);
        }
    }
    emit_ready(sock);
    poke(sock);
    Ok(sock.inner.lock().unwrap().busy)
}

enum SendOutcome {
    Reply(Option<&'static str>),
    Deferred,
    Failed { error: &'static str, active: bool },
}

/// Bytes handed to `tcp_sendv`: the port command keeps its flattened buffer (the
/// payload starts at the offset), distribution borrows its packet.
enum SendData<'a> {
    Owned(Vec<u8>, usize),
    Borrowed(&'a [u8]),
}

impl SendData<'_> {
    fn bytes(&self) -> &[u8] {
        match self {
            SendData::Owned(buf, start) => &buf[*start..],
            SendData::Borrowed(bytes) => bytes,
        }
    }

    /// Queue the payload from `skip` on. An owned buffer moves into the queue.
    fn enqueue(self, q: &mut IoQueue, skip: usize) {
        match self {
            SendData::Owned(buf, start) => q.enq_owned(buf, start + skip),
            SendData::Borrowed(bytes) => q.enq(&bytes[skip..]),
        }
    }
}

fn accept_send(
    inner: &mut Inner,
    caller: Pid,
    ids: [u32; 3],
    payload: SendData<'_>,
) -> SendOutcome {
    // Port of erts/emulator/drivers/common/inet_drv.c:13736-13847 (tcp_sendv), OTP-29.1.1.
    if inner.peer_closed {
        return SendOutcome::Reply(Some(close_atom(inner)));
    }
    if inner.phase != Phase::Connected {
        return SendOutcome::Reply(Some("enotconn"));
    }
    let len = payload.bytes().len();
    // inet_drv.c:13745-13761: TCP_PB_1/2/4 headers; htype 3 is TCP_PB_4.
    let mut hdr = [0u8; 4];
    let h_len = match inner.htype {
        1 => {
            hdr[0] = len as u8;
            1
        }
        2 => {
            hdr[..2].copy_from_slice(&(len as u16).to_be_bytes());
            2
        }
        3 => {
            hdr.copy_from_slice(&(len as u32).to_be_bytes());
            4
        }
        _ => 0,
    };
    output_count(inner, len + h_len);
    let sz = inner.sendq.size();
    if inner.sendfile.is_some() || sz > 0 {
        // Port of inet_drv.c:13773-13793, OTP-29.1.1: queue behind pending output, and
        // behind the file while a sendfile (TCP_ADDF_SENDFILE) is in progress; busy at `high`.
        inner.sendq.enq(&hdr[..h_len]);
        payload.enqueue(&mut inner.sendq, 0);
        if sz + len + h_len >= inner.high.max(0) as usize {
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
        return SendOutcome::Reply(None);
    }
    if h_len == 0 && len == 0 {
        return SendOutcome::Reply(None);
    }
    if inner.delay_send {
        // inet_drv.c:13810-13814: queue; output runs on the next write event.
        inner.sendq.enq(&hdr[..h_len]);
        payload.enqueue(&mut inner.sendq, 0);
        return SendOutcome::Reply(None);
    }
    let Some(fd) = inner.fd.as_ref().map(AsRawFd::as_raw_fd) else {
        return SendOutcome::Reply(Some("enotconn"));
    };
    // inet_drv.c:13815-13844: one sock_sendv of header and payload, then queue
    // whatever was not written (driver_enqv with skip = bytes sent).
    let iov = [
        libc::iovec {
            iov_base: hdr.as_ptr() as *mut libc::c_void,
            iov_len: h_len,
        },
        libc::iovec {
            iov_base: payload.bytes().as_ptr() as *mut libc::c_void,
            iov_len: len,
        },
    ];
    let n = sock_sendv(fd, &iov);
    let n = if n < 0 {
        let err = last_errno();
        if err != libc::EAGAIN && err != libc::EWOULDBLOCK && err != libc::EINTR {
            return send_failed(inner, err);
        }
        0
    } else {
        n as usize
    };
    if n == len + h_len {
        return SendOutcome::Reply(None);
    }
    if n < h_len {
        inner.sendq.enq(&hdr[n..h_len]);
        payload.enqueue(&mut inner.sendq, 0);
    } else {
        payload.enqueue(&mut inner.sendq, n - h_len);
    }
    SendOutcome::Reply(None)
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
    let mut sendfile_end: Option<SendfileEnd> = None;
    let reply = {
        let mut inner = sock.inner.lock().unwrap();
        match cmd {
            REQ_OPEN => open_socket(&mut inner, data),
            REQ_FDOPEN => fdopen_socket(&mut inner, data),
            REQ_GETFD => getfd(&inner),
            REQ_CLOSE => {
                // inet_drv.c:11932 (tcp_desc_close) drops the fd. Write bytes
                // already accepted by tcp_sendv first so FIN cannot overtake them.
                // Port of erts/emulator/drivers/common/inet_drv.c:12718-12725, OTP-29.1.1:
                // during a sendfile the queue is discarded, and the dup'ed file
                // descriptor stays open until the port stops (`detach`).
                if inner.sendfile.is_some() {
                    inner.sendq.clear();
                } else {
                    let _ = flush_send(&mut inner);
                    inner.sendq.clear();
                }
                inner.fd.take();
                inner.fd_external = None;
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
            REQ_SUBSCRIBE => subscribe(&mut inner, caller, data),
            REQ_GETTYPE => gettype(&inner),
            REQ_GETSTATUS => getstatus(&inner),
            TCP_REQ_RECV => recv_req(&mut inner, caller, data),
            TCP_REQ_SHUTDOWN => shutdown_sock(&inner, data),
            TCP_REQ_SENDFILE => sendfile_req(&mut inner, data, &mut sendfile_end),
            _ => err_bytes("exbadport"),
        }
    };
    if let Some((fd, aref)) = accept_now {
        install_accepted(sock, fd, caller, aref);
    }
    if let Some(end) = sendfile_end {
        finish_sendfile(sock, end);
    }
    if cmd == REQ_CLOSE {
        send_empty_out_q_msgs(sock);
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
                owner: sock.handle().owner_pid(),
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
    inner.fd = Some(SockFd::new(
        unsafe { OwnedFd::from_raw_fd(fd) },
        inner.selection_owner,
    ));
    inner.domain = domain;
    inner.family_code = data[0];
    inner.fd_external = None;
    inner.phase = Phase::Open;
    apply_saved(inner);
    ok_bytes(&[])
}

fn fdopen_socket(inner: &mut Inner, data: &[u8]) -> Vec<u8> {
    // Port of inet_ctl_fdopen and tcp_inet_ctl INET_REQ_FDOPEN, OTP-29.1.1.
    if (data.len() != 6 && data.len() < 10) || inner.fd.is_some() {
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
    let raw_fd = i32::from_be_bytes(data[2..6].try_into().unwrap());
    if raw_fd < 0 {
        return err_bytes("einval");
    }
    let bound = data.len() == 6 || i32::from_be_bytes(data[6..10].try_into().unwrap()) != 0;
    let fd = match crate::port::duplicate_fd(raw_fd) {
        Ok(fd) => fd,
        Err(error) => return err_bytes(errno_name(error.raw_os_error().unwrap_or(libc::EINVAL))),
    };
    if bound {
        let addr = match rustix::net::getsockname(&fd) {
            Ok(addr) => addr,
            Err(error) => return err_bytes(errno_name(error.raw_os_error())),
        };
        if addr.address_family() != rustix::net::AddressFamily::from_raw(domain as _) {
            return err_bytes("einval");
        }
    }
    let connected = rustix::net::getpeername(&fd).is_ok();
    set_nonblock(fd.as_raw_fd());
    set_nosigpipe(fd.as_raw_fd());
    inner.fd = Some(SockFd::new(fd, inner.selection_owner));
    inner.fd_external = Some(raw_fd);
    inner.domain = domain;
    inner.family_code = data[0];
    inner.phase = if connected {
        Phase::Connected
    } else {
        Phase::Open
    };
    ok_bytes(&[])
}

fn getfd(inner: &Inner) -> Vec<u8> {
    // Port of inet_ctl INET_REQ_GETFD, OTP-29.1.1.
    let Some(fd) = inner.fd.as_ref() else {
        return err_bytes("einval");
    };
    let raw = inner.fd_external.unwrap_or_else(|| fd.as_raw_fd());
    ok_bytes(&(raw as u32).to_be_bytes())
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
            // Wake the inet thread so it selects FD_CONNECT for this fd.
            poke(sock);
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
    let runtime = listen.runtime();
    let name = listen.handle().port_name();
    // Port of erts/emulator/drivers/common/inet_drv.c:11829-11839 (tcp_inet_copy), OTP-29.1.1.
    let (id, handle) = match crate::port::alloc_inet_port(&runtime, caller, name) {
        Ok(port) => port,
        Err(crate::port::InetPortAllocError::SystemLimit) => {
            emit(
                listen,
                Out::AsyncError {
                    caller,
                    aref,
                    reason: "system_limit",
                },
            );
            return;
        }
        Err(crate::port::InetPortAllocError::NoMemory) => {
            emit(
                listen,
                Out::AsyncError {
                    caller,
                    aref,
                    reason: "enomem",
                },
            );
            return;
        }
    };
    let selection_owner = Arc::as_ptr(&handle) as usize;
    // Port of inet_drv.c:11795 (tcp_inet_copy), OTP-29.1.1.
    // `active` is not copied here; prim_inet:accept_opts sets it afterwards.
    let born = {
        let inner = listen.inner.lock().unwrap();
        Inner {
            fd: Some(SockFd::new(fd, selection_owner)),
            selection_owner,
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
            read_ahead: inner.read_ahead,
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
        selection_owner,
        runtime: Arc::downgrade(&runtime),
        handle: Arc::downgrade(&handle),
        inner: Mutex::new(born),
        io: Mutex::new(()),
    });
    handle.set_tcp_driver_data(Arc::clone(&sock));
    register_sock(&sock);
    // Port of inet_drv.c:2514 (send_async_ok_port), OTP-29.1.1.
    emit(
        listen,
        Out::AsyncPort {
            caller,
            aref,
            port: id,
        },
    );
    poke(&sock);
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
            out.extend(path[..n].iter().map(|c| c.to_ne_bytes()[0]));
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
        // Port of inet_drv.c:7184 (INET_LOPT_TCP_READ_AHEAD), OTP-29.1.1.
        OPT_READ_AHEAD => inner.read_ahead = val != 0,
        OPT_SHOW_ECONNRESET => inner.show_econnreset = val != 0,
        OPT_LINE => inner.delimiter = val as u8,
        OPT_RECVTOS => {
            inner.recvtos = val != 0;
            if !sock_set(inner, libc::IPPROTO_IP, libc::IP_RECVTOS, val, true) {
                return false;
            }
        }
        // Port of inet_drv.c:7466-7478 (INET_OPT_RECVTCLASS), OTP-29.1.1.
        OPT_RECVTCLASS => {
            inner.recvtclass = val != 0;
            if !sock_set(inner, libc::IPPROTO_IPV6, libc::IPV6_RECVTCLASS, val, true) {
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
        // Port of inet_drv.c:9305 (INET_LOPT_TCP_READ_AHEAD), OTP-29.1.1.
        OPT_READ_AHEAD => write_i32(out, i32::from(inner.read_ahead)),
        OPT_SHOW_ECONNRESET => write_i32(out, i32::from(inner.show_econnreset)),
        // inet_fill_opts has no LINE_DELIM case, so getopts returns einval.
        OPT_LINE => return false,
        OPT_RECVTOS => {
            if let Some(value) = sock_get_int(inner, libc::IPPROTO_IP, libc::IP_RECVTOS) {
                write_i32(out, i32::from(value != 0));
            }
        }
        // Port of inet_drv.c:9362-9368 (INET_OPT_RECVTCLASS), OTP-29.1.1.
        OPT_RECVTCLASS => {
            if let Some(value) = sock_get_int(inner, libc::IPPROTO_IPV6, libc::IPV6_RECVTCLASS) {
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
            8 => put_u32(&mut out, inner.sendq.size() as u32),
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

fn subscribe(inner: &mut Inner, caller: Pid, data: &[u8]) -> Vec<u8> {
    // Port of prim_inet.erl subs_empty_out_q / inet_drv INET_REQ_SUBSCRIBE, OTP-29.1.1.
    let mut out = Vec::new();
    for &code in data {
        if code != 1 {
            return err_bytes("einval");
        }
        out.push(1);
        let queued = inner.sendq.size();
        if queued > 0 {
            save_subscriber(&mut inner.empty_out_q_subs, caller);
        }
        put_u32(&mut out, queued as u32);
    }
    ok_bytes(&out)
}

/// `save_subscriber`: the first subscriber stays at the head, later ones go right behind it.
fn save_subscriber(subs: &mut Vec<Pid>, pid: Pid) {
    if subs.is_empty() {
        subs.push(pid);
    } else {
        subs.insert(1, pid);
    }
}

/// `send_empty_out_q_msgs`: tell every subscriber that the output queue is empty and forget
/// them. Call it where the queue has just drained or been discarded.
fn send_empty_out_q_msgs(sock: &Sock) {
    let subs = {
        let mut inner = sock.inner.lock().unwrap();
        if !inner.sendq.is_empty() {
            return;
        }
        std::mem::take(&mut inner.empty_out_q_subs)
    };
    for subscriber in subs {
        emit(sock, Out::EmptyOutQ { subscriber });
    }
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
        // BSD sockaddrs carry sa_len (struct entries vary in size) and a one-byte family;
        // Linux entries are all sizeof(struct ifreq) with a native-endian u16 family.
        #[cfg(target_os = "macos")]
        let (n, family) = {
            let sa_len = buf[i + name_len] as usize;
            let sa_size = sa_len.max(std::mem::size_of::<libc::sockaddr>());
            (
                (name_len + sa_size).max(ifreq),
                i32::from(buf[i + name_len + 1]),
            )
        };
        #[cfg(not(target_os = "macos"))]
        let (n, family) = (
            ifreq,
            i32::from(u16::from_ne_bytes([
                buf[i + name_len],
                buf[i + name_len + 1],
            ])),
        );
        if i + n > buf.len() {
            break;
        }
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

/// Link-layer addresses by interface name, from the `AF_PACKET` rows of getifaddrs (the data
/// `SIOCGIFHWADDR` returns, six bytes per interface), read through nix's safe wrapper.
#[cfg(target_os = "linux")]
fn hw_table() -> std::collections::HashMap<Vec<u8>, Vec<u8>> {
    nix::ifaddrs::getifaddrs()
        .map(|rows| {
            rows.filter_map(|row| {
                let hw = row.address?.as_link_addr()?.addr()?;
                Some((row.interface_name.into_bytes(), hw.to_vec()))
            })
            .collect()
        })
        .unwrap_or_default()
}

// Port of inet_drv.c (INET_IFOPT_HWADDR with SIOCGIFHWADDR), OTP-29.1.1.
#[cfg(target_os = "linux")]
fn hwaddr(name: &[u8]) -> Option<Vec<u8>> {
    hw_table().remove(name)
}

#[cfg(target_os = "linux")]
fn link_addr_of(
    table: &std::collections::HashMap<Vec<u8>, Vec<u8>>,
    name: &[u8],
    _addr: *const libc::sockaddr,
) -> Option<Vec<u8>> {
    table.get(name).cloned()
}

/// macOS reads the `sockaddr_dl` rows themselves, so there is no table.
#[cfg(target_os = "macos")]
fn hw_table() -> std::collections::HashMap<Vec<u8>, Vec<u8>> {
    std::collections::HashMap::new()
}

#[cfg(target_os = "macos")]
fn link_addr_of(
    _table: &std::collections::HashMap<Vec<u8>, Vec<u8>>,
    _name: &[u8],
    addr: *const libc::sockaddr,
) -> Option<Vec<u8>> {
    link_addr(addr)
}

#[cfg(target_os = "macos")]
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
        if family == AF_HWADDR && name_eq(ifa.ifa_name, name) {
            found = link_addr(ifa.ifa_addr);
            break;
        }
        cur = ifa.ifa_next;
    }
    // SAFETY: head came from getifaddrs.
    unsafe { libc::freeifaddrs(head) };
    found.filter(|hw| hw.len() + 2 > 3)
}

#[cfg(target_os = "macos")]
fn name_eq(ptr: *const libc::c_char, name: &[u8]) -> bool {
    if ptr.is_null() {
        return false;
    }
    // SAFETY: getifaddrs names are NUL-terminated.
    let c = unsafe { std::ffi::CStr::from_ptr(ptr) };
    c.to_bytes() == name
}

/// The link-layer address family of getifaddrs rows (`AF_LINK` / `AF_PACKET` in erts).
#[cfg(target_os = "macos")]
const AF_HWADDR: i32 = libc::AF_LINK;
#[cfg(target_os = "linux")]
const AF_HWADDR: i32 = libc::AF_PACKET;

#[cfg(target_os = "macos")]
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

// Linux names the broadcast/destination union member ifa_ifu.
#[cfg(target_os = "linux")]
fn ifa_dstaddr(item: &libc::ifaddrs) -> *mut libc::sockaddr {
    item.ifa_ifu
}
#[cfg(not(target_os = "linux"))]
fn ifa_dstaddr(item: &libc::ifaddrs) -> *mut libc::sockaddr {
    item.ifa_dstaddr
}

pub(crate) fn getifaddrs_reply() -> Vec<u8> {
    // Port of inet_drv.c:6611 (inet_ctl_getifaddrs), OTP-29.1.1.
    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs writes a list we free below.
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return err_bytes(errno_name(last_errno()));
    }
    let mut out = Vec::new();
    let hw = hw_table();
    let mut cur = head;
    while !cur.is_null() {
        // SAFETY: cur is a live ifaddrs node from getifaddrs.
        let ifa = unsafe { &*cur };
        let mut if_name = Vec::new();
        if !ifa.ifa_name.is_null() {
            // SAFETY: ifa_name is a NUL-terminated C string from getifaddrs.
            let name = unsafe { std::ffi::CStr::from_ptr(ifa.ifa_name) };
            if_name = name.to_bytes().to_vec();
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
                if p2p && !ifa_dstaddr(ifa).is_null() {
                    push_ifaddr(&mut out, IFOPT_DSTADDR, ifa_dstaddr(ifa));
                } else if bcast && !ifa_dstaddr(ifa).is_null() {
                    push_ifaddr(&mut out, IFOPT_BROADADDR, ifa_dstaddr(ifa));
                }
            } else if family == AF_HWADDR
                && let Some(addr) = link_addr_of(&hw, &if_name, ifa.ifa_addr)
                && addr.len() + 2 > 3
            {
                out.push(IFOPT_HWADDR);
                out.extend_from_slice(&(addr.len() as u16).to_be_bytes());
                out.extend_from_slice(&addr);
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
            // BSD sockaddrs carry their length; elsewhere it follows from the family.
            {
                #[cfg(target_os = "macos")]
                {
                    (*addr).sa_len as usize
                }
                #[cfg(not(target_os = "macos"))]
                {
                    if i32::from((*addr).sa_family) == libc::AF_INET6 {
                        std::mem::size_of::<libc::sockaddr_in6>()
                    } else {
                        std::mem::size_of::<libc::sockaddr_in>()
                    }
                }
            },
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

/// Send queued output until the queue is empty or the socket would block.
///
/// Port of erts/emulator/drivers/common/inet_drv.c:14295-14361 (`tcp_inet_output`
/// send loop), OTP-29.1.1: `driver_peekq`, one `sock_sendv` of at most `MAX_VSIZE`
/// entries, then `driver_deq` of the bytes written. Queued bytes are not copied.
fn flush_send(inner: &mut Inner) -> Option<i32> {
    // Port of erts/emulator/drivers/common/inet_drv.c:14291-14295, OTP-29.1.1: with
    // TCP_ADDF_SENDFILE set, output goes through tcp_inet_sendfile, which sends only the
    // `ioq_skip` bytes queued before the file; the rest waits for the file to finish.
    if inner.sendfile.is_some() {
        return None;
    }
    let fd = inner.fd.as_ref()?;
    let fd = fd.as_raw_fd();
    while !inner.sendq.is_empty() {
        let n = sock_sendv(fd, &inner.sendq.peekq(max_vsize()));
        if n > 0 {
            inner.sendq.deq(n as usize);
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

/// `sock_sendv`: one `writev` of `iov`. Port of erts/emulator/drivers/common/inet_drv.c:649-650, OTP-29.1.1.
///
/// Every `iovec` must point into memory that stays alive and unmodified for the call.
fn sock_sendv(fd: RawFd, iov: &[libc::iovec]) -> isize {
    // SAFETY: fd is a socket this driver owns; the callers build `iov` from borrowed
    // slices (the send header and payload, or segments held by `sendq`) that outlive
    // this call and are only read by `writev`.
    unsafe { libc::writev(fd, iov.as_ptr(), iov.len() as libc::c_int) }
}

/// `MAX_VSIZE`: the most entries one `sock_sendv` passes.
///
/// Port of erts/emulator/drivers/common/inet_drv.c:1319-1321 and :4532-4537
/// (`iov_max = sysconf(_SC_IOV_MAX)`, POSIX minimum 16), OTP-29.1.1.
fn max_vsize() -> usize {
    static IOV_MAX: OnceLock<usize> = OnceLock::new();
    *IOV_MAX.get_or_init(|| {
        // SAFETY: sysconf only reads a system limit.
        let n = unsafe { libc::sysconf(libc::_SC_IOV_MAX) };
        if n > 0 { n as usize } else { 16 }
    })
}

/// Driver output queue: segments written with `writev` and released as sent.
///
/// Port of erts/emulator/beam/erl_io_queue.c:233-284 (`erts_ioq_enqv`), :349-379
/// (`erts_ioq_deq`) and :400-410 (`erts_ioq_peekq`), OTP-29.1.1. A queued buffer
/// is never copied again: `deq` drops whole segments and advances into the first.
#[derive(Default)]
struct IoQueue {
    segs: VecDeque<(Vec<u8>, usize)>,
    size: usize,
}

impl IoQueue {
    /// `driver_sizeq`.
    fn size(&self) -> usize {
        self.size
    }

    fn is_empty(&self) -> bool {
        self.size == 0
    }

    /// `driver_enq`: copy `bytes` into a new segment; zero-length items are dropped.
    fn enq(&mut self, bytes: &[u8]) {
        if !bytes.is_empty() {
            self.size += bytes.len();
            self.segs.push_back((bytes.to_vec(), 0));
        }
    }

    /// `driver_enqv` with a skip: queue `buf[start..]` without copying it.
    fn enq_owned(&mut self, buf: Vec<u8>, start: usize) {
        if start < buf.len() {
            self.size += buf.len() - start;
            self.segs.push_back((buf, start));
        }
    }

    /// First entry of `driver_peekq` (`iov[0]`): the unsent bytes of the head segment.
    fn head(&self) -> Option<&[u8]> {
        self.segs.front().map(|(buf, start)| &buf[*start..])
    }

    /// `driver_peekq`, limited to `max` entries.
    fn peekq(&self, max: usize) -> Vec<libc::iovec> {
        self.segs
            .iter()
            .take(max)
            .map(|(buf, start)| libc::iovec {
                iov_base: buf[*start..].as_ptr() as *mut libc::c_void,
                iov_len: buf.len() - start,
            })
            .collect()
    }

    /// `driver_deq`: drop `n` bytes from the head.
    fn deq(&mut self, mut n: usize) {
        self.size -= n.min(self.size);
        while n > 0 {
            let Some((buf, start)) = self.segs.front_mut() else {
                break;
            };
            let len = buf.len() - *start;
            if len <= n {
                n -= len;
                self.segs.pop_front();
            } else {
                *start += n;
                n = 0;
            }
        }
    }

    fn clear(&mut self) {
        self.segs.clear();
        self.size = 0;
    }
}

fn release_unbusy(inner: &mut Inner) {
    if inner.busy && inner.sendq.size() <= inner.low.max(0) as usize {
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

/// Port of erts/emulator/drivers/common/inet_drv.c:1498-1511 (`tcp_descriptor.sendfile`),
/// OTP-29.1.1.
struct Sendfile {
    /// Bytes queued when sendfile was issued; they go out before the file.
    ioq_skip: usize,
    /// The file handle to send from, duplicated when sendfile is issued.
    dup_file_fd: OwnedFd,
    bytes_sent: u64,
    offset: u64,
    length: u64,
}

/// How a sendfile ended, reported once the socket lock is released.
enum SendfileEnd {
    Completed {
        bytes_sent: u64,
    },
    Aborted {
        reason: &'static str,
        error: &'static str,
        active: bool,
    },
}

// Port of erts/emulator/drivers/common/inet_drv.c:12380-12441 (TCP_REQ_SENDFILE with
// HAVE_SENDFILE), OTP-29.1.1.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn sendfile_req(inner: &mut Inner, data: &[u8], end: &mut Option<SendfileEnd>) -> Vec<u8> {
    const REQUIRED_LEN: usize = std::mem::size_of::<i32>() + std::mem::size_of::<u64>() * 2;
    if data.len() != REQUIRED_LEN {
        return err_bytes("einval");
    } else if inner.phase != Phase::Connected || inner.fd.is_none() {
        return err_bytes("enotconn");
    } else if inner.sendfile.is_some() {
        // prim_inet.erl lets only the controlling process sendfile; erts checks anyway.
        return err_bytes("einval");
    }
    let raw_file_fd = i32::from_ne_bytes(data[0..4].try_into().unwrap());
    // inet_drv.c:12409 dups the handle; Arinsal's dup also sets FD_CLOEXEC under
    // `cloexec_publish` so a port child cannot inherit it.
    let dup_file_fd = match crate::port::duplicate_fd(raw_file_fd) {
        Ok(fd) => fd,
        Err(error) => return err_bytes(errno_name(error.raw_os_error().unwrap_or(libc::EINVAL))),
    };
    let offset = u64::from_be_bytes(data[4..12].try_into().unwrap());
    let length = u64::from_be_bytes(data[12..20].try_into().unwrap());
    inner.sendfile = Some(Sendfile {
        ioq_skip: inner.sendq.size(),
        dup_file_fd,
        bytes_sent: 0,
        offset,
        length,
    });
    // See if we can finish sending without selecting & rescheduling. An unfinished
    // file keeps the socket selected for write in `io_loop`.
    *end = tcp_inet_sendfile(inner);
    ok_bytes(&[])
}

// Port of erts/emulator/drivers/common/inet_drv.c:12442-12444 (TCP_REQ_SENDFILE without
// HAVE_SENDFILE), OTP-29.1.1: configure checks sendfile only on Linux, the BSDs and Darwin.
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn sendfile_req(_inner: &mut Inner, _data: &[u8], _end: &mut Option<SendfileEnd>) -> Vec<u8> {
    err_bytes("enotsup")
}

/// Send the queue's head and then the file; `None` while the socket would block.
///
/// Port of erts/emulator/drivers/common/inet_drv.c:14077-14227 (tcp_inet_sendfile),
/// OTP-29.1.1.
fn tcp_inet_sendfile(inner: &mut Inner) -> Option<SendfileEnd> {
    enum Step {
        Blocked,
        Completed,
        SocketError(i32),
    }
    let s = inner.fd.as_ref()?.as_raw_fd();
    let step = 'done: {
        let sf = inner.sendfile.as_mut()?;
        // If there was any data in the queue by the time sendfile was issued, it goes
        // first. Busy status is not cleared until the file is sent.
        while sf.ioq_skip > 0 {
            assert!(
                inner.sendq.size() >= sf.ioq_skip,
                "ioq smaller than sendfile.ioq_skip"
            );
            let Some(head) = inner.sendq.head() else {
                panic!("ioq empty when sendfile.ioq_skip > 0");
            };
            let bytes_to_send = sf.ioq_skip.min(head.len());
            // SAFETY: s is the connected socket this driver owns and head holds at
            // least bytes_to_send initialized bytes.
            let n = unsafe { libc::send(s, head.as_ptr().cast(), bytes_to_send, 0) };
            if n >= 0 {
                sf.ioq_skip -= n as usize;
                inner.sendq.deq(n as usize);
            } else {
                let err = last_errno();
                if err == libc::EAGAIN || err == libc::EWOULDBLOCK {
                    break 'done Step::Blocked;
                } else if err != libc::EINTR {
                    break 'done Step::SocketError(err);
                }
            }
        }
        while sf.length > 0 {
            // For some reason the maximum ssize_t cannot be used as the max size.
            // 1GB seems to work on all platforms.
            const SENDFILE_CHUNK_SIZE: u64 = (1 << 30) - 1;
            let bytes_to_send = SENDFILE_CHUNK_SIZE.min(sf.length);
            let (n, err) = sendfile_chunk(s, sf.dup_file_fd.as_raw_fd(), sf.offset, bytes_to_send);
            if n > 0 {
                sf.bytes_sent += n as u64;
                sf.offset += n as u64;
                sf.length -= n as u64;
            } else if n == 0 {
                // EOF.
                sf.length = 0;
                break;
            } else if err != libc::EINTR {
                if err != libc::EAGAIN && err != libc::EWOULDBLOCK {
                    break 'done Step::SocketError(err);
                }
                break;
            }
        }
        if sf.length == 0 {
            Step::Completed
        } else {
            Step::Blocked
        }
    };
    match step {
        Step::Blocked => None,
        Step::Completed => Some(tcp_sendfile_completed(inner)),
        Step::SocketError(err) => {
            let reason = tcp_sendfile_aborted(err);
            // tcp_send_error closes the socket; the sendfile state stays until the port
            // stops, as in erts.
            let SendOutcome::Failed { error, active } = send_failed(inner, err) else {
                unreachable!("send_failed always fails");
            };
            Some(SendfileEnd::Aborted {
                reason,
                error,
                active,
            })
        }
    }
}

/// One sendfile(2) call: `(bytes, errno)`, with bytes `-1` on error.
///
/// Port of erts/emulator/drivers/common/inet_drv.c:14123-14125 (Linux), OTP-29.1.1.
#[cfg(target_os = "linux")]
fn sendfile_chunk(s: RawFd, file: RawFd, offset: u64, bytes_to_send: u64) -> (i64, i32) {
    let mut offset = offset as libc::off_t;
    // SAFETY: s is the connected socket, file the dup'ed descriptor this socket owns,
    // and offset a live local.
    let n = unsafe { libc::sendfile(s, file, &mut offset, bytes_to_send as usize) };
    let err = if n < 0 { last_errno() } else { 0 };
    (n as i64, err)
}

/// One sendfile(2) call: `(bytes, errno)`, with bytes `-1` on error.
///
/// Port of erts/emulator/drivers/common/inet_drv.c:14126-14153 (`__DARWIN__`), OTP-29.1.1.
#[cfg(target_os = "macos")]
fn sendfile_chunk(s: RawFd, file: RawFd, offset: u64, bytes_to_send: u64) -> (i64, i32) {
    let mut bytes_sent = bytes_to_send as libc::off_t;
    // SAFETY: file is the dup'ed descriptor this socket owns, s the connected socket,
    // bytes_sent a live local, and no header/trailer vector is passed.
    let error = unsafe {
        libc::sendfile(
            file,
            s,
            offset as libc::off_t,
            &mut bytes_sent,
            std::ptr::null_mut(),
            0,
        )
    };
    let err = if error < 0 { last_errno() } else { 0 };
    let mut n = bytes_sent as i64;
    // EAGAIN/EINTR report partial success by setting bytes_sent, so error handling is
    // skipped if nonzero, and EOF handling if zero.
    if error < 0 && ((err != libc::EAGAIN && err != libc::EINTR) || bytes_sent == 0) {
        n = -1;
    }
    (n, err)
}

/// Port of erts/emulator/drivers/common/inet_drv.c:13987-14046 (tcp_sendfile_completed),
/// OTP-29.1.1.
fn tcp_sendfile_completed(inner: &mut Inner) -> SendfileEnd {
    // Clears TCP_ADDF_SENDFILE and closes the dup'ed descriptor.
    let bytes_sent = inner.sendfile.take().map_or(0, |sf| sf.bytes_sent);
    // Busy status was deferred until now; more data may have been queued meanwhile.
    release_unbusy(inner);
    // An empty queue deselects FD_WRITE in `io_loop`; `finish_sendfile` sends the
    // empty_out_q messages before the sendfile result.
    SendfileEnd::Completed { bytes_sent }
}

/// Port of erts/emulator/drivers/common/inet_drv.c:14048-14075 (tcp_sendfile_aborted),
/// OTP-29.1.1: the reason in `{sendfile, S, {error, Reason}}`.
fn tcp_sendfile_aborted(socket_error: i32) -> &'static str {
    match socket_error {
        libc::ECONNRESET | libc::ENOTCONN | libc::EPIPE => "closed",
        _ => errno_name(socket_error),
    }
}

/// Deliver the end of a sendfile to the port owner (`desc->inet.dport`).
fn finish_sendfile(sock: &Arc<Sock>, end: SendfileEnd) {
    let owner = sock.handle().owner_pid();
    match end {
        SendfileEnd::Completed { bytes_sent } => {
            // Port of inet_drv.c:14006-14021, OTP-29.1.1: the busy sender's reply first.
            emit_ready(sock);
            send_empty_out_q_msgs(sock);
            emit(
                sock,
                Out::Sendfile {
                    owner,
                    result: Ok(bytes_sent),
                },
            );
        }
        SendfileEnd::Aborted {
            reason,
            error,
            active,
        } => {
            emit(
                sock,
                Out::Sendfile {
                    owner,
                    result: Err(reason),
                },
            );
            // Port of erts/emulator/drivers/common/inet_drv.c:13638-13653, OTP-29.1.1
            // (tcp_send_or_shutdown_error, active): tcp_error/tcp_closed, but no
            // inet_reply while TCP_ADDF_SENDFILE is set.
            if active {
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
                    crate::port::abandon_port(&sock.runtime(), sock.id);
                }
            }
            send_empty_out_q_msgs(sock);
        }
    }
}

fn close_atom(inner: &Inner) -> &'static str {
    if inner.reset { "econnreset" } else { "closed" }
}

pub(crate) struct Sock {
    id: u64,
    selection_owner: usize,
    runtime: Weak<Runtime>,
    handle: Weak<PortHandle>,
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
    /// `driver_sizeq` of the port's output queue, for `port_info(Port, queue_size)`.
    pub(crate) fn out_queue_size(&self) -> usize {
        self.inner.lock().unwrap().sendq.size()
    }

    fn new(id: u64, runtime: &Arc<Runtime>, handle: &Arc<PortHandle>) -> Self {
        let selection_owner = Arc::as_ptr(handle) as usize;
        Self {
            id,
            selection_owner,
            runtime: Arc::downgrade(runtime),
            handle: Arc::downgrade(handle),
            inner: Mutex::new(Inner {
                selection_owner,
                ..Inner::default()
            }),
            io: Mutex::new(()),
        }
    }

    fn runtime(&self) -> Arc<Runtime> {
        self.runtime.upgrade().expect("live inet port runtime")
    }

    fn handle(&self) -> Arc<PortHandle> {
        self.handle.upgrade().expect("live inet port handle")
    }
}

/// The socket of a `tcp_inet` port with its poll-set selection.
///
/// Dropping it deselects the descriptor before closing it, as `tcp_desc_close`
/// does with `sock_select(desc, FD_READ|FD_WRITE|FD_CLOSE|ERL_DRV_USE_NO_CALLBACK, 0)`
/// (erts/emulator/drivers/common/inet_drv.c:11473), OTP-29.1.1.
struct SockFd {
    fd: OwnedFd,
    owner: usize,
    /// Events selected in the shared poll set (`state->events` in erl_check_io.c).
    selected: crate::check_io::InterestSet,
}

impl SockFd {
    fn new(fd: OwnedFd, owner: usize) -> Self {
        Self {
            fd,
            owner,
            selected: crate::check_io::InterestSet {
                readable: false,
                writable: false,
            },
        }
    }
}

impl AsRawFd for SockFd {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

impl Drop for SockFd {
    fn drop(&mut self) {
        if self.selected.readable || self.selected.writable {
            crate::check_io::driver_deselect(self.fd.as_raw_fd(), self.owner);
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
    fd: Option<SockFd>,
    fd_external: Option<RawFd>,
    selection_owner: usize,
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
    read_ahead: bool,
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
    recvtclass: bool,
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
    sendq: IoQueue,
    empty_out_q_subs: Vec<Pid>,
    /// `Some` while TCP_ADDF_SENDFILE is set.
    sendfile: Option<Sendfile>,
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
            fd_external: None,
            selection_owner: 0,
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
            read_ahead: true,
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
            recvtclass: false,
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
            sendq: IoQueue::default(),
            empty_out_q_subs: Vec::new(),
            sendfile: None,
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
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (i, byte) in data[1..1 + n].iter().enumerate() {
        addr.sun_path[i] = *byte as libc::c_char;
    }
    let len = (std::mem::offset_of!(libc::sockaddr_un, sun_path) + n) as libc::socklen_t;
    #[cfg(target_os = "macos")]
    {
        addr.sun_len = len as u8;
    }
    Ok(Dest::Local(addr, len))
}

fn v4(port: u16, ip: [u8; 4]) -> libc::sockaddr_in {
    let mut addr: libc::sockaddr_in = zeroed();
    #[cfg(target_os = "macos")]
    {
        addr.sin_len = std::mem::size_of::<libc::sockaddr_in>() as u8;
    }
    addr.sin_family = libc::AF_INET as libc::sa_family_t;
    addr.sin_port = port.to_be();
    addr.sin_addr.s_addr = u32::from_ne_bytes(ip);
    addr
}

fn v6(port: u16, ip: [u8; 16]) -> libc::sockaddr_in6 {
    let mut addr: libc::sockaddr_in6 = zeroed();
    #[cfg(target_os = "macos")]
    {
        addr.sin6_len = std::mem::size_of::<libc::sockaddr_in6>() as u8;
    }
    addr.sin6_family = libc::AF_INET6 as libc::sa_family_t;
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
        libc::EBADF => "ebadf",
        libc::ENOTSOCK => "enotsock",
        // erl_errno_id names ENOTSUP only where it differs from EOPNOTSUPP.
        code if code == libc::ENOTSUP => "enotsup",
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
    Sendfile {
        owner: Pid,
        result: Result<u64, &'static str>,
    },
    EmptyOutQ {
        subscriber: Pid,
    },
}

fn output_list_len(sock: &Sock, out: &Out) -> usize {
    match out {
        Out::AsyncData { bytes, .. } | Out::Tcp { bytes, .. } | Out::PortData { bytes, .. } => {
            let inner = sock.inner.lock().unwrap();
            let header = if inner.header < 0 {
                bytes.len()
            } else {
                inner.header as usize
            };
            if !inner.binary || header > bytes.len() {
                bytes.len()
            } else {
                header
            }
        }
        Out::Http { packet, binary, .. } | Out::AsyncHttp { packet, binary, .. } => {
            http_list_len(packet, *binary)
        }
        _ => 0,
    }
}

fn http_list_len(packet: &HttpPacket, binary: bool) -> usize {
    if binary {
        return 0;
    }
    match packet {
        HttpPacket::Request {
            method,
            known_method,
            uri,
            ..
        } => {
            let method_len = if *known_method { 0 } else { method.len() };
            method_len + http_uri_list_len(uri)
        }
        HttpPacket::Response { phrase, .. } => phrase.len(),
        HttpPacket::Header {
            known_name,
            name,
            original_name,
            value,
            ..
        } => {
            (if known_name.is_none() { name.len() } else { 0 }) + original_name.len() + value.len()
        }
        HttpPacket::Error(line) => line.len(),
        HttpPacket::Eoh => 0,
    }
}

fn http_uri_list_len(uri: &HttpUri) -> usize {
    match uri {
        HttpUri::Star => 0,
        HttpUri::String(bytes) | HttpUri::AbsPath(bytes) => bytes.len(),
        HttpUri::Scheme { scheme, rest } => scheme.len() + rest.len(),
        HttpUri::Absolute { host, path, .. } => host.len() + path.len(),
    }
}

fn emit(sock: &Sock, out: Out) {
    // Distribution ports feed the emulator decoder, not the port owner.
    // Port of inet_drv.c + dist.c:2017 (erts_net_message), OTP-29.1.1.
    if let Out::PortData { bytes, .. } = &out
        && crate::node_tables::is_dist_port(sock.id)
    {
        let _ = crate::dist::ingest_port_data(&sock.runtime(), sock.id, bytes);
        return;
    }
    if let Out::TcpClosed { .. } = &out
        && crate::node_tables::is_dist_port(sock.id)
    {
        let _ = crate::dist::port_connection_closed(&sock.runtime(), sock.id);
        // Still deliver tcp_closed to the connection ticker so it shuts down.
    }
    let sched = sock.handle().scheduler();
    let port = Term::port(sock.id).unwrap();
    // Port of inet_drv.c:3987-4005 (tcp_message uses LOAD_STRING sized to the
    // complete packet), OTP-29.1.1. List-mode packets need two heap words per byte.
    let words = 128usize.saturating_add(output_list_len(sock, &out).saturating_mul(2));
    let mut heap = ProcessHeap::with_words(words);
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
        Out::EmptyOutQ { subscriber } => TermBuilder::new(&mut heap)
            .tuple(&[atom("empty_out_q"), port])
            .ok()
            .map(|term| (*subscriber, term)),
        Out::Sendfile { owner, result } => {
            // Port of inet_drv.c:14032-14043 ({sendfile, S, {ok, SentLow, SentHigh}}) and
            // :14055-14072 ({sendfile, S, {error, Reason}}), OTP-29.1.1.
            let status = match result {
                Ok(bytes_sent) => TermBuilder::new(&mut heap)
                    .tuple(&[
                        atom("ok"),
                        Term::small((bytes_sent & 0xFFFF_FFFF) as i64).unwrap(),
                        Term::small((bytes_sent >> 32) as i64).unwrap(),
                    ])
                    .ok(),
                Err(reason) => error_tuple(&mut heap, reason),
            };
            status
                .and_then(|status| {
                    TermBuilder::new(&mut heap)
                        .tuple(&[atom("sendfile"), port, status])
                        .ok()
                })
                .map(|term| (*owner, term))
        }
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
    if sock.inner.lock().unwrap().sendfile.is_none() {
        send_empty_out_q_msgs(sock);
    }
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
    crate::dist::distribution_port_state_changed(&sock.runtime(), sock.id, busy);
}

/// Write queued output once the poll set reports the connected socket writable.
///
/// Port of erts/emulator/drivers/common/inet_drv.c:14289-14361, OTP-29.1.1
/// (`tcp_inet_output`, connected branch): send from the driver queue until it is
/// empty or the socket would block, and drop the busy state at the low watermark
/// (`release_unbusy`; the deferred `inet_reply` goes out through `emit_ready`).
/// The output callback runs whether or not the owner has a receive pending, so a
/// passive socket whose owner is blocked in `gen_tcp:send/2` still drains. The
/// write selection follows the queue: `sock_select` selects for write only while
/// `sendq` is non-empty or a sendfile is unfinished (inet_drv.c:14302-14303 deselects
/// when the queue is empty).
fn tcp_inet_output(sock: &Arc<Sock>) {
    let failure = {
        let mut inner = sock.inner.lock().unwrap();
        // Port of erts/emulator/drivers/common/inet_drv.c:14291-14295, OTP-29.1.1: with
        // TCP_ADDF_SENDFILE set, output continues the file instead of the queue.
        if inner.phase == Phase::Connected && inner.sendfile.is_some() {
            let end = tcp_inet_sendfile(&mut inner);
            drop(inner);
            if let Some(end) = end {
                finish_sendfile(sock, end);
            }
            return;
        }
        if inner.phase != Phase::Connected || inner.sendq.is_empty() {
            return;
        }
        let Some(err) = flush_send(&mut inner) else {
            drop(inner);
            send_empty_out_q_msgs(sock);
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
        let owner = sock.handle().owner_pid();
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
            crate::port::abandon_port(&sock.runtime(), sock.id);
        }
    }
    send_empty_out_q_msgs(sock);
}

fn deliver_pending_close(sock: &Arc<Sock>) {
    // Port of inet_drv.c:7001 (inet_set_opts active while INET_STATE_CLOSED), OTP-29.1.1.
    let (owner, exit_on_close) = {
        let mut inner = sock.inner.lock().unwrap();
        if !inner.peer_closed || inner.closed_sent || !active_is(&inner.active) {
            return;
        }
        inner.closed_sent = true;
        (sock.handle().owner_pid(), inner.exit_on_close)
    };
    emit(sock, Out::TcpClosed { owner });
    if exit_on_close {
        crate::port::abandon_port(&sock.runtime(), sock.id);
    }
}

fn satisfy(sock: &Arc<Sock>) {
    let _io = sock.io.lock().unwrap_or_else(|poison| poison.into_inner());
    let (outs, abandon) = {
        let mut inner = sock.inner.lock().unwrap();
        let mut outs = Vec::new();
        let abandon = take_packets(&sock.handle(), &mut inner, &mut outs);
        (outs, abandon)
    };
    for out in outs {
        emit(sock, out);
    }
    if abandon {
        crate::port::abandon_port(&sock.runtime(), sock.id);
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

fn tcp_read_size(inner: &Inner) -> usize {
    // Port of inet_drv.c:12896-12949 (packet_header_length and tcp_remain), OTP-29.1.1.
    let buffer = inner.buffer.max(1) as usize;
    if inner.read_ahead || inner.htype == 0 {
        return buffer;
    }
    let Some(ty) = packet_type(inner.htype) else {
        return 1;
    };
    let mut http = inner.http;
    match parse_with_state(
        ty,
        &inner.rbuf,
        PacketOptions {
            packet_size: inner.packet_size,
            line_length: 0,
            line_delimiter: inner.delimiter,
        },
        &mut http,
    ) {
        PacketResult::More(Some(packet_len)) => {
            return packet_len.saturating_sub(inner.rbuf.len()).max(1);
        }
        PacketResult::More(None) => {}
        PacketResult::Ok { .. } | PacketResult::Error => return 1,
    }
    let header_len: usize = match ty {
        PacketType::Length1 => 1,
        PacketType::Length2 => 2,
        PacketType::Length4 | PacketType::Sunrm | PacketType::Tpkt => 4,
        PacketType::Asn1 => 2,
        PacketType::Cdr => 12,
        PacketType::Fcgi => 8,
        PacketType::SslTls => 5,
        _ => 1,
    };
    header_len
        .saturating_sub(inner.rbuf.len())
        .max(1)
        .min(buffer)
}

fn tcp_packet_complete(inner: &Inner) -> bool {
    let Some(ty) = packet_type(inner.htype) else {
        return false;
    };
    let mut http = inner.http;
    matches!(
        parse_with_state(
            ty,
            &inner.rbuf,
            PacketOptions {
                packet_size: inner.packet_size,
                line_length: 0,
                line_delimiter: inner.delimiter,
            },
            &mut http,
        ),
        PacketResult::Ok { .. } | PacketResult::Error
    )
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
        let read_ahead = inner.read_ahead || inner.htype == 0;
        let mut eof = false;
        let mut bytes_read = 0;
        for _ in 0..32 {
            let read_size = if read_ahead {
                inner.buffer.max(1) as usize
            } else {
                tcp_read_size(&inner)
            };
            let mut buf = vec![0u8; read_size];
            // SAFETY: fd is the connected socket this driver owns.
            let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
            if n > 0 {
                bytes_read += n as usize;
                inner.rbuf.extend_from_slice(&buf[..n as usize]);
                if !read_ahead && tcp_packet_complete(&inner) {
                    break;
                }
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
        let owner = sock.handle().owner_pid();
        let reason = close_atom(&inner);
        // Port of erts/emulator/drivers/common/inet_drv.c:12805-12810 (tcp_recv_closed
        // aborts with ENOTCONN) and :12863-12867 (tcp_recv_error aborts with its err),
        // OTP-29.1.1, before any other close reporting. `pull` ends the stream on a
        // zero-byte read (closed) or ECONNRESET, which it records in `inner.reset`.
        if inner.sendfile.is_some() {
            let err = if inner.reset {
                libc::ECONNRESET
            } else {
                libc::ENOTCONN
            };
            drop(inner);
            emit(
                sock,
                Out::Sendfile {
                    owner,
                    result: Err(tcp_sendfile_aborted(err)),
                },
            );
            inner = sock.inner.lock().unwrap();
        }
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
            crate::port::abandon_port(&sock.runtime(), sock.id);
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

/// The inet thread: run the I/O tasks of `tcp_inet` ports and their timers.
///
/// Port of the port-task side of erts/emulator/sys/common/erl_check_io.c, OTP-29.1.1:
/// the poll set holds a persistent selection per socket (`driver_select`), a
/// readiness event schedules that port's task (`iready`/`oready`), the task runs
/// (`tcp_inet_input`/`tcp_inet_output` through `try_io`), and then the fired events
/// are re-armed (`erts_io_notify_port_task_executed`, :546-640). Only ports with an
/// event or a poke are touched; idle sockets cost nothing per event.
fn io_loop() {
    let (lock, wake) = tasks();
    loop {
        // Ports take the task lock (`poke`) while holding their own lock, so the
        // timers are read before it is taken.
        let timeout = next_timeout()
            .map(|timeout| Duration::new(timeout.tv_sec as u64, timeout.tv_nsec as u32));
        let (ready, poked) = {
            let mut tasks = lock.lock().unwrap();
            if tasks.ready.is_empty() && tasks.poked.is_empty() {
                tasks = match timeout {
                    Some(timeout) => wake.wait_timeout(tasks, timeout).unwrap().0,
                    None => wake.wait(tasks).unwrap(),
                };
            }
            (
                std::mem::take(&mut tasks.ready),
                std::mem::take(&mut tasks.poked),
            )
        };
        for (sock, fd, event) in ready {
            let Some(_runtime) = sock.runtime.upgrade() else {
                continue;
            };
            let Some(_handle) = sock.handle.upgrade() else {
                continue;
            };
            try_io(&sock, event.writable || event.error || event.closed);
            sock_select(&sock);
            crate::check_io::notify_executed(
                fd,
                sock.selection_owner,
                crate::check_io::InterestSet {
                    readable: true,
                    writable: true,
                },
            );
        }
        for sock in poked {
            let Some(_runtime) = sock.runtime.upgrade() else {
                continue;
            };
            let Some(_handle) = sock.handle.upgrade() else {
                continue;
            };
            try_io(&sock, false);
            sock_select(&sock);
        }
        for sock in fire_timeouts() {
            sock_select(&sock);
        }
    }
}

/// Bring the poll-set selection of `sock` in line with its state.
///
/// Port of the `sock_select` calls of erts/emulator/drivers/common/inet_drv.c,
/// OTP-29.1.1: FD_ACCEPT while an accept waits (:12224, :12584), FD_CONNECT while
/// connecting (:12109, :14243), FD_READ while active or a receive is pending
/// (:12126, :12317, :13110), FD_WRITE while the output queue is non-empty
/// (:13844, :14303).
fn sock_select(sock: &Arc<Sock>) {
    let mut inner = sock.inner.lock().unwrap();
    let readable = match inner.phase {
        Phase::Listening => !inner.accept_q.is_empty(),
        Phase::Connected => {
            !inner.peer_closed && (active_is(&inner.active) || inner.recv.is_some())
        }
        _ => false,
    };
    let writable = inner.phase == Phase::Connecting
        || !inner.sendq.is_empty()
        || (inner.phase == Phase::Connected && inner.sendfile.is_some());
    let Some(fd) = inner.fd.as_mut() else {
        return;
    };
    let want = crate::check_io::InterestSet { readable, writable };
    if want.readable == fd.selected.readable && want.writable == fd.selected.writable {
        return;
    }
    let raw = fd.as_raw_fd();
    let weak = Arc::downgrade(sock);
    let ready: crate::check_io::SelectCallback = Arc::new(move |fd, event| {
        if let Some(sock) = weak.upgrade() {
            schedule_ready(sock, fd, event);
        }
    });
    if crate::check_io::driver_select(raw, sock.selection_owner, want, ready).is_ok() {
        fd.selected = want;
    }
}

fn next_timeout() -> Option<libc::timespec> {
    let socks = live_socks();
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

/// Expire receive, accept, connect and send timers; returns the ports it changed.
fn fire_timeouts() -> Vec<Arc<Sock>> {
    let socks = live_socks();
    let now = Instant::now();
    let mut fired = Vec::new();
    for sock in socks {
        let Some(_runtime) = sock.runtime.upgrade() else {
            continue;
        };
        let Some(_handle) = sock.handle.upgrade() else {
            continue;
        };
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
                let owner = sock.handle().owner_pid();
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
        let changed = !due.is_empty() || !sends.is_empty();
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
                crate::port::abandon_port(&sock.runtime(), sock.id);
            }
        }
        if changed {
            fired.push(sock);
        }
    }
    fired
}
