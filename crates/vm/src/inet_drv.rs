//! `tcp_inet` / `tcp_inet6` port driver.
//!
//! Erlang `prim_inet` talks to this port with `port_control` (`INET_REQ_*`,
//! `TCP_REQ_*` in `inet_int.hrl`, plus `16#03f1a300`) and `port_command`.
//! Replies are `{inet_reply, …}`, `{inet_async, …}`, `{tcp, S, Data}`,
//! `{tcp_closed, S}` and `{tcp_passive, S}`.
//!
//! Port of `erts/emulator/drivers/common/inet_drv.c` (`tcp_inet_ctl`,
//! `tcp_inet_command`, `tcp_message`, `tcp_closed_message`), OTP-29.1.1.

use crate::VmError;
use crate::port::PortHandle;
use crate::process::{Message, MessageNode, Runtime};
use arinsal_drv::port_task::{PT_FLG_WAIT_BUSY, ProcSig, SigOp};
use arinsal_drv::{CommandPiece, ControlBytes, ControlReply, DriverPort, NativeDriver};
use arinsal_packet::{
    HttpPacket, HttpUri, Packet, PacketOptions, PacketResult, PacketState, PacketType,
    parse_with_state,
};
use arinsal_sched::Pid;
use arinsal_term::{HeapAlloc, Term, TermBuilder, global_atoms};
use parking_lot::Mutex;
use std::collections::VecDeque;
use std::ops::Range;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock, Weak};
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
const REQ_GETSERVBYNAME: i64 = 17;
const REQ_GETSERVBYPORT: i64 = 18;
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
const OPT_DONTROUTE: u8 = 2;
const OPT_LINGER: u8 = 3;
const OPT_BROADCAST: u8 = 4;
const OPT_OOBINLINE: u8 = 5;
const OPT_SNDBUF: u8 = 6;
const OPT_RCVBUF: u8 = 7;
const OPT_PRIORITY: u8 = 8;
const OPT_TOS: u8 = 9;
const OPT_NODELAY: u8 = 10;
const OPT_V6ONLY: u8 = 16;
const OPT_REUSEPORT: u8 = 17;
const OPT_REUSEPORT_LB: u8 = 18;
const OPT_EXCLUSIVEADDRUSE: u8 = 19;
const OPT_NON_BLOCK_SEND: u8 = 50;
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
#[cfg(target_os = "linux")]
const OPT_KEEPCNT: u8 = 51;
#[cfg(target_os = "linux")]
const OPT_KEEPIDLE: u8 = 52;
#[cfg(target_os = "linux")]
const OPT_KEEPINTVL: u8 = 53;
#[cfg(target_os = "linux")]
const OPT_USER_TIMEOUT: u8 = 54;
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

fn atom(name: &'static str) -> Term {
    crate::atom_cache::atom(name)
}

fn atom_dyn(name: &str) -> Term {
    Term::atom(global_atoms().intern(name).expect("inet atom"))
}

fn badarg() -> VmError {
    VmError::Trap(crate::exceptions::Trap::error(atom("badarg")))
}

/// `driver_flags` of `tcp_inet_driver_entry`: `ERL_DRV_FLAG_USE_PORT_LOCKING |
/// ERL_DRV_FLAG_SOFT_BUSY` (erts/emulator/drivers/common/inet_drv.c).
const DRIVER_FLAGS: i32 = (1 << 0) | (1 << 1);

/// The linked-in `tcp_inet` driver. A port of it is a port like any other driver's:
/// process signals run as immediate calls or port tasks, `driver_select` readiness and
/// the port timer schedule port tasks that a scheduler executes with the port locked.
///
/// Port of erts/emulator/drivers/common/inet_drv.c (`tcp_inet_driver_entry`), OTP-29.1.1.
pub(crate) fn driver() -> Arc<arinsal_drv::Driver> {
    static DRIVER: OnceLock<Arc<arinsal_drv::Driver>> = OnceLock::new();
    Arc::clone(
        DRIVER.get_or_init(|| {
            arinsal_drv::Driver::native("tcp_inet", DRIVER_FLAGS, Arc::new(TcpInet))
        }),
    )
}

/// The callbacks of `tcp_inet_driver_entry`.
struct TcpInet;

/// The socket of a port together with its port handle, which stays alive for the whole
/// callback: the callback may close the port (`driver_exit`) and still emits after that.
fn sock_of(port: &DriverPort) -> Option<(Arc<Sock>, Arc<PortHandle>)> {
    let sock = port.native_data::<Sock>()?;
    let handle = sock.handle.upgrade()?;
    Some((sock, handle))
}

impl NativeDriver for TcpInet {
    fn has_outputv(&self) -> bool {
        true
    }

    // Port of inet_drv.c (tcp_inet_stop).
    fn stop(&self, port: &DriverPort) {
        if let Some((sock, _handle)) = sock_of(port) {
            tcp_inet_stop(&sock);
        }
    }

    // Port of inet_drv.c (tcp_inet_commandv).
    fn output(&self, port: &DriverPort, data: &[u8]) {
        if let Some((sock, _handle)) = sock_of(port) {
            command(&sock, Pid::from_data(port.caller()), data.to_vec());
        }
    }

    // Port of inet_drv.c (tcp_inet_commandv): the flattened command is queued as it is.
    fn output_owned(&self, port: &DriverPort, data: Vec<u8>) {
        if let Some((sock, _handle)) = sock_of(port) {
            command(&sock, Pid::from_data(port.caller()), data);
        }
    }

    // Port of inet_drv.c (tcp_inet_commandv): refc binaries of the command stay referenced.
    fn outputv_owned(&self, port: &DriverPort, pieces: arinsal_drv::CommandVector) {
        if let Some((sock, _handle)) = sock_of(port) {
            command_pieces(&sock, Pid::from_data(port.caller()), pieces);
        }
    }

    // Port of inet_drv.c (tcp_inet_ctl).
    fn control(&self, port: &DriverPort, op: u32, data: &[u8]) -> Option<ControlReply> {
        let (sock, _handle) = sock_of(port)?;
        let reply = control(&sock, Pid::from_data(port.caller()), op, data);
        Some(ControlReply::List(reply))
    }

    // Port of inet_drv.c (tcp_inet_input).
    fn ready_input(&self, port: &DriverPort, _fd: i32) {
        if let Some((sock, _handle)) = sock_of(port) {
            try_io(&sock, false);
            settle(&sock);
        }
    }

    // Port of inet_drv.c (tcp_inet_output).
    fn ready_output(&self, port: &DriverPort, _fd: i32) {
        if let Some((sock, _handle)) = sock_of(port) {
            try_io(&sock, true);
            settle(&sock);
        }
    }

    // Port of inet_drv.c (tcp_inet_timeout).
    fn timeout(&self, port: &DriverPort) {
        if let Some((sock, _handle)) = sock_of(port) {
            sock.inner.lock().timer_at = None;
            expire(&sock);
            settle(&sock);
        }
    }

    // Port of inet_drv.c (inet_stop_select): the descriptor closes with its `SockFd`.
    fn stop_select(&self, _fd: i32) {}

    // Port of inet_drv.c (tcp_inet_process_exit).
    fn process_exit(&self, port: &DriverPort, monitor: u64) {
        if let Some((sock, _handle)) = sock_of(port) {
            acceptor_exited(&sock, monitor);
        }
    }
}

/// Bring selection, port timer and busy state in line with the socket after a callback.
fn settle(sock: &Arc<Sock>) {
    let Some(port) = sock.port() else {
        return;
    };
    // One look at the socket state for all three, as the C callback reads its descriptor once.
    let task_deadline = port.next_task_deadline();
    let (timer, busy) = {
        let mut inner = sock.inner.lock();
        select_locked(&port, &mut inner);
        let port_busy = port.sched_flags() & arinsal_drv::port_task::PTS_FLG_BUSY_PORT != 0;
        (
            timer_change(&mut inner, task_deadline),
            (inner.busy != port_busy).then_some(inner.busy),
        )
    };
    set_port_timer(&port, timer);
    if let Some(busy) = busy {
        port.set_busy_port(busy);
    }
}

/// `driver_exit(port, 0)`: the peer closed an `{exit_on_close, true}` socket.
fn driver_exit(sock: &Sock) {
    if let Some(port) = sock.port() {
        port.driver_exit();
    }
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

/// Install the driver state of a `tcp_inet` port (`tcp_inet_start` /
/// `tcp_inet_copy` for `driver_create_port`).
pub(crate) fn attach(runtime: &'static Runtime, handle: &Arc<PortHandle>, port: &DriverPort) {
    let sock = Arc::new(Sock::new(handle.id(), runtime, handle, port));
    port.start_native(sock);
}

/// Port of erts/emulator/drivers/common/inet_drv.c (tcp_inet_stop and tcp_desc_close),
/// OTP-29.1.1: the port terminates; waiters receive `{error, closed}`.
fn tcp_inet_stop(sock: &Arc<Sock>) {
    sock.stopped.store(true, Ordering::Release);
    let id = sock.id;
    // The port closed while owning a dist connection (its controller exited, e.g. through
    // `net_kernel:disconnect/1`): tear the connection down and deliver nodedown.
    // Port of erts/emulator/beam/dist.c (erts_do_net_exits via the dist port's exit), OTP-29.1.1.
    if crate::node_tables::is_dist_port(id) {
        let _ = crate::dist::port_connection_closed(sock.runtime, id);
    }
    let pending = {
        let mut inner = sock.inner.lock();
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
        inner.take_fd();
        inner.phase = Phase::Closed;
        // Port of inet_drv.c (tcp_inet_stop, tcp_clear_output): a sender blocked on the
        // queue is released by the port's exit, not by a reply.
        inner
            .pending
            .take()
            .map(|pending| *pending)
            .unwrap_or_default()
    };
    send_empty_out_q_msgs(sock);
    for (caller, aref) in pending {
        emit(
            sock,
            Out::AsyncError {
                caller,
                aref,
                reason: "closed",
            },
        );
    }
}

/// Port of erts/emulator/drivers/common/inet_drv.c (tcp_inet_ctl), OTP-29.1.1.
fn control(sock: &Arc<Sock>, caller: Pid, op: u32, data: &[u8]) -> ControlBytes {
    // Port of inet_drv.c:11956 (tcp_inet_ctl subtracts the magic), OTP-29.1.1.
    let cmd = i64::from(op).wrapping_sub(MAGIC);
    let reply = dispatch(sock, caller, cmd, data);
    settle(sock);
    reply
}

fn command(sock: &Arc<Sock>, caller: Pid, data: Vec<u8>) {
    // Port of inet_drv.c:13736 (tcp_sendv) and :12629 (tcp_inet_command), OTP-29.1.1.
    let Some((ids, payload)) = split_caller(&data) else {
        return;
    };
    let start = data.len() - payload.len();
    let outcome = {
        let mut inner = sock.inner.lock();
        accept_send(&mut inner, SendData::Owned(data, start))
    };
    finish_command(sock, outcome, Some((caller, ids)));
}

/// `command` for a vector: the caller reference prefix is in the first element, the packet is
/// everything after it, with refc binaries referenced (`tcp_sendv` over an `ErlIOVec`).
fn command_pieces(sock: &Arc<Sock>, caller: Pid, pieces: arinsal_drv::CommandVector) {
    let Some(CommandPiece::Bytes(first)) = pieces.first() else {
        return;
    };
    let Some((ids, payload)) = split_caller(first) else {
        return;
    };
    let start = first.len() - payload.len();
    let outcome = {
        let mut inner = sock.inner.lock();
        accept_send(&mut inner, SendData::Pieces(pieces, start))
    };
    finish_command(sock, outcome, Some((caller, ids)));
}

/// What a send does once `tcp_sendv` decided: reply, or fail the socket.
fn finish_command(sock: &Arc<Sock>, outcome: SendOutcome, reply: Option<(Pid, [u32; 3])>) {
    match outcome {
        SendOutcome::Reply(error) => {
            if let Some((caller, ids)) = reply {
                emit(sock, Out::InetReply { caller, ids, error });
            }
        }
        SendOutcome::Deferred { deadline } => {
            if let (Some((caller, ids)), Some(port)) = (reply, sock.port()) {
                port.set_busy_port(true);
                let weak = Arc::downgrade(sock);
                let _ = port.schedule_signal(ProcSig {
                    caller: caller.data(),
                    flags: PT_FLG_WAIT_BUSY,
                    size: 0,
                    deadline,
                    callback: Box::new(move |op| {
                        if let Some(sock) = weak.upgrade() {
                            let error = match op {
                                SigOp::Exec => {
                                    let inner = sock.inner.lock();
                                    inner.peer_closed.then(|| close_atom(&inner))
                                }
                                SigOp::Abort => Some("timeout"),
                                SigOp::AbortNosuspend | SigOp::AbortClosed => Some("closed"),
                            };
                            emit(&sock, Out::InetReply { caller, ids, error });
                        }
                        0
                    }),
                });
            }
        }
        SendOutcome::Failed { error, active } => {
            if let Some((caller, ids)) = reply {
                emit(
                    sock,
                    Out::InetReply {
                        caller,
                        ids,
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
                if sock.inner.lock().exit_on_close {
                    driver_exit(sock);
                }
            }
            send_empty_out_q_msgs(sock);
        }
    }
    settle(sock);
}

/// Write a raw distribution packet (no caller-ref prefix, no `inet_reply`) with the port
/// locked, as the dist command task does.
///
/// Port of dist.c:3794 (`dist_port_command`) calling `tcp_inet_command` with
/// `prt->caller = NIL`, so `init_caller` skips the ref header, OTP-29.1.1.
pub(crate) fn dist_output(sock: &Arc<Sock>, data: &[u8]) -> Result<bool, VmError> {
    let (Some(port), Some(_handle)) = (sock.port(), sock.handle.upgrade()) else {
        return Err(badarg());
    };
    port.serialized(|| {
        let outcome = {
            let mut inner = sock.inner.lock();
            // Dummy caller/ids: dist never waits on inet_reply for these writes.
            accept_send(&mut inner, SendData::Borrowed(data))
        };
        finish_command(sock, outcome, None);
        Ok(sock.inner.lock().busy)
    })
}

enum SendOutcome {
    Reply(Option<&'static str>),
    Deferred { deadline: Option<Instant> },
    Failed { error: &'static str, active: bool },
}

/// Bytes handed to `tcp_sendv`: the port command keeps its flattened buffer (the
/// payload starts at the offset), distribution borrows its packet.
// OTP passes an inline ErlIOVec through tcp_inet_commandv and tcp_sendv.
#[allow(clippy::large_enum_variant)]
enum SendData<'a> {
    Owned(Vec<u8>, usize),
    Borrowed(&'a [u8]),
    /// A command vector; the payload starts at the offset in its first element.
    Pieces(arinsal_drv::CommandVector, usize),
}

impl SendData<'_> {
    /// Payload length (`ErlIOVec.size` less the caller prefix).
    fn len(&self) -> usize {
        match self {
            SendData::Owned(buf, start) => buf.len() - start,
            SendData::Borrowed(bytes) => bytes.len(),
            SendData::Pieces(pieces, start) => {
                pieces
                    .iter()
                    .map(|piece| piece.bytes().len())
                    .sum::<usize>()
                    - start
            }
        }
    }

    /// The payload as `iovec` entries, appended to `iov`.
    fn push_iov(&self, iov: &mut smallvec::SmallVec<[libc::iovec; 16]>) {
        let mut entry = |bytes: &[u8]| {
            if !bytes.is_empty() {
                iov.push(libc::iovec {
                    iov_base: bytes.as_ptr() as *mut libc::c_void,
                    iov_len: bytes.len(),
                });
            }
        };
        match self {
            SendData::Owned(buf, start) => entry(&buf[*start..]),
            SendData::Borrowed(bytes) => entry(bytes),
            SendData::Pieces(pieces, start) => {
                for (index, piece) in pieces.iter().enumerate() {
                    entry(&piece.bytes()[if index == 0 { *start } else { 0 }..]);
                }
            }
        }
    }

    /// Queue the payload from `skip` on. Owned buffers and referenced binaries move into
    /// the queue (`driver_enqv`).
    fn enqueue(self, q: &mut IoQueue, skip: usize) {
        match self {
            SendData::Owned(buf, start) => q.enq_owned(buf, start + skip),
            SendData::Borrowed(bytes) => q.enq(&bytes[skip..]),
            SendData::Pieces(pieces, start) => {
                let mut skip = start + skip;
                for piece in pieces {
                    let len = piece.bytes().len();
                    if skip >= len {
                        skip -= len;
                        continue;
                    }
                    q.enq_piece(piece, skip);
                    skip = 0;
                }
            }
        }
    }
}

fn accept_send(inner: &mut Inner, payload: SendData<'_>) -> SendOutcome {
    // Port of erts/emulator/drivers/common/inet_drv.c:13736-13847 (tcp_sendv), OTP-29.1.1.
    // With `{exit_on_close, false}` an EOF only closes the read side (desc_close_read); the
    // socket stays connected for sending until the send fails or it is closed.
    if inner.peer_closed && inner.fd.is_none() {
        return SendOutcome::Reply(Some(close_atom(inner)));
    }
    if inner.phase != Phase::Connected {
        return SendOutcome::Reply(Some("enotconn"));
    }
    // Port of inet_drv.c (tcp_inet_commandv): a send after a pending shutdown(write).
    if inner.pending_shut != 0 {
        return send_or_shutdown_failed(inner, libc::EPIPE);
    }
    let len = payload.len();
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
            return SendOutcome::Deferred { deadline };
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
    let mut iov = smallvec::SmallVec::<[libc::iovec; 16]>::new();
    if h_len != 0 {
        iov.push(libc::iovec {
            iov_base: hdr.as_ptr() as *mut libc::c_void,
            iov_len: h_len,
        });
    }
    payload.push_iov(&mut iov);
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
    // Port of inet_drv.c:13690 (tcp_send_error), OTP-29.1.1: an EPIPE that is not the result
    // of our own shutdown(write) is a reset by the peer.
    let err = if err == libc::EPIPE && !inner.shutdown_wr_done {
        libc::ECONNRESET
    } else {
        err
    };
    send_or_shutdown_failed(inner, err)
}

/// Port of inet_drv.c:13613 (tcp_send_or_shutdown_error), OTP-29.1.1.
fn send_or_shutdown_failed(inner: &mut Inner, err: i32) -> SendOutcome {
    let show = inner.show_econnreset && err == libc::ECONNRESET;
    inner.reset = show;
    inner.peer_closed = true;
    inner.sendq.clear();
    inner.busy = false;
    inner.take_fd();
    let active = active_is(&inner.active);
    if active {
        inner.closed_sent = true;
    }
    SendOutcome::Failed {
        error: if show { "econnreset" } else { "closed" },
        active,
    }
}

fn dispatch(sock: &Arc<Sock>, caller: Pid, cmd: i64, data: &[u8]) -> ControlBytes {
    let mut accept_now: Option<(OwnedFd, u16)> = None;
    let mut sendfile_end: Option<SendfileEnd> = None;
    let mut setopts_action = SetoptsAction::None;
    let mut emit_passive = false;
    let reply: ControlBytes = {
        let mut inner = sock.inner.lock();
        match cmd {
            REQ_OPEN => open_socket(&mut inner, data).into(),
            REQ_FDOPEN => fdopen_socket(&mut inner, data).into(),
            REQ_GETFD => getfd(&inner).into(),
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
                inner.take_fd();
                inner.phase = Phase::Closed;
                ok_small()
            }
            REQ_BIND => bind_socket(&mut inner, data).into(),
            REQ_LISTEN => listen_socket(&mut inner, data).into(),
            REQ_CONNECT => connect_socket(sock, &mut inner, caller, data).into(),
            REQ_ACCEPT => match accept_socket(sock, &mut inner, caller, data) {
                Accept::Reply(bytes) => bytes.into(),
                Accept::Now(fd, aref, bytes) => {
                    accept_now = Some((fd, aref));
                    bytes.into()
                }
            },
            REQ_NAME => sockname(&inner).into(),
            REQ_PEER => peername(&inner).into(),
            REQ_SETOPTS => {
                let (reply, action, passive) = setopts(&mut inner, data);
                setopts_action = action;
                emit_passive |= passive;
                reply
            }
            REQ_GETOPTS => getopts(&inner, data).into(),
            REQ_GETSTAT => getstat(&inner, data).into(),
            REQ_GETIFLIST | REQ_IFGET | REQ_GETIFADDRS => interface_control(
                cmd,
                data,
                inner.phase != Phase::Closed && inner.fd.is_some(),
            )
            .unwrap_or_else(|| err_bytes("exbadport"))
            .into(),
            REQ_GETSERVBYNAME | REQ_GETSERVBYPORT => interface_control(cmd, data, true)
                .unwrap_or_else(|| err_bytes("exbadport"))
                .into(),
            REQ_SUBSCRIBE => subscribe(&mut inner, caller, data).into(),
            REQ_GETTYPE => gettype(&inner).into(),
            REQ_GETSTATUS => getstatus(&inner).into(),
            TCP_REQ_RECV => recv_req(&mut inner, caller, data).into(),
            TCP_REQ_SHUTDOWN => shutdown_sock(&mut inner, data).into(),
            TCP_REQ_SENDFILE => sendfile_req(&mut inner, data, &mut sendfile_end).into(),
            _ => err_bytes("exbadport").into(),
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
    if cmd == REQ_SETOPTS {
        match setopts_action {
            SetoptsAction::None => {}
            SetoptsAction::Select => sock_select(sock),
            SetoptsAction::Deliver => {
                satisfy(sock);
                sock_select(sock);
            }
            SetoptsAction::Recv => {
                let eof = pull(sock);
                satisfy(sock);
                if let Some(error) = eof {
                    on_eof(sock, error);
                }
                sock_select(sock);
            }
        }
        // A socket already closed (EOF, send error) reports it once it turns active.
        deliver_pending_close(sock);
    } else if cmd == TCP_REQ_RECV {
        try_io(sock, false);
        sock_select(sock);
    } else if cmd == REQ_CONNECT {
        // Port of inet_drv.c:12098-12114 (INET_REQ_CONNECT): `sock_select(FD_CONNECT)` right
        // after connect() returns EINPROGRESS, so the completion event is reported ahead of
        // the accept the connection causes on the listening side.
        sock_select(sock);
        try_io(sock, false);
    }
    if emit_passive {
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
        REQ_GETSERVBYNAME => servbyname_req(data),
        REQ_GETSERVBYPORT => servbyport_req(data),
        _ => return None,
    };
    Some(reply)
}

/// Port of inet_drv.c (inet_ctl INET_REQ_GETSERVBYNAME), OTP-29.1.1: `L1 Name L2 Proto`.
fn servbyname_req(data: &[u8]) -> Vec<u8> {
    if data.len() < 2 {
        return err_bytes("einval");
    }
    let n = usize::from(data[0]);
    // The `=` makes the test include the next length byte.
    if n >= data.len() - 1 {
        return err_bytes("einval");
    }
    let name = &data[1..1 + n];
    let rest = &data[1 + n..];
    let m = usize::from(rest[0]);
    if m > rest.len() - 1 {
        return err_bytes("einval");
    }
    let proto = &rest[1..1 + m];
    let (Ok(name), Ok(proto)) = (std::ffi::CString::new(name), std::ffi::CString::new(proto))
    else {
        return err_bytes("einval");
    };
    match arinsal_nif_socket::servbyname(&name, &proto) {
        Some(port) => ok_bytes(&port.to_be_bytes()),
        None => err_bytes("einval"),
    }
}

/// Port of inet_drv.c (inet_ctl INET_REQ_GETSERVBYPORT), OTP-29.1.1: `P1 P0 L1 Proto`.
fn servbyport_req(data: &[u8]) -> Vec<u8> {
    if data.len() < 3 {
        return err_bytes("einval");
    }
    let port = u16::from_be_bytes([data[0], data[1]]);
    let n = usize::from(data[2]);
    if n > data.len() - 3 {
        return err_bytes("einval");
    }
    let Ok(proto) = std::ffi::CString::new(&data[3..3 + n]) else {
        return err_bytes("einval");
    };
    match arinsal_nif_socket::servbyport(port, &proto) {
        Some(name) => ok_bytes(name.as_bytes()),
        None => err_bytes("einval"),
    }
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
    inner.fd = Some(SockFd::new(unsafe { OwnedFd::from_raw_fd(fd) }));
    inner.domain = domain;
    inner.family_code = data[0];
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
    inner.fd = Some(SockFd::new(fd));
    // Port of inet_drv.c:5269 (inet_fdopen, `prebound`): the port selects on the descriptor
    // number it was given, so a later port on it steals the selection from the earlier one.
    if let Some(fd) = inner.fd.as_mut() {
        fd.select_fd = raw_fd;
    }
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
    // `select_fd` is the number the socket was opened with: the caller's for `{fd, Fd}`.
    let raw = fd.select_fd;
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
            inner.take_fd();
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
            inner.connect = Some(Box::new(Waiter {
                monitor: None,
                caller,
                aref,
                deadline: deadline(timeout),
            }));
            inner
                .pending
                .get_or_insert_with(Default::default)
                .push((caller, aref));
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
                // Port of inet_drv.c (INET_REQ_ACCEPT: driver_monitor_process on the caller).
                let monitor = inner
                    .port
                    .as_ref()
                    .and_then(|port| port.upgrade())
                    .and_then(|port| port.monitor(caller.data()));
                inner.accept_q.push_back(Waiter {
                    caller,
                    aref,
                    deadline: deadline(timeout),
                    monitor,
                });
                inner
                    .pending
                    .get_or_insert_with(Default::default)
                    .push((caller, aref));
            }
            Accept::Reply(ok_bytes(&aref.to_be_bytes()))
        }
    }
}

/// A monitored acceptor exited: its accept leaves the queue.
// Port of inet_drv.c (tcp_inet_process_exit), OTP-29.1.1.
fn acceptor_exited(sock: &Arc<Sock>, monitor: u64) {
    {
        let mut inner = sock.inner.lock();
        let (gone, keep): (VecDeque<_>, VecDeque<_>) = inner
            .accept_q
            .take_all()
            .into_iter()
            .partition(|waiter| waiter.monitor == Some(monitor));
        inner.accept_q = keep.into();
        for waiter in &gone {
            drop_pending(&mut inner, waiter.caller, waiter.aref);
        }
    }
    settle(sock);
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
    let mut fd = Some(fd);
    // Port of erts/emulator/drivers/common/inet_drv.c:11829-11839 (tcp_inet_copy), OTP-29.1.1.
    let created = crate::port::alloc_inet_port(runtime, caller, name, driver(), |handle, port| {
        let fd = fd.take().expect("accepted descriptor");
        // Port of inet_drv.c:11795 (tcp_inet_copy), OTP-29.1.1.
        // `active` is not copied here; prim_inet:accept_opts sets it afterwards.
        let born = {
            let inner = listen.inner.lock();
            Inner {
                fd: Some(SockFd::new(fd)),
                port: Some(port.weak()),
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
        let sock = Arc::new(Sock::with_inner(handle.id(), runtime, handle, born));
        port.start_native(sock);
    });
    let (id, handle, port) = match created {
        Ok(created) => created,
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
    // Port of inet_drv.c:2514 (send_async_ok_port), OTP-29.1.1.
    emit(
        listen,
        Out::AsyncPort {
            caller,
            aref,
            port: id,
        },
    );
    if let Some(sock) = handle.tcp_driver_data() {
        port.serialized(|| settle(&sock));
    }
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

#[derive(Clone, Copy)]
enum SetoptsAction {
    None,
    Select,
    Deliver,
    Recv,
}

fn setopts(inner: &mut Inner, data: &[u8]) -> (ControlBytes, SetoptsAction, bool) {
    // Port of inet_drv.c:6871, 7950-7980 (inet_set_opts), OTP-29.1.1.
    let old_active = inner.active_value;
    let old_was_active = active_is(&inner.active);
    let old_htype = inner.htype;
    let mut emit_passive = false;
    let mut i = 0;
    while i < data.len() {
        let code = data[i];
        i += 1;
        if i + 4 > data.len() {
            return (err_small("einval"), SetoptsAction::None, false);
        }
        let val = i32::from_be_bytes(data[i..i + 4].try_into().unwrap());
        i += 4;
        if !apply_opt(inner, code, val, data, &mut i, &mut emit_passive) {
            return (err_small("einval"), SetoptsAction::None, false);
        }
    }
    let action = if inner.phase != Phase::Connected {
        SetoptsAction::None
    } else if !old_was_active && matches!(inner.active_value, 2 | 3) && inner.htype == old_htype {
        SetoptsAction::Recv
    } else if inner.active_value != old_active {
        if active_is(&inner.active) && !old_was_active {
            SetoptsAction::Deliver
        } else {
            SetoptsAction::Select
        }
    } else if active_is(&inner.active) && inner.htype != old_htype {
        SetoptsAction::Deliver
    } else {
        SetoptsAction::None
    };
    (ok_small(), action, emit_passive)
}

fn apply_opt(
    inner: &mut Inner,
    code: u8,
    val: i32,
    data: &[u8],
    i: &mut usize,
    emit_passive: &mut bool,
) -> bool {
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
        #[cfg(not(target_os = "linux"))]
        OPT_PRIORITY => {}
        #[cfg(target_os = "linux")]
        OPT_PRIORITY => {
            if !sock_set(inner, libc::SOL_SOCKET, libc::SO_PRIORITY, val, true) {
                return false;
            }
        }
        // Port of inet_drv.c (TCP_OPT_KEEPCNT .. USER_TIMEOUT, `#if defined(TCP_KEEPCNT)` etc.).
        #[cfg(target_os = "linux")]
        OPT_KEEPCNT => sock_int(inner, libc::IPPROTO_TCP, libc::TCP_KEEPCNT, val),
        #[cfg(target_os = "linux")]
        OPT_KEEPIDLE => sock_int(inner, libc::IPPROTO_TCP, libc::TCP_KEEPIDLE, val),
        #[cfg(target_os = "linux")]
        OPT_KEEPINTVL => sock_int(inner, libc::IPPROTO_TCP, libc::TCP_KEEPINTVL, val),
        #[cfg(target_os = "linux")]
        OPT_USER_TIMEOUT => sock_int(inner, libc::IPPROTO_TCP, libc::TCP_USER_TIMEOUT, val),
        OPT_DONTROUTE => sock_bool(inner, libc::SOL_SOCKET, libc::SO_DONTROUTE, val != 0),
        OPT_BROADCAST => sock_bool(inner, libc::SOL_SOCKET, libc::SO_BROADCAST, val != 0),
        OPT_OOBINLINE => sock_bool(inner, libc::SOL_SOCKET, libc::SO_OOBINLINE, val != 0),
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
        #[cfg(not(target_os = "linux"))]
        OPT_NOPUSH => {}
        // INET_TCP_NOPUSH is TCP_CORK on Linux.
        #[cfg(target_os = "linux")]
        OPT_NOPUSH => sock_bool(inner, libc::IPPROTO_TCP, libc::TCP_CORK, val != 0),
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
                    *emit_passive = true;
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
        #[cfg(not(target_os = "linux"))]
        OPT_REUSEPORT_LB => {}
        // SO_REUSEPORT is load balancing on Linux.
        #[cfg(target_os = "linux")]
        OPT_REUSEPORT_LB => sock_bool(inner, libc::SOL_SOCKET, libc::SO_REUSEPORT, val != 0),
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
        // Port of inet_drv.c (inet_set_opts): Windows only / SCTP only, ignored elsewhere.
        OPT_EXCLUSIVEADDRUSE | OPT_NON_BLOCK_SEND => {}
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
        #[cfg(not(target_os = "linux"))]
        OPT_PRIORITY => write_i32(out, 0),
        #[cfg(target_os = "linux")]
        OPT_PRIORITY => {
            if let Some(value) = sock_get_int(inner, libc::SOL_SOCKET, libc::SO_PRIORITY) {
                write_i32(out, value);
            }
        }
        #[cfg(target_os = "linux")]
        OPT_KEEPCNT => {
            if let Some(value) = sock_get_int(inner, libc::IPPROTO_TCP, libc::TCP_KEEPCNT) {
                write_i32(out, value);
            }
        }
        #[cfg(target_os = "linux")]
        OPT_KEEPIDLE => {
            if let Some(value) = sock_get_int(inner, libc::IPPROTO_TCP, libc::TCP_KEEPIDLE) {
                write_i32(out, value);
            }
        }
        #[cfg(target_os = "linux")]
        OPT_KEEPINTVL => {
            if let Some(value) = sock_get_int(inner, libc::IPPROTO_TCP, libc::TCP_KEEPINTVL) {
                write_i32(out, value);
            }
        }
        #[cfg(target_os = "linux")]
        OPT_USER_TIMEOUT => {
            if let Some(value) = sock_get_int(inner, libc::IPPROTO_TCP, libc::TCP_USER_TIMEOUT) {
                write_i32(out, value);
            }
        }
        OPT_DONTROUTE => {
            if let Some(value) = sock_get_int(inner, libc::SOL_SOCKET, libc::SO_DONTROUTE) {
                write_i32(out, value);
            }
        }
        OPT_BROADCAST => {
            if let Some(value) = sock_get_int(inner, libc::SOL_SOCKET, libc::SO_BROADCAST) {
                write_i32(out, value);
            }
        }
        OPT_OOBINLINE => {
            if let Some(value) = sock_get_int(inner, libc::SOL_SOCKET, libc::SO_OOBINLINE) {
                write_i32(out, value);
            }
        }
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
        #[cfg(not(target_os = "linux"))]
        OPT_NOPUSH => write_i32(out, 0),
        #[cfg(target_os = "linux")]
        OPT_NOPUSH => {
            if let Some(value) = sock_get_int(inner, libc::IPPROTO_TCP, libc::TCP_CORK) {
                write_i32(out, i32::from(value != 0));
            }
        }
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
        #[cfg(not(target_os = "linux"))]
        OPT_REUSEPORT_LB => write_i32(out, 0),
        #[cfg(target_os = "linux")]
        OPT_REUSEPORT_LB => {
            if let Some(value) = sock_get_int(inner, libc::SOL_SOCKET, libc::SO_REUSEPORT) {
                write_i32(out, i32::from(value != 0));
            }
        }
        // inet_fill_opts answers 0 where SO_EXCLUSIVEADDRUSE does not exist (not Windows).
        OPT_EXCLUSIVEADDRUSE => write_i32(out, 0),
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
            // PLACE_FOR(13 + arg_sz) fails once the reply would pass INET_MAX_OPT_BUFFER.
            if size < 0
                || size as usize > MAX_OPT_BUFFER
                || out.len() + 13 + size as usize > MAX_OPT_BUFFER
            {
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
            save_subscriber(
                inner.empty_out_q_subs.get_or_insert_with(Default::default),
                caller,
            );
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
        let mut inner = sock.inner.lock();
        if !inner.sendq.is_empty() {
            return;
        }
        inner
            .empty_out_q_subs
            .take()
            .map(|subs| *subs)
            .unwrap_or_default()
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
    if inner.peer_closed && !buffered_deliverable(inner, data) {
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
    inner
        .pending
        .get_or_insert_with(Default::default)
        .push((caller, aref));
    if timeout == 0 {
        inner.recv_timeout_if_empty = true;
    }
    ok_bytes(&aref.to_be_bytes())
}

fn has_buffered_packet(inner: &Inner) -> bool {
    if rbuf_len(inner) == 0 {
        false
    } else if inner.htype == 0 {
        true
    } else {
        tcp_packet_complete(inner)
    }
}

/// After EOF a receive still succeeds from input read before it (tcp_recv drains the buffer
/// before it reads the socket again).
fn buffered_deliverable(inner: &Inner, data: &[u8]) -> bool {
    if rbuf_len(inner) == 0 || active_is(&inner.active) || data.len() != 8 {
        return false;
    }
    let length = i32::from_be_bytes(data[4..8].try_into().unwrap());
    if inner.htype == 0 {
        usize::try_from(length).is_ok_and(|n| rbuf_len(inner) >= n.max(1))
    } else {
        tcp_packet_complete(inner)
    }
}

fn shutdown_sock(inner: &mut Inner, data: &[u8]) -> Vec<u8> {
    // Port of inet_drv.c:12339 (TCP_REQ_SHUTDOWN), OTP-29.1.1.
    if inner.phase != Phase::Connected {
        return err_bytes("enotconn");
    }
    if data.len() != 1 || data[0] > 2 {
        return err_bytes("einval");
    }
    let how = data[0];
    // SHUT_RD is 0, SHUT_WR 1, SHUT_RDWR 2. Output still queued is sent first.
    if how != 0 && inner.sendq.size() > 0 {
        inner.pending_shut = how;
        return ok_bytes(&[]);
    }
    let fd = inner.fd.as_ref().unwrap().as_raw_fd();
    // SAFETY: fd is the connected socket this driver owns.
    let rc = unsafe { libc::shutdown(fd, i32::from(how)) };
    if rc < 0 {
        if how != 0 {
            inner.shutdown_wr_done = true;
        }
        return err_bytes(errno_name(last_errno()));
    }
    ok_bytes(&[])
}

/// Shutdown on the socket once the queue has emptied.
// Port of inet_drv.c (tcp_shutdown_async), OTP-29.1.1. `Some(errno)` when it failed.
fn shutdown_async(inner: &mut Inner) -> Option<i32> {
    let how = if inner.pending_shut == 1 { 1 } else { 2 };
    let fd = inner.fd.as_ref()?.as_raw_fd();
    // SAFETY: fd is the connected socket this driver owns.
    if unsafe { libc::shutdown(fd, how) } < 0 {
        return Some(last_errno());
    }
    inner.shutdown_wr_done = true;
    None
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
    segs: VecDeque<(CommandPiece, usize)>,
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
            self.segs
                .push_back((CommandPiece::Bytes(bytes.to_vec()), 0));
        }
    }

    /// `driver_enqv` with a skip: queue `buf[start..]` without copying it.
    fn enq_owned(&mut self, buf: Vec<u8>, start: usize) {
        if start < buf.len() {
            self.size += buf.len() - start;
            self.segs.push_back((CommandPiece::Bytes(buf), start));
        }
    }

    /// `driver_enqv` of one vector element, referenced binaries included.
    fn enq_piece(&mut self, piece: CommandPiece, start: usize) {
        let len = piece.bytes().len();
        if start < len {
            self.size += len - start;
            self.segs.push_back((piece, start));
        }
    }

    /// First entry of `driver_peekq` (`iov[0]`): the unsent bytes of the head segment.
    fn head(&self) -> Option<&[u8]> {
        self.segs.front().map(|(buf, start)| &buf.bytes()[*start..])
    }

    /// `driver_peekq`, limited to `max` entries.
    fn peekq(&self, max: usize) -> Vec<libc::iovec> {
        self.segs
            .iter()
            .take(max)
            .map(|(buf, start)| libc::iovec {
                iov_base: buf.bytes()[*start..].as_ptr() as *mut libc::c_void,
                iov_len: buf.bytes().len() - start,
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
            let len = buf.bytes().len() - *start;
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
    inner.sendfile = Some(Box::new(Sendfile {
        ioq_skip: inner.sendq.size(),
        dup_file_fd,
        bytes_sent: 0,
        offset,
        length,
    }));
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
                if sock.inner.lock().exit_on_close {
                    driver_exit(sock);
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
    runtime: &'static Runtime,
    handle: Weak<PortHandle>,
    /// `tcp_inet_stop` ran: the port no longer has socket data.
    stopped: AtomicBool,
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
        self.inner.lock().sendq.size()
    }

    fn new(
        id: u64,
        runtime: &'static Runtime,
        handle: &Arc<PortHandle>,
        port: &DriverPort,
    ) -> Self {
        Self::with_inner(
            id,
            runtime,
            handle,
            Inner {
                port: Some(port.weak()),
                ..Inner::default()
            },
        )
    }

    fn with_inner(
        id: u64,
        runtime: &'static Runtime,
        handle: &Arc<PortHandle>,
        inner: Inner,
    ) -> Self {
        Self {
            id,
            runtime,
            handle: Arc::downgrade(handle),
            stopped: AtomicBool::new(false),
            inner: Mutex::new(inner),
            io: Mutex::new(()),
        }
    }

    fn runtime(&self) -> &'static Runtime {
        self.runtime
    }

    pub(crate) fn stopped(&self) -> bool {
        self.stopped.load(Ordering::Acquire)
    }

    fn handle(&self) -> Arc<PortHandle> {
        self.handle.upgrade().expect("live inet port handle")
    }

    /// The `DriverPort` this socket is the driver data of.
    fn port(&self) -> Option<arinsal_drv::PortRef> {
        self.handle.upgrade()?.drv_port()
    }
}

impl Drop for Sock {
    fn drop(&mut self) {
        drop(self.inner.get_mut().take_fd());
    }
}

/// The socket descriptor and poll-set state stored in `tcp_descriptor`.
struct SockFd {
    fd: OwnedFd,
    /// The descriptor number given to `driver_select` (the caller's one for `{fd, Fd}`).
    select_fd: RawFd,
    /// Events selected through `driver_select` (`FD_READ`, `FD_WRITE`).
    readable: bool,
    writable: bool,
}

impl SockFd {
    fn new(fd: OwnedFd) -> Self {
        Self {
            select_fd: fd.as_raw_fd(),
            fd,
            readable: false,
            writable: false,
        }
    }
}

impl AsRawFd for SockFd {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
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
    /// `driver_monitor_process` of an accepting process (`ar->mon`).
    monitor: Option<u64>,
}

/// `driver_demonitor_process` once an accept no longer waits.
fn demonitor_waiter(inner: &Inner, waiter: &Waiter) {
    if let (Some(monitor), Some(port)) = (
        waiter.monitor,
        inner.port.as_ref().and_then(|port| port.upgrade()),
    ) {
        port.demonitor(monitor);
    }
}

struct Recv {
    caller: Pid,
    aref: u16,
    length: u32,
    deadline: Option<Instant>,
}

/// The acceptors waiting on a listening socket: allocated by the first one, so a connected
/// socket carries only the pointer (erts keeps `tcp_descriptor.inet.acceptor` as a list head).
// Boxed on purpose: an empty `VecDeque` is 32 bytes of every connected socket, the pointer is 8.
#[allow(clippy::box_collection)]
#[derive(Default)]
struct WaiterQueue(Option<Box<VecDeque<Waiter>>>);

impl WaiterQueue {
    fn push_back(&mut self, waiter: Waiter) {
        self.0
            .get_or_insert_with(Default::default)
            .push_back(waiter);
    }

    fn pop_front(&mut self) -> Option<Waiter> {
        self.0.as_mut()?.pop_front()
    }

    fn is_empty(&self) -> bool {
        self.0.as_ref().is_none_or(|queue| queue.is_empty())
    }

    fn iter(&self) -> impl Iterator<Item = &Waiter> {
        self.0.iter().flat_map(|queue| queue.iter())
    }

    fn take_all(&mut self) -> VecDeque<Waiter> {
        self.0.take().map(|queue| *queue).unwrap_or_default()
    }
}

impl From<VecDeque<Waiter>> for WaiterQueue {
    fn from(queue: VecDeque<Waiter>) -> Self {
        Self((!queue.is_empty()).then(|| Box::new(queue)))
    }
}

struct Inner {
    fd: Option<SockFd>,
    /// The `DriverPort` of this socket (`desc->inet.port`).
    port: Option<arinsal_drv::WeakPortRef>,
    /// The deadline the port timer is armed for (`driver_set_timer`).
    timer_at: Option<Instant>,
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
    /// The input buffer (`i_buf`, `i_ptr_start`, `i_ptr`): allocated by the first receive, null
    /// before, as in erts.
    rx: Option<Box<RxBuf>>,
    sendq: IoQueue,
    // Boxed on purpose: the pointer is 8 bytes where an empty `Vec` is 24.
    #[allow(clippy::box_collection)]
    empty_out_q_subs: Option<Box<Vec<Pid>>>,
    /// `Some` while TCP_ADDF_SENDFILE is set.
    sendfile: Option<Box<Sendfile>>,
    recv: Option<Recv>,
    accept_q: WaiterQueue,
    connect: Option<Box<Waiter>>,
    // Boxed on purpose: the pointer is 8 bytes where an empty `Vec` is 24.
    #[allow(clippy::box_collection)]
    pending: Option<Box<Vec<(Pid, u16)>>>,
    busy: bool,
    peer_closed: bool,
    /// `TCP_ADDF_PENDING_SHUT_WR` (1) / `TCP_ADDF_PENDING_SHUT_RDWR` (2): shutdown once the
    /// output queue has drained. The flag stays set afterwards, as in erts.
    pending_shut: u8,
    /// `TCP_ADDF_SHUTDOWN_WR_DONE`.
    shutdown_wr_done: bool,
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

/// The input buffer of a socket: a plain vector, or a reference-counted binary (`i_buf`) when
/// the packet is delivered as a sub-binary of it, in which case the bytes live there and `buf`
/// is empty.
// Port of inet_drv.c (`i_buf`, `i_ptr_start`, `i_ptr`, `i_bufsz`), OTP-29.1.1.
#[derive(Default)]
struct RxBuf {
    buf: Vec<u8>,
    bin: Option<arinsal_term::RefcBinary>,
    start: usize,
    end: usize,
}

impl Inner {
    fn rx_start(&self) -> usize {
        self.rx.as_ref().map_or(0, |rx| rx.start)
    }

    fn rx_end(&self) -> usize {
        self.rx.as_ref().map_or(0, |rx| rx.end)
    }

    fn rx_bin(&self) -> Option<&arinsal_term::RefcBinary> {
        self.rx.as_ref()?.bin.as_ref()
    }

    fn rx_buf(&self) -> &[u8] {
        self.rx.as_ref().map_or(&[], |rx| rx.buf.as_slice())
    }

    /// The input buffer, allocated first when the socket has none.
    fn rx_mut(&mut self) -> &mut RxBuf {
        self.rx.get_or_insert_with(Default::default)
    }

    // Port of erts/emulator/drivers/common/inet_drv.c:11473 (tcp_desc_close), OTP-29.1.1.
    fn take_fd(&mut self) -> Option<SockFd> {
        let fd = self.fd.take()?;
        if let Some(port) = self.port.as_ref().and_then(|port| port.upgrade()) {
            use arinsal_drv::{SELECT_READ, SELECT_USE, SELECT_WRITE};
            port.select(fd.select_fd, SELECT_READ | SELECT_WRITE | SELECT_USE, false);
        }
        Some(fd)
    }
}

impl Default for Inner {
    fn default() -> Self {
        Self {
            fd: None,
            port: None,
            timer_at: None,
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
            rx: None,
            sendq: IoQueue::default(),
            empty_out_q_subs: None,
            sendfile: None,
            recv: None,
            accept_q: WaiterQueue::default(),
            connect: None,
            pending: None,
            busy: false,
            peer_closed: false,
            pending_shut: 0,
            shutdown_wr_done: false,
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

/// `ok_bytes(&[])` in the inline control reply buffer.
pub(crate) fn ok_small() -> ControlBytes {
    ControlBytes::from_slice(&[1])
}

/// `err_bytes` in the inline control reply buffer.
fn err_small(reason: &str) -> ControlBytes {
    let mut out = ControlBytes::new();
    out.push(0);
    out.extend_from_slice(reason.as_bytes());
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

/// The messages one callback delivers, in order; a packet is usually one.
type Outs = smallvec::SmallVec<[Out; 1]>;

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
    TcpMessage {
        to: Pid,
        message: MessageNode,
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
            let inner = sock.inner.lock();
            output_list_len_from_options(bytes.len(), inner.binary, inner.header)
        }
        Out::Http { packet, binary, .. } | Out::AsyncHttp { packet, binary, .. } => {
            http_list_len(packet, *binary)
        }
        _ => 0,
    }
}

fn output_list_len_from_options(bytes_len: usize, binary: bool, header: i32) -> usize {
    let header = if header < 0 {
        bytes_len
    } else {
        header as usize
    };
    if !binary || header > bytes_len {
        bytes_len
    } else {
        header
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
    let Some((to, message)) = output_message(sock, out) else {
        return;
    };
    let _ = sock.handle().scheduler().send_node(to, message);
}

/// Deliver the messages of one port task. Each receiver's ordered output is published as a
/// block with one wake decision, so a receiver is scheduled once per task, not per message.
///
/// Port of erts/emulator/beam/erl_port_task.c (erts_port_task_execute runs the task to a
/// scheduling boundary) and erl_proc_sig_queue.h (erts_proc_notify_new_message), OTP-29.1.1.
fn emit_block(sock: &Sock, mut outs: Outs) {
    // One message (the usual case of one received packet) goes out as `emit` does.
    if outs.len() == 1 {
        if let Some(out) = outs.pop() {
            emit(sock, out);
        }
        return;
    }
    let mut pending: Vec<(Pid, Vec<MessageNode>)> = Vec::new();
    for out in outs {
        let Some((to, message)) = output_message(sock, out) else {
            continue;
        };
        if let Some((_, messages)) = pending.iter_mut().find(|(current, _)| *current == to) {
            messages.push(message);
        } else {
            pending.push((to, vec![message]));
        }
    }
    if pending.is_empty() {
        return;
    }
    let sched = sock.handle().scheduler();
    for (to, mut messages) in pending {
        if messages.len() == 1 {
            let _ = sched.send_node(to, messages.remove(0));
        } else {
            let _ = sched.send_node_block(to, messages);
        }
    }
}

fn output_message(sock: &Sock, out: Out) -> Option<(Pid, MessageNode)> {
    // Distribution ports feed the emulator decoder, not the port owner.
    // Port of inet_drv.c + dist.c:2017 (erts_net_message), OTP-29.1.1.
    if let Out::PortData { bytes, .. } = &out
        && crate::node_tables::is_dist_port(sock.id)
    {
        let _ = crate::dist::ingest_port_data(sock.runtime(), sock.id, bytes);
        return None;
    }
    if let Out::TcpClosed { .. } = &out
        && crate::node_tables::is_dist_port(sock.id)
    {
        let _ = crate::dist::port_connection_closed(sock.runtime(), sock.id);
        // Still deliver tcp_closed to the connection ticker so it shuts down.
    }
    let out = match out {
        Out::TcpMessage { to, message } => return Some((to, message)),
        out => out,
    };
    let port = Term::port(sock.id).unwrap();
    // The hot shapes are built in the node's own heap fragment, sized exactly as
    // driver_deliver_term sizes its term specification (io.c erts_factory_message_create).
    match &out {
        Out::Tcp { owner, bytes } => {
            let (binary, header) = {
                let inner = sock.inner.lock();
                (inner.binary, inner.header)
            };
            if let Some(node) = tcp_node(*owner, port, bytes, None, binary, header) {
                return Some((*owner, node));
            }
        }
        Out::InetReply {
            caller,
            ids,
            error: None,
        } => {
            // {inet_reply, Port, ok, Ref}: a 5-word tuple and a 3-word reference.
            let node = Message::node_built(8, |heap| {
                let tag = TermBuilder::new(heap).local_ref(*ids).ok()?;
                TermBuilder::new(heap)
                    .tuple(&[atom("inet_reply"), port, atom("ok"), tag])
                    .ok()
                    .map(|term| (*caller, term))
            });
            if node.is_some() {
                return node;
            }
        }
        _ => {}
    }
    // Port of inet_drv.c:3987-4005 (tcp_message uses LOAD_STRING sized to the
    // complete packet), OTP-29.1.1. List-mode packets need two heap words per byte.
    let words = match out {
        // Fixed-shape status messages, sized as the term specification of driver_deliver_term:
        // {inet_async, Port, Ref, ok | {error, R} | {ok, Port}}, {inet_reply, Port, Status, Ref},
        // {tcp_closed, Port}, {tcp_error, Port, R}, {tcp_passive, Port}, {empty_out_q, Port},
        // {sendfile, Port, {ok, Lo, Hi} | {error, R}}.
        Out::AsyncOk { .. } => 5,
        Out::AsyncError { .. } | Out::AsyncPort { .. } => 8,
        Out::InetReply { .. } => 11,
        Out::TcpClosed { .. } | Out::TcpPassive { .. } | Out::EmptyOutQ { .. } => 3,
        Out::TcpError { .. } => 4,
        Out::Sendfile { .. } => 8,
        _ => 128usize.saturating_add(output_list_len(sock, &out).saturating_mul(2)),
    };
    // The term is built in the fragment that is queued, as driver_deliver_term does
    // (io.c:5658), not copied out of a scratch heap.
    Message::node_built(words, |heap| match &out {
        Out::AsyncError {
            caller,
            aref,
            reason,
        } => error_tuple(heap, reason)
            .and_then(|status| message_async(heap, port, *aref, status))
            .map(|term| (*caller, term)),
        Out::AsyncOk { caller, aref } => {
            message_async(heap, port, *aref, atom("ok")).map(|term| (*caller, term))
        }
        Out::AsyncPort {
            caller,
            aref,
            port: born,
        } => {
            let born = Term::port(*born).unwrap();
            let status = TermBuilder::new(heap).tuple(&[atom("ok"), born]).ok();
            status.and_then(|status| {
                message_async(heap, port, *aref, status).map(|term| (*caller, term))
            })
        }
        Out::AsyncData {
            caller,
            aref,
            bytes,
        } => {
            let data = data_term(sock, heap, bytes);
            let status =
                data.and_then(|data| TermBuilder::new(heap).tuple(&[atom("ok"), data]).ok());
            status.and_then(|status| {
                message_async(heap, port, *aref, status).map(|term| (*caller, term))
            })
        }
        Out::InetReply { caller, ids, error } => {
            let status = if let Some(reason) = error {
                error_tuple(heap, reason)
            } else {
                Some(atom("ok"))
            };
            let tag = TermBuilder::new(heap).local_ref(*ids).ok();
            match (status, tag) {
                (Some(status), Some(tag)) => TermBuilder::new(heap)
                    .tuple(&[atom("inet_reply"), port, status, tag])
                    .ok()
                    .map(|term| (*caller, term)),
                _ => None,
            }
        }
        Out::Tcp { owner, bytes } => {
            // Port of inet_drv.c:3987 (tcp_message), OTP-29.1.1.
            data_term(sock, heap, bytes)
                .and_then(|data| {
                    TermBuilder::new(heap)
                        .tuple(&[atom("tcp"), port, data])
                        .ok()
                })
                .map(|term| (*owner, term))
        }
        Out::TcpMessage { .. } => unreachable!("TCP message was already dispatched"),
        Out::TcpClosed { owner } => TermBuilder::new(heap)
            .tuple(&[atom("tcp_closed"), port])
            .ok()
            .map(|term| (*owner, term)),
        Out::TcpError { owner, reason } => TermBuilder::new(heap)
            .tuple(&[atom("tcp_error"), port, atom(reason)])
            .ok()
            .map(|term| (*owner, term)),
        Out::TcpPassive { owner } => TermBuilder::new(heap)
            .tuple(&[atom("tcp_passive"), port])
            .ok()
            .map(|term| (*owner, term)),
        Out::Http {
            owner,
            packet,
            binary,
        } => http_message(heap, port, packet, *binary).map(|term| (*owner, term)),
        Out::AsyncHttp {
            caller,
            aref,
            packet,
            binary,
        } => http_value(heap, packet, *binary)
            .and_then(|value| TermBuilder::new(heap).tuple(&[atom("ok"), value]).ok())
            .and_then(|status| message_async(heap, port, *aref, status))
            .map(|term| (*caller, term)),
        Out::PortData { owner, bytes } => data_term(sock, heap, bytes)
            .and_then(|data| TermBuilder::new(heap).tuple(&[atom("data"), data]).ok())
            .and_then(|data| TermBuilder::new(heap).tuple(&[port, data]).ok())
            .map(|term| (*owner, term)),
        Out::EmptyOutQ { subscriber } => TermBuilder::new(heap)
            .tuple(&[atom("empty_out_q"), port])
            .ok()
            .map(|term| (*subscriber, term)),
        Out::Sendfile { owner, result } => {
            // Port of inet_drv.c:14032-14043 ({sendfile, S, {ok, SentLow, SentHigh}}) and
            // :14055-14072 ({sendfile, S, {error, Reason}}), OTP-29.1.1.
            let status = match result {
                Ok(bytes_sent) => TermBuilder::new(heap)
                    .tuple(&[
                        atom("ok"),
                        Term::small((bytes_sent & 0xFFFF_FFFF) as i64).unwrap(),
                        Term::small((bytes_sent >> 32) as i64).unwrap(),
                    ])
                    .ok(),
                Err(reason) => error_tuple(heap, reason),
            };
            status
                .and_then(|status| {
                    TermBuilder::new(heap)
                        .tuple(&[atom("sendfile"), port, status])
                        .ok()
                })
                .map(|term| (*owner, term))
        }
    })
}

fn message_async(
    heap: &mut (impl HeapAlloc + ?Sized),
    port: Term,
    aref: u16,
    status: Term,
) -> Option<Term> {
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

fn error_tuple(heap: &mut (impl HeapAlloc + ?Sized), reason: &'static str) -> Option<Term> {
    TermBuilder::new(heap)
        .tuple(&[atom("error"), atom(reason)])
        .ok()
}

fn http_message(
    heap: &mut (impl HeapAlloc + ?Sized),
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

fn http_value(
    heap: &mut (impl HeapAlloc + ?Sized),
    packet: &HttpPacket,
    binary: bool,
) -> Option<Term> {
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
                atom_dyn(std::str::from_utf8(method).unwrap_or("GET"))
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

fn uri_term(heap: &mut (impl HeapAlloc + ?Sized), uri: &HttpUri, binary: bool) -> Option<Term> {
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

fn bytes_term(heap: &mut (impl HeapAlloc + ?Sized), bytes: &[u8], binary: bool) -> Option<Term> {
    let mut builder = TermBuilder::new(heap);
    if binary {
        builder.binary(bytes).ok()
    } else {
        builder.bytes_to_list(bytes).ok()
    }
}

fn data_term(sock: &Sock, heap: &mut (impl HeapAlloc + ?Sized), bytes: &[u8]) -> Option<Term> {
    let (binary, hsz) = {
        let inner = sock.inner.lock();
        (inner.binary, inner.header)
    };
    data_term_with_options(heap, bytes, None, binary, hsz)
}

/// Words of the term `data_term_with_options` builds for `len` packet bytes.
// Port of erts/emulator/beam/io.c (driver_deliver_term sizing of LOAD_STRING / LOAD_BINARY and
// the header list cells), OTP-29.1.1.
fn data_words(len: usize, binary: bool, header: i32) -> usize {
    let hsz = if header < 0 { len } else { header as usize };
    if !binary || hsz > len {
        return 2 * len;
    }
    let rest = len - hsz;
    // A heap binary is two words and the payload; a larger one is a BinRef and a SubBits.
    2 * hsz + if rest <= 64 { 2 + rest.div_ceil(8) } else { 8 }
}

/// `{tcp, Port, Data}` built in its own message node.
fn tcp_node(
    to: Pid,
    port: Term,
    bytes: &[u8],
    source: Option<(&arinsal_term::RefcBinary, usize)>,
    binary: bool,
    header: i32,
) -> Option<MessageNode> {
    Message::node_built(4 + data_words(bytes.len(), binary, header), |heap| {
        let data = data_term_with_options(heap, bytes, source, binary, header)?;
        TermBuilder::new(heap)
            .tuple(&[atom("tcp"), port, data])
            .ok()
            .map(|term| (to, term))
    })
    .map(|(_, node)| node)
}

fn data_term_with_options(
    heap: &mut (impl HeapAlloc + ?Sized),
    bytes: &[u8],
    source: Option<(&arinsal_term::RefcBinary, usize)>,
    binary: bool,
    header: i32,
) -> Option<Term> {
    // Port of inet_drv.c:4000 (list, or [H1..Hsz | Binary]), OTP-29.1.1.
    let mut builder = TermBuilder::new(heap);
    let hsz = if header < 0 {
        bytes.len()
    } else {
        header as usize
    };
    if !binary || hsz > bytes.len() {
        return builder.bytes_to_list(bytes).ok();
    }
    let rest = bytes.len() - hsz;
    let mut tail = match source {
        // Port of io.c (driver_deliver_term, ERL_DRV_BINARY): a large binary is referenced.
        Some((bin, offset)) if rest > arinsal_drv::ERL_ONHEAP_BINARY_LIMIT => {
            builder.refc_slice(bin, offset + hsz, rest).ok()?
        }
        _ => builder.binary(&bytes[hsz..]).ok()?,
    };
    for byte in bytes[..hsz].iter().rev() {
        tail = builder
            .cons(Term::small(i64::from(*byte)).unwrap(), tail)
            .ok()?;
    }
    Some(tail)
}

fn drop_pending(inner: &mut Inner, caller: Pid, aref: u16) {
    if let Some(pending) = inner.pending.as_mut() {
        pending.retain(|(c, r)| *c != caller || *r != aref);
    }
}

fn try_io(sock: &Arc<Sock>, writable_ready: bool) {
    // Port of erts/emulator/sys/common/erl_check_io.c:2098-2109, OTP-29.1.1: oready
    // runs before iready for one fd.
    if writable_ready {
        tcp_inet_output(sock);
        // The blocked sender's reply goes out when the queue drains (tcp_inet_output), ahead
        // of whatever the input side finds.
    }
    satisfy(sock);
    let eof = pull(sock);
    // `pull` flushes the output queue too: a sender released by that goes before the close.
    if sock.inner.lock().sendfile.is_none() {
        send_empty_out_q_msgs(sock);
    }
    satisfy(sock);
    if let Some(error) = eof {
        on_eof(sock, error);
    }
    let connect_done = {
        let mut inner = sock.inner.lock();
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
        let mut inner = sock.inner.lock();
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
    let busy = sock.inner.lock().busy;
    crate::dist::distribution_port_state_changed(sock.runtime(), sock.id, busy);
}

/// Write queued output once the poll set reports the connected socket writable.
///
/// Port of erts/emulator/drivers/common/inet_drv.c:14289-14361, OTP-29.1.1
/// (`tcp_inet_output`, connected branch): send from the driver queue until it is
/// empty or the socket would block, and drop the busy state at the low watermark
/// (`release_unbusy`; deferred replies are queued as tasks on the busy port).
/// The output callback runs whether or not the owner has a receive pending, so a
/// passive socket whose owner is blocked in `gen_tcp:send/2` still drains. The
/// write selection follows the queue: `sock_select` selects for write only while
/// `sendq` is non-empty or a sendfile is unfinished (inet_drv.c:14302-14303 deselects
/// when the queue is empty).
fn tcp_inet_output(sock: &Arc<Sock>) {
    let failure = {
        let mut inner = sock.inner.lock();
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
        let (err, shutdown_error) = match flush_send(&mut inner) {
            Some(err) => (err, false),
            None => {
                let failed = if inner.sendq.is_empty() && inner.pending_shut != 0 {
                    shutdown_async(&mut inner)
                } else {
                    None
                };
                let Some(err) = failed else {
                    drop(inner);
                    send_empty_out_q_msgs(sock);
                    return;
                };
                (err, true)
            }
        };
        // Port of inet_drv.c:13690-13720 (tcp_send_error) and :13613-13688
        // (tcp_send_or_shutdown_error), OTP-29.1.1: the blocked senders get the
        // error reply; an active socket also gets `tcp_closed`.
        let outcome = if shutdown_error {
            send_or_shutdown_failed(&mut inner, err)
        } else {
            send_failed(&mut inner, err)
        };
        match outcome {
            SendOutcome::Failed { error, active } => (error, active),
            SendOutcome::Reply(_) | SendOutcome::Deferred { .. } => return,
        }
    };
    let (error, active) = failure;
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
        if sock.inner.lock().exit_on_close {
            driver_exit(sock);
        }
    }
    send_empty_out_q_msgs(sock);
}

fn deliver_pending_close(sock: &Arc<Sock>) {
    // Port of inet_drv.c:7001 (inet_set_opts active while INET_STATE_CLOSED), OTP-29.1.1.
    let (owner, exit_on_close, delayed_reset) = {
        let mut inner = sock.inner.lock();
        if !inner.peer_closed || inner.closed_sent || !active_is(&inner.active) {
            return;
        }
        // EOF is only seen once the input before it was consumed (tcp_recv delivers the
        // buffer first), so `tcp_closed` waits behind buffered packets.
        if has_buffered_packet(&inner) {
            return;
        }
        inner.closed_sent = true;
        // TCP_ADDF_DELAYED_ECONNRESET: the reset that closed the passive socket is reported
        // once, as `{tcp_error, S, econnreset}` ahead of `tcp_closed`.
        let delayed_reset = std::mem::take(&mut inner.reset);
        (
            sock.handle().owner_pid(),
            inner.exit_on_close,
            delayed_reset,
        )
    };
    if delayed_reset {
        emit(
            sock,
            Out::TcpError {
                owner,
                reason: "econnreset",
            },
        );
    }
    emit(sock, Out::TcpClosed { owner });
    if exit_on_close {
        driver_exit(sock);
    }
}

fn satisfy(sock: &Arc<Sock>) {
    let _io = sock.io.lock();
    let (outs, abandon) = {
        let mut inner = sock.inner.lock();
        let mut outs = Outs::new();
        let port = Term::port(sock.id).unwrap();
        let abandon = take_packets(&sock.handle(), port, &mut inner, &mut outs);
        (outs, abandon)
    };
    emit_block(sock, outs);
    if abandon {
        driver_exit(sock);
    }
}

fn take_packets(handle: &PortHandle, port: Term, inner: &mut Inner, outs: &mut Outs) -> bool {
    if inner.phase != Phase::Connected {
        return false;
    }
    if inner.recv.is_some() {
        if inner.htype == 0 {
            let recv = inner.recv.as_ref().unwrap();
            let buffered = rbuf_len(inner);
            let ready = if recv.length == 0 {
                buffered != 0
            } else {
                buffered >= recv.length as usize
            };
            if ready {
                let n = if recv.length == 0 {
                    buffered
                } else {
                    recv.length as usize
                };
                let bytes = rbuf_take(inner, n);
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
                    push_frame(
                        inner,
                        port,
                        outs,
                        DataWho::Async(recv.caller, recv.aref),
                        frame,
                    );
                }
                Read::Wait => {}
                Read::Bad => return packet_error(handle, inner, outs),
            }
        }
    }
    while active_is(&inner.active) {
        let owner = handle.owner_pid();
        if inner.htype == 0 {
            if rbuf_len(inner) == 0 {
                break;
            }
            if inner.rx_bin().is_some() && inner.deliver != DELIVER_PORT {
                let range = inner.rx_start()..inner.rx_end();
                input_count(inner, range.len());
                push_frame(
                    inner,
                    port,
                    outs,
                    DataWho::Active(owner),
                    Frame::InputBytes(range),
                );
                rbuf_reset(inner);
                note_active(inner, owner, outs);
                continue;
            }
            rbuf_unstage(inner);
            let bytes = if inner.rx_start() == 0 && inner.rx_end() == inner.rx_buf().len() {
                std::mem::take(&mut inner.rx_mut().buf)
            } else {
                let len = rbuf_len(inner);
                rbuf_take(inner, len)
            };
            let rx = inner.rx_mut();
            rx.start = 0;
            rx.end = 0;
            input_count(inner, bytes.len());
            push_data(inner, outs, DataWho::Active(owner), bytes);
        } else {
            match next_frame(inner) {
                Read::Ready(frame, used) => {
                    input_count(inner, used);
                    push_frame(inner, port, outs, DataWho::Active(owner), frame);
                }
                Read::Wait => break,
                Read::Bad => return packet_error(handle, inner, outs),
            }
        }
        note_active(inner, owner, outs);
    }
    if inner.rx_start() == inner.rx_end() {
        rbuf_reset(inner);
    }
    false
}

fn packet_error(handle: &PortHandle, inner: &mut Inner, outs: &mut Outs) -> bool {
    // Port of inet_drv.c:13170 (tcp_recv → tcp_recv_error EMSGSIZE), OTP-29.1.1.
    if let Some(recv) = inner.recv.take() {
        drop_pending(inner, recv.caller, recv.aref);
        outs.push(Out::AsyncError {
            caller: recv.caller,
            aref: recv.aref,
            reason: "emsgsize",
        });
    }
    rbuf_reset(inner);
    inner.take_fd();
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

#[derive(Clone, Copy)]
enum DataWho {
    Active(Pid),
    Async(Pid, u16),
}

fn push_data(inner: &Inner, outs: &mut Outs, who: DataWho, bytes: Vec<u8>) {
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

fn push_frame(inner: &Inner, port: Term, outs: &mut Outs, who: DataWho, frame: Frame) {
    let binary = inner.htype >= 13;
    match frame {
        Frame::Bytes(bytes) => push_data(inner, outs, who, bytes),
        Frame::InputBytes(range) if inner.deliver != DELIVER_PORT => {
            let bytes = rbuf_slice(inner, range.clone());
            let (binary, header) = (inner.binary, inner.header);
            // tcp_deliver shares i_buf only when the packet occupies at least 75% of
            // its original allocation; smaller packets go through tcp_reply_data.
            let source = inner.rx_bin().and_then(|bin| {
                (bytes.len() >= bin.len() - (bin.len() >> 2)).then_some((bin, range.start))
            });
            let message = match who {
                DataWho::Active(owner) => {
                    tcp_node(owner, port, bytes, source, binary, header).map(|node| (owner, node))
                }
                DataWho::Async(caller, aref) => {
                    // {inet_async, Port, Ref, {ok, Data}}: a 5-word and a 3-word tuple.
                    let words = 8 + data_words(bytes.len(), binary, header);
                    Message::node_built(words, |heap| {
                        let data = data_term_with_options(heap, bytes, source, binary, header)?;
                        let status = TermBuilder::new(heap).tuple(&[atom("ok"), data]).ok()?;
                        message_async(heap, port, aref, status).map(|term| (caller, term))
                    })
                }
            };
            if let Some((to, message)) = message {
                outs.push(Out::TcpMessage { to, message });
            }
        }
        Frame::InputBytes(range) => {
            push_data(inner, outs, who, rbuf_slice(inner, range).to_vec());
        }
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
    InputBytes(Range<usize>),
    Http(HttpPacket),
}

enum Read {
    Ready(Frame, usize),
    Wait,
    Bad,
}

// Port of erts/emulator/drivers/common/inet_drv.c:13042 (tcp_deliver), OTP-29.1.1.
fn next_frame(inner: &mut Inner) -> Read {
    let Some(ty) = packet_type(inner.htype) else {
        return Read::Wait;
    };
    let opts = PacketOptions {
        packet_size: inner.packet_size,
        line_length: 0,
        line_delimiter: inner.delimiter,
    };
    let (start, end) = (inner.rx_start(), inner.rx_end());
    let Inner { rx, http, .. } = &mut *inner;
    let input: &[u8] = match rx.as_deref() {
        Some(RxBuf { bin: Some(bin), .. }) => &bin.bytes()[start..end],
        Some(rx) => &rx.buf[start..end],
        None => &[],
    };
    let parsed = parse_with_state(ty, input, opts, http);
    match parsed {
        PacketResult::Ok { packet, rest } => {
            let used = input.len() - rest.len();
            let frame = match packet {
                Packet::Bytes(bytes) => {
                    let offset = bytes.as_ptr() as usize - input.as_ptr() as usize;
                    let body_start = start + offset;
                    Frame::InputBytes(body_start..body_start + bytes.len())
                }
                Packet::Http(http) => Frame::Http(http),
                Packet::SslTls { data, .. } => Frame::Bytes(data),
            };
            rbuf_consume(inner, used);
            Read::Ready(frame, used)
        }
        PacketResult::More(_) => Read::Wait,
        // Port of inet_drv.c:13033 (tcp_remain packet error), OTP-29.1.1.
        PacketResult::Error => Read::Bad,
    }
}

// Port of erts/emulator/drivers/common/inet_drv.c:13042 (tcp_deliver), OTP-29.1.1.
fn rbuf_bytes(inner: &Inner) -> &[u8] {
    rbuf_slice(inner, inner.rx_start()..inner.rx_end())
}

/// `range` of the input buffer, wherever it lives.
fn rbuf_slice(inner: &Inner, range: Range<usize>) -> &[u8] {
    match inner.rx_bin() {
        Some(bin) => &bin.bytes()[range],
        None => &inner.rx_buf()[range],
    }
}

/// Move the buffered bytes of the binary input buffer into the plain one.
fn rbuf_unstage(inner: &mut Inner) {
    if let Some(rx) = inner.rx.as_mut()
        && let Some(bin) = rx.bin.take()
    {
        rx.buf = bin.bytes()[rx.start..rx.end].to_vec();
        rx.end -= rx.start;
        rx.start = 0;
    }
}

/// Make room for `extra` more bytes in a binary input buffer: allocate the binary of
/// `tcp_expand_buffer` holding the buffered bytes and `extra` more.
// Port of erts/emulator/drivers/common/inet_drv.c (tcp_expand_buffer, tcp_recv: `i_buf` is a
// driver binary), OTP-29.1.1.
fn rbuf_stage(inner: &mut Inner, extra: usize) -> bool {
    let len = rbuf_len(inner);
    let Some(total) = len.checked_add(extra) else {
        return false;
    };
    let end = inner.rx_end();
    if let Some(bin) = inner.rx.as_mut().and_then(|rx| rx.bin.as_mut())
        && bin.bytes_mut_unique().is_some()
    {
        // tcp_expand_buffer reallocates the unique driver binary in place. Once a
        // delivered sub-binary shares it, buffered bytes move to a fresh allocation.
        let Some(needed) = end.checked_add(extra) else {
            return false;
        };
        return needed <= bin.len() || bin.realloc(needed).is_ok();
    }
    // tcp_recv starts with alloc_buffer(desc->inet.bufsz), then tcp_expand_buffer keeps
    // the used prefix and grows that allocation when packet_parser knows the frame size.
    let initial = if inner.htype != 0 && len == 0 && end == 0 {
        (inner.buffer.max(1) as usize).max(total)
    } else {
        total
    };
    let Ok(mut bin) = arinsal_term::RefcBinary::new_zeroed(initial) else {
        return false;
    };
    let Some(buf) = bin.bytes_mut_unique() else {
        return false;
    };
    buf[..len].copy_from_slice(rbuf_bytes(inner));
    let rx = inner.rx_mut();
    rx.buf = Vec::new();
    rx.bin = Some(bin);
    rx.start = 0;
    rx.end = len;
    true
}

// Port of inet_drv.c (`tcp_deliver`/`tcp_remain` valid range), OTP-29.1.1.
fn rbuf_len(inner: &Inner) -> usize {
    inner.rx_end() - inner.rx_start()
}

// Port of inet_drv.c (`tcp_clear_input` logical pointer reset), OTP-29.1.1.
// Port of inet_drv.c (`tcp_clear_input`): a consumed input buffer is freed, so an idle
// connection holds none.
fn rbuf_reset(inner: &mut Inner) {
    if let Some(rx) = inner.rx.as_mut() {
        rx.start = 0;
        rx.end = 0;
        rx.buf = Vec::new();
        rx.bin = None;
    }
}

// Port of inet_drv.c (`tcp_deliver`), OTP-29.1.1.
fn rbuf_consume(inner: &mut Inner, len: usize) {
    inner.rx_mut().start += len;
}

// Port of inet_drv.c (`tcp_deliver`), OTP-29.1.1.
fn rbuf_take(inner: &mut Inner, len: usize) -> Vec<u8> {
    let start = inner.rx_start();
    let bytes = rbuf_slice(inner, start..start + len).to_vec();
    rbuf_consume(inner, len);
    if inner.rx_start() == inner.rx_end() {
        rbuf_reset(inner);
    }
    bytes
}

// Port of inet_drv.c (`tcp_restart_input`), OTP-29.1.1.
fn rbuf_compact(inner: &mut Inner) {
    if inner.rx_bin().is_some() {
        return;
    }
    if inner.rx_start() != 0 {
        let len = rbuf_len(inner);
        let rx = inner.rx_mut();
        rx.buf.copy_within(rx.start..rx.end, 0);
        rx.start = 0;
        rx.end = len;
        rx.buf.truncate(len);
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

fn note_active(inner: &mut Inner, owner: Pid, outs: &mut Outs) {
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
    let buffered = rbuf_len(inner);
    if inner.htype == 0 {
        if !active_is(&inner.active)
            && let Some(recv) = &inner.recv
            && recv.length > 0
        {
            return (recv.length as usize).saturating_sub(buffered).max(1);
        }
        return buffer.saturating_sub(buffered).max(1);
    }
    let Some(ty) = packet_type(inner.htype) else {
        return 1;
    };
    let mut http = inner.http;
    match parse_with_state(
        ty,
        rbuf_bytes(inner),
        PacketOptions {
            packet_size: inner.packet_size,
            line_length: 0,
            line_delimiter: inner.delimiter,
        },
        &mut http,
    ) {
        PacketResult::More(Some(packet_len)) => {
            return packet_len.saturating_sub(buffered).max(1);
        }
        PacketResult::More(None) => {}
        PacketResult::Ok { .. } | PacketResult::Error => return 1,
    }
    if inner.read_ahead {
        return buffer.saturating_sub(buffered).max(1);
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
    header_len.saturating_sub(buffered).max(1).min(buffer)
}

fn tcp_packet_complete(inner: &Inner) -> bool {
    let Some(ty) = packet_type(inner.htype) else {
        return false;
    };
    let mut http = inner.http;
    matches!(
        parse_with_state(
            ty,
            rbuf_bytes(inner),
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

// Port of erts/emulator/drivers/common/inet_drv.c:12967 (tcp_remain), OTP-29.1.1.
fn tcp_input_ready(inner: &Inner) -> bool {
    if inner.htype == 0 {
        if active_is(&inner.active) {
            rbuf_len(inner) != 0
        } else if let Some(recv) = &inner.recv {
            if recv.length == 0 {
                rbuf_len(inner) != 0
            } else {
                rbuf_len(inner) >= recv.length as usize
            }
        } else {
            false
        }
    } else {
        tcp_packet_complete(inner)
    }
}

// Port of erts/emulator/drivers/common/inet_drv.c:13130 (tcp_recv), OTP-29.1.1.
fn pull(sock: &Arc<Sock>) -> Option<&'static str> {
    let phase = sock.inner.lock().phase;
    if phase == Phase::Listening {
        pull_accept(sock);
        return None;
    }
    let (eof, bytes_read, read_error) = {
        let mut inner = sock.inner.lock();
        // Port of inet_drv.c:2819 (sock_select only while active or receiving).
        // A passive socket must leave the FIN unread so `{active, true}` still
        // observes it and emits `{tcp_closed, S}`.
        let want_read = inner.phase == Phase::Connected
            && inner.fd.is_some()
            && !inner.peer_closed
            && (active_is(&inner.active) || inner.recv.is_some());
        if !want_read {
            return None;
        }
        let mut eof = false;
        let mut read_error = None;
        let mut bytes_read = 0;
        loop {
            // tcp_recv checks buffered data before issuing another read.
            if tcp_input_ready(&inner) {
                break;
            }
            // Port of inet_drv.c (tcp_expand_buffer, tcp_recv): the input buffer grows to the
            // announced remaining size once and is read in place; the reserved pages stay
            // untouched until data arrives, so a bogus 4 GiB header costs address space only.
            let read_size = tcp_read_size(&inner);
            // Packet-mode binary input uses the driver-binary shape of tcp_recv's i_buf from
            // its first header read; tcp_expand_buffer grows it when the frame length is known.
            let staged = inner.binary
                && inner.deliver != DELIVER_PORT
                && (inner.htype != 0 || active_is(&inner.active))
                && (inner.htype != 0
                    || rbuf_len(&inner).saturating_add(read_size)
                        > arinsal_drv::ERL_ONHEAP_BINARY_LIMIT)
                && rbuf_stage(&mut inner, read_size);
            if !staged {
                rbuf_unstage(&mut inner);
                rbuf_compact(&mut inner);
            }
            let read_start = inner.rx_end();
            if !staged {
                let rx = inner.rx_mut();
                rx.buf.truncate(read_start);
                if rx.buf.try_reserve_exact(read_size).is_err() {
                    // tcp_expand_buffer failing is tcp_recv_error(ENOMEM).
                    read_error = Some("enomem");
                    eof = true;
                    break;
                }
            }
            let read = {
                let Inner { fd, rx, .. } = &mut *inner;
                let rx = rx.get_or_insert_with(Default::default);
                let fd = &fd.as_ref().unwrap().fd;
                match rx.bin.as_mut().and_then(|bin| bin.bytes_mut_unique()) {
                    Some(buf) if staged => {
                        rustix::io::read(fd, &mut buf[read_start..read_start + read_size])
                    }
                    _ => rustix::io::read(fd, rustix::buffer::spare_capacity(&mut rx.buf)),
                }
            };
            match read {
                Ok(n) if n > 0 => {
                    bytes_read += n;
                    inner.rx_mut().end = read_start + n;
                    // Port of inet_drv.c (tcp_recv): return to tcp_deliver as soon as a
                    // complete message is buffered. In active_once mode, reading the next
                    // chunk here can observe EOF and discard the remaining buffered frames.
                    if tcp_input_ready(&inner) {
                        break;
                    }
                }
                Ok(_) => {
                    eof = true;
                    break;
                }
                Err(error) if error == rustix::io::Errno::INTR => continue,
                Err(error) => {
                    if error == rustix::io::Errno::CONNRESET {
                        // Port of inet_drv.c:13190 (tcp_recv): an RST is an error only with
                        // show_econnreset, else it reads as a plain close.
                        inner.reset = inner.show_econnreset;
                        eof = true;
                    }
                    break;
                }
            }
        }
        let _ = flush_send(&mut inner);
        (eof, bytes_read, read_error)
    };
    if bytes_read > 0 && crate::node_tables::is_dist_port(sock.id) && crate::debug_env::trace_dist()
    {
        eprintln!("DIST_SOCKET_READ port={} bytes={bytes_read}", sock.id);
    }
    read_error.or_else(|| eof.then_some("closed"))
}

fn pull_accept(sock: &Arc<Sock>) {
    loop {
        let accepted = {
            let inner = sock.inner.lock();
            if inner.accept_q.is_empty() {
                return;
            }
            try_accept(&inner)
        };
        match accepted {
            Some(Ok(fd)) => {
                let waiter = {
                    let mut inner = sock.inner.lock();
                    inner.accept_q.pop_front().inspect(|waiter| {
                        drop_pending(&mut inner, waiter.caller, waiter.aref);
                        demonitor_waiter(&inner, waiter);
                    })
                };
                if let Some(waiter) = waiter {
                    install_accepted(sock, fd, waiter.caller, waiter.aref);
                }
            }
            Some(Err(err)) => {
                let waiter = {
                    let mut inner = sock.inner.lock();
                    inner.accept_q.pop_front().inspect(|waiter| {
                        drop_pending(&mut inner, waiter.caller, waiter.aref);
                        demonitor_waiter(&inner, waiter);
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

fn on_eof(sock: &Arc<Sock>, read_error: &'static str) {
    // Port of inet_drv.c:12783 (tcp_recv_closed) and :12849 (tcp_recv_error), OTP-29.1.1.
    // A sender blocked on the queue is released first: the queue is dropped, the port is no
    // longer busy and the sender gets `{error, closed}` (tcp_clear_output).
    {
        let mut inner = sock.inner.lock();
        if !inner.peer_closed && inner.busy {
            inner.sendq.clear();
            inner.busy = false;
        }
    }
    let (active, exit_on_close, owner, reason) = {
        let mut inner = sock.inner.lock();
        if inner.peer_closed {
            return;
        }
        inner.peer_closed = true;
        let active = active_is(&inner.active);
        // erts reads EOF only once the buffered input is consumed, so a passive socket with no
        // receive pending keeps what it holds for the receives that follow (tcp_recv).
        if active || inner.recv.is_some() {
            rbuf_reset(&mut inner);
        }
        let owner = sock.handle().owner_pid();
        let reason = if read_error == "enomem" {
            read_error
        } else {
            close_atom(&inner)
        };
        // Port of erts/emulator/drivers/common/inet_drv.c:12805-12810 (tcp_recv_closed
        // aborts with ENOTCONN) and :12863-12867 (tcp_recv_error aborts with its err),
        // OTP-29.1.1, before any other close reporting. `pull` ends the stream on a
        // zero-byte read (closed) or ECONNRESET, which it records in `inner.reset`.
        if inner.sendfile.is_some() {
            let err = if read_error == "enomem" {
                libc::ENOMEM
            } else if inner.reset {
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
            inner = sock.inner.lock();
        }
        if !active {
            if inner.exit_on_close {
                inner.take_fd();
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
            driver_exit(sock);
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

/// Bring the poll-set selection of `sock` in line with its state.
///
/// Port of the `sock_select` calls of erts/emulator/drivers/common/inet_drv.c,
/// OTP-29.1.1: FD_ACCEPT while an accept waits (:12224, :12584), FD_CONNECT while
/// connecting (:12109, :14243), FD_READ while active or a receive is pending
/// (:12126, :12317, :13110), FD_WRITE while the output queue is non-empty
/// (:13844, :14303).
fn sock_select(sock: &Arc<Sock>) {
    let Some(port) = sock.port() else {
        return;
    };
    select_locked(&port, &mut sock.inner.lock());
}

fn select_locked(port: &DriverPort, inner: &mut Inner) {
    use arinsal_drv::{SELECT_READ, SELECT_USE, SELECT_WRITE};
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
    let raw = fd.select_fd;
    // Port of inet_drv.c (inet_driver_select): `ERL_DRV_USE` only when turning events on.
    if readable != fd.readable {
        let mode = if readable {
            SELECT_READ | SELECT_USE
        } else {
            SELECT_READ
        };
        port.select(raw, mode, readable);
        fd.readable = readable;
    }
    if writable != fd.writable {
        let mode = if writable {
            SELECT_WRITE | SELECT_USE
        } else {
            SELECT_WRITE
        };
        port.select(raw, mode, writable);
        fd.writable = writable;
    }
}

/// The nearest accept, connect, receive or send deadline.
fn next_deadline(inner: &Inner, task_deadline: Option<Instant>) -> Option<Instant> {
    let waiters = inner
        .accept_q
        .iter()
        .chain(inner.connect.as_deref())
        .filter_map(|waiter| waiter.deadline);
    let recv = inner.recv.as_ref().and_then(|recv| recv.deadline);
    waiters.chain(recv).chain(task_deadline).min()
}

/// Keep the port timer at the nearest deadline.
///
/// Port of the `driver_set_timer`/`driver_cancel_timer` calls of
/// erts/emulator/drivers/common/inet_drv.c, OTP-29.1.1: the timer expires as a port
/// timeout task (`tcp_inet_timeout`) that a scheduler executes.
/// The new port timer deadline when it differs from the armed one.
fn timer_change(inner: &mut Inner, task_deadline: Option<Instant>) -> Option<Option<Instant>> {
    let next = next_deadline(inner, task_deadline);
    if next == inner.timer_at {
        return None;
    }
    inner.timer_at = next;
    Some(next)
}

fn set_port_timer(port: &DriverPort, timer: Option<Option<Instant>>) {
    match timer {
        None => {}
        Some(Some(at)) => {
            let left = at.saturating_duration_since(Instant::now());
            // Round up so the callback never runs before the deadline.
            let millis = left.as_millis() + u128::from(left.subsec_nanos() % 1_000_000 != 0);
            port.set_timer(i64::try_from(millis).unwrap_or(i64::MAX));
        }
        Some(None) => port.cancel_timer(),
    }
}

/// Expire receive, accept, connect and send timers of `sock`.
///
/// Port of erts/emulator/drivers/common/inet_drv.c (tcp_inet_timeout), OTP-29.1.1.
fn expire(sock: &Arc<Sock>) {
    let now = Instant::now();
    let port = sock.port();
    let expired_sends = port
        .as_ref()
        .map_or(0, |port| port.expire_task_deadlines(now));
    let busy_waits_remain = port.as_ref().is_some_and(|port| port.has_busy_wait_tasks());
    let (due, close) = {
        let mut inner = sock.inner.lock();
        let mut due = Vec::new();
        let mut keep = VecDeque::new();
        while let Some(waiter) = inner.accept_q.pop_front() {
            if waiter.deadline.is_some_and(|at| at <= now) {
                drop_pending(&mut inner, waiter.caller, waiter.aref);
                demonitor_waiter(&inner, &waiter);
                due.push((waiter.caller, waiter.aref));
            } else {
                keep.push_back(waiter);
            }
        }
        inner.accept_q = keep.into();
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
            inner.take_fd();
            inner.phase = Phase::Closed;
            due.push((waiter.caller, waiter.aref));
        }
        let close = if expired_sends != 0 && inner.send_timeout_close {
            inner.take_fd();
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
        if expired_sends != 0 && (close.is_some() || !busy_waits_remain) {
            inner.busy = false;
        }
        (due, close)
    };
    for (caller, aref) in due {
        emit(
            sock,
            Out::AsyncError {
                caller,
                aref,
                reason: "timeout",
            },
        );
    }
    if let Some((owner, active, exit_on_close)) = close
        && active
    {
        emit(sock, Out::TcpClosed { owner });
        if exit_on_close {
            driver_exit(sock);
        }
    }
}

#[cfg(test)]
mod layout_tests {
    #[test]
    fn reports_tcp_socket_layout() {
        eprintln!(
            "Sock={} Inner={} SockFd={} PortHandle={} DriverPort={}",
            std::mem::size_of::<super::Sock>(),
            std::mem::size_of::<super::Inner>(),
            std::mem::size_of::<super::SockFd>(),
            std::mem::size_of::<crate::port::PortHandle>(),
            std::mem::size_of::<arinsal_drv::DriverPort>(),
        );
        eprintln!(
            "PacketState={} Option<Recv>={} IoQueue={} Option<SockFd>={} Option<RefcBinary>={} \
             {} Mutex<Inner>={}",
            std::mem::size_of::<super::PacketState>(),
            std::mem::size_of::<Option<super::Recv>>(),
            std::mem::size_of::<super::IoQueue>(),
            std::mem::size_of::<Option<super::SockFd>>(),
            std::mem::size_of::<Option<arinsal_term::RefcBinary>>(),
            crate::port::layout_sizes().join(" "),
            std::mem::size_of::<parking_lot::Mutex<super::Inner>>(),
        );
    }
}
