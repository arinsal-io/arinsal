//! `udp_inet` port driver (`gen_udp`, inet / inet6 / local).
//!
//! `prim_inet` uses the same `port_control` opcodes as TCP (`INET_REQ_*` plus
//! `PACKET_REQ_RECV`) and `port_command` for `sendto`. Replies are
//! `{inet_reply, …}`, `{inet_async, …}`, `{udp, S, IP, Port, Data}` and the
//! ancillary-data form of that tuple.
//!
//! Port of `erts/emulator/drivers/common/inet_drv.c` (`udp_inet_start`,
//! `packet_inet_ctl`, `packet_inet_command`, `packet_inet_input`,
//! `packet_binary_message`), OTP-29.1.1.
//!
//! `sctp_inet` is not registered. On macOS erts has no SCTP driver, so
//! `open_port({spawn_driver, "sctp_inet"}, …)` is `badarg` and `prim_inet`
//! turns that into `{error, eprotonosupport}`.

use crate::inet_drv::{
    self, err_bytes, errno_name, last_errno, ok_bytes, set_nonblock, set_nosigpipe, split_caller,
    zeroed,
};
use crate::port::PortHandle;
use crate::process::Message;
use arinsal_drv::{ControlReply, DriverPort, NativeDriver};
use arinsal_sched::Pid;
use arinsal_term::{ProcessHeap, Term, TermBuilder};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::{Duration, Instant};

const REQ_OPEN: i64 = 1;
const REQ_FDOPEN: i64 = 13;
const REQ_CONNECT: i64 = 3;
const REQ_PEER: i64 = 4;
const REQ_NAME: i64 = 5;
const REQ_BIND: i64 = 6;
const REQ_SETOPTS: i64 = 7;
const REQ_GETOPTS: i64 = 8;
const REQ_GETSTAT: i64 = 11;
const REQ_GETHOSTNAME: i64 = 12;
const REQ_GETTYPE: i64 = 15;
const REQ_GETSTATUS: i64 = 16;
const REQ_GETFD: i64 = 14;
const REQ_GETIFLIST: i64 = 21;
const REQ_IFGET: i64 = 22;
const REQ_SUBSCRIBE: i64 = 24;
const REQ_GETIFADDRS: i64 = 25;
const PACKET_REQ_RECV: i64 = 60;

const AF_INET_CODE: u8 = 1;
const AF_INET6_CODE: u8 = 2;
const AF_ANY: u8 = 3;
const AF_LOOPBACK: u8 = 4;
const AF_LOCAL_CODE: u8 = 5;

const TYPE_DGRAM: u8 = 2;
const PROTO_DEFAULT: u8 = 0;
const PROTO_UDP: u8 = 2;

const OPT_REUSEADDR: u8 = 0;
const OPT_DONTROUTE: u8 = 2;
const OPT_BROADCAST: u8 = 4;
const OPT_SNDBUF: u8 = 6;
const OPT_RCVBUF: u8 = 7;
const OPT_PRIORITY: u8 = 8;
const OPT_TOS: u8 = 9;
const OPT_REUSEPORT_LB: u8 = 18;
const OPT_EXCLUSIVEADDRUSE: u8 = 19;
const OPT_MSGQ_HIGH: u8 = 36;
const OPT_MSGQ_LOW: u8 = 37;
const OPT_MULTICAST_IF: u8 = 11;
const OPT_MULTICAST_TTL: u8 = 12;
const OPT_MULTICAST_LOOP: u8 = 13;
const OPT_ADD_MEMBERSHIP: u8 = 14;
const OPT_DROP_MEMBERSHIP: u8 = 15;
const OPT_IPV6_V6ONLY: u8 = 16;
const OPT_REUSEPORT: u8 = 17;
const OPT_BUFFER: u8 = 20;
const OPT_HEADER: u8 = 21;
const OPT_ACTIVE: u8 = 22;
const OPT_PACKET: u8 = 23;
const OPT_MODE: u8 = 24;
const OPT_DELIVER: u8 = 25;
const OPT_EXIT: u8 = 26;
const OPT_PACKET_SIZE: u8 = 32;
const OPT_READ_PACKETS: u8 = 33;
const OPT_TCLASS: u8 = 41;
const OPT_RECVTOS: u8 = 43;
const OPT_RECVTCLASS: u8 = 44;
const OPT_TTL: u8 = 46;
const OPT_RECVTTL: u8 = 47;
const OPT_DEBUG: u8 = 99;

const F_OPEN: u32 = 0x0001;
const F_ACTIVE: u32 = 0x0004;
const INFINITY: u32 = 0xffff_ffff;

fn atom(name: &'static str) -> Term {
    crate::atom_cache::atom(name)
}

/// `driver_flags` of `udp_inet_driver_entry`: `ERL_DRV_FLAG_USE_PORT_LOCKING`.
const DRIVER_FLAGS: i32 = 1 << 0;

/// The linked-in `udp_inet` driver; see [`inet_drv::driver`].
///
/// Port of erts/emulator/drivers/common/inet_drv.c (`udp_inet_driver_entry`), OTP-29.1.1.
pub(crate) fn driver() -> Arc<arinsal_drv::Driver> {
    static DRIVER: OnceLock<Arc<arinsal_drv::Driver>> = OnceLock::new();
    Arc::clone(
        DRIVER.get_or_init(|| {
            arinsal_drv::Driver::native("udp_inet", DRIVER_FLAGS, Arc::new(UdpInet))
        }),
    )
}

/// The callbacks of `udp_inet_driver_entry`.
struct UdpInet;

/// The socket of a port together with its port handle, which stays alive for the whole
/// callback: the callback may close the port and still emits after that.
fn sock_of(port: &DriverPort) -> Option<(Arc<Sock>, Arc<PortHandle>)> {
    let sock = port.native_data::<Sock>()?;
    let handle = sock.handle.upgrade()?;
    Some((sock, handle))
}

impl NativeDriver for UdpInet {
    // Port of inet_drv.c (packet_inet_stop).
    fn stop(&self, port: &DriverPort) {
        if let Some((sock, _handle)) = sock_of(port) {
            udp_inet_stop(&sock);
        }
    }

    // Port of inet_drv.c (packet_inet_command).
    fn output(&self, port: &DriverPort, data: &[u8]) {
        if let Some((sock, _handle)) = sock_of(port) {
            command(&sock, Pid::from_data(port.caller()), data);
        }
    }

    // Port of inet_drv.c (packet_inet_ctl).
    fn control(&self, port: &DriverPort, op: u32, data: &[u8]) -> Option<ControlReply> {
        let (sock, _handle) = sock_of(port)?;
        // Port of inet_drv.c:14574 (packet_inet_ctl subtracts the magic), OTP-29.1.1.
        let cmd = i64::from(op).wrapping_sub(inet_drv::MAGIC);
        let reply = dispatch(&sock, Pid::from_data(port.caller()), cmd, data);
        settle(&sock);
        Some(ControlReply::List(reply.into()))
    }

    // Port of inet_drv.c (packet_inet_input).
    fn ready_input(&self, port: &DriverPort, _fd: i32) {
        if let Some((sock, _handle)) = sock_of(port) {
            pump(&sock);
            settle(&sock);
        }
    }

    // Port of inet_drv.c (packet_inet_timeout).
    fn timeout(&self, port: &DriverPort) {
        if let Some((sock, _handle)) = sock_of(port) {
            sock.inner.lock().unwrap().timer_at = None;
            expire(&sock);
            settle(&sock);
        }
    }

    fn stop_select(&self, _fd: i32) {}
}

/// Bring selection and port timer in line with the socket after a callback.
fn settle(sock: &Arc<Sock>) {
    sock_select(sock);
    arm_timer(sock);
}

/// Install the driver state of a `udp_inet` port.
pub(crate) fn attach(handle: &Arc<PortHandle>, port: &Arc<DriverPort>) {
    let sock = Arc::new(Sock::new(handle.id(), handle, port));
    handle.set_udp_driver_data(Arc::clone(&sock));
    port.start_native(sock);
}

/// Port of inet_drv.c (packet_inet_stop): drop the datagram socket. A waiting `recv`
/// sees `{error, closed}`.
fn udp_inet_stop(sock: &Arc<Sock>) {
    if let Some(handle) = sock.handle.upgrade() {
        handle.take_udp_driver_data();
    }
    let (fd, pending) = {
        let mut inner = sock.inner.lock().unwrap();
        let fd = inner.fd.take();
        inner.open = false;
        inner.connected = false;
        (fd, inner.recv.take())
    };
    drop(fd);
    if let Some(recv) = pending {
        emit(
            sock,
            Out::AsyncError {
                caller: recv.caller,
                aref: recv.aref,
                reason: "closed",
            },
        );
    }
}

fn command(sock: &Arc<Sock>, caller: Pid, data: &[u8]) {
    // Port of inet_drv.c:15037 (packet_inet_command), OTP-29.1.1.
    let Some((ids, payload)) = split_caller(data) else {
        return;
    };
    let error = send_command(sock, payload);
    emit(sock, Out::InetReply { caller, ids, error });
    settle(sock);
}

fn dispatch(sock: &Arc<Sock>, caller: Pid, cmd: i64, data: &[u8]) -> Vec<u8> {
    let (reply, closed) = {
        let mut inner = sock.inner.lock().unwrap();
        match cmd {
            REQ_OPEN => (open_socket(&mut inner, data), None),
            REQ_FDOPEN => (fdopen_socket(&mut inner, data), None),
            2 => {
                // INET_REQ_CLOSE. Port of inet_drv.c:14701 (packet_inet_ctl CLOSE).
                let fd = inner.fd.take();
                inner.fd_external = None;
                inner.open = false;
                inner.connected = false;
                (ok_bytes(&[]), Some((fd, inner.recv.take())))
            }
            REQ_BIND => (bind_socket(&mut inner, data), None),
            REQ_CONNECT => (connect_socket(&mut inner, data), None),
            REQ_NAME => (name_of(&inner, true), None),
            REQ_PEER => (name_of(&inner, false), None),
            REQ_SETOPTS => (setopts(&mut inner, data), None),
            REQ_GETOPTS => (getopts(&inner, data), None),
            REQ_GETSTAT => (getstat(&inner, data), None),
            REQ_GETHOSTNAME => (gethostname(data), None),
            REQ_GETFD => (getfd(&inner), None),
            // Port of inet_drv.c:11067-11086 (common inet_ctl), OTP-29.1.1.
            REQ_GETIFLIST if inner.open => (inet_drv::getiflist(), None),
            REQ_IFGET if inner.open => (inet_drv::ifget(data), None),
            REQ_GETIFADDRS if inner.open => (inet_drv::getifaddrs_reply(), None),
            REQ_GETIFLIST | REQ_IFGET | REQ_GETIFADDRS => (err_bytes("exbadport"), None),
            REQ_GETTYPE => (gettype(&inner), None),
            REQ_GETSTATUS => (getstatus(&inner), None),
            REQ_SUBSCRIBE => (subscribe(data), None),
            PACKET_REQ_RECV => (recv_req(sock, &mut inner, caller, data), None),
            _ => match inet_drv::interface_control(cmd, data, inner.open) {
                Some(reply) => (reply, None),
                None => (err_bytes("exbadport"), None),
            },
        }
    };
    if let Some((fd, pending)) = closed {
        drop(fd);
        if let Some(recv) = pending {
            emit(
                sock,
                Out::AsyncError {
                    caller: recv.caller,
                    aref: recv.aref,
                    reason: "closed",
                },
            );
        }
    }
    let passive = std::mem::take(&mut sock.inner.lock().unwrap().emit_passive);
    if passive {
        let owner = sock.handle().owner_pid();
        emit(sock, Out::UdpPassive { owner });
    }
    pump(sock);
    reply
}

fn open_socket(inner: &mut Inner, data: &[u8]) -> Vec<u8> {
    // Port of inet_drv.c:14577 (packet_inet_ctl INET_REQ_OPEN), OTP-29.1.1.
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
    if data[1] != TYPE_DGRAM {
        return err_bytes("einval");
    }
    let mut protocol = match data[2] {
        PROTO_DEFAULT => 0,
        PROTO_UDP => libc::IPPROTO_UDP,
        _ => return err_bytes("eprotonosupport"),
    };
    // Port of inet_drv.c:5167 (inet_ctl_open): Unix sockets take protocol 0.
    if domain == libc::AF_UNIX {
        protocol = 0;
    }
    // SAFETY: socket returns a fresh descriptor; set close-on-exec before publishing it.
    let (fd, cloexec_error) = crate::port::cloexec_publish(|| unsafe {
        let fd = libc::socket(domain, libc::SOCK_DGRAM, protocol);
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
    inner.fd = Some(UdpFd::new(
        unsafe { OwnedFd::from_raw_fd(fd) },
        inner.port.clone(),
    ));
    inner.domain = domain;
    inner.family_code = data[0];
    inner.open = true;
    ok_bytes(&[])
}

fn fdopen_socket(inner: &mut Inner, data: &[u8]) -> Vec<u8> {
    // Port of inet_drv.c:14639-14678 (packet_inet_ctl INET_REQ_FDOPEN), OTP-29.1.1.
    if (data.len() != 6 && data.len() != 10) || inner.fd.is_some() {
        return err_bytes("einval");
    }
    let domain = match data[0] {
        AF_INET_CODE => libc::AF_INET,
        AF_INET6_CODE => libc::AF_INET6,
        AF_LOCAL_CODE => libc::AF_UNIX,
        _ => return err_bytes("eafnosupport"),
    };
    if data[1] != TYPE_DGRAM {
        return err_bytes("einval");
    }
    let raw_fd = i32::from_be_bytes(data[2..6].try_into().unwrap());
    if raw_fd < 0 {
        return err_bytes("einval");
    }
    let bound = if data.len() == 6 {
        true
    } else {
        i32::from_be_bytes(data[6..10].try_into().unwrap()) != 0
    };
    let fd = match crate::port::duplicate_fd(raw_fd) {
        Ok(fd) => fd,
        Err(error) => return err_bytes(errno_name(error.raw_os_error().unwrap_or(libc::EINVAL))),
    };
    if bound {
        let addr = match rustix::net::getsockname(&fd) {
            Ok(addr) => addr,
            Err(error) => return err_bytes(errno_name(error.raw_os_error())),
        };
        let family = rustix::net::AddressFamily::from_raw(domain as _);
        if addr.address_family() != family {
            return err_bytes("einval");
        }
    }
    set_nonblock(fd.as_raw_fd());
    set_nosigpipe(fd.as_raw_fd());
    inner.fd = Some(UdpFd::new(fd, inner.port.clone()));
    // Port of inet_drv.c:5269 (inet_fdopen, `prebound`): the port selects on the descriptor
    // number it was given, so a later port on it steals the selection from the earlier one.
    if let Some(fd) = inner.fd.as_mut() {
        fd.select_fd = raw_fd;
    }
    inner.fd_external = Some(raw_fd);
    inner.domain = domain;
    inner.family_code = data[0];
    inner.open = true;
    ok_bytes(&[])
}

fn bind_socket(inner: &mut Inner, data: &[u8]) -> Vec<u8> {
    // Port of inet_drv.c:11409 (INET_REQ_BIND), OTP-29.1.1.
    if !inner.open || inner.fd.is_none() {
        return err_bytes("exbadport");
    }
    let Ok((dest, _)) = parse_addr(inner.domain, data) else {
        return err_bytes("einval");
    };
    let fd = inner.fd.as_ref().unwrap().as_raw_fd();
    let rc = dest.call(|ptr, len| {
        // SAFETY: ptr/len is the sockaddr this driver built; fd is its socket.
        unsafe { libc::bind(fd, ptr, len) }
    });
    if rc < 0 {
        return err_bytes(errno_name(last_errno()));
    }
    let port = match &dest {
        Dest::V4(addr) => u16::from_be(addr.sin_port),
        Dest::V6(addr) => u16::from_be(addr.sin6_port),
        Dest::Unix(_, _) => 0,
    };
    let port = if port == 0 {
        match sock_port(inner) {
            Ok(p) => p,
            Err(reason) => return err_bytes(reason),
        }
    } else {
        port
    };
    ok_bytes(&port.to_be_bytes())
}

// BSDs spell the IPv6 membership options JOIN/LEAVE_GROUP, Linux ADD/DROP_MEMBERSHIP;
// erts maps both onto IPV6_ADD_MEMBERSHIP / IPV6_DROP_MEMBERSHIP.
#[cfg(target_os = "macos")]
const IPV6_ADD_MEMBERSHIP: i32 = libc::IPV6_JOIN_GROUP;
#[cfg(target_os = "macos")]
const IPV6_DROP_MEMBERSHIP: i32 = libc::IPV6_LEAVE_GROUP;
#[cfg(target_os = "linux")]
const IPV6_ADD_MEMBERSHIP: i32 = libc::IPV6_ADD_MEMBERSHIP;
#[cfg(target_os = "linux")]
const IPV6_DROP_MEMBERSHIP: i32 = libc::IPV6_DROP_MEMBERSHIP;

fn connect_socket(inner: &mut Inner, data: &[u8]) -> Vec<u8> {
    // Port of inet_drv.c:14710 (packet_inet_ctl INET_REQ_CONNECT, UDP), OTP-29.1.1.
    if !inner.open || inner.fd.is_none() {
        return err_bytes("exbadport");
    }
    let fd = inner.fd.as_ref().unwrap().as_raw_fd();
    if data.is_empty() {
        let mut sa: libc::sockaddr = zeroed();
        #[cfg(target_os = "macos")]
        {
            sa.sa_len = 2;
        }
        sa.sa_family = libc::AF_UNSPEC as libc::sa_family_t;
        // SAFETY: fd is the datagram socket this driver owns.
        unsafe { libc::connect(fd, &sa, 2) };
        inner.connected = false;
        return ok_bytes(&[]);
    }
    if data.len() < 6 {
        return err_bytes("einval");
    }
    // Timeout is ignored; UDP connect is synchronous.
    let Ok((dest, _)) = parse_addr(inner.domain, &data[4..]) else {
        return err_bytes("eafnosupport");
    };
    let rc = dest.call(|ptr, len| {
        // SAFETY: ptr/len is the sockaddr this driver built; fd is its socket.
        unsafe { libc::connect(fd, ptr, len) }
    });
    if rc < 0 {
        let err = last_errno();
        let mut sa: libc::sockaddr = zeroed();
        sa.sa_family = libc::AF_UNSPEC as libc::sa_family_t;
        // SAFETY: fd is the datagram socket this driver owns.
        unsafe { libc::connect(fd, &sa, 2) };
        inner.connected = false;
        return err_bytes(errno_name(err));
    }
    inner.connected = true;
    ok_bytes(&[])
}

fn name_of(inner: &Inner, local: bool) -> Vec<u8> {
    // Port of inet_drv.c:4890 (inet_get_address), OTP-29.1.1.
    let Some(fd) = inner.fd.as_ref() else {
        return err_bytes("einval");
    };
    if !local && !inner.connected {
        return err_bytes("enotconn");
    }
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
        return err_bytes(errno_name(last_errno()));
    }
    match encode_addr(&storage, len) {
        Some(bytes) => ok_bytes(&bytes),
        None => err_bytes("einval"),
    }
}

fn sock_port(inner: &Inner) -> Result<u16, &'static str> {
    let Some(fd) = inner.fd.as_ref() else {
        return Err("einval");
    };
    let mut storage: libc::sockaddr_storage = zeroed();
    let mut len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    // SAFETY: fd is a socket this driver owns.
    let rc = unsafe {
        libc::getsockname(
            fd.as_raw_fd(),
            (&mut storage as *mut libc::sockaddr_storage).cast(),
            &mut len,
        )
    };
    if rc < 0 {
        return Err(errno_name(last_errno()));
    }
    // SAFETY: family discriminates the active member.
    unsafe {
        if storage.ss_family as i32 == libc::AF_INET {
            let addr = &*(&storage as *const libc::sockaddr_storage).cast::<libc::sockaddr_in>();
            Ok(u16::from_be(addr.sin_port))
        } else if storage.ss_family as i32 == libc::AF_INET6 {
            let addr = &*(&storage as *const libc::sockaddr_storage).cast::<libc::sockaddr_in6>();
            Ok(u16::from_be(addr.sin6_port))
        } else {
            Ok(0)
        }
    }
}

fn setopts(inner: &mut Inner, data: &[u8]) -> Vec<u8> {
    // Port of inet_drv.c:6871 (inet_set_opts) and the UDP cases, OTP-29.1.1.
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
        OPT_REUSEADDR => sock_bool(inner, libc::SOL_SOCKET, libc::SO_REUSEADDR, val != 0),
        OPT_DONTROUTE => sock_bool(inner, libc::SOL_SOCKET, libc::SO_DONTROUTE, val != 0),
        OPT_BROADCAST => sock_bool(inner, libc::SOL_SOCKET, libc::SO_BROADCAST, val != 0),
        OPT_REUSEPORT => sock_bool(inner, libc::SOL_SOCKET, libc::SO_REUSEPORT, val != 0),
        // Port of inet_drv.c (inet_set_opts): load balancing is SO_REUSEPORT on Linux and
        // absent elsewhere; SO_PRIORITY and SO_EXCLUSIVEADDRUSE likewise.
        #[cfg(target_os = "linux")]
        OPT_REUSEPORT_LB => sock_bool(inner, libc::SOL_SOCKET, libc::SO_REUSEPORT, val != 0),
        #[cfg(not(target_os = "linux"))]
        OPT_REUSEPORT_LB => true,
        OPT_EXCLUSIVEADDRUSE => true,
        #[cfg(target_os = "linux")]
        OPT_PRIORITY => sock_int(inner, libc::SOL_SOCKET, libc::SO_PRIORITY, val),
        #[cfg(not(target_os = "linux"))]
        OPT_PRIORITY => true,
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
            true
        }
        OPT_SNDBUF => sock_int(inner, libc::SOL_SOCKET, libc::SO_SNDBUF, val),
        OPT_RCVBUF => {
            if !inner.buffer_set {
                // Port of inet_drv.c:7328-7348 (UDP rcvbuf buffer cap), OTP-29.1.1.
                inner.buffer = if val > (1 << 16) {
                    1 << 16
                } else {
                    inner.buffer.max(val)
                };
            }
            sock_int(inner, libc::SOL_SOCKET, libc::SO_RCVBUF, val)
        }
        OPT_TOS => {
            inner.tos = val;
            sock_int(inner, libc::IPPROTO_IP, libc::IP_TOS, val)
        }
        // Port of inet_drv.c:7428-7438 (INET_OPT_TCLASS), OTP-29.1.1.
        OPT_TCLASS => {
            inner.tclass = val;
            sock_int(inner, libc::IPPROTO_IPV6, libc::IPV6_TCLASS, val)
        }
        OPT_TTL => {
            inner.ttl = val;
            sock_int(inner, libc::IPPROTO_IP, libc::IP_TTL, val)
        }
        OPT_MULTICAST_TTL => {
            // Port of inet_drv.c:7571. Always IP_MULTICAST_TTL; propagate stays 0.
            inner.multicast_ttl = val;
            let _ = sock_int(inner, libc::IPPROTO_IP, libc::IP_MULTICAST_TTL, val);
            true
        }
        OPT_MULTICAST_LOOP => {
            // Port of inet_drv.c:7580. Always IP_MULTICAST_LOOP; propagate stays 0.
            inner.multicast_loop = val != 0;
            let _ = sock_int(inner, libc::IPPROTO_IP, libc::IP_MULTICAST_LOOP, val);
            true
        }
        OPT_MULTICAST_IF => set_multicast_if(inner, val),
        OPT_ADD_MEMBERSHIP | OPT_DROP_MEMBERSHIP => {
            set_membership(inner, code == OPT_DROP_MEMBERSHIP, val, data, i)
        }
        OPT_IPV6_V6ONLY => {
            inner.v6only = val != 0;
            if inner.domain == libc::AF_INET6 {
                sock_bool(inner, libc::IPPROTO_IPV6, libc::IPV6_V6ONLY, val != 0)
            } else {
                // No fd yet: the option is remembered. With an fd, inet4 rejects it.
                inner.fd.is_none()
            }
        }
        OPT_BUFFER => {
            if val <= 0 {
                return false;
            }
            inner.buffer = val;
            inner.buffer_set = true;
            true
        }
        OPT_HEADER => {
            if val < 0 {
                return false;
            }
            inner.header = val as usize;
            true
        }
        OPT_ACTIVE => set_active(inner, val, data, i),
        OPT_PACKET => {
            inner.htype = val;
            true
        }
        OPT_MODE => {
            inner.binary = val == 1;
            true
        }
        OPT_DELIVER => {
            inner.deliver = val;
            true
        }
        OPT_EXIT => {
            inner.exit_on_close = val != 0;
            true
        }
        OPT_PACKET_SIZE => {
            inner.packet_size = val.max(0) as u32;
            true
        }
        OPT_READ_PACKETS => {
            // Port of inet_drv.c:7138 (INET_LOPT_UDP_READ_PACKETS), OTP-29.1.1.
            if val <= 0 {
                return false;
            }
            inner.read_packets = val;
            true
        }
        OPT_RECVTOS => {
            inner.recvtos = val != 0;
            sock_bool(inner, libc::IPPROTO_IP, libc::IP_RECVTOS, val != 0)
        }
        // Port of inet_drv.c:7466-7478 (INET_OPT_RECVTCLASS), OTP-29.1.1.
        OPT_RECVTCLASS => {
            inner.recvtclass = val != 0;
            sock_bool(inner, libc::IPPROTO_IPV6, libc::IPV6_RECVTCLASS, val != 0)
        }
        OPT_RECVTTL => {
            inner.recvttl = val != 0;
            sock_bool(inner, libc::IPPROTO_IP, libc::IP_RECVTTL, val != 0)
        }
        OPT_DEBUG => {
            inner.debug = val != 0;
            true
        }
        _ => false,
    }
}

fn set_active(inner: &mut Inner, val: i32, data: &[u8], i: &mut usize) -> bool {
    // Port of inet_drv.c:6968 (inet_set_opts, INET_LOPT_ACTIVE), OTP-29.1.1.
    if val == 3 {
        if *i + 2 > data.len() {
            return false;
        }
        let n = i16::from_be_bytes([data[*i], data[*i + 1]]);
        *i += 2;
        let current = match inner.active {
            Active::Multi(count) => count,
            _ => 0,
        };
        let sum = i32::from(current) + i32::from(n);
        if sum > i32::from(i16::MAX) || sum < i32::from(i16::MIN) {
            return false;
        }
        if sum <= 0 {
            inner.active = Active::Passive;
            inner.emit_passive = true;
        } else {
            inner.active = Active::Multi(sum as i16);
        }
    } else {
        inner.active = match val {
            0 => Active::Passive,
            1 => Active::True,
            2 => Active::Once,
            _ => return false,
        };
    }
    true
}

fn set_multicast_if(inner: &mut Inner, val: i32) -> bool {
    // Port of inet_drv.c:7589 (UDP_OPT_MULTICAST_IF), OTP-29.1.1.
    // The option word is already host-order; htonl restores network order.
    // `propagate` stays 0, so a setsockopt failure is still success.
    inner.multicast_if = val;
    let net = val.to_be();
    if inner.domain == libc::AF_INET {
        let _ = sock_int(inner, libc::IPPROTO_IP, libc::IP_MULTICAST_IF, net);
        true
    } else if inner.domain == libc::AF_INET6 {
        let _ = sock_int(inner, libc::IPPROTO_IPV6, libc::IPV6_MULTICAST_IF, net);
        true
    } else {
        inner.fd.is_none()
    }
}

fn set_membership(
    inner: &mut Inner,
    drop: bool,
    domain_code: i32,
    data: &[u8],
    i: &mut usize,
) -> bool {
    // Port of inet_drv.c:7619 (UDP_OPT_ADD_MEMBERSHIP / L_init_mreq), OTP-29.1.1.
    if *i + 4 > data.len() {
        return false;
    }
    let ifindex = i32::from_be_bytes(data[*i..*i + 4].try_into().unwrap());
    *i += 4;
    if domain_code == i32::from(AF_INET_CODE) {
        if inner.domain != libc::AF_INET || *i + 8 > data.len() {
            return false;
        }
        let multi = be_addr(&data[*i..*i + 4]);
        *i += 4;
        let iface = be_addr(&data[*i..*i + 4]);
        *i += 4;
        let req = libc::ip_mreq {
            imr_multiaddr: libc::in_addr { s_addr: multi },
            imr_interface: libc::in_addr { s_addr: iface },
        };
        let _ = ifindex;
        let name = if drop {
            libc::IP_DROP_MEMBERSHIP
        } else {
            libc::IP_ADD_MEMBERSHIP
        };
        // propagate stays 0 (inet_drv.c:7923): a kernel refusal is still ok.
        let _ = sock_bytes(
            inner,
            libc::IPPROTO_IP,
            name,
            (&req as *const libc::ip_mreq).cast(),
            std::mem::size_of::<libc::ip_mreq>() as libc::socklen_t,
        );
        true
    } else if domain_code == i32::from(AF_INET6_CODE) {
        if inner.domain != libc::AF_INET6 || *i + 16 > data.len() {
            return false;
        }
        let mut addr = libc::in6_addr { s6_addr: [0; 16] };
        addr.s6_addr.copy_from_slice(&data[*i..*i + 16]);
        *i += 16;
        let req = libc::ipv6_mreq {
            ipv6mr_multiaddr: addr,
            ipv6mr_interface: ifindex as u32,
        };
        let name = if drop {
            IPV6_DROP_MEMBERSHIP
        } else {
            IPV6_ADD_MEMBERSHIP
        };
        let _ = sock_bytes(
            inner,
            libc::IPPROTO_IPV6,
            name,
            (&req as *const libc::ipv6_mreq).cast(),
            std::mem::size_of::<libc::ipv6_mreq>() as libc::socklen_t,
        );
        true
    } else {
        false
    }
}

fn be_addr(bytes: &[u8]) -> u32 {
    u32::from_be_bytes(bytes.try_into().unwrap()).to_be()
}

fn sock_bool(inner: &Inner, level: i32, name: i32, on: bool) -> bool {
    sock_int(inner, level, name, i32::from(on))
}

fn sock_int(inner: &Inner, level: i32, name: i32, val: i32) -> bool {
    let Some(fd) = inner.fd.as_ref() else {
        return true;
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
    rc == 0
}

fn sock_bytes(inner: &Inner, level: i32, name: i32, ptr: *const u8, len: libc::socklen_t) -> bool {
    let Some(fd) = inner.fd.as_ref() else {
        return true;
    };
    // SAFETY: ptr/len describe a setsockopt argument this driver built; fd is its socket.
    let rc = unsafe { libc::setsockopt(fd.as_raw_fd(), level, name, ptr.cast(), len) };
    rc == 0
}

fn sock_get_int(inner: &Inner, level: i32, name: i32, fallback: i32) -> i32 {
    let Some(fd) = inner.fd.as_ref() else {
        return fallback;
    };
    let mut val = fallback;
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
    if rc == 0 { val } else { fallback }
}

fn getopts(inner: &Inner, data: &[u8]) -> Vec<u8> {
    // Port of inet_drv.c:9071 (inet_fill_opts), OTP-29.1.1.
    let mut out = Vec::new();
    for &code in data {
        if !push_opt(inner, code, &mut out) {
            return err_bytes("einval");
        }
    }
    ok_bytes(&out)
}

fn push_opt(inner: &Inner, code: u8, out: &mut Vec<u8>) -> bool {
    out.push(code);
    match code {
        OPT_REUSEADDR => put_i32(
            out,
            sock_get_int(inner, libc::SOL_SOCKET, libc::SO_REUSEADDR, 0),
        ),
        OPT_DONTROUTE => put_i32(
            out,
            sock_get_int(inner, libc::SOL_SOCKET, libc::SO_DONTROUTE, 0),
        ),
        OPT_BROADCAST => put_i32(
            out,
            sock_get_int(inner, libc::SOL_SOCKET, libc::SO_BROADCAST, 0),
        ),
        OPT_REUSEPORT => put_i32(
            out,
            sock_get_int(inner, libc::SOL_SOCKET, libc::SO_REUSEPORT, 0),
        ),
        #[cfg(target_os = "linux")]
        OPT_REUSEPORT_LB => put_i32(
            out,
            sock_get_int(inner, libc::SOL_SOCKET, libc::SO_REUSEPORT, 0),
        ),
        #[cfg(not(target_os = "linux"))]
        OPT_REUSEPORT_LB => put_i32(out, 0),
        OPT_EXCLUSIVEADDRUSE => put_i32(out, 0),
        #[cfg(target_os = "linux")]
        OPT_PRIORITY => put_i32(
            out,
            sock_get_int(inner, libc::SOL_SOCKET, libc::SO_PRIORITY, 0),
        ),
        #[cfg(not(target_os = "linux"))]
        OPT_PRIORITY => put_i32(out, 0),
        OPT_MSGQ_HIGH => put_i32(out, inner.msgq_high),
        OPT_MSGQ_LOW => put_i32(out, inner.msgq_low),
        OPT_SNDBUF => put_i32(
            out,
            sock_get_int(inner, libc::SOL_SOCKET, libc::SO_SNDBUF, 0),
        ),
        OPT_RCVBUF => put_i32(
            out,
            sock_get_int(inner, libc::SOL_SOCKET, libc::SO_RCVBUF, 0),
        ),
        OPT_TOS => put_i32(
            out,
            sock_get_int(inner, libc::IPPROTO_IP, libc::IP_TOS, inner.tos),
        ),
        OPT_TCLASS => put_i32(
            out,
            sock_get_int(inner, libc::IPPROTO_IPV6, libc::IPV6_TCLASS, inner.tclass),
        ),
        OPT_TTL => put_i32(
            out,
            sock_get_int(inner, libc::IPPROTO_IP, libc::IP_TTL, inner.ttl),
        ),
        OPT_MULTICAST_TTL => {
            let (level, name) = if inner.domain == libc::AF_INET6 {
                (libc::IPPROTO_IPV6, libc::IPV6_MULTICAST_HOPS)
            } else {
                (libc::IPPROTO_IP, libc::IP_MULTICAST_TTL)
            };
            put_i32(out, sock_get_int(inner, level, name, inner.multicast_ttl));
        }
        OPT_MULTICAST_LOOP => {
            let (level, name) = if inner.domain == libc::AF_INET6 {
                (libc::IPPROTO_IPV6, libc::IPV6_MULTICAST_LOOP)
            } else {
                (libc::IPPROTO_IP, libc::IP_MULTICAST_LOOP)
            };
            put_i32(
                out,
                sock_get_int(inner, level, name, i32::from(inner.multicast_loop)),
            );
        }
        OPT_MULTICAST_IF => {
            // Decoder wants 4 address/index bytes, then the family code.
            // Port of inet_drv.c:9497 (inet_fill_opts multicast-if), OTP-29.1.1.
            let family = if inner.domain == libc::AF_INET6 {
                i32::from(AF_INET6_CODE)
            } else {
                i32::from(AF_INET_CODE)
            };
            put_i32(out, inner.multicast_if);
            put_i32(out, family);
        }
        OPT_IPV6_V6ONLY => put_i32(
            out,
            sock_get_int(
                inner,
                libc::IPPROTO_IPV6,
                libc::IPV6_V6ONLY,
                i32::from(inner.v6only),
            ),
        ),
        OPT_BUFFER => put_i32(out, inner.buffer),
        OPT_HEADER => put_i32(out, inner.header as i32),
        OPT_ACTIVE => match inner.active {
            Active::Passive => put_i32(out, 0),
            Active::True => put_i32(out, 1),
            Active::Once => put_i32(out, 2),
            Active::Multi(n) => {
                put_i32(out, 3);
                out.extend_from_slice(&n.to_be_bytes());
            }
        },
        OPT_PACKET => put_i32(out, inner.htype),
        OPT_MODE => put_i32(out, i32::from(inner.binary)),
        OPT_DELIVER => put_i32(out, inner.deliver),
        OPT_EXIT => put_i32(out, i32::from(inner.exit_on_close)),
        OPT_PACKET_SIZE => put_i32(out, inner.packet_size as i32),
        OPT_READ_PACKETS => put_i32(out, inner.read_packets),
        OPT_RECVTOS => put_i32(out, i32::from(inner.recvtos)),
        OPT_RECVTCLASS => put_i32(out, i32::from(inner.recvtclass)),
        OPT_RECVTTL => put_i32(out, i32::from(inner.recvttl)),
        OPT_DEBUG => put_i32(out, i32::from(inner.debug)),
        _ => return false,
    }
    true
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

fn getstat(inner: &Inner, data: &[u8]) -> Vec<u8> {
    // Port of inet_drv.c:10732 (inet_fill_stat), OTP-29.1.1.
    let mut out = Vec::new();
    for &code in data {
        out.push(code);
        match code {
            1 => put_u32(&mut out, inner.recv_cnt),
            2 => put_u32(&mut out, inner.recv_max),
            3 => put_u32(&mut out, inner.recv_avg as u32),
            4 => put_u32(&mut out, inner.recv_dvi.abs() as u32),
            5 => put_u32(&mut out, inner.send_cnt),
            6 => put_u32(&mut out, inner.send_max),
            7 => put_u32(&mut out, inner.send_avg as u32),
            8 => put_u32(&mut out, 0),
            9 => put_u64(&mut out, inner.recv_oct),
            10 => put_u64(&mut out, inner.send_oct),
            _ => return err_bytes("einval"),
        }
    }
    ok_bytes(&out)
}

fn gethostname(data: &[u8]) -> Vec<u8> {
    // Port of inet_drv.c:11219 (INET_REQ_GETHOSTNAME), OTP-29.1.1.
    if !data.is_empty() {
        return err_bytes("einval");
    }
    let mut buf = [0u8; 256];
    // SAFETY: buf is a writable 256-byte hostname buffer, the size erts passes.
    let rc = unsafe { libc::gethostname(buf.as_mut_ptr().cast::<libc::c_char>(), buf.len()) };
    if rc != 0 {
        return err_bytes(errno_name(last_errno()));
    }
    let n = buf.iter().position(|b| *b == 0).unwrap_or(buf.len());
    ok_bytes(&buf[..n])
}

fn gettype(inner: &Inner) -> Vec<u8> {
    // Port of inet_drv.c:11165 (INET_REQ_GETTYPE), OTP-29.1.1.
    if !inner.open {
        return err_bytes("einval");
    }
    let mut out = Vec::new();
    put_u32(&mut out, u32::from(inner.family_code));
    put_u32(&mut out, u32::from(TYPE_DGRAM));
    ok_bytes(&out)
}

fn getstatus(inner: &Inner) -> Vec<u8> {
    // Port of inet_drv.c:11153 (INET_REQ_GETSTATUS), OTP-29.1.1.
    let mut flags = 0u32;
    if inner.open {
        flags |= F_OPEN;
    }
    if inner.connected {
        flags |= F_ACTIVE;
    }
    ok_bytes(&flags.to_be_bytes())
}

fn getfd(inner: &Inner) -> Vec<u8> {
    // Port of inet_drv.c:11205-11213 (INET_REQ_GETFD), OTP-29.1.1.
    let Some(fd) = inner.fd.as_ref() else {
        return err_bytes("einval");
    };
    let raw = inner.fd_external.unwrap_or_else(|| fd.as_raw_fd());
    ok_bytes(&(raw as u32).to_be_bytes())
}

fn subscribe(data: &[u8]) -> Vec<u8> {
    // UDP sends complete inside port_command, so the output queue is empty.
    let mut out = Vec::new();
    for &code in data {
        if code != 1 {
            return err_bytes("einval");
        }
        out.push(1);
        put_u32(&mut out, 0);
    }
    ok_bytes(&out)
}

fn recv_req(sock: &Arc<Sock>, inner: &mut Inner, caller: Pid, data: &[u8]) -> Vec<u8> {
    // Port of inet_drv.c:14968 (PACKET_REQ_RECV), OTP-29.1.1.
    if !inner.open {
        return err_bytes("exbadport");
    }
    if active_is(&inner.active) || data.len() != 8 {
        return err_bytes("einval");
    }
    if inner.recv.is_some() {
        return err_bytes("ealready");
    }
    let timeout = u32::from_be_bytes(data[0..4].try_into().unwrap());
    let aref = alloc_async(inner);
    inner.recv = Some(Recv {
        caller,
        aref,
        deadline: if timeout == INFINITY {
            None
        } else {
            Some(Instant::now() + Duration::from_millis(u64::from(timeout)))
        },
        timeout_if_empty: timeout == 0,
    });
    let _ = sock;
    ok_bytes(&aref.to_be_bytes())
}

fn alloc_async(inner: &mut Inner) -> u16 {
    // Port of inet_drv.c:1549 (NEW_ASYNC_ID), OTP-29.1.1.
    let id = inner.op_ref;
    inner.op_ref = inner.op_ref.wrapping_add(1);
    id
}

fn send_command(sock: &Sock, payload: &[u8]) -> Option<&'static str> {
    let mut inner = sock.inner.lock().unwrap();
    if !inner.open || inner.fd.is_none() {
        return Some("einval");
    }
    let Ok((dest, used)) = parse_addr(inner.domain, payload) else {
        return Some("einval");
    };
    if payload.len() < used + 4 {
        return Some("einval");
    }
    let anc_len = u32::from_be_bytes(payload[used..used + 4].try_into().unwrap()) as usize;
    if payload.len() < used + 4 + anc_len {
        return Some("einval");
    }
    let anc = &payload[used + 4..used + 4 + anc_len];
    let body = &payload[used + 4 + anc_len..];
    let fd = inner.fd.as_ref().unwrap().as_raw_fd();
    let connected = inner.connected;
    let rc = if anc.is_empty() {
        if connected {
            // SAFETY: fd is the connected datagram socket this driver owns.
            unsafe { libc::send(fd, body.as_ptr().cast(), body.len(), 0) }
        } else {
            dest.call(|ptr, len| {
                // SAFETY: ptr/len is the destination this driver parsed; fd is its socket.
                unsafe { libc::sendto(fd, body.as_ptr().cast(), body.len(), 0, ptr, len) }
            })
        }
    } else {
        match send_anc(fd, &dest, connected, anc, body) {
            Ok(n) => n,
            Err(()) => return Some("einval"),
        }
    };
    if rc < 0 {
        return Some(errno_name(last_errno()));
    }
    note_send(&mut inner, body.len() as u64);
    None
}

fn send_anc(fd: RawFd, dest: &Dest, connected: bool, anc: &[u8], body: &[u8]) -> Result<isize, ()> {
    // Port of inet_drv.c:3784 (compile_ancillary_data) and :15184 (sendmsg), OTP-29.1.1.
    let mut ctrl = Aligned([0u8; 256]);
    let mut used = 0usize;
    let mut cursor = anc;
    while !cursor.is_empty() {
        let code = cursor[0];
        cursor = &cursor[1..];
        if cursor.len() < 4 {
            return Err(());
        }
        let val = i32::from_be_bytes(cursor[..4].try_into().unwrap());
        cursor = &cursor[4..];
        let (level, opt) = match code {
            OPT_TOS => (libc::IPPROTO_IP, libc::IP_TOS),
            OPT_TTL => (libc::IPPROTO_IP, libc::IP_TTL),
            OPT_TCLASS => (libc::IPPROTO_IPV6, libc::IPV6_TCLASS),
            _ => return Err(()),
        };
        if !write_cmsg(&mut ctrl.0, &mut used, level, opt, val) {
            return Err(());
        }
    }
    let mut iov = libc::iovec {
        iov_base: body.as_ptr() as *mut libc::c_void,
        iov_len: body.len(),
    };
    let mut msg: libc::msghdr = zeroed();
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = ctrl.0.as_mut_ptr().cast();
    msg.msg_controllen = used as _;
    // The destination has to stay alive for the duration of sendmsg.
    let rc = if connected {
        // SAFETY: fd is the connected datagram socket; msg describes caller buffers.
        unsafe { libc::sendmsg(fd, &msg, 0) }
    } else {
        dest.call(|ptr, len| {
            msg.msg_name = ptr as *mut libc::c_void;
            msg.msg_namelen = len;
            // SAFETY: ptr/len is the parsed destination; fd is this driver's socket.
            unsafe { libc::sendmsg(fd, &msg, 0) }
        })
    };
    Ok(rc)
}

fn note_send(inner: &mut Inner, len: u64) {
    // Port of inet_drv.c:11560 (inet_output_count), OTP-29.1.1.
    let mut n = inner.send_cnt.wrapping_add(1);
    if n == 0 {
        n = 1;
    }
    let len_f = len as f64;
    inner.send_avg += (len_f - inner.send_avg) / f64::from(n);
    if len > u64::from(inner.send_max) {
        inner.send_max = len as u32;
    }
    inner.send_cnt = n;
    inner.send_oct = inner.send_oct.wrapping_add(len);
}

fn note_recv(inner: &mut Inner, len: u64) {
    // Port of inet_drv.c:11585 (inet_input_count), OTP-29.1.1.
    let mut n = inner.recv_cnt.wrapping_add(1);
    if n == 0 {
        n = 1;
    }
    let len_f = len as f64;
    let avg = inner.recv_avg + (len_f - inner.recv_avg) / f64::from(n);
    inner.recv_avg = avg;
    if len > u64::from(inner.recv_max) {
        inner.recv_max = len as u32;
    }
    inner.recv_dvi += ((len_f - avg) - inner.recv_dvi) / f64::from(n);
    inner.recv_cnt = n;
    inner.recv_oct = inner.recv_oct.wrapping_add(len);
}

fn pump(sock: &Arc<Sock>) {
    let outs = {
        let mut inner = sock.inner.lock().unwrap();
        let mut outs = Vec::new();
        pull(&sock.handle(), &mut inner, &mut outs);
        timeout_if_empty(&mut inner, &mut outs);
        outs
    };
    for out in outs {
        emit(sock, out);
    }
}

fn timeout_if_empty(inner: &mut Inner, outs: &mut Vec<Out>) {
    let Some(recv) = inner.recv.as_ref() else {
        return;
    };
    if recv.timeout_if_empty {
        let recv = inner.recv.take().unwrap();
        outs.push(Out::AsyncError {
            caller: recv.caller,
            aref: recv.aref,
            reason: "timeout",
        });
    }
}

fn pull(handle: &PortHandle, inner: &mut Inner, outs: &mut Vec<Out>) {
    if inner.fd.is_none() || !inner.open {
        return;
    }
    let want = if inner.recv.is_some() {
        // One datagram completes a passive recv. Port of packet_inet_input.
        1
    } else if active_is(&inner.active) {
        inner.read_packets.max(1)
    } else {
        return;
    };
    let mut left = want;
    while left > 0 {
        left -= 1;
        match recv_one(inner) {
            RecvOne::Empty => break,
            RecvOne::Error(reason) => {
                if let Some(recv) = inner.recv.take() {
                    outs.push(Out::AsyncError {
                        caller: recv.caller,
                        aref: recv.aref,
                        reason,
                    });
                } else if active_is(&inner.active) {
                    outs.push(Out::UdpError {
                        owner: handle.owner_pid(),
                        reason,
                    });
                }
                break;
            }
            RecvOne::Packet(packet) => {
                note_recv(inner, packet.data.len() as u64);
                deliver(handle, inner, packet, outs);
                if inner.recv.is_none() && !active_is(&inner.active) {
                    break;
                }
                if inner.recv.is_none() && !active_is(&inner.active) {
                    break;
                }
                // Passive mode delivers a single datagram.
                if !active_is(&inner.active) {
                    break;
                }
            }
        }
    }
}

fn deliver(handle: &PortHandle, inner: &mut Inner, packet: Packet, outs: &mut Vec<Out>) {
    // Port of inet_drv.c:4334 (packet_reply_binary_data), OTP-29.1.1.
    let owner = handle.owner_pid();
    if let Some(recv) = inner.recv.take() {
        outs.push(Out::AsyncData {
            caller: recv.caller,
            aref: recv.aref,
            packet,
            binary: inner.binary,
            header: inner.header,
            with_anc: inner.recvtos || inner.recvtclass || inner.recvttl,
        });
        return;
    }
    if !active_is(&inner.active) {
        return;
    }
    outs.push(Out::Udp {
        owner,
        packet,
        binary: inner.binary,
        header: inner.header,
        with_anc: inner.recvtos || inner.recvtclass || inner.recvttl,
    });
    match inner.active {
        Active::Once => inner.active = Active::Passive,
        Active::Multi(n) => {
            let next = n - 1;
            if next <= 0 {
                inner.active = Active::Passive;
                outs.push(Out::UdpPassive { owner });
            } else {
                inner.active = Active::Multi(next);
            }
        }
        Active::True | Active::Passive => {}
    }
}

struct Packet {
    addr: Vec<u8>,
    data: Vec<u8>,
    anc: Vec<Anc>,
}

enum Anc {
    Tos(i32),
    Ttl(i32),
    Tclass(i32),
}

enum RecvOne {
    Empty,
    Error(&'static str),
    Packet(Packet),
}

fn recv_one(inner: &mut Inner) -> RecvOne {
    // Port of inet_drv.c:15361 (packet_inet_input), OTP-29.1.1.
    let fd = inner.fd.as_ref().unwrap().as_raw_fd();
    let mut buf = vec![0u8; inner.buffer.max(1) as usize];
    let mut storage: libc::sockaddr_storage = zeroed();
    let mut ctrl = Aligned([0u8; 256]);
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr().cast(),
        iov_len: buf.len(),
    };
    let mut msg: libc::msghdr = zeroed();
    msg.msg_name = (&mut storage as *mut libc::sockaddr_storage).cast();
    msg.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    let want_cmsg = inner.recvtos || inner.recvtclass || inner.recvttl;
    if want_cmsg {
        msg.msg_control = ctrl.0.as_mut_ptr().cast();
        msg.msg_controllen = ctrl.0.len() as _;
    }
    // SAFETY: fd is the datagram socket this driver owns; buffers outlive the call.
    let n = unsafe { libc::recvmsg(fd, &mut msg, 0) };
    if n < 0 {
        let err = last_errno();
        if err == libc::EAGAIN || err == libc::EWOULDBLOCK || err == libc::EINTR {
            return RecvOne::Empty;
        }
        return RecvOne::Error(errno_name(err));
    }
    let addr = encode_addr(&storage, msg.msg_namelen).unwrap_or_else(|| vec![0]);
    let anc = if want_cmsg {
        #[allow(clippy::unnecessary_cast)] // msg_controllen is u32 on macOS, usize on Linux
        parse_cmsgs(&ctrl.0[..msg.msg_controllen as usize])
    } else {
        Vec::new()
    };
    buf.truncate(n as usize);
    RecvOne::Packet(Packet {
        addr,
        data: buf,
        anc,
    })
}

fn active_is(active: &Active) -> bool {
    !matches!(active, Active::Passive)
}

enum Dest {
    V4(libc::sockaddr_in),
    V6(libc::sockaddr_in6),
    Unix(libc::sockaddr_un, libc::socklen_t),
}

impl Dest {
    fn call<R>(&self, mut f: impl FnMut(*const libc::sockaddr, libc::socklen_t) -> R) -> R {
        match self {
            Dest::V4(addr) => f(
                (addr as *const libc::sockaddr_in).cast(),
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            ),
            Dest::V6(addr) => f(
                (addr as *const libc::sockaddr_in6).cast(),
                std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
            ),
            Dest::Unix(addr, len) => f((addr as *const libc::sockaddr_un).cast(), *len),
        }
    }
}

fn parse_addr(domain: i32, data: &[u8]) -> Result<(Dest, usize), ()> {
    // Port of inet_drv.c:4795 (inet_set_faddress) and :4706 (inet_set_address), OTP-29.1.1.
    if data.is_empty() {
        return Err(());
    }
    let tag = data[0];
    let rest = &data[1..];
    match tag {
        AF_INET_CODE => {
            if rest.len() < 6 {
                return Err(());
            }
            let port = u16::from_be_bytes([rest[0], rest[1]]);
            let mut ip = [0u8; 4];
            ip.copy_from_slice(&rest[2..6]);
            Ok((Dest::V4(v4(port, ip)), 7))
        }
        AF_INET6_CODE => {
            if rest.len() < 26 {
                return Err(());
            }
            let port = u16::from_be_bytes([rest[0], rest[1]]);
            let mut ip = [0u8; 16];
            ip.copy_from_slice(&rest[2..18]);
            let flow = u32::from_be_bytes(rest[18..22].try_into().unwrap());
            let scope = u32::from_be_bytes(rest[22..26].try_into().unwrap());
            Ok((Dest::V6(v6(port, ip, flow, scope)), 27))
        }
        AF_ANY | AF_LOOPBACK => {
            if rest.len() < 2 {
                return Err(());
            }
            let port = u16::from_be_bytes([rest[0], rest[1]]);
            let loopback = tag == AF_LOOPBACK;
            if domain == libc::AF_INET6 {
                let mut ip = [0u8; 16];
                if loopback {
                    ip[15] = 1;
                }
                Ok((Dest::V6(v6(port, ip, 0, 0)), 3))
            } else if domain == libc::AF_INET {
                let ip = if loopback {
                    [127, 0, 0, 1]
                } else {
                    [0, 0, 0, 0]
                };
                Ok((Dest::V4(v4(port, ip)), 3))
            } else {
                Err(())
            }
        }
        AF_LOCAL_CODE => {
            if rest.is_empty() {
                return Err(());
            }
            let n = rest[0] as usize;
            if rest.len() < 1 + n {
                return Err(());
            }
            let (addr, len) = unix_addr(&rest[1..1 + n])?;
            Ok((Dest::Unix(addr, len), 2 + n))
        }
        _ => Err(()),
    }
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

fn v6(port: u16, ip: [u8; 16], flow: u32, scope: u32) -> libc::sockaddr_in6 {
    let mut addr: libc::sockaddr_in6 = zeroed();
    #[cfg(target_os = "macos")]
    {
        addr.sin6_len = std::mem::size_of::<libc::sockaddr_in6>() as u8;
    }
    addr.sin6_family = libc::AF_INET6 as libc::sa_family_t;
    addr.sin6_port = port.to_be();
    addr.sin6_flowinfo = flow;
    addr.sin6_addr.s6_addr = ip;
    addr.sin6_scope_id = scope;
    addr
}

fn unix_addr(path: &[u8]) -> Result<(libc::sockaddr_un, libc::socklen_t), ()> {
    let mut addr: libc::sockaddr_un = zeroed();
    let cap = addr.sun_path.len();
    if path.len() + 1 > cap {
        return Err(());
    }
    let off = std::mem::offset_of!(libc::sockaddr_un, sun_path);
    let len = off + path.len();
    #[cfg(target_os = "macos")]
    {
        addr.sun_len = len as u8;
    }
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    // SAFETY: path.len() is less than sun_path, and the struct was zeroed.
    unsafe {
        std::ptr::copy_nonoverlapping(path.as_ptr(), addr.sun_path.as_mut_ptr().cast(), path.len());
    }
    Ok((addr, len as libc::socklen_t))
}

fn encode_addr(storage: &libc::sockaddr_storage, len: libc::socklen_t) -> Option<Vec<u8>> {
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
            let addr = &*(storage as *const libc::sockaddr_storage).cast::<libc::sockaddr_un>();
            let off = std::mem::offset_of!(libc::sockaddr_un, sun_path);
            let n = (len as usize).saturating_sub(off).min(addr.sun_path.len());
            let bytes = std::slice::from_raw_parts(addr.sun_path.as_ptr().cast::<u8>(), n);
            let m = bytes.iter().position(|b| *b == 0).unwrap_or(n);
            let mut out = vec![AF_LOCAL_CODE, m as u8];
            out.extend_from_slice(&bytes[..m]);
            Some(out)
        } else {
            None
        }
    }
}

#[repr(C, align(8))]
struct Aligned([u8; 256]);

/// `CMSG_ALIGN`: Darwin aligns to 4 bytes, Linux to `sizeof(size_t)`.
fn cmsg_align(len: usize) -> usize {
    const ALIGN: usize = if cfg!(target_os = "macos") {
        4
    } else {
        std::mem::size_of::<usize>()
    };
    len.div_ceil(ALIGN) * ALIGN
}

fn cmsg_space(len: usize) -> usize {
    cmsg_align(std::mem::size_of::<libc::cmsghdr>()) + cmsg_align(len)
}

fn write_cmsg(buf: &mut [u8], used: &mut usize, level: i32, opt: i32, val: i32) -> bool {
    let space = cmsg_space(4);
    if *used + space > buf.len() {
        return false;
    }
    let hdr = libc::cmsghdr {
        cmsg_len: (cmsg_align(std::mem::size_of::<libc::cmsghdr>()) + 4) as _,
        cmsg_level: level,
        cmsg_type: opt,
    };
    // SAFETY: `used` is aligned to the cmsg alignment and space bytes remain.
    unsafe {
        std::ptr::write_unaligned(buf[*used..].as_mut_ptr().cast(), hdr);
        std::ptr::write_unaligned(
            buf[*used + cmsg_align(std::mem::size_of::<libc::cmsghdr>())..]
                .as_mut_ptr()
                .cast(),
            val,
        );
    }
    *used += space;
    true
}

fn parse_cmsgs(buf: &[u8]) -> Vec<Anc> {
    // Port of inet_drv.c:3230 (parse_ancillary_data_item), OTP-29.1.1.
    let mut out = Vec::new();
    let mut off = 0;
    let hdr_len = std::mem::size_of::<libc::cmsghdr>();
    while off + hdr_len <= buf.len() {
        // SAFETY: off is within buf and cmsghdr is a plain integer struct.
        let hdr: libc::cmsghdr = unsafe { std::ptr::read_unaligned(buf[off..].as_ptr().cast()) };
        let total = hdr.cmsg_len as usize;
        if total < hdr_len || off + total > buf.len() {
            break;
        }
        let data_off = off + cmsg_align(hdr_len);
        let data_len = total.saturating_sub(cmsg_align(hdr_len));
        if data_off + data_len.min(4) <= buf.len() && data_len > 0 {
            let val = cmsg_int(&buf[data_off..data_off + data_len]);
            let anc = match (hdr.cmsg_level, hdr.cmsg_type) {
                (x, y) if x == libc::IPPROTO_IP && (y == libc::IP_TOS || y == libc::IP_RECVTOS) => {
                    Some(Anc::Tos(val))
                }
                (x, y) if x == libc::IPPROTO_IP && (y == libc::IP_TTL || y == libc::IP_RECVTTL) => {
                    Some(Anc::Ttl(val))
                }
                (x, y)
                    if x == libc::IPPROTO_IPV6
                        && (y == libc::IPV6_TCLASS || y == libc::IPV6_RECVTCLASS) =>
                {
                    Some(Anc::Tclass(val))
                }
                _ => None,
            };
            if let Some(anc) = anc {
                out.push(anc);
            }
        }
        let step = cmsg_align(total).max(cmsg_align(hdr_len));
        off += step;
    }
    out
}

fn cmsg_int(bytes: &[u8]) -> i32 {
    match bytes.len() {
        1 => i32::from(bytes[0]),
        2 => i32::from(u16::from_ne_bytes([bytes[0], bytes[1]])),
        n if n >= 4 => i32::from_ne_bytes(bytes[..4].try_into().unwrap()),
        _ => 0,
    }
}

enum Out {
    AsyncError {
        caller: Pid,
        aref: u16,
        reason: &'static str,
    },
    AsyncData {
        caller: Pid,
        aref: u16,
        packet: Packet,
        binary: bool,
        header: usize,
        with_anc: bool,
    },
    InetReply {
        caller: Pid,
        ids: [u32; 3],
        error: Option<&'static str>,
    },
    Udp {
        owner: Pid,
        packet: Packet,
        binary: bool,
        header: usize,
        with_anc: bool,
    },
    UdpPassive {
        owner: Pid,
    },
    UdpError {
        owner: Pid,
        reason: &'static str,
    },
}

fn emit(sock: &Sock, out: Out) {
    let sched = sock.handle().scheduler();
    let port = Term::port(sock.id).unwrap();
    let words = 256
        + match &out {
            Out::AsyncData { packet, .. } | Out::Udp { packet, .. } => packet.data.len() * 2,
            _ => 0,
        };
    let mut heap = ProcessHeap::with_words(words);
    let term = match &out {
        Out::AsyncError {
            caller,
            aref,
            reason,
        } => error_tuple(&mut heap, reason)
            .and_then(|status| message_async(&mut heap, port, *aref, status))
            .map(|term| (*caller, term)),
        Out::AsyncData {
            caller,
            aref,
            packet,
            binary,
            header,
            with_anc,
        } => {
            let data = passive_data(&mut heap, packet, *binary, *header, *with_anc);
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
        Out::Udp {
            owner,
            packet,
            binary,
            header,
            with_anc,
        } => active_message(&mut heap, port, packet, *binary, *header, *with_anc)
            .map(|term| (*owner, term)),
        Out::UdpPassive { owner } => TermBuilder::new(&mut heap)
            .tuple(&[atom("udp_passive"), port])
            .ok()
            .map(|term| (*owner, term)),
        Out::UdpError { owner, reason } => TermBuilder::new(&mut heap)
            .tuple(&[atom("udp_error"), port, atom(reason)])
            .ok()
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

fn error_tuple(heap: &mut ProcessHeap, reason: &'static str) -> Option<Term> {
    TermBuilder::new(heap)
        .tuple(&[atom("error"), atom(reason)])
        .ok()
}

fn passive_data(
    heap: &mut ProcessHeap,
    packet: &Packet,
    binary: bool,
    header: usize,
    with_anc: bool,
) -> Option<Term> {
    // Address bytes then datagram. Ancillary data wraps that in a 2-tuple
    // when RECVTOS / RECVTTL is set (inet_drv.c:3964).
    let mut bytes = packet.addr.clone();
    bytes.extend_from_slice(&packet.data);
    let hsz = packet.addr.len() + header;
    let body = byte_term(heap, &bytes, binary, hsz)?;
    if !with_anc {
        return Some(body);
    }
    let anc = anc_term(heap, &packet.anc)?;
    TermBuilder::new(heap).tuple(&[body, anc]).ok()
}

fn active_message(
    heap: &mut ProcessHeap,
    port: Term,
    packet: &Packet,
    binary: bool,
    header: usize,
    with_anc: bool,
) -> Option<Term> {
    // Port of inet_drv.c:4106 (packet_binary_message), OTP-29.1.1.
    let (ip, udp_port) = load_address(heap, &packet.addr)?;
    let data = byte_term(heap, &packet.data, binary, header)?;
    if with_anc {
        let anc = anc_term(heap, &packet.anc)?;
        TermBuilder::new(heap)
            .tuple(&[atom("udp"), port, ip, udp_port, anc, data])
            .ok()
    } else {
        TermBuilder::new(heap)
            .tuple(&[atom("udp"), port, ip, udp_port, data])
            .ok()
    }
}

fn load_address(heap: &mut ProcessHeap, addr: &[u8]) -> Option<(Term, Term)> {
    // Port of inet_drv.c:1916 (load_address), OTP-29.1.1.
    match addr.first().copied()? {
        AF_INET_CODE if addr.len() >= 7 => {
            let port = u16::from_be_bytes([addr[1], addr[2]]);
            let ip = TermBuilder::new(heap)
                .tuple(&[
                    small(addr[3])?,
                    small(addr[4])?,
                    small(addr[5])?,
                    small(addr[6])?,
                ])
                .ok()?;
            Some((ip, Term::small(i64::from(port))?))
        }
        AF_INET6_CODE if addr.len() >= 19 => {
            let port = u16::from_be_bytes([addr[1], addr[2]]);
            let mut words = [Term::NIL; 8];
            for (i, word) in words.iter_mut().enumerate() {
                let n = u16::from_be_bytes([addr[3 + i * 2], addr[4 + i * 2]]);
                *word = Term::small(i64::from(n))?;
            }
            let ip = TermBuilder::new(heap).tuple(&words).ok()?;
            Some((ip, Term::small(i64::from(port))?))
        }
        AF_LOCAL_CODE if addr.len() >= 2 => {
            let n = addr[1] as usize;
            if addr.len() < 2 + n {
                return None;
            }
            let path = TermBuilder::new(heap).binary(&addr[2..2 + n]).ok()?;
            let local = TermBuilder::new(heap).tuple(&[atom("local"), path]).ok()?;
            Some((local, Term::small(0)?))
        }
        _ => None,
    }
}

fn small(b: u8) -> Option<Term> {
    Term::small(i64::from(b))
}

fn byte_term(heap: &mut ProcessHeap, bytes: &[u8], binary: bool, hsz: usize) -> Option<Term> {
    // Port of inet_drv.c:3951 (list, or [H1..Hsz | Binary]), OTP-29.1.1.
    let mut builder = TermBuilder::new(heap);
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

fn anc_term(heap: &mut ProcessHeap, anc: &[Anc]) -> Option<Term> {
    let mut items = Vec::with_capacity(anc.len());
    for item in anc {
        let (name, val) = match item {
            Anc::Tos(v) => ("tos", *v),
            Anc::Ttl(v) => ("ttl", *v),
            Anc::Tclass(v) => ("tclass", *v),
        };
        let pair = TermBuilder::new(heap)
            .tuple(&[atom(name), Term::small(i64::from(val))?])
            .ok()?;
        items.push(pair);
    }
    TermBuilder::new(heap).list_from_iter(items).ok()
}

pub(crate) struct Sock {
    id: u64,
    handle: Weak<PortHandle>,
    port: Weak<DriverPort>,
    inner: Mutex<Inner>,
}

impl Sock {
    fn new(id: u64, handle: &Arc<PortHandle>, port: &Arc<DriverPort>) -> Self {
        Self {
            id,
            handle: Arc::downgrade(handle),
            port: Arc::downgrade(port),
            inner: Mutex::new(Inner {
                port: Arc::downgrade(port),
                ..Inner::default()
            }),
        }
    }

    fn handle(&self) -> Arc<PortHandle> {
        self.handle.upgrade().expect("live udp inet port handle")
    }

    fn port(&self) -> Option<Arc<DriverPort>> {
        self.port.upgrade()
    }
}

#[derive(Clone, Copy)]
enum Active {
    Passive,
    True,
    Once,
    Multi(i16),
}

struct Recv {
    caller: Pid,
    aref: u16,
    deadline: Option<Instant>,
    timeout_if_empty: bool,
}

struct Inner {
    /// `{udp_passive, S}` is due after `setopts` (the `{active,N}` count reached zero).
    emit_passive: bool,
    /// The `DriverPort` of this socket (`desc->inet.port`).
    port: Weak<DriverPort>,
    /// The deadline the port timer is armed for.
    timer_at: Option<Instant>,
    fd: Option<UdpFd>,
    fd_external: Option<RawFd>,
    domain: i32,
    family_code: u8,
    open: bool,
    connected: bool,
    binary: bool,
    active: Active,
    htype: i32,
    header: usize,
    buffer: i32,
    buffer_set: bool,
    deliver: i32,
    exit_on_close: bool,
    packet_size: u32,
    read_packets: i32,
    msgq_high: i32,
    msgq_low: i32,
    tos: i32,
    tclass: i32,
    ttl: i32,
    multicast_ttl: i32,
    multicast_loop: bool,
    multicast_if: i32,
    v6only: bool,
    recvtos: bool,
    recvtclass: bool,
    recvttl: bool,
    debug: bool,
    op_ref: u16,
    recv: Option<Recv>,
    recv_cnt: u32,
    send_cnt: u32,
    recv_max: u32,
    send_max: u32,
    recv_oct: u64,
    send_oct: u64,
    recv_avg: f64,
    send_avg: f64,
    recv_dvi: f64,
}

impl Default for Inner {
    fn default() -> Self {
        // Port of inet_drv.c:10891 (inet_start) and :14508 (read_packets), OTP-29.1.1.
        Self {
            port: Weak::new(),
            timer_at: None,
            fd: None,
            fd_external: None,
            domain: libc::AF_INET,
            family_code: AF_INET_CODE,
            open: false,
            connected: false,
            binary: false,
            emit_passive: false,
            active: Active::Passive,
            htype: 0,
            header: 0,
            buffer: 9216,
            buffer_set: false,
            deliver: 1,
            exit_on_close: true,
            packet_size: 0,
            read_packets: 5,
            msgq_high: 8192,
            msgq_low: 4096,
            tos: 0,
            tclass: 0,
            ttl: 0,
            multicast_ttl: 1,
            multicast_loop: true,
            multicast_if: 0,
            v6only: false,
            recvtos: false,
            recvtclass: false,
            recvttl: false,
            debug: false,
            op_ref: 0,
            recv: None,
            recv_cnt: 0,
            send_cnt: 0,
            recv_max: 0,
            send_max: 0,
            recv_oct: 0,
            send_oct: 0,
            recv_avg: 0.0,
            send_avg: 0.0,
            recv_dvi: 0.0,
        }
    }
}

/// Bring the poll-set selection of `sock` in line with its state.
///
/// Port of the `sock_select` calls of inet_drv.c, OTP-29.1.1: FD_READ while active or a
/// receive is pending.
fn sock_select(sock: &Arc<Sock>) {
    use arinsal_drv::{SELECT_READ, SELECT_USE};
    let Some(port) = sock.port() else {
        return;
    };
    let mut inner = sock.inner.lock().unwrap();
    let readable = inner.open && (inner.recv.is_some() || active_is(&inner.active));
    let Some(fd) = inner.fd.as_mut() else {
        return;
    };
    if readable == fd.selected {
        return;
    }
    // Port of inet_drv.c (inet_driver_select): `ERL_DRV_USE` only when turning events on.
    let mode = if readable {
        SELECT_READ | SELECT_USE
    } else {
        SELECT_READ
    };
    port.select(fd.select_fd, mode, readable);
    fd.selected = readable;
}

/// The socket of a `udp_inet` port.
///
/// Dropping it deselects the descriptor before closing it, as `inet_stop_select` is
/// reached in erts only after `driver_select(..., ERL_DRV_USE, 0)` has taken the
/// descriptor out of the poll set (inet_drv.c, OTP-29.1.1).
struct UdpFd {
    fd: OwnedFd,
    /// The descriptor number given to `driver_select` (the caller's one for `{fd, Fd}`).
    select_fd: RawFd,
    port: Weak<DriverPort>,
    /// FD_READ is selected through `driver_select`.
    selected: bool,
}

impl UdpFd {
    fn new(fd: OwnedFd, port: Weak<DriverPort>) -> Self {
        Self {
            select_fd: fd.as_raw_fd(),
            fd,
            port,
            selected: false,
        }
    }
}

impl AsRawFd for UdpFd {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

impl Drop for UdpFd {
    fn drop(&mut self) {
        if let Some(port) = self.port.upgrade() {
            use arinsal_drv::{SELECT_READ, SELECT_USE, SELECT_WRITE};
            port.select(
                self.select_fd,
                SELECT_READ | SELECT_WRITE | SELECT_USE,
                false,
            );
        }
    }
}

/// Keep the port timer at the receive deadline (`driver_set_timer`).
fn arm_timer(sock: &Arc<Sock>) {
    let Some(port) = sock.port() else {
        return;
    };
    let next = {
        let mut inner = sock.inner.lock().unwrap();
        let next = inner.recv.as_ref().and_then(|recv| recv.deadline);
        if next == inner.timer_at {
            return;
        }
        inner.timer_at = next;
        next
    };
    match next {
        Some(at) => {
            let left = at.saturating_duration_since(Instant::now());
            // Round up so the callback never runs before the deadline.
            let millis = left.as_millis() + u128::from(left.subsec_nanos() % 1_000_000 != 0);
            port.set_timer(i64::try_from(millis).unwrap_or(i64::MAX));
        }
        None => port.cancel_timer(),
    }
}

/// Port of inet_drv.c (packet_inet_timeout): a passive `recv` ran out of time.
fn expire(sock: &Arc<Sock>) {
    let now = Instant::now();
    let due = {
        let mut inner = sock.inner.lock().unwrap();
        if inner
            .recv
            .as_ref()
            .and_then(|recv| recv.deadline)
            .is_some_and(|at| at <= now)
        {
            inner.recv.take()
        } else {
            None
        }
    };
    if let Some(recv) = due {
        emit(
            sock,
            Out::AsyncError {
                caller: recv.caller,
                aref: recv.aref,
                reason: "timeout",
            },
        );
    }
}
