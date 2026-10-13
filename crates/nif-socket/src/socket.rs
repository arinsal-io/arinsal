use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use arinsal_bifs::BifError;
use arinsal_etf::OwnedTerm as O;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};

use crate::{Reactor, atom, errno, error, field, last_error, list, map, name, number, ok, pair};

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

pub(super) fn reactor() -> &'static Mutex<Option<Arc<dyn Reactor>>> {
    REACTOR.get_or_init(|| Mutex::new(None))
}
fn handles() -> &'static Mutex<HashMap<u64, Arc<Handle>>> {
    HANDLES.get_or_init(|| Mutex::new(HashMap::new()))
}
struct Handle {
    socket: Mutex<Option<Socket>>,
    reference: O,
    owner: Mutex<Option<O>>,
    monitors: Mutex<Vec<O>>,
    counters: Mutex<Counters>,
    otp_options: Mutex<HashMap<i32, O>>,
    sendfile_fd: Mutex<Option<OwnedFd>>,
    domain: &'static str,
    kind: &'static str,
    protocol: i32,
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
fn reference(
    socket: Socket,
    domain: &'static str,
    kind: &'static str,
    protocol: i32,
    owner: Option<O>,
) -> O {
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let reference = O::Ref {
        node: "nonode@nohost".into(),
        creation: 0,
        ids: vec![MAGIC, id as u32, (id >> 32) as u32],
    };
    handles().lock().unwrap().insert(
        id,
        Arc::new(Handle {
            socket: Mutex::new(Some(socket)),
            reference: reference.clone(),
            owner: Mutex::new(owner),
            monitors: Mutex::new(Vec::new()),
            counters: Mutex::new(Counters::default()),
            otp_options: Mutex::new(HashMap::new()),
            sendfile_fd: Mutex::new(None),
            domain,
            kind,
            protocol,
        }),
    );
    reference
}
pub(super) fn set_owner(value: &O, pid: O) -> Result<(), BifError> {
    if !matches!(pid, O::Pid { .. }) {
        return Err(BifError::BADARG);
    }
    *handle(value)?.owner.lock().unwrap() = Some(pid);
    Ok(())
}
pub(super) fn owner_died(pid: &O) {
    let mut table = handles().lock().unwrap();
    table.retain(|_, h| {
        let owned = h.owner.lock().unwrap().as_ref() == Some(pid);
        if owned {
            close_handle(h);
        }
        !owned
    });
}
pub(super) fn release(value: &O) -> Result<(), BifError> {
    let id = handle_id(value)?;
    if let Some(h) = handles().lock().unwrap().remove(&id) {
        close_handle(&h);
    }
    Ok(())
}
fn selected(h: &Handle, fd: i32, reference: &O, read: bool) -> O {
    if let (Some(pid), Some(r)) = (
        h.owner.lock().unwrap().as_ref(),
        reactor().lock().unwrap().as_ref(),
    ) {
        if read {
            r.register_read(fd, pid, &h.reference, reference);
        } else {
            r.register_write(fd, pid, &h.reference, reference);
        }
        h.monitors.lock().unwrap().push(reference.clone());
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
    let (domain, kind, protocol, owner) = if args.len() == 4 {
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
        (domain, kind, protocol, field(&args[3], "owner").cloned())
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
            field(&args[1], "owner").cloned(),
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
            Ok(ok(reference(socket, d, k, protocol, owner)))
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
    Ok(match guard.as_ref() {
        Some(s) => io_result(s.bind(&addr)),
        None => error("closed"),
    })
}
fn connect(args: &[O]) -> Result<O, BifError> {
    let h = handle(&args[0])?;
    let guard = h.socket.lock().unwrap();
    let Some(s) = guard.as_ref() else {
        return Ok(error("closed"));
    };
    if args.len() == 1 {
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
        return Ok(if status < 0 {
            last_error()
        } else if code == 0 {
            atom("ok")
        } else {
            errno(code)
        });
    }
    let Some(addr) = to_sock_addr(&args[2]) else {
        return Ok(invalid("sockaddr"));
    };
    Ok(match s.connect(&addr) {
        Ok(()) => atom("ok"),
        Err(e)
            if matches!(
                e.raw_os_error(),
                Some(libc::EINPROGRESS | libc::EALREADY | libc::EWOULDBLOCK)
            ) =>
        {
            selected(&h, s.as_raw_fd(), &args[1], false)
        }
        Err(e) => fail(&e),
    })
}
fn accept(args: &[O]) -> Result<O, BifError> {
    let h = handle(&args[0])?;
    let guard = h.socket.lock().unwrap();
    let Some(s) = guard.as_ref() else {
        return Ok(error("closed"));
    };
    h.counters.lock().unwrap().acc_tries += 1;
    Ok(match s.accept() {
        Ok((socket, _)) => {
            h.counters.lock().unwrap().acc_success += 1;
            if let Err(e) = socket.set_nonblocking(true) {
                fail(&e)
            } else {
                ok(reference(
                    socket,
                    h.domain,
                    h.kind,
                    h.protocol,
                    h.owner.lock().unwrap().clone(),
                ))
            }
        }
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
            h.counters.lock().unwrap().acc_waits += 1;
            selected(&h, s.as_raw_fd(), &args[1], true)
        }
        Err(e) => {
            h.counters.lock().unwrap().acc_fails += 1;
            fail(&e)
        }
    })
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
        return Ok(if e.kind() == io::ErrorKind::WouldBlock {
            h.counters.lock().unwrap().read_waits += 1;
            selected(&h, s.as_raw_fd(), reference, true)
        } else {
            h.counters.lock().unwrap().read_fails += 1;
            fail(&e)
        });
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
fn close(value: &O) -> Result<O, BifError> {
    let h = handle(value)?;
    close_handle(&h);
    Ok(atom("ok"))
}
fn close_handle(h: &Handle) {
    let fd = h.socket.lock().unwrap().as_ref().map(AsRawFd::as_raw_fd);
    if let (Some(fd), Some(r)) = (fd, reactor().lock().unwrap().as_ref()) {
        for reference in h.monitors.lock().unwrap().drain(..) {
            r.cancel(fd, &reference);
        }
    }
    h.monitors.lock().unwrap().clear();
    h.sendfile_fd.lock().unwrap().take();
    h.socket.lock().unwrap().take();
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
fn option(args: &[O], set: bool) -> Result<O, BifError> {
    // Port of erts/emulator/nifs/common/prim_socket_nif.c:7802 (nif_setopt), OTP-29.1.1.
    let h = handle(&args[0])?;
    let level = match name(&args[1]) {
        Some("socket") => libc::SOL_SOCKET,
        Some("otp") => -1,
        _ => integer(&args[1])?,
    };
    let opt = integer(&args[2])?;
    let guard = h.socket.lock().unwrap();
    let Some(s) = guard.as_ref() else {
        return Ok(error("closed"));
    };
    if level == -1 {
        return if set {
            if number(&args[4]) != Some(0) {
                return Ok(invalid("socket_option"));
            }
            match opt {
                1003 => {
                    if matches!(args[3], O::Pid { .. }) {
                        *h.owner.lock().unwrap() = Some(args[3].clone());
                        Ok(atom("ok"))
                    } else {
                        Ok(invalid("value"))
                    }
                }
                1001 | 1002 | 1010 | 1011 if matches!(name(&args[3]), Some("true" | "false")) => {
                    h.otp_options.lock().unwrap().insert(opt, args[3].clone());
                    Ok(atom("ok"))
                }
                1004 | 1006 | 1007 if number(&args[3]).is_some_and(|n| n > 0) => {
                    h.otp_options.lock().unwrap().insert(opt, args[3].clone());
                    Ok(atom("ok"))
                }
                1009 => {
                    h.otp_options.lock().unwrap().insert(opt, args[3].clone());
                    Ok(atom("ok"))
                }
                1001 | 1002 | 1004 | 1006 | 1007 | 1008 | 1010 | 1011 | 1999 => {
                    Ok(invalid("value"))
                }
                _ => Ok(invalid("socket_option")),
            }
        } else {
            let value = match opt {
                1003 => h
                    .owner
                    .lock()
                    .unwrap()
                    .clone()
                    .unwrap_or_else(|| atom("undefined")),
                1008 => O::Int(s.as_raw_fd().into()),
                1999 => atom(h.domain),
                1001 | 1002 => h
                    .otp_options
                    .lock()
                    .unwrap()
                    .get(&opt)
                    .cloned()
                    .unwrap_or_else(|| atom("false")),
                1010 | 1011 => h
                    .otp_options
                    .lock()
                    .unwrap()
                    .get(&opt)
                    .cloned()
                    .unwrap_or_else(|| atom("true")),
                1004 => h
                    .otp_options
                    .lock()
                    .unwrap()
                    .get(&opt)
                    .cloned()
                    .unwrap_or(O::Int(8192)),
                1006 | 1007 => h
                    .otp_options
                    .lock()
                    .unwrap()
                    .get(&opt)
                    .cloned()
                    .unwrap_or(O::Int(1024)),
                1009 => h
                    .otp_options
                    .lock()
                    .unwrap()
                    .get(&opt)
                    .cloned()
                    .unwrap_or_else(|| atom("undefined")),
                _ => return Ok(invalid("socket_option")),
            };
            Ok(ok(value))
        };
    }
    if set {
        let native = number(&args[4]) == Some(1);
        if native {
            let O::Binary(bytes) = &args[3] else {
                return Ok(invalid("value"));
            };
            // SAFETY: bytes is live and its length matches the supplied buffer.
            let status = unsafe {
                libc::setsockopt(
                    s.as_raw_fd(),
                    level,
                    opt,
                    bytes.as_ptr().cast(),
                    bytes.len() as libc::socklen_t,
                )
            };
            return Ok(if status < 0 { last_error() } else { atom("ok") });
        }
        let mut linger = libc::linger {
            l_onoff: 0,
            l_linger: 0,
        };
        let mut value = match &args[3] {
            O::Atom(v) if v == "true" => 1,
            O::Atom(v) if v == "false" => 0,
            O::Int(n) => i32::try_from(*n).map_err(|_| BifError::BADARG)?,
            O::Map(_) if opt == libc::SO_LINGER => {
                linger.l_onoff =
                    if name(field(&args[3], "onoff").unwrap_or(&atom("false"))) == Some("true") {
                        1
                    } else {
                        0
                    };
                linger.l_linger = field(&args[3], "linger")
                    .and_then(number)
                    .and_then(|n| i32::try_from(n).ok())
                    .ok_or(BifError::BADARG)?;
                0
            }
            _ => return Ok(invalid("value")),
        };
        let (ptr, len) = if opt == libc::SO_LINGER {
            (
                std::ptr::addr_of_mut!(linger).cast::<libc::c_void>(),
                std::mem::size_of_val(&linger),
            )
        } else {
            (
                std::ptr::addr_of_mut!(value).cast(),
                std::mem::size_of_val(&value),
            )
        };
        // SAFETY: ptr points to initialized value or linger and len matches its size.
        let status =
            unsafe { libc::setsockopt(s.as_raw_fd(), level, opt, ptr, len as libc::socklen_t) };
        Ok(if status < 0 { last_error() } else { atom("ok") })
    } else {
        if args.len() == 5 && name(&args[3]) == Some("native") {
            let mut bytes = match &args[4] {
                O::Int(n) if *n > 0 && *n <= 65536 => vec![0; *n as usize],
                O::Binary(value) if !value.is_empty() && value.len() <= 65536 => value.clone(),
                _ => return Ok(invalid("value")),
            };
            let mut len = bytes.len() as libc::socklen_t;
            // SAFETY: bytes is a writable buffer and len starts at its capacity.
            let status = unsafe {
                libc::getsockopt(
                    s.as_raw_fd(),
                    level,
                    opt,
                    bytes.as_mut_ptr().cast(),
                    &mut len,
                )
            };
            bytes.truncate(len as usize);
            return Ok(if status < 0 {
                last_error()
            } else {
                ok(O::Binary(bytes))
            });
        }
        if args.len() == 5 && name(&args[3]) != Some("value") {
            return Ok(invalid("value"));
        }
        if opt == libc::SO_LINGER {
            // SAFETY: zeroed linger has a valid representation for getsockopt output.
            let mut linger: libc::linger = unsafe { std::mem::zeroed() };
            let mut len = std::mem::size_of_val(&linger) as libc::socklen_t;
            // SAFETY: linger and len are writable and sized correctly.
            let status = unsafe {
                libc::getsockopt(
                    s.as_raw_fd(),
                    level,
                    opt,
                    (&mut linger as *mut libc::linger).cast(),
                    &mut len,
                )
            };
            return Ok(if status < 0 {
                last_error()
            } else {
                ok(map(&[
                    (
                        "onoff",
                        atom(if linger.l_onoff == 0 { "false" } else { "true" }),
                    ),
                    ("linger", O::Int(linger.l_linger.into())),
                ]))
            });
        }
        let mut value = 0i32;
        let mut len = std::mem::size_of_val(&value) as libc::socklen_t;
        // SAFETY: value and len are writable and sized correctly.
        let status = unsafe {
            libc::getsockopt(
                s.as_raw_fd(),
                level,
                opt,
                (&mut value as *mut i32).cast(),
                &mut len,
            )
        };
        let is_bool = matches!(
            opt,
            libc::SO_REUSEADDR | libc::SO_KEEPALIVE | libc::SO_REUSEPORT | libc::TCP_NODELAY
        );
        Ok(if status < 0 {
            last_error()
        } else if is_bool {
            ok(atom(if value == 0 { "false" } else { "true" }))
        } else {
            ok(O::Int(value.into()))
        })
    }
}
fn info(value: &O) -> Result<O, BifError> {
    let h = handle(value)?;
    let owner = h
        .owner
        .lock()
        .unwrap()
        .clone()
        .unwrap_or_else(|| atom("undefined"));
    Ok(map(&[
        ("domain", atom(h.domain)),
        ("type", atom(h.kind)),
        ("protocol", O::Int(h.protocol.into())),
        ("owner", owner),
        ("counters", h.counters.lock().unwrap().term()),
        ("ctype", atom("normal")),
        ("rstates", O::Nil),
        ("wstates", O::Nil),
        ("num_readers", O::Int(0)),
        ("num_writers", O::Int(0)),
        ("num_acceptors", O::Int(0)),
    ]))
}
fn global_info() -> O {
    let table = handles().lock().unwrap();
    let live: Vec<_> = table
        .values()
        .filter(|h| h.socket.lock().unwrap().is_some())
        .collect();
    let count = |test: fn(&Handle) -> bool| O::Int(live.iter().filter(|h| test(h)).count() as i64);
    let counters = map(&[
        ("num_cnt_bits", O::Int(64)),
        ("num_sockets", O::Int(live.len() as i64)),
        ("num_dinet", count(|h| h.domain == "inet")),
        ("num_dinet6", count(|h| h.domain == "inet6")),
        ("num_dlocal", count(|h| h.domain == "local")),
        ("num_tstreams", count(|h| h.kind == "stream")),
        ("num_tdgrams", count(|h| h.kind == "dgram")),
        ("num_tseqpkgs", O::Int(0)),
        ("num_ptcp", count(|h| h.protocol == 6)),
        ("num_pudp", count(|h| h.protocol == 17)),
        ("num_pip", count(|h| h.protocol == 0)),
        ("num_psctp", O::Int(0)),
    ]);
    map(&[
        ("counters", counters),
        ("debug", bool_atom(DEBUG.load(Ordering::Relaxed))),
        (
            "socket_debug",
            bool_atom(SOCKET_DEBUG.load(Ordering::Relaxed)),
        ),
        (
            "use_registry",
            bool_atom(USE_REGISTRY.load(Ordering::Relaxed)),
        ),
        ("iow", atom("false")),
        ("eei", atom("true")),
        ("iov_max", O::Int(1024)),
        (
            "io_backend",
            map(&[("name", atom("unix_essio")), ("sctp", atom("undefined"))]),
        ),
    ])
}
fn bool_atom(value: bool) -> O {
    atom(if value { "true" } else { "false" })
}
fn command(value: &O) -> Result<O, BifError> {
    let cmd = name(field(value, "command").ok_or(BifError::BADARG)?).ok_or(BifError::BADARG)?;
    let data = field(value, "data").ok_or(BifError::BADARG)?;
    let flag = match name(data) {
        Some("true") => true,
        Some("false") => false,
        _ => return Ok(invalid("value")),
    };
    match cmd {
        "debug" => DEBUG.store(flag, Ordering::Relaxed),
        "socket_debug" => SOCKET_DEBUG.store(flag, Ordering::Relaxed),
        "use_registry" => USE_REGISTRY.store(flag, Ordering::Relaxed),
        _ => return Ok(invalid("command")),
    }
    Ok(atom("ok"))
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
        ("nif_listen", 2) => {
            let h = handle(&args[0])?;
            let guard = h.socket.lock().unwrap();
            Ok(match guard.as_ref() {
                Some(s) => io_result(s.listen(integer(&args[1])?)),
                None => error("closed"),
            })
        }
        ("nif_accept", 2) => accept(args),
        ("nif_send", 4) => send(args, None),
        ("nif_sendto", 5) => send(args, Some(&args[2])),
        ("nif_sendmsg", 5) => send_vectors(args, true),
        ("nif_sendv", 3) => send_vectors(args, false),
        ("nif_recv", 4) => recv(args, false, false),
        ("nif_recvfrom", 4) => recv(args, true, false),
        ("nif_recvmsg", 5) => recv(args, false, true),
        ("nif_close" | "nif_finalize_close", 1) => close(&args[0]),
        ("nif_shutdown", 2) => shutdown(args),
        ("nif_setopt", 5) => option(args, true),
        ("nif_getopt", 3 | 5) => option(args, false),
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
        ("nif_info", 1) => info(&args[0]),
        ("nif_cancel", 3) => {
            let h = handle(&args[0])?;
            if let (Some(s), Some(r)) = (
                h.socket.lock().unwrap().as_ref(),
                reactor().lock().unwrap().as_ref(),
            ) {
                r.cancel(s.as_raw_fd(), &args[2]);
            }
            h.monitors.lock().unwrap().retain(|r| r != &args[2]);
            Ok(atom("ok"))
        }
        ("nif_supports", 0) => Ok(supports(None)),
        ("nif_supports", 1) => Ok(supports(Some(&args[0]))),
        ("nif_info", 0) => Ok(global_info()),
        ("nif_command", 1) => command(&args[0]),
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

    static REACTOR_TEST_LOCK: Mutex<()> = Mutex::new(());

    fn result(value: O) -> O {
        let O::Tuple(parts) = &value else {
            panic!("expected tuple: {value:?}")
        };
        assert_eq!(parts[0], atom("ok"), "{value:?}");
        parts[1].clone()
    }
    fn invoke(op: &str, args: &[O]) -> O {
        dispatch(op, args).unwrap()
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
    #[test]
    fn tcp_ipv4_ipv6_and_options() {
        let _lock = REACTOR_TEST_LOCK.lock().unwrap();
        io_round_trip("inet");
        io_round_trip("inet6");
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
        let connected = invoke("nif_connect", &[client.clone(), O::Int(1), address]);
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
            &[client.clone(), O::Int(1), addr("inet", port)],
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
            &[client.clone(), O::Int(1), addr("inet", port)],
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
            &[client.clone(), O::Int(1), addr("inet", port)],
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
        assert_eq!(
            invoke("nif_cancel", &[socket.clone(), atom("recvfrom"), reference]),
            atom("ok")
        );
        assert_eq!(invoke("nif_close", &[sender]), atom("ok"));
        owner_died(&pid);
        assert!(handle(&socket).is_err());
        set_reactor(None);
    }
}
