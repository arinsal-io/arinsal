// Port of erts/epmd/src/epmd_srv.c (descriptor operations), OTP-29.1.1.

use std::io;
use std::mem::{MaybeUninit, size_of};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::RawFd;
use std::ptr;
use std::ptr::NonNull;

// erts equivalent: FIFO tail append in epmd_srv.c:node_unreg.
pub fn append_node(
    head: &mut Option<Box<super::Node>>,
    tail: &mut Option<NonNull<super::Node>>,
    mut node: Box<super::Node>,
) {
    node.next = None;
    let new_tail = NonNull::from(node.as_mut());
    if let Some(mut previous) = *tail {
        // SAFETY: tail points to a node still owned by the list rooted at head.
        // Box keeps that allocation stable, and append is the only operation
        // that mutates its next link through this pointer.
        unsafe { previous.as_mut().next = Some(node) };
    } else {
        *head = Some(node);
    }
    *tail = Some(new_tail);
}

pub const FD_SETSIZE: usize = libc::FD_SETSIZE;

pub struct FdSet(libc::fd_set);

impl FdSet {
    // erts equivalent: FD_ZERO in epmd_srv.c:run.
    pub fn empty() -> Self {
        let mut set = MaybeUninit::<libc::fd_set>::uninit();
        // SAFETY: FD_ZERO initializes every field of the fd_set object.
        unsafe { libc::FD_ZERO(set.as_mut_ptr()) };
        // SAFETY: FD_ZERO initialized the complete fd_set value.
        Self(unsafe { set.assume_init() })
    }

    // erts equivalent: FD_SET in epmd_srv.c:select_fd_set.
    pub fn set(&mut self, fd: RawFd) -> io::Result<()> {
        if fd < 0 || fd as usize >= FD_SETSIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "file descriptor does not fit in fd_set",
            ));
        }
        // SAFETY: fd was checked against FD_SETSIZE and the set is initialized.
        unsafe { libc::FD_SET(fd, &mut self.0) };
        Ok(())
    }

    // erts equivalent: FD_CLR in epmd_srv.c:epmd_conn_close.
    pub fn clear(&mut self, fd: RawFd) {
        if fd >= 0 && (fd as usize) < FD_SETSIZE {
            // SAFETY: fd is in range and the set is initialized.
            unsafe { libc::FD_CLR(fd, &mut self.0) };
        }
    }

    // erts equivalent: FD_ISSET in epmd_srv.c:run.
    pub fn contains(&self, fd: RawFd) -> bool {
        fd >= 0
            && (fd as usize) < FD_SETSIZE
            // SAFETY: fd is in range and the set is initialized.
            && unsafe { libc::FD_ISSET(fd, &self.0) }
    }

    // erts equivalent: local fd_set copy in epmd_srv.c:run select_again.
    pub fn duplicate(&self) -> Self {
        let mut duplicate = Self::empty();
        // SAFETY: both fd_set values are initialized and non-overlapping.
        unsafe { ptr::copy_nonoverlapping(&self.0, &mut duplicate.0, 1) };
        duplicate
    }
}

// erts equivalent: select() in epmd_srv.c:run.
pub fn select(max_fd: i32, set: &mut FdSet, timeout_seconds: i64) -> io::Result<i32> {
    let mut timeout = libc::timeval {
        tv_sec: timeout_seconds as libc::time_t,
        tv_usec: 0,
    };
    // SAFETY: set is initialized; the remaining fd_set pointers are null as in
    // epmd_srv.c, and timeout points to a live timeval for the duration of select.
    let result = unsafe {
        libc::select(
            max_fd,
            &mut set.0,
            ptr::null_mut(),
            ptr::null_mut(),
            &mut timeout,
        )
    };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(result)
    }
}

// erts equivalent: socket, setsockopt, fcntl, bind, and listen in epmd_srv.c:run.
pub struct ListenerError {
    pub phase: ListenerPhase,
    pub error: io::Error,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ListenerPhase {
    Socket,
    Setup,
    Bind,
    Listen,
}

pub fn listener(address: SocketAddr) -> Result<RawFd, ListenerError> {
    let (domain, sockaddr, length) = sockaddr(address);
    // SAFETY: socket receives a supported address family and constant stream
    // socket arguments; its returned descriptor is checked before use.
    let fd = unsafe { libc::socket(domain, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        return Err(ListenerError {
            phase: ListenerPhase::Socket,
            error: io::Error::last_os_error(),
        });
    }

    let result: Result<(), ListenerError> = (|| {
        if address.is_ipv6() {
            let enabled: libc::c_int = 1;
            // SAFETY: fd is a live socket and enabled has the size required by
            // IPV6_V6ONLY.
            if unsafe {
                libc::setsockopt(
                    fd,
                    libc::IPPROTO_IPV6,
                    libc::IPV6_V6ONLY,
                    (&enabled as *const libc::c_int).cast(),
                    size_of::<libc::c_int>() as libc::socklen_t,
                )
            } < 0
            {
                return Err(ListenerError {
                    phase: ListenerPhase::Setup,
                    error: io::Error::last_os_error(),
                });
            }
        }

        let enabled: libc::c_int = 1;
        // SAFETY: fd is a live socket and enabled has the size required by
        // SO_REUSEADDR.
        if unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_REUSEADDR,
                (&enabled as *const libc::c_int).cast(),
                size_of::<libc::c_int>() as libc::socklen_t,
            )
        } < 0
        {
            return Err(ListenerError {
                phase: ListenerPhase::Setup,
                error: io::Error::last_os_error(),
            });
        }

        // SAFETY: fd is a live socket. F_GETFL takes no third argument.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 {
            return Err(ListenerError {
                phase: ListenerPhase::Setup,
                error: io::Error::last_os_error(),
            });
        }
        // SAFETY: fd is a live socket and flags are the value returned by F_GETFL.
        if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            return Err(ListenerError {
                phase: ListenerPhase::Setup,
                error: io::Error::last_os_error(),
            });
        }

        // SAFETY: sockaddr points to an initialized family-specific address and
        // length matches that address type.
        if unsafe {
            libc::bind(
                fd,
                (&sockaddr as *const libc::sockaddr_storage).cast(),
                length,
            )
        } < 0
        {
            return Err(ListenerError {
                phase: ListenerPhase::Bind,
                error: io::Error::last_os_error(),
            });
        }
        // SAFETY: fd is bound and may be marked listening with SOMAXCONN.
        if unsafe { libc::listen(fd, libc::SOMAXCONN) } < 0 {
            return Err(ListenerError {
                phase: ListenerPhase::Listen,
                error: io::Error::last_os_error(),
            });
        }
        Ok(())
    })();

    match result {
        Ok(()) => Ok(fd),
        Err(error) => {
            close(fd);
            Err(error)
        }
    }
}

// erts equivalent: accept in epmd_srv.c:do_accept.
pub fn accept(fd: RawFd) -> io::Result<RawFd> {
    let mut address = MaybeUninit::<libc::sockaddr_storage>::zeroed();
    let mut length = size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    // SAFETY: address has sockaddr_storage size and length is its writable size.
    let accepted = unsafe {
        libc::accept(
            fd,
            address.as_mut_ptr().cast::<libc::sockaddr>(),
            &mut length,
        )
    };
    if accepted < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(accepted)
    }
}

// erts equivalent: locality check in epmd_srv.c:conn_local_peer_check.
pub fn is_local_peer(fd: RawFd) -> bool {
    let Some(peer) = socket_address(fd, true) else {
        return false;
    };
    if peer.ip().is_loopback() {
        return true;
    }
    socket_address(fd, false).is_some_and(|local| peer.ip() == local.ip())
}

// erts equivalent: getpeername/getsockname in epmd_srv.c:conn_local_peer_check.
fn socket_address(fd: RawFd, peer: bool) -> Option<SocketAddr> {
    let mut address = MaybeUninit::<libc::sockaddr_storage>::zeroed();
    let mut length = size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    let result = if peer {
        // SAFETY: address has sockaddr_storage size and length is its writable size.
        unsafe {
            libc::getpeername(
                fd,
                address.as_mut_ptr().cast::<libc::sockaddr>(),
                &mut length,
            )
        }
    } else {
        // SAFETY: address has sockaddr_storage size and length is its writable size.
        unsafe {
            libc::getsockname(
                fd,
                address.as_mut_ptr().cast::<libc::sockaddr>(),
                &mut length,
            )
        }
    };
    if result != 0 || length as usize > size_of::<libc::sockaddr_storage>() {
        return None;
    }
    // SAFETY: getpeername/getsockname succeeded and initialized the address
    // bytes selected by its reported family and length.
    let storage = unsafe { address.assume_init() };
    match storage.ss_family as libc::c_int {
        libc::AF_INET if length as usize >= size_of::<libc::sockaddr_in>() => {
            // SAFETY: ss_family is AF_INET and the reported length fits sockaddr_in.
            let address = unsafe {
                &*((&storage as *const libc::sockaddr_storage).cast::<libc::sockaddr_in>())
            };
            Some(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::from(address.sin_addr.s_addr.to_ne_bytes())),
                u16::from_be(address.sin_port),
            ))
        }
        libc::AF_INET6 if length as usize >= size_of::<libc::sockaddr_in6>() => {
            // SAFETY: ss_family is AF_INET6 and the reported length fits sockaddr_in6.
            let address = unsafe {
                &*((&storage as *const libc::sockaddr_storage).cast::<libc::sockaddr_in6>())
            };
            Some(SocketAddr::new(
                IpAddr::V6(Ipv6Addr::from(address.sin6_addr.s6_addr)),
                u16::from_be(address.sin6_port),
            ))
        }
        _ => None,
    }
}

// erts equivalent: socket/connect in epmd_cli.c:conn_to_epmd.
pub fn connect(address: SocketAddr) -> io::Result<RawFd> {
    let (domain, sockaddr, length) = sockaddr(address);
    // SAFETY: socket receives a supported family and constant stream socket
    // arguments; its returned descriptor is checked before use.
    let fd = unsafe { libc::socket(domain, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: sockaddr points to an initialized family-specific address and
    // length matches that address type.
    if unsafe {
        libc::connect(
            fd,
            (&sockaddr as *const libc::sockaddr_storage).cast(),
            length,
        )
    } < 0
    {
        let error = io::Error::last_os_error();
        close(fd);
        Err(error)
    } else {
        Ok(fd)
    }
}

// erts equivalent: IPv6 then IPv4 loopback in epmd_cli.c:conn_to_epmd.
pub fn connect_loopback(port: u16) -> io::Result<RawFd> {
    if let Ok(fd) = connect(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), port)) {
        return Ok(fd);
    }
    connect(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port))
}

// erts equivalent: read in epmd_srv.c:do_read and epmd_cli.c:read_fill.
pub fn read(fd: RawFd, buffer: &mut [u8]) -> io::Result<usize> {
    // SAFETY: buffer is writable for its length and remains live during read.
    let result = unsafe { libc::read(fd, buffer.as_mut_ptr().cast(), buffer.len()) };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(result as usize)
    }
}

// erts equivalent: write in epmd_srv.c:reply and epmd_cli.c client routines.
pub fn write(fd: RawFd, buffer: &[u8]) -> io::Result<usize> {
    // SAFETY: buffer is readable for its length and remains live during write.
    let result = unsafe { libc::write(fd, buffer.as_ptr().cast(), buffer.len()) };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(result as usize)
    }
}

// erts equivalent: close in epmd_srv.c:epmd_conn_close and epmd_cleanup_exit.
pub fn close(fd: RawFd) {
    // SAFETY: close is called only for descriptors owned by epmd.
    unsafe { libc::close(fd) };
}

// erts equivalent: time() in epmd_srv.c:current_time.
pub fn current_time() -> u32 {
    // SAFETY: time accepts a null pointer when the return value is sufficient.
    unsafe { libc::time(ptr::null_mut()) as u32 }
}

// erts equivalent: ctime() in epmd.c:dbg_gen_printf.
pub fn ctime(timestamp: u32) -> String {
    let mut output = [0 as libc::c_char; 32];
    let value = timestamp as libc::time_t;
    // SAFETY: output has sufficient capacity for the fixed ctime_r format.
    let result = unsafe { libc::ctime_r(&value, output.as_mut_ptr()) };
    if result.is_null() {
        return "unknown time".to_owned();
    }
    // SAFETY: ctime_r returned output, which is NUL terminated on success.
    unsafe { std::ffi::CStr::from_ptr(output.as_ptr()) }
        .to_string_lossy()
        .trim_end_matches('\n')
        .to_owned()
}

// erts equivalent: sysconf and FD_SETSIZE cap in epmd.c:main.
pub fn max_open_files() -> i32 {
    // SAFETY: sysconf is queried with the platform's _SC_OPEN_MAX constant.
    let value = unsafe { libc::sysconf(libc::_SC_OPEN_MAX) };
    if value <= 0 {
        2048.min(FD_SETSIZE) as i32
    } else {
        (value as usize).min(FD_SETSIZE) as i32
    }
}

// erts equivalent: signal(SIGPIPE, SIG_IGN) in epmd_srv.c:run.
pub fn ignore_sigpipe() {
    // SAFETY: SIGPIPE is assigned SIG_IGN, the same process-wide action used
    // by epmd_srv.c before its socket write loop.
    unsafe { libc::signal(libc::SIGPIPE, libc::SIG_IGN) };
}

// erts equivalent: sleep in epmd_srv.c:run and reply.
pub fn sleep_seconds(seconds: u32) {
    // SAFETY: sleep has no pointer arguments and is safe for any u32 duration.
    unsafe { libc::sleep(seconds) };
}

// erts equivalent: syslog(LOG_ERR, "epmd: %s", ...) in epmd.c:dbg_gen_printf.
pub fn syslog(message: &str) {
    let format = c"epmd: %s";
    let mut bytes = message.as_bytes().to_vec();
    if let Some(nul) = bytes.iter().position(|byte| *byte == 0) {
        bytes.truncate(nul);
    }
    let message = std::ffi::CString::new(bytes).expect("NUL bytes were removed");
    // SAFETY: both format strings are valid C strings and remain alive during
    // the variadic syslog call; %s consumes one C string argument.
    unsafe { libc::syslog(libc::LOG_ERR, format.as_ptr(), message.as_ptr()) };
}

// erts equivalent: closelog in epmd.c:run_daemon.
pub fn close_syslog() {
    // SAFETY: closelog has no pointer arguments and is safe after daemon fd cleanup.
    unsafe { libc::closelog() };
}

// erts equivalent: sd_listen_fds(0) in epmd_srv.c:run.
pub fn systemd_fds() -> io::Result<usize> {
    let Some(pid) = std::env::var_os("LISTEN_PID") else {
        return Ok(0);
    };
    let pid = pid
        .to_string_lossy()
        .parse::<libc::pid_t>()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid LISTEN_PID value"))?;
    if pid != std::process::id() as libc::pid_t {
        return Ok(0);
    }
    let Some(count) = std::env::var_os("LISTEN_FDS") else {
        return Ok(0);
    };
    let count = count
        .to_string_lossy()
        .parse::<usize>()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid LISTEN_FDS value"))?;
    if count > 16 {
        return Ok(count);
    }
    for fd in 3..(3 + count as RawFd) {
        let mut socket_type: libc::c_int = 0;
        let mut length = size_of::<libc::c_int>() as libc::socklen_t;
        // SAFETY: getsockopt writes one c_int into socket_type for a live
        // systemd-passed descriptor; an invalid descriptor returns an error.
        if unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_TYPE,
                (&mut socket_type as *mut libc::c_int).cast(),
                &mut length,
            )
        } < 0
        {
            return Err(io::Error::last_os_error());
        }
        if socket_type != libc::SOCK_STREAM {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "systemd passed a non-stream socket",
            ));
        }
    }
    Ok(count)
}

// erts equivalent: sd_notifyf in epmd_srv.c:run and epmd_cleanup_exit.
pub fn systemd_notify(message: &str) {
    let Some(path) = std::env::var_os("NOTIFY_SOCKET") else {
        return;
    };
    let path = path.to_string_lossy();
    #[cfg(target_os = "linux")]
    {
        let Some(name) = path.strip_prefix('@') else {
            use std::os::unix::net::UnixDatagram;
            if let Ok(socket) = UnixDatagram::unbound() {
                let _ = socket.send_to(message.as_bytes(), path.as_ref());
            }
            return;
        };
        let name = name.as_bytes();
        let offset = std::mem::offset_of!(libc::sockaddr_un, sun_path);
        if name.len() + 1 > size_of::<libc::sockaddr_un>().saturating_sub(offset) {
            return;
        }
        // SAFETY: socket is created as an AF_UNIX datagram socket and checked.
        let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_DGRAM, 0) };
        if fd < 0 {
            return;
        }
        let mut address = MaybeUninit::<libc::sockaddr_un>::zeroed();
        // SAFETY: zeroed initializes the complete sockaddr_un value.
        let address = unsafe { address.assume_init_mut() };
        address.sun_family = libc::AF_UNIX as libc::sa_family_t;
        address.sun_path[0] = 0;
        let sun_path = address.sun_path.as_mut_ptr();
        // SAFETY: sun_path has space for the leading abstract NUL and name.
        let abstract_path = unsafe { sun_path.add(1) };
        // SAFETY: name fits in sun_path after the abstract leading NUL.
        unsafe { ptr::copy_nonoverlapping(name.as_ptr(), abstract_path.cast(), name.len()) };
        // SAFETY: sockaddr_un contains the initialized abstract address and
        // message is readable for its length during sendto.
        unsafe {
            libc::sendto(
                fd,
                message.as_ptr().cast(),
                message.len(),
                0,
                (address as *const libc::sockaddr_un).cast::<libc::sockaddr>(),
                (offset + 1 + name.len()) as libc::socklen_t,
            );
        }
        close(fd);
    }
    #[cfg(not(target_os = "linux"))]
    {
        use std::os::unix::net::UnixDatagram;
        if let Ok(socket) = UnixDatagram::unbound() {
            let _ = socket.send_to(message.as_bytes(), path.as_ref());
        }
    }
}

// erts equivalent: double-fork and descriptor setup in epmd.c:run_daemon.
pub fn daemonize(max_conn: i32) -> io::Result<bool> {
    // SAFETY: fork is called during single-threaded process startup, before
    // the epmd select loop or any worker threads exist.
    let first = unsafe { libc::fork() };
    if first < 0 {
        return Err(io::Error::last_os_error());
    }
    if first > 0 {
        return Ok(true);
    }

    // SAFETY: setsid has no pointer arguments and runs in the first child.
    if unsafe { libc::setsid() } < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: SIGHUP is ignored as in epmd.c:run_daemon.
    unsafe { libc::signal(libc::SIGHUP, libc::SIG_IGN) };

    // SAFETY: this second fork is also before any runtime threads exist.
    let second = unsafe { libc::fork() };
    if second < 0 {
        return Err(io::Error::last_os_error());
    }
    if second > 0 {
        // SAFETY: the intermediate daemon parent must terminate without
        // flushing inherited stdio buffers, matching exit from epmd.c.
        unsafe { libc::_exit(0) };
    }

    let root = c"/";
    // SAFETY: root is a NUL-terminated static path.
    if unsafe { libc::chdir(root.as_ptr()) } < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: umask has no pointer arguments and zero matches epmd.c.
    unsafe { libc::umask(0) };
    for fd in 0..max_conn {
        close(fd);
    }
    close_syslog();
    let null = c"/dev/null";
    // SAFETY: null is a NUL-terminated static path and the descriptors were closed.
    unsafe { libc::open(null.as_ptr(), libc::O_RDONLY) };
    // SAFETY: null is a NUL-terminated static path and the descriptors were closed.
    unsafe { libc::open(null.as_ptr(), libc::O_WRONLY) };
    // SAFETY: null is a NUL-terminated static path and the descriptors were closed.
    unsafe { libc::open(null.as_ptr(), libc::O_WRONLY) };
    Ok(false)
}

// erts equivalent: SET_ADDR/SET_ADDR6 in epmd_srv.c:run.
fn sockaddr(address: SocketAddr) -> (libc::c_int, libc::sockaddr_storage, libc::socklen_t) {
    let mut storage = MaybeUninit::<libc::sockaddr_storage>::zeroed();
    let length = match address {
        SocketAddr::V4(address) => {
            let value = libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: address.port().to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes(address.ip().octets()),
                },
                sin_zero: [0; 8],
            };
            // SAFETY: sockaddr_in fits in sockaddr_storage and the destination
            // was zero-initialized with suitable alignment.
            unsafe { ptr::write(storage.as_mut_ptr().cast::<libc::sockaddr_in>(), value) };
            size_of::<libc::sockaddr_in>()
        }
        SocketAddr::V6(address) => {
            let value = libc::sockaddr_in6 {
                sin6_family: libc::AF_INET6 as libc::sa_family_t,
                sin6_port: address.port().to_be(),
                sin6_flowinfo: address.flowinfo(),
                sin6_addr: libc::in6_addr {
                    s6_addr: address.ip().octets(),
                },
                sin6_scope_id: address.scope_id(),
            };
            // SAFETY: sockaddr_in6 fits in sockaddr_storage and the destination
            // was zero-initialized with suitable alignment.
            unsafe { ptr::write(storage.as_mut_ptr().cast::<libc::sockaddr_in6>(), value) };
            size_of::<libc::sockaddr_in6>()
        }
    };
    // SAFETY: either sockaddr_in or sockaddr_in6 was initialized above and
    // sockaddr_storage was zeroed before writing its family-specific prefix.
    (
        if address.is_ipv4() {
            libc::AF_INET
        } else {
            libc::AF_INET6
        },
        unsafe { storage.assume_init() },
        length as libc::socklen_t,
    )
}
