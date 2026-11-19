#![allow(clippy::multiple_unsafe_ops_per_block)]

use std::alloc::{Layout, alloc, dealloc, handle_alloc_error};
use std::ffi::{CStr, CString};
use std::mem::{self, align_of, size_of};
use std::os::fd::RawFd;
use std::ptr;
use std::slice;

pub(crate) enum ForkResult {
    Parent(libc::pid_t),
    Child,
}

pub(crate) struct HostEntry {
    pub(crate) unit: usize,
    pub(crate) addresses: Vec<Vec<u8>>,
    pub(crate) names: Vec<Vec<u8>>,
}

pub(crate) struct AiEntry {
    pub(crate) family: libc::c_int,
    pub(crate) address: Option<Vec<u8>>,
    pub(crate) canonname: Option<Vec<u8>>,
}

#[repr(C)]
// Port of the linked `QueItem` request queue in erts/etc/common/inet_gethost.c.
struct QueueNode {
    next: *mut QueueNode,
    req_size: libc::c_int,
    request: [u8; 1],
}

pub(crate) struct Queue {
    first: *mut QueueNode,
    last: *mut QueueNode,
    size: usize,
}

pub(crate) struct QueueItem {
    node: *mut QueueNode,
}

impl QueueItem {
    pub(crate) fn request(&self) -> &[u8] {
        // SAFETY: the detached queue node remains allocated until this item's Drop.
        unsafe {
            slice::from_raw_parts(
                ptr::addr_of!((*self.node).request).cast::<u8>(),
                (*self.node).req_size as usize,
            )
        }
    }
}

impl Drop for QueueItem {
    fn drop(&mut self) {
        // SAFETY: the queue detached this node, so QueueItem is its unique owner.
        let request_size = unsafe { (*self.node).req_size as usize };
        // SAFETY: queue nodes are allocated with the request-sized layout used by push.
        unsafe { dealloc(self.node.cast(), queue_node_layout(request_size)) };
    }
}

impl Queue {
    pub(crate) fn new() -> Self {
        Self {
            first: ptr::null_mut(),
            last: ptr::null_mut(),
            size: 0,
        }
    }

    pub(crate) fn size(&self) -> usize {
        self.size
    }

    pub(crate) fn front(&self) -> Option<&[u8]> {
        if self.first.is_null() {
            return None;
        }
        // SAFETY: first points to a live inline request whose length is stored in req_size.
        let request = unsafe {
            slice::from_raw_parts(
                ptr::addr_of!((*self.first).request).cast::<u8>(),
                (*self.first).req_size as usize,
            )
        };
        Some(request)
    }

    pub(crate) fn push(&mut self, request: &[u8]) {
        let layout = queue_node_layout(request.len());
        // SAFETY: layout matches the inline flexible-array allocation used by this queue node.
        let node = unsafe { alloc(layout).cast::<QueueNode>() };
        if node.is_null() {
            handle_alloc_error(layout);
        }
        // SAFETY: node points to `layout` bytes and the fields fit before the inline request.
        unsafe {
            ptr::addr_of_mut!((*node).next).write(ptr::null_mut());
            ptr::addr_of_mut!((*node).req_size).write(request.len() as libc::c_int);
            ptr::copy_nonoverlapping(
                request.as_ptr(),
                ptr::addr_of_mut!((*node).request).cast::<u8>(),
                request.len(),
            );
        }
        if self.last.is_null() {
            self.first = node;
        } else {
            // SAFETY: `last` is a live queue node, and no alias is used while it is updated.
            unsafe { (*self.last).next = node };
        }
        self.last = node;
        self.size += 1;
    }

    pub(crate) fn pop(&mut self) -> Option<QueueItem> {
        if self.first.is_null() {
            return None;
        }
        let node = self.first;
        // SAFETY: node is the owned first queue node and is removed exactly once here.
        self.first = unsafe { (*node).next };
        if self.first.is_null() {
            self.last = ptr::null_mut();
        }
        self.size -= 1;
        Some(QueueItem { node })
    }

    pub(crate) fn remove_serial(&mut self, serial: i32) -> bool {
        let mut previous: *mut QueueNode = ptr::null_mut();
        let mut current = self.first;
        while !current.is_null() {
            // SAFETY: traversal follows live nodes with requests of at least the packet minimum.
            let matches = unsafe {
                let request = slice::from_raw_parts(
                    ptr::addr_of!((*current).request).cast::<u8>(),
                    (*current).req_size as usize,
                );
                i32::from_be_bytes(request[..4].try_into().unwrap()) == serial
            };
            if matches {
                // SAFETY: `current` is live and `previous` is null or a live node before it.
                let next = unsafe { (*current).next };
                if previous.is_null() {
                    self.first = next;
                } else {
                    // SAFETY: `previous` is a live node owned by this queue.
                    unsafe { (*previous).next = next };
                }
                if self.last == current {
                    self.last = previous;
                }
                // SAFETY: current was unlinked and was allocated with this request-sized layout.
                let req_size = unsafe { (*current).req_size as usize };
                // SAFETY: current was allocated by `push` with this request-sized layout.
                unsafe { dealloc(current.cast(), queue_node_layout(req_size)) };
                self.size -= 1;
                return true;
            }
            previous = current;
            // SAFETY: `current` is live for the duration of this traversal.
            current = unsafe { (*current).next };
        }
        false
    }
}

fn queue_node_layout(request_size: usize) -> Layout {
    let size = size_of::<QueueNode>() - 1 + request_size;
    Layout::from_size_align(size, align_of::<QueueNode>()).unwrap()
}

impl Drop for Queue {
    fn drop(&mut self) {
        while self.pop().is_some() {}
    }
}

#[repr(C)]
struct HostEnt {
    name: *mut libc::c_char,
    aliases: *mut *mut libc::c_char,
    address_type: libc::c_int,
    length: libc::c_int,
    address_list: *mut *mut libc::c_char,
}

unsafe extern "C" {
    #[link_name = "gethostbyname"]
    fn c_gethostbyname(name: *const libc::c_char) -> *mut HostEnt;
    #[link_name = "gethostbyaddr"]
    fn c_gethostbyaddr(
        address: *const libc::c_void,
        length: libc::socklen_t,
        address_type: libc::c_int,
    ) -> *mut HostEnt;
    #[cfg(target_os = "linux")]
    fn __h_errno_location() -> *mut libc::c_int;
    #[cfg(target_os = "macos")]
    static mut h_errno: libc::c_int;
}

pub(crate) fn pipe() -> Result<(RawFd, RawFd), i32> {
    let mut fds = [-1; 2];
    // SAFETY: `fds` points to writable storage for the two descriptors returned by `pipe`.
    let result = unsafe { libc::pipe(fds.as_mut_ptr()) };
    if result == -1 {
        Err(last_errno())
    } else {
        Ok((fds[0], fds[1]))
    }
}

pub(crate) fn fork() -> Result<ForkResult, i32> {
    // SAFETY: this executable is single-threaded, and the child only enters the port worker loop.
    let pid = unsafe { libc::fork() };
    match pid {
        -1 => Err(last_errno()),
        0 => Ok(ForkResult::Child),
        pid => Ok(ForkResult::Parent(pid)),
    }
}

pub(crate) fn close(fd: RawFd) -> Result<(), i32> {
    // SAFETY: closing a raw descriptor does not dereference memory.
    let result = unsafe { libc::close(fd) };
    if result == -1 {
        Err(last_errno())
    } else {
        Ok(())
    }
}

pub(crate) fn dup2(source: RawFd, destination: RawFd) -> Result<(), i32> {
    // SAFETY: `dup2` operates on the process descriptor table.
    let result = unsafe { libc::dup2(source, destination) };
    if result == -1 {
        Err(last_errno())
    } else {
        Ok(())
    }
}

pub(crate) fn read(fd: RawFd, buffer: &mut [u8]) -> Result<usize, i32> {
    // SAFETY: the mutable slice is valid writable storage for `buffer.len()` bytes.
    let result = unsafe { libc::read(fd, buffer.as_mut_ptr().cast(), buffer.len()) };
    if result == -1 {
        Err(last_errno())
    } else {
        Ok(result as usize)
    }
}

pub(crate) fn write(fd: RawFd, buffer: &[u8]) -> Result<usize, i32> {
    // SAFETY: the immutable slice is valid readable storage for `buffer.len()` bytes.
    let result = unsafe { libc::write(fd, buffer.as_ptr().cast(), buffer.len()) };
    if result == -1 {
        Err(last_errno())
    } else {
        Ok(result as usize)
    }
}

pub(crate) fn select_read(fds: &[RawFd], timeout_seconds: Option<u64>) -> Result<Vec<RawFd>, i32> {
    let mut max_fd = 0;
    for fd in fds {
        max_fd = max_fd.max(*fd);
    }
    loop {
        // SAFETY: fd_set is a plain C value initialized before its fields are accessed.
        let mut set = unsafe { mem::zeroed::<libc::fd_set>() };
        // SAFETY: `set` is initialized storage for fd_set.
        unsafe { libc::FD_ZERO(&mut set) };
        for fd in fds {
            // SAFETY: each descriptor is a valid int value and `set` is writable.
            unsafe { libc::FD_SET(*fd, &mut set) };
        }
        let mut timeout = timeout_seconds.map(|seconds| libc::timeval {
            tv_sec: seconds as libc::time_t,
            tv_usec: 0,
        });
        let timeout_ptr = timeout
            .as_mut()
            .map_or(ptr::null_mut(), |value| value as *mut libc::timeval);
        // SAFETY: `set` and optional timeout live for the full call; write sets are null.
        let result = unsafe {
            libc::select(
                max_fd + 1,
                &mut set,
                ptr::null_mut(),
                ptr::null_mut(),
                timeout_ptr,
            )
        };
        if result < 0 {
            let errno = last_errno();
            if errno == libc::EINTR {
                continue;
            }
            return Err(errno);
        }
        if result == 0 {
            return Ok(Vec::new());
        }
        return Ok(fds
            .iter()
            .copied()
            .filter(|fd| {
                // SAFETY: `set` is the read set returned by select and `fd` is a member candidate.
                unsafe { libc::FD_ISSET(*fd, &set) }
            })
            .collect());
    }
}

pub(crate) fn kill(pid: libc::pid_t, signal: libc::c_int) -> Result<(), i32> {
    // SAFETY: `kill` sends a signal to a process id and does not access Rust memory.
    let result = unsafe { libc::kill(pid, signal) };
    if result == -1 {
        Err(last_errno())
    } else {
        Ok(())
    }
}

pub(crate) fn pid() -> libc::pid_t {
    // SAFETY: `getpid` has no pointer arguments or side effects beyond reading the process id.
    unsafe { libc::getpid() }
}

pub(crate) fn last_errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

pub(crate) fn write_stderr(message: &str) {
    let _ = write(2, message.as_bytes());
}

pub(crate) fn init_signals() {
    // SAFETY: signal disposition structures are initialized before being passed to sigaction.
    unsafe {
        let mut child_action = mem::zeroed::<libc::sigaction>();
        libc::sigemptyset(&mut child_action.sa_mask);
        child_action.sa_sigaction = reap_children as *const () as usize;
        child_action.sa_flags = 0;
        libc::sigaction(libc::SIGCHLD, &child_action, ptr::null_mut());

        let mut pipe_action = mem::zeroed::<libc::sigaction>();
        libc::sigemptyset(&mut pipe_action.sa_mask);
        pipe_action.sa_sigaction = libc::SIG_IGN;
        pipe_action.sa_flags = 0;
        libc::sigaction(libc::SIGPIPE, &pipe_action, ptr::null_mut());
    }
}

pub(crate) fn ignore_sigchld() {
    // SAFETY: `signal` updates the SIGCHLD disposition in the child process.
    unsafe {
        libc::signal(libc::SIGCHLD, libc::SIG_IGN);
    }
}

extern "C" fn reap_children(_: libc::c_int) {
    loop {
        // SAFETY: the signal handler uses waitpid's async-signal-safe process reaping operation.
        let result = unsafe { libc::waitpid(-1, ptr::null_mut(), libc::WNOHANG) };
        if result <= 0 {
            break;
        }
    }
}

pub(crate) fn gethostbyname(name: &[u8]) -> Result<HostEntry, i32> {
    let name = CString::new(name).map_err(|_| 1)?;
    // SAFETY: the NUL-terminated name remains live during lookup; returned hostent data is copied.
    let host = unsafe { c_gethostbyname(name.as_ptr()) };
    if host.is_null() {
        return Err(h_errno());
    }
    // SAFETY: a non-null hostent is returned by libc for the duration of this synchronous call.
    unsafe { copy_hostent(host) }
}

pub(crate) fn gethostbyaddr(address: &[u8], family: libc::c_int) -> Result<HostEntry, i32> {
    // SAFETY: address is a byte slice of the family-specific length and hostent data is copied.
    let host = unsafe {
        c_gethostbyaddr(
            address.as_ptr().cast(),
            address.len() as libc::socklen_t,
            family,
        )
    };
    if host.is_null() {
        return Err(h_errno());
    }
    // SAFETY: a non-null hostent is returned by libc for the duration of this synchronous call.
    unsafe { copy_hostent(host) }
}

unsafe fn copy_hostent(host: *mut HostEnt) -> Result<HostEntry, i32> {
    // SAFETY: caller provides a non-null pointer from gethostbyname/gethostbyaddr.
    let host = unsafe { &*host };
    let unit = usize::try_from(host.length).map_err(|_| 3)?;
    let name = if host.name.is_null() {
        Vec::new()
    } else {
        // SAFETY: hostent name is a NUL-terminated field owned by libc for this call.
        unsafe { CStr::from_ptr(host.name) }.to_bytes().to_vec()
    };
    let mut addresses = Vec::new();
    if !host.address_list.is_null() {
        let mut index = 0;
        loop {
            // SAFETY: hostent address_list is a null-terminated pointer array from libc.
            let address = unsafe { *host.address_list.add(index) };
            if address.is_null() {
                break;
            }
            // SAFETY: each non-null address points to `unit` bytes per hostent.h_length.
            addresses.push(unsafe { std::slice::from_raw_parts(address.cast(), unit) }.to_vec());
            index += 1;
        }
    }
    let mut names = vec![name];
    if !host.aliases.is_null() {
        let mut index = 0;
        loop {
            // SAFETY: hostent aliases is a null-terminated pointer array from libc.
            let alias = unsafe { *host.aliases.add(index) };
            if alias.is_null() {
                break;
            }
            // SAFETY: each alias is a NUL-terminated string owned by libc for this call.
            names.push(unsafe { CStr::from_ptr(alias) }.to_bytes().to_vec());
            index += 1;
        }
    }
    Ok(HostEntry {
        unit,
        addresses,
        names,
    })
}

pub(crate) fn getaddrinfo(name: &[u8], family: libc::c_int) -> Result<Vec<AiEntry>, i32> {
    let name = CString::new(name).map_err(|_| libc::EAI_NONAME)?;
    // SAFETY: `hints` is zero-initialized as required by getaddrinfo and all pointers live until freeaddrinfo.
    unsafe {
        let mut hints = mem::zeroed::<libc::addrinfo>();
        hints.ai_flags = libc::AI_CANONNAME;
        hints.ai_socktype = libc::SOCK_STREAM;
        hints.ai_family = family;
        let mut result = ptr::null_mut();
        let code = libc::getaddrinfo(name.as_ptr(), ptr::null(), &hints, &mut result);
        if code != 0 {
            return Err(code);
        }
        let mut entries = Vec::new();
        let mut current = result;
        while !current.is_null() {
            let info = &*current;
            let address = if !info.ai_addr.is_null() {
                match info.ai_family {
                    libc::AF_INET => Some(
                        std::slice::from_raw_parts(
                            (&(*(info.ai_addr.cast::<libc::sockaddr_in>())).sin_addr
                                as *const libc::in_addr)
                                .cast(),
                            4,
                        )
                        .to_vec(),
                    ),
                    libc::AF_INET6 => Some(
                        std::slice::from_raw_parts(
                            (&(*(info.ai_addr.cast::<libc::sockaddr_in6>())).sin6_addr
                                as *const libc::in6_addr)
                                .cast(),
                            16,
                        )
                        .to_vec(),
                    ),
                    _ => None,
                }
            } else {
                None
            };
            let canonname = if info.ai_canonname.is_null() {
                None
            } else {
                Some(CStr::from_ptr(info.ai_canonname).to_bytes().to_vec())
            };
            entries.push(AiEntry {
                family: info.ai_family,
                address,
                canonname,
            });
            current = info.ai_next;
        }
        libc::freeaddrinfo(result);
        Ok(entries)
    }
}

pub(crate) fn getnameinfo(address: &[u8]) -> Result<Vec<u8>, i32> {
    // SAFETY: a zeroed sockaddr_in6 is a valid base for filling the family and address fields.
    let mut socket_address = unsafe { mem::zeroed::<libc::sockaddr_in6>() };
    socket_address.sin6_family = libc::AF_INET6 as libc::sa_family_t;
    socket_address.sin6_addr.s6_addr.copy_from_slice(address);
    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly"
    ))]
    {
        socket_address.sin6_len = mem::size_of::<libc::sockaddr_in6>() as u8;
    }
    let mut name = [0 as libc::c_char; 1025];
    // SAFETY: socket address and output name buffer are valid for the specified lengths.
    let code = unsafe {
        libc::getnameinfo(
            (&socket_address as *const libc::sockaddr_in6).cast(),
            mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
            name.as_mut_ptr(),
            name.len() as libc::socklen_t,
            ptr::null_mut(),
            0,
            libc::NI_NAMEREQD,
        )
    };
    if code != 0 {
        return Err(code);
    }
    // SAFETY: successful getnameinfo writes a NUL-terminated host name in `name`.
    Ok(unsafe { CStr::from_ptr(name.as_ptr()) }.to_bytes().to_vec())
}

fn h_errno() -> i32 {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: glibc returns the calling thread's h_errno slot.
        unsafe { *__h_errno_location() }
    }
    #[cfg(target_os = "macos")]
    {
        // SAFETY: Darwin exposes h_errno as the resolver error slot for this process.
        unsafe { h_errno }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        1
    }
}
