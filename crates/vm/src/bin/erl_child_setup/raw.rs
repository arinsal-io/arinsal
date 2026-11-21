//! Raw Unix calls of `erl_child_setup.c` and `sys_uds.c`. Unsafe stays here.
// Port of erts/emulator/sys/unix/erl_child_setup.c and sys_uds.c, OTP-29.1.1.

#![allow(clippy::multiple_unsafe_ops_per_block)]

use std::ffi::{CStr, c_char};
use std::io;
use std::os::fd::{BorrowedFd, RawFd};
use std::ptr;

pub(crate) const UDS_FD: RawFd = 3;

pub(crate) enum Fork {
    Parent(libc::pid_t),
    Child,
}

/// `SET_CLOEXEC(fd)`.
// Port of erts/emulator/sys/unix/erl_child_setup.c (`SET_CLOEXEC`), OTP-29.1.1.
pub(crate) fn set_cloexec(fd: RawFd) -> io::Result<()> {
    // SAFETY: `fd` is a live descriptor the caller still owns; F_GETFD only reads its flags.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` is still live; F_SETFD writes the previous flags with FD_CLOEXEC set.
    let rc = unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// The forker UDS on fd 3 for the life of this process.
// Port of erts/emulator/sys/unix/erl_child_setup.c (`main`: `uds_fd = 3`), OTP-29.1.1.
pub(crate) fn uds_fd() -> BorrowedFd<'static> {
    // SAFETY: forker_start dup2'd the socket onto 3; this process keeps it open until _exit.
    unsafe { BorrowedFd::borrow_raw(UDS_FD) }
}

/// `pipe(sigchld_pipe)`.
// Port of erts/emulator/sys/unix/erl_child_setup.c (`main`: `pipe(sigchld_pipe)`), OTP-29.1.1.
pub(crate) fn pipe() -> io::Result<[RawFd; 2]> {
    let mut fds = [0; 2];
    // SAFETY: `pipe` writes two new descriptors into `fds` or returns -1.
    if unsafe { libc::pipe(fds.as_mut_ptr()) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(fds)
}

/// Close `fd`. Errors are ignored the way `erl_child_setup` ignores `close` on extra fds.
pub(crate) fn close(fd: RawFd) {
    // SAFETY: the caller is done with `fd`; a double close is the same -1 erts ignores.
    let _ = unsafe { libc::close(fd) };
}

/// Close every descriptor at and above `min_fd` (`closefrom(4)` / `/dev/fd`).
// Port of erts/emulator/sys/unix/erl_child_setup.c (`main`), OTP-29.1.1.
pub(crate) fn close_from(min_fd: RawFd, max_files: i32) {
    #[cfg(target_os = "linux")]
    {
        let _ = max_files;
        // SAFETY: close_range drops descriptors in `[min_fd, ∞)`; uds_fd 3 is below min_fd.
        let _ = unsafe { libc::close_range(min_fd as libc::c_uint, libc::c_uint::MAX, 0) };
    }
    #[cfg(not(target_os = "linux"))]
    close_from_dev_fd(min_fd, max_files);
}

#[cfg(not(target_os = "linux"))]
fn close_from_dev_fd(min_fd: RawFd, max_files: i32) {
    // SAFETY: opendir("/dev/fd") is the HAVE_CLOSEFROM-missing path of `main`.
    let dir = unsafe { libc::opendir(c"/dev/fd".as_ptr()) };
    if dir.is_null() {
        for fd in min_fd..max_files {
            close(fd);
        }
        return;
    }
    // SAFETY: `dir` is a live DIR* from opendir.
    let dir_fd = unsafe { libc::dirfd(dir) };
    loop {
        // SAFETY: readdir on this DIR* until NULL; errno is not checked, matching erts.
        let entry = unsafe { libc::readdir(dir) };
        if entry.is_null() {
            break;
        }
        // SAFETY: `entry` is a live dirent from readdir; d_name is NUL-terminated.
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
        let Ok(fd) = name.to_bytes().parse::<RawFd>() else {
            continue;
        };
        if fd >= min_fd && fd != dir_fd {
            close(fd);
        }
    }
    // SAFETY: `dir` is still the DIR* from opendir above.
    let _ = unsafe { libc::closedir(dir) };
}

/// `sigaction(signum, handler, flags)`.
fn sigaction(signum: i32, handler: libc::sighandler_t, flags: libc::c_int) -> io::Result<()> {
    // SAFETY: sigaction is a C POD; zeroed is the empty sa_mask erts starts from.
    let mut sa: libc::sigaction = unsafe { std::mem::zeroed() };
    sa.sa_sigaction = handler;
    sa.sa_flags = flags;
    // SAFETY: `sa` is fully initialized; this is the process-wide disposition of `signum`.
    if unsafe { libc::sigaction(signum, &sa, ptr::null_mut()) } == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// `sigaction(SIGCHLD, SA_RESTART|SA_NOCLDSTOP, handle_sigchld)`.
// Port of erts/emulator/sys/unix/erl_child_setup.c (`main`), OTP-29.1.1.
pub(crate) fn install_sigchld(handler: libc::sighandler_t) -> io::Result<()> {
    sigaction(
        libc::SIGCHLD,
        handler,
        libc::SA_RESTART | libc::SA_NOCLDSTOP,
    )
}

/// `sigaction(SIGTERM, SIG_IGN)` or `SIG_DFL`.
// Port of erts/emulator/sys/unix/erl_child_setup.c (`main` / `start_new_child`), OTP-29.1.1.
pub(crate) fn set_sigterm(handler: libc::sighandler_t) -> io::Result<()> {
    sigaction(libc::SIGTERM, handler, 0)
}

/// `sys_sigblock(SIGCHLD)` / `sys_sigrelease(SIGCHLD)`.
// Port of erts/emulator/sys/unix/erl_child_setup.c (`sys_sigblock`/`sys_sigrelease`), OTP-29.1.1.
pub(crate) fn sigchld_block(block: bool) {
    // SAFETY: sigset_t is a C POD; zeroed is an empty mask before sigemptyset.
    let mut mask = unsafe { std::mem::zeroed() };
    // SAFETY: `mask` is a local sigset_t; sigemptyset/sigaddset only write it.
    unsafe {
        libc::sigemptyset(&mut mask);
        libc::sigaddset(&mut mask, libc::SIGCHLD);
        libc::sigprocmask(
            if block {
                libc::SIG_BLOCK
            } else {
                libc::SIG_UNBLOCK
            },
            &mask,
            ptr::null_mut(),
        );
    }
}

/// `fork()`.
// Port of erts/emulator/sys/unix/erl_child_setup.c (`main` Start branch), OTP-29.1.1.
pub(crate) fn fork() -> io::Result<Fork> {
    // SAFETY: the child uses only async-signal-safe calls until exec/_exit.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(io::Error::last_os_error());
    }
    if pid == 0 {
        Ok(Fork::Child)
    } else {
        Ok(Fork::Parent(pid))
    }
}

/// `dup2(src, dst)`.
pub(crate) fn dup2(src: RawFd, dst: RawFd) -> io::Result<()> {
    // SAFETY: both descriptors are live in this process; dup2 replaces `dst`.
    if unsafe { libc::dup2(src, dst) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// `setsid()`.
pub(crate) fn setsid() {
    // SAFETY: POSIX setsid is async-signal-safe and has no pointer arguments.
    let _ = unsafe { libc::setsid() };
}

/// `chdir`.
pub(crate) fn chdir(path: &CStr) -> io::Result<()> {
    // SAFETY: `path` is a NUL-terminated CStr that outlives the call.
    if unsafe { libc::chdir(path.as_ptr()) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// `execve`. Does not return on success.
pub(crate) fn execve(path: &CStr, argv: &[*const c_char], envp: &[*const c_char]) -> io::Error {
    // SAFETY: `path`/`argv`/`envp` are NUL-terminated and live until the image is replaced.
    unsafe {
        libc::execve(path.as_ptr(), argv.as_ptr(), envp.as_ptr());
    }
    io::Error::last_os_error()
}

/// `_exit(status)`.
pub(crate) fn exit_now(status: i32) -> ! {
    // SAFETY: `_exit` terminates this process without running Drop.
    unsafe { libc::_exit(status) }
}

/// `abort()` after printing the slogan, as `ABORT` in `erl_child_setup.c`.
pub(crate) fn abort_now() -> ! {
    // SAFETY: abort dumps core the way `ABORT` does.
    unsafe { libc::abort() }
}

/// `waitpid(-1, ..., WNOHANG)` until it stops reporting children.
// Port of erts/emulator/sys/unix/erl_child_setup.c (`handle_sigchld`), OTP-29.1.1.
pub(crate) fn waitpid_nohang() -> Option<(libc::pid_t, i32)> {
    let mut status = 0;
    // SAFETY: waitpid with WNOHANG is async-signal-safe; `status` is a local int.
    let pid = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) };
    (pid > 0).then_some((pid, status))
}

/// Full-size `read` ignoring EINTR/EAGAIN, as `read_all`.
// Port of erts/emulator/sys/unix/erl_child_setup.c (`read_all`), OTP-29.1.1.
pub(crate) fn read_all(fd: RawFd, buf: &mut [u8]) -> io::Result<()> {
    let mut pos = 0;
    while pos < buf.len() {
        // SAFETY: `buf[pos..]` is writable for the rest of the slice.
        let n = unsafe { libc::read(fd, buf[pos..].as_mut_ptr().cast(), buf.len() - pos) };
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted
                || err.kind() == io::ErrorKind::WouldBlock
                || err.raw_os_error() == Some(libc::EAGAIN)
            {
                continue;
            }
            return Err(err);
        }
        if n == 0 {
            return Err(io::Error::from_raw_os_error(libc::EPIPE));
        }
        pos += n as usize;
    }
    Ok(())
}

/// Full-size `write` ignoring EINTR/EAGAIN, as `write_all`.
// Port of erts/emulator/sys/unix/erl_child_setup.c (`write_all`), OTP-29.1.1.
pub(crate) fn write_all(fd: RawFd, buf: &[u8]) -> io::Result<()> {
    let mut pos = 0;
    while pos < buf.len() {
        // SAFETY: `buf[pos..]` is readable for the rest of the slice.
        let n = unsafe { libc::write(fd, buf[pos..].as_ptr().cast(), buf.len() - pos) };
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted
                || err.kind() == io::ErrorKind::WouldBlock
                || err.raw_os_error() == Some(libc::EAGAIN)
            {
                continue;
            }
            return Err(err);
        }
        if n == 0 {
            return Err(io::Error::from_raw_os_error(libc::EPIPE));
        }
        pos += n as usize;
    }
    Ok(())
}

/// `select` on two read fds. `Ok(None)` is EINTR.
// Port of erts/emulator/sys/unix/erl_child_setup.c (`main` select loop), OTP-29.1.1.
pub(crate) fn select_read(a: RawFd, b: RawFd) -> io::Result<Option<(bool, bool)>> {
    // SAFETY: fd_set is a C POD; FD_ZERO overwrites it before any read.
    let mut set = unsafe { std::mem::zeroed::<libc::fd_set>() };
    // SAFETY: FD_ZERO/FD_SET initialize `set` before select; both fds are live.
    unsafe {
        libc::FD_ZERO(&mut set);
        libc::FD_SET(a, &mut set);
        libc::FD_SET(b, &mut set);
        let max = a.max(b);
        let rc = libc::select(
            max + 1,
            &mut set,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
        );
        if rc < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                return Ok(None);
            }
            return Err(err);
        }
        Ok(Some((libc::FD_ISSET(a, &set), libc::FD_ISSET(b, &set))))
    }
}

/// `sys_uds_read`: `recvmsg` of `buf` plus up to `fds.len()` `SCM_RIGHTS` descriptors.
// Port of erts/emulator/sys/unix/sys_uds.c (`sys_uds_read`), OTP-29.1.1.
pub(crate) fn sys_uds_read(
    fd: RawFd,
    buf: &mut [u8],
    fds: &mut [RawFd],
    flags: libc::c_int,
) -> io::Result<usize> {
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr().cast(),
        iov_len: buf.len(),
    };
    let mut ancillary = [0u8; 256];
    // SAFETY: msghdr is a C POD; the fields we need are filled before recvmsg.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = ancillary.as_mut_ptr().cast();
    msg.msg_controllen = ancillary.len() as _;
    // SAFETY: `msg` references `iov` and `ancillary` for the duration of recvmsg.
    let res = unsafe { libc::recvmsg(fd, &mut msg, flags) };
    if res < 0 {
        let err = io::Error::last_os_error();
        #[cfg(target_os = "macos")]
        if err.raw_os_error() == Some(libc::EMSGSIZE) {
            return Err(io::Error::from_raw_os_error(libc::EMFILE));
        }
        return Err(err);
    }
    if msg.msg_flags & libc::MSG_CTRUNC != 0 {
        return Err(io::Error::from_raw_os_error(libc::EMFILE));
    }
    let mut n = 0;
    // SAFETY: `msg` was filled by recvmsg; CMSG_FIRSTHDR/NXTHDR walk its control buffer.
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
        while !cmsg.is_null() {
            if (*cmsg).cmsg_level == libc::SOL_SOCKET && (*cmsg).cmsg_type == libc::SCM_RIGHTS {
                let data = libc::CMSG_DATA(cmsg);
                let len = (*cmsg).cmsg_len as usize - (data as usize - cmsg as usize);
                let count = len / std::mem::size_of::<RawFd>();
                let received = std::slice::from_raw_parts(data.cast::<RawFd>(), count);
                for &received_fd in received {
                    if n < fds.len() {
                        fds[n] = received_fd;
                        n += 1;
                    } else {
                        libc::abort();
                    }
                }
            }
            cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
        }
    }
    let _ = n;
    Ok(res as usize)
}

/// `isatty(0) && isatty(1)`.
pub(crate) fn stdio_is_tty() -> bool {
    // SAFETY: isatty only inspects the process's stdin/stdout descriptors.
    unsafe { libc::isatty(0) != 0 && libc::isatty(1) != 0 }
}

/// `tcsetattr(0, TCSANOW, mode)` to restore the VM's tty after beam dies.
// Port of erts/emulator/sys/unix/erl_child_setup.c (`main` uds close path), OTP-29.1.1.
pub(crate) fn restore_tty(mode: &libc::termios) {
    // SAFETY: `mode` is the termios the VM wrote at forker_start.
    let _ = unsafe { libc::tcsetattr(0, libc::TCSANOW, mode) };
}

/// Read `sizeof(termios)` from the UDS, as `main` does when stdin/stdout are ttys.
pub(crate) fn read_tty_mode(fd: RawFd) -> io::Result<libc::termios> {
    // SAFETY: termios is a C POD; read_all overwrites every byte from the UDS.
    let mut mode = unsafe { std::mem::zeroed::<libc::termios>() };
    // SAFETY: `mode` is a live local; the slice is its exact byte size.
    let bytes = unsafe {
        std::slice::from_raw_parts_mut(
            (&raw mut mode).cast::<u8>(),
            std::mem::size_of::<libc::termios>(),
        )
    };
    read_all(fd, bytes)?;
    Ok(mode)
}

/// `errno` after a failed libc call.
pub(crate) fn last_errno() -> i32 {
    io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(libc::EIO)
}

/// Restore `errno` after `handle_sigchld`, as erts's `__preverrno`.
// Port of erts/emulator/sys/unix/erl_child_setup.c (`handle_sigchld`), OTP-29.1.1.
pub(crate) fn set_errno(value: i32) {
    // SAFETY: errno is the C library's thread-local; the handler writes back the
    // value saved on entry so select() still sees EINTR instead of waitpid's ECHILD.
    unsafe {
        #[cfg(target_os = "linux")]
        {
            *libc::__errno_location() = value;
        }
        #[cfg(target_os = "macos")]
        {
            *libc::__error() = value;
        }
    }
}
