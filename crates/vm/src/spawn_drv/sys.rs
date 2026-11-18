// Port of erts/emulator/sys/unix/sys_drivers.c (the system calls of the spawn, fd and forker
// drivers), OTP-29.1.1.
//
//! The raw descriptor access of the drivers of sys_drivers.c: the one place their descriptors,
//! held as plain integers like `ErtsSysFdData.fd`, become borrowed handles.

use std::os::fd::{BorrowedFd, RawFd};

fn borrow(fd: RawFd) -> Option<BorrowedFd<'static>> {
    // SAFETY: the drivers own `fd` until they close it (`stop_select` after the last
    // selection is gone, forker_deq once a Start request was sent), always under the port
    // lock that every call made here also holds, so no borrow outlives the descriptor.
    (fd >= 0).then(|| unsafe { BorrowedFd::borrow_raw(fd) })
}

pub(crate) fn read(fd: RawFd, buf: &mut [u8]) -> Result<usize, i32> {
    let fd = borrow(fd).ok_or(libc::EBADF)?;
    rustix::io::read(fd, buf).map_err(|errno| errno.raw_os_error())
}

pub(crate) fn write(fd: RawFd, buf: &[u8]) -> Result<usize, i32> {
    let fd = borrow(fd).ok_or(libc::EBADF)?;
    rustix::io::write(fd, buf).map_err(|errno| errno.raw_os_error())
}

pub(crate) fn writev2(fd: RawFd, first: &[u8], second: &[u8]) -> Result<usize, i32> {
    let fd = borrow(fd).ok_or(libc::EBADF)?;
    rustix::io::writev(
        fd,
        &[std::io::IoSlice::new(first), std::io::IoSlice::new(second)],
    )
    .map_err(|errno| errno.raw_os_error())
}

pub(crate) fn set_blocking(fd: RawFd) {
    if let Some(fd) = borrow(fd)
        && let Ok(flags) = rustix::fs::fcntl_getfl(fd)
    {
        let _ = rustix::fs::fcntl_setfl(fd, flags - rustix::fs::OFlags::NONBLOCK);
    }
}

pub(crate) fn isatty(fd: RawFd) -> bool {
    borrow(fd).is_some_and(rustix::termios::isatty)
}

pub(crate) fn set_nonblocking(fd: RawFd) {
    if let Some(fd) = borrow(fd)
        && let Ok(flags) = rustix::fs::fcntl_getfl(fd)
    {
        let _ = rustix::fs::fcntl_setfl(fd, flags | rustix::fs::OFlags::NONBLOCK);
    }
}

/// Re-open the tty `fd` points at and put the new descriptor in its place
/// (fd_start: `dup2(open(ttyname(ofd)), ofd)`).
pub(crate) fn reopen_tty(fd: RawFd) -> bool {
    let Some(borrowed) = borrow(fd) else {
        return false;
    };
    let Ok(name) = rustix::termios::ttyname(borrowed, Vec::new()) else {
        return false;
    };
    let Ok(tty) = rustix::fs::open(
        name.as_c_str(),
        rustix::fs::OFlags::WRONLY,
        rustix::fs::Mode::empty(),
    ) else {
        return false;
    };
    // SAFETY: `fd` is the caller's descriptor; dup2 replaces it in place and the
    // borrowed handle is forgotten, so nothing closes it here.
    let mut target = std::mem::ManuallyDrop::new(unsafe {
        <std::os::fd::OwnedFd as std::os::fd::FromRawFd>::from_raw_fd(fd)
    });
    rustix::io::dup2(&tty, &mut target).is_ok()
}

/// `TIOCGWINSZ`: columns and rows.
pub(crate) fn window_size(fd: RawFd) -> Option<(u32, u32)> {
    let size = rustix::termios::tcgetwinsize(borrow(fd)?).ok()?;
    Some((u32::from(size.ws_col), u32::from(size.ws_row)))
}

pub(crate) fn close(fd: RawFd) {
    if fd >= 0 {
        // SAFETY: the caller hands over its last use of a descriptor the driver owns
        // (`stop_select`, or forker_deq for the descriptors of a sent Start request).
        drop(unsafe { <std::os::fd::OwnedFd as std::os::fd::FromRawFd>::from_raw_fd(fd) });
    }
}

/// Port of erts/emulator/sys/unix/sys_uds.c (sys_uds_write): send `buf` with the descriptors
/// `fds` as `SCM_RIGHTS` in one message.
pub(crate) fn uds_write(fd: RawFd, buf: &[u8], fds: &[RawFd]) -> Result<usize, i32> {
    use rustix::net::{SendAncillaryBuffer, SendAncillaryMessage, SendFlags, sendmsg};
    let socket = borrow(fd).ok_or(libc::EBADF)?;
    let fds = fds
        .iter()
        .map(|&fd| borrow(fd).ok_or(libc::EBADF))
        .collect::<Result<Vec<_>, _>>()?;
    let mut space = [std::mem::MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(3))];
    let mut ancillary = SendAncillaryBuffer::new(&mut space);
    if !ancillary.push(SendAncillaryMessage::ScmRights(&fds)) {
        return Err(libc::EINVAL);
    }
    sendmsg(
        socket,
        &[std::io::IoSlice::new(buf)],
        &mut ancillary,
        SendFlags::empty(),
    )
    .map_err(|errno| errno.raw_os_error())
}

/// `shutdown(fd, SHUT_WR)`: the peer reads end of file.
pub(crate) fn shutdown_write(fd: RawFd) {
    if let Some(fd) = borrow(fd) {
        let _ = rustix::net::shutdown(fd, rustix::net::Shutdown::Write);
    }
}
