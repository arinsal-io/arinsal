//! Raw libc wrappers used by `inet_drv` / `inet_udp`.
// Port of erts/emulator/drivers/common/inet_drv.c (`sock_setopt`, `sock_getopt`,
// `inet_ctl_open` `HAVE_SETNS`), OTP-29.1.1.

use std::os::fd::RawFd;

pub(crate) fn sock_setopt(
    fd: RawFd,
    proto: i32,
    ty: i32,
    arg: *const u8,
    arg_sz: libc::socklen_t,
) -> i32 {
    // SAFETY: `fd` is a socket the inet driver owns; `arg`/`arg_sz` is the option payload.
    unsafe { libc::setsockopt(fd, proto, ty, arg.cast(), arg_sz) }
}

pub(crate) fn sock_getopt(
    fd: RawFd,
    proto: i32,
    ty: i32,
    arg: *mut u8,
    arg_sz: *mut libc::socklen_t,
) -> i32 {
    // SAFETY: `fd` is a socket the inet driver owns; `arg`/`arg_sz` is the output buffer.
    unsafe { libc::getsockopt(fd, proto, ty, arg.cast(), arg_sz) }
}

/// Port of `setns(2)` in `inet_ctl_open` (`HAVE_SETNS`).
#[cfg(target_os = "linux")]
pub(crate) fn setns(fd: RawFd, nstype: i32) -> i32 {
    // SAFETY: `fd` is an open namespace file; setns(2) only changes this thread.
    unsafe { libc::setns(fd, nstype) }
}

/// Port of `open(path, O_RDONLY)` in `inet_ctl_open` (`HAVE_SETNS`).
#[cfg(target_os = "linux")]
pub(crate) fn open_rdonly(path: &[u8]) -> Result<RawFd, i32> {
    let end = path.iter().position(|&b| b == 0).unwrap_or(path.len());
    let cstr = std::ffi::CString::new(&path[..end]).map_err(|_| libc::EINVAL)?;
    // SAFETY: `cstr` is a NUL-terminated path this function owns.
    let fd = unsafe { libc::open(cstr.as_ptr(), libc::O_RDONLY) };
    if fd < 0 {
        Err(std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO))
    } else {
        Ok(fd)
    }
}

/// Port of `inet_ctl_open`: `while (close(fd) == INVALID_SOCKET && sock_errno() == EINTR);`
#[cfg(target_os = "linux")]
pub(crate) fn close_eintr(fd: RawFd) {
    loop {
        // SAFETY: the caller transfers unique ownership of `fd`; EINTR retries the same close.
        let rc = unsafe { libc::close(fd) };
        if rc == 0 || std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            break;
        }
    }
}
