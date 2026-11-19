// Port of Unix calls used by erts/etc/common/heart.c and erts/etc/unix/run_erl.c,
// erts/etc/unix/to_erl.c, OTP-29.1.1. Unsafe stays at this boundary.

use std::ffi::{CStr, CString};
use std::io;
use std::os::fd::RawFd;

pub fn read(fd: RawFd, buffer: &mut [u8]) -> io::Result<usize> {
    // SAFETY: The slice is writable for `buffer.len()` bytes for the duration of the call.
    let result = unsafe { libc::read(fd, buffer.as_mut_ptr().cast(), buffer.len()) };
    cvt_size(result)
}

pub fn write(fd: RawFd, buffer: &[u8]) -> io::Result<usize> {
    // SAFETY: The slice is readable for `buffer.len()` bytes for the duration of the call.
    let result = unsafe { libc::write(fd, buffer.as_ptr().cast(), buffer.len()) };
    cvt_size(result)
}

fn cvt_size(result: libc::ssize_t) -> io::Result<usize> {
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(result as usize)
    }
}

pub fn select(
    readers: &[RawFd],
    writers: &[RawFd],
    timeout_seconds: Option<i64>,
) -> io::Result<(usize, Vec<RawFd>, Vec<RawFd>)> {
    let mut read_set = std::mem::MaybeUninit::<libc::fd_set>::uninit();
    let mut write_set = std::mem::MaybeUninit::<libc::fd_set>::uninit();
    // SAFETY: FD_ZERO initializes the complete fd_set before it is read.
    unsafe { libc::FD_ZERO(read_set.as_mut_ptr()) };
    // SAFETY: FD_ZERO initializes the complete fd_set before it is read.
    unsafe { libc::FD_ZERO(write_set.as_mut_ptr()) };
    // SAFETY: FD_ZERO initialized both complete fd_sets above.
    let mut read_set = unsafe { read_set.assume_init() };
    // SAFETY: FD_ZERO initialized both complete fd_sets above.
    let mut write_set = unsafe { write_set.assume_init() };
    for fd in readers {
        // SAFETY: `read_set` is initialized and `fd` is a descriptor being selected.
        unsafe { libc::FD_SET(*fd, &mut read_set) };
    }
    for fd in writers {
        // SAFETY: `write_set` is initialized and `fd` is a descriptor being selected.
        unsafe { libc::FD_SET(*fd, &mut write_set) };
    }
    let max_fd = readers.iter().chain(writers).copied().max().unwrap_or(-1);
    let mut timeout = timeout_seconds.map(|seconds| libc::timeval {
        tv_sec: seconds as libc::time_t,
        tv_usec: 0,
    });
    let timeout_ptr = timeout
        .as_mut()
        .map_or(std::ptr::null_mut(), |value| value as *mut libc::timeval);
    // SAFETY: The fd sets and optional timeval remain live for the synchronous select call.
    let ready = unsafe {
        libc::select(
            max_fd + 1,
            &mut read_set,
            &mut write_set,
            std::ptr::null_mut(),
            timeout_ptr,
        )
    };
    if ready < 0 {
        return Err(io::Error::last_os_error());
    }
    let readable = readers
        .iter()
        .copied()
        .filter(|fd| {
            // SAFETY: `read_set` was initialized and returned by select.
            unsafe { libc::FD_ISSET(*fd, &read_set) }
        })
        .collect();
    let writable = writers
        .iter()
        .copied()
        .filter(|fd| {
            // SAFETY: `write_set` was initialized and returned by select.
            unsafe { libc::FD_ISSET(*fd, &write_set) }
        })
        .collect();
    Ok((ready as usize, readable, writable))
}

pub fn now() -> libc::time_t {
    // SAFETY: `time` accepts a null pointer when only its return value is needed.
    unsafe { libc::time(std::ptr::null_mut()) }
}

// Port of erts/etc/common/heart.c (sys_gethrtime), OTP-29.1.1.
pub fn monotonic_seconds() -> io::Result<libc::time_t> {
    let mut value = std::mem::MaybeUninit::<libc::timespec>::uninit();
    // SAFETY: `value` is writable and CLOCK_MONOTONIC is a supported scalar clock id.
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, value.as_mut_ptr()) } < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: clock_gettime initialized the timespec when it returned zero.
    Ok(unsafe { value.assume_init() }.tv_sec)
}

pub fn getpid() -> libc::pid_t {
    // SAFETY: `getpid` has no pointer arguments.
    unsafe { libc::getpid() }
}

pub fn strerror(error: libc::c_int) -> Vec<u8> {
    // SAFETY: strerror returns a NUL-terminated string for the scalar error number.
    let message = unsafe { libc::strerror(error) };
    if message.is_null() {
        Vec::new()
    } else {
        // SAFETY: strerror returned a valid NUL-terminated error message.
        unsafe { CStr::from_ptr(message) }.to_bytes().to_vec()
    }
}

pub fn open_max() -> libc::c_int {
    // SAFETY: sysconf consumes a scalar selector.
    unsafe { libc::sysconf(libc::_SC_OPEN_MAX) as libc::c_int }
}

pub fn ctime(value: libc::time_t) -> String {
    let mut buffer = [0_i8; 32];
    // SAFETY: `buffer` is writable and `value` is a valid time_t input.
    let result = unsafe { libc::ctime_r(&value, buffer.as_mut_ptr()) };
    if result.is_null() {
        String::new()
    } else {
        // SAFETY: ctime_r wrote a NUL-terminated string into `buffer`.
        unsafe { CStr::from_ptr(buffer.as_ptr()) }
            .to_string_lossy()
            .trim_end_matches('\n')
            .to_owned()
    }
}

pub fn sleep(seconds: u32) {
    // SAFETY: `sleep` has no pointer arguments and is safe for any duration.
    unsafe { libc::sleep(seconds) };
}

pub fn kill(pid: libc::pid_t, signal: libc::c_int) -> io::Result<()> {
    // SAFETY: `kill` consumes only scalar identifiers.
    if unsafe { libc::kill(pid, signal) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

pub fn kill_with_errno(pid: libc::pid_t, signal: libc::c_int) -> (bool, libc::c_int) {
    // SAFETY: `kill` consumes only scalar identifiers.
    let result = unsafe { libc::kill(pid, signal) };
    let error_number = io::Error::last_os_error().raw_os_error().unwrap_or(0);
    (result == 0, error_number)
}

pub fn system(command: &CStr) -> libc::c_int {
    // SAFETY: `command` is NUL-terminated and remains live for the synchronous call.
    unsafe { libc::system(command.as_ptr()) }
}

pub fn open(path: &CStr, flags: libc::c_int, mode: libc::mode_t) -> io::Result<RawFd> {
    // SAFETY: `path` is NUL-terminated and valid for the synchronous call.
    let fd = unsafe { libc::open(path.as_ptr(), flags, mode) };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(fd)
    }
}

pub fn close(fd: RawFd) {
    // SAFETY: The caller owns or otherwise manages this descriptor.
    unsafe { libc::close(fd) };
}

pub fn mkfifo(path: &CStr, mode: libc::mode_t) -> io::Result<()> {
    // SAFETY: `path` is NUL-terminated for the call.
    if unsafe { libc::mkfifo(path.as_ptr(), mode) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

pub fn unlink(path: &CStr) {
    // SAFETY: `path` is NUL-terminated for the call.
    unsafe { libc::unlink(path.as_ptr()) };
}

pub fn lseek_end(fd: RawFd) -> io::Result<libc::off_t> {
    // SAFETY: `lseek` consumes only a descriptor and scalar offset/whence.
    let result = unsafe { libc::lseek(fd, 0, libc::SEEK_END) };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(result)
    }
}

pub fn fsync(fd: RawFd) -> io::Result<()> {
    // SAFETY: `fsync` consumes only a descriptor.
    if unsafe { libc::fsync(fd) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

pub fn fork() -> io::Result<libc::pid_t> {
    // SAFETY: The caller performs only async-signal-safe operations in the child before exec.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(pid)
    }
}

pub fn setsid() -> io::Result<()> {
    // SAFETY: `setsid` has no pointer arguments.
    if unsafe { libc::setsid() } < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub fn dup(fd: RawFd) -> io::Result<RawFd> {
    // SAFETY: `dup` consumes only a descriptor.
    let result = unsafe { libc::dup(fd) };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(result)
    }
}

pub fn dup2(old: RawFd, new: RawFd) -> io::Result<()> {
    // SAFETY: `dup2` consumes only descriptors.
    if unsafe { libc::dup2(old, new) } < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub fn waitpid_nohang(pid: libc::pid_t) -> io::Result<bool> {
    let mut status = 0;
    // SAFETY: `status` points to a writable integer for the duration of waitpid.
    let result = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(result == pid)
    }
}

pub fn alarm(seconds: u32) {
    // SAFETY: `alarm` consumes only a scalar duration.
    unsafe { libc::alarm(seconds) };
}

pub fn raise(signal: libc::c_int) {
    // SAFETY: `raise` targets the current process with a scalar signal number.
    unsafe { libc::raise(signal) };
}

pub fn openlog(identifier: &[u8]) {
    let Ok(identifier) = CString::new(identifier) else {
        return;
    };
    // SAFETY: The identifier is NUL-terminated and remains live for openlog to copy.
    unsafe {
        libc::openlog(
            identifier.as_ptr(),
            libc::LOG_PID | libc::LOG_CONS | libc::LOG_NOWAIT,
            libc::LOG_USER,
        )
    };
}

pub fn closelog() {
    // SAFETY: closelog has no arguments and closes the current process's syslog connection.
    unsafe { libc::closelog() };
}

pub fn syslog(priority: libc::c_int, message: &[u8]) {
    let Ok(message) = CString::new(message) else {
        return;
    };
    // SAFETY: The fixed format has one string conversion and `message` is NUL-terminated.
    unsafe { libc::syslog(priority, c"%s".as_ptr(), message.as_ptr()) };
}

pub fn set_signal_handler(
    signal: libc::c_int,
    handler: extern "C" fn(libc::c_int),
    flags: libc::c_int,
) -> io::Result<()> {
    // SAFETY: A zeroed sigaction is valid before sigemptyset initializes its mask.
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    action.sa_sigaction = handler as usize;
    action.sa_flags = flags;
    // SAFETY: `action` is initialized and both pointers remain valid for sigaction.
    unsafe { libc::sigemptyset(&mut action.sa_mask) };
    // SAFETY: `action` is a live sigaction; old action is not requested.
    if unsafe { libc::sigaction(signal, &action, std::ptr::null_mut()) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

pub fn ignore_signal(signal: libc::c_int) -> io::Result<()> {
    // SAFETY: `signal` is a valid signal number and SIG_IGN is the documented disposition.
    if unsafe { libc::signal(signal, libc::SIG_IGN) } == libc::SIG_ERR {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub fn set_signal_ignored(signal: libc::c_int, flags: libc::c_int) -> io::Result<()> {
    // SAFETY: A zeroed sigaction is valid before sigemptyset initializes its mask.
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    action.sa_sigaction = libc::SIG_IGN;
    action.sa_flags = flags;
    // SAFETY: `action` is initialized and `sa_mask` is writable.
    unsafe { libc::sigemptyset(&mut action.sa_mask) };
    // SAFETY: `action` is a live sigaction; old action is not requested.
    if unsafe { libc::sigaction(signal, &action, std::ptr::null_mut()) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

pub fn signal(signal: libc::c_int, handler: extern "C" fn(libc::c_int)) -> bool {
    // SAFETY: The handler has the C signal-handler ABI and remains loaded for process lifetime.
    unsafe { libc::signal(signal, handler as usize) != libc::SIG_ERR }
}

// Port of erts/etc/unix/run_erl.c (open_pty_master), OTP-29.1.1.
pub fn open_pty_master() -> io::Result<(RawFd, CString, RawFd)> {
    // SAFETY: `posix_openpt` consumes flags only.
    let master = unsafe { libc::posix_openpt(libc::O_RDWR) };
    if master >= 0 {
        // SAFETY: `ptsname` returns storage owned by libc for the opened PTY master.
        let name = unsafe { libc::ptsname(master) };
        if !name.is_null() {
            // SAFETY: grantpt operates on the newly opened PTY master.
            if unsafe { libc::grantpt(master) } == 0 {
                // SAFETY: unlockpt operates on the newly opened PTY master.
                if unsafe { libc::unlockpt(master) } == 0 {
                    // SAFETY: ptsname returned a NUL-terminated slave name.
                    let slave = unsafe { CStr::from_ptr(name) }.to_owned();
                    return Ok((master, slave, -1));
                }
            }
        }
        close(master);
    }

    openpty_fallback()
}

#[cfg(target_vendor = "apple")]
fn openpty_fallback() -> io::Result<(RawFd, CString, RawFd)> {
    let mut master = -1;
    let mut slave_fd = -1;
    let mut name = vec![0_i8; 1024];
    // SAFETY: all output pointers remain writable for the call; optional termios/winsize are null.
    if unsafe {
        libc::openpty(
            &mut master,
            &mut slave_fd,
            name.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: openpty wrote a NUL-terminated slave name into `name`.
    let slave_name = unsafe { CStr::from_ptr(name.as_ptr()) }.to_owned();
    Ok((master, slave_name, slave_fd))
}

#[cfg(target_os = "linux")]
#[link(name = "util")]
unsafe extern "C" {
    fn openpty(
        master: *mut libc::c_int,
        slave: *mut libc::c_int,
        name: *mut libc::c_char,
        termp: *const libc::termios,
        winp: *const libc::winsize,
    ) -> libc::c_int;
}

#[cfg(target_os = "linux")]
fn openpty_fallback() -> io::Result<(RawFd, CString, RawFd)> {
    let mut master = -1;
    let mut slave_fd = -1;
    let mut name = vec![0_i8; 1024];
    // SAFETY: all output pointers remain writable for the call; optional termios/winsize are null.
    if unsafe {
        openpty(
            &mut master,
            &mut slave_fd,
            name.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: openpty wrote a NUL-terminated slave name into `name`.
    let slave_name = unsafe { CStr::from_ptr(name.as_ptr()) }.to_owned();
    Ok((master, slave_name, slave_fd))
}

pub fn tcgetattr(fd: RawFd) -> io::Result<libc::termios> {
    // SAFETY: A zeroed termios is writable output storage for tcgetattr.
    let mut value: libc::termios = unsafe { std::mem::zeroed() };
    // SAFETY: `value` is writable for the call.
    if unsafe { libc::tcgetattr(fd, &mut value) } == 0 {
        Ok(value)
    } else {
        Err(io::Error::last_os_error())
    }
}

pub fn tcsetattr(fd: RawFd, action: libc::c_int, value: &libc::termios) -> io::Result<()> {
    // SAFETY: `value` is a valid termios structure for the descriptor.
    if unsafe { libc::tcsetattr(fd, action, value) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

pub fn set_window_size(fd: RawFd, columns: u16, rows: u16) -> io::Result<()> {
    let value = libc::winsize {
        ws_row: rows,
        ws_col: columns,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: `value` has the kernel winsize layout and is readable for ioctl.
    if unsafe { libc::ioctl(fd, libc::TIOCSWINSZ, &value) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

pub fn terminal_window_size(fd: RawFd) -> io::Result<(u16, u16)> {
    // SAFETY: A zeroed winsize is writable output storage for ioctl.
    let mut value: libc::winsize = unsafe { std::mem::zeroed() };
    // SAFETY: `value` is writable for ioctl's TIOCGWINSZ request.
    if unsafe { libc::ioctl(fd, libc::TIOCGWINSZ, &mut value) } == 0 {
        Ok((value.ws_col, value.ws_row))
    } else {
        Err(io::Error::last_os_error())
    }
}

pub fn set_controlling_terminal(fd: RawFd) -> io::Result<()> {
    // SAFETY: The descriptor is the PTY slave opened after setsid.
    if unsafe { libc::ioctl(fd, libc::TIOCSCTTY, std::ptr::null_mut::<libc::c_void>()) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

pub fn execv(path: &CStr, args: &[*const libc::c_char]) -> io::Result<()> {
    let mut pointers = args.to_vec();
    pointers.push(std::ptr::null());
    // SAFETY: `path` and each argument are NUL-terminated; the pointer array is terminated and live.
    unsafe { libc::execv(path.as_ptr(), pointers.as_ptr()) };
    Err(io::Error::last_os_error())
}

pub fn strftime(format: &CStr, now: libc::time_t, utc: bool, output: &mut [u8]) -> usize {
    // SAFETY: tm is initialized by gmtime_r/localtime_r, with a valid output buffer.
    let mut broken_down: libc::tm = unsafe { std::mem::zeroed() };
    let time_ptr = &now as *const libc::time_t;
    let tm_ptr = if utc {
        // SAFETY: Both pointers refer to live values for gmtime_r.
        unsafe { libc::gmtime_r(time_ptr, &mut broken_down) }
    } else {
        // SAFETY: Both pointers refer to live values for localtime_r.
        unsafe { libc::localtime_r(time_ptr, &mut broken_down) }
    };
    if tm_ptr.is_null() {
        return 0;
    }
    // SAFETY: format is NUL-terminated and output is writable for its full length.
    unsafe {
        libc::strftime(
            output.as_mut_ptr().cast(),
            output.len(),
            format.as_ptr(),
            tm_ptr,
        )
    }
}
