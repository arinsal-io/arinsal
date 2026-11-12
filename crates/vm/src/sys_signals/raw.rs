//! POSIX signal and pipe operations for `sys_signals`.

use crate::VmError;
use crate::process::Runtime;
use std::os::fd::RawFd;
use std::sync::atomic::{AtomicI32, Ordering};

static SIGNAL_WRITE_FD: AtomicI32 = AtomicI32::new(-1);

// Port of `init_smp_sig_notify` in erts/emulator/sys/unix/sys.c, OTP-29.1.1.
pub(super) fn init_dispatcher(runtime: &'static Runtime) -> Result<(), VmError> {
    let mut fds = [-1; 2];
    let result = crate::port::cloexec_publish(|| {
        // SAFETY: pipe initializes both fresh descriptors in `fds`.
        let rc = unsafe { libc::pipe(fds.as_mut_ptr()) };
        if rc == 0 {
            // SAFETY: both descriptors were created by pipe and remain open.
            let failed = unsafe {
                libc::fcntl(fds[0], libc::F_SETFD, libc::FD_CLOEXEC) < 0
                    || libc::fcntl(fds[1], libc::F_SETFD, libc::FD_CLOEXEC) < 0
            };
            if failed {
                let error = std::io::Error::last_os_error();
                // SAFETY: both descriptors are still ours and are closed on this error path.
                unsafe {
                    libc::close(fds[0]);
                    libc::close(fds[1]);
                }
                return Err(error);
            }
        }
        Ok(rc)
    })
    .map_err(|error| VmError::Unsupported(format!("signal pipe close-on-exec: {error}")))?;
    if result != 0 {
        return Err(VmError::Unsupported(format!(
            "signal pipe creation: {}",
            std::io::Error::last_os_error()
        )));
    }
    if SIGNAL_WRITE_FD
        .compare_exchange(-1, fds[1], Ordering::Relaxed, Ordering::Relaxed)
        .is_err()
    {
        // SAFETY: another initializer published the process signal pipe first.
        unsafe {
            libc::close(fds[0]);
            libc::close(fds[1]);
        }
        return Ok(());
    }
    if let Err(error) = std::thread::Builder::new()
        .name("arinsal-signal-dispatch".into())
        .spawn(move || signal_dispatcher_thread_func(fds[0], runtime))
    {
        SIGNAL_WRITE_FD.store(-1, Ordering::Relaxed);
        // SAFETY: dispatcher creation failed, so both pipe descriptors are still ours.
        unsafe {
            libc::close(fds[0]);
            libc::close(fds[1]);
        }
        return Err(VmError::Unsupported(format!("signal dispatcher: {error}")));
    }
    Ok(())
}

pub(super) fn signal_handler() -> libc::sighandler_t {
    signal_handler_impl as *const () as libc::sighandler_t
}

pub(super) fn set_disposition(signum: i32, handler: libc::sighandler_t) {
    // Port of `sys_signal` in erts/emulator/sys/unix/sys.c, OTP-29.1.1.
    // SAFETY: zeroed sigaction is initialized before being passed to sigaction.
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    // SAFETY: sigemptyset initializes the mask; sigaction installs the disposition.
    unsafe {
        libc::sigemptyset(&mut action.sa_mask);
        action.sa_flags = 0;
        action.sa_sigaction = handler;
        libc::sigaction(signum, &action, std::ptr::null_mut());
    }
}

// Port of `generic_signal_handler` and `smp_sig_notify` in erts/emulator/sys/unix/sys.c.
extern "C" fn signal_handler_impl(signum: libc::c_int) {
    let fd = SIGNAL_WRITE_FD.load(Ordering::Relaxed);
    loop {
        // SAFETY: write is async-signal-safe; the integer and pipe remain valid for this call.
        let rc = unsafe {
            libc::write(
                fd,
                std::ptr::from_ref(&signum).cast(),
                std::mem::size_of::<libc::c_int>(),
            )
        };
        if rc < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            continue;
        } else if rc != std::mem::size_of::<libc::c_int>() as isize {
            // SAFETY: fatal pipe failure must not return to a VM with a broken dispatcher.
            unsafe { libc::_exit(1) };
        }
        break;
    }
}

// Port of `signal_dispatcher_thread_func` in erts/emulator/sys/unix/sys.c.
fn signal_dispatcher_thread_func(read_fd: RawFd, runtime: &'static Runtime) {
    loop {
        let mut signum = 0i32;
        let mut offset = 0;
        while offset < std::mem::size_of::<i32>() {
            // SAFETY: signum is writable and read_fd is this thread's open pipe read end.
            let rc = unsafe {
                libc::read(
                    read_fd,
                    (std::ptr::from_mut(&mut signum).cast::<u8>())
                        .add(offset)
                        .cast(),
                    std::mem::size_of::<i32>() - offset,
                )
            };
            if rc > 0 {
                offset += rc as usize;
            } else if rc < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR)
            {
                continue;
            } else {
                // SAFETY: the process-lifetime pipe must not close or lose dispatching.
                unsafe { libc::_exit(1) };
            }
        }
        if !crate::sys_signals::dispatch_signal(runtime, signum) {
            // SAFETY: C treats unknown pipe values as a fatal dispatcher error.
            unsafe { libc::_exit(1) };
        }
    }
}
