//! Raw Darwin main-thread pipe operations.
//!
//! Port of erts/emulator/sys/unix/sys.c (erts_sys_main_thread) and
//! erts/emulator/beam/erl_drv_thread.c (erl_drv_steal_main_thread), OTP-29.1.1.

use std::ffi::{c_int, c_void};

type MainFunc = extern "C" fn(*mut c_void) -> *mut c_void;

static mut MAIN_PIPE: [c_int; 2] = [-1; 2];
static mut RESULT_PIPE: [c_int; 2] = [-1; 2];

/// Port of sys.c (initialize_darwin_main_thread_pipes), OTP-29.1.1.
pub(super) fn initialize() -> Result<(), c_int> {
    // SAFETY: initialization runs on the process main thread before the VM worker starts;
    // these descriptors are then immutable until the worker closes the request writer.
    unsafe {
        if libc::pipe(std::ptr::addr_of_mut!(MAIN_PIPE).cast()) < 0
            || libc::pipe(std::ptr::addr_of_mut!(RESULT_PIPE).cast()) < 0
        {
            return Err(*libc::__error());
        }
    }
    Ok(())
}

/// Port of sys.c (erts_sys_main_thread), OTP-29.1.1.
pub(super) fn park() -> ! {
    loop {
        // SAFETY: the main thread owns the read descriptors; the worker only writes requests.
        let (read_fd, result_fd) = unsafe { (MAIN_PIPE[0], RESULT_PIPE[1]) };
        // SAFETY: fd_set is a plain C bitset initialized immediately by FD_ZERO below.
        let mut read_set = unsafe { std::mem::zeroed::<libc::fd_set>() };
        // SAFETY: read_fd is a valid descriptor created by initialize.
        unsafe {
            libc::FD_ZERO(&mut read_set);
            libc::FD_SET(read_fd, &mut read_set);
        }
        // SAFETY: select waits on the initialized pipe descriptor.
        let selected = unsafe {
            libc::select(
                read_fd + 1,
                &mut read_set,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if selected <= 0 {
            // SAFETY: libc exposes the calling thread's errno through __error on Darwin.
            if selected < 0 && unsafe { *libc::__error() } == libc::EINTR {
                continue;
            }
            break;
        }
        let mut func = std::mem::MaybeUninit::<MainFunc>::uninit();
        let mut arg: *mut c_void = std::ptr::null_mut();
        // SAFETY: request writes contain one callback pointer followed by one argument pointer,
        // matching erl_drv_steal_main_thread's two writes and the pipe's blocking semantics.
        let read_func = unsafe {
            libc::read(
                read_fd,
                func.as_mut_ptr().cast(),
                std::mem::size_of::<MainFunc>(),
            )
        };
        if read_func != std::mem::size_of::<MainFunc>() as isize {
            break;
        }
        // SAFETY: the read above initialized every byte of the function pointer.
        let func = unsafe { func.assume_init() };
        // SAFETY: follows a complete callback pointer in the same request stream.
        let read_arg = unsafe {
            libc::read(
                read_fd,
                std::ptr::addr_of_mut!(arg).cast(),
                std::mem::size_of::<*mut c_void>(),
            )
        };
        if read_arg != std::mem::size_of::<*mut c_void>() as isize {
            break;
        }
        let result = func(arg);
        // SAFETY: result pipe is read by erl_drv_stolen_main_thread_join.
        let _ = unsafe {
            libc::write(
                result_fd,
                std::ptr::from_ref(&result).cast(),
                std::mem::size_of_val(&result),
            )
        };
    }
    loop {
        // SAFETY: OTP falls back to select(0, ...) after the Darwin pipe loop ends, keeping
        // the process main thread parked until process termination.
        unsafe {
            libc::select(
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            );
        }
    }
}

/// Port of erl_drv_thread.c (erl_drv_steal_main_thread), OTP-29.1.1.
pub(super) fn steal(func: MainFunc, arg: *mut c_void) -> c_int {
    // SAFETY: worker writes a fixed-size request to the pipe initialized before it started.
    unsafe {
        let fd = MAIN_PIPE[1];
        let _ = libc::write(
            fd,
            std::ptr::from_ref(&func).cast(),
            std::mem::size_of::<MainFunc>(),
        );
        let _ = libc::write(
            fd,
            std::ptr::from_ref(&arg).cast(),
            std::mem::size_of::<*mut c_void>(),
        );
        0
    }
}

/// Port of erl_drv_thread.c (erl_drv_stolen_main_thread_join), OTP-29.1.1.
pub(super) fn join(result: *mut *mut c_void) -> c_int {
    // SAFETY: join is called once for each submitted callback; the pipe carries its pointer result.
    unsafe {
        let mut dummy = std::ptr::null_mut();
        let output = if result.is_null() {
            &mut dummy
        } else {
            &mut *result
        };
        let _ = libc::read(
            RESULT_PIPE[0],
            std::ptr::addr_of_mut!(*output).cast(),
            std::mem::size_of::<*mut c_void>(),
        );
        0
    }
}
