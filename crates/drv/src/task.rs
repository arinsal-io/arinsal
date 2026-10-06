//! Port tasks: the executor behind `ready_input`, `ready_output`, `timeout` and
//! `ready_async`.
//!
//! Port of the task part of erts/emulator/beam/erl_port_task.c:1700
//! (erts_port_task_execute), OTP-29.1.1. erts runs these on a scheduler with the port
//! locked; here one executor thread runs them one at a time with the port lock held,
//! so callbacks of one port never overlap with each other or with commands.

use std::ffi::c_void;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::mpsc::{Sender, channel};
use std::sync::{Mutex, OnceLock};
use std::thread;

use crate::asyncq::Job;
use crate::{DrvFn1, DrvFn2};

/// A unit of work for the executor.
pub(crate) enum Task {
    /// The poller reported registration `reg` of `fd` (`dir` 0 = input, 1 = output).
    Ready { fd: i32, dir: usize, reg: u64 },
    /// An async job finished on its worker thread.
    AsyncReady(Job),
}

fn sender() -> &'static Mutex<Sender<Task>> {
    static TX: OnceLock<Mutex<Sender<Task>>> = OnceLock::new();
    TX.get_or_init(|| {
        let (tx, rx) = channel::<Task>();
        thread::Builder::new()
            .name("arinsal-drv-tasks".into())
            .spawn(move || {
                for task in rx {
                    // A panicking host callback must not take the executor down.
                    let _ = catch_unwind(AssertUnwindSafe(|| run(task)));
                }
            })
            .expect("start driver task executor");
        Mutex::new(tx)
    })
}

/// Queue `task` (`erts_port_task_schedule`).
pub(crate) fn schedule(task: Task) {
    let _ = sender().lock().unwrap().send(task);
}

fn run(task: Task) {
    match task {
        Task::Ready { fd, dir, reg } => crate::select::ready(fd, dir, reg),
        Task::AsyncReady(job) => job.ready(),
    }
}

/// Call a `void (*)(void *)` driver callback.
pub(crate) fn call1(callback: DrvFn1, arg: *mut c_void) {
    // SAFETY: the callback comes from a loaded driver entry or a driver_async call whose
    // library stays loaded while the port or job exists; `arg` is that driver's own data.
    unsafe { callback(arg) }
}

/// Call a `void (*)(void *, void *)` driver callback.
pub(crate) fn call2(callback: DrvFn2, first: *mut c_void, second: *mut c_void) {
    // SAFETY: as for `call1`; the pointers are the driver's data and the event or job data.
    unsafe { callback(first, second) }
}

/// The `ErlDrvEvent` for descriptor `fd` (`(ErlDrvEvent)(long)fd` in drivers).
pub(crate) fn event_of(fd: i32) -> *mut c_void {
    fd as isize as usize as *mut c_void
}

/// The descriptor behind an `ErlDrvEvent`.
pub(crate) fn fd_of(event: *mut c_void) -> i32 {
    event as usize as isize as i32
}
