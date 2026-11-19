//! The scheduler data a process reaches while its native code runs.
//!
//! erts gives every BIF the scheduler it runs on through the process
//! (`erts_proc_sched_data(c_p)` reads `c_p->scheduler_data`, erl_process.h), so a BIF called
//! straight from module code reaches the scheduler's state without leaving native code. Here
//! that state is the executor's VM view (code tables, loader) and the slice's `RunCtx` (run
//! queue, timers, thread progress). The executor stores both into the process for exactly the
//! time the process's native code runs; a BIF entered from that code reaches them through the
//! process.
// Port of erts/emulator/beam/erl_process.h (erts_proc_sched_data, `c_p->scheduler_data`),
// OTP-29.1.1.

mod raw;

pub(crate) use raw::Published as SchedulerDataPtr;

use crate::{Process, Vm};
use arinsal_sched::RunCtx;

/// Running a process's native code with its scheduler data set.
pub(crate) struct NativeSlice;

impl NativeSlice {
    /// Runs `body` with `process.scheduler_data` pointing at `vm` and `ctx`; the previous
    /// value is restored when it returns. The borrows of `vm` and `ctx` are held for the call,
    /// so the executor cannot touch either while native code runs.
    #[inline(always)]
    pub(crate) fn run<R>(
        vm: &mut Vm,
        ctx: &mut RunCtx<'_, crate::Process>,
        process: &mut Process,
        body: impl FnOnce(&mut Process) -> R,
    ) -> R {
        let previous = std::mem::replace(&mut process.scheduler_data, raw::publish(vm, ctx));
        let result = body(process);
        process.scheduler_data = previous;
        result
    }
}

/// Runs `f` with the scheduler data of the native slice `process` runs in: the executor's
/// VM view and the slice context. `None` outside a native slice (a process run by a VM with
/// no scheduler, such as the in-process test harness).
// Port of erts/emulator/beam/erl_process.h (erts_proc_sched_data), OTP-29.1.1.
#[inline]
pub(crate) fn with_sched_data<R>(
    process: &mut Process,
    f: impl FnOnce(&mut Vm, &mut Process, &mut RunCtx<'_, crate::Process>) -> R,
) -> Option<R> {
    let published = std::mem::take(&mut process.scheduler_data);
    let result = raw::with_published(published, |vm, ctx| {
        debug_assert!(
            process.self_pid == Some(ctx.pid()),
            "scheduler data reached from a process that is not the slice's"
        );
        f(vm, process, ctx)
    });
    process.scheduler_data = published;
    result
}

/// `erts_proc_sched_data(c_p)->registers->x_reg_array` of the native slice `process` runs
/// in, or `None` outside one.
// Port of erts/emulator/beam/erl_process.h (erts_proc_sched_data, ErtsSchedulerData.registers),
// OTP-29.1.1.
pub(crate) fn sched_registers<'a>(process: &mut Process) -> Option<&'a mut [arinsal_term::Term]> {
    with_sched_data(process, |vm, _, _| vm.x_regs().ok()).flatten()
}
