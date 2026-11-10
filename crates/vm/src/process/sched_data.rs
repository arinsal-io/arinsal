//! The scheduler data a process reaches while its native code runs.
//!
//! erts gives every BIF the scheduler it runs on through the process
//! (`erts_proc_sched_data(c_p)`, erl_process.h), so a BIF called straight from module code
//! reaches the scheduler's state without leaving native code. Here that state is the
//! executor's VM view (code tables, loader) and the slice's `RunCtx` (run queue, timers,
//! thread progress). The executor publishes both for its thread for exactly the time the
//! process's native code runs; a BIF entered from that code reaches them through the process.
// Port of erts/emulator/beam/erl_process.h (erts_proc_sched_data, `c_p->scheduler_data`),
// OTP-29.1.1.

mod raw;

use super::Message;
use crate::{Process, Vm};
use arinsal_sched::RunCtx;

/// The published scheduler data of the running native slice. Dropping it restores the
/// previous publication; it holds the borrows of the VM view and slice context it published,
/// so the executor cannot touch either while native code runs.
pub(crate) struct NativeSlice<'s> {
    previous: raw::Published,
    _borrow: std::marker::PhantomData<&'s mut ()>,
}

impl<'s> NativeSlice<'s> {
    /// Publishes `vm` and `ctx` for this thread while the process runs native code.
    #[inline(always)]
    pub(crate) fn enter(vm: &'s mut Vm, ctx: &'s mut RunCtx<'_, Message>) -> Self {
        Self {
            previous: raw::publish(vm, ctx),
            _borrow: std::marker::PhantomData,
        }
    }
}

impl Drop for NativeSlice<'_> {
    #[inline(always)]
    fn drop(&mut self) {
        raw::restore(self.previous);
    }
}

/// Runs `f` with the scheduler data of the native slice `process` runs in: the executor's
/// VM view and the slice context. `None` outside a native slice (a process run by a VM with
/// no scheduler, such as the in-process test harness).
// Port of erts/emulator/beam/erl_process.h (erts_proc_sched_data), OTP-29.1.1.
#[inline]
pub(crate) fn with_sched_data<R>(
    process: &mut Process,
    f: impl FnOnce(&mut Vm, &mut Process, &mut RunCtx<'_, Message>) -> R,
) -> Option<R> {
    raw::with_published(|vm, ctx| {
        debug_assert!(
            process.self_pid == Some(ctx.pid()),
            "scheduler data reached from a process that is not the slice's"
        );
        f(vm, process, ctx)
    })
}
