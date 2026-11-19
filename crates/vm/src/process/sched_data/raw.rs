//! Raw storage of `c_p->scheduler_data` while the process's native slice runs.

use crate::Vm;
use arinsal_sched::RunCtx;

/// The VM view and slice context pointers a process carries while its native code runs
/// (`c_p->scheduler_data`); null outside a native slice.
#[derive(Clone, Copy)]
pub(crate) struct Published {
    vm: *mut Vm,
    ctx: *mut RunCtx<'static, crate::Process>,
}

impl Published {
    /// No scheduler data: the process is not in a native slice.
    pub(crate) const NONE: Self = Self {
        vm: std::ptr::null_mut(),
        ctx: std::ptr::null_mut(),
    };
}

impl Default for Published {
    fn default() -> Self {
        Self::NONE
    }
}

/// The pointers of `vm` and `ctx`, to store into the process.
#[inline(always)]
pub(super) fn publish(vm: &mut Vm, ctx: &mut RunCtx<'_, crate::Process>) -> Published {
    Published {
        vm: std::ptr::from_mut(vm),
        // Only the lifetime parameter changes; `with_published` hands the context out again
        // under a lifetime bounded by the call.
        ctx: std::ptr::from_mut(ctx).cast::<RunCtx<'static, crate::Process>>(),
    }
}

/// Runs `f` with the scheduler data `published` points to. The caller has taken it out of
/// the process for the duration of the call, so no second `&mut` to it can be taken from
/// inside `f`.
#[inline]
pub(super) fn with_published<R>(
    published: Published,
    f: impl FnOnce(&mut Vm, &mut RunCtx<'_, crate::Process>) -> R,
) -> Option<R> {
    if published.vm.is_null() || published.ctx.is_null() {
        return None;
    }
    // SAFETY: only during this process's native slice. `NativeSlice::run` derived both
    // pointers from exclusive borrows it holds, unused, until its body returns; the body runs
    // on this thread only, and the caller took the pointers out of the process, so this is
    // the one live `&mut` to each.
    Some(unsafe { f(&mut *published.vm, &mut *published.ctx) })
}
