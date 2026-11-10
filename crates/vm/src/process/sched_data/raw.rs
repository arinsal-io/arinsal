//! Raw storage of the running native slice's scheduler data (one per scheduler thread).

use super::Message;
use crate::Vm;
use arinsal_sched::RunCtx;
use std::cell::Cell;

/// The VM view and slice context pointers published for this thread.
#[derive(Clone, Copy)]
pub(super) struct Published {
    vm: *mut Vm,
    ctx: *mut RunCtx<'static, Message>,
}

const NONE: Published = Published {
    vm: std::ptr::null_mut(),
    ctx: std::ptr::null_mut(),
};

thread_local! {
    static CURRENT: Cell<Published> = const { Cell::new(NONE) };
}

/// Publishes `vm` and `ctx`; returns what was published before.
#[inline(always)]
pub(super) fn publish(vm: &mut Vm, ctx: &mut RunCtx<'_, Message>) -> Published {
    let published = Published {
        vm: std::ptr::from_mut(vm),
        // Only the lifetime parameter changes; `with_published` hands the context out again
        // under a lifetime bounded by the call.
        ctx: std::ptr::from_mut(ctx).cast::<RunCtx<'static, Message>>(),
    };
    CURRENT.with(|current| current.replace(published))
}

/// Restores the publication `publish` replaced.
#[inline(always)]
pub(super) fn restore(previous: Published) {
    CURRENT.with(|current| current.set(previous));
}

/// Runs `f` with the published scheduler data, unpublished for the duration of the call so
/// that no second `&mut` to it can be taken from inside `f`.
#[inline]
pub(super) fn with_published<R>(
    f: impl FnOnce(&mut Vm, &mut RunCtx<'_, Message>) -> R,
) -> Option<R> {
    let published = CURRENT.with(|current| current.replace(NONE));
    if published.vm.is_null() || published.ctx.is_null() {
        return None;
    }
    // SAFETY: only during this process's native slice on this thread. `NativeSlice::enter`
    // derived both pointers from exclusive borrows that the executor holds, unused, until the
    // guard drops after native code returns; native code runs on this thread only, and the
    // publication is taken out above, so this is the one live `&mut` to each.
    let result = unsafe { f(&mut *published.vm, &mut *published.ctx) };
    restore(published);
    Some(result)
}
