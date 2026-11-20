//! Raw thread-specific slot of `erts_sched_data_key`.
// Port of erts/emulator/beam/erl_process.h (erts_get_scheduler_data), OTP-29.1.1.

use crate::{
    ErtsSchedulerData, MatchPseudoProcess, PendingSlot, SchedulerType, Task, unique::SchedRefUnique,
};
use std::any::TypeId;
use std::cell::Cell;

/// The bound scheduler data: its address and the task type it was built for.
type Slot = (*const (), Option<TypeId>);

thread_local! {
    static SCHED_DATA: Cell<Slot> = const { Cell::new((std::ptr::null(), None)) };
}

/// What the slot held before a binding.
pub(super) struct Previous(Slot);

/// The leading fields of every `ErtsSchedulerData<T>`, which do not depend on `T`: erts has one
/// scheduler data type, and code that does not know the task type (erl_bif_unique.c,
/// erl_nif.c `enif_thread_type`, `esdp->pending_signal` on every send) reads these through
/// `erts_get_scheduler_data()` as well. `ErtsSchedulerData` is `#[repr(C)]` and starts with
/// exactly these fields in this order, so they sit at the same offsets for every `T`.
#[repr(C)]
pub(crate) struct Head {
    pub(crate) worker: Option<usize>,
    pub(crate) sched_type: SchedulerType,
    pub(crate) pending_signal: PendingSlot,
    pub(crate) ref_unique: SchedRefUnique,
    pub(crate) match_pseudo_process: MatchPseudoProcess,
}

pub(super) fn set<T: Task>(esdp: &ErtsSchedulerData<T>) -> Previous {
    let base = std::ptr::from_ref(esdp).cast::<Head>();
    // The `T`-independent prefix must keep the layout of `Head`; checked once per scheduler
    // thread, as `with_head` relies on it.
    assert!(
        std::ptr::eq(std::ptr::addr_of!(esdp.worker), base.cast())
            && std::ptr::eq(
                std::ptr::addr_of!(esdp.sched_type),
                // SAFETY: `base` is the address of `esdp`; `addr_of!` only computes the
                // field address of the `Head` view, nothing is read.
                unsafe { std::ptr::addr_of!((*base).sched_type) }
            )
            && std::ptr::eq(
                std::ptr::addr_of!(esdp.pending_signal),
                // SAFETY: as above.
                unsafe { std::ptr::addr_of!((*base).pending_signal) }
            )
            && std::ptr::eq(
                std::ptr::addr_of!(esdp.ref_unique),
                // SAFETY: as above.
                unsafe { std::ptr::addr_of!((*base).ref_unique) }
            )
            && std::ptr::eq(
                std::ptr::addr_of!(esdp.match_pseudo_process),
                // SAFETY: as above.
                unsafe { std::ptr::addr_of!((*base).match_pseudo_process) }
            ),
        "ErtsSchedulerData starts with the fields of Head"
    );
    let slot = (
        std::ptr::from_ref(esdp).cast::<()>(),
        Some(TypeId::of::<T>()),
    );
    Previous(SCHED_DATA.with(|key| key.replace(slot)))
}

pub(super) fn restore(previous: &Previous) {
    SCHED_DATA.with(|key| key.set(previous.0));
}

#[inline]
pub(super) fn with<T: Task, R>(f: impl for<'a> FnOnce(&'a ErtsSchedulerData<T>) -> R) -> Option<R> {
    let (data, ty) = SCHED_DATA.with(Cell::get);
    if data.is_null() || ty != Some(TypeId::of::<T>()) {
        return None;
    }
    // SAFETY: `SchedDataKey::set` stored the address of an `ErtsSchedulerData<T>` (the type
    // id matches) that its scheduler thread keeps in place, reached only by shared reference,
    // until the guard's drop clears this slot; the slot is thread-local, so the data belongs
    // to the calling thread. The reference cannot outlive `f`.
    Some(f(unsafe { &*data.cast::<ErtsSchedulerData<T>>() }))
}

/// `erts_get_scheduler_data()` for code that does not know the task type: runs `f` on the
/// `T`-independent fields of the calling scheduler thread's data, or returns `None` on a
/// thread that is not a scheduler.
#[inline]
pub(crate) fn with_head<R>(f: impl for<'a> FnOnce(&'a Head) -> R) -> Option<R> {
    let (data, _) = SCHED_DATA.with(Cell::get);
    if data.is_null() {
        return None;
    }
    // SAFETY: `set` stored the address of an `ErtsSchedulerData<T>` for some `T`; that struct
    // is `#[repr(C)]` and begins with the fields of `Head` in its order (asserted in `set`),
    // so its first bytes are a `Head` whatever `T` is. The scheduler thread keeps the data in
    // place and reaches it only by shared reference until the guard clears this thread-local
    // slot; every field of `Head` is read-only or a `Cell`. The reference cannot outlive `f`.
    Some(f(unsafe { &*data.cast::<Head>() }))
}

/// `p->scheduler_data`: the address of the scheduler data of the normal scheduler running
/// the process, or null.
pub struct ProcSchedData<T: Task>(Cell<*const ErtsSchedulerData<T>>);

impl<T: Task> ProcSchedData<T> {
    pub(super) const fn null() -> Self {
        Self(Cell::new(std::ptr::null()))
    }

    pub(super) fn set(&self, esdp: Option<&ErtsSchedulerData<T>>) {
        self.0
            .set(esdp.map_or(std::ptr::null(), std::ptr::from_ref));
    }

    pub(super) fn is_set(&self) -> bool {
        !self.0.get().is_null()
    }
}

/// Runs `f` on `c_p` and the scheduler data `c_p->scheduler_data` points to, or returns
/// `None` when it is null.
#[inline]
pub(super) fn with_proc<T: Task, R, F>(c_p: &mut T, f: F) -> Result<R, F>
where
    F: for<'a> FnOnce(&mut T, &'a ErtsSchedulerData<T>) -> R,
{
    let data = c_p
        .scheduler_data()
        .map_or(std::ptr::null(), |slot| slot.0.get());
    if data.is_null() {
        return Err(f);
    }
    // SAFETY: `set` stored the address of the scheduler data of the normal scheduler that
    // runs the process, at schedule-in of its slice (erts_schedule), and clears it at the
    // schedule-out of that slice. The scheduler thread keeps that data in place, reached only
    // by shared reference, for its whole life; the process is reached here only by the code
    // of its slice on that thread, so the data is live. The reference cannot outlive `f`.
    Ok(f(c_p, unsafe { &*data }))
}
