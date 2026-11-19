//! Raw thread-specific slot of `erts_sched_data_key`.
// Port of erts/emulator/beam/erl_process.h (erts_get_scheduler_data), OTP-29.1.1.

use crate::{ErtsSchedulerData, Task};
use std::any::TypeId;
use std::cell::Cell;

/// The bound scheduler data: its address and the task type it was built for.
type Slot = (*const (), Option<TypeId>);

thread_local! {
    static SCHED_DATA: Cell<Slot> = const { Cell::new((std::ptr::null(), None)) };
}

/// What the slot held before a binding.
pub(super) struct Previous(Slot);

pub(super) fn set<T: Task>(esdp: &ErtsSchedulerData<T>) -> Previous {
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
