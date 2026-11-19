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
