//! The scheduler data of the calling thread (`erts_get_scheduler_data()`).
//!
//! erts keeps a pointer to each scheduler thread's `ErtsSchedulerData` in thread-specific
//! data under `sched_data_key`; code that has no `esdp` at hand reads it from there, and gets
//! NULL on a thread that is not a scheduler.
// Port of erts/emulator/beam/erl_process.h (erts_get_scheduler_data: erts_tsd_get(
// erts_sched_data_key)) and erl_process.c (sched_thread_func / sched_dirty_*_thread_func:
// erts_tsd_set(erts_sched_data_key, esdp)), OTP-29.1.1.

mod raw;

use crate::{ErtsSchedulerData, Task};

/// The binding of one scheduler thread's data to the thread; dropping it clears the key, as
/// a scheduler thread's data is torn down with the thread.
pub(crate) struct SchedDataKey(raw::Previous);

impl SchedDataKey {
    /// `erts_tsd_set(erts_sched_data_key, esdp)`: `esdp` stays bound until the returned
    /// guard drops; the caller keeps `esdp` in place and reaches it only through shared
    /// references for that time.
    pub(crate) fn set<T: Task>(esdp: &ErtsSchedulerData<T>) -> Self {
        Self(raw::set(esdp))
    }
}

impl Drop for SchedDataKey {
    fn drop(&mut self) {
        raw::restore(&self.0);
    }
}

/// `erts_get_scheduler_data()`: runs `f` on the calling scheduler thread's data, or returns
/// `None` on a thread that is not a scheduler of a `T` runtime (erts: NULL).
#[inline]
pub fn erts_get_scheduler_data<T: Task, R>(
    f: impl for<'a> FnOnce(&'a ErtsSchedulerData<T>) -> R,
) -> Option<R> {
    raw::with::<T, R>(f)
}
