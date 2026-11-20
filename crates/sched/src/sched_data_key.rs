//! The scheduler data of the calling thread (`erts_get_scheduler_data()`).
//!
//! erts keeps a pointer to each scheduler thread's `ErtsSchedulerData` in thread-specific
//! data under `sched_data_key`; code that has no `esdp` at hand reads it from there, and gets
//! NULL on a thread that is not a scheduler.
// Port of erts/emulator/beam/erl_process.h (erts_get_scheduler_data: erts_tsd_get(
// erts_sched_data_key)) and erl_process.c (sched_thread_func / sched_dirty_*_thread_func:
// erts_tsd_set(erts_sched_data_key, esdp)), OTP-29.1.1.

mod raw;

pub use raw::ProcSchedData;
pub(crate) use raw::with_head;

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

impl<T: Task> Default for ProcSchedData<T> {
    fn default() -> Self {
        Self::null()
    }
}

impl<T: Task> ProcSchedData<T> {
    /// `p->scheduler_data = esdp` when a normal scheduler selects the process to run, `NULL`
    /// at its schedule-out.
    // Port of erts/emulator/beam/erl_process.c:10232 and :9756 (erts_schedule), OTP-29.1.1.
    pub(crate) fn set_scheduler(&self, esdp: Option<&ErtsSchedulerData<T>>) {
        debug_assert!(
            esdp.is_none() || !self.is_set(),
            "ASSERT(!p->scheduler_data)"
        );
        self.set(esdp);
    }
}

/// `erts_proc_sched_data(c_p)`: runs `f` on `c_p` and the data of the scheduler `c_p` runs
/// on, reached through `c_p->scheduler_data` on a normal scheduler and through
/// `erts_get_scheduler_data()` otherwise (a dirty scheduler, or code running on behalf of
/// another process). `None` on a thread that is no scheduler (erts asserts).
// Port of erts/emulator/beam/erl_process.h:2595 (erts_proc_sched_data), OTP-29.1.1.
#[inline]
pub fn erts_proc_sched_data<T: Task, R>(
    c_p: &mut T,
    f: impl for<'a> FnOnce(&mut T, &'a ErtsSchedulerData<T>) -> R,
) -> Option<R> {
    match raw::with_proc(c_p, f) {
        Ok(result) => Some(result),
        Err(f) => raw::with::<T, R>(|esdp| f(c_p, esdp)),
    }
}
