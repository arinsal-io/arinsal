//! Per-thread microstate accounting.
//!
//! Port of erts/emulator/beam/erl_msacc.h and erl_msacc.c (OTP-29.1.1).

mod raw;

use crate::MsaccState;

/// An msacc request sent to each managed thread.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MsAccAction {
    /// Start accounting on a thread.
    Enable,
    /// Stop accounting on a thread.
    Disable,
    /// Clear the thread's accumulated state counters.
    Reset,
}

/// A thread's counters copied by erts_msacc_request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MsAccSnapshot {
    /// The type passed to erts_msacc_init_thread.
    pub thread_type: String,
    /// The thread id passed to erts_msacc_init_thread.
    pub id: i64,
    /// Accumulated performance-counter ticks in MsaccState order.
    pub counters: [u64; crate::MSACC_STATE_COUNT],
}

/// erts_msacc_init_thread(type, id, liberty) for a newly started thread.
// Port of erts/emulator/beam/erl_msacc.c (erts_msacc_init_thread), OTP-29.1.1.
pub fn erts_msacc_init_thread(thread_type: &'static str, id: usize, managed: bool) {
    let _ = raw::init_thread(thread_type, id as i64, managed);
}

/// Whether the VM-wide microstate accounting switch is on.
pub fn erts_msacc_enabled() -> bool {
    raw::enabled()
}

/// Whether this thread's `erts_msacc_key` currently holds an `ErtsMsAcc`.
// Port of erts/emulator/beam/erl_msacc.h (`ERTS_MSACC_TSD_GET`), OTP-29.1.1.
pub(crate) fn erts_msacc_tsd() -> bool {
    raw::tsd_is_set()
}

/// Change the current thread's accounting state through its TSD key.
// Port of erts/emulator/beam/erl_msacc.h (ERTS_MSACC_SET_STATE), OTP-29.1.1.
#[inline]
pub fn erts_msacc_set_state(state: MsaccState) {
    raw::set_current_state(state);
}

/// Save the current state and switch to state until the returned guard is dropped.
// Port of erts/emulator/beam/erl_msacc.h (ERTS_MSACC_PUSH_AND_SET_STATE / POP_STATE), OTP-29.1.1.
pub fn erts_msacc_push_and_set_state(state: MsaccState) -> MsAccStateGuard {
    MsAccStateGuard(raw::push_and_set_state(state))
}

/// Restores the state saved by erts_msacc_push_and_set_state.
pub struct MsAccStateGuard(Option<raw::CachedMsAccState>);

impl Drop for MsAccStateGuard {
    fn drop(&mut self) {
        raw::restore_state(self.0.take());
    }
}

pub(crate) fn erts_msacc_request_unmanaged(action: MsAccAction) {
    raw::request_unmanaged(action);
}

pub(crate) fn erts_msacc_set_enabled(enabled: bool) {
    raw::set_enabled(enabled);
}

pub(crate) fn erts_msacc_gather_current_managed() -> MsAccSnapshot {
    raw::gather_current_managed()
}

pub(crate) fn erts_msacc_gather_unmanaged() -> Vec<MsAccSnapshot> {
    raw::gather_unmanaged()
}

pub(crate) fn erts_msacc_apply_current_managed(action: MsAccAction) {
    raw::apply_current_managed(action);
}
