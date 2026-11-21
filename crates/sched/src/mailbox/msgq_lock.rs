//! The msgq lock held across native calls: a receive that found every queue empty returns to
//! generated code with `ERTS_PROC_LOCKS_MSG_RECEIVE` held, and the wait instruction it reaches
//! releases it from another runtime call. No guard can live across that boundary, so the lock
//! is kept by forgetting its guard and released through the raw mutex.
// Port of erts/emulator/beam/erl_proc_sig_queue.c:7782-7795 (erts_proc_sig_receive_helper
// returns with the message queue locked) and jit/beam_jit_common.cpp:1188-1256
// (beam_jit_take_receive_lock / beam_jit_wait_locked unlock), OTP-29.1.1.

use crate::sig_queue::SignalQueue;
use parking_lot::{Mutex, MutexGuard};

/// Keep the msgq lock of `guard` held after the guard ends.
pub(super) fn keep_locked<T>(guard: MutexGuard<'_, SignalQueue<T>>) {
    let _ = MutexGuard::leak(guard);
}

/// Release a msgq lock kept by [`keep_locked`].
pub(super) fn release_kept<T>(msgq: &Mutex<SignalQueue<T>>) {
    assert!(
        msgq.is_locked(),
        "the receive holds the msgq lock it releases"
    );
    // SAFETY: the lock was taken and its guard leaked by `keep_locked` on this thread (the
    // receive protocol: the helper or beam_jit_take_receive_lock takes it, and exactly one of
    // the wait / timeout runtime calls releases it), so no guard of it is live.
    unsafe { msgq.force_unlock() };
}
