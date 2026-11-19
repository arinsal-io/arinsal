//! Runtime-system globals set up at boot.
// Port of erts/emulator/beam/erl_init.c, OTP-29.1.1.

use std::sync::atomic::{AtomicUsize, Ordering};

/// `DEFAULT_BACKTRACE_SIZE` (error.h).
const DEFAULT_BACKTRACE_SIZE: usize = 8;

/// `int erts_backtrace_depth` (erl_init.c): how many functions a backtrace in an error shows.
/// A plain global in erts, read without ordering; `system_flag(backtrace_depth, N)` (bif.c)
/// stores it.
static ERTS_BACKTRACE_DEPTH: AtomicUsize = AtomicUsize::new(DEFAULT_BACKTRACE_SIZE);

/// Reads `erts_backtrace_depth`.
#[inline]
pub(crate) fn erts_backtrace_depth() -> usize {
    ERTS_BACKTRACE_DEPTH.load(Ordering::Relaxed)
}

/// `erts_backtrace_depth = n` (bif.c, system_flag_2); returns the previous depth.
pub(crate) fn set_erts_backtrace_depth(n: usize) -> usize {
    ERTS_BACKTRACE_DEPTH.swap(n, Ordering::Relaxed)
}
