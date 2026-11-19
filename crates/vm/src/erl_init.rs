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

/// The node's runtime-system tables that `erl_start` (erl_init.c) initialises once per OS
/// process: the process and port tables (`erts_proc`, `erts_port`), `erts_schedulers`, the
/// registered-name table (register.c `process_reg`), the trap exports and the statistics
/// state. erts keeps each as its own global; here they are still fields of one
/// [`crate::process::Runtime`] that `erl_start` creates and that lives until `erts_exit`.
static ERTS_RUNTIME: std::sync::OnceLock<&'static crate::process::Runtime> =
    std::sync::OnceLock::new();

/// The runtime-system tables once `erl_start` created them.
#[inline]
pub(crate) fn erts_runtime() -> Option<&'static crate::process::Runtime> {
    ERTS_RUNTIME.get().copied()
}

/// `erl_start` (erl_init.c): creates the runtime-system tables on the first call; later calls
/// return the ones that exist.
// Port of erts/emulator/beam/erl_init.c (erl_start: erts_init_process, erts_init_port,
// erts_init_scheduling, init_register_table, ...), OTP-29.1.1.
pub(crate) fn erl_start(
    create: impl FnOnce() -> &'static crate::process::Runtime,
) -> &'static crate::process::Runtime {
    ERTS_RUNTIME.get_or_init(create)
}
