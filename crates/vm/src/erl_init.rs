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

/// `erl_start` (erl_init.c): creates the runtime-system tables on the first call; later calls
/// return the ones that exist.
// Port of erts/emulator/beam/erl_init.c (erl_start: erts_init_process, erts_init_port,
// erts_init_scheduling, init_register_table, ...), OTP-29.1.1.
pub(crate) fn erl_start(
    create: impl FnOnce() -> &'static crate::process::Runtime,
) -> &'static crate::process::Runtime {
    ERTS_RUNTIME.get_or_init(create)
}

/// The boot arguments `erl_start` reads from `argv` (erl_init.c): `-root` (what
/// `init:get_argument(root)` returns) and the boot code path the primitive loader searches
/// (`-pa` plus the release's `lib/*/ebin`). A `Vm` constructor sets them before the node
/// loads its first module.
struct BootArgs {
    paths: Vec<std::path::PathBuf>,
    root: Option<std::path::PathBuf>,
}

/// `argv` of erl_init.c (erl_start): set by the node's start, read by the module loader and
/// by `open_port({spawn, ...})` children that need the release root.
static ERTS_BOOT_ARGS: std::sync::RwLock<BootArgs> = std::sync::RwLock::new(BootArgs {
    paths: Vec::new(),
    root: None,
});

/// Records the node's boot arguments (erl_init.c erl_start parsing `argv`).
pub(crate) fn erts_set_boot_args(paths: Vec<std::path::PathBuf>, root: Option<std::path::PathBuf>) {
    let mut args = ERTS_BOOT_ARGS.write().unwrap_or_else(|e| e.into_inner());
    args.paths = paths;
    args.root = root;
}

/// The boot code path, searched in order for a module's `.beam` file.
pub(crate) fn erts_boot_paths() -> Vec<std::path::PathBuf> {
    ERTS_BOOT_ARGS
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .paths
        .clone()
}

/// Runs `f` over the boot code path without copying it.
pub(crate) fn with_erts_boot_paths<R>(f: impl FnOnce(&[std::path::PathBuf]) -> R) -> R {
    f(&ERTS_BOOT_ARGS
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .paths)
}

/// `-root`: the release root, or the one the loaded erts ebin directory implies.
pub(crate) fn erts_root_dir() -> Option<std::path::PathBuf> {
    let args = ERTS_BOOT_ARGS.read().unwrap_or_else(|e| e.into_inner());
    args.root.clone().or_else(|| {
        args.paths.iter().find_map(|path| {
            if path.ends_with(std::path::Path::new("lib/erts-17.1/ebin")) {
                path.parent()?
                    .parent()?
                    .parent()
                    .map(std::path::Path::to_path_buf)
            } else {
                None
            }
        })
    })
}
