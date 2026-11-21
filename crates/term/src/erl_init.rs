// Port of erts/emulator/beam/erl_init.c (erts_exit, erts_exit_vv, erts_exit_epilogue), OTP-29.1.1.
//! `erts_exit` for the term-level runtime code (heap sizing, index tables) that ends the node
//! the way erts does when an invariant it cannot recover from breaks.

use std::io::Write;

/// `erts_exit` modes (sys.h `ERTS_DUMP_EXIT`, `ERTS_ERROR_EXIT`, `ERTS_ABORT_EXIT`).
#[derive(Clone, Copy)]
pub(crate) enum ExitMode {
    /// `ERTS_DUMP_EXIT`: crash dump, then `exit(1)`.
    Dump,
    /// `ERTS_ERROR_EXIT`: crash dump, then `abort()`.
    Error,
    /// `ERTS_ABORT_EXIT`: no crash dump, only `abort()`.
    Abort,
}

/// `erts_exit(mode, slogan)`: print the slogan (`erl_error`) and the crash dump banner
/// (erl_crash_dump.c:509), then end the OS process as `erts_exit_epilogue`.
pub(crate) fn erts_exit(mode: ExitMode, slogan: &str) -> ! {
    // erts_fprintf writes `\r\n` on this platform.
    let message = match mode {
        ExitMode::Abort => format!("{slogan}\r\n"),
        ExitMode::Dump | ExitMode::Error => {
            format!("{slogan}\r\n\r\nCrash dump is being written to: erl_crash.dump...done\r\n")
        }
    };
    let mut stderr = std::io::stderr().lock();
    let _ = stderr.write_all(message.as_bytes());
    let _ = stderr.flush();
    match mode {
        ExitMode::Dump => std::process::exit(1),
        ExitMode::Error | ExitMode::Abort => std::process::abort(),
    }
}
