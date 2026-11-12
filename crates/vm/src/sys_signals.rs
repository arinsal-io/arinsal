//! Unix process signal delivery.
//!
//! Port of erts/emulator/sys/unix/sys.c (signal delivery), OTP-29.1.1.

use crate::process::{Message, Runtime};
use crate::{Process, VmError};
use arinsal_term::{ProcessHeap, Term, TermBuilder, global_atoms};
mod raw;

/// Port of `erts_sys_unix_later_init` and `init_break_handler` in
/// erts/emulator/sys/unix/sys.c: install the dispatcher before any handled disposition.
pub(crate) fn install_boot_signals(runtime: &'static Runtime) -> Result<(), VmError> {
    raw::init_dispatcher(runtime)?;

    // Port of erts_sys_unix_later_init. sys_signal ignores sigaction's return value.
    raw::set_disposition(libc::SIGTERM, raw::signal_handler());
    raw::set_disposition(libc::SIGUSR1, raw::signal_handler());
    // erl_child_setup reaps port children, so the VM can ignore its own SIGCHLD.
    raw::set_disposition(libc::SIGCHLD, libc::SIG_IGN);

    let flags = arinsal_args::active_emulator_flags();
    if flags.ignore_break {
        set_ignore_break();
    } else if !flags.no_break_handler {
        raw::set_disposition(libc::SIGINT, raw::signal_handler());
        raw::set_disposition(libc::SIGQUIT, raw::signal_handler());
    }
    Ok(())
}

/// Port of `erts_set_signal` in erts/emulator/sys/unix/sys.c, OTP-29.1.1.
pub(crate) fn set_signal(
    process: &mut Process,
    signal: Term,
    action: Term,
) -> Result<Term, VmError> {
    let Some(name) = signal.as_atom().and_then(|atom| global_atoms().text(atom)) else {
        return Err(badarg());
    };
    let Some(signum) = signal_name_to_signum(name) else {
        return Err(badarg());
    };
    if action != Term::atom(arinsal_term::atoms::DEFAULT)
        && action != Term::atom(arinsal_term::atoms::IGNORE)
    {
        let runtime = process.runtime.as_ref().ok_or_else(badarg)?;
        raw::init_dispatcher(runtime)?;
    }
    let handler = if action == Term::atom(arinsal_term::atoms::IGNORE) {
        libc::SIG_IGN
    } else if action == Term::atom(arinsal_term::atoms::DEFAULT) {
        libc::SIG_DFL
    } else {
        raw::signal_handler()
    };
    raw::set_disposition(signum, handler);
    Ok(Term::atom(arinsal_term::atoms::OK))
}

/// Port of `erts_set_ignore_break` in erts/emulator/sys/unix/sys.c, OTP-29.1.1.
fn set_ignore_break() {
    for signum in [libc::SIGINT, libc::SIGQUIT, libc::SIGTSTP] {
        raw::set_disposition(signum, libc::SIG_IGN);
    }
}

fn badarg() -> VmError {
    VmError::Trap(crate::exceptions::Trap::error(Term::atom(
        arinsal_term::atoms::BADARG,
    )))
}

// Port of `signalterm_to_signum` in erts/emulator/sys/unix/sys.c, OTP-29.1.1.
fn signal_name_to_signum(name: &str) -> Option<i32> {
    Some(match name {
        "sighup" => libc::SIGHUP,
        "sigquit" => libc::SIGQUIT,
        "sigabrt" => libc::SIGABRT,
        "sigalrm" => libc::SIGALRM,
        "sigterm" => libc::SIGTERM,
        "sigusr1" => libc::SIGUSR1,
        "sigusr2" => libc::SIGUSR2,
        "sigchld" => libc::SIGCHLD,
        "sigcont" => libc::SIGCONT,
        "sigstop" => libc::SIGSTOP,
        "sigtstp" => libc::SIGTSTP,
        "sigwinch" => libc::SIGWINCH,
        #[cfg(any(target_os = "macos", target_os = "freebsd"))]
        "siginfo" => libc::SIGINFO,
        _ => return None,
    })
}

// Port of `signum_to_signalterm` in erts/emulator/sys/unix/sys.c, OTP-29.1.1.
fn signum_to_signal_name(signum: i32) -> Option<&'static str> {
    Some(match signum {
        libc::SIGHUP => "sighup",
        libc::SIGQUIT => "sigquit",
        libc::SIGABRT => "sigabrt",
        libc::SIGALRM => "sigalrm",
        libc::SIGTERM => "sigterm",
        libc::SIGUSR1 => "sigusr1",
        libc::SIGUSR2 => "sigusr2",
        libc::SIGCHLD => "sigchld",
        libc::SIGSTOP => "sigstop",
        libc::SIGTSTP => "sigtstp",
        libc::SIGCONT => "sigcont",
        libc::SIGWINCH => "sigwinch",
        #[cfg(any(target_os = "macos", target_os = "freebsd"))]
        libc::SIGINFO => "siginfo",
        _ => return None,
    })
}

// Port of `signal_dispatcher_thread_func` in erts/emulator/sys/unix/sys.c.
pub(super) fn dispatch_signal(runtime: &'static Runtime, signum: i32) -> bool {
    if signum == 0 {
        return true;
    }
    if signum == libc::SIGINT {
        crate::natives::tty::request_break();
    } else if let Some(name) = signum_to_signal_name(signum) {
        signal_notify_requested(runtime, name);
    } else {
        return false;
    }
    true
}

// Port of `signal_notify_requested` in erts/emulator/sys/unix/sys.c.
fn signal_notify_requested(runtime: &Runtime, signal: &str) {
    let Some(pid) = runtime.reg.whereis_proc_str("erl_signal_server") else {
        return;
    };
    let Ok(scheduler) = runtime.scheduler() else {
        return;
    };
    let mut heap = ProcessHeap::with_words(8);
    let message = TermBuilder::new(&mut heap)
        .tuple(&[
            Term::atom(arinsal_term::atoms::NOTIFY),
            crate::atom_cache::put(signal),
        ])
        .ok()
        .and_then(|term| Message::copy_from(term).ok());
    if let Some(message) = message {
        let _ = scheduler.send(pid, pid, message);
    }
}
