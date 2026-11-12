//! Process-wide OS environment and signal BIFs.

use crate::process::{Message, Runtime};
use crate::{Process, VmError};
use arinsal_term::{ProcessHeap, Term, TermBuilder, global_atoms};
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

fn badarg() -> VmError {
    VmError::Trap(crate::exceptions::Trap::error(Term::atom(
        arinsal_term::atoms::BADARG,
    )))
}

/// Runtime that receives a handled signal; the server pid is resolved per delivery.
#[derive(Clone)]
struct SignalTarget {
    runtime: &'static Runtime,
}

static SIGNAL_TARGETS: OnceLock<Mutex<HashMap<i32, SignalTarget>>> = OnceLock::new();
static SIGNAL_PIPE: OnceLock<i32> = OnceLock::new();

fn targets() -> &'static Mutex<HashMap<i32, SignalTarget>> {
    SIGNAL_TARGETS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Port of erts/emulator/sys/unix/sys.c:815 (erts_sys_unix_later_init), OTP-29.1.1: SIGTERM and
/// SIGUSR1 are handled from boot and reported to `erl_signal_server`.
pub(crate) fn install_boot_signals(runtime: &'static Runtime) -> Result<(), VmError> {
    ensure_signal_reader()?;
    for signal_num in [libc::SIGTERM, libc::SIGUSR1, libc::SIGQUIT] {
        targets()
            .lock()
            .unwrap()
            .insert(signal_num, SignalTarget { runtime });
        // SIGQUIT is installed by `init_break_handler` (only without +Bi / +Bd).
        if signal_num != libc::SIGQUIT {
            install_disposition(
                signal_num,
                signal_handler as *const () as libc::sighandler_t,
            )?;
        }
    }
    Ok(())
}

/// Port of erts/emulator/sys/unix/sys.c (init_break_handler), OTP-29.1.1: SIGQUIT goes to
/// `generic_signal_handler`, i.e. to `erl_signal_server` as `{notify, sigquit}`.
pub(crate) fn install_quit_handler() {
    if ensure_signal_reader().is_ok() {
        let _ = install_disposition(
            libc::SIGQUIT,
            signal_handler as *const () as libc::sighandler_t,
        );
    }
}

pub(crate) fn set_signal(
    process: &mut Process,
    signal: Term,
    action: Term,
) -> Result<Term, VmError> {
    let Some(name) = signal.as_atom().and_then(|a| global_atoms().text(a)) else {
        return Err(badarg());
    };
    let signal_num = match name {
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
        _ => return Err(badarg()),
    };
    let runtime = process.runtime.as_ref().ok_or_else(badarg)?;
    let server = SignalTarget { runtime };
    if action == Term::atom(arinsal_term::atoms::HANDLE) {
        // POSIX cannot catch SIGSTOP; erts accepts the request and the kernel keeps stopping.
        // Port of erts/emulator/sys/unix/sys.c:754 (erts_set_signal), OTP-29.1.1.
        if signal_num != libc::SIGSTOP {
            ensure_signal_reader()?;
            install_disposition(
                signal_num,
                signal_handler as *const () as libc::sighandler_t,
            )?;
        }
        targets().lock().unwrap().insert(signal_num, server);
    } else if action == Term::atom(arinsal_term::atoms::DEFAULT)
        || action == Term::atom(arinsal_term::atoms::IGNORE)
    {
        targets().lock().unwrap().remove(&signal_num);
        if signal_num != libc::SIGSTOP {
            // erts ignores SIGCHLD safely because erl_child_setup reaps port children; here the
            // VM waits for them itself, and SIG_IGN would auto-reap them (waitpid -> ECHILD).
            // The default disposition of SIGCHLD already discards the signal.
            let handler = if action == Term::atom(arinsal_term::atoms::DEFAULT)
                || signal_num == libc::SIGCHLD
            {
                libc::SIG_DFL
            } else {
                libc::SIG_IGN
            };
            install_disposition(signal_num, handler)?;
        }
    } else {
        return Err(badarg());
    }
    Ok(Term::atom(arinsal_term::atoms::OK))
}

/// `+Bi`: ignore the signals a terminal sends for Ctrl+C, Ctrl+Backslash and Ctrl+Z.
// Port of erts/emulator/sys/unix/sys.c:770 (erts_set_ignore_break), OTP-29.1.1.
pub(crate) fn set_ignore_break() {
    for signum in [libc::SIGINT, libc::SIGQUIT, libc::SIGTSTP] {
        // Only an invalid signal number fails.
        let _ = install_disposition(signum, libc::SIG_IGN);
    }
}

// Port of erts/emulator/sys/unix/sys.c:437 (sys_signal), OTP-29.1.1.
fn install_disposition(signum: i32, handler: libc::sighandler_t) -> Result<(), VmError> {
    // SAFETY: zeroed sigaction is the POSIX starting point; sigemptyset and
    // sa_handler/sa_flags are filled in before sigaction is called.
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    // SAFETY: sigemptyset initializes the mask; sigaction installs the disposition for this signal.
    unsafe {
        if libc::sigemptyset(&mut action.sa_mask) != 0 {
            return Err(badarg());
        }
        action.sa_flags = 0;
        action.sa_sigaction = handler;
        if libc::sigaction(signum, &action, std::ptr::null_mut()) != 0 {
            return Err(badarg());
        }
    }
    Ok(())
}

extern "C" fn signal_handler(sig: libc::c_int) {
    let Some(&fd) = SIGNAL_PIPE.get() else {
        return;
    };
    let byte = sig as u8;
    // SAFETY: write to the self-pipe is async-signal-safe and the fd stays open.
    unsafe {
        libc::write(fd, (&byte as *const u8).cast(), 1);
    }
}

fn ensure_signal_reader() -> Result<(), VmError> {
    if SIGNAL_PIPE.get().is_some() {
        return Ok(());
    }
    let mut fds = [0; 2];
    // SAFETY: pipe writes two fresh descriptors; mark both close-on-exec before
    // publishing them so concurrently spawned port children cannot inherit them.
    let rc = crate::port::cloexec_publish(|| unsafe {
        let rc = libc::pipe(fds.as_mut_ptr());
        if rc == 0
            && (libc::fcntl(fds[0], libc::F_SETFD, libc::FD_CLOEXEC) < 0
                || libc::fcntl(fds[1], libc::F_SETFD, libc::FD_CLOEXEC) < 0)
        {
            let error = std::io::Error::last_os_error();
            libc::close(fds[0]);
            libc::close(fds[1]);
            Err(error)
        } else {
            Ok(rc)
        }
    });
    let rc = match rc {
        Err(error) => {
            return Err(VmError::Unsupported(format!(
                "signal pipe close-on-exec: {error}"
            )));
        }
        Ok(rc) => rc,
    };
    if rc != 0 {
        return Err(badarg());
    }
    let read_fd = fds[0];
    let write_fd = fds[1];
    if SIGNAL_PIPE.set(write_fd).is_err() {
        // SAFETY: another thread won the race; these descriptors are still ours to close.
        unsafe {
            libc::close(read_fd);
            libc::close(write_fd);
        }
        return Ok(());
    }
    std::thread::Builder::new()
        .name("arinsal-signal-dispatch".into())
        .spawn(move || {
            let mut buf = [0u8; 32];
            loop {
                // SAFETY: read_fd is the read end of the signal self-pipe owned by this thread.
                let n = unsafe { libc::read(read_fd, buf.as_mut_ptr().cast(), buf.len()) };
                if n < 0 {
                    let err = std::io::Error::last_os_error();
                    if err.kind() == std::io::ErrorKind::Interrupted
                        || err.kind() == std::io::ErrorKind::WouldBlock
                    {
                        std::thread::yield_now();
                        continue;
                    }
                    break;
                }
                if n == 0 {
                    break;
                }
                for byte in &buf[..n as usize] {
                    let received = i32::from(*byte);
                    let target = targets().lock().unwrap().get(&received).cloned();
                    if let Some(target) = target {
                        deliver_signal(target, received);
                    }
                }
            }
        })
        .map_err(|_| badarg())?;
    Ok(())
}

fn deliver_signal(target: SignalTarget, signal: i32) {
    let name = match signal {
        libc::SIGHUP => "sighup",
        libc::SIGQUIT => "sigquit",
        libc::SIGABRT => "sigabrt",
        libc::SIGALRM => "sigalrm",
        libc::SIGTERM => "sigterm",
        libc::SIGUSR1 => "sigusr1",
        libc::SIGUSR2 => "sigusr2",
        libc::SIGCHLD => "sigchld",
        libc::SIGCONT => "sigcont",
        libc::SIGSTOP => "sigstop",
        libc::SIGTSTP => "sigtstp",
        libc::SIGWINCH => "sigwinch",
        #[cfg(any(target_os = "macos", target_os = "freebsd"))]
        libc::SIGINFO => "siginfo",
        _ => return,
    };
    // Port of erts/emulator/sys/unix/sys.c:594 (signal_notify_requested), OTP-29.1.1: the
    // server is looked up per signal and a missing one drops it.
    let runtime = target.runtime;
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
            crate::atom_cache::put(name),
        ])
        .ok()
        .and_then(|term| Message::copy_from(term).ok());
    if let Some(message) = message {
        let _ = scheduler.send(pid, pid, message);
    }
    // The send wakes the server's scheduler only when that scheduler already
    // sleeps. Poke the rest: a scheduler that publishes its sleeping flag after
    // the send would otherwise stay in `scheduler_wait` and never run
    // `erl_signal_server` (sys.c signal_notify_requested plus erts_sched_poke).
    scheduler.poke_schedulers();
}
