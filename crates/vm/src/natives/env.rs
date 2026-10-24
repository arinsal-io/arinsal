//! Process-wide OS environment and signal BIFs.

use crate::process::Message;
use crate::process::Runtime;
use crate::{Process, Vm, VmError};
use arinsal_sched::RunCtx;
use arinsal_term::{ProcessHeap, Term, TermBuilder, TermKind, global_atoms};
use std::collections::HashMap;
use std::ffi::OsString;
use std::sync::{Mutex, OnceLock, RwLock};

pub(crate) type Environment = Vec<(OsString, OsString)>;
static ENVIRONMENT: OnceLock<RwLock<Environment>> = OnceLock::new();

fn environment() -> &'static RwLock<Environment> {
    ENVIRONMENT.get_or_init(|| RwLock::new(std::env::vars_os().collect()))
}

/// A variable of the VM-owned environment (`erl_drv_getenv`).
pub(crate) fn get(key: &[u8]) -> Option<Vec<u8>> {
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    let name = std::ffi::OsStr::from_bytes(key);
    environment()
        .read()
        .unwrap()
        .iter()
        .find(|(candidate, _)| candidate == name)
        .map(|(_, value)| value.clone().into_vec())
}

/// Set a variable of the VM-owned environment (`erl_drv_putenv`).
pub(crate) fn put(key: &[u8], value: &[u8]) {
    use std::os::unix::ffi::OsStringExt;
    seed_raw(
        OsString::from_vec(key.to_vec()),
        OsString::from_vec(value.to_vec()),
    );
}

fn seed_raw(name: OsString, value: OsString) {
    let mut env = environment().write().unwrap();
    if let Some((_, existing)) = env.iter_mut().find(|(key, _)| *key == name) {
        *existing = value;
    } else {
        env.push((name, value));
    }
}

/// Snapshot of the VM-owned environment for a newly spawned child.
pub(crate) fn snapshot() -> Environment {
    environment().read().unwrap().clone()
}

/// Set variables in the VM-owned environment before boot (erlexec's `set_env`).
pub(crate) fn seed(vars: &[(String, String)]) {
    let mut env = environment().write().unwrap();
    for (name, value) in vars {
        let (name, value) = (OsString::from(name), OsString::from(value));
        if let Some((_, existing)) = env.iter_mut().find(|(key, _)| *key == name) {
            *existing = value;
        } else {
            env.push((name, value));
        }
    }
}

fn atom(name: &str) -> Term {
    Term::atom(global_atoms().intern(name).expect("built-in atom"))
}

fn badarg() -> VmError {
    VmError::Trap(crate::exceptions::Trap::error(atom("badarg")))
}

/// `os` environment BIFs this family dispatches. The match below is this table.
pub(crate) const IMPLEMENTED: &[(&str, &str, u8)] = &[
    ("os", "getenv", 1),
    // mix_loop1: Elixir System.get_env/0 calls os:env/0, a list of {Name, Value}.
    ("os", "env", 0),
    ("os", "putenv", 2),
    ("os", "unsetenv", 1),
    ("os", "set_signal", 2),
];

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn recognizes(module: &str, function: &str, arity: u8) -> bool {
    super::listed(IMPLEMENTED, module, function, arity)
}

type Handler =
    fn(&mut Vm, &mut Process, &mut RunCtx<'_, Message>, &[Term]) -> Result<Term, VmError>;

pub(crate) fn handler(module: &str, function: &str, arity: u8) -> Option<Handler> {
    match (module, function, arity) {
        ("os", "getenv", 1) => Some(call_getenv_one),
        ("os", "env", 0) => Some(call_env_all),
        ("os", "putenv", 2) => Some(call_putenv),
        ("os", "unsetenv", 1) => Some(call_unsetenv),
        ("os", "set_signal", 2) => Some(call_set_signal),
        _ => None,
    }
}

fn call_env_all(
    _vm: &mut Vm,
    process: &mut Process,
    _ctx: &mut RunCtx<'_, Message>,
    _args: &[Term],
) -> Result<Term, VmError> {
    env_all(process)
}

fn call_getenv_one(
    _vm: &mut Vm,
    process: &mut Process,
    _ctx: &mut RunCtx<'_, Message>,
    args: &[Term],
) -> Result<Term, VmError> {
    getenv_one(process, args[0])
}

fn call_putenv(
    _vm: &mut Vm,
    process: &mut Process,
    _ctx: &mut RunCtx<'_, Message>,
    args: &[Term],
) -> Result<Term, VmError> {
    putenv(process, args[0], args[1])
}

fn call_unsetenv(
    _vm: &mut Vm,
    process: &mut Process,
    _ctx: &mut RunCtx<'_, Message>,
    args: &[Term],
) -> Result<Term, VmError> {
    unsetenv(process, args[0])
}

fn call_set_signal(
    _vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    args: &[Term],
) -> Result<Term, VmError> {
    set_signal(process, ctx, args[0], args[1])
}

pub(super) fn call(
    vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    module: &str,
    function: &str,
    args: &[Term],
) -> Option<Result<Term, VmError>> {
    handler(module, function, args.len() as u8).map(|handle| handle(vm, process, ctx, args))
}

fn text(term: Term) -> Result<String, VmError> {
    let mut out = String::new();
    let mut cursor = term;
    while cursor != Term::NIL {
        if cursor.classify() != TermKind::List {
            return Err(badarg());
        }
        // SAFETY: The cons cells are read while the caller's process heap is live.
        let (head, tail) = unsafe { cursor.cons_ref() }.ok_or_else(badarg)?;
        let code = head
            .as_small()
            .filter(|n| (0..=0x10ffff).contains(n))
            .ok_or_else(badarg)?;
        out.push(char::from_u32(code as u32).ok_or_else(badarg)?);
        cursor = tail;
    }
    Ok(out)
}

fn valid_name(name: Term) -> Result<OsString, VmError> {
    let name = text(name)?;
    if name.contains('=') || name.contains('\0') {
        return Err(badarg());
    }
    Ok(name.into())
}

fn string(process: &mut Process, value: &str) -> Result<Term, VmError> {
    let mut tail = Term::NIL;
    for ch in value.chars().rev() {
        let code = Term::small(i64::from(ch as u32)).ok_or_else(badarg)?;
        let mut heap = crate::ProcessHeapHandle(&mut process.heap);
        tail = TermBuilder::new(&mut heap)
            .cons(code, tail)
            .map_err(|_| badarg())?;
    }
    Ok(tail)
}

fn env_all(process: &mut Process) -> Result<Term, VmError> {
    // Port of lib/kernel/src/os.erl (env/0), OTP-29.1.1: [{Name, Value}].
    let entries = environment().read().unwrap().clone();
    let mut result = Term::NIL;
    for (key, value) in entries.into_iter().rev() {
        let key = string(process, &key.to_string_lossy())?;
        let value = string(process, &value.to_string_lossy())?;
        let mut heap = crate::ProcessHeapHandle(&mut process.heap);
        let pair = TermBuilder::new(&mut heap)
            .tuple(&[key, value])
            .map_err(|_| badarg())?;
        result = TermBuilder::new(&mut heap)
            .cons(pair, result)
            .map_err(|_| badarg())?;
    }
    Ok(result)
}

fn getenv_one(process: &mut Process, name: Term) -> Result<Term, VmError> {
    let name = valid_name(name)?;
    match environment()
        .read()
        .unwrap()
        .iter()
        .find(|(key, _)| *key == name)
    {
        Some((_, value)) => string(process, &value.to_string_lossy()),
        None => Ok(atom("false")),
    }
}

fn putenv(process: &mut Process, name: Term, value: Term) -> Result<Term, VmError> {
    let name = valid_name(name)?;
    let value: OsString = text(value)?.into();
    if value.to_string_lossy().contains('\0') {
        return Err(badarg());
    }
    let mut env = environment().write().unwrap();
    if let Some((_, existing)) = env.iter_mut().find(|(key, _)| *key == name) {
        *existing = value;
    } else {
        env.push((name, value));
    }
    let _ = process;
    Ok(atom("true"))
}

fn unsetenv(_process: &mut Process, name: Term) -> Result<Term, VmError> {
    let name = valid_name(name)?;
    environment()
        .write()
        .unwrap()
        .retain(|(key, _)| *key != name);
    Ok(atom("true"))
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
    for signal_num in [libc::SIGTERM, libc::SIGUSR1] {
        targets()
            .lock()
            .unwrap()
            .insert(signal_num, SignalTarget { runtime });
        install_disposition(
            signal_num,
            signal_handler as *const () as libc::sighandler_t,
        )?;
    }
    Ok(())
}

fn set_signal(
    process: &mut Process,
    _ctx: &mut RunCtx<'_, Message>,
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
    if action == atom("handle") {
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
    } else if action == atom("default") || action == atom("ignore") {
        targets().lock().unwrap().remove(&signal_num);
        if signal_num != libc::SIGSTOP {
            // erts ignores SIGCHLD safely because erl_child_setup reaps port children; here the
            // VM waits for them itself, and SIG_IGN would auto-reap them (waitpid -> ECHILD).
            // The default disposition of SIGCHLD already discards the signal.
            let handler = if action == atom("default") || signal_num == libc::SIGCHLD {
                libc::SIG_DFL
            } else {
                libc::SIG_IGN
            };
            install_disposition(signal_num, handler)?;
        }
    } else {
        return Err(badarg());
    }
    Ok(atom("ok"))
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
        .tuple(&[atom("notify"), atom(name)])
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
