//! Process-aware `prim_tty` select delivery.
//!
//! `tty_select/2` and a successful `read_nif/3` arm a one-shot poll, matching
//! `enif_select` in `prim_tty_nif.c` (`tty_select_nif`, `tty_read_nif`). A
//! helper thread waits for readability and sends `{select, TTY, Ref, ready_input}`
//! through the scheduler. Local calls inside `prim_tty` reach the NIF body
//! directly; the heap address recorded on earlier scheduler calls identifies
//! the owner. External calls record the owner immediately before the NIF runs.

use crate::process::Message;
use crate::{Process, Vm, VmError, exceptions};
use arinsal_bifs::{Ctx, FragmentingHeap};
use arinsal_etf::OwnedTerm;
use arinsal_sched::{Pid, RunCtx, Scheduler};
use arinsal_term::{ProcessHeap, Term, TermBuilder, from_owned, global_atoms};
use std::cell::RefCell;
use std::collections::HashMap;
use std::os::fd::RawFd;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::{Arc, Mutex, Once, OnceLock, Weak};
use std::thread;

#[derive(Clone)]
struct Target {
    pid: Pid,
    scheduler: Weak<Scheduler<Process>>,
}

struct Watch {
    generation: u64,
    fd: RawFd,
    tty: OwnedTerm,
    reference: OwnedTerm,
    target: Target,
}

struct Hub {
    wake_write: RawFd,
}

thread_local! {
    static CURRENT: RefCell<Option<(usize, Target)>> = const { RefCell::new(None) };
}

fn registry() -> &'static Mutex<HashMap<usize, Target>> {
    static REGISTRY: OnceLock<Mutex<HashMap<usize, Target>>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

fn hub() -> &'static Hub {
    static HUB: std::sync::OnceLock<Hub> = std::sync::OnceLock::new();
    HUB.get_or_init(|| {
        let mut pipe = [-1; 2];
        // SAFETY: pipe writes two new descriptors on success.
        let status = unsafe { libc::pipe(pipe.as_mut_ptr()) };
        assert_eq!(status, 0, "tty select wake pipe");
        for fd in pipe {
            // SAFETY: both pipe ends are open descriptors from the successful pipe call.
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
            if flags >= 0 {
                // SAFETY: the same descriptor stays open and the flag word is from F_GETFL.
                unsafe {
                    libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
                }
            }
        }
        let wake_read = pipe[0];
        thread::Builder::new()
            .name("arinsal-tty-select".into())
            .spawn(move || poll_loop(wake_read))
            .expect("tty select thread");
        Hub {
            wake_write: pipe[1],
        }
    })
}

fn shared_watches() -> &'static Mutex<Vec<Watch>> {
    static WATCHES: std::sync::OnceLock<Mutex<Vec<Watch>>> = std::sync::OnceLock::new();
    WATCHES.get_or_init(|| Mutex::new(Vec::new()))
}

fn install() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        // Touch the hub so the poll thread exists before the first arm.
        let _ = hub();
        arinsal_nif_tty::set_arm_hook(arm_hook);
        install_break();
    });
}

/// First Ctrl-C is being handled. A second one aborts, as in `break_requested`.
static BREAKING: AtomicBool = AtomicBool::new(false);
static BREAK_WRITE: AtomicI32 = AtomicI32::new(-1);

/// Port of erts/emulator/sys/unix/sys.c:626 (`request_break`) and
/// erts/emulator/beam/break.c:571 (`do_break`), OTP-29.1.1.
/// The handler only records the request; the menu runs on `arinsal-break`.
extern "C" fn sigint_handler(_signum: i32) {
    if BREAKING.swap(true, Ordering::SeqCst) {
        // SAFETY: a second Ctrl-C must leave immediately, without running destructors.
        unsafe { libc::_exit(0) };
    }
    let fd = BREAK_WRITE.load(Ordering::Relaxed);
    if fd >= 0 {
        let byte = 1u8;
        // SAFETY: the break pipe write end stays open and one byte is in-bounds.
        unsafe {
            libc::write(fd, std::ptr::from_ref(&byte).cast(), 1);
        }
    }
}

fn install_break() {
    // SAFETY: isatty only inspects descriptor 0.
    if unsafe { libc::isatty(0) } == 0 {
        return;
    }
    let mut pipe = [-1; 2];
    // SAFETY: pipe writes two new descriptors on success.
    if unsafe { libc::pipe(pipe.as_mut_ptr()) } != 0 {
        return;
    }
    BREAK_WRITE.store(pipe[1], Ordering::Relaxed);
    let read = pipe[0];
    thread::Builder::new()
        .name("arinsal-break".into())
        .spawn(move || break_loop(read))
        .expect("break thread");
    // SAFETY: zeroed sigaction is initialized before it is installed.
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        libc::sigemptyset(&mut action.sa_mask);
        action.sa_flags = 0;
        action.sa_sigaction = sigint_handler as *const () as libc::sighandler_t;
        libc::sigaction(libc::SIGINT, &action, std::ptr::null_mut());
    }
}

fn wake_poll() {
    let byte = 1u8;
    // SAFETY: the tty wake write end stays open for the process lifetime.
    unsafe {
        libc::write(hub().wake_write, std::ptr::from_ref(&byte).cast(), 1);
    }
}

fn tty_write(fd: RawFd, bytes: &[u8]) {
    // SAFETY: `bytes` is a live buffer and `fd` is stdout or stderr for this process.
    unsafe {
        libc::write(fd, bytes.as_ptr().cast(), bytes.len());
    }
}

fn abort_break(code: i32) -> ! {
    // SAFETY: the break menu exits without running destructors, matching `erts_exit`.
    unsafe { libc::_exit(code) }
}

fn break_loop(read_fd: RawFd) {
    const HELP: &str = "BREAK: (a)bort (A)bort with dump (c)ontinue (p)roc info (i)nfo\n       (l)oaded (v)ersion (k)ill (D)b-tables (d)istribution\n";
    let mut buf = [0u8; 16];
    loop {
        // SAFETY: buf is writable and the break read end stays open.
        let n = unsafe { libc::read(read_fd, buf.as_mut_ptr().cast(), buf.len()) };
        if n <= 0 {
            continue;
        }
        // Drop the tty from the poll set before reading the menu key.
        wake_poll();
        tty_write(1, format!("\n\u{1b}[J{HELP}").as_bytes());
        loop {
            let mut key = [0u8; 1];
            // SAFETY: one-byte stack buffer and stdin stays open.
            let got = unsafe { libc::read(0, key.as_mut_ptr().cast(), 1) };
            if got <= 0 {
                abort_break(0);
            }
            match key[0] {
                b'a' | b'q' | b'*' => abort_break(0),
                b'A' => {
                    tty_write(2, b"Crash dump requested by user\n");
                    abort_break(1);
                }
                b'c' => break,
                b'v' => {
                    tty_write(1, b"Erlang/OTP 29 [erts-17.1] [arinsal 0.0.1]\n");
                    break;
                }
                b'\n' | b'\r' => continue,
                other => {
                    tty_write(
                        1,
                        format!(
                            "Invalid option '{}'. Please enter one of the following:\n{HELP}",
                            other as char
                        )
                        .as_bytes(),
                    );
                }
            }
        }
        BREAKING.store(false, Ordering::SeqCst);
        wake_poll();
    }
}

/// Record the scheduler pid that owns this process heap.
///
/// Local `prim_tty` calls are `NativeBody` and never enter [`call`], so the
/// interpreter records the owner immediately before those NIF bodies run.
/// A remote call records it here as well. The poll thread delivers
/// `{select, TTY, Ref, ready_input}` to that pid.
pub(crate) fn note_caller(process: &Process, ctx: &RunCtx<'_, Message>) {
    let Some(runtime) = process.runtime.as_ref() else {
        return;
    };
    let Ok(scheduler) = runtime.scheduler() else {
        return;
    };
    let key = std::ptr::from_ref(&process.heap) as usize;
    let target = Target {
        pid: ctx.pid(),
        scheduler: Arc::downgrade(&scheduler),
    };
    registry().lock().unwrap().insert(key, target.clone());
    CURRENT.with(|slot| *slot.borrow_mut() = Some((key, target)));
    install();
}

fn arm_hook(token: usize, fd: RawFd, tty: OwnedTerm, reference: OwnedTerm) {
    if fd < 0 {
        return;
    }
    let target = (token != 0)
        .then(|| registry().lock().unwrap().get(&token).cloned())
        .flatten()
        .or_else(|| CURRENT.with(|slot| slot.borrow().as_ref().map(|(_, target)| target.clone())));
    let Some(target) = target else {
        return;
    };
    let generation = {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    };
    {
        let mut watches = shared_watches().lock().unwrap();
        watches.retain(|watch| watch.tty != tty);
        watches.push(Watch {
            generation,
            fd,
            tty,
            reference,
            target,
        });
    }
    let byte = 1u8;
    // SAFETY: the wake write end stays open for the process lifetime.
    unsafe {
        libc::write(hub().wake_write, std::ptr::from_ref(&byte).cast(), 1);
    }
}

fn poll_loop(wake_read: RawFd) {
    // Port of prim_tty_nif.c enif_select registrations through erl_check_io.c:1228, OTP-29.1.1.
    loop {
        // While the break menu is reading stdin, leave the tty out of the set
        // so the shell reader does not consume the menu key.
        let snapshot: Vec<(u64, RawFd)> = if BREAKING.load(Ordering::SeqCst) {
            Vec::new()
        } else {
            shared_watches()
                .lock()
                .unwrap()
                .iter()
                .map(|watch| (watch.generation, watch.fd))
                .collect()
        };
        let mut fds = Vec::with_capacity(snapshot.len() + 1);
        let interest = crate::check_io::InterestSet {
            readable: true,
            writable: false,
        };
        fds.push((wake_read, interest));
        fds.extend(snapshot.iter().map(|(_, fd)| (*fd, interest)));
        // Port of one-shot `driver_select`/`enif_select` wake delivery.
        let (ready_fd, ready) = match crate::check_io::wait_any_nif_timeout(&fds, None) {
            Ok(Some(ready)) => ready,
            Ok(None) => continue,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => continue,
        };
        if ready_fd == wake_read && (ready.readable || ready.closed || ready.error) {
            let mut buf = [0u8; 64];
            loop {
                // SAFETY: buf is writable and the wake read end stays open.
                let n = unsafe { libc::read(wake_read, buf.as_mut_ptr().cast(), buf.len()) };
                if n <= 0 {
                    break;
                }
            }
        }
        let ready_gen: Vec<u64> = snapshot
            .iter()
            .filter_map(|(generation, fd)| {
                (*fd == ready_fd && (ready.readable || ready.closed || ready.error))
                    .then_some(*generation)
            })
            .collect();
        if ready_gen.is_empty() {
            continue;
        }
        let fired = {
            let mut watches = shared_watches().lock().unwrap();
            let mut keep = Vec::new();
            let mut fired = Vec::new();
            for watch in watches.drain(..) {
                if ready_gen.contains(&watch.generation) {
                    fired.push(watch);
                } else {
                    keep.push(watch);
                }
            }
            *watches = keep;
            fired
        };
        for watch in fired {
            deliver(watch);
        }
    }
}

fn deliver(watch: Watch) {
    let Some(scheduler) = watch.target.scheduler.upgrade() else {
        return;
    };
    let Some(message) = select_message(&watch.tty, &watch.reference) else {
        return;
    };
    let _ = scheduler.send(watch.target.pid, watch.target.pid, message);
}

fn atom(name: &str) -> Term {
    Term::atom(global_atoms().intern(name).expect("built-in atom"))
}

fn select_message(tty: &OwnedTerm, reference: &OwnedTerm) -> Option<Message> {
    let mut heap = ProcessHeap::with_words(128);
    let tty = from_owned(tty, &mut heap).ok()?;
    let reference = from_owned(reference, &mut heap).ok()?;
    let term = TermBuilder::new(&mut heap)
        .tuple(&[atom("select"), tty, reference, atom("ready_input")])
        .ok()?;
    Message::copy_from(term).ok()
}

/// `prim_tty` NIFs. These are the `arinsal_nif_tty::lookup` arms this family invokes.
pub(crate) const IMPLEMENTED: &[(&str, &str, u8)] = &[
    ("prim_tty", "isatty", 1),
    ("prim_tty", "tty_create", 1),
    ("prim_tty", "tty_init", 2),
    ("prim_tty", "setlocale", 1),
    ("prim_tty", "tty_select", 2),
    ("prim_tty", "tty_window_size", 1),
    ("prim_tty", "tty_encoding", 1),
    ("prim_tty", "tty_is_open", 2),
    ("prim_tty", "write_nif", 2),
    ("prim_tty", "read_nif", 3),
    ("prim_tty", "isprint", 1),
    ("prim_tty", "wcwidth", 1),
    ("prim_tty", "wcswidth", 1),
    ("prim_tty", "sizeof_wchar", 0),
    ("prim_tty", "setupterm_nif", 0),
    ("prim_tty", "tigetnum_nif", 1),
    ("prim_tty", "tigetflag_nif", 1),
    ("prim_tty", "tigetstr_nif", 1),
    ("prim_tty", "tinfo_nif", 0),
    ("prim_tty", "tputs_nif", 2),
];

pub(crate) fn recognizes(module: &str, function: &str, arity: u8) -> bool {
    super::listed(IMPLEMENTED, module, function, arity)
}

pub(super) fn call(
    _vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    module: &str,
    function: &str,
    args: super::NativeArgs<'_>,
) -> Option<Result<Term, VmError>> {
    args.with_values(process, |process, values| {
        call_values(process, ctx, module, function, values)
    })
}

fn call_values(
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    module: &str,
    function: &str,
    args: &[Term],
) -> Option<Result<Term, VmError>> {
    if module == "erlang" && matches!(function, "atom_to_list" | "list_to_atom" | "++") {
        // prim_tty's reader registers its name, then calls tty_select locally.
        // Recording the owner here lets that local NIF deliver to this process.
        note_caller(process, ctx);
        return None;
    }
    let arity = args.len() as u8;
    if !recognizes(module, function, arity) {
        return None;
    }
    let native = arinsal_nif_tty::lookup(module, function, arity)?;
    note_caller(process, ctx);
    let result = {
        let mut heap = FragmentingHeap(&mut process.heap);
        let mut bif_ctx = Ctx::new(&mut heap);
        native(&mut bif_ctx, args)
    };
    Some(result.map_err(|error| exceptions::bif_error(process, module, function, args, error)))
}
