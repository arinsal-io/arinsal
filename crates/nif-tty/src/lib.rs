//! Native operations for OTP 29.1.1 `prim_tty` on Unix.
//!
//! `tty_select/2` records the Erlang read reference and, when the VM has
//! installed [`set_arm_hook`], asks it to watch the input fd. The hook runs
//! again after a successful [`read_nif`] so the next readable event is
//! delivered, matching `enif_select` in `tty_read_nif`. [`wait_readable`]
//! remains a blocking poll path for tests. The VM owns ref-shaped resources
//! and must call [`release`] when one dies.

use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::ptr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use arinsal_bifs::{BifError, BifFn, Ctx};
use arinsal_etf::OwnedTerm as O;
use arinsal_term::{ExportEntry, FunEntry, HeapAlloc, Node, Term, from_owned, to_owned};
use num_traits::ToPrimitive;

const MAGIC: u32 = 0x5454_5921;
static NEXT_ID: AtomicU64 = AtomicU64::new(1);
static HANDLES: OnceLock<Mutex<HashMap<u64, Arc<Tty>>>> = OnceLock::new();
static TERMINFO: Mutex<()> = Mutex::new(());
static SAVED_TERM: Mutex<usize> = Mutex::new(0);
static EXIT_HOOK: OnceLock<()> = OnceLock::new();

extern "C" fn restore_at_exit() {
    if let Some(table) = HANDLES.get() {
        for tty in table.lock().unwrap().values() {
            let state = tty.state.lock().unwrap();
            if let Some(original) = state.original.as_ref() {
                // SAFETY: the table retains the resource and its output fd during this callback.
                unsafe { libc::tcsetattr(tty.output.as_raw_fd(), libc::TCSANOW, original) };
            }
        }
    }
}

#[link(name = "ncurses")]
unsafe extern "C" {
    #[link_name = "setupterm"]
    fn c_setupterm(
        term: *const libc::c_char,
        fd: libc::c_int,
        err: *mut libc::c_int,
    ) -> libc::c_int;
    fn tgetnum(cap: *const libc::c_char) -> libc::c_int;
    fn tgetflag(cap: *const libc::c_char) -> libc::c_int;
    fn tigetstr(cap: *const libc::c_char) -> *mut libc::c_char;
    fn tparm(cap: *const libc::c_char, ...) -> *mut libc::c_char;
    fn tputs(
        cap: *const libc::c_char,
        affcnt: libc::c_int,
        putc: extern "C" fn(libc::c_int) -> libc::c_int,
    ) -> libc::c_int;
    fn del_curterm(term: *mut libc::c_void) -> libc::c_int;
    static mut cur_term: *mut libc::c_void;
    static boolnames: [*const libc::c_char; 1];
    static boolcodes: [*const libc::c_char; 1];
    static boolfnames: [*const libc::c_char; 1];
    static numnames: [*const libc::c_char; 1];
    static numcodes: [*const libc::c_char; 1];
    static numfnames: [*const libc::c_char; 1];
    static strnames: [*const libc::c_char; 1];
    static strcodes: [*const libc::c_char; 1];
    static strfnames: [*const libc::c_char; 1];
}

unsafe extern "C" {
    fn wcwidth(wc: libc::wchar_t) -> libc::c_int;
    fn wcswidth(wcs: *const libc::wchar_t, n: libc::size_t) -> libc::c_int;
    fn isprint(c: libc::c_int) -> libc::c_int;
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Unavailable,
    Disabled,
    Enabled,
}

struct State {
    original: Option<libc::termios>,
    current: Option<libc::termios>,
    mode: Mode,
    read_ref: Option<O>,
}

struct Tty {
    input: OwnedFd,
    output: OwnedFd,
    state: Mutex<State>,
}

impl Drop for Tty {
    fn drop(&mut self) {
        let state = self.state.lock().unwrap();
        if let Some(original) = state.original.as_ref() {
            // SAFETY: the fd remains owned through this destructor and `original` came from tcgetattr.
            unsafe { libc::tcsetattr(self.output.as_raw_fd(), libc::TCSANOW, original) };
        }
    }
}

fn handles() -> &'static Mutex<HashMap<u64, Arc<Tty>>> {
    HANDLES.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Return the implementation of an OTP 29.1.1 `prim_tty` NIF.
pub fn lookup(module: &str, name: &str, arity: u8) -> Option<BifFn> {
    if module != "prim_tty" {
        return None;
    }
    Some(match (name, arity) {
        ("isatty", 1) => isatty_nif,
        ("tty_create", 1) => tty_create_nif,
        ("tty_init", 2) => tty_init_nif,
        ("setlocale", 1) => setlocale_nif,
        ("tty_select", 2) => tty_select_nif,
        ("tty_window_size", 1) => tty_window_size_nif,
        ("tty_encoding", 1) => tty_encoding_nif,
        ("tty_is_open", 2) => tty_is_open_nif,
        ("write_nif", 2) => write_nif,
        ("read_nif", 3) => read_nif,
        ("isprint", 1) => isprint_nif,
        ("wcwidth", 1) => wcwidth_nif,
        ("wcswidth", 1) => wcswidth_nif,
        ("sizeof_wchar", 0) => sizeof_wchar_nif,
        ("setupterm_nif", 0) => setupterm_nif,
        ("tigetnum_nif", 1) => tigetnum_nif,
        ("tigetflag_nif", 1) => tigetflag_nif,
        ("tigetstr_nif", 1) => tigetstr_nif,
        ("tinfo_nif", 0) => tinfo_nif,
        ("tputs_nif", 2) => tputs_nif,
        _ => return None,
    })
}

struct Heap<'a>(&'a mut dyn HeapAlloc);
impl HeapAlloc for Heap<'_> {
    fn alloc(&mut self, words: usize) -> Option<*mut u64> {
        self.0.alloc(words)
    }
    fn retain_binary(&mut self, value: Arc<Vec<u8>>) {
        self.0.retain_binary(value)
    }
    fn retain_writable_binary(
        &mut self,
        value: Arc<arinsal_term::WritableBinary>,
    ) -> Result<(), arinsal_term::TermError> {
        self.0.retain_writable_binary(value)
    }
    fn supports_writable_binary(&self) -> bool {
        self.0.supports_writable_binary()
    }
    fn retain_node(&mut self, value: Arc<Node>) {
        self.0.retain_node(value)
    }
    fn retain_fun(&mut self, value: Arc<FunEntry>) {
        self.0.retain_fun(value)
    }
    fn retain_export(&mut self, value: Arc<ExportEntry>) {
        self.0.retain_export(value)
    }
}
type Outcome = Result<O, BifError>;
fn call(
    ctx: &mut Ctx<'_>,
    args: &[Term],
    f: impl FnOnce(&[O]) -> Outcome,
) -> Result<Term, BifError> {
    let args = args
        .iter()
        .map(|a| to_owned(*a).map_err(|_| BifError::BADARG))
        .collect::<Result<Vec<_>, _>>()?;
    let result = f(&args)?;
    from_owned(&result, &mut Heap(ctx.heap)).map_err(|_| BifError::SystemLimit)
}
fn atom(s: &str) -> O {
    O::atom(s)
}
fn pair(a: O, b: O) -> O {
    O::tuple(vec![a, b])
}
fn ok(v: O) -> O {
    pair(atom("ok"), v)
}
fn error(s: &str) -> O {
    pair(atom("error"), atom(s))
}
fn errno_error(function: &str) -> O {
    let code = io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(libc::EINVAL);
    let name = match code {
        libc::EPERM => "eperm",
        libc::ESRCH => "esrch",
        libc::ENXIO => "enxio",
        libc::E2BIG => "e2big",
        libc::ENOEXEC => "enoexec",
        libc::EBADF => "ebadf",
        libc::ECHILD => "echild",
        libc::EDEADLK => "edeadlk",
        libc::EIO => "eio",
        libc::EINTR => "eintr",
        libc::EAGAIN => "eagain",
        libc::EBUSY => "ebusy",
        libc::EEXIST => "eexist",
        libc::EXDEV => "exdev",
        libc::ENODEV => "enodev",
        libc::ENOTDIR => "enotdir",
        libc::EISDIR => "eisdir",
        libc::ENOTTY => "enotty",
        libc::EINVAL => "einval",
        libc::ENFILE => "enfile",
        libc::EMFILE => "emfile",
        libc::ENOMEM => "enomem",
        libc::EFBIG => "efbig",
        libc::ENOSPC => "enospc",
        libc::ESPIPE => "espipe",
        libc::EROFS => "erofs",
        libc::EMLINK => "emlink",
        libc::EPIPE => "epipe",
        libc::EDOM => "edom",
        libc::ERANGE => "erange",
        libc::ENAMETOOLONG => "enametoolong",
        libc::ENOTEMPTY => "enotempty",
        libc::ELOOP => "eloop",
        libc::EOVERFLOW => "eoverflow",
        libc::ENOTSUP => "enotsup",
        libc::EILSEQ => "eilseq",
        libc::ETIMEDOUT => "etimedout",
        libc::ECANCELED => "ecanceled",
        libc::EACCES => "eacces",
        libc::ENOENT => "enoent",
        _ => {
            return pair(
                atom("error"),
                pair(atom(function), atom(&format!("errno_{code}"))),
            );
        }
    };
    pair(atom("error"), pair(atom(function), atom(name)))
}
fn number(o: &O) -> Option<i64> {
    if let O::Int(n) = o { Some(*n) } else { None }
}
fn unsigned(o: &O) -> Option<u64> {
    match o {
        O::Int(n) => (*n).try_into().ok(),
        O::BigInt(n) => n.to_u64(),
        _ => None,
    }
}
fn list(o: &O) -> Option<&[O]> {
    match o {
        O::Nil => Some(&[]),
        O::List { elems, tail } if **tail == O::Nil => Some(elems),
        _ => None,
    }
}
fn fd_atom(o: &O) -> Option<RawFd> {
    match o {
        O::Atom(s) if s == "stdin" => Some(0),
        O::Atom(s) if s == "stdout" => Some(1),
        O::Atom(s) if s == "stderr" => Some(2),
        _ => None,
    }
}
/// Check an arbitrary descriptor, including PTY, file, and pipe descriptors.
pub fn isatty_fd(fd: RawFd) -> io::Result<bool> {
    // SAFETY: isatty only examines the descriptor.
    if unsafe { libc::isatty(fd) } != 0 {
        return Ok(true);
    }
    let e = io::Error::last_os_error();
    match e.raw_os_error() {
        Some(libc::EINVAL | libc::ENOTTY) => Ok(false),
        _ => Err(e),
    }
}
fn id(o: &O) -> Result<u64, BifError> {
    match o {
        O::Ref {
            node,
            creation,
            ids,
        } if node == "nonode@nohost" && *creation == 0 && ids.len() == 3 && ids[0] == MAGIC => {
            Ok(u64::from(ids[1]) | (u64::from(ids[2]) << 32))
        }
        _ => Err(BifError::BADARG),
    }
}
fn handle(o: &O) -> Result<Arc<Tty>, BifError> {
    handles()
        .lock()
        .unwrap()
        .get(&id(o)?)
        .cloned()
        .ok_or(BifError::BADARG)
}
fn make_ref(id: u64) -> O {
    O::Ref {
        node: "nonode@nohost".into(),
        creation: 0,
        ids: vec![MAGIC, id as u32, (id >> 32) as u32],
    }
}
fn duplicate(fd: RawFd) -> io::Result<OwnedFd> {
    // SAFETY: dup creates an independently owned descriptor or returns an error.
    let copy = unsafe { libc::dup(fd) };
    if copy < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the successful dup result is a new owned fd.
    Ok(unsafe { OwnedFd::from_raw_fd(copy) })
}

/// Create a TTY resource for supplied input and output fds, duplicating both.
/// This is also the PTY entry point for tests and an embedding VM.
pub fn create_with_fds(input: RawFd, output: RawFd) -> io::Result<O> {
    EXIT_HOOK.get_or_init(|| {
        // SAFETY: the callback has C ABI and only reads resources retained until exit.
        unsafe { libc::atexit(restore_at_exit) };
    });
    let input = duplicate(input)?;
    let output = duplicate(output)?;
    let mut original = std::mem::MaybeUninit::<libc::termios>::uninit();
    // SAFETY: tcgetattr initializes `original` on success, and the fd is valid.
    let status = unsafe { libc::tcgetattr(output.as_raw_fd(), original.as_mut_ptr()) };
    let original = (status == 0).then(|| unsafe {
        // SAFETY: only evaluated after a successful tcgetattr.
        original.assume_init()
    });
    let mode = if original.is_some() {
        Mode::Disabled
    } else {
        Mode::Unavailable
    };
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    handles().lock().unwrap().insert(
        id,
        Arc::new(Tty {
            input,
            output,
            state: Mutex::new(State {
                original,
                current: original,
                mode,
                read_ref: None,
            }),
        }),
    );
    Ok(make_ref(id))
}

/// Remove a resource and restore its original termios once active users finish.
pub fn release(resource: &O) -> Result<(), BifError> {
    handles()
        .lock()
        .unwrap()
        .remove(&id(resource)?)
        .ok_or(BifError::BADARG)?;
    Ok(())
}

/// A reactor registration that delivers `{select, tty, reference, ready_input}`.
#[derive(Debug, Clone)]
pub struct Selection {
    /// Readable descriptor to poll or register with a reactor.
    pub fd: RawFd,
    /// The resource term in the select message.
    pub tty: O,
    /// Reader supplied reference in the select message.
    pub reference: O,
}

/// Get the current reactor registration for a selected resource.
pub fn selection(resource: &O) -> Result<Option<Selection>, BifError> {
    let tty = handle(resource)?;
    let state = tty.state.lock().unwrap();
    Ok(state.read_ref.as_ref().map(|reference| Selection {
        fd: tty.input.as_raw_fd(),
        tty: resource.clone(),
        reference: reference.clone(),
    }))
}

/// Called when `tty_select/2` or a successful `read_nif/3` arms input notification.
///
/// `token` is the address of the `ProcessHeap` inside the calling process when
/// the NIF runs on a [`arinsal_bifs::FragmentingHeap`]. The VM maps that address
/// to the scheduler pid. A zero token means the heap shape was not recognized.
pub type ArmHook = fn(usize, RawFd, O, O);

static ARM_HOOK: Mutex<Option<ArmHook>> = Mutex::new(None);

/// Install the process-aware select callback. The last installer wins.
pub fn set_arm_hook(hook: ArmHook) {
    *ARM_HOOK.lock().unwrap() = Some(hook);
}

fn arm_hook() -> Option<ArmHook> {
    *ARM_HOOK.lock().unwrap()
}

/// Address of the process heap wrapped by a one-word `FragmentingHeap`.
///
/// The VM registry uses this as the key recorded before the NIF runs.
pub fn heap_token(ctx: &mut Ctx<'_>) -> usize {
    if arm_hook().is_none() {
        return 0;
    }
    let obj: &mut dyn HeapAlloc = ctx.heap;
    // SAFETY: `Ctx::heap` is a trait object. On this ABI the fat pointer is
    // (data, vtable). The VM only installs the arm hook for NIFs invoked with
    // `FragmentingHeap`, whose sole field is the `ProcessHeap` pointer. The
    // pointer is used as a map key; a mismatch skips delivery.
    let parts: [*mut (); 2] = unsafe { std::mem::transmute_copy(&obj) };
    let data = parts[0];
    if data.is_null() {
        return 0;
    }
    // SAFETY: data is the FragmentingHeap address; its first word is the ProcessHeap pointer used only as a map key.
    let heap = unsafe { *(data.cast::<*mut ()>()) };
    heap as usize
}

fn notify_armed(token: usize, fd: RawFd, tty: &O, reference: &O) {
    if let Some(hook) = arm_hook() {
        hook(token, fd, tty.clone(), reference.clone());
    }
}

/// Wait for input readiness; returns false on timeout.
pub fn wait_readable(resource: &O, timeout: Duration) -> io::Result<bool> {
    let tty = handle(resource).map_err(|_| io::Error::from_raw_os_error(libc::EBADF))?;
    let mut pfd = libc::pollfd {
        fd: tty.input.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    let millis = timeout.as_millis().min(i32::MAX as u128) as i32;
    loop {
        // SAFETY: pfd is initialized and poll receives a single valid entry.
        let result = unsafe { libc::poll(&mut pfd, 1, millis) };
        if result >= 0 {
            return Ok(result != 0);
        }
        let e = io::Error::last_os_error();
        if e.kind() != io::ErrorKind::Interrupted {
            return Err(e);
        }
    }
}

fn isatty_nif(ctx: &mut Ctx<'_>, a: &[Term]) -> Result<Term, BifError> {
    call(ctx, a, |a| {
        let fd = fd_atom(&a[0]).ok_or(BifError::BADARG)?;
        // SAFETY: isatty only examines the descriptor.
        let yes = unsafe { libc::isatty(fd) };
        Ok(if yes != 0 {
            atom("true")
        } else {
            match io::Error::last_os_error().raw_os_error() {
                Some(libc::EINVAL | libc::ENOTTY) => atom("false"),
                _ => atom("ebadf"),
            }
        })
    })
}
fn tty_create_nif(ctx: &mut Ctx<'_>, a: &[Term]) -> Result<Term, BifError> {
    call(ctx, a, |a| {
        let output = match fd_atom(&a[0]) {
            Some(1 | 2) => fd_atom(&a[0]).unwrap(),
            _ => return Err(BifError::BADARG),
        };
        create_with_fds(0, output)
            .map(ok)
            .map_err(|_| BifError::SystemLimit)
    })
}
fn tty_init_nif(ctx: &mut Ctx<'_>, a: &[Term]) -> Result<Term, BifError> {
    call(ctx, a, |a| {
        // Port of erts/emulator/nifs/common/prim_tty_nif.c:1074 (tty_init_nif), OTP-29.1.1.
        let tty = handle(&a[0])?;
        let O::Map(entries) = &a[1] else {
            return Err(BifError::BADARG);
        };
        let input = entries
            .iter()
            .find(|(k, _)| *k == atom("input"))
            .map(|(_, v)| v)
            .ok_or(BifError::BADARG)?;
        let mut state = tty.state.lock().unwrap();
        if state.mode == Mode::Unavailable {
            return Ok(if *input == atom("raw") {
                error("enotsup")
            } else {
                atom("ok")
            });
        }
        let raw = *input == atom("raw");
        let original = state.original.ok_or(BifError::BADARG)?;
        let mut mode = original;
        if raw {
            mode.c_iflag &= !(libc::ISTRIP | libc::ICRNL);
            mode.c_lflag &= !(libc::ICANON | libc::ECHO);
            mode.c_oflag &= !libc::OPOST;
            mode.c_cc[libc::VMIN] = 1;
            mode.c_cc[libc::VTIME] = 0;
            #[cfg(target_os = "macos")]
            {
                mode.c_cc[libc::VDSUSP] = 0;
            }
        }
        if raw || state.mode == Mode::Enabled {
            // SAFETY: the resource owns output and mode is a valid termios derived from tcgetattr.
            if unsafe { libc::tcsetattr(tty.output.as_raw_fd(), libc::TCSANOW, &mode) } < 0 {
                return Ok(errno_error("tcsetattr"));
            }
        }
        state.current = Some(mode);
        state.mode = if raw { Mode::Enabled } else { Mode::Disabled };
        Ok(atom("ok"))
    })
}
fn setlocale_nif(ctx: &mut Ctx<'_>, a: &[Term]) -> Result<Term, BifError> {
    call(ctx, a, |_| {
        // Port of erts/emulator/nifs/common/prim_tty_nif.c:747 (setlocale_nif), OTP-29.1.1.
        // SAFETY: C string is static; setlocale and nl_langinfo return process-owned strings.
        let locale = unsafe { libc::setlocale(libc::LC_CTYPE, c"".as_ptr()) };
        // SAFETY: nl_langinfo(CODESET) returns a process-owned NUL-terminated string.
        let utf8 = !locale.is_null()
            && unsafe { CStr::from_ptr(libc::nl_langinfo(libc::CODESET)) }.to_bytes() == b"UTF-8";
        Ok(atom(if utf8 { "true" } else { "false" }))
    })
}
fn tty_select_nif(ctx: &mut Ctx<'_>, a: &[Term]) -> Result<Term, BifError> {
    // Port of erts/emulator/nifs/common/prim_tty_nif.c:1213 (tty_select_nif), OTP-29.1.1.
    // enif_select is one-shot; the VM hook delivers {select, TTY, Ref, ready_input}.
    let token = heap_token(ctx);
    call(ctx, a, |a| {
        let tty = handle(&a[0])?;
        let fd = tty.input.as_raw_fd();
        tty.state.lock().unwrap().read_ref = Some(a[1].clone());
        drop(tty);
        notify_armed(token, fd, &a[0], &a[1]);
        Ok(atom("ok"))
    })
}
fn tty_encoding_nif(ctx: &mut Ctx<'_>, a: &[Term]) -> Result<Term, BifError> {
    call(ctx, a, |_| Ok(atom("utf8")))
}
fn tty_is_open_nif(ctx: &mut Ctx<'_>, a: &[Term]) -> Result<Term, BifError> {
    call(ctx, a, |a| {
        handle(&a[0])?;
        let fd = fd_atom(&a[1]).ok_or(BifError::BADARG)?;
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLHUP,
            revents: 0,
        };
        // SAFETY: pfd is initialized and poll uses one entry.
        let result = unsafe { libc::poll(&mut pfd, 1, 0) };
        if result < 0 {
            return Ok(errno_error("tty_is_open"));
        }
        if result == 0 {
            return Ok(atom("true"));
        }
        if pfd.revents & libc::POLLHUP != 0 {
            return Ok(atom("false"));
        }
        Err(BifError::BADARG)
    })
}
fn tty_window_size_nif(ctx: &mut Ctx<'_>, a: &[Term]) -> Result<Term, BifError> {
    call(ctx, a, |a| {
        let tty = handle(&a[0])?;
        let mut ws = libc::winsize {
            ws_row: 0,
            ws_col: 0,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        // SAFETY: ioctl writes the provided winsize on success.
        let first = unsafe { libc::ioctl(tty.input.as_raw_fd(), libc::TIOCGWINSZ, &mut ws) };
        if first < 0 {
            // SAFETY: same initialized winsize for the output fd fallback.
            let second = unsafe { libc::ioctl(tty.output.as_raw_fd(), libc::TIOCGWINSZ, &mut ws) };
            if second < 0 {
                return Ok(error("enotsup"));
            }
        }
        let cols = if ws.ws_col > 0 {
            i64::from(ws.ws_col)
        } else {
            -1
        };
        let rows = if ws.ws_row > 0 {
            i64::from(ws.ws_row)
        } else {
            -1
        };
        if cols < 0 && rows < 0 {
            Ok(error("enotsup"))
        } else {
            Ok(ok(pair(O::Int(cols), O::Int(rows))))
        }
    })
}

fn iolist(o: &O, bytes: &mut Vec<u8>) -> Result<(), BifError> {
    match o {
        O::Binary(b) => bytes.extend_from_slice(b),
        O::Int(n) if (0..=255).contains(n) => bytes.push(*n as u8),
        O::Nil => {}
        O::List { elems, tail } => {
            for e in elems {
                iolist(e, bytes)?;
            }
            iolist(tail, bytes)?;
        }
        _ => return Err(BifError::BADARG),
    }
    Ok(())
}
fn write_nif(ctx: &mut Ctx<'_>, a: &[Term]) -> Result<Term, BifError> {
    call(ctx, a, |a| {
        // Port of erts/emulator/nifs/common/prim_tty_nif.c:354 (tty_write_nif), OTP-29.1.1.
        let tty = handle(&a[0])?;
        let mut bytes = Vec::new();
        iolist(&a[1], &mut bytes)?;
        let mut offset = 0;
        while offset < bytes.len() {
            // SAFETY: byte slice remains alive during write and fd is owned by tty.
            let n = unsafe {
                libc::write(
                    tty.output.as_raw_fd(),
                    bytes[offset..].as_ptr().cast(),
                    bytes.len() - offset,
                )
            };
            if n > 0 {
                offset += n as usize;
                continue;
            }
            if n == 0 {
                return Ok(error("eio"));
            }
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            if e.kind() == io::ErrorKind::WouldBlock {
                let mut pfd = libc::pollfd {
                    fd: tty.output.as_raw_fd(),
                    events: libc::POLLOUT,
                    revents: 0,
                };
                // SAFETY: initialized pollfd and one element.
                if unsafe { libc::poll(&mut pfd, 1, -1) } >= 0 {
                    continue;
                }
            }
            let name = match e.raw_os_error() {
                Some(libc::EPIPE) => "epipe",
                Some(libc::EBADF) => "ebadf",
                _ => "eio",
            };
            return Ok(error(name));
        }
        Ok(atom("ok"))
    })
}
fn read_nif(ctx: &mut Ctx<'_>, a: &[Term]) -> Result<Term, BifError> {
    // Port of erts/emulator/nifs/common/prim_tty_nif.c:429 (tty_read_nif), OTP-29.1.1.
    // A successful read (including EAGAIN/EINTR as an empty binary) rearms select.
    let token = heap_token(ctx);
    call(ctx, a, |a| {
        let tty = handle(&a[0])?;
        let fd = tty.input.as_raw_fd();
        let size = unsigned(&a[2]).ok_or(BifError::BADARG)?.min(1024) as usize;
        let mut bytes = vec![0; size];
        // SAFETY: bytes has capacity `size` and fd remains owned during read.
        let n = unsafe { libc::read(fd, bytes.as_mut_ptr().cast(), size) };
        if n == 0 {
            return Ok(error("closed"));
        }
        if n < 0 {
            let e = io::Error::last_os_error();
            if matches!(
                e.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
            ) {
                notify_armed(token, fd, &a[0], &a[1]);
                return Ok(ok(O::Binary(Vec::new())));
            }
            return Ok(errno_error("read"));
        }
        bytes.truncate(n as usize);
        notify_armed(token, fd, &a[0], &a[1]);
        Ok(ok(O::Binary(bytes)))
    })
}
fn isprint_nif(ctx: &mut Ctx<'_>, a: &[Term]) -> Result<Term, BifError> {
    call(ctx, a, |a| {
        let i =
            i32::try_from(number(&a[0]).ok_or(BifError::BADARG)?).map_err(|_| BifError::BADARG)?;
        // SAFETY: libc isprint accepts a C int; this cast matches OTP's `(char)i`.
        Ok(atom(if unsafe { isprint(i as i8 as i32) } != 0 {
            "true"
        } else {
            "false"
        }))
    })
}
fn wcwidth_nif(ctx: &mut Ctx<'_>, a: &[Term]) -> Result<Term, BifError> {
    call(ctx, a, |a| {
        let i =
            i32::try_from(number(&a[0]).ok_or(BifError::BADARG)?).map_err(|_| BifError::BADARG)?;
        // SAFETY: wchar_t on macOS is a signed 32-bit integer, matching OTP's cast.
        let width = unsafe { wcwidth(i as libc::wchar_t) };
        Ok(if width < 0 {
            error("not_printable")
        } else {
            O::Int(i64::from(width))
        })
    })
}
fn wcswidth_nif(ctx: &mut Ctx<'_>, a: &[Term]) -> Result<Term, BifError> {
    call(ctx, a, |a| {
        let mut bytes = Vec::new();
        iolist(&a[0], &mut bytes)?;
        let chars = bytes
            .as_chunks::<4>()
            .0
            .iter()
            .map(|chunk| i32::from_ne_bytes(*chunk))
            .collect::<Vec<_>>();
        // SAFETY: chars is a valid contiguous wchar_t array for the supplied count.
        let width = unsafe { wcswidth(chars.as_ptr(), chars.len()) };
        Ok(if width < 0 {
            error("not_printable")
        } else {
            ok(O::Int(i64::from(width)))
        })
    })
}
fn sizeof_wchar_nif(ctx: &mut Ctx<'_>, a: &[Term]) -> Result<Term, BifError> {
    call(ctx, a, |_| {
        Ok(O::Int(std::mem::size_of::<libc::wchar_t>() as i64))
    })
}

fn nul_iolist(o: &O) -> Result<CString, BifError> {
    let mut bytes = Vec::new();
    iolist(o, &mut bytes)?;
    let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    CString::new(&bytes[..end]).map_err(|_| BifError::BADARG)
}
fn setupterm_nif(ctx: &mut Ctx<'_>, a: &[Term]) -> Result<Term, BifError> {
    call(ctx, a, |_| {
        let _lock = TERMINFO.lock().unwrap();
        let mut err = 0;
        // SAFETY: null asks ncurses to use TERM; `err` is writable.
        let status = unsafe { c_setupterm(ptr::null(), -1, &mut err) };
        if status < 0 {
            return Ok(errno_error("setupterm"));
        }
        let mut saved = SAVED_TERM.lock().unwrap();
        if *saved != 0 {
            // SAFETY: the previous successful setupterm supplied this ncurses terminal.
            unsafe { del_curterm(*saved as *mut libc::c_void) };
        }
        // SAFETY: setupterm succeeded while TERMINFO serializes all ncurses calls.
        *saved = unsafe { cur_term as usize };
        Ok(atom("ok"))
    })
}
fn tigetnum_nif(ctx: &mut Ctx<'_>, a: &[Term]) -> Result<Term, BifError> {
    call(ctx, a, |a| {
        let cap = nul_iolist(&a[0])?;
        let _lock = TERMINFO.lock().unwrap();
        // SAFETY: cap is NUL-terminated and the ncurses global state is serialized.
        Ok(O::Int(i64::from(unsafe { tgetnum(cap.as_ptr()) })))
    })
}
fn tigetflag_nif(ctx: &mut Ctx<'_>, a: &[Term]) -> Result<Term, BifError> {
    call(ctx, a, |a| {
        let cap = nul_iolist(&a[0])?;
        let _lock = TERMINFO.lock().unwrap();
        // SAFETY: cap is NUL-terminated and the ncurses global state is serialized.
        Ok(atom(if unsafe { tgetflag(cap.as_ptr()) } != 0 {
            "true"
        } else {
            "false"
        }))
    })
}
fn tigetstr_nif(ctx: &mut Ctx<'_>, a: &[Term]) -> Result<Term, BifError> {
    call(ctx, a, |a| {
        let cap = nul_iolist(&a[0])?;
        let _lock = TERMINFO.lock().unwrap();
        // SAFETY: cap is NUL-terminated; returned string is owned by ncurses while locked.
        let p = unsafe { tigetstr(cap.as_ptr()) };
        if p.is_null() {
            return Ok(atom("false"));
        }
        if p as isize == -1 {
            return Err(BifError::BADARG);
        }
        // SAFETY: ncurses returns a NUL-terminated capability string.
        Ok(ok(O::Binary(
            unsafe { CStr::from_ptr(p) }.to_bytes().to_vec(),
        )))
    })
}

unsafe fn table(
    names: *const *const libc::c_char,
    codes: *const *const libc::c_char,
    full: *const *const libc::c_char,
) -> O {
    let mut rows = Vec::new();
    for i in 0..1024 {
        // SAFETY: ncurses exports three null-terminated arrays of equal length.
        let (name, code, fullname) = unsafe { (*names.add(i), *codes.add(i), *full.add(i)) };
        if name.is_null() || code.is_null() || fullname.is_null() {
            break;
        }
        let charlist = |p| {
            // SAFETY: entries in ncurses name arrays are NUL-terminated strings.
            let bytes = unsafe { CStr::from_ptr(p) }.to_bytes();
            O::list(bytes.iter().map(|b| O::Int(i64::from(*b))).collect())
        };
        rows.push(O::Map(vec![
            (atom("name"), charlist(name)),
            (atom("code"), charlist(code)),
            (atom("full_name"), charlist(fullname)),
        ]));
    }
    rows.reverse();
    O::list(rows)
}
fn tinfo_nif(ctx: &mut Ctx<'_>, a: &[Term]) -> Result<Term, BifError> {
    call(ctx, a, |_| {
        let _lock = TERMINFO.lock().unwrap();
        // SAFETY: these are the null-terminated ncurses capability metadata arrays.
        let result = unsafe {
            O::Map(vec![
                (
                    atom("bool"),
                    table(
                        ptr::addr_of!(boolnames).cast(),
                        ptr::addr_of!(boolcodes).cast(),
                        ptr::addr_of!(boolfnames).cast(),
                    ),
                ),
                (
                    atom("num"),
                    table(
                        ptr::addr_of!(numnames).cast(),
                        ptr::addr_of!(numcodes).cast(),
                        ptr::addr_of!(numfnames).cast(),
                    ),
                ),
                (
                    atom("str"),
                    table(
                        ptr::addr_of!(strnames).cast(),
                        ptr::addr_of!(strcodes).cast(),
                        ptr::addr_of!(strfnames).cast(),
                    ),
                ),
            ])
        };
        Ok(result)
    })
}

thread_local! { static TPUTS_BYTES: std::cell::RefCell<Vec<u8>> = const { std::cell::RefCell::new(Vec::new()) }; }
extern "C" fn collect_putc(c: libc::c_int) -> libc::c_int {
    TPUTS_BYTES.with(|out| out.borrow_mut().push(c as u8));
    0
}
fn tputs_nif(ctx: &mut Ctx<'_>, a: &[Term]) -> Result<Term, BifError> {
    call(ctx, a, |a| {
        let cap = nul_iolist(&a[0])?;
        let args = list(&a[1]).ok_or(BifError::BADARG)?;
        if args.len() > 9 {
            return Err(BifError::BADARG);
        }
        let mut params = [0 as libc::c_long; 9];
        for (slot, value) in args.iter().enumerate() {
            params[slot] = number(value).ok_or(BifError::BADARG)? as libc::c_long;
        }
        let _lock = TERMINFO.lock().unwrap();
        TPUTS_BYTES.with(|out| out.borrow_mut().clear());
        let ent = if args.is_empty() {
            cap.as_ptr()
        } else {
            // SAFETY: cap is NUL-terminated and all nine portable tparm arguments are supplied.
            unsafe {
                tparm(
                    cap.as_ptr(),
                    params[0],
                    params[1],
                    params[2],
                    params[3],
                    params[4],
                    params[5],
                    params[6],
                    params[7],
                    params[8],
                )
            }
        };
        if ent.is_null() {
            return Ok(errno_error("tparm"));
        }
        // SAFETY: ent points to a NUL-terminated ncurses capability; callback appends into thread-local storage.
        unsafe { tputs(ent, 1, collect_putc) };
        Ok(ok(O::Binary(TPUTS_BYTES.with(|out| out.borrow().clone()))))
    })
}
