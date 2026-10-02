//! Local OS ports backed by child processes.
use crate::process::Message;
use crate::{Process, Vm, VmError};
use arinsal_etf::OwnedTerm;
use arinsal_sched::{Pid, RunCtx, Scheduler};
use arinsal_term::{
    ProcessHeap, Term, TermBuilder, TermKind, copy_term, from_owned, global_atoms, to_owned,
};
use std::cell::Cell;
use std::collections::{HashMap, HashSet, VecDeque};
use std::ffi::{OsStr, OsString};
use std::io::Write;
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::CommandExt;
use std::process::{Child, ChildStdout, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};

// Port of erts/emulator/beam/erl_bif_port.c:824 (open_port defaults), OTP-29.1.1.
const DEFAULT_HIGH: usize = 8192;
const DEFAULT_LOW: usize = 4096;
const INLINE_ENV_LIMIT: usize = 128 * 1024;
static NEXT_CHILD_CONFIG: AtomicU64 = AtomicU64::new(0);

fn write_port_exec_config(
    program: &OsStr,
    args: &[OsString],
    arg0: Option<&OsStr>,
    cwd: Option<&OsStr>,
    env: &[(OsString, OsString)],
) -> std::io::Result<std::path::PathBuf> {
    fn push_bytes(output: &mut Vec<u8>, value: &[u8]) -> std::io::Result<()> {
        let len = u32::try_from(value.len()).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "port config field too large",
            )
        })?;
        output.extend_from_slice(&len.to_le_bytes());
        output.extend_from_slice(value);
        Ok(())
    }

    fn push_optional(output: &mut Vec<u8>, value: Option<&OsStr>) -> std::io::Result<()> {
        match value {
            Some(value) => {
                output.push(1);
                push_bytes(output, value.as_bytes())
            }
            None => {
                output.push(0);
                Ok(())
            }
        }
    }

    let mut bytes = b"ARPC\x01".to_vec();
    push_bytes(&mut bytes, program.as_bytes())?;
    push_optional(&mut bytes, arg0)?;
    push_optional(&mut bytes, cwd)?;
    bytes.extend_from_slice(
        &u32::try_from(args.len())
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "too many port args")
            })?
            .to_le_bytes(),
    );
    for arg in args {
        push_bytes(&mut bytes, arg.as_bytes())?;
    }
    bytes.extend_from_slice(
        &u32::try_from(env.len())
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "too many port env vars")
            })?
            .to_le_bytes(),
    );
    for (key, value) in env {
        push_bytes(&mut bytes, key.as_bytes())?;
        push_bytes(&mut bytes, value.as_bytes())?;
    }

    let path = std::env::temp_dir().join(format!(
        "arinsal-port-child-{}-{}.bin",
        std::process::id(),
        NEXT_CHILD_CONFIG.fetch_add(1, Ordering::Relaxed)
    ));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)?;
    if let Err(error) = file.write_all(&bytes) {
        let _ = std::fs::remove_file(&path);
        return Err(error);
    }
    Ok(path)
}

thread_local! {
    /// Set when `port_command` must suspend the caller and retry the call.
    static BUSY_SUSPEND: Cell<bool> = const { Cell::new(false) };
}

/// True once, when the running BIF asked to suspend on a busy port.
pub(crate) fn take_busy_suspend() -> bool {
    BUSY_SUSPEND.with(|flag| flag.replace(false))
}

/// Output-queue and message-queue busy limits from `open_port` options.
#[derive(Clone, Copy)]
struct BusyLimits {
    port_low: usize,
    port_high: usize,
    port_enabled: bool,
    msgq_low: usize,
    msgq_high: usize,
    msgq_enabled: bool,
}

struct PortState {
    outq: VecDeque<u8>,
    /// Bytes scheduled ahead of the driver when `{parallelism, true}`.
    msgq: usize,
    pending: VecDeque<Vec<u8>>,
    busy_port: bool,
    busy_msgq: bool,
    graceful_close: bool,
    send_closed: bool,
    exit_complete: bool,
    suspended: Vec<Pid>,
    closed: bool,
    broken: bool,
    in_output: bool,
    profile_active: bool,
}

#[derive(Clone)]
struct PortMonitor {
    pid: Pid,
    object: OwnedTerm,
}

/// State retained for a live child or fd port.
pub(crate) struct PortHandle {
    id: u64,
    out: Mutex<Option<OwnedFd>>,
    wake_r: Mutex<Option<OwnedFd>>,
    wake_w: OwnedFd,
    wake_needed: AtomicBool,
    framing: Option<(u8, usize)>,
    owner: Mutex<Pid>,
    links: Mutex<HashSet<Pid>>,
    monitors: Mutex<HashMap<u64, PortMonitor>>,
    os_pid: u32,
    name: String,
    parallelism: bool,
    limits: BusyLimits,
    state: Mutex<PortState>,
    scheduler: Arc<Scheduler<Process>>,
    /// `port_set_data/2` term. `undefined` until the first store.
    data: Mutex<OwnedTerm>,
    /// `tcp_inet` / `tcp_inet6` port. I/O is owned by `inet_drv`, not a stdio worker.
    inet: bool,
    /// Dynamically loaded (`erl_ddll`) driver port.
    driver: OnceLock<Arc<arinsal_drv::DriverPort>>,
}

/// Inspect or move the next local port id for `erts_debug` table tests.
/// Port of erts/emulator/beam/erl_ptab.c:1356-1460 (`erts_ptab_test_next_id`), OTP-29.1.1.
pub(crate) fn test_next_port_id(
    runtime: &crate::process::Runtime,
    set: bool,
    next_id: u64,
) -> Option<u64> {
    const MAX_PORT_ID: u64 = u32::MAX as u64;
    let ports = runtime.ports.lock().unwrap();
    let start = if set {
        next_id.checked_add(1)?
    } else {
        runtime.next_port.load(Ordering::Relaxed)
    };
    let candidate = (start..=MAX_PORT_ID).find(|id| !ports.contains_key(id))?;
    if set {
        runtime.next_port.store(candidate, Ordering::Relaxed);
    }
    Some(candidate)
}

impl PortHandle {
    pub(crate) fn owner_pid(&self) -> Pid {
        *self.owner.lock().unwrap()
    }
    pub(crate) fn scheduler(&self) -> Arc<Scheduler<Process>> {
        Arc::clone(&self.scheduler)
    }
    pub(crate) fn port_name(&self) -> String {
        self.name.clone()
    }
}

fn atom(s: &str) -> Term {
    Term::atom(global_atoms().intern(s).expect("built-in atom"))
}
fn badarg() -> VmError {
    VmError::Trap(crate::exceptions::Trap::error(atom("badarg")))
}
fn list(t: Term) -> Option<Vec<Term>> {
    let mut out = Vec::new();
    let mut cur = t;
    while cur.classify() == TermKind::List {
        // SAFETY: The source term remains in the live caller heap for this BIF.
        let (h, tail) = unsafe { cur.cons_ref()? };
        out.push(h);
        cur = tail;
    }
    (cur == Term::NIL).then_some(out)
}
fn bytes(t: Term) -> Option<Vec<u8>> {
    if let Some(n) = t.as_small() {
        return (0..=255).contains(&n).then_some(vec![n as u8]);
    }
    let mut out = Vec::new();
    let mut pending = vec![t];
    while let Some(term) = pending.pop() {
        if let Some(n) = term.as_small() {
            if !(0..=255).contains(&n) {
                return None;
            }
            out.push(n as u8);
        } else if term.classify() == TermKind::List {
            // SAFETY: The list is traversed before the caller's process heap can move.
            let (head, tail) = unsafe { term.cons_ref()? };
            pending.push(tail);
            pending.push(head);
        } else if term == Term::NIL {
        } else {
            // SAFETY: This view is consumed before the caller's process heap can move.
            let binary = unsafe { term.binary_ref() }?;
            out.extend_from_slice(binary.bytes());
        }
    }
    Some(out)
}
fn string_bytes(t: Term) -> Option<Vec<u8>> {
    // `args` entries are strings or binaries; a byte integer is not a string.
    // Port of erts/emulator/beam/erl_bif_port.c (open_port args validation), OTP-29.1.1.
    if t.as_small().is_some() {
        None
    } else {
        bytes(t)
    }
}
fn iodata(t: Term) -> Option<Vec<u8>> {
    fn append(term: Term, tail: bool, out: &mut Vec<u8>) -> Option<()> {
        if term.classify() == TermKind::List {
            // SAFETY: The list is traversed before the caller's process heap can move.
            let (head, rest) = unsafe { term.cons_ref()? };
            append(head, false, out)?;
            append(rest, true, out)
        } else if term == Term::NIL {
            Some(())
        // SAFETY: This view is consumed before the caller's process heap can move.
        } else if let Some(binary) = unsafe { term.binary_ref() } {
            out.extend_from_slice(binary.bytes());
            Some(())
        } else if !tail {
            let value = term.as_small()?;
            if !(0..=255).contains(&value) {
                return None;
            }
            out.push(value as u8);
            Some(())
        } else {
            None
        }
    }
    if t.as_small().is_some() {
        return None;
    }
    let mut out = Vec::new();
    append(t, false, &mut out)?;
    Some(out)
}
fn tuple(t: Term) -> Option<Vec<Term>> {
    // SAFETY: The borrowed tuple is collected while the caller heap remains live.
    unsafe { t.tuple_ref() }.map(|v| v.iter().collect())
}
struct PortOptions {
    binary: bool,
    framing: Option<(u8, usize)>,
    exit_status: bool,
    eof: bool,
    args: Vec<Vec<u8>>,
    arg0: Option<Vec<u8>>,
    cwd: Option<Vec<u8>>,
    env: Vec<(Vec<u8>, Option<Vec<u8>>)>,
    stderr_to_stdout: bool,
    use_stdio: bool,
    rw: u8,
    parallelism: bool,
    limits: BusyLimits,
}
fn options(t: Term) -> Option<PortOptions> {
    let mut opts = PortOptions {
        binary: false,
        framing: None,
        exit_status: false,
        eof: false,
        args: Vec::new(),
        arg0: None,
        cwd: None,
        env: Vec::new(),
        stderr_to_stdout: false,
        use_stdio: true,
        rw: 0,
        parallelism: false,
        limits: BusyLimits {
            port_low: DEFAULT_LOW,
            port_high: DEFAULT_HIGH,
            port_enabled: true,
            msgq_low: DEFAULT_LOW,
            msgq_high: DEFAULT_HIGH,
            msgq_enabled: true,
        },
    };
    for item in list(t)? {
        if item == atom("binary") {
            opts.binary = true;
        } else if item == atom("exit_status") {
            opts.exit_status = true;
        } else if item == atom("eof") {
            opts.eof = true;
        } else if item == atom("line") {
            // Port of erts/emulator/beam/erl_bif_port.c:985, OTP-29.1.1.
            if opts.framing.is_some_and(|(mode, _)| mode != 1) {
                return None;
            }
            opts.framing = Some((1, 512));
        } else if item == atom("stream") || item == atom("hide") || item == atom("overlapped_io") {
        } else if item == atom("use_stdio") {
            opts.use_stdio = true;
        } else if item == atom("nouse_stdio") {
            opts.use_stdio = false;
        } else if item == atom("stderr_to_stdout") {
            opts.stderr_to_stdout = true;
        } else if item == atom("in") {
            opts.rw |= 1;
        } else if item == atom("out") {
            opts.rw |= 2;
        } else {
            let pair = tuple(item)?;
            if pair.len() == 2
                && pair[0] == atom("packet")
                && matches!(pair[1].as_small(), Some(1 | 2 | 4))
            {
                // Port of erts/emulator/beam/erl_bif_port.c (open_port packet 1|2|4), OTP-29.1.1.
                let n = pair[1].as_small().unwrap() as u8;
                if opts.framing.is_some_and(|(mode, _)| mode == 1) {
                    return None;
                }
                opts.framing = Some((2, n as usize));
            } else if pair.len() == 2 && pair[0] == atom("line") {
                let n = pair[1].as_small()?;
                if n <= 0 {
                    return None;
                }
                if opts.framing.is_some_and(|(mode, _)| mode != 1) {
                    return None;
                }
                opts.framing = Some((1, n as usize));
            } else if pair.len() == 2 && pair[0] == atom("args") {
                opts.args = list(pair[1])?
                    .into_iter()
                    .map(string_bytes)
                    .collect::<Option<Vec<_>>>()?;
            } else if pair.len() == 2 && pair[0] == atom("arg0") {
                opts.arg0 = Some(bytes(pair[1])?);
            } else if pair.len() == 2 && pair[0] == atom("cd") {
                opts.cwd = Some(bytes(pair[1])?);
            } else if pair.len() == 2 && pair[0] == atom("env") {
                opts.env.clear();
                for entry in list(pair[1])? {
                    let env = tuple(entry)?;
                    if env.len() != 2 {
                        return None;
                    }
                    let name = bytes(env[0])?;
                    if name.is_empty() || name.contains(&b'=') {
                        return None;
                    }
                    let value = if env[1] == atom("false") {
                        None
                    } else {
                        Some(bytes(env[1])?)
                    };
                    opts.env.push((name, value));
                }
            } else if pair.len() == 2 && pair[0] == atom("parallelism") {
                // Port of erts/emulator/beam/erl_bif_port.c:913 (open_port parallelism), OTP-29.1.1.
                if pair[1] == atom("true") {
                    opts.parallelism = true;
                } else if pair[1] == atom("false") {
                    opts.parallelism = false;
                } else {
                    return None;
                }
            } else if pair.len() == 2
                && (pair[0] == atom("busy_limits_port") || pair[0] == atom("busy_limits_msgq"))
            {
                // Port of erts/emulator/beam/erl_bif_port.c:920 (busy_limits_port / busy_limits_msgq), OTP-29.1.1.
                let port_limit = pair[0] == atom("busy_limits_port");
                let (low, high, enabled) = if pair[1] == atom("disabled") {
                    (0, 0, false)
                } else {
                    let limits = tuple(pair[1])?;
                    if limits.len() != 2 {
                        return None;
                    }
                    let mut low = limits[0].as_small()?;
                    let high = limits[1].as_small()?;
                    if low < 1 || high < 1 {
                        return None;
                    }
                    if low > high {
                        low = high;
                    }
                    (low as usize, high as usize, true)
                };
                if port_limit {
                    opts.limits.port_low = low;
                    opts.limits.port_high = high;
                    opts.limits.port_enabled = enabled;
                } else {
                    opts.limits.msgq_low = low;
                    opts.limits.msgq_high = high;
                    opts.limits.msgq_enabled = enabled;
                }
            } else {
                return None;
            }
        }
    }
    // Port of erts/emulator/beam/erl_bif_port.c:1014 (default read_write), OTP-29.1.1.
    if opts.rw == 0 {
        opts.rw = 3;
    }
    if opts.stderr_to_stdout && !opts.use_stdio {
        return None;
    }
    Some(opts)
}
fn term_data(heap: &mut ProcessHeap, bytes: &[u8], binary: bool) -> Result<Term, VmError> {
    let mut b = TermBuilder::new(heap);
    if binary {
        b.binary(bytes)
    } else {
        b.list_from_iter(bytes.iter().map(|x| Term::small(*x as i64).unwrap()))
    }
    .map_err(|e| VmError::Unsupported(format!("port data allocation: {e:?}")))
}
fn publish(scheduler: &Scheduler<Process>, owner: Pid, port: Term, msg: Term) {
    let Ok(envelope) = Message::copy_from(msg) else {
        return;
    };
    let _ = scheduler.send(owner, owner, envelope);
    let _ = port;
}
fn output_message(
    scheduler: &Scheduler<Process>,
    owner: Pid,
    port_id: u64,
    bytes: &[u8],
    binary: bool,
) {
    let Some(port) = Term::port(port_id) else {
        return;
    };
    let mut heap = ProcessHeap::with_words(output_heap_words(bytes.len(), binary, 24));
    let Ok(data) = term_data(&mut heap, bytes, binary) else {
        return;
    };
    let data = TermBuilder::new(&mut heap).tuple(&[atom("data"), data]);
    let Ok(data) = data else { return };
    let Ok(msg) = TermBuilder::new(&mut heap).tuple(&[port, data]) else {
        return;
    };
    publish(scheduler, owner, port, msg);
}
fn line_message(
    scheduler: &Scheduler<Process>,
    owner: Pid,
    port_id: u64,
    bytes: &[u8],
    binary: bool,
    complete: bool,
) {
    let Some(port) = Term::port(port_id) else {
        return;
    };
    let mut heap = ProcessHeap::with_words(output_heap_words(bytes.len(), binary, 32));
    let Ok(data) = term_data(&mut heap, bytes, binary) else {
        return;
    };
    let kind = if complete { atom("eol") } else { atom("noeol") };
    let Ok(line) = TermBuilder::new(&mut heap).tuple(&[kind, data]) else {
        return;
    };
    let Ok(data) = TermBuilder::new(&mut heap).tuple(&[atom("data"), line]) else {
        return;
    };
    if let Ok(msg) = TermBuilder::new(&mut heap).tuple(&[port, data]) {
        publish(scheduler, owner, port, msg);
    }
}

fn output_heap_words(byte_len: usize, binary: bool, overhead: usize) -> usize {
    if binary {
        byte_len / 4 + overhead
    } else {
        // A list byte per output byte needs two young-heap words per cons cell.
        byte_len.saturating_mul(2).saturating_add(overhead)
    }
}
fn event_message(scheduler: &Scheduler<Process>, owner: Pid, port_id: u64, event: Term) {
    let Some(port) = Term::port(port_id) else {
        return;
    };
    let mut heap = ProcessHeap::with_words(24);
    if let Ok(msg) = TermBuilder::new(&mut heap).tuple(&[port, event]) {
        publish(scheduler, owner, port, msg);
    }
}

fn start(
    vm: &mut Vm,
    process: &Process,
    ctx: &RunCtx<'_, Message>,
    spec: Term,
    opts: Term,
) -> Result<Term, VmError> {
    let parsed_opts = options(opts).ok_or_else(badarg)?;
    let spec = tuple(spec).ok_or_else(badarg)?;
    if let [kind, input, output] = spec.as_slice() {
        if *kind != atom("fd") {
            return Err(badarg());
        }
        let input = input.as_small().filter(|fd| *fd >= 0).ok_or_else(badarg)? as RawFd;
        let output = output.as_small().filter(|fd| *fd >= 0).ok_or_else(badarg)? as RawFd;
        return start_fd(vm, process, ctx, input, output, &parsed_opts);
    }
    let PortOptions {
        binary,
        framing,
        exit_status: want_status,
        eof: want_eof,
        args,
        arg0,
        cwd,
        env,
        stderr_to_stdout,
        use_stdio,
        rw,
        parallelism,
        limits,
        ..
    } = parsed_opts;
    if let [kind, cmd] = spec.as_slice()
        && (*kind == atom("spawn_driver") || *kind == atom("spawn"))
    {
        // erts_convert_filename_to_encoding also takes an atom name.
        let name = match cmd.as_atom() {
            Some(name) => global_atoms()
                .text(name)
                .map(|text| text.to_string())
                .ok_or_else(badarg)?,
            None => String::from_utf8(bytes(*cmd).ok_or_else(badarg)?).map_err(|_| badarg())?,
        };
        // Port of erts/emulator/beam/io.c:579-620 (erts_open_driver): the first word of
        // the command names the driver; `spawn` falls back to the spawn driver.
        let first = name.split(' ').next().unwrap_or_default();
        match crate::ddll::find_driver(first) {
            Some(crate::ddll::Found::Dynamic(handle_id, driver)) => {
                if want_status {
                    return Err(badarg());
                }
                let line = framing.and_then(|(mode, n)| (mode == 1).then_some(n));
                return start_dyn_driver(
                    process,
                    ctx,
                    handle_id,
                    driver,
                    name,
                    DriverIoFlags {
                        binary,
                        eof: want_eof,
                        line,
                    },
                );
            }
            Some(crate::ddll::Found::Static) if *kind == atom("spawn_driver") => {
                return start_driver(process, ctx, name);
            }
            None if *kind == atom("spawn_driver") => return Err(badarg()),
            _ => {}
        }
    }
    let (name, executable, child_program, child_args) = match spec.as_slice() {
        [kind, path] if *kind == atom("spawn_executable") => {
            let path = bytes(*path).ok_or_else(badarg)?;
            let name = String::from_utf8(path).map_err(|_| badarg())?;
            let args = args
                .into_iter()
                .map(|arg| String::from_utf8(arg).map(Into::into).map_err(|_| badarg()))
                .collect::<Result<Vec<OsString>, _>>()?;
            let executable_path = if name.contains('/') {
                OsString::from(&name)
            } else {
                OsString::from(format!("./{name}"))
            };
            (name, true, executable_path, args)
        }
        [kind, cmd] if *kind == atom("spawn") => {
            let cmd = bytes(*cmd).ok_or_else(badarg)?;
            let name = String::from_utf8(cmd).map_err(|_| badarg())?;
            (
                name.clone(),
                false,
                OsString::from("/bin/sh"),
                vec![OsString::from("-c"), OsString::from(name)],
            )
        }
        _ => return Err(badarg()),
    };
    let child_arg0 = if executable {
        arg0.map(|arg0| {
            String::from_utf8(arg0)
                .map(OsString::from)
                .map_err(|_| badarg())
        })
        .transpose()?
    } else {
        None
    };
    let child_cwd = cwd
        .map(|cwd| {
            String::from_utf8(cwd)
                .map(OsString::from)
                .map_err(|_| badarg())
        })
        .transpose()?;
    // Port of erts/emulator/beam/erl_bif_port.c:1024 (default child environment), OTP-29.1.1.
    let mut child_env = crate::natives::env::snapshot();
    // Keep `erl` child launchers on this VM's selected installation when the port changes cwd.
    if erl_launcher(&name, executable)
        && let Some(root) = process
            .runtime
            .as_ref()
            .and_then(|runtime| runtime.otp_root())
    {
        let mut paths = vec![root.join("bin")];
        if let Some(path) = child_env
            .iter()
            .find_map(|(key, value)| (key == "PATH").then_some(value.clone()))
        {
            paths.extend(std::env::split_paths(&path));
        }
        if let Ok(path) = std::env::join_paths(paths) {
            child_env.retain(|(key, _)| key != "PATH");
            child_env.push((OsString::from("PATH"), path));
        }
    }
    for (key, value) in env {
        let key = OsString::from(String::from_utf8(key).map_err(|_| badarg())?);
        child_env.retain(|(existing, _)| existing != &key);
        if let Some(value) = value {
            child_env.push((
                key,
                OsString::from(String::from_utf8(value).map_err(|_| badarg())?),
            ));
        }
    }
    let env_size = child_env
        .iter()
        .map(|(key, value)| key.as_bytes().len() + value.as_bytes().len() + 2)
        .sum::<usize>();
    let mut config_path = None;
    let mut command = if env_size > INLINE_ENV_LIMIT || child_cwd.is_some() {
        // Port of erts/emulator/sys/unix/erl_child_setup.c:220-363, OTP-29.1.1.
        let helper = port_exec_helper().ok_or_else(badarg)?;
        let path = write_port_exec_config(
            &child_program,
            &child_args,
            child_arg0.as_deref(),
            child_cwd.as_deref(),
            &child_env,
        )
        .map_err(|_| badarg())?;
        config_path = Some(path.clone());
        let mut helper_command = Command::new(helper);
        helper_command
            .arg("--port-exec-config")
            .arg(path)
            .env_clear();
        helper_command
    } else {
        let mut child_command = Command::new(child_program);
        child_command.args(child_args).env_clear().envs(child_env);
        if let Some(arg0) = child_arg0 {
            child_command.arg0(arg0);
        }
        if let Some(cwd) = child_cwd {
            child_command.current_dir(cwd);
        }
        child_command
    };
    command
        .stdin(if rw & 2 != 0 {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(if rw & 1 != 0 {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stderr(if stderr_to_stdout {
            Stdio::inherit()
        } else {
            Stdio::null()
        });
    if stderr_to_stdout {
        // SAFETY: The child has a valid stdout pipe when this closure runs; dup2 only redirects fd 2.
        unsafe {
            command.pre_exec(move || {
                unsafe extern "C" {
                    fn dup2(oldfd: i32, newfd: i32) -> i32;
                }
                if dup2(1, 2) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if !use_stdio {
                    if rw & 2 != 0 && dup2(0, 3) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    if rw & 1 != 0 && dup2(1, 4) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                }
                Ok(())
            });
        }
    } else if !use_stdio {
        // SAFETY: The child stdio descriptors are prepared by Command before this closure runs.
        unsafe {
            command.pre_exec(move || {
                unsafe extern "C" {
                    fn dup2(oldfd: i32, newfd: i32) -> i32;
                }
                if rw & 2 != 0 && dup2(0, 3) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if rw & 1 != 0 && dup2(1, 4) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            if let Some(path) = config_path {
                let _ = std::fs::remove_file(path);
            }
            if executable {
                let reason = match error.kind() {
                    std::io::ErrorKind::NotFound => "enoent",
                    std::io::ErrorKind::PermissionDenied => "eacces",
                    _ => return Err(badarg()),
                };
                return Err(VmError::Trap(crate::exceptions::Trap::error(atom(reason))));
            }
            return Err(badarg());
        }
    };
    let os_pid = child.id();
    let out = child.stdin.take().map(owned_stdio);
    let read_fd = child
        .stdout
        .take()
        .map(|stdout: ChildStdout| stdout.into_raw_fd());
    let runtime = process.runtime.as_ref().ok_or_else(badarg)?;
    let scheduler = runtime.scheduler()?;
    let port_id = runtime
        .next_port
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let port = Term::port(port_id).ok_or_else(badarg)?;
    let handle = make_handle(
        port_id,
        out,
        framing,
        ctx.pid(),
        os_pid,
        name,
        parallelism,
        limits,
        Arc::clone(&scheduler),
        false,
    )?;
    runtime
        .ports
        .lock()
        .unwrap()
        .insert(port_id, Arc::clone(&handle));
    let owner = ctx.pid();
    std::thread::Builder::new()
        .name(format!("arinsal-port-{port_id}"))
        .spawn(move || {
            worker(
                handle,
                Some(child),
                read_fd,
                scheduler,
                owner,
                port_id,
                binary,
                framing,
                want_status,
                want_eof,
            );
        })
        .map_err(|_| badarg())?;
    let _ = vm;
    Ok(port)
}

// Port of erts/emulator/drivers/common/inet_drv.c:1361 (tcp_inet driver entry), OTP-29.1.1.
// `tcp_inet6` is the same driver; OPEN carries the address family.
// g_inet_udp: `udp_inet` is the only datagram driver erts registers.
// `udp_inet6` and `sctp_inet` are absent, so `open_port` stays `badarg`
// and `prim_inet` maps that onto `{error, eprotonosupport}`.
fn start_driver(
    process: &Process,
    ctx: &RunCtx<'_, Message>,
    name: String,
) -> Result<Term, VmError> {
    let udp = name == "udp_inet";
    if name != "tcp_inet" && name != "tcp_inet6" && !udp {
        return Err(badarg());
    }
    let runtime = process.runtime.as_ref().ok_or_else(badarg)?;
    let scheduler = runtime.scheduler()?;
    let port_id = runtime
        .next_port
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let port = Term::port(port_id).ok_or_else(badarg)?;
    let handle = make_handle(
        port_id,
        None,
        None,
        ctx.pid(),
        0,
        name,
        false,
        default_limits(),
        scheduler,
        true,
    )?;
    runtime
        .ports
        .lock()
        .unwrap()
        .insert(port_id, Arc::clone(&handle));
    // g_inet_udp
    if udp {
        crate::inet_udp::attach(Arc::clone(runtime), port_id, Arc::clone(&handle));
    } else {
        crate::inet_drv::attach(Arc::clone(runtime), port_id, Arc::clone(&handle));
    }
    Ok(port)
}

/// `open_port` options that become driver port state flags.
struct DriverIoFlags {
    binary: bool,
    eof: bool,
    line: Option<usize>,
}

/// Port of erts/emulator/beam/io.c:542 (erts_open_driver) for a dynamically loaded
/// driver, with the state flags erl_bif_port.c:1140 sets after `start`.
fn start_dyn_driver(
    process: &Process,
    ctx: &RunCtx<'_, Message>,
    handle_id: u64,
    driver: Arc<arinsal_drv::Driver>,
    name: String,
    io: DriverIoFlags,
) -> Result<Term, VmError> {
    let runtime = process.runtime.as_ref().ok_or_else(badarg)?;
    let scheduler = runtime.scheduler()?;
    let port_id = runtime
        .next_port
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let port = Term::port(port_id).ok_or_else(badarg)?;
    let handle = make_handle(
        port_id,
        None,
        None,
        ctx.pid(),
        0,
        name.clone(),
        false,
        default_limits(),
        Arc::clone(&scheduler),
        false,
    )?;
    let host = DrvHost {
        runtime: Arc::downgrade(runtime),
    };
    let drv_port = arinsal_drv::DriverPort::new(Arc::clone(&driver), port_id, Box::new(host));
    let _ = handle.driver.set(Arc::clone(&drv_port));
    crate::ddll::port_opened(handle_id, &drv_port);
    runtime
        .ports
        .lock()
        .unwrap()
        .insert(port_id, Arc::clone(&handle));
    let caller = packed_pid(ctx.pid());
    if let Err(error) = drv_port.start(&name, caller) {
        runtime.ports.lock().unwrap().remove(&port_id);
        drv_port.abandon();
        release_io(&handle);
        crate::ddll::port_closed(&scheduler, &driver);
        // Port of erts/emulator/beam/erl_bif_port.c:69-89 (open_port error atoms).
        return Ok(match error {
            arinsal_drv::StartError::General => atom("einval"),
            arinsal_drv::StartError::Errno(errno) => atom(&arinsal_drv::errno_id(errno)),
            arinsal_drv::StartError::Badarg => atom("badarg"),
        });
    }
    drv_port.set_io_flags(io.binary, io.eof, io.line);
    Ok(port)
}

/// Caller identity for drivers (`prt->caller`): `index | generation << 32`.
fn packed_pid(pid: Pid) -> u64 {
    u64::from(pid.index) | (u64::from(pid.generation) << 32)
}

/// `PortHost` for a dynamically loaded driver port.
struct DrvHost {
    runtime: Weak<crate::process::Runtime>,
}

impl DrvHost {
    fn handle(&self, id: u64) -> Option<Arc<PortHandle>> {
        self.runtime
            .upgrade()?
            .ports
            .lock()
            .unwrap()
            .get(&id)
            .cloned()
    }
}

impl arinsal_drv::PortHost for DrvHost {
    // Port of erts/emulator/beam/io.c:3357 (deliver_read_message), OTP-29.1.1.
    fn deliver_data(
        &self,
        port: &arinsal_drv::DriverPort,
        header: &[u8],
        data: Option<&[u8]>,
        binary: bool,
        line: Option<bool>,
    ) {
        let Some(handle) = self.handle(port.id()) else {
            return;
        };
        let Some(port_term) = Term::port(port.id()) else {
            return;
        };
        let owner = handle.owner_pid();
        let len = data.map_or(0, <[u8]>::len) + header.len();
        let mut heap = ProcessHeap::with_words(output_heap_words(len, false, 32));
        let build = |heap: &mut ProcessHeap| -> Result<Term, arinsal_term::TermError> {
            let mut list = match data {
                Some(bytes) if binary => TermBuilder::new(heap).binary(bytes)?,
                Some(bytes) => TermBuilder::new(heap)
                    .list_from_iter(bytes.iter().map(|b| Term::small(*b as i64).unwrap()))?,
                None => Term::NIL,
            };
            for byte in header.iter().rev() {
                list = TermBuilder::new(heap).cons(Term::small(*byte as i64).unwrap(), list)?;
            }
            if let Some(eol) = line {
                list = TermBuilder::new(heap)
                    .tuple(&[atom(if eol { "eol" } else { "noeol" }), list])?;
            }
            let data = TermBuilder::new(heap).tuple(&[atom("data"), list])?;
            TermBuilder::new(heap).tuple(&[port_term, data])
        };
        if let Ok(message) = build(&mut heap) {
            publish(&handle.scheduler, owner, port_term, message);
        }
    }

    fn deliver_eof(&self, port: &arinsal_drv::DriverPort) {
        if let Some(handle) = self.handle(port.id()) {
            event_message(
                &handle.scheduler,
                handle.owner_pid(),
                port.id(),
                atom("eof"),
            );
        }
    }

    fn exit(&self, port: &arinsal_drv::DriverPort, reason: arinsal_drv::ExitReason) {
        let Some(runtime) = self.runtime.upgrade() else {
            port.terminate();
            return;
        };
        let reason = match reason {
            arinsal_drv::ExitReason::Normal => atom("normal"),
            arinsal_drv::ExitReason::Code(code) => {
                Term::small(i64::from(code)).unwrap_or_else(|| atom("normal"))
            }
            arinsal_drv::ExitReason::Atom(name) => atom(&name),
        };
        driver_port_exit(&runtime, port.id(), reason);
    }

    fn unlink_connected(&self, port: &arinsal_drv::DriverPort) {
        if let Some(handle) = self.handle(port.id()) {
            let owner = handle.owner_pid();
            handle.links.lock().unwrap().remove(&owner);
        }
    }
}

/// Port of erts/emulator/beam/io.c:3841 (erts_deliver_port_exit) for a driver that
/// fails: the port terminates (`stop`), then links and monitors see `reason`.
fn driver_port_exit(runtime: &crate::process::Runtime, id: u64, reason: Term) {
    let Some(handle) = runtime.ports.lock().unwrap().remove(&id) else {
        return;
    };
    let owner = handle.owner_pid();
    let scheduler = Arc::clone(&handle.scheduler);
    release_io(&handle);
    notify_exit(&handle, id, &scheduler, owner, reason);
}

fn default_limits() -> BusyLimits {
    BusyLimits {
        port_low: DEFAULT_LOW,
        port_high: DEFAULT_HIGH,
        port_enabled: true,
        msgq_low: DEFAULT_LOW,
        msgq_high: DEFAULT_HIGH,
        msgq_enabled: true,
    }
}

fn erl_launcher(name: &str, executable: bool) -> bool {
    let program = if executable {
        name
    } else {
        let command = name.trim_start();
        command
            .strip_prefix('"')
            .unwrap_or(command)
            .split_whitespace()
            .next()
            .unwrap_or_default()
            .strip_suffix('"')
            .unwrap_or_else(|| {
                command
                    .strip_prefix('"')
                    .unwrap_or(command)
                    .split_whitespace()
                    .next()
                    .unwrap_or_default()
            })
    };
    std::path::Path::new(program)
        .file_name()
        .is_some_and(|file| file == "erl")
}

fn port_exec_helper() -> Option<std::path::PathBuf> {
    let executable = std::env::current_exe().ok()?;
    if executable.file_stem().is_some_and(|name| name == "arinsal") {
        return Some(executable);
    }
    let mut directory = executable.parent();
    while let Some(parent) = directory {
        let candidate = parent.join("arinsal");
        if candidate.is_file() {
            return Some(candidate);
        }
        directory = parent.parent();
    }
    None
}

/// Allocate a connected `tcp_inet` port for an accepted socket.
pub(crate) fn alloc_inet_port(
    runtime: &crate::process::Runtime,
    owner: Pid,
    name: String,
) -> Result<(u64, Arc<PortHandle>), VmError> {
    let scheduler = runtime.scheduler()?;
    let port_id = runtime
        .next_port
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let handle = make_handle(
        port_id,
        None,
        None,
        owner,
        0,
        name,
        false,
        default_limits(),
        scheduler,
        true,
    )?;
    runtime
        .ports
        .lock()
        .unwrap()
        .insert(port_id, Arc::clone(&handle));
    Ok((port_id, handle))
}

/// Remove an inet port after the peer closes an active socket (`driver_exit`).
pub(crate) fn abandon_port(runtime: &crate::process::Runtime, id: u64) {
    let Some(handle) = runtime.ports.lock().unwrap().remove(&id) else {
        return;
    };
    crate::inet_drv::detach(id);
    // g_inet_udp
    crate::inet_udp::detach(id);
    let owner = *handle.owner.lock().unwrap();
    let scheduler = Arc::clone(&handle.scheduler);
    release_io(&handle);
    notify_closed(&handle, id, &scheduler, owner, false);
}

fn notify_closed(
    handle: &PortHandle,
    id: u64,
    scheduler: &Scheduler<Process>,
    from: Pid,
    skip_owner: bool,
) {
    notify_links_monitors(handle, id, scheduler, from, skip_owner, atom("normal"));
}

fn notify_exit(
    handle: &PortHandle,
    id: u64,
    scheduler: &Scheduler<Process>,
    from: Pid,
    reason: Term,
) {
    notify_links_monitors(handle, id, scheduler, from, false, reason);
}

fn notify_links_monitors(
    handle: &PortHandle,
    id: u64,
    scheduler: &Scheduler<Process>,
    from: Pid,
    skip_owner: bool,
    reason: Term,
) {
    let Some(port) = Term::port(id) else {
        return;
    };
    for linked in handle.links.lock().unwrap().iter().copied() {
        if skip_owner && linked == from {
            continue;
        }
        if let (Ok(port_message), Ok(reason_message)) =
            (Message::copy_from(port), Message::copy_from(reason))
        {
            let _ = scheduler.signal(
                from,
                linked,
                arinsal_sched::Signal::PortExit {
                    port: port_message,
                    reason: reason_message,
                },
            );
        }
    }
    let monitors = std::mem::take(&mut *handle.monitors.lock().unwrap());
    for (reference, monitor) in monitors {
        let mut heap = ProcessHeap::with_words(32);
        let Ok(reference_term) =
            TermBuilder::new(&mut heap).local_ref([reference as u32, (reference >> 32) as u32, 0])
        else {
            continue;
        };
        let Ok(object) = from_owned(&monitor.object, &mut heap) else {
            continue;
        };
        let Ok(down) = TermBuilder::new(&mut heap).tuple(&[
            atom("DOWN"),
            reference_term,
            atom("port"),
            object,
            reason,
        ]) else {
            continue;
        };
        if let Ok(message) = Message::copy_from(down) {
            let _ = scheduler.send(from, monitor.pid, message);
        }
    }
}

fn signal_port_exit(handle: &PortHandle, id: u64, reason: Term) {
    let Some(port) = Term::port(id) else {
        return;
    };
    let owner = *handle.owner.lock().unwrap();
    if let (Ok(port), Ok(reason)) = (Message::copy_from(port), Message::copy_from(reason)) {
        let _ = handle.scheduler.signal(
            owner,
            owner,
            arinsal_sched::Signal::PortExit { port, reason },
        );
    }
}

fn signal_badsig(handle: &PortHandle, id: u64) {
    signal_port_exit(handle, id, atom("badsig"));
}

fn duplicate_fd(fd: RawFd) -> std::io::Result<OwnedFd> {
    unsafe extern "C" {
        fn dup(fd: i32) -> i32;
    }
    // SAFETY: dup returns a fresh descriptor; setting CLOEXEC before it is published
    // prevents a concurrently spawned port child from inheriting this duplicate.
    let copy = unsafe {
        let copy = dup(fd);
        if copy >= 0 && libc::fcntl(copy, libc::F_SETFD, libc::FD_CLOEXEC) < 0 {
            let error = std::io::Error::last_os_error();
            libc::close(copy);
            return Err(error);
        }
        copy
    };
    if copy < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: copy is a fresh descriptor owned by this OwnedFd.
    Ok(unsafe { OwnedFd::from_raw_fd(copy) })
}

fn owned_stdio(file: impl IntoRawFd) -> OwnedFd {
    let fd = file.into_raw_fd();
    set_nonblock(fd);
    // SAFETY: into_raw_fd transferred ownership of this descriptor.
    unsafe { OwnedFd::from_raw_fd(fd) }
}

fn set_nonblock(fd: RawFd) {
    // SAFETY: fcntl only changes flags on a descriptor this port owns.
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        if flags >= 0 {
            libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
        }
    }
}

fn wake_pipe() -> std::io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0; 2];
    // SAFETY: pipe initializes both slots with fresh descriptors on success; fcntl
    // marks those owned descriptors close-on-exec before any child can inherit them.
    let rc = unsafe {
        let rc = libc::pipe(fds.as_mut_ptr());
        if rc == 0
            && (libc::fcntl(fds[0], libc::F_SETFD, libc::FD_CLOEXEC) < 0
                || libc::fcntl(fds[1], libc::F_SETFD, libc::FD_CLOEXEC) < 0)
        {
            let error = std::io::Error::last_os_error();
            libc::close(fds[0]);
            libc::close(fds[1]);
            return Err(error);
        }
        rc
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    set_nonblock(fds[0]);
    set_nonblock(fds[1]);
    // SAFETY: both descriptors were just created by pipe and are not aliased.
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

#[allow(clippy::too_many_arguments)]
fn make_handle(
    id: u64,
    out: Option<OwnedFd>,
    framing: Option<(u8, usize)>,
    owner: Pid,
    os_pid: u32,
    name: String,
    parallelism: bool,
    limits: BusyLimits,
    scheduler: Arc<Scheduler<Process>>,
    inet: bool,
) -> Result<Arc<PortHandle>, VmError> {
    let (wake_r, wake_w) = wake_pipe().map_err(|_| badarg())?;
    if let Some(fd) = out.as_ref() {
        set_nonblock(fd.as_raw_fd());
    }
    let handle = Arc::new(PortHandle {
        id,
        out: Mutex::new(out),
        wake_r: Mutex::new(Some(wake_r)),
        wake_w,
        wake_needed: AtomicBool::new(true),
        framing,
        owner: Mutex::new(owner),
        links: Mutex::new(HashSet::from([owner])),
        monitors: Mutex::new(HashMap::new()),
        os_pid,
        name,
        parallelism,
        limits,
        state: Mutex::new(PortState {
            outq: VecDeque::new(),
            msgq: 0,
            pending: VecDeque::new(),
            busy_port: false,
            busy_msgq: false,
            graceful_close: false,
            send_closed: false,
            exit_complete: false,
            suspended: Vec::new(),
            closed: false,
            broken: false,
            in_output: false,
            profile_active: false,
        }),
        scheduler,
        data: Mutex::new(OwnedTerm::Atom("undefined".into())),
        inet,
        driver: OnceLock::new(),
    });
    Ok(handle)
}

fn start_fd(
    vm: &mut Vm,
    process: &Process,
    ctx: &RunCtx<'_, Message>,
    input_fd: RawFd,
    output_fd: RawFd,
    opts: &PortOptions,
) -> Result<Term, VmError> {
    let reader = duplicate_fd(input_fd).map_err(|_| badarg())?;
    let writer = duplicate_fd(output_fd).map_err(|_| badarg())?;
    let runtime = process.runtime.as_ref().ok_or_else(badarg)?;
    let scheduler = runtime.scheduler()?;
    let id = runtime
        .next_port
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let port = Term::port(id).ok_or_else(badarg)?;
    let handle = make_handle(
        id,
        Some(writer),
        opts.framing,
        ctx.pid(),
        0,
        format!("fd {input_fd} {output_fd}"),
        opts.parallelism,
        opts.limits,
        Arc::clone(&scheduler),
        false,
    )?;
    runtime
        .ports
        .lock()
        .unwrap()
        .insert(id, Arc::clone(&handle));
    let owner = ctx.pid();
    let read_fd = reader.into_raw_fd();
    let binary = opts.binary;
    let framing = opts.framing;
    let want_eof = opts.eof;
    std::thread::Builder::new()
        .name(format!("arinsal-port-{id}"))
        .spawn(move || {
            worker(
                handle,
                None,
                Some(read_fd),
                scheduler,
                owner,
                id,
                binary,
                framing,
                false,
                want_eof,
            );
        })
        .map_err(|_| badarg())?;
    let _ = vm;
    Ok(port)
}

fn output_fd(handle: &PortHandle) -> RawFd {
    handle
        .out
        .lock()
        .unwrap()
        .as_ref()
        .map(|fd| fd.as_raw_fd())
        .unwrap_or(-1)
}

fn nb_write(fd: RawFd, buf: &[u8]) -> std::io::Result<usize> {
    if fd < 0 {
        return Err(std::io::Error::from_raw_os_error(libc::EBADF));
    }
    loop {
        // SAFETY: `buf` is a live slice and `fd` belongs to this port.
        let n = unsafe { libc::write(fd, buf.as_ptr().cast(), buf.len()) };
        if n >= 0 {
            return Ok(n as usize);
        }
        let err = std::io::Error::last_os_error();
        if err.kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        if err.kind() == std::io::ErrorKind::WouldBlock {
            return Ok(0);
        }
        return Err(err);
    }
}

fn poke(handle: &PortHandle) {
    if handle.wake_needed.swap(false, Ordering::AcqRel) {
        let fd = handle.wake_w.as_raw_fd();
        // SAFETY: the wake pipe write end stays open for the life of the handle.
        unsafe {
            libc::write(fd, (&1u8 as *const u8).cast(), 1);
        }
    }
}

fn wake_suspended(scheduler: &Scheduler<Process>, pids: Vec<Pid>) {
    for pid in pids {
        // UnlinkAck wakes a waiting process without entering its mailbox.
        let _ = scheduler.signal(pid, pid, arinsal_sched::Signal::UnlinkAck(0));
    }
}

fn refresh_busy(st: &mut PortState, limits: &BusyLimits) -> Vec<Pid> {
    // Port of erts/emulator/sys/unix/sys_drivers.c:1479 (ready_output low watermark), OTP-29.1.1.
    if limits.port_enabled && st.busy_port && st.outq.len() < limits.port_low {
        st.busy_port = false;
    }
    // Port of erts/emulator/beam/erl_port_task.c:706 (dequeued_proc2port_data), OTP-29.1.1.
    if limits.msgq_enabled && st.busy_msgq && st.msgq < limits.msgq_low {
        st.busy_msgq = false;
    }
    if !st.busy_port && !st.busy_msgq {
        std::mem::take(&mut st.suspended)
    } else {
        Vec::new()
    }
}

/// Accept `data` into the driver output queue. Sets the busy-port flag when the
/// unwritten queue reaches the high watermark.
fn accept_output(handle: &PortHandle, st: &mut PortState, data: &[u8]) -> Result<(), ()> {
    if st.closed || st.broken {
        return Err(());
    }
    // Port of erts/emulator/sys/unix/sys_drivers.c:1140 (output), OTP-29.1.1.
    if st.outq.is_empty() {
        match nb_write(output_fd(handle), data) {
            Ok(n) if n == data.len() => return Ok(()),
            Ok(n) => st.outq.extend(data[n..].iter().copied()),
            Err(_) => {
                st.broken = true;
                return Err(());
            }
        }
    } else {
        st.outq.extend(data.iter().copied());
    }
    if handle.limits.port_enabled && !st.busy_port && st.outq.len() >= handle.limits.port_high {
        st.busy_port = true;
    }
    Ok(())
}

fn note_msgq(st: &mut PortState, limits: &BusyLimits, extra: usize) {
    if !limits.msgq_enabled || extra == 0 {
        return;
    }
    st.msgq = st.msgq.saturating_add(extra);
    // Port of erts/emulator/beam/erl_port_task.c:744 (enqueue_proc2port_data), OTP-29.1.1.
    if !st.busy_msgq && st.msgq > limits.msgq_high {
        st.busy_msgq = true;
    }
}

fn flush_output(handle: &PortHandle) -> Vec<Pid> {
    let mut woken = Vec::new();
    let mut became_inactive = false;
    loop {
        let mut st = handle.state.lock().unwrap();
        if st.outq.is_empty() {
            woken.extend(refresh_busy(&mut st, &handle.limits));
            if st.pending.is_empty() && st.profile_active {
                st.profile_active = false;
                became_inactive = true;
            }
            break;
        }
        let n = st.outq.len().min(16 * 1024);
        let chunk: Vec<u8> = st.outq.drain(..n).collect();
        drop(st);
        match nb_write(output_fd(handle), &chunk) {
            Ok(0) => {
                let mut st = handle.state.lock().unwrap();
                for byte in chunk.into_iter().rev() {
                    st.outq.push_front(byte);
                }
                break;
            }
            Ok(wrote) if wrote < chunk.len() => {
                let mut st = handle.state.lock().unwrap();
                for byte in chunk[wrote..].iter().rev() {
                    st.outq.push_front(*byte);
                }
                woken.extend(refresh_busy(&mut st, &handle.limits));
                break;
            }
            Ok(_) => {
                let mut st = handle.state.lock().unwrap();
                woken.extend(refresh_busy(&mut st, &handle.limits));
            }
            Err(_) => {
                let mut st = handle.state.lock().unwrap();
                st.broken = true;
                st.busy_port = false;
                st.busy_msgq = false;
                st.outq.clear();
                became_inactive = std::mem::replace(&mut st.profile_active, false);
                woken.extend(std::mem::take(&mut st.suspended));
                break;
            }
        }
    }
    if became_inactive {
        crate::natives::misc::profile_port_event(
            &handle.scheduler,
            handle.owner_pid(),
            handle.id,
            false,
        );
    }
    woken
}

fn drain_pending(handle: &PortHandle) -> Vec<Pid> {
    let mut woken = Vec::new();
    loop {
        let next = {
            let mut st = handle.state.lock().unwrap();
            if st.in_output {
                return woken;
            }
            let Some(data) = st.pending.pop_front() else {
                return woken;
            };
            st.msgq = st.msgq.saturating_sub(data.len());
            st.in_output = true;
            data
        };
        let failed = {
            let mut st = handle.state.lock().unwrap();
            let failed = accept_output(handle, &mut st, &next).is_err();
            st.in_output = false;
            woken.extend(refresh_busy(&mut st, &handle.limits));
            failed
        };
        if failed {
            let mut st = handle.state.lock().unwrap();
            st.broken = true;
            woken.extend(std::mem::take(&mut st.suspended));
            return woken;
        }
    }
}

fn command_bytes(handle: &PortHandle, data: &[u8]) -> Result<(), ()> {
    let became_active = {
        let mut st = handle.state.lock().unwrap();
        if st.closed || st.broken {
            return Err(());
        }
        // Parallel commands that arrive while output is in progress join the
        // port task queue (busy_limits_msgq) instead of the driver queue.
        if handle.parallelism && st.in_output {
            note_msgq(&mut st, &handle.limits, data.len());
            st.pending.push_back(data.to_vec());
        } else {
            st.in_output = true;
            let failed = accept_output(handle, &mut st, data).is_err();
            st.in_output = false;
            if failed {
                return Err(());
            }
        }
        let runnable = !st.outq.is_empty() || !st.pending.is_empty();
        let became_active = runnable && !st.profile_active;
        st.profile_active |= runnable;
        became_active
    };
    if became_active {
        crate::natives::misc::profile_port_event(
            &handle.scheduler,
            handle.owner_pid(),
            handle.id,
            true,
        );
    }
    poke(handle);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn worker(
    handle: Arc<PortHandle>,
    mut child: Option<Child>,
    mut read_fd: Option<RawFd>,
    scheduler: Arc<Scheduler<Process>>,
    owner: Pid,
    id: u64,
    binary: bool,
    framing: Option<(u8, usize)>,
    want_status: bool,
    want_eof: bool,
) {
    let wake_r = handle
        .wake_r
        .lock()
        .unwrap()
        .take()
        .map(|fd| fd.into_raw_fd())
        .unwrap_or(-1);
    let mut data = Vec::new();
    let mut buf = [0u8; 4096];
    let mut saw_eof = false;
    let mut input_closed = false;
    loop {
        let closed = handle.state.lock().unwrap().closed;
        if closed {
            break;
        }
        let wants_out = !handle.state.lock().unwrap().outq.is_empty()
            || !handle.state.lock().unwrap().pending.is_empty();
        handle.wake_needed.store(true, Ordering::Release);
        let mut fds = Vec::with_capacity(3);
        if let Some(fd) = read_fd {
            fds.push((
                fd,
                crate::check_io::InterestSet {
                    readable: true,
                    writable: false,
                },
            ));
        }
        if wake_r >= 0 {
            fds.push((
                wake_r,
                crate::check_io::InterestSet {
                    readable: true,
                    writable: false,
                },
            ));
        }
        let write_fd = output_fd(&handle);
        if wants_out && write_fd >= 0 {
            fds.push((
                write_fd,
                crate::check_io::InterestSet {
                    readable: false,
                    writable: true,
                },
            ));
        }
        if handle.state.lock().unwrap().closed
            || !handle.state.lock().unwrap().outq.is_empty()
            || !handle.state.lock().unwrap().pending.is_empty()
        {
            handle.wake_needed.store(false, Ordering::Release);
        }
        let mut input_ready = false;
        if !handle.state.lock().unwrap().closed {
            // Port of `erts_check_io` one-shot readiness delivery; every
            // operation is re-registered after this worker handles the event.
            let result = crate::check_io::wait_any(&fds);
            match result {
                Ok(Some((ready_fd, ready))) => {
                    input_ready = Some(ready_fd) == read_fd
                        && (ready.readable || ready.closed || ready.error);
                }
                Ok(None) => continue,
                Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            }
        }
        handle.wake_needed.store(false, Ordering::Release);
        if wake_r >= 0 {
            let mut scratch = [0u8; 64];
            loop {
                // SAFETY: scratch is a live buffer and wake_r is the port's self-pipe.
                let n = unsafe { libc::read(wake_r, scratch.as_mut_ptr().cast(), scratch.len()) };
                if n > 0 {
                    continue;
                }
                break;
            }
        }
        if handle.state.lock().unwrap().closed {
            break;
        }
        let woken = drain_pending(&handle);
        wake_suspended(&scheduler, woken);
        let woken = flush_output(&handle);
        wake_suspended(&scheduler, woken);
        if !input_closed {
            let should_close_input = {
                let st = handle.state.lock().unwrap();
                st.graceful_close && st.outq.is_empty() && st.pending.is_empty()
            };
            if should_close_input {
                handle.out.lock().unwrap().take();
                input_closed = true;
            }
        }
        if input_ready && let Some(fd) = read_fd {
            // SAFETY: `buf` is a live buffer and `fd` is the port's input descriptor.
            let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
            if n < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::Interrupted
                    || err.kind() == std::io::ErrorKind::WouldBlock
                {
                    continue;
                }
                saw_eof = true;
                read_fd = None;
            } else if n == 0 {
                saw_eof = true;
                read_fd = None;
            } else {
                let n = n as usize;
                if framing.is_none() {
                    output_message(&scheduler, owner, id, &buf[..n], binary);
                } else {
                    data.extend_from_slice(&buf[..n]);
                    decode_frames(&scheduler, owner, id, &mut data, binary, framing);
                }
            }
        }
        let st = handle.state.lock().unwrap();
        if saw_eof && st.outq.is_empty() && st.pending.is_empty() {
            break;
        }
        if input_closed && read_fd.is_none() && st.outq.is_empty() && st.pending.is_empty() {
            break;
        }
        drop(st);
    }
    let woken = flush_output(&handle);
    wake_suspended(&scheduler, woken);
    if wake_r >= 0 {
        // SAFETY: this thread owns the wake read end taken from the handle.
        unsafe { libc::close(wake_r) };
    }
    if let Some(fd) = read_fd {
        // SAFETY: the worker owns the duplicated input descriptor.
        unsafe { libc::close(fd) };
    }
    let closed = handle.state.lock().unwrap().closed;
    if !closed && saw_eof && !data.is_empty() {
        if framing.is_some_and(|(mode, _)| mode == 1) {
            line_message(&scheduler, owner, id, &data, binary, false);
        } else {
            output_message(&scheduler, owner, id, &data, binary);
        }
    }
    // Port of erts/emulator/sys/unix/sys_drivers.c:1039 (stop), OTP-29.1.1.
    // Close the child's input first; a detached child may keep running after
    // the port descriptors close, so reap it only after its own exit.
    if let Some(mut child) = child.take() {
        if closed {
            handle.out.lock().unwrap().take();
        }
        let status = child.wait().ok();
        if !closed && want_status {
            let code = status.and_then(|status| status.code()).unwrap_or(1);
            let mut heap = ProcessHeap::with_words(16);
            if let Ok(event) = TermBuilder::new(&mut heap)
                .tuple(&[atom("exit_status"), Term::small(code as i64).unwrap()])
            {
                event_message(&scheduler, owner, id, event);
            }
        }
    }
    handle.state.lock().unwrap().exit_complete = true;
    if !closed && saw_eof && want_eof {
        event_message(&scheduler, owner, id, atom("eof"));
    }
    if !closed && handle.state.lock().unwrap().send_closed {
        event_message(&scheduler, owner, id, atom("closed"));
    }
    if !closed {
        // Port of erts/emulator/beam/io.c:3841-3891 (erts_deliver_port_exit), OTP-29.1.1.
        notify_closed(&handle, id, &scheduler, owner, false);
    }
}

fn decode_frames(
    scheduler: &Scheduler<Process>,
    owner: Pid,
    id: u64,
    data: &mut Vec<u8>,
    binary: bool,
    framing: Option<(u8, usize)>,
) {
    let Some((mode, size)) = framing else {
        return;
    };
    loop {
        if mode == 1 {
            let newline = data.iter().position(|b| *b == b'\n');
            // Port of erts/emulator/beam/io.c:3228-3295 (read_linebuf), OTP-29.1.1.
            // A newline at the limit completes the line; after a full buffer,
            // only CRLF may consume one extra byte before completing it.
            let newline_fits = newline.is_some_and(|n| {
                n <= size || (n == size + 1 && data.get(n.wrapping_sub(1)) == Some(&b'\r'))
            });
            let chunk_len = newline
                .filter(|_| newline_fits)
                .map(|n| n + 1)
                .or_else(|| (size > 0 && data.len() >= size).then_some(size));
            let Some(n) = chunk_len else { break };
            let mut body = data[..n].to_vec();
            let complete = body.last() == Some(&b'\n');
            if complete {
                body.pop();
                if body.last() == Some(&b'\r') {
                    body.pop();
                }
            }
            line_message(scheduler, owner, id, &body, binary, complete);
            data.drain(..n);
            continue;
        }
        // mode == 2: length-prefixed packet; `size` is the header width (1, 2, or 4).
        let hdr = size;
        if data.len() < hdr {
            break;
        }
        let body_len = match hdr {
            1 => data[0] as usize,
            2 => u16::from_be_bytes([data[0], data[1]]) as usize,
            4 => u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize,
            _ => break,
        };
        let n = hdr + body_len;
        if data.len() < n {
            break;
        }
        let body = data[hdr..n].to_vec();
        output_message(scheduler, owner, id, &body, binary);
        data.drain(..n);
    }
}

fn lookup_port(process: &Process, term: Term) -> Result<Arc<PortHandle>, VmError> {
    let id = term.as_port().ok_or_else(badarg)?;
    process
        .runtime
        .as_ref()
        .and_then(|runtime| runtime.ports.lock().unwrap().get(&id).cloned())
        .ok_or_else(badarg)
}

pub(crate) fn is_live(process: &Process, id: u64) -> bool {
    process
        .runtime
        .as_ref()
        .and_then(|runtime| runtime.ports.lock().unwrap().get(&id).cloned())
        .is_some_and(|handle| !handle.state.lock().unwrap().exit_complete)
}

// Port of erts/emulator/beam/erl_bif_port.c:734 (port_get_data_1), OTP-29.1.1.
fn port_get_data(process: &mut Process, port: Term) -> Result<Term, VmError> {
    let handle = lookup_port(process, port)?;
    let owned = handle.data.lock().unwrap().clone();
    let mut heap = arinsal_bifs::FragmentingHeap(&mut process.heap);
    from_owned(&owned, &mut heap).map_err(|_| badarg())
}

// Port of erts/emulator/beam/erl_bif_port.c:687 (port_set_data_2), OTP-29.1.1.
fn port_set_data(process: &Process, port: Term, data: Term) -> Result<Term, VmError> {
    let handle = lookup_port(process, port)?;
    let owned = to_owned(data).map_err(|_| badarg())?;
    *handle.data.lock().unwrap() = owned;
    Ok(atom("true"))
}

pub(crate) fn family(
    vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    module: &str,
    function: &str,
    args: &[Term],
) -> Option<Result<Term, VmError>> {
    if module != "erts_internal" && module != "erlang" {
        return None;
    }
    let result = match (function, args) {
        ("open_port", [spec, opts]) if module == "erts_internal" => {
            start(vm, process, ctx, *spec, *opts)
        }
        ("port_command", [port, data, _]) if module == "erts_internal" => {
            port_command(process, ctx, *port, *data, args)
        }
        ("port_close", [port]) if module == "erts_internal" => close(process, *port),
        ("port_connect", [port, pid]) if module == "erts_internal" => {
            connect(process, *port, *pid, false)
        }
        // Port of erts/emulator/beam/erl_bif_port.c:322 (erts_internal_port_control_3), OTP-29.1.1.
        // Spawn and fd ports have no driver control. The internal BIF returns the
        // atom `badarg`; `erlang:port_control/3` turns that atom into an exception.
        ("port_control", [port, op, data]) if module == "erts_internal" => {
            port_control(process, ctx.pid(), *port, *op, *data)
        }
        // Port of erts/emulator/beam/erl_bif_port.c:263 (erts_internal_port_call_3), OTP-29.1.1.
        // Spawn/fd/inet ports here have no driver call path; return the atom `badarg`.
        ("port_call", [port, op, data]) if module == "erts_internal" => {
            port_call(process, ctx.pid(), *port, *op, *data)
        }
        ("port_get_data", [port]) if module == "erlang" => port_get_data(process, *port),
        ("port_set_data", [port, data]) if module == "erlang" => {
            port_set_data(process, *port, *data)
        }
        ("ports", []) if module == "erlang" => ports(vm, process),
        ("port_info", [port]) if module == "erts_internal" => port_info(process, *port, None),
        ("port_info", [port, item]) if module == "erts_internal" => {
            port_info(process, *port, Some(*item))
        }
        _ => return None,
    };
    Some(result)
}

fn copied_reason(reason: Term) -> Option<Message> {
    let mut heap = ProcessHeap::with_words(64);
    let term = copy_term(reason, &mut heap).ok()?;
    Message::copy_from(term).ok()
}

// Port of erts/emulator/beam/erl_bif_port.c:322 (erts_internal_port_control_3), OTP-29.1.1.
// Non-inet ports still return the atom `badarg`. `tcp_inet` returns a byte list.
fn port_control(
    process: &mut Process,
    caller: Pid,
    port: Term,
    op: Term,
    data: Term,
) -> Result<Term, VmError> {
    let Some(id) = port.as_port() else {
        return Ok(atom("badarg"));
    };
    let Some(handle) = process
        .runtime
        .as_ref()
        .and_then(|runtime| runtime.ports.lock().unwrap().get(&id).cloned())
    else {
        return Ok(atom("badarg"));
    };
    if let Some(drv_port) = handle.driver.get() {
        return driver_control(process, caller, drv_port, op, data);
    }
    if !handle.inet {
        return Ok(atom("badarg"));
    }
    let Some(op) = op.as_small() else {
        return Ok(atom("badarg"));
    };
    let Some(data) = bytes(data) else {
        return Ok(atom("badarg"));
    };
    // g_inet_udp
    if crate::inet_udp::owns(id) {
        return crate::inet_udp::control(process, id, caller, op, &data);
    }
    crate::inet_drv::control(process, id, caller, op, &data)
}

// Port of erts/emulator/beam/erl_bif_port.c:263 (erts_internal_port_call_3), OTP-29.1.1.
fn port_call(
    process: &mut Process,
    caller: Pid,
    port: Term,
    op: Term,
    data: Term,
) -> Result<Term, VmError> {
    let Some(id) = port.as_port() else {
        return Ok(atom("badarg"));
    };
    let Some(handle) = process
        .runtime
        .as_ref()
        .and_then(|runtime| runtime.ports.lock().unwrap().get(&id).cloned())
    else {
        return Ok(atom("badarg"));
    };
    let Some(op) = op.as_small().and_then(|n| u32::try_from(n).ok()) else {
        return Ok(atom("badarg"));
    };
    if let Some(drv_port) = handle.driver.get() {
        // Port of erts/emulator/beam/io.c:4618 (erts_port_call).
        let Ok(owned) = to_owned(data) else {
            return Ok(atom("badarg"));
        };
        let encoded = arinsal_etf::encode(&owned, arinsal_etf::EncodeOptions::default());
        let Some(reply) = drv_port.call(op, &encoded, packed_pid(caller)) else {
            return Ok(atom("badarg"));
        };
        let Ok((term, _)) = arinsal_etf::decode_prefix(&reply) else {
            return Ok(atom("badarg"));
        };
        let mut heap = arinsal_bifs::FragmentingHeap(&mut process.heap);
        let term = from_owned(&term, &mut heap).map_err(|_| badarg())?;
        return TermBuilder::new(&mut heap)
            .tuple(&[atom("ok"), term])
            .map_err(|_| badarg());
    }
    // No driver currently implements call; match OTP spawn/inet ports on this machine.
    Ok(atom("badarg"))
}

const ERL_DRV_FLAG_SOFT_BUSY: i32 = 1 << 1;

/// Port of erts/emulator/beam/erl_io_queue.c:441 (erts_ioq_iolist_to_vec) input walk:
/// pieces in order, `true` for a reference-counted binary (larger than
/// ERL_ONHEAP_BINARY_LIMIT).
fn io_pieces(term: Term, out: &mut Vec<(Vec<u8>, bool)>) -> Option<()> {
    fn walk(term: &OwnedTerm, tail: bool, out: &mut Vec<(Vec<u8>, bool)>) -> Option<()> {
        match term {
            OwnedTerm::Nil => Some(()),
            OwnedTerm::List { elems, tail: rest } => {
                for elem in elems {
                    walk(elem, false, out)?;
                }
                walk(rest, true, out)
            }
            OwnedTerm::Binary(bytes) => {
                let refc = bytes.len() > arinsal_drv::ERL_ONHEAP_BINARY_LIMIT;
                out.push((bytes.clone(), refc));
                Some(())
            }
            OwnedTerm::Int(value) if !tail && (0..=255).contains(value) => {
                match out.last_mut() {
                    Some((bytes, false)) => bytes.push(*value as u8),
                    _ => out.push((vec![*value as u8], false)),
                }
                Some(())
            }
            _ => None,
        }
    }
    if term.as_small().is_some() {
        return None;
    }
    walk(&to_owned(term).ok()?, false, out)
}

// Port of erts/emulator/beam/erl_bif_port.c:322 (erts_internal_port_control_3) and
// io.c:4268 (erts_port_control) for a loaded driver.
fn driver_control(
    process: &mut Process,
    caller: Pid,
    drv_port: &arinsal_drv::DriverPort,
    op: Term,
    data: Term,
) -> Result<Term, VmError> {
    let Some(op) = op.as_small().and_then(|n| u32::try_from(n).ok()) else {
        return Ok(atom("badarg"));
    };
    let mut pieces = Vec::new();
    if io_pieces(data, &mut pieces).is_none() {
        return Ok(atom("badarg"));
    }
    let bytes = pieces.into_iter().flat_map(|(b, _)| b).collect::<Vec<_>>();
    let Some(reply) = drv_port.control(op, &bytes, packed_pid(caller)) else {
        return Ok(atom("badarg"));
    };
    let mut heap = arinsal_bifs::FragmentingHeap(&mut process.heap);
    let mut builder = TermBuilder::new(&mut heap);
    match reply {
        arinsal_drv::ControlReply::Nil => Ok(Term::NIL),
        arinsal_drv::ControlReply::Binary(bytes) => builder.binary(&bytes),
        arinsal_drv::ControlReply::List(bytes) => {
            builder.list_from_iter(bytes.iter().map(|b| Term::small(*b as i64).unwrap()))
        }
    }
    .map_err(|_| badarg())
}

fn notsup() -> VmError {
    VmError::Trap(crate::exceptions::Trap::error(atom("notsup")))
}

fn port_command(
    process: &Process,
    ctx: &mut RunCtx<'_, Message>,
    port: Term,
    data: Term,
    args: &[Term],
) -> Result<Term, VmError> {
    // Port of erts/emulator/beam/erl_bif_port.c:168 (erts_internal_port_command_3), OTP-29.1.1.
    let id = port.as_port().ok_or_else(badarg)?;
    let handle = process
        .runtime
        .as_ref()
        .and_then(|runtime| runtime.ports.lock().unwrap().get(&id).cloned())
        .ok_or_else(badarg)?;
    let mut nosuspend = false;
    if args.len() == 3 {
        let options = list(args[2]).ok_or_else(badarg)?;
        for option in options {
            if option == atom("nosuspend") {
                nosuspend = true;
            } else if option == atom("force") {
                // tcp_inet sets ERL_DRV_FLAG_SOFT_BUSY (inet_drv.c driver flags).
                // spawn/fd drivers do not, so `force` is `notsup` there.
                let soft_busy = handle
                    .driver
                    .get()
                    .is_some_and(|d| d.driver().flags() & ERL_DRV_FLAG_SOFT_BUSY != 0);
                if !handle.inet && !soft_busy {
                    return Err(notsup());
                }
            } else {
                return Err(badarg());
            }
        }
    }
    if let Some(drv_port) = handle.driver.get() {
        // Port of erts/emulator/beam/io.c:1715 (erts_port_output) for a loaded driver.
        let mut pieces = Vec::new();
        io_pieces(data, &mut pieces).ok_or_else(badarg)?;
        let pieces = pieces
            .iter()
            .map(|(bytes, refc)| {
                if *refc {
                    arinsal_drv::IoPiece::Refc(bytes)
                } else {
                    arinsal_drv::IoPiece::Copied(bytes)
                }
            })
            .collect::<Vec<_>>();
        if !drv_port.output(&pieces, packed_pid(ctx.pid())) {
            return Err(badarg());
        }
        return Ok(atom("true"));
    }
    let mut framed = iodata(data).ok_or_else(badarg)?;
    if handle.inet {
        let st = handle.state.lock().unwrap();
        if st.closed || st.broken || st.graceful_close {
            return Err(badarg());
        }
        drop(st);
        // Port of erts/emulator/drivers/common/inet_drv.c:12629 (tcp_inet_command), OTP-29.1.1.
        // g_inet_udp: datagram sends use packet_inet_command, not tcp_sendv.
        if crate::inet_udp::owns(id) {
            return crate::inet_udp::command(id, ctx.pid(), &framed).map(|()| atom("true"));
        }
        return crate::inet_drv::command(id, ctx.pid(), &framed).map(|()| atom("true"));
    }
    if let Some((2, hdr)) = handle.framing {
        match hdr {
            1 => {
                if framed.len() > u8::MAX as usize {
                    return Err(badarg());
                }
                framed.insert(0, framed.len() as u8);
            }
            2 => {
                if framed.len() > u16::MAX as usize {
                    return Err(badarg());
                }
                let len = (framed.len() as u16).to_be_bytes();
                framed.splice(0..0, len);
            }
            4 => {
                if framed.len() > u32::MAX as usize {
                    return Err(badarg());
                }
                let len = (framed.len() as u32).to_be_bytes();
                framed.splice(0..0, len);
            }
            _ => return Err(badarg()),
        }
    }
    {
        let mut st = handle.state.lock().unwrap();
        if st.closed || st.broken {
            return Err(badarg());
        }
        // Port of erts/emulator/beam/io.c:1754 (erts_port_output), OTP-29.1.1.
        if st.busy_port || st.busy_msgq {
            if nosuspend {
                return Ok(atom("false"));
            }
            let busy_port = st.busy_port;
            st.suspended.push(ctx.pid());
            drop(st);
            if busy_port {
                crate::natives::erts_debug::notify_busy_port(process, ctx.pid(), id);
            }
            BUSY_SUSPEND.with(|flag| flag.set(true));
            return Err(badarg());
        }
    }
    command_bytes(&handle, &framed).map_err(|()| badarg())?;
    Ok(atom("true"))
}

// Port of erts/emulator/sys/unix/sys_drivers.c:1039 (stop), OTP-29.1.1.
// Closing a port releases its descriptors; the child may have detached from them.
fn release_io(handle: &PortHandle) {
    // Port of erts/emulator/beam/io.c:3698 (terminate_port) for a dynamic driver.
    if let Some(drv_port) = handle.driver.get()
        && drv_port.terminate()
    {
        crate::ddll::port_closed(&handle.scheduler, drv_port.driver());
    }
    let waiters = {
        let mut st = handle.state.lock().unwrap();
        st.closed = true;
        st.broken = true;
        st.busy_port = false;
        st.busy_msgq = false;
        std::mem::take(&mut st.suspended)
    };
    wake_suspended(&handle.scheduler, waiters);
    poke(handle);
}

fn close(process: &Process, term: Term) -> Result<Term, VmError> {
    let sender = process.self_pid.ok_or_else(badarg)?;
    let runtime = process.runtime.as_ref().ok_or_else(badarg)?;
    let scheduler = runtime.scheduler().map_err(|_| badarg())?;
    let id = term.as_port().ok_or_else(badarg)?;
    let removed = process
        .runtime
        .as_ref()
        .and_then(|r| r.ports.lock().unwrap().remove(&id));
    if let Some(handle) = removed {
        if handle.inet {
            crate::inet_drv::detach(id);
            // g_inet_udp
            crate::inet_udp::detach(id);
        }
        release_io(&handle);
        let reason_term = atom("normal");
        let port = Term::port(id).ok_or_else(badarg)?;
        for linked in handle.links.lock().unwrap().iter().copied() {
            if linked == sender && process.trap_exit {
                let mut heap = ProcessHeap::with_words(24);
                let exit = TermBuilder::new(&mut heap)
                    .tuple(&[atom("EXIT"), port, reason_term])
                    .map_err(|error| VmError::Unsupported(format!("port EXIT tuple: {error:?}")))?;
                if let Ok(message) = Message::copy_from(exit) {
                    let _ = scheduler.send(sender, linked, message);
                }
                continue;
            }
            if let Ok(reason) = Message::copy_from(reason_term) {
                let _ = scheduler.signal(sender, linked, arinsal_sched::Signal::Exit(reason));
            }
        }
        let monitors = std::mem::take(&mut *handle.monitors.lock().unwrap());
        for (reference, monitor) in monitors {
            let mut heap = ProcessHeap::with_words(32);
            let reference_term = TermBuilder::new(&mut heap)
                .local_ref([reference as u32, (reference >> 32) as u32, 0])
                .map_err(|error| {
                    VmError::Unsupported(format!("port monitor reference: {error:?}"))
                })?;
            let object = from_owned(&monitor.object, &mut heap)
                .map_err(|error| VmError::Unsupported(format!("port monitor object: {error:?}")))?;
            let down = TermBuilder::new(&mut heap)
                .tuple(&[
                    atom("DOWN"),
                    reference_term,
                    atom("port"),
                    object,
                    atom("normal"),
                ])
                .map_err(|error| VmError::Unsupported(format!("port DOWN tuple: {error:?}")))?;
            if let Ok(message) = Message::copy_from(down) {
                let _ = scheduler.send(sender, monitor.pid, message);
            }
        }
        Ok(atom("true"))
    } else {
        Err(badarg())
    }
}

/// Close a runtime port selected by its internal id.
pub(crate) fn close_by_id(
    process: &Process,
    _ctx: &mut RunCtx<'_, Message>,
    id: u64,
) -> Result<bool, VmError> {
    let term = Term::port(id).ok_or_else(badarg)?;
    close(process, term).map(|result| result == atom("true"))
}

/// Apply an exit signal to a port and deliver its reason to linked processes.
pub(crate) fn exit_port(
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    port: Term,
    reason: Term,
) -> Result<(), VmError> {
    let id = port.as_port().ok_or_else(badarg)?;
    let removed = process
        .runtime
        .as_ref()
        .and_then(|runtime| runtime.ports.lock().unwrap().remove(&id))
        .ok_or_else(badarg)?;
    if removed.inet {
        crate::inet_drv::detach(id);
    }
    release_io(&removed);

    let refs = std::mem::take(&mut *removed.monitors.lock().unwrap());
    for (reference, monitor) in refs {
        if monitor.pid == ctx.pid() {
            let mut heap = arinsal_bifs::FragmentingHeap(&mut process.heap);
            let reference_term = TermBuilder::new(&mut heap)
                .local_ref([reference as u32, (reference >> 32) as u32, 0])
                .map_err(|error| {
                    VmError::Unsupported(format!("port monitor reference: {error:?}"))
                })?;
            let object = from_owned(&monitor.object, &mut heap)
                .map_err(|error| VmError::Unsupported(format!("port monitor object: {error:?}")))?;
            let down = TermBuilder::new(&mut heap)
                .tuple(&[atom("DOWN"), reference_term, atom("port"), object, reason])
                .map_err(|error| VmError::Unsupported(format!("port DOWN tuple: {error:?}")))?;
            process.inbox.push_back(down);
        } else {
            let mut heap = ProcessHeap::with_words(32);
            let reference_term = TermBuilder::new(&mut heap)
                .local_ref([reference as u32, (reference >> 32) as u32, 0])
                .map_err(|error| {
                    VmError::Unsupported(format!("port monitor reference: {error:?}"))
                })?;
            let object = from_owned(&monitor.object, &mut heap)
                .map_err(|error| VmError::Unsupported(format!("port monitor object: {error:?}")))?;
            let down = TermBuilder::new(&mut heap)
                .tuple(&[atom("DOWN"), reference_term, atom("port"), object, reason])
                .map_err(|error| VmError::Unsupported(format!("port DOWN tuple: {error:?}")))?;
            if let Ok(message) = Message::copy_from(down) {
                let _ = ctx.send(monitor.pid, message);
            }
        }
    }
    for linked in removed.links.lock().unwrap().iter().copied() {
        if linked == ctx.pid() && process.trap_exit {
            let mut heap = arinsal_bifs::FragmentingHeap(&mut process.heap);
            let exit = TermBuilder::new(&mut heap)
                .tuple(&[atom("EXIT"), port, reason])
                .map_err(|error| VmError::Unsupported(format!("port EXIT tuple: {error:?}")))?;
            process.inbox.push_back(exit);
            continue;
        }
        if let Ok(message) = Message::copy_from(reason) {
            let _ = ctx.signal(linked, arinsal_sched::Signal::Exit(message));
        }
    }
    Ok(())
}

fn connect(process: &Process, port: Term, pid: Term, notify: bool) -> Result<Term, VmError> {
    let id = port.as_port().ok_or_else(badarg)?;
    let pid = Pid::from_term(pid).ok_or_else(badarg)?;
    let runtime = process.runtime.as_ref().ok_or_else(badarg)?;
    let handle = runtime
        .ports
        .lock()
        .unwrap()
        .get(&id)
        .cloned()
        .ok_or_else(badarg)?;
    if !runtime.scheduler()?.lookup(pid) {
        return Err(badarg());
    }
    handle.links.lock().unwrap().insert(pid);
    *handle.owner.lock().unwrap() = pid;
    let scheduler = runtime.scheduler()?;
    if notify {
        event_message(
            &scheduler,
            process.self_pid.ok_or_else(badarg)?,
            id,
            atom("connected"),
        );
    }
    Ok(atom("true"))
}

/// Close ports owned by a process when its scheduler task terminates.
///
/// Port of erts/emulator/beam/erl_process.c:14084 (erts_proc_exit_handle_link), OTP-29.1.1.
pub(crate) fn owner_exit(
    runtime: &crate::process::Runtime,
    scheduler: &Scheduler<Process>,
    owner: Pid,
    reason: Term,
) {
    // g_port_fix: synchronous owner-exit hook; the caller is the termination path.
    let closed = {
        let mut ports = runtime.ports.lock().unwrap();
        for handle in ports.values() {
            handle
                .monitors
                .lock()
                .unwrap()
                .retain(|_, monitor| monitor.pid != owner);
        }
        let abnormal = reason != atom("normal");
        let ids = ports
            .iter()
            .filter_map(|(&id, handle)| {
                let is_owner = *handle.owner.lock().unwrap() == owner;
                let linked = handle.links.lock().unwrap().remove(&owner);
                (is_owner || (abnormal && linked)).then_some(id)
            })
            .collect::<Vec<_>>();
        ids.into_iter()
            .filter_map(|id| ports.remove(&id).map(|handle| (id, handle)))
            .collect::<Vec<_>>()
    };
    for (port_id, handle) in closed {
        if handle.inet {
            crate::inet_drv::detach(port_id);
            // g_inet_udp
            crate::inet_udp::detach(port_id);
        }
        release_io(&handle);
        let Some(port) = Term::port(port_id) else {
            continue;
        };
        // Linked processes observe the port, the same shape `port_close` uses.
        // A non-normal reason also becomes an exit signal so a process that does
        // not trap exits terminates; `normal` is ignored by that path in erts.
        let abnormal = reason != atom("normal");
        for linked in handle.links.lock().unwrap().iter().copied() {
            if linked == owner {
                continue;
            }
            let mut heap = ProcessHeap::with_words(32);
            let reason_term = copy_term(reason, &mut heap).unwrap_or_else(|_| atom("normal"));
            let Ok(exit) = TermBuilder::new(&mut heap).tuple(&[atom("EXIT"), port, reason_term])
            else {
                continue;
            };
            if let Ok(message) = Message::copy_from(exit) {
                let _ = scheduler.send(owner, linked, message);
            }
            if abnormal && let Some(message) = copied_reason(reason) {
                let _ = scheduler.signal(owner, linked, arinsal_sched::Signal::Exit(message));
            }
        }
        let monitors = std::mem::take(&mut *handle.monitors.lock().unwrap());
        for (reference, monitor) in &monitors {
            let mut heap = ProcessHeap::with_words(32);
            let reference_term = TermBuilder::new(&mut heap).local_ref([
                *reference as u32,
                (*reference >> 32) as u32,
                0,
            ]);
            let Ok(reference_term) = reference_term else {
                continue;
            };
            let reason_term = copy_term(reason, &mut heap).unwrap_or_else(|_| atom("normal"));
            let object = arinsal_term::from_owned(&monitor.object, &mut heap).unwrap_or(port);
            let down = TermBuilder::new(&mut heap).tuple(&[
                atom("DOWN"),
                reference_term,
                atom("port"),
                object,
                reason_term,
            ]);
            let Ok(down) = down else { continue };
            if let Ok(message) = Message::copy_from(down) {
                let _ = scheduler.send(owner, monitor.pid, message);
            }
        }
    }
}

/// Add or remove a process from a port's link set.
pub(crate) fn link(process: &Process, port: Term, pid: Pid, linked: bool) -> Result<(), VmError> {
    let id = port.as_port().ok_or_else(badarg)?;
    let handle = process
        .runtime
        .as_ref()
        .and_then(|runtime| runtime.ports.lock().unwrap().get(&id).cloned())
        .ok_or_else(badarg)?;
    let mut links = handle.links.lock().unwrap();
    if linked {
        links.insert(pid);
    } else {
        links.remove(&pid);
    }
    Ok(())
}

/// Register or remove a process monitor on a port.
pub(crate) fn monitor(
    process: &Process,
    port: Term,
    reference: u64,
    pid: Pid,
    object: OwnedTerm,
    monitored: bool,
) -> Result<bool, VmError> {
    let id = port.as_port().ok_or_else(badarg)?;
    let handle = process
        .runtime
        .as_ref()
        .and_then(|runtime| runtime.ports.lock().unwrap().get(&id).cloned())
        .ok_or_else(badarg)?;
    let state = handle.state.lock().unwrap();
    if monitored && state.exit_complete {
        return Ok(false);
    }
    let mut monitors = handle.monitors.lock().unwrap();
    if monitored {
        monitors.insert(reference, PortMonitor { pid, object });
    } else {
        monitors.remove(&reference);
    }
    Ok(true)
}

/// Monitor targets reported by `process_info/2` for one process.
pub(crate) fn monitors_by(process: &Process, pid: Pid) -> Vec<OwnedTerm> {
    let Some(runtime) = process.runtime.as_ref() else {
        return Vec::new();
    };
    runtime
        .ports
        .lock()
        .unwrap()
        .values()
        .flat_map(|handle| {
            handle
                .monitors
                .lock()
                .unwrap()
                .values()
                .filter(|monitor| monitor.pid == pid)
                .map(|monitor| monitor.object.clone())
                .collect::<Vec<_>>()
        })
        .collect()
}

/// Remove a reference from any live port's monitor set.
pub(crate) fn demonitor(process: &Process, reference: u64) -> bool {
    let Some(runtime) = &process.runtime else {
        return false;
    };
    let ports = runtime.ports.lock().unwrap();
    ports
        .values()
        .any(|handle| handle.monitors.lock().unwrap().remove(&reference).is_some())
}

pub(crate) fn send_message(process: &Process, port: Term, message: Term) -> Result<(), VmError> {
    let id = port.as_port().ok_or_else(badarg)?;
    let runtime = process.runtime.as_ref().ok_or_else(badarg)?;
    let handle = runtime
        .ports
        .lock()
        .unwrap()
        .get(&id)
        .cloned()
        .ok_or_else(badarg)?;
    let owner_pid = process.self_pid.ok_or_else(badarg)?;
    let Some(parts) = tuple(message) else {
        signal_badsig(&handle, id);
        return Ok(());
    };
    if parts.len() != 2 || parts[0] != process.self_pid.and_then(Pid::to_term).ok_or_else(badarg)? {
        signal_badsig(&handle, id);
        return Ok(());
    }
    if parts[1] == atom("close") {
        if Some(*handle.owner.lock().unwrap()) != process.self_pid {
            signal_badsig(&handle, id);
            return Ok(());
        }
        if handle.os_pid == 0 {
            close(process, port)?;
            event_message(&handle.scheduler, owner_pid, id, atom("closed"));
            return Ok(());
        }
        let notify_now = {
            let mut state = handle.state.lock().unwrap();
            if state.closed || state.graceful_close {
                return Err(badarg());
            }
            state.graceful_close = true;
            state.send_closed = true;
            state.exit_complete
        };
        runtime.ports.lock().unwrap().remove(&id);
        if notify_now {
            event_message(&handle.scheduler, owner_pid, id, atom("closed"));
        } else {
            poke(&handle);
        }
        return Ok(());
    }
    let Some(command) = tuple(parts[1]) else {
        signal_badsig(&handle, id);
        return Ok(());
    };
    if command.len() == 2 && command[0] == atom("command") {
        let Some(mut data) = iodata(command[1]) else {
            signal_badsig(&handle, id);
            return Ok(());
        };
        if let Some((2, hdr)) = handle.framing {
            match hdr {
                1 => {
                    if data.len() > u8::MAX as usize {
                        signal_port_exit(&handle, id, atom("einval"));
                        return Ok(());
                    }
                    data.insert(0, data.len() as u8);
                }
                2 => {
                    if data.len() > u16::MAX as usize {
                        signal_port_exit(&handle, id, atom("einval"));
                        return Ok(());
                    }
                    data.splice(0..0, (data.len() as u16).to_be_bytes());
                }
                4 => {
                    if data.len() > u32::MAX as usize {
                        signal_port_exit(&handle, id, atom("einval"));
                        return Ok(());
                    }
                    data.splice(0..0, (data.len() as u32).to_be_bytes());
                }
                _ => {
                    signal_badsig(&handle, id);
                    return Ok(());
                }
            }
        }
        if command_bytes(&handle, &data).is_err() {
            signal_badsig(&handle, id);
        }
        return Ok(());
    }
    if command.len() == 2 && command[0] == atom("connect") {
        if Some(*handle.owner.lock().unwrap()) != process.self_pid || command[1].as_pid().is_none()
        {
            signal_badsig(&handle, id);
            return Ok(());
        }
        if connect(process, port, command[1], true).is_err() {
            signal_badsig(&handle, id);
        }
        return Ok(());
    }
    signal_badsig(&handle, id);
    Ok(())
}

fn ports(_vm: &mut Vm, process: &mut Process) -> Result<Term, VmError> {
    // Port of erts/emulator/beam/bif.c:4125 (ports/0), OTP-29.1.1.
    // Standard I/O is a registered port even when no user port is open.
    let mut values = vec![Term::port(0).expect("standard I/O port tag")];
    if let Some(runtime) = &process.runtime {
        values.extend(
            runtime
                .ports
                .lock()
                .unwrap()
                .keys()
                .filter(|id| **id != 0)
                .filter_map(|id| Term::port(*id)),
        );
    }
    let mut heap = arinsal_bifs::FragmentingHeap(&mut process.heap);
    TermBuilder::new(&mut heap)
        .list_from_iter(values)
        .map_err(|e| VmError::Unsupported(format!("ports list: {e:?}")))
}
fn port_info(process: &mut Process, port: Term, item: Option<Term>) -> Result<Term, VmError> {
    let id = port.as_port().ok_or_else(badarg)?;
    let Some(handle) = process
        .runtime
        .as_ref()
        .and_then(|r| r.ports.lock().unwrap().get(&id).cloned())
    else {
        return Ok(atom("undefined"));
    };
    let mut heap = arinsal_bifs::FragmentingHeap(&mut process.heap);
    let name = TermBuilder::new(&mut heap)
        .string_to_list(&handle.name)
        .map_err(|e| VmError::Unsupported(format!("port info name: {e:?}")))?;
    let connected = handle.owner.lock().unwrap().to_term().ok_or_else(badarg)?;
    let links = TermBuilder::new(&mut heap)
        .list_from_iter(
            handle
                .links
                .lock()
                .unwrap()
                .iter()
                .filter_map(|pid| pid.to_term()),
        )
        .map_err(|e| VmError::Unsupported(format!("port info links: {e:?}")))?;
    let monitored_pids = handle
        .monitors
        .lock()
        .unwrap()
        .values()
        .filter_map(|monitor| monitor.pid.to_term())
        .collect::<Vec<_>>();
    let memory = 48 + monitored_pids.len() * 24;
    let monitored_by = TermBuilder::new(&mut heap)
        .list_from_iter(monitored_pids)
        .map_err(|error| VmError::Unsupported(format!("port monitored_by: {error:?}")))?;
    let fields = [
        ("name", name),
        ("links", links),
        ("id", Term::small(id as i64).unwrap()),
        ("connected", connected),
        ("input", Term::small(0).unwrap()),
        ("output", Term::small(0).unwrap()),
        ("os_pid", Term::small(handle.os_pid as i64).unwrap()),
        ("monitors", Term::NIL),
        ("monitored_by", monitored_by),
        ("memory", Term::small(memory as i64).unwrap()),
        (
            "queue_size",
            Term::small(handle.state.lock().unwrap().outq.len() as i64).unwrap(),
        ),
        ("locking", atom("port_level")),
        (
            "parallelism",
            atom(if handle.parallelism { "true" } else { "false" }),
        ),
    ];
    if let Some(item) = item {
        let key = global_atoms()
            .text(item.as_atom().ok_or_else(badarg)?)
            .ok_or_else(badarg)?;
        let value = fields
            .iter()
            .find_map(|(name, value)| (*name == key).then_some(*value))
            .ok_or_else(badarg)?;
        return TermBuilder::new(&mut heap)
            .tuple(&[item, value])
            .map_err(|e| VmError::Unsupported(format!("port info: {e:?}")));
    }
    let tuples: Vec<Term> = fields
        .into_iter()
        .take(7)
        .map(|(key, value)| {
            let key = atom(key);
            TermBuilder::new(&mut heap)
                .tuple(&[key, value])
                .map_err(|e| VmError::Unsupported(format!("port info: {e:?}")))
        })
        .collect::<Result<_, _>>()?;
    TermBuilder::new(&mut heap)
        .list_from_iter(tuples)
        .map_err(|e| VmError::Unsupported(format!("port info: {e:?}")))
}
