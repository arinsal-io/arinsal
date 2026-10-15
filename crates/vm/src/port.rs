//! Local OS ports backed by child processes.
use crate::process::Message;
use crate::{Process, Vm, VmError};
use arinsal_etf::OwnedTerm;
use arinsal_sched::{HaltProgress, Pid, RunCtx, Scheduler};
use arinsal_term::{
    ProcessHeap, Term, TermBuilder, TermKind, VecHeap, copy_term, from_owned, global_atoms,
    to_owned,
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
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};

mod drv_sig;

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

thread_local! {
    /// `erlang:send/3` with `[nosuspend]` is sending (`ERTS_PORT_SIG_FLG_NOSUSPEND`).
    static SEND_NOSUSPEND: Cell<bool> = const { Cell::new(false) };
    /// A nosuspend send found the port busy: `send/3` returns `nosuspend`.
    static SEND_BUSY_NOSUSPEND: Cell<bool> = const { Cell::new(false) };
}

/// Run a send of `erlang:send/3` with `[nosuspend]`; `true` when a port was busy and the
/// message was not sent.
pub(crate) fn send_nosuspend<R>(send: impl FnOnce() -> R) -> (R, bool) {
    SEND_NOSUSPEND.with(|flag| flag.set(true));
    SEND_BUSY_NOSUSPEND.with(|flag| flag.set(false));
    let result = send();
    SEND_NOSUSPEND.with(|flag| flag.set(false));
    (result, SEND_BUSY_NOSUSPEND.with(|flag| flag.replace(false)))
}

/// `Port ! Message` from a running process: port of erts/emulator/beam/bif.c:2560
/// (erts_send to an internal port). A busy port suspends the sender: either the send is
/// redone after the suspension (nothing sent) or the process yields after it.
pub(crate) fn process_send(
    process: &mut Process,
    port: Term,
    message: Term,
) -> Result<(), VmError> {
    process_send_inner(process, None, port, message)
}

/// `Port ! Message` with its running process scheduler context.
// Port of erts/emulator/beam/io.c:923-1055 (try_imm_drv_call), OTP-29.1.1.
pub(crate) fn process_send_in(
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    port: Term,
    message: Term,
) -> Result<(), VmError> {
    process_send_inner(process, Some(ctx), port, message)
}

fn process_send_inner(
    process: &mut Process,
    ctx: Option<&mut RunCtx<'_, Message>>,
    port: Term,
    message: Term,
) -> Result<(), VmError> {
    // arl: a send to a port of another namespace is dropped, like one to a dead port.
    if let Some(id) = port.as_port()
        && !arl_port_ns_ok(process, id)
    {
        return Ok(());
    }
    let nosuspend = SEND_NOSUSPEND.with(Cell::get);
    match send_from_process(process, port, message, nosuspend, ctx)? {
        PortSend::Sent => Ok(()),
        PortSend::SentSuspended => {
            // SEND_YIELD_RETURN: the send is done; the process leaves the scheduler.
            process.force_yield = true;
            Ok(())
        }
        PortSend::Busy if nosuspend => {
            SEND_BUSY_NOSUSPEND.with(|flag| flag.set(true));
            Ok(())
        }
        PortSend::Busy => {
            // SEND_YIELD: the suspended send is redone when the port is no longer busy.
            BUSY_SUSPEND.with(|flag| flag.set(true));
            Err(badarg())
        }
    }
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
    /// `None` for loaded-driver ports: they have no worker thread to wake.
    wake_w: Option<OwnedFd>,
    wake_needed: AtomicBool,
    framing: Option<(u8, usize)>,
    /// arl: namespace of the process that opened the port (0 is root).
    arl_ns: u32,
    owner: Mutex<Pid>,
    links: Mutex<HashSet<Pid>>,
    monitors: Mutex<HashMap<u64, PortMonitor>>,
    os_pid: u32,
    name: String,
    parallelism: bool,
    limits: BusyLimits,
    state: Mutex<PortState>,
    scheduler: Arc<Scheduler<Process>>,
    trace_scope: usize,
    /// `port_set_data/2` term. `undefined` until the first store.
    data: Mutex<OwnedTerm>,
    /// `tcp_inet` / `tcp_inet6` port. I/O is owned by `inet_drv`, not a stdio worker.
    inet: bool,
    /// Dynamically loaded (`erl_ddll`) driver port.
    driver: OnceLock<Arc<arinsal_drv::DriverPort>>,
    /// Processes this driver port monitors (`driver_monitor_process`): monitor id to pid.
    drv_monitors: Mutex<HashMap<u64, Pid>>,
    /// The `open_port` waiting for `erl_drv_init_ack`: reference id and opener.
    async_open: Mutex<Option<(u64, Pid)>>,
    /// `port->common.u.alive.reg->name`, shared with the register table entry.
    reg_word: Arc<AtomicU32>,
    /// Set when the port is removed, before its name is erased.
    reg_closing: AtomicBool,
    halt_progress: Mutex<Option<HaltProgress>>,
    /// `ram_file_drv` port data (`drv_data`), present from `rfile_start` until `rfile_stop`.
    ram_file: Mutex<Option<Arc<crate::ram_file_drv::RamPort>>>,
    /// Driver-owned state returned by the inet driver's start callback.
    inet_tcp: Mutex<Option<Arc<crate::inet_drv::Sock>>>,
    inet_udp: Mutex<Option<Arc<crate::inet_udp::Sock>>>,
}

/// Inspect or move the next local port id for `erts_debug` table tests.
/// Port of erts/emulator/beam/erl_ptab.c:1356-1460 (`erts_ptab_test_next_id`), OTP-29.1.1.
pub(crate) fn test_next_port_id(
    runtime: &crate::process::Runtime,
    set: bool,
    next_id: u64,
) -> Option<u64> {
    let ports = runtime.ports.lock().unwrap();
    Some(runtime.port_ids.test_next_id(set, next_id, |pix| {
        ports
            .keys()
            .any(|id| arinsal_term::ptab::port_table_layout().data2pix(*id) == pix)
    }))
}

/// Port of erts/emulator/beam/erl_ptab.c:500, 675 (new/delete element), OTP-29.1.1.
/// A reserved local port id is returned to the ptab ring if construction fails.
struct PortIdReservation<'a> {
    runtime: &'a crate::process::Runtime,
    id: u64,
    committed: bool,
}

impl PortIdReservation<'_> {
    fn id(&self) -> u64 {
        self.id
    }

    fn commit(mut self) -> u64 {
        self.committed = true;
        self.id
    }
}

impl Drop for PortIdReservation<'_> {
    fn drop(&mut self) {
        if !self.committed {
            let _ports = self.runtime.ports.lock().unwrap();
            self.runtime.port_ids.release(self.id);
        }
    }
}

fn reserve_port_id(runtime: &crate::process::Runtime) -> Result<PortIdReservation<'_>, VmError> {
    let _ports = runtime.ports.lock().unwrap();
    // Port exhaustion is the `driver_create_port` failure mapped to `system_limit` in
    // erts/emulator/drivers/common/inet_drv.c:11834-11837, OTP-29.1.1.
    let id = runtime
        .port_ids
        .reserve()
        .ok_or_else(|| VmError::Trap(crate::exceptions::Trap::error(atom("system_limit"))))?;
    Ok(PortIdReservation {
        runtime,
        id,
        committed: false,
    })
}

fn remove_port(runtime: &crate::process::Runtime, id: u64) -> Option<Arc<PortHandle>> {
    let mut ports = runtime.ports.lock().unwrap();
    let handle = ports.remove(&id)?;
    runtime.port_ids.release(id);
    drop(ports);
    release_port_name(runtime, &handle);
    crate::trace::port_closed(runtime, id);
    Some(handle)
}

fn release_port_name(runtime: &crate::process::Runtime, handle: &PortHandle) {
    // Closing is published before the register lock so a concurrent register/2,
    // which checks it under that lock, cannot insert a name for a dead port.
    handle.mark_reg_closing();
    let mut table = runtime.reg.write();
    let Some(name) = handle.take_registered_atom() else {
        return;
    };
    if matches!(table.fetch(name), Some(crate::register::RegId::Port(id)) if id == handle.id()) {
        table.erase(name);
        drop(table);
        crate::trace::emit_port_event(
            runtime,
            handle.id(),
            crate::trace::PORTS,
            "unregister",
            &[Term::atom(name)],
        );
    }
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

    pub(crate) fn tcp_driver_data(&self) -> Option<Arc<crate::inet_drv::Sock>> {
        self.inet_tcp.lock().unwrap().clone()
    }

    pub(crate) fn set_tcp_driver_data(&self, data: Arc<crate::inet_drv::Sock>) {
        *self.inet_tcp.lock().unwrap() = Some(data);
    }

    pub(crate) fn take_tcp_driver_data(&self) -> Option<Arc<crate::inet_drv::Sock>> {
        self.inet_tcp.lock().unwrap().take()
    }

    pub(crate) fn udp_driver_data(&self) -> Option<Arc<crate::inet_udp::Sock>> {
        self.inet_udp.lock().unwrap().clone()
    }

    pub(crate) fn set_udp_driver_data(&self, data: Arc<crate::inet_udp::Sock>) {
        *self.inet_udp.lock().unwrap() = Some(data);
    }

    pub(crate) fn take_udp_driver_data(&self) -> Option<Arc<crate::inet_udp::Sock>> {
        self.inet_udp.lock().unwrap().take()
    }

    pub(crate) fn id(&self) -> u64 {
        self.id
    }

    pub(crate) fn reg_word(&self) -> Arc<AtomicU32> {
        Arc::clone(&self.reg_word)
    }

    pub(crate) fn reg_closing(&self) -> bool {
        self.reg_closing.load(Ordering::Acquire)
    }

    /// Port is gone: later `register/2` must fail even if it already cloned this handle.
    pub(crate) fn mark_reg_closing(&self) {
        self.reg_closing.store(true, Ordering::Release);
    }

    pub(crate) fn registered_atom(&self) -> Option<arinsal_term::Atom> {
        let index = self.reg_word.load(Ordering::Acquire);
        (index != crate::register::NO_REG_ATOM).then_some(arinsal_term::Atom(index))
    }

    pub(crate) fn set_registered_atom(&self, atom: arinsal_term::Atom) {
        self.reg_word.store(atom.0, Ordering::Release);
    }

    pub(crate) fn take_registered_atom(&self) -> Option<arinsal_term::Atom> {
        let index = self
            .reg_word
            .swap(crate::register::NO_REG_ATOM, Ordering::AcqRel);
        (index != crate::register::NO_REG_ATOM).then_some(arinsal_term::Atom(index))
    }

    pub(crate) fn exit_complete(&self) -> bool {
        self.state.lock().unwrap().exit_complete
    }

    fn track_halt(&self, progress: HaltProgress) {
        progress.port_started();
        let mut tracked = self.halt_progress.lock().unwrap();
        if self.state.lock().unwrap().exit_complete {
            progress.port_finished();
        } else {
            *tracked = Some(progress);
        }
    }

    fn finish_halt(&self) {
        if let Some(progress) = self.halt_progress.lock().unwrap().take() {
            progress.port_finished();
        }
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
            append_binary(term, &mut out)?;
        }
    }
    Some(out)
}
/// Append a binary's significant bytes: the window `[start_bit, start_bit + bit_len)`
/// of its owner, which is not the owner's whole backing data for a sub-binary.
/// A bitstring whose size is not a multiple of 8 is not iodata.
fn append_binary(term: Term, out: &mut Vec<u8>) -> Option<()> {
    let bits = arinsal_bifs::bitstring_bit_len(term).ok()?;
    if !bits.is_multiple_of(8) {
        return None;
    }
    let start = out.len();
    out.resize(start + bits / 8, 0);
    arinsal_bifs::copy_binary_range(term, 0, &mut out[start..]).ok()
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
    fn append(mut term: Term, mut tail: bool, out: &mut Vec<u8>) -> Option<()> {
        // The spine is walked in a loop: long lists must not recurse per cell.
        while term.classify() == TermKind::List {
            // SAFETY: The list is traversed before the caller's process heap can move.
            let (head, rest) = unsafe { term.cons_ref()? };
            append(head, false, out)?;
            term = rest;
            tail = true;
        }
        if term == Term::NIL {
            Some(())
        } else if term.classify() == TermKind::Bitstring {
            append_binary(term, out)
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
    trace_scope: usize,
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
    trace_port_send(scheduler, trace_scope, port_id, owner, msg);
    publish(scheduler, owner, port, msg);
}

// Port of erts/emulator/drivers/common/ram_file_drv.c:217-229 (driver_output2 replies).
pub(crate) fn static_driver_output(handle: &PortHandle, bytes: &[u8]) {
    output_message(
        &handle.scheduler,
        handle.owner_pid(),
        handle.id,
        bytes,
        false,
        handle.trace_scope,
    );
}

// Port of erts/emulator/drivers/common/ram_file_drv.c:465-470, :479-484 and :506-510.
pub(crate) fn static_driver_output_binary(
    handle: &PortHandle,
    header: &[u8],
    bytes: &[u8],
    binary: bool,
) {
    if !binary {
        let mut reply = Vec::with_capacity(header.len() + bytes.len());
        reply.extend_from_slice(header);
        reply.extend_from_slice(bytes);
        static_driver_output(handle, &reply);
        return;
    }
    let Some(port) = Term::port(handle.id) else {
        return;
    };
    let mut heap =
        ProcessHeap::with_words(output_heap_words(header.len() + bytes.len(), false, 32));
    let build = |heap: &mut ProcessHeap| -> Result<Term, arinsal_term::TermError> {
        let mut data = TermBuilder::new(heap).binary(bytes)?;
        for byte in header.iter().rev() {
            data = TermBuilder::new(heap).cons(Term::small(i64::from(*byte)).unwrap(), data)?;
        }
        let message = TermBuilder::new(heap).tuple(&[atom("data"), data])?;
        TermBuilder::new(heap).tuple(&[port, message])
    };
    if let Ok(message) = build(&mut heap) {
        trace_port_send(
            &handle.scheduler,
            handle.trace_scope,
            handle.id,
            handle.owner_pid(),
            message,
        );
        publish(&handle.scheduler, handle.owner_pid(), port, message);
    }
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
fn event_message(
    scheduler: &Scheduler<Process>,
    owner: Pid,
    port_id: u64,
    trace_scope: usize,
    event: Term,
) {
    let Some(port) = Term::port(port_id) else {
        return;
    };
    let mut heap = ProcessHeap::with_words(24);
    if let Ok(msg) = TermBuilder::new(&mut heap).tuple(&[port, event]) {
        // terminate_port traces the `closed` atom even though the delivered message is
        // `{Port, closed}` (io.c:3755, OTP-29.1.1).
        trace_port_send(
            scheduler,
            trace_scope,
            port_id,
            owner,
            if event == atom("closed") { event } else { msg },
        );
        publish(scheduler, owner, port, msg);
    }
}

fn connected_message(
    runtime: &crate::process::Runtime,
    scheduler: &Scheduler<Process>,
    owner: Pid,
    port_id: u64,
    trace_scope: usize,
    deliver: bool,
) {
    // Port of erts/emulator/beam/io.c:2324-2410 (set_port_connected), OTP-29.1.1.
    let Some(port) = Term::port(port_id) else {
        return;
    };
    let mut heap = ProcessHeap::with_words(24);
    let Ok(message) = TermBuilder::new(&mut heap).tuple(&[port, atom("connected")]) else {
        return;
    };
    trace_port_send(scheduler, trace_scope, port_id, owner, message);
    if !deliver {
        return;
    }
    let traced = crate::trace::emit_external_process_event(
        runtime,
        owner,
        crate::trace::RECEIVE,
        "receive",
        &[message],
    );
    let Ok(mut envelope) = Message::copy_from(message) else {
        return;
    };
    if traced {
        envelope = envelope.with_receive_traced();
    }
    let _ = scheduler.send(owner, owner, envelope);
}

fn trace_port_send(
    scheduler: &Scheduler<Process>,
    trace_scope: usize,
    port_id: u64,
    receiver: Pid,
    message: Term,
) {
    // Port of erts/emulator/beam/erl_trace.c:2221 (trace_port_send), OTP-29.1.1.
    if let Some(receiver) = receiver.to_term() {
        crate::trace::emit_port_event_scoped(
            trace_scope,
            scheduler,
            port_id,
            crate::trace::SEND,
            "send",
            &[message, receiver],
        );
    }
}

fn start(
    vm: &mut Vm,
    process: &mut Process,
    ctx: &RunCtx<'_, Message>,
    spec: Term,
    opts: Term,
) -> Result<Term, VmError> {
    let parsed_opts = options(opts).ok_or_else(badarg)?;
    let spec = tuple(spec).ok_or_else(badarg)?;
    // arl: a namespace may open only the inet socket drivers.
    if process.ns != 0 && !arl_ns_may_open(&spec) {
        return Err(VmError::Trap(crate::exceptions::Trap::error(atom(
            "notsup",
        ))));
    }
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
            Some(crate::ddll::Found::Static) => {
                return start_driver(process, ctx, name, binary);
            }
            None if *kind == atom("spawn_driver") => return Err(badarg()),
            Some(found) => {
                if let Some((handle_id, driver)) = found.into_loaded() {
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
                            msgq: limits
                                .msgq_enabled
                                .then_some((limits.msgq_low, limits.msgq_high)),
                            binary,
                            eof: want_eof,
                            line,
                            parallelism,
                        },
                    );
                }
            }
            None => {}
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
    // Hold the publish lock across the fd scan and spawn so a descriptor created on
    // another thread cannot appear after the list is taken (erl_child_setup.c:313-318
    // and closefrom at :466-470: only 0, 1, 2 and maybe 3, 4 survive exec).
    let mut child = match cloexec_publish(|| {
        let stray: Vec<i32> = std::fs::read_dir("/dev/fd")
            .map(|entries| {
                entries
                    .filter_map(|entry| entry.ok()?.file_name().into_string().ok()?.parse().ok())
                    .filter(|fd: &i32| *fd >= 3)
                    .collect()
            })
            .unwrap_or_default();
        let keep_below = if use_stdio { 3 } else { 5 };
        // SAFETY: pre_exec runs in the forked child after Command has dup2'd stdio.
        // dup2 and close are async-signal-safe. Descriptors at or above `keep_below`
        // are the ones erl_child_setup closes before exec.
        unsafe {
            command.pre_exec(move || {
                unsafe extern "C" {
                    fn dup2(oldfd: i32, newfd: i32) -> i32;
                    fn close(fd: i32) -> i32;
                }
                // dup2/close are async-signal-safe and run in the forked child.
                if stderr_to_stdout && dup2(1, 2) < 0 {
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
                for fd in &stray {
                    if *fd >= keep_below {
                        close(*fd);
                    }
                }
                Ok(())
            });
        }
        command.spawn()
    }) {
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
    let reservation = reserve_port_id(runtime)?;
    let port_id = reservation.id();
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
        Arc::as_ptr(runtime) as usize,
        false,
    )?;
    runtime
        .ports
        .lock()
        .unwrap()
        .insert(port_id, Arc::clone(&handle));
    let _ = runtime.publish_proc_flag(ctx.pid(), arinsal_sched::proc_flags::PORTS);
    crate::trace::port_opened(runtime, port_id);
    reservation.commit();
    let owner = ctx.pid();
    let runtime_weak = Arc::downgrade(runtime);
    std::thread::Builder::new()
        .name(format!("arinsal-port-{port_id}"))
        .spawn(move || {
            worker(
                handle,
                Some(child),
                read_fd,
                scheduler,
                runtime_weak,
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
    _binary: bool,
) -> Result<Term, VmError> {
    let udp = name == "udp_inet";
    let ram_file = name == "ram_file_drv";
    if name != "tcp_inet" && name != "tcp_inet6" && !udp && !ram_file {
        return Err(badarg());
    }
    let runtime = process.runtime.as_ref().ok_or_else(badarg)?;
    let scheduler = runtime.scheduler()?;
    let reservation = reserve_port_id(runtime)?;
    let port_id = reservation.id();
    let port = Term::port(port_id).ok_or_else(badarg)?;
    let handle = if ram_file {
        make_driver_handle(
            port_id,
            ctx.pid(),
            name,
            false,
            scheduler,
            Arc::as_ptr(runtime) as usize,
        )?
    } else {
        make_handle(
            port_id,
            None,
            None,
            ctx.pid(),
            0,
            name,
            false,
            default_limits(),
            scheduler,
            Arc::as_ptr(runtime) as usize,
            true,
        )?
    };
    runtime
        .ports
        .lock()
        .unwrap()
        .insert(port_id, Arc::clone(&handle));
    let _ = runtime.publish_proc_flag(ctx.pid(), arinsal_sched::proc_flags::PORTS);
    crate::trace::port_opened(runtime, port_id);
    reservation.commit();
    // g_inet_udp
    if ram_file {
        *handle.ram_file.lock().unwrap() = Some(crate::ram_file_drv::start(_binary));
    } else if udp {
        crate::inet_udp::attach(port_id, Arc::clone(&handle));
    } else {
        crate::inet_drv::attach(Arc::clone(runtime), port_id, Arc::clone(&handle));
    }
    Ok(port)
}

/// `open_port` options that become driver port state flags.
struct DriverIoFlags {
    /// `{busy_limits_msgq, {Low, High}}`, `None` when disabled.
    msgq: Option<(usize, usize)>,
    binary: bool,
    eof: bool,
    line: Option<usize>,
    parallelism: bool,
}

/// `ERL_DRV_FLAG_USE_INIT_ACK`.
const ERL_DRV_FLAG_USE_INIT_ACK: i32 = 1 << 3;
const ERL_DRV_FLAG_NO_BUSY_MSGQ: i32 = 1 << 2;

/// Port of erts/emulator/beam/io.c:542 (erts_open_driver) for a dynamically loaded
/// driver, with the state flags erl_bif_port.c:1140 sets after `start`.
fn start_dyn_driver(
    process: &mut Process,
    ctx: &RunCtx<'_, Message>,
    handle_id: Option<u64>,
    driver: Arc<arinsal_drv::Driver>,
    name: String,
    io: DriverIoFlags,
) -> Result<Term, VmError> {
    let runtime = process.runtime.clone().ok_or_else(badarg)?;
    let scheduler = runtime.scheduler()?;
    install_hooks();
    let reservation = reserve_port_id(&runtime)?;
    let port_id = reservation.id();
    let port = Term::port(port_id).ok_or_else(badarg)?;
    let handle = make_driver_handle(
        port_id,
        ctx.pid(),
        name.clone(),
        io.parallelism,
        Arc::clone(&scheduler),
        Arc::as_ptr(&runtime) as usize,
    )?;
    install_poll_backend();
    let host = DrvHost {
        runtime: Arc::downgrade(&runtime),
        own: Arc::downgrade(&handle),
    };
    let drv_port = arinsal_drv::DriverPort::new(Arc::clone(&driver), port_id, Box::new(host));
    drv_port.init_run_queue(scheduler.current_run_queue());
    let _ = handle.driver.set(Arc::clone(&drv_port));
    if let Some(handle_id) = handle_id {
        crate::ddll::port_opened(handle_id, &drv_port);
    }
    // Port of io.c:318 and io.c:683: drivers without ERL_DRV_FLAG_NO_BUSY_MSGQ have a busy
    // port message queue; open_port limits are set before `start`.
    if let Some((low, high)) = io.msgq {
        drv_port.set_msgq_limits(low, high);
    } else if driver.flags() & ERL_DRV_FLAG_NO_BUSY_MSGQ != 0 {
        drv_port.set_msgq_limits(
            arinsal_drv::BUSY_MSGQ_DISABLED,
            arinsal_drv::BUSY_MSGQ_DISABLED,
        );
    }
    drv_port.set_parallelism(io.parallelism);
    runtime
        .ports
        .lock()
        .unwrap()
        .insert(port_id, Arc::clone(&handle));
    let _ = runtime.publish_proc_flag(ctx.pid(), arinsal_sched::proc_flags::PORTS);
    crate::trace::port_opened(&runtime, port_id);
    reservation.commit();
    let caller = packed_pid(ctx.pid());
    if let Err(error) = drv_port.start(&name, caller) {
        remove_port(&runtime, port_id);
        drv_port.abandon();
        release_io(&handle);
        if handle_id.is_some() {
            crate::ddll::port_closed(&scheduler, &driver);
        }
        // Port of erts/emulator/beam/erl_bif_port.c:69-89 (open_port error atoms).
        return Ok(match error {
            arinsal_drv::StartError::General => atom("einval"),
            arinsal_drv::StartError::Errno(errno) => atom(&arinsal_drv::errno_id(errno)),
            arinsal_drv::StartError::Badarg => atom("badarg"),
        });
    }
    drv_port.set_io_flags(io.binary, io.eof, io.line);
    if let Some(caller) = ctx.pid().to_term() {
        crate::trace::emit_port_event(
            &runtime,
            port_id,
            crate::trace::PORTS,
            "open",
            &[caller, atom(&name)],
        );
        crate::trace::emit_port_event(
            &runtime,
            port_id,
            crate::trace::PORTS,
            "getting_linked",
            &[caller],
        );
    }
    if driver.flags() & ERL_DRV_FLAG_USE_INIT_ACK != 0 {
        // Port of erts/emulator/beam/erl_bif_port.c:102: the opener gets a
        // reference and the port, or the error, in `{Ref, Result}` from `erl_drv_init_ack`.
        let reference = runtime.next_ref();
        *handle.async_open.lock().unwrap() = Some((reference, ctx.pid()));
        drv_port.expect_init_ack();
        let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
        return TermBuilder::new(&mut heap)
            .local_ref(arinsal_bifs::ordinary_ref_words(reference))
            .map_err(|_| badarg());
    }
    Ok(port)
}

/// Caller identity for drivers (`prt->caller`): the erts pid data word.
fn packed_pid(pid: Pid) -> u64 {
    pid.data()
}

/// `PortHost` for a dynamically loaded driver port.
struct DrvHost {
    runtime: Weak<crate::process::Runtime>,
    /// The port itself: `stop` still delivers output after the port left the table
    /// (io.c:3698 terminate_port runs after erts_deliver_port_exit unlinked it).
    own: Weak<PortHandle>,
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
            .or_else(|| self.own.upgrade())
    }
}

impl arinsal_drv::PortHost for DrvHost {
    // Port of erts/emulator/beam/erl_trace.c:2299-2324 (trace_sched_ports_where), OTP-29.1.1.
    fn trace_sched_port(
        &self,
        port: &arinsal_drv::DriverPort,
        scheduled_in: bool,
        where_: Option<&str>,
    ) {
        let Some(runtime) = self.runtime.upgrade() else {
            return;
        };
        let where_term = where_.map_or_else(|| Term::small(0).unwrap(), crate::signals::atom);
        crate::trace::emit_port_event(
            &runtime,
            port.id(),
            crate::trace::RUNNING_PORTS,
            if scheduled_in { "in" } else { "out" },
            &[where_term],
        );
    }

    fn task_done(&self, port: &arinsal_drv::DriverPort, op: &str, elapsed_ns: u64) {
        let Some(runtime) = self.runtime.upgrade() else {
            return;
        };
        let Some(handle) = runtime.ports.lock().unwrap().get(&port.id()).cloned() else {
            return;
        };
        if let Some(term) = Term::port(port.id()) {
            crate::natives::erts_debug::after_port_task(
                &runtime,
                term,
                handle.owner_pid(),
                op,
                elapsed_ns,
            );
        }
    }

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
            trace_port_send(
                &handle.scheduler,
                handle.trace_scope,
                port.id(),
                owner,
                message,
            );
            publish(&handle.scheduler, owner, port_term, message);
        }
    }

    fn deliver_eof(&self, port: &arinsal_drv::DriverPort) {
        if let Some(handle) = self.handle(port.id()) {
            event_message(
                &handle.scheduler,
                handle.owner_pid(),
                port.id(),
                handle.trace_scope,
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

    // Port of erts/emulator/beam/utils.c:802 (do_send_logger_message) for
    // erts_send_error_to_logger_nogl: an `error_msg` event to the logger process.
    fn log_error(&self, text: &str) {
        let Some(runtime) = self.runtime.upgrade() else {
            eprint!("{text}");
            return;
        };
        let logger = runtime
            .reg
            .whereis_proc_str("logger")
            .or_else(|| runtime.reg.whereis_proc_str("error_logger"));
        let Some(logger) = logger else {
            eprint!("{text}");
            return;
        };
        let Ok(scheduler) = runtime.scheduler() else {
            return;
        };
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_micros())
            .try_into()
            .unwrap_or(i64::MAX);
        let mut heap = ProcessHeap::with_words(output_heap_words(text.len() * 2 + 64, false, 96));
        let event = (|| -> Result<Term, arinsal_term::TermError> {
            let mut builder = TermBuilder::new(&mut heap);
            let format = builder.string_to_list("~s")?;
            let message = builder.string_to_list(text)?;
            let args = builder.list_from_iter([message])?;
            let error_logger = builder.flatmap_from_pairs(&[
                (atom("emulator"), atom("true")),
                (atom("tag"), atom("error")),
            ])?;
            let metadata = builder.flatmap_from_pairs(&[
                (atom("error_logger"), error_logger),
                (atom("time"), Term::small(timestamp).unwrap_or(Term::NIL)),
            ])?;
            builder.tuple(&[atom("log"), atom("error"), format, args, metadata])
        })();
        if let Ok(event) = event
            && let Ok(message) = Message::copy_from(event)
        {
            let _ = scheduler.send(logger, logger, message);
        }
    }

    fn ddll_reference(&self, port: &arinsal_drv::DriverPort) {
        crate::ddll::reference_referenced(port.driver());
    }

    fn ddll_dereference(&self, port: &arinsal_drv::DriverPort) {
        if let Some(runtime) = self.runtime.upgrade()
            && let Ok(scheduler) = runtime.scheduler()
        {
            crate::ddll::dereference_referenced(&scheduler, port.driver());
        }
    }

    // Port of erts/emulator/beam/io.c:3496 (deliver_vec_message), OTP-29.1.1.
    fn deliver_vec(
        &self,
        port: &arinsal_drv::DriverPort,
        header: &[u8],
        segments: &[Vec<u8>],
        binary: bool,
    ) {
        let Some(handle) = self.handle(port.id()) else {
            return;
        };
        let Some(port_term) = Term::port(port.id()) else {
            return;
        };
        let total: usize = segments.iter().map(Vec::len).sum();
        let words = if binary {
            total / 4 + segments.len() * 12
        } else {
            total * 2
        } + header.len() * 2
            + 32;
        let mut heap = ProcessHeap::with_words(words);
        let build = |heap: &mut ProcessHeap| -> Result<Term, arinsal_term::TermError> {
            let mut list = Term::NIL;
            if binary {
                // erts conses every binary but the last onto it, so the tail of the
                // list is the last binary itself and a single binary is not a list.
                for (at, segment) in segments.iter().enumerate().rev() {
                    let bin = TermBuilder::new(heap).binary(segment)?;
                    list = if at + 1 == segments.len() {
                        bin
                    } else {
                        TermBuilder::new(heap).cons(bin, list)?
                    };
                }
            } else {
                for byte in segments.iter().flatten().rev() {
                    list = TermBuilder::new(heap)
                        .cons(Term::small(i64::from(*byte)).unwrap(), list)?;
                }
            }
            for byte in header.iter().rev() {
                list = TermBuilder::new(heap).cons(Term::small(i64::from(*byte)).unwrap(), list)?;
            }
            let data = TermBuilder::new(heap).tuple(&[atom("data"), list])?;
            TermBuilder::new(heap).tuple(&[port_term, data])
        };
        if let Ok(message) = build(&mut heap) {
            let owner = handle.owner_pid();
            trace_port_send(
                &handle.scheduler,
                handle.trace_scope,
                port.id(),
                owner,
                message,
            );
            publish(&handle.scheduler, owner, port_term, message);
        }
    }

    // Port of erts/emulator/beam/io.c:5658 (driver_deliver_term, message queueing), OTP-29.1.1.
    fn deliver_term(
        &self,
        port: &arinsal_drv::DriverPort,
        to: Option<u64>,
        term: &OwnedTerm,
        trace: bool,
    ) -> bool {
        let Some(handle) = self.handle(port.id()) else {
            return false;
        };
        let target = to.map_or_else(|| handle.owner_pid(), Pid::from_data);
        let mut heap = VecHeap::new();
        let Ok(built) = from_owned(term, &mut heap) else {
            return false;
        };
        let exists = handle.scheduler.lookup(target);
        if trace && let Some(receiver) = target.to_term() {
            crate::trace::emit_port_event_scoped(
                handle.trace_scope,
                &handle.scheduler,
                port.id(),
                crate::trace::SEND,
                if exists {
                    "send"
                } else {
                    "send_to_non_existing_process"
                },
                &[built, receiver],
            );
        }
        if !exists {
            return false;
        }
        let Ok(message) = Message::copy_from(built) else {
            return false;
        };
        handle.scheduler.send(target, target, message).is_ok()
    }

    fn trace_timeout(&self, port: &arinsal_drv::DriverPort) {
        let Some(runtime) = self.runtime.upgrade() else {
            return;
        };
        // Port of erts/emulator/beam/erl_port_task.c:1770, OTP-29.1.1.
        crate::trace::emit_port_event(
            &runtime,
            port.id(),
            crate::trace::RECEIVE,
            "receive",
            &[atom("timeout")],
        );
    }

    fn connected(&self, port: &arinsal_drv::DriverPort) -> u64 {
        self.handle(port.id())
            .map_or(0, |handle| handle.owner_pid().data())
    }

    // Port of erts/emulator/beam/io.c:5203 (set_busy_port), OTP-29.1.1.
    fn set_busy(&self, port: &arinsal_drv::DriverPort, on: bool) {
        let Some(handle) = self.handle(port.id()) else {
            return;
        };
        handle.state.lock().unwrap().busy_port = on;
    }

    // Port of erts/emulator/beam/erl_port_task.c:107 (profile_runnable_port), OTP-29.1.1.
    fn profile_runnable_port(&self, port: &arinsal_drv::DriverPort, active: bool) {
        let Some(handle) = self.handle(port.id()) else {
            return;
        };
        crate::natives::misc::profile_port_event(
            &handle.scheduler,
            handle.owner_pid(),
            port.id(),
            active,
        );
    }

    // Port of erts/emulator/beam/erl_process.c:9413 (erts_resume_processes), OTP-29.1.1.
    fn schedule_async_ready(&self, sched_id: usize, ready: Box<dyn FnOnce() + Send>) {
        match self.runtime.upgrade().map(|runtime| runtime.scheduler()) {
            Some(Ok(scheduler)) => scheduler.request_aux_work(sched_id, ready),
            // Without schedulers the job is completed here so its data is released.
            _ => ready(),
        }
    }

    fn enqueue_port(&self, port: Arc<arinsal_drv::DriverPort>) {
        let Some(runtime) = self.runtime.upgrade() else {
            return;
        };
        if let Ok(scheduler) = runtime.scheduler() {
            scheduler.enqueue_port(port);
        }
    }

    fn resume_processes(&self, _port: &arinsal_drv::DriverPort, pids: Vec<u64>) {
        let Some(runtime) = self.runtime.upgrade() else {
            return;
        };
        let Ok(scheduler) = runtime.scheduler() else {
            return;
        };
        for pid in pids {
            let pid = Pid::from_data(pid);
            if runtime.resume_internal(pid) {
                let _ = scheduler.signal(pid, pid, arinsal_sched::Signal::UnlinkAck(u64::MAX));
            }
        }
    }

    // Port of erts/emulator/beam/io.c:7006 (do_driver_monitor_process), OTP-29.1.1.
    fn monitor_process(&self, port: &arinsal_drv::DriverPort, pid: u64, monitor: u64) -> bool {
        let Some(handle) = self.handle(port.id()) else {
            return false;
        };
        let target = Pid::from_data(pid);
        if !handle.scheduler.lookup(target) {
            return false;
        }
        handle.drv_monitors.lock().unwrap().insert(monitor, target);
        if let Some(runtime) = self.runtime.upgrade() {
            let _ = runtime.publish_proc_flag(target, arinsal_sched::proc_flags::PORTS);
        }
        true
    }

    fn demonitor_process(&self, port: &arinsal_drv::DriverPort, monitor: u64) {
        if let Some(handle) = self.handle(port.id()) {
            handle.drv_monitors.lock().unwrap().remove(&monitor);
        }
    }

    // Port of erts/emulator/beam/io.c:7318 (driver_lock_driver), OTP-29.1.1.
    fn lock_driver(&self, port: &arinsal_drv::DriverPort) -> bool {
        self.handle(port.id())
            .is_some_and(|handle| crate::ddll::lock_driver(&handle.scheduler, port.driver()))
    }

    // Port of erts/emulator/beam/io.c:2912 (init_ack_send_reply), OTP-29.1.1.
    fn init_ack(&self, port: &arinsal_drv::DriverPort, reply: arinsal_drv::InitAck) {
        let Some(handle) = self.handle(port.id()) else {
            return;
        };
        let Some((reference, opener)) = handle.async_open.lock().unwrap().take() else {
            return;
        };
        let Some(port_term) = Term::port(port.id()) else {
            return;
        };
        let result = match reply {
            arinsal_drv::InitAck::Opened => port_term,
            arinsal_drv::InitAck::Failed(error) => {
                // The opener is no longer linked to a port that failed to open.
                handle.links.lock().unwrap().remove(&opener);
                atom(&match error {
                    arinsal_drv::StartError::General => "einval".to_owned(),
                    arinsal_drv::StartError::Errno(errno) => arinsal_drv::errno_id(errno),
                    arinsal_drv::StartError::Badarg => "badarg".to_owned(),
                })
            }
        };
        let mut heap = ProcessHeap::with_words(16);
        let Ok(reference) =
            TermBuilder::new(&mut heap).local_ref(arinsal_bifs::ordinary_ref_words(reference))
        else {
            return;
        };
        if let Ok(message) = TermBuilder::new(&mut heap).tuple(&[reference, result]) {
            publish(&handle.scheduler, opener, port_term, message);
        }
    }

    // Port of erts/emulator/beam/io.c:781 (driver_create_port), OTP-29.1.1.
    fn create_port(
        &self,
        creator: &arinsal_drv::DriverPort,
        owner: u64,
        name: &str,
        drv_data: usize,
    ) -> Option<Arc<arinsal_drv::DriverPort>> {
        let runtime = self.runtime.upgrade()?;
        let scheduler = runtime.scheduler().ok()?;
        let owner = Pid::from_data(owner);
        if !scheduler.lookup(owner) {
            return None;
        }
        let reservation = reserve_port_id(&runtime).ok()?;
        let port_id = reservation.id();
        let handle = make_driver_handle(
            port_id,
            owner,
            name.to_owned(),
            false,
            Arc::clone(&scheduler),
            Arc::as_ptr(&runtime) as usize,
        )
        .ok()?;
        let driver = Arc::clone(creator.driver());
        let drv_port = arinsal_drv::DriverPort::new(
            Arc::clone(&driver),
            port_id,
            Box::new(DrvHost {
                runtime: self.runtime.clone(),
                own: Arc::downgrade(&handle),
            }),
        );
        drv_port.init_run_queue(scheduler.current_run_queue());
        drv_port.adopt(drv_data);
        let _ = handle.driver.set(Arc::clone(&drv_port));
        crate::ddll::port_opened_for(&driver, &drv_port);
        runtime.ports.lock().unwrap().insert(port_id, handle);
        // The owner has a port in its link list (erl_process.c:14084). Exit scans the
        // port table only when that list is non-NULL.
        let _ = runtime.publish_proc_flag(owner, arinsal_sched::proc_flags::PORTS);
        crate::trace::port_opened(&runtime, port_id);
        reservation.commit();
        Some(drv_port)
    }
}

/// Registrations of the shared poller that `driver_select` holds.
#[derive(Default)]
struct DrvPollState {
    live: HashMap<u64, crate::check_io::Registration>,
    /// Fired before `register` returned its handle.
    fired: HashSet<u64>,
}

/// The shared poller as the `driver_select` poll set.
struct DrvPoll {
    state: Arc<Mutex<DrvPollState>>,
}

impl arinsal_drv::PollBackend for DrvPoll {
    fn register(
        &self,
        id: u64,
        fd: i32,
        write: bool,
        ready: Box<dyn FnOnce() + Send>,
    ) -> std::io::Result<()> {
        let state = Arc::clone(&self.state);
        let registration = crate::check_io::register_driver(
            fd,
            crate::check_io::InterestSet {
                readable: !write,
                writable: write,
            },
            move |_, _| {
                {
                    let mut state = state.lock().unwrap();
                    if state.live.remove(&id).is_none() {
                        state.fired.insert(id);
                    }
                }
                ready();
            },
        )?;
        let mut state = self.state.lock().unwrap();
        if !state.fired.remove(&id) {
            state.live.insert(id, registration);
        }
        Ok(())
    }

    fn deregister(&self, id: u64) {
        let registration = self.state.lock().unwrap().live.remove(&id);
        if let Some(registration) = registration {
            crate::check_io::deregister(registration);
        }
    }
}

/// Process-wide services for the driver API (`arinsal_drv::SystemHooks`).
struct VmHooks {
    offset: OnceLock<i128>,
}

impl arinsal_drv::SystemHooks for VmHooks {
    fn monotonic_nanos(&self) -> i128 {
        arinsal_bifs::monotonic_time_nanos()
    }

    fn time_offset_nanos(&self) -> i128 {
        *self.offset.get_or_init(|| {
            let wall = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as i128;
            wall - arinsal_bifs::monotonic_time_nanos()
        })
    }

    fn getenv(&self, key: &[u8]) -> Option<Vec<u8>> {
        crate::natives::env::get(key)
    }

    fn putenv(&self, key: &[u8], value: &[u8]) {
        crate::natives::env::put(key, value);
    }

    fn async_threads(&self) -> usize {
        // Port of erts/emulator/beam/erl_bif_info.c:3032-3037, OTP-29.1.1.
        arinsal_args::active_emulator_flags()
            .async_threads
            .unwrap_or(1)
            .max(1) as usize
    }

    fn scheduler_threads(&self) -> usize {
        crate::natives::sys::schedulers_total()
    }

    fn add_driver(&self, driver: Arc<arinsal_drv::Driver>) {
        crate::ddll::add_linked(driver);
    }

    fn remove_driver(&self, entry: usize) -> i32 {
        crate::ddll::remove_linked(entry)
    }
}

/// Install the shared poller as the `driver_select`/`enif_select` poll set.
pub(crate) fn install_poll_backend() {
    static INSTALLED: std::sync::Once = std::sync::Once::new();
    INSTALLED.call_once(|| {
        arinsal_drv::set_poll_backend(Arc::new(DrvPoll {
            state: Arc::default(),
        }));
    });
}

/// `erts_send_error_to_logger_nogl` for `runtime`.
pub(crate) fn log_error_for(runtime: &Weak<crate::process::Runtime>, text: &str) {
    arinsal_drv::PortHost::log_error(
        &DrvHost {
            runtime: runtime.clone(),
            own: Weak::new(),
        },
        text,
    );
}

/// Install the driver API hooks once, before the first driver code runs.
pub(crate) fn install_hooks() {
    static INSTALLED: std::sync::Once = std::sync::Once::new();
    INSTALLED.call_once(|| {
        arinsal_drv::set_system_hooks(Arc::new(VmHooks {
            offset: OnceLock::new(),
        }));
    });
}

/// Port of erts/emulator/beam/io.c:3841 (erts_deliver_port_exit) for a driver that
/// fails: the port terminates (`stop`), then links and monitors see `reason`.
fn driver_port_exit(runtime: &crate::process::Runtime, id: u64, reason: Term) {
    crate::trace::emit_port_event(runtime, id, crate::trace::PORTS, "closed", &[reason]);
    let Some(handle) = remove_port(runtime, id) else {
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
    // The VM may run through a symlink such as `erl`; the helper is the real binary.
    let executable = std::fs::canonicalize(&executable).unwrap_or(executable);
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

/// Failure while creating the accepted TCP port.
pub(crate) enum InetPortAllocError {
    /// The runtime port table has no free identifiers.
    SystemLimit,
    /// Creating the scheduler or OS port resources failed.
    NoMemory,
}

/// Allocate a connected `tcp_inet` port for an accepted socket.
pub(crate) fn alloc_inet_port(
    runtime: &crate::process::Runtime,
    owner: Pid,
    name: String,
) -> Result<(u64, Arc<PortHandle>), InetPortAllocError> {
    let scheduler = runtime
        .scheduler()
        .map_err(|_| InetPortAllocError::NoMemory)?;
    let reservation = reserve_port_id(runtime).map_err(|_| InetPortAllocError::SystemLimit)?;
    let port_id = reservation.id();
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
        runtime as *const crate::process::Runtime as usize,
        true,
    )
    .map_err(|_| InetPortAllocError::NoMemory)?;
    runtime
        .ports
        .lock()
        .unwrap()
        .insert(port_id, Arc::clone(&handle));
    let _ = runtime.publish_proc_flag(owner, arinsal_sched::proc_flags::PORTS);
    crate::trace::port_opened(runtime, port_id);
    reservation.commit();
    Ok((port_id, handle))
}

/// Remove an inet port after the peer closes an active socket (`driver_exit`).
pub(crate) fn abandon_port(runtime: &crate::process::Runtime, id: u64) {
    let Some(handle) = remove_port(runtime, id) else {
        return;
    };
    crate::inet_drv::detach(&handle);
    // g_inet_udp
    crate::inet_udp::detach(&handle);
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
    // The lock is held while the DOWNs are queued so that a concurrent `demonitor(_, [flush])`
    // either removes the monitor first or finds the message already in its mailbox.
    let mut guard = handle.monitors.lock().unwrap();
    let monitors = std::mem::take(&mut *guard);
    for (reference, monitor) in monitors {
        let mut heap = ProcessHeap::with_words(32);
        let Ok(reference_term) =
            TermBuilder::new(&mut heap).local_ref(arinsal_bifs::ordinary_ref_words(reference))
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

/// Mutual exclusion between descriptor creation and `Command::spawn`.
///
/// `pipe`/`dup`/`socket`/`accept` then `FD_CLOEXEC` is not atomic. A port child
/// spawned in that window inherits the descriptor. `erl_child_setup` never has
/// this window: it closes every fd above 3 at start and sets CLOEXEC before any
/// child exists (erl_child_setup.c:466-470, OTP-29.1.1).
pub(crate) fn cloexec_publish<R>(body: impl FnOnce() -> R) -> R {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _guard = LOCK.lock().unwrap_or_else(|error| error.into_inner());
    body()
}

pub(crate) fn duplicate_fd(fd: RawFd) -> std::io::Result<OwnedFd> {
    cloexec_publish(|| {
        unsafe extern "C" {
            fn dup(fd: i32) -> i32;
        }
        // SAFETY: dup returns a fresh descriptor; setting CLOEXEC before the lock is
        // released prevents a concurrently spawned port child from inheriting it.
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
    })
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
    let fds = cloexec_publish(|| {
        let mut fds = [0; 2];
        // SAFETY: pipe initializes both slots with fresh descriptors on success; fcntl
        // marks those owned descriptors close-on-exec before the publish lock is released.
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
        Ok(fds)
    })?;
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
    trace_scope: usize,
    inet: bool,
) -> Result<Arc<PortHandle>, VmError> {
    make_handle_with(
        id,
        out,
        framing,
        owner,
        os_pid,
        name,
        parallelism,
        limits,
        scheduler,
        trace_scope,
        inet,
        true,
    )
}

/// Port handle of a loaded driver: no wake pipe, so a full port table does not need two
/// descriptors per port.
#[allow(clippy::too_many_arguments)]
fn make_driver_handle(
    id: u64,
    owner: Pid,
    name: String,
    parallelism: bool,
    scheduler: Arc<Scheduler<Process>>,
    trace_scope: usize,
) -> Result<Arc<PortHandle>, VmError> {
    make_handle_with(
        id,
        None,
        None,
        owner,
        0,
        name,
        parallelism,
        default_limits(),
        scheduler,
        trace_scope,
        false,
        false,
    )
}

#[allow(clippy::too_many_arguments)]
fn make_handle_with(
    id: u64,
    out: Option<OwnedFd>,
    framing: Option<(u8, usize)>,
    owner: Pid,
    os_pid: u32,
    name: String,
    parallelism: bool,
    limits: BusyLimits,
    scheduler: Arc<Scheduler<Process>>,
    trace_scope: usize,
    inet: bool,
    wake: bool,
) -> Result<Arc<PortHandle>, VmError> {
    let (wake_r, wake_w) = if wake {
        let (r, w) = wake_pipe().map_err(|_| badarg())?;
        (Some(r), Some(w))
    } else {
        (None, None)
    };
    if let Some(fd) = out.as_ref() {
        set_nonblock(fd.as_raw_fd());
    }
    let handle = Arc::new(PortHandle {
        id,
        out: Mutex::new(out),
        wake_r: Mutex::new(wake_r),
        wake_w,
        wake_needed: AtomicBool::new(true),
        framing,
        arl_ns: scheduler
            .ns_word(owner)
            .map_or(0, |word| word & arinsal_sched::NS_ID_MASK),
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
        trace_scope,
        data: Mutex::new(OwnedTerm::Atom("undefined".into())),
        inet,
        driver: OnceLock::new(),
        drv_monitors: Mutex::new(HashMap::new()),
        async_open: Mutex::new(None),
        reg_word: Arc::new(AtomicU32::new(crate::register::NO_REG_ATOM)),
        reg_closing: AtomicBool::new(false),
        halt_progress: Mutex::new(None),
        ram_file: Mutex::new(None),
        inet_tcp: Mutex::new(None),
        inet_udp: Mutex::new(None),
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
    let reservation = reserve_port_id(runtime)?;
    let id = reservation.id();
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
        Arc::as_ptr(runtime) as usize,
        false,
    )?;
    runtime
        .ports
        .lock()
        .unwrap()
        .insert(id, Arc::clone(&handle));
    let _ = runtime.publish_proc_flag(ctx.pid(), arinsal_sched::proc_flags::PORTS);
    crate::trace::port_opened(runtime, id);
    reservation.commit();
    let owner = ctx.pid();
    let read_fd = reader.into_raw_fd();
    let runtime_weak = Arc::downgrade(runtime);
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
                runtime_weak,
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
        let Some(wake_w) = handle.wake_w.as_ref() else {
            return;
        };
        let fd = wake_w.as_raw_fd();
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

/// Port of erts/emulator/beam/io.c:1203 (erts_schedule_proc2port_signal, the caller side of a
/// reply reference), OTP-29.1.1: called before the port signal is scheduled, so the reply cannot
/// be queued before the save pointer moves. The receive that waits for the reply then starts at
/// the end of the message queue.
// Port of erts/emulator/beam/erl_proc_sig_queue.h:2397 (erts_msgq_set_save_end), OTP-29.1.1.
pub(crate) fn set_save_end(process: &mut Process, ctx: &mut RunCtx<'_, Message>) {
    // erts_proc_sig_fetch(c_p). Fetching links queued messages and cannot fail: `push_message`
    // only appends, so the Result is an internal invariant.
    process
        .fetch_signals(ctx)
        .expect("fetching signals links queued messages and cannot fail");
    let len = process.inbox.len();
    process.priority_resume_cursor = None;
    if process.sig_cont_empty() {
        // `c_p->sig_qs.save = c_p->sig_qs.last`.
        process.receive_cursor = len;
    } else {
        // Unhandled signals in the middle queue: a receive marker passes through it and
        // sets the save pointer when it enters the message queue.
        // erts_msgq_recv_marker_create_insert_set_save(c_p, NIL): the marker goes to the end.
        process.recv_marker_create_insert_set_save(None);
    }
}

/// Port of erts/emulator/beam/erl_process.c:9369 (erts_suspend) with a busy port: `false`
/// when the port stopped being busy, and the operation is to be retried at once.
fn suspend_on_busy(
    process: &mut Process,
    handle: &PortHandle,
    drv: &arinsal_drv::DriverPort,
    pid: Pid,
) -> bool {
    let Some(runtime) = process.runtime.clone() else {
        return false;
    };
    // Suspended before it is queued on the port, so a resume racing with this cannot be lost.
    if process.self_pid == Some(pid) {
        crate::suspend::suspend_self(process);
    }
    if !drv.save_suspend_process(packed_pid(pid)) {
        runtime.resume_internal(pid);
        return false;
    }
    crate::natives::erts_debug::notify_busy_port(process, pid, handle.id);
    true
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

/// Exit status of a child as a driver reports it: the exit code, or 128 plus the signal number.
fn child_exit_code(status: std::process::ExitStatus) -> i64 {
    use std::os::unix::process::ExitStatusExt;
    match status.signal() {
        Some(signal) => 128 + i64::from(signal),
        None => i64::from(status.code().unwrap_or(0)),
    }
}

fn exit_status_message(
    scheduler: &Scheduler<Process>,
    owner: Pid,
    id: u64,
    trace_scope: usize,
    code: i64,
) {
    let mut heap = ProcessHeap::with_words(16);
    if let Ok(event) =
        TermBuilder::new(&mut heap).tuple(&[atom("exit_status"), Term::small(code).unwrap()])
    {
        event_message(scheduler, owner, id, trace_scope, event);
    }
}

/// What the port does once its input side ended.
enum InputEnd {
    /// `exit_status` is wanted and the child still runs: report when it exits.
    WaitForExit,
    /// `{Port, eof}` was sent and the port stays open (`eof` option).
    Reported,
    /// The port exits with reason `normal`.
    Terminate,
}

/// End of input on a spawn or fd port, as the stdio drivers handle it: the exit status comes
/// first when it is wanted and known, then a partial line, then `{Port, eof}` for a port
/// opened with `eof` or the port exit otherwise.
#[allow(clippy::too_many_arguments)]
fn end_of_input(
    handle: &PortHandle,
    scheduler: &Scheduler<Process>,
    owner: Pid,
    id: u64,
    binary: bool,
    framing: Option<(u8, usize)>,
    want_eof: bool,
    exit_code: Option<i64>,
    child_running: bool,
    data: &mut Vec<u8>,
) -> InputEnd {
    if handle.state.lock().unwrap().closed {
        return InputEnd::Terminate;
    }
    if child_running {
        return InputEnd::WaitForExit;
    }
    if let Some(code) = exit_code {
        exit_status_message(scheduler, owner, id, handle.trace_scope, code);
    }
    if framing.is_some_and(|(mode, _)| mode == 1) && !data.is_empty() {
        line_message(scheduler, owner, id, data, binary, false);
        data.clear();
    }
    if want_eof {
        event_message(scheduler, owner, id, handle.trace_scope, atom("eof"));
        InputEnd::Reported
    } else {
        InputEnd::Terminate
    }
}

#[allow(clippy::too_many_arguments)]
fn worker(
    handle: Arc<PortHandle>,
    mut child: Option<Child>,
    read_fd: Option<RawFd>,
    scheduler: Arc<Scheduler<Process>>,
    runtime: Weak<crate::process::Runtime>,
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
    // The input descriptor stays open until the port terminates; at end of input it only
    // leaves the poll set.
    let mut input_live = read_fd.is_some();
    let mut exit_code: Option<i64> = None;
    let mut status_reported = false;
    let mut eof_waiting = false;
    let mut eof_terminate = false;
    let mut input_closed = false;
    loop {
        let closed = handle.state.lock().unwrap().closed;
        if closed {
            break;
        }
        if eof_waiting
            && let Some(status) = child
                .as_mut()
                .and_then(|child| child.try_wait().ok().flatten())
        {
            exit_code = Some(child_exit_code(status));
            eof_waiting = false;
            match end_of_input(
                &handle, &scheduler, owner, id, binary, framing, want_eof, exit_code, false,
                &mut data,
            ) {
                InputEnd::WaitForExit => eof_waiting = true,
                InputEnd::Reported => status_reported = true,
                InputEnd::Terminate => {
                    status_reported = true;
                    eof_terminate = true;
                    break;
                }
            }
        }
        let wants_out = !handle.state.lock().unwrap().outq.is_empty()
            || !handle.state.lock().unwrap().pending.is_empty();
        handle.wake_needed.store(true, Ordering::Release);
        let mut fds = Vec::with_capacity(3);
        if input_live && let Some(fd) = read_fd {
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
            let timeout = eof_waiting.then(|| std::time::Duration::from_millis(5));
            let result = crate::check_io::wait_any_timeout_wake(&fds, timeout, wake_r);
            match result {
                Ok(Some((ready_fd, ready))) => {
                    input_ready = input_live
                        && Some(ready_fd) == read_fd
                        && (ready.readable || ready.closed || ready.error);
                }
                Ok(None) => continue,
                Err(err)
                    if matches!(
                        err.kind(),
                        std::io::ErrorKind::Interrupted | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    continue;
                }
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
                // A read error deselects the input and drops a partial packet; the port
                // itself stays open.
                input_live = false;
                if framing.is_some_and(|(mode, _)| mode == 2) {
                    data.clear();
                }
            } else if n == 0 {
                input_live = false;
                if framing.is_some_and(|(mode, _)| mode == 2) {
                    data.clear();
                }
                if want_status
                    && exit_code.is_none()
                    && let Some(status) = child
                        .as_mut()
                        .and_then(|child| child.try_wait().ok().flatten())
                {
                    exit_code = Some(child_exit_code(status));
                }
                let child_running = want_status && exit_code.is_none() && child.is_some();
                match end_of_input(
                    &handle,
                    &scheduler,
                    owner,
                    id,
                    binary,
                    framing,
                    want_eof,
                    exit_code,
                    child_running,
                    &mut data,
                ) {
                    InputEnd::WaitForExit => eof_waiting = true,
                    InputEnd::Reported => status_reported = exit_code.is_some(),
                    InputEnd::Terminate => {
                        status_reported = exit_code.is_some();
                        eof_terminate = true;
                        break;
                    }
                }
            } else {
                let n = n as usize;
                if framing.is_none() {
                    output_message(&scheduler, owner, id, &buf[..n], binary, handle.trace_scope);
                } else {
                    data.extend_from_slice(&buf[..n]);
                    decode_frames(
                        &scheduler,
                        owner,
                        id,
                        &mut data,
                        binary,
                        framing,
                        handle.trace_scope,
                    );
                }
            }
        }
        let st = handle.state.lock().unwrap();
        if input_closed && !input_live && st.outq.is_empty() && st.pending.is_empty() {
            break;
        }
        drop(st);
    }
    if eof_terminate && !handle.state.lock().unwrap().closed {
        eof_exit(
            &handle, &scheduler, &runtime, owner, id, wake_r, read_fd, child,
        );
        return;
    }
    let woken = flush_output(&handle);
    wake_suspended(&scheduler, woken);
    close_worker_fds(wake_r, read_fd);
    let closed = handle.state.lock().unwrap().closed;
    // Port of erts/emulator/sys/unix/sys_drivers.c:1039 (stop), OTP-29.1.1.
    // Close the child's input first; a detached child may keep running after
    // the port descriptors close, so reap it only after its own exit.
    if let Some(mut child) = child.take() {
        if closed {
            handle.out.lock().unwrap().take();
            // erts frees a killed port without waiting for the child; the forker
            // reports its exit later (sys_drivers.c:1039 stop), so halt need not wait.
            handle.finish_halt();
        }
        let status = child.wait().ok();
        if !closed && want_status && !status_reported {
            let code = status.map(child_exit_code).unwrap_or(1);
            exit_status_message(&scheduler, owner, id, handle.trace_scope, code);
        }
    }
    handle.state.lock().unwrap().exit_complete = true;
    handle.finish_halt();
    if !closed && handle.state.lock().unwrap().send_closed {
        event_message(&scheduler, owner, id, handle.trace_scope, atom("closed"));
    }
    if !closed {
        // Port of erts/emulator/beam/io.c:3841-3891 (erts_deliver_port_exit), OTP-29.1.1.
        notify_closed(&handle, id, &scheduler, owner, false);
    }
}

/// Close the wake read end and the duplicated input descriptor this worker thread owns.
fn close_worker_fds(wake_r: RawFd, read_fd: Option<RawFd>) {
    if wake_r >= 0 {
        // SAFETY: this thread owns the wake read end taken from the handle.
        unsafe { libc::close(wake_r) };
    }
    if let Some(fd) = read_fd {
        // SAFETY: the worker owns the duplicated input descriptor.
        unsafe { libc::close(fd) };
    }
}

/// The port exits at end of input (no `eof` option): the descriptors close, the port leaves the
/// port table, links and monitors get reason `normal`, and only then is the child reaped.
#[allow(clippy::too_many_arguments)]
fn eof_exit(
    handle: &PortHandle,
    scheduler: &Scheduler<Process>,
    runtime: &Weak<crate::process::Runtime>,
    owner: Pid,
    id: u64,
    wake_r: RawFd,
    read_fd: Option<RawFd>,
    mut child: Option<Child>,
) {
    if let Some(runtime) = runtime.upgrade() {
        let listed = runtime.ports.lock().unwrap().contains_key(&id);
        if listed {
            crate::trace::emit_port_event(
                &runtime,
                id,
                crate::trace::PORTS,
                "closed",
                &[atom("normal")],
            );
            remove_port(&runtime, id);
        }
    }
    let woken = {
        let mut st = handle.state.lock().unwrap();
        st.closed = true;
        st.broken = true;
        st.busy_port = false;
        st.busy_msgq = false;
        st.outq.clear();
        st.pending.clear();
        std::mem::take(&mut st.suspended)
    };
    wake_suspended(scheduler, woken);
    close_worker_fds(wake_r, read_fd);
    handle.out.lock().unwrap().take();
    handle.state.lock().unwrap().exit_complete = true;
    handle.finish_halt();
    if handle.state.lock().unwrap().send_closed {
        event_message(scheduler, owner, id, handle.trace_scope, atom("closed"));
    }
    notify_closed(handle, id, scheduler, owner, false);
    if let Some(mut child) = child.take() {
        let _ = child.wait();
    }
}

fn decode_frames(
    scheduler: &Scheduler<Process>,
    owner: Pid,
    id: u64,
    data: &mut Vec<u8>,
    binary: bool,
    framing: Option<(u8, usize)>,
    trace_scope: usize,
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
        output_message(scheduler, owner, id, &body, binary, trace_scope);
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
        .is_some_and(|runtime| runtime_port_live(runtime, id))
}

/// Whether local port `id` of `runtime` exists and has not finished exiting.
pub(crate) fn runtime_port_live(runtime: &crate::process::Runtime, id: u64) -> bool {
    let handle = runtime.ports.lock().unwrap().get(&id).cloned();
    handle.is_some_and(|handle| !handle.state.lock().unwrap().exit_complete)
}

// Port of erts/emulator/beam/erl_bif_port.c:734 (port_get_data_1), OTP-29.1.1.
fn port_get_data(process: &mut Process, port: Term) -> Result<Term, VmError> {
    let handle = lookup_port(process, port)?;
    let owned = handle.data.lock().unwrap().clone();
    let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
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
    // arl: a process of a namespace reaches only the ports of its own namespace.
    if process.ns != 0
        && let Some(refused) = arl_port_guard(process, module, function, args)
    {
        return Some(refused);
    }
    let result = match (function, args) {
        ("open_port", [spec, opts]) if module == "erts_internal" => {
            start(vm, process, ctx, *spec, *opts)
        }
        ("port_command", [port, data, _]) if module == "erts_internal" => {
            port_command(process, ctx, *port, *data, args)
        }
        ("port_close", [port]) if module == "erts_internal" => port_close(process, ctx, *port),
        ("port_connect", [port, pid]) if module == "erts_internal" => {
            connect(process, *port, *pid, None)
        }
        // Port of erts/emulator/beam/erl_bif_port.c:322 (erts_internal_port_control_3), OTP-29.1.1.
        // Spawn and fd ports have no driver control. The internal BIF returns the
        // atom `badarg`; `erlang:port_control/3` turns that atom into an exception.
        ("port_control", [port, op, data]) if module == "erts_internal" => {
            port_control(process, ctx, *port, *op, *data)
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
    ctx: &mut RunCtx<'_, Message>,
    port: Term,
    op: Term,
    data: Term,
) -> Result<Term, VmError> {
    let caller = ctx.pid();
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
        return driver_control(process, ctx, caller, drv_port, op, data);
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
    if let Some(sock) = handle.udp_driver_data() {
        return crate::inet_udp::control(process, &sock, caller, op, &data);
    }
    let Some(sock) = handle.tcp_driver_data() else {
        return Ok(atom("badarg"));
    };
    crate::inet_drv::control(process, &sock, caller, op, &data)
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
        trace_port_receive_indexed(process, caller, id, "call", op, &encoded);
        let Some(reply) = drv_port.call(op, &encoded, packed_pid(caller)) else {
            return Ok(atom("badarg"));
        };
        if let Some(port) = Term::port(id) {
            let mut trace_heap = VecHeap::new();
            if let Ok(binary) = TermBuilder::new(&mut trace_heap).binary(&reply)
                && let Ok(call) = TermBuilder::new(&mut trace_heap).tuple(&[atom("call"), binary])
                && let Ok(message) = TermBuilder::new(&mut trace_heap).tuple(&[port, call])
            {
                trace_port_send(&handle.scheduler, handle.trace_scope, id, caller, message);
            }
        }
        let Ok((term, _)) = arinsal_etf::decode_prefix(&reply) else {
            return Ok(atom("badarg"));
        };
        let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
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
    ctx: &mut RunCtx<'_, Message>,
    caller: Pid,
    drv_port: &Arc<arinsal_drv::DriverPort>,
    op: Term,
    data: Term,
) -> Result<Term, VmError> {
    let Some(opcode) = op.as_small().and_then(|n| u32::try_from(n).ok()) else {
        return Ok(atom("badarg"));
    };
    let mut pieces = Vec::new();
    if io_pieces(data, &mut pieces).is_none() {
        return Ok(atom("badarg"));
    }
    let bytes = pieces.into_iter().flat_map(|(b, _)| b).collect::<Vec<_>>();
    drv_sig::control(process, ctx, caller, drv_port, opcode, bytes)
}

/// Next local port id for `open_port`, or `system_limit` when the port table is full.
// Port of erts/emulator/beam/erl_ptab.c (erts_ptab_new_element), OTP-29.1.1.
fn notsup() -> VmError {
    VmError::Trap(crate::exceptions::Trap::error(atom("notsup")))
}

fn port_command(
    process: &mut Process,
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
    let mut force = false;
    if args.len() == 3 {
        let options = list(args[2]).ok_or_else(badarg)?;
        for option in options {
            if option == atom("nosuspend") {
                nosuspend = true;
            } else if option == atom("force") {
                force = true;
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
    if let Some(drv_port) = handle.driver.get().cloned() {
        // Port of erts/emulator/beam/erl_bif_port.c:168 (erts_internal_port_command_3).
        let flags = drv_sig::OutputFlags {
            bang: false,
            nosuspend,
            force,
        };
        loop {
            let pid = ctx.pid();
            match drv_sig::output(
                process,
                Some(ctx),
                pid,
                &handle,
                &drv_port,
                pid,
                data,
                flags,
                true,
            ) {
                drv_sig::PortOp::Done => return Ok(atom("true")),
                drv_sig::PortOp::Dropped | drv_sig::PortOp::Badarg => return Ok(atom("badarg")),
                drv_sig::PortOp::Busy if nosuspend => return Ok(atom("false")),
                drv_sig::PortOp::Busy => {
                    if suspend_on_busy(process, &handle, &drv_port, pid) {
                        BUSY_SUSPEND.with(|flag| flag.set(true));
                        return Err(badarg());
                    }
                }
                drv_sig::PortOp::BusyScheduled(reference)
                | drv_sig::PortOp::Scheduled(reference) => {
                    return match reference {
                        Some(reference) => drv_sig::reference_term(process, reference),
                        None => Ok(atom("true")),
                    };
                }
            }
        }
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
        if let Some(sock) = handle.udp_driver_data() {
            return crate::inet_udp::command(&sock, ctx.pid(), &framed).map(|()| atom("true"));
        }
        let Some(sock) = handle.tcp_driver_data() else {
            return Err(badarg());
        };
        return crate::inet_drv::command(&sock, ctx.pid(), framed).map(|()| atom("true"));
    }
    let ram_file = handle.ram_file.lock().unwrap().clone();
    if let Some(ram_file) = ram_file {
        let state = handle.state.lock().unwrap();
        if state.closed || state.broken {
            return Err(badarg());
        }
        drop(state);
        trace_command_received_data(process, ctx.pid(), id, data, &framed);
        return crate::ram_file_drv::command(&ram_file, &handle, &framed)
            .map(|()| atom("true"))
            .map_err(|()| badarg());
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
    trace_command_received_data(process, ctx.pid(), id, data, &framed);
    command_bytes(&handle, &framed).map_err(|()| badarg())?;
    Ok(atom("true"))
}

// Port of erts/emulator/beam/io.c:1508 (trace_port_receive command), OTP-29.1.1.
fn trace_command_received(
    process: &Process,
    caller: Pid,
    id: u64,
    pieces: &[arinsal_drv::IoPiece<'_>],
    outputv_segments: Option<Vec<Vec<u8>>>,
) {
    let Some(runtime) = process.runtime.as_ref() else {
        return;
    };
    let Some(caller) = caller.to_term() else {
        return;
    };
    let mut heap = VecHeap::new();
    let data = if let Some(segments) = outputv_segments {
        let mut binaries = Vec::with_capacity(segments.len());
        for segment in segments {
            let Ok(binary) = TermBuilder::new(&mut heap).binary(&segment) else {
                return;
            };
            binaries.push(binary);
        }
        let Ok(list) = TermBuilder::new(&mut heap).list_from_iter(binaries) else {
            return;
        };
        list
    } else {
        let bytes = pieces
            .iter()
            .flat_map(|piece| match piece {
                arinsal_drv::IoPiece::Copied(bytes) | arinsal_drv::IoPiece::Refc(bytes) => {
                    bytes.iter().copied()
                }
            })
            .collect::<Vec<_>>();
        let Ok(binary) = TermBuilder::new(&mut heap).binary(&bytes) else {
            return;
        };
        binary
    };
    let Ok(command) = TermBuilder::new(&mut heap).tuple(&[atom("command"), data]) else {
        return;
    };
    let Ok(event) = TermBuilder::new(&mut heap).tuple(&[caller, command]) else {
        return;
    };
    crate::trace::emit_port_event(runtime, id, crate::trace::RECEIVE, "receive", &[event]);
}

fn trace_command_received_data(process: &Process, caller: Pid, id: u64, data: Term, bytes: &[u8]) {
    let Some(runtime) = process.runtime.as_ref() else {
        return;
    };
    let Some(caller) = caller.to_term() else {
        return;
    };
    let mut heap = VecHeap::new();
    let binary_list = to_owned(data).ok().is_some_and(|owned| {
        matches!(&owned, arinsal_etf::OwnedTerm::List { elems, tail }
            if **tail == arinsal_etf::OwnedTerm::Nil
                && !elems.is_empty()
                && elems.iter().all(|item| matches!(item, arinsal_etf::OwnedTerm::Binary(_)))
        )
    });
    let data = if binary_list {
        copy_term(data, &mut heap)
    } else {
        TermBuilder::new(&mut heap).binary(bytes)
    };
    let (Ok(caller), Ok(data)) = (copy_term(caller, &mut heap), data) else {
        return;
    };
    let Ok(command) = TermBuilder::new(&mut heap).tuple(&[atom("command"), data]) else {
        return;
    };
    let Ok(event) = TermBuilder::new(&mut heap).tuple(&[caller, command]) else {
        return;
    };
    crate::trace::emit_port_event(runtime, id, crate::trace::RECEIVE, "receive", &[event]);
}

fn trace_port_receive_term(process: &Process, caller: Pid, id: u64, message: Term) {
    let Some(runtime) = process.runtime.as_ref() else {
        return;
    };
    let Some(caller) = caller.to_term() else {
        return;
    };
    let mut heap = VecHeap::new();
    let (Ok(caller), Ok(message)) = (copy_term(caller, &mut heap), copy_term(message, &mut heap))
    else {
        return;
    };
    let Ok(event) = TermBuilder::new(&mut heap).tuple(&[caller, message]) else {
        return;
    };
    crate::trace::emit_port_event(runtime, id, crate::trace::RECEIVE, "receive", &[event]);
}

fn trace_port_receive_indexed(
    process: &Process,
    caller: Pid,
    id: u64,
    name: &str,
    index: u32,
    data: &[u8],
) {
    if let Some(runtime) = process.runtime.as_ref() {
        trace_port_receive_indexed_rt(runtime, caller, id, name, index, data);
    }
}

/// `trace_port_receive(prt, caller, Name, Index, Data)` (erl_trace.c) without a process.
fn trace_port_receive_indexed_rt(
    runtime: &crate::process::Runtime,
    caller: Pid,
    id: u64,
    name: &str,
    index: u32,
    data: &[u8],
) {
    let Some(caller) = caller.to_term() else {
        return;
    };
    let mut heap = VecHeap::new();
    let Ok(data) = TermBuilder::new(&mut heap).binary(data) else {
        return;
    };
    let Ok(arg) =
        TermBuilder::new(&mut heap).tuple(&[Term::small(i64::from(index)).unwrap(), data])
    else {
        return;
    };
    let Ok(message) = TermBuilder::new(&mut heap).tuple(&[atom(name), arg]) else {
        return;
    };
    let Ok(event) = TermBuilder::new(&mut heap).tuple(&[caller, message]) else {
        return;
    };
    crate::trace::emit_port_event(runtime, id, crate::trace::RECEIVE, "receive", &[event]);
}

// Port of erts/emulator/sys/unix/sys_drivers.c:1039 (stop), OTP-29.1.1.
// Closing a port releases its descriptors; the child may have detached from them.
fn release_io(handle: &PortHandle) {
    // rfile_stop: release the ram_file_drv port data.
    handle.ram_file.lock().unwrap().take();
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
        // Driver and inet ports have no worker thread to finish the exit.
        if handle.wake_w.is_none() || handle.inet {
            st.exit_complete = true;
        }
        std::mem::take(&mut st.suspended)
    };
    wake_suspended(&handle.scheduler, waiters);
    poke(handle);
    if handle.wake_w.is_none() || handle.inet {
        handle.finish_halt();
    }
}

fn remove_and_notify(
    runtime: &crate::process::Runtime,
    id: u64,
    scheduler: &Scheduler<Process>,
    from: Pid,
    reason: Term,
) -> Option<Arc<PortHandle>> {
    let mut ports = runtime.ports.lock().unwrap();
    let handle = ports.remove(&id)?;
    runtime.port_ids.release(id);
    drop(ports);
    release_port_name(runtime, &handle);
    notify_links_monitors(&handle, id, scheduler, from, false, reason);
    Some(handle)
}

fn close(process: &Process, term: Term) -> Result<Term, VmError> {
    close_inner(process, term, true)
}

fn close_inner(process: &Process, term: Term, trace_receive: bool) -> Result<Term, VmError> {
    let sender = process.self_pid.ok_or_else(badarg)?;
    let runtime = process.runtime.as_ref().ok_or_else(badarg)?;
    let scheduler = runtime.scheduler().map_err(|_| badarg())?;
    let id = term.as_port().ok_or_else(badarg)?;
    if trace_receive && let Some(caller) = sender.to_term() {
        let mut heap = VecHeap::new();
        if let Ok(event) = TermBuilder::new(&mut heap).tuple(&[caller, atom("close")]) {
            crate::trace::emit_port_event(runtime, id, crate::trace::RECEIVE, "receive", &[event]);
        }
    }
    crate::trace::emit_port_event(
        runtime,
        id,
        crate::trace::PORTS,
        "closed",
        &[atom("normal")],
    );
    // Port of erts/emulator/beam/io.c:3698 (terminate_port): links get a port exit signal,
    // monitors a DOWN, both with the port as origin. Removal and notification share one
    // critical section of the port table so `demonitor` cannot slip between them.
    let removed = remove_and_notify(runtime, id, &scheduler, sender, atom("normal"));
    if let Some(handle) = removed {
        crate::trace::port_closed(runtime, id);
        if handle.inet {
            crate::inet_drv::detach(&handle);
            crate::inet_udp::detach(&handle);
        }
        release_io(&handle);
        Ok(atom("true"))
    } else {
        Err(badarg())
    }
}

// Port of erts/emulator/beam/erl_bif_port.c:233 (erts_internal_port_close_1), OTP-29.1.1.
fn port_close(
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    port: Term,
) -> Result<Term, VmError> {
    let caller = ctx.pid();
    if let Some(id) = port.as_port()
        && let Some(handle) = process
            .runtime
            .as_ref()
            .and_then(|runtime| runtime.ports.lock().unwrap().get(&id).cloned())
        && let Some(drv) = handle.driver.get().cloned()
    {
        // The `{Caller, close}` receive trace is emitted when the exit signal executes
        // (drv_sig::exit, io.c:2196 call_deliver_port_exit).
        let normal = OwnedTerm::Atom("normal".into());
        return match drv_sig::exit(
            process,
            Some(ctx),
            caller,
            &handle,
            &drv,
            false,
            caller,
            normal,
            true,
        ) {
            Ok(Some(reference)) => drv_sig::reference_term(process, reference),
            Ok(None) => Ok(atom("true")),
            // erl_bif_port.c:405: a dropped close answers `badarg`.
            Err(_) => Ok(atom("badarg")),
        };
    }
    close(process, port)
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
    // arl: an exit signal to a port of another namespace is dropped.
    if !arl_port_ns_ok(process, id) {
        return Ok(());
    }
    // Port of erts/emulator/beam/io.c:3854 (deliver_port_exit): `kill` reaches links as `killed`.
    let reason = if reason == atom("kill") {
        atom("killed")
    } else {
        reason
    };
    let Some(runtime) = process.runtime.as_ref() else {
        return Ok(());
    };
    let handle = runtime.ports.lock().unwrap().get(&id).cloned();
    if let Some(handle) = handle
        && let Some(drv) = handle.driver.get().cloned()
    {
        let reason = to_owned(reason).map_err(|_| badarg())?;
        let pid = ctx.pid();
        // An exit signal to a port that is gone is dropped (bif.c:1794).
        let _ = drv_sig::exit(
            process,
            Some(ctx),
            pid,
            &handle,
            &drv,
            false,
            pid,
            reason,
            false,
        );
        return Ok(());
    }
    crate::trace::emit_port_event(runtime, id, crate::trace::PORTS, "closed", &[reason]);
    let scheduler = runtime.scheduler()?;
    let Some(removed) = remove_and_notify(runtime, id, &scheduler, ctx.pid(), reason) else {
        return Ok(());
    };
    crate::trace::port_closed(runtime, id);
    if removed.inet {
        crate::inet_drv::detach(&removed);
        crate::inet_udp::detach(&removed);
    }
    release_io(&removed);
    Ok(())
}

/// Reap every live port during an orderly halt, leaving `heart_port` alive.
///
/// Port of erts/emulator/beam/erl_process.c:2537-2581 (`handle_reap_ports`), OTP-29.1.1.
pub(crate) fn halt_reap_ports(runtime: &Arc<crate::process::Runtime>, progress: HaltProgress) {
    let heart = global_atoms().intern("heart_port").ok();
    let ports: Vec<_> = runtime.ports.lock().unwrap().values().cloned().collect();
    for handle in ports {
        if heart.is_some() && handle.registered_atom() == heart {
            continue;
        }
        handle.track_halt(progress.clone());
        if handle.driver.get().is_some() {
            drv_sig::exit_for_halt(
                Arc::clone(runtime),
                Arc::clone(&handle),
                handle.owner_pid(),
                OwnedTerm::Atom("killed".into()),
            );
            continue;
        }
        crate::trace::emit_port_event(
            runtime,
            handle.id,
            crate::trace::PORTS,
            "closed",
            &[atom("killed")],
        );
        let scheduler = Arc::clone(&handle.scheduler);
        if let Some(removed) = remove_and_notify(
            runtime,
            handle.id,
            &scheduler,
            handle.owner_pid(),
            atom("killed"),
        ) {
            crate::trace::port_closed(runtime, handle.id);
            if removed.inet {
                crate::inet_drv::detach(&removed);
                crate::inet_udp::detach(&removed);
            }
            release_io(&removed);
        }
    }
}

fn connect(process: &Process, port: Term, pid: Term, notify: Option<Pid>) -> Result<Term, VmError> {
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
    let old_owner = handle.owner_pid();
    handle.links.lock().unwrap().insert(pid);
    *handle.owner.lock().unwrap() = pid;
    let _ = runtime.publish_proc_flag(pid, arinsal_sched::proc_flags::PORTS);
    if notify.is_none()
        && old_owner != pid
        && let Some(pid_term) = pid.to_term()
    {
        crate::trace::emit_port_event(
            runtime,
            id,
            crate::trace::PORTS,
            "getting_linked",
            &[pid_term],
        );
    }
    if notify.is_none()
        && let Some(from) = process.self_pid
        && let Some(target) = pid.to_term()
    {
        let mut heap = VecHeap::new();
        if let Ok(message) = TermBuilder::new(&mut heap).tuple(&[atom("connect"), target]) {
            trace_port_receive_term(process, from, id, message);
        }
    }
    let scheduler = runtime.scheduler()?;
    if let Some(from) = notify.or(process.self_pid) {
        // Port of erts/emulator/beam/io.c:2324-2351 and 3304-3332 (set_port_connected,
        // deliver_result), OTP-29.1.1. `port_connect/2` traces the result but only
        // `! {connect, ...}` queues it.
        connected_message(
            runtime,
            &scheduler,
            from,
            id,
            handle.trace_scope,
            notify.is_some(),
        );
    }
    if notify.is_none()
        && old_owner != pid
        && let Some(port) = Term::port(id)
    {
        crate::trace::emit_external_process_event(
            runtime,
            pid,
            crate::trace::PROCS,
            "getting_linked",
            &[port],
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
    // Port of erts/emulator/beam/io.c:7143 (erts_fire_port_monitor): ports that
    // monitor the exiting process run their driver's `process_exit` callback.
    let fired: Vec<(Arc<arinsal_drv::DriverPort>, u64)> = {
        let ports = runtime.ports.lock().unwrap();
        ports
            .values()
            .flat_map(|handle| {
                let Some(drv_port) = handle.driver.get() else {
                    return Vec::new();
                };
                let mut monitors = handle.drv_monitors.lock().unwrap();
                let ids: Vec<u64> = monitors
                    .iter()
                    .filter(|(_, pid)| **pid == owner)
                    .map(|(id, _)| *id)
                    .collect();
                for id in &ids {
                    monitors.remove(id);
                }
                ids.into_iter()
                    .map(|id| (Arc::clone(drv_port), id))
                    .collect()
            })
            .collect()
    };
    for (drv_port, monitor) in fired {
        drv_port.process_exit(monitor);
    }
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
            .filter_map(|id| {
                let handle = ports.remove(&id)?;
                runtime.port_ids.release(id);
                Some((id, handle))
            })
            .collect::<Vec<_>>()
    };
    for (port_id, handle) in closed {
        crate::trace::emit_port_event(runtime, port_id, crate::trace::PORTS, "closed", &[reason]);
        release_port_name(runtime, &handle);
        crate::trace::port_closed(runtime, port_id);
        if handle.inet {
            crate::inet_drv::detach(&handle);
            crate::inet_udp::detach(&handle);
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
            let reference_term =
                TermBuilder::new(&mut heap).local_ref(arinsal_bifs::ordinary_ref_words(*reference));
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
pub(crate) fn link(process: &Process, port: Term, pid: Pid, linked: bool) -> Result<bool, VmError> {
    let id = port.as_port().ok_or_else(badarg)?;
    let runtime = process.runtime.as_ref().ok_or_else(badarg)?;
    // arl: a link across namespaces is refused as for a dead port.
    if linked && !arl_port_ns_ok(process, id) {
        return Ok(false);
    }
    let Some(handle) = runtime.ports.lock().unwrap().get(&id).cloned() else {
        return Ok(!linked);
    };
    if !linked {
        // The unlinking process traces `unlink` when it sends the signal (bif.c unlink_1).
        crate::trace::emit_external_process_event(
            runtime,
            pid,
            crate::trace::PROCS,
            "unlink",
            &[port],
        );
    }
    if let Some(drv) = handle.driver.get().cloned() {
        return Ok(drv_sig::link(runtime, &handle, &drv, pid, linked) || !linked);
    }
    // Termination removes the port from the table and drains `links` in one critical section
    // of the table lock (`remove_and_notify`); taking the locks in the same order makes this
    // registration either visible to it or refused.
    let ports = runtime.ports.lock().unwrap();
    if linked && !ports.contains_key(&id) {
        return Ok(false);
    }
    let mut links = handle.links.lock().unwrap();
    if linked {
        links.insert(pid);
    } else {
        links.remove(&pid);
    }
    drop(links);
    drop(ports);
    // A linked port is on the process link list. Exit scans ports only when that
    // list is non-empty (erl_process.c:14084, `erts_proc_exit_handle_link`).
    if linked && !runtime.publish_proc_flag(pid, arinsal_sched::proc_flags::PORTS) {
        handle.links.lock().unwrap().remove(&pid);
        return Ok(false);
    }
    if let Some(pid_term) = pid.to_term() {
        crate::trace::emit_port_event(
            runtime,
            id,
            crate::trace::PORTS,
            if linked {
                "getting_linked"
            } else {
                "getting_unlinked"
            },
            &[pid_term],
        );
    }
    Ok(true)
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
    // arl: a monitor across namespaces is refused as for a dead port.
    if monitored && !arl_port_ns_ok(process, id) {
        return Ok(false);
    }
    let handle = process
        .runtime
        .as_ref()
        .and_then(|runtime| runtime.ports.lock().unwrap().get(&id).cloned());
    let Some(handle) = handle else {
        // The port vanished between lookup and registration: the caller sends DOWN noproc.
        return Ok(!monitored);
    };
    if monitored && let Some(drv_port) = handle.driver.get() {
        // Port of erts/emulator/beam/io.c:6787 (erts_port_monitor): the request is a port
        // signal, handled once the callback holding the port lock has returned.
        return drv_port.serialized(|| {
            register_monitor(process, id, &handle, reference, pid, object, monitored)
        });
    }
    register_monitor(process, id, &handle, reference, pid, object, monitored)
}

fn register_monitor(
    process: &Process,
    id: u64,
    handle: &Arc<PortHandle>,
    reference: u64,
    pid: Pid,
    object: OwnedTerm,
    monitored: bool,
) -> Result<bool, VmError> {
    if monitored && handle.state.lock().unwrap().exit_complete {
        return Ok(false);
    }
    // See `link`: same lock order as termination (table, then monitors).
    let ports = process
        .runtime
        .as_ref()
        .map(|runtime| runtime.ports.lock().unwrap());
    if monitored && !ports.as_ref().is_some_and(|ports| ports.contains_key(&id)) {
        return Ok(false);
    }
    let mut monitors = handle.monitors.lock().unwrap();
    if monitored {
        monitors.insert(reference, PortMonitor { pid, object });
        if let Some(runtime) = process.runtime.as_ref() {
            let _ = runtime.publish_proc_flag(pid, arinsal_sched::proc_flags::PORTS);
        }
    } else {
        monitors.remove(&reference);
    }
    Ok(true)
}

/// Ports linked to `pid`, in id order, for `process_info(Pid, links)`.
pub(crate) fn linked_ports(process: &Process, pid: Pid) -> Vec<Term> {
    let Some(runtime) = process.runtime.as_ref() else {
        return Vec::new();
    };
    let mut ids: Vec<u64> = runtime
        .ports
        .lock()
        .unwrap()
        .iter()
        .filter(|(_, handle)| handle.links.lock().unwrap().contains(&pid))
        .map(|(id, _)| *id)
        .collect();
    ids.sort_unstable();
    ids.into_iter().filter_map(Term::port).collect()
}

/// Ports monitoring `pid` through `driver_monitor_process`, for `process_info(Pid, monitored_by)`.
pub(crate) fn driver_monitoring_ports(process: &Process, pid: Pid) -> Vec<Term> {
    let Some(runtime) = process.runtime.as_ref() else {
        return Vec::new();
    };
    let mut ids: Vec<u64> = runtime
        .ports
        .lock()
        .unwrap()
        .iter()
        .filter(|(_, handle)| {
            handle
                .drv_monitors
                .lock()
                .unwrap()
                .values()
                .any(|monitored| *monitored == pid)
        })
        .map(|(id, _)| *id)
        .collect();
    ids.sort_unstable();
    ids.into_iter().filter_map(Term::port).collect()
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

/// Demonitor one port. The caller already removed the origin from its monitor tree.
///
/// Port of erts/emulator/beam/bif.c:504-510 and io.c:2850 (`erts_port_demonitor`),
/// OTP-29.1.1. A loaded driver gets a proc-to-port demonitor signal (immediate when
/// the port is free). A spawn or fd port has no driver task queue; the target half
/// is dropped under the port's monitor lock, which is that port's `try_imm` path.
pub(crate) fn demonitor_port(process: &Process, caller: Pid, port_id: u64, reference: u64) {
    let Some(runtime) = process.runtime.as_ref() else {
        return;
    };
    let handle = runtime.ports.lock().unwrap().get(&port_id).cloned();
    let Some(handle) = handle else {
        // `erts_port_lookup` failed: `ERTS_PORT_OP_DROPPED`, origin already released.
        return;
    };
    if let Some(drv) = handle.driver.get().cloned() {
        drv_sig::demonitor(&handle, &drv, caller, reference);
        return;
    }
    handle.monitors.lock().unwrap().remove(&reference);
}

/// Port of erts/emulator/beam/io.c:1715 (erts_port_output) for `{command, Data}`; also
/// the body of `erts_port_output_async` (`enif_port_command`). Failures signal the port.
fn output_command(
    runtime: &crate::process::Runtime,
    handle: &Arc<PortHandle>,
    id: u64,
    from: Pid,
    data: Term,
    tracer: Option<&Process>,
) {
    if let Some(drv_port) = handle.driver.get() {
        // Port of erts/emulator/beam/io.c:1715 (erts_port_output) for `Port ! {Pid, {command, D}}`.
        let mut pieces = Vec::new();
        if io_pieces(data, &mut pieces).is_none() {
            signal_badsig(handle, id);
            return;
        }
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
        if let Some(process) = tracer {
            trace_command_received(
                process,
                from,
                id,
                &pieces,
                drv_port.outputv_trace_segments(&pieces),
            );
        }
        if !drv_port.output(&pieces, packed_pid(from))
            && runtime.ports.lock().unwrap().contains_key(&id)
        {
            signal_badsig(handle, id);
        }
        return;
    }
    let Some(mut data) = iodata(data) else {
        signal_badsig(handle, id);
        return;
    };
    if let Some(process) = tracer {
        trace_command_received(
            process,
            from,
            id,
            &[arinsal_drv::IoPiece::Copied(&data)],
            None,
        );
    }
    let ram_file = handle.ram_file.lock().unwrap().clone();
    if let Some(ram_file) = ram_file {
        if crate::ram_file_drv::command(&ram_file, handle, &data).is_err() {
            signal_badsig(handle, id);
        }
        return;
    }
    if let Some((2, hdr)) = handle.framing {
        match hdr {
            1 => {
                if data.len() > u8::MAX as usize {
                    signal_port_exit(handle, id, atom("einval"));
                    return;
                }
                data.insert(0, data.len() as u8);
            }
            2 => {
                if data.len() > u16::MAX as usize {
                    signal_port_exit(handle, id, atom("einval"));
                    return;
                }
                data.splice(0..0, (data.len() as u16).to_be_bytes());
            }
            4 => {
                if data.len() > u32::MAX as usize {
                    signal_port_exit(handle, id, atom("einval"));
                    return;
                }
                data.splice(0..0, (data.len() as u32).to_be_bytes());
            }
            _ => {
                signal_badsig(handle, id);
                return;
            }
        }
    }
    if command_bytes(handle, &data).is_err() {
        signal_badsig(handle, id);
    }
}

/// Port of erts/emulator/beam/erl_nif.c:1097 (enif_port_command): `erts_port_output_async`
/// of `data` on behalf of `from`; `false` when the port is gone.
pub(crate) fn nif_port_command(
    runtime: &crate::process::Runtime,
    port: Term,
    from: Pid,
    data: Term,
) -> bool {
    let Some(id) = port.as_port() else {
        return false;
    };
    let Some(handle) = runtime.ports.lock().unwrap().get(&id).cloned() else {
        return false;
    };
    if handle.state.lock().unwrap().exit_complete {
        return false;
    }
    // Port of erts/emulator/beam/io.c:1603-1605 (erts_port_output_async): data that is not
    // iodata is refused (`bad_value`, result 0) without signalling the port.
    if io_pieces(data, &mut Vec::new()).is_none() {
        return false;
    }
    output_command(runtime, &handle, id, from, data, None);
    true
}

pub(crate) fn send_message(
    process: &mut Process,
    port: Term,
    message: Term,
) -> Result<(), VmError> {
    send_message_inner(process, port, message, false, None).map(|_| ())
}

/// Outcome of `Port ! Message` from a process (erts_send to a port, bif.c:2560).
pub(crate) enum PortSend {
    /// Sent or dropped: the send is complete.
    Sent,
    /// Sent, and the sender is now suspended on the busy port (`SEND_YIELD_RETURN`).
    SentSuspended,
    /// Nothing was sent: the port is busy (`SEND_YIELD`). The sender is suspended
    /// unless `nosuspend` was given.
    Busy,
}

/// `Port ! Message` from process code; `nosuspend` is `erlang:send/3` with `[nosuspend]`.
pub(crate) fn send_from_process(
    process: &mut Process,
    port: Term,
    message: Term,
    nosuspend: bool,
    mut ctx: Option<&mut RunCtx<'_, Message>>,
) -> Result<PortSend, VmError> {
    loop {
        match send_message_inner(process, port, message, nosuspend, ctx.as_deref_mut())? {
            (PortSend::Busy, Some((handle, drv))) if !nosuspend => {
                let pid = process.self_pid.ok_or_else(badarg)?;
                if suspend_on_busy(process, &handle, &drv, pid) {
                    return Ok(PortSend::Busy);
                }
            }
            (PortSend::SentSuspended, Some((handle, drv))) => {
                let pid = process.self_pid.ok_or_else(badarg)?;
                if suspend_on_busy(process, &handle, &drv, pid) {
                    return Ok(PortSend::SentSuspended);
                }
                return Ok(PortSend::Sent);
            }
            (outcome, _) => return Ok(outcome),
        }
    }
}

type DrvTarget = Option<(Arc<PortHandle>, Arc<arinsal_drv::DriverPort>)>;

fn send_message_inner(
    process: &mut Process,
    port: Term,
    message: Term,
    nosuspend: bool,
    mut ctx: Option<&mut RunCtx<'_, Message>>,
) -> Result<(PortSend, DrvTarget), VmError> {
    let id = port.as_port().ok_or_else(badarg)?;
    let runtime = process.runtime.as_ref().ok_or_else(badarg)?;
    // A message to a dead local port is dropped (erts_port_command DROPPED).
    let Some(handle) = runtime.ports.lock().unwrap().get(&id).cloned() else {
        return Ok(sent());
    };
    let Some(parts) = tuple(message) else {
        signal_badsig(&handle, id);
        return Ok(sent());
    };
    // Port of erts/emulator/beam/io.c:3991 (erts_port_command): the first element names the
    // connected process (checked per operation), not necessarily the sender.
    let from = if parts.len() == 2 {
        Pid::from_term(parts[0])
    } else {
        None
    };
    let Some(from) = from else {
        signal_badsig(&handle, id);
        return Ok(sent());
    };
    let from_connected = *handle.owner.lock().unwrap() == from;
    let drv = handle.driver.get().cloned();
    if let Some(drv) = &drv
        && (parts[1] == atom("close")
            || tuple(parts[1]).is_some_and(|command| {
                command.len() == 2 && command[0] == atom("connect") && command[1].as_pid().is_some()
            }))
    {
        // Port of erts/emulator/beam/io.c:3975 (erts_port_command): `close` and `connect`
        // are port signals checked against the connected process when they execute.
        let sender = process.self_pid.unwrap_or(from);
        if from_connected {
            trace_port_receive_term(process, from, id, parts[1]);
        }
        if parts[1] == atom("close") {
            let normal = OwnedTerm::Atom("normal".into());
            let _ = drv_sig::exit(
                process,
                ctx.as_deref_mut(),
                sender,
                &handle,
                drv,
                true,
                from,
                normal,
                false,
            );
        } else {
            let command = tuple(parts[1]).unwrap_or_default();
            let pid = Pid::from_term(command[1]).ok_or_else(badarg)?;
            drv_sig::connect(process, sender, &handle, drv, from, pid);
        }
        return Ok(sent());
    }
    if parts[1] == atom("close") {
        if !from_connected {
            signal_badsig(&handle, id);
            return Ok(sent());
        }
        trace_port_receive_term(process, from, id, parts[1]);
        if handle.os_pid == 0 {
            // A port that terminated meanwhile drops the signal.
            event_message(
                &handle.scheduler,
                from,
                id,
                handle.trace_scope,
                atom("closed"),
            );
            if close_inner(process, port, false).is_err() {
                return Ok(sent());
            }
            return Ok(sent());
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
        remove_port(runtime, id);
        if notify_now {
            event_message(
                &handle.scheduler,
                from,
                id,
                handle.trace_scope,
                atom("closed"),
            );
        } else {
            poke(&handle);
        }
        return Ok(sent());
    }
    let Some(command) = tuple(parts[1]) else {
        signal_badsig(&handle, id);
        return Ok(sent());
    };
    if command.len() == 2 && command[0] == atom("command") && !from_connected && drv.is_none() {
        // io.c:1887 (erts_port_output, bang op): only the connected process may command.
        signal_badsig(&handle, id);
        return Ok(sent());
    }
    if command.len() == 2
        && command[0] == atom("command")
        && let Some(drv_port) = drv
    {
        // Port of erts/emulator/beam/io.c:1715 (erts_port_output) for `Port ! {Pid, {command, D}}`.
        let flags = drv_sig::OutputFlags {
            bang: true,
            nosuspend,
            force: false,
        };
        let sender = process.self_pid.unwrap_or(from);
        return Ok(
            match drv_sig::output(
                process, ctx, sender, &handle, &drv_port, from, command[1], flags, false,
            ) {
                drv_sig::PortOp::Busy => (PortSend::Busy, Some((handle, drv_port))),
                drv_sig::PortOp::BusyScheduled(_) => {
                    (PortSend::SentSuspended, Some((handle, drv_port)))
                }
                _ => sent(),
            },
        );
    }
    if command.len() == 2 && command[0] == atom("command") {
        output_command(runtime, &handle, id, from, command[1], Some(process));
        return Ok(sent());
    }
    if command.len() == 2 && command[0] == atom("connect") {
        if !from_connected || command[1].as_pid().is_none() {
            signal_badsig(&handle, id);
            return Ok(sent());
        }
        trace_port_receive_term(process, from, id, parts[1]);
        if connect(process, port, command[1], Some(from)).is_err()
            && runtime.ports.lock().unwrap().contains_key(&id)
        {
            signal_badsig(&handle, id);
        }
        return Ok(sent());
    }
    signal_badsig(&handle, id);
    Ok(sent())
}

fn sent() -> (PortSend, DrvTarget) {
    (PortSend::Sent, None)
}

/// Send an ETF encoded trace event through the tracer port's command channel.
// Port of erts/emulator/nifs/common/erl_tracer_nif.c:251-260 (enif_port_command), OTP-29.1.1.
pub(crate) fn trace_command(process: &mut Process, port: Term, event: Term) -> Result<(), VmError> {
    let id = port.as_port().ok_or_else(badarg)?;
    let owner = process
        .runtime
        .as_ref()
        .and_then(|runtime| runtime.ports.lock().unwrap().get(&id).cloned())
        .map(|handle| handle.owner_pid())
        .ok_or_else(badarg)?;
    let encoded = {
        let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
        let mut ctx = arinsal_bifs::Ctx::with_fcalls(&mut heap, &mut process.reductions);
        let encode = arinsal_bifs::lookup("erlang", "term_to_binary", 1).ok_or_else(badarg)?;
        encode(&mut ctx, &[event]).map_err(|_| badarg())?
    };
    let command = {
        let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
        TermBuilder::new(&mut heap)
            .tuple(&[atom("command"), encoded])
            .map_err(|_| badarg())?
    };
    let envelope = {
        let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
        TermBuilder::new(&mut heap)
            .tuple(&[owner.to_term().ok_or_else(badarg)?, command])
            .map_err(|_| badarg())?
    };
    send_message(process, port, envelope)
}

fn ports(_vm: &mut Vm, process: &mut Process) -> Result<Term, VmError> {
    // Port of erts/emulator/beam/bif.c:4125 (ports/0), OTP-29.1.1.
    // The forker is port zero and exists even when no user port is open.
    // arl: port zero (the forker) is root's; a namespace sees only its own ports.
    let mut values = if process.ns == 0 {
        vec![Term::port(0).expect("standard I/O port tag")]
    } else {
        Vec::new()
    };
    if let Some(runtime) = &process.runtime {
        values.extend(
            runtime
                .ports
                .lock()
                .unwrap()
                .iter()
                .filter(|(id, handle)| {
                    **id != 0 && (process.ns == 0 || handle.arl_ns == process.ns)
                })
                .filter_map(|(id, _)| Term::port(*id)),
        );
    }
    let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
    TermBuilder::new(&mut heap)
        .list_from_iter(values)
        .map_err(|e| VmError::Unsupported(format!("ports list: {e:?}")))
}
/// `port_info` of port zero, the forker driver's port.
// Port of erts/emulator/beam/io.c (port_info) for the port erts creates in
// erts/emulator/sys/unix/sys_drivers.c:291 (forker_init), OTP-29.1.1.
fn forker_port_info(process: &mut Process, item: Option<Term>) -> Result<Term, VmError> {
    let mut heap = crate::ProcessHeapHandle(&mut process.heap);
    let name = TermBuilder::new(&mut heap)
        .string_to_list("forker")
        .map_err(|e| VmError::Unsupported(format!("port info name: {e:?}")))?;
    let connected = Pid::from_data(0).to_term().ok_or_else(badarg)?;
    let zero = Term::small(0).unwrap();
    let fields = [
        ("name", name),
        ("links", Term::NIL),
        ("id", zero),
        ("connected", connected),
        ("input", zero),
        ("output", zero),
        ("os_pid", atom("undefined")),
        ("monitors", Term::NIL),
        ("monitored_by", Term::NIL),
        ("memory", zero),
        ("queue_size", zero),
        ("locking", atom("driver_level")),
        ("parallelism", atom("false")),
    ];
    if let Some(item) = item {
        let key = global_atoms()
            .text(item.as_atom().ok_or_else(badarg)?)
            .ok_or_else(badarg)?;
        if key == "registered_name" {
            return Ok(Term::NIL);
        }
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
            TermBuilder::new(&mut heap)
                .tuple(&[atom(key), value])
                .map_err(|e| VmError::Unsupported(format!("port info: {e:?}")))
        })
        .collect::<Result<_, _>>()?;
    TermBuilder::new(&mut heap)
        .list_from_iter(tuples)
        .map_err(|e| VmError::Unsupported(format!("port info: {e:?}")))
}

fn port_info(process: &mut Process, port: Term, item: Option<Term>) -> Result<Term, VmError> {
    let id = port.as_port().ok_or_else(badarg)?;
    let Some(handle) = process
        .runtime
        .as_ref()
        .and_then(|r| r.ports.lock().unwrap().get(&id).cloned())
    else {
        // The forker is port zero and has no handle here (see `ports`).
        return if id == 0 {
            forker_port_info(process, item)
        } else {
            Ok(atom("undefined"))
        };
    };
    let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
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
    let drv_port = handle.driver.get();
    let process_monitors = drv_port
        .map(|drv| drv.monitored())
        .unwrap_or_default()
        .into_iter()
        .map(|data| {
            let pid = Pid::from_data(data).to_term().ok_or_else(badarg)?;
            TermBuilder::new(&mut heap)
                .tuple(&[atom("process"), pid])
                .map_err(|e| VmError::Unsupported(format!("port info monitors: {e:?}")))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let monitors = TermBuilder::new(&mut heap)
        .list_from_iter(process_monitors)
        .map_err(|e| VmError::Unsupported(format!("port info monitors: {e:?}")))?;
    let memory = 48 + monitored_pids.len() * 24;
    let queue_size = drv_port.map_or_else(
        || handle.state.lock().unwrap().outq.len(),
        |drv| drv.queue_size(),
    );
    // Port of erts/emulator/beam/io.c (port_info os_pid): a driver that never
    // called `erl_drv_set_os_pid` reports `undefined`.
    let os_pid = match drv_port.map(|drv| drv.os_pid()) {
        Some(pid) if pid < 0 => atom("undefined"),
        Some(pid) => Term::small(pid).unwrap(),
        None => Term::small(handle.os_pid as i64).unwrap(),
    };
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
        ("os_pid", os_pid),
        ("monitors", monitors),
        ("monitored_by", monitored_by),
        ("memory", Term::small(memory as i64).unwrap()),
        ("queue_size", Term::small(queue_size as i64).unwrap()),
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

/// arl: whether `process` may act on port `id`: root always, a namespace only on its own
/// ports. A port that does not exist is left to the ordinary path; port zero is root's.
fn arl_port_ns_ok(process: &Process, id: u64) -> bool {
    if process.ns == 0 {
        return true;
    }
    if id == 0 {
        return false;
    }
    process
        .runtime
        .as_ref()
        .and_then(|runtime| runtime.ports.lock().unwrap().get(&id).map(|h| h.arl_ns))
        .is_none_or(|ns| ns == process.ns)
}

/// arl: the inet socket drivers `gen_tcp`, `gen_udp` and `gen_sctp` open.
const ARL_NS_DRIVERS: &[&str] = &["tcp_inet", "udp_inet", "sctp_inet"];

/// arl: whether a process of a namespace may open the port described by `spec`.
fn arl_ns_may_open(spec: &[Term]) -> bool {
    let [kind, cmd] = spec else {
        return false;
    };
    if *kind != atom("spawn_driver") {
        return false;
    }
    let name = match cmd.as_atom() {
        Some(name) => global_atoms().text(name).map(|text| text.to_string()),
        None => bytes(*cmd).and_then(|raw| String::from_utf8(raw).ok()),
    };
    name.is_some_and(|name| ARL_NS_DRIVERS.contains(&name.as_str()))
}

/// arl: the port natives of a namespace process. `None` lets the call through. A call on a
/// port of another namespace answers like a missing port (`badarg`), and `port_connect`
/// refuses a new owner of another namespace.
fn arl_port_guard(
    process: &Process,
    module: &str,
    function: &str,
    args: &[Term],
) -> Option<Result<Term, VmError>> {
    let port_arg = matches!(
        function,
        "port_command"
            | "port_close"
            | "port_connect"
            | "port_control"
            | "port_call"
            | "port_info"
            | "port_get_data"
            | "port_set_data"
    );
    if !port_arg {
        return None;
    }
    let refuse = || {
        if module == "erlang" {
            Err(badarg())
        } else {
            Ok(atom("badarg"))
        }
    };
    let id = args.first().and_then(|port| port.as_port())?;
    if !arl_port_ns_ok(process, id) {
        return Some(if function == "port_info" {
            Ok(atom("undefined"))
        } else {
            refuse()
        });
    }
    if function == "port_connect"
        && let Some(pid) = args.get(1).and_then(|pid| Pid::from_term(*pid))
    {
        let foreign = process
            .runtime
            .as_ref()
            .and_then(|runtime| runtime.scheduler().ok())
            .and_then(|scheduler| scheduler.ns_word(pid))
            .is_some_and(|word| word & arinsal_sched::NS_ID_MASK != process.ns);
        if foreign {
            return Some(refuse());
        }
    }
    None
}
