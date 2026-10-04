//! Process and message tracing for ERTS trace sessions.

use crate::{Process, Vm, VmError, process::Message};
use arinsal_etf::OwnedTerm;
use arinsal_sched::{Pid, RunCtx};
use arinsal_term::{Term, TermBuilder, VecHeap, copy_term, from_owned, global_atoms, to_owned};
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

pub(crate) const SEND: u64 = 1 << 4;
pub(crate) const RECEIVE: u64 = 1 << 5;
pub(crate) const SET_ON_SPAWN: u64 = 1 << 6;
pub(crate) const SET_ON_FIRST_SPAWN: u64 = 1 << 7;
pub(crate) const SET_ON_LINK: u64 = 1 << 8;
pub(crate) const PROCS: u64 = 1 << 11;
pub(crate) const RUNNING: u64 = 1 << 13;
pub(crate) const GC: u64 = 1 << 14;
pub(crate) const TIMESTAMP: u64 = 1;
pub(crate) const STRICT_MONOTONIC_TIMESTAMP: u64 = 2;
pub(crate) const MONOTONIC_TIMESTAMP: u64 = 4;
pub(crate) const CALL: u64 = 1 << 10;
pub(crate) const ARITY: u64 = 1 << 15;
pub(crate) const RETURN_TO: u64 = 1 << 16;
pub(crate) const SILENT: u64 = 1 << 17;
pub(crate) const FIRST_LINK: u64 = 1 << 9;
pub(crate) const GARBAGE_COLLECTION: u64 = 1 << 14;
pub(crate) const RUNNING_PORTS: u64 = 1 << 20;
pub(crate) const RUNNING_PROCS: u64 = 1 << 21;
pub(crate) const PORTS: u64 = 1 << 22;
pub(crate) const SCHEDULER_ID: u64 = 1 << 23;
pub(crate) const EXITING: u64 = 1 << 24;

#[derive(Clone)]
struct Entry {
    flags: u64,
    tracer: Tracer,
}

#[derive(Clone, Default)]
pub(crate) enum Tracer {
    #[default]
    Default,
    Pid(Pid),
    Port(u64),
    /// `instance` is the module code whose NIFs were bound when the tracer was set; once the
    /// module is deleted, purged or reloaded the tracer is gone (erts_tracer_nif_clear).
    Module {
        module: String,
        state: OwnedTerm,
        instance: std::sync::Arc<arinsal_loader::Module>,
    },
}

type TraceTable = HashMap<(usize, u64, Pid), Entry, crate::trace_bp::FastHash>;

type PortTraceTable = HashMap<(usize, u64, u64), Entry>;

struct TraceEvent<'a> {
    flags: u64,
    tracee: Term,
    name: &'a str,
    fields: &'a [Term],
    extra: Option<Term>,
}

struct CallEvent<'a> {
    pid: Pid,
    module: &'a str,
    function: &'a str,
    args: &'a [Term],
    flags: u64,
    extra: Option<Term>,
    actions: (bool, bool),
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct CallActions {
    /// Session id, or the id of a meta tracer (`trace_bp::is_meta_id`).
    pub(crate) session: u64,
    pub(crate) return_trace: bool,
    pub(crate) exception_trace: bool,
    pub(crate) return_to: bool,
    /// A `call_time`/`call_memory` return frame.
    pub(crate) acc: Option<CallAcc>,
}

/// Port of erts/emulator/beam/beam_bp.c:1126-1150 (the call acc trace frame), OTP-29.1.1.
#[derive(Clone, Copy, Debug)]
pub(crate) struct CallAcc {
    /// `BPF_TIME_TRACE_ACTIVE` and `BPF_MEM_TRACE_ACTIVE` bits of the breakpoint.
    pub(crate) flags: u32,
    /// The function the process was accounted to before this call (`trace_bp::func_id`).
    pub(crate) prev: Option<u32>,
}

/// Return actions recorded for a native entry frame.
#[derive(Clone, Copy, Debug)]
pub(crate) struct NativeTraceAction {
    pub(crate) session: u64,
    pub(crate) return_trace: bool,
    pub(crate) exception_trace: bool,
    pub(crate) return_to: bool,
    pub(crate) acc: Option<CallAcc>,
}

impl NativeTraceAction {
    /// The flags word of the action in a native trace frame: bit 0 return_trace, 1
    /// exception_trace, 2 return_to, 3 call time/memory frame with its breakpoint flags from
    /// bit 4 and the previous function id plus one from bit 16.
    fn flags_word(&self) -> i64 {
        let mut flags = i64::from(self.return_trace)
            | (i64::from(self.exception_trace) << 1)
            | (i64::from(self.return_to) << 2);
        if let Some(acc) = self.acc {
            flags |= 8
                | (i64::from(acc.flags) << 4)
                | (acc.prev.map_or(0, |prev| i64::from(prev) + 1) << 16);
        }
        flags
    }

    fn from_words(session: i64, flags: i64) -> Self {
        Self {
            session: session as u64,
            return_trace: flags & 1 != 0,
            exception_trace: flags & 2 != 0,
            return_to: flags & 4 != 0,
            acc: (flags & 8 != 0).then(|| CallAcc {
                flags: ((flags >> 4) & 0xFFF) as u32,
                prev: match flags >> 16 {
                    0 => None,
                    prev => Some(prev as u32 - 1),
                },
            }),
        }
    }
}

/// The traced function's pc and the actions of the native trace frame whose function pc word
/// is at stack index `pc_index` (the frame starts two words earlier), with the frame's size.
pub(crate) fn native_frame_actions(
    process: &Process,
    pc_index: usize,
) -> (usize, Vec<NativeTraceAction>, usize) {
    let function_pc = process
        .heap
        .stack_get(pc_index)
        .and_then(Term::as_small)
        .unwrap_or(0) as usize;
    let count = process
        .heap
        .stack_get(pc_index + 1)
        .and_then(Term::as_small)
        .and_then(|count| usize::try_from(count).ok())
        .unwrap_or(0);
    let actions = (0..count)
        .filter_map(|action| {
            let session = process
                .heap
                .stack_get(pc_index + 2 + action * 2)?
                .as_small()?;
            let flags = process
                .heap
                .stack_get(pc_index + 3 + action * 2)?
                .as_small()?;
            Some(NativeTraceAction::from_words(session, flags))
        })
        .collect();
    (function_pc, actions, 4 + count * 2)
}

struct CallMatchContext {
    /// `{message, Term}` result, copied out of the match program's scratch heap, which dies
    /// when the program run returns.
    message: RefCell<Option<(VecHeap, Term)>>,
    /// `print_process_info` text, captured before the program runs when it uses
    /// `{process_dump}`, and the heaps holding binaries built from it.
    dump: Option<Vec<u8>>,
    dump_heaps: RefCell<Vec<VecHeap>>,
    /// `{silent, Bool}` ran: the new silent state of the process in the session.
    silent: Cell<Option<bool>>,
    return_trace: Cell<bool>,
    exception_trace: Cell<bool>,
    trace_control_word: Cell<i64>,
    caller: Option<Term>,
    caller_line: Option<Term>,
    current_stacktraces: Vec<(VecHeap, Term)>,
    trace_actions: RefCell<Vec<(String, VecHeap, Vec<Term>)>>,
}

impl CallMatchContext {
    fn new(
        caller: Option<Term>,
        caller_line: Option<Term>,
        current_stacktraces: Vec<(VecHeap, Term)>,
        dump: Option<Vec<u8>>,
        trace_control_word: i64,
    ) -> Self {
        Self {
            message: RefCell::new(None),
            silent: Cell::new(None),
            return_trace: Cell::new(false),
            exception_trace: Cell::new(false),
            trace_control_word: Cell::new(trace_control_word),
            caller,
            caller_line,
            current_stacktraces,
            trace_actions: RefCell::new(Vec::new()),
            dump,
            dump_heaps: RefCell::new(Vec::new()),
        }
    }

    /// Copy the `{message, Term}` result into the tracee heap.
    // Port of erts/emulator/beam/erl_db_util.c:2452-2460 (matchPushC with ERTS_PAM_COPY_RESULT:
    // trace results live on the tracee heap), OTP-29.1.1.
    fn take_message(&self, process: &mut Process) -> Option<Term> {
        let (_heap, term) = self.message.borrow_mut().take()?;
        copy_term(term, &mut arinsal_bifs::FragmentingHeap(&mut process.heap)).ok()
    }

    fn take_trace_actions(&self) -> Vec<(String, VecHeap, Vec<Term>)> {
        std::mem::take(&mut *self.trace_actions.borrow_mut())
    }
}

impl arinsal_ets::match_spec::MatchContext for CallMatchContext {
    fn trace_control_word(&self) -> Option<Term> {
        Term::small(self.trace_control_word.get())
    }

    fn trace_operation(
        &self,
        name: &str,
        arguments: &[Term],
    ) -> Result<Term, arinsal_ets::EtsError> {
        match name {
            "message" => {
                let value = *arguments.first().ok_or(arinsal_ets::EtsError::BadArg)?;
                // Port of erts/emulator/beam/erl_db_util.c:1622-1626 and :4857-4893,
                // OTP-29.1.1: `message` returns its value to the match runner, while `true`
                // means no extra trace payload. Later message actions replace earlier ones.
                if value == crate::signals::atom("true") {
                    *self.message.borrow_mut() = None;
                    return Ok(value);
                }
                let mut heap = VecHeap::new();
                let copy = copy_term(value, &mut heap)?;
                *self.message.borrow_mut() = Some((heap, copy));
                Ok(value)
            }
            "set_tcw" => {
                let value = arguments
                    .first()
                    .and_then(|value| value.as_small())
                    .ok_or(arinsal_ets::EtsError::BadArg)?;
                let previous = self.trace_control_word.get();
                self.trace_control_word.set(value);
                Term::small(previous).ok_or(arinsal_ets::EtsError::BadArg)
            }
            "silent" => {
                match arguments.first().copied() {
                    Some(value) if value == crate::signals::atom("true") => {
                        self.silent.set(Some(true));
                    }
                    Some(value) if value == crate::signals::atom("false") => {
                        self.silent.set(Some(false));
                    }
                    _ => {}
                }
                Ok(crate::signals::atom("true"))
            }
            "display" => {
                // Port of erts/emulator/beam/erl_db_util.c:5091-5115 (dmc_display and
                // matchDisplay), OTP-29.1.1.
                let value = *arguments.first().ok_or(arinsal_ets::EtsError::BadArg)?;
                crate::natives::sys::display_match_spec(value)
                    .map_err(|_| arinsal_ets::EtsError::Unsupported("match-spec display"))?;
                Ok(crate::signals::atom("true"))
            }
            "enable_trace" | "disable_trace" | "trace" => {
                let mut heap = VecHeap::new();
                let copied = arguments
                    .iter()
                    .map(|&argument| copy_term(argument, &mut heap))
                    .collect::<Result<Vec<_>, _>>()?;
                self.trace_actions
                    .borrow_mut()
                    .push((name.to_owned(), heap, copied));
                Ok(crate::signals::atom("true"))
            }
            "caller" => Ok(self
                .caller
                .unwrap_or_else(|| crate::signals::atom("undefined"))),
            "caller_line" => Ok(self
                .caller_line
                .unwrap_or_else(|| crate::signals::atom("undefined"))),
            "current_stacktrace" => {
                let depth = arguments
                    .first()
                    .and_then(|value| value.as_small())
                    .and_then(|depth| usize::try_from(depth).ok())
                    .unwrap_or_else(|| self.current_stacktraces.len().saturating_sub(1));
                self.current_stacktraces
                    .get(depth.min(self.current_stacktraces.len().saturating_sub(1)))
                    .map(|(_, term)| *term)
                    .ok_or(arinsal_ets::EtsError::Unsupported(
                        "current stacktrace context",
                    ))
            }
            "return_trace" => {
                self.return_trace.set(true);
                Ok(crate::signals::atom("true"))
            }
            "exception_trace" => {
                self.exception_trace.set(true);
                Ok(crate::signals::atom("true"))
            }
            "process_dump" => {
                let dump = self
                    .dump
                    .as_deref()
                    .ok_or(arinsal_ets::EtsError::Unsupported(
                        "process_dump outside a process",
                    ))?;
                let mut heap = VecHeap::new();
                let binary = TermBuilder::new(&mut heap).binary(dump)?;
                self.dump_heaps.borrow_mut().push(heap);
                Ok(binary)
            }
            _ => Err(arinsal_ets::EtsError::Unsupported(
                "trace match specification operation",
            )),
        }
    }
}

/// The trace table: calls only read it, trace flag changes write it.
struct TraceTableLock(std::sync::RwLock<TraceTable>);

impl TraceTableLock {
    /// Exclusive access (the name keeps the call sites of the former mutex).
    fn lock(&self) -> std::sync::LockResult<std::sync::RwLockWriteGuard<'_, TraceTable>> {
        self.0.write()
    }

    fn read(&self) -> std::sync::LockResult<std::sync::RwLockReadGuard<'_, TraceTable>> {
        self.0.read()
    }
}

fn table() -> &'static TraceTableLock {
    static TABLE: OnceLock<TraceTableLock> = OnceLock::new();
    TABLE.get_or_init(|| TraceTableLock(std::sync::RwLock::new(HashMap::default())))
}

fn port_table() -> &'static Mutex<PortTraceTable> {
    static TABLE: OnceLock<Mutex<PortTraceTable>> = OnceLock::new();
    TABLE.get_or_init(|| Mutex::new(HashMap::new()))
}

type NewPortTracing = Mutex<HashMap<(usize, u64), (u64, Option<Tracer>)>>;

fn new_port_tracing() -> &'static NewPortTracing {
    static TRACING: OnceLock<NewPortTracing> = OnceLock::new();
    TRACING.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Pids of processes with `process_flag(sensitive, true)` (erts `F_SENSITIVE`).
fn sensitive_set() -> &'static Mutex<std::collections::HashSet<(usize, Pid)>> {
    static SET: OnceLock<Mutex<std::collections::HashSet<(usize, Pid)>>> = OnceLock::new();
    SET.get_or_init(Default::default)
}

static SENSITIVE_COUNT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Sets or clears the sensitive flag of `pid`; returns the previous value.
// Port of erts/emulator/beam/bif.c:2173 (process_flag sensitive), OTP-29.1.1.
pub(crate) fn set_sensitive(process: &Process, pid: Pid, on: bool) -> bool {
    let mut set = sensitive_set().lock().unwrap();
    let key = (scope(process), pid);
    let old = if on {
        !set.insert(key)
    } else {
        set.remove(&key)
    };
    SENSITIVE_COUNT.store(set.len(), Ordering::Relaxed);
    old
}

/// Whether `pid` is sensitive (`ERTS_IS_PROC_SENSITIVE`).
pub(crate) fn is_sensitive(process: &Process, pid: Pid) -> bool {
    SENSITIVE_COUNT.load(Ordering::Relaxed) != 0
        && sensitive_set()
            .lock()
            .unwrap()
            .contains(&(scope(process), pid))
}

/// One entry of a process's `save_calls` buffer.
// Port of erts/emulator/beam/erl_trace.c:70 (exp_send, exp_receive, exp_timeout), OTP-29.1.1.
#[derive(Clone, Copy)]
pub(crate) enum SavedCall {
    Mfa(arinsal_term::Atom, arinsal_term::Atom, u8),
    Send,
    Receive,
    Timeout,
}

/// The circular `save_calls` buffer (`struct saved_calls`).
pub(crate) struct SavedCalls {
    len: usize,
    cur: usize,
    n: usize,
    ct: Vec<Option<SavedCall>>,
}

/// Whether `process` has a `save_calls` buffer (`ERTS_PROC_GET_SAVED_CALLS_BUF`).
#[inline(always)]
pub(crate) fn saves_calls(process: &Process) -> bool {
    process
        .cold
        .as_ref()
        .is_some_and(|cold| cold.saved_calls.is_some())
}

/// Replaces the `save_calls` buffer of `process` and returns the old length.
// Port of erts/emulator/beam/bif.c:1907-1950 (process_flag save_calls), OTP-29.1.1.
pub(crate) fn set_save_calls(process: &mut Process, len: usize) -> usize {
    let new = (len != 0).then(|| SavedCalls {
        len,
        cur: 0,
        n: 0,
        ct: vec![None; len],
    });
    let cold = process.cold_mut();
    let old = std::mem::replace(&mut cold.saved_calls, new);
    let was = old.as_ref().map_or(0, |scb| scb.len);
    if (was != 0) != (len != 0) {
        // ERTS_VBUMP_ALL_REDS: reschedule at once so native code runs with the code index
        // that matches the new setting (ERTS_SAVE_CALLS_CODE_IX or the active one).
        process.reductions = 0;
        process.force_yield = true;
    }
    was
}

/// Drops the buffer of an exiting process.
pub(crate) fn clear_save_calls(process: &mut Process) {
    if let Some(cold) = process.cold.as_mut() {
        cold.saved_calls = None;
    }
}

/// Records a call in the buffer of `process`, unless it is sensitive.
// Port of erts/emulator/beam/erl_trace.c:1409 (save_calls), OTP-29.1.1.
pub(crate) fn save_call(process: &mut Process, call: SavedCall) {
    if process
        .self_pid
        .is_some_and(|pid| is_sensitive(process, pid))
    {
        return;
    }
    let Some(scb) = process
        .cold
        .as_mut()
        .and_then(|cold| cold.saved_calls.as_mut())
    else {
        return;
    };
    scb.ct[scb.cur] = Some(call);
    scb.cur += 1;
    if scb.cur >= scb.len {
        scb.cur = 0;
    }
    if scb.n < scb.len {
        scb.n += 1;
    }
}

/// Saved calls, newest first.
pub(crate) fn saved_calls(process: &Process) -> Option<Vec<SavedCall>> {
    let scb = process.cold.as_ref()?.saved_calls.as_ref()?;
    Some(
        (0..scb.n)
            .filter_map(|i| {
                let j = (scb.cur + scb.len - i - 1) % scb.len;
                scb.ct[j]
            })
            .collect(),
    )
}

/// Records the `erlang:send/2` export a process saving calls dispatches `send` through.
// Port of erts/emulator/beam/jit/arm/instr_bif.cpp:612-625 (emit_send dispatches through
// BIF_TRAP_EXPORT(BIF_send_2)), OTP-29.1.1.
pub(crate) fn save_call_send_export(process: &mut Process) {
    let atoms = arinsal_term::global_atoms();
    if let (Ok(m), Ok(f)) = (atoms.intern("erlang"), atoms.intern("send")) {
        save_call(process, SavedCall::Mfa(m, f, 2));
    }
}

/// Whether any process is traced at all.
pub(crate) fn active() -> bool {
    enabled().load(Ordering::Relaxed)
}

fn enabled() -> &'static AtomicBool {
    static ENABLED: AtomicBool = AtomicBool::new(false);
    &ENABLED
}

#[derive(Clone)]
struct TraceSession {
    tracer: Tracer,
    name: String,
    weak_id: i64,
}

struct TraceSessionHandle {
    owner: usize,
    session: u64,
}

// Port of erts/emulator/beam/erl_bif_trace.c:1188-1213 (tracer_session_destructor), OTP-29.1.1.
impl Drop for TraceSessionHandle {
    fn drop(&mut self) {
        session_handle_ids()
            .lock()
            .unwrap()
            .retain(|(owner, _), session| *owner != self.owner || *session != self.session);
        destroy_session_key(self.owner, self.session);
        crate::trace_bp::clear_session_scope(self.owner, self.session);
    }
}

fn session_handle_ids() -> &'static Mutex<HashMap<(usize, u64), u64>> {
    static IDS: OnceLock<Mutex<HashMap<(usize, u64), u64>>> = OnceLock::new();
    IDS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn sessions() -> &'static Mutex<HashMap<(usize, u64), TraceSession>> {
    static SESSIONS: OnceLock<Mutex<HashMap<(usize, u64), TraceSession>>> = OnceLock::new();
    SESSIONS.get_or_init(|| Mutex::new(HashMap::new()))
}

type NewProcessTracing = Mutex<HashMap<(usize, u64), (u64, Option<Tracer>)>>;

fn new_process_tracing() -> &'static NewProcessTracing {
    static TRACING: OnceLock<NewProcessTracing> = OnceLock::new();
    TRACING.get_or_init(|| Mutex::new(HashMap::new()))
}

#[derive(Clone)]
struct EventPattern {
    enabled: bool,
    match_spec: Option<OwnedTerm>,
}

type EventPatterns = Mutex<HashMap<(usize, u64, &'static str), EventPattern>>;

fn event_patterns() -> &'static EventPatterns {
    static EVENTS: OnceLock<EventPatterns> = OnceLock::new();
    EVENTS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn scope(process: &Process) -> usize {
    process
        .runtime
        .as_ref()
        .map_or(0, |runtime| std::sync::Arc::as_ptr(runtime) as usize)
}

fn scope_runtime(runtime: &crate::process::Runtime) -> usize {
    runtime as *const crate::process::Runtime as usize
}

#[cfg(test)]
pub(crate) fn configure(
    process: &Process,
    pid: Pid,
    how_on: bool,
    flags: u64,
    tracer: Tracer,
) -> u64 {
    configure_session(process, 0, pid, how_on, flags, tracer)
}

pub(crate) fn configure_session(
    process: &Process,
    session: u64,
    pid: Pid,
    how_on: bool,
    flags: u64,
    tracer: Tracer,
) -> u64 {
    let mut table = table().lock().unwrap();
    let entry = table
        .entry((scope(process), session, pid))
        .or_insert(Entry {
            flags: 0,
            tracer: tracer.clone(),
        });
    let before = entry.flags;
    if how_on {
        entry.flags |= flags;
        entry.tracer = tracer.clone();
    } else {
        entry.flags &= !flags;
    }
    if entry.flags == 0 {
        table.remove(&(scope(process), session, pid));
    }
    enabled().store(
        !table.is_empty() || !port_table().lock().unwrap().is_empty(),
        Ordering::Relaxed,
    );
    before
}

/// Configure flags on a port in one trace session.
// Port of erts/emulator/beam/erl_bif_trace.c:826-888 (start_trace port ref), OTP-29.1.1.
pub(crate) fn configure_port(
    process: &Process,
    session: u64,
    port: u64,
    how_on: bool,
    flags: u64,
    tracer: Tracer,
) -> u64 {
    let key = (scope(process), session, port);
    let mut port_entries = port_table().lock().unwrap();
    let entry = port_entries.entry(key).or_insert(Entry {
        flags: 0,
        tracer: tracer.clone(),
    });
    let before = entry.flags;
    if how_on {
        entry.flags |= flags;
        entry.tracer = tracer;
    } else {
        entry.flags &= !flags;
    }
    if entry.flags == 0 {
        port_entries.remove(&key);
    }
    enabled().store(
        !port_entries.is_empty() || !table().lock().unwrap().is_empty(),
        Ordering::Relaxed,
    );
    before
}

pub(crate) fn configure_new_ports(
    process: &Process,
    session: u64,
    how_on: bool,
    flags: u64,
    tracer: Tracer,
) {
    let key = (scope(process), session);
    let mut tracing = new_port_tracing().lock().unwrap();
    let (current, current_tracer) = tracing.entry(key).or_default();
    if how_on {
        *current |= flags;
        *current_tracer = Some(tracer);
    } else {
        *current &= !flags;
        if *current == 0 {
            *current_tracer = None;
        }
    }
    if *current == 0 {
        tracing.remove(&key);
    }
}

/// Apply the session defaults to a newly registered port.
// Port of erts/emulator/beam/erl_trace.c:615-639 (new port trace flags), OTP-29.1.1.
pub(crate) fn port_opened(runtime: &crate::process::Runtime, port: u64) {
    let owner = runtime as *const crate::process::Runtime as usize;
    let defaults = new_port_tracing()
        .lock()
        .unwrap()
        .iter()
        .filter(|((scope, _), (flags, _))| *scope == owner && *flags != 0)
        .map(|((_, session), (flags, tracer))| {
            (*session, *flags, tracer.clone().unwrap_or(Tracer::Default))
        })
        .collect::<Vec<_>>();
    let mut entries = port_table().lock().unwrap();
    for (session, flags, tracer) in defaults {
        entries.insert((owner, session, port), Entry { flags, tracer });
    }
    if !entries.is_empty() {
        enabled().store(true, Ordering::Relaxed);
    }
}

pub(crate) fn port_closed(runtime: &crate::process::Runtime, port: u64) {
    let owner = runtime as *const crate::process::Runtime as usize;
    table().lock().unwrap().retain(|(scope, _, _), entry| {
        *scope != owner || !matches!(entry.tracer, Tracer::Port(tracer) if tracer == port)
    });
    let mut new_processes = new_process_tracing().lock().unwrap();
    new_processes.retain(|(scope, _), (flags, tracer)| {
        if *scope == owner && matches!(tracer, Some(Tracer::Port(tracer)) if *tracer == port) {
            *flags = 0;
            *tracer = None;
        }
        *scope != owner || *flags != 0
    });
    let mut entries = port_table().lock().unwrap();
    entries.retain(|(scope, _, id), entry| {
        *scope != owner
            || (*id != port && !matches!(entry.tracer, Tracer::Port(tracer) if tracer == port))
    });
    drop(entries);
    let mut defaults = new_port_tracing().lock().unwrap();
    defaults.retain(|(scope, _), (flags, tracer)| {
        if *scope == owner && matches!(tracer, Some(Tracer::Port(tracer)) if *tracer == port) {
            *flags = 0;
            *tracer = None;
        }
        *scope != owner || *flags != 0
    });
    enabled().store(
        !port_table().lock().unwrap().is_empty() || !table().lock().unwrap().is_empty(),
        Ordering::Relaxed,
    );
}

pub(crate) fn port_flags(process: &Process, session: u64, port: u64) -> u64 {
    port_table()
        .lock()
        .unwrap()
        .get(&(scope(process), session, port))
        .map_or(0, |entry| entry.flags)
}

pub(crate) fn port_tracer(process: &Process, session: u64, port: u64) -> Option<Tracer> {
    port_table()
        .lock()
        .unwrap()
        .get(&(scope(process), session, port))
        .map(|entry| entry.tracer.clone())
}

/// Emit a port event to its configured trace-session destinations.
// Port of erts/emulator/beam/erl_trace.c:1998-2053 (trace_port_open and trace_port), OTP-29.1.1.
pub(crate) fn emit_port_event(
    runtime: &crate::process::Runtime,
    port: u64,
    class: u64,
    name: &str,
    fields: &[Term],
) {
    let Ok(scheduler) = runtime.scheduler() else {
        return;
    };
    emit_port_event_scoped(
        scope_runtime(runtime),
        &scheduler,
        port,
        class,
        name,
        fields,
    );
}

pub(crate) fn emit_port_event_scoped(
    owner: usize,
    scheduler: &arinsal_sched::Scheduler<Process>,
    port: u64,
    class: u64,
    name: &str,
    fields: &[Term],
) {
    if !enabled().load(Ordering::Relaxed) {
        return;
    }
    let entries = port_table()
        .lock()
        .unwrap()
        .iter()
        .filter(|((scope, _, id), entry)| {
            *scope == owner && *id == port && entry.flags & class != 0
        })
        .map(|(_, entry)| entry.clone())
        .collect::<Vec<_>>();
    if entries.is_empty() {
        return;
    }
    let Some(port_term) = Term::port(port) else {
        return;
    };
    for entry in entries {
        let mut heap = VecHeap::new();
        let Ok(port_term) = copy_term(port_term, &mut heap) else {
            continue;
        };
        let Ok(mut values) = fields
            .iter()
            .map(|field| copy_term(*field, &mut heap))
            .collect::<Result<Vec<_>, _>>()
        else {
            continue;
        };
        values.splice(0..0, [port_term, crate::signals::atom(name)]);
        values.insert(
            0,
            crate::signals::atom(
                if entry.flags & (TIMESTAMP | MONOTONIC_TIMESTAMP | STRICT_MONOTONIC_TIMESTAMP) != 0
                {
                    "trace_ts"
                } else {
                    "trace"
                },
            ),
        );
        if entry.flags & TIMESTAMP != 0 {
            let micros = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_micros();
            let stamp = [
                (micros / 1_000_000 / 1_000_000) as i64,
                (micros / 1_000_000 % 1_000_000) as i64,
                (micros % 1_000_000) as i64,
            ]
            .map(|value| Term::small(value).unwrap_or(Term::NIL));
            if let Ok(stamp) = TermBuilder::new(&mut heap).tuple(&stamp) {
                values.push(stamp);
            }
        } else if entry.flags & (MONOTONIC_TIMESTAMP | STRICT_MONOTONIC_TIMESTAMP) != 0 {
            static START: OnceLock<std::time::Instant> = OnceLock::new();
            values.push(
                Term::small(
                    i64::try_from(
                        START
                            .get_or_init(std::time::Instant::now)
                            .elapsed()
                            .as_nanos(),
                    )
                    .unwrap_or(i64::MAX),
                )
                .unwrap_or(Term::NIL),
            );
        }
        let Ok(event) = TermBuilder::new(&mut heap).tuple(&values) else {
            continue;
        };
        let Ok(message) = Message::copy_from(event) else {
            continue;
        };
        match entry.tracer {
            Tracer::Pid(tracer) => {
                let _ = scheduler.send(tracer, tracer, message);
            }
            Tracer::Port(_) | Tracer::Module { .. } | Tracer::Default => {}
        }
    }
}

pub(crate) fn traced_port_by_other(
    vm: &Vm,
    process: &mut Process,
    session: u64,
    port: u64,
    tracer: &Tracer,
) -> bool {
    let current = port_table()
        .lock()
        .unwrap()
        .get(&(scope(process), session, port))
        .filter(|entry| entry.flags != 0)
        .map(|entry| entry.tracer.clone());
    let Some(current) = current else {
        return false;
    };
    let same = match (&current, tracer) {
        (Tracer::Default, Tracer::Default) => true,
        (Tracer::Pid(a), Tracer::Pid(b)) => a == b,
        (Tracer::Port(a), Tracer::Port(b)) => a == b,
        (
            Tracer::Module { module, state, .. },
            Tracer::Module {
                module: other_module,
                state: other_state,
                ..
            },
        ) => module == other_module && state == other_state,
        _ => false,
    };
    if same {
        return false;
    }
    let Some(runtime) = process.runtime.as_ref() else {
        return false;
    };
    match current {
        Tracer::Default => false,
        Tracer::Pid(tracer) => runtime
            .scheduler()
            .is_ok_and(|scheduler| scheduler.lookup(tracer)),
        Tracer::Port(tracer) => runtime.ports.lock().unwrap().contains_key(&tracer),
        Tracer::Module {
            module,
            state,
            instance,
        } => module_tracer_alive(vm, process, &module, &state, &instance, Term::port(port)),
    }
}

pub(crate) fn new_port_flags(process: &Process, session: u64) -> u64 {
    new_port_tracing()
        .lock()
        .unwrap()
        .get(&(scope(process), session))
        .map_or(0, |(flags, _)| *flags)
}

pub(crate) fn new_port_tracer(process: &Process, session: u64) -> Option<Tracer> {
    new_port_tracing()
        .lock()
        .unwrap()
        .get(&(scope(process), session))
        .and_then(|(_, tracer)| tracer.clone())
}

pub(crate) fn new_process_session_refs(process: &Process) -> Vec<(String, i64)> {
    let runtime = scope(process);
    let mut refs = new_process_tracing()
        .lock()
        .unwrap()
        .iter()
        .filter(|((owner, _), (flags, _))| *owner == runtime && *flags != 0)
        .filter_map(|((_, session), _)| session_ref(process, *session))
        .collect::<Vec<_>>();
    refs.sort_unstable_by_key(|(_, weak_id)| std::cmp::Reverse(*weak_id));
    refs
}

pub(crate) fn new_port_session_refs(process: &Process) -> Vec<(String, i64)> {
    let runtime = scope(process);
    let mut refs = new_port_tracing()
        .lock()
        .unwrap()
        .iter()
        .filter(|((owner, _), (flags, _))| *owner == runtime && *flags != 0)
        .filter_map(|((_, session), _)| session_ref(process, *session))
        .collect::<Vec<_>>();
    refs.sort_unstable_by_key(|(_, weak_id)| std::cmp::Reverse(*weak_id));
    refs
}

pub(crate) fn port_session_refs(process: &Process, port: u64) -> Vec<(String, i64)> {
    let runtime = scope(process);
    let entries = port_table().lock().unwrap();
    let mut refs = entries
        .iter()
        .filter(|((owner, _, id), entry)| *owner == runtime && *id == port && entry.flags != 0)
        .filter_map(|((_, session, _), _)| {
            sessions()
                .lock()
                .unwrap()
                .get(&(runtime, *session))
                .map(|session| (session.name.clone(), session.weak_id))
        })
        .collect::<Vec<_>>();
    if entries.iter().any(|((owner, session, id), entry)| {
        *owner == runtime && *session == 0 && *id == port && entry.flags != 0
    }) {
        refs.push(("legacy".to_owned(), -1));
    }
    refs.sort_unstable_by_key(|(_, weak_id)| std::cmp::Reverse(*weak_id));
    refs
}

/// Whether `pid` is already traced in `session` by a live tracer other than `tracer`.
// Port of erts/emulator/beam/erl_bif_trace.c:853-863 (start_trace), OTP-29.1.1.
pub(crate) fn traced_by_other(
    vm: &Vm,
    process: &mut Process,
    session: u64,
    pid: Pid,
    tracer: &Tracer,
) -> bool {
    let current = table()
        .lock()
        .unwrap()
        .get(&(scope(process), session, pid))
        .filter(|entry| entry.flags != 0)
        .map(|entry| entry.tracer.clone());
    let Some(current) = current else {
        return false;
    };
    let same = match (&current, tracer) {
        (Tracer::Default, Tracer::Default) => true,
        (Tracer::Pid(a), Tracer::Pid(b)) => a == b,
        (Tracer::Port(a), Tracer::Port(b)) => a == b,
        (
            Tracer::Module { module, state, .. },
            Tracer::Module {
                module: other_module,
                state: other_state,
                ..
            },
        ) => module == other_module && state == other_state,
        _ => false,
    };
    if same {
        return false;
    }
    let Some(runtime) = process.runtime.as_ref() else {
        return false;
    };
    match current {
        Tracer::Default => false,
        Tracer::Pid(tracer) => runtime
            .scheduler()
            .is_ok_and(|scheduler| scheduler.lookup(tracer)),
        Tracer::Port(id) => runtime.ports.lock().unwrap().contains_key(&id),
        Tracer::Module {
            module,
            state,
            instance,
        } => module_tracer_alive(vm, process, &module, &state, &instance, pid.to_term()),
    }
}

/// Whether `instance` is still the current code of `module`.
fn tracer_instance_current(
    vm: &Vm,
    module: &str,
    instance: &std::sync::Arc<arinsal_loader::Module>,
) -> bool {
    vm.loaded
        .get(module)
        .and_then(|&id| vm.modules.get(id))
        .is_some_and(|current| std::sync::Arc::ptr_eq(current, instance))
}

/// Whether a module tracer still answers `enabled(trace_status, ...)` with `trace` or `discard`.
// Port of erts/emulator/beam/erl_trace.c:3374-3390 (erts_is_tracer_enabled), OTP-29.1.1: a
// tracer whose module was deleted, purged or reloaded without the NIFs is no longer a tracer.
fn module_tracer_alive(
    vm: &Vm,
    process: &mut Process,
    module: &str,
    state: &OwnedTerm,
    instance: &std::sync::Arc<arinsal_loader::Module>,
    tracee: Option<Term>,
) -> bool {
    let Some(tracee) = tracee else {
        return false;
    };
    if !tracer_instance_current(vm, module, instance) {
        return false;
    }
    let Ok(state) = from_owned(state, &mut arinsal_bifs::FragmentingHeap(&mut process.heap)) else {
        return false;
    };
    let result = crate::natives::nif::invoke_tracer(
        vm,
        process,
        module,
        "enabled",
        &[crate::signals::atom("trace_status"), state, tracee],
    );
    result == Some(crate::signals::atom("trace")) || result == Some(crate::signals::atom("discard"))
}

// Port of erts/emulator/beam/erl_process.c:12692-12705, OTP-29.1.1.
fn replace_session_flags(process: &Process, session: u64, pid: Pid, flags: u64, tracer: Tracer) {
    let key = (scope(process), session, pid);
    let mut table = table().lock().unwrap();
    if flags == 0 {
        table.remove(&key);
    } else {
        table.insert(key, Entry { flags, tracer });
    }
    let processes_active = !table.is_empty();
    drop(table);
    enabled().store(
        processes_active || !port_table().lock().unwrap().is_empty(),
        Ordering::Relaxed,
    );
}

pub(crate) fn flags(process: &Process, pid: Pid) -> u64 {
    if !enabled().load(Ordering::Relaxed) || is_sensitive(process, pid) {
        return 0;
    }
    table()
        .read()
        .unwrap()
        .iter()
        .filter(|((runtime, _, subject), _)| *runtime == scope(process) && *subject == pid)
        .fold(0, |flags, (_, entry)| flags | entry.flags)
}

pub(crate) fn return_to_enabled(process: &Process) -> bool {
    let runtime = scope(process);
    table()
        .lock()
        .unwrap()
        .iter()
        .any(|((owner, _, _), entry)| *owner == runtime && entry.flags & RETURN_TO != 0)
}

pub(crate) fn clear_runtime(runtime: usize) {
    table()
        .lock()
        .unwrap()
        .retain(|(owner, _, _), _| *owner != runtime);
    port_table()
        .lock()
        .unwrap()
        .retain(|(owner, _, _), _| *owner != runtime);
    sessions()
        .lock()
        .unwrap()
        .retain(|(owner, _), _| *owner != runtime);
    new_process_tracing()
        .lock()
        .unwrap()
        .retain(|(owner, _), _| *owner != runtime);
    new_port_tracing()
        .lock()
        .unwrap()
        .retain(|(owner, _), _| *owner != runtime);
    event_patterns()
        .lock()
        .unwrap()
        .retain(|(owner, _, _), _| *owner != runtime);
    enabled().store(
        !table().lock().unwrap().is_empty() || !port_table().lock().unwrap().is_empty(),
        Ordering::Relaxed,
    );
}

/// Store the state of an ERTS send or receive trace event pattern.
// Port of erts/emulator/beam/erl_bif_trace.c:2800-2828 (stage_trace_event_pattern), OTP-29.1.1.
pub(crate) fn set_event_pattern(
    process: &Process,
    session: u64,
    event: &str,
    enabled: bool,
    match_spec: Option<OwnedTerm>,
) {
    let event = match event {
        "send" => "send",
        "receive" => "receive",
        _ => return,
    };
    let key = (scope(process), session, event);
    event_patterns().lock().unwrap().insert(
        key,
        EventPattern {
            enabled,
            match_spec,
        },
    );
}

fn event_pattern(process: &Process, session: u64, event: &str) -> Option<EventPattern> {
    let key = (scope(process), session, event);
    event_patterns().lock().unwrap().get(&key).cloned()
}

// Port of erts/emulator/beam/erl_bif_trace.c:2474-2505, OTP-29.1.1.
pub(crate) fn event_match_spec(
    process: &Process,
    session: u64,
    event: &str,
) -> (bool, Option<OwnedTerm>) {
    event_pattern(process, session, event)
        .map(|pattern| (pattern.enabled, pattern.match_spec))
        .unwrap_or((true, None))
}

pub(crate) fn event_session_refs(process: &Process, event: &str) -> Vec<(String, i64)> {
    let _ = event;
    session_refs(process)
}

/// Trace flags of `pid` in `session` that generate events: none for a sensitive process.
// Port of erts/emulator/beam/erl_trace.c:3798 (erts_sum_all_trace_flags), OTP-29.1.1.
pub(crate) fn active_session_flags(process: &Process, session: u64, pid: Pid) -> u64 {
    if is_sensitive(process, pid) {
        return 0;
    }
    session_flags(process, session, pid)
}

pub(crate) fn session_flags(process: &Process, session: u64, pid: Pid) -> u64 {
    table()
        .read()
        .unwrap()
        .get(&(scope(process), session, pid))
        .map_or(0, |entry| entry.flags)
}

fn set_session_flags(
    process: &Process,
    session: u64,
    pid: Pid,
    clear: u64,
    set: u64,
    tracer: Option<Tracer>,
) -> bool {
    let key = (scope(process), session, pid);
    let mut entries = table().lock().unwrap();
    let Some(entry) = entries.get_mut(&key) else {
        return false;
    };
    entry.flags = (entry.flags & !clear) | set;
    if let Some(tracer) = tracer {
        entry.tracer = tracer;
    }
    if entry.flags == 0 {
        entries.remove(&key);
    }
    enabled().store(!entries.is_empty(), Ordering::Relaxed);
    true
}

fn trace_action_target(process: &Process, current: Pid, value: Term) -> Option<Pid> {
    if let Some(pid) = Pid::from_term(value) {
        return Some(pid);
    }
    let owned = to_owned(value).ok()?;
    let OwnedTerm::Atom(name) = &owned else {
        return None;
    };
    process
        .runtime
        .as_ref()?
        .names
        .lock()
        .unwrap()
        .get(name)
        .copied()
        .or_else(|| (name == "self").then_some(current))
}

fn trace_action_flags(value: Term) -> Option<(u64, Option<Tracer>)> {
    let mut flags = 0;
    let mut tracer = None;
    let owned = to_owned(value).ok()?;
    let values = match &owned {
        OwnedTerm::Atom(name) => {
            if name == "all" {
                return crate::natives::proc::trace_flag_bit("all").map(|bits| (bits, None));
            }
            std::slice::from_ref(&owned)
        }
        OwnedTerm::Nil => &[],
        OwnedTerm::List { elems, tail } if **tail == OwnedTerm::Nil => elems.as_slice(),
        _ => return None,
    };
    for flag in values {
        if let OwnedTerm::Atom(name) = flag {
            flags |= crate::natives::proc::trace_flag_bit(name)?;
            continue;
        }
        match flag {
            OwnedTerm::Tuple(fields)
                if fields.len() == 2
                    && fields.first() == Some(&OwnedTerm::Atom("tracer".into())) =>
            {
                let OwnedTerm::Pid {
                    node,
                    id,
                    serial,
                    creation,
                } = &fields[1]
                else {
                    return None;
                };
                if node != "nonode@nohost" || *creation != 0 {
                    return None;
                }
                tracer = Some(Tracer::Pid(Pid::from_term(Term::pid(*id, *serial)?)?));
            }
            _ => return None,
        }
    }
    Some((flags, tracer))
}

// Port of erts/emulator/beam/erl_trace.c:3374-3390 (erts_is_tracer_enabled), OTP-29.1.1.
fn match_trace_tracer_alive(
    vm: &mut Vm,
    process: &mut Process,
    tracee: Pid,
    tracer: &Tracer,
) -> bool {
    match tracer {
        Tracer::Default => true,
        Tracer::Pid(pid) => process.runtime.as_ref().is_some_and(|runtime| {
            runtime
                .scheduler()
                .is_ok_and(|scheduler| scheduler.lookup(*pid))
        }),
        Tracer::Port(port) => process
            .runtime
            .as_ref()
            .is_some_and(|runtime| runtime.ports.lock().unwrap().contains_key(port)),
        Tracer::Module {
            module,
            state,
            instance,
        } => module_tracer_alive(vm, process, module, state, instance, tracee.to_term()),
    }
}

// Port of erts/emulator/beam/erl_db_util.c:251-267,3023-3090
// (set_match_trace and do_trace), OTP-29.1.1: the resolved session tracer is installed on the
// tracee, a nil tracer clears trace flags, and an inactive tracer rejects the update.
fn apply_match_trace_action(
    vm: &mut Vm,
    process: &mut Process,
    session: u64,
    current: Pid,
    name: &str,
    args: &[Term],
) -> bool {
    let (target, clear, set, tracer) = match (name, args) {
        ("enable_trace", [flag]) => {
            let Some((flags, tracer)) = trace_action_flags(*flag) else {
                return false;
            };
            (current, 0, flags, tracer)
        }
        ("enable_trace", [target, flag]) => {
            let (Some(target), Some((flags, tracer))) = (
                trace_action_target(process, current, *target),
                trace_action_flags(*flag),
            ) else {
                return false;
            };
            (target, 0, flags, tracer)
        }
        ("disable_trace", [flag]) => {
            let Some((flags, _)) = trace_action_flags(*flag) else {
                return false;
            };
            (current, flags, 0, None)
        }
        ("disable_trace", [target, flag]) => {
            let (Some(target), Some((flags, _))) = (
                trace_action_target(process, current, *target),
                trace_action_flags(*flag),
            ) else {
                return false;
            };
            (target, flags, 0, None)
        }
        ("trace", [disable, enable]) => {
            let (Some((clear, _)), Some((set, tracer))) =
                (trace_action_flags(*disable), trace_action_flags(*enable))
            else {
                return false;
            };
            let tracer = tracer
                .or_else(|| process_tracer(process, session, current))
                .or_else(|| session_tracer(process, session));
            if tracer.is_none() {
                (current, u64::MAX, 0, None)
            } else {
                (current, clear, set, tracer)
            }
        }
        ("trace", [target, disable, enable]) => {
            let (Some(target), Some((clear, _)), Some((set, tracer))) = (
                trace_action_target(process, current, *target),
                trace_action_flags(*disable),
                trace_action_flags(*enable),
            ) else {
                return false;
            };
            let tracer = tracer
                .or_else(|| process_tracer(process, session, current))
                .or_else(|| session_tracer(process, session));
            if tracer.is_none() {
                (target, u64::MAX, 0, None)
            } else {
                (target, clear, set, tracer)
            }
        }
        _ => return false,
    };
    if let Some(tracer) = tracer.as_ref()
        && !match_trace_tracer_alive(vm, process, target, tracer)
    {
        return false;
    }
    let applied = set_session_flags(process, session, target, clear, set, tracer.clone());
    if applied {
        return true;
    }
    if set == 0 {
        return true;
    }
    // Port of erts/emulator/beam/erl_db_util.c:2868-2901 (matchEnableTrace and matchTrace2),
    // OTP-29.1.1: enabling another process inherits the tracee's session tracer.
    let Some(tracer) = tracer
        .or_else(|| process_tracer(process, session, current))
        .or_else(|| session_tracer(process, session))
    else {
        return false;
    };
    replace_session_flags(process, session, target, set, tracer);
    true
}

// Port of erts/emulator/beam/erl_db_util.c:3007-3018 (matchSilent), OTP-29.1.1.
fn set_session_silent(process: &Process, session: u64, pid: Pid, silent: bool) {
    let mut entries = table().lock().unwrap();
    if let Some(entry) = entries.get_mut(&(scope(process), session, pid)) {
        if silent {
            entry.flags |= SILENT;
        } else {
            entry.flags &= !SILENT;
        }
    }
}

// Port of erts/emulator/beam/erl_trace.c:559-582, OTP-29.1.1.
pub(crate) fn configure_new_processes(
    process: &Process,
    session: u64,
    how_on: bool,
    flags: u64,
    tracer: Tracer,
) {
    let key = (scope(process), session);
    let mut tracing = new_process_tracing().lock().unwrap();
    let (current, current_tracer) = tracing.entry(key).or_default();
    if how_on {
        *current |= flags;
        *current_tracer = Some(tracer);
    } else {
        *current &= !flags;
        if *current == 0 {
            *current_tracer = None;
        }
    }
    if *current == 0 {
        tracing.remove(&key);
    }
}

pub(crate) fn new_process_flags(process: &Process, session: u64) -> u64 {
    new_process_tracing()
        .lock()
        .unwrap()
        .get(&(scope(process), session))
        .map_or(0, |(flags, _)| *flags)
}

pub(crate) fn new_process_tracer(process: &Process, session: u64) -> Option<Tracer> {
    new_process_tracing()
        .lock()
        .unwrap()
        .get(&(scope(process), session))
        .and_then(|(_, tracer)| tracer.clone())
}

pub(crate) fn tracer(process: &Process, pid: Pid) -> Option<Tracer> {
    table()
        .lock()
        .unwrap()
        .get(&(scope(process), 0, pid))
        .map(|entry| entry.tracer.clone())
}

pub(crate) fn clear(process: &Process, pid: Pid) {
    set_sensitive(process, pid, false);
    let mut entries = table().lock().unwrap();
    entries.retain(|(runtime, _, subject), _| *runtime != scope(process) || *subject != pid);
    let processes_active = !entries.is_empty();
    drop(entries);
    enabled().store(
        processes_active || !port_table().lock().unwrap().is_empty(),
        Ordering::Relaxed,
    );
}

/// Keep only the `exiting` flag of an exiting process's trace entries, so its scheduling
/// events stay visible until `out_exited` while all other events stop at exit.
// Port of erts/emulator/beam/erl_process.c:14784 (delete_all_trace_refs after out_exited), OTP-29.1.1.
pub(crate) fn retain_exiting(process: &Process, pid: Pid) {
    let mut entries = table().lock().unwrap();
    entries.retain(|(runtime, _, subject), entry| {
        if *runtime != scope(process) || *subject != pid {
            return true;
        }
        entry.flags &= EXITING;
        entry.flags != 0
    });
    let processes_active = !entries.is_empty();
    drop(entries);
    enabled().store(
        processes_active || !port_table().lock().unwrap().is_empty(),
        Ordering::Relaxed,
    );
}

/// Remove process and future-process tracing owned by a dying tracer.
// Port of erts/emulator/beam/erl_trace.c (tracer process termination), OTP-29.1.1.
pub(crate) fn tracer_exited(process: &Process, pid: Pid) {
    let runtime = scope(process);
    let mut entries = table().lock().unwrap();
    entries.retain(|(owner, _, _), entry| {
        *owner != runtime || !matches!(entry.tracer, Tracer::Pid(tracer) if tracer == pid)
    });
    drop(entries);
    for ((owner, _), (flags, tracer_state)) in new_process_tracing().lock().unwrap().iter_mut() {
        if *owner == runtime
            && matches!(tracer_state.as_ref(), Some(Tracer::Pid(tracer)) if *tracer == pid)
        {
            *flags = 0;
            *tracer_state = None;
        }
    }
    new_process_tracing()
        .lock()
        .unwrap()
        .retain(|(owner, _), (flags, _)| *owner != runtime || *flags != 0);
    let mut ports = port_table().lock().unwrap();
    ports.retain(|(owner, _, _), entry| {
        *owner != runtime || !matches!(entry.tracer, Tracer::Pid(tracer) if tracer == pid)
    });
    drop(ports);
    for ((owner, _), (flags, tracer_state)) in new_port_tracing().lock().unwrap().iter_mut() {
        if *owner == runtime
            && matches!(tracer_state.as_ref(), Some(Tracer::Pid(tracer)) if *tracer == pid)
        {
            *flags = 0;
            *tracer_state = None;
        }
    }
    new_port_tracing()
        .lock()
        .unwrap()
        .retain(|(owner, _), (flags, _)| *owner != runtime || *flags != 0);
    enabled().store(
        !table().lock().unwrap().is_empty() || !port_table().lock().unwrap().is_empty(),
        Ordering::Relaxed,
    );
}

/// Port of erts/emulator/beam/beam_bp.c:1115-1285 (generic entry breakpoint), OTP-29.1.1.
/// Emit a call event after the function entry has resolved its trace pattern.
pub(crate) fn call_event(
    vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    module: &str,
    function: &str,
    args: &[Term],
    local: bool,
) -> Result<Vec<CallActions>, VmError> {
    call_event_scope(vm, process, ctx, module, function, args, local, false)
}

/// Call event of a BIF reached through its export entry.
// Port of erts/emulator/beam/emu/bif_instrs.tab:237 (is_bif_traced), OTP-29.1.1: a traced BIF
// dispatches through the export trampoline and then the BIF stub's code, so both global and
// local breakpoints fire.
pub(crate) fn bif_call_event(
    vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    module: &str,
    function: &str,
    args: &[Term],
    scan: StackScan,
) -> Result<Vec<CallActions>, VmError> {
    let actions = call_event_scope(vm, process, ctx, module, function, args, false, true)?;
    Ok(dedupe_return_frames(vm, process, actions, scan))
}

/// Outcome of running a trace match specification for a call.
struct CallMatch {
    /// The result was `false` or no clause matched: only the call message is dropped.
    suppress_call: bool,
    return_trace: bool,
    exception_trace: bool,
    extra: Option<Term>,
    /// `enable_trace`, `disable_trace` and `trace` calls, applied after the call event.
    trace_actions: Vec<(String, VecHeap, Vec<Term>)>,
}

/// Run the match specification of a traced call, if any.
// Port of erts/emulator/beam/erl_trace.c:1263-1297 (erts_call_trace, PAM program), OTP-29.1.1.
#[allow(clippy::too_many_arguments)] // The call and its match program are separate inputs.
fn run_call_match(
    vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    spec: Option<&std::sync::Arc<crate::trace_bp::MatchSpec>>,
    session: u64,
    (module, function): (&str, &str),
    args: &[Term],
) -> Result<CallMatch, VmError> {
    let Some(spec) = spec else {
        return Ok(CallMatch {
            suppress_call: false,
            return_trace: false,
            exception_trace: false,
            extra: None,
            trace_actions: Vec::new(),
        });
    };
    let dump = if spec.uses_process_dump {
        crate::natives::proc::process_dump(Some(&*vm), process, ctx).ok()
    } else {
        None
    };
    // Port of erts/emulator/beam/erl_trace.c:1266-1267, OTP-29.1.1.
    let against = TermBuilder::new(&mut arinsal_bifs::FragmentingHeap(&mut process.heap))
        .list_from_iter(args.iter().copied())
        .map_err(|error| VmError::Unsupported(format!("trace subject: {error:?}")))?;
    let program = spec
        .program(|source| {
            let specification = from_owned(
                source,
                &mut arinsal_bifs::FragmentingHeap(&mut process.heap),
            )
            .map_err(|_| ())?;
            arinsal_ets::match_spec::MatchProgram::compile_trace(specification).map_err(|_| ())
        })
        .map_err(|()| VmError::Unsupported("invalid trace match specification".into()))?;
    let current_stacktraces = if spec.uses_current_stacktrace {
        current_stacktraces(vm, process)?
    } else {
        Vec::new()
    };
    let (caller, caller_line) = if spec.uses_caller {
        caller_info(process, vm, module, function)?
    } else {
        (None, None)
    };
    let context = CallMatchContext::new(
        caller,
        caller_line,
        current_stacktraces,
        dump,
        crate::natives::sys::trace_control_word_value(process),
    );
    let result = program
        .run_with_context(
            against,
            &mut arinsal_bifs::FragmentingHeap(&mut process.heap),
            &context,
        )
        .map_err(|error| VmError::Unsupported(format!("trace match spec execution: {error:?}")))?;
    crate::natives::sys::set_trace_control_word_value(process, context.trace_control_word.get());
    if let Some(silent) = context.silent.get() {
        set_session_silent(process, session, ctx.pid(), silent);
    }
    // Port of erts/emulator/beam/erl_trace.c:1293-1297 (erts_call_trace), OTP-29.1.1.
    // A false result (`{message,false}`) only drops the call message;
    // {return_trace} and {exception_trace} still apply.
    let suppress_call = result.is_none_or(|result| result == crate::signals::atom("false"));
    Ok(CallMatch {
        suppress_call,
        return_trace: context.return_trace.get(),
        exception_trace: context.exception_trace.get(),
        extra: if suppress_call {
            None
        } else {
            context.take_message(process)
        },
        trace_actions: context.take_trace_actions(),
    })
}

#[allow(clippy::too_many_arguments)] // Shared body of the call and BIF call events.
fn call_event_scope(
    vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    module: &str,
    function: &str,
    args: &[Term],
    local: bool,
    bif: bool,
) -> Result<Vec<CallActions>, VmError> {
    use crate::trace_bp::{
        BPF_MEM_TRACE_ACTIVE, BPF_TIME_TRACE_ACTIVE, HIT_COUNT_ACTIVE, HIT_GLOBAL, HIT_LOCAL,
        HIT_META,
    };
    let pid = ctx.pid();
    // Port of erts/emulator/beam/beam_bp.c:1004 (erts_generic_breakpoint), OTP-29.1.1: a
    // sensitive process runs no session breakpoint.
    if is_sensitive(process, pid) {
        return Ok(Vec::new());
    }
    let arity = args.len() as u8;
    let hits = crate::trace_bp::hits(process, module, function, arity);
    if hits.is_empty() {
        return Ok(Vec::new());
    }
    let mut actions = Vec::new();
    // The export entry holds the global call trace, the function's code the others; a traced
    // BIF dispatches through both.
    let site_flags = if bif {
        u32::MAX
    } else if local {
        !HIT_GLOBAL
    } else {
        HIT_GLOBAL
    };
    for hit in hits {
        let mut bp_flags = hit.flags & site_flags;
        let flags = active_session_flags(process, hit.session, pid);
        // Port of erts/emulator/beam/beam_bp.c:1017-1060 (do_session_breakpoint), OTP-29.1.1.
        let acc_flags = BPF_TIME_TRACE_ACTIVE | BPF_MEM_TRACE_ACTIVE;
        if bp_flags & (HIT_LOCAL | HIT_GLOBAL | acc_flags) != 0 && flags & CALL == 0 {
            // The session does not trace calls of this process.
            bp_flags &= !(HIT_LOCAL | HIT_GLOBAL | acc_flags);
        } else if bp_flags & (HIT_LOCAL | HIT_GLOBAL) != 0 {
            let local_hit = bp_flags & HIT_LOCAL != 0;
            let outcome = run_call_match(
                vm,
                process,
                ctx,
                hit.local_ms.as_ref(),
                hit.session,
                (module, function),
                args,
            )?;
            // The match specification may have changed the silent state.
            let call_was_enabled = flags & CALL != 0;
            let flags = active_session_flags(process, hit.session, pid);
            let silent = flags & SILENT != 0;
            let mut extra = outcome.extra;
            if call_was_enabled && !silent && !outcome.suppress_call {
                emit_call_event(
                    vm,
                    process,
                    ctx,
                    CallEvent {
                        pid,
                        module,
                        function,
                        args,
                        flags,
                        extra: extra.take(),
                        actions: (outcome.return_trace, outcome.exception_trace),
                    },
                    Some(hit.session),
                )?;
            }
            // Port of erts/emulator/beam/erl_trace.c:1270-1302 (erts_call_trace), OTP-29.1.1:
            // the current event uses the pre-match tracer and flags; match trace actions affect
            // later events from the tracee.
            for (name, _heap, arguments) in outcome.trace_actions {
                let _ = apply_match_trace_action(vm, process, hit.session, pid, &name, &arguments);
            }
            if !silent {
                let return_to = !outcome.suppress_call
                    && local_hit
                    && active_session_flags(process, hit.session, pid) & RETURN_TO != 0;
                if outcome.return_trace || outcome.exception_trace || return_to {
                    actions.push(CallActions {
                        session: hit.session,
                        return_trace: outcome.return_trace,
                        exception_trace: outcome.exception_trace,
                        return_to,
                        acc: None,
                    });
                }
            }
        }
        if bp_flags & HIT_META != 0
            && let Some(meta) = hit.meta_tracer.as_ref()
        {
            // Meta trace: fixed flags, independent of the process flags.
            let outcome = run_call_match(
                vm,
                process,
                ctx,
                hit.meta_ms.as_ref(),
                hit.session,
                (module, function),
                args,
            )?;
            {
                if !outcome.suppress_call {
                    emit_meta_call_event(
                        vm,
                        process,
                        ctx,
                        meta,
                        module,
                        function,
                        args,
                        outcome.extra,
                    )?;
                }
                // The call event uses the pre-match state; trace actions affect later events.
                for (name, _heap, arguments) in outcome.trace_actions {
                    let _ =
                        apply_match_trace_action(vm, process, hit.session, pid, &name, &arguments);
                }
                if outcome.return_trace || outcome.exception_trace {
                    actions.push(CallActions {
                        session: meta.id,
                        return_trace: outcome.return_trace,
                        exception_trace: outcome.exception_trace,
                        return_to: false,
                        acc: None,
                    });
                }
            }
        }
        // Port of erts/emulator/beam/beam_bp.c:1090-1092 (ERTS_BPF_COUNT_ACTIVE), OTP-29.1.1.
        if bp_flags & HIT_COUNT_ACTIVE != 0
            && let Some(count) = hit.count.as_ref()
        {
            count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        if bp_flags & acc_flags != 0 {
            let ci = crate::trace_bp::func_id(module, function, arity);
            let mut prev = None;
            if bp_flags & BPF_TIME_TRACE_ACTIVE != 0
                && let Some(bdt) = hit.time.as_ref()
            {
                let time = arinsal_bifs::monotonic_time_nanos() as i64;
                prev = crate::trace_bp::trace_call_acc(
                    process,
                    pid,
                    hit.session,
                    false,
                    ci,
                    time,
                    bdt,
                );
            }
            if bp_flags & BPF_MEM_TRACE_ACTIVE != 0
                && let Some(bdt) = hit.memory.as_ref()
            {
                let adjustment = crate::trace_bp::call_memory_adjustment(process, hit.session);
                // The initial call of a process starts counting from zero.
                let allocated =
                    if adjustment.is_none() && is_initial_call(process, module, function, arity) {
                        0
                    } else {
                        process.allocated_words(adjustment.unwrap_or(0))
                    };
                prev = crate::trace_bp::trace_call_acc(
                    process,
                    pid,
                    hit.session,
                    true,
                    ci,
                    allocated,
                    bdt,
                );
            }
            actions.push(CallActions {
                session: hit.session,
                return_trace: false,
                exception_trace: false,
                return_to: false,
                acc: Some(CallAcc {
                    flags: bp_flags & acc_flags,
                    prev,
                }),
            });
        }
    }
    Ok(actions)
}

/// Whether `module:function/arity` is the initial call of the process.
fn is_initial_call(process: &Process, module: &str, function: &str, arity: u8) -> bool {
    process.cold.as_ref().is_some_and(|cold| {
        cold.initial_call
            .as_ref()
            .is_some_and(|(m, f, a)| m == module && f == function && *a == arity)
    })
}

/// The call event of a meta trace: fixed `call` and `timestamp` flags.
// Port of erts/emulator/beam/erl_trace.c:1213-1260 (erts_call_trace, meta trace branch),
// OTP-29.1.1.
#[allow(clippy::too_many_arguments)] // The call and its tracer are separate inputs.
fn emit_meta_call_event(
    vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    meta: &crate::trace_bp::MetaTracer,
    module: &str,
    function: &str,
    args: &[Term],
    extra: Option<Term>,
) -> Result<(), VmError> {
    let mfa = call_mfa_term(process, module, function, args, false)?;
    emit_meta(vm, process, ctx, meta, "call", &[mfa], extra, true);
    Ok(())
}

/// Send a trace event of the traced process to a meta tracer.
#[allow(clippy::too_many_arguments)] // The event and its meta tracer are separate inputs.
fn emit_meta(
    vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    meta: &crate::trace_bp::MetaTracer,
    name: &str,
    fields: &[Term],
    extra: Option<Term>,
    remove_dead: bool,
) {
    let subject = ctx.pid();
    let Some(subject_term) = subject.to_term() else {
        return;
    };
    let tracer = meta.tracer();
    // Port of erts/emulator/nifs/common/erl_tracer_nif.c:127-155 (enabled): a dead tracer is
    // removed, and nothing is traced when tracer and tracee are the same.
    match &tracer {
        Tracer::Default => return,
        Tracer::Pid(pid) => {
            let alive = process
                .runtime
                .as_ref()
                .and_then(|runtime| runtime.scheduler().ok())
                .is_some_and(|scheduler| scheduler.lookup(*pid));
            if !alive {
                if remove_dead {
                    meta.clear();
                }
                return;
            }
        }
        Tracer::Port(id) => {
            let alive = process
                .runtime
                .as_ref()
                .is_some_and(|runtime| runtime.ports.lock().unwrap().contains_key(id));
            if !alive {
                if remove_dead {
                    meta.clear();
                }
                return;
            }
        }
        Tracer::Module { module, state, .. } => {
            let Some(state) =
                from_owned(state, &mut arinsal_bifs::FragmentingHeap(&mut process.heap)).ok()
            else {
                return;
            };
            crate::natives::nif::refresh_hub(process, ctx);
            let status = crate::natives::nif::invoke_tracer(
                vm,
                process,
                module,
                "enabled",
                &[crate::signals::atom("trace_status"), state, subject_term],
            );
            if status == Some(crate::signals::atom("remove")) {
                if remove_dead {
                    meta.clear();
                }
                return;
            }
            if status != Some(crate::signals::atom("trace")) {
                return;
            }
        }
    }
    let entry = Entry {
        flags: CALL | TIMESTAMP,
        tracer,
    };
    deliver(
        Some(vm),
        process,
        ctx,
        subject,
        subject_term,
        &entry,
        name,
        fields,
        extra,
    );
}

/// A trace frame at the top of the stack.
enum SpecialFrame {
    /// A return_trace, exception_trace or call time/memory frame.
    Trace,
    /// A return_to frame of a session.
    ReturnTo(u64),
}

/// Where a traced call looks for the trace frames already on the stack.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum StackScan {
    /// The return address of the call is on top: no trace frame is (a BIF call).
    None,
    /// The run of trace frames on top of the stack (a call to Erlang code).
    Top,
    /// The current function's frame is dropped by the tail call: the run of trace frames
    /// below it.
    AfterFrame,
}

/// The trace frames on top of the stack, innermost first, up to the first real return address.
// Port of erts/emulator/beam/beam_bp.c:938-980 (fixup_cp_before_trace), OTP-29.1.1.
fn special_frames(
    vm: &Vm,
    process: &Process,
    first_only: bool,
    skip_frame: bool,
) -> Vec<SpecialFrame> {
    let trace_stub = crate::native_bridge::native_trace_return_address();
    let bridge = arinsal_beamasm::rt::arinsal_enter_native_return as *const () as usize;
    let mut frames = Vec::new();
    let mut index = 0;
    if skip_frame {
        // Skip the Y registers up to the frame's own return address.
        while let Some(word) = process.heap.stack_get(index) {
            if word.tagged_word() as usize == trace_stub
                || matches!(crate::stacktrace::decode_tag(word), Some((false, _, _)))
                || crate::native_bridge::is_native_function_at(word.tagged_word() as usize)
            {
                break;
            }
            index += 1;
        }
    }
    while let Some(word) = process.heap.stack_get(index) {
        if first_only && !frames.is_empty() {
            break;
        }
        if word.tagged_word() as usize == bridge {
            // The bridge from native code into the interpreter is no real return address.
            index += 1;
            continue;
        }
        if word.tagged_word() as usize == trace_stub {
            let (_, actions, words) = native_frame_actions(process, index + 2);
            frames.push(SpecialFrame::Trace);
            for action in actions.iter().filter(|action| action.return_to) {
                frames.push(SpecialFrame::ReturnTo(action.session));
            }
            index += words;
            continue;
        }
        let Some((false, module_id, ip)) = crate::stacktrace::decode_tag(word) else {
            break;
        };
        let Some(module) = vm.modules.get(module_id) else {
            break;
        };
        if ip == module.return_trace_ip {
            frames.push(SpecialFrame::Trace);
            index += 6;
        } else if ip == module.return_to_trace_ip {
            let session = process.heap.stack_get(index + 1).and_then(Term::as_small);
            frames.push(SpecialFrame::ReturnTo(session.unwrap_or(-1) as u64));
            index += 2;
        } else {
            break;
        }
    }
    frames
}

/// Drop the return_to frames a session already has on top of the stack, and the call time or
/// memory frames that would sit on another trace frame: tail recursion must not grow the stack.
// Port of erts/emulator/beam/beam_bp.c:1181-1250 (do_call_trace, return_to_trace) and
// :1119-1150 (do_session_breakpoint, call acc frame), OTP-29.1.1.
pub(crate) fn dedupe_return_frames(
    vm: &Vm,
    process: &Process,
    actions: Vec<CallActions>,
    scan: StackScan,
) -> Vec<CallActions> {
    if actions.is_empty() {
        return actions;
    }
    // Only return_to frames need the whole run of trace frames; the rest only the top one.
    let first_only = !actions.iter().any(|action| action.return_to);
    // A BIF is never tail called: the loader keeps the caller's frame, so the return address
    // of the call is on top of the stack and no trace frame is.
    // Port of erts/emulator/beam/ops.tab (call_ext_last/call_ext_only to a BIF), OTP-29.1.1.
    let mut frames = match scan {
        StackScan::None => Vec::new(),
        StackScan::Top => special_frames(vm, process, first_only, false),
        StackScan::AfterFrame => special_frames(vm, process, first_only, true),
    };
    let mut actions = actions;
    for action in &mut actions {
        if action.return_to {
            if frames
                .iter()
                .any(|frame| matches!(frame, SpecialFrame::ReturnTo(session) if *session == action.session))
            {
                action.return_to = false;
            } else {
                frames.insert(0, SpecialFrame::ReturnTo(action.session));
            }
        }
        if action.return_trace || action.exception_trace {
            frames.insert(0, SpecialFrame::Trace);
        }
        if action.acc.is_some() {
            if frames.is_empty() {
                frames.insert(0, SpecialFrame::Trace);
            } else {
                action.acc = None;
            }
        }
    }
    actions
        .into_iter()
        .filter(|action| {
            action.return_to
                || action.return_trace
                || action.exception_trace
                || action.acc.is_some()
        })
        .collect()
}

/// The frame of a call time/memory accounted call returns.
// Port of erts/emulator/beam/emu/trace_instrs.tab:54-70 (i_call_trace_return), OTP-29.1.1.
pub(crate) fn call_acc_return(
    process: &mut Process,
    pid: Pid,
    session: u64,
    bp_flags: u32,
    prev: Option<u32>,
) {
    // Port of erts/emulator/beam/beam_bp.c:1352-1365 (erts_call_trace_return): a session that
    // no longer traces the process has no state to update.
    if !table()
        .lock()
        .unwrap()
        .contains_key(&(scope(process), session, pid))
    {
        return;
    }
    crate::trace_bp::call_trace_return(process, pid, session, bp_flags, prev);
}

/// Capture the process dump up front when a match specification uses `{process_dump}`.
// Port of erts/emulator/beam/erl_db_util.c:2756-2765 (matchProcessDump), OTP-29.1.1.
fn process_dump_for(
    specification: &OwnedTerm,
    vm: Option<&Vm>,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
) -> Option<Vec<u8>> {
    fn uses(term: &OwnedTerm) -> bool {
        match term {
            OwnedTerm::Tuple(fields) => {
                matches!(fields.as_slice(), [OwnedTerm::Atom(name)] if name == "process_dump")
                    || fields.iter().any(uses)
            }
            OwnedTerm::List { elems, tail } => elems.iter().any(uses) || uses(tail),
            OwnedTerm::Map(pairs) => pairs.iter().any(|(key, value)| uses(key) || uses(value)),
            _ => false,
        }
    }
    if !uses(specification) {
        return None;
    }
    crate::natives::proc::process_dump(vm, process, ctx).ok()
}

fn emit_call_event(
    vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    event: CallEvent<'_>,
    session: Option<u64>,
) -> Result<(bool, bool), VmError> {
    let CallEvent {
        pid,
        module,
        function,
        args,
        flags,
        extra,
        actions,
    } = event;
    let call = call_mfa_term(process, module, function, args, flags & ARITY != 0)?;
    let fields = if let Some(extra) = extra {
        vec![call, extra]
    } else {
        vec![call]
    };
    emit_filtered(
        Some(vm),
        process,
        ctx,
        pid,
        CALL,
        "call",
        &fields,
        session,
        None,
    );
    Ok(actions)
}

/// The `{M, F, Args}` (or `{M, F, Arity}`) tuple of a call event.
// Port of erts/emulator/beam/erl_trace.c:1330-1350 (erts_call_trace, mfa_tuple), OTP-29.1.1.
fn call_mfa_term(
    process: &mut Process,
    module: &str,
    function: &str,
    args: &[Term],
    arity_only: bool,
) -> Result<Term, VmError> {
    let mut values = vec![
        Term::atom(
            global_atoms()
                .intern(module)
                .map_err(|_| VmError::Unsupported("module atom".into()))?,
        ),
        Term::atom(
            global_atoms()
                .intern(function)
                .map_err(|_| VmError::Unsupported("function atom".into()))?,
        ),
    ];
    if arity_only {
        values.push(
            Term::small(args.len() as i64)
                .ok_or_else(|| VmError::Unsupported("trace arity".into()))?,
        );
    } else {
        let args = TermBuilder::new(&mut arinsal_bifs::FragmentingHeap(&mut process.heap))
            .list_from_iter(args.iter().copied())
            .map_err(|error| VmError::Unsupported(format!("trace args: {error:?}")))?;
        values.push(args);
    }
    TermBuilder::new(&mut arinsal_bifs::FragmentingHeap(&mut process.heap))
        .tuple(&values)
        .map_err(|error| VmError::Unsupported(format!("trace call: {error:?}")))
}

// Port of erts/emulator/beam/erl_db_util.c:5335-5370 (matchCaller and matchCallerLine),
// OTP-29.1.1.
fn caller_info(
    process: &mut Process,
    vm: &Vm,
    target_module: &str,
    target_function: &str,
) -> Result<(Option<Term>, Option<Term>), VmError> {
    let direct_caller = if let Some(module) = vm.modules.get(process.module)
        && let Some((function, arity)) = module.function_at(process.ip)
        && (module.name != target_module || function != target_function)
        && !function.starts_with('-')
        && module.line_term_at(process.ip).is_some()
    {
        Some((module, function.to_owned(), arity, process.ip))
    } else {
        None
    };
    let caller = {
        let mut index = 0;
        loop {
            let Some(word) = process.heap.stack_get(index) else {
                if let Some(caller) = direct_caller {
                    break caller;
                }
                return Ok((None, None));
            };
            let raw_address = word.tagged_word() as usize;
            if let Some(native) =
                crate::native_bridge::native_stack_frame_at(raw_address.saturating_sub(1))
            {
                if native.module_atom
                    != global_atoms()
                        .intern(target_module)
                        .map_err(|_| VmError::Unsupported("caller module atom".into()))?
                    || native.function_atom
                        != global_atoms()
                            .intern(target_function)
                            .map_err(|_| VmError::Unsupported("caller function atom".into()))?
                {
                    let mfa = [
                        Term::atom(native.module_atom),
                        Term::atom(native.function_atom),
                        Term::small(i64::from(native.arity))
                            .ok_or_else(|| VmError::Unsupported("caller arity".into()))?,
                    ];
                    let mut heap = arinsal_bifs::FragmentingHeap(&mut process.heap);
                    let caller = TermBuilder::new(&mut heap)
                        .tuple(&mfa)
                        .map_err(|error| VmError::Unsupported(format!("caller MFA: {error:?}")))?;
                    let caller_line =
                        if let (Some(file), Some(line)) = (native.file_term, native.line) {
                            let line = Term::small(i64::from(line))
                                .ok_or_else(|| VmError::Unsupported("caller line".into()))?;
                            let source = TermBuilder::new(&mut heap).tuple(&[file, line]).map_err(
                                |error| {
                                    VmError::Unsupported(format!("caller source line: {error:?}"))
                                },
                            )?;
                            Some(
                                TermBuilder::new(&mut heap)
                                    .tuple(&[mfa[0], mfa[1], mfa[2], source])
                                    .map_err(|error| {
                                        VmError::Unsupported(format!("caller line: {error:?}"))
                                    })?,
                            )
                        } else {
                            None
                        };
                    return Ok((Some(caller), caller_line));
                }
                index += 1;
                continue;
            }
            let Some((handler, module_id, ip)) = crate::stacktrace::decode_tag(word) else {
                index += 1;
                continue;
            };
            let Some(module) = vm.modules.get(module_id) else {
                index += 1;
                continue;
            };
            if handler {
                index += 1;
                continue;
            }
            if ip == module.return_trace_ip {
                index += 6;
                continue;
            }
            if ip == module.return_to_trace_ip {
                index += 2;
                continue;
            }
            let call_site = ip.saturating_sub(1);
            let Some((function, arity)) = module.function_at(call_site) else {
                index += 1;
                continue;
            };
            if function.starts_with('-') || function == "module_info" {
                index += 1;
                continue;
            }
            break (module, function.to_owned(), arity, call_site);
        }
    };
    let (module, function, arity, call_site) = caller;
    let mfa = [
        Term::atom(
            global_atoms()
                .intern(&module.name)
                .map_err(|_| VmError::Unsupported("caller module atom".into()))?,
        ),
        Term::atom(
            global_atoms()
                .intern(&function)
                .map_err(|_| VmError::Unsupported("caller function atom".into()))?,
        ),
        Term::small(i64::from(arity)).ok_or_else(|| VmError::Unsupported("caller arity".into()))?,
    ];
    let mut heap = arinsal_bifs::FragmentingHeap(&mut process.heap);
    let caller = TermBuilder::new(&mut heap)
        .tuple(&mfa)
        .map_err(|error| VmError::Unsupported(format!("caller MFA: {error:?}")))?;
    let caller_line = if let Some((file, line)) = module.line_term_at(call_site) {
        let line = Term::small(i64::try_from(line).unwrap_or(i64::MAX))
            .ok_or_else(|| VmError::Unsupported("caller line".into()))?;
        let source = TermBuilder::new(&mut heap)
            .tuple(&[file, line])
            .map_err(|error| VmError::Unsupported(format!("caller source line: {error:?}")))?;
        let values = [mfa[0], mfa[1], mfa[2], source];
        Some(
            TermBuilder::new(&mut heap)
                .tuple(&values)
                .map_err(|error| VmError::Unsupported(format!("caller line: {error:?}")))?,
        )
    } else {
        None
    };
    Ok((Some(caller), caller_line))
}

// Port of erts/emulator/beam/erl_db_util.c:5375-5421 (matchCurrentStacktrace), OTP-29.1.1.
fn current_stacktraces(vm: &Vm, process: &mut Process) -> Result<Vec<(VecHeap, Term)>, VmError> {
    // Reserve one slot beyond OTP's MAX_BACKTRACE_SIZE for the current frame, which is
    // removed before the caller prefixes are built below.
    let trace = crate::stacktrace::build(&vm.modules, process, None, 65)?;
    let owned = to_owned(trace)
        .map_err(|error| VmError::Unsupported(format!("match stacktrace copy: {error:?}")))?;
    let OwnedTerm::List { elems, .. } = &owned else {
        return Err(VmError::Unsupported(
            "match stacktrace is not a list".into(),
        ));
    };
    // Port of erts/emulator/beam/erl_db_util.c:5375-5421 (matchCurrentStacktrace),
    // OTP-29.1.1: the match-spec operation reports the tracee's saved callers, excluding the
    // current interpreter/JIT position used as the top frame by the general stacktrace builder.
    let callers = elems.get(1..).unwrap_or_default();
    // Port of erts/emulator/beam/error.h:206 (MAX_BACKTRACE_SIZE), OTP-29.1.1. Capture once
    // at the runtime maximum, then apply each match-spec's requested depth to the saved callers.
    let backtrace_depth = process
        .runtime
        .as_ref()
        .map_or(vm.backtrace_depth, |runtime| {
            runtime.backtrace_depth.load(Ordering::Acquire)
        });
    let maximum = backtrace_depth.min(callers.len());
    let mut traces = Vec::with_capacity(maximum + 1);
    for depth in 0..=maximum {
        let trace = OwnedTerm::List {
            elems: callers[..depth].to_vec(),
            tail: Box::new(OwnedTerm::Nil),
        };
        let mut heap = VecHeap::new();
        let term = from_owned(&trace, &mut heap)
            .map_err(|error| VmError::Unsupported(format!("match stacktrace build: {error:?}")))?;
        traces.push((heap, term));
    }
    Ok(traces)
}

/// Runs a native entry breakpoint with the scheduler context that owns its trace callbacks.
// Port of erts/emulator/beam/beam_bp.c (erts_generic_breakpoint), OTP-29.1.1.
pub(crate) fn executor_native_call_event(
    vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    function: &crate::NativeFunction,
) -> Result<Vec<NativeTraceAction>, VmError> {
    let args = process.x[..usize::from(function.arity)].to_vec();
    let actions = call_event(
        vm,
        process,
        ctx,
        &function.module,
        &function.function,
        &args,
        true,
    )?;
    let actions = dedupe_return_frames(vm, process, actions, StackScan::Top);
    Ok(actions
        .into_iter()
        // Port of erts/emulator/beam/beam_bp.c (do_call_trace: MATCH_SET_RX_TRACE), OTP-29.1.1:
        // an exception_trace frame also reports a normal return, like return_trace.
        .map(|action| NativeTraceAction {
            session: action.session,
            return_trace: action.return_trace || action.exception_trace,
            exception_trace: action.exception_trace,
            return_to: action.return_to,
            acc: action.acc,
        })
        .collect())
}

/// The traced native functions a return passes through, innermost first, and the address that
/// execution continues at.
pub(crate) type PoppedNativeFrames = (Vec<(usize, Vec<NativeTraceAction>)>, Term);

/// Pop the native trace frames a return passes through. The frame's stub word is already
/// dropped: the saved caller is at stack index 0 and the traced function's pc follows. A caller
/// that is itself a trace frame returns through it right away; its stub word is the slot that
/// was just dropped. `drop_words` removes words from the stack.
// Port of erts/emulator/beam/jit/arm/instr_trace.cpp:152-195, OTP-29.1.1.
pub(crate) fn pop_native_trace_frames(
    process: &mut Process,
    mut drop_words: impl FnMut(&mut Process, usize),
) -> Option<PoppedNativeFrames> {
    let trace_stub = crate::native_bridge::native_trace_return_address();
    let mut frames = Vec::new();
    loop {
        let saved_caller = process.heap.stack_get(0)?;
        let (function_pc, actions, _) = native_frame_actions(process, 1);
        if crate::native_function_at(function_pc).is_none() {
            return if frames.is_empty() {
                None
            } else {
                Some((frames, saved_caller))
            };
        }
        let cleanup = 4usize.saturating_add(actions.len() * 2);
        drop_words(process, cleanup);
        frames.push((function_pc, actions));
        if saved_caller.tagged_word() as usize != trace_stub {
            return Some((frames, saved_caller));
        }
    }
}

/// Saves native return and exception actions until the traced function exits.
pub(crate) fn push_native_trace_frame(
    process: &mut Process,
    return_address: usize,
    actions: &[NativeTraceAction],
) -> Result<(), VmError> {
    if actions.is_empty() {
        return Ok(());
    }
    let frame_words = 4usize.saturating_add(actions.len().saturating_mul(2));
    let Some(old_cp) = process.heap.stack_get(0) else {
        return Err(VmError::Unsupported(
            "native trace continuation missing".into(),
        ));
    };
    if !process.heap.reserve_stack(frame_words) {
        return Err(VmError::Unsupported("native trace stack limit".into()));
    }
    let trace_stub = arinsal_beamasm::rt::arinsal_enter_native_trace_return as *const () as usize;
    let metadata = [
        crate::proc_create::native_continuation_term(trace_stub),
        old_cp,
        Term::small(return_address as i64).unwrap_or(Term::NIL),
        Term::small(actions.len() as i64).unwrap_or(Term::NIL),
    ];
    for (index, value) in metadata.into_iter().enumerate() {
        process.heap.stack_set(index, value);
    }
    for (index, action) in actions.iter().enumerate() {
        process.heap.stack_set(
            4 + index * 2,
            Term::small(action.session as i64).unwrap_or(Term::NIL),
        );
        process.heap.stack_set(
            5 + index * 2,
            Term::small(action.flags_word()).unwrap_or(Term::NIL),
        );
    }
    process.sync_native_header();
    Ok(())
}

/// Emit the trace events of the actions of a native trace frame that is left by a return, or
/// by an exception when `exception` is set.
// Port of erts/emulator/beam/jit/arm/instr_trace.cpp:152-195 and
// erts/emulator/beam/beam_common.c:622-640 (next_catch), OTP-29.1.1.
pub(crate) fn native_return_events(
    vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    function: &crate::NativeFunction,
    actions: &[NativeTraceAction],
    value: Term,
    exception: bool,
) -> Result<(), VmError> {
    let pid = ctx.pid();
    let mut mfa = None;
    // The frames pop innermost first: the last action pushed its frames last.
    for action in actions.iter().rev() {
        if let Some(acc) = action.acc {
            // Frames left by an exception do no accounting.
            if !exception {
                call_acc_return(process, pid, action.session, acc.flags, acc.prev);
            }
            continue;
        }
        if (exception && !action.exception_trace) || (!exception && !action.return_trace) {
            continue;
        }
        let meta = if crate::trace_bp::is_meta_id(action.session) {
            let Some(meta) = crate::trace_bp::meta_tracer_by_id(action.session) else {
                continue;
            };
            Some(meta)
        } else {
            let flags = active_session_flags(process, action.session, pid);
            if flags & CALL == 0 || flags & SILENT != 0 {
                continue;
            }
            None
        };
        let mfa = match mfa {
            Some(mfa) => mfa,
            None => {
                let built = TermBuilder::new(&mut arinsal_bifs::FragmentingHeap(&mut process.heap))
                    .tuple(&[
                        Term::atom(
                            global_atoms()
                                .intern(&function.module)
                                .map_err(|_| VmError::Unsupported("trace module atom".into()))?,
                        ),
                        Term::atom(
                            global_atoms()
                                .intern(&function.function)
                                .map_err(|_| VmError::Unsupported("trace function atom".into()))?,
                        ),
                        Term::small(i64::from(function.arity))
                            .ok_or_else(|| VmError::Unsupported("trace arity".into()))?,
                    ])
                    .map_err(|error| VmError::Unsupported(format!("trace MFA: {error:?}")))?;
                mfa = Some(built);
                built
            }
        };
        let name = if exception {
            "exception_from"
        } else {
            "return_from"
        };
        if let Some(meta) = meta {
            emit_meta(vm, process, ctx, &meta, name, &[mfa, value], None, false);
        } else {
            emit_filtered(
                Some(vm),
                process,
                ctx,
                pid,
                CALL,
                name,
                &[mfa, value],
                Some(action.session),
                None,
            );
        }
    }
    Ok(())
}

// Port of erts/emulator/beam/erl_trace.c:1095-1180 (return and exception events), OTP-29.1.1.
#[allow(clippy::too_many_arguments)] // The special stack frame carries these exact ERTS return fields.
pub(crate) fn return_event(
    vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    session: u64,
    module_id: usize,
    entry_ip: usize,
    value: Term,
    exception: bool,
    exception_class_and_reason: Option<Term>,
) -> Result<(), VmError> {
    let meta = if crate::trace_bp::is_meta_id(session) {
        // Meta trace ignores the process flags, `silent` included.
        let Some(meta) = crate::trace_bp::meta_tracer_by_id(session) else {
            return Ok(());
        };
        Some(meta)
    } else {
        let flags = active_session_flags(process, session, ctx.pid());
        if flags & CALL == 0 || flags & SILENT != 0 {
            return Ok(());
        }
        None
    };
    let Some((module_name, function_name, arity)) = vm.modules.get(module_id).and_then(|module| {
        module
            .function_at(entry_ip)
            .map(|(function, arity)| (module.name.clone(), function.to_owned(), arity))
    }) else {
        return Ok(());
    };
    let module = Term::atom(
        global_atoms()
            .intern(&module_name)
            .map_err(|_| VmError::Unsupported("trace return module atom".into()))?,
    );
    let function = Term::atom(
        global_atoms()
            .intern(&function_name)
            .map_err(|_| VmError::Unsupported("trace return function atom".into()))?,
    );
    let arity = Term::small(i64::from(arity))
        .ok_or_else(|| VmError::Unsupported("trace return arity".into()))?;
    let mfa = TermBuilder::new(&mut arinsal_bifs::FragmentingHeap(&mut process.heap))
        .tuple(&[module, function, arity])
        .map_err(|error| VmError::Unsupported(format!("trace return MFA: {error:?}")))?;
    let fields = if exception {
        vec![mfa, exception_class_and_reason.unwrap_or(value)]
    } else {
        vec![mfa, value]
    };
    if let Some(meta) = meta {
        let name = if exception {
            "exception_from"
        } else {
            "return_from"
        };
        emit_meta(vm, process, ctx, &meta, name, &fields, None, false);
        return Ok(());
    }
    emit_filtered(
        Some(vm),
        process,
        ctx,
        ctx.pid(),
        CALL,
        if exception {
            "exception_from"
        } else {
            "return_from"
        },
        &fields,
        Some(session),
        None,
    );
    Ok(())
}

/// Emit the return or exception events of a traced BIF whose call event ran inline.
// Port of erts/emulator/beam/emu/trace_instrs.tab:25-70 (return_trace), applied to BIFs as in
// erts/emulator/beam/beam_bp.c:321-330 (erts_export_is_bif_traced), OTP-29.1.1.
#[allow(clippy::too_many_arguments)] // The BIF identity and outcome stay explicit.
pub(crate) fn bif_return_events(
    vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    actions: &[CallActions],
    module: &str,
    function: &str,
    arity: u8,
    outcome: Result<Term, Term>,
    site: Option<(usize, usize)>,
) -> Result<(), VmError> {
    if actions.is_empty() {
        return Ok(());
    }
    let atom_of = |name: &str| {
        global_atoms()
            .intern(name)
            .map(Term::atom)
            .map_err(|_| VmError::Unsupported("trace return atom".into()))
    };
    // Only call time and memory frames: no event carries the MFA.
    let mfa = if actions.iter().any(|action| action.acc.is_none()) {
        TermBuilder::new(&mut arinsal_bifs::FragmentingHeap(&mut process.heap))
            .tuple(&[
                atom_of(module)?,
                atom_of(function)?,
                Term::small(i64::from(arity)).unwrap_or(Term::NIL),
            ])
            .map_err(|error| VmError::Unsupported(format!("trace return MFA: {error:?}")))?
    } else {
        Term::NIL
    };
    let pid = ctx.pid();
    // The frames pop innermost first: the last action pushed its frames last.
    for action in actions.iter().rev() {
        if let Some(acc) = action.acc {
            call_acc_return(process, pid, action.session, acc.flags, acc.prev);
            continue;
        }
        let (name, wanted, value) = match outcome {
            Ok(value) => (
                "return_from",
                action.return_trace || action.exception_trace,
                value,
            ),
            Err(class_and_reason) => ("exception_from", action.exception_trace, class_and_reason),
        };
        if wanted {
            if crate::trace_bp::is_meta_id(action.session) {
                if let Some(meta) = crate::trace_bp::meta_tracer_by_id(action.session) {
                    emit_meta(vm, process, ctx, &meta, name, &[mfa, value], None, false);
                }
            } else {
                emit_filtered(
                    Some(vm),
                    process,
                    ctx,
                    pid,
                    CALL,
                    name,
                    &[mfa, value],
                    Some(action.session),
                    None,
                );
            }
        }
        if action.return_to && outcome.is_err() {
            // The unwinding to a catch reports the return_to of the catching function.
            process.cold_mut().bif_return_to.push(action.session);
        }
        if action.return_to && outcome.is_ok() {
            let flags = active_session_flags(process, action.session, pid);
            if flags & RETURN_TO != 0 && flags & SILENT == 0 {
                let target = caller_mfa_name(vm, process, site);
                emit_return_to(vm, process, ctx, action.session, target)?;
            }
        }
    }
    Ok(())
}

/// The function a traced BIF call returns to: the one that holds the call site.
fn caller_mfa_name(
    vm: &Vm,
    process: &Process,
    site: Option<(usize, usize)>,
) -> Option<(String, String, u8)> {
    let (module_id, ip) = match site {
        // An interpreted `apply` names its instruction in the running module.
        Some((id, ip)) if id == usize::MAX - 1 => (process.module, ip),
        Some(site) => site,
        None => (process.module, process.ip),
    };
    if module_id == usize::MAX {
        // A native call site: the pc names the caller's native function.
        let function = crate::native_function_at(ip)?;
        return Some((function.module, function.function, function.arity));
    }
    let module = vm.modules.get(module_id)?;
    let (function, arity) = module.function_at(ip)?;
    Some((module.name.clone(), function.to_owned(), arity))
}

// Port of erts/emulator/beam/beam_bp.c:1242-1268 and
// erts/emulator/beam/erl_trace.c:1037-1055 (return-to tracing), OTP-29.1.1.
pub(crate) fn return_to_event(
    vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    session: u64,
) -> Result<(), VmError> {
    let flags = active_session_flags(process, session, ctx.pid());
    if flags & RETURN_TO == 0 || flags & SILENT != 0 {
        return Ok(());
    }
    // The return-to continuation has already transferred control here, leaving
    // its session word at stack index 0. Match OTP's scan from the end of that
    // frame: Y slots can precede the next CP, and other trace frames can be
    // nested between it and the real caller.
    let target = return_to_target(vm, process, 1);
    emit_return_to(vm, process, ctx, session, target)
}

/// The catching function gets the `return_to` event of every session that had a return_to
/// frame on the unwound stack.
// Port of erts/emulator/beam/beam_common.c:585-700 (next_catch, have_return_to_trace),
// OTP-29.1.1.
pub(crate) fn unwound_return_to(
    vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    sessions: &[u64],
    target: Option<(String, String, u8)>,
) -> Result<(), VmError> {
    let pid = ctx.pid();
    let mut done = Vec::new();
    for session in sessions {
        if done.contains(session) {
            continue;
        }
        done.push(*session);
        let flags = active_session_flags(process, *session, pid);
        if flags & RETURN_TO == 0 || flags & SILENT != 0 {
            continue;
        }
        emit_return_to(vm, process, ctx, *session, target.clone())?;
    }
    Ok(())
}

/// Emits the `return_to` event of a traced native return that resumes at `caller`.
// Port of erts/emulator/beam/emu/trace_instrs.tab:73-105 (i_return_to_trace), OTP-29.1.1.
pub(crate) fn native_return_to_event(
    vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    session: u64,
    caller: usize,
) -> Result<(), VmError> {
    let flags = flags(process, ctx.pid());
    if flags & RETURN_TO == 0 || flags & SILENT != 0 {
        return Ok(());
    }
    // The native frame's CP was consumed by the return: a native caller is named by it,
    // an interpreted one by the continuation the bridge left on the stack.
    let target = match crate::native_function_at(caller) {
        Some(function) => Some((function.module, function.function, function.arity)),
        None => return_to_target(vm, process, 0),
    };
    emit_return_to(vm, process, ctx, session, target)
}

fn return_to_target(vm: &Vm, process: &Process, start: usize) -> Option<(String, String, u8)> {
    let trace_stub = arinsal_beamasm::rt::arinsal_enter_native_trace_return as *const () as usize;
    let mut index = start;
    loop {
        let word = process.heap.stack_get(index)?;
        let raw = word.tagged_word() as usize;
        if raw == trace_stub {
            // A native return trace frame: stub, caller CP, function pc, count, actions.
            let count = process
                .heap
                .stack_get(index + 3)
                .and_then(Term::as_small)
                .and_then(|count| usize::try_from(count).ok())
                .unwrap_or(0);
            index += 4 + count * 2;
            continue;
        }
        if let Some(function) = crate::native_function_at(raw) {
            return Some((function.module, function.function, function.arity));
        }
        let Some((is_handler, module_id, ip)) = crate::stacktrace::decode_tag(word) else {
            index += 1;
            continue;
        };
        if is_handler {
            index += 1;
            continue;
        }
        let Some(module) = vm.modules.get(module_id) else {
            index += 1;
            continue;
        };
        if ip == module.return_trace_ip {
            index += 6;
            continue;
        }
        if ip == module.return_to_trace_ip {
            index += 2;
            continue;
        }
        return module
            .function_at(ip)
            .map(|(function, arity)| (module.name.clone(), function.to_owned(), arity));
    }
}

fn emit_return_to(
    vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    session: u64,
    target: Option<(String, String, u8)>,
) -> Result<(), VmError> {
    let mfa = if let Some((module, function, arity)) = target {
        let values = [
            Term::atom(
                global_atoms()
                    .intern(&module)
                    .map_err(|_| VmError::Unsupported("return_to module atom".into()))?,
            ),
            Term::atom(
                global_atoms()
                    .intern(&function)
                    .map_err(|_| VmError::Unsupported("return_to function atom".into()))?,
            ),
            Term::small(i64::from(arity))
                .ok_or_else(|| VmError::Unsupported("return_to arity".into()))?,
        ];
        TermBuilder::new(&mut arinsal_bifs::FragmentingHeap(&mut process.heap))
            .tuple(&values)
            .map_err(|error| VmError::Unsupported(format!("return_to MFA: {error:?}")))?
    } else {
        crate::signals::atom("undefined")
    };
    emit_filtered(
        Some(vm),
        process,
        ctx,
        ctx.pid(),
        RETURN_TO,
        "return_to",
        &[mfa],
        Some(session),
        None,
    );
    Ok(())
}

// Port of erts/emulator/beam/erl_process.c:12685-12713, OTP-29.1.1.
pub(crate) fn spawned(
    vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    child: Pid,
    mfa: Term,
    linked: bool,
) {
    let parent = ctx.pid();
    if let Some(child_term) = child.to_term() {
        emit(
            Some(vm),
            process,
            ctx,
            parent,
            PROCS,
            "spawn",
            &[child_term, mfa],
        );
        if linked {
            // Port of erts/emulator/beam/erl_process.c:12884-12888 (erl_create_process link
            // trace), OTP-29.1.1.
            emit(Some(vm), process, ctx, parent, PROCS, "link", &[child_term]);
        }
    }
    let defaults = new_process_tracing()
        .lock()
        .unwrap()
        .iter()
        .filter(|((owner, _), (flags, _))| *owner == scope(process) && *flags != 0)
        .map(|((_, session), (flags, tracer))| (*session, *flags, tracer.clone()))
        .collect::<Vec<_>>();
    for (session, flags, tracer) in defaults {
        configure_session(
            process,
            session,
            child,
            true,
            flags,
            tracer.unwrap_or(Tracer::Pid(parent)),
        );
    }
    let runtime = scope(process);
    let entries = table()
        .lock()
        .unwrap()
        .iter()
        .filter(|((owner, _, pid), _)| {
            *owner == runtime && *pid == parent && !is_sensitive(process, parent)
        })
        .map(|((_, session, _), entry)| (*session, entry.clone()))
        .collect::<Vec<_>>();
    for (session, entry) in entries {
        let flags = entry.flags;
        let inherits_spawn = flags & (SET_ON_SPAWN | SET_ON_FIRST_SPAWN) != 0;
        let inherits_link = linked && flags & (SET_ON_LINK | FIRST_LINK) != 0;
        if !inherits_spawn && !inherits_link {
            continue;
        }
        let mut child_flags = flags;
        let mut clear_parent = 0;
        if flags & SET_ON_FIRST_SPAWN != 0 {
            child_flags &= !(SET_ON_SPAWN | SET_ON_FIRST_SPAWN);
            clear_parent |= SET_ON_SPAWN | SET_ON_FIRST_SPAWN;
        }
        if linked && flags & FIRST_LINK != 0 {
            child_flags &= !(SET_ON_LINK | FIRST_LINK);
            clear_parent |= SET_ON_LINK | FIRST_LINK;
        }
        if clear_parent != 0 {
            configure_session(
                process,
                session,
                parent,
                false,
                clear_parent,
                entry.tracer.clone(),
            );
        }
        if child_flags != 0 {
            // The parent trace flags replace a same-session new-process default.
            replace_session_flags(process, session, child, child_flags, entry.tracer);
        }
    }
    if linked && let Some(parent_term) = parent.to_term() {
        emit(
            Some(vm),
            process,
            ctx,
            child,
            PROCS,
            "spawned",
            &[parent_term, mfa],
        );
        emit(
            Some(vm),
            process,
            ctx,
            child,
            PROCS,
            "getting_linked",
            &[parent_term],
        );
    }
}

pub(crate) fn spawn_interested(process: &Process, parent: Pid) -> bool {
    flags(process, parent) & (PROCS | SET_ON_SPAWN | SET_ON_FIRST_SPAWN | SET_ON_LINK | FIRST_LINK)
        != 0
        || new_process_tracing()
            .lock()
            .unwrap()
            .iter()
            .any(|((runtime, _), (flags, _))| *runtime == scope(process) && *flags != 0)
}

// Port of erts/emulator/beam/erl_proc_sig_queue.c:618-655, OTP-29.1.1.
pub(crate) fn linked(process: &Process, from: Pid, to: Pid) {
    for (source, target) in [(from, to), (to, from)] {
        if is_sensitive(process, source) {
            continue;
        }
        let source_entries = table()
            .lock()
            .unwrap()
            .iter()
            .filter(|((runtime, _, pid), entry)| {
                *runtime == scope(process)
                    && *pid == source
                    && entry.flags & (SET_ON_LINK | FIRST_LINK) != 0
            })
            .map(|((_, session, _), entry)| (*session, entry.clone()))
            .collect::<Vec<_>>();
        for (session, entry) in source_entries {
            let first_link = entry.flags & FIRST_LINK != 0;
            let target_flags = if first_link {
                entry.flags & !(SET_ON_LINK | FIRST_LINK)
            } else {
                entry.flags
            };
            replace_session_flags(process, session, target, target_flags, entry.tracer.clone());
            if first_link {
                configure_session(
                    process,
                    session,
                    source,
                    false,
                    SET_ON_LINK | FIRST_LINK,
                    entry.tracer,
                );
            }
        }
    }
}

/// Emit an event to its configured pid tracer. The global atomic keeps the
/// untraced send and receive paths to one predictable, uncontended read.
pub(crate) fn emit(
    vm: Option<&mut Vm>,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    subject: Pid,
    class: u64,
    name: &str,
    fields: &[Term],
) {
    emit_filtered(vm, process, ctx, subject, class, name, fields, None, None);
}

pub(crate) fn receive_event(
    vm: Option<&mut Vm>,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    message: Term,
    from: Option<Pid>,
) {
    let node = crate::signals::atom("nonode@nohost");
    let from = from
        .and_then(Pid::to_term)
        .unwrap_or(crate::signals::atom("undefined"));
    emit_filtered(
        vm,
        process,
        ctx,
        ctx.pid(),
        RECEIVE,
        "receive",
        &[message],
        None,
        Some(&[node, from, message]),
    );
}

// Port of erts/emulator/beam/emu/msg_instrs.tab:276, OTP-29.1.1.
pub(crate) fn timeout_event(
    vm: Option<&mut Vm>,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
) {
    let node = crate::signals::atom("clock_service");
    let undefined = crate::signals::atom("undefined");
    let timeout = crate::signals::atom("timeout");
    emit_filtered(
        vm,
        process,
        ctx,
        ctx.pid(),
        RECEIVE,
        "receive",
        &[timeout],
        None,
        Some(&[node, undefined, timeout]),
    );
}

/// Whether `process` has send tracing on: its sends then need the scheduler context that
/// send trace patterns are evaluated with.
pub(crate) fn traces_sends(process: &Process) -> bool {
    if !enabled().load(Ordering::Relaxed) {
        return false;
    }
    let Some(pid) = process.self_pid else {
        return false;
    };
    if is_sensitive(process, pid) {
        return false;
    }
    table()
        .lock()
        .unwrap()
        .iter()
        .any(|((runtime, _sid, subject), entry)| {
            *runtime == scope(process) && *subject == pid && entry.flags & SEND != 0
        })
}

pub(crate) fn emit_process(
    vm: Option<&mut Vm>,
    process: &mut Process,
    subject: Pid,
    class: u64,
    name: &str,
    fields: &[Term],
) {
    emit_filtered_without_ctx(vm, process, subject, class, name, fields, None);
}

fn emit_filtered_without_ctx(
    mut vm: Option<&mut Vm>,
    process: &mut Process,
    subject: Pid,
    class: u64,
    name: &str,
    fields: &[Term],
    session: Option<u64>,
) {
    if !enabled().load(Ordering::Relaxed) || is_sensitive(process, subject) {
        return;
    }
    let entries = table()
        .lock()
        .unwrap()
        .iter()
        .filter(|((runtime, sid, pid), entry)| {
            *runtime == scope(process)
                && *pid == subject
                && entry.flags & class != 0
                && session.is_none_or(|wanted| *sid == wanted)
        })
        .map(|(_, entry)| entry.clone())
        .collect::<Vec<_>>();
    let Some(subject_term) = subject.to_term() else {
        return;
    };
    for entry in entries {
        if let Tracer::Module {
            module,
            state,
            instance,
        } = &entry.tracer
        {
            let event = TraceEvent {
                flags: entry.flags,
                tracee: subject_term,
                name,
                fields,
                extra: None,
            };
            if let Some(vm) = vm.as_deref_mut() {
                emit_module(vm, process, None, module, state, instance, event);
            } else if let Some(runtime) = process.runtime.clone() {
                crate::process::with_replica_vm(&runtime, |vm| {
                    emit_module(vm, process, None, module, state, instance, event);
                });
            }
            continue;
        }
        let mut values = Vec::with_capacity(3 + fields.len());
        values.extend([
            crate::signals::atom(
                if entry.flags & (TIMESTAMP | MONOTONIC_TIMESTAMP | STRICT_MONOTONIC_TIMESTAMP) != 0
                {
                    "trace_ts"
                } else {
                    "trace"
                },
            ),
            subject_term,
            crate::signals::atom(name),
        ]);
        values.extend_from_slice(fields);
        if let Some(stamp) = timestamp_term(process, entry.flags) {
            values.push(stamp);
        }
        // Port of erts/emulator/nifs/common/erl_tracer_nif.c:237-253 (enif_make_tuple_from_array
        // in the tracee env, then enif_send copies it), OTP-29.1.1. A full heap must not drop
        // the event, so the tuple may land in a heap fragment.
        let Ok(event) =
            TermBuilder::new(&mut arinsal_bifs::FragmentingHeap(&mut process.heap)).tuple(&values)
        else {
            continue;
        };
        let Ok(message) = Message::copy_from(event) else {
            continue;
        };
        match entry.tracer {
            Tracer::Default => continue,
            // A process never traces itself: the default tracer discards such events.
            Tracer::Pid(pid) if pid == subject => continue,
            Tracer::Pid(pid) => {
                if let Some(runtime) = &process.runtime
                    && let Ok(scheduler) = runtime.scheduler()
                {
                    let _ = scheduler.send(subject, pid, message);
                }
            }
            Tracer::Port(id) => {
                if let Some(port) = Term::port(id) {
                    let _ = crate::port::trace_command(process, port, event);
                }
            }
            Tracer::Module { .. } => unreachable!(),
        }
    }
}

/// Return the MFA reported by running-status events, including a trapped BIF's continuation.
pub(crate) fn running_mfa(
    process: &mut Process,
    vm: &Vm,
    subject: Pid,
) -> Result<Option<Term>, VmError> {
    if flags(process, subject) & RUNNING == 0 {
        return Ok(None);
    }
    let continuation = process
        .cold
        .as_ref()
        .and_then(|cold| cold.bif_trap.as_ref())
        .and_then(|pending| {
            let (module, rest) = pending.continuation.split_once(':')?;
            let (function, arity) = rest.rsplit_once('/')?;
            Some((module, function, arity.parse::<u8>().ok()?))
        });
    // Port of erts/emulator/beam/erl_db.c:3075 (BIF_TRAP1 ets_delete_continue_exp) and :3275
    // (BIF_TRAP2 ets_internal_delete_all_2), OTP-29.1.1: a trapped call runs as the trap export.
    let ets_trap = process
        .cold
        .as_ref()
        .and_then(|cold| cold.ets_free.as_ref())
        .map(|state| match state.tid {
            None => ("ets", "delete_trap", 1),
            Some(_) => ("ets", "internal_delete_all", 2),
        });
    let (module, function, arity) = if let Some(trap) = ets_trap {
        trap
    } else if let Some(continuation) = continuation {
        continuation
    } else {
        let Some(module) = vm.modules.get(process.module) else {
            return Ok(None);
        };
        let Some((function, arity)) = module.function_at(process.ip) else {
            return Ok(None);
        };
        (&*module.name, function, arity)
    };
    let tuple = TermBuilder::new(&mut arinsal_bifs::FragmentingHeap(&mut process.heap))
        .tuple(&[
            Term::atom(
                global_atoms()
                    .intern(module)
                    .map_err(|_| VmError::Unsupported("running module atom".into()))?,
            ),
            Term::atom(
                global_atoms()
                    .intern(function)
                    .map_err(|_| VmError::Unsupported("running function atom".into()))?,
            ),
            Term::small(i64::from(arity))
                .ok_or_else(|| VmError::Unsupported("running arity".into()))?,
        ])
        .map_err(|error| VmError::Unsupported(format!("running MFA: {error:?}")))?;
    Ok(Some(tuple))
}

#[allow(clippy::too_many_arguments)] // Trace event identity and routing stay explicit at emission sites.
fn emit_filtered(
    mut vm: Option<&mut Vm>,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    subject: Pid,
    class: u64,
    name: &str,
    fields: &[Term],
    session: Option<u64>,
    match_args: Option<&[Term]>,
) {
    if !enabled().load(Ordering::Relaxed) || is_sensitive(process, subject) {
        return;
    }
    let entries = table()
        .lock()
        .unwrap()
        .iter()
        .filter(|((runtime, sid, pid), entry)| {
            *runtime == scope(process)
                && *pid == subject
                && entry.flags & class != 0
                && session.is_none_or(|wanted| *sid == wanted)
        })
        .map(|((_, session, _), entry)| (*session, entry.clone()))
        .collect::<Vec<_>>();
    if entries.is_empty() {
        return;
    }
    let Some(subject_term) = subject.to_term() else {
        return;
    };
    for (session, entry) in entries {
        let mut extra = None;
        // Port of erts/emulator/beam/erl_trace.c:805-832 (trace_send), OTP-29.1.1: a send to a
        // dead local process is filtered by the send pattern but reported under its own name.
        let pattern_name = if name == "send_to_non_existing_process" {
            "send"
        } else {
            name
        };
        if matches!(pattern_name, "send" | "receive")
            && let Some(pattern) = event_pattern(process, session, pattern_name)
        {
            if !pattern.enabled {
                continue;
            }
            if let Some(specification) = pattern.match_spec {
                let generated_args;
                let arguments = if let Some(arguments) = match_args {
                    arguments
                } else if pattern_name == "send" && fields.len() >= 2 {
                    generated_args = [fields[1], fields[0]];
                    &generated_args
                } else {
                    fields
                };
                let dump = process_dump_for(&specification, vm.as_deref(), process, ctx);
                let against =
                    match TermBuilder::new(&mut arinsal_bifs::FragmentingHeap(&mut process.heap))
                        .list_from_iter(arguments.iter().copied())
                    {
                        Ok(against) => against,
                        Err(_) => continue,
                    };
                let specification = match from_owned(
                    &specification,
                    &mut arinsal_bifs::FragmentingHeap(&mut process.heap),
                ) {
                    Ok(specification) => specification,
                    Err(_) => continue,
                };
                let program =
                    match arinsal_ets::match_spec::MatchProgram::compile_trace(specification) {
                        Ok(program) => program,
                        Err(_) => continue,
                    };
                let context = CallMatchContext::new(
                    None,
                    None,
                    Vec::new(),
                    dump,
                    crate::natives::sys::trace_control_word_value(process),
                );
                let result = program.run_with_context(
                    against,
                    &mut arinsal_bifs::FragmentingHeap(&mut process.heap),
                    &context,
                );
                crate::natives::sys::set_trace_control_word_value(
                    process,
                    context.trace_control_word.get(),
                );
                if let Some(silent) = context.silent.get() {
                    set_session_silent(process, session, subject, silent);
                }
                if !result.is_ok_and(|result| {
                    result.is_some_and(|value| value != crate::signals::atom("false"))
                }) || session_flags(process, session, subject) & SILENT != 0
                {
                    continue;
                }
                extra = context.take_message(process);
            }
        }
        deliver(
            vm.as_deref_mut(),
            process,
            ctx,
            subject,
            subject_term,
            &entry,
            name,
            fields,
            extra,
        );
    }
}

/// Send one trace event to the tracer of `entry`.
// Port of erts/emulator/nifs/common/erl_tracer_nif.c:204-260 (trace) and
// erts/emulator/beam/erl_trace.c:3150-3260 (send_to_tracer_nif), OTP-29.1.1.
#[allow(clippy::too_many_arguments)] // The event and its tracer are separate inputs.
fn deliver(
    vm: Option<&mut Vm>,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    subject: Pid,
    subject_term: Term,
    entry: &Entry,
    name: &str,
    fields: &[Term],
    extra: Option<Term>,
) {
    if let Tracer::Module {
        module,
        state,
        instance,
    } = &entry.tracer
    {
        let event = TraceEvent {
            flags: entry.flags,
            tracee: subject_term,
            name,
            fields,
            extra,
        };
        if let Some(vm) = vm {
            emit_module(vm, process, Some(ctx), module, state, instance, event);
        } else if let Some(runtime) = process.runtime.clone() {
            // Receive tracing runs inside signal handling, which has no Vm of its own.
            crate::process::with_replica_vm(&runtime, |vm| {
                emit_module(vm, process, Some(ctx), module, state, instance, event);
            });
        }
        return;
    }
    let mut values = Vec::with_capacity(3 + fields.len() + 1);
    values.extend([
        crate::signals::atom(
            if entry.flags & (TIMESTAMP | MONOTONIC_TIMESTAMP | STRICT_MONOTONIC_TIMESTAMP) != 0 {
                "trace_ts"
            } else {
                "trace"
            },
        ),
        subject_term,
        crate::signals::atom(name),
    ]);
    values.extend_from_slice(fields);
    if let Some(extra) = extra {
        values.push(extra);
    }
    if entry.flags & SCHEDULER_ID != 0 {
        values.push(
            Term::small(ctx.scheduler_id().unwrap_or(0) as i64)
                .unwrap_or(crate::signals::atom("undefined")),
        );
    }
    if let Some(stamp) = timestamp_term(process, entry.flags) {
        values.push(stamp);
    }
    // Port of erts/emulator/nifs/common/erl_tracer_nif.c:237-253 (enif_make_tuple_from_array
    // in the tracee env, then enif_send copies it), OTP-29.1.1. A full heap must not drop
    // the event, so the tuple may land in a heap fragment.
    let Ok(event) =
        TermBuilder::new(&mut arinsal_bifs::FragmentingHeap(&mut process.heap)).tuple(&values)
    else {
        return;
    };
    let Ok(message) = Message::copy_from(event) else {
        return;
    };
    match &entry.tracer {
        Tracer::Default => {}
        Tracer::Pid(pid) if *pid == subject => {}
        Tracer::Pid(pid) => {
            let _ = ctx.send(*pid, message);
        }
        Tracer::Port(id) => {
            if let Some(port) = Term::port(*id) {
                let _ = crate::port::trace_command(process, port, event);
            }
        }
        Tracer::Module { .. } => unreachable!(),
    }
}

/// The timestamp field of a trace message for the timestamp flags in `flags`.
// Port of erts/emulator/beam/erl_trace.c:3221-3234 and :2970-3010 (patch_ts, erts_trace_ts):
// `timestamp` wins over `strict_monotonic_timestamp`, which wins over `monotonic_timestamp`.
fn timestamp_term(process: &mut Process, flags: u64) -> Option<Term> {
    if flags & (TIMESTAMP | STRICT_MONOTONIC_TIMESTAMP | MONOTONIC_TIMESTAMP) == 0 {
        return None;
    }
    let mut heap = arinsal_bifs::FragmentingHeap(&mut process.heap);
    if flags & TIMESTAMP != 0 {
        let now = arinsal_bifs::lookup("erlang", "now", 0)?;
        return now(&mut arinsal_bifs::Ctx::new(&mut heap), &[]).ok();
    }
    let monotonic = TermBuilder::new(&mut heap)
        .int_from_i128(arinsal_bifs::monotonic_time_nanos())
        .ok()?;
    if flags & STRICT_MONOTONIC_TIMESTAMP != 0 {
        let unique = TermBuilder::new(&mut heap)
            .int_from_i64(arinsal_bifs::next_unique_monotonic())
            .ok()?;
        return TermBuilder::new(&mut heap).tuple(&[monotonic, unique]).ok();
    }
    Some(monotonic)
}

fn emit_module(
    vm: &mut Vm,
    process: &mut Process,
    ctx: Option<&mut RunCtx<'_, Message>>,
    module: &str,
    owned_state: &OwnedTerm,
    instance: &std::sync::Arc<arinsal_loader::Module>,
    event: TraceEvent<'_>,
) {
    if !tracer_instance_current(vm, module, instance) {
        return;
    }
    let scheduler_id = ctx
        .as_ref()
        .and_then(|ctx| ctx.scheduler_id())
        .or_else(|| process.cold.as_ref().map(|cold| cold.scheduler_id));
    if let Some(ctx) = ctx {
        crate::natives::nif::refresh_hub(process, ctx);
    }
    let Some(state) = from_owned(
        owned_state,
        &mut arinsal_bifs::FragmentingHeap(&mut process.heap),
    )
    .ok() else {
        return;
    };
    let tag = crate::signals::atom(event.name);
    let action = crate::natives::nif::invoke_tracer(
        vm,
        process,
        module,
        "enabled",
        &[tag, state, event.tracee],
    );
    if action != Some(crate::signals::atom("trace")) {
        return;
    }
    let data = event.fields.first().copied().unwrap_or(Term::NIL);
    let mut options = Vec::new();
    // Port of erts/emulator/beam/erl_trace.c:3195-3206 (send_to_tracer_nif_raw), OTP-29.1.1:
    // the second event field is `extra`, except for call events where it is the match spec
    // result; send and receive carry that result separately.
    let (extra, match_spec_result) = if event.name == "call" {
        (None, event.fields.get(1).copied())
    } else {
        (event.fields.get(1).copied(), event.extra)
    };
    if let Some(extra) = extra {
        options.push((crate::signals::atom("extra"), extra));
    }
    if let Some(result) = match_spec_result {
        options.push((crate::signals::atom("match_spec_result"), result));
    }
    // Port of erts/emulator/beam/erl_trace.c:3216-3219 (F_TRACE_SCHED_NO option), OTP-29.1.1.
    if event.flags & SCHEDULER_ID != 0
        && let Some(id) = scheduler_id.and_then(|id| Term::small(id as i64))
    {
        options.push((crate::signals::atom("scheduler_id"), id));
    }
    if event.flags & TIMESTAMP != 0 {
        options.push((
            crate::signals::atom("timestamp"),
            crate::signals::atom("timestamp"),
        ));
    } else if event.flags & STRICT_MONOTONIC_TIMESTAMP != 0 {
        options.push((
            crate::signals::atom("timestamp"),
            crate::signals::atom("strict_monotonic"),
        ));
    } else if event.flags & MONOTONIC_TIMESTAMP != 0 {
        options.push((
            crate::signals::atom("timestamp"),
            crate::signals::atom("monotonic"),
        ));
    }
    let Ok(options) = TermBuilder::new(&mut arinsal_bifs::FragmentingHeap(&mut process.heap))
        .flatmap_from_pairs(&options)
    else {
        return;
    };
    let _ = crate::natives::nif::invoke_tracer(
        vm,
        process,
        module,
        "trace",
        &[tag, state, event.tracee, data, options],
    );
}

pub(crate) fn create_session(process: &Process, name: String, tracer: Tracer) -> (u64, i64) {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    // Session ids stay below 2^59 so trace frames can keep them in small integers.
    let id = (1 << 58) | NEXT.fetch_add(1, Ordering::Relaxed).max(1);
    let weak_id = process
        .runtime
        .as_ref()
        .map(|runtime| runtime.next_trace_weak_id.fetch_add(1, Ordering::Relaxed))
        .unwrap_or(0) as i64;
    sessions().lock().unwrap().insert(
        (scope(process), id),
        TraceSession {
            tracer,
            name,
            weak_id,
        },
    );
    (id, weak_id)
}

pub(crate) fn session_handle(
    process: &Process,
    session: u64,
) -> std::sync::Arc<arinsal_term::MagicRef> {
    let owner = scope(process);
    let handle = arinsal_term::MagicRef::new(TraceSessionHandle { owner, session });
    let magic_id = handle.id();
    session_handle_ids()
        .lock()
        .unwrap()
        .insert((owner, magic_id), session);
    handle
}

pub(crate) fn session_from_magic_ref(process: &Process, magic_id: u64) -> Option<u64> {
    session_handle_ids()
        .lock()
        .unwrap()
        .get(&(scope(process), magic_id))
        .copied()
}

pub(crate) fn session_tracer(process: &Process, session: u64) -> Option<Tracer> {
    sessions()
        .lock()
        .unwrap()
        .get(&(scope(process), session))
        .map(|session| session.tracer.clone())
}

/// Resolve the weak `{Name, Id}` handle exposed by `trace:session_info/1`.
// Port of erts/emulator/beam/erl_bif_trace.c:208-239 (trace session lookup), OTP-29.1.1.
pub(crate) fn session_id(process: &Process, name: &str, weak_id: i64) -> Option<u64> {
    sessions()
        .lock()
        .unwrap()
        .iter()
        .find_map(|(&(owner, id), session)| {
            (owner == scope(process) && session.name == name && session.weak_id == weak_id)
                .then_some(id)
        })
}

pub(crate) fn process_tracer(process: &Process, session: u64, pid: Pid) -> Option<Tracer> {
    // Port of erts/emulator/beam/erl_bif_trace.c:1640-1708, OTP-29.1.1.
    table()
        .lock()
        .unwrap()
        .get(&(scope(process), session, pid))
        .map(|entry| entry.tracer.clone())
}

/// Return the sessions that trace `pid` for `trace:session_info/1`.
// Port of erts/emulator/beam/erl_bif_trace.c:1667-1737 (trace_info_pid), OTP-29.1.1.
pub(crate) fn process_session_refs(process: &Process, pid: Pid) -> Vec<(String, i64)> {
    let runtime = scope(process);
    let entries = table().lock().unwrap();
    let mut refs = entries
        .iter()
        .filter(|((owner, _, subject), entry)| {
            *owner == runtime && *subject == pid && entry.flags != 0
        })
        .filter_map(|((_, session, _), _)| {
            sessions()
                .lock()
                .unwrap()
                .get(&(runtime, *session))
                .map(|session| (session.name.clone(), session.weak_id))
        })
        .collect::<Vec<_>>();
    refs.sort_unstable_by_key(|(_, weak_id)| std::cmp::Reverse(*weak_id));
    refs
}

pub(crate) fn session_refs(process: &Process) -> Vec<(String, i64)> {
    let runtime = scope(process);
    let mut refs = sessions()
        .lock()
        .unwrap()
        .iter()
        .filter(|((owner, _), _)| *owner == runtime)
        .map(|(_, session)| (session.name.clone(), session.weak_id))
        .collect::<Vec<_>>();
    refs.sort_unstable_by_key(|(_, weak_id)| std::cmp::Reverse(*weak_id));
    refs.push(("legacy".to_owned(), -1));
    refs
}

pub(crate) fn session_ref(process: &Process, session: u64) -> Option<(String, i64)> {
    if session == 0 {
        return Some(("legacy".to_owned(), -1));
    }
    sessions()
        .lock()
        .unwrap()
        .get(&(scope(process), session))
        .map(|entry| (entry.name.clone(), entry.weak_id))
}

pub(crate) fn destroy_session(process: &Process, session: u64) -> bool {
    destroy_session_key(scope(process), session)
}

fn destroy_session_key(runtime: usize, session: u64) -> bool {
    let existed = sessions()
        .lock()
        .unwrap()
        .remove(&(runtime, session))
        .is_some();
    let mut entries = table().lock().unwrap();
    entries.retain(|(owner, id, _), _| *owner != runtime || *id != session);
    let mut ports = port_table().lock().unwrap();
    ports.retain(|(owner, id, _), _| *owner != runtime || *id != session);
    event_patterns()
        .lock()
        .unwrap()
        .retain(|(owner, id, _), _| *owner != runtime || *id != session);
    new_process_tracing()
        .lock()
        .unwrap()
        .remove(&(runtime, session));
    new_port_tracing()
        .lock()
        .unwrap()
        .remove(&(runtime, session));
    let any_entries = !entries.is_empty() || !ports.is_empty();
    drop(ports);
    drop(entries);
    enabled().store(any_entries, Ordering::Relaxed);
    existed
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Vm;
    use arinsal_difftest::{CallResult, RefErl};

    fn trace_pattern_diff(name: &str, source: &str) {
        let Ok(reference) = RefErl::start() else {
            eprintln!("erl unavailable; skipping trace_pattern differential test");
            return;
        };
        let beam = reference.compile_named(name, source, &[]).unwrap();
        reference.load(name, &beam).unwrap();
        let expected = reference.call(name, "run", &[]);
        let mut vm = Vm::new([]);
        vm.load_bytes(&beam).unwrap();
        let actual = vm.eval_scheduled(name, "run", &[], 1, None).unwrap();
        assert_eq!(expected, CallResult::Ok(actual.term));
    }

    #[test]
    fn send_event_pattern_false_matches_otp() {
        trace_pattern_diff(
            "trace_t3a_send_pattern",
            "-module(trace_t3a_send_pattern). -export([run/0]). run() -> Parent=self(), S=trace:session_create(s,Parent,[]), 1=trace:send(S,false,[]), P=spawn(fun() -> receive go -> Parent ! done end end), trace:process(S,P,true,[send]), P ! go, receive done -> ok after 1000 -> timeout end, Result=receive {trace,P,send,_,_} -> unexpected after 0 -> quiet end, trace:session_destroy(S), Result.",
        );
    }

    #[test]
    fn event_match_spec_info_matches_otp() {
        trace_pattern_diff(
            "trace_t3a_event_info",
            "-module(trace_t3a_event_info). -export([run/0]). run() -> 1=erlang:trace_pattern(send,false,[]), Before=erlang:trace_info(send,match_spec), 1=erlang:trace_pattern(send,true,[]), Enabled=erlang:trace_info(send,match_spec), Spec=[{'_',[],[{message,4711}]}], 1=erlang:trace_pattern(send,Spec,[]), Active=erlang:trace_info(send,match_spec), 1=erlang:trace_pattern(send,false,[]), Disabled=erlang:trace_info(send,match_spec), {Before,Enabled,Active,Disabled}.",
        );
    }

    #[test]
    fn receive_event_match_spec_uses_sender_and_message_like_otp() {
        trace_pattern_diff(
            "trace_t3a_receive_match_spec",
            "-module(trace_t3a_receive_match_spec). -export([run/0]). run() -> Parent=self(), S=trace:session_create(s,Parent,[]), 1=trace:recv(S,[{[node(),'$1',go],[{is_pid,'$1'}],[]}],[]), P=spawn(fun() -> receive go -> Parent!hello end end), 1=trace:process(S,P,true,['receive']), P!go, receive hello -> ok end, Result=receive {trace,P,'receive',go} -> is_pid(P) after 1000 -> missing end, trace:session_destroy(S), Result.",
        );
    }

    #[test]
    fn receive_timeout_event_matches_otp() {
        trace_pattern_diff(
            "trace_t3a_receive_timeout",
            "-module(trace_t3a_receive_timeout). -export([run/0]). run() -> Parent=self(), P=spawn(fun() -> receive after 1 -> ok end end), 1=erlang:trace(P,true,['receive']), receive {trace,P,'receive',timeout} -> ok after 1000 -> missing end.",
        );
    }

    #[test]
    fn trace_existing_then_all_clear_matches_otp() {
        trace_pattern_diff(
            "trace_t3a_existing_clear",
            "-module(trace_t3a_existing_clear). -export([run/0]). run() -> Tracer=spawn(fun receiver/0), N=erlang:trace(existing,true,[send,{tracer,Tracer}]), {flags,[send]}=erlang:trace_info(self(),flags), {tracer,Tracer}=erlang:trace_info(self(),tracer), M=erlang:trace(all,false,[all]), {flags,[]}=erlang:trace_info(self(),flags), {tracer,[]}=erlang:trace_info(self(),tracer), N=:=M. receiver() -> receive _ -> receiver() end.",
        );
    }

    #[test]
    fn trace_spawn_link_events_match_otp() {
        trace_pattern_diff(
            "trace_t3a_spawn_link_events",
            "-module(trace_t3a_spawn_link_events). -export([run/0,child/1]). run() -> Parent=self(), 1=erlang:trace(Parent,true,[procs,set_on_first_spawn]), ParentFlags=erlang:trace_info(Parent,flags), Child=spawn_link(trace_t3a_spawn_link_events,child,[Parent]), ChildFlags=erlang:trace_info(Child,flags), Spawned=receive {trace,Child,spawned,Parent,_MFA} -> true after 1000 -> false end, Linked=receive {trace,Child,getting_linked,Parent} -> true after 1000 -> false end, Child!go, receive done -> ok end, {ParentFlags,ChildFlags,Spawned,Linked}. child(Parent) -> receive go -> Parent!done end.",
        );
    }

    #[test]
    fn tracer_can_set_call_pattern_while_tracee_waits() {
        trace_pattern_diff(
            "trace_t3a_tracer_sets_pattern",
            "-module(trace_t3a_tracer_sets_pattern). -export([run/0,foo/0]). run() -> Parent=self(), Tracer=spawn(fun() -> 1=erlang:trace(Parent,true,[call]), receive {apply,From} -> N=erlang:trace_pattern({trace_t3a_tracer_sets_pattern,foo,0},true,[]), From!{apply_result,N} end end), Tracer!{apply,self()}, N=receive {apply_result,Result} -> Result after 1000 -> timeout end, foo(), Event=receive {trace,Parent,call,{trace_t3a_tracer_sets_pattern,foo,[]}} -> true after 1000 -> false end, {N,Event}. foo() -> ok.",
        );
    }

    #[test]
    fn child_can_set_call_pattern_without_tracing_the_caller() {
        trace_pattern_diff(
            "trace_t3a_child_sets_pattern",
            "-module(trace_t3a_child_sets_pattern). -export([run/0]). run() -> Parent=self(), Tracer=spawn(fun() -> receive apply_pattern -> N=erlang:trace_pattern({trace_t3a_child_sets_pattern,no_such,0},true,[]), Parent!{pattern_result,N} end end), Tracer!apply_pattern, receive {pattern_result,N} -> N after 1000 -> timeout end.",
        );
    }

    #[test]
    fn send_event_match_spec_uses_destination_and_message_arguments() {
        trace_pattern_diff(
            "trace_t3a_send_match_spec",
            "-module(trace_t3a_send_match_spec). -export([run/0]). run() -> Parent=self(), S=trace:session_create(s,Parent,[]), 1=trace:send(S,[{['$1','_'],[{is_pid,'$1'}],[{message,4711}]}],[]), P=spawn(fun() -> receive go -> Parent!hello end end), 1=trace:process(S,P,true,[send]), P!go, receive {trace,P,send,hello,Parent,4711} -> {is_pid(P),is_pid(Parent),4711} after 1000 -> missing end.",
        );
    }

    #[test]
    fn trace_pattern_local_call_event_matches_otp() {
        trace_pattern_diff(
            "trace_t3a_call",
            "-module(trace_t3a_call). -export([run/0]). run() -> Parent=self(), P=spawn(fun() -> receive go -> f(), Parent ! done end end), erlang:trace(P,true,[call]), erlang:trace_pattern({trace_t3a_call,f,0},true,[local]), P ! go, receive {trace,P,call,{trace_t3a_call,f,[]}} -> ok after 1000 -> missing end. f() -> ok.",
        );
    }

    #[test]
    fn trace_pattern_call_count_matches_otp() {
        trace_pattern_diff(
            "trace_t3a_count",
            "-module(trace_t3a_count). -export([run/0]). run() -> erlang:trace_pattern({trace_t3a_count,f,0},true,[call_count]), f(), erlang:trace_info({trace_t3a_count,f,0},call_count). f() -> ok.",
        );
    }

    #[test]
    fn trace_pattern_match_spec_matches_otp() {
        trace_pattern_diff(
            "trace_t3a_ms",
            "-module(trace_t3a_ms). -export([run/0]). run() -> Parent=self(), P=spawn(fun() -> receive go -> f(ok), Parent ! done end end), erlang:trace(P,true,[call]), erlang:trace_pattern({trace_t3a_ms,f,1}, [{'_',[],[]}],[local]), P ! go, receive {trace,P,call,{trace_t3a_ms,f,[ok]}} -> ok after 1000 -> missing end. f(_) -> ok.",
        );
    }

    #[test]
    fn trace_pattern_message_action_keeps_heap_terms_alive_like_otp() {
        trace_pattern_diff(
            "trace_t3a_ms_message",
            "-module(trace_t3a_ms_message). -export([run/0]). run() -> Parent=self(), P=spawn(fun() -> receive go -> f({payload,42}), Parent ! done end end), erlang:trace(P,true,[call]), erlang:trace_pattern({trace_t3a_ms_message,f,1}, [{['$1'],[],[{message,['$1']}]}],[local]), P ! go, receive {trace,P,call,{trace_t3a_ms_message,f,[{payload,42}]},[{payload,42}]} -> receive done -> ok after 1000 -> no_done end; Other -> Other after 1000 -> missing end. f(_) -> ok.",
        );
    }

    #[test]
    fn trace_pattern_matches_function_arguments_like_otp() {
        trace_pattern_diff(
            "trace_t3a_ms_args",
            "-module(trace_t3a_ms_args). -export([run/0]). run() -> Parent=self(), P=spawn(fun() -> receive go -> f(a), f(#{b=>c}), Parent ! done end end), erlang:trace(P,true,[call]), erlang:trace_pattern({trace_t3a_ms_args,f,1}, [{['$1'],[{'==','$1',#{b=>c}}],[{return_trace}]}],[local]), P ! go, receive {trace,P,call,{trace_t3a_ms_args,f,[#{b:=c}]}} -> receive {trace,P,return_from,{trace_t3a_ms_args,f,1},ok} -> ok after 1000 -> missing_return end after 1000 -> missing_call end. f(_) -> ok.",
        );
    }

    #[test]
    fn trace_pattern_global_export_call_matches_otp() {
        trace_pattern_diff(
            "trace_t3a_global",
            "-module(trace_t3a_global). -export([run/0, f/0]). run() -> Parent=self(), P=spawn(fun() -> receive go -> trace_t3a_global:f(), Parent ! done end end), erlang:trace(P,true,[call]), erlang:trace_pattern({trace_t3a_global,f,0},true,[global]), P ! go, receive {trace,P,call,{trace_t3a_global,f,[]}} -> ok after 1000 -> missing end. f() -> ok.",
        );
    }

    #[test]
    fn trace_pattern_return_trace_matches_otp() {
        trace_pattern_diff(
            "trace_t3a_return",
            "-module(trace_t3a_return). -export([run/0]). run() -> Parent=self(), P=spawn(fun() -> receive go -> f(), Parent ! done end end), erlang:trace(P,true,[call]), erlang:trace_pattern({trace_t3a_return,f,0}, [{'_',[],[{return_trace}]}],[local]), P ! go, receive {trace,P,return_from,{trace_t3a_return,f,0},ok} -> ok after 1000 -> missing end. f() -> ok.",
        );
    }

    #[test]
    fn trace_pattern_message_true_omits_extra_matches_otp() {
        trace_pattern_diff(
            "trace_t3a_message_true",
            "-module(trace_t3a_message_true). -export([run/0]). run() -> Parent=self(), P=spawn(fun() -> receive go -> f(a,a), Parent ! done end end), erlang:trace(P,true,[call]), erlang:trace_pattern({trace_t3a_message_true,f,2}, [{'_',[],[{message,4711},{message,true}]}],[local]), P ! go, receive {trace,P,call,{trace_t3a_message_true,f,[a,a]}} -> receive done -> ok after 1000 -> no_done end; Other -> Other after 1000 -> missing end. f(_,_) -> ok.",
        );
    }

    #[test]
    fn trace_pattern_silent_flag_updates_match_otp() {
        trace_pattern_diff(
            "trace_t3a_silent_flag",
            "-module(trace_t3a_silent_flag). -export([run/0,f/1]). run() -> Parent=self(), P=spawn(fun() -> receive go -> trace_t3a_silent_flag:f(start), trace_t3a_silent_flag:f(c), trace_t3a_silent_flag:f(stop), trace_t3a_silent_flag:f(d), Parent ! done end end), erlang:trace(P,true,[call,silent]), erlang:trace_pattern({trace_t3a_silent_flag,f,1}, [{[start],[],[{silent,false},{message,start}]},{[stop],[],[{silent,true},{message,stop}]},{['$1'],[],[{message,'$1'}]}],[global]), P ! go, receive done -> flush([]) end. flush(A) -> receive {trace,_,call,Call,Extra} -> flush([{Call,Extra}|A]); {trace,_,call,Call} -> flush([{Call,none}|A]) after 20 -> lists:reverse(A) end. f(_) -> ok.",
        );
    }

    #[test]
    fn trace_pattern_silent_global_match_spec_matches_suite() {
        trace_pattern_diff(
            "trace_t3a_silent_global_suite",
            "-module(trace_t3a_silent_global_suite). -export([run/0,runner/1,f1/1]).\nrun() -> Parent=self(), P=spawn(trace_t3a_silent_global_suite,runner,[Parent]), erlang:trace(P,true,[call,silent]), erlang:trace_pattern({trace_t3a_silent_global_suite,f1,1}, [{[start],[],[{silent,false},{message,start}]},{[stop],[],[{silent,true},{message,stop}]},{[miss],[],[{silent,neither_true_nor_false},{message,miss}]},{['$1'],[],[{message,'$1'}]}],[global]), P ! go, receive done -> flush([]) end.\nrunner(Parent) -> receive go -> trace_t3a_silent_global_suite:f1(a), trace_t3a_silent_global_suite:f1(miss), trace_t3a_silent_global_suite:f1(b), trace_t3a_silent_global_suite:f1(start), trace_t3a_silent_global_suite:f1(c), f1(d), trace_t3a_silent_global_suite:f1(miss), trace_t3a_silent_global_suite:f1(e), trace_t3a_silent_global_suite:f1(stop), trace_t3a_silent_global_suite:f1(f), Parent ! done end.\nflush(A) -> receive {trace,_,call,Call,Extra} -> flush([{call,Call,Extra}|A]); {trace,_,call,Call} -> flush([{call,Call,none}|A]) after 20 -> lists:reverse(A) end.\nf1(_) -> ok.",
        );
    }

    #[test]
    fn trace_pattern_silent_local_match_spec_matches_suite() {
        trace_pattern_diff(
            "trace_t3a_silent_local_suite",
            "-module(trace_t3a_silent_local_suite). -export([run/0,runner/1,f1/1]).\nrun() -> Parent=self(), P=spawn(trace_t3a_silent_local_suite,runner,[Parent]), erlang:trace(P,true,[call,silent]), erlang:trace_pattern({trace_t3a_silent_local_suite,f1,1}, [{[start],[],[{silent,false},{message,start}]},{[stop],[],[{silent,true},{message,stop}]},{['$1'],[],[{message,'$1'}]}],[local]), P ! go, receive done -> flush([]) end.\nrunner(Parent) -> receive go -> trace_t3a_silent_local_suite:f1(a), f1(b), trace_t3a_silent_local_suite:f1(start), trace_t3a_silent_local_suite:f1(c), f1(d), f1(stop), trace_t3a_silent_local_suite:f1(e), f1(f), Parent ! done end.\nflush(A) -> receive {trace,_,call,Call,Extra} -> flush([{call,Call,Extra}|A]); {trace,_,call,Call} -> flush([{call,Call,none}|A]) after 20 -> lists:reverse(A) end.\nf1(_) -> ok.",
        );
    }

    #[test]
    fn trace_pattern_caller_line_matches_otp() {
        trace_pattern_diff(
            "trace_t3a_caller_line",
            "-module(trace_t3a_caller_line). -export([run/0,runner/1,f2/0,f3/0]).\nrun() -> Parent=self(), P=spawn(trace_t3a_caller_line,runner,[Parent]), erlang:trace(P,true,[call]), erlang:trace_pattern({trace_t3a_caller_line,f2,0}, [{[],[],[{message,{caller_line}}]}],[global]), P ! go, receive {trace,P,call,{trace_t3a_caller_line,f2,[]},Caller} -> Caller after 1000 -> missing end.\nrunner(Parent) -> receive go -> f3(), Parent ! done end.\nf3() -> trace_t3a_caller_line:f2(), ok.\nf2() -> ok.",
        );
    }

    #[test]
    fn trace_pattern_message_false_keeps_return_trace_matches_otp() {
        trace_pattern_diff(
            "trace_t3b_msg_false",
            "-module(trace_t3b_msg_false). -export([run/0]). run() -> Parent=self(), P=spawn(fun() -> receive go -> f(1), Parent ! done end end), erlang:trace(P,true,[call]), erlang:trace_pattern({trace_t3b_msg_false,f,1}, [{'_',[],[{return_trace},{message,false}]}],[local]), P ! go, receive {trace,P,return_from,{trace_t3b_msg_false,f,1},ok} -> receive {trace,P,call,_} -> call_traced after 200 -> ok end after 1000 -> missing end. f(_) -> ok.",
        );
    }

    #[test]
    fn trace_pattern_bif_return_and_apply_match_otp() {
        trace_pattern_diff(
            "trace_t3b_bif_apply",
            "-module(trace_t3b_bif_apply). -export([run/0]). run() -> Parent=self(), P=spawn(fun() -> receive go -> catch erlang:apply(erlang,error,[x]), catch erlang:throw(y), Parent ! done end end), erlang:trace(P,true,[call]), erlang:trace_pattern({erlang,error,1}, [{'_',[],[{exception_trace}]}],[global]), erlang:trace_pattern({erlang,throw,1}, [{'_',[],[{exception_trace}]}],[global]), P ! go, receive done -> ok end, flush(). flush() -> receive {trace,_,Tag,MFA,R} -> [{Tag,MFA,R}|flush()]; {trace,_,Tag,MFA} -> [{Tag,MFA}|flush()] after 300 -> [] end.",
        );
    }

    #[test]
    fn trace_pattern_on_load_state_matches_otp() {
        trace_pattern_diff(
            "trace_t3b_on_load",
            "-module(trace_t3b_on_load). -export([run/0]). run() -> A=erlang:trace_pattern(on_load, [], []), B=erlang:trace_info(on_load, traced), C=erlang:trace_pattern(on_load, true, [local]), D=erlang:trace_info(on_load, traced), E=erlang:trace_pattern(on_load, false, [local]), F=erlang:trace_info(on_load, match_spec), G=catch erlang:trace_pattern({'_',foo,1}, true, []), {A,B,C,D,E,F,element(1,G)}.",
        );
    }

    #[test]
    fn trace_pattern_exception_trace_matches_otp() {
        trace_pattern_diff(
            "trace_t3a_exception",
            "-module(trace_t3a_exception). -export([run/0]). run() -> Parent=self(), P=spawn(fun() -> receive go -> try f() catch error:boom -> ok end, Parent ! done end end), erlang:trace(P,true,[call]), erlang:trace_pattern({trace_t3a_exception,f,0}, [{'_',[],[{exception_trace}]}],[local]), P ! go, receive {trace,P,exception_from,{trace_t3a_exception,f,0},{error,boom}} -> ok after 1000 -> missing end. f() -> erlang:error(boom).",
        );
    }

    #[test]
    fn trace_pattern_exception_trace_includes_successful_return_like_otp() {
        trace_pattern_diff(
            "trace_t3a_exception_return",
            "-module(trace_t3a_exception_return). -export([run/0]). run() -> Parent=self(), P=spawn(fun() -> receive go -> f(), Parent ! done end end), erlang:trace(P,true,[call]), erlang:trace_pattern({trace_t3a_exception_return,f,0}, [{'_',[],[{exception_trace}]}],[local]), P ! go, receive {trace,P,return_from,{trace_t3a_exception_return,f,0},ok} -> receive done -> ok after 1000 -> trace_only end after 1000 -> missing end. f() -> ok.",
        );
    }

    #[test]
    fn trace_pattern_return_to_matches_otp() {
        trace_pattern_diff(
            "trace_t3a_return_to",
            "-module(trace_t3a_return_to). -export([run/0]). run() -> Parent=self(), P=spawn(fun() -> worker(Parent) end), erlang:trace(P,true,[call,return_to]), erlang:trace_pattern({trace_t3a_return_to,f,0},true,[local]), P ! go, receive {trace,P,return_to,{trace_t3a_return_to,worker,1}} -> ok after 1000 -> missing end. worker(Parent) -> receive go -> f(), Parent ! done end. f() -> ok.",
        );
    }

    #[test]
    fn return_to_trace_preserves_live_y_registers_like_otp() {
        let Ok(reference) = RefErl::start() else {
            eprintln!("erl unavailable; skipping return_to stack differential test");
            return;
        };
        let source = "-module(trace_t3a_return_to_stack). -export([run/0,g/1,h/1]). run() -> [t(Action,FlagMode) || Action <- [none,return_trace,exception_trace], FlagMode <- [call,return_to]]. t(Action,FlagMode) -> Tracer=spawn(fun() -> receive after infinity -> ok end end), OldGL=group_leader(), GL=spawn(fun Loop() -> receive {io_request,From,ReplyAs,_} -> From ! {io_reply,ReplyAs,ok}, Loop(); stop -> ok end end), true=group_leader(GL,self()), Actions=case Action of none -> []; return_trace -> [return_trace]; exception_trace -> [exception_trace] end, Mprog=[{'_',[],Actions}], Flags=case FlagMode of call -> [call]; return_to -> [call,return_to] end, erlang:trace_pattern({trace_t3a_return_to_stack,'_','_'},Mprog,[local]), erlang:trace(self(),true,[{tracer,Tracer}|Flags]), A=g(3), R=try io:format(\"\",[]) of V -> V catch C:E -> {C,E} end, erlang:trace(self(),false,[{tracer,Tracer}|Flags]), erlang:trace_pattern({trace_t3a_return_to_stack,'_','_'},false,[local]), true=group_leader(OldGL,self()), GL ! stop, {A,R}. g(X) -> h(X)+1. h(X) -> X*2.";
        let module = "trace_t3a_return_to_stack";
        let beam = reference.compile_named(module, source, &[]).unwrap();
        reference.load(module, &beam).unwrap();
        let mut vm = Vm::new([]);
        vm.load_bytes(&beam).unwrap();
        let expected = reference.call(module, "run", &[]);
        let actual = vm.eval_scheduled(module, "run", &[], 1, None).unwrap();
        assert_eq!(expected, CallResult::Ok(actual.term));
    }

    #[test]
    fn trace_send_flag_is_recorded_and_cleared() {
        let process = Process::new();
        let pid = Pid::new(7001, 1);
        configure(&process, pid, true, SEND, Tracer::Pid(pid));
        assert_eq!(flags(&process, pid), SEND);
        configure(&process, pid, false, SEND, Tracer::Pid(pid));
        assert_eq!(flags(&process, pid), 0);
    }

    #[test]
    fn trace_receive_flag_is_recorded() {
        let process = Process::new();
        let pid = Pid::new(7002, 1);
        configure(&process, pid, true, RECEIVE, Tracer::Pid(pid));
        assert_eq!(flags(&process, pid), RECEIVE);
        configure(&process, pid, false, RECEIVE, Tracer::Pid(pid));
    }

    #[test]
    fn trace_procs_flags_are_recorded() {
        let process = Process::new();
        let pid = Pid::new(7003, 1);
        configure(
            &process,
            pid,
            true,
            PROCS | SET_ON_SPAWN | SET_ON_LINK,
            Tracer::Pid(pid),
        );
        assert_eq!(flags(&process, pid), PROCS | SET_ON_SPAWN | SET_ON_LINK);
        configure(
            &process,
            pid,
            false,
            PROCS | SET_ON_SPAWN | SET_ON_LINK,
            Tracer::Pid(pid),
        );
    }

    #[test]
    fn trace_timestamp_flags_are_recorded() {
        let process = Process::new();
        let pid = Pid::new(7004, 1);
        let bits = TIMESTAMP | MONOTONIC_TIMESTAMP | STRICT_MONOTONIC_TIMESTAMP;
        configure(&process, pid, true, bits, Tracer::Pid(pid));
        assert_eq!(flags(&process, pid) & bits, bits);
        configure(&process, pid, false, bits, Tracer::Pid(pid));
    }

    #[test]
    fn trace_receive_message_shape_matches_otp() {
        let Ok(reference) = RefErl::start() else {
            eprintln!("erl unavailable; skipping trace differential test");
            return;
        };
        let beam = reference.compile_named("trace_t1_shape", "-module(trace_t1_shape). -export([run/0]). run() -> Parent=self(), Child=spawn(fun() -> receive ping -> ok end end), erlang:trace(Child,true,['receive']), Child ! ping, receive {trace,Child,'receive',ping} -> {trace,is_pid(Child),'receive',ping} after 1000 -> timeout end.", &[]).unwrap();
        reference.load("trace_t1_shape", &beam).unwrap();
        let expected = reference.call("trace_t1_shape", "run", &[]);
        let mut vm = Vm::new([]);
        vm.load_bytes(&beam).unwrap();
        let actual = vm
            .eval_scheduled("trace_t1_shape", "run", &[], 2, None)
            .unwrap();
        assert_eq!(expected, CallResult::Ok(actual.term));
    }

    #[test]
    fn trace_send_message_shape_matches_otp() {
        let Ok(reference) = RefErl::start() else {
            eprintln!("erl unavailable; skipping trace send differential test");
            return;
        };
        let source = "-module(trace_t1_send). -export([run/0]). run() -> Parent=self(), Child=spawn(fun() -> receive go -> Parent ! done end end), erlang:trace(Child,true,[send]), Child ! go, receive {trace,Child,send,done,Parent} -> {send,is_pid(Child)} after 1000 -> timeout end.";
        let beam = reference
            .compile_named("trace_t1_send", source, &[])
            .unwrap();
        reference.load("trace_t1_send", &beam).unwrap();
        let expected = reference.call("trace_t1_send", "run", &[]);
        let mut vm = Vm::new([]);
        vm.load_bytes(&beam).unwrap();
        let actual = vm
            .eval_scheduled("trace_t1_send", "run", &[], 2, None)
            .unwrap();
        assert_eq!(expected, CallResult::Ok(actual.term));
    }

    #[test]
    fn trace_timestamp_event_shape_matches_otp() {
        let Ok(reference) = RefErl::start() else {
            eprintln!("erl unavailable; skipping trace timestamp differential test");
            return;
        };
        let source = "-module(trace_t1_timestamp). -export([run/0]). run() -> Parent=self(), Child=spawn(fun() -> receive ping -> ok end end), erlang:trace(Child,true,['receive',timestamp]), Child ! ping, receive {trace_ts,Child,'receive',ping,Stamp} -> {timestamp,is_tuple(Stamp),tuple_size(Stamp)} after 1000 -> timeout end.";
        let beam = reference
            .compile_named("trace_t1_timestamp", source, &[])
            .unwrap();
        reference.load("trace_t1_timestamp", &beam).unwrap();
        let expected = reference.call("trace_t1_timestamp", "run", &[]);
        let mut vm = Vm::new([]);
        vm.load_bytes(&beam).unwrap();
        let actual = vm
            .eval_scheduled("trace_t1_timestamp", "run", &[], 2, None)
            .unwrap();
        assert_eq!(expected, CallResult::Ok(actual.term));
    }

    #[test]
    fn trace_info_flags_and_tracer_match_otp() {
        let Ok(reference) = RefErl::start() else {
            eprintln!("erl unavailable; skipping trace_info differential test");
            return;
        };
        let source = "-module(trace_t1_info). -export([run/0]). run() -> P=self(), erlang:trace(P,true,[send,timestamp]), {erlang:trace_info(P,flags),element(1,erlang:trace_info(P,tracer)),is_pid(element(2,erlang:trace_info(P,tracer)))}.";
        let beam = reference
            .compile_named("trace_t1_info", source, &[])
            .unwrap();
        reference.load("trace_t1_info", &beam).unwrap();
        let expected = reference.call("trace_t1_info", "run", &[]);
        let mut vm = Vm::new([]);
        vm.load_bytes(&beam).unwrap();
        let actual = vm
            .eval_scheduled("trace_t1_info", "run", &[], 2, None)
            .unwrap();
        assert_eq!(expected, CallResult::Ok(actual.term));
    }

    #[test]
    fn trace_sessions_keep_independent_process_flags() {
        let Ok(reference) = RefErl::start() else {
            eprintln!("erl unavailable; skipping trace session differential test");
            return;
        };
        let source = "-module(trace_t4_sessions). -export([run/0]). run() -> Parent=self(), A=trace:session_create(a,Parent,[]), B=trace:session_create(b,Parent,[]), P=spawn(fun() -> receive go -> Parent ! payload, receive stop -> ok end end end), trace:process(A,P,true,[send]), trace:process(B,P,true,['receive']), P ! go, R1=receive {trace,P,send,payload,Parent} -> true after 1000 -> false end, R2=receive {trace,P,'receive',go} -> true after 1000 -> false end, I1=trace:info(A,P,flags), I2=trace:info(B,P,flags), P ! stop, trace:session_destroy(A), trace:session_destroy(B), {R1,R2,I1,I2}.";
        let beam = reference
            .compile_named("trace_t4_sessions", source, &[])
            .unwrap();
        reference.load("trace_t4_sessions", &beam).unwrap();
        let expected = reference.call("trace_t4_sessions", "run", &[]);
        let mut vm = Vm::new([]);
        vm.load_bytes(&beam).unwrap();
        let actual = vm
            .eval_scheduled("trace_t4_sessions", "run", &[], 2, None)
            .unwrap_or_else(|error| panic!("session VM error: {error:?}"));
        assert_eq!(expected, CallResult::Ok(actual.term));
    }

    #[test]
    fn trace_session_destroy_is_idempotent() {
        let process = Process::new();
        let session = create_session(
            &process,
            "trace_test".to_owned(),
            Tracer::Pid(Pid::new(7005, 1)),
        );
        crate::trace_bp::set_trace_pattern(
            &process,
            session.0,
            &[crate::trace_bp::BpFunction {
                module: "trace_test".into(),
                function: "function".into(),
                arity: 0,
                exported: true,
            }],
            None,
            None,
            crate::trace_bp::BreakOp::Set,
            crate::trace_bp::TracePatternFlags::default(),
            &Tracer::Default,
        );
        let traced = |process: &Process| {
            crate::trace_bp::function_info(
                process,
                session.0,
                "trace_test",
                "function",
                0,
                crate::trace_bp::WANT_TRACE,
            )
            .got
        };
        assert_eq!(traced(&process), crate::trace_bp::GOT_GLOBAL);
        assert!(destroy_session(&process, session.0));
        crate::trace_bp::clear_session(&process, session.0);
        assert_eq!(traced(&process), 0);
        assert!(!destroy_session(&process, session.0));
    }

    #[test]
    fn trace_sessions_store_flags_independently() {
        let process = Process::new();
        let pid = Pid::new(7006, 1);
        let a = create_session(&process, "a".to_owned(), Tracer::Pid(pid));
        let b = create_session(&process, "b".to_owned(), Tracer::Pid(pid));
        configure_session(&process, a.0, pid, true, SEND, Tracer::Pid(pid));
        configure_session(&process, b.0, pid, true, RECEIVE, Tracer::Pid(pid));
        assert_eq!(session_flags(&process, a.0, pid), SEND);
        assert_eq!(session_flags(&process, b.0, pid), RECEIVE);
        destroy_session(&process, a.0);
        destroy_session(&process, b.0);
    }

    #[test]
    fn trace_session_info_all_matches_otp() {
        let Ok(reference) = RefErl::start() else {
            eprintln!("erl unavailable; skipping trace session info differential test");
            return;
        };
        let source = "-module(trace_t4_session_info). -export([run/0]). run() -> Before=trace:session_info(all), S=trace:session_create(sample,self(),[]), During=trace:session_info(all), 1=trace:process(S,self(),true,[send]), Tracees=trace:session_info(self()), true=trace:session_destroy(S), After=trace:session_info(all), {Before,During,Tracees,After}.";
        let beam = reference
            .compile_named("trace_t4_session_info", source, &[])
            .unwrap();
        reference.load("trace_t4_session_info", &beam).unwrap();
        let expected = reference.call("trace_t4_session_info", "run", &[]);
        let mut vm = Vm::new([]);
        vm.load_bytes(&beam).unwrap();
        let actual = vm
            .eval_scheduled("trace_t4_session_info", "run", &[], 2, None)
            .unwrap_or_else(|error| panic!("session info VM error: {error:?}"));
        assert_eq!(expected, CallResult::Ok(actual.term));
    }

    #[test]
    fn trace_session_info_process_and_port_matches_otp() {
        let Ok(reference) = RefErl::start() else {
            eprintln!("erl unavailable; skipping per-tracee session info differential test");
            return;
        };
        let source = "-module(trace_t4_tracee_info). -export([run/0]). run() -> S=trace:session_create(sample,self(),[]), 1=trace:process(S,self(),true,[procs]), Port=hd(erlang:ports()), 1=trace:port(S,Port,true,[ports]), Result={trace:session_info(self()),trace:session_info(Port)}, trace:session_destroy(S), Result.";
        let beam = reference
            .compile_named("trace_t4_tracee_info", source, &[])
            .unwrap();
        reference.load("trace_t4_tracee_info", &beam).unwrap();
        let expected = reference.call("trace_t4_tracee_info", "run", &[]);
        let mut vm = Vm::new([]);
        vm.load_bytes(&beam).unwrap();
        let actual = vm
            .eval_scheduled("trace_t4_tracee_info", "run", &[], 2, None)
            .unwrap_or_else(|error| panic!("per-tracee session info VM error: {error:?}"));
        assert_eq!(expected, CallResult::Ok(actual.term));
    }

    #[test]
    fn trace_session_destroy_info_matches_otp() {
        let Ok(reference) = RefErl::start() else {
            eprintln!("erl unavailable; skipping trace session destroy differential test");
            return;
        };
        let source = "-module(trace_t4_destroy_info). -export([run/0,exported/1]). run() -> S=trace:session_create(sample,self(),[]), Exp={trace_t4_destroy_info,exported,1}, Loc={trace_t4_destroy_info,local,1}, CallMS=[{[arg],[],[]}], SendMS=[{[self(),message],[],[]}], RecvMS=[{[node(),self(),message],[],[]}], A=trace:function(S,Exp,CallMS,[global]), B=trace:function(S,Loc,CallMS,[local]), C=trace:function(S,on_load,CallMS,[local]), D=trace:send(S,SendMS,[]), E=trace:recv(S,RecvMS,[]), F=trace:process(S,new_processes,true,[all]), G=trace:port(S,new_ports,true,[all]), H=trace:process(S,self(),true,[procs]), [Port|_]=erlang:ports(), I=trace:port(S,Port,true,[ports]), Info={[A,B,C,D,E,F,G,H,I],[trace:session_info(X) || X <- [Exp,Loc,on_load,send,'receive',new_processes,new_ports,self(),Port]],[trace:info(S,X,traced) || X <- [Exp,Loc,on_load]],[trace:info(S,X,flags) || X <- [new_processes,new_ports,self(),Port]],[norm_ms(trace:info(S,send,match_spec)),norm_ms(trace:info(S,'receive',match_spec))]}, true=trace:session_destroy(S), After=[trace:session_info(X) || X <- [Exp,Loc,on_load,send,'receive',new_processes,new_ports,self(),Port]], {Info,After}. norm_ms({match_spec,[{[Pid,message],[],[]}]}) -> {match_spec,[{[is_pid(Pid),message],[],[]}]}; norm_ms({match_spec,[{[Node,Pid,message],[],[]}]}) -> {match_spec,[{[Node,is_pid(Pid),message],[],[]}]}. exported(_) -> ok. local(_) -> ok.";
        let beam = reference
            .compile_named("trace_t4_destroy_info", source, &[])
            .unwrap();
        reference.load("trace_t4_destroy_info", &beam).unwrap();
        let expected = reference.call("trace_t4_destroy_info", "run", &[]);
        let mut vm = Vm::new([]);
        vm.load_bytes(&beam).unwrap();
        let actual = vm
            .eval_scheduled("trace_t4_destroy_info", "run", &[], 2, None)
            .unwrap_or_else(|error| panic!("trace session destroy VM error: {error:?}"));
        assert_eq!(expected, CallResult::Ok(actual.term));
    }

    #[test]
    fn trace_session_gc_drop_matches_otp() {
        let Ok(reference) = RefErl::start() else {
            eprintln!("erl unavailable; skipping trace session GC differential test");
            return;
        };
        let source = "-module(trace_t4_session_gc). -export([run/0,helper/0]). run() -> erts_debug:set_internal_state(available_internal_state,true), Before=trace:session_info(all), make_session(self()), erase(session), garbage_collect(), wait(5), After=trace:session_info(all), Functions=trace:session_info({trace_t4_session_gc,helper,0}), {Before,After,Functions}. make_session(Parent) -> Session=trace:session_create(sample,Parent,[]), put(session,Session), 1=trace:process(Session,Parent,true,[send]), 1=trace:function(Session,{trace_t4_session_gc,helper,0},true,[global]), ok. wait(0) -> ok; wait(N) -> ok=erts_debug:set_internal_state(wait,thread_progress), wait(N-1). helper() -> ok.";
        let beam = reference
            .compile_named("trace_t4_session_gc", source, &[])
            .unwrap();
        reference.load("trace_t4_session_gc", &beam).unwrap();
        let expected = reference.call("trace_t4_session_gc", "run", &[]);
        let mut vm = Vm::new([]);
        vm.load_bytes(&beam).unwrap();
        let actual = vm
            .eval_scheduled("trace_t4_session_gc", "run", &[], 2, None)
            .unwrap_or_else(|error| panic!("trace session GC VM error: {error:?}"));
        assert_eq!(expected, CallResult::Ok(actual.term));
    }

    #[test]
    fn trace_session_dropped_with_process_dictionary_entry_matches_otp() {
        let Ok(reference) = RefErl::start() else {
            eprintln!("erl unavailable; skipping process dictionary session GC test");
            return;
        };
        // The dictionary is a GC root on the process heap: erasing the only strong handle and
        // collecting destroys the session, and the weak handle then fails with badarg.
        let source = "-module(trace_t8_dict_gc). -export([run/0]). run() -> erts_debug:set_internal_state(available_internal_state,true), [put({k,I},lists:seq(1,I*7)) || I <- lists:seq(1,13)], Weak=make_session(), erase(session), garbage_collect(), wait(5), After=trace:session_info(all), {'EXIT',{Reason,_}}=(catch trace:info(Weak,on_load,traced)), {After,Reason,length(get())}. make_session() -> {_,Weak}=Session=trace:session_create(sample,self(),[]), put(session,Session), 1=trace:process(Weak,self(),true,[procs]), Weak. wait(0) -> ok; wait(N) -> ok=erts_debug:set_internal_state(wait,thread_progress), wait(N-1).";
        let beam = reference
            .compile_named("trace_t8_dict_gc", source, &[])
            .unwrap();
        reference.load("trace_t8_dict_gc", &beam).unwrap();
        let expected = reference.call("trace_t8_dict_gc", "run", &[]);
        let mut vm = Vm::new([]);
        vm.load_bytes(&beam).unwrap();
        let actual = vm
            .eval_scheduled("trace_t8_dict_gc", "run", &[], 2, None)
            .unwrap_or_else(|error| panic!("dictionary session GC VM error: {error:?}"));
        assert_eq!(expected, CallResult::Ok(actual.term));
    }

    #[test]
    fn weak_trace_session_handles_match_otp() {
        let Ok(reference) = RefErl::start() else {
            eprintln!("erl unavailable; skipping weak trace session differential test");
            return;
        };
        let source = "-module(trace_t4_weak_handle). -export([run/0,helper/0]). run() -> Parent=self(), {_,Weak}=trace:session_create(sample,Parent,[]), 1=trace:process(Weak,Parent,true,[send]), 1=trace:function(Weak,{trace_t4_weak_handle,helper,0},true,[local]), [Weak]=trace:session_info({trace_t4_weak_handle,helper,0}), Flags=trace:info(Weak,Parent,flags), Destroyed=trace:session_destroy(Weak), {Flags,Destroyed,trace:session_info(all)}. helper() -> ok.";
        let beam = reference
            .compile_named("trace_t4_weak_handle", source, &[])
            .unwrap();
        reference.load("trace_t4_weak_handle", &beam).unwrap();
        let expected = reference.call("trace_t4_weak_handle", "run", &[]);
        let mut vm = Vm::new([]);
        vm.load_bytes(&beam).unwrap();
        let actual = vm
            .eval_scheduled("trace_t4_weak_handle", "run", &[], 2, None)
            .unwrap_or_else(|error| panic!("weak session handle VM error: {error:?}"));
        assert_eq!(expected, CallResult::Ok(actual.term));
    }

    #[test]
    fn trace_session_routes_call_events_and_keeps_legacy_info_isolated() {
        trace_pattern_diff(
            "trace_t4_session_call",
            "-module(trace_t4_session_call). -export([run/0, f/0]). run() -> Parent=self(), S=trace:session_create(sample,undefined,[]), Tracer=spawn(fun() -> 1=trace:process(S,Parent,true,[call]), Count=trace:function(S,{trace_t4_session_call,f,0},true,[global]), Parent!{ready,Count}, receive Event={trace,Parent,call,{trace_t4_session_call,f,[]}} -> Parent!Event after 1000 -> ok end end), {ready,PatternCount}=receive Ready -> Ready after 1000 -> timeout end, SessionFlags=trace:info(S,Parent,flags), LegacyFlags=erlang:trace_info(Parent,flags), Pattern=trace:info(S,{trace_t4_session_call,f,0},traced), trace_t4_session_call:f(), Event=receive {trace,Pid,call,{trace_t4_session_call,f,[]}} when Pid =:= Parent -> {trace,is_pid(Pid),call,{trace_t4_session_call,f,[]}} after 1000 -> missing end, {is_pid(Tracer),PatternCount,SessionFlags,LegacyFlags,Pattern,Event}. f() -> ok.",
        );
    }

    #[test]
    fn call_trace_flags_do_not_cross_trace_sessions() {
        trace_pattern_diff(
            "trace_t4_session_call_isolation",
            "-module(trace_t4_session_call_isolation). -export([run/0,f/0]). run() -> Parent=self(), A=trace:session_create(a,Parent,[]), B=trace:session_create(b,Parent,[]), 1=trace:process(A,Parent,true,[call]), 1=trace:function(B,{trace_t4_session_call_isolation,f,0},true,[global]), trace_t4_session_call_isolation:f(), Event=receive {trace,Parent,call,{trace_t4_session_call_isolation,f,[]}} -> unexpected after 0 -> quiet end, trace:session_destroy(A), trace:session_destroy(B), Event. f() -> ok.",
        );
    }

    #[test]
    fn trace_session_inherits_process_flags_on_spawn() {
        trace_pattern_diff(
            "trace_t4_session_spawn",
            "-module(trace_t4_session_spawn). -export([run/0]). run() -> Parent=self(), S=trace:session_create(sample,undefined,[]), 1=trace:process(S,Parent,true,[send,set_on_spawn]), P=spawn(fun() -> Parent!ready, receive hello -> Parent!ack end end), receive ready -> ok after 1000 -> timeout end, P!hello, receive ack -> ok after 1000 -> timeout end, (fun Collect(0,Acc) -> lists:reverse(Acc); Collect(N,Acc) -> receive {trace,Tracee,send,Message,To} when (Tracee =:= Parent orelse Tracee =:= P) andalso (Message =:= hello orelse Message =:= ack) -> Collect(N-1,[{is_pid(Tracee),Message,is_pid(To)}|Acc]) after 1000 -> timeout end end)(2,[]).",
        );
    }

    #[test]
    fn trace_pattern_with_empty_flags_is_a_global_call_trace() {
        trace_pattern_diff(
            "trace_t5_empty_flags",
            "-module(trace_t5_empty_flags). -export([run/0,f/1]). f(X) -> X. run() -> Me=self(), T=spawn(fun() -> receive {go,From} -> erlang:trace(From,true,[call]), erlang:trace_pattern({trace_t5_empty_flags,f,1},[],[]), From ! armed, receive stop -> ok end end end), T!{go,Me}, receive armed -> ok end, trace_t5_empty_flags:f(1), receive {trace,Me,call,{trace_t5_empty_flags,f,[1]}} -> T!stop, ok after 1000 -> timeout end.",
        );
    }

    #[test]
    fn match_trace_action_updates_tracee_before_next_receive() {
        trace_pattern_diff(
            "trace_t3_match_action_order",
            "-module(trace_t3_match_action_order). -export([run/0,control/3]). run() -> Parent=self(), Tracee=spawn(fun() -> receive stop -> Parent!done end end), 1=erlang:trace(Tracee,true,['receive',{tracer,Parent}]), 1=erlang:trace_pattern({trace_t3_match_action_order,control,3},[{['$1','$2','$3'],[],[{trace,'$1','$2','$3'}]}],[{meta,Parent}]), _Controller=spawn(fun() -> control(Tracee,['receive'],[]), Tracee!stop end), receive done -> ok after 1000 -> timeout end, Result=receive {trace,Tracee,'receive',stop} -> unexpected after 0 -> quiet end, erlang:trace_pattern({trace_t3_match_action_order,control,3},false,[meta]), Result. control(_,_,_) -> ok.",
        );
    }

    #[test]
    fn match_trace_action_does_not_restore_a_dead_tracer() {
        trace_pattern_diff(
            "trace_t3_dead_tracer_action",
            "-module(trace_t3_dead_tracer_action). -export([run/0,f/1]). run() -> Self=self(), TFun=fun F() -> receive M -> Self!M, F() end end, {Tracer,MRef}=spawn_monitor(TFun), MetaTracer=spawn_link(TFun), 1=erlang:trace_pattern({trace_t3_dead_tracer_action,f,1},[{'_',[],[{message,false},{trace,[],[call,{const,{tracer,Tracer}}]}]}],[{meta,MetaTracer}]), f(1), {tracer,Tracer}=erlang:trace_info(self(),tracer), exit(Tracer,stop), receive {'DOWN',MRef,_,_,_} -> ok end, f(2), Result=erlang:trace_info(self(),tracer), erlang:trace_pattern({trace_t3_dead_tracer_action,f,1},false,[meta]), Result. f(_) -> ok.",
        );
    }

    #[test]
    fn send_pattern_message_results_outlive_the_match_program() {
        trace_pattern_diff(
            "trace_t7_send_message",
            "-module(trace_t7_send_message). -export([run/0,sender/0]). sender() -> receive {go,To,M} -> To ! M, sender() end. run() -> R=spawn(fun L() -> receive _ -> L() end end), S=spawn(trace_t7_send_message,sender,[]), 1=erlang:trace(S,true,[send]), erlang:trace_pattern(send,[{['_','_'],[],[{message,\"4711\"}]}],[]), Strings=[begin S ! {go,R,m}, receive {trace,S,send,m,R,X} -> X after 1000 -> timeout end end || _ <- lists:seq(1,8)], erlang:trace_pattern(send,[{['_','_'],[],[{message,{process_dump}}]}],[]), S ! {go,R,m}, Dump=receive {trace,S,send,m,R,D} -> is_binary(D) after 1000 -> timeout end, {Strings,Dump}.",
        );
    }

    #[test]
    fn new_process_tracing_reaches_funs_spawned_with_spawn_1() {
        trace_pattern_diff(
            "trace_t6_new_fun_spawn",
            "-module(trace_t6_new_fun_spawn). -export([run/0]). run() -> Me=self(), T=spawn(fun() -> erlang:trace(new,true,[send]), Me!armed, receive stop -> ok end end), receive armed -> ok end, W=spawn(fun() -> receive go -> Me!done end end), {flags,F}=erlang:trace_info(W,flags), W!go, receive done -> ok end, T!stop, F.",
        );
    }
}
