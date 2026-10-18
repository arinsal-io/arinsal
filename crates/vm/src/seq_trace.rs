//! Sequential trace tokens carried with ordinary process messages.

use crate::process::Message;
use crate::{Process, Vm, VmError};
use arinsal_etf::OwnedTerm;
use arinsal_sched::{Pid, RunCtx};
use arinsal_term::{Term, TermBuilder, from_owned, to_owned};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

const SEND: u64 = 1;
const RECEIVE: u64 = 2;
const PRINT: u64 = 4;
const TIMESTAMP: u64 = 8;
// Port of erts/emulator/beam/erl_process.h:1820-1830 (SEQ_TRACE_* flags), OTP-29.1.1.
const STRICT_MONOTONIC: u64 = 16;
const MONOTONIC: u64 = 32;

pub(crate) const IMPLEMENTED: &[(&str, &str, u8)] = &[
    ("erlang", "seq_trace", 2),
    ("erlang", "seq_trace_info", 1),
    ("erlang", "seq_trace_print", 1),
    ("erlang", "seq_trace_print", 2),
];

pub(crate) fn recognizes(module: &str, function: &str, arity: u8) -> bool {
    IMPLEMENTED.contains(&(module, function, arity))
}

#[derive(Clone)]
/// The five-tuple `{Flags, Label, Serial, From, LastCnt}` of `SEQ_TRACE_TOKEN`
/// (erl_trace.h SEQ_TRACE_T_*), OTP-29.1.1.
pub(crate) struct Token {
    label: OwnedTerm,
    flags: u64,
    serial: u64,
    sender: OwnedTerm,
    lastcnt: u64,
    epoch: u64,
    /// Where a queued message's copy of the token lives (the words copied after the message
    /// term); `NIL` when it has none. Not part of the token's value.
    heap_ref: Term,
}

/// What a queued message says about the sequential trace token: erts keeps `NIL` for a message
/// sent by a process without a token, `am_undefined` for one from a port or another non-process
/// source, and the token tuple otherwise (ERL_MESSAGE_TOKEN).
#[derive(Default)]
pub(crate) enum SeqState {
    #[default]
    Undefined,
    Nil,
    Token(Box<Token>),
}

/// Whether receiving a message in this state touches the process's token.
#[inline(always)]
pub(crate) fn needs_receive(state: &SeqState, process: &Process) -> bool {
    match state {
        SeqState::Undefined => false,
        SeqState::Nil => has_token(process),
        SeqState::Token(_) => true,
    }
}

struct SeqEvent {
    kind: &'static str,
    sender: OwnedTerm,
    receiver: OwnedTerm,
    info: OwnedTerm,
}

#[inline(always)]
pub(crate) fn has_token(process: &Process) -> bool {
    process.seq_trace_token.is_some()
}
fn epoch() -> &'static AtomicU64 {
    static EPOCH: AtomicU64 = AtomicU64::new(0);
    &EPOCH
}
fn unique() -> &'static AtomicU64 {
    static UNIQUE: AtomicU64 = AtomicU64::new(0);
    &UNIQUE
}
fn tracer() -> &'static Mutex<OwnedTerm> {
    static TRACER: OnceLock<Mutex<OwnedTerm>> = OnceLock::new();
    TRACER.get_or_init(|| Mutex::new(OwnedTerm::atom("false")))
}
fn atom(term: Term, name: &str) -> bool {
    term.as_atom()
        .and_then(|atom| arinsal_term::global_atoms().text(atom))
        .is_some_and(|s| s == name)
}
fn badarg() -> VmError {
    VmError::Trap(crate::exceptions::Trap::error(crate::signals::atom(
        "badarg",
    )))
}
/// The process's token for `process_info(Pid, sequential_trace_token)`, read without clearing
/// a stale one. Port of erts/emulator/beam/erl_bif_info.c:2140 (ERTS_PI_IX_SEQUENTIAL_TRACE_TOKEN),
/// OTP-29.1.1.
pub(crate) fn token_of(process: &Process) -> Option<Token> {
    process
        .seq_trace_token
        .as_deref()
        .filter(|token| token.epoch == epoch().load(Ordering::Relaxed))
        .cloned()
}
/// The token as the term `process_info` reports, built on `process`.
pub(crate) fn token_term_on(process: &mut Process, token: Option<&Token>) -> Result<Term, VmError> {
    token_term(process, token)
}
/// Apply a `seq_trace:reset_trace/0` that happened since the process last looked: erts clears
/// every process's token, `seq_trace_clock` and `seq_trace_lastcnt` (bif.c:5150-5170).
pub(crate) fn sync_epoch(process: &mut Process) {
    let now = epoch().load(Ordering::Relaxed);
    if process.seq_trace_epoch != now {
        process.seq_trace_epoch = now;
        process.seq_trace_token = None;
        process.seq_token_root = Term::NIL;
        process.seq_trace_clock = 0;
        process.seq_trace_lastcnt = 0;
    }
}
fn token(process: &mut Process) -> Option<Token> {
    sync_epoch(process);
    if process.seq_trace_spawn_pending {
        process.seq_trace_spawn_pending = false;
        if let (Some(pid), Some(mut token)) = (process.self_pid, process.seq_trace_token.take()) {
            // The spawn reply the child sent (erl_process.c:12960-12965) bumped its serial.
            token.sender = pid
                .to_term()
                .and_then(|p| to_owned(p).ok())
                .unwrap_or_else(|| OwnedTerm::atom("undefined"));
            process.seq_trace_clock += 1;
            token.serial = process.seq_trace_clock;
            token.lastcnt = process.seq_trace_lastcnt;
            process.seq_trace_token = Some(token);
        }
    }
    process.seq_trace_token.as_deref().cloned()
}
fn put(process: &mut Process, value: Option<Token>) {
    if value.is_none() {
        process.seq_token_root = Term::NIL;
    }
    process.seq_trace_token = value.map(Box::new);
}

/// The `enabled` answer of the system tracer for `tracee` (erl_tracer_nif.c:114-140): a pid or
/// port tracer that is dead, or is the tracee itself, discards. A module tracer is asked when
/// the event is delivered. `None` means no system tracer is set.
fn tracer_enabled(process: &Process, tracee: Pid) -> Option<bool> {
    let tracer = tracer().lock().unwrap().clone();
    match tracer {
        OwnedTerm::Pid { .. } => {
            let pid = to_pid_term(&tracer)?;
            Some(
                pid != tracee
                    && process
                        .runtime
                        .as_ref()
                        .and_then(|runtime| runtime.scheduler().ok())
                        .is_some_and(|scheduler| scheduler.lookup(pid)),
            )
        }
        OwnedTerm::Port { .. } => Some(true),
        OwnedTerm::Tuple(_) => Some(true),
        _ => None,
    }
}

fn to_pid_term(term: &OwnedTerm) -> Option<Pid> {
    let OwnedTerm::Pid { id, serial, .. } = term else {
        return None;
    };
    Some(Pid::new(*id, *serial))
}

// Port of erts/emulator/beam/erl_trace.c:918-940 (seq_trace_update_serial), OTP-29.1.1.
fn update_serial(process: &mut Process, pid: Pid) -> Option<Token> {
    if tracer_enabled(process, pid) == Some(false) {
        return None;
    }
    let mut token = token(process)?;
    token.sender = pid
        .to_term()
        .and_then(|p| to_owned(p).ok())
        .unwrap_or_else(|| OwnedTerm::atom("undefined"));
    process.seq_trace_clock += 1;
    token.serial = process.seq_trace_clock;
    token.lastcnt = process.seq_trace_lastcnt;
    put(process, Some(token.clone()));
    Some(token)
}

// Port of erts/emulator/beam/erl_trace.c:449-489 (system sequential tracer), OTP-29.1.1.
pub(crate) fn set_system_tracer(
    vm: &Vm,
    process: &mut Process,
    value: Term,
) -> Result<Term, VmError> {
    let module_state = if value.classify() == arinsal_term::TermKind::Tuple {
        let (module, _) = crate::natives::proc::tuple2(value).ok_or_else(badarg)?;
        let module = module
            .as_atom()
            .and_then(|atom| arinsal_term::global_atoms().text(atom))
            .ok_or_else(badarg)?;
        if !crate::natives::nif::has_tracer_nifs(vm, module) {
            return Err(badarg());
        }
        true
    } else {
        false
    };
    if value != crate::signals::atom("false")
        && Pid::from_term(value).is_none()
        && value.as_port().is_none()
        && !module_state
    {
        return Err(badarg());
    }
    if let Some(pid) = Pid::from_term(value)
        && !process
            .runtime
            .as_ref()
            .and_then(|runtime| runtime.scheduler().ok())
            .is_some_and(|scheduler| scheduler.lookup(pid))
    {
        return Err(badarg());
    }
    let next = if value == crate::signals::atom("false") {
        OwnedTerm::atom("false")
    } else {
        to_owned(value).map_err(|_| badarg())?
    };
    let mut current = tracer().lock().unwrap();
    let old = std::mem::replace(&mut *current, next);
    from_owned(
        &old,
        &mut arinsal_bifs::ProcessHeapHandle(&mut process.heap),
    )
    .map_err(|e| VmError::Unsupported(format!("seq tracer: {e:?}")))
}

pub(crate) fn system_tracer_info(process: &mut Process) -> Result<Term, VmError> {
    let value = tracer().lock().unwrap().clone();
    let value = from_owned(
        &value,
        &mut arinsal_bifs::ProcessHeapHandle(&mut process.heap),
    )
    .map_err(|e| VmError::Unsupported(format!("seq tracer info: {e:?}")))?;
    TermBuilder::new(&mut process.heap)
        .tuple(&[crate::signals::atom("sequential_tracer"), value])
        .map_err(|e| VmError::Unsupported(format!("seq tracer info tuple: {e:?}")))
}

// Port of erts/emulator/beam/erl_bif_trace.c:3109-3125 (erts_seq_trace, sequential_trace_token), OTP-29.1.1.
pub(crate) fn set_token_value(
    process: &mut Process,
    _pid: Pid,
    value: Term,
) -> Result<Term, VmError> {
    if value != Term::NIL {
        return Err(badarg());
    }
    let old = token(process);
    put(process, None);
    token_term(process, old.as_ref())
}

// Port of erts/emulator/beam/erl_bif_trace.c:3133 (new_seq_trace_token), OTP-29.1.1.
fn token_term(process: &mut Process, token: Option<&Token>) -> Result<Term, VmError> {
    let Some(token) = token else {
        return Ok(Term::NIL);
    };
    token
        .build_on(&mut arinsal_bifs::ProcessHeapHandle(&mut process.heap))
        .map_err(|e| VmError::Unsupported(format!("seq token: {e:?}")))
}

impl Token {
    /// Where the copy of this token that travels with a queued message lives.
    pub(crate) fn heap_ref(&self) -> Term {
        self.heap_ref
    }

    pub(crate) fn heap_ref_mut(&mut self) -> &mut Term {
        &mut self.heap_ref
    }

    /// The heap copy as a collection root: a `seq_trace:reset_trace/0` since the token was
    /// made cleared it (`erts_proc_sig_clear_seq_trace_tokens`), so it names nothing.
    pub(crate) fn root(&self) -> Term {
        if self.epoch == epoch().load(Ordering::Relaxed) {
            self.heap_ref
        } else {
            Term::NIL
        }
    }

    /// The five-tuple built on `heap`.
    pub(crate) fn build_on<H: arinsal_term::HeapAlloc>(
        &self,
        heap: &mut H,
    ) -> Result<Term, arinsal_term::TermError> {
        let fields = [
            OwnedTerm::Int(self.flags as i64),
            self.label.clone(),
            OwnedTerm::Int(self.serial as i64),
            self.sender.clone(),
            OwnedTerm::Int(self.lastcnt as i64),
        ];
        let mut values = Vec::with_capacity(fields.len());
        for field in &fields {
            values.push(from_owned(field, heap)?);
        }
        TermBuilder::new(heap).tuple(&values)
    }

    /// Words the token takes on a heap: `size_object` of the five-tuple a send copies along
    /// with the message.
    // Port of erts/emulator/beam/erl_message.c (erts_send_message, seq_trace_size), OTP-29.1.1.
    pub(crate) fn heap_words(&self) -> usize {
        let mut scratch = arinsal_term::VecHeap::new();
        self.build_on(&mut scratch)
            .map_or(0, arinsal_term::size_object)
    }
}

pub(crate) fn get_token_term(process: &mut Process, _pid: Pid) -> Result<Term, VmError> {
    let token = token(process);
    token_term(process, token.as_ref())
}

/// Attach the sender's current token to an ordinary message and emit its send event.
// Port of erts/emulator/beam/erl_message.c:739-757 (erts_send_message, seq trace), OTP-29.1.1.
pub(crate) fn on_send(
    vm: Option<&mut Vm>,
    process: &mut Process,
    ctx: Option<&mut RunCtx<'_, Message>>,
    pid: Pid,
    receiver: Term,
    message: Term,
) -> Option<Box<Token>> {
    let token = update_serial(process, pid)?;
    if let (Ok(receiver), Ok(message)) = (to_owned(receiver), to_owned(message)) {
        emit(
            vm,
            process,
            ctx,
            &token,
            SeqEvent {
                kind: "send",
                sender: token.sender.clone(),
                receiver,
                info: message,
            },
        );
    }
    Some(Box::new(token))
}

/// Adopt a message token at the successful receive boundary.
// Port of erts/emulator/beam/emu/msg_instrs.tab:161-203 (remove_message), OTP-29.1.1.
pub(crate) fn on_receive(
    vm: Option<&mut Vm>,
    process: &mut Process,
    ctx: Option<&mut RunCtx<'_, Message>>,
    pid: Pid,
    state: SeqState,
    message: OwnedTerm,
) {
    sync_epoch(process);
    let token = match state {
        // A message from a port leaves the token alone (msg_instrs.tab:177).
        SeqState::Undefined => return,
        SeqState::Nil => {
            put(process, None);
            return;
        }
        SeqState::Token(token) => *token,
    };
    if token.epoch != epoch().load(Ordering::Relaxed) {
        put(process, None);
        return;
    }
    process.seq_trace_lastcnt = token.serial;
    process.seq_trace_clock = process.seq_trace_clock.max(token.serial);
    // Port of erts/emulator/beam/jit/beam_jit_common.cpp (beam_jit_remove_message), OTP-29.1.1:
    // SEQ_TRACE_TOKEN(c_p) becomes the message's own token tuple, no copy.
    let mut token = token;
    process.seq_token_root = std::mem::replace(&mut token.heap_ref, Term::NIL);
    put(process, Some(token.clone()));
    let receiver = pid
        .to_term()
        .and_then(|p| to_owned(p).ok())
        .unwrap_or_else(|| OwnedTerm::atom("undefined"));
    emit(
        vm,
        process,
        ctx,
        &token,
        SeqEvent {
            kind: "receive",
            sender: token.sender.clone(),
            receiver,
            info: message,
        },
    );
}

/// A link exit signal sent by an exiting process: a send of `{'EXIT', From, Reason}`.
// Port of erts/emulator/beam/erl_proc_sig_queue.c:1700-1703,1827,1844-1870
// (send_gen_exit_signal, do_seq_trace_output), OTP-29.1.1.
pub(crate) fn on_exit_signal(
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    to: Pid,
    reason: Term,
) -> Option<Box<Token>> {
    let from = ctx.pid();
    let token = update_serial(process, from)?;
    let owned = |term: Option<Term>| {
        term.and_then(|term| to_owned(term).ok())
            .unwrap_or_else(|| OwnedTerm::atom("undefined"))
    };
    let message = OwnedTerm::tuple(vec![
        OwnedTerm::atom("EXIT"),
        owned(from.to_term()),
        owned(Some(reason)),
    ]);
    emit(
        None,
        process,
        Some(ctx),
        &token,
        SeqEvent {
            kind: "send",
            sender: token.sender.clone(),
            receiver: owned(to.to_term()),
            info: message,
        },
    );
    Some(Box::new(token))
}

pub(crate) fn current_epoch() -> u64 {
    epoch().load(Ordering::Relaxed)
}

/// The parent's side of a spawn with a token: bump the parent's serial and give the child the
/// token.
// Port of erts/emulator/beam/erl_process.c:12786-12832 (erl_create_process, seq trace), OTP-29.1.1.
pub(crate) fn spawn_prepare(
    parent: &mut Process,
    parent_pid: Pid,
    child: &mut Process,
) -> Option<Token> {
    let token = update_serial(parent, parent_pid)?;
    child.seq_trace_token = Some(Box::new(token.clone()));
    // The counters behave the same way on spawning as they do on messages.
    child.seq_trace_clock = token.serial;
    child.seq_trace_lastcnt = token.serial;
    child.seq_trace_epoch = epoch().load(Ordering::Relaxed);
    child.seq_trace_spawn_pending = true;
    Some(token)
}

/// Events of a spawn: the spawn request as a message sent and received, and the reply sent.
/// A synchronous spawn also receives the reply at once. Returns the reply's token.
// Port of erts/emulator/beam/erl_process.c:12818-12832 and 12980-13003, OTP-29.1.1.
pub(crate) fn spawn_events(
    vm: &mut Vm,
    parent: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    request: &Token,
    child: Pid,
    messages: (OwnedTerm, OwnedTerm),
    synchronous: bool,
) -> Token {
    let (request_message, reply_message) = messages;
    let parent_pid = ctx.pid();
    let term_of = |pid: Pid| {
        pid.to_term()
            .and_then(|term| to_owned(term).ok())
            .unwrap_or_else(|| OwnedTerm::atom("undefined"))
    };
    for kind in ["send", "receive"] {
        emit(
            Some(&mut *vm),
            parent,
            Some(&mut *ctx),
            request,
            SeqEvent {
                kind,
                sender: request.sender.clone(),
                receiver: term_of(child),
                info: request_message.clone(),
            },
        );
    }
    let mut reply = request.clone();
    reply.sender = term_of(child);
    reply.lastcnt = request.serial;
    reply.serial = request.serial + 1;
    emit(
        Some(&mut *vm),
        parent,
        Some(&mut *ctx),
        &reply,
        SeqEvent {
            kind: "send",
            sender: reply.sender.clone(),
            receiver: term_of(parent_pid),
            info: reply_message.clone(),
        },
    );
    if synchronous {
        // The parent is updated as if it had received the reply.
        parent.seq_trace_lastcnt = reply.serial;
        parent.seq_trace_clock = reply.serial;
        emit(
            Some(vm),
            parent,
            Some(ctx),
            &reply,
            SeqEvent {
                kind: "receive",
                sender: reply.sender.clone(),
                receiver: term_of(parent_pid),
                info: reply_message,
            },
        );
    }
    reply
}

pub(crate) fn clear_all() {
    epoch().fetch_add(1, Ordering::Relaxed);
}

fn term(process: &mut Process, owned: &OwnedTerm) -> Result<Term, VmError> {
    from_owned(
        owned,
        &mut arinsal_bifs::ProcessHeapHandle(&mut process.heap),
    )
    .map_err(|e| VmError::Unsupported(format!("seq_trace term: {e:?}")))
}
fn emit(
    vm: Option<&mut Vm>,
    process: &mut Process,
    mut ctx: Option<&mut RunCtx<'_, Message>>,
    token: &Token,
    event: SeqEvent,
) {
    // Port of erts/emulator/beam/erl_trace.c:964-1024 (seq_trace_output_generic), OTP-29.1.1.
    // The event is built in a local heap (erts' `local_heap`), never on the process heap:
    // the receive event is emitted inside remove_message, after a test_heap reserved space.
    let flag = match event.kind {
        "send" => SEND,
        "receive" => RECEIVE,
        _ => PRINT,
    };
    if token.flags & flag == 0 {
        return;
    }
    if process
        .self_pid
        .is_some_and(|pid| crate::trace::is_sensitive(process, pid))
    {
        return;
    }
    if process
        .self_pid
        .is_some_and(|pid| tracer_enabled(process, pid) == Some(false))
    {
        return;
    }
    let target = tracer().lock().unwrap().clone();
    let mut scratch = arinsal_term::VecHeap::new();
    let Some(target_term) = from_owned(&target, &mut scratch).ok() else {
        return;
    };
    let Some(sender) = from_owned(&event.sender, &mut scratch).ok() else {
        return;
    };
    let Some(receiver) = from_owned(&event.receiver, &mut scratch).ok() else {
        return;
    };
    let Some(info) = from_owned(&event.info, &mut scratch).ok() else {
        return;
    };
    let serial = TermBuilder::new(&mut scratch).tuple(&[
        Term::small(token.lastcnt as i64).unwrap_or(Term::NIL),
        Term::small(token.serial as i64).unwrap_or(Term::NIL),
    ]);
    let Ok(serial) = serial else {
        return;
    };
    let detail = TermBuilder::new(&mut scratch).tuple(&[
        crate::signals::atom(event.kind),
        serial,
        sender,
        receiver,
        info,
    ]);
    let Ok(detail) = detail else {
        return;
    };
    let mut values = vec![crate::signals::atom("seq_trace"), Term::NIL, detail];
    let Ok(label) = from_owned(&token.label, &mut scratch) else {
        return;
    };
    values[1] = label;
    if token.flags & TIMESTAMP != 0 {
        let micros = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros();
        let stamp = [
            micros / 1_000_000 / 1_000_000,
            micros / 1_000_000 % 1_000_000,
            micros % 1_000_000,
        ]
        .map(|n| Term::small(n as i64).unwrap_or(Term::NIL));
        if let Ok(stamp) = TermBuilder::new(&mut scratch).tuple(&stamp) {
            values.push(stamp);
        }
    } else if token.flags & STRICT_MONOTONIC != 0 {
        static START: OnceLock<std::time::Instant> = OnceLock::new();
        let nanos = START
            .get_or_init(std::time::Instant::now)
            .elapsed()
            .as_nanos();
        let time = Term::small(i64::try_from(nanos).unwrap_or(i64::MAX)).unwrap_or(Term::NIL);
        let serial =
            Term::small(unique().fetch_add(1, Ordering::Relaxed) as i64).unwrap_or(Term::NIL);
        if let Ok(stamp) = TermBuilder::new(&mut scratch).tuple(&[time, serial]) {
            values.push(stamp);
        }
    } else if token.flags & MONOTONIC != 0 {
        static START: OnceLock<std::time::Instant> = OnceLock::new();
        let nanos = START
            .get_or_init(std::time::Instant::now)
            .elapsed()
            .as_nanos();
        values.push(Term::small(i64::try_from(nanos).unwrap_or(i64::MAX)).unwrap_or(Term::NIL));
    }
    let Ok(event) = TermBuilder::new(&mut scratch).tuple(&values) else {
        return;
    };
    if let Some(target_pid) = Pid::from_term(target_term)
        && let Ok(message) = Message::copy_from(event)
    {
        if let Some(ctx) = ctx.as_deref_mut() {
            let _ = ctx.send(target_pid, message);
        } else if let (Some(runtime), Some(sender)) = (&process.runtime, process.self_pid)
            && let Ok(scheduler) = runtime.scheduler()
        {
            let _ = scheduler.send(sender, target_pid, message);
        }
    } else if target_term.as_port().is_some() {
        let _ = crate::port::trace_command(process, target_term, event);
    } else if let Some(vm) = vm
        && let OwnedTerm::Tuple(parts) = &target
        && parts.len() == 2
        && let OwnedTerm::Atom(module) = &parts[0]
        && let Some(state) = from_owned(&parts[1], &mut scratch).ok()
    {
        if let Some(ctx) = ctx {
            crate::natives::nif::refresh_hub(process, ctx);
        }
        let Some(tracee) = process.self_pid.and_then(Pid::to_term) else {
            return;
        };
        let tag = crate::signals::atom("seq_trace");
        let action = crate::natives::nif::invoke_tracer(
            vm,
            process,
            module,
            "enabled",
            None,
            &[tag, state, tracee],
        );
        if action != Some(crate::signals::atom("trace")) {
            return;
        }
        let mut opts = Vec::new();
        if token.flags & TIMESTAMP != 0 {
            opts.push((
                crate::signals::atom("timestamp"),
                crate::signals::atom("timestamp"),
            ));
        } else if token.flags & STRICT_MONOTONIC != 0 {
            opts.push((
                crate::signals::atom("timestamp"),
                crate::signals::atom("strict_monotonic"),
            ));
        } else if token.flags & MONOTONIC != 0 {
            opts.push((
                crate::signals::atom("timestamp"),
                crate::signals::atom("monotonic"),
            ));
        }
        let Ok(opts) = TermBuilder::new(&mut scratch).flatmap_from_pairs(&opts) else {
            return;
        };
        let _ = crate::natives::nif::invoke_tracer(
            vm,
            process,
            module,
            "trace",
            None,
            &[tag, state, label, detail, opts],
        );
    }
}

pub(crate) fn call(
    vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    module: &str,
    function: &str,
    args: crate::natives::NativeArgs<'_>,
) -> Option<Result<Term, VmError>> {
    if module != "erlang" {
        return None;
    }
    args.with_values(process, |process, args| {
        let result = match (function, args) {
            ("seq_trace", [component, value]) => {
                if atom(*component, "sequential_trace_token") {
                    set_token_value(process, ctx.pid(), *value)
                } else {
                    set_component(process, ctx.pid(), *component, *value)
                }
            }
            ("seq_trace_info", [component]) => info(process, ctx.pid(), *component),
            ("seq_trace_print", [message]) => print(vm, process, ctx, ctx.pid(), None, *message),
            ("seq_trace_print", [label, message]) => {
                print(vm, process, ctx, ctx.pid(), Some(*label), *message)
            }
            _ => return None,
        };
        Some(result)
    })
}

/// A working copy of a process's sequential trace state, for code that sets components
/// without the process at hand (a trace match specification's `set_seq_token`).
pub(crate) struct Local {
    token: Option<Token>,
    clock: u64,
    lastcnt: u64,
    pub(crate) changed: bool,
}

impl Local {
    pub(crate) fn of(process: &mut Process) -> Self {
        let token = token(process);
        Self {
            token,
            clock: process.seq_trace_clock,
            lastcnt: process.seq_trace_lastcnt,
            changed: false,
        }
    }

    pub(crate) fn commit(self, process: &mut Process) {
        if self.changed {
            put(process, self.token);
            process.seq_trace_clock = self.clock;
            process.seq_trace_lastcnt = self.lastcnt;
            // Port of erts/emulator/beam/erl_bif_trace.c (new_seq_trace_token), OTP-29.1.1: a
            // new token is a tuple built on the process heap.
            if let Some(token) = process.seq_trace_token.as_deref()
                && !process.seq_token_root.is_pointer()
                && let Ok(root) =
                    token.build_on(&mut arinsal_bifs::ProcessHeapHandle(&mut process.heap))
            {
                process.seq_token_root = root;
            }
        }
    }

    pub(crate) fn has_token(&self) -> bool {
        self.token.is_some()
    }

    /// The token as `get_seq_token` returns it: the five-tuple or `[]`.
    pub(crate) fn token_owned(&self) -> OwnedTerm {
        match &self.token {
            None => OwnedTerm::Nil,
            Some(token) => OwnedTerm::tuple(vec![
                OwnedTerm::Int(token.flags as i64),
                token.label.clone(),
                OwnedTerm::Int(token.serial as i64),
                token.sender.clone(),
                OwnedTerm::Int(token.lastcnt as i64),
            ]),
        }
    }

    /// `erts_seq_trace(p, Item, Value, 1)`: set one component, return its old value; `None`
    /// is badarg.
    // Port of erts/emulator/beam/erl_bif_trace.c:3035-3131 (erts_seq_trace, new_seq_trace_token),
    // OTP-29.1.1.
    pub(crate) fn set_component(
        &mut self,
        pid: Pid,
        name: &str,
        value: &OwnedTerm,
    ) -> Option<OwnedTerm> {
        let bit = flag_bit(name);
        let boolean = match value {
            OwnedTerm::Atom(atom) if atom == "true" => Some(true),
            OwnedTerm::Atom(atom) if atom == "false" => Some(false),
            _ => None,
        };
        if bit.is_none() && !matches!(name, "label" | "serial") {
            return None;
        }
        if bit.is_some() && boolean.is_none() {
            return None;
        }
        let serial = if name == "serial" {
            let OwnedTerm::Tuple(v) = value else {
                return None;
            };
            let [OwnedTerm::Int(a), OwnedTerm::Int(b)] = v.as_slice() else {
                return None;
            };
            if *a < 0 || *b < 0 {
                return None;
            }
            Some((*a as u64, *b as u64))
        } else {
            None
        };
        let lastcnt = self.lastcnt;
        let current = self.token.get_or_insert_with(|| Token {
            label: OwnedTerm::Int(0),
            flags: 0,
            serial: 0,
            sender: pid
                .to_term()
                .and_then(|p| to_owned(p).ok())
                .unwrap_or(OwnedTerm::atom("undefined")),
            lastcnt,
            epoch: epoch().load(Ordering::Relaxed),
            heap_ref: Term::NIL,
        });
        self.changed = true;
        Some(if let Some(bit) = bit {
            let was = current.flags & bit != 0;
            if boolean == Some(true) {
                current.flags |= bit;
            } else {
                current.flags &= !bit;
            }
            OwnedTerm::atom(if was { "true" } else { "false" })
        } else if name == "label" {
            std::mem::replace(&mut current.label, value.clone())
        } else {
            let (new_lastcnt, new_serial) = serial.expect("serial parsed above");
            let old = OwnedTerm::tuple(vec![
                OwnedTerm::Int(current.lastcnt as i64),
                OwnedTerm::Int(current.serial as i64),
            ]);
            current.lastcnt = new_lastcnt;
            current.serial = new_serial;
            self.clock = new_serial;
            self.lastcnt = new_lastcnt;
            old
        })
    }
}

fn set_component(
    process: &mut Process,
    pid: Pid,
    component: Term,
    value: Term,
) -> Result<Term, VmError> {
    let name = component
        .as_atom()
        .and_then(|atom| arinsal_term::global_atoms().text(atom))
        .ok_or_else(badarg)?
        .to_owned();
    let value = to_owned(value).map_err(|_| badarg())?;
    let mut local = Local::of(process);
    let old = local.set_component(pid, &name, &value).ok_or_else(badarg)?;
    local.commit(process);
    from_owned(
        &old,
        &mut arinsal_bifs::ProcessHeapHandle(&mut process.heap),
    )
    .map_err(|e| VmError::Unsupported(format!("seq token result: {e:?}")))
}
// Port of erts/emulator/beam/erl_process.h:1820-1832 (SEQ_TRACE_* flags), OTP-29.1.1.
fn flag_bit(name: &str) -> Option<u64> {
    Some(match name {
        "send" => SEND,
        "receive" => RECEIVE,
        "print" => PRINT,
        "timestamp" => TIMESTAMP,
        "monotonic_timestamp" => MONOTONIC,
        "strict_monotonic_timestamp" => STRICT_MONOTONIC,
        _ => return None,
    })
}
// Port of erts/emulator/beam/erl_bif_trace.c:3157-3214 (erl_seq_trace_info), OTP-29.1.1.
fn info(process: &mut Process, _pid: Pid, component: Term) -> Result<Term, VmError> {
    let name = component
        .as_atom()
        .and_then(|atom| arinsal_term::global_atoms().text(atom))
        .ok_or_else(badarg)?
        .to_owned();
    let bit = flag_bit(&name);
    let value = match token(process) {
        None if bit.is_some() || name == "spawn" => OwnedTerm::atom("false"),
        None if matches!(name.as_str(), "label" | "serial") => return Ok(Term::NIL),
        Some(t) if bit.is_some() => OwnedTerm::atom(if t.flags & bit.unwrap_or(0) != 0 {
            "true"
        } else {
            "false"
        }),
        Some(t) if name == "label" => t.label,
        Some(t) if name == "serial" => OwnedTerm::tuple(vec![
            OwnedTerm::Int(t.lastcnt as i64),
            OwnedTerm::Int(t.serial as i64),
        ]),
        _ => return Err(badarg()),
    };
    let value = from_owned(
        &value,
        &mut arinsal_bifs::ProcessHeapHandle(&mut process.heap),
    )
    .map_err(|e| VmError::Unsupported(format!("seq info: {e:?}")))?;
    let key = term(process, &OwnedTerm::Atom(name))?;
    TermBuilder::new(&mut process.heap)
        .tuple(&[key, value])
        .map_err(|e| VmError::Unsupported(format!("seq info tuple: {e:?}")))
}
// Port of erts/emulator/beam/erl_bif_trace.c:3229-3258 (seq_trace_print), OTP-29.1.1.
fn print(
    vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    pid: Pid,
    label: Option<Term>,
    message: Term,
) -> Result<Term, VmError> {
    let Some(current) = token(process) else {
        return Ok(crate::signals::atom("false"));
    };
    if let Some(label) = label
        && to_owned(label).ok().as_ref() != Some(&current.label)
    {
        return Ok(crate::signals::atom("false"));
    }
    let msg = to_owned(message).map_err(|_| badarg())?;
    let Some(t) = update_serial(process, pid) else {
        return Ok(crate::signals::atom("false"));
    };
    emit(
        Some(vm),
        process,
        Some(ctx),
        &t,
        SeqEvent {
            kind: "print",
            sender: t.sender.clone(),
            receiver: OwnedTerm::Nil,
            info: msg,
        },
    );
    Ok(crate::signals::atom("true"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Vm;
    use arinsal_difftest::{CallResult, RefErl};
    fn test_lock() -> &'static Mutex<()> {
        static LOCK: Mutex<()> = Mutex::new(());
        &LOCK
    }

    #[test]
    fn seq_trace_label_flags_and_serial_are_mutable() {
        let _guard = test_lock().lock().unwrap();
        let mut process = Process::new();
        let pid = Pid::new(8101, 1);
        let label = Term::small(99).unwrap();
        set_component(&mut process, pid, crate::signals::atom("label"), label).unwrap();
        set_component(
            &mut process,
            pid,
            crate::signals::atom("send"),
            crate::signals::atom("true"),
        )
        .unwrap();
        assert_eq!(token(&mut process).unwrap().label, OwnedTerm::Int(99));
        assert_ne!(token(&mut process).unwrap().flags & SEND, 0);
    }

    #[test]
    fn seq_trace_reset_clears_active_tokens() {
        let _guard = test_lock().lock().unwrap();
        let mut process = Process::new();
        let pid = Pid::new(8102, 1);
        set_component(
            &mut process,
            pid,
            crate::signals::atom("label"),
            Term::small(7).unwrap(),
        )
        .unwrap();
        assert!(token(&mut process).is_some());
        clear_all();
        assert!(token(&mut process).is_none());
    }

    #[test]
    fn seq_trace_three_process_chain_matches_otp() {
        let _guard = test_lock().lock().unwrap();
        let Ok(reference) = RefErl::start() else {
            eprintln!("erl unavailable; skipping sequential trace differential test");
            return;
        };
        let source = r#"-module(seq_trace_chain). -export([run/0]).
run() ->
  Parent=self(),
  Tracer=spawn(fun() -> gather(6, Parent, []) end),
  seq_trace:set_system_tracer(Tracer),
  C=spawn(fun() -> receive {Parent,step2} -> Parent ! done end end),
  B=spawn(fun() -> receive {C,step1} -> C ! {Parent,step2} end end),
  seq_trace:set_token(label,77), seq_trace:set_token(send,true), seq_trace:set_token('receive',true),
  B ! {C,step1}, receive done -> ok end,
  receive {trace_result,Events} -> Events end.
gather(0, Parent, Acc) -> Parent ! {trace_result,lists:reverse(Acc)};
gather(N, Parent, Acc) -> receive
  {seq_trace,77,{Type,Serial,_From,_To,Info}} -> gather(N-1, Parent, [{Type,Serial,msg_tag(Info)}|Acc])
end.
msg_tag({_,Tag}) -> Tag;
msg_tag(Tag) -> Tag."#;
        let beam = reference
            .compile_named("seq_trace_chain", source, &[])
            .unwrap();
        reference.load("seq_trace_chain", &beam).unwrap();
        let expected = reference.call("seq_trace_chain", "run", &[]);
        let mut vm = Vm::new([]);
        vm.load_bytes(&beam).unwrap();
        let actual = vm
            .eval_scheduled("seq_trace_chain", "run", &[], 2, None)
            .unwrap();
        assert_eq!(expected, CallResult::Ok(actual.term));
    }
}
