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
const MONOTONIC: u64 = 16;
const STRICT_MONOTONIC: u64 = 32;

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
pub(crate) struct Token {
    label: OwnedTerm,
    flags: u64,
    previous: u64,
    serial: u64,
    sender: OwnedTerm,
    last: u64,
    epoch: u64,
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
        .is_some_and(|s| s.as_ref() == name)
}
fn badarg() -> VmError {
    VmError::Trap(crate::exceptions::Trap::error(crate::signals::atom(
        "badarg",
    )))
}
fn token(process: &mut Process) -> Option<Token> {
    if process
        .seq_trace_token
        .as_ref()
        .is_some_and(|token| token.epoch != epoch().load(Ordering::Relaxed))
    {
        process.seq_trace_token = None;
    }
    process.seq_trace_token.as_deref().cloned()
}
fn put(process: &mut Process, value: Option<Token>) {
    process.seq_trace_token = value.map(Box::new);
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
        if !crate::natives::nif::has_tracer_nifs(vm, &module) {
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
    from_owned(&old, &mut arinsal_bifs::FragmentingHeap(&mut process.heap))
        .map_err(|e| VmError::Unsupported(format!("seq tracer: {e:?}")))
}

pub(crate) fn system_tracer_info(process: &mut Process) -> Result<Term, VmError> {
    let value = tracer().lock().unwrap().clone();
    let value = from_owned(
        &value,
        &mut arinsal_bifs::FragmentingHeap(&mut process.heap),
    )
    .map_err(|e| VmError::Unsupported(format!("seq tracer info: {e:?}")))?;
    TermBuilder::new(&mut process.heap)
        .tuple(&[crate::signals::atom("sequential_tracer"), value])
        .map_err(|e| VmError::Unsupported(format!("seq tracer info tuple: {e:?}")))
}

// Port of erts/emulator/beam/erl_bif_trace.c:3035-3112 (seq_trace token reset), OTP-29.1.1.
pub(crate) fn set_token_value(
    process: &mut Process,
    _pid: Pid,
    value: Term,
) -> Result<Term, VmError> {
    let old = token(process);
    if value == Term::NIL {
        put(process, None);
        return token_term(process, old.as_ref());
    }
    Err(badarg())
}

// Port of erts/emulator/beam/erl_bif_trace.c:3133 (new_seq_trace_token), OTP-29.1.1.
fn token_term(process: &mut Process, token: Option<&Token>) -> Result<Term, VmError> {
    let Some(token) = token else {
        return Ok(Term::NIL);
    };
    let fields = [
        OwnedTerm::Int(token.flags as i64),
        token.label.clone(),
        OwnedTerm::Int(token.serial as i64),
        token.sender.clone(),
        OwnedTerm::Int(token.last as i64),
    ];
    let mut values = Vec::with_capacity(fields.len());
    for field in &fields {
        values.push(
            from_owned(field, &mut arinsal_bifs::FragmentingHeap(&mut process.heap))
                .map_err(|e| VmError::Unsupported(format!("seq token: {e:?}")))?,
        );
    }
    TermBuilder::new(&mut process.heap)
        .tuple(&values)
        .map_err(|e| VmError::Unsupported(format!("seq token tuple: {e:?}")))
}

pub(crate) fn get_token_term(process: &mut Process, _pid: Pid) -> Result<Term, VmError> {
    let token = token(process);
    token_term(process, token.as_ref())
}

/// Attach the sender's current token to an ordinary message and emit its send event.
// Port of erts/emulator/beam/erl_message.c:742-802 (seq trace send), OTP-29.1.1.
pub(crate) fn on_send(
    vm: Option<&mut Vm>,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    pid: Pid,
    receiver: Term,
    message: Term,
) -> Option<Box<Token>> {
    let mut token = token(process)?;
    token.serial = token.serial.saturating_add(1);
    token.previous = token.last;
    token.last = token.serial;
    token.sender = pid
        .to_term()
        .and_then(|p| to_owned(p).ok())
        .unwrap_or_else(|| OwnedTerm::atom("undefined"));
    put(process, Some(token.clone()));
    if token.flags & SEND != 0
        && let (Ok(receiver), Ok(message)) = (to_owned(receiver), to_owned(message))
    {
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
// Port of erts/emulator/beam/erl_proc_sig_queue.c:8610-8615, OTP-29.1.1.
pub(crate) fn on_receive(
    vm: Option<&mut Vm>,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    pid: Pid,
    token: Option<Box<Token>>,
    message: OwnedTerm,
) {
    let Some(mut token) = token
        .map(|token| *token)
        .filter(|t| t.epoch == epoch().load(Ordering::Relaxed))
    else {
        put(process, None);
        return;
    };
    if token.flags & RECEIVE != 0 {
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
    token.previous = token.last;
    put(process, Some(token));
}

pub(crate) fn clear_all() {
    epoch().fetch_add(1, Ordering::Relaxed);
}

fn term(process: &mut Process, owned: &OwnedTerm) -> Result<Term, VmError> {
    from_owned(owned, &mut arinsal_bifs::FragmentingHeap(&mut process.heap))
        .map_err(|e| VmError::Unsupported(format!("seq_trace term: {e:?}")))
}
fn emit(
    vm: Option<&mut Vm>,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    token: &Token,
    event: SeqEvent,
) {
    // Port of erts/emulator/beam/erl_trace.c:964-1024 (seq_trace_output_generic), OTP-29.1.1.
    let target = tracer().lock().unwrap().clone();
    let Some(target_term) = from_owned(
        &target,
        &mut arinsal_bifs::FragmentingHeap(&mut process.heap),
    )
    .ok() else {
        return;
    };
    let Some(sender) = from_owned(
        &event.sender,
        &mut arinsal_bifs::FragmentingHeap(&mut process.heap),
    )
    .ok() else {
        return;
    };
    let Some(receiver) = from_owned(
        &event.receiver,
        &mut arinsal_bifs::FragmentingHeap(&mut process.heap),
    )
    .ok() else {
        return;
    };
    let Some(info) = from_owned(
        &event.info,
        &mut arinsal_bifs::FragmentingHeap(&mut process.heap),
    )
    .ok() else {
        return;
    };
    let serial = TermBuilder::new(&mut process.heap).tuple(&[
        Term::small(token.previous as i64).unwrap_or(Term::NIL),
        Term::small(token.serial as i64).unwrap_or(Term::NIL),
    ]);
    let Ok(serial) = serial else {
        return;
    };
    let detail = TermBuilder::new(&mut process.heap).tuple(&[
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
    let Ok(label) = from_owned(
        &token.label,
        &mut arinsal_bifs::FragmentingHeap(&mut process.heap),
    ) else {
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
        if let Ok(stamp) = TermBuilder::new(&mut process.heap).tuple(&stamp) {
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
        if let Ok(stamp) = TermBuilder::new(&mut process.heap).tuple(&[time, serial]) {
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
    let Ok(event) = TermBuilder::new(&mut process.heap).tuple(&values) else {
        return;
    };
    if let Some(target_pid) = Pid::from_term(target_term) {
        if let Ok(message) = Message::copy_from(event) {
            let _ = ctx.send(target_pid, message);
        }
    } else if target_term.as_port().is_some() {
        let _ = crate::port::send_message(process, ctx, target_term, event);
    } else if let Some(vm) = vm
        && let OwnedTerm::Tuple(parts) = &target
        && parts.len() == 2
        && let OwnedTerm::Atom(module) = &parts[0]
        && let Some(state) = from_owned(
            &parts[1],
            &mut arinsal_bifs::FragmentingHeap(&mut process.heap),
        )
        .ok()
    {
        crate::natives::nif::refresh_hub(process, ctx);
        let Some(tracee) = ctx.pid().to_term() else {
            return;
        };
        let tag = crate::signals::atom("seq_trace");
        let action = crate::natives::nif::invoke_tracer(
            vm,
            process,
            module,
            "enabled",
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
        let Ok(opts) = TermBuilder::new(&mut process.heap).flatmap_from_pairs(&opts) else {
            return;
        };
        let _ = crate::natives::nif::invoke_tracer(
            vm,
            process,
            module,
            "trace",
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

// Port of erts/emulator/beam/erl_bif_trace.c:3035-3112 (erts_seq_trace), OTP-29.1.1.
fn set_component(
    process: &mut Process,
    pid: Pid,
    component: Term,
    value: Term,
) -> Result<Term, VmError> {
    let name = component
        .as_atom()
        .and_then(|atom| arinsal_term::global_atoms().text(atom))
        .ok_or_else(badarg)?;
    let mut current = token(process).unwrap_or(Token {
        label: OwnedTerm::Int(0),
        flags: 0,
        previous: 0,
        serial: 0,
        sender: pid
            .to_term()
            .and_then(|p| to_owned(p).ok())
            .unwrap_or(OwnedTerm::atom("undefined")),
        last: 0,
        epoch: epoch().load(Ordering::Relaxed),
    });
    let old = match name.as_ref() {
        "label" => {
            let old = current.label.clone();
            current.label = to_owned(value).map_err(|_| badarg())?;
            old
        }
        "serial" => {
            let owned = to_owned(value).map_err(|_| badarg())?;
            let OwnedTerm::Tuple(v) = &owned else {
                return Err(badarg());
            };
            if v.len() != 2 {
                return Err(badarg());
            }
            let (OwnedTerm::Int(a), OwnedTerm::Int(b)) = (&v[0], &v[1]) else {
                return Err(badarg());
            };
            let old = OwnedTerm::tuple(vec![
                OwnedTerm::Int(current.previous as i64),
                OwnedTerm::Int(current.serial as i64),
            ]);
            current.previous = *a as u64;
            current.serial = *b as u64;
            current.last = *a as u64;
            old
        }
        flag => {
            let bit = flag_bit(flag).ok_or_else(badarg)?;
            if value != crate::signals::atom("true") && value != crate::signals::atom("false") {
                return Err(badarg());
            }
            let was = current.flags & bit != 0;
            if value == crate::signals::atom("true") {
                current.flags |= bit
            } else {
                current.flags &= !bit
            };
            OwnedTerm::atom(if was { "true" } else { "false" })
        }
    };
    current.epoch = epoch().load(Ordering::Relaxed);
    put(process, Some(current));
    from_owned(&old, &mut arinsal_bifs::FragmentingHeap(&mut process.heap))
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
// Port of erts/emulator/beam/erl_bif_trace.c:3157-3210 (erl_seq_trace_info), OTP-29.1.1.
fn info(process: &mut Process, _pid: Pid, component: Term) -> Result<Term, VmError> {
    let name = component
        .as_atom()
        .and_then(|atom| arinsal_term::global_atoms().text(atom))
        .ok_or_else(badarg)?;
    let bit = flag_bit(name.as_ref());
    if bit.is_none() && !matches!(name.as_ref(), "label" | "serial" | "spawn") {
        return Err(badarg());
    }
    let current = token(process);
    if current.is_none() && matches!(name.as_ref(), "label" | "serial") {
        return Ok(Term::NIL);
    }
    let value = current
        .map(|t| match name.as_ref() {
            "label" => t.label,
            "serial" => OwnedTerm::tuple(vec![
                OwnedTerm::Int(t.previous as i64),
                OwnedTerm::Int(t.serial as i64),
            ]),
            "spawn" => OwnedTerm::atom("false"),
            _ => OwnedTerm::atom(if bit.is_some_and(|b| t.flags & b != 0) {
                "true"
            } else {
                "false"
            }),
        })
        .or_else(|| match name.as_ref() {
            "label" | "serial" => None,
            "spawn"
            | "send"
            | "receive"
            | "print"
            | "timestamp"
            | "monotonic_timestamp"
            | "strict_monotonic_timestamp" => Some(OwnedTerm::atom("false")),
            _ => None,
        })
        .ok_or_else(badarg)?;
    let value = from_owned(
        &value,
        &mut arinsal_bifs::FragmentingHeap(&mut process.heap),
    )
    .map_err(|e| VmError::Unsupported(format!("seq info: {e:?}")))?;
    let key = term(process, &OwnedTerm::Atom(name.to_string()))?;
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
    let Some(mut t) = token(process) else {
        return Ok(crate::signals::atom("false"));
    };
    if t.flags & PRINT == 0 {
        return Ok(crate::signals::atom("false"));
    };
    let msg = to_owned(message).map_err(|_| badarg())?;
    if label.is_some_and(|l| to_owned(l).ok() != Some(t.label.clone())) {
        return Ok(crate::signals::atom("false"));
    };
    t.serial = t.serial.saturating_add(1);
    t.previous = t.last;
    t.last = t.serial;
    let sender = pid
        .to_term()
        .and_then(|p| to_owned(p).ok())
        .unwrap_or_else(|| OwnedTerm::atom("undefined"));
    emit(
        Some(vm),
        process,
        ctx,
        &t,
        SeqEvent {
            kind: "print",
            sender,
            receiver: OwnedTerm::atom("undefined"),
            info: msg,
        },
    );
    put(process, Some(t));
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
        let pid = Pid {
            index: 8101,
            generation: 1,
        };
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
        let pid = Pid {
            index: 8102,
            generation: 1,
        };
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
