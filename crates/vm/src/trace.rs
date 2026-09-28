//! Process and message tracing for ERTS trace sessions.

use crate::{Process, Vm, VmError, process::Message};
use arinsal_etf::OwnedTerm;
use arinsal_sched::{Pid, RunCtx};
use arinsal_term::{Term, TermBuilder, from_owned, global_atoms};
use std::cell::Cell;
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
pub(crate) const TIMESTAMP: u64 = 1;
pub(crate) const STRICT_MONOTONIC_TIMESTAMP: u64 = 2;
pub(crate) const MONOTONIC_TIMESTAMP: u64 = 4;
pub(crate) const CALL: u64 = 1 << 10;
pub(crate) const ARITY: u64 = 1 << 15;
pub(crate) const RETURN_TO: u64 = 1 << 16;
pub(crate) const SILENT: u64 = 1 << 17;

#[derive(Clone)]
struct Entry {
    flags: u64,
    tracer: Tracer,
}

#[derive(Clone)]
pub(crate) enum Tracer {
    Pid(Pid),
    Port(u64),
    Module { module: String, state: OwnedTerm },
}

type TraceTable = HashMap<(usize, u64, Pid), Entry>;

struct TraceEvent<'a> {
    flags: u64,
    tracee: Term,
    name: &'a str,
    fields: &'a [Term],
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
    pub(crate) session: u64,
    pub(crate) return_trace: bool,
    pub(crate) exception_trace: bool,
    pub(crate) return_to: bool,
}

struct CallMatchContext {
    message: Cell<Option<Term>>,
    silent: Cell<bool>,
    return_trace: Cell<bool>,
    exception_trace: Cell<bool>,
    caller: Option<Term>,
}

impl arinsal_ets::match_spec::MatchContext for CallMatchContext {
    fn trace_operation(
        &self,
        name: &str,
        arguments: &[Term],
    ) -> Result<Term, arinsal_ets::EtsError> {
        match name {
            "message" => {
                let value = *arguments.first().ok_or(arinsal_ets::EtsError::BadArg)?;
                self.message.set(Some(value));
                Ok(value)
            }
            "silent" => {
                self.silent.set(true);
                Ok(crate::signals::atom("true"))
            }
            "caller" => Ok(self
                .caller
                .unwrap_or_else(|| crate::signals::atom("undefined"))),
            "caller_line" => Err(arinsal_ets::EtsError::Unsupported(
                "caller_line trace action",
            )),
            "return_trace" => {
                self.return_trace.set(true);
                Ok(crate::signals::atom("true"))
            }
            "exception_trace" => {
                self.exception_trace.set(true);
                Ok(crate::signals::atom("true"))
            }
            "process_dump" => Err(arinsal_ets::EtsError::Unsupported(
                "process_dump trace action",
            )),
            _ => Err(arinsal_ets::EtsError::Unsupported(
                "trace match specification operation",
            )),
        }
    }
}

fn table() -> &'static Mutex<TraceTable> {
    static TABLE: OnceLock<Mutex<TraceTable>> = OnceLock::new();
    TABLE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn enabled() -> &'static AtomicBool {
    static ENABLED: AtomicBool = AtomicBool::new(false);
    &ENABLED
}

fn sessions() -> &'static Mutex<HashMap<(usize, u64), Tracer>> {
    static SESSIONS: OnceLock<Mutex<HashMap<(usize, u64), Tracer>>> = OnceLock::new();
    SESSIONS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn scope(process: &Process) -> usize {
    process
        .runtime
        .as_ref()
        .map_or(0, |runtime| std::sync::Arc::as_ptr(runtime) as usize)
}

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
    enabled().store(!table.is_empty(), Ordering::Relaxed);
    before
}

pub(crate) fn flags(process: &Process, pid: Pid) -> u64 {
    if !enabled().load(Ordering::Relaxed) {
        return 0;
    }
    table()
        .lock()
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
    sessions()
        .lock()
        .unwrap()
        .retain(|(owner, _), _| *owner != runtime);
    enabled().store(!table().lock().unwrap().is_empty(), Ordering::Relaxed);
}

pub(crate) fn session_flags(process: &Process, session: u64, pid: Pid) -> u64 {
    table()
        .lock()
        .unwrap()
        .get(&(scope(process), session, pid))
        .map_or(0, |entry| entry.flags)
}

pub(crate) fn tracer(process: &Process, pid: Pid) -> Option<Tracer> {
    table()
        .lock()
        .unwrap()
        .get(&(scope(process), 0, pid))
        .map(|entry| entry.tracer.clone())
}

pub(crate) fn clear(process: &Process, pid: Pid) {
    let mut entries = table().lock().unwrap();
    entries.retain(|(runtime, _, subject), _| *runtime != scope(process) || *subject != pid);
    enabled().store(!entries.is_empty(), Ordering::Relaxed);
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
    let pid = ctx.pid();
    let flags = flags(process, pid);
    let patterns = crate::trace_bp::matching(process, module, function, args.len() as u8, local);
    if patterns.is_empty() {
        return Ok(Vec::new());
    }
    let mut actions = Vec::new();
    for pattern in patterns {
        if pattern.paused {
            continue;
        }
        let mut extra = None;
        let mut return_trace = false;
        let mut exception_trace = false;
        if let Some(specification) = pattern.match_spec.as_ref() {
            let against = [
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
                TermBuilder::new(&mut arinsal_bifs::FragmentingHeap(&mut process.heap))
                    .list_from_iter(args.iter().copied())
                    .map_err(|error| VmError::Unsupported(format!("trace args: {error:?}")))?,
            ];
            let against = TermBuilder::new(&mut arinsal_bifs::FragmentingHeap(&mut process.heap))
                .list_from_iter(against)
                .map_err(|error| VmError::Unsupported(format!("trace subject: {error:?}")))?;
            let specification = from_owned(
                specification,
                &mut arinsal_bifs::FragmentingHeap(&mut process.heap),
            )
            .map_err(|error| VmError::Unsupported(format!("trace match spec: {error:?}")))?;
            let program = arinsal_ets::match_spec::MatchProgram::compile_trace(specification)
                .map_err(|_| VmError::Unsupported("invalid trace match specification".into()))?;
            let context = CallMatchContext {
                message: Cell::new(None),
                silent: Cell::new(false),
                return_trace: Cell::new(false),
                exception_trace: Cell::new(false),
                caller: caller_mfa(process, vm)?,
            };
            let result = program
                .run_with_context(
                    against,
                    &mut arinsal_bifs::FragmentingHeap(&mut process.heap),
                    &context,
                )
                .map_err(|error| {
                    VmError::Unsupported(format!("trace match spec execution: {error:?}"))
                })?;
            if context.silent.get() {
                continue;
            }
            let Some(result) = result else {
                continue;
            };
            if result == crate::signals::atom("false") {
                continue;
            }
            extra = context.message.get();
            return_trace = context.return_trace.get();
            exception_trace = context.exception_trace.get();
        }
        if flags & CALL != 0 && flags & SILENT == 0 {
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
                    extra,
                    actions: (return_trace, exception_trace),
                },
                Some(pattern.session),
            )?;
        }
        let return_to = local && session_flags(process, pattern.session, pid) & RETURN_TO != 0;
        if return_trace || exception_trace || return_to {
            actions.push(CallActions {
                session: pattern.session,
                return_trace,
                exception_trace,
                return_to,
            });
        }
    }
    Ok(actions)
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
    if flags & ARITY != 0 {
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
    let call = TermBuilder::new(&mut arinsal_bifs::FragmentingHeap(&mut process.heap))
        .tuple(&values)
        .map_err(|error| VmError::Unsupported(format!("trace call: {error:?}")))?;
    let fields = if let Some(extra) = extra {
        vec![call, extra]
    } else {
        vec![call]
    };
    emit_filtered(Some(vm), process, ctx, pid, CALL, "call", &fields, session);
    Ok(actions)
}

fn caller_mfa(process: &mut Process, vm: &Vm) -> Result<Option<Term>, VmError> {
    let Some(module) = vm.modules.get(process.module) else {
        return Ok(None);
    };
    let Some((function, arity)) = module.function_at(process.ip) else {
        return Ok(None);
    };
    let values = [
        Term::atom(
            global_atoms()
                .intern(&module.name)
                .map_err(|_| VmError::Unsupported("caller module atom".into()))?,
        ),
        Term::atom(
            global_atoms()
                .intern(function)
                .map_err(|_| VmError::Unsupported("caller function atom".into()))?,
        ),
        Term::small(i64::from(arity)).ok_or_else(|| VmError::Unsupported("caller arity".into()))?,
    ];
    let tuple = TermBuilder::new(&mut arinsal_bifs::FragmentingHeap(&mut process.heap))
        .tuple(&values)
        .map_err(|error| VmError::Unsupported(format!("caller MFA: {error:?}")))?;
    Ok(Some(tuple))
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
    let flags = flags(process, ctx.pid());
    if flags & CALL == 0 || flags & SILENT != 0 {
        return Ok(());
    }
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
    );
    Ok(())
}

// Port of erts/emulator/beam/erl_trace.c:1037-1055 (erts_trace_return_to), OTP-29.1.1.
pub(crate) fn return_to_event(
    vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    module_id: usize,
    ip: usize,
    session: u64,
) -> Result<(), VmError> {
    let flags = flags(process, ctx.pid());
    if flags & RETURN_TO == 0 || flags & SILENT != 0 {
        return Ok(());
    }
    let target = vm.modules.get(module_id).and_then(|module| {
        module
            .function_at(ip)
            .map(|(function, arity)| (module.name.clone(), function.to_owned(), arity))
    });
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
    );
    Ok(())
}

pub(crate) fn spawned(
    vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    child: Pid,
    mfa: Term,
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
    }
    let inherited = flags(process, parent);
    let inherit = inherited & (SET_ON_SPAWN | SET_ON_FIRST_SPAWN) != 0;
    if inherit {
        let mut child_flags = inherited & !(SET_ON_SPAWN | SET_ON_FIRST_SPAWN);
        if inherited & SET_ON_FIRST_SPAWN != 0 {
            let _ = configure(
                process,
                parent,
                false,
                SET_ON_FIRST_SPAWN,
                Tracer::Pid(parent),
            );
            child_flags |= inherited & SET_ON_FIRST_SPAWN;
        }
        if child_flags != 0 {
            let target = tracer(process, parent).unwrap_or(Tracer::Pid(parent));
            configure(process, child, true, child_flags, target);
        }
    }
}

pub(crate) fn spawn_interested(process: &Process, parent: Pid) -> bool {
    flags(process, parent) & (PROCS | SET_ON_SPAWN | SET_ON_FIRST_SPAWN) != 0
}

pub(crate) fn linked(process: &Process, from: Pid, to: Pid) {
    for (source, target) in [(from, to), (to, from)] {
        let source_flags = flags(process, source);
        if source_flags & SET_ON_LINK != 0 {
            let target_flags = source_flags & !SET_ON_LINK;
            let target_tracer = tracer(process, source).unwrap_or(Tracer::Pid(source));
            configure(process, target, true, target_flags, target_tracer);
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
    emit_filtered(vm, process, ctx, subject, class, name, fields, None);
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
) {
    if !enabled().load(Ordering::Relaxed) {
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
    if entries.is_empty() {
        return;
    }
    let Some(subject_term) = subject.to_term() else {
        return;
    };
    for entry in entries {
        if let Tracer::Module { module, state } = &entry.tracer {
            let Some(vm) = vm.as_deref_mut() else {
                continue;
            };
            emit_module(
                vm,
                process,
                ctx,
                module,
                state,
                TraceEvent {
                    flags: entry.flags,
                    tracee: subject_term,
                    name,
                    fields,
                },
            );
            continue;
        }
        let mut values = Vec::with_capacity(3 + fields.len() + 1);
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
        if entry.flags & TIMESTAMP != 0 {
            let micros = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_micros();
            let stamp = [
                micros / 1_000_000 / 1_000_000,
                micros / 1_000_000 % 1_000_000,
                micros % 1_000_000,
            ]
            .map(|value| Term::small(value as i64).unwrap_or(Term::NIL));
            if let Ok(tuple) = TermBuilder::new(&mut process.heap).tuple(&stamp) {
                values.push(tuple);
            }
        } else if entry.flags & (MONOTONIC_TIMESTAMP | STRICT_MONOTONIC_TIMESTAMP) != 0 {
            static START: OnceLock<std::time::Instant> = OnceLock::new();
            let stamp = Term::small(
                i64::try_from(
                    START
                        .get_or_init(std::time::Instant::now)
                        .elapsed()
                        .as_nanos(),
                )
                .unwrap_or(i64::MAX),
            )
            .unwrap_or(Term::NIL);
            values.push(stamp);
        }
        let Ok(event) = TermBuilder::new(&mut process.heap).tuple(&values) else {
            return;
        };
        let Ok(message) = Message::copy_from(event) else {
            return;
        };
        match entry.tracer {
            Tracer::Pid(pid) => {
                let _ = ctx.send(pid, message);
            }
            Tracer::Port(id) => {
                if let Some(port) = Term::port(id) {
                    let _ = crate::port::send_message(process, ctx, port, event);
                }
            }
            Tracer::Module { .. } => unreachable!(),
        }
    }
}

fn emit_module(
    vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    module: &str,
    owned_state: &OwnedTerm,
    event: TraceEvent<'_>,
) {
    crate::natives::nif::refresh_hub(process, ctx);
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
    if event.name == "send"
        && let Some(extra) = event.fields.get(1)
    {
        options.push((crate::signals::atom("extra"), *extra));
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
    let Ok(options) = TermBuilder::new(&mut process.heap).flatmap_from_pairs(&options) else {
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

pub(crate) fn create_session(process: &Process, tracer: Tracer) -> u64 {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    let id = 0x7000_0000_0000_0000 | NEXT.fetch_add(1, Ordering::Relaxed).max(1);
    sessions()
        .lock()
        .unwrap()
        .insert((scope(process), id), tracer);
    id
}

pub(crate) fn session_tracer(process: &Process, session: u64) -> Option<Tracer> {
    sessions()
        .lock()
        .unwrap()
        .get(&(scope(process), session))
        .cloned()
}

pub(crate) fn destroy_session(process: &Process, session: u64) -> bool {
    let existed = sessions()
        .lock()
        .unwrap()
        .remove(&(scope(process), session))
        .is_some();
    let mut entries = table().lock().unwrap();
    entries.retain(|(runtime, id, _), _| *runtime != scope(process) || *id != session);
    enabled().store(!entries.is_empty(), Ordering::Relaxed);
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
    fn trace_pattern_exception_trace_matches_otp() {
        trace_pattern_diff(
            "trace_t3a_exception",
            "-module(trace_t3a_exception). -export([run/0]). run() -> Parent=self(), P=spawn(fun() -> receive go -> try f() catch error:boom -> ok end, Parent ! done end end), erlang:trace(P,true,[call]), erlang:trace_pattern({trace_t3a_exception,f,0}, [{'_',[],[{exception_trace}]}],[local]), P ! go, receive {trace,P,exception_from,{trace_t3a_exception,f,0},{error,boom}} -> ok after 1000 -> missing end. f() -> erlang:error(boom).",
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
    fn trace_send_flag_is_recorded_and_cleared() {
        let process = Process::new();
        let pid = Pid {
            index: 7001,
            generation: 1,
        };
        configure(&process, pid, true, SEND, Tracer::Pid(pid));
        assert_eq!(flags(&process, pid), SEND);
        configure(&process, pid, false, SEND, Tracer::Pid(pid));
        assert_eq!(flags(&process, pid), 0);
    }

    #[test]
    fn trace_receive_flag_is_recorded() {
        let process = Process::new();
        let pid = Pid {
            index: 7002,
            generation: 1,
        };
        configure(&process, pid, true, RECEIVE, Tracer::Pid(pid));
        assert_eq!(flags(&process, pid), RECEIVE);
        configure(&process, pid, false, RECEIVE, Tracer::Pid(pid));
    }

    #[test]
    fn trace_procs_flags_are_recorded() {
        let process = Process::new();
        let pid = Pid {
            index: 7003,
            generation: 1,
        };
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
        let pid = Pid {
            index: 7004,
            generation: 1,
        };
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
            Tracer::Pid(Pid {
                index: 7005,
                generation: 1,
            }),
        );
        assert!(destroy_session(&process, session));
        assert!(!destroy_session(&process, session));
    }

    #[test]
    fn trace_sessions_store_flags_independently() {
        let process = Process::new();
        let pid = Pid {
            index: 7006,
            generation: 1,
        };
        let a = create_session(&process, Tracer::Pid(pid));
        let b = create_session(&process, Tracer::Pid(pid));
        configure_session(&process, a, pid, true, SEND, Tracer::Pid(pid));
        configure_session(&process, b, pid, true, RECEIVE, Tracer::Pid(pid));
        assert_eq!(session_flags(&process, a, pid), SEND);
        assert_eq!(session_flags(&process, b, pid), RECEIVE);
        destroy_session(&process, a);
        destroy_session(&process, b);
    }
}
