//! BEAM exception tags, handlers, and exception terms.

use crate::{Process, Vm, VmError, stacktrace};
use arinsal_bifs::{BifError, Class, FragmentingHeap};
use arinsal_etf::OwnedTerm;
use arinsal_loader::{Arg, Module};
use arinsal_spec::Opcode;
use arinsal_term::{Atom, Term, TermBuilder, global_atoms, to_owned};
use std::fmt;

/// A BEAM exception before handler dispatch.
#[derive(Debug)]
pub struct Trap {
    pub(super) class: Class,
    pub(super) reason: Term,
    pub(super) trace: Option<Term>,
    pub(super) top: Option<stacktrace::TopFrame>,
    pub(super) raw_rethrow: bool,
    pub(super) untrappable: bool,
}

/// An uncaught Erlang exception detached from the process heap.
#[derive(Debug)]
pub struct Raised {
    /// Exception class.
    pub class: Class,
    /// Exception reason.
    pub reason: OwnedTerm,
    /// Symbolic stacktrace.
    pub stack: OwnedTerm,
}

impl fmt::Display for Raised {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let class = match self.class {
            Class::Error => "error",
            Class::Exit => "exit",
            Class::Throw => "throw",
        };
        write!(f, "** exception {class}: {}", self.reason)?;
        let OwnedTerm::List { elems, .. } = &self.stack else {
            return Ok(());
        };
        for (index, frame) in elems.iter().enumerate() {
            let OwnedTerm::Tuple(parts) = frame else {
                continue;
            };
            if parts.len() != 4 {
                continue;
            }
            let arity = match &parts[2] {
                OwnedTerm::Int(arity) => *arity as usize,
                OwnedTerm::List { elems, .. } => elems.len(),
                _ => 0,
            };
            if index == 0 {
                write!(f, "\n     in function  {}:{}/{arity}", parts[0], parts[1])?;
            } else {
                write!(f, "\n     in call from {}:{}/{arity}", parts[0], parts[1])?;
            }
            if let OwnedTerm::List { elems: args, .. } = &parts[2] {
                write!(f, "\n        called as {}:{}(", parts[0], parts[1])?;
                for (n, arg) in args.iter().enumerate() {
                    if n > 0 {
                        f.write_str(",")?;
                    }
                    write!(f, "{arg}")?;
                }
                f.write_str(")")?;
            }
            if let OwnedTerm::List { elems: entries, .. } = &parts[3] {
                let mut file = None;
                let mut line = None;
                for entry in entries {
                    let OwnedTerm::Tuple(pair) = entry else {
                        continue;
                    };
                    if pair.len() != 2 {
                        continue;
                    }
                    match (&pair[0], &pair[1]) {
                        (OwnedTerm::Atom(key), OwnedTerm::List { elems, .. }) if key == "file" => {
                            file = elems
                                .iter()
                                .map(|ch| match ch {
                                    OwnedTerm::Int(value) => char::from_u32(*value as u32),
                                    _ => None,
                                })
                                .collect::<Option<String>>();
                        }
                        (OwnedTerm::Atom(key), OwnedTerm::Int(value)) if key == "line" => {
                            line = Some(*value);
                        }
                        _ => {}
                    }
                }
                if let (Some(file), Some(line)) = (file, line) {
                    write!(f, " ({file}, line {line})")?;
                }
            }
        }
        Ok(())
    }
}

impl Trap {
    /// An `error`-class exception with `reason` and a stack trace built on dispatch.
    pub(super) fn error(reason: Term) -> Self {
        Self {
            class: Class::Error,
            reason,
            trace: None,
            top: None,
            raw_rethrow: false,
            untrappable: false,
        }
    }
    pub(super) fn exit(reason: Term) -> Self {
        Self {
            class: Class::Exit,
            reason,
            trace: None,
            top: None,
            raw_rethrow: false,
            untrappable: false,
        }
    }

    /// An `exit/2` self-signal that erts handles before returning to BEAM code.
    pub(super) fn untrappable_exit(reason: Term) -> Self {
        Self {
            class: Class::Exit,
            reason,
            trace: None,
            top: None,
            raw_rethrow: false,
            untrappable: true,
        }
    }

    /// An exit signal carrying `kill` cannot be caught by the receiving process.
    pub(super) fn killed() -> Self {
        Self {
            class: Class::Exit,
            reason: crate::signals::atom("killed"),
            trace: None,
            top: None,
            raw_rethrow: false,
            untrappable: true,
        }
    }
}

/// Decode an exception raised by a native runtime hook after native state is committed.
pub(super) fn native_trap(class: u64, reason: u64) -> Result<Trap, VmError> {
    // SAFETY: The native hook accepts only tagged BEAM terms supplied by generated code.
    let reason = unsafe { Term::from_raw_bits(reason) };
    // BeamAsm emitters store either the compact class tags used by `set_error`
    // (1/2/3) or OTP-style freason codes / the module assembler's `0x1b` error
    // sentinel from `emit_error`. All of those are Error-class exits unless the
    // compact Exit/Throw tags are used.
    let class = match class {
        1 | 0x1b => Class::Error,
        2 => Class::Exit,
        3 => Class::Throw,
        other if other != 0 => Class::Error,
        _ => return Err(VmError::Unsupported("native exception class".into())),
    };
    Ok(Trap {
        class,
        reason,
        trace: None,
        top: None,
        raw_rethrow: false,
        untrappable: false,
    })
}

fn atom(name: &str) -> Result<Term, VmError> {
    static COMMON: std::sync::OnceLock<[Atom; 5]> = std::sync::OnceLock::new();
    let common = COMMON.get_or_init(|| {
        let atoms = global_atoms();
        ["badarg", "badarith", "system_limit", "error", "exit"]
            .map(|name| atoms.intern(name).expect("built-in exception atom"))
    });
    let atom = match name {
        "badarg" => Some(common[0]),
        "badarith" => Some(common[1]),
        "system_limit" => Some(common[2]),
        "error" => Some(common[3]),
        "exit" => Some(common[4]),
        _ => None,
    };
    atom.map(Term::atom)
        .map_or_else(|| stacktrace::atom_term(name), Ok)
}

/// `{Class, Reason}` as reported by exception trace events.
// Port of erts/emulator/beam/beam_common.c:510-516 (handle_error): a throw with no catch
// active is reported as `{error,{nocatch,Reason}}` from the first event on.
pub(crate) fn trace_class_reason(
    p: &mut Process,
    class: Class,
    reason: Term,
) -> Result<Term, VmError> {
    if class == Class::Throw && p.header.catches == 0 {
        let nocatch = tuple(p, &[atom("nocatch")?, reason])?;
        return tuple(p, &[class_term(Class::Error)?, nocatch]);
    }
    tuple(p, &[class_term(class)?, reason])
}

pub(super) fn tuple(p: &mut Process, values: &[Term]) -> Result<Term, VmError> {
    TermBuilder::new(&mut FragmentingHeap(&mut p.heap))
        .tuple(values)
        .map_err(|e| VmError::Unsupported(format!("exception tuple {e:?}")))
}

fn list(p: &mut Process, values: &[Term]) -> Result<Term, VmError> {
    TermBuilder::new(&mut FragmentingHeap(&mut p.heap))
        .list_from_iter(values.iter().copied())
        .map_err(|e| VmError::Unsupported(format!("exception list {e:?}")))
}

pub(super) fn class_term(class: Class) -> Result<Term, VmError> {
    atom(match class {
        Class::Error => "error",
        Class::Exit => "exit",
        Class::Throw => "throw",
    })
}

pub(super) fn parse_class(term: Term) -> Option<Class> {
    let atom = term.as_atom()?;
    let name = arinsal_term::global_atoms().text(atom)?;
    match name {
        "error" => Some(Class::Error),
        "exit" => Some(Class::Exit),
        "throw" => Some(Class::Throw),
        _ => None,
    }
}

fn empty_trace_handle(class: Class) -> Term {
    let class = match class {
        Class::Error => 0,
        Class::Exit => 1,
        Class::Throw => 2,
    };
    let index = ((u32::MAX >> 2) << 2) | class;
    Term::catch((((1_u64 << 26) - 1) << 32) | u64::from(index))
}

pub(super) fn empty_trace_class(term: Term) -> Option<Class> {
    [Class::Error, Class::Exit, Class::Throw]
        .into_iter()
        .find(|&class| term == empty_trace_handle(class))
}

/// Preserve BIF exception classes and terms across interpreter dispatch.
pub(super) fn bif_error(
    p: &mut Process,
    module: &str,
    function: &str,
    args: &[Term],
    error: BifError,
) -> VmError {
    let Ok(module_atom) = global_atoms().intern(module) else {
        return VmError::Unsupported(format!("exception module atom {module}"));
    };
    let Ok(function_atom) = global_atoms().intern(function) else {
        return VmError::Unsupported(format!("exception function atom {function}"));
    };
    bif_error_with_atoms(p, module, function, module_atom, function_atom, args, error)
}

pub(super) fn bif_error_with_atoms(
    p: &mut Process,
    module: &str,
    function: &str,
    module_atom: Atom,
    function_atom: Atom,
    args: &[Term],
    error: BifError,
) -> VmError {
    if let BifError::Dirty(class) = error {
        // Port of erts/emulator/beam/erl_nif.c:3540 (enif_schedule_nif), OTP-29.1.1: the
        // call traps to a continuation that must run on a scheduler of `class`.
        if let Some(pending) = crate::natives::nif::take_rescheduled() {
            p.cold_mut().nif_pending = Some(pending);
        }
        return match class {
            arinsal_bifs::SchedulerClass::Normal => VmError::Yield,
            arinsal_bifs::SchedulerClass::DirtyCpu => VmError::Dirty(arinsal_sched::DirtyKind::Cpu),
            arinsal_bifs::SchedulerClass::DirtyIo => VmError::Dirty(arinsal_sched::DirtyKind::Io),
        };
    }
    // A raised BIF exception abandons the suspended call before catch/after
    // code runs, so its process-local continuation must not survive unwind.
    if let Some(cold) = p.cold.as_mut() {
        cold.nif_pending = None;
    }
    if let Some(pending) = p.cold_mut().bif_trap.take() {
        p.set_gc_enabled(pending.gc_was_enabled);
    }
    if let BifError::Unsupported(reason) = error {
        return VmError::Unsupported(reason.into());
    }
    let trap = (|| -> Result<Trap, VmError> {
        if let BifError::Raise {
            class,
            reason,
            stacktrace,
        } = error
        {
            let top = if module == "erlang" && function == "error" && args.len() > 1 {
                let frame_args = proper_list(args[1]).then_some(args[1]);
                match args.get(2).and_then(error_info_option) {
                    Some(info) => Some(stacktrace::TopFrame::CurrentArgsWithInfo(
                        frame_args,
                        Box::new(info),
                    )),
                    None => frame_args.map(stacktrace::TopFrame::CurrentArgs),
                }
            } else {
                None
            };
            return Ok(Trap {
                class,
                reason,
                trace: stacktrace,
                top,
                raw_rethrow: false,
                untrappable: false,
            });
        }
        let info = match error {
            BifError::Badarg { cause: Some(cause) } => cause.as_atom().map_or(
                stacktrace::BifErrorInfo::Plain,
                stacktrace::BifErrorInfo::Cause,
            ),
            _ => stacktrace::BifErrorInfo::Plain,
        };
        let reason = match error {
            BifError::Badarg { .. } => atom("badarg")?,
            BifError::Badarith => atom("badarith")?,
            BifError::SystemLimit => atom("system_limit")?,
            BifError::Error(value) => value,
            BifError::Raise { .. } | BifError::Unsupported(_) | BifError::Dirty(_) => {
                unreachable!()
            }
        };
        Ok(Trap {
            class: Class::Error,
            reason,
            trace: None,
            top: Some(stacktrace::TopFrame::Bif {
                module: module_atom,
                function: function_atom,
                args: stacktrace::BifArgs::from_terms(args)?,
                info,
            }),
            raw_rethrow: false,
            untrappable: false,
        })
    })();
    match trap {
        Ok(trap) => VmError::Trap(trap),
        Err(error) => error,
    }
}

// Port of erts/emulator/beam/bif.c:1464-1499 (error_3 option validation), OTP-29.1.1.
fn error_info_option(options: &Term) -> Option<OwnedTerm> {
    let owned = to_owned(*options).ok()?;
    let OwnedTerm::List { elems, tail } = &owned else {
        return None;
    };
    if **tail != OwnedTerm::Nil {
        return None;
    }
    if elems.is_empty() {
        return None;
    }
    let mut error_info = None;
    for option in elems {
        let OwnedTerm::Tuple(fields) = option else {
            return None;
        };
        if fields.len() != 2 || fields[0] != OwnedTerm::atom("error_info") {
            return None;
        }
        let OwnedTerm::Map(_) = &fields[1] else {
            return None;
        };
        error_info = Some(fields[1].clone());
    }
    error_info
}

fn proper_list(term: Term) -> bool {
    matches!(
        to_owned(term).as_ref(),
        Ok(OwnedTerm::List { tail, .. }) if **tail == OwnedTerm::Nil
    )
}

/// Detach a direct host-to-BIF failure when there is no BEAM caller frame.
pub(super) fn direct_bif_error(
    p: &mut Process,
    module: &str,
    function: &str,
    args: &[Term],
    error: BifError,
) -> VmError {
    let trap = match bif_error(p, module, function, args, error) {
        VmError::Trap(trap) => trap,
        error => return error,
    };
    let result = (|| -> Result<Raised, VmError> {
        let mut class = trap.class;
        let mut reason = to_owned(trap.reason)
            .map_err(|e| VmError::Unsupported(format!("exception reason {e:?}")))?;
        if class == Class::Throw {
            class = Class::Error;
            reason = OwnedTerm::Tuple(vec![OwnedTerm::Atom("nocatch".into()), reason]);
        }
        let stack = match trap.trace {
            Some(trace) => to_owned(trace)
                .map_err(|e| VmError::Unsupported(format!("exception stack {e:?}")))?,
            None => OwnedTerm::Nil,
        };
        Ok(Raised {
            class,
            reason,
            stack,
        })
    })();
    match result {
        Ok(raised) => VmError::Raised(Box::new(raised)),
        Err(error) => error,
    }
}

pub(super) fn system_flag(
    process: &crate::Process,
    depth_limit: &mut usize,
    key: Term,
    value: Term,
) -> Result<Term, VmError> {
    if key == atom("system_logger")? {
        return crate::natives::sys::set_system_logger(process, value);
    }
    if key != atom("backtrace_depth")? {
        return Err(VmError::Unsupported("system_flag setting".into()));
    }
    let Some(depth) = value.as_small().filter(|depth| *depth >= 0) else {
        return Err(VmError::Trap(Trap::error(atom("badarg")?)));
    };
    let requested = (depth as usize).min(64);
    let old = process.runtime.as_ref().map_or(*depth_limit, |runtime| {
        runtime
            .backtrace_depth
            .swap(requested, std::sync::atomic::Ordering::AcqRel)
    });
    *depth_limit = requested;
    Ok(Term::small(old as i64).expect("depth is small"))
}

fn source(p: &Process, arg: Arg) -> Result<Term, VmError> {
    p.read(arg)
}

/// Port of erts/emulator/beam/emu/instrs.tab:1170 (catch/try), OTP-29.1.1.
#[inline]
pub(super) fn execute(vm: &Vm, p: &mut Process, op: Opcode, a: Arg, b: Arg) -> Result<(), VmError> {
    match op {
        Opcode::Try | Opcode::Catch => {
            if a.kind() != Arg::Y || b.kind() != Arg::LABEL {
                return Err(VmError::Unsupported("exception handler operands".into()));
            }
            let tag = stacktrace::handler_tag(p.module, b.value() as usize)?;
            p.write(a, tag)?;
            p.header.catches = p.header.catches.saturating_add(1);
            p.ip += 1;
        }
        Opcode::TryEnd | Opcode::TryCase => {
            p.write(a, Term::NIL)?;
            p.header.catches = p.header.catches.saturating_sub(1);
            if op == Opcode::TryCase {
                p.x[0] = p.x[3];
            }
            p.ip += 1;
        }
        Opcode::CatchEnd => {
            p.write(a, Term::NIL)?;
            p.header.catches = p.header.catches.saturating_sub(1);
            if p.x[0] == Term::catch(0) {
                let reason = p.x[1];
                p.x[0] = match parse_class(p.x[3]) {
                    Some(Class::Throw) => reason,
                    Some(Class::Error) => {
                        let trace = materialize(p, p.x[2])?;
                        p.x[2] = trace;
                        let reason_with_trace = tuple(p, &[reason, trace])?;
                        tuple(p, &[atom("EXIT")?, reason_with_trace])?
                    }
                    Some(Class::Exit) => tuple(p, &[atom("EXIT")?, reason])?,
                    None => return Err(VmError::Unsupported("exception class".into())),
                };
            }
            p.ip += 1;
        }
        Opcode::Badmatch | Opcode::CaseEnd | Opcode::TryCaseEnd | Opcode::Badrecord => {
            let key = match op {
                Opcode::Badmatch => "badmatch",
                Opcode::CaseEnd => "case_clause",
                Opcode::TryCaseEnd => "try_clause",
                Opcode::Badrecord => "badrecord",
                _ => unreachable!(),
            };
            let value = source(p, a)?;
            let reason = tuple(p, &[atom(key)?, value])?;
            return Err(VmError::Trap(Trap::error(reason)));
        }
        Opcode::IfEnd => return Err(VmError::Trap(Trap::error(atom("if_clause")?))),
        Opcode::FuncInfo => {
            let module: &Module = &vm.modules[p.module];
            let (_, arity) = module.function_at(p.ip).unwrap_or(("?", 0));
            let args = p.x[..usize::from(arity)].to_vec();
            let args = list(p, &args)?;
            return Err(VmError::Trap(Trap {
                class: Class::Error,
                reason: atom("function_clause")?,
                trace: None,
                top: Some(stacktrace::TopFrame::CurrentArgs(args)),
                raw_rethrow: false,
                untrappable: false,
            }));
        }
        Opcode::Raise | Opcode::RawRaise => {
            // mix_loop1: `raise/2` is the try/after re-raise. OTP reads the class
            // from the raw stacktrace's freason (i_raise / erts_sanitize_freason),
            // which survives the `after` body. X(3) does not: `gen_server` calls
            // `reply/2` before re-raising. An invalid class must not fall through
            // into the next basic block (that block's Y frame was already trimmed).
            let saved_trace = if op == Opcode::Raise {
                Some(source(p, a)?)
            } else {
                None
            };
            let class = if op == Opcode::RawRaise {
                parse_class(p.x[0])
            } else {
                saved_trace
                    .and_then(|trace| {
                        empty_trace_class(trace).or_else(|| stacktrace::raw_class(p, trace))
                    })
                    .or(p.exc_class)
                    .or_else(|| parse_class(p.x[3]))
            };
            let Some(class) = class else {
                p.x[0] = atom("badarg")?;
                if op == Opcode::RawRaise {
                    p.ip += 1;
                    return Ok(());
                }
                return Err(VmError::Trap(Trap::error(atom("badarg")?)));
            };
            if op == Opcode::RawRaise {
                let trace = p.x[2];
                if !stacktrace::set_raw_class(p, trace, class) {
                    p.x[0] = atom("badarg")?;
                    p.ip += 1;
                    return Ok(());
                }
            }
            let (reason, trace) = if op == Opcode::Raise {
                (source(p, b)?, saved_trace.expect("raise trace"))
            } else {
                (p.x[1], p.x[2])
            };
            return Err(VmError::Trap(Trap {
                class,
                reason,
                trace: Some(trace),
                top: None,
                raw_rethrow: op == Opcode::RawRaise,
                untrappable: false,
            }));
        }
        Opcode::BuildStacktrace => {
            // Port of erts/emulator/beam/beam_common.c:1205 (build_stacktrace), OTP-29.1.1.
            p.x[0] = materialize(p, p.x[0])?;
            p.ip += 1;
        }
        _ => {
            return Err(VmError::Unsupported(format!(
                "exception opcode {}",
                op.name()
            )));
        }
    }
    Ok(())
}

/// Port of erts/emulator/beam/beam_common.c:449 (handle_error), OTP-29.1.1.
pub(super) fn resume(
    vm: &mut Vm,
    p: &mut Process,
    mut ctx: Option<&mut arinsal_sched::RunCtx<'_, crate::process::Message>>,
    mut trap: Trap,
) -> Result<Option<VmError>, VmError> {
    // An exception leaves the active BEAM call site. Any trap record belongs
    // to that abandoned call, even if the error did not originate in its BIF.
    if let Some(pending) = p.cold_mut().bif_trap.take() {
        p.set_gc_enabled(pending.gc_was_enabled);
    }
    if trap.untrappable {
        let reason = to_owned(trap.reason)
            .map_err(|e| VmError::Unsupported(format!("exception reason {e:?}")))?;
        return Ok(Some(VmError::Raised(Box::new(Raised {
            class: trap.class,
            reason,
            stack: OwnedTerm::Nil,
        }))));
    }
    let trace = if let Some(trace) = trap.trace {
        // OTP's raise/3 accepts an empty explicit stacktrace; it needs no raw
        // handle because materializing that handle would return the same nil.
        if trace == Term::NIL {
            empty_trace_handle(trap.class)
        } else if empty_trace_class(trace).is_some() || stacktrace::is_saved(trace) {
            trace
        } else {
            save_explicit(p, trace, trap.class)?
        }
    } else {
        save_raw(vm, p, vm.backtrace_depth, trap.class, trap.top.as_ref())?
    };
    let trace = if trap.raw_rethrow && trap.reason == atom("function_clause")? {
        let cooked = materialize(p, trace)?;
        let stripped = strip_top_location(p, cooked)?;
        save_explicit(p, stripped, trap.class)?
    } else {
        trace
    };
    let mut frame_start = 0;
    let mut handler = None;
    let mut index = 0;
    // Sessions with a return_to frame on the unwound stack: the catching function gets their
    // return_to event.
    let mut return_to_sessions: Vec<u64> = p
        .cold
        .as_mut()
        .map(|cold| std::mem::take(&mut cold.bif_return_to))
        .unwrap_or_default();
    while index < p.heap.stack_words() {
        // Port of beam_common.c:600-614 (`is_CP`/`erts_inspect_frame`), OTP-29.1.1.
        if let Some(word) = p.heap.stack_get(index) {
            let address = word.tagged_word() as usize;
            if address == crate::native_bridge::native_trace_return_address() {
                let (function_pc, actions, frame_words) =
                    crate::trace::native_frame_actions(p, index + 2);
                if let Some(function) = crate::native_function_at(function_pc)
                    && let Some(trace_ctx) = ctx.as_deref_mut()
                {
                    let class_reason = trace_class_reason(p, trap.class, trap.reason)?;
                    crate::trace::native_return_events(
                        vm,
                        p,
                        trace_ctx,
                        &function,
                        &actions,
                        class_reason,
                        true,
                    )?;
                }
                return_to_sessions.extend(
                    actions
                        .iter()
                        .filter(|action| action.return_to)
                        .map(|action| action.session),
                );
                frame_start = index + frame_words;
                index += frame_words;
                continue;
            }
            // Only CP words (low tag bits 00, erts is_CP) can be native return addresses.
            if address & 3 == 0 && crate::native_bridge::is_native_function_at(address) {
                frame_start = index + 1;
                index += 1;
                continue;
            }
        }
        let Some(word) = p.heap.stack_get(index) else {
            index += 1;
            continue;
        };
        // Port of erts/emulator/beam/beam_common.c:581-680 (next_catch), OTP-29.1.1: the
        // frames above were unwound here (with their exception trace events); a catch in a
        // native frame is resumed by the native catch search.
        if crate::native_bridge::is_native_catch_tag(word)
            && let Some(handler) =
                crate::native_bridge::next_catch(p, trap.class, trap.reason, trace)
        {
            let target = match handler {
                crate::native_bridge::CatchHandler::Native(handler) => {
                    p.native_pc = Some(handler);
                    crate::native_function_at(handler)
                        .map(|function| (function.module, function.function, function.arity))
                }
                crate::native_bridge::CatchHandler::Interpreted => {
                    vm.modules.get(p.module).and_then(|module| {
                        module.function_at(p.ip).map(|(function, arity)| {
                            (module.name.clone(), function.to_owned(), arity)
                        })
                    })
                }
            };
            if let Some(trace_ctx) = ctx.as_deref_mut() {
                crate::trace::unwound_return_to(vm, p, trace_ctx, &return_to_sessions, target)?;
            }
            // The exception is caught: an exit reason noted for it must not name a later death.
            if let Some(cold) = p.cold.as_mut() {
                cold.exit_reason = None;
            }
            return Ok(None);
        }
        let Some((is_handler, module, ip)) = stacktrace::decode_tag(word) else {
            index += 1;
            continue;
        };
        if !is_handler {
            let special = vm.modules.get(module).and_then(|module| {
                if ip == module.return_trace_ip {
                    Some((true, module))
                } else if ip == module.return_to_trace_ip {
                    Some((false, module))
                } else {
                    None
                }
            });
            if let Some((return_trace, _)) = special {
                let width = if return_trace { 6 } else { 2 };
                if !return_trace
                    && let Some(session) = p.heap.stack_get(index + 1).and_then(Term::as_small)
                {
                    return_to_sessions.push(session as u64);
                }
                if return_trace
                    && let (
                        Some(frame_module),
                        Some(entry),
                        Some(session_high),
                        Some(session_low),
                        Some(exception),
                    ) = (
                        p.heap.stack_get(index + 1).and_then(Term::as_small),
                        p.heap.stack_get(index + 2).and_then(Term::as_small),
                        p.heap.stack_get(index + 3).and_then(Term::as_small),
                        p.heap.stack_get(index + 4).and_then(Term::as_small),
                        p.heap.stack_get(index + 5).and_then(Term::as_small),
                    )
                    && exception & 1 != 0
                    && exception & 2 == 0
                    && let Some(trace_ctx) = ctx.as_deref_mut()
                {
                    let class_reason = trace_class_reason(p, trap.class, trap.reason)?;
                    crate::trace::return_event(
                        vm,
                        p,
                        trace_ctx,
                        ((session_high as u64) << 32) | session_low as u32 as u64,
                        frame_module as usize,
                        entry as usize,
                        class_reason,
                        true,
                        Some(class_reason),
                    )?;
                }
                frame_start = index + width;
                index += width;
                continue;
            }
            frame_start = index + 1;
            index += 1;
            continue;
        }
        handler = Some((index, frame_start, module, ip));
        break;
    }
    if let Some((index, frame_start, module, ip)) = handler {
        if !p.heap.release_stack(frame_start) {
            return Err(VmError::Unsupported("exception stack".into()));
        }
        p.heap.stack_set(index - frame_start, Term::NIL);
        p.module = module;
        p.ip = ip;
        if p.x.len() < 4 {
            let mut registers = p.x.to_vec();
            registers.resize(4, Term::NIL);
            p.x = registers.into_boxed_slice();
        }
        p.x[0] = Term::catch(0);
        p.x[1] = trap.reason;
        p.x[2] = trace;
        p.x[3] = class_term(trap.class)?;
        // The handler's try_case/catch_end read x0-x3, so a switch-out before it runs
        // (reductions exhausted by the failing BIF) must root all four.
        p.gc_live = 4;
        // mix_loop1: keep the class for a later raise/2. See Opcode::Raise.
        p.exc_class = Some(trap.class);
        if !return_to_sessions.is_empty()
            && let Some(trace_ctx) = ctx
        {
            let target = vm.modules.get(module).and_then(|loaded| {
                loaded
                    .function_at(ip)
                    .map(|(function, arity)| (loaded.name.clone(), function.to_owned(), arity))
            });
            crate::trace::unwound_return_to(vm, p, trace_ctx, &return_to_sessions, target)?;
        }
        if let Some(cold) = p.cold.as_mut() {
            cold.exit_reason = None;
        }
        return Ok(None);
    }
    if trap.class == Class::Throw {
        trap.class = Class::Error;
        trap.reason = tuple(p, &[atom("nocatch")?, trap.reason])?;
    }
    let reason = to_owned(trap.reason)
        .map_err(|e| VmError::Unsupported(format!("exception reason {e:?}")))?;
    let stack = if trap.class == Class::Error {
        let trace = materialize(p, trace)?;
        to_owned(trace).map_err(|e| VmError::Unsupported(format!("exception stack {e:?}")))?
    } else {
        OwnedTerm::Nil
    };
    Ok(Some(VmError::Raised(Box::new(Raised {
        class: trap.class,
        reason,
        stack,
    }))))
}

// Port of erts/emulator/beam/beam_common.c:581-680 (next_catch), OTP-29.1.1.
/// Port of erts/emulator/beam/beam_common.c:880 (save_stacktrace), OTP-29.1.1.
fn save_raw(
    vm: &Vm,
    p: &mut Process,
    depth: usize,
    class: Class,
    top: Option<&stacktrace::TopFrame>,
) -> Result<Term, VmError> {
    let error_pc = p
        .cold
        .as_deref_mut()
        .map_or(0, |cold| std::mem::take(&mut cold.native_error_pc));
    let mut raw = stacktrace::RawTrace::default();
    stacktrace::capture(
        &mut raw,
        Some(class),
        top,
        &vm.modules,
        (p.module, p.ip),
        &p.heap,
        depth,
    )?;
    if error_pc != 0 && crate::native_bridge::is_native_function_at(error_pc) {
        stacktrace::set_native_top(&mut raw, error_pc);
    }
    stacktrace::store(p, raw)
}

fn save_explicit(p: &mut Process, trace: Term, class: Class) -> Result<Term, VmError> {
    let mut raw = stacktrace::RawTrace::default();
    stacktrace::save_explicit(&mut raw, class, trace)?;
    stacktrace::store(p, raw)
}

pub(super) fn materialize(p: &mut Process, trace: Term) -> Result<Term, VmError> {
    if empty_trace_class(trace).is_some() {
        return Ok(Term::NIL);
    }
    // The saved trace stays behind the term: the same one can be rebuilt by a later raise.
    match stacktrace::with_saved(trace, |raw| stacktrace::build_saved(p, raw)) {
        Some(result) => result,
        None => Ok(trace),
    }
}

fn strip_top_location(p: &mut Process, trace: Term) -> Result<Term, VmError> {
    // SAFETY: The symbolic trace is process-owned; fragment allocation below cannot collect it.
    let Some((head, tail)) = (unsafe { trace.cons_ref() }) else {
        return Ok(trace);
    };
    // SAFETY: Stack frames are tuples allocated on a live process heap.
    let Some(frame) = (unsafe { head.tuple_ref() }) else {
        return Ok(trace);
    };
    if frame.len() != 4 {
        return Ok(trace);
    }
    let frame = tuple(
        p,
        &[
            frame.get(0).unwrap(),
            frame.get(1).unwrap(),
            frame.get(2).unwrap(),
            Term::NIL,
        ],
    )?;
    TermBuilder::new(&mut FragmentingHeap(&mut p.heap))
        .cons(frame, tail)
        .map_err(|e| VmError::Unsupported(format!("raw stacktrace {e:?}")))
}

pub(super) fn from_legacy(reason: &str) -> Result<Trap, VmError> {
    Ok(Trap::error(atom(reason)?))
}
