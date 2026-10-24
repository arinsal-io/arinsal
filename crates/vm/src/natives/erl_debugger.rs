//! OTP debugger BIFs and debugger event delivery.

use crate::process::Message;
use crate::{Process, Vm, VmError};
use arinsal_etf::OwnedTerm as O;
use arinsal_sched::{Pid, RunCtx};
use arinsal_term::{Term, TermKind, from_owned, global_atoms, size_object, to_owned};
use std::collections::BTreeMap;

pub(crate) const IMPLEMENTED: &[(&str, &str, u8)] = &[
    ("erl_debugger", "supported", 0),
    ("erl_debugger", "instrumentations", 0),
    ("erl_debugger", "toggle_instrumentations", 1),
    ("erl_debugger", "register", 1),
    ("erl_debugger", "unregister", 2),
    ("erl_debugger", "whereis", 0),
    ("erl_debugger", "breakpoint", 3),
    ("erl_debugger", "breakpoints", 1),
    ("erl_debugger", "breakpoints", 3),
    ("erl_debugger", "stack_frames", 2),
    ("erl_debugger", "peek_stack_frame_slot", 4),
    ("erl_debugger", "xregs_count", 1),
    ("erl_debugger", "peek_xreg", 3),
    ("erts_internal", "notify_breakpoint_hit", 3),
    ("erts_debug", "breakpoint", 2),
];

fn atom(name: &str) -> Term {
    Term::atom(global_atoms().intern(name).expect("built-in debugger atom"))
}

fn badarg() -> VmError {
    VmError::Trap(crate::exceptions::Trap::error(atom("badarg")))
}

fn undef() -> VmError {
    VmError::Trap(crate::exceptions::Trap::error(atom("undef")))
}

fn integer(value: usize) -> O {
    if let Ok(value) = i64::try_from(value) {
        O::Int(value)
    } else {
        O::BigInt(num_bigint::BigInt::from(value))
    }
}

fn from_owned_term(process: &mut Process, value: &O) -> Result<Term, VmError> {
    from_owned(
        value,
        &mut arinsal_bifs::ProcessHeapHandle(&mut process.heap),
    )
    .map_err(|_| VmError::Trap(crate::exceptions::Trap::error(atom("system_limit"))))
}

fn bool_term(value: bool) -> O {
    O::Atom(if value { "true" } else { "false" }.into())
}

fn call_impl(
    vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    module: &str,
    function: &str,
    args: &[Term],
) -> Result<Term, VmError> {
    if module == "erl_debugger" && function != "supported" && !crate::trace_bp::debugger_supported()
        || module == "erts_internal" && !crate::trace_bp::debugger_supported()
    {
        return Err(undef());
    }
    match (module, function, args) {
        ("erl_debugger", "supported", []) => Ok(atom(if crate::trace_bp::debugger_supported() {
            "true"
        } else {
            "false"
        })),
        ("erl_debugger", "instrumentations", []) => instrumentation_map(process),
        ("erl_debugger", "toggle_instrumentations", [toggles]) => {
            toggle_instrumentations(process, *toggles)
        }
        ("erl_debugger", "register", [pid]) => register(process, ctx, *pid),
        ("erl_debugger", "unregister", [pid, session]) => unregister(process, *pid, *session),
        ("erl_debugger", "whereis", []) => whereis(process),
        ("erl_debugger", "breakpoint", [module, line, enable]) => {
            breakpoint(vm, process, *module, *line, *enable)
        }
        ("erl_debugger", "breakpoints", [module]) => breakpoints(vm, process, *module, None),
        ("erl_debugger", "breakpoints", [module, function, arity]) => {
            breakpoints(vm, process, *module, Some((*function, *arity)))
        }
        ("erl_debugger", "stack_frames", [pid, max_size]) => stack_frames(process, *pid, *max_size),
        ("erl_debugger", "peek_stack_frame_slot", [pid, frame, slot, max_size]) => {
            peek_stack_frame_slot(process, *pid, *frame, *slot, *max_size)
        }
        ("erl_debugger", "xregs_count", [pid]) => xregs_count(process, *pid),
        ("erl_debugger", "peek_xreg", [pid, register, max_size]) => {
            peek_xreg(process, *pid, *register, *max_size)
        }
        ("erts_internal", "notify_breakpoint_hit", [mfa, line, resume]) => {
            notify_breakpoint_hit(process, ctx, *mfa, *line, *resume)
        }
        ("erts_debug", "breakpoint", [pattern, enable]) => {
            debug_breakpoint(vm, process, *pattern, *enable)
        }
        _ => Err(badarg()),
    }
}

pub(crate) fn call(
    vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    module: &str,
    function: &str,
    args: super::NativeArgs<'_>,
) -> Option<Result<Term, VmError>> {
    if !super::listed(IMPLEMENTED, module, function, args.len() as u8) {
        return None;
    }
    args.with_values(process, |process, values| {
        Some(call_impl(vm, process, ctx, module, function, values))
    })
}

// Port of erts/emulator/beam/erl_debugger.c:87-99, OTP-29.1.1.
fn instrumentation_map(process: &mut Process) -> Result<Term, VmError> {
    let value = O::Map(vec![(
        O::Atom("line_breakpoint".into()),
        bool_term(crate::trace_bp::line_breakpoints_instrumented()),
    )]);
    from_owned_term(process, &value)
}

// Port of erts/emulator/beam/erl_debugger.c:70-112, OTP-29.1.1.
fn toggle_instrumentations(_process: &mut Process, toggles: Term) -> Result<Term, VmError> {
    let owned = to_owned(toggles).map_err(|_| badarg())?;
    let O::Map(entries) = &owned else {
        return Err(badarg());
    };
    let mut line_breakpoints = crate::trace_bp::line_breakpoints_instrumented();
    for (key, value) in entries {
        let (O::Atom(key), O::Atom(value)) = (key, value) else {
            return Err(badarg());
        };
        if key != "line_breakpoint" || (value != "true" && value != "false") {
            return Err(badarg());
        }
        line_breakpoints = value == "true";
    }
    crate::trace_bp::set_line_breakpoint_instrumentation(line_breakpoints);
    Ok(atom("ok"))
}

// Port of erts/emulator/beam/erl_debugger.c:126-160, OTP-29.1.1.
fn register(
    process: &mut Process,
    _ctx: &RunCtx<'_, Message>,
    term: Term,
) -> Result<Term, VmError> {
    let pid = Pid::from_term(term).ok_or_else(badarg)?;
    match crate::trace_bp::register_debugger(process, pid) {
        Ok(session) => from_owned_term(
            process,
            &O::Tuple(vec![O::Atom("ok".into()), O::Int(session as i64)]),
        ),
        Err(()) => from_owned_term(
            process,
            &O::Tuple(vec![
                O::Atom("error".into()),
                O::Atom("already_exists".into()),
            ]),
        ),
    }
}

// Port of erts/emulator/beam/erl_debugger.c:163-188, OTP-29.1.1.
fn unregister(process: &Process, term: Term, session: Term) -> Result<Term, VmError> {
    let pid = Pid::from_term(term).ok_or_else(badarg)?;
    let session = session.as_small().ok_or_else(badarg)? as u64;
    crate::trace_bp::unregister_debugger(process, pid, session).map_err(|_| badarg())?;
    Ok(atom("ok"))
}

// Port of erts/emulator/beam/erl_debugger.c:191-204, OTP-29.1.1.
fn whereis(process: &Process) -> Result<Term, VmError> {
    let Some(registration) = crate::trace_bp::debugger_registration(process) else {
        return Ok(atom("undefined"));
    };
    registration.pid.to_term().ok_or_else(badarg)
}

// Port of erts/emulator/beam/erl_debugger.c:318-403, OTP-29.1.1.
fn breakpoint(
    vm: &mut Vm,
    process: &mut Process,
    module: Term,
    line: Term,
    enable: Term,
) -> Result<Term, VmError> {
    let module = atom_text(module).ok_or_else(badarg)?;
    let line_term = line.as_small().ok_or_else(badarg)?;
    let line = line_term as i32;
    if line <= 0 {
        return Err(badarg());
    }
    let line = line as u32;
    if enable != atom("true") && enable != atom("false") {
        return Err(badarg());
    }
    let Some(&id) = vm.code.loaded.get(&module) else {
        return result_error(
            process,
            O::Tuple(vec![O::Atom("badkey".into()), O::Atom(module)]),
        );
    };
    let Some(code) = vm.code.modules.get(id) else {
        return result_error(
            process,
            O::Tuple(vec![O::Atom("badkey".into()), O::Atom(module)]),
        );
    };
    if !code.line_breakpoints_supported {
        return result_error(
            process,
            O::Tuple(vec![O::Atom("unsupported".into()), O::Atom(module)]),
        );
    }
    if !code
        .debug_line_points
        .iter()
        .any(|(_, candidate, _)| *candidate == line)
    {
        let appears_in_source = code
            .lines
            .values()
            .iter()
            .flatten()
            .any(|(_, n)| *n == u64::from(line));
        return result_error(
            process,
            O::Tuple(vec![
                O::Atom(
                    if appears_in_source {
                        "unsupported"
                    } else {
                        "badkey"
                    }
                    .into(),
                ),
                O::Int(line_term),
            ]),
        );
    }
    crate::trace_bp::set_line_breakpoint(process, id, line, enable == atom("true"));
    crate::beamasm_integration::patch_native_line_breakpoint(
        vm.code_scope,
        &module,
        line,
        enable == atom("true"),
    );
    Ok(atom("ok"))
}

// Port of erts/emulator/beam/erl_debugger.c:447-555, OTP-29.1.1.
fn breakpoints(
    vm: &Vm,
    process: &mut Process,
    module_term: Term,
    function: Option<(Term, Term)>,
) -> Result<Term, VmError> {
    let module_name = atom_text(module_term).ok_or_else(badarg)?;
    let function = function
        .map(|(function, arity)| {
            Ok((
                atom_text(function).ok_or_else(badarg)?,
                arity.as_small().ok_or_else(badarg)?,
            ))
        })
        .transpose()?;
    let Some(&id) = vm.code.loaded.get(&module_name) else {
        return if function.is_some() {
            result_error(
                process,
                O::Tuple(vec![O::Atom("badkey".into()), O::Atom(module_name)]),
            )
        } else {
            result_error(process, O::Atom("badkey".into()))
        };
    };
    let code = vm.code.modules.get(id).ok_or_else(badarg)?;
    if let Some((function, arity)) = function {
        let Some((start, _, _)) = code
            .functions
            .iter()
            .find(|(_, name, a)| name == &function && i64::from(*a) == arity)
        else {
            return result_error(
                process,
                O::Tuple(vec![
                    O::Atom("badkey".into()),
                    O::Tuple(vec![O::Atom(function), O::Int(arity)]),
                ]),
            );
        };
        let lines = line_map(process, id, code, *start);
        return from_owned_term(process, &O::Tuple(vec![O::Atom("ok".into()), lines]));
    }
    let mut functions = Vec::new();
    for (index, (start, name, arity)) in code.functions.iter().enumerate() {
        let end = code
            .functions
            .get(index + 1)
            .map_or(code.code.len(), |next| next.0);
        let lines = code
            .debug_line_points
            .iter()
            .filter(|(ip, _, _)| *ip >= *start && *ip < end)
            .map(|(_, line, _)| {
                (
                    *line,
                    bool_term(crate::trace_bp::line_breakpoint_enabled(process, id, *line)),
                )
            })
            .collect::<BTreeMap<_, _>>()
            .into_iter()
            .map(|(line, enabled)| (O::Int(i64::from(line)), enabled))
            .collect();
        functions.push((
            O::Tuple(vec![O::Atom(name.clone()), O::Int(i64::from(*arity))]),
            O::Map(lines),
        ));
    }
    from_owned_term(
        process,
        &O::Tuple(vec![O::Atom("ok".into()), O::Map(functions)]),
    )
}

fn line_map(process: &Process, module_id: usize, code: &arinsal_loader::Module, start: usize) -> O {
    let end = code
        .functions
        .iter()
        .find(|(candidate, _, _)| *candidate > start)
        .map_or(code.code.len(), |next| next.0);
    let lines = code
        .debug_line_points
        .iter()
        .filter(|(ip, _, _)| *ip >= start && *ip < end)
        .map(|(_, line, _)| {
            (
                *line,
                bool_term(crate::trace_bp::line_breakpoint_enabled(
                    process, module_id, *line,
                )),
            )
        })
        .collect::<BTreeMap<_, _>>()
        .into_iter()
        .map(|(line, enabled)| (O::Int(i64::from(line)), enabled))
        .collect();
    O::Map(lines)
}

fn result_error(process: &mut Process, reason: O) -> Result<Term, VmError> {
    from_owned_term(process, &O::Tuple(vec![O::Atom("error".into()), reason]))
}

// Port of erts/emulator/beam/erl_debugger.c:625-714, OTP-29.1.1.
fn stack_frames(process: &mut Process, pid_term: Term, max_size: Term) -> Result<Term, VmError> {
    let pid = inspect_pid(process, pid_term)?;
    let max_size = nonnegative(max_size)?;
    let runtime = process.runtime.ok_or_else(badarg)?;
    let Some(frames) = runtime.inspect_suspended(pid, |target, modules| {
        inspect_frames(target, modules, max_size, hibernation_arity(target))
    }) else {
        return Ok(atom("running"));
    };
    from_owned_term(
        process,
        &O::List {
            elems: frames,
            tail: Box::new(O::Nil),
        },
    )
}

// Port of erts/emulator/beam/erl_debugger.c:716-804, OTP-29.1.1.
fn peek_stack_frame_slot(
    process: &mut Process,
    pid_term: Term,
    frame_term: Term,
    slot_term: Term,
    max_size_term: Term,
) -> Result<Term, VmError> {
    let pid = inspect_pid(process, pid_term)?;
    let frame = nonnegative(frame_term)?;
    let slot = nonnegative(slot_term)?;
    let max_size = nonnegative(max_size_term)?;
    let runtime = process.runtime.ok_or_else(badarg)?;
    let Some(value) = runtime.inspect_suspended(pid, |target, modules| {
        inspect_frames(target, modules, max_size, hibernation_arity(target))
            .iter()
            .find(|frame_info| frame_number(frame_info) == Some(frame))
            .and_then(|frame| frame_slots(frame).get(slot).cloned())
    }) else {
        return Ok(atom("running"));
    };
    match value {
        Some(value) => from_owned_term(process, &value),
        None => Ok(atom("undefined")),
    }
}

// Port of erts/emulator/beam/erl_debugger.c:807-831, OTP-29.1.1.
fn xregs_count(process: &Process, pid_term: Term) -> Result<Term, VmError> {
    let pid = inspect_pid(process, pid_term)?;
    let runtime = process.runtime.as_ref().ok_or_else(badarg)?;
    let Some(count) =
        runtime.inspect_suspended(pid, |target, _| crate::process::switched_out_live(target))
    else {
        return Ok(atom("running"));
    };
    Term::small(count as i64).ok_or_else(badarg)
}

// Port of erts/emulator/beam/erl_debugger.c:833-900, OTP-29.1.1.
fn peek_xreg(
    process: &mut Process,
    pid_term: Term,
    register_term: Term,
    max_size_term: Term,
) -> Result<Term, VmError> {
    let pid = inspect_pid(process, pid_term)?;
    let register = nonnegative(register_term)?;
    let max_size = nonnegative(max_size_term)?;
    let runtime = process.runtime.ok_or_else(badarg)?;
    let Some(value) = runtime.inspect_suspended(pid, |target, _| {
        (register < crate::process::switched_out_live(target))
            .then(|| target.x[register])
            .map(|term| limit_term(term, max_size))
    }) else {
        return Ok(atom("running"));
    };
    match value {
        Some(value) => from_owned_term(process, &value),
        None => Ok(atom("undefined")),
    }
}

fn inspect_pid(process: &Process, term: Term) -> Result<Pid, VmError> {
    let pid = Pid::from_term(term).ok_or_else(badarg)?;
    let self_pid = process.header.self_pid;
    if term.tagged_word() == self_pid {
        return Err(badarg());
    }
    Ok(pid)
}

fn nonnegative(term: Term) -> Result<usize, VmError> {
    let value = term.as_small().ok_or_else(badarg)? as i32;
    usize::try_from(value).map_err(|_| badarg())
}

/// Code position of the frame being assembled by [`inspect_frames`].
#[derive(Clone, Copy)]
enum FramePc {
    Interpreted { module: usize, ip: usize },
    Native(usize),
}

/// Arity of the `erlang:hibernate` call a hibernating process is parked in (read from the
/// suspended target itself, as erl_debugger.c reads `p`).
fn hibernation_arity(target: &Process) -> Option<u8> {
    target
        .cold
        .as_ref()
        .and_then(|cold| cold.hibernate.as_ref())
        .map(|cont| if cont.resume_in_place { 0 } else { 3 })
}

// Port of erts/emulator/beam/erl_debugger.c:754-855 (erl_debugger_stack_frames_2), OTP-29.1.1.
fn inspect_frames(
    process: &Process,
    modules: &[std::sync::Arc<arinsal_loader::Module>],
    max_size: usize,
    hibernation: Option<u8>,
) -> Vec<O> {
    let mut frames = Vec::new();
    if let Some(arity) = hibernation {
        // erts: the process waits at beam_run_process, whose function is `rp->current`
        // (erlang:hibernate) and whose stack has been discarded.
        frames.push(O::Tuple(vec![
            O::Int(1),
            O::Map(vec![
                (
                    O::Atom("function".into()),
                    O::Tuple(vec![
                        O::Atom("erlang".into()),
                        O::Atom("hibernate".into()),
                        O::Int(i64::from(arity)),
                    ]),
                ),
                (O::Atom("line".into()), O::Atom("undefined".into())),
            ]),
            O::Map(vec![
                (O::Atom("code".into()), integer(1)),
                (
                    O::Atom("slots".into()),
                    O::List {
                        elems: Vec::new(),
                        tail: Box::new(O::Nil),
                    },
                ),
            ]),
        ]));
        frames.push(O::Tuple(vec![
            O::Int(0),
            O::Atom("<terminate process normally>".into()),
            O::Map(vec![
                (O::Atom("code".into()), integer(1)),
                (
                    O::Atom("slots".into()),
                    O::List {
                        elems: Vec::new(),
                        tail: Box::new(O::Nil),
                    },
                ),
            ]),
        ]));
        return frames;
    }
    let mut current = match process.native_pc {
        Some(address) => FramePc::Native(address),
        None => FramePc::Interpreted {
            module: process.module,
            ip: process.ip,
        },
    };
    // Only the top frame, the current pc, is not a return address.
    let mut current_is_return = false;
    let mut slots = Vec::new();
    let mut stack_index = 0;
    // The bottom frame's return address is the exit bridge (erts' `beam_normal_exit`) once the
    // process runs; a process that has not run yet has an empty stack.
    let mut reached_exit = false;
    while let Some(word) = process.heap.stack_get(stack_index) {
        stack_index += 1;
        let raw = word.tagged_word() as usize;
        let normal_exit = raw == crate::native_bridge::bridge_return_address();
        reached_exit |= normal_exit;
        let breakpoint_cleanup = crate::beamasm_integration::is_line_breakpoint_cleanup(raw);
        if normal_exit || breakpoint_cleanup || crate::native_bridge::is_native_function_at(raw) {
            push_frame(&mut frames, modules, current, &slots, current_is_return);
            slots.clear();
            current = FramePc::Native(raw);
            current_is_return = true;
            continue;
        }
        if let Some(handler) = crate::stacktrace::native_catch_address(word) {
            slots.push(O::Tuple(vec![
                O::Atom("catch".into()),
                function_info_native(handler, false),
            ]));
            continue;
        }
        if let Some((handler, next_module, next_ip)) = crate::stacktrace::decode_tag(word) {
            if handler {
                slots.push(O::Tuple(vec![
                    O::Atom("catch".into()),
                    function_info(modules, next_module, next_ip),
                ]));
            } else {
                push_frame(&mut frames, modules, current, &slots, current_is_return);
                slots.clear();
                current = FramePc::Interpreted {
                    module: next_module,
                    ip: next_ip,
                };
                current_is_return = true;
            }
        } else {
            slots.push(limit_term(word, max_size));
        }
    }
    push_frame(&mut frames, modules, current, &slots, current_is_return);
    if reached_exit {
        renumber_frames(&mut frames);
        return frames;
    }
    frames.push(O::Tuple(vec![
        O::Int(-1),
        O::Atom("<terminate process normally>".into()),
        O::Map(vec![
            (O::Atom("code".into()), integer(1)),
            (
                O::Atom("slots".into()),
                O::List {
                    elems: Vec::new(),
                    tail: Box::new(O::Nil),
                },
            ),
        ]),
    ]));
    renumber_frames(&mut frames);
    frames
}

/// erts numbers frames from the bottom of the stack.
fn renumber_frames(frames: &mut [O]) {
    let frame_count = frames.len();
    for (position, frame) in frames.iter_mut().enumerate() {
        if let O::Tuple(fields) = frame {
            fields[0] = O::Int((frame_count - position - 1) as i64);
        }
    }
}

/// Function info of a native pc; a return address is moved back into its call instruction.
// Port of erts/emulator/beam/erl_debugger.c:660-716 (stack_frame_fun_info), OTP-29.1.1.
fn function_info_native(address: usize, is_return_address: bool) -> O {
    if address == crate::native_bridge::bridge_return_address() {
        // Port of erts/emulator/beam/erl_process.c:14938-14953
        // (erts_internal_fun_description_from_pc), OTP-29.1.1.
        return O::Atom("<terminate process normally>".into());
    }
    if is_return_address && crate::beamasm_integration::is_line_breakpoint_cleanup(address) {
        // Port of erts/emulator/beam/erl_process.c:14945-14946, OTP-29.1.1.
        return O::Atom("<breakpoint>".into());
    }
    let lookup = if is_return_address {
        address.wrapping_sub(1)
    } else {
        address
    };
    let Some(frame) = crate::native_bridge::native_stack_frame_at(lookup) else {
        return O::Atom("unknown function".into());
    };
    let atoms = arinsal_term::global_atoms();
    let text = |atom| atoms.text(atom).unwrap_or("?").to_owned();
    let wrapper = text(frame.module_atom) == "erts_internal"
        && text(frame.function_atom) == "breakpoint"
        && frame.arity == 4;
    O::Map(vec![
        (
            O::Atom("function".into()),
            O::Tuple(vec![
                O::Atom(text(frame.module_atom)),
                O::Atom(text(frame.function_atom)),
                O::Int(i64::from(frame.arity)),
            ]),
        ),
        (
            O::Atom("line".into()),
            frame
                .line
                .filter(|_| !wrapper)
                .map_or(O::Atom("undefined".into()), |line| O::Int(i64::from(line))),
        ),
    ])
}

/// erts leaves the unwritten stack slots of `erts_internal:breakpoint/4` holding -1.
fn uninitialized_slots_as_erts(slots: &[O]) -> Vec<O> {
    slots
        .iter()
        .map(|slot| match slot {
            O::Tuple(fields)
                if fields.len() == 2
                    && fields[0] == O::Atom("value".into())
                    && fields[1] == O::Nil =>
            {
                O::Tuple(vec![O::Atom("value".into()), O::Int(-1)])
            }
            slot => slot.clone(),
        })
        .collect()
}

fn push_frame(
    frames: &mut Vec<O>,
    modules: &[std::sync::Arc<arinsal_loader::Module>],
    pc: FramePc,
    slots: &[O],
    return_address: bool,
) {
    let (module_index, ip) = match pc {
        FramePc::Native(address) => {
            let wrapper = crate::native_bridge::native_stack_frame_at(address).is_some_and(|f| {
                let atoms = arinsal_term::global_atoms();
                atoms.text(f.module_atom) == Some("erts_internal")
                    && atoms.text(f.function_atom) == Some("breakpoint")
                    && f.arity == 4
            });
            let slots = if wrapper {
                uninitialized_slots_as_erts(slots)
            } else {
                slots.to_vec()
            };
            frames.push(O::Tuple(vec![
                O::Int(-1),
                function_info_native(address, return_address),
                O::Map(vec![
                    (O::Atom("code".into()), integer(address)),
                    (
                        O::Atom("slots".into()),
                        O::List {
                            elems: slots,
                            tail: Box::new(O::Nil),
                        },
                    ),
                ]),
            ]));
            return;
        }
        FramePc::Interpreted { module, ip } => (module, ip),
    };
    let (function, code_ptr) = modules
        .get(module_index)
        .map(|module| {
            let function = if return_address
                && matches!(
                    module.code.get(ip),
                    Some(arinsal_loader::Instr::DebugLineCleanup { .. })
                ) {
                O::Atom("<breakpoint>".into())
            } else {
                // Port of erts/emulator/beam/erl_debugger.c:671-690 (stack_frame_fun_info),
                // OTP-29.1.1: a return address is looked up one word back, inside the
                // call, so that a debug line right after the call is not taken.
                function_info(
                    modules,
                    module_index,
                    if return_address {
                        ip.saturating_sub(1)
                    } else {
                        ip
                    },
                )
            };
            let code_ptr = module.code.as_ptr().wrapping_add(ip) as usize;
            (function, code_ptr)
        })
        .unwrap_or_else(|| (O::Atom("unknown function".into()), 0));
    let slots = if modules.get(module_index).is_some_and(|module| {
        module.name == "erts_internal"
            && module
                .function_at(ip)
                .is_some_and(|(name, arity)| name == "breakpoint" && arity == 4)
    }) {
        uninitialized_slots_as_erts(slots)
    } else {
        slots.to_vec()
    };
    frames.push(O::Tuple(vec![
        O::Int(-1),
        function,
        O::Map(vec![
            (O::Atom("code".into()), integer(code_ptr)),
            (
                O::Atom("slots".into()),
                O::List {
                    elems: slots,
                    tail: Box::new(O::Nil),
                },
            ),
        ]),
    ]));
}

fn function_info(
    modules: &[std::sync::Arc<arinsal_loader::Module>],
    module_index: usize,
    ip: usize,
) -> O {
    let Some(module) = modules.get(module_index) else {
        return O::Atom("unknown function".into());
    };
    module.function_at(ip).map_or_else(
        || O::Atom("unknown function".into()),
        |(name, arity)| {
            O::Map(vec![
                (
                    O::Atom("function".into()),
                    O::Tuple(vec![
                        O::Atom(module.name.clone()),
                        O::Atom(name.to_owned()),
                        O::Int(i64::from(arity)),
                    ]),
                ),
                (
                    O::Atom("line".into()),
                    debugger_frame_line(module, name, arity, ip),
                ),
            ])
        },
    )
}

fn debugger_frame_line(module: &arinsal_loader::Module, function: &str, arity: u8, ip: usize) -> O {
    if module.name == "erts_internal" && function == "breakpoint" && arity == 4 {
        return O::Atom("undefined".into());
    }
    let start = module
        .functions
        .iter()
        .find(|(_, name, candidate_arity)| name == function && *candidate_arity == arity)
        .map(|(start, _, _)| *start)
        .unwrap_or(0);
    let next_line = module
        .debug_line_points
        .iter()
        .filter(|(point, _, _)| *point >= start && *point <= ip)
        .max_by_key(|(point, _, _)| *point)
        .map(|(_, line, _)| *line);
    next_line.map_or_else(
        || {
            module
                .lines
                .get(ip)
                .and_then(Option::as_ref)
                .map_or(O::Atom("undefined".into()), |(_, line)| {
                    O::Int(*line as i64)
                })
        },
        |line| O::Int(i64::from(line)),
    )
}

fn frame_slots(frame: &O) -> Vec<O> {
    let O::Tuple(fields) = frame else {
        return Vec::new();
    };
    let Some(O::Map(fields)) = fields.get(2) else {
        return Vec::new();
    };
    let Some((_, O::List { elems, .. })) = fields
        .iter()
        .find(|(key, _)| *key == O::Atom("slots".into()))
    else {
        return Vec::new();
    };
    elems.clone()
}

fn frame_number(frame: &O) -> Option<usize> {
    let O::Tuple(fields) = frame else {
        return None;
    };
    match fields.first()? {
        O::Int(value) => usize::try_from(*value).ok(),
        _ => None,
    }
}

fn limit_term(term: Term, max_size: usize) -> O {
    let size = size_object(term);
    if size > max_size {
        O::Tuple(vec![O::Atom("too_large".into()), integer(size)])
    } else {
        O::Tuple(vec![
            O::Atom("value".into()),
            to_owned(term).unwrap_or(O::Atom("undefined".into())),
        ])
    }
}

// Port of erts/emulator/beam/erl_debugger.c:418-444, OTP-29.1.1.
fn notify_breakpoint_hit(
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    mfa: Term,
    line: Term,
    resume: Term,
) -> Result<Term, VmError> {
    if !crate::trace_bp::debugger_supported() {
        return Err(undef());
    }
    let owned_mfa = to_owned(mfa).map_err(|_| badarg())?;
    let O::Tuple(fields) = &owned_mfa else {
        return Err(badarg());
    };
    let [O::Atom(module), O::Atom(function), O::Int(arity)] = fields.as_slice() else {
        return Err(badarg());
    };
    if !matches!(resume.classify(), TermKind::Fun)
        || arinsal_beamasm::rt::fun_ref(resume).is_none_or(|view| match view {
            arinsal_term::FunRef::Local { entry, .. } => entry.arity != 0,
            arinsal_term::FunRef::Export { entry } => entry.arity != 0,
        })
        || line.as_small().is_none()
    {
        return Err(badarg());
    }
    let Some(registration) = crate::trace_bp::debugger_registration(process) else {
        return Ok(atom("noproc"));
    };
    if registration.pid == ctx.pid() {
        return Ok(atom("abort"));
    }
    let pid = ctx.pid().to_term().ok_or_else(badarg)?;
    let event = O::Tuple(vec![
        O::Atom("breakpoint".into()),
        to_owned(pid).map_err(|_| badarg())?,
        O::Tuple(vec![
            O::Atom(module.clone()),
            O::Atom(function.clone()),
            O::Int(*arity),
        ]),
        O::Int(line.as_small().unwrap()),
        to_owned(resume).map_err(|_| badarg())?,
    ]);
    let envelope = O::Tuple(vec![
        O::Atom("debugger_event".into()),
        O::Int(registration.session as i64),
        event,
    ]);
    let message = from_owned_term(process, &envelope)?;
    process.send_message(registration.pid.to_term().ok_or_else(badarg)?, message)?;
    Ok(atom("ok"))
}

// Port of erts/emulator/beam/beam_debug.c:269-335, OTP-29.1.1.
fn debug_breakpoint(
    vm: &mut Vm,
    process: &mut Process,
    pattern: Term,
    enable: Term,
) -> Result<Term, VmError> {
    if enable != atom("true") && enable != atom("false") {
        return Err(badarg());
    }
    let owned_pattern = to_owned(pattern).map_err(|_| badarg())?;
    let O::Tuple(fields) = &owned_pattern else {
        return Err(badarg());
    };
    if fields.len() != 3 {
        return Err(badarg());
    }
    let Some(O::Atom(module)) = fields.first() else {
        return Err(badarg());
    };
    let Some(O::Atom(function)) = fields.get(1) else {
        return Err(badarg());
    };
    let arity = match fields.get(2) {
        Some(O::Int(value)) => Some(*value),
        Some(O::Atom(value)) if value == "_" => None,
        _ => return Err(badarg()),
    };
    let mut wildcard_seen = false;
    for wildcard in [module == "_", function == "_", arity.is_none()] {
        if wildcard {
            wildcard_seen = true;
        } else if wildcard_seen {
            return Err(badarg());
        }
    }
    let matches = vm
        .code
        .loaded
        .values()
        .copied()
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .filter_map(|id| vm.code.modules.get(id))
        .flat_map(|code| {
            code.functions
                .iter()
                .filter_map(|(_, name, candidate_arity)| {
                    ((module == "_" || module == &code.name)
                        && (function == "_" || function == name)
                        && arity.is_none_or(|a| a == i64::from(*candidate_arity)))
                    .then_some(())
                })
        })
        .count();
    crate::trace_bp::set_debug_breakpoint(
        process,
        module.clone(),
        function.clone(),
        arity,
        enable == atom("true"),
    );
    vm.refresh_all_trace_breakpoints(process);
    Term::small(matches as i64).ok_or_else(badarg)
}

fn atom_text(term: Term) -> Option<String> {
    global_atoms()
        .text(term.as_atom()?)
        .map(|text| text.to_string())
}
