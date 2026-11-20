//! Process exception and map helpers called by generated BeamAsm code.
//!
//! Port of erts/emulator/beam/beam_common.c, OTP-29.1.1.

use crate::{ImportOutcome, Process, Vm, VmError};
use arinsal_beamasm::ProcessHeader;
use arinsal_bifs::BifError;
use arinsal_maps::MapError;
use arinsal_sched::RunCtx;
use arinsal_term::{FunRef, Term, TermBuilder, exc, global_atoms};

/// Load the `c_p->arity` saved argument registers into the scheduler's register array and make
/// it the process's X file for the slice.
// Port of erts/emulator/beam/beam_common.c:336 (copy_in_registers), OTP-29.1.1: `reg` is
// `esdp->registers`; the X file stays the array until copy_out_registers.
pub(crate) fn copy_in_registers(c_p: &mut Process, reg: &mut arinsal_beamasm::SchedulerRegisters) {
    crate::raw::beam_common_ffi::attach_process_registers(c_p, reg);
}

/// Save the `c_p->arity` live registers from `reg` (the scheduler's `x_reg_array`) into the
/// process (`arg_reg`, growing it past `def_arg_reg` when needed) and give the array back.
// Port of erts/emulator/beam/beam_common.c:306 (copy_out_registers), OTP-29.1.1.
pub(crate) fn copy_out_registers(c_p: &mut Process, reg: &[Term]) {
    let arity = usize::from(c_p.heap.abi.arity);
    c_p.x.copy_out(reg, arity);
}

/// Invoke a fun from the scheduler register array.
// Port of erts/emulator/beam/beam_common.c:1605 (`call_fun`), OTP-29.1.1.
pub(crate) fn call_fun(
    c_p: &mut Process,
    arity: usize,
    reg: &mut [Term],
    args: Term,
    vm: &mut Vm,
    ctx: Option<&mut RunCtx<'_, crate::Process>>,
) -> Result<ImportOutcome, VmError> {
    if arity >= crate::proc_create::ATTACHED_X_REGS {
        return Err(VmError::Unsupported("fun arity exceeds X registers".into()));
    }
    let fun = reg[arity];
    // SAFETY: `reg[arity]` roots the fun while dispatch metadata is inspected.
    let view = unsafe { fun.fun_ref() };
    let actual = match &view {
        Some(FunRef::Local { .. } | FunRef::Export { .. }) => fun.fun_arity().map(usize::from),
        None => None,
    };
    if actual != Some(arity) {
        let reason = crate::funs::call_error_reason(c_p, &mut reg[..arity + 1], fun, arity, args)?;
        return Err(VmError::Trap(crate::exceptions::Trap::error(reason)));
    }
    match view.unwrap() {
        FunRef::Local { entry, free_vars } => {
            let cached = entry.get_dispatch(0).and_then(|(id, target, generation)| {
                if generation == crate::load::code_generation() {
                    return Some((id, target));
                }
                (crate::code_ix::code_tables(crate::code_ix::erts_active_code_ix())
                    .module_live
                    .get(id)
                    == Some(&true))
                .then_some((id, target))
            });
            let resolved = match cached {
                Some(cached) if !crate::natives::code::erts_purge_state().pending(cached.0) => {
                    Some(cached)
                }
                _ => vm.resolve_local_fun(c_p, entry, arity)?,
            };
            let Some((module_id, target)) = resolved else {
                return vm.call_lambda_handler(c_p, entry.module, arity, false, ctx);
            };
            if crate::natives::code::erts_purge_state().pending(module_id) {
                return vm.call_lambda_handler(c_p, entry.module, arity, true, ctx);
            }
            let need = arity + free_vars.len();
            if need > crate::proc_create::ATTACHED_X_REGS {
                return Err(VmError::Unsupported(
                    "closure environment exceeds X registers".into(),
                ));
            }
            for (i, &word) in free_vars.iter().enumerate() {
                // SAFETY: The fun header bounds the environment and every word is a term.
                reg[arity + i] = unsafe { std::mem::transmute::<u64, Term>(word) };
            }
            c_p.gc_live = need;
            vm.set_position(c_p, module_id, target)?;
            Ok(ImportOutcome::Dispatch)
        }
        FunRef::Export { entry } => {
            let module = crate::funs::atom_name(Term::atom(entry.module()))
                .ok_or_else(|| VmError::Unsupported("export module atom".into()))?;
            let function = crate::funs::atom_name(Term::atom(entry.function()))
                .ok_or_else(|| VmError::Unsupported("export function atom".into()))?;
            if module == "erlang" && function == "apply" {
                return match arity {
                    2 => apply_fun(c_p, reg[0], reg[1], reg, vm, ctx),
                    3 => apply(c_p, reg, vm, ctx),
                    _ => unreachable!("erlang:apply export arity is 2 or 3"),
                };
            }
            let began = c_p.begin_tail_apply(crate::proc_create::TAIL_FUN_CALL);
            let result = vm.call_named_atoms(
                c_p,
                entry.module(),
                entry.function(),
                &module,
                &function,
                arity,
                ctx,
            );
            c_p.end_tail_apply(began, &result);
            result
        }
    }
}

/// Resolve an `apply_last` target from the module/function registers.
// Port of erts/emulator/beam/beam_common.c:1529 (`fixed_apply`), OTP-29.1.1.
pub(crate) fn fixed_apply(
    c_p: &mut Process,
    reg: &mut [Term],
    arity: usize,
    vm: &mut Vm,
    ctx: Option<&mut RunCtx<'_, crate::Process>>,
) -> Result<ImportOutcome, VmError> {
    if arity + 1 >= crate::proc_create::ATTACHED_X_REGS {
        return Err(vm.exception(c_p, "system_limit"));
    }
    if reg[arity].as_atom().is_none() || reg[arity + 1].as_atom().is_none() {
        let words = arity
            .checked_mul(2)
            .ok_or_else(|| vm.exception(c_p, "system_limit"))?;
        c_p.ensure_objv(words, &mut reg[..arity + 2])?;
        let module_term = reg[arity];
        let function_term = reg[arity + 1];
        let arguments = TermBuilder::new(&mut c_p.heap)
            .list_from_iter(reg[..arity].iter().copied())
            .map_err(|error| VmError::Unsupported(format!("apply args {error:?}")))?;
        return Err(crate::exceptions::bif_error(
            c_p,
            "erlang",
            "apply",
            &[module_term, function_term, arguments],
            BifError::BADARG,
        ));
    }
    let module_atom = reg[arity].as_atom().expect("checked apply module");
    let function_atom = reg[arity + 1].as_atom().expect("checked apply function");
    let module = crate::funs::atom_name(Term::atom(module_atom))
        .ok_or_else(|| vm.exception(c_p, "badarg"))?;
    let function = crate::funs::atom_name(Term::atom(function_atom))
        .ok_or_else(|| vm.exception(c_p, "badarg"))?;
    if crate::trace::saves_calls(c_p) {
        crate::trace::save_call(
            c_p,
            crate::trace::SavedCall::Mfa(module_atom, function_atom, arity as u32),
        );
    }
    if module == "erlang" && function == "apply" && arity == 3 {
        return apply(c_p, reg, vm, ctx);
    }
    let began = c_p.begin_tail_apply(crate::proc_create::TAIL_APPLY);
    let result = vm.call_named_atoms(
        c_p,
        module_atom,
        function_atom,
        &module,
        &function,
        arity,
        ctx,
    );
    c_p.end_tail_apply(began, &result);
    result
}

/// Apply an MFA to the terms in the argument list.
// Port of erts/emulator/beam/beam_common.c:1434 (`apply`), OTP-29.1.1.
pub(crate) fn apply(
    c_p: &mut Process,
    reg: &mut [Term],
    vm: &mut Vm,
    ctx: Option<&mut RunCtx<'_, crate::Process>>,
) -> Result<ImportOutcome, VmError> {
    let original_position = c_p.position_marker();
    let original_gc_live = c_p.gc_live;
    let original_operands = [reg[0], reg[1], reg[2]];
    let (module_term, function_term, arguments_term) =
        crate::funs::unwrap_nested_apply(reg[0], reg[1], reg[2]);
    let named = match (module_term.as_atom(), function_term.as_atom()) {
        (Some(module), Some(function)) => Some((module, function)),
        _ => {
            return Err(crate::exceptions::bif_error(
                c_p,
                "erlang",
                "apply",
                &[module_term, function_term, arguments_term],
                BifError::BADARG,
            ));
        }
    };
    let bif_args = vec![module_term, function_term, arguments_term];
    let args = crate::funs::argument_list(arguments_term).map_err(|error| {
        crate::exceptions::bif_error(
            c_p,
            "erlang",
            "apply",
            &bif_args,
            match error {
                crate::funs::ArgumentError::Badarg => BifError::BADARG,
                crate::funs::ArgumentError::SystemLimit => BifError::SystemLimit,
            },
        )
    })?;
    if args.len() >= crate::proc_create::ATTACHED_X_REGS {
        return Err(crate::exceptions::bif_error(
            c_p,
            "erlang",
            "apply",
            &bif_args,
            BifError::SystemLimit,
        ));
    }
    reg[..args.len()].copy_from_slice(&args);
    if named.is_some_and(|(module, function)| {
        global_atoms().text(module) == Some("erlang")
            && global_atoms().text(function) == Some("apply")
    }) && args.len() == 2
    {
        return apply_fun(c_p, reg[0], reg[1], reg, vm, ctx);
    }
    let inline = c_p.apply_inline_len == 0
        && c_p
            .cold
            .as_ref()
            .is_none_or(|cold| cold.apply_roots.is_empty());
    let roots_base = if inline {
        c_p.apply_inline[..3].copy_from_slice(&original_operands);
        c_p.apply_inline_len = 3;
        0
    } else {
        let cold = c_p.cold_mut();
        let base = cold.apply_roots.len();
        cold.apply_roots.extend_from_slice(&original_operands);
        base
    };
    let began = c_p.begin_tail_apply(crate::proc_create::TAIL_APPLY);
    let (module_atom, function_atom) = named.unwrap();
    let module = global_atoms()
        .text(module_atom)
        .ok_or_else(|| vm.exception(c_p, "badarg"))?;
    let function = global_atoms()
        .text(function_atom)
        .ok_or_else(|| vm.exception(c_p, "badarg"))?;
    let result = vm.call_named_atoms(
        c_p,
        module_atom,
        function_atom,
        module,
        function,
        args.len(),
        ctx,
    );
    c_p.end_tail_apply(began, &result);
    let mut operand_buf = [Term::NIL; 3];
    let operand_len = if inline {
        operand_buf[..3].copy_from_slice(&c_p.apply_inline[..3]);
        c_p.apply_inline_len = 0;
        3
    } else {
        let cold = c_p.cold_mut();
        let len = cold.apply_roots.len() - roots_base;
        operand_buf[..len].copy_from_slice(&cold.apply_roots[roots_base..]);
        cold.apply_roots.truncate(roots_base);
        len
    };
    let reexec_apply =
        matches!(&result, Ok(ImportOutcome::Yield)) && c_p.position_marker() == original_position;
    if matches!(&result, Err(VmError::Dirty(_))) || reexec_apply {
        reg[..operand_len].copy_from_slice(&operand_buf[..operand_len]);
        c_p.gc_live = original_gc_live;
    } else if result.is_ok() {
        c_p.gc_live = original_gc_live;
    }
    result
}

/// Apply a fun to the terms in its argument list.
// Port of erts/emulator/beam/beam_common.c:1734 (`apply_fun`), OTP-29.1.1.
pub(crate) fn apply_fun(
    c_p: &mut Process,
    fun: Term,
    arguments_term: Term,
    reg: &mut [Term],
    vm: &mut Vm,
    ctx: Option<&mut RunCtx<'_, crate::Process>>,
) -> Result<ImportOutcome, VmError> {
    let original_position = c_p.position_marker();
    let original_gc_live = c_p.gc_live;
    let original_operands = [fun, arguments_term];
    let args = crate::funs::argument_list(arguments_term).map_err(|error| {
        crate::exceptions::bif_error(
            c_p,
            "erlang",
            "apply",
            &original_operands,
            match error {
                crate::funs::ArgumentError::Badarg => BifError::BADARG,
                crate::funs::ArgumentError::SystemLimit => BifError::SystemLimit,
            },
        )
    })?;
    if args.len() >= crate::proc_create::ATTACHED_X_REGS {
        return Err(crate::exceptions::bif_error(
            c_p,
            "erlang",
            "apply",
            &original_operands,
            BifError::SystemLimit,
        ));
    }
    reg[..args.len()].copy_from_slice(&args);
    reg[args.len()] = fun;
    let inline = c_p.apply_inline_len == 0
        && c_p
            .cold
            .as_ref()
            .is_none_or(|cold| cold.apply_roots.is_empty());
    let roots_base = if inline {
        c_p.apply_inline[..2].copy_from_slice(&original_operands);
        c_p.apply_inline_len = 2;
        0
    } else {
        let cold = c_p.cold_mut();
        let base = cold.apply_roots.len();
        cold.apply_roots.extend_from_slice(&original_operands);
        base
    };
    let result = call_fun(c_p, args.len(), reg, arguments_term, vm, ctx);
    let mut operand_buf = [Term::NIL; 2];
    let operand_len = if inline {
        operand_buf.copy_from_slice(&c_p.apply_inline[..2]);
        c_p.apply_inline_len = 0;
        2
    } else {
        let cold = c_p.cold_mut();
        let len = cold.apply_roots.len() - roots_base;
        operand_buf[..len].copy_from_slice(&cold.apply_roots[roots_base..]);
        cold.apply_roots.truncate(roots_base);
        len
    };
    let reexec_apply =
        matches!(&result, Ok(ImportOutcome::Yield)) && c_p.position_marker() == original_position;
    if matches!(&result, Err(VmError::Dirty(_))) || reexec_apply {
        reg[..operand_len].copy_from_slice(&operand_buf[..operand_len]);
        c_p.gc_live = original_gc_live;
    } else if result.is_ok() {
        c_p.gc_live = original_gc_live;
    }
    result
}

/// Dispatch an undefined or breakpoint call through the process error handler.
// Port of erts/emulator/beam/beam_common.c:1294 (`call_error_handler`), OTP-29.1.1.
pub(crate) fn call_error_handler(
    c_p: &mut Process,
    mfa: (&str, &str, usize),
    reg: &mut [Term],
    func: &str,
    vm: &mut Vm,
    ctx: Option<&mut RunCtx<'_, crate::Process>>,
) -> Result<ImportOutcome, VmError> {
    let (module, function, arity) = mfa;
    let handler = crate::funs::error_handler_module(c_p);
    let ready = crate::code_ix::code_tables(crate::code_ix::erts_active_code_ix())
        .loaded
        .get(&handler)
        .is_some_and(|id| {
            crate::code_ix::code_tables(crate::code_ix::erts_active_code_ix()).modules[*id]
                .export(func, 3)
                .is_some()
        });
    if !ready {
        return Err(VmError::Exception {
            reason: "undef".into(),
            frame: format!("{module}:{function}/{arity}"),
        });
    }
    c_p.ensure_objv(arity.saturating_mul(2).saturating_add(8), &mut reg[..arity])?;
    let args = reg[..arity].to_vec();
    let list = TermBuilder::new(&mut c_p.heap)
        .list_from_iter(args)
        .map_err(|error| VmError::Unsupported(format!("undef arg list: {error:?}")))?;
    let module_atom = global_atoms()
        .intern(module)
        .map_err(|_| VmError::Unsupported("undef module atom".into()))?;
    let function_atom = global_atoms()
        .intern(function)
        .map_err(|_| VmError::Unsupported("undef function atom".into()))?;
    reg[0] = Term::atom(module_atom);
    reg[1] = Term::atom(function_atom);
    reg[2] = list;
    vm.call_named(c_p, &handler, func, 3, ctx)
}

fn term(raw: u64) -> Term {
    crate::native_hooks::from_raw(raw)
}

fn raw(value: Term) -> u64 {
    crate::native_hooks::raw(value)
}

pub(crate) fn set_map_error(process: &mut Process, error: MapError) -> u64 {
    match error {
        MapError::Badmap(map) => {
            process.heap.abi.exc.freason = exc::EXC_BADMAP;
            process.heap.abi.exc.fvalue = raw(map);
        }
        MapError::Badkey(key) => {
            process.heap.abi.exc.freason = exc::EXC_BADKEY;
            process.heap.abi.exc.fvalue = raw(key);
        }
        MapError::Badarg(value) => {
            process.heap.abi.exc.freason = exc::EXC_BADARG;
            process.heap.abi.exc.fvalue = raw(value);
        }
        MapError::Allocation => {
            process.heap.abi.exc.freason = exc::EXC_SYSTEM_LIMIT;
            process.heap.abi.exc.fvalue = raw(Term::atom(arinsal_term::atoms::SYSTEM_LIMIT));
        }
    }
    Term::NON_VALUE.tagged_word()
}

fn set_system_limit(process: &mut Process) -> u64 {
    process.heap.abi.exc.freason = exc::EXC_SYSTEM_LIMIT;
    process.heap.abi.exc.fvalue = raw(Term::atom(arinsal_term::atoms::SYSTEM_LIMIT));
    Term::NON_VALUE.tagged_word()
}

fn ensure_x_roots(
    process: &mut Process,
    registers: &mut arinsal_beamasm::SchedulerRegisters,
    need: usize,
    live: usize,
) -> bool {
    if process.heap.words_left() >= need {
        return true;
    }
    let Some(roots) = registers.x_reg_array.get_mut(..live) else {
        return false;
    };
    process.ensure_objv(need, roots).is_ok()
}

/// Resolves the exception of `c_p` to its catch handler, or returns zero when the scheduler
/// must exit it. The one entry of generated code on both targets (x86 `raise_exception_shared`
/// / `process_exit`, the arm raise fragments).
// Port of erts/emulator/beam/beam_common.c:449-570 (handle_error), OTP-29.1.1.
#[unsafe(no_mangle)]
pub extern "C" fn handle_error(
    c_p: *mut ProcessHeader,
    pc: usize,
    reg: *mut u64,
    bif_mfa: *const arinsal_term::ErtsCodeMfa,
) -> usize {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    let Some((process, registers)) = crate::native_hooks::scheduler_registers_at(
        process,
        arinsal_beamasm::SchedulerRegisters::from_reg(reg),
    ) else {
        return 0;
    };
    let registers = &mut registers.x_reg_array[..];
    let (mut pc, mut bif_info) = (pc, bif_mfa as usize as u64);
    // Port of erts/emulator/beam/beam_common.c:458-459 (handle_error), OTP-29.1.1.
    if process.heap.abi.exc.freason & arinsal_term::exc::EXF_RESTORE_NFUNC != 0 {
        crate::erl_nfunc_sched::erts_nfunc_restore_error(
            process,
            &mut pc,
            registers,
            &mut bif_info,
        );
    }
    process.heap.abi.i = pc as *const core::ffi::c_void;
    let freason = process.heap.abi.exc.freason;
    let error_arglist = crate::native_helpers::is_error_arglist(process, bif_info, freason);
    let Some(class) = crate::native_helpers::native_exception_class(freason, error_arglist) else {
        return 0;
    };
    let arglist = if error_arglist {
        let Some(arglist) = crate::native_helpers::unpack_error_arglist(process, freason) else {
            return 0;
        };
        Some(arglist)
    } else {
        None
    };
    let trace = if freason & arinsal_beamasm::exc::EXF_SAVETRACE == 0 {
        crate::native_hooks::from_raw(process.heap.abi.exc.ftrace)
    } else {
        let top = crate::native_helpers::native_bif_top(process, bif_info, registers);
        let input = crate::stacktrace::StackTraceSave {
            class,
            depth: crate::erl_init::erts_backtrace_depth(),
            freason,
            native_pc: (pc != 0).then_some(pc),
            top: top.as_ref().map(crate::stacktrace::SaveTop::Live),
        };
        let Ok(trace) = crate::stacktrace::save_stacktrace(process, input, registers) else {
            return 0;
        };
        trace
    };
    process.heap.abi.exc.ftrace = crate::native_hooks::raw(trace);
    let reason = if let Some((reason, _args)) = arglist {
        reason
    } else if freason
        & (arinsal_beamasm::exc::EXC_INDEXBITS | arinsal_beamasm::exc::EXF_HAS_EXT_INFO)
        == 0
    {
        crate::native_hooks::from_raw(process.heap.abi.exc.fvalue)
    } else {
        let Some(reason) = crate::native_helpers::expand_error_value(process) else {
            return 0;
        };
        reason
    };
    let trace = crate::native_hooks::from_raw(process.heap.abi.exc.ftrace);
    crate::native_bridge::native_found_catch(process, registers, class, reason, trace).unwrap_or(0)
}

/// Finds the error-handler export and builds its three arguments in the X registers.
// Port of erts/emulator/beam/beam_common.c:1294-1345 (call_error_handler), OTP-29.1.1.
#[unsafe(export_name = "call_error_handler")]
pub extern "C" fn call_error_handler_abi(
    c_p: *mut ProcessHeader,
    mfa: *const arinsal_term::ErtsCodeMfa,
    reg: *mut u64,
    func: u64,
) -> usize {
    let mfa_pointer = mfa;
    let Some(mfa) = crate::raw::beam_common_ffi::code_mfa(mfa_pointer as usize as u64) else {
        return 0;
    };
    let Some((process, registers)) = crate::native_hooks::enter_runtime_reg(c_p, reg) else {
        return 0;
    };
    let Some(function) = term(func).as_atom() else {
        return 0;
    };
    call_error_handler_core(process, registers, mfa, mfa_pointer, function)
}

/// Implements the lookup and argument setup shared with the current ARM trampoline ABI.
// Port of erts/emulator/beam/beam_common.c:1308-1345 (call_error_handler), OTP-29.1.1.
pub(crate) fn call_error_handler_core(
    process: &mut Process,
    registers: &mut arinsal_beamasm::SchedulerRegisters,
    mfa: (arinsal_term::Atom, arinsal_term::Atom, u32),
    mfa_pointer: *const arinsal_term::ErtsCodeMfa,
    function: arinsal_term::Atom,
) -> usize {
    let Some(runtime) = process.runtime.as_ref() else {
        return 0;
    };
    let handler = crate::proc_create::raw::erts_psd_get_term(
        &process.psd,
        crate::proc_create::raw::ERTS_PSD_ERROR_HANDLER,
    )
    .and_then(Term::as_atom)
    .unwrap_or(arinsal_term::atoms::ERROR_HANDLER);
    let code_ix = registers.active_code_ix as usize;
    let Some(handler_export) = runtime
        .export_entry((handler, function, 3), code_ix)
        .filter(|ep| {
            !crate::export::is_export_trampoline_active(ep, code_ix)
                || crate::export::has_export_breakpoint(ep)
        })
    else {
        if !mfa_pointer.is_null() {
            process.heap.abi.current = mfa_pointer.cast();
        }
        process.heap.abi.exc.freason = exc::EXC_UNDEF;
        return 0;
    };
    let arity = mfa.2 as usize;
    if registers.x_reg_array.len() < arity
        || process
            .ensure_objv(arity.saturating_mul(2), &mut registers.x_reg_array[..arity])
            .is_err()
    {
        set_system_limit(process);
        return 0;
    }
    let args: smallvec::SmallVec<[Term; 8]> =
        smallvec::SmallVec::from_slice(&registers.x_reg_array[..arity]);
    let Ok(args) =
        TermBuilder::new(&mut crate::ProcessHeapHandle(&mut process.heap)).list_from_iter(args)
    else {
        set_system_limit(process);
        return 0;
    };
    registers.x_reg_array[0] = Term::atom(mfa.0);
    registers.x_reg_array[1] = Term::atom(mfa.1);
    registers.x_reg_array[2] = args;
    std::ptr::from_ref(handler_export) as usize
}

/// Adds the symbolic stacktrace to an error value.
// Port of erts/emulator/beam/beam_common.c:731-735 (add_stacktrace), OTP-29.1.1.
#[unsafe(no_mangle)]
pub extern "C" fn add_stacktrace(c_p: *mut ProcessHeader, value: u64, exception: u64) -> u64 {
    let Some(process) = crate::native_hooks::enter_runtime(c_p) else {
        return Term::NON_VALUE.tagged_word();
    };
    let value = term(value);
    let exception = term(exception);
    let result = crate::exceptions::materialize(process, exception).and_then(|trace| {
        TermBuilder::new(&mut crate::ProcessHeapHandle(&mut process.heap))
            .tuple(&[value, trace])
            .map_err(|error| crate::VmError::Unsupported(format!("add_stacktrace {error:?}")))
    });
    match result {
        Ok(result) => raw(result),
        Err(_) => set_system_limit(process),
    }
}

/// Restores the primary exception bits from a saved stacktrace.
// Port of erts/emulator/beam/beam_common.c:1089-1097 (erts_sanitize_freason), OTP-29.1.1.
#[unsafe(no_mangle)]
pub extern "C" fn erts_sanitize_freason(c_p: *mut ProcessHeader, exception: u64) {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return;
    };
    process.heap.abi.exc.freason = crate::stacktrace::raw_freason(term(exception))
        .map(arinsal_term::exc::primary_exception)
        .unwrap_or(arinsal_beamasm::exc::EXC_ERROR);
}

/// Generic fallback lookup for non-immediate keys.
// Port of erts/emulator/beam/beam_common.c:1775-1808 (get_map_element), OTP-29.1.1.
#[unsafe(no_mangle)]
pub extern "C" fn get_map_element(map: u64, key: u64) -> u64 {
    match arinsal_maps::get(term(map), term(key)) {
        Ok(Some(value)) => raw(value),
        Ok(None) | Err(MapError::Badmap(_)) => Term::NON_VALUE.tagged_word(),
        Err(_) => Term::NON_VALUE.tagged_word(),
    }
}

/// Generic fallback lookup using a compiler supplied internal key hash.
// Port of erts/emulator/beam/beam_common.c:1810-1861 (get_map_element_hash), OTP-29.1.1.
#[unsafe(no_mangle)]
pub extern "C" fn get_map_element_hash(map: u64, key: u64, hash: u64) -> u64 {
    match arinsal_maps::get_with_hash(term(map), term(key), hash) {
        Ok(Some(value)) => raw(value),
        Ok(None) | Err(MapError::Badmap(_)) => Term::NON_VALUE.tagged_word(),
        Err(_) => Term::NON_VALUE.tagged_word(),
    }
}

/// Builds a map from the key/value operands embedded by the loader.
// Port of erts/emulator/beam/beam_common.c:1864-1923 (erts_gc_new_map), OTP-29.1.1.
#[unsafe(no_mangle)]
pub extern "C" fn erts_gc_new_map(
    c_p: *mut ProcessHeader,
    reg: *mut u64,
    live: u64,
    n: u64,
    data: *const u64,
) -> u64 {
    let Some((process, registers)) = crate::native_hooks::enter_runtime_reg(c_p, reg) else {
        return Term::NON_VALUE.tagged_word();
    };
    let (Ok(live), Ok(n)) = (usize::try_from(live), usize::try_from(n)) else {
        return set_system_limit(process);
    };
    if n % 2 != 0 {
        return set_system_limit(process);
    }
    let need = arinsal_maps::new_map_need(n);
    if !ensure_x_roots(process, registers, need, live) {
        return set_system_limit(process);
    }
    let stack = process.heap.abi.stop.cast_const();
    match arinsal_maps::gc_new_map(
        n,
        |index| {
            term(
                raw::read_operand(data, index, reg, stack).unwrap_or(Term::NON_VALUE.tagged_word()),
            )
        },
        &mut process.heap,
    ) {
        Ok(map) => raw(map),
        Err(error) => set_map_error(process, error),
    }
}

/// Builds a compiler-literal-key flatmap from embedded values.
// Port of erts/emulator/beam/beam_common.c:1925-1957 (erts_gc_new_small_map_lit), OTP-29.1.1.
#[unsafe(no_mangle)]
pub extern "C" fn erts_gc_new_small_map_lit(
    c_p: *mut ProcessHeader,
    reg: *mut u64,
    keys_literal: u64,
    live: u64,
    data: *const u64,
) -> u64 {
    let Some((process, registers)) = crate::native_hooks::enter_runtime_reg(c_p, reg) else {
        return Term::NON_VALUE.tagged_word();
    };
    let Ok(live) = usize::try_from(live) else {
        return set_system_limit(process);
    };
    let keys_literal = term(keys_literal);
    let Some(tuple) = arinsal_term::raw::Tuple::try_from(keys_literal).ok() else {
        return set_system_limit(process);
    };
    let n = tuple.arity();
    let need = n.saturating_add(4);
    if !ensure_x_roots(process, registers, need, live) {
        return set_system_limit(process);
    }
    let stack = process.heap.abi.stop.cast_const();
    let mut values = [Term::NIL; 32];
    if n > values.len() {
        return set_system_limit(process);
    }
    for (index, value) in values[..n].iter_mut().enumerate() {
        let Some(bits) = raw::read_operand(data, index, reg, stack) else {
            return set_system_limit(process);
        };
        *value = term(bits);
    }
    let result = TermBuilder::new(&mut crate::ProcessHeapHandle(&mut process.heap))
        .flatmap_with_key_tuple(keys_literal, &values[..n]);
    match result {
        Ok(map) => raw(map),
        Err(_) => set_system_limit(process),
    }
}

/// Applies an associative map update from an embedded key/value vector.
// Port of erts/emulator/beam/beam_common.c:1960-2192 (erts_gc_update_map_assoc), OTP-29.1.1.
#[unsafe(no_mangle)]
pub extern "C" fn erts_gc_update_map_assoc(
    c_p: *mut ProcessHeader,
    reg: *mut u64,
    live: u64,
    n: u64,
    data: *const u64,
) -> u64 {
    let Some((process, registers)) = crate::native_hooks::enter_runtime_reg(c_p, reg) else {
        return Term::NON_VALUE.tagged_word();
    };
    let (Ok(live), Ok(n)) = (usize::try_from(live), usize::try_from(n)) else {
        return set_system_limit(process);
    };
    if n % 2 != 0 || live >= registers.x_reg_array.len() {
        return set_system_limit(process);
    }
    let source = registers.x_reg_array[live];
    let need = arinsal_maps::update_map_assoc_need(source, n);
    if !ensure_x_roots(process, registers, need, live.saturating_add(1)) {
        return set_system_limit(process);
    }
    let source = registers.x_reg_array[live];
    let stack = process.heap.abi.stop.cast_const();
    match arinsal_maps::gc_update_map_assoc(
        source,
        n,
        |index| {
            term(
                raw::read_operand(data, index, reg, stack).unwrap_or(Term::NON_VALUE.tagged_word()),
            )
        },
        &mut process.heap,
    ) {
        Ok(map) => raw(map),
        Err(error) => set_map_error(process, error),
    }
}

/// Applies an exact map update from an embedded key/value vector.
// Port of erts/emulator/beam/beam_common.c:2203-2344 (erts_gc_update_map_exact), OTP-29.1.1.
#[unsafe(no_mangle)]
pub extern "C" fn erts_gc_update_map_exact(
    c_p: *mut ProcessHeader,
    reg: *mut u64,
    live: u64,
    n: u64,
    data: *const u64,
) -> u64 {
    let Some((process, registers)) = crate::native_hooks::enter_runtime_reg(c_p, reg) else {
        return Term::NON_VALUE.tagged_word();
    };
    let (Ok(live), Ok(n)) = (usize::try_from(live), usize::try_from(n)) else {
        return set_system_limit(process);
    };
    if n % 2 != 0 || live >= registers.x_reg_array.len() {
        return set_system_limit(process);
    }
    let source = registers.x_reg_array[live];
    let need = arinsal_maps::update_map_exact_need(source);
    if !ensure_x_roots(process, registers, need, live.saturating_add(1)) {
        return set_system_limit(process);
    }
    let source = registers.x_reg_array[live];
    let stack = process.heap.abi.stop.cast_const();
    match arinsal_maps::gc_update_map_exact(
        source,
        n,
        |index| {
            term(
                raw::read_operand(data, index, reg, stack).unwrap_or(Term::NON_VALUE.tagged_word()),
            )
        },
        &mut process.heap,
    ) {
        Ok(map) => raw(map),
        Err(error) => set_map_error(process, error),
    }
}

mod raw {
    //! Loader-table reads and `Eterm *` result stores for `beam_common.c`.
    // Port of erts/emulator/beam/beam_common.c (GET_TERM/PUT_TERM_REG), OTP-29.1.1.

    const LOADER_TAG_MASK: u64 = 0x0f;
    const LOADER_TAG_SIZE: u32 = 4;
    const LOADER_X_REG: u64 = 0x3;
    const LOADER_Y_REG: u64 = 0x7;

    /// Reads one operand from the immutable vararg table, resolving loader-tagged registers.
    pub(super) fn read_operand(
        data: *const u64,
        index: usize,
        reg: *mut u64,
        stack: *const u64,
    ) -> Option<u64> {
        let descriptor = crate::raw::beam_common_ffi::read_optional_word(data, index)?;
        match descriptor & LOADER_TAG_MASK {
            LOADER_X_REG => crate::raw::beam_common_ffi::read_optional_word(
                reg.cast_const(),
                (descriptor >> LOADER_TAG_SIZE) as usize,
            ),
            LOADER_Y_REG => crate::raw::beam_common_ffi::read_optional_word(
                stack,
                (descriptor >> LOADER_TAG_SIZE) as usize,
            ),
            _ => Some(descriptor),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::erl_map::{erts_maps_get, erts_maps_put, erts_maps_update};

    #[test]
    fn map_runtime_symbol_signatures_match_otp() {
        let _: extern "C" fn(*mut ProcessHeader, *mut u64, u64, u64, *const u64) -> u64 =
            erts_gc_new_map;
        let _: extern "C" fn(*mut ProcessHeader, *mut u64, u64, u64, *const u64) -> u64 =
            erts_gc_new_small_map_lit;
        let _: extern "C" fn(*mut ProcessHeader, *mut u64, u64, u64, *const u64) -> u64 =
            erts_gc_update_map_assoc;
        let _: extern "C" fn(*mut ProcessHeader, *mut u64, u64, u64, *const u64) -> u64 =
            erts_gc_update_map_exact;
        let _: extern "C" fn(u64, u64) -> u64 = get_map_element;
        let _: extern "C" fn(u64, u64, u64) -> u64 = get_map_element_hash;
        let _: extern "C" fn(u64, u64) -> *const u64 = erts_maps_get;
        let _: extern "C" fn(*mut ProcessHeader, u64, u64, u64) -> u64 = erts_maps_put;
        let _: extern "C" fn(*mut ProcessHeader, u64, u64, u64, *mut u64) -> i32 = erts_maps_update;
        let _: extern "C" fn(
            *mut ProcessHeader,
            usize,
            *mut u64,
            *const arinsal_term::ErtsCodeMfa,
        ) -> usize = handle_error;
        let _: extern "C" fn(
            *mut ProcessHeader,
            *const arinsal_term::ErtsCodeMfa,
            *mut u64,
            u64,
        ) -> usize = call_error_handler_abi;
        let _: extern "C" fn(*mut ProcessHeader, u64, u64) -> u64 = add_stacktrace;
        let _: extern "C" fn(*mut ProcessHeader, u64) = erts_sanitize_freason;
    }

    #[test]
    fn map_runtime_symbols_match_otp_values() {
        let reference = arinsal_difftest::RefErl::start().expect("OTP 29.1.1 is required");
        let expected = reference
            .eval("[maps:get(rt_b,#{rt_a=>1,rt_b=>2}),maps:get(rt_b,#{rt_a=>1,rt_b=>2}),maps:get(rt_b,#{rt_a=>1,rt_b=>2}),maps:get(rt_a,#{rt_a=>3,rt_b=>2}),maps:get(rt_b,#{rt_a=>3,rt_b=>4}),maps:get(rt_a,#{rt_a=>5,rt_b=>4}),maps:get(rt_b,#{rt_a=>5,rt_b=>6}),maps:get(rt_b,#{rt_a=>5,rt_b=>6}),maps:get(rt_a,#{rt_a=>5,rt_b=>6})]")
            .unwrap();
        let atoms = arinsal_term::global_atoms();
        let key_a = Term::atom(atoms.intern("rt_a").unwrap());
        let key_b = Term::atom(atoms.intern("rt_b").unwrap());
        let one = Term::small(1).unwrap();
        let two = Term::small(2).unwrap();
        let three = Term::small(3).unwrap();
        let four = Term::small(4).unwrap();
        let five = Term::small(5).unwrap();
        let six = Term::small(6).unwrap();
        let mut process = crate::Process::new();
        let mut registers = arinsal_beamasm::SchedulerRegisters::default();
        let base_map = arinsal_maps::from_pairs(
            &[(key_a, one), (key_b, two)],
            &mut crate::ProcessHeapHandle(&mut process.heap),
        )
        .unwrap();
        let data = [raw(key_a), raw(one), raw(key_b), raw(two)];
        let map = erts_gc_new_map(
            process.native_header(),
            registers.x_reg_array.as_mut_ptr().cast(),
            0,
            data.len() as u64,
            data.as_ptr(),
        );
        let mut actual = vec![own(get_map_element(map, raw(key_b)))];

        let keys = TermBuilder::new(&mut crate::ProcessHeapHandle(&mut process.heap))
            .tuple(&[key_a, key_b])
            .unwrap();
        let values = [raw(one), raw(two)];
        let small_map = erts_gc_new_small_map_lit(
            process.native_header(),
            registers.x_reg_array.as_mut_ptr().cast(),
            raw(keys),
            0,
            values.as_ptr(),
        );
        actual.push(own(get_map_element(small_map, raw(key_b))));
        actual.push(own(get_map_element_hash(
            raw(base_map),
            raw(key_b),
            arinsal_term::internal_hash(key_b),
        )));

        registers.x_reg_array[0] = crate::native_hooks::from_raw(map);
        let update_assoc = [raw(key_a), raw(three)];
        let map = erts_gc_update_map_assoc(
            process.native_header(),
            registers.x_reg_array.as_mut_ptr().cast(),
            0,
            update_assoc.len() as u64,
            update_assoc.as_ptr(),
        );
        actual.push(own(get_map_element(map, raw(key_a))));

        registers.x_reg_array[0] = crate::native_hooks::from_raw(map);
        let update_exact = [raw(key_b), raw(four)];
        let map = erts_gc_update_map_exact(
            process.native_header(),
            registers.x_reg_array.as_mut_ptr().cast(),
            0,
            update_exact.len() as u64,
            update_exact.as_ptr(),
        );
        actual.push(own(get_map_element(map, raw(key_b))));

        let map = erts_maps_put(process.native_header(), raw(key_a), raw(five), map);
        actual.push(own(get_map_element(map, raw(key_a))));
        let mut updated = 0;
        assert_eq!(
            erts_maps_update(
                process.native_header(),
                raw(key_b),
                raw(six),
                map,
                &mut updated,
            ),
            1
        );
        actual.push(own(get_map_element(
            crate::native_hooks::from_raw(updated).tagged_word(),
            raw(key_b),
        )));
        actual.push(own(get_map_element_hash(
            updated,
            raw(key_b),
            arinsal_term::internal_hash(key_b),
        )));
        let value_table = [raw(key_a), 3, arinsal_term::internal_hash(key_a)];
        let mut stack = [0_u64; 8];
        assert_eq!(
            crate::beam_jit_common::beam_jit_get_map_elements(
                updated,
                registers.x_reg_array.as_mut_ptr().cast(),
                stack.as_mut_ptr(),
                1,
                value_table.as_ptr().cast_mut(),
            ),
            1
        );
        actual.push(own(registers.x_reg_array[0].tagged_word()));
        assert_eq!(
            erts_maps_get(raw(key_b), updated),
            arinsal_maps::get_ptr(crate::native_hooks::from_raw(updated), key_b)
                .unwrap()
                .unwrap()
        );
        let actual = arinsal_etf::OwnedTerm::List {
            elems: actual,
            tail: Box::new(arinsal_etf::OwnedTerm::Nil),
        };
        similar_asserts::assert_eq!(actual, expected);
    }

    fn own(bits: u64) -> arinsal_etf::OwnedTerm {
        arinsal_term::to_owned(crate::native_hooks::from_raw(bits)).unwrap()
    }
}
