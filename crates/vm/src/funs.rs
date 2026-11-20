//! Local closures, export funs, and dynamic calls.

use crate::code_ix::{code_tables, erts_active_code_ix};
use crate::{EvalResult, ImportOutcome, Process, Vm, VmError, exceptions};
use arinsal_bifs::{BifError, Ctx, ProcessHeapHandle};
use arinsal_loader::Module;
use arinsal_sched::RunCtx;
use arinsal_term::{FunRef, Term, TermBuilder, TermKind, global_atoms};
use std::sync::Arc;

pub(super) fn set_module_uniq(module: &mut Module, uniq: [u8; 16]) {
    for slot in &mut module.funs {
        if let Some(entry) = Arc::get_mut(&mut slot.entry) {
            entry.uniq = uniq;
        }
    }
}

/// Build the Erlang exception reason before the exception handler formats it.
pub(super) fn call_error_reason(
    p: &mut Process,
    reg: &mut [Term],
    fun: Term,
    arity: usize,
    args: Term,
) -> Result<Term, VmError> {
    let is_fun = fun.classify() == TermKind::Fun;
    p.ensure_objv(6 + arity * 2, &mut reg[..arity + 1])?;
    let fun = reg[arity];
    let mut builder = TermBuilder::new(&mut p.heap);
    let kind = global_atoms()
        .intern(if is_fun { "badarity" } else { "badfun" })
        .map_err(|_| VmError::Unsupported("exception atom".into()))?;
    if !is_fun {
        return builder
            .tuple(&[Term::atom(kind), fun])
            .map_err(|e| VmError::Unsupported(format!("exception allocation {e:?}")));
    }
    let args = if args == Term::NON_VALUE {
        let mut list = Term::NIL;
        for value in reg[..arity].iter().rev().copied() {
            list = builder
                .cons(value, list)
                .map_err(|e| VmError::Unsupported(format!("exception allocation {e:?}")))?;
        }
        list
    } else {
        args
    };
    let detail = builder
        .tuple(&[fun, args])
        .map_err(|e| VmError::Unsupported(format!("exception allocation {e:?}")))?;
    builder
        .tuple(&[Term::atom(kind), detail])
        .map_err(|e| VmError::Unsupported(format!("exception allocation {e:?}")))
}

pub(super) fn error_handler_module(process: &Process) -> String {
    crate::proc_create::raw::erts_psd_get_term(
        &process.psd,
        crate::proc_create::raw::ERTS_PSD_ERROR_HANDLER,
    )
    .and_then(atom_name)
    .unwrap_or_else(|| "error_handler".to_owned())
}

pub(super) fn atom_name(term: Term) -> Option<String> {
    global_atoms()
        .text(term.as_atom()?)
        .map(|name| name.to_string())
}

pub(super) enum ArgumentError {
    Badarg,
    SystemLimit,
}

pub(super) fn argument_list(mut list: Term) -> Result<Vec<Term>, ArgumentError> {
    let mut args = Vec::new();
    while list.classify() == TermKind::List {
        if args.len() >= 1023 {
            return Err(ArgumentError::SystemLimit);
        }
        // SAFETY: The list is retained by an X register throughout traversal.
        let (head, tail) = unsafe { list.cons_ref() }.ok_or(ArgumentError::Badarg)?;
        args.push(head);
        list = tail;
    }
    (list == Term::NIL)
        .then_some(args)
        .ok_or(ArgumentError::Badarg)
}

// Port of erts/emulator/beam/beam_common.c:1462-1495 (nested apply loop), OTP-29.1.1.
pub(super) fn unwrap_nested_apply(
    mut module: Term,
    mut function: Term,
    mut arguments: Term,
) -> (Term, Term, Term) {
    while let Some(module_atom) = module.as_atom() {
        let Some(function_atom) = function.as_atom() else {
            break;
        };
        if global_atoms().text(module_atom) != Some("erlang")
            || global_atoms().text(function_atom) != Some("apply")
        {
            break;
        }
        let Ok(nested) = argument_list(arguments) else {
            break;
        };
        let [nested_module, nested_function, nested_arguments] = nested.as_slice() else {
            break;
        };
        module = *nested_module;
        function = *nested_function;
        arguments = *nested_arguments;
    }
    (module, function, arguments)
}

impl Vm {
    /// `reg[..live]` of `esdp->registers`, the roots of a collection the scheduler does for the
    /// running process.
    // Port of erts/emulator/beam/erl_process.h (erts_proc_sched_data(c_p)->registers),
    // OTP-29.1.1.
    pub(crate) fn reg_prefix<'a>(&self, live: usize) -> Result<&'a mut [Term], VmError> {
        let registers = arinsal_sched::erts_get_scheduler_data::<crate::Process, _>(|esdp| {
            arinsal_sched::erts_sched_registers(esdp)
                .registers_addr
                .get()
        })
        .unwrap_or(0);
        crate::native_hooks::registers_at(registers as *mut arinsal_beamasm::SchedulerRegisters)
            .and_then(|registers| registers.x_reg_array.get_mut(..live))
            .ok_or_else(|| VmError::Unsupported("no scheduler registers".into()))
    }

    /// `reg`, the whole register array of `esdp->registers`.
    pub(crate) fn x_regs<'a>(&self) -> Result<&'a mut [Term], VmError> {
        self.reg_prefix(crate::proc_create::ATTACHED_X_REGS)
    }

    pub(super) fn eval_erlang_fun_builtin(
        &mut self,
        function: &str,
        args: &[Term],
    ) -> Option<Result<EvalResult, VmError>> {
        let arity = args.len();
        let result = match (function, arity) {
            // erts runs every call in a process: these BIFs read and write the scheduler's
            // `reg`, which only a scheduled process has.
            ("apply", 2 | 3) | ("make_fun", 3) | ("fun_info", 1 | 2) | ("fun_info_mfa", 1) => {
                self.eval_in_scheduled_process("erlang", function, args)
            }
            _ => return None,
        };
        Some(result)
    }

    // Port of erts/emulator/beam/beam_common.c:1605 (call_fun), OTP-29.1.1.
    #[inline]
    /// Continue a local fun call whose code is not callable in
    /// `Handler(Module, Fun, Args)`. With `pending_purge` the code is being purged:
    /// the caller suspends in `erts_code_purger:pending_purge_lambda/3`, which retries
    /// once the purge completes or aborts. Otherwise no current code exists and
    /// `error_handler:undefined_lambda/3` tries to load it.
    /// Port of erts/emulator/beam/beam_common.c:1677-1727 (call_fun), OTP-29.1.1.
    #[cold]
    pub(super) fn call_lambda_handler(
        &mut self,
        p: &mut Process,
        module: arinsal_term::Atom,
        arity: usize,
        pending_purge: bool,
        ctx: Option<&mut RunCtx<'_, crate::Process>>,
    ) -> Result<ImportOutcome, VmError> {
        let (handler, function) = if pending_purge {
            let name = atom_name(Term::atom(module))
                .ok_or_else(|| VmError::Unsupported("lambda module atom".into()))?;
            // Port of erts/emulator/beam/beam_bif_load.c:1977
            // (erts_suspend_process_on_pending_purge_lambda), OTP-29.1.1.
            if let Some(pid) = p.self_pid
                && crate::natives::code::erts_purge_state().suspend_on_pending_lambda(&name, pid)
            {
                crate::suspend::suspend_self(p);
                // erts_suspend + ERTS_VBUMP_ALL_REDS (beam_bif_load.c:2003-2004).
                crate::bif_traps::vbump_all_reds(p);
            }
            ("erts_code_purger".to_owned(), "pending_purge_lambda")
        } else {
            let handler = error_handler_module(p);
            let ready = code_tables(erts_active_code_ix())
                .loaded
                .get(&handler)
                .is_some_and(|id| {
                    code_tables(erts_active_code_ix()).modules[*id]
                        .export("undefined_lambda", 3)
                        .is_some()
                });
            if !ready {
                return Err(VmError::Trap(exceptions::Trap::error(Term::atom(
                    global_atoms()
                        .intern("undef")
                        .map_err(|_| VmError::Unsupported("undef atom".into()))?,
                ))));
            }
            (handler, "undefined_lambda")
        };
        p.ensure_objv(
            arity.saturating_mul(2).saturating_add(4),
            self.reg_prefix(arity + 1)?,
        )?;
        let fun = self.x_regs()?[arity];
        let args: Vec<Term> = self.x_regs()?[..arity].to_vec();
        let list = TermBuilder::new(&mut p.heap)
            .list_from_iter(args)
            .map_err(|error| VmError::Unsupported(format!("lambda arg list: {error:?}")))?;
        self.x_regs()?[0] = Term::atom(module);
        self.x_regs()?[1] = fun;
        self.x_regs()?[2] = list;
        self.x_regs()?[3] = Term::NIL;
        self.call_named(p, &handler, function, 3, ctx)
    }

    #[cold]
    pub(super) fn resolve_local_fun(
        &mut self,
        p: &mut Process,
        entry: &arinsal_term::FunEntry,
        arity: usize,
    ) -> Result<Option<(usize, usize)>, VmError> {
        let name = atom_name(Term::atom(entry.module))
            .ok_or_else(|| VmError::Unsupported("lambda module atom".into()))?;
        let found = [
            code_tables(erts_active_code_ix()).loaded.get(&name),
            code_tables(erts_active_code_ix()).old.get(&name),
        ]
        .into_iter()
        .flatten()
        .find_map(|&id| {
            code_tables(erts_active_code_ix()).modules[id]
                .funs
                .iter()
                .find(|slot| {
                    slot.entry.index == entry.index
                        && slot.entry.uniq == entry.uniq
                        && slot.entry.arity == entry.arity
                })
                .map(|slot| (id, slot.target))
        });
        let Some((module_id, target)) = found else {
            // Port of erts/emulator/beam/beam_common.c:1702-1712 (call_fun), OTP-29.1.1:
            // current code without this fun is `badfun`; no current code goes to
            // `error_handler:undefined_lambda/3`.
            if code_tables(erts_active_code_ix())
                .loaded
                .contains_key(&name)
            {
                let reason = badfun_reason(p, self.reg_prefix(arity + 1)?, arity)?;
                return Err(VmError::Trap(exceptions::Trap::error(reason)));
            }
            return Ok(None);
        };
        entry.set_dispatch(0, module_id, target, crate::load::code_generation());
        Ok(Some((module_id, target)))
    }

    #[inline]
    pub(super) fn call_named(
        &mut self,
        p: &mut Process,
        module: &str,
        function: &str,
        arity: usize,
        ctx: Option<&mut RunCtx<'_, crate::Process>>,
    ) -> Result<ImportOutcome, VmError> {
        self.call_named_resolved(p, None, module, function, arity, ctx)
    }

    /// Make the call a BIF trapped to, on the schedule-in after the trap's context switch.
    /// erts leaves the trap arguments in X and `beam_bif_export_trap` dispatches the export as
    /// an ordinary call; this is its only caller, so a trap never runs its export in the slice
    /// that trapped.
    // Port of erts/emulator/beam/bif.h:316-326 (BIF_TRAP*) and
    // jit/arm/beam_asm_global.cpp:145-155 (emit_bif_export_trap), OTP-29.1.1.
    #[cfg(target_arch = "aarch64")]
    pub(crate) fn trap_to_export(
        &mut self,
        p: &mut Process,
        trap: crate::ExportTrap,
        ctx: Option<&mut RunCtx<'_, crate::Process>>,
    ) -> Result<ImportOutcome, VmError> {
        let target = trap.target;
        let (module, function, arity) = (target.module, target.function, target.arity);
        if arity != trap.args.len() {
            return Err(VmError::Unsupported(format!(
                "trap to {module}:{function}/{arity} with {} arguments",
                trap.args.len()
            )));
        }
        let module_atom = trap.entry.module();
        let function_atom = trap.entry.function();
        if !crate::trace_bp::any_pattern()
            && !crate::trace::saves_calls(p)
            && !code_tables(erts_active_code_ix())
                .pending_on_load
                .contains_key(module)
            && let Some(&module_id) = code_tables(erts_active_code_ix()).loaded.get(&module_atom)
            && let Some(target) = code_tables(erts_active_code_ix()).modules[module_id]
                .export_slot_atom(function_atom, arity as u32)
                .map(arinsal_loader::ExportSlot::target)
        {
            // Port of erts/emulator/beam/bif.h:316-326 (BIF_TRAP*: set `c_p->i`
            // to the already-resolved export and leave its arguments in X), OTP-29.1.1.
            // The trap itself costs nothing: a BIF export runs `call_bif_mfa`, which does not
            // touch FCALLS, and an Erlang export charges its call in its own `i_test_yield`
            // (jit/arm/ops.tab, int_func_start).
            p.gc_live = arity;
            self.x_regs()?[..arity].copy_from_slice(&trap.args);
            self.set_position(p, module_id, target)?;
            return Ok(ImportOutcome::Dispatch);
        }
        self.x_regs()?[..arity].copy_from_slice(&trap.args);
        // A BIF traps to its `bif_trap_export` entry (erl_bif_table.c, erts_init_trap_export),
        // which has no breakpoint: the continuation is not a traced call of its own.
        if u8::try_from(arity)
            .ok()
            .is_some_and(|arity| arinsal_spec::bif_lookup(module, function, arity).is_some())
        {
            let atoms = Some((module_atom, function_atom));
            return self.call_named_untraced(p, atoms, module, function, arity, ctx);
        }
        self.call_named_atoms(p, module_atom, function_atom, module, function, arity, ctx)
    }

    /// `BIF_TRAP*` of a BIF the executor called. Every trap leaves the process at
    /// `beam_bif_export_trap`, which context-switches and calls the export on schedule-in, as
    /// the native call path does, whether the export is a BIF or an Erlang function. The
    /// export is never called from here, so a BIF that traps again cannot chain slices
    /// without a context switch.
    // Port of erts/emulator/beam/bif.h:316-326 (ERTS_BIF_PREP_TRAP: `c_p->i` =
    // beam_bif_export_trap) and jit/arm/instr_bif.cpp:515-536 (call_bif_shared: every
    // TRAP branches to context_switch_simplified), OTP-29.1.1.
    fn bif_trap_from_executor(
        &mut self,
        p: &mut Process,
        trap: crate::ExportTrap,
    ) -> Result<ImportOutcome, VmError> {
        let target = trap.target;
        let trap_pc = crate::bif_traps::bif_export_trap_pc();
        crate::bif_traps::install_export_trap(
            p,
            trap_pc,
            (target.module_atom, target.function_atom),
            &trap,
            // The slice ends here: this yield is the trap's context switch.
            false,
        );
        crate::bif_traps::arm_export_trap(p);
        p.set_native_retry(Some(trap_pc));
        Ok(ImportOutcome::Yield)
    }

    #[allow(clippy::too_many_arguments)] // Preserve the call metadata without rebuilding an MFA tuple.
    pub(super) fn call_named_atoms(
        &mut self,
        p: &mut Process,
        module_atom: arinsal_term::Atom,
        function_atom: arinsal_term::Atom,
        module: &str,
        function: &str,
        arity: usize,
        ctx: Option<&mut RunCtx<'_, crate::Process>>,
    ) -> Result<ImportOutcome, VmError> {
        self.call_named_resolved(
            p,
            Some((module_atom, function_atom)),
            module,
            function,
            arity,
            ctx,
        )
    }

    #[allow(clippy::too_many_arguments)] // The optional atom identity accompanies the existing MFA fields.
    fn call_named_resolved(
        &mut self,
        p: &mut Process,
        atoms: Option<(arinsal_term::Atom, arinsal_term::Atom)>,
        module: &str,
        function: &str,
        arity: usize,
        mut ctx: Option<&mut RunCtx<'_, crate::Process>>,
    ) -> Result<ImportOutcome, VmError> {
        // A BIF reached through apply is traced like a direct call.
        // Port of erts/emulator/beam/beam_bp.c:321-330 (erts_export_is_bif_traced), OTP-29.1.1.
        let traced = match ctx.as_deref_mut() {
            Some(run)
                if arity <= usize::from(u8::MAX)
                    && crate::export::is_bif_traced(module, function, arity as u32) =>
            {
                // The apply's return address names its native call site.
                let site = (
                    usize::MAX,
                    p.heap
                        .stack_get(0)
                        .map_or(0, |cp| (cp.tagged_word() as usize).wrapping_sub(1)),
                );
                self.trace_native_call_named(
                    p,
                    run,
                    module,
                    function,
                    arity,
                    site,
                    crate::trace::StackScan::AfterFrame,
                )
            }
            _ => None,
        };
        let result =
            self.call_named_untraced(p, atoms, module, function, arity, ctx.as_deref_mut());
        let (Some((module, function, args)), Some(run)) = (traced, ctx) else {
            return result;
        };
        match result {
            Ok(outcome) => {
                let value = match &outcome {
                    ImportOutcome::Returned(value) => Some(*value),
                    _ => None,
                };
                if let Some(value) = value {
                    self.trace_native_return(p, run, &module, &function, &args, &Ok(value));
                }
                Ok(outcome)
            }
            Err(error) => {
                let failed: Result<Term, VmError> = Err(error);
                self.trace_native_return(p, run, &module, &function, &args, &failed);
                failed.map(ImportOutcome::Returned)
            }
        }
    }

    #[allow(clippy::too_many_arguments)] // Same signature as `call_named_resolved`, which it backs.
    fn call_named_untraced(
        &mut self,
        p: &mut Process,
        atoms: Option<(arinsal_term::Atom, arinsal_term::Atom)>,
        module: &str,
        function: &str,
        arity: usize,
        mut ctx: Option<&mut RunCtx<'_, crate::Process>>,
    ) -> Result<ImportOutcome, VmError> {
        p.gc_live = arity;
        let arity8 = u8::try_from(arity).ok();
        if module == "erts_internal" {
            match (function, arity) {
                ("dirty_bif_result", 1) => {
                    // Port of erts/emulator/beam/bif.c:5605-5610 (dirty_bif_result):
                    // restore the saved native call and return the dirty worker's value.
                    p.take_dirty_bif_original();
                    let x0 = self.x_regs()?[0];
                    let mut args = [x0];
                    let mut result = Ok(x0);
                    crate::calls::gc_after_bif(p, &mut args, &mut result)?;
                    let value = result.map_err(|error| {
                        exceptions::bif_error(p, module, function, &args, error)
                    })?;
                    self.x_regs()?[0] = value;
                    return Ok(Self::return_value(p, value));
                }
                ("dirty_bif_exception", 2) => {
                    // Port of erts/emulator/beam/bif.c:5630-5640 (dirty_bif_exception):
                    // restore the original call site and raise the dirty worker's failure.
                    let mut args = self.x_regs()?[..2].to_vec();
                    let Some(freason) = args[0].as_small() else {
                        return Err(exceptions::bif_error(
                            p,
                            module,
                            function,
                            &args,
                            BifError::BADARG,
                        ));
                    };
                    let class = match (freason as u64) & 3 {
                        2 => arinsal_bifs::Class::Exit,
                        3 => arinsal_bifs::Class::Throw,
                        _ => arinsal_bifs::Class::Error,
                    };
                    let mut result = Err(BifError::Raise {
                        class,
                        reason: args[1],
                        stacktrace: None,
                    });
                    crate::calls::gc_after_bif(p, &mut args, &mut result)?;
                    let Err(mut error) = result else {
                        unreachable!("dirty exception continuation must raise")
                    };
                    if let Some(stacktrace) = p.take_dirty_bif_exception_trace()
                        && let BifError::Raise {
                            stacktrace: saved, ..
                        } = &mut error
                    {
                        *saved = Some(stacktrace);
                    }
                    let call_pc = p.take_dirty_bif_call_pc();
                    if let Some(((original_module, original_function, _), original_args)) =
                        p.take_dirty_bif_original()
                    {
                        // Port of erts/emulator/beam/erl_nfunc_sched.h
                        // (erts_nfunc_restore_error): raise at the original native call site.
                        if let Some(call_pc) = call_pc {
                            p.native_error_pc = call_pc;
                        }
                        return Err(exceptions::dirty_bif_exception(
                            p,
                            original_module,
                            original_function,
                            &original_args,
                            error,
                        )?);
                    }
                    return Err(exceptions::bif_error(p, module, function, &args, error));
                }
                ("dirty_bif_trap", 1..=3) => {
                    // Port of erts/emulator/beam/bif.c:5612-5627 (dirty_bif_trap): restore the
                    // native-function continuation and its scheduled argument registers.
                    let Some(((target_module, target_function, target_arity), args)) =
                        p.take_dirty_bif_trap_target()
                    else {
                        return Err(VmError::Unsupported(
                            "dirty_bif_trap has no saved export continuation".into(),
                        ));
                    };
                    p.take_dirty_bif_original();
                    let target_arity = usize::from(target_arity);
                    self.x_regs()?[..target_arity].copy_from_slice(&args);
                    self.x_regs()?[target_arity] = Term::atom(
                        global_atoms()
                            .intern(target_module)
                            .map_err(|_| VmError::Unsupported("dirty trap module atom".into()))?,
                    );
                    self.x_regs()?[target_arity + 1] =
                        Term::atom(global_atoms().intern(target_function).map_err(|_| {
                            VmError::Unsupported("dirty trap function atom".into())
                        })?);
                    p.gc_live = target_arity;
                    return crate::beam_common::fixed_apply(
                        p,
                        self.x_regs()?,
                        target_arity,
                        self,
                        ctx,
                    );
                }
                _ => {}
            }
        }
        // Apply enters the active BIF export through its bif_table index, as a static call does.
        if let Some(arity8) = arity8
            && arinsal_spec::bif_lookup(module, function, arity8).is_some()
            && let Some(run) = ctx.as_deref_mut()
        {
            let native_function = if module == "erlang" && function == "!" && arity == 2 {
                "send"
            } else {
                function
            };
            if let Some(result) = self.dispatch_native(
                p,
                run,
                module,
                native_function,
                arity,
                crate::natives::native_entry(module, native_function, arity8),
            ) {
                return self.finish_apply_native_result(p, module, function, arity, atoms, result);
            }
        }
        // Apply carries atom identities, so resolve the same process-aware BIF
        // entry as a static import without re-matching its module or function.
        let mut resolved_entry = false;
        if let (Some((module_atom, function_atom)), Some(run), Some(arity8)) =
            (atoms, ctx.as_deref_mut(), arity8)
            && let Some(entry) = crate::signals::handler_atoms(module_atom, function_atom, arity8)
        {
            resolved_entry = true;
            if let Some(result) = self.dispatch_resolved_entry(
                p,
                run,
                crate::natives::NativeArgs::registers(self.x_regs()?, arity),
                entry,
            ) {
                let result = match result {
                    // Port of erts/emulator/beam/bif.h:316-326 (BIF_TRAP*), OTP-29.1.1: an
                    // applied BIF that traps (demonitor_2 to flush_monitor_messages/3)
                    // continues in the trap's export, as the same BIF called statically.
                    Err(VmError::TrapExport(trap)) => {
                        return self.bif_trap_from_executor(p, trap);
                    }
                    // Port of erts/emulator/beam/beam_common.c:880-930 (save_stacktrace),
                    // OTP-29.1.1: BIF_ERROR names the applied BIF as the top frame.
                    Err(VmError::Trap(mut trap))
                        if trap.class == arinsal_bifs::Class::Error
                            && trap.top.is_none()
                            && trap.trace.is_none() =>
                    {
                        trap.top = Some(crate::stacktrace::TopFrame::Bif {
                            module: module_atom,
                            function: function_atom,
                            args: crate::stacktrace::BifArgs::from_terms(&self.x_regs()?[..arity])?,
                            info: crate::stacktrace::BifErrorInfo::Plain,
                        });
                        Err(VmError::Trap(trap))
                    }
                    result => result,
                };
                // Port of erts/emulator/beam/jit/arm/instr_bif.cpp:730-776
                // (call_bif_shared, ERTS_IS_GC_AFTER_BIF_DESIRED), OTP-29.1.1: the export
                // trampoline an apply reaches collects after the BIF as a static call does.
                self.x_regs()?[0] = p.gc_after_bif(result?)?;
                return Ok(Self::return_value_after_dirty(p, self.x_regs()?[0]));
            }
        }
        // `!` is an export alias for the process-aware `send/2` BIF.
        let native_function = if module == "erlang" && function == "!" && arity == 2 {
            "send"
        } else {
            function
        };
        if !resolved_entry
            && let Some(run) = ctx.as_deref_mut()
            && let Some(arity8) = arity8
            && let Some(result) = self.dispatch_native(
                p,
                run,
                module,
                native_function,
                arity,
                crate::natives::native_entry(module, native_function, arity8),
            )
        {
            let result = match result {
                Err(VmError::Trap(mut trap))
                    if trap.class == arinsal_bifs::Class::Error
                        && trap.top.is_none()
                        && trap.trace.is_none()
                        && !(module == "erlang" && function == "error") =>
                {
                    // Port of erts/emulator/beam/beam_common.c (save_stacktrace),
                    // OTP-29.1.1: a failing BIF reached through apply owns the top frame too.
                    let (module_atom, function_atom) = match atoms {
                        Some(atoms) => atoms,
                        None => (
                            global_atoms().intern(module).map_err(|error| {
                                VmError::Unsupported(format!("BIF module atom: {error:?}"))
                            })?,
                            global_atoms().intern(function).map_err(|error| {
                                VmError::Unsupported(format!("BIF function atom: {error:?}"))
                            })?,
                        ),
                    };
                    trap.top = Some(crate::stacktrace::TopFrame::Bif {
                        module: module_atom,
                        function: function_atom,
                        args: crate::stacktrace::BifArgs::from_terms(&self.x_regs()?[..arity])?,
                        info: crate::stacktrace::BifErrorInfo::Plain,
                    });
                    Err(VmError::Trap(trap))
                }
                result => result,
            };
            let result = match result {
                Err(VmError::TrapExport(trap)) => {
                    return self.bif_trap_from_executor(p, trap);
                }
                result => result,
            };
            self.x_regs()?[0] = result?;
            return Ok(Self::return_value_after_dirty(p, self.x_regs()?[0]));
        }
        // elixir_loop1: apply/3 reaches this path without an import slot.
        // sys_core_fold:fold_lit_args/4 applies erlang:make_fun/3 the same way.
        if module == "erlang" && function == "make_fun" && arity == 3 {
            let args = [self.x_regs()?[0], self.x_regs()?[1], self.x_regs()?[2]];
            let value = crate::bif::make_fun_3(p, &args)
                .ok_or_else(|| VmError::Unsupported("make_fun BIF declined".into()))?
                .map_err(VmError::Trap)?;
            self.x_regs()?[0] = value;
            return Ok(Self::return_value(p, self.x_regs()?[0]));
        }
        if module == "erlang" && function == "fun_info" && (arity == 1 || arity == 2) {
            self.x_regs()?[0] = if arity == 2 {
                crate::erl_bif_info::fun_info_2(p, &self.x_regs()?[..2])
                    .ok_or_else(|| VmError::Unsupported("fun_info/2 BIF declined".into()))?
                    .map_err(VmError::Trap)?
            } else {
                self.fun_info(p)?
            };
            return Ok(Self::return_value(p, self.x_regs()?[0]));
        }
        if module == "erlang" && function == "fun_info_mfa" && arity == 1 {
            self.x_regs()?[0] = crate::erl_bif_info::fun_info_mfa_1(p, self.x_regs()?)?;
            return Ok(Self::return_value(p, self.x_regs()?[0]));
        }
        // elixir_loop1: dynamic apply must see static NIFs such as re:import/1.
        if let Some(bif) = arity8
            .and_then(|arity| crate::natives::plain_static_nif_lookup(module, function, arity))
        {
            let result = {
                let mut heap = ProcessHeapHandle(&mut p.heap);
                let mut state = arinsal_bifs::BifState::default();
                let mut bif_ctx = Ctx::with_fcalls(&mut heap, &mut state);
                bif(&mut bif_ctx, &self.x_regs()?[..arity])
            };
            let mut bif_args = self.x_regs()?[..arity].to_vec();
            let mut result = result;
            crate::calls::gc_after_bif(p, &mut bif_args, &mut result)?;
            let result = result.map_err(|error| match error {
                BifError::Unsupported(reason) => VmError::Unsupported(reason.into()),
                error => exceptions::bif_error(p, module, function, &bif_args, error),
            })?;
            self.x_regs()?[0] = result;
            return Ok(Self::return_value(p, self.x_regs()?[0]));
        }
        if arity8.is_some_and(|arity| arinsal_spec::bif_lookup(module, function, arity).is_some()) {
            return Err(VmError::Unsupported(format!(
                "BIF {module}:{function}/{arity}"
            )));
        }
        let Some(&module_id) = code_tables(erts_active_code_ix()).loaded.get(module) else {
            // Port of erts/emulator/beam/beam_common.c:1294 (call_error_handler), OTP-29.1.1.
            return crate::beam_common::call_error_handler(
                p,
                (module, function, arity),
                self.x_regs()?,
                "undefined_function",
                self,
                ctx,
            );
        };
        let Some(target) =
            code_tables(erts_active_code_ix()).modules[module_id].export(function, arity as u32)
        else {
            // Port of erts/emulator/beam/beam_common.c (call_error_handler).
            return crate::beam_common::call_error_handler(
                p,
                (module, function, arity),
                self.x_regs()?,
                "undefined_function",
                self,
                ctx,
            );
        };
        // Port of erts/emulator/beam/beam_bp.c:1181-1250 (do_call_trace), OTP-29.1.1:
        // apply resolves an export through its global breakpoint before entering native code.
        // Its native export normally reaches this event via the export trampoline; a
        // scheduler-interpreted apply must preserve that event when the module has no
        // interpreter export-breakpoint entry.
        if let Some(run) = ctx
            && let Some(arity8) = arity8
            && crate::trace_bp::breakpoint_kinds(p, module, function, arity8).1
            && let Some(native) =
                crate::beamasm_integration::erts_code_hdr_function(module_id, target)
        {
            let actions = crate::trace::executor_native_call_event(self, p, run, &native, false)?;
            crate::trace::push_native_trace_frame(
                p,
                native.start,
                &actions,
                self.reg_prefix(usize::from(native.arity))?,
            )?;
        }
        self.set_position(p, module_id, target)?;
        // Port of erts/emulator/beam/jit/arm/instr_common.cpp:3098-3116 (emit_i_test_yield),
        // OTP-29.1.1: the call's reduction is taken by the entered function's own
        // `i_test_yield`, which runs at `set_position`'s native entry; a tick here charged
        // it twice (a traced BIF's trap continuation went through this path).
        Ok(ImportOutcome::Dispatch)
    }

    fn finish_apply_native_result(
        &mut self,
        p: &mut Process,
        module: &str,
        function: &str,
        arity: usize,
        atoms: Option<(arinsal_term::Atom, arinsal_term::Atom)>,
        result: Result<Term, VmError>,
    ) -> Result<ImportOutcome, VmError> {
        let result = match result {
            Err(VmError::Trap(mut trap))
                if trap.class == arinsal_bifs::Class::Error
                    && trap.top.is_none()
                    && trap.trace.is_none()
                    && !(module == "erlang" && function == "error") =>
            {
                // Port of erts/emulator/beam/beam_common.c (save_stacktrace), OTP-29.1.1.
                let (module_atom, function_atom) = match atoms {
                    Some(atoms) => atoms,
                    None => (
                        global_atoms().intern(module).map_err(|error| {
                            VmError::Unsupported(format!("BIF module atom: {error:?}"))
                        })?,
                        global_atoms().intern(function).map_err(|error| {
                            VmError::Unsupported(format!("BIF function atom: {error:?}"))
                        })?,
                    ),
                };
                trap.top = Some(crate::stacktrace::TopFrame::Bif {
                    module: module_atom,
                    function: function_atom,
                    args: crate::stacktrace::BifArgs::from_terms(&self.x_regs()?[..arity])?,
                    info: crate::stacktrace::BifErrorInfo::Plain,
                });
                Err(VmError::Trap(trap))
            }
            result => result,
        };
        match result {
            Err(VmError::TrapExport(trap)) => self.bif_trap_from_executor(p, trap),
            result => {
                let value = result?;
                self.x_regs()?[0] = value;
                Ok(Self::return_value_after_dirty(p, value))
            }
        }
    }

    /// `fun_info/1` is the OTP-level list wrapper around the keyed `fun_info/2` BIF.
    pub(super) fn fun_info(&self, p: &mut Process) -> Result<Term, VmError> {
        p.ensure_objv(1024, self.reg_prefix(1)?)?;
        let fun = self.x_regs()?[0];
        // SAFETY: X0 retains the fun throughout construction; no collection follows.
        let view = unsafe { fun.fun_ref() }.ok_or_else(|| self.exception(p, "badarg"))?;
        let keys: &[&str] = if matches!(view, FunRef::Local { .. }) {
            &[
                "pid",
                "module",
                "new_index",
                "new_uniq",
                "index",
                "uniq",
                "name",
                "arity",
                "env",
                "type",
            ]
        } else {
            &["module", "name", "arity", "env", "type"]
        };
        let mut builder = TermBuilder::new(&mut p.heap);
        let mut pairs = Vec::with_capacity(keys.len());
        for &key in keys {
            let value = match (&view, key) {
                (FunRef::Local { .. }, "pid") => Term::pid(0, 0).unwrap(),
                (
                    FunRef::Export { .. },
                    "pid" | "index" | "new_index" | "uniq" | "new_uniq" | "refc",
                ) => Term::atom(
                    global_atoms()
                        .intern("undefined")
                        .map_err(|_| VmError::Unsupported("atom undefined".into()))?,
                ),
                (FunRef::Local { entry, .. }, "module") => Term::atom(entry.module),
                (FunRef::Export { entry }, "module") => Term::atom(entry.module()),
                (FunRef::Local { entry, .. }, "index") => {
                    Term::small(i64::from(entry.old_index))
                        .ok_or_else(|| VmError::Unsupported("fun index".into()))?
                }
                (FunRef::Local { entry, .. }, "new_index") => {
                    Term::small(i64::from(entry.index))
                        .ok_or_else(|| VmError::Unsupported("fun index".into()))?
                }
                (FunRef::Local { entry, .. }, "uniq") => Term::small(i64::from(entry.old_uniq))
                    .ok_or_else(|| VmError::Unsupported("fun uniq".into()))?,
                (FunRef::Local { entry, .. }, "new_uniq") => builder
                    .binary(&entry.uniq)
                    .map_err(|e| VmError::Unsupported(format!("fun uniq allocation {e:?}")))?,
                (FunRef::Local { entry, .. }, "name") => crate::erl_fun::erts_get_fun_mfa(entry)
                    .map(|mfa| crate::native_hooks::from_raw(mfa.function))
                    .unwrap_or(Term::NIL),
                (FunRef::Export { entry }, "name") => Term::atom(entry.function()),
                (FunRef::Local { .. } | FunRef::Export { .. }, "arity") => {
                    Term::small(i64::from(fun.fun_arity().unwrap())).unwrap()
                }
                (FunRef::Local { free_vars, .. }, "env") => {
                    let mut list = Term::NIL;
                    for &word in free_vars.iter().rev() {
                        // SAFETY: The fun header bounds the captured term words.
                        let value = unsafe { std::mem::transmute::<u64, Term>(word) };
                        list = builder.cons(value, list).map_err(|e| {
                            VmError::Unsupported(format!("fun env allocation {e:?}"))
                        })?;
                    }
                    list
                }
                (FunRef::Export { .. }, "env") => Term::NIL,
                (FunRef::Local { .. }, "type") => Term::atom(
                    global_atoms()
                        .intern("local")
                        .map_err(|_| VmError::Unsupported("atom local".into()))?,
                ),
                (FunRef::Export { .. }, "type") => Term::atom(
                    global_atoms()
                        .intern("external")
                        .map_err(|_| VmError::Unsupported("atom external".into()))?,
                ),
                (FunRef::Local { .. }, "refc") => Term::small(1).unwrap(),
                _ => return Err(self.exception(p, "badarg")),
            };
            let key_atom = Term::atom(
                global_atoms()
                    .intern(key)
                    .map_err(|_| VmError::Unsupported("fun info key".into()))?,
            );
            let pair = builder
                .tuple(&[key_atom, value])
                .map_err(|e| VmError::Unsupported(format!("fun info allocation {e:?}")))?;
            pairs.push(pair);
        }
        builder
            .list_from_iter(pairs)
            .map_err(|e| VmError::Unsupported(format!("fun info list {e:?}")))
    }
}

/// `{badfun, Fun}` for a fun whose code is no longer loaded.
fn badfun_reason(p: &mut Process, reg: &mut [Term], arity: usize) -> Result<Term, VmError> {
    p.ensure_objv(3, &mut reg[..arity + 1])?;
    let fun = reg[arity];
    let kind = global_atoms()
        .intern("badfun")
        .map_err(|_| VmError::Unsupported("exception atom".into()))?;
    TermBuilder::new(&mut p.heap)
        .tuple(&[Term::atom(kind), fun])
        .map_err(|e| VmError::Unsupported(format!("exception allocation {e:?}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn make_fun_keeps_arguments_live_under_gc_stress() {
        const CHILD: &str = "ARINSAL_MAKE_FUN_GC_STRESS_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "funs::tests::make_fun_keeps_arguments_live_under_gc_stress",
                    "--nocapture",
                ])
                .env(CHILD, "1")
                .env("ARINSAL_GC_STRESS", "1")
                .env("ARINSAL_GC_VERIFY", "1")
                .status()
                .unwrap();
            assert!(status.success(), "GC stress child failed: {status}");
            return;
        }

        let reference = arinsal_difftest::RefErl::start()
            .expect("the regression test requires the reference erl");
        let beam = reference
            .compile_named(
                "vm_make_fun_gc_stress",
                "-module(vm_make_fun_gc_stress). -export([run/2]). run(A,B) -> F = fun() -> ok end, {A,B,F}.",
                &[],
            )
            .unwrap();
        let mut vm = crate::boot::test_node();
        vm.load_bytes(&beam).unwrap();
        let args = [Term::small(17).unwrap(), Term::small(29).unwrap()];
        let result = vm
            .eval_scheduled("vm_make_fun_gc_stress", "run", &args, 1)
            .unwrap();
        let arinsal_etf::OwnedTerm::Tuple(items) = &result.term else {
            panic!("expected {{17, 29, Fun}}, got {:?}", result.term);
        };
        assert_eq!(items[0], arinsal_etf::OwnedTerm::Int(17));
        assert_eq!(items[1], arinsal_etf::OwnedTerm::Int(29));
    }
}
