//! Local closures, export funs, and dynamic calls.

use crate::process::Message;
use crate::{EvalResult, ImportOutcome, Process, Vm, VmError, exceptions};
use arinsal_bifs::{BifError, Ctx, ProcessHeapHandle};
use arinsal_loader::{ImportClass, Module};
use arinsal_sched::RunCtx;
use arinsal_term::{ExportEntry, FunRef, Term, TermBuilder, TermKind, global_atoms};
use std::sync::Arc;

pub(super) fn set_module_uniq(module: &mut Module, uniq: [u8; 16]) {
    for slot in &mut module.funs {
        if let Some(entry) = Arc::get_mut(&mut slot.entry) {
            entry.uniq = uniq;
        }
    }
}

/// Build the Erlang exception reason before the exception handler formats it.
pub(super) fn call_error_reason(p: &mut Process, fun: Term, arity: usize) -> Result<Term, VmError> {
    let is_fun = fun.classify() == TermKind::Fun;
    p.ensure(6 + arity * 2, arity + 1)?;
    let fun = p.x[arity];
    let mut builder = TermBuilder::new(&mut p.heap);
    let kind = global_atoms()
        .intern(if is_fun { "badarity" } else { "badfun" })
        .map_err(|_| VmError::Unsupported("exception atom".into()))?;
    if !is_fun {
        return builder
            .tuple(&[Term::atom(kind), fun])
            .map_err(|e| VmError::Unsupported(format!("exception allocation {e:?}")));
    }
    let mut args = Term::NIL;
    for value in p.x[..arity].iter().rev().copied() {
        args = builder
            .cons(value, args)
            .map_err(|e| VmError::Unsupported(format!("exception allocation {e:?}")))?;
    }
    let detail = builder
        .tuple(&[fun, args])
        .map_err(|e| VmError::Unsupported(format!("exception allocation {e:?}")))?;
    builder
        .tuple(&[Term::atom(kind), detail])
        .map_err(|e| VmError::Unsupported(format!("exception allocation {e:?}")))
}

fn error_handler_module(process: &Process) -> String {
    process
        .cold
        .as_ref()
        .and_then(|cold| cold.flags.error_handler)
        .and_then(atom_name)
        .unwrap_or_else(|| "error_handler".to_owned())
}

fn atom_name(term: Term) -> Option<String> {
    global_atoms()
        .text(term.as_atom()?)
        .map(|name| name.to_string())
}

enum ArgumentError {
    Badarg,
    SystemLimit,
}

fn argument_list(mut list: Term) -> Result<Vec<Term>, ArgumentError> {
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
/// The plain BIF or static NIF that `{module, function, arity}` names, found once per export.
///
/// A name is plain when the load-time import classifier calls it `Pure` and it is not a
/// trapping BIF: a static call of it runs the function directly, and so does `apply`.
// Port of erts/emulator/beam/beam_common.c (apply: `erts_find_export_entry` then the BIF),
// OTP-29.1.1.
fn apply_plain_bif(
    module_atom: arinsal_term::Atom,
    function_atom: arinsal_term::Atom,
    module: &str,
    function: &str,
    arity: usize,
) -> Option<arinsal_bifs::BifFn> {
    use std::collections::HashMap;
    use std::sync::{OnceLock, RwLock};
    type Key = (arinsal_term::Atom, arinsal_term::Atom, u8);
    static PLAIN: OnceLock<RwLock<HashMap<Key, arinsal_bifs::BifFn>>> = OnceLock::new();
    let arity = u8::try_from(arity).ok()?;
    let key = (module_atom, function_atom, arity);
    let table = PLAIN.get_or_init(|| RwLock::new(HashMap::new()));
    if let Some(bif) = table
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(&key)
    {
        return Some(*bif);
    }
    let bif = arinsal_bifs::lookup(module, function, arity)
        .or_else(|| crate::natives::plain_static_nif_lookup(module, function, arity))?;
    if crate::natives::classify(module, function, arity, true).0 != ImportClass::Pure
        || crate::bif_traps::traps(module, function, arity)
    {
        return None;
    }
    table
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(key, bif);
    Some(bif)
}

fn unwrap_nested_apply(
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
    pub(super) fn eval_erlang_fun_builtin(
        &mut self,
        function: &str,
        args: &[Term],
    ) -> Option<Result<EvalResult, VmError>> {
        let arity = args.len();
        let result = match (function, arity) {
            ("apply", 2 | 3) | ("make_fun", 3) | ("fun_info", 1 | 2) | ("fun_info_mfa", 1) => {
                // elixir_loop1
                let mut p = Process::new();
                p.x[..arity].copy_from_slice(args);
                p.gc_live = arity;
                let value = match function {
                    "apply" => match self.apply_bif(&mut p, arity, None) {
                        Ok(ImportOutcome::Returned(value)) => Ok(value),
                        Ok(ImportOutcome::Dispatch) | Ok(ImportOutcome::Yield) => {
                            // The apply resolved to Erlang code: erts runs it in the calling
                            // process's native code, which here is a scheduled process.
                            return Some(self.eval_in_scheduled_process("erlang", function, args));
                        }
                        Err(error) => Err(error),
                    },
                    "make_fun" => self.make_export_fun(&mut p, args),
                    "fun_info" => self.fun_info(&mut p, arity == 2),
                    "fun_info_mfa" => self.fun_info_mfa(&mut p), // elixir_loop1
                    _ => unreachable!(),
                };
                // An exception raised here has no BEAM frame to unwind into: turn it
                // into an uncaught `Raised` while its reason still lives on `p`'s heap.
                let value = match value {
                    Err(VmError::Trap(trap)) => {
                        match exceptions::resume(self, &mut p, None, trap) {
                            Ok(Some(error)) | Err(error) => Err(error),
                            Ok(None) => Err(VmError::Unsupported(
                                "exception resumed without a handler".into(),
                            )),
                        }
                    }
                    other => other,
                };
                value.map(|term| {
                    p.stats.heap_words = p.heap.capacity_words();
                    EvalResult {
                        term,
                        stats: p.stats.snapshot(),
                        _process: p,
                    }
                })
            }
            _ => return None,
        };
        Some(result)
    }

    // Port of erts/emulator/beam/beam_common.c:1605 (call_fun), OTP-29.1.1.
    #[inline]
    pub(super) fn call_fun_term(
        &mut self,
        p: &mut Process,
        fun: Term,
        arity: usize,
        ctx: Option<&mut RunCtx<'_, Message>>,
    ) -> Result<ImportOutcome, VmError> {
        if arity >= crate::proc_create::ATTACHED_X_REGS {
            return Err(VmError::Unsupported("fun arity exceeds X registers".into()));
        }
        p.x.ensure_x(arity + 1);
        p.x[arity] = fun;
        // SAFETY: The fun is held in an X register while this process is live.
        let view = unsafe { fun.fun_ref() };
        let actual = match &view {
            Some(FunRef::Local { entry, .. }) => Some(entry.arity as usize),
            Some(FunRef::Export { entry }) => Some(entry.arity as usize),
            None => None,
        };
        if actual != Some(arity) {
            let reason = call_error_reason(p, fun, arity)?;
            return Err(VmError::Trap(exceptions::Trap::error(reason)));
        }
        match view.unwrap() {
            FunRef::Local { entry, free_vars } => {
                // Port of erts/emulator/beam/beam_common.c:1621-1624 (call_fun), OTP-29.1.1.
                self.refresh_code();
                let cached = entry.get_dispatch(0).and_then(|(id, target, generation)| {
                    if generation == self.code_generation() {
                        return Some((id, target));
                    }
                    (self.code.module_live.get(id) == Some(&true)).then_some((id, target))
                });
                let resolved = match cached {
                    Some(cached) if !self.purge_state.pending(cached.0) => Some(cached),
                    // A cached target in code pending purge is re-resolved: the fun
                    // entry may also exist in the current instance, where erts
                    // already dispatches it.
                    _ => self.resolve_local_fun(p, entry, arity)?,
                };
                let Some((module_id, target)) = resolved else {
                    return self.call_lambda_handler(p, entry.module, arity, false, ctx);
                };
                if self.purge_state.pending(module_id) {
                    return self.call_lambda_handler(p, entry.module, arity, true, ctx);
                }
                // The caller module's register file is sized from its own beam.
                // A closure passes its environment in `x[arity..]`, which can sit
                // past that size (elixir_erl_compiler's spawn fun). OTP grows the
                // process X array; shrinking never happens, so the callee keeps it.
                let need = arity + free_vars.len();
                if need > crate::proc_create::ATTACHED_X_REGS {
                    return Err(VmError::Unsupported(
                        "closure environment exceeds X registers".into(),
                    ));
                }
                p.x.ensure_x(need);
                for (i, &word) in free_vars.iter().enumerate() {
                    // SAFETY: The fun header bounds the environment and every word is a term.
                    p.x[arity + i] = unsafe { std::mem::transmute::<u64, Term>(word) };
                }
                p.gc_live = arity + free_vars.len();
                self.set_position(p, module_id, target)?;
                p.tick();
                Ok(ImportOutcome::Dispatch)
            }
            FunRef::Export { entry } => {
                let module = atom_name(Term::atom(entry.module))
                    .ok_or_else(|| VmError::Unsupported("export module atom".into()))?;
                let function = atom_name(Term::atom(entry.function))
                    .ok_or_else(|| VmError::Unsupported("export function atom".into()))?;
                if module == "erlang" && function == "apply" && matches!(arity, 2 | 3) {
                    return self.apply_bif(p, arity, ctx);
                }
                // The fun's own checks (badfun, badarity) raise before the frame is released;
                // only the callee BIF runs with it gone.
                let began = p.begin_tail_apply(crate::proc_create::TAIL_FUN_CALL);
                let result = self.call_named_atoms(
                    p,
                    entry.module,
                    entry.function,
                    &module,
                    &function,
                    arity,
                    ctx,
                );
                p.end_tail_apply(began, &result);
                result
            }
        }
    }

    /// Continue a local fun call whose code is not callable in
    /// `Handler(Module, Fun, Args)`. With `pending_purge` the code is being purged:
    /// the caller suspends in `erts_code_purger:pending_purge_lambda/3`, which retries
    /// once the purge completes or aborts. Otherwise no current code exists and
    /// `error_handler:undefined_lambda/3` tries to load it.
    /// Port of erts/emulator/beam/beam_common.c:1677-1727 (call_fun), OTP-29.1.1.
    #[cold]
    fn call_lambda_handler(
        &mut self,
        p: &mut Process,
        module: arinsal_term::Atom,
        arity: usize,
        pending_purge: bool,
        ctx: Option<&mut RunCtx<'_, Message>>,
    ) -> Result<ImportOutcome, VmError> {
        let (handler, function) = if pending_purge {
            let name = atom_name(Term::atom(module))
                .ok_or_else(|| VmError::Unsupported("lambda module atom".into()))?;
            // Port of erts/emulator/beam/beam_bif_load.c:1977
            // (erts_suspend_process_on_pending_purge_lambda), OTP-29.1.1.
            if let Some(pid) = p.self_pid
                && self.purge_state.suspend_on_pending_lambda(&name, pid)
            {
                crate::suspend::suspend_self(p);
                // erts_suspend + ERTS_VBUMP_ALL_REDS (beam_bif_load.c:2003-2004).
                crate::bif_traps::vbump_all_reds(p);
            }
            ("erts_code_purger".to_owned(), "pending_purge_lambda")
        } else {
            let handler = error_handler_module(p);
            let ready = self.code.loaded.get(&handler).is_some_and(|id| {
                self.code.modules[*id]
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
        p.ensure(arity.saturating_mul(2).saturating_add(4), arity + 1)?;
        let fun = p.x[arity];
        let args: Vec<Term> = p.x[..arity].to_vec();
        let list = TermBuilder::new(&mut p.heap)
            .list_from_iter(args)
            .map_err(|error| VmError::Unsupported(format!("lambda arg list: {error:?}")))?;
        p.x.ensure_x(4);
        p.x[0] = Term::atom(module);
        p.x[1] = fun;
        p.x[2] = list;
        p.x[3] = Term::NIL;
        self.call_named(p, &handler, function, 3, ctx)
    }

    #[cold]
    fn resolve_local_fun(
        &mut self,
        p: &mut Process,
        entry: &arinsal_term::FunEntry,
        arity: usize,
    ) -> Result<Option<(usize, usize)>, VmError> {
        let name = atom_name(Term::atom(entry.module))
            .ok_or_else(|| VmError::Unsupported("lambda module atom".into()))?;
        let found = [self.code.loaded.get(&name), self.code.old.get(&name)]
            .into_iter()
            .flatten()
            .find_map(|&id| {
                self.code.modules[id]
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
            if self.code.loaded.contains_key(&name) {
                let reason = badfun_reason(p, arity)?;
                return Err(VmError::Trap(exceptions::Trap::error(reason)));
            }
            return Ok(None);
        };
        entry.set_dispatch(0, module_id, target, self.code_generation());
        Ok(Some((module_id, target)))
    }

    #[inline]
    pub(super) fn call_named(
        &mut self,
        p: &mut Process,
        module: &str,
        function: &str,
        arity: usize,
        ctx: Option<&mut RunCtx<'_, Message>>,
    ) -> Result<ImportOutcome, VmError> {
        self.call_named_resolved(p, None, module, function, arity, ctx)
    }

    /// Make the call a BIF trapped to, on the schedule-in after the trap's context switch.
    /// erts leaves the trap arguments in X and `beam_bif_export_trap` dispatches the export as
    /// an ordinary call; this is its only caller, so a trap never runs its export in the slice
    /// that trapped.
    // Port of erts/emulator/beam/bif.h:316-326 (BIF_TRAP*) and
    // jit/arm/beam_asm_global.cpp:145-155 (emit_bif_export_trap), OTP-29.1.1.
    pub(crate) fn trap_to_export(
        &mut self,
        p: &mut Process,
        trap: crate::ExportTrap,
        ctx: Option<&mut RunCtx<'_, Message>>,
    ) -> Result<ImportOutcome, VmError> {
        let target = trap.target;
        let (module, function, arity) = (target.module, target.function, target.arity);
        if arity != trap.args.len() {
            return Err(VmError::Unsupported(format!(
                "trap to {module}:{function}/{arity} with {} arguments",
                trap.args.len()
            )));
        }
        let module_atom = trap.entry.module;
        let function_atom = trap.entry.function;
        if !crate::trace_bp::any_pattern()
            && !crate::trace::saves_calls(p)
            && !self.unloaded_on_load(p, module)
            && let Some(&module_id) = self.code.loaded.get(&module_atom)
            && let Some(target) = self.code.modules[module_id]
                .export_slot_atom(function_atom, arity as u8)
                .map(arinsal_loader::ExportSlot::target)
        {
            // Port of erts/emulator/beam/bif.h:316-326 (BIF_TRAP*: set `c_p->i`
            // to the already-resolved export and leave its arguments in X), OTP-29.1.1.
            // The trap itself costs nothing: a BIF export runs `call_bif_mfa`, which does not
            // touch FCALLS, and an Erlang export charges its call in its own `i_test_yield`
            // (jit/arm/ops.tab, int_func_start).
            p.gc_live = arity;
            p.x.ensure_x(arity);
            p.x[..arity].copy_from_slice(&trap.args);
            self.set_position(p, module_id, target)?;
            return Ok(ImportOutcome::Dispatch);
        }
        p.x.ensure_x(arity);
        p.x[..arity].copy_from_slice(&trap.args);
        // A BIF traps to its `bif_trap_export` entry (erl_bif_table.c, erts_init_trap_export),
        // which has no breakpoint: the continuation is not a traced call of its own.
        if arinsal_spec::bif_lookup(module, function, arity as u8).is_some() {
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
    fn call_named_atoms(
        &mut self,
        p: &mut Process,
        module_atom: arinsal_term::Atom,
        function_atom: arinsal_term::Atom,
        module: &str,
        function: &str,
        arity: usize,
        ctx: Option<&mut RunCtx<'_, Message>>,
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
        mut ctx: Option<&mut RunCtx<'_, Message>>,
    ) -> Result<ImportOutcome, VmError> {
        // A BIF reached through apply is traced like a direct call.
        // Port of erts/emulator/beam/beam_bp.c:321-330 (erts_export_is_bif_traced), OTP-29.1.1.
        let traced = match ctx.as_deref_mut() {
            Some(run)
                if arity <= usize::from(u8::MAX)
                    && crate::trace_bp::any_pattern()
                    && arinsal_spec::bif_lookup(module, function, arity as u8).is_some() =>
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

    /// Run a plain BIF or static NIF reached through `apply`, as a static call of the same
    /// export would.
    #[allow(clippy::too_many_arguments)] // The call site's own context, passed through.
    fn run_apply_bif(
        &mut self,
        p: &mut Process,
        ctx: Option<&mut RunCtx<'_, Message>>,
        module: &str,
        function: &str,
        arity: usize,
        bif: arinsal_bifs::BifFn,
    ) -> Result<ImportOutcome, VmError> {
        // The BIF's BUMP_REDS lowers FCALLS, which the context switch reads.
        let (result, deferred) = {
            let mut heap = ProcessHeapHandle(&mut p.heap);
            let mut state = arinsal_bifs::BifState::default();
            let mut bif_ctx = Ctx::with_fcalls(&mut heap, &mut state);
            let result = bif(&mut bif_ctx, &p.x[..arity]);
            (result, bif_ctx.take_deferred())
        };
        // Port of erts/emulator/beam/bif.h (BIF_TRAP*) and beam_common.c (fixed_apply returns the
        // BIF's own export dispatch), OTP-29.1.1: a BIF that ran out of reductions returns
        // THE_NON_VALUE with its continuation installed, and the process context-switches into
        // the continuation export. Dropping the deferred state here would hand the non-value
        // back to the caller as a result.
        if let Some(trap) = deferred {
            let module_atom = global_atoms()
                .intern(module)
                .map_err(|error| VmError::Unsupported(format!("BIF module atom: {error:?}")))?;
            let function_atom = global_atoms()
                .intern(function)
                .map_err(|error| VmError::Unsupported(format!("BIF function atom: {error:?}")))?;
            let args = p.x[..arity].to_vec();
            crate::bif_traps::install_deferred_trap(
                p,
                crate::bif_traps::APPLY_TRAP_KEY,
                (module_atom, function_atom),
                &args,
                *trap,
            )
            .map_err(|_| {
                exceptions::bif_error(p, module, function, &args, BifError::SystemLimit)
            })?;
            // Port of erts/emulator/beam/jit/arm/instr_bif.cpp:676-700 (bif_nif_epilogue: a TRAP
            // result jumps to context_switch_simplified once), OTP-29.1.1: this Yield is that
            // switch, so the export trap runs the continuation when the process is next
            // scheduled instead of scheduling it out a second time.
            if let Some(pending) = p.bif_trap_mut() {
                pending.schedule_out = false;
            }
            crate::bif_traps::arm_export_trap(p);
            return Ok(ImportOutcome::Yield);
        }
        let mut bif_args = p.x[..arity].to_vec();
        if matches!(&result, Err(BifError::DirtyTrap)) {
            // Port of erts/emulator/beam/bif.c:5612-5627 (dirty_bif_trap): restore the
            // saved BIF arguments and continue at the export saved by the dirty scheduler.
            let Some(((target_module, target_function, target_arity), args)) =
                p.take_dirty_bif_trap_target()
            else {
                return Err(VmError::Unsupported(
                    "dirty_bif_trap has no saved export continuation".into(),
                ));
            };
            p.take_dirty_bif_original();
            let target_arity = usize::from(target_arity);
            p.x.ensure_x(target_arity + 2);
            p.x[..target_arity].copy_from_slice(&args);
            p.x[target_arity] = Term::atom(
                global_atoms()
                    .intern(target_module)
                    .map_err(|_| VmError::Unsupported("dirty trap module atom".into()))?,
            );
            p.x[target_arity + 1] = Term::atom(
                global_atoms()
                    .intern(target_function)
                    .map_err(|_| VmError::Unsupported("dirty trap function atom".into()))?,
            );
            p.gc_live = target_arity;
            return self.apply_fixed(p, target_arity, ctx);
        }
        if module == "erts_internal" && function == "dirty_bif_result" {
            p.take_dirty_bif_original();
        }
        // Port of erts/emulator/beam/beam_jit_common.cpp (beam_jit_call_bif:
        // ERTS_IS_GC_AFTER_BIF_DESIRED → erts_gc_after_bif_call_lhf), OTP-29.1.1: the export's
        // call_bif_mfa stub an apply reaches collects after the BIF returns, before the
        // epilogue raises or returns. A value roots only the result; an error roots the
        // argument registers.
        let mut result = result;
        crate::calls::gc_after_bif(p, &mut bif_args, &mut result)?;
        let result = match result {
            Err(error @ BifError::Raise { .. })
                if module == "erts_internal" && function == "dirty_bif_exception" =>
            {
                let mut error = error;
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
                    // Port of erts/emulator/beam/erl_nfunc_sched.h (erts_nfunc_restore_error),
                    // OTP-29.1.1: `handle_error` raises at the saved `nep->pc`, the call
                    // site of the original BIF, while the return address pushed by the trap
                    // stays on the stack as the caller's continuation.
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
                Err(error)
            }
            result => result,
        };
        let result = result.map_err(|error| match error {
            BifError::Unsupported(reason) => VmError::Unsupported(reason.into()),
            error => exceptions::bif_error(p, module, function, &bif_args, error),
        })?;
        p.x[0] = result;
        // Port of erts/emulator/beam/jit/arm/instr_bif.cpp (call_bif_shared, bif_nif_epilogue)
        // and instr_call.cpp (emit_variable_apply, emit_fixed_apply), OTP-29.1.1: neither the
        // apply nor the BIF stub decrements FCALLS; the BIF's own BUMP_REDS, already taken
        // from FCALLS and folded above, is the whole charge.
        Ok(Self::return_value(p))
    }

    #[allow(clippy::too_many_arguments)] // Same signature as `call_named_resolved`, which it backs.
    fn call_named_untraced(
        &mut self,
        p: &mut Process,
        atoms: Option<(arinsal_term::Atom, arinsal_term::Atom)>,
        module: &str,
        function: &str,
        arity: usize,
        mut ctx: Option<&mut RunCtx<'_, Message>>,
    ) -> Result<ImportOutcome, VmError> {
        p.gc_live = arity;
        if arity > u8::MAX as usize {
            return Err(VmError::Exception {
                reason: "undef".into(),
                frame: format!("{module}:{function}/{arity}"),
            });
        }
        // Apply carries atom identities, so resolve the same process-aware BIF
        // entry as a static import without re-matching its module or function.
        let mut resolved_entry = false;
        if let (Some((module_atom, function_atom)), Some(run)) = (atoms, ctx.as_deref_mut()) {
            let entry = crate::signals::handler_atoms(module_atom, function_atom, arity as u8);
            if let Some(entry) = entry {
                resolved_entry = true;
                if let Some(result) = self.dispatch_resolved_entry(
                    p,
                    run,
                    crate::natives::NativeArgs::Registers(arity),
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
                                args: crate::stacktrace::BifArgs::from_terms(&p.x[..arity])?,
                                info: crate::stacktrace::BifErrorInfo::Plain,
                            });
                            Err(VmError::Trap(trap))
                        }
                        result => result,
                    };
                    // Port of erts/emulator/beam/jit/arm/instr_bif.cpp:730-776
                    // (call_bif_shared, ERTS_IS_GC_AFTER_BIF_DESIRED), OTP-29.1.1: the export
                    // trampoline an apply reaches collects after the BIF as a static call does.
                    p.x[0] = p.gc_after_bif(result?)?;
                    return Ok(Self::return_value_after_dirty(p));
                }
            }
        }
        // Trapping BIFs must be intercepted before native dispatch: dynamic
        // apply may otherwise enter a synchronous fast path for the same MFA.
        // The export of a plain BIF is found by its atoms and run as a static call of it
        // would, without matching names against every family of natives. An interrupted
        // trapping BIF keeps its state for `execute_named` to settle first.
        if let Some((module_atom, function_atom)) = atoms
            && p.cold.as_ref().is_none_or(|cold| cold.bif_trap.is_none())
            && let Some(bif) = apply_plain_bif(module_atom, function_atom, module, function, arity)
        {
            return self.run_apply_bif(p, ctx, module, function, arity, bif);
        }
        // A trap through `apply` is keyed as an apply: a static call is keyed by its native
        // call target instead, so the two never resume each other's continuation.
        let trap_key = crate::bif_traps::APPLY_TRAP_KEY;
        let trap_args = [
            p.x.first().copied().unwrap_or(Term::NIL),
            p.x.get(1).copied().unwrap_or(Term::NIL),
            p.x.get(2).copied().unwrap_or(Term::NIL),
            p.x.get(3).copied().unwrap_or(Term::NIL),
        ];
        let meter = crate::bif_traps::TrapMeter::start(p, ctx.as_deref());
        if let Some(result) = crate::bif_traps::execute_named(
            p,
            module,
            function,
            trap_key,
            arity,
            trap_args,
            ctx.as_deref_mut(),
        ) {
            let result = match result {
                // BIF_TRAP* to an export: the trap's context switch comes first.
                Err(VmError::TrapExport(trap)) => return self.bif_trap_from_executor(p, trap),
                result => result?,
            };
            meter.finish(p, ctx.as_deref_mut(), result.reductions());
            return match result {
                crate::bif_traps::HandlerResult::Done { value, .. } => {
                    p.x[0] = p.gc_after_bif(value)?;
                    Ok(Self::return_value(p))
                }
                crate::bif_traps::HandlerResult::Failed { .. } => {
                    unreachable!("failed trapping BIFs become VM exceptions")
                }
                crate::bif_traps::HandlerResult::Yield { .. } => Ok(ImportOutcome::Yield),
                crate::bif_traps::HandlerResult::Export(_) => {
                    unreachable!("execute_named converts export traps to VM transfers")
                }
            };
        }
        // `!` is an export alias for the process-aware `send/2` BIF.
        let native_function = if module == "erlang" && function == "!" && arity == 2 {
            "send"
        } else {
            function
        };
        if !resolved_entry
            && let Some(run) = ctx.as_deref_mut()
            && let Some(result) = self.dispatch_native(
                p,
                run,
                module,
                native_function,
                arity,
                crate::natives::native_entry(module, native_function, arity as u8),
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
                        args: crate::stacktrace::BifArgs::from_terms(&p.x[..arity])?,
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
            p.x[0] = result?;
            return Ok(Self::return_value_after_dirty(p));
        }
        // elixir_loop1: apply/3 reaches this path without an import slot.
        // sys_core_fold:fold_lit_args/4 applies erlang:make_fun/3 the same way.
        if module == "erlang" && function == "make_fun" && arity == 3 {
            let args = [p.x[0], p.x[1], p.x[2]];
            p.x[0] = self.make_export_fun(p, &args)?;
            return Ok(Self::return_value(p));
        }
        if module == "erlang" && function == "fun_info" && (arity == 1 || arity == 2) {
            p.x[0] = self.fun_info(p, arity == 2)?;
            return Ok(Self::return_value(p));
        }
        if module == "erlang" && function == "fun_info_mfa" && arity == 1 {
            p.x[0] = self.fun_info_mfa(p)?;
            return Ok(Self::return_value(p));
        }
        // elixir_loop1: dynamic apply must see static NIFs such as re:import/1.
        if let Some(bif) = arinsal_bifs::lookup(module, function, arity as u8)
            .or_else(|| crate::natives::plain_static_nif_lookup(module, function, arity as u8))
        {
            return self.run_apply_bif(p, ctx, module, function, arity, bif);
        }
        if arinsal_spec::bif_lookup(module, function, arity as u8).is_some() {
            return Err(VmError::Unsupported(format!(
                "BIF {module}:{function}/{arity}"
            )));
        }
        // Same as `call_import`: a not-yet-loaded `-on_load` module has to go
        // through `code_server` or its NIF stubs run.
        if self.unloaded_on_load(p, module) {
            return self.call_undefined_function_with_ctx(p, module, function, arity, ctx);
        }
        let module_id = match self.load_named_traced(p, module) {
            Ok(id) => id,
            Err(_) if self.should_autoload(p, module) => {
                // mix_loop1: OTP calls error_handler:undefined_function/3, which
                // code:ensure_loaded's from the code server path. Vm paths do
                // not include Mix archives added with code:add_pathz/1.
                if crate::calls::trace_boot_enabled() {
                    eprintln!("arinsal boot: autoload {module}:{function}/{arity}");
                }
                return self.call_undefined_function_with_ctx(p, module, function, arity, ctx);
            }
            Err(_) => {
                return Err(VmError::Exception {
                    reason: "undef".into(),
                    frame: format!("{module}:{function}/{arity}"),
                });
            }
        };
        let Some(target) = self.code.modules[module_id].export(function, arity as u8) else {
            // Port of erts/emulator/beam/beam_common.c (call_error_handler).
            if self.should_autoload(p, module) {
                return self.call_undefined_function_with_ctx(p, module, function, arity, ctx);
            }
            return Err(VmError::Exception {
                reason: "undef".into(),
                frame: format!("{module}:{function}/{arity}"),
            });
        };
        // Port of erts/emulator/beam/beam_bp.c:1181-1250 (do_call_trace), OTP-29.1.1:
        // apply resolves an export through its global breakpoint before entering native code.
        // Its native export normally reaches this event via the export trampoline; a
        // scheduler-interpreted apply must preserve that event when the module has no
        // interpreter export-breakpoint entry.
        if let Some(run) = ctx
            && crate::trace_bp::breakpoint_kinds(p, module, function, arity as u8).1
            && let Some(native) = self.beamasm_targets.function_for_target(
                module_id,
                &self.code.modules[module_id],
                crate::load::native_code_range(&self.code.code_meta, module_id),
                target,
            )
        {
            let actions = crate::trace::executor_native_call_event(self, p, run, &native, false)?;
            crate::trace::push_native_trace_frame(
                p,
                native.start,
                &actions,
                usize::from(native.arity),
            )?;
        }
        self.set_position(p, module_id, target)?;
        // Port of erts/emulator/beam/jit/arm/instr_common.cpp:3098-3116 (emit_i_test_yield),
        // OTP-29.1.1: the call's reduction is taken by the entered function's own
        // `i_test_yield`, which runs at `set_position`'s native entry; a tick here charged
        // it twice (a traced BIF's trap continuation went through this path).
        Ok(ImportOutcome::Dispatch)
    }

    /// `code_server` is up, so a missing module must go through `error_handler`
    /// instead of becoming `undef` immediately. A `code:delete`d module is
    /// missing too: Mix purges and deletes a protocol, then the next call
    /// autoloads the consolidated beam. Port of
    /// `error_handler:undefined_function/3`, OTP-29.1.1.
    pub(super) fn should_autoload(&self, p: &Process, module: &str) -> bool {
        if module == "error_handler" || self.code.pending_on_load.contains_key(module) {
            return false;
        }
        p.runtime
            .as_ref()
            .is_some_and(|runtime| runtime.reg.whereis_proc_str("code_server").is_some())
    }

    /// Jump to `error_handler:undefined_function(Module, Function, Args)`.
    pub(super) fn call_undefined_function(
        &mut self,
        p: &mut Process,
        module: &str,
        function: &str,
        arity: usize,
    ) -> Result<ImportOutcome, VmError> {
        self.call_undefined_function_with_ctx(p, module, function, arity, None)
    }

    fn call_undefined_function_with_ctx(
        &mut self,
        p: &mut Process,
        module: &str,
        function: &str,
        arity: usize,
        ctx: Option<&mut RunCtx<'_, Message>>,
    ) -> Result<ImportOutcome, VmError> {
        // Port of erts/emulator/beam/beam_common.c:1294-1345
        // (`call_error_handler`), OTP-29.1.1. Resolve the handler before changing X registers:
        // with no handler, the undef stack frame must retain the original call arguments.
        // `process_flag(error_handler, Module)` also disables autoload for that module.
        let handler = error_handler_module(p);
        let ready = self.code.loaded.get(&handler).is_some_and(|id| {
            self.code.modules[*id]
                .export("undefined_function", 3)
                .is_some()
        });
        if !ready {
            return Err(VmError::Exception {
                reason: "undef".into(),
                frame: format!("{module}:{function}/{arity}"),
            });
        }
        p.ensure(arity.saturating_mul(2).saturating_add(8), arity)?;
        let args: Vec<Term> = p.x[..arity].to_vec();
        let list = TermBuilder::new(&mut p.heap)
            .list_from_iter(args)
            .map_err(|error| VmError::Unsupported(format!("undef arg list: {error:?}")))?;
        let module_atom = global_atoms()
            .intern(module)
            .map_err(|_| VmError::Unsupported("undef module atom".into()))?;
        let function_atom = global_atoms()
            .intern(function)
            .map_err(|_| VmError::Unsupported("undef function atom".into()))?;
        p.x[0] = Term::atom(module_atom);
        p.x[1] = Term::atom(function_atom);
        p.x[2] = list;
        self.call_named(p, &handler, "undefined_function", 3, ctx)
    }

    /// Call the configured error handler for a debug breakpoint.
    pub(super) fn call_debug_breakpoint_handler(
        &mut self,
        p: &mut Process,
        module: &str,
        function: &str,
        arity: usize,
        ctx: Option<&mut RunCtx<'_, Message>>,
    ) -> Result<ImportOutcome, VmError> {
        // Port of erts/emulator/beam/beam_common.c:1294-1345
        // (`call_error_handler`), OTP-29.1.1. A breakpoint dispatches through the
        // process-configured handler just like an undefined call does.
        let handler = error_handler_module(p);
        let ready = self
            .code
            .loaded
            .get(&handler)
            .is_some_and(|id| self.code.modules[*id].export("breakpoint", 3).is_some());
        if !ready {
            return Err(VmError::Exception {
                reason: "undef".into(),
                frame: format!("{module}:{function}/{arity}"),
            });
        }
        p.ensure(arity.saturating_mul(2).saturating_add(8), arity)?;
        let args = p.x[..arity].to_vec();
        let list = TermBuilder::new(&mut p.heap)
            .list_from_iter(args)
            .map_err(|error| VmError::Unsupported(format!("breakpoint arg list: {error:?}")))?;
        let module_atom = global_atoms()
            .intern(module)
            .map_err(|_| VmError::Unsupported("breakpoint module atom".into()))?;
        let function_atom = global_atoms()
            .intern(function)
            .map_err(|_| VmError::Unsupported("breakpoint function atom".into()))?;
        p.x[0] = Term::atom(module_atom);
        p.x[1] = Term::atom(function_atom);
        p.x[2] = list;
        self.call_named(p, &handler, "breakpoint", 3, ctx)
    }

    #[inline]
    pub(super) fn apply_fixed(
        &mut self,
        p: &mut Process,
        arity: usize,
        ctx: Option<&mut RunCtx<'_, Message>>,
    ) -> Result<ImportOutcome, VmError> {
        if arity + 1 >= crate::proc_create::ATTACHED_X_REGS {
            return Err(self.exception(p, "system_limit"));
        }
        p.x.ensure_x(arity + 2);
        if p.x[arity].as_atom().is_none() || p.x[arity + 1].as_atom().is_none() {
            // Port of erts/emulator/beam/beam_common.c:1543-1550 (fixed_apply), OTP-29.1.1.
            let words = arity
                .checked_mul(2)
                .ok_or_else(|| self.exception(p, "system_limit"))?;
            p.ensure(words, arity + 2)?;
            let module_term = p.x[arity];
            let function_term = p.x[arity + 1];
            let arguments = TermBuilder::new(&mut p.heap)
                .list_from_iter(p.x[..arity].iter().copied())
                .map_err(|error| VmError::Unsupported(format!("apply args {error:?}")))?;
            return Err(exceptions::bif_error(
                p,
                "erlang",
                "apply",
                &[module_term, function_term, arguments],
                BifError::BADARG,
            ));
        }
        let module_term = p.x[arity];
        let function_term = p.x[arity + 1];
        let module_atom = module_term.as_atom();
        let function_atom = function_term.as_atom();
        let module_atom = module_atom.expect("checked apply module");
        let function_atom = function_atom.expect("checked apply function");
        let module =
            atom_name(Term::atom(module_atom)).ok_or_else(|| self.exception(p, "badarg"))?;
        let function =
            atom_name(Term::atom(function_atom)).ok_or_else(|| self.exception(p, "badarg"))?;
        if crate::trace::saves_calls(p) {
            crate::trace::save_call(
                p,
                crate::trace::SavedCall::Mfa(module_atom, function_atom, arity as u8),
            );
        }
        if module == "erlang" && function == "apply" && arity == 3 {
            // Port of erts/emulator/beam/beam_common.c:1445-1450 (apply), OTP-29.1.1.
            return self.apply_bif(p, 3, ctx);
        }
        // Port of erts/emulator/beam/jit/arm/instr_call.cpp (emit_i_apply_last, OTP-29.1.1):
        // the frame is deallocated before the callee runs, but a failure of the apply itself
        // (above) is raised at the apply instruction, in the caller.
        let began = p.begin_tail_apply(crate::proc_create::TAIL_APPLY);
        let result = self.call_named_atoms(
            p,
            module_atom,
            function_atom,
            &module,
            &function,
            arity,
            ctx,
        );
        p.end_tail_apply(began, &result);
        result
    }

    #[inline]
    // Port of erts/emulator/beam/beam_common.c:1350-1519 (apply and its BIF adjustment), OTP-29.1.1.
    pub(super) fn apply_bif(
        &mut self,
        p: &mut Process,
        arity: usize,
        ctx: Option<&mut RunCtx<'_, Message>>,
    ) -> Result<ImportOutcome, VmError> {
        let original_position = p.position_marker();
        let original_gc_live = p.gc_live;
        let original_operands = [p.x[0], p.x[1], p.x[2]];
        let (module_term, function_term, arguments_term, target) = if arity == 2 {
            (p.x[0], p.x[1], p.x[1], Some(p.x[0]))
        } else {
            let (module, function, arguments) = unwrap_nested_apply(p.x[0], p.x[1], p.x[2]);
            (module, function, arguments, None)
        };
        let named = if arity == 3 {
            match (module_term.as_atom(), function_term.as_atom()) {
                (Some(module), Some(function)) => Some((module, function)),
                _ => {
                    // Port of erts/emulator/beam/beam_common.c:1543-1550 (fixed_apply), OTP-29.1.1.
                    return Err(exceptions::bif_error(
                        p,
                        "erlang",
                        "apply",
                        &[module_term, function_term, arguments_term],
                        BifError::BADARG,
                    ));
                }
            }
        } else {
            None
        };
        let bif_args = if arity == 2 {
            vec![module_term, arguments_term]
        } else {
            vec![module_term, function_term, arguments_term]
        };
        let args = argument_list(arguments_term).map_err(|error| {
            exceptions::bif_error(
                p,
                "erlang",
                "apply",
                &bif_args,
                match error {
                    ArgumentError::Badarg => BifError::BADARG,
                    ArgumentError::SystemLimit => BifError::SystemLimit,
                },
            )
        })?;
        if args.len() >= crate::proc_create::ATTACHED_X_REGS {
            return Err(exceptions::bif_error(
                p,
                "erlang",
                "apply",
                &bif_args,
                BifError::SystemLimit,
            ));
        }
        p.x.ensure_x(args.len() + 1);
        p.x[..args.len()].copy_from_slice(&args);
        if named.is_some_and(|(module, function)| {
            global_atoms().text(module) == Some("erlang")
                && global_atoms().text(function) == Some("apply")
        }) && args.len() == 2
        {
            return self.apply_bif(p, 2, ctx);
        }
        // erts' `apply_bif_error_adjustment` pushes the apply site as the CP of a tail-applied
        // error/exit/throw. Under BeamAsm only the `i_apply_only` instruction passes that site
        // (`I`, with a zero stack offset); the native caller records it at its own call site,
        // and every other apply (through an export) passes NULL, which skips the adjustment.
        // Port of erts/emulator/beam/beam_common.c:1345-1427 (apply_bif_error_adjustment) and
        // erts/emulator/beam/jit/arm/instr_call.cpp (emit_variable_apply), OTP-29.1.1.
        // Re-executing this apply needs its own operands; keep them rooted while the callee runs.
        // The outermost apply (spawn's erlang:apply/2) stays on the process. Nested applies
        // spill into ProcessCold, which erts does not allocate for an empty fun.
        let inline = arity <= 3
            && p.apply_inline_len == 0
            && p.cold
                .as_ref()
                .is_none_or(|cold| cold.apply_roots.is_empty());
        let roots_base = if inline {
            p.apply_inline[..arity].copy_from_slice(&original_operands[..arity]);
            p.apply_inline_len = arity as u8;
            0
        } else {
            let cold = p.cold_mut();
            let base = cold.apply_roots.len();
            cold.apply_roots
                .extend_from_slice(&original_operands[..arity]);
            base
        };
        let began = arity == 3 && p.begin_tail_apply(crate::proc_create::TAIL_APPLY);
        let result = if let Some(fun) = target {
            self.call_fun_term(p, fun, args.len(), ctx)
        } else {
            let (module_atom, function_atom) = named.unwrap();
            let module = global_atoms()
                .text(module_atom)
                .ok_or_else(|| self.exception(p, "badarg"))?;
            let function = global_atoms()
                .text(function_atom)
                .ok_or_else(|| self.exception(p, "badarg"))?;
            self.call_named_atoms(
                p,
                module_atom,
                function_atom,
                module,
                function,
                args.len(),
                ctx,
            )
        };
        p.end_tail_apply(began, &result);
        let mut operand_buf = [Term::NIL; 3];
        let operand_len = if inline {
            operand_buf[..arity].copy_from_slice(&p.apply_inline[..arity]);
            p.apply_inline_len = 0;
            arity
        } else {
            let cold = p.cold_mut();
            let len = cold.apply_roots.len() - roots_base;
            operand_buf[..len].copy_from_slice(&cold.apply_roots[roots_base..]);
            cold.apply_roots.truncate(roots_base);
            len
        };
        let reexec_apply =
            matches!(&result, Ok(ImportOutcome::Yield)) && p.position_marker() == original_position;
        if matches!(&result, Err(VmError::Dirty(_))) || reexec_apply {
            // Only a yield that re-executes this apply may restore its argument registers; a yield after the
            // callee returned (reductions exhausted, ip advanced) must keep the result in x0.
            p.x[..operand_len].copy_from_slice(&operand_buf[..operand_len]);
            p.gc_live = original_gc_live;
        } else if result.is_ok() {
            // The deferred collector runs before the next instruction. A completed callee
            // has installed its result in X0, while later caller X registers may still
            // hold values used after apply/3 returns.
            p.gc_live = original_gc_live;
        }
        result
    }

    /// `erlang:make_fun/3` as a light BIF. A call that is not a plain `{Module, Function,
    /// Arity}` of atoms and a byte-sized arity is declined for the executor to raise.
    // Port of erts/emulator/beam/bif.c:4467 (make_fun_3), OTP-29.1.1.
    pub(crate) fn make_fun_light(
        process: &mut Process,
        args: &[Term],
    ) -> Option<Result<Term, exceptions::Trap>> {
        let [module, function, arity] = args else {
            return None;
        };
        let (module, function) = (module.as_atom()?, function.as_atom()?);
        let arity = u8::try_from(arity.as_small()?).ok()?;
        process.runtime?;
        let entry = crate::export::export_get_or_make_stub((module, function, arity))?;
        TermBuilder::new(&mut process.heap)
            .export_fun(entry)
            .ok()
            .map(Ok)
    }

    pub(super) fn make_export_fun(
        &mut self,
        p: &mut Process,
        args: &[Term],
    ) -> Result<Term, VmError> {
        let module = args[0]
            .as_atom()
            .ok_or_else(|| self.exception(p, "badarg"))?;
        let function = args[1]
            .as_atom()
            .ok_or_else(|| self.exception(p, "badarg"))?;
        let arity = args[2]
            .as_small()
            .filter(|n| (0..=255).contains(n))
            .ok_or_else(|| self.exception(p, "badarg"))? as u8;
        // Port of erts/emulator/beam/bif.c (erlang:make_fun/3: erts_export_get_or_make_stub,
        // the fun is the export's lambda), OTP-29.1.1.
        let entry = crate::export::export_get_or_make_stub((module, function, arity))
            .unwrap_or_else(|| Arc::new(ExportEntry::new(module, function, arity)));
        TermBuilder::new(&mut p.heap)
            .export_fun(entry)
            .map_err(|e| VmError::Unsupported(format!("export fun allocation {e:?}")))
    }

    // elixir_loop1: Port of erts/emulator/beam/erl_bif_info.c:4011
    // (fun_info_mfa_1), OTP-29.1.1.
    pub(super) fn fun_info_mfa(&self, p: &mut Process) -> Result<Term, VmError> {
        p.ensure(4, 1)?;
        // SAFETY: X0 retains the fun throughout this BIF; tuple construction cannot collect.
        let view = unsafe { p.x[0].fun_ref() }.ok_or_else(|| self.exception(p, "badarg"))?;
        let (module, name, arity) = match view {
            FunRef::Local { entry, .. } => {
                (entry.module, self.fun_function_name(entry), entry.arity)
            }
            FunRef::Export { entry } => (
                entry.module,
                atom_name(Term::atom(entry.function)),
                entry.arity,
            ),
        };
        let name = match name {
            Some(name) => Term::atom(
                global_atoms()
                    .intern(&name)
                    .map_err(|_| VmError::Unsupported("fun name atom".into()))?,
            ),
            None => Term::NIL,
        };
        TermBuilder::new(&mut p.heap)
            .tuple(&[
                Term::atom(module),
                name,
                Term::small(i64::from(arity)).unwrap(),
            ])
            .map_err(|error| VmError::Unsupported(format!("fun_info_mfa tuple: {error:?}")))
    }

    /// Function name of a local fun, or `None` for an unloaded or pending-purge fun.
    /// Port of erts/emulator/beam/erl_fun.c:37 (erts_get_fun_mfa), OTP-29.1.1.
    fn fun_function_name(&self, entry: &arinsal_term::FunEntry) -> Option<String> {
        let module = atom_name(Term::atom(entry.module))?;
        let (id, target) = [self.code.loaded.get(&module), self.code.old.get(&module)]
            .into_iter()
            .flatten()
            .find_map(|&id| {
                self.code.modules[id]
                    .funs
                    .iter()
                    .find(|slot| {
                        slot.entry.index == entry.index
                            && slot.entry.uniq == entry.uniq
                            && slot.entry.arity == entry.arity
                    })
                    .map(|slot| (id, slot.target))
            })?;
        if self.purge_state.pending(id) {
            return None;
        }
        self.code.modules[id]
            .function_at(target)
            .map(|(name, _)| name.to_owned())
    }

    pub(super) fn fun_info(&self, p: &mut Process, keyed: bool) -> Result<Term, VmError> {
        // Port of erts/emulator/beam/erl_bif_info.c:3912 (fun_info_2), OTP-29.1.1.
        p.ensure(1024, usize::from(keyed) + 1)?;
        let fun = p.x[0];
        // SAFETY: X0 retains the fun throughout construction; no collection follows.
        let view = unsafe { fun.fun_ref() }.ok_or_else(|| self.exception(p, "badarg"))?;
        let requested = if keyed {
            Some(atom_name(p.x[1]).ok_or_else(|| self.exception(p, "badarg"))?)
        } else {
            None
        };
        let keys: &[&str] = if let Some(ref key) = requested {
            &[key]
        } else if matches!(view, FunRef::Local { .. }) {
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
                (FunRef::Export { entry }, "module") => Term::atom(entry.module),
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
                (FunRef::Local { entry, .. }, "name") => {
                    if let Some(function) = self.fun_function_name(entry) {
                        Term::atom(
                            global_atoms()
                                .intern(&function)
                                .map_err(|_| VmError::Unsupported("fun name atom".into()))?,
                        )
                    } else {
                        Term::NIL
                    }
                }
                (FunRef::Export { entry }, "name") => Term::atom(entry.function),
                (FunRef::Local { entry, .. }, "arity") => {
                    Term::small(i64::from(entry.arity)).unwrap()
                }
                (FunRef::Export { entry }, "arity") => Term::small(i64::from(entry.arity)).unwrap(),
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
        if keyed {
            Ok(pairs[0])
        } else {
            builder
                .list_from_iter(pairs)
                .map_err(|e| VmError::Unsupported(format!("fun info list {e:?}")))
        }
    }
}

/// `{badfun, Fun}` for a fun whose code is no longer loaded.
fn badfun_reason(p: &mut Process, arity: usize) -> Result<Term, VmError> {
    p.ensure(3, arity + 1)?;
    let fun = p.x[arity];
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
        let mut vm = Vm::new([]);
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
