//! Local closures, export funs, and dynamic calls.

use crate::process::Message;
use crate::{EvalResult, ImportOutcome, Process, Vm, VmError, calls, exceptions};
use arinsal_bifs::{BifError, Ctx, FragmentingHeap};
use arinsal_loader::{Arg, ImportClass, Instr, Module};
use arinsal_sched::RunCtx;
use arinsal_term::{ExportEntry, FunRef, Term, TermBuilder, TermKind, global_atoms};
use std::sync::Arc;

pub(super) fn set_module_uniq(module: &mut Module, bytes: &[u8]) -> Result<(), VmError> {
    let uniq = arinsal_loader::module_uniq(bytes).map_err(|e| VmError::Load(e.to_string()))?;
    for slot in &mut module.funs {
        if let Some(entry) = Arc::get_mut(&mut slot.entry) {
            entry.uniq = uniq;
        }
    }
    Ok(())
}

#[inline]
pub(super) fn make_fun(
    p: &mut Process,
    module: &Module,
    index: u32,
    dst: Arg,
    env: u32,
    code_generation: u64,
) -> Result<(), VmError> {
    let slot = module
        .funs
        .iter()
        .find(|slot| slot.entry.old_index == index)
        .ok_or_else(|| VmError::Unsupported(format!("lambda index {index}")))?;
    let sources = module
        .lists
        .get(env as usize)
        .ok_or_else(|| VmError::Unsupported("lambda environment".into()))?;
    if sources.len() != slot.num_free {
        return Err(VmError::Unsupported("lambda environment size".into()));
    }
    // Port of erts/emulator/beam/emu/instrs.tab:545 (i_make_fun3), OTP-29.1.1.
    // This opcode allocates directly; its preceding test_heap is the safepoint.
    let free = sources
        .iter()
        .map(|&src| p.read(src))
        .collect::<Result<Vec<_>, _>>()?;
    let value = TermBuilder::new(&mut p.heap)
        .local_fun(Arc::clone(&slot.entry), &free)
        .map_err(|e| VmError::Unsupported(format!("fun allocation {e:?}")))?;
    slot.set_dispatch(0, p.module, module.code.as_ptr() as usize, code_generation);
    p.write(dst, value)
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

#[inline]
pub(super) fn is_function2(p: &Process, src: Arg, arity: Arg) -> Result<bool, VmError> {
    let fun = p.read(src)?;
    let requested = if arity.kind() == Arg::U {
        i64::try_from(arity.value()).ok()
    } else {
        p.read(arity)?.as_small()
    };
    if !(Some(0)..=Some(255)).contains(&requested) {
        return Ok(false);
    }
    // SAFETY: The source term remains live in this process or a module literal heap.
    Ok(match unsafe { fun.fun_ref() } {
        Some(FunRef::Local { entry, .. }) => Some(i64::from(entry.arity)) == requested,
        Some(FunRef::Export { entry }) => Some(i64::from(entry.arity)) == requested,
        None => false,
    })
}

fn error_handler_module(process: &Process) -> String {
    process
        .cold
        .as_ref()
        .and_then(|cold| cold.flags.get("error_handler"))
        .and_then(|term| atom_name(*term))
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

// Port of erts/emulator/beam/beam_common.c:1345-1427 (apply_bif_error_adjustment), OTP-29.1.1.
fn push_apply_error_continuation(
    p: &mut Process,
    return_ip: usize,
    stack_offset: usize,
) -> Result<(), VmError> {
    let offset = stack_offset.max(1);
    if !p.heap.reserve_stack(offset + 1) {
        return Err(VmError::Unsupported("apply continuation stack".into()));
    }
    for index in 0..=offset {
        p.heap.stack_set(index, Term::NIL);
    }
    let module = u32::try_from(p.module)
        .map_err(|_| VmError::Unsupported("apply continuation module".into()))?;
    let ip = u32::try_from(return_ip)
        .map_err(|_| VmError::Unsupported("apply continuation ip".into()))?;
    p.heap.stack_set(
        offset,
        Term::catch((u64::from(module) << 32) | u64::from(ip)),
    );
    Ok(())
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
                let module_id = match self.load_named("erlang") {
                    Ok(id) => id,
                    Err(error) => return Some(Err(error)),
                };
                p.module = module_id;
                p.ip = self.code.modules[module_id]
                    .export(function, arity as u8)
                    .unwrap_or(0);
                p.x[..arity].copy_from_slice(args);
                p.gc_live = arity;
                let value = match function {
                    "apply" => match self.apply_bif(&mut p, arity, true, 0, None) {
                        Ok(ImportOutcome::Returned(value)) => Ok(value),
                        Ok(ImportOutcome::Jump(_))
                        | Ok(ImportOutcome::Advanced)
                        | Ok(ImportOutcome::Yield) => self.run(&mut p),
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

    pub(super) fn intercept_fun_import(
        &mut self,
        p: &mut Process,
        index: usize,
        arity: usize,
        tail: bool,
        ctx: Option<&mut RunCtx<'_, Message>>,
    ) -> Result<Option<ImportOutcome>, VmError> {
        let import = self.code.modules[p.module]
            .imports
            .get(index)
            .ok_or_else(|| VmError::Unsupported(format!("import {index}")))?;
        if import.module != "erlang" {
            return Ok(None);
        }
        let function = import.function.as_str();
        if function == "apply" && (arity == 2 || arity == 3) {
            return self.apply_bif(p, arity, tail, 0, ctx).map(Some);
        }
        let value = if function == "make_fun" && arity == 3 {
            let args = [p.x[0], p.x[1], p.x[2]];
            self.make_export_fun(p, &args)?
        } else if function == "fun_info" && (arity == 1 || arity == 2) {
            self.fun_info(p, arity == 2)?
        } else if function == "fun_info_mfa" && arity == 1 {
            self.fun_info_mfa(p)? // elixir_loop1
        } else {
            return Ok(None);
        };
        p.x[0] = value;
        if tail {
            return Ok(Some(match Self::ret(p) {
                Some(value) => ImportOutcome::Returned(value),
                None => ImportOutcome::Advanced,
            }));
        }
        p.ip += 1;
        Ok(Some(ImportOutcome::Advanced))
    }

    // Port of erts/emulator/beam/beam_common.c:1605 (call_fun), OTP-29.1.1.
    #[inline]
    pub(super) fn call_fun_term(
        &mut self,
        p: &mut Process,
        fun: Term,
        arity: usize,
        tail: bool,
        ctx: Option<&mut RunCtx<'_, Message>>,
    ) -> Result<ImportOutcome, VmError> {
        if arity >= p.x.len() {
            return Err(VmError::Unsupported("fun arity exceeds X registers".into()));
        }
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
                let cached = entry
                    .get_dispatch(0)
                    .and_then(|(id, target, code, generation)| {
                        if generation == self.code_generation() {
                            return Some((id, target, code));
                        }
                        let module = self.code.modules.get(id)?;
                        (self.code.module_live.get(id) == Some(&true)
                            && module.code.as_ptr() as usize == code)
                            .then_some((id, target, code))
                    });
                let resolved = match cached {
                    Some(cached) if !self.purge_state.pending(cached.0) => Some(cached),
                    // A cached target in code pending purge is re-resolved: the fun
                    // entry may also exist in the current instance, where erts
                    // already dispatches it.
                    _ => self.resolve_local_fun(p, entry, arity)?,
                };
                let Some((module_id, target, code)) = resolved else {
                    return self.call_lambda_handler(p, entry.module, arity, tail, false, ctx);
                };
                if self.purge_state.pending(module_id) {
                    return self.call_lambda_handler(p, entry.module, arity, tail, true, ctx);
                }
                // The caller module's register file is sized from its own beam.
                // A closure passes its environment in `x[arity..]`, which can sit
                // past that size (elixir_erl_compiler's spawn fun). OTP grows the
                // process X array; shrinking never happens, so the callee keeps it.
                let need = arity + free_vars.len();
                if need > 1024 {
                    return Err(VmError::Unsupported(
                        "closure environment exceeds X registers".into(),
                    ));
                }
                if need > p.x.len() {
                    let mut registers = p.x.to_vec();
                    registers.resize(need, Term::NIL);
                    p.x = registers.into();
                }
                for (i, &word) in free_vars.iter().enumerate() {
                    // SAFETY: The fun header bounds the environment and every word is a term.
                    p.x[arity + i] = unsafe { std::mem::transmute::<u64, Term>(word) };
                }
                p.gc_live = arity + free_vars.len();
                if !tail {
                    calls::push_continuation(p, p.module, p.ip + 1, p.gc_live)?;
                }
                p.module = module_id;
                p.ip = target;
                p.tick();
                Ok(ImportOutcome::Jump(
                    (code as *const Instr).wrapping_add(target),
                ))
            }
            FunRef::Export { entry } => {
                let module = atom_name(Term::atom(entry.module))
                    .ok_or_else(|| VmError::Unsupported("export module atom".into()))?;
                let function = atom_name(Term::atom(entry.function))
                    .ok_or_else(|| VmError::Unsupported("export function atom".into()))?;
                if module == "erlang" && function == "apply" && matches!(arity, 2 | 3) {
                    return self.apply_bif(p, arity, tail, 0, ctx);
                }
                self.call_named_atoms(
                    p,
                    entry.module,
                    entry.function,
                    &module,
                    &function,
                    arity,
                    tail,
                    ctx,
                )
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
        tail: bool,
        pending_purge: bool,
        ctx: Option<&mut RunCtx<'_, Message>>,
    ) -> Result<ImportOutcome, VmError> {
        let (handler, function) = if pending_purge {
            let name = atom_name(Term::atom(module))
                .ok_or_else(|| VmError::Unsupported("lambda module atom".into()))?;
            // Port of erts/emulator/beam/beam_bif_load.c:1977
            // (erts_suspend_process_on_pending_purge_lambda), OTP-29.1.1.
            if let (Some(runtime), Some(pid)) = (p.runtime.clone(), p.self_pid)
                && self.purge_state.suspend_on_pending_lambda(&name, pid)
            {
                runtime.suspend_internal(pid);
                // ERTS_VBUMP_ALL_REDS: leave the scheduler at the next instruction.
                p.force_yield = true;
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
        if p.x.len() < 4 {
            return Err(VmError::Unsupported("lambda handler registers".into()));
        }
        p.x[0] = Term::atom(module);
        p.x[1] = fun;
        p.x[2] = list;
        p.x[3] = Term::NIL;
        self.call_named(p, &handler, function, 3, tail, ctx)
    }

    #[cold]
    fn resolve_local_fun(
        &mut self,
        p: &mut Process,
        entry: &arinsal_term::FunEntry,
        arity: usize,
    ) -> Result<Option<(usize, usize, usize)>, VmError> {
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
                            && slot.entry.old_uniq == entry.old_uniq
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
        entry.set_dispatch(
            0,
            module_id,
            target,
            self.code.modules[module_id].code.as_ptr() as usize,
            self.code_generation(),
        );
        Ok(Some((
            module_id,
            target,
            self.code.modules[module_id].code.as_ptr() as usize,
        )))
    }

    #[inline]
    pub(super) fn call_named(
        &mut self,
        p: &mut Process,
        module: &str,
        function: &str,
        arity: usize,
        tail: bool,
        ctx: Option<&mut RunCtx<'_, Message>>,
    ) -> Result<ImportOutcome, VmError> {
        self.call_named_resolved(p, None, module, function, arity, tail, ctx)
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
        tail: bool,
        ctx: Option<&mut RunCtx<'_, Message>>,
    ) -> Result<ImportOutcome, VmError> {
        self.call_named_resolved(
            p,
            Some((module_atom, function_atom)),
            module,
            function,
            arity,
            tail,
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
        tail: bool,
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
                let site = (usize::MAX - 1, p.ip);
                self.trace_native_call_named(
                    p,
                    run,
                    module,
                    function,
                    arity,
                    site,
                    if tail {
                        crate::trace::StackScan::AfterFrame
                    } else {
                        crate::trace::StackScan::None
                    },
                )
            }
            _ => None,
        };
        let result =
            self.call_named_untraced(p, atoms, module, function, arity, tail, ctx.as_deref_mut());
        let (Some((module, function, args)), Some(run)) = (traced, ctx) else {
            return result;
        };
        match result {
            Ok(outcome) => {
                let value = match &outcome {
                    ImportOutcome::Returned(value) => Some(*value),
                    ImportOutcome::Advanced => Some(p.x[0]),
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
                failed.map(|_| ImportOutcome::Advanced)
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
        tail: bool,
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
                    p.x[0] = result?;
                    if tail {
                        return Ok(match Self::ret(p) {
                            Some(value) => ImportOutcome::Returned(value),
                            None => crate::calls::after_dirty(ImportOutcome::Advanced),
                        });
                    }
                    p.ip += 1;
                    return Ok(crate::calls::after_dirty(ImportOutcome::Advanced));
                }
            }
        }
        // Trapping BIFs must be intercepted before native dispatch: dynamic
        // apply may otherwise enter a synchronous fast path for the same MFA.
        // A trap through `apply` is keyed by the caller's import when it has one, so a
        // static call and its apply re-execution resume the same continuation.
        let trap_key = self.code.modules[p.module]
            .imports
            .iter()
            .position(|import| {
                import.module == module
                    && import.function == function
                    && usize::from(import.arity) == arity
            })
            .unwrap_or(crate::bif_traps::APPLY_TRAP_KEY);
        let trap_args = [
            p.x.first().copied().unwrap_or(Term::NIL),
            p.x.get(1).copied().unwrap_or(Term::NIL),
            p.x.get(2).copied().unwrap_or(Term::NIL),
        ];
        if let Some(result) = crate::bif_traps::execute_named(
            p,
            module,
            function,
            trap_key,
            arity,
            trap_args,
            ctx.as_deref_mut(),
        ) {
            return match result? {
                crate::bif_traps::TrapResult::Done { value, .. } => {
                    p.x[0] = value;
                    p.collect_bin_vheap_if_due(1)?;
                    if tail {
                        Ok(match Self::ret(p) {
                            Some(value) => ImportOutcome::Returned(value),
                            None => ImportOutcome::Advanced,
                        })
                    } else {
                        p.ip += 1;
                        Ok(ImportOutcome::Advanced)
                    }
                }
                crate::bif_traps::TrapResult::Failed { .. } => {
                    unreachable!("failed trapping BIFs become VM exceptions")
                }
                crate::bif_traps::TrapResult::Yield { .. } => Ok(ImportOutcome::Yield),
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
                (ImportClass::Dynamic, 0),
            )
        {
            p.x[0] = result?;
            if tail {
                return Ok(match Self::ret(p) {
                    Some(value) => ImportOutcome::Returned(value),
                    None => crate::calls::after_dirty(ImportOutcome::Advanced),
                });
            }
            p.ip += 1;
            return Ok(crate::calls::after_dirty(ImportOutcome::Advanced));
        }
        // elixir_loop1: apply/3 reaches this path without an import slot.
        // sys_core_fold:fold_lit_args/4 applies erlang:make_fun/3 the same way.
        if module == "erlang" && function == "make_fun" && arity == 3 {
            let args = [p.x[0], p.x[1], p.x[2]];
            p.x[0] = self.make_export_fun(p, &args)?;
            if tail {
                return Ok(match Self::ret(p) {
                    Some(value) => ImportOutcome::Returned(value),
                    None => ImportOutcome::Advanced,
                });
            }
            p.ip += 1;
            return Ok(ImportOutcome::Advanced);
        }
        if module == "erlang" && function == "fun_info" && (arity == 1 || arity == 2) {
            p.x[0] = self.fun_info(p, arity == 2)?;
            if tail {
                return Ok(match Self::ret(p) {
                    Some(value) => ImportOutcome::Returned(value),
                    None => ImportOutcome::Advanced,
                });
            }
            p.ip += 1;
            return Ok(ImportOutcome::Advanced);
        }
        if module == "erlang" && function == "fun_info_mfa" && arity == 1 {
            p.x[0] = self.fun_info_mfa(p)?;
            if tail {
                return Ok(match Self::ret(p) {
                    Some(value) => ImportOutcome::Returned(value),
                    None => ImportOutcome::Advanced,
                });
            }
            p.ip += 1;
            return Ok(ImportOutcome::Advanced);
        }
        // elixir_loop1: dynamic apply must see static NIFs such as re:import/1.
        if let Some(bif) = arinsal_bifs::lookup(module, function, arity as u8)
            .or_else(|| crate::natives::static_nif_lookup(module, function, arity as u8))
        {
            let (result, bif_reductions) = {
                let mut heap = FragmentingHeap(&mut p.heap);
                let mut bif_ctx = Ctx::new(&mut heap);
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    bif(&mut bif_ctx, &p.x[..arity])
                }))
                .map_err(|_| {
                    VmError::Unsupported(format!("BIF {module}:{function}/{arity} panicked"))
                })?;
                (result, bif_ctx.reductions())
            };
            let bif_args = p.x[..arity].to_vec();
            let result = result.map_err(|error| match error {
                BifError::Unsupported(reason) => VmError::Unsupported(reason.into()),
                error => exceptions::bif_error(p, module, function, &bif_args, error),
            })?;
            p.x[0] = result;
            let charge = bif_reductions.saturating_add(1);
            p.reductions_used = p.reductions_used.saturating_add(u64::from(bif_reductions));
            p.reductions = p
                .reductions
                .saturating_sub(charge.min(i32::MAX as u32) as i32);
            let exhausted = ctx.as_deref_mut().is_some_and(|run| !run.consume(charge));
            if tail {
                return Ok(match Self::ret(p) {
                    Some(value) => ImportOutcome::Returned(value),
                    None => ImportOutcome::Advanced,
                });
            }
            p.ip += 1;
            if exhausted {
                p.reductions = 4000;
                return Ok(ImportOutcome::Yield);
            }
            return Ok(ImportOutcome::Advanced);
        }
        if arinsal_spec::bif_lookup(module, function, arity as u8).is_some() {
            return Err(VmError::Unsupported(format!(
                "BIF {module}:{function}/{arity}"
            )));
        }
        // Same as `call_import`: a not-yet-loaded `-on_load` module has to go
        // through `code_server` or its NIF stubs run.
        if self.unloaded_on_load(p, module) {
            return self.call_undefined_function_with_ctx(p, module, function, arity, tail, ctx);
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
                return self
                    .call_undefined_function_with_ctx(p, module, function, arity, tail, ctx);
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
                return self
                    .call_undefined_function_with_ctx(p, module, function, arity, tail, ctx);
            }
            return Err(VmError::Exception {
                reason: "undef".into(),
                frame: format!("{module}:{function}/{arity}"),
            });
        };
        if !tail {
            calls::push_continuation(p, p.module, p.ip + 1, arity)?;
        }
        p.module = module_id;
        p.ip = target;
        p.tick();
        Ok(ImportOutcome::Jump(
            self.code.modules[module_id]
                .code
                .as_ptr()
                .wrapping_add(target),
        ))
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
        tail: bool,
    ) -> Result<ImportOutcome, VmError> {
        self.call_undefined_function_with_ctx(p, module, function, arity, tail, None)
    }

    fn call_undefined_function_with_ctx(
        &mut self,
        p: &mut Process,
        module: &str,
        function: &str,
        arity: usize,
        tail: bool,
        ctx: Option<&mut RunCtx<'_, Message>>,
    ) -> Result<ImportOutcome, VmError> {
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
        // `process_flag(error_handler, Module)` replaces the module the
        // emulator calls. Elixir's compiler sets `Kernel.ErrorHandler`, which
        // waits on `Kernel.ParallelCompiler` before the default handler runs.
        // An unloaded handler raises `undef` for the original call; OTP does
        // not autoload the handler. Port of erts/emulator/beam/beam_common.c
        // (`call_error_handler`), OTP-29.1.1.
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
        self.call_named(p, &handler, "undefined_function", 3, tail, ctx)
    }

    #[inline]
    pub(super) fn apply_fixed(
        &mut self,
        p: &mut Process,
        arity: usize,
        tail: bool,
        dealloc: usize,
        ctx: Option<&mut RunCtx<'_, Message>>,
    ) -> Result<ImportOutcome, VmError> {
        if arity + 1 >= p.x.len() {
            return Err(self.exception(p, "system_limit"));
        }
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
            return self.apply_bif(p, 3, tail, dealloc, ctx);
        }
        self.call_named_atoms(
            p,
            module_atom,
            function_atom,
            &module,
            &function,
            arity,
            tail,
            ctx,
        )
    }

    #[inline]
    // Port of erts/emulator/beam/beam_common.c:1350-1519 (apply and its BIF adjustment), OTP-29.1.1.
    pub(super) fn apply_bif(
        &mut self,
        p: &mut Process,
        arity: usize,
        tail: bool,
        tail_dealloc: usize,
        ctx: Option<&mut RunCtx<'_, Message>>,
    ) -> Result<ImportOutcome, VmError> {
        let original_ip = p.ip;
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
        // The register file is sized for the running module; the callee may take more
        // arguments (up to erts MAX_ARG), so grow it before the copy.
        if args.len() <= 255 && args.len() >= p.x.len() {
            let mut registers = p.x.to_vec();
            registers.resize(args.len() + 1, Term::NIL);
            p.x = registers.into();
        }
        if args.len() >= p.x.len() {
            return Err(exceptions::bif_error(
                p,
                "erlang",
                "apply",
                &bif_args,
                BifError::SystemLimit,
            ));
        }
        p.x[..args.len()].copy_from_slice(&args);
        if named.is_some_and(|(module, function)| {
            global_atoms().text(module) == Some("erlang")
                && global_atoms().text(function) == Some("apply")
        }) && args.len() == 2
        {
            return self.apply_bif(p, 2, tail, tail_dealloc, ctx);
        }
        let tail_applies_exception_bif = named.is_some_and(|(module, function)| {
            global_atoms().text(module) == Some("erlang")
                && global_atoms()
                    .text(function)
                    .is_some_and(|name| matches!(name, "error" | "exit" | "throw"))
        });
        // A native caller's frame comes from its recorded call site instead.
        let native_caller = p.cold.as_ref().is_some_and(|cold| cold.native_apply);
        if tail && tail_applies_exception_bif && !native_caller {
            // Port of erts/emulator/beam/beam_common.c:1350-1427 (apply_bif_error_adjustment), OTP-29.1.1.
            let return_ip =
                p.ip.checked_add(1)
                    .ok_or_else(|| VmError::Unsupported("apply continuation".into()))?;
            // `apply_last` has already deallocated its frame. ERTS restores
            // the complete stack offset before letting the error BIF unwind.
            push_apply_error_continuation(p, return_ip, tail_dealloc)?;
        }
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
        let result = if let Some(fun) = target {
            self.call_fun_term(p, fun, args.len(), tail, ctx)
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
                tail,
                ctx,
            )
        };
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
        let reexec_apply = matches!(&result, Ok(ImportOutcome::Yield)) && p.ip == original_ip;
        if matches!(
            &result,
            Err(VmError::Unsupported(message)) if crate::signals::is_await_message(message)
        ) || matches!(&result, Err(VmError::Dirty(_)))
            || reexec_apply
        {
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
        p.ensure(2, 3)?;
        // Port of erts/emulator/beam/bif.c (erlang:make_fun/3: erts_export_get_or_make_stub,
        // the fun is the export's lambda), OTP-29.1.1.
        let entry = crate::beamasm_integration::export_get_or_make_stub(
            self.code_scope,
            (module, function, arity),
        )
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
                            && slot.entry.old_uniq == entry.old_uniq
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
    fn function_arity_instruction_accepts_unsigned_immediate() {
        let mut p = Process::new();
        let module = global_atoms().intern("erlang").unwrap();
        let function = global_atoms().intern("abs").unwrap();
        p.x[0] = TermBuilder::new(&mut p.heap)
            .export_fun(Arc::new(ExportEntry::new(module, function, 1)))
            .unwrap();
        let fun = Arg::new(Arg::X, 0);
        assert!(is_function2(&p, fun, Arg::new(Arg::U, 1)).unwrap());
        assert!(!is_function2(&p, fun, Arg::new(Arg::U, 2)).unwrap());
    }

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
            .eval_scheduled("vm_make_fun_gc_stress", "run", &args, 1, None)
            .unwrap();
        let arinsal_etf::OwnedTerm::Tuple(items) = &result.term else {
            panic!("expected {{17, 29, Fun}}, got {:?}", result.term);
        };
        assert_eq!(items[0], arinsal_etf::OwnedTerm::Int(17));
        assert_eq!(items[1], arinsal_etf::OwnedTerm::Int(29));
    }
}
