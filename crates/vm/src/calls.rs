//! Continuations and Y frames on the process stack.

use crate::{Process, VmError};
use arinsal_term::{Term, TermKind};
use std::sync::LazyLock;

enum BifErrorRoots {
    BadargCause(usize),
    Reason(usize),
    Raise(usize, Option<usize>),
}

enum NativeErrorRoots {
    Trap {
        reason: usize,
        trace: Option<usize>,
        top: Option<NativeTopRoots>,
    },
}

enum NativeTopRoots {
    BifArgs { start: usize, len: usize },
    CurrentArgs(usize),
}

static TRACE_BOOT_ENABLED: LazyLock<bool> =
    LazyLock::new(|| std::env::var_os("ARINSAL_TRACE_BOOT").is_some());

pub(crate) fn trace_boot_enabled() -> bool {
    *TRACE_BOOT_ENABLED
}

/// Push a tagged continuation. The collector treats the CATCH immediate as a
/// non-pointer, so code offsets survive a moving collection unchanged.
#[inline]
pub(super) fn push_continuation(
    p: &mut Process,
    module: usize,
    ip: usize,
    arity: usize,
) -> Result<(), VmError> {
    let module = u64::try_from(module).map_err(|_| VmError::Unsupported("module index".into()))?;
    let ip = u32::try_from(ip).map_err(|_| VmError::Unsupported("code index".into()))?;
    if module >= 1 << 26 {
        return Err(VmError::Unsupported("module index".into()));
    }
    // Port of erts/emulator/beam/emu/macros.tab:85 (GC_TEST) and
    // erts/emulator/beam/erl_gc.c:2639 (setup_rootset), OTP-29.1.1.
    // `nobj` is the callee arity. Registers above that prefix are not roots
    // and are not rewritten.
    p.ensure_roots(1, arity, false)?;
    if !p.heap.reserve_stack(1) {
        return Err(VmError::Unsupported("continuation stack".into()));
    }
    let cp = crate::stacktrace::continuation_tag(module as usize, ip as usize)?;
    p.heap.stack_set(0, cp);
    Ok(())
}

/// Invoke a resolved pure BIF or static NIF without allocating.
///
/// `args` views the caller's X registers. The same entry is
/// [`arinsal_loader::call_bif`], which the JIT can call without a VM borrow.
#[inline(always)]
pub fn call_bif(
    heap: &mut arinsal_term::ProcessHeap,
    target: arinsal_bifs::BifFn,
    args: &[arinsal_term::Term],
) -> Result<arinsal_term::Term, arinsal_bifs::BifError> {
    let mut fragment = arinsal_bifs::FragmentingHeap(heap);
    arinsal_loader::call_bif(&mut fragment, target, args)
}

/// Invoke a BIF and return its reported work for scheduler accounting.
pub(crate) fn call_bif_metered(
    heap: &mut arinsal_term::ProcessHeap,
    target: arinsal_bifs::BifFn,
    args: &[arinsal_term::Term],
) -> (Result<arinsal_term::Term, arinsal_bifs::BifError>, u32) {
    let mut fragment = arinsal_bifs::FragmentingHeap(heap);
    let mut ctx = arinsal_bifs::Ctx::new(&mut fragment);
    let result = target(&mut ctx, args);
    (result, ctx.reductions())
}

/// Collect after a BIF when message-buffer fragments occupy more space than
/// the process can keep free on its heap.
// Port of erts/emulator/beam/erl_gc.c:418-478 (erts_gc_after_bif_call_lhf), OTP-29.1.1.
pub(super) fn gc_after_bif(
    process: &mut Process,
    arguments: &mut [Term],
    result: &mut Result<Term, arinsal_bifs::BifError>,
) -> Result<(), VmError> {
    if !process.gc_enabled || !process.heap.gc_desired() {
        return Ok(());
    }
    let mut roots = arguments.to_vec();
    let result_index = if let Ok(value) = result {
        roots.push(*value);
        (Some(roots.len() - 1), None)
    } else if let Err(error) = result {
        let error_roots = match error {
            arinsal_bifs::BifError::Badarg { cause: Some(cause) } => {
                let index = roots.len();
                roots.push(*cause);
                Some(BifErrorRoots::BadargCause(index))
            }
            arinsal_bifs::BifError::Error(reason) => {
                let index = roots.len();
                roots.push(*reason);
                Some(BifErrorRoots::Reason(index))
            }
            arinsal_bifs::BifError::Raise {
                reason, stacktrace, ..
            } => {
                let reason_index = roots.len();
                roots.push(*reason);
                let trace_index = stacktrace.map(|trace| {
                    roots.push(trace);
                    roots.len() - 1
                });
                Some(BifErrorRoots::Raise(reason_index, trace_index))
            }
            _ => None,
        };
        (None, error_roots)
    } else {
        (None, None)
    };
    process.collect_heap_roots(arguments.len(), &mut roots, 0)?;
    arguments.copy_from_slice(&roots[..arguments.len()]);
    if let Some(index) = result_index.0 {
        if let Ok(value) = result {
            *value = roots[index];
        }
    } else if let Some(error_roots) = result_index.1
        && let Err(error) = result
    {
        match (error_roots, error) {
            (BifErrorRoots::BadargCause(index), arinsal_bifs::BifError::Badarg { cause }) => {
                *cause = Some(roots[index]);
            }
            (BifErrorRoots::Reason(index), arinsal_bifs::BifError::Error(reason)) => {
                *reason = roots[index];
            }
            (
                BifErrorRoots::Raise(reason_index, trace_index),
                arinsal_bifs::BifError::Raise {
                    reason, stacktrace, ..
                },
            ) => {
                *reason = roots[reason_index];
                *stacktrace = trace_index.map(|index| roots[index]);
            }
            _ => unreachable!("the error variant is stable across collection"),
        }
    }
    Ok(())
}

/// Apply the native BIF epilogue with the process argument registers as roots.
// Port of erts/emulator/beam/erl_gc.c:418-478 (erts_gc_after_bif_call_lhf), OTP-29.1.1.
pub(super) fn gc_after_native(
    process: &mut Process,
    arguments: &mut [Term],
    result: &mut Result<Term, VmError>,
) -> Result<(), VmError> {
    if !process.gc_enabled || !process.heap.gc_desired() {
        return Ok(());
    }
    let mut roots = arguments.to_vec();
    let result_index = if let Ok(value) = result {
        roots.push(*value);
        (Some(roots.len() - 1), None)
    } else if let Err(VmError::Trap(trap)) = result {
        let reason = roots.len();
        roots.push(trap.reason);
        let trace = trap.trace.map(|value| {
            roots.push(value);
            roots.len() - 1
        });
        let top = trap.top.as_ref().and_then(|top| match top {
            crate::stacktrace::TopFrame::Bif { args, .. } => args
                .root_terms(&mut roots)
                .map(|(start, len)| NativeTopRoots::BifArgs { start, len }),
            crate::stacktrace::TopFrame::CurrentArgs(args) => {
                roots.push(*args);
                Some(NativeTopRoots::CurrentArgs(roots.len() - 1))
            }
            crate::stacktrace::TopFrame::CurrentArgsWithInfo(Some(args), _) => {
                roots.push(*args);
                Some(NativeTopRoots::CurrentArgs(roots.len() - 1))
            }
            crate::stacktrace::TopFrame::CurrentArgsWithInfo(None, _) => None,
        });
        (None, Some(NativeErrorRoots::Trap { reason, trace, top }))
    } else {
        (None, None)
    };
    process.collect_heap_roots(arguments.len(), &mut roots, 0)?;
    arguments.copy_from_slice(&roots[..arguments.len()]);
    if let Some(index) = result_index.0 {
        if let Ok(value) = result {
            *value = roots[index];
        }
    } else if let Some(NativeErrorRoots::Trap { reason, trace, top }) = result_index.1
        && let Err(VmError::Trap(trap)) = result
    {
        trap.reason = roots[reason];
        trap.trace = trace.map(|index| roots[index]);
        if let Some(top_roots) = top {
            match trap.top.as_mut() {
                Some(crate::stacktrace::TopFrame::Bif { args, .. }) => {
                    if let NativeTopRoots::BifArgs { start, len } = top_roots {
                        args.update_root_terms(&roots, start, len);
                    }
                }
                Some(crate::stacktrace::TopFrame::CurrentArgs(args))
                    if let NativeTopRoots::CurrentArgs(index) = top_roots =>
                {
                    *args = roots[index]
                }
                Some(crate::stacktrace::TopFrame::CurrentArgsWithInfo(Some(args), _))
                    if let NativeTopRoots::CurrentArgs(index) = top_roots =>
                {
                    *args = roots[index]
                }
                _ => unreachable!("trapped top-frame metadata remains stable across GC"),
            }
        }
    }
    Ok(())
}

/// [`call_bif`] with the panic landing the interpreter already used.
pub(super) fn call_bif_catch(
    heap: &mut arinsal_term::ProcessHeap,
    target: arinsal_bifs::BifFn,
    args: &[arinsal_term::Term],
) -> Result<Result<arinsal_term::Term, arinsal_bifs::BifError>, ()> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        call_bif(heap, target, args)
    }))
    .map_err(|_| ())
}

/// Pop a continuation after the callee deallocated its Y slots.
#[inline]
pub(super) fn return_to(p: &mut Process) -> Option<Term> {
    let Some(cp) = p.heap.stack_get(0) else {
        return Some(p.x[0]);
    };
    if cp.classify() != TermKind::Catch {
        return Some(p.x[0]);
    }
    let Some((false, module, ip)) = crate::stacktrace::decode_tag(cp) else {
        return Some(p.x[0]);
    };
    p.module = module;
    p.ip = ip;
    p.heap.release_stack(1);
    None
}

pub(crate) enum ImportOutcome {
    Returned(Term),
    Advanced,
    Jump(*const Instr),
    Yield,
}

// VM calls implementation.

use super::*;

impl Vm {
    /// Run a pure BIF, emitting call and return trace events when a pattern selects it.
    // Port of erts/emulator/beam/emu/bif_instrs.tab (call_light_bif with Export.is_bif_traced)
    // and erts/emulator/beam/beam_bp.c:321-330 (erts_export_is_bif_traced), OTP-29.1.1.
    pub(crate) fn call_bif_traced(
        &mut self,
        p: &mut Process,
        ctx: Option<&mut arinsal_sched::RunCtx<'_, process::Message>>,
        module_id: usize,
        import: usize,
        bif: arinsal_bifs::BifFn,
        arity: usize,
    ) -> (Result<Term, arinsal_bifs::BifError>, u32) {
        let untraced = |p: &mut Process| calls::call_bif_metered(&mut p.heap, bif, &p.x[..arity]);
        if !crate::trace_bp::any_pattern() {
            return untraced(p);
        }
        let Some(entry) = self
            .modules
            .get(module_id)
            .and_then(|module| module.imports.get(import))
        else {
            return untraced(p);
        };
        let (module, function) = (entry.module.clone(), entry.function.clone());
        let Some(ctx) = ctx else {
            return untraced(p);
        };
        self.call_bif_traced_named(p, ctx, &module, &function, bif, arity)
    }

    /// Call a BIF by name, emitting call and return events when a pattern selects it.
    pub(crate) fn call_bif_traced_named(
        &mut self,
        p: &mut Process,
        ctx: &mut arinsal_sched::RunCtx<'_, process::Message>,
        module: &str,
        function: &str,
        bif: arinsal_bifs::BifFn,
        arity: usize,
    ) -> (Result<Term, arinsal_bifs::BifError>, u32) {
        let untraced = |p: &mut Process| calls::call_bif_metered(&mut p.heap, bif, &p.x[..arity]);
        if !crate::trace_bp::any_pattern()
            || !crate::trace_bp::selects(module, function, arity as u8)
        {
            return untraced(p);
        }
        let (module, function) = (module.to_owned(), function.to_owned());
        let args = p.x[..arity].to_vec();
        // A native import that missed (dynamic natives) already emitted the call event.
        let mut site = None;
        let actions = match p
            .cold
            .as_mut()
            .and_then(|cold| cold.traced_native_call.take())
        {
            Some((site_module, site_ip, actions)) => {
                site = Some((site_module, site_ip));
                actions
            }
            None => crate::trace::bif_call_event(
                self,
                p,
                ctx,
                &module,
                &function,
                &args,
                crate::trace::StackScan::None,
            )
            .unwrap_or_default(),
        };
        let (result, reductions) = untraced(p);
        let outcome = match result {
            Ok(value) => Some(Ok(value)),
            Err(error) => match exceptions::bif_error(p, &module, &function, &args, error) {
                VmError::Trap(trap) => exceptions::trace_class_reason(p, trap.class, trap.reason)
                    .ok()
                    .map(Err),
                _ => None,
            },
        };
        if let Some(outcome) = outcome {
            let _ = crate::trace::bif_return_events(
                self,
                p,
                ctx,
                &actions,
                &module,
                &function,
                arity as u8,
                outcome,
                site,
            );
        }
        (result, reductions)
    }
    /// Emit the call event of a traced native BIF once per call, even when the BIF yields
    /// and its instruction runs again.
    // Port of erts/emulator/beam/beam_bp.c:321-330 (erts_export_is_bif_traced) and
    // erts/emulator/beam/erl_trace.c:1159-1260 (erts_call_trace), OTP-29.1.1.
    fn trace_native_call(
        &mut self,
        p: &mut Process,
        ctx: &mut arinsal_sched::RunCtx<'_, process::Message>,
        caller_module: usize,
        caller_ip: usize,
        import: usize,
        arity: usize,
    ) -> Option<(String, String, Vec<Term>)> {
        if !crate::trace_bp::any_pattern() {
            return None;
        }
        let entry = self.modules.get(caller_module)?.imports.get(import)?;
        let (module, function) = (entry.module.clone(), entry.function.clone());
        self.trace_native_call_named(
            p,
            ctx,
            &module,
            &function,
            arity,
            (caller_module, caller_ip),
            crate::trace::StackScan::None,
        )
    }

    /// `trace_native_call` for a caller that knows the callee name, keyed by its call site.
    #[allow(clippy::too_many_arguments)] // The call site and its stack scan accompany the MFA.
    pub(crate) fn trace_native_call_named(
        &mut self,
        p: &mut Process,
        ctx: &mut arinsal_sched::RunCtx<'_, process::Message>,
        module: &str,
        function: &str,
        arity: usize,
        site: (usize, usize),
        scan: crate::trace::StackScan,
    ) -> Option<(String, String, Vec<Term>)> {
        if !crate::trace_bp::any_pattern()
            || !crate::trace_bp::selects(module, function, arity as u8)
        {
            return None;
        }
        let (module, function) = (module.to_owned(), function.to_owned());
        let args = p.x[..arity].to_vec();
        let resumed = p.cold.as_ref().is_some_and(
            |cold| matches!(&cold.traced_native_call, Some((m, ip, _)) if (*m, *ip) == site),
        );
        if !resumed {
            let actions =
                crate::trace::bif_call_event(self, p, ctx, &module, &function, &args, scan)
                    .unwrap_or_default();
            p.cold_mut().traced_native_call = Some((site.0, site.1, actions));
        }
        Some((module, function, args))
    }

    /// Emit the return or exception events of a traced native BIF that finished.
    pub(crate) fn trace_native_return(
        &mut self,
        p: &mut Process,
        ctx: &mut arinsal_sched::RunCtx<'_, process::Message>,
        module: &str,
        function: &str,
        args: &[Term],
        result: &Result<Term, VmError>,
    ) {
        if matches!(result, Err(VmError::Unsupported(message)) if signals::is_await_message(message))
        {
            return;
        }
        let outcome = match result {
            Ok(value) => Ok(*value),
            Err(VmError::Trap(trap)) => {
                match exceptions::trace_class_reason(p, trap.class, trap.reason) {
                    Ok(pair) => Err(pair),
                    Err(_) => {
                        p.cold_mut().traced_native_call = None;
                        return;
                    }
                }
            }
            Err(_) => {
                p.cold_mut().traced_native_call = None;
                return;
            }
        };
        self.trace_native_return_outcome(p, ctx, module, function, args, outcome);
    }

    /// `trace_native_return` for an outcome already reduced to a value or a class and reason.
    pub(crate) fn trace_native_return_outcome(
        &mut self,
        p: &mut Process,
        ctx: &mut arinsal_sched::RunCtx<'_, process::Message>,
        module: &str,
        function: &str,
        args: &[Term],
        outcome: Result<Term, Term>,
    ) {
        let Some((site_module, site_ip, actions)) = p
            .cold
            .as_mut()
            .and_then(|cold| cold.traced_native_call.take())
        else {
            return;
        };
        let _ = crate::trace::bif_return_events(
            self,
            p,
            ctx,
            &actions,
            module,
            function,
            args.len() as u8,
            outcome,
            Some((site_module, site_ip)),
        );
    }

    pub(crate) fn ret(p: &mut Process) -> Option<Term> {
        p.tick();
        while let Some(cp) = p.heap.stack_get(0) {
            if cp.classify() == TermKind::Catch {
                break;
            } else {
                let word = cp.tagged_word() as usize;
                if word == arinsal_beamasm::rt::arinsal_enter_native_return as *const () as usize {
                    p.heap.release_stack(1);
                    continue;
                }
                if crate::native_bridge::is_native_continuation(word) {
                    // A native return address, or the stub of a traced native function's
                    // return frame, which finishes the frame when entered.
                    p.heap.release_stack(1);
                    p.cold_mut().native_continuation_resume = true;
                    p.cold_mut().native_resume_live = 2;
                    p.native_pc = Some(word);
                    return None;
                }
                break;
            }
        }
        calls::return_to(p)
    }
    pub(crate) fn branch(p: &mut Process, label: Arg) -> Result<(), VmError> {
        if label.kind() != Arg::LABEL || label.value() == u32::MAX as u64 {
            return Err(VmError::Unsupported("failure label zero".into()));
        }
        p.ip = label.value() as usize;
        Ok(())
    }
    pub(crate) fn import_class(&self, module: usize, index: usize) -> Result<ImportClass, VmError> {
        let import = self
            .modules
            .get(module)
            .and_then(|module| module.imports.get(index))
            .ok_or_else(|| VmError::Unsupported(format!("import {index}")))?;
        if import.class() == ImportClass::Fresh {
            if import.bif.is_none()
                && let Some(bif) =
                    natives::static_nif_lookup(&import.module, &import.function, import.arity)
            {
                import.set_extra_bif(bif);
            }
            let (class, bits) = natives::classify(
                &import.module,
                &import.function,
                import.arity,
                import.bif_fn().is_some(),
            );
            if bits != 0 {
                import.set_native_bits(bits);
            }
            import.set_class(class);
        }
        Ok(self.modules[module].imports[index].class())
    }
    /// Return the import's cached code destination for the current code epoch.
    // Port of erts/emulator/beam/emu/macros.tab:175-185, OTP-29.1.1.
    pub(crate) fn cached_import_jump(
        &self,
        caller: usize,
        index: usize,
    ) -> Option<(usize, usize, *const Instr)> {
        let import = self.modules.get(caller)?.imports.get(index)?;
        let (id, epoch, target, code) = import.resolved()?;
        if epoch != self.seen_epoch || code.is_null() {
            return None;
        }
        Some((id, target, code))
    }
    /// Pure BIF or static NIF bound into this import slot.
    #[inline(always)]
    pub(crate) fn pure_bif(&self, module: usize, index: usize) -> Option<arinsal_bifs::BifFn> {
        let import = self.modules.get(module)?.imports.get(index)?;
        if import.class() != ImportClass::Pure {
            return None;
        }
        import.bif_fn()
    }
    #[cold]
    pub(crate) fn fail_pure_bif(
        &self,
        p: &mut Process,
        module: usize,
        index: usize,
        arity: usize,
        error: arinsal_bifs::BifError,
    ) -> VmError {
        let args = p.x[..arity].to_vec();
        let import = &self.modules[module].imports[index];
        exceptions::bif_error_with_atoms(
            p,
            &import.module,
            &import.function,
            import.module_atom,
            import.function_atom,
            &args,
            error,
        )
    }
    pub(crate) fn remember_export(
        &self,
        caller: usize,
        index: usize,
        target_module: usize,
        function: &str,
        arity: u8,
    ) {
        let Some(export) = self
            .modules
            .get(target_module)
            .and_then(|module| module.export_slot(function, arity))
        else {
            return;
        };
        // SAFETY: `export` points at an `ExportSlot` inside this VM's module
        // table. The slot stays allocated for the life of that module entry.
        unsafe {
            self.modules[caller].imports[index].resolve(target_module, self.seen_epoch, export);
        }
    }
    pub(crate) fn jump_import(
        &mut self,
        p: &mut Process,
        module: usize,
        ip: usize,
        code: *const Instr,
        arity: usize,
        tail: bool,
    ) -> Result<ImportOutcome, VmError> {
        if !tail {
            // Native exports use this interpreter CP after run_native removes
            // its bridge CP and copies XREG0 back to the process register file.
            calls::push_continuation(p, p.module, p.ip + 1, arity)?;
        }
        p.module = module;
        p.ip = ip;
        p.tick();
        Ok(ImportOutcome::Jump(code))
    }
    pub(crate) fn finish_native_value(
        &mut self,
        p: &mut Process,
        tail: bool,
        value: Term,
    ) -> Result<ImportOutcome, VmError> {
        p.x[0] = value;
        // Port of erts/emulator/beam/erl_gc.c:418 (erts_gc_after_bif_call_lhf), OTP-29.1.1:
        // a BIF that pushed the virtual binary heap over its limit collects before returning.
        p.collect_bin_vheap_if_due(1)?;
        if tail {
            return Ok(match Self::ret(p) {
                Some(value) => ImportOutcome::Returned(value),
                None => {
                    if p.native_pc.is_some() {
                        // Returning into a native continuation is not a scheduling point.
                        p.cold_mut().native_transfer = true;
                        ImportOutcome::Yield
                    } else {
                        ImportOutcome::Advanced
                    }
                }
            });
        }
        p.ip += 1;
        Ok(ImportOutcome::Advanced)
    }
    pub(crate) fn finish_bif(
        &mut self,
        p: &mut Process,
        index: usize,
        arity: usize,
        tail: bool,
        bif: arinsal_bifs::BifFn,
        mut ctx: Option<&mut arinsal_sched::RunCtx<'_, process::Message>>,
    ) -> Result<ImportOutcome, VmError> {
        // A panic in a pure BIF is a VM bug. Erlang failures still return
        // `BifError` and build the same exception frame.
        let (result, bif_reductions) =
            self.call_bif_traced(p, ctx.as_deref_mut(), p.module, index, bif, arity);
        p.reductions_used = p.reductions_used.saturating_add(u64::from(bif_reductions));
        let value = match result {
            Ok(value) => value,
            Err(error) => {
                let args = p.x[..arity].to_vec();
                let import = &self.modules[p.module].imports[index];
                return Err(exceptions::bif_error_with_atoms(
                    p,
                    &import.module,
                    &import.function,
                    import.module_atom,
                    import.function_atom,
                    &args,
                    error,
                ));
            }
        };
        let value = p.gc_after_bif(value)?;
        let charge = bif_reductions.saturating_add(1);
        p.reductions = p
            .reductions
            .saturating_sub(charge.min(i32::MAX as u32) as i32);
        let exhausted = ctx.is_some_and(|run| !run.consume(charge));
        let outcome = self.finish_native_value(p, tail, value)?;
        if exhausted && matches!(outcome, ImportOutcome::Advanced | ImportOutcome::Jump(_)) {
            p.reductions = 4000;
            Ok(ImportOutcome::Yield)
        } else {
            Ok(outcome)
        }
    }
    #[inline(always)]
    pub(crate) fn call_import(
        &mut self,
        p: &mut Process,
        index: usize,
        arity: usize,
        tail: bool,
        mut ctx: Option<&mut arinsal_sched::RunCtx<'_, process::Message>>,
    ) -> Result<ImportOutcome, VmError> {
        p.gc_live = arity;
        if let Some(result) = crate::bif_traps::execute(
            self,
            p,
            index,
            arity,
            [
                p.x.first().copied().unwrap_or(Term::NIL),
                p.x.get(1).copied().unwrap_or(Term::NIL),
                p.x.get(2).copied().unwrap_or(Term::NIL),
            ],
            ctx.as_deref_mut(),
        ) {
            return match result? {
                crate::bif_traps::TrapResult::Done { value, .. } => {
                    self.finish_native_value(p, tail, value)
                }
                crate::bif_traps::TrapResult::Failed { .. } => {
                    unreachable!("failed trapping BIFs become VM exceptions")
                }
                crate::bif_traps::TrapResult::Yield { .. } => Ok(ImportOutcome::Yield),
            };
        }
        let class = self.import_class(p.module, index)?;
        // Pure BIF: one tag load and one indirect call. No name copy, no
        // argument Vec, no family scan. Code reload does not retarget a BIF.
        if class == ImportClass::Pure {
            let bif = self.modules[p.module].imports[index]
                .bif_fn()
                .ok_or_else(|| VmError::Unsupported("pure BIF".into()))?;
            return self.finish_bif(p, index, arity, tail, bif, ctx);
        }
        self.call_import_general(p, index, arity, tail, ctx, class)
    }
    #[cold]
    #[inline(never)]
    pub(crate) fn call_import_general(
        &mut self,
        p: &mut Process,
        index: usize,
        arity: usize,
        tail: bool,
        mut ctx: Option<&mut arinsal_sched::RunCtx<'_, process::Message>>,
        class: ImportClass,
    ) -> Result<ImportOutcome, VmError> {
        self.sync_code_epoch();
        if class == ImportClass::Remote
            && let Some((module, ip, code)) = self.cached_import_jump(p.module, index)
        {
            return self.jump_import(p, module, ip, code, arity, tail);
        }
        // The caller's module stays alive for this call, so the MFA strings
        // are borrowed. A reload of some other module cannot free them.
        let caller_module = Arc::clone(
            self.modules
                .get(p.module)
                .ok_or_else(|| VmError::Unsupported(format!("import {index}")))?,
        );
        let caller_module_id = p.module;
        let caller_ip = p.ip;
        let import = caller_module
            .imports
            .get(index)
            .ok_or_else(|| VmError::Unsupported(format!("import {index}")))?;
        let module_name = import.module.as_str();
        let function_name = import.function.as_str();
        let import_arity = import.arity;
        let bif = import.bif_fn();
        let native_bits = import.native_bits();
        if matches!(class, ImportClass::Native | ImportClass::Dynamic)
            && let Some(run) = ctx.as_deref_mut()
        {
            if trace_boot_enabled()
                && (bif.is_some()
                    || arinsal_spec::bif_lookup(module_name, function_name, arity as u8).is_some())
            {
                eprintln!(
                    "arinsal boot: native {}:{}/{}",
                    module_name, function_name, arity
                );
            }
            let traced = self.trace_native_call(p, run, caller_module_id, caller_ip, index, arity);
            if let Some(result) = self.dispatch_native(
                p,
                run,
                module_name,
                function_name,
                arity,
                (class, native_bits),
            ) {
                if let Some((module, function, args)) = traced {
                    self.trace_native_return(p, run, &module, &function, &args, &result);
                }
                let value = result?;
                if module_name == "erlang"
                    && function_name == "call_on_load_function"
                    && p.module != caller_module_id
                {
                    // Port of erts/emulator/beam/beam_bif_load.c:793
                    // (call_on_load_function_1), OTP-29.1.1. A trap behaves like
                    // a call: tail calls retain their caller's CP, other calls
                    // resume at the instruction after the BIF when on_load returns.
                    if !tail {
                        calls::push_continuation(p, caller_module_id, caller_ip + 1, arity)?;
                    }
                    let target = self
                        .modules
                        .get(p.module)
                        .and_then(|module| module.code.get(p.ip))
                        .map(|instruction| instruction as *const Instr)
                        .ok_or_else(|| VmError::Unsupported("on_load entry".into()))?;
                    p.tick();
                    return Ok(ImportOutcome::Jump(target));
                }
                let outcome = self.finish_native_value(p, tail, value)?;
                return Ok(after_dirty(outcome));
            }
        }
        // ---- vm_funs ----
        if class == ImportClass::Fun
            && let Some(outcome) =
                self.intercept_fun_import(p, index, arity, tail, ctx.as_deref_mut())?
        {
            return Ok(outcome);
        }
        // ---- vm_exc ----
        if module_name == "erlang" && function_name == "system_flag" && arity == 2 {
            let value = exceptions::system_flag(p, &mut self.backtrace_depth, p.x[0], p.x[1])?;
            return self.finish_native_value(p, tail, value);
        }
        if let Some(bif) = bif {
            return self.finish_bif(p, index, arity, tail, bif, ctx);
        }
        if class == ImportClass::Unsupported
            || arinsal_spec::bif_lookup(module_name, function_name, import_arity).is_some()
        {
            let caller = self.frame_name(p);
            eprintln!(
                "arinsal: unsupported BIF {}:{}/{} (called from {})",
                module_name, function_name, import_arity, caller
            );
            return Err(VmError::Unsupported(format!(
                "BIF {}:{}/{}",
                module_name, function_name, import_arity
            )));
        }
        if let Some(&target_module) = self.loaded.get(module_name)
            && self.modules[target_module]
                .export_slot(function_name, import_arity)
                .is_some()
        {
            self.remember_export(p.module, index, target_module, function_name, import_arity);
            let (ip, code) = {
                let slot = self.modules[target_module]
                    .export_slot(function_name, import_arity)
                    .ok_or_else(|| VmError::Exception {
                        reason: "undef".into(),
                        frame: format!("{module_name}:{function_name}/{import_arity}"),
                    })?;
                (slot.target(), slot.code_ptr())
            };
            return self.jump_import(p, target_module, ip, code, arity, tail);
        }
        if self.pending_on_load.contains_key(module_name) {
            return Err(VmError::Trap(exceptions::Trap::error(signals::atom(
                "undef",
            ))));
        }
        // mix_loop3: `code:delete` drops the current version. The next call
        // goes through `error_handler`, which `code:ensure_loaded`s the beam
        // now first on the path (protocol consolidation).
        if self.deleted.contains(module_name) {
            if self.should_autoload(p, module_name) {
                return self.call_undefined_function(
                    p,
                    module_name,
                    function_name,
                    import_arity as usize,
                    tail,
                );
            }
            return Err(VmError::Trap(exceptions::Trap::error(signals::atom(
                "undef",
            ))));
        }
        // `load_named` would mark the beam current and skip `-on_load`, so
        // crypto's NIF stubs would stay in place. `prim_tty` has no `-on_load`
        // and must stay on `load_named`, which binds its static NIFs.
        if self.unloaded_on_load(p, module_name) {
            return self.call_undefined_function(
                p,
                module_name,
                function_name,
                import_arity as usize,
                tail,
            );
        }
        let target_module = match self.load_named_traced(p, module_name) {
            Ok(id) => id,
            // mix_loop1: same autoload as apply/3. See call_undefined_function.
            Err(_) if self.should_autoload(p, module_name) => {
                return self.call_undefined_function(
                    p,
                    module_name,
                    function_name,
                    import_arity as usize,
                    tail,
                );
            }
            Err(error) => return Err(error),
        };
        if self.modules[target_module]
            .export_slot(function_name, import_arity)
            .is_none()
        {
            // Port of erts/emulator/beam/beam_common.c (call_error_handler): a missing
            // export of a loaded module also goes through error_handler:undefined_function/3.
            if self.should_autoload(p, module_name) {
                return self.call_undefined_function(
                    p,
                    module_name,
                    function_name,
                    import_arity as usize,
                    tail,
                );
            }
            return Err(VmError::Exception {
                reason: "undef".into(),
                frame: format!("{module_name}:{function_name}/{import_arity}"),
            });
        }
        self.remember_export(p.module, index, target_module, function_name, import_arity);
        let (ip, code) = {
            let slot = self.modules[target_module]
                .export_slot(function_name, import_arity)
                .ok_or_else(|| VmError::Exception {
                    reason: "undef".into(),
                    frame: format!("{module_name}:{function_name}/{import_arity}"),
                })?;
            (slot.target(), slot.code_ptr())
        };
        self.jump_import(p, target_module, ip, code, arity, tail)
    }
}

/// After a BIF completed on a dirty scheduler, continue on a normal scheduler.
///
/// Port of erts/emulator/beam/erl_process.c:10190 (a finished dirty job is scheduled out
/// to a normal run queue), OTP-29.1.1.
pub(crate) fn after_dirty(outcome: ImportOutcome) -> ImportOutcome {
    if arinsal_sched::current_scheduler_type().is_dirty()
        && matches!(outcome, ImportOutcome::Advanced | ImportOutcome::Jump(_))
    {
        ImportOutcome::Yield
    } else {
        outcome
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use arinsal_term::{ProcessHeap, TermBuilder};

    #[test]
    fn bif_epilogue_collects_when_heap_fragments_exceed_free_heap() {
        let mut process = Process::with_registers(4, 0);
        process.heap.gc_fragment(process.heap.free_words() + 1);
        let mut arguments = [Term::NIL];
        let mut result = Ok(Term::atom(arinsal_term::atoms::TRUE));

        gc_after_bif(&mut process, &mut arguments, &mut result).unwrap();

        assert!(!process.heap.gc_desired());
        assert!(process.stats.gc.collections > 0);
        assert_eq!(result.unwrap().as_atom(), Some(arinsal_term::atoms::TRUE));
    }

    #[test]
    fn continuation_gc_keeps_only_callee_arguments() {
        let mut process = Process::with_registers(8, 8);
        process.heap = ProcessHeap::with_words(8);
        process.x[0] = TermBuilder::new(&mut process.heap)
            .tuple(&[Term::small(1).unwrap()])
            .unwrap();
        process.x[2] = TermBuilder::new(&mut process.heap)
            .tuple(&[Term::small(2).unwrap()])
            .unwrap();
        let dead = process.x[2];
        let free = process.heap.free_words();
        process.heap.alloc(free).unwrap();

        push_continuation(&mut process, 0, 0, 1).unwrap();

        assert_eq!(process.x[2], dead);
        assert_eq!(process.gc_live, 1);
    }
}
