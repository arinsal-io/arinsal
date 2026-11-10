//! Continuations and Y frames on the process stack.

use crate::{Process, VmError};
use arinsal_term::{Term, TermKind};

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
    BifRegisters { start: usize, len: usize },
    CurrentArgs(usize),
    CurrentArgsNoLocation(usize),
}

#[inline]
pub(crate) fn trace_boot_enabled() -> bool {
    crate::debug_env::slice::get() & crate::debug_env::slice::TRACE_BOOT != 0
}

/// Invoke a resolved pure BIF or static NIF on the process heap.
///
/// `args` views the caller's X registers, and BIF reductions mutate `fcalls` directly.
#[inline(always)]
pub fn call_bif(
    heap: &mut arinsal_term::ProcessHeap,
    target: arinsal_bifs::BifFn,
    args: &[arinsal_term::Term],
) -> Result<arinsal_term::Term, arinsal_bifs::BifError> {
    let mut fragment = arinsal_bifs::ProcessHeapHandle(heap);
    let mut state = arinsal_bifs::BifState::default();
    let mut ctx = arinsal_bifs::Ctx::with_fcalls(&mut fragment, &mut state);
    target(&mut ctx, args)
}

/// Invoke a BIF and return its reported work for scheduler accounting.
pub(crate) fn call_bif_metered(
    heap: &mut arinsal_term::ProcessHeap,
    target: arinsal_bifs::BifFn,
    args: &[arinsal_term::Term],
) -> (Result<arinsal_term::Term, arinsal_bifs::BifError>, u32) {
    let mut fragment = arinsal_bifs::ProcessHeapHandle(heap);
    let mut state = arinsal_bifs::BifState::default();
    let mut ctx = arinsal_bifs::Ctx::with_fcalls(&mut fragment, &mut state);
    let result = target(&mut ctx, args);
    let reductions = ctx.reductions();
    (result, reductions)
}

/// Collect after a BIF when message-buffer fragments occupy more space than
/// the process can keep free on its heap.
// Port of erts/emulator/beam/erl_gc.c:418-478 (erts_gc_after_bif_call_lhf), OTP-29.1.1.
pub(super) fn gc_after_bif(
    process: &mut Process,
    arguments: &mut [Term],
    result: &mut Result<Term, arinsal_bifs::BifError>,
) -> Result<(), VmError> {
    if !process.heap.gc_after_bif_desired() {
        return Ok(());
    }
    // Port of erl_gc.c:418-478 (`erts_gc_after_bif_call_lhf`), OTP-29.1.1:
    // a successful BIF return roots only the result slot; argument registers are dead.
    if let Ok(value) = result {
        let mut roots = [*value];
        let collected = process.collect_heap_roots(0, &mut roots, 0);
        let stats = collected?;
        *value = roots[0];
        // Port of erl_gc.c:922-932 (`garbage_collect` records scheduler GC statistics), OTP-29.1.1.
        crate::natives::sys::after_collection(process, stats.collections, stats.words_reclaimed);
        process.charge_gc_stats(&stats);
        return Ok(());
    }

    // The error path roots the BIF argument registers plus process-owned error terms.
    let mut roots: smallvec::SmallVec<[Term; 8]> = smallvec::SmallVec::new();
    let error_roots = if let Err(error) = result {
        match error {
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
        }
    } else {
        None
    };
    let stats = process.collect_heap_roots(arguments.len(), &mut roots, 0)?;
    arguments.copy_from_slice(&process.x[..arguments.len()]);
    if let Some(error_roots) = error_roots
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
    // Port of erts/emulator/beam/erl_gc.c:922-932 (`garbage_collect` updates
    // `esdp->gc_info`), OTP-29.1.1: the BIF epilogue collection is counted.
    crate::natives::sys::after_collection(process, stats.collections, stats.words_reclaimed);
    process.charge_gc_stats(&stats);
    Ok(())
}

/// Apply the native BIF epilogue, preserving error arguments when needed.
// Port of erts/emulator/beam/erl_gc.c:418-478 (erts_gc_after_bif_call_lhf), OTP-29.1.1.
pub(super) fn gc_after_native(
    process: &mut Process,
    arguments: &mut [Term],
    result: &mut Result<Term, VmError>,
) -> Result<(), VmError> {
    match result {
        Ok(value) => gc_after_native_parts(process, arguments, Some(value), None),
        Err(VmError::Trap(trap)) => gc_after_native_parts(process, arguments, None, Some(trap)),
        Err(_) => gc_after_native_parts(process, arguments, None, None),
    }
}

/// [`gc_after_native`] for a result already split into its value or raised exception.
pub(crate) fn gc_after_native_parts(
    process: &mut Process,
    arguments: &mut [Term],
    value: Option<&mut Term>,
    raised: Option<&mut crate::exceptions::Trap>,
) -> Result<(), VmError> {
    if !process.heap.gc_after_bif_desired() {
        return Ok(());
    }
    if let Some(value) = value {
        let mut roots = [*value];
        let stats = process.collect_heap_roots(0, &mut roots, 0)?;
        *value = roots[0];
        // Port of erl_gc.c:922-932 (`garbage_collect` records scheduler GC statistics), OTP-29.1.1.
        crate::natives::sys::after_collection(process, stats.collections, stats.words_reclaimed);
        process.charge_gc_stats(&stats);
        return Ok(());
    }
    let mut roots = arguments.to_vec();
    let error_roots = if let Some(trap) = raised.as_deref() {
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
            crate::stacktrace::TopFrame::BifRegisters { arity, .. } => {
                let len = (*arity).min(arguments.len());
                Some(NativeTopRoots::BifRegisters { start: 0, len })
            }
            crate::stacktrace::TopFrame::CurrentArgs(args) => {
                roots.push(*args);
                Some(NativeTopRoots::CurrentArgs(roots.len() - 1))
            }
            crate::stacktrace::TopFrame::CurrentArgsNoLocation { args, .. } => {
                roots.push(*args);
                Some(NativeTopRoots::CurrentArgsNoLocation(roots.len() - 1))
            }
            crate::stacktrace::TopFrame::CurrentArgsWithInfo(Some(args), _) => {
                roots.push(*args);
                Some(NativeTopRoots::CurrentArgs(roots.len() - 1))
            }
            crate::stacktrace::TopFrame::CurrentArgsWithInfo(None, _) => None,
            // Resolver-local; it never reaches a trap that survives a collection.
            crate::stacktrace::TopFrame::CurrentArgsInfoTerm(..) => None,
        });
        Some(NativeErrorRoots::Trap { reason, trace, top })
    } else {
        None
    };
    let stats = process.collect_heap_roots(arguments.len(), &mut roots, 0)?;
    arguments.copy_from_slice(&roots[..arguments.len()]);
    if let Some(NativeErrorRoots::Trap { reason, trace, top }) = error_roots
        && let Some(trap) = raised
    {
        trap.reason = roots[reason];
        trap.trace = trace.map(|index| roots[index]);
        if let Some(top_roots) = top {
            match trap.top.as_mut() {
                Some(crate::stacktrace::TopFrame::Bif { args, .. }) => match top_roots {
                    NativeTopRoots::BifArgs { start, len } => {
                        args.update_root_terms(&roots, start, len);
                    }
                    NativeTopRoots::BifRegisters { .. } => {
                        unreachable!("BIF argument storage remains stable across GC")
                    }
                    NativeTopRoots::CurrentArgs(_) => {
                        unreachable!("BIF argument storage remains stable across GC")
                    }
                    NativeTopRoots::CurrentArgsNoLocation(_) => {
                        unreachable!("BIF argument storage remains stable across GC")
                    }
                },
                Some(crate::stacktrace::TopFrame::BifRegisters { .. }) => {
                    if let NativeTopRoots::BifRegisters { start, len } = top_roots {
                        arguments[..len].copy_from_slice(&roots[start..start + len]);
                    }
                }
                Some(crate::stacktrace::TopFrame::CurrentArgs(args))
                    if let NativeTopRoots::CurrentArgs(index) = top_roots =>
                {
                    *args = roots[index]
                }
                Some(crate::stacktrace::TopFrame::CurrentArgsNoLocation { args, .. })
                    if let NativeTopRoots::CurrentArgsNoLocation(index) = top_roots =>
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
    // Port of erts/emulator/beam/erl_gc.c:922-932 (`garbage_collect` updates
    // `esdp->gc_info`), OTP-29.1.1: the BIF epilogue collection is counted.
    crate::natives::sys::after_collection(process, stats.collections, stats.words_reclaimed);
    process.charge_gc_stats(&stats);
    Ok(())
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
    p.set_ip(ip);
    p.heap.release_stack(1);
    None
}

pub(crate) enum ImportOutcome {
    Returned(Term),
    Advanced,
    Jump,
    Yield,
}

// VM calls implementation.

use super::*;

impl Vm {
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
            || !crate::trace_bp::selects(p, module, function, arity as u8)
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
            || !crate::trace_bp::selects(p, module, function, arity as u8)
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
                    p.native_continuation_resume = true;
                    p.set_native_resume_arity(1);
                    p.set_native_pc(Some(word));
                    return None;
                }
                break;
            }
        }
        calls::return_to(p)
    }
}

/// After a BIF completed on a dirty scheduler, continue on a normal scheduler.
///
/// Port of erts/emulator/beam/erl_process.c:10190 (a finished dirty job is scheduled out
/// to a normal run queue), OTP-29.1.1.
pub(crate) fn after_dirty(outcome: ImportOutcome) -> ImportOutcome {
    if arinsal_sched::current_scheduler_type().is_dirty()
        && matches!(outcome, ImportOutcome::Advanced | ImportOutcome::Jump)
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

    fn process_over_the_bin_vheap_limit() -> Process {
        let mut process = Process::with_registers(4, 0);
        process.heap = ProcessHeap::with_words(256);
        let bytes = vec![1u8; 8 * (process.heap.bin_vheap_block_size() as usize + 1)];
        TermBuilder::new(&mut process.heap).binary(&bytes).unwrap();
        assert!(process.heap.bin_vheap_gc_due());
        assert!(!process.heap.gc_desired());
        process
    }

    #[test]
    fn bif_epilogue_collects_when_the_bin_vheap_is_over_its_limit() {
        let mut process = process_over_the_bin_vheap_limit();
        let mut arguments = [Term::NIL];
        let mut result = Ok(Term::atom(arinsal_term::atoms::TRUE));

        gc_after_bif(&mut process, &mut arguments, &mut result).unwrap();

        assert_eq!(process.stats.gc.collections, 1);
        assert!(!process.heap.bin_vheap_gc_due());
    }

    #[test]
    fn bif_epilogue_collects_a_failed_bif_when_the_bin_vheap_is_over_its_limit() {
        let mut process = process_over_the_bin_vheap_limit();
        let mut arguments = [Term::NIL];
        let mut result = Err(arinsal_bifs::BifError::Badarg { cause: None });

        gc_after_bif(&mut process, &mut arguments, &mut result).unwrap();

        assert_eq!(process.stats.gc.collections, 1);
        assert!(!process.heap.bin_vheap_gc_due());
    }

    #[test]
    fn bif_epilogue_collects_once_for_fragments_and_bin_vheap() {
        let mut process = process_over_the_bin_vheap_limit();
        process.heap.gc_fragment(process.heap.free_words() + 1);
        assert!(process.heap.gc_desired());
        let mut arguments = [Term::NIL];
        let mut result = Ok(Term::atom(arinsal_term::atoms::TRUE));

        gc_after_bif(&mut process, &mut arguments, &mut result).unwrap();

        assert_eq!(process.stats.gc.collections, 1);
        assert!(!process.heap.gc_after_bif_desired());
    }

    #[test]
    fn bif_epilogue_does_not_collect_with_gc_disabled() {
        let mut process = process_over_the_bin_vheap_limit();
        process.heap.gc_enabled = false;
        let mut arguments = [Term::NIL];
        let mut result = Ok(Term::atom(arinsal_term::atoms::TRUE));

        gc_after_bif(&mut process, &mut arguments, &mut result).unwrap();

        assert_eq!(process.stats.gc.collections, 0);
    }
}
