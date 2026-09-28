//! Continuations and Y frames on the process stack.

use crate::{Process, VmError};
use arinsal_term::{Term, TermKind};
use std::sync::LazyLock;

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
    let cp = Term::catch((module << 32) | u64::from(ip));
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
pub(super) fn call_bif_metered(
    heap: &mut arinsal_term::ProcessHeap,
    target: arinsal_bifs::BifFn,
    args: &[arinsal_term::Term],
) -> (Result<arinsal_term::Term, arinsal_bifs::BifError>, u32) {
    let mut fragment = arinsal_bifs::FragmentingHeap(heap);
    let mut ctx = arinsal_bifs::Ctx::new(&mut fragment);
    let result = target(&mut ctx, args);
    (result, ctx.reductions())
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
    // SAFETY: CATCH is an immediate and contains no heap address.
    let bits = unsafe { cp.raw_bits() } >> 6;
    p.module = (bits >> 32) as usize;
    p.ip = bits as u32 as usize;
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
                if crate::native_function_at(word).is_some() {
                    p.heap.release_stack(1);
                    p.cold_mut().native_continuation_resume = true;
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
    /// Export cached for the module id currently in `loaded`.
    ///
    /// The cached pointer is used only when it still addresses an export of
    /// that module with the same name and arity. A reload that replaces the
    /// module drops the match and the caller resolves again.
    pub(crate) fn cached_import_jump(
        &self,
        caller: usize,
        index: usize,
    ) -> Option<(usize, usize, *const Instr)> {
        let import = self.modules.get(caller)?.imports.get(index)?;
        let id = self.loaded.get(&import.module).copied()?;
        let (cached, slot) = import.resolved()?;
        if cached != id {
            return None;
        }
        let module = self.modules.get(id)?;
        let live = module
            .exports
            .iter()
            .find(|export| std::ptr::eq(export.as_ref() as *const _, slot))?;
        if live.function != import.function || live.arity != import.arity {
            return None;
        }
        Some((id, live.target(), live.code_ptr()))
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
        exceptions::bif_error(p, &import.module, &import.function, &args, error)
    }
    pub(crate) fn remember_export(
        &self,
        caller: usize,
        index: usize,
        target_module: usize,
        function: &str,
        arity: u8,
    ) {
        let export = {
            let Some(slot) = self
                .modules
                .get(target_module)
                .and_then(|module| module.export_slot(function, arity))
            else {
                return;
            };
            slot as *const arinsal_loader::ExportSlot
        };
        // SAFETY: `export` points at an `ExportSlot` inside this VM's module
        // table. The slot stays allocated for the life of that module entry.
        unsafe {
            self.modules[caller].imports[index].resolve(target_module, &*export);
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
        if tail {
            return Ok(match Self::ret(p) {
                Some(value) => ImportOutcome::Returned(value),
                None => {
                    if p.native_pc.is_some() {
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
        ctx: Option<&mut arinsal_sched::RunCtx<'_, process::Message>>,
    ) -> Result<ImportOutcome, VmError> {
        // A panic in a pure BIF is a VM bug. Erlang failures still return
        // `BifError` and build the same exception frame.
        let (result, bif_reductions) = calls::call_bif_metered(&mut p.heap, bif, &p.x[..arity]);
        let value = match result {
            Ok(value) => value,
            Err(error) => {
                let args = p.x[..arity].to_vec();
                let import = &self.modules[p.module].imports[index];
                return Err(exceptions::bif_error(
                    p,
                    &import.module,
                    &import.function,
                    &args,
                    error,
                ));
            }
        };
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
        ctx: Option<&mut arinsal_sched::RunCtx<'_, process::Message>>,
    ) -> Result<ImportOutcome, VmError> {
        p.gc_live = arity;
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
            if let Some(result) = self.dispatch_native(
                p,
                run,
                module_name,
                function_name,
                arity,
                (class, native_bits),
            ) {
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
                return self.finish_native_value(p, tail, value);
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
            let value = exceptions::system_flag(&mut self.backtrace_depth, p.x[0], p.x[1])?;
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
        let target_module = match self.load_named(module_name) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use arinsal_term::{ProcessHeap, TermBuilder};

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
