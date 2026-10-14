//! VM bif dispatch implementation.

use super::*;

impl Vm {
    pub(crate) fn dispatch_native(
        &mut self,
        p: &mut Process,
        ctx: &mut arinsal_sched::RunCtx<'_, process::Message>,
        module: &str,
        function: &str,
        arity: usize,
        resolved: (ImportClass, usize),
    ) -> Option<Result<Term, VmError>> {
        if arity > p.x.len() {
            return Some(Err(VmError::Unsupported(format!(
                "native arity {arity} exceeds register file"
            ))));
        }
        let mut result = self.dispatch_native_source(
            p,
            ctx,
            module,
            function,
            resolved,
            natives::NativeArgs::Registers(arity),
        );
        // A BIF that traps to an export returns THE_NON_VALUE: no collection runs after it, so
        // the trap's saved arguments stay valid until the process resumes (erts BIF_TRAP keeps
        // them in def_arg_reg, GC disabled while trapped).
        if let Some(result) = result
            .as_mut()
            .filter(|result| !matches!(result, Err(VmError::TrapExport(_))))
        {
            // Port of erts/emulator/beam/erl_gc.c:418-478 (erts_gc_after_bif_call_lhf with
            // `regs`), OTP-29.1.1: the argument registers are the BIF's arguments. A
            // collection inside the BIF (live = arity) already moved them, so the epilogue
            // roots the registers as they are now, not values saved before the call.
            let mut inline_arguments = [Term::NIL; 8];
            let mut overflow_arguments =
                (arity > inline_arguments.len()).then(|| p.x[..arity].to_vec());
            let arguments = if let Some(arguments) = overflow_arguments.as_mut() {
                arguments.as_mut_slice()
            } else {
                inline_arguments[..arity].copy_from_slice(&p.x[..arity]);
                &mut inline_arguments[..arity]
            };
            if let Err(error) = calls::gc_after_native(p, arguments, result) {
                return Some(Err(error));
            }
            p.x[..arity].copy_from_slice(arguments);
        }
        result
    }
    pub(crate) fn dispatch_native_args(
        &mut self,
        p: &mut Process,
        ctx: &mut arinsal_sched::RunCtx<'_, process::Message>,
        module: &str,
        function: &str,
        resolved: (ImportClass, usize),
        args: &[Term],
    ) -> Option<Result<Term, VmError>> {
        self.dispatch_native_source(
            p,
            ctx,
            module,
            function,
            resolved,
            natives::NativeArgs::Slice(args),
        )
    }
    pub(crate) fn dispatch_resolved_entry(
        &mut self,
        p: &mut Process,
        ctx: &mut arinsal_sched::RunCtx<'_, process::Message>,
        args: natives::NativeArgs<'_>,
        entry: natives::NativeEntry,
    ) -> Option<Result<Term, VmError>> {
        match entry {
            natives::NativeEntry::Direct(fun) => {
                Some(args.with_values(p, |p, args| fun(self, p, ctx, args)))
            }
            natives::NativeEntry::Resolved(fun) => fun(self, p, ctx, args),
            natives::NativeEntry::DirectFamily(_) => None,
        }
    }

    fn dispatch_native_source(
        &mut self,
        p: &mut Process,
        ctx: &mut arinsal_sched::RunCtx<'_, process::Message>,
        module: &str,
        function: &str,
        resolved: (ImportClass, usize),
        args: natives::NativeArgs<'_>,
    ) -> Option<Result<Term, VmError>> {
        let (class, bits) = resolved;
        if class == ImportClass::Dynamic
            && let Some(result) = args.with_values(p, |p, values| {
                signals::call(self, p, ctx, module, function, values)
            })
        {
            return Some(result);
        }
        match natives::unpack_native(bits) {
            Some(natives::NativeEntry::Direct(fun)) => {
                Some(args.with_values(p, |p, values| fun(self, p, ctx, values)))
            }
            Some(natives::NativeEntry::DirectFamily(fun)) => {
                fun(self, p, ctx, module, function, args)
            }
            Some(natives::NativeEntry::Resolved(fun)) => fun(self, p, ctx, args),
            None => natives::call(self, p, ctx, module, function, args),
        }
    }
    /// Execute a `bif`/`gc_bif` instruction; a trapping BIF may ask the scheduler to yield.
    pub(crate) fn exec_bif_op(
        &mut self,
        p: &mut Process,
        mut ctx: Option<&mut arinsal_sched::RunCtx<'_, process::Message>>,
        op: GenericOp,
        opcode: Opcode,
    ) -> Result<BifOpOutcome, VmError> {
        let [a, b, c] = op.args;
        let (index, first, arity, dst, fast) = {
            let module = &self.code.modules[p.module];
            let (index, first, arity, dst) = match opcode {
                Opcode::GcBif1 => (c.value() as usize, 3, 1, module.arg(&op, 4)),
                Opcode::GcBif2 => (c.value() as usize, 3, 2, module.arg(&op, 5)),
                Opcode::GcBif3 => (c.value() as usize, 3, 3, module.arg(&op, 6)),
                Opcode::Bif0 => (a.value() as usize, 1, 0, b),
                Opcode::Bif1 => (b.value() as usize, 2, 1, module.arg(&op, 3)),
                Opcode::Bif2 => (b.value() as usize, 2, 2, module.arg(&op, 4)),
                Opcode::Bif3 => (b.value() as usize, 2, 3, module.arg(&op, 5)),
                _ => unreachable!(),
            };
            let fast = module
                .imports
                .get(index)
                .map(|import| import.fast)
                .unwrap_or_default();
            (index, first, arity, dst, fast)
        };
        p.gc_live = if matches!(opcode, Opcode::GcBif1 | Opcode::GcBif2 | Opcode::GcBif3) {
            b.value() as usize
        } else {
            arity
        };
        let mut regs = [Arg::NONE; 3];
        {
            let module = &self.code.modules[p.module];
            for (i, reg) in regs.iter_mut().enumerate().take(arity) {
                *reg = module.arg(&op, first + i);
            }
        }
        let mut stored = [Term::NIL; 3];
        for i in 0..arity {
            stored[i] = p.read(regs[i])?;
        }
        let meter = crate::bif_traps::TrapMeter::start(p, ctx.as_deref());
        if let Some(result) = crate::bif_traps::execute(
            self,
            p,
            index,
            arity,
            [stored[0], stored[1], stored[2], Term::NIL],
            ctx.as_deref_mut(),
        ) {
            let result = result?;
            meter.finish(p, ctx.as_deref_mut(), result.reductions());
            return match result {
                crate::bif_traps::HandlerResult::Done { value, .. } => {
                    p.write(dst, value)?;
                    p.ip += 1;
                    Ok(BifOpOutcome::Done(0))
                }
                crate::bif_traps::HandlerResult::Failed { .. } => {
                    unreachable!("failed trapping BIFs become VM exceptions")
                }
                crate::bif_traps::HandlerResult::Yield { .. } => Ok(BifOpOutcome::Yield),
            };
        }
        if arity == 2 && fast != FastBif::None {
            let result = arith::small(fast, stored[0], stored[1]);
            if let Some(result) = result {
                p.write(dst, result)?;
                p.ip += 1;
                return Ok(BifOpOutcome::Done(0));
            }
        }
        let class = self.import_class(p.module, index)?;
        let args = &stored[..arity];
        let (result, bif_reductions) = if class == ImportClass::Pure {
            let bif = self.code.modules[p.module].imports[index]
                .bif_fn()
                .ok_or_else(|| VmError::Unsupported("pure BIF".into()))?;
            let (result, reductions) =
                calls::call_bif_metered(&mut p.heap, &mut p.reductions, bif, args);
            let result = match result {
                Ok(value) => Ok(value),
                Err(error) => {
                    let import = &self.code.modules[p.module].imports[index];
                    Err(exceptions::bif_error_with_atoms(
                        p,
                        &import.module,
                        &import.function,
                        import.module_atom,
                        import.function_atom,
                        args,
                        error,
                    ))
                }
            };
            (result, reductions)
        } else {
            let caller_module = Arc::clone(&self.code.modules[p.module]);
            let import = &caller_module.imports[index];
            let module_name = import.module.as_str();
            let function_name = import.function.as_str();
            let bif = import.bif_fn();
            let bits = import.native_bits();
            let native = if matches!(class, ImportClass::Native | ImportClass::Dynamic) {
                ctx.and_then(|run| {
                    self.dispatch_native_args(
                        p,
                        run,
                        module_name,
                        function_name,
                        (class, bits),
                        args,
                    )
                })
            } else {
                ctx.and_then(|run| signals::call(self, p, run, module_name, function_name, args))
            };
            if let Some(result) = native {
                (result, 0)
            } else if let Some(bif) = bif {
                match calls::call_bif_catch(&mut p.heap, &mut p.reductions, bif, args) {
                    Ok(Ok(value)) => (Ok(value), 0),
                    Ok(Err(error)) => (
                        Err(exceptions::bif_error_with_atoms(
                            p,
                            module_name,
                            function_name,
                            import.module_atom,
                            import.function_atom,
                            args,
                            error,
                        )),
                        0,
                    ),
                    Err(()) => (
                        Err(VmError::Unsupported(format!(
                            "BIF {module_name}:{function_name} panicked"
                        ))),
                        0,
                    ),
                }
            } else {
                return Err(VmError::Unsupported(format!(
                    "BIF {module_name}:{function_name}/{arity}"
                )));
            }
        };
        if p.cold
            .as_ref()
            .and_then(|cold| cold.debug_wait_completion.as_ref())
            .is_some_and(|completed| !completed.load(std::sync::atomic::Ordering::Acquire))
        {
            // The BIF continuation remains at this instruction until every
            // scheduler has reached its auxiliary-work scheduling point.
            p.force_yield = true;
            return Ok(BifOpOutcome::Done(0));
        }
        // Port of erts/emulator/beam/erl_arith.c:56-85, OTP-29.1.1.
        p.reductions_used = p.reductions_used.saturating_add(u64::from(bif_reductions));
        match result {
            Ok(value) => {
                p.write(dst, value)?;
                p.ip += 1;
                Ok(BifOpOutcome::Done(bif_reductions))
            }
            Err(_) if a.kind() == Arg::LABEL && a.value() != u32::MAX as u64 => {
                p.ip = a.value() as usize;
                Ok(BifOpOutcome::Done(bif_reductions))
            }
            Err(error) => Err(error),
        }
    }
}

/// Result of one `bif`/`gc_bif` instruction.
pub(crate) enum BifOpOutcome {
    /// The instruction completed; carries reductions still to charge to the caller.
    Done(u32),
    /// A trapping BIF yielded; the instruction is re-executed on resume.
    Yield,
}
