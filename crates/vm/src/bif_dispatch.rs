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
        if arity > crate::proc_create::ATTACHED_X_REGS {
            return Some(Err(VmError::Unsupported(format!(
                "native arity {arity} exceeds register file"
            ))));
        }
        let reg = match self.x_regs() {
            Ok(reg) => reg,
            Err(error) => return Some(Err(error)),
        };
        // The body charges BUMP_REDS on FCALLS, as from native code.
        let mut result = self.dispatch_native_source(
            p,
            ctx,
            module,
            function,
            resolved,
            natives::NativeArgs::registers(reg, arity),
        );
        // Port of erts/emulator/beam/erl_gc.c:454-456 (erts_gc_after_bif_call_lhf: a BIF_TRAP
        // collects with `regs` up to `p->arity`), OTP-29.1.1: BIF_TRAP's arguments are the
        // registers the trap target is called with, so they are the roots, and they are what
        // the executor installs when it makes the call.
        if let Some(Err(VmError::TrapExport(trap))) = result.as_mut() {
            if let Err(error) = calls::gc_after_native_parts(p, &mut trap.args, None, None) {
                return Some(Err(error));
            }
            return result;
        }
        if let Some(result) = result.as_mut() {
            // Port of erts/emulator/beam/erl_gc.c:418-478 (erts_gc_after_bif_call_lhf with
            // `regs`), OTP-29.1.1: the argument registers are the BIF's arguments. A
            // collection inside the BIF (live = arity) already moved them, so the epilogue
            // roots the registers as they are now, not values saved before the call.
            let mut inline_arguments = [Term::NIL; 8];
            let mut overflow_arguments =
                (arity > inline_arguments.len()).then(|| reg[..arity].to_vec());
            let arguments = if let Some(arguments) = overflow_arguments.as_mut() {
                arguments.as_mut_slice()
            } else {
                inline_arguments[..arity].copy_from_slice(&reg[..arity]);
                &mut inline_arguments[..arity]
            };
            if let Err(error) = calls::gc_after_native(p, arguments, result) {
                return Some(Err(error));
            }
            reg[..arity].copy_from_slice(arguments);
        }
        result
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
        let arity = args.len();
        if arity <= u8::MAX as usize
            && arinsal_spec::bif_lookup(module, function, arity as u8).is_some()
        {
            // Port of erts/emulator/beam/beam_bp.c (`erts_bif_trace`): a traced BIF
            // calls the pointer selected by the export's `bif_number`.
            let table_result = {
                // The BIF table body runs with this scheduler's process data, as from a
                // generated call fragment.
                let reg = match self.x_regs() {
                    Ok(reg) => reg,
                    Err(error) => return Some(Err(error)),
                };
                if let natives::NativeArgs::Slice(values) = args {
                    reg[..values.len()].copy_from_slice(values);
                }
                crate::process::sched_data::NativeSlice::run(self, ctx, p, |p| {
                    crate::bif_table::call_from_executor(p, reg, module, function, arity)
                })
            };
            if table_result.is_some() {
                return table_result;
            }
            if class == ImportClass::Pure {
                return None;
            }
        }
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
            // A native BIF without a named entry is its `bif_table` body.
            None if class == ImportClass::Native
                && arinsal_spec::bif_lookup(module, function, arity as u8).is_none() =>
            {
                // `bif_table[].f` reads its arguments from the register array.
                let reg = match self.x_regs() {
                    Ok(reg) => reg,
                    Err(error) => return Some(Err(error)),
                };
                if let natives::NativeArgs::Slice(values) = args {
                    reg[..values.len()].copy_from_slice(values);
                }
                // `erts_proc_sched_data(c_p)`: the body reaches this scheduler's data as it
                // does from native code.
                let arity = args.len();
                crate::process::sched_data::NativeSlice::run(self, ctx, p, |p| {
                    crate::bif_table::call_from_executor(p, reg, module, function, arity)
                })
            }
            None => None,
        }
    }
}
