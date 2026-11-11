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
        p.x.ensure_x(arity);
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
            // A native BIF without a named entry is its `bif_table` body.
            None if class == ImportClass::Native => {
                // `bif_table[].f` reads its arguments from the register array.
                if let natives::NativeArgs::Slice(values) = args {
                    p.x.ensure_x(values.len());
                    p.x[..values.len()].copy_from_slice(values);
                }
                crate::bif_table::call_from_executor(p, module, function, args.len())
            }
            None => None,
        }
    }
}
