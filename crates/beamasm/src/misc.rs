//! Miscellaneous BeamAsm instructions for messaging, apply, and match positions.

use arinsal_a64::enc::Gpr;

use crate::module::{ArgVal, BeamModuleAssembler, ModuleError};

/// Resolves `apply Arity` to a native entry or the interpreter fragment.
pub type ApplyHook = extern "C" fn(*mut crate::ProcessHeader, u32) -> usize;

impl BeamModuleAssembler {
    /// Sends through the light-BIF trap path so the executor owns the scheduler context.
    // Port of erts/emulator/beam/jit/arm/instr_bif.cpp:612-624, OTP-29.1.1.
    pub fn emit_send(&mut self, fragment: usize, identity: usize) -> Result<(), ModuleError> {
        self.dispatch_send(fragment, identity)
    }

    /// Restores the saved bit offset in an `ErlSubBits` match context.
    // Port of erts/emulator/beam/jit/arm/instr_bs.cpp:371-384, OTP-29.1.1
    pub fn emit_bs_set_position(&mut self, ctx: ArgVal, pos: ArgVal) -> Result<(), ModuleError> {
        let ctx = self.source_reg(ctx)?;
        self.code.emit(|e| e.and_imm(Gpr::x(9), ctx, !7))?;
        let pos = self.source_reg_into(pos, Gpr::x(17))?;
        self.code.emit(|e| {
            e.asr_imm(Gpr::x(10), pos, 4)?;
            e.str_uoff(Gpr::x(10), Gpr::x(9), 16)
        })?;
        Ok(())
    }
}

/// Which apply form an instruction implements.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApplyKind {
    /// `apply Arity`: arguments in X0.., module and function in `x[Arity]`, `x[Arity+1]`.
    Fixed(u32),
    /// `apply/3` (`i_apply`): module, function and argument list in X0..X2.
    Apply3,
    /// `apply/2` (`i_apply_fun`): fun and argument list in X0, X1.
    Apply2,
}

/// Runtime entry points used by the apply instructions.
#[derive(Clone, Copy, Debug)]
pub struct ApplyRuntime {
    /// Resolves a fixed-arity apply; returns a native target or the fixed-apply fragment.
    pub resolver: ApplyHook,
    /// Fragment handing `apply/2` to the interpreter.
    pub apply2_fragment: usize,
    /// Fragment handing `apply/3` to the interpreter.
    pub apply3_fragment: usize,
}

/// Calls the target of an apply form.
// Port of erts/emulator/beam/jit/arm/instr_call.cpp:246-249,263-266, OTP-29.1.1
pub fn emit_apply_call(
    asm: &mut BeamModuleAssembler,
    kind: ApplyKind,
    runtime: ApplyRuntime,
) -> Result<(), ModuleError> {
    emit_apply_common(asm, kind, runtime, false)
}

/// Tail-calls the target of an apply form after releasing `deallocate` Y slots.
// Port of erts/emulator/beam/jit/arm/instr_call.cpp:251-260,301-309, OTP-29.1.1
pub fn emit_apply_tail(
    asm: &mut BeamModuleAssembler,
    kind: ApplyKind,
    runtime: ApplyRuntime,
    deallocate: u32,
) -> Result<(), ModuleError> {
    asm.deallocate(deallocate)?;
    emit_apply_common(asm, kind, runtime, true)
}

// Port of erts/emulator/beam/jit/arm/instr_call.cpp:205-320, OTP-29.1.1.
// `apply/2` and `apply/3` reach the interpreter through a shared fragment, which
// validates and applies them; a fixed apply first looks for a native target.
fn emit_apply_common(
    asm: &mut BeamModuleAssembler,
    kind: ApplyKind,
    runtime: ApplyRuntime,
    tail: bool,
) -> Result<(), ModuleError> {
    let continuation = asm.code.new_label();
    if tail {
        asm.record_call_site()?;
    } else {
        asm.record_return_site(continuation)?;
    }
    let fragment = match kind {
        ApplyKind::Fixed(arity) => {
            if arity > 255 {
                return Err(ModuleError::InvalidOperand("apply arity exceeds 255"));
            }
            asm.code
                .emit(|e| e.mov_const(Gpr::x(9), u64::from(arity)))?;
            asm.emit_runtime_hook_with(
                runtime.resolver as usize,
                &[Gpr::x(9)],
                6,
                crate::Update::HEAP_ALLOC
                    .union(crate::Update::REDUCTIONS)
                    .union(crate::Update::X_REGS),
            )?;
            asm.code.emit(|e| e.mov_reg(Gpr::x(17), Gpr::x(0)))?;
            None
        }
        ApplyKind::Apply2 => Some(runtime.apply2_fragment),
        ApplyKind::Apply3 => Some(runtime.apply3_fragment),
    };
    if let Some(fragment) = fragment {
        asm.code
            .emit(|e| e.mov_const(Gpr::x(17), fragment as u64))?;
    }
    if tail {
        asm.emit_leave_frame()?;
        asm.code.emit(|e| e.br(Gpr::x(17)))?;
    } else {
        asm.code.adr(Gpr::x(30), continuation)?;
        asm.code.emit(|e| e.br(Gpr::x(17)))?;
        asm.code.bind(continuation)?;
    }
    Ok(())
}
