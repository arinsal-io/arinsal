//! Miscellaneous BeamAsm instructions for messaging, apply, and match positions.

use arinsal_a64::enc::Gpr;

use crate::module::{ArgVal, BeamModuleAssembler, ModuleError};

const XREGS: [Gpr; 6] = [
    Gpr::x(25),
    Gpr::x(26),
    Gpr::x(27),
    Gpr::x(28),
    Gpr::x(15),
    Gpr::x(16),
];

/// Resolves an MFA apply call to a native function entry; zero means failure.
pub type ApplyHook = extern "C" fn(*mut crate::ProcessHeader, u64, u32, u32) -> usize;

impl BeamModuleAssembler {
    /// Sends through the light-BIF trap path so the executor owns the scheduler context.
    // Port of erts/emulator/beam/jit/arm/instr_bif.cpp:595-610, OTP-29.1.1.
    pub fn emit_send(&mut self, fragment: usize, identity: usize) -> Result<(), ModuleError> {
        self.dispatch_light_bif(fragment, identity)
    }

    /// Restores the saved bit offset in an `ErlSubBits` match context.
    // Port of erts/emulator/beam/jit/arm/instr_bs.cpp:371-384, OTP-29.1.1
    pub fn emit_bs_set_position(&mut self, ctx: ArgVal, pos: ArgVal) -> Result<(), ModuleError> {
        let ctx = self.source_reg(ctx)?;
        self.code.emit(|e| e.and_imm(Gpr::x(9), ctx, !7))?;
        let pos = self.source_reg(pos)?;
        self.code.emit(|e| {
            e.asr_imm(Gpr::x(10), pos, 4)?;
            e.str_uoff(Gpr::x(10), Gpr::x(9), 16)
        })?;
        Ok(())
    }
}

/// Applies the MFA encoded in X0/X1 and calls the returned native target.
// Port of erts/emulator/beam/jit/arm/instr_call.cpp:246-249, OTP-29.1.1
pub fn emit_i_apply(
    asm: &mut BeamModuleAssembler,
    hook: ApplyHook,
    live: u32,
) -> Result<(), ModuleError> {
    emit_apply_common(asm, None, hook, live, false, false)
}

/// Applies X0/X1 after releasing the current Y frame.
// Port of erts/emulator/beam/jit/arm/instr_call.cpp:251-254, OTP-29.1.1
pub fn emit_i_apply_last(
    asm: &mut BeamModuleAssembler,
    hook: ApplyHook,
    live: u32,
    deallocate: u32,
) -> Result<(), ModuleError> {
    asm.deallocate(deallocate)?;
    emit_i_apply_only(asm, hook, live)
}

/// Tail-applies the MFA in X0/X1.
// Port of erts/emulator/beam/jit/arm/instr_call.cpp:256-260, OTP-29.1.1
pub fn emit_i_apply_only(
    asm: &mut BeamModuleAssembler,
    hook: ApplyHook,
    live: u32,
) -> Result<(), ModuleError> {
    emit_apply_common(asm, None, hook, live, true, true)
}

/// Applies the MFA in X0/X1 with a statically known argument count.
// Port of erts/emulator/beam/jit/arm/instr_call.cpp:263-266, OTP-29.1.1
pub fn emit_apply(
    asm: &mut BeamModuleAssembler,
    arity: u32,
    hook: ApplyHook,
    live: u32,
) -> Result<(), ModuleError> {
    emit_apply_common(asm, Some(arity), hook, live, false, false)
}

/// Tail-applies a fixed-arity MFA after releasing its Y frame.
// Port of erts/emulator/beam/jit/arm/instr_call.cpp:301-309, OTP-29.1.1
pub fn emit_apply_last(
    asm: &mut BeamModuleAssembler,
    arity: u32,
    hook: ApplyHook,
    live: u32,
    deallocate: u32,
) -> Result<(), ModuleError> {
    asm.deallocate(deallocate)?;
    emit_apply_common(asm, Some(arity), hook, live, true, true)
}

// Port of erts/emulator/beam/jit/arm/instr_call.cpp:263-320, OTP-29.1.1.
fn emit_apply_common(
    asm: &mut BeamModuleAssembler,
    arity: Option<u32>,
    hook: ApplyHook,
    live: u32,
    tail: bool,
    helper_continuation: bool,
) -> Result<(), ModuleError> {
    if live > 6 || arity.is_some_and(|n| n > 6) {
        return Err(ModuleError::InvalidOperand(
            "apply arity or live count exceeds X registers",
        ));
    }
    asm.code.emit(|e| {
        e.mov_reg(Gpr::x(10), XREGS[0])?;
        if let Some(arity) = arity {
            e.mov_const(Gpr::x(11), u64::from(arity))?;
        } else {
            e.mov_reg(Gpr::x(11), XREGS[1])?;
        }
        e.mov_const(Gpr::x(12), u64::from(live))
    })?;
    asm.emit_runtime_hook(hook as usize, &[Gpr::x(10), Gpr::x(11), Gpr::x(12)])?;
    let target = asm.code.new_label();
    asm.code.cbnz(Gpr::x(0), target)?;
    asm.code.b(asm.error_label)?;
    asm.code.bind(target)?;
    if helper_continuation {
        asm.code.emit(|e| e.mov_reg(Gpr::x(14), Gpr::x(0)))?;
    }
    if tail {
        asm.emit_leave_frame()?;
        let reg = if helper_continuation {
            Gpr::x(14)
        } else {
            Gpr::x(0)
        };
        asm.code.emit(|e| e.br(reg))?;
    } else {
        let reg = if helper_continuation {
            Gpr::x(14)
        } else {
            Gpr::x(0)
        };
        asm.code.emit(|e| e.blr(reg))?;
    }
    Ok(())
}
