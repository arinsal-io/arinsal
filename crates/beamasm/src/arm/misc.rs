//! Miscellaneous BeamAsm instructions for messaging, apply, and match positions.

use arinsal_a64::enc::Gpr;

use crate::module::{ArgVal, BeamModuleAssembler, ModuleError};
use crate::rt::{addr, apply, fixed_apply};
use crate::{Update, emit_enter_runtime, emit_leave_runtime};

const C_P: Gpr = Gpr::x(21);
const ACTIVE_CODE_IX: Gpr = Gpr::x(24);

impl BeamModuleAssembler {
    /// `send`: `call_light_bif_shared` with `BIF_TRAP_EXPORT(BIF_send_2)` and `send_2`.
    // Port of erts/emulator/beam/jit/arm/instr_bif.cpp:612-624 (emit_send), OTP-29.1.1.
    pub fn emit_send(
        &mut self,
        fragment: usize,
        send_export: usize,
        send_2: usize,
    ) -> Result<(), ModuleError> {
        self.dispatch_light_bif(fragment, send_export, send_2)
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

/// Runtime entry points used by `apply/2`. `apply` / `fixed_apply` are the erts C
/// symbols the emitters `runtime_call`, as x86 does.
#[derive(Clone, Copy, Debug)]
pub struct ApplyRuntime {
    /// Shared fragment unpacking the `apply/2` argument list (`apply_fun_shared`).
    pub apply_fun_shared: usize,
    /// Resolves the fun of an `apply/2` that misses the local fun fast path.
    pub fun_resolver: crate::fun::FunResolver,
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
// `apply` / `fixed_apply` return the Export* (ARG1); a null pointer raises with apply3_mfa,
// otherwise `emit_setup_dispatchable_call` loads `addresses[active_code_ix]`.
fn emit_apply_common(
    asm: &mut BeamModuleAssembler,
    kind: ApplyKind,
    runtime: ApplyRuntime,
    tail: bool,
) -> Result<(), ModuleError> {
    if kind == ApplyKind::Apply2 {
        return emit_apply_fun(asm, runtime, tail);
    }
    let continuation = asm.code.new_label();
    if tail {
        asm.record_call_site()?;
    } else {
        asm.record_return_site(continuation)?;
    }
    let update = Update::HEAP_ALLOC
        .union(Update::REDUCTIONS)
        .union(Update::X_REGS);
    let enter_live = match kind {
        // Port of emit_fixed_apply's `emit_enter_runtime(Arity.get() + 2)`,
        // erts/emulator/beam/jit/arm/instr_call.cpp:270-274, OTP-29.1.1.
        ApplyKind::Fixed(arity) => {
            if arity > 255 {
                return Err(ModuleError::InvalidOperand("apply arity exceeds 255"));
            }
            arity as usize + 2
        }
        // Port of emit_variable_apply's `emit_enter_runtime(..., 3)`,
        // erts/emulator/beam/jit/arm/instr_call.cpp:217-218, OTP-29.1.1.
        _ => 3,
    };
    let dispatch = asm.code.new_label();
    let entry = asm.code.new_label();
    asm.code.bind(entry)?;
    if let ApplyKind::Fixed(arity) = kind {
        // ARG3 = arity before enter_runtime (instr_call.cpp:270).
        asm.code
            .emit(|e| e.mov_const(Gpr::x(2), u64::from(arity)))?;
    }
    emit_enter_runtime(&mut asm.code, enter_live, update)?;
    asm.code.emit(|e| {
        e.mov_reg(Gpr::x(0), C_P)?;
        crate::arm::beam_asm::load_x_reg_array(e, Gpr::x(1))
    })?;
    match kind {
        ApplyKind::Fixed(_) => {
            if tail {
                asm.code.adr(Gpr::x(3), entry)?;
            } else {
                asm.code.emit(|e| e.mov_const(Gpr::x(3), 0))?;
            }
            asm.code.emit(|e| e.mov_const(Gpr::x(4), 0))?;
            asm.fragment_call(addr(fixed_apply as *const ()))?;
        }
        // Port of erts/emulator/beam/jit/arm/instr_call.cpp:205-244 (emit_variable_apply),
        // OTP-29.1.1: any number of X registers is live after the call.
        _ => {
            if tail {
                asm.code.adr(Gpr::x(2), entry)?;
            } else {
                asm.code.emit(|e| e.mov_const(Gpr::x(2), 0))?;
            }
            asm.code.emit(|e| e.mov_const(Gpr::x(3), 0))?;
            asm.fragment_call(addr(apply as *const ()))?;
        }
    }
    // Port of emit_leave_runtime without a live count: reload all six cached X registers
    // (instr_call.cpp:236-237, 289-292).
    emit_leave_runtime(&mut asm.code, 6, update)?;
    asm.code.cbnz(Gpr::x(0), dispatch)?;
    // Port of erts/emulator/beam/jit/arm/instr_call.cpp:239-240,294-295
    // (emit_raise_exception(entry, &apply3_mfa)), OTP-29.1.1: X0..X2 hold the operands.
    static APPLY3_MFA: std::sync::OnceLock<crate::bif::ErtsCodeMfa> = std::sync::OnceLock::new();
    let mfa = APPLY3_MFA.get_or_init(|| crate::bif::ErtsCodeMfa {
        module: arinsal_term::Term::atom(arinsal_term::atoms::ERLANG).word(),
        function: arinsal_term::Term::atom(arinsal_term::atoms::APPLY).word(),
        arity: 3,
    });
    asm.branch_error_with_mfa(std::ptr::from_ref(mfa) as usize)?;
    asm.code.bind(dispatch)?;
    // Port of beam_asm.hpp:388-403 (emit_setup_dispatchable_call): ARG1 is the Export*.
    asm.code
        .emit(|e| e.ldr_regoff(Gpr::x(14), Gpr::x(0), ACTIVE_CODE_IX, 3))?;
    if tail {
        asm.emit_leave_frame()?;
        asm.code.emit(|e| e.br(Gpr::x(14)))?;
    } else {
        asm.code.emit(|e| e.blr(Gpr::x(14)))?;
        asm.code.bind(continuation)?;
    }
    Ok(())
}

// Port of erts/emulator/beam/jit/arm/instr_fun.cpp:330-344 (emit_i_apply_fun,
// emit_i_apply_fun_only), OTP-29.1.1: the shared fragment unpacks the argument list into the
// X registers and leaves the arity in x2 and the fun in x4 for `call_fun`. A malformed or too
// long list raises with erlang:apply/2 as the current MFA.
fn emit_apply_fun(
    asm: &mut BeamModuleAssembler,
    runtime: ApplyRuntime,
    tail: bool,
) -> Result<(), ModuleError> {
    if runtime.apply_fun_shared == 0 {
        return Err(ModuleError::InvalidOperand("apply/2 fragment is missing"));
    }
    let unpacked = asm.code.new_label();
    asm.fragment_call(runtime.apply_fun_shared)?;
    asm.code.cbz(Gpr::x(0), unpacked)?;
    // Port of erts/emulator/beam/jit/arm/instr_fun.cpp:300-316 (emit_apply_fun_shared,
    // `raise_error`: `ARG4 = &apply_mfa`), OTP-29.1.1.
    static APPLY2_MFA: std::sync::OnceLock<crate::bif::ErtsCodeMfa> = std::sync::OnceLock::new();
    let mfa = APPLY2_MFA.get_or_init(|| crate::bif::ErtsCodeMfa {
        module: arinsal_term::Term::atom(arinsal_term::atoms::ERLANG).word(),
        function: arinsal_term::Term::atom(arinsal_term::atoms::APPLY).word(),
        arity: 2,
    });
    asm.branch_error_with_mfa(std::ptr::from_ref(mfa) as usize)?;
    asm.code.bind(unpacked)?;
    asm.emit_dynamic_fun_call(runtime.fun_resolver, tail, 0)?;
    Ok(())
}
