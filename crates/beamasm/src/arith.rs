//! Integer arithmetic emission for BeamAsm modules.

use arinsal_a64::buf::Label;
use arinsal_a64::enc::{Cond, Gpr, Shift, Shifted, is_logical_immediate};

use crate::module::{ArgVal, BeamModuleAssembler, ModuleError};
use crate::types::{
    ArgType, TypedArg, is_bsl_small, is_diff_small_if_args_are_small,
    is_product_small_if_args_are_small, is_sum_small_if_args_are_small, type_id,
};

/// Runtime fallback for arithmetic that cannot return a small integer.
///
/// The VM supplies this hook. Arguments and the result use OTP tagged-term words.
pub type ArithHelper = unsafe extern "C" fn(
    process: *mut crate::ProcessHeader,
    op: u32,
    lhs: u64,
    rhs: u64,
    extra: u64,
) -> u64;

const ARG1: Gpr = Gpr::x(0);
const ARG2: Gpr = Gpr::x(14);
const ARG3: Gpr = Gpr::x(17);
const TMP1: Gpr = Gpr::x(8);
const TMP: Gpr = Gpr::x(9);

/// erts register names used by `emit_i_mul_add` (ARG2/ARG3 here are x1/x2, not the helper ABI).
const M_ARG2: Gpr = Gpr::x(1);
const M_ARG3: Gpr = Gpr::x(2);
const M_ARG4: Gpr = Gpr::x(3);
const M_TMP2: Gpr = Gpr::x(9);
const M_TMP3: Gpr = Gpr::x(10);
const M_TMP4: Gpr = Gpr::x(11);

/// Scheduler `tmp_mem[1]`, where the fused div/rem helper publishes the remainder.
const TMP_MEM_REM: u32 = 16_392;

/// Base and byte offset of an operand that lives in memory (not a cached X register).
fn mem_operand(arg: ArgVal) -> Option<(Gpr, i64)> {
    match arg {
        ArgVal::XMemory(index) if index < 1024 => Some((Gpr::x(19), i64::from(index) * 8)),
        ArgVal::Y(index) => index
            .checked_mul(8)
            .map(|offset| (Gpr::x(20), i64::from(offset))),
        _ => None,
    }
}

/// Untagged small factor and its shift (`ctz`) when it is a positive power of two.
fn small_factor(src: &TypedArg) -> (i64, i32) {
    if !src.is_small() {
        return (0, -1);
    }
    let factor = src.small_value();
    if factor > 0 && factor.count_ones() == 1 {
        (factor, factor.trailing_zeros() as i32)
    } else {
        (factor, -1)
    }
}

#[derive(Clone, Copy)]
enum BinaryOp {
    Add,
    Sub,
    Mul,
    Div,
    Rem,
    And,
    Or,
    Xor,
}

impl BinaryOp {
    const fn id(self) -> u32 {
        match self {
            Self::Add => 0,
            Self::Sub => 1,
            Self::Mul => 2,
            Self::Div => 3,
            Self::Rem => 4,
            Self::And => 5,
            Self::Or => 6,
            Self::Xor => 7,
        }
    }
}

impl BeamModuleAssembler {
    /// Emits `i_plus`; non-small operands and small overflow use the VM hook.
    // Port of erts/emulator/beam/jit/arm/instr_arith.cpp:145-244, OTP-29.1.1
    pub fn emit_i_plus(
        &mut self,
        lhs: ArgVal,
        rhs: ArgVal,
        dst: ArgVal,
        helper: ArithHelper,
    ) -> Result<(), ModuleError> {
        self.emit_i_plus_with_fail(lhs, rhs, dst, 0, helper)
    }

    /// Emits `i_plus`, branching to the BEAM failure label when guard arithmetic fails.
    // Port of erts/emulator/beam/jit/arm/instr_arith.cpp:145-244, OTP-29.1.1.
    pub fn emit_i_plus_with_fail(
        &mut self,
        lhs: ArgVal,
        rhs: ArgVal,
        dst: ArgVal,
        fail: u32,
        helper: ArithHelper,
    ) -> Result<(), ModuleError> {
        self.emit_add_sub(true, lhs, rhs, dst, helper, fail)
    }

    /// Emits `i_minus`; non-small operands and small overflow use the VM hook.
    // Port of erts/emulator/beam/jit/arm/instr_arith.cpp:334-456, OTP-29.1.1
    pub fn emit_i_minus(
        &mut self,
        lhs: ArgVal,
        rhs: ArgVal,
        dst: ArgVal,
        helper: ArithHelper,
    ) -> Result<(), ModuleError> {
        self.emit_i_minus_with_fail(lhs, rhs, dst, 0, helper)
    }

    /// Emits `i_minus` with the BEAM guard failure behavior.
    // Port of erts/emulator/beam/jit/arm/instr_arith.cpp:334-456, OTP-29.1.1.
    pub fn emit_i_minus_with_fail(
        &mut self,
        lhs: ArgVal,
        rhs: ArgVal,
        dst: ArgVal,
        fail: u32,
        helper: ArithHelper,
    ) -> Result<(), ModuleError> {
        self.emit_add_sub(false, lhs, rhs, dst, helper, fail)
    }

    /// Emits `i_times` with a 60-bit result check.
    // Port of erts/emulator/beam/jit/arm/ops.tab (`stimes` → `i_mul_add` with increment 0)
    // and instr_arith.cpp:542-731 (emit_i_mul_add), OTP-29.1.1.
    pub fn emit_i_times(
        &mut self,
        lhs: ArgVal,
        rhs: ArgVal,
        dst: ArgVal,
        helper: ArithHelper,
    ) -> Result<(), ModuleError> {
        self.emit_i_times_with_fail(lhs, rhs, dst, 0, helper)
    }

    /// Emits `i_times` with the BEAM guard failure behavior.
    // Port of erts/emulator/beam/jit/arm/instr_arith.cpp:542-731 (emit_i_mul_add), OTP-29.1.1.
    pub fn emit_i_times_with_fail(
        &mut self,
        lhs: ArgVal,
        rhs: ArgVal,
        dst: ArgVal,
        fail: u32,
        helper: ArithHelper,
    ) -> Result<(), ModuleError> {
        // `i_mul_add Fail S1 S2 Dst i Dst`: the addend is the small integer 0.
        self.emit_i_mul_add_with_fail(lhs, rhs, dst, ArgVal::Immediate(0xf), dst, fail, helper)
    }

    /// Emits `i_mul_add`: `Dst = Src1 * Src2 + Src4`, with `Src3` used for the sum type check.
    // Port of erts/emulator/beam/jit/arm/instr_arith.cpp:542-731, OTP-29.1.1.
    pub fn emit_i_mul_add(
        &mut self,
        src1: ArgVal,
        src2: ArgVal,
        src3: ArgVal,
        src4: ArgVal,
        dst: ArgVal,
        helper: ArithHelper,
    ) -> Result<(), ModuleError> {
        self.emit_i_mul_add_with_fail(src1, src2, src3, src4, dst, 0, helper)
    }

    /// Emits `i_mul_add` with the BEAM guard failure behavior.
    // Port of erts/emulator/beam/jit/arm/instr_arith.cpp:542-731, OTP-29.1.1.
    #[allow(clippy::too_many_arguments)]
    pub fn emit_i_mul_add_with_fail(
        &mut self,
        src1: ArgVal,
        src2: ArgVal,
        src3: ArgVal,
        src4: ArgVal,
        dst: ArgVal,
        fail: u32,
        helper: ArithHelper,
    ) -> Result<(), ModuleError> {
        self.emit_mul_add(src1, src2, src3, src4, dst, helper, fail)
    }

    /// Emits `i_int_div`, including divide-by-zero and minimum-value overflow fallback.
    // Port of erts/emulator/beam/jit/arm/instr_arith.cpp:1043-1076, OTP-29.1.1
    pub fn emit_i_int_div(
        &mut self,
        lhs: ArgVal,
        rhs: ArgVal,
        dst: ArgVal,
        helper: ArithHelper,
    ) -> Result<(), ModuleError> {
        self.emit_i_int_div_with_fail(lhs, rhs, dst, 0, helper)
    }

    /// Emits `i_int_div` with the BEAM guard failure behavior.
    // Port of erts/emulator/beam/jit/arm/instr_arith.cpp:1043-1076, OTP-29.1.1.
    pub fn emit_i_int_div_with_fail(
        &mut self,
        lhs: ArgVal,
        rhs: ArgVal,
        dst: ArgVal,
        fail: u32,
        helper: ArithHelper,
    ) -> Result<(), ModuleError> {
        self.emit_div_rem(lhs, rhs, dst, ArgVal::X(0), helper, fail, true, false)
    }

    /// Emits fused `i_div_rem`: quotient and remainder from one division.
    // Port of erts/emulator/beam/jit/arm/instr_arith.cpp:1055-1065, OTP-29.1.1.
    pub fn emit_i_div_rem(
        &mut self,
        lhs: ArgVal,
        rhs: ArgVal,
        quotient: ArgVal,
        remainder: ArgVal,
        helper: ArithHelper,
    ) -> Result<(), ModuleError> {
        self.emit_i_div_rem_with_fail(lhs, rhs, quotient, remainder, 0, helper)
    }

    /// Emits fused `i_div_rem` with the BEAM guard failure behavior.
    // Port of erts/emulator/beam/jit/arm/instr_arith.cpp:1055-1065, OTP-29.1.1.
    pub fn emit_i_div_rem_with_fail(
        &mut self,
        lhs: ArgVal,
        rhs: ArgVal,
        quotient: ArgVal,
        remainder: ArgVal,
        fail: u32,
        helper: ArithHelper,
    ) -> Result<(), ModuleError> {
        let need_div = quotient != remainder;
        self.emit_div_rem(lhs, rhs, quotient, remainder, helper, fail, need_div, true)
    }

    /// Emits fused `i_rem_div`: remainder and quotient from one division.
    // Port of erts/emulator/beam/jit/arm/instr_arith.cpp:1043-1053, OTP-29.1.1.
    pub fn emit_i_rem_div(
        &mut self,
        lhs: ArgVal,
        rhs: ArgVal,
        remainder: ArgVal,
        quotient: ArgVal,
        helper: ArithHelper,
    ) -> Result<(), ModuleError> {
        self.emit_i_rem_div_with_fail(lhs, rhs, remainder, quotient, 0, helper)
    }

    /// Emits fused `i_rem_div` with the BEAM guard failure behavior.
    // Port of erts/emulator/beam/jit/arm/instr_arith.cpp:1043-1053, OTP-29.1.1.
    pub fn emit_i_rem_div_with_fail(
        &mut self,
        lhs: ArgVal,
        rhs: ArgVal,
        remainder: ArgVal,
        quotient: ArgVal,
        fail: u32,
        helper: ArithHelper,
    ) -> Result<(), ModuleError> {
        let need_rem = quotient != remainder;
        self.emit_div_rem(lhs, rhs, quotient, remainder, helper, fail, true, need_rem)
    }

    /// Emits `i_m_div` (`/`): always a runtime call, like erts.
    // Port of erts/emulator/beam/jit/arm/instr_arith.cpp:1089-1125 (emit_i_m_div), OTP-29.1.1
    pub fn emit_i_m_div(
        &mut self,
        lhs: ArgVal,
        rhs: ArgVal,
        dst: ArgVal,
        helper: ArithHelper,
    ) -> Result<(), ModuleError> {
        self.emit_helper_operation(12, lhs, rhs, dst, helper)
    }

    /// Emits `i_rem` with the Erlang remainder sign rule.
    // Port of erts/emulator/beam/jit/arm/instr_arith.cpp:1043-1088, OTP-29.1.1
    pub fn emit_i_rem(
        &mut self,
        lhs: ArgVal,
        rhs: ArgVal,
        dst: ArgVal,
        helper: ArithHelper,
    ) -> Result<(), ModuleError> {
        self.emit_i_rem_with_fail(lhs, rhs, dst, 0, helper)
    }

    /// Emits `i_rem` with the BEAM guard failure behavior.
    // Port of erts/emulator/beam/jit/arm/instr_arith.cpp:1043-1088, OTP-29.1.1.
    pub fn emit_i_rem_with_fail(
        &mut self,
        lhs: ArgVal,
        rhs: ArgVal,
        dst: ArgVal,
        fail: u32,
        helper: ArithHelper,
    ) -> Result<(), ModuleError> {
        self.emit_div_rem(lhs, rhs, ArgVal::X(0), dst, helper, fail, false, true)
    }

    /// Emits `i_band`.
    // Port of erts/emulator/beam/jit/arm/instr_arith.cpp:1172-1249, OTP-29.1.1
    pub fn emit_i_band(
        &mut self,
        lhs: ArgVal,
        rhs: ArgVal,
        dst: ArgVal,
        helper: ArithHelper,
    ) -> Result<(), ModuleError> {
        self.emit_i_band_with_fail(lhs, rhs, dst, 0, helper)
    }

    /// Emits `i_band` with the BEAM guard failure behavior.
    // Port of erts/emulator/beam/jit/arm/instr_arith.cpp:1172-1249, OTP-29.1.1.
    pub fn emit_i_band_with_fail(
        &mut self,
        lhs: ArgVal,
        rhs: ArgVal,
        dst: ArgVal,
        fail: u32,
        helper: ArithHelper,
    ) -> Result<(), ModuleError> {
        self.emit_band(lhs, rhs, dst, helper, fail)
    }

    /// Emits `i_bor`.
    // Port of erts/emulator/beam/jit/arm/instr_arith.cpp:1268-1323, OTP-29.1.1
    pub fn emit_i_bor(
        &mut self,
        lhs: ArgVal,
        rhs: ArgVal,
        dst: ArgVal,
        helper: ArithHelper,
    ) -> Result<(), ModuleError> {
        self.emit_i_bor_with_fail(lhs, rhs, dst, 0, helper)
    }

    /// Emits `i_bor` with the BEAM guard failure behavior.
    // Port of erts/emulator/beam/jit/arm/instr_arith.cpp:1268-1323, OTP-29.1.1.
    pub fn emit_i_bor_with_fail(
        &mut self,
        lhs: ArgVal,
        rhs: ArgVal,
        dst: ArgVal,
        fail: u32,
        helper: ArithHelper,
    ) -> Result<(), ModuleError> {
        self.emit_bor(lhs, rhs, dst, helper, fail)
    }

    /// Emits `i_bxor`.
    // Port of erts/emulator/beam/jit/arm/instr_arith.cpp:1343-1388, OTP-29.1.1
    pub fn emit_i_bxor(
        &mut self,
        lhs: ArgVal,
        rhs: ArgVal,
        dst: ArgVal,
        helper: ArithHelper,
    ) -> Result<(), ModuleError> {
        self.emit_i_bxor_with_fail(lhs, rhs, dst, 0, helper)
    }

    /// Emits `i_bxor` with the BEAM guard failure behavior.
    // Port of erts/emulator/beam/jit/arm/instr_arith.cpp:1343-1388, OTP-29.1.1.
    pub fn emit_i_bxor_with_fail(
        &mut self,
        lhs: ArgVal,
        rhs: ArgVal,
        dst: ArgVal,
        fail: u32,
        helper: ArithHelper,
    ) -> Result<(), ModuleError> {
        self.emit_bxor(lhs, rhs, dst, helper, fail)
    }

    /// Emits `i_bsl` through the VM helper, which handles arbitrary precision shifts.
    // Port of erts/emulator/beam/jit/arm/instr_arith.cpp:1628-1771, OTP-29.1.1
    pub fn emit_i_bsl(
        &mut self,
        lhs: ArgVal,
        rhs: ArgVal,
        dst: ArgVal,
        helper: ArithHelper,
    ) -> Result<(), ModuleError> {
        self.emit_i_bsl_with_fail(lhs, rhs, dst, 0, helper)
    }

    /// Emits `i_bsl` with the BEAM guard failure behavior.
    // Port of erts/emulator/beam/jit/arm/instr_arith.cpp:1628-1771, OTP-29.1.1.
    pub fn emit_i_bsl_with_fail(
        &mut self,
        lhs: ArgVal,
        rhs: ArgVal,
        dst: ArgVal,
        fail: u32,
        helper: ArithHelper,
    ) -> Result<(), ModuleError> {
        self.emit_bsl(lhs, rhs, dst, helper, fail)
    }

    /// Emits `i_bsr` through the VM helper, preserving arithmetic right-shift semantics.
    // Port of erts/emulator/beam/jit/arm/instr_arith.cpp:1507-1608, OTP-29.1.1
    pub fn emit_i_bsr(
        &mut self,
        lhs: ArgVal,
        rhs: ArgVal,
        dst: ArgVal,
        helper: ArithHelper,
    ) -> Result<(), ModuleError> {
        self.emit_i_bsr_with_fail(lhs, rhs, dst, 0, helper)
    }

    /// Emits `i_bsr` with the BEAM guard failure behavior.
    // Port of erts/emulator/beam/jit/arm/instr_arith.cpp:1507-1608, OTP-29.1.1.
    pub fn emit_i_bsr_with_fail(
        &mut self,
        lhs: ArgVal,
        rhs: ArgVal,
        dst: ArgVal,
        fail: u32,
        helper: ArithHelper,
    ) -> Result<(), ModuleError> {
        self.emit_bsr(lhs, rhs, dst, helper, fail)
    }

    /// Emits `i_bnot` through the arithmetic hook, which also handles bignums.
    // Port of erts/emulator/beam/jit/arm/instr_arith.cpp:1456-1490, OTP-29.1.1
    pub fn emit_i_bnot(
        &mut self,
        src: ArgVal,
        dst: ArgVal,
        helper: ArithHelper,
    ) -> Result<(), ModuleError> {
        self.emit_i_bnot_with_fail(src, dst, 0, helper)
    }

    /// Emits `i_bnot` with the BEAM guard failure behavior.
    // Port of erts/emulator/beam/jit/arm/instr_arith.cpp:1456-1490, OTP-29.1.1.
    pub fn emit_i_bnot_with_fail(
        &mut self,
        src: ArgVal,
        dst: ArgVal,
        fail: u32,
        helper: ArithHelper,
    ) -> Result<(), ModuleError> {
        self.emit_unary_small(8, src, dst, helper, false, fail)
    }

    /// Emits `i_unary_minus` with small-integer overflow fallback.
    // Port of erts/emulator/beam/jit/arm/instr_arith.cpp:246-333, OTP-29.1.1
    pub fn emit_i_unary_minus(
        &mut self,
        src: ArgVal,
        dst: ArgVal,
        helper: ArithHelper,
    ) -> Result<(), ModuleError> {
        self.emit_i_unary_minus_with_fail(src, dst, 0, helper)
    }

    /// Emits `i_unary_minus` with the BEAM guard failure behavior.
    // Port of erts/emulator/beam/jit/arm/instr_arith.cpp:246-333, OTP-29.1.1.
    pub fn emit_i_unary_minus_with_fail(
        &mut self,
        src: ArgVal,
        dst: ArgVal,
        fail: u32,
        helper: ArithHelper,
    ) -> Result<(), ModuleError> {
        self.emit_unary_small(9, src, dst, helper, true, fail)
    }

    /// Emits `i_increment` for a source and immediate BEAM small integer.
    // Port of erts/emulator/beam/jit/arm/instr_arith.cpp:145-244, OTP-29.1.1
    pub fn emit_i_increment(
        &mut self,
        src: ArgVal,
        amount: i64,
        dst: ArgVal,
        helper: ArithHelper,
    ) -> Result<(), ModuleError> {
        self.emit_i_plus(
            src,
            ArgVal::Immediate(((amount as u64) << 4) | 15),
            dst,
            helper,
        )
    }

    /// Emits a float load using the VM hook to validate and unbox the source term.
    // Port of erts/emulator/beam/jit/arm/instr_float.cpp:71-79, OTP-29.1.1
    pub fn emit_fload(
        &mut self,
        source: ArgVal,
        destination: ArgVal,
        helper: ArithHelper,
    ) -> Result<(), ModuleError> {
        self.emit_unary_fallback(16, source, destination, helper)
    }

    /// Emits float storage through the VM hook, which allocates a boxed flonum.
    // Port of erts/emulator/beam/jit/arm/instr_float.cpp:81-94, OTP-29.1.1
    pub fn emit_fstore(
        &mut self,
        source: ArgVal,
        destination: ArgVal,
        helper: ArithHelper,
    ) -> Result<(), ModuleError> {
        self.emit_unary_fallback(17, source, destination, helper)
    }

    /// Emits numeric conversion through the VM hook.
    // Port of erts/emulator/beam/jit/arm/instr_float.cpp:138-195, OTP-29.1.1
    pub fn emit_fconv(
        &mut self,
        source: ArgVal,
        destination: ArgVal,
        helper: ArithHelper,
    ) -> Result<(), ModuleError> {
        self.emit_unary_fallback(18, source, destination, helper)
    }

    /// Emits `fadd` through the VM arithmetic hook; operands/results are IEEE-754 bits.
    // Port of erts/emulator/beam/jit/arm/instr_float.cpp:198-202, OTP-29.1.1
    pub fn emit_fadd(
        &mut self,
        lhs: ArgVal,
        rhs: ArgVal,
        destination: ArgVal,
        helper: ArithHelper,
    ) -> Result<(), ModuleError> {
        self.emit_helper_operation(19, lhs, rhs, destination, helper)
    }

    /// Emits `fsub` through the VM arithmetic hook; operands/results are IEEE-754 bits.
    // Port of erts/emulator/beam/jit/arm/instr_float.cpp:204-208, OTP-29.1.1
    pub fn emit_fsub(
        &mut self,
        lhs: ArgVal,
        rhs: ArgVal,
        destination: ArgVal,
        helper: ArithHelper,
    ) -> Result<(), ModuleError> {
        self.emit_helper_operation(20, lhs, rhs, destination, helper)
    }

    /// Emits `fmul` through the VM arithmetic hook; operands/results are IEEE-754 bits.
    // Port of erts/emulator/beam/jit/arm/instr_float.cpp:210-214, OTP-29.1.1
    pub fn emit_fmul(
        &mut self,
        lhs: ArgVal,
        rhs: ArgVal,
        destination: ArgVal,
        helper: ArithHelper,
    ) -> Result<(), ModuleError> {
        self.emit_helper_operation(21, lhs, rhs, destination, helper)
    }

    /// Emits `fdiv` through the VM arithmetic hook; operands/results are IEEE-754 bits.
    // Port of erts/emulator/beam/jit/arm/instr_float.cpp:216-220, OTP-29.1.1
    pub fn emit_fdiv(
        &mut self,
        lhs: ArgVal,
        rhs: ArgVal,
        destination: ArgVal,
        helper: ArithHelper,
    ) -> Result<(), ModuleError> {
        self.emit_helper_operation(22, lhs, rhs, destination, helper)
    }

    /// Emits `fnegate` through the VM hook; the input must be a finite float.
    // Port of erts/emulator/beam/jit/arm/instr_float.cpp:222-232, OTP-29.1.1
    pub fn emit_fnegate(
        &mut self,
        source: ArgVal,
        destination: ArgVal,
        helper: ArithHelper,
    ) -> Result<(), ModuleError> {
        self.emit_unary_fallback(23, source, destination, helper)
    }

    fn emit_helper_operation(
        &mut self,
        op: u32,
        lhs: ArgVal,
        rhs: ArgVal,
        dst: ArgVal,
        helper: ArithHelper,
    ) -> Result<(), ModuleError> {
        let left = self.source_reg(lhs)?;
        self.code.emit(|e| e.mov_reg(Gpr::x(14), left))?;
        let right = self.source_reg_into(rhs, Gpr::x(17))?;
        self.code.emit(|e| e.mov_reg(Gpr::x(17), right))?;
        self.emit_helper(op, Gpr::x(14), Gpr::x(17), helper, None)?;
        self.store_result(dst, Gpr::x(0))
    }

    /// Takes the operand types supplied by [`Self::set_arith_types`]; untyped operands are `Any`.
    fn take_arith_args(&mut self, lhs: ArgVal, rhs: ArgVal) -> (TypedArg, TypedArg) {
        let types = self.arith_types.take().unwrap_or([ArgType::ANY; 4]);
        (TypedArg::new(lhs, types[0]), TypedArg::new(rhs, types[1]))
    }

    /// `load_sources(LHS, ARG2, RHS, ARG3)`, pairing adjacent memory operands with `ldp`.
    // Port of erts/emulator/beam/jit/arm/beam_asm.hpp:1586-1606, OTP-29.1.1.
    fn load_sources(&mut self, lhs: &TypedArg, rhs: &TypedArg) -> Result<(Gpr, Gpr), ModuleError> {
        self.load_pair(lhs.val, ARG2, rhs.val, ARG3)
    }

    /// Loads two operands, using `ldp` when they occupy adjacent X-array or Y slots.
    // Port of erts/emulator/beam/jit/arm/beam_asm.hpp:1586-1606 (load_sources) and
    // :1862-1895 (safe_ldp), OTP-29.1.1.
    fn load_pair(
        &mut self,
        src1: ArgVal,
        tmp1: Gpr,
        src2: ArgVal,
        tmp2: Gpr,
    ) -> Result<(Gpr, Gpr), ModuleError> {
        if tmp1 != tmp2
            && let (Some((base1, off1)), Some((base2, off2))) =
                (mem_operand(src1), mem_operand(src2))
            && base1 == base2
        {
            if off1 + 8 == off2 {
                self.safe_ldp(tmp1, tmp2, base1, off1 as u32)?;
                return Ok((tmp1, tmp2));
            }
            if off2 + 8 == off1 {
                self.safe_ldp(tmp2, tmp1, base2, off2 as u32)?;
                return Ok((tmp1, tmp2));
            }
        }
        let left = self.source_reg_into(src1, tmp1)?;
        let right = self.source_reg_into(src2, tmp2)?;
        Ok((left, right))
    }

    /// `emit_is_boxed(next, reg)`: branches when bit 0 is set, i.e. the value is not boxed.
    // Port of erts/emulator/beam/jit/arm/beam_asm.hpp:631-636, OTP-29.1.1.
    fn branch_if_bit0(&mut self, reg: Gpr, label: Label) -> Result<(), ModuleError> {
        self.code.tbnz(reg, 0, label)?;
        Ok(())
    }

    /// `emit_are_both_small`: jumps to `next` when both operands are small integers.
    // Port of erts/emulator/beam/jit/arm/instr_arith.cpp:62-112, OTP-29.1.1
    fn emit_are_both_small(
        &mut self,
        lhs: &TypedArg,
        lhs_reg: Gpr,
        rhs: &TypedArg,
        rhs_reg: Gpr,
        next: Label,
    ) -> Result<(), ModuleError> {
        let int_or_boxed = type_id::INTEGER | type_id::ALWAYS_BOXED;
        if rhs.is_literal() {
            // One operand is never small.
        } else if rhs.always_small() && lhs.always_one_of(int_or_boxed) {
            self.branch_if_bit0(lhs_reg, next)?;
        } else if lhs.always_small() && rhs.always_one_of(int_or_boxed) {
            self.branch_if_bit0(rhs_reg, next)?;
        } else if lhs.always_one_of(int_or_boxed) && rhs.always_one_of(int_or_boxed) {
            self.code.emit(|e| {
                e.and_reg(
                    TMP1,
                    lhs_reg,
                    Shifted {
                        reg: rhs_reg,
                        shift: Shift::Lsl,
                        amount: 0,
                    },
                )
            })?;
            self.branch_if_bit0(TMP1, next)?;
        } else {
            self.emit_tag_of_both(lhs, lhs_reg, rhs, rhs_reg)?;
            self.code.emit(|e| e.cmp_imm(TMP1, 15, false))?;
            self.code.b_cond(Cond::Eq, next)?;
        }
        Ok(())
    }

    /// TMP1 = the tag bits that are all ones only when both operands are small.
    fn emit_tag_of_both(
        &mut self,
        lhs: &TypedArg,
        lhs_reg: Gpr,
        rhs: &TypedArg,
        rhs_reg: Gpr,
    ) -> Result<(), ModuleError> {
        self.code.emit(|e| {
            if rhs.always_small() {
                e.and_imm(TMP1, lhs_reg, 15)
            } else if lhs.always_small() {
                e.and_imm(TMP1, rhs_reg, 15)
            } else {
                e.and_reg(
                    TMP1,
                    lhs_reg,
                    Shifted {
                        reg: rhs_reg,
                        shift: Shift::Lsl,
                        amount: 0,
                    },
                )?;
                e.and_imm(TMP1, TMP1, 15)
            }
        })?;
        Ok(())
    }

    /// `emit_add_sub_types`: jumps to `next` when the flags say no overflow and both are small.
    // Port of erts/emulator/beam/jit/arm/instr_arith.cpp:31-60, OTP-29.1.1
    fn emit_add_sub_types(
        &mut self,
        is_small_result: bool,
        lhs: &TypedArg,
        lhs_reg: Gpr,
        rhs: &TypedArg,
        rhs_reg: Gpr,
        next: Label,
    ) -> Result<(), ModuleError> {
        if is_small_result {
            self.emit_are_both_small(lhs, lhs_reg, rhs, rhs_reg, next)
        } else if rhs.is_literal() {
            // Skipping test for small.
            Ok(())
        } else {
            self.emit_tag_of_both(lhs, lhs_reg, rhs, rhs_reg)?;
            self.code.emit(|e| e.ccmp_imm(TMP1, 15, 0, Cond::Vc))?;
            self.code.b_cond(Cond::Eq, next)?;
            Ok(())
        }
    }

    /// Calls the arithmetic hook for the slow path (`erts_mixed_*`, `erts_band`, ...).
    fn emit_arith_call(
        &mut self,
        op: u32,
        lhs: Gpr,
        rhs: Gpr,
        helper: ArithHelper,
        fail: u32,
    ) -> Result<(), ModuleError> {
        self.emit_helper(op, lhs, rhs, helper, (fail != 0).then_some(fail))
    }

    /// `i_plus` / `i_minus`.
    // Port of erts/emulator/beam/jit/arm/instr_arith.cpp:145-213 (emit_i_plus) and
    // :334-401 (emit_i_minus), OTP-29.1.1
    fn emit_add_sub(
        &mut self,
        add: bool,
        lhs: ArgVal,
        rhs: ArgVal,
        dst: ArgVal,
        helper: ArithHelper,
        fail: u32,
    ) -> Result<(), ModuleError> {
        let (l, r) = self.take_arith_args(lhs, rhs);
        let rhs_is_arm_literal = r.is_small() && r.word() <= 4095;
        let is_small_result = if add {
            is_sum_small_if_args_are_small(&l, &r)
        } else {
            is_diff_small_if_args_are_small(&l, &r)
        };

        if l.always_small() && r.always_small() && is_small_result {
            let d = self.init_destination(dst, ARG1);
            if rhs_is_arm_literal {
                let left = self.source_reg_into(l.val, ARG2)?;
                let cleared_tag = (r.word() & !15) as u16;
                self.code.emit(|e| {
                    if add {
                        e.add_imm(d, left, cleared_tag, false)
                    } else {
                        e.sub_imm(d, left, cleared_tag, false)
                    }
                })?;
            } else {
                let (left, right) = self.load_sources(&l, &r)?;
                self.code.emit(|e| {
                    e.and_imm(TMP1, right, !15u64)?;
                    if add {
                        e.add_reg(d, left, TMP1, Shift::Lsl, 0)
                    } else {
                        e.sub_reg(d, left, TMP1, Shift::Lsl, 0)
                    }
                })?;
            }
            return self.store_result(dst, d);
        }

        let next = self.code.new_label();
        let (left, right) = self.load_sources(&l, &r)?;
        if r.is_literal() {
            // One operand is never small.
        } else if rhs_is_arm_literal {
            let cleared_tag = (r.word() & !15) as u16;
            self.code.emit(|e| {
                if add {
                    e.adds_imm(ARG1, left, cleared_tag, false)
                } else {
                    e.subs_imm(ARG1, left, cleared_tag, false)
                }
            })?;
        } else {
            self.code.emit(|e| {
                e.and_imm(TMP1, right, !15u64)?;
                if add {
                    e.adds_reg(ARG1, left, TMP1, Shift::Lsl, 0)
                } else {
                    e.subs_reg(ARG1, left, TMP1, Shift::Lsl, 0)
                }
            })?;
        }
        self.emit_add_sub_types(is_small_result, &l, left, &r, right, next)?;
        let op = if add { BinaryOp::Add } else { BinaryOp::Sub };
        self.emit_arith_call(op.id(), left, right, helper, fail)?;
        self.code.bind(next)?;
        self.store_result(dst, ARG1)
    }

    /// `i_band`.
    // Port of erts/emulator/beam/jit/arm/instr_arith.cpp:1172-1249, OTP-29.1.1
    fn emit_band(
        &mut self,
        lhs: ArgVal,
        rhs: ArgVal,
        dst: ArgVal,
        helper: ArithHelper,
        fail: u32,
    ) -> Result<(), ModuleError> {
        let (l, r) = self.take_arith_args(lhs, rhs);
        if l.always_small() && r.is_small() && is_logical_immediate(r.word(), 64) {
            // TAG & TAG = TAG, so the result needs no tagging.
            let left = self.source_reg_into(l.val, ARG2)?;
            let d = self.init_destination(dst, ARG1);
            self.code.emit(|e| e.and_imm(d, left, r.word()))?;
            return self.store_result(dst, d);
        }
        let (left, right) = self.load_sources(&l, &r)?;
        let d = self.init_destination(dst, ARG1);
        if l.always_small() && r.always_small() {
            self.code.emit(|e| {
                e.and_reg(
                    d,
                    left,
                    Shifted {
                        reg: right,
                        shift: Shift::Lsl,
                        amount: 0,
                    },
                )
            })?;
            return self.store_result(dst, d);
        }
        let next = self.code.new_label();
        if !r.is_literal() {
            self.code.emit(|e| {
                e.and_reg(
                    ARG1,
                    left,
                    Shifted {
                        reg: right,
                        shift: Shift::Lsl,
                        amount: 0,
                    },
                )
            })?;
            let int_or_boxed = type_id::INTEGER | type_id::ALWAYS_BOXED;
            if l.always_one_of(int_or_boxed) && r.always_one_of(int_or_boxed) {
                self.branch_if_bit0(ARG1, next)?;
            } else {
                // All other term types have at least one zero in the low 4 bits, so the
                // result is small iff both operands are.
                self.code.emit(|e| {
                    e.and_imm(TMP1, ARG1, 15)?;
                    e.cmp_imm(TMP1, 15, false)
                })?;
                self.code.b_cond(Cond::Eq, next)?;
            }
        }
        self.emit_arith_call(BinaryOp::And.id(), left, right, helper, fail)?;
        self.code.bind(next)?;
        self.store_result_via(dst, d, ARG1)
    }

    /// `i_bor`.
    // Port of erts/emulator/beam/jit/arm/instr_arith.cpp:1268-1335, OTP-29.1.1
    fn emit_bor(
        &mut self,
        lhs: ArgVal,
        rhs: ArgVal,
        dst: ArgVal,
        helper: ArithHelper,
        fail: u32,
    ) -> Result<(), ModuleError> {
        let (l, r) = self.take_arith_args(lhs, rhs);
        if l.always_small() && r.is_small() {
            let cleared = r.word() & !15;
            if is_logical_immediate(cleared, 64) {
                let left = self.source_reg_into(l.val, ARG2)?;
                let d = self.init_destination(dst, ARG1);
                self.code.emit(|e| e.orr_imm(d, left, cleared))?;
                return self.store_result(dst, d);
            }
        }
        let (left, right) = self.load_sources(&l, &r)?;
        let d = self.init_destination(dst, ARG1);
        if l.always_small() && r.always_small() {
            // TAG | TAG = TAG, so the result needs no tagging.
            self.code.emit(|e| {
                e.orr_reg(
                    d,
                    left,
                    Shifted {
                        reg: right,
                        shift: Shift::Lsl,
                        amount: 0,
                    },
                )
            })?;
            return self.store_result(dst, d);
        }
        let next = self.code.new_label();
        self.code.emit(|e| {
            e.orr_reg(
                ARG1,
                left,
                Shifted {
                    reg: right,
                    shift: Shift::Lsl,
                    amount: 0,
                },
            )
        })?;
        self.emit_are_both_small(&l, left, &r, right, next)?;
        self.emit_arith_call(BinaryOp::Or.id(), left, right, helper, fail)?;
        self.code.bind(next)?;
        self.store_result_via(dst, d, ARG1)
    }

    /// `i_bxor`.
    // Port of erts/emulator/beam/jit/arm/instr_arith.cpp:1343-1399, OTP-29.1.1
    fn emit_bxor(
        &mut self,
        lhs: ArgVal,
        rhs: ArgVal,
        dst: ArgVal,
        helper: ArithHelper,
        fail: u32,
    ) -> Result<(), ModuleError> {
        let (l, r) = self.take_arith_args(lhs, rhs);
        let (left, right) = self.load_sources(&l, &r)?;
        let d = self.init_destination(dst, ARG1);
        if l.always_small() && r.always_small() {
            // TAG ^ TAG = 0, so the tag is added again.
            self.code.emit(|e| {
                e.eor_reg(
                    d,
                    left,
                    Shifted {
                        reg: right,
                        shift: Shift::Lsl,
                        amount: 0,
                    },
                )?;
                e.orr_imm(d, d, 15)
            })?;
            return self.store_result(dst, d);
        }
        let next = self.code.new_label();
        self.code.emit(|e| {
            e.eor_reg(
                ARG1,
                left,
                Shifted {
                    reg: right,
                    shift: Shift::Lsl,
                    amount: 0,
                },
            )?;
            e.orr_imm(ARG1, ARG1, 15)
        })?;
        self.emit_are_both_small(&l, left, &r, right, next)?;
        self.emit_arith_call(BinaryOp::Xor.id(), left, right, helper, fail)?;
        self.code.bind(next)?;
        self.store_result_via(dst, d, ARG1)
    }

    /// `i_bsr`.
    // Port of erts/emulator/beam/jit/arm/instr_arith.cpp:1507-1599, OTP-29.1.1
    fn emit_bsr(
        &mut self,
        lhs: ArgVal,
        rhs: ArgVal,
        dst: ArgVal,
        helper: ArithHelper,
        fail: u32,
    ) -> Result<(), ModuleError> {
        let (l, r) = self.take_arith_args(lhs, rhs);
        let generic = self.code.new_label();
        let next = self.code.new_label();
        let left = self.source_reg_into(l.val, ARG2)?;
        let d = self.init_destination(dst, ARG1);
        let mut need_generic = true;

        if r.is_small() {
            let shift = r.small_value();
            if shift >= 0 {
                if l.always_small() {
                    need_generic = false;
                    self.code.emit(|e| e.mov_const(TMP1, 15))?;
                } else if l.always_one_of(type_id::NUMBER) {
                    self.code.tbz(left, 0, generic)?;
                    self.code.emit(|e| e.mov_const(TMP1, 15))?;
                } else {
                    self.code.emit(|e| {
                        e.and_imm(TMP1, left, 15)?;
                        e.cmp_imm(TMP1, 15, false)
                    })?;
                    self.code.b_cond(Cond::Ne, generic)?;
                }
                // The mask need not be cleared after shifting: the small tag sets all the
                // low bits anyway.
                let shift = shift.min(63) as u8;
                self.code.emit(|e| {
                    e.orr_reg(
                        d,
                        TMP1,
                        Shifted {
                            reg: left,
                            shift: Shift::Asr,
                            amount: shift,
                        },
                    )
                })?;
                if need_generic {
                    self.code.b(next)?;
                }
            }
            // A negative constant shift takes the generic path.
        } else {
            let right = self.source_reg_into(r.val, ARG3)?;
            // Both operands must be small and the shift count non-negative.
            self.code.emit(|e| {
                e.ands_imm(TMP1, right, (1u64 << 63) | 15)?;
                e.and_reg(
                    TMP1,
                    left,
                    Shifted {
                        reg: TMP1,
                        shift: Shift::Lsl,
                        amount: 0,
                    },
                )?;
                e.ccmp_imm(TMP1, 15, 0, Cond::Pl)
            })?;
            self.code.b_cond(Cond::Ne, generic)?;
            self.code.emit(|e| {
                e.asr_imm(TMP1, right, 4)?;
                e.mov_const(TMP, 63)?;
                e.cmp_reg(TMP1, TMP, Shift::Lsl, 0)?;
                e.csel(TMP1, TMP1, TMP, Cond::Le)?;
                e.asr_reg(d, left, TMP1)?;
                e.orr_imm(d, d, 15)
            })?;
            self.code.b(next)?;
        }

        self.code.bind(generic)?;
        if need_generic {
            let right = self.source_reg_into(r.val, ARG3)?;
            self.emit_arith_call(11, left, right, helper, fail)?;
            self.mov_if_needed(d, ARG1)?;
        }
        self.code.bind(next)?;
        self.store_result(dst, d)
    }

    /// `i_bsl`.
    // Port of erts/emulator/beam/jit/arm/instr_arith.cpp:1628-1771, OTP-29.1.1
    fn emit_bsl(
        &mut self,
        lhs: ArgVal,
        rhs: ArgVal,
        dst: ArgVal,
        helper: ArithHelper,
        fail: u32,
    ) -> Result<(), ModuleError> {
        let (l, r) = self.take_arith_args(lhs, rhs);
        let d = self.init_destination(dst, ARG1);

        if is_bsl_small(&l, &r) {
            // Operands and result are always small.
            if r.is_small() {
                let left = self.source_reg_into(l.val, ARG2)?;
                let count = r.small_value() as u8;
                self.code.emit(|e| {
                    e.and_imm(TMP1, left, !15u64)?;
                    e.lsl_imm(TMP1, TMP1, count)?;
                    e.orr_imm(d, TMP1, 15)
                })?;
            } else {
                let (left, right) = self.load_sources(&l, &r)?;
                self.code.emit(|e| {
                    e.and_imm(TMP1, left, !15u64)?;
                    e.lsr_imm(TMP, right, 4)?;
                    e.lsl_reg(TMP1, TMP1, TMP)?;
                    e.orr_imm(d, TMP1, 15)
                })?;
            }
            return self.store_result(dst, d);
        }

        let (left, right) = self.load_sources(&l, &r)?;
        let generic = self.code.new_label();
        let next = self.code.new_label();
        // Both constant (the compiler should have folded it), a boxed literal operand (never
        // small), an invalid constant, or a constant shift that is invalid or always produces
        // a bignum all take the generic path only.
        let inline_shift = !(l.is_immed() && r.is_immed()
            || l.is_literal()
            || r.is_literal()
            || l.is_immed() && !l.is_small()
            || r.is_immed() && (!r.is_small() || r.small_value() < 0 || r.small_value() >= 59));

        if inline_shift {
            // The shift limit is the number of leading sign bits not counting the sign bit.
            let limit_reg = Gpr::x(10);
            let limit_imm;
            if l.is_register() {
                // The topmost tag bit must equal the inverted sign bit so that the tag bits
                // are not counted.
                self.code.emit(|e| {
                    e.eor_reg(
                        TMP1,
                        left,
                        Shifted {
                            reg: left,
                            shift: Shift::Lsr,
                            amount: 60,
                        },
                    )?;
                    e.cls(limit_reg, TMP1)
                })?;
                limit_imm = None;
                if l.always_small() {
                    // The operand is always small.
                } else if l.always_one_of(type_id::NUMBER) {
                    self.code.tbz(TMP1, 0, generic)?;
                } else {
                    self.code.emit(|e| {
                        e.and_imm(TMP1, left, 15)?;
                        e.cmp_imm(TMP1, 15, false)
                    })?;
                    self.code.b_cond(Cond::Ne, generic)?;
                }
            } else {
                let mut value = l.word();
                if (value as i64) < 0 {
                    value ^= !15u64;
                }
                let zeroes = if value == 0 {
                    64
                } else {
                    value.leading_zeros()
                };
                limit_imm = Some((zeroes - 1) as u16);
            }

            let count_reg = Gpr::x(11);
            let mut count_imm = None;
            if r.is_register() {
                // Negate the tag bits and rotate them out so the comparison fails for
                // non-smalls.
                self.code.emit(|e| {
                    e.eor_imm(count_reg, right, 15)?;
                    e.ror_imm(count_reg, count_reg, 4)
                })?;
                // Fall back to the generic path for a negative or too large shift.
                match limit_imm {
                    Some(imm) => self.code.emit(|e| e.cmp_imm(count_reg, imm, false))?,
                    None => self
                        .code
                        .emit(|e| e.cmp_reg(count_reg, limit_reg, Shift::Lsl, 0))?,
                }
                self.code.b_cond(Cond::Hi, generic)?;
            } else {
                let count = r.small_value() as u16;
                count_imm = Some(count as u8);
                self.code.emit(|e| e.cmp_imm(limit_reg, count, false))?;
                self.code.b_cond(Cond::Cc, generic)?;
            }

            self.code.emit(|e| {
                e.and_imm(TMP1, left, !15u64)?;
                match count_imm {
                    Some(count) => e.lsl_imm(TMP1, TMP1, count)?,
                    None => e.lsl_reg(TMP1, TMP1, count_reg)?,
                }
                e.orr_imm(d, TMP1, 15)
            })?;
            self.code.b(next)?;
        }

        self.code.bind(generic)?;
        self.emit_arith_call(10, left, right, helper, fail)?;
        self.mov_if_needed(d, ARG1)?;
        self.code.bind(next)?;
        self.store_result(dst, d)
    }

    /// `i_int_div`, `i_rem`, `i_div_rem` and `i_rem_div`.
    // Port of erts/emulator/beam/jit/arm/instr_arith.cpp:968-1087 (emit_div_rem and the four
    // callers), OTP-29.1.1.
    #[allow(clippy::too_many_arguments)]
    fn emit_div_rem(
        &mut self,
        lhs: ArgVal,
        rhs: ArgVal,
        quotient_dst: ArgVal,
        remainder_dst: ArgVal,
        helper: ArithHelper,
        fail: u32,
        need_div: bool,
        need_rem: bool,
    ) -> Result<(), ModuleError> {
        let (l, r) = self.take_arith_args(lhs, rhs);
        let mut divisor = if r.is_small() { r.small_value() } else { 0 };
        if divisor == -1 {
            divisor = 0;
        }

        if l.always_small() && divisor != 0 {
            let left = self.source_reg_into(l.val, ARG3)?;
            let quotient = if need_div {
                self.init_destination(quotient_dst, ARG1)
            } else {
                ARG1
            };
            let remainder = if need_rem {
                self.init_destination(remainder_dst, ARG2)
            } else {
                ARG2
            };
            self.emit_div_rem_literal(
                divisor, &l, left, quotient, remainder, None, need_div, need_rem,
            )?;
            if need_div {
                self.store_result(quotient_dst, quotient)?;
            }
            if need_rem {
                self.store_result(remainder_dst, remainder)?;
            }
            return Ok(());
        }

        let generic = self.code.new_label();
        let done = self.code.new_label();
        let (left, right) = self.load_sources(&l, &r)?;
        if divisor != 0 {
            self.emit_div_rem_literal(
                divisor,
                &l,
                left,
                ARG1,
                ARG2,
                Some(generic),
                need_div,
                need_rem,
            )?;
            self.code.b(done)?;
        }
        self.code.bind(generic)?;
        self.emit_int_div_rem_shared(need_div, need_rem, left, right, helper, fail)?;
        self.code.bind(done)?;
        if need_div {
            self.store_result(quotient_dst, ARG1)?;
        }
        if need_rem {
            self.store_result(remainder_dst, ARG2)?;
        }
        Ok(())
    }

    /// The shared `int_div_rem` fragment inlined: quotient in ARG1, remainder in ARG2.
    // Port of erts/emulator/beam/jit/arm/instr_arith.cpp:740-875 (emit_int_div_rem_guard_shared,
    // emit_int_div_rem_body_shared), OTP-29.1.1
    fn emit_int_div_rem_shared(
        &mut self,
        need_div: bool,
        need_rem: bool,
        lhs: Gpr,
        rhs: Gpr,
        helper: ArithHelper,
        fail: u32,
    ) -> Result<(), ModuleError> {
        let slow = self.code.new_label();
        let done = self.code.new_label();
        let quotient = Gpr::x(12);
        let remainder = Gpr::x(13);
        // Speculatively go ahead with the division.
        self.code.emit(|e| {
            e.asr_imm(TMP1, lhs, 4)?;
            e.asr_imm(TMP, rhs, 4)?;
            e.sdiv(quotient, TMP1, TMP)?;
            e.msub(remainder, quotient, TMP, TMP1)?;
            e.cmp_imm(rhs, 15, false)
        })?;
        self.code.b_cond(Cond::Eq, slow)?;
        // Check whether both operands are small integers.
        self.code.emit(|e| {
            e.and_reg(
                TMP1,
                lhs,
                Shifted {
                    reg: rhs,
                    shift: Shift::Lsl,
                    amount: 0,
                },
            )?;
            e.and_imm(TMP1, TMP1, 15)?;
            e.cmp_imm(TMP1, 15, false)
        })?;
        self.code.b_cond(Cond::Ne, slow)?;
        // MIN_SMALL divided by -1 overflows; the generic handler produces the bignum.
        self.code.emit(|e| {
            e.asr_imm(TMP1, quotient, 59)?;
            e.cmp_imm(TMP1, 1, false)
        })?;
        self.code.b_cond(Cond::Ge, slow)?;
        self.code.emit(|e| {
            e.mov_const(TMP1, 15)?;
            e.orr_reg(
                ARG1,
                TMP1,
                Shifted {
                    reg: quotient,
                    shift: Shift::Lsl,
                    amount: 4,
                },
            )?;
            e.orr_reg(
                ARG2,
                TMP1,
                Shifted {
                    reg: remainder,
                    shift: Shift::Lsl,
                    amount: 4,
                },
            )
        })?;
        self.code.b(done)?;
        self.code.bind(slow)?;
        if need_div && need_rem {
            // Quotient comes back in x0; the helper stores the remainder in tmp_mem[1].
            self.emit_arith_call(14, lhs, rhs, helper, fail)?;
            self.code
                .emit(|e| e.ldr_uoff(ARG2, Gpr::x(19), TMP_MEM_REM))?;
        } else {
            let op = if need_div {
                BinaryOp::Div
            } else {
                BinaryOp::Rem
            };
            self.emit_arith_call(op.id(), lhs, rhs, helper, fail)?;
            self.mov_if_needed(if need_div { ARG1 } else { ARG2 }, ARG1)?;
        }
        self.code.bind(done)?;
        Ok(())
    }

    /// Division or remainder by a constant; the dividend is checked unless `generic` is `None`.
    // Port of erts/emulator/beam/jit/arm/instr_arith.cpp:877-966 (emit_div_rem_literal),
    // OTP-29.1.1
    #[allow(clippy::too_many_arguments)]
    fn emit_div_rem_literal(
        &mut self,
        divisor: i64,
        dividend: &TypedArg,
        dividend_reg: Gpr,
        quotient: Gpr,
        remainder: Gpr,
        generic: Option<Label>,
        need_div: bool,
        need_rem: bool,
    ) -> Result<(), ModuleError> {
        let small_tag = Gpr::x(13);
        let small_dividend = generic.is_none();

        if let Some(generic) = generic {
            self.code.emit(|e| {
                e.and_imm(small_tag, dividend_reg, 15)?;
                e.cmp_imm(small_tag, 15, false)
            })?;
            self.code.b_cond(Cond::Ne, generic)?;
        }

        if divisor > 0 && (divisor & (divisor - 1)) == 0 {
            let mut original_dividend = dividend_reg;
            let shift = divisor.trailing_zeros() as u8;
            if need_div && need_rem && quotient == dividend_reg {
                original_dividend = Gpr::x(12);
                self.code
                    .emit(|e| e.mov_reg(original_dividend, dividend_reg))?;
            }
            if need_div && small_dividend {
                self.code.emit(|e| e.mov_const(small_tag, 15))?;
            }
            if dividend.clamped_range().0 >= 0 {
                // Positive dividend.
                if need_div {
                    self.code.emit(|e| {
                        e.orr_reg(
                            quotient,
                            small_tag,
                            Shifted {
                                reg: dividend_reg,
                                shift: Shift::Lsr,
                                amount: shift,
                            },
                        )
                    })?;
                }
                if need_rem {
                    let mask = (1u64 << (u32::from(shift) + 4)) - 1;
                    self.code
                        .emit(|e| e.and_imm(remainder, original_dividend, mask))?;
                }
            } else {
                // Negative dividend: bias by divisor - 1 before shifting.
                let biased = Gpr::x(10);
                if divisor == 2 {
                    self.code
                        .emit(|e| e.add_reg(biased, dividend_reg, dividend_reg, Shift::Lsr, 63))?;
                } else {
                    self.add_constant(TMP1, dividend_reg, ((divisor - 1) as u64) << 4)?;
                    self.code.emit(|e| {
                        e.cmp_imm(dividend_reg, 0, false)?;
                        e.csel(biased, TMP1, dividend_reg, Cond::Lt)
                    })?;
                }
                if need_div {
                    self.code.emit(|e| {
                        e.orr_reg(
                            quotient,
                            small_tag,
                            Shifted {
                                reg: biased,
                                shift: Shift::Asr,
                                amount: shift,
                            },
                        )
                    })?;
                }
                if need_rem {
                    let mask = u64::MAX << (u32::from(shift) + 4);
                    self.code.emit(|e| {
                        e.and_imm(TMP1, biased, mask)?;
                        e.sub_reg(remainder, original_dividend, TMP1, Shift::Lsl, 0)
                    })?;
                }
            }
        } else {
            self.code.emit(|e| {
                e.asr_imm(TMP1, dividend_reg, 4)?;
                e.mov_const(TMP, divisor as u64)?;
                e.sdiv(quotient, TMP1, TMP)?;
                if need_rem {
                    e.msub(remainder, quotient, TMP, TMP1)?;
                }
                if small_dividend {
                    e.mov_const(small_tag, 15)?;
                }
                if need_div {
                    e.orr_reg(
                        quotient,
                        small_tag,
                        Shifted {
                            reg: quotient,
                            shift: Shift::Lsl,
                            amount: 4,
                        },
                    )?;
                }
                if need_rem {
                    e.orr_reg(
                        remainder,
                        small_tag,
                        Shifted {
                            reg: remainder,
                            shift: Shift::Lsl,
                            amount: 4,
                        },
                    )?;
                }
                Ok(())
            })?;
        }
        Ok(())
    }

    /// `add(to, src, val)`: an immediate add, through a scratch register when it does not encode.
    // Port of erts/emulator/beam/jit/arm/beam_asm_module.cpp (BeamAssembler::add), OTP-29.1.1
    fn add_constant(&mut self, to: Gpr, src: Gpr, value: u64) -> Result<(), ModuleError> {
        self.code.emit(|e| {
            if value <= 4095 {
                e.add_imm(to, src, value as u16, false)
            } else if value & 0xfff == 0 && value >> 12 <= 4095 {
                e.add_imm(to, src, (value >> 12) as u16, true)
            } else {
                let scratch = Gpr::x(11);
                e.mov_const(scratch, value)?;
                e.add_reg(to, src, scratch, Shift::Lsl, 0)
            }
        })?;
        Ok(())
    }

    /// `mov_var(to, from)`.
    fn mov_if_needed(&mut self, to: Gpr, from: Gpr) -> Result<(), ModuleError> {
        if to != from {
            self.code.emit(|e| e.mov_reg(to, from))?;
        }
        Ok(())
    }

    /// `mov_var(dst, ARG1); flush_var(dst)` for a result computed in `from`.
    fn store_result_via(&mut self, dst: ArgVal, d: Gpr, from: Gpr) -> Result<(), ModuleError> {
        self.mov_if_needed(d, from)?;
        self.store_result(dst, d)
    }

    /// `i_mul_add` / `i_times`: typed product, power-of-two shift, or `smulh` overflow check.
    // Port of erts/emulator/beam/jit/arm/instr_arith.cpp:542-731 (emit_i_mul_add), OTP-29.1.1.
    #[allow(clippy::too_many_arguments)]
    fn emit_mul_add(
        &mut self,
        src1: ArgVal,
        src2: ArgVal,
        src3: ArgVal,
        src4: ArgVal,
        dst: ArgVal,
        helper: ArithHelper,
        fail: u32,
    ) -> Result<(), ModuleError> {
        let (src1, src2, src3, src4) = self.take_mul_args(src1, src2, src3, src4);
        let is_product_small = is_product_small_if_args_are_small(&src1, &src2);
        let is_sum_small = is_sum_small_if_args_are_small(&src3, &src4);
        let sometimes_small = !(src2.is_literal() || src4.is_literal());
        let is_increment_zero = src4.is_small() && src4.small_value() == 0;
        let (factor, left_shift) = small_factor(&src2);

        if src1.always_small()
            && src2.is_small()
            && src4.always_small()
            && is_product_small
            && is_sum_small
        {
            let destination = self.init_destination(dst, ARG1);
            let (left, increment) = self.load_pair(src1.val, M_ARG2, src4.val, M_ARG3)?;
            self.code.emit(|e| e.and_imm(TMP1, left, !15u64))?;
            if left_shift > 0 {
                self.code.emit(|e| {
                    e.add_reg(destination, increment, TMP1, Shift::Lsl, left_shift as u8)
                })?;
            } else {
                self.code.emit(|e| {
                    e.mov_const(M_TMP2, factor as u64)?;
                    e.madd(destination, TMP1, M_TMP2, increment, false)
                })?;
            }
            return self.store_result(dst, destination);
        }

        let small = self.code.new_label();
        let store_result = self.code.new_label();
        let (left, right) = self.load_pair(src1.val, M_ARG2, src2.val, M_ARG3)?;
        let increment = if is_increment_zero {
            Gpr::xzr()
        } else {
            self.source_reg_into(src4.val, M_ARG4)?
        };
        let all_small = src1.always_small() && src2.always_small() && src4.always_small();
        if !all_small {
            if src4.always_small() {
                self.emit_are_both_small(&src1, left, &src2, right, small)?;
            } else if src2.always_small() {
                self.emit_are_both_small(&src1, left, &src4, increment, small)?;
            } else if sometimes_small {
                self.code.emit(|e| {
                    e.and_reg(
                        TMP1,
                        left,
                        Shifted {
                            reg: right,
                            shift: Shift::Lsl,
                            amount: 0,
                        },
                    )?;
                    e.and_reg(
                        TMP1,
                        TMP1,
                        Shifted {
                            reg: increment,
                            shift: Shift::Lsl,
                            amount: 0,
                        },
                    )
                })?;
                let int_or_boxed = type_id::INTEGER | type_id::ALWAYS_BOXED;
                if src1.always_one_of(int_or_boxed)
                    && src2.always_one_of(int_or_boxed)
                    && src4.always_one_of(int_or_boxed)
                {
                    self.branch_if_bit0(TMP1, small)?;
                } else {
                    self.code.emit(|e| {
                        e.and_imm(TMP1, TMP1, 15)?;
                        e.cmp_imm(TMP1, 15, false)
                    })?;
                    self.code.b_cond(Cond::Eq, small)?;
                }
            }
            if !is_increment_zero {
                self.mov_if_needed(M_ARG4, increment)?;
            }
            let op = if is_increment_zero {
                BinaryOp::Mul.id()
            } else {
                13
            };
            self.emit_helper(op, left, right, helper, (fail != 0).then_some(fail))?;
            if sometimes_small {
                self.code.b(store_result)?;
            }
        }

        self.code.bind(small)?;
        if is_product_small && is_sum_small {
            self.code.emit(|e| e.and_imm(M_TMP3, left, !15u64))?;
            let increment_reg = if is_increment_zero {
                self.code.emit(|e| e.mov_const(TMP1, 0xf))?;
                TMP1
            } else {
                increment
            };
            if left_shift > 0 {
                self.code.emit(|e| {
                    e.add_reg(ARG1, increment_reg, M_TMP3, Shift::Lsl, left_shift as u8)
                })?;
            } else {
                self.code.emit(|e| {
                    e.asr_imm(M_TMP4, right, 4)?;
                    e.madd(ARG1, M_TMP3, M_TMP4, increment_reg, false)
                })?;
            }
        } else if sometimes_small {
            self.emit_mul_overflow_check(
                &src4,
                left,
                right,
                increment,
                left_shift,
                is_increment_zero,
                store_result,
                helper,
            )?;
        }

        self.code.bind(store_result)?;
        self.store_result(dst, ARG1)
    }

    /// Small multiply whose product may not fit, then `int128_to_big` on overflow.
    // Port of erts/emulator/beam/jit/arm/instr_arith.cpp:680-725, OTP-29.1.1.
    #[allow(clippy::too_many_arguments)]
    fn emit_mul_overflow_check(
        &mut self,
        src4: &TypedArg,
        left: Gpr,
        right: Gpr,
        increment: Gpr,
        left_shift: i32,
        is_increment_zero: bool,
        store_result: Label,
        helper: ArithHelper,
    ) -> Result<(), ModuleError> {
        let min_increment = src4.clamped_range().0;
        self.code.emit(|e| e.and_imm(M_TMP3, left, !15u64))?;
        if left_shift == 0 {
            self.code.emit(|e| {
                e.mov_reg(ARG1, M_TMP3)?;
                e.asr_imm(M_TMP2, M_TMP3, 63)
            })?;
        } else if left_shift > 0 {
            self.code.emit(|e| {
                e.lsl_imm(ARG1, M_TMP3, left_shift as u8)?;
                e.asr_imm(M_TMP2, M_TMP3, (64 - left_shift) as u8)
            })?;
        } else {
            self.code.emit(|e| {
                e.asr_imm(M_TMP4, right, 4)?;
                e.mul(ARG1, M_TMP3, M_TMP4)?;
                e.smulh(M_TMP2, M_TMP3, M_TMP4)
            })?;
        }
        if is_increment_zero {
            self.code.emit(|e| e.add_imm(ARG1, ARG1, 15, false))?;
        } else if min_increment > 0 {
            self.code.emit(|e| {
                e.adds_reg(ARG1, ARG1, increment, Shift::Lsl, 0)?;
                e.adc(M_TMP2, M_TMP2, Gpr::xzr())
            })?;
        } else {
            self.code.emit(|e| {
                e.asr_imm(M_TMP3, increment, 63)?;
                e.adds_reg(ARG1, ARG1, increment, Shift::Lsl, 0)?;
                e.adc(M_TMP2, M_TMP2, M_TMP3)
            })?;
        }
        // The high half equals the sign extension of the low half when the tagged
        // result fits in a small.
        self.code.emit(|e| {
            e.asr_imm(M_TMP3, ARG1, 63)?;
            e.cmp_reg(M_TMP2, M_TMP3, Shift::Lsl, 0)
        })?;
        self.code.b_cond(Cond::Eq, store_result)?;
        self.emit_int128_to_big(helper)
    }

    /// Converts the 128-bit tagged product in x0:x9 into a bignum.
    // Port of erts/emulator/beam/jit/arm/instr_arith.cpp:403-428 (emit_int128_to_big_shared),
    // OTP-29.1.1.
    fn emit_int128_to_big(&mut self, helper: ArithHelper) -> Result<(), ModuleError> {
        self.code.emit(|e| {
            e.extr(Gpr::x(2), M_TMP2, ARG1, 4)?;
            e.asr_imm(Gpr::x(3), M_TMP2, 4)?;
            e.cmp_imm(Gpr::x(3), 0, false)?;
            e.cset(Gpr::x(1), Cond::Mi)
        })?;
        let positive = self.code.new_label();
        self.code.b_cond(Cond::Pl, positive)?;
        self.code.emit(|e| {
            e.negs(Gpr::x(2), Gpr::x(2))?;
            e.ngc(Gpr::x(3), Gpr::x(3))
        })?;
        self.code.bind(positive)?;
        self.code.emit(|e| {
            e.mov_reg(ARG2, Gpr::x(2))?;
            e.mov_reg(ARG3, Gpr::x(3))?;
            e.mov_reg(M_ARG4, Gpr::x(1))
        })?;
        self.emit_helper(15, ARG2, ARG3, helper, None)
    }

    fn take_mul_args(
        &mut self,
        src1: ArgVal,
        src2: ArgVal,
        src3: ArgVal,
        src4: ArgVal,
    ) -> (TypedArg, TypedArg, TypedArg, TypedArg) {
        let types = self.arith_types.take().unwrap_or([ArgType::ANY; 4]);
        (
            TypedArg::new(src1, types[0]),
            TypedArg::new(src2, types[1]),
            TypedArg::new(src3, types[2]),
            TypedArg::new(src4, types[3]),
        )
    }
    fn emit_small_range_check(&mut self, slow: arinsal_a64::buf::Label) -> Result<(), ModuleError> {
        self.code.emit(|e| {
            e.lsl_imm(Gpr::x(13), Gpr::x(12), 4)?;
            e.asr_imm(Gpr::x(13), Gpr::x(13), 4)?;
            e.cmp_reg(Gpr::x(12), Gpr::x(13), Shift::Lsl, 0)
        })?;
        self.code.b_cond(Cond::Ne, slow)?;
        Ok(())
    }

    fn emit_unary_small(
        &mut self,
        op: u32,
        src: ArgVal,
        dst: ArgVal,
        helper: ArithHelper,
        negate: bool,
        fail: u32,
    ) -> Result<(), ModuleError> {
        let value = self.source_reg(src)?;
        self.code.emit(|e| {
            e.mov_reg(Gpr::x(10), value)?;
            e.mov_reg(Gpr::x(14), value)
        })?;
        let slow = self.code.new_label();
        let done = self.code.new_label();
        self.code.emit(|e| {
            e.ands_imm(Gpr::x(8), Gpr::x(10), 15)?;
            e.cmp_imm(Gpr::x(8), 15, false)
        })?;
        self.code.b_cond(Cond::Ne, slow)?;
        self.code.emit(|e| e.asr_imm(Gpr::x(10), Gpr::x(10), 4))?;
        if negate {
            self.code
                .emit(|e| e.sub_reg(Gpr::x(12), Gpr::xzr(), Gpr::x(10), Shift::Lsl, 0))?;
        } else {
            self.code.emit(|e| {
                e.sub_reg(Gpr::x(12), Gpr::xzr(), Gpr::x(10), Shift::Lsl, 0)?;
                e.sub_imm(Gpr::x(12), Gpr::x(12), 1, false)
            })?;
        }
        self.emit_small_range_check(slow)?;
        self.code.emit(|e| {
            e.lsl_imm(Gpr::x(12), Gpr::x(12), 4)?;
            e.orr_imm(Gpr::x(12), Gpr::x(12), 15)
        })?;
        self.store_result(dst, Gpr::x(12))?;
        self.code.b(done)?;
        self.code.bind(slow)?;
        self.emit_helper(
            op,
            Gpr::x(14),
            Gpr::xzr(),
            helper,
            (fail != 0).then_some(fail),
        )?;
        self.store_result(dst, Gpr::x(0))?;
        self.code.bind(done)?;
        Ok(())
    }

    fn emit_unary_fallback(
        &mut self,
        op: u32,
        src: ArgVal,
        dst: ArgVal,
        helper: ArithHelper,
    ) -> Result<(), ModuleError> {
        let value = self.source_reg(src)?;
        self.code.emit(|e| {
            e.mov_reg(Gpr::x(10), value)?;
            e.mov_reg(Gpr::x(14), value)
        })?;
        self.emit_helper(op, Gpr::x(14), Gpr::xzr(), helper, None)?;
        self.store_result(dst, Gpr::x(0))
    }

    /// Calls the shared slow-path fragment for `op`: ARG2/ARG3 = operands, result in ARG1.
    // Port of erts/emulator/beam/jit/arm/instr_arith.cpp:145-213 (fragment_call of the
    // *_body_shared fragments), OTP-29.1.1
    fn emit_helper(
        &mut self,
        op: u32,
        lhs: Gpr,
        rhs: Gpr,
        helper: ArithHelper,
        fail: Option<u32>,
    ) -> Result<(), ModuleError> {
        // The failure label comes from the instruction (guard arithmetic) or the emitting
        // context; with one the runtime records no BIF frame (QUIET_GUARD in the VM hook).
        let fail = fail.or((self.arith_fail != 0).then_some(self.arith_fail));
        let op = if fail.is_none() { op } else { op | 0x100 };
        let fragment = self.arith_fragment(helper as usize, op);
        self.mov_if_needed(ARG2, lhs)?;
        self.mov_if_needed(ARG3, rhs)?;
        self.code.bl(fragment)?;
        let Some(fail) = fail else {
            return Ok(());
        };
        // Guard context: the failure clears the pending exception and falls to the label.
        let ok = self.code.new_label();
        if op & 0xff <= 14 {
            // Port of erts/emulator/beam/jit/arm/instr_arith.cpp,
            // OTP-29.1.1: arithmetic BIF helpers return THE_NON_VALUE on failure.
            self.code.cbnz(Gpr::x(0), ok)?;
        } else {
            self.code.cbz(Gpr::x(9), ok)?;
        }
        self.code.emit(|e| {
            e.str_uoff(Gpr::xzr(), Gpr::x(21), 40)?;
            e.str_uoff(Gpr::xzr(), Gpr::x(21), 48)
        })?;
        let fail = self.label(fail);
        self.code.b(fail)?;
        self.code.bind(ok)?;
        Ok(())
    }

    fn store_result(&mut self, dst: ArgVal, src: Gpr) -> Result<(), ModuleError> {
        self.store_operand(dst, src)
    }
}
