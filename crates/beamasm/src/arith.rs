//! Integer arithmetic emission for BeamAsm modules.

use arinsal_a64::enc::{Cond, Gpr, Shift, Shifted};

use crate::module::{ArgVal, BeamModuleAssembler, ModuleError};
use crate::{Update, emit_enter_runtime, emit_leave_runtime};

/// Runtime fallback for arithmetic that cannot return a small integer.
///
/// The VM supplies this hook. Arguments and the result use OTP tagged-term words.
pub type ArithHelper =
    unsafe extern "C" fn(process: *mut crate::ProcessHeader, op: u32, lhs: u64, rhs: u64) -> u64;

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

fn small_arithmetic_immediate(value: ArgVal) -> Option<u64> {
    match value {
        ArgVal::Immediate(word) if word & 15 == 15 => Some(word),
        _ => None,
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
        if let Some(immediate) = small_arithmetic_immediate(rhs) {
            return self.emit_small_immediate_arithmetic(true, lhs, immediate, dst, helper, fail);
        }
        self.emit_integer_binary(BinaryOp::Add, lhs, rhs, dst, helper, fail)
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
        if let Some(immediate) = small_arithmetic_immediate(rhs) {
            return self.emit_small_immediate_arithmetic(false, lhs, immediate, dst, helper, fail);
        }
        self.emit_integer_binary(BinaryOp::Sub, lhs, rhs, dst, helper, fail)
    }

    /// Emits `i_times` with a 60-bit result check.
    // Port of erts/emulator/beam/jit/arm/instr_arith.cpp:472-590, OTP-29.1.1
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
    // Port of erts/emulator/beam/jit/arm/instr_arith.cpp:472-590, OTP-29.1.1.
    pub fn emit_i_times_with_fail(
        &mut self,
        lhs: ArgVal,
        rhs: ArgVal,
        dst: ArgVal,
        fail: u32,
        helper: ArithHelper,
    ) -> Result<(), ModuleError> {
        self.emit_integer_binary(BinaryOp::Mul, lhs, rhs, dst, helper, fail)
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
        self.emit_integer_binary(BinaryOp::Div, lhs, rhs, dst, helper, fail)
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
        self.emit_integer_binary(BinaryOp::Rem, lhs, rhs, dst, helper, fail)
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
        self.emit_integer_binary(BinaryOp::And, lhs, rhs, dst, helper, fail)
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
        self.emit_integer_binary(BinaryOp::Or, lhs, rhs, dst, helper, fail)
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
        self.emit_integer_binary(BinaryOp::Xor, lhs, rhs, dst, helper, fail)
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
        self.emit_integer_shift(true, lhs, rhs, dst, helper, fail)
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
        self.emit_integer_shift(false, lhs, rhs, dst, helper, fail)
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

    fn emit_integer_shift(
        &mut self,
        left_shift: bool,
        lhs: ArgVal,
        rhs: ArgVal,
        dst: ArgVal,
        helper: ArithHelper,
        fail: u32,
    ) -> Result<(), ModuleError> {
        let left = self.source_reg(lhs)?;
        self.code.emit(|e| {
            e.mov_reg(Gpr::x(10), left)?;
            e.mov_reg(Gpr::x(14), left)
        })?;
        let right = self.source_reg(rhs)?;
        self.code.emit(|e| {
            e.mov_reg(Gpr::x(11), right)?;
            e.mov_reg(Gpr::x(17), right)
        })?;
        let slow = self.code.new_label();
        let done = self.code.new_label();
        self.code.emit(|e| {
            e.ands_imm(Gpr::x(8), Gpr::x(10), 15)?;
            e.cmp_imm(Gpr::x(8), 15, false)
        })?;
        self.code.b_cond(Cond::Ne, slow)?;
        self.code.emit(|e| {
            e.ands_imm(Gpr::x(8), Gpr::x(11), 15)?;
            e.cmp_imm(Gpr::x(8), 15, false)
        })?;
        self.code.b_cond(Cond::Ne, slow)?;
        self.code.emit(|e| {
            e.asr_imm(Gpr::x(10), Gpr::x(10), 4)?;
            e.asr_imm(Gpr::x(11), Gpr::x(11), 4)?;
            e.cmp_imm(Gpr::x(11), 0, false)
        })?;
        self.code.b_cond(Cond::Lt, slow)?;
        self.code.emit(|e| e.cmp_imm(Gpr::x(11), 60, false))?;
        self.code.b_cond(Cond::Ge, slow)?;
        if left_shift {
            self.code.emit(|e| {
                e.lsl_reg(Gpr::x(12), Gpr::x(10), Gpr::x(11))?;
                e.asr_reg(Gpr::x(13), Gpr::x(12), Gpr::x(11))?;
                e.cmp_reg(Gpr::x(13), Gpr::x(10), Shift::Lsl, 0)
            })?;
            self.code.b_cond(Cond::Ne, slow)?;
        } else {
            self.code
                .emit(|e| e.asr_reg(Gpr::x(12), Gpr::x(10), Gpr::x(11)))?;
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
            if left_shift { 10 } else { 11 },
            Gpr::x(14),
            Gpr::x(17),
            helper,
            (fail != 0).then_some(fail),
        )?;
        self.store_result(dst, Gpr::x(0))?;
        self.code.bind(done)?;
        Ok(())
    }

    fn emit_integer_binary(
        &mut self,
        op: BinaryOp,
        lhs: ArgVal,
        rhs: ArgVal,
        dst: ArgVal,
        helper: ArithHelper,
        fail: u32,
    ) -> Result<(), ModuleError> {
        let left = self.source_reg(lhs)?;
        self.code.emit(|e| {
            e.mov_reg(Gpr::x(10), left)?;
            e.mov_reg(Gpr::x(14), left)
        })?;
        let right = self.source_reg(rhs)?;
        self.code.emit(|e| {
            e.mov_reg(Gpr::x(11), right)?;
            e.mov_reg(Gpr::x(17), right)
        })?;
        let slow = self.code.new_label();
        let done = self.code.new_label();
        self.code.emit(|e| {
            e.ands_imm(Gpr::x(8), Gpr::x(10), 15)?;
            e.cmp_imm(Gpr::x(8), 15, false)?;
            Ok(())
        })?;
        self.code.b_cond(Cond::Ne, slow)?;
        self.code.emit(|e| {
            e.ands_imm(Gpr::x(8), Gpr::x(11), 15)?;
            e.cmp_imm(Gpr::x(8), 15, false)?;
            Ok(())
        })?;
        self.code.b_cond(Cond::Ne, slow)?;
        self.code.emit(|e| {
            e.asr_imm(Gpr::x(10), Gpr::x(10), 4)?;
            e.asr_imm(Gpr::x(11), Gpr::x(11), 4)
        })?;
        match op {
            BinaryOp::Add => self
                .code
                .emit(|e| e.add_reg(Gpr::x(12), Gpr::x(10), Gpr::x(11), Shift::Lsl, 0))?,
            BinaryOp::Sub => self
                .code
                .emit(|e| e.sub_reg(Gpr::x(12), Gpr::x(10), Gpr::x(11), Shift::Lsl, 0))?,
            BinaryOp::Mul => {
                self.code.emit(|e| {
                    e.mul(Gpr::x(12), Gpr::x(10), Gpr::x(11))?;
                    e.smulh(Gpr::x(13), Gpr::x(10), Gpr::x(11))?;
                    e.asr_imm(Gpr::x(9), Gpr::x(12), 63)?;
                    e.cmp_reg(Gpr::x(13), Gpr::x(9), Shift::Lsl, 0)
                })?;
                self.code.b_cond(Cond::Ne, slow)?;
            }
            BinaryOp::Div | BinaryOp::Rem => {
                self.code.emit(|e| e.cmp_imm(Gpr::x(11), 0, false))?;
                self.code.b_cond(Cond::Eq, slow)?;
                self.code
                    .emit(|e| e.sdiv(Gpr::x(12), Gpr::x(10), Gpr::x(11)))?;
                if matches!(op, BinaryOp::Rem) {
                    self.code
                        .emit(|e| e.msub(Gpr::x(12), Gpr::x(12), Gpr::x(11), Gpr::x(10)))?;
                }
            }
            BinaryOp::And => self.code.emit(|e| {
                e.and_reg(
                    Gpr::x(12),
                    Gpr::x(10),
                    Shifted {
                        reg: Gpr::x(11),
                        shift: Shift::Lsl,
                        amount: 0,
                    },
                )
            })?,
            BinaryOp::Or => self.code.emit(|e| {
                e.orr_reg(
                    Gpr::x(12),
                    Gpr::x(10),
                    Shifted {
                        reg: Gpr::x(11),
                        shift: Shift::Lsl,
                        amount: 0,
                    },
                )
            })?,
            BinaryOp::Xor => self.code.emit(|e| {
                e.eor_reg(
                    Gpr::x(12),
                    Gpr::x(10),
                    Shifted {
                        reg: Gpr::x(11),
                        shift: Shift::Lsl,
                        amount: 0,
                    },
                )
            })?,
        }
        if !matches!(op, BinaryOp::And | BinaryOp::Or | BinaryOp::Xor) {
            self.emit_small_range_check(slow)?;
        }
        self.code.emit(|e| {
            e.lsl_imm(Gpr::x(12), Gpr::x(12), 4)?;
            e.orr_imm(Gpr::x(12), Gpr::x(12), 15)
        })?;
        self.store_result(dst, Gpr::x(12))?;
        self.code.b(done)?;
        self.code.bind(slow)?;
        self.emit_helper(
            op.id(),
            Gpr::x(14),
            Gpr::x(17),
            helper,
            (fail != 0).then_some(fail),
        )?;
        self.store_result(dst, Gpr::x(0))?;
        self.code.bind(done)?;
        Ok(())
    }

    fn emit_small_immediate_arithmetic(
        &mut self,
        add: bool,
        lhs: ArgVal,
        tagged_rhs: u64,
        dst: ArgVal,
        helper: ArithHelper,
        fail: u32,
    ) -> Result<(), ModuleError> {
        let delta = tagged_rhs & !15;
        if delta > 4095 {
            return self.emit_integer_binary(
                if add { BinaryOp::Add } else { BinaryOp::Sub },
                lhs,
                ArgVal::Immediate(tagged_rhs),
                dst,
                helper,
                fail,
            );
        }

        let value = self.source_reg(lhs)?;
        let fast = self.code.new_label();
        self.code.emit(|e| {
            if add {
                e.adds_imm(Gpr::x(0), value, delta as u16, false)
            } else {
                e.subs_imm(Gpr::x(0), value, delta as u16, false)
            }
        })?;
        self.code.emit(|e| {
            e.and_imm(Gpr::x(8), value, 15)?;
            e.ccmp_imm(Gpr::x(8), 15, 0, Cond::Vc)
        })?;
        self.code.b_cond(Cond::Eq, fast)?;
        self.code.emit(|e| {
            e.mov_reg(Gpr::x(14), value)?;
            e.mov_const(Gpr::x(17), tagged_rhs)
        })?;
        self.emit_helper(
            if add {
                BinaryOp::Add.id()
            } else {
                BinaryOp::Sub.id()
            },
            Gpr::x(14),
            Gpr::x(17),
            helper,
            (fail != 0).then_some(fail),
        )?;
        self.code.bind(fast)?;
        self.store_result(dst, Gpr::x(0))?;
        Ok(())
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
        self.code.emit(|e| e.mov_const(Gpr::x(8), u64::from(op)))?;
        // The slow path allocates bignums and floats from the young heap, so it must see (and
        // publish) the native heap and stack cursors.
        let update = Update::HEAP_ALLOC.union(Update::REDUCTIONS);
        emit_enter_runtime(&mut self.code, 6, update)?;
        self.code.emit(|e| {
            e.mov_reg(Gpr::x(0), Gpr::x(21))?;
            e.mov_reg(Gpr::x(1), Gpr::x(8))?;
            e.mov_reg(Gpr::x(2), lhs)?;
            e.mov_reg(Gpr::x(3), rhs)?;
            e.mov_const(Gpr::x(17), helper as usize as u64)?;
            e.str_uoff(Gpr::x(30), Gpr::x(21), 72)?;
            e.blr(Gpr::x(17))
        })?;
        emit_leave_runtime(&mut self.code, 6, update)?;
        self.code.emit(|e| {
            e.ldr_uoff(Gpr::x(30), Gpr::x(21), 72)?;
            e.ldr_uoff(Gpr::x(9), Gpr::x(21), 40)
        })?;
        let Some(fail) = fail else {
            self.error_if_nonzero(Gpr::x(9))?;
            return Ok(());
        };
        // Guard context: the failure clears the pending exception and falls to the label.
        let ok = self.code.new_label();
        self.code.cbz(Gpr::x(9), ok)?;
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
