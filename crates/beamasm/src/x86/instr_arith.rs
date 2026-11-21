//! Port of erts/emulator/beam/jit/x86/instr_arith.cpp, OTP-29.1.1: arithmetic and bitwise
//! I2-I4 emitters, their shared runtime fragments, and the small-tag test helpers.

use arinsal_term::{ErtsCodeMfa, Term, atoms};
use arinsal_x64::buf::Label;
use arinsal_x64::enc::{self, CondCode, Gp, Mem, qword_ptr};

use super::beam_asm::AsmError;
use super::beam_asm::register::{
    ARG1, ARG1D, ARG2, ARG2D, ARG3, ARG3D, ARG4, ARG4D, ARG5, ARG6, C_P, RET, RETB, RETD,
};
use super::beam_asm::{
    BeamAssembler, CpuFeature, Distance, Update, process, process_ref, tmp_mem_q,
};
use super::beam_asm_global::{BeamGlobalAssembler, GlobalLabels};
use super::beam_asm_module::{BeamModuleAssembler, arg_label};
use super::rt::addr;
pub use super::rt::{
    erts_band, erts_bnot, erts_bor, erts_bsl, erts_bsr, erts_bxor, erts_int_div_rem,
    erts_mixed_div, erts_mixed_minus, erts_mixed_plus, erts_mixed_times, erts_mul_add,
    erts_unary_minus,
};
use crate::common::args::ArgVal;
use crate::common::types::{BeamModuleAssemblerCommon, type_id};
use crate::exc::EXC_BADARITH;

const TAG_PRIMARY_LIST: i64 = 1;
const TAG_IMMED1_MASK: i64 = 0x0f;
const TAG_IMMED1_SMALL: i64 = 0x0f;
const TAG_IMMED1_SIZE: i64 = 4;
const SMALL_BITS: u32 = 60;
const SMALL_ZERO: i64 = TAG_IMMED1_SMALL;

const fn bif_mfa(function: arinsal_term::Atom, arity: usize) -> ErtsCodeMfa {
    ErtsCodeMfa {
        module: Term::atom(atoms::ERLANG).word(),
        function: Term::atom(function).word(),
        arity,
    }
}

pub(crate) static PLUS_MFA: ErtsCodeMfa = bif_mfa(atoms::PLUS, 2);
pub(crate) static MINUS_MFA: ErtsCodeMfa = bif_mfa(atoms::MINUS, 2);
pub(crate) static UNARY_MINUS_MFA: ErtsCodeMfa = bif_mfa(atoms::MINUS, 1);
pub(crate) static TIMES_MFA: ErtsCodeMfa = bif_mfa(atoms::TIMES, 2);
pub(crate) static DIV_MFA: ErtsCodeMfa = bif_mfa(atoms::DIV, 2);
pub(crate) static REM_MFA: ErtsCodeMfa = bif_mfa(atoms::REM, 2);
pub(crate) static DIV2_MFA: ErtsCodeMfa = bif_mfa(atoms::DIV_2, 2);
pub(crate) static BAND_MFA: ErtsCodeMfa = bif_mfa(atoms::BAND, 2);
pub(crate) static BOR_MFA: ErtsCodeMfa = bif_mfa(atoms::BOR, 2);
pub(crate) static BXOR_MFA: ErtsCodeMfa = bif_mfa(atoms::BXOR, 2);
pub(crate) static BNOT_MFA: ErtsCodeMfa = bif_mfa(atoms::BNOT, 1);
pub(crate) static BSL_MFA: ErtsCodeMfa = bif_mfa(atoms::BSL, 2);
pub(crate) static BSR_MFA: ErtsCodeMfa = bif_mfa(atoms::BSR, 2);

fn mfa_address(mfa: &'static ErtsCodeMfa) -> u64 {
    std::ptr::from_ref(mfa) as usize as u64
}

fn fits_i32(value: i64) -> bool {
    value as i32 as i64 == value
}

/// `ArgLabel` of an arithmetic instruction: label 0 means no fail label (body context).
fn beam_label(m: &BeamModuleAssembler, fail: ArgVal) -> Result<Option<Label>, AsmError> {
    let index = arg_label(fail)?;
    if index == 0 {
        Ok(None)
    } else {
        m.resolve_beam_label(index)
            .map(Some)
            .ok_or(AsmError::Operand("arithmetic fail label"))
    }
}

fn tagged_small(value: i64) -> i64 {
    (value << TAG_IMMED1_SIZE) | TAG_IMMED1_SMALL
}

fn arg_term(module: &BeamModuleAssembler, arg: ArgVal) -> u64 {
    match arg {
        ArgVal::Immediate(term) => term,
        ArgVal::Literal(index) => module.beamfile_get_literal(index),
        _ => 0,
    }
}

fn arg_small_value(arg: ArgVal) -> i64 {
    arg.small_signed().unwrap_or(0)
}

fn is_power_of_two(value: i64) -> bool {
    value > 0 && (value as u64).is_power_of_two()
}

fn safe_arith_fragment_call(
    m: &mut BeamModuleAssembler,
    label: GlobalLabels,
) -> Result<(), AsmError> {
    let address = m.ga_get(label)?;
    m.safe_fragment_call(address)
}

impl BeamGlobalAssembler {
    /// Runs the common bitwise fallback guard body for one erts runtime function.
    // Port of erts/emulator/beam/jit/x86/instr_arith.cpp:1218-1235
    // (emit_bitwise_fallback_guard), OTP-29.1.1.
    fn emit_bitwise_fallback_guard(&mut self, function: usize) -> Result<(), AsmError> {
        self.asm.emit_enter_frame()?;
        self.asm.emit_enter_runtime(Update::REDUCTIONS)?;
        self.asm.emit(|e| e.mov_rr(ARG1, C_P))?;
        self.asm.emit(|e| e.mov_rr(ARG3, RET))?;
        self.asm.runtime_call(function)?;
        self.asm.emit_leave_runtime(Update::REDUCTIONS)?;
        self.asm.emit_leave_frame()?;
        self.asm.emit_test_the_non_value(RET)?;
        self.asm.emit(|e| e.ret())?;
        Ok(())
    }

    /// Runs the common bitwise fallback body and raises with the operation's MFA on failure.
    // Port of erts/emulator/beam/jit/x86/instr_arith.cpp:1238-1270
    // (emit_bitwise_fallback_body), OTP-29.1.1.
    fn emit_bitwise_fallback_body(
        &mut self,
        function: usize,
        mfa: &'static ErtsCodeMfa,
    ) -> Result<(), AsmError> {
        let error = self.asm.a.new_label();
        self.asm.emit_enter_frame()?;
        self.asm.emit_enter_runtime(Update::REDUCTIONS)?;
        self.asm.emit(|e| e.mov_mr(tmp_mem_q(0), ARG2))?;
        self.asm.emit(|e| e.mov_mr(tmp_mem_q(1), RET))?;
        self.asm.emit(|e| e.mov_rr(ARG1, C_P))?;
        self.asm.emit(|e| e.mov_rr(ARG3, RET))?;
        self.asm.runtime_call(function)?;
        self.asm.emit_leave_runtime(Update::REDUCTIONS)?;
        self.asm.emit_leave_frame()?;
        self.asm.emit_test_the_non_value(RET)?;
        self.asm.short_jcc(CondCode::E, error)?;
        self.asm.emit(|e| e.ret())?;
        self.asm.bind(error)?;
        self.asm.emit(|e| e.mov_rm(ARG1, tmp_mem_q(0)))?;
        self.asm.emit(|e| e.mov_rm(ARG2, tmp_mem_q(1)))?;
        self.asm
            .emit(|e| e.mov_mr(crate::x86::beam_asm::get_x_ref(0, 8), ARG1))?;
        self.asm
            .emit(|e| e.mov_mr(crate::x86::beam_asm::get_x_ref(1, 8), ARG2))?;
        self.asm.mov_imm(ARG4, mfa_address(mfa))?;
        self.asm.jmp(self.label(GlobalLabels::RaiseException))?;
        Ok(())
    }

    /// Shared body for mixed integer/float addition.
    // Port of erts/emulator/beam/jit/x86/instr_arith.cpp:124-157 (emit_plus_body_shared),
    // OTP-29.1.1.
    pub(crate) fn emit_plus_body_shared(&mut self) -> Result<(), AsmError> {
        let error = self.asm.a.new_label();
        self.asm.emit_enter_frame()?;
        self.asm.emit_enter_runtime(Update::REDUCTIONS)?;
        self.asm.emit(|e| e.mov_mr(tmp_mem_q(0), ARG2))?;
        self.asm.emit(|e| e.mov_mr(tmp_mem_q(1), ARG3))?;
        self.asm.emit(|e| e.mov_rr(ARG1, C_P))?;
        self.asm.runtime_call(addr(erts_mixed_plus as *const ()))?;
        self.asm.emit_leave_runtime(Update::REDUCTIONS)?;
        self.asm.emit_leave_frame()?;
        self.asm.emit_test_the_non_value(RET)?;
        self.asm.short_jcc(CondCode::E, error)?;
        self.asm.emit(|e| e.ret())?;
        self.asm.bind(error)?;
        self.asm.emit(|e| e.mov_rm(ARG1, tmp_mem_q(0)))?;
        self.asm.emit(|e| e.mov_rm(ARG2, tmp_mem_q(1)))?;
        self.asm
            .emit(|e| e.mov_mr(crate::x86::beam_asm::get_x_ref(0, 8), ARG1))?;
        self.asm
            .emit(|e| e.mov_mr(crate::x86::beam_asm::get_x_ref(1, 8), ARG2))?;
        self.asm.mov_imm(ARG4, mfa_address(&PLUS_MFA))?;
        self.asm.jmp(self.label(GlobalLabels::RaiseException))
    }

    /// Shared guard body for mixed integer/float addition.
    // Port of erts/emulator/beam/jit/x86/instr_arith.cpp:159-173 (emit_plus_guard_shared),
    // OTP-29.1.1.
    pub(crate) fn emit_plus_guard_shared(&mut self) -> Result<(), AsmError> {
        self.asm.emit_enter_frame()?;
        self.asm.emit_enter_runtime(Update::REDUCTIONS)?;
        self.asm.emit(|e| e.mov_rr(ARG1, C_P))?;
        self.asm.runtime_call(addr(erts_mixed_plus as *const ()))?;
        self.asm.emit_leave_runtime(Update::REDUCTIONS)?;
        self.asm.emit_leave_frame()?;
        self.asm.emit_test_the_non_value(RET)?;
        self.asm.emit(|e| e.ret())?;
        Ok(())
    }

    /// Shared body for mixed integer/float subtraction.
    // Port of erts/emulator/beam/jit/x86/instr_arith.cpp:261-294 (emit_minus_body_shared),
    // OTP-29.1.1.
    pub(crate) fn emit_minus_body_shared(&mut self) -> Result<(), AsmError> {
        let error = self.asm.a.new_label();
        self.asm.emit_enter_frame()?;
        self.asm.emit_enter_runtime(Update::REDUCTIONS)?;
        self.asm.emit(|e| e.mov_mr(tmp_mem_q(0), ARG2))?;
        self.asm.emit(|e| e.mov_mr(tmp_mem_q(1), ARG3))?;
        self.asm.emit(|e| e.mov_rr(ARG1, C_P))?;
        self.asm.runtime_call(addr(erts_mixed_minus as *const ()))?;
        self.asm.emit_leave_runtime(Update::REDUCTIONS)?;
        self.asm.emit_leave_frame()?;
        self.asm.emit_test_the_non_value(RET)?;
        self.asm.short_jcc(CondCode::E, error)?;
        self.asm.emit(|e| e.ret())?;
        self.asm.bind(error)?;
        self.asm.emit(|e| e.mov_rm(ARG1, tmp_mem_q(0)))?;
        self.asm.emit(|e| e.mov_rm(ARG2, tmp_mem_q(1)))?;
        self.asm
            .emit(|e| e.mov_mr(crate::x86::beam_asm::get_x_ref(0, 8), ARG1))?;
        self.asm
            .emit(|e| e.mov_mr(crate::x86::beam_asm::get_x_ref(1, 8), ARG2))?;
        self.asm.mov_imm(ARG4, mfa_address(&MINUS_MFA))?;
        self.asm.jmp(self.label(GlobalLabels::RaiseException))
    }

    /// Shared guard body for mixed integer/float subtraction.
    // Port of erts/emulator/beam/jit/x86/instr_arith.cpp:296-310 (emit_minus_guard_shared),
    // OTP-29.1.1.
    pub(crate) fn emit_minus_guard_shared(&mut self) -> Result<(), AsmError> {
        self.asm.emit_enter_frame()?;
        self.asm.emit_enter_runtime(Update::REDUCTIONS)?;
        self.asm.emit(|e| e.mov_rr(ARG1, C_P))?;
        self.asm.runtime_call(addr(erts_mixed_minus as *const ()))?;
        self.asm.emit_leave_runtime(Update::REDUCTIONS)?;
        self.asm.emit_leave_frame()?;
        self.asm.emit_test_the_non_value(RET)?;
        self.asm.emit(|e| e.ret())?;
        Ok(())
    }

    /// Shared body for unary mixed negation.
    // Port of erts/emulator/beam/jit/x86/instr_arith.cpp:394-424
    // (emit_unary_minus_body_shared), OTP-29.1.1.
    pub(crate) fn emit_unary_minus_body_shared(&mut self) -> Result<(), AsmError> {
        let error = self.asm.a.new_label();
        self.asm.emit_enter_frame()?;
        self.asm.emit_enter_runtime(Update::REDUCTIONS)?;
        self.asm.emit(|e| e.mov_mr(tmp_mem_q(0), ARG2))?;
        self.asm.emit(|e| e.mov_rr(ARG1, C_P))?;
        self.asm.runtime_call(addr(erts_unary_minus as *const ()))?;
        self.asm.emit_leave_runtime(Update::REDUCTIONS)?;
        self.asm.emit_leave_frame()?;
        self.asm.emit_test_the_non_value(RET)?;
        self.asm.short_jcc(CondCode::E, error)?;
        self.asm.emit(|e| e.ret())?;
        self.asm.bind(error)?;
        self.asm.emit(|e| e.mov_rm(ARG1, tmp_mem_q(0)))?;
        self.asm
            .emit(|e| e.mov_mr(crate::x86::beam_asm::get_x_ref(0, 8), ARG1))?;
        self.asm.mov_imm(ARG4, mfa_address(&UNARY_MINUS_MFA))?;
        self.asm.jmp(self.label(GlobalLabels::RaiseException))
    }

    /// Shared guard body for unary mixed negation.
    // Port of erts/emulator/beam/jit/x86/instr_arith.cpp:426-440
    // (emit_unary_minus_guard_shared), OTP-29.1.1.
    pub(crate) fn emit_unary_minus_guard_shared(&mut self) -> Result<(), AsmError> {
        self.asm.emit_enter_frame()?;
        self.asm.emit_enter_runtime(Update::REDUCTIONS)?;
        self.asm.emit(|e| e.mov_rr(ARG1, C_P))?;
        self.asm.runtime_call(addr(erts_unary_minus as *const ()))?;
        self.asm.emit_leave_runtime(Update::REDUCTIONS)?;
        self.asm.emit_leave_frame()?;
        self.asm.emit_test_the_non_value(RET)?;
        self.asm.emit(|e| e.ret())?;
        Ok(())
    }
}

impl BeamGlobalAssembler {
    /// Shared integer div/rem fragment used by guard instructions.
    // Port of erts/emulator/beam/jit/x86/instr_arith.cpp:498-575
    // (emit_int_div_rem_guard_shared), OTP-29.1.1.
    pub(crate) fn emit_int_div_rem_guard_shared(&mut self) -> Result<(), AsmError> {
        let exit = self.asm.a.new_label();
        let generic = self.asm.a.new_label();
        self.asm.emit_enter_frame()?;
        self.asm.emit(|e| e.cmp_ri(ARG4, SMALL_ZERO))?;
        self.asm.jcc(CondCode::E, exit)?;
        self.asm.emit(|e| e.mov_rr(ARG2D, ARG1D))?;
        self.asm.emit(|e| e.and_rr(ARG2D, ARG4D))?;
        self.asm.emit(|e| e.and_ri(ARG2D, TAG_IMMED1_MASK))?;
        self.asm.emit(|e| e.cmp_ri(ARG2D, TAG_IMMED1_SMALL))?;
        self.asm.jcc(CondCode::NE, generic)?;
        self.asm.emit(|e| e.mov_rr(ARG5, ARG4))?;
        self.asm.emit(|e| e.sar_ri(ARG5, TAG_IMMED1_SIZE))?;
        self.asm.emit(|e| e.mov_rr(enc::RAX, ARG1))?;
        self.asm.emit(|e| e.sar_ri(enc::RAX, TAG_IMMED1_SIZE))?;
        self.asm.emit(|e| e.cqo())?;
        self.asm.emit(|e| e.idiv_r(ARG5))?;
        self.asm.emit(|e| e.mov_rr(ARG5, enc::RAX))?;
        self.asm.emit(|e| e.shl_ri(enc::RAX, TAG_IMMED1_SIZE))?;
        self.asm.emit(|e| e.shl_ri(enc::RDX, TAG_IMMED1_SIZE))?;
        self.asm.emit(|e| e.or_ri(enc::RAX, TAG_IMMED1_SMALL))?;
        self.asm.emit(|e| e.or_ri(enc::RDX, TAG_IMMED1_SMALL))?;
        self.asm
            .emit(|e| e.sar_ri(ARG5, i64::from(SMALL_BITS - 1)))?;
        self.asm.emit(|e| e.cmp_ri(ARG5, 1))?;
        self.asm.jcc(CondCode::L, exit)?;
        self.asm.bind(generic)?;
        self.asm.emit_enter_runtime(Update::REDUCTIONS)?;
        self.asm.emit(|e| e.mov_rr(ARG2, ARG1))?;
        self.asm.emit(|e| e.mov_rr(ARG3, ARG4))?;
        self.asm.emit(|e| e.lea(ARG4, tmp_mem_q(0)))?;
        self.asm.emit(|e| e.lea(ARG5, tmp_mem_q(1)))?;
        self.asm.emit(|e| e.mov_rr(ARG1, C_P))?;
        self.asm.runtime_call(addr(erts_int_div_rem as *const ()))?;
        self.asm.emit_leave_runtime(Update::REDUCTIONS)?;
        self.asm.emit(|e| e.test_rr(RETD, RETD))?;
        self.asm.emit(|e| e.mov_rm(enc::RAX, tmp_mem_q(0)))?;
        self.asm.emit(|e| e.mov_rm(enc::RDX, tmp_mem_q(1)))?;
        self.asm.bind(exit)?;
        self.asm.emit_leave_frame()?;
        self.asm.emit(|e| e.ret())
    }

    /// Shared integer div/rem fragment used by body instructions.
    // Port of erts/emulator/beam/jit/x86/instr_arith.cpp:578-679
    // (emit_int_div_rem_body_shared), OTP-29.1.1.
    pub(crate) fn emit_int_div_rem_body_shared(&mut self) -> Result<(), AsmError> {
        let div_zero = self.asm.a.new_label();
        let generic_div = self.asm.a.new_label();
        let generic_error = self.asm.a.new_label();
        self.asm.emit_enter_frame()?;
        self.asm.emit(|e| e.cmp_ri(ARG4, SMALL_ZERO))?;
        self.asm.jcc(CondCode::E, div_zero)?;
        self.asm.emit(|e| e.mov_rr(ARG2D, ARG1D))?;
        self.asm.emit(|e| e.and_rr(ARG2D, ARG4D))?;
        self.asm.emit(|e| e.and_ri(ARG2D, TAG_IMMED1_MASK))?;
        self.asm.emit(|e| e.cmp_ri(ARG2D, TAG_IMMED1_SMALL))?;
        self.asm.jcc(CondCode::NE, generic_div)?;
        self.asm.emit(|e| e.mov_rr(ARG6, ARG4))?;
        self.asm.emit(|e| e.sar_ri(ARG6, TAG_IMMED1_SIZE))?;
        self.asm.emit(|e| e.mov_rr(enc::RAX, ARG1))?;
        self.asm.emit(|e| e.sar_ri(enc::RAX, TAG_IMMED1_SIZE))?;
        self.asm.emit(|e| e.cqo())?;
        self.asm.emit(|e| e.idiv_r(ARG6))?;
        self.asm.emit(|e| e.mov_rr(ARG6, enc::RAX))?;
        self.asm.emit(|e| e.shl_ri(enc::RAX, TAG_IMMED1_SIZE))?;
        self.asm.emit(|e| e.shl_ri(enc::RDX, TAG_IMMED1_SIZE))?;
        self.asm.emit(|e| e.or_ri(enc::RAX, TAG_IMMED1_SMALL))?;
        self.asm.emit(|e| e.or_ri(enc::RDX, TAG_IMMED1_SMALL))?;
        self.asm
            .emit(|e| e.sar_ri(ARG6, i64::from(SMALL_BITS - 1)))?;
        self.asm.emit(|e| e.cmp_ri(ARG6, 1))?;
        self.asm.short_jcc(CondCode::GE, generic_div)?;
        self.asm.emit_leave_frame()?;
        self.asm.emit(|e| e.ret())?;

        self.asm.bind(generic_div)?;
        self.asm.emit_enter_runtime(Update::REDUCTIONS)?;
        self.asm.emit(|e| e.mov_mr(tmp_mem_q(0), ARG1))?;
        self.asm.emit(|e| e.mov_mr(tmp_mem_q(1), ARG4))?;
        self.asm.emit(|e| e.mov_mr(tmp_mem_q(2), ARG5))?;
        self.asm.emit(|e| e.mov_rr(ARG2, ARG1))?;
        self.asm.emit(|e| e.mov_rr(ARG3, ARG4))?;
        self.asm.emit(|e| e.lea(ARG4, tmp_mem_q(3)))?;
        self.asm.emit(|e| e.lea(ARG5, tmp_mem_q(4)))?;
        self.asm.emit(|e| e.mov_rr(ARG1, C_P))?;
        self.asm.runtime_call(addr(erts_int_div_rem as *const ()))?;
        self.asm.emit_leave_runtime(Update::REDUCTIONS)?;
        self.asm.emit_leave_frame()?;
        self.asm.emit(|e| e.test_rr(RETD, RETD))?;
        self.asm.emit(|e| e.mov_rm(enc::RAX, tmp_mem_q(3)))?;
        self.asm.emit(|e| e.mov_rm(enc::RDX, tmp_mem_q(4)))?;
        self.asm.short_jcc(CondCode::E, generic_error)?;
        self.asm.emit(|e| e.ret())?;

        self.asm.bind(div_zero)?;
        self.asm.emit_leave_frame()?;
        self.asm
            .emit(|e| e.mov_mi(process_ref(process::FREASON, 8), EXC_BADARITH as i64))?;
        self.asm
            .emit(|e| e.mov_mr(crate::x86::beam_asm::get_x_ref(0, 8), ARG1))?;
        self.asm
            .emit(|e| e.mov_mr(crate::x86::beam_asm::get_x_ref(1, 8), ARG4))?;
        self.asm.emit(|e| e.mov_rr(ARG4, ARG5))?;
        self.asm.jmp(self.label(GlobalLabels::RaiseException))?;

        self.asm.bind(generic_error)?;
        self.asm.emit(|e| e.mov_rm(ARG1, tmp_mem_q(0)))?;
        self.asm.emit(|e| e.mov_rm(ARG2, tmp_mem_q(1)))?;
        self.asm
            .emit(|e| e.mov_mr(crate::x86::beam_asm::get_x_ref(0, 8), ARG1))?;
        self.asm
            .emit(|e| e.mov_mr(crate::x86::beam_asm::get_x_ref(1, 8), ARG2))?;
        self.asm.emit(|e| e.mov_rm(ARG4, tmp_mem_q(2)))?;
        self.asm.jmp(self.label(GlobalLabels::RaiseException))
    }

    /// Shared guard body for multiplication plus addition.
    // Port of erts/emulator/beam/jit/x86/instr_arith.cpp:915-947
    // (emit_mul_add_guard_shared), OTP-29.1.1.
    pub(crate) fn emit_mul_add_guard_shared(&mut self) -> Result<(), AsmError> {
        let done = self.asm.a.new_label();
        self.asm.emit_enter_frame()?;
        self.asm.emit_enter_runtime(Update::REDUCTIONS)?;
        self.asm.emit(|e| e.mov_mr(tmp_mem_q(0), ARG4))?;
        self.asm.emit(|e| e.mov_rr(ARG1, C_P))?;
        self.asm.runtime_call(addr(erts_mixed_times as *const ()))?;
        self.asm.emit_test_the_non_value(RET)?;
        self.asm.short_jcc(CondCode::E, done)?;
        self.asm.emit(|e| e.mov_rm(ARG3, tmp_mem_q(0)))?;
        self.asm.emit(|e| e.mov_rr(ARG2, RET))?;
        self.asm.emit(|e| e.mov_rr(ARG1, C_P))?;
        self.asm.emit(|e| e.cmp_ri(ARG3, tagged_small(0)))?;
        self.asm.short_jcc(CondCode::E, done)?;
        self.asm.runtime_call(addr(erts_mixed_plus as *const ()))?;
        self.asm.bind(done)?;
        self.asm.emit_leave_runtime(Update::REDUCTIONS)?;
        self.asm.emit_leave_frame()?;
        self.asm.emit_test_the_non_value(RET)?;
        self.asm.emit(|e| e.ret())
    }

    /// Shared body for multiplication plus addition.
    // Port of erts/emulator/beam/jit/x86/instr_arith.cpp:949-1015
    // (emit_mul_add_body_shared), OTP-29.1.1.
    pub(crate) fn emit_mul_add_body_shared(&mut self) -> Result<(), AsmError> {
        let mul_only = self.asm.a.new_label();
        let error = self.asm.a.new_label();
        let mul_error = self.asm.a.new_label();
        let do_error = self.asm.a.new_label();
        self.asm.emit_enter_frame()?;
        self.asm.emit_enter_runtime(Update::REDUCTIONS)?;
        self.asm.emit(|e| e.mov_mr(tmp_mem_q(0), ARG2))?;
        self.asm.emit(|e| e.mov_mr(tmp_mem_q(1), ARG3))?;
        self.asm.emit(|e| e.mov_rr(ARG1, C_P))?;
        self.asm.emit(|e| e.cmp_ri(ARG4, tagged_small(0)))?;
        self.asm.short_jcc(CondCode::E, mul_only)?;
        self.asm.emit(|e| e.mov_mr(tmp_mem_q(3), ARG4))?;
        self.asm.emit(|e| e.lea(ARG5, tmp_mem_q(2)))?;
        self.asm.runtime_call(addr(erts_mul_add as *const ()))?;
        self.asm.emit_leave_runtime(Update::REDUCTIONS)?;
        self.asm.emit_leave_frame()?;
        self.asm.emit_test_the_non_value(RET)?;
        self.asm.short_jcc(CondCode::E, error)?;
        self.asm.emit(|e| e.ret())?;

        self.asm.bind(mul_only)?;
        self.asm.runtime_call(addr(erts_mixed_times as *const ()))?;
        self.asm.emit_leave_runtime(Update::REDUCTIONS)?;
        self.asm.emit_leave_frame()?;
        self.asm.emit_test_the_non_value(RET)?;
        self.asm.short_jcc(CondCode::E, mul_error)?;
        self.asm.emit(|e| e.ret())?;

        self.asm.bind(error)?;
        self.asm.emit(|e| e.mov_rm(ARG1, tmp_mem_q(2)))?;
        self.asm.emit(|e| e.mov_rm(ARG2, tmp_mem_q(3)))?;
        self.asm.mov_imm(ARG4, mfa_address(&PLUS_MFA))?;
        self.asm.emit_test_the_non_value(ARG1)?;
        self.asm.short_jcc(CondCode::NE, do_error)?;
        self.asm.bind(mul_error)?;
        self.asm.emit(|e| e.mov_rm(ARG1, tmp_mem_q(0)))?;
        self.asm.emit(|e| e.mov_rm(ARG2, tmp_mem_q(1)))?;
        self.asm.mov_imm(ARG4, mfa_address(&TIMES_MFA))?;
        self.asm.bind(do_error)?;
        self.asm
            .emit(|e| e.mov_mr(crate::x86::beam_asm::get_x_ref(0, 8), ARG1))?;
        self.asm
            .emit(|e| e.mov_mr(crate::x86::beam_asm::get_x_ref(1, 8), ARG2))?;
        self.asm.jmp(self.label(GlobalLabels::RaiseException))
    }

    /// Shared multiplication body, tail-calling multiply-add with a zero increment.
    // Port of erts/emulator/beam/jit/x86/instr_arith.cpp:1017-1025 (emit_mul_body_shared),
    // OTP-29.1.1.
    pub(crate) fn emit_mul_body_shared(&mut self) -> Result<(), AsmError> {
        self.asm.mov_imm(ARG4, tagged_small(0) as u64)?;
        self.asm.jmp(self.label(GlobalLabels::MulAddBodyShared))
    }

    /// Shared multiplication guard, tail-calling multiply-add with a zero increment.
    // Port of erts/emulator/beam/jit/x86/instr_arith.cpp:1027-1030 (emit_mul_guard_shared),
    // OTP-29.1.1.
    pub(crate) fn emit_mul_guard_shared(&mut self) -> Result<(), AsmError> {
        self.asm.mov_imm(ARG4, tagged_small(0) as u64)?;
        self.asm.jmp(self.label(GlobalLabels::MulAddGuardShared))
    }
}

impl BeamModuleAssembler {
    /// Emits tagged-small addition and its mixed-number fragment path.
    // Port of erts/emulator/beam/jit/x86/instr_arith.cpp:175-258 (emit_i_plus), OTP-29.1.1.
    pub fn emit_i_plus(
        &mut self,
        lhs: ArgVal,
        rhs: ArgVal,
        fail: ArgVal,
        dst: ArgVal,
    ) -> Result<(), AsmError> {
        let small_result = self.is_sum_small_if_args_are_small(lhs, rhs);
        let rhs_term = arg_term(self, rhs);
        let rhs_untagged = arg_small_value(rhs) << TAG_IMMED1_SIZE;
        let rhs_is_literal = rhs.is_small() && fits_i32(rhs_untagged);

        if self.always_small(lhs) && self.always_small(rhs) && small_result {
            self.mov_arg_to_reg(RET, lhs)?;
            if rhs_is_literal {
                self.preserve_cache(&[RET], &[], |m| m.asm.emit(|e| e.add_ri(RET, rhs_untagged)))?;
            } else if rhs.is_small() {
                self.preserve_cache(&[RET, ARG2], &[], |m| {
                    m.asm.mov_imm(ARG2, rhs_term & !(TAG_IMMED1_MASK as u64))?;
                    m.asm.emit(|e| e.add_rr(RET, ARG2))
                })?;
            } else {
                self.mov_arg_to_reg(ARG2, rhs)?;
                self.preserve_cache(&[RET], &[], |m| {
                    m.asm.emit(|e| {
                        e.lea(
                            RET,
                            Mem::base_index(RET, ARG2, 0, -TAG_IMMED1_SMALL as i32, 8),
                        )
                    })
                })?;
            }
            return self.mov_arg_from_reg(dst, RET);
        }

        let next = self.asm.new_label();
        let mixed = self.asm.new_label();
        self.mov_arg_to_reg(ARG2, lhs)?;
        self.mov_arg_to_reg(ARG3, rhs)?;
        if !lhs.is_literal() && !rhs.is_literal() {
            self.emit_are_both_small(mixed, lhs, ARG2, rhs, ARG3)?;
            if small_result {
                self.asm.emit(|e| {
                    e.lea(
                        RET,
                        Mem::base_index(ARG2, ARG3, 0, -TAG_IMMED1_SMALL as i32, 8),
                    )
                })?;
                self.asm.short_jmp(next)?;
            } else {
                self.asm
                    .emit(|e| e.lea(RET, qword_ptr(ARG2, -TAG_IMMED1_SMALL as i32)))?;
                self.asm.emit(|e| e.add_rr(RET, ARG3))?;
                self.asm.short_jcc(CondCode::NO, next)?;
            }
        }
        self.asm.bind(mixed)?;
        if let Some(fail_label) = beam_label(self, fail)? {
            safe_arith_fragment_call(self, GlobalLabels::PlusGuardShared)?;
            self.asm.jcc(CondCode::E, fail_label)?;
        } else {
            safe_arith_fragment_call(self, GlobalLabels::PlusBodyShared)?;
        }
        self.asm.bind(next)?;
        self.mov_arg_from_reg(dst, RET)
    }

    /// Emits tagged-small subtraction and its mixed-number fragment path.
    // Port of erts/emulator/beam/jit/x86/instr_arith.cpp:312-391 (emit_i_minus), OTP-29.1.1.
    pub fn emit_i_minus(
        &mut self,
        lhs: ArgVal,
        rhs: ArgVal,
        fail: ArgVal,
        dst: ArgVal,
    ) -> Result<(), AsmError> {
        let small_result = self.is_diff_small_if_args_are_small(lhs, rhs);
        let rhs_untagged = arg_small_value(rhs) << TAG_IMMED1_SIZE;
        let rhs_is_literal = rhs.is_small() && fits_i32(rhs_untagged);

        if self.always_small(lhs) && self.always_small(rhs) && small_result {
            self.mov_arg_to_reg(RET, lhs)?;
            if rhs_is_literal {
                self.preserve_cache(&[RET], &[], |m| m.asm.emit(|e| e.sub_ri(RET, rhs_untagged)))?;
            } else if rhs.is_small() {
                self.asm
                    .mov_imm(ARG2, arg_term(self, rhs) & !(TAG_IMMED1_MASK as u64))?;
                self.asm.emit(|e| e.sub_rr(RET, ARG2))?;
            } else {
                self.mov_arg_to_reg(ARG2, rhs)?;
                self.asm.emit(|e| e.and_ri(ARG2, !TAG_IMMED1_MASK))?;
                self.asm.emit(|e| e.sub_rr(RET, ARG2))?;
            }
            return self.mov_arg_from_reg(dst, RET);
        }

        let next = self.asm.new_label();
        let mixed = self.asm.new_label();
        self.mov_arg_to_reg(ARG2, lhs)?;
        self.mov_arg_to_reg(ARG3, rhs)?;
        if !lhs.is_literal() && !rhs.is_literal() {
            self.emit_are_both_small(mixed, lhs, ARG2, rhs, ARG3)?;
            self.asm.emit(|e| e.mov_rr(RET, ARG2))?;
            if small_result {
                if rhs_is_literal {
                    self.asm.emit(|e| e.sub_ri(RET, rhs_untagged))?;
                } else {
                    self.asm.emit(|e| e.and_ri(ARG3, !TAG_IMMED1_MASK))?;
                    self.asm.emit(|e| e.sub_rr(RET, ARG3))?;
                }
                self.asm.short_jmp(next)?;
            } else {
                if rhs_is_literal {
                    self.asm.emit(|e| e.sub_ri(RET, rhs_untagged))?;
                } else {
                    self.asm
                        .emit(|e| e.lea(ARG4, qword_ptr(ARG3, -TAG_IMMED1_SMALL as i32)))?;
                    self.asm.emit(|e| e.sub_rr(RET, ARG4))?;
                }
                self.asm.short_jcc(CondCode::NO, next)?;
            }
        }
        self.asm.bind(mixed)?;
        if let Some(fail_label) = beam_label(self, fail)? {
            safe_arith_fragment_call(self, GlobalLabels::MinusGuardShared)?;
            self.asm.jcc(CondCode::E, fail_label)?;
        } else {
            safe_arith_fragment_call(self, GlobalLabels::MinusBodyShared)?;
        }
        self.asm.bind(next)?;
        self.mov_arg_from_reg(dst, RET)
    }

    /// Emits tagged-small unary negation and its mixed-number fragment path.
    // Port of erts/emulator/beam/jit/x86/instr_arith.cpp:442-495
    // (emit_i_unary_minus), OTP-29.1.1.
    pub fn emit_i_unary_minus(
        &mut self,
        src: ArgVal,
        fail: ArgVal,
        dst: ArgVal,
    ) -> Result<(), AsmError> {
        let small_result =
            self.is_diff_small_if_args_are_small(ArgVal::Immediate(SMALL_ZERO as u64), src);
        if self.always_small(src) && small_result {
            self.mov_arg_to_reg(ARG2, src)?;
            self.asm.emit(|e| e.mov_ri(RETD, TAG_IMMED1_SMALL))?;
            self.asm.emit(|e| e.and_ri(ARG2, !TAG_IMMED1_MASK))?;
            self.asm.emit(|e| e.sub_rr(RET, ARG2))?;
            return self.mov_arg_from_reg(dst, RET);
        }

        let next = self.asm.new_label();
        let mixed = self.asm.new_label();
        self.mov_arg_to_reg(ARG2, src)?;
        self.asm.emit(|e| e.mov_rr(RETD, ARG2D))?;
        self.asm.emit(|e| e.and_ri(RETB, TAG_IMMED1_MASK))?;
        self.asm.emit(|e| e.cmp_ri(RETB, TAG_IMMED1_SMALL))?;
        self.asm.short_jcc(CondCode::NE, mixed)?;
        self.asm.emit(|e| e.movzx_rr(RET, RETB))?;
        self.asm.emit(|e| e.mov_rr(ARG3, ARG2))?;
        self.asm.emit(|e| e.and_ri(ARG3, !TAG_IMMED1_MASK))?;
        self.asm.emit(|e| e.sub_rr(RET, ARG3))?;
        if small_result {
            self.asm.short_jmp(next)?;
        } else {
            self.asm.short_jcc(CondCode::NO, next)?;
        }
        self.asm.bind(mixed)?;
        if let Some(fail_label) = beam_label(self, fail)? {
            safe_arith_fragment_call(self, GlobalLabels::UnaryMinusGuardShared)?;
            self.asm.jcc(CondCode::E, fail_label)?;
        } else {
            safe_arith_fragment_call(self, GlobalLabels::UnaryMinusBodyShared)?;
        }
        self.asm.bind(next)?;
        self.mov_arg_from_reg(dst, RET)
    }
}

impl BeamModuleAssembler {
    /// Emits the small-integer test used by arithmetic fast paths.
    // Port of erts/emulator/beam/jit/x86/instr_arith.cpp:39-60 (emit_is_small), OTP-29.1.1.
    pub fn emit_is_small(&mut self, fail: Label, arg: ArgVal, reg: Gp) -> Result<(), AsmError> {
        assert_ne!(ARG1, reg);

        if self.always_small(arg) {
            // The type range proves the check.
        } else if self.always_one_of(arg, type_id::NUMBER) {
            self.asm.emit(|e| e.test_ri(reg.r8(), TAG_PRIMARY_LIST))?;
            self.asm.short_jcc(arinsal_x64::enc::CondCode::E, fail)?;
        } else {
            self.asm.emit(|e| e.mov_rr(ARG1D, reg.r32()))?;
            self.asm.emit(|e| e.and_ri(ARG1D, TAG_IMMED1_MASK))?;
            self.asm.emit(|e| e.cmp_ri(ARG1D, TAG_IMMED1_SMALL))?;
            self.asm.short_jcc(arinsal_x64::enc::CondCode::NE, fail)?;
        }
        Ok(())
    }

    /// Emits a single small-integer test for two arithmetic operands.
    // Port of erts/emulator/beam/jit/x86/instr_arith.cpp:62-121
    // (emit_are_both_small), OTP-29.1.1.
    pub fn emit_are_both_small(
        &mut self,
        fail: Label,
        lhs: ArgVal,
        a: Gp,
        rhs: ArgVal,
        b: Gp,
    ) -> Result<(), AsmError> {
        assert_ne!(ARG1, a);
        assert_ne!(ARG1, b);

        if self.always_small(lhs) && self.always_small(rhs) {
            return Ok(());
        }

        if self.always_one_of(lhs, type_id::NUMBER) && self.always_one_of(rhs, type_id::NUMBER) {
            if self.always_small(rhs) {
                self.asm.emit(|e| e.test_ri(a.r8(), TAG_PRIMARY_LIST))?;
            } else if self.always_small(lhs) {
                self.asm.emit(|e| e.test_ri(b.r8(), TAG_PRIMARY_LIST))?;
            } else if a != RET && b != RET {
                self.asm.emit(|e| e.mov_rr(RETD, a.r32()))?;
                self.asm.emit(|e| e.and_rr(RETD, b.r32()))?;
                self.asm.emit(|e| e.test_ri(RETB, TAG_PRIMARY_LIST))?;
            } else {
                self.asm.emit(|e| e.mov_rr(ARG1D, a.r32()))?;
                self.asm.emit(|e| e.and_rr(ARG1D, b.r32()))?;
                self.asm.emit(|e| e.test_ri(ARG1.r8(), TAG_PRIMARY_LIST))?;
            }
            self.asm.short_jcc(arinsal_x64::enc::CondCode::E, fail)?;
        } else if self.always_small(lhs) {
            if a == RET || b == RET {
                self.emit_is_small(fail, rhs, b)?;
            } else {
                self.asm.emit(|e| e.mov_rr(RETD, b.r32()))?;
                self.asm.emit(|e| e.and_ri(RETB, TAG_IMMED1_MASK))?;
                self.asm.emit(|e| e.cmp_ri(RETB, TAG_IMMED1_SMALL))?;
                self.asm.short_jcc(arinsal_x64::enc::CondCode::NE, fail)?;
            }
        } else if self.always_small(rhs) {
            if a == RET || b == RET {
                self.emit_is_small(fail, lhs, a)?;
            } else {
                self.asm.emit(|e| e.mov_rr(RETD, a.r32()))?;
                self.asm.emit(|e| e.and_ri(RETB, TAG_IMMED1_MASK))?;
                self.asm.emit(|e| e.cmp_ri(RETB, TAG_IMMED1_SMALL))?;
                self.asm.short_jcc(arinsal_x64::enc::CondCode::NE, fail)?;
            }
        } else if a != RET && b != RET {
            self.asm.emit(|e| e.mov_rr(RETD, a.r32()))?;
            self.asm.emit(|e| e.and_rr(RETD, b.r32()))?;
            self.asm.emit(|e| e.and_ri(RETB, TAG_IMMED1_MASK))?;
            self.asm.emit(|e| e.cmp_ri(RETB, TAG_IMMED1_SMALL))?;
            self.asm.short_jcc(arinsal_x64::enc::CondCode::NE, fail)?;
        } else {
            self.asm.emit(|e| e.mov_rr(ARG1D, a.r32()))?;
            self.asm.emit(|e| e.and_rr(ARG1D, b.r32()))?;
            self.asm.emit(|e| e.and_ri(ARG1D, TAG_IMMED1_MASK))?;
            self.asm.emit(|e| e.cmp_ri(ARG1D, TAG_IMMED1_SMALL))?;
            self.asm.short_jcc(arinsal_x64::enc::CondCode::NE, fail)?;
        }

        Ok(())
    }
}

impl BeamModuleAssembler {
    /// Emits the integer quotient/remainder fast path and generic fragment call.
    // Port of erts/emulator/beam/jit/x86/instr_arith.cpp:682-822 (emit_div_rem), OTP-29.1.1.
    fn emit_div_rem(
        &mut self,
        fail: ArgVal,
        lhs: ArgVal,
        rhs: ArgVal,
        error_mfa: &'static ErtsCodeMfa,
        need_div: bool,
        need_rem: bool,
    ) -> Result<(), AsmError> {
        let generic_div = self.asm.new_label();
        let next = self.asm.new_label();
        let mut need_generic = true;
        let divisor = if rhs.is_small() {
            arg_small_value(rhs)
        } else {
            0
        };
        self.mov_arg_to_reg(enc::RAX, lhs)?;

        if divisor != 0 && divisor != -1 {
            if self.always_small(lhs) {
                need_generic = false;
            } else if self.always_one_of(lhs, type_id::NUMBER) {
                self.asm.emit(|e| e.test_ri(enc::AL, TAG_PRIMARY_LIST))?;
                self.asm.short_jcc(CondCode::E, generic_div)?;
            } else {
                self.asm.emit(|e| e.mov_rr(ARG2D, enc::EAX))?;
                self.asm.emit(|e| e.and_ri(ARG2D, TAG_IMMED1_MASK))?;
                self.asm.emit(|e| e.cmp_ri(ARG2D, TAG_IMMED1_SMALL))?;
                self.asm.short_jcc(CondCode::NE, generic_div)?;
            }

            if is_power_of_two(divisor) && self.get_clamped_range(lhs).0 >= 0 {
                let trailing_bits = (divisor as u64).trailing_zeros() as i64;
                if need_rem {
                    let mask = (1_u64 << (trailing_bits + TAG_IMMED1_SIZE)) - 1;
                    self.asm.mov_imm(enc::RDX, mask)?;
                    self.asm.emit(|e| e.and_rr(enc::RDX, enc::RAX))?;
                }
                if need_div {
                    self.asm.emit(|e| e.shr_ri(enc::RAX, trailing_bits))?;
                    self.asm.emit(|e| e.or_ri(enc::RAX, TAG_IMMED1_SMALL))?;
                }
            } else if is_power_of_two(divisor) {
                let shift = (divisor as u64).trailing_zeros() as i64;
                let offset = (divisor - 1) << TAG_IMMED1_SIZE;
                if need_rem {
                    self.asm.emit(|e| e.mov_rr(enc::RDX, enc::RAX))?;
                }
                if need_div {
                    if divisor == 2 {
                        self.asm.emit(|e| e.mov_rr(ARG1, enc::RAX))?;
                        self.asm.emit(|e| e.shr_ri(ARG1, 63))?;
                        self.asm.emit(|e| e.add_rr(enc::RAX, ARG1))?;
                    } else {
                        if fits_i32(offset) {
                            self.asm
                                .emit(|e| e.lea(ARG1, qword_ptr(enc::RAX, offset as i32)))?;
                        } else {
                            self.asm.mov_imm(ARG1, offset as u64)?;
                            self.asm.emit(|e| e.add_rr(ARG1, enc::RAX))?;
                        }
                        self.asm.emit(|e| e.test_rr(enc::RAX, enc::RAX))?;
                        self.asm
                            .emit(|e| e.cmovcc_rr(CondCode::S, enc::RAX, ARG1))?;
                    }
                }
                if need_rem {
                    let mask = u64::MAX << (shift + TAG_IMMED1_SIZE);
                    self.asm.mov_imm(ARG1, mask)?;
                    self.asm.emit(|e| e.and_rr(ARG1, enc::RAX))?;
                    self.asm.emit(|e| e.sub_rr(enc::RDX, ARG1))?;
                }
                if need_div {
                    self.asm.emit(|e| e.sar_ri(enc::RAX, shift))?;
                    self.asm.emit(|e| e.or_ri(enc::RAX, TAG_IMMED1_SMALL))?;
                }
            } else {
                self.asm.mov_imm(ARG6, divisor as u64)?;
                self.asm.emit(|e| e.sar_ri(enc::RAX, TAG_IMMED1_SIZE))?;
                self.asm.emit(|e| e.cqo())?;
                self.asm.emit(|e| e.idiv_r(ARG6))?;
                if need_div {
                    self.asm.emit(|e| e.shl_ri(enc::RAX, TAG_IMMED1_SIZE))?;
                }
                if need_rem {
                    self.asm.emit(|e| e.shl_ri(enc::RDX, TAG_IMMED1_SIZE))?;
                }
                if need_div {
                    self.asm.emit(|e| e.or_ri(enc::RAX, TAG_IMMED1_SMALL))?;
                }
                if need_rem {
                    self.asm.emit(|e| e.or_ri(enc::RDX, TAG_IMMED1_SMALL))?;
                }
            }
            if need_generic {
                self.asm.short_jmp(next)?;
            }
        }

        self.asm.bind(generic_div)?;
        if need_generic {
            self.mov_arg_to_reg(ARG4, rhs)?;
            self.asm.emit(|e| e.mov_rr(ARG1, enc::RAX))?;
            if let Some(fail_label) = beam_label(self, fail)? {
                safe_arith_fragment_call(self, GlobalLabels::IntDivRemGuardShared)?;
                self.asm.jcc(CondCode::E, fail_label)?;
            } else {
                self.asm.mov_imm(ARG5, mfa_address(error_mfa))?;
                safe_arith_fragment_call(self, GlobalLabels::IntDivRemBodyShared)?;
            }
        }
        self.asm.bind(next)
    }

    /// Emits Erlang `rem` and `div` into their two destination registers.
    // Port of erts/emulator/beam/jit/x86/instr_arith.cpp:824-835 (emit_i_rem_div), OTP-29.1.1.
    pub fn emit_i_rem_div(
        &mut self,
        lhs: ArgVal,
        rhs: ArgVal,
        fail: ArgVal,
        remainder: ArgVal,
        quotient: ArgVal,
    ) -> Result<(), AsmError> {
        self.emit_div_rem(fail, lhs, rhs, &REM_MFA, true, true)?;
        self.mov_arg_from_reg(remainder, enc::RDX)?;
        self.mov_arg_from_reg(quotient, enc::RAX)
    }

    /// Emits Erlang `div` and `rem` into their two destination registers.
    // Port of erts/emulator/beam/jit/x86/instr_arith.cpp:837-848 (emit_i_div_rem), OTP-29.1.1.
    pub fn emit_i_div_rem(
        &mut self,
        lhs: ArgVal,
        rhs: ArgVal,
        fail: ArgVal,
        quotient: ArgVal,
        remainder: ArgVal,
    ) -> Result<(), AsmError> {
        self.emit_div_rem(fail, lhs, rhs, &DIV_MFA, true, true)?;
        self.mov_arg_from_reg(quotient, enc::RAX)?;
        self.mov_arg_from_reg(remainder, enc::RDX)
    }

    /// Emits integer division, omitting the remainder result when unused.
    // Port of erts/emulator/beam/jit/x86/instr_arith.cpp:850-859 (emit_i_int_div), OTP-29.1.1.
    pub fn emit_i_int_div(
        &mut self,
        fail: ArgVal,
        lhs: ArgVal,
        rhs: ArgVal,
        quotient: ArgVal,
    ) -> Result<(), AsmError> {
        self.emit_div_rem(fail, lhs, rhs, &DIV_MFA, true, false)?;
        self.mov_arg_from_reg(quotient, enc::RAX)
    }

    /// Emits integer remainder, omitting the quotient result when unused.
    // Port of erts/emulator/beam/jit/x86/instr_arith.cpp:861-870 (emit_i_rem), OTP-29.1.1.
    pub fn emit_i_rem(
        &mut self,
        lhs: ArgVal,
        rhs: ArgVal,
        fail: ArgVal,
        remainder: ArgVal,
    ) -> Result<(), AsmError> {
        self.emit_div_rem(fail, lhs, rhs, &REM_MFA, false, true)?;
        self.mov_arg_from_reg(remainder, enc::RDX)
    }

    /// Emits mixed integer/float division using `erts_mixed_div`.
    // Port of erts/emulator/beam/jit/x86/instr_arith.cpp:872-913 (emit_i_m_div), OTP-29.1.1.
    pub fn emit_i_m_div(
        &mut self,
        fail: ArgVal,
        lhs: ArgVal,
        rhs: ArgVal,
        dst: ArgVal,
    ) -> Result<(), AsmError> {
        let next = self.asm.new_label();
        self.mov_arg_to_reg(ARG2, lhs)?;
        self.mov_arg_to_reg(ARG3, rhs)?;
        self.asm.emit_enter_runtime(Update::NONE)?;
        self.asm.emit(|e| e.mov_rr(ARG1, C_P))?;
        self.asm.runtime_call(addr(erts_mixed_div as *const ()))?;
        self.asm.emit_leave_runtime(Update::NONE)?;
        self.asm.emit_test_the_non_value(RET)?;
        if let Some(fail_label) = beam_label(self, fail)? {
            self.asm.jcc(CondCode::E, fail_label)?;
        } else {
            self.asm.short_jcc(CondCode::NE, next)?;
            self.mov_arg_to_reg(ARG2, lhs)?;
            self.mov_arg_to_reg(ARG3, rhs)?;
            self.mov_arg_from_reg(ArgVal::X(0), ARG2)?;
            self.mov_arg_from_reg(ArgVal::X(1), ARG3)?;
            self.emit_raise_exception_mfa(&DIV2_MFA)?;
        }
        self.asm.bind(next)?;
        self.mov_arg_from_reg(dst, RET)
    }
}

impl BeamGlobalAssembler {
    /// Shared guard fragment for band.
    // Port of erts/emulator/beam/jit/x86/instr_arith.cpp:1273-1276
    // (emit_i_band_guard_shared), OTP-29.1.1.
    pub(crate) fn emit_i_band_guard_shared(&mut self) -> Result<(), AsmError> {
        self.emit_bitwise_fallback_guard(addr(erts_band as *const ()))
    }

    /// Shared body fragment for band.
    // Port of erts/emulator/beam/jit/x86/instr_arith.cpp:1278-1282
    // (emit_i_band_body_shared), OTP-29.1.1.
    pub(crate) fn emit_i_band_body_shared(&mut self) -> Result<(), AsmError> {
        self.emit_bitwise_fallback_body(addr(erts_band as *const ()), &BAND_MFA)
    }

    /// Shared guard fragment for bor.
    // Port of erts/emulator/beam/jit/x86/instr_arith.cpp:1344-1349
    // (emit_i_bor_guard_shared), OTP-29.1.1.
    pub(crate) fn emit_i_bor_guard_shared(&mut self) -> Result<(), AsmError> {
        self.emit_bitwise_fallback_guard(addr(erts_bor as *const ()))
    }

    /// Shared body fragment for bor.
    // Port of erts/emulator/beam/jit/x86/instr_arith.cpp:1351-1355
    /// (emit_i_bor_body_shared), OTP-29.1.1.
    pub(crate) fn emit_i_bor_body_shared(&mut self) -> Result<(), AsmError> {
        self.emit_bitwise_fallback_body(addr(erts_bor as *const ()), &BOR_MFA)
    }

    /// Shared guard fragment for bxor.
    // Port of erts/emulator/beam/jit/x86/instr_arith.cpp:1403-1408
    // (emit_i_bxor_guard_shared), OTP-29.1.1.
    pub(crate) fn emit_i_bxor_guard_shared(&mut self) -> Result<(), AsmError> {
        self.emit_bitwise_fallback_guard(addr(erts_bxor as *const ()))
    }

    /// Shared body fragment for bxor.
    // Port of erts/emulator/beam/jit/x86/instr_arith.cpp:1411-1415
    // (emit_i_bxor_body_shared), OTP-29.1.1.
    pub(crate) fn emit_i_bxor_body_shared(&mut self) -> Result<(), AsmError> {
        self.emit_bitwise_fallback_body(addr(erts_bxor as *const ()), &BXOR_MFA)
    }

    /// Shared guard fragment for bnot.
    // Port of erts/emulator/beam/jit/x86/instr_arith.cpp:1476-1495
    // (emit_i_bnot_guard_shared), OTP-29.1.1.
    pub(crate) fn emit_i_bnot_guard_shared(&mut self) -> Result<(), AsmError> {
        self.asm.emit_enter_frame()?;
        self.asm.emit(|e| e.xor_ri(RET, !TAG_IMMED1_MASK))?;
        self.asm.emit_enter_runtime(Update::REDUCTIONS)?;
        self.asm.emit(|e| e.mov_rr(ARG1, C_P))?;
        self.asm.emit(|e| e.mov_rr(ARG2, RET))?;
        self.asm.runtime_call(addr(erts_bnot as *const ()))?;
        self.asm.emit_leave_runtime(Update::REDUCTIONS)?;
        self.asm.emit_leave_frame()?;
        self.asm.emit_test_the_non_value(RET)?;
        self.asm.emit(|e| e.ret())
    }

    /// Shared body fragment for bnot.
    // Port of erts/emulator/beam/jit/x86/instr_arith.cpp:1498-1532
    // (emit_i_bnot_body_shared), OTP-29.1.1.
    pub(crate) fn emit_i_bnot_body_shared(&mut self) -> Result<(), AsmError> {
        let error = self.asm.a.new_label();
        self.asm.emit_enter_frame()?;
        self.asm.emit(|e| e.xor_ri(RET, !TAG_IMMED1_MASK))?;
        self.asm.emit_enter_runtime(Update::REDUCTIONS)?;
        self.asm.emit(|e| e.mov_mr(tmp_mem_q(0), RET))?;
        self.asm.emit(|e| e.mov_rr(ARG1, C_P))?;
        self.asm.emit(|e| e.mov_rr(ARG2, RET))?;
        self.asm.runtime_call(addr(erts_bnot as *const ()))?;
        self.asm.emit_leave_runtime(Update::REDUCTIONS)?;
        self.asm.emit_leave_frame()?;
        self.asm.emit_test_the_non_value(RET)?;
        self.asm.short_jcc(CondCode::E, error)?;
        self.asm.emit(|e| e.ret())?;
        self.asm.bind(error)?;
        self.asm.emit(|e| e.mov_rm(ARG1, tmp_mem_q(0)))?;
        self.asm
            .emit(|e| e.mov_mr(crate::x86::beam_asm::get_x_ref(0, 8), ARG1))?;
        self.asm.mov_imm(ARG4, mfa_address(&BNOT_MFA))?;
        self.asm.jmp(self.label(GlobalLabels::RaiseException))
    }

    /// Shared guard/body fragment for bsr.
    // Port of erts/emulator/beam/jit/x86/instr_arith.cpp:1572-1577 (emit_i_bsr_guard_shared),
    // OTP-29.1.1.
    pub(crate) fn emit_i_bsr_guard_shared(&mut self) -> Result<(), AsmError> {
        self.emit_bitwise_fallback_guard(addr(erts_bsr as *const ()))
    }

    /// Shared body fragment for bsr.
    // Port of erts/emulator/beam/jit/x86/instr_arith.cpp:1579-1583 (emit_i_bsr_body_shared),
    // OTP-29.1.1.
    pub(crate) fn emit_i_bsr_body_shared(&mut self) -> Result<(), AsmError> {
        self.emit_bitwise_fallback_body(addr(erts_bsr as *const ()), &BSR_MFA)
    }

    /// Shared guard fragment for bsl.
    // Port of erts/emulator/beam/jit/x86/instr_arith.cpp:1663-1668 (emit_i_bsl_guard_shared),
    // OTP-29.1.1.
    pub(crate) fn emit_i_bsl_guard_shared(&mut self) -> Result<(), AsmError> {
        self.emit_bitwise_fallback_guard(addr(erts_bsl as *const ()))
    }

    /// Shared body fragment for bsl.
    // Port of erts/emulator/beam/jit/x86/instr_arith.cpp:1670-1684 (emit_i_bsl_body_shared),
    // OTP-29.1.1.
    pub(crate) fn emit_i_bsl_body_shared(&mut self) -> Result<(), AsmError> {
        self.emit_bitwise_fallback_body(addr(erts_bsl as *const ()), &BSL_MFA)
    }
}

impl BeamModuleAssembler {
    /// Emits tagged-small multiplication and addition with the erts overflow paths.
    // Port of erts/emulator/beam/jit/x86/instr_arith.cpp:1032-1215
    // (emit_i_mul_add), OTP-29.1.1.
    pub fn emit_i_mul_add(
        &mut self,
        fail: ArgVal,
        src1: ArgVal,
        src2: ArgVal,
        src3: ArgVal,
        src4: ArgVal,
        dst: ArgVal,
    ) -> Result<(), AsmError> {
        let product_small = self.is_product_small_if_args_are_small(src1, src2);
        let sum_small = self.is_sum_small_if_args_are_small(src3, src4);
        let sometimes_small = !(src2.is_literal() || src4.is_literal());
        let increment_zero = src4.is_small() && arg_small_value(src4) == 0;
        let factor = if src2.is_small() {
            arg_small_value(src2)
        } else {
            0
        };
        let left_shift = if src2.is_small() && is_power_of_two(factor) {
            factor.trailing_zeros() as i64
        } else {
            -1
        };

        if self.always_small(src1)
            && src2.is_small()
            && src4.is_small()
            && product_small
            && sum_small
        {
            let mut increment = arg_term(self, src4) as i64;
            increment = increment.wrapping_sub(factor.wrapping_mul(TAG_IMMED1_SMALL));
            let lea = match factor {
                2 | 3 | 5 | 9 => Some(Mem::base_index(
                    RET,
                    RET,
                    match factor {
                        2 => 0,
                        3 => 1,
                        5 => 2,
                        _ => 3,
                    },
                    increment as i32,
                    0,
                )),
                4 | 8 => Some(Mem {
                    base: None,
                    index: Some(RET),
                    shift: if factor == 4 { 2 } else { 3 },
                    disp: increment as i32,
                    size: 0,
                }),
                _ => None,
            };
            if fits_i32(increment)
                && let Some(lea) = lea
            {
                self.mov_arg_to_reg(RET, src1)?;
                self.asm.emit(|e| e.lea(RET, lea))?;
                self.mov_arg_from_reg(dst, RET)?;
                return Ok(());
            }
        }

        if self.always_small(src1)
            && self.always_small(src2)
            && self.always_small(src4)
            && product_small
            && sum_small
        {
            if src2.is_small() {
                self.mov_arg_to_reg(RET, src1)?;
                self.asm.emit(|e| e.and_ri(RET, !TAG_IMMED1_MASK))?;
                if is_power_of_two(factor) {
                    self.asm.emit(|e| e.shl_ri(RET, left_shift))?;
                } else {
                    self.asm.mov_imm(ARG2, factor as u64)?;
                    self.asm.emit(|e| e.imul_rr(RET, ARG2))?;
                }
            } else {
                self.mov_arg_to_reg(RET, src1)?;
                self.mov_arg_to_reg(ARG2, src2)?;
                self.asm.emit(|e| e.and_ri(RET, !TAG_IMMED1_MASK))?;
                self.asm.emit(|e| e.sar_ri(ARG2, TAG_IMMED1_SIZE))?;
                self.asm.emit(|e| e.imul_rr(RET, ARG2))?;
            }
            if increment_zero {
                self.asm.emit(|e| e.or_ri(RET, TAG_IMMED1_SMALL))?;
            } else {
                self.mov_arg_to_reg(ARG2, src4)?;
                self.asm.emit(|e| e.add_rr(RET, ARG2))?;
            }
            return self.mov_arg_from_reg(dst, RET);
        }

        let next = self.asm.new_label();
        let mixed = self.asm.new_label();
        self.mov_arg_to_reg(ARG2, src1)?;
        self.mov_arg_to_reg(ARG3, src2)?;
        if !increment_zero {
            self.mov_arg_to_reg(ARG4, src4)?;
        }
        if sometimes_small {
            if src2.is_small() {
                self.emit_are_both_small(mixed, src1, ARG2, src4, ARG4)?;
                self.asm.emit(|e| e.mov_rr(RET, ARG2))?;
                self.asm.mov_imm(ARG5, factor as u64)?;
            } else {
                if increment_zero {
                    self.emit_are_both_small(mixed, src1, ARG2, src2, ARG3)?;
                } else if self.always_small(src1) {
                    self.emit_are_both_small(mixed, src2, ARG3, src4, ARG4)?;
                } else {
                    self.asm.emit(|e| e.mov_rr(RETD, ARG2D))?;
                    self.asm.emit(|e| e.and_rr(RETD, ARG3D))?;
                    self.asm.emit(|e| e.and_rr(RETD, ARG4D))?;
                    if self.always_one_of(src1, type_id::INTEGER | type_id::ALWAYS_BOXED)
                        && self.always_one_of(src2, type_id::INTEGER | type_id::ALWAYS_BOXED)
                        && self.always_one_of(src4, type_id::INTEGER | type_id::ALWAYS_BOXED)
                    {
                        self.asm.emit_is_not_boxed(mixed, RET, Distance::Short)?;
                    } else {
                        self.asm.emit(|e| e.and_ri(RETB, TAG_IMMED1_MASK))?;
                        self.asm.emit(|e| e.cmp_ri(RETB, TAG_IMMED1_SMALL))?;
                        self.asm.short_jcc(CondCode::NE, mixed)?;
                    }
                }
                self.asm.emit(|e| e.mov_rr(RET, ARG2))?;
                self.asm.emit(|e| e.mov_rr(ARG5, ARG3))?;
                self.asm.emit(|e| e.sar_ri(ARG5, TAG_IMMED1_SIZE))?;
            }
            self.asm.emit(|e| e.and_ri(RET, !TAG_IMMED1_MASK))?;
            self.asm.emit(|e| e.imul_rr(RET, ARG5))?;
            if !product_small {
                self.asm.short_jcc(CondCode::O, mixed)?;
            }
            if increment_zero {
                self.asm.emit(|e| e.or_ri(RET, TAG_IMMED1_SMALL))?;
            } else {
                self.asm.emit(|e| e.add_rr(RET, ARG4))?;
                if !sum_small {
                    self.asm.short_jcc(CondCode::O, mixed)?;
                }
            }
            self.asm.short_jmp(next)?;
        }

        self.asm.bind(mixed)?;
        let fail_index = arg_label(fail)?;
        let guard = fail_index != 0;
        let fragment = match (guard, increment_zero) {
            (true, true) => GlobalLabels::MulGuardShared,
            (true, false) => GlobalLabels::MulAddGuardShared,
            (false, true) => GlobalLabels::MulBodyShared,
            (false, false) => GlobalLabels::MulAddBodyShared,
        };
        safe_arith_fragment_call(self, fragment)?;
        if guard {
            let fail_label = self
                .resolve_beam_label(fail_index)
                .ok_or(AsmError::Operand("arithmetic fail label"))?;
            self.asm.jcc(CondCode::E, fail_label)?;
        }
        self.asm.bind(next)?;
        self.mov_arg_from_reg(dst, RET)
    }

    /// Emits tagged-small bitwise and with the generic runtime fragment.
    // Port of erts/emulator/beam/jit/x86/instr_arith.cpp:1284-1342 (emit_i_band), OTP-29.1.1.
    pub fn emit_i_band(
        &mut self,
        lhs: ArgVal,
        rhs: ArgVal,
        fail: ArgVal,
        dst: ArgVal,
    ) -> Result<(), AsmError> {
        if self.always_small(lhs) && self.always_small(rhs) {
            self.mov_arg_to_reg(RET, lhs)?;
            let raw = arg_term(self, rhs) as i64;
            if rhs.is_small() && arg_term(self, rhs) <= i32::MAX as u64 {
                self.preserve_cache(&[RET], &[], |m| m.asm.emit(|e| e.and_ri(RETD, raw)))?;
            } else if rhs.is_small() && fits_i32(raw) {
                self.preserve_cache(&[RET], &[], |m| m.asm.emit(|e| e.and_ri(RET, raw)))?;
            } else {
                self.mov_arg_to_reg(ARG2, rhs)?;
                self.asm.emit(|e| e.and_rr(RET, ARG2))?;
            }
            return self.mov_arg_from_reg(dst, RET);
        }

        let generic = self.asm.new_label();
        let next = self.asm.new_label();
        self.mov_arg_to_reg(ARG2, lhs)?;
        self.mov_arg_to_reg(RET, rhs)?;
        if !rhs.is_literal() {
            self.emit_are_both_small(generic, lhs, ARG2, rhs, RET)?;
            self.asm.emit(|e| e.and_rr(RET, ARG2))?;
            self.asm.short_jmp(next)?;
        }
        self.asm.bind(generic)?;
        if let Some(fail_label) = beam_label(self, fail)? {
            safe_arith_fragment_call(self, GlobalLabels::IBandGuardShared)?;
            self.asm.jcc(CondCode::E, fail_label)?;
        } else {
            safe_arith_fragment_call(self, GlobalLabels::IBandBodyShared)?;
        }
        self.asm.bind(next)?;
        self.mov_arg_from_reg(dst, RET)
    }

    /// Emits tagged-small bitwise or with the generic runtime fragment.
    // Port of erts/emulator/beam/jit/x86/instr_arith.cpp:1357-1401 (emit_i_bor), OTP-29.1.1.
    pub fn emit_i_bor(
        &mut self,
        fail: ArgVal,
        lhs: ArgVal,
        rhs: ArgVal,
        dst: ArgVal,
    ) -> Result<(), AsmError> {
        if self.always_small(lhs) && self.always_small(rhs) {
            self.mov_arg_to_reg(RET, lhs)?;
            let raw = arg_term(self, rhs) as i64;
            if rhs.is_immed() && fits_i32(raw) {
                self.asm.emit(|e| e.or_ri(RET, raw))?;
            } else {
                self.mov_arg_to_reg(ARG2, rhs)?;
                self.asm.emit(|e| e.or_rr(RET, ARG2))?;
            }
            return self.mov_arg_from_reg(dst, RET);
        }

        let generic = self.asm.new_label();
        let next = self.asm.new_label();
        self.mov_arg_to_reg(ARG2, lhs)?;
        self.mov_arg_to_reg(RET, rhs)?;
        self.emit_are_both_small(generic, lhs, ARG2, rhs, RET)?;
        self.asm.emit(|e| e.or_rr(RET, ARG2))?;
        self.asm.short_jmp(next)?;
        self.asm.bind(generic)?;
        if let Some(fail_label) = beam_label(self, fail)? {
            safe_arith_fragment_call(self, GlobalLabels::IBorGuardShared)?;
            self.asm.jcc(CondCode::E, fail_label)?;
        } else {
            safe_arith_fragment_call(self, GlobalLabels::IBorBodyShared)?;
        }
        self.asm.bind(next)?;
        self.mov_arg_from_reg(dst, RET)
    }

    /// Emits tagged-small bitwise xor with the generic runtime fragment.
    // Port of erts/emulator/beam/jit/x86/instr_arith.cpp:1417-1473 (emit_i_bxor), OTP-29.1.1.
    pub fn emit_i_bxor(
        &mut self,
        fail: ArgVal,
        lhs: ArgVal,
        rhs: ArgVal,
        dst: ArgVal,
    ) -> Result<(), AsmError> {
        if self.always_small(lhs) && self.always_small(rhs) {
            self.mov_arg_to_reg(RET, lhs)?;
            let raw = arg_term(self, rhs) as i64;
            if rhs.is_immed() && fits_i32(raw) {
                self.preserve_cache(&[RET], &[], |m| {
                    m.asm.emit(|e| e.xor_ri(RET, raw & !TAG_IMMED1_SMALL))
                })?;
            } else {
                self.mov_arg_to_reg(ARG2, rhs)?;
                self.preserve_cache(&[RET], &[], |m| {
                    m.asm.emit(|e| e.xor_rr(RET, ARG2))?;
                    m.asm.emit(|e| e.or_ri(RET, TAG_IMMED1_SMALL))
                })?;
            }
            return self.mov_arg_from_reg(dst, RET);
        }

        let generic = self.asm.new_label();
        let next = self.asm.new_label();
        self.mov_arg_to_reg(ARG2, lhs)?;
        self.mov_arg_to_reg(RET, rhs)?;
        self.emit_are_both_small(generic, lhs, ARG2, rhs, RET)?;
        self.asm.emit(|e| e.xor_rr(RET, ARG2))?;
        self.asm.emit(|e| e.or_ri(RET, TAG_IMMED1_SMALL))?;
        self.asm.short_jmp(next)?;
        self.asm.bind(generic)?;
        if let Some(fail_label) = beam_label(self, fail)? {
            safe_arith_fragment_call(self, GlobalLabels::IBxorGuardShared)?;
            self.asm.jcc(CondCode::E, fail_label)?;
        } else {
            safe_arith_fragment_call(self, GlobalLabels::IBxorBodyShared)?;
        }
        self.asm.bind(next)?;
        self.mov_arg_from_reg(dst, RET)
    }

    /// Emits tagged-small bitwise not with the generic runtime fragment.
    // Port of erts/emulator/beam/jit/x86/instr_arith.cpp:1535-1570 (emit_i_bnot), OTP-29.1.1.
    pub fn emit_i_bnot(&mut self, fail: ArgVal, src: ArgVal, dst: ArgVal) -> Result<(), AsmError> {
        let next = self.asm.new_label();
        self.mov_arg_to_reg(RET, src)?;
        self.asm.emit(|e| e.xor_ri(RET, !TAG_IMMED1_MASK))?;
        if self.always_one_of(src, type_id::NUMBER) {
            self.asm.emit(|e| e.test_ri(RETB, TAG_PRIMARY_LIST))?;
            self.asm.short_jcc(CondCode::NE, next)?;
        } else {
            self.asm.emit(|e| e.mov_rr(ARG1D, RETD))?;
            self.asm.emit(|e| e.and_ri(ARG1D, TAG_IMMED1_MASK))?;
            self.asm.emit(|e| e.cmp_ri(ARG1D, TAG_IMMED1_SMALL))?;
            self.asm.short_jcc(CondCode::E, next)?;
        }
        if let Some(fail_label) = beam_label(self, fail)? {
            safe_arith_fragment_call(self, GlobalLabels::IBnotGuardShared)?;
            self.asm.jcc(CondCode::E, fail_label)?;
        } else {
            safe_arith_fragment_call(self, GlobalLabels::IBnotBodyShared)?;
        }
        self.asm.bind(next)?;
        self.mov_arg_from_reg(dst, RET)
    }

    /// Emits tagged-small arithmetic right shift with the BMI2 path and generic fallback.
    // Port of erts/emulator/beam/jit/x86/instr_arith.cpp:1585-1661 (emit_i_bsr), OTP-29.1.1.
    pub fn emit_i_bsr(
        &mut self,
        lhs: ArgVal,
        rhs: ArgVal,
        fail: ArgVal,
        dst: ArgVal,
    ) -> Result<(), AsmError> {
        let generic = self.asm.new_label();
        let next = self.asm.new_label();
        let mut need_generic = true;
        let mut need_register_load = true;
        self.mov_arg_to_reg(ARG2, lhs)?;
        if rhs.is_small() {
            let shift = arg_small_value(rhs);
            if shift >= 0 {
                if self.always_small(lhs) {
                    need_generic = false;
                } else {
                    self.emit_is_small(generic, lhs, ARG2)?;
                }
                self.asm.emit(|e| e.mov_rr(RET, ARG2))?;
                self.asm.emit(|e| e.sar_ri(RET, shift.min(63)))?;
                self.asm.emit(|e| e.or_ri(RET, TAG_IMMED1_SMALL))?;
                if need_generic {
                    self.asm.short_jmp(next)?;
                }
            }
        } else if BeamAssembler::has_cpu_feature(CpuFeature::Bmi2) {
            self.mov_arg_to_reg(RET, rhs)?;
            need_register_load = false;
            self.emit_are_both_small(generic, lhs, ARG2, rhs, RET)?;
            self.asm.emit(|e| e.mov_rr(ARG1, RET))?;
            self.asm.emit(|e| e.sar_ri(ARG1, TAG_IMMED1_SIZE))?;
            self.asm.jcc(CondCode::S, generic)?;
            self.asm.mov_imm(RET, 63)?;
            self.asm.emit(|e| e.cmp_rr(ARG1, RET))?;
            self.asm.emit(|e| e.cmovcc_rr(CondCode::A, ARG1, RET))?;
            self.asm.emit(|e| e.sarx_rrr(RET, ARG2, ARG1))?;
            self.asm.emit(|e| e.or_ri(RET, TAG_IMMED1_SMALL))?;
            self.asm.short_jmp(next)?;
        }
        self.asm.bind(generic)?;
        if need_generic {
            if need_register_load {
                self.mov_arg_to_reg(RET, rhs)?;
            }
            if let Some(fail_label) = beam_label(self, fail)? {
                safe_arith_fragment_call(self, GlobalLabels::IBsrGuardShared)?;
                self.asm.jcc(CondCode::E, fail_label)?;
            } else {
                safe_arith_fragment_call(self, GlobalLabels::IBsrBodyShared)?;
            }
        }
        self.asm.bind(next)?;
        self.mov_arg_from_reg(dst, RET)
    }

    /// Emits tagged-small left shift with the LZCNT overflow analysis and generic fallback.
    // Port of erts/emulator/beam/jit/x86/instr_arith.cpp:1686-1817 (emit_i_bsl), OTP-29.1.1.
    pub fn emit_i_bsl(
        &mut self,
        lhs: ArgVal,
        rhs: ArgVal,
        fail: ArgVal,
        dst: ArgVal,
    ) -> Result<(), AsmError> {
        if self.is_bsl_small(lhs, rhs) {
            self.mov_arg_to_reg(RET, lhs)?;
            self.asm.emit(|e| e.xor_ri(RET, TAG_IMMED1_MASK))?;
            if rhs.is_small() {
                self.asm.emit(|e| e.shl_ri(RET, arg_small_value(rhs)))?;
            } else {
                self.mov_arg_to_reg(enc::RCX, rhs)?;
                self.asm.emit(|e| e.shr_ri(enc::RCX, TAG_IMMED1_SIZE))?;
                self.asm.emit(|e| e.shl_rr(RET, enc::CL))?;
            }
            self.asm.emit(|e| e.or_ri(RET, TAG_IMMED1_SMALL))?;
            return self.mov_arg_from_reg(dst, RET);
        }

        let mut inline_shift = BeamAssembler::has_cpu_feature(CpuFeature::Lzcnt);
        let generic = self.asm.new_label();
        let next = self.asm.new_label();
        self.mov_arg_to_reg(ARG2, lhs)?;
        self.mov_arg_to_reg(RET, rhs)?;
        if lhs.is_immed() && rhs.is_immed()
            || lhs.is_literal()
            || rhs.is_literal()
            || lhs.is_immed() && !lhs.is_small()
            || rhs.is_immed()
                && (!rhs.is_small()
                    || arg_small_value(rhs) < 0
                    || arg_small_value(rhs) >= (SMALL_BITS - 1) as i64)
        {
            inline_shift = false;
        }

        if inline_shift {
            let shift_limit = if lhs.is_register() {
                self.asm.emit(|e| e.mov_rr(ARG1, ARG2))?;
                self.asm.emit(|e| e.mov_rr(ARG3, ARG2))?;
                self.asm.emit(|e| e.xor_ri(ARG3, !TAG_IMMED1_MASK))?;
                self.asm.emit(|e| e.cmovcc_rr(CondCode::NS, ARG1, ARG3))?;
                self.asm.emit(|e| e.lzcnt_rr(ARG3, ARG1))?;
                if !self.always_small(lhs) {
                    self.asm.emit(|e| e.and_ri(ARG1D, TAG_IMMED1_MASK))?;
                    self.asm.emit(|e| e.cmp_ri(ARG1D, TAG_IMMED1_SMALL))?;
                    self.asm.short_jcc(CondCode::NE, generic)?;
                }
                ARG3
            } else {
                let mut value = arg_term(self, lhs);
                if (value as i64) < 0 {
                    value ^= !(TAG_IMMED1_MASK as u64);
                }
                let leading = if value == 0 {
                    64
                } else {
                    value.leading_zeros()
                };
                if rhs.is_register() {
                    self.mov_arg_to_reg(enc::RCX, rhs)?;
                    self.asm.emit(|e| e.xor_ri(enc::RCX, TAG_IMMED1_SMALL))?;
                    self.asm.emit(|e| e.ror_ri(enc::RCX, TAG_IMMED1_SIZE))?;
                    self.asm.emit(|e| e.cmp_ri(enc::RCX, i64::from(leading)))?;
                    self.asm.short_jcc(CondCode::AE, generic)?;
                    self.asm.emit(|e| e.and_ri(ARG2, !TAG_IMMED1_MASK))?;
                    self.asm.emit(|e| e.shl_rr(ARG2, enc::CL))?;
                } else {
                    unreachable!("only register RHS reaches inline constant LHS")
                }
                self.asm
                    .emit(|e| e.lea(RET, qword_ptr(ARG2, TAG_IMMED1_SMALL as i32)))?;
                self.asm.short_jmp(next)?;
                self.asm.bind(generic)?;
                if let Some(fail_label) = beam_label(self, fail)? {
                    safe_arith_fragment_call(self, GlobalLabels::IBslGuardShared)?;
                    self.asm.jcc(CondCode::E, fail_label)?;
                } else {
                    safe_arith_fragment_call(self, GlobalLabels::IBslBodyShared)?;
                }
                self.asm.bind(next)?;
                return self.mov_arg_from_reg(dst, RET);
            };

            if rhs.is_register() {
                self.mov_arg_to_reg(enc::RCX, rhs)?;
                self.asm.emit(|e| e.xor_ri(enc::RCX, TAG_IMMED1_SMALL))?;
                self.asm.emit(|e| e.ror_ri(enc::RCX, TAG_IMMED1_SIZE))?;
                self.asm.emit(|e| e.cmp_rr(enc::RCX, shift_limit))?;
                self.asm.short_jcc(CondCode::AE, generic)?;
                self.asm.emit(|e| e.and_ri(ARG2, !TAG_IMMED1_MASK))?;
                self.asm.emit(|e| e.shl_rr(ARG2, enc::CL))?;
            } else {
                let shift_count = arg_small_value(rhs);
                self.asm.emit(|e| e.cmp_ri(shift_limit, shift_count))?;
                self.asm.short_jcc(CondCode::BE, generic)?;
                self.asm.emit(|e| e.and_ri(ARG2, !TAG_IMMED1_MASK))?;
                self.asm.emit(|e| e.shl_ri(ARG2, shift_count))?;
            }
            self.asm
                .emit(|e| e.lea(RET, qword_ptr(ARG2, TAG_IMMED1_SMALL as i32)))?;
            self.asm.short_jmp(next)?;
        }

        self.asm.bind(generic)?;
        if let Some(fail_label) = beam_label(self, fail)? {
            safe_arith_fragment_call(self, GlobalLabels::IBslGuardShared)?;
            self.asm.jcc(CondCode::E, fail_label)?;
        } else {
            safe_arith_fragment_call(self, GlobalLabels::IBslBodyShared)?;
        }
        self.asm.bind(next)?;
        self.mov_arg_from_reg(dst, RET)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use arinsal_x64::buf::Section;

    use crate::x86::beam_asm::register::{ARG2, ARG3};
    use crate::x86::jdump::{erts_dump, gnu_as};

    const MODULES: [&str; 5] = ["edlin", "erl_prim_loader", "ets", "file", "inet_parse"];

    fn internal_label(line: &str) -> bool {
        let Some(name) = line.strip_suffix(':').and_then(|s| s.strip_prefix('L')) else {
            return false;
        };
        !name.is_empty() && name.bytes().all(|byte| byte.is_ascii_digit())
    }

    fn blocks_with_internal_labels(dump: &str, op: &str) -> Vec<Vec<String>> {
        let mut blocks = Vec::new();
        let mut current: Option<Vec<String>> = None;
        for line in dump.lines() {
            if let Some(header) = line.strip_prefix("# ")
                && !header.is_empty()
                && header
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
            {
                blocks.extend(current.take());
                if header == op {
                    current = Some(Vec::new());
                }
                continue;
            }
            let Some(block) = current.as_mut() else {
                continue;
            };
            let trimmed = line.trim();
            if trimmed.is_empty() || line.starts_with('#') {
                continue;
            }
            if internal_label(trimmed) || line.starts_with([' ', '\t']) {
                block.push(trimmed.to_owned());
            } else {
                blocks.extend(current.take());
            }
        }
        blocks.extend(current);
        blocks
    }

    fn branch_target(line: &str) -> Option<&str> {
        let line = line.strip_prefix("short ").unwrap_or(line);
        let (instruction, target) = line.split_once(' ')?;
        instruction.starts_with('j').then_some(target.trim())
    }

    fn call_target(line: &str) -> Option<&str> {
        line.strip_prefix("call ").map(str::trim)
    }

    fn branch_code(line: &str) -> Option<(bool, u8, &str)> {
        let (short, line) = match line.strip_prefix("short ") {
            Some(line) => (true, line),
            None => (false, line),
        };
        let (instruction, target) = line.split_once(' ')?;
        let code = match instruction {
            "jo" => 0,
            "jno" => 1,
            "jb" | "jc" | "jnae" => 2,
            "jae" | "jnb" | "jnc" => 3,
            "je" | "jz" => 4,
            "jne" | "jnz" => 5,
            "jbe" | "jna" => 6,
            "ja" | "jnbe" => 7,
            "js" => 8,
            "jns" => 9,
            "jp" | "jpe" => 10,
            "jnp" | "jpo" => 11,
            "jl" | "jnge" => 12,
            "jge" | "jnl" => 13,
            "jle" | "jng" => 14,
            "jg" | "jnle" => 15,
            "jmp" => 0xff,
            _ => return None,
        };
        Some((short, code, target.trim()))
    }

    fn asm_lines(block: &[String]) -> Vec<String> {
        let mut lines = Vec::with_capacity(block.len());
        for line in block {
            if let Some((short, code, target)) = branch_code(line) {
                match (code, short) {
                    (0xff, true) => {
                        lines.push(".byte 0xeb".to_owned());
                        lines.push(format!(".byte {target} - . - 1"));
                    }
                    (0xff, false) => {
                        lines.push(".byte 0xe9".to_owned());
                        lines.push(format!(".long {target} - . - 4"));
                    }
                    (code, true) => {
                        lines.push(format!(".byte 0x{:02x}", 0x70 + code));
                        lines.push(format!(".byte {target} - . - 1"));
                    }
                    (code, false) => {
                        lines.push(format!(".byte 0x0f, 0x{:02x}", 0x80 + code));
                        lines.push(format!(".long {target} - . - 4"));
                    }
                }
            } else if let Some(target) = call_target(line) {
                if target.parse::<u64>().is_ok() {
                    lines.push(".byte 0x40, 0xe8, 0, 0, 0, 0".to_owned());
                } else {
                    lines.push(".byte 0xe8".to_owned());
                    lines.push(format!(".long {target} - . - 4"));
                }
            } else {
                lines.push(crate::x86::jdump::erts_to_arinsal(line));
            }
        }
        lines
    }

    fn expected_arith_bytes(
        block: &[String],
        mfa: Option<&'static ErtsCodeMfa>,
    ) -> Option<Vec<u8>> {
        let rewritten: Vec<String> = block
            .iter()
            .cloned()
            .map(|line| {
                let Some(mfa) = mfa else { return line };
                let Some((register, value)) = line
                    .strip_prefix("mov ")
                    .and_then(|operands| operands.split_once(", "))
                else {
                    return line;
                };
                if value
                    .parse::<u64>()
                    .is_ok_and(|value| value > u64::from(u32::MAX))
                {
                    format!("movabs {register}, {}", mfa_address(mfa))
                } else {
                    line
                }
            })
            .collect();
        let mut lines = asm_lines(&rewritten);
        let is_defined = |target: &str| rewritten.iter().any(|line| line == &format!("{target}:"));
        let mut external = std::collections::BTreeSet::new();
        for line in &rewritten {
            if let Some(target) = call_target(line).or_else(|| branch_target(line))
                && !is_defined(target)
            {
                external.insert(target.to_owned());
            }
        }
        lines.extend(external.into_iter().map(|target| format!("{target}:")));
        gnu_as(&lines)
    }

    fn module_block_matches(
        block: &[String],
        mfa: Option<&'static ErtsCodeMfa>,
        emit: impl FnOnce(&mut BeamModuleAssembler) -> Result<(), AsmError>,
    ) -> bool {
        module_block_matches_after(block, mfa, |_| Ok(()), emit)
    }

    fn module_block_matches_after(
        block: &[String],
        mfa: Option<&'static ErtsCodeMfa>,
        setup: impl FnOnce(&mut BeamModuleAssembler) -> Result<(), AsmError>,
        emit: impl FnOnce(&mut BeamModuleAssembler) -> Result<(), AsmError>,
    ) -> bool {
        let Some(expected) = expected_arith_bytes(block, mfa) else {
            return false;
        };
        let addresses: Vec<Option<usize>> = crate::x86::beam_asm_global::GLOBAL_LABELS
            .iter()
            .enumerate()
            .map(|(index, _)| Some(0x10000 + index * 16))
            .collect();
        let mut assembler = BeamModuleAssembler::with_fragment_addresses(4, addresses);
        if setup(&mut assembler).is_err() {
            return false;
        }
        let start = assembler.asm.a.offset();
        if emit(&mut assembler).is_err() {
            return false;
        }
        let body_len = assembler.asm.a.offset();
        for index in 1..4 {
            let Some(label) = assembler.resolve_beam_label(index) else {
                return false;
            };
            if assembler.asm.bind(label).is_err() {
                return false;
            }
        }
        for (index, _) in crate::x86::beam_asm_global::GLOBAL_LABELS
            .iter()
            .enumerate()
        {
            let address = 0x10000 + index * 16;
            let label = assembler.resolve_fragment(address);
            if assembler.asm.bind(label).is_err() {
                return false;
            }
        }
        let actual = &assembler.asm.a.bytes(Section::Code)[start..body_len];
        if actual != expected {
            eprintln!("block: {block:#?}");
            eprintln!("expected: {expected:02x?}");
            eprintln!("actual:   {actual:02x?}");
        }
        actual == expected
    }

    fn verify_helper_prefix(
        block: &[String],
        helper_start: usize,
        emit: impl FnOnce(&mut BeamModuleAssembler, Label) -> Result<(), AsmError>,
    ) -> bool {
        let Some(branch) = block.get(helper_start..).and_then(|tail| {
            tail.iter()
                .position(|line| branch_target(line).is_some())
                .map(|offset| helper_start + offset)
        }) else {
            return false;
        };
        let Some(target) = branch_target(&block[branch]) else {
            return false;
        };
        let Some(label_offset) = block.iter().position(|line| line == &format!("{target}:")) else {
            return false;
        };
        let target_block = &block[..=label_offset];
        let Some(prefix_bytes) = gnu_as(&asm_lines(&block[..helper_start])) else {
            return false;
        };
        let mut expected_lines = asm_lines(target_block);
        let mut external_labels = std::collections::BTreeSet::new();
        for line in target_block {
            let Some(target) = call_target(line).or_else(|| branch_target(line)) else {
                continue;
            };
            if !target_block
                .iter()
                .any(|line| line == &format!("{target}:"))
            {
                external_labels.insert(target);
            }
        }
        expected_lines.extend(
            external_labels
                .into_iter()
                .map(|target| format!("{target}:")),
        );
        let Some(expected) = gnu_as(&expected_lines) else {
            return false;
        };

        let mut assembler = BeamModuleAssembler::new(1);
        assembler.beam_types.push(crate::common::types::ArgType {
            union_bits: type_id::NUMBER,
            ..crate::common::types::ArgType::ANY
        });
        let fail = assembler.asm.new_label();
        if emit(&mut assembler, fail).is_err() {
            return false;
        }
        let helper_len = assembler.asm.a.offset();
        let displacement = expected[prefix_bytes.len() + helper_len - 1] as i8 as isize;
        let target_offset = helper_len as isize + displacement;
        if target_offset < helper_len as isize {
            return false;
        }
        for _ in 0..(target_offset as usize - helper_len) {
            if assembler.asm.emit(|e| e.nop()).is_err() {
                return false;
            }
        }
        if assembler.asm.bind(fail).is_err() {
            return false;
        }

        assembler.asm.a.bytes(Section::Code)[..helper_len]
            == expected[prefix_bytes.len()..prefix_bytes.len() + helper_len]
    }

    fn any_arg() -> ArgVal {
        ArgVal::X(0)
    }

    fn number_arg() -> ArgVal {
        ArgVal::typed_x(0, 1)
    }

    #[test]
    fn is_small_matches_erts_i_bsr_blocks() {
        let Some(dumps) = MODULES
            .iter()
            .map(|module| erts_dump(module))
            .collect::<Option<Vec<_>>>()
        else {
            eprintln!("skipping: `erl +JDdump true` unavailable");
            return;
        };
        let mut compared = 0;
        for dump in &dumps {
            for block in blocks_with_internal_labels(dump, "i_bsr_ssjd") {
                let Some(start) = block
                    .windows(3)
                    .position(|window| window == ["mov edi, esi", "and edi, 15", "cmp edi, 15"])
                else {
                    continue;
                };
                if !verify_helper_prefix(&block, start, |assembler, fail| {
                    assembler.emit_is_small(fail, any_arg(), ARG2)
                }) {
                    panic!("i_bsr small test differs: {block:#?}");
                }
                compared += 1;
            }
        }
        assert!(compared > 0, "no generic small-tag checks compared");
    }

    #[test]
    fn are_both_small_matches_erts_i_plus_blocks() {
        let Some(dumps) = MODULES
            .iter()
            .map(|module| erts_dump(module))
            .collect::<Option<Vec<_>>>()
        else {
            eprintln!("skipping: `erl +JDdump true` unavailable");
            return;
        };
        let mut compared = 0;
        for dump in &dumps {
            for block in blocks_with_internal_labels(dump, "i_plus_ssjd") {
                let Some(start) = block
                    .windows(3)
                    .position(|window| window == ["mov eax, esi", "and eax, edx", "test al, 1"])
                else {
                    continue;
                };
                if !verify_helper_prefix(&block, start, |assembler, fail| {
                    assembler.emit_are_both_small(fail, number_arg(), ARG2, number_arg(), ARG3)
                }) {
                    panic!("i_plus pair small test differs: {block:#?}");
                }
                compared += 1;
            }
        }
        assert!(compared > 0, "no pair small-tag checks compared");
    }

    #[test]
    fn plus_emitter_matches_erts_block() {
        let Some(dump) = erts_dump("file") else {
            eprintln!("skipping: `erl +JDdump true` unavailable");
            return;
        };
        let block = blocks_with_internal_labels(&dump, "i_plus_ssjd")
            .into_iter()
            .find(|block| {
                block.iter().any(|line| line == "mov edx, 31")
                    && block
                        .iter()
                        .any(|line| line == "lea rax, qword ptr [rsi-15]")
                    && block
                        .iter()
                        .any(|line| line.starts_with("mov qword ptr [rbx+"))
            })
            .expect("file dump contains a generic small plus block");
        let lhs = ArgVal::Y(1);
        let rhs = ArgVal::Immediate(tagged_small(1) as u64);
        let dst = ArgVal::X(2);
        assert!(module_block_matches(&block, None, |assembler| {
            let lhs = assembler.typed_arg(
                lhs,
                crate::common::types::ArgType {
                    union_bits: type_id::NUMBER,
                    ..crate::common::types::ArgType::ANY
                },
            );
            assembler.emit_i_plus(lhs, rhs, ArgVal::Label(0), dst)
        }));
    }

    #[test]
    fn minus_emitter_matches_erts_block() {
        let Some(dump) = erts_dump("file") else {
            eprintln!("skipping: `erl +JDdump true` unavailable");
            return;
        };
        let block = blocks_with_internal_labels(&dump, "i_minus_ssjd")
            .into_iter()
            .find(|block| {
                block
                    .iter()
                    .any(|line| line == "mov rsi, qword ptr [rbx+16]")
                    && block
                        .iter()
                        .any(|line| line == "mov rdx, qword ptr [rbx+32]")
                    && block
                        .iter()
                        .any(|line| line == "lea rcx, qword ptr [rdx-15]")
            })
            .expect("file dump contains a generic minus block");
        assert!(module_block_matches(&block, None, |assembler| {
            let ty = crate::common::types::ArgType {
                union_bits: type_id::NUMBER,
                ..crate::common::types::ArgType::ANY
            };
            let lhs = assembler.typed_arg(ArgVal::X(2), ty);
            let rhs = assembler.typed_arg(ArgVal::X(4), ty);
            assembler.emit_i_minus(lhs, rhs, ArgVal::Label(1), ArgVal::X(1))
        }));
    }

    #[test]
    fn unary_minus_emitter_matches_erts_block() {
        let Some(dump) = erts_dump("counters") else {
            eprintln!("skipping: `erl +JDdump true` unavailable");
            return;
        };
        let block = blocks_with_internal_labels(&dump, "i_unary_minus_sjd")
            .into_iter()
            .find(|block| {
                block
                    .iter()
                    .any(|line| line == "mov rsi, qword ptr [rbx+16]")
                    && block.iter().any(|line| line == "mov qword ptr [rbx], rax")
            })
            .expect("counters dump contains a unary minus block");
        assert!(module_block_matches(&block, None, |assembler| {
            assembler.emit_i_unary_minus(ArgVal::X(2), ArgVal::Label(0), ArgVal::X(0))
        }));
    }

    #[test]
    fn bitwise_and_emitter_matches_erts_block() {
        let Some(dump) = erts_dump("rand") else {
            eprintln!("skipping: `erl +JDdump true` unavailable");
            return;
        };
        let block = blocks_with_internal_labels(&dump, "i_band_ssjd")
            .into_iter()
            .find(|block| {
                block
                    .iter()
                    .any(|line| line == "mov rsi, qword ptr [rsp+24]")
                    && block
                        .iter()
                        .any(|line| line == "mov rax, qword ptr [rsp+16]")
                    && block.iter().any(|line| line == "cmp edi, 15")
            })
            .expect("rand dump contains a generic band block");
        assert!(module_block_matches(&block, None, |assembler| {
            assembler.emit_i_band(ArgVal::Y(3), ArgVal::Y(2), ArgVal::Label(0), ArgVal::X(2))
        }));
    }

    #[test]
    fn bitwise_or_emitter_matches_erts_block() {
        let Some(dump) = erts_dump("inet_parse") else {
            eprintln!("skipping: `erl +JDdump true` unavailable");
            return;
        };
        let block = blocks_with_internal_labels(&dump, "i_bor_jssd")
            .into_iter()
            .find(|block| {
                block
                    .iter()
                    .any(|line| line == "mov rsi, qword ptr [rbx+8]")
                    && block
                        .iter()
                        .any(|line| line == "mov rax, qword ptr [rbx+16]")
                    && block.iter().any(|line| line == "or rax, rsi")
            })
            .expect("inet_parse dump contains a generic bor block");
        assert!(module_block_matches(&block, None, |assembler| {
            let ty = crate::common::types::ArgType {
                union_bits: type_id::NUMBER,
                ..crate::common::types::ArgType::ANY
            };
            let lhs = assembler.typed_arg(ArgVal::X(1), ty);
            let rhs = assembler.typed_arg(ArgVal::X(2), ty);
            assembler.emit_i_bor(ArgVal::Label(0), lhs, rhs, ArgVal::X(0))
        }));
    }

    #[test]
    fn bitwise_xor_emitter_matches_erts_block() {
        let Some(dump) = erts_dump("rand") else {
            eprintln!("skipping: `erl +JDdump true` unavailable");
            return;
        };
        let block = blocks_with_internal_labels(&dump, "i_bxor_jssd")
            .into_iter()
            .find(|block| {
                block
                    .iter()
                    .any(|line| line == "mov rax, qword ptr [rbx+8]")
                    && block
                        .iter()
                        .any(|line| line == "mov rsi, qword ptr [rbx+24]")
                    && block
                        .iter()
                        .any(|line| line == "xor rax, rsi" || line == "xor rax, rsi")
            })
            .expect("rand dump contains a small bxor block");
        assert!(module_block_matches(&block, None, |assembler| {
            let ty = crate::common::types::ArgType {
                union_bits: type_id::INTEGER,
                min: Some(0),
                max: Some(100),
                ..crate::common::types::ArgType::ANY
            };
            let lhs = assembler.typed_arg(ArgVal::X(1), ty);
            let rhs = assembler.typed_arg(ArgVal::X(3), ty);
            assembler.emit_i_bxor(ArgVal::Label(0), lhs, rhs, ArgVal::X(1))
        }));
    }

    #[test]
    fn bitwise_not_emitter_matches_erts_block() {
        let Some(dump) = erts_dump("rand") else {
            eprintln!("skipping: `erl +JDdump true` unavailable");
            return;
        };
        let block = blocks_with_internal_labels(&dump, "i_bnot_jsd")
            .into_iter()
            .find(|block| {
                block.iter().any(|line| line == "xor rax, -16")
                    && block.iter().any(|line| line == "test al, 1")
                    && block
                        .iter()
                        .any(|line| line == "mov qword ptr [rbx+48], rax")
            })
            .expect("rand dump contains a bnot block");
        assert!(module_block_matches_after(
            &block,
            None,
            |assembler| { assembler.load_cached(RET, crate::x86::beam_asm::get_x_ref(0, 8),) },
            |assembler| {
                let src = assembler.typed_arg(
                    ArgVal::X(0),
                    crate::common::types::ArgType {
                        union_bits: type_id::NUMBER,
                        ..crate::common::types::ArgType::ANY
                    },
                );
                assembler.emit_i_bnot(ArgVal::Label(0), src, ArgVal::X(6))
            }
        ));
    }

    #[test]
    fn right_shift_emitter_matches_erts_block() {
        let Some(dump) = erts_dump("rand") else {
            eprintln!("skipping: `erl +JDdump true` unavailable");
            return;
        };
        let block = blocks_with_internal_labels(&dump, "i_bsr_ssjd")
            .into_iter()
            .find(|block| {
                block.iter().any(|line| line == "mov rsi, qword ptr [rbx]")
                    && block
                        .iter()
                        .any(|line| line == "mov rax, qword ptr [rbx+32]")
                    && block.iter().any(|line| line.starts_with("sarx "))
            })
            .expect("rand dump contains the BMI2 bsr block");
        assert!(module_block_matches(&block, None, |assembler| {
            let ty = crate::common::types::ArgType {
                union_bits: type_id::NUMBER,
                ..crate::common::types::ArgType::ANY
            };
            let lhs = assembler.typed_arg(ArgVal::X(0), ty);
            let rhs = assembler.typed_arg(ArgVal::X(4), ty);
            assembler.emit_i_bsr(lhs, rhs, ArgVal::Label(0), ArgVal::X(0))
        }));
    }

    #[test]
    fn left_shift_emitter_matches_erts_block() {
        let Some(dump) = erts_dump("rand") else {
            eprintln!("skipping: `erl +JDdump true` unavailable");
            return;
        };
        let block = blocks_with_internal_labels(&dump, "i_bsl_ssjd")
            .into_iter()
            .find(|block| {
                block.iter().any(|line| line == "mov esi, 31")
                    && block
                        .iter()
                        .any(|line| line == "mov rax, qword ptr [rbx+48]")
                    && block.iter().any(|line| line == "cmp rcx, 59")
            })
            .expect("rand dump contains a LZCNT bsl block");
        assert!(module_block_matches(&block, None, |assembler| {
            assembler.emit_i_bsl(
                ArgVal::Immediate(31),
                ArgVal::X(6),
                ArgVal::Label(0),
                ArgVal::X(6),
            )
        }));
    }

    #[test]
    fn multiply_add_emitter_matches_erts_block() {
        let Some(dump) = erts_dump("inet_parse") else {
            eprintln!("skipping: `erl +JDdump true` unavailable");
            return;
        };
        let block = blocks_with_internal_labels(&dump, "i_mul_add_jssssd")
            .into_iter()
            .find(|block| {
                block
                    .iter()
                    .any(|line| line == "mov rsi, qword ptr [rbx+8]")
                    && block.iter().any(|line| line == "mov edx, 175")
                    && block.iter().any(|line| line == "mov r8d, 10")
            })
            .expect("inet_parse dump contains a small-factor mul_add block");
        assert!(module_block_matches(&block, None, |assembler| {
            let lhs = assembler.typed_arg(
                ArgVal::X(1),
                crate::common::types::ArgType {
                    union_bits: type_id::NUMBER,
                    ..crate::common::types::ArgType::ANY
                },
            );
            assembler.emit_i_mul_add(
                ArgVal::Label(0),
                lhs,
                ArgVal::Immediate(tagged_small(10) as u64),
                ArgVal::X(0),
                ArgVal::Immediate(SMALL_ZERO as u64),
                ArgVal::X(0),
            )
        }));
    }

    #[test]
    fn div_rem_emitter_matches_erts_block() {
        let Some(dump) = erts_dump("net_kernel") else {
            eprintln!("skipping: `erl +JDdump true` unavailable");
            return;
        };
        let block = blocks_with_internal_labels(&dump, "i_div_rem_ssjdd")
            .into_iter()
            .find(|block| {
                block
                    .iter()
                    .any(|line| line == "mov rax, qword ptr [rbx+32]")
                    && block
                        .iter()
                        .any(|line| line == "mov qword ptr [rbx+48], rax")
                    && block
                        .iter()
                        .any(|line| line == "mov qword ptr [rbx+56], rdx")
            })
            .expect("net_kernel dump contains a generic div_rem block");
        assert!(module_block_matches(&block, Some(&DIV_MFA), |assembler| {
            assembler.emit_i_div_rem(
                ArgVal::X(4),
                ArgVal::X(0),
                ArgVal::Label(0),
                ArgVal::X(6),
                ArgVal::X(7),
            )
        }));
    }

    #[test]
    fn rem_div_emitter_matches_erts_block() {
        let Some(dump) = erts_dump("logger_formatter") else {
            eprintln!("skipping: `erl +JDdump true` unavailable");
            return;
        };
        let block = blocks_with_internal_labels(&dump, "i_rem_div_ssjdd")
            .into_iter()
            .find(|block| {
                block.iter().any(|line| line == "mov rax, rdi")
                    && block.iter().any(|line| line == "mov r9, 1000000")
                    && block
                        .iter()
                        .any(|line| line == "mov qword ptr [rbx+16], rdx")
                    && block.iter().any(|line| line == "mov qword ptr [rbx], rax")
            })
            .expect("logger_formatter dump contains the rem/div paired emitter");
        assert!(module_block_matches_after(
            &block,
            Some(&REM_MFA),
            |assembler| assembler.load_cached(ARG1, crate::x86::beam_asm::get_x_ref(0, 8)),
            |assembler| {
                let lhs = assembler.typed_arg(
                    ArgVal::X(0),
                    crate::common::types::ArgType {
                        union_bits: type_id::INTEGER,
                        ..crate::common::types::ArgType::ANY
                    },
                );
                assembler.emit_i_rem_div(
                    lhs,
                    ArgVal::Immediate(tagged_small(1_000_000) as u64),
                    ArgVal::Label(0),
                    ArgVal::X(2),
                    ArgVal::X(0),
                )
            }
        ));
    }

    #[test]
    fn integer_division_emitter_matches_erts_block() {
        let Some(dump) = erts_dump("queue") else {
            eprintln!("skipping: `erl +JDdump true` unavailable");
            return;
        };
        let block = blocks_with_internal_labels(&dump, "i_int_div_jssd")
            .into_iter()
            .find(|block| {
                block
                    .iter()
                    .any(|line| line == "mov rax, qword ptr [rbx+8]")
                    && block.iter().any(|line| line == "shr rax, 1")
                    && block.iter().any(|line| line == "or rax, 15")
            })
            .expect("queue dump contains an integer division by two");
        assert!(module_block_matches(&block, None, |assembler| {
            let lhs = assembler.typed_arg(
                ArgVal::X(1),
                crate::common::types::ArgType {
                    union_bits: type_id::INTEGER,
                    min: Some(0),
                    max: Some(100),
                    ..crate::common::types::ArgType::ANY
                },
            );
            assembler.emit_i_int_div(
                ArgVal::Label(0),
                lhs,
                ArgVal::Immediate(tagged_small(2) as u64),
                ArgVal::X(1),
            )
        }));
    }

    #[test]
    fn remainder_emitter_matches_erts_block() {
        let Some(dump) = erts_dump("edlin") else {
            eprintln!("skipping: `erl +JDdump true` unavailable");
            return;
        };
        let block = blocks_with_internal_labels(&dump, "i_rem_ssjd")
            .into_iter()
            .find(|block| {
                block.iter().any(|line| line == "mov edx, 31")
                    && block.iter().any(|line| line == "and rdx, rax")
                    && block.iter().any(|line| line == "mov qword ptr [rbx], rdx")
            })
            .expect("edlin dump contains an optimized remainder block");
        assert!(module_block_matches_after(
            &block,
            None,
            |assembler| assembler.load_cached(RET, crate::x86::beam_asm::get_x_ref(0, 8)),
            |assembler| {
                let lhs = assembler.typed_arg(
                    ArgVal::X(0),
                    crate::common::types::ArgType {
                        union_bits: type_id::INTEGER,
                        min: Some(0),
                        max: Some(100),
                        ..crate::common::types::ArgType::ANY
                    },
                );
                assembler.emit_i_rem(
                    lhs,
                    ArgVal::Immediate(tagged_small(2) as u64),
                    ArgVal::Label(0),
                    ArgVal::X(0),
                )
            }
        ));
    }
}
