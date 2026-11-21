//! Port of erts/emulator/beam/jit/x86/instr_guard_bifs.cpp, OTP-29.1.1.
//!
//! Guard and body BIF emitters, plus the shared fragment for `element/2`.

use arinsal_x64::buf::Label;
use arinsal_x64::enc::{self, CondCode, Gp, Mem, qword_ptr};

use super::beam_asm::{
    AsmError, BeamAssembler, CpuFeature, Distance, TAG_PRIMARY_LIST, Update, emit_boxed_val,
    get_arg_ref, get_car_ref,
};
use super::beam_asm_global::{BeamGlobalAssembler, GlobalLabels};
use super::beam_asm_module::BeamModuleAssembler;
use super::rt::addr;
pub use super::rt::eq;
use crate::common::args::ArgVal;
use crate::common::types::{BeamModuleAssemblerCommon, type_id};
use arinsal_term::{Term, atoms, raw::term_from_bits};

pub use super::rt::get_map_element;

const TAG_IMMED1_MASK: i64 = 0x0f;
const TAG_IMMED1_SMALL: i64 = 0x0f;
const TAG_IMMED1_SIZE: i64 = 4;
const TAG_PRIMARY_MASK: i64 = 0x3;
const TAG_IMMED1_PID: i64 = 0x03;
const TAG_IMMED1_PORT: i64 = 0x07;
const TAG_HEADER_MASK: i64 = 0x3f;
const TAG_HEADER_EXTERNAL_PID: i64 = 0x30;
const TAG_HEADER_EXTERNAL_PORT: i64 = 0x34;
const TAG_HEADER_EXTERNAL_REF: i64 = 0x38;
const TAG_HEADER_REF: i64 = 0x10;
const TAG_HEADER_MAP: i64 = 0x2c;
const HEADER_SUB_BITS: i64 = 0x124;
const HEADER_ARITY_OFFSET: i64 = 6;
const MAX_ARITYVAL: i64 = (1 << 24) - 1;
const SUB_BITS_START: i32 = 16;
const SUB_BITS_END: i32 = 24;

const _: () = {
    assert!((TAG_HEADER_EXTERNAL_PORT - TAG_HEADER_EXTERNAL_PID) >> 2 == 1);
    assert!((TAG_HEADER_EXTERNAL_REF - TAG_HEADER_EXTERNAL_PORT) >> 2 == 1);
    assert!(TAG_IMMED1_PORT - TAG_IMMED1_PID == 0x4);
};

fn fail_label(m: &BeamModuleAssembler, fail: ArgVal) -> Result<Option<Label>, AsmError> {
    let ArgVal::Label(index) = fail else {
        return Err(AsmError::Operand("failure label operand"));
    };
    if index == 0 {
        Ok(None)
    } else {
        m.resolve_beam_label(index)
            .map(Some)
            .ok_or(AsmError::Operand("unknown failure label"))
    }
}

fn tagged_small(value: i64) -> u64 {
    ((value as u64) << TAG_IMMED1_SIZE) | TAG_IMMED1_SMALL as u64
}

fn emit_is_not_boxed_source(
    m: &mut BeamModuleAssembler,
    fail: Label,
    source: ArgVal,
    reg: Gp,
    distance: Distance,
) -> Result<(), AsmError> {
    if m.always_one_of(source, type_id::ALWAYS_BOXED) {
        Ok(())
    } else {
        m.preserve_cache(&[], &[], |m| m.asm.emit_is_not_boxed(fail, reg, distance))
    }
}

fn arg_ref(arg: ArgVal) -> Result<Mem, AsmError> {
    get_arg_ref(arg, 8).ok_or(AsmError::Operand("BEAM register operand"))
}

impl BeamGlobalAssembler {
    /// ARG1 is the 1-based tuple position, ARG2 the tuple, and ARG3 the fail address or zero.
    // Port of erts/emulator/beam/jit/x86/instr_guard_bifs.cpp:291-344
    // (emit_bif_element_shared), OTP-29.1.1.
    pub fn emit_bif_element_shared(&mut self) -> Result<(), AsmError> {
        const TAG_IMMED1_MASK: i64 = 0x0f;
        const TAG_IMMED1_SMALL: i64 = 0x0f;
        const TAG_HEADER_MASK: i64 = 0x3f;
        const HEADER_ARITY_OFFSET: i64 = 6;

        let error = self.asm.new_label();
        self.asm.emit_enter_frame()?;
        self.asm
            .emit(|e| e.mov_rr(enc::EAX, super::beam_asm::register::ARG1.r32()))?;
        self.asm.emit(|e| e.and_ri(enc::AL, TAG_IMMED1_MASK))?;
        self.asm.emit(|e| e.cmp_ri(enc::AL, TAG_IMMED1_SMALL))?;
        self.asm.short_jcc(CondCode::NE, error)?;

        self.asm.emit(|e| {
            e.mov_rr(
                super::beam_asm::register::ARG4,
                super::beam_asm::register::ARG1,
            )
        })?;
        self.asm
            .emit(|e| e.sar_ri(super::beam_asm::register::ARG4, 4))?;
        self.asm.emit_is_boxed(
            error,
            super::beam_asm::register::ARG2,
            super::beam_asm::Distance::Short,
        )?;

        self.asm.emit(|e| {
            e.mov_rr(
                super::beam_asm::register::ARG5,
                super::beam_asm::register::ARG2,
            )
        })?;
        self.asm.emit(|e| {
            e.lea(
                super::beam_asm::register::ARG5,
                Mem::base_disp(super::beam_asm::register::ARG5, -2, 8),
            )
        })?;
        self.asm.emit(|e| {
            e.mov_rm(
                super::beam_asm::register::ARG6,
                enc::qword_ptr(super::beam_asm::register::ARG5, 0),
            )
        })?;
        self.asm
            .emit(|e| e.mov_rr(enc::EAX, super::beam_asm::register::ARG6.r32()))?;
        self.asm.emit(|e| e.and_ri(enc::AL, TAG_HEADER_MASK))?;
        self.asm.short_jcc(CondCode::NE, error)?;
        self.asm
            .emit(|e| e.shr_ri(super::beam_asm::register::ARG6, HEADER_ARITY_OFFSET))?;
        self.asm
            .emit(|e| e.dec_r(super::beam_asm::register::ARG4))?;
        self.asm.emit(|e| {
            e.cmp_rr(
                super::beam_asm::register::ARG6,
                super::beam_asm::register::ARG4,
            )
        })?;
        self.asm.short_jcc(CondCode::BE, error)?;
        self.asm
            .emit(|e| e.inc_r(super::beam_asm::register::ARG4))?;
        self.asm.emit(|e| {
            e.mov_rm(
                super::beam_asm::register::RET,
                Mem::base_index(
                    super::beam_asm::register::ARG5,
                    super::beam_asm::register::ARG4,
                    3,
                    0,
                    8,
                ),
            )
        })?;
        self.asm.emit_leave_frame()?;
        self.asm.emit(|e| e.ret())?;

        self.asm.bind(error)?;
        self.asm.emit_leave_frame()?;
        self.asm.emit(|e| {
            e.test_rr(
                super::beam_asm::register::ARG3,
                super::beam_asm::register::ARG3,
            )
        })?;
        self.asm
            .jcc(CondCode::E, self.label(GlobalLabels::HandleElementError))?;
        self.asm.emit(|e| e.add_ri(enc::RSP, 8))?;
        self.asm
            .emit(|e| e.jmp_r(super::beam_asm::register::ARG3))?;
        Ok(())
    }
}

impl BeamModuleAssembler {
    /// Emits `=:=/2` or `=/=/2`, using raw tagged equality before `eq/2` for compounds.
    // Port of erts/emulator/beam/jit/x86/instr_guard_bifs.cpp:47-86
    // (emit_bif_is_eq_ne_exact), OTP-29.1.1.
    pub fn emit_bif_is_eq_ne_exact(
        &mut self,
        lhs: ArgVal,
        rhs: ArgVal,
        dst: ArgVal,
        fail_value: u64,
        succ_value: u64,
    ) -> Result<(), AsmError> {
        debug_assert_ne!(fail_value, 0);
        debug_assert_ne!(succ_value, 0);
        self.cmp_arg_mem(arg_ref(lhs)?, rhs, super::beam_asm::register::ARG1)?;
        self.asm
            .mov_imm(super::beam_asm::register::RET, succ_value)?;

        if self.always_immediate(lhs) || self.always_immediate(rhs) {
            self.asm
                .mov_imm(super::beam_asm::register::ARG1, fail_value)?;
            self.asm.emit(|e| {
                e.cmovcc_rr(
                    CondCode::NE,
                    super::beam_asm::register::RET,
                    super::beam_asm::register::ARG1,
                )
            })?;
        } else {
            let next = self.asm.new_label();
            self.asm.jcc(CondCode::E, next)?;
            self.mov_arg_to_reg(super::beam_asm::register::ARG1, lhs)?;
            self.mov_arg_to_reg(super::beam_asm::register::ARG2, rhs)?;
            self.asm.emit_enter_runtime(Update::NONE)?;
            self.asm.runtime_call(addr(eq as *const ()))?;
            self.asm.emit_leave_runtime(Update::NONE)?;
            self.asm.emit(|e| {
                e.test_rr(
                    super::beam_asm::register::RET,
                    super::beam_asm::register::RET,
                )
            })?;
            self.asm
                .mov_imm(super::beam_asm::register::RET, succ_value)?;
            self.asm
                .mov_imm(super::beam_asm::register::ARG1, fail_value)?;
            self.asm.emit(|e| {
                e.cmovcc_rr(
                    CondCode::E,
                    super::beam_asm::register::RET,
                    super::beam_asm::register::ARG1,
                )
            })?;
            self.asm.bind(next)?;
        }
        self.mov_arg_from_reg(dst, super::beam_asm::register::RET)
    }

    /// Emits the `is_eq_exact/2` atom result.
    // Port of erts/emulator/beam/jit/x86/instr_guard_bifs.cpp:88-92
    // (emit_bif_is_eq_exact), OTP-29.1.1.
    pub fn emit_bif_is_eq_exact(
        &mut self,
        lhs: ArgVal,
        rhs: ArgVal,
        dst: ArgVal,
    ) -> Result<(), AsmError> {
        self.emit_bif_is_eq_ne_exact(
            lhs,
            rhs,
            dst,
            Term::atom(atoms::FALSE).word(),
            Term::atom(atoms::TRUE).word(),
        )
    }

    /// Emits the `is_ne_exact/2` atom result.
    // Port of erts/emulator/beam/jit/x86/instr_guard_bifs.cpp:94-98
    // (emit_bif_is_ne_exact), OTP-29.1.1.
    pub fn emit_bif_is_ne_exact(
        &mut self,
        lhs: ArgVal,
        rhs: ArgVal,
        dst: ArgVal,
    ) -> Result<(), AsmError> {
        self.emit_bif_is_eq_ne_exact(
            lhs,
            rhs,
            dst,
            Term::atom(atoms::TRUE).word(),
            Term::atom(atoms::FALSE).word(),
        )
    }
}

impl BeamModuleAssembler {
    fn emit_cond_to_bool(&mut self, condition: CondCode, dst: ArgVal) -> Result<(), AsmError> {
        use super::beam_asm::register::{ARG1, RET};
        self.asm.mov_imm(RET, Term::atom(atoms::TRUE).word())?;
        self.asm.mov_imm(ARG1, Term::atom(atoms::FALSE).word())?;
        self.asm.emit(|e| e.cmovcc_rr(condition, RET, ARG1))?;
        self.mov_arg_from_reg(dst, RET)
    }

    fn emit_bif_is_ge_lt(
        &mut self,
        condition: CondCode,
        lhs: ArgVal,
        rhs: ArgVal,
        dst: ArgVal,
    ) -> Result<(), AsmError> {
        use super::beam_asm::register::{ARG1, ARG2, RET, RETB, RETD};
        let generic = self.asm.new_label();
        let make_boolean = self.asm.new_label();
        self.mov_arg_to_reg(ARG2, rhs)?;
        self.mov_arg_to_reg(ARG1, lhs)?;

        if self.always_one_of(lhs, type_id::INTEGER | type_id::ALWAYS_BOXED)
            && self.always_one_of(rhs, type_id::INTEGER | type_id::ALWAYS_BOXED)
        {
            if self.always_small(lhs) {
                emit_is_not_boxed_source(self, generic, rhs, ARG2, Distance::Short)?;
            } else if self.always_small(rhs) {
                emit_is_not_boxed_source(self, generic, lhs, ARG1, Distance::Short)?;
            } else {
                self.asm.emit(|e| e.mov_rr(RETD, ARG1.r32()))?;
                self.asm.emit(|e| e.and_rr(RETD, ARG2.r32()))?;
                self.asm.emit_is_not_boxed(generic, RET, Distance::Short)?;
            }
        } else {
            if self.always_small(rhs) {
                self.asm.emit(|e| e.mov_rr(RETD, ARG1.r32()))?;
            } else if self.always_small(lhs) {
                self.asm.emit(|e| e.mov_rr(RETD, ARG2.r32()))?;
            } else {
                self.asm.emit(|e| e.mov_rr(RETD, ARG1.r32()))?;
                self.asm.emit(|e| e.and_rr(RETD, ARG2.r32()))?;
            }
            self.asm.emit(|e| e.and_ri(RETB, TAG_IMMED1_MASK))?;
            self.asm.emit(|e| e.cmp_ri(RETB, TAG_IMMED1_SMALL))?;
            self.asm.short_jcc(CondCode::NE, generic)?;
        }

        self.asm.emit(|e| e.cmp_rr(ARG1, ARG2))?;
        self.asm.short_jmp(make_boolean)?;
        self.asm.bind(generic)?;
        self.asm.emit(|e| e.cmp_rr(ARG1, ARG2))?;
        self.asm.short_jcc(CondCode::E, make_boolean)?;
        let fragment = self.ga_get(GlobalLabels::ArithCompareShared)?;
        self.safe_fragment_call(fragment)?;
        self.asm.bind(make_boolean)?;
        self.emit_cond_to_bool(condition, dst)
    }

    /// Emits the guard comparison `is_ge/2`.
    // Port of erts/emulator/beam/jit/x86/instr_guard_bifs.cpp:164-186 (emit_bif_is_ge),
    // OTP-29.1.1.
    pub fn emit_bif_is_ge(
        &mut self,
        lhs: ArgVal,
        rhs: ArgVal,
        dst: ArgVal,
    ) -> Result<(), AsmError> {
        let both_small = self.always_small(lhs) && self.always_small(rhs);
        if both_small {
            if let (Some(lhs_ref), ArgVal::Immediate(value)) = (get_arg_ref(lhs, 8), rhs)
                && (value as i64 as i32) as i64 == value as i64
            {
                self.asm.emit(|e| e.cmp_mi(lhs_ref, value as i64))?;
                return self.emit_cond_to_bool(CondCode::L, dst);
            }
            if let (Some(rhs_ref), ArgVal::Immediate(value)) = (get_arg_ref(rhs, 8), lhs)
                && (value as i64 as i32) as i64 == value as i64
            {
                self.asm.emit(|e| e.cmp_mi(rhs_ref, value as i64))?;
                return self.emit_cond_to_bool(CondCode::G, dst);
            }
        }
        self.emit_bif_is_ge_lt(CondCode::L, lhs, rhs, dst)
    }

    /// Emits the guard comparison `is_lt/2`.
    // Port of erts/emulator/beam/jit/x86/instr_guard_bifs.cpp:188-196 (emit_bif_is_lt),
    // OTP-29.1.1.
    pub fn emit_bif_is_lt(
        &mut self,
        lhs: ArgVal,
        rhs: ArgVal,
        dst: ArgVal,
    ) -> Result<(), AsmError> {
        self.emit_bif_is_ge_lt(CondCode::GE, lhs, rhs, dst)
    }

    /// Emits `bit_size/1`, inlining the exact-bitstring case.
    // Port of erts/emulator/beam/jit/x86/instr_guard_bifs.cpp:199-234 (emit_bif_bit_size),
    // OTP-29.1.1.
    pub fn emit_bif_bit_size(
        &mut self,
        bif: ArgVal,
        fail: ArgVal,
        src: ArgVal,
        dst: ArgVal,
    ) -> Result<(), AsmError> {
        use super::beam_asm::register::{ARG1, ARG2};
        if !self.exact_type(src, type_id::BITSTRING) {
            return self.emit_i_bif1(src, fail, bif, dst);
        }
        self.mov_arg_to_reg(ARG2, src)?;
        let boxed = self.asm.emit_ptr_val(ARG2, ARG2);
        self.asm
            .emit(|e| e.mov_rm(ARG1, emit_boxed_val(boxed, 8, 8)))?;
        let not_sub_bits = self.asm.new_label();
        self.asm
            .emit(|e| e.cmp_mi(emit_boxed_val(boxed, 0, 8), HEADER_SUB_BITS))?;
        self.asm.short_jcc(CondCode::NE, not_sub_bits)?;
        self.asm
            .emit(|e| e.mov_rm(ARG1, emit_boxed_val(boxed, SUB_BITS_END, 8)))?;
        self.asm
            .emit(|e| e.sub_rm(ARG1, emit_boxed_val(boxed, SUB_BITS_START, 8)))?;
        self.asm.bind(not_sub_bits)?;
        self.asm.emit(|e| e.shl_ri(ARG1, TAG_IMMED1_SIZE))?;
        self.asm.emit(|e| e.or_ri(ARG1, TAG_IMMED1_SMALL))?;
        self.mov_arg_from_reg(dst, ARG1)
    }

    /// Emits `byte_size/1`, inlining the exact-bitstring case.
    // Port of erts/emulator/beam/jit/x86/instr_guard_bifs.cpp:236-272 (emit_bif_byte_size),
    // OTP-29.1.1.
    pub fn emit_bif_byte_size(
        &mut self,
        bif: ArgVal,
        fail: ArgVal,
        src: ArgVal,
        dst: ArgVal,
    ) -> Result<(), AsmError> {
        use super::beam_asm::register::{ARG1, ARG2};
        if !self.exact_type(src, type_id::BITSTRING) {
            return self.emit_i_bif1(src, fail, bif, dst);
        }
        self.mov_arg_to_reg(ARG2, src)?;
        let boxed = self.asm.emit_ptr_val(ARG2, ARG2);
        self.asm
            .emit(|e| e.mov_rm(ARG1, emit_boxed_val(boxed, 8, 8)))?;
        let not_sub_bits = self.asm.new_label();
        self.asm
            .emit(|e| e.cmp_mi(emit_boxed_val(boxed, 0, 8), HEADER_SUB_BITS))?;
        self.asm.short_jcc(CondCode::NE, not_sub_bits)?;
        self.asm
            .emit(|e| e.mov_rm(ARG1, emit_boxed_val(boxed, SUB_BITS_END, 8)))?;
        self.asm
            .emit(|e| e.sub_rm(ARG1, emit_boxed_val(boxed, SUB_BITS_START, 8)))?;
        self.asm.bind(not_sub_bits)?;
        self.asm.emit(|e| e.add_ri(ARG1, 7))?;
        self.asm.emit(|e| e.shl_ri(ARG1, TAG_IMMED1_SIZE - 3))?;
        self.asm.emit(|e| e.or_ri(ARG1, TAG_IMMED1_SMALL))?;
        self.mov_arg_from_reg(dst, ARG1)
    }

    /// Emits `element/2`, using the source tuple and position facts to choose its inline form.
    // Port of erts/emulator/beam/jit/x86/instr_guard_bifs.cpp:346-510 (emit_bif_element),
    // OTP-29.1.1.
    pub fn emit_bif_element(
        &mut self,
        fail: ArgVal,
        pos: ArgVal,
        tuple: ArgVal,
        dst: ArgVal,
    ) -> Result<(), AsmError> {
        use super::beam_asm::register::{ARG1, ARG2, ARG3, ARG4, ARG5, RET};
        let fail = fail_label(self, fail)?;
        let position = pos.small_signed();
        let const_position = position.is_some_and(|n| n > 0 && n <= MAX_ARITYVAL);

        if self.exact_type(pos, type_id::INTEGER)
            && let ArgVal::Literal(index) = tuple
            && let Ok(literal_tuple) =
                arinsal_term::raw::Tuple::try_from(term_from_bits(self.beamfile_get_literal(index)))
        {
            let size = literal_tuple.arity() as i64;
            let (min, max) = self.get_clamped_range(pos);
            let can_fail = min < 1 || size < max;
            let error = self.asm.new_label();
            let next = self.asm.new_label();
            self.mov_arg_to_reg(ARG2, tuple)?;
            self.mov_arg_to_reg(ARG1, pos)?;
            let boxed = self.asm.emit_ptr_val(ARG3, ARG2);
            self.asm
                .emit(|e| e.lea(ARG4, emit_boxed_val(boxed, 0, 8)))?;
            if !self.always_small(pos) {
                self.asm
                    .emit(|e| e.test_ri(ARG1.r8(), i64::from(TAG_PRIMARY_LIST)))?;
                self.asm.short_jcc(CondCode::E, error)?;
            }
            self.asm.emit(|e| e.mov_rr(RET, ARG1))?;
            self.asm.emit(|e| e.sar_ri(RET, TAG_IMMED1_SIZE))?;
            if !(1 <= min && max <= size) {
                self.asm.emit(|e| e.lea(ARG3, qword_ptr(RET, -1)))?;
                self.cmp(ARG3, size, ARG5)?;
                self.asm.short_jcc(CondCode::AE, error)?;
            }
            self.asm
                .emit(|e| e.mov_rm(RET, Mem::base_index(ARG4, RET, 3, 0, 8)))?;
            if can_fail {
                self.asm.short_jmp(next)?;
            }
            self.asm.bind(error)?;
            if can_fail {
                if let Some(fail) = fail {
                    self.asm.jmp(fail)?;
                } else {
                    let fragment = self.ga_get(GlobalLabels::HandleElementError)?;
                    self.safe_fragment_call(fragment)?;
                }
            }
            self.asm.bind(next)?;
            return self.mov_arg_from_reg(dst, RET);
        }

        if const_position {
            let position = position.expect("constant position");
            self.mov_arg_to_reg(ARG2, tuple)?;
            let boxed = self.asm.emit_ptr_val(ARG3, ARG2);
            if self.exact_type(tuple, type_id::TUPLE) {
                self.asm.emit(|e| {
                    e.cmp_mi(
                        emit_boxed_val(boxed, 0, 4),
                        ((position as u64) << HEADER_ARITY_OFFSET) as i64,
                    )
                })?;
                if let Some(fail) = fail {
                    self.asm.jcc(CondCode::B, fail)?;
                } else {
                    let next = self.asm.new_label();
                    self.asm.short_jcc(CondCode::AE, next)?;
                    self.asm.mov_imm(ARG1, tagged_small(position))?;
                    let fragment = self.ga_get(GlobalLabels::HandleElementError)?;
                    self.safe_fragment_call(fragment)?;
                    self.asm.bind(next)?;
                }
            } else {
                let error = fail.unwrap_or_else(|| self.asm.new_label());
                let distance = if fail.is_some() {
                    Distance::Long
                } else {
                    Distance::Short
                };
                self.emit_is_boxed_source(error, tuple, ARG2, distance)?;
                self.asm.emit(|e| {
                    e.mov_rm(super::beam_asm::register::RETD, emit_boxed_val(boxed, 0, 4))
                })?;
                self.asm.emit(|e| {
                    e.cmp_ri(
                        super::beam_asm::register::RETD,
                        ((position as u64) << HEADER_ARITY_OFFSET) as i64,
                    )
                })?;
                self.asm.jcc_dist(CondCode::B, error, distance)?;
                self.asm
                    .emit(|e| e.and_ri(super::beam_asm::register::RETB, TAG_HEADER_MASK))?;
                if fail.is_none() {
                    let next = self.asm.new_label();
                    self.asm.short_jcc(CondCode::E, next)?;
                    self.asm.bind(error)?;
                    self.asm.mov_imm(ARG1, tagged_small(position))?;
                    let fragment = self.ga_get(GlobalLabels::HandleElementError)?;
                    self.safe_fragment_call(fragment)?;
                    self.asm.bind(next)?;
                } else {
                    self.asm.jcc(CondCode::NE, error)?;
                }
            }
            self.asm
                .emit(|e| e.mov_rm(RET, emit_boxed_val(boxed, (position * 8) as i32, 8)))?;
        } else {
            self.mov_arg_to_reg(ARG2, tuple)?;
            self.mov_arg_to_reg(ARG1, pos)?;
            if let Some(fail) = fail {
                self.asm
                    .a
                    .emit_rip_label(fail, |e| e.lea(ARG3, Mem::rip(0, 8)))?;
            } else {
                self.asm.mov_imm(ARG3, 0)?;
            }
            let fragment = self.ga_get(GlobalLabels::BifElementShared)?;
            self.safe_fragment_call(fragment)?;
        }
        self.mov_arg_from_reg(dst, RET)
    }

    /// Emits `hd/1` with a cons-cell fast path.
    // Port of erts/emulator/beam/jit/x86/instr_guard_bifs.cpp:531-551 (emit_bif_hd),
    // OTP-29.1.1.
    pub fn emit_bif_hd(&mut self, src: ArgVal, dst: ArgVal) -> Result<(), AsmError> {
        use super::beam_asm::register::{ARG2, RET, RETB};
        let good_cons = self.asm.new_label();
        self.mov_arg_to_reg(RET, src)?;
        self.asm
            .emit(|e| e.test_ri(RETB, TAG_PRIMARY_MASK - i64::from(TAG_PRIMARY_LIST)))?;
        self.asm.short_jcc(CondCode::E, good_cons)?;
        let fragment = self.ga_get(GlobalLabels::HandleHdError)?;
        self.safe_fragment_call(fragment)?;
        self.asm.bind(good_cons)?;
        let list = self.asm.emit_ptr_val(RET, RET);
        self.asm.emit(|e| e.mov_rm(ARG2, get_car_ref(list, 8)))?;
        self.mov_arg_from_reg(dst, ARG2)
    }

    /// Emits `is_map_key/2`, specializing a known map argument.
    // Port of erts/emulator/beam/jit/x86/instr_guard_bifs.cpp:554-586
    // (emit_bif_is_map_key), OTP-29.1.1.
    pub fn emit_bif_is_map_key(
        &mut self,
        bif: ArgVal,
        fail: ArgVal,
        key: ArgVal,
        src: ArgVal,
        dst: ArgVal,
    ) -> Result<(), AsmError> {
        use super::beam_asm::register::{ARG1, ARG2, RET};
        if !self.exact_type(src, type_id::MAP) {
            return self.emit_i_bif2(key, src, fail, bif, dst);
        }
        self.mov_arg_to_reg(ARG1, src)?;
        self.mov_arg_to_reg(ARG2, key)?;
        if self.maybe_one_of(key, type_id::MAYBE_IMMEDIATE)
            && BeamAssembler::has_cpu_feature(CpuFeature::Bmi2)
        {
            let fragment = self.ga_get(GlobalLabels::IGetMapElementShared)?;
            self.safe_fragment_call(fragment)?;
            self.emit_cond_to_bool(CondCode::NE, dst)
        } else {
            self.asm.emit_enter_runtime(Update::NONE)?;
            self.asm.runtime_call(addr(get_map_element as *const ()))?;
            self.asm.emit_leave_runtime(Update::NONE)?;
            self.asm.emit_test_the_non_value(RET)?;
            self.emit_cond_to_bool(CondCode::E, dst)
        }
    }

    /// Emits `map_get/2`, including the body and guard error paths.
    // Port of erts/emulator/beam/jit/x86/instr_guard_bifs.cpp:608-681 (emit_bif_map_get),
    // OTP-29.1.1.
    pub fn emit_bif_map_get(
        &mut self,
        fail: ArgVal,
        key: ArgVal,
        src: ArgVal,
        dst: ArgVal,
    ) -> Result<(), AsmError> {
        use super::beam_asm::register::{ARG1, ARG2, RET, RETB};
        let fail = fail_label(self, fail)?;
        let good_key = self.asm.new_label();
        self.mov_arg_to_reg(ARG1, src)?;
        self.mov_arg_to_reg(ARG2, key)?;

        if !self.exact_type(src, type_id::MAP) {
            let bad_map = self.asm.new_label();
            let good_map = self.asm.new_label();
            let bad_map_target = fail.unwrap_or(bad_map);
            self.emit_is_boxed_source(bad_map_target, src, ARG1, Distance::Long)?;
            if self.masked_types(src, type_id::MAYBE_BOXED) == type_id::MAP {
                if fail.is_none() {
                    self.asm.short_jmp(good_map)?;
                }
            } else {
                let boxed = self.asm.emit_ptr_val(RET, ARG1);
                self.asm
                    .emit(|e| e.mov_rm(RET, emit_boxed_val(boxed, 0, 8)))?;
                self.asm.emit(|e| e.and_ri(RETB, TAG_HEADER_MASK))?;
                self.asm.emit(|e| e.cmp_ri(RETB, TAG_HEADER_MAP))?;
                if let Some(fail) = fail {
                    self.asm.jcc(CondCode::NE, fail)?;
                } else {
                    self.asm.short_jcc(CondCode::E, good_map)?;
                }
            }
            self.asm.bind(bad_map)?;
            if fail.is_none() {
                let fragment = self.ga_get(GlobalLabels::HandleMapGetBadmap)?;
                let target = self.resolve_fragment(fragment);
                self.asm.fragment_call(target)?;
            }
            self.asm.bind(good_map)?;
        }

        if self.maybe_one_of(key, type_id::MAYBE_IMMEDIATE)
            && BeamAssembler::has_cpu_feature(CpuFeature::Bmi2)
        {
            let fragment = self.ga_get(GlobalLabels::IGetMapElementShared)?;
            self.safe_fragment_call(fragment)?;
            if let Some(fail) = fail {
                self.asm.jcc(CondCode::NE, fail)?;
            } else {
                self.asm.jcc(CondCode::E, good_key)?;
            }
        } else {
            self.asm.emit_enter_runtime(Update::NONE)?;
            self.asm.runtime_call(addr(get_map_element as *const ()))?;
            self.asm.emit_leave_runtime(Update::NONE)?;
            self.asm.emit_test_the_non_value(RET)?;
            if let Some(fail) = fail {
                self.asm.jcc(CondCode::E, fail)?;
            } else {
                self.asm.short_jcc(CondCode::NE, good_key)?;
            }
        }
        if fail.is_none() {
            self.mov_arg_to_reg(ARG1, src)?;
            self.mov_arg_to_reg(ARG2, key)?;
            let fragment = self.ga_get(GlobalLabels::HandleMapGetBadkey)?;
            let target = self.resolve_fragment(fragment);
            self.asm.fragment_call(target)?;
        }
        self.asm.bind(good_key)?;
        self.mov_arg_from_reg(dst, RET)
    }

    /// Emits `map_size/1`, inlining the exact-map case.
    // Port of erts/emulator/beam/jit/x86/instr_guard_bifs.cpp:703-754 (emit_bif_map_size),
    // OTP-29.1.1.
    pub fn emit_bif_map_size(
        &mut self,
        fail: ArgVal,
        src: ArgVal,
        dst: ArgVal,
    ) -> Result<(), AsmError> {
        use super::beam_asm::register::{RET, RETB, RETD};
        let fail = fail_label(self, fail)?;
        let error = self.asm.new_label();
        let good_map = self.asm.new_label();
        self.mov_arg_to_reg(RET, src)?;
        if let Some(fail) = fail {
            self.emit_is_boxed_source(fail, src, RET, Distance::Long)?;
        } else {
            self.emit_is_boxed_source(error, src, RET, Distance::Long)?;
        }
        let boxed = self.asm.emit_ptr_val(enc::RDX, RET);
        if self.exact_type(src, type_id::MAP) {
            self.asm.bind(error)?;
        } else {
            self.asm
                .emit(|e| e.mov_rm(RETD, emit_boxed_val(boxed, 0, 4)))?;
            self.asm.emit(|e| e.and_ri(RETB, TAG_HEADER_MASK))?;
            self.asm.emit(|e| e.cmp_ri(RETB, TAG_HEADER_MAP))?;
            if let Some(fail) = fail {
                self.asm.jcc(CondCode::NE, fail)?;
                self.asm.bind(error)?;
            } else {
                self.asm.short_jcc(CondCode::E, good_map)?;
                self.asm.bind(error)?;
                let fragment = self.ga_get(GlobalLabels::HandleMapSizeError)?;
                self.safe_fragment_call(fragment)?;
            }
        }
        self.asm.bind(good_map)?;
        self.preserve_cache(&[RET], &[], |m| {
            m.asm.emit(|e| e.mov_rm(RET, emit_boxed_val(boxed, 8, 8)))?;
            m.asm.emit(|e| e.shl_ri(RET, TAG_IMMED1_SIZE))?;
            m.asm.emit(|e| e.or_ri(RETB, TAG_IMMED1_SMALL))
        })?;
        self.mov_arg_from_reg(dst, RET)
    }

    fn emit_bif_min_max(
        &mut self,
        condition: CondCode,
        lhs: ArgVal,
        rhs: ArgVal,
        dst: ArgVal,
    ) -> Result<(), AsmError> {
        use super::beam_asm::register::{ARG1, ARG2, RET, RETB, RETD};
        let generic = self.asm.new_label();
        let do_cmov = self.asm.new_label();
        let both_small = self.always_small(lhs) && self.always_small(rhs);
        let need_generic = !both_small;
        self.mov_arg_to_reg(ARG2, rhs)?;
        self.mov_arg_to_reg(ARG1, lhs)?;

        if both_small {
        } else if self.always_one_of(lhs, type_id::INTEGER | type_id::ALWAYS_BOXED)
            && self.always_small(rhs)
        {
            emit_is_not_boxed_source(self, generic, lhs, ARG1, Distance::Short)?;
        } else if self.always_small(lhs)
            && self.always_one_of(rhs, type_id::INTEGER | type_id::ALWAYS_BOXED)
        {
            emit_is_not_boxed_source(self, generic, rhs, ARG2, Distance::Short)?;
        } else if self.always_one_of(lhs, type_id::INTEGER | type_id::ALWAYS_BOXED)
            && self.always_one_of(rhs, type_id::INTEGER | type_id::ALWAYS_BOXED)
        {
            self.asm.emit(|e| e.mov_rr(RETD, ARG1.r32()))?;
            self.asm.emit(|e| e.and_rr(RETD, ARG2.r32()))?;
            self.asm.emit_is_not_boxed(generic, RET, Distance::Short)?;
        } else {
            if rhs.is_small() {
                self.asm.emit(|e| e.mov_rr(RETD, ARG1.r32()))?;
            } else if lhs.is_small() {
                self.asm.emit(|e| e.mov_rr(RETD, ARG2.r32()))?;
            } else {
                self.asm.emit(|e| e.mov_rr(RETD, ARG1.r32()))?;
                self.asm.emit(|e| e.and_rr(RETD, ARG2.r32()))?;
            }
            self.asm.emit(|e| e.and_ri(RETB, TAG_IMMED1_MASK))?;
            self.asm.emit(|e| e.cmp_ri(RETB, TAG_IMMED1_SMALL))?;
            self.asm.short_jcc(CondCode::NE, generic)?;
        }

        self.asm.emit(|e| e.cmp_rr(ARG1, ARG2))?;
        if need_generic {
            self.asm.short_jmp(do_cmov)?;
        }
        self.asm.bind(generic)?;
        if need_generic {
            self.asm.emit(|e| e.cmp_rr(ARG1, ARG2))?;
            self.asm.short_jcc(CondCode::E, do_cmov)?;
            self.asm.emit(|e| e.push_r(ARG1))?;
            self.asm.emit(|e| e.push_r(ARG2))?;
            let fragment = self.ga_get(GlobalLabels::ArithCompareShared)?;
            self.safe_fragment_call(fragment)?;
            self.asm.emit(|e| e.pop_r(ARG2))?;
            self.asm.emit(|e| e.pop_r(ARG1))?;
        }
        self.asm.bind(do_cmov)?;
        self.asm.emit(|e| e.cmovcc_rr(condition, ARG1, ARG2))?;
        self.mov_arg_from_reg(dst, ARG1)
    }

    /// Emits `max/2`.
    // Port of erts/emulator/beam/jit/x86/instr_guard_bifs.cpp:825-829 (emit_bif_max),
    // OTP-29.1.1.
    pub fn emit_bif_max(&mut self, lhs: ArgVal, rhs: ArgVal, dst: ArgVal) -> Result<(), AsmError> {
        self.emit_bif_min_max(CondCode::L, lhs, rhs, dst)
    }

    /// Emits `min/2`.
    // Port of erts/emulator/beam/jit/x86/instr_guard_bifs.cpp:831-839 (emit_bif_min),
    // OTP-29.1.1.
    pub fn emit_bif_min(&mut self, lhs: ArgVal, rhs: ArgVal, dst: ArgVal) -> Result<(), AsmError> {
        self.emit_bif_min_max(CondCode::G, lhs, rhs, dst)
    }

    /// Emits `node/1` for internal and external identifiers.
    // Port of erts/emulator/beam/jit/x86/instr_guard_bifs.cpp:851-934 (emit_bif_node),
    // OTP-29.1.1.
    pub fn emit_bif_node(
        &mut self,
        fail: ArgVal,
        src: ArgVal,
        dst: ArgVal,
    ) -> Result<(), AsmError> {
        use super::beam_asm::register::{ARG1, ARG2, RETB, RETD};
        let fail = fail_label(self, fail)?;
        let identifier = type_id::PID | type_id::PORT | type_id::REFERENCE;
        let always_identifier = self.always_one_of(src, identifier);
        let test_internal = self.asm.new_label();
        let internal = self.asm.new_label();
        let next = self.asm.new_label();
        let local_fail = if fail.is_none() && !always_identifier {
            Some(self.asm.new_label())
        } else {
            None
        };
        self.mov_arg_to_reg(ARG1, src)?;
        self.emit_is_boxed_source(test_internal, src, ARG1, Distance::Long)?;
        let boxed = self.asm.emit_ptr_val(ARG2, ARG1);
        if !self.always_one_of(src, type_id::PID | type_id::PORT) {
            self.asm
                .emit(|e| e.mov_rm(RETD, emit_boxed_val(boxed, 0, 4)))?;
            self.asm.emit(|e| e.and_ri(RETD, TAG_HEADER_MASK))?;
        }
        if self.maybe_one_of(src, type_id::REFERENCE) {
            self.asm.emit(|e| e.cmp_ri(RETB, TAG_HEADER_REF))?;
            self.asm.short_jcc(CondCode::E, internal)?;
        }
        if !always_identifier {
            let external = self.asm.new_label();
            self.asm.emit(|e| e.sub_ri(RETB, TAG_HEADER_EXTERNAL_PID))?;
            self.asm
                .emit(|e| e.cmp_ri(RETB, TAG_HEADER_EXTERNAL_REF - TAG_HEADER_EXTERNAL_PID))?;
            if let Some(fail) = fail {
                self.asm.jcc(CondCode::A, fail)?;
            } else {
                self.asm.short_jcc(CondCode::BE, external)?;
                self.asm.bind(local_fail.expect("created for body error"))?;
                let fragment = self.ga_get(GlobalLabels::HandleNodeError)?;
                let target = self.resolve_fragment(fragment);
                self.asm.fragment_call(target)?;
            }
            self.asm.bind(external)?;
            self.asm
                .emit(|e| e.mov_rm(ARG1, emit_boxed_val(boxed, 8, 8)))?;
            self.asm.short_jmp(next)?;
        }

        self.asm.bind(test_internal)?;
        if !always_identifier {
            self.asm.emit(|e| e.mov_rr(RETD, ARG1.r32()))?;
            self.asm.emit(|e| {
                e.and_ri(
                    RETB,
                    !((TAG_IMMED1_PORT - TAG_IMMED1_PID) & TAG_IMMED1_MASK) & TAG_IMMED1_MASK,
                )
            })?;
            self.asm.emit(|e| e.cmp_ri(RETB, TAG_IMMED1_PID))?;
            if let Some(fail) = fail {
                self.asm.jcc(CondCode::NE, fail)?;
            } else {
                self.asm
                    .short_jcc(CondCode::NE, local_fail.expect("created for body error"))?;
            }
        }
        self.asm.bind(internal)?;
        self.asm
            .mov_imm(ARG1, arinsal_term::erts_this_node_addr() as u64)?;
        self.asm.emit(|e| e.mov_rm(ARG1, qword_ptr(ARG1, 0)))?;
        self.asm.bind(next)?;
        self.asm.emit(|e| {
            e.mov_rm(
                ARG1,
                qword_ptr(ARG1, arinsal_term::ERL_NODE_SYSNAME_OFFSET as i32),
            )
        })?;
        self.mov_arg_from_reg(dst, ARG1)
    }

    /// Emits `tuple_size/1`, inlining an exact tuple argument.
    // Port of erts/emulator/beam/jit/x86/instr_guard_bifs.cpp:936-957 (emit_bif_tuple_size),
    // OTP-29.1.1.
    pub fn emit_bif_tuple_size(
        &mut self,
        bif: ArgVal,
        fail: ArgVal,
        src: ArgVal,
        dst: ArgVal,
    ) -> Result<(), AsmError> {
        use super::beam_asm::register::{RET, RETB, RETD};
        if self.exact_type(src, type_id::TUPLE) {
            self.mov_arg_to_reg(RET, src)?;
            let boxed = self.asm.emit_ptr_val(RET, RET);
            self.asm
                .emit(|e| e.mov_rm(RETD, emit_boxed_val(boxed, 0, 4)))?;
            self.asm
                .emit(|e| e.shr_ri(RETD, HEADER_ARITY_OFFSET - TAG_IMMED1_SIZE))?;
            self.asm.emit(|e| e.or_ri(RETB, TAG_IMMED1_SMALL))?;
            self.mov_arg_from_reg(dst, RET)
        } else {
            self.emit_i_bif1(src, fail, bif, dst)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::x86::beam_asm_global::GlobalLabels;
    use crate::x86::beam_asm_module::BeamModuleAssembler;
    use crate::x86::jdump::{
        erts_dump, erts_to_arinsal, gnu_as, matches_with_global_jumps, op_blocks,
    };
    use arinsal_x64::buf::Section;
    use similar_asserts::assert_eq;

    fn global_lines(dump: &str, name: &str) -> Vec<String> {
        let head = format!("global::{name}:");
        let mut found = false;
        let mut lines = Vec::new();
        for line in dump.lines() {
            if line.starts_with("global::") {
                if found {
                    break;
                }
                found = line == head;
                continue;
            }
            if found {
                let line = line.trim();
                if !line.is_empty() && !line.starts_with("align ") && !line.starts_with('#') {
                    lines.push(erts_to_arinsal(line));
                }
            }
        }
        lines
    }

    fn complete_blocks(dump: &str, op: &str) -> Vec<Vec<String>> {
        let is_header = |line: &str| {
            line.strip_prefix("# ").is_some_and(|name| {
                !name.is_empty()
                    && name
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
            })
        };
        let mut blocks = Vec::new();
        let mut current: Option<Vec<String>> = None;
        for line in dump.lines() {
            if is_header(line) {
                blocks.extend(current.take());
                if line == format!("# {op}") {
                    current = Some(Vec::new());
                }
            } else if let Some(block) = current.as_mut()
                && !line.starts_with('#')
            {
                block.push(line.trim().to_string());
            }
        }
        blocks.extend(current);
        blocks
    }

    fn fragment_module() -> BeamModuleAssembler {
        BeamModuleAssembler::with_fragment_addresses(
            8,
            vec![Some(0x100000); crate::x86::beam_asm_global::GLOBAL_LABELS.len()],
        )
    }

    fn module_block(lines: &[String], start_offset: usize) -> Vec<String> {
        const NOPS: [&str; 3] = ["0x90", "0x66, 0x90", "0x0f, 0x1f, 0x00"];
        let is_call_alignment_nop = |line: &str| {
            matches!(
                line.to_ascii_lowercase().replace(' ', "").as_str(),
                ".byte0x90" | ".byte0x66,0x90" | ".byte0x0f,0x1f,0x00"
            )
        };
        let mut output = Vec::with_capacity(lines.len());
        for source in lines {
            let line = erts_to_arinsal(source);
            if line.starts_with("call L") {
                output.push(".byte 0xe8, 0, 0, 0, 0".to_string());
            } else if let Some(("call", target)) = line.split_once(' ')
                && target.parse::<u64>().is_ok()
            {
                while output
                    .last()
                    .is_some_and(|line| is_call_alignment_nop(line))
                {
                    output.pop();
                }
                let prefix_len = gnu_as(&output).expect("GNU as for call prefix").len();
                let padding = (4 - (start_offset + prefix_len + 5) % 4) % 4;
                if padding > 0 {
                    output.push(format!(".byte {}", NOPS[padding - 1]));
                }
                output.push(".byte 0xe8, 0, 0, 0, 0".to_string());
            } else {
                output.push(line);
            }
        }
        output
    }

    fn assert_dump_bytes(actual: &[u8], lines: &[String], context: &str) {
        assert_dump_bytes_at(actual, lines, context, 0);
    }

    fn assert_dump_bytes_at(actual: &[u8], lines: &[String], context: &str, start_offset: usize) {
        let expected = module_block(lines, start_offset);
        let expected_bytes = gnu_as(&expected).expect("GNU as");
        assert_eq!(
            matches_with_global_jumps(&expected, actual, &[]),
            Some(true),
            "{context}: {expected:?}; expected bytes {expected_bytes:02x?} vs {actual:02x?}"
        );
    }

    fn add_type(module: &mut BeamModuleAssembler, bits: u16, min: Option<i64>, max: Option<i64>) {
        module.beam_types.push(crate::common::types::ArgType {
            union_bits: bits,
            min,
            max,
            unit: 1,
        });
    }

    #[test]
    fn element_shared_matches_erts_global_fragment() {
        let dump = erts_dump("beam_asm_global").expect("OTP 29.1.1 global jdump");
        let lines = global_lines(&dump, "bif_element_shared");
        let mut global = BeamGlobalAssembler::declare_labels(
            crate::common::process_offsets::ProcessOffsets::ERTS_X86_64,
        );
        let label = global.label(GlobalLabels::BifElementShared);
        global.asm.bind(label).unwrap();
        global.emit_bif_element_shared().unwrap();
        let actual = global.asm.a.bytes(Section::Code);
        assert_eq!(
            matches_with_global_jumps(&lines, actual, &["handle_element_error"]),
            Some(true),
            "{lines:?} vs {actual:02x?}"
        );
    }

    #[test]
    fn exact_immediate_bifs_match_erts_dump() {
        let dump = erts_dump("ets").expect("OTP 29.1.1 jdump for boot module");
        let eq_block = op_blocks(&dump, "bif_is_eq_exact_Ssd")
            .into_iter()
            .find(|block| block.iter().any(|line| line == "cmp qword ptr [rbx], 111"))
            .expect("exact equality with the tagged small 6");
        let eq_expected = gnu_as(
            &eq_block
                .iter()
                .map(|line| erts_to_arinsal(line))
                .collect::<Vec<_>>(),
        )
        .expect("GNU as");
        let mut eq_module = BeamModuleAssembler::new(0);
        eq_module
            .emit_bif_is_eq_exact(ArgVal::X(0), ArgVal::Immediate(111), ArgVal::X(0))
            .unwrap();
        assert_eq!(eq_module.asm.a.bytes(Section::Code), eq_expected);

        let dump = erts_dump("edlin").expect("OTP 29.1.1 jdump for boot module");
        let ne_block = op_blocks(&dump, "bif_is_ne_exact_Ssd")
            .into_iter()
            .find(|block| block.iter().any(|line| line == "cmp qword ptr [rbx], 59"))
            .expect("exact inequality with nil");
        let ne_expected = gnu_as(
            &ne_block
                .iter()
                .map(|line| erts_to_arinsal(line))
                .collect::<Vec<_>>(),
        )
        .expect("GNU as");
        let mut ne_module = BeamModuleAssembler::new(0);
        ne_module
            .emit_bif_is_ne_exact(ArgVal::X(0), ArgVal::Immediate(59), ArgVal::X(0))
            .unwrap();
        assert_eq!(ne_module.asm.a.bytes(Section::Code), ne_expected);
    }

    #[test]
    fn exact_compound_bifs_match_erts_dump() {
        let dump = erts_dump("code").expect("OTP 29.1.1 jdump for code");
        let eq_block = complete_blocks(&dump, "bif_is_eq_exact_Ssd")
            .into_iter()
            .find(|block| {
                block.iter().any(|line| line == "cmp qword ptr [rbx], rdi")
                    && block.iter().any(|line| line == "mov rsi, qword ptr [rsp]")
            })
            .expect("compound equality with X0 and Y0");
        let eq_expected = eq_block
            .iter()
            .map(|line| erts_to_arinsal(line))
            .collect::<Vec<_>>();
        let mut eq_module = BeamModuleAssembler::new(0);
        eq_module
            .emit_bif_is_eq_exact(ArgVal::X(0), ArgVal::Y(0), ArgVal::X(0))
            .unwrap();
        let eq_actual = eq_module.asm.a.bytes(Section::Code);
        assert_eq!(
            matches_with_global_jumps(&eq_expected, eq_actual, &[]),
            Some(true),
            "{eq_expected:?} vs {eq_actual:02x?}"
        );

        let ne_block = complete_blocks(&dump, "bif_is_ne_exact_Ssd")
            .into_iter()
            .find(|block| {
                block.iter().any(|line| line == "cmp qword ptr [rsp], rdi")
                    && block.iter().any(|line| line == "mov rsi, qword ptr [rbx]")
            })
            .expect("compound inequality with Y0 and X0");
        let ne_expected = ne_block
            .iter()
            .map(|line| erts_to_arinsal(line))
            .collect::<Vec<_>>();
        let mut ne_module = BeamModuleAssembler::new(0);
        ne_module
            .emit_bif_is_ne_exact(ArgVal::Y(0), ArgVal::X(0), ArgVal::X(0))
            .unwrap();
        let ne_actual = ne_module.asm.a.bytes(Section::Code);
        assert_eq!(
            matches_with_global_jumps(&ne_expected, ne_actual, &[]),
            Some(true),
            "{ne_expected:?} vs {ne_actual:02x?}"
        );
    }

    #[test]
    fn guard_bif_inline_and_compare_paths_match_erts_dump() {
        let dump = erts_dump("kernel_refc").expect("OTP 29.1.1 jdump for kernel_refc");
        let ge = complete_blocks(&dump, "bif_is_ge_ssd")
            .into_iter()
            .find(|block| block.iter().any(|line| line == "cmp qword ptr [rbx], 31"))
            .expect("small immediate is_ge/2");
        let mut module = fragment_module();
        add_type(&mut module, type_id::INTEGER, Some(0), Some(10));
        module
            .emit_bif_is_ge(ArgVal::typed_x(0, 1), ArgVal::Immediate(31), ArgVal::X(0))
            .unwrap();
        assert_dump_bytes(module.asm.a.bytes(Section::Code), &ge, "is_ge/2");

        let dump = erts_dump("erl_parse").expect("OTP 29.1.1 jdump for erl_parse");
        let lt = complete_blocks(&dump, "bif_is_lt_ssd")
            .into_iter()
            .find(|block| block.iter().any(|line| line == "mov esi, 4111"))
            .expect("general is_lt/2");
        let mut module = fragment_module();
        module
            .emit_bif_is_lt(ArgVal::X(0), ArgVal::Immediate(4111), ArgVal::X(0))
            .unwrap();
        assert_dump_bytes(module.asm.a.bytes(Section::Code), &lt, "is_lt/2");

        let dump = erts_dump("binary").expect("OTP 29.1.1 jdump for binary");
        let bit_size = complete_blocks(&dump, "bif_bit_size_bjsd")
            .into_iter()
            .find(|block| block.iter().any(|line| line == "mov rsi, r10"))
            .expect("inlined bit_size/1");
        let source = ArgVal::typed_x(0, 1);
        let mut module = fragment_module();
        add_type(&mut module, type_id::BITSTRING, None, None);
        module
            .mov_arg_to_reg(super::super::beam_asm::register::TMP1, source)
            .unwrap();
        let start = module.asm.a.offset();
        module
            .emit_bif_bit_size(ArgVal::Immediate(0), ArgVal::Label(0), source, ArgVal::X(0))
            .unwrap();
        let bytes = module.asm.a.bytes(Section::Code);
        assert_dump_bytes(&bytes[start..], &bit_size, "bit_size/1");

        let dump = erts_dump("file").expect("OTP 29.1.1 jdump for file");
        let byte_size = complete_blocks(&dump, "bif_byte_size_bjsd")
            .into_iter()
            .find(|block| block.iter().any(|line| line == "mov rsi, r10"))
            .expect("inlined byte_size/1");
        let mut module = fragment_module();
        add_type(&mut module, type_id::BITSTRING, None, None);
        module
            .mov_arg_to_reg(super::super::beam_asm::register::TMP1, source)
            .unwrap();
        let start = module.asm.a.offset();
        module
            .emit_bif_byte_size(ArgVal::Immediate(0), ArgVal::Label(0), source, ArgVal::X(1))
            .unwrap();
        let bytes = module.asm.a.bytes(Section::Code);
        assert_dump_bytes(&bytes[start..], &byte_size, "byte_size/1");

        let dump = erts_dump("io_lib").expect("OTP 29.1.1 jdump for io_lib");
        let element = complete_blocks(&dump, "bif_element_jssd")
            .into_iter()
            .find(|block| {
                block.iter().any(|line| line == "cmp dword ptr [rsi-2], 64")
                    && block.iter().any(|line| line == "mov edi, 31")
            })
            .expect("inlined element/2");
        let mut module = fragment_module();
        add_type(&mut module, type_id::TUPLE, None, None);
        module
            .emit_bif_element(
                ArgVal::Label(0),
                ArgVal::Immediate(31),
                ArgVal::typed_x(0, 1),
                ArgVal::X(6),
            )
            .unwrap();
        assert_dump_bytes(module.asm.a.bytes(Section::Code), &element, "element/2");

        let dump = erts_dump("gen_statem").expect("OTP 29.1.1 jdump for gen_statem");
        let hd = complete_blocks(&dump, "bif_hd_sd")
            .into_iter()
            .find(|block| {
                block
                    .iter()
                    .any(|line| line == "mov rax, qword ptr [rsp+16]")
            })
            .expect("hd/1 cons fast path");
        let mut module = fragment_module();
        module.emit_bif_hd(ArgVal::Y(2), ArgVal::X(0)).unwrap();
        assert_dump_bytes(module.asm.a.bytes(Section::Code), &hd, "hd/1");

        let dump = erts_dump("io_lib").expect("OTP 29.1.1 jdump for io_lib");
        let tuple_size = complete_blocks(&dump, "bif_tuple_size_bjSd")
            .into_iter()
            .find(|block| {
                block
                    .iter()
                    .any(|line| line == "mov qword ptr [rbx+56], rax")
            })
            .expect("inlined tuple_size/1");
        let mut module = fragment_module();
        add_type(&mut module, type_id::TUPLE, None, None);
        module
            .emit_bif_tuple_size(
                ArgVal::Immediate(0),
                ArgVal::Label(0),
                ArgVal::typed_x(0, 1),
                ArgVal::X(7),
            )
            .unwrap();
        assert_dump_bytes(
            module.asm.a.bytes(Section::Code),
            &tuple_size,
            "tuple_size/1",
        );
    }

    #[test]
    fn map_and_node_bifs_match_erts_dump() {
        let dump = erts_dump("sets").expect("OTP 29.1.1 jdump for sets");
        let map_key = complete_blocks(&dump, "bif_is_map_key_bjssd")
            .into_iter()
            .find(|block| block.iter().any(|line| line == "call L320"))
            .expect("inlined is_map_key/2");
        let src = ArgVal::typed_x(1, 1);
        let mut module = fragment_module();
        add_type(&mut module, type_id::MAP, None, None);
        module
            .mov_arg_to_reg(super::super::beam_asm::register::ARG1, src)
            .unwrap();
        let start = module.asm.a.offset();
        module
            .emit_bif_is_map_key(
                ArgVal::Immediate(0),
                ArgVal::Label(0),
                ArgVal::X(0),
                src,
                ArgVal::X(0),
            )
            .unwrap();
        let bytes = module.asm.a.bytes(Section::Code);
        assert_dump_bytes(&bytes[start..], &map_key, "is_map_key/2");

        let dump = erts_dump("logger_formatter").expect("OTP 29.1.1 jdump for logger_formatter");
        let map_get = complete_blocks(&dump, "bif_map_get_jssd")
            .into_iter()
            .find(|block| {
                block.iter().any(|line| line == "call L270")
                    && block
                        .iter()
                        .any(|line| line == "mov rdi, qword ptr [rbx+8]")
                    && block.iter().any(|line| line == "mov rsi, qword ptr [rbx]")
            })
            .expect("inlined map_get/2");
        let src = ArgVal::typed_x(1, 1);
        let mut module = fragment_module();
        add_type(&mut module, type_id::MAP, None, None);
        module.asm.a.embed(&[0x90]).unwrap();
        let start = module.asm.a.offset();
        module
            .emit_bif_map_get(ArgVal::Label(0), ArgVal::X(0), src, ArgVal::X(0))
            .unwrap();
        let bytes = module.asm.a.bytes(Section::Code);
        assert_dump_bytes_at(&bytes[start..], &map_get, "map_get/2", start);

        let dump = erts_dump("application").expect("OTP 29.1.1 jdump for application");
        let map_size = complete_blocks(&dump, "bif_map_size_jsd")
            .into_iter()
            .find(|block| {
                block
                    .iter()
                    .any(|line| line == "mov rax, qword ptr [rax+6]")
            })
            .expect("inlined map_size/1");
        let src = ArgVal::typed_y(1, 1);
        let mut module = fragment_module();
        add_type(&mut module, type_id::MAP, None, None);
        module
            .emit_bif_map_size(ArgVal::Label(0), src, ArgVal::X(0))
            .unwrap();
        assert_dump_bytes(module.asm.a.bytes(Section::Code), &map_size, "map_size/1");

        let dump = erts_dump("logger_formatter").expect("OTP 29.1.1 jdump for logger_formatter");
        let max = complete_blocks(&dump, "bif_max_ssd")
            .into_iter()
            .find(|block| block.iter().any(|line| line == "mov edi, 175"))
            .expect("generic max/2");
        let max = max
            .iter()
            .map(|line| match line.as_str() {
                "jnz L594" => "short jnz L594".to_string(),
                "jmp L595" => "short jmp L595".to_string(),
                "jz L595" => "short jz L595".to_string(),
                _ => line.clone(),
            })
            .collect::<Vec<_>>();
        let mut module = fragment_module();
        module
            .emit_bif_max(ArgVal::Immediate(175), ArgVal::X(0), ArgVal::X(0))
            .unwrap();
        assert_dump_bytes(module.asm.a.bytes(Section::Code), &max, "max/2");

        let dump = erts_dump("prim_zip").expect("OTP 29.1.1 jdump for prim_zip");
        let min = complete_blocks(&dump, "bif_min_ssd")
            .into_iter()
            .find(|block| block.iter().any(|line| line == "mov esi, 959"))
            .expect("small min/2");
        let mut module = fragment_module();
        add_type(&mut module, type_id::INTEGER, Some(0), Some(100));
        module
            .emit_bif_min(ArgVal::typed_x(1, 1), ArgVal::Immediate(959), ArgVal::X(1))
            .unwrap();
        assert_dump_bytes(module.asm.a.bytes(Section::Code), &min, "min/2");

        let dump = erts_dump("group").expect("OTP 29.1.1 jdump for group");
        let node = complete_blocks(&dump, "bif_node_jSd")
            .into_iter()
            .next()
            .expect("node/1");
        let original_node = node
            .iter()
            .find_map(|line| line.strip_prefix("mov rdi, ")?.parse::<u64>().ok())
            .expect("erts_this_node address in node/1 dump");
        let expected = node
            .iter()
            .map(|line| {
                let line = match line.as_str() {
                    "jz L600" => "short jz L600",
                    "jbe L603" => "short jbe L603",
                    "jmp L601" => "short jmp L601",
                    "jnz L602" => "short jnz L602",
                    _ => line,
                };
                line.replace(
                    &original_node.to_string(),
                    &arinsal_term::erts_this_node_addr().to_string(),
                )
            })
            .collect::<Vec<_>>();
        let expected = module_block(&expected, 0);
        let mut module = fragment_module();
        module
            .emit_bif_node(ArgVal::Label(0), ArgVal::X(0), ArgVal::X(0))
            .unwrap();
        let expected_reloc_bytes = gnu_as(&expected).expect("GNU as");
        let expected_bytes = gnu_as(&expected).expect("GNU as");
        assert_eq!(
            expected_reloc_bytes,
            module.asm.a.bytes(Section::Code),
            "node/1 relocated bytes"
        );
        assert_eq!(
            matches_with_global_jumps(&expected, module.asm.a.bytes(Section::Code), &[]),
            Some(true),
            "node/1: {expected:?}; expected bytes {expected_bytes:02x?} vs {:02x?}",
            module.asm.a.bytes(Section::Code)
        );
    }
}
