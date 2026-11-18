//! Port of erts/emulator/beam/jit/x86/instr_bs.cpp, OTP-29.1.1: the bit syntax matching
//! instructions (`i_bs_start_match3`, `i_bs_match`, `i_bs_match_test_heap`, `bs_get_*`,
//! `i_bs_get_*`, `i_bs_skip_*`, `bs_set_position`, ...), `bs_init_writable`, and the global
//! fragments `bs_size_check_shared`, `bs_get_tail_shared`, `bs_get_utf8_shared`,
//! `bs_create_bin_error_shared`, `get_sint64_shared`, `construct_utf8_shared` and
//! `store_unaligned`. Every `emit_*` is one erts `BeamModuleAssembler::emit_*` or
//! `BeamGlobalAssembler::emit_*`; segment planning is the arch-neutral port of
//! jit/beam_jit_bs.cpp in `common::bs`.

use arinsal_x64::buf::Label;
use arinsal_x64::enc::{self, CondCode, Gp, Mem, byte_ptr, dword_ptr, qword_ptr};

use super::beam_asm::register::{
    ARG1, ARG2, ARG2D, ARG3, ARG3D, ARG4, ARG4D, ARG5, ARG5D, ARG6, ARG6D, C_P, HTOP, RET, RETB,
    RETD,
};
use super::beam_asm::{
    AsmError, BeamAssembler, CpuFeature, Distance, TAG_PRIMARY_BOXED, Update, emit_boxed_val,
    get_x_ref, process, tmp_mem_q,
};
use super::beam_asm_global::{BeamGlobalAssembler, GlobalLabels};
use super::beam_asm_module::{BeamModuleAssembler, arg_label, arg_word};
pub use super::rt::{
    beam_jit_bs_construct_fail_info, beam_jit_bs_field_size_argument_error,
    beam_jit_bs_get_integer, erts_bs_get_binary_2, erts_bs_get_float_2, erts_bs_get_integer_2,
    erts_bs_get_utf8, erts_bs_get_utf16, erts_bs_init_writable, erts_bs_start_match_3,
    erts_build_sub_bitstring, erts_cmp_bits,
};
use crate::common::args::ArgVal;
use crate::common::bs::{
    Action, BUILD_SUB_BITSTRING_HEAP_NEED, ERL_ONHEAP_BITS_LIMIT, ERL_SUB_BITS_SIZE, SMALL_BITS,
    beam_jit_bsm_init, heap_bits_size, opt_bsm_segments,
};
use crate::common::types::BeamModuleAssemblerCommon;
use arinsal_term::{Atom, Term, atoms};

// erl_term.h, erl_bits.h, big.h (64-bit, OTP-29.1.1).
const TAG_IMMED1_SIZE: i64 = 4;
const TAG_IMMED1_MASK: i64 = 0x0f;
const TAG_IMMED1_SMALL: i64 = 0x0f;
const TAG_PRIMARY_MASK: i64 = 0x3;
/// `TAG_PTR_MASK__` (erl_term.h, `ARCH_64`).
const TAG_PTR_MASK: i64 = 0x7;
const TAG_HEADER_MASK: i64 = 0x3f;
const TAG_HEADER_HEAP_BITS: u64 = 0x20;
const BITSTRING_TAG_MASK: i64 = 0x3b;
const POS_BIG_SUBTAG: i64 = 0x08;
const NEG_BIG_SUBTAG: i64 = 0x0c;
const HEADER_ARITY_OFFS: u32 = 6;
/// `MAX_SMALL`.
const MAX_SMALL: i64 = (1 << (SMALL_BITS - 1)) - 1;
/// `ERL_UNIT_BITS` (erl_bits.h).
const ERL_UNIT_BITS: u64 = 8;
/// `ERL_SUB_BITS_FLAG_MASK` and `ERL_SUB_BITS_FLAGS_MATCH_CONTEXT` (erl_bits.h).
const ERL_SUB_BITS_FLAG_MASK: i64 = 3;
const ERL_SUB_BITS_FLAGS_MATCH_CONTEXT: i64 = 1;
/// `HEADER_SUB_BITS`: `_make_header(ERL_SUB_BITS_SIZE - 1, _TAG_HEADER_SUB_BITS)`.
const HEADER_SUB_BITS: i64 = (((ERL_SUB_BITS_SIZE - 1) << HEADER_ARITY_OFFS) | 0x24) as i64;
/// `FLOAT_SIZE_OBJECT` (erl_term.h): `DOUBLE_DATA_WORDS + 1`.
const FLOAT_SIZE_OBJECT: u64 = 2;
/// `BSF_LITTLE`, `BSF_SIGNED`, `BSF_NATIVE` (erl_bits.h).
const BSF_LITTLE: u64 = 2;
const BSF_SIGNED: u64 = 4;
const BSF_NATIVE: u64 = 16;

/// `ArgAtom(atom)`.
fn atom_arg(atom: Atom) -> ArgVal {
    ArgVal::Immediate(Term::atom(atom).word())
}

/// `offsetof(ErlSubBits, field)` (erl_bits.h): `thing_word`, `base_flags`, `start`, `end`,
/// `orig`, one word each.
const SUB_BITS_BASE_FLAGS: i32 = 8;
const SUB_BITS_START: i32 = 16;
const SUB_BITS_END: i32 = 24;
const SUB_BITS_ORIG: i32 = 32;

const fn make_small(value: u64) -> i64 {
    ((value << TAG_IMMED1_SIZE) | TAG_IMMED1_SMALL as u64) as i64
}

/// `_make_header(sz, tag)`.
const fn make_header(size: u64, tag: u64) -> u64 {
    (size << HEADER_ARITY_OFFS) | tag
}

/// `header_heap_bits(num_bits)` (erl_bits.h).
fn header_heap_bits(bits: u64) -> i64 {
    make_header(heap_bits_size(bits) - 1, TAG_HEADER_HEAP_BITS) as i64
}

/// `x86::qword_ptr(0, index, shift)`: an index-only address.
const fn index_ptr(index: Gp, shift: u8) -> Mem {
    Mem {
        base: None,
        index: Some(index),
        shift,
        disp: 0,
        size: 8,
    }
}

fn boxed(src: Gp, offset: i32) -> Mem {
    emit_boxed_val(src, offset, 8)
}

impl BeamModuleAssembler {
    fn beam_label(&self, label: u32) -> Result<Label, AsmError> {
        self.resolve_beam_label(label)
            .ok_or(AsmError::Operand("bit syntax jump to an unknown label"))
    }

    /// `safe_fragment_call(ga->get_<label>())`.
    fn safe_fragment_call_ga(&mut self, label: GlobalLabels) -> Result<(), AsmError> {
        let fragment = self.ga_get(label)?;
        self.safe_fragment_call(fragment)
    }

    /// Loads the size of a segment times `unit` into `out` (clobbering RET and ARG3), jumping
    /// to `fail` when the size is not a valid one (or above `max_size` when non-zero).
    /// Returns -1 when the check always fails, 1 if it may fail, 0 if it never fails.
    // Port of erts/emulator/beam/jit/x86/instr_bs.cpp:34-126 (emit_bs_get_field_size),
    // OTP-29.1.1.
    fn emit_bs_get_field_size(
        &mut self,
        size: ArgVal,
        unit: u64,
        fail: Label,
        out: Gp,
        max_size: u64,
    ) -> Result<i32, AsmError> {
        if size.is_immed() {
            if let Some(sval) = size.small_signed() {
                let limit = MAX_SMALL
                    .checked_div(unit as i64)
                    .ok_or(AsmError::Operand("bit syntax unit zero"))?;
                if sval < 0 || (max_size != 0 && sval as u64 > max_size) || sval > limit {
                    // badarg or system_limit
                } else {
                    self.asm.mov_imm(out, (sval as u64).wrapping_mul(unit))?;
                    return Ok(0);
                }
            }
            self.asm.jmp(fail)?;
            return Ok(-1);
        }

        let mut can_fail = true;
        self.mov_arg_to_reg(RET, size)?;
        if self.always_small(size) {
            let (min, max) = self.get_clamped_range(size);
            can_fail = !(0 <= min && (max >> (SMALL_BITS - ERL_UNIT_BITS)) == 0);
        } else {
            self.asm.emit(|e| e.mov_rr(ARG3D, RETD))?;
            self.asm.emit(|e| e.and_ri(ARG3D, TAG_IMMED1_MASK))?;
            self.asm.emit(|e| e.cmp_ri(ARG3D, TAG_IMMED1_SMALL))?;
            self.asm.jcc(CondCode::NE, fail)?;
        }

        if max_size != 0 {
            self.asm.emit(|e| e.cmp_ri(RET, make_small(max_size)))?;
            self.asm.jcc(CondCode::A, fail)?;
        }

        if unit == 0 {
            self.asm.mov_imm(RET, 0)?;
        } else if unit == 1 {
            self.asm.emit(|e| e.sar_ri(RET, TAG_IMMED1_SIZE))?;
            if can_fail {
                self.asm.jcc(CondCode::S, fail)?;
            }
        } else if !can_fail && unit.is_power_of_two() {
            let trailing_bits = i64::from(unit.trailing_zeros());
            self.asm.emit(|e| e.and_ri(RET, !TAG_IMMED1_MASK))?;
            if trailing_bits < TAG_IMMED1_SIZE {
                self.asm
                    .emit(|e| e.sar_ri(RET, TAG_IMMED1_SIZE - trailing_bits))?;
            } else if trailing_bits > TAG_IMMED1_SIZE {
                self.asm
                    .emit(|e| e.shl_ri(RET, trailing_bits - TAG_IMMED1_SIZE))?;
            }
        } else {
            // Untag the size but don't shift it yet: fail on overflow if the final result
            // doesn't fit into a small.
            self.asm.emit(|e| e.and_ri(RET, !TAG_IMMED1_MASK))?;
            if can_fail {
                self.asm.jcc(CondCode::S, fail)?;
            }
            self.asm.mov_imm(ARG3, unit)?;
            self.asm.emit(|e| e.mul_r(ARG3))?;
            if can_fail {
                self.asm.jcc(CondCode::O, fail)?;
            }
            self.asm.emit(|e| e.sar_ri(RET, TAG_IMMED1_SIZE))?;
        }

        if out != RET {
            self.asm.emit(|e| e.mov_rr(out, RET))?;
        }
        Ok(1)
    }

    /// `i_bs_start_match3 Src Live Fail Dst`: a match context for a bitstring, or the
    /// context itself.
    // Port of erts/emulator/beam/jit/x86/instr_bs.cpp:138-201 (emit_i_bs_start_match3),
    // OTP-29.1.1.
    pub fn emit_i_bs_start_match3(
        &mut self,
        src: ArgVal,
        live: ArgVal,
        fail: ArgVal,
        dst: ArgVal,
    ) -> Result<(), AsmError> {
        let live = arg_word(live)?;
        let fail = arg_label(fail)?;
        let next = self.asm.new_label();
        self.mov_arg_to_reg(ARG2, src)?;
        if fail != 0 {
            let fail = self.beam_label(fail)?;
            self.emit_is_boxed_source(fail, src, ARG2, Distance::Long)?;
        }
        // bs_start_match3 may not throw; the compiler emits {f,0} only when the source is a
        // match context or a bitstring.
        let boxed_ptr = self.asm.emit_ptr_val(ARG1, ARG2);
        // Boxed terms have at least one word past the header, so base_flags is loaded
        // together with the thing word speculatively.
        self.asm
            .emit(|e| e.mov_rm(RETD, emit_boxed_val(boxed_ptr, SUB_BITS_BASE_FLAGS, 4)))?;
        self.asm.emit(|e| e.and_ri(RETD, ERL_SUB_BITS_FLAG_MASK))?;
        self.asm
            .emit(|e| e.xor_ri(RETD, HEADER_SUB_BITS | ERL_SUB_BITS_FLAGS_MATCH_CONTEXT))?;
        self.asm
            .emit(|e| e.xor_rm(RETD, emit_boxed_val(boxed_ptr, 0, 4)))?;
        self.asm.short_jcc(CondCode::E, next)?;

        // RETd holds the thing word and the flag bits that differ; a bitstring has all bits
        // within the bitstring mask zero.
        if fail != 0 {
            let fail = self.beam_label(fail)?;
            self.asm
                .emit(|e| e.and_ri(RETD, BITSTRING_TAG_MASK & !TAG_PRIMARY_MASK))?;
            self.asm.jcc(CondCode::NE, fail)?;
        }

        self.emit_gc_test_preserve(ERL_SUB_BITS_SIZE, live, src, ARG2)?;
        self.asm.emit_enter_runtime(Update::HEAP_ONLY_ALLOC)?;
        self.asm.emit(|e| e.mov_rr(ARG1, C_P))?;
        // ARG2 was set above.
        self.asm
            .runtime_call(erts_bs_start_match_3 as *const () as usize)?;
        self.asm.emit_leave_runtime(Update::HEAP_ONLY_ALLOC)?;
        self.asm
            .emit(|e| e.lea(ARG2, qword_ptr(RET, i32::from(TAG_PRIMARY_BOXED))))?;

        self.asm.bind(next)?;
        self.mov_arg_from_reg(dst, ARG2)
    }

    /// `i_bs_match_string Ctx Fail Bits Ptr`.
    // Port of erts/emulator/beam/jit/x86/instr_bs.cpp:203-247 (emit_i_bs_match_string),
    // OTP-29.1.1.
    pub fn emit_i_bs_match_string(
        &mut self,
        ctx: ArgVal,
        fail: ArgVal,
        bits: ArgVal,
        ptr: ArgVal,
    ) -> Result<(), AsmError> {
        let fail = arg_label(fail)?;
        let bits = arg_word(bits)?;
        let size = bits;
        let fail = self.beam_label(fail)?;
        self.mov_arg_to_reg(ARG1, ctx)?;

        self.asm
            .emit(|e| e.mov_rm(ARG2, boxed(ARG1, SUB_BITS_START)))?;
        self.asm
            .emit(|e| e.lea(ARG3, qword_ptr(ARG2, size as i32)))?;
        self.asm
            .emit(|e| e.cmp_rm(ARG3, boxed(ARG1, SUB_BITS_END)))?;
        self.asm.jcc(CondCode::A, fail)?;

        self.asm.emit(|e| e.mov_mr(tmp_mem_q(0), ARG1))?;

        // ARG4 = sb->start & 7
        self.asm.emit(|e| e.mov_rr(ARG4, ARG2))?;
        self.asm.emit(|e| e.and_ri(ARG4, 7))?;

        // ARG3 = sb->base_flags + (sb->start >> 3) - match_ctx_flag
        self.asm.emit(|e| e.shr_ri(ARG2, 3))?;
        self.asm
            .emit(|e| e.mov_rm(ARG3, boxed(ARG1, SUB_BITS_BASE_FLAGS)))?;
        self.asm.emit(|e| {
            e.lea(
                ARG3,
                Mem::base_index(ARG3, ARG2, 0, -(ERL_SUB_BITS_FLAGS_MATCH_CONTEXT as i32), 8),
            )
        })?;

        self.asm.emit_enter_runtime(Update::NONE)?;
        self.mov_arg_to_reg(ARG1, ptr)?;
        self.asm.mov_imm(ARG2, 0)?;
        self.asm.mov_imm(ARG5, size)?;
        self.asm.runtime_call(erts_cmp_bits as *const () as usize)?;
        self.asm.emit_leave_runtime(Update::NONE)?;

        self.asm.emit(|e| e.test_rr(RET, RET))?;
        self.asm.jcc(CondCode::NE, fail)?;

        self.asm.emit(|e| e.mov_rm(ARG1, tmp_mem_q(0)))?;
        self.asm
            .emit(|e| e.add_mi(boxed(ARG1, SUB_BITS_START), size as i64))
    }

    /// `i_bs_get_position Ctx Dst`: the match position as a small.
    // Port of erts/emulator/beam/jit/x86/instr_bs.cpp:249-267 (emit_i_bs_get_position),
    // OTP-29.1.1.
    pub fn emit_i_bs_get_position(&mut self, ctx: ArgVal, dst: ArgVal) -> Result<(), AsmError> {
        let tmp_reg = self.alloc_temp_reg();
        self.mov_arg_to_reg(ARG1, ctx)?;
        // Match contexts can never be literals, so literal tags need no clearing.
        self.mov_preserve_cache_load(tmp_reg, boxed(ARG1, SUB_BITS_START))?;
        self.preserve_cache(&[tmp_reg], &[], |m| {
            // `a.sal`: the same encoding as `shl` (`D1 /4`, `C1 /4 ib`).
            m.asm.emit(|e| e.shl_ri(tmp_reg, TAG_IMMED1_SIZE))?;
            m.asm.emit(|e| e.or_ri(tmp_reg, TAG_IMMED1_SMALL))
        })?;
        self.mov_arg_from_reg(dst, tmp_reg)
    }

    // Port of erts/emulator/beam/jit/x86/instr_bs.cpp:269-298 (emit_bs_get_small),
    // OTP-29.1.1.
    fn emit_bs_get_small(
        &mut self,
        fail: Label,
        ctx: ArgVal,
        sz: ArgVal,
        unit: u64,
        flags: u64,
    ) -> Result<(), AsmError> {
        // Clobbers RET + ARG3; a negative result means we always fail.
        if self.emit_bs_get_field_size(sz, unit, fail, ARG2, 0)? >= 0 {
            self.asm.mov_imm(ARG3, flags)?;
            self.mov_arg_to_reg(ARG4, ctx)?;
            self.asm
                .emit(|e| e.sub_ri(ARG4, i64::from(TAG_PRIMARY_BOXED)))?;
            self.asm.emit_enter_runtime(Update::NONE)?;
            // The process argument is never used.
            self.asm
                .runtime_call(erts_bs_get_integer_2 as *const () as usize)?;
            self.asm.emit_leave_runtime(Update::NONE)?;
            self.asm.emit_test_the_non_value(RET)?;
            self.asm.jcc(CondCode::E, fail)?;
        }
        Ok(())
    }

    // Port of erts/emulator/beam/jit/x86/instr_bs.cpp:300-328 (emit_bs_get_any_int),
    // OTP-29.1.1.
    fn emit_bs_get_any_int(
        &mut self,
        fail: Label,
        ctx: ArgVal,
        live: u64,
        sz: ArgVal,
        unit: u64,
        flags: u64,
    ) -> Result<(), AsmError> {
        if self.emit_bs_get_field_size(sz, unit, fail, ARG5, 0)? >= 0 {
            let spec = Update::REDUCTIONS.union(Update::HEAP_ALLOC);
            self.mov_arg_to_reg(ARG3, ctx)?;
            self.asm.mov_imm(ARG4, flags)?;
            self.mov_arg_to_reg(ARG6, ArgVal::Word(live))?;
            self.asm.emit_enter_runtime(spec)?;
            self.asm.emit(|e| e.mov_rr(ARG1, C_P))?;
            self.asm.load_x_reg_array(ARG2)?;
            self.asm
                .runtime_call(beam_jit_bs_get_integer as *const () as usize)?;
            self.asm.emit_leave_runtime(spec)?;
            self.asm.emit_test_the_non_value(RET)?;
            self.asm.jcc(CondCode::E, fail)?;
            // Test for max heap size exceeded.
            let do_schedule = self.ga_get(GlobalLabels::DoSchedule)?;
            let schedule = self.resolve_fragment(do_schedule);
            self.emit_is_not_cons(schedule, RET, Distance::Long)?;
        }
        Ok(())
    }

    /// `bs_get_integer2 Fail Ctx Live Sz Unit Flags Dst`.
    // Port of erts/emulator/beam/jit/x86/instr_bs.cpp:330-377 (emit_bs_get_integer2),
    // OTP-29.1.1.
    #[allow(clippy::too_many_arguments)]
    pub fn emit_bs_get_integer2(
        &mut self,
        fail: ArgVal,
        ctx: ArgVal,
        live: ArgVal,
        sz: ArgVal,
        unit: ArgVal,
        flags: ArgVal,
        dst: ArgVal,
    ) -> Result<(), AsmError> {
        let unit = arg_word(unit)?;
        let flags = arg_word(flags)?;
        let mut flags = flags;
        if flags & BSF_NATIVE != 0 {
            flags &= !BSF_NATIVE;
            flags |= BSF_LITTLE;
        }
        // `Sz.as<ArgSmall>().getUnsigned()`.
        let small = sz.small_signed().map(|value| value as u64);
        let size = small.map_or(0, |value| value.wrapping_mul(unit));
        if small.is_some_and(|value| value < 64) && size < 64 {
            // A segment of a fixed size supported by bs_match.
            let commands = [
                atom_arg(atoms::ENSURE_AT_LEAST),
                ArgVal::Word(size),
                ArgVal::Word(1),
                atom_arg(atoms::INTEGER),
                live,
                ArgVal::Word(flags),
                ArgVal::Word(size),
                ArgVal::Word(1),
                dst,
            ];
            self.emit_i_bs_match(fail, ctx, &commands)
        } else {
            let fail = self.beam_label(arg_label(fail)?)?;
            let live = arg_word(live)?;
            let max = self.get_clamped_range(sz).1;
            let potential_gc =
                max >= SMALL_BITS as i64 || (max as u64).wrapping_mul(unit) >= SMALL_BITS;
            if potential_gc {
                self.emit_bs_get_any_int(fail, ctx, live, sz, unit, flags)?;
            } else {
                self.emit_bs_get_small(fail, ctx, sz, unit, flags)?;
            }
            self.mov_arg_from_reg(dst, RET)
        }
    }

    /// `bs_test_tail2 Fail Ctx Offset`, only in unoptimized code and code compiled for
    /// OTP 25 and earlier.
    // Port of erts/emulator/beam/jit/x86/instr_bs.cpp:379-388 (emit_bs_test_tail2),
    // OTP-29.1.1.
    pub fn emit_bs_test_tail2(
        &mut self,
        fail: ArgVal,
        ctx: ArgVal,
        offset: ArgVal,
    ) -> Result<(), AsmError> {
        self.emit_i_bs_match(fail, ctx, &[atom_arg(atoms::ENSURE_EXACTLY), offset])
    }

    /// `bs_set_position Ctx Pos`.
    // Port of erts/emulator/beam/jit/x86/instr_bs.cpp:390-401 (emit_bs_set_position),
    // OTP-29.1.1.
    pub fn emit_bs_set_position(&mut self, ctx: ArgVal, pos: ArgVal) -> Result<(), AsmError> {
        self.mov_arg_to_reg(ARG1, ctx)?;
        self.mov_arg_to_reg(ARG2, pos)?;
        self.preserve_cache(&[ARG2], &[], |m| {
            m.asm.emit(|e| e.sar_ri(ARG2, TAG_IMMED1_SIZE))
        })?;
        self.mov_preserve_cache_store(boxed(ARG1, SUB_BITS_START), ARG2)
    }

    /// `i_bs_get_binary_all2 Ctx Fail Live Unit Dst`, only in unoptimized code and code
    /// compiled for OTP 25 and earlier.
    // Port of erts/emulator/beam/jit/x86/instr_bs.cpp:403-422 (emit_i_bs_get_binary_all2),
    // OTP-29.1.1.
    pub fn emit_i_bs_get_binary_all2(
        &mut self,
        ctx: ArgVal,
        fail: ArgVal,
        live: ArgVal,
        unit: ArgVal,
        dst: ArgVal,
    ) -> Result<(), AsmError> {
        let unit = arg_word(unit)?;
        let commands = [
            atom_arg(atoms::ENSURE_AT_LEAST),
            ArgVal::Word(0),
            ArgVal::Word(unit),
            atom_arg(atoms::GET_TAIL),
            live,
            ArgVal::Word(unit),
            dst,
        ];
        self.emit_i_bs_match(fail, ctx, &commands)
    }

    /// `bs_get_tail Ctx Dst Live`.
    // Port of erts/emulator/beam/jit/x86/instr_bs.cpp:456-469 (emit_bs_get_tail), OTP-29.1.1.
    pub fn emit_bs_get_tail(
        &mut self,
        ctx: ArgVal,
        dst: ArgVal,
        live: ArgVal,
    ) -> Result<(), AsmError> {
        let live = arg_word(live)?;
        self.mov_arg_to_reg(ARG1, ctx)?;
        self.emit_gc_test_preserve(BUILD_SUB_BITSTRING_HEAP_NEED, live, ctx, ARG1)?;
        self.safe_fragment_call_ga(GlobalLabels::BsGetTailShared)?;
        self.mov_arg_from_reg(dst, RET)
    }

    /// Skips the bits in RET.
    // Port of erts/emulator/beam/jit/x86/instr_bs.cpp:471-481 (emit_bs_skip_bits), OTP-29.1.1.
    fn emit_bs_skip_bits(&mut self, fail: u32, ctx: ArgVal) -> Result<(), AsmError> {
        self.mov_arg_to_reg(ARG1, ctx)?;
        self.asm
            .emit(|e| e.add_rm(RET, boxed(ARG1, SUB_BITS_START)))?;
        self.asm
            .emit(|e| e.cmp_rm(RET, boxed(ARG1, SUB_BITS_END)))?;
        let fail = self.beam_label(fail)?;
        self.asm.jcc(CondCode::A, fail)?;
        self.asm
            .emit(|e| e.mov_mr(boxed(ARG1, SUB_BITS_START), RET))
    }

    /// `i_bs_skip_bits2 Ctx Bits Fail Unit`.
    // Port of erts/emulator/beam/jit/x86/instr_bs.cpp:483-493 (emit_i_bs_skip_bits2),
    // OTP-29.1.1.
    pub fn emit_i_bs_skip_bits2(
        &mut self,
        ctx: ArgVal,
        bits: ArgVal,
        fail: ArgVal,
        unit: ArgVal,
    ) -> Result<(), AsmError> {
        let fail = arg_label(fail)?;
        let unit = arg_word(unit)?;
        let fail_label = self.beam_label(fail)?;
        if self.emit_bs_get_field_size(bits, unit, fail_label, RET, 0)? >= 0 {
            self.emit_bs_skip_bits(fail, ctx)?;
        }
        Ok(())
    }

    // Port of erts/emulator/beam/jit/x86/instr_bs.cpp:495-531 (emit_bs_get_binary),
    // OTP-29.1.1.
    #[allow(clippy::too_many_arguments)]
    fn emit_bs_get_binary(
        &mut self,
        heap_need: u64,
        ctx: ArgVal,
        fail: u32,
        live: u64,
        size: ArgVal,
        unit: u64,
        dst: ArgVal,
    ) -> Result<(), AsmError> {
        let fail = self.beam_label(fail)?;
        // Clobbers RET + ARG3.
        if self.emit_bs_get_field_size(size, unit, fail, ARG2, 0)? >= 0 {
            self.asm.emit(|e| e.mov_mr(tmp_mem_q(0), ARG2))?;
            self.mov_arg_to_reg(ARG4, ctx)?;
            self.emit_gc_test_preserve(heap_need, live, ctx, ARG4)?;
            self.asm.emit_enter_runtime(Update::HEAP_ONLY_ALLOC)?;
            self.asm.emit(|e| e.mov_rr(ARG1, C_P))?;
            self.asm.emit(|e| e.mov_rm(ARG2, tmp_mem_q(0)))?;
            self.asm
                .emit(|e| e.lea(ARG3, qword_ptr(ARG4, -i32::from(TAG_PRIMARY_BOXED))))?;
            self.asm
                .runtime_call(erts_bs_get_binary_2 as *const () as usize)?;
            self.asm.emit_leave_runtime(Update::HEAP_ONLY_ALLOC)?;
            self.asm.emit_test_the_non_value(RET)?;
            self.asm.jcc(CondCode::E, fail)?;
            self.mov_arg_from_reg(dst, RET)?;
        }
        Ok(())
    }

    /// `i_bs_get_binary2 Ctx Fail Live Size Unit Dst`.
    // Port of erts/emulator/beam/jit/x86/instr_bs.cpp:533-546 (emit_i_bs_get_binary2),
    // OTP-29.1.1.
    pub fn emit_i_bs_get_binary2(
        &mut self,
        ctx: ArgVal,
        fail: ArgVal,
        live: ArgVal,
        size: ArgVal,
        unit: ArgVal,
        dst: ArgVal,
    ) -> Result<(), AsmError> {
        let fail = arg_label(fail)?;
        let live = arg_word(live)?;
        let unit = arg_word(unit)?;
        self.emit_bs_get_binary(
            BUILD_SUB_BITSTRING_HEAP_NEED,
            ctx,
            fail,
            live,
            size,
            unit,
            dst,
        )
    }

    /// `i_bs_get_bin_and_tail Ctx Fail Live Size Unit Dst1 Dst2`.
    // Port of erts/emulator/beam/jit/x86/instr_bs.cpp:548-566 (emit_i_bs_get_bin_and_tail),
    // OTP-29.1.1.
    #[allow(clippy::too_many_arguments)]
    pub fn emit_i_bs_get_bin_and_tail(
        &mut self,
        ctx: ArgVal,
        fail: ArgVal,
        live: ArgVal,
        size: ArgVal,
        unit: ArgVal,
        dst1: ArgVal,
        dst2: ArgVal,
    ) -> Result<(), AsmError> {
        let fail = arg_label(fail)?;
        let live = arg_word(live)?;
        let unit = arg_word(unit)?;
        self.emit_bs_get_binary(
            2 * BUILD_SUB_BITSTRING_HEAP_NEED,
            ctx,
            fail,
            live,
            size,
            unit,
            dst1,
        )?;
        self.mov_arg_to_reg(ARG1, ctx)?;
        self.safe_fragment_call_ga(GlobalLabels::BsGetTailShared)?;
        self.mov_arg_from_reg(dst2, RET)
    }

    /// `i_bs_get_float2 Ctx Fail Live Sz Flags Dst`.
    // Port of erts/emulator/beam/jit/x86/instr_bs.cpp:568-601 (emit_i_bs_get_float2),
    // OTP-29.1.1.
    pub fn emit_i_bs_get_float2(
        &mut self,
        ctx: ArgVal,
        fail: ArgVal,
        live: ArgVal,
        sz: ArgVal,
        flags: ArgVal,
        dst: ArgVal,
    ) -> Result<(), AsmError> {
        let fail = arg_label(fail)?;
        let live = arg_word(live)?;
        let flags = arg_word(flags)?;
        let fail = self.beam_label(fail)?;
        let unit = flags >> 3;
        self.mov_arg_to_reg(ARG4, ctx)?;
        self.emit_gc_test_preserve(FLOAT_SIZE_OBJECT, live, ctx, ARG4)?;
        if self.emit_bs_get_field_size(sz, unit, fail, ARG2, 64)? >= 0 {
            self.asm.emit_enter_runtime(Update::HEAP_ONLY_ALLOC)?;
            self.asm.emit(|e| e.mov_rr(ARG1, C_P))?;
            // ARG2 set above.
            self.asm.mov_imm(ARG3, flags)?;
            self.asm
                .emit(|e| e.sub_ri(ARG4, i64::from(TAG_PRIMARY_BOXED)))?;
            self.asm
                .runtime_call(erts_bs_get_float_2 as *const () as usize)?;
            self.asm.emit_leave_runtime(Update::HEAP_ONLY_ALLOC)?;
            self.asm.emit_test_the_non_value(RET)?;
            self.asm.jcc(CondCode::E, fail)?;
            self.mov_arg_from_reg(dst, RET)?;
        }
        Ok(())
    }

    /// Matches one UTF-8 code point: the code point as a small in RET, ZF set on failure.
    // Port of erts/emulator/beam/jit/x86/instr_bs.cpp:907-983 (emit_bs_get_utf8), OTP-29.1.1.
    fn emit_bs_get_utf8(&mut self, ctx_arg: ArgVal, fail: u32) -> Result<(), AsmError> {
        let ctx = ARG1;
        let bin_position = ARG2;
        let bin_base = ARG3;
        let multi_byte = self.asm.new_label();
        let fallback = self.asm.new_label();
        let check = self.asm.new_label();
        let done = self.asm.new_label();

        self.mov_arg_to_reg(ctx, ctx_arg)?;
        let a = &mut self.asm;
        a.emit(|e| e.sub_ri(ctx, i64::from(TAG_PRIMARY_BOXED)))?;
        a.emit(|e| e.mov_rm(bin_position, qword_ptr(ctx, SUB_BITS_START)))?;
        a.emit(|e| e.mov_rm(RET, qword_ptr(ctx, SUB_BITS_END)))?;
        a.emit(|e| e.mov_rm(bin_base, qword_ptr(ctx, SUB_BITS_BASE_FLAGS)))?;
        a.emit(|e| e.and_ri(bin_base, !ERL_SUB_BITS_FLAG_MASK))?;
        a.emit(|e| e.sub_rr(RET, bin_position))?;
        a.emit(|e| e.cmp_ri(RET, 32))?;
        a.short_jcc(CondCode::B, fallback)?;

        a.emit(|e| e.test_ri(bin_position, 7))?;
        a.short_jcc(CondCode::NE, fallback)?;

        // Byte-aligned with at least 32 bits left.
        a.emit(|e| e.mov_rr(RET, bin_position))?;
        a.emit(|e| e.shr_ri(RET, 3))?;

        // The most significant bits come first: read the next four bytes big-endian.
        let next_four = Mem::base_index(bin_base, RET, 0, 0, 4);
        if BeamAssembler::has_cpu_feature(CpuFeature::Movbe) {
            a.emit(|e| e.movbe_rm(RETD, next_four))?;
        } else {
            a.emit(|e| e.mov_rm(RETD, next_four))?;
            a.emit(|e| e.bswap(RETD))?;
        }
        a.emit(|e| e.test_rr(RETD, RETD))?;
        a.short_jcc(CondCode::S, multi_byte)?;

        // Plain ASCII (code point < 128).
        a.emit(|e| e.add_mi(qword_ptr(ctx, SUB_BITS_START), 8))?;
        a.emit(|e| e.shr_ri(RETD, 24 - TAG_IMMED1_SIZE))?;
        a.emit(|e| e.or_ri(RETD, TAG_IMMED1_SMALL))?;
        a.short_jmp(done)?;

        a.bind(multi_byte)?;
        let bmi2 = BeamAssembler::has_cpu_feature(CpuFeature::Bmi2);
        if bmi2 {
            // This CPU supports the PEXT and SHRX instructions.
            self.safe_fragment_call_ga(GlobalLabels::BsGetUtf8Shared)?;
            self.asm.short_jmp(check)?;
        }

        // Unaligned binaries and binaries with less than 32 bits left.
        self.asm.bind(fallback)?;
        if bmi2 {
            self.safe_fragment_call_ga(GlobalLabels::BsGetUtf8ShortShared)?;
        } else {
            let a = &mut self.asm;
            a.emit_enter_runtime(Update::NONE)?;
            a.runtime_call(erts_bs_get_utf8 as *const () as usize)?;
            a.emit_leave_runtime(Update::NONE)?;
            a.emit_test_the_non_value(RET)?;
        }

        self.asm.bind(check)?;
        let fail = self.beam_label(fail)?;
        self.asm.jcc(CondCode::E, fail)?;
        self.asm.bind(done)
    }

    /// `i_bs_get_utf8 Ctx Fail Dst`.
    // Port of erts/emulator/beam/jit/x86/instr_bs.cpp:985-990 (emit_i_bs_get_utf8),
    // OTP-29.1.1.
    pub fn emit_i_bs_get_utf8(
        &mut self,
        ctx: ArgVal,
        fail: ArgVal,
        dst: ArgVal,
    ) -> Result<(), AsmError> {
        let fail = arg_label(fail)?;
        self.emit_bs_get_utf8(ctx, fail)?;
        self.mov_arg_from_reg(dst, RET)
    }

    /// `i_bs_skip_utf8 Ctx Fail`.
    // Port of erts/emulator/beam/jit/x86/instr_bs.cpp:992-995 (emit_i_bs_skip_utf8),
    // OTP-29.1.1.
    pub fn emit_i_bs_skip_utf8(&mut self, ctx: ArgVal, fail: ArgVal) -> Result<(), AsmError> {
        let fail = arg_label(fail)?;
        self.emit_bs_get_utf8(ctx, fail)
    }

    // Port of erts/emulator/beam/jit/x86/instr_bs.cpp:997-1012 (emit_bs_get_utf16),
    // OTP-29.1.1.
    fn emit_bs_get_utf16(&mut self, ctx: ArgVal, fail: u32, flags: u64) -> Result<(), AsmError> {
        self.mov_arg_to_reg(ARG1, ctx)?;
        let a = &mut self.asm;
        a.emit_enter_runtime(Update::NONE)?;
        a.emit(|e| e.sub_ri(ARG1, i64::from(TAG_PRIMARY_BOXED)))?;
        a.mov_imm(ARG2, flags)?;
        a.runtime_call(erts_bs_get_utf16 as *const () as usize)?;
        a.emit_leave_runtime(Update::NONE)?;
        a.emit_test_the_non_value(RET)?;
        let fail = self.beam_label(fail)?;
        self.asm.jcc(CondCode::E, fail)
    }

    /// `i_bs_get_utf16 Ctx Fail Flags Dst`.
    // Port of erts/emulator/beam/jit/x86/instr_bs.cpp:1014-1020 (emit_i_bs_get_utf16),
    // OTP-29.1.1.
    pub fn emit_i_bs_get_utf16(
        &mut self,
        ctx: ArgVal,
        fail: ArgVal,
        flags: ArgVal,
        dst: ArgVal,
    ) -> Result<(), AsmError> {
        let fail = arg_label(fail)?;
        let flags = arg_word(flags)?;
        self.emit_bs_get_utf16(ctx, fail, flags)?;
        self.mov_arg_from_reg(dst, RET)
    }

    /// `i_bs_skip_utf16 Ctx Fail Flags`.
    // Port of erts/emulator/beam/jit/x86/instr_bs.cpp:1022-1026 (emit_i_bs_skip_utf16),
    // OTP-29.1.1.
    pub fn emit_i_bs_skip_utf16(
        &mut self,
        ctx: ArgVal,
        fail: ArgVal,
        flags: ArgVal,
    ) -> Result<(), AsmError> {
        let fail = arg_label(fail)?;
        let flags = arg_word(flags)?;
        self.emit_bs_get_utf16(ctx, fail, flags)
    }

    // Port of erts/emulator/beam/jit/x86/instr_bs.cpp:1028-1044 (emit_validate_unicode),
    // OTP-29.1.1.
    fn emit_validate_unicode(
        &mut self,
        next: Label,
        fail: Label,
        value: Gp,
    ) -> Result<(), AsmError> {
        let a = &mut self.asm;
        a.emit(|e| e.mov_rr(ARG3D, value.r32()))?;
        a.emit(|e| e.and_ri(ARG3D.r8(), TAG_IMMED1_MASK))?;
        a.emit(|e| e.cmp_ri(ARG3D.r8(), TAG_IMMED1_SMALL))?;
        a.jcc(CondCode::NE, fail)?;

        a.emit(|e| e.cmp_ri(value, make_small(0xD800)))?;
        a.jcc(CondCode::B, next)?;
        a.emit(|e| e.cmp_ri(value, make_small(0xDFFF)))?;
        a.jcc(CondCode::BE, fail)?;
        a.emit(|e| e.cmp_ri(value, make_small(0x10FFFF)))?;
        a.jcc(CondCode::A, fail)?;

        a.jmp(next)
    }

    /// `i_bs_validate_unicode_retract Fail Src Ms`.
    // Port of erts/emulator/beam/jit/x86/instr_bs.cpp:1046-1067
    // (emit_i_bs_validate_unicode_retract), OTP-29.1.1.
    pub fn emit_i_bs_validate_unicode_retract(
        &mut self,
        fail: ArgVal,
        src: ArgVal,
        ms: ArgVal,
    ) -> Result<(), AsmError> {
        let fail = arg_label(fail)?;
        let fail_label = self.asm.new_label();
        let next = self.asm.new_label();
        self.mov_arg_to_reg(ARG1, src)?;
        self.emit_validate_unicode(next, fail_label, ARG1)?;

        self.asm.bind(fail_label)?;
        self.mov_arg_to_reg(ARG1, ms)?;
        self.asm
            .emit(|e| e.sub_mi(boxed(ARG1, SUB_BITS_START), 32))?;
        if fail == 0 {
            return Err(AsmError::Operand(
                "i_bs_validate_unicode_retract without a fail label",
            ));
        }
        let fail = self.beam_label(fail)?;
        self.asm.jmp(fail)?;

        self.asm.bind(next)
    }

    /// `bs_init_writable`: x0 becomes a writable binary of x0 bytes.
    // Port of erts/emulator/beam/jit/x86/instr_bs.cpp:1069-1078 (emit_bs_init_writable),
    // OTP-29.1.1.
    pub fn emit_bs_init_writable(&mut self) -> Result<(), AsmError> {
        let spec = Update::REDUCTIONS.union(Update::HEAP_ALLOC);
        let a = &mut self.asm;
        a.emit_enter_runtime(spec)?;
        a.emit(|e| e.mov_rr(ARG1, C_P))?;
        a.emit(|e| e.mov_rm(ARG2, get_x_ref(0, 8)))?;
        a.runtime_call(erts_bs_init_writable as *const () as usize)?;
        a.emit(|e| e.mov_mr(get_x_ref(0, 8), RET))?;
        a.emit_leave_runtime(spec)
    }

    /// Reads `bits` (at most 64) from `bin_base` at the bit offset in `bin_offset` (RCX) into
    /// the most significant bits of `bitdata`.
    // Port of erts/emulator/beam/jit/x86/instr_bs.cpp:2673-2799 (emit_read_bits), OTP-29.1.1.
    fn emit_read_bits(
        &mut self,
        bits: u64,
        bin_base: Gp,
        bin_offset: Gp,
        bitdata: Gp,
    ) -> Result<(), AsmError> {
        let movbe = BeamAssembler::has_cpu_feature(CpuFeature::Movbe);
        let a = &mut self.asm;
        let read_done = a.new_label();
        let num_partial = bits % 8;
        let num_bytes_to_read = bits.div_ceil(8) as i32;
        assert_eq!(bin_offset, enc::RCX);

        a.emit(|e| e.mov_rr(RET, bin_offset))?;
        a.emit(|e| e.shr_ri(RET, 3))?;
        if num_bytes_to_read != 1 {
            a.emit(|e| e.add_rr(bin_base, RET))?;
        }
        a.emit(|e| e.and_ri(bin_offset.r32(), 7))?;

        // Reading 8 or 9 bytes.
        if num_bytes_to_read == 8 {
            let src = qword_ptr(bin_base, num_bytes_to_read - 8);
            if movbe {
                a.emit(|e| e.movbe_rm(bitdata, src))?;
            } else {
                a.emit(|e| e.mov_rm(bitdata, src))?;
                a.emit(|e| e.bswap(bitdata))?;
            }
            a.emit(|e| e.shl_rr(bitdata, enc::CL))?;

            a.emit(|e| e.test_ri(enc::CL, 7))?;
            if num_partial == 0 {
                // Byte-sized segment: an unaligned offset always needs an extra byte.
                a.jcc(CondCode::E, read_done)?;
            } else if num_partial > 1 {
                // Test whether an additional byte is needed.
                a.emit(|e| e.cmp_ri(bin_offset.r32(), 8 - num_partial as i64))?;
                a.jcc(CondCode::LE, read_done)?;
            }

            if num_partial != 1 {
                // Read an extra byte.
                a.emit(|e| e.movzx_rm(RETD, byte_ptr(bin_base, 8)))?;
                a.emit(|e| e.shl_rr(RETD, enc::CL))?;
                a.emit(|e| e.shr_ri(RETD, 8))?;
                a.emit(|e| e.or_rr(bitdata, RET))?;
            }

            return a.bind(read_done);
        }

        // Reading up to 7 bytes.
        let handle_partial = a.new_label();
        let swap = a.new_label();
        let shift = a.new_label();

        if num_partial == 0 {
            // Byte-sized segment: an unaligned offset always needs an extra byte.
            a.jcc(CondCode::NE, handle_partial)?;
        } else if num_partial > 1 {
            a.emit(|e| e.cmp_ri(bin_offset.r32(), 8 - num_partial as i64))?;
            a.jcc(CondCode::G, handle_partial)?;
        }

        // No extra byte needed.
        if num_bytes_to_read == 1 {
            a.emit(|e| e.movzx_rm(bitdata.r32(), Mem::base_index(bin_base, RET, 0, 0, 1)))?;
            if num_partial == 0 {
                a.emit(|e| e.bswap(bitdata))?;
                a.short_jmp(read_done)?;
            } else if num_partial > 1 {
                a.short_jmp(swap)?;
            }
        } else if num_bytes_to_read <= 4 {
            let src = dword_ptr(bin_base, num_bytes_to_read - 4);
            if movbe {
                a.emit(|e| e.movbe_rm(bitdata.r32(), src))?;
            } else {
                a.emit(|e| e.mov_rm(bitdata.r32(), src))?;
                a.emit(|e| e.bswap(bitdata.r32()))?;
            }
            a.emit(|e| e.add_ri(bin_offset.r32(), i64::from(64 - 8 * num_bytes_to_read)))?;
            a.short_jmp(shift)?;
        } else {
            let src = qword_ptr(bin_base, num_bytes_to_read - 8);
            if movbe {
                a.emit(|e| e.movbe_rm(bitdata, src))?;
            } else {
                a.emit(|e| e.mov_rm(bitdata, src))?;
                a.emit(|e| e.bswap(bitdata))?;
            }
            assert!(num_bytes_to_read < 8);
            a.emit(|e| e.add_ri(bin_offset.r32(), i64::from(64 - 8 * num_bytes_to_read)))?;
            a.short_jmp(shift)?;
        }

        // An extra byte is needed, and a shift.
        a.bind(handle_partial)?;
        if num_partial != 1 {
            if num_bytes_to_read == 1 {
                a.emit(|e| e.mov_rm(bitdata.r16(), Mem::base_index(bin_base, RET, 0, 0, 2)))?;
            } else {
                assert!(num_bytes_to_read < 8);
                a.emit(|e| e.mov_rm(bitdata, qword_ptr(bin_base, num_bytes_to_read - 7)))?;
                a.emit(|e| e.shr_ri(bitdata, i64::from(64 - 8 * (num_bytes_to_read + 1))))?;
            }
        }

        a.bind(swap)?;
        a.emit(|e| e.bswap(bitdata))?;

        // Shift the read data into the most significant bits of the word.
        a.bind(shift)?;
        a.emit(|e| e.shl_rr(bitdata, enc::CL))?;

        a.bind(read_done)
    }

    /// Reads an integer of a common size (8, 16 or 32 bits) and stores it as a small: the
    /// case of a single integer extracted from a binary. Clobbers `bin_base`, `bin_offset`,
    /// `tmp` and RET.
    // Port of erts/emulator/beam/jit/x86/instr_bs.cpp:2801-2958 (emit_read_integer),
    // OTP-29.1.1.
    fn emit_read_integer(
        &mut self,
        bin_base: Gp,
        bin_offset: Gp,
        tmp: Gp,
        flags: u64,
        bits: u64,
        dst: ArgVal,
    ) -> Result<(), AsmError> {
        let movbe = BeamAssembler::has_cpu_feature(CpuFeature::Movbe);
        let signed = flags & BSF_SIGNED != 0;
        let little = flags & BSF_LITTLE != 0;
        let a = &mut self.asm;
        let handle_unaligned = a.new_label();
        let store = a.new_label();

        a.emit(|e| e.mov_rr(tmp, bin_offset))?;
        a.emit(|e| e.shr_ri(tmp, 3))?;
        a.emit(|e| e.and_ri(bin_offset.r32(), 7))?;
        assert_eq!(bin_offset, enc::RCX);

        match bits {
            8 => {
                let address = Mem::base_index(bin_base, tmp, 0, 0, 1);
                if !signed {
                    a.emit(|e| e.movzx_rm(RETD, address))?;
                } else {
                    a.emit(|e| e.movsx_rm(RET, address))?;
                }
                a.short_jcc(CondCode::E, store)?;

                a.bind(handle_unaligned)?;
                let address = Mem::base_index(bin_base, tmp, 0, 0, 2);
                if movbe {
                    a.emit(|e| e.movbe_rm(RET.r16(), address))?;
                } else {
                    a.emit(|e| e.mov_rm(RET.r16(), address))?;
                    a.emit(|e| e.xchg_rr(enc::AL, enc::AH))?;
                }
                a.emit(|e| e.shl_rr(RETD, enc::CL))?;
                a.emit(|e| e.mov_rr(enc::AL, enc::AH))?;
                if !signed {
                    a.emit(|e| e.movzx_rr(RETD, RETB))?;
                } else {
                    a.emit(|e| e.movsx_rr(RET, RETB))?;
                }
            }
            16 => {
                let address = Mem::base_index(bin_base, tmp, 0, 0, 2);
                if little {
                    if !signed {
                        a.emit(|e| e.movzx_rm(RETD, address))?;
                    } else {
                        a.emit(|e| e.movsx_rm(RET, address))?;
                    }
                } else {
                    // Big-endian segment.
                    if movbe {
                        a.emit(|e| e.movbe_rm(RET.r16(), address))?;
                    } else {
                        a.emit(|e| e.mov_rm(RET.r16(), address))?;
                        a.emit(|e| e.xchg_rr(enc::AL, enc::AH))?;
                    }
                    if signed {
                        a.emit(|e| e.movsx_rr(RET, RET.r16()))?;
                    } else {
                        a.emit(|e| e.movzx_rr(RET, RET.r16()))?;
                    }
                }
                a.short_jcc(CondCode::E, store)?;

                a.bind(handle_unaligned)?;
                a.emit(|e| e.add_rr(bin_base, tmp))?;
                let address = dword_ptr(bin_base, -1);
                if movbe {
                    a.emit(|e| e.movbe_rm(RETD, address))?;
                } else {
                    a.emit(|e| e.mov_rm(RETD, address))?;
                    a.emit(|e| e.bswap(RETD))?;
                }
                a.emit(|e| e.shl_rr(RETD, enc::CL))?;
                a.emit(|e| e.shr_ri(RETD, 8))?;
                if little {
                    a.emit(|e| e.xchg_rr(enc::AL, enc::AH))?;
                }
                if !signed {
                    a.emit(|e| e.movzx_rr(RETD, RET.r16()))?;
                } else {
                    a.emit(|e| e.movsx_rr(RET, RET.r16()))?;
                }
            }
            32 => {
                let address = Mem::base_index(bin_base, tmp, 0, 0, 4);
                if little {
                    // Little-endian segment.
                    if !signed {
                        a.emit(|e| e.mov_rm(RETD, address))?;
                    } else {
                        a.emit(|e| e.movsxd_rm(RET, address))?;
                    }
                } else {
                    // Big-endian segment.
                    if movbe {
                        a.emit(|e| e.movbe_rm(RETD, address))?;
                    } else {
                        a.emit(|e| e.mov_rm(RETD, address))?;
                        a.emit(|e| e.bswap(RETD))?;
                    }
                    if signed {
                        a.emit(|e| e.movsxd_rr(RET, RETD))?;
                    }
                }
                a.short_jcc(CondCode::E, store)?;

                a.bind(handle_unaligned)?;
                a.emit(|e| e.add_rr(bin_base, tmp))?;
                let address = qword_ptr(bin_base, -3);
                if movbe {
                    a.emit(|e| e.movbe_rm(RET, address))?;
                } else {
                    a.emit(|e| e.mov_rm(RET, address))?;
                    a.emit(|e| e.bswap(RET))?;
                }
                a.emit(|e| e.shl_rr(RET, enc::CL))?;
                a.emit(|e| e.shr_ri(RET, 8))?;
                if little {
                    a.emit(|e| e.bswap(RETD))?;
                }
                if !signed {
                    a.emit(|e| e.mov_rr(RETD, RETD))?;
                } else {
                    a.emit(|e| e.movsxd_rr(RET, RETD))?;
                }
            }
            _ => return Err(AsmError::Operand("read integer of an uncommon size")),
        }

        a.bind(store)?;
        a.emit(|e| e.shl_ri(RET, TAG_IMMED1_SIZE))?;
        a.emit(|e| e.or_ri(RET, TAG_IMMED1_SMALL))?;
        self.mov_arg_from_reg(dst, RET)
    }

    /// Extracts the integer in the most significant `bits` of `bitdata` into `dst`, as a
    /// small or a one-word bignum on the heap.
    // Port of erts/emulator/beam/jit/x86/instr_bs.cpp:2960-3086 (emit_extract_integer),
    // OTP-29.1.1.
    fn emit_extract_integer(
        &mut self,
        bitdata: Gp,
        tmp: Gp,
        flags: u64,
        bits: u64,
        dst: ArgVal,
    ) -> Result<(), AsmError> {
        if bits == 0 {
            // Needed for correctness when matching a zero-size signed segment.
            return self.mov_arg_word(dst, make_small(0) as u64, ARG1);
        }

        let mut flags = flags;
        let a = &mut self.asm;
        let big = a.new_label();
        let done = a.new_label();
        let num_partial = bits % 8;
        let num_complete = 8 * (bits / 8);

        if bits <= 8 {
            // Endianness does not matter for values that fit in a byte.
            flags &= !BSF_LITTLE;
        }
        let signed = flags & BSF_SIGNED != 0;

        if flags & BSF_LITTLE == 0 {
            // Big-endian segment.
            a.emit(|e| e.mov_rr(RET, bitdata))?;
        } else if num_partial == 0 {
            // Reverse the endianness of this little-endian segment.
            a.emit(|e| e.mov_rr(RET, bitdata))?;
            a.emit(|e| e.bswap(RET))?;
            if bits < 64 {
                a.emit(|e| e.shl_ri(RET, (64 - num_complete) as i64))?;
            }
        } else {
            let shifted_mask = ((1i64 << num_partial) - 1) << (8 - num_partial);
            a.emit(|e| e.mov_rr(tmp, bitdata))?;
            a.emit(|e| e.shr_ri(tmp, (64 - num_complete) as i64))?;
            a.emit(|e| e.bswap(tmp))?;
            a.emit(|e| e.shr_ri(tmp, num_partial as i64))?;

            a.emit(|e| e.mov_rr(RET, bitdata))?;
            a.emit(|e| e.rol_ri(RET, (num_complete + 8) as i64))?;
            a.emit(|e| e.and_ri(RETD, shifted_mask))?;
            a.emit(|e| e.ror_ri(RET, 8))?;
            a.emit(|e| e.or_rr(RET, tmp))?;
        }

        // The extracted data is in RET.
        if bits >= SMALL_BITS {
            // The value might not fit in a small.
            let small = a.new_label();
            if bits < 64 {
                if !signed {
                    a.emit(|e| e.shr_ri(RET, (64 - bits) as i64))?;
                } else {
                    a.emit(|e| e.sar_ri(RET, (64 - bits) as i64))?;
                }
            }
            a.emit(|e| e.mov_rr(tmp, RET))?;
            a.emit(|e| e.shr_ri(tmp, (SMALL_BITS - 1) as i64))?;
            if !signed {
                a.jcc(CondCode::NE, big)?;
            } else {
                a.jcc(CondCode::E, small)?;
                a.emit(|e| e.cmp_ri(tmp.r32(), (TAG_IMMED1_MASK << 1) | 1))?;
                a.jcc(CondCode::NE, big)?;
            }

            a.bind(small)?;
            a.emit(|e| e.shl_ri(RET, TAG_IMMED1_SIZE))?;
            a.emit(|e| e.or_ri(RET, TAG_IMMED1_SMALL))?;
            a.short_jmp(done)?;
        } else {
            // This segment always fits in a small.
            let count = (64 - bits) as i64 - TAG_IMMED1_SIZE;
            if !signed {
                a.emit(|e| e.shr_ri(RET, count))?;
            } else {
                a.emit(|e| e.sar_ri(RET, count))?;
            }
            const { assert!(TAG_IMMED1_SMALL == (1 << TAG_IMMED1_SIZE) - 1) };
            a.emit(|e| e.or_ri(RET, TAG_IMMED1_SMALL))?;
        }

        a.bind(big)?;
        if bits >= SMALL_BITS {
            let pos_big_header = make_header(1, POS_BIG_SUBTAG as u64) as i64;
            let neg_big_header = make_header(1, NEG_BIG_SUBTAG as u64) as i64;
            if !signed {
                a.emit(|e| e.mov_mi(qword_ptr(HTOP, 0), pos_big_header))?;
                a.emit(|e| e.mov_mr(qword_ptr(HTOP, 8), RET))?;
            } else {
                let negative = a.new_label();
                let sign_done = a.new_label();
                a.emit(|e| e.test_rr(RET, RET))?;
                a.short_jcc(CondCode::L, negative)?;

                a.emit(|e| e.mov_mi(qword_ptr(HTOP, 0), pos_big_header))?;
                a.short_jmp(sign_done)?;

                a.bind(negative)?;
                a.emit(|e| e.mov_mi(qword_ptr(HTOP, 0), neg_big_header))?;
                a.emit(|e| e.neg_r(RET))?;

                a.bind(sign_done)?;
                a.emit(|e| e.mov_mr(qword_ptr(HTOP, 8), RET))?;
            }
            a.emit(|e| e.lea(RET, qword_ptr(HTOP, i32::from(TAG_PRIMARY_BOXED))))?;
            a.emit(|e| e.add_ri(HTOP, 16))?;
        }

        a.bind(done)?;
        self.mov_arg_from_reg(dst, RET)
    }

    /// Builds a heap bitstring of the most significant `bits` of `bitdata`. Clobbers RET.
    // Port of erts/emulator/beam/jit/x86/instr_bs.cpp:3088-3106 (emit_extract_bitstring),
    // OTP-29.1.1.
    fn emit_extract_bitstring(
        &mut self,
        bitdata: Gp,
        bits: u64,
        dst: ArgVal,
    ) -> Result<(), AsmError> {
        self.asm
            .emit(|e| e.lea(RET, qword_ptr(HTOP, i32::from(TAG_PRIMARY_BOXED))))?;
        self.mov_arg_from_reg(dst, RET)?;

        let a = &mut self.asm;
        let header = header_heap_bits(bits);
        a.emit(|e| e.mov_mi(qword_ptr(HTOP, 0), header))?;
        a.emit(|e| e.mov_mi(qword_ptr(HTOP, 8), bits as i64))?;
        if bits > 0 {
            a.emit(|e| e.mov_rr(RET, bitdata))?;
            a.emit(|e| e.bswap(RET))?;
            a.emit(|e| e.mov_mr(qword_ptr(HTOP, 16), RET))?;
            a.emit(|e| e.add_ri(HTOP, 24))
        } else {
            a.emit(|e| e.add_ri(HTOP, 16))
        }
    }

    /// `i_bs_match Fail Ctx {commands}`.
    // Port of erts/emulator/beam/jit/x86/instr_bs.cpp:3108-3112 (emit_i_bs_match), OTP-29.1.1.
    pub fn emit_i_bs_match(
        &mut self,
        fail: ArgVal,
        ctx: ArgVal,
        list: &[ArgVal],
    ) -> Result<(), AsmError> {
        self.emit_i_bs_match_test_heap(fail, ctx, ArgVal::Word(0), ArgVal::Word(0), list)
    }

    /// `i_bs_match_test_heap Fail Ctx Need Live {commands}`: the segments of a binary match,
    /// planned by `beam_jit_bsm_init` and `beam_jit_opt_bsm_segments`.
    // Port of erts/emulator/beam/jit/x86/instr_bs.cpp:3114-3446 (emit_i_bs_match_test_heap),
    // OTP-29.1.1.
    pub fn emit_i_bs_match_test_heap(
        &mut self,
        fail: ArgVal,
        ctx_arg: ArgVal,
        need: ArgVal,
        live: ArgVal,
        list: &[ArgVal],
    ) -> Result<(), AsmError> {
        let fail = arg_label(fail)?;
        let need = arg_word(need)?;
        let live = arg_word(live)?;
        let segments = beam_jit_bsm_init(list).map_err(AsmError::Operand)?;
        let segments = opt_bsm_segments(&segments, need, live as u32);

        // bin_position must be RCX: only CL can be a variable shift count without BMI2's SHLX.
        let bin_position = ARG4;
        let bitdata = ARG3;
        let bin_base = ARG1;
        let ctx = ARG2;
        assert_eq!(bin_position, enc::RCX);
        let tmp = ARG5;

        let mut is_ctx_valid = false;
        let mut is_position_valid = false;
        let count = segments.len();

        for i in 0..count {
            let seg = segments[i];
            // Whether the next sub instruction clobbers registers or this is the last one.
            let next_instr_clobbers =
                i == count - 1 || (i < count - 1 && segments[i + 1].action == Action::TestHeap);

            match seg.action {
                Action::EnsureAtLeast => {
                    let size = seg.size;
                    let unit = seg.unit;
                    let fail_label = self.beam_label(fail)?;
                    self.mov_arg_to_reg(ctx, ctx_arg)?;
                    if unit == 1 {
                        self.asm
                            .emit(|e| e.mov_rm(bin_position, boxed(ctx, SUB_BITS_START)))?;
                        self.asm
                            .emit(|e| e.lea(RET, qword_ptr(bin_position, size as i32)))?;
                        self.asm.emit(|e| e.cmp_rm(RET, boxed(ctx, SUB_BITS_END)))?;
                        self.asm.jcc(CondCode::A, fail_label)?;
                    } else if size == 0 && next_instr_clobbers {
                        self.asm.emit(|e| e.mov_rm(RET, boxed(ctx, SUB_BITS_END)))?;
                        self.asm
                            .emit(|e| e.sub_rm(RET, boxed(ctx, SUB_BITS_START)))?;
                    } else {
                        self.asm.emit(|e| e.mov_rm(RET, boxed(ctx, SUB_BITS_END)))?;
                        self.asm
                            .emit(|e| e.mov_rm(bin_position, boxed(ctx, SUB_BITS_START)))?;
                        self.asm.emit(|e| e.sub_rr(RET, bin_position))?;
                        self.cmp(RET, size as i64, tmp)?;
                        self.asm.jcc(CondCode::L, fail_label)?;
                    }

                    is_ctx_valid = true;
                    is_position_valid = true;

                    if unit != 1 {
                        if !size.is_multiple_of(unit) {
                            self.sub(RET, size as i64, tmp)?;
                        }
                        if unit & (unit - 1) != 0 {
                            // Clobbers ARG3.
                            self.asm.emit(|e| e.cqo())?;
                            self.asm.mov_imm(tmp, unit)?;
                            self.asm.emit(|e| e.div_r(tmp))?;
                            self.asm.emit(|e| e.test_rr(enc::RDX, enc::RDX))?;
                            is_ctx_valid = false;
                            is_position_valid = false;
                        } else {
                            self.asm.emit(|e| e.test_ri(RETB, (unit - 1) as i64))?;
                        }
                        self.asm.jcc(CondCode::NE, fail_label)?;
                    }
                }
                Action::EnsureExactly => {
                    let size = seg.size;
                    self.mov_arg_to_reg(ctx, ctx_arg)?;
                    self.asm.emit(|e| e.mov_rm(RET, boxed(ctx, SUB_BITS_END)))?;
                    if next_instr_clobbers {
                        self.asm
                            .emit(|e| e.sub_rm(RET, boxed(ctx, SUB_BITS_START)))?;
                        is_ctx_valid = false;
                        is_position_valid = false;
                    } else {
                        self.asm
                            .emit(|e| e.mov_rm(bin_position, boxed(ctx, SUB_BITS_START)))?;
                        self.asm.emit(|e| e.sub_rr(RET, bin_position))?;
                        is_ctx_valid = true;
                        is_position_valid = true;
                    }
                    if size != 0 {
                        self.cmp(RET, size as i64, tmp)?;
                    }
                    let fail_label = self.beam_label(fail)?;
                    self.asm.jcc(CondCode::NE, fail_label)?;
                }
                Action::Eq => {
                    let bits = seg.size;
                    let extract_reg = if next_instr_clobbers {
                        bitdata
                    } else {
                        self.asm.emit(|e| e.mov_rr(RET, bitdata))?;
                        RET
                    };
                    if bits != 0 && bits != 64 {
                        self.asm
                            .emit(|e| e.shr_ri(extract_reg, (64 - bits) as i64))?;
                    }
                    if seg.size <= 32 {
                        self.cmp(extract_reg.r32(), seg.unit as i64, tmp)?;
                    } else {
                        self.cmp(extract_reg, seg.unit as i64, tmp)?;
                    }
                    let fail_label = self.beam_label(fail)?;
                    self.asm.jcc(CondCode::NE, fail_label)?;
                    if !next_instr_clobbers && bits != 0 && bits != 64 {
                        self.asm.emit(|e| e.shl_ri(bitdata, bits as i64))?;
                    }
                    // bin_position is clobbered.
                    is_position_valid = false;
                }
                Action::TestHeap => {
                    let live = seg
                        .live
                        .ok_or(AsmError::Operand("test_heap segment without live"))?;
                    self.emit_gc_test(0, seg.size, u64::from(live))?;
                    is_ctx_valid = false;
                    is_position_valid = false;
                }
                Action::Read => {
                    if seg.size != 0 {
                        if !is_ctx_valid {
                            self.mov_arg_to_reg(ctx, ctx_arg)?;
                            is_ctx_valid = true;
                        }
                        // erts marks the position valid here; this action invalidates it.
                        if !is_position_valid {
                            self.asm
                                .emit(|e| e.mov_rm(bin_position, boxed(ctx, SUB_BITS_START)))?;
                        }
                        self.asm
                            .emit(|e| e.mov_rm(bin_base, boxed(ctx, SUB_BITS_BASE_FLAGS)))?;
                        self.asm
                            .emit(|e| e.and_ri(bin_base, !ERL_SUB_BITS_FLAG_MASK))?;
                        self.asm
                            .emit(|e| e.add_mi(boxed(ctx, SUB_BITS_START), seg.size as i64))?;
                        self.emit_read_bits(seg.size, bin_base, bin_position, bitdata)?;
                    }
                    is_position_valid = false;
                }
                Action::ExtractBitstring => {
                    let bits = seg.size;
                    let dst = seg.dst.ok_or(AsmError::Operand("segment without dst"))?;
                    self.emit_extract_bitstring(bitdata, bits, dst)?;
                    if !next_instr_clobbers && bits != 0 && bits != 64 {
                        self.asm.emit(|e| e.shl_ri(bitdata, bits as i64))?;
                    }
                }
                Action::ExtractInteger => {
                    let bits = seg.size;
                    let flags = seg.flags;
                    let dst = seg.dst.ok_or(AsmError::Operand("segment without dst"))?;
                    if next_instr_clobbers && flags == 0 && bits < SMALL_BITS {
                        self.asm
                            .emit(|e| e.shr_ri(bitdata, (64 - bits) as i64 - TAG_IMMED1_SIZE))?;
                        self.asm.emit(|e| e.or_ri(bitdata, TAG_IMMED1_SMALL))?;
                        self.mov_arg_from_reg(dst, bitdata)?;
                    } else {
                        self.emit_extract_integer(bitdata, tmp, flags, bits, dst)?;
                        if !next_instr_clobbers && bits != 0 && bits != 64 {
                            self.asm.emit(|e| e.shl_ri(bitdata, bits as i64))?;
                        }
                    }
                    // bin_position is clobbered.
                    is_position_valid = false;
                }
                Action::ReadInteger => {
                    let dst = seg.dst.ok_or(AsmError::Operand("segment without dst"))?;
                    if !is_ctx_valid {
                        self.mov_arg_to_reg(ctx, ctx_arg)?;
                        is_ctx_valid = true;
                    }
                    // erts marks the position valid here; this action invalidates it.
                    if !is_position_valid {
                        self.asm
                            .emit(|e| e.mov_rm(bin_position, boxed(ctx, SUB_BITS_START)))?;
                    }
                    self.asm
                        .emit(|e| e.mov_rm(bin_base, boxed(ctx, SUB_BITS_BASE_FLAGS)))?;
                    self.asm
                        .emit(|e| e.and_ri(bin_base, !ERL_SUB_BITS_FLAG_MASK))?;
                    self.asm
                        .emit(|e| e.add_mi(boxed(ctx, SUB_BITS_START), seg.size as i64))?;
                    self.emit_read_integer(bin_base, bin_position, tmp, seg.flags, seg.size, dst)?;
                    is_position_valid = false;
                }
                Action::GetInteger => {
                    // Integer segments of more than 64 bits.
                    let dst = seg.dst.ok_or(AsmError::Operand("segment without dst"))?;
                    if !is_ctx_valid {
                        self.mov_arg_to_reg(ARG4, ctx_arg)?;
                    } else if ctx != ARG4 {
                        self.asm.emit(|e| e.mov_rr(ARG4, ctx))?;
                    }
                    let spec = Update::REDUCTIONS.union(Update::HEAP_ONLY_ALLOC);
                    let a = &mut self.asm;
                    a.emit_enter_runtime(spec)?;
                    a.emit(|e| e.mov_rr(ARG1, C_P))?;
                    a.emit(|e| e.mov_ri(ARG2, seg.size as i64))?;
                    a.emit(|e| e.mov_ri(ARG3, seg.flags as i64))?;
                    a.emit(|e| e.sub_ri(ARG4, i64::from(TAG_PRIMARY_BOXED)))?;
                    a.runtime_call(erts_bs_get_integer_2 as *const () as usize)?;
                    a.emit_leave_runtime(spec)?;
                    self.mov_arg_from_reg(dst, RET)?;
                    is_ctx_valid = false;
                    is_position_valid = false;
                }
                Action::GetBitstring => {
                    assert!(seg.size > 64);
                    let dst = seg.dst.ok_or(AsmError::Operand("segment without dst"))?;
                    if is_ctx_valid {
                        self.asm.emit(|e| e.mov_rr(RET, ctx))?;
                    } else {
                        self.mov_arg_to_reg(RET, ctx_arg)?;
                    }
                    let a = &mut self.asm;
                    a.emit_enter_runtime(Update::HEAP_ONLY_ALLOC)?;
                    a.emit(|e| e.mov_rm(ARG5, boxed(RET, SUB_BITS_START)))?;
                    a.emit(|e| e.lea(ARG1, qword_ptr(C_P, process::HTOP)))?;
                    if seg.size > ERL_ONHEAP_BITS_LIMIT {
                        a.emit(|e| e.mov_rm(ARG2, boxed(RET, SUB_BITS_ORIG)))?;
                        a.emit(|e| e.mov_rr(ARG3, ARG2))?;
                        a.emit(|e| e.and_ri(ARG2, TAG_PTR_MASK))?;
                        a.emit(|e| e.and_ri(ARG3, !TAG_PTR_MASK))?;
                    }
                    a.emit(|e| e.mov_rm(ARG4, boxed(RET, SUB_BITS_BASE_FLAGS)))?;
                    a.emit(|e| e.and_ri(ARG4, !ERL_SUB_BITS_FLAG_MASK))?;
                    a.mov_imm(ARG6, seg.size)?;
                    a.emit(|e| e.add_mr(boxed(RET, SUB_BITS_START), ARG6))?;
                    a.runtime_call(erts_build_sub_bitstring as *const () as usize)?;
                    a.emit_leave_runtime(Update::HEAP_ONLY_ALLOC)?;
                    self.mov_arg_from_reg(dst, RET)?;
                    is_ctx_valid = false;
                    is_position_valid = false;
                }
                Action::GetTail => {
                    let dst = seg.dst.ok_or(AsmError::Operand("segment without dst"))?;
                    if is_ctx_valid {
                        self.asm.emit(|e| e.mov_rr(ARG1, ctx))?;
                    } else {
                        self.mov_arg_to_reg(ARG1, ctx_arg)?;
                    }
                    self.safe_fragment_call_ga(GlobalLabels::BsGetTailShared)?;
                    self.mov_arg_from_reg(dst, RET)?;
                    is_ctx_valid = false;
                    is_position_valid = false;
                }
                Action::Skip => {
                    if !is_ctx_valid {
                        self.mov_arg_to_reg(ctx, ctx_arg)?;
                        is_ctx_valid = true;
                    }
                    // The compiler limits the size of any segment of a bs_match to 24 bits.
                    assert_eq!(seg.size >> 24, 0);
                    self.asm
                        .emit(|e| e.add_mi(boxed(ctx, SUB_BITS_START), seg.size as i64))?;
                    is_position_valid = false;
                }
                Action::Drop => {
                    let bits = seg.size;
                    if bits != 0 && bits != 64 {
                        self.asm.emit(|e| e.shl_ri(bitdata, bits as i64))?;
                    }
                }
            }
        }
        Ok(())
    }
}

impl BeamGlobalAssembler {
    /// Sets the error reason of a failed size check.
    // Port of erts/emulator/beam/jit/x86/instr_bs.cpp:128-136 (emit_bs_size_check_shared),
    // OTP-29.1.1.
    pub(crate) fn emit_bs_size_check_shared(&mut self) -> Result<(), AsmError> {
        let a = &mut self.asm;
        a.emit_enter_runtime(Update::NONE)?;
        a.emit(|e| e.mov_rr(ARG1, C_P))?;
        a.runtime_call(beam_jit_bs_field_size_argument_error as *const () as usize)?;
        a.emit_leave_runtime(Update::NONE)?;
        a.emit(|e| e.ret())
    }

    /// The rest of the match context in ARG1 as a sub-bitstring in RET.
    // Port of erts/emulator/beam/jit/x86/instr_bs.cpp:424-454 (emit_bs_get_tail_shared),
    // OTP-29.1.1.
    pub(crate) fn emit_bs_get_tail_shared(&mut self) -> Result<(), AsmError> {
        let a = &mut self.asm;
        a.emit_enter_runtime(Update::HEAP_ONLY_ALLOC)?;

        a.emit(|e| e.mov_rm(ARG2, boxed(ARG1, SUB_BITS_ORIG)))?;
        a.emit(|e| e.mov_rr(ARG3, ARG2))?;
        // ARG2 = tag bits of mb.orig, ARG3 = mb.orig without tag bits.
        a.emit(|e| e.and_ri(ARG2, TAG_PTR_MASK))?;
        a.emit(|e| e.and_ri(ARG3, !TAG_PTR_MASK))?;

        a.emit(|e| e.mov_rm(ARG4, boxed(ARG1, SUB_BITS_BASE_FLAGS)))?;
        a.emit(|e| e.and_ri(ARG4, !ERL_SUB_BITS_FLAG_MASK))?;
        a.emit(|e| e.mov_rm(ARG5, boxed(ARG1, SUB_BITS_START)))?;

        // Extracted size = end - start.
        a.emit(|e| e.mov_rm(ARG6, boxed(ARG1, SUB_BITS_END)))?;
        a.emit(|e| e.sub_rr(ARG6, ARG5))?;

        a.emit(|e| e.lea(ARG1, qword_ptr(C_P, process::HTOP)))?;
        a.runtime_call(erts_build_sub_bitstring as *const () as usize)?;
        a.emit_leave_runtime(Update::HEAP_ONLY_ALLOC)?;
        a.emit(|e| e.ret())
    }

    /// Decodes a multi-byte UTF-8 code point with PEXT/SHRX: ARG1 the match state, ARG2 the
    /// bit position, RETd four big-endian bytes. On success the code point is a small in RET,
    /// the position is advanced and ZF is clear; on failure ZF is set.
    // Port of erts/emulator/beam/jit/x86/instr_bs.cpp:744-905 (emit_bs_get_utf8_shared),
    // OTP-29.1.1.
    pub(crate) fn emit_bs_get_utf8_shared(&mut self) -> Result<(), AsmError> {
        let a = &mut self.asm;
        let error = a.new_label();

        let (shift_q, shift_d, shift_b) = (ARG4, ARG4D, ARG4.r8());
        let original_value_d = RETD;
        let (byte_count_q, byte_count_d) = (ARG2, ARG2D);
        let (extracted_value_d, extracted_value_b) = (ARG3D, ARG3.r8());
        let control_mask_d = ARG5D;
        let error_mask_d = ARG6D;

        // UTF-8: the number of leading one bits of the first byte is the number of bytes,
        // which gives the masks for extraction and error checking.
        //
        // The PEXT mask covers the data bits of every variant, including the 23rd bit for the
        // 2-byte case, set on every well-formed 4-byte code point; it is cleared before the
        // range tests.
        a.emit(|e| e.mov_ri(extracted_value_d, 0x1F3F3F3F))?;
        a.emit(|e| e.pext_rrr(extracted_value_d, original_value_d, extracted_value_d))?;

        // Preserve the match buffer and bit offset.
        a.emit(|e| e.push_r(ARG1))?;
        a.emit(|e| e.push_r(ARG2))?;

        // Byte count = leading bit count.
        a.emit(|e| e.mov_rr(byte_count_d, original_value_d))?;
        a.emit(|e| e.not_r(byte_count_d))?;
        a.emit(|e| e.lzcnt_rr(byte_count_d, byte_count_d))?;

        // Mask shift = (4 - byte count) * 8
        a.emit(|e| e.mov_ri(shift_d, 4))?;
        a.emit(|e| e.sub_rr(shift_d, byte_count_d))?;
        a.emit(|e| e.lea(shift_d, index_ptr(shift_q, 3)))?;

        // Shift the original value and masks into place.
        a.emit(|e| e.shrx_rrr(original_value_d, original_value_d, shift_d))?;

        // Matches the '10xxxxxx' components, leaving the header byte alone.
        a.emit(|e| e.mov_ri(control_mask_d, 0x00C0C0C0))?;
        a.emit(|e| e.shrx_rrr(control_mask_d, control_mask_d, shift_d))?;
        a.emit(|e| e.mov_ri(error_mask_d, 0x00808080))?;
        a.emit(|e| e.shrx_rrr(error_mask_d, error_mask_d, shift_d))?;

        // Extracted value shift = (4 - byte count) * 6, computed now as byte_count_d may
        // change later.
        a.emit(|e| e.mov_ri(shift_d, 4))?;
        a.emit(|e| e.sub_rr(shift_d, byte_count_d))?;
        a.emit(|e| e.add_rr(shift_d, shift_d))?;
        a.emit(|e| e.lea(shift_d, Mem::base_index(shift_q, shift_q, 1, 0, 8)))?;

        // Check the header bits of each '10xxxxxx' component; errors trash the byte count
        // with a guaranteed-illegal value.
        a.emit(|e| e.and_rr(original_value_d, control_mask_d))?;
        a.emit(|e| e.cmp_rr(original_value_d, error_mask_d))?;
        a.emit(|e| e.cmovcc_rr(CondCode::NE, byte_count_d, error_mask_d))?;

        // Shift the extracted value into place.
        a.emit(|e| e.shrx_rrr(RETD, extracted_value_d, shift_d))?;

        // The extraction mask is a bit too wide, see above.
        a.emit(|e| e.and_ri(RETD, !(1 << 22)))?;

        // Too large code point.
        a.emit(|e| e.cmp_ri(RETD, 0x10FFFF))?;
        a.emit(|e| e.cmovcc_rr(CondCode::A, byte_count_d, error_mask_d))?;

        // The illegal range 16#D800 - 16#DFFF.
        a.emit(|e| e.mov_rr(shift_d, RETD))?;
        a.emit(|e| e.and_ri(shift_d, -0x800))?;
        a.emit(|e| e.cmp_ri(shift_d, 0xD800))?;
        a.emit(|e| e.cmovcc_rr(CondCode::E, byte_count_d, error_mask_d))?;

        // Overlong sequences: the 'y' bits must be zero; they are isolated by shifting down
        // byte_count * 4 - 1 bits (2 and 3 bytes) or byte_count * 4 bits (4 bytes).
        a.emit(|e| e.lea(shift_d, index_ptr(byte_count_q, 2)))?;
        a.emit(|e| e.cmp_ri(byte_count_d, 4))?;
        a.emit(|e| e.setcc_r(CondCode::NE, extracted_value_b))?;
        a.emit(|e| e.sub_rr(shift_b, extracted_value_b))?;
        a.emit(|e| e.movzx_rr(shift_q, shift_b))?;

        // Isolate the y bits and compare to zero.
        a.emit(|e| e.shrx_rrr(extracted_value_d, RETD, shift_d))?;
        a.emit(|e| e.test_rr(extracted_value_d, extracted_value_d))?;
        a.emit(|e| e.cmovcc_rr(CondCode::E, byte_count_d, error_mask_d))?;

        // Restore the bit offset and match buffer.
        a.emit(|e| e.pop_r(ARG3))?;
        a.emit(|e| e.pop_r(ARG1))?;

        // Advance the position.
        a.emit(|e| e.lea(ARG3, Mem::base_index(ARG3, byte_count_q, 3, 0, 8)))?;

        // Byte count must be 2, 3, or 4.
        a.emit(|e| e.sub_ri(byte_count_d, 2))?;
        a.emit(|e| e.cmp_ri(byte_count_d, 2))?;
        a.jcc(CondCode::A, error)?;

        a.emit(|e| e.mov_mr(qword_ptr(ARG1, SUB_BITS_START), ARG3))?;

        a.emit(|e| e.shl_ri(RETD, TAG_IMMED1_SIZE))?;
        a.emit(|e| e.or_ri(RETD, TAG_IMMED1_SMALL))?; // Always clears ZF.
        a.emit(|e| e.ret())?;

        a.bind(error)?;
        // Signal the error by setting ZF.
        a.emit(|e| e.xor_rr(RET, RET))?;
        a.emit(|e| e.ret())
    }

    /// The error of a failed `bs_create_bin` segment: ARG1/ARG3 the optional bad values,
    /// ARG4 the packed error information.
    // Port of erts/emulator/beam/jit/x86/instr_bs.cpp:1080-1112
    // (emit_bs_create_bin_error_shared), OTP-29.1.1.
    pub(crate) fn emit_bs_create_bin_error_shared(&mut self) -> Result<(), AsmError> {
        let raise_exception_shared = self.label(GlobalLabels::RaiseExceptionShared);
        let a = &mut self.asm;
        a.emit_enter_runtime(Update::HEAP_ALLOC)?;
        // ARG3 is already set by the caller.
        a.emit(|e| e.mov_rr(ARG2, ARG4))?;
        a.emit(|e| e.mov_rr(ARG4, ARG1))?;
        a.emit(|e| e.mov_rr(ARG1, C_P))?;
        a.runtime_call(beam_jit_bs_construct_fail_info as *const () as usize)?;
        a.emit_leave_runtime(Update::HEAP_ALLOC)?;

        // Align the return address to a proper tagged CP, in case we were called with
        // `safe_fragment_call`; we never return to it.
        a.emit(|e| e.pop_r(ARG2))?;
        a.emit(|e| e.and_ri(ARG2, -8))?;
        // NATIVE_ERLANG_STACK with the RA frame layout: the CP is the whole frame.
        a.emit(|e| e.push_r(ARG2))?;

        a.mov_imm(ARG4, 0)?;
        a.jmp(raise_exception_shared)
    }

    /// The 64 least significant bits of the bignum in ARG1 (ZF clear), or ZF set when ARG1
    /// is not a bignum.
    // Port of erts/emulator/beam/jit/x86/instr_bs.cpp:1114-1154 (emit_get_sint64_shared),
    // OTP-29.1.1.
    pub(crate) fn emit_get_sint64_shared(&mut self) -> Result<(), AsmError> {
        let a = &mut self.asm;
        let success = a.new_label();
        let fail = a.new_label();

        a.emit_is_boxed(fail, ARG1, Distance::Long)?;
        let boxed_ptr = a.emit_ptr_val(ARG4, ARG1);
        a.emit(|e| e.mov_rm(ARG2, boxed(boxed_ptr, 0)))?;
        a.emit(|e| e.mov_rm(ARG3, boxed(boxed_ptr, 8)))?;
        a.emit(|e| e.and_ri(ARG2, TAG_HEADER_MASK))?;
        a.emit(|e| e.cmp_ri(ARG2, POS_BIG_SUBTAG))?;
        a.jcc(CondCode::E, success)?;

        a.emit(|e| e.cmp_ri(ARG2, NEG_BIG_SUBTAG))?;
        a.jcc(CondCode::NE, fail)?;

        a.emit(|e| e.neg_r(ARG3))?;

        a.bind(success)?;
        a.emit(|e| e.mov_rr(ARG1, ARG3))?;
        // Clear ZF: ARG2 is POS_BIG_SUBTAG or NEG_BIG_SUBTAG, both non-zero.
        const { assert!(POS_BIG_SUBTAG != 0 && NEG_BIG_SUBTAG != 0) };
        a.emit(|e| e.test_rr(ARG2, ARG2))?;
        a.emit(|e| e.ret())?;

        a.bind(fail)?;
        a.emit(|e| e.xor_rr(ARG2, ARG2))?; // Set ZF.
        a.emit(|e| e.ret())
    }

    /// Encodes the code point (>= 0x80) in ARG3 as UTF-8 in ARG3d, its size in bits (16, 24
    /// or 32) in ARG2. Clobbers RET and the other ARG registers.
    // Port of erts/emulator/beam/jit/x86/instr_bs.cpp:1341-1417 (emit_construct_utf8_shared),
    // OTP-29.1.1.
    pub(crate) fn emit_construct_utf8_shared(&mut self) -> Result<(), AsmError> {
        let a = &mut self.asm;
        let more_than_two_bytes = a.new_label();
        let four_bytes = a.new_label();
        let (tmp1, tmp2, value, num_bits) = (ARG1, ARG2, ARG3, ARG2);

        a.emit(|e| e.mov_rr(RETD, value.r32()))?;
        a.emit(|e| e.and_ri(RETD, 0x3f))?;

        a.emit(|e| e.cmp_ri(value.r32(), 0x800))?;
        a.jcc(CondCode::AE, more_than_two_bytes)?;

        a.emit(|e| e.shl_ri(RETD, 8))?;
        a.emit(|e| e.shr_ri(value, 6))?;
        a.emit(|e| e.or_rr(value.r32(), RETD))?;
        a.emit(|e| e.or_ri(value.r32(), 0x80c0))?;
        a.mov_imm(num_bits, 16)?;
        a.emit(|e| e.ret())?;

        // Whether the value is encoded in four bytes.
        a.bind(more_than_two_bytes)?;
        a.emit(|e| e.cmp_ri(value.r32(), 0x10000))?;
        a.jcc(CondCode::AE, four_bytes)?;

        // Three bytes.
        a.emit(|e| e.shl_ri(RETD, 16))?;
        let scaled = Mem {
            size: 0,
            ..index_ptr(ARG3, 2)
        };
        a.emit(|e| e.lea(tmp1.r32(), scaled))?;
        a.emit(|e| e.and_ri(tmp1.r32(), 0x3f00))?;
        a.emit(|e| e.shr_ri(value.r32(), 12))?;
        a.emit(|e| e.or_rr(value.r32(), tmp1.r32()))?;
        a.emit(|e| e.or_rr(value.r32(), RETD))?;
        a.emit(|e| e.or_ri(value.r32(), 0x8080e0))?;
        a.mov_imm(num_bits, 24)?;
        a.emit(|e| e.ret())?;

        // Four bytes.
        a.bind(four_bytes)?;
        a.emit(|e| e.shl_ri(RETD, 24))?;
        a.emit(|e| e.mov_rr(tmp1.r32(), value.r32()))?;
        a.emit(|e| e.shl_ri(tmp1.r32(), 10))?;
        a.emit(|e| e.and_ri(tmp1.r32(), 0x3f0000))?;
        a.emit(|e| e.mov_rr(tmp2.r32(), value.r32()))?;
        a.emit(|e| e.shr_ri(tmp2.r32(), 4))?;
        a.emit(|e| e.and_ri(tmp2.r32(), 0x3f00))?;
        a.emit(|e| e.shr_ri(value.r32(), 18))?;
        a.emit(|e| e.or_rr(value.r32(), RETD))?;
        a.emit(|e| e.or_rr(value.r32(), tmp1.r32()))?;
        a.emit(|e| e.or_rr(value.r32(), tmp2.r32()))?;
        a.emit(|e| e.or_ri(value.r32(), 0xffffffff808080f0_u64 as i64))?;
        a.mov_imm(num_bits, 32)?;
        a.emit(|e| e.ret())
    }

    /// Stores ARG4 bits of ARG5 at the bit offset ARG3 of the byte ARG1 points at.
    // Port of erts/emulator/beam/jit/x86/instr_bs.cpp:1522-1576 (emit_store_unaligned),
    // OTP-29.1.1.
    pub(crate) fn emit_store_unaligned(&mut self) -> Result<(), AsmError> {
        let a = &mut self.asm;
        let looop = a.new_label();
        let done = a.new_label();
        let bin_ptr = ARG1;
        let left_bit_offset = ARG3;
        let right_bit_offset = ARG2;
        let num_bits = ARG4;
        let bitdata = ARG5;

        a.emit(|e| e.movzx_rm(RETD, byte_ptr(bin_ptr, 0)))?;

        a.emit(|e| e.xchg_rr(left_bit_offset, enc::RCX))?;

        a.emit(|e| e.mov_rr(right_bit_offset, bitdata))?;
        a.emit(|e| e.and_ri(right_bit_offset, 0xff))?;
        a.emit(|e| e.shr_rr(right_bit_offset, enc::CL))?;

        a.emit(|e| e.shl_rr(RETD, enc::CL))?;
        a.emit(|e| e.and_ri(RETD, !0xff))?;
        a.emit(|e| e.shr_rr(RETD, enc::CL))?;

        a.emit(|e| e.xchg_rr(left_bit_offset, enc::RCX))?;

        a.emit(|e| e.or_rr(RETD, ARG2D))?;
        a.emit(|e| e.mov_mr(byte_ptr(ARG1, 0), RETB))?;
        a.emit(|e| e.add_ri(ARG1, 1))?;

        a.mov_imm(right_bit_offset, 8)?;
        a.emit(|e| e.sub_rr(right_bit_offset, left_bit_offset))?;

        a.emit(|e| e.xchg_rr(right_bit_offset, enc::RCX))?;
        a.emit(|e| e.bswap(bitdata))?;
        a.emit(|e| e.shl_rr(bitdata, enc::CL))?;
        a.emit(|e| e.xchg_rr(right_bit_offset, enc::RCX))?;

        a.emit(|e| e.sub_rr(ARG4, right_bit_offset))?;
        a.jcc(CondCode::LE, done)?;

        a.bind(looop)?;
        a.emit(|e| e.rol_ri(bitdata, 8))?;
        a.emit(|e| e.mov_mr(byte_ptr(ARG1, 0), bitdata.r8()))?;
        a.emit(|e| e.add_ri(ARG1, 1))?;
        a.emit(|e| e.sub_ri(num_bits, 8))?;
        a.jcc(CondCode::G, looop)?;

        a.bind(done)?;
        a.emit(|e| e.ret())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::types::{ArgType, type_id};
    use crate::x86::beam_asm_global::GLOBAL_LABELS;
    use crate::x86::jdump::{beam_register, erts_to_arinsal, gnu_as};
    use arinsal_x64::buf::Section;
    use std::path::PathBuf;
    use std::process::Command;
    use std::sync::OnceLock;

    /// Modules with heavy bit syntax, loaded after boot so `+JDdump` writes their code too.
    const BS_MODULES: &str = "[binary, unicode, base64, string, erl_scan, zlib, uri_string, \
        json, unicode_util, inet_parse, beam_lib, zip, erl_tar, erl_parse, epp, calendar, \
        io_lib_format, io_lib, compile, beam_asm, beam_dict, beam_disasm, beam_ssa_codegen, \
        ssl_cipher, public_key, inet_dns, tls_record, ssh_message, ssh_bits, erl_epmd, \
        dist_util, inet_db, disk_log_1, disk_log, dets_v9, file_io_server, erl_ddll, \
        erts_debug, net_kernel, global, prim_inet, sys_core_fold, cerl, ram_file, \
        beam_validator, rand, c, observer_backend, httpd_util, asn1rt_nif]";

    /// `erl +JDdump true` of the boot modules plus [`BS_MODULES`], shared by every test
    /// process (the first one dumps into a private directory and renames it into place).
    fn dump_dir() -> Option<&'static PathBuf> {
        static DIR: OnceLock<Option<PathBuf>> = OnceLock::new();
        DIR.get_or_init(|| {
            let dir = std::env::temp_dir().join("arinsal-x86-jdump-otp29-bs");
            if dir.join("binary.asm").exists() {
                return Some(dir);
            }
            let private =
                std::env::temp_dir().join(format!("arinsal-x86-jdump-bs-{}", std::process::id()));
            std::fs::create_dir_all(&private).ok()?;
            let eval = format!("[code:ensure_loaded(M) || M <- {BS_MODULES}], halt().");
            let dumped = Command::new("erl")
                .args(["+JDdump", "true", "-noshell", "-eval", &eval])
                .current_dir(&private)
                .status()
                .is_ok_and(|status| status.success());
            if !dumped || std::fs::rename(&private, &dir).is_err() {
                let _ = std::fs::remove_dir_all(&private);
            }
            dir.join("binary.asm").exists().then_some(dir)
        })
        .as_ref()
    }

    /// Every `# <op>` block of every dumped module, comments and local labels included. A
    /// block ends at the next instruction header (`# name`, one word; `# get_tail` and
    /// `# done` are bs comments).
    fn blocks(op: &str) -> Option<Vec<Vec<String>>> {
        let dir = dump_dir()?;
        let is_header = |line: &str| {
            line.strip_prefix("# ").is_some_and(|name| {
                !name.is_empty()
                    && name != "get_tail"
                    && name != "done"
                    && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
            })
        };
        let mut blocks = Vec::new();
        let mut paths: Vec<_> = std::fs::read_dir(dir)
            .ok()?
            .flatten()
            .map(|e| e.path())
            .collect();
        paths.sort();
        for path in paths {
            let Ok(bytes) = std::fs::read(&path) else {
                continue;
            };
            let text = String::from_utf8_lossy(&bytes);
            let mut current: Option<Vec<String>> = None;
            for line in text.lines() {
                if is_header(line)
                    || line.starts_with("label_")
                    || line.ends_with(':') && !line.starts_with('L') && !line.starts_with(' ')
                {
                    blocks.extend(current.take());
                    if line == format!("# {op}") {
                        current = Some(Vec::new());
                    }
                } else if let Some(block) = current.as_mut() {
                    block.push(line.trim().to_string());
                }
            }
            blocks.extend(current);
        }
        Some(blocks)
    }

    fn instrs(block: &[String]) -> Vec<&str> {
        block
            .iter()
            .map(String::as_str)
            .filter(|l| !l.starts_with('#'))
            .collect()
    }

    /// The bytes erts emitted for `block`, or `None` for a block whose shape the byte test
    /// cannot reproduce (a short jump to a label outside the block).
    fn expected(block: &[String]) -> Option<Vec<u8>> {
        let lines = instrs(block);
        let local: Vec<&str> = lines.iter().filter_map(|l| l.strip_suffix(':')).collect();
        let mut out = Vec::new();
        for line in lines {
            let target = line.rsplit(' ').next().unwrap_or("");
            let external = (target.starts_with('L') || target.starts_with("label_"))
                && !local.contains(&target);
            if line.starts_with("short ") && external {
                return None;
            }
            if let Some(address) = line.strip_prefix("call ")
                && address.parse::<u64>().is_ok()
            {
                // runtime_call / fragment_call(ga->get_x()): `REX call rel32`, relocated.
                out.push(".byte 0x40, 0xe8, 0, 0, 0, 0".to_string());
                continue;
            }
            let mut line = erts_to_arinsal(line);
            if line.starts_with('j') && external && !line.starts_with('{') {
                line = format!("{{disp32}} {line}");
            }
            out.push(line);
        }
        gnu_as(&out)
    }

    /// The BEAM registers a block reads or writes, in order of appearance.
    fn slots(block: &[String]) -> Vec<ArgVal> {
        let mut out = Vec::new();
        for line in instrs(block) {
            for part in line.split(", ") {
                let operand = part.split_once(' ').map_or(part, |(_, rest)| {
                    if rest.starts_with("qword ptr") {
                        rest
                    } else {
                        part
                    }
                });
                if let Some(slot) = beam_register(operand)
                    && !out.contains(&slot)
                {
                    out.push(slot);
                }
            }
        }
        out
    }

    /// The `label_N` BEAM labels a block jumps to.
    fn beam_labels(block: &[String]) -> Vec<u32> {
        let mut out = Vec::new();
        for line in instrs(block) {
            if let Some(n) = line
                .rsplit(' ')
                .next()
                .and_then(|t| t.strip_prefix("label_"))
                && let Ok(n) = n.parse::<u32>()
                && !out.contains(&n)
            {
                out.push(n);
            }
        }
        out
    }

    /// The immediate of the first `<mnemonic> <reg>, <imm>` line.
    fn imm_of(block: &[String], prefix: &str) -> Option<i64> {
        instrs(block)
            .iter()
            .find_map(|l| l.strip_prefix(prefix)?.parse::<i64>().ok())
    }

    /// The live count a GC test passes in ECX (`xor ecx, ecx` / `mov ecx, N`), and one less
    /// for the stashed preserved term.
    fn lives(block: &[String]) -> Vec<u64> {
        let lines = instrs(block);
        let n = if lines.contains(&"xor ecx, ecx") {
            Some(0)
        } else {
            imm_of(block, "mov ecx, ").map(|n| n as u64)
        };
        let mut out = match n {
            Some(0) => vec![0],
            Some(n) => vec![n, n - 1],
            None => vec![0],
        };
        // `mov_arg(ARG6, Live)` of beam_jit_bs_get_integer.
        if let Some(live) = imm_of(block, "mov r9d, ") {
            out.push(live as u64);
        }
        out
    }

    /// A register a block found in the register cache (`simplified`/`skipped fetching`): the
    /// test warms the cache with X(63) in it.
    fn warm_reg(block: &[String]) -> Option<Gp> {
        let first = block.first()?;
        let gp = |name: &str| -> Option<Gp> {
            let names = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi"];
            names
                .iter()
                .position(|n| *n == name)
                .map(|i| Gp::q(i as u8))
        };
        if first == "# simplified fetching of BEAM register" {
            let (_, src) = block.get(1)?.strip_prefix("mov ")?.split_once(", ")?;
            gp(src)
        } else if first == "# skipped fetching of BEAM register" {
            // The first instruction uses the cached register; only ctx fetches into
            // ARG1/ARG2/ARG4 are skipped in the blocks compared here.
            None
        } else {
            None
        }
    }

    const WARM: ArgVal = ArgVal::X(63);

    /// A block extracting a bitstring of more than 64 bits whose heap need
    /// `common::bs::extracted_bitstring_size` does not take from erts'
    /// `erts_extracted_bitstring_size` (erl_bits.h): its test_heap differs from erts'.
    fn heap_need_deviates(block: &[String]) -> bool {
        block.iter().any(|l| {
            l.strip_prefix("# get binary ")
                .and_then(|n| n.parse::<u64>().ok())
                .is_some_and(|bits| {
                    // erts_extracted_bitstring_size and common::bs's version of it.
                    let (erts, ours) = if bits <= ERL_ONHEAP_BITS_LIMIT {
                        (heap_bits_size(bits), heap_bits_size(bits).max(8))
                    } else {
                        (ERL_SUB_BITS_SIZE, 8)
                    };
                    bits > 64 && erts != ours
                })
        })
    }

    fn fragment_addresses() -> Vec<Option<usize>> {
        (0..GLOBAL_LABELS.len())
            .map(|i| Some(0x7000_0000 + 64 * i))
            .collect()
    }

    /// Emits with a fresh module assembler (with X(63) cached in `warm` first) and compares
    /// the bytes after the warm-up with `expected`.
    fn emits(
        expected: &[u8],
        warm: Option<(Gp, ArgVal)>,
        emit: &dyn Fn(&mut BeamModuleAssembler) -> Result<(), AsmError>,
    ) -> bool {
        // Aligned calls pad by the code offset modulo 4, unknown for an erts block.
        (0..4).any(|pad| {
            let mut m = BeamModuleAssembler::with_fragment_addresses(4096, fragment_addresses());
            if m.asm.a.embed(&[0x90; 3][..pad]).is_err() {
                return false;
            }
            if let Some((reg, slot)) = warm
                && m.load_cached(reg, super::super::beam_asm::get_arg_ref(slot, 8).unwrap())
                    .is_err()
            {
                return false;
            }
            let start = m.asm.a.offset();
            if emit(&mut m).is_err() {
                return false;
            }
            &m.asm.a.bytes(Section::Code)[start..] == expected
        })
    }

    fn types() -> [ArgType; 5] {
        let int = |min, max| ArgType {
            union_bits: type_id::INTEGER,
            min: Some(min),
            max: Some(max),
            unit: 1,
        };
        [
            ArgType::ANY,
            int(-(1 << 59), (1 << 59) - 1),
            int(0, 1 << 20),
            int(0, 7),
            // A bounded integer that may also be something else.
            ArgType {
                union_bits: type_id::INTEGER | type_id::ATOM,
                ..int(0, 7)
            },
        ]
    }

    /// Counts the blocks of `op` some operand combination reproduces byte for byte, and
    /// asserts that at least `min` of them do.
    fn check_op(
        op: &str,
        min: usize,
        mut candidates: impl FnMut(
            &[String],
            &[ArgVal],
            Option<Gp>,
        )
            -> Vec<Box<dyn Fn(&mut BeamModuleAssembler) -> Result<(), AsmError>>>,
    ) {
        let Some(blocks) = blocks(op) else {
            eprintln!("skipping: `erl +JDdump true` unavailable");
            return;
        };
        if gnu_as(&[]).is_none() {
            eprintln!("skipping: GNU binutils unavailable");
            return;
        }
        let mut compared = 0;
        let mut deviating = 0;
        let mut matched = 0;
        let mut failed: Vec<&Vec<String>> = Vec::new();
        for block in &blocks {
            let warm = warm_reg(block);
            if block
                .iter()
                .any(|l| l == "# skipped fetching of BEAM register")
                || (block
                    .iter()
                    .any(|l| l.ends_with("fetching of BEAM register"))
                    && warm.is_none())
            {
                continue;
            }
            if heap_need_deviates(block) {
                deviating += 1;
                continue;
            }
            let Some(expected) = expected(block) else {
                continue;
            };
            let slots = slots(block);
            // The cached register holds some BEAM register: X(63), or one the block names.
            let warm_slots: Vec<Option<ArgVal>> = match warm {
                Some(_) => std::iter::once(WARM)
                    .chain(slots.iter().copied())
                    .map(Some)
                    .collect(),
                None => vec![None],
            };
            compared += 1;
            let hit = warm_slots.iter().any(|warm_slot| {
                let mut slots = slots.clone();
                if let Some(slot) = warm_slot {
                    slots.retain(|s| s != slot);
                    slots.insert(0, *slot);
                }
                let warm = warm.zip(*warm_slot);
                candidates(block, &slots, warm.map(|w| w.0))
                    .iter()
                    .any(|emit| emits(&expected, warm, emit.as_ref()))
            });
            if hit {
                matched += 1;
            } else {
                failed.push(block);
            }
        }
        eprintln!(
            "{op}: {matched}/{compared} blocks byte-identical; {deviating} skipped for the \
             common::bs heap-need deviation"
        );
        assert!(
            matched >= min && matched == compared,
            "{op}: {matched}/{compared} matched; first mismatch: {:#?}",
            failed.first()
        );
    }

    type Emit = Box<dyn Fn(&mut BeamModuleAssembler) -> Result<(), AsmError>>;

    #[test]
    fn start_match3_matches_erts_dump() {
        check_op("i_bs_start_match3_Stjd", 50, |block, slots, _| {
            let mut out: Vec<Emit> = Vec::new();
            let fail = beam_labels(block).first().copied().unwrap_or(0);
            for &src in slots {
                for &dst in slots {
                    for live in lives(block) {
                        for ty in types() {
                            out.push(Box::new(move |m| {
                                let src = m.typed_arg(src, ty);
                                m.emit_i_bs_start_match3(
                                    src,
                                    ArgVal::Word(live),
                                    ArgVal::Label(fail),
                                    dst,
                                )
                            }));
                        }
                    }
                }
            }
            out
        });
    }

    /// Units a block may use: the `mov edx, U` of a multiplication, and powers of two.
    fn units(block: &[String]) -> Vec<u64> {
        let mut out = vec![1, 8, 16, 32, 2, 4, 64];
        if let Some(u) = imm_of(block, "mov edx, ") {
            out.push(u as u64);
        }
        out
    }

    /// Size operands: the BEAM registers of the block, and the small whose untagged value
    /// times `unit` a block loads as an immediate.
    fn sizes(block: &[String], slots: &[ArgVal], unit: u64, reg: &str) -> Vec<ArgVal> {
        let mut out = slots.to_vec();
        let n = if instrs(block).contains(&format!("xor {reg}, {reg}").as_str()) {
            Some(0)
        } else {
            imm_of(block, &format!("mov {reg}, "))
        };
        if let Some(n) = n
            && unit != 0
            && (n as u64).is_multiple_of(unit)
        {
            out.push(ArgVal::Immediate(make_small(n as u64 / unit) as u64));
        }
        out
    }

    fn fail_label(block: &[String]) -> u32 {
        beam_labels(block).first().copied().unwrap_or(0)
    }

    #[test]
    fn match_string_and_positions_match_erts_dump() {
        check_op("i_bs_match_string_SfWM", 4, |block, slots, _| {
            let fail = fail_label(block);
            let bits = instrs(block)
                .iter()
                .find_map(|l| {
                    l.strip_prefix("lea rdx, qword ptr [rsi+")?
                        .strip_suffix(']')?
                        .parse()
                        .ok()
                })
                .unwrap_or(0u64);
            let mut out: Vec<Emit> = Vec::new();
            for &ctx in slots {
                out.push(Box::new(move |m| {
                    m.emit_i_bs_match_string(
                        ctx,
                        ArgVal::Label(fail),
                        ArgVal::Word(bits),
                        ArgVal::BytePtr(0),
                    )
                }));
            }
            out
        });
        check_op("i_bs_get_position_SS", 50, |_, slots, _| {
            let mut out: Vec<Emit> = Vec::new();
            for &ctx in slots {
                for &dst in slots {
                    out.push(Box::new(move |m| m.emit_i_bs_get_position(ctx, dst)));
                }
            }
            out
        });
        check_op("bs_set_position_SS", 50, |_, slots, _| {
            let mut out: Vec<Emit> = Vec::new();
            for &ctx in slots {
                for &pos in slots {
                    out.push(Box::new(move |m| m.emit_bs_set_position(ctx, pos)));
                }
            }
            out
        });
    }

    #[test]
    fn get_tail_and_skips_match_erts_dump() {
        check_op("bs_get_tail_Sdt", 50, |block, slots, _| {
            let mut out: Vec<Emit> = Vec::new();
            for &ctx in slots {
                for &dst in slots {
                    for live in lives(block) {
                        out.push(Box::new(move |m| {
                            m.emit_bs_get_tail(ctx, dst, ArgVal::Word(live))
                        }));
                    }
                }
            }
            out
        });
        check_op("i_bs_skip_bits2_Ssft", 20, |block, slots, _| {
            let fail = fail_label(block);
            let mut out: Vec<Emit> = Vec::new();
            for unit in units(block) {
                for bits in sizes(block, slots, unit, "eax") {
                    for &ctx in slots {
                        for ty in types() {
                            out.push(Box::new(move |m| {
                                let bits = m.typed_arg(bits, ty);
                                m.emit_i_bs_skip_bits2(
                                    ctx,
                                    bits,
                                    ArgVal::Label(fail),
                                    ArgVal::Word(unit),
                                )
                            }));
                        }
                    }
                }
            }
            out
        });
    }

    #[test]
    fn get_binary_and_float_match_erts_dump() {
        check_op("i_bs_get_binary2_Sftstd", 30, |block, slots, _| {
            let fail = fail_label(block);
            let mut out: Vec<Emit> = Vec::new();
            for unit in units(block) {
                for size in sizes(block, slots, unit, "esi") {
                    for &ctx in slots {
                        for &dst in slots {
                            for live in lives(block) {
                                for ty in types() {
                                    out.push(Box::new(move |m| {
                                        let size = m.typed_arg(size, ty);
                                        m.emit_i_bs_get_binary2(
                                            ctx,
                                            ArgVal::Label(fail),
                                            ArgVal::Word(live),
                                            size,
                                            ArgVal::Word(unit),
                                            dst,
                                        )
                                    }));
                                }
                            }
                        }
                    }
                }
            }
            out
        });
        check_op("i_bs_get_bin_and_tail_SftStdd", 3, |block, slots, _| {
            let fail = fail_label(block);
            let mut out: Vec<Emit> = Vec::new();
            for unit in units(block) {
                for &size in slots {
                    for &ctx in slots {
                        for &dst1 in slots {
                            for &dst2 in slots {
                                for live in lives(block) {
                                    for ty in types() {
                                        out.push(Box::new(move |m| {
                                            let size = m.typed_arg(size, ty);
                                            m.emit_i_bs_get_bin_and_tail(
                                                ctx,
                                                ArgVal::Label(fail),
                                                ArgVal::Word(live),
                                                size,
                                                ArgVal::Word(unit),
                                                dst1,
                                                dst2,
                                            )
                                        }));
                                    }
                                }
                            }
                        }
                    }
                }
            }
            out
        });
        check_op("i_bs_get_float2_Sftstd", 1, |block, slots, _| {
            let fail = fail_label(block);
            let flags = imm_of(block, "mov edx, ").unwrap_or(0) as u64;
            let mut out: Vec<Emit> = Vec::new();
            for sz in sizes(block, slots, flags >> 3, "esi") {
                for &ctx in slots {
                    for &dst in slots {
                        for live in lives(block) {
                            for ty in types() {
                                out.push(Box::new(move |m| {
                                    let sz = m.typed_arg(sz, ty);
                                    m.emit_i_bs_get_float2(
                                        ctx,
                                        ArgVal::Label(fail),
                                        ArgVal::Word(live),
                                        sz,
                                        ArgVal::Word(flags),
                                        dst,
                                    )
                                }));
                            }
                        }
                    }
                }
            }
            out
        });
    }

    #[test]
    fn unicode_matches_erts_dump() {
        check_op("i_bs_get_utf8_Sfd", 10, |block, slots, _| {
            let fail = fail_label(block);
            let mut out: Vec<Emit> = Vec::new();
            for &ctx in slots {
                for &dst in slots {
                    out.push(Box::new(move |m| {
                        m.emit_i_bs_get_utf8(ctx, ArgVal::Label(fail), dst)
                    }));
                }
            }
            out
        });
        check_op("i_bs_skip_utf8_Sf", 1, |block, slots, _| {
            let fail = fail_label(block);
            let mut out: Vec<Emit> = Vec::new();
            for &ctx in slots {
                out.push(Box::new(move |m| {
                    m.emit_i_bs_skip_utf8(ctx, ArgVal::Label(fail))
                }));
            }
            out
        });
        let utf16_flags = |block: &[String]| -> u64 {
            if instrs(block).contains(&"xor esi, esi") {
                0
            } else {
                imm_of(block, "mov esi, ").unwrap_or(0) as u64
            }
        };
        check_op("i_bs_get_utf16_Sftd", 2, |block, slots, _| {
            let fail = fail_label(block);
            let flags = utf16_flags(block);
            let mut out: Vec<Emit> = Vec::new();
            for &ctx in slots {
                for &dst in slots {
                    out.push(Box::new(move |m| {
                        m.emit_i_bs_get_utf16(ctx, ArgVal::Label(fail), ArgVal::Word(flags), dst)
                    }));
                }
            }
            out
        });
        check_op("i_bs_skip_utf16_Sft", 0, |block, slots, _| {
            let fail = fail_label(block);
            let flags = utf16_flags(block);
            let mut out: Vec<Emit> = Vec::new();
            for &ctx in slots {
                out.push(Box::new(move |m| {
                    m.emit_i_bs_skip_utf16(ctx, ArgVal::Label(fail), ArgVal::Word(flags))
                }));
            }
            out
        });
        check_op("i_bs_validate_unicode_retract_jsS", 3, |block, slots, _| {
            let fail = fail_label(block);
            let mut out: Vec<Emit> = Vec::new();
            for &src in slots {
                for &ms in slots {
                    out.push(Box::new(move |m| {
                        m.emit_i_bs_validate_unicode_retract(ArgVal::Label(fail), src, ms)
                    }));
                }
            }
            out
        });
        check_op("bs_init_writable", 5, |_, _, _| {
            vec![Box::new(|m: &mut BeamModuleAssembler| m.emit_bs_init_writable()) as Emit]
        });
    }

    #[test]
    fn get_integer2_matches_erts_dump() {
        check_op("bs_get_integer2_fStsttd", 10, |block, slots, _| {
            let fail = fail_label(block);
            let mut out: Vec<Emit> = Vec::new();
            // The fixed size of the bs_match form, from its `ensure_at_least` comment.
            let fixed = block.iter().find_map(|l| {
                l.strip_prefix("# ensure_at_least ")?
                    .split(' ')
                    .next()?
                    .parse::<u64>()
                    .ok()
            });
            for unit in [1, 8] {
                let mut sizes = sizes(block, slots, unit, "esi");
                if let Some(bits) = fixed
                    && bits % unit == 0
                {
                    sizes.push(ArgVal::Immediate(make_small(bits / unit) as u64));
                }
                for sz in sizes {
                    for &ctx in slots {
                        for &dst in slots {
                            for live in lives(block) {
                                for flags in [0, 2, 4, 6, 16, 20] {
                                    for ty in types() {
                                        out.push(Box::new(move |m| {
                                            let sz = m.typed_arg(sz, ty);
                                            m.emit_bs_get_integer2(
                                                ArgVal::Label(fail),
                                                ctx,
                                                ArgVal::Word(live),
                                                sz,
                                                ArgVal::Word(unit),
                                                ArgVal::Word(flags),
                                                dst,
                                            )
                                        }));
                                    }
                                }
                            }
                        }
                    }
                }
            }
            out
        });
    }

    /// The `bs_match` command lists a block's action comments can come from: each
    /// extract/read/get comment is one command, `ensure_*`, `=:=`, `skip`/`drop` and
    /// `get_tail` one each; `read` and `test_heap` are planned by `beam_jit_opt_bsm_segments`.
    /// Integer flags are not in the dump, so every combination is listed. Returns the lists
    /// and the trailing test_heap's live count, or `None` for a block with an unknown comment.
    fn match_commands(block: &[String]) -> Option<(Vec<Vec<ArgVal>>, u64, u64)> {
        let mut actions: Vec<(String, Vec<&str>)> = Vec::new();
        const ACTIONS: [&str; 13] = [
            "ensure_at_least ",
            "ensure_exactly ",
            "=:= ",
            "test_heap ",
            "read ",
            "extract integer ",
            "extract binary ",
            "read integer ",
            "get integer ",
            "get binary ",
            "get_tail",
            "skip ",
            "drop ",
        ];
        for line in block {
            if let Some(comment) = line.strip_prefix("# ") {
                if ACTIONS.iter().any(|a| comment.starts_with(a)) {
                    actions.push((comment.to_string(), Vec::new()));
                }
            } else if let Some((_, lines)) = actions.last_mut() {
                lines.push(line);
            }
        }
        let store = |lines: &[&str]| -> Option<ArgVal> {
            lines.iter().find_map(|l| {
                let (dst, _) = l.strip_prefix("mov ")?.split_once(", ")?;
                beam_register(dst)
            })
        };
        let gc_live = |lines: &[&str]| -> Option<u64> {
            if lines.contains(&"xor ecx, ecx") {
                Some(0)
            } else {
                lines
                    .iter()
                    .find_map(|l| l.strip_prefix("mov ecx, ")?.parse().ok())
            }
        };
        let num = |s: &str| s.parse::<i64>().ok().map(|v| v as u64);
        // The loader's flattened `{Command, Operands...}` list.
        let word = ArgVal::Word;
        let live_arg = |live: Option<u32>| {
            live.map_or(ArgVal::Immediate(Term::NIL.word()), |l| word(l.into()))
        };
        let mut commands: Vec<Vec<ArgVal>> = Vec::new();
        let mut integers: Vec<usize> = Vec::new();
        let mut live: Option<u32> = None;
        let mut test_heaps: Vec<(u64, u64)> = Vec::new();
        for (comment, lines) in &actions {
            let args: Vec<&str> = comment.split(' ').collect();
            let command = match args.as_slice() {
                ["ensure_at_least", size, unit] => vec![
                    atom_arg(atoms::ENSURE_AT_LEAST),
                    word(num(size)?),
                    word(num(unit)?),
                ],
                ["ensure_exactly", size] => {
                    vec![atom_arg(atoms::ENSURE_EXACTLY), word(num(size)?)]
                }
                ["=:=", size, value] => vec![
                    atom_arg(atoms::EQ),
                    live_arg(live),
                    word(num(size)?),
                    word(num(value)?),
                ],
                ["test_heap", size] => {
                    let l = gc_live(lines)?;
                    live = Some(l as u32);
                    test_heaps.push((num(size)?, l));
                    continue;
                }
                ["read", _] => continue,
                ["extract", "integer", size]
                | ["read", "integer", size]
                | ["get", "integer", size] => {
                    integers.push(commands.len());
                    vec![
                        atom_arg(atoms::INTEGER),
                        live_arg(live),
                        word(0),
                        word(num(size)?),
                        word(1),
                        store(lines).unwrap_or(ArgVal::X(1023)),
                    ]
                }
                ["extract", "binary", size] | ["get", "binary", size] => vec![
                    atom_arg(atoms::BINARY),
                    live_arg(live),
                    word(0),
                    word(num(size)?),
                    word(1),
                    store(lines)?,
                ],
                ["get_tail"] => vec![
                    atom_arg(atoms::GET_TAIL),
                    live_arg(live),
                    word(1),
                    store(lines)?,
                ],
                ["skip", size] | ["drop", size] => {
                    vec![atom_arg(atoms::SKIP), word(num(size)?)]
                }
                _ => return None,
            };
            commands.push(command);
        }
        // Need: the test_heap total minus what the commands themselves need.
        let planned = opt_bsm_segments(&beam_jit_bsm_init(&commands.concat()).ok()?, 0, 0);
        let own: u64 = planned
            .iter()
            .filter(|s| s.action == Action::TestHeap)
            .map(|s| s.size)
            .sum();
        let total: u64 = test_heaps.iter().map(|(n, _)| n).sum();
        let need = total.checked_sub(own)?;
        let trailing_live = test_heaps.last().map_or(0, |(_, l)| *l);
        let flag_sets = [0, BSF_SIGNED, BSF_LITTLE, BSF_SIGNED | BSF_LITTLE];
        let combos = flag_sets.len().pow(integers.len().min(4) as u32);
        let mut lists = Vec::new();
        for combo in 0..combos {
            let mut list = commands.clone();
            for (k, &index) in integers.iter().enumerate() {
                let flags = flag_sets[(combo / flag_sets.len().pow(k.min(3) as u32)) % 4];
                // The flags operand of `{integer, Live, Flags, ...}`.
                list[index][2] = word(flags);
            }
            lists.push(list.concat());
        }
        Some((lists, need, trailing_live))
    }

    fn check_match(op: &str, min: usize) {
        check_op(op, min, |block, slots, _| {
            let fail = fail_label(block);
            let Some((lists, need, live)) = match_commands(block) else {
                return Vec::new();
            };
            let mut out: Vec<Emit> = Vec::new();
            for &ctx in slots.iter().take(2) {
                for list in &lists {
                    let list = list.clone();
                    out.push(Box::new(move |m| {
                        m.emit_i_bs_match_test_heap(
                            ArgVal::Label(fail),
                            ctx,
                            ArgVal::Word(need),
                            ArgVal::Word(live),
                            &list,
                        )
                    }));
                }
            }
            out
        });
    }

    #[test]
    fn bs_match_matches_erts_dump() {
        check_match("i_bs_match_fS", 300);
    }

    #[test]
    fn bs_match_test_heap_matches_erts_dump() {
        check_match("i_bs_match_test_heap_fSIt", 20);
    }

    // bs_test_tail2 and i_bs_get_binary_all2 are bs_match forms (only in code from OTP 25 and
    // earlier, none in the dump): the same bytes as the equivalent command lists.
    #[test]
    fn old_match_forms_are_bs_match() {
        let bytes = |emit: &dyn Fn(&mut BeamModuleAssembler) -> Result<(), AsmError>| {
            let mut m = BeamModuleAssembler::with_fragment_addresses(4, fragment_addresses());
            emit(&mut m).unwrap();
            m.asm.a.bytes(Section::Code).to_vec()
        };
        let (ctx, dst) = (ArgVal::X(1), ArgVal::Y(2));
        assert_eq!(
            bytes(&|m| m.emit_bs_test_tail2(ArgVal::Label(1), ctx, ArgVal::Word(16))),
            bytes(&|m| m.emit_i_bs_match(
                ArgVal::Label(1),
                ctx,
                &[atom_arg(atoms::ENSURE_EXACTLY), ArgVal::Word(16)]
            ))
        );
        assert_eq!(
            bytes(&|m| m.emit_i_bs_get_binary_all2(
                ctx,
                ArgVal::Label(1),
                ArgVal::Word(3),
                ArgVal::Word(8),
                dst
            )),
            bytes(&|m| m.emit_i_bs_match(
                ArgVal::Label(1),
                ctx,
                &[
                    atom_arg(atoms::ENSURE_AT_LEAST),
                    ArgVal::Word(0),
                    ArgVal::Word(8),
                    atom_arg(atoms::GET_TAIL),
                    ArgVal::Word(3),
                    ArgVal::Word(8),
                    dst,
                ]
            ))
        );
        // skip_utf16 is get_utf16 without the store.
        let get = bytes(&|m| m.emit_i_bs_get_utf16(ctx, ArgVal::Label(1), ArgVal::Word(2), dst));
        let skip = bytes(&|m| m.emit_i_bs_skip_utf16(ctx, ArgVal::Label(1), ArgVal::Word(2)));
        assert!(get.starts_with(&skip) && get.len() > skip.len());
    }

    // The CPU feature arms this host does not take (no MOVBE: `mov` + `bswap`/`xchg`; no
    // BMI2: `erts_bs_get_utf8` instead of the PEXT fragments): every encoder form they emit
    // encodes.
    #[test]
    fn other_cpu_feature_arms_encode() {
        let mut e = enc::Emitter::new();
        fn base_index(size: u8) -> Mem {
            Mem::base_index(ARG1, ARG5, 0, 0, size)
        }
        type Form = dyn Fn(&mut enc::Emitter) -> Result<(), enc::EncodeError>;
        let forms: [&Form; 12] = [
            &|e| e.mov_rm(RETD, Mem::base_index(ARG3, RET, 0, 0, 4)),
            &|e| e.bswap(RETD),
            &|e| e.mov_rm(ARG3, qword_ptr(ARG1, 0)),
            &|e| e.bswap(ARG3),
            &|e| e.mov_rm(ARG3D, dword_ptr(ARG1, -2)),
            &|e| e.bswap(ARG3D),
            &|e| e.mov_rm(RET.r16(), base_index(2)),
            &|e| e.xchg_rr(enc::AL, enc::AH),
            &|e| e.mov_rm(RETD, dword_ptr(ARG1, -1)),
            &|e| e.mov_rm(RETD, base_index(4)),
            &|e| e.mov_rm(RET, qword_ptr(ARG1, -3)),
            &|e| e.bswap(RET),
        ];
        for form in forms {
            form(&mut e).unwrap();
        }
        assert!(!e.is_empty());
        let mut m = BeamModuleAssembler::with_fragment_addresses(4, fragment_addresses());
        m.asm.emit_enter_runtime(Update::NONE).unwrap();
        m.asm
            .runtime_call(erts_bs_get_utf8 as *const () as usize)
            .unwrap();
        m.asm.emit_leave_runtime(Update::NONE).unwrap();
        m.asm.emit_test_the_non_value(RET).unwrap();
    }

    // erts' module code calls these fragments; their emitters exist (byte-compared with the
    // dump by beam_asm_global's fragments_match_erts_dump).
    #[test]
    fn bs_fragments_are_emitted() {
        use GlobalLabels as G;
        for label in [
            G::BsSizeCheckShared,
            G::BsGetTailShared,
            G::BsGetUtf8Shared,
            G::BsCreateBinErrorShared,
            G::GetSint64Shared,
            G::ConstructUtf8Shared,
            G::StoreUnaligned,
        ] {
            assert!(BeamGlobalAssembler::emit_ptr(label).is_some(), "{label:?}");
        }
        let ga = BeamGlobalAssembler::new().unwrap();
        let m = BeamModuleAssembler::with_global(4, &ga, 0x1000);
        assert!(m.ga_get(G::BsGetTailShared).is_ok());
        assert!(m.ga_get(G::BsGetUtf8ShortShared).is_err());
    }
}
