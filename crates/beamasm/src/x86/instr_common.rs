//! Port of erts/emulator/beam/jit/x86/instr_common.cpp, OTP-29.1.1: the move, trim and jump
//! instructions of box I1 so far. Every `emit_*` here is one erts `BeamModuleAssembler::emit_*`,
//! and the global fragments `raise_shared` and `catch_end_shared`.

use arinsal_x64::enc::{self, Xmm};

use arinsal_term::{Term, atoms};
use arinsal_x64::enc::{CondCode, Mem, qword_ptr};

use super::beam_asm::register::{
    ARG1, ARG1D, ARG2, ARG2D, ARG3, ARG4, C_P, E, HTOP, RET, RETB, RETD,
};
use super::beam_asm::{
    AsmError, BeamAssembler, CpuFeature, Distance, TAG_PRIMARY_BOXED, TAG_PRIMARY_LIST,
    emit_boxed_val, get_arg_ref, get_car_ref, get_cdr_ref, get_y_ref, process, process_ref,
};
use super::beam_asm::{Update, get_x_ref};
use super::beam_asm_global::{BeamGlobalAssembler, GlobalLabels};
use super::beam_asm_module::{BeamModuleAssembler, arg_label, arg_word};
pub use super::rt::{add_stacktrace, erts_sanitize_freason};
use crate::common::args::ArgVal;
use crate::common::args::{Relation, memory_relation};
use crate::common::types::{TypedArg, type_id};

const NIL: i64 = 0x3b;
const TAG_IMMED1_MASK: i64 = 0x0f;
const TAG_IMMED1_SMALL: i64 = 0x0f;
const TAG_IMMED1_PID: i64 = 0x03;
const TAG_IMMED1_PORT: i64 = 0x07;
const TAG_IMMED2_MASK: i64 = 0x3f;
const TAG_IMMED2_ATOM: i64 = 0x0b;
const TAG_HEADER_MASK: i64 = 0x3f;
const TAG_HEADER_POS_BIG: i64 = 0x08;
const TAG_HEADER_REF: i64 = 0x10;
const TAG_HEADER_FLOAT: i64 = 0x58;
const TAG_HEADER_EXTERNAL_PID: i64 = 0x30;
const TAG_HEADER_EXTERNAL_PORT: i64 = 0x34;
const TAG_HEADER_EXTERNAL_REF: i64 = 0x38;
const TAG_HEADER_HEAP_BITS: i64 = 0x20;
const TAG_HEADER_MAP: i64 = 0x2c;
const BITSTRING_TAG_MASK: i64 = 0x3b;
const BIG_TAG_MASK: i64 = 0x3b;
const FUN_SUBTAG: i64 = 0x14;
const AM_FALSE: i64 = 0x0b;
const AM_TRUE: i64 = 0x4b;
const HEADER_SUB_BITS: i64 = 0x124;

fn arg_ref(arg: ArgVal, size: u8) -> Result<Mem, AsmError> {
    get_arg_ref(arg, size).ok_or(AsmError::Operand("BEAM register operand"))
}

impl BeamModuleAssembler {
    /// `i_move Src Dst`.
    // Port of erts/emulator/beam/jit/x86/instr_common.cpp:654-661 (emit_i_move), OTP-29.1.1.
    pub fn emit_i_move(&mut self, src: ArgVal, dst: ArgVal) -> Result<(), AsmError> {
        let spill = self.alloc_temp_reg();
        self.mov_arg(dst, src, spill)
    }

    /// `init_yregs Size Ys`: stores NIL in every listed Y register, using `stosq` for runs
    /// of consecutive ones.
    // Port of erts/emulator/beam/jit/x86/instr_common.cpp:569-648 (emit_init_yregs),
    // OTP-29.1.1.
    pub fn emit_init_yregs(&mut self, size: ArgVal, args: &[ArgVal]) -> Result<(), AsmError> {
        const NIL: u64 = 0x3b;
        let ys = args
            .iter()
            .map(|arg| match arg {
                ArgVal::Y(y) => Ok(*y),
                _ => Err(AsmError::Operand("init_yregs takes Y registers")),
            })
            .collect::<Result<Vec<u32>, AsmError>>()?;
        if arg_word(size)? != ys.len() as u64 {
            return Err(AsmError::Operand("init_yregs size"));
        }
        let ys = ys.as_slice();
        if let [y] = ys {
            return self.mov_arg_word(ArgVal::Y(*y), NIL, ARG1);
        }
        let mut i = 0;
        let mut y_ptr: i64 = -1;
        self.asm.mov_imm(enc::RAX, NIL)?;
        while i < ys.len() {
            let first_y = ys[i];
            let mut slots = 1;
            while i + slots < ys.len() && first_y + slots as u32 == ys[i + slots] {
                slots += 1;
            }
            let a = &mut self.asm;
            if slots == 1 {
                a.emit(|e| e.mov_mr(get_y_ref(first_y, 8), enc::RAX))?;
            } else {
                if first_y == 0 {
                    // With NATIVE_ERLANG_STACK, `mov` is two bytes shorter than `lea`.
                    a.emit(|e| e.mov_rr(enc::RDI, super::beam_asm::register::E))?;
                    y_ptr = 0;
                } else if y_ptr < 0 {
                    y_ptr = i64::from(first_y);
                    a.emit(|e| e.lea(enc::RDI, get_y_ref(first_y, 8)))?;
                } else {
                    let offset = (i64::from(first_y) - y_ptr) * 8;
                    a.emit(|e| e.add_ri(enc::RDI, offset))?;
                    y_ptr = i64::from(first_y);
                }
                if slots <= 4 {
                    for _ in 0..slots {
                        a.emit(|e| e.stosq())?;
                    }
                } else {
                    a.mov_imm(enc::RCX, slots as u64)?;
                    a.emit(|e| e.rep_stosq())?;
                }
                y_ptr += slots as i64;
            }
            i += slots;
        }
        Ok(())
    }

    /// `move_two_words Src1 Dst1 Src2 Dst2`: two adjacent words to adjacent destinations.
    // Port of erts/emulator/beam/jit/x86/instr_common.cpp:663-707 (emit_move_two_words),
    // OTP-29.1.1.
    pub fn emit_move_two_words(
        &mut self,
        src1: ArgVal,
        dst1: ArgVal,
        src2: ArgVal,
        dst2: ArgVal,
    ) -> Result<(), AsmError> {
        let reg = |arg| get_arg_ref(arg, 8).ok_or(AsmError::Operand("BEAM register operand"));
        let src_ptr = reg(src1)?.with_size(16);
        if memory_relation(src1, src2) != Relation::Consecutive {
            return Err(AsmError::Operand("move_two_words sources not consecutive"));
        }
        let (d1, d2) = (reg(dst1)?, reg(dst2)?);
        match memory_relation(dst1, dst2) {
            Relation::Consecutive => {
                let dst_ptr = d1.with_size(16);
                self.preserve_cache(&[], &[d1, d2], |m| {
                    m.asm.vmovups_xm(Xmm(0), src_ptr)?;
                    m.asm.vmovups_mx(dst_ptr, Xmm(0))
                })
            }
            Relation::ReverseConsecutive => {
                let dst_ptr = d2.with_size(16);
                if BeamAssembler::has_cpu_feature(CpuFeature::Avx) {
                    // "(moving and swapping)": load and swap.
                    self.preserve_cache(&[], &[d1, d2], |m| {
                        m.asm.emit(|e| e.vpermilpd_xmi(Xmm(0), src_ptr, 1))?;
                        m.asm.emit(|e| e.vmovups_mx(dst_ptr, Xmm(0)))
                    })
                } else {
                    self.mov_arg_to_reg(ARG1, src1)?;
                    self.mov_arg_to_reg(ARG2, src2)?;
                    self.mov_arg_from_reg(dst1, ARG1)?;
                    self.mov_arg_from_reg(dst2, ARG2)
                }
            }
            Relation::None => Err(AsmError::Operand(
                "move_two_words destinations not adjacent",
            )),
        }
    }

    /// `swap R1 R2`.
    // Port of erts/emulator/beam/jit/x86/instr_common.cpp:709-748 (emit_swap), OTP-29.1.1.
    pub fn emit_swap(&mut self, r1: ArgVal, r2: ArgVal) -> Result<(), AsmError> {
        let reg = |arg| get_arg_ref(arg, 8).ok_or(AsmError::Operand("BEAM register operand"));
        let (m1, m2) = (reg(r1)?, reg(r2)?);
        let relation = if BeamAssembler::has_cpu_feature(CpuFeature::Avx) {
            memory_relation(r1, r2)
        } else {
            Relation::None
        };
        let ptr = match relation {
            Relation::Consecutive => m1.with_size(16),
            Relation::ReverseConsecutive => m2.with_size(16),
            Relation::None => {
                self.mov_arg_to_reg(ARG1, r1)?;
                self.mov_arg_to_reg(ARG2, r2)?;
                self.mov_arg_from_reg(r2, ARG1)?;
                return self.mov_arg_from_reg(r1, ARG2);
            }
        };
        // "(swapping using AVX)": load and swap, then store back.
        self.preserve_cache(&[], &[m1, m2], |m| {
            m.asm.emit(|e| e.vpermilpd_xmi(Xmm(0), ptr, 1))?;
            m.asm.emit(|e| e.vmovups_mx(ptr, Xmm(0)))
        })
    }

    /// `i_trim Words`.
    // Port of erts/emulator/beam/jit/x86/instr_common.cpp:650-652 (emit_i_trim), OTP-29.1.1.
    pub fn emit_i_trim(&mut self, words: ArgVal) -> Result<(), AsmError> {
        let words =
            u32::try_from(arg_word(words)?).map_err(|_| AsmError::Operand("i_trim word count"))?;
        self.trim_preserve_cache(words)
    }

    /// `self Dst`.
    // Port of erts/emulator/beam/jit/x86/instr_common.cpp:914-924 (emit_self), OTP-29.1.1.
    pub fn emit_self(&mut self, dst: ArgVal) -> Result<(), AsmError> {
        let reg = self.alloc_temp_reg();
        self.preserve_cache(&[reg], &[], |m| {
            m.asm
                .emit(|e| e.mov_rm(reg, process_ref(process::SELF_PID, 8)))
        })?;
        self.mov_arg_from_reg(dst, reg)
    }

    /// `jump Fail`.
    // Port of erts/emulator/beam/jit/x86/instr_common.cpp:1140-1142 (emit_jump), OTP-29.1.1.
    pub fn emit_jump(&mut self, fail: ArgVal) -> Result<(), AsmError> {
        let label = self
            .resolve_beam_label(arg_label(fail)?)
            .ok_or(AsmError::Operand("jump to an unknown label"))?;
        self.asm.jmp(label)
    }

    /// `get_list Src Hd Tl`, with the boxed source pointer already in `src`.
    // Port of erts/emulator/beam/jit/x86/instr_common.cpp:303-352 (emit_get_list), OTP-29.1.1.
    pub fn emit_get_list_from_reg(
        &mut self,
        src: arinsal_x64::enc::Gp,
        hd: ArgVal,
        tl: ArgVal,
    ) -> Result<(), AsmError> {
        let boxed_ptr = self.asm.emit_ptr_val(src, src);
        let hd_ref = arg_ref(hd, 8)?;
        let tl_ref = arg_ref(tl, 8)?;
        match memory_relation(hd, tl) {
            Relation::Consecutive => {
                let dst_ptr = arg_ref(hd, 16)?;
                let src_ptr = get_car_ref(boxed_ptr, 16);
                self.preserve_cache(&[], &[hd_ref, tl_ref], |m| {
                    m.asm.vmovups_xm(Xmm(0), src_ptr)?;
                    m.asm.vmovups_mx(dst_ptr, Xmm(0))
                })?;
            }
            Relation::ReverseConsecutive if BeamAssembler::has_cpu_feature(CpuFeature::Avx) => {
                let dst_ptr = arg_ref(tl, 16)?;
                let src_ptr = get_car_ref(boxed_ptr, 16);
                self.preserve_cache(&[], &[hd_ref, tl_ref], |m| {
                    m.asm.emit(|e| e.vpermilpd_xmi(Xmm(0), src_ptr, 1))?;
                    m.asm.vmovups_mx(dst_ptr, Xmm(0))
                })?;
            }
            Relation::None | Relation::ReverseConsecutive => {
                self.preserve_cache(&[ARG2, ARG3], &[], |m| {
                    m.asm.emit(|e| e.mov_rm(ARG2, get_car_ref(boxed_ptr, 8)))?;
                    m.asm.emit(|e| e.mov_rm(ARG3, get_cdr_ref(boxed_ptr, 8)))
                })?;
                self.mov_arg_from_reg(hd, ARG2)?;
                self.mov_arg_from_reg(tl, ARG3)?;
            }
        }
        Ok(())
    }

    /// `get_list Src Hd Tl`.
    // Port of erts/emulator/beam/jit/x86/instr_common.cpp:354-359 (emit_get_list), OTP-29.1.1.
    pub fn emit_get_list(&mut self, src: ArgVal, hd: ArgVal, tl: ArgVal) -> Result<(), AsmError> {
        self.mov_arg_to_reg(ARG1, src)?;
        self.emit_get_list_from_reg(ARG1, hd, tl)
    }

    /// `get_hd Src Hd`.
    // Port of erts/emulator/beam/jit/x86/instr_common.cpp:361-370 (emit_get_hd), OTP-29.1.1.
    pub fn emit_get_hd(&mut self, src: ArgVal, hd: ArgVal) -> Result<(), AsmError> {
        self.mov_arg_to_reg(ARG1, src)?;
        let boxed_ptr = self.asm.emit_ptr_val(ARG1, ARG1);
        self.mov_preserve_cache_load(ARG2, get_car_ref(boxed_ptr, 8))?;
        self.mov_arg_from_reg(hd, ARG2)
    }

    /// `get_tl Src Tl`.
    // Port of erts/emulator/beam/jit/x86/instr_common.cpp:372-381 (emit_get_tl), OTP-29.1.1.
    pub fn emit_get_tl(&mut self, src: ArgVal, tl: ArgVal) -> Result<(), AsmError> {
        self.mov_arg_to_reg(ARG1, src)?;
        let boxed_ptr = self.asm.emit_ptr_val(ARG1, ARG1);
        self.mov_preserve_cache_load(ARG2, get_cdr_ref(boxed_ptr, 8))?;
        self.mov_arg_from_reg(tl, ARG2)
    }

    /// Fused `is_nonempty_list` followed by `get_list` on the same source.
    // Port of erts/emulator/beam/jit/x86/instr_common.cpp:383-391
    // (emit_is_nonempty_list_get_list), OTP-29.1.1.
    pub fn emit_is_nonempty_list_get_list(
        &mut self,
        fail: ArgVal,
        src: ArgVal,
        hd: ArgVal,
        tl: ArgVal,
    ) -> Result<(), AsmError> {
        self.mov_arg_to_reg(RET, src)?;
        let fail = self
            .resolve_beam_label(arg_label(fail)?)
            .ok_or(AsmError::Operand("list test to an unknown label"))?;
        self.asm.emit_is_cons(fail, RET, Distance::Long)?;
        self.emit_get_list_from_reg(RET, hd, tl)
    }

    /// Fused `is_nonempty_list` followed by `get_hd` on the same source.
    // Port of erts/emulator/beam/jit/x86/instr_common.cpp:393-404
    // (emit_is_nonempty_list_get_hd), OTP-29.1.1.
    pub fn emit_is_nonempty_list_get_hd(
        &mut self,
        fail: ArgVal,
        src: ArgVal,
        hd: ArgVal,
    ) -> Result<(), AsmError> {
        self.mov_arg_to_reg(RET, src)?;
        let fail = self
            .resolve_beam_label(arg_label(fail)?)
            .ok_or(AsmError::Operand("list test to an unknown label"))?;
        self.asm.emit_is_cons(fail, RET, Distance::Long)?;
        let ptr = self.asm.emit_ptr_val(RET, RET);
        self.mov_preserve_cache_load(ARG2, get_car_ref(ptr, 8))?;
        self.mov_arg_from_reg(hd, ARG2)
    }

    /// Fused `is_nonempty_list` followed by `get_tl` on the same source.
    // Port of erts/emulator/beam/jit/x86/instr_common.cpp:406-417
    // (emit_is_nonempty_list_get_tl), OTP-29.1.1.
    pub fn emit_is_nonempty_list_get_tl(
        &mut self,
        fail: ArgVal,
        src: ArgVal,
        tl: ArgVal,
    ) -> Result<(), AsmError> {
        self.mov_arg_to_reg(RET, src)?;
        let fail = self
            .resolve_beam_label(arg_label(fail)?)
            .ok_or(AsmError::Operand("list test to an unknown label"))?;
        self.asm.emit_is_cons(fail, RET, Distance::Long)?;
        let ptr = self.asm.emit_ptr_val(RET, RET);
        self.mov_preserve_cache_load(ARG2, get_cdr_ref(ptr, 8))?;
        self.mov_arg_from_reg(tl, ARG2)
    }

    /// Loads a tuple source into ARG2 and removes its boxed pointer tag.
    // Port of erts/emulator/beam/jit/x86/instr_common.cpp:450-454 (emit_load_tuple_ptr),
    // OTP-29.1.1.
    pub fn emit_load_tuple_ptr(&mut self, term: TypedArg) -> Result<(), AsmError> {
        self.mov_arg_to_reg(ARG2, term.val)?;
        self.asm.emit_ptr_val(ARG2, ARG2);
        Ok(())
    }

    /// Fetches one tuple element from the tuple pointer already in ARG2.
    // Port of erts/emulator/beam/jit/x86/instr_common.cpp:480-495
    // (emit_i_get_tuple_element), OTP-29.1.1.
    pub fn emit_i_get_tuple_element(
        &mut self,
        _src: TypedArg,
        element: ArgVal,
        dst: ArgVal,
    ) -> Result<(), AsmError> {
        let element = i32::try_from(arg_word(element)?)
            .map_err(|_| AsmError::Operand("tuple element byte offset"))?;
        let tmp_reg = self.alloc_temp_reg();
        self.preserve_cache(&[tmp_reg], &[], |m| {
            m.asm
                .emit(|e| e.mov_rm(tmp_reg, emit_boxed_val(ARG2, element, 8)))
        })?;
        self.mov_arg_from_reg(dst, tmp_reg)
    }

    /// Fetches one tuple element and swaps it with the other destination.
    // Port of erts/emulator/beam/jit/x86/instr_common.cpp:497-515
    // (emit_get_tuple_element_swap), OTP-29.1.1.
    pub fn emit_get_tuple_element_swap(
        &mut self,
        _src: TypedArg,
        element: ArgVal,
        dst: ArgVal,
        other_dst: ArgVal,
    ) -> Result<(), AsmError> {
        let element = i32::try_from(arg_word(element)?)
            .map_err(|_| AsmError::Operand("tuple element byte offset"))?;
        self.preserve_cache(&[ARG1, ARG3], &[], |m| {
            m.mov_arg_to_reg(ARG1, other_dst)?;
            m.asm
                .emit(|e| e.mov_rm(ARG3, emit_boxed_val(ARG2, element, 8)))
        })?;
        self.mov_arg_from_reg(dst, ARG1)?;
        self.mov_arg_from_reg(other_dst, ARG3)
    }

    /// Fetches two consecutive tuple elements from the tuple pointer already in ARG2.
    // Port of erts/emulator/beam/jit/x86/instr_common.cpp:519-567
    // (emit_get_two_tuple_elements), OTP-29.1.1.
    pub fn emit_get_two_tuple_elements(
        &mut self,
        _src: TypedArg,
        element: ArgVal,
        dst1: ArgVal,
        dst2: ArgVal,
    ) -> Result<(), AsmError> {
        let element = i32::try_from(arg_word(element)?)
            .map_err(|_| AsmError::Operand("tuple element byte offset"))?;
        let element_ptr = emit_boxed_val(ARG2, element, 16);
        match memory_relation(dst1, dst2) {
            Relation::Consecutive => {
                let dst_ptr = arg_ref(dst1, 16)?;
                let first = arg_ref(dst1, 8)?;
                let second = arg_ref(dst2, 8)?;
                self.preserve_cache(&[], &[first, second], |m| {
                    m.asm.vmovups_xm(Xmm(0), element_ptr)?;
                    m.asm.vmovups_mx(dst_ptr, Xmm(0))
                })?;
            }
            Relation::ReverseConsecutive if BeamAssembler::has_cpu_feature(CpuFeature::Avx) => {
                let dst_ptr = arg_ref(dst2, 16)?;
                let first = arg_ref(dst1, 8)?;
                let second = arg_ref(dst2, 8)?;
                self.preserve_cache(&[], &[first, second], |m| {
                    m.asm.emit(|e| e.vpermilpd_xmi(Xmm(0), element_ptr, 1))?;
                    m.asm.vmovups_mx(dst_ptr, Xmm(0))
                })?;
            }
            Relation::None | Relation::ReverseConsecutive => {
                self.asm
                    .emit(|e| e.mov_rm(ARG1, emit_boxed_val(ARG2, element, 8)))?;
                self.asm
                    .emit(|e| e.mov_rm(ARG3, emit_boxed_val(ARG2, element + 8, 8)))?;
                self.mov_arg_from_reg(dst1, ARG1)?;
                self.mov_arg_from_reg(dst2, ARG3)?;
            }
        }
        Ok(())
    }

    /// Writes a cons cell at HTOP and leaves its tagged pointer in ARG2.
    // Port of erts/emulator/beam/jit/x86/instr_common.cpp:763-801 (emit_put_cons), OTP-29.1.1.
    pub fn emit_put_cons(&mut self, hd: ArgVal, tl: ArgVal) -> Result<(), AsmError> {
        match memory_relation(hd, tl) {
            Relation::Consecutive => {
                let src_ptr = arg_ref(hd, 16)?;
                let dst_ptr = Mem::base_disp(HTOP, 0, 16);
                self.preserve_cache(&[], &[], |m| {
                    m.asm.vmovups_xm(Xmm(0), src_ptr)?;
                    m.asm.vmovups_mx(dst_ptr, Xmm(0))
                })?;
            }
            Relation::ReverseConsecutive if BeamAssembler::has_cpu_feature(CpuFeature::Avx) => {
                let src_ptr = arg_ref(tl, 16)?;
                let dst_ptr = Mem::base_disp(HTOP, 0, 16);
                self.preserve_cache(&[], &[], |m| {
                    m.asm.emit(|e| e.vpermilpd_xmi(Xmm(0), src_ptr, 1))?;
                    m.asm.vmovups_mx(dst_ptr, Xmm(0))
                })?;
            }
            Relation::None | Relation::ReverseConsecutive => {
                self.mov_arg_to_mem(Mem::base_disp(HTOP, 0, 8), hd, ARG1)?;
                self.mov_arg_to_mem(Mem::base_disp(HTOP, 8, 8), tl, ARG1)?;
            }
        }
        self.preserve_cache(&[ARG2], &[], |m| {
            m.asm
                .emit(|e| e.lea(ARG2, Mem::base_disp(HTOP, i32::from(TAG_PRIMARY_LIST), 8)))
        })
    }

    /// Writes the arity word and fields of a tuple at HTOP, then stores its tagged pointer.
    // Port of erts/emulator/beam/jit/x86/instr_common.cpp:825-912 (emit_put_tuple2), OTP-29.1.1.
    pub fn emit_put_tuple2(
        &mut self,
        dst: ArgVal,
        arity_word: ArgVal,
        args: &[ArgVal],
    ) -> Result<(), AsmError> {
        let arity_word = arg_word(arity_word)?;
        if arity_word >> 6 != args.len() as u64 {
            return Err(AsmError::Operand("tuple arity and fields disagree"));
        }
        let arity_dst = Mem::base_disp(HTOP, 0, 8);
        self.preserve_cache(&[], &[arity_dst], |m| {
            m.asm.emit(|e| e.mov_mi(arity_dst, arity_word as i64))
        })?;

        let mut index = 0;
        let mut repeated_value = Some(ArgVal::Word(0));
        while index < args.len() {
            let dst_ptr = Mem::base_disp(HTOP, ((index + 1) * 8) as i32, 8);
            if index + 1 == args.len() {
                self.mov_arg_to_mem(dst_ptr, args[index], ARG1)?;
                index += 1;
                continue;
            }
            match memory_relation(args[index], args[index + 1]) {
                Relation::Consecutive => {
                    let src_ptr = arg_ref(args[index], 16)?;
                    let dst_ptr = dst_ptr.with_size(16);
                    self.preserve_cache(&[], &[], |m| {
                        m.asm.vmovups_xm(Xmm(0), src_ptr)?;
                        m.asm.vmovups_mx(dst_ptr, Xmm(0))
                    })?;
                    index += 2;
                }
                Relation::ReverseConsecutive if BeamAssembler::has_cpu_feature(CpuFeature::Avx) => {
                    let src_ptr = arg_ref(args[index + 1], 16)?;
                    let dst_ptr = dst_ptr.with_size(16);
                    self.preserve_cache(&[], &[], |m| {
                        m.asm.emit(|e| e.vpermilpd_xmi(Xmm(0), src_ptr, 1))?;
                        m.asm.vmovups_mx(dst_ptr, Xmm(0))
                    })?;
                    index += 2;
                }
                Relation::ReverseConsecutive => {
                    self.mov_arg_to_mem(dst_ptr, args[index], ARG1)?;
                    index += 1;
                }
                Relation::None => {
                    if repeated_value == Some(args[index]) {
                        self.mov_preserve_cache_store(dst_ptr, RET)?;
                        index += 1;
                        continue;
                    }
                    let mut end = index + 1;
                    while end < args.len() && args[index] == args[end] {
                        end += 1;
                    }
                    if end - index < 2 {
                        self.mov_arg_to_mem(dst_ptr, args[index], ARG1)?;
                    } else {
                        repeated_value = Some(args[index]);
                        self.mov_arg_to_reg(RET, args[index])?;
                        while index < end {
                            let element_dst = Mem::base_disp(HTOP, ((index + 1) * 8) as i32, 8);
                            self.preserve_cache(&[], &[], |m| {
                                m.asm.emit(|e| e.mov_mr(element_dst, RET))
                            })?;
                            index += 1;
                        }
                        continue;
                    }
                    index += 1;
                }
            }
        }

        let tuple_size = args.len() + 1;
        let tmp_reg = self.alloc_temp_reg();
        self.preserve_cache(&[HTOP, tmp_reg], &[], |m| {
            m.asm.emit(|e| {
                e.lea(
                    tmp_reg,
                    Mem::base_disp(HTOP, i32::from(TAG_PRIMARY_BOXED), 8),
                )
            })?;
            m.asm.emit(|e| e.add_ri(HTOP, (tuple_size * 8) as i64))
        })?;
        self.mov_arg_from_reg(dst, tmp_reg)
    }

    /// `emit_is_boxed(Fail, Src, Arg, dist)` after specializing for compiler type information.
    // Port of erts/emulator/beam/jit/x86/beam_asm.hpp:1324-1342 (emit_is_boxed), OTP-29.1.1.
    fn emit_is_boxed_source(
        &mut self,
        fail: arinsal_x64::buf::Label,
        source: TypedArg,
        reg: arinsal_x64::enc::Gp,
        distance: Distance,
    ) -> Result<(), AsmError> {
        if source.always_one_of(type_id::ALWAYS_BOXED) {
            Ok(())
        } else {
            self.preserve_cache(&[], &[], |m| m.asm.emit_is_boxed(fail, reg, distance))
        }
    }

    /// Tests whether an X or Y register contains a nonempty list cell.
    // Port of erts/emulator/beam/jit/x86/instr_common.cpp:1130-1138
    // (emit_is_nonempty_list), OTP-29.1.1.
    pub fn emit_is_nonempty_list(&mut self, fail: ArgVal, src: ArgVal) -> Result<(), AsmError> {
        let fail = self
            .resolve_beam_label(arg_label(fail)?)
            .ok_or(AsmError::Operand("list test to an unknown label"))?;
        let list_ptr = arg_ref(src, 1)?;
        self.preserve_cache(&[], &[], |m| {
            m.asm.emit(|e| {
                e.test_mi(
                    list_ptr,
                    i64::from(
                        super::beam_asm::TAG_PRIMARY_MASK - super::beam_asm::TAG_PRIMARY_LIST,
                    ),
                )
            })?;
            m.asm.jcc(CondCode::NE, fail)
        })
    }

    /// Tests whether Src is an atom.
    // Port of erts/emulator/beam/jit/x86/instr_common.cpp:1144-1161 (emit_is_atom), OTP-29.1.1.
    pub fn emit_is_atom(&mut self, fail: ArgVal, src: TypedArg) -> Result<(), AsmError> {
        let fail = self
            .resolve_beam_label(arg_label(fail)?)
            .ok_or(AsmError::Operand("atom test to an unknown label"))?;
        self.mov_arg_to_reg(RET, src.val)?;
        if src.always_one_of(type_id::ATOM | type_id::ALWAYS_BOXED) {
            self.preserve_cache(&[], &[], |m| {
                m.asm.emit_is_not_boxed(fail, RET, Distance::Long)
            })
        } else {
            self.preserve_cache(&[RET], &[], |m| {
                m.asm.emit(|e| e.and_ri(RETB, TAG_IMMED2_MASK))?;
                m.asm.emit(|e| e.cmp_ri(RETB, TAG_IMMED2_ATOM))?;
                m.asm.jcc(CondCode::NE, fail)
            })
        }
    }

    /// Tests whether Src is the `true` or `false` atom.
    // Port of erts/emulator/beam/jit/x86/instr_common.cpp:1163-1175 (emit_is_boolean),
    // OTP-29.1.1.
    pub fn emit_is_boolean(&mut self, fail: ArgVal, src: TypedArg) -> Result<(), AsmError> {
        let fail = self
            .resolve_beam_label(arg_label(fail)?)
            .ok_or(AsmError::Operand("boolean test to an unknown label"))?;
        self.mov_arg_to_reg(ARG1, src.val)?;
        self.asm
            .emit(|e| e.and_ri(ARG1, !(AM_TRUE & !TAG_IMMED2_MASK)))?;
        self.asm.emit(|e| e.cmp_ri(ARG1, AM_FALSE))?;
        self.asm.jcc(CondCode::NE, fail)
    }

    /// Tests whether Src is any bitstring.
    // Port of erts/emulator/beam/jit/x86/instr_common.cpp:1177-1198
    // (emit_is_bitstring), OTP-29.1.1.
    pub fn emit_is_bitstring(&mut self, fail: ArgVal, src: TypedArg) -> Result<(), AsmError> {
        let fail = self
            .resolve_beam_label(arg_label(fail)?)
            .ok_or(AsmError::Operand("bitstring test to an unknown label"))?;
        self.mov_arg_to_reg(ARG1, src.val)?;
        self.emit_is_boxed_source(fail, src, ARG1, Distance::Long)?;
        if src.masked_types(type_id::MAYBE_BOXED) == type_id::BITSTRING {
            return Ok(());
        }
        let boxed_ptr = self.asm.emit_ptr_val(ARG1, ARG1);
        self.preserve_cache(&[RET], &[], |m| {
            m.asm
                .emit(|e| e.mov_rm(RETD, emit_boxed_val(boxed_ptr, 0, 4)))?;
            m.asm.emit(|e| e.and_ri(RETB, BITSTRING_TAG_MASK))?;
            m.asm.emit(|e| e.cmp_ri(RETB, TAG_HEADER_HEAP_BITS))?;
            m.asm.jcc(CondCode::NE, fail)
        })
    }

    /// Tests whether Src is a byte-aligned binary.
    // Port of erts/emulator/beam/jit/x86/instr_common.cpp:1200-1261 (emit_is_binary),
    // OTP-29.1.1.
    pub fn emit_is_binary(&mut self, fail: ArgVal, src: TypedArg) -> Result<(), AsmError> {
        let fail = self
            .resolve_beam_label(arg_label(fail)?)
            .ok_or(AsmError::Operand("binary test to an unknown label"))?;
        let not_sub_bits = self.asm.new_label();
        self.mov_arg_to_reg(ARG1, src.val)?;
        self.emit_is_boxed_source(fail, src, ARG1, Distance::Long)?;
        let boxed_ptr = self.asm.emit_ptr_val(ARG1, ARG1);

        self.preserve_cache(&[RET, ARG2], &[], |m| {
            m.asm
                .emit(|e| e.mov_rm(RET, emit_boxed_val(boxed_ptr, 8, 8)))?;
            m.asm
                .emit(|e| e.mov_rm(ARG2D, emit_boxed_val(boxed_ptr, 0, 4)))?;
            m.asm.emit(|e| e.cmp_ri(ARG2D, HEADER_SUB_BITS))?;
            m.asm.short_jcc(CondCode::NE, not_sub_bits)?;
            m.asm
                .emit(|e| e.mov_rm(RET, emit_boxed_val(boxed_ptr, 24, 8)))?;
            m.asm
                .emit(|e| e.sub_rm(RET, emit_boxed_val(boxed_ptr, 16, 8)))
        })?;
        self.asm.bind(not_sub_bits)?;

        self.preserve_cache(&[RET], &[], |m| m.asm.emit(|e| e.shl_ri(RETD, 32 - 3)))?;
        if src.masked_types(type_id::MAYBE_BOXED) != type_id::BITSTRING {
            self.preserve_cache(&[ARG2], &[], |m| {
                m.asm.emit(|e| e.and_ri(ARG2D, BITSTRING_TAG_MASK))?;
                m.asm.emit(|e| e.or_rr(ARG2D, RETD))?;
                m.asm.emit(|e| e.cmp_ri(ARG2D, TAG_HEADER_HEAP_BITS))
            })?;
        }
        self.preserve_cache(&[], &[], |m| m.asm.jcc(CondCode::NE, fail))
    }

    /// Tests whether Src is a float.
    // Port of erts/emulator/beam/jit/x86/instr_common.cpp:1263-1278 (emit_is_float), OTP-29.1.1.
    pub fn emit_is_float(&mut self, fail: ArgVal, src: TypedArg) -> Result<(), AsmError> {
        let fail = self
            .resolve_beam_label(arg_label(fail)?)
            .ok_or(AsmError::Operand("float test to an unknown label"))?;
        self.mov_arg_to_reg(ARG1, src.val)?;
        self.emit_is_boxed_source(fail, src, ARG1, Distance::Long)?;
        if src.masked_types(type_id::MAYBE_BOXED) == type_id::FLOAT {
            return Ok(());
        }
        let boxed_ptr = self.asm.emit_ptr_val(ARG1, ARG1);
        self.preserve_cache(&[], &[], |m| {
            m.asm
                .emit(|e| e.cmp_mi(emit_boxed_val(boxed_ptr, 0, 8), TAG_HEADER_FLOAT))?;
            m.asm.jcc(CondCode::NE, fail)
        })
    }

    /// Tests whether Src is a function.
    // Port of erts/emulator/beam/jit/x86/instr_common.cpp:1280-1296 (emit_is_function),
    // OTP-29.1.1.
    pub fn emit_is_function(&mut self, fail: ArgVal, src: TypedArg) -> Result<(), AsmError> {
        let fail = self
            .resolve_beam_label(arg_label(fail)?)
            .ok_or(AsmError::Operand("function test to an unknown label"))?;
        self.mov_arg_to_reg(RET, src.val)?;
        self.emit_is_boxed_source(fail, src, RET, Distance::Long)?;
        if src.masked_types(type_id::MAYBE_BOXED) == type_id::FUN {
            return Ok(());
        }
        let boxed_ptr = self.asm.emit_ptr_val(RET, RET);
        self.preserve_cache(&[], &[], |m| {
            m.asm
                .emit(|e| e.cmp_mi(emit_boxed_val(boxed_ptr, 0, 1), FUN_SUBTAG))?;
            m.asm.jcc(CondCode::NE, fail)
        })
    }

    /// Tests whether Src is a small or boxed integer.
    // Port of erts/emulator/beam/jit/x86/instr_common.cpp:1342-1396 (emit_is_integer),
    // OTP-29.1.1.
    pub fn emit_is_integer(&mut self, fail: ArgVal, src: TypedArg) -> Result<(), AsmError> {
        let fail = self
            .resolve_beam_label(arg_label(fail)?)
            .ok_or(AsmError::Operand("integer test to an unknown label"))?;
        if src.always_immediate() {
            self.mov_arg_to_reg(RET, src.val)?;
            return self.preserve_cache(&[RET], &[], |m| {
                m.asm.emit(|e| e.and_ri(RETB, TAG_IMMED1_MASK))?;
                m.asm.emit(|e| e.cmp_ri(RETB, TAG_IMMED1_SMALL))?;
                m.asm.jcc(CondCode::NE, fail)
            });
        }

        let next = self.asm.new_label();
        self.mov_arg_to_reg(ARG1, src.val)?;
        if src.always_one_of(type_id::INTEGER | type_id::ALWAYS_BOXED) {
            self.emit_is_boxed_source(next, src, ARG1, Distance::Long)?;
        } else {
            self.preserve_cache(&[RET], &[], |m| {
                m.asm.emit(|e| e.mov_rr(RETD, ARG1D))?;
                m.asm.emit(|e| e.and_ri(RETB, TAG_IMMED1_MASK))?;
                m.asm.emit(|e| e.cmp_ri(RETB, TAG_IMMED1_SMALL))?;
                m.asm.short_jcc(CondCode::E, next)
            })?;
            self.emit_is_boxed_source(fail, src, RET, Distance::Long)?;
        }
        if src.masked_types(type_id::MAYBE_BOXED) != type_id::INTEGER {
            let boxed_ptr = self.asm.emit_ptr_val(ARG1, ARG1);
            self.preserve_cache(&[RET], &[], |m| {
                m.asm
                    .emit(|e| e.mov_rm(RETD, emit_boxed_val(boxed_ptr, 0, 4)))?;
                m.asm.emit(|e| e.and_ri(RETB, BIG_TAG_MASK))?;
                m.asm.emit(|e| e.cmp_ri(RETB, TAG_HEADER_POS_BIG))?;
                m.asm.jcc(CondCode::NE, fail)
            })?;
        }
        self.asm.bind(next)
    }

    /// Tests whether Src is nil or a cons cell.
    // Port of erts/emulator/beam/jit/x86/instr_common.cpp:1398-1410 (emit_is_list), OTP-29.1.1.
    pub fn emit_is_list(&mut self, fail: ArgVal, src: TypedArg) -> Result<(), AsmError> {
        let fail = self
            .resolve_beam_label(arg_label(fail)?)
            .ok_or(AsmError::Operand("list test to an unknown label"))?;
        let next = self.asm.new_label();
        self.mov_arg_to_reg(RET, src.val)?;
        self.preserve_cache(&[], &[], |m| {
            m.asm.emit(|e| e.cmp_ri(RET, NIL))?;
            m.asm.short_jcc(CondCode::E, next)
        })?;
        self.asm.emit_is_cons(fail, RET, Distance::Long)?;
        self.asm.bind(next)
    }

    /// Tests whether Src is a map.
    // Port of erts/emulator/beam/jit/x86/instr_common.cpp:1412-1433 (emit_is_map), OTP-29.1.1.
    pub fn emit_is_map(&mut self, fail: ArgVal, src: TypedArg) -> Result<(), AsmError> {
        let fail = self
            .resolve_beam_label(arg_label(fail)?)
            .ok_or(AsmError::Operand("map test to an unknown label"))?;
        self.mov_arg_to_reg(ARG1, src.val)?;
        self.emit_is_boxed_source(fail, src, ARG1, Distance::Long)?;
        if src.masked_types(type_id::MAYBE_BOXED) == type_id::MAP {
            return Ok(());
        }
        let boxed_ptr = self.asm.emit_ptr_val(RET, ARG1);
        self.preserve_cache(&[RET], &[], |m| {
            m.asm
                .emit(|e| e.mov_rm(RETD, emit_boxed_val(boxed_ptr, 0, 4)))?;
            m.asm.emit(|e| e.and_ri(RETB, TAG_HEADER_MASK))?;
            m.asm.emit(|e| e.cmp_ri(RETB, TAG_HEADER_MAP))?;
            m.asm.jcc(CondCode::NE, fail)
        })
    }

    /// Tests whether an X or Y register contains nil.
    // Port of erts/emulator/beam/jit/x86/instr_common.cpp:1435-1441 (emit_is_nil), OTP-29.1.1.
    pub fn emit_is_nil(&mut self, fail: ArgVal, src: ArgVal) -> Result<(), AsmError> {
        let fail = self
            .resolve_beam_label(arg_label(fail)?)
            .ok_or(AsmError::Operand("nil test to an unknown label"))?;
        let src = arg_ref(src, 1)?;
        self.preserve_cache(&[], &[], |m| {
            m.asm.emit(|e| e.cmp_mi(src, NIL))?;
            m.asm.jcc(CondCode::NE, fail)
        })
    }

    /// Tests whether Src is an integer or float.
    // Port of erts/emulator/beam/jit/x86/instr_common.cpp:1443-1479 (emit_is_number),
    // OTP-29.1.1.
    pub fn emit_is_number(&mut self, fail: ArgVal, src: TypedArg) -> Result<(), AsmError> {
        let fail = self
            .resolve_beam_label(arg_label(fail)?)
            .ok_or(AsmError::Operand("number test to an unknown label"))?;
        let next = self.asm.new_label();
        self.mov_arg_to_reg(ARG1, src.val)?;
        if src.always_one_of(type_id::INTEGER | type_id::ALWAYS_BOXED) {
            self.emit_is_boxed_source(next, src, ARG1, Distance::Long)?;
        } else {
            self.preserve_cache(&[RET], &[], |m| {
                m.asm.emit(|e| e.mov_rr(RETD, ARG1D))?;
                m.asm.emit(|e| e.and_ri(RETB, TAG_IMMED1_MASK))?;
                m.asm.emit(|e| e.cmp_ri(RETB, TAG_IMMED1_SMALL))?;
                m.asm.short_jcc(CondCode::E, next)
            })?;
            self.emit_is_boxed_source(fail, src, RET, Distance::Long)?;
        }
        if src.masked_types(type_id::MAYBE_BOXED) != type_id::NUMBER {
            let boxed_ptr = self.asm.emit_ptr_val(ARG1, ARG1);
            self.preserve_cache(&[ARG1], &[], |m| {
                m.asm
                    .emit(|e| e.mov_rm(ARG1, emit_boxed_val(boxed_ptr, 0, 8)))?;
                m.asm.emit(|e| e.mov_rr(RETD, ARG1D))?;
                m.asm.emit(|e| e.and_ri(RETB, BIG_TAG_MASK))?;
                m.asm.emit(|e| e.cmp_ri(RETB, TAG_HEADER_POS_BIG))?;
                m.asm.short_jcc(CondCode::E, next)?;
                m.asm.emit(|e| e.cmp_ri(ARG1D, TAG_HEADER_FLOAT))?;
                m.asm.jcc(CondCode::NE, fail)
            })?;
        }
        self.asm.bind(next)
    }

    /// Tests whether Src is a local or external pid.
    // Port of erts/emulator/beam/jit/x86/instr_common.cpp:1481-1519 (emit_is_pid), OTP-29.1.1.
    pub fn emit_is_pid(&mut self, fail: ArgVal, src: TypedArg) -> Result<(), AsmError> {
        let fail = self
            .resolve_beam_label(arg_label(fail)?)
            .ok_or(AsmError::Operand("pid test to an unknown label"))?;
        let next = self.asm.new_label();
        self.mov_arg_to_reg(ARG1, src.val)?;
        if src.always_one_of(type_id::PID | type_id::ALWAYS_BOXED) {
            self.emit_is_boxed_source(next, src, ARG1, Distance::Long)?;
        } else {
            self.preserve_cache(&[RET], &[], |m| {
                m.asm.emit(|e| e.mov_rr(RETD, ARG1D))?;
                m.asm.emit(|e| e.and_ri(RETB, TAG_IMMED1_MASK))?;
                m.asm.emit(|e| e.cmp_ri(RETB, TAG_IMMED1_PID))?;
                m.asm.short_jcc(CondCode::E, next)
            })?;
            self.emit_is_boxed_source(fail, src, RET, Distance::Long)?;
        }
        if src.masked_types(type_id::MAYBE_BOXED) != type_id::PID {
            let boxed_ptr = self.asm.emit_ptr_val(ARG1, ARG1);
            self.preserve_cache(&[RET], &[], |m| {
                m.asm
                    .emit(|e| e.mov_rm(RETD, emit_boxed_val(boxed_ptr, 0, 4)))?;
                m.asm.emit(|e| e.and_ri(RETB, TAG_HEADER_MASK))?;
                m.asm.emit(|e| e.cmp_ri(RETB, TAG_HEADER_EXTERNAL_PID))?;
                m.asm.jcc(CondCode::NE, fail)
            })?;
        }
        self.asm.bind(next)
    }

    /// Tests whether Src is an external port.
    // Port of erts/emulator/beam/jit/x86/instr_common.cpp:1521-1551 (emit_is_port), OTP-29.1.1.
    pub fn emit_is_port(&mut self, fail: ArgVal, src: TypedArg) -> Result<(), AsmError> {
        let fail = self
            .resolve_beam_label(arg_label(fail)?)
            .ok_or(AsmError::Operand("port test to an unknown label"))?;
        let next = self.asm.new_label();
        self.mov_arg_to_reg(ARG1, src.val)?;
        if src.always_one_of(type_id::PORT | type_id::ALWAYS_BOXED) {
            self.emit_is_boxed_source(next, src, ARG1, Distance::Long)?;
        } else {
            self.preserve_cache(&[RET], &[], |m| {
                m.asm.emit(|e| e.mov_rr(RETD, ARG1D))?;
                m.asm.emit(|e| e.and_ri(RETB, TAG_IMMED1_MASK))?;
                m.asm.emit(|e| e.cmp_ri(RETB, TAG_IMMED1_PORT))?;
                m.asm.short_jcc(CondCode::E, next)
            })?;
            self.emit_is_boxed_source(fail, src, RET, Distance::Long)?;
        }
        if src.masked_types(type_id::MAYBE_BOXED) != type_id::PORT {
            let boxed_ptr = self.asm.emit_ptr_val(ARG1, ARG1);
            self.preserve_cache(&[RET], &[], |m| {
                m.asm
                    .emit(|e| e.mov_rm(RETD, emit_boxed_val(boxed_ptr, 0, 4)))?;
                m.asm.emit(|e| e.and_ri(RETB, TAG_HEADER_MASK))?;
                m.asm.emit(|e| e.cmp_ri(RETB, TAG_HEADER_EXTERNAL_PORT))?;
                m.asm.jcc(CondCode::NE, fail)
            })?;
        }
        self.asm.bind(next)
    }

    /// Tests whether Src is a local or external reference.
    // Port of erts/emulator/beam/jit/x86/instr_common.cpp:1553-1578
    // (emit_is_reference), OTP-29.1.1.
    pub fn emit_is_reference(&mut self, fail: ArgVal, src: TypedArg) -> Result<(), AsmError> {
        let fail = self
            .resolve_beam_label(arg_label(fail)?)
            .ok_or(AsmError::Operand("reference test to an unknown label"))?;
        self.mov_arg_to_reg(ARG1, src.val)?;
        self.emit_is_boxed_source(fail, src, ARG1, Distance::Long)?;
        if src.masked_types(type_id::MAYBE_BOXED) != type_id::REFERENCE {
            let next = self.asm.new_label();
            let boxed_ptr = self.asm.emit_ptr_val(ARG1, ARG1);
            self.preserve_cache(&[RET], &[], |m| {
                m.asm
                    .emit(|e| e.mov_rm(RETD, emit_boxed_val(boxed_ptr, 0, 4)))?;
                m.asm.emit(|e| e.and_ri(RETB, TAG_HEADER_MASK))?;
                m.asm.emit(|e| e.cmp_ri(RETB, TAG_HEADER_REF))?;
                m.asm.short_jcc(CondCode::E, next)?;
                m.asm.emit(|e| e.cmp_ri(RETB, TAG_HEADER_EXTERNAL_REF))?;
                m.asm.jcc(CondCode::NE, fail)
            })?;
            self.asm.bind(next)?;
        }
        Ok(())
    }

    /// Tests a tuple's header arity and first element tag, leaving its pointer in ARG2.
    // Port of erts/emulator/beam/jit/x86/instr_common.cpp:1580-1598
    // (emit_i_is_tagged_tuple), OTP-29.1.1.
    pub fn emit_i_is_tagged_tuple(
        &mut self,
        fail: ArgVal,
        src: TypedArg,
        arity_word: ArgVal,
        tag_word: ArgVal,
    ) -> Result<(), AsmError> {
        let fail = self
            .resolve_beam_label(arg_label(fail)?)
            .ok_or(AsmError::Operand("tagged tuple test to an unknown label"))?;
        let arity_word = i64::try_from(arg_word(arity_word)?)
            .map_err(|_| AsmError::Operand("tuple arity word"))?;
        let tag_word =
            i64::try_from(arg_word(tag_word)?).map_err(|_| AsmError::Operand("tuple tag word"))?;
        self.mov_arg_to_reg(ARG2, src.val)?;
        self.emit_is_boxed_source(fail, src, ARG2, Distance::Long)?;
        let boxed_ptr = self.asm.emit_ptr_val(ARG2, ARG2);
        self.preserve_cache(&[], &[], |m| {
            m.asm
                .emit(|e| e.cmp_mi(emit_boxed_val(boxed_ptr, 0, 4), arity_word))?;
            m.asm.jcc(CondCode::NE, fail)?;
            m.asm
                .emit(|e| e.cmp_mi(emit_boxed_val(boxed_ptr, 8, 8), tag_word))?;
            m.asm.jcc(CondCode::NE, fail)
        })
    }

    /// Distinguishes non-tuples from tuples with the wrong record tag or arity.
    // Port of erts/emulator/beam/jit/x86/instr_common.cpp:1600-1624
    // (emit_i_is_tagged_tuple_ff), OTP-29.1.1.
    pub fn emit_i_is_tagged_tuple_ff(
        &mut self,
        not_tuple: ArgVal,
        not_record: ArgVal,
        src: TypedArg,
        arity_word: ArgVal,
        tag_word: ArgVal,
    ) -> Result<(), AsmError> {
        let not_tuple = self
            .resolve_beam_label(arg_label(not_tuple)?)
            .ok_or(AsmError::Operand("tuple test to an unknown label"))?;
        let not_record = self
            .resolve_beam_label(arg_label(not_record)?)
            .ok_or(AsmError::Operand("record test to an unknown label"))?;
        let arity_word = i64::try_from(arg_word(arity_word)?)
            .map_err(|_| AsmError::Operand("tuple arity word"))?;
        let tag_word =
            i64::try_from(arg_word(tag_word)?).map_err(|_| AsmError::Operand("tuple tag word"))?;
        self.mov_arg_to_reg(ARG2, src.val)?;
        self.emit_is_boxed_source(not_tuple, src, ARG2, Distance::Long)?;
        let boxed_ptr = self.asm.emit_ptr_val(ARG2, ARG2);
        self.asm
            .emit(|e| e.mov_rm(ARG1, emit_boxed_val(boxed_ptr, 0, 8)))?;
        self.asm.emit(|e| e.test_ri(ARG1.r8(), TAG_HEADER_MASK))?;
        self.asm.jcc(CondCode::NE, not_tuple)?;
        self.asm.emit(|e| e.cmp_ri(ARG1D, arity_word))?;
        self.asm.jcc(CondCode::NE, not_record)?;
        self.asm
            .emit(|e| e.cmp_mi(emit_boxed_val(boxed_ptr, 8, 8), tag_word))?;
        self.asm.jcc(CondCode::NE, not_record)
    }

    /// Tests tuple boxedness and leaves its untagged pointer in ARG2.
    // Port of erts/emulator/beam/jit/x86/instr_common.cpp:1625-1653 (emit_i_is_tuple),
    // OTP-29.1.1.
    pub fn emit_i_is_tuple(&mut self, fail: ArgVal, src: TypedArg) -> Result<(), AsmError> {
        let fail = self
            .resolve_beam_label(arg_label(fail)?)
            .ok_or(AsmError::Operand("tuple test to an unknown label"))?;
        self.mov_arg_to_reg(ARG2, src.val)?;
        if src.masked_types(type_id::MAYBE_BOXED) == type_id::TUPLE {
            self.asm.emit_ptr_val(ARG2, ARG2);
            self.preserve_cache(&[], &[], |m| {
                m.asm
                    .emit_test(ARG2, super::beam_asm::TAG_PRIMARY_MASK - TAG_PRIMARY_BOXED)
            })?;
        } else {
            self.emit_is_boxed_source(fail, src, ARG2, Distance::Long)?;
            let boxed_ptr = self.asm.emit_ptr_val(ARG2, ARG2);
            self.preserve_cache(&[], &[], |m| {
                m.asm
                    .emit(|e| e.test_mi(emit_boxed_val(boxed_ptr, 0, 1), TAG_HEADER_MASK))
            })?;
        }
        self.preserve_cache(&[], &[], |m| m.asm.jcc(CondCode::NE, fail))
    }

    /// Tests tuple boxedness and arity, leaving its untagged pointer in ARG2.
    // Port of erts/emulator/beam/jit/x86/instr_common.cpp:1655-1670
    // (emit_i_is_tuple_of_arity), OTP-29.1.1.
    pub fn emit_i_is_tuple_of_arity(
        &mut self,
        fail: ArgVal,
        src: TypedArg,
        arity_word: ArgVal,
    ) -> Result<(), AsmError> {
        let fail = self
            .resolve_beam_label(arg_label(fail)?)
            .ok_or(AsmError::Operand("tuple arity test to an unknown label"))?;
        let arity_word = i64::try_from(arg_word(arity_word)?)
            .map_err(|_| AsmError::Operand("tuple arity word"))?;
        self.mov_arg_to_reg(ARG2, src.val)?;
        self.emit_is_boxed_source(fail, src, ARG2, Distance::Long)?;
        let boxed_ptr = self.asm.emit_ptr_val(ARG2, ARG2);
        self.preserve_cache(&[], &[], |m| {
            m.asm
                .emit(|e| e.cmp_mi(emit_boxed_val(boxed_ptr, 0, 4), arity_word))?;
            m.asm.jcc(CondCode::NE, fail)
        })
    }

    /// Splits non-tuple and wrong-arity failures while retaining the tuple pointer in ARG2.
    // Port of erts/emulator/beam/jit/x86/instr_common.cpp:1672-1706
    // (emit_i_is_tuple_of_arity_ff), OTP-29.1.1.
    pub fn emit_i_is_tuple_of_arity_ff(
        &mut self,
        not_tuple: ArgVal,
        bad_arity: ArgVal,
        src: TypedArg,
        arity_word: ArgVal,
    ) -> Result<(), AsmError> {
        let not_tuple = self
            .resolve_beam_label(arg_label(not_tuple)?)
            .ok_or(AsmError::Operand("tuple test to an unknown label"))?;
        let bad_arity = self
            .resolve_beam_label(arg_label(bad_arity)?)
            .ok_or(AsmError::Operand("tuple arity test to an unknown label"))?;
        let arity_word = i64::try_from(arg_word(arity_word)?)
            .map_err(|_| AsmError::Operand("tuple arity word"))?;
        self.mov_arg_to_reg(ARG2, src.val)?;
        let boxed_ptr = self.asm.emit_ptr_val(ARG2, ARG2);
        if src.masked_types(type_id::MAYBE_BOXED) == type_id::TUPLE {
            self.asm.emit_is_boxed(not_tuple, ARG2, Distance::Long)?;
            self.preserve_cache(&[], &[], |m| {
                m.asm
                    .emit(|e| e.cmp_mi(emit_boxed_val(boxed_ptr, 0, 4), arity_word))?;
                m.asm.jcc(CondCode::NE, bad_arity)
            })
        } else {
            self.emit_is_boxed_source(not_tuple, src, ARG2, Distance::Long)?;
            self.preserve_cache(&[RET], &[], |m| {
                m.asm
                    .emit(|e| e.mov_rm(RETD, emit_boxed_val(boxed_ptr, 0, 4)))?;
                m.asm.emit(|e| e.test_ri(RETB, TAG_HEADER_MASK))?;
                m.asm.jcc(CondCode::NE, not_tuple)?;
                m.asm.emit(|e| e.cmp_ri(RETD, arity_word))?;
                m.asm.jcc(CondCode::NE, bad_arity)
            })
        }
    }

    /// Tests the tuple arity at the tuple pointer left in ARG2.
    // Port of erts/emulator/beam/jit/x86/instr_common.cpp:1708-1720
    // (emit_i_test_arity), OTP-29.1.1.
    pub fn emit_i_test_arity(
        &mut self,
        fail: ArgVal,
        src: TypedArg,
        arity_word: ArgVal,
    ) -> Result<(), AsmError> {
        let fail = self
            .resolve_beam_label(arg_label(fail)?)
            .ok_or(AsmError::Operand("tuple arity test to an unknown label"))?;
        let arity_word = i64::try_from(arg_word(arity_word)?)
            .map_err(|_| AsmError::Operand("tuple arity word"))?;
        self.mov_arg_to_reg(ARG2, src.val)?;
        let boxed_ptr = self.asm.emit_ptr_val(ARG2, ARG2);
        self.preserve_cache(&[], &[], |m| {
            m.asm
                .emit(|e| e.cmp_mi(emit_boxed_val(boxed_ptr, 0, 4), arity_word))?;
            m.asm.jcc(CondCode::NE, fail)
        })
    }
}

impl BeamGlobalAssembler {
    /// Attaches a stacktrace to an error reason: `ARG3` is the reason, `ARG2` the trace.
    // Port of erts/emulator/beam/jit/x86/instr_common.cpp:3138-3152 (emit_raise_shared),
    // OTP-29.1.1.
    pub(crate) fn emit_raise_shared(&mut self) -> Result<(), AsmError> {
        let a = &mut self.asm;
        a.emit(|e| e.mov_mr(process_ref(process::FVALUE, 8), ARG3))?;
        a.emit(|e| e.mov_mr(process_ref(process::FTRACE, 8), ARG2))?;
        a.emit_enter_runtime(Update::NONE)?;
        a.emit(|e| e.mov_rr(ARG1, C_P))?;
        a.runtime_call(erts_sanitize_freason as *const () as usize)?;
        a.emit_leave_runtime(Update::NONE)?;
        a.mov_imm(ARG4, 0)?;
        let label = self.label(GlobalLabels::RaiseException);
        self.asm.jmp(label)
    }

    /// The value of a `catch`: a thrown value as is, an error reason with its stacktrace,
    /// anything else as `{'EXIT', Reason}`; class in x3, value in x1, trace in x2, result in
    /// x0.
    // Port of erts/emulator/beam/jit/x86/instr_common.cpp:3021-3083 (emit_catch_end_shared),
    // OTP-29.1.1.
    pub(crate) fn emit_catch_end_shared(&mut self) -> Result<(), AsmError> {
        let throw = Term::atom(atoms::THROW).word() as i64;
        let error = Term::atom(atoms::ERROR).word() as i64;
        let exit = Term::atom(atoms::EXIT_2).word() as i64;
        let garbage_collect = self.label(GlobalLabels::GarbageCollect);
        let a = &mut self.asm;
        let (not_throw, not_error, after_gc) = (a.new_label(), a.new_label(), a.new_label());
        a.emit_enter_frame()?;
        // Load thrown value / reason into ARG2 for add_stacktrace.
        a.emit(|e| e.mov_rm(ARG2, get_x_ref(1, 8)))?;
        a.emit(|e| e.cmp_mi(get_x_ref(3, 8), throw))?;
        a.short_jcc(CondCode::NE, not_throw)?;
        // Thrown value, return it in x0.
        a.emit(|e| e.mov_mr(get_x_ref(0, 8), ARG2))?;
        a.emit_leave_frame()?;
        a.emit(|e| e.ret())?;

        a.bind(not_throw)?;
        a.emit(|e| e.cmp_mi(get_x_ref(3, 8), error))?;
        a.jcc(CondCode::NE, not_error)?;
        // This is an error, attach a stacktrace to the reason.
        a.emit_enter_runtime(Update::HEAP_ALLOC)?;
        a.emit(|e| e.mov_rr(ARG1, C_P))?;
        a.emit(|e| e.mov_rm(ARG3, get_x_ref(2, 8)))?;
        a.runtime_call(add_stacktrace as *const () as usize)?;
        a.emit_leave_runtime(Update::HEAP_ALLOC)?;
        // not_error assumes stacktrace/reason is in ARG2.
        a.emit(|e| e.mov_rr(ARG2, RET))?;

        a.bind(not_error)?;
        let bytes_needed = ((3 + arinsal_term::S_RESERVED) * 8) as i32;
        a.emit(|e| e.lea(ARG3, qword_ptr(HTOP, bytes_needed)))?;
        a.emit(|e| e.cmp_rr(ARG3, E))?;
        a.short_jcc(CondCode::BE, after_gc)?;
        // Preserve stacktrace / reason.
        a.emit(|e| e.mov_mr(get_x_ref(0, 8), ARG2))?;
        a.mov_imm(ARG4, 1)?;
        a.aligned_call_label(garbage_collect)?;
        a.emit(|e| e.mov_rm(ARG2, get_x_ref(0, 8)))?;
        a.bind(after_gc)?;
        // make_arityval(2).
        a.emit(|e| e.mov_mi(qword_ptr(HTOP, 0), 2 << 6))?;
        a.emit(|e| e.mov_mi(qword_ptr(HTOP, 8), exit))?;
        a.emit(|e| e.mov_mr(qword_ptr(HTOP, 16), ARG2))?;
        a.emit(|e| e.lea(RET, qword_ptr(HTOP, 2)))?;
        a.emit(|e| e.add_ri(HTOP, 24))?;
        a.emit(|e| e.mov_mr(get_x_ref(0, 8), RET))?;
        a.emit_leave_frame()?;
        a.emit(|e| e.ret())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::x86::beam_asm::register::TMP1;
    use crate::x86::jdump::{beam_register, erts_dump, gnu_as, op_blocks};
    use arinsal_x64::buf::Section;

    /// Real boot modules whose dumps the x86 emitter tests compare against.
    const MODULES: [&str; 10] = [
        "lists",
        "maps",
        "gen_server",
        "proc_lib",
        "global_group",
        "erl_parse",
        "erl_eval",
        "io_lib_format",
        "io_lib",
        "application_controller",
    ];

    /// The `i_move_sd` operands of an erts block emitted with a fresh register cache: one
    /// store of an immediate, or a load into the first temporary (`TMP1`, r10) and its store.
    fn i_move_operands(block: &[String]) -> Option<(ArgVal, ArgVal)> {
        match block {
            [store] => {
                let (dst, imm) = store.strip_prefix("mov ")?.split_once(", ")?;
                Some((
                    ArgVal::Immediate(imm.parse::<i64>().ok()? as u64),
                    beam_register(dst)?,
                ))
            }
            [load, store] => {
                let (reg, src) = load.strip_prefix("mov ")?.split_once(", ")?;
                let (dst, reg2) = store.strip_prefix("mov ")?.split_once(", ")?;
                (reg == "r10" && reg2 == "r10").then_some(())?;
                Some((beam_register(src)?, beam_register(dst)?))
            }
            _ => None,
        }
    }

    fn emitted(f: impl FnOnce(&mut BeamModuleAssembler) -> Result<(), AsmError>) -> Vec<u8> {
        let mut m = BeamModuleAssembler::new(1);
        f(&mut m).unwrap();
        m.asm.a.bytes(Section::Code).to_vec()
    }

    // Differential check against erts: every `i_move_sd` and `i_trim_t` erts emitted for real
    // modules, whose operands can be read back from its text, encodes to the same bytes here.
    #[test]
    fn moves_and_trims_match_erts_dump() {
        let Some(dumps) = MODULES
            .iter()
            .map(|m| erts_dump(m))
            .collect::<Option<Vec<_>>>()
        else {
            eprintln!("skipping: `erl +JDdump true` unavailable");
            return;
        };
        let (mut moves, mut trims) = (0, 0);
        for dump in &dumps {
            for block in op_blocks(dump, "i_move_sd") {
                let Some((src, dst)) = i_move_operands(&block) else {
                    continue;
                };
                let Some(expected) = gnu_as(&block) else {
                    eprintln!("skipping: GNU binutils unavailable");
                    return;
                };
                assert_eq!(emitted(|m| m.emit_i_move(src, dst)), expected, "{block:?}");
                moves += 1;
            }
            for block in op_blocks(dump, "i_trim_t") {
                let [add] = block.as_slice() else { continue };
                let words = add
                    .strip_prefix("add rsp, ")
                    .unwrap()
                    .parse::<u32>()
                    .unwrap()
                    / 8;
                let expected = gnu_as(&block).unwrap();
                assert_eq!(
                    emitted(|m| m.emit_i_trim(ArgVal::Word(u64::from(words)))),
                    expected,
                    "{block:?}"
                );
                trims += 1;
            }
        }
        eprintln!("compared {moves} i_move_sd and {trims} i_trim_t blocks");
        assert!(
            moves > 1000 && trims > 50,
            "compared {moves} moves, {trims} trims"
        );
    }

    // erts' `self_d`: `common.id` is at offset 0 of erts' Process, `self_pid` in Arinsal's
    // `ProcessHeader`.
    #[test]
    fn self_matches_erts_dump() {
        let Some(dump) = erts_dump("lists").or_else(|| erts_dump("gen_server")) else {
            eprintln!("skipping: `erl +JDdump true` unavailable");
            return;
        };
        let mut compared = 0;
        for module in ["gen_server", "proc_lib", "gen", "application_master"] {
            let dump = erts_dump(module).unwrap_or_else(|| dump.clone());
            for block in op_blocks(&dump, "self_d") {
                let [load, store] = block.as_slice() else {
                    continue;
                };
                if load != "mov r10, qword ptr [r13]" {
                    continue;
                }
                let dst = beam_register(
                    store
                        .strip_prefix("mov ")
                        .unwrap()
                        .split_once(", ")
                        .unwrap()
                        .0,
                )
                .unwrap();
                let ours = [
                    format!("mov r10, qword ptr [r13+{}]", process::SELF_PID),
                    store.clone(),
                ];
                let Some(expected) = gnu_as(&ours) else {
                    return;
                };
                assert_eq!(emitted(|m| m.emit_self(dst)), expected, "{block:?}");
                compared += 1;
            }
        }
        assert!(compared > 0);
    }

    // erts' register cache: a store leaves the value cached, so a following load of the same
    // slot reuses the register ("skipped fetching of BEAM register").
    #[test]
    fn move_reuses_cached_register() {
        let bytes = emitted(|m| {
            m.emit_i_move(ArgVal::X(1), ArgVal::Y(0))?;
            m.emit_i_move(ArgVal::Y(0), ArgVal::X(2))
        });
        let expected = gnu_as(&[
            "mov r10, qword ptr [rbx+8]".into(),
            "mov qword ptr [rsp], r10".into(),
            "mov qword ptr [rbx+16], r10".into(),
        ]);
        if let Some(expected) = expected {
            assert_eq!(bytes, expected);
        }
    }

    fn dump_blocks(op: &str) -> Option<Vec<Vec<String>>> {
        let dumps = MODULES
            .iter()
            .map(|m| erts_dump(m))
            .collect::<Option<Vec<_>>>()?;
        Some(dumps.iter().flat_map(|d| full_op_blocks(d, op)).collect())
    }

    fn full_op_blocks(dump: &str, op: &str) -> Vec<Vec<String>> {
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
                let name = line.strip_prefix("# ").unwrap();
                if name == op || name.starts_with(&format!("{op}_")) {
                    current = Some(Vec::new());
                }
            } else if let Some(block) = current.as_mut()
                && !line.starts_with('#')
            {
                block.push(line.trim().to_owned());
            }
        }
        blocks.extend(current);
        blocks
    }

    fn parse_mem(operand: &str) -> Option<(&str, i32)> {
        let start = operand.find('[')? + 1;
        let end = operand[start..].find(']')? + start;
        let inner = &operand[start..end];
        let (base, disp) = if let Some((base, disp)) = inner.split_once('+') {
            (base, disp.parse::<i32>().ok()?)
        } else if let Some((base, disp)) = inner.split_once('-') {
            (base, -disp.parse::<i32>().ok()?)
        } else {
            (inner, 0)
        };
        Some((base, disp))
    }

    fn arg_slot(operand: &str) -> Option<ArgVal> {
        let (base, disp) = parse_mem(operand)?;
        if disp < 0 || disp % 8 != 0 {
            return None;
        }
        match base {
            "rbx" => Some(ArgVal::X((disp / 8) as u32)),
            "rsp" => Some(ArgVal::Y((disp / 8) as u32)),
            _ => None,
        }
    }

    fn source_slot(block: &[String]) -> Option<ArgVal> {
        for line in block {
            let Some((_, rhs)) = line.split_once(", ") else {
                continue;
            };
            if let Some(arg) = arg_slot(rhs) {
                return Some(arg);
            }
        }
        block.iter().find_map(|line| arg_slot(line))
    }

    fn stored_slots(block: &[String]) -> Vec<ArgVal> {
        block
            .iter()
            .filter_map(|line| {
                let (lhs, _) = line.split_once(", ")?;
                (lhs.starts_with("mov qword ptr [")
                    || lhs.starts_with("movups xmmword ptr [")
                    || lhs.starts_with("vmovups xmmword ptr ["))
                .then(|| arg_slot(lhs))
                .flatten()
            })
            .collect()
    }

    fn put_cons_args(block: &[String]) -> Option<(ArgVal, ArgVal)> {
        let mut regs = std::collections::HashMap::<String, ArgVal>::new();
        let mut vector = None;
        let mut values = [None, None];
        for line in block {
            if let Some(rest) = line.strip_prefix("mov ") {
                if let Some((dst, src)) = rest.split_once(", ") {
                    if let Some(arg) = arg_slot(src) {
                        regs.insert(dst.to_owned(), arg);
                    } else if let Some(value) =
                        src.parse::<i64>().ok().map(|v| ArgVal::Immediate(v as u64))
                    {
                        regs.insert(dst.to_owned(), value);
                    } else if let Some(value) = regs.get(src).copied() {
                        regs.insert(dst.to_owned(), value);
                    }
                    if let Some(("r15", offset)) = parse_mem(dst)
                        && (0..=8).contains(&offset)
                        && offset % 8 == 0
                    {
                        let index = (offset / 8) as usize;
                        values[index] = src
                            .parse::<i64>()
                            .ok()
                            .map(|v| ArgVal::Immediate(v as u64))
                            .or_else(|| regs.get(src).copied());
                    }
                }
            } else if line.starts_with("vmovups xmm0, xmmword ptr ")
                || line.starts_with("movups xmm0, xmmword ptr ")
            {
                let (_, src) = line.split_once(", ")?;
                let first = arg_slot(src)?;
                vector = Some((first, increment_slot(first, 1)?));
            } else if line.starts_with("vpermilpd xmm0, xmmword ptr ") {
                let (_, src) = line.split_once(", ")?;
                let first = arg_slot(src)?;
                vector = Some((increment_slot(first, 1)?, first));
            } else if line.starts_with("vmovups xmmword ptr [r15")
                || line.starts_with("movups xmmword ptr [r15")
            {
                let (dst, _) = line.split_once(", ")?;
                if let Some(("r15", 0)) = parse_mem(dst) {
                    values = [Some(vector?.0), Some(vector?.1)];
                }
            }
        }
        Some((values[0]?, values[1]?))
    }

    fn put_tuple2_args(block: &[String]) -> Option<(ArgVal, u64, Vec<ArgVal>)> {
        let mut regs = std::collections::HashMap::<String, ArgVal>::new();
        let mut vector = None;
        let mut arity_word = None;
        let mut args = Vec::new();
        let mut dst = None;
        for line in block {
            if let Some(rest) = line.strip_prefix("mov ") {
                let (lhs, rhs) = rest.split_once(", ")?;
                if let Some(("r15", offset)) = parse_mem(lhs) {
                    if offset == 0 {
                        arity_word = rhs.parse::<u64>().ok();
                    } else if offset >= 8 && offset % 8 == 0 {
                        let index = (offset / 8 - 1) as usize;
                        if args.len() <= index {
                            args.resize(index + 1, None);
                        }
                        args[index] = rhs
                            .parse::<i64>()
                            .ok()
                            .map(|v| ArgVal::Immediate(v as u64))
                            .or_else(|| regs.get(rhs).copied());
                    }
                } else if let Some(arg) = arg_slot(rhs) {
                    regs.insert(lhs.to_owned(), arg);
                } else if let Some(value) =
                    rhs.parse::<i64>().ok().map(|v| ArgVal::Immediate(v as u64))
                {
                    regs.insert(lhs.to_owned(), value);
                } else if let Some(value) = regs.get(rhs).copied() {
                    regs.insert(lhs.to_owned(), value);
                }
                if let Some(arg) = arg_slot(lhs) {
                    dst = Some(arg);
                }
            } else if line.starts_with("vmovups xmm0, xmmword ptr ")
                || line.starts_with("movups xmm0, xmmword ptr ")
            {
                let (_, src) = line.split_once(", ")?;
                let first = arg_slot(src)?;
                vector = Some((first, increment_slot(first, 1)?));
            } else if line.starts_with("vpermilpd xmm0, xmmword ptr ") {
                let (_, src) = line.split_once(", ")?;
                let first = arg_slot(src)?;
                vector = Some((increment_slot(first, 1)?, first));
            } else if line.starts_with("vmovups xmmword ptr [r15")
                || line.starts_with("movups xmmword ptr [r15")
            {
                let (lhs, _) = line.split_once(", ")?;
                let (base, offset) = parse_mem(lhs)?;
                if base == "r15" {
                    let first = (offset / 8).checked_sub(1)? as usize;
                    if first + 1 < args.len() {
                        let pair = vector?;
                        args[first] = Some(pair.0);
                        args[first + 1] = Some(pair.1);
                    }
                }
            }
        }
        let arity_word = arity_word?;
        let arity = (arity_word >> 6) as usize;
        let args = args.into_iter().collect::<Option<Vec<_>>>()?;
        (args.len() == arity).then_some((dst?, arity_word, args))
    }

    fn increment_slot(arg: ArgVal, words: i32) -> Option<ArgVal> {
        match arg {
            ArgVal::X(index) => u32::try_from(i64::from(index) + i64::from(words))
                .ok()
                .map(ArgVal::X),
            ArgVal::Y(index) => u32::try_from(i64::from(index) + i64::from(words))
                .ok()
                .map(ArgVal::Y),
            _ => None,
        }
    }

    fn destination_pair(block: &[String]) -> Option<(ArgVal, ArgVal)> {
        let stored = stored_slots(block);
        if stored.len() >= 2 {
            return Some((stored[0], stored[1]));
        }
        let first = *stored.first()?;
        if block.iter().any(|line| line.contains("vpermilpd")) {
            Some((increment_slot(first, 1)?, first))
        } else {
            Some((first, increment_slot(first, 1)?))
        }
    }

    fn tuple_element_offset(block: &[String]) -> Option<i32> {
        for line in block {
            let (_, rhs) = line.split_once(", ").unwrap_or(("", line.as_str()));
            let Some((base, disp)) = parse_mem(rhs) else {
                continue;
            };
            if base == "rsi" {
                return disp.checked_add(i32::from(TAG_PRIMARY_BOXED));
            }
        }
        None
    }

    fn cmp_immediates(block: &[String]) -> Vec<u64> {
        block
            .iter()
            .filter_map(|line| line.strip_prefix("cmp ")?.split_once(", ")?.1.parse().ok())
            .collect()
    }

    fn jump_target(line: &str) -> Option<&str> {
        let mut words = line.split_whitespace();
        let first = words.next()?;
        let instruction = if first == "short" || first == "long" {
            words.next()?
        } else {
            first
        };
        if !instruction.starts_with('j') {
            return None;
        }
        let target = line.split_whitespace().last()?.trim_end_matches(',');
        (target.starts_with('L') || target.starts_with("label_")).then_some(target)
    }

    fn external_labels(block: &[String]) -> Vec<String> {
        let defined: std::collections::HashSet<&str> = block
            .iter()
            .filter_map(|line| line.strip_suffix(':'))
            .collect();
        let mut labels = Vec::new();
        for target in block.iter().filter_map(|line| jump_target(line)) {
            if !defined.contains(target) && !labels.iter().any(|label| label == target) {
                labels.push(target.to_owned());
            }
        }
        labels
    }

    fn assert_block_matches(
        block: &[String],
        emit: impl FnOnce(&mut BeamModuleAssembler) -> Result<(), AsmError>,
    ) -> bool {
        assert_block_matches_with_labels(block, |m, _| emit(m))
    }

    fn assert_block_matches_with_labels(
        block: &[String],
        emit: impl FnOnce(&mut BeamModuleAssembler, &[u32]) -> Result<(), AsmError>,
    ) -> bool {
        const FILLER: usize = 48;
        let labels = external_labels(block);
        let mut expected_lines = block.to_vec();
        for (index, label) in labels.iter().enumerate() {
            let replacement = format!("fail{index}");
            for line in &mut expected_lines {
                *line = line.replace(label, &replacement);
                if let Some(instruction) = line
                    .strip_prefix("short ")
                    .or_else(|| line.strip_prefix("long "))
                    .filter(|instruction| instruction.starts_with('j'))
                {
                    *line = instruction.to_owned();
                }
            }
        }
        for (index, _) in labels.iter().enumerate() {
            expected_lines.extend(std::iter::repeat_n("mov r10, r10".to_owned(), FILLER));
            expected_lines.push(format!("fail{index}:"));
        }
        let Some(expected) = gnu_as(&expected_lines) else {
            return false;
        };

        let mut m = BeamModuleAssembler::new(4);
        let fail_labels: Vec<u32> = (1..=labels.len() as u32).collect();
        if emit(&mut m, &fail_labels).is_err() {
            return false;
        }
        for index in 0..labels.len() {
            for _ in 0..FILLER {
                if m.asm.emit(|e| e.mov_rr(TMP1, TMP1)).is_err() {
                    return false;
                }
            }
            let Some(label) = m.resolve_beam_label(index as u32 + 1) else {
                return false;
            };
            if m.asm.bind(label).is_err() {
                return false;
            }
        }
        m.asm.a.bytes(Section::Code) == expected
    }

    fn assert_source_op_matches(
        op: &str,
        emit: impl Fn(&mut BeamModuleAssembler, &[String], ArgVal) -> Result<(), AsmError>,
    ) {
        let Some(blocks) = dump_blocks(op) else {
            eprintln!("skipping: `erl +JDdump true` unavailable");
            return;
        };
        let matched = blocks.iter().any(|block| {
            let Some(src) = source_slot(block) else {
                return false;
            };
            assert_block_matches(block, |m| emit(m, block, src))
        });
        assert!(matched, "no byte-identical erts dump block for {op}");
    }

    fn assert_source_pair_op_matches(
        op: &str,
        emit: impl Fn(
            &mut BeamModuleAssembler,
            &[String],
            ArgVal,
            ArgVal,
            ArgVal,
        ) -> Result<(), AsmError>,
    ) {
        let Some(blocks) = dump_blocks(op) else {
            eprintln!("skipping: `erl +JDdump true` unavailable");
            return;
        };
        let matched = blocks.iter().any(|block| {
            let Some(src) = source_slot(block) else {
                return false;
            };
            let Some((dst1, dst2)) = destination_pair(block) else {
                return false;
            };
            assert_block_matches(block, |m| emit(m, block, src, dst1, dst2))
        });
        assert!(matched, "no byte-identical erts dump block for {op}");
    }

    const TYPE_VARIANTS: [u16; 20] = [
        type_id::ANY,
        type_id::ATOM,
        type_id::BITSTRING,
        type_id::CONS,
        type_id::FLOAT,
        type_id::FUN,
        type_id::INTEGER,
        type_id::MAP,
        type_id::NIL,
        type_id::PID,
        type_id::PORT,
        type_id::REFERENCE,
        type_id::TUPLE,
        type_id::RECORD,
        type_id::ALWAYS_BOXED,
        type_id::INTEGER | type_id::ALWAYS_BOXED,
        type_id::ATOM | type_id::ALWAYS_BOXED,
        type_id::BITSTRING | type_id::ALWAYS_BOXED,
        type_id::PID | type_id::ALWAYS_BOXED,
        type_id::PORT | type_id::ALWAYS_BOXED,
    ];

    fn assert_typed_source_op_matches(
        op: &str,
        emit: impl Fn(&mut BeamModuleAssembler, &[String], u32, TypedArg) -> Result<(), AsmError>,
    ) {
        let Some(blocks) = dump_blocks(op) else {
            eprintln!("skipping: `erl +JDdump true` unavailable");
            return;
        };
        let matched = blocks.iter().any(|block| {
            let Some(src) = source_slot(block) else {
                return false;
            };
            TYPE_VARIANTS.iter().copied().any(|union_bits| {
                let src = TypedArg::new(
                    src,
                    crate::common::types::ArgType {
                        union_bits,
                        min: None,
                        max: None,
                    },
                );
                assert_block_matches(block, |m| emit(m, block, 1, src))
            })
        });
        assert!(matched, "no byte-identical erts dump block for {op}");
    }

    fn assert_typed_two_label_op_matches(
        op: &str,
        emit: impl Fn(&mut BeamModuleAssembler, u32, u32, TypedArg, &[u64]) -> Result<(), AsmError>,
    ) {
        let Some(blocks) = dump_blocks(op) else {
            eprintln!("skipping: `erl +JDdump true` unavailable");
            return;
        };
        let matched = blocks.iter().any(|block| {
            let Some(src) = source_slot(block) else {
                return false;
            };
            let immediates = cmp_immediates(block);
            TYPE_VARIANTS.iter().copied().any(|union_bits| {
                let src = TypedArg::new(
                    src,
                    crate::common::types::ArgType {
                        union_bits,
                        min: None,
                        max: None,
                    },
                );
                assert_block_matches_with_labels(block, |m, labels| {
                    if labels.len() != 2 {
                        return Err(AsmError::Operand("expected two external failure labels"));
                    }
                    emit(m, labels[0], labels[1], src, &immediates)
                })
            })
        });
        assert!(matched, "no byte-identical erts dump block for {op}");
    }

    fn mem_operand(text: &str) -> Option<ArgVal> {
        beam_register(&text.replace("xmmword ptr", "qword ptr"))
    }

    fn assert_matches(block: &[String], ours: Vec<u8>) {
        let text: Vec<String> = block
            .iter()
            .map(|l| {
                l.replace("rep stos qword ptr [rdi], rax", "rep stosq")
                    .replace("stos qword ptr [rdi], rax", "stosq")
            })
            .collect();
        if let Some(expected) = gnu_as(&text) {
            assert_eq!(ours, expected, "{block:?}");
        }
    }

    // init_yregs: the Y registers are read back by replaying erts' stores (`rdi` tracking).
    #[test]
    fn init_yregs_matches_erts_dump() {
        let Some(blocks) = dump_blocks("init_yregs_I") else {
            eprintln!("skipping: `erl +JDdump true` unavailable");
            return;
        };
        let mut compared = 0;
        for block in blocks {
            let mut ys = Vec::new();
            let mut rdi = 0u32;
            let mut count = 0u32;
            for line in &block {
                if let Some(rest) = line.strip_prefix("mov qword ptr ") {
                    ys.push(
                        beam_register(&format!("qword ptr {}", rest.split_once(", ").unwrap().0))
                            .unwrap(),
                    );
                } else if line == "mov rdi, rsp" {
                    rdi = 0;
                } else if let Some(mem) = line.strip_prefix("lea rdi, ") {
                    let ArgVal::Y(y) = beam_register(mem).unwrap() else {
                        panic!()
                    };
                    rdi = y;
                } else if let Some(n) = line.strip_prefix("add rdi, ") {
                    rdi += n.parse::<u32>().unwrap() / 8;
                } else if let Some(n) = line.strip_prefix("mov ecx, ") {
                    count = n.parse().unwrap();
                } else if line.starts_with("rep stos") {
                    ys.extend((rdi..rdi + count).map(ArgVal::Y));
                    rdi += count;
                } else if line.starts_with("stos") {
                    ys.push(ArgVal::Y(rdi));
                    rdi += 1;
                }
            }
            let ys: Vec<u32> = ys
                .into_iter()
                .map(|y| match y {
                    ArgVal::Y(y) => y,
                    _ => panic!(),
                })
                .collect();
            let args: Vec<ArgVal> = ys.iter().map(|y| ArgVal::Y(*y)).collect();
            let size = ArgVal::Word(args.len() as u64);
            assert_matches(&block, emitted(|m| m.emit_init_yregs(size, &args)));
            compared += 1;
        }
        assert!(compared > 50, "compared {compared}");
    }

    // move_two_words and swap on an AVX host: one `vmovups`/`vpermilpd` load and one store.
    #[test]
    fn move_two_words_and_swap_match_erts_dump() {
        let (Some(moves), Some(swaps)) =
            (dump_blocks("move_two_words_sdsd"), dump_blocks("swap_dd"))
        else {
            eprintln!("skipping: `erl +JDdump true` unavailable");
            return;
        };
        if !BeamAssembler::has_cpu_feature(CpuFeature::Avx) {
            return;
        }
        let next = |arg: ArgVal| match arg {
            ArgVal::X(i) => ArgVal::X(i + 1),
            ArgVal::Y(i) => ArgVal::Y(i + 1),
            other => other,
        };
        let mut compared = 0;
        for block in moves {
            let [load, store] = block.as_slice() else {
                continue;
            };
            let src = load
                .split_once(", ")
                .and_then(|(_, m)| mem_operand(m.trim_end_matches(", 1")));
            let dst = store
                .strip_prefix("vmovups ")
                .and_then(|rest| mem_operand(rest.split_once(", ")?.0));
            let (Some(src), Some(dst)) = (src, dst) else {
                continue;
            };
            let ours = if load.starts_with("vpermilpd") {
                emitted(|m| m.emit_move_two_words(src, next(dst), next(src), dst))
            } else {
                emitted(|m| m.emit_move_two_words(src, dst, next(src), next(dst)))
            };
            assert_matches(&block, ours);
            compared += 1;
        }
        for block in swaps {
            let operands = match block.as_slice() {
                [load, _] if load.starts_with("vpermilpd ") => {
                    let r = load
                        .split_once(", ")
                        .and_then(|(_, m)| mem_operand(m.trim_end_matches(", 1")));
                    r.map(|r| (r, next(r)))
                }
                [l1, l2, _, _] => l1
                    .strip_prefix("mov rdi, ")
                    .and_then(beam_register)
                    .zip(l2.strip_prefix("mov rsi, ").and_then(beam_register)),
                _ => None,
            };
            let Some((r1, r2)) = operands else { continue };
            assert_matches(&block, emitted(|m| m.emit_swap(r1, r2)));
            compared += 1;
        }
        assert!(compared > 100, "compared {compared}");
    }

    #[test]
    fn list_tuple_and_constructor_emitters_match_erts_dumps() {
        assert_source_op_matches("get_hd_Sd", |m, block, src| {
            let Some(dst) = stored_slots(block).first().copied() else {
                return Err(AsmError::Operand("head destination missing"));
            };
            m.emit_get_hd(src, dst)
        });
        assert_source_op_matches("get_tl_Sd", |m, block, src| {
            let Some(dst) = stored_slots(block).first().copied() else {
                return Err(AsmError::Operand("tail destination missing"));
            };
            m.emit_get_tl(src, dst)
        });
        assert_source_pair_op_matches("get_list_Sdd", |m, _, src, hd, tl| {
            m.emit_get_list(src, hd, tl)
        });
        assert_source_op_matches("load_tuple_ptr_s", |m, _, src| {
            m.emit_load_tuple_ptr(TypedArg::from(src))
        });
        assert_source_pair_op_matches("is_nonempty_list_get_list_fSdd", |m, _, src, hd, tl| {
            m.emit_is_nonempty_list_get_list(ArgVal::Label(1), src, hd, tl)
        });
        assert_source_op_matches("is_nonempty_list_get_hd_fSd", |m, block, src| {
            let Some(dst) = stored_slots(block).first().copied() else {
                return Err(AsmError::Operand("head destination missing"));
            };
            m.emit_is_nonempty_list_get_hd(ArgVal::Label(1), src, dst)
        });
        assert_source_op_matches("is_nonempty_list_get_tl_fSd", |m, block, src| {
            let Some(dst) = stored_slots(block).first().copied() else {
                return Err(AsmError::Operand("tail destination missing"));
            };
            m.emit_is_nonempty_list_get_tl(ArgVal::Label(1), src, dst)
        });

        let Some(blocks) = dump_blocks("i_get_tuple_element_sPS") else {
            eprintln!("skipping: `erl +JDdump true` unavailable");
            return;
        };
        let matched = blocks.iter().any(|block| {
            let Some(offset) = tuple_element_offset(block) else {
                return false;
            };
            let Some(dst) = stored_slots(block).first().copied() else {
                return false;
            };
            assert_block_matches(block, |m| {
                m.emit_i_get_tuple_element(
                    TypedArg::from(ArgVal::X(0)),
                    ArgVal::Word(offset as u64),
                    dst,
                )
            })
        });
        assert!(
            matched,
            "no byte-identical erts dump block for i_get_tuple_element"
        );

        let Some(blocks) = dump_blocks("get_tuple_element_swap_sPdd") else {
            eprintln!("skipping: `erl +JDdump true` unavailable");
            return;
        };
        let matched = blocks.iter().any(|block| {
            let Some(offset) = tuple_element_offset(block) else {
                return false;
            };
            let slots = stored_slots(block);
            let [dst, other_dst, ..] = slots.as_slice() else {
                return false;
            };
            assert_block_matches(block, |m| {
                m.emit_get_tuple_element_swap(
                    TypedArg::from(ArgVal::X(0)),
                    ArgVal::Word(offset as u64),
                    *dst,
                    *other_dst,
                )
            })
        });
        assert!(
            matched,
            "no byte-identical erts dump block for get_tuple_element_swap"
        );

        assert_source_pair_op_matches(
            "get_two_tuple_elements_sPSS",
            |m, block, src, dst1, dst2| {
                let offset = tuple_element_offset(block)
                    .ok_or(AsmError::Operand("tuple field offset not found"))?;
                m.emit_get_two_tuple_elements(
                    TypedArg::from(src),
                    ArgVal::Word(offset as u64),
                    dst1,
                    dst2,
                )
            },
        );

        let Some(blocks) = dump_blocks("put_cons_ss") else {
            eprintln!("skipping: `erl +JDdump true` unavailable");
            return;
        };
        let matched = blocks.iter().any(|block| {
            let Some((hd, tl)) = put_cons_args(block) else {
                return false;
            };
            assert_block_matches(block, |m| m.emit_put_cons(hd, tl))
        });
        assert!(matched, "no byte-identical erts dump block for put_cons");

        let Some(blocks) = dump_blocks("put_tuple2_SA") else {
            eprintln!("skipping: `erl +JDdump true` unavailable");
            return;
        };
        let matched = blocks.iter().any(|block| {
            let Some((dst, arity_word, args)) = put_tuple2_args(block) else {
                return false;
            };
            assert_block_matches(block, |m| {
                m.emit_put_tuple2(dst, ArgVal::Word(arity_word), &args)
            })
        });
        assert!(matched, "no byte-identical erts dump block for put_tuple2");
    }

    #[test]
    fn no_c_type_test_emitters_match_erts_dumps() {
        assert_source_op_matches("is_nonempty_list_fS", |m, _, src| {
            m.emit_is_nonempty_list(ArgVal::Label(1), src)
        });
        assert_typed_source_op_matches("is_atom_fs", |m, _, fail, src| {
            m.emit_is_atom(ArgVal::Label(fail), src)
        });
        assert_typed_source_op_matches("is_boolean_fs", |m, _, fail, src| {
            m.emit_is_boolean(ArgVal::Label(fail), src)
        });
        assert_typed_source_op_matches("is_bitstring_fs", |m, _, fail, src| {
            m.emit_is_bitstring(ArgVal::Label(fail), src)
        });
        assert_typed_source_op_matches("is_binary_fs", |m, _, fail, src| {
            m.emit_is_binary(ArgVal::Label(fail), src)
        });
        assert_typed_source_op_matches("is_float_fs", |m, _, fail, src| {
            m.emit_is_float(ArgVal::Label(fail), src)
        });
        assert_typed_source_op_matches("is_function_fS", |m, _, fail, src| {
            m.emit_is_function(ArgVal::Label(fail), src)
        });
        assert_typed_source_op_matches("is_integer_fs", |m, _, fail, src| {
            m.emit_is_integer(ArgVal::Label(fail), src)
        });
        assert_typed_source_op_matches("is_list_fs", |m, _, fail, src| {
            m.emit_is_list(ArgVal::Label(fail), src)
        });
        assert_typed_source_op_matches("is_map_fs", |m, _, fail, src| {
            m.emit_is_map(ArgVal::Label(fail), src)
        });
        assert_source_op_matches("is_nil_fS", |m, _, src| {
            m.emit_is_nil(ArgVal::Label(1), src)
        });
        assert_typed_source_op_matches("is_number_fs", |m, _, fail, src| {
            m.emit_is_number(ArgVal::Label(fail), src)
        });
        assert_typed_source_op_matches("is_pid_fs", |m, _, fail, src| {
            m.emit_is_pid(ArgVal::Label(fail), src)
        });
        assert_typed_source_op_matches("is_port_fs", |m, _, fail, src| {
            m.emit_is_port(ArgVal::Label(fail), src)
        });
        assert_typed_source_op_matches("is_reference_fs", |m, _, fail, src| {
            m.emit_is_reference(ArgVal::Label(fail), src)
        });
        assert_typed_source_op_matches("i_is_tuple_fs", |m, _, fail, src| {
            m.emit_i_is_tuple(ArgVal::Label(fail), src)
        });
        assert_typed_source_op_matches("i_is_tuple_of_arity_fsA", |m, block, fail, src| {
            let Some(arity) = cmp_immediates(block).first().copied() else {
                return Err(AsmError::Operand("tuple arity missing"));
            };
            m.emit_i_is_tuple_of_arity(ArgVal::Label(fail), src, ArgVal::Word(arity))
        });
        assert_typed_two_label_op_matches(
            "i_is_tuple_of_arity_ff_ffsA",
            |m, not_tuple, bad_arity, src, immediates| {
                let Some(arity) = immediates.first().copied() else {
                    return Err(AsmError::Operand("tuple arity missing"));
                };
                m.emit_i_is_tuple_of_arity_ff(
                    ArgVal::Label(not_tuple),
                    ArgVal::Label(bad_arity),
                    src,
                    ArgVal::Word(arity),
                )
            },
        );
        assert_typed_two_label_op_matches(
            "i_is_tagged_tuple_ff_ffsAa",
            |m, not_tuple, not_record, src, immediates| {
                let [arity, tag, ..] = immediates else {
                    return Err(AsmError::Operand("tagged tuple values missing"));
                };
                m.emit_i_is_tagged_tuple_ff(
                    ArgVal::Label(not_tuple),
                    ArgVal::Label(not_record),
                    src,
                    ArgVal::Word(*arity),
                    ArgVal::Word(*tag),
                )
            },
        );
        assert_typed_source_op_matches("i_is_tagged_tuple_fsAa", |m, block, fail, src| {
            let immediates = cmp_immediates(block);
            let [arity, tag, ..] = immediates.as_slice() else {
                return Err(AsmError::Operand("tagged tuple values missing"));
            };
            m.emit_i_is_tagged_tuple(
                ArgVal::Label(fail),
                src,
                ArgVal::Word(*arity),
                ArgVal::Word(*tag),
            )
        });
        assert_typed_source_op_matches("i_test_arity_fsA", |m, block, fail, src| {
            let Some(arity) = cmp_immediates(block).first().copied() else {
                return Err(AsmError::Operand("tuple arity missing"));
            };
            m.emit_i_test_arity(ArgVal::Label(fail), src, ArgVal::Word(arity))
        });
    }
}
