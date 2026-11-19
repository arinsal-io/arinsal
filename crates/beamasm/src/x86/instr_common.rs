//! Port of erts/emulator/beam/jit/x86/instr_common.cpp, OTP-29.1.1: the move, trim and jump
//! instructions of box I1 so far. Every `emit_*` here is one erts `BeamModuleAssembler::emit_*`,
//! and the global fragments `raise_shared` and `catch_end_shared`.

use arinsal_x64::enc::{self, Xmm};

use arinsal_term::{Term, atoms};
use arinsal_x64::enc::{CondCode, Mem, qword_ptr};

use super::beam_asm::register::{
    ARG1, ARG1D, ARG2, ARG2D, ARG3, ARG3D, ARG4, ARG5, ARG5D, C_P, E, HTOP, RET, RETB, RETD,
};
use super::beam_asm::{
    AsmError, BeamAssembler, CpuFeature, Distance, TAG_PRIMARY_BOXED, TAG_PRIMARY_LIST,
    TAG_PRIMARY_MASK, emit_boxed_val, get_arg_ref, get_car_ref, get_cdr_ref, get_y_ref, process,
    process_ref, tmp_mem_q,
};
use super::beam_asm::{Update, get_x_ref};
use super::beam_asm_global::{BeamGlobalAssembler, GlobalLabels};
use super::beam_asm_module::{BeamModuleAssembler, Patch, PatchCatch, arg_label, arg_word};
pub use super::rt::{
    add_stacktrace, build_stacktrace, erl_is_function, erts_cmp_atoms, erts_cmp_compound,
    erts_continue_exit_process, erts_do_exit_process, erts_pd_hash_get, erts_pd_hash_get_with_hx,
    erts_sanitize_freason, perf_counter_address, raw_raise,
};
use crate::common::args::ArgVal;
use crate::common::args::{Relation, memory_relation};
use crate::common::types::{BeamModuleAssemblerCommon, type_id};
use arinsal_term::TermKind;
use arinsal_term::raw::{Cons, Tuple, bitstring_extent, term_from_bits};

const NIL: i64 = 0x3b;
const TAG_IMMED1_MASK: i64 = 0x0f;
const TAG_IMMED1_SMALL: i64 = 0x0f;
const TAG_IMMED1_PID: i64 = 0x03;
const TAG_IMMED1_PORT: i64 = 0x07;
const TAG_IMMED2_MASK: i64 = 0x3f;
const TAG_IMMED2_ATOM: i64 = 0x0b;
const TAG_HEADER_MASK: i64 = 0x3f;
const TAG_PTR_MASK: i64 = 0x7;
const TAG_HEADER_POS_BIG: i64 = 0x08;
const TAG_HEADER_REF: i64 = 0x10;
const TAG_HEADER_FLOAT: i64 = 0x58;
const TAG_HEADER_FLOAT_MASKED: i64 = TAG_HEADER_FLOAT & TAG_HEADER_MASK;
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
const HEADER_ARITY_OFFS: i64 = 6;
const FUN_HEADER_ARITY_OFFS: i64 = HEADER_ARITY_OFFS + 2;
const TAG_HEADER_NEG_BIG: i64 = 0x0c;
const TAG_HEADER_FLONUM: i64 = 0x58;
const TAG_IMMED1_SIZE: i64 = 4;
const MAP_HEADER_FLATMAP: i64 = 0x12c;
const SUB_BITS_START_OFFSET: i32 = 16;
const SUB_BITS_END_OFFSET: i32 = 24;
const ERTS_MAX_UINT64_HEAP_SIZE: u64 = 2;
const POS_BIGNUM_HEADER_ONE_DIGIT: i64 = (1 << HEADER_ARITY_OFFS) | TAG_HEADER_POS_BIG;

fn is_int32(value: i64) -> bool {
    value as i32 as i64 == value
}

fn literal_is_list_of_immediates(term: arinsal_term::Term) -> Option<(usize, arinsal_term::Term)> {
    let mut current = term;
    let mut len = 0;
    let mut first = None;
    loop {
        if current == arinsal_term::Term::NIL {
            return Some((len, first.unwrap_or(arinsal_term::Term::NIL)));
        }
        let cell = Cons::try_from(current).ok()?;
        let head = cell.head();
        if !head.is_immed() {
            return None;
        }
        first.get_or_insert(head);
        len += 1;
        current = cell.tail();
    }
}

fn literal_is_shallow_boxed(term: arinsal_term::Term) -> bool {
    if term.classify() == TermKind::Tuple {
        return Tuple::try_from(term)
            .is_ok_and(|tuple| tuple.elements().all(|value| value.is_immed()));
    }
    let Some(header) = term.header() else {
        return false;
    };
    let subtag = (header as i64) & BIG_TAG_MASK;
    matches!(subtag, TAG_HEADER_POS_BIG | TAG_HEADER_NEG_BIG) || header as i64 == TAG_HEADER_FLONUM
}

fn literal_is_empty_bitstring(term: arinsal_term::Term) -> bool {
    bitstring_extent(term).is_some_and(|(_, bits)| bits == 0)
}

fn literal_is_empty_map(term: arinsal_term::Term) -> bool {
    term.classify() == TermKind::Map
        && term.is_flatmap()
        && term
            .flatmap_keys_tuple()
            .and_then(|keys| Tuple::try_from(keys).ok())
            .is_some_and(|tuple| tuple.arity() == 0)
}

fn emit_vmovsd(
    m: &mut BeamAssembler,
    dst: arinsal_x64::enc::Xmm,
    src: arinsal_x64::enc::Mem,
) -> Result<(), AsmError> {
    if BeamAssembler::has_cpu_feature(CpuFeature::Avx) {
        m.emit(|e| e.vmovsd_xm(dst, src))
    } else {
        m.emit(|e| e.movsd_xm(dst, src))
    }
}

fn emit_vucomisd_xx(
    m: &mut BeamAssembler,
    lhs: arinsal_x64::enc::Xmm,
    rhs: arinsal_x64::enc::Xmm,
) -> Result<(), AsmError> {
    if BeamAssembler::has_cpu_feature(CpuFeature::Avx) {
        m.emit(|e| e.vucomisd_xx(lhs, rhs))
    } else {
        m.emit(|e| e.ucomisd_xx(lhs, rhs))
    }
}

fn arg_ref(arg: ArgVal, size: u8) -> Result<Mem, AsmError> {
    get_arg_ref(arg, size).ok_or(AsmError::Operand("BEAM register operand"))
}

fn immediate_word(arg: ArgVal) -> Result<i64, AsmError> {
    match arg {
        ArgVal::Immediate(word) => Ok(word as i64),
        _ => Err(AsmError::Operand("immediate operand")),
    }
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
            .map(|arg| match arg.reg() {
                Some(y) if arg.is_y_register() => Ok(y),
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
    pub fn emit_load_tuple_ptr(&mut self, term: ArgVal) -> Result<(), AsmError> {
        self.mov_arg_to_reg(ARG2, term)?;
        self.asm.emit_ptr_val(ARG2, ARG2);
        Ok(())
    }

    /// Fetches one tuple element from the tuple pointer already in ARG2.
    // Port of erts/emulator/beam/jit/x86/instr_common.cpp:480-495
    // (emit_i_get_tuple_element), OTP-29.1.1.
    pub fn emit_i_get_tuple_element(
        &mut self,
        _src: ArgVal,
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
        _src: ArgVal,
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
        _src: ArgVal,
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
    pub(crate) fn emit_is_boxed_source(
        &mut self,
        fail: arinsal_x64::buf::Label,
        source: ArgVal,
        reg: arinsal_x64::enc::Gp,
        distance: Distance,
    ) -> Result<(), AsmError> {
        if self.always_one_of(source, type_id::ALWAYS_BOXED) {
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
    pub fn emit_is_atom(&mut self, fail: ArgVal, src: ArgVal) -> Result<(), AsmError> {
        let fail = self
            .resolve_beam_label(arg_label(fail)?)
            .ok_or(AsmError::Operand("atom test to an unknown label"))?;
        self.mov_arg_to_reg(RET, src)?;
        if self.always_one_of(src, type_id::ATOM | type_id::ALWAYS_BOXED) {
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
    pub fn emit_is_boolean(&mut self, fail: ArgVal, src: ArgVal) -> Result<(), AsmError> {
        let fail = self
            .resolve_beam_label(arg_label(fail)?)
            .ok_or(AsmError::Operand("boolean test to an unknown label"))?;
        self.mov_arg_to_reg(ARG1, src)?;
        self.asm
            .emit(|e| e.and_ri(ARG1, !(AM_TRUE & !TAG_IMMED2_MASK)))?;
        self.asm.emit(|e| e.cmp_ri(ARG1, AM_FALSE))?;
        self.asm.jcc(CondCode::NE, fail)
    }

    /// Tests whether Src is any bitstring.
    // Port of erts/emulator/beam/jit/x86/instr_common.cpp:1177-1198
    // (emit_is_bitstring), OTP-29.1.1.
    pub fn emit_is_bitstring(&mut self, fail: ArgVal, src: ArgVal) -> Result<(), AsmError> {
        let fail = self
            .resolve_beam_label(arg_label(fail)?)
            .ok_or(AsmError::Operand("bitstring test to an unknown label"))?;
        self.mov_arg_to_reg(ARG1, src)?;
        self.emit_is_boxed_source(fail, src, ARG1, Distance::Long)?;
        if self.masked_types(src, type_id::MAYBE_BOXED) == type_id::BITSTRING {
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
    pub fn emit_is_binary(&mut self, fail: ArgVal, src: ArgVal) -> Result<(), AsmError> {
        let fail = self
            .resolve_beam_label(arg_label(fail)?)
            .ok_or(AsmError::Operand("binary test to an unknown label"))?;
        let not_sub_bits = self.asm.new_label();
        self.mov_arg_to_reg(ARG1, src)?;
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
        if self.masked_types(src, type_id::MAYBE_BOXED) != type_id::BITSTRING {
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
    pub fn emit_is_float(&mut self, fail: ArgVal, src: ArgVal) -> Result<(), AsmError> {
        let fail = self
            .resolve_beam_label(arg_label(fail)?)
            .ok_or(AsmError::Operand("float test to an unknown label"))?;
        self.mov_arg_to_reg(ARG1, src)?;
        self.emit_is_boxed_source(fail, src, ARG1, Distance::Long)?;
        if self.masked_types(src, type_id::MAYBE_BOXED) == type_id::FLOAT {
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
    pub fn emit_is_function(&mut self, fail: ArgVal, src: ArgVal) -> Result<(), AsmError> {
        let fail = self
            .resolve_beam_label(arg_label(fail)?)
            .ok_or(AsmError::Operand("function test to an unknown label"))?;
        self.mov_arg_to_reg(RET, src)?;
        self.emit_is_boxed_source(fail, src, RET, Distance::Long)?;
        if self.masked_types(src, type_id::MAYBE_BOXED) == type_id::FUN {
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
    pub fn emit_is_integer(&mut self, fail: ArgVal, src: ArgVal) -> Result<(), AsmError> {
        let fail = self
            .resolve_beam_label(arg_label(fail)?)
            .ok_or(AsmError::Operand("integer test to an unknown label"))?;
        if self.always_immediate(src) {
            self.mov_arg_to_reg(RET, src)?;
            return self.preserve_cache(&[RET], &[], |m| {
                m.asm.emit(|e| e.and_ri(RETB, TAG_IMMED1_MASK))?;
                m.asm.emit(|e| e.cmp_ri(RETB, TAG_IMMED1_SMALL))?;
                m.asm.jcc(CondCode::NE, fail)
            });
        }

        let next = self.asm.new_label();
        self.mov_arg_to_reg(ARG1, src)?;
        if self.always_one_of(src, type_id::INTEGER | type_id::ALWAYS_BOXED) {
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
        if self.masked_types(src, type_id::MAYBE_BOXED) != type_id::INTEGER {
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
    pub fn emit_is_list(&mut self, fail: ArgVal, src: ArgVal) -> Result<(), AsmError> {
        let fail = self
            .resolve_beam_label(arg_label(fail)?)
            .ok_or(AsmError::Operand("list test to an unknown label"))?;
        let next = self.asm.new_label();
        self.mov_arg_to_reg(RET, src)?;
        self.preserve_cache(&[], &[], |m| {
            m.asm.emit(|e| e.cmp_ri(RET, NIL))?;
            m.asm.short_jcc(CondCode::E, next)
        })?;
        self.asm.emit_is_cons(fail, RET, Distance::Long)?;
        self.asm.bind(next)
    }

    /// Tests whether Src is a map.
    // Port of erts/emulator/beam/jit/x86/instr_common.cpp:1412-1433 (emit_is_map), OTP-29.1.1.
    pub fn emit_is_map(&mut self, fail: ArgVal, src: ArgVal) -> Result<(), AsmError> {
        let fail = self
            .resolve_beam_label(arg_label(fail)?)
            .ok_or(AsmError::Operand("map test to an unknown label"))?;
        self.mov_arg_to_reg(ARG1, src)?;
        self.emit_is_boxed_source(fail, src, ARG1, Distance::Long)?;
        if self.masked_types(src, type_id::MAYBE_BOXED) == type_id::MAP {
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
    pub fn emit_is_number(&mut self, fail: ArgVal, src: ArgVal) -> Result<(), AsmError> {
        let fail = self
            .resolve_beam_label(arg_label(fail)?)
            .ok_or(AsmError::Operand("number test to an unknown label"))?;
        let next = self.asm.new_label();
        self.mov_arg_to_reg(ARG1, src)?;
        if self.always_one_of(src, type_id::INTEGER | type_id::ALWAYS_BOXED) {
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
        if self.masked_types(src, type_id::MAYBE_BOXED) != type_id::NUMBER {
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
    pub fn emit_is_pid(&mut self, fail: ArgVal, src: ArgVal) -> Result<(), AsmError> {
        let fail = self
            .resolve_beam_label(arg_label(fail)?)
            .ok_or(AsmError::Operand("pid test to an unknown label"))?;
        let next = self.asm.new_label();
        self.mov_arg_to_reg(ARG1, src)?;
        if self.always_one_of(src, type_id::PID | type_id::ALWAYS_BOXED) {
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
        if self.masked_types(src, type_id::MAYBE_BOXED) != type_id::PID {
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
    pub fn emit_is_port(&mut self, fail: ArgVal, src: ArgVal) -> Result<(), AsmError> {
        let fail = self
            .resolve_beam_label(arg_label(fail)?)
            .ok_or(AsmError::Operand("port test to an unknown label"))?;
        let next = self.asm.new_label();
        self.mov_arg_to_reg(ARG1, src)?;
        if self.always_one_of(src, type_id::PORT | type_id::ALWAYS_BOXED) {
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
        if self.masked_types(src, type_id::MAYBE_BOXED) != type_id::PORT {
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
    pub fn emit_is_reference(&mut self, fail: ArgVal, src: ArgVal) -> Result<(), AsmError> {
        let fail = self
            .resolve_beam_label(arg_label(fail)?)
            .ok_or(AsmError::Operand("reference test to an unknown label"))?;
        self.mov_arg_to_reg(ARG1, src)?;
        self.emit_is_boxed_source(fail, src, ARG1, Distance::Long)?;
        if self.masked_types(src, type_id::MAYBE_BOXED) != type_id::REFERENCE {
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
        src: ArgVal,
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
        self.mov_arg_to_reg(ARG2, src)?;
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
        src: ArgVal,
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
        self.mov_arg_to_reg(ARG2, src)?;
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
    pub fn emit_i_is_tuple(&mut self, fail: ArgVal, src: ArgVal) -> Result<(), AsmError> {
        let fail = self
            .resolve_beam_label(arg_label(fail)?)
            .ok_or(AsmError::Operand("tuple test to an unknown label"))?;
        self.mov_arg_to_reg(ARG2, src)?;
        if self.masked_types(src, type_id::MAYBE_BOXED) == type_id::TUPLE {
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
        src: ArgVal,
        arity_word: ArgVal,
    ) -> Result<(), AsmError> {
        let fail = self
            .resolve_beam_label(arg_label(fail)?)
            .ok_or(AsmError::Operand("tuple arity test to an unknown label"))?;
        let arity_word = i64::try_from(arg_word(arity_word)?)
            .map_err(|_| AsmError::Operand("tuple arity word"))?;
        self.mov_arg_to_reg(ARG2, src)?;
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
        src: ArgVal,
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
        self.mov_arg_to_reg(ARG2, src)?;
        let boxed_ptr = self.asm.emit_ptr_val(ARG2, ARG2);
        if self.masked_types(src, type_id::MAYBE_BOXED) == type_id::TUPLE {
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
        src: ArgVal,
        arity_word: ArgVal,
    ) -> Result<(), AsmError> {
        let fail = self
            .resolve_beam_label(arg_label(fail)?)
            .ok_or(AsmError::Operand("tuple arity test to an unknown label"))?;
        let arity_word = i64::try_from(arg_word(arity_word)?)
            .map_err(|_| AsmError::Operand("tuple arity word"))?;
        self.mov_arg_to_reg(ARG2, src)?;
        let boxed_ptr = self.asm.emit_ptr_val(ARG2, ARG2);
        self.preserve_cache(&[], &[], |m| {
            m.asm
                .emit(|e| e.cmp_mi(emit_boxed_val(boxed_ptr, 0, 4), arity_word))?;
            m.asm.jcc(CondCode::NE, fail)
        })
    }
}

impl BeamGlobalAssembler {
    /// Compares the literal cons chain element by element.
    // Port of erts/emulator/beam/jit/x86/instr_common.cpp:1728-1767
    // (emit_is_eq_exact_list_shared), OTP-29.1.1.
    pub(crate) fn emit_is_eq_exact_list_shared(&mut self) -> Result<(), AsmError> {
        let loop_label = self.asm.new_label();
        let mid = self.asm.new_label();
        let done = self.asm.new_label();
        self.asm.short_jmp(mid)?;
        self.asm.bind(loop_label)?;
        self.asm.emit_ptr_val(ARG1, ARG1);
        self.asm.emit_ptr_val(ARG2, ARG2);
        self.asm.emit(|e| e.mov_rm(RET, get_car_ref(ARG1, 8)))?;
        self.asm.emit(|e| e.mov_rm(ARG1, get_cdr_ref(ARG1, 8)))?;
        self.asm.emit(|e| e.cmp_mr(get_car_ref(ARG2, 8), RET))?;
        self.asm.short_jcc(CondCode::NE, done)?;
        self.asm.emit(|e| e.mov_rm(ARG2, get_cdr_ref(ARG2, 8)))?;
        self.asm.bind(mid)?;
        self.asm.emit(|e| e.cmp_rr(ARG1, ARG2))?;
        self.asm.short_jcc(CondCode::E, done)?;
        self.asm.emit(|e| e.mov_rr(RETD, ARG1D))?;
        self.asm.emit(|e| e.or_rr(RETD, ARG2D))?;
        self.asm.emit_is_not_cons(loop_label, RET, Distance::Long)?;
        self.asm.emit(|e| e.cmp_ri(RETB, 0))?;
        self.asm.bind(done)?;
        self.asm.emit(|e| e.ret())
    }

    /// Compares a literal tuple, bignum or float's heap words.
    // Port of erts/emulator/beam/jit/x86/instr_common.cpp:1770-1818
    // (emit_is_eq_exact_shallow_boxed_shared), OTP-29.1.1.
    pub(crate) fn emit_is_eq_exact_shallow_boxed_shared(&mut self) -> Result<(), AsmError> {
        let loop_label = self.asm.new_label();
        let done = self.asm.new_label();
        let not_equal = self.asm.new_label();
        self.asm.emit(|e| e.mov_rr(RETD, ARG1D))?;
        self.asm.emit(|e| e.or_rr(RETD, ARG2D))?;
        self.asm.emit_is_boxed(not_equal, RET, Distance::Long)?;
        self.asm.emit(|e| e.and_ri(ARG1, !TAG_PTR_MASK))?;
        self.asm.emit(|e| e.and_ri(ARG2, !TAG_PTR_MASK))?;
        self.asm.emit(|e| e.mov_rm(ARG3, qword_ptr(ARG1, 0)))?;
        self.asm.emit(|e| e.shr_ri(ARG3, HEADER_ARITY_OFFS))?;
        self.asm.emit(|e| e.dec_r(ARG3))?;
        self.asm.mov_imm(ARG4, 0)?;
        self.asm.bind(loop_label)?;
        if BeamAssembler::has_cpu_feature(CpuFeature::Avx) {
            self.asm
                .emit(|e| e.vmovdqu_xm(Xmm(0), Mem::base_index(ARG1, ARG4, 0, 0, 16)))?;
            self.asm
                .emit(|e| e.vpxor_xxm(Xmm(0), Xmm(0), Mem::base_index(ARG2, ARG4, 0, 0, 16)))?;
            self.asm.emit(|e| e.vptest_xx(Xmm(0), Xmm(0)))?;
        } else {
            let lhs0 = Mem::base_index(ARG1, ARG4, 0, 0, 8);
            let rhs0 = Mem::base_index(ARG2, ARG4, 0, 0, 8);
            let lhs1 = Mem::base_index(ARG1, ARG4, 0, 8, 8);
            let rhs1 = Mem::base_index(ARG2, ARG4, 0, 8, 8);
            self.asm.emit(|e| e.mov_rm(RET, lhs0))?;
            self.asm.emit(|e| e.cmp_rm(RET, rhs0))?;
            self.asm.short_jcc(CondCode::NE, done)?;
            self.asm.emit(|e| e.mov_rm(RET, lhs1))?;
            self.asm.emit(|e| e.cmp_rm(RET, rhs1))?;
        }
        self.asm.short_jcc(CondCode::NE, done)?;
        self.asm.emit(|e| e.add_ri(ARG4, 16))?;
        self.asm.emit(|e| e.sub_ri(ARG3, 2))?;
        self.asm.jcc(CondCode::GE, loop_label)?;
        self.asm.emit(|e| e.cmp_ri(ARG3.r8(), -2))?;
        self.asm.short_jcc(CondCode::E, done)?;
        let lhs = Mem::base_index(ARG1, ARG4, 0, 0, 8);
        let rhs = Mem::base_index(ARG2, ARG4, 0, 0, 8);
        self.asm.emit(|e| e.mov_rm(RET, lhs))?;
        self.asm.emit(|e| e.cmp_rm(RET, rhs))?;
        self.asm.bind(done)?;
        self.asm.emit(|e| e.ret())?;
        self.asm.bind(not_equal)?;
        self.asm.emit(|e| e.cmp_ri(RETB, 0))?;
        self.asm.emit(|e| e.ret())
    }
}

impl BeamGlobalAssembler {
    /// Compares numeric terms for arithmetic equality, returning flags for the caller.
    // Port of erts/emulator/beam/jit/x86/instr_common.cpp:2138-2179
    // (emit_arith_eq_shared), OTP-29.1.1.
    pub(crate) fn emit_arith_eq_shared(&mut self) -> Result<(), AsmError> {
        let generic = self.asm.new_label();
        self.asm.emit(|e| e.mov_rr(ARG3D, ARG1D))?;
        self.asm.emit(|e| e.or_rr(ARG3D, ARG2D))?;
        self.asm.emit(|e| e.and_ri(ARG3D, 1))?;
        self.asm.short_jcc(CondCode::NE, generic)?;
        let boxed = self.asm.emit_ptr_val(ARG3, ARG1);
        self.asm
            .emit(|e| e.mov_rm(ARG3, emit_boxed_val(boxed, 0, 8)))?;
        let boxed = self.asm.emit_ptr_val(ARG5, ARG2);
        self.asm
            .emit(|e| e.mov_rm(ARG5, emit_boxed_val(boxed, 0, 8)))?;
        self.asm.emit(|e| e.and_ri(ARG3D, TAG_HEADER_MASK))?;
        self.asm.emit(|e| e.and_ri(ARG5D, TAG_HEADER_MASK))?;
        self.asm
            .emit(|e| e.sub_ri(ARG3D, TAG_HEADER_FLOAT_MASKED))?;
        self.asm
            .emit(|e| e.sub_ri(ARG5D, TAG_HEADER_FLOAT_MASKED))?;
        self.asm.emit(|e| e.or_rr(ARG3D, ARG5D))?;
        self.asm.short_jcc(CondCode::NE, generic)?;

        let boxed = self.asm.emit_ptr_val(ARG1, ARG1);
        emit_vmovsd(&mut self.asm, Xmm(0), emit_boxed_val(boxed, 8, 8))?;
        let boxed = self.asm.emit_ptr_val(ARG2, ARG2);
        emit_vmovsd(&mut self.asm, Xmm(1), emit_boxed_val(boxed, 8, 8))?;
        emit_vucomisd_xx(&mut self.asm, Xmm(0), Xmm(1))?;
        self.asm.emit(|e| e.ret())?;

        self.asm.bind(generic)?;
        self.asm.emit_enter_runtime(Update::NONE)?;
        self.asm.mov_imm(ARG3, 0)?;
        self.asm.mov_imm(ARG4, 1)?;
        self.asm
            .runtime_call(erts_cmp_compound as *const () as usize)?;
        self.asm.emit_leave_runtime(Update::NONE)?;
        self.asm.emit(|e| e.test_rr(RET, RET))?;
        self.asm.emit(|e| e.ret())
    }

    /// Compares terms in Erlang term order, returning flags for the caller.
    // Port of erts/emulator/beam/jit/x86/instr_common.cpp:2222-2319
    // (emit_arith_compare_shared), OTP-29.1.1.
    pub(crate) fn emit_arith_compare_shared(&mut self) -> Result<(), AsmError> {
        let atom_compare = self.asm.new_label();
        let generic_compare = self.asm.new_label();
        self.asm.emit_enter_frame()?;

        self.asm.emit(|e| e.mov_rr(ARG3D, ARG1D))?;
        self.asm.emit(|e| e.or_rr(ARG3D, ARG2D))?;
        self.asm.emit(|e| e.and_ri(ARG3D, 1))?;
        self.asm.short_jcc(CondCode::NE, atom_compare)?;
        let boxed = self.asm.emit_ptr_val(ARG3, ARG1);
        self.asm
            .emit(|e| e.mov_rm(ARG3, emit_boxed_val(boxed, 0, 8)))?;
        let boxed = self.asm.emit_ptr_val(ARG5, ARG2);
        self.asm
            .emit(|e| e.mov_rm(ARG5, emit_boxed_val(boxed, 0, 8)))?;
        self.asm.emit(|e| e.and_ri(ARG3D, TAG_HEADER_MASK))?;
        self.asm.emit(|e| e.and_ri(ARG5D, TAG_HEADER_MASK))?;
        self.asm
            .emit(|e| e.sub_ri(ARG3D, TAG_HEADER_FLOAT_MASKED))?;
        self.asm
            .emit(|e| e.sub_ri(ARG5D, TAG_HEADER_FLOAT_MASKED))?;
        self.asm.emit(|e| e.or_rr(ARG3D, ARG5D))?;
        self.asm.jcc(CondCode::NE, generic_compare)?;
        let boxed = self.asm.emit_ptr_val(ARG1, ARG1);
        emit_vmovsd(&mut self.asm, Xmm(0), emit_boxed_val(boxed, 8, 8))?;
        let boxed = self.asm.emit_ptr_val(ARG2, ARG2);
        emit_vmovsd(&mut self.asm, Xmm(1), emit_boxed_val(boxed, 8, 8))?;
        emit_vucomisd_xx(&mut self.asm, Xmm(0), Xmm(1))?;
        self.asm.emit(|e| e.setcc_r(CondCode::A, enc::AL))?;
        self.asm.emit(|e| e.setcc_r(CondCode::B, enc::AH))?;
        self.asm.emit(|e| e.sub_rr(enc::AL, enc::AH))?;
        self.asm.emit_leave_frame()?;
        self.asm.emit(|e| e.ret())?;

        self.asm.bind(atom_compare)?;
        self.asm.emit(|e| e.mov_rr(ARG3D, ARG1D))?;
        self.asm.emit(|e| e.mov_rr(ARG5D, ARG2D))?;
        self.asm.emit(|e| e.and_ri(ARG3D, TAG_IMMED2_MASK))?;
        self.asm.emit(|e| e.and_ri(ARG5D, TAG_IMMED2_MASK))?;
        self.asm.emit(|e| e.sub_ri(ARG3D, TAG_IMMED2_ATOM))?;
        self.asm.emit(|e| e.sub_ri(ARG5D, TAG_IMMED2_ATOM))?;
        self.asm.emit(|e| e.or_rr(ARG3D, ARG5D))?;
        self.asm.jcc(CondCode::NE, generic_compare)?;
        self.asm.emit_enter_runtime(Update::NONE)?;
        self.asm
            .runtime_call(erts_cmp_atoms as *const () as usize)?;
        self.asm.emit_leave_runtime(Update::NONE)?;
        self.asm.emit(|e| e.test_rr(RETD, RETD))?;
        self.asm.emit_leave_frame()?;
        self.asm.emit(|e| e.ret())?;

        self.asm.bind(generic_compare)?;
        self.asm.emit_enter_runtime(Update::NONE)?;
        self.asm.mov_imm(ARG3, 0)?;
        self.asm.mov_imm(ARG4, 0)?;
        self.asm
            .runtime_call(erts_cmp_compound as *const () as usize)?;
        self.asm.emit_leave_runtime(Update::NONE)?;
        self.asm.emit(|e| e.test_rr(RET, RET))?;
        self.asm.emit_leave_frame()?;
        self.asm.emit(|e| e.ret())
    }

    /// Compares a source against an inclusive integer range using float and generic fallbacks.
    // Port of erts/emulator/beam/jit/x86/instr_common.cpp:2577-2652
    // (emit_is_in_range_shared), OTP-29.1.1.
    pub(crate) fn emit_is_in_range_shared(&mut self) -> Result<(), AsmError> {
        let immediate = self.asm.new_label();
        let generic_compare = self.asm.new_label();
        let done = self.asm.new_label();
        self.asm.emit_is_boxed(immediate, ARG1, Distance::Long)?;
        let boxed = self.asm.emit_ptr_val(ARG4, ARG1);
        self.asm
            .emit(|e| e.cmp_mi(emit_boxed_val(boxed, 0, 8), TAG_HEADER_FLONUM))?;
        self.asm.short_jcc(CondCode::NE, generic_compare)?;
        emit_vmovsd(&mut self.asm, Xmm(0), emit_boxed_val(boxed, 8, 8))?;
        self.asm.emit(|e| e.sar_ri(ARG2, TAG_IMMED1_SIZE))?;
        self.asm.emit(|e| e.sar_ri(ARG3, TAG_IMMED1_SIZE))?;
        if BeamAssembler::has_cpu_feature(CpuFeature::Avx) {
            self.asm.emit(|e| e.vcvtsi2sd_xxr(Xmm(1), Xmm(1), ARG2))?;
            self.asm.emit(|e| e.vcvtsi2sd_xxr(Xmm(2), Xmm(2), ARG3))?;
        } else {
            self.asm.emit(|e| e.cvtsi2sd_xr(Xmm(1), ARG2))?;
            self.asm.emit(|e| e.cvtsi2sd_xr(Xmm(2), ARG3))?;
        }
        self.asm.mov_imm(RET, u64::MAX)?;
        self.asm.mov_imm(enc::RCX, 0)?;
        emit_vucomisd_xx(&mut self.asm, Xmm(0), Xmm(2))?;
        self.asm.emit(|e| e.setcc_r(CondCode::A, enc::CL))?;
        emit_vucomisd_xx(&mut self.asm, Xmm(1), Xmm(0))?;
        self.asm
            .emit(|e| e.cmovcc_rr(CondCode::BE, RET, enc::RCX))?;
        self.asm.emit(|e| e.cmp_ri(RET, 0))?;
        self.asm.emit(|e| e.ret())?;

        self.asm.bind(immediate)?;
        self.asm.mov_imm(RET, 1)?;
        self.asm.emit(|e| e.cmp_ri(RET, 0))?;
        self.asm.emit(|e| e.ret())?;

        self.asm.bind(generic_compare)?;
        self.asm.emit_enter_runtime(Update::NONE)?;
        self.asm.emit(|e| e.mov_mr(tmp_mem_q(0), ARG1))?;
        self.asm.emit(|e| e.mov_mr(tmp_mem_q(1), ARG3))?;
        self.asm.mov_imm(ARG3, 0)?;
        self.asm.mov_imm(ARG4, 0)?;
        self.asm
            .runtime_call(erts_cmp_compound as *const () as usize)?;
        self.asm.emit(|e| e.test_rr(RET, RET))?;
        self.asm.jcc(CondCode::S, done)?;
        self.asm.emit(|e| e.mov_rm(ARG1, tmp_mem_q(0)))?;
        self.asm.emit(|e| e.mov_rm(ARG2, tmp_mem_q(1)))?;
        self.asm.mov_imm(ARG3, 0)?;
        self.asm.mov_imm(ARG4, 0)?;
        self.asm
            .runtime_call(erts_cmp_compound as *const () as usize)?;
        self.asm.emit(|e| e.test_rr(RET, RET))?;
        self.asm.bind(done)?;
        self.asm.emit_leave_runtime(Update::NONE)?;
        self.asm.emit(|e| e.ret())
    }

    /// Checks `Src >= A && Src < B` after generic term comparisons.
    // Port of erts/emulator/beam/jit/x86/instr_common.cpp:2776-2822
    // (emit_is_ge_lt_shared), OTP-29.1.1.
    pub(crate) fn emit_is_ge_lt_shared(&mut self) -> Result<(), AsmError> {
        let done = self.asm.new_label();
        self.asm.emit_enter_runtime(Update::NONE)?;
        self.asm.emit(|e| e.mov_mr(tmp_mem_q(0), ARG1))?;
        self.asm.emit(|e| e.mov_mr(tmp_mem_q(1), ARG3))?;
        self.asm.mov_imm(ARG3, 0)?;
        self.asm.mov_imm(ARG4, 0)?;
        self.asm
            .runtime_call(erts_cmp_compound as *const () as usize)?;
        self.asm.emit(|e| e.test_rr(RET, RET))?;
        self.asm.short_jcc(CondCode::S, done)?;
        self.asm.emit(|e| e.mov_rm(ARG1, tmp_mem_q(1)))?;
        self.asm.emit(|e| e.mov_rm(ARG2, tmp_mem_q(0)))?;
        self.asm.mov_imm(ARG3, 0)?;
        self.asm.mov_imm(ARG4, 0)?;
        self.asm
            .runtime_call(erts_cmp_compound as *const () as usize)?;
        self.asm.mov_imm(ARG1, u64::MAX)?;
        self.asm.mov_imm(ARG4, 1)?;
        self.asm.emit(|e| e.test_rr(RET, RET))?;
        self.asm.emit(|e| e.cmovcc_rr(CondCode::S, RET, ARG1))?;
        self.asm.emit(|e| e.cmovcc_rr(CondCode::G, RET, ARG4))?;
        self.asm.emit(|e| e.add_ri(RET, 1))?;
        self.asm.bind(done)?;
        self.asm.emit_leave_runtime(Update::NONE)?;
        self.asm.emit(|e| e.ret())
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

impl BeamModuleAssembler {
    /// `emit_gc_test_preserve(Need, Live, Preserve, preserve_reg)`: a heap test whose garbage
    /// collection keeps `preserve` (held in `preserve_reg`) alive.
    // Port of erts/emulator/beam/jit/x86/instr_common.cpp:109-152 (emit_gc_test_preserve),
    // OTP-29.1.1.
    pub fn emit_gc_test_preserve(
        &mut self,
        need: u64,
        live: u64,
        preserve: ArgVal,
        preserve_reg: enc::Gp,
    ) -> Result<(), AsmError> {
        let bytes_needed = ((need + arinsal_term::S_RESERVED as u64) * 8) as i32;
        let after_gc_check = self.asm.new_label();
        assert_ne!(preserve_reg, ARG3);
        self.asm
            .emit(|e| e.lea(ARG3, qword_ptr(HTOP, bytes_needed)))?;
        self.asm.emit(|e| e.cmp_rr(ARG3, E))?;
        self.asm.short_jcc(CondCode::BE, after_gc_check)?;
        let garbage_collect = self.ga_get(GlobalLabels::GarbageCollect)?;
        let garbage_collect = self.resolve_fragment(garbage_collect);
        // The preserved term need not be stashed when it is currently live.
        if !(preserve.is_x_register() && preserve.reg().is_some_and(|x| u64::from(x) >= live)) {
            self.asm.mov_imm(ARG4, live)?;
            self.asm.fragment_call(garbage_collect)?;
            self.mov_arg_to_reg(preserve_reg, preserve)?;
        } else {
            let slot = get_x_ref(live as u32, 8);
            self.asm.emit(|e| e.mov_mr(slot, preserve_reg))?;
            self.asm.mov_imm(ARG4, live + 1)?;
            self.asm.fragment_call(garbage_collect)?;
            self.asm.emit(|e| e.mov_rm(preserve_reg, slot))?;
        }
        self.asm.bind(after_gc_check)
    }

    /// `emit_gc_test(Ns, Nh, Live)`: collects garbage unless `ns` stack and `nh` heap words
    /// are free.
    // Port of erts/emulator/beam/jit/x86/instr_common.cpp:154-175 (emit_gc_test), OTP-29.1.1.
    pub fn emit_gc_test(&mut self, ns: u64, nh: u64, live: u64) -> Result<(), AsmError> {
        let bytes_needed = ((ns + nh + arinsal_term::S_RESERVED as u64) * 8) as i32;
        let after_gc_check = self.asm.new_label();
        self.asm
            .emit(|e| e.lea(ARG3, qword_ptr(HTOP, bytes_needed)))?;
        self.asm.emit(|e| e.cmp_rr(ARG3, E))?;
        self.asm.short_jcc(CondCode::BE, after_gc_check)?;
        self.asm.mov_imm(ARG4, live)?;
        let garbage_collect = self.ga_get(GlobalLabels::GarbageCollect)?;
        let garbage_collect = self.resolve_fragment(garbage_collect);
        self.asm.fragment_call(garbage_collect)?;
        self.asm.bind(after_gc_check)
    }
}

impl BeamModuleAssembler {
    /// `emit_i_test_yield()`: the reduction test of a function prologue, right after the
    /// breakpoint trampoline. `ARG3` is the return address `i_test_yield_shared` resumes at
    /// (`current_label + TEST_YIELD_RETURN_OFFSET`, the end of this instruction).
    // Port of erts/emulator/beam/jit/x86/instr_common.cpp:3217-3252 (emit_i_test_yield),
    // OTP-29.1.1. `erts_alcu_enable_code_atags` (an undocumented `+M` option Arinsal does not
    // have) is off, so `c_p->i` is not stored.
    pub fn emit_i_test_yield(&mut self) -> Result<(), AsmError> {
        use super::beam_asm::register::FCALLS;
        use super::beam_asm_global::TEST_YIELD_RETURN_OFFSET;
        use crate::common::beam_asm_h::BEAM_ASM_FUNC_PROLOGUE_SIZE;
        let current = self
            .current_label()
            .ok_or(AsmError::Operand("i_test_yield outside a function"))?;
        debug_assert_eq!(
            self.current_label_offset(),
            Some(self.asm.a.offset() - BEAM_ASM_FUNC_PROLOGUE_SIZE)
        );
        self.asm.emit_enter_frame()?;
        self.asm.a.emit_rip_label(current, |e| {
            e.lea(ARG3, Mem::rip(TEST_YIELD_RETURN_OFFSET as i32, 8))
        })?;
        self.asm.emit(|e| e.dec_r(FCALLS))?;
        let fragment = self.ga_get(GlobalLabels::ITestYieldShared)?;
        let target = self.resolve_fragment(fragment);
        self.asm.a.jcc_near(CondCode::LE as u8, target)?;
        self.asm.align_code(4)?;
        debug_assert_eq!(
            self.current_label_offset(),
            Some(self.asm.a.offset() - TEST_YIELD_RETURN_OFFSET as usize)
        );
        Ok(())
    }

    /// `emit_coverage(coverage, index, size)`: marks (byte flags) or counts (word counters)
    /// the execution of coverage point `index`.
    // Port of erts/emulator/beam/jit/x86/instr_common.cpp:3332-3351 (emit_coverage),
    // OTP-29.1.1.
    pub fn emit_coverage(
        &mut self,
        coverage: usize,
        index: u64,
        size: u64,
    ) -> Result<(), AsmError> {
        let address = coverage as u64 + index * size;
        self.asm.mov_imm(RET, address)?;
        match size {
            8 => self.asm.emit(|e| e.lock_inc_m(qword_ptr(RET, 0))),
            1 if address & 0xff != 0 => {
                // The size of this instruction is two bytes.
                self.asm.emit(|e| e.mov_mr(enc::byte_ptr(RET, 0), RETB))
            }
            // The size of this instruction is three bytes.
            1 => self.asm.emit(|e| e.mov_mi(enc::byte_ptr(RET, 0), 1)),
            _ => Err(AsmError::Operand("coverage counter size")),
        }
    }
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod tests {
    use super::*;
    use crate::common::types::ArgType;
    use crate::x86::beam_asm::register::TMP1;
    use crate::x86::jdump::{beam_register, erts_dump, gnu_as, op_blocks};
    use arinsal_x64::buf::Section;
    use similar_asserts::assert_eq;

    /// Real boot modules whose dumps the x86 emitter tests compare against.
    const MODULES: [&str; 17] = [
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
        "group",
        "ets",
        "peer",
        "file",
        "erlang",
        "erts_beamasm",
        "os",
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

    fn emitted_with_fragments_at(
        start_offset: usize,
        f: impl FnOnce(&mut BeamModuleAssembler) -> Result<(), AsmError>,
    ) -> Vec<u8> {
        let addresses = vec![Some(0x1000); super::super::beam_asm_global::GLOBAL_LABELS.len()];
        let mut m = BeamModuleAssembler::with_fragment_addresses(8, addresses);
        for _ in 0..start_offset {
            m.asm.emit(|e| e.nop()).unwrap();
        }
        let start = m.asm.a.offset();
        f(&mut m).unwrap();
        m.asm.a.bytes(Section::Code)[start..].to_vec()
    }

    fn expected_erts_block(
        block: &[String],
        start_offset: usize,
        resolve_fragment_calls: bool,
    ) -> Option<Vec<u8>> {
        use std::collections::HashSet;

        let labels: HashSet<&str> = block
            .iter()
            .filter_map(|line| line.strip_suffix(':'))
            .collect();
        const CALL_NOPS: [&str; 3] = ["0x90", "0x66, 0x90", "0x0f, 0x1f, 0x00"];
        let is_call_alignment_nop = |line: &str| {
            matches!(
                line.to_ascii_lowercase().replace(' ', "").as_str(),
                ".byte0x90" | ".byte0x66,0x90" | ".byte0x0f,0x1f,0x00"
            )
        };
        let mut lines = Vec::with_capacity(block.len());
        for source in block {
            let line = crate::x86::jdump::erts_to_arinsal(source);
            let (prefix, instruction) = if let Some(rest) = line.strip_prefix("short ") {
                (Some(true), rest)
            } else if let Some(rest) = line.strip_prefix("long ") {
                (Some(false), rest)
            } else {
                (None, line.as_str())
            };
            let Some((op, target)) = instruction.split_once(' ') else {
                lines.push(line);
                continue;
            };
            // `call imm(address)` (through the address table) vs. `call L<n>`, the
            // module's dispatch-table thunk of a fragment (`safe_fragment_call`).
            if op == "call" && target.parse::<u64>().is_ok() {
                if resolve_fragment_calls {
                    while lines.last().is_some_and(|line| is_call_alignment_nop(line)) {
                        lines.pop();
                    }
                    let prefix_len = gnu_as(&lines)?.len();
                    let padding = (4 - (start_offset + prefix_len + 5) % 4) % 4;
                    if padding > 0 {
                        lines.push(format!(".byte {}", CALL_NOPS[padding - 1]));
                    }
                    lines.push(".byte 0xe8, 0, 0, 0, 0".to_owned());
                } else {
                    lines.push(".byte 0x40, 0xe8, 0, 0, 0, 0".to_owned());
                }
                continue;
            }
            if op == "call"
                && (matches!(
                    target,
                    "rax"
                        | "rcx"
                        | "rdx"
                        | "rbx"
                        | "rsp"
                        | "rbp"
                        | "rsi"
                        | "rdi"
                        | "r8"
                        | "r9"
                        | "r10"
                        | "r11"
                        | "r12"
                        | "r13"
                        | "r14"
                        | "r15"
                ) || target.starts_with("qword ptr "))
            {
                lines.push(line);
                continue;
            }
            if op == "call" && !labels.contains(target) {
                lines.push(".byte 0xe8, 0, 0, 0, 0".to_owned());
                continue;
            }
            let target_is_local = labels.contains(target);
            if !target_is_local && op.starts_with('j') {
                let condition = match op {
                    "jo" => 0x0,
                    "jno" => 0x1,
                    "jb" | "jc" | "jnae" => 0x2,
                    "jae" | "jnb" | "jnc" => 0x3,
                    "je" | "jz" => 0x4,
                    "jne" | "jnz" => 0x5,
                    "jbe" | "jna" => 0x6,
                    "ja" | "jnbe" => 0x7,
                    "js" => 0x8,
                    "jns" => 0x9,
                    "jp" | "jpe" => 0xa,
                    "jnp" | "jpo" => 0xb,
                    "jl" | "jnge" => 0xc,
                    "jge" | "jnl" => 0xd,
                    "jle" | "jng" => 0xe,
                    "jg" | "jnle" => 0xf,
                    "jmp" => {
                        lines.push(if prefix == Some(true) {
                            ".byte 0xeb, 0".to_owned()
                        } else {
                            ".byte 0xe9, 0, 0, 0, 0".to_owned()
                        });
                        continue;
                    }
                    _ => {
                        lines.push(line);
                        continue;
                    }
                };
                let short = prefix == Some(true);
                lines.push(if short {
                    format!(".byte {:#04x}, 0", 0x70 + condition)
                } else {
                    format!(".byte 0x0f, {:#04x}, 0, 0, 0, 0", 0x80 + condition)
                });
                continue;
            }
            lines.push(line);
        }
        gnu_as(&lines)
    }

    fn assert_erts_block_matches(
        block: &[String],
        emit: impl Fn(&mut BeamModuleAssembler) -> Result<(), AsmError>,
    ) {
        let expected =
            expected_erts_block(block, 0, false).expect("GNU binutils must assemble erts dump");
        let mut last = Vec::new();
        for start_offset in 0..4 {
            last = emitted_with_fragments_at(start_offset, |m| emit(m));
            if last == expected {
                return;
            }
        }
        assert_eq!(last, expected, "{block:#?}");
    }

    fn assert_erts_block_matches_thunk_call(
        block: &[String],
        emit: impl Fn(&mut BeamModuleAssembler) -> Result<(), AsmError>,
    ) {
        let mut last = Vec::new();
        let mut expected = Vec::new();
        for start_offset in 0..4 {
            expected = expected_erts_block(block, start_offset, true)
                .expect("GNU binutils must assemble erts dump");
            last = emitted_with_fragments_at(start_offset, |m| emit(m));
            if last == expected {
                return;
            }
        }
        assert_eq!(last, expected, "{block:#?}");
    }

    fn dump_block(op: &str, accept: impl Fn(&[String]) -> bool) -> Vec<String> {
        dump_blocks(op)
            .unwrap_or_else(|| panic!("OTP 29 +JDdump unavailable for {op}"))
            .into_iter()
            .find(|block| accept(block))
            .unwrap_or_else(|| panic!("OTP 29 +JDdump has no usable {op} block"))
    }

    fn stack_words(block: &[String]) -> Option<u64> {
        Some(
            block
                .iter()
                .find_map(|line| line.strip_prefix("sub rsp, "))
                .and_then(|words| words.parse::<u64>().ok().map(|bytes| bytes / 8))
                .unwrap_or(0),
        )
    }

    fn heap_test_args(block: &[String]) -> Option<(u64, u64)> {
        let live = block.iter().find_map(|line| {
            if let Some(words) = line.strip_prefix("mov ecx, ") {
                words.parse::<u64>().ok()
            } else if line == "xor ecx, ecx" {
                Some(0)
            } else {
                None
            }
        })?;
        let bytes = block.iter().find_map(|line| {
            let (_, rhs) = line.split_once(", ")?;
            let (base, disp) = parse_mem(rhs)?;
            (base == "r15" && line.starts_with("lea rdx, ")).then_some(u64::try_from(disp).ok()?)
        })?;
        Some((bytes / 8 - arinsal_term::S_RESERVED as u64, live))
    }

    fn source_for_register(block: &[String], register: &str) -> Option<ArgVal> {
        block.iter().find_map(|line| {
            let (dst, src) = line.strip_prefix("mov ")?.split_once(", ")?;
            (dst == register).then(|| arg_slot(src)).flatten()
        })
    }

    fn tracked_source_for_register(block: &[String], register: &str) -> Option<ArgVal> {
        let mut values = std::collections::HashMap::<String, ArgVal>::new();
        for line in block {
            let Some((dst, src)) = line.strip_prefix("mov ").and_then(|s| s.split_once(", "))
            else {
                continue;
            };
            let value = arg_slot(src)
                .or_else(|| {
                    src.parse::<i64>()
                        .ok()
                        .map(|word| ArgVal::Immediate(word as u64))
                })
                .or_else(|| values.get(src).copied());
            if let Some(value) = value {
                values.insert(dst.to_owned(), value);
                if dst == register {
                    return Some(value);
                }
            }
        }
        None
    }

    fn immediate_move(block: &[String], register: &str) -> Option<u64> {
        block.iter().find_map(|line| {
            let (dst, value) = line.strip_prefix("mov ")?.split_once(", ")?;
            (dst == register).then(|| value.parse().ok()).flatten()
        })
    }

    fn cmp_memory_immediate(block: &[String]) -> Option<(ArgVal, u64)> {
        block.iter().find_map(|line| {
            let (memory, value) = line.strip_prefix("cmp ")?.split_once(", ")?;
            Some((arg_slot(memory)?, value.parse().ok()?))
        })
    }

    fn stack_slot(block: &[String]) -> Option<ArgVal> {
        stored_slots(block)
            .into_iter()
            .rev()
            .find(|arg| matches!(arg, ArgVal::Y(_)))
    }

    fn deallocate_words(block: &[String]) -> Option<u64> {
        block
            .iter()
            .find_map(|line| {
                line.strip_prefix("add rsp, ")
                    .and_then(|words| words.parse::<u64>().ok())
                    .map(|bytes| bytes / 8)
            })
            .or(Some(0))
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
        let mut blocks: Vec<Vec<String>> =
            dumps.iter().flat_map(|d| full_op_blocks(d, op)).collect();
        if let Some(dump) = crate::x86::jdump::generated_misc_emitters_dump() {
            blocks.extend(full_op_blocks(&dump, op));
        }
        Some(blocks)
    }

    fn full_op_blocks(dump: &str, op: &str) -> Vec<Vec<String>> {
        let is_requested_op = |name: &str| {
            let prefix_match = name == op || name.starts_with(&format!("{op}_"));
            prefix_match
                && !matches!(
                    (op, name),
                    ("is_eq", name) if name.starts_with("is_eq_exact_")
                )
                && !matches!(
                    (op, name),
                    ("is_ne", name) if name.starts_with("is_ne_exact_")
                )
                && !matches!(
                    (op, name),
                    ("is_ge", name) if name.starts_with("is_ge_ge_") || name.starts_with("is_ge_lt_")
                )
                && !matches!(
                    (op, name),
                    ("i_get", name) if name.starts_with("i_get_hash_")
                        || name.starts_with("i_get_map_")
                        || name.starts_with("i_get_tuple_")
                )
        };
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
                if is_requested_op(name) {
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
        let Some((expected, label_count)) = expected_block_bytes(block) else {
            return false;
        };
        emitted_with_labels(label_count, emit).is_some_and(|ours| ours == expected)
    }

    fn expected_block_bytes(block: &[String]) -> Option<(Vec<u8>, usize)> {
        const FILLER: usize = 48;
        let labels = external_labels(block);
        let defined: std::collections::HashSet<&str> = block
            .iter()
            .filter_map(|line| line.strip_suffix(':'))
            .collect();
        let mut expected_lines: Vec<String> = block
            .iter()
            .map(|line| crate::x86::jdump::erts_to_arinsal(line))
            .collect();
        for line in &mut expected_lines {
            if let Some(target) = line.strip_prefix("call ") {
                if target.parse::<u64>().is_ok() {
                    *line = ".byte 0x40, 0xe8, 0, 0, 0, 0".to_owned();
                } else if (target.starts_with('L') || target.starts_with("label_"))
                    && !defined.contains(target)
                {
                    *line = ".byte 0xe8, 0, 0, 0, 0".to_owned();
                }
            }
        }
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
        Some((gnu_as(&expected_lines)?, labels.len()))
    }

    fn emitted_with_labels(
        label_count: usize,
        emit: impl FnOnce(&mut BeamModuleAssembler, &[u32]) -> Result<(), AsmError>,
    ) -> Option<Vec<u8>> {
        const FILLER: usize = 48;
        let addresses = vec![Some(0x1000); super::super::beam_asm_global::GLOBAL_LABELS.len()];
        let mut m = BeamModuleAssembler::with_fragment_addresses(4, addresses);
        let fail_labels: Vec<u32> = (1..=label_count as u32).collect();
        emit(&mut m, &fail_labels).ok()?;
        for index in 0..label_count {
            for _ in 0..FILLER {
                m.asm.emit(|e| e.mov_rr(TMP1, TMP1)).ok()?;
            }
            let label = m.resolve_beam_label(index as u32 + 1)?;
            m.asm.bind(label).ok()?;
        }
        Some(m.asm.a.bytes(Section::Code).to_vec())
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

    fn test_types() -> Vec<ArgType> {
        let mut types = TYPE_VARIANTS
            .into_iter()
            .map(|union_bits| ArgType {
                union_bits,
                ..ArgType::ANY
            })
            .collect::<Vec<_>>();
        types.push(ArgType {
            union_bits: type_id::INTEGER,
            min: Some(-100),
            max: Some(100),
            unit: 1,
        });
        types
    }

    fn typed_pair_dump_matches(
        op: &str,
        emit: impl Fn(&mut BeamModuleAssembler, u32, ArgVal, ArgVal) -> Result<(), AsmError>,
    ) -> bool {
        let Some(blocks) = dump_blocks(op) else {
            return false;
        };
        for block in blocks.iter().filter(|block| !block.is_empty()).take(40) {
            let (Some(lhs), Some(rhs)) = (
                tracked_source_for_register(block, "rdi"),
                tracked_source_for_register(block, "rsi"),
            ) else {
                continue;
            };
            let labels = external_labels(block);
            if labels.len() != 1 {
                continue;
            }
            let Some((expected, label_count)) = expected_block_bytes(block) else {
                continue;
            };
            let types = test_types();
            for lhs_type in &types {
                for rhs_type in &types {
                    let (lhs_type, rhs_type) = (*lhs_type, *rhs_type);
                    let ours = emitted_with_labels(label_count, |m, fail| {
                        let [fail] = fail else {
                            return Err(AsmError::Operand("expected one comparison failure label"));
                        };
                        let lhs = m.typed_arg(lhs, lhs_type);
                        let rhs = m.typed_arg(rhs, rhs_type);
                        emit(m, *fail, lhs, rhs)
                    });
                    if ours.as_deref() == Some(expected.as_slice()) {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn typed_literal_dump_matches(
        op: &str,
        emit: impl Fn(&mut BeamModuleAssembler, u32, ArgVal, ArgVal) -> Result<(), AsmError>,
    ) -> bool {
        let Some(blocks) = dump_blocks(op) else {
            return false;
        };
        for block in blocks.iter().filter(|block| !block.is_empty()).take(80) {
            let Some((src, immediate)) = cmp_memory_immediate(block) else {
                continue;
            };
            let labels = external_labels(block);
            if labels.len() != 1 {
                continue;
            }
            let Some((expected, label_count)) = expected_block_bytes(block) else {
                continue;
            };
            for ty in test_types() {
                let ours = emitted_with_labels(label_count, |m, fail| {
                    let [fail] = fail else {
                        return Err(AsmError::Operand("expected one comparison failure label"));
                    };
                    let src = m.typed_arg(src, ty);
                    emit(m, *fail, src, ArgVal::Immediate(immediate))
                });
                if ours.as_deref() == Some(expected.as_slice()) {
                    return true;
                }
            }
        }
        false
    }

    fn assert_typed_source_op_matches(
        op: &str,
        emit: impl Fn(&mut BeamModuleAssembler, &[String], u32, ArgVal) -> Result<(), AsmError>,
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
                let ty = ArgType {
                    union_bits,
                    ..ArgType::ANY
                };
                assert_block_matches(block, |m| {
                    let src = m.typed_arg(src, ty);
                    emit(m, block, 1, src)
                })
            })
        });
        assert!(matched, "no byte-identical erts dump block for {op}");
    }

    fn assert_typed_two_label_op_matches(
        op: &str,
        emit: impl Fn(&mut BeamModuleAssembler, u32, u32, ArgVal, &[u64]) -> Result<(), AsmError>,
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
                let ty = ArgType {
                    union_bits,
                    ..ArgType::ANY
                };
                assert_block_matches_with_labels(block, |m, labels| {
                    if labels.len() != 2 {
                        return Err(AsmError::Operand("expected two external failure labels"));
                    }
                    let src = m.typed_arg(src, ty);
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
        assert_source_op_matches("load_tuple_ptr_s", |m, _, src| m.emit_load_tuple_ptr(src));
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
                m.emit_i_get_tuple_element(ArgVal::X(0), ArgVal::Word(offset as u64), dst)
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
                    ArgVal::X(0),
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
                m.emit_get_two_tuple_elements(src, ArgVal::Word(offset as u64), dst1, dst2)
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
    fn remaining_misc_emitters_match_erts_dumps() {
        if erts_dump("lists").is_none() {
            eprintln!("skipping: `erl +JDdump true` unavailable");
            return;
        }

        assert!(typed_literal_dump_matches(
            "is_eq_exact",
            |m, fail, src, rhs| { m.emit_is_eq_exact(ArgVal::Label(fail), src, rhs) }
        ));
        assert!(typed_literal_dump_matches(
            "is_ne_exact",
            |m, fail, src, rhs| { m.emit_is_ne_exact(ArgVal::Label(fail), src, rhs) }
        ));
        assert!(typed_pair_dump_matches("is_eq", |m, fail, lhs, rhs| {
            m.emit_is_eq(ArgVal::Label(fail), lhs, rhs)
        }));
        assert!(typed_pair_dump_matches("is_ne", |m, fail, lhs, rhs| {
            m.emit_is_ne(ArgVal::Label(fail), lhs, rhs)
        }));
        assert!(typed_pair_dump_matches("is_lt", |m, fail, lhs, rhs| {
            m.emit_is_lt(ArgVal::Label(fail), lhs, rhs)
        }));
        assert!(typed_pair_dump_matches("is_ge", |m, fail, lhs, rhs| {
            m.emit_is_ge(ArgVal::Label(fail), lhs, rhs)
        }));

        let ge_lt_blocks = dump_blocks("is_ge_lt").unwrap();
        let ge_lt_matched = ge_lt_blocks.iter().any(|block| {
            let (Some(src), Some(min), Some(max)) = (
                tracked_source_for_register(block, "rdi"),
                immediate_move(block, "esi"),
                immediate_move(block, "edx"),
            ) else {
                return false;
            };
            let labels = external_labels(block);
            if labels.len() != 2 {
                return false;
            }
            let Some((expected, label_count)) = expected_block_bytes(block) else {
                return false;
            };
            test_types().into_iter().any(|ty| {
                emitted_with_labels(label_count, |m, fail| {
                    let [fail1, fail2] = fail else {
                        return Err(AsmError::Operand("expected two range failure labels"));
                    };
                    let src = m.typed_arg(src, ty);
                    m.emit_is_ge_lt(
                        ArgVal::Label(*fail1),
                        ArgVal::Label(*fail2),
                        src,
                        ArgVal::Immediate(min),
                        ArgVal::Immediate(max),
                    )
                })
                .is_some_and(|ours| ours == expected)
            })
        });
        assert!(
            ge_lt_matched,
            "no byte-identical erts dump block for is_ge_lt"
        );

        let ge_ge_blocks = dump_blocks("is_ge_ge").unwrap();
        let ge_ge_matched = ge_ge_blocks.iter().any(|block| {
            let (Some(src), Some(min), Some(diff)) = (
                tracked_source_for_register(block, "rax"),
                block
                    .iter()
                    .find_map(|line| line.strip_prefix("sub rax, ")?.parse().ok()),
                block
                    .iter()
                    .find_map(|line| line.strip_prefix("cmp rax, ")?.parse().ok()),
            ) else {
                return false;
            };
            let labels = external_labels(block);
            if labels.len() != 2 {
                return false;
            }
            let Some((expected, label_count)) = expected_block_bytes(block) else {
                return false;
            };
            test_types().into_iter().any(|ty| {
                emitted_with_labels(label_count, |m, fail| {
                    let [fail1, fail2] = fail else {
                        return Err(AsmError::Operand("expected two range failure labels"));
                    };
                    let src = m.typed_arg(src, ty);
                    m.emit_is_ge_ge(
                        ArgVal::Label(*fail1),
                        ArgVal::Label(*fail2),
                        src,
                        ArgVal::Immediate(min),
                        ArgVal::Immediate(min.wrapping_add(diff)),
                    )
                })
                .is_some_and(|ours| ours == expected)
            })
        });
        assert!(
            ge_ge_matched,
            "no byte-identical erts dump block for is_ge_ge"
        );

        let int_ge_blocks = dump_blocks("is_int_ge").unwrap();
        let int_ge_matched = int_ge_blocks.iter().any(|block| {
            let (Some(src), Some(min)) = (
                tracked_source_for_register(block, "rcx"),
                block
                    .iter()
                    .find_map(|line| line.strip_prefix("cmp rcx, ")?.parse().ok()),
            ) else {
                return false;
            };
            let labels = external_labels(block);
            if labels.len() != 1 {
                return false;
            }
            let Some((expected, label_count)) = expected_block_bytes(block) else {
                return false;
            };
            test_types().into_iter().any(|ty| {
                emitted_with_labels(label_count, |m, fail| {
                    let [fail] = fail else {
                        return Err(AsmError::Operand("expected one integer failure label"));
                    };
                    let src = m.typed_arg(src, ty);
                    m.emit_is_int_ge(ArgVal::Label(*fail), src, ArgVal::Immediate(min))
                })
                .is_some_and(|ours| ours == expected)
            })
        });
        assert!(
            int_ge_matched,
            "no byte-identical erts dump block for is_int_ge"
        );

        let int_range_blocks = dump_blocks("is_int_in_range").unwrap();
        let int_range_matched = int_range_blocks.iter().any(|block| {
            let (Some(src), Some(min), Some(diff)) = (
                tracked_source_for_register(block, "rax"),
                block
                    .iter()
                    .find_map(|line| line.strip_prefix("sub rax, ")?.parse().ok()),
                block
                    .iter()
                    .find_map(|line| line.strip_prefix("cmp rax, ")?.parse().ok()),
            ) else {
                return false;
            };
            let labels = external_labels(block);
            if labels.len() != 1 {
                return false;
            }
            let Some((expected, label_count)) = expected_block_bytes(block) else {
                return false;
            };
            test_types().into_iter().any(|ty| {
                emitted_with_labels(label_count, |m, fail| {
                    let [fail] = fail else {
                        return Err(AsmError::Operand("expected one range failure label"));
                    };
                    let src = m.typed_arg(src, ty);
                    m.emit_is_int_in_range(
                        ArgVal::Label(*fail),
                        src,
                        ArgVal::Immediate(min),
                        ArgVal::Immediate(min.wrapping_add(diff)),
                    )
                })
                .is_some_and(|ours| ours == expected)
            })
        });
        assert!(
            int_range_matched,
            "no byte-identical erts dump block for is_int_in_range"
        );

        let range_blocks = dump_blocks("is_in_range").unwrap();
        let range_matched = range_blocks.iter().any(|block| {
            let Some(src) = tracked_source_for_register(block, "rdi") else {
                return false;
            };
            let bounds: Vec<u64> = block
                .iter()
                .filter_map(|line| line.strip_prefix("cmp rdi, ")?.parse().ok())
                .collect();
            let [min, max, ..] = bounds.as_slice() else {
                return false;
            };
            let labels = external_labels(block);
            if !(labels.len() == 1 || labels.len() == 2) {
                return false;
            }
            let Some((expected, label_count)) = expected_block_bytes(block) else {
                return false;
            };
            test_types().into_iter().any(|ty| {
                emitted_with_labels(label_count, |m, fail| {
                    let (small_fail, large_fail) = match fail {
                        [only] => (*only, *only),
                        [small, large] => (*small, *large),
                        _ => return Err(AsmError::Operand("range failure labels")),
                    };
                    let src = m.typed_arg(src, ty);
                    m.emit_is_in_range(
                        ArgVal::Label(small_fail),
                        ArgVal::Label(large_fail),
                        src,
                        ArgVal::Immediate(*min),
                        ArgVal::Immediate(*max),
                    )
                })
                .is_some_and(|ours| ours == expected)
            })
        });
        assert!(
            range_matched,
            "no byte-identical erts dump block for is_in_range"
        );

        let function_blocks = dump_blocks("is_function2").unwrap();
        let function_matched = function_blocks.iter().any(|block| {
            let (Some(src), Some(header)) = (
                tracked_source_for_register(block, "rdi"),
                block.iter().find_map(|line| {
                    line.strip_prefix("cmp word ptr [rdi-2], ")?
                        .parse::<u64>()
                        .ok()
                }),
            ) else {
                return false;
            };
            let arity = (header.saturating_sub(FUN_SUBTAG as u64)) >> FUN_HEADER_ARITY_OFFS;
            let Some(small) = Term::small(arity as i64) else {
                return false;
            };
            assert_block_matches(block, |m| {
                m.emit_is_function2(ArgVal::Label(1), src, ArgVal::Immediate(small.word()))
            })
        });
        assert!(
            function_matched,
            "no byte-identical erts dump block for is_function2"
        );

        let append_blocks = dump_blocks("append_cons").unwrap();
        let append_matched = append_blocks.iter().any(|block| {
            let Some(head) = tracked_source_for_register(block, "rdi") else {
                return false;
            };
            let Some(index) = block.iter().find_map(|line| {
                let lhs = line.strip_prefix("mov qword ptr ")?.split_once(", ")?.0;
                let (base, offset) = parse_mem(lhs)?;
                (base == "r15" && offset >= 0 && offset % 16 == 0).then_some((offset / 16) as u64)
            }) else {
                return false;
            };
            assert_block_matches(block, |m| m.emit_append_cons(ArgVal::Word(index), head))
        });
        assert!(
            append_matched,
            "no byte-identical erts dump block for append_cons"
        );

        let store_blocks = dump_blocks("store_cons").unwrap();
        let store_matched = store_blocks.iter().any(|block| {
            let len = block
                .iter()
                .find_map(|line| line.strip_prefix("add r15, ")?.parse::<u64>().ok())
                .map(|bytes| bytes / 16);
            let dst = stored_slots(block).first().copied();
            let (Some(len), Some(dst)) = (len, dst) else {
                return false;
            };
            assert_block_matches(block, |m| m.emit_store_cons(ArgVal::Word(len), dst))
        });
        assert!(
            store_matched,
            "no byte-identical erts dump block for store_cons"
        );

        let get_blocks = dump_blocks("i_get").unwrap();
        let get_matched = get_blocks.iter().any(|block| {
            let (Some(src), Some(dst)) = (
                tracked_source_for_register(block, "rsi"),
                stored_slots(block).first().copied(),
            ) else {
                return false;
            };
            assert_block_matches(block, |m| m.emit_i_get(src, dst))
        });
        assert!(get_matched, "no byte-identical erts dump block for i_get");

        let get_hash_blocks = dump_blocks("i_get_hash").unwrap();
        let get_hash_matched = get_hash_blocks.iter().any(|block| {
            let (Some(hash), Some(src), Some(dst)) = (
                immediate_move(block, "esi"),
                immediate_move(block, "edx"),
                stored_slots(block).first().copied(),
            ) else {
                return false;
            };
            assert_block_matches(block, |m| {
                m.emit_i_get_hash(ArgVal::Immediate(src), ArgVal::Word(hash), dst)
            })
        });
        assert!(
            get_hash_matched,
            "no byte-identical erts dump block for i_get_hash"
        );

        let node_blocks = dump_blocks("node").unwrap();
        let node_matched = node_blocks.iter().any(|block| {
            let Some(dst) = stored_slots(block).first().copied() else {
                return false;
            };
            let mut rewritten = block.clone();
            for line in &mut rewritten {
                if line.starts_with("mov r10, ") && line[9..].parse::<u64>().is_ok() {
                    *line = format!("mov r10, {}", arinsal_term::erts_this_node_addr());
                    break;
                }
            }
            assert_block_matches(&rewritten, |m| m.emit_node(dst))
        });
        assert!(node_matched, "no byte-identical erts dump block for node");

        let Some(generated) = crate::x86::jdump::generated_misc_emitters_dump() else {
            eprintln!("skipping generated old-op checks: `erl` or `timeout` unavailable");
            return;
        };
        let set_tuple_blocks = full_op_blocks(&generated, "set_tuple_element");
        assert!(set_tuple_blocks.iter().any(|block| {
            assert_block_matches(block, |m| {
                m.emit_set_tuple_element(ArgVal::X(0), ArgVal::X(1), ArgVal::Word(16))
            })
        }));
        let debug_line_blocks = full_op_blocks(&generated, "i_debug_line");
        let debug_line_matched = debug_line_blocks.iter().any(|block| {
            if !block.iter().any(|line| line == "align 8") {
                return false;
            }
            let Some(line) = block
                .first()
                .and_then(|line| line.strip_prefix("mov r10, "))
            else {
                return false;
            };
            let Ok(index) = line.parse::<u32>() else {
                return false;
            };
            const NOPS: [&[u8]; 8] = [
                &[],
                &[0x90],
                &[0x66, 0x90],
                &[0x0f, 0x1f, 0x00],
                &[0x0f, 0x1f, 0x40, 0x00],
                &[0x0f, 0x1f, 0x44, 0x00, 0x00],
                &[0x66, 0x0f, 0x1f, 0x44, 0x00, 0x00],
                &[0x0f, 0x1f, 0x80, 0x00, 0x00, 0x00, 0x00],
            ];
            (0..8).any(|start| {
                let mut expected = vec![0x41, 0xba];
                expected.extend_from_slice(&index.to_le_bytes());
                let padding = (8 - (start + expected.len()) % 8) % 8;
                expected.extend_from_slice(NOPS[padding]);
                let ours = emitted_with_fragments_at(start, |m| {
                    m.emit_i_debug_line(ArgVal::Word(0), ArgVal::Word(1), ArgVal::Word(2))
                });
                ours == expected
            })
        });
        assert!(
            debug_line_matched,
            "no byte-identical erts dump block for i_debug_line"
        );

        let perf_blocks = dump_blocks("i_perf_counter").unwrap();
        let perf_matched = perf_blocks.iter().any(|block| {
            let mut rewritten = block.clone();
            for line in &mut rewritten {
                if line.starts_with("mov rax, ") && line[9..].parse::<u64>().is_ok() {
                    *line = format!("mov rax, {}", super::perf_counter_address());
                    break;
                }
            }
            let Some(expected) = expected_erts_block(&rewritten, 0, true) else {
                return false;
            };
            emitted_with_fragments_at(0, |m| m.emit_i_perf_counter()).as_slice()
                == expected.as_slice()
        });
        assert!(
            perf_matched,
            "no byte-identical erts dump block for i_perf_counter"
        );

        let validation_blocks = dump_blocks("i_validate").unwrap();
        assert!(validation_blocks.iter().all(Vec::is_empty));
        assert!(emitted(|m| m.emit_i_validate(ArgVal::Word(0))).is_empty());
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

    #[test]
    fn frames_and_heap_emitters_match_erts_dump() {
        let allocate = dump_block("allocate_tt", |_| true);
        let (_, live) = heap_test_args(&allocate).expect("allocate_tt operands");
        assert_erts_block_matches_thunk_call(&allocate, |m| {
            m.emit_allocate(
                ArgVal::Word(stack_words(&allocate).unwrap()),
                ArgVal::Word(live),
            )
        });

        let allocate_heap = dump_block("allocate_heap_tIt", |_| true);
        let (need_heap, live) = heap_test_args(&allocate_heap).expect("allocate_heap operands");
        let need_stack = stack_words(&allocate_heap).unwrap();
        assert_erts_block_matches_thunk_call(&allocate_heap, |m| {
            m.emit_allocate_heap(
                ArgVal::Word(need_stack),
                ArgVal::Word(need_heap),
                ArgVal::Word(live),
            )
        });

        let test_heap = dump_block("test_heap_It", |_| true);
        let (need_heap, live) = heap_test_args(&test_heap).expect("test_heap operands");
        assert_erts_block_matches_thunk_call(&test_heap, |m| {
            m.emit_test_heap(ArgVal::Word(need_heap), ArgVal::Word(live))
        });

        let deallocate = dump_block("deallocate_t", |_| true);
        assert_erts_block_matches(&deallocate, |m| {
            m.emit_deallocate(ArgVal::Word(deallocate_words(&deallocate).unwrap()))
        });
    }

    #[test]
    fn record_emitters_and_copy_words_match_erts_dump() {
        let update = dump_block("update_record_aIsdI", |block| {
            block
                .iter()
                .any(|line| line == "cmp qword ptr [rdi+70], 907" && line.starts_with("cmp"))
        });
        assert_erts_block_matches(&update, |m| {
            m.emit_update_record(
                ArgVal::Immediate(Term::atom(atoms::REUSE).word()),
                ArgVal::Word(15),
                ArgVal::X(1),
                ArgVal::X(0),
                ArgVal::Word(2),
                &[ArgVal::Word(9), ArgVal::Immediate(907)],
            )
        });

        let safe = dump_block("update_record_in_place_IsdI", |block| {
            block
                .iter()
                .any(|line| line == "mov qword ptr [rax+30], 75")
        });
        assert_erts_block_matches(&safe, |m| {
            m.emit_update_record_in_place(
                ArgVal::Word(4),
                ArgVal::X(1),
                ArgVal::X(1),
                ArgVal::Word(2),
                &[ArgVal::Word(4), ArgVal::Immediate(75)],
            )
        });

        let fallback = dump_block("update_record_in_place_IsdI", |block| {
            block
                .iter()
                .any(|line| line == "mov rax, qword ptr [rsp+40]")
                && block
                    .iter()
                    .any(|line| line == "mov qword ptr [rax+46], rdi")
        });
        assert_erts_block_matches(&fallback, |m| {
            m.emit_update_record_in_place(
                ArgVal::Word(12),
                ArgVal::Y(5),
                ArgVal::X(0),
                ArgVal::Word(2),
                &[ArgVal::Word(6), ArgVal::Y(6)],
            )
        });
    }

    #[test]
    fn exception_catch_raise_and_yield_emitters_match_erts_dump() {
        for (op, emit) in [
            ("badmatch_s", 0u8),
            ("case_end_s", 1),
            ("badrecord_s", 2),
            ("try_case_end_s", 3),
        ] {
            let block = dump_block(op, |block| source_slot(block).is_some());
            let src = source_slot(&block).unwrap();
            assert_erts_block_matches(&block, |m| match emit {
                0 => m.emit_badmatch(src),
                1 => m.emit_case_end(src),
                2 => m.emit_badrecord(src),
                _ => m.emit_try_case_end(src),
            });
        }

        let if_end = dump_block("if_end", |_| true);
        assert_erts_block_matches(&if_end, |m| m.emit_if_end());

        let catch = dump_block("catch_yf", |block| stack_slot(block).is_some());
        let catch_tag = stack_slot(&catch).unwrap();
        assert_erts_block_matches(&catch, |m| m.emit_catch(catch_tag, ArgVal::Label(1)));

        let catch_end = dump_block("catch_end_y", |block| stack_slot(block).is_some());
        let catch_tag = stack_slot(&catch_end).unwrap();
        assert_erts_block_matches_thunk_call(&catch_end, |m| m.emit_catch_end(catch_tag));

        let try_end = dump_block("try_end_y", |block| stack_slot(block).is_some());
        let catch_tag = stack_slot(&try_end).unwrap();
        assert_erts_block_matches(&try_end, |m| m.emit_try_end(catch_tag));

        let try_end_deallocate = dump_block("try_end_deallocate_t", |_| true);
        assert_erts_block_matches(&try_end_deallocate, |m| {
            m.emit_try_end_deallocate(ArgVal::Word(deallocate_words(&try_end_deallocate).unwrap()))
        });

        let try_case = dump_block("try_case_y", |_| true);
        assert_erts_block_matches(&try_case, |m| m.emit_try_case(ArgVal::Y(0)));

        let raise = dump_block("raise_ss", |block| {
            source_for_register(block, "rdx").is_some()
                && source_for_register(block, "rsi").is_some()
        });
        let trace = source_for_register(&raise, "rsi").unwrap();
        let value = source_for_register(&raise, "rdx").unwrap();
        assert_erts_block_matches(&raise, |m| m.emit_raise(trace, value));

        let mut build_stacktrace = dump_block("build_stacktrace", |block| {
            block.first().is_some_and(|line| line == "mov rsi, r10")
        });
        let mut with_cached_x0 = vec![
            "mov r10, qword ptr [rsp]".to_owned(),
            "mov qword ptr [rbx], r10".to_owned(),
        ];
        with_cached_x0.append(&mut build_stacktrace);
        assert_erts_block_matches(&with_cached_x0, |m| {
            m.emit_i_move(ArgVal::Y(0), ArgVal::X(0))?;
            m.emit_build_stacktrace()
        });

        let raw_raise = dump_block("raw_raise", |_| true);
        assert_erts_block_matches(&raw_raise, |m| m.emit_raw_raise());

        let yield_block = dump_block("i_yield", |_| true);
        assert_erts_block_matches(&yield_block, |m| m.emit_i_yield());
    }

    #[test]
    fn exits_match_erts_dump() {
        let normal_exit = dump_block("normal_exit", |_| true);
        assert_erts_block_matches(&normal_exit, |m| m.emit_normal_exit());

        let continue_exit = dump_block("continue_exit", |_| true);
        assert_erts_block_matches(&continue_exit, |m| m.emit_continue_exit());
    }

    #[test]
    fn test_yield_matches_erts_dump() {
        let dump = erts_dump("erts_code_purger").expect("OTP 29 +JDdump unavailable");
        let block = full_op_blocks(&dump, "i_test_yield")
            .into_iter()
            .next()
            .expect("OTP 29 dump has no i_test_yield block");

        let expected_context = block
            .iter()
            .filter(|line| line.as_str() != "align 4")
            .map(|line| line.replace("[start/0+24]", "[rip+9]"))
            .collect::<Vec<_>>();
        let expected =
            expected_erts_block(&expected_context, 0, false).expect("assemble erts block");

        let addresses = vec![Some(0x1000); super::super::beam_asm_global::GLOBAL_LABELS.len()];
        let mut m = BeamModuleAssembler::with_fragment_addresses(2, addresses);
        m.emit_label(ArgVal::Label(1)).unwrap();
        for _ in 0..8 {
            m.asm.emit(|e| e.nop()).unwrap();
        }
        let start = m.asm.a.offset();
        m.emit_i_test_yield().unwrap();
        assert_eq!(
            m.asm.a.bytes(Section::Code)[start..],
            *expected,
            "{block:#?}"
        );
    }
}

// Port of erts/emulator/beam/jit/x86/instr_common.cpp:219-266, 926-1089, OTP-29.1.1.
impl BeamModuleAssembler {
    /// `allocate_heap(NeedStack, NeedHeap, Live)` on erts' native Erlang stack.
    // Port of erts/emulator/beam/jit/x86/instr_common.cpp:219-238 (emit_allocate_heap),
    // OTP-29.1.1.
    pub fn emit_allocate_heap(
        &mut self,
        need_stack: ArgVal,
        need_heap: ArgVal,
        live: ArgVal,
    ) -> Result<(), AsmError> {
        let stack_words = arg_word(need_stack)?;
        debug_assert!(stack_words <= 1024);
        self.emit_gc_test(stack_words, arg_word(need_heap)?, arg_word(live)?)?;
        if stack_words > 0 {
            self.asm.emit(|e| e.sub_ri(E, (stack_words * 8) as i64))?;
        }
        Ok(())
    }

    /// `allocate(NeedStack, Live)`.
    // Port of erts/emulator/beam/jit/x86/instr_common.cpp:240-243 (emit_allocate), OTP-29.1.1.
    pub fn emit_allocate(&mut self, need_stack: ArgVal, live: ArgVal) -> Result<(), AsmError> {
        self.emit_allocate_heap(need_stack, ArgVal::Word(0), live)
    }

    /// Deallocates an RA frame on erts' native Erlang stack.
    // Port of erts/emulator/beam/jit/x86/instr_common.cpp:245-261 (emit_deallocate), OTP-29.1.1.
    pub fn emit_deallocate(&mut self, deallocate: ArgVal) -> Result<(), AsmError> {
        let words = arg_word(deallocate)?;
        debug_assert!(words <= 1023);
        if words > 0 {
            self.asm.emit(|e| e.add_ri(E, (words * 8) as i64))?;
        }
        Ok(())
    }

    /// `test_heap(Nh, Live)`.
    // Port of erts/emulator/beam/jit/x86/instr_common.cpp:263-266 (emit_test_heap), OTP-29.1.1.
    pub fn emit_test_heap(&mut self, need_heap: ArgVal, live: ArgVal) -> Result<(), AsmError> {
        self.emit_gc_test(0, arg_word(need_heap)?, arg_word(live)?)
    }

    /// Copies unchanged tuple spans while constructing an updated record.
    // Port of erts/emulator/beam/jit/x86/instr_common.cpp:926-990 (emit_update_record),
    // OTP-29.1.1.
    pub fn emit_update_record(
        &mut self,
        hint: ArgVal,
        tuple_size: ArgVal,
        src: ArgVal,
        dst: ArgVal,
        update_count: ArgVal,
        updates: &[ArgVal],
    ) -> Result<(), AsmError> {
        let tuple_size = usize::try_from(arg_word(tuple_size)?)
            .map_err(|_| AsmError::Operand("record tuple size"))?;
        let update_count = usize::try_from(arg_word(update_count)?)
            .map_err(|_| AsmError::Operand("record update count"))?;
        debug_assert_eq!(update_count, updates.len());
        debug_assert!(update_count.is_multiple_of(2));
        let size_on_heap = tuple_size + 1;
        debug_assert!(size_on_heap > 2);

        let mut copy_index = 0usize;
        let next = self.asm.new_label();
        self.mov_arg_to_reg(RET, src)?;
        if matches!(hint, ArgVal::Immediate(value) if value == Term::atom(atoms::REUSE).word())
            && updates.len() == 2
        {
            let field = usize::try_from(arg_word(updates[0])?)
                .map_err(|_| AsmError::Operand("record field index"))?;
            let offset =
                i32::try_from(field * 8).map_err(|_| AsmError::Operand("record field offset"))?;
            self.asm.emit(|e| e.mov_rr(ARG1, RET))?;
            let ptr = self.asm.emit_ptr_val(ARG1, ARG1);
            self.cmp_arg_mem(emit_boxed_val(ptr, offset, 8), updates[1], ARG2)?;
            self.asm.jcc(CondCode::E, next)?;
        }

        let ptr = self.asm.emit_ptr_val(RET, RET);
        for pair in updates.as_chunks::<2>().0 {
            let field = usize::try_from(arg_word(pair[0])?)
                .map_err(|_| AsmError::Operand("record field index"))?;
            debug_assert!(field > 0 && field >= copy_index);
            let count = i32::try_from(field - copy_index)
                .map_err(|_| AsmError::Operand("record copy length"))?;
            let offset = i32::try_from(copy_index * 8)
                .map_err(|_| AsmError::Operand("record copy offset"))?;
            self.asm.emit_copy_words(
                emit_boxed_val(ptr, offset, 0),
                qword_ptr(HTOP, offset),
                count,
                ARG1,
            )?;
            let field_offset =
                i32::try_from(field * 8).map_err(|_| AsmError::Operand("record field offset"))?;
            self.mov_arg_to_mem(qword_ptr(HTOP, field_offset), pair[1], ARG1)?;
            copy_index = field + 1;
        }

        let count = i32::try_from(size_on_heap - copy_index)
            .map_err(|_| AsmError::Operand("record copy length"))?;
        let offset =
            i32::try_from(copy_index * 8).map_err(|_| AsmError::Operand("record copy offset"))?;
        self.asm.emit_copy_words(
            emit_boxed_val(ptr, offset, 0),
            qword_ptr(HTOP, offset),
            count,
            ARG1,
        )?;
        self.asm
            .emit(|e| e.lea(RET, qword_ptr(HTOP, i32::from(TAG_PRIMARY_BOXED))))?;
        self.asm
            .emit(|e| e.add_ri(HTOP, (size_on_heap * 8) as i64))?;
        self.asm.bind(next)?;
        self.mov_arg_from_reg(dst, RET)
    }

    /// Mutates a tuple when its heap range and update values make that safe.
    // Port of erts/emulator/beam/jit/x86/instr_common.cpp:991-1089
    // (emit_update_record_in_place), OTP-29.1.1.
    pub fn emit_update_record_in_place(
        &mut self,
        tuple_size: ArgVal,
        src: ArgVal,
        dst: ArgVal,
        update_count: ArgVal,
        updates: &[ArgVal],
    ) -> Result<(), AsmError> {
        let tuple_size = usize::try_from(arg_word(tuple_size)?)
            .map_err(|_| AsmError::Operand("record tuple size"))?;
        let update_count = usize::try_from(arg_word(update_count)?)
            .map_err(|_| AsmError::Operand("record update count"))?;
        debug_assert_eq!(update_count, updates.len());
        debug_assert!(update_count.is_multiple_of(2));
        let size_on_heap = tuple_size + 1;
        debug_assert!(size_on_heap > 2);

        let mut all_safe = true;
        let mut maybe_immediate = None;
        for pair in updates.as_chunks::<2>().0 {
            let value = pair[1];
            if !(self.always_immediate(value) || value.is_literal()) {
                all_safe = false;
                if maybe_immediate.is_none() && self.always_one_of(value, type_id::MAYBE_IMMEDIATE)
                {
                    maybe_immediate = Some(value);
                } else {
                    maybe_immediate = None;
                    break;
                }
            }
        }

        self.mov_arg_to_reg(RET, src)?;
        if !all_safe {
            let update = self.asm.new_label();
            if let Some(value) = maybe_immediate {
                self.mov_arg_to_reg(ARG4, value)?;
                self.emit_is_boxed(update, ARG4, Distance::Short)?;
            }

            self.preserve_cache(&[ARG1], &[], |m| {
                let copy = m.asm.new_label();
                let high_water = core::mem::offset_of!(crate::ProcessHeader, high_water) as i32;
                m.asm.emit(|e| e.mov_rm(ARG1, process_ref(high_water, 8)))?;
                m.asm.emit(|e| e.cmp_rr(RET, HTOP))?;
                m.asm.short_jcc(CondCode::AE, copy)?;
                m.asm.emit(|e| e.cmp_rr(RET, ARG1))?;
                m.asm.short_jcc(CondCode::AE, update)?;
                m.asm.bind(copy)?;
                m.asm.emit_copy_words(
                    emit_boxed_val(RET, 0, 0),
                    qword_ptr(HTOP, 0),
                    i32::try_from(size_on_heap)
                        .map_err(|_| AsmError::Operand("record copy length"))?,
                    ARG1,
                )?;
                m.asm
                    .emit(|e| e.lea(RET, qword_ptr(HTOP, i32::from(TAG_PRIMARY_BOXED))))?;
                m.asm.emit(|e| e.add_ri(HTOP, (size_on_heap * 8) as i64))?;
                Ok(())
            })?;
            self.asm.bind(update)?;
        }

        for pair in updates.as_chunks::<2>().0 {
            let field = usize::try_from(arg_word(pair[0])?)
                .map_err(|_| AsmError::Operand("record field index"))?;
            debug_assert!(field > 0);
            let offset =
                i32::try_from(field * 8).map_err(|_| AsmError::Operand("record field offset"))?;
            self.mov_arg_to_mem(emit_boxed_val(RET, offset, 8), pair[1], ARG1)?;
        }

        self.mov_arg_from_reg(dst, RET)
    }
}

// Port of erts/emulator/beam/jit/x86/instr_common.cpp:82-106, 2966-3197, OTP-29.1.1.
impl BeamModuleAssembler {
    /// Emits the common raise path after setting `freason`.
    // Port of erts/emulator/beam/jit/x86/instr_common.cpp:82-86 (emit_error), OTP-29.1.1.
    fn emit_error(&mut self, reason: u64) -> Result<(), AsmError> {
        self.asm
            .emit(|e| e.mov_mi(process_ref(process::FREASON, 8), reason as i64))?;
        self.emit_raise_exception()
    }

    /// `badmatch(Src)`.
    // Port of erts/emulator/beam/jit/x86/instr_common.cpp:2966-2969 (emit_badmatch), OTP-29.1.1.
    pub fn emit_badmatch(&mut self, src: ArgVal) -> Result<(), AsmError> {
        self.mov_arg_to_mem(process_ref(process::FVALUE, 8), src, ARG1)?;
        self.emit_error(crate::exc::EXC_BADMATCH)
    }

    /// `case_end(Src)`.
    // Port of erts/emulator/beam/jit/x86/instr_common.cpp:2971-2974 (emit_case_end), OTP-29.1.1.
    pub fn emit_case_end(&mut self, src: ArgVal) -> Result<(), AsmError> {
        self.mov_arg_to_mem(process_ref(process::FVALUE, 8), src, ARG1)?;
        self.emit_error(crate::exc::EXC_CASE_CLAUSE)
    }

    /// Raises `system_limit`.
    // Port of erts/emulator/beam/jit/x86/instr_common.cpp:2976-2978
    // (emit_system_limit_body), OTP-29.1.1.
    pub fn emit_system_limit_body(&mut self) -> Result<(), AsmError> {
        self.emit_error(crate::exc::EXC_SYSTEM_LIMIT)
    }

    /// Raises `if_clause`.
    // Port of erts/emulator/beam/jit/x86/instr_common.cpp:2980-2982 (emit_if_end), OTP-29.1.1.
    pub fn emit_if_end(&mut self) -> Result<(), AsmError> {
        self.emit_error(crate::exc::EXC_IF_CLAUSE)
    }

    /// `badrecord(Src)`.
    // Port of erts/emulator/beam/jit/x86/instr_common.cpp:2984-2987 (emit_badrecord), OTP-29.1.1.
    pub fn emit_badrecord(&mut self, src: ArgVal) -> Result<(), AsmError> {
        self.mov_arg_to_mem(process_ref(process::FVALUE, 8), src, ARG1)?;
        self.emit_error(crate::exc::EXC_BADRECORD)
    }

    /// Registers a catch handler and leaves its tag for `patch_catches`.
    // Port of erts/emulator/beam/jit/x86/instr_common.cpp:2989-3011 (emit_catch), OTP-29.1.1.
    pub fn emit_catch(&mut self, catch_tag: ArgVal, handler: ArgVal) -> Result<(), AsmError> {
        if !catch_tag.is_y_register() {
            return Err(AsmError::Operand("catch tag must be a Y register"));
        }
        let handler = self
            .resolve_beam_label(arg_label(handler)?)
            .ok_or(AsmError::Operand("catch handler label"))?;
        self.asm
            .emit(|e| e.inc_m(process_ref(process::CATCHES, 8)))?;
        let patch_at = self.asm.new_label();
        self.asm.bind(patch_at)?;
        self.asm.emit(|e| e.mov_ri(RETD, i32::MAX as i64))?;
        self.mov_arg_from_reg(catch_tag, RET)?;
        self.catches.push(PatchCatch {
            patch: Patch {
                at: patch_at,
                ptr_offs: 1,
                val_offs: 0,
            },
            handler,
        });
        Ok(())
    }

    /// Stores `Src` and raises with the `try_clause` reason.
    // Port of erts/emulator/beam/jit/x86/instr_common.cpp:3133-3135 (emit_try_case_end),
    // OTP-29.1.1.
    pub fn emit_try_case_end(&mut self, src: ArgVal) -> Result<(), AsmError> {
        self.mov_arg_to_mem(process_ref(process::FVALUE, 8), src, ARG1)?;
        self.emit_error(crate::exc::EXC_TRY_CLAUSE)
    }

    /// Handles an exception marker in X0 after clearing the active catch.
    // Port of erts/emulator/beam/jit/x86/instr_common.cpp:3089-3097 (emit_catch_end),
    // OTP-29.1.1.
    pub fn emit_catch_end(&mut self, catch_tag: ArgVal) -> Result<(), AsmError> {
        let next = self.asm.new_label();
        self.emit_try_end(catch_tag)?;
        self.asm
            .emit(|e| e.cmp_mi(get_x_ref(0, 8), arinsal_term::THE_NON_VALUE as i64))?;
        self.asm.short_jcc(CondCode::NE, next)?;
        let fragment = self.ga_get(GlobalLabels::CatchEndShared)?;
        let target = self.resolve_fragment(fragment);
        self.asm.fragment_call(target)?;
        self.asm.bind(next)
    }

    /// Decrements the catch count and clears its Y slot.
    // Port of erts/emulator/beam/jit/x86/instr_common.cpp:3100-3103 (emit_try_end), OTP-29.1.1.
    pub fn emit_try_end(&mut self, catch_tag: ArgVal) -> Result<(), AsmError> {
        self.asm
            .emit(|e| e.dec_m(process_ref(process::CATCHES, 8)))?;
        self.mov_arg_word(catch_tag, Term::NIL.word(), ARG1)
    }

    /// Decrements the catch count and deallocates its frame.
    // Port of erts/emulator/beam/jit/x86/instr_common.cpp:3105-3108
    // (emit_try_end_deallocate), OTP-29.1.1.
    pub fn emit_try_end_deallocate(&mut self, deallocate: ArgVal) -> Result<(), AsmError> {
        self.asm
            .emit(|e| e.dec_m(process_ref(process::CATCHES, 8)))?;
        self.emit_deallocate(deallocate)
    }

    /// Transfers the caught exception class from X3 to X0.
    // Port of erts/emulator/beam/jit/x86/instr_common.cpp:3110-3130 (emit_try_case), OTP-29.1.1.
    pub fn emit_try_case(&mut self, _catch_tag: ArgVal) -> Result<(), AsmError> {
        self.asm
            .emit(|e| e.dec_m(process_ref(process::CATCHES, 8)))?;
        self.asm.emit(|e| e.mov_rm(RET, get_x_ref(3, 8)))?;
        self.asm.emit(|e| e.mov_mr(get_x_ref(0, 8), RET))?;
        Ok(())
    }

    /// Raises with the provided stacktrace and value through the shared fragment.
    // Port of erts/emulator/beam/jit/x86/instr_common.cpp:3154-3164 (emit_raise), OTP-29.1.1.
    pub fn emit_raise(&mut self, trace: ArgVal, value: ArgVal) -> Result<(), AsmError> {
        let fragment = self.ga_get(GlobalLabels::RaiseShared)?;
        self.mov_arg_to_reg(ARG3, value)?;
        self.mov_arg_to_reg(ARG2, trace)?;
        // `fragment_call(resolve_fragment(ga->get_raise_shared()))`: a call to the module's
        // thunk of the fragment.
        let thunk = self.resolve_fragment(fragment);
        self.asm.fragment_call(thunk)?;
        self.last_error_offset = self.asm.a.offset();
        Ok(())
    }

    /// Builds the stacktrace for X0 through the runtime helper.
    // Port of erts/emulator/beam/jit/x86/instr_common.cpp:3166-3178
    // (emit_build_stacktrace), OTP-29.1.1.
    pub fn emit_build_stacktrace(&mut self) -> Result<(), AsmError> {
        self.mov_arg_to_reg(ARG2, ArgVal::X(0))?;
        self.asm.emit_enter_runtime(Update::HEAP_ALLOC)?;
        self.asm.emit(|e| e.mov_rr(ARG1, C_P))?;
        self.asm
            .runtime_call(build_stacktrace as *const () as usize)?;
        self.asm.emit_leave_runtime(Update::HEAP_ALLOC)?;
        self.asm.emit(|e| e.mov_mr(get_x_ref(0, 8), RET))?;
        Ok(())
    }

    /// Re-raises X2's saved trace, X0's class, and X1's value.
    // Port of erts/emulator/beam/jit/x86/instr_common.cpp:3179-3197 (emit_raw_raise),
    // OTP-29.1.1.
    pub fn emit_raw_raise(&mut self) -> Result<(), AsmError> {
        let next = self.asm.new_label();
        self.mov_arg_to_reg(ARG1, ArgVal::X(2))?;
        self.mov_arg_to_reg(ARG2, ArgVal::X(0))?;
        self.mov_arg_to_reg(ARG3, ArgVal::X(1))?;
        self.asm.emit_enter_runtime(Update::NONE)?;
        self.asm.emit(|e| e.mov_rr(ARG4, C_P))?;
        self.asm.runtime_call(raw_raise as *const () as usize)?;
        self.asm.emit_leave_runtime(Update::NONE)?;
        self.asm.emit(|e| e.test_rr(RET, RET))?;
        self.asm.short_jcc(CondCode::NE, next)?;
        self.emit_raise_exception()?;
        self.asm.bind(next)?;
        self.mov_arg_to_mem(
            get_x_ref(0, 8),
            ArgVal::Immediate(Term::atom(atoms::BADARG).word()),
            ARG1,
        )
    }

    /// Returns `true` in X0 and calls the shared dispatch return fragment.
    // Port of erts/emulator/beam/jit/x86/instr_common.cpp:3254-3263 (emit_i_yield), OTP-29.1.1.
    pub fn emit_i_yield(&mut self) -> Result<(), AsmError> {
        let fragment = self.ga_get(GlobalLabels::DispatchReturn)?;
        self.mov_arg_to_mem(
            get_x_ref(0, 8),
            ArgVal::Immediate(Term::atom(atoms::TRUE).word()),
            ARG1,
        )?;
        // `fragment_call(resolve_fragment(ga->get_dispatch_return()))` (NATIVE_ERLANG_STACK).
        let thunk = self.resolve_fragment(fragment);
        self.asm.fragment_call(thunk)
    }
}

// Port of erts/emulator/beam/jit/x86/instr_common.cpp:268-300, OTP-29.1.1.
impl BeamModuleAssembler {
    /// Exits normally, then jumps to the global scheduler loop.
    // Port of erts/emulator/beam/jit/x86/instr_common.cpp:268-285 (emit_normal_exit), OTP-29.1.1.
    pub fn emit_normal_exit(&mut self) -> Result<(), AsmError> {
        let do_schedule = self.ga_get(GlobalLabels::DoSchedule)?;
        let spec = Update::HEAP_ALLOC.union(Update::REDUCTIONS);
        self.asm.emit_enter_runtime(spec)?;
        // `EXC_NORMAL` is `EXC_EXIT` with the normal-exit index from `error.h`.
        self.asm.emit(|e| {
            e.mov_mi(
                process_ref(process::FREASON, 8),
                (crate::exc::EXC_EXIT | (1 << crate::exc::EXC_OFFSET)) as i64,
            )
        })?;
        self.asm
            .emit(|e| e.mov_mi(process_ref(process::ARITY, 1), 0))?;
        self.asm.emit(|e| e.mov_rr(ARG1, C_P))?;
        self.asm.mov_imm(ARG2, Term::atom(atoms::NORMAL).word())?;
        self.asm
            .runtime_call(erts_do_exit_process as *const () as usize)?;
        self.asm.emit_leave_runtime(spec)?;
        let schedule = self.resolve_fragment(do_schedule);
        self.asm.jmp(schedule)
    }

    /// Continues an exit already in progress, then jumps to the scheduler loop.
    // Port of erts/emulator/beam/jit/x86/instr_common.cpp:287-300 (emit_continue_exit),
    // OTP-29.1.1.
    pub fn emit_continue_exit(&mut self) -> Result<(), AsmError> {
        let do_schedule = self.ga_get(GlobalLabels::DoSchedule)?;
        let spec = Update::HEAP_ALLOC.union(Update::REDUCTIONS);
        self.asm.emit_enter_runtime(spec)?;
        self.asm.emit(|e| e.mov_rr(ARG1, C_P))?;
        self.asm
            .runtime_call(erts_continue_exit_process as *const () as usize)?;
        self.asm.emit_leave_runtime(spec)?;
        let schedule = self.resolve_fragment(do_schedule);
        self.asm.jmp(schedule)
    }
}

impl BeamModuleAssembler {
    /// `i_validate Arity` has no instructions in a non-DEBUG erts build.
    // Port of erts/emulator/beam/jit/x86/instr_common.cpp:215-216 (emit_i_validate), OTP-29.1.1.
    pub fn emit_i_validate(&mut self, arity: ArgVal) -> Result<(), AsmError> {
        let _ = arg_word(arity)?;
        Ok(())
    }

    /// Looks up a process dictionary key through the hash table.
    // Port of erts/emulator/beam/jit/x86/instr_common.cpp:419-431 (emit_i_get), OTP-29.1.1.
    pub fn emit_i_get(&mut self, src: ArgVal, dst: ArgVal) -> Result<(), AsmError> {
        self.mov_arg_to_reg(ARG2, src)?;
        self.asm.emit_enter_runtime(Update::NONE)?;
        self.asm.emit(|e| e.mov_rr(ARG1, C_P))?;
        self.asm
            .runtime_call(erts_pd_hash_get as *const () as usize)?;
        self.asm.emit_leave_runtime(Update::NONE)?;
        self.mov_arg_from_reg(dst, RET)
    }

    /// Looks up a process dictionary key using the compiler supplied hash.
    // Port of erts/emulator/beam/jit/x86/instr_common.cpp:433-448 (emit_i_get_hash), OTP-29.1.1.
    pub fn emit_i_get_hash(
        &mut self,
        src: ArgVal,
        hash: ArgVal,
        dst: ArgVal,
    ) -> Result<(), AsmError> {
        self.mov_arg_to_reg(ARG2, hash)?;
        self.mov_arg_to_reg(ARG3, src)?;
        self.asm.emit_enter_runtime(Update::NONE)?;
        self.asm.emit(|e| e.mov_rr(ARG1, C_P))?;
        self.asm
            .runtime_call(erts_pd_hash_get_with_hx as *const () as usize)?;
        self.asm.emit_leave_runtime(Update::NONE)?;
        self.mov_arg_from_reg(dst, RET)
    }

    /// Loads `erts_this_node->sysname`.
    // Port of erts/emulator/beam/jit/x86/instr_common.cpp:750-762 (emit_node), OTP-29.1.1.
    pub fn emit_node(&mut self, dst: ArgVal) -> Result<(), AsmError> {
        let reg = self.alloc_temp_reg();
        let sysname = arinsal_term::ERL_NODE_SYSNAME_OFFSET as i32;
        self.preserve_cache(&[reg], &[], |m| {
            m.asm
                .mov_imm(reg, arinsal_term::erts_this_node_addr() as u64)?;
            m.asm.emit(|e| e.mov_rm(reg, qword_ptr(reg, 0)))?;
            m.asm.emit(|e| e.mov_rm(reg, qword_ptr(reg, sysname)))
        })?;
        self.mov_arg_from_reg(dst, reg)
    }

    /// Appends one cons cell at the requested heap index and returns its tagged pointer in ARG2.
    // Port of erts/emulator/beam/jit/x86/instr_common.cpp:803-813 (emit_append_cons), OTP-29.1.1.
    pub fn emit_append_cons(&mut self, index: ArgVal, head: ArgVal) -> Result<(), AsmError> {
        let offset = arg_word(index)?
            .checked_mul(16)
            .and_then(|n| i32::try_from(n).ok())
            .ok_or(AsmError::Operand("cons heap offset"))?;
        self.mov_arg_to_mem(qword_ptr(HTOP, offset), head, ARG1)?;
        self.preserve_cache(&[ARG2], &[], |m| {
            m.asm
                .emit(|e| e.mov_mr(qword_ptr(HTOP, offset + 8), ARG2))?;
            m.asm
                .emit(|e| e.lea(ARG2, qword_ptr(HTOP, offset + i32::from(TAG_PRIMARY_LIST))))
        })
    }

    /// Advances HTOP across a cons cell and stores the cell pointer.
    // Port of erts/emulator/beam/jit/x86/instr_common.cpp:815-826 (emit_store_cons), OTP-29.1.1.
    pub fn emit_store_cons(&mut self, len: ArgVal, dst: ArgVal) -> Result<(), AsmError> {
        let bytes = arg_word(len)?
            .checked_mul(16)
            .and_then(|n| i32::try_from(n).ok())
            .ok_or(AsmError::Operand("cons heap size"))?;
        self.preserve_cache(&[HTOP], &[], |m| {
            m.asm.emit(|e| e.add_ri(HTOP, i64::from(bytes)))
        })?;
        self.mov_arg_from_reg(dst, ARG2)
    }

    /// Writes one element into a tuple.
    // Port of erts/emulator/beam/jit/x86/instr_common.cpp:1116-1127 (emit_set_tuple_element), OTP-29.1.1.
    pub fn emit_set_tuple_element(
        &mut self,
        element: ArgVal,
        tuple: ArgVal,
        offset: ArgVal,
    ) -> Result<(), AsmError> {
        self.mov_arg_to_reg(ARG1, tuple)?;
        let boxed_ptr = self.asm.emit_ptr_val(ARG1, ARG1);
        let offset = i32::try_from(arg_word(offset)?)
            .map_err(|_| AsmError::Operand("tuple element byte offset"))?;
        self.mov_arg_to_mem(emit_boxed_val(boxed_ptr, offset, 8), element, ARG2)
    }

    /// Checks a fun value against a literal arity or calls `erl_is_function/3` for a dynamic one.
    // Port of erts/emulator/beam/jit/x86/instr_common.cpp:1298-1330 (emit_is_function2), OTP-29.1.1.
    pub fn emit_is_function2(
        &mut self,
        fail: ArgVal,
        src: ArgVal,
        arity: ArgVal,
    ) -> Result<(), AsmError> {
        let fail = self
            .resolve_beam_label(arg_label(fail)?)
            .ok_or(AsmError::Operand("function test to an unknown label"))?;
        let Some(arity_value) = arity.small_signed() else {
            self.mov_arg_to_reg(ARG2, src)?;
            self.mov_arg_to_reg(ARG3, arity)?;
            self.asm.emit_enter_runtime(Update::NONE)?;
            self.asm.emit(|e| e.mov_rr(ARG1, C_P))?;
            self.asm
                .runtime_call(erl_is_function as *const () as usize)?;
            self.asm.emit_leave_runtime(Update::NONE)?;
            self.asm.emit(|e| e.cmp_ri(RET, 0x4b))?;
            return self.asm.jcc(CondCode::NE, fail);
        };
        if !(0..=255).contains(&arity_value) {
            return self.asm.jmp(fail);
        }

        self.mov_arg_to_reg(ARG1, src)?;
        self.emit_is_boxed_source(fail, src, ARG1, Distance::Long)?;
        let boxed_ptr = self.asm.emit_ptr_val(ARG1, ARG1);
        let expected = FUN_SUBTAG | (arity_value << FUN_HEADER_ARITY_OFFS);
        self.preserve_cache(&[], &[], |m| {
            m.asm
                .emit(|e| e.cmp_mi(emit_boxed_val(boxed_ptr, 0, 2), expected))?;
            m.asm.jcc(CondCode::NE, fail)
        })
    }

    /// Emits the tag-only inequality test shared by exact comparisons.
    // Port of erts/emulator/beam/jit/x86/beam_asm.hpp:1814-1857
    // (emit_is_unequal_based_on_tags), OTP-29.1.1.
    fn emit_is_unequal_based_on_tags(
        &mut self,
        unequal: arinsal_x64::buf::Label,
        src1: ArgVal,
        reg1: arinsal_x64::enc::Gp,
        src2: ArgVal,
        reg2: arinsal_x64::enc::Gp,
        distance: Distance,
    ) -> Result<(), AsmError> {
        if self.always_one_of(src1, type_id::ALWAYS_BOXED) {
            return self.asm.emit_is_boxed(unequal, reg2, distance);
        }
        if self.always_one_of(src2, type_id::ALWAYS_BOXED) {
            return self.asm.emit_is_boxed(unequal, reg1, distance);
        }
        if self.exact_type(src1, type_id::CONS) {
            return self.asm.emit_is_cons(unequal, reg2, distance);
        }
        if self.exact_type(src2, type_id::CONS) {
            return self.asm.emit_is_cons(unequal, reg1, distance);
        }

        self.asm.emit(|e| e.mov_rr(RETD, reg1.r32()))?;
        self.asm.emit(|e| e.or_rr(RETD, reg2.r32()))?;
        if self.never_one_of(src1, type_id::CONS) || self.never_one_of(src2, type_id::CONS) {
            return self.asm.emit_is_boxed(unequal, RET, distance);
        }
        if self.never_one_of(src1, type_id::ALWAYS_BOXED)
            || self.never_one_of(src2, type_id::ALWAYS_BOXED)
        {
            return self.asm.emit_is_cons(unequal, RET, distance);
        }
        self.asm.emit(|e| e.and_ri(RETB, TAG_PRIMARY_MASK as i64))?;
        self.asm.emit(|e| e.cmp_ri(RETB, TAG_PRIMARY_MASK as i64))?;
        self.asm.jcc_dist(CondCode::E, unequal, distance)
    }

    /// Leaves ZF set when both comparison operands must be immediate terms.
    // Port of erts/emulator/beam/jit/x86/beam_asm.hpp:1859-1882
    // (emit_are_both_immediate), OTP-29.1.1.
    fn emit_are_both_immediate(
        &mut self,
        src1: ArgVal,
        reg1: arinsal_x64::enc::Gp,
        src2: ArgVal,
        reg2: arinsal_x64::enc::Gp,
    ) -> Result<(), AsmError> {
        if self.always_immediate(src1) {
            self.asm.emit(|e| e.mov_rr(RETD, reg2.r32()))?;
        } else if self.always_immediate(src2) {
            self.asm.emit(|e| e.mov_rr(RETD, reg1.r32()))?;
        } else {
            self.asm.emit(|e| e.mov_rr(RETD, reg1.r32()))?;
            self.asm.emit(|e| e.and_rr(RETD, reg2.r32()))?;
        }
        self.asm.emit(|e| e.and_ri(RETB, TAG_PRIMARY_MASK as i64))?;
        self.asm.emit(|e| e.cmp_ri(RETB, TAG_PRIMARY_MASK as i64))
    }

    /// Exact equality with literal-specialized list, shallow-boxed, bitstring and map cases.
    // Port of erts/emulator/beam/jit/x86/instr_common.cpp:1820-1972
    // (emit_is_eq_exact), OTP-29.1.1.
    pub fn emit_is_eq_exact(&mut self, fail: ArgVal, x: ArgVal, y: ArgVal) -> Result<(), AsmError> {
        let fail = self
            .resolve_beam_label(arg_label(fail)?)
            .ok_or(AsmError::Operand("exact compare to an unknown label"))?;
        if let ArgVal::Literal(bits) = y {
            let literal = term_from_bits(bits);
            if let Some((len, head)) = literal_is_list_of_immediates(literal) {
                if len == 1 {
                    let head = head.word() as i64;
                    self.mov_arg_to_reg(RET, x)?;
                    if !self.exact_type(x, type_id::CONS) {
                        self.asm.emit_is_cons(fail, RET, Distance::Long)?;
                    }
                    let ptr = self.asm.emit_ptr_val(RET, RET);
                    if is_int32(head) {
                        self.asm.emit(|e| e.cmp_mi(get_car_ref(ptr, 8), head))?;
                    } else {
                        self.asm.mov_imm(ARG1, head as u64)?;
                        self.asm.emit(|e| e.cmp_mr(get_car_ref(ptr, 8), ARG1))?;
                    }
                    self.asm.jcc(CondCode::NE, fail)?;
                    self.asm.emit(|e| e.cmp_mi(get_cdr_ref(ptr, 8), NIL))?;
                    self.asm.jcc(CondCode::NE, fail)?;
                    return Ok(());
                }
                self.mov_arg_to_reg(ARG2, y)?;
                self.mov_arg_to_reg(ARG1, x)?;
                let fragment = self.ga_get(GlobalLabels::IsEqExactListShared)?;
                self.safe_fragment_call(fragment)?;
                return self.asm.jcc(CondCode::NE, fail);
            }
            if literal_is_shallow_boxed(literal) {
                self.mov_arg_to_reg(ARG2, y)?;
                self.mov_arg_to_reg(ARG1, x)?;
                let fragment = self.ga_get(GlobalLabels::IsEqExactShallowBoxedShared)?;
                self.safe_fragment_call(fragment)?;
                return self.asm.jcc(CondCode::NE, fail);
            }
            if literal_is_empty_bitstring(literal) {
                self.mov_arg_to_reg(ARG2, x)?;
                self.emit_is_boxed_source(fail, x, ARG2, Distance::Long)?;
                let boxed = self.asm.emit_ptr_val(ARG2, ARG2);
                self.asm
                    .emit(|e| e.mov_rm(ARG1, emit_boxed_val(boxed, 8, 8)))?;
                let not_sub_bits = self.asm.new_label();
                if self.masked_types(x, type_id::MAYBE_BOXED) == type_id::BITSTRING {
                    self.asm
                        .emit(|e| e.cmp_mi(emit_boxed_val(boxed, 0, 8), HEADER_SUB_BITS))?;
                } else {
                    self.asm
                        .emit(|e| e.mov_rm(RETD, emit_boxed_val(boxed, 0, 4)))?;
                    self.asm.emit(|e| e.cmp_ri(RETD, HEADER_SUB_BITS))?;
                }
                self.asm.short_jcc(CondCode::NE, not_sub_bits)?;
                self.asm
                    .emit(|e| e.mov_rm(ARG1, emit_boxed_val(boxed, SUB_BITS_END_OFFSET, 8)))?;
                self.asm
                    .emit(|e| e.sub_rm(ARG1, emit_boxed_val(boxed, SUB_BITS_START_OFFSET, 8)))?;
                self.asm.bind(not_sub_bits)?;
                if self.masked_types(x, type_id::MAYBE_BOXED) == type_id::BITSTRING {
                    self.asm.emit(|e| e.test_rr(ARG1, ARG1))?;
                } else {
                    self.asm.emit(|e| e.and_ri(RETD, BITSTRING_TAG_MASK))?;
                    self.asm.emit(|e| e.sub_ri(RETD, TAG_HEADER_HEAP_BITS))?;
                    self.asm.emit(|e| e.or_rr(RETD, ARG1D))?;
                }
                return self.asm.jcc(CondCode::NE, fail);
            }
            if literal_is_empty_map(literal) {
                self.mov_arg_to_reg(ARG1, x)?;
                self.emit_is_boxed_source(fail, x, ARG1, Distance::Long)?;
                let boxed = self.asm.emit_ptr_val(ARG1, ARG1);
                self.asm
                    .emit(|e| e.cmp_mi(emit_boxed_val(boxed, 0, 4), MAP_HEADER_FLATMAP))?;
                self.asm.jcc(CondCode::NE, fail)?;
                self.asm
                    .emit(|e| e.cmp_mi(emit_boxed_val(boxed, 8, 4), 0))?;
                return self.asm.jcc(CondCode::NE, fail);
            }
        }

        if x.is_register() && self.always_immediate(y) {
            return self
                .cmp_arg_mem(arg_ref(x, 8)?, y, ARG1)
                .and_then(|()| self.preserve_cache(&[], &[], |m| m.asm.jcc(CondCode::NE, fail)));
        }

        let next = self.asm.new_label();
        self.mov_arg_to_reg(ARG2, y)?;
        self.mov_arg_to_reg(ARG1, x)?;
        self.asm.emit(|e| e.cmp_rr(ARG1, ARG2))?;
        self.asm.short_jcc(CondCode::E, next)?;
        if self.exact_type(x, type_id::INTEGER) && self.exact_type(y, type_id::INTEGER) {
            self.asm.emit(|e| e.mov_rr(RETD, ARG1D))?;
            self.asm.emit(|e| e.or_rr(RETD, ARG2D))?;
            self.asm.emit_test_boxed(RET)?;
            self.asm.jcc(CondCode::NE, fail)?;
        } else if !self.always_same_types(x, y) {
            self.emit_is_unequal_based_on_tags(next, x, ARG1, y, ARG2, Distance::Long)?;
        }
        if self.always_one_of(x, type_id::INTEGER | type_id::FLOAT)
            || self.always_one_of(y, type_id::INTEGER | type_id::FLOAT)
        {
            let fragment = self.ga_get(GlobalLabels::IsEqExactShallowBoxedShared)?;
            self.safe_fragment_call(fragment)?;
            self.asm.jcc(CondCode::NE, fail)?;
        } else {
            self.asm.emit_enter_runtime(Update::NONE)?;
            self.asm.runtime_call(super::rt::eq as *const () as usize)?;
            self.asm.emit_leave_runtime(Update::NONE)?;
            self.asm.emit(|e| e.test_rr(RETD, RETD))?;
            self.asm.jcc(CondCode::E, fail)?;
        }
        self.asm.bind(next)
    }

    /// Exact non-equality with literal-specialized checks matching the equality emitter.
    // Port of erts/emulator/beam/jit/x86/instr_common.cpp:1974-2178
    // (emit_is_ne_exact), OTP-29.1.1.
    pub fn emit_is_ne_exact(&mut self, fail: ArgVal, x: ArgVal, y: ArgVal) -> Result<(), AsmError> {
        let fail = self
            .resolve_beam_label(arg_label(fail)?)
            .ok_or(AsmError::Operand("exact compare to an unknown label"))?;
        if let ArgVal::Literal(bits) = y {
            let literal = term_from_bits(bits);
            if let Some((len, head)) = literal_is_list_of_immediates(literal) {
                if len == 1 {
                    let next = self.asm.new_label();
                    let head = head.word() as i64;
                    self.mov_arg_to_reg(RET, x)?;
                    if !self.exact_type(x, type_id::CONS) {
                        self.asm.emit_is_cons(next, RET, Distance::Short)?;
                    }
                    let ptr = self.asm.emit_ptr_val(RET, RET);
                    if is_int32(head) {
                        self.asm.emit(|e| e.cmp_mi(get_car_ref(ptr, 8), head))?;
                    } else {
                        self.asm.mov_imm(ARG1, head as u64)?;
                        self.asm.emit(|e| e.cmp_mr(get_car_ref(ptr, 8), ARG1))?;
                    }
                    self.asm.short_jcc(CondCode::NE, next)?;
                    self.asm.emit(|e| e.cmp_mi(get_cdr_ref(ptr, 8), NIL))?;
                    self.asm.jcc(CondCode::E, fail)?;
                    return self.asm.bind(next);
                }
                self.mov_arg_to_reg(ARG2, y)?;
                self.mov_arg_to_reg(ARG1, x)?;
                let fragment = self.ga_get(GlobalLabels::IsEqExactListShared)?;
                self.safe_fragment_call(fragment)?;
                return self.asm.jcc(CondCode::E, fail);
            }
            if literal_is_shallow_boxed(literal) {
                self.mov_arg_to_reg(ARG2, y)?;
                self.mov_arg_to_reg(ARG1, x)?;
                let fragment = self.ga_get(GlobalLabels::IsEqExactShallowBoxedShared)?;
                self.safe_fragment_call(fragment)?;
                return self.asm.jcc(CondCode::E, fail);
            }
            if literal_is_empty_bitstring(literal) {
                let next = self.asm.new_label();
                self.mov_arg_to_reg(ARG2, x)?;
                self.emit_is_boxed_source(next, x, ARG2, Distance::Short)?;
                let boxed = self.asm.emit_ptr_val(ARG2, ARG2);
                self.asm
                    .emit(|e| e.mov_rm(ARG1, emit_boxed_val(boxed, 8, 8)))?;
                let not_sub_bits = self.asm.new_label();
                if self.masked_types(x, type_id::MAYBE_BOXED) == type_id::BITSTRING {
                    self.asm
                        .emit(|e| e.cmp_mi(emit_boxed_val(boxed, 0, 8), HEADER_SUB_BITS))?;
                } else {
                    self.asm
                        .emit(|e| e.mov_rm(RETD, emit_boxed_val(boxed, 0, 4)))?;
                    self.asm.emit(|e| e.cmp_ri(RETD, HEADER_SUB_BITS))?;
                }
                self.asm.short_jcc(CondCode::NE, not_sub_bits)?;
                self.asm
                    .emit(|e| e.mov_rm(ARG1, emit_boxed_val(boxed, SUB_BITS_END_OFFSET, 8)))?;
                self.asm
                    .emit(|e| e.sub_rm(ARG1, emit_boxed_val(boxed, SUB_BITS_START_OFFSET, 8)))?;
                self.asm.bind(not_sub_bits)?;
                if self.masked_types(x, type_id::MAYBE_BOXED) == type_id::BITSTRING {
                    self.asm.emit(|e| e.test_rr(ARG1, ARG1))?;
                } else {
                    self.asm.emit(|e| e.and_ri(RETD, BITSTRING_TAG_MASK))?;
                    self.asm.emit(|e| e.sub_ri(RETD, TAG_HEADER_HEAP_BITS))?;
                    self.asm.emit(|e| e.or_rr(RETD, ARG1D))?;
                }
                self.asm.short_jcc(CondCode::E, fail)?;
                return self.asm.bind(next);
            }
            if literal_is_empty_map(literal) {
                let next = self.asm.new_label();
                self.mov_arg_to_reg(ARG1, x)?;
                self.emit_is_boxed_source(next, x, ARG1, Distance::Short)?;
                let boxed = self.asm.emit_ptr_val(ARG1, ARG1);
                self.asm
                    .emit(|e| e.cmp_mi(emit_boxed_val(boxed, 0, 4), MAP_HEADER_FLATMAP))?;
                self.asm.short_jcc(CondCode::NE, next)?;
                self.asm
                    .emit(|e| e.cmp_mi(emit_boxed_val(boxed, 8, 4), 0))?;
                self.asm.jcc(CondCode::E, fail)?;
                return self.asm.bind(next);
            }
        }

        if x.is_register() && self.always_immediate(y) {
            self.cmp_arg_mem(arg_ref(x, 8)?, y, ARG1)?;
            return self.preserve_cache(&[], &[], |m| m.asm.jcc(CondCode::E, fail));
        }

        let next = self.asm.new_label();
        self.mov_arg_to_reg(ARG2, y)?;
        self.mov_arg_to_reg(ARG1, x)?;
        self.asm.emit(|e| e.cmp_rr(ARG1, ARG2))?;
        self.asm.jcc(CondCode::E, fail)?;
        if self.exact_type(x, type_id::INTEGER) && self.exact_type(y, type_id::INTEGER) {
            self.asm.emit(|e| e.mov_rr(RETD, ARG1D))?;
            self.asm.emit(|e| e.or_rr(RETD, ARG2D))?;
            self.asm.emit_test_boxed(RET)?;
            self.asm.short_jcc(CondCode::NE, next)?;
        } else if !self.always_same_types(x, y) {
            self.emit_is_unequal_based_on_tags(next, x, ARG1, y, ARG2, Distance::Short)?;
        }
        if self.always_one_of(x, type_id::INTEGER | type_id::FLOAT)
            || self.always_one_of(y, type_id::INTEGER | type_id::FLOAT)
        {
            let fragment = self.ga_get(GlobalLabels::IsEqExactShallowBoxedShared)?;
            self.safe_fragment_call(fragment)?;
            self.asm.jcc(CondCode::E, fail)?;
        } else {
            self.asm.emit_enter_runtime(Update::NONE)?;
            self.asm.runtime_call(super::rt::eq as *const () as usize)?;
            self.asm.emit_leave_runtime(Update::NONE)?;
            self.asm.emit(|e| e.test_rr(RETD, RETD))?;
            self.asm.jcc(CondCode::NE, fail)?;
        }
        self.asm.bind(next)
    }

    /// Arithmetic equality, including the fast immediate and float paths.
    // Port of erts/emulator/beam/jit/x86/instr_common.cpp:2181-2204 (emit_is_eq), OTP-29.1.1.
    pub fn emit_is_eq(&mut self, fail: ArgVal, lhs: ArgVal, rhs: ArgVal) -> Result<(), AsmError> {
        let fail = self
            .resolve_beam_label(arg_label(fail)?)
            .ok_or(AsmError::Operand("compare to an unknown label"))?;
        let next = self.asm.new_label();
        self.mov_arg_to_reg(ARG2, rhs)?;
        self.mov_arg_to_reg(ARG1, lhs)?;
        self.asm.emit(|e| e.cmp_rr(ARG1, ARG2))?;
        self.asm.short_jcc(CondCode::E, next)?;
        if self.always_one_of(lhs, type_id::CONS | type_id::ALWAYS_BOXED)
            || self.always_one_of(rhs, type_id::CONS | type_id::ALWAYS_BOXED)
        {
            // erts omits the immediate test when either operand cannot be immediate.
        } else {
            self.emit_are_both_immediate(lhs, ARG1, rhs, ARG2)?;
            self.asm.jcc(CondCode::E, fail)?;
        }
        let fragment = self.ga_get(GlobalLabels::ArithEqShared)?;
        self.safe_fragment_call(fragment)?;
        self.asm.jcc(CondCode::NE, fail)?;
        self.asm.bind(next)
    }

    /// Arithmetic non-equality, including the fast immediate and float paths.
    // Port of erts/emulator/beam/jit/x86/instr_common.cpp:2206-2219 (emit_is_ne), OTP-29.1.1.
    pub fn emit_is_ne(&mut self, fail: ArgVal, lhs: ArgVal, rhs: ArgVal) -> Result<(), AsmError> {
        let fail = self
            .resolve_beam_label(arg_label(fail)?)
            .ok_or(AsmError::Operand("compare to an unknown label"))?;
        let next = self.asm.new_label();
        self.mov_arg_to_reg(ARG2, rhs)?;
        self.mov_arg_to_reg(ARG1, lhs)?;
        self.asm.emit(|e| e.cmp_rr(ARG1, ARG2))?;
        self.asm.jcc(CondCode::E, fail)?;
        if !(self.always_one_of(lhs, type_id::CONS | type_id::ALWAYS_BOXED)
            || self.always_one_of(rhs, type_id::CONS | type_id::ALWAYS_BOXED))
        {
            self.emit_are_both_immediate(lhs, ARG1, rhs, ARG2)?;
            self.asm.short_jcc(CondCode::E, next)?;
        }
        let fragment = self.ga_get(GlobalLabels::ArithEqShared)?;
        self.safe_fragment_call(fragment)?;
        self.asm.jcc(CondCode::E, fail)?;
        self.asm.bind(next)
    }

    /// Emits Erlang term ordering for the `is_lt` guard instruction.
    // Port of erts/emulator/beam/jit/x86/instr_common.cpp:2321-2416 (emit_is_lt), OTP-29.1.1.
    pub fn emit_is_lt(&mut self, fail: ArgVal, lhs: ArgVal, rhs: ArgVal) -> Result<(), AsmError> {
        let fail = self
            .resolve_beam_label(arg_label(fail)?)
            .ok_or(AsmError::Operand("compare to an unknown label"))?;
        let generic = self.asm.new_label();
        let do_jge = self.asm.new_label();
        let next = self.asm.new_label();
        let both_small = self.always_small(lhs) && self.always_small(rhs);
        let mut need_generic = !both_small;
        let never_small = lhs.is_literal() || rhs.is_literal();
        self.mov_arg_to_reg(ARG2, rhs)?;
        self.mov_arg_to_reg(ARG1, lhs)?;

        if both_small {
        } else if self.always_small(lhs)
            && self.exact_type(rhs, type_id::INTEGER)
            && self.get_type_entry(rhs).min.is_some()
        {
            need_generic = false;
            self.asm.emit_is_not_boxed(next, ARG2, Distance::Short)?;
        } else if self.always_small(lhs)
            && self.exact_type(rhs, type_id::INTEGER)
            && self.get_type_entry(rhs).max.is_some()
        {
            need_generic = false;
            self.asm.emit_is_not_boxed(fail, ARG2, Distance::Long)?;
        } else if self.exact_type(lhs, type_id::INTEGER)
            && self.get_type_entry(lhs).min.is_some()
            && self.always_small(rhs)
        {
            need_generic = false;
            self.asm.emit_is_not_boxed(fail, ARG1, Distance::Long)?;
        } else if self.exact_type(lhs, type_id::INTEGER)
            && self.get_type_entry(lhs).max.is_some()
            && self.always_small(rhs)
        {
            self.asm.emit_is_not_boxed(next, ARG1, Distance::Short)?;
        } else if never_small {
            self.asm.emit(|e| e.cmp_rr(ARG1, ARG2))?;
            self.asm.short_jcc(CondCode::E, do_jge)?;
        } else if self.always_one_of(lhs, type_id::INTEGER | type_id::ALWAYS_BOXED)
            && self.always_one_of(rhs, type_id::INTEGER | type_id::ALWAYS_BOXED)
        {
            if self.always_small(lhs) {
                self.asm.emit_is_not_boxed(generic, ARG2, Distance::Short)?;
            } else if self.always_small(rhs) {
                self.asm.emit_is_not_boxed(generic, ARG1, Distance::Short)?;
            } else {
                self.asm.emit(|e| e.mov_rr(RETD, ARG1D))?;
                self.asm.emit(|e| e.and_rr(RETD, ARG2D))?;
                self.asm.emit_is_not_boxed(generic, RET, Distance::Short)?;
            }
        } else {
            if self.always_small(rhs) {
                self.asm.emit(|e| e.mov_rr(RETD, ARG1D))?;
            } else if self.always_small(lhs) {
                self.asm.emit(|e| e.mov_rr(RETD, ARG2D))?;
            } else {
                self.asm.emit(|e| e.cmp_rr(ARG1, ARG2))?;
                self.asm.short_jcc(CondCode::E, do_jge)?;
                self.asm.emit(|e| e.mov_rr(RETD, ARG1D))?;
                self.asm.emit(|e| e.and_rr(RETD, ARG2D))?;
            }
            self.asm.emit(|e| e.and_ri(RETB, TAG_IMMED1_MASK))?;
            self.asm.emit(|e| e.cmp_ri(RETB, TAG_IMMED1_SMALL))?;
            self.asm.short_jcc(CondCode::NE, generic)?;
        }

        if !never_small {
            self.asm.emit(|e| e.cmp_rr(ARG1, ARG2))?;
            if need_generic {
                self.asm.short_jmp(do_jge)?;
            }
        }
        self.asm.bind(generic)?;
        if need_generic {
            let fragment = self.ga_get(GlobalLabels::ArithCompareShared)?;
            self.safe_fragment_call(fragment)?;
        }
        self.asm.bind(do_jge)?;
        self.asm.jcc(CondCode::GE, fail)?;
        self.asm.bind(next)
    }

    /// Emits Erlang term ordering for the `is_ge` guard instruction.
    // Port of erts/emulator/beam/jit/x86/instr_common.cpp:2418-2575 (emit_is_ge), OTP-29.1.1.
    pub fn emit_is_ge(&mut self, fail: ArgVal, lhs: ArgVal, rhs: ArgVal) -> Result<(), AsmError> {
        let fail = self
            .resolve_beam_label(arg_label(fail)?)
            .ok_or(AsmError::Operand("compare to an unknown label"))?;
        let both_small = self.always_small(lhs) && self.always_small(rhs);
        if both_small
            && lhs.is_register()
            && matches!(rhs, ArgVal::Immediate(_))
            && is_int32(immediate_word(rhs)?)
        {
            let imm = immediate_word(rhs)?;
            let mem = arg_ref(lhs, 8)?;
            return self.preserve_cache(&[], &[], |m| {
                m.asm.emit(|e| e.cmp_mi(mem, imm))?;
                m.asm.jcc(CondCode::L, fail)
            });
        } else if both_small
            && rhs.is_register()
            && matches!(lhs, ArgVal::Immediate(_))
            && is_int32(immediate_word(lhs)?)
        {
            let imm = immediate_word(lhs)?;
            let mem = arg_ref(rhs, 8)?;
            return self.preserve_cache(&[], &[], |m| {
                m.asm.emit(|e| e.cmp_mi(mem, imm))?;
                m.asm.jcc(CondCode::G, fail)
            });
        }

        let generic = self.asm.new_label();
        let small = self.asm.new_label();
        let do_jl = self.asm.new_label();
        let next = self.asm.new_label();
        let mut need_generic = !both_small;
        let never_small = lhs.is_literal() || rhs.is_literal();
        self.mov_arg_to_reg(ARG2, rhs)?;
        self.mov_arg_to_reg(ARG1, lhs)?;

        if both_small {
        } else if self.always_small(lhs)
            && self.exact_type(rhs, type_id::INTEGER)
            && self.get_type_entry(rhs).min.is_some()
        {
            need_generic = false;
            self.asm.emit_is_not_boxed(fail, ARG2, Distance::Long)?;
        } else if self.always_small(lhs)
            && self.exact_type(rhs, type_id::INTEGER)
            && self.get_type_entry(rhs).max.is_some()
        {
            need_generic = false;
            self.asm.emit_is_not_boxed(next, ARG2, Distance::Short)?;
        } else if self.exact_type(lhs, type_id::INTEGER)
            && self.get_type_entry(lhs).max.is_some()
            && self.always_small(rhs)
        {
            need_generic = false;
            self.asm.emit_is_not_boxed(fail, ARG1, Distance::Long)?;
        } else if self.exact_type(lhs, type_id::INTEGER)
            && self.get_type_entry(lhs).min.is_some()
            && self.always_small(rhs)
        {
            self.asm.emit_is_not_boxed(next, ARG1, Distance::Short)?;
        } else if self.exact_type(lhs, type_id::INTEGER) && self.always_small(rhs) {
            let sign_bit = TAG_HEADER_NEG_BIG - TAG_HEADER_POS_BIG;
            need_generic = false;
            self.asm.emit_is_boxed(small, ARG1, Distance::Short)?;
            let boxed = self.asm.emit_ptr_val(ARG1, ARG1);
            self.asm
                .emit(|e| e.mov_rm(RETD, emit_boxed_val(boxed, 0, 4)))?;
            self.asm.emit(|e| e.test_ri(RETB, sign_bit))?;
            self.asm.jcc(CondCode::NE, fail)?;
            self.asm.short_jmp(next)?;
        } else if self.always_small(lhs) && self.exact_type(rhs, type_id::INTEGER) {
            need_generic = false;
            self.asm.emit_is_boxed(small, ARG2, Distance::Short)?;
            let boxed = self.asm.emit_ptr_val(ARG2, ARG2);
            self.asm
                .emit(|e| e.mov_rm(RETD, emit_boxed_val(boxed, 0, 4)))?;
            self.asm.emit(|e| e.and_ri(RETB, TAG_HEADER_MASK))?;
            self.asm.emit(|e| e.cmp_ri(RETB, TAG_HEADER_NEG_BIG))?;
            self.asm.short_jmp(do_jl)?;
        } else if never_small {
            self.asm.emit(|e| e.cmp_rr(ARG1, ARG2))?;
            self.asm.short_jcc(CondCode::E, next)?;
        } else if self.always_one_of(lhs, type_id::INTEGER | type_id::ALWAYS_BOXED)
            && self.always_one_of(rhs, type_id::INTEGER | type_id::ALWAYS_BOXED)
        {
            if self.always_small(lhs) {
                self.asm.emit_is_not_boxed(generic, ARG2, Distance::Short)?;
            } else if self.always_small(rhs) {
                self.asm.emit_is_not_boxed(generic, ARG1, Distance::Short)?;
            } else {
                self.asm.emit(|e| e.mov_rr(RETD, ARG1D))?;
                self.asm.emit(|e| e.and_rr(RETD, ARG2D))?;
                self.asm.emit_is_not_boxed(generic, RET, Distance::Short)?;
            }
        } else {
            if self.always_small(rhs) {
                self.asm.emit(|e| e.mov_rr(RETD, ARG1D))?;
            } else if self.always_small(lhs) {
                self.asm.emit(|e| e.mov_rr(RETD, ARG2D))?;
            } else {
                self.asm.emit(|e| e.cmp_rr(ARG1, ARG2))?;
                self.asm.short_jcc(CondCode::E, next)?;
                self.asm.emit(|e| e.mov_rr(RETD, ARG1D))?;
                self.asm.emit(|e| e.and_rr(RETD, ARG2D))?;
            }
            self.asm.emit(|e| e.and_ri(RETB, TAG_IMMED1_MASK))?;
            self.asm.emit(|e| e.cmp_ri(RETB, TAG_IMMED1_SMALL))?;
            self.asm.short_jcc(CondCode::NE, generic)?;
        }

        self.asm.bind(small)?;
        if !never_small {
            self.cmp_preserve_cache_rr(ARG1, ARG2)?;
            if need_generic {
                self.asm.short_jmp(do_jl)?;
            }
        }
        self.asm.bind(generic)?;
        if need_generic {
            let fragment = self.ga_get(GlobalLabels::ArithCompareShared)?;
            self.safe_fragment_call(fragment)?;
        }
        self.asm.bind(do_jl)?;
        self.preserve_cache(&[], &[], |m| m.asm.jcc(CondCode::L, fail))?;
        self.asm.bind(next)
    }

    /// Checks the fused `Src >= A && Src < B` instruction.
    // Port of erts/emulator/beam/jit/x86/instr_common.cpp:2824-2855
    // (emit_is_ge_lt), OTP-29.1.1.
    pub fn emit_is_ge_lt(
        &mut self,
        fail1: ArgVal,
        fail2: ArgVal,
        src: ArgVal,
        a: ArgVal,
        b: ArgVal,
    ) -> Result<(), AsmError> {
        let fail1 = self
            .resolve_beam_label(arg_label(fail1)?)
            .ok_or(AsmError::Operand("range test to an unknown label"))?;
        let fail2 = self
            .resolve_beam_label(arg_label(fail2)?)
            .ok_or(AsmError::Operand("range test to an unknown label"))?;
        let generic = self.asm.new_label();
        let next = self.asm.new_label();
        self.mov_arg_to_reg(ARG2, a)?;
        self.mov_arg_to_reg(ARG3, b)?;
        self.mov_arg_to_reg(ARG1, src)?;
        self.asm.emit(|e| e.mov_rr(RETD, ARG1D))?;
        self.asm.emit(|e| e.and_ri(RETB, TAG_IMMED1_MASK))?;
        self.asm.emit(|e| e.cmp_ri(RETB, TAG_IMMED1_SMALL))?;
        self.asm.short_jcc(CondCode::NE, generic)?;
        self.asm.emit(|e| e.cmp_rr(ARG1, ARG2))?;
        self.asm.jcc(CondCode::L, fail1)?;
        self.asm.emit(|e| e.cmp_rr(ARG3, ARG1))?;
        self.asm.jcc(CondCode::GE, fail2)?;
        self.asm.short_jmp(next)?;
        self.asm.bind(generic)?;
        let fragment = self.ga_get(GlobalLabels::IsGeLtShared)?;
        self.safe_fragment_call(fragment)?;
        self.asm.jcc(CondCode::L, fail1)?;
        self.asm.jcc(CondCode::G, fail2)?;
        self.asm.bind(next)
    }

    /// Checks two inclusive lower bounds while loading the source once when its type is small.
    // Port of erts/emulator/beam/jit/x86/instr_common.cpp:2858-2886
    // (emit_is_ge_ge), OTP-29.1.1.
    pub fn emit_is_ge_ge(
        &mut self,
        fail1: ArgVal,
        fail2: ArgVal,
        src: ArgVal,
        a: ArgVal,
        b: ArgVal,
    ) -> Result<(), AsmError> {
        if !self.always_small(src) {
            self.emit_is_ge(fail1, src, a)?;
            return self.emit_is_ge(fail2, src, b);
        }
        let fail1 = self
            .resolve_beam_label(arg_label(fail1)?)
            .ok_or(AsmError::Operand("range test to an unknown label"))?;
        let fail2 = self
            .resolve_beam_label(arg_label(fail2)?)
            .ok_or(AsmError::Operand("range test to an unknown label"))?;
        self.mov_arg_to_reg(RET, src)?;
        self.sub(RET, immediate_word(a)?, ARG1)?;
        self.preserve_cache(&[], &[], |m| m.asm.jcc(CondCode::L, fail1))?;
        self.cmp(
            RET,
            immediate_word(b)?.wrapping_sub(immediate_word(a)?),
            ARG1,
        )?;
        self.preserve_cache(&[], &[], |m| m.asm.jcc(CondCode::B, fail2))
    }

    /// Checks that a small integer lies in an inclusive range.
    // Port of erts/emulator/beam/jit/x86/instr_common.cpp:2889-2915
    // (emit_is_int_in_range), OTP-29.1.1.
    pub fn emit_is_int_in_range(
        &mut self,
        fail: ArgVal,
        src: ArgVal,
        min: ArgVal,
        max: ArgVal,
    ) -> Result<(), AsmError> {
        let fail = self
            .resolve_beam_label(arg_label(fail)?)
            .ok_or(AsmError::Operand("integer range test to an unknown label"))?;
        self.mov_arg_to_reg(RET, src)?;
        self.sub(RET, immediate_word(min)?, ARG1)?;
        self.preserve_cache(&[RET], &[], |m| {
            m.asm.emit(|e| e.test_ri(RETB, TAG_IMMED1_MASK))?;
            m.asm.jcc(CondCode::NE, fail)
        })?;
        self.cmp(
            RET,
            immediate_word(max)?.wrapping_sub(immediate_word(min)?),
            ARG1,
        )?;
        self.preserve_cache(&[], &[], |m| m.asm.jcc(CondCode::A, fail))
    }

    /// Checks that an integer is greater than or equal to a small lower bound.
    // Port of erts/emulator/beam/jit/x86/instr_common.cpp:2917-2960
    // (emit_is_int_ge), OTP-29.1.1.
    pub fn emit_is_int_ge(
        &mut self,
        fail: ArgVal,
        src: ArgVal,
        min: ArgVal,
    ) -> Result<(), AsmError> {
        let fail = self
            .resolve_beam_label(arg_label(fail)?)
            .ok_or(AsmError::Operand("integer compare to an unknown label"))?;
        let small = self.asm.new_label();
        let bignum_fail = self.asm.new_label();
        let bignum_next = self.asm.new_label();
        let src_reg = enc::RCX;
        self.mov_arg_to_reg(src_reg, src)?;
        if self.always_one_of(src, type_id::INTEGER | type_id::ALWAYS_BOXED) {
            self.emit_is_boxed_source(small, src, src_reg, Distance::Long)?;
        } else {
            self.preserve_cache(&[RET], &[], |m| {
                m.asm.emit(|e| e.mov_rr(RETD, src_reg.r32()))?;
                m.asm.emit(|e| e.and_ri(RETB, TAG_IMMED1_MASK))?;
                m.asm.emit(|e| e.cmp_ri(RETB, TAG_IMMED1_SMALL))?;
                m.asm.short_jcc(CondCode::E, small)
            })?;
            self.emit_is_boxed_source(fail, src, src_reg, Distance::Long)?;
        }
        let boxed = self.asm.emit_ptr_val(src_reg, src_reg);
        self.preserve_cache(&[RET], &[], |m| {
            m.asm
                .emit(|e| e.mov_rm(RETD, emit_boxed_val(boxed, 0, 4)))?;
            m.asm.emit(|e| e.and_ri(RETB, TAG_HEADER_MASK))?;
            m.asm.emit(|e| e.cmp_ri(RETB, TAG_HEADER_POS_BIG))?;
            m.asm.short_jcc(CondCode::E, bignum_next)?;
            m.asm.bind(bignum_fail)?;
            m.asm.jmp(fail)?;
            m.asm.bind(small)?;
            m.cmp(src_reg, immediate_word(min)?, RET)?;
            m.asm.short_jcc(CondCode::L, bignum_fail)
        })?;
        self.asm.bind(bignum_next)
    }

    /// Tests whether Src is inside the inclusive range [Min, Max].
    // Port of erts/emulator/beam/jit/x86/instr_common.cpp:2654-2773
    // (emit_is_in_range), OTP-29.1.1.
    pub fn emit_is_in_range(
        &mut self,
        small_fail: ArgVal,
        large_fail: ArgVal,
        src: ArgVal,
        min: ArgVal,
        max: ArgVal,
    ) -> Result<(), AsmError> {
        let small_fail = self
            .resolve_beam_label(arg_label(small_fail)?)
            .ok_or(AsmError::Operand("range test to an unknown label"))?;
        let large_fail = self
            .resolve_beam_label(arg_label(large_fail)?)
            .ok_or(AsmError::Operand("range test to an unknown label"))?;
        let same_fail = small_fail == large_fail;
        let next = self.asm.new_label();
        let generic = self.asm.new_label();
        let mut need_generic = true;
        self.mov_arg_to_reg(ARG1, src)?;

        if self.always_small(src) {
            need_generic = false;
        } else if self.always_one_of(src, type_id::INTEGER | type_id::ALWAYS_BOXED) {
            if same_fail && self.never_one_of(src, type_id::FLOAT) {
                need_generic = false;
                self.preserve_cache(&[], &[], |m| {
                    m.asm.emit(|e| e.test_ri(ARG1.r8(), 1))?;
                    m.asm.short_jcc(CondCode::E, small_fail)
                })?;
            } else {
                self.asm.emit(|e| e.test_ri(ARG1.r8(), 1))?;
                self.asm.short_jcc(CondCode::E, generic)?;
            }
        } else if same_fail {
            let min_imm = immediate_word(min)?;
            let max_imm = immediate_word(max)?;
            self.asm.emit(|e| e.mov_rr(RET, ARG1))?;
            self.sub(RET, min_imm, ARG4)?;
            self.asm.emit(|e| e.test_ri(RETB, TAG_IMMED1_MASK))?;
            self.asm.jcc(CondCode::NE, generic)?;
            self.cmp(RET, max_imm.wrapping_sub(min_imm), ARG4)?;
            self.asm.jcc(CondCode::A, small_fail)?;
            need_generic = false;
            self.asm.short_jmp(next)?;
        } else {
            self.asm.emit(|e| e.mov_rr(RETD, ARG1D))?;
            self.asm.emit(|e| e.and_ri(RETB, TAG_IMMED1_MASK))?;
            self.asm.emit(|e| e.cmp_ri(RETB, TAG_IMMED1_SMALL))?;
            self.asm.short_jcc(CondCode::NE, generic)?;
        }

        if same_fail {
            self.preserve_cache(&[ARG1, RET], &[], |m| {
                m.sub(ARG1, immediate_word(min)?, RET)?;
                m.cmp(
                    ARG1,
                    immediate_word(max)?.wrapping_sub(immediate_word(min)?),
                    RET,
                )?;
                m.asm.jcc(CondCode::A, small_fail)
            })?;
        } else {
            self.preserve_cache(&[RET], &[], |m| {
                m.cmp_arg_reg(ARG1, min, RET)?;
                m.asm.jcc(CondCode::L, small_fail)?;
                m.cmp_arg_reg(ARG1, max, RET)?;
                m.asm.jcc(CondCode::G, large_fail)
            })?;
        }
        if need_generic {
            self.asm.short_jmp(next)?;
        }
        self.asm.bind(generic)?;
        if need_generic {
            self.mov_arg_to_reg(ARG2, min)?;
            self.mov_arg_to_reg(ARG3, max)?;
            let fragment = self.ga_get(GlobalLabels::IsInRangeShared)?;
            self.safe_fragment_call(fragment)?;
            if same_fail {
                self.asm.jcc(CondCode::NE, small_fail)?;
            } else {
                self.asm.jcc(CondCode::L, small_fail)?;
                self.asm.jcc(CondCode::G, large_fail)?;
            }
        }
        self.asm.bind(next)
    }

    /// Emits the `os:perf_counter/0` instruction, producing a small or heap bignum.
    // Port of erts/emulator/beam/jit/x86/instr_common.cpp:3281-3329
    // (emit_i_perf_counter), OTP-29.1.1.
    pub fn emit_i_perf_counter(&mut self) -> Result<(), AsmError> {
        let next = self.asm.new_label();
        let small = self.asm.new_label();
        self.asm.emit_enter_runtime(Update::NONE)?;
        self.asm.mov_imm(RET, perf_counter_address() as u64)?;
        self.asm.dynamic_runtime_call(RET)?;
        self.asm.emit_leave_runtime(Update::NONE)?;
        self.asm.emit(|e| e.mov_rr(ARG1, RET))?;
        self.asm.emit(|e| e.sar_ri(ARG1, 59))?;
        self.asm.emit(|e| e.add_ri(ARG1, 1))?;
        self.asm.emit(|e| e.cmp_ri(ARG1, 1))?;
        self.asm.jcc(CondCode::BE, small)?;
        self.asm.emit(|e| e.mov_mr(tmp_mem_q(0), RET))?;
        self.emit_gc_test(0, ERTS_MAX_UINT64_HEAP_SIZE, 0)?;
        self.asm.emit(|e| e.mov_rm(ARG1, tmp_mem_q(0)))?;
        self.asm
            .emit(|e| e.mov_mi(qword_ptr(HTOP, 0), POS_BIGNUM_HEADER_ONE_DIGIT))?;
        self.asm.emit(|e| e.mov_mr(qword_ptr(HTOP, 8), ARG1))?;
        self.asm
            .emit(|e| e.lea(RET, qword_ptr(HTOP, i32::from(TAG_PRIMARY_BOXED))))?;
        self.asm.emit(|e| e.add_ri(HTOP, 16))?;
        self.asm.short_jmp(next)?;
        self.asm.bind(small)?;
        self.asm.emit(|e| e.shl_ri(RET, TAG_IMMED1_SIZE))?;
        self.asm.emit(|e| e.or_ri(RET, TAG_IMMED1_SMALL))?;
        self.asm.bind(next)?;
        self.mov_arg_from_reg(ArgVal::X(0), RET)
    }

    /// Stores the live count for the line-breakpoint trampoline and aligns its entry.
    // Port of erts/emulator/beam/jit/x86/instr_common.cpp:3352-3373
    // (emit_i_debug_line), OTP-29.1.1.
    pub fn emit_i_debug_line(
        &mut self,
        _loc: ArgVal,
        _index: ArgVal,
        live: ArgVal,
    ) -> Result<(), AsmError> {
        let live = arg_word(live)?;
        if live > 255 {
            return Err(AsmError::Operand("debug line live count"));
        }
        self.asm.mov_imm(super::beam_asm::register::TMP1, live)?;
        self.asm.align_code(8)
    }
}
