//! Port of erts/emulator/beam/jit/x86/instr_map.cpp: map instructions and their shared fragments,
//! OTP-29.1.1.

use arinsal_x64::enc::{self as enc, CondCode, Mem, byte_ptr, qword_ptr};

use crate::common::args::{ArgVal, Relation, memory_relation};
use crate::common::types::{BeamModuleAssemblerCommon, type_id};

use super::beam_asm::register::{
    ARG1, ARG2, ARG2D, ARG3, ARG4, ARG4D, ARG5, ARG5D, ARG6, ARG6D, C_P, E, HTOP, RET, RETB, RETD,
};
use super::beam_asm::{
    AsmError, BeamAssembler, CpuFeature, TAG_PRIMARY_LIST, TAG_PRIMARY_MASK, Update,
    emit_boxed_val, get_arg_ref, get_car_ref, get_cdr_ref, get_x_ref, process, process_ref,
    tmp_mem_q,
};
use super::beam_asm_global::{BeamGlobalAssembler, GlobalLabels};
use super::beam_asm_module::{BeamModuleAssembler, arg_label, arg_word};
use super::rt::{
    beam_jit_get_map_elements, erts_gc_new_map, erts_gc_update_map_assoc, erts_gc_update_map_exact,
    erts_maps_put, erts_maps_update, get_map_element, get_map_element_hash,
};

// erl_term.h / erl_map.h: the map header's type and subtype fields.
const TAG_PRIMARY_BOXED: i64 = 0x2;
const HEADER_ARITY_OFFS: i64 = 6;
const HEADER_MAP_SUBTAG_MASK: i64 = (3 << HEADER_ARITY_OFFS) | 0x3c;
const HAMT_SUBTAG_HEAD_FLATMAP: i64 = 0x2c;
const MAP_HEADER_FLATMAP: u64 = 0x12c;
const MAP_HEADER_FLATMAP_SZ: u64 = 3;
const FLATMAP_SIZE_OFFSET: i32 = 8;
const FLATMAP_KEYS_OFFSET: i32 = 16;
const FLATMAP_VALUES_OFFSET: i32 = 24;
const SCRATCH_X_REG: u32 = 1023;
const HAMT_HEADER_SHIFT: i64 = 16;
const HAMT_MAX_LEVEL: i64 = 16;

impl BeamGlobalAssembler {
    /// Hashes a key with the same two multiply/xor rounds used by `erts_internal_hash`.
    // Port of erts/emulator/beam/jit/x86/instr_map.cpp:41-103 (emit_internal_hash_helper),
    // OTP-29.1.1.
    pub(crate) fn emit_internal_hash_helper(&mut self) -> Result<(), AsmError> {
        let key = ARG2;
        let key_hash = ARG3;
        if key == enc::RDX {
            self.asm.emit(|e| e.mov_mr(tmp_mem_q(0), enc::RDX))?;
        } else {
            assert_eq!(key_hash, enc::RDX);
        }

        self.asm.emit(|e| e.mov_rr(ARG4, ARG2))?;
        self.asm.emit(|e| e.shr_ri(ARG4, 33))?;
        self.asm.emit(|e| e.mov_rr(enc::RDX, ARG2))?;
        self.asm.emit(|e| e.xor_rr(enc::RDX, ARG4))?;
        self.asm.mov_imm(ARG6, 0xFF51AFD7ED558CCD)?;
        self.asm.emit(|e| e.mulx_rrr(ARG4, enc::RDX, ARG6))?;

        self.asm.emit(|e| e.mov_rr(ARG4, enc::RDX))?;
        self.asm.emit(|e| e.shr_ri(ARG4, 33))?;
        self.asm.emit(|e| e.xor_rr(enc::RDX, ARG4))?;
        self.asm.mov_imm(ARG6, 0xC4CEB9FE1A85EC53)?;
        self.asm.emit(|e| e.mulx_rrr(ARG4, enc::RDX, ARG6))?;

        self.asm.emit(|e| e.mov_rr(ARG4, enc::RDX))?;
        self.asm.emit(|e| e.shr_ri(ARG4, 33))?;
        self.asm.emit(|e| e.xor_rr(enc::RDX, ARG4))?;

        if key == enc::RDX {
            self.asm.emit(|e| e.mov_rr(key_hash, enc::RDX))?;
            self.asm.emit(|e| e.mov_rm(key, tmp_mem_q(0)))?;
        }
        Ok(())
    }

    /// Searches a hash-trie node and its collision tuple, returning the value in RET and the
    /// match status in ZF.
    // Port of erts/emulator/beam/jit/x86/instr_map.cpp:106-212 (emit_hashmap_get_element),
    // OTP-29.1.1.
    pub(crate) fn emit_hashmap_get_element(&mut self) -> Result<(), AsmError> {
        let node_loop = self.asm.new_label();
        let node = ARG1;
        let key = ARG2;
        let key_hash = ARG3;
        let header_val = RETD;
        let index = ARG4D;
        let depth = ARG5D;

        self.asm.emit(|e| e.add_ri(node, 8))?;
        self.asm.mov_imm(depth, 0)?;
        self.asm.bind(node_loop)?;

        let done = self.asm.new_label();
        let leaf_node = self.asm.new_label();
        let skip_index_adjustment = self.asm.new_label();
        let collision_node = self.asm.new_label();

        self.asm.emit(|e| e.mov_rr(index, key_hash.r32()))?;
        self.asm.emit(|e| e.and_ri(index, 0xF))?;
        self.asm.emit(|e| e.shr_ri(key_hash, 4))?;
        self.asm.emit(|e| e.inc_r(depth))?;
        self.asm.emit(|e| e.sar_ri(header_val, HAMT_HEADER_SHIFT))?;
        self.asm.emit(|e| e.cmp_ri(header_val, -1))?;
        self.asm.short_jcc(CondCode::E, skip_index_adjustment)?;
        self.asm.emit(|e| e.bt_rr(header_val, index))?;
        self.asm.short_jcc(CondCode::AE, done)?;
        self.asm
            .emit(|e| e.bzhi_rrr(header_val, header_val, index))?;
        self.asm.emit(|e| e.popcnt_rr(index, header_val))?;
        self.asm.bind(skip_index_adjustment)?;

        let child = Mem::base_index(node, ARG4, 3, 8 - TAG_PRIMARY_BOXED as i32, 8);
        self.asm.emit(|e| e.mov_rm(node, child))?;
        self.asm.emit_ptr_val(node, node);
        self.asm
            .emit(|e| e.test_ri(node.r8(), i64::from(TAG_PRIMARY_MASK - TAG_PRIMARY_LIST)))?;
        self.asm.short_jcc(CondCode::E, leaf_node)?;
        self.asm
            .emit(|e| e.mov_rm(header_val, emit_boxed_val(node, 0, 4)))?;
        self.asm.emit(|e| e.test_ri(depth, HAMT_MAX_LEVEL - 1))?;
        self.asm.short_jcc(CondCode::NE, node_loop)?;
        self.asm.short_jmp(collision_node)?;

        self.asm.bind(leaf_node)?;
        self.asm.emit(|e| e.cmp_mr(get_car_ref(node, 8), key))?;
        self.asm.emit(|e| e.mov_rm(RET, get_cdr_ref(node, 8)))?;
        self.asm.bind(done)?;
        self.asm.emit(|e| e.ret())?;

        self.asm.bind(collision_node)?;
        self.asm.emit(|e| e.shr_ri(header_val, 6))?;
        self.asm.emit(|e| {
            // Asmjit infers address-size 32 from RETd for this qword memory operand.
            e.bytes.push(0x67);
            e.lea(ARG6D, qword_ptr(header_val.r64(), -1))
        })?;
        let linear_loop = self.asm.new_label();
        self.asm.bind(linear_loop)?;
        let leaf = Mem::base_index(node, ARG6, 3, 8 - TAG_PRIMARY_BOXED as i32, 8);
        self.asm.emit(|e| e.mov_rm(ARG3, leaf))?;
        self.asm.emit_ptr_val(ARG3, ARG3);
        self.asm.emit(|e| e.cmp_rm(key, get_car_ref(ARG3, 8)))?;
        self.asm.emit(|e| e.mov_rm(RET, get_cdr_ref(ARG3, 8)))?;
        self.asm.short_jcc(CondCode::E, done)?;
        self.asm.emit(|e| e.dec_r(ARG6D))?;
        self.asm.short_jcc(CondCode::NS, linear_loop)?;
        self.asm.emit(|e| e.ret())
    }

    /// Looks up a key in a flatmap, returning the value in RET and match status in ZF.
    // Port of erts/emulator/beam/jit/x86/instr_map.cpp:215-238 (emit_flatmap_get_element),
    // OTP-29.1.1.
    pub(crate) fn emit_flatmap_get_element(&mut self) -> Result<(), AsmError> {
        let fail = self.asm.new_label();
        let loop_label = self.asm.new_label();
        self.asm
            .emit(|e| e.mov_rm(RETD, emit_boxed_val(ARG1, FLATMAP_SIZE_OFFSET, 4)))?;
        self.asm
            .emit(|e| e.mov_rm(ARG4, emit_boxed_val(ARG1, FLATMAP_KEYS_OFFSET, 8)))?;
        self.asm.emit_ptr_val(ARG4, ARG4);
        self.asm.bind(loop_label)?;
        self.asm.emit(|e| e.dec_r(RETD))?;
        self.asm.short_jcc(CondCode::L, fail)?;
        let candidate = Mem::base_index(ARG4, RET, 3, 8 - TAG_PRIMARY_BOXED as i32, 8);
        self.asm.emit(|e| e.cmp_rm(ARG2, candidate))?;
        self.asm.short_jcc(CondCode::NE, loop_label)?;
        self.asm.emit(|e| {
            e.mov_rm(
                RET,
                Mem::base_index(
                    ARG1,
                    RET,
                    3,
                    FLATMAP_VALUES_OFFSET - TAG_PRIMARY_BOXED as i32,
                    8,
                ),
            )
        })?;
        self.asm.bind(fail)?;
        self.asm.emit(|e| e.ret())
    }

    /// Gets a key from an immediate-key flatmap or from a HAMT, falling back to the runtime
    /// helper for non-immediate keys.
    // Port of erts/emulator/beam/jit/x86/instr_map.cpp:349-393
    // (emit_i_get_map_element_shared), OTP-29.1.1.
    pub(crate) fn emit_i_get_map_element_shared(&mut self) -> Result<(), AsmError> {
        let generic = self.asm.new_label();
        let hashmap = self.asm.new_label();

        self.asm.emit(|e| e.mov_rr(RETD, ARG2D))?;
        self.asm.emit(|e| e.and_ri(RETB, 0x3))?;
        self.asm.emit(|e| e.cmp_ri(RETB, 0x3))?;
        self.asm.short_jcc(CondCode::NE, generic)?;

        self.asm.emit_ptr_val(ARG1, ARG1);
        self.asm
            .emit(|e| e.mov_rm(RETD, emit_boxed_val(ARG1, 0, 4)))?;
        self.asm.emit(|e| e.mov_rr(ARG4D, RETD))?;
        self.asm.emit(|e| e.and_ri(ARG4D, HEADER_MAP_SUBTAG_MASK))?;
        self.asm
            .emit(|e| e.cmp_ri(ARG4D, HAMT_SUBTAG_HEAD_FLATMAP))?;
        self.asm.short_jcc(CondCode::NE, hashmap)?;
        self.emit_flatmap_get_element()?;

        self.asm.bind(generic)?;
        self.asm.emit_enter_frame()?;
        self.asm.emit_enter_runtime(Update::NONE)?;
        self.asm
            .runtime_call(get_map_element as *const () as usize)?;
        self.asm.emit_leave_runtime(Update::NONE)?;
        self.asm.emit_leave_frame()?;
        self.asm.emit_test_the_non_value(RET)?;
        self.asm.emit(|e| e.setcc_r(CondCode::NE, ARG1.r8()))?;
        self.asm.emit(|e| e.dec_r(ARG1.r8()))?;
        self.asm.emit(|e| e.ret())?;

        self.asm.bind(hashmap)?;
        self.emit_internal_hash_helper()?;
        self.emit_hashmap_get_element()
    }

    /// Gets a key using a compiler supplied hash, searching flatmaps or the HAMT directly.
    // Port of erts/emulator/beam/jit/x86/instr_map.cpp:520-535
    // (emit_i_get_map_element_hash_shared), OTP-29.1.1.
    pub(crate) fn emit_i_get_map_element_hash_shared(&mut self) -> Result<(), AsmError> {
        let hashmap = self.asm.new_label();

        self.asm.emit_ptr_val(ARG1, ARG1);
        self.asm
            .emit(|e| e.mov_rm(RETD, emit_boxed_val(ARG1, 0, 4)))?;
        self.asm.emit(|e| e.mov_rr(ARG4D, RETD))?;
        self.asm.emit(|e| e.and_ri(ARG4D, HEADER_MAP_SUBTAG_MASK))?;
        self.asm
            .emit(|e| e.cmp_ri(ARG4D, HAMT_SUBTAG_HEAD_FLATMAP))?;
        self.asm.short_jcc(CondCode::NE, hashmap)?;
        self.emit_flatmap_get_element()?;

        self.asm.bind(hashmap)?;
        self.emit_hashmap_get_element()
    }

    /// `new_map_shared`: calls the GC-aware map constructor with the live X register array.
    // Port of erts/emulator/beam/jit/x86/instr_map.cpp:240-253 (emit_new_map_shared),
    // OTP-29.1.1.
    pub(crate) fn emit_new_map_shared(&mut self) -> Result<(), AsmError> {
        self.asm.emit_enter_frame()?;
        let update = Update::REDUCTIONS.union(Update::HEAP_ALLOC);
        self.asm.emit_enter_runtime(update)?;
        self.asm.emit(|e| e.mov_rr(ARG1, C_P))?;
        self.asm.load_x_reg_array(ARG2)?;
        self.asm
            .runtime_call(erts_gc_new_map as *const () as usize)?;
        self.asm.emit_leave_runtime(update)?;
        self.asm.emit_leave_frame()?;
        self.asm.emit(|e| e.ret())
    }

    /// `update_map_assoc_shared`: allocates an associative map update from embedded rodata.
    // Port of erts/emulator/beam/jit/x86/instr_map.cpp:568-583
    // (emit_update_map_assoc_shared), OTP-29.1.1.
    pub(crate) fn emit_update_map_assoc_shared(&mut self) -> Result<(), AsmError> {
        self.asm.emit_enter_frame()?;
        let update = Update::REDUCTIONS.union(Update::HEAP_ALLOC);
        self.asm.emit_enter_runtime(update)?;
        self.asm.emit(|e| e.mov_rr(ARG1, C_P))?;
        self.asm.load_x_reg_array(ARG2)?;
        self.asm
            .runtime_call(erts_gc_update_map_assoc as *const () as usize)?;
        self.asm.emit_leave_runtime(update)?;
        self.asm.emit_leave_frame()?;
        self.asm.emit(|e| e.ret())
    }

    /// `update_map_single_assoc_shared`: calls `erts_maps_put` for one key/value pair.
    // Port of erts/emulator/beam/jit/x86/instr_map.cpp:585-598
    // (emit_update_map_single_assoc_shared), OTP-29.1.1.
    pub(crate) fn emit_update_map_single_assoc_shared(&mut self) -> Result<(), AsmError> {
        self.asm.emit_enter_frame()?;
        self.asm.emit_enter_runtime(Update::HEAP_ALLOC)?;
        self.asm.emit(|e| e.mov_rr(ARG1, C_P))?;
        self.asm.runtime_call(erts_maps_put as *const () as usize)?;
        self.asm.emit_leave_runtime(Update::HEAP_ALLOC)?;
        self.asm.emit_leave_frame()?;
        self.asm.emit(|e| e.ret())
    }

    /// `update_map_exact_guard_shared`: returns with ZF set for `THE_NON_VALUE`.
    // Port of erts/emulator/beam/jit/x86/instr_map.cpp:628-646
    // (emit_update_map_exact_guard_shared), OTP-29.1.1.
    pub(crate) fn emit_update_map_exact_guard_shared(&mut self) -> Result<(), AsmError> {
        self.asm.emit_enter_frame()?;
        let update = Update::REDUCTIONS.union(Update::HEAP_ALLOC);
        self.asm.emit_enter_runtime(update)?;
        self.asm.emit(|e| e.mov_rr(ARG1, C_P))?;
        self.asm.load_x_reg_array(ARG2)?;
        self.asm
            .runtime_call(erts_gc_update_map_exact as *const () as usize)?;
        self.asm.emit_leave_runtime(update)?;
        self.asm.emit_leave_frame()?;
        self.asm.emit_test_the_non_value(RET)?;
        self.asm.emit(|e| e.ret())
    }

    /// `update_map_exact_body_shared`: raises on `THE_NON_VALUE` and returns the updated map.
    // Port of erts/emulator/beam/jit/x86/instr_map.cpp:647-672
    // (emit_update_map_exact_body_shared), OTP-29.1.1.
    pub(crate) fn emit_update_map_exact_body_shared(&mut self) -> Result<(), AsmError> {
        let error = self.asm.new_label();
        self.asm.emit_enter_frame()?;
        let update = Update::REDUCTIONS.union(Update::HEAP_ALLOC);
        self.asm.emit_enter_runtime(update)?;
        self.asm.emit(|e| e.mov_rr(ARG1, C_P))?;
        self.asm.load_x_reg_array(ARG2)?;
        self.asm
            .runtime_call(erts_gc_update_map_exact as *const () as usize)?;
        self.asm.emit_leave_runtime(update)?;
        self.asm.emit_leave_frame()?;
        self.asm.emit_test_the_non_value(RET)?;
        self.asm.short_jcc(CondCode::E, error)?;
        self.asm.emit(|e| e.ret())?;
        self.asm.bind(error)?;
        self.asm.mov_imm(ARG4, 0)?;
        let raise = self.label(GlobalLabels::RaiseException);
        self.asm.jmp(raise)
    }

    /// `update_map_single_exact_body_shared`: performs one exact update and raises BADKEY on
    /// failure, preserving the key across the runtime call.
    // Port of erts/emulator/beam/jit/x86/instr_map.cpp:674-708
    // (emit_update_map_single_exact_body_shared), OTP-29.1.1.
    pub(crate) fn emit_update_map_single_exact_body_shared(&mut self) -> Result<(), AsmError> {
        let error = self.asm.new_label();
        self.asm.emit(|e| e.mov_mr(tmp_mem_q(1), ARG2))?;
        self.asm.emit_enter_frame()?;
        self.asm.emit_enter_runtime(Update::HEAP_ALLOC)?;
        self.asm.emit(|e| e.mov_rr(ARG1, C_P))?;
        self.asm.emit(|e| e.lea(ARG5, tmp_mem_q(0)))?;
        self.asm
            .runtime_call(erts_maps_update as *const () as usize)?;
        self.asm.emit_leave_runtime(Update::HEAP_ALLOC)?;
        self.asm.emit_leave_frame()?;
        self.asm.emit(|e| e.test_rr(RETD, RETD))?;
        self.asm.short_jcc(CondCode::E, error)?;
        self.asm.emit(|e| e.mov_rm(RET, tmp_mem_q(0)))?;
        self.asm.emit(|e| e.ret())?;

        self.asm.bind(error)?;
        self.asm.emit(|e| e.mov_rm(RET, tmp_mem_q(1)))?;
        self.asm.emit(|e| {
            e.mov_mi(
                process_ref(process::FREASON, 8),
                crate::exc::EXC_BADKEY as i64,
            )
        })?;
        self.asm
            .emit(|e| e.mov_mr(process_ref(process::FVALUE, 8), RET))?;
        self.asm.mov_imm(ARG4, 0)?;
        let raise = self.label(GlobalLabels::RaiseException);
        self.asm.jmp(raise)
    }
}

impl BeamModuleAssembler {
    /// `new_map`: embeds the key/value vector and calls the GC-aware constructor fragment.
    // Port of erts/emulator/beam/jit/x86/instr_map.cpp:255-267 (emit_new_map), OTP-29.1.1.
    pub fn emit_new_map(
        &mut self,
        dst: ArgVal,
        live: ArgVal,
        size: ArgVal,
        args: &[ArgVal],
    ) -> Result<(), AsmError> {
        assert_eq!(arg_word(size)?, args.len() as u64);
        self.asm.mov_imm(ARG3, arg_word(live)?)?;
        self.asm.mov_imm(ARG4, args.len() as u64)?;
        self.embed_vararg_rodata(args, ARG5, super::beam_asm::CP_SIZE as u32)?;
        let fragment = self.ga_get(GlobalLabels::NewMapShared)?;
        let target = self.resolve_fragment(fragment);
        self.asm.fragment_call(target)?;
        self.mov_arg_from_reg(dst, RET)
    }

    /// Builds a literal-key flatmap directly on the heap, using the AVX pair copy when erts does.
    // Port of erts/emulator/beam/jit/x86/instr_map.cpp:269-347
    // (emit_i_new_small_map_lit), OTP-29.1.1.
    pub fn emit_i_new_small_map_lit(
        &mut self,
        dst: ArgVal,
        live: ArgVal,
        keys: ArgVal,
        size: ArgVal,
        args: &[ArgVal],
    ) -> Result<(), AsmError> {
        assert_eq!(arg_word(size)?, args.len() as u64);
        let live = arg_word(live)?;
        self.emit_gc_test(0, args.len() as u64 + MAP_HEADER_FLATMAP_SZ + 1, live)?;

        let mut data = Vec::with_capacity(args.len() + MAP_HEADER_FLATMAP_SZ as usize + 1);
        data.push(ArgVal::Word(MAP_HEADER_FLATMAP));
        data.push(size);
        data.push(keys);
        data.extend_from_slice(args);
        let size = data.len();
        self.asm
            .emit(|e| e.mov_mi(qword_ptr(HTOP, 0), MAP_HEADER_FLATMAP as i64))?;

        let mut i = 1;
        while i < size - 1 {
            let dst0 = qword_ptr(HTOP, (i * 8) as i32);
            let dst1 = qword_ptr(HTOP, ((i + 1) * 8) as i32);
            let first = data[i];
            let second = data[i + 1];
            match memory_relation(first, second) {
                Relation::Consecutive => {
                    let src = get_arg_ref(first, 16)
                        .ok_or(AsmError::Operand("consecutive map source registers"))?;
                    self.asm.vmovups_xm(enc::Xmm(0), src)?;
                    self.asm.vmovups_mx(dst0.with_size(16), enc::Xmm(0))?;
                }
                Relation::ReverseConsecutive if BeamAssembler::has_cpu_feature(CpuFeature::Avx) => {
                    let src = get_arg_ref(second, 16)
                        .ok_or(AsmError::Operand("reversed map source registers"))?;
                    self.asm.emit(|e| e.vpermilpd_xmi(enc::Xmm(0), src, 1))?;
                    self.asm.vmovups_mx(dst0.with_size(16), enc::Xmm(0))?;
                }
                Relation::ReverseConsecutive | Relation::None => {
                    for (dst, value) in [(dst0, first), (dst1, second)] {
                        if let ArgVal::Word(value) = value
                            && i32::try_from(value).is_ok()
                        {
                            self.asm.emit(|e| e.mov_mi(dst, value as i64))?;
                        } else {
                            self.mov_arg_to_mem(dst, value, ARG1)?;
                        }
                    }
                }
            }
            i += 2;
        }

        if i < size {
            let dst = qword_ptr(HTOP, (i * 8) as i32);
            if let ArgVal::Word(value) = data[i]
                && i32::try_from(value).is_ok()
            {
                self.asm.emit(|e| e.mov_mi(dst, value as i64))?;
            } else {
                self.mov_arg_to_mem(dst, data[i], ARG1)?;
            }
        }
        self.asm
            .emit(|e| e.lea(ARG1, byte_ptr(HTOP, TAG_PRIMARY_BOXED as i32)))?;
        self.asm.emit(|e| e.add_ri(HTOP, (size * 8) as i64))?;
        self.mov_arg_from_reg(dst, ARG1)
    }

    /// Looks up one map element through the shared flatmap/HAMT fragment when the key may be
    /// immediate and BMI2 is available; otherwise calls the generic runtime lookup.
    // Port of erts/emulator/beam/jit/x86/instr_map.cpp:395-419 (emit_i_get_map_element),
    // OTP-29.1.1.
    pub fn emit_i_get_map_element(
        &mut self,
        fail: ArgVal,
        src: ArgVal,
        key: ArgVal,
        dst: ArgVal,
    ) -> Result<(), AsmError> {
        let fail = self
            .resolve_beam_label(arg_label(fail)?)
            .ok_or(AsmError::Operand("map-get-element failure label"))?;
        self.mov_arg_to_reg(ARG1, src)?;
        self.mov_arg_to_reg(ARG2, key)?;

        if self.maybe_one_of(key, type_id::MAYBE_IMMEDIATE)
            && BeamAssembler::has_cpu_feature(CpuFeature::Bmi2)
        {
            let fragment = self.ga_get(GlobalLabels::IGetMapElementShared)?;
            self.safe_fragment_call(fragment)?;
            self.asm.jcc(CondCode::NE, fail)?;
        } else {
            self.asm.emit_enter_runtime(Update::NONE)?;
            self.asm
                .runtime_call(get_map_element as *const () as usize)?;
            self.asm.emit_leave_runtime(Update::NONE)?;
            self.asm.emit_test_the_non_value(RET)?;
            self.asm.jcc(CondCode::E, fail)?;
        }

        if !(dst.is_x_register() && dst.reg() == Some(SCRATCH_X_REG)) {
            self.mov_arg_from_reg(dst, RET)?;
        }
        Ok(())
    }

    /// Extracts requested keys from a flatmap inline when possible and otherwise calls the
    /// generic multi-get runtime helper with erts' triplet table.
    // Port of erts/emulator/beam/jit/x86/instr_map.cpp:422-518
    // (emit_i_get_map_elements), OTP-29.1.1.
    pub fn emit_i_get_map_elements(
        &mut self,
        fail: ArgVal,
        src: ArgVal,
        size: ArgVal,
        args: &[ArgVal],
    ) -> Result<(), AsmError> {
        let fail = self
            .resolve_beam_label(arg_label(fail)?)
            .ok_or(AsmError::Operand("map-get-elements failure label"))?;
        assert_eq!(arg_word(size)?, args.len() as u64);
        assert_eq!(args.len() % 3, 0);

        let generic = self.asm.new_label();
        let next = self.asm.new_label();
        let mut can_inline = args.len() < 8 * 3;
        for key in args.iter().step_by(3) {
            can_inline &= matches!(key, ArgVal::Immediate(_));
        }

        self.mov_arg_to_reg(ARG1, src)?;
        if can_inline {
            self.asm.emit_ptr_val(ARG1, ARG1);
            self.asm
                .emit(|e| e.mov_rm(RETD, emit_boxed_val(ARG1, 0, 4)))?;
            self.asm.emit(|e| e.and_ri(RETB, HEADER_MAP_SUBTAG_MASK))?;
            self.asm
                .emit(|e| e.cmp_ri(RETB, HAMT_SUBTAG_HEAD_FLATMAP))?;
            self.asm.jcc(CondCode::NE, generic)?;

            self.asm
                .emit(|e| e.mov_rm(RETD, emit_boxed_val(ARG1, FLATMAP_SIZE_OFFSET, 4)))?;
            self.asm
                .emit(|e| e.mov_rm(ARG2, emit_boxed_val(ARG1, FLATMAP_KEYS_OFFSET, 8)))?;
            self.asm.emit_ptr_val(ARG2, ARG2);

            let mut i = args.len() as isize - 3;
            while i >= 0 {
                let loop_label = self.asm.new_label();
                let candidate = Mem::base_index(ARG2, RET, 3, 8 - TAG_PRIMARY_BOXED as i32, 8);
                self.asm.bind(loop_label)?;
                self.asm.emit(|e| e.dec_r(RETD))?;
                self.asm.jcc(CondCode::L, fail)?;
                self.cmp_arg_mem(candidate, args[i as usize], ARG3)?;
                self.asm.short_jcc(CondCode::NE, loop_label)?;

                let dst = args[i as usize + 1];
                if !(dst.is_x_register() && dst.reg() == Some(SCRATCH_X_REG)) {
                    self.mov_arg_from_mem(
                        dst,
                        Mem::base_index(
                            ARG1,
                            RET,
                            3,
                            FLATMAP_VALUES_OFFSET - TAG_PRIMARY_BOXED as i32,
                            8,
                        ),
                        ARG3,
                    )?;
                }
                i -= 3;
            }
            self.asm.short_jmp(next)?;
        }

        self.asm.bind(generic)?;
        self.asm.mov_imm(ARG4, (args.len() / 3) as u64)?;
        self.embed_vararg_rodata(args, ARG5, 0)?;
        self.asm.emit(|e| e.mov_rr(ARG3, E))?;
        self.asm.emit_enter_runtime(Update::NONE)?;
        self.asm.load_x_reg_array(ARG2)?;
        self.asm
            .runtime_call(beam_jit_get_map_elements as *const () as usize)?;
        self.asm.emit_leave_runtime(Update::NONE)?;
        self.asm.emit(|e| e.test_rr(RET, RET))?;
        self.asm.jcc(CondCode::E, fail)?;
        self.asm.bind(next)
    }

    /// Looks up one map element using the loader's precomputed key hash when the key is
    /// immediate and BMI2 is available; otherwise calls the hashed runtime lookup.
    // Port of erts/emulator/beam/jit/x86/instr_map.cpp:538-565
    // (emit_i_get_map_element_hash), OTP-29.1.1.
    pub fn emit_i_get_map_element_hash(
        &mut self,
        fail: ArgVal,
        src: ArgVal,
        key: ArgVal,
        hash: ArgVal,
        dst: ArgVal,
    ) -> Result<(), AsmError> {
        let fail = self
            .resolve_beam_label(arg_label(fail)?)
            .ok_or(AsmError::Operand("hashed map-get-element failure label"))?;
        self.mov_arg_to_reg(ARG1, src)?;
        self.mov_arg_to_reg(ARG2, key)?;
        self.mov_arg_to_reg(ARG3, hash)?;

        if key.is_immed() && BeamAssembler::has_cpu_feature(CpuFeature::Bmi2) {
            let fragment = self.ga_get(GlobalLabels::IGetMapElementHashShared)?;
            self.safe_fragment_call(fragment)?;
            self.asm.jcc(CondCode::NE, fail)?;
        } else {
            self.asm.emit_enter_runtime(Update::NONE)?;
            self.asm
                .runtime_call(get_map_element_hash as *const () as usize)?;
            self.asm.emit_leave_runtime(Update::NONE)?;
            self.asm.emit_test_the_non_value(RET)?;
            self.asm.jcc(CondCode::E, fail)?;
        }

        if !(dst.is_x_register() && dst.reg() == Some(SCRATCH_X_REG)) {
            self.mov_arg_from_reg(dst, RET)?;
        }
        Ok(())
    }

    /// Applies one or more associative map updates.
    // Port of erts/emulator/beam/jit/x86/instr_map.cpp:600-626 (emit_update_map_assoc),
    // OTP-29.1.1.
    pub fn emit_update_map_assoc(
        &mut self,
        src: ArgVal,
        dst: ArgVal,
        live: ArgVal,
        size: ArgVal,
        args: &[ArgVal],
    ) -> Result<(), AsmError> {
        assert_eq!(arg_word(size)?, args.len() as u64);
        let live = arg_word(live)?;
        if args.len() == 2 {
            self.mov_arg_to_reg(ARG2, args[0])?;
            self.mov_arg_to_reg(ARG3, args[1])?;
            self.mov_arg_to_reg(ARG4, src)?;
            let fragment = self.ga_get(GlobalLabels::UpdateMapSingleAssocShared)?;
            self.safe_fragment_call(fragment)?;
        } else {
            self.mov_arg_to_mem(get_x_ref(live as u32, 8), src, ARG1)?;
            self.asm.mov_imm(ARG3, live)?;
            self.asm.mov_imm(ARG4, args.len() as u64)?;
            self.embed_vararg_rodata(args, ARG5, super::beam_asm::CP_SIZE as u32)?;
            let fragment = self.ga_get(GlobalLabels::UpdateMapAssocShared)?;
            let target = self.resolve_fragment(fragment);
            self.asm.fragment_call(target)?;
        }
        self.mov_arg_from_reg(dst, RET)
    }

    /// Applies exact map updates, branching to the fail label or raising BADKEY as erts specifies.
    // Port of erts/emulator/beam/jit/x86/instr_map.cpp:710-716 (emit_update_map_exact),
    // OTP-29.1.1.
    pub fn emit_update_map_exact(
        &mut self,
        src: ArgVal,
        fail: ArgVal,
        dst: ArgVal,
        live: ArgVal,
        size: ArgVal,
        args: &[ArgVal],
    ) -> Result<(), AsmError> {
        assert_eq!(arg_word(size)?, args.len() as u64);
        let fail = arg_label(fail)?;
        let live = arg_word(live)?;
        if args.len() == 2 && fail == 0 {
            self.mov_arg_to_reg(ARG2, args[0])?;
            self.mov_arg_to_reg(ARG3, args[1])?;
            self.mov_arg_to_reg(ARG4, src)?;
            let fragment = self.ga_get(GlobalLabels::UpdateMapSingleExactBodyShared)?;
            let target = self.resolve_fragment(fragment);
            self.asm.fragment_call(target)?;
        } else {
            self.mov_arg_to_mem(get_x_ref(live as u32, 8), src, ARG1)?;
            self.asm.mov_imm(ARG3, live)?;
            self.asm.mov_imm(ARG4, args.len() as u64)?;
            self.embed_vararg_rodata(args, ARG5, super::beam_asm::CP_SIZE as u32)?;
            if fail != 0 {
                let fragment = self.ga_get(GlobalLabels::UpdateMapExactGuardShared)?;
                let target = self.resolve_fragment(fragment);
                self.asm.fragment_call(target)?;
                let fail = self
                    .resolve_beam_label(fail)
                    .ok_or(AsmError::Operand("map-update fail label"))?;
                self.asm.jcc(CondCode::E, fail)?;
            } else {
                let fragment = self.ga_get(GlobalLabels::UpdateMapExactBodyShared)?;
                let target = self.resolve_fragment(fragment);
                self.asm.fragment_call(target)?;
            }
        }
        self.mov_arg_from_reg(dst, RET)
    }
}

// `Section` is used by the byte-differential tests below. The test fixture definitions for
// external runtime symbols live in rt.rs, alongside the other x86 runtime byte-test fixtures.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::x86::beam_asm_global::{BeamGlobalAssembler, GLOBAL_LABELS};
    use crate::x86::jdump::{erts_dump, erts_to_arinsal, gnu_as, matches_with_global_jumps};
    use arinsal_x64::buf::Section;
    use similar_asserts::assert_eq;

    #[test]
    fn map_global_fragment_table_contains_erts_map_fragments() {
        for label in [
            GlobalLabels::NewMapShared,
            GlobalLabels::IGetMapElementShared,
            GlobalLabels::IGetMapElementHashShared,
            GlobalLabels::UpdateMapAssocShared,
            GlobalLabels::UpdateMapSingleAssocShared,
            GlobalLabels::UpdateMapExactGuardShared,
            GlobalLabels::UpdateMapExactBodyShared,
            GlobalLabels::UpdateMapSingleExactBodyShared,
        ] {
            assert!(BeamGlobalAssembler::emit_ptr(label).is_some(), "{label:?}");
        }
        assert_eq!(
            GLOBAL_LABELS[GlobalLabels::NewMapShared as usize].name(),
            "new_map_shared"
        );
    }

    #[test]
    fn gc_test_map_literal_uses_the_global_fragment_address() {
        let mut addresses = vec![None; GLOBAL_LABELS.len()];
        addresses[GlobalLabels::GarbageCollect as usize] = Some(0x7000_0000);
        let mut module = BeamModuleAssembler::with_fragment_addresses(2, addresses);
        module
            .emit_i_new_small_map_lit(
                ArgVal::X(0),
                ArgVal::Word(1),
                ArgVal::Literal(0x1234),
                ArgVal::Word(1),
                &[ArgVal::X(1)],
            )
            .unwrap();
        assert!(!module.asm.a.bytes(Section::Code).is_empty());
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
                if let Some(block) = current.take() {
                    blocks.push(block);
                }
                if line == format!("# {op}") {
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

    fn module_code_lines(block: &[String]) -> Vec<String> {
        let mut in_code = true;
        block
            .iter()
            .filter_map(|line| {
                if line.starts_with(".section .rodata") {
                    in_code = false;
                    return None;
                }
                if line.starts_with(".section .text") {
                    in_code = true;
                    return None;
                }
                if !in_code {
                    return None;
                }
                let line = if let Some((_, label)) = line.split_once("ptr [L") {
                    let _label = label.trim_end_matches(']');
                    return Some("lea r8, qword ptr [rip + 0]".to_owned());
                } else {
                    line.clone()
                };
                Some(erts_to_arinsal(&line))
            })
            .collect()
    }

    fn module_data_lines(block: &[String]) -> Vec<String> {
        let mut in_data = false;
        block
            .iter()
            .filter_map(|line| {
                if line.starts_with(".section .rodata") {
                    in_data = true;
                    return None;
                }
                if line.starts_with(".section .text") {
                    in_data = false;
                    return None;
                }
                if !in_data {
                    return None;
                }
                let line = line
                    .strip_prefix(".dq ")
                    .map(|value| format!(".quad {value}"))
                    .unwrap_or_else(|| {
                        line.strip_prefix("align ")
                            .map(|size| format!(".balign {size}"))
                            .unwrap_or_else(|| line.clone())
                    });
                Some(line)
            })
            .collect()
    }

    fn zero_r8_rip_lea(bytes: &mut [u8]) -> bool {
        let Some(at) = bytes
            .windows(3)
            .position(|window| window == [0x4c, 0x8d, 0x05])
        else {
            return false;
        };
        let Some(disp) = bytes.get_mut(at + 3..at + 7) else {
            return false;
        };
        disp.fill(0);
        true
    }

    fn compare_code(
        block: &[String],
        bytes: &[u8],
        call_rewrites: &[(&str, &str)],
        fragment_call_start: Option<usize>,
    ) {
        let mut lines = module_code_lines(block);
        for line in &mut lines {
            for (from, to) in call_rewrites {
                if line == from {
                    *line = (*to).to_owned();
                }
            }
        }
        if let Some(start_offset) = fragment_call_start {
            const NOPS: [&str; 3] = ["0x90", "0x66, 0x90", "0x0f, 0x1f, 0x00"];
            let is_call_alignment_nop = |line: &str| {
                matches!(
                    line.to_ascii_lowercase().replace(' ', "").as_str(),
                    ".byte0x90" | ".byte0x66,0x90" | ".byte0x0f,0x1f,0x00"
                )
            };
            let mut normalized: Vec<String> = Vec::with_capacity(lines.len());
            for line in lines {
                if let Some(("call", target)) = line.split_once(' ')
                    && target.parse::<u64>().is_ok()
                {
                    while normalized
                        .last()
                        .is_some_and(|line| is_call_alignment_nop(line))
                    {
                        normalized.pop();
                    }
                    let prefix_len = gnu_as(&normalized).expect("GNU as for call prefix").len();
                    let padding = (4 - (start_offset + prefix_len + 5) % 4) % 4;
                    if padding > 0 {
                        normalized.push(format!(".byte {}", NOPS[padding - 1]));
                    }
                    normalized.push(".byte 0xe8, 0, 0, 0, 0".to_owned());
                } else {
                    normalized.push(line);
                }
            }
            lines = normalized;
        }
        let expected_bytes = gnu_as(&lines).expect("GNU as for map code block");
        let mut actual_bytes = bytes.to_vec();
        let mut search_from = 0;
        for line in &lines {
            if line == ".byte 0xe8, 0, 0, 0, 0" {
                let call_offset = search_from
                    + expected_bytes[search_from..]
                        .windows(5)
                        .position(|window| window == [0xe8, 0, 0, 0, 0])
                        .expect("expected relative fragment call");
                if let Some(displacement) = actual_bytes.get_mut(call_offset + 1..call_offset + 5) {
                    displacement.fill(0);
                }
                search_from = call_offset + 5;
            }
        }
        let unbound = [];
        assert_eq!(
            matches_with_global_jumps(&lines, &actual_bytes, &unbound),
            Some(true),
            "{lines:?}; expected={expected_bytes:02x?}; actual={bytes:02x?}; masked={actual_bytes:02x?}"
        );
    }

    #[test]
    fn internal_hash_and_flatmap_helpers_match_erts_dump() {
        let Some(dump) = erts_dump("beam_asm_global") else {
            eprintln!("skipping: `erl +JDdump true` unavailable");
            return;
        };
        let lines: Vec<String> = dump.lines().map(str::trim).map(str::to_owned).collect();
        let start = lines
            .iter()
            .position(|line| *line == "global::i_get_map_element_shared:")
            .unwrap();
        let hash_start = lines[start..]
            .iter()
            .position(|line| *line == "mov rcx, rsi")
            .unwrap()
            + start;
        let hash_end = lines[hash_start..]
            .iter()
            .position(|line| *line == "add rdi, 8")
            .unwrap()
            + hash_start;
        let hash_lines: Vec<String> = lines[hash_start..hash_end]
            .iter()
            .filter(|line| !line.is_empty())
            .map(|line| erts_to_arinsal(line))
            .collect();

        let mut ga = BeamGlobalAssembler::declare_labels(
            crate::common::process_offsets::ProcessOffsets::ERTS_X86_64,
        );
        ga.emit_internal_hash_helper().unwrap();
        let hash_expected = gnu_as(&hash_lines).expect("GNU binutils required for JIT dump tests");
        assert_eq!(ga.asm.a.bytes(Section::Code), hash_expected);

        let flatmap_start = lines[start..]
            .iter()
            .position(|line| *line == "mov eax, dword ptr [rdi+6]")
            .unwrap()
            + start;
        let flatmap_end = lines[flatmap_start..]
            .iter()
            .position(|line| *line == "L159:")
            .unwrap()
            + flatmap_start;
        let flatmap_lines: Vec<String> = lines[flatmap_start..flatmap_end]
            .iter()
            .filter(|line| !line.is_empty())
            .map(|line| erts_to_arinsal(line))
            .collect();
        let mut ga = BeamGlobalAssembler::declare_labels(
            crate::common::process_offsets::ProcessOffsets::ERTS_X86_64,
        );
        ga.emit_flatmap_get_element().unwrap();
        let flatmap_expected =
            gnu_as(&flatmap_lines).expect("GNU binutils required for JIT dump tests");
        assert_eq!(ga.asm.a.bytes(Section::Code), flatmap_expected);
    }

    #[test]
    fn map_builders_and_updates_match_erts_dump() {
        let Some(new_map_dump) = erts_dump("global") else {
            eprintln!("skipping: `erl +JDdump true` unavailable");
            return;
        };
        let new_map_block = full_op_blocks(&new_map_dump, "new_map_dtI")
            .into_iter()
            .find(|block| block.iter().any(|line| line == ".dq 0x0000000000007E8B"))
            .expect("new_map_dtI example in global module dump");
        let mut addresses = vec![None; GLOBAL_LABELS.len()];
        addresses[GlobalLabels::NewMapShared as usize] = Some(0x7000_1000);
        let mut new_map = BeamModuleAssembler::with_fragment_addresses(2, addresses);
        new_map.asm.emit(|e| e.nop()).unwrap();
        new_map
            .emit_new_map(
                ArgVal::X(0),
                ArgVal::Word(0),
                ArgVal::Word(2),
                &[ArgVal::Immediate(0x17), ArgVal::Immediate(0x7E8B)],
            )
            .unwrap();
        let mut code = new_map.asm.a.bytes(Section::Code)[1..].to_vec();
        assert!(zero_r8_rip_lea(&mut code), "new_map rodata lea not found");
        compare_code(&new_map_block, &code, &[], Some(1));
        let data_expected = gnu_as(&module_data_lines(&new_map_block))
            .expect("GNU binutils required for JIT dump tests");
        assert_eq!(new_map.asm.a.bytes(Section::Data), data_expected);

        let Some(small_map_dump) = erts_dump("os") else {
            eprintln!("skipping: `erl +JDdump true` unavailable");
            return;
        };
        let small_map_block = full_op_blocks(&small_map_dump, "i_new_small_map_lit_dtqI")
            .into_iter()
            .find(|block| {
                block
                    .iter()
                    .any(|line| line == "mov qword ptr [r15+32], 15371")
            })
            .expect("small literal map example in os module dump");
        let mut addresses = vec![None; GLOBAL_LABELS.len()];
        addresses[GlobalLabels::GarbageCollect as usize] = Some(0x7000_2000);
        let mut small_map = BeamModuleAssembler::with_fragment_addresses(2, addresses);
        for _ in 0..2 {
            small_map.asm.emit(|e| e.nop()).unwrap();
        }
        small_map
            .emit_i_new_small_map_lit(
                ArgVal::X(1),
                ArgVal::Word(2),
                ArgVal::Literal(u64::MAX),
                ArgVal::Word(2),
                &[ArgVal::X(1), ArgVal::Immediate(15371)],
            )
            .unwrap();
        let op_end = small_map.asm.a.offset();
        small_map.emit_dispatch_table().unwrap();
        let code = small_map.asm.a.bytes(Section::Code)[2..op_end].to_vec();
        compare_code(&small_map_block, &code, &[], Some(2));

        let Some(maps_dump) = erts_dump("maps") else {
            eprintln!("skipping: `erl +JDdump true` unavailable");
            return;
        };
        let assoc_block = full_op_blocks(&maps_dump, "update_map_assoc_sdtI")
            .into_iter()
            .find(|block| block.iter().any(|line| line == "call L335"))
            .expect("single-pair update_map_assoc example in maps module dump");
        let mut addresses = vec![None; GLOBAL_LABELS.len()];
        addresses[GlobalLabels::UpdateMapSingleAssocShared as usize] = Some(0x7000_3000);
        let mut assoc = BeamModuleAssembler::with_fragment_addresses(2, addresses);
        assoc
            .emit_update_map_assoc(
                ArgVal::Y(3),
                ArgVal::X(1),
                ArgVal::Word(2),
                ArgVal::Word(2),
                &[ArgVal::Y(0), ArgVal::Y(1)],
            )
            .unwrap();
        let assoc_code = assoc.asm.a.bytes(Section::Code).to_vec();
        // `call L335`: the module's dispatch-table thunk (5-byte `call rel32`), unbound until
        // the table is emitted at the end of the module.
        compare_code(
            &assoc_block,
            &assoc_code,
            &[("call L335", ".byte 0xe8, 0, 0, 0, 0")],
            None,
        );

        let exact_block = full_op_blocks(&maps_dump, "update_map_exact_sjdtI")
            .into_iter()
            .find(|block| {
                block.iter().any(|line| line.starts_with("call "))
                    && block.iter().any(|line| line == "mov rsi, qword ptr [rsp]")
                    && block.iter().any(|line| line == "mov rdx, qword ptr [rbx]")
            })
            .expect("single-pair update_map_exact example in maps module dump");
        let mut addresses = vec![None; GLOBAL_LABELS.len()];
        addresses[GlobalLabels::UpdateMapSingleExactBodyShared as usize] = Some(0x7000_4000);
        let mut exact = BeamModuleAssembler::with_fragment_addresses(2, addresses);
        exact
            .emit_update_map_exact(
                ArgVal::Y(3),
                ArgVal::Label(0),
                ArgVal::Y(3),
                ArgVal::Word(2),
                ArgVal::Word(2),
                &[ArgVal::Y(0), ArgVal::X(0)],
            )
            .unwrap();
        let exact_code = exact.asm.a.bytes(Section::Code).to_vec();
        compare_code(&exact_block, &exact_code, &[], Some(0));
    }

    #[test]
    fn map_get_elements_matches_erts_dump() {
        let Some(dump) = erts_dump("prim_tty_sighandler") else {
            eprintln!("skipping: `erl +JDdump true` unavailable");
            return;
        };
        let block = full_op_blocks(&dump, "i_get_map_elements_fsI")
            .into_iter()
            .find(|block| {
                block
                    .iter()
                    .any(|line| line == "cmp qword ptr [rsi+rax*8+6], 505611")
            })
            .expect("multi-get map example in prim_tty_sighandler module dump");
        let mut module = BeamModuleAssembler::new(2);
        // The selected erts block starts with the source already cached in ARG1 (rdi), as
        // indicated by its preceding `# skipped fetching of BEAM register` comment.
        let fail = module.resolve_beam_label(1).unwrap();
        module.asm.bind(fail).unwrap();
        let context_start = module.asm.a.offset();
        // In the dump, the failure label is outside this block: its two inline loop branches
        // are short, while the later runtime-failure branch is near. Keep that branch reach
        // context here without coupling the test to the instructions preceding this opcode.
        for _ in 0..48 {
            module.asm.emit(|e| e.nop()).unwrap();
        }
        module.mov_arg_to_reg(ARG1, ArgVal::X(0)).unwrap();
        module
            .emit_i_get_map_elements(
                ArgVal::Label(1),
                ArgVal::X(0),
                ArgVal::Word(6),
                &[
                    ArgVal::Immediate(33931),
                    ArgVal::X(SCRATCH_X_REG),
                    ArgVal::Word(0xA0CFAE5A7B1DDE7E),
                    ArgVal::Immediate(505611),
                    ArgVal::X(SCRATCH_X_REG),
                    ArgVal::Word(0x9F1673045FDAB106),
                ],
            )
            .unwrap();
        let mut code = module.asm.a.bytes(Section::Code)[context_start..].to_vec();
        assert!(
            zero_r8_rip_lea(&mut code),
            "map-get-elements rodata lea not found"
        );
        let mut expected = vec!["label_1:".to_owned()];
        expected.extend(std::iter::repeat_n("nop".to_owned(), 48));
        expected.push("mov rdi, qword ptr [rbx]".to_owned());
        expected.extend(module_code_lines(&block));
        assert_eq!(
            matches_with_global_jumps(&expected, &code, &[]),
            Some(true),
            "{expected:?}; actual={code:02x?}"
        );
        let data_expected =
            gnu_as(&module_data_lines(&block)).expect("GNU binutils required for JIT dump tests");
        assert_eq!(module.asm.a.bytes(Section::Data), data_expected);
    }

    #[test]
    fn map_single_gets_match_erts_dump() {
        use crate::common::types::{ArgType, type_id};
        use crate::x86::beam_asm::register::TMP1;

        let Some(dump) = erts_dump("global") else {
            eprintln!("skipping: `erl +JDdump true` unavailable");
            return;
        };
        let get_block = full_op_blocks(&dump, "i_get_map_element_fSSS")
            .into_iter()
            .find(|block| block.iter().any(|line| line == "mov rsi, r10"))
            .expect("runtime single-get map example in global module dump");
        let mut module = BeamModuleAssembler::new(2);
        let key = module.typed_arg(
            ArgVal::X(1),
            ArgType {
                union_bits: type_id::MAP,
                min: None,
                max: None,
                unit: 1,
            },
        );
        module.mov_arg_to_reg(ARG1, ArgVal::X(0)).unwrap();
        module.mov_arg_to_reg(TMP1, key).unwrap();
        let start = module.asm.a.offset();
        module
            .emit_i_get_map_element(ArgVal::Label(1), ArgVal::X(0), key, ArgVal::X(1))
            .unwrap();
        let fail = module.resolve_beam_label(1).unwrap();
        module.asm.bind(fail).unwrap();
        let code = module.asm.a.bytes(Section::Code)[start..].to_vec();
        let mut expected = module_code_lines(&get_block);
        for line in &mut expected {
            if line.starts_with("jz label_") {
                *line = "{disp32} jz label_1".to_owned();
            }
        }
        expected.push("label_1:".to_owned());
        assert_eq!(
            matches_with_global_jumps(&expected, &code, &[]),
            Some(true),
            "{expected:?}; actual={code:02x?}"
        );

        let hash_block = full_op_blocks(&dump, "i_get_map_element_hash_fScWS")
            .into_iter()
            .find(|block| block.iter().any(|line| line == "call L1351"))
            .expect("hashed single-get map example in global module dump");
        let mut addresses = vec![None; GLOBAL_LABELS.len()];
        addresses[GlobalLabels::IGetMapElementHashShared as usize] = Some(0x7000_5000);
        let mut module = BeamModuleAssembler::with_fragment_addresses(2, addresses);
        module.mov_arg_to_reg(ARG1, ArgVal::X(0)).unwrap();
        let start = module.asm.a.offset();
        module
            .emit_i_get_map_element_hash(
                ArgVal::Label(1),
                ArgVal::X(0),
                ArgVal::Immediate(10443),
                ArgVal::Word(3942270382581511675),
                ArgVal::X(2),
            )
            .unwrap();
        let fail = module.resolve_beam_label(1).unwrap();
        module.asm.bind(fail).unwrap();
        let code = module.asm.a.bytes(Section::Code)[start..].to_vec();
        let mut expected = module_code_lines(&hash_block);
        for line in &mut expected {
            if line == "call L1351" {
                // The module's thunk of the fragment (`safe_fragment_call`), unbound here.
                *line = ".byte 0xe8, 0, 0, 0, 0".to_owned();
            } else if line.starts_with("jnz label_") {
                *line = "{disp32} jnz label_1".to_owned();
            }
        }
        expected.push("label_1:".to_owned());
        assert_eq!(
            matches_with_global_jumps(&expected, &code, &[]),
            Some(true),
            "{expected:?}; actual={code:02x?}"
        );
    }
}
