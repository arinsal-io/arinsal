//! Map construction, lookup, update, and boolean emitters.

use super::beam_asm::NUM_REGISTER_BACKED_XREGS;
use arinsal_a64::{
    buf::{BufferError, CodeBuffer, Label},
    enc::{Cond, Gpr, Shift, Shifted, VecReg},
    exec::{CodeMemory, ExecError},
};

use crate::{
    Update, emit_enter_runtime, emit_leave_runtime,
    module::{ArgVal, BeamModuleAssembler, ModuleError},
};

const X: [Gpr; 6] = [
    Gpr::x(25),
    Gpr::x(26),
    Gpr::x(27),
    Gpr::x(28),
    logical_xreg(15),
    logical_xreg(16),
];
const E: Gpr = Gpr::x(20);
const HTOP: Gpr = Gpr::x(23);
const ATOM_TAG: u16 = 0x0b;
/// [`crate::bif::guard_bif_mfa`] indexes of `erlang:not/1`, `'and'/2` and `'or'/2`.
const NOT_MFA_INDEX: u64 = 10;
const AND_MFA_INDEX: u64 = 11;
const OR_MFA_INDEX: u64 = 12;

// These entries map logical XREG4/5 to their caller-saved hardware registers.
const fn logical_xreg(index: u8) -> Gpr {
    Gpr::x(index)
}

/// The process-wide map fragments a module calls ([`MapFragments`] entries).
#[derive(Clone, Copy, Default)]
pub struct MapRuntime {
    /// Shared map construction fragment (`new_map_shared`).
    pub new_map_shared: usize,
    /// Shared single-pair exact update fragment (`erts_maps_update`).
    pub update_single_exact_shared: usize,
    /// Shared single-pair associative update fragment (`update_map_single_assoc_shared`).
    pub update_single_assoc_shared: usize,
    /// Shared multi-pair associative update fragment (`update_map_assoc_shared`).
    pub update_assoc_shared: usize,
    /// Shared multi-pair exact update fragment of an instruction with a failure label
    /// (`update_map_exact_guard_shared`).
    pub update_exact_guard_shared: usize,
    /// Shared multi-pair exact update fragment of a body (`update_map_exact_body_shared`).
    pub update_exact_shared: usize,
    /// `i_get_map_element_shared` fragment ([`MapFragments::get_element_shared`]).
    pub get_element_shared: usize,
    /// `i_get_map_element_hash_shared` fragment ([`MapFragments::get_element_hash_shared`]).
    pub get_element_hash_shared: usize,
}

/// The `hashmap_make_hash` the loader passes to `i_get_map_element_hash` for an
/// immediate key; other literal keys are hashed by the runtime lookup.
// Port of erts/emulator/beam/generators.tab (gen.get_map_element) and erl_map.h:216
// (hashmap_make_hash), OTP-29.1.1.
pub fn literal_key_hash(word: u64) -> u64 {
    if word & 3 == 3 {
        arinsal_term::immediate_internal_hash(word)
    } else {
        0
    }
}

/// Process-wide map lookup fragments shared by every compiled module.
pub struct MapFragments {
    memory: CodeMemory,
    new_map_offset: usize,
    get_element_offset: usize,
    get_element_hash_offset: usize,
    update_single_exact_offset: usize,
    update_single_assoc_offset: usize,
    update_assoc_offset: usize,
    update_exact_guard_offset: usize,
    update_exact_offset: usize,
}

impl MapFragments {
    /// Emits the shared map lookup, construction and update fragments. Each calls the erts
    /// runtime function itself (`erts_gc_new_map`, `erts_maps_put`, `erts_maps_update`,
    /// `erts_gc_update_map_assoc`, `erts_gc_update_map_exact`); a failed update in a body (no
    /// failure label) raises through `raise_exception`, the global fragment erts branches to
    /// (`labels[raise_exception]`).
    // Port of erts/emulator/beam/jit/arm/instr_map.cpp:228-243, 316-361, 493-509, 540-583,
    // 604-683, OTP-29.1.1.
    pub fn new(raise_exception: usize) -> Result<Self, ExecError> {
        let mut code = CodeBuffer::new();
        let new_map = code.new_label();
        let get_element = code.new_label();
        let get_element_hash = code.new_label();
        let update_single_exact = code.new_label();
        let update_single_assoc = code.new_label();
        let update_assoc_label = code.new_label();
        let update_exact_guard_label = code.new_label();
        let update_exact_label = code.new_label();
        let fail = |_: BufferError| ExecError::InvalidSize("map fragment");
        let vector_update = Update::HEAP_ALLOC
            .union(Update::X_REGS)
            .union(Update::REDUCTIONS);
        code.bind(new_map).map_err(fail)?;
        emit_vector_map_shared(
            &mut code,
            crate::rt::erts_gc_new_map as *const () as usize,
            vector_update,
            None,
        )
        .map_err(fail)?;
        code.bind(get_element).map_err(fail)?;
        emit_i_get_map_element_shared(&mut code).map_err(fail)?;
        code.bind(get_element_hash).map_err(fail)?;
        emit_i_get_map_element_hash_shared(&mut code).map_err(fail)?;
        code.bind(update_single_exact).map_err(fail)?;
        emit_update_map_single_exact_body_shared(&mut code, raise_exception).map_err(fail)?;
        code.bind(update_single_assoc).map_err(fail)?;
        emit_update_map_single_assoc_shared(&mut code).map_err(fail)?;
        code.bind(update_assoc_label).map_err(fail)?;
        emit_vector_map_shared(
            &mut code,
            crate::rt::erts_gc_update_map_assoc as *const () as usize,
            vector_update,
            None,
        )
        .map_err(fail)?;
        code.bind(update_exact_guard_label).map_err(fail)?;
        emit_vector_map_shared(
            &mut code,
            crate::rt::erts_gc_update_map_exact as *const () as usize,
            vector_update,
            None,
        )
        .map_err(fail)?;
        code.bind(update_exact_label).map_err(fail)?;
        emit_vector_map_shared(
            &mut code,
            crate::rt::erts_gc_update_map_exact as *const () as usize,
            vector_update,
            Some(raise_exception),
        )
        .map_err(fail)?;
        let (words, labels) = code.finish_with_labels().map_err(fail)?;
        let bytes = words
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .collect::<Vec<_>>();
        let mut memory = CodeMemory::new(bytes.len().max(4))?;
        let offset = memory.alloc(bytes.len().max(4))?;
        memory.write_bytes(offset, &bytes)?;
        Ok(Self {
            memory,
            new_map_offset: labels[&new_map],
            get_element_offset: labels[&get_element],
            get_element_hash_offset: labels[&get_element_hash],
            update_single_exact_offset: labels[&update_single_exact],
            update_single_assoc_offset: labels[&update_single_assoc],
            update_assoc_offset: labels[&update_assoc_label],
            update_exact_guard_offset: labels[&update_exact_guard_label],
            update_exact_offset: labels[&update_exact_label],
        })
    }

    /// The [`MapRuntime`] a module uses: every fragment entry.
    pub fn runtime(&self) -> MapRuntime {
        MapRuntime {
            new_map_shared: self.new_map_shared(),
            update_single_exact_shared: self.update_single_exact_shared(),
            update_single_assoc_shared: self.update_single_assoc_shared(),
            update_assoc_shared: self.update_assoc_shared(),
            update_exact_guard_shared: self.update_exact_guard_shared(),
            update_exact_shared: self.update_exact_shared(),
            get_element_shared: self.get_element_shared(),
            get_element_hash_shared: self.get_element_hash_shared(),
        }
    }

    /// Entry of `new_map_shared`: live X count in X2, number of key/value terms in X3, the
    /// operand vector in X4. Returns the new map in X0.
    pub fn new_map_shared(&self) -> usize {
        self.memory.ptr_at(self.new_map_offset) as usize
    }

    /// Entry of `i_get_map_element_shared`: map in X0, key in X1; ZF set and the value in X0
    /// on success.
    pub fn get_element_shared(&self) -> usize {
        self.memory.ptr_at(self.get_element_offset) as usize
    }

    /// Entry of `i_get_map_element_hash_shared`: map in X0, immediate key in X1, its internal
    /// hash in X2; ZF set and the value in X0 on success.
    pub fn get_element_hash_shared(&self) -> usize {
        self.memory.ptr_at(self.get_element_hash_offset) as usize
    }

    /// Entry of `update_map_single_exact_body_shared`: key in X1, value in X2, map in X3.
    /// Returns the updated map in X0; a missing key raises `{badkey, Key}`.
    pub fn update_single_exact_shared(&self) -> usize {
        self.memory.ptr_at(self.update_single_exact_offset) as usize
    }

    /// Entry of `update_map_single_assoc_shared`: key in X1, value in X2, map in X3. Returns
    /// the updated map in X0.
    pub fn update_single_assoc_shared(&self) -> usize {
        self.memory.ptr_at(self.update_single_assoc_offset) as usize
    }

    /// Entry of `update_map_assoc_shared`: the map in X[live], live X count in X2, number of
    /// update terms in X3, the operand vector in X4. Returns the updated map in X0.
    pub fn update_assoc_shared(&self) -> usize {
        self.memory.ptr_at(self.update_assoc_offset) as usize
    }

    /// Entry of `update_map_exact_guard_shared`: as [`Self::update_assoc_shared`]. Returns the
    /// updated map in X0, or `THE_NON_VALUE` when the update fails.
    pub fn update_exact_guard_shared(&self) -> usize {
        self.memory.ptr_at(self.update_exact_guard_offset) as usize
    }

    /// Entry of `update_map_exact_body_shared`: as [`Self::update_exact_guard_shared`]; a
    /// failed update raises.
    pub fn update_exact_shared(&self) -> usize {
        self.memory.ptr_at(self.update_exact_offset) as usize
    }
}

// Registers of the lookup fragments, named after erts' ARG*/TMP* (arm/beam_asm.hpp).
const ARG1: Gpr = Gpr::x(0);
const ARG2: Gpr = Gpr::x(1);
const ARG3: Gpr = Gpr::x(2);
const ARG4: Gpr = Gpr::x(3);
const ARG5: Gpr = Gpr::x(4);
const TMP1: Gpr = Gpr::x(8);
const TMP2: Gpr = Gpr::x(9);
const TMP3: Gpr = Gpr::x(10);
const TMP4: Gpr = Gpr::x(11);
const TMP5: Gpr = Gpr::x(12);
const TMP6: Gpr = Gpr::x(13);
/// `_HEADER_MAP_SUBTAG_MASK` and `HAMT_SUBTAG_HEAD_FLATMAP`.
const HEADER_MAP_SUBTAG_MASK: u64 = 0xfc;
const HAMT_SUBTAG_HEAD_FLATMAP: u16 = 0x2c;
/// `MAP_HEADER_FLATMAP` (erl_map.h:185): subtag 0x2c, arity field 1.
const MAP_HEADER_FLATMAP: u64 = 0x12c;
const HAMT_MAX_LEVEL: u16 = 16;

// Port of erts/emulator/beam/jit/arm/instr_map.cpp:316-361 (emit_i_get_map_element_shared),
// OTP-29.1.1. ARG1 = map, ARG2 = key; the result is in ARG1 and ZF is set on success.
fn emit_i_get_map_element_shared(code: &mut CodeBuffer) -> Result<(), BufferError> {
    let generic = code.new_label();
    let hashmap = code.new_label();
    code.emit(|e| {
        e.and_imm(TMP1, ARG2, 3)?;
        e.cmp_imm(TMP1, 3, false)
    })?;
    code.b_cond(Cond::Ne, generic)?;
    code.emit(|e| {
        e.and_imm(ARG1, ARG1, !7)?;
        e.ldp(ARG4, ARG5, ARG1, 0)?;
        e.and_imm(TMP1, ARG4, HEADER_MAP_SUBTAG_MASK)?;
        e.cmp_imm(TMP1, HAMT_SUBTAG_HEAD_FLATMAP, false)
    })?;
    code.b_cond(Cond::Ne, hashmap)?;
    emit_flatmap_get_element(code)?;

    code.bind(generic)?;
    // `runtime_call<get_map_element>`: ARG1 = map, ARG2 = key; it cannot fail and returns the
    // value or THE_NON_VALUE.
    code.emit(|e| {
        e.stp_pre(Gpr::x(29), Gpr::x(30), Gpr::sp(), -16)?;
        e.mov_reg(Gpr::x(29), Gpr::sp())
    })?;
    emit_enter_runtime(code, 6, Update::NONE)?;
    code.emit(|e| {
        e.mov_const(Gpr::x(17), crate::rt::get_map_element as *const () as u64)?;
        e.blr(Gpr::x(17))
    })?;
    emit_leave_runtime(code, 6, Update::NONE)?;
    code.emit(|e| {
        e.cmp_imm(ARG1, 0, false)?;
        // Invert ZF: it must be set when the result is a value.
        e.cset(TMP1, Cond::Eq)?;
        e.tst_reg(TMP1, TMP1, Shift::Lsl, 0)?;
        e.mov_reg(Gpr::sp(), Gpr::x(29))?;
        e.ldp_post(Gpr::x(29), Gpr::x(30), Gpr::sp(), 16)?;
        e.ret(Gpr::x(30))
    })?;

    code.bind(hashmap)?;
    emit_internal_hash_helper(code)?;
    emit_hashmap_get_element(code)
}

// Port of erts/emulator/beam/jit/arm/instr_map.cpp:493-509
// (emit_i_get_map_element_hash_shared), OTP-29.1.1. ARG1 = map, ARG2 = key, ARG3 = hash.
fn emit_i_get_map_element_hash_shared(code: &mut CodeBuffer) -> Result<(), BufferError> {
    let hashmap = code.new_label();
    code.emit(|e| {
        e.and_imm(ARG1, ARG1, !7)?;
        e.ldp(ARG4, ARG5, ARG1, 0)?;
        e.and_imm(TMP1, ARG4, HEADER_MAP_SUBTAG_MASK)?;
        e.cmp_imm(TMP1, HAMT_SUBTAG_HEAD_FLATMAP, false)
    })?;
    code.b_cond(Cond::Ne, hashmap)?;
    emit_flatmap_get_element(code)?;
    code.bind(hashmap)?;
    emit_hashmap_get_element(code)
}

// Port of erts/emulator/beam/jit/arm/instr_map.cpp:25-60 (emit_internal_hash_helper),
// OTP-29.1.1. ARG2 = term; the result is in ARG3. Clobbers TMP1.
fn emit_internal_hash_helper(code: &mut CodeBuffer) -> Result<(), BufferError> {
    let (key, key_hash) = (ARG2, ARG3);
    let lsr33 = |reg| Shifted {
        reg,
        shift: Shift::Lsr,
        amount: 33,
    };
    code.emit(|e| {
        e.eor_reg(key_hash, key, lsr33(key))?;
        e.mov_const(TMP1, 0xff51_afd7_ed55_8ccd)?;
        e.mul(key_hash, key_hash, TMP1)?;
        e.eor_reg(key_hash, key_hash, lsr33(key_hash))?;
        e.mov_const(TMP1, 0xc4ce_b9fe_1a85_ec53)?;
        e.mul(key_hash, key_hash, TMP1)?;
        e.eor_reg(key_hash, key_hash, lsr33(key_hash))
    })
}

// Port of erts/emulator/beam/jit/arm/instr_map.cpp:80-187 (emit_hashmap_get_element),
// OTP-29.1.1. ARG1 = untagged root, ARG2 = key, ARG3 = key hash, ARG4 = node header.
// The result is in ARG1 and ZF is set on success; every path returns.
fn emit_hashmap_get_element(code: &mut CodeBuffer) -> Result<(), BufferError> {
    let (node, key, key_hash, header) = (ARG1, ARG2, ARG3, ARG4);
    let (depth, index) = (TMP5, TMP6);
    let node_loop = code.new_label();
    let done = code.new_label();
    let leaf_node = code.new_label();
    let skip_index_adjustment = code.new_label();
    let collision_node = code.new_label();
    // The root header is two words long; child headers are one word.
    code.emit(|e| {
        e.add_imm(node, node, 16, false)?;
        e.mov_reg(depth, Gpr::xzr())
    })?;
    code.bind(node_loop)?;
    code.emit(|e| {
        e.and_imm(index, key_hash, 0xf)?;
        e.lsr_imm(key_hash, key_hash, 4)?;
        e.add_imm(depth, depth, 1, false)?;
        // Fully populated nodes have the index as the entry offset.
        e.asr_imm(Gpr::w(3), Gpr::w(3), 16)?;
        e.cmn_imm(Gpr::w(3), 1, false)
    })?;
    code.b_cond(Cond::Eq, skip_index_adjustment)?;
    code.emit(|e| e.lsr_reg(TMP1, header, index))?;
    // ZF is clear here, so the return sequence reports a miss.
    code.tbz(TMP1, 0, done)?;
    // The entry offset is the number of bitmap bits set below our index.
    code.emit(|e| {
        e.lsl_reg(TMP2, TMP1, index)?;
        e.eor_reg(
            TMP1,
            TMP2,
            Shifted {
                reg: header,
                shift: Shift::Lsl,
                amount: 0,
            },
        )?;
        e.fmov_d_from_x(VecReg(0), TMP1)?;
        e.cnt_8b(VecReg(0), VecReg(0))?;
        e.addv_8b(VecReg(0), VecReg(0))?;
        e.fmov_x_from_d(index, VecReg(0))
    })?;
    code.bind(skip_index_adjustment)?;
    code.emit(|e| {
        e.ldr_regoff(TMP1, node, index, 3)?;
        e.and_imm(node, TMP1, !7)
    })?;
    // A leaf is a list cell, not a boxed node.
    code.tbnz(TMP1, 0, leaf_node)?;
    code.emit(|e| {
        e.ldr_post(header, node, 8)?;
        e.cmp_imm(depth, HAMT_MAX_LEVEL, false)
    })?;
    code.b_cond(Cond::Ne, node_loop)?;
    code.b(collision_node)?;

    code.bind(leaf_node)?;
    code.emit(|e| {
        e.ldp(TMP1, ARG1, node, 0)?;
        e.cmp_reg(TMP1, key, Shift::Lsl, 0)
    })?;
    code.bind(done)?;
    code.emit(|e| e.ret(Gpr::x(30)))?;

    // A collision node is a tuple of leaves searched linearly.
    code.bind(collision_node)?;
    let linear_loop = code.new_label();
    code.emit(|e| e.lsr_imm(TMP1, header, 6 - 3))?;
    code.bind(linear_loop)?;
    code.emit(|e| {
        e.sub_imm(TMP1, TMP1, 8, false)?;
        e.ldr_regoff(TMP2, node, TMP1, 0)?;
        e.and_imm(TMP2, TMP2, !7)?;
        e.ldp(TMP3, TMP4, TMP2, 0)?;
        e.cmp_reg(key, TMP3, Shift::Lsl, 0)?;
        e.csel(ARG1, node, TMP4, Cond::Ne)
    })?;
    code.b_cond(Cond::Eq, done)?;
    code.cbnz(TMP1, linear_loop)?;
    code.emit(|e| e.ret(Gpr::x(30)))
}

// Port of erts/emulator/beam/jit/arm/instr_map.cpp:196-221 (emit_flatmap_get_element),
// OTP-29.1.1. ARG1 = untagged flat map, ARG2 = key, ARG5 = size.
// The result is in ARG1 and ZF is set on success.
fn emit_flatmap_get_element(code: &mut CodeBuffer) -> Result<(), BufferError> {
    let fail = code.new_label();
    let loop_label = code.new_label();
    // Bump size by one to slide past the keys tuple header; the flags keep ZF clear when
    // entering the loop.
    code.emit(|e| {
        e.adds_imm(ARG5, ARG5, 1, false)?;
        e.ldr_pre(TMP1, ARG1, 16)?;
        e.and_imm(TMP1, TMP1, !7)
    })?;
    code.bind(loop_label)?;
    code.emit(|e| e.sub_imm(ARG5, ARG5, 1, false))?;
    code.cbz(ARG5, fail)?;
    code.emit(|e| {
        e.ldr_regoff(TMP4, TMP1, ARG5, 3)?;
        e.cmp_reg(ARG2, TMP4, Shift::Lsl, 0)
    })?;
    code.b_cond(Cond::Ne, loop_label)?;
    code.emit(|e| e.ldr_regoff(ARG1, ARG1, ARG5, 3))?;
    code.bind(fail)?;
    code.emit(|e| e.ret(Gpr::x(30)))
}

impl BeamModuleAssembler {
    /// Emits one flatmap or HAMT lookup and branches to `fail` when absent.
    // Port of erts/emulator/beam/jit/arm/instr_map.cpp:362-390, OTP-29.1.1.
    pub fn emit_i_get_map_element(
        &mut self,
        fail: u32,
        src: ArgVal,
        key: ArgVal,
        dst: ArgVal,
        runtime: MapRuntime,
    ) -> Result<(), ModuleError> {
        // erts' `maybe_one_of<BeamTypeId::MaybeImmediate>(Key)`: only a boxed literal is
        // known not to be an immediate. Any other key goes through the shared fragment.
        let key_is_immediate = self.constant_word(key).is_none_or(|word| word & 3 == 3);
        let map = self.source_reg(src)?;
        self.code.emit(|e| e.mov_reg(Gpr::x(0), map))?;
        let key = self.source_reg_into(key, Gpr::x(17))?;
        self.code.emit(|e| e.mov_reg(Gpr::x(1), key))?;
        let fail = self.label(fail);
        if key_is_immediate {
            return self.emit_get_element_fragment_call(runtime.get_element_shared, fail, dst);
        }
        self.emit_get_map_element_call(crate::rt::get_map_element as *const () as usize)?;
        self.code.cbz(Gpr::x(0), fail)?;
        self.store_map_result(dst, Gpr::x(0))
    }

    /// Emits lookup using a precomputed key hash, as generated map code does.
    // Port of erts/emulator/beam/jit/arm/instr_map.cpp:511-542, OTP-29.1.1.
    pub fn emit_i_get_map_element_hash(
        &mut self,
        fail: u32,
        src: ArgVal,
        key: ArgVal,
        hash: ArgVal,
        dst: ArgVal,
        runtime: MapRuntime,
    ) -> Result<(), ModuleError> {
        let fail = self.label(fail);
        // erts calls the shared fragment only for an immediate key (`Key.isImmed()`); any
        // other constant goes straight to the runtime lookup.
        if self.constant_word(key).is_some_and(|word| word & 3 == 3) {
            for (arg, value) in [(Gpr::x(0), src), (Gpr::x(1), key)] {
                let reg = self.source_reg(value)?;
                self.code.emit(|e| e.mov_reg(arg, reg))?;
            }
            match self.constant_word(hash) {
                Some(value) => {
                    // ArgWord constants wider than 32 bits are embedded in OTP's module
                    // literal area and loaded with LDR literal.
                    // Port of erts/emulator/beam/jit/arm/beam_asm.hpp:1528-1554,
                    // OTP-29.1.1.
                    self.code.ldr_literal(Gpr::x(2), value)?;
                }
                None => {
                    let reg = self.source_reg(hash)?;
                    self.code.emit(|e| e.mov_reg(Gpr::x(2), reg))?;
                }
            }
            return self.emit_get_element_fragment_call(runtime.get_element_hash_shared, fail, dst);
        }
        for (arg, value) in [(Gpr::x(0), src), (Gpr::x(1), key), (Gpr::x(2), hash)] {
            let reg = self.source_reg(value)?;
            self.code.emit(|e| e.mov_reg(arg, reg))?;
        }
        self.emit_get_map_element_call(crate::rt::get_map_element_hash as *const () as usize)?;
        self.code.cbz(Gpr::x(0), fail)?;
        self.store_map_result(dst, Gpr::x(0))
    }

    /// `fragment_call` of a shared lookup fragment (map in X0, key in X1): ZF set and the
    /// value in X0 on success, otherwise branch to `fail`.
    // Port of erts/emulator/beam/jit/arm/instr_map.cpp:379-389 and 531-541, OTP-29.1.1.
    fn emit_get_element_fragment_call(
        &mut self,
        fragment: usize,
        fail: Label,
        dst: ArgVal,
    ) -> Result<(), ModuleError> {
        self.fragment_call(fragment)?;
        self.code.b_cond(Cond::Ne, fail)?;
        // Port of erts/emulator/beam/jit/arm/instr_map.cpp:384-389, OTP-29.1.1.
        // The scratch destination is used by `has_map_fields` only to test key presence.
        if is_scratch_x(dst) {
            Ok(())
        } else {
            self.store_map_result(dst, Gpr::x(0))
        }
    }

    /// Emits the generic runtime lookup for a boxed-only key.
    // Port of erts/emulator/beam/jit/arm/instr_guard_bifs.cpp:813-822,891-913,
    // OTP-29.1.1 (`runtime_call<get_map_element>`).
    pub(crate) fn emit_map_get_runtime(
        &mut self,
        key: Gpr,
        map: Gpr,
        _runtime: MapRuntime,
    ) -> Result<(), ModuleError> {
        self.code.emit(|e| {
            e.mov_reg(Gpr::x(17), key)?;
            e.mov_reg(Gpr::x(0), map)?;
            e.mov_reg(Gpr::x(1), Gpr::x(17))
        })?;
        self.emit_get_map_element_call(crate::rt::get_map_element as *const () as usize)
    }

    /// `emit_enter_runtime(); runtime_call<get_map_element[_hash]>(); emit_leave_runtime()`
    /// with the map in ARG1, the key in ARG2 (and the hash in ARG3): the value, or
    /// THE_NON_VALUE when the key is absent. The lookup reads no process state.
    // Port of erts/emulator/beam/jit/arm/instr_map.cpp:362-390,511-542 and
    // instr_guard_bifs.cpp:813-822,906-913, OTP-29.1.1.
    pub(crate) fn emit_get_map_element_call(&mut self, target: usize) -> Result<(), ModuleError> {
        emit_enter_runtime(&mut self.code, 6, Update::NONE)?;
        self.code.emit(|e| {
            e.mov_const(Gpr::x(17), target as u64)?;
            e.str_uoff(Gpr::x(30), Gpr::x(21), 72)?;
            e.blr(Gpr::x(17))
        })?;
        emit_leave_runtime(&mut self.code, 6, Update::NONE)?;
        self.code.emit(|e| e.ldr_uoff(Gpr::x(30), Gpr::x(21), 72))?;
        Ok(())
    }

    /// Emits multi-key lookup; the operands are flattened `{key, dst, hash}` triplets.
    // Port of erts/emulator/beam/jit/arm/instr_map.cpp:391-490, OTP-29.1.1.
    pub fn emit_i_get_map_elements(
        &mut self,
        fail: u32,
        src: ArgVal,
        args: &[ArgVal],
    ) -> Result<(), ModuleError> {
        if !args.len().is_multiple_of(3) {
            return Err(ModuleError::InvalidOperand(
                "map get operands must be triplets",
            ));
        }
        let map = self.source_reg(src)?;
        // Port of erts/emulator/beam/jit/arm/instr_map.cpp:391-490, OTP-29.1.1.
        let can_inline = args.len() < 24
            && args
                .iter()
                .step_by(3)
                .all(|&arg| self.constant_word(arg).is_some_and(|word| word & 3 == 3));
        let generic = self.code.new_label();
        let done = self.code.new_label();
        self.code.emit(|e| e.mov_reg(ARG1, map))?;
        if can_inline {
            self.code.emit(|e| e.and_imm(Gpr::x(8), map, !7))?;
            self.code
                .emit(|e| e.ldp(Gpr::x(9), Gpr::x(10), Gpr::x(8), 0))?;
            self.code.emit(|e| e.and_imm(Gpr::x(9), Gpr::x(9), 0xc0))?;
            self.code.emit(|e| e.cmp_imm(Gpr::x(9), 0, false))?;
            self.code.b_cond(Cond::Ne, generic)?;
            self.code
                .emit(|e| e.add_imm(Gpr::x(10), Gpr::x(10), 1, false))?;
            // The pre-index load leaves x8 at the `keys` field, which the value loads then
            // index with the bumped size.
            self.code.emit(|e| e.ldr_pre(Gpr::x(11), Gpr::x(8), 16))?;
            self.code.emit(|e| e.and_imm(Gpr::x(11), Gpr::x(11), !7))?;
            for triple in args.as_chunks::<3>().0.iter().rev() {
                let loop_label = self.code.new_label();
                self.code.bind(loop_label)?;
                self.code
                    .emit(|e| e.subs_imm(Gpr::x(10), Gpr::x(10), 1, false))?;
                let fail_label = self.label(fail);
                self.code.b_cond(Cond::Eq, fail_label)?;
                self.code
                    .emit(|e| e.ldr_regoff(Gpr::x(12), Gpr::x(11), Gpr::x(10), 3))?;
                let key = self.source_reg(triple[0])?;
                self.code
                    .emit(|e| e.cmp_reg(Gpr::x(12), key, Shift::Lsl, 0))?;
                self.code.b_cond(Cond::Ne, loop_label)?;
                if !is_scratch_x(triple[1]) {
                    self.emit_flatmap_value_to_destination(triple[1], Gpr::x(8), Gpr::x(10))?;
                }
            }
            self.code.b(done)?;
        }
        self.code.bind(generic)?;
        self.embed_vararg_rodata(args, ARG5)?;
        self.code.emit(|e| e.mov_reg(ARG3, E))?;
        emit_enter_runtime(&mut self.code, 6, Update::X_REGS)?;
        let count = (args.len() / 3) as u64;
        self.code.emit(|e| {
            e.mov_const(ARG4, count)?;
            crate::arm::beam_asm::load_x_reg_array(e, ARG2)?;
            e.mov_const(
                Gpr::x(17),
                crate::rt::beam_jit_get_map_elements as *const () as u64,
            )?;
            e.str_uoff(Gpr::x(30), Gpr::x(21), 72)?;
            e.blr(Gpr::x(17))
        })?;
        emit_leave_runtime(&mut self.code, 6, Update::X_REGS)?;
        self.code.emit(|e| e.ldr_uoff(Gpr::x(30), Gpr::x(21), 72))?;
        let fail_label = self.label(fail);
        self.code.cbz(ARG1, fail_label)?;
        let fail_label = self.label(fail);
        self.code.cbz(Gpr::x(0), fail_label)?;
        if can_inline {
            self.code.bind(done)?;
        }
        Ok(())
    }

    /// Emits a small literal flatmap in OTP's header, size, keys, values layout.
    // Port of erts/emulator/beam/jit/arm/instr_map.cpp:151-201, OTP-29.1.1.
    pub fn emit_i_new_small_map_lit(
        &mut self,
        dst: ArgVal,
        keys: ArgVal,
        values: &[ArgVal],
    ) -> Result<(), ModuleError> {
        let count = u64::try_from(values.len())
            .map_err(|_| ModuleError::InvalidOperand("map size overflow"))?;
        let words = count
            .checked_add(3)
            .ok_or(ModuleError::InvalidOperand("map allocation overflow"))?;
        // Arity field 1, type 0. The flatmap test masks with 0xfc, so this word
        // still compares equal to HAMT_SUBTAG_HEAD_FLATMAP.
        self.code
            .emit(|e| e.mov_const(Gpr::x(8), MAP_HEADER_FLATMAP))?;
        self.code.emit(|e| e.str_post(Gpr::x(8), HTOP, 8))?;
        self.code.emit(|e| e.mov_const(Gpr::x(8), count))?;
        self.code.emit(|e| e.str_post(Gpr::x(8), HTOP, 8))?;
        let keys = self.source_reg(keys)?;
        self.code.emit(|e| e.str_post(keys, HTOP, 8))?;
        for value in values {
            let value = self.source_reg_into(*value, Gpr::x(17))?;
            self.code.emit(|e| e.str_post(value, HTOP, 8))?;
        }
        self.code
            .emit(|e| e.sub_imm(Gpr::x(8), HTOP, (words * 8 - 2) as u16, false))?;
        self.store_map_result(dst, Gpr::x(8))
    }

    /// Emits construction through the runtime map allocation helper.
    // Port of erts/emulator/beam/jit/arm/instr_map.cpp:228-265, OTP-29.1.1.
    pub fn emit_new_map(
        &mut self,
        dst: ArgVal,
        live: u32,
        args: &[ArgVal],
        runtime: MapRuntime,
    ) -> Result<(), ModuleError> {
        if !args.len().is_multiple_of(2) {
            return Err(ModuleError::InvalidOperand(
                "new map operands must be key/value pairs",
            ));
        }
        self.embed_vararg_rodata(args, ARG5)?;
        self.code.emit(|e| {
            e.mov_const(ARG3, u64::from(live))?;
            e.mov_const(ARG4, args.len() as u64)
        })?;
        self.fragment_call(runtime.new_map_shared)?;
        self.store_map_result(dst, ARG1)
    }

    /// Emits associative map update through the runtime helper.
    // Port of erts/emulator/beam/jit/arm/instr_map.cpp:542-602, OTP-29.1.1.
    pub fn emit_update_map_assoc(
        &mut self,
        src: ArgVal,
        dst: ArgVal,
        live: u32,
        updates: &[ArgVal],
        runtime: MapRuntime,
    ) -> Result<(), ModuleError> {
        if !updates.len().is_multiple_of(2) {
            return Err(ModuleError::InvalidOperand(
                "map update operands must be key/value pairs",
            ));
        }
        if updates.len() == 2 {
            for (target, value) in [
                (Gpr::x(1), updates[0]),
                (Gpr::x(2), updates[1]),
                (Gpr::x(3), src),
            ] {
                let reg = self.source_reg(value)?;
                self.code.emit(|e| e.mov_reg(target, reg))?;
            }
            self.fragment_call(runtime.update_single_assoc_shared)?;
            return self.store_map_result(dst, Gpr::x(0));
        }
        let source = self.source_reg_into(src, TMP1)?;
        self.embed_vararg_rodata(updates, ARG5)?;
        self.store_map_result(ArgVal::X(live), source)?;
        self.code.emit(|e| {
            e.mov_const(ARG3, u64::from(live))?;
            e.mov_const(ARG4, updates.len() as u64)
        })?;
        self.fragment_call(runtime.update_assoc_shared)?;
        self.store_map_result(dst, ARG1)
    }

    /// Emits exact map update and routes missing keys to `fail` when supplied.
    // Port of erts/emulator/beam/jit/arm/instr_map.cpp:604-720, OTP-29.1.1.
    pub fn emit_update_map_exact(
        &mut self,
        src: ArgVal,
        fail: u32,
        dst: ArgVal,
        live: u32,
        updates: &[ArgVal],
        runtime: MapRuntime,
    ) -> Result<(), ModuleError> {
        if !updates.len().is_multiple_of(2) {
            return Err(ModuleError::InvalidOperand(
                "map update operands must be key/value pairs",
            ));
        }
        if updates.len() == 2 && fail == 0 {
            for (target, value) in [
                (Gpr::x(1), updates[0]),
                (Gpr::x(2), updates[1]),
                (Gpr::x(3), src),
            ] {
                let reg = self.source_reg(value)?;
                self.code.emit(|e| e.mov_reg(target, reg))?;
            }
            self.fragment_call(runtime.update_single_exact_shared)?;
            return self.store_map_result(dst, Gpr::x(0));
        }
        let source = self.source_reg_into(src, ARG4)?;
        self.embed_vararg_rodata(updates, ARG5)?;
        self.store_map_result(ArgVal::X(live), source)?;
        self.code.emit(|e| {
            e.mov_const(ARG3, u64::from(live))?;
            e.mov_const(ARG4, updates.len() as u64)
        })?;
        if fail != 0 {
            self.fragment_call(runtime.update_exact_guard_shared)?;
            let fail_label = self.label(fail);
            self.code.cbz(ARG1, fail_label)?;
        } else {
            self.fragment_call(runtime.update_exact_shared)?;
        }
        self.store_map_result(dst, ARG1)
    }

    /// Emits Erlang's strict boolean `and/2` BIF.
    // Port of erts/emulator/beam/jit/arm/instr_guard_bifs.cpp:294-340, OTP-29.1.1.
    pub fn emit_bif_and(
        &mut self,
        fail: u32,
        lhs: ArgVal,
        rhs: ArgVal,
        dst: ArgVal,
    ) -> Result<(), ModuleError> {
        self.emit_boolean_binary(fail, lhs, rhs, dst, false)
    }

    /// Emits Erlang's strict boolean `or/2` BIF.
    // Port of erts/emulator/beam/jit/arm/instr_guard_bifs.cpp:1215-1250, OTP-29.1.1.
    pub fn emit_bif_or(
        &mut self,
        fail: u32,
        lhs: ArgVal,
        rhs: ArgVal,
        dst: ArgVal,
    ) -> Result<(), ModuleError> {
        self.emit_boolean_binary(fail, lhs, rhs, dst, true)
    }

    /// Emits Erlang's strict boolean `not/1` BIF.
    // Port of erts/emulator/beam/jit/arm/instr_guard_bifs.cpp:1177-1213, OTP-29.1.1.
    pub fn emit_bif_not(&mut self, fail: u32, src: ArgVal, dst: ArgVal) -> Result<(), ModuleError> {
        let value = self.source_reg(src)?;
        self.code.emit(|e| e.and_imm(Gpr::x(8), value, !0x40))?;
        self.code.emit(|e| e.cmp_imm(Gpr::x(8), ATOM_TAG, false))?;
        if fail != 0 {
            let fail_label = self.label(fail);
            self.code.b_cond(Cond::Ne, fail_label)?;
        } else {
            let badarg = self.code.new_label();
            let done = self.code.new_label();
            self.code.b_cond(Cond::Ne, badarg)?;
            self.code.emit(|e| e.eor_imm(Gpr::x(9), value, 0x40))?;
            self.store_map_result(dst, Gpr::x(9))?;
            self.code.b(done)?;
            self.code.bind(badarg)?;
            // `mov_var(XREG0, src); fragment_call(ga->get_handle_not_error())`.
            self.emit_raise_badarg(NOT_MFA_INDEX, &[value])?;
            self.code.bind(done)?;
            return Ok(());
        }
        self.code.emit(|e| e.eor_imm(Gpr::x(9), value, 0x40))?;
        self.store_map_result(dst, Gpr::x(9))
    }

    // Port of erts/emulator/beam/jit/arm/instr_guard_bifs.cpp:294-340,1215-1250, OTP-29.1.1.
    fn emit_boolean_binary(
        &mut self,
        fail: u32,
        lhs: ArgVal,
        rhs: ArgVal,
        dst: ArgVal,
        is_or: bool,
    ) -> Result<(), ModuleError> {
        let left = self.source_reg(lhs)?;
        self.code.emit(|e| e.mov_reg(Gpr::x(8), left))?;
        let right = self.source_reg_into(rhs, Gpr::x(17))?;
        self.code.emit(|e| e.mov_reg(Gpr::x(9), right))?;
        self.code
            .emit(|e| e.and_imm(Gpr::x(10), Gpr::x(8), !0x40))?;
        self.code.emit(|e| e.cmp_imm(Gpr::x(10), ATOM_TAG, false))?;
        if fail == 0 {
            let badarg = self.code.new_label();
            let done = self.code.new_label();
            self.code.b_cond(Cond::Ne, badarg)?;
            self.code
                .emit(|e| e.and_imm(Gpr::x(10), Gpr::x(9), !0x40))?;
            self.code.emit(|e| e.cmp_imm(Gpr::x(10), ATOM_TAG, false))?;
            self.code.b_cond(Cond::Ne, badarg)?;
            let shifted = arinsal_a64::enc::Shifted {
                reg: Gpr::x(9),
                shift: arinsal_a64::enc::Shift::Lsl,
                amount: 0,
            };
            self.code.emit(|e| {
                if is_or {
                    e.orr_reg(Gpr::x(11), Gpr::x(8), shifted)
                } else {
                    e.and_reg(Gpr::x(11), Gpr::x(8), shifted)
                }
            })?;
            self.store_map_result(dst, Gpr::x(11))?;
            self.code.b(done)?;
            self.code.bind(badarg)?;
            // `mov_var(XREG0, src1); mov_var(XREG1, src2); fragment_call(handle_and/or_error)`.
            let mfa = if is_or { OR_MFA_INDEX } else { AND_MFA_INDEX };
            self.emit_raise_badarg(mfa, &[Gpr::x(8), Gpr::x(9)])?;
            self.code.bind(done)?;
            return Ok(());
        }
        let fail_label = self.label(fail);
        self.code.b_cond(Cond::Ne, fail_label)?;
        self.code
            .emit(|e| e.and_imm(Gpr::x(10), Gpr::x(9), !0x40))?;
        self.code.emit(|e| e.cmp_imm(Gpr::x(10), ATOM_TAG, false))?;
        let fail_label = self.label(fail);
        self.code.b_cond(Cond::Ne, fail_label)?;
        let shifted = arinsal_a64::enc::Shifted {
            reg: Gpr::x(9),
            shift: arinsal_a64::enc::Shift::Lsl,
            amount: 0,
        };
        self.code.emit(|e| {
            if is_or {
                e.orr_reg(Gpr::x(11), Gpr::x(8), shifted)
            } else {
                e.and_reg(Gpr::x(11), Gpr::x(8), shifted)
            }
        })?;
        self.store_map_result(dst, Gpr::x(11))
    }

    // Port of `mov_arg(Dst, a64::Mem(TMP1, TMP3, a64::lsl(3)))` in
    // erts/emulator/beam/jit/arm/instr_map.cpp:459, OTP-29.1.1. A cached X destination can
    // load straight from the flatmap values; memory-backed destinations need a scratch word.
    fn emit_flatmap_value_to_destination(
        &mut self,
        dst: ArgVal,
        values: Gpr,
        index: Gpr,
    ) -> Result<(), ModuleError> {
        if let ArgVal::X(register @ 0..NUM_REGISTER_BACKED_XREGS) = dst {
            let destination = X[register as usize];
            return self
                .code
                .emit(|e| e.ldr_regoff(destination, values, index, 3))
                .map_err(ModuleError::from);
        }
        self.code
            .emit(|e| e.ldr_regoff(Gpr::x(14), values, index, 3))?;
        self.store_map_result(dst, Gpr::x(14))
    }

    pub(crate) fn store_map_result(&mut self, dst: ArgVal, src: Gpr) -> Result<(), ModuleError> {
        match dst {
            ArgVal::X(i) if i < 6 => self.code.emit(|e| e.mov_reg(X[i as usize], src))?,
            ArgVal::Y(i) => self.code.emit(|e| e.str_uoff(src, E, i * 8))?,
            ArgVal::X(i) => self
                .code
                .emit(|e| e.str_uoff(src, Gpr::x(19), crate::arm::beam_asm::x_ref(i)))?,
            _ => {
                return Err(ModuleError::InvalidOperand(
                    "map destination must be X or Y register",
                ));
            }
        }
        Ok(())
    }
}

/// OTP's `SCRATCH_X_REG` (X1023): a destination whose value is not wanted.
fn is_scratch_x(dst: ArgVal) -> bool {
    matches!(dst, ArgVal::X(1023))
}

// Port of erts/emulator/beam/jit/arm/instr_map.cpp:650-683
// (emit_update_map_single_exact_body_shared), OTP-29.1.1.
fn emit_update_map_single_exact_body_shared(
    code: &mut CodeBuffer,
    raise_exception: usize,
) -> Result<(), BufferError> {
    let error = code.new_label();
    let tmp_mem1 = crate::arm::beam_asm::tmp_mem_ref(0);
    let tmp_mem2 = crate::arm::beam_asm::tmp_mem_ref(1);
    let freason = std::mem::offset_of!(crate::ProcessHeader, exc.freason) as u32;

    code.emit(|e| e.str_uoff(Gpr::x(1), Gpr::x(19), tmp_mem2))?;
    code.emit(|e| {
        e.stp_pre(Gpr::x(29), Gpr::x(30), Gpr::sp(), -16)?;
        e.mov_reg(Gpr::x(29), Gpr::sp())
    })?;
    emit_enter_runtime(code, 6, Update::HEAP_ALLOC)?;
    code.emit(|e| {
        e.mov_reg(ARG1, Gpr::x(21))?;
        e.add_imm(ARG5, Gpr::x(19), tmp_mem1 as u16, false)?;
        e.mov_const(Gpr::x(17), crate::rt::erts_maps_update as *const () as u64)?;
        e.blr(Gpr::x(17))
    })?;
    emit_leave_runtime(code, 6, Update::HEAP_ALLOC)?;
    code.emit(|e| e.ldp_post(Gpr::x(29), Gpr::x(30), Gpr::sp(), 16))?;
    code.cbz(Gpr::w(0), error)?;
    code.emit(|e| e.ldr_uoff(Gpr::x(0), Gpr::x(19), tmp_mem1))?;
    code.emit(|e| e.ret(Gpr::x(30)))?;

    code.bind(error)?;
    code.emit(|e| {
        e.ldr_uoff(TMP2, Gpr::x(19), tmp_mem2)?;
        e.mov_const(TMP1, crate::guard::EXC_BADKEY)?;
        e.stp(TMP1, TMP2, Gpr::x(21), freason as i16)?;
        emit_raise_without_bif(e, raise_exception)
    })
}

// Port of erts/emulator/beam/jit/arm/instr_map.cpp:228-243 (emit_new_map_shared), 540-559
// (emit_update_map_assoc_shared) and 604-648 (emit_update_map_exact_guard_shared,
// emit_update_map_exact_body_shared), OTP-29.1.1. ARG3 = live, ARG4 = vector size, ARG5 =
// vector; `runtime` is `erts_gc_new_map`, `erts_gc_update_map_assoc` or
// `erts_gc_update_map_exact`. Only the exact body (`raise_exception` given) tests the result:
// `emit_branch_if_not_value(ARG1, error)`, then `mov ARG4, 0; b raise_exception`.
fn emit_vector_map_shared(
    code: &mut CodeBuffer,
    runtime: usize,
    update: Update,
    raise_exception: Option<usize>,
) -> Result<(), BufferError> {
    code.emit(|e| {
        e.stp_pre(Gpr::x(29), Gpr::x(30), Gpr::sp(), -16)?;
        e.mov_reg(Gpr::x(29), Gpr::sp())
    })?;
    emit_enter_runtime(code, 6, update)?;
    code.emit(|e| {
        e.mov_reg(ARG1, Gpr::x(21))?;
        crate::arm::beam_asm::load_x_reg_array(e, ARG2)?;
        e.mov_const(Gpr::x(17), runtime as u64)?;
        e.blr(Gpr::x(17))
    })?;
    emit_leave_runtime(code, 6, update)?;
    code.emit(|e| e.ldp_post(Gpr::x(29), Gpr::x(30), Gpr::sp(), 16))?;
    let Some(raise_exception) = raise_exception else {
        return code.emit(|e| e.ret(Gpr::x(30)));
    };
    let error = code.new_label();
    code.cbz(ARG1, error)?;
    code.emit(|e| e.ret(Gpr::x(30)))?;
    code.bind(error)?;
    code.emit(|e| emit_raise_without_bif(e, raise_exception))
}

// Port of erts/emulator/beam/jit/arm/instr_map.cpp:561-577
// (emit_update_map_single_assoc_shared), OTP-29.1.1. ARG2 = key, ARG3 = value, ARG4 = map.
fn emit_update_map_single_assoc_shared(code: &mut CodeBuffer) -> Result<(), BufferError> {
    code.emit(|e| {
        e.stp_pre(Gpr::x(29), Gpr::x(30), Gpr::sp(), -16)?;
        e.mov_reg(Gpr::x(29), Gpr::sp())
    })?;
    emit_enter_runtime(code, 6, Update::HEAP_ALLOC)?;
    code.emit(|e| {
        e.mov_reg(ARG1, Gpr::x(21))?;
        e.mov_const(Gpr::x(17), crate::rt::erts_maps_put as *const () as u64)?;
        e.blr(Gpr::x(17))
    })?;
    emit_leave_runtime(code, 6, Update::HEAP_ALLOC)?;
    code.emit(|e| {
        e.ldp_post(Gpr::x(29), Gpr::x(30), Gpr::sp(), 16)?;
        e.ret(Gpr::x(30))
    })
}

/// `mov_imm(ARG4, 0); a.b(labels[raise_exception])`.
fn emit_raise_without_bif(
    e: &mut arinsal_a64::enc::Emitter,
    raise_exception: usize,
) -> Result<(), arinsal_a64::enc::EncodeError> {
    e.mov_const(ARG4, 0)?;
    e.mov_const(Gpr::x(17), raise_exception as u64)?;
    e.br(Gpr::x(17))
}
