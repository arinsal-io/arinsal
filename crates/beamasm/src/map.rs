//! Map construction, lookup, update, and boolean emitters.

use arinsal_a64::{
    buf::{BufferError, CodeBuffer, Label},
    enc::{Cond, Gpr, Shift, Shifted, VecReg},
    exec::{CodeMemory, ExecError},
};

use crate::{
    ProcessHeader, Update, emit_enter_runtime, emit_leave_runtime,
    guard::GuardHelper,
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
/// Staging area top for `get_map_elements`, which does not allocate and has no live count:
/// the vector sits just below OTP's scratch X register (1023), away from live X registers.
const GET_ELEMENTS_STAGING_TOP: u32 = 1020;
const HTOP: Gpr = Gpr::x(23);
const ATOM_TAG: u16 = 0x0b;

// These entries map logical XREG4/5 to their caller-saved hardware registers.
const fn logical_xreg(index: u8) -> Gpr {
    Gpr::x(index)
}

/// Runtime implementation for OTP's generic map get helper.
pub type MapGetHelper = extern "C" fn(*mut ProcessHeader, u64, u64, u64) -> u64;
/// Runtime implementation for OTP's multi-key map get helper.
pub type MapGetElementsHelper = extern "C" fn(*mut ProcessHeader, u64, u64, u64, u64) -> u64;
/// Runtime implementation for map construction and updates; argument terms are staged at X6.
pub type MapUpdateHelper = extern "C" fn(*mut ProcessHeader, u64, u64, u64, u64) -> u64;

/// Runtime helpers for map operations delegated to the OTP-compatible runtime.
#[derive(Clone, Copy)]
pub struct MapRuntime {
    /// Generic lookup for non-flatmap or non-immediate keys.
    pub get: MapGetHelper,
    /// Runtime multi-key lookup.
    pub get_elements: MapGetElementsHelper,
    /// Runtime map construction.
    pub new_map: MapUpdateHelper,
    /// Runtime associative update.
    pub update_assoc: MapUpdateHelper,
    /// Runtime exact update; zero signals a missing key.
    pub update_exact: MapUpdateHelper,
    /// Single-pair associative update (`erts_maps_put`): key, value, map.
    pub put_single: MapUpdateHelper,
    /// Shared single-pair exact update fragment (`erts_maps_update`).
    pub update_single_exact_shared: usize,
    /// `i_get_map_element_shared` fragment ([`MapFragments::get_element_shared`]).
    pub get_element_shared: usize,
    /// `i_get_map_element_hash_shared` fragment ([`MapFragments::get_element_hash_shared`]).
    pub get_element_hash_shared: usize,
}

/// The `hashmap_make_hash` the loader passes to `i_get_map_element_hash` for an
/// immediate key; other literal keys are hashed by the runtime lookup.
// Port of erts/emulator/beam/generators.tab (gen.get_map_element) and erl_map.h:216
// (hashmap_make_hash), OTP-29.1.1.
pub fn literal_key_hash(key: ArgVal) -> u64 {
    match key {
        ArgVal::Immediate(word) | ArgVal::Literal(word) if word & 3 == 3 => {
            arinsal_term::immediate_internal_hash(word)
        }
        _ => 0,
    }
}

/// Process-wide map lookup fragments shared by every compiled module.
pub struct MapFragments {
    memory: CodeMemory,
    get_element_offset: usize,
    get_element_hash_offset: usize,
    update_single_exact_offset: usize,
}

impl MapFragments {
    /// Emits the shared map lookup and single exact-update fragments; `get` handles generic
    /// keys, while `update_single` implements `erts_maps_update`.
    // Port of erts/emulator/beam/jit/arm/instr_map.cpp:316-361, 493-509, and 650-683,
    // OTP-29.1.1.
    pub fn new(get: MapGetHelper, update_single: MapUpdateHelper) -> Result<Self, ExecError> {
        let mut code = CodeBuffer::new();
        let get_element = code.new_label();
        let get_element_hash = code.new_label();
        let update_single_exact = code.new_label();
        let fail = |_: BufferError| ExecError::InvalidSize("map fragment");
        code.bind(get_element).map_err(fail)?;
        emit_i_get_map_element_shared(&mut code, get).map_err(fail)?;
        code.bind(get_element_hash).map_err(fail)?;
        emit_i_get_map_element_hash_shared(&mut code).map_err(fail)?;
        code.bind(update_single_exact).map_err(fail)?;
        emit_update_map_single_exact_body_shared(&mut code, update_single).map_err(fail)?;
        let (words, labels) = code.finish_with_labels().map_err(fail)?;
        let bytes = words
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .collect::<Vec<_>>();
        let mut memory = CodeMemory::new(bytes.len().max(4))?;
        let offset = memory.alloc(bytes.len().max(4))?;
        memory.write_bytes(offset, &bytes)?;
        memory.flush_all()?;
        Ok(Self {
            memory,
            get_element_offset: labels[&get_element],
            get_element_hash_offset: labels[&get_element_hash],
            update_single_exact_offset: labels[&update_single_exact],
        })
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

    /// Entry of the shared single-pair exact update fragment: key in X1, value in X2, map in
    /// X3. Returns the updated map in X0; a missing key transfers to the native error exit.
    pub fn update_single_exact_shared(&self) -> usize {
        self.memory.ptr_at(self.update_single_exact_offset) as usize
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
fn emit_i_get_map_element_shared(
    code: &mut CodeBuffer,
    get: MapGetHelper,
) -> Result<(), BufferError> {
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
    // erts' get_map_element cannot fail; the helper's error word is cleared so a map the
    // compiler did not guard with is_map reads as a miss instead of a stale pending error.
    code.emit(|e| {
        e.stp_pre(Gpr::x(29), Gpr::x(30), Gpr::sp(), -16)?;
        e.mov_reg(Gpr::x(29), Gpr::sp())
    })?;
    emit_enter_runtime(code, 6, Update::NONE)?;
    code.emit(|e| {
        e.mov_reg(Gpr::x(2), ARG2)?;
        e.mov_reg(Gpr::x(1), ARG1)?;
        e.mov_reg(Gpr::x(0), Gpr::x(21))?;
        e.mov_reg(Gpr::x(3), Gpr::xzr())?;
        e.mov_const(Gpr::x(17), get as usize as u64)?;
        e.blr(Gpr::x(17))
    })?;
    emit_leave_runtime(code, 6, Update::NONE)?;
    code.emit(|e| {
        e.str_uoff(Gpr::xzr(), Gpr::x(21), 40)?;
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
        let map = self.source_reg(src)?;
        self.code.emit(|e| e.mov_reg(Gpr::x(0), map))?;
        let key = self.source_reg_into(key, Gpr::x(17))?;
        self.code.emit(|e| e.mov_reg(Gpr::x(1), key))?;
        let fail = self.label(fail);
        self.emit_get_element_fragment_call(runtime.get_element_shared, fail, dst)
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
        if matches!(key, ArgVal::Immediate(word) | ArgVal::Literal(word) if word & 3 == 3) {
            for (arg, value) in [(Gpr::x(0), src), (Gpr::x(1), key)] {
                let reg = self.source_reg(value)?;
                self.code.emit(|e| e.mov_reg(arg, reg))?;
            }
            match hash {
                ArgVal::Immediate(value) | ArgVal::Literal(value) => {
                    // ArgWord constants wider than 32 bits are embedded in OTP's module
                    // literal area and loaded with LDR literal.
                    // Port of erts/emulator/beam/jit/arm/beam_asm.hpp:1528-1554,
                    // OTP-29.1.1.
                    self.code.ldr_literal(Gpr::x(2), value)?;
                }
                _ => {
                    let reg = self.source_reg(hash)?;
                    self.code.emit(|e| e.mov_reg(Gpr::x(2), reg))?;
                }
            }
            return self.emit_get_element_fragment_call(runtime.get_element_hash_shared, fail, dst);
        }
        for (arg, value) in [(Gpr::x(1), src), (Gpr::x(2), key), (Gpr::x(3), hash)] {
            let reg = self.source_reg(value)?;
            self.code.emit(|e| e.mov_reg(arg, reg))?;
        }
        emit_map_runtime(
            self,
            runtime.get as usize,
            &[Gpr::x(1), Gpr::x(2), Gpr::x(3)],
            6,
            Update::NONE,
        )?;
        self.code.emit(|e| e.cmp_imm(Gpr::x(0), 0, false))?;
        self.code.b_cond(Cond::Eq, fail)?;
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

    /// Emits the body fast path of `is_map_key/2`.
    // Port of erts/emulator/beam/jit/arm/instr_guard_bifs.cpp:799-830, OTP-29.1.1.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn emit_map_is_key_fast(
        &mut self,
        map: ArgVal,
        key: ArgVal,
        destination: ArgVal,
        exact_map: bool,
        key_maybe_immediate: bool,
        slow: Option<Label>,
        runtime: MapRuntime,
    ) -> Result<(), ModuleError> {
        let map = self.source_reg(map)?;
        self.code.emit(|e| e.mov_reg(Gpr::x(0), map))?;
        let key = self.source_reg_into(key, Gpr::x(17))?;
        self.code.emit(|e| e.mov_reg(Gpr::x(1), key))?;

        if !exact_map {
            let slow = slow.ok_or(ModuleError::InvalidOperand(
                "unknown map type needs a BIF fallback label",
            ))?;
            emit_map_type_check(&mut self.code, Gpr::x(0), slow)?;
        }
        if key_maybe_immediate {
            self.fragment_call(runtime.get_element_shared)?;
            self.code.emit(|e| {
                e.mov_const(Gpr::x(10), 0x0b)?;
                e.mov_const(Gpr::x(11), 0x4b)?;
                e.csel(Gpr::x(0), Gpr::x(11), Gpr::x(10), Cond::Eq)
            })?;
        } else {
            // The header test writes TMP (x9). A map loaded from Y or memory lives in that
            // register; x0 still holds it, as ARG1 does across erts' TMP1 header test.
            self.emit_map_get_runtime(key, preserved_map(map), runtime)?;
            self.code.emit(|e| {
                e.cmp_imm(Gpr::x(0), 0, false)?;
                e.mov_const(Gpr::x(10), 0x0b)?;
                e.mov_const(Gpr::x(11), 0x4b)?;
                e.csel(Gpr::x(0), Gpr::x(11), Gpr::x(10), Cond::Ne)
            })?;
        }
        self.store_map_result(destination, Gpr::x(0))
    }

    /// Emits the generic runtime lookup for a boxed-only key.
    // Port of erts/emulator/beam/jit/arm/instr_guard_bifs.cpp:813-822,891-913,
    // OTP-29.1.1 (`runtime_call<get_map_element>`).
    fn emit_map_get_runtime(
        &mut self,
        key: Gpr,
        map: Gpr,
        runtime: MapRuntime,
    ) -> Result<(), ModuleError> {
        self.code.emit(|e| {
            e.mov_reg(Gpr::x(2), key)?;
            e.mov_reg(Gpr::x(1), map)?;
            e.mov_reg(Gpr::x(3), Gpr::xzr())
        })?;
        emit_map_runtime(
            self,
            runtime.get as usize,
            &[Gpr::x(1), Gpr::x(2), Gpr::x(3)],
            6,
            Update::NONE,
        )
    }

    /// Emits multi-key lookup; the operands are flattened `{key, dst, hash}` triplets.
    // Port of erts/emulator/beam/jit/arm/instr_map.cpp:391-490, OTP-29.1.1.
    pub fn emit_i_get_map_elements(
        &mut self,
        fail: u32,
        src: ArgVal,
        args: &[ArgVal],
        runtime: MapRuntime,
    ) -> Result<(), ModuleError> {
        if !args.len().is_multiple_of(3) {
            return Err(ModuleError::InvalidOperand(
                "map get operands must be triplets",
            ));
        }
        let base = GET_ELEMENTS_STAGING_TOP - args.len() as u32;
        // The inline flatmap scan compares key words, which identifies only immediate keys;
        // a boxed literal key (float, tuple, map, list) is compared by value in the runtime.
        // Port of erts/emulator/beam/jit/arm/instr_map.cpp (emit_i_get_map_elements), OTP-29.1.1.
        if args.len() < 24
            && args.iter().step_by(3).all(
                |v| matches!(v, ArgVal::Immediate(word) | ArgVal::Literal(word) if word & 3 == 3),
            )
        {
            let map = self.source_reg(src)?;
            self.code.emit(|e| e.mov_reg(Gpr::x(1), map))?;
            self.code.emit(|e| e.and_imm(Gpr::x(8), map, !7))?;
            self.code.emit(|e| e.ldr_uoff(Gpr::x(9), Gpr::x(8), 0))?;
            self.code.emit(|e| e.and_imm(Gpr::x(9), Gpr::x(9), 0xc0))?;
            self.code.emit(|e| e.cmp_imm(Gpr::x(9), 0, false))?;
            let generic = self.code.new_label();
            let done = self.code.new_label();
            self.code.b_cond(Cond::Ne, generic)?;
            self.code.emit(|e| e.ldr_uoff(Gpr::x(10), Gpr::x(8), 8))?;
            self.code
                .emit(|e| e.add_imm(Gpr::x(10), Gpr::x(10), 1, false))?;
            self.code.emit(|e| e.mov_reg(Gpr::x(14), Gpr::x(10)))?;
            self.code.emit(|e| e.ldr_uoff(Gpr::x(11), Gpr::x(8), 16))?;
            self.code.emit(|e| e.and_imm(Gpr::x(11), Gpr::x(11), !7))?;
            for triplet in args.as_chunks::<3>().0.iter().rev() {
                let loop_label = self.code.new_label();
                self.code.emit(|e| e.mov_reg(Gpr::x(10), Gpr::x(14)))?;
                self.code.bind(loop_label)?;
                self.code
                    .emit(|e| e.subs_imm(Gpr::x(10), Gpr::x(10), 1, false))?;
                let fail_label = self.label(fail);
                self.code.b_cond(Cond::Eq, fail_label)?;
                self.code
                    .emit(|e| e.ldr_regoff(Gpr::x(12), Gpr::x(11), Gpr::x(10), 3))?;
                let key = self.source_reg(triplet[0])?;
                self.code
                    .emit(|e| e.cmp_reg(Gpr::x(12), key, arinsal_a64::enc::Shift::Lsl, 0))?;
                self.code.b_cond(Cond::Ne, loop_label)?;
                let dst = triplet[1];
                if !is_scratch_x(dst) {
                    let val = self.destination_register_for(dst)?;
                    self.code
                        .emit(|e| e.add_imm(Gpr::x(13), Gpr::x(8), 16, false))?;
                    self.code
                        .emit(|e| e.ldr_regoff(val, Gpr::x(13), Gpr::x(10), 3))?;
                    self.store_map_result(dst, val)?;
                }
            }
            self.code.b(done)?;
            self.code.bind(generic)?;
            self.stage_map_args(args, base)?;
            self.code.emit(|e| e.mov_reg(Gpr::x(2), Gpr::x(19)))?;
            self.code
                .emit(|e| e.mov_const(Gpr::x(3), u64::from(base)))?;
            self.code
                .emit(|e| e.mov_const(Gpr::x(4), (args.len() / 3) as u64))?;
            emit_map_runtime(
                self,
                runtime.get_elements as usize,
                &[Gpr::x(1), Gpr::x(2), Gpr::x(3), Gpr::x(4)],
                6,
                Update::X_REGS,
            )?;
            self.code.emit(|e| e.cmp_imm(Gpr::x(0), 0, false))?;
            let fail_label = self.label(fail);
            self.code.b_cond(Cond::Eq, fail_label)?;
            self.store_staged_map_elements(args, base)?;
            self.code.bind(done)?;
            Ok(())
        } else {
            self.stage_map_args(args, base)?;
            let map = self.source_reg(src)?;
            self.code.emit(|e| e.mov_reg(Gpr::x(1), map))?;
            self.code.emit(|e| e.mov_reg(Gpr::x(2), Gpr::x(19)))?;
            self.code
                .emit(|e| e.mov_const(Gpr::x(3), u64::from(base)))?;
            self.code
                .emit(|e| e.mov_const(Gpr::x(4), (args.len() / 3) as u64))?;
            emit_map_runtime(
                self,
                runtime.get_elements as usize,
                &[Gpr::x(1), Gpr::x(2), Gpr::x(3), Gpr::x(4)],
                6,
                Update::X_REGS,
            )?;
            let fail_label = self.label(fail);
            self.code.cbz(Gpr::x(0), fail_label)?;
            self.store_staged_map_elements(args, base)?;
            Ok(())
        }
    }

    /// Moves the values the runtime lookup left in the staging area to their destinations.
    // Port of erts/emulator/beam/jit/arm/instr_map.cpp:391-490, OTP-29.1.1.
    fn store_staged_map_elements(&mut self, args: &[ArgVal], base: u32) -> Result<(), ModuleError> {
        for (index, triplet) in args.as_chunks::<3>().0.iter().enumerate() {
            let dst = triplet[1];
            if is_scratch_x(dst) {
                continue;
            }
            let offset = u32::try_from(base as usize + 1 + index * 3)
                .map_err(|_| ModuleError::InvalidOperand("map argument offset overflow"))?
                * 8;
            self.code
                .emit(|e| e.ldr_uoff(Gpr::x(8), Gpr::x(19), offset))?;
            self.store_map_result(dst, Gpr::x(8))?;
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
        self.stage_map_args(args, live.max(6))?;
        self.code.emit(|e| e.mov_reg(Gpr::x(1), Gpr::xzr()))?;
        self.code.emit(|e| e.mov_reg(Gpr::x(2), Gpr::x(19)))?;
        self.code.emit(|e| e.mov_const(Gpr::x(3), live as u64))?;
        self.code
            .emit(|e| e.mov_const(Gpr::x(4), (args.len() / 2) as u64))?;
        emit_map_runtime(
            self,
            runtime.new_map as usize,
            &[Gpr::x(1), Gpr::x(2), Gpr::x(3), Gpr::x(4)],
            6,
            Update::HEAP_ALLOC
                .union(Update::X_REGS)
                .union(Update::REDUCTIONS),
        )?;
        self.store_map_result(dst, Gpr::x(0))
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
            self.emit_map_single(src, updates, runtime.put_single, false)?;
            return self.store_map_result(dst, Gpr::x(0));
        }
        self.stage_map_args(updates, live.max(6))?;
        let source = self.source_reg(src)?;
        self.code.emit(|e| e.mov_reg(Gpr::x(1), source))?;
        self.code.emit(|e| e.mov_reg(Gpr::x(2), Gpr::x(19)))?;
        self.code.emit(|e| e.mov_const(Gpr::x(3), live as u64))?;
        self.code
            .emit(|e| e.mov_const(Gpr::x(4), (updates.len() / 2) as u64))?;
        emit_map_runtime(
            self,
            runtime.update_assoc as usize,
            &[Gpr::x(1), Gpr::x(2), Gpr::x(3), Gpr::x(4)],
            6,
            Update::HEAP_ALLOC
                .union(Update::X_REGS)
                .union(Update::REDUCTIONS),
        )?;
        self.store_map_result(dst, Gpr::x(0))
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
        self.stage_map_args(updates, live.max(6))?;
        let source = self.source_reg(src)?;
        self.code.emit(|e| e.mov_reg(Gpr::x(1), source))?;
        self.code.emit(|e| e.mov_reg(Gpr::x(2), Gpr::x(19)))?;
        // Bit 32 tells the runtime that a failure label exists: a missing key then fails the
        // instruction quietly instead of raising `{badkey, Key}`.
        let live_and_flags = u64::from(live) | (u64::from(fail != 0) << 32);
        self.code.emit(|e| e.mov_const(Gpr::x(3), live_and_flags))?;
        self.code
            .emit(|e| e.mov_const(Gpr::x(4), (updates.len() / 2) as u64))?;
        emit_map_runtime(
            self,
            runtime.update_exact as usize,
            &[Gpr::x(1), Gpr::x(2), Gpr::x(3), Gpr::x(4)],
            6,
            Update::HEAP_ALLOC
                .union(Update::X_REGS)
                .union(Update::REDUCTIONS),
        )?;
        if fail != 0 {
            self.code.emit(|e| e.cmp_imm(Gpr::x(0), 0, false))?;
            let fail_label = self.label(fail);
            self.code.b_cond(Cond::Eq, fail_label)?;
        }
        self.store_map_result(dst, Gpr::x(0))
    }

    /// Emits Erlang's strict boolean `and/2` BIF.
    // Port of erts/emulator/beam/jit/arm/instr_guard_bifs.cpp:294-340, OTP-29.1.1.
    pub fn emit_bif_and(
        &mut self,
        fail: u32,
        lhs: ArgVal,
        rhs: ArgVal,
        dst: ArgVal,
        runtime: GuardHelper,
    ) -> Result<(), ModuleError> {
        self.emit_boolean_binary(fail, lhs, rhs, dst, false, runtime)
    }

    /// Emits Erlang's strict boolean `or/2` BIF.
    // Port of erts/emulator/beam/jit/arm/instr_guard_bifs.cpp:1215-1250, OTP-29.1.1.
    pub fn emit_bif_or(
        &mut self,
        fail: u32,
        lhs: ArgVal,
        rhs: ArgVal,
        dst: ArgVal,
        runtime: GuardHelper,
    ) -> Result<(), ModuleError> {
        self.emit_boolean_binary(fail, lhs, rhs, dst, true, runtime)
    }

    /// Emits Erlang's strict boolean `not/1` BIF.
    // Port of erts/emulator/beam/jit/arm/instr_guard_bifs.cpp:1177-1213, OTP-29.1.1.
    pub fn emit_bif_not(
        &mut self,
        fail: u32,
        src: ArgVal,
        dst: ArgVal,
        runtime: GuardHelper,
    ) -> Result<(), ModuleError> {
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
            self.code.emit(|e| e.mov_const(Gpr::x(8), 42))?;
            self.code.emit(|e| e.mov_const(Gpr::x(9), 0))?;
            self.emit_guard_runtime_call(runtime as usize, &[Gpr::x(8), value, Gpr::x(9)])?;
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
        runtime: GuardHelper,
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
            self.code
                .emit(|e| e.mov_const(Gpr::x(10), if is_or { 41 } else { 40 }))?;
            self.emit_guard_runtime_call(runtime as usize, &[Gpr::x(10), Gpr::x(8), Gpr::x(9)])?;
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

    /// Inline part of `bif_map_get`: a key found in a map is stored in `dst`; anything else
    /// (not a map, a miss) branches to `slow`.
    // Port of erts/emulator/beam/jit/arm/instr_guard_bifs.cpp:854-930 (emit_bif_map_get),
    // OTP-29.1.1.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn emit_map_get_fast(
        &mut self,
        map: ArgVal,
        key: ArgVal,
        dst: ArgVal,
        slow: Label,
        exact_map: bool,
        key_maybe_immediate: bool,
        runtime: MapRuntime,
    ) -> Result<(), ModuleError> {
        let map = self.source_reg(map)?;
        self.code.emit(|e| e.mov_reg(Gpr::x(0), map))?;
        let key = self.source_reg_into(key, Gpr::x(17))?;
        self.code.emit(|e| e.mov_reg(Gpr::x(1), key))?;
        if !exact_map {
            emit_map_type_check(&mut self.code, Gpr::x(0), slow)?;
        }
        if key_maybe_immediate {
            self.emit_get_element_fragment_call(runtime.get_element_shared, slow, dst)
        } else {
            // The header test writes TMP (x9). A map loaded from Y or memory lives in that
            // register; x0 still holds it, as ARG1 does across erts' TMP1 header test.
            self.emit_map_get_runtime(key, preserved_map(map), runtime)?;
            self.code.emit(|e| e.cmp_imm(Gpr::x(0), 0, false))?;
            self.code.b_cond(Cond::Eq, slow)?;
            self.store_map_result(dst, Gpr::x(0))
        }
    }

    fn destination_register_for(&self, dst: ArgVal) -> Result<Gpr, ModuleError> {
        match dst {
            ArgVal::X(i) if i < 6 => Ok(X[i as usize]),
            // Y destinations load through a scratch that no fast path uses.
            ArgVal::Y(_) | ArgVal::XMemory(_) => Ok(Gpr::x(5)),
            _ => Err(ModuleError::InvalidOperand(
                "map destination must be an X register below 6 or a Y register",
            )),
        }
    }

    // Port of erts/emulator/beam/jit/arm/instr_map.cpp:579-598,686-694, OTP-29.1.1: a
    // single pair goes to `erts_maps_put`/`erts_maps_update` in argument registers; those
    // never collect, and `erts_maps_update` writes its result through `TMP_MEM1`.
    fn emit_map_single(
        &mut self,
        src: ArgVal,
        pair: &[ArgVal],
        helper: MapUpdateHelper,
        result_in_tmp_mem: bool,
    ) -> Result<(), ModuleError> {
        for (target, value) in [(Gpr::x(1), pair[0]), (Gpr::x(2), pair[1]), (Gpr::x(3), src)] {
            let reg = self.source_reg(value)?;
            self.code.emit(|e| e.mov_reg(target, reg))?;
        }
        if result_in_tmp_mem {
            let tmp_mem = std::mem::offset_of!(crate::SchedulerRegisters, tmp_mem) as u32;
            // The failure fragment reads TMP_MEM2 after the runtime call.
            self.code
                .emit(|e| e.str_uoff(Gpr::x(1), Gpr::x(19), tmp_mem + 8))?;
            self.code
                .emit(|e| e.add_imm(Gpr::x(4), Gpr::x(19), (tmp_mem >> 12) as u16, true))?;
        } else {
            self.code.emit(|e| e.mov_reg(Gpr::x(4), Gpr::xzr()))?;
        }
        let args = [Gpr::x(1), Gpr::x(2), Gpr::x(3), Gpr::x(4)];
        if result_in_tmp_mem {
            emit_map_runtime_status(self, helper as usize, &args, 0, Update::HEAP_ALLOC)?;
        } else {
            emit_map_runtime_framed(self, helper as usize, &args, 0, Update::HEAP_ALLOC)?;
        }
        if result_in_tmp_mem {
            let tmp_mem = std::mem::offset_of!(crate::SchedulerRegisters, tmp_mem) as u32;
            self.code
                .emit(|e| e.ldr_uoff(Gpr::x(0), Gpr::x(19), tmp_mem))?;
        }
        Ok(())
    }

    fn stage_map_args(&mut self, args: &[ArgVal], base: u32) -> Result<(), ModuleError> {
        if args.len() + base as usize > 1022 {
            return Err(ModuleError::InvalidOperand(
                "map argument vector exceeds scheduler register capacity",
            ));
        }
        for (index, arg) in args.iter().copied().enumerate() {
            let value = self.source_reg(arg)?;
            let offset = u32::try_from(index + base as usize)
                .map_err(|_| ModuleError::InvalidOperand("map argument offset overflow"))?
                * 8;
            self.code.emit(|e| e.str_uoff(value, Gpr::x(19), offset))?;
        }
        Ok(())
    }

    fn store_map_result(&mut self, dst: ArgVal, src: Gpr) -> Result<(), ModuleError> {
        match dst {
            ArgVal::X(i) if i < 6 => self.code.emit(|e| e.mov_reg(X[i as usize], src))?,
            ArgVal::Y(i) => self.code.emit(|e| e.str_uoff(src, E, i * 8))?,
            ArgVal::XMemory(i) => self.code.emit(|e| e.str_uoff(src, Gpr::x(19), i * 8))?,
            _ => {
                return Err(ModuleError::InvalidOperand(
                    "map destination must be X or Y register",
                ));
            }
        }
        Ok(())
    }
}

// `exact_type<Map>` lets erts omit these checks; otherwise the boxed tag and map header are
// checked before the shared fragment dereferences the term.
// Port of erts/emulator/beam/jit/arm/instr_guard_bifs.cpp:854-885, OTP-29.1.1.
/// Map operand to pass to the boxed-key runtime after `emit_map_type_check`.
///
/// The check materializes the header in TMP (`x9`), which is also where
/// `source_reg` puts a Y or memory operand. The copy in `x0` is the map.
// Port of erts/emulator/beam/jit/arm/instr_guard_bifs.cpp:868-891, OTP-29.1.1
// (the map stays in ARG1 while the header test uses TMP1).
fn preserved_map(map: Gpr) -> Gpr {
    if map == Gpr::x(9) { Gpr::x(0) } else { map }
}

fn emit_map_type_check(code: &mut CodeBuffer, map: Gpr, not_map: Label) -> Result<(), ModuleError> {
    code.emit(|e| {
        e.and_imm(Gpr::x(9), map, 3)?;
        e.cmp_imm(Gpr::x(9), 2, false)
    })?;
    code.b_cond(Cond::Ne, not_map)?;
    code.emit(|e| {
        e.and_imm(Gpr::x(8), map, !7)?;
        e.ldr_uoff(Gpr::x(9), Gpr::x(8), 0)?;
        e.and_imm(Gpr::x(10), Gpr::x(9), 0x3f)?;
        e.cmp_imm(Gpr::x(10), 0x2c, false)
    })?;
    code.b_cond(Cond::Ne, not_map)?;
    Ok(())
}

/// OTP's `SCRATCH_X_REG` (X1023): a destination whose value is not wanted.
fn is_scratch_x(dst: ArgVal) -> bool {
    matches!(dst, ArgVal::XMemory(1023))
}

// Port of erts/emulator/beam/jit/arm/beam_asm.hpp:459-601, OTP-29.1.1.
fn emit_map_runtime(
    asm: &mut BeamModuleAssembler,
    helper: usize,
    args: &[Gpr],
    live: usize,
    update: Update,
) -> Result<(), ModuleError> {
    emit_map_runtime_inner(asm, helper, args, live, update, false, false)
}

fn emit_map_runtime_framed(
    asm: &mut BeamModuleAssembler,
    helper: usize,
    args: &[Gpr],
    live: usize,
    update: Update,
) -> Result<(), ModuleError> {
    emit_map_runtime_inner(asm, helper, args, live, update, false, true)
}

fn emit_map_runtime_status(
    asm: &mut BeamModuleAssembler,
    helper: usize,
    args: &[Gpr],
    live: usize,
    update: Update,
) -> Result<(), ModuleError> {
    emit_map_runtime_inner(asm, helper, args, live, update, true, true)
}

// Port of erts/emulator/beam/jit/arm/instr_map.cpp:650-683
// (emit_update_map_single_exact_body_shared), OTP-29.1.1. Arinsal transfers a failed update
// through its module error-exit slots, preserving the raising pc from the fragment call.
fn emit_update_map_single_exact_body_shared(
    code: &mut CodeBuffer,
    helper: MapUpdateHelper,
) -> Result<(), BufferError> {
    let error = code.new_label();
    let tmp_mem1 = std::mem::offset_of!(crate::SchedulerRegisters, tmp_mem) as u32;
    let tmp_mem2 = tmp_mem1 + 8;
    let native_error_pc = tmp_mem1 + 6 * 8;
    let native_return = tmp_mem1 + 4 * 8;
    let freason = std::mem::offset_of!(crate::ProcessHeader, freason) as u32;

    code.emit(|e| e.str_uoff(Gpr::x(1), Gpr::x(19), tmp_mem2))?;
    code.emit(|e| {
        e.stp_pre(Gpr::x(29), Gpr::x(30), Gpr::sp(), -16)?;
        e.mov_reg(Gpr::x(29), Gpr::sp())
    })?;
    emit_enter_runtime(code, 0, Update::HEAP_ALLOC)?;
    code.emit(|e| {
        e.mov_reg(Gpr::x(0), Gpr::x(21))?;
        e.add_imm(Gpr::x(4), Gpr::x(19), (tmp_mem1 >> 12) as u16, true)?;
        e.mov_const(Gpr::x(17), helper as usize as u64)?;
        e.blr(Gpr::x(17))
    })?;
    emit_leave_runtime(code, 0, Update::HEAP_ALLOC)?;
    code.emit(|e| e.ldp_post(Gpr::x(29), Gpr::x(30), Gpr::sp(), 16))?;
    code.cbz(Gpr::w(0), error)?;
    code.emit(|e| e.ldr_uoff(Gpr::x(0), Gpr::x(19), tmp_mem1))?;
    code.emit(|e| e.ret(Gpr::x(30)))?;

    code.bind(error)?;
    code.emit(|e| {
        e.ldr_uoff(Gpr::x(9), Gpr::x(19), tmp_mem2)?;
        e.mov_const(Gpr::x(8), crate::guard::EXC_BADKEY)?;
        e.stp(Gpr::x(8), Gpr::x(9), Gpr::x(21), freason as i16)?;
        e.mov_reg(Gpr::x(0), Gpr::xzr())?;
        e.str_uoff(Gpr::x(30), Gpr::x(19), native_error_pc)?;
        e.ldr_uoff(Gpr::x(30), Gpr::x(19), native_return)?;
        e.br(Gpr::x(30))
    })
}

fn emit_map_runtime_inner(
    asm: &mut BeamModuleAssembler,
    helper: usize,
    args: &[Gpr],
    live: usize,
    update: Update,
    status_result: bool,
    runtime_frame: bool,
) -> Result<(), ModuleError> {
    if args.len() > 5 {
        return Err(ModuleError::InvalidOperand(
            "runtime hook has too many arguments",
        ));
    }
    if runtime_frame {
        asm.code.emit(|e| {
            e.stp_pre(Gpr::x(29), Gpr::x(30), Gpr::sp(), -16)?;
            e.mov_reg(Gpr::x(29), Gpr::sp())
        })?;
    }
    emit_enter_runtime(&mut asm.code, live, update)?;
    asm.code.emit(|e| {
        e.mov_reg(Gpr::x(0), Gpr::x(21))?;
        for (index, arg) in args.iter().copied().enumerate() {
            let target = Gpr::x(index as u8 + 1);
            // BeamAsm's mov_var omits moves when source and destination already match.
            // Port of erts/emulator/beam/jit/arm/beam_asm.hpp:1649-1664, OTP-29.1.1.
            if target != arg {
                e.mov_reg(target, arg)?;
            }
        }
        e.mov_const(Gpr::x(17), helper as u64)?;
        if runtime_frame {
            e.blr(Gpr::x(17))
        } else {
            e.str_uoff(Gpr::x(30), Gpr::x(21), 72)?;
            e.blr(Gpr::x(17))
        }
    })?;
    emit_leave_runtime(&mut asm.code, live, update)?;
    asm.code.emit(|e| {
        if runtime_frame {
            e.ldp_post(Gpr::x(29), Gpr::x(30), Gpr::sp(), 16)?;
        } else {
            e.ldr_uoff(Gpr::x(30), Gpr::x(21), 72)?;
        }
        if status_result {
            Ok(())
        } else {
            e.ldr_uoff(Gpr::x(9), Gpr::x(21), 40)
        }
    })?;
    if status_result {
        emit_map_update_status_error(asm)?;
    } else {
        asm.error_if_nonzero(Gpr::x(9))?;
    }
    Ok(())
}

fn emit_map_update_status_error(asm: &mut BeamModuleAssembler) -> Result<(), ModuleError> {
    // Port of erts/emulator/beam/jit/arm/instr_map.cpp:671-683,
    // emit_update_map_single_exact_body_shared, OTP-29.1.1.
    let success = asm.code.new_label();
    let other_error = asm.code.new_label();
    let tmp_mem2 = std::mem::offset_of!(crate::SchedulerRegisters, tmp_mem) as u32 + 8;
    let freason = std::mem::offset_of!(crate::ProcessHeader, freason) as u32;

    asm.code.cbnz(Gpr::w(0), success)?;
    asm.code
        .emit(|e| e.ldr_uoff(Gpr::x(9), Gpr::x(21), freason))?;
    asm.code.cbnz(Gpr::x(9), other_error)?;
    asm.code
        .emit(|e| e.ldr_uoff(Gpr::x(10), Gpr::x(19), tmp_mem2))?;
    asm.code
        .emit(|e| e.mov_const(Gpr::x(11), crate::guard::EXC_BADKEY))?;
    asm.code
        .emit(|e| e.stp(Gpr::x(11), Gpr::x(10), Gpr::x(21), freason as i16))?;
    asm.branch_error()?;

    asm.code.bind(other_error)?;
    asm.branch_error()?;
    asm.code.bind(success)?;
    Ok(())
}
