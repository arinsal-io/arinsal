//! Map construction, lookup, update, and boolean emitters.

use arinsal_a64::{
    buf::Label,
    enc::{Cond, Gpr},
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
        self.code.emit(|e| e.mov_reg(Gpr::x(1), map))?;
        let key = self.source_reg_into(key, Gpr::x(17))?;
        self.code.emit(|e| e.mov_reg(Gpr::x(2), key))?;
        self.emit_small_internal_hash(Gpr::x(2))?;
        let fail = self.label(fail);
        self.emit_map_get_inline(fail, dst, runtime.get)
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
        for (arg, value) in [(Gpr::x(1), src), (Gpr::x(2), key), (Gpr::x(3), hash)] {
            let reg = self.source_reg(value)?;
            self.code.emit(|e| e.mov_reg(arg, reg))?;
        }
        let fail = self.label(fail);
        self.emit_map_get_inline(fail, dst, runtime.get)
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
        // A flatmap header carries only the MAP subtag; bits 6-7 would mark a hashmap.
        self.code.emit(|e| e.mov_const(Gpr::x(8), 0x2c))?;
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

    // Port of erts/emulator/beam/jit/arm/instr_map.cpp:316-390,511-542, OTP-29.1.1.
    fn emit_map_get_inline(
        &mut self,
        fail: Label,
        dst: ArgVal,
        generic: MapGetHelper,
    ) -> Result<(), ModuleError> {
        let generic_label = self.code.new_label();
        let done = self.code.new_label();
        self.code.emit(|e| e.and_imm(Gpr::x(9), Gpr::x(2), 3))?;
        self.code.emit(|e| e.cmp_imm(Gpr::x(9), 3, false))?;
        self.code.b_cond(Cond::Ne, generic_label)?;
        self.code.emit(|e| e.and_imm(Gpr::x(9), Gpr::x(1), 3))?;
        self.code.emit(|e| e.cmp_imm(Gpr::x(9), 2, false))?;
        self.code.b_cond(Cond::Ne, generic_label)?;
        self.code.emit(|e| e.and_imm(Gpr::x(8), Gpr::x(1), !7))?;
        self.code.emit(|e| e.ldr_uoff(Gpr::x(9), Gpr::x(8), 0))?;
        self.code.emit(|e| e.and_imm(Gpr::x(10), Gpr::x(9), 0x3f))?;
        self.code.emit(|e| e.cmp_imm(Gpr::x(10), 0x2c, false))?;
        self.code.b_cond(Cond::Ne, generic_label)?;
        self.code.emit(|e| e.and_imm(Gpr::x(9), Gpr::x(9), 0xc0))?;
        let hashmap = self.code.new_label();
        self.code.emit(|e| e.cmp_imm(Gpr::x(9), 0, false))?;
        self.code.b_cond(Cond::Ne, hashmap)?;
        self.emit_flatmap_lookup(fail)?;
        self.code.b(done)?;
        self.code.bind(hashmap)?;
        self.code.emit(|e| e.ldr_uoff(Gpr::x(9), Gpr::x(8), 0))?;
        let runtime_fallback = self.code.new_label();
        self.emit_hashmap_lookup(runtime_fallback)?;
        self.code.b(done)?;
        self.code.bind(runtime_fallback)?;
        emit_map_runtime(
            self,
            generic as usize,
            &[Gpr::x(1), Gpr::x(2), Gpr::x(3)],
            6,
            Update::NONE,
        )?;
        self.code.emit(|e| e.cmp_imm(Gpr::x(0), 0, false))?;
        self.code.b_cond(Cond::Eq, fail)?;
        self.code.bind(done)?;
        self.store_map_result(dst, Gpr::x(0))?;
        let after_store = self.code.new_label();
        self.code.b(after_store)?;
        self.code.bind(generic_label)?;
        emit_map_runtime(
            self,
            generic as usize,
            &[Gpr::x(1), Gpr::x(2), Gpr::x(3)],
            6,
            Update::NONE,
        )?;
        self.code.emit(|e| e.cmp_imm(Gpr::x(0), 0, false))?;
        self.code.b_cond(Cond::Eq, fail)?;
        self.store_map_result(dst, Gpr::x(0))?;
        self.code.bind(after_store)?;
        Ok(())
    }

    // Port of erts/emulator/beam/jit/arm/instr_map.cpp:267-293, OTP-29.1.1.
    fn emit_flatmap_lookup(&mut self, fail: Label) -> Result<(), ModuleError> {
        self.code.emit(|e| e.ldr_uoff(Gpr::x(10), Gpr::x(8), 8))?;
        self.code
            .emit(|e| e.add_imm(Gpr::x(10), Gpr::x(10), 1, false))?;
        self.code.emit(|e| e.ldr_uoff(Gpr::x(11), Gpr::x(8), 16))?;
        self.code.emit(|e| e.and_imm(Gpr::x(11), Gpr::x(11), !7))?;
        let loop_label = self.code.new_label();
        self.code.bind(loop_label)?;
        self.code
            .emit(|e| e.subs_imm(Gpr::x(10), Gpr::x(10), 1, false))?;
        self.code.b_cond(Cond::Eq, fail)?;
        self.code
            .emit(|e| e.ldr_regoff(Gpr::x(12), Gpr::x(11), Gpr::x(10), 3))?;
        self.code
            .emit(|e| e.cmp_reg(Gpr::x(2), Gpr::x(12), arinsal_a64::enc::Shift::Lsl, 0))?;
        self.code.b_cond(Cond::Ne, loop_label)?;
        self.code
            .emit(|e| e.add_imm(Gpr::x(13), Gpr::x(8), 16, false))?;
        self.code
            .emit(|e| e.ldr_regoff(Gpr::x(0), Gpr::x(13), Gpr::x(10), 3))?;
        Ok(())
    }

    // Port of erts/emulator/beam/jit/arm/instr_map.cpp:25-60, OTP-29.1.1.
    fn emit_small_internal_hash(&mut self, key: Gpr) -> Result<(), ModuleError> {
        let shifted_key = arinsal_a64::enc::Shifted {
            reg: key,
            shift: arinsal_a64::enc::Shift::Lsr,
            amount: 33,
        };
        self.code.emit(|e| e.eor_reg(Gpr::x(3), key, shifted_key))?;
        self.code
            .emit(|e| e.mov_const(Gpr::x(12), 0xff51_afd7_ed55_8ccd))?;
        self.code
            .emit(|e| e.mul(Gpr::x(3), Gpr::x(3), Gpr::x(12)))?;
        let shifted = arinsal_a64::enc::Shifted {
            reg: Gpr::x(3),
            shift: arinsal_a64::enc::Shift::Lsr,
            amount: 33,
        };
        self.code
            .emit(|e| e.eor_reg(Gpr::x(3), Gpr::x(3), shifted))?;
        self.code
            .emit(|e| e.mov_const(Gpr::x(12), 0xc4ce_b9fe_1a85_ec53))?;
        self.code
            .emit(|e| e.mul(Gpr::x(3), Gpr::x(3), Gpr::x(12)))?;
        let shifted = arinsal_a64::enc::Shifted {
            reg: Gpr::x(3),
            shift: arinsal_a64::enc::Shift::Lsr,
            amount: 33,
        };
        self.code
            .emit(|e| e.eor_reg(Gpr::x(3), Gpr::x(3), shifted))?;
        Ok(())
    }

    // Port of erts/emulator/beam/jit/arm/instr_map.cpp:64-264, OTP-29.1.1.
    fn emit_hashmap_lookup(&mut self, fail: Label) -> Result<(), ModuleError> {
        let node_loop = self.code.new_label();
        let direct = self.code.new_label();
        let rank_loop = self.code.new_label();
        let rank_done = self.code.new_label();
        let nonroot = self.code.new_label();
        let base_ready = self.code.new_label();
        let leaf = self.code.new_label();
        let child_ready = self.code.new_label();
        let bitmap_miss = self.code.new_label();
        let key_miss = self.code.new_label();
        let level_miss = self.code.new_label();
        let collision = self.code.new_label();
        let collision_loop = self.code.new_label();
        let success = self.code.new_label();
        self.code.emit(|e| e.mov_reg(Gpr::x(11), Gpr::xzr()))?;
        self.code.bind(node_loop)?;
        self.code.emit(|e| e.and_imm(Gpr::x(12), Gpr::x(3), 15))?;
        self.code.emit(|e| e.lsr_imm(Gpr::x(3), Gpr::x(3), 4))?;
        self.code.emit(|e| e.and_imm(Gpr::x(13), Gpr::x(9), 0xc0))?;
        self.code.emit(|e| e.cmp_imm(Gpr::x(13), 0x80, false))?;
        self.code.b_cond(Cond::Eq, direct)?;
        self.code.emit(|e| e.lsr_imm(Gpr::x(13), Gpr::x(9), 16))?;
        self.code.emit(|e| e.mov_reg(Gpr::x(14), Gpr::x(13)))?;
        self.code
            .emit(|e| e.lsr_reg(Gpr::x(14), Gpr::x(14), Gpr::x(12)))?;
        self.code.tbz(Gpr::x(14), 0, bitmap_miss)?;
        self.code.emit(|e| e.mov_reg(Gpr::x(14), Gpr::xzr()))?;
        self.code.emit(|e| e.mov_reg(Gpr::x(10), Gpr::xzr()))?;
        self.code.bind(rank_loop)?;
        self.code
            .emit(|e| e.cmp_reg(Gpr::x(14), Gpr::x(12), arinsal_a64::enc::Shift::Lsl, 0))?;
        self.code.b_cond(Cond::Cs, rank_done)?;
        self.code.emit(|e| e.and_imm(Gpr::x(5), Gpr::x(13), 1))?;
        self.code.emit(|e| {
            e.add_reg(
                Gpr::x(10),
                Gpr::x(10),
                Gpr::x(5),
                arinsal_a64::enc::Shift::Lsl,
                0,
            )
        })?;
        self.code
            .emit(|e| e.add_imm(Gpr::x(14), Gpr::x(14), 1, false))?;
        self.code.emit(|e| e.lsr_imm(Gpr::x(13), Gpr::x(13), 1))?;
        self.code.b(rank_loop)?;
        self.code.bind(rank_done)?;
        self.code.emit(|e| e.mov_reg(Gpr::x(14), Gpr::x(10)))?;
        let rank = self.code.new_label();
        self.code.b(rank)?;
        self.code.bind(direct)?;
        self.code.emit(|e| e.mov_reg(Gpr::x(14), Gpr::x(12)))?;
        self.code.bind(rank)?;
        self.code.emit(|e| e.cmp_imm(Gpr::x(11), 0, false))?;
        self.code.b_cond(Cond::Ne, nonroot)?;
        self.code
            .emit(|e| e.add_imm(Gpr::x(13), Gpr::x(8), 16, false))?;
        self.code.b(base_ready)?;
        self.code.bind(nonroot)?;
        self.code
            .emit(|e| e.add_imm(Gpr::x(13), Gpr::x(8), 8, false))?;
        self.code.bind(base_ready)?;
        self.code
            .emit(|e| e.ldr_regoff(Gpr::x(8), Gpr::x(13), Gpr::x(14), 3))?;
        self.code.emit(|e| e.and_imm(Gpr::x(10), Gpr::x(8), 3))?;
        self.code.emit(|e| e.cmp_imm(Gpr::x(10), 1, false))?;
        self.code.b_cond(Cond::Eq, leaf)?;
        self.code.emit(|e| e.and_imm(Gpr::x(8), Gpr::x(8), !7))?;
        self.code.emit(|e| e.ldr_uoff(Gpr::x(9), Gpr::x(8), 0))?;
        self.code
            .emit(|e| e.add_imm(Gpr::x(11), Gpr::x(11), 1, false))?;
        self.code.emit(|e| e.cmp_imm(Gpr::x(11), 16, false))?;
        self.code.b_cond(Cond::Eq, collision)?;
        self.code.b_cond(Cond::Cs, level_miss)?;
        self.code.b(node_loop)?;
        self.code.bind(leaf)?;
        self.code.emit(|e| e.and_imm(Gpr::x(8), Gpr::x(8), !7))?;
        self.code
            .emit(|e| e.ldp(Gpr::x(10), Gpr::x(0), Gpr::x(8), 0))?;
        self.code
            .emit(|e| e.cmp_reg(Gpr::x(10), Gpr::x(2), arinsal_a64::enc::Shift::Lsl, 0))?;
        self.code.b_cond(Cond::Ne, key_miss)?;
        self.code.b(success)?;
        self.code.bind(collision)?;
        self.code.emit(|e| e.lsr_imm(Gpr::x(10), Gpr::x(9), 6))?;
        self.code.bind(collision_loop)?;
        self.code.emit(|e| e.cmp_imm(Gpr::x(10), 0, false))?;
        self.code.b_cond(Cond::Eq, key_miss)?;
        self.code
            .emit(|e| e.subs_imm(Gpr::x(10), Gpr::x(10), 1, false))?;
        self.code
            .emit(|e| e.add_imm(Gpr::x(13), Gpr::x(8), 8, false))?;
        self.code
            .emit(|e| e.ldr_regoff(Gpr::x(14), Gpr::x(13), Gpr::x(10), 3))?;
        self.code.emit(|e| e.and_imm(Gpr::x(14), Gpr::x(14), !7))?;
        self.code.emit(|e| e.ldr_uoff(Gpr::x(12), Gpr::x(14), 0))?;
        self.code
            .emit(|e| e.cmp_reg(Gpr::x(12), Gpr::x(2), arinsal_a64::enc::Shift::Lsl, 0))?;
        self.code.b_cond(Cond::Eq, success)?;
        self.code.emit(|e| e.cmp_imm(Gpr::x(10), 0, false))?;
        self.code.b_cond(Cond::Ne, collision_loop)?;
        self.code.b(key_miss)?;
        self.code.emit(|e| e.ldr_uoff(Gpr::x(0), Gpr::x(14), 8))?;
        self.code.b(success)?;
        self.code.bind(bitmap_miss)?;
        self.code.emit(|e| e.mov_const(Gpr::x(3), 1))?;
        self.code.b(fail)?;
        self.code.bind(key_miss)?;
        self.code.emit(|e| e.mov_const(Gpr::x(3), 2))?;
        self.code.b(fail)?;
        self.code.bind(level_miss)?;
        self.code.emit(|e| e.mov_const(Gpr::x(3), 3))?;
        self.code.b(fail)?;
        self.code.bind(success)?;
        self.code.bind(child_ready)?;
        Ok(())
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
    if args.len() > 5 {
        return Err(ModuleError::InvalidOperand(
            "runtime hook has too many arguments",
        ));
    }
    emit_enter_runtime(&mut asm.code, live, update)?;
    asm.code.emit(|e| {
        e.mov_reg(Gpr::x(0), Gpr::x(21))?;
        for (index, arg) in args.iter().copied().enumerate() {
            e.mov_reg(Gpr::x(index as u8 + 1), arg)?;
        }
        e.mov_const(Gpr::x(17), helper as u64)?;
        e.str_uoff(Gpr::x(30), Gpr::x(21), 72)?;
        e.blr(Gpr::x(17))
    })?;
    emit_leave_runtime(&mut asm.code, live, update)?;
    asm.code.emit(|e| {
        e.ldr_uoff(Gpr::x(30), Gpr::x(21), 72)?;
        e.ldr_uoff(Gpr::x(9), Gpr::x(21), 40)
    })?;
    asm.error_if_nonzero(Gpr::x(9))?;
    Ok(())
}
