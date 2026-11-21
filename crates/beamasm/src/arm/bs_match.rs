//! AArch64 emitters for BEAM bit syntax matching.
//!
//! Port of erts/emulator/beam/jit/arm/instr_bs.cpp and beam_jit_bs.cpp, OTP-29.1.1.

use super::beam_asm::{NUM_REGISTER_BACKED_XREGS, is_register_backed};
use crate::module::{ArgVal, BeamModuleAssembler, ModuleError};
use arinsal_a64::enc::{Cond, Gpr};
/// Words of a `SUB_BITS` object (erts/emulator/beam/erl_bits.h, ERL_SUB_BITS_SIZE).
const ERL_SUB_BITS_SIZE: u32 = 5;
/// Heap words for an extracted bitstring: a sub-bitstring, or an on-heap copy of at most
/// 64 bytes (erts/emulator/beam/erl_bits.h, BUILD_SUB_BITSTRING_HEAP_NEED).
const BUILD_SUB_BITSTRING_HEAP_NEED: u32 = 2 + 64 / 8;
/// Words of a boxed float (erts/emulator/beam/erl_term.h, FLOAT_SIZE_OBJECT).
const FLOAT_SIZE_OBJECT: u32 = 2;
const CTX: Gpr = Gpr::x(11);
const START: Gpr = Gpr::x(13);
const END: Gpr = Gpr::x(14);
const TMP: Gpr = Gpr::x(9);
/// Field size in bits; the context cursor loads may use `TMP` as scratch.
const FIELD_BITS: Gpr = Gpr::x(12);

/// Emits a direct `runtime_call<erts function>()` with the C ABI argument registers.
// Port of erts/emulator/beam/jit/arm/beam_asm.hpp (`runtime_call`), OTP-29.1.1.
pub(super) fn emit_bs_runtime_call(
    asm: &mut BeamModuleAssembler,
    target: usize,
    live: usize,
    update: crate::Update,
    args: &[Gpr],
) -> Result<(), ModuleError> {
    if args.len() > 8 {
        return Err(ModuleError::InvalidOperand(
            "too many bit-syntax runtime arguments",
        ));
    }
    crate::emit_enter_runtime(&mut asm.code, live, update)?;
    asm.code.emit(|e| {
        let mut copies = args
            .iter()
            .copied()
            .enumerate()
            .map(|(index, source)| (Gpr::x(index as u8), source))
            .filter(|(destination, source)| destination != source)
            .collect::<Vec<_>>();
        while !copies.is_empty() {
            if let Some(index) = copies.iter().position(|(destination, _)| {
                !copies.iter().any(|(_, source)| source == destination)
            }) {
                let (destination, source) = copies.remove(index);
                e.mov_reg(destination, source)?;
            } else {
                let saved = copies[0].0;
                e.mov_reg(Gpr::x(16), saved)?;
                for (_, source) in &mut copies {
                    if *source == saved {
                        *source = Gpr::x(16);
                    }
                }
            }
        }
        e.str_uoff(Gpr::x(30), Gpr::x(21), 72)?;
        e.mov_const(Gpr::x(17), target as u64)?;
        e.blr(Gpr::x(17))
    })?;
    crate::emit_leave_runtime(&mut asm.code, live, update)?;
    asm.code.emit(|e| e.ldr_uoff(Gpr::x(30), Gpr::x(21), 72))?;
    Ok(())
}

impl BeamModuleAssembler {
    /// Resolves a `bs_match` flags operand through the module's literal table.
    // Port of erts/emulator/beam/jit/beam_jit_bs.cpp:255-285 (bs_get_flags), OTP-29.1.1.
    pub fn bs_get_flags(&self, value: ArgVal) -> Result<u64, ModuleError> {
        crate::common::bs::beam_jit_bs_get_flags(value, &|index| self.beamfile_get_literal(index))
            .map_err(ModuleError::InvalidOperand)
    }

    /// Checks heap space for a match allocation while keeping the match context alive.
    ///
    /// The runtime call that follows allocates without collecting, so every allocating match
    /// instruction reserves its words here with the instruction's live count. A context outside
    /// the live prefix is parked in `X[live]` so that the collection updates it.
    // Port of erts/emulator/beam/jit/arm/beam_asm.hpp (emit_gc_test_preserve), OTP-29.1.1.
    pub fn emit_gc_test_preserve(
        &mut self,
        need: u32,
        live: u32,
        ctx: ArgVal,
    ) -> Result<(), ModuleError> {
        let index = match ctx {
            ArgVal::X(index) => index,
            _ => return self.emit_test_heap(need, live),
        };
        if index < live {
            return self.emit_test_heap(need, live);
        }
        let parked = ArgVal::X(live);
        let value = self.source_reg(ctx)?;
        self.store_x(parked, value)?;
        self.emit_test_heap(need, live + 1)?;
        let value = self.source_reg(parked)?;
        self.store_x(ctx, value)
    }

    fn store_x(&mut self, dst: ArgVal, src: Gpr) -> Result<(), ModuleError> {
        self.store_operand(dst, src)
    }

    fn cursor(&mut self, ctx: ArgVal) -> Result<(), ModuleError> {
        // `ldur` from the tagged pointer matches emit_i_bs_match (instr_bs.cpp:2956-2958):
        // the box tag is the displacement, so the two loads do not wait on the untag.
        let source = self.source_reg(ctx)?;
        self.code.emit(|e| {
            e.ldur(START, source, 14)?;
            e.ldur(END, source, 22)?;
            e.and_imm(CTX, source, !7)
        })?;
        Ok(())
    }

    /// Tagged match-context pointer. Cached X registers are already stable; other operands
    /// are copied to `CTX` so a later field read can address them with `ldur`/`stur`.
    fn tagged_context(&mut self, ctx: ArgVal) -> Result<Gpr, ModuleError> {
        let source = self.source_reg(ctx)?;
        if is_register_backed(ctx) || source == CTX {
            return Ok(source);
        }
        self.code.emit(|e| e.mov_reg(CTX, source))?;
        Ok(CTX)
    }

    fn fixed_integer_inline(
        &mut self,
        ctx: ArgVal,
        bits: u16,
        fail: u32,
        dst: ArgVal,
    ) -> Result<(), ModuleError> {
        let context = self.source_reg(ctx)?;
        self.code.emit(|e| {
            e.and_imm(CTX, context, !7)?;
            e.mov_const(Gpr::x(10), u64::from(bits))?;
            e.mov_const(Gpr::x(9), 0)
        })?;
        emit_bs_runtime_call(
            self,
            crate::raw::erts_bs_get_integer_2 as *const () as usize,
            0,
            crate::Update::NONE,
            &[Gpr::x(21), Gpr::x(10), Gpr::x(9), CTX],
        )?;
        if fail != 0 {
            let fail = self.label(fail);
            self.code.cbz(Gpr::x(0), fail)?;
        }
        self.store_register(dst, Gpr::x(0))
    }

    /// Creates or reuses a `SUB_BITS` match context.
    // Port of erts/emulator/beam/jit/arm/instr_bs.cpp:134-190, OTP-29.1.1.
    pub fn emit_i_bs_start_match3(
        &mut self,
        src: ArgVal,
        live: u32,
        fail: u32,
        dst: ArgVal,
    ) -> Result<(), ModuleError> {
        let next = self.code.new_label();
        let hit = self.code.new_label();
        let src_reg = self.source_reg_into(src, Gpr::x(8))?;
        self.code.emit(|e| e.mov_reg(Gpr::x(8), src_reg))?;
        if fail != 0 {
            let fail_label = self.label(fail);
            self.code.tbnz(Gpr::x(8), 0, fail_label)?;
        }
        self.code.emit(|e| {
            e.and_imm(CTX, Gpr::x(8), !7)?;
            e.ldp(Gpr::x(10), Gpr::x(12), CTX, 0)?;
            // Insert the sub-bits flags into the header and compare with a match context.
            e.bfi(Gpr::x(10), Gpr::x(12), 0, 2)?;
            e.cmp_imm(Gpr::x(10), (4 << 6) | 0x24 | 1, false)
        })?;
        self.code.b_cond(Cond::Eq, hit)?;
        if fail != 0 {
            let fail_label = self.label(fail);
            self.code.emit(|e| {
                e.and_imm(Gpr::x(9), Gpr::x(10), 0x38)?;
                e.cmp_imm(Gpr::x(9), 0x20, false)
            })?;
            self.code.b_cond(Cond::Ne, fail_label)?;
        }
        // erts delegates construction of all fresh contexts to its ErlBits implementation.
        // Port of erts/emulator/beam/jit/arm/instr_bs.cpp:134-190.
        self.emit_gc_test_preserve(ERL_SUB_BITS_SIZE, live, src)?;
        let src_reg = self.source_reg_into(src, Gpr::x(8))?;
        self.code.emit(|e| e.mov_reg(Gpr::x(8), src_reg))?;
        emit_bs_runtime_call(
            self,
            crate::raw::erts_bs_start_match_3 as *const () as usize,
            live as usize,
            crate::Update::HEAP,
            &[Gpr::x(21), Gpr::x(8)],
        )?;
        self.code
            .emit(|e| e.add_imm(Gpr::x(0), Gpr::x(0), 2, false))?;
        self.store_register(dst, Gpr::x(0))?;
        self.code.b(next)?;
        self.code.bind(hit)?;
        self.store_register(dst, Gpr::x(8))?;
        self.code.bind(next)?;
        Ok(())
    }

    /// Reads the current bit position into a destination term.
    // Port of erts/emulator/beam/jit/arm/instr_bs.cpp:236-255, OTP-29.1.1.
    pub fn emit_i_bs_get_position(&mut self, ctx: ArgVal, dst: ArgVal) -> Result<(), ModuleError> {
        // One unscaled load of `start`. The position is tagged in a temporary so the
        // cursor registers stay available to the next command.
        // Port of instr_bs.cpp:244-252, OTP-29.1.1.
        let source = self.source_reg(ctx)?;
        self.code.emit(|e| {
            e.ldur(Gpr::x(10), source, 14)?;
            e.lsl_imm(Gpr::x(10), Gpr::x(10), 4)?;
            e.orr_imm(Gpr::x(10), Gpr::x(10), 0xf)
        })?;
        self.store_register(dst, Gpr::x(10))
    }

    /// Restores a saved match position.
    // Port of erts/emulator/beam/jit/arm/instr_bs.cpp:371-384, OTP-29.1.1.
    pub fn emit_i_bs_set_position(&mut self, ctx: ArgVal, pos: ArgVal) -> Result<(), ModuleError> {
        let pos_reg = self.source_reg_into(pos, Gpr::x(8))?;
        self.code.emit(|e| e.mov_reg(Gpr::x(8), pos_reg))?;
        self.cursor(ctx)?;
        self.code.emit(|e| e.lsr_imm(Gpr::x(8), Gpr::x(8), 4))?;
        self.code.emit(|e| e.str_uoff(Gpr::x(8), CTX, 16))?;
        Ok(())
    }

    /// Tests that exactly the requested number of bits remain.
    // Port of erts/emulator/beam/jit/arm/instr_bs.cpp:360-369, OTP-29.1.1.
    pub fn emit_bs_test_tail2(
        &mut self,
        ctx: ArgVal,
        bits: ArgVal,
        fail: u32,
    ) -> Result<(), ModuleError> {
        self.cursor(ctx)?;
        self.code.emit(|e| e.ldr_uoff(Gpr::x(10), CTX, 8))?;
        let bits = self.source_reg(bits)?;
        let label = self.label(fail);
        self.code.emit(|e| {
            e.mov_reg(Gpr::x(10), bits)?;
            e.lsr_imm(Gpr::x(10), Gpr::x(10), 4)?;
            e.sub_reg(TMP, END, START, arinsal_a64::enc::Shift::Lsl, 0)?;
            e.cmp_reg(TMP, Gpr::x(10), arinsal_a64::enc::Shift::Lsl, 0)
        })?;
        self.code.b_cond(Cond::Ne, label)?;
        Ok(())
    }

    /// Tests the remaining bit count against a unit.
    // Port of erts/emulator/beam/jit/arm/instr_bs.cpp:360-369, OTP-29.1.1.
    pub fn emit_bs_test_unit(
        &mut self,
        ctx: ArgVal,
        unit: u32,
        fail: u32,
    ) -> Result<(), ModuleError> {
        self.cursor(ctx)?;
        let label = self.label(fail);
        self.code.emit(|e| {
            e.sub_reg(TMP, END, START, arinsal_a64::enc::Shift::Lsl, 0)?;
            e.mov_const(Gpr::x(10), u64::from(unit))?;
            e.udiv(Gpr::x(8), TMP, Gpr::x(10))?;
            e.msub(Gpr::x(8), Gpr::x(8), Gpr::x(10), TMP)?;
            e.cmp_imm(Gpr::x(8), 0, false)
        })?;
        self.code.b_cond(Cond::Ne, label)?;
        Ok(())
    }

    /// Advances the context by a fixed bit count, branching on underflow.
    // Port of erts/emulator/beam/jit/arm/instr_bs.cpp:457-505, OTP-29.1.1.
    pub fn emit_i_bs_skip_bits2(
        &mut self,
        ctx: ArgVal,
        bits: ArgVal,
        unit: u32,
        fail: u32,
    ) -> Result<(), ModuleError> {
        let label = self.label(fail);
        if !self.emit_bs_field_size(bits, unit, label)? {
            return Ok(());
        }
        // Port of instr_bs.cpp:466-472: add the bit count and store through the tagged pointer.
        let tagged = self.tagged_context(ctx)?;
        self.code.emit(|e| {
            e.ldur(START, tagged, 14)?;
            e.ldur(END, tagged, 22)?;
            e.add_reg(START, START, FIELD_BITS, arinsal_a64::enc::Shift::Lsl, 0)?;
            e.cmp_reg(START, END, arinsal_a64::enc::Shift::Lsl, 0)
        })?;
        self.code.b_cond(Cond::Hi, label)?;
        self.code.emit(|e| e.stur(START, tagged, 14))?;
        Ok(())
    }

    /// Computes `Size * Unit` bits into `FIELD_BITS`, branching to `fail` unless `Size` is a
    /// non-negative small whose product cannot overflow. Returns false when the size is a
    /// constant that always fails, after emitting the branch.
    // Port of erts/emulator/beam/jit/arm/instr_bs.cpp:38-115 (emit_bs_get_field_size),
    // OTP-29.1.1.
    fn emit_bs_field_size(
        &mut self,
        size: ArgVal,
        unit: u32,
        fail: arinsal_a64::buf::Label,
    ) -> Result<bool, ModuleError> {
        const MAX_SMALL: i64 = (1 << 59) - 1;
        if let Some(word) = self.constant_word(size) {
            let value = (word & 0xf == 0xf).then_some(word as i64 >> 4);
            match value {
                Some(value)
                    if value >= 0 && (unit == 0 || value <= MAX_SMALL / i64::from(unit)) =>
                {
                    let bits = value as u64 * u64::from(unit);
                    self.code.emit(|e| e.mov_const(FIELD_BITS, bits))?;
                    Ok(true)
                }
                _ => {
                    self.code.b(fail)?;
                    Ok(false)
                }
            }
        } else {
            let source = self.source_reg(size)?;
            self.code.emit(|e| {
                // Negating the tag bits guards against non-smalls, negative sizes and
                // overflow with one test.
                e.eor_imm(FIELD_BITS, source, 0xf)?;
                e.tst_imm(FIELD_BITS, 0xfff0_0000_0000_000f)?;
                if unit == 0 {
                    e.mov_const(FIELD_BITS, 0)?;
                } else if unit.is_power_of_two() {
                    let trailing = unit.trailing_zeros() as u8;
                    if trailing < 4 {
                        e.lsr_imm(FIELD_BITS, FIELD_BITS, 4 - trailing)?;
                    } else if trailing > 4 {
                        e.lsl_imm(FIELD_BITS, FIELD_BITS, trailing - 4)?;
                    }
                } else {
                    e.lsr_imm(FIELD_BITS, FIELD_BITS, 4)?;
                    e.mov_const(Gpr::x(10), u64::from(unit))?;
                    e.mul(FIELD_BITS, FIELD_BITS, Gpr::x(10))?;
                }
                Ok(())
            })?;
            self.code.b_cond(Cond::Ne, fail)?;
            Ok(true)
        }
    }

    /// Inline aligned 8-bit integer extraction fast path.
    // Port of erts/emulator/beam/jit/arm/instr_bs.cpp:257-311, OTP-29.1.1.
    pub fn emit_i_bs_get_integer_8(
        &mut self,
        ctx: ArgVal,
        fail: u32,
        dst: ArgVal,
    ) -> Result<(), ModuleError> {
        self.fixed_integer_inline(ctx, 8, fail, dst)
    }
    /// Inline aligned 16-bit integer extraction fast path.
    // Port of erts/emulator/beam/jit/arm/instr_bs.cpp:257-311, OTP-29.1.1.
    pub fn emit_i_bs_get_integer_16(
        &mut self,
        ctx: ArgVal,
        fail: u32,
        dst: ArgVal,
    ) -> Result<(), ModuleError> {
        self.fixed_integer_inline(ctx, 16, fail, dst)
    }
    /// Inline aligned 32-bit integer extraction fast path.
    // Port of erts/emulator/beam/jit/arm/instr_bs.cpp:257-311, OTP-29.1.1.
    pub fn emit_i_bs_get_integer_32(
        &mut self,
        ctx: ArgVal,
        fail: u32,
        dst: ArgVal,
    ) -> Result<(), ModuleError> {
        self.fixed_integer_inline(ctx, 32, fail, dst)
    }
    /// Extracts a general sized integer field.
    // Port of erts/emulator/beam/jit/arm/instr_bs.cpp:312-359, OTP-29.1.1.
    pub fn emit_i_bs_get_integer(
        &mut self,
        ctx: ArgVal,
        fail: u32,
        bits: ArgVal,
        unit: u32,
        dst: ArgVal,
    ) -> Result<(), ModuleError> {
        let fail_label = self.label(fail);
        if !self.emit_bs_field_size(bits, unit, fail_label)? {
            return Ok(());
        }
        let context = self.source_reg_into(ctx, Gpr::x(9))?;
        self.code.emit(|e| e.and_imm(CTX, context, !7))?;
        emit_bs_runtime_call(
            self,
            crate::raw::erts_bs_get_integer_2 as *const () as usize,
            0,
            crate::Update::HEAP,
            &[Gpr::x(21), FIELD_BITS, Gpr::xzr(), CTX],
        )?;
        self.code.cbz(Gpr::x(0), fail_label)?;
        self.store_register(dst, Gpr::x(0))
    }

    /// Emits `bs_get_integer2` with the same small and allocating calls as erts.
    // Port of erts/emulator/beam/jit/arm/instr_bs.cpp:330-377, OTP-29.1.1.
    #[allow(clippy::too_many_arguments)]
    pub fn emit_bs_get_integer2(
        &mut self,
        ctx: ArgVal,
        fail: u32,
        live: u32,
        size: ArgVal,
        unit: u32,
        mut flags: u64,
        dst: ArgVal,
    ) -> Result<(), ModuleError> {
        const BSF_NATIVE: u64 = 16;
        const BSF_LITTLE: u64 = 2;
        if flags & BSF_NATIVE != 0 {
            flags &= !BSF_NATIVE;
            flags |= BSF_LITTLE;
        }
        let fail = self.label(fail);
        if !self.emit_bs_field_size(size, unit, fail)? {
            return Ok(());
        }
        let is_static_small = self
            .constant_word(size)
            .filter(|word| word & 0xf == 0xf)
            .map(|word| (word as i64) >> 4)
            .is_some_and(|size| {
                (0..64).contains(&size) && (size as u64).saturating_mul(u64::from(unit)) < 64
            });
        if is_static_small {
            let context = self.source_reg(ctx)?;
            self.code.emit(|e| {
                e.and_imm(CTX, context, !7)?;
                e.mov_const(Gpr::x(10), flags)
            })?;
            emit_bs_runtime_call(
                self,
                crate::raw::erts_bs_get_integer_2 as *const () as usize,
                live as usize,
                crate::Update::NONE,
                &[Gpr::x(21), FIELD_BITS, Gpr::x(10), CTX],
            )?;
            self.code.cbz(Gpr::x(0), fail)?;
        } else {
            let context = self.source_reg(ctx)?;
            self.code.emit(|e| {
                if context != Gpr::x(9) {
                    e.mov_reg(Gpr::x(9), context)?;
                }
                crate::arm::beam_asm::load_x_reg_array(e, Gpr::x(8))?;
                e.mov_const(Gpr::x(10), flags)?;
                e.mov_const(Gpr::x(11), u64::from(live))?;
                Ok(())
            })?;
            emit_bs_runtime_call(
                self,
                crate::raw::beam_jit_bs_get_integer as *const () as usize,
                live as usize,
                crate::Update::HEAP_ALLOC
                    .union(crate::Update::X_REGS)
                    .union(crate::Update::REDUCTIONS),
                &[
                    Gpr::x(21),
                    Gpr::x(8),
                    Gpr::x(9),
                    Gpr::x(10),
                    FIELD_BITS,
                    Gpr::x(11),
                ],
            )?;
            self.code.cbz(Gpr::x(0), fail)?;
        }
        self.store_register(dst, Gpr::x(0))
    }
    /// Extracts a bitstring sub-binary with a unit constraint.
    // Port of erts/emulator/beam/jit/arm/instr_bs.cpp:506-577, OTP-29.1.1.
    #[allow(clippy::too_many_arguments)]
    pub fn emit_i_bs_get_binary2(
        &mut self,
        ctx: ArgVal,
        fail: u32,
        live: u32,
        bits: ArgVal,
        unit: u32,
        dst: ArgVal,
    ) -> Result<(), ModuleError> {
        let fail_label = self.label(fail);
        if !self.emit_bs_field_size(bits, unit, fail_label)? {
            return Ok(());
        }
        self.emit_gc_test_preserve(BUILD_SUB_BITSTRING_HEAP_NEED, live, ctx)?;
        let context = self.source_reg(ctx)?;
        self.code.emit(|e| e.and_imm(CTX, context, !7))?;
        self.emit_bs_field_size(bits, unit, fail_label)?;
        emit_bs_runtime_call(
            self,
            crate::raw::erts_bs_get_binary_2 as *const () as usize,
            live as usize,
            crate::Update::HEAP,
            &[Gpr::x(21), FIELD_BITS, CTX],
        )?;
        self.code.cbz(Gpr::x(0), fail_label)?;
        self.store_register(dst, Gpr::x(0))
    }
    /// Extracts all remaining bits as a sub-binary.
    // Port of erts/emulator/beam/jit/arm/instr_bs.cpp:386-405, OTP-29.1.1.
    pub fn emit_i_bs_get_binary_all2(
        &mut self,
        ctx: ArgVal,
        fail: u32,
        live: u32,
        unit: u32,
        dst: ArgVal,
    ) -> Result<(), ModuleError> {
        let fail_label = self.label(fail);
        let context = self.source_reg(ctx)?;
        self.code.emit(|e| {
            e.and_imm(CTX, context, !7)?;
            e.ldp(START, END, CTX, 16)?;
            e.sub_reg(FIELD_BITS, END, START, arinsal_a64::enc::Shift::Lsl, 0)
        })?;
        if unit != 1 {
            self.code.emit(|e| {
                e.mov_const(Gpr::x(10), u64::from(unit))?;
                e.udiv(Gpr::x(9), FIELD_BITS, Gpr::x(10))?;
                e.msub(Gpr::x(9), Gpr::x(9), Gpr::x(10), FIELD_BITS)?;
                e.cmp_imm(Gpr::x(9), 0, false)
            })?;
            self.code.b_cond(Cond::Ne, fail_label)?;
        }
        self.emit_gc_test_preserve(BUILD_SUB_BITSTRING_HEAP_NEED, live, ctx)?;
        let context = self.source_reg(ctx)?;
        self.code.emit(|e| {
            e.and_imm(CTX, context, !7)?;
            e.ldp(START, END, CTX, 16)?;
            e.sub_reg(FIELD_BITS, END, START, arinsal_a64::enc::Shift::Lsl, 0)
        })?;
        emit_bs_runtime_call(
            self,
            crate::raw::erts_bs_get_binary_2 as *const () as usize,
            live as usize,
            crate::Update::HEAP,
            &[Gpr::x(21), FIELD_BITS, CTX],
        )?;
        self.code.cbz(Gpr::x(0), fail_label)?;
        self.store_register(dst, Gpr::x(0))
    }
    /// Compares fixed bits against a module string constant.
    // Port of erts/emulator/beam/jit/arm/instr_bs.cpp:191-234, OTP-29.1.1.
    pub fn emit_i_bs_match_string(
        &mut self,
        ctx: ArgVal,
        fail: u32,
        bits: u64,
        string: ArgVal,
    ) -> Result<(), ModuleError> {
        let fail_label = self.label(fail);
        let context = self.source_reg(ctx)?;
        let pointer = self.source_reg(string)?;
        self.code.emit(|e| {
            // erts keeps the match-context pointer in TMP5 while TMP4 holds `start + size`.
            // CTX is x11/TMP4 here, so using it for both would lose the context before the
            // base-field load below.
            e.and_imm(Gpr::x(12), context, !7)?;
            e.ldp(START, END, Gpr::x(12), 16)?;
            e.mov_const(Gpr::x(10), bits)?;
            e.add_reg(CTX, START, Gpr::x(10), arinsal_a64::enc::Shift::Lsl, 0)?;
            e.cmp_reg(CTX, END, arinsal_a64::enc::Shift::Lsl, 0)
        })?;
        self.code.b_cond(Cond::Hi, fail_label)?;
        self.code.emit(|e| {
            e.ldr_uoff(Gpr::x(12), Gpr::x(12), 8)?;
            e.and_imm(Gpr::x(12), Gpr::x(12), !3)?;
            e.and_imm(Gpr::x(14), START, 7)?;
            e.add_reg(
                Gpr::x(13),
                Gpr::x(12),
                START,
                arinsal_a64::enc::Shift::Lsr,
                3,
            )
        })?;
        emit_bs_runtime_call(
            self,
            crate::raw::erts_cmp_bits as *const () as usize,
            NUM_REGISTER_BACKED_XREGS as usize,
            crate::Update::NONE,
            &[pointer, Gpr::xzr(), Gpr::x(13), Gpr::x(14), Gpr::x(10)],
        )?;
        self.code.cbnz(Gpr::x(0), fail_label)?;
        let context = self.source_reg(ctx)?;
        self.code.emit(|e| {
            e.and_imm(CTX, context, !7)?;
            e.ldr_uoff(START, CTX, 16)?;
            e.mov_const(Gpr::x(10), bits)?;
            e.add_reg(START, START, Gpr::x(10), arinsal_a64::enc::Shift::Lsl, 0)?;
            e.str_uoff(START, CTX, 16)
        })?;
        Ok(())
    }
    /// Builds a sub-bitstring from the current cursor to the context end.
    // Port of erts/emulator/beam/jit/arm/instr_bs.cpp:407-455, OTP-29.1.1.
    pub fn emit_bs_get_tail(
        &mut self,
        ctx: ArgVal,
        dst: ArgVal,
        live: u32,
    ) -> Result<(), ModuleError> {
        self.emit_gc_test_preserve(BUILD_SUB_BITSTRING_HEAP_NEED, live, ctx)?;
        self.emit_bs_build_sub_bitstring(ctx, Some(dst), live, None)
    }

    /// Builds an extracted or tail bitstring using the common erts allocation function.
    // Port of erts/emulator/beam/jit/arm/instr_bs.cpp:407-455 and 3129-3172, OTP-29.1.1.
    pub(super) fn emit_bs_build_sub_bitstring(
        &mut self,
        ctx: ArgVal,
        dst: Option<ArgVal>,
        live: u32,
        size: Option<u64>,
    ) -> Result<(), ModuleError> {
        let context = self.source_reg(ctx)?;
        self.code.emit(|e| {
            e.and_imm(CTX, context, !7)?;
            e.ldr_uoff(Gpr::x(9), CTX, 8)?;
            e.ldr_uoff(Gpr::x(10), CTX, 32)?;
            e.ldp(START, END, CTX, 16)?;
            e.and_imm(Gpr::x(9), Gpr::x(9), !3)?;
            if let Some(size) = size {
                e.mov_const(Gpr::x(12), size)?;
                e.add_reg(END, START, Gpr::x(12), arinsal_a64::enc::Shift::Lsl, 0)?;
                e.str_uoff(END, CTX, 16)?;
            } else {
                e.sub_reg(Gpr::x(12), END, START, arinsal_a64::enc::Shift::Lsl, 0)?;
            }
            // Keep CTX live through the cursor update. In the erts sequence, the
            // match-context pointer is consumed before ARG2 is reused for its tag.
            e.and_imm(Gpr::x(11), Gpr::x(10), 3)?;
            e.and_imm(Gpr::x(10), Gpr::x(10), !3)?;
            Ok(())
        })?;
        // Port of instr_bs.cpp:407-436: the shared tail fragment establishes the runtime frame
        // before `emit_enter_runtime`, so stack walking sees the C call as a native frame.
        self.code.emit(|e| {
            e.stp_pre(Gpr::x(29), Gpr::x(30), Gpr::sp(), -16)?;
            e.mov_reg(Gpr::x(29), Gpr::sp())
        })?;
        emit_bs_runtime_call(
            self,
            crate::raw::erts_build_sub_bitstring as *const () as usize,
            live as usize,
            crate::Update::HEAP,
            &[
                Gpr::x(21),
                Gpr::x(11),
                Gpr::x(10),
                Gpr::x(9),
                START,
                Gpr::x(12),
            ],
        )?;
        self.code.emit(|e| {
            e.mov_reg(Gpr::sp(), Gpr::x(29))?;
            e.ldp_post(Gpr::x(29), Gpr::x(30), Gpr::sp(), 16)
        })?;
        if let Some(dst) = dst {
            self.store_register(dst, Gpr::x(0))?;
        }
        Ok(())
    }
    /// Extracts and validates one UTF-8 scalar.
    // Port of erts/emulator/beam/jit/arm/instr_bs.cpp:712-899, OTP-29.1.1.
    pub fn emit_i_bs_get_utf8(
        &mut self,
        ctx: ArgVal,
        fail: u32,
        dst: ArgVal,
    ) -> Result<(), ModuleError> {
        self.emit_bs_get_utf8(ctx, fail, Some(dst))
    }
    /// Skips one UTF-8 scalar, failing on malformed input.
    // Port of erts/emulator/beam/jit/arm/instr_bs.cpp:900-903, OTP-29.1.1.
    pub fn emit_i_bs_skip_utf8(&mut self, ctx: ArgVal, fail: u32) -> Result<(), ModuleError> {
        self.emit_bs_get_utf8(ctx, fail, None)
    }
    /// Skips one UTF-16 scalar, failing on malformed input.
    // Port of erts/emulator/beam/jit/arm/instr_bs.cpp:930-934, OTP-29.1.1.
    pub fn emit_i_bs_skip_utf16(
        &mut self,
        ctx: ArgVal,
        fail: u32,
        flags: ArgVal,
    ) -> Result<(), ModuleError> {
        self.emit_bs_get_utf16(ctx, fail, flags, None)
    }
    /// Rejects a 32-bit value that is not a Unicode scalar and un-reads its 32 bits.
    // Port of erts/emulator/beam/jit/arm/instr_bs.cpp:935-984
    // (emit_validate_unicode, emit_i_bs_validate_unicode_retract), OTP-29.1.1.
    pub fn emit_i_bs_validate_unicode_retract(
        &mut self,
        fail: u32,
        src: ArgVal,
        ctx: ArgVal,
    ) -> Result<(), ModuleError> {
        let next = self.code.new_label();
        let failing = self.code.new_label();
        let value = self.source_reg_into(src, Gpr::x(10))?;
        let small = |code_point: u64| (code_point << 4) | 0xf;
        self.code.emit(|e| {
            e.and_imm(Gpr::x(12), value, 0xf)?;
            e.cmp_imm(Gpr::x(12), 0xf, false)
        })?;
        self.code.b_cond(Cond::Ne, failing)?;
        self.code.emit(|e| e.mov_const(Gpr::x(12), small(0xD800)))?;
        self.code
            .emit(|e| e.cmp_reg(value, Gpr::x(12), arinsal_a64::enc::Shift::Lsl, 0))?;
        self.code.b_cond(Cond::Cc, next)?;
        self.code.emit(|e| e.mov_const(Gpr::x(12), small(0xDFFF)))?;
        self.code
            .emit(|e| e.cmp_reg(value, Gpr::x(12), arinsal_a64::enc::Shift::Lsl, 0))?;
        self.code.b_cond(Cond::Ls, failing)?;
        self.code
            .emit(|e| e.mov_const(Gpr::x(12), small(0x10FFFF)))?;
        self.code
            .emit(|e| e.cmp_reg(value, Gpr::x(12), arinsal_a64::enc::Shift::Lsl, 0))?;
        self.code.b_cond(Cond::Hi, failing)?;
        self.code.b(next)?;
        self.code.bind(failing)?;
        let ctx = self.source_reg_into(ctx, Gpr::x(10))?;
        self.code.emit(|e| {
            e.and_imm(Gpr::x(10), ctx, !7)?;
            e.ldr_uoff(Gpr::x(12), Gpr::x(10), 16)?;
            e.sub_imm(Gpr::x(12), Gpr::x(12), 32, false)?;
            e.str_uoff(Gpr::x(12), Gpr::x(10), 16)
        })?;
        let fail = self.label(fail);
        self.code.b(fail)?;
        self.code.bind(next)?;
        Ok(())
    }
    /// Extracts and validates one UTF-16 scalar.
    // Port of erts/emulator/beam/jit/arm/instr_bs.cpp:905-929, OTP-29.1.1.
    pub fn emit_i_bs_get_utf16(
        &mut self,
        ctx: ArgVal,
        fail: u32,
        flags: ArgVal,
        dst: ArgVal,
    ) -> Result<(), ModuleError> {
        self.emit_bs_get_utf16(ctx, fail, flags, Some(dst))
    }
    /// Extracts an IEEE binary16, binary32, or binary64 value.
    // Port of erts/emulator/beam/jit/arm/instr_bs.cpp:578-617, OTP-29.1.1.
    #[allow(clippy::too_many_arguments)]
    pub fn emit_i_bs_get_float2(
        &mut self,
        ctx: ArgVal,
        fail: u32,
        live: u32,
        bits: ArgVal,
        flags: u32,
        dst: ArgVal,
    ) -> Result<(), ModuleError> {
        let fail_label = self.label(fail);
        self.emit_gc_test_preserve(FLOAT_SIZE_OBJECT, live, ctx)?;
        if !self.emit_bs_field_size(bits, flags >> 3, fail_label)? {
            return Ok(());
        }
        self.code
            .emit(|e| e.mov_const(Gpr::x(10), u64::from(flags)))?;
        let context = self.source_reg(ctx)?;
        self.code.emit(|e| e.and_imm(CTX, context, !7))?;
        emit_bs_runtime_call(
            self,
            crate::raw::erts_bs_get_float_2 as *const () as usize,
            live as usize,
            crate::Update::HEAP,
            &[Gpr::x(21), FIELD_BITS, Gpr::x(10), CTX],
        )?;
        self.code.cbz(Gpr::x(0), fail_label)?;
        self.store_register(dst, Gpr::x(0))
    }

    fn emit_bs_get_utf8(
        &mut self,
        ctx: ArgVal,
        fail: u32,
        dst: Option<ArgVal>,
    ) -> Result<(), ModuleError> {
        let context = self.source_reg_into(ctx, Gpr::x(9))?;
        self.code.emit(|e| e.and_imm(CTX, context, !7))?;
        emit_bs_runtime_call(
            self,
            crate::raw::erts_bs_get_utf8 as *const () as usize,
            NUM_REGISTER_BACKED_XREGS as usize,
            crate::Update::NONE,
            &[CTX],
        )?;
        let fail = self.label(fail);
        self.code.cbz(Gpr::x(0), fail)?;
        if let Some(dst) = dst {
            self.store_register(dst, Gpr::x(0))?;
        }
        Ok(())
    }

    fn emit_bs_get_utf16(
        &mut self,
        ctx: ArgVal,
        fail: u32,
        flags: ArgVal,
        dst: Option<ArgVal>,
    ) -> Result<(), ModuleError> {
        let context = self.source_reg_into(ctx, Gpr::x(9))?;
        let flags = self.source_reg_into(flags, Gpr::x(10))?;
        self.code.emit(|e| e.and_imm(CTX, context, !7))?;
        emit_bs_runtime_call(
            self,
            crate::raw::erts_bs_get_utf16 as *const () as usize,
            NUM_REGISTER_BACKED_XREGS as usize,
            crate::Update::NONE,
            &[CTX, flags],
        )?;
        let fail = self.label(fail);
        self.code.cbz(Gpr::x(0), fail)?;
        if let Some(dst) = dst {
            self.store_register(dst, Gpr::x(0))?;
        }
        Ok(())
    }
}
