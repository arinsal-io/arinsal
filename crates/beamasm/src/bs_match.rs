//! AArch64 emitters for BEAM bit syntax matching.

use crate::module::{ArgVal, BeamModuleAssembler, ModuleError};
use arinsal_a64::enc::{Cond, Gpr};

/// Runtime slow path for operations that allocate a term or decode variable-width fields.
pub type BsMatchHelper = extern "C" fn(*mut crate::ProcessHeader, u32, u64, u64, u64) -> u64;
/// Runtime hook for the `bs_match` commands that decode fields (integer, binary, tail, `=:=`).
/// Arguments: the command kind, then the live X register count; the operands are staged in
/// [`crate::SchedulerRegisters::match_staging`]. Zero means the match failed.
pub type BsMatchCmdHelper = extern "C" fn(*mut crate::ProcessHeader, u64, u64) -> u64;
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

impl BeamModuleAssembler {
    /// Runs one field-decoding `bs_match` command through the runtime.
    ///
    /// `staged` holds the match context and the command's operands as terms; the collector
    /// sees them as roots. A zero result branches to `fail`; a pending exception propagates.
    // Port of erts/emulator/beam/jit/arm/instr_bs.cpp:2910-3210 (emit_i_bs_match_test_heap), OTP-29.1.1.
    pub fn emit_bs_match_command(
        &mut self,
        kind: u32,
        live: u32,
        staged: &[ArgVal],
        fail: u32,
        dst: Option<ArgVal>,
        helper: BsMatchCmdHelper,
    ) -> Result<(), ModuleError> {
        let staging = std::mem::offset_of!(crate::SchedulerRegisters, match_staging) as u32;
        for (index, operand) in staged.iter().copied().enumerate() {
            let register = self.source_reg(operand)?;
            let offset = staging + index as u32 * 8;
            self.code
                .emit(|e| e.str_uoff(register, Gpr::x(19), offset))?;
        }
        let update = crate::Update::HEAP_ALLOC
            .union(crate::Update::X_REGS)
            .union(crate::Update::REDUCTIONS);
        crate::emit_enter_runtime(&mut self.code, 6, update)?;
        self.code.emit(|e| {
            e.mov_reg(Gpr::x(0), Gpr::x(21))?;
            e.mov_const(Gpr::x(1), u64::from(kind))?;
            e.mov_const(Gpr::x(2), u64::from(live))?;
            e.mov_const(Gpr::x(17), helper as usize as u64)?;
            e.str_uoff(Gpr::x(30), Gpr::x(21), 72)?;
            e.blr(Gpr::x(17))
        })?;
        crate::emit_leave_runtime(&mut self.code, 6, update)?;
        self.code.emit(|e| {
            e.ldr_uoff(Gpr::x(30), Gpr::x(21), 72)?;
            e.ldr_uoff(Gpr::x(9), Gpr::x(21), 40)
        })?;
        self.error_if_nonzero(Gpr::x(9))?;
        let fail = self.label(fail);
        self.code.cbz(Gpr::x(0), fail)?;
        if let Some(dst) = dst {
            self.store_register(dst, Gpr::x(0))?;
        }
        Ok(())
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
        hook: crate::construct::GcHook,
    ) -> Result<(), ModuleError> {
        let index = match ctx {
            ArgVal::X(index) => u32::from(index),
            ArgVal::XMemory(index) => index,
            _ => return self.emit_test_heap(need, live, hook),
        };
        if index < live {
            return self.emit_test_heap(need, live, hook);
        }
        let parked = if live < 6 {
            ArgVal::X(live as u8)
        } else {
            ArgVal::XMemory(live)
        };
        let value = self.source_reg(ctx)?;
        self.store_x(parked, value)?;
        self.emit_test_heap(need, live + 1, hook)?;
        let value = self.source_reg(parked)?;
        self.store_x(ctx, value)
    }

    fn store_x(&mut self, dst: ArgVal, src: Gpr) -> Result<(), ModuleError> {
        self.store_operand(dst, src)
    }

    fn emit_bs_runtime_hook(
        &mut self,
        helper: usize,
        args: &[Gpr],
        live: usize,
        update: crate::Update,
    ) -> Result<(), ModuleError> {
        if args.len() > 5 {
            return Err(ModuleError::InvalidOperand(
                "runtime hook has too many arguments",
            ));
        }
        crate::emit_enter_runtime(&mut self.code, live, update)?;
        self.code.emit(|e| {
            e.mov_reg(Gpr::x(0), Gpr::x(21))?;
            for (index, arg) in args.iter().copied().enumerate() {
                e.mov_reg(Gpr::x(index as u8 + 1), arg)?;
            }
            e.mov_const(Gpr::x(17), helper as u64)?;
            e.str_uoff(Gpr::x(30), Gpr::x(21), 72)?;
            e.blr(Gpr::x(17))
        })?;
        crate::emit_leave_runtime(&mut self.code, live, update)?;
        self.code.emit(|e| {
            e.ldr_uoff(Gpr::x(30), Gpr::x(21), 72)?;
            e.ldr_uoff(Gpr::x(9), Gpr::x(21), 40)
        })?;
        self.error_if_nonzero(Gpr::x(9))?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn emit_bs_helper(
        &mut self,
        op: u32,
        ctx: ArgVal,
        size: ArgVal,
        unit: u32,
        dst: Option<ArgVal>,
        fail: Option<u32>,
        helper: BsMatchHelper,
    ) -> Result<(), ModuleError> {
        let ctx = self.source_reg(ctx)?;
        self.code.emit(|e| e.mov_reg(Gpr::x(2), ctx))?;
        let live = if op == 0 {
            match size {
                ArgVal::Immediate(value) | ArgVal::Literal(value) => value as usize,
                _ => 0,
            }
        } else {
            6
        };
        let size = self.source_reg(size)?;
        self.code.emit(|e| {
            e.mov_const(Gpr::x(1), u64::from(op))?;
            e.mov_reg(Gpr::x(3), size)?;
            e.mov_const(Gpr::x(4), u64::from(unit))
        })?;
        // Port of erts/emulator/beam/jit/arm/instr_bs.cpp:175-182, OTP-29.1.1.
        // `start_match` may collect (it needs two words for the context), and a collection
        // moves the stack together with the heap, so the stack pointer is reloaded as well.
        let update = if op == 0 {
            crate::Update::HEAP_ALLOC
        } else {
            crate::Update::HEAP_ALLOC
                .union(crate::Update::REDUCTIONS)
                .union(crate::Update::X_REGS)
        };
        self.emit_bs_runtime_hook(
            helper as usize,
            &[Gpr::x(1), Gpr::x(2), Gpr::x(3), Gpr::x(4)],
            live,
            update,
        )?;
        // Port of erts/emulator/beam/jit/arm/instr_bs.cpp:142-163, OTP-29.1.1:
        // `{f,0}` means the compiler proved this match cannot fail.
        if let Some(label) = fail.filter(|label| *label != 0) {
            let label = self.label(label);
            self.code.cbz(Gpr::x(0), label)?;
        }
        if let Some(dst) = dst {
            // The helper result must not pass through X0: it may hold the match context.
            self.store_register(dst, Gpr::x(0))?;
        }
        Ok(())
    }

    fn cursor(&mut self, ctx: ArgVal) -> Result<(), ModuleError> {
        let source = self.source_reg(ctx)?;
        self.code.emit(|e| {
            e.and_imm(CTX, source, !7)?;
            e.ldr_uoff(START, CTX, 16)?;
            e.ldr_uoff(END, CTX, 24)
        })?;
        Ok(())
    }

    fn fixed_integer_inline(
        &mut self,
        ctx: ArgVal,
        bits: u16,
        fail: u32,
        dst: ArgVal,
        helper: BsMatchHelper,
    ) -> Result<(), ModuleError> {
        self.cursor(ctx)?;
        self.code.emit(|e| {
            e.sub_reg(TMP, END, START, arinsal_a64::enc::Shift::Lsl, 0)?;
            e.cmp_imm(TMP, bits, false)
        })?;
        let enough = self.code.new_label();
        self.code.b_cond(Cond::Cs, enough)?;
        let fail_label = self.label(fail);
        self.code.b(fail_label)?;
        self.code.bind(enough)?;
        self.code.emit(|e| e.ldr_uoff(Gpr::x(10), CTX, 8))?;
        self.code
            .emit(|e| e.cmp_reg(Gpr::x(10), Gpr::x(10), arinsal_a64::enc::Shift::Lsl, 0))?;
        let aligned = self.code.new_label();
        self.code.b_cond(Cond::Eq, aligned)?;
        self.code.bind(aligned)?;
        self.emit_bs_helper(
            u32::from(bits),
            ctx,
            ArgVal::Immediate(u64::from(bits)),
            1,
            Some(dst),
            Some(fail),
            helper,
        )
    }

    /// Creates or reuses a `SUB_BITS` match context.
    // Port of erts/emulator/beam/jit/arm/instr_bs.cpp:134-190, OTP-29.1.1.
    pub fn emit_i_bs_start_match3(
        &mut self,
        src: ArgVal,
        live: u32,
        fail: u32,
        dst: ArgVal,
        helper: BsMatchHelper,
        gc_hook: crate::construct::GcHook,
    ) -> Result<(), ModuleError> {
        // OTP ensures space before entering the heap-only runtime call.
        // Port of erts/emulator/beam/jit/arm/instr_bs.cpp:170-182, OTP-29.1.1.
        self.emit_gc_test_preserve(ERL_SUB_BITS_SIZE, live, src, gc_hook)?;
        self.emit_bs_helper(
            0,
            src,
            ArgVal::Immediate(u64::from(live)),
            0,
            Some(dst),
            // Port of erts/emulator/beam/jit/arm/instr_bs.cpp:134-186, OTP-29.1.1.
            (fail != 0).then_some(fail),
            helper,
        )
    }

    /// Match-command list entry point introduced with OTP 26.
    // Port of erts/emulator/beam/jit/arm/instr_bs.cpp:2910-2922, OTP-29.1.1.
    pub fn emit_i_bs_match(
        &mut self,
        ctx: ArgVal,
        fail: u32,
        command: ArgVal,
        helper: BsMatchHelper,
    ) -> Result<(), ModuleError> {
        self.emit_bs_helper(1, ctx, command, 0, None, Some(fail), helper)
    }

    /// Requires an exact number of bits to remain at the current match position.
    // Port of erts/emulator/beam/jit/arm/instr_bs.cpp:2984-3016, OTP-29.1.1.
    pub fn emit_bs_match_ensure_exactly(
        &mut self,
        ctx: ArgVal,
        bits: u32,
        fail: u32,
    ) -> Result<(), ModuleError> {
        self.cursor(ctx)?;
        self.code.emit(|e| {
            e.sub_reg(TMP, END, START, arinsal_a64::enc::Shift::Lsl, 0)?;
            e.mov_const(Gpr::x(10), u64::from(bits))?;
            e.cmp_reg(TMP, Gpr::x(10), arinsal_a64::enc::Shift::Lsl, 0)
        })?;
        let fail_label = self.label(fail);
        self.code.b_cond(Cond::Ne, fail_label)?;
        Ok(())
    }

    /// Requires a minimum number of bits and a valid unit-aligned remainder.
    // Port of erts/emulator/beam/jit/arm/instr_bs.cpp:2949-2983, OTP-29.1.1.
    pub fn emit_bs_match_ensure_at_least(
        &mut self,
        ctx: ArgVal,
        bits: u32,
        unit: u32,
        fail: u32,
    ) -> Result<(), ModuleError> {
        if unit == 0 {
            return Err(ModuleError::InvalidOperand(
                "bitstring match unit must be nonzero",
            ));
        }
        self.cursor(ctx)?;
        self.code.emit(|e| {
            e.sub_reg(TMP, END, START, arinsal_a64::enc::Shift::Lsl, 0)?;
            e.mov_const(Gpr::x(10), u64::from(bits))?;
            e.cmp_reg(TMP, Gpr::x(10), arinsal_a64::enc::Shift::Lsl, 0)
        })?;
        let fail_label = self.label(fail);
        self.code.b_cond(Cond::Cc, fail_label)?;
        let remainder_bits = if bits.is_multiple_of(unit) {
            None
        } else {
            Some(bits)
        };
        if let Some(remainder_bits) = remainder_bits {
            self.code.emit(|e| {
                e.mov_const(Gpr::x(10), u64::from(remainder_bits))?;
                e.sub_reg(TMP, TMP, Gpr::x(10), arinsal_a64::enc::Shift::Lsl, 0)
            })?;
        }
        self.code.emit(|e| {
            e.mov_const(Gpr::x(10), u64::from(unit))?;
            e.udiv(Gpr::x(8), TMP, Gpr::x(10))?;
            e.msub(Gpr::x(8), Gpr::x(8), Gpr::x(10), TMP)?;
            e.cmp_imm(Gpr::x(8), 0, false)
        })?;
        self.code.b_cond(Cond::Ne, fail_label)?;
        Ok(())
    }

    /// Advances the match cursor after a preceding ensure command succeeds.
    // Port of erts/emulator/beam/jit/arm/instr_bs.cpp:3180-3205, OTP-29.1.1.
    pub fn emit_bs_match_skip(&mut self, ctx: ArgVal, bits: u32) -> Result<(), ModuleError> {
        self.cursor(ctx)?;
        self.code.emit(|e| {
            e.mov_const(Gpr::x(10), u64::from(bits))?;
            e.add_reg(START, START, Gpr::x(10), arinsal_a64::enc::Shift::Lsl, 0)?;
            e.and_imm(CTX, CTX, !7)?;
            e.str_uoff(START, CTX, 16)
        })?;
        Ok(())
    }

    /// Publishes a match context around an instruction heap check.
    // Port of erts/emulator/beam/jit/arm/instr_bs.cpp:2916-2940, OTP-29.1.1.
    pub fn emit_i_bs_match_test_heap(
        &mut self,
        ctx: ArgVal,
        _need: u32,
        _live: u32,
        fail: u32,
        helper: BsMatchHelper,
    ) -> Result<(), ModuleError> {
        self.emit_bs_helper(2, ctx, ArgVal::Immediate(0), 0, None, Some(fail), helper)
    }

    /// Reads the current bit position into a destination term.
    // Port of erts/emulator/beam/jit/arm/instr_bs.cpp:236-255, OTP-29.1.1.
    pub fn emit_i_bs_get_position(
        &mut self,
        ctx: ArgVal,
        dst: ArgVal,
        helper: BsMatchHelper,
    ) -> Result<(), ModuleError> {
        self.emit_bs_helper(3, ctx, ArgVal::Immediate(0), 0, Some(dst), None, helper)
    }

    /// Restores a saved match position.
    // Port of erts/emulator/beam/jit/arm/instr_bs.cpp:371-384, OTP-29.1.1.
    pub fn emit_i_bs_set_position(
        &mut self,
        ctx: ArgVal,
        pos: ArgVal,
        helper: BsMatchHelper,
    ) -> Result<(), ModuleError> {
        self.emit_bs_helper(4, ctx, pos, 0, None, None, helper)
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
        self.cursor(ctx)?;
        let source = self.source_reg_into(ctx, Gpr::x(17))?;
        self.code.emit(|e| {
            e.add_reg(START, START, FIELD_BITS, arinsal_a64::enc::Shift::Lsl, 0)?;
            e.cmp_reg(START, END, arinsal_a64::enc::Shift::Lsl, 0)?;
            e.and_imm(CTX, source, !7)
        })?;
        self.code.b_cond(Cond::Hi, label)?;
        self.code.emit(|e| e.str_uoff(START, CTX, 16))?;
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
        match size {
            ArgVal::Immediate(word) | ArgVal::Literal(word) => {
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
            }
            _ => {
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
    }

    /// Inline aligned 8-bit integer extraction fast path.
    // Port of erts/emulator/beam/jit/arm/instr_bs.cpp:257-311, OTP-29.1.1.
    pub fn emit_i_bs_get_integer_8(
        &mut self,
        ctx: ArgVal,
        fail: u32,
        dst: ArgVal,
        helper: BsMatchHelper,
    ) -> Result<(), ModuleError> {
        self.cursor(ctx)?;
        self.code.emit(|e| {
            e.ldr_uoff(Gpr::x(10), CTX, 8)?;
            e.cmp_reg(Gpr::x(10), Gpr::x(10), arinsal_a64::enc::Shift::Lsl, 0)
        })?;
        let aligned = self.code.new_label();
        self.code.b_cond(Cond::Eq, aligned)?;
        self.code.bind(aligned)?;
        self.fixed_integer_inline(ctx, 8, fail, dst, helper)
    }
    /// Inline aligned 16-bit integer extraction fast path.
    // Port of erts/emulator/beam/jit/arm/instr_bs.cpp:257-311, OTP-29.1.1.
    pub fn emit_i_bs_get_integer_16(
        &mut self,
        ctx: ArgVal,
        fail: u32,
        dst: ArgVal,
        helper: BsMatchHelper,
    ) -> Result<(), ModuleError> {
        self.cursor(ctx)?;
        self.code.emit(|e| {
            e.ldr_uoff(Gpr::x(10), CTX, 8)?;
            e.cmp_reg(Gpr::x(10), Gpr::x(10), arinsal_a64::enc::Shift::Lsl, 0)
        })?;
        let aligned = self.code.new_label();
        self.code.b_cond(Cond::Eq, aligned)?;
        self.code.bind(aligned)?;
        self.fixed_integer_inline(ctx, 16, fail, dst, helper)
    }
    /// Inline aligned 32-bit integer extraction fast path.
    // Port of erts/emulator/beam/jit/arm/instr_bs.cpp:257-311, OTP-29.1.1.
    pub fn emit_i_bs_get_integer_32(
        &mut self,
        ctx: ArgVal,
        fail: u32,
        dst: ArgVal,
        helper: BsMatchHelper,
    ) -> Result<(), ModuleError> {
        self.cursor(ctx)?;
        self.code.emit(|e| {
            e.ldr_uoff(Gpr::x(10), CTX, 8)?;
            e.cmp_reg(Gpr::x(10), Gpr::x(10), arinsal_a64::enc::Shift::Lsl, 0)
        })?;
        let aligned = self.code.new_label();
        self.code.b_cond(Cond::Eq, aligned)?;
        self.code.bind(aligned)?;
        self.fixed_integer_inline(ctx, 32, fail, dst, helper)
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
        helper: BsMatchHelper,
    ) -> Result<(), ModuleError> {
        self.emit_bs_helper(5, ctx, bits, unit, Some(dst), Some(fail), helper)
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
        helper: BsMatchHelper,
        gc_hook: crate::construct::GcHook,
    ) -> Result<(), ModuleError> {
        self.emit_gc_test_preserve(BUILD_SUB_BITSTRING_HEAP_NEED, live, ctx, gc_hook)?;
        self.emit_bs_helper(6, ctx, bits, unit, Some(dst), Some(fail), helper)
    }
    /// Extracts all remaining bits as a sub-binary.
    // Port of erts/emulator/beam/jit/arm/instr_bs.cpp:386-405, OTP-29.1.1.
    pub fn emit_i_bs_get_binary_all2(
        &mut self,
        ctx: ArgVal,
        fail: u32,
        unit: u32,
        dst: ArgVal,
        helper: BsMatchHelper,
    ) -> Result<(), ModuleError> {
        self.emit_bs_helper(
            7,
            ctx,
            ArgVal::Immediate(0),
            unit,
            Some(dst),
            Some(fail),
            helper,
        )
    }
    /// Compares fixed bits against a module string constant.
    // Port of erts/emulator/beam/jit/arm/instr_bs.cpp:191-234, OTP-29.1.1.
    pub fn emit_i_bs_match_string(
        &mut self,
        ctx: ArgVal,
        fail: u32,
        bits: ArgVal,
        string: ArgVal,
        helper: BsMatchHelper,
    ) -> Result<(), ModuleError> {
        // The hook receives the bit count in the unit argument.
        let ArgVal::Immediate(bits) = bits else {
            return Err(ModuleError::InvalidOperand(
                "match string size must be an immediate",
            ));
        };
        let bits = u32::try_from(bits >> 4)
            .map_err(|_| ModuleError::InvalidOperand("match string size overflow"))?;
        self.emit_bs_helper(9, ctx, string, bits, None, Some(fail), helper)
    }
    /// Builds a sub-bitstring from the current cursor to the context end.
    // Port of erts/emulator/beam/jit/arm/instr_bs.cpp:407-455, OTP-29.1.1.
    pub fn emit_bs_get_tail(
        &mut self,
        ctx: ArgVal,
        dst: ArgVal,
        live: u32,
        helper: BsMatchHelper,
        gc_hook: crate::construct::GcHook,
    ) -> Result<(), ModuleError> {
        self.emit_gc_test_preserve(BUILD_SUB_BITSTRING_HEAP_NEED, live, ctx, gc_hook)?;
        self.emit_bs_helper(
            10,
            ctx,
            ArgVal::Immediate(u64::from(live)),
            0,
            Some(dst),
            None,
            helper,
        )
    }
    /// Extracts and validates one UTF-8 scalar.
    // Port of erts/emulator/beam/jit/arm/instr_bs.cpp:712-899, OTP-29.1.1.
    pub fn emit_i_bs_get_utf8(
        &mut self,
        ctx: ArgVal,
        fail: u32,
        dst: ArgVal,
        helper: BsMatchHelper,
    ) -> Result<(), ModuleError> {
        self.emit_bs_helper(
            11,
            ctx,
            ArgVal::Immediate(0),
            0,
            Some(dst),
            Some(fail),
            helper,
        )
    }
    /// Skips one UTF-8 scalar, failing on malformed input.
    // Port of erts/emulator/beam/jit/arm/instr_bs.cpp:900-903, OTP-29.1.1.
    pub fn emit_i_bs_skip_utf8(
        &mut self,
        ctx: ArgVal,
        fail: u32,
        helper: BsMatchHelper,
    ) -> Result<(), ModuleError> {
        self.emit_bs_helper(11, ctx, ArgVal::Immediate(0), 0, None, Some(fail), helper)
    }
    /// Skips one UTF-16 scalar, failing on malformed input.
    // Port of erts/emulator/beam/jit/arm/instr_bs.cpp:930-934, OTP-29.1.1.
    pub fn emit_i_bs_skip_utf16(
        &mut self,
        ctx: ArgVal,
        fail: u32,
        flags: ArgVal,
        helper: BsMatchHelper,
    ) -> Result<(), ModuleError> {
        self.emit_bs_helper(12, ctx, flags, 0, None, Some(fail), helper)
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
        helper: BsMatchHelper,
    ) -> Result<(), ModuleError> {
        self.emit_bs_helper(12, ctx, flags, 0, Some(dst), Some(fail), helper)
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
        unit: u32,
        dst: ArgVal,
        helper: BsMatchHelper,
        gc_hook: crate::construct::GcHook,
    ) -> Result<(), ModuleError> {
        self.emit_gc_test_preserve(FLOAT_SIZE_OBJECT, live, ctx, gc_hook)?;
        self.emit_bs_helper(13, ctx, bits, unit, Some(dst), Some(fail), helper)
    }

    /// Parses a fixed number of bytes in a native loop and returns their sum.
    // Port of erts/emulator/beam/jit/arm/instr_bs.cpp:257-311, OTP-29.1.1.
    pub fn emit_i_bs_sum_bytes_loop(
        &mut self,
        ctx: ArgVal,
        count: u32,
        helper: BsMatchHelper,
    ) -> Result<(), ModuleError> {
        let loop_label = self.code.new_label();
        self.code.emit(|e| {
            e.mov_const(Gpr::x(27), u64::from(count))?;
            e.mov_reg(Gpr::x(28), Gpr::xzr())
        })?;
        self.code.bind(loop_label)?;
        self.emit_bs_helper(
            8,
            ctx,
            ArgVal::Immediate(8),
            1,
            Some(ArgVal::X(1)),
            None,
            helper,
        )?;
        self.code.emit(|e| {
            e.asr_imm(Gpr::x(26), Gpr::x(26), 4)?;
            e.add_reg(
                Gpr::x(28),
                Gpr::x(28),
                Gpr::x(26),
                arinsal_a64::enc::Shift::Lsl,
                0,
            )?;
            e.sub_imm(Gpr::x(27), Gpr::x(27), 1, false)
        })?;
        self.code.cbnz(Gpr::x(27), loop_label)?;
        self.code.emit(|e| e.mov_reg(Gpr::x(26), Gpr::x(28)))?;
        Ok(())
    }
}
