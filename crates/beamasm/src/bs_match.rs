//! AArch64 emitters for BEAM bit syntax matching.

use crate::module::{ArgVal, BeamModuleAssembler, ModuleError};
use arinsal_a64::enc::{Cond, Gpr};

/// Runtime slow path for operations that allocate a term or decode variable-width fields.
pub type BsMatchHelper = extern "C" fn(*mut crate::ProcessHeader, u32, u64, u64, u64) -> u64;
const CTX: Gpr = Gpr::x(11);
const START: Gpr = Gpr::x(13);
const END: Gpr = Gpr::x(14);
const TMP: Gpr = Gpr::x(9);

impl BeamModuleAssembler {
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
        self.code.cbnz(Gpr::x(9), self.error_label)?;
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
        let update = if op == 0 {
            crate::Update::HEAP
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
        if let Some(label) = fail {
            let label = self.label(label);
            self.code.cbz(Gpr::x(0), label)?;
        }
        if let Some(dst) = dst {
            self.code.emit(|e| e.mov_reg(Gpr::x(25), Gpr::x(0)))?;
            self.move_(ArgVal::X(0), dst)?;
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
        // OTP ensures space before entering the heap-only runtime fragment.
        // Keeping collection here also keeps the raw match-context argument live.
        // Port of erts/emulator/beam/jit/arm/instr_bs.cpp:170-182, OTP-29.1.1.
        self.emit_test_heap(2, live, gc_hook)?;
        self.emit_bs_helper(
            0,
            src,
            ArgVal::Immediate(u64::from(live)),
            0,
            Some(dst),
            Some(fail),
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
        self.cursor(ctx)?;
        self.code.emit(|e| e.ldr_uoff(Gpr::x(8), CTX, 8))?;
        let bits = self.source_reg(bits)?;
        let label = self.label(fail);
        let source = self.source_reg(ctx)?;
        self.code.emit(|e| {
            e.lsr_imm(TMP, bits, 4)?;
            if unit != 1 {
                e.mov_const(Gpr::x(10), u64::from(unit))?;
                e.mul(Gpr::x(10), TMP, Gpr::x(10))?;
                e.mov_reg(TMP, Gpr::x(10))?;
            }
            e.add_reg(START, START, TMP, arinsal_a64::enc::Shift::Lsl, 0)?;
            e.cmp_reg(START, END, arinsal_a64::enc::Shift::Lsl, 0)?;
            e.and_imm(CTX, source, !7)?;
            Ok(())
        })?;
        self.code.b_cond(Cond::Hi, label)?;
        self.code.emit(|e| e.str_uoff(START, CTX, 16))?;
        Ok(())
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
    pub fn emit_i_bs_get_binary2(
        &mut self,
        ctx: ArgVal,
        fail: u32,
        bits: ArgVal,
        unit: u32,
        dst: ArgVal,
        helper: BsMatchHelper,
    ) -> Result<(), ModuleError> {
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
        _bits: ArgVal,
        string: ArgVal,
        helper: BsMatchHelper,
    ) -> Result<(), ModuleError> {
        self.emit_bs_helper(9, ctx, string, 0, None, Some(fail), helper)
    }
    /// Builds a sub-bitstring from the current cursor to the context end.
    // Port of erts/emulator/beam/jit/arm/instr_bs.cpp:407-455, OTP-29.1.1.
    pub fn emit_bs_get_tail(
        &mut self,
        ctx: ArgVal,
        dst: ArgVal,
        live: u32,
        helper: BsMatchHelper,
    ) -> Result<(), ModuleError> {
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
    pub fn emit_i_bs_get_float2(
        &mut self,
        ctx: ArgVal,
        fail: u32,
        bits: ArgVal,
        unit: u32,
        dst: ArgVal,
        helper: BsMatchHelper,
    ) -> Result<(), ModuleError> {
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
