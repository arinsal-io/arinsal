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
        // Fixed unsigned fields are read inline; everything else stays on the runtime hook.
        // Port of erts/emulator/beam/jit/arm/instr_bs.cpp:3055-3125 (READ / EXTRACT_INTEGER), OTP-29.1.1.
        if kind == 0 && self.emit_inline_fixed_integer(staged, fail, dst, live, helper)? {
            return Ok(());
        }
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
        if matches!(ctx, ArgVal::X(_)) || source == CTX {
            return Ok(source);
        }
        self.code.emit(|e| e.mov_reg(CTX, source))?;
        Ok(CTX)
    }

    /// Records that `START` and `END` are live and at least `proved` bits remain.
    fn mark_live_cursor(&mut self, proved: u32) {
        self.bs_live_cursor = Some((self.code.offset(), proved));
    }

    /// Reuses the cursor left by the previous command of this `bs_match` when it proved
    /// `need` bits remain. Otherwise the caller reloads.
    fn take_live_cursor(&mut self, need: u32) -> bool {
        matches!(
            self.bs_live_cursor.take(),
            Some((at, proved)) if at == self.code.offset() && proved >= need
        )
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
        // Reuse an existing match context. A plain bitstring falls through to
        // erts_bs_start_match_3, which allocates a fresh context.
        let next = self.code.new_label();
        let hit = self.code.new_label();
        let src_reg = self.source_reg_into(src, Gpr::x(8))?;
        self.code.emit(|e| e.mov_reg(Gpr::x(8), src_reg))?;
        // Port of instr_bs.cpp:142-146: `{f,0}` skips the box test; bit 0 rejects lists
        // and immediates.
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
        // A plain sub-bitstring becomes a match context with five stores. Heap bits and
        // writable binaries still go through erts_bs_start_match_3.
        // Port of erts/emulator/beam/erl_bits.c:81-104 (erts_bs_start_match_3), OTP-29.1.1.
        let plain = self.code.new_label();
        self.code.emit(|e| {
            e.and_imm(Gpr::x(9), Gpr::x(10), 63)?;
            e.cmp_imm(Gpr::x(9), 0x24, false)
        })?;
        self.code.b_cond(Cond::Ne, plain)?;
        self.code.emit(|e| e.tst_imm(Gpr::x(12), 3))?;
        self.code.b_cond(Cond::Ne, plain)?;
        self.emit_gc_test_preserve(ERL_SUB_BITS_SIZE, live, src, gc_hook)?;
        let src_reg = self.source_reg_into(src, Gpr::x(8))?;
        self.code.emit(|e| {
            e.mov_reg(Gpr::x(8), src_reg)?;
            e.and_imm(CTX, Gpr::x(8), !7)?;
            e.ldp(Gpr::x(12), START, CTX, 8)?;
            e.ldp(END, Gpr::x(9), CTX, 24)?;
            e.orr_imm(Gpr::x(12), Gpr::x(12), 1)?;
            e.mov_const(Gpr::x(10), 0x124)?;
            e.mov_reg(Gpr::x(8), Gpr::x(23))?;
            e.stp(Gpr::x(10), Gpr::x(12), Gpr::x(8), 0)?;
            e.stp(START, END, Gpr::x(8), 16)?;
            e.str_uoff(Gpr::x(9), Gpr::x(8), 32)?;
            e.add_imm(Gpr::x(23), Gpr::x(8), 40, false)?;
            e.orr_imm(Gpr::x(8), Gpr::x(8), 2)
        })?;
        self.store_register(dst, Gpr::x(8))?;
        self.code.b(next)?;
        self.code.bind(plain)?;
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
        )?;
        self.code.b(next)?;
        self.code.bind(hit)?;
        self.store_register(dst, Gpr::x(8))?;
        self.code.bind(next)?;
        Ok(())
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
        let fail_label = self.label(fail);
        if bits == 0 {
            // Port of instr_bs.cpp:3004-3008: a zero tail is `subs` so the flags are the test.
            self.code
                .emit(|e| e.subs_reg(TMP, END, START, arinsal_a64::enc::Shift::Lsl, 0))?;
        } else {
            self.code
                .emit(|e| e.sub_reg(TMP, END, START, arinsal_a64::enc::Shift::Lsl, 0))?;
            self.cmp_bit_count(TMP, bits)?;
        }
        self.code.b_cond(Cond::Ne, fail_label)?;
        self.mark_live_cursor(bits);
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
        let fail_label = self.label(fail);
        if bits != 0 {
            self.code
                .emit(|e| e.sub_reg(TMP, END, START, arinsal_a64::enc::Shift::Lsl, 0))?;
            self.cmp_bit_count(TMP, bits)?;
            self.code.b_cond(Cond::Cc, fail_label)?;
        } else {
            self.code
                .emit(|e| e.sub_reg(TMP, END, START, arinsal_a64::enc::Shift::Lsl, 0))?;
        }
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
        // Port of erts/emulator/beam/jit/arm/instr_bs.cpp:2970-2981, OTP-29.1.1:
        // a unit of 1 is free, and a power-of-two unit is a mask test.
        if unit == 1 {
            self.mark_live_cursor(bits);
            return Ok(());
        }
        if unit.is_power_of_two() {
            self.code.emit(|e| e.tst_imm(TMP, u64::from(unit - 1)))?;
            self.code.b_cond(Cond::Ne, fail_label)?;
        } else {
            self.code.emit(|e| {
                e.mov_const(Gpr::x(10), u64::from(unit))?;
                e.udiv(Gpr::x(8), TMP, Gpr::x(10))?;
                e.msub(Gpr::x(8), Gpr::x(8), Gpr::x(10), TMP)?;
                e.cmp_imm(Gpr::x(8), 0, false)
            })?;
            self.code.b_cond(Cond::Ne, fail_label)?;
        }
        self.mark_live_cursor(bits);
        Ok(())
    }

    /// Compares `reg` with a bit count. Counts that fit in a shifted 12-bit immediate use
    /// `cmp` directly, as `emit_i_bs_match` does.
    fn cmp_bit_count(&mut self, reg: Gpr, bits: u32) -> Result<(), ModuleError> {
        if bits <= 0xfff {
            self.code.emit(|e| e.cmp_imm(reg, bits as u16, false))?;
        } else if bits <= 0xfff_000 && bits & 0xfff == 0 {
            self.code
                .emit(|e| e.cmp_imm(reg, (bits >> 12) as u16, true))?;
        } else {
            self.code.emit(|e| {
                e.mov_const(Gpr::x(10), u64::from(bits))?;
                e.cmp_reg(reg, Gpr::x(10), arinsal_a64::enc::Shift::Lsl, 0)
            })?;
        }
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
        _helper: BsMatchHelper,
    ) -> Result<(), ModuleError> {
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
    pub fn emit_i_bs_set_position(
        &mut self,
        ctx: ArgVal,
        pos: ArgVal,
        helper: BsMatchHelper,
    ) -> Result<(), ModuleError> {
        let slow = self.code.new_label();
        let next = self.code.new_label();
        let pos_reg = self.source_reg_into(pos, Gpr::x(8))?;
        self.code.emit(|e| {
            e.mov_reg(Gpr::x(8), pos_reg)?;
            e.and_imm(Gpr::x(10), Gpr::x(8), 0xf)?;
            e.cmp_imm(Gpr::x(10), 0xf, false)
        })?;
        self.code.b_cond(Cond::Ne, slow)?;
        self.cursor(ctx)?;
        self.code.emit(|e| e.lsr_imm(Gpr::x(8), Gpr::x(8), 4))?;
        self.code.emit(|e| e.str_uoff(Gpr::x(8), CTX, 16))?;
        self.code.b(next)?;
        self.code.bind(slow)?;
        self.emit_bs_helper(4, ctx, pos, 0, None, None, helper)?;
        self.code.bind(next)?;
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
        // Port of erts/emulator/beam/erl_bits.c:2635-2668 (erts_build_sub_bitstring), OTP-29.1.1.
        self.emit_inline_get_binary(ctx, fail, bits, unit, dst, helper)
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
        self.emit_inline_utf8(ctx, fail, Some(dst), helper)
    }
    /// Skips one UTF-8 scalar, failing on malformed input.
    // Port of erts/emulator/beam/jit/arm/instr_bs.cpp:900-903, OTP-29.1.1.
    pub fn emit_i_bs_skip_utf8(
        &mut self,
        ctx: ArgVal,
        fail: u32,
        helper: BsMatchHelper,
    ) -> Result<(), ModuleError> {
        self.emit_inline_utf8(ctx, fail, None, helper)
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

    /// Untagged small immediate, when the operand was encoded as one.
    fn small_immediate(value: ArgVal) -> Option<u64> {
        match value {
            ArgVal::Immediate(word) | ArgVal::Literal(word) if word & 0xf == 0xf => Some(word >> 4),
            _ => None,
        }
    }

    /// Byte-aligned unsigned integer of 8, 16, or 32 bits. Unaligned positions use the hook.
    // Port of erts/emulator/beam/jit/arm/instr_bs.cpp:2496-2748 (emit_read_bits) and
    // 2750-2774 (emit_extract_integer), OTP-29.1.1.
    fn emit_inline_fixed_integer(
        &mut self,
        staged: &[ArgVal],
        fail: u32,
        dst: Option<ArgVal>,
        live: u32,
        helper: BsMatchCmdHelper,
    ) -> Result<bool, ModuleError> {
        let [ctx, flags, size, unit] = staged else {
            return Ok(false);
        };
        let (Some(flags), Some(size), Some(unit)) = (
            Self::small_immediate(*flags),
            Self::small_immediate(*size),
            Self::small_immediate(*unit),
        ) else {
            return Ok(false);
        };
        let Some(bits) = size.checked_mul(unit) else {
            return Ok(false);
        };
        // Native endian is little on this host, same as `BSF_LITTLE`.
        let flags = if flags & 16 != 0 {
            (flags & !16) | 2
        } else {
            flags
        };
        if flags & 4 != 0 || (flags & 2 != 0 && bits > 8) || !matches!(bits, 8 | 16 | 32) {
            return Ok(false);
        }
        let bits = u16::try_from(bits).unwrap_or(0);
        let slow = self.code.new_label();
        let done = self.code.new_label();
        let fail_label = (fail != 0).then(|| self.label(fail));
        // The preceding ensure already loaded the cursor and proved these bits remain
        // (instr_bs.cpp:2931 `position_is_valid`, 3055-3073 READ_INTEGER).
        let reused = self.take_live_cursor(u32::from(bits));
        if !reused {
            self.cursor(*ctx)?;
            self.code.emit(|e| {
                e.sub_reg(TMP, END, START, arinsal_a64::enc::Shift::Lsl, 0)?;
                e.cmp_imm(TMP, bits, false)
            })?;
            if let Some(fail_label) = fail_label {
                self.code.b_cond(Cond::Cc, fail_label)?;
            } else {
                self.code.b_cond(Cond::Cc, slow)?;
            }
        }
        self.code.emit(|e| {
            e.ldr_uoff(Gpr::x(10), CTX, 8)?;
            e.and_imm(Gpr::x(10), Gpr::x(10), !3)?;
            e.add_reg(
                Gpr::x(10),
                Gpr::x(10),
                START,
                arinsal_a64::enc::Shift::Lsr,
                3,
            )?;
            e.tst_imm(START, 7)
        })?;
        self.code.b_cond(Cond::Ne, slow)?;
        match bits {
            8 => self.code.emit(|e| e.ldrb_uoff(Gpr::x(9), Gpr::x(10), 0))?,
            16 => self.code.emit(|e| {
                e.ldrh_uoff(Gpr::x(9), Gpr::x(10), 0)?;
                e.rev16(Gpr::x(9), Gpr::x(9))
            })?,
            _ => self.code.emit(|e| {
                e.ldr_uoff(Gpr::w(9), Gpr::x(10), 0)?;
                e.rev32(Gpr::x(9), Gpr::x(9))
            })?,
        }
        self.code.emit(|e| {
            e.add_imm(START, START, bits, false)?;
            e.str_uoff(START, CTX, 16)?;
            e.lsl_imm(Gpr::x(9), Gpr::x(9), 4)?;
            e.orr_imm(Gpr::x(9), Gpr::x(9), 0xf)
        })?;
        if let Some(dst) = dst {
            self.store_register(dst, Gpr::x(9))?;
        }
        self.code.b(done)?;
        self.code.bind(slow)?;
        self.emit_bs_match_command_hook(live, staged, fail, dst, helper)?;
        self.code.bind(done)?;
        Ok(true)
    }

    /// One aligned read of several adjacent unsigned big-endian fields.
    ///
    /// `beam_jit_opt_bsm_segments` merges consecutive integer commands that fit in one
    /// 64-bit read into a single `READ` plus `EXTRACT_INTEGER`s. Unaligned positions fall
    /// back to one inline field at a time.
    // Port of erts/emulator/beam/jit/beam_jit_bs.cpp:414-461 and
    // erts/emulator/beam/jit/arm/instr_bs.cpp:3024-3073, OTP-29.1.1.
    pub fn emit_bs_match_fused_integers(
        &mut self,
        ctx: ArgVal,
        fail: u32,
        live: u32,
        fields: &[(u16, ArgVal)],
        helper: BsMatchCmdHelper,
    ) -> Result<(), ModuleError> {
        let total: u16 = fields.iter().map(|(bits, _)| *bits).sum();
        if !matches!(total, 16 | 24 | 32) {
            return Err(ModuleError::InvalidOperand(
                "fused integer read must be 16, 24, or 32 bits",
            ));
        }
        let slow = self.code.new_label();
        let done = self.code.new_label();
        let fail_label = (fail != 0).then(|| self.label(fail));
        // One read of every field, using the cursor the preceding ensure left live.
        // Port of instr_bs.cpp:3040-3073 (READ + EXTRACT_INTEGER), OTP-29.1.1.
        let reused = self.take_live_cursor(u32::from(total));
        if !reused {
            self.cursor(ctx)?;
            self.code.emit(|e| {
                e.sub_reg(TMP, END, START, arinsal_a64::enc::Shift::Lsl, 0)?;
                e.cmp_imm(TMP, total, false)
            })?;
            if let Some(fail_label) = fail_label {
                self.code.b_cond(Cond::Cc, fail_label)?;
            } else {
                self.code.b_cond(Cond::Cc, slow)?;
            }
        }
        self.code.emit(|e| {
            e.ldr_uoff(Gpr::x(10), CTX, 8)?;
            e.and_imm(Gpr::x(10), Gpr::x(10), !3)?;
            e.add_reg(
                Gpr::x(10),
                Gpr::x(10),
                START,
                arinsal_a64::enc::Shift::Lsr,
                3,
            )?;
            e.tst_imm(START, 7)
        })?;
        self.code.b_cond(Cond::Ne, slow)?;
        match total {
            16 => self.code.emit(|e| {
                e.ldrh_uoff(Gpr::x(9), Gpr::x(10), 0)?;
                e.rev16(Gpr::x(9), Gpr::x(9))
            })?,
            24 => self.code.emit(|e| {
                e.ldrh_uoff(Gpr::x(9), Gpr::x(10), 0)?;
                e.rev16(Gpr::x(9), Gpr::x(9))?;
                e.ldrb_uoff(Gpr::x(17), Gpr::x(10), 2)?;
                e.orr_reg(
                    Gpr::x(9),
                    Gpr::x(17),
                    arinsal_a64::enc::Shifted {
                        reg: Gpr::x(9),
                        shift: arinsal_a64::enc::Shift::Lsl,
                        amount: 8,
                    },
                )
            })?,
            _ => self.code.emit(|e| {
                e.ldr_uoff(Gpr::w(9), Gpr::x(10), 0)?;
                e.rev32(Gpr::x(9), Gpr::x(9))
            })?,
        }
        self.code.emit(|e| {
            e.add_imm(START, START, total, false)?;
            e.str_uoff(START, CTX, 16)
        })?;
        let mut shift = total;
        for (bits, dst) in fields {
            shift -= *bits;
            let mask = (1u64 << *bits) - 1;
            self.code.emit(|e| {
                if shift == 0 {
                    e.and_imm(Gpr::x(17), Gpr::x(9), mask)?;
                } else {
                    e.lsr_imm(Gpr::x(17), Gpr::x(9), u8::try_from(shift).unwrap_or(0))?;
                    e.and_imm(Gpr::x(17), Gpr::x(17), mask)?;
                }
                e.lsl_imm(Gpr::x(17), Gpr::x(17), 4)?;
                e.orr_imm(Gpr::x(17), Gpr::x(17), 0xf)
            })?;
            self.store_register(*dst, Gpr::x(17))?;
        }
        self.code.b(done)?;
        self.code.bind(slow)?;
        for (bits, dst) in fields {
            let staged = [
                ctx,
                ArgVal::Immediate(0xf),
                ArgVal::Immediate((u64::from(*bits) << 4) | 0xf),
                ArgVal::Immediate((1 << 4) | 0xf),
            ];
            self.emit_inline_fixed_integer(&staged, fail, Some(*dst), live, helper)?;
        }
        self.code.bind(done)?;
        Ok(())
    }

    /// The runtime hook used when an inline match cannot handle the operand.
    fn emit_bs_match_command_hook(
        &mut self,
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
            e.mov_const(Gpr::x(1), 0)?;
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
        if fail != 0 {
            let fail = self.label(fail);
            self.code.cbz(Gpr::x(0), fail)?;
        }
        if let Some(dst) = dst {
            self.store_register(dst, Gpr::x(0))?;
        }
        Ok(())
    }

    /// Extracts a byte-multiple binary segment into a heap bitstring or a shared sub-bits.
    // Port of erts/emulator/beam/erl_bits.c:2635-2668 (erts_build_sub_bitstring) and
    // erl_bits.h:171-176 (HEAP_BITSTRING), OTP-29.1.1.
    fn emit_inline_get_binary(
        &mut self,
        ctx: ArgVal,
        fail: u32,
        bits: ArgVal,
        unit: u32,
        dst: ArgVal,
        helper: BsMatchHelper,
    ) -> Result<(), ModuleError> {
        if unit == 0 || unit > 64 {
            return self.emit_bs_helper(6, ctx, bits, unit, Some(dst), Some(fail), helper);
        }
        let slow = self.code.new_label();
        let done = self.code.new_label();
        let heap_bits = self.code.new_label();
        let copy = self.code.new_label();
        let copy_done = self.code.new_label();
        let size_reg = self.source_reg_into(bits, Gpr::x(8))?;
        self.code.emit(|e| {
            e.mov_reg(Gpr::x(8), size_reg)?;
            e.and_imm(Gpr::x(10), Gpr::x(8), 0xf)?;
            e.cmp_imm(Gpr::x(10), 0xf, false)
        })?;
        self.code.b_cond(Cond::Ne, slow)?;
        if fail != 0 {
            let fail_label = self.label(fail);
            self.code.tbnz(Gpr::x(8), 63, fail_label)?;
        } else {
            self.code.tbnz(Gpr::x(8), 63, slow)?;
        }
        let shift = unit.trailing_zeros();
        self.code.emit(|e| e.lsr_imm(FIELD_BITS, Gpr::x(8), 4))?;
        if !unit.is_power_of_two() {
            self.code.emit(|e| {
                e.mov_const(Gpr::x(10), u64::from(unit))?;
                e.mul(FIELD_BITS, FIELD_BITS, Gpr::x(10))
            })?;
        } else if shift > 0 {
            self.code
                .emit(|e| e.lsl_imm(FIELD_BITS, FIELD_BITS, shift as u8))?;
        }
        self.cursor(ctx)?;
        self.code.emit(|e| {
            e.sub_reg(TMP, END, START, arinsal_a64::enc::Shift::Lsl, 0)?;
            e.cmp_reg(TMP, FIELD_BITS, arinsal_a64::enc::Shift::Lsl, 0)
        })?;
        if fail != 0 {
            let fail_label = self.label(fail);
            self.code.b_cond(Cond::Cc, fail_label)?;
        } else {
            self.code.b_cond(Cond::Cc, slow)?;
        }
        self.code.emit(|e| e.tst_imm(START, 7))?;
        self.code.b_cond(Cond::Ne, slow)?;
        self.code.emit(|e| e.tst_imm(FIELD_BITS, 7))?;
        self.code.b_cond(Cond::Ne, slow)?;
        self.code.emit(|e| {
            e.ldr_uoff(Gpr::x(10), CTX, 8)?;
            e.and_imm(Gpr::x(10), Gpr::x(10), !3)?;
            e.add_reg(
                Gpr::x(10),
                Gpr::x(10),
                START,
                arinsal_a64::enc::Shift::Lsr,
                3,
            )?;
            e.cmp_imm(FIELD_BITS, 512, false)
        })?;
        self.code.b_cond(Cond::Ls, heap_bits)?;
        // Larger than 64 bytes: five-word sub-bits sharing the original owner.
        self.code.emit(|e| {
            e.mov_reg(Gpr::x(8), Gpr::x(23))?;
            e.ldr_uoff(Gpr::x(9), CTX, 8)?;
            e.and_imm(Gpr::x(9), Gpr::x(9), !1)?;
            e.mov_const(Gpr::x(17), 0x124)?;
            e.str_uoff(Gpr::x(17), Gpr::x(8), 0)?;
            e.str_uoff(Gpr::x(9), Gpr::x(8), 8)?;
            e.str_uoff(START, Gpr::x(8), 16)?;
            e.add_reg(
                Gpr::x(14),
                START,
                FIELD_BITS,
                arinsal_a64::enc::Shift::Lsl,
                0,
            )?;
            e.str_uoff(Gpr::x(14), Gpr::x(8), 24)?;
            e.ldr_uoff(Gpr::x(9), CTX, 32)?;
            e.str_uoff(Gpr::x(9), Gpr::x(8), 32)?;
            e.add_reg(START, START, FIELD_BITS, arinsal_a64::enc::Shift::Lsl, 0)?;
            e.str_uoff(START, CTX, 16)?;
            e.add_imm(Gpr::x(23), Gpr::x(8), 40, false)?;
            e.orr_imm(Gpr::x(8), Gpr::x(8), 2)
        })?;
        self.store_register(dst, Gpr::x(8))?;
        self.code.b(done)?;
        self.code.bind(heap_bits)?;
        // On-heap copy of at most 64 bytes. The preceding heap test reserved the words.
        self.code.emit(|e| {
            e.mov_reg(Gpr::x(8), Gpr::x(23))?;
            e.lsr_imm(Gpr::x(17), FIELD_BITS, 3)?;
            e.add_imm(Gpr::x(9), Gpr::x(17), 7, false)?;
            e.lsr_imm(Gpr::x(9), Gpr::x(9), 3)?;
            e.add_imm(Gpr::x(14), Gpr::x(9), 2, false)?;
            e.str_uoff(FIELD_BITS, Gpr::x(8), 8)?;
            e.sub_imm(Gpr::x(12), Gpr::x(14), 1, false)?;
            e.lsl_imm(Gpr::x(12), Gpr::x(12), 6)?;
            e.orr_imm(Gpr::x(12), Gpr::x(12), 0x20)?;
            e.str_uoff(Gpr::x(12), Gpr::x(8), 0)
        })?;
        // Byte-aligned copy, widest load that fits. Matches copy_binary_to_buffer's
        // memcpy of an exact byte count (erl_bits.h:549-550): the unread tail of the
        // last word is not part of the bitstring.
        let copy8 = self.code.new_label();
        let copy4 = self.code.new_label();
        let copy2 = self.code.new_label();
        let copy1 = self.code.new_label();
        self.code
            .emit(|e| e.add_imm(Gpr::x(12), Gpr::x(8), 16, false))?;
        self.code.cbz(Gpr::x(17), copy_done)?;
        self.code.bind(copy8)?;
        self.code.emit(|e| e.cmp_imm(Gpr::x(17), 8, false))?;
        self.code.b_cond(Cond::Cc, copy4)?;
        self.code.emit(|e| {
            e.ldr_uoff(Gpr::x(9), Gpr::x(10), 0)?;
            e.str_uoff(Gpr::x(9), Gpr::x(12), 0)?;
            e.add_imm(Gpr::x(10), Gpr::x(10), 8, false)?;
            e.add_imm(Gpr::x(12), Gpr::x(12), 8, false)?;
            e.sub_imm(Gpr::x(17), Gpr::x(17), 8, false)
        })?;
        self.code.b(copy8)?;
        self.code.bind(copy4)?;
        self.code.emit(|e| e.cmp_imm(Gpr::x(17), 4, false))?;
        self.code.b_cond(Cond::Cc, copy2)?;
        self.code.emit(|e| {
            e.ldr_uoff(Gpr::w(9), Gpr::x(10), 0)?;
            e.str_uoff(Gpr::w(9), Gpr::x(12), 0)?;
            e.add_imm(Gpr::x(10), Gpr::x(10), 4, false)?;
            e.add_imm(Gpr::x(12), Gpr::x(12), 4, false)?;
            e.sub_imm(Gpr::x(17), Gpr::x(17), 4, false)
        })?;
        self.code.bind(copy2)?;
        self.code.emit(|e| e.cmp_imm(Gpr::x(17), 2, false))?;
        self.code.b_cond(Cond::Cc, copy1)?;
        self.code.emit(|e| {
            e.ldrh_uoff(Gpr::x(9), Gpr::x(10), 0)?;
            e.strh_uoff(Gpr::x(9), Gpr::x(12), 0)?;
            e.add_imm(Gpr::x(10), Gpr::x(10), 2, false)?;
            e.add_imm(Gpr::x(12), Gpr::x(12), 2, false)?;
            e.sub_imm(Gpr::x(17), Gpr::x(17), 2, false)
        })?;
        self.code.bind(copy1)?;
        self.code.cbz(Gpr::x(17), copy_done)?;
        self.code.bind(copy)?;
        self.code.emit(|e| {
            e.ldrb_uoff(Gpr::x(9), Gpr::x(10), 0)?;
            e.strb_uoff(Gpr::x(9), Gpr::x(12), 0)?;
            e.add_imm(Gpr::x(10), Gpr::x(10), 1, false)?;
            e.add_imm(Gpr::x(12), Gpr::x(12), 1, false)?;
            e.sub_imm(Gpr::x(17), Gpr::x(17), 1, false)
        })?;
        self.code.cbnz(Gpr::x(17), copy)?;
        self.code.bind(copy_done)?;
        self.code.emit(|e| {
            e.ldr_uoff(FIELD_BITS, Gpr::x(8), 8)?;
            e.add_reg(START, START, FIELD_BITS, arinsal_a64::enc::Shift::Lsl, 0)?;
            e.str_uoff(START, CTX, 16)?;
            e.lsl_imm(Gpr::x(14), Gpr::x(14), 3)?;
            e.add_reg(
                Gpr::x(23),
                Gpr::x(8),
                Gpr::x(14),
                arinsal_a64::enc::Shift::Lsl,
                0,
            )?;
            e.orr_imm(Gpr::x(8), Gpr::x(8), 2)
        })?;
        self.store_register(dst, Gpr::x(8))?;
        self.code.b(done)?;
        self.code.bind(slow)?;
        self.emit_bs_helper(6, ctx, bits, unit, Some(dst), Some(fail), helper)?;
        self.code.bind(done)?;
        Ok(())
    }

    /// Byte-aligned UTF-8 scalar. Unaligned input uses the runtime hook.
    // Port of erts/emulator/beam/jit/arm/instr_bs.cpp:621-700 (emit_bs_get_utf8_short_shared)
    // and erl_bits.c:580 (UTF-8 match), OTP-29.1.1.
    fn emit_inline_utf8(
        &mut self,
        ctx: ArgVal,
        fail: u32,
        dst: Option<ArgVal>,
        helper: BsMatchHelper,
    ) -> Result<(), ModuleError> {
        let slow = self.code.new_label();
        let done = self.code.new_label();
        let ascii = self.code.new_label();
        let two = self.code.new_label();
        let three = self.code.new_label();
        let four = self.code.new_label();
        let store = self.code.new_label();
        let fail_label = (fail != 0).then(|| self.label(fail));
        let fail_or_slow = |this: &mut Self, cond: Cond| -> Result<(), ModuleError> {
            if let Some(label) = fail_label {
                this.code.b_cond(cond, label)?;
            } else {
                this.code.b_cond(cond, slow)?;
            }
            Ok(())
        };
        self.cursor(ctx)?;
        self.code.emit(|e| {
            e.sub_reg(TMP, END, START, arinsal_a64::enc::Shift::Lsl, 0)?;
            e.cmp_imm(TMP, 8, false)
        })?;
        fail_or_slow(self, Cond::Cc)?;
        self.code.emit(|e| e.tst_imm(START, 7))?;
        self.code.b_cond(Cond::Ne, slow)?;
        self.code.emit(|e| {
            e.ldr_uoff(Gpr::x(10), CTX, 8)?;
            e.and_imm(Gpr::x(10), Gpr::x(10), !3)?;
            e.add_reg(
                Gpr::x(10),
                Gpr::x(10),
                START,
                arinsal_a64::enc::Shift::Lsr,
                3,
            )?;
            e.ldrb_uoff(Gpr::x(8), Gpr::x(10), 0)
        })?;
        self.code.tbz(Gpr::x(8), 7, ascii)?;
        self.code.emit(|e| e.cmp_imm(Gpr::x(8), 0xc2, false))?;
        fail_or_slow(self, Cond::Cc)?;
        self.code.emit(|e| e.cmp_imm(Gpr::x(8), 0xdf, false))?;
        self.code.b_cond(Cond::Ls, two)?;
        self.code.emit(|e| e.cmp_imm(Gpr::x(8), 0xe0, false))?;
        fail_or_slow(self, Cond::Cc)?;
        self.code.emit(|e| e.cmp_imm(Gpr::x(8), 0xef, false))?;
        self.code.b_cond(Cond::Ls, three)?;
        self.code.emit(|e| e.cmp_imm(Gpr::x(8), 0xf0, false))?;
        fail_or_slow(self, Cond::Cc)?;
        self.code.emit(|e| e.cmp_imm(Gpr::x(8), 0xf4, false))?;
        fail_or_slow(self, Cond::Hi)?;
        self.code.b(four)?;
        self.code.bind(two)?;
        self.code.emit(|e| e.cmp_imm(TMP, 16, false))?;
        fail_or_slow(self, Cond::Cc)?;
        self.emit_utf8_continue(1, fail_label, slow)?;
        self.code.emit(|e| {
            e.and_imm(Gpr::x(8), Gpr::x(8), 0x1f)?;
            e.lsl_imm(Gpr::x(8), Gpr::x(8), 6)?;
            e.and_imm(Gpr::x(9), Gpr::x(9), 0x3f)?;
            e.orr_reg(
                Gpr::x(8),
                Gpr::x(8),
                arinsal_a64::enc::Shifted {
                    reg: Gpr::x(9),
                    shift: arinsal_a64::enc::Shift::Lsl,
                    amount: 0,
                },
            )?;
            e.mov_const(Gpr::x(12), 2)
        })?;
        self.code.b(store)?;
        self.code.bind(three)?;
        self.code.emit(|e| e.cmp_imm(TMP, 24, false))?;
        fail_or_slow(self, Cond::Cc)?;
        self.emit_utf8_continue(1, fail_label, slow)?;
        self.code.emit(|e| e.mov_reg(Gpr::x(17), Gpr::x(9)))?;
        self.emit_utf8_continue(2, fail_label, slow)?;
        self.code.emit(|e| {
            e.and_imm(Gpr::x(8), Gpr::x(8), 0x0f)?;
            e.lsl_imm(Gpr::x(8), Gpr::x(8), 12)?;
            e.and_imm(Gpr::x(17), Gpr::x(17), 0x3f)?;
            e.lsl_imm(Gpr::x(17), Gpr::x(17), 6)?;
            e.orr_reg(
                Gpr::x(8),
                Gpr::x(8),
                arinsal_a64::enc::Shifted {
                    reg: Gpr::x(17),
                    shift: arinsal_a64::enc::Shift::Lsl,
                    amount: 0,
                },
            )?;
            e.and_imm(Gpr::x(9), Gpr::x(9), 0x3f)?;
            e.orr_reg(
                Gpr::x(8),
                Gpr::x(8),
                arinsal_a64::enc::Shifted {
                    reg: Gpr::x(9),
                    shift: arinsal_a64::enc::Shift::Lsl,
                    amount: 0,
                },
            )?;
            e.mov_const(Gpr::x(12), 0x800)?;
            e.cmp_reg(Gpr::x(8), Gpr::x(12), arinsal_a64::enc::Shift::Lsl, 0)
        })?;
        fail_or_slow(self, Cond::Cc)?;
        let three_ok = self.code.new_label();
        self.code.emit(|e| {
            e.mov_const(Gpr::x(12), 0xd800)?;
            e.cmp_reg(Gpr::x(8), Gpr::x(12), arinsal_a64::enc::Shift::Lsl, 0)
        })?;
        self.code.b_cond(Cond::Cc, three_ok)?;
        self.code.emit(|e| {
            e.mov_const(Gpr::x(12), 0xdfff)?;
            e.cmp_reg(Gpr::x(8), Gpr::x(12), arinsal_a64::enc::Shift::Lsl, 0)
        })?;
        self.code.b_cond(Cond::Hi, three_ok)?;
        if let Some(label) = fail_label {
            self.code.b(label)?;
        } else {
            self.code.b(slow)?;
        }
        self.code.bind(three_ok)?;
        self.code.emit(|e| e.mov_const(Gpr::x(12), 3))?;
        self.code.b(store)?;
        self.code.bind(four)?;
        self.code.emit(|e| e.cmp_imm(TMP, 32, false))?;
        fail_or_slow(self, Cond::Cc)?;
        self.emit_utf8_continue(1, fail_label, slow)?;
        self.code.emit(|e| e.mov_reg(Gpr::x(17), Gpr::x(9)))?;
        self.emit_utf8_continue(2, fail_label, slow)?;
        self.code.emit(|e| e.mov_reg(Gpr::x(12), Gpr::x(9)))?;
        self.emit_utf8_continue(3, fail_label, slow)?;
        self.code.emit(|e| {
            e.and_imm(Gpr::x(8), Gpr::x(8), 0x07)?;
            e.lsl_imm(Gpr::x(8), Gpr::x(8), 18)?;
            e.and_imm(Gpr::x(17), Gpr::x(17), 0x3f)?;
            e.lsl_imm(Gpr::x(17), Gpr::x(17), 12)?;
            e.orr_reg(
                Gpr::x(8),
                Gpr::x(8),
                arinsal_a64::enc::Shifted {
                    reg: Gpr::x(17),
                    shift: arinsal_a64::enc::Shift::Lsl,
                    amount: 0,
                },
            )?;
            e.and_imm(Gpr::x(12), Gpr::x(12), 0x3f)?;
            e.lsl_imm(Gpr::x(12), Gpr::x(12), 6)?;
            e.orr_reg(
                Gpr::x(8),
                Gpr::x(8),
                arinsal_a64::enc::Shifted {
                    reg: Gpr::x(12),
                    shift: arinsal_a64::enc::Shift::Lsl,
                    amount: 0,
                },
            )?;
            e.and_imm(Gpr::x(9), Gpr::x(9), 0x3f)?;
            e.orr_reg(
                Gpr::x(8),
                Gpr::x(8),
                arinsal_a64::enc::Shifted {
                    reg: Gpr::x(9),
                    shift: arinsal_a64::enc::Shift::Lsl,
                    amount: 0,
                },
            )?;
            e.mov_const(Gpr::x(12), 0x10000)?;
            e.cmp_reg(Gpr::x(8), Gpr::x(12), arinsal_a64::enc::Shift::Lsl, 0)
        })?;
        fail_or_slow(self, Cond::Cc)?;
        self.code.emit(|e| {
            e.mov_const(Gpr::x(12), 0x10_ffff)?;
            e.cmp_reg(Gpr::x(8), Gpr::x(12), arinsal_a64::enc::Shift::Lsl, 0)
        })?;
        fail_or_slow(self, Cond::Hi)?;
        self.code.emit(|e| e.mov_const(Gpr::x(12), 4))?;
        self.code.b(store)?;
        self.code.bind(ascii)?;
        self.code.emit(|e| e.mov_const(Gpr::x(12), 1))?;
        self.code.bind(store)?;
        self.code.emit(|e| {
            e.lsl_imm(Gpr::x(9), Gpr::x(12), 3)?;
            e.add_reg(START, START, Gpr::x(9), arinsal_a64::enc::Shift::Lsl, 0)?;
            e.str_uoff(START, CTX, 16)
        })?;
        if let Some(dst) = dst {
            self.code.emit(|e| {
                e.lsl_imm(Gpr::x(8), Gpr::x(8), 4)?;
                e.orr_imm(Gpr::x(8), Gpr::x(8), 0xf)
            })?;
            self.store_register(dst, Gpr::x(8))?;
        }
        self.code.b(done)?;
        self.code.bind(slow)?;
        self.emit_bs_helper(
            11,
            ctx,
            ArgVal::Immediate(0),
            0,
            dst,
            (fail != 0).then_some(fail),
            helper,
        )?;
        self.code.bind(done)?;
        Ok(())
    }

    /// Loads one UTF-8 continuation byte at `offset` into `x9`, failing unless it is `10xxxxxx`.
    fn emit_utf8_continue(
        &mut self,
        offset: u16,
        fail: Option<arinsal_a64::buf::Label>,
        slow: arinsal_a64::buf::Label,
    ) -> Result<(), ModuleError> {
        self.code.emit(|e| {
            e.ldrb_uoff(Gpr::x(9), Gpr::x(10), offset)?;
            e.and_imm(END, Gpr::x(9), 0xc0)?;
            e.cmp_imm(END, 0x80, false)
        })?;
        if let Some(fail) = fail {
            self.code.b_cond(Cond::Ne, fail)?;
        } else {
            self.code.b_cond(Cond::Ne, slow)?;
        }
        Ok(())
    }
}
