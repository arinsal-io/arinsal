//! Inline list, tuple, and heap allocation emitters.

use arinsal_a64::enc::{Cond, Gpr};

use crate::{
    ProcessHeader, SchedulerRegisters,
    module::{ArgVal, BeamModuleAssembler, ModuleError},
};

const E: Gpr = Gpr::x(20);
const C_P: Gpr = Gpr::x(21);
const FCALLS: Gpr = Gpr::w(22);
const HTOP: Gpr = Gpr::x(23);
const SCHEDULER_REGS: Gpr = Gpr::x(19);
const XREGS: [Gpr; 6] = [
    Gpr::x(25),
    Gpr::x(26),
    Gpr::x(27),
    Gpr::x(28),
    Gpr::x(15),
    Gpr::x(16),
];
const SCRATCH: [Gpr; 6] = [
    Gpr::x(8),
    Gpr::x(9),
    Gpr::x(10),
    Gpr::x(11),
    Gpr::x(12),
    Gpr::x(13),
];
const NIL: u64 = 0x3b;
const TAG_BOXED: u64 = 2;
const RESERVED_WORDS: u32 = arinsal_term::S_RESERVED as u32;
// Port of erts/emulator/beam/jit/arm/instr_common.cpp:137-149 and erl_vm.h:120, OTP-29.1.1.
const MAX_LIVE_X_REGS: u32 = 1027;

/// GC callback used by emitted heap checks. It receives the minimum free-word
/// gap checked by the emitter, including the stack/heap reserve, and the live
/// X register count.
pub type GcHook =
    unsafe extern "C" fn(*mut ProcessHeader, *mut SchedulerRegisters, usize, usize, i32) -> i32;

impl BeamModuleAssembler {
    /// Builds a cons cell in the young heap and writes its tagged list pointer.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:707-722, OTP-29.1.1
    pub fn emit_put_list(
        &mut self,
        head: ArgVal,
        tail: ArgVal,
        dst: ArgVal,
    ) -> Result<(), ModuleError> {
        // Port of load_sources + stp into HTOP (instr_common.cpp:707-720): the source
        // registers are stored directly. The tagged pointer is subtracted into the
        // destination register.
        let head_reg = self.source_reg(head)?;
        let tail_scratch = if head_reg == Gpr::x(17) {
            SCRATCH[5]
        } else {
            Gpr::x(17)
        };
        let tail_reg = self.source_reg_into(tail, tail_scratch)?;
        let (dst_reg, store) = match dst {
            ArgVal::X(index) if index < 6 => (XREGS[index as usize], false),
            _ => (SCRATCH[4], true),
        };
        self.code.emit(|e| {
            e.stp_post(head_reg, tail_reg, HTOP, 16)?;
            e.sub_imm(dst_reg, HTOP, 15, false)
        })?;
        if store {
            self.store_arg(dst, dst_reg)?;
        }
        Ok(())
    }

    /// Builds a tuple whose elements are supplied in source order.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:794-872, OTP-29.1.1
    pub fn emit_put_tuple2(&mut self, dst: ArgVal, elements: &[ArgVal]) -> Result<(), ModuleError> {
        let arity = u64::try_from(elements.len())
            .map_err(|_| ModuleError::InvalidOperand("tuple arity overflow"))?;
        // The arity header is the first word of the object and is paired with the
        // following element, as erts does (instr_common.cpp:794-842).
        let mut words = Vec::with_capacity(elements.len() + 1);
        words.push(ArgVal::Immediate(arity << 6));
        words.extend_from_slice(elements);
        let mut index = 0;
        while index + 1 < words.len() {
            let first = self.source_reg(words[index])?;
            let second_scratch = if first == Gpr::x(17) {
                SCRATCH[3]
            } else {
                Gpr::x(17)
            };
            let second = self.source_reg_into(words[index + 1], second_scratch)?;
            self.code.emit(|e| e.stp_post(first, second, HTOP, 16))?;
            index += 2;
        }
        if index < words.len() {
            let last = self.source_reg(words[index])?;
            self.code.emit(|e| e.str_post(last, HTOP, 8))?;
        }
        let bytes = words
            .len()
            .checked_mul(8)
            .ok_or(ModuleError::InvalidOperand("tuple allocation overflow"))?;
        let tag_offset = u64::try_from(bytes)
            .ok()
            .and_then(|bytes| bytes.checked_sub(TAG_BOXED))
            .ok_or(ModuleError::InvalidOperand("tuple allocation overflow"))?;
        let (dst_reg, store) = match dst {
            ArgVal::X(index) if index < 6 => (XREGS[index as usize], false),
            _ => (SCRATCH[4], true),
        };
        self.emit_pointer_offset(dst_reg, HTOP, tag_offset, true)?;
        if store {
            self.store_arg(dst, dst_reg)?;
        }
        Ok(())
    }

    /// Loads a list head and tail, matching OTP's identical-destination rule.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:274-297, OTP-29.1.1
    pub fn emit_get_list(
        &mut self,
        src: ArgVal,
        head: ArgVal,
        tail: ArgVal,
    ) -> Result<(), ModuleError> {
        let list = self.source_reg(src)?;
        self.code.emit(|e| e.and_imm(SCRATCH[0], list, !7))?;
        if head == tail {
            let tdst = self.destination_reg(tail)?;
            self.code.emit(|e| e.ldr_uoff(tdst, SCRATCH[0], 8))?;
            self.store_arg(tail, tdst)
        } else {
            let hdst = match head {
                ArgVal::X(i) if i < 6 => XREGS[i as usize],
                _ => SCRATCH[2],
            };
            let tdst = match tail {
                ArgVal::X(i) if i < 6 => XREGS[i as usize],
                _ => SCRATCH[3],
            };
            self.code.emit(|e| e.ldp(hdst, tdst, SCRATCH[0], 0))?;
            self.store_arg(head, hdst)?;
            self.store_arg(tail, tdst)
        }
    }

    /// Loads the head word from a cons cell.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:299-307, OTP-29.1.1
    pub fn emit_get_hd(&mut self, src: ArgVal, dst: ArgVal) -> Result<(), ModuleError> {
        self.emit_list_field(src, dst, -1)
    }

    /// Loads the tail word from a cons cell.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:309-317, OTP-29.1.1
    pub fn emit_get_tl(&mut self, src: ArgVal, dst: ArgVal) -> Result<(), ModuleError> {
        self.emit_list_field(src, dst, 7)
    }

    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:299-317, OTP-29.1.1.
    fn emit_list_field(
        &mut self,
        src: ArgVal,
        dst: ArgVal,
        offset: i16,
    ) -> Result<(), ModuleError> {
        let list = self.source_reg(src)?;
        let out = self.destination_reg(dst)?;
        self.code.emit(|e| e.ldur(out, list, offset))?;
        self.store_arg(dst, out)
    }

    /// Loads an untagged tuple data pointer into ARG1 without clobbering `src`.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:351-355, OTP-29.1.1
    pub fn emit_load_tuple_ptr(&mut self, src: ArgVal, _dst: ArgVal) -> Result<(), ModuleError> {
        let tuple = self.source_reg(src)?;
        // OTP stores the untagged pointer in ARG1 (x0) and keeps the tagged term
        // in the source register. Overwriting X with an untagged pointer corrupts
        // later term uses (e.g. returning State after `inet_exit_port/3`).
        self.code.emit(|e| e.and_imm(Gpr::x(0), tuple, !7))?;
        Ok(())
    }

    /// Loads a tuple word at its byte offset from the tuple header.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:378-389, OTP-29.1.1
    pub fn emit_get_tuple_element(
        &mut self,
        _src: ArgVal,
        element: u32,
        dst: ArgVal,
    ) -> Result<(), ModuleError> {
        self.emit_tuple_element_load(Gpr::x(0), element, dst)
    }

    /// Loads a tuple word at its byte offset from an untagged tuple pointer.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:378-389, OTP-29.1.1
    pub fn emit_i_get_tuple_element2(
        &mut self,
        tuple_ptr: ArgVal,
        element: u32,
        dst: ArgVal,
    ) -> Result<(), ModuleError> {
        let ptr = self.source_reg(tuple_ptr)?;
        self.emit_tuple_element_load(ptr, element, dst)
    }

    fn emit_tuple_element_load(
        &mut self,
        ptr: Gpr,
        element: u32,
        dst: ArgVal,
    ) -> Result<(), ModuleError> {
        let out = self.destination_reg(dst)?;
        self.code.emit(|e| e.ldr_uoff(out, ptr, element))?;
        self.store_arg(dst, out)
    }

    /// Replaces a tuple word at its byte offset for legacy OTP bytecode.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:1105-1119, OTP-29.1.1
    pub fn emit_set_tuple_element(
        &mut self,
        element: ArgVal,
        tuple: ArgVal,
        offset: u32,
    ) -> Result<(), ModuleError> {
        let tuple_reg = self.source_reg(tuple)?;
        self.code.emit(|e| e.and_imm(SCRATCH[0], tuple_reg, !7))?;
        let value = self.source_reg_into(element, Gpr::x(17))?;
        let byte_offset = i16::try_from(offset)
            .map_err(|_| ModuleError::InvalidOperand("tuple offset exceeds immediate range"))?;
        self.code.emit(|e| e.stur(value, SCRATCH[0], byte_offset))?;
        Ok(())
    }

    /// Copies a tuple and applies one-based field updates inline.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:893-999, OTP-29.1.1
    pub fn emit_update_record(
        &mut self,
        src: ArgVal,
        dst: ArgVal,
        arity: u32,
        updates: &[(u32, ArgVal)],
    ) -> Result<(), ModuleError> {
        let tuple = self.source_reg(src)?;
        self.code.emit(|e| e.and_imm(SCRATCH[0], tuple, !7))?;
        self.code.emit(|e| e.ldr_post(SCRATCH[1], SCRATCH[0], 8))?;
        self.code.emit(|e| e.str_post(SCRATCH[1], HTOP, 8))?;
        for index in 0..arity {
            let field = index
                .checked_add(1)
                .ok_or(ModuleError::InvalidOperand("tuple offset overflow"))?;
            let update = updates
                .iter()
                .find(|(update_index, _)| *update_index == field);
            if let Some((_, value)) = update {
                let val = self.source_reg(*value)?;
                self.code.emit(|e| e.mov_reg(SCRATCH[2], val))?;
            } else {
                let offset = index
                    .checked_mul(8)
                    .ok_or(ModuleError::InvalidOperand("tuple offset overflow"))?;
                self.code
                    .emit(|e| e.ldr_uoff(SCRATCH[2], SCRATCH[0], offset))?;
            }
            self.code.emit(|e| e.str_post(SCRATCH[2], HTOP, 8))?;
        }
        let tuple_words = arity
            .checked_add(1)
            .ok_or(ModuleError::InvalidOperand("tuple allocation overflow"))?;
        let bytes = u64::from(tuple_words) * 8;
        self.emit_pointer_offset(SCRATCH[4], HTOP, bytes - TAG_BOXED, true)?;
        self.store_arg(dst, SCRATCH[4])
    }

    /// Updates tuple fields in place when the heap boundary makes mutation safe.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:1000-1096, OTP-29.1.1.
    pub fn emit_update_record_in_place(
        &mut self,
        src: ArgVal,
        dst: ArgVal,
        arity: u32,
        updates: &[(u32, ArgVal)],
    ) -> Result<(), ModuleError> {
        if arity < 2 {
            return Err(ModuleError::InvalidOperand(
                "in-place tuple update requires arity above one",
            ));
        }
        let mut previous = 0;
        for (index, _) in updates {
            if *index <= previous || *index > arity {
                return Err(ModuleError::InvalidOperand(
                    "in-place tuple update indices must be ordered and in range",
                ));
            }
            previous = *index;
        }

        let tuple = self.source_reg(src)?;
        self.code.emit(|e| e.and_imm(SCRATCH[0], tuple, !7))?;

        // Immediate values cannot retain aliases into another tuple, so OTP
        // may update those tuples directly. Register and stack values need the
        // high-water check because they may point into the heap.
        let all_safe = updates
            .iter()
            .all(|(_, value)| matches!(value, ArgVal::Immediate(_) | ArgVal::Literal(_)));
        if !all_safe && !updates.is_empty() {
            let update = self.code.new_label();
            let copy = self.code.new_label();
            let words = arity
                .checked_add(1)
                .ok_or(ModuleError::InvalidOperand("tuple allocation overflow"))?;
            let bytes = u64::from(words)
                .checked_mul(8)
                .ok_or(ModuleError::InvalidOperand("tuple allocation overflow"))?;
            self.code.emit(|e| {
                e.ldr_uoff(
                    SCRATCH[4],
                    C_P,
                    std::mem::offset_of!(ProcessHeader, high_water) as u32,
                )?;
                e.cmp_reg(SCRATCH[0], HTOP, arinsal_a64::enc::Shift::Lsl, 0)
            })?;
            // Only a tuple built since the last collection (high_water <= src < HTOP) may be
            // mutated; anything else (older generation, fragments) is copied first.
            self.code.b_cond(Cond::Cs, copy)?;
            self.code
                .emit(|e| e.cmp_reg(SCRATCH[0], SCRATCH[4], arinsal_a64::enc::Shift::Lsl, 0))?;
            self.code.b_cond(Cond::Cs, update)?;
            self.code.bind(copy)?;
            self.code
                .emit(|e| e.mov_const(SCRATCH[5], u64::from(words)))?;
            let copy_loop = self.code.new_label();
            self.code.bind(copy_loop)?;
            self.code.emit(|e| {
                e.ldr_post(SCRATCH[2], SCRATCH[0], 8)?;
                e.str_post(SCRATCH[2], HTOP, 8)?;
                e.subs_imm(SCRATCH[5], SCRATCH[5], 1, false)
            })?;
            self.code.b_cond(Cond::Ne, copy_loop)?;
            self.emit_pointer_offset(SCRATCH[0], HTOP, bytes, true)?;
            self.code.bind(update)?;
        }

        for (index, value) in updates {
            let value = self.source_reg(*value)?;
            self.code.emit(|e| e.mov_reg(SCRATCH[2], value))?;
            let offset = u64::from(*index)
                .checked_mul(8)
                .ok_or(ModuleError::InvalidOperand("tuple offset overflow"))?;
            self.emit_pointer_offset(SCRATCH[1], SCRATCH[0], offset, false)?;
            self.code.emit(|e| e.str_uoff(SCRATCH[2], SCRATCH[1], 0))?;
        }
        self.code
            .emit(|e| e.add_imm(SCRATCH[4], SCRATCH[0], TAG_BOXED as u16, false))?;
        self.store_arg(dst, SCRATCH[4])
    }

    /// `os:perf_counter/0` as an instruction: calls the performance counter `clock` directly
    /// and tags its value, boxing it as a one-digit bignum when it is not a small.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:3126-3164 (emit_i_perf_counter),
    // OTP-29.1.1.
    pub fn emit_i_perf_counter(&mut self, clock: usize, hook: GcHook) -> Result<(), ModuleError> {
        if clock == 0 {
            return Err(ModuleError::InvalidOperand("perf counter clock is missing"));
        }
        let next = self.code.new_label();
        let small = self.code.new_label();
        // No X register is live after a call, and the clock touches no process state.
        crate::emit_enter_runtime(&mut self.code, 0, crate::Update::NONE)?;
        self.code.emit(|e| {
            e.mov_const(Gpr::x(17), clock as u64)?;
            e.str_uoff(Gpr::x(30), C_P, 72)?;
            e.blr(Gpr::x(17))
        })?;
        crate::emit_leave_runtime(&mut self.code, 0, crate::Update::NONE)?;
        self.code.emit(|e| {
            e.ldr_uoff(Gpr::x(30), C_P, 72)?;
            // A small has SMALL_BITS (60) bits: the top five bits must all be equal.
            e.asr_imm(SCRATCH[0], Gpr::x(0), 59)?;
            e.add_imm(SCRATCH[0], SCRATCH[0], 1, false)?;
            e.cmp_imm(SCRATCH[0], 1, false)
        })?;
        self.code.b_cond(Cond::Ls, small)?;
        // XREG0 is callee-saved, so the raw counter survives the collection that keeps no
        // X register live.
        self.code.emit(|e| e.mov_reg(XREGS[0], Gpr::x(0)))?;
        // ERTS_MAX_UINT64_HEAP_SIZE: a header and one digit.
        self.emit_heap_check(0, 2, 0, hook)?;
        self.code.emit(|e| {
            // make_pos_bignum_header(1)
            e.mov_const(SCRATCH[0], (1 << 6) | 0x08)?;
            e.stp_post(SCRATCH[0], XREGS[0], HTOP, 16)?;
            e.sub_imm(XREGS[0], HTOP, 16 - TAG_BOXED as u16, false)
        })?;
        self.code.b(next)?;
        self.code.bind(small)?;
        self.code.emit(|e| {
            e.lsl_imm(Gpr::x(0), Gpr::x(0), 4)?;
            e.orr_imm(XREGS[0], Gpr::x(0), 0xf)
        })?;
        self.code.bind(next)?;
        Ok(())
    }

    /// Checks available heap space and calls the GC hook on the slow path.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:90-122 and beam_asm_global.cpp:102-140, OTP-29.1.1
    pub fn emit_test_heap(
        &mut self,
        words: u32,
        live: u32,
        hook: GcHook,
    ) -> Result<(), ModuleError> {
        self.emit_heap_check(0, words, live, hook)
    }

    /// Checks heap space, allocates heap words inline, and reserves stack words.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:206-218 and beam_asm_global.cpp:102-140, OTP-29.1.1
    pub fn emit_allocate_heap(
        &mut self,
        stack_words: u32,
        heap_words: u32,
        live: u32,
        hook: GcHook,
    ) -> Result<(), ModuleError> {
        self.emit_heap_check(stack_words, heap_words, live, hook)?;
        if stack_words != 0 {
            let bytes = stack_words
                .checked_mul(8)
                .ok_or(ModuleError::InvalidOperand("stack allocation overflow"))?;
            self.emit_pointer_offset(E, E, u64::from(bytes), true)?;
        }
        Ok(())
    }

    /// Allocates heap and stack space, then initializes each new stack slot to nil.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:206-218 and erts/emulator/beam/emu/instrs.tab:53, OTP-29.1.1
    pub fn emit_allocate_heap_zero(
        &mut self,
        stack_words: u32,
        heap_words: u32,
        live: u32,
        hook: GcHook,
    ) -> Result<(), ModuleError> {
        self.emit_allocate_heap(stack_words, heap_words, live, hook)?;
        self.code.emit(|e| e.mov_const(SCRATCH[0], NIL))?;
        for index in 0..stack_words {
            let offset = index
                .checked_mul(8)
                .ok_or(ModuleError::InvalidOperand("stack offset overflow"))?;
            self.code.emit(|e| e.str_uoff(SCRATCH[0], E, offset))?;
        }
        Ok(())
    }

    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:90-120, OTP-29.1.1.
    fn emit_heap_check(
        &mut self,
        stack_words: u32,
        heap_words: u32,
        live: u32,
        hook: GcHook,
    ) -> Result<(), ModuleError> {
        if live >= MAX_LIVE_X_REGS {
            return Err(ModuleError::InvalidOperand(
                "live X count exceeds OTP register allocation",
            ));
        }
        let requested_words = stack_words
            .checked_add(heap_words)
            .ok_or(ModuleError::InvalidOperand("heap check size overflow"))?;
        let need = requested_words
            .checked_add(RESERVED_WORDS)
            .ok_or(ModuleError::InvalidOperand("heap check size overflow"))?;
        let bytes = need
            .checked_mul(8)
            .ok_or(ModuleError::InvalidOperand("heap check size overflow"))?;
        let done = self.code.new_label();
        self.emit_pointer_offset(SCRATCH[0], HTOP, u64::from(bytes), false)?;
        self.code
            .emit(|e| e.cmp_reg(SCRATCH[0], E, arinsal_a64::enc::Shift::Lsl, 0))?;
        self.code.b_cond(Cond::Ls, done)?;
        // Port of erts/emulator/beam/jit/arm/beam_asm_global.cpp:99-129, OTP-29.1.1.
        let update = crate::Update::HEAP_ALLOC.union(crate::Update::X_REGS);
        crate::emit_enter_runtime(&mut self.code, live as usize, update)?;
        self.code.emit(|e| {
            e.str_uoff(Gpr::x(30), C_P, 72)?;
            e.mov_reg(Gpr::x(0), C_P)?;
            e.mov_reg(Gpr::x(1), SCHEDULER_REGS)?;
            // The slow path must see the same minimum as the fast-path check;
            // otherwise ensure() can skip collection while E is inside the reserve.
            e.mov_const(Gpr::x(2), need as u64)?;
            e.mov_const(Gpr::x(3), live as u64)?;
            e.mov_reg(Gpr::w(4), FCALLS)?;
            e.mov_const(Gpr::x(17), hook as usize as u64)?;
            e.blr(Gpr::x(17))
        })?;
        crate::emit_leave_runtime(&mut self.code, live as usize, update)?;
        self.code.emit(|e| {
            e.sub_reg(FCALLS, FCALLS, Gpr::w(0), arinsal_a64::enc::Shift::Lsl, 0)?;
            e.ldr_uoff(Gpr::x(30), C_P, 72)?;
            e.ldr_uoff(Gpr::x(9), C_P, 40)
        })?;
        self.error_if_nonzero(Gpr::x(9))?;
        self.code.bind(done)?;
        Ok(())
    }

    pub(super) fn emit_stack_check(
        &mut self,
        stack_words: u32,
        live: u32,
        hook: GcHook,
    ) -> Result<(), ModuleError> {
        self.emit_heap_check(stack_words, 0, live, hook)
    }

    fn destination_reg(&self, dst: ArgVal) -> Result<Gpr, ModuleError> {
        match dst {
            ArgVal::X(i) if i < 6 => Ok(XREGS[i as usize]),
            _ => Ok(SCRATCH[5]),
        }
    }

    fn emit_pointer_offset(
        &mut self,
        dst: Gpr,
        base: Gpr,
        bytes: u64,
        subtract: bool,
    ) -> Result<(), ModuleError> {
        if bytes == 0 {
            self.code.emit(|e| e.mov_reg(dst, base))?;
        } else if bytes <= 4095 {
            let imm = bytes as u16;
            self.code.emit(|e| {
                if subtract {
                    e.sub_imm(dst, base, imm, false)
                } else {
                    e.add_imm(dst, base, imm, false)
                }
            })?;
        } else if bytes.is_multiple_of(4096) && bytes / 4096 <= 4095 {
            let imm = (bytes / 4096) as u16;
            self.code.emit(|e| {
                if subtract {
                    e.sub_imm(dst, base, imm, true)
                } else {
                    e.add_imm(dst, base, imm, true)
                }
            })?;
        } else {
            self.code.emit(|e| {
                e.mov_const(SCRATCH[1], bytes)?;
                if subtract {
                    e.sub_reg(dst, base, SCRATCH[1], arinsal_a64::enc::Shift::Lsl, 0)
                } else {
                    e.add_reg(dst, base, SCRATCH[1], arinsal_a64::enc::Shift::Lsl, 0)
                }
            })?;
        }
        Ok(())
    }

    fn store_arg(&mut self, dst: ArgVal, src: Gpr) -> Result<(), ModuleError> {
        self.store_operand(dst, src)
    }
}
