//! Inline list, tuple, and heap allocation emitters.

use arinsal_a64::enc::{Cond, Gpr, VecReg};

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
const SUPER_TMP: Gpr = Gpr::x(17);
const NIL: u64 = 0x3b;
const TAG_BOXED: u64 = 2;
const RESERVED_WORDS: u32 = arinsal_term::S_RESERVED as u32;
// Port of erts/emulator/beam/jit/arm/instr_common.cpp:137-149 and erl_vm.h:120, OTP-29.1.1.
const MAX_LIVE_X_REGS: u32 = 1027;
const MAX_REGISTER_X: usize = 6;

/// GC callback used by emitted heap checks. It receives the raw allocation
/// need and the live X register count; the reserve belongs to the heap check.
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
        let (head_reg, tail_reg) = self.load_two_sources(head, SCRATCH[0], tail, SCRATCH[1])?;
        let dst = self.pair_destination(dst, SCRATCH[2])?;
        self.preserve_cache(&[], |this| {
            this.code.emit(|e| {
                e.stp_post(head_reg, tail_reg, HTOP, 16)?;
                e.sub_imm(dst.reg, HTOP, 15, false)
            })?;
            Ok(())
        })?;
        self.flush_var(dst)
    }

    /// `put_list` fused with a deallocation: the Y0 operand is read with a post-index `ldr` that
    /// also pops the frame.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:723-773 (emit_put_list_deallocate),
    // OTP-29.1.1.
    pub fn emit_put_list_deallocate(
        &mut self,
        head: ArgVal,
        tail: ArgVal,
        dst: ArgVal,
        words: u32,
    ) -> Result<(), ModuleError> {
        let mut dealloc = i64::from(words) * 8;
        let dst = self.pair_destination(dst, SCRATCH[2])?;
        let fits = dealloc > 0 && dealloc < 256;
        let mut regs = None;
        if fits && let (ArgVal::Y(0), false) = (head, matches!(tail, ArgVal::Y(_))) {
            self.code
                .emit(|e| e.ldr_post(SCRATCH[0], E, dealloc as i16))?;
            let tail_reg = self.source_reg_into(tail, SCRATCH[1])?;
            regs = Some((SCRATCH[0], tail_reg));
            dealloc = 0;
        } else if fits && let (false, ArgVal::Y(0)) = (matches!(head, ArgVal::Y(_)), tail) {
            self.code
                .emit(|e| e.ldr_post(SCRATCH[1], E, dealloc as i16))?;
            let head_reg = self.source_reg_into(head, SCRATCH[0])?;
            regs = Some((head_reg, SCRATCH[1]));
            dealloc = 0;
        }
        let (head_reg, tail_reg) = match regs {
            Some(regs) => regs,
            None => self.load_two_sources(head, SCRATCH[0], tail, SCRATCH[1])?,
        };
        self.code.emit(|e| {
            e.stp_post(head_reg, tail_reg, HTOP, 16)?;
            e.sub_imm(dst.reg, HTOP, 15, false)
        })?;
        self.flush_var(dst)?;
        if dealloc > 0 {
            self.deallocate(words)?;
        }
        Ok(())
    }

    /// Builds two cons cells at once, the second one with the first as its tail.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:775-792 (emit_put_list2), OTP-29.1.1.
    pub fn emit_put_list2(
        &mut self,
        head1: ArgVal,
        head2: ArgVal,
        tail: ArgVal,
        dst: ArgVal,
    ) -> Result<(), ModuleError> {
        let (hd1, hd2) = self.load_two_sources(head1, SCRATCH[0], head2, SCRATCH[1])?;
        let tl = self.source_reg_into(tail, SCRATCH[2])?;
        let dst = self.pair_destination(dst, SCRATCH[3])?;
        self.code.emit(|e| {
            e.stp_post(hd1, tl, HTOP, 16)?;
            e.sub_imm(dst.reg, HTOP, 15, false)?;
            e.stp_post(hd2, dst.reg, HTOP, 16)?;
            e.sub_imm(dst.reg, HTOP, 15, false)
        })?;
        self.flush_var(dst)
    }

    /// Builds a tuple whose elements are supplied in source order.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:794-872, OTP-29.1.1
    pub fn emit_put_tuple2(&mut self, dst: ArgVal, elements: &[ArgVal]) -> Result<(), ModuleError> {
        let arity = u64::try_from(elements.len())
            .map_err(|_| ModuleError::InvalidOperand("tuple arity overflow"))?;
        let mut data = Vec::with_capacity(elements.len() + 1);
        data.push(ArgVal::Immediate(arity << 6));
        data.extend_from_slice(elements);
        let size = data.len();
        let mut value: Option<ArgVal> = None;
        let mut index = 0;
        while index + 1 < size {
            if index % 128 == 0 {
                self.check_pending_stubs()?;
            }
            let (first, second) = (data[index], data[index + 1]);
            let is_register =
                |arg: ArgVal| matches!(arg, ArgVal::X(_) | ArgVal::XMemory(_) | ArgVal::Y(_));
            let (left, right) = if !is_register(first) && first == second {
                if value != Some(first) {
                    value = Some(first);
                    self.mov_arg_to_reg(SCRATCH[0], first)?;
                }
                (SCRATCH[0], SCRATCH[0])
            } else if value == Some(first) {
                let second = self.source_reg_into(second, SCRATCH[2])?;
                (SCRATCH[0], second)
            } else if value == Some(second) {
                let first = self.source_reg_into(first, SCRATCH[1])?;
                (first, SCRATCH[0])
            } else {
                self.load_two_sources(first, SCRATCH[1], second, SCRATCH[2])?
            };
            self.code.emit(|e| e.stp_post(left, right, HTOP, 16))?;
            index += 2;
        }
        if index < size {
            if value == Some(data[index]) {
                self.code.emit(|e| e.str_post(SCRATCH[0], HTOP, 8))?;
            } else {
                let last = self.source_reg_into(data[index], Gpr::x(17))?;
                self.code.emit(|e| e.str_post(last, HTOP, 8))?;
            }
        }
        let bytes = size
            .checked_mul(8)
            .ok_or(ModuleError::InvalidOperand("tuple allocation overflow"))?;
        let tag_offset = u64::try_from(bytes)
            .ok()
            .and_then(|bytes| bytes.checked_sub(TAG_BOXED))
            .ok_or(ModuleError::InvalidOperand("tuple allocation overflow"))?;
        let ptr = self.pair_destination(dst, SCRATCH[0])?;
        self.emit_pointer_offset(ptr.reg, HTOP, tag_offset, true)?;
        self.flush_var(ptr)
    }

    /// Loads a list head and tail, matching OTP's identical-destination rule.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:274-297, OTP-29.1.1
    pub fn emit_get_list(
        &mut self,
        src: ArgVal,
        head: ArgVal,
        tail: ArgVal,
    ) -> Result<(), ModuleError> {
        let list = self.load_source_any(src, SCRATCH[0], &[])?;
        self.preserve_cache(&[SCRATCH[0]], |this| {
            this.code.emit(|e| e.and_imm(SCRATCH[0], list, !7))?;
            Ok(())
        })?;
        let hd = self.pair_destination(head, SCRATCH[1])?;
        let tl = self.pair_destination(tail, SCRATCH[2])?;
        if hd.reg == tl.reg {
            self.code.emit(|e| e.ldr_uoff(tl.reg, SCRATCH[0], 8))?;
            self.flush_var(tl)
        } else {
            self.preserve_cache(&[], |this| {
                this.code.emit(|e| e.ldp(hd.reg, tl.reg, SCRATCH[0], 0))?;
                Ok(())
            })?;
            self.flush_vars(hd, tl)
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
        let list = self.load_source_any(src, SCRATCH[0], &[])?;
        let out = self.pair_destination(dst, SCRATCH[1])?;
        self.code.emit(|e| e.ldur(out.reg, list, offset))?;
        self.flush_var(out)
    }

    /// Loads an untagged tuple data pointer into ARG1 without clobbering `src`.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:351-355, OTP-29.1.1
    pub fn emit_load_tuple_ptr(&mut self, src: ArgVal, _dst: ArgVal) -> Result<(), ModuleError> {
        let tuple = self.load_source_any(src, SCRATCH[0], &[])?;
        // OTP stores the untagged pointer in ARG1 (x0) and keeps the tagged term
        // in the source register. Overwriting X with an untagged pointer corrupts
        // later term uses (e.g. returning State after `inet_exit_port/3`).
        self.preserve_cache(&[Gpr::x(0)], |this| {
            this.code.emit(|e| e.and_imm(Gpr::x(0), tuple, !7))?;
            Ok(())
        })
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

    /// Loads a tuple word into `other_dst` after moving `other_dst` into `dst`: the fused form of
    /// an element load followed by a swap.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:390-405 (emit_get_tuple_element_swap),
    // OTP-29.1.1.
    pub fn emit_get_tuple_element_swap(
        &mut self,
        _src: ArgVal,
        element: u32,
        dst: ArgVal,
        other_dst: ArgVal,
    ) -> Result<(), ModuleError> {
        self.move_(other_dst, dst)?;
        self.emit_tuple_element_load(Gpr::x(0), element, other_dst)
    }

    /// Loads two consecutive tuple words from the untagged tuple pointer in ARG1 with one `ldp`.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:408-421 (emit_get_two_tuple_elements),
    // OTP-29.1.1.
    pub fn emit_get_two_tuple_elements(
        &mut self,
        _src: ArgVal,
        element: u32,
        dst1: ArgVal,
        dst2: ArgVal,
    ) -> Result<(), ModuleError> {
        let first = self.pair_destination(dst1, Gpr::x(9))?;
        let second = self.pair_destination(dst2, Gpr::x(10))?;
        self.safe_ldp(first.reg, second.reg, Gpr::x(0), element)?;
        self.flush_vars(first, second)
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

    /// Copies `count` words from `from` to `to`, advancing both: 32 bytes per `ldp`/`stp` of
    /// `q30`/`q31`, a counted loop above 16 words, then a 16 byte move and a single word.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp (emit_copy_words_increment),
    // OTP-29.1.1.
    fn emit_copy_words_increment(
        &mut self,
        from: Gpr,
        to: Gpr,
        mut count: usize,
    ) -> Result<(), ModuleError> {
        self.check_pending_stubs()?;
        let q30 = VecReg(30);
        let q31 = VecReg(31);
        if count <= 16 {
            while count >= 4 {
                self.code.emit(|e| {
                    e.ldp_q_post(q30, q31, from, 32)?;
                    e.stp_q_post(q30, q31, to, 32)
                })?;
                count -= 4;
            }
        } else {
            let iterations = u64::try_from(count / 4)
                .ok()
                .filter(|iterations| *iterations <= 0xffff)
                .ok_or(ModuleError::InvalidOperand("tuple copy too large"))?;
            let copy_next = self.code.new_label();
            self.code.emit(|e| e.mov_const(SUPER_TMP, iterations))?;
            self.code.bind(copy_next)?;
            self.code.emit(|e| {
                e.ldp_q_post(q30, q31, from, 32)?;
                e.stp_q_post(q30, q31, to, 32)?;
                e.subs_imm(SUPER_TMP, SUPER_TMP, 1, false)
            })?;
            self.code.b_cond(Cond::Ne, copy_next)?;
            count %= 4;
        }
        if count >= 2 {
            self.code.emit(|e| {
                e.ldr_q_post(q30, from, 16)?;
                e.str_q_post(q30, to, 16)
            })?;
            count -= 2;
        }
        if count == 1 {
            self.code.emit(|e| {
                e.ldr_post(SUPER_TMP, from, 8)?;
                e.str_post(SUPER_TMP, to, 8)
            })?;
        }
        Ok(())
    }

    /// Copies a tuple and applies one-based field updates inline. With the `reuse` hint and a
    /// single update that stores the value already in the field, the source tuple is the result
    /// and nothing is allocated.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp (emit_update_record), OTP-29.1.1.
    pub fn emit_update_record(
        &mut self,
        reuse: bool,
        src: ArgVal,
        dst: ArgVal,
        arity: u32,
        updates: &[(u32, ArgVal)],
    ) -> Result<(), ModuleError> {
        let size_on_heap = arity
            .checked_add(1)
            .ok_or(ModuleError::InvalidOperand("tuple allocation overflow"))?
            as usize;
        if size_on_heap <= 2 {
            return Err(ModuleError::InvalidOperand(
                "tuple update requires arity above one",
            ));
        }
        let mut previous = 0;
        for (index, _) in updates {
            if *index <= previous || *index > arity {
                return Err(ModuleError::InvalidOperand(
                    "tuple update indices must be ordered and in range",
                ));
            }
            previous = *index;
        }
        let tmp1 = SCRATCH[2];
        let tmp2 = SCRATCH[3];
        let tmp3 = SCRATCH[4];
        let next = self.code.new_label();

        let destination = self.pair_destination(dst, SCRATCH[5])?;
        let source = self.source_reg_into(src, SCRATCH[1])?;
        let untagged_src = SCRATCH[0];
        self.code.emit(|e| e.and_imm(untagged_src, source, !7))?;

        if reuse && updates.len() == 1 {
            let (index, value) = updates[0];
            let offset = index
                .checked_mul(8)
                .ok_or(ModuleError::InvalidOperand("tuple offset overflow"))?;
            self.code.emit(|e| e.ldr_uoff(tmp1, untagged_src, offset))?;
            self.cmp_arg(tmp1, value)?;
            if destination.reg != source {
                self.code
                    .emit(|e| e.csel(destination.reg, destination.reg, source, Cond::Ne))?;
            }
            self.code.b_cond(Cond::Eq, next)?;
        }

        let mut copy_index = 0usize;
        let mut i = 0;
        while i < updates.len() {
            let (next_index, next_value) = updates[i];
            let next_index = next_index as usize;
            let odd_copy = (next_index - copy_index) & 1 == 1;
            self.emit_copy_words_increment(untagged_src, HTOP, (next_index - copy_index) & !1)?;

            if let Some(&(adjacent_index, adjacent_value)) = updates.get(i + 1)
                && adjacent_index as usize == next_index + 1
            {
                let (first, second) =
                    self.load_two_sources(next_value, tmp1, adjacent_value, tmp2)?;
                if odd_copy {
                    self.code.emit(|e| {
                        e.ldr_post(tmp3, untagged_src, 24)?;
                        e.stp_post(tmp3, first, HTOP, 16)?;
                        e.str_post(second, HTOP, 8)
                    })?;
                } else {
                    self.code.emit(|e| {
                        e.add_imm(untagged_src, untagged_src, 16, false)?;
                        e.stp_post(first, second, HTOP, 16)
                    })?;
                }
                copy_index = next_index + 2;
                i += 2;
                continue;
            }

            let value = self.source_reg_into(next_value, tmp1)?;
            if odd_copy {
                self.code.emit(|e| {
                    e.ldr_post(tmp2, untagged_src, 16)?;
                    e.stp_post(tmp2, value, HTOP, 16)
                })?;
            } else {
                self.code.emit(|e| {
                    e.add_imm(untagged_src, untagged_src, 8, false)?;
                    e.str_post(value, HTOP, 8)
                })?;
            }
            copy_index = next_index + 1;
            i += 1;
        }

        self.emit_copy_words_increment(untagged_src, HTOP, size_on_heap - copy_index)?;
        let bytes = size_on_heap as u64 * 8;
        self.emit_pointer_offset(destination.reg, HTOP, bytes - TAG_BOXED, true)?;
        self.code.bind(next)?;
        self.flush_var(destination)
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
            self.emit_copy_words_increment(SCRATCH[0], HTOP, words as usize)?;
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
        self.code
            .emit(|e| e.mov_const(Gpr::x(3), u64::from(live)))?;
        self.gc_fragment_call(hook as usize)?;
        self.code.bind(done)?;
        Ok(())
    }

    /// Emits the shared garbage-collection fragment called by every heap and stack check.
    ///
    /// ARG3 (x8) is `HTOP` plus the reserve and the bytes needed, ARG4 (x3) the live X count.
    /// The reserve is removed again: the collector adds it itself.
    // Port of erts/emulator/beam/jit/arm/beam_asm_global.cpp:99-129 (emit_garbage_collect),
    // OTP-29.1.1.
    pub(super) fn emit_garbage_collect_fragment(&mut self, hook: usize) -> Result<(), ModuleError> {
        let error = self.code.new_label();
        let update = crate::Update::HEAP_ALLOC.union(crate::Update::X_REGS);
        self.code
            .emit(|e| e.stp_pre(Gpr::x(29), Gpr::x(30), Gpr::sp(), -16))?;
        self.code.emit(|e| {
            e.sub_reg(Gpr::x(2), SCRATCH[0], HTOP, arinsal_a64::enc::Shift::Lsl, 0)?;
            e.lsr_imm(Gpr::x(2), Gpr::x(2), 3)?;
            e.sub_imm(Gpr::x(2), Gpr::x(2), RESERVED_WORDS as u16, false)?;
            e.str_uoff(Gpr::x(30), C_P, 72)
        })?;
        crate::emit_enter_runtime(&mut self.code, MAX_REGISTER_X, update)?;
        self.code.emit(|e| {
            e.mov_reg(Gpr::x(0), C_P)?;
            e.mov_reg(Gpr::x(1), SCHEDULER_REGS)?;
            e.mov_reg(Gpr::w(4), FCALLS)?;
            e.mov_const(Gpr::x(17), hook as u64)?;
            e.blr(Gpr::x(17))
        })?;
        crate::emit_leave_runtime(&mut self.code, MAX_REGISTER_X, update)?;
        self.code.emit(|e| {
            e.sub_reg(FCALLS, FCALLS, Gpr::w(0), arinsal_a64::enc::Shift::Lsl, 0)?;
            e.ldp_post(Gpr::x(29), Gpr::x(30), Gpr::sp(), 16)?;
            e.ldr_uoff(Gpr::x(9), C_P, 40)
        })?;
        self.code.cbnz(Gpr::x(9), error)?;
        self.code.emit(|e| e.ret(Gpr::x(30)))?;
        self.code.bind(error)?;
        self.code
            .emit(|e| e.sub_imm(Gpr::x(30), Gpr::x(30), 4, false))?;
        self.branch_error_from_lr()
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
