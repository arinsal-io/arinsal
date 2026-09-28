//! Catch records, exception transfer, and error instructions.

use arinsal_a64::enc::Gpr;

use crate::{
    ProcessHeader, SchedulerRegisters,
    module::{ArgVal, BeamModuleAssembler, ModuleError},
};

const E: Gpr = Gpr::x(20);
const C_P: Gpr = Gpr::x(21);
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
const TMP: Gpr = Gpr::x(9);
const TMP2: Gpr = Gpr::x(10);
const TMP3: Gpr = Gpr::x(11);
const NIL: u64 = 0x3b;
const TAG_IMMED2_CATCH: u64 = 0x1b;

/// Resolves an exception against the process catch chain and returns a native handler address.
/// A zero result means that the exception is uncaught and should return to the runtime.
pub type ExceptionResolver =
    extern "C" fn(*mut ProcessHeader, *mut SchedulerRegisters, *mut u64) -> usize;

/// Builds the OTP immediate stored in a Y slot for catch number `number`.
// Port of erts/emulator/beam/erl_term.h:1385-1386, OTP-29.1.1
pub const fn make_catch(number: u32) -> u64 {
    ((number as u64) << 6) | TAG_IMMED2_CATCH
}

impl BeamModuleAssembler {
    /// Registers a catch handler and stores its `make_catch` tag in the supplied Y slot.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:2855-2862 and beam_jit_common.cpp:507-530, OTP-29.1.1
    pub fn emit_catch(&mut self, y: ArgVal, handler: u32) -> Result<(), ModuleError> {
        self.emit_catch_inner(y, handler, false)
    }

    /// Registers a catch with the frame base needed for direct native unwinding.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:2855-2862, OTP-29.1.1
    pub fn emit_native_catch(&mut self, y: ArgVal, handler: u32) -> Result<(), ModuleError> {
        self.emit_catch_inner(y, handler, true)
    }

    fn emit_catch_inner(
        &mut self,
        y: ArgVal,
        handler: u32,
        save_frame_base: bool,
    ) -> Result<(), ModuleError> {
        let ArgVal::Y(slot) = y else {
            return Err(ModuleError::InvalidOperand(
                "catch tag destination must be a Y register",
            ));
        };
        let offset = slot
            .checked_mul(8)
            .ok_or(ModuleError::InvalidOperand("catch Y offset overflow"))?;
        let code_label = self.label(handler);

        if save_frame_base {
            let handler_offset = offset
                .checked_add(8)
                .ok_or(ModuleError::InvalidOperand("catch Y offset overflow"))?;
            let prev_offset = offset
                .checked_add(16)
                .ok_or(ModuleError::InvalidOperand("catch Y offset overflow"))?;
            let patch_offset = self.code.offset() + 16;
            self.add_catch_patch(patch_offset, code_label);
            self.code.emit(|e| {
                e.ldr_uoff(TMP, C_P, 64)?;
                e.str_uoff(TMP, E, prev_offset)?;
                e.add_imm(TMP3, E, offset as u16, false)?;
                e.str_uoff(TMP3, C_P, 64)?;
                // Finalize patches this fixed-width immediate to the module-local catch number.
                e.movz(Gpr::w(9), u16::MAX, 0)?;
                e.movk(Gpr::w(9), u16::MAX, 16)?;
                e.str_uoff(TMP, E, offset)?;
                e.str_uoff(E, E, prev_offset + 8)?;
                Ok(())
            })?;
            self.code.adr(TMP2, code_label)?;
            self.code.emit(|e| e.str_uoff(TMP2, E, handler_offset))?;
        } else {
            // Port of erts/emulator/beam/jit/arm/instr_common.cpp:2855-2862, OTP-29.1.1
            self.code.emit(|e| {
                e.ldr_uoff(TMP, C_P, 64)?;
                e.add_imm(TMP, TMP, 1, false)?;
                e.str_uoff(TMP, C_P, 64)
            })?;
            let patch_offset = self.code.offset();
            self.add_catch_patch(patch_offset, code_label);
            self.code.emit(|e| {
                // Finalize patches this fixed-width immediate to the module-local catch number.
                e.movz(Gpr::w(9), u16::MAX, 0)?;
                e.movk(Gpr::w(9), u16::MAX, 16)?;
                e.str_uoff(TMP, E, offset)?;
                Ok(())
            })?;
        }
        Ok(())
    }

    /// Begins a `try` region using the same catch record format as `catch`.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:2855-2862, OTP-29.1.1
    pub fn emit_try(&mut self, y: ArgVal, handler: u32) -> Result<(), ModuleError> {
        self.emit_catch(y, handler)
    }

    /// Ends a catch expression after removing its catch record.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:2937-2949, OTP-29.1.1
    pub fn emit_catch_end(&mut self, y: ArgVal) -> Result<(), ModuleError> {
        let next = self.code.new_label();
        self.emit_try_end(y)?;
        self.code.emit(|e| e.cmp_imm(XREGS[0], 0x0f, false))?;
        self.code.b_cond(arinsal_a64::enc::Cond::Ne, next)?;
        // Throws return their value; exit and error classes build an EXIT tuple.
        self.emit_catch_result(None)?;
        self.code.bind(next)?;
        // The shared result builder preserves the raw trace for errors.
        Ok(())
    }

    /// Completes a catch while using OTP's stacktrace helper for error exceptions.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:2864-2913, OTP-29.1.1
    pub fn emit_catch_end_with_stacktrace(
        &mut self,
        y: ArgVal,
        helper: extern "C" fn(*mut ProcessHeader, u64, u64) -> u64,
    ) -> Result<(), ModuleError> {
        let next = self.code.new_label();
        self.emit_try_end(y)?;
        self.code.emit(|e| e.cmp_imm(XREGS[0], 0x0f, false))?;
        self.code.b_cond(arinsal_a64::enc::Cond::Ne, next)?;
        self.emit_catch_result(Some(helper))?;
        self.code.bind(next)?;
        Ok(())
    }

    fn emit_catch_result(
        &mut self,
        helper: Option<extern "C" fn(*mut ProcessHeader, u64, u64) -> u64>,
    ) -> Result<(), ModuleError> {
        let is_throw = self.code.new_label();
        let is_error = self.code.new_label();
        let build_exit = self.code.new_label();
        let done = self.code.new_label();
        // OTP places the exception class, reason, and raw trace in X1-X3.
        self.code
            .emit(|e| e.cmp_imm(XREGS[1], atom_word("throw") as u16, false))?;
        self.code.b_cond(arinsal_a64::enc::Cond::Eq, is_throw)?;
        self.code.emit(|e| e.mov_reg(TMP2, XREGS[2]))?;
        self.code
            .emit(|e| e.cmp_imm(XREGS[1], atom_word("error") as u16, false))?;
        self.code.b_cond(arinsal_a64::enc::Cond::Eq, is_error)?;
        self.code.b(build_exit)?;
        self.code.bind(is_error)?;
        if let Some(helper) = helper {
            let address = helper as usize;
            // Port of erts/emulator/beam/jit/arm/instr_common.cpp:2888-2901, OTP-29.1.1.
            let update = crate::Update::HEAP;
            crate::emit_enter_runtime(&mut self.code, 2, update)?;
            self.code.emit(|e| {
                e.str_uoff(Gpr::x(30), C_P, 72)?;
                e.mov_reg(Gpr::x(0), C_P)?;
                e.mov_reg(Gpr::x(1), XREGS[2])?;
                e.mov_reg(Gpr::x(2), XREGS[3])?;
                e.mov_const(Gpr::x(17), address as u64)?;
                e.blr(Gpr::x(17))
            })?;
            crate::emit_leave_runtime(&mut self.code, 2, update)?;
            self.code.emit(|e| {
                e.ldr_uoff(Gpr::x(30), C_P, 72)?;
                e.mov_reg(XREGS[3], Gpr::x(0))
            })?;
        }
        // Errors retain their trace inside {Reason, Trace}.
        self.code.emit(|e| {
            e.mov_const(TMP3, (2 << 6) | 2)?;
            e.str_post(TMP3, HTOP, 8)?;
            e.stp_post(XREGS[2], XREGS[3], HTOP, 16)?;
            e.sub_imm(TMP2, HTOP, 2, false)
        })?;
        self.code.b(build_exit)?;
        self.code.bind(build_exit)?;
        // Build the outer {'EXIT', Reason} tuple in the current young heap.
        let exit_atom = atom_word("EXIT");
        self.code.emit(|e| {
            e.mov_const(TMP3, (2 << 6) | 2)?;
            e.str_post(TMP3, HTOP, 8)?;
            e.mov_const(TMP3, exit_atom)?;
            e.str_post(TMP3, HTOP, 8)?;
            e.str_post(TMP2, HTOP, 8)?;
            e.sub_imm(XREGS[0], HTOP, 2, false)
        })?;
        self.code.b(done)?;
        self.code.bind(is_throw)?;
        self.code.emit(|e| e.mov_reg(XREGS[0], XREGS[2]))?;
        self.code.bind(done)?;
        Ok(())
    }

    /// Removes the active catch record and clears its Y slot.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:2937-2955, OTP-29.1.1
    pub fn emit_try_end(&mut self, y: ArgVal) -> Result<(), ModuleError> {
        let ArgVal::Y(slot) = y else {
            return Err(ModuleError::InvalidOperand(
                "catch tag must be a Y register",
            ));
        };
        let offset = slot
            .checked_mul(8)
            .ok_or(ModuleError::InvalidOperand("catch Y offset overflow"))?;
        let is_counter = self.code.new_label();
        let store_catches = self.code.new_label();
        self.code.emit(|e| {
            e.ldr_uoff(TMP, C_P, 64)?;
            e.cmp_imm(TMP, 4095, false)
        })?;
        self.code.b_cond(arinsal_a64::enc::Cond::Ls, is_counter)?;
        self.code.emit(|e| e.ldr_uoff(TMP, TMP, 16))?;
        self.code.b(store_catches)?;
        self.code.bind(is_counter)?;
        self.code.emit(|e| e.sub_imm(TMP, TMP, 1, false))?;
        self.code.bind(store_catches)?;
        self.code.emit(|e| {
            e.str_uoff(TMP, C_P, 64)?;
            e.mov_const(TMP, NIL)?;
            e.str_uoff(TMP, E, offset)
        })?;
        Ok(())
    }

    /// Removes a catch record and releases the requested Y frame words.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:2958-2978, OTP-29.1.1
    pub fn emit_try_end_deallocate(&mut self, y: ArgVal, words: u32) -> Result<(), ModuleError> {
        self.emit_try_end(y)?;
        self.deallocate(words)
    }

    /// Completes exception dispatch by discarding the active catch record.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:2981-3009, OTP-29.1.1
    pub fn emit_try_case(&mut self, y: ArgVal) -> Result<(), ModuleError> {
        self.emit_try_end(y)
    }

    /// Raises the `try_clause` error for a failed `try ... of` clause.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:3012-3014, OTP-29.1.1
    pub fn emit_try_case_end(
        &mut self,
        reason: ArgVal,
        resolver: ExceptionResolver,
    ) -> Result<(), ModuleError> {
        self.emit_error(reason, resolver)
    }

    /// Calls the runtime stacktrace builder and places its result in X0.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:3046-3055, OTP-29.1.1
    pub fn emit_build_stacktrace(
        &mut self,
        helper: extern "C" fn(*mut ProcessHeader, u64) -> u64,
    ) -> Result<(), ModuleError> {
        let helper_address = helper as usize;
        // Port of erts/emulator/beam/jit/arm/instr_common.cpp:3049-3054, OTP-29.1.1.
        let update = crate::Update::HEAP;
        crate::emit_enter_runtime(&mut self.code, 0, update)?;
        self.code.emit(|e| {
            e.str_uoff(Gpr::x(30), C_P, 72)?;
            e.mov_reg(Gpr::x(0), C_P)?;
            e.mov_reg(Gpr::x(1), XREGS[0])?;
            e.mov_const(Gpr::x(17), helper_address as u64)?;
            e.blr(Gpr::x(17))
        })?;
        crate::emit_leave_runtime(&mut self.code, 0, update)?;
        self.code.emit(|e| {
            e.ldr_uoff(Gpr::x(30), C_P, 72)?;
            e.mov_reg(XREGS[0], Gpr::x(0))
        })?;
        Ok(())
    }

    /// Raises class, value, and trace terms through the runtime exception resolver.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:3020-3034 and beam_asm_global.cpp:300-329, OTP-29.1.1
    pub fn emit_raise(
        &mut self,
        class: ArgVal,
        value: ArgVal,
        trace: ArgVal,
        resolver: ExceptionResolver,
    ) -> Result<(), ModuleError> {
        let class = self.source_reg(class)?;
        self.code.emit(|e| e.mov_reg(TMP3, class))?;
        let value = self.source_reg(value)?;
        self.code.emit(|e| e.mov_reg(TMP2, value))?;
        let trace = self.source_reg(trace)?;
        self.code.emit(|e| e.mov_reg(TMP, trace))?;
        self.emit_exception_transfer(TMP3, TMP2, TMP, resolver)
    }

    /// Emits OTP's generated `i_raise` instruction form.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:3020-3034, OTP-29.1.1
    pub fn emit_i_raise(
        &mut self,
        class: ArgVal,
        value: ArgVal,
        trace: ArgVal,
        resolver: ExceptionResolver,
    ) -> Result<(), ModuleError> {
        self.emit_raise(class, value, trace, resolver)
    }

    /// Re-raises the raw class, value, and trace in X0-X2.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:3037-3044, OTP-29.1.1
    pub fn emit_raw_raise(&mut self, resolver: ExceptionResolver) -> Result<(), ModuleError> {
        self.emit_exception_transfer(XREGS[0], XREGS[1], XREGS[2], resolver)
    }

    /// Raises class, reason, and trace by following the active catch record directly.
    // Port of erts/emulator/beam/jit/beam_jit_common.cpp:506-531 and beam_asm_global.cpp:300-329, OTP-29.1.1
    pub fn emit_native_raise(
        &mut self,
        class: ArgVal,
        value: ArgVal,
        trace: ArgVal,
    ) -> Result<(), ModuleError> {
        let class = self.source_reg(class)?;
        self.code.emit(|e| e.mov_reg(TMP3, class))?;
        let value = self.source_reg(value)?;
        self.code.emit(|e| e.mov_reg(TMP2, value))?;
        let trace = self.source_reg(trace)?;
        self.code.emit(|e| e.mov_reg(TMP, trace))?;
        let caught = self.code.new_label();
        self.code.emit(|e| {
            e.str_uoff(TMP3, C_P, 40)?;
            e.str_uoff(TMP2, C_P, 48)?;
            e.str_uoff(TMP, C_P, 56)?;
            e.ldr_uoff(Gpr::x(0), C_P, 64)
        })?;
        self.code.cbnz(Gpr::x(0), caught)?;
        self.code.emit(|e| {
            e.mov_reg(Gpr::x(0), Gpr::xzr())?;
            e.ret(Gpr::x(30))
        })?;
        self.code.bind(caught)?;
        self.code.emit(|e| {
            e.ldr_uoff(XREGS[1], C_P, 40)?;
            e.ldr_uoff(XREGS[2], C_P, 48)?;
            e.ldr_uoff(XREGS[3], C_P, 56)?;
            e.mov_const(XREGS[0], 0x0f)?;
            e.ldr_uoff(E, Gpr::x(0), 24)?;
            e.ldr_uoff(Gpr::x(17), Gpr::x(0), 8)?;
            e.br(Gpr::x(17))
        })?;
        Ok(())
    }

    // Port of erts/emulator/beam/jit/arm/beam_asm_global.cpp:300-329, OTP-29.1.1
    fn emit_exception_transfer(
        &mut self,
        class: Gpr,
        value: Gpr,
        trace: Gpr,
        resolver: ExceptionResolver,
    ) -> Result<(), ModuleError> {
        let resolver_address = resolver as usize;
        let caught = self.code.new_label();
        // Port of erts/emulator/beam/jit/arm/beam_asm_global.cpp:311-326, OTP-29.1.1.
        let update = crate::Update::HEAP_ALLOC.union(crate::Update::X_REGS);
        crate::emit_enter_runtime(&mut self.code, 6, update)?;
        self.code.emit(|e| {
            e.str_uoff(class, C_P, 40)?;
            e.str_uoff(value, C_P, 48)?;
            e.str_uoff(trace, C_P, 56)?;
            e.str_uoff(Gpr::x(30), C_P, 72)?;
            e.mov_reg(Gpr::x(0), C_P)?;
            e.mov_reg(Gpr::x(1), Gpr::x(19))?;
            e.mov_reg(Gpr::x(2), E)?;
            e.mov_const(Gpr::x(17), resolver_address as u64)?;
            e.blr(Gpr::x(17))
        })?;
        crate::emit_leave_runtime(&mut self.code, 6, update)?;
        self.code.emit(|e| e.ldr_uoff(Gpr::x(30), C_P, 72))?;
        self.code.cbnz(Gpr::x(0), caught)?;
        // Port of beam_asm_global.cpp:328 (`cbz ARG1, do_schedule`): an uncaught
        // exception must leave native via the enter_native bridge, not `ret` to
        // the caller's LR (nested native frames would re-enter and spin).
        self.code.emit(|e| {
            e.mov_reg(Gpr::x(0), Gpr::xzr())?;
            e.ldr_uoff(Gpr::x(30), SCHEDULER_REGS, 16_416)?;
            e.br(Gpr::x(30))
        })?;
        self.code.bind(caught)?;
        self.code.emit(|e| {
            e.ldr_uoff(E, C_P, 8)?;
            e.br(Gpr::x(0))
        })?;
        Ok(())
    }

    /// Raises `badmatch` with the supplied value.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:2830-2833, OTP-29.1.1
    pub fn emit_badmatch(
        &mut self,
        value: ArgVal,
        resolver: ExceptionResolver,
    ) -> Result<(), ModuleError> {
        self.emit_error(value, resolver)
    }

    /// Raises `case_clause` with the supplied value.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:2835-2838, OTP-29.1.1
    pub fn emit_case_end(
        &mut self,
        value: ArgVal,
        resolver: ExceptionResolver,
    ) -> Result<(), ModuleError> {
        self.emit_error(value, resolver)
    }

    /// Raises `if_clause`.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:2845-2847, OTP-29.1.1
    pub fn emit_if_end(&mut self, resolver: ExceptionResolver) -> Result<(), ModuleError> {
        self.emit_error(ArgVal::Immediate(NIL), resolver)
    }

    /// Raises `badrecord` with the supplied value.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:2850-2853, OTP-29.1.1
    pub fn emit_badrecord(
        &mut self,
        value: ArgVal,
        resolver: ExceptionResolver,
    ) -> Result<(), ModuleError> {
        self.emit_error(value, resolver)
    }

    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:2830-2853, OTP-29.1.1
    fn emit_error(
        &mut self,
        reason: ArgVal,
        resolver: ExceptionResolver,
    ) -> Result<(), ModuleError> {
        let value = self.source_reg(reason)?;
        self.code.emit(|e| e.mov_reg(TMP2, value))?;
        self.code.emit(|e| e.mov_const(TMP3, 0x1b))?;
        self.emit_exception_transfer(TMP3, TMP2, Gpr::xzr(), resolver)
    }
}

fn atom_word(name: &str) -> u64 {
    arinsal_term::Term::atom(
        arinsal_term::global_atoms()
            .get(name)
            .unwrap_or_else(|| panic!("{name} atom is preloaded")),
    )
    .tagged_word()
}
