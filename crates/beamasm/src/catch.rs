//! Catch records, exception transfer, and error instructions.

use arinsal_a64::enc::Gpr;
use std::sync::atomic::{AtomicU32, Ordering};

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

// Port of erts/emulator/beam/error.h:111-170, OTP-29.1.1: `(index << EXC_OFFSET) | EXC_ERROR`.
const EXC_BADMATCH: u64 = (5 << 10) | 0x50;
const EXC_CASE_CLAUSE: u64 = (7 << 10) | 0x50;
const EXC_IF_CLAUSE: u64 = (8 << 10) | 0x50;
const EXC_TRY_CLAUSE: u64 = (16 << 10) | 0x50;
const EXC_BADRECORD: u64 = (20 << 10) | 0x50;
/// `freason` flag of a native `raw_raise`: the low bits are the class (1 error, 2 exit,
/// 3 throw) and `c_p->ftrace` holds the stacktrace being re-raised.
pub const RAW_RAISE: u64 = 1 << 9;
/// `freason` flag of a native `raise/2` (`i_raise`) whose stacktrace in `c_p->ftrace` is valid:
/// the exception keeps that stacktrace but is not a raw rethrow.
pub const RERAISE: u64 = 1 << 8;
const NIL: u64 = 0x3b;
const TAG_IMMED2_CATCH: u64 = 0x1b;
/// Stands in for `THE_NON_VALUE` in X0 while a native handler runs: a catch immediate is
/// never an Erlang term.
pub const NON_VALUE_MARKER: u64 = TAG_IMMED2_CATCH;
static NEXT_CATCH_INDEX: AtomicU32 = AtomicU32::new(0);

/// Reserves globally unique catch-table indices for a loaded code module.
pub fn reserve_catch_indices(count: usize) -> Result<u32, ModuleError> {
    let count =
        u32::try_from(count).map_err(|_| ModuleError::InvalidOperand("catch count overflow"))?;
    NEXT_CATCH_INDEX
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |base| {
            base.checked_add(count).filter(|end| *end < (1 << 25))
        })
        .map_err(|_| ModuleError::InvalidOperand("global catch table exhausted"))
}

/// Resolves an exception against the process catch chain and returns a native handler address.
/// A zero result means that the exception is uncaught and should return to the runtime.
pub type ExceptionResolver =
    extern "C" fn(*mut ProcessHeader, *mut SchedulerRegisters, *mut u64) -> usize;
/// Runtime callback that pairs an error reason with its materialized stacktrace.
pub type AddStacktraceHook = extern "C" fn(*mut ProcessHeader, u64, u64) -> u64;
/// Runtime callback that materializes a raw stacktrace term.
pub type BuildStacktraceHook = extern "C" fn(*mut ProcessHeader, u64) -> u64;

/// Builds the OTP immediate stored in a Y slot for catch number `number`.
// Port of erts/emulator/beam/erl_term.h:1385-1386, OTP-29.1.1
pub const fn make_catch(number: u32) -> u64 {
    ((number as u64) << 6) | TAG_IMMED2_CATCH
}

impl BeamModuleAssembler {
    /// Registers a catch handler and stores its `make_catch` tag in the supplied Y slot.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:2855-2862 and beam_jit_common.cpp:507-530, OTP-29.1.1
    pub fn emit_catch(&mut self, y: ArgVal, handler: u32) -> Result<(), ModuleError> {
        let ArgVal::Y(slot) = y else {
            return Err(ModuleError::InvalidOperand(
                "catch tag destination must be a Y register",
            ));
        };
        let offset = slot
            .checked_mul(8)
            .ok_or(ModuleError::InvalidOperand("catch Y offset overflow"))?;
        let code_label = self.label(handler);

        // Port of erts/emulator/beam/jit/arm/instr_common.cpp:2855-2862, OTP-29.1.1.
        self.code.emit(|e| {
            e.ldr_uoff(TMP, C_P, 64)?;
            e.add_imm(TMP, TMP, 1, false)?;
            e.str_uoff(TMP, C_P, 64)
        })?;
        let patch_offset = self.code.offset();
        self.add_catch_patch(patch_offset, code_label);
        self.code.emit(|e| {
            e.movz(Gpr::w(9), u16::MAX, 0)?;
            e.movk(Gpr::w(9), u16::MAX, 16)?;
            e.str_uoff(TMP, E, offset)
        })?;
        Ok(())
    }

    /// Begins a `try` region using the same catch record format as `catch`.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:2855-2862, OTP-29.1.1
    pub fn emit_try(&mut self, y: ArgVal, handler: u32) -> Result<(), ModuleError> {
        self.emit_catch(y, handler)
    }

    /// Ends a catch expression after removing its catch record.
    ///
    /// `X0` is the value of the catch body, or the non-value marker when an exception was
    /// caught, with the reason in `X1`, the raw stacktrace in `X2` and the class in `X3`.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:2937-2949 and
    // beam_asm_global.cpp (emit_catch_end_shared), OTP-29.1.1
    pub fn emit_catch_end(
        &mut self,
        y: ArgVal,
        gc: crate::construct::GcHook,
        add_stacktrace: AddStacktraceHook,
    ) -> Result<(), ModuleError> {
        let done = self.code.new_label();
        let have_reason = self.code.new_label();
        self.emit_try_end(y)?;
        self.code
            .emit(|e| e.cmp_imm(XREGS[0], NON_VALUE_MARKER as u16, false))?;
        self.code.b_cond(arinsal_a64::enc::Cond::Ne, done)?;
        self.code.emit(|e| {
            e.mov_reg(XREGS[0], XREGS[1])?;
            e.mov_const(TMP, atom_word("throw"))?;
            e.cmp_reg(XREGS[3], TMP, arinsal_a64::enc::Shift::Lsl, 0)
        })?;
        // A thrown value is the result of the catch.
        self.code.b_cond(arinsal_a64::enc::Cond::Eq, done)?;
        self.code.emit(|e| {
            e.mov_const(TMP, atom_word("error"))?;
            e.cmp_reg(XREGS[3], TMP, arinsal_a64::enc::Shift::Lsl, 0)
        })?;
        self.code.b_cond(arinsal_a64::enc::Cond::Ne, have_reason)?;
        // Port of erts/emulator/beam/jit/arm/beam_asm_global.cpp (add_stacktrace call), OTP-29.1.1.
        let update = crate::Update::HEAP_ALLOC;
        crate::emit_enter_runtime(&mut self.code, 2, update)?;
        self.code.emit(|e| {
            e.str_uoff(Gpr::x(30), C_P, 72)?;
            e.mov_reg(Gpr::x(0), C_P)?;
            e.mov_reg(Gpr::x(1), XREGS[0])?;
            e.mov_reg(Gpr::x(2), XREGS[2])?;
            e.mov_const(Gpr::x(17), add_stacktrace as usize as u64)?;
            e.blr(Gpr::x(17))
        })?;
        crate::emit_leave_runtime(&mut self.code, 2, update)?;
        self.code.emit(|e| {
            e.ldr_uoff(Gpr::x(30), C_P, 72)?;
            e.mov_reg(XREGS[0], Gpr::x(0))
        })?;
        self.code.bind(have_reason)?;
        // The reason or {Reason, Stacktrace} stays live in X0 across the possible GC.
        self.emit_test_heap(3, 1, gc)?;
        let exit_atom = atom_word("EXIT");
        self.code.emit(|e| {
            e.mov_reg(TMP2, XREGS[0])?;
            e.add_imm(XREGS[0], HTOP, 2, false)?;
            e.mov_const(TMP3, 2 << 6)?;
            e.mov_const(TMP, exit_atom)?;
            e.stp_post(TMP3, TMP, HTOP, 16)?;
            e.str_post(TMP2, HTOP, 8)
        })?;
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
        self.code.emit(|e| {
            e.ldr_uoff(TMP, C_P, 64)?;
            e.sub_imm(TMP, TMP, 1, false)?;
            e.str_uoff(TMP, C_P, 64)?;
            e.mov_const(TMP, NIL)?;
            e.str_uoff(TMP, E, offset)
        })?;
        Ok(())
    }

    /// Removes a catch record and releases the requested Y frame words.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:2958-2978, OTP-29.1.1
    pub fn emit_try_end_deallocate(&mut self, words: u32) -> Result<(), ModuleError> {
        self.code.emit(|e| {
            e.ldr_uoff(TMP, C_P, 64)?;
            e.sub_imm(TMP, TMP, 1, false)?;
            e.str_uoff(TMP, C_P, 64)
        })?;
        self.deallocate(words)
    }

    /// Removes a catch record, moves `src` to `dst` and releases the Y frame.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:2968-2978, OTP-29.1.1
    pub fn emit_try_end_move_deallocate(
        &mut self,
        src: ArgVal,
        dst: ArgVal,
        words: u32,
    ) -> Result<(), ModuleError> {
        self.code.emit(|e| {
            e.ldr_uoff(TMP, C_P, 64)?;
            e.sub_imm(TMP, TMP, 1, false)?;
            e.str_uoff(TMP, C_P, 64)
        })?;
        self.move_(src, dst)?;
        self.deallocate(words)
    }

    /// Completes exception dispatch by discarding the active catch record.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:2981-3009, OTP-29.1.1
    pub fn emit_try_case(&mut self, y: ArgVal) -> Result<(), ModuleError> {
        // X1 (reason) and X2 (raw stacktrace) already have their `try_case` positions; the
        // class moves from X3 to X0. The catch tag in the Y slot was cleared when the
        // handler was selected.
        let _ = y;
        self.code.emit(|e| {
            e.ldr_uoff(TMP, C_P, 64)?;
            e.mov_reg(XREGS[0], XREGS[3])?;
            e.sub_imm(TMP, TMP, 1, false)?;
            e.str_uoff(TMP, C_P, 64)
        })?;
        Ok(())
    }

    /// Raises the `try_clause` error for a failed `try ... of` clause.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:3012-3014, OTP-29.1.1
    pub fn emit_try_case_end(
        &mut self,
        reason: ArgVal,
        resolver: ExceptionResolver,
    ) -> Result<(), ModuleError> {
        self.emit_error(reason, EXC_TRY_CLAUSE, resolver)
    }

    /// Calls the runtime stacktrace builder and places its result in X0.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:3046-3055, OTP-29.1.1
    pub fn emit_build_stacktrace(
        &mut self,
        helper: BuildStacktraceHook,
    ) -> Result<(), ModuleError> {
        let helper_address = helper as usize;
        // Port of erts/emulator/beam/jit/arm/instr_common.cpp:3049-3054, OTP-29.1.1.
        let update = crate::Update::HEAP_ALLOC;
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
        trace: ArgVal,
        value: ArgVal,
        class_helper: usize,
        resolver: ExceptionResolver,
    ) -> Result<(), ModuleError> {
        if class_helper == 0 {
            return Err(ModuleError::InvalidOperand("raise class helper is missing"));
        }
        let value = self.source_reg(value)?;
        self.code.emit(|e| e.mov_reg(TMP2, value))?;
        let trace = self.source_reg(trace)?;
        self.code.emit(|e| e.mov_reg(TMP, trace))?;
        self.code.emit(|e| {
            e.mov_reg(XREGS[2], TMP)?;
            e.mov_reg(XREGS[1], TMP2)
        })?;

        // i_raise/0 needs the raw trace's saved class. This helper mirrors
        // erts_sanitize_freason without moving the heap or Erlang stack.
        let update = crate::Update::NONE;
        self.code.emit(|e| e.str_uoff(XREGS[1], C_P, 48))?;
        crate::emit_enter_runtime(&mut self.code, 3, update)?;
        self.code.emit(|e| {
            e.mov_reg(Gpr::x(0), C_P)?;
            e.mov_reg(Gpr::x(1), XREGS[2])?;
            e.mov_reg(Gpr::x(2), XREGS[1])?;
            e.mov_const(Gpr::x(17), class_helper as u64)?;
            e.str_uoff(Gpr::x(30), C_P, 72)?;
            e.blr(Gpr::x(17))
        })?;
        crate::emit_leave_runtime(&mut self.code, 3, update)?;
        self.code.emit(|e| {
            e.ldr_uoff(Gpr::x(30), C_P, 72)?;
            e.mov_reg(TMP3, Gpr::x(0))?;
            e.ldr_uoff(TMP2, C_P, 48)
        })?;
        self.emit_exception_transfer(TMP3, TMP2, XREGS[2], resolver)
    }

    /// Re-raises the raw class, value, and trace in X0-X2.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:3037-3044, OTP-29.1.1
    // and erts/emulator/beam/beam_common.c:1148-1178 (raw_raise): an invalid class leaves
    // `badarg` in X0 and execution continues.
    pub fn emit_raw_raise(&mut self, resolver: ExceptionResolver) -> Result<(), ModuleError> {
        let raise = self.code.new_label();
        let next = self.code.new_label();
        for (class, code) in [("error", 1_u64), ("exit", 2), ("throw", 3)] {
            let word = atom_word(class);
            self.code.emit(|e| {
                e.mov_const(Gpr::x(8), word)?;
                e.cmp_reg(XREGS[0], Gpr::x(8), arinsal_a64::enc::Shift::Lsl, 0)?;
                e.mov_const(TMP, RAW_RAISE | code)
            })?;
            self.code.b_cond(arinsal_a64::enc::Cond::Eq, raise)?;
        }
        let badarg = atom_word("badarg");
        self.code.emit(|e| e.mov_const(XREGS[0], badarg))?;
        self.code.b(next)?;
        self.code.bind(raise)?;
        self.emit_exception_transfer(TMP, XREGS[1], XREGS[2], resolver)?;
        self.code.bind(next)?;
        Ok(())
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
            // Port of erts/emulator/beam/beam_common.c:541-544 (handle_error), OTP-29.1.1.
            e.ldr_uoff(XREGS[3], C_P, 40)?;
            e.ldr_uoff(XREGS[1], C_P, 48)?;
            e.ldr_uoff(XREGS[2], C_P, 56)?;
            e.mov_const(XREGS[0], NON_VALUE_MARKER)?;
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
        // The exception's source position: the address of this instruction.
        let here = self.code.new_label();
        self.code.bind(here)?;
        self.code.adr(Gpr::x(8), here)?;
        self.code
            .emit(|e| e.str_uoff(Gpr::x(8), SCHEDULER_REGS, 16_432))?;
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
        self.emit_error(value, EXC_BADMATCH, resolver)
    }

    /// Raises `case_clause` with the supplied value.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:2835-2838, OTP-29.1.1
    pub fn emit_case_end(
        &mut self,
        value: ArgVal,
        resolver: ExceptionResolver,
    ) -> Result<(), ModuleError> {
        self.emit_error(value, EXC_CASE_CLAUSE, resolver)
    }

    /// Raises `if_clause`.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:2845-2847, OTP-29.1.1
    pub fn emit_if_end(&mut self, resolver: ExceptionResolver) -> Result<(), ModuleError> {
        self.emit_error(ArgVal::Immediate(NIL), EXC_IF_CLAUSE, resolver)
    }

    /// Raises `badrecord` with the supplied value.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:2850-2853, OTP-29.1.1
    pub fn emit_badrecord(
        &mut self,
        value: ArgVal,
        resolver: ExceptionResolver,
    ) -> Result<(), ModuleError> {
        self.emit_error(value, EXC_BADRECORD, resolver)
    }

    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:81-87 (`emit_error`) and
    // beam_asm_global.cpp:239-249 (`emit_raise_exception` → the shared fragment), OTP-29.1.1.
    // `freason` and `fvalue` are stored, then control goes to `error_label`
    // (`raise_exception_shared`). The fragment is not entered inline at the site.
    fn emit_error(
        &mut self,
        reason: ArgVal,
        freason: u64,
        resolver: ExceptionResolver,
    ) -> Result<(), ModuleError> {
        self.ensure_exception_resolver(resolver as usize);
        let value = self.source_reg(reason)?;
        self.code.emit(|e| {
            e.mov_const(TMP3, freason)?;
            e.stp(TMP3, value, C_P, 40)
        })?;
        self.branch_error()
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
