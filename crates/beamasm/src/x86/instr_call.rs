//! Port of erts/emulator/beam/jit/x86/instr_call.cpp, OTP-29.1.1: so far the global fragments
//! `dispatch_return` and `dispatch_save_calls_export`, `return`, `i_call` and `i_call_only`.

use arinsal_x64::enc::dword_ptr;

use super::beam_asm::register::{ARG1, ARG1D, ARG2, ARG3, C_P, RET};
use super::beam_asm::{AsmError, Update, process, process_ref, tmp_mem_q};
use super::beam_asm_global::{BeamGlobalAssembler, GlobalLabels};
pub use super::rt::save_calls;
use crate::common::args::ArgVal;

impl BeamGlobalAssembler {
    /// Schedules out at a return: `ARG3` (popped with `NATIVE_ERLANG_STACK`) is the place to
    /// continue at.
    // Port of erts/emulator/beam/jit/x86/instr_call.cpp:30-41 (emit_dispatch_return),
    // OTP-29.1.1.
    pub(crate) fn emit_dispatch_return(&mut self) -> Result<(), AsmError> {
        let a = &mut self.asm;
        a.emit(|e| e.pop_r(ARG3))?;
        a.emit(|e| e.mov_mi(process_ref(process::CURRENT, 8), 0))?;
        a.emit(|e| e.mov_mi(process_ref(process::ARITY, 1), 1))?;
        let label = self.label(GlobalLabels::ContextSwitchSimplified);
        self.asm.jmp(label)
    }

    /// Records an export call for `save_calls` and continues it with the actual code index;
    /// `RET` is the export.
    // Port of erts/emulator/beam/jit/x86/instr_call.cpp:43-60
    // (emit_dispatch_save_calls_export), OTP-29.1.1.
    pub(crate) fn emit_dispatch_save_calls_export(&mut self) -> Result<(), AsmError> {
        let active = &raw const super::rt::the_active_code_index as i64;
        let a = &mut self.asm;
        a.emit(|e| e.mov_mr(tmp_mem_q(0), RET))?;
        a.emit_enter_runtime(Update::NONE)?;
        a.emit(|e| e.mov_rr(ARG1, C_P))?;
        a.emit(|e| e.mov_rr(ARG2, RET))?;
        a.runtime_call(save_calls as *const () as usize)?;
        a.emit_leave_runtime(Update::NONE)?;
        a.emit(|e| e.mov_rm(RET, tmp_mem_q(0)))?;
        // Keep going with the actual code index.
        a.emit(|e| e.mov_ri(ARG1, active))?;
        a.emit(|e| e.mov_rm(ARG1D, dword_ptr(ARG1, 0)))?;
        let target = a.emit_setup_dispatchable_call(RET, ARG1)?;
        a.emit(|e| e.jmp_m(target))
    }
}

impl super::beam_asm_module::BeamModuleAssembler {
    /// `emit_return()`.
    // Port of erts/emulator/beam/jit/x86/instr_call.cpp:43-45 (emit_return), OTP-29.1.1.
    pub fn emit_return(&mut self) -> Result<(), AsmError> {
        self.emit_return_do(false)
    }

    /// `emit_return_do(set_I)`: returns to the CP on top of the Erlang stack, scheduling out
    /// through `dispatch_return` when the reductions are used up. The reduction test stays
    /// in module code (moving it to a fragment slowed dialyzer down in erts).
    // Port of erts/emulator/beam/jit/x86/instr_call.cpp:47-80 (emit_return_do), OTP-29.1.1.
    // `erts_alcu_enable_code_atags` is off (see `TEST_YIELD_RETURN_OFFSET`).
    pub fn emit_return_do(&mut self, set_i: bool) -> Result<(), AsmError> {
        use super::beam_asm::register::{E, FCALLS};
        use arinsal_x64::enc::{CondCode, qword_ptr};
        self.asm.emit_leave_frame()?;
        if set_i {
            // See emit_i_test_yield.
            self.asm.emit(|e| e.mov_rm(ARG3, qword_ptr(E, 0)))?;
            self.asm
                .emit(|e| e.mov_mr(process_ref(process::I, 8), ARG3))?;
        }
        self.asm.emit(|e| e.dec_r(FCALLS))?;
        let fragment = self.ga_get(GlobalLabels::DispatchReturn)?;
        let target = self.resolve_fragment(fragment);
        self.asm.jcc(CondCode::L, target)?;
        self.asm.emit(|e| e.ret())
    }

    /// `emit_i_call(CallDest)`: a local body call.
    // Port of erts/emulator/beam/jit/x86/instr_call.cpp:80-82 (emit_i_call), OTP-29.1.1.
    pub fn emit_i_call(&mut self, call_dest: ArgVal) -> Result<(), AsmError> {
        let target = self.call_label(call_dest)?;
        self.asm.erlang_call(target)
    }

    /// `emit_i_call_only(CallDest)`: a local tail call without a frame to drop.
    // Port of erts/emulator/beam/jit/x86/instr_call.cpp:90-94 (emit_i_call_only), OTP-29.1.1.
    pub fn emit_i_call_only(&mut self, call_dest: ArgVal) -> Result<(), AsmError> {
        self.asm.emit_leave_frame()?;
        let target = self.call_label(call_dest)?;
        self.asm.jmp(target)
    }

    /// `resolve_beam_label(CallDest)`.
    fn call_label(&self, call_dest: ArgVal) -> Result<arinsal_x64::buf::Label, AsmError> {
        self.resolve_beam_label(super::beam_asm_module::arg_label(call_dest)?)
            .ok_or(AsmError::Operand("call to an unknown label"))
    }
}
