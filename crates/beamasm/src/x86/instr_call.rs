//! Port of erts/emulator/beam/jit/x86/instr_call.cpp, OTP-29.1.1: so far the global fragments
//! `dispatch_return` and `dispatch_save_calls_export`.

use arinsal_x64::enc::dword_ptr;

use super::beam_asm::register::{ARG1, ARG1D, ARG2, ARG3, C_P, RET};
use super::beam_asm::{AsmError, Update, process, process_ref, tmp_mem_q};
use super::beam_asm_global::{BeamGlobalAssembler, GlobalLabels};
pub use super::rt::save_calls;

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
