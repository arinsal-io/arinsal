//! Port of erts/emulator/beam/jit/x86/instr_call.cpp, OTP-29.1.1: so far the global fragment
//! `dispatch_return`.

use super::beam_asm::register::ARG3;
use super::beam_asm::{AsmError, process, process_ref};
use super::beam_asm_global::{BeamGlobalAssembler, GlobalLabels};

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
}
