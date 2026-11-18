//! Port of erts/emulator/beam/jit/x86/instr_trace.cpp, OTP-29.1.1: the global export
//! breakpoint fragment.

use arinsal_x64::enc::qword_ptr;

use super::beam_asm::register::{ARG1, ARG2, ARG3, C_P, RET};
use super::beam_asm::{AsmError, Update};
use super::beam_asm_global::BeamGlobalAssembler;
pub use super::rt::erts_generic_breakpoint;

impl BeamGlobalAssembler {
    /// Calls `erts_generic_breakpoint` for an export entry, then tail-dispatches its result.
    // Port of erts/emulator/beam/jit/x86/instr_trace.cpp:35-57 (emit_generic_bp_global),
    // OTP-29.1.1.
    pub(crate) fn emit_generic_bp_global(&mut self) -> Result<(), AsmError> {
        let a = &mut self.asm;
        a.emit_enter_frame()?;
        a.emit_enter_runtime(Update::REDUCTIONS.union(Update::HEAP_ALLOC))?;
        a.emit(|e| e.mov_rr(ARG1, C_P))?;
        a.emit(|e| {
            e.lea(
                ARG2,
                qword_ptr(RET, arinsal_term::EXPORT_INFO_OFFSET as i32),
            )
        })?;
        a.load_x_reg_array(ARG3)?;
        a.runtime_call(erts_generic_breakpoint as *const () as usize)?;
        a.emit_leave_runtime(Update::REDUCTIONS.union(Update::HEAP_ALLOC))?;
        a.emit_leave_frame()?;
        a.emit(|e| e.jmp_r(RET))
    }
}
