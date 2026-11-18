//! Port of erts/emulator/beam/jit/x86/instr_fun.cpp, OTP-29.1.1: so far the global fragment
//! `dispatch_save_calls_fun`.

use arinsal_x64::enc::dword_ptr;

use super::beam_asm::AsmError;
use super::beam_asm::register::{ARG1, ARG1D, RET};
use super::beam_asm_global::BeamGlobalAssembler;

impl BeamGlobalAssembler {
    /// Continues a fun call made while saving calls with the actual code index.
    // Port of erts/emulator/beam/jit/x86/instr_fun.cpp:159-165 (emit_dispatch_save_calls_fun),
    // OTP-29.1.1.
    pub(crate) fn emit_dispatch_save_calls_fun(&mut self) -> Result<(), AsmError> {
        let active = &raw const super::rt::the_active_code_index as i64;
        let a = &mut self.asm;
        a.emit(|e| e.mov_ri(ARG1, active))?;
        a.emit(|e| e.mov_rm(ARG1D, dword_ptr(ARG1, 0)))?;
        let target = a.emit_setup_dispatchable_call(RET, ARG1)?;
        a.emit(|e| e.jmp_m(target))
    }
}
