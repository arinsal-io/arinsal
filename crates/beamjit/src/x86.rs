//! The x86-64 side of erts/emulator/beam/jit/beam_asm.cpp (`beamasm_emit`): hands a specific
//! instruction to the x86 module assembler through the dispatch `beam_makeops` generates from
//! `beam/jit/x86/ops.tab` (`beamasm_emit.h`, here `arinsal_beamops::beamasm_emit!`), OTP-29.1.1.
//!
//! An emitter the x86 `BeamModuleAssembler` does not have yet is a compile error naming it:
//! the remaining I-box inventory.

use arinsal_beamasm::beam_asm::AsmError;
use arinsal_beamasm::beam_asm_module::BeamModuleAssembler;
use arinsal_beamasm::common::args::ArgVal;

/// `beamasm_emit(instance, specific_op, op)` after the operands are converted to `ArgVal`s:
/// `ba->emit(specific_op, args)`.
// Port of erts/emulator/beam/jit/beam_asm.cpp (beamasm_emit) and
// erts/emulator/beam/jit/x86/beam_asm_module.cpp (BeamModuleAssembler::emit), OTP-29.1.1.
pub fn beamasm_emit(
    ba: &mut BeamModuleAssembler,
    specific_op: usize,
    args: &[ArgVal],
) -> Result<(), AsmError> {
    arinsal_beamops::beamasm_emit!(ba, specific_op, args)
}
