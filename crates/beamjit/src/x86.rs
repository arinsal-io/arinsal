//! The x86-64 module assembler driver: the x86 side of erts/emulator/beam/jit/beam_jit_main.cpp
//! (`beamasm_new_assembler`, `beamasm_emit`), which hands each specific instruction of the
//! loader to the x86 module assembler through the dispatch `beam_makeops` generates from
//! `beam/jit/x86/ops.tab` (`beamasm_emit.h`, here `arinsal_beamops::beamasm_emit!`),
//! OTP-29.1.1.
//!
//! An emitter the x86 `BeamModuleAssembler` does not have yet is a compile error naming it:
//! the remaining I-box inventory.

use crate::beam_asm::{
    CompileError, LoaderEnv, beam_load_emit_op, resolve_new_literal, with_transform_arena,
};
use arinsal_beam::BeamFile;
use arinsal_beamasm::beam_asm::AsmError;
use arinsal_beamasm::beam_asm_module::BeamModuleAssembler;
use arinsal_beamasm::common::args::ArgVal;
use arinsal_beamops::{self as beamops, NewLiteral, OpSink, SpecificOperand};

/// `beamasm_new_assembler(mod, num_labels, num_functions, file)`: the module assembler the
/// load emits into.
// Port of erts/emulator/beam/jit/beam_jit_main.cpp:508-517 (beamasm_new_assembler), OTP-29.1.1.
pub fn beamasm_new_assembler(beam: &BeamFile) -> BeamModuleAssembler {
    BeamModuleAssembler::new(beam.code.label_count)
}

/// `beamasm_emit(instance, specific_op, op)` after the operands are converted to `ArgVal`s:
/// `ba->emit(specific_op, args)`.
// Port of erts/emulator/beam/jit/beam_jit_main.cpp:519-532 (beamasm_emit) and
// erts/emulator/beam/jit/x86/beam_asm_module.cpp:419-445 (BeamModuleAssembler::emit),
// OTP-29.1.1.
pub fn beamasm_emit(
    ba: &mut BeamModuleAssembler,
    specific_op: usize,
    args: &[ArgVal],
) -> Result<(), AsmError> {
    arinsal_beamops::beamasm_emit!(ba, specific_op, args)
}

/// The loader state of one module load as the receiver of the transform engine's output:
/// each specific instruction goes through `beam_load_emit_op` into the module assembler.
struct Loader<'a, E: LoaderEnv + ?Sized> {
    beam: &'a BeamFile,
    env: &'a E,
    ba: &'a mut BeamModuleAssembler,
    /// The `ArgVal`s of the instruction being emitted, reused across instructions.
    args: Vec<ArgVal>,
}

impl<E: LoaderEnv + ?Sized> OpSink for Loader<'_, E> {
    fn new_literal(&mut self, index: u32, literal: &NewLiteral) -> Result<(), String> {
        resolve_new_literal(self.beam, self.env, index, literal)
    }

    // Port of erts/emulator/beam/jit/asm_load.c:357-640 (beam_load_emit_op), OTP-29.1.1.
    fn emit(&mut self, op: u16, specific: u16, operands: &[SpecificOperand]) -> Result<(), String> {
        let info = beamops::specific_op_info(specific)
            .ok_or_else(|| format!("no specific instruction {specific}"))?;
        beam_load_emit_op(self.beam, self.env, info.sign, operands, &mut self.args)
            .map_err(|error| format!("{}: {error}", info.name))?;
        beamasm_emit(self.ba, usize::from(specific), &self.args).map_err(|error| {
            format!(
                "failed to emit asm for {} ({}): {error:?}",
                info.name,
                beamops::generic_op_name(op)
            )
        })
    }
}

/// Emits the code of `beam` into `ba`: the transform engine's specific instructions, each
/// through `beam_load_emit_op` and `beamasm_emit`, as erts' `load_code` does with
/// `stp->ba`.
// Port of erts/emulator/beam/beam_load.c (load_code) with the BeamAsm emit of
// erts/emulator/beam/jit/asm_load.c, OTP-29.1.1.
pub fn load_code(
    beam: &BeamFile,
    env: &(impl LoaderEnv + ?Sized),
    line_breakpoints: bool,
    ba: &mut BeamModuleAssembler,
) -> Result<(), CompileError> {
    let mut loader = Loader {
        beam,
        env,
        ba,
        args: Vec::new(),
    };
    with_transform_arena(|arena| {
        beamops::load_code(beam, line_breakpoints, true, arena, &mut loader)
    })
    .map_err(|error| CompileError::Assemble(format!("{}: {error}", beam.module)))
}
