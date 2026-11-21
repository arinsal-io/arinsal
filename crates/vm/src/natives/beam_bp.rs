//! Native line-breakpoint callbacks.
//!
//! Port of erts/emulator/beam/beam_bp.c, OTP-29.1.1.

use arinsal_beamasm::SchedulerRegisters;
use arinsal_term::{ExportEntry, Term};

/// Resolves a line breakpoint and prepares its `erts_internal:breakpoint/4` call.
// Port of erts/emulator/beam/beam_bp.c:1821-1865
// (erts_line_breakpoint_hit__prepare_call), OTP-29.1.1.
pub(crate) fn prepare_call(
    registers: &mut SchedulerRegisters,
    pc: usize,
    stack: &mut [u64],
) -> Option<&'static ExportEntry> {
    let export =
        crate::beamasm_integration::line_breakpoint_export(registers.active_code_ix as usize)?;
    let function = crate::native_function_at(pc)?;
    // `LOC_LINE(fi.loc)` is zero when `erts_lookup_function_info` has no source location.
    let line = function.line_at(pc).map_or(0, |(_, line)| line);

    if export.info.mfa.module == Term::atom(function.module_atom).word()
        && export.info.mfa.function == Term::atom(function.function_atom).word()
        && export.info.mfa.arity == usize::from(function.arity)
    {
        return None;
    }

    for (index, slot) in stack.iter_mut().enumerate() {
        *slot = registers.x_reg_array[index].tagged_word();
    }
    let args = [
        Term::atom(function.module_atom),
        Term::atom(function.function_atom),
        Term::small(i64::from(function.arity)).expect("arity is a small integer"),
        Term::small(i64::from(line)).expect("debug line is a small integer"),
    ];
    registers.x_reg_array[..4].copy_from_slice(&args);
    Some(export)
}

/// Restores X registers through the first continuation word on the Erlang stack.
// Port of erts/emulator/beam/beam_bp.c:1868-1882
// (erts_line_breakpoint_hit__cleanup), OTP-29.1.1.
pub(crate) fn cleanup(
    registers: &mut SchedulerRegisters,
    stack: &mut crate::raw::line_breakpoint::StackWords,
) -> u64 {
    let mut live = 0usize;
    loop {
        let Some(term) = stack.next() else {
            return live as u64;
        };
        registers.x_reg_array[live] = term;
        live += 1;
    }
}
