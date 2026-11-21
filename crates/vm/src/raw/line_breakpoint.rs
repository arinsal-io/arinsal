//! Pointer boundary for the shared BeamAsm line-breakpoint callbacks.

use arinsal_beamasm::{ProcessHeader, SchedulerRegisters, common::args::MAX_REG};
use arinsal_term::Term;

/// Reads saved X registers from a native Erlang stack until its continuation word.
pub(crate) struct StackWords {
    stack: *const u64,
    index: usize,
}

impl StackWords {
    /// Reads the next saved register, returning `None` at the continuation word.
    pub(crate) fn next(&mut self) -> Option<Term> {
        // SAFETY: the cleanup entry contract keeps each stack word readable; non-continuation
        // words are live BEAM terms whose pointer-bearing storage remains alive during the call.
        unsafe {
            let word = self.stack.add(self.index).read();
            if word & 3 == 0 {
                return None;
            }
            self.index += 1;
            Some(Term::from_raw_bits(word))
        }
    }
}

/// Prepares the one erts line-breakpoint handler call for either BeamAsm architecture.
// Port of erts/emulator/beam/beam_bp.c:1821-1865
// (erts_line_breakpoint_hit__prepare_call), OTP-29.1.1.
///
/// # Safety
/// `header` and `registers` must be the active process and scheduler register array. `stack`
/// must point to the `live` writable words reserved by `i_line_breakpoint_trampoline_shared`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn arinsal_beamasm_line_breakpoint_prepare(
    header: *mut ProcessHeader,
    pc: u64,
    live: u64,
    registers: *mut u64,
    stack: *mut u64,
) -> u64 {
    assert!(live <= u64::from(MAX_REG));
    let live = usize::try_from(live).expect("MAX_REG fits usize");

    {
        let process = crate::native_hooks::process_from_header(header)
            .expect("line-breakpoint trampoline has an active process");
        process.heap.note_bif_entry();
    }
    let registers = crate::native_hooks::registers_at(SchedulerRegisters::from_reg(registers))
        .expect("line-breakpoint trampoline has an active register array");
    let export = {
        // SAFETY: the trampoline reserves exactly `live` words at E before this call and keeps
        // both E and the scheduler register array valid for the callback.
        let stack = unsafe { std::slice::from_raw_parts_mut(stack, live) };
        crate::natives::beam_bp::prepare_call(registers, pc as usize, stack)
    };
    let Some(export) = export else {
        return 0;
    };

    let process = crate::native_hooks::process_from_header(header)
        .expect("line-breakpoint trampoline has an active process");
    // The native dispatch setup reads the export arguments through this ABI field.
    process.heap.abi.arity = 4;
    export as *const arinsal_term::ExportEntry as usize as u64
}

/// Restores the live X-register prefix after `erts_internal:breakpoint/4` returns.
// Port of erts/emulator/beam/beam_bp.c:1868-1882
// (erts_line_breakpoint_hit__cleanup), OTP-29.1.1.
///
/// # Safety
/// `registers` must be the active scheduler X-register array. `stack` must point to its saved
/// live-register prefix followed by the aligned continuation word in the active process stack.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn arinsal_beamasm_line_breakpoint_cleanup(
    registers: *mut u64,
    stack: *mut u64,
) -> u64 {
    let registers = crate::native_hooks::registers_at(SchedulerRegisters::from_reg(registers))
        .expect("line-breakpoint cleanup has an active register array");
    // SAFETY: the cleanup trampoline returns with precisely the saved register prefix and its
    // continuation at this stack pointer; the stack remains active through this callback.
    let mut stack = StackWords { stack, index: 0 };
    crate::natives::beam_bp::cleanup(registers, &mut stack)
}
