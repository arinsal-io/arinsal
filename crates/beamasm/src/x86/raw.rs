//! Direct C ABI imports used by native fragments.
//!
//! Port of erts/emulator/beam/jit/x86/beam_asm_module.cpp:299-317, OTP-29.1.1:
//! `i_line_breakpoint_trampoline_shared` calls the shared prepare and cleanup helpers with the
//! process header, PC, live count, X-register array and Erlang stack pointer.

unsafe extern "C" {
    fn arinsal_beamasm_line_breakpoint_prepare(
        header: *mut crate::ProcessHeader,
        pc: u64,
        live: u64,
        registers: *mut u64,
        stack: *mut u64,
    ) -> u64;

    fn arinsal_beamasm_line_breakpoint_cleanup(registers: *mut u64, stack: *mut u64) -> u64;
}

pub(crate) fn line_breakpoint_prepare() -> usize {
    arinsal_beamasm_line_breakpoint_prepare as *const () as usize
}

pub(crate) fn line_breakpoint_cleanup() -> usize {
    arinsal_beamasm_line_breakpoint_cleanup as *const () as usize
}

#[cfg(test)]
mod test_symbols {
    #[unsafe(no_mangle)]
    pub extern "C" fn arinsal_beamasm_line_breakpoint_prepare(
        _header: *mut crate::ProcessHeader,
        _pc: u64,
        _live: u64,
        _registers: *mut u64,
        _stack: *mut u64,
    ) -> u64 {
        0
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn arinsal_beamasm_line_breakpoint_cleanup(
        _registers: *mut u64,
        _stack: *mut u64,
    ) -> u64 {
        0
    }
}
