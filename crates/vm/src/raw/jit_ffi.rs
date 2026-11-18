//! Raw accesses of the `extern "C"` runtime symbols that BeamAsm fragments call
//! (beam_jit_common.rs, receive.rs, big.rs, beamasm_integration.rs).
//!
//! The symbols take C pointers by erts' signatures; the callers stay safe by going through
//! these functions. Every function states what the generated code guarantees.

use arinsal_beamasm::bif::ExportEntry;

/// Writes `value` through a C out-pointer (`int *get_outp`, `ErtsMessage **msgpp`,
/// `double *resp`).
pub(crate) fn write_out<T>(out: *mut T, value: T) {
    // SAFETY: the JIT fragment passes the address of a live, aligned slot of its frame
    // (`TMP_MEM*q`) that nothing else reads until the call returns.
    unsafe { out.write(value) };
}

/// The text of a NUL-terminated C string literal (`char *msg`).
pub(crate) fn c_str_lossy(msg: *const core::ffi::c_char) -> String {
    // SAFETY: the emitter passes a NUL-terminated string literal that outlives the call.
    unsafe { core::ffi::CStr::from_ptr(msg) }
        .to_string_lossy()
        .into_owned()
}

/// The first `len` words of an X register array (`const Eterm *regs`).
pub(crate) fn reg_words<'a>(regs: *const u64, len: usize) -> &'a [u64] {
    // SAFETY: the fragment passes its register array; its first `len` words are live X
    // registers that stay unchanged for the duration of the call.
    unsafe { std::slice::from_raw_parts(regs, len) }
}

/// The export entry at `address` (`Export *`).
pub(crate) fn export_entry<'a>(address: usize) -> &'a ExportEntry {
    // SAFETY: the address is an export entry taken from the export tables or returned by the
    // runtime; entries are leaked when created and never freed, like erts' export entries.
    unsafe { &*(address as *const ExportEntry) }
}
