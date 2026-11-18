//! Pointer operations for runtime symbols ported from OTP's C ABI.
// Port of erts/emulator/beam/erl_vm.h (Eterm pointer access) and beam_common.c,
// OTP-29.1.1.

/// Reads a caller-owned word at `index`.
pub(crate) fn read_word(words: *const u64, index: usize) -> u64 {
    // SAFETY: generated BeamAsm operations pass aligned operand, X-register, or stack arrays;
    // their encoded indexes name live words for the duration of this runtime call.
    unsafe { words.add(index).read() }
}

/// Reads a caller-owned word at `index`, or returns `None` for a null table.
pub(crate) fn read_optional_word(words: *const u64, index: usize) -> Option<u64> {
    (!words.is_null()).then(|| read_word(words, index))
}

/// Writes one caller-owned Eterm slot, returning false when the output is null.
pub(crate) fn write_word(output: *mut u64, value: u64) -> bool {
    if output.is_null() {
        return false;
    }
    // SAFETY: the runtime symbol's C ABI contract supplies one writable Eterm output slot.
    unsafe { output.write(value) };
    true
}

/// Gives a runtime root range to a closure while keeping its raw-pointer borrow local.
pub(crate) fn with_mut_terms<R>(
    words: *mut u64,
    len: usize,
    body: impl FnOnce(&mut [arinsal_term::Term]) -> R,
) -> Option<R> {
    if len == 0 {
        return Some(body(&mut []));
    }
    if words.is_null() {
        return None;
    }
    // SAFETY: `erts_garbage_collect_nobump` receives `objv` and `nobj` from generated code; the
    // live register array contains `nobj` aligned, writable Eterm slots throughout collection.
    Some(body(unsafe {
        std::slice::from_raw_parts_mut(words.cast::<arinsal_term::Term>(), len)
    }))
}

/// Copies the stable MFA fields from an export entry supplied to `save_calls`.
// Port of erts/emulator/beam/export.h (`Export.info.mfa`), OTP-29.1.1.
pub(crate) fn export_mfa(address: usize) -> Option<(arinsal_term::Atom, arinsal_term::Atom, u8)> {
    if address == 0 {
        return None;
    }
    // SAFETY: `save_calls` receives an Export pointer whose code index keeps the entry stable
    // while its address is copied into this process's saved-calls ring.
    let export = unsafe { &*(address as *const arinsal_term::ExportEntry) };
    let mfa = &export.info.mfa;
    Some((
        crate::native_hooks::from_raw(mfa.module).as_atom()?,
        crate::native_hooks::from_raw(mfa.function).as_atom()?,
        u8::try_from(mfa.arity).ok()?,
    ))
}

/// Reads the `ErtsCodeMFA` at `info`: the `bif_mfa` that `handle_error` and the BIF error
/// paths receive from native code (`Export.info.mfa` or a file-static MFA of instr_*.cpp).
// Port of erts/emulator/beam/beam_common.c (handle_error, save_stacktrace read `bif_mfa`),
// OTP-29.1.1.
pub(crate) fn code_mfa(info: u64) -> Option<(arinsal_term::Atom, arinsal_term::Atom, u8)> {
    let info = usize::try_from(info).ok()?;
    if info == 0 || !info.is_multiple_of(core::mem::align_of::<arinsal_term::ErtsCodeMfa>()) {
        return None;
    }
    // SAFETY: native code passes only addresses of live `ErtsCodeMfa`s (export entries, which
    // the code index keeps alive, and the static MFAs of the emitters), as erts' `bif_mfa`.
    let mfa = unsafe { (info as *const arinsal_term::ErtsCodeMfa).read() };
    Some((
        crate::native_hooks::from_raw(mfa.module).as_atom()?,
        crate::native_hooks::from_raw(mfa.function).as_atom()?,
        u8::try_from(mfa.arity).ok()?,
    ))
}

/// The fun view of a term native code handed to the runtime; the process heap holding it is
/// live for the whole runtime call.
pub(crate) fn fun_ref(term: arinsal_term::Term) -> Option<arinsal_term::FunRef<'static>> {
    // SAFETY: the term comes from a live process heap (registers, stack or message) that is
    // not collected while the runtime function borrowing the view runs.
    unsafe { term.fun_ref() }
}
