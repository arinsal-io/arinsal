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
