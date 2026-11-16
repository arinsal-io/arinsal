//! Atom and binary conversion BIFs of erl_unicode.c (the atom half of erl_unicode.c).
//!
//! Port of erts/emulator/beam/erl_unicode.c (atom_to_binary_2, binary_to_atom_2,
//! binary_to_existing_atom_2, unicode_bin_is_7bit_1), OTP-29.1.1. Every body is a
//! `bif_table[].f` entry with `(c_p, reg, I)`.

use crate::natives::bif::{bif_badarg, bif_system_limit};
use arinsal_beamasm::ProcessHeader;
use arinsal_term::{AtomEncoding, AtomError, Term, TermBuilder, atoms, global_atoms};

fn encoding(term: Term) -> Option<AtomEncoding> {
    let name = term.as_atom().and_then(|atom| global_atoms().text(atom))?;
    match name {
        "utf8" | "unicode" => Some(AtomEncoding::Utf8),
        "latin1" => Some(AtomEncoding::Latin1),
        _ => None,
    }
}

/// `atom_to_binary/2`.
// Port of erts/emulator/beam/erl_unicode.c (atom_to_binary_2), OTP-29.1.1.
pub(crate) extern "C" fn atom_to_binary_2(c_p: *mut ProcessHeader, reg: *mut u64, _i: u64) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let [term, encoding_term] = crate::bif_table::bif_args::<2>(reg);
    let (Some(atom), Some(encoding)) = (term.as_atom(), encoding(encoding_term)) else {
        return bif_badarg(c_p);
    };
    let table = global_atoms();
    if encoding == AtomEncoding::Utf8 {
        return table
            .utf8_literal(atom)
            .map_or_else(|| bif_badarg(c_p), crate::native_hooks::raw);
    }
    match table.latin1_is_stored(atom) {
        Some(true) => table
            .utf8_literal(atom)
            .map_or_else(|| bif_badarg(c_p), crate::native_hooks::raw),
        Some(false) => {
            let Some(bytes) = table.latin1_bytes(atom) else {
                return bif_badarg(c_p);
            };
            match TermBuilder::new(&mut arinsal_bifs::ProcessHeapHandle(&mut process.heap))
                .binary(&bytes)
            {
                Ok(result) => crate::native_hooks::raw(result),
                Err(_) => bif_system_limit(c_p),
            }
        }
        None => bif_badarg(c_p),
    }
}

/// `binary_to_atom/2`.
// Port of erts/emulator/beam/erl_unicode.c (binary_to_atom_2), OTP-29.1.1.
pub(crate) extern "C" fn binary_to_atom_2(c_p: *mut ProcessHeader, reg: *mut u64, _i: u64) -> u64 {
    atom_from_binary(c_p, reg, false)
}

/// `binary_to_existing_atom/2`.
// Port of erts/emulator/beam/erl_unicode.c (binary_to_existing_atom_2), OTP-29.1.1.
pub(crate) extern "C" fn binary_to_existing_atom_2(
    c_p: *mut ProcessHeader,
    reg: *mut u64,
    _i: u64,
) -> u64 {
    atom_from_binary(c_p, reg, true)
}

fn atom_from_binary(c_p: *mut ProcessHeader, reg: *mut u64, existing: bool) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let [binary, encoding_term] = crate::bif_table::bif_args::<2>(reg);
    let Some(encoding) = encoding(encoding_term) else {
        return bif_badarg(c_p);
    };
    let Some(bytes) = arinsal_term::raw::BinRef::try_from(binary)
        .ok()
        .and_then(|binary| binary.bytes())
    else {
        return bif_badarg(c_p);
    };
    if existing {
        return global_atoms().existing(bytes, encoding).map_or_else(
            || bif_badarg(c_p),
            |atom| crate::native_hooks::raw(Term::atom(atom)),
        );
    }
    match global_atoms().put(bytes, encoding, false) {
        Ok(atom) => crate::native_hooks::raw(Term::atom(atom)),
        Err(AtomError::TooLong | AtomError::SystemLimit) => bif_system_limit(c_p),
        Err(AtomError::BadEncoding) => bif_badarg(c_p),
    }
}

/// `unicode:bin_is_7bit/1`.
// Port of erts/emulator/beam/erl_unicode.c (unicode_bin_is_7bit_1), OTP-29.1.1.
pub(crate) extern "C" fn bin_is_7bit_1(_c_p: *mut ProcessHeader, reg: *mut u64, _i: u64) -> u64 {
    let [term] = crate::bif_table::bif_args::<1>(reg);
    let is_7bit = arinsal_term::raw::BinRef::try_from(term)
        .ok()
        .and_then(|binary| binary.bytes())
        .is_some_and(|bytes| bytes.iter().all(u8::is_ascii));
    crate::native_hooks::raw(Term::atom(if is_7bit { atoms::TRUE } else { atoms::FALSE }))
}
