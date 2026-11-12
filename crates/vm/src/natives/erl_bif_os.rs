//! OS environment BIFs.
//!
//! Port of erts/emulator/beam/erl_bif_os.c (os_env_0, os_getenv_1, os_putenv_2,
//! os_unsetenv_1, os_set_signal_2), OTP-29.1.1. The environment storage is
//! `erts_osenv_t` in `crate::erl_osenv`, protected by its process-wide rwlock.

use crate::VmError;
use arinsal_beamasm::ProcessHeader;
use arinsal_term::{Term, TermBuilder, TermKind, atoms};

fn native_bytes(term: Term, key: bool) -> Result<Vec<u8>, VmError> {
    if term.as_atom().is_some() {
        return Err(super::bif::badarg());
    }
    let mut out = Vec::new();
    if term.classify() == TermKind::Bitstring {
        let bits = arinsal_bifs::bitstring_bit_len(term).map_err(|_| super::bif::badarg())?;
        if !bits.is_multiple_of(8) {
            return Err(super::bif::badarg());
        }
        out.resize(bits / 8, 0);
        arinsal_bifs::copy_binary_range(term, 0, &mut out).map_err(|_| super::bif::badarg())?;
    } else {
        let mut cursor = term;
        while cursor != Term::NIL {
            if cursor.classify() != TermKind::List {
                return Err(super::bif::badarg());
            }
            // SAFETY: BIF arguments remain rooted in the active process heap during conversion.
            let (head, tail) = unsafe { cursor.cons_ref() }.ok_or_else(super::bif::badarg)?;
            let code = head
                .as_small()
                .and_then(|n| u32::try_from(n).ok())
                .and_then(char::from_u32)
                .ok_or_else(super::bif::badarg)?;
            let mut encoded = [0; 4];
            out.extend_from_slice(code.encode_utf8(&mut encoded).as_bytes());
            cursor = tail;
        }
    }
    if out.contains(&0) || (key && out.contains(&b'=')) {
        return Err(super::bif::badarg());
    }
    std::str::from_utf8(&out).map_err(|_| super::bif::badarg())?;
    Ok(out)
}

fn filename_term(process: &mut crate::Process, bytes: &[u8]) -> Result<Term, VmError> {
    let text = std::str::from_utf8(bytes).map_err(|_| super::bif::badarg())?;
    let mut tail = Term::NIL;
    for ch in text.chars().rev() {
        let code = Term::small(i64::from(ch as u32)).ok_or_else(super::bif::badarg)?;
        let mut heap = crate::ProcessHeapHandle(&mut process.heap);
        tail = TermBuilder::new(&mut heap)
            .cons(code, tail)
            .map_err(|_| super::bif::badarg())?;
    }
    Ok(tail)
}

/// `os:env/0`.
// Port of erts/emulator/beam/erl_bif_os.c:81-91 (os_getenv_foreach, os_env_0), OTP-29.1.1.
pub(crate) extern "C" fn env_0(c_p: *mut ProcessHeader, _reg: *mut u64, i: u64) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let env = crate::erl_osenv::read();
    let mut result = Term::NIL;
    for (key, value) in env.iter() {
        let key = match filename_term(process, key) {
            Ok(term) => term,
            Err(error) => return super::bif::bif_ret(c_p, i, Err(error)),
        };
        let value = match filename_term(process, value) {
            Ok(term) => term,
            Err(error) => return super::bif::bif_ret(c_p, i, Err(error)),
        };
        let mut heap = crate::ProcessHeapHandle(&mut process.heap);
        let pair = match TermBuilder::new(&mut heap).tuple(&[key, value]) {
            Ok(term) => term,
            Err(_) => return super::bif::bif_ret(c_p, i, Err(super::bif::badarg())),
        };
        result = match TermBuilder::new(&mut heap).cons(pair, result) {
            Ok(term) => term,
            Err(_) => return super::bif::bif_ret(c_p, i, Err(super::bif::badarg())),
        };
    }
    crate::native_hooks::raw(result)
}

/// `os:getenv/1`.
// Port of erts/emulator/beam/erl_bif_os.c:94-111 (os_getenv_1), OTP-29.1.1.
pub(crate) extern "C" fn getenv_1(c_p: *mut ProcessHeader, _reg: *mut u64, i: u64) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let env = crate::erl_osenv::read();
    let key = match native_bytes(process.x[0], true) {
        Ok(key) => key,
        Err(error) => return super::bif::bif_ret(c_p, i, Err(error)),
    };
    match env.get(&key) {
        Some(value) => match filename_term(process, value) {
            Ok(value) => crate::native_hooks::raw(value),
            Err(error) => super::bif::bif_ret(c_p, i, Err(error)),
        },
        None => crate::native_hooks::raw(Term::atom(atoms::FALSE)),
    }
}

/// `os:putenv/2`.
// Port of erts/emulator/beam/erl_bif_os.c:113-127 (os_putenv_2), OTP-29.1.1.
pub(crate) extern "C" fn putenv_2(c_p: *mut ProcessHeader, _reg: *mut u64, i: u64) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let mut env = crate::erl_osenv::write();
    let key = match native_bytes(process.x[0], true) {
        Ok(key) => key,
        Err(error) => return super::bif::bif_ret(c_p, i, Err(error)),
    };
    let value = match native_bytes(process.x[1], false) {
        Ok(value) => value,
        Err(error) => return super::bif::bif_ret(c_p, i, Err(error)),
    };
    env.put(&key, &value);
    crate::native_hooks::raw(Term::atom(atoms::TRUE))
}

/// `os:unsetenv/1`.
// Port of erts/emulator/beam/erl_bif_os.c:129-143 (os_unsetenv_1), OTP-29.1.1.
pub(crate) extern "C" fn unsetenv_1(c_p: *mut ProcessHeader, _reg: *mut u64, i: u64) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let mut env = crate::erl_osenv::write();
    let key = match native_bytes(process.x[0], true) {
        Ok(key) => key,
        Err(error) => return super::bif::bif_ret(c_p, i, Err(error)),
    };
    env.unset(&key);
    crate::native_hooks::raw(Term::atom(atoms::TRUE))
}

/// `os:set_signal/2`.
// Port of erts/emulator/beam/erl_bif_os.c:145-164 (os_set_signal_2), OTP-29.1.1.
pub(crate) extern "C" fn set_signal_2(c_p: *mut ProcessHeader, _reg: *mut u64, i: u64) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let (signal, action) = (process.x[0], process.x[1]);
    if action != Term::atom(atoms::IGNORE)
        && action != Term::atom(atoms::DEFAULT)
        && action != Term::atom(atoms::HANDLE)
    {
        let error = super::bif::badarg_ext(
            crate::atom_cache::put("os").as_atom().expect("os atom"),
            "set_signal",
            2,
            Term::atom(atoms::BADOPT),
        );
        return super::bif::bif_ret(c_p, i, Err(error));
    }
    match super::env::set_signal(process, signal, action) {
        Ok(value) => crate::native_hooks::raw(value),
        Err(error) => super::bif::bif_ret(c_p, i, Err(error)),
    }
}
