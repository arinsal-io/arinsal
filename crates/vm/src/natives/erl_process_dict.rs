//! The process dictionary BIFs.
//!
//! Port of erts/emulator/beam/erl_process_dict.c (get_0, get_1, get_keys_0, get_keys_1, put_2,
//! erase_0, erase_1, erts_pd_hash_get), OTP-29.1.1. Each BIF is `bif_table[].f`, called by
//! `call_light_bif_shared` / `call_bif_shared` with `(c_p, reg, I)`; GC after the BIF is the
//! fragment's. The hash itself is `proc_create::ProcDict`.

use crate::Process;
use arinsal_beamasm::ProcessHeader;
use arinsal_term::{Term, TermBuilder};

fn undefined() -> Term {
    Term::atom(arinsal_term::atoms::UNDEFINED)
}

/// `BIF_RET` of a term the BIF built on the process heap; `HAlloc` does not fail in erts, a
/// heap that cannot grow is `system_limit` here.
fn heap_result(process: &mut Process, built: Result<Term, arinsal_term::TermError>) -> u64 {
    match built {
        Ok(value) => crate::native_hooks::raw(value),
        Err(_) => crate::native_helpers::bif_error(
            process,
            crate::exceptions::Trap::error(Term::atom(arinsal_term::atoms::SYSTEM_LIMIT)),
        ),
    }
}

/// `erts_pd_hash_get`: the value of `key`, or `undefined`. Called by `get_1` and by the `i_get`
/// instruction, which does not store HTOP: the lookup never allocates.
// Port of erts/emulator/beam/erl_process_dict.c (erts_pd_hash_get) and
// jit/arm/instr_common.cpp (emit_i_get: `runtime_call<..., erts_pd_hash_get>`), OTP-29.1.1.
pub extern "C" fn erts_pd_hash_get(c_p: *mut ProcessHeader, key: u64) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    crate::native_hooks::raw(pd_hash_get(process, crate::native_hooks::from_raw(key)))
}

fn pd_hash_get(process: &Process, key: Term) -> Term {
    process
        .dictionary
        .as_ref()
        .and_then(|dictionary| dictionary.get(key))
        .unwrap_or_else(undefined)
}

/// `get/0`.
// Port of erts/emulator/beam/erl_process_dict.c (get_0, pd_hash_get_all), OTP-29.1.1.
pub(crate) extern "C" fn get_0(c_p: *mut ProcessHeader, _reg: *mut u64, _i: u64) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    let Some(dictionary) = process.dictionary.as_ref().filter(|d| d.len() != 0) else {
        return crate::native_hooks::raw(Term::NIL);
    };
    let len = dictionary.len();
    let entries = dictionary.entries();
    let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
    let built = TermBuilder::new(&mut heap).tuple2_list_from_iter_reversed(len, entries);
    heap_result(process, built)
}

/// `get/1`.
// Port of erts/emulator/beam/erl_process_dict.c (get_1), OTP-29.1.1.
pub(crate) extern "C" fn get_1(c_p: *mut ProcessHeader, _reg: *mut u64, _i: u64) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    // BIF_ARG_1: `reg[0]`, the scheduler register file `process.x` is for native code.
    let key = process.x[0];
    crate::native_hooks::raw(pd_hash_get(process, key))
}

/// `get_keys/0`.
// Port of erts/emulator/beam/erl_process_dict.c (get_keys_0, pd_hash_get_all_keys), OTP-29.1.1.
pub(crate) extern "C" fn get_keys_0(c_p: *mut ProcessHeader, _reg: *mut u64, _i: u64) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    let keys: Vec<Term> = process
        .dictionary
        .as_ref()
        .map_or_else(Vec::new, |dictionary| {
            dictionary
                .entries_reversed()
                .into_iter()
                .map(|(key, _)| key)
                .collect()
        });
    let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
    let built = TermBuilder::new(&mut heap).list_from_iter(keys);
    heap_result(process, built)
}

/// `get_keys/1`.
// Port of erts/emulator/beam/erl_process_dict.c (get_keys_1, pd_hash_get_keys), OTP-29.1.1.
pub(crate) extern "C" fn get_keys_1(c_p: *mut ProcessHeader, _reg: *mut u64, _i: u64) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    let value = process.x[0];
    let keys: Vec<Term> = process
        .dictionary
        .as_ref()
        .map_or_else(Vec::new, |dictionary| {
            dictionary
                .entries_reversed()
                .into_iter()
                .filter_map(|(key, stored)| arinsal_term::exact_eq(stored, value).then_some(key))
                .collect()
        });
    let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
    let built = TermBuilder::new(&mut heap).list_from_iter(keys);
    heap_result(process, built)
}

/// `put/2`.
// Port of erts/emulator/beam/erl_process_dict.c (put_2, pd_hash_put), OTP-29.1.1.
pub(crate) extern "C" fn put_2(c_p: *mut ProcessHeader, _reg: *mut u64, _i: u64) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    let (key, value) = (process.x[0], process.x[1]);
    let old = process
        .dictionary
        .get_or_insert_with(Box::<crate::proc_create::ProcDict>::default)
        .put(key, value)
        .unwrap_or_else(undefined);
    crate::native_hooks::raw(old)
}

/// `erase/0`.
// Port of erts/emulator/beam/erl_process_dict.c (erase_0, pd_hash_get_all,
// pd_hash_erase_all), OTP-29.1.1.
pub(crate) extern "C" fn erase_0(c_p: *mut ProcessHeader, _reg: *mut u64, _i: u64) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    let Some(dictionary) = process.dictionary.take().filter(|d| d.len() != 0) else {
        return crate::native_hooks::raw(Term::NIL);
    };
    let len = dictionary.len();
    let entries = dictionary.entries();
    let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
    let built = TermBuilder::new(&mut heap).tuple2_list_from_iter_reversed(len, entries);
    heap_result(process, built)
}

/// `erase/1`.
// Port of erts/emulator/beam/erl_process_dict.c (erase_1, pd_hash_erase), OTP-29.1.1.
pub(crate) extern "C" fn erase_1(c_p: *mut ProcessHeader, _reg: *mut u64, _i: u64) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    let key = process.x[0];
    let old = process
        .dictionary
        .as_mut()
        .and_then(|dictionary| dictionary.erase(key))
        .unwrap_or_else(undefined);
    crate::native_hooks::raw(old)
}
