//! The ETS BIFs of erl_db.c that are `bif_table[].f` bodies: `ets:insert/2`,
//! `ets:insert_new/2` and `ets:lookup/2`.
//!
//! Each is called with `(c_p, reg, I)` by `call_light_bif_shared`. A value returns in x0, a
//! failure is `BIF_ERROR`. The list insert of `ets_insert_2_list_driver` still runs in the
//! executor (the call is parked there), until its trap state is ported.

use crate::VmError;
use crate::bif_table::bif_args;
use crate::natives::ets;
use arinsal_beamasm::ProcessHeader;

/// `BIF_RET` / `BIF_ERROR` of an ETS body. A failure that is not an exception is a call only the
/// executor completes.
#[inline(always)]
fn finish(
    c_p: *mut ProcessHeader,
    reg: *mut u64,
    i: u64,
    function: &str,
    args: &[arinsal_term::Term],
    result: Result<arinsal_term::Term, VmError>,
) -> u64 {
    match result {
        Ok(value) => crate::native_hooks::raw(value),
        Err(error) => finish_error(c_p, reg, i, function, args, error),
    }
}

#[cold]
#[inline(never)]
fn finish_error(
    c_p: *mut ProcessHeader,
    reg: *mut u64,
    i: u64,
    function: &str,
    args: &[arinsal_term::Term],
    error: VmError,
) -> u64 {
    match ets::bif_failure(function, args, Err(error)) {
        Err(error @ VmError::Trap(_)) => crate::native_helpers::bif_return_current(c_p, i, error),
        Ok(value) => crate::native_hooks::raw(value),
        Err(_) => crate::native_helpers::yield_executor_bif(c_p, reg, i),
    }
}

fn insert_body<const NEW: bool>(c_p: *mut ProcessHeader, reg: *mut u64, i: u64) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let x = bif_args::<2>(reg);
    let result = ets::ets_insert_2::<NEW>(process, &x);
    finish(
        c_p,
        reg,
        i,
        if NEW { "insert_new" } else { "insert" },
        &x,
        result,
    )
}

/// `ets:insert/2`.
// Port of erts/emulator/beam/erl_db.c (ets_insert_2), OTP-29.1.1.
pub(crate) extern "C" fn ets_insert_2(c_p: *mut ProcessHeader, reg: *mut u64, i: u64) -> u64 {
    insert_body::<false>(c_p, reg, i)
}

/// `ets:insert_new/2`.
// Port of erts/emulator/beam/erl_db.c (ets_insert_new_2), OTP-29.1.1.
pub(crate) extern "C" fn ets_insert_new_2(c_p: *mut ProcessHeader, reg: *mut u64, i: u64) -> u64 {
    insert_body::<true>(c_p, reg, i)
}

/// `ets:lookup/2`.
// Port of erts/emulator/beam/erl_db.c (ets_lookup_2), OTP-29.1.1.
pub(crate) extern "C" fn ets_lookup_2(c_p: *mut ProcessHeader, reg: *mut u64, i: u64) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let x = bif_args::<2>(reg);
    let result = ets::ets_lookup_2(process, &x);
    finish(c_p, reg, i, "lookup", &x, result)
}
