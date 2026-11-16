//! Reference and unique integer BIFs.
//!
//! Port of erts/emulator/beam/erl_bif_unique.c and erl_bif_unique.h, OTP-29.1.1. The scheduler's
//! reference and unique counters are reached through the running process, as `c_p->scheduler_data`
//! reaches `ErtsSchedulerData` in erts.

use crate::bif_table::bif_args;
use crate::natives::bif::{badarg, bif_ret};
use crate::{Process, VmError};
use arinsal_beamasm::ProcessHeader;
use arinsal_bifs::ProcessHeapHandle;
use arinsal_term::{Term, TermBuilder, atoms};

/// `erlang:make_ref/0`.
// Port of erts/emulator/beam/erl_bif_unique.c (make_ref_0) and erl_bif_unique.h
// (erts_sched_make_ref_in_buffer), OTP-29.1.1.
pub(crate) extern "C" fn make_ref_0(c_p: *mut ProcessHeader, _reg: *mut u64, i: u64) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let result =
        Term::local_ref_with_process_heap(&mut process.heap, arinsal_sched::unique::next_ref_words);
    bif_ret(c_p, i, Ok(result))
}

fn system_limit() -> VmError {
    VmError::Trap(crate::exceptions::Trap::error(Term::atom(
        atoms::SYSTEM_LIMIT,
    )))
}

fn option_flags(options: Term) -> Result<(bool, bool), VmError> {
    // Port of erts/emulator/beam/erl_bif_unique.c (unique_integer_1), OTP-29.1.1: the option
    // list is walked comparing each element with `am_monotonic` and `am_positive`.
    let mut positive = false;
    let mut monotonic = false;
    let mut modlist = options;
    while let Ok(cons) = arinsal_term::raw::Cons::try_from(modlist) {
        let (option, next) = cons.pair();
        match option.as_atom() {
            Some(atoms::MONOTONIC) => monotonic = true,
            Some(atoms::POSITIVE) => positive = true,
            _ => return Err(badarg()),
        }
        modlist = next;
    }
    if modlist != Term::NIL {
        return Err(badarg());
    }
    Ok((positive, monotonic))
}

fn unique_value(process: &mut Process, positive: bool, monotonic: bool) -> Result<Term, VmError> {
    // Port of erts/emulator/beam/erl_bif_unique.c (unique_integer_bif,
    // unique_monotonic_integer_bif), OTP-29.1.1.
    if monotonic {
        return TermBuilder::new(&mut ProcessHeapHandle(&mut process.heap))
            .int_from_i128(if positive {
                arinsal_sched::unique::next_unique_monotonic_positive()
            } else {
                arinsal_sched::unique::next_unique_monotonic()
            })
            .map_err(|_| system_limit());
    }
    TermBuilder::new(&mut ProcessHeapHandle(&mut process.heap))
        .int_from_i128(arinsal_sched::unique::next_unique_integer(positive))
        .map_err(|_| system_limit())
}

/// `erlang:unique_integer/0`.
// Port of erts/emulator/beam/erl_bif_unique.c (unique_integer_0), OTP-29.1.1.
pub(crate) extern "C" fn unique_integer_0(c_p: *mut ProcessHeader, _reg: *mut u64, i: u64) -> u64 {
    call_unique(c_p, std::ptr::null_mut(), i, false)
}

/// `erlang:unique_integer/1`.
// Port of erts/emulator/beam/erl_bif_unique.c (unique_integer_1), OTP-29.1.1.
pub(crate) extern "C" fn unique_integer_1(c_p: *mut ProcessHeader, reg: *mut u64, i: u64) -> u64 {
    call_unique(c_p, reg, i, true)
}

fn call_unique(c_p: *mut ProcessHeader, reg: *mut u64, i: u64, has_options: bool) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let options = has_options.then(|| bif_args::<1>(reg)[0]);
    let result = if let Some(options) = options {
        option_flags(options)
            .and_then(|(positive, monotonic)| unique_value(process, positive, monotonic))
    } else {
        unique_value(process, false, false)
    };
    bif_ret(c_p, i, result)
}
