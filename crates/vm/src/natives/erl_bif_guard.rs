//! The trapping `length/1` of erl_bif_guard.c.
//!
//! Port of erts/emulator/beam/erl_bif_guard.c (length_1, erlang_length_trap,
//! erts_trapping_length_1), OTP-29.1.1. Each BIF is `bif_table[].f` with `(c_p, reg, I)`.
//! `length/1` is called from native code and `apply/3`; a list too long for the reductions left
//! traps to the hidden `erlang:length/3` (`erlang_length_export`, installed by
//! `erts_init_trap_export`) with `(List, Length, OriginalList)`.

use crate::natives::bif::bif_ret;
use arinsal_beamasm::ProcessHeader;
use arinsal_bifs::{BifCall, Ctx, LengthStep, ProcessHeapHandle};
use arinsal_term::Term;

/// `erlang:length/1`.
// Port of erts/emulator/beam/erl_bif_guard.c (length_1), OTP-29.1.1.
pub(crate) extern "C" fn length_1(c_p: *mut ProcessHeader, _reg: *mut u64, i: u64) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    // args[0] = BIF_ARG_1; args[1] = make_small(0); args[2] = BIF_ARG_1 (kept for the error).
    let list = process.x[0];
    length_run(c_p, i, process, list, 0, list)
}

/// `erlang:length/3`, the hidden trap target of `length_1`.
// Port of erts/emulator/beam/erl_bif_guard.c (erlang_length_trap), OTP-29.1.1.
pub(crate) extern "C" fn erlang_length_trap(
    c_p: *mut ProcessHeader,
    _reg: *mut u64,
    i: u64,
) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let (list, acc, original) = (process.x[0], process.x[1], process.x[2]);
    let Some(acc) = acc.as_small().and_then(|acc| usize::try_from(acc).ok()) else {
        return bif_ret(c_p, i, Err(crate::natives::bif::badarg()));
    };
    length_run(c_p, i, process, list, acc, original)
}

/// `erts_trapping_length_1` and the result handling of `erlang_length_trap`: the length,
/// `BIF_TRAP3(&erlang_length_export, ...)`, or `ERTS_BIF_ERROR_TRAPPED1` naming `length/1`
/// with the original argument.
fn length_run(
    c_p: *mut ProcessHeader,
    i: u64,
    process: &mut crate::Process,
    list: Term,
    acc: usize,
    original: Term,
) -> u64 {
    let step = {
        let mut heap = ProcessHeapHandle(&mut process.heap);
        let mut call = BifCall::default();
        let mut ctx = Ctx::with_fcalls(&mut heap, &mut call);
        arinsal_bifs::length_slice(&mut ctx, list, acc)
    };
    match step {
        Ok(LengthStep::Done(value)) => crate::native_hooks::raw(value),
        Ok(LengthStep::More(cont)) => {
            let acc = Term::small(cont.acc() as i64).expect("a list length is a small integer");
            let trap = crate::natives::erl_bif_lists::bif_trap(
                process,
                "erlang:length/3",
                vec![cont.list(), acc, original],
            );
            bif_ret(c_p, i, Err(trap))
        }
        Err(error) => {
            process.x[0] = original;
            let error =
                crate::exceptions::bif_error(process, "erlang", "length", &[original], error);
            bif_ret(c_p, i, Err(error))
        }
    }
}
