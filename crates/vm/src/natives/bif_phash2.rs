//! `erlang:phash2/1,2`.
//!
//! Port of erts/emulator/beam/bif.c (phash2_1, phash2_2) over erl_term_hashing.c
//! (`trapping_make_hash2`), OTP-29.1.1. Each BIF is `bif_table[].f` with `(c_p, reg, I)`. A walk
//! that runs out of reductions saves its context in a magic reference, disables GC and
//! `BIF_TRAP1(BIF_TRAP_EXPORT(BIF_phash2_1), c_p, state)` / `BIF_TRAP2(..phash2_2.., state,
//! range)`; the resumed call receives the magic reference as its first argument.

use super::bif::{badarg, bif_ret};
use super::erl_bif_lists::{bif_trap, create_trap_state};
use crate::{Process, VmError};
use arinsal_beamasm::ProcessHeader;
use arinsal_bifs::{BifCall, Ctx, Phash2Cont, Phash2Run, ProcessHeapHandle};
use arinsal_term::Term;
use std::sync::Mutex;

/// `sizeof(ErtsMakeHash2Context)` on a 64-bit build: the magic binary's `orig_size`.
// Port of erts/emulator/beam/erl_term_hashing.c (ErtsMakeHash2Context), OTP-29.1.1.
const ERTS_HASH2_CONTEXT_SIZE: usize = 136;

/// `erlang:phash2/1`.
// Port of erts/emulator/beam/bif.c (phash2_1), OTP-29.1.1.
pub(crate) extern "C" fn phash2_1(c_p: *mut ProcessHeader, _reg: *mut u64, i: u64) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let term = process.x[0];
    // make_hash2_helper: atoms and smalls hash before the trapping work loop, with no charge.
    if let Some(value) = arinsal_bifs::phash2_immediate_1(term) {
        return crate::native_hooks::raw(value);
    }
    let result = trapping_make_hash2(process, term, None, "erlang:phash2/1");
    bif_ret(c_p, i, result)
}

/// `erlang:phash2/2`.
// Port of erts/emulator/beam/bif.c (phash2_2), OTP-29.1.1.
pub(crate) extern "C" fn phash2_2(c_p: *mut ProcessHeader, _reg: *mut u64, i: u64) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let (term, range) = (process.x[0], process.x[1]);
    // The range is checked before the term is hashed, on a resumed call too.
    if arinsal_bifs::phash2_range_arg(range).is_err() {
        return bif_ret(c_p, i, Err(badarg()));
    }
    let result = trapping_make_hash2(process, term, Some(range), "erlang:phash2/2");
    bif_ret(c_p, i, result)
}

/// `trapping_make_hash2` and the result handling of `phash2_1` / `phash2_2`: restore a saved
/// context when `term` is one, else start; trap again, or return the hash.
// Port of erts/emulator/beam/erl_term_hashing.c (trapping_make_hash2) and
// erts/emulator/beam/bif.c (phash2_1, phash2_2), OTP-29.1.1.
fn trapping_make_hash2(
    process: &mut Process,
    term: Term,
    range: Option<Term>,
    bif: &'static str,
) -> Result<Term, VmError> {
    // `ASSERT(p->flags & F_DISABLE_GC); erts_set_gc_state(p, 1);` after restoring the context.
    let resumed = term.with_magic_payload::<Mutex<Phash2Cont>, _>(|context| {
        let mut context = context.lock().expect("phash2 context");
        process.set_gc_enabled(true);
        let mut heap = ProcessHeapHandle(&mut process.heap);
        let mut call = BifCall::default();
        let mut ctx = Ctx::with_fcalls(&mut heap, &mut call);
        arinsal_bifs::phash2_slice(&mut ctx, &mut context)
    });
    let trap_args = |state: Term| match range {
        Some(range) => vec![state, range],
        None => vec![state],
    };
    if let Some(step) = resumed {
        return match step {
            Ok(Some(value)) => Ok(value),
            // `BUMP_ALL_REDS` was charged by the slice; the context is saved again.
            Ok(None) => {
                process.set_gc_enabled(false);
                Err(bif_trap(process, bif, trap_args(term)))
            }
            Err(_) => Err(badarg()),
        };
    }
    let fcalls = process.heap.abi.fcalls;
    let run = match range {
        None => arinsal_bifs::phash2_run_1_after_immediate_check(term, fcalls),
        Some(range) => arinsal_bifs::phash2_run_2(term, range, fcalls),
    }
    .map_err(|_| badarg())?;
    match run {
        Phash2Run::Done { value, reductions } => {
            // BUMP_REDS(p, (max_iterations - iterations_until_trap) / ITERATIONS_PER_RED)
            let mut heap = ProcessHeapHandle(&mut process.heap);
            let mut call = BifCall::default();
            Ctx::with_fcalls(&mut heap, &mut call).charge_reductions(reductions as usize);
            Ok(value)
        }
        Phash2Run::More(context) => {
            // BUMP_ALL_REDS, then erts_set_gc_state(p, 0) with the context in a magic reference.
            let mut heap = ProcessHeapHandle(&mut process.heap);
            let mut call = BifCall::default();
            Ctx::with_fcalls(&mut heap, &mut call).bump_all_reds();
            let state = create_trap_state(process, *context, ERTS_HASH2_CONTEXT_SIZE)?;
            process.set_gc_enabled(false);
            Err(bif_trap(process, bif, trap_args(state)))
        }
    }
}
