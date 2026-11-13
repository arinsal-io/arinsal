//! `iolist_size/1` of erl_iolist.c.
//!
//! Port of erts/emulator/beam/erl_iolist.c (iolist_size_1, iolist_size_continue,
//! iolist_size_dispatch), OTP-29.1.1. Each BIF is `bif_table[].f` with `(c_p, reg, I)`. A walk
//! that runs out of reductions keeps its state in a magic binary, disables collection and
//! `BIF_TRAP1`s to the hidden `erts_internal:iolist_size_continue/1`
//! (`iolist_size_continue_export`, installed by `erts_init_trap_export`).

use crate::natives::bif::bif_ret;
use arinsal_beamasm::ProcessHeader;
use arinsal_bifs::{BifCall, BifError, Ctx, IolistSizeWalk, ProcessHeapHandle};
use arinsal_term::{MagicRef, Term, TermBuilder};
use std::sync::{Arc, Mutex};

/// `sizeof(IOListSizeState)` on a 64-bit build: the magic binary's `orig_size`.
// Port of erts/emulator/beam/erl_iolist.c (IOListSizeState), OTP-29.1.1.
const ERTS_IOLIST_SIZE_STATE_SIZE: usize = 88;

/// Yield counts of `generic_iolist_size` per reduction left.
const SIZE_YIELDS_PER_RED: usize = 8;

/// `IOListSizeState`: the walk and the original argument `ERTS_BIF_ERROR_TRAPPED1` names.
struct SizeState {
    walk: IolistSizeWalk,
    arg: Term,
}

type SizeHolder = Mutex<Option<SizeState>>;

/// `erlang:iolist_size/1`.
// Port of erts/emulator/beam/erl_iolist.c (iolist_size_1), OTP-29.1.1.
pub(crate) extern "C" fn iolist_size_1(c_p: *mut ProcessHeader, _reg: *mut u64, i: u64) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let arg = process.x[0];
    let state = SizeState {
        walk: IolistSizeWalk::new(arg),
        arg,
    };
    iolist_size_dispatch(c_p, i, process, state, None)
}

/// `erts_internal:iolist_size_continue/1`.
// Port of erts/emulator/beam/erl_iolist.c (iolist_size_continue), OTP-29.1.1.
pub(crate) extern "C" fn iolist_size_continue_1(
    c_p: *mut ProcessHeader,
    _reg: *mut u64,
    i: u64,
) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let mref = process.x[0];
    let state = mref
        .with_magic_payload::<SizeHolder, _>(|holder| holder.lock().ok()?.take())
        .flatten();
    match state {
        Some(state) => iolist_size_dispatch(c_p, i, process, state, Some(mref)),
        None => bif_ret(c_p, i, Err(crate::natives::bif::badarg())),
    }
}

/// `iolist_size_dispatch`: the size, `BIF_TRAP1` to `iolist_size_continue_export`, or
/// `ERTS_BIF_ERROR_TRAPPED1` naming `iolist_size/1` with the original argument.
fn iolist_size_dispatch(
    c_p: *mut ProcessHeader,
    i: u64,
    process: &mut crate::Process,
    mut state: SizeState,
    mref: Option<Term>,
) -> u64 {
    let gc_disabled = mref.is_some();
    let budget = (process.heap.abi.fcalls.max(0) as usize).saturating_mul(SIZE_YIELDS_PER_RED);
    let step = state.walk.step(budget);
    let work = match step {
        Ok((_, work)) | Err((_, work)) => work,
    };
    // generic_iolist_size's BUMP_REDS of the yield counts used.
    charge(process, arinsal_bifs::iolist_yield_reductions(work));
    match step {
        Ok((false, _)) => {
            let mref = match mref {
                Some(mref) => {
                    let _ = mref.with_magic_payload::<SizeHolder, _>(|holder| {
                        *holder.lock().expect("iolist size state") = Some(state);
                    });
                    mref
                }
                None => {
                    let holder: Arc<MagicRef> = MagicRef::with_erts_payload_size_and_refn(
                        SizeHolder::new(Some(state)),
                        ERTS_IOLIST_SIZE_STATE_SIZE,
                        arinsal_bifs::next_ref_words(),
                    );
                    let built = {
                        let mut heap = ProcessHeapHandle(&mut process.heap);
                        TermBuilder::new(&mut heap).magic_ref(holder)
                    };
                    match built {
                        Ok(mref) => {
                            process.set_gc_enabled(false);
                            mref
                        }
                        Err(_) => {
                            return fail(c_p, i, process, Term::NIL, BifError::SystemLimit, false);
                        }
                    }
                }
            };
            let trap = crate::natives::erl_bif_lists::bif_trap(
                process,
                "erts_internal:iolist_size_continue/1",
                vec![mref],
            );
            bif_ret(c_p, i, Err(trap))
        }
        Ok((true, _)) => {
            let size = state.walk.take_size();
            let built = {
                let mut heap = ProcessHeapHandle(&mut process.heap);
                u64::try_from(size)
                    .ok()
                    .and_then(|size| TermBuilder::new(&mut heap).int_from_u64(size).ok())
            };
            match built {
                Some(value) => {
                    if gc_disabled {
                        process.set_gc_enabled(true);
                    }
                    crate::native_hooks::raw(value)
                }
                None => fail(
                    c_p,
                    i,
                    process,
                    state.arg,
                    BifError::SystemLimit,
                    gc_disabled,
                ),
            }
        }
        Err((error, _)) => fail(c_p, i, process, state.arg, error, gc_disabled),
    }
}

/// `ERTS_BIF_ERROR_TRAPPED1(c_p, reason, BIF_TRAP_EXPORT(BIF_iolist_size_1), arg)` after
/// `erts_set_gc_state(c_p, 1)` of a parked call.
fn fail(
    c_p: *mut ProcessHeader,
    i: u64,
    process: &mut crate::Process,
    arg: Term,
    error: BifError,
    gc_disabled: bool,
) -> u64 {
    if gc_disabled {
        process.set_gc_enabled(true);
    }
    process.x[0] = arg;
    let error = crate::exceptions::bif_error(process, "erlang", "iolist_size", &[arg], error);
    bif_ret(c_p, i, Err(error))
}

/// `BUMP_REDS(c_p, reds)`.
fn charge(process: &mut crate::Process, reds: usize) {
    let mut heap = ProcessHeapHandle(&mut process.heap);
    let mut call = BifCall::default();
    let mut ctx = Ctx::with_fcalls(&mut heap, &mut call);
    ctx.charge_reductions(reds);
}
