//! `binary_to_list/1,3` of binary.c.
//!
//! Port of erts/emulator/beam/binary.c (binary_to_list_1, binary_to_list_3, binary_to_list,
//! binary_to_list_chunk, binary_to_list_continue), OTP-29.1.1. Each BIF is `bif_table[].f`
//! with `(c_p, reg, I)`. A list too long for the reductions left is filled in chunks from its
//! end: the state (`ErtsB2LState`) lives in a magic binary, collection is disabled while
//! parked, and the BIF `BIF_TRAP1`s to the hidden `erts_internal:binary_to_list_continue/1`.

use crate::natives::bif::{badarg, bif_ret};
use crate::natives::erl_bif_lists::bif_trap;
use arinsal_beamasm::ProcessHeader;
use arinsal_bifs::{B2L_BYTES_PER_REDUCTION, BifCall, BinaryToListWalk, Ctx, ProcessHeapHandle};
use arinsal_term::{MagicRef, Term, TermBuilder};
use std::sync::{Arc, Mutex};

/// `CONTEXT_REDS`, `B2L_MIN_EXEC_REDS` and `B2L_RESCHED_REDS`.
const CONTEXT_REDS: usize = 4000;
const B2L_MIN_EXEC_REDS: usize = CONTEXT_REDS / 4;
const B2L_RESCHED_REDS: usize = CONTEXT_REDS / 40;

/// `sizeof(ErtsB2LState)` on a 64-bit build: the magic binary's `orig_size`.
// Port of erts/emulator/beam/binary.c (ErtsB2LState), OTP-29.1.1.
const ERTS_B2L_STATE_SIZE: usize = 40;

type B2lHolder = Mutex<BinaryToListWalk>;

/// `erlang:binary_to_list/1`.
// Port of erts/emulator/beam/binary.c (binary_to_list_1), OTP-29.1.1.
pub(crate) extern "C" fn binary_to_list_1(c_p: *mut ProcessHeader, _reg: *mut u64, i: u64) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let bin = process.x[0];
    let Ok((bits, byte_start, bit_offset)) = arinsal_bifs::bitstring_source(bin) else {
        return bif_ret(c_p, i, Err(badarg()));
    };
    if bits == 0 {
        return crate::native_hooks::raw(Term::NIL);
    }
    if bits % 8 != 0 {
        return bif_ret(c_p, i, Err(badarg()));
    }
    let size = bits / 8;
    binary_to_list_checked(
        c_p,
        i,
        process,
        "erlang:binary_to_list/1",
        1,
        (bin, byte_start, bit_offset, size),
    )
}

/// `erlang:binary_to_list/3`.
// Port of erts/emulator/beam/binary.c (binary_to_list_3), OTP-29.1.1.
pub(crate) extern "C" fn binary_to_list_3(c_p: *mut ProcessHeader, _reg: *mut u64, i: u64) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let (bin, start, stop) = (process.x[0], process.x[1], process.x[2]);
    let Ok((bits, byte_start, bit_offset)) = arinsal_bifs::bitstring_source(bin) else {
        return bif_ret(c_p, i, Err(badarg()));
    };
    // term_to_Uint: a non-negative small integer.
    let to_uint = |term: Term| term.as_small().and_then(|n| usize::try_from(n).ok());
    let (Some(start), Some(stop)) = (to_uint(start), to_uint(stop)) else {
        return bif_ret(c_p, i, Err(badarg()));
    };
    if bits % 8 != 0 {
        return bif_ret(c_p, i, Err(badarg()));
    }
    let size = bits / 8;
    if start < 1 || start > size || stop < 1 || stop > size || stop < start {
        return bif_ret(c_p, i, Err(badarg()));
    }
    if size == 0 {
        return crate::native_hooks::raw(Term::NIL);
    }
    binary_to_list_checked(
        c_p,
        i,
        process,
        "erlang:binary_to_list/3",
        3,
        (bin, byte_start + start - 1, bit_offset, stop - start + 1),
    )
}

/// The tail shared by `binary_to_list_1` and `_3`: the one-chunk decision and the
/// `ERTS_BIF_YIELD1/3` of a call that gets too few reductions.
fn binary_to_list_checked(
    c_p: *mut ProcessHeader,
    i: u64,
    process: &mut crate::Process,
    bif: &'static str,
    arity: usize,
    (bin, source_start, bit_offset, count): (Term, usize, usize, usize),
) -> u64 {
    // `size` of the C code is the whole binary's byte size for the decision below.
    let size = arinsal_bifs::bitstring_source(bin).map_or(0, |(bits, _, _)| bits / 8);
    let mut reds_left = process.heap.abi.fcalls.max(0) as usize;
    let mut one_chunk = size < reds_left.saturating_mul(B2L_BYTES_PER_REDUCTION);
    if !one_chunk && size < B2L_MIN_EXEC_REDS * B2L_BYTES_PER_REDUCTION {
        if reds_left <= B2L_RESCHED_REDS {
            // ERTS_BIF_YIELD1/3: ERTS_VBUMP_ALL_REDS, then BIF_TRAP to the BIF itself.
            crate::bif_traps::vbump_all_reds(process);
            let args = process.x[..arity].to_vec();
            let trap = bif_trap(process, bif, args);
            return bif_ret(c_p, i, Err(trap));
        }
        one_chunk = true;
        reds_left = B2L_MIN_EXEC_REDS;
    }
    binary_to_list(
        c_p,
        i,
        process,
        BinaryToListWalk::new(bin, source_start, bit_offset, count),
        reds_left,
        one_chunk,
    )
}

/// `binary_to_list`: the whole list in one chunk, or the first chunk of a trapped fill.
// Port of erts/emulator/beam/binary.c (binary_to_list), OTP-29.1.1.
fn binary_to_list(
    c_p: *mut ProcessHeader,
    i: u64,
    process: &mut crate::Process,
    mut walk: BinaryToListWalk,
    reds_left: usize,
    one_chunk: bool,
) -> u64 {
    if one_chunk {
        // BUMP_REDS((size - 1)/ERTS_B2L_BYTES_PER_REDUCTION + 1) before the fill.
        return match chunk_locked(process, &mut walk, usize::MAX) {
            Ok(Some(value)) => crate::native_hooks::raw(value),
            Ok(None) => unreachable!("an unbounded chunk finishes the list"),
            Err(error) => bif_ret(c_p, i, Err(error)),
        };
    }
    let Some(mref) = create_state(process, walk) else {
        return bif_ret(c_p, i, Err(system_limit()));
    };
    binary_to_list_chunk(c_p, i, process, mref, reds_left, false)
}

/// `erts_internal:binary_to_list_continue/1`.
// Port of erts/emulator/beam/binary.c (binary_to_list_continue), OTP-29.1.1.
pub(crate) extern "C" fn binary_to_list_continue_1(
    c_p: *mut ProcessHeader,
    _reg: *mut u64,
    i: u64,
) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let mref = process.x[0];
    let reds_left = process.heap.abi.fcalls.max(0) as usize;
    binary_to_list_chunk(c_p, i, process, mref, reds_left, true)
}

/// `binary_to_list_chunk`: fill the next chunk from the end, then return the list or trap again.
// Port of erts/emulator/beam/binary.c (binary_to_list_chunk), OTP-29.1.1.
fn binary_to_list_chunk(
    c_p: *mut ProcessHeader,
    i: u64,
    process: &mut crate::Process,
    mref: Term,
    reds_left: usize,
    gc_disabled: bool,
) -> u64 {
    let size = reds_left
        .saturating_add(1)
        .saturating_mul(B2L_BYTES_PER_REDUCTION);
    let stepped = mref
        .with_magic_payload::<B2lHolder, _>(|holder| {
            let mut walk = holder.lock().expect("binary_to_list state");
            chunk_locked(process, &mut walk, size)
        })
        .unwrap_or_else(|| Err(badarg()));
    match stepped {
        Ok(None) => {
            if !gc_disabled {
                process.set_gc_enabled(false);
            }
            let trap = bif_trap(
                process,
                "erts_internal:binary_to_list_continue/1",
                vec![mref],
            );
            bif_ret(c_p, i, Err(trap))
        }
        Ok(Some(value)) => {
            if gc_disabled {
                process.set_gc_enabled(true);
                if process.delayed_gc_due() {
                    // ERTS_BIF_PREP_YIELD_RETURN: ERTS_VBUMP_ALL_REDS, then bif_return_trap.
                    crate::bif_traps::vbump_all_reds(process);
                    let undefined = Term::atom(arinsal_term::atoms::UNDEFINED);
                    let trap =
                        bif_trap(process, "erlang:bif_return_trap/2", vec![value, undefined]);
                    return bif_ret(c_p, i, Err(trap));
                }
            }
            crate::native_hooks::raw(value)
        }
        Err(error) => bif_ret(c_p, i, Err(error)),
    }
}

/// `BUMP_REDS` of the bytes in the chunk, then `erts_bin_bytes_to_list` from the end.
fn chunk_locked(
    process: &mut crate::Process,
    walk: &mut BinaryToListWalk,
    size: usize,
) -> Result<Option<Term>, crate::VmError> {
    let mut heap = ProcessHeapHandle(&mut process.heap);
    let (value, used) = walk.step(&mut heap, size).map_err(|_| system_limit())?;
    let reds = used.saturating_sub(1) / B2L_BYTES_PER_REDUCTION + 1;
    let mut call = BifCall::default();
    let mut ctx = Ctx::with_fcalls(&mut heap, &mut call);
    ctx.charge_reductions(reds);
    Ok(value)
}

/// `erts_create_magic_binary(sizeof(ErtsB2LState))` + `erts_mk_magic_ref`.
fn create_state(process: &mut crate::Process, walk: BinaryToListWalk) -> Option<Term> {
    let state: Arc<MagicRef> = MagicRef::with_erts_payload_size_and_refn(
        B2lHolder::new(walk),
        ERTS_B2L_STATE_SIZE,
        arinsal_bifs::next_ref_words(),
    );
    let mut heap = ProcessHeapHandle(&mut process.heap);
    TermBuilder::new(&mut heap).magic_ref(state).ok()
}

fn system_limit() -> crate::VmError {
    crate::VmError::Trap(crate::exceptions::Trap::error(Term::atom(
        arinsal_term::atoms::SYSTEM_LIMIT,
    )))
}
