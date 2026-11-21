//! `binary_to_list/1,3`, `bitstring_to_list/1` and `split_binary/2` of binary.c.
//!
//! Port of erts/emulator/beam/binary.c (binary_to_list_1, binary_to_list_3, binary_to_list,
//! binary_to_list_chunk, binary_to_list_continue), OTP-29.1.1. Each BIF is `bif_table[].f`
//! with `(c_p, reg, I)`. A list too long for the reductions left is filled in chunks from its
//! end: the state (`ErtsB2LState`) lives in a magic binary, collection is disabled while
//! parked, and the BIF `BIF_TRAP1`s to the hidden `erts_internal:binary_to_list_continue/1`.

use crate::bif_traps::TrapContext;
use crate::natives::bif::bif_badarg;
use crate::natives::bif::{badarg, bif_ret};
use crate::natives::erl_bif_lists::bif_trap;
use arinsal_beamasm::ProcessHeader;
use arinsal_bifs::{BifCall, Ctx, ProcessHeapHandle};
use arinsal_term::raw::BinRef;
use arinsal_term::{ConsListBuilder, MagicBin, Term, TermBuilder};

/// `ERTS_B2L_BYTES_PER_REDUCTION`.
const B2L_BYTES_PER_REDUCTION: usize = 256;

/// `CONTEXT_REDS`, `B2L_MIN_EXEC_REDS` and `B2L_RESCHED_REDS`.
const CONTEXT_REDS: usize = 4000;
const B2L_MIN_EXEC_REDS: usize = CONTEXT_REDS / 4;
const B2L_RESCHED_REDS: usize = CONTEXT_REDS / 40;

/// `sizeof(ErtsB2LState)` on a 64-bit build: the magic binary's `orig_size`.
// Port of erts/emulator/beam/binary.c (ErtsB2LState), OTP-29.1.1.
const ERTS_B2L_STATE_SIZE: usize = 40;

/// `ErtsB2LState`: the source, how much of it is still to be turned into cells, and the
/// reserved cells filled from the end of the source.
// Port of erts/emulator/beam/binary.c (ErtsB2LState, binary_to_list_chunk), OTP-29.1.1.
struct B2lState {
    source: Term,
    source_start: usize,
    bit_offset: usize,
    remaining: usize,
    total: usize,
    /// What the last cell points at: `[]`, or the cell of a trailing partial byte.
    tail: Term,
    list: Option<ConsListBuilder>,
}

impl B2lState {
    fn new(source: Term, source_start: usize, bit_offset: usize, size: usize, tail: Term) -> Self {
        Self {
            source,
            source_start,
            bit_offset,
            remaining: size,
            total: size,
            tail,
            list: None,
        }
    }

    /// `binary_to_list_chunk`: fill at most `max_bytes` more cells, from the end of the source;
    /// the list once all are filled and the bytes of this chunk.
    fn step(
        &mut self,
        heap: &mut ProcessHeapHandle<'_>,
        max_bytes: usize,
    ) -> Result<(Option<Term>, usize), ()> {
        if self.list.is_none() {
            self.list = Some(
                TermBuilder::new(heap)
                    .reserve_cons_list(self.total)
                    .map_err(|_| ())?,
            );
        }
        let view = BinRef::try_from(self.source).map_err(|_| ())?;
        let count = self.remaining.min(max_bytes);
        let from = self.source_start + self.remaining - count;
        let list = self.list.as_mut().ok_or(())?;
        list.prepend_binary_bytes(view.window(), from, count, self.bit_offset)
            .map_err(|_| ())?;
        self.remaining -= count;
        if self.remaining != 0 {
            return Ok((None, count));
        }
        let value = self
            .list
            .take()
            .ok_or(())?
            .finish(self.tail)
            .map_err(|_| ())?;
        Ok((Some(value), count))
    }
}

/// `ERTS_GET_BITSTRING`: the bit length, first byte and bit offset of a bitstring.
fn bitstring_source(term: Term) -> Option<(usize, usize, usize)> {
    let view = BinRef::try_from(term).ok()?;
    Some((view.bit_len(), view.start_bit() / 8, view.start_bit() % 8))
}

type B2lHolder = TrapContext<B2lState>;

/// `erlang:binary_to_list/1`.
// Port of erts/emulator/beam/binary.c (binary_to_list_1), OTP-29.1.1.
pub(crate) extern "C" fn binary_to_list_1(c_p: *mut ProcessHeader, reg: *mut u64, i: u64) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let [bin] = crate::bif_table::bif_args::<1>(reg);
    let Some((bits, byte_start, bit_offset)) = bitstring_source(bin) else {
        return bif_badarg(c_p);
    };
    if bits == 0 {
        return crate::native_hooks::raw(Term::NIL);
    }
    if bits % 8 != 0 {
        return bif_badarg(c_p);
    }
    let size = bits / 8;
    binary_to_list_checked(
        c_p,
        reg,
        i,
        process,
        "erlang:binary_to_list/1",
        1,
        (bin, byte_start, bit_offset, size),
        Term::NIL,
        size,
    )
}

/// `erlang:binary_to_list/3`.
// Port of erts/emulator/beam/binary.c (binary_to_list_3), OTP-29.1.1.
pub(crate) extern "C" fn binary_to_list_3(c_p: *mut ProcessHeader, reg: *mut u64, i: u64) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let [bin, start, stop] = crate::bif_table::bif_args::<3>(reg);
    let Some((bits, byte_start, bit_offset)) = bitstring_source(bin) else {
        return bif_badarg(c_p);
    };
    // term_to_Uint: a non-negative small integer.
    let to_uint = |term: Term| term.as_small().and_then(|n| usize::try_from(n).ok());
    let (Some(start), Some(stop)) = (to_uint(start), to_uint(stop)) else {
        return bif_badarg(c_p);
    };
    if bits % 8 != 0 {
        return bif_badarg(c_p);
    }
    let size = bits / 8;
    if start < 1 || start > size || stop < 1 || stop > size || stop < start {
        return bif_badarg(c_p);
    }
    if size == 0 {
        return crate::native_hooks::raw(Term::NIL);
    }
    binary_to_list_checked(
        c_p,
        reg,
        i,
        process,
        "erlang:binary_to_list/3",
        3,
        (bin, byte_start + start - 1, bit_offset, stop - start + 1),
        Term::NIL,
        size,
    )
}

/// `erlang:bitstring_to_list/1`.
// Port of erts/emulator/beam/binary.c (bitstring_to_list_1), OTP-29.1.1.
pub(crate) extern "C" fn bitstring_to_list_1(
    c_p: *mut ProcessHeader,
    reg: *mut u64,
    i: u64,
) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let [bin] = crate::bif_table::bif_args::<1>(reg);
    let Some((size, byte_start, bit_offset)) = bitstring_source(bin) else {
        return bif_badarg(c_p);
    };
    if size == 0 {
        return crate::native_hooks::raw(Term::NIL);
    }
    // One cell per byte, plus one more for the trailing bits if any.
    let cells = size.div_ceil(8);
    let tail_bits = size % 8;
    let tail = if tail_bits == 0 {
        Term::NIL
    } else {
        // The trailing bits are a bitstring of their own, in the last cell.
        let mut heap = ProcessHeapHandle(&mut process.heap);
        let mut builder = TermBuilder::new(&mut heap);
        let cell = builder
            .sub_binary(bin, size - tail_bits, tail_bits)
            .and_then(|last| builder.cons(last, Term::NIL));
        match cell {
            Ok(cell) => cell,
            Err(_) => return bif_ret(c_p, i, Err(system_limit())),
        }
    };
    binary_to_list_checked(
        c_p,
        reg,
        i,
        process,
        "erlang:bitstring_to_list/1",
        1,
        (bin, byte_start, bit_offset, size / 8),
        tail,
        cells,
    )
}

/// `erlang:split_binary/2`.
// Port of erts/emulator/beam/binary.c (split_binary_2), OTP-29.1.1.
pub(crate) extern "C" fn split_binary_2(c_p: *mut ProcessHeader, reg: *mut u64, i: u64) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let [bin, at] = crate::bif_table::bif_args::<2>(reg);
    let (Ok(view), Some(split_at)) = (
        BinRef::try_from(bin),
        at.as_small().and_then(|n| usize::try_from(n).ok()),
    ) else {
        return bif_badarg(c_p);
    };
    let size = view.bit_len();
    if split_at > size / 8 {
        return bif_badarg(c_p);
    }
    let split_bits = split_at * 8;
    let mut heap = ProcessHeapHandle(&mut process.heap);
    let mut builder = TermBuilder::new(&mut heap);
    // `erts_build_sub_bitstring`: a binary whose size is not a whole number of bytes keeps
    // its trailing bits in the right part.
    let aligned = size.is_multiple_of(8);
    let sub = |builder: &mut TermBuilder<'_, _>, start: usize, bits: usize| {
        if aligned {
            builder.sub_binary_bif(bin, start, bits)
        } else {
            builder.sub_binary(bin, start, bits)
        }
    };
    let built = sub(&mut builder, 0, split_bits)
        .and_then(|left| {
            sub(&mut builder, split_bits, size - split_bits).map(|right| (left, right))
        })
        .and_then(|(left, right)| builder.tuple(&[left, right]));
    match built {
        Ok(tuple) => crate::native_hooks::raw(tuple),
        Err(_) => bif_ret(c_p, i, Err(system_limit())),
    }
}

/// The tail shared by `binary_to_list_1` and `_3`: the one-chunk decision and the
/// `ERTS_BIF_YIELD1/3` of a call that gets too few reductions.
#[allow(clippy::too_many_arguments)]
fn binary_to_list_checked(
    c_p: *mut ProcessHeader,
    reg: *mut u64,
    i: u64,
    process: &mut crate::Process,
    bif: &'static str,
    arity: usize,
    (bin, source_start, bit_offset, count): (Term, usize, usize, usize),
    tail: Term,
    size: usize,
) -> u64 {
    // `size` is what the C code's decision below measures: the whole binary's byte size.
    let mut reds_left = process.heap.abi.fcalls.max(0) as usize;
    let mut one_chunk = size < reds_left.saturating_mul(B2L_BYTES_PER_REDUCTION);
    if !one_chunk && size < B2L_MIN_EXEC_REDS * B2L_BYTES_PER_REDUCTION {
        if reds_left <= B2L_RESCHED_REDS {
            // ERTS_BIF_YIELD1/3: ERTS_VBUMP_ALL_REDS, then BIF_TRAP to the BIF itself.
            crate::bif_traps::vbump_all_reds(process);
            let args = crate::bif_table::bif_arg_vec(reg, arity);
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
        B2lState::new(bin, source_start, bit_offset, count, tail),
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
    mut walk: B2lState,
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
    reg: *mut u64,
    i: u64,
) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let [mref] = crate::bif_table::bif_args::<1>(reg);
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
        .with_magic_payload_mut::<B2lHolder, _>(|holder| {
            let walk = &mut holder.0;
            chunk_locked(process, walk, size)
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
            if gc_disabled && process.erts_set_gc_state_enable() {
                // ERTS_BIF_PREP_YIELD_RETURN: ERTS_VBUMP_ALL_REDS, then bif_return_trap.
                crate::bif_traps::vbump_all_reds(process);
                let undefined = Term::atom(arinsal_term::atoms::UNDEFINED);
                let trap = bif_trap(process, "erlang:bif_return_trap/2", vec![value, undefined]);
                return bif_ret(c_p, i, Err(trap));
            }
            crate::native_hooks::raw(value)
        }
        Err(error) => bif_ret(c_p, i, Err(error)),
    }
}

/// `BUMP_REDS` of the bytes in the chunk, then `erts_bin_bytes_to_list` from the end.
fn chunk_locked(
    process: &mut crate::Process,
    walk: &mut B2lState,
    size: usize,
) -> Result<Option<Term>, crate::VmError> {
    let mut heap = ProcessHeapHandle(&mut process.heap);
    let (value, used) = walk.step(&mut heap, size).map_err(|_| system_limit())?;
    // `(size - 1)/ERTS_B2L_BYTES_PER_REDUCTION + 1` in unsigned arithmetic, kept in an `int`: an
    // empty chunk (only the trailing bits of a bitstring) wraps to 0.
    let reds = ((used as u64).wrapping_sub(1) / B2L_BYTES_PER_REDUCTION as u64 + 1) as i32 as usize;
    let mut call = BifCall::default();
    let mut ctx = Ctx::with_fcalls(&mut heap, &mut call);
    ctx.charge_reductions(reds);
    Ok(value)
}

/// `erts_create_magic_binary(sizeof(ErtsB2LState))` + `erts_mk_magic_ref`.
fn create_state(process: &mut crate::Process, walk: B2lState) -> Option<Term> {
    let state: MagicBin = MagicBin::with_erts_payload_size_and_refn(
        B2lHolder::new(walk),
        ERTS_B2L_STATE_SIZE,
        arinsal_sched::unique::next_ref_words(),
    );
    let mut heap = ProcessHeapHandle(&mut process.heap);
    TermBuilder::new(&mut heap).magic_ref(state).ok()
}

fn system_limit() -> crate::VmError {
    crate::VmError::Trap(crate::exceptions::Trap::error(Term::atom(
        arinsal_term::atoms::SYSTEM_LIMIT,
    )))
}

arinsal_term::magic_payload!(
    B2lHolder => binary_to_list_destructor,
);
