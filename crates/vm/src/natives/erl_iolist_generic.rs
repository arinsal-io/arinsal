//! `generic_iolist_size` and `generic_iolist_copy` of erl_iolist.c.
//!
//! Port of erts/emulator/beam/erl_iolist.c (ErtsIOListState, ErtsIOListCopyState,
//! generic_iolist_size, generic_iolist_copy, generic_iolist_copy_bitstring,
//! generic_iolist_copy_vec_enqueue), OTP-29.1.1. erts instantiates both functions through
//! `ERTS_FORCE_INLINE` with constant `VecThreshold`, `Unit`, `ErrorSupport` and `YieldSupport`;
//! the yielding callers of this port (`iolist_size/1`, `list_to_binary/1` and friends,
//! `iolist_to_iovec/1`) use `YieldSupport = 1`, `ErrorSupport = 0`, so `UNIT` is a const parameter
//! and `VecThreshold == ERTS_UINT_MAX` (usize::MAX) switches the iovec logic off.

use crate::natives::erl_iolist::charge;
use arinsal_bifs::ProcessHeapHandle;
use arinsal_term::raw::{BinRef, Cons, UninitBitstring};
use arinsal_term::{ConsHeapChain, EStack, Term, TermBuilder};

/// `ERTS_IOLIST_SIZE_YIELDS_COUNT_PER_RED`.
pub(crate) const YIELDS_PER_RED: i64 = 8;
/// `ERTS_IOLIST_COPY_BITS_PER_YIELD_COUNT`.
const COPY_BITS_PER_YIELD: usize = 32 * 8;
/// `ERTS_UINT_MAX` as the `VecThreshold` that suppresses the iovec logic.
pub(crate) const NO_VEC: usize = usize::MAX;

/// `enum iolist_action`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum IolistAction {
    Ok,
    Overflow,
    Type,
    Yield,
}

/// Why a pass left its loop early.
enum Stop {
    Overflow,
    Type,
    Yield,
}

/// `ErtsIOListState`.
pub(crate) struct IolistState {
    pub(crate) estack: EStack<8>,
    pub(crate) obj: Term,
    /// In bits.
    pub(crate) size: usize,
    pub(crate) have_size: bool,
    pub(crate) reds_left: i64,
}

impl IolistState {
    /// `ERTS_IOLIST_STATE_INITER`.
    pub(crate) fn new(obj: Term) -> Self {
        Self {
            estack: EStack::new(),
            obj,
            size: 0,
            have_size: false,
            reds_left: 0,
        }
    }

    /// `state.reds_left = ERTS_BIF_REDS_LEFT(c_p)`.
    pub(crate) fn set_reds_left(&mut self, process: &crate::Process) {
        self.reds_left = i64::from(process.heap.abi.fcalls);
    }

    /// `BUMP_REDS` for `used` yield counts and the reductions left.
    fn finish_reds(&mut self, process: &mut crate::Process, init: i64, yield_count: i64) {
        let reds = (init - yield_count - 1) / YIELDS_PER_RED + 1;
        charge(process, reds as usize);
        self.reds_left -= reds;
    }

    /// `L_yield`: `BUMP_ALL_REDS`, `reds_left = 0`, keep the cursor.
    fn yield_pass(&mut self, process: &mut crate::Process, obj: Term) -> IolistAction {
        process.heap.abi.fcalls = 0;
        self.reds_left = 0;
        self.obj = obj;
        IolistAction::Yield
    }
}

/// A binary leaf copied in several yields: `from_base`, `from_offset` and `from_size`.
struct PartialLeaf {
    leaf: Term,
    offset: usize,
    size: usize,
}

/// The iovec part of `ErtsIOListCopyState`: `bin_ref`, `vec_start` and `vec_tail`.
struct Vec2 {
    bin_ref: Term,
    vec_start: usize,
    vec_tail: ConsHeapChain,
}

/// `ErtsIOListCopyState`.
pub(crate) struct CopyState {
    pub(crate) iolist: IolistState,
    vec: Vec2,
    from: Option<PartialLeaf>,
    pub(crate) to_base: Option<UninitBitstring>,
    to_offset: usize,
}

impl CopyState {
    /// `ERTS_IOLIST_COPY_STATE_INITER`.
    pub(crate) fn new(obj: Term) -> Self {
        Self {
            iolist: IolistState::new(obj),
            vec: Vec2 {
                bin_ref: Term::NIL,
                vec_start: 0,
                vec_tail: ConsHeapChain::new(),
            },
            from: None,
            to_base: None,
            to_offset: 0,
        }
    }

    /// The common off-heap binary that `iolist_to_iovec` copies into: `state->copy.bin_ref` and
    /// `to_base`.
    pub(crate) fn set_vec_output(&mut self, output: UninitBitstring) {
        self.vec.bin_ref = output.term();
        self.to_base = Some(output);
    }

    /// `state->copy.vec_tail = &state->result`.
    pub(crate) fn start_vec_result(&mut self) {
        self.vec.vec_tail = ConsHeapChain::new();
    }

    /// The finished list of `iolist_to_iovec` (`state->result`).
    pub(crate) fn take_vec_result(&mut self) -> Term {
        std::mem::replace(&mut self.vec.vec_tail, ConsHeapChain::new()).finish(Term::NIL)
    }
}

/// `is_byte`.
#[inline(always)]
fn as_byte(term: Term) -> Option<u8> {
    term.as_small().and_then(|n| u8::try_from(n).ok())
}

/// `(offset, size)` of a bitstring term (`ERTS_GET_BITSTRING`).
#[inline(always)]
fn bitstring_geometry(term: Term) -> Option<(usize, usize)> {
    arinsal_term::raw::bitstring_extent(term)
}

/// `IOL_SHOULD_COPY(VecThreshold, Unit, offset, size)`.
#[inline(always)]
fn should_copy<const UNIT: usize>(threshold: usize, start_bit: usize, bit_len: usize) -> bool {
    bit_len <= threshold || !start_bit.is_multiple_of(UNIT)
}

/// `generic_iolist_size(state, VecThreshold, Unit, 1)`.
// Port of erts/emulator/beam/erl_iolist.c (generic_iolist_size), OTP-29.1.1.
pub(crate) fn generic_iolist_size<const UNIT: usize>(
    state: &mut IolistState,
    process: &mut crate::Process,
    threshold: usize,
) -> IolistAction {
    if state.reds_left <= 0 {
        return IolistAction::Yield;
    }
    let init = YIELDS_PER_RED * state.reds_left;
    let mut yield_count = init;
    let mut obj = state.obj;
    let mut size = state.size;
    let stack = &mut state.estack;
    let run: Result<(), Stop> = 'pass: {
        let mut resume = true;
        loop {
            if !resume {
                match stack.pop() {
                    Some(next) => obj = next,
                    None => break,
                }
            }
            resume = false;
            while let Ok(cons) = Cons::try_from(obj) {
                yield_count -= 1;
                if yield_count <= 0 {
                    break 'pass Err(Stop::Yield);
                }
                let (head, tail) = cons.pair();
                if as_byte(head).is_some() {
                    match size.checked_add(8) {
                        Some(sum) => size = sum,
                        None => break 'pass Err(Stop::Overflow),
                    }
                    // A run of bytes stays in this loop: the next cell is the tail.
                    obj = tail;
                    continue;
                } else if let Some((start, bits)) = bitstring_geometry(head) {
                    if bits % UNIT != 0 {
                        break 'pass Err(Stop::Type);
                    }
                    if should_copy::<UNIT>(threshold, start, bits) {
                        match size.checked_add(bits) {
                            Some(sum) => size = sum,
                            None => break 'pass Err(Stop::Overflow),
                        }
                    }
                } else if Cons::try_from(head).is_ok() {
                    stack.push(tail);
                    obj = head;
                    continue;
                } else if head != Term::NIL {
                    break 'pass Err(Stop::Type);
                }
                obj = tail;
            }
            yield_count -= 1;
            if yield_count <= 0 {
                break 'pass Err(Stop::Yield);
            } else if let Some((start, bits)) = bitstring_geometry(obj) {
                if bits % UNIT != 0 {
                    break 'pass Err(Stop::Type);
                }
                if should_copy::<UNIT>(threshold, start, bits) {
                    match size.checked_add(bits) {
                        Some(sum) => size = sum,
                        None => break 'pass Err(Stop::Overflow),
                    }
                }
            } else if obj != Term::NIL {
                break 'pass Err(Stop::Type);
            }
        }
        Ok(())
    };
    match run {
        Ok(()) => {
            state.have_size = true;
            state.size = size;
            state.estack = EStack::new();
            state.finish_reds(process, init, yield_count);
            IolistAction::Ok
        }
        Err(Stop::Type) => {
            state.estack = EStack::new();
            state.finish_reds(process, init, yield_count);
            IolistAction::Type
        }
        Err(Stop::Overflow) => {
            state.size = size;
            state.obj = obj;
            state.finish_reds(process, init, yield_count);
            IolistAction::Overflow
        }
        Err(Stop::Yield) => {
            state.size = size;
            state.yield_pass(process, obj)
        }
    }
}

/// `generic_iolist_copy_vec_enqueue`.
fn vec_enqueue(vec: &mut Vec2, to_offset: usize, process: &mut crate::Process, obj: Term) {
    if vec.vec_start < to_offset {
        let sub = TermBuilder::new(&mut ProcessHeapHandle(&mut process.heap))
            .sub_binary(vec.bin_ref, vec.vec_start, to_offset - vec.vec_start)
            .expect("HAlloc");
        vec.vec_start = to_offset;
        vec_enqueue(vec, to_offset, process, sub);
    }
    if obj != Term::NIL {
        vec.vec_tail
            .push(&mut ProcessHeapHandle(&mut process.heap), obj, 0)
            .expect("HAlloc");
    }
}

#[inline(always)]
/// `copy_binary_to_buffer`: `bits` bits of `window` from bit `source_bit` to bit `target_bit` of
/// `target`, leaving the other bits of the touched bytes.
// Port of erts/emulator/beam/erl_bits.h (copy_binary_to_buffer, erts_copy_bits), OTP-29.1.1.
pub(crate) fn copy_bits(
    target: &mut [u8],
    target_bit: usize,
    window: &[u8],
    source_bit: usize,
    bits: usize,
) {
    if bits == 0 {
        return;
    }
    if target_bit.is_multiple_of(8) && bits.is_multiple_of(8) {
        crate::natives::erl_bif_binary::copy_binary_to_buffer(
            &mut target[target_bit / 8..],
            window,
            source_bit,
            bits / 8,
        );
        return;
    }
    let mut done = 0;
    while done < bits {
        let at = target_bit + done;
        let from = source_bit + done;
        // Up to the end of the target byte, so one write touches a single byte.
        let count = (bits - done).min(8 - at % 8);
        let first = window[from / 8];
        let chunk = if from % 8 + count <= 8 {
            first << (from % 8)
        } else {
            (first << (from % 8)) | (window[from / 8 + 1] >> (8 - from % 8))
        };
        let mask = (0xff_u8 << (8 - count)) >> (at % 8);
        let value = (chunk >> (at % 8)) & mask;
        target[at / 8] = (target[at / 8] & !mask) | value;
        done += count;
    }
}

/// `generic_iolist_copy_bitstring`: whether the leaf was copied only in part.
#[inline(always)]
// Port of erts/emulator/beam/erl_iolist.c (generic_iolist_copy_bitstring), OTP-29.1.1.
fn copy_bitstring(
    from: &mut Option<PartialLeaf>,
    base: &mut [u8],
    to_offset: &mut usize,
    leaf: Term,
    yield_count: &mut i64,
) -> bool {
    let (leaf, offset, size) = match from.take() {
        Some(partial) => (partial.leaf, partial.offset, partial.size),
        None => {
            let bits = bitstring_geometry(leaf).map_or(0, |(_, bits)| bits);
            (leaf, 0, bits)
        }
    };
    let copy_limit = (*yield_count as usize + 1) * COPY_BITS_PER_YIELD;
    let copy_size = size.min(copy_limit);
    if copy_size > 0 {
        let view = BinRef::try_from(leaf).expect("a bitstring leaf");
        copy_bits(
            base,
            *to_offset,
            view.window(),
            view.start_bit() + offset,
            copy_size,
        );
    }
    *to_offset += copy_size;
    if copy_size < size {
        *from = Some(PartialLeaf {
            leaf,
            offset: offset + copy_size,
            size: size - copy_size,
        });
        *yield_count = 0;
        return true;
    }
    *yield_count -= (copy_size / COPY_BITS_PER_YIELD) as i64;
    false
}

/// `generic_iolist_copy(copy_state, VecThreshold, Unit, 0, 1)`.
// Port of erts/emulator/beam/erl_iolist.c (generic_iolist_copy), OTP-29.1.1.
pub(crate) fn generic_iolist_copy<const UNIT: usize>(
    copy: &mut CopyState,
    process: &mut crate::Process,
    threshold: usize,
) -> IolistAction {
    let CopyState {
        iolist,
        vec,
        from,
        to_base,
        to_offset,
    } = copy;
    if iolist.reds_left <= 0 {
        return IolistAction::Yield;
    }
    let init = YIELDS_PER_RED * iolist.reds_left;
    let start = iolist.obj;
    let mut pass = |base: &mut [u8]| -> (Option<Term>, i64) {
        // The cursor and the yield count are locals of the pass, not captured state.
        let mut yield_count = init;
        let mut obj = start;
        let mut resume = true;
        let mut offset = *to_offset;
        let stopped = 'pass: loop {
            if !resume {
                match iolist.estack.pop() {
                    Some(next) => obj = next,
                    None => break None,
                }
            }
            resume = false;
            while let Ok(cons) = Cons::try_from(obj) {
                yield_count -= 1;
                if yield_count <= 0 {
                    break 'pass Some(obj);
                }
                let (head, tail) = cons.pair();
                obj = head;
                if let Some(byte) = as_byte(obj) {
                    let byte_offset = offset / 8;
                    let shift = if UNIT == 8 { 0 } else { offset % 8 };
                    if shift == 0 {
                        base[byte_offset] = byte;
                    } else {
                        let leading_bits = base[byte_offset];
                        base[byte_offset] =
                            (byte >> shift) | ((leading_bits >> (8 - shift)) << (8 - shift));
                        base[byte_offset + 1] = byte << (8 - shift);
                    }
                    offset += 8;
                    // A run of bytes stays in this loop: the next cell is the tail.
                    obj = tail;
                    continue;
                } else if let Some((start, bits)) = bitstring_geometry(obj) {
                    if should_copy::<UNIT>(threshold, start, bits) {
                        if copy_bitstring(from, base, &mut offset, obj, &mut yield_count) {
                            iolist.estack.push(tail);
                            break 'pass Some(obj);
                        }
                    } else {
                        vec_enqueue(vec, offset, process, obj);
                    }
                } else if Cons::try_from(obj).is_ok() {
                    iolist.estack.push(tail);
                    continue;
                }
                obj = tail;
            }
            yield_count -= 1;
            if yield_count <= 0 {
                break 'pass Some(obj);
            } else if let Some((start, bits)) = bitstring_geometry(obj) {
                if should_copy::<UNIT>(threshold, start, bits) {
                    if copy_bitstring(from, base, &mut offset, obj, &mut yield_count) {
                        break 'pass Some(obj);
                    }
                } else {
                    vec_enqueue(vec, offset, process, obj);
                }
            }
        };
        *to_offset = offset;
        (stopped, yield_count)
    };
    // A copy pass over a list of only empty leaves has no target. For the off-heap kind the
    // payload does not move when the pass allocates (iovec); a heap bitstring is only used by the
    // list_to_bitstring family, whose pass allocates nothing.
    let (stopped, yield_count) = match to_base.as_mut() {
        Some(output) => output.with_bytes_mut(&mut pass).expect("a sized copy pass"),
        None => pass(&mut []),
    };
    match stopped {
        None => {
            if threshold < NO_VEC {
                vec_enqueue(vec, *to_offset, process, Term::NIL);
            }
            iolist.estack = EStack::new();
            iolist.finish_reds(process, init, yield_count);
            IolistAction::Ok
        }
        Some(obj) => iolist.yield_pass(process, obj),
    }
}
