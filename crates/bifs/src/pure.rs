//! Pure BIFs implemented against stable heap terms.

use std::sync::Arc;

use arinsal_term::{
    BinaryRef, ExternalBinary, HeapAlloc, MagicBin, Node, Term, TermBuilder, TermKind,
};

use crate::{BifError, Ctx};

const BADARG: BifError = BifError::BADARG;

pub(super) struct Heap<'a, H: HeapAlloc + ?Sized>(pub(super) &'a mut H);
impl<H: HeapAlloc + ?Sized> HeapAlloc for Heap<'_, H> {
    fn alloc(&mut self, words: usize) -> Option<*mut u64> {
        self.0.alloc(words)
    }
    fn alloc_with_extra(&mut self, words: usize, extra: usize) -> Option<*mut u64> {
        self.0.alloc_with_extra(words, extra)
    }
    fn alloc_fragment_only(&mut self, words: usize) -> Option<*mut u64> {
        self.0.alloc_fragment_only(words)
    }
    fn words_left(&self) -> Option<usize> {
        self.0.words_left()
    }
    fn release(&mut self, end: *mut u64, start: *mut u64) {
        self.0.release(end, start)
    }
    fn release_needs_filler(&self, end: *mut u64, start: *mut u64) -> bool {
        self.0.release_needs_filler(end, start)
    }
    fn retain_binary(&mut self, value: Arc<arinsal_term::RefcBinary>) {
        self.0.retain_binary(value)
    }
    fn link_bin_ref(
        &mut self,
        bin_ref: *mut u64,
        writable: bool,
        overhead_words: u64,
        owner: Option<arinsal_term::OwnedBinaryRef>,
    ) {
        HeapAlloc::link_bin_ref(self.0, bin_ref, writable, overhead_words, owner)
    }
    fn add_bin_vheap(&mut self, words: u64) {
        HeapAlloc::add_bin_vheap(self.0, words)
    }
    fn retain_writable_binary(&mut self, value: Arc<arinsal_term::WritableBinary>) {
        self.0.retain_writable_binary(value)
    }
    fn retain_writable_binary_with_apparent_size(
        &mut self,
        value: Arc<arinsal_term::WritableBinary>,
        apparent_size_bits: usize,
    ) {
        self.0
            .retain_writable_binary_with_apparent_size(value, apparent_size_bits)
    }
    fn update_writable_binary_overhead(
        &mut self,
        source: Term,
        old_size_bits: usize,
        new_size_bits: usize,
    ) {
        self.0
            .update_writable_binary_overhead(source, old_size_bits, new_size_bits)
    }
    fn supports_writable_binary(&self) -> bool {
        self.0.supports_writable_binary()
    }
    fn link_node(&mut self, thing: *mut u64, value: Node) {
        self.0.link_node(thing, value)
    }
    fn link_external_binary(&mut self, bin_ref: *mut u64, value: Arc<ExternalBinary>) {
        self.0.link_external_binary(bin_ref, value)
    }
    fn supports_external_binary(&self) -> bool {
        self.0.supports_external_binary()
    }
    fn link_magic_ref(&mut self, thing: *mut u64, owner: MagicBin) {
        self.0.link_magic_ref(thing, owner)
    }
    fn supports_magic(&self) -> bool {
        self.0.supports_magic()
    }
}

pub(super) fn integer(ctx: &mut Ctx<'_>, value: usize) -> Result<Term, BifError> {
    if let Some(small) = i64::try_from(value).ok().and_then(Term::small) {
        return Ok(small);
    }
    TermBuilder::new(&mut Heap(&mut ctx.heap))
        .int_from_i128(value as i128)
        .map_err(|_| BifError::SystemLimit)
}

fn tuple_view(term: &Term) -> Result<arinsal_term::TupleRef<'_>, BifError> {
    // SAFETY: BIF arguments remain rooted in the live process heap for this call.
    unsafe { term.tuple_ref() }.ok_or(BADARG)
}

/// Return the arity of a tuple without copying its elements.
pub fn tuple_arity(term: Term) -> Result<usize, BifError> {
    Ok(tuple_view(&term)?.len())
}

/// Read one tuple element without copying the tuple's element array.
pub fn tuple_element(term: Term, index: usize) -> Result<Term, BifError> {
    tuple_view(&term)?.element(index).ok_or(BADARG)
}

/// The elements of a proper list, `None` for any other term.
pub fn proper_list_terms(term: Term) -> Option<Vec<Term>> {
    list(term).ok()
}

/// Visit the elements of a proper list in order without collecting them. A non-list or an
/// improper list is `badarg`, after the elements before the bad tail were visited.
pub fn for_each_list_term(
    term: Term,
    visit: impl FnMut(Term) -> Result<(), BifError>,
) -> Result<(), BifError> {
    for_each_cons(term, visit)
}

/// The two elements of a 2-tuple, `None` for any other term.
pub fn tuple_pair(term: Term) -> Option<(Term, Term)> {
    let view = tuple_view(&term).ok()?;
    if view.len() != 2 {
        return None;
    }
    Some((view.element(0)?, view.element(1)?))
}

/// The elements of a tuple, `None` for any other term.
pub fn tuple_terms(term: Term) -> Option<Vec<Term>> {
    let view = tuple_view(&term).ok()?;
    Some(view.iter().collect())
}

pub(super) fn list(term: Term) -> Result<Vec<Term>, BifError> {
    list_with_limit(term, usize::MAX)
}

fn list_with_limit(term: Term, limit: usize) -> Result<Vec<Term>, BifError> {
    let mut out = Vec::new();
    for_each_cons(term, |head| {
        if out.len() == limit {
            return Err(BADARG);
        }
        out.push(head);
        Ok(())
    })?;
    Ok(out)
}

/// The head and tail of a cons cell, `None` for any other term.
#[inline(always)]
fn next_cons(list: Term) -> Option<(Term, Term)> {
    // SAFETY: The source heap remains live and stable for the call.
    unsafe { list.cons_ref() }
}

/// Walk a proper list without allocating, as `unique_integer_1` walks `modlist`.
fn for_each_cons(
    mut tail: Term,
    mut visit: impl FnMut(Term) -> Result<(), BifError>,
) -> Result<(), BifError> {
    while let Some((head, next)) = next_cons(tail) {
        visit(head)?;
        tail = next;
    }
    if tail != Term::NIL {
        Err(BADARG)
    } else {
        Ok(())
    }
}

/// Resume state of `erlang:phash2/1,2`.
///
/// Port of the trap state `trapping_make_hash2` hands back in
/// erts/emulator/beam/erl_term_hashing.c, OTP-29.1.1.
pub struct Phash2Cont {
    run: arinsal_term::Hash2Run,
    range: Option<u64>,
}

/// Run `run` for the reductions left, then charge them.
// Port of erts/emulator/beam/bif.c (phash2_1, phash2_2), OTP-29.1.1, over `trapping_make_hash2`.
pub fn phash2_slice(ctx: &mut Ctx<'_>, cont: &mut Phash2Cont) -> Result<Option<Term>, BifError> {
    let budget = ctx.reduction_budget();
    let iterations = (budget != usize::MAX).then(|| {
        i64::try_from(budget)
            .unwrap_or(i64::MAX / arinsal_term::HASH2_ITERATIONS_PER_RED)
            .saturating_mul(arinsal_term::HASH2_ITERATIONS_PER_RED)
    });
    match cont.run.run(iterations) {
        arinsal_term::Hash2Progress::Yield => {
            ctx.bump_all_reds();
            Ok(None)
        }
        arinsal_term::Hash2Progress::Done { hash, used } => {
            if iterations.is_some() {
                ctx.charge_reductions(
                    (used / arinsal_term::HASH2_ITERATIONS_PER_RED).max(0) as usize
                );
            }
            let value = match cont.range {
                None => u64::from(hash & ((1 << 27) - 1)),
                Some(range) if range == 1_u64 << 32 => u64::from(hash),
                Some(range) => u64::from(hash % range as u32),
            };
            Ok(Some(integer(ctx, value as usize)?))
        }
    }
}

/// Outcome of [`phash2_run_2`] and [`phash2_run_1_after_immediate_check`].
pub enum Phash2Run {
    /// The hash, and the reductions the walk used.
    Done {
        /// The `phash2` value (always a small on a 64-bit build).
        value: Term,
        /// `(max_iterations - iterations_until_trap) / ITERATIONS_PER_RED`.
        reductions: u32,
    },
    /// The walk used up the process's reductions; the saved state to trap with.
    More(Box<Phash2Cont>),
}

/// Run the `phash2/1` BIF after its direct entry checked the immediate cases.
// Port of erts/emulator/beam/bif.c:5350-5360 (`phash2_1`), OTP-29.1.1.
#[inline(always)]
pub fn phash2_run_1_after_immediate_check(term: Term, fcalls: i32) -> Result<Phash2Run, BifError> {
    let run = arinsal_term::Hash2Run::new_after_immediate_check(term);
    phash2_run_initialized(run, None, fcalls, true)
}

/// Run the `phash2/2` BIF after validating its range argument.
// Port of erts/emulator/beam/bif.c:5362-5389 (`phash2_2`), OTP-29.1.1.
pub fn phash2_run_2(term: Term, range_term: Term, fcalls: i32) -> Result<Phash2Run, BifError> {
    let range = phash2_range_arg(range_term)?;
    phash2_run_initialized(
        arinsal_term::Hash2Run::new(term),
        Some(range),
        fcalls,
        false,
    )
}

#[inline(always)]
fn phash2_run_initialized(
    mut run: arinsal_term::Hash2Run,
    range: Option<u64>,
    fcalls: i32,
    immediate_checked: bool,
) -> Result<Phash2Run, BifError> {
    let iterations =
        i64::from(fcalls.max(0)).saturating_mul(arinsal_term::HASH2_ITERATIONS_PER_RED);
    let progress = if immediate_checked {
        run.run_after_immediate_check(Some(iterations))
    } else {
        run.run(Some(iterations))
    };
    Ok(match progress {
        arinsal_term::Hash2Progress::Done { hash, used } => {
            let value = match range {
                None => u64::from(hash & ((1 << 27) - 1)),
                Some(range) if range == 1_u64 << 32 => u64::from(hash),
                Some(range) => u64::from(hash % range as u32),
            };
            Phash2Run::Done {
                value: Term::small(value as i64).ok_or(BifError::SystemLimit)?,
                reductions: (used / arinsal_term::HASH2_ITERATIONS_PER_RED).max(0) as u32,
            }
        }
        arinsal_term::Hash2Progress::Yield => Phash2Run::More(Box::new(Phash2Cont { run, range })),
    })
}

/// The range argument of `phash2/2`.
pub fn phash2_range_arg(term: Term) -> Result<u64, BifError> {
    let range: u64 = term
        .as_small()
        .ok_or(BADARG)?
        .try_into()
        .map_err(|_| BADARG)?;
    if range == 0 || range > (1_u64 << 32) {
        return Err(BADARG);
    }
    Ok(range)
}

/// Return `phash2/1` immediately for the atom and small-integer cases.
// Port of erts/emulator/beam/erl_term_hashing.c:974-980 (`make_hash2_helper`) and
// erts/emulator/beam/bif.c:5350-5360 (`phash2_1`), OTP-29.1.1.
#[inline(always)]
pub fn phash2_immediate_1(term: Term) -> Option<Term> {
    let hash = arinsal_term::hash2_immediate(term)?;
    Some(Term::small(i64::from(hash & ((1 << 27) - 1))).expect("27-bit phash2 is a small"))
}

/// Copy a byte-aligned binary's significant bytes for a VM continuation.
pub fn binary_bytes(term: Term) -> Result<Vec<u8>, BifError> {
    let bits = bitstring_bit_len(term)?;
    if !bits.is_multiple_of(8) {
        return Err(BADARG);
    }
    let mut bytes = vec![0; bits / 8];
    copy_binary_range(term, 0, &mut bytes)?;
    Ok(bytes)
}

/// Copy a bounded byte range from a live, byte-aligned bitstring.
pub fn copy_binary_range(term: Term, start: usize, output: &mut [u8]) -> Result<(), BifError> {
    let bits = output.len().checked_mul(8).ok_or(BADARG)?;
    let start_bit = start.checked_mul(8).ok_or(BADARG)?;
    copy_bitstring_range(term, start_bit, output, bits)
}

/// Copy a bit range into a destination at an arbitrary bit offset.
// Port of erts/emulator/beam/erl_bits.c:2389-2505 (erts_copy_bits_fwd), OTP-29.1.1.
pub fn copy_bitstring_range_to(
    term: Term,
    source_start: usize,
    destination: &mut [u8],
    destination_start: usize,
    bit_count: usize,
) -> Result<(), BifError> {
    with_binary_bytes(term, |view| {
        copy_bitstring_view_range_to(
            &view,
            source_start,
            destination,
            destination_start,
            bit_count,
        )
    })?
}

fn copy_bitstring_view_range_to(
    view: &BinaryRef<'_>,
    source_start: usize,
    destination: &mut [u8],
    destination_start: usize,
    bit_count: usize,
) -> Result<(), BifError> {
    let destination_bits = destination.len().checked_mul(8).ok_or(BADARG)?;
    let destination_end = destination_start
        .checked_add(bit_count)
        .filter(|&end| end <= destination_bits)
        .ok_or(BADARG)?;

    let _source_end = source_start
        .checked_add(bit_count)
        .filter(|&end| end <= view.bit_len())
        .ok_or(BADARG)?;
    let source_start = view.start_bit().checked_add(source_start).ok_or(BADARG)?;
    if bit_count == 0 {
        return Ok(());
    }
    if source_start.is_multiple_of(8)
        && destination_start.is_multiple_of(8)
        && bit_count.is_multiple_of(8)
    {
        // Port of erts/emulator/beam/erl_bits.h:541-552 (copy_binary_to_buffer), OTP-29.1.1.
        let byte_count = bit_count / 8;
        let source_byte = source_start / 8;
        let destination_byte = destination_start / 8;
        let source_end = source_byte.checked_add(byte_count).ok_or(BADARG)?;
        let destination_end = destination_byte.checked_add(byte_count).ok_or(BADARG)?;
        destination[destination_byte..destination_end]
            .copy_from_slice(&view.bytes()[source_byte..source_end]);
        return Ok(());
    }
    let source = view.bytes().get(source_start / 8..).ok_or(BADARG)?;
    let destination = destination.get_mut(destination_start / 8..).ok_or(BADARG)?;
    let mut source_index = 0;
    let mut destination_index = 0;
    let source_offset = source_start % 8;
    let destination_offset = destination_start % 8;
    let destination_end_offset = destination_end % 8;
    let left_mask = if destination_offset == 0 {
        0
    } else {
        0xff >> destination_offset
    };
    let right_mask = if destination_end_offset == 0 {
        0
    } else {
        (((1_u16 << destination_end_offset) - 1) << (8 - destination_end_offset)) as u8
    };

    if destination_offset + bit_count < 8 {
        let mask = if left_mask & right_mask != 0 {
            left_mask & right_mask
        } else {
            left_mask | right_mask
        };
        let mut bits = if source_offset == destination_offset {
            u16::from(source[source_index])
        } else if source_offset > destination_offset {
            let shift = source_offset - destination_offset;
            let mut bits = u16::from(source[source_index]) << shift;
            if source_offset + bit_count > 8 {
                let next = source.get(source_index + 1).ok_or(BADARG)?;
                bits |= u16::from(*next) >> (8 - shift);
            }
            bits
        } else {
            u16::from(source[source_index]) >> (destination_offset - source_offset)
        };
        bits &= 0xff;
        destination[destination_index] =
            (bits as u8 & mask) | (destination[destination_index] & !mask);
        return Ok(());
    }

    let mut count = if left_mask == 0 {
        bit_count >> 3
    } else {
        (bit_count - (8 - destination_offset)) >> 3
    };

    if source_offset == destination_offset {
        if left_mask != 0 {
            destination[destination_index] =
                (source[source_index] & left_mask) | (destination[destination_index] & !left_mask);
            destination_index += 1;
            source_index += 1;
        }
        if count != 0 {
            let source_end = source_index + count;
            let destination_end = destination_index + count;
            destination[destination_index..destination_end]
                .copy_from_slice(&source[source_index..source_end]);
            destination_index = destination_end;
            source_index = source_end;
        }
        if right_mask != 0 {
            destination[destination_index] = (source[source_index] & right_mask)
                | (destination[destination_index] & !right_mask);
        }
        return Ok(());
    }

    let (mut bits, left_shift, right_shift) = if source_offset > destination_offset {
        let left_shift = source_offset - destination_offset;
        let right_shift = 8 - left_shift;
        let bits = u16::from(source[source_index]);
        if source_offset + bit_count > 8 {
            source_index += 1;
        }
        (bits, left_shift, right_shift)
    } else {
        let right_shift = destination_offset - source_offset;
        (0, 8 - right_shift, right_shift)
    };

    if left_mask != 0 {
        let first = bits << left_shift;
        bits = u16::from(source[source_index]);
        source_index += 1;
        let first = (first | (bits >> right_shift)) as u8;
        destination[destination_index] =
            (first & left_mask) | (destination[destination_index] & !left_mask);
        destination_index += 1;
    }

    while count != 0 {
        let high = bits << left_shift;
        bits = u16::from(source[source_index]);
        source_index += 1;
        destination[destination_index] = (high | (bits >> right_shift)) as u8;
        destination_index += 1;
        count -= 1;
    }

    if right_mask != 0 {
        let mut last = bits << left_shift;
        if (u16::from(right_mask) << right_shift) & 0xff != 0 {
            bits = u16::from(*source.get(source_index).ok_or(BADARG)?);
            last |= bits >> right_shift;
        }
        let last = last as u8;
        destination[destination_index] =
            (last & right_mask) | (destination[destination_index] & !right_mask);
    }
    Ok(())
}

/// Copy significant bits into a most-significant-bit-first packed byte slice.
// Port of erts/emulator/beam/erl_bits.c:2389-2515 (erts_copy_bits_fwd), OTP-29.1.1.
pub fn copy_bitstring_range(
    term: Term,
    start: usize,
    output: &mut [u8],
    bit_count: usize,
) -> Result<(), BifError> {
    arinsal_term::erl_bits::copy_bitstring_range(term, start, output, bit_count).map_err(|_| BADARG)
}

/// Run a read-only operation while the term's backing bytes remain borrowed.
///
/// The callback cannot retain the view beyond the term's live interval.
pub fn with_binary_bytes<R>(term: Term, f: impl FnOnce(BinaryRef<'_>) -> R) -> Result<R, BifError> {
    // SAFETY: The view cannot escape `f`, and the caller keeps the term and its owner live.
    let view = unsafe { term.binary_ref() }.ok_or(BADARG)?;
    Ok(f(view))
}
/// Return the sole bitstring in a singleton list when its length satisfies `unit`.
// Port of erts/emulator/beam/erl_iolist.c:865-879, OTP-29.1.1.
pub fn singleton_bitstring(root: Term, unit: usize) -> Result<Option<Term>, BifError> {
    if root.classify() != TermKind::List {
        return Ok(None);
    }
    let (head, tail) = iolist_cons(root)?;
    if tail != Term::NIL || head.classify() != TermKind::Bitstring {
        return Ok(None);
    }
    let bits = bitstring_bit_len(head)?;
    Ok(bits.is_multiple_of(unit).then_some(head))
}

/// Return the significant bit count for a live bitstring term.
pub fn bitstring_bit_len(term: Term) -> Result<usize, BifError> {
    arinsal_term::erl_bits::bitstring_bit_len(term).ok_or(BADARG)
}

pub(crate) fn iolist_cons(term: Term) -> Result<(Term, Term), BifError> {
    // SAFETY: The source heap remains live throughout the BIF call.
    unsafe { term.cons_ref() }.ok_or(BADARG)
}
