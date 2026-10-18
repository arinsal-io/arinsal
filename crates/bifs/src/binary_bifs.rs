//! Binary and iolist BIFs ported from ERTS binary and iolist code.

use std::borrow::Cow;
use std::sync::Arc;

use arinsal_term::{
    ConsListBuilder, HeapAlloc, MagicRef, TermBuilder, writable_bytes_mut, writable_extend_private,
    writable_finalize,
};

use crate::binary_mod::{SearchPattern, SearchWalk};
use crate::lists::DeferredTrap;
use crate::{BifError, Ctx};

use super::*;

pub(super) fn lookup<V: crate::BifTableVisitor>(
    module: &str,
    name: &str,
    arity: u8,
    v: &mut V,
) -> Option<V::Output> {
    let bif = match (module, name, arity) {
        ("erlang", "byte_size", 1) => v.entry::<bodies::byte_size>(),
        ("erlang", "bit_size", 1) => v.entry::<bodies::bit_size>(),
        ("erlang", "binary_to_list", 1 | 3) => v.entry::<bodies::erlang_binary_to_list>(),
        ("erlang", "list_to_binary", 1) => v.entry::<bodies::list_to_binary>(),
        ("erlang", "iolist_to_binary", 1) => v.entry::<bodies::iolist_to_binary>(),
        ("erlang", "iolist_to_iovec", 1) => v.entry::<bodies::iolist_to_iovec>(),
        ("erlang", "iolist_size", 1) => v.entry::<bodies::iolist_size>(),
        ("erlang", "bitstring_to_list", 1) => v.entry::<bodies::bitstring_to_list>(),
        ("erlang", "list_to_bitstring", 1) => v.entry::<bodies::list_to_bitstring>(),
        ("erlang", "split_binary", 2) => v.entry::<bodies::split_binary>(),
        ("erlang", "binary_part", 2 | 3) | ("binary", "part", 2 | 3) => {
            v.entry::<bodies::binary_part>()
        }
        ("binary", "first", 1) => v.entry::<bodies::binary_first>(),
        ("binary", "last", 1) => v.entry::<bodies::binary_last>(),
        ("binary", "at", 2) => v.entry::<bodies::binary_at>(),
        ("binary", "copy", 1 | 2) => v.entry::<bodies::binary_copy>(),
        ("binary", "referenced_byte_size", 1) => v.entry::<bodies::referenced_byte_size>(),
        ("binary", "longest_common_prefix", 1) => v.entry::<bodies::longest_common_prefix>(),
        ("binary", "longest_common_suffix", 1) => v.entry::<bodies::longest_common_suffix>(),
        ("binary", "compile_pattern", 1) => v.entry::<bodies::compile_pattern>(),
        ("binary", "match", 2 | 3) => v.entry::<bodies::binary_match>(),
        ("binary", "matches", 2 | 3) => v.entry::<bodies::binary_matches>(),
        ("binary", "split", 2 | 3) => v.entry::<bodies::binary_split>(),
        ("binary", "encode_unsigned", 1 | 2) => v.entry::<bodies::encode_unsigned>(),
        ("binary", "decode_unsigned", 1 | 2) => v.entry::<bodies::decode_unsigned>(),
        ("binary", "list_to_bin", 1) => v.entry::<bodies::list_to_binary>(),
        _ => return None,
    };
    Some(bif)
}

// Port of erts/emulator/beam/erl_bif_guard.c:376 (byte_size_1), OTP-29.1.1.
fn byte_size(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    let bits = bitstring_bit_len(args[0])?;
    integer(ctx, bits.div_ceil(8))
}

// Port of erts/emulator/beam/erl_bif_guard.c:354 (bit_size_1), OTP-29.1.1.
fn bit_size(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    integer(ctx, bitstring_bit_len(args[0])?)
}

// Port of erts/emulator/beam/binary.c (binary_to_list_1/3), OTP-29.1.1.
fn erlang_binary_to_list(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    with_binary_bytes(args[0], |view| {
        if !view.bit_len().is_multiple_of(8) {
            return Err(BADARG);
        }
        let size = view.bit_len() / 8;
        let (start, len) = if args.len() == 3 {
            let start = args[1].as_small().ok_or(BADARG)?;
            let end = args[2].as_small().ok_or(BADARG)?;
            if start < 1 || end < start || end as usize > size {
                return Err(BADARG);
            }
            (start as usize - 1, (end - start + 1) as usize)
        } else {
            (0, size)
        };
        if len == 0 {
            return Ok(Term::NIL);
        }
        let bit_offset = view.start_bit() % 8;
        let source_start = (view.start_bit() / 8).checked_add(start).ok_or(BADARG)?;
        validate_binary_to_list_range(view.bytes(), source_start, len, bit_offset)?;

        let budget = ctx.reduction_budget();
        let min_reds = 1_000;
        let resched_reds = 100;
        if budget != usize::MAX
            && size >= budget.saturating_mul(B2L_BYTES_PER_REDUCTION)
            && size < min_reds * B2L_BYTES_PER_REDUCTION
            && budget <= resched_reds
        {
            ctx.defer_trap(DeferredTrap::BinaryToList(BinaryToListWalk {
                source: args[0],
                start,
                remaining: len,
                total: len,
                list: None,
            }));
            return Ok(Term::NIL);
        }
        let one_chunk = budget == usize::MAX
            || size < budget.saturating_mul(B2L_BYTES_PER_REDUCTION)
            || (size < min_reds * B2L_BYTES_PER_REDUCTION && budget > resched_reds);
        let reservation = {
            let mut builder = TermBuilder::new(&mut ctx.heap);
            builder
                .reserve_cons_list(len)
                .map_err(|_| BifError::SystemLimit)?
        };
        if one_chunk {
            // Port of erts/emulator/beam/binary.c (erts_bin_bytes_to_list), OTP-29.1.1.
            let value = reservation
                .prepend_exact_with_tail(
                    (source_start..source_start + len).rev().map(|index| {
                        Term::small(i64::from(binary_to_list_byte(
                            view.bytes(),
                            index,
                            bit_offset,
                        )))
                        .expect("byte fits small")
                    }),
                    Term::NIL,
                )
                .map_err(|_| BifError::SystemLimit)?;
            ctx.charge_reductions(len.div_ceil(B2L_BYTES_PER_REDUCTION));
            return Ok(value);
        }
        let mut walk = BinaryToListWalk {
            source: args[0],
            start,
            remaining: len,
            total: len,
            list: Some(reservation),
        };
        let chunk = len.min(
            budget
                .saturating_add(1)
                .saturating_mul(B2L_BYTES_PER_REDUCTION),
        );
        let (result, used) = walk.step_bytes(view.bytes(), source_start, bit_offset, chunk)?;
        if let Some(result) = result {
            ctx.charge_reductions(used.div_ceil(B2L_BYTES_PER_REDUCTION));
            Ok(result)
        } else {
            ctx.charge_reductions(used.div_ceil(B2L_BYTES_PER_REDUCTION));
            ctx.defer_trap(DeferredTrap::BinaryToList(walk));
            Ok(Term::NIL)
        }
    })?
}

fn validate_binary_to_list_range(
    bytes: &[u8],
    source_start: usize,
    len: usize,
    bit_offset: usize,
) -> Result<(), BifError> {
    let end = source_start
        .checked_add(len)
        .and_then(|end| end.checked_add(usize::from(bit_offset != 0)))
        .ok_or(BADARG)?;
    if end > bytes.len() {
        return Err(BADARG);
    }
    Ok(())
}

// Port of erts/emulator/beam/binary.c (erts_bin_bytes_to_list), OTP-29.1.1.
fn binary_to_list_byte(bytes: &[u8], index: usize, bit_offset: usize) -> u8 {
    if bit_offset == 0 {
        bytes[index]
    } else {
        (bytes[index] << bit_offset) | (bytes[index + 1] >> (8 - bit_offset))
    }
}

const B2L_BYTES_PER_REDUCTION: usize = 256;

/// Resumable fill of one HAlloc reservation, as in `ErtsB2LState`.
// Port of erts/emulator/beam/binary.c (binary_to_list_chunk), OTP-29.1.1.
pub struct BinaryToListWalk {
    source: Term,
    start: usize,
    remaining: usize,
    total: usize,
    list: Option<ConsListBuilder>,
}

impl BinaryToListWalk {
    /// Whether OTP would first reschedule before creating the list reservation.
    pub fn needs_initial_allocation(&self) -> bool {
        self.list.is_none()
    }

    /// Fill at most one scheduler chunk, visiting the source from its end.
    pub fn step<H: HeapAlloc + ?Sized>(
        &mut self,
        heap: &mut H,
        max_bytes: usize,
    ) -> Result<(Option<Term>, usize), BifError> {
        if self.list.is_none() {
            let mut builder = TermBuilder::new(heap);
            self.list = Some(
                builder
                    .reserve_cons_list(self.total)
                    .map_err(|_| BifError::SystemLimit)?,
            );
        }
        with_binary_bytes(self.source, |view| {
            if !view.bit_len().is_multiple_of(8) {
                return Err(BADARG);
            }
            let bit_offset = view.start_bit() % 8;
            let source_start = (view.start_bit() / 8)
                .checked_add(self.start)
                .ok_or(BADARG)?;
            validate_binary_to_list_range(view.bytes(), source_start, self.remaining, bit_offset)?;
            self.step_bytes(view.bytes(), source_start, bit_offset, max_bytes)
        })?
    }

    fn step_bytes(
        &mut self,
        bytes: &[u8],
        source_start: usize,
        bit_offset: usize,
        max_bytes: usize,
    ) -> Result<(Option<Term>, usize), BifError> {
        let count = self.remaining.min(max_bytes);
        let from = source_start + self.remaining - count;
        let list = self.list.as_mut().ok_or(BifError::SystemLimit)?;
        for index in (from..from + count).rev() {
            let byte = binary_to_list_byte(bytes, index, bit_offset);
            list.prepend(Term::small(i64::from(byte)).expect("byte fits small integer"))
                .map_err(|_| BifError::SystemLimit)?;
        }
        self.remaining -= count;
        if self.remaining == 0 {
            let value = self
                .list
                .take()
                .ok_or(BifError::SystemLimit)?
                .finish(Term::NIL)
                .map_err(|_| BifError::SystemLimit)?;
            Ok((Some(value), count))
        } else {
            Ok((None, count))
        }
    }
}

/// Use the original byte slice when aligned; OTP likewise allocates a
/// temporary byte-aligned copy only for a bit-offset binary.
// Port of erts/emulator/beam/erl_bits.h:606-630
// (erts_get_aligned_binary_bytes_extra), OTP-29.1.1.
fn binary_input<'a>(view: &'a BinaryRef<'_>) -> Result<Cow<'a, [u8]>, BifError> {
    if !view.bit_len().is_multiple_of(8) {
        return Err(BADARG);
    }
    let byte_count = view.bit_len() / 8;
    if view.start_bit().is_multiple_of(8) {
        let start = view.start_bit() / 8;
        let end = start.checked_add(byte_count).ok_or(BADARG)?;
        return view
            .bytes()
            .get(start..end)
            .map(Cow::Borrowed)
            .ok_or(BADARG);
    }

    let mut aligned = vec![0; byte_count];
    let byte_offset = view.start_bit() / 8;
    let bit_offset = view.start_bit() % 8;
    for (index, byte) in aligned.iter_mut().enumerate() {
        let source = byte_offset + index;
        *byte = view.bytes()[source] << bit_offset;
        if bit_offset != 0 {
            *byte |= view.bytes()[source + 1] >> (8 - bit_offset);
        }
    }
    Ok(Cow::Owned(aligned))
}

pub(super) fn with_binary_input<R>(
    term: Term,
    f: impl FnOnce(&[u8]) -> Result<R, BifError>,
) -> Result<R, BifError> {
    with_binary_bytes(term, |view| {
        let bytes = binary_input(&view)?;
        f(&bytes)
    })?
}

// Port of erts/emulator/beam/erl_iolist.c:857-935 (list_to_bitstring_bif), OTP-29.1.1.
fn list_to_binary(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    if !matches!(args[0].classify(), TermKind::List | TermKind::Nil) {
        return Err(BADARG);
    }
    if let Some(binary) = singleton_bitstring(args[0], 8)? {
        return Ok(binary);
    }
    iolist_to_binary_result(ctx, args[0])
}

// Port of erts/emulator/beam/erl_iolist.c:916-927 (iolist_to_binary_1), OTP-29.1.1.
fn iolist_to_binary(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    if args[0].classify() == TermKind::Bitstring {
        if !bitstring_bit_len(args[0])?.is_multiple_of(8) {
            return Err(BADARG);
        }
        return Ok(args[0]);
    }
    if let Some(binary) = singleton_bitstring(args[0], 8)? {
        return Ok(binary);
    }
    iolist_to_binary_result(ctx, args[0])
}

fn iolist_to_binary_result(ctx: &mut Ctx<'_>, root: Term) -> Result<Term, BifError> {
    // ERTS sizes once, allocates the result binary, then copies directly into it.
    let size = iolist_size_value(root)?;
    let result = write_binary(ctx, size, |output| copy_iolist(root, output))?;
    ctx.charge_reductions(size);
    Ok(result)
}

/// Bits at or below which `iolist_to_iovec/1` copies a binary into the shared run (OTP-29.1.1).
const IOL2V_COPY_THRESHOLD_BITS: usize = 64 * 8 * 8;

/// Whether `iolist_to_iovec/1` copies a bitstring instead of keeping it as a segment.
fn iol2v_should_copy(start_bit: usize, bit_len: usize) -> bool {
    bit_len <= IOL2V_COPY_THRESHOLD_BITS || !start_bit.is_multiple_of(8)
}

fn bitstring_geometry(term: Term) -> Result<(usize, usize), BifError> {
    with_binary_bytes(term, |view| (view.start_bit(), view.bit_len()))
}

/// Yield counts one reduction buys in the iolist size and copy passes.
const IOL2V_YIELDS_PER_RED: usize = 8;
/// Bits copied per yield count.
const IOL2V_COPY_BITS_PER_YIELD: usize = 32 * 8;

/// Reductions charged for `used` yield counts.
pub fn iolist_yield_reductions(used: usize) -> usize {
    used.saturating_sub(1) / IOL2V_YIELDS_PER_RED + 1
}

/// The `[]`, `Bin` and `[Bin]` cases of `iolist_to_iovec/1` that need no traversal.
pub fn iolist_to_iovec_shortcut<H: HeapAlloc + ?Sized>(
    heap: &mut H,
    root: Term,
) -> Result<Option<Term>, BifError> {
    let single = match root.classify() {
        TermKind::Nil => return Ok(Some(Term::NIL)),
        TermKind::Bitstring => root,
        TermKind::List => {
            let (head, tail) = iolist_cons(root)?;
            if head.classify() == TermKind::Bitstring && tail.classify() == TermKind::Nil {
                head
            } else {
                return Ok(None);
            }
        }
        _ => return Err(BADARG),
    };
    let (_, bit_len) = bitstring_geometry(single)?;
    if !bit_len.is_multiple_of(8) {
        return Err(BADARG);
    }
    if bit_len == 0 {
        return Ok(Some(Term::NIL));
    }
    if root.classify() == TermKind::List {
        return Ok(Some(root));
    }
    TermBuilder::new(&mut Heap(heap))
        .list_from_iter([single])
        .map(Some)
        .map_err(|_| BifError::SystemLimit)
}

enum VecSegment {
    Run(usize, usize),
    Large(Term),
}

/// Resumable size and copy passes of `iolist_to_iovec/1`.
pub struct IolistVecWalk {
    root: Term,
    obj: Term,
    stack: SmallVec<[Term; 8]>,
    size: usize,
    sized: bool,
    copied: Vec<u8>,
    run_start: usize,
    segments: Vec<VecSegment>,
    from: Option<(usize, usize)>,
}

impl IolistVecWalk {
    /// Start traversing an iolist rooted in a stable process heap.
    pub fn new(root: Term) -> Self {
        Self {
            root,
            obj: root,
            stack: SmallVec::new(),
            size: 0,
            sized: false,
            copied: Vec::new(),
            run_start: 0,
            segments: Vec::new(),
            from: None,
        }
    }

    /// Whether the sizing pass has finished.
    pub fn sized(&self) -> bool {
        self.sized
    }

    /// Run the sizing pass for at most `budget` yield counts.
    ///
    /// Returns whether the pass finished and the yield counts used.
    pub fn size_step(&mut self, budget: usize) -> Result<(bool, usize), (BifError, usize)> {
        let init = isize::try_from(budget).unwrap_or(isize::MAX);
        let mut yield_count = init;
        let used = |yield_count: isize| (init - yield_count) as usize;
        let mut obj = self.obj;
        let mut resume = true;
        loop {
            if !resume {
                match self.stack.pop() {
                    Some(next) => obj = next,
                    None => break,
                }
            }
            resume = false;
            while obj.classify() == TermKind::List {
                yield_count -= 1;
                if yield_count <= 0 {
                    self.obj = obj;
                    return Ok((false, used(yield_count)));
                }
                let (head, tail) = iolist_cons(obj).map_err(|error| (error, used(yield_count)))?;
                match head.classify() {
                    TermKind::Nil => {}
                    TermKind::List => {
                        self.stack.push(tail);
                        obj = head;
                        continue;
                    }
                    _ => self
                        .size_leaf(head, true)
                        .map_err(|error| (error, used(yield_count)))?,
                }
                obj = tail;
            }
            yield_count -= 1;
            if yield_count <= 0 {
                self.obj = obj;
                return Ok((false, used(yield_count)));
            }
            self.size_leaf(obj, false)
                .map_err(|error| (error, used(yield_count)))?;
        }
        self.sized = true;
        self.obj = self.root;
        Ok((true, used(yield_count)))
    }

    fn size_leaf(&mut self, term: Term, byte_allowed: bool) -> Result<(), BifError> {
        let bytes = match term.classify() {
            TermKind::Nil => 0,
            TermKind::Bitstring => {
                let (start_bit, bit_len) = bitstring_geometry(term)?;
                if !bit_len.is_multiple_of(8) {
                    return Err(BADARG);
                }
                if iol2v_should_copy(start_bit, bit_len) {
                    bit_len / 8
                } else {
                    0
                }
            }
            TermKind::Number if byte_allowed => {
                term.as_small()
                    .and_then(|n| u8::try_from(n).ok())
                    .ok_or(BADARG)?;
                1
            }
            _ => return Err(BADARG),
        };
        self.size = self.size.checked_add(bytes).ok_or(BifError::SystemLimit)?;
        Ok(())
    }

    fn flush_run(&mut self) {
        if self.run_start < self.copied.len() {
            self.segments.push(VecSegment::Run(
                self.run_start,
                self.copied.len() - self.run_start,
            ));
            self.run_start = self.copied.len();
        }
    }

    fn enqueue(&mut self, term: Term) {
        self.flush_run();
        self.segments.push(VecSegment::Large(term));
    }

    fn copy_bitstring(
        &mut self,
        term: Term,
        bit_len: usize,
        yield_count: &mut isize,
    ) -> Result<bool, BifError> {
        let (offset, size) = self.from.take().unwrap_or((0, bit_len));
        let copy_limit = usize::try_from(*yield_count)
            .unwrap_or(0)
            .saturating_add(1)
            .saturating_mul(IOL2V_COPY_BITS_PER_YIELD);
        let copy_size = size.min(copy_limit);
        let previous = self.copied.len();
        self.copied.resize(previous + copy_size / 8, 0);
        copy_bitstring_range(term, offset, &mut self.copied[previous..], copy_size)?;
        if copy_size < size {
            self.from = Some((offset + copy_size, size - copy_size));
            *yield_count = 0;
            return Ok(true);
        }
        *yield_count -= (copy_size / IOL2V_COPY_BITS_PER_YIELD) as isize;
        Ok(false)
    }

    fn copy_leaf(&mut self, term: Term, yield_count: &mut isize) -> Result<bool, BifError> {
        match term.classify() {
            TermKind::Nil => {}
            TermKind::Bitstring => {
                let (start_bit, bit_len) = bitstring_geometry(term)?;
                if iol2v_should_copy(start_bit, bit_len) {
                    return self.copy_bitstring(term, bit_len, yield_count);
                }
                self.enqueue(term);
            }
            TermKind::Number => {
                let byte = term
                    .as_small()
                    .and_then(|n| u8::try_from(n).ok())
                    .ok_or(BADARG)?;
                self.copied.push(byte);
            }
            _ => return Err(BADARG),
        }
        Ok(false)
    }

    /// Run the copy pass for at most `budget` yield counts.
    ///
    /// Returns whether the pass finished and the yield counts used.
    pub fn copy_step(&mut self, budget: usize) -> Result<(bool, usize), (BifError, usize)> {
        let init = isize::try_from(budget).unwrap_or(isize::MAX);
        let mut yield_count = init;
        let mut obj = self.obj;
        let mut resume = true;
        loop {
            if !resume {
                match self.stack.pop() {
                    Some(next) => obj = next,
                    None => break,
                }
            }
            resume = false;
            while obj.classify() == TermKind::List {
                yield_count -= 1;
                if yield_count <= 0 {
                    self.obj = obj;
                    return Ok((false, init as usize));
                }
                let (head, tail) =
                    iolist_cons(obj).map_err(|error| (error, (init - yield_count) as usize))?;
                if head.classify() == TermKind::List {
                    self.stack.push(tail);
                    obj = head;
                    continue;
                }
                let yielded = self
                    .copy_leaf(head, &mut yield_count)
                    .map_err(|error| (error, (init - yield_count) as usize))?;
                if yielded {
                    self.obj = head;
                    self.stack.push(tail);
                    return Ok((false, init as usize));
                }
                obj = tail;
            }
            yield_count -= 1;
            if yield_count <= 0 {
                self.obj = obj;
                return Ok((false, init as usize));
            }
            let yielded = self
                .copy_leaf(obj, &mut yield_count)
                .map_err(|error| (error, (init - yield_count) as usize))?;
            if yielded {
                self.obj = obj;
                return Ok((false, init as usize));
            }
        }
        self.flush_run();
        Ok((true, (init - yield_count) as usize))
    }

    /// Build the iovec after both passes have finished.
    ///
    /// OTP allocates one off-heap binary for every copied run and returns
    /// sub-binaries of it.
    pub fn finish<H: HeapAlloc + ?Sized>(&mut self, heap: &mut H) -> Result<Term, BifError> {
        if self.copied.len() != self.size {
            return Err(BifError::SystemLimit);
        }
        let shared = if self.copied.is_empty() || !heap.supports_writable_binary() {
            None
        } else {
            let shared = allocate_iolist_binary(heap, self.copied.len())?;
            with_iolist_binary_output(shared, |output| {
                output.copy_from_slice(&self.copied);
                Ok(())
            })?;
            finish_iolist_binary_output(shared);
            Some(shared)
        };
        let mut terms = Vec::with_capacity(self.segments.len());
        for segment in std::mem::take(&mut self.segments) {
            terms.push(match segment {
                VecSegment::Large(term) => term,
                VecSegment::Run(start, len) => {
                    let mut heap = Heap(&mut *heap);
                    let mut builder = TermBuilder::new(&mut heap);
                    match shared {
                        Some(shared) => builder.sub_binary(shared, start * 8, len * 8),
                        None => builder.binary(&self.copied[start..start + len]),
                    }
                    .map_err(|_| BifError::SystemLimit)?
                }
            });
        }
        TermBuilder::new(&mut Heap(heap))
            .list_from_iter(terms)
            .map_err(|_| BifError::SystemLimit)
    }
}

fn iolist_to_iovec(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    if let Some(result) = iolist_to_iovec_shortcut(&mut ctx.heap, args[0])? {
        return Ok(result);
    }
    let mut walk = IolistVecWalk::new(args[0]);
    let (_, size_used) = walk.size_step(usize::MAX).map_err(|(error, _)| error)?;
    let (_, copy_used) = walk.copy_step(usize::MAX).map_err(|(error, _)| error)?;
    ctx.charge_reductions(iolist_yield_reductions(size_used) + iolist_yield_reductions(copy_used));
    walk.finish(&mut ctx.heap)
}

/// Flatten an iolist into its byte-aligned contents.
// Port of erts/emulator/beam/erl_iolist.c:419-620, 842-849 (list_to_binary_copy), OTP-29.1.1.
pub(super) fn iolist_bytes(root: Term) -> Result<Vec<u8>, BifError> {
    let size = iolist_size_value(root)?;
    let mut output = Vec::new();
    output
        .try_reserve_exact(size)
        .map_err(|_| BifError::SystemLimit)?;
    output.resize(size, 0);
    let mut offset = 0_usize;
    walk_iolist(root, |term, byte_allowed| {
        match term.classify() {
            TermKind::Nil => {}
            TermKind::Bitstring => {
                with_binary_input(term, |bytes| {
                    let end = offset
                        .checked_add(bytes.len())
                        .ok_or(BifError::SystemLimit)?;
                    output
                        .get_mut(offset..end)
                        .ok_or(BifError::SystemLimit)?
                        .copy_from_slice(bytes);
                    offset = end;
                    Ok(())
                })?;
            }
            TermKind::Number if byte_allowed => {
                let byte = term
                    .as_small()
                    .and_then(|n| u8::try_from(n).ok())
                    .ok_or(BADARG)?;
                let slot = output.get_mut(offset).ok_or(BifError::SystemLimit)?;
                *slot = byte;
                offset += 1;
            }
            _ => return Err(BADARG),
        }
        Ok(())
    })?;
    if offset != size {
        return Err(BifError::SystemLimit);
    }
    Ok(output)
}

// Port of erts/emulator/beam/erl_iolist.c:938-1093 (iolist_size_1), OTP-29.1.1.
fn iolist_size(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    let size = iolist_size_value(args[0])?;
    ctx.charge_reductions(size);
    integer(ctx, size)
}

// Port of erts/emulator/beam/erl_iolist.c:114-397 (generic_iolist_size), OTP-29.1.1.
fn iolist_size_value(root: Term) -> Result<usize, BifError> {
    let mut size = 0_usize;
    walk_iolist(root, |term, byte_allowed| {
        match term.classify() {
            TermKind::Nil => {}
            TermKind::Bitstring => {
                let bits = bitstring_bit_len(term)?;
                if !bits.is_multiple_of(8) {
                    return Err(BADARG);
                }
                add_iolist_size(&mut size, bits)?;
            }
            TermKind::Number if byte_allowed => {
                if !term.as_small().is_some_and(|n| (0..=255).contains(&n)) {
                    return Err(BADARG);
                }
                add_iolist_size(&mut size, 8)?;
            }
            _ => return Err(BADARG),
        }
        Ok(())
    })?;
    Ok(size / 8)
}

// Port of erts/emulator/beam/erl_iolist.c:114-397 (generic_iolist_size) and
// 419-620 (generic_iolist_copy), OTP-29.1.1. ERTS follows each list tail and
// saves only outer tails when descending into a nested head.
fn walk_iolist(
    root: Term,
    mut visit: impl FnMut(Term, bool) -> Result<(), BifError>,
) -> Result<(), BifError> {
    let mut pending = SmallVec::<[Term; 8]>::new();
    let mut current = root;
    loop {
        while current.classify() == TermKind::List {
            let (head, tail) = iolist_cons(current)?;
            if head.classify() == TermKind::List {
                pending.push(tail);
                current = head;
            } else {
                visit(head, true)?;
                current = tail;
            }
        }
        visit(current, false)?;
        match pending.pop() {
            Some(tail) => current = tail,
            None => return Ok(()),
        }
    }
}

fn copy_iolist(root: Term, output: &mut [u8]) -> Result<(), BifError> {
    let mut offset = 0_usize;
    walk_iolist(root, |term, byte_allowed| {
        match term.classify() {
            TermKind::Nil => {}
            TermKind::Bitstring => {
                with_binary_input(term, |bytes| {
                    let end = offset
                        .checked_add(bytes.len())
                        .ok_or(BifError::SystemLimit)?;
                    output
                        .get_mut(offset..end)
                        .ok_or(BifError::SystemLimit)?
                        .copy_from_slice(bytes);
                    offset = end;
                    Ok(())
                })?;
            }
            TermKind::Number if byte_allowed => {
                let byte = term
                    .as_small()
                    .and_then(|n| u8::try_from(n).ok())
                    .ok_or(BADARG)?;
                *output.get_mut(offset).ok_or(BifError::SystemLimit)? = byte;
                offset += 1;
            }
            _ => return Err(BADARG),
        }
        Ok(())
    })?;
    if offset != output.len() {
        return Err(BifError::SystemLimit);
    }
    Ok(())
}

/// Resumable second pass of `list_to_binary` and `iolist_to_binary`.
// Port of erts/emulator/beam/erl_iolist.c:294-620 (generic_iolist_copy), OTP-29.1.1.
pub struct IolistCopyWalk {
    current: Term,
    tails: SmallVec<[Term; 8]>,
    source: Option<CopySource>,
    offset: usize,
    done_after_source: bool,
    bit_mode: bool,
    to_bit: usize,
}

struct CopySource {
    term: Term,
    bit_offset: usize,
    remaining_bits: usize,
}

impl IolistCopyWalk {
    /// Start copying a validated iolist into its final binary allocation.
    pub fn new(root: Term) -> Self {
        Self {
            current: root,
            tails: SmallVec::new(),
            source: None,
            offset: 0,
            done_after_source: false,
            bit_mode: false,
            to_bit: 0,
        }
    }

    /// Start copying into a bit-addressed output, for `list_to_bitstring/1` (Unit 1).
    pub fn new_bits(root: Term) -> Self {
        Self {
            bit_mode: true,
            ..Self::new(root)
        }
    }

    /// Copy at most `yield_count` ERTS iolist units into `output`.
    pub fn step(
        &mut self,
        output: &mut [u8],
        yield_count: usize,
    ) -> Result<(bool, usize), (BifError, usize)> {
        let mut remaining = yield_count;
        loop {
            if let Some(mut source) = self.source.take() {
                let copy_limit = remaining.saturating_add(1).saturating_mul(32 * 8);
                let copy_bits = source.remaining_bits.min(copy_limit);
                let copy_bytes = copy_bits / 8;
                if self.bit_mode {
                    let mut staged = SmallVec::<[u8; 64]>::new();
                    staged.resize(copy_bits.div_ceil(8), 0);
                    copy_bitstring_range(source.term, source.bit_offset, &mut staged, copy_bits)
                        .map_err(|error| (error, yield_count.saturating_sub(remaining)))?;
                    or_bits_at(output, self.to_bit, &staged, copy_bits)
                        .map_err(|error| (error, yield_count))?;
                    self.to_bit += copy_bits;
                } else {
                    let end = self
                        .offset
                        .checked_add(copy_bytes)
                        .filter(|end| *end <= output.len())
                        .ok_or((BifError::SystemLimit, yield_count))?;
                    copy_bitstring_range(
                        source.term,
                        source.bit_offset,
                        &mut output[self.offset..end],
                        copy_bits,
                    )
                    .map_err(|error| (error, yield_count.saturating_sub(remaining)))?;
                    self.offset = end;
                }
                source.bit_offset = source
                    .bit_offset
                    .checked_add(copy_bits)
                    .ok_or((BifError::SystemLimit, yield_count))?;
                source.remaining_bits -= copy_bits;
                if source.remaining_bits != 0 {
                    self.source = Some(source);
                    return Ok((false, yield_count));
                }
                if self.done_after_source {
                    return Ok((true, yield_count - remaining));
                }
                remaining = remaining.saturating_sub(copy_bits / (32 * 8));
                continue;
            }

            while self.current.classify() == TermKind::List {
                if remaining <= 1 {
                    return Ok((false, yield_count));
                }
                remaining -= 1;
                let (head, tail) = iolist_cons(self.current)
                    .map_err(|error| (error, yield_count.saturating_sub(remaining)))?;
                if head.classify() == TermKind::List {
                    self.tails.push(tail);
                    self.current = head;
                    continue;
                }
                self.current = tail;
                match head.classify() {
                    TermKind::Nil => {}
                    TermKind::Bitstring => {
                        let bits = bitstring_bit_len(head)
                            .map_err(|error| (error, yield_count.saturating_sub(remaining)))?;
                        if !self.bit_mode && !bits.is_multiple_of(8) {
                            return Err((BifError::BADARG, yield_count - remaining));
                        }
                        self.source = Some(CopySource {
                            term: head,
                            bit_offset: 0,
                            remaining_bits: bits,
                        });
                        break;
                    }
                    TermKind::Number => {
                        let byte = head
                            .as_small()
                            .and_then(|number| u8::try_from(number).ok())
                            .ok_or((BifError::BADARG, yield_count - remaining))?;
                        if self.bit_mode {
                            or_bits_at(output, self.to_bit, &[byte], 8)
                                .map_err(|error| (error, yield_count - remaining))?;
                            self.to_bit += 8;
                        } else {
                            let slot = output
                                .get_mut(self.offset)
                                .ok_or((BifError::SystemLimit, yield_count - remaining))?;
                            *slot = byte;
                            self.offset += 1;
                        }
                    }
                    _ => return Err((BifError::BADARG, yield_count - remaining)),
                }
                if self.source.is_some() {
                    break;
                }
            }

            if self.source.is_some() {
                continue;
            }
            if remaining <= 1 {
                return Ok((false, yield_count));
            }
            remaining -= 1;
            match self.current.classify() {
                TermKind::Nil => {}
                TermKind::Bitstring => {
                    let bits = bitstring_bit_len(self.current)
                        .map_err(|error| (error, yield_count - remaining))?;
                    if !self.bit_mode && !bits.is_multiple_of(8) {
                        return Err((BifError::BADARG, yield_count - remaining));
                    }
                    self.source = Some(CopySource {
                        term: self.current,
                        bit_offset: 0,
                        remaining_bits: bits,
                    });
                    self.done_after_source = self.tails.is_empty();
                }
                _ => return Err((BifError::BADARG, yield_count - remaining)),
            }
            match self.tails.pop() {
                Some(tail) => self.current = tail,
                None if self.source.is_none() => {
                    return Ok((true, yield_count - remaining));
                }
                None => self.current = Term::NIL,
            }
        }
    }

    /// Return bits written after the walk has completed.
    pub fn written_bits(&self) -> usize {
        if self.bit_mode {
            self.to_bit
        } else {
            self.offset * 8
        }
    }
}

/// OR the first `bits` bits of `source` into zeroed `output` starting at bit `to_bit`.
fn or_bits_at(
    output: &mut [u8],
    to_bit: usize,
    source: &[u8],
    bits: usize,
) -> Result<(), BifError> {
    if to_bit
        .checked_add(bits)
        .is_none_or(|end| end > output.len().saturating_mul(8))
    {
        return Err(BifError::SystemLimit);
    }
    let shift = to_bit % 8;
    for (position, byte) in source.iter().enumerate() {
        let index = to_bit / 8 + position;
        let used = (bits - position * 8).min(8);
        let byte = *byte & (0xFF_u8 << (8 - used));
        output[index] |= byte >> shift;
        if shift + used > 8 {
            output[index + 1] |= byte << (8 - shift);
        }
    }
    Ok(())
}

/// Allocate the final writable binary before the iolist copy pass.
pub fn allocate_iolist_binary<H: HeapAlloc + ?Sized>(
    heap: &mut H,
    byte_len: usize,
) -> Result<Term, BifError> {
    if byte_len == 0 {
        return TermBuilder::new(&mut super::Heap(heap))
            .binary(&[])
            .map_err(|_| BifError::SystemLimit);
    }
    let bit_len = byte_len
        .checked_mul(8)
        .filter(|bits| *bits <= isize::MAX as usize)
        .ok_or(BifError::SystemLimit)?;
    let term = TermBuilder::new(&mut super::Heap(heap))
        .writable_binary(&[], 0, byte_len)
        .map_err(|_| BifError::SystemLimit)?;
    writable_extend_private(term, bit_len).map_err(|_| BifError::SystemLimit)?;
    Ok(term)
}

/// Give the unique writer a temporary mutable view of its final binary.
pub fn with_iolist_binary_output<R>(
    term: Term,
    f: impl FnOnce(&mut [u8]) -> Result<R, BifError>,
) -> Result<R, BifError> {
    // SAFETY: the active writer is owned by this process and the callback does not retain a view.
    let output = unsafe { writable_bytes_mut(term) }.ok_or(BifError::SystemLimit)?;
    f(output)
}

/// End the unique writer before the completed binary is shared with Erlang code.
pub fn finish_iolist_binary_output(term: Term) {
    writable_finalize(term);
}

/// Allocate a binary and fill its final byte slice while its writer is private.
pub(crate) fn write_binary(
    ctx: &mut Ctx<'_>,
    byte_len: usize,
    fill: impl FnOnce(&mut [u8]) -> Result<(), BifError>,
) -> Result<Term, BifError> {
    if byte_len == 0 {
        return Ok(TermBuilder::new(&mut Heap(&mut ctx.heap))
            .binary(&[])
            .expect("infallible BIF heap"));
    }
    byte_len.checked_mul(8).ok_or(BifError::SystemLimit)?;
    // Port of erts/emulator/beam/erl_bits.c:2841-2858 (erts_new_bitstring_refc), OTP-29.1.1.
    const ONHEAP_BYTES: usize = 64;
    if byte_len <= ONHEAP_BYTES {
        let mut bytes = [0_u8; ONHEAP_BYTES];
        fill(&mut bytes[..byte_len])?;
        return TermBuilder::new(&mut Heap(&mut ctx.heap))
            .binary(&bytes[..byte_len])
            .map_err(|_| BifError::SystemLimit);
    }
    if !ctx.heap.supports_writable_binary() {
        let mut bytes = vec![0; byte_len];
        fill(&mut bytes)?;
        return TermBuilder::new(&mut Heap(&mut ctx.heap))
            .binary(&bytes)
            .map_err(|_| BifError::SystemLimit);
    }
    let result = allocate_iolist_binary(&mut ctx.heap, byte_len)?;
    with_iolist_binary_output(result, fill)?;
    finish_iolist_binary_output(result);
    Ok(result)
}

// Port of erts/emulator/beam/erl_iolist.c:139-191 (generic_iolist_size), OTP-29.1.1.
fn add_iolist_size(size: &mut usize, amount: usize) -> Result<(), BifError> {
    *size = size.checked_add(amount).ok_or(BifError::SystemLimit)?;
    Ok(())
}

// Port of erts/emulator/beam/binary.c:413-474 (bitstring_to_list_1), OTP-29.1.1.
fn bitstring_to_list(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    // SAFETY: The source bitstring and owner remain live.
    let view = unsafe { args[0].binary_ref() }.ok_or(BADARG)?;
    let mut data = Vec::with_capacity(view.bit_len().div_ceil(8));
    for i in 0..view.bit_len() {
        let source = view.start_bit() + i;
        if i % 8 == 0 {
            data.push(0_u8);
        }
        let bit = (view.bytes()[source / 8] >> (7 - source % 8)) & 1;
        let last = data.last_mut().expect("byte");
        *last |= bit << (7 - i % 8);
    }
    let full = view.bit_len() / 8;
    ctx.charge_reductions(full);
    let mut values = data[..full]
        .iter()
        .map(|&b| Term::small(b as i64).unwrap())
        .collect::<Vec<_>>();
    if view.bit_len() % 8 != 0 {
        values.push(
            TermBuilder::new(&mut Heap(&mut ctx.heap))
                .bitstring(&data[full..], view.bit_len() % 8)
                .expect("infallible BIF heap"),
        );
    }
    Ok(make_list(ctx, values, Term::NIL))
}

// Port of erts/emulator/beam/erl_iolist.c:857-935 (list_to_bitstring_bif), OTP-29.1.1.
fn list_to_bitstring(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    if !matches!(args[0].classify(), TermKind::List | TermKind::Nil) {
        return Err(BADARG);
    }
    if let Some(bitstring) = singleton_bitstring(args[0], 1)? {
        return Ok(bitstring);
    }
    let mut work: SmallVec<[(Term, bool); 8]> = smallvec![(args[0], false)];
    let mut data = SmallVec::<[u8; 64]>::new();
    let mut bits = 0_usize;
    while let Some((term, byte_allowed)) = work.pop() {
        match term.classify() {
            TermKind::Nil => {}
            TermKind::List => {
                let (head, tail) = iolist_cons(term)?;
                work.push((tail, false));
                work.push((head, true));
            }
            TermKind::Number if byte_allowed && term.as_small().is_some() => {
                let byte = u8::try_from(term.as_small().expect("checked")).map_err(|_| BADARG)?;
                for bit in 0..8 {
                    append_bit(&mut data, &mut bits, (byte >> (7 - bit)) & 1);
                }
            }
            TermKind::Bitstring => append_term_bitstring(&mut data, &mut bits, term)?,
            _ => return Err(BADARG),
        }
    }
    ctx.charge_reductions(data.len());
    Ok(TermBuilder::new(&mut Heap(&mut ctx.heap))
        .bitstring(&data, bits)
        .expect("infallible BIF heap"))
}

// Port of erts/emulator/beam/erl_bif_binary.c:1954-2038 (erts_binary_part), OTP-29.1.1.
fn binary_part(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    let (mut position, mut length) = if args.len() == 2 {
        if tuple_arity(args[1])? != 2 {
            return Err(BADARG);
        }
        (
            tuple_element(args[1], 0)?.as_small().ok_or(BADARG)?,
            tuple_element(args[1], 1)?.as_small().ok_or(BADARG)?,
        )
    } else {
        (
            args[1].as_small().ok_or(BADARG)?,
            args[2].as_small().ok_or(BADARG)?,
        )
    };
    if length < 0 {
        length = length.checked_neg().ok_or(BADARG)?;
        if length > position {
            return Err(BADARG);
        }
        position -= length;
    }
    if position < 0 || length < 0 || position.checked_add(length).is_none() {
        return Err(BADARG);
    }
    let start_bits = usize::try_from(position)
        .ok()
        .and_then(|value| value.checked_mul(8))
        .ok_or(BADARG)?;
    let length_bits = usize::try_from(length)
        .ok()
        .and_then(|value| value.checked_mul(8))
        .ok_or(BADARG)?;
    TermBuilder::new(&mut Heap(&mut ctx.heap))
        .sub_binary_bif(args[0], start_bits, length_bits)
        .map_err(|error| match error {
            arinsal_term::TermError::BadArg => BADARG,
            _ => BifError::SystemLimit,
        })
}

/// Execute the tuple-range form of `binary:part/2` without resolving the BIF name again.
// Port of erts/emulator/beam/erl_bif_binary.c:1954-2038 (`erts_binary_part`), OTP-29.1.1.
pub fn binary_part_2(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    if args.len() != 2 {
        return Err(BADARG);
    }
    binary_part(ctx, args)
}

// Port of erts/emulator/beam/binary.c:476-513 (split_binary_2), OTP-29.1.1.
fn split_binary(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    let bits = bitstring_bit_len(args[0])?;
    let at = args[1].as_small().ok_or(BADARG)?;
    if at < 0 || at as u128 > (bits / 8) as u128 {
        return Err(BADARG);
    }
    let split_at = usize::try_from(at).map_err(|_| BADARG)? * 8;
    let mut heap = Heap(&mut ctx.heap);
    let mut builder = TermBuilder::new(&mut heap);
    let left = builder
        .sub_binary_bif(args[0], 0, split_at)
        .map_err(|_| BifError::SystemLimit)?;
    let right = builder
        .sub_binary_bif(args[0], split_at, bits - split_at)
        .map_err(|_| BifError::SystemLimit)?;
    builder
        .tuple(&[left, right])
        .map_err(|_| BifError::SystemLimit)
}

// Port of erts/emulator/beam/erl_bif_binary.c:2286-2313 (binary_first_1), OTP-29.1.1.
fn binary_first(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    with_binary_input(args[0], |bytes| {
        let byte = bytes.first().ok_or(BADARG)?;
        integer(ctx, usize::from(*byte))
    })
}

// Port of erts/emulator/beam/erl_bif_binary.c:2316-2343 (binary_last_1), OTP-29.1.1.
fn binary_last(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    with_binary_input(args[0], |bytes| {
        let byte = bytes.last().ok_or(BADARG)?;
        integer(ctx, usize::from(*byte))
    })
}

// Port of erts/emulator/beam/erl_bif_binary.c:2335-2368 (binary_at_2), OTP-29.1.1.
fn binary_at(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    with_binary_input(args[0], |bytes| {
        let index = args[1].as_small().ok_or(BADARG)?;
        let byte = bytes
            .get(usize::try_from(index).map_err(|_| BADARG)?)
            .ok_or(BADARG)?;
        integer(ctx, usize::from(*byte))
    })
}

// Port of erts/emulator/beam/erl_bif_binary.c:2400-2512 (do_binary_copy), OTP-29.1.1.
fn binary_copy(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    let bits = bitstring_bit_len(args[0])?;
    let count = if args.len() == 2 {
        args[1].as_small().ok_or(BADARG)?
    } else {
        1
    };
    if !bits.is_multiple_of(8) || count < 0 {
        return Err(BADARG);
    }
    let count = usize::try_from(count).map_err(|_| BifError::SystemLimit)?;
    let source_len = bits / 8;
    if count == 0 || source_len == 0 {
        return Ok(TermBuilder::new(&mut Heap(&mut ctx.heap))
            .binary(&[])
            .expect("infallible BIF heap"));
    }
    if count >= (usize::MAX / source_len) {
        return Err(BifError::SystemLimit);
    }
    let length = source_len * count;
    if length > (1 << 30) {
        return Err(BifError::SystemLimit);
    }
    with_binary_input(args[0], |source| {
        TermBuilder::new(&mut Heap(&mut ctx.heap))
            .binary_from_fn(length, |output| {
                let mut copied = 0;
                while copied < length {
                    let source_offset = copied % source_len;
                    let stride = (length - copied).min(source_len - source_offset);
                    output[copied..copied + stride]
                        .copy_from_slice(&source[source_offset..source_offset + stride]);
                    copied += stride;
                }
            })
            .map_err(|_| BifError::SystemLimit)
    })
}

// Port of erts/emulator/beam/erl_bif_binary.c:2515-2555 (binary_referenced_byte_size_1), OTP-29.1.1.
fn referenced_byte_size(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    let bytes = with_binary_bytes(args[0], |view| view.referenced_size())?;
    integer(ctx, bytes)
}

// Port of erts/emulator/beam/erl_bif_binary.c:2183-2284 (start_longest_common), OTP-29.1.1.
fn longest_common_prefix(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    let binaries = list(args[0])?;
    let first = *binaries.first().ok_or(BADARG)?;
    with_binary_input(first, |first_bytes| {
        let mut length = 0;
        for (index, byte) in first_bytes.iter().enumerate() {
            let mut all_match = true;
            for other in binaries.iter().skip(1) {
                if !with_binary_input(*other, |other_bytes| {
                    Ok(other_bytes.get(index) == Some(byte))
                })? {
                    all_match = false;
                    break;
                }
            }
            if !all_match {
                break;
            }
            length += 1;
        }
        integer(ctx, length)
    })
}

// Port of erts/emulator/beam/erl_bif_binary.c:2183-2284 (start_longest_common), OTP-29.1.1.
fn longest_common_suffix(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    let binaries = list(args[0])?;
    let first = *binaries.first().ok_or(BADARG)?;
    with_binary_input(first, |first_bytes| {
        let mut length = 0;
        for (index, byte) in first_bytes.iter().rev().enumerate() {
            let mut all_match = true;
            for other in binaries.iter().skip(1) {
                if !with_binary_input(*other, |other_bytes| {
                    Ok(other_bytes.len() > index
                        && other_bytes[other_bytes.len() - index - 1] == *byte)
                })? {
                    all_match = false;
                    break;
                }
            }
            if !all_match {
                break;
            }
            length += 1;
        }
        integer(ctx, length)
    })
}

// Port of erts/emulator/beam/erl_bif_binary.c:1004-1113 (do_binary_match_compile), OTP-29.1.1.
fn patterns(term: Term) -> Result<Vec<Vec<u8>>, BifError> {
    let candidates = if term.classify() == TermKind::Bitstring {
        vec![term]
    } else {
        list(term)?
    };
    if candidates.is_empty() {
        return Err(BADARG);
    }
    let mut result = Vec::new();
    for candidate in candidates {
        let bytes = binary_bytes(candidate)?;
        if bytes.is_empty() {
            return Err(BADARG);
        }
        result.push(bytes);
    }
    Ok(result)
}

// Port of erts/emulator/beam/erl_bif_binary.c:1004-1113, 1230-1270 (pattern extraction), OTP-29.1.1.
fn pattern(term: Term) -> Result<Arc<SearchPattern>, BifError> {
    if tuple_arity(term).ok() == Some(2) {
        let tag = atom_name(tuple_element(term, 0)?).filter(|tag| matches!(*tag, "bm" | "ac"));
        if let Some(tag) = tag {
            let reference = tuple_element(term, 1)?;
            let owner = reference.magic_owner().ok_or(BADARG)?;
            let compiled = owner
                .downcast_ref::<Arc<SearchPattern>>()
                .filter(|compiled| compiled.tag() == tag)
                .ok_or(BADARG)?;
            return Ok(Arc::clone(compiled));
        }
    }
    Ok(Arc::new(SearchPattern::compile(&patterns(term)?)?))
}

// Port of erts/emulator/beam/erl_bif_binary.c:1004-1113 (binary_compile_pattern_1), OTP-29.1.1.
fn compile_pattern(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    let patterns = patterns(args[0])?;
    let compiled = Arc::new(SearchPattern::compile(&patterns)?);
    let orig_size = arinsal_term::MAGIC_BIN_DATA_OFFSET + compiled.erts_payload_size();
    let tag = Term::atom(global_atoms().intern(compiled.tag()).expect("atom"));
    let reference = TermBuilder::new(&mut Heap(&mut ctx.heap))
        .magic_ref(MagicRef::with_orig_size(compiled, orig_size))
        .map_err(|_| BifError::SystemLimit)?;
    Ok(tuple_build(ctx, &[tag, reference]))
}

// Port of erts/emulator/beam/erl_bif_binary.c:1273-1344 (parse_match_opts_list), OTP-29.1.1.
fn match_scope(len: usize, options: Term) -> Result<(usize, usize), BifError> {
    let mut scope = (0, len);
    for option in list(options)? {
        scope = scope_option(len, option)?;
    }
    Ok(scope)
}

// Port of erts/emulator/beam/erl_bif_binary.c:1273-1400 (scope option parsing), OTP-29.1.1.
fn scope_option(len: usize, option: Term) -> Result<(usize, usize), BifError> {
    if tuple_arity(option)? != 2 || atom_name(tuple_element(option, 0)?) != Some("scope") {
        return Err(BADARG);
    }
    let range = tuple_element(option, 1)?;
    if tuple_arity(range)? != 2 {
        return Err(BADARG);
    }
    let start = tuple_element(range, 0)?.as_small().ok_or(BADARG)?;
    let length = tuple_element(range, 1)?.as_small().ok_or(BADARG)?;
    let end = start.checked_add(length).ok_or(BADARG)?;
    let (lo, hi) = if length < 0 {
        (end, start)
    } else {
        (start, end)
    };
    if lo < 0 || hi < 0 || hi as usize > len {
        return Err(BADARG);
    }
    Ok((lo as usize, hi as usize))
}

/// Search operations supported by the binary BIF continuation.
#[derive(Clone, Copy)]
pub enum BinarySearchKind {
    /// Return the first matching range.
    Match,
    /// Return all non-overlapping matching ranges.
    Matches,
    /// Split at the first or all matching ranges.
    Split,
}

/// Resumable state for `binary:match/2,3`, `matches/2,3`, and `split/2,3`.
pub struct BinarySearchWalk {
    subject: Term,
    walk: SearchWalk,
    kind: BinarySearchKind,
    split_trim: bool,
    split_trim_all: bool,
    global: bool,
    result_left: Option<usize>,
}

impl BinarySearchWalk {
    /// Parse BIF options and prepare a Boyer–Moore or Aho–Corasick walk.
    pub fn new(kind: BinarySearchKind, args: &[Term]) -> Result<Self, BifError> {
        let compiled = pattern(args[1])?;
        let (walk, split_trim, split_trim_all, first_only) = with_binary_input(args[0], |bytes| {
            let (scope, first_only, split_trim, split_trim_all) = match kind {
                BinarySearchKind::Match => (
                    if args.len() == 3 {
                        match_scope(bytes.len(), args[2])?
                    } else {
                        (0, bytes.len())
                    },
                    true,
                    false,
                    false,
                ),
                BinarySearchKind::Matches => (
                    if args.len() == 3 {
                        match_scope(bytes.len(), args[2])?
                    } else {
                        (0, bytes.len())
                    },
                    false,
                    false,
                    false,
                ),
                BinarySearchKind::Split => {
                    let (global, trim, trim_all, scope) = if args.len() == 3 {
                        split_options(bytes.len(), args[2])?
                    } else {
                        (false, false, false, (0, bytes.len()))
                    };
                    (scope, !global, trim, trim_all)
                }
            };
            Ok((
                SearchWalk::new(bytes.len(), compiled, scope, first_only),
                split_trim,
                split_trim_all,
                first_only,
            ))
        })?;
        let global = !first_only;
        Ok(Self {
            subject: args[0],
            walk,
            kind,
            split_trim,
            split_trim_all,
            global,
            result_left: None,
        })
    }

    /// Run at most `budget` ERTS search units, then the units of building a global result.
    // Port of erts/emulator/beam/erl_bif_binary.c (do_binary_find) and
    // 1671-1735, 1809-1915 (do_match_global_result, do_split_global_result), OTP-29.1.1.
    pub fn step(&mut self, budget: usize) -> (bool, usize) {
        let mut work = 0;
        if !self.walk.is_done() {
            let (done, used) =
                with_binary_input(self.subject, |bytes| Ok(self.walk.step(bytes, budget)))
                    .expect("search subject remains a live binary");
            if !done {
                return (false, used);
            }
            work = used;
        }
        let mut left = *self.result_left.get_or_insert_with(|| {
            let found = self.walk.match_count();
            match (self.kind, self.global) {
                (BinarySearchKind::Matches, _) => found * 2,
                (BinarySearchKind::Split, true) => found,
                _ => 0,
            }
        });
        while left > 0 {
            if work + 1 >= budget {
                self.result_left = Some(left);
                return (false, budget.max(work));
            }
            work += 1;
            left -= 1;
        }
        self.result_left = Some(0);
        (true, work)
    }

    /// Build the BIF result after searching completes.
    pub fn finish(&self, ctx: &mut Ctx<'_>) -> Result<Term, BifError> {
        let found = self.walk.finish();
        match self.kind {
            BinarySearchKind::Match => match found.first() {
                Some(&(position, length)) => match_result(ctx, position, length),
                None => Ok(Term::atom(global_atoms().intern("nomatch").expect("atom"))),
            },
            BinarySearchKind::Matches => {
                let values = found
                    .into_iter()
                    .map(|(position, length)| match_result(ctx, position, length))
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(make_list(ctx, values, Term::NIL))
            }
            BinarySearchKind::Split => {
                let mut ranges = Vec::new();
                let mut previous = 0;
                for (position, length) in found {
                    ranges.push((previous, position - previous));
                    previous = position + length;
                }
                ranges.push((previous, self.walk.len() - previous));
                if self.split_trim_all {
                    ranges.retain(|(_, length)| *length != 0);
                } else if self.split_trim {
                    while ranges.last().is_some_and(|(_, length)| *length == 0) {
                        ranges.pop();
                    }
                }
                let values = {
                    let mut heap = Heap(&mut ctx.heap);
                    let mut builder = TermBuilder::new(&mut heap);
                    ranges
                        .into_iter()
                        .map(|(start, length)| {
                            builder
                                .sub_binary_bif(self.subject, start * 8, length * 8)
                                .map_err(|_| BifError::SystemLimit)
                        })
                        .collect::<Result<Vec<_>, _>>()?
                };
                Ok(make_list(ctx, values, Term::NIL))
            }
        }
    }
}

// Port of erts/emulator/beam/erl_bif_binary.c:1840-1850 (match result), OTP-29.1.1.
fn match_result(ctx: &mut Ctx<'_>, position: usize, length: usize) -> Result<Term, BifError> {
    let pos = integer(ctx, position)?;
    let len = integer(ctx, length)?;
    Ok(tuple_build(ctx, &[pos, len]))
}

// Port of erts/emulator/beam/erl_bif_binary.c:1538-1587 (binary_match_2/3), OTP-29.1.1.
fn binary_match(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    let mut walk = BinarySearchWalk::new(BinarySearchKind::Match, args)?;
    while !walk.step(usize::MAX).0 {}
    walk.finish(ctx)
}

// Port of erts/emulator/beam/erl_bif_binary.c:1589-1597 (binary_matches_2/3), OTP-29.1.1.
fn binary_matches(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    let mut walk = BinarySearchWalk::new(BinarySearchKind::Matches, args)?;
    while !walk.step(usize::MAX).0 {}
    walk.finish(ctx)
}

// Port of erts/emulator/beam/erl_bif_binary.c:1346-1405 (parse_split_opts_list), OTP-29.1.1.
fn split_options(
    len: usize,
    options: Term,
) -> Result<(bool, bool, bool, (usize, usize)), BifError> {
    let mut global = false;
    let mut trim = false;
    let mut trim_all = false;
    let mut scope = (0, len);
    for option in list(options)? {
        match atom_name(option) {
            Some("global") => global = true,
            Some("trim") => trim = true,
            Some("trim_all") => trim_all = true,
            _ => scope = scope_option(len, option)?,
        }
    }
    Ok((global, trim, trim_all, scope))
}

// Port of erts/emulator/beam/erl_bif_binary.c:1600-1645 (binary_split_2/3), OTP-29.1.1.
fn binary_split(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    let mut walk = BinarySearchWalk::new(BinarySearchKind::Split, args)?;
    while !walk.step(usize::MAX).0 {}
    walk.finish(ctx)
}

// Port of erts/emulator/beam/erl_bif_binary.c:2572-2683 (unsigned endian parsing), OTP-29.1.1.
fn byte_order(args: &[Term]) -> Result<bool, BifError> {
    if args.len() == 1 {
        return Ok(false);
    }
    match atom_name(args[1]) {
        Some("big") => Ok(false),
        Some("little") => Ok(true),
        _ => Err(BADARG),
    }
}

// Port of erts/emulator/beam/erl_bif_binary.c:2572-2647, 2818-2826 (encode_unsigned), OTP-29.1.1.
fn encode_unsigned(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    let value = bigint(args[0])?;
    if value.sign() == Sign::Minus {
        return Err(BADARG);
    }
    let mut bytes = value.to_bytes_be().1;
    if bytes.is_empty() {
        bytes.push(0);
    }
    if byte_order(args)? {
        bytes.reverse();
    }
    Ok(TermBuilder::new(&mut Heap(&mut ctx.heap))
        .binary(&bytes)
        .expect("infallible BIF heap"))
}

// Port of erts/emulator/beam/erl_bif_binary.c:2649-2683, 2828-2835 (decode_unsigned), OTP-29.1.1.
fn decode_unsigned(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    let little_endian = byte_order(args)?;
    with_binary_input(args[0], |bytes| {
        let value = if little_endian {
            BigInt::from_bytes_le(Sign::Plus, bytes)
        } else {
            BigInt::from_bytes_be(Sign::Plus, bytes)
        };
        TermBuilder::new(&mut Heap(&mut ctx.heap))
            .int_from_bigint(&value)
            .map_err(|_| BifError::SystemLimit)
    })
}

crate::bif_bodies!(
    byte_size,
    bit_size,
    erlang_binary_to_list,
    list_to_binary,
    iolist_to_binary,
    iolist_to_iovec,
    iolist_size,
    bitstring_to_list,
    list_to_bitstring,
    split_binary,
    binary_part,
    binary_first,
    binary_last,
    binary_at,
    binary_copy,
    referenced_byte_size,
    longest_common_prefix,
    longest_common_suffix,
    compile_pattern,
    binary_match,
    binary_matches,
    binary_split,
    encode_unsigned,
    decode_unsigned,
);
