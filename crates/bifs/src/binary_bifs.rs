//! Binary and iolist BIFs ported from ERTS binary and iolist code.

use std::borrow::Cow;

use arinsal_term::{HeapAlloc, TermBuilder};

use crate::{BifError, Ctx};

use super::*;

pub(super) fn lookup<V: crate::BifTableVisitor>(
    module: &str,
    name: &str,
    arity: u8,
    v: &mut V,
) -> Option<V::Output> {
    let bif = match (module, name, arity) {
        ("erlang", "byte_size", 1) => v.entry::<word_bodies::byte_size>(),
        ("erlang", "bit_size", 1) => v.entry::<word_bodies::bit_size>(),
        ("erlang", "binary_part", 2 | 3) | ("binary", "part", 2 | 3) => {
            v.entry::<word_bodies::binary_part>()
        }
        _ => return None,
    };
    Some(bif)
}

// Port of erts/emulator/beam/erl_bif_guard.c:376 (byte_size_1), OTP-29.1.1.
#[inline(always)]
fn byte_size_result(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    let bits = bitstring_bit_len(args[0])?;
    integer(ctx, bits.div_ceil(8))
}

// Port of erts/emulator/beam/erl_bif_guard.c:354 (bit_size_1), OTP-29.1.1.
#[inline(always)]
fn bit_size_result(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    integer(ctx, bitstring_bit_len(args[0])?)
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
    stack: arinsal_term::EStack<8>,
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
            stack: arinsal_term::EStack::new(),
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

pub fn allocate_iolist_binary<H: HeapAlloc + ?Sized>(
    heap: &mut H,
    byte_len: usize,
) -> Result<Term, BifError> {
    arinsal_term::raw::allocate_iolist_binary(heap, byte_len).map_err(|_| BifError::SystemLimit)
}

/// Give the unique writer a temporary mutable view of its final binary.
pub fn with_iolist_binary_output<R>(
    term: Term,
    f: impl FnOnce(&mut [u8]) -> Result<R, BifError>,
) -> Result<R, BifError> {
    arinsal_term::raw::with_iolist_binary_output(term, f).ok_or(BifError::SystemLimit)?
}

/// End the unique writer before the completed binary is shared with Erlang code.
pub fn finish_iolist_binary_output(term: Term) {
    arinsal_term::raw::finish_iolist_binary_output(term);
}

// Port of erts/emulator/beam/erl_bif_binary.c:1954-2038 (erts_binary_part), OTP-29.1.1.
#[inline(always)]
fn binary_part_result(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
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
    binary_part_result(ctx, args)
}

// Port of erts/emulator/beam/erl_bif_binary.c:1004-1113 (do_binary_match_compile), OTP-29.1.1.

macro_rules! word_result_body {
    ($name:ident, $result:ident) => {
        #[inline(always)]
        fn $name(ctx: &mut Ctx<'_>, args: &[Term]) -> Term {
            match $result(ctx, args) {
                Ok(value) => value,
                Err(error) => ctx.fail(error),
            }
        }
    };
}

word_result_body!(byte_size, byte_size_result);
word_result_body!(bit_size, bit_size_result);
word_result_body!(binary_part, binary_part_result);

crate::word_bif_bodies_in!(word_bodies;
    byte_size,
    bit_size,
    binary_part,
);
