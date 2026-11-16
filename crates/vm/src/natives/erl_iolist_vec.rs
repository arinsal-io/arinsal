//! The `iolist_to_iovec/1` walk of erl_iolist.c.
//!
//! Port of erts/emulator/beam/erl_iolist.c (iolist_to_iovec_1, the size and copy passes of
//! iolist_to_iovec_engine), OTP-29.1.1. The passes are resumable: each runs for a number of
//! yield counts and reports how many it used; `natives::erl_iolist` charges reductions and traps.

use arinsal_bifs::BifError;
use arinsal_term::raw::{BinRef, Cons};
use arinsal_term::{HeapAlloc, Term, TermBuilder, TermKind};

const BADARG: BifError = BifError::BADARG;

fn iolist_cons(term: Term) -> Result<(Term, Term), BifError> {
    Cons::try_from(term).ok().map(Cons::pair).ok_or(BADARG)
}

fn copy_bitstring_range(
    term: Term,
    start: usize,
    output: &mut [u8],
    bit_count: usize,
) -> Result<(), BifError> {
    arinsal_term::erl_bits::copy_bitstring_range(term, start, output, bit_count).map_err(|_| BADARG)
}

/// Bits at or below which `iolist_to_iovec/1` copies a binary into the shared run (OTP-29.1.1).
const IOL2V_COPY_THRESHOLD_BITS: usize = 64 * 8 * 8;

/// Whether `iolist_to_iovec/1` copies a bitstring instead of keeping it as a segment.
fn iol2v_should_copy(start_bit: usize, bit_len: usize) -> bool {
    bit_len <= IOL2V_COPY_THRESHOLD_BITS || !start_bit.is_multiple_of(8)
}

fn bitstring_geometry(term: Term) -> Result<(usize, usize), BifError> {
    BinRef::try_from(term)
        .map(|view| (view.start_bit(), view.bit_len()))
        .map_err(|_| BADARG)
}

/// Yield counts one reduction buys in the iolist size and copy passes.
const IOL2V_YIELDS_PER_RED: usize = 8;
/// Bits copied per yield count.
const IOL2V_COPY_BITS_PER_YIELD: usize = 32 * 8;

/// Reductions charged for `used` yield counts.
pub(crate) fn iolist_yield_reductions(used: usize) -> usize {
    used.saturating_sub(1) / IOL2V_YIELDS_PER_RED + 1
}

/// The `[]`, `Bin` and `[Bin]` cases of `iolist_to_iovec/1` that need no traversal.
pub(crate) fn iolist_to_iovec_shortcut<H: HeapAlloc + ?Sized>(
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
    TermBuilder::new(heap)
        .list_from_iter([single])
        .map(Some)
        .map_err(|_| BifError::SystemLimit)
}

enum VecSegment {
    Run(usize, usize),
    Large(Term),
}

/// Resumable size and copy passes of `iolist_to_iovec/1`.
pub(crate) struct IolistVecWalk {
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
    pub(crate) fn new(root: Term) -> Self {
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
    pub(crate) fn sized(&self) -> bool {
        self.sized
    }

    /// Run the sizing pass for at most `budget` yield counts.
    ///
    /// Returns whether the pass finished and the yield counts used.
    pub(crate) fn size_step(&mut self, budget: usize) -> Result<(bool, usize), (BifError, usize)> {
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
    pub(crate) fn copy_step(&mut self, budget: usize) -> Result<(bool, usize), (BifError, usize)> {
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
    pub(crate) fn finish<H: HeapAlloc + ?Sized>(&mut self, heap: &mut H) -> Result<Term, BifError> {
        if self.copied.len() != self.size {
            return Err(BifError::SystemLimit);
        }
        let shared = if self.copied.is_empty() || !heap.supports_writable_binary() {
            None
        } else {
            let shared = arinsal_term::raw::allocate_iolist_binary(heap, self.copied.len())
                .map_err(|_| BifError::SystemLimit)?;
            arinsal_term::raw::with_iolist_binary_output(shared, |output| {
                output.copy_from_slice(&self.copied);
            })
            .ok_or(BifError::SystemLimit)?;
            arinsal_term::raw::finish_iolist_binary_output(shared);
            Some(shared)
        };
        let mut terms = Vec::with_capacity(self.segments.len());
        for segment in std::mem::take(&mut self.segments) {
            terms.push(match segment {
                VecSegment::Large(term) => term,
                VecSegment::Run(start, len) => {
                    let mut builder = TermBuilder::new(&mut *heap);
                    match shared {
                        Some(shared) => builder.sub_binary(shared, start * 8, len * 8),
                        None => builder.binary(&self.copied[start..start + len]),
                    }
                    .map_err(|_| BifError::SystemLimit)?
                }
            });
        }
        TermBuilder::new(heap)
            .list_from_iter(terms)
            .map_err(|_| BifError::SystemLimit)
    }
}
