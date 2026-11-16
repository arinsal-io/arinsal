//! The resumable iolist size and copy passes of `erl_iolist.c`.
//!
//! They live in this crate because `erts_iolist_size` / `erts_iolist_to_buf` are shared by the
//! `re` BIFs and by the trapping `list_to_binary` family of the vm, and the vm depends on `re`.
use crate::EStack;
use crate::Term;
use crate::raw::{BinRef, Cons};

/// Why an iolist pass stopped before its end.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IolistError {
    /// `ERTS_IOLIST_TYPE`: not an iolist (or not a byte-sized bitstring).
    BadArg,
    /// `ERTS_IOLIST_OVERFLOW` or a size that does not fit.
    SystemLimit,
}

/// A step of a pass: finished or not and the yield counts used, or the error and the yield
/// counts used before it.
pub type IolistProgress = Result<(bool, usize), (IolistError, usize)>;

/// `generic_iolist_size` state: `IOListSizeState`'s cursor, `estack` and size.
// Port of erts/emulator/beam/erl_iolist.c (generic_iolist_size), OTP-29.1.1.
pub struct IolistSizeWalk {
    current: Term,
    tails: EStack<8>,
    size: usize,
    unit: usize,
    overflowed: bool,
}

impl IolistSizeWalk {
    /// Start traversing an iolist rooted in a stable process heap.
    pub fn new(root: Term) -> Self {
        Self {
            current: root,
            tails: EStack::new(),
            size: 0,
            unit: 8,
            overflowed: false,
        }
    }

    /// Start a walk that accepts bitstrings of any size, for `list_to_bitstring/1`.
    pub fn new_bits(root: Term) -> Self {
        Self {
            unit: 1,
            ..Self::new(root)
        }
    }

    /// Whether this walk was started by `new_bits`.
    pub fn is_bits(&self) -> bool {
        self.unit == 1
    }

    /// The accumulated bit count after a complete traversal.
    pub fn take_bits(&mut self) -> usize {
        std::mem::take(&mut self.size)
    }

    /// The accumulated byte count after a complete traversal.
    pub fn take_size(&mut self) -> usize {
        std::mem::take(&mut self.size) / 8
    }

    /// After `SystemLimit` from [`Self::step`]: whether it was `ERTS_IOLIST_OVERFLOW`; if so the
    /// bytes counted so far, restarting the count at zero.
    pub fn take_overflow(&mut self) -> Option<usize> {
        if !std::mem::take(&mut self.overflowed) {
            return None;
        }
        Some(std::mem::take(&mut self.size) / 8)
    }

    /// Count at most `budget - 1` yield counts of list cells and leaves.
    // Port of erts/emulator/beam/erl_iolist.c (generic_iolist_size), OTP-29.1.1: the cursor and
    // the accumulator are locals stored back only when the walk yields or finishes.
    #[inline]
    pub fn step(&mut self, budget: usize) -> IolistProgress {
        let mut consumed = 0;
        let mut current = self.current;
        let mut size = self.size;
        loop {
            while let Ok(cons) = Cons::try_from(current) {
                if consumed + 1 >= budget {
                    self.current = current;
                    self.size = size;
                    return Ok((false, budget));
                }
                consumed += 1;
                let (head, tail) = cons.pair();
                // Bytes first, then sublists, as erts.
                if let Some(byte) = head.as_small() {
                    if !(0..=255).contains(&byte) {
                        return Err((IolistError::BadArg, consumed));
                    }
                    let Some(sum) = size.checked_add(8) else {
                        return Err(self.overflow(current, size, consumed));
                    };
                    size = sum;
                    current = tail;
                    continue;
                }
                if Cons::try_from(head).is_ok() {
                    self.tails.push(tail);
                    current = head;
                    continue;
                }
                size = match leaf_size(self.unit, size, head, true) {
                    Ok(size) => size,
                    Err(IolistError::SystemLimit) => {
                        return Err(self.overflow(current, size, consumed));
                    }
                    Err(error) => return Err((error, consumed)),
                };
                current = tail;
            }

            if consumed + 1 >= budget {
                self.current = current;
                self.size = size;
                return Ok((false, budget));
            }
            consumed += 1;
            size = match leaf_size(self.unit, size, current, false) {
                Ok(size) => size,
                Err(IolistError::SystemLimit) => {
                    return Err(self.overflow(current, size, consumed));
                }
                Err(error) => return Err((error, consumed)),
            };
            match self.tails.pop() {
                Some(tail) => current = tail,
                None => {
                    self.current = current;
                    self.size = size;
                    return Ok((true, consumed));
                }
            }
        }
    }

    /// `L_overflow`: stop at the element whose size does not fit the word, keeping the cursor
    /// on it, so the caller can accumulate `size` and resume.
    fn overflow(&mut self, current: Term, size: usize, consumed: usize) -> (IolistError, usize) {
        self.current = current;
        self.size = size;
        self.overflowed = true;
        (IolistError::SystemLimit, consumed)
    }
}

/// The size of one leaf of the list: `[]`, a bitstring whose size is a multiple of `unit`, or
/// (as an element, not a tail) a byte.
#[inline(always)]
fn leaf_size(
    unit: usize,
    size: usize,
    term: Term,
    byte_allowed: bool,
) -> Result<usize, IolistError> {
    if let Ok(bin) = BinRef::try_from(term) {
        let bits = bin.bit_len();
        if !bits.is_multiple_of(unit) {
            return Err(IolistError::BadArg);
        }
        return size.checked_add(bits).ok_or(IolistError::SystemLimit);
    }
    if term == Term::NIL {
        return Ok(size);
    }
    if byte_allowed && term.as_small().is_some_and(|n| (0..=255).contains(&n)) {
        return size.checked_add(8).ok_or(IolistError::SystemLimit);
    }
    Err(IolistError::BadArg)
}

/// `generic_iolist_copy` state: the cursor, the pending binary leaf and the output offset.
// Port of erts/emulator/beam/erl_iolist.c (generic_iolist_copy), OTP-29.1.1.
pub struct IolistCopyWalk {
    current: Term,
    tails: EStack<8>,
    source: Option<CopySource>,
    offset: usize,
    done_after_source: bool,
    bit_mode: bool,
    to_bit: usize,
}

/// A binary leaf copied in several yields.
struct CopySource {
    term: Term,
    bit_offset: usize,
    remaining_bits: usize,
}

/// Bits one yield count buys in the copy pass.
const COPY_BITS_PER_YIELD: usize = 32 * 8;

impl IolistCopyWalk {
    /// Start copying a validated iolist into its final binary allocation.
    pub fn new(root: Term) -> Self {
        Self {
            current: root,
            tails: EStack::new(),
            source: None,
            offset: 0,
            done_after_source: false,
            bit_mode: false,
            to_bit: 0,
        }
    }

    /// Start copying into a bit-addressed output, for `list_to_bitstring/1` (unit 1).
    pub fn new_bits(root: Term) -> Self {
        Self {
            bit_mode: true,
            ..Self::new(root)
        }
    }

    /// Bits written after the walk has completed.
    pub fn written_bits(&self) -> usize {
        if self.bit_mode {
            self.to_bit
        } else {
            self.offset * 8
        }
    }

    /// Write one byte of the list at the output cursor.
    #[inline(always)]
    fn put_byte(
        &mut self,
        output: &mut [u8],
        offset: &mut usize,
        byte: u8,
    ) -> Result<(), IolistError> {
        if self.bit_mode {
            or_bits_at(output, self.to_bit, &[byte], 8)?;
            self.to_bit += 8;
        } else {
            *output.get_mut(*offset).ok_or(IolistError::SystemLimit)? = byte;
            *offset += 1;
        }
        Ok(())
    }

    /// Copy up to the yield budget of the binary `bin` from `bit_offset`; whether it was done.
    #[inline(always)]
    fn copy_binary(
        &mut self,
        output: &mut [u8],
        bin: BinRef<'_>,
        bit_offset: usize,
        remaining_bits: usize,
        remaining: usize,
    ) -> Result<usize, IolistError> {
        let copy_limit = remaining
            .saturating_add(1)
            .saturating_mul(COPY_BITS_PER_YIELD);
        let copy_bits = remaining_bits.min(copy_limit);
        let source_start = bin
            .start_bit()
            .checked_add(bit_offset)
            .ok_or(IolistError::SystemLimit)?;
        let window = bin.window();
        if self.bit_mode {
            let mut staged = vec![0_u8; copy_bits.div_ceil(8)];
            copy_bits_out(window, source_start, &mut staged, copy_bits);
            or_bits_at(output, self.to_bit, &staged, copy_bits)?;
            self.to_bit += copy_bits;
        } else {
            let end = self
                .offset
                .checked_add(copy_bits / 8)
                .filter(|end| *end <= output.len())
                .ok_or(IolistError::SystemLimit)?;
            if source_start.is_multiple_of(8) && copy_bits.is_multiple_of(8) {
                let from = source_start / 8;
                output[self.offset..end].copy_from_slice(
                    window
                        .get(from..from + copy_bits / 8)
                        .ok_or(IolistError::BadArg)?,
                );
            } else {
                copy_bits_out(
                    window,
                    source_start,
                    &mut output[self.offset..end],
                    copy_bits,
                );
            }
            self.offset = end;
        }
        Ok(copy_bits)
    }

    /// Start copying the binary leaf `leaf`; the bits copied when it went whole.
    #[inline(always)]
    fn start_leaf(
        &mut self,
        output: &mut [u8],
        leaf: Term,
        remaining: usize,
    ) -> Result<Option<usize>, IolistError> {
        let bin = BinRef::try_from(leaf).map_err(|_| IolistError::BadArg)?;
        let bits = bin.bit_len();
        if !self.bit_mode && !bits.is_multiple_of(8) {
            return Err(IolistError::BadArg);
        }
        let copied = self.copy_binary(output, bin, 0, bits, remaining)?;
        if copied == bits {
            return Ok(Some(bits));
        }
        self.source = Some(CopySource {
            term: leaf,
            bit_offset: copied,
            remaining_bits: bits - copied,
        });
        Ok(None)
    }

    /// Copy at most `yield_count` iolist units into `output`.
    // Port of erts/emulator/beam/erl_iolist.c (generic_iolist_copy), OTP-29.1.1.
    #[inline]
    pub fn step(&mut self, output: &mut [u8], yield_count: usize) -> IolistProgress {
        let mut remaining = yield_count;
        loop {
            if let Some(source) = self.source.take() {
                let bin = BinRef::try_from(source.term)
                    .map_err(|_| (IolistError::BadArg, yield_count - remaining))?;
                let copied = self
                    .copy_binary(
                        output,
                        bin,
                        source.bit_offset,
                        source.remaining_bits,
                        remaining,
                    )
                    .map_err(|error| (error, yield_count - remaining))?;
                if copied != source.remaining_bits {
                    self.source = Some(CopySource {
                        term: source.term,
                        bit_offset: source.bit_offset + copied,
                        remaining_bits: source.remaining_bits - copied,
                    });
                    return Ok((false, yield_count));
                }
                if self.done_after_source {
                    return Ok((true, yield_count - remaining));
                }
                remaining = remaining.saturating_sub(copied / COPY_BITS_PER_YIELD);
                continue;
            }

            let mut current = self.current;
            let mut offset = self.offset;
            while let Ok(cons) = Cons::try_from(current) {
                if remaining <= 1 {
                    self.current = current;
                    self.offset = offset;
                    return Ok((false, yield_count));
                }
                remaining -= 1;
                let (head, tail) = cons.pair();
                if let Some(number) = head.as_small() {
                    let byte = u8::try_from(number)
                        .map_err(|_| (IolistError::BadArg, yield_count - remaining))?;
                    self.put_byte(output, &mut offset, byte)
                        .map_err(|error| (error, yield_count - remaining))?;
                    current = tail;
                    continue;
                }
                if Cons::try_from(head).is_ok() {
                    self.tails.push(tail);
                    current = head;
                    continue;
                }
                current = tail;
                if head == Term::NIL {
                    continue;
                }
                // The leaf is a bitstring; its bytes go at the cursor, which the copy reads from
                // the walk.
                self.offset = offset;
                let whole = self
                    .start_leaf(output, head, remaining)
                    .map_err(|error| (error, yield_count - remaining))?;
                offset = self.offset;
                match whole {
                    Some(bits) => remaining = remaining.saturating_sub(bits / COPY_BITS_PER_YIELD),
                    None => break,
                }
            }
            self.current = current;
            self.offset = offset;

            if self.source.is_some() {
                continue;
            }
            if remaining <= 1 {
                return Ok((false, yield_count));
            }
            remaining -= 1;
            // The tail of the list: `[]` or a bitstring.
            if self.current != Term::NIL {
                let leaf = self.current;
                let whole = self
                    .start_leaf(output, leaf, remaining)
                    .map_err(|error| (error, yield_count - remaining))?;
                match whole {
                    Some(bits) => remaining = remaining.saturating_sub(bits / COPY_BITS_PER_YIELD),
                    None => self.done_after_source = self.tails.is_empty(),
                }
            }
            match self.tails.pop() {
                Some(tail) => self.current = tail,
                None if self.source.is_none() => return Ok((true, yield_count - remaining)),
                None => self.current = Term::NIL,
            }
        }
    }
}

/// Copy `bit_count` bits from `source` at bit `start` into zeroed `output`, most significant bit
/// first.
// Port of erts/emulator/beam/erl_bits.c (erts_copy_bits_fwd), OTP-29.1.1.
fn copy_bits_out(source: &[u8], start: usize, output: &mut [u8], bit_count: usize) {
    output.fill(0);
    for index in 0..bit_count {
        let at = start + index;
        let bit = (source[at / 8] >> (7 - at % 8)) & 1;
        output[index / 8] |= bit << (7 - index % 8);
    }
}

/// OR the first `bits` bits of `source` into zeroed `output` starting at bit `to_bit`.
fn or_bits_at(
    output: &mut [u8],
    to_bit: usize,
    source: &[u8],
    bits: usize,
) -> Result<(), IolistError> {
    if to_bit
        .checked_add(bits)
        .is_none_or(|end| end > output.len().saturating_mul(8))
    {
        return Err(IolistError::SystemLimit);
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
