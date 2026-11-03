//! Raw heap word access for the collector: the one place where `crates/term` code that
//! moves objects dereferences a heap address. Callers pass addresses, never references, and
//! uphold the contract of each primitive.
//!
//! The second half of the file is the typed accessor set for validated terms ([`Cons`],
//! [`Tuple`], [`boxed_header`]); it is public so that BIF loops outside this crate can walk
//! lists and tuples with erts-shaped code while staying in safe Rust.

use crate::{ARITY, Term};

/// Reads the word at `address`.
///
/// Contract: `address` is word-aligned and names an initialized word of a live heap block,
/// heap fragment or reserved destination that the calling collection owns.
#[inline(always)]
pub(crate) fn load(address: usize) -> u64 {
    // SAFETY: the contract above; the collector has exclusive access to the process heap.
    unsafe { *(address as *const u64) }
}

/// Writes `value` to the word at `address`.
///
/// Contract: `address` is word-aligned and inside a live heap block, heap fragment or
/// destination range the calling collection owns exclusively, with no live Rust reference
/// to the word.
#[inline(always)]
pub(crate) fn store(address: usize, value: u64) {
    // SAFETY: the contract above.
    unsafe { *(address as *mut u64) = value }
}

/// Copies `words` words from `src` to `dst`.
///
/// Contract: both ranges are word-aligned, inside owned live blocks, readable respectively
/// writable for `words` words, and do not overlap.
#[inline(always)]
pub(crate) fn copy_words(src: usize, dst: usize, words: usize) {
    // SAFETY: the contract above.
    unsafe { std::ptr::copy_nonoverlapping(src as *const u64, dst as *mut u64, words) }
}

/// Words of the boxed object with header `header` at `address` (header word included).
///
/// Contract: `address` names a live boxed object of an owned heap block or fragment with
/// its complete payload initialized (see `hamt::boxed_object_words`).
#[inline(always)]
pub(crate) fn boxed_words(header: u64, address: usize) -> usize {
    // SAFETY: the contract above.
    unsafe { crate::hamt::boxed_object_words(header, address as *const u64) }
}

// ---------------------------------------------------------------------------------------
// View types for validated terms (plan step 7.A U4, "term kernel"). A view is constructed
// only by a checked test (`Cons::try_from(term)`, `Tuple::try_from(term)`, ...) and is then
// the proof that the term has that shape; its accessors read the heap with no further test,
// like the erts macros list_val/CAR/CDR/tuple_val/arityval. The tag is folded into the load
// offset (`ldur x, [term, #-1]`), so a list walk has no pointer-masking step in its
// dependent chain.
//
// Lifetime `'h` is the lifetime of the heap area the term lives in. A `TryFrom<Term>` cannot
// borrow, so `'h` is chosen by the caller (inferred); the callers' contract is the one every
// checked `Term` accessor already relies on: the term was produced by the runtime
// (`TermBuilder`, a heap reservation, the loader) and its heap area is live and neither moved
// nor freed (no GC, no heap fragment release) while a view is used.
// ---------------------------------------------------------------------------------------

use std::marker::PhantomData;

/// Reads the word at byte distance `offset` from the tagged term word `word`.
///
/// Contract: `word + offset` is the address of an initialized word of a live heap object
/// (see the section comment).
#[inline(always)]
fn read_tagged(word: u64, offset: i64) -> u64 {
    // SAFETY: the contract above; the offset folds the primary tag, so the address is the
    // 8-aligned object address plus a whole number of words.
    unsafe { *(word.wrapping_add_signed(offset) as *const u64) }
}

/// The checked test failed: the term does not have the requested shape.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WrongShape;

/// A list cell: a pointer to two adjacent words, head then tail.
///
/// Port of erts/emulator/beam/erl_term.h (`is_list`, `list_val`, `CAR`, `CDR`), OTP-29.1.1.
#[derive(Clone, Copy)]
pub struct Cons<'h> {
    word: u64,
    heap: PhantomData<&'h ()>,
}

impl TryFrom<Term> for Cons<'_> {
    type Error = WrongShape;

    /// `is_list(term)`; `[]` is not a cell.
    #[inline(always)]
    fn try_from(term: Term) -> Result<Self, WrongShape> {
        if term.0 & 3 == 1 {
            Ok(Cons {
                word: term.0,
                heap: PhantomData,
            })
        } else {
            Err(WrongShape)
        }
    }
}

impl Cons<'_> {
    /// The list term of this cell.
    #[inline(always)]
    pub fn term(self) -> Term {
        Term(self.word)
    }

    /// `CAR(list_val(term))`.
    #[inline(always)]
    pub fn head(self) -> Term {
        Term(read_tagged(self.word, -1))
    }

    /// `CDR(list_val(term))`.
    #[inline(always)]
    pub fn tail(self) -> Term {
        Term(read_tagged(self.word, 7))
    }

    /// Both words.
    #[inline(always)]
    pub fn pair(self) -> (Term, Term) {
        (self.head(), self.tail())
    }
}

/// A tuple: a boxed term whose header is an arity word.
///
/// Port of erts/emulator/beam/erl_term.h (`is_tuple`, `tuple_val`, `arityval`), OTP-29.1.1.
#[derive(Clone, Copy)]
pub struct Tuple<'h> {
    word: u64,
    arity: usize,
    heap: PhantomData<&'h ()>,
}

impl TryFrom<Term> for Tuple<'_> {
    type Error = WrongShape;

    /// `is_tuple(term)`. Reads the header once; the arity is cached in the view.
    #[inline(always)]
    fn try_from(term: Term) -> Result<Self, WrongShape> {
        if term.0 & 3 != 2 {
            return Err(WrongShape);
        }
        let header = read_tagged(term.0, -2);
        if header & 63 != ARITY {
            return Err(WrongShape);
        }
        Ok(Tuple {
            word: term.0,
            arity: (header >> 6) as usize,
            heap: PhantomData,
        })
    }
}

impl Tuple<'_> {
    /// `arityval(*tuple_val(term))`.
    #[inline(always)]
    pub fn arity(self) -> usize {
        self.arity
    }

    /// The tuple term.
    #[inline(always)]
    pub fn term(self) -> Term {
        Term(self.word)
    }

    /// Element `index` (zero based), `None` past the arity.
    #[inline(always)]
    pub fn get(self, index: usize) -> Option<Term> {
        (index < self.arity).then(|| Term(read_tagged(self.word, 6 + 8 * index as i64)))
    }

    /// Elements in order: one cursor and one end address, no per-element index check.
    #[inline(always)]
    pub fn elements(self) -> TupleElements {
        TupleElements {
            at: self.word.wrapping_add(6),
            end: self.word.wrapping_add(6 + 8 * self.arity as u64),
        }
    }
}

/// Element cursor of a [`Tuple`].
#[derive(Clone, Copy)]
pub struct TupleElements {
    at: u64,
    end: u64,
}

impl Iterator for TupleElements {
    type Item = Term;

    #[inline(always)]
    fn next(&mut self) -> Option<Term> {
        if self.at == self.end {
            return None;
        }
        // SAFETY: `at` walks the element words of a tuple proven by `Tuple::try_from`, below
        // `end`; the view's heap contract keeps them live.
        let word = unsafe { *(self.at as *const u64) };
        self.at = self.at.wrapping_add(8);
        Some(Term(word))
    }
}

/// A bit string (heap binary, refc binary reference or sub-binary) with its byte window.
///
/// Port of erts/emulator/beam/erl_bits.h (`ERTS_GET_BITSTRING_REF`), OTP-29.1.1.
#[derive(Clone, Copy)]
pub struct BinRef<'h> {
    bytes: &'h [u8],
    start_bit: usize,
    bit_len: usize,
}

impl TryFrom<Term> for BinRef<'_> {
    type Error = WrongShape;

    /// `is_bitstring(term)`.
    #[inline(always)]
    fn try_from(term: Term) -> Result<Self, WrongShape> {
        // SAFETY: the view contract of this section: the binary and its owner stay live and
        // no writable append runs while the view is used.
        let view = unsafe { term.binary_ref() }.ok_or(WrongShape)?;
        Ok(BinRef {
            bytes: view.bytes(),
            start_bit: view.start_bit(),
            bit_len: view.bit_len(),
        })
    }
}

impl<'h> BinRef<'h> {
    /// Size in bits.
    #[inline(always)]
    pub fn bit_len(self) -> usize {
        self.bit_len
    }

    /// Offset of the first bit inside the backing bytes.
    #[inline(always)]
    pub fn start_bit(self) -> usize {
        self.start_bit
    }

    /// The whole backing byte window of the binary.
    #[inline(always)]
    pub fn window(self) -> &'h [u8] {
        self.bytes
    }

    /// The payload bytes when the binary is byte aligned and a whole number of bytes.
    #[inline(always)]
    pub fn bytes(self) -> Option<&'h [u8]> {
        if !self.start_bit.is_multiple_of(8) || !self.bit_len.is_multiple_of(8) {
            return None;
        }
        let from = self.start_bit / 8;
        self.bytes.get(from..from + self.bit_len / 8)
    }
}

/// A flatmap: size, keys tuple and value array. Hash-array-mapped nodes are not viewed here.
#[derive(Clone, Copy)]
pub struct MapRef<'h> {
    keys: &'h [u64],
    values: &'h [u64],
}

impl TryFrom<Term> for MapRef<'_> {
    type Error = WrongShape;

    /// `is_flatmap(term)`.
    #[inline(always)]
    fn try_from(term: Term) -> Result<Self, WrongShape> {
        // SAFETY: the view contract of this section.
        let flat = unsafe { term.flatmap_ref() }.ok_or(WrongShape)?;
        let (keys, values) = flat.arrays();
        Ok(MapRef { keys, values })
    }
}

impl MapRef<'_> {
    /// `MAP_SZ`.
    #[inline(always)]
    pub fn len(self) -> usize {
        self.keys.len()
    }

    /// Whether the map has no pairs.
    #[inline(always)]
    pub fn is_empty(self) -> bool {
        self.keys.is_empty()
    }

    /// Pair `index` in stored key order.
    #[inline(always)]
    pub fn pair(self, index: usize) -> Option<(Term, Term)> {
        Some((Term(*self.keys.get(index)?), Term(*self.values.get(index)?)))
    }
}

/// The header word of a boxed term (`*boxed_val(term)`), `None` for other primary tags.
///
/// Port of erts/emulator/beam/erl_term.h (`is_boxed`, `boxed_val`), OTP-29.1.1.
#[inline(always)]
pub fn boxed_header(term: Term) -> Option<u64> {
    (term.0 & 3 == 2).then(|| read_tagged(term.0, -2))
}

/// The tagged term for word `index` of `words` (a pointer into a reserved block).
///
/// `tag` is the primary tag: 1 list, 2 boxed. Panics when `index` is outside `words`, so the
/// returned pointer always names a word of the slice.
#[inline(always)]
pub fn term_at(words: &[u64], index: usize, tag: u64) -> Term {
    assert!(index < words.len() && tag < 4);
    Term((words.as_ptr() as u64).wrapping_add(8 * index as u64) | tag)
}
