//! Raw heap word access for the collector: the one place where `crates/term` code that
//! moves objects dereferences a heap address. Callers pass addresses, never references, and
//! uphold the contract of each primitive.
//!
//! The second half of the file is the typed accessor set for validated terms ([`Cons`],
//! [`Tuple`], [`boxed_header`]); it is public so that BIF loops outside this crate can walk
//! lists and tuples with erts-shaped code while staying in safe Rust.

use crate::{ARITY, EMPTY_TUPLE, HeapAlloc, Term, TermError};

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
// Lazy signal nodes (`message::OwnedSignal::lazy`): the queue header of a signal node
// overlaid on another structure, and the reads of a signal node that has no value yet.

use crate::message::SignalNode;
use std::ptr::NonNull;

/// The queue header of a lazy node (`ErtsSignalCommon`): `next`, a marker where
/// `fragment_words` sits, and the function that makes the signal value, where `value` sits.
#[repr(C)]
struct LazyHeader<T> {
    next: Option<NonNull<SignalNode<T>>>,
    marker: usize,
    materialise: unsafe fn(NonNull<u8>) -> T,
}

/// Bytes of a lazy node's header.
pub(crate) const LAZY_HEADER_BYTES: usize = std::mem::size_of::<LazyHeader<()>>();

const _: () = assert!(std::mem::offset_of!(SignalNode<()>, next) == 0);

/// Writes a lazy node header at `header`.
///
/// Contract: `header` is word aligned and addresses [`LAZY_HEADER_BYTES`] bytes that nothing
/// else uses until the node is taken out of its queue.
#[inline(always)]
pub(crate) fn lazy_header_write<T>(
    header: NonNull<u8>,
    marker: usize,
    materialise: unsafe fn(NonNull<u8>) -> T,
) {
    // SAFETY: the contract above.
    unsafe {
        header.cast::<LazyHeader<T>>().as_ptr().write(LazyHeader {
            next: None,
            marker,
            materialise,
        });
    }
}

/// The second word of a signal node: `fragment_words`, or the marker of a lazy node.
///
/// Contract: `node` is a live signal node of an owned handle or a queue.
#[inline(always)]
pub(crate) fn node_marker(node: NonNull<u8>) -> usize {
    load(node.as_ptr() as usize + std::mem::size_of::<usize>()) as usize
}

/// Calls the function of a lazy node to make its value.
///
/// Contract: `node` is a lazy node whose header was written by [`lazy_header_write`] for `T`;
/// its owner does not use it afterwards.
#[inline(always)]
pub(crate) fn lazy_make<T>(node: NonNull<u8>) -> T {
    // SAFETY: the contract above; the function is valid once for this node.
    unsafe {
        let make = (*node.cast::<LazyHeader<T>>().as_ptr()).materialise;
        make(node)
    }
}

/// The value of a node that has one.
///
/// Contract: `node` is a live, non-lazy node, not written while the reference is in use.
#[inline(always)]
pub(crate) fn node_value<'a, T>(node: NonNull<SignalNode<T>>) -> &'a T {
    // SAFETY: the contract above.
    unsafe { &(*node.as_ptr()).value }
}

/// [`node_value`], mutably; the caller has exclusive use of the node.
#[inline(always)]
pub(crate) fn node_value_mut<'a, T>(node: NonNull<SignalNode<T>>) -> &'a mut T {
    // SAFETY: the contract above.
    unsafe { &mut (*node.as_ptr()).value }
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

/// A proper list whose length and terminator were checked in one pass.
#[derive(Clone, Copy)]
pub struct ProperList<'h> {
    term: Term,
    len: usize,
    heap: PhantomData<&'h ()>,
}

impl TryFrom<Term> for ProperList<'_> {
    type Error = WrongShape;

    /// Checks every cons tag and the final `[]`, like `erts_list_length`.
    // Port of erts/emulator/beam/utils.c:345-354 (erts_list_length), OTP-29.1.1.
    #[inline(always)]
    fn try_from(term: Term) -> Result<Self, WrongShape> {
        let len = proper_list_len(term);
        if len < 0 {
            return Err(WrongShape);
        }
        Ok(Self {
            term,
            len: len as usize,
            heap: PhantomData,
        })
    }
}

#[inline(never)]
fn proper_list_len(mut current: Term) -> isize {
    let mut len = 0isize;
    while current.0 & 2 == 0 {
        len = len.wrapping_add(1);
        current = Term(read_tagged(current.0, 7));
    }
    if current == Term::NIL { len } else { -1 }
}

impl ProperList<'_> {
    /// Number of cons cells.
    #[inline(always)]
    pub fn len(self) -> usize {
        self.len
    }

    /// Whether the list is empty.
    #[inline(always)]
    pub fn is_empty(self) -> bool {
        self.len == 0
    }

    /// Copies the validated list into a tuple using its list terminator as the loop condition.
    ///
    /// The list's heap area must remain live and unmoved through the allocation and copy.
    // Port of erts/emulator/beam/bif.c:3789-3808 (list_to_tuple_1), OTP-29.1.1.
    #[inline(always)]
    pub fn to_tuple<H: HeapAlloc + ?Sized>(self, heap: &mut H) -> Result<Term, TermError> {
        if self.len == 0 {
            return Ok(Term::from_ptr((&EMPTY_TUPLE as *const u64).cast_mut(), 2));
        }
        if self.len > (1 << 24) - 1 {
            return Err(TermError::SystemLimit);
        }
        let start = heap.alloc(self.len + 1).ok_or(TermError::HeapFull)?;
        store(start as usize, (self.len as u64) << 6 | ARITY);
        let mut source = self.term;
        let mut dst = start.wrapping_add(1) as usize;
        // The proof guarantees every value in this chain is a list cell or the final nil;
        // erts tests only the list tag bit in its copy loop.
        while source.0 & 2 == 0 {
            store(dst, read_tagged(source.0, -1));
            dst = dst.wrapping_add(8);
            source = Term(read_tagged(source.0, 7));
        }
        debug_assert_eq!(source, Term::NIL);
        Ok(Term::from_ptr(start, 2))
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

/// A validated two-tuple whose pair can be loaded without another header or arity test.
///
/// Port of `tuple_val`/`arityval` followed by tuple element reads in
/// erts/emulator/beam/erl_map.c:367-472, OTP-29.1.1.
#[derive(Clone, Copy)]
pub struct Tuple2<'h> {
    word: u64,
    heap: PhantomData<&'h ()>,
}

impl TryFrom<Term> for Tuple2<'_> {
    type Error = WrongShape;

    /// Checks the boxed tuple header and arity once.
    #[inline(always)]
    fn try_from(term: Term) -> Result<Self, WrongShape> {
        let tuple = Tuple::try_from(term)?;
        if tuple.arity() != 2 {
            return Err(WrongShape);
        }
        Ok(Tuple2 {
            word: tuple.word,
            heap: PhantomData,
        })
    }
}

impl Tuple2<'_> {
    /// The validated tuple term.
    #[inline(always)]
    pub fn term(self) -> Term {
        Term(self.word)
    }

    /// Loads the first two tuple elements without further tag, header, or arity checks.
    #[inline(always)]
    pub fn pair(self) -> (Term, Term) {
        (
            Term(read_tagged(self.word, 6)),
            Term(read_tagged(self.word, 14)),
        )
    }
}

/// Incremental shape validation for a proper list of two-tuples.
///
/// The caller keeps the source heap live and unmoved while validation and the resulting
/// [`ValidatedMapList`] are in use.
///
/// Port of `maps_from_list_1_helper` in erts/emulator/beam/erl_map.c:321-366, OTP-29.1.1.
pub struct MapListValidator<'h> {
    root: Term,
    cursor: Term,
    pending: Option<Cons<'h>>,
    heap: PhantomData<&'h ()>,
}

impl<'h> MapListValidator<'h> {
    /// Start validating `maps:from_list/1` input.
    #[inline(always)]
    pub fn new(list: Term) -> Self {
        Self {
            root: list,
            cursor: list,
            pending: None,
            heap: PhantomData,
        }
    }

    /// The current cons cell, or `None` at nil; an improper tail is an error.
    ///
    /// Port of the `is_list` validation in `maps_from_list_1_helper`, OTP-29.1.1.
    #[inline(always)]
    pub fn current(&mut self) -> Result<Option<Cons<'h>>, WrongShape> {
        if let Some(cons) = self.pending {
            return Ok(Some(cons));
        }
        if self.cursor == Term::NIL {
            Ok(None)
        } else {
            let cons = Cons::try_from(self.cursor)?;
            self.pending = Some(cons);
            Ok(Some(cons))
        }
    }

    /// Validate the current cell's head as a two-tuple and advance the list cursor.
    ///
    /// Port of the tuple validation in `maps_from_list_1_helper`, OTP-29.1.1.
    #[inline(always)]
    pub fn advance(&mut self) -> Result<(), WrongShape> {
        let cons = self.pending.take().ok_or(WrongShape)?;
        let _tuple = Tuple2::try_from(cons.head())?;
        self.cursor = cons.tail();
        Ok(())
    }

    /// Finish after the cursor reaches nil.
    ///
    /// Port of the validated-list handoff to `flatmap_from_validated_list`, OTP-29.1.1.
    #[inline(always)]
    pub fn finish(self) -> Result<ValidatedMapList<'h>, WrongShape> {
        if self.cursor != Term::NIL || self.pending.is_some() {
            return Err(WrongShape);
        }
        Ok(ValidatedMapList {
            root: self.root,
            heap: PhantomData,
        })
    }
}

/// A proper list whose every head has already been validated as a two-tuple.
#[derive(Clone, Copy)]
pub struct ValidatedMapList<'h> {
    root: Term,
    heap: PhantomData<&'h ()>,
}

impl<'h> ValidatedMapList<'h> {
    /// Rewalk the validated list with erts-shaped CAR/CDR and tuple element loads.
    ///
    /// Port of the second pass in `flatmap_from_validated_list`, OTP-29.1.1.
    #[inline(always)]
    pub fn pairs(self) -> ValidatedMapPairs<'h> {
        ValidatedMapPairs {
            cursor: self.root,
            heap: PhantomData,
        }
    }
}

/// Iterator over a [`ValidatedMapList`], with no per-cell or per-tuple shape checks.
pub struct ValidatedMapPairs<'h> {
    cursor: Term,
    heap: PhantomData<&'h ()>,
}

impl Iterator for ValidatedMapPairs<'_> {
    type Item = (Term, Term);

    #[inline(always)]
    fn next(&mut self) -> Option<Self::Item> {
        if self.cursor == Term::NIL {
            return None;
        }
        let cons = Cons {
            word: self.cursor.0,
            heap: PhantomData,
        };
        let tuple = Tuple2 {
            word: cons.head().0,
            heap: PhantomData,
        };
        self.cursor = cons.tail();
        Some(tuple.pair())
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (0, None)
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
