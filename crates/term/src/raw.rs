//! Raw heap word access for the collector: the one place where `crates/term` code that
//! moves objects dereferences a heap address. Callers pass addresses, never references, and
//! uphold the contract of each primitive.
//!
//! The second half of the file is the typed accessor set for validated terms ([`Cons`],
//! [`Tuple`], [`boxed_header`]); it is public so that BIF loops outside this crate can walk
//! lists and tuples with erts-shaped code while staying in safe Rust.

use crate::{ARITY, BIN_REF, HeapAlloc, SUB_BITS, Term, TermError};
use arinsal_alloc::raw::BinaryView;
use std::mem::MaybeUninit;
use std::num::NonZeroUsize;

/// Rebuilds a term from its tagged word after it has been held by the ETF work stack.
///
/// # Safety contract
/// `bits` must come from [`Term::word`] for a live term in the same encode walk. The walk must
/// not run GC or release a heap fragment between saving and restoring the word.
#[inline(always)]
pub fn term_from_bits(bits: u64) -> Term {
    // SAFETY: callers only restore tagged words previously obtained from a live `Term` in
    // the same walk, which keeps the owning heap stable until the word is consumed.
    unsafe { Term::from_raw_bits(bits) }
}

/// `ERTS_GET_BITSTRING_REF` of a BIF argument: the bytes of a bitstring term.
///
/// Contract: `term` is a BIF argument (or a term reachable from one) of the running process;
/// its heap and off-heap owner stay live for the call, and the caller runs no writable append
/// on that owner while the view is held.
// Port of erts/emulator/beam/erl_bits.h (ERTS_GET_BITSTRING_REF), OTP-29.1.1.
#[inline(always)]
pub fn bif_arg_binary_ref<'a>(term: Term) -> Option<crate::BinaryRef<'a>> {
    // SAFETY: the contract above.
    unsafe { term.binary_ref() }
}

/// Fixed-capacity stack storage for terms whose populated prefix is known at runtime.
///
/// The backing array has no capacity field and does not initialize unused slots.
pub struct UninitTermArray<const N: usize> {
    words: [MaybeUninit<Term>; N],
    len: usize,
}

impl<const N: usize> UninitTermArray<N> {
    /// Creates empty storage without initializing its term slots.
    #[inline(always)]
    pub fn new() -> Self {
        // SAFETY: an array of `MaybeUninit<Term>` is valid with every slot uninitialized.
        let words = unsafe { MaybeUninit::<[MaybeUninit<Term>; N]>::uninit().assume_init() };
        Self { words, len: 0 }
    }

    /// Fills `count` slots from a callback, checking the fixed bound once.
    #[inline(always)]
    pub fn fill_with(&mut self, count: usize, mut next: impl FnMut() -> Option<Term>) -> bool {
        assert!(count <= N - self.len);
        for _ in 0..count {
            let Some(value) = next() else {
                return false;
            };
            // SAFETY: the upfront count check bounds every slot written in this loop.
            unsafe { self.words.get_unchecked_mut(self.len).write(value) };
            self.len += 1;
        }
        true
    }

    /// Returns a copied term from the populated prefix.
    #[inline(always)]
    pub fn get(&self, index: usize) -> Term {
        assert!(index < self.len);
        // SAFETY: `push` initializes every slot below `len`, and `index < len`.
        unsafe { self.words[index].assume_init_read() }
    }

    /// Replaces one initialized term in the populated prefix.
    #[inline(always)]
    pub fn set(&mut self, index: usize, value: Term) {
        assert!(index < self.len);
        self.words[index].write(value);
    }

    /// Number of terms in the initialized prefix.
    #[inline(always)]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether the initialized prefix is empty.
    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns the initialized prefix as a slice.
    #[inline(always)]
    pub fn as_slice(&self) -> &[Term] {
        // SAFETY: `push` initializes every slot below `len`; the backing array is aligned
        // for `Term` and remains borrowed for the returned slice lifetime.
        unsafe { std::slice::from_raw_parts(self.words.as_ptr().cast::<Term>(), self.len) }
    }

    /// Removes one initialized entry while preserving the order of the remaining prefix.
    #[inline(always)]
    pub fn shift_down(&mut self, index: usize) {
        assert!(index < self.len);
        // SAFETY: both ranges are within the initialized prefix and `ptr::copy` permits overlap.
        unsafe {
            std::ptr::copy(
                self.words.as_ptr().add(index + 1).cast::<Term>(),
                self.words.as_mut_ptr().add(index).cast::<Term>(),
                self.len - index - 1,
            );
        }
        self.len -= 1;
    }
}

impl<const N: usize> Default for UninitTermArray<N> {
    fn default() -> Self {
        Self::new()
    }
}

/// Reads the word at `address`.
///
/// Contract: `address` is word-aligned and names an initialized word in a live allocation,
/// heap fragment or reserved destination that the caller owns or may read immutably.
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

/// Sorts evaluated flatmap keys and their values in place, keeping the last duplicate.
///
/// The map and its key tuple must belong to the current exclusive heap allocation, as in
/// `matchMkFlatMap` immediately before OTP calls `erts_usort_flatmap`.
// Port of erts/emulator/beam/erl_map.c:3218-3252 (erts_usort_flatmap), OTP-29.1.1.
pub(crate) fn usort_flatmap_in_place(map: Term) {
    // SAFETY: the caller passes a newly allocated flatmap and its owned key tuple; the heap
    // remains exclusive while the match-spec instruction builds and normalizes the map.
    unsafe {
        let map_ptr = map.raw_ptr().cast_mut();
        let mut size = *map_ptr.add(1) as usize;
        let keys_term = Term(*map_ptr.add(2));
        let keys_ptr = keys_term.raw_ptr().cast_mut();
        let keys = keys_ptr.add(1).cast::<Term>();
        let values = map_ptr.add(3).cast::<Term>();
        let mut ix = 1;
        while ix < size {
            let mut jx = ix;
            while jx > 0 {
                let ordering = crate::heap::flat_key_cmp(*keys.add(jx), *keys.add(jx - 1));
                if ordering == std::cmp::Ordering::Greater {
                    break;
                }
                if ordering == std::cmp::Ordering::Equal {
                    std::ptr::copy(keys.add(jx), keys.add(jx - 1), size - ix);
                    std::ptr::copy(values.add(jx), values.add(jx - 1), size - ix);
                    size -= 1;
                    ix -= 1;
                    break;
                }
                std::ptr::swap(keys.add(jx), keys.add(jx - 1));
                std::ptr::swap(values.add(jx), values.add(jx - 1));
                jx -= 1;
            }
            ix += 1;
        }
        *map_ptr.add(1) = size as u64;
        *keys_ptr = ((size as u64) << 6) | ARITY;
    }
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

/// Validated raw view of one `SUB_BITS` heap object.
// Port of erts/emulator/beam/erl_bits.h (`ErlSubBits`), OTP-29.1.1.
#[derive(Clone, Copy)]
pub(crate) struct SubBitsRecord(usize);

impl SubBitsRecord {
    /// Resolve a live sub-bits term without retaining a Rust reference across mutation.
    #[inline(always)]
    pub(crate) fn from_term(term: Term) -> Option<Self> {
        if term.header()? & 63 != SUB_BITS {
            return None;
        }
        // SAFETY: the term header proves the five-word SUB_BITS layout and callers keep its
        // owning heap stable until this view is discarded.
        Some(Self(unsafe { term.raw_ptr() as usize }))
    }

    #[inline(always)]
    pub(crate) fn flags(self) -> u64 {
        load(self.0 + 8) & 3
    }

    #[inline(always)]
    pub(crate) fn original(self) -> Term {
        Term(load(self.0 + 32))
    }

    #[inline(always)]
    pub(crate) fn end(self) -> usize {
        load(self.0 + 24) as usize
    }

    #[inline(always)]
    pub(crate) fn set_flags(self, flags: u64) {
        store(self.0 + 8, flags);
    }

    #[inline(always)]
    pub(crate) fn address(self) -> usize {
        self.0
    }
}

/// Validated direct view of a process `BinRef` and its reference-counted `Binary`.
// Port of erts/emulator/beam/erl_binary.h (`BinRef`), OTP-29.1.1.
#[derive(Clone, Copy)]
pub(crate) struct BinRefRecord {
    address: usize,
    binary: BinaryView<'static>,
}

impl BinRefRecord {
    /// Resolve a `BinRef` without consulting the heap's owner registry.
    #[inline(always)]
    pub(crate) fn from_term(term: Term) -> Option<Self> {
        if term.header()? & 63 != BIN_REF {
            return None;
        }
        // SAFETY: the validated live BinRef keeps its Binary allocation alive; its value word
        // is stable while the process is not concurrently collecting or appending.
        unsafe {
            let address = term.raw_ptr() as usize;
            let value = load(address + 8);
            if crate::bits::bin_ref_val_is_external(value) {
                return None;
            }
            let header = value as *const u64;
            let capacity = load(header as usize + 24) as usize;
            let binary = BinaryView::from_header(header, 4 + capacity.div_ceil(8));
            Some(Self { address, binary })
        }
    }

    #[inline(always)]
    pub(crate) fn address(&self) -> usize {
        self.address
    }

    #[inline(always)]
    pub(crate) fn binary(&self) -> BinaryView<'static> {
        self.binary
    }
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
            return Ok(crate::global_empty_tuple());
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

    /// Address of element `index` for a tuple array task.
    #[inline(always)]
    pub fn element_pointer(self, index: usize) -> Option<u64> {
        (index < self.arity).then(|| self.word.wrapping_add(6 + 8 * index as u64))
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
    heap: PhantomData<&'h ()>,
}

/// A current validated-list cursor that can advance only its originating validator.
pub struct CurrentMapListCell<'v, 'h> {
    validator: &'v mut MapListValidator<'h>,
    cons: Cons<'h>,
}

impl CurrentMapListCell<'_, '_> {
    /// Validate this cell's head as a two-tuple and move its validator to the tail.
    ///
    /// Port of the tuple check and `CDR` advance in `maps_from_list_1_helper`, OTP-29.1.1.
    #[inline(always)]
    pub fn advance(self) -> Result<(), WrongShape> {
        let _tuple = Tuple2::try_from(self.cons.head())?;
        self.validator.cursor = self.cons.tail();
        Ok(())
    }
}

impl<'h> MapListValidator<'h> {
    /// Start validating `maps:from_list/1` input.
    #[inline(always)]
    pub fn new(list: Term) -> Self {
        Self {
            root: list,
            cursor: list,
            heap: PhantomData,
        }
    }

    /// The current cons cell, or `None` at nil; an improper tail is an error.
    ///
    /// Port of the `is_list` validation in `maps_from_list_1_helper`, OTP-29.1.1.
    #[inline(always)]
    pub fn current(&mut self) -> Result<Option<CurrentMapListCell<'_, 'h>>, WrongShape> {
        if self.cursor == Term::NIL {
            Ok(None)
        } else {
            Cons::try_from(self.cursor).map(|cons| {
                Some(CurrentMapListCell {
                    validator: self,
                    cons,
                })
            })
        }
    }

    /// Finish after the cursor reaches nil.
    ///
    /// Port of the validated-list handoff to `flatmap_from_validated_list`, OTP-29.1.1.
    #[inline(always)]
    pub fn finish(self) -> Result<ValidatedMapList<'h>, WrongShape> {
        if self.cursor != Term::NIL {
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

/// Reads a tuple element at an address produced by [`Tuple::element_pointer`].
///
/// The pointer must still refer to the same live tuple element. ETF encode walks retain
/// source terms and do not run GC while their WSTACK tasks are saved or restored.
#[inline(always)]
pub fn term_at_pointer(pointer: u64) -> Term {
    // SAFETY: callers only pass a pointer previously produced by a validated tuple view and
    // preserved in the same walk; no GC or heap-fragment release occurs during that walk.
    unsafe { Term::from_raw_bits(*(pointer as *const u64)) }
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

// Port of erts/emulator/beam/external.c (dec_term: the `next` pointer chain written into the
// words of the preallocated heap), OTP-29.1.1.
/// A slot address inside the heap reservation held by an active ETF decode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub struct HeapSlotPtr(NonZeroUsize);

impl HeapSlotPtr {
    /// Retain an in-range heap slot as an address for the decoder's `next` chain.
    #[inline(always)]
    pub fn at(words: &mut [u64], index: usize) -> Option<Self> {
        words
            .get_mut(index)
            .and_then(|word| NonZeroUsize::new(word as *mut u64 as usize).map(Self))
    }

    /// Return the address stored in a term word, as used by erts' `next` chain.
    #[inline(always)]
    pub fn address(self) -> u64 {
        self.0.get() as u64
    }

    /// Clear this destination and take its chained child slot.
    #[inline(always)]
    pub fn take_next(self) -> Option<Self> {
        // SAFETY: `HeapSlotPtr` is created from an in-range reserved heap word or from a
        // pointer previously stored in such a word. `B2tContext` retains the reservation
        // across yields, and a failed decode drops the cursor before factory rollback.
        let address = unsafe {
            let slot = self.0.get() as *mut u64;
            let address = *slot;
            *slot = 0;
            address
        };
        NonZeroUsize::new(address as usize).map(Self)
    }

    /// Store an encoded term or chain link in this destination word.
    #[inline(always)]
    pub fn store(self, word: u64) {
        // SAFETY: this cursor points into the live reservation, which is retained until the
        // decode finishes or is rolled back after the cursor is discarded.
        unsafe { (self.0.get() as *mut u64).write(word) };
    }

    /// `objp`/`hp` of `dec_term` for a word of the factory block (or `&ctx->u.dc.res`).
    ///
    /// Contract: `ptr` names a word of a live block the decoder owns (the parked factory block
    /// or the boxed `B2TContext`), which stays at its address until the decode ends.
    #[inline(always)]
    pub fn from_ptr(ptr: *mut u64) -> Option<Self> {
        NonZeroUsize::new(ptr as usize).map(Self)
    }

    /// The word address.
    #[inline(always)]
    pub fn as_ptr(self) -> *mut u64 {
        self.0.get() as *mut u64
    }

    /// `objp + words` (pointer arithmetic inside the same block).
    #[inline(always)]
    pub fn offset(self, words: usize) -> Self {
        Self(
            NonZeroUsize::new(self.0.get().wrapping_add(words * 8))
                .expect("heap word address is non-null"),
        )
    }

    /// `objp - words` (pointer arithmetic inside the same block).
    #[inline(always)]
    pub fn back(self, words: usize) -> Self {
        Self(
            NonZeroUsize::new(self.0.get().wrapping_sub(words * 8))
                .expect("heap word address is non-null"),
        )
    }

    /// `*objp`: read the word.
    #[inline(always)]
    pub fn load(self) -> u64 {
        // SAFETY: as for `store`: the word lies in the live block the decoder owns.
        unsafe { (self.0.get() as *const u64).read() }
    }
}

/// `sys_memcpy(ctx->u.dc.remaining_bytes, ep, n)` of `dec_term` (`B2TDecodeBinary`): copy into
/// the payload of a refc `Binary` already wrapped in the decoded term.
///
/// Contract: `dst..dst + src.len()` lies in the payload of a `Binary` that only the decoding
/// process references (its `BinRef` is on the factory heap, the process has GC disabled
/// across the trap), and nothing reads those bytes before the decode ends.
// Port of erts/emulator/beam/external.c (dec_term, B2TDecodeBinary), OTP-29.1.1.
#[inline(always)]
pub fn copy_to_binary_payload(dst: usize, src: &[u8]) {
    // SAFETY: the contract above; `src` is the external format data, never the destination.
    unsafe { std::ptr::copy_nonoverlapping(src.as_ptr(), dst as *mut u8, src.len()) }
}

/// `erts_validate_and_sort_flatmap`: insertion sort of the keys (and values) of a flatmap that
/// `dec_term` just filled; `false` on a duplicate key.
///
/// Contract: `map` is a flatmap of the decoder's factory heap whose keys and values are all
/// written and whose key tuple is owned by the same decode.
// Port of erts/emulator/beam/erl_map.c (erts_validate_and_sort_flatmap), OTP-29.1.1.
pub fn validate_and_sort_flatmap(map: Term) -> bool {
    // SAFETY: the contract above: the map and its key tuple are exclusive to this decode.
    unsafe {
        let map_ptr = map.raw_ptr().cast_mut();
        let size = *map_ptr.add(1) as usize;
        let keys = Term(*map_ptr.add(2))
            .raw_ptr()
            .cast_mut()
            .add(1)
            .cast::<Term>();
        let values = map_ptr.add(3).cast::<Term>();
        for ix in 1..size {
            let mut jx = ix;
            while jx > 0 {
                match crate::heap::flat_key_cmp(*keys.add(jx), *keys.add(jx - 1)) {
                    std::cmp::Ordering::Greater => break,
                    std::cmp::Ordering::Equal => return false,
                    std::cmp::Ordering::Less => {
                        std::ptr::swap(keys.add(jx), keys.add(jx - 1));
                        std::ptr::swap(values.add(jx), values.add(jx - 1));
                        jx -= 1;
                    }
                }
            }
        }
    }
    true
}

/// Get a reserved word's index when a safe heap builder API requires an indexed handle.
#[inline(always)]
pub fn slot_index(base: usize, length: usize, slot: HeapSlotPtr) -> Option<usize> {
    let offset = slot.0.get().checked_sub(base)?;
    if !offset.is_multiple_of(std::mem::size_of::<u64>()) {
        return None;
    }
    let index = offset / std::mem::size_of::<u64>();
    (index < length).then_some(index)
}

/// Encode a reserved heap word's address as erts stores it in `next` chains.
#[inline(always)]
pub fn slot_address(base: usize, index: usize) -> u64 {
    base.wrapping_add(index * std::mem::size_of::<u64>()) as u64
}
