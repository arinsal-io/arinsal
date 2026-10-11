//! Stable word allocations. Every pointer remains valid until its heap is dropped.
use crate::bits::{ExternalBinary, RefcBinary, WritableBinary, binary_data, owner_adjustment};
use crate::identity::check_external_ref;
use crate::record::RecordSnapshot;
use crate::record_table::RecordLayout;
use crate::{
    ARITY, Atom, BIN_REF, EMPTY_TUPLE, EXTERNAL_PID, EXTERNAL_PORT, EXTERNAL_REF, ExportEntry,
    FLOAT, FunEntry, HEAP_BITS, MAP, MAX_SMALL, MIN_SMALL, NEG_BIG, Node, POS_BIG, RECORD, REF,
    SUB_BITS, Term, TermError, TermKind, cmp, exact_eq,
};
use arinsal_alloc::typed::{AllocBlock, ErtsAlcType};
use num_bigint::{BigInt, Sign};
use num_traits::ToPrimitive;
use std::cell::UnsafeCell;
use std::cmp::Ordering;
use std::ops::Index;
use std::sync::Arc;

/// One young or old heap block: the user pointer only.
///
/// The allocator handle sits in a prefix of the same allocation (`ERTS_HEAP_ALLOC`
/// stores `Eterm *heap` in the process, not a side object). Null is an absent block,
/// the way erts leaves `old_heap` NULL.
pub(crate) struct WordBlock {
    ptr: *mut u64,
}

const LITERAL_HEAP_BIT: usize = MAPPED_WORDS;
const MAPPED_WORDS: usize = 1 << (usize::BITS - 1);

// SAFETY: A process owns its word block exclusively; moving it changes no pointers within it.
unsafe impl Send for WordBlock {}

/// A heap fragment: a BIF-allocated side buffer or an adopted message heap.
pub(crate) enum Fragment {
    /// erts `ErlHeapFragment` on the `p->mbuf` list: one `ERTS_ALC_T_HEAP_FRAG` block whose
    /// first `used` words (`used_size`) hold objects; `memory.len()` is `alloc_size`.
    // Port of erts/emulator/beam/erl_message.h:72-78 (ErlHeapFragment), OTP-29.1.1.
    Block { memory: AllocBlock, used: usize },
    /// erts `p->abandoned_heap`: the young heap left behind by a delayed collection. Its
    /// first `used` words hold objects, and those below `high_water` are mature. It is not
    /// part of `mbuf_sz`.
    Abandoned {
        block: WordBlock,
        used: usize,
        high_water: usize,
    },
}

impl Fragment {
    pub(crate) fn as_ptr(&self) -> *const u64 {
        match self {
            Self::Block { memory, .. } => memory.as_ptr(),
            Self::Abandoned { block, .. } => block.as_ptr().cast(),
        }
    }
    /// Words that hold objects.
    pub(crate) fn len(&self) -> usize {
        match self {
            Self::Block { used, .. } | Self::Abandoned { used, .. } => *used,
        }
    }
}

impl WordBlock {
    /// A heap block whose words are not cleared: like `ERTS_HEAP_ALLOC`, only the words
    /// below the heap top and above the stack pointer are ever read.
    // Port of erts/emulator/beam/erl_gc.c:1659 (do_minor `ERTS_HEAP_ALLOC`), OTP-29.1.1.
    pub(crate) fn new(words: usize, allocation_type: ErtsAlcType) -> Self {
        Self {
            ptr: AllocBlock::detach_heap(allocation_type, words)
                .expect("ERTS heap block allocation failed"),
        }
    }

    /// Grow or shrink this block in place when the carrier allows it.
    /// Port of erts/emulator/beam/erl_gc.c:2794 (`resize_new_heap` / `ERTS_HEAP_REALLOC`), OTP-29.1.1.
    pub(crate) fn realloc(&mut self, words: usize) {
        self.ptr = AllocBlock::realloc_detached_heap(self.ptr, words)
            .expect("ERTS heap block reallocation failed");
    }

    /// The typed block itself, for a heap block that joins the `mbuf` list.
    pub(crate) fn into_alloc_block(self) -> AllocBlock {
        let ptr = self.ptr;
        // The reconstructed block frees the allocation; this value must not.
        std::mem::forget(self);
        AllocBlock::reattach_heap(ptr).expect("ERTS heap block reattach failed")
    }

    /// The block's words, for a copy that holds the heap exclusively.
    pub(crate) fn words(&self) -> &[u64] {
        AllocBlock::heap_user_slice(self.ptr)
    }

    pub(crate) fn words_mut(&mut self) -> &mut [u64] {
        AllocBlock::heap_user_slice_mut(self.ptr)
    }

    pub(crate) fn as_ptr(&self) -> *const UnsafeCell<u64> {
        self.ptr.cast()
    }

    pub(crate) fn len(&self) -> usize {
        AllocBlock::heap_user_len(self.ptr)
    }

    pub(crate) fn contains_initialized(&self, address: usize, words: usize) -> bool {
        if self.ptr.is_null() {
            return false;
        }
        let start = self.as_ptr() as usize;
        address >= start && address < start.saturating_add(words.saturating_mul(8))
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.ptr.is_null()
    }

    pub(crate) fn get(&self, index: usize) -> Option<&UnsafeCell<u64>> {
        let word = self.words().get(index)?;
        // SAFETY: The allocator supplies aligned word storage; UnsafeCell has u64's layout.
        Some(unsafe { &*std::ptr::from_ref(word).cast::<UnsafeCell<u64>>() })
    }
}

impl Drop for WordBlock {
    fn drop(&mut self) {
        AllocBlock::free_detached_heap(self.ptr);
    }
}

/// A zero-filled typed block: no stale word can pass for a term in a heap scan.
fn zeroed_block(words: usize, allocation_type: ErtsAlcType) -> AllocBlock {
    let mut memory =
        AllocBlock::new(allocation_type, words).expect("ERTS heap block allocation failed");
    memory.as_mut_slice().fill(0);
    memory
}

impl Default for WordBlock {
    fn default() -> Self {
        // An absent old heap: erts leaves OLD_HEAP null and does not allocate.
        Self {
            ptr: std::ptr::null_mut(),
        }
    }
}

impl Index<usize> for WordBlock {
    type Output = UnsafeCell<u64>;

    fn index(&self, index: usize) -> &Self::Output {
        self.get(index).expect("word index out of bounds")
    }
}

/// Order of flatmap keys (`erts_cmp_flatmap_keys`), also the order of record fields.
pub fn flat_key_cmp(a: Term, b: Term) -> Ordering {
    exact_flat_key_cmp(a, b, true)
}

pub(crate) fn exact_flat_key_cmp(a: Term, b: Term, flat_atom: bool) -> Ordering {
    if let (Some(a), Some(b)) = (a.as_atom(), b.as_atom())
        && flat_atom
    {
        return a.0.cmp(&b.0);
    }
    if a.classify() == TermKind::Number && b.classify() == TermKind::Number {
        let af = a.header().is_some_and(|h| h & 63 == FLOAT);
        let bf = b.header().is_some_and(|h| h & 63 == FLOAT);
        return match (af, bf) {
            (false, true) => Ordering::Less,
            (true, false) => Ordering::Greater,
            (true, true) => {
                // SAFETY: both headers identify live float terms.
                unsafe {
                    a.float_ref()
                        .unwrap()
                        .get()
                        .total_cmp(&b.float_ref().unwrap().get())
                }
            }
            (false, false) => cmp(a, b),
        };
    }
    match (a.classify(), b.classify()) {
        (TermKind::Tuple, TermKind::Tuple) => {
            // SAFETY: the tuple terms remain live during sorting.
            let (a, b) = unsafe { (a.tuple_ref().unwrap(), b.tuple_ref().unwrap()) };
            let order = a.len().cmp(&b.len());
            if order != Ordering::Equal {
                return order;
            }
            for i in 0..a.len() {
                let order = exact_flat_key_cmp(a.get(i).unwrap(), b.get(i).unwrap(), false);
                if order != Ordering::Equal {
                    return order;
                }
            }
            Ordering::Equal
        }
        (TermKind::List, TermKind::List) => {
            // SAFETY: the list cells remain live during sorting.
            let ((ah, at), (bh, bt)) = unsafe { (a.cons_ref().unwrap(), b.cons_ref().unwrap()) };
            exact_flat_key_cmp(ah, bh, false).then_with(|| exact_flat_key_cmp(at, bt, false))
        }
        (TermKind::Map, TermKind::Map) => {
            let (mut av, mut bv) = (crate::hamt::pairs(a), crate::hamt::pairs(b));
            let order = av.len().cmp(&bv.len());
            if order != Ordering::Equal {
                return order;
            }
            av.sort_by(|x, y| exact_flat_key_cmp(x.0, y.0, false));
            bv.sort_by(|x, y| exact_flat_key_cmp(x.0, y.0, false));
            for i in 0..av.len() {
                let order = exact_flat_key_cmp(av[i].0, bv[i].0, false);
                if order != Ordering::Equal {
                    return order;
                }
            }
            for i in 0..av.len() {
                let order = exact_flat_key_cmp(av[i].1, bv[i].1, false);
                if order != Ordering::Equal {
                    return order;
                }
            }
            Ordering::Equal
        }
        _ => cmp(a, b),
    }
}

/// Allocator for word-aligned, stable term objects.
pub trait HeapAlloc {
    /// Reserve contiguous words, or return `None` so the caller can collect.
    fn alloc(&mut self, words: usize) -> Option<*mut u64>;
    /// Reserve words with spare capacity for later allocations from a heap fragment.
    ///
    /// Port of `HAllocX` in `erts/emulator/beam/erl_vm.h:154-159`, OTP-29.1.1.
    fn alloc_with_extra(&mut self, words: usize, _extra: usize) -> Option<*mut u64> {
        self.alloc(words)
    }
    /// Allocate words in a heap fragment without first trying the young heap.
    ///
    /// Port of `HeapFragOnlyAlloc` in erts/emulator/beam/erl_vm.h:219-224, OTP-29.1.1.
    fn alloc_fragment_only(&mut self, words: usize) -> Option<*mut u64> {
        self.alloc(words)
    }
    /// Young-heap words [`alloc`](Self::alloc) can still return.
    ///
    /// `None` when this allocator does not expose a young-heap limit (a heap
    /// fragment, or a process whose allocations are detached). Port of
    /// erts/emulator/beam/erl_vm.h:175 (`HeapWordsLeft`), OTP-29.1.1.
    fn words_left(&self) -> Option<usize> {
        None
    }
    /// Keep an off-heap binary alive until GC examines this heap's owners.
    fn retain_binary(&mut self, binary: Arc<RefcBinary>);
    /// Retain a growable off-heap binary until collection examines its BinRef.
    fn retain_writable_binary(&mut self, _binary: Arc<WritableBinary>) -> Result<(), TermError> {
        Err(TermError::Unsupported("writable binary heap owner"))
    }
    /// Retain a writable binary using erts' apparent size, in bits, for pre-GC overhead.
    fn retain_writable_binary_with_apparent_size(
        &mut self,
        binary: Arc<WritableBinary>,
        _apparent_size_bits: usize,
    ) -> Result<(), TermError> {
        self.retain_writable_binary(binary)
    }
    /// Add the overhead change performed by `update_wb_overhead` before a writable append.
    fn update_writable_binary_overhead(
        &mut self,
        _source: Term,
        _old_size_bits: usize,
        _new_size_bits: usize,
    ) {
    }
    /// Whether this heap can retain a writable owner without losing it at GC.
    fn supports_writable_binary(&self) -> bool {
        false
    }
    /// Retain a resource-backed binary until GC examines its BinRef.
    fn retain_external_binary(&mut self, _binary: Arc<ExternalBinary>) -> Result<(), TermError> {
        Err(TermError::Unsupported("external binary heap owner"))
    }
    /// Whether the heap retains external binary owners across collection.
    fn supports_external_binary(&self) -> bool {
        false
    }
    /// Keep a node-table entry alive for external identities.
    fn retain_node(&mut self, node: Arc<Node>);
    /// Retain a local fun entry.
    fn retain_fun(&mut self, entry: Arc<FunEntry>);
    /// Retain an export entry.
    fn retain_export(&mut self, entry: Arc<ExportEntry>);
    /// Keep a magic reference alive until GC examines this heap's owners.
    fn retain_magic(&mut self, _owner: Arc<crate::MagicRef>) {
        unreachable!("supports_magic must be checked before retention")
    }
    /// Whether the allocator keeps magic owners across its heap lifetime.
    fn supports_magic(&self) -> bool {
        false
    }
    /// Give back the unused words `[start, end)` at the end of the latest allocation.
    ///
    /// The caller has already covered the hole with a heap filler
    /// (`erts_write_heap_filler`), so allocators that cannot lower their top keep it.
    // Port of erts/emulator/beam/erl_vm.h:164-173 (HRelease), OTP-29.1.1.
    fn release(&mut self, _end: *mut u64, _start: *mut u64) {}
}

/// Store one word into a block the caller owns (`HAlloc` memory, a reservation or a patched slot).
///
/// Private on purpose: every caller passes a pointer it obtained from the allocator for the
/// block it is filling, which is the one invariant a raw store needs.
#[inline]
fn store(ptr: *mut u64, value: u64) {
    // SAFETY: callers pass an in-bounds, initialized-or-reserved slot of a live heap block.
    unsafe { *ptr = value }
}

/// Head and open tail slot of a chain built by [`TermBuilder::chain3_push`].
pub struct Tuple3Chain {
    head: Term,
    last: Option<*mut u64>,
}
impl Tuple3Chain {
    /// An empty chain.
    pub const fn new() -> Self {
        Self {
            head: Term::NIL,
            last: None,
        }
    }
    /// Close the chain with `tail`; an empty chain is just `tail`.
    pub fn finish(self, tail: Term) -> Term {
        match self.last {
            Some(last) => {
                store(last.wrapping_add(3), tail.bits());
                self.head
            }
            None => tail,
        }
    }
}
impl Default for Tuple3Chain {
    fn default() -> Self {
        Self::new()
    }
}

/// Build a list in input order inside one pre-reserved heap block.
pub struct ConsHeapBuilder<'a, H: HeapAlloc + ?Sized> {
    reservation: HeapReservation<'a, H>,
    head: Term,
    last: Option<*mut u64>,
}
impl<'a, H: HeapAlloc + ?Sized> ConsHeapBuilder<'a, H> {
    /// Reserve space for at most `max_cells` cons cells.
    pub fn new(heap: &'a mut H, max_cells: usize) -> Result<Self, TermError> {
        let words = max_cells.checked_mul(2).ok_or(TermError::SystemLimit)?;
        Ok(Self {
            reservation: HeapReservation::new(heap, words)?,
            head: Term::NIL,
            last: None,
        })
    }

    /// Append a cell after the previous cell in input order.
    pub fn push(&mut self, head: Term) -> Result<(), TermError> {
        let cell = TermBuilder::new(&mut self.reservation).words(2)?;
        let term = Term::from_ptr(cell, 1);
        match self.last {
            Some(last) => store(last.wrapping_add(1), term.bits()),
            None => self.head = term,
        }
        self.last = Some(cell);
        // Port of the `CAR(hp) = value` store in `erl_bif_lists.c:750-756` and
        // `:896-899`; the open CDR is written by the next push or `finish`.
        store(cell, head.bits());
        Ok(())
    }

    /// Close the list with `tail` and release unused reserved heap words.
    pub fn finish(mut self, tail: Term) -> Term {
        match self.last.take() {
            Some(last) => {
                store(last.wrapping_add(1), tail.bits());
                self.head
            }
            None => tail,
        }
    }
}
impl<H: HeapAlloc + ?Sized> Drop for ConsHeapBuilder<'_, H> {
    fn drop(&mut self) {
        if let Some(last) = self.last.take() {
            store(last.wrapping_add(1), Term::NIL.bits());
        }
    }
}

/// An append-only list whose open tail can survive a BIF reduction trap.
///
/// The caller must keep the heap stable while the chain is open. Trapping BIFs
/// do this by disabling collection until the continuation completes.
pub struct ConsHeapChain {
    head: Term,
    result_cdr: Option<usize>,
}

impl ConsHeapChain {
    /// Start an empty chain.
    /// Port of the initial result-cdr setup in `erl_bif_lists.c:697-705` and `:858-867`.
    pub const fn new() -> Self {
        Self {
            head: Term::NIL,
            result_cdr: None,
        }
    }

    /// Append one input-order cell with the same heap-fragment slack as `HAllocX`.
    ///
    /// Port of `erl_bif_lists.c:740-756` and `:881-899`, OTP-29.1.1.
    pub fn push<H: HeapAlloc + ?Sized>(
        &mut self,
        heap: &mut H,
        value: Term,
        remaining_cells: usize,
    ) -> Result<(), TermError> {
        let extra_words = remaining_cells
            .checked_mul(2)
            .ok_or(TermError::SystemLimit)?;
        let cell = heap
            .alloc_with_extra(2, extra_words)
            .ok_or(TermError::SystemLimit)?;
        let term = Term::from_ptr(cell, 1);
        if let Some(result_cdr) = self.result_cdr {
            store(result_cdr as *mut u64, term.bits());
        } else {
            self.head = term;
        }
        store(cell, value.bits());
        self.result_cdr = Some(cell.wrapping_add(1) as usize);
        Ok(())
    }

    /// Terminate the chain before yielding so the partial result remains valid.
    /// Port of `*context->result_cdr = NIL` in `erl_bif_lists.c:786` and `:919`.
    pub fn suspend(&self) {
        if let Some(result_cdr) = self.result_cdr {
            store(result_cdr as *mut u64, Term::NIL.bits());
        }
    }

    /// Close the chain with `tail` and return its head.
    /// Port of the result-cdr tail stores in `erl_bif_lists.c:767-771` and `:900-906`.
    pub fn finish(mut self, tail: Term) -> Term {
        if let Some(result_cdr) = self.result_cdr {
            store(result_cdr as *mut u64, tail.bits());
            self.result_cdr = None;
            self.head
        } else {
            tail
        }
    }
}

impl Drop for ConsHeapChain {
    // Port of the partial-result termination performed before trapping or BIF errors.
    fn drop(&mut self) {
        self.suspend();
    }
}

impl Default for ConsHeapChain {
    fn default() -> Self {
        Self::new()
    }
}

/// A block taken from a heap in one `HAlloc` whose unused tail is handed back on drop.
///
/// Port of the `HAlloc(worst case)` / `HRelease(hp_end, hp)` idiom used by BIFs such as
/// erts/emulator/beam/erl_map.c:3636-4130 (erts_internal_map_next_3), OTP-29.1.1: one block
/// (one heap fragment when the heap is full) instead of one allocation per term.
pub struct HeapReservation<'a, H: HeapAlloc + ?Sized> {
    heap: &'a mut H,
    cur: *mut u64,
    end: *mut u64,
}
impl<'a, H: HeapAlloc + ?Sized> HeapReservation<'a, H> {
    /// Reserve `words` words from `heap`.
    pub fn new(heap: &'a mut H, words: usize) -> Result<Self, TermError> {
        let cur = heap.alloc(words).ok_or(TermError::SystemLimit)?;
        let end = cur.wrapping_add(words);
        Ok(Self { heap, cur, end })
    }
    /// Cursor (`HEAP_TOP` after the `HAlloc` of this block).
    #[inline]
    pub fn cursor(&self) -> *mut u64 {
        self.cur
    }
    /// Exclusive end of the block.
    #[inline]
    pub fn limit(&self) -> *mut u64 {
        self.end
    }
    /// Advance the cursor after a direct fill. `[cur, limit)` is released on drop.
    ///
    /// `cur` must be word-aligned and lie in `[cursor, limit]`.
    #[inline]
    pub fn set_cursor(&mut self, cur: *mut u64) {
        self.cur = cur;
    }
    /// Give back the unused tail and reserve a fresh block of `words` words.
    pub fn regrow(&mut self, words: usize) -> Result<(), TermError> {
        self.release_tail();
        let cur = self.heap.alloc(words).ok_or(TermError::SystemLimit)?;
        self.end = cur.wrapping_add(words);
        self.cur = cur;
        Ok(())
    }
    /// Port of erts/emulator/beam/erl_vm.h:164-173 (HRelease) with erl_term.h:1500
    /// (erts_write_heap_filler), OTP-29.1.1.
    fn release_tail(&mut self) {
        let words = (self.end as usize - self.cur as usize) / 8;
        if words > 0 {
            store(self.cur, ((words as u64 - 1) << 6) | POS_BIG);
            self.heap.release(self.end, self.cur);
            self.cur = self.end;
        }
    }
}
impl<H: HeapAlloc + ?Sized> Drop for HeapReservation<'_, H> {
    fn drop(&mut self) {
        self.release_tail();
    }
}
impl<H: HeapAlloc + ?Sized> HeapAlloc for HeapReservation<'_, H> {
    #[inline]
    fn alloc(&mut self, words: usize) -> Option<*mut u64> {
        if words <= (self.end as usize - self.cur as usize) / 8 {
            let ptr = self.cur;
            self.cur = ptr.wrapping_add(words);
            Some(ptr)
        } else {
            self.heap.alloc(words)
        }
    }
    #[inline]
    fn alloc_with_extra(&mut self, words: usize, extra_words: usize) -> Option<*mut u64> {
        // Port of `HAllocX`'s young-heap check and `erts_heap_alloc` fallback.
        if words <= (self.end as usize - self.cur as usize) / 8 {
            let ptr = self.cur;
            self.cur = ptr.wrapping_add(words);
            Some(ptr)
        } else {
            self.heap.alloc_with_extra(words, extra_words)
        }
    }
    fn alloc_fragment_only(&mut self, words: usize) -> Option<*mut u64> {
        self.heap.alloc_fragment_only(words)
    }
    fn retain_binary(&mut self, binary: Arc<RefcBinary>) {
        self.heap.retain_binary(binary)
    }
    fn retain_writable_binary_with_apparent_size(
        &mut self,
        binary: Arc<WritableBinary>,
        apparent_size_bits: usize,
    ) -> Result<(), TermError> {
        self.heap
            .retain_writable_binary_with_apparent_size(binary, apparent_size_bits)
    }
    fn update_writable_binary_overhead(
        &mut self,
        source: Term,
        old_size_bits: usize,
        new_size_bits: usize,
    ) {
        self.heap
            .update_writable_binary_overhead(source, old_size_bits, new_size_bits)
    }
    fn retain_node(&mut self, node: Arc<Node>) {
        self.heap.retain_node(node)
    }
    fn retain_fun(&mut self, entry: Arc<FunEntry>) {
        self.heap.retain_fun(entry)
    }
    fn retain_export(&mut self, entry: Arc<ExportEntry>) {
        self.heap.retain_export(entry)
    }
}

/// A process heap with an upward bump pointer and a downward stack pointer.
pub struct ProcessHeap {
    pub(crate) words: WordBlock,
    pub(crate) htop: usize,
    pub(crate) stop: usize,
    pub(crate) frame_pointer: usize,
    pub(crate) old_words: WordBlock,
    pub(crate) old_htop: usize,
    pub(crate) high_water: usize,
    pub(crate) min_heap_size: u32,
    pub(crate) fullsweep_after: u16,
    pub(crate) minor_since_major: u16,
    pub(crate) bin_vheap: u64,
    pub(crate) bin_vheap_size: u64,
    pub(crate) heap_grow: bool,
    pub(crate) native_allocation: bool,
    /// Allocations go to `owners.detached` (see [`ProcessHeap::begin_detached`]).
    pub(crate) detached: bool,
    /// Whether `fragments` holds the abandoned heap (erts `p->abandoned_heap != NULL`),
    /// so the frequent "is there one" question does not walk the fragment list.
    pub(crate) abandoned: bool,
    pub(crate) fragments: Vec<Fragment>,
    /// Total word capacity in process heap fragments (`mbuf_sz` in erts).
    /// Words in heap fragments (u32 keeps the hot heap struct within 128 bytes).
    pub(crate) fragment_words: u32,
    pub(crate) owners: LazyOwners,
}

/// Word kinds found while walking the live Erlang stack.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StackWord {
    /// A tagged Erlang term.
    Term(Term),
    /// A return address into registered native code.
    ReturnAddr(usize),
    /// A frame pointer into the live Erlang stack.
    FramePtr(usize),
}

/// The native FP_RA frame layout: `[frame pointer, return address]`.
pub struct FrameLayout;

impl FrameLayout {
    /// Word offset of the saved frame pointer.
    pub const FRAME_POINTER_WORD: usize = 0;
    /// Word offset of the saved return address.
    pub const RETURN_ADDRESS_WORD: usize = 1;
    /// Number of words in a frame header.
    pub const WORDS: usize = 2;
}

/// Number of words reserved for a default BeamAsm continuation pointer.
pub const CP_WORDS: usize = 1;
/// Stack redzone that runtime heap allocators must leave for native calls.
// Port of erts/emulator/beam/erl_vm.h:108-110, OTP-29.1.1, BEAMAsm AArch64.
pub const S_REDZONE: usize = CP_WORDS * 3;
/// Minimum free gap kept between the young heap and Erlang stack.
// Port of erts/emulator/beam/erl_vm.h:120, OTP-29.1.1.
pub const S_RESERVED: usize = CP_WORDS + S_REDZONE;
/// Rarely touched virtual binary heap state, kept out of the hot `ProcessHeap`.
pub(crate) struct VheapCold {
    pub(crate) old: u64,
    pub(crate) old_size: u64,
    pub(crate) min: u64,
}

impl Default for VheapCold {
    fn default() -> Self {
        Self {
            old: 0,
            old_size: 46_422,
            min: 46_422,
        }
    }
}

#[derive(Default)]
pub(crate) struct HeapOwners {
    pub(crate) vheap: VheapCold,
    pub(crate) off_heap: Vec<Arc<RefcBinary>>,
    pub(crate) writable: Vec<Arc<WritableBinary>>,
    pub(crate) external: Vec<Arc<ExternalBinary>>,
    pub(crate) nodes: Vec<Arc<Node>>,
    pub(crate) funs: Vec<Arc<FunEntry>>,
    pub(crate) exports: Vec<Arc<ExportEntry>>,
    pub(crate) magic: Vec<Arc<crate::MagicRef>>,
    pub(crate) old_off_heap: Vec<Arc<RefcBinary>>,
    pub(crate) old_writable: Vec<Arc<WritableBinary>>,
    pub(crate) old_external: Vec<Arc<ExternalBinary>>,
    pub(crate) old_nodes: Vec<Arc<Node>>,
    pub(crate) old_funs: Vec<Arc<FunEntry>>,
    pub(crate) old_exports: Vec<Arc<ExportEntry>>,
    pub(crate) old_magic: Vec<Arc<crate::MagicRef>>,
    pub(crate) old_writable_refs: Vec<Term>,
    /// Heap that receives all allocations while the heap is detached.
    pub(crate) detached: Option<Box<VecHeap>>,
}

#[derive(Default)]
pub(crate) struct LazyOwners(Option<Box<HeapOwners>>);

impl LazyOwners {
    /// Whether the off-heap owner box has been created. A minor GC of a process
    /// with no binaries must not allocate one.
    pub(crate) fn is_allocated(&self) -> bool {
        self.0.is_some()
    }

    pub(crate) fn vheap_min(&self) -> u64 {
        self.0
            .as_ref()
            .map(|owners| owners.vheap.min)
            .unwrap_or(46_422)
    }

    pub(crate) fn vheap_old(&self) -> u64 {
        self.0.as_ref().map(|owners| owners.vheap.old).unwrap_or(0)
    }

    pub(crate) fn vheap_old_size(&self) -> u64 {
        self.0
            .as_ref()
            .map(|owners| owners.vheap.old_size)
            .unwrap_or(46_422)
    }

    pub(crate) fn has_collection_state(&self) -> bool {
        let Some(owners) = self.0.as_deref() else {
            return false;
        };
        owners.vheap.min != 46_422
            || owners.vheap.old != 0
            || owners.vheap.old_size != 46_422
            || !owners.old_off_heap.is_empty()
            || !owners.old_writable.is_empty()
            || !owners.old_external.is_empty()
            || !owners.old_nodes.is_empty()
            || !owners.old_funs.is_empty()
            || !owners.old_exports.is_empty()
            || !owners.old_magic.is_empty()
            || !owners.old_writable_refs.is_empty()
    }
}

impl std::ops::Deref for LazyOwners {
    type Target = HeapOwners;
    fn deref(&self) -> &Self::Target {
        static EMPTY: std::sync::OnceLock<HeapOwners> = std::sync::OnceLock::new();
        self.0
            .as_deref()
            .unwrap_or_else(|| EMPTY.get_or_init(HeapOwners::default))
    }
}
impl std::ops::DerefMut for LazyOwners {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.0
            .get_or_insert_with(|| Box::new(HeapOwners::default()))
    }
}

/// A heap with stack or old-generation words cannot be adopted as a message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdoptError {
    /// The source is not a standalone message fragment.
    NotStandalone,
}

impl ProcessHeap {
    /// Create a heap with 64 words, including stack space.
    pub fn new() -> Self {
        Self::with_words(64)
    }
    /// Create a heap of the specified word capacity.
    pub fn with_words(words: usize) -> Self {
        Self::with_words_for_type(words, ErtsAlcType::HEAP)
    }

    /// Create a heap fragment block with the requested typed allocator.
    pub fn with_words_for_type(words: usize, allocation_type: ErtsAlcType) -> Self {
        Self {
            words: WordBlock::new(words, allocation_type),
            htop: 0,
            stop: words,
            frame_pointer: 0,
            old_words: WordBlock::default(),
            old_htop: 0,
            high_water: 0,
            min_heap_size: 233,
            fullsweep_after: u16::MAX,
            minor_since_major: 0,
            bin_vheap: 0,
            bin_vheap_size: 46_422,
            heap_grow: false,
            native_allocation: false,
            detached: false,
            abandoned: false,
            fragments: Vec::new(),
            fragment_words: 0,
            owners: LazyOwners::default(),
        }
    }

    /// Reserve contiguous words for a process object.
    pub fn alloc(&mut self, words: usize) -> Option<*mut Term> {
        <Self as HeapAlloc>::alloc(self, words).map(|ptr| ptr.cast::<Term>())
    }
    /// Number of words consumed by heap objects.
    pub fn used_words(&self) -> usize {
        self.htop
    }
    /// Write one allocated raw word for the `erts_debug:inconsistent_heap` test hook.
    ///
    /// This debug-only API deliberately permits invalid term headers and sentinels.
    pub fn debug_write_heap_word(&mut self, index: usize, word: u64) -> bool {
        let Some(cell) = self.words.get(index).filter(|_| index < self.htop) else {
            return false;
        };
        // SAFETY: The index is within the allocated young heap, owned exclusively here.
        unsafe { cell.get().write(word) };
        true
    }
    /// Young-heap words `alloc` will accept, or `None` when allocations are
    /// redirected to a detached heap.
    pub fn alloc_words_left(&self) -> Option<usize> {
        if self.detached {
            None
        } else {
            Some(self.words_left())
        }
    }
    /// erts `HeapWordsLeft`: words a normal heap allocation can hand out.
    // Port of erts/emulator/beam/erl_vm.h:175 (HeapWordsLeft), OTP-29.1.1.
    pub fn words_left(&self) -> usize {
        let limit = if self.native_allocation {
            self.heap_limit_words()
        } else {
            self.stop
        };
        limit.saturating_sub(self.htop)
    }
    /// Number of words between the heap and stack pointers.
    pub fn free_words(&self) -> usize {
        self.stop - self.htop
    }
    /// Runtime heap allocation boundary, leaving the stack redzone unused.
    // Port of erts/emulator/beam/erl_process.h:990-998, OTP-29.1.1.
    pub fn heap_limit_words(&self) -> usize {
        self.htop.max(self.stop.saturating_sub(crate::S_REDZONE))
    }
    /// Young-heap words available to `HAlloc` before it uses a fragment.
    // Port of erts/emulator/beam/erl_vm.h:150-175 (HAllocX/HeapWordsLeft), OTP-29.1.1.
    pub fn halloc_words_left(&self) -> Option<usize> {
        (!self.detached).then(|| self.heap_limit_words().saturating_sub(self.htop))
    }
    /// Allocate on the young heap only when `HAlloc` stays below `HEAP_LIMIT`.
    // Port of erts/emulator/beam/erl_vm.h:150-162 (HAllocX), OTP-29.1.1.
    pub fn alloc_halloc(&mut self, words: usize) -> Option<*mut u64> {
        if self.detached {
            return self.owners.detached.as_deref_mut()?.alloc(words);
        }
        if words > self.heap_limit_words().saturating_sub(self.htop) {
            return None;
        }
        let ptr = self
            .words
            .as_ptr()
            .wrapping_add(self.htop)
            .cast::<u64>()
            .cast_mut();
        self.htop += words;
        Some(ptr)
    }
    /// Whether generated code is running on this heap (set by the native bridge).
    pub fn native_active(&self) -> bool {
        self.native_allocation
    }
    /// Words a normal allocation must leave free below the stack.
    pub fn allocation_reserve(&self) -> usize {
        if self.native_allocation {
            crate::S_REDZONE
        } else {
            0
        }
    }
    /// Record whether generated Erlang code is active on this heap.
    pub fn set_native_allocation(&mut self, active: bool) {
        self.native_allocation = active;
    }
    /// Return the current heap top and stack boundary for a VM-local bump cursor.
    /// The pointers remain valid until this heap collects or grows.
    pub fn heap_cursor(&self) -> (*mut u64, *mut u64) {
        // SAFETY: Both indices are within or one past the fixed allocation.
        unsafe {
            let base = self.words.as_ptr().cast::<u64>().cast_mut();
            (base.add(self.htop), base.add(self.stop))
        }
    }
    /// Publish the active native frame pointer before a moving collection.
    pub fn set_frame_pointer(&mut self, frame_pointer: usize) {
        let base = self.words.as_ptr() as usize;
        let start = base + self.stop * 8;
        let end = base + self.words.len() * 8;
        self.frame_pointer = if frame_pointer >= start && frame_pointer < end {
            frame_pointer
        } else {
            0
        };
    }
    /// Return the active native frame pointer after collection.
    pub fn frame_pointer(&self) -> usize {
        self.frame_pointer
    }
    /// Return the start and end of the young heap allocation.
    pub fn heap_bounds(&self) -> (*mut u64, *mut u64) {
        // SAFETY: The fixed word block owns this entire allocation.
        unsafe {
            let base = self.words.as_ptr().cast::<u64>().cast_mut();
            (base, base.add(self.words.len()))
        }
    }
    /// Return the address of the young-heap high-water boundary.
    pub fn high_water_ptr(&self) -> *mut u64 {
        let (heap, _) = self.heap_bounds();
        heap.wrapping_add(self.high_water)
    }
    /// Commit a VM-local cursor before collection or another heap allocator runs.
    pub fn set_heap_top(&mut self, top: *mut u64) {
        let base = self.words.as_ptr() as usize;
        let address = top as usize;
        assert!(
            address >= base && address <= base + self.stop * 8,
            "heap top={address:#x} base={base:#x} stop={:#x} end={:#x}",
            base + self.stop * 8,
            base + self.words.len() * 8,
        );
        assert_eq!((address - base) % 8, 0);
        self.htop = (address - base) / 8;
    }
    /// Commit both native cursors at once when native code enters the runtime.
    // Port of erts/emulator/beam/jit/arm/beam_asm.hpp:459-537 (emit_enter_runtime stores HTOP
    // and E into c_p as they are), OTP-29.1.1. The young-heap base is `c_p->heap`; the
    // indices are that base subtracted from the pointers, with no release-mode bounds check.
    #[inline(always)]
    pub fn set_native_cursors(&mut self, htop: *mut u64, stop: *mut u64) {
        self.commit_native_cursors(self.words.as_ptr() as usize, htop, stop);
    }

    /// Same as [`ProcessHeap::set_native_cursors`] using an already-known heap base
    /// (`c_p->heap`). A null base falls back to the block pointer.
    #[inline(always)]
    pub fn set_native_cursors_at(&mut self, base: *mut u64, htop: *mut u64, stop: *mut u64) {
        let base = if base.is_null() {
            self.words.as_ptr() as usize
        } else {
            base as usize
        };
        self.commit_native_cursors(base, htop, stop);
    }

    #[inline(always)]
    fn commit_native_cursors(&mut self, base: usize, htop: *mut u64, stop: *mut u64) {
        let top = (htop as usize).wrapping_sub(base) >> 3;
        let stack = (stop as usize).wrapping_sub(base) >> 3;
        debug_assert!(
            top <= stack && stack <= self.words.len(),
            "native cursors outside the heap: htop={htop:p} stop={stop:p} base={base:#x}"
        );
        self.htop = top;
        self.stop = stack;
    }
    /// Young heap top as a word index.
    #[inline]
    pub fn heap_top_index(&self) -> usize {
        self.htop
    }
    /// Stack pointer as a word index.
    #[inline]
    pub fn stack_index(&self) -> usize {
        self.stop
    }
    /// Capacity of the heap fragments in words (`mbuf_sz`), as [`ProcessHeap::gc_desired`]
    /// compares it.
    #[inline]
    pub fn mbuf_size(&self) -> usize {
        self.fragment_words as usize
    }
    /// Address of the word at `index` in the young heap block.
    #[inline]
    pub fn word_address(&self, index: usize) -> *mut u64 {
        (self.words.as_ptr() as usize).wrapping_add(index.wrapping_mul(8)) as *mut u64
    }
    /// Commit the native Erlang stack pointer before collection or interpretation.
    pub fn set_stack_pointer(&mut self, stop: *mut u64) {
        let base = self.words.as_ptr() as usize;
        let address = stop as usize;
        assert!(address >= base && address <= base + self.words.len() * 8);
        assert_eq!((address - base) % 8, 0);
        let index = (address - base) / 8;
        assert!(index >= self.htop);
        self.stop = index;
    }
    /// Reserve stack words from the high end.
    pub fn reserve_stack(&mut self, words: usize) -> bool {
        if words > self.free_words() {
            return false;
        }
        self.stop -= words;
        true
    }
    /// Allocate a side fragment when a BIF cannot collect at this point.
    pub fn heap_fragment(&mut self, words: usize) -> *mut u64 {
        self.heap_fragment_with_extra(words, 0)
    }
    /// Allocate a side fragment with spare capacity for subsequent BIF allocations.
    ///
    /// Port of erts/emulator/beam/utils.c:135-189 (`erts_heap_alloc`), OTP-29.1.1.
    pub fn heap_fragment_with_extra(&mut self, words: usize, extra: usize) -> *mut u64 {
        if self.detached
            && let Some(ptr) = self
                .owners
                .detached
                .as_deref_mut()
                .and_then(|heap| heap.alloc_with_extra(words, extra))
        {
            return ptr;
        }
        // ERTS reuses the newest fragment before allocating another one.
        self.fragment_words = self
            .fragment_words
            .saturating_add(u32::try_from(words).unwrap_or(u32::MAX));
        if let Some(Fragment::Block { memory, used }) = self.fragments.last_mut()
            && words <= memory.len() - *used
        {
            let at = *used;
            *used += words;
            return memory.as_mut_slice()[at..].as_mut_ptr();
        }
        let block_words = words.checked_add(extra).unwrap_or(words);
        let mut memory = zeroed_block(block_words, ErtsAlcType::HEAP_FRAG);
        let ptr = memory.as_mut_ptr();
        self.fragments.push(Fragment::Block {
            memory,
            used: words,
        });
        ptr
    }
    /// Move a standalone message heap into this process without copying its terms.
    ///
    /// The source must have no live stack or old generation. Terms allocated in
    /// it remain valid until this process next collects its fragments.
    pub fn adopt_message_fragment(&mut self, mut source: ProcessHeap) -> Result<(), AdoptError> {
        if source.stop != source.words.len()
            || source.old_htop != 0
            || !source.old_words.is_empty()
            || !source.owners.old_writable_refs.is_empty()
        {
            return Err(AdoptError::NotStandalone);
        }
        // The block moves with its terms; no word is copied.
        let adopted_words = source
            .words
            .len()
            .saturating_add(source.fragment_words as usize);
        self.fragment_words = self
            .fragment_words
            .saturating_add(u32::try_from(adopted_words).unwrap_or(u32::MAX));
        let block = std::mem::take(&mut source.words).into_alloc_block();
        let used = block.len();
        self.fragments.push(Fragment::Block {
            memory: block,
            used,
        });
        self.fragments.append(&mut source.fragments);
        self.abandoned |= source.abandoned;
        self.absorb_fragment_owners(&mut source);
        Ok(())
    }

    /// Words of message data held by a standalone message heap: the used part of its block
    /// and of each heap fragment.
    // Port of erts/emulator/beam/erl_message.h (erts_msg_attached_data_size), OTP-29.1.1.
    pub fn message_data_size(&self) -> usize {
        self.fragments
            .iter()
            .filter_map(|fragment| match fragment {
                Fragment::Block { used, .. } => Some(*used),
                Fragment::Abandoned { .. } => None,
            })
            .fold(self.htop, usize::saturating_add)
    }

    /// Link the off-heap objects of a message fragment into this process's off-heap list
    /// and add its virtual binary heap overhead.
    // Port of erts/emulator/beam/erl_message.c:980-990 (erts_save_message_in_proc) and
    // erl_gc.c:2524 (OH_OVERHEAD in erts_copy_one_frag), OTP-29.1.1.
    pub(crate) fn absorb_fragment_owners(&mut self, source: &mut ProcessHeap) {
        if let Some(mut owners) = source.owners.0.take() {
            let source_old_vheap = owners.vheap.old;
            self.bin_vheap = self.bin_vheap.saturating_add(source.bin_vheap);
            self.owners.vheap.old = self.owners.vheap.old.saturating_add(source_old_vheap);
            if let Some(target) = self.owners.0.as_mut() {
                target.off_heap.append(&mut owners.off_heap);
                target.writable.append(&mut owners.writable);
                target.external.append(&mut owners.external);
                target.nodes.append(&mut owners.nodes);
                target.funs.append(&mut owners.funs);
                target.exports.append(&mut owners.exports);
                target.magic.append(&mut owners.magic);
                target.old_off_heap.append(&mut owners.old_off_heap);
                target.old_writable.append(&mut owners.old_writable);
                target.old_external.append(&mut owners.old_external);
                target.old_nodes.append(&mut owners.old_nodes);
                target.old_funs.append(&mut owners.old_funs);
                target.old_exports.append(&mut owners.old_exports);
                target.old_magic.append(&mut owners.old_magic);
            } else {
                self.owners.0 = Some(owners);
            }
        }
    }
    /// Number of off-heap binary owners retained by this process.
    pub fn off_heap_count(&self) -> usize {
        self.owners.off_heap.len()
            + self.owners.writable.len()
            + self.owners.external.len()
            + self.owners.old_off_heap.len()
            + self.owners.old_writable.len()
            + self.owners.old_external.len()
    }

    /// Number of bytes in the process's retained non-writable binaries.
    pub fn off_heap_binary_bytes(&self) -> u64 {
        self.owners
            .off_heap
            .iter()
            .chain(&self.owners.old_off_heap)
            .map(|binary| binary.len() as u64)
            .chain(
                self.owners
                    .external
                    .iter()
                    .chain(&self.owners.old_external)
                    .map(|binary| binary.len() as u64),
            )
            .sum()
    }

    /// Return one `(identity, byte length, refcount)` per retained refc binary reference.
    ///
    /// Port of erts/emulator/beam/erl_bif_info.c:179 (erts_bld_bin_list), OTP-29.1.1: every
    /// reference in the off-heap list is reported separately, newest first.
    pub fn off_heap_binary_info(&self) -> Vec<(usize, usize, usize)> {
        let o = &self.owners;
        let mut out = Vec::new();
        for binary in o.off_heap.iter().chain(&o.old_off_heap) {
            out.push((
                Arc::as_ptr(binary) as usize,
                binary.len(),
                Arc::strong_count(binary),
            ));
        }
        for binary in o.writable.iter().chain(&o.old_writable) {
            out.push((
                Arc::as_ptr(binary) as usize,
                binary.len(),
                Arc::strong_count(binary),
            ));
        }
        for binary in o.external.iter().chain(&o.old_external) {
            out.push((
                Arc::as_ptr(binary) as usize,
                binary.len(),
                Arc::strong_count(binary),
            ));
        }
        out.reverse();
        out
    }

    /// Minimum virtual binary heap capacity, in machine words.
    pub fn min_bin_vheap_size(&self) -> u64 {
        self.owners.vheap.min
    }

    /// Current young virtual binary heap usage, in machine words.
    pub fn bin_vheap_used(&self) -> u64 {
        self.bin_vheap
    }

    /// Current old virtual binary heap usage, in machine words.
    pub fn bin_old_vheap_used(&self) -> u64 {
        self.owners.vheap.old
    }

    /// Current young virtual binary heap block size, in machine words.
    pub fn bin_vheap_block_size(&self) -> u64 {
        self.bin_vheap_size
    }

    /// Current old virtual binary heap block size, in machine words.
    pub fn bin_old_vheap_block_size(&self) -> u64 {
        self.owners.vheap.old_size
    }

    /// Set the process minimum used by virtual binary heap growth.
    pub fn set_min_bin_vheap_size(&mut self, words: u64) {
        self.owners.vheap.min = words.max(46_422);
        self.bin_vheap_size = self.bin_vheap_size.max(self.owners.vheap.min);
        self.owners.vheap.old_size = self.owners.vheap.old_size.max(self.owners.vheap.min);
    }

    /// Account `words` of virtual binary heap to the young or old counter.
    pub(crate) fn add_vheap(&mut self, promote: bool, words: u64) {
        if promote {
            self.owners.vheap.old = self.owners.vheap.old.saturating_add(words);
        } else {
            self.bin_vheap = self.bin_vheap.saturating_add(words);
        }
    }

    /// Whether off-heap binary overhead has reached the young virtual heap limit.
    pub fn bin_vheap_gc_due(&self) -> bool {
        self.bin_vheap > self.bin_vheap_size
    }
}
impl Default for ProcessHeap {
    fn default() -> Self {
        Self::new()
    }
}
impl HeapAlloc for ProcessHeap {
    fn words_left(&self) -> Option<usize> {
        self.alloc_words_left()
    }
    // Port of erts/emulator/beam/erl_vm.h:164-173 (HRelease) and erl_process.h:1586-1598
    // (erts_heap_frag_shrink), OTP-29.1.1.
    fn release(&mut self, end: *mut u64, start: *mut u64) {
        if self.detached {
            if let Some(heap) = self.owners.detached.as_deref_mut() {
                heap.release(end, start);
            }
            return;
        }
        let base = self.words.as_ptr() as usize;
        let top = base + self.htop * 8;
        let address = start as usize;
        if address >= base && address < top && end as usize == top {
            self.htop = (address - base) / 8;
            return;
        }
        let Some(Fragment::Block { memory, used }) = self.fragments.last_mut() else {
            return;
        };
        let fragment_start = memory.as_ptr() as usize;
        let fragment_end = fragment_start.saturating_add(used.saturating_mul(8));
        if address >= fragment_start
            && address <= fragment_end
            && end as usize == fragment_end
            && (address - fragment_start).is_multiple_of(8)
        {
            let new_used = (address - fragment_start) / 8;
            self.fragment_words = self
                .fragment_words
                .saturating_sub(u32::try_from(*used - new_used).unwrap_or(u32::MAX));
            *used = new_used;
        }
    }
    #[inline]
    fn alloc(&mut self, words: usize) -> Option<*mut u64> {
        if self.detached {
            return self.owners.detached.as_deref_mut()?.alloc(words);
        }
        let limit = if self.native_allocation {
            self.heap_limit_words()
        } else {
            self.stop
        };
        let available = limit.saturating_sub(self.htop);
        if words > available {
            return None;
        }
        // SAFETY: htop is within the fixed boxed slice and capacity is checked.
        let ptr = unsafe { self.words.as_ptr().add(self.htop).cast::<u64>().cast_mut() };
        self.htop += words;
        Some(ptr)
    }
    fn alloc_fragment_only(&mut self, words: usize) -> Option<*mut u64> {
        // HeapFragOnlyAlloc reserves 512 extra words outside Valgrind builds.
        Some(self.heap_fragment_with_extra(words, 512))
    }
    fn retain_binary(&mut self, binary: Arc<RefcBinary>) {
        if self.detached
            && let Some(heap) = self.owners.detached.as_deref_mut()
        {
            return heap.retain_binary(binary);
        }
        // Port of erts/emulator/beam/erl_message.h:85 (OH_OVERHEAD), OTP-29.1.1.
        self.bin_vheap = self.bin_vheap.saturating_add((binary.len() / 8) as u64);
        self.owners.off_heap.push(binary);
    }
    fn retain_writable_binary(&mut self, binary: Arc<WritableBinary>) -> Result<(), TermError> {
        if self.detached
            && let Some(heap) = self.owners.detached.as_deref_mut()
        {
            return heap.retain_writable_binary(binary);
        }
        self.bin_vheap = self
            .bin_vheap
            .saturating_add((binary.capacity() / 8) as u64);
        self.owners.writable.push(binary);
        Ok(())
    }
    fn retain_writable_binary_with_apparent_size(
        &mut self,
        binary: Arc<WritableBinary>,
        apparent_size_bits: usize,
    ) -> Result<(), TermError> {
        if self.detached
            && let Some(heap) = self.owners.detached.as_deref_mut()
        {
            return heap.retain_writable_binary_with_apparent_size(binary, apparent_size_bits);
        }
        // Port of erl_bits.c:1691 (`build_writable_bitstring`), OTP-29.1.1.
        self.bin_vheap = self
            .bin_vheap
            .saturating_add((apparent_size_bits.div_ceil(8) / 8) as u64);
        self.owners.writable.push(binary);
        Ok(())
    }
    fn update_writable_binary_overhead(
        &mut self,
        source: Term,
        old_size_bits: usize,
        new_size_bits: usize,
    ) {
        if self.detached {
            if let Some(heap) = self.owners.detached.as_deref_mut() {
                heap.update_writable_binary_overhead(source, old_size_bits, new_size_bits);
            }
            return;
        }
        // Port of erl_bits.c:1660-1670 (`update_wb_overhead`), OTP-29.1.1.
        let overhead = |bits: usize| (bits.div_ceil(8) / 8) as u64;
        let increase = overhead(new_size_bits).saturating_sub(overhead(old_size_bits));
        let old_start = self.old_words.as_ptr() as usize;
        let old_end = old_start.saturating_add(self.old_htop.saturating_mul(8));
        let old_generation = crate::bits::writable_bin_ref_address(source)
            .is_some_and(|address| address >= old_start && address < old_end);
        self.add_vheap(old_generation, increase);
    }
    fn supports_writable_binary(&self) -> bool {
        true
    }
    fn retain_external_binary(&mut self, binary: Arc<ExternalBinary>) -> Result<(), TermError> {
        if self.detached
            && let Some(heap) = self.owners.detached.as_deref_mut()
        {
            return heap.retain_external_binary(binary);
        }
        self.owners.external.push(binary);
        Ok(())
    }
    fn supports_external_binary(&self) -> bool {
        true
    }
    fn retain_node(&mut self, node: Arc<Node>) {
        if self.detached
            && let Some(heap) = self.owners.detached.as_deref_mut()
        {
            return heap.retain_node(node);
        }
        self.owners.nodes.push(node);
    }
    fn retain_fun(&mut self, entry: Arc<FunEntry>) {
        if self.detached
            && let Some(heap) = self.owners.detached.as_deref_mut()
        {
            return heap.retain_fun(entry);
        }
        self.owners.funs.push(entry);
    }
    fn retain_export(&mut self, entry: Arc<ExportEntry>) {
        if self.detached
            && let Some(heap) = self.owners.detached.as_deref_mut()
        {
            return heap.retain_export(entry);
        }
        self.owners.exports.push(entry);
    }
    fn retain_magic(&mut self, owner: Arc<crate::MagicRef>) {
        if self.detached
            && let Some(heap) = self.owners.detached.as_deref_mut()
        {
            return heap.retain_magic(owner);
        }
        self.owners.magic.push(owner);
    }
    fn supports_magic(&self) -> bool {
        true
    }
}

enum HeapChunk {
    Ordinary(Vec<UnsafeCell<u64>>),
    Literal(crate::literal::LiteralChunk),
}

impl HeapChunk {
    fn new(words: usize, literal: bool) -> Option<Self> {
        if literal {
            crate::literal::allocate_chunk(words).map(Self::Literal)
        } else {
            Some(Self::Ordinary(Vec::with_capacity(words)))
        }
    }

    fn as_ptr(&self) -> *const UnsafeCell<u64> {
        match self {
            Self::Ordinary(chunk) => chunk.as_ptr(),
            Self::Literal(chunk) => chunk.as_ptr().cast(),
        }
    }

    fn capacity(&self) -> usize {
        match self {
            Self::Ordinary(chunk) => chunk.capacity(),
            Self::Literal(chunk) => chunk.capacity(),
        }
    }

    fn initialize_until(&mut self, start: usize, end: usize) -> bool {
        match self {
            Self::Ordinary(chunk) => {
                chunk.resize_with(end, || UnsafeCell::new(0));
                true
            }
            Self::Literal(chunk) => chunk.initialize_words(start, end),
        }
    }
}

/// Growable heap whose separately allocated chunks never move.
pub struct VecHeap {
    // Each chunk reserves its full capacity up front and never grows past it, so words
    // handed out stay put; only words actually allocated are initialized.
    chunks: Vec<HeapChunk>,
    off_heap: Vec<Arc<RefcBinary>>,
    writable: Vec<Arc<WritableBinary>>,
    external: Vec<Arc<ExternalBinary>>,
    nodes: Vec<Arc<Node>>,
    funs: Vec<Arc<FunEntry>>,
    exports: Vec<Arc<ExportEntry>>,
    magic: Vec<Arc<crate::MagicRef>>,
    used: usize,
    total_used: usize,
    chunk_words: usize,
}

// SAFETY: Reading an allocated literal through a shared heap is safe. Every
// operation that can write or grow VecHeap requires exclusive `&mut self`.
unsafe impl Sync for VecHeap {}
impl VecHeap {
    /// Create a standalone heap.
    pub fn new() -> Self {
        Self {
            chunks: Vec::new(),
            off_heap: Vec::new(),
            writable: Vec::new(),
            external: Vec::new(),
            nodes: Vec::new(),
            funs: Vec::new(),
            exports: Vec::new(),
            magic: Vec::new(),
            used: 0,
            total_used: 0,
            chunk_words: 1024,
        }
    }
    /// Create a stable heap for module literal terms.
    pub fn new_literal() -> Self {
        let mut heap = Self::new();
        heap.chunk_words |= LITERAL_HEAP_BIT;
        heap
    }
    fn with_literal_chunk_words(words: usize) -> Self {
        let mut heap = Self::new();
        heap.chunk_words = words.max(1) | LITERAL_HEAP_BIT;
        heap
    }
    fn is_literal_area(&self) -> bool {
        self.chunk_words & LITERAL_HEAP_BIT != 0
    }
    fn next_chunk_words(&self) -> usize {
        self.chunk_words & !LITERAL_HEAP_BIT
    }
    /// Number of allocated words.
    pub fn used_words(&self) -> usize {
        self.total_used
    }
    /// Whether a pointer belongs to any allocation in this area.
    pub fn contains(&self, ptr: *const u64) -> bool {
        let address = ptr as usize;
        self.chunks.iter().any(|chunk| {
            address >= chunk.as_ptr() as usize
                && address < (chunk.as_ptr() as usize + chunk.capacity() * 8)
        })
    }
    /// Address ranges occupied by initialized or reserved heap chunks.
    pub fn pointer_ranges(&self) -> Vec<(usize, usize)> {
        self.chunks
            .iter()
            .map(|chunk| {
                let start = chunk.as_ptr() as usize;
                (start, start.saturating_add(chunk.capacity() * 8))
            })
            .collect()
    }
}
impl Default for VecHeap {
    fn default() -> Self {
        Self::new()
    }
}
impl Drop for VecHeap {
    fn drop(&mut self) {
        for chunk in &self.chunks {
            #[cfg(any(feature = "validate-terms", debug_assertions, test))]
            crate::validate::forget_stable_range(chunk.as_ptr() as usize);
        }
    }
}
impl HeapAlloc for VecHeap {
    fn alloc(&mut self, words: usize) -> Option<*mut u64> {
        let needed = self.used.checked_add(words)?;
        if self.chunks.is_empty() || needed > self.chunks.last()?.capacity() {
            let size = self.next_chunk_words().max(words);
            // erts hands out heap words uninitialized (erl_alloc.c); reserving without
            // zeroing keeps a short-lived heap from touching its whole first chunk.
            self.chunks
                .push(HeapChunk::new(size, self.is_literal_area())?);
            self.used = 0;
            let literal_bit = self.chunk_words & LITERAL_HEAP_BIT;
            self.chunk_words = self.next_chunk_words().saturating_mul(2) | literal_bit;
            // g_asan: literal areas and other VecHeaps stay address-stable.
            #[cfg(any(feature = "validate-terms", debug_assertions, test))]
            if let Some(chunk) = self.chunks.last() {
                crate::validate::note_stable_range(chunk.as_ptr() as usize, chunk.capacity() * 8);
            }
        }
        let chunk = self.chunks.last_mut()?;
        let end = self.used + words;
        // Within the reserved capacity: the buffer does not move.
        if !chunk.initialize_until(self.used, end) {
            return None;
        }
        // SAFETY: checked against chunk length above.
        let ptr = unsafe { chunk.as_ptr().add(self.used).cast::<u64>().cast_mut() };
        self.used += words;
        self.total_used += words;
        Some(ptr)
    }
    fn retain_binary(&mut self, binary: Arc<RefcBinary>) {
        self.off_heap.push(binary);
    }
    fn retain_writable_binary(&mut self, binary: Arc<WritableBinary>) -> Result<(), TermError> {
        self.writable.push(binary);
        Ok(())
    }
    fn supports_writable_binary(&self) -> bool {
        true
    }
    fn retain_external_binary(&mut self, binary: Arc<ExternalBinary>) -> Result<(), TermError> {
        self.external.push(binary);
        Ok(())
    }
    fn supports_external_binary(&self) -> bool {
        true
    }
    fn retain_node(&mut self, node: Arc<Node>) {
        self.nodes.push(node);
    }
    fn retain_fun(&mut self, entry: Arc<FunEntry>) {
        self.funs.push(entry);
    }
    fn retain_export(&mut self, entry: Arc<ExportEntry>) {
        self.exports.push(entry);
    }
    fn retain_magic(&mut self, owner: Arc<crate::MagicRef>) {
        self.magic.push(owner);
    }
    fn supports_magic(&self) -> bool {
        true
    }
}

/// Immutable module literals. Address-range checks avoid consuming a pointer tag bit.
pub struct LiteralArea {
    heap: VecHeap,
}
impl LiteralArea {
    /// Create an empty literal area.
    pub fn new() -> Self {
        Self {
            heap: VecHeap::new_literal(),
        }
    }
    /// Reserve a first chunk sized for a known literal graph.
    pub fn with_capacity_words(words: usize) -> Self {
        Self {
            heap: VecHeap::with_literal_chunk_words(words),
        }
    }
    /// Build literals before publishing the area to readers.
    pub fn builder(&mut self) -> TermBuilder<'_, VecHeap> {
        TermBuilder::new(&mut self.heap)
    }
    /// Copy a term and all of its children into this unpublished area.
    pub fn copy_from(&mut self, term: Term) -> Result<Term, TermError> {
        crate::copy_term_preserving_sharing(term, &mut self.heap)
    }
    /// Number of initialized words in this area.
    pub fn used_words(&self) -> usize {
        self.heap.used_words()
    }
    /// Check whether a tagged pointer lies in this area's allocations.
    pub fn is_literal(&self, term: Term) -> bool {
        term.is_pointer() && self.heap.contains((term.bits() & !7) as *const u64)
    }
    /// Address ranges used by the literal-reference collector's pointer checks.
    pub fn pointer_ranges(&self) -> Vec<(usize, usize)> {
        self.heap.pointer_ranges()
    }
}
impl Default for LiteralArea {
    fn default() -> Self {
        Self::new()
    }
}

/// Build terms in any stable heap. Methods report exhaustion without moving objects.
pub struct TermBuilder<'a, H: HeapAlloc + ?Sized> {
    pub(crate) heap: &'a mut H,
}
impl<'a, H: HeapAlloc + ?Sized> TermBuilder<'a, H> {
    /// Attach a builder to a heap.
    pub fn new(heap: &'a mut H) -> Self {
        Self { heap }
    }
    pub(crate) fn words(&mut self, words: usize) -> Result<*mut u64, TermError> {
        self.heap.alloc(words).ok_or(TermError::HeapFull)
    }
    /// Build a tuple with OTP's arity header.
    pub fn tuple(&mut self, values: &[Term]) -> Result<Term, TermError> {
        self.tuple_iter(values.len(), values.iter().copied())
    }

    /// Build a tuple from an exact-length iterator without staging its elements.
    pub fn tuple_iter(
        &mut self,
        len: usize,
        mut values: impl ExactSizeIterator<Item = Term>,
    ) -> Result<Term, TermError> {
        if values.len() != len {
            return Err(TermError::BadArg);
        }
        self.tuple_from_fn(len, |_, _| {
            values.next().expect("tuple iterator length was checked")
        })
    }

    /// Build a tuple while reading each element from the heap that will own it.
    pub fn tuple_from_fn(
        &mut self,
        len: usize,
        mut value_at: impl FnMut(usize, &mut H) -> Term,
    ) -> Result<Term, TermError> {
        if len > (1 << 24) - 1 {
            return Err(TermError::SystemLimit);
        }
        if len == 0 {
            return Ok(Term::from_ptr((&EMPTY_TUPLE as *const u64).cast_mut(), 2));
        }
        let p = self.words(len + 1)?;
        store(p, (len as u64) << 6 | ARITY);
        for i in 0..len {
            // words() reserved exactly the header and elements.
            store(p.wrapping_add(i + 1), value_at(i, self.heap).bits());
        }
        Ok(Term::from_ptr(p, 2))
    }

    /// Append `{first, second, _}` to a destructively patched 3-tuple chain.
    ///
    /// The previous tuple's tail slot is patched to point at the new one, like
    /// `*patch_ptr = make_tuple(hp); patch_ptr = &hp[3];` in erl_map.c.
    // Port of erts/emulator/beam/erl_map.c:3920-3927 (iterator tuple chain), OTP-29.1.1.
    #[inline(always)]
    pub fn chain3_push(
        &mut self,
        chain: &mut Tuple3Chain,
        first: Term,
        second: Term,
    ) -> Result<(), TermError> {
        let words = self.words(4)?;
        store(words, (3u64 << 6) | ARITY);
        store(words.wrapping_add(1), first.bits());
        store(words.wrapping_add(2), second.bits());
        store(words.wrapping_add(3), Term::NIL.bits());
        let tuple = Term::from_ptr(words, 2);
        match chain.last {
            Some(last) => store(last.wrapping_add(3), tuple.bits()),
            None => chain.head = tuple,
        }
        chain.last = Some(words);
        Ok(())
    }

    /// Box a positive bignum from little-endian digits without normalising to a small.
    pub fn pos_bignum_from_digits(&mut self, digits: &[u64]) -> Result<Term, TermError> {
        let p = self.words(1 + digits.len())?;
        self.write_bignum(p, digits.len(), Sign::Plus, |index| digits[index]);
        Ok(Term::from_ptr(p, 2))
    }

    /// Write `STRING_EXT` bytes as one contiguous run of cons cells.
    /// Port of erts/emulator/beam/external.c:4615 (STRING_EXT), OTP-29.1.1.
    pub fn byte_string_list(&mut self, bytes: &[u8]) -> Result<Term, TermError> {
        if bytes.is_empty() {
            return Ok(Term::NIL);
        }
        let words = bytes.len().checked_mul(2).ok_or(TermError::SystemLimit)?;
        let p = self.words(words)?;
        for (i, byte) in bytes.iter().enumerate() {
            let cell = p.wrapping_add(i * 2);
            store(cell, Term::small(i64::from(*byte)).unwrap().bits());
            let tail = if i + 1 == bytes.len() {
                Term::NIL.bits()
            } else {
                Term::from_ptr(cell.wrapping_add(2), 1).bits()
            };
            store(cell.wrapping_add(1), tail);
        }
        Ok(Term::from_ptr(p, 1))
    }

    /// Build a two-word cons cell.
    pub fn cons(&mut self, head: Term, tail: Term) -> Result<Term, TermError> {
        let p = self.words(2)?;
        // SAFETY: two words were reserved.
        unsafe {
            *p = head.bits();
            *p.add(1) = tail.bits();
        }
        Ok(Term::from_ptr(p, 1))
    }
    /// Build a list in iteration order.
    pub fn list_from_iter(
        &mut self,
        values: impl IntoIterator<Item = Term>,
    ) -> Result<Term, TermError> {
        let values: Vec<Term> = values.into_iter().collect();
        let mut tail = Term::NIL;
        for value in values.into_iter().rev() {
            tail = self.cons(value, tail)?;
        }
        Ok(tail)
    }
    /// Build a list from a slice without staging the elements.
    pub fn list_from_slice(&mut self, values: &[Term]) -> Result<Term, TermError> {
        let mut tail = Term::NIL;
        for value in values.iter().rev() {
            tail = self.cons(*value, tail)?;
        }
        Ok(tail)
    }
    /// Build a list of Unicode scalar values.
    pub fn string_to_list(&mut self, text: &str) -> Result<Term, TermError> {
        self.list_from_iter(text.chars().map(|c| Term::small(c as i64).unwrap()))
    }
    /// Box a 64-bit float, retaining its exact bit pattern.
    pub fn float(&mut self, value: f64) -> Result<Term, TermError> {
        let p = self.words(2)?;
        // SAFETY: two words were reserved.
        unsafe {
            *p = (1 << 6) | FLOAT;
            *p.add(1) = value.to_bits();
        }
        Ok(Term::from_ptr(p, 2))
    }
    /// Select immediate or bignum storage for an `i64`.
    pub fn int_from_i64(&mut self, value: i64) -> Result<Term, TermError> {
        self.int_from_bigint(&BigInt::from(value))
    }
    /// Select immediate or bignum storage for an `i128`.
    pub fn int_from_i128(&mut self, value: i128) -> Result<Term, TermError> {
        self.int_from_bigint(&BigInt::from(value))
    }
    /// Select immediate or positive bignum storage for an unsigned integer.
    pub fn int_from_u64(&mut self, value: u64) -> Result<Term, TermError> {
        if value <= MAX_SMALL as u64 {
            return Ok(Term::small(value as i64).unwrap());
        }
        let p = self.words(2)?;
        self.write_bignum(p, 1, Sign::Plus, |index| if index == 0 { value } else { 0 });
        Ok(Term::from_ptr(p, 2))
    }
    /// Box little-endian 64-bit magnitude digits when outside the small range.
    pub fn int_from_bigint(&mut self, value: &BigInt) -> Result<Term, TermError> {
        if let Some(n) = value.to_i64()
            && (MIN_SMALL..=MAX_SMALL).contains(&n)
        {
            return Ok(Term::small(n).unwrap());
        }
        let (sign, bytes) = value.to_bytes_le();
        let digits = bytes.len().div_ceil(8);
        if digits > 65_535 {
            return Err(TermError::SystemLimit);
        }
        let p = self.words(1 + digits)?;
        self.write_bignum(p, digits, sign, |index| {
            let start = index * 8;
            let end = (start + 8).min(bytes.len());
            let mut digit = [0; 8];
            digit[..end - start].copy_from_slice(&bytes[start..end]);
            u64::from_le_bytes(digit)
        });
        Ok(Term::from_ptr(p, 2))
    }

    fn write_bignum(
        &mut self,
        p: *mut u64,
        digits: usize,
        sign: Sign,
        mut digit_at: impl FnMut(usize) -> u64,
    ) {
        // SAFETY: the allocation reserves one header word and `digits` digit words.
        unsafe {
            *p = ((digits as u64) << 6)
                | if sign == Sign::Minus {
                    NEG_BIG
                } else {
                    POS_BIG
                };
            for index in 0..digits {
                *p.add(index + 1) = digit_at(index);
            }
        }
    }
    /// Build a byte-aligned binary.
    pub fn binary(&mut self, bytes: &[u8]) -> Result<Term, TermError> {
        self.bitstring(bytes, bytes.len() * 8)
    }
    /// Build a bitstring with high bits significant in its final byte.
    pub fn bitstring(&mut self, bytes: &[u8], bit_len: usize) -> Result<Term, TermError> {
        if bit_len > bytes.len().saturating_mul(8) {
            return Err(TermError::BadArg);
        }
        let count = bit_len.div_ceil(8);
        if count <= 64 {
            let words = 2 + count.div_ceil(8);
            let p = self.words(words)?;
            // SAFETY: allocation includes count rounded to whole words.
            unsafe {
                *p = (((words - 1) as u64) << 6) | HEAP_BITS;
                *p.add(1) = bit_len as u64;
                std::ptr::copy_nonoverlapping(bytes.as_ptr(), p.add(2).cast::<u8>(), count);
                if !bit_len.is_multiple_of(8) && count > 0 {
                    let last = p.add(2).cast::<u8>().add(count - 1);
                    *last &= 0xff << (8 - (bit_len % 8));
                }
            }
            return Ok(Term::from_ptr(p, 2));
        }
        let mut data = bytes[..count].to_vec();
        if !bit_len.is_multiple_of(8)
            && let Some(last) = data.last_mut()
        {
            *last &= 0xff << (8 - bit_len % 8);
        }
        let binary = Arc::new(RefcBinary::new(data));
        let adjustment = binary.as_ptr() as usize & 3;
        let ref_ptr = self.words(8)?;
        // SAFETY: the same allocation reserves three BinRef and five SubBits words.
        let sub_ptr = unsafe { ref_ptr.add(3) };
        // SAFETY: both word ranges are reserved; Arc owns stable vector data.
        unsafe {
            *ref_ptr = (2 << 6) | BIN_REF;
            *ref_ptr.add(1) = Arc::as_ptr(&binary) as u64;
            *ref_ptr.add(2) = (adjustment as u64) << 1;
            *sub_ptr = (4 << 6) | SUB_BITS;
            *sub_ptr.add(1) = binary.as_ptr() as u64 & !3;
            *sub_ptr.add(2) = (adjustment * 8) as u64;
            *sub_ptr.add(3) = (bit_len + adjustment * 8) as u64;
            *sub_ptr.add(4) = Term::from_ptr(ref_ptr, 2).bits();
        }
        self.heap.retain_binary(binary);
        Ok(Term::from_ptr(sub_ptr, 2))
    }
    /// Create a slice of a bitstring, retaining the original owner.
    pub fn sub_binary(
        &mut self,
        original: Term,
        start: usize,
        bit_len: usize,
    ) -> Result<Term, TermError> {
        crate::bits::writable_finalize(original);
        // SAFETY: The original binary and heap remain live during construction.
        let view = unsafe { original.binary_ref() }.ok_or(TermError::BadArg)?;
        if start
            .checked_add(bit_len)
            .is_none_or(|end| end > view.bit_len())
        {
            return Err(TermError::BadArg);
        }
        let mut owner = original;
        while owner.header().is_some_and(|h| h & 63 == SUB_BITS) {
            // SAFETY: a live SubBits has its original term in word four.
            owner = Term(unsafe { *owner.raw_ptr().add(4) });
        }
        if owner.header().is_some_and(|h| h & 63 == HEAP_BITS) {
            let mut bytes = vec![0; bit_len.div_ceil(8)];
            for i in 0..bit_len {
                let src = view.start_bit() + start + i;
                bytes[i / 8] |= ((view.bytes()[src / 8] >> (7 - src % 8)) & 1) << (7 - i % 8);
            }
            return self.bitstring(&bytes, bit_len);
        }
        if owner.header().is_none_or(|h| h & 63 != BIN_REF) {
            return Err(TermError::BadArg);
        }
        if !self.heap.supports_writable_binary() && crate::bits::binary_owner_is_writable(owner) {
            return Err(TermError::Unsupported("writable binary heap owner"));
        }
        let p = self.words(8)?;
        // SAFETY: the BinRef pointer is held by the original heap.
        let (binary, flags) = unsafe { crate::bits::clone_binary_owner(owner) };
        // SAFETY: eight reserved words hold a BinRef followed by a SubBits.
        let sub = unsafe { p.add(3) };
        let absolute = view.start_bit() + start;
        let adjustment = owner_adjustment(owner);
        // SAFETY: the new BinRef owns the Arc data and both objects are initialized.
        unsafe {
            *p = (2 << 6) | BIN_REF;
            *p.add(1) = binary;
            *p.add(2) = flags;
            *sub = (4 << 6) | SUB_BITS;
            *sub.add(1) = binary_data(p) as u64 & !3;
            *sub.add(2) = (absolute + adjustment * 8) as u64;
            *sub.add(3) = (absolute + bit_len + adjustment * 8) as u64;
            *sub.add(4) = Term::from_ptr(p, 2).bits();
        }
        // SAFETY: clone_binary_owner returned an owned Arc raw pointer.
        unsafe { crate::bits::retain_cloned_binary_owner(self.heap, binary, flags)? };
        Ok(Term::from_ptr(sub, 2))
    }
    /// Construct a sorted flatmap; last duplicate key wins.
    pub fn flatmap_from_pairs(&mut self, pairs: &[(Term, Term)]) -> Result<Term, TermError> {
        // Port of erts/emulator/beam/erl_utils.h:267 (erts_cmp_flatmap_keys), OTP-29.1.1.
        let mut sorted: Vec<_> = pairs.iter().copied().enumerate().collect();
        sorted.sort_by(|a, b| flat_key_cmp(a.1.0, b.1.0).then(a.0.cmp(&b.0)));
        let mut unique: Vec<(Term, Term)> = Vec::with_capacity(sorted.len());
        for (_, pair) in sorted {
            if unique.last().is_some_and(|prior| exact_eq(prior.0, pair.0)) {
                *unique.last_mut().unwrap() = pair;
            } else {
                unique.push(pair);
            }
        }
        if unique.len() > 32 {
            return crate::hamt::build_hamt_from_unique(&unique, self.heap);
        }
        let keys = self.tuple(&unique.iter().map(|p| p.0).collect::<Vec<_>>())?;
        let values: Vec<Term> = unique.iter().map(|p| p.1).collect();
        self.flatmap_with_key_tuple(keys, &values)
    }
    /// Construct a flatmap that shares a sorted key tuple, allocating its header and values.
    ///
    /// Port of erts/emulator/beam/beam_common.c:2203-2283 (`erts_gc_update_map_exact`), OTP-29.1.1.
    pub fn flatmap_with_key_tuple(
        &mut self,
        keys: Term,
        values: &[Term],
    ) -> Result<Term, TermError> {
        // `keys` must be the sorted key tuple of a flatmap with exactly `values.len()` keys (the caller's map).
        if keys.classify() != crate::TermKind::Tuple
            || keys
                .header()
                .is_none_or(|header| (header >> 6) as usize != values.len())
            || values.len() > 32
        {
            return Err(TermError::BadArg);
        }
        let p = self.words(3 + values.len())?;
        // SAFETY: header, size, keys, values are reserved.
        unsafe {
            *p = MAP;
            *p.add(1) = values.len() as u64;
            *p.add(2) = keys.bits();
            for (i, value) in values.iter().enumerate() {
                *p.add(3 + i) = value.bits();
            }
        }
        Ok(Term::from_ptr(p, 2))
    }
    /// Port of erts/emulator/beam/erl_record.c:701-779 (records_create_4), OTP-29.1.1.
    /// Construct a native record, reusing the canonical definition of its module when one
    /// matches (`erts_canonical_record_def`). Fields are supplied in definition order and
    /// stored in atom-index order.
    pub fn native_record(
        &mut self,
        module: Atom,
        name: Atom,
        exported: bool,
        fields: &[(Atom, Term)],
    ) -> Result<Term, TermError> {
        let layout = RecordLayout::new(module, name, exported, fields.iter().map(|(k, _)| *k))?;
        let definition = match crate::record_table::canonical_definition(&layout) {
            Some(canonical) => canonical,
            None => self.record_definition_tuple(&layout)?,
        };
        let values: Vec<_> = layout
            .sorted
            .iter()
            .map(|(original_index, _)| fields[*original_index].1)
            .collect();
        self.native_record_instance(definition, &values)
    }
    /// Port of erts/emulator/beam/beam_file.c:1100-1310 (parse_record_chunk), OTP-29.1.1.
    /// Build the literal `[Definition | DefaultValues]` cons of one compiler-emitted record:
    /// the definition tuple and a tuple of default values in atom-index order, where
    /// `None` (a field without default) is stored as `catch(0)`.
    pub fn native_record_literal(
        &mut self,
        module: Atom,
        name: Atom,
        exported: bool,
        fields: &[(Atom, Option<Term>)],
    ) -> Result<Term, TermError> {
        let layout = RecordLayout::new(module, name, exported, fields.iter().map(|(k, _)| *k))?;
        let definition = self.record_definition_tuple(&layout)?;
        let defaults: Vec<_> = layout
            .sorted
            .iter()
            .map(|(original_index, _)| fields[*original_index].1.unwrap_or(Term::catch(0)))
            .collect();
        let defaults = self.tuple(&defaults)?;
        self.cons(definition, defaults)
    }
    fn record_definition_tuple(&mut self, layout: &RecordLayout) -> Result<Term, TermError> {
        let count = layout.sorted.len();
        let order: Vec<Term> = layout
            .order
            .iter()
            .map(|index| Term::small(*index as i64).unwrap_or(Term::NIL))
            .collect();
        let order = self.tuple(&order)?;
        let def = self.words(6 + count)?;
        // SAFETY: definition tuple has header and 5 fields plus field keys.
        unsafe {
            *def = ((5 + count) as u64) << 6 | ARITY;
            *def.add(1) = order.bits();
            *def.add(2) = Term::small(i64::from(layout.hash))
                .unwrap_or(Term::NIL)
                .bits();
            *def.add(3) = Term::atom(layout.module).bits();
            *def.add(4) = Term::atom(layout.name).bits();
            *def.add(5) = layout.exported_term().bits();
            for (i, (_, key)) in layout.sorted.iter().enumerate() {
                *def.add(6 + i) = Term::atom(*key).bits();
            }
        }
        Ok(Term::from_ptr(def, 2))
    }
    /// Copy a native record with selected field replacements.
    pub fn update_native_record(
        &mut self,
        snapshot: &RecordSnapshot,
        changes: &[(Atom, Term)],
    ) -> Result<Term, TermError> {
        if changes.is_empty() {
            return Ok(snapshot.instance);
        }
        let mut values = snapshot.values.clone();
        for (key, value) in changes {
            let Some(original_index) = snapshot.fields.iter().position(|field| field == key) else {
                return Err(TermError::BadArg);
            };
            let sorted_index = snapshot.fields[..original_index]
                .iter()
                .filter(|field| field.0 < key.0)
                .count()
                + snapshot.fields[original_index + 1..]
                    .iter()
                    .filter(|field| field.0 < key.0)
                    .count();
            let slot = values.get_mut(sorted_index).ok_or(TermError::BadArg)?;
            *slot = *value;
        }
        self.native_record_instance(snapshot.definition, &values)
    }
    /// Build an instance of `definition` from field values in atom-index order.
    pub fn native_record_instance(
        &mut self,
        definition: Term,
        values: &[Term],
    ) -> Result<Term, TermError> {
        let instance = self.words(2 + values.len())?;
        // SAFETY: instance has header, definition pointer, and all field values.
        unsafe {
            *instance = ((1 + values.len()) as u64) << 6 | RECORD;
            *instance.add(1) = definition.bits();
            for (i, value) in values.iter().enumerate() {
                *instance.add(2 + i) = value.bits();
            }
        }
        Ok(Term::from_ptr(instance, 2))
    }
    /// Construct a local fun, with a two-word head and captured environment.
    pub fn local_fun(&mut self, entry: Arc<FunEntry>, free: &[Term]) -> Result<Term, TermError> {
        let header =
            crate::fun::local_header(entry.arity, free.len()).ok_or(TermError::SystemLimit)?;
        let p = self.words(2 + free.len())?;
        // SAFETY: header, entry pointer, and environment words were reserved.
        unsafe {
            *p = header;
            *p.add(1) = Arc::as_ptr(&entry) as u64;
            for (i, value) in free.iter().enumerate() {
                *p.add(2 + i) = value.bits();
            }
        }
        self.heap.retain_fun(entry);
        Ok(Term::from_ptr(p, 2))
    }
    /// Construct an export fun with no environment.
    pub fn export_fun(&mut self, entry: Arc<ExportEntry>) -> Result<Term, TermError> {
        // An export fun points at its node's export entry, never at a detached copy: entries
        // built without a node (literals, `binary_to_term`) are looked up in the export table.
        // Port of erts/emulator/beam/external.c (dec_term FUN_EXT/EXPORT_EXT:
        // erts_export_get_or_make_stub), OTP-29.1.1.
        let entry = if entry.info() == 0 {
            crate::fun::export_get_or_make_stub(entry.module, entry.function, entry.arity)
        } else {
            entry
        };
        let p = self.words(2)?;
        // SAFETY: the two-word fun head was reserved.
        unsafe {
            *p = crate::fun::export_header(entry.arity);
            *p.add(1) = Arc::as_ptr(&entry) as u64;
        }
        self.heap.retain_export(entry);
        Ok(Term::from_ptr(p, 2))
    }
    /// Construct an external pid with the OTP four-word ExternalThing head.
    pub fn external_pid(
        &mut self,
        node: Arc<Node>,
        index: u32,
        serial: u32,
    ) -> Result<Term, TermError> {
        let p = self.words(4)?;
        // SAFETY: four words are reserved and the retained Arc keeps the node pointer live.
        unsafe {
            *p = (3 << 6) | EXTERNAL_PID;
            *p.add(1) = Arc::as_ptr(&node) as u64;
            *p.add(2) = 0;
            *p.add(3) = (index as u64) | ((serial as u64) << 32);
        }
        self.heap.retain_node(node);
        Ok(Term::from_ptr(p, 2))
    }
    /// Construct an external port.
    pub fn external_port(&mut self, node: Arc<Node>, id: u64) -> Result<Term, TermError> {
        let p = self.words(4)?;
        // SAFETY: four words are reserved and the retained Arc keeps the node pointer live.
        unsafe {
            *p = (3 << 6) | EXTERNAL_PORT;
            *p.add(1) = Arc::as_ptr(&node) as u64;
            *p.add(2) = 0;
            *p.add(3) = id;
        }
        self.heap.retain_node(node);
        Ok(Term::from_ptr(p, 2))
    }
    /// Construct an external ordinary or pid reference.
    // Port of erts/emulator/beam/erl_term.h:1142-1161 (ExternalThing layout), OTP-29.1.1.
    pub fn external_ref(&mut self, node: Arc<Node>, ids: &[u32]) -> Result<Term, TermError> {
        check_external_ref(ids)?;
        let words = 3 + (ids.len() + 1).div_ceil(2);
        let p = self.words(words)?;
        // SAFETY: words includes the external head and packed 32-bit count and ids.
        unsafe {
            *p = (((words - 1) as u64) << 6) | EXTERNAL_REF;
            *p.add(1) = Arc::as_ptr(&node) as u64;
            *p.add(2) = 0;
            *p.add(3) = ids.len() as u64;
            // Heap words are not cleared on allocation; the id words are OR-ed together.
            for word in 4..words {
                *p.add(word) = 0;
            }
            for (i, id) in ids.iter().enumerate() {
                let index = i + 1;
                let slot = p.add(3 + index / 2);
                if index % 2 == 0 {
                    *slot |= *id as u64;
                } else {
                    *slot |= (*id as u64) << 32;
                }
            }
        }
        self.heap.retain_node(node);
        Ok(Term::from_ptr(p, 2))
    }
    /// Construct an ordinary local reference (three 32-bit components).
    #[inline]
    pub fn local_ref(&mut self, ids: [u32; 3]) -> Result<Term, TermError> {
        Term::local_ref(self.heap, ids)
    }
}

impl Term {
    /// Construct an ordinary local reference (three 32-bit components) directly on any heap.
    #[inline]
    pub fn local_ref(
        heap: &mut (impl HeapAlloc + ?Sized),
        ids: [u32; 3],
    ) -> Result<Self, TermError> {
        let p = heap.alloc(3).ok_or(TermError::HeapFull)?;
        // SAFETY: three words reserved, matching ErtsORefThing on little endian.
        unsafe {
            *p = (2 << 6) | REF;
            *p.add(1) = ((ids[0] as u64) << 32) | 0xffff_ffff;
            *p.add(2) = ((ids[2] as u64) << 32) | ids[1] as u64;
        }
        Ok(Term::from_ptr(p, 2))
    }
}

impl<'a, H: HeapAlloc + ?Sized> TermBuilder<'a, H> {
    /// Box a reference to an opaque owner for NIF resources and future native handles.
    pub fn magic_ref(&mut self, owner: Arc<crate::MagicRef>) -> Result<Term, TermError> {
        if !self.heap.supports_magic() {
            return Err(TermError::Unsupported("magic reference heap owner"));
        }
        let p = self.words(3)?;
        // Port of erts/emulator/beam/erl_term.h:883-890 (write_magic_ref_thing), OTP-29.1.1:
        // an ErtsMRefThing is header, magic binary pointer and the off-heap `next` slot.
        // The heap's off-heap owner list holds the reference count, so `next` stays null.
        // SAFETY: three reserved words hold the ErtsMRefThing.
        unsafe {
            *p = crate::REF_THING_HEADER;
            *p.add(1) = Arc::as_ptr(&owner) as u64;
            *p.add(2) = 0;
        }
        self.heap.retain_magic(owner);
        Ok(Term::from_ptr(p, 2))
    }
}

/// Borrowed bitstring view. An unaligned slice includes the surrounding bytes;
/// `start_bit` and `bit_len` identify the significant bit interval.
pub struct BinaryRef<'a> {
    bytes: &'a [u8],
    start: usize,
    bits: usize,
}
impl BinaryRef<'_> {
    /// Whole backing bytes; unused bits may be present at the ends.
    pub fn bytes(&self) -> &[u8] {
        self.bytes
    }
    /// Number of significant bits.
    pub fn bit_len(&self) -> usize {
        self.bits
    }
    /// Starting bit within the backing data.
    pub fn start_bit(&self) -> usize {
        self.start
    }
}
impl Term {
    /// Borrow a binary's underlying bytes.
    ///
    /// # Safety
    /// The owning heap and any off-heap binary owner must remain live. No
    /// writable append may run while a view of its owner is retained.
    pub unsafe fn binary_ref<'a>(self) -> Option<BinaryRef<'a>> {
        let header = self.header()?;
        // SAFETY: The header determines the initialized object layout.
        let p = unsafe { self.raw_ptr() };
        if header & 63 == HEAP_BITS {
            // SAFETY: HeapBits has size in word 1 and data starting in word 2.
            let bits = unsafe { *p.add(1) } as usize;
            // SAFETY: HeapBits data begins at word two.
            let base = unsafe { p.add(2).cast::<u8>() };
            // SAFETY: The builder allocated ceil(bits / 8) data bytes.
            let bytes = unsafe { std::slice::from_raw_parts(base, bits.div_ceil(8)) };
            Some(BinaryRef {
                bytes,
                start: 0,
                bits,
            })
        } else if header & 63 == SUB_BITS {
            // SAFETY: SUB_BITS stores start/end and a live original in word four.
            let (start, end, original) =
                unsafe { (*p.add(2) as usize, *p.add(3) as usize, Term(*p.add(4))) };
            let adjustment = owner_adjustment(original) * 8;
            let base = if original.header().is_some_and(|h| h & 63 == BIN_REF) {
                // SAFETY: original is a retained BinRef and the caller prevents mutation.
                unsafe { binary_data(original.raw_ptr()) }
            } else {
                // SAFETY: a match context may refer directly to live HeapBits data.
                unsafe { original.raw_ptr().add(2).cast::<u8>() }
            };
            // SAFETY: The original allocation keeps this bit interval live.
            let bytes = unsafe { std::slice::from_raw_parts(base, (end - adjustment).div_ceil(8)) };
            Some(BinaryRef {
                bytes,
                start: start - adjustment,
                bits: end - start,
            })
        } else {
            None
        }
    }
}
#[cfg(test)]
mod heap_block_tests {
    use super::{HeapAlloc, ProcessHeap};

    #[test]
    fn realloc_preserves_the_user_prefix_and_can_shrink() {
        let mut heap = ProcessHeap::with_words(64);
        assert!(heap.old_words.is_empty());
        heap.words.words_mut()[0] = 0x1111;
        heap.words.words_mut()[3] = 0x2222;
        heap.words.words_mut()[60] = 0x3333;
        heap.words.realloc(128);
        assert_eq!(heap.words.len(), 128);
        assert_eq!(heap.words.words()[0], 0x1111);
        assert_eq!(heap.words.words()[3], 0x2222);
        assert_eq!(heap.words.words()[60], 0x3333);
        heap.words.realloc(32);
        assert_eq!(heap.words.len(), 32);
        assert_eq!(heap.words.words()[0], 0x1111);
        assert_eq!(heap.words.words()[3], 0x2222);
    }

    #[test]
    fn heap_fragment_reuses_hallocx_extra_words() {
        let mut heap = ProcessHeap::with_words(1);
        let first = heap.heap_fragment_with_extra(2, 200);
        let second = heap.heap_fragment_with_extra(3, 200);

        assert_eq!(
            second as usize,
            first as usize + 2 * std::mem::size_of::<u64>()
        );
        assert_eq!(heap.mbuf_size(), 5);
        let released_to = second as usize + std::mem::size_of::<u64>();
        let end = (second as usize + 3 * std::mem::size_of::<u64>()) as *mut u64;
        heap.release(end, released_to as *mut u64);
        assert_eq!(heap.mbuf_size(), 3);
        assert_eq!(heap.heap_fragment_with_extra(1, 200) as usize, released_to);
    }
}
