//! Stable word allocations. Every pointer remains valid until its heap is dropped.
use crate::bits::{ExternalBinary, RefcBinary, WritableBinary, binary_data, owner_adjustment};
use crate::identity::check_external_ref;
use crate::record::RecordSnapshot;
use crate::record_table::RecordLayout;
use crate::{
    ARITY, Atom, BIN_REF, EMPTY_TUPLE, EXTERNAL_PID, EXTERNAL_PORT, EXTERNAL_REF, ExportEntry,
    FLOAT, FunEntry, HEAP_BITS, MAP_HEADER_FLATMAP, MAX_SMALL, MIN_SMALL, NEG_BIG, Node, POS_BIG,
    RECORD, SUB_BITS, Term, TermError, TermKind, cmp, exact_eq,
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

/// `ProcessHeap::alloc_ix` of a heap whose allocations read the thread's allocator index.
pub(crate) const NO_ALLOC_IX: u16 = u16::MAX;

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
    /// A received message whose data is in the heap fragment inline in its node: erts keeps
    /// the whole `ErtsMessage` on `p->msg_frag` until the next collection.
    // Port of erts/emulator/beam/erl_message.c (erts_save_message_in_proc), OTP-29.1.1.
    Node(crate::message::NodeFragment),
}

#[derive(Clone, Copy, Default)]
pub(crate) struct MbufFast {
    pub(crate) base: usize,
    alloc_size: usize,
    pub(crate) used_size: usize,
    pub(crate) fragment_index: usize,
}

impl Fragment {
    pub(crate) fn as_ptr(&self) -> *const u64 {
        match self {
            Self::Block { memory, .. } => memory.as_ptr(),
            Self::Abandoned { block, .. } => block.as_ptr().cast(),
            Self::Node(fragment) => fragment.as_ptr(),
        }
    }
    /// Words that hold objects.
    pub(crate) fn len(&self) -> usize {
        match self {
            Self::Block { used, .. } | Self::Abandoned { used, .. } => *used,
            Self::Node(fragment) => fragment.len(),
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

    /// [`WordBlock::new`] on the allocator index `ix` of the calling scheduler thread.
    pub(crate) fn new_at(words: usize, allocation_type: ErtsAlcType, ix: usize) -> Self {
        Self {
            ptr: AllocBlock::detach_heap_at(ix, allocation_type, words)
                .expect("ERTS heap block allocation failed"),
        }
    }

    /// A block on the allocator index `alloc_ix`, or on the thread's own when it is
    /// [`NO_ALLOC_IX`].
    fn new_for(words: usize, allocation_type: ErtsAlcType, alloc_ix: u16) -> Self {
        if alloc_ix == NO_ALLOC_IX {
            Self::new(words, allocation_type)
        } else {
            Self::new_at(words, allocation_type, usize::from(alloc_ix))
        }
    }

    /// Frees the block on the allocator index `ix` of the calling scheduler thread.
    pub(crate) fn release_at(self, ix: usize) {
        let ptr = self.ptr;
        // The allocator frees the block here; the destructor must not free it again.
        std::mem::forget(self);
        AllocBlock::free_detached_heap_at(ix, ptr);
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
    /// Reserve words with the `HAlloc` cursor check used by native term construction.
    ///
    /// Port of `HAlloc` in `erts/emulator/beam/erl_vm.h`, OTP-29.1.1.
    #[inline]
    fn alloc_halloc(&mut self, words: usize) -> Option<*mut u64> {
        self.alloc(words)
    }
    /// Reserve `words` with `HAlloc`, requiring `extra` additional free words without consuming them.
    ///
    /// Port of `HeapWordsLeft` plus `HAlloc` in `erts/emulator/beam/erl_vm.h`, OTP-29.1.1.
    #[inline]
    fn alloc_halloc_with_extra(&mut self, words: usize, _extra: usize) -> Option<*mut u64> {
        self.alloc_halloc(words)
    }
    /// Stable identity for reservations which outlive one borrowing call.
    fn allocator_identity(&self) -> usize {
        std::ptr::from_ref(self).cast::<()>() as usize
    }
    /// A slot handle for the first word at `ptr` in an allocated object.
    ///
    /// Most heaps keep an address. A reserved-slice allocator keeps an index so later fixups
    /// use the same bounds-checked slice as the object writes.
    #[inline]
    fn term_slot(&self, ptr: *mut u64) -> HeapTermSlot {
        HeapTermSlot::address(ptr as usize)
    }
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
    /// Link a BinRef into this heap's ERTS off-heap or writable-binary chain.
    fn link_bin_ref(
        &mut self,
        bin_ref: *mut u64,
        writable: bool,
        overhead_words: u64,
        owner: Option<arinsal_alloc::raw::OwnedBinaryRef>,
    ) -> Result<(), TermError> {
        let _ = (bin_ref, writable, overhead_words, owner);
        Err(TermError::Unsupported("BinRef heap chain"))
    }
    /// Account for one retained Binary reference on the young virtual heap.
    fn add_bin_vheap(&mut self, words: u64) {
        let _ = words;
    }
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
    #[inline(always)]
    fn update_writable_binary_overhead(
        &mut self,
        _source: Term,
        _old_size_bits: usize,
        _new_size_bits: usize,
    ) {
    }
    /// Apply a writable-binary overhead change when the bit-syntax parse already has its BinRef.
    #[inline(always)]
    fn update_writable_binary_overhead_at(
        &mut self,
        source: Term,
        _bin_ref: usize,
        old_size_bits: usize,
        new_size_bits: usize,
    ) {
        self.update_writable_binary_overhead(source, old_size_bits, new_size_bits)
    }
    /// Whether this heap can retain a writable owner without losing it at GC.
    fn supports_writable_binary(&self) -> bool {
        false
    }
    /// Link a BinRef over a resource-backed binary into this heap's off-heap list. The BinRef's
    /// `val` word already names `binary`, and the list entry takes over the counted reference.
    fn link_external_binary(
        &mut self,
        _bin_ref: *mut u64,
        _binary: Arc<ExternalBinary>,
    ) -> Result<(), TermError> {
        Err(TermError::Unsupported("external binary heap owner"))
    }
    /// Whether the heap retains external binary owners across collection.
    fn supports_external_binary(&self) -> bool {
        false
    }
    /// Link an external pid, port or reference thing into this heap's off-heap list. The
    /// thing's node word names `node`, and the list entry takes over the counted reference.
    // Port of erts/emulator/beam/external.c (erts_ref_node_entry with `ohp->first`), OTP-29.1.1.
    fn link_node(&mut self, thing: *mut u64, node: Arc<Node>);
    /// Link a magic reference thing into this heap's off-heap list. The thing's pointer
    /// word names `owner`, and the list entry takes over the counted reference.
    // Port of erts/emulator/beam/erl_bif_unique.h (erts_mk_magic_ref), OTP-29.1.1.
    fn link_magic_ref(
        &mut self,
        _thing: *mut u64,
        _owner: Arc<crate::MagicRef>,
    ) -> Result<(), TermError> {
        Err(TermError::Unsupported("magic reference heap owner"))
    }
    /// Whether the allocator keeps an off-heap list for magic references.
    fn supports_magic(&self) -> bool {
        false
    }
    /// Whether `HRelease` must mark this unused block with a heap filler.
    ///
    /// Process heaps omit the filler when the block ends at `HEAP_TOP`; fragments and
    /// non-top blocks need one so heap scans do not mistake the hole for terms.
    fn release_needs_filler(&self, _end: *mut u64, _start: *mut u64) -> bool {
        true
    }
    /// Give back the unused words `[start, end)` at the end of the latest allocation.
    // Port of erts/emulator/beam/erl_vm.h:164-173 (HRelease), OTP-29.1.1.
    fn release(&mut self, _end: *mut u64, _start: *mut u64) {}
    /// Trim a result built in the most recent fragment-only allocation.
    ///
    /// Port of `maybe_shrink` in `erts/emulator/beam/erl_arith.c:43-49`, OTP-29.1.1.
    #[inline(always)]
    fn shrink_fragment_tail(&mut self, start: *mut u64, allocated: usize, used: usize) {
        self.release(start.wrapping_add(allocated), start.wrapping_add(used));
    }
    /// The process' native ABI words (`c_p->htop`, `fcalls`, `freason`) when this allocator is
    /// a process heap; BIF contexts reach FCALLS and the failure words through it.
    #[inline(always)]
    fn native_abi(&self) -> Option<&NativeAbi> {
        None
    }
    /// Mutable form of [`native_abi`](Self::native_abi).
    #[inline(always)]
    fn native_abi_mut(&mut self) -> Option<&mut NativeAbi> {
        None
    }
}

impl<H: HeapAlloc + ?Sized> HeapAlloc for &mut H {
    #[inline(always)]
    fn native_abi(&self) -> Option<&NativeAbi> {
        (**self).native_abi()
    }
    #[inline(always)]
    fn native_abi_mut(&mut self) -> Option<&mut NativeAbi> {
        (**self).native_abi_mut()
    }
    fn allocator_identity(&self) -> usize {
        (**self).allocator_identity()
    }
    fn term_slot(&self, ptr: *mut u64) -> HeapTermSlot {
        (**self).term_slot(ptr)
    }
    fn alloc(&mut self, words: usize) -> Option<*mut u64> {
        (**self).alloc(words)
    }
    fn alloc_with_extra(&mut self, words: usize, extra: usize) -> Option<*mut u64> {
        (**self).alloc_with_extra(words, extra)
    }
    fn alloc_fragment_only(&mut self, words: usize) -> Option<*mut u64> {
        (**self).alloc_fragment_only(words)
    }
    #[inline(always)]
    fn shrink_fragment_tail(&mut self, start: *mut u64, allocated: usize, used: usize) {
        (**self).shrink_fragment_tail(start, allocated, used)
    }
    fn words_left(&self) -> Option<usize> {
        (**self).words_left()
    }
    fn retain_binary(&mut self, binary: Arc<RefcBinary>) {
        (**self).retain_binary(binary)
    }
    fn link_bin_ref(
        &mut self,
        bin_ref: *mut u64,
        writable: bool,
        overhead_words: u64,
        owner: Option<arinsal_alloc::raw::OwnedBinaryRef>,
    ) -> Result<(), TermError> {
        (**self).link_bin_ref(bin_ref, writable, overhead_words, owner)
    }
    fn add_bin_vheap(&mut self, words: u64) {
        (**self).add_bin_vheap(words)
    }
    fn retain_writable_binary(&mut self, binary: Arc<WritableBinary>) -> Result<(), TermError> {
        (**self).retain_writable_binary(binary)
    }
    fn retain_writable_binary_with_apparent_size(
        &mut self,
        binary: Arc<WritableBinary>,
        apparent_size_bits: usize,
    ) -> Result<(), TermError> {
        (**self).retain_writable_binary_with_apparent_size(binary, apparent_size_bits)
    }
    fn update_writable_binary_overhead(
        &mut self,
        source: Term,
        old_size_bits: usize,
        new_size_bits: usize,
    ) {
        (**self).update_writable_binary_overhead(source, old_size_bits, new_size_bits)
    }
    fn update_writable_binary_overhead_at(
        &mut self,
        source: Term,
        bin_ref: usize,
        old_size_bits: usize,
        new_size_bits: usize,
    ) {
        (**self).update_writable_binary_overhead_at(source, bin_ref, old_size_bits, new_size_bits)
    }
    fn supports_writable_binary(&self) -> bool {
        (**self).supports_writable_binary()
    }
    fn link_external_binary(
        &mut self,
        bin_ref: *mut u64,
        binary: Arc<ExternalBinary>,
    ) -> Result<(), TermError> {
        (**self).link_external_binary(bin_ref, binary)
    }
    fn supports_external_binary(&self) -> bool {
        (**self).supports_external_binary()
    }
    fn link_node(&mut self, thing: *mut u64, node: Arc<Node>) {
        (**self).link_node(thing, node)
    }
    fn link_magic_ref(
        &mut self,
        thing: *mut u64,
        owner: Arc<crate::MagicRef>,
    ) -> Result<(), TermError> {
        (**self).link_magic_ref(thing, owner)
    }
    fn supports_magic(&self) -> bool {
        (**self).supports_magic()
    }
    fn release_needs_filler(&self, end: *mut u64, start: *mut u64) -> bool {
        (**self).release_needs_filler(end, start)
    }
    fn release(&mut self, end: *mut u64, start: *mut u64) {
        (**self).release(end, start)
    }
}

/// Store one word into a block the caller owns (`HAlloc` memory, a reservation or a patched slot).
///
/// Private on purpose: every caller passes a pointer it obtained from the allocator for the
/// block it is filling, which is the one invariant a raw store needs.
#[inline]
pub(crate) fn store(ptr: *mut u64, value: u64) {
    // SAFETY: callers pass an in-bounds, initialized-or-reserved slot of a live heap block.
    unsafe { *ptr = value }
}

/// Read one word from a block the caller owns or is tracing.
#[inline]
pub(crate) fn load(ptr: *const u64) -> u64 {
    // SAFETY: callers pass an in-bounds, initialized slot of a live heap block.
    unsafe { *ptr }
}

/// What an off-heap list node is: erts' list holds refc/writable binaries, magic references
/// and external things alike, told apart by the thing word.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OffHeapKind {
    /// A `BinRef` (`ProcBin`).
    BinRef,
    /// A magic reference thing (`ErtsMRefThing`).
    Magic,
    /// An external pid, port or reference thing (`ExternalThing`).
    Node,
}

/// The kind of an off-heap list node. A forwarded node keeps its type in the header of its copy.
#[inline]
pub(crate) fn off_heap_node_kind(node: usize) -> OffHeapKind {
    let mut header = load(node as *const u64);
    if header & 3 == 2 {
        header = load((header & !3) as *const u64);
    }
    match header & 63 {
        crate::REF => OffHeapKind::Magic,
        BIN_REF => OffHeapKind::BinRef,
        _ => OffHeapKind::Node,
    }
}

/// Whether an off-heap list node is a `BinRef`.
#[inline]
pub(crate) fn off_heap_node_is_bin_ref(node: usize) -> bool {
    off_heap_node_kind(node) == OffHeapKind::BinRef
}

/// Link a BinRef over a resource-backed binary at the head of an off-heap list, which takes
/// over `binary`'s counted reference. The BinRef's `val` word was tagged by the builder.
// Port of erts/emulator/beam/erl_nif.c (enif_make_resource_binary: `erts_wrap_refc_bitstring`
// links the BinRef at `ohp->first`), OTP-29.1.1.
pub(crate) fn link_external_bin_ref(
    head: &mut usize,
    bin_ref: *mut u64,
    binary: Arc<ExternalBinary>,
) {
    std::mem::forget(binary);
    store(bin_ref.wrapping_add(2), *head as u64);
    *head = bin_ref as usize;
}

/// Link an external thing at the head of an off-heap list, which takes over `node`'s counted
/// reference. External things add nothing to the list's overhead.
// Port of erts/emulator/beam/external.c (erts_ref_node_entry; `ohp->first = ...`), OTP-29.1.1.
pub(crate) fn link_node_thing(head: &mut usize, thing: *mut u64, node: Arc<Node>) {
    store(thing.wrapping_add(1), Arc::into_raw(node) as u64);
    store(thing.wrapping_add(2), *head as u64);
    *head = thing as usize;
}

/// Link a magic reference thing at the head of an off-heap list, which takes over `owner`'s
/// counted reference, and charge `mb->orig_size` to the list's overhead.
// Port of erts/emulator/beam/erl_bif_unique.h (erts_mk_magic_ref: `ohp->first`,
// `OH_OVERHEAD`), OTP-29.1.1.
pub(crate) fn link_magic_thing(
    head: &mut usize,
    overhead: &mut u64,
    thing: *mut u64,
    owner: Arc<crate::MagicRef>,
) {
    let words = (owner.orig_size() / 8) as u64;
    store(thing.wrapping_add(1), Arc::into_raw(owner) as u64);
    store(thing.wrapping_add(2), *head as u64);
    *head = thing as usize;
    *overhead = overhead.saturating_add(words);
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
    cur: *mut u64,
    head: Term,
    last: Option<*mut u64>,
}
impl<'a, H: HeapAlloc + ?Sized> ConsHeapBuilder<'a, H> {
    /// Reserve space for at most `max_cells` cons cells.
    /// Port of `HAlloc(p, 2 * max_cells)` in `erl_bif_lists.c:145-147`, OTP-29.1.1.
    pub fn new(heap: &'a mut H, max_cells: usize) -> Result<Self, TermError> {
        let words = max_cells.checked_mul(2).ok_or(TermError::SystemLimit)?;
        let reservation = HeapReservation::new(heap, words)?;
        let cur = reservation.cursor();
        Ok(Self {
            reservation,
            cur,
            head: Term::NIL,
            last: None,
        })
    }

    /// Append a cell after the previous cell in input order.
    #[inline(always)]
    pub fn push(&mut self, head: Term) -> Result<(), TermError> {
        let cell = self.cur;
        if cell == self.reservation.limit() {
            return Err(TermError::HeapFull);
        }
        self.cur = cell.wrapping_add(2);
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
    /// Port of final RHS linking and `HEAP_TOP` advancement in `erl_bif_lists.c:148-163`.
    pub fn finish(mut self, tail: Term) -> Term {
        let result = match self.last.take() {
            Some(last) => {
                store(last.wrapping_add(1), tail.bits());
                self.head
            }
            None => tail,
        };
        self.reservation.set_cursor(self.cur);
        result
    }

    /// Finish a nonempty segment with an open tail so another heap block can follow it.
    /// Port of the retained `result_cdr` slot in `erl_bif_lists.c:52-58`, OTP-29.1.1.
    pub fn finish_open(mut self) -> Option<ConsHeapSegment> {
        let segment = self.last.take().map(|last| ConsHeapSegment {
            head: self.head,
            last_cdr: last.wrapping_add(1) as usize,
        });
        self.reservation.set_cursor(self.cur);
        segment
    }
}
impl<H: HeapAlloc + ?Sized> Drop for ConsHeapBuilder<'_, H> {
    fn drop(&mut self) {
        if let Some(last) = self.last.take() {
            store(last.wrapping_add(1), Term::NIL.bits());
            self.reservation.set_cursor(self.cur);
        }
    }
}

/// A contiguous list segment whose final CDR can be linked to another segment.
pub struct ConsHeapSegment {
    head: Term,
    last_cdr: usize,
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

    /// Join a completed contiguous segment to this list and keep its tail open.
    /// Port of the result CDR link in `erl_bif_lists.c:121-132`, OTP-29.1.1.
    pub fn append_segment(&mut self, segment: ConsHeapSegment) {
        if let Some(result_cdr) = self.result_cdr {
            store(result_cdr as *mut u64, segment.head.bits());
        } else {
            self.head = segment.head;
        }
        self.result_cdr = Some(segment.last_cdr);
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
    start: *mut u64,
    cur: *mut u64,
    end: *mut u64,
}

/// Allocation state of a [`ProcessHeap`] taken before a builder runs, to undo a failed build.
// Port of the saved fields of erts/emulator/beam/erl_message.h (ErtsHeapFactory), OTP-29.1.1.
#[derive(Clone, Copy, Debug)]
pub struct HeapFactoryMark {
    htop: usize,
    fragments: usize,
    last_used: usize,
    off_heap_first: usize,
    overhead: u64,
    bin_vheap: u64,
}

/// A suspended heap reservation whose owning process heap remains live across a BIF trap.
///
/// Resume this value only with the same live allocator. `ProcessHeap` allocations stay at a
/// stable address while GC is disabled for the trapped BIF.
pub struct HeapReservationState {
    start: usize,
    cur: usize,
    end: usize,
    allocator: usize,
}

/// A checked word in one reserved ETF decode slice.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HeapTermSlot {
    value: usize,
    indexed: bool,
}

impl HeapTermSlot {
    /// The slot at word `index` of a reservation slice.
    #[inline(always)]
    pub fn from_index(index: usize) -> Self {
        Self::index(index)
    }

    /// The word index of an indexed slot, `None` for an address slot.
    #[inline(always)]
    pub fn word_index(self) -> Option<usize> {
        self.indexed.then_some(self.value)
    }

    #[inline]
    fn address(value: usize) -> Self {
        Self {
            value,
            indexed: false,
        }
    }

    #[inline]
    fn index(value: usize) -> Self {
        Self {
            value,
            indexed: true,
        }
    }
}

/// A small heap binary reserved across a BIF trap while GC is disabled.
/// Port of `erts_new_bitstring` plus the retained `to` cursor in
/// `erts/emulator/beam/erl_iolist.c` (`list_to_bitstring_engine`), OTP-29.1.1.
pub struct HeapBinaryWriter {
    reservation: HeapReservationState,
    term: Term,
    bytes: usize,
    written: usize,
    restore_gc: bool,
    finished: bool,
}

impl HeapBinaryWriter {
    /// Reserve the final heap binary. The owning process heap must remain live and GC disabled
    /// until [`Self::finish`] is called.
    // Port of erts/emulator/beam/erl_bits.c:2841-2860 (`erts_new_bitstring`), OTP-29.1.1.
    pub fn new(heap: &mut ProcessHeap, bytes: usize) -> Result<Self, TermError> {
        if bytes > 64 {
            return Err(TermError::BadArg);
        }
        let words = 2 + bytes.div_ceil(8);
        let restore_gc = heap.gc_enabled;
        let start = heap
            .alloc_halloc(words)
            .unwrap_or_else(|| heap.heap_fragment(words));
        let reservation = HeapReservation {
            heap,
            start,
            cur: start,
            end: start.wrapping_add(words),
        };
        let start = reservation.cursor();
        store(start, (((words - 1) as u64) << 6) | HEAP_BITS);
        store(start.wrapping_add(1), (bytes * 8) as u64);
        for index in 0..bytes.div_ceil(8) {
            store(start.wrapping_add(2 + index), 0);
        }
        let term = Term::from_ptr(start, 2);
        let state = reservation.suspend();
        heap.gc_enabled = false;
        Ok(Self {
            reservation: state,
            term,
            bytes,
            written: 0,
            restore_gc,
            finished: false,
        })
    }

    /// Reserved payload length in bytes.
    pub fn len(&self) -> usize {
        self.bytes
    }

    /// Whether the reserved binary has an empty payload.
    pub fn is_empty(&self) -> bool {
        self.bytes == 0
    }

    /// Append the next source chunk at the retained write offset.
    // Port of erts/emulator/beam/erl_iolist.c:425-620 (`generic_iolist_copy`), OTP-29.1.1.
    pub fn write(&mut self, heap: &mut ProcessHeap, chunk: &[u8]) -> Result<(), TermError> {
        assert!(!self.finished, "heap binary writer is finalized");
        assert!(!heap.gc_enabled, "heap binary writer requires GC disabled");
        let end = self
            .written
            .checked_add(chunk.len())
            .ok_or(TermError::SystemLimit)?;
        if end > self.bytes {
            return Err(TermError::BadArg);
        }
        assert_eq!(heap.allocator_identity(), self.reservation.allocator);
        let start = (self.term.0 & !7) as *mut u64;
        let mut input = 0;
        while input < chunk.len() {
            let offset = self.written + input;
            let in_word = offset % 8;
            let count = (8 - in_word).min(chunk.len() - input);
            let word = start.wrapping_add(2 + offset / 8);
            if in_word == 0 && count == 8 {
                let bytes: [u8; 8] = chunk[input..input + 8]
                    .try_into()
                    .expect("eight bytes remain in the chunk");
                store(word, u64::from_le_bytes(bytes));
            } else {
                let mut bytes = load(word).to_le_bytes();
                bytes[in_word..in_word + count].copy_from_slice(&chunk[input..input + count]);
                store(word, u64::from_le_bytes(bytes));
            }
            input += count;
        }
        self.written = end;
        Ok(())
    }

    /// Publish the fully written binary and release the retained reservation.
    // Port of erts/emulator/beam/erl_iolist.c:765-834 (`list_to_bitstring_dispatch`), OTP-29.1.1.
    pub fn finish(&mut self, heap: &mut ProcessHeap) -> Result<Term, TermError> {
        assert!(!self.finished, "heap binary writer is finalized");
        assert!(!heap.gc_enabled, "heap binary writer requires GC disabled");
        if self.written != self.bytes {
            return Err(TermError::BadArg);
        }
        let state = std::mem::replace(
            &mut self.reservation,
            HeapReservationState {
                start: 0,
                cur: 0,
                end: 0,
                allocator: 0,
            },
        );
        let mut reservation = HeapReservation::resume(heap, state);
        reservation.set_cursor(reservation.limit());
        drop(reservation);
        heap.gc_enabled = self.restore_gc;
        self.finished = true;
        Ok(self.term)
    }

    /// Discard a partial result and restore the process's previous GC state.
    // Port of erts/emulator/beam/erl_iolist.c:806-821 (trapped error cleanup), OTP-29.1.1.
    pub fn cancel(&mut self, heap: &mut ProcessHeap) {
        if self.finished {
            return;
        }
        assert!(!heap.gc_enabled, "heap binary writer requires GC disabled");
        let state = std::mem::replace(
            &mut self.reservation,
            HeapReservationState {
                start: 0,
                cur: 0,
                end: 0,
                allocator: 0,
            },
        );
        drop(HeapReservation::resume(heap, state));
        heap.gc_enabled = self.restore_gc;
        self.finished = true;
    }
}

impl<'a, H: HeapAlloc + ?Sized> HeapReservation<'a, H> {
    /// Reserve `words` words from `heap`.
    pub fn new(heap: &'a mut H, words: usize) -> Result<Self, TermError> {
        let cur = heap
            .alloc_with_extra(words, 0)
            .ok_or(TermError::SystemLimit)?;
        let end = cur.wrapping_add(words);
        Ok(Self {
            heap,
            start: cur,
            cur,
            end,
        })
    }
    /// Reserve `words` words from `heap`, leaving `extra` spare words in a new heap fragment.
    ///
    /// Port of `erts_produce_heap(hfact, words, extra)` in erts/emulator/beam/erl_message.h
    /// and its `erts_reserve_heap__` in erl_message.c (`HAllocX`), OTP-29.1.1: the block lands
    /// on the young heap when it fits and otherwise whole in one heap fragment sized
    /// `words + extra`.
    pub fn with_extra(heap: &'a mut H, words: usize, extra: usize) -> Result<Self, TermError> {
        let cur = heap
            .alloc_with_extra(words, extra)
            .ok_or(TermError::SystemLimit)?;
        let end = cur.wrapping_add(words);
        Ok(Self {
            heap,
            start: cur,
            cur,
            end,
        })
    }
    /// Reattach a reservation suspended by [`Self::suspend`].
    pub fn resume(heap: &'a mut H, state: HeapReservationState) -> Self {
        assert_eq!(heap.allocator_identity(), state.allocator);
        Self {
            heap,
            start: state.start as *mut u64,
            cur: state.cur as *mut u64,
            end: state.end as *mut u64,
        }
    }
    /// Suspend this reservation without returning its unused words.
    pub fn suspend(self) -> HeapReservationState {
        let state = HeapReservationState {
            start: self.start as usize,
            cur: self.cur as usize,
            end: self.end as usize,
            allocator: self.heap.allocator_identity(),
        };
        std::mem::forget(self);
        state
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
        let cur = self
            .heap
            .alloc_with_extra(words, 0)
            .ok_or(TermError::SystemLimit)?;
        self.start = cur;
        self.end = cur.wrapping_add(words);
        self.cur = cur;
        Ok(())
    }
    /// Port of erts/emulator/beam/erl_vm.h:164-173 (HRelease) with erl_term.h:1500
    /// (erts_write_heap_filler), OTP-29.1.1.
    fn release_tail(&mut self) {
        let words = (self.end as usize - self.cur as usize) / 8;
        if words > 0 {
            if self.heap.release_needs_filler(self.end, self.cur) {
                store(self.cur, ((words as u64 - 1) << 6) | POS_BIG);
            }
            self.heap.release(self.end, self.cur);
            self.cur = self.end;
        }
    }
}

impl<'a> HeapReservation<'a, ProcessHeap> {
    /// Borrow the reserved words once as a safe slice-backed allocator.
    ///
    /// Port of `erts_factory_proc_prealloc_init` followed by `hp++` in
    /// erts/emulator/beam/erl_message.c and erts/emulator/beam/external.c (`dec_term`), OTP-29.1.1.
    pub fn with_words<R>(
        &mut self,
        f: impl FnOnce(&mut HeapReservationWords<'_>) -> R,
    ) -> Result<R, TermError> {
        let Self {
            heap,
            start,
            cur,
            end,
        } = self;
        let first = *start;
        let count = (*end as usize)
            .checked_sub(first as usize)
            .filter(|bytes| bytes.is_multiple_of(std::mem::size_of::<u64>()))
            .ok_or(TermError::BadArg)?
            / std::mem::size_of::<u64>();
        let cursor = (*cur as usize)
            .checked_sub(first as usize)
            .filter(|bytes| bytes.is_multiple_of(std::mem::size_of::<u64>()))
            .ok_or(TermError::BadArg)?
            / std::mem::size_of::<u64>();
        let allocator = heap.allocator_identity();
        let (words, owners, bin_vheap) = heap.reservation_words_mut(first, count)?;
        let mut slice = HeapReservationWords {
            words,
            cursor,
            reservation_cursor: cur,
            allocator,
            owners,
            bin_vheap,
        };
        Ok(f(&mut slice))
    }
}

/// One reserved heap block viewed as a safe word slice and an `hp++` allocator.
pub struct HeapReservationWords<'a> {
    words: &'a mut [u64],
    cursor: usize,
    reservation_cursor: &'a mut *mut u64,
    allocator: usize,
    owners: &'a mut LazyOwners,
    bin_vheap: &'a mut u64,
}

impl HeapReservationWords<'_> {
    /// Return the reserved words and the `hp` cursor for inline heap block construction.
    #[inline(always)]
    pub fn words_and_cursor(&mut self) -> (&mut [u64], &mut usize) {
        (&mut *self.words, &mut self.cursor)
    }

    /// Return the words already reserved by `HAlloc`.
    #[inline]
    pub fn as_mut_words(&mut self) -> &mut [u64] {
        self.words
    }

    /// Build an index handle for an address returned by this slice allocator.
    #[inline]
    pub fn slot_for(&self, ptr: *mut u64) -> Result<HeapTermSlot, TermError> {
        Ok(self.term_slot(ptr))
    }

    /// Store a decoded term into a previously reserved slot.
    #[inline(always)]
    pub fn write_term_slot(&mut self, slot: HeapTermSlot, term: Term) -> Result<(), TermError> {
        let Some(word) = slot
            .indexed
            .then(|| self.words.get_mut(slot.value))
            .flatten()
        else {
            return Err(TermError::BadArg);
        };
        *word = term.bits();
        Ok(())
    }

    /// Read a decoded term from a previously reserved slot.
    #[inline(always)]
    pub fn read_term_slot(&self, slot: HeapTermSlot) -> Result<Term, TermError> {
        let Some(bits) = slot
            .indexed
            .then(|| self.words.get(slot.value))
            .flatten()
            .copied()
        else {
            return Err(TermError::BadArg);
        };
        if bits & 7 == 0 {
            return Err(TermError::BadArg);
        }
        Ok(Term(bits))
    }

    /// Return a list term over two adjacent words in the slice.
    #[inline]
    pub fn list_term_at(&self, slot: HeapTermSlot) -> Result<Term, TermError> {
        if !slot.indexed || slot.value >= self.words.len().saturating_sub(1) {
            return Err(TermError::BadArg);
        }
        Ok(Term::from_ptr(
            self.words.as_ptr().wrapping_add(slot.value).cast_mut(),
            1,
        ))
    }

    /// Return a tuple term over an initialized header at a reserved word index.
    #[inline(always)]
    pub fn boxed_term_at(&self, slot: HeapTermSlot) -> Result<Term, TermError> {
        if !slot.indexed || slot.value >= self.words.len() {
            return Err(TermError::BadArg);
        }
        Ok(Term::from_ptr(
            self.words.as_ptr().wrapping_add(slot.value).cast_mut(),
            2,
        ))
    }

    /// Reserve a decoded local fun and return the first captured-term slot.
    // Port of erts/emulator/beam/external.c:5162-5168 (`dec_term`, NEW_FUN_EXT), OTP-29.1.1.
    pub fn reserve_local_fun_stub(
        &mut self,
        entry: Arc<FunEntry>,
        free: usize,
    ) -> Result<(Term, Option<HeapTermSlot>), TermError> {
        let entry = crate::fun::fun_entry_get_or_make_stub(entry);
        crate::fun::make_fun_entry_permanent(&entry);
        let header = crate::fun::local_header(entry.arity, free).ok_or(TermError::SystemLimit)?;
        let words = 2usize.checked_add(free).ok_or(TermError::SystemLimit)?;
        let ptr = self.alloc(words).ok_or(TermError::HeapFull)?;
        store(ptr, header);
        store(ptr.wrapping_add(1), Arc::as_ptr(&entry) as u64);
        for offset in 0..free {
            store(ptr.wrapping_add(2 + offset), Term::NIL.bits());
        }
        let first = (free != 0).then(|| self.term_slot(ptr.wrapping_add(2)));
        Ok((Term::from_ptr(ptr, 2), first))
    }

    /// Return a slot at an offset in this reservation.
    #[inline]
    pub fn offset_slot(
        &self,
        slot: HeapTermSlot,
        word_offset: usize,
    ) -> Result<HeapTermSlot, TermError> {
        let value = slot
            .indexed
            .then(|| slot.value.checked_add(word_offset))
            .flatten()
            .filter(|value| *value < self.words.len())
            .ok_or(TermError::BadArg)?;
        Ok(HeapTermSlot::index(value))
    }

    /// Store an index to the next unfilled slot, matching `dec_term`'s `*objp` chain.
    #[inline(always)]
    pub fn write_next_slot(
        &mut self,
        slot: HeapTermSlot,
        next: Option<HeapTermSlot>,
    ) -> Result<(), TermError> {
        let value = match next {
            Some(next) if next.indexed => next.value.checked_add(1).ok_or(TermError::BadArg)?,
            Some(_) => return Err(TermError::BadArg),
            None => 0,
        };
        *self
            .words
            .get_mut(
                slot.indexed
                    .then_some(slot.value)
                    .ok_or(TermError::BadArg)?,
            )
            .ok_or(TermError::BadArg)? = value as u64;
        Ok(())
    }

    /// Read and clear the next unfilled slot index.
    #[inline(always)]
    pub fn take_next_slot(
        &mut self,
        slot: HeapTermSlot,
    ) -> Result<Option<HeapTermSlot>, TermError> {
        let word = self
            .words
            .get_mut(
                slot.indexed
                    .then_some(slot.value)
                    .ok_or(TermError::BadArg)?,
            )
            .ok_or(TermError::BadArg)?;
        let next = *word as usize;
        *word = 0;
        if next == 0 {
            Ok(None)
        } else {
            let index = next - 1;
            (index < self.words.len())
                .then_some(HeapTermSlot::index(index))
                .ok_or(TermError::BadArg)
                .map(Some)
        }
    }

    /// Swap two decoded terms inside the reserved slice.
    #[inline(always)]
    pub fn swap_term_slots(
        &mut self,
        left: HeapTermSlot,
        right: HeapTermSlot,
    ) -> Result<(), TermError> {
        if !left.indexed || !right.indexed {
            return Err(TermError::BadArg);
        }
        self.words.swap(left.value, right.value);
        Ok(())
    }
}

impl Drop for HeapReservationWords<'_> {
    fn drop(&mut self) {
        *self.reservation_cursor = self.words.as_mut_ptr().wrapping_add(self.cursor);
    }
}

impl HeapAlloc for HeapReservationWords<'_> {
    fn allocator_identity(&self) -> usize {
        self.allocator
    }

    #[inline(always)]
    fn term_slot(&self, ptr: *mut u64) -> HeapTermSlot {
        let base = self.words.as_ptr() as usize;
        let address = ptr as usize;
        let offset = address.wrapping_sub(base);
        if address < base
            || !offset.is_multiple_of(std::mem::size_of::<u64>())
            || offset / std::mem::size_of::<u64>() >= self.words.len()
        {
            return HeapTermSlot::index(usize::MAX);
        }
        HeapTermSlot::index(offset / std::mem::size_of::<u64>())
    }

    #[inline(always)]
    fn alloc(&mut self, words: usize) -> Option<*mut u64> {
        let end = self.cursor.checked_add(words)?;
        if end > self.words.len() {
            return None;
        }
        let ptr = self.words[self.cursor..].as_mut_ptr();
        self.cursor = end;
        Some(ptr)
    }

    #[inline(always)]
    fn alloc_with_extra(&mut self, words: usize, _extra: usize) -> Option<*mut u64> {
        self.alloc(words)
    }

    fn retain_binary(&mut self, binary: Arc<RefcBinary>) {
        *self.bin_vheap = self.bin_vheap.saturating_add((binary.len() / 8) as u64);
        drop(binary);
    }

    fn link_bin_ref(
        &mut self,
        bin_ref: *mut u64,
        writable: bool,
        overhead_words: u64,
        owner: Option<arinsal_alloc::raw::OwnedBinaryRef>,
    ) -> Result<(), TermError> {
        let head = if writable {
            &mut self.owners.wrt_bins
        } else {
            &mut self.owners.off_heap_first
        };
        store(bin_ref.wrapping_add(2), *head as u64);
        *head = bin_ref as usize;
        if let Some(owner) = owner {
            owner.transfer_to_bin_ref(bin_ref);
        }
        self.owners.overhead = self.owners.overhead.saturating_add(overhead_words);
        Ok(())
    }

    fn add_bin_vheap(&mut self, words: u64) {
        *self.bin_vheap = self.bin_vheap.saturating_add(words);
    }

    fn retain_writable_binary_with_apparent_size(
        &mut self,
        binary: Arc<WritableBinary>,
        apparent_size_bits: usize,
    ) -> Result<(), TermError> {
        *self.bin_vheap = self
            .bin_vheap
            .saturating_add((apparent_size_bits.div_ceil(8) / 8) as u64);
        drop(binary);
        Ok(())
    }

    fn link_external_binary(
        &mut self,
        bin_ref: *mut u64,
        binary: Arc<ExternalBinary>,
    ) -> Result<(), TermError> {
        link_external_bin_ref(&mut self.owners.off_heap_first, bin_ref, binary);
        Ok(())
    }

    fn supports_external_binary(&self) -> bool {
        true
    }

    fn link_node(&mut self, thing: *mut u64, node: Arc<Node>) {
        link_node_thing(&mut self.owners.off_heap_first, thing, node);
    }

    fn link_magic_ref(
        &mut self,
        thing: *mut u64,
        owner: Arc<crate::MagicRef>,
    ) -> Result<(), TermError> {
        let HeapOwners {
            off_heap_first: head,
            overhead,
            ..
        } = &mut **self.owners;
        link_magic_thing(head, overhead, thing, owner);
        Ok(())
    }

    fn supports_magic(&self) -> bool {
        true
    }
}
impl<H: HeapAlloc + ?Sized> Drop for HeapReservation<'_, H> {
    fn drop(&mut self) {
        self.release_tail();
    }
}
impl<H: HeapAlloc + ?Sized> HeapAlloc for HeapReservation<'_, H> {
    fn allocator_identity(&self) -> usize {
        self.heap.allocator_identity()
    }
    #[inline]
    fn alloc(&mut self, words: usize) -> Option<*mut u64> {
        if words <= (self.end as usize - self.cur as usize) / 8 {
            let ptr = self.cur;
            self.cur = ptr.wrapping_add(words);
            Some(ptr)
        } else {
            self.heap.alloc_with_extra(words, 0)
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
    fn link_bin_ref(
        &mut self,
        bin_ref: *mut u64,
        writable: bool,
        overhead_words: u64,
        owner: Option<arinsal_alloc::raw::OwnedBinaryRef>,
    ) -> Result<(), TermError> {
        self.heap
            .link_bin_ref(bin_ref, writable, overhead_words, owner)
    }
    fn add_bin_vheap(&mut self, words: u64) {
        self.heap.add_bin_vheap(words)
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
    fn link_node(&mut self, thing: *mut u64, node: Arc<Node>) {
        self.heap.link_node(thing, node)
    }
    // Port of erts/emulator/beam/external.c (dec_term, NEWER_REFERENCE_EXT), OTP-29.1.1.
    fn link_magic_ref(
        &mut self,
        thing: *mut u64,
        owner: Arc<crate::MagicRef>,
    ) -> Result<(), TermError> {
        self.heap.link_magic_ref(thing, owner)
    }
    fn supports_magic(&self) -> bool {
        self.heap.supports_magic()
    }
}

/// The fixed process prefix read and written by generated BeamAsm code.
///
/// Port of erts/emulator/beam/jit/arm/beam_asm.hpp (`emit_enter_runtime` and
/// `emit_leave_runtime`), OTP-29.1.1.
#[repr(C)]
pub struct NativeAbi {
    /// Current young heap allocation pointer.
    pub htop: *mut u64,
    /// Erlang stack pointer, growing toward lower addresses.
    pub stop: *mut u64,
    /// Young heap start.
    pub heap: *mut u64,
    /// Young heap end.
    pub hend: *mut u64,
    /// Reductions remaining in the current scheduler slice.
    pub fcalls: i32,
    pub _fcalls_pad: u32,
    /// `c_p->freason`, `fvalue` and `ftrace` in adjacent words.
    pub exc: crate::exc::ExcFields,
    /// Number of active catch tags in the process stack.
    pub catches: usize,
    /// Next instruction or native code pointer.
    pub i: *const core::ffi::c_void,
    /// Current function arity.
    pub arity: u8,
    pub _arity_pad: [u8; 7],
    /// Current function metadata pointer.
    pub current: *const core::ffi::c_void,
    /// Process flags.
    pub flags: u64,
    /// Current process identifier consumed by the inline `self/0` emitter.
    pub self_pid: u64,
    /// First heap address safe for destructive tuple updates.
    pub high_water: *mut u64,
}

// SAFETY: the pointers address the owning `ProcessHeap`'s own blocks and immutable code; the
// heap moves between scheduler threads as a whole, exactly as it did when `htop`/`stop` were
// `usize`. Nothing aliases them from another thread while the process is not running.
unsafe impl Send for NativeAbi {}
// SAFETY: shared references expose only copies of the words.
unsafe impl Sync for NativeAbi {}

impl Default for NativeAbi {
    fn default() -> Self {
        Self {
            htop: std::ptr::null_mut(),
            stop: std::ptr::null_mut(),
            heap: std::ptr::null_mut(),
            hend: std::ptr::null_mut(),
            fcalls: 0,
            _fcalls_pad: 0,
            exc: crate::exc::ExcFields::default(),
            catches: 0,
            i: std::ptr::null(),
            arity: 0,
            _arity_pad: [0; 7],
            current: std::ptr::null(),
            flags: 0,
            self_pid: 0,
            high_water: std::ptr::null_mut(),
        }
    }
}

const _: () = assert!(std::mem::offset_of!(NativeAbi, htop) == 0x00);
const _: () = assert!(std::mem::offset_of!(NativeAbi, stop) == 0x08);
const _: () = assert!(std::mem::offset_of!(NativeAbi, heap) == 0x10);
const _: () = assert!(std::mem::offset_of!(NativeAbi, hend) == 0x18);
const _: () = assert!(std::mem::offset_of!(NativeAbi, fcalls) == 0x20);
const _: () = assert!(std::mem::offset_of!(NativeAbi, exc) == 0x28);
const _: () = assert!(std::mem::offset_of!(NativeAbi, catches) == 0x40);
const _: () = assert!(std::mem::offset_of!(NativeAbi, i) == 0x48);
const _: () = assert!(std::mem::offset_of!(NativeAbi, arity) == 0x50);
const _: () = assert!(std::mem::offset_of!(NativeAbi, current) == 0x58);
const _: () = assert!(std::mem::offset_of!(NativeAbi, flags) == 0x60);
const _: () = assert!(std::mem::offset_of!(NativeAbi, self_pid) == 0x68);
const _: () = assert!(std::mem::offset_of!(NativeAbi, high_water) == 0x70);

/// A process heap with an upward bump pointer and a downward stack pointer.
#[repr(C)]
pub struct ProcessHeap {
    /// The fixed native ABI fields share storage with this heap's cursors.
    pub abi: NativeAbi,
    // Drop token owners before the heap words referenced by BinRef.val/next.
    pub(crate) owners: LazyOwners,
    pub(crate) words: WordBlock,
    pub(crate) old_words: WordBlock,
    pub(crate) old_htop: usize,
    pub(crate) min_heap_size: u32,
    pub(crate) fullsweep_after: u16,
    pub(crate) minor_since_major: u16,
    /// Allocator index of the scheduler thread running this process, set for the span of one
    /// run; [`NO_ALLOC_IX`] otherwise, when allocations read it from thread-local storage.
    pub(crate) alloc_ix: u16,
    pub(crate) bin_vheap: u64,
    pub(crate) bin_vheap_size: u64,
    pub(crate) heap_grow: bool,
    pub(crate) native_allocation: bool,
    /// Set once generated code has run on this heap: runtime allocations stay below `HEAP_LIMIT`.
    pub(crate) native_redzone: bool,
    /// Words at the top of the stack that erts does not have while a BIF body runs: the native
    /// continuation the executor pushed before it ran a native BIF. HAlloc and the post-BIF
    /// collection test see `E` above them.
    pub(crate) bif_hidden_words: usize,
    /// Allocations go to `owners.detached` (see [`ProcessHeap::begin_detached`]).
    pub(crate) detached: bool,
    /// Whether `fragments` holds the abandoned heap (erts `p->abandoned_heap != NULL`),
    /// so the frequent "is there one" question does not walk the fragment list.
    pub(crate) abandoned: bool,
    pub(crate) fragments: Vec<Fragment>,
    /// Cached current `p->mbuf` cursor, kept out of the fragment vector for its allocation path.
    pub(crate) mbuf_fast: MbufFast,
    /// Sum of used words in process heap fragments (`mbuf_sz` in erts).
    pub(crate) fragment_words: usize,
    /// `F_DISABLE_GC` inverted: collection may run after a BIF (`Process.gc_enabled`).
    pub gc_enabled: bool,
    /// Whether the next collection is the epilogue of a BIF call that decided to collect
    /// (`erts_gc_after_bif_call_lhf` with a valid `live_hf_end`).
    live_frags_armed: std::cell::Cell<bool>,
    /// Length of `fragments` when the last BIF epilogue found no collection due: every fragment
    /// from this index on was allocated by the BIF that follows (erts `live_hf_end`).
    live_frag_mark: std::cell::Cell<u32>,
    /// Whether `live_frag_mark` was taken at the entry of the BIF whose epilogue collects.
    live_frag_valid: std::cell::Cell<bool>,
}

/// HAlloc space validated for a fixed heap object plus words reserved for following stores.
pub struct HAllocReservation<'a> {
    heap: &'a mut ProcessHeap,
    used_words: usize,
}

impl<'a> HAllocReservation<'a> {
    /// Advance HTOP by the object size after the caller's single HeapWordsLeft check.
    // Port of `HeapOnlyAlloc` in erts/emulator/beam/erl_vm.h:195-210, OTP-29.1.1.
    #[inline(always)]
    pub fn allocate(self) -> *mut u64 {
        self.allocate_with_heap().0
    }

    /// Advance HTOP and return the same process heap for ProcBin linking.
    #[inline(always)]
    pub fn allocate_with_heap(self) -> (*mut u64, &'a mut ProcessHeap) {
        let top = self.heap.abi.htop;
        self.heap.abi.htop = top.wrapping_add(self.used_words);
        (top, self.heap)
    }
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
    pub(crate) off_heap_first: usize,
    pub(crate) wrt_bins: usize,
    pub(crate) overhead: u64,
    /// Heap that receives all allocations while the heap is detached.
    pub(crate) detached: Option<Box<VecHeap>>,
}

/// The off-heap lists of a message's inline heap fragment, stored in the fragment header
/// (`ErlHeapFragment.off_heap`: `first` and `overhead`; the writable list is ours).
// Port of erts/emulator/beam/erl_message.h (ErlHeapFragment, ErlOffHeap), OTP-29.1.1.
#[derive(Default)]
pub(crate) struct OffHeapLists {
    pub(crate) off_heap_first: usize,
    pub(crate) wrt_bins: usize,
    pub(crate) overhead: u64,
}

impl Drop for OffHeapLists {
    fn drop(&mut self) {
        crate::gc::release_off_heap_chain(self.off_heap_first);
        crate::gc::release_off_heap_chain(self.wrt_bins);
    }
}

#[derive(Default)]
pub(crate) struct LazyOwners(pub(crate) HeapOwners);
impl Drop for LazyOwners {
    fn drop(&mut self) {
        crate::gc::release_off_heap_chain(self.0.off_heap_first);
        crate::gc::release_off_heap_chain(self.0.wrt_bins);
    }
}

impl LazyOwners {
    pub(crate) fn as_mut(&mut self) -> Option<&mut HeapOwners> {
        Some(&mut self.0)
    }

    /// Whether this process has state that needs off-heap collection work.
    pub(crate) fn is_allocated(&self) -> bool {
        self.0.off_heap_first != 0
            || self.0.wrt_bins != 0
            || self.0.overhead != 0
            || self.0.vheap.min != 46_422
            || self.0.vheap.old != 0
            || self.0.vheap.old_size != 46_422
            || self.0.detached.is_some()
    }

    /// The refc and writable off-heap list heads in process state.
    pub(crate) fn chain_heads(&self) -> (usize, usize) {
        (self.0.off_heap_first, self.0.wrt_bins)
    }

    pub(crate) fn overhead(&self) -> u64 {
        self.0.overhead
    }

    pub(crate) fn vheap_min(&self) -> u64 {
        self.0.vheap.min
    }

    pub(crate) fn vheap_old(&self) -> u64 {
        self.0.vheap.old
    }

    pub(crate) fn vheap_old_size(&self) -> u64 {
        self.0.vheap.old_size
    }

    pub(crate) fn has_collection_state(&self) -> bool {
        self.0.vheap.min != 46_422 || self.0.vheap.old != 0 || self.0.vheap.old_size != 46_422
    }
}

impl std::ops::Deref for LazyOwners {
    type Target = HeapOwners;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl std::ops::DerefMut for LazyOwners {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

/// A heap with stack or old-generation words cannot be adopted as a message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdoptError {
    /// The source is not a standalone message fragment.
    NotStandalone,
}

impl ProcessHeap {
    /// Release process-owned heap storage after the exit phases have finished.
    // Port of erts/emulator/beam/erl_process.c (delete_process), OTP-29.1.1.
    pub fn clear_for_exit(&mut self) {
        self.abi = NativeAbi::default();
        self.owners = LazyOwners::default();
        self.fragments = Vec::new();
        self.words = WordBlock::default();
        self.old_words = WordBlock::default();
        self.old_htop = 0;
        self.min_heap_size = 233;
        self.fullsweep_after = u16::MAX;
        self.minor_since_major = 0;
        self.alloc_ix = NO_ALLOC_IX;
        self.bin_vheap = 0;
        self.bin_vheap_size = 46_422;
        self.heap_grow = false;
        self.native_allocation = false;
        self.native_redzone = false;
        self.bif_hidden_words = 0;
        self.detached = false;
        self.abandoned = false;
        self.mbuf_fast = MbufFast::default();
        self.fragment_words = 0;
        self.gc_enabled = true;
        self.live_frags_armed.set(false);
        self.live_frag_mark.set(0);
        self.live_frag_valid.set(false);
    }

    /// Byte offset of `fragment_words` (`mbuf_sz`) in the heap, for the native GC-desired test.
    // Port of erts/emulator/beam/erl_gc.h:132-139 (ERTS_IS_GC_DESIRED), OTP-29.1.1.
    pub const FRAGMENT_WORDS_OFFSET: usize = std::mem::offset_of!(ProcessHeap, fragment_words);
    /// Byte offset of the process off-heap overhead field.
    /// Size of the owner state kept inline, as `Process.off_heap` is in erts.
    pub const OWNERS_SIZE: usize = std::mem::size_of::<HeapOwners>();
    pub const OFF_HEAP_OVERHEAD_OFFSET: usize = std::mem::offset_of!(ProcessHeap, owners)
        + std::mem::offset_of!(LazyOwners, 0)
        + std::mem::offset_of!(HeapOwners, overhead);
    /// Byte offset of `bin_vheap_size` (`bin_vheap_sz`) in the heap.
    pub const BIN_VHEAP_SIZE_OFFSET: usize = std::mem::offset_of!(ProcessHeap, bin_vheap_size);
    /// Byte offset of `gc_enabled` in the heap.
    pub const GC_ENABLED_OFFSET: usize = std::mem::offset_of!(ProcessHeap, gc_enabled);

    /// Create a heap with 64 words, including stack space.
    pub fn new() -> Self {
        Self::with_words(64)
    }
    /// Create a heap of the specified word capacity.
    pub fn with_words(words: usize) -> Self {
        Self::with_words_for_type(words, ErtsAlcType::HEAP)
    }

    /// [`ProcessHeap::with_words`] allocating on allocator index `ix` (the creating scheduler's
    /// `esdp->no`, which must be the calling thread's). The heap does not keep the index: it is
    /// set on each run, since the new process may first run on another scheduler.
    pub fn with_words_at(words: usize, ix: Option<usize>) -> Self {
        let words_ix = ix.map_or(NO_ALLOC_IX, |ix| {
            u16::try_from(ix).map_or(NO_ALLOC_IX, |ix| ix.min(NO_ALLOC_IX - 1))
        });
        let mut heap = Self::with_words_for_type_at(words, ErtsAlcType::HEAP, words_ix);
        heap.alloc_ix = NO_ALLOC_IX;
        heap
    }

    /// Create a heap fragment block with the requested typed allocator.
    pub fn with_words_for_type(words: usize, allocation_type: ErtsAlcType) -> Self {
        Self::with_words_for_type_at(words, allocation_type, NO_ALLOC_IX)
    }

    fn with_words_for_type_at(words: usize, allocation_type: ErtsAlcType, alloc_ix: u16) -> Self {
        let block = WordBlock::new_for(words, allocation_type, alloc_ix);
        let base = block.as_ptr().cast::<u64>().cast_mut();
        Self {
            abi: NativeAbi {
                htop: base,
                stop: base.wrapping_add(words),
                heap: base,
                hend: base.wrapping_add(words),
                high_water: base,
                ..NativeAbi::default()
            },
            words: block,
            old_words: WordBlock::default(),
            old_htop: 0,
            min_heap_size: 233,
            fullsweep_after: u16::MAX,
            minor_since_major: 0,
            alloc_ix,
            bin_vheap: 0,
            bin_vheap_size: 46_422,
            heap_grow: false,
            native_allocation: false,
            native_redzone: false,
            bif_hidden_words: 0,
            detached: false,
            abandoned: false,
            fragments: Vec::new(),
            mbuf_fast: MbufFast::default(),
            fragment_words: 0,
            gc_enabled: true,
            live_frags_armed: std::cell::Cell::new(false),
            live_frag_mark: std::cell::Cell::new(0),
            live_frag_valid: std::cell::Cell::new(false),
            owners: LazyOwners::default(),
        }
    }

    /// Names the allocator index of the scheduler thread that runs this process, or `None` once
    /// it stops running, so heap blocks are allocated and freed without a thread-local read.
    ///
    /// Port of the `esdp->no` the scheduler passes to `erts_alloc` for the thread-specific heap
    /// types, in place of a lookup of the thread, OTP-29.1.1. The index must be that of the
    /// calling thread for as long as it is set.
    pub fn set_alloc_ix(&mut self, ix: Option<usize>) {
        self.alloc_ix = ix.map_or(NO_ALLOC_IX, |ix| {
            u16::try_from(ix).map_or(NO_ALLOC_IX, |ix| ix.min(NO_ALLOC_IX - 1))
        });
    }

    /// The allocator index set by [`ProcessHeap::set_alloc_ix`], `None` while the process is
    /// not running.
    #[inline]
    pub fn alloc_ix(&self) -> Option<usize> {
        (self.alloc_ix != NO_ALLOC_IX).then_some(usize::from(self.alloc_ix))
    }

    /// A word block of `allocation_type` for this heap's scheduler thread.
    pub(crate) fn new_block(&self, words: usize, allocation_type: ErtsAlcType) -> WordBlock {
        WordBlock::new_for(words, allocation_type, self.alloc_ix)
    }

    /// Frees every block of `fragments`, as [`Vec::clear`] would, on the allocator index of this
    /// heap's scheduler thread.
    #[inline]
    pub(crate) fn release_fragments(&self, fragments: &mut Vec<Fragment>) {
        if self.alloc_ix != NO_ALLOC_IX {
            for fragment in fragments.iter_mut() {
                if let Fragment::Block { memory, .. } = fragment {
                    memory.release_in_place_at(usize::from(self.alloc_ix));
                }
            }
        }
        fragments.clear();
    }

    /// Record the allocation state a failing builder can roll back to.
    // Port of erts/emulator/beam/erl_message.c (erts_factory_proc_init / erts_factory_proc_prealloc_init:
    // `original_htop`, `off_heap_saved`, `heap_frags_saved`, `heap_frags_saved_used`), OTP-29.1.1.
    pub fn factory_mark(&mut self) -> HeapFactoryMark {
        self.sync_mbuf_fast();
        let last_used = match self.fragments.last() {
            Some(Fragment::Block { used, .. }) => *used,
            _ => 0,
        };
        HeapFactoryMark {
            htop: self.htop_index(),
            fragments: self.fragments.len(),
            last_used,
            off_heap_first: self.owners.off_heap_first,
            overhead: self.owners.overhead,
            bin_vheap: self.bin_vheap,
        }
    }

    /// Discard everything allocated since `mark`: off-heap entries, heap fragments and the heap top.
    // Port of erts/emulator/beam/erl_message.c:1543 (erts_factory_undo, FACTORY_HALLOC), OTP-29.1.1.
    pub fn factory_undo(&mut self, mark: HeapFactoryMark) {
        self.sync_mbuf_fast();
        // Cleanup off-heap: cut the chain at the saved head and release the new entries.
        let first = self.owners.off_heap_first;
        if first != mark.off_heap_first {
            let mut prev = first;
            loop {
                let next = load((prev as *const u64).wrapping_add(2)) as usize;
                if next == mark.off_heap_first {
                    break;
                }
                prev = next;
            }
            store((prev as *mut u64).wrapping_add(2), 0);
            crate::gc::release_off_heap_chain(first);
            self.owners.off_heap_first = mark.off_heap_first;
            self.owners.overhead = mark.overhead;
        }
        self.bin_vheap = mark.bin_vheap;
        // Free the heap fragments added since the mark.
        if self.fragments.len() > mark.fragments {
            let mut added = self.fragments.split_off(mark.fragments);
            self.fragment_words -= added.iter().map(Fragment::len).sum::<usize>();
            self.release_fragments(&mut added);
        }
        // Roll back the heap top and fix the last fragment.
        self.set_htop_index(mark.htop);
        if mark.fragments > 0
            && let Some(Fragment::Block { used, .. }) = self.fragments.get_mut(mark.fragments - 1)
        {
            self.fragment_words -= *used - mark.last_used;
            *used = mark.last_used;
        }
        self.rebuild_mbuf_fast();
    }

    /// Reserve contiguous words for a process object.
    pub fn alloc(&mut self, words: usize) -> Option<*mut Term> {
        <Self as HeapAlloc>::alloc(self, words).map(|ptr| ptr.cast::<Term>())
    }
    /// Number of words consumed by heap objects.
    pub fn used_words(&self) -> usize {
        self.htop_index()
    }
    /// Write one allocated raw word for the `erts_debug:inconsistent_heap` test hook.
    ///
    /// This debug-only API deliberately permits invalid term headers and sentinels.
    pub fn debug_write_heap_word(&mut self, index: usize, word: u64) -> bool {
        let Some(cell) = self.words.get(index).filter(|_| index < self.htop_index()) else {
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
        let limit = if self.native_allocation || self.native_redzone {
            self.heap_limit_words()
        } else {
            self.stop_index()
        };
        limit.saturating_sub(self.htop_index())
    }
    /// Number of words between the heap and stack pointers.
    #[inline(always)]
    pub fn free_words(&self) -> usize {
        self.stop_index() - self.htop_index()
    }
    /// Runtime heap allocation boundary, leaving the stack redzone unused.
    // Port of erts/emulator/beam/erl_process.h:990-998, OTP-29.1.1.
    #[inline(always)]
    pub fn heap_limit_words(&self) -> usize {
        self.htop_index().max(
            self.stop_index()
                .saturating_add(self.bif_hidden_words)
                .saturating_sub(crate::S_REDZONE),
        )
    }
    /// `E - HTOP` as the erts BIF epilogue sees it, with the words of a native continuation that
    /// erts has not pushed yet left out of the stack.
    // Port of erts/emulator/beam/jit/arm/instr_bif.cpp (call_light_bif_shared computes
    // `E - HTOP` after the BIF returns, before any return address is pushed), OTP-29.1.1.
    pub fn bif_free_words(&self) -> usize {
        (self.stop_index() + self.bif_hidden_words).saturating_sub(self.htop_index())
    }
    /// Run a native BIF body as erts runs it: the `words` the executor already pushed for the
    /// caller's return are not part of the stack the body allocates against. Pass 0 to end it.
    // Port of erts/emulator/beam/jit/arm/instr_bif.cpp (call_light_bif_shared calls the
    // BIF with E at the caller's frame; only `context_switch_simplified` pushes the return
    // address), OTP-29.1.1.
    pub fn set_bif_hidden_words(&mut self, words: usize) {
        self.bif_hidden_words = words;
    }
    /// The free young-heap window `[HEAP_TOP, HEAP_LIMIT)` of the process as a slice, for BIF
    /// loops that fill cells by index and then publish `HEAP_TOP` once with
    /// [`ProcessHeap::commit_window`]. `None` for a detached heap, whose allocations never touch
    /// the young heap.
    // Port of erts/emulator/beam/erl_process.h:990-998 (HEAP_LIMIT), OTP-29.1.1.
    #[inline(always)]
    pub fn halloc_window(&mut self) -> Option<&mut [u64]> {
        if self.detached {
            return None;
        }
        let base = self.words.as_ptr() as usize;
        let top = self.abi.htop as usize;
        let limit = (self.abi.stop as usize)
            .wrapping_add(self.bif_hidden_words << 3)
            .wrapping_sub(crate::S_REDZONE << 3)
            .max(top);
        let (lo, hi) = (top.wrapping_sub(base) >> 3, limit.wrapping_sub(base) >> 3);
        self.words.words_mut().get_mut(lo..hi)
    }
    /// Publish `words` window words as allocated: `HEAP_TOP += words`.
    #[inline(always)]
    pub fn commit_window(&mut self, words: usize) {
        self.abi.htop = self.abi.htop.wrapping_add(words);
    }
    /// The list term of the cons cell `word_offset` words above the current `HEAP_TOP`; it
    /// designates window cells that the caller has written (and commits before use).
    #[inline(always)]
    pub fn window_list_term(&self, word_offset: usize) -> Term {
        Term((self.abi.htop as u64).wrapping_add((word_offset as u64) << 3) | 1)
    }
    /// Young-heap words available to `HAlloc` before it uses a fragment.
    // Port of erts/emulator/beam/erl_vm.h:150-175 (HAllocX/HeapWordsLeft), OTP-29.1.1.
    #[inline(always)]
    pub fn halloc_words_left(&self) -> Option<usize> {
        (!self.detached).then(|| self.heap_limit_words().saturating_sub(self.htop_index()))
    }
    /// Check `HeapWordsLeft` once and reserve object words plus a following-store allowance.
    #[inline(always)]
    pub fn reserve_halloc(
        &mut self,
        used_words: usize,
        extra_words: usize,
    ) -> Option<HAllocReservation<'_>> {
        if self.detached {
            return None;
        }
        let required = used_words.wrapping_add(extra_words);
        let top = self.abi.htop as usize;
        let limit = (self.abi.stop as usize)
            .wrapping_add(self.bif_hidden_words << 3)
            .wrapping_sub(crate::S_REDZONE << 3)
            .max(top);
        let available_words = limit.wrapping_sub(top) >> 3;
        (available_words >= required).then_some(HAllocReservation {
            heap: self,
            used_words,
        })
    }
    /// Reserve process-heap words using the attached-process `HeapWordsLeft` path.
    // Port of erts/emulator/beam/erl_vm.h:175 (`HeapWordsLeft`), OTP-29.1.1.
    #[inline(always)]
    pub fn reserve_native_halloc(
        &mut self,
        used_words: usize,
        extra_words: usize,
    ) -> Option<HAllocReservation<'_>> {
        debug_assert!(!self.detached);
        let required_bytes = used_words
            .wrapping_add(extra_words)
            .wrapping_mul(std::mem::size_of::<u64>());
        let top = self.abi.htop as usize;
        let limit = (self.abi.stop as usize)
            .wrapping_add(self.bif_hidden_words << 3)
            .wrapping_sub(crate::S_REDZONE << 3)
            .max(top);
        if limit.wrapping_sub(top) < required_bytes {
            None
        } else {
            Some(HAllocReservation {
                heap: self,
                used_words,
            })
        }
    }

    /// Link a freshly built append binary to the process writable-bin chain.
    // Port of `build_writable_bitstring` in erts/emulator/beam/erl_bits.c:1675-1700, OTP-29.1.1.
    #[inline(always)]
    pub fn link_writable_append_bin_ref(
        &mut self,
        bin_ref: *mut u64,
        overhead_words: u64,
        owner: arinsal_alloc::raw::OwnedBinaryRef,
    ) {
        debug_assert!(!self.detached);
        let owners = &mut self.owners.0;
        crate::raw::store(bin_ref.wrapping_add(2) as usize, owners.wrt_bins as u64);
        owners.wrt_bins = bin_ref as usize;
        owners.overhead = owners.overhead.wrapping_add(overhead_words);
        owner.transfer_to_bin_ref(bin_ref);
    }
    /// Allocate on the young heap only when `HAlloc` stays below `HEAP_LIMIT`.
    // Port of erts/emulator/beam/erl_vm.h:150-162 (HAllocX), OTP-29.1.1.
    #[inline(always)]
    pub fn alloc_halloc(&mut self, words: usize) -> Option<*mut u64> {
        // `HAlloc`: one test of `HEAP_LIMIT - HTOP >= n` against the cursors, which are
        // addresses. `end + REDZONE <= stop + hidden` is that test without the saturating
        // subtraction and the `max(htop)` clamp of `heap_limit_words`; the words are small, so
        // the products cannot wrap, and a detached heap or a request that fails the test takes
        // the full computation out of line.
        let top = self.abi.htop as usize;
        let end = top.wrapping_add(words << 3);
        if !self.detached
            && words < (1 << 40)
            && end.wrapping_add(crate::S_REDZONE << 3)
                <= self.abi.stop as usize + (self.bif_hidden_words << 3)
        {
            self.abi.htop = end as *mut u64;
            return Some(top as *mut u64);
        }
        self.alloc_halloc_slow(words)
    }

    /// Allocate `words` while keeping `extra` words available for native stores.
    // Port of `HeapWordsLeft` and `HAlloc` in erts/emulator/beam/erl_vm.h, OTP-29.1.1.
    #[inline(always)]
    pub fn alloc_halloc_with_extra(&mut self, words: usize, extra: usize) -> Option<*mut u64> {
        if self.detached {
            return self
                .owners
                .detached
                .as_deref_mut()?
                .alloc_with_extra(words, extra);
        }
        let required = words.checked_add(extra)?;
        if required < (1 << 40) {
            let top = self.abi.htop as usize;
            let end = top.wrapping_add(required << 3);
            if end.wrapping_add(crate::S_REDZONE << 3)
                <= self.abi.stop as usize + (self.bif_hidden_words << 3)
            {
                self.abi.htop = top.wrapping_add(words << 3) as *mut u64;
                return Some(top as *mut u64);
            }
        }
        let limit = self.heap_limit_words();
        if required > limit.saturating_sub(self.htop_index()) {
            return None;
        }
        let top = self.abi.htop as usize;
        self.abi.htop = top.checked_add(words.checked_mul(8)?)? as *mut u64;
        Some(top as *mut u64)
    }

    #[cold]
    #[inline(never)]
    fn alloc_halloc_slow(&mut self, words: usize) -> Option<*mut u64> {
        if self.detached {
            return self.owners.detached.as_deref_mut()?.alloc(words);
        }
        let top = self.abi.htop as usize;
        let end = top.checked_add(words.checked_mul(8)?)?;
        if end > self.words.as_ptr() as usize + (self.heap_limit_words() << 3) {
            return None;
        }
        self.abi.htop = end as *mut u64;
        Some(top as *mut u64)
    }
    /// Whether generated code is running on this heap (set by the native bridge).
    pub fn native_active(&self) -> bool {
        self.native_allocation
    }
    /// Words a collection check must leave free for an allocation: the redzone and the CP while
    /// generated code runs, only the redzone for a BIF the scheduler runs for a native exit.
    pub fn check_reserve(&self) -> usize {
        if self.native_allocation {
            crate::S_RESERVED
        } else if self.native_redzone {
            crate::S_REDZONE
        } else {
            0
        }
    }
    /// Words a normal allocation must leave free below the stack.
    pub fn allocation_reserve(&self) -> usize {
        if self.native_allocation {
            crate::S_REDZONE
        } else {
            0
        }
    }
    /// Keep runtime allocations below `HEAP_LIMIT` from here on: native code is about to run.
    pub fn arm_native_redzone(&mut self) {
        self.native_redzone = true;
    }
    /// Interpreted code allocates up to the stack pointer, like the erts interpreter.
    pub fn clear_native_redzone(&mut self) {
        self.native_redzone = false;
    }
    /// Record whether generated Erlang code is active on this heap.
    pub fn set_native_allocation(&mut self, active: bool) {
        self.native_allocation = active;
        // Port of erts/emulator/beam/erl_process.h (HEAP_LIMIT), OTP-29.1.1: a BIF the scheduler
        // runs for a native call exit allocates below the redzone like one called from the JIT.
        self.native_redzone |= active;
    }
    /// Return the current heap top and stack boundary for a VM-local bump cursor.
    /// The pointers remain valid until this heap collects or grows.
    pub fn heap_cursor(&self) -> (*mut u64, *mut u64) {
        (self.abi.htop, self.abi.stop)
    }
    /// Return the start and end of the young heap allocation.
    pub fn heap_bounds(&self) -> (*mut u64, *mut u64) {
        (self.abi.heap, self.abi.hend)
    }
    /// Refresh the native bounds after the collector replaces or resizes `words`.
    pub(crate) fn refresh_native_heap_bounds(&mut self) {
        self.abi.heap = self.words.as_ptr().cast::<u64>().cast_mut();
        self.abi.hend = self.abi.heap.wrapping_add(self.words.len());
    }
    /// Mature boundary as an index in the current young heap.
    pub(crate) fn high_water_index(&self) -> usize {
        (self.abi.high_water as usize).wrapping_sub(self.abi.heap as usize) >> 3
    }
    /// Set the mature boundary after collection.
    pub(crate) fn set_high_water_index(&mut self, index: usize) {
        self.abi.high_water = self.abi.heap.wrapping_add(index);
    }
    /// Return the address of the young-heap high-water boundary.
    pub fn high_water_ptr(&self) -> *mut u64 {
        self.abi.high_water
    }
    /// Commit a VM-local cursor before collection or another heap allocator runs.
    pub fn set_heap_top(&mut self, top: *mut u64) {
        let base = self.words.as_ptr() as usize;
        let address = top as usize;
        // The cursor is the BIF's own bump of the native HTOP (erts stores `HEAP_TOP` unchecked),
        // so the range test is a debug check, not a release cost on every light BIF.
        debug_assert!(
            address >= base && address <= base + self.stop_index() * 8,
            "heap top={address:#x} base={base:#x} stop={:#x} end={:#x}",
            base + self.stop_index() * 8,
            base + self.words.len() * 8,
        );
        debug_assert_eq!((address - base) % 8, 0);
        self.set_htop_index((address - base) / 8);
    }
    /// The young heap top as a word index from the heap base.
    #[inline(always)]
    pub(crate) fn htop_index(&self) -> usize {
        (self.abi.htop as usize).wrapping_sub(self.words.as_ptr() as usize) >> 3
    }
    /// Sets the young heap top from a word index.
    #[inline(always)]
    pub(crate) fn set_htop_index(&mut self, index: usize) {
        self.abi.htop = self
            .words
            .as_ptr()
            .cast::<u64>()
            .cast_mut()
            .wrapping_add(index);
    }
    /// The stack pointer as a word index from the heap base.
    #[inline(always)]
    pub(crate) fn stop_index(&self) -> usize {
        (self.abi.stop as usize).wrapping_sub(self.words.as_ptr() as usize) >> 3
    }
    /// Sets the stack pointer from a word index.
    #[inline(always)]
    pub(crate) fn set_stop_index(&mut self, index: usize) {
        self.abi.stop = self
            .words
            .as_ptr()
            .cast::<u64>()
            .cast_mut()
            .wrapping_add(index);
    }
    /// The young heap top as an address, `c_p->htop`.
    #[inline(always)]
    pub fn heap_top_addr(&self) -> usize {
        self.abi.htop as usize
    }
    /// Young heap top as a word index.
    #[inline]
    pub fn heap_top_index(&self) -> usize {
        self.htop_index()
    }
    /// Stack pointer as a word index.
    #[inline]
    pub fn stack_index(&self) -> usize {
        self.stop_index()
    }
    /// Capacity of the heap fragments in words (`mbuf_sz`), as [`ProcessHeap::gc_desired`]
    /// compares it.
    #[inline]
    pub fn mbuf_size(&self) -> usize {
        self.fragment_words
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
        assert!(index >= self.htop_index());
        self.set_stop_index(index);
    }
    /// Reserve stack words from the high end.
    pub fn reserve_stack(&mut self, words: usize) -> bool {
        if words > self.free_words() {
            return false;
        }
        self.set_stop_index(self.stop_index() - (words));
        true
    }
    /// Allocate a side fragment when a BIF cannot collect at this point.
    pub fn heap_fragment(&mut self, words: usize) -> *mut u64 {
        self.heap_fragment_with_extra(words, 0)
    }

    /// Publish the cached `mbuf` used size to the corresponding fragment before a slow walk.
    pub(crate) fn sync_mbuf_fast(&mut self) {
        let mbuf = self.mbuf_fast;
        if mbuf.base == 0 {
            return;
        }
        if let Some(Fragment::Block { memory, used }) = self.fragments.get_mut(mbuf.fragment_index)
        {
            debug_assert_eq!(memory.as_ptr() as usize, mbuf.base);
            *used = mbuf.used_size;
        }
    }

    pub(crate) fn set_mbuf_fast(&mut self, index: usize) {
        self.sync_mbuf_fast();
        self.mbuf_fast = match self.fragments.get(index) {
            Some(Fragment::Block { memory, used }) => MbufFast {
                base: memory.as_ptr() as usize,
                alloc_size: memory.len(),
                used_size: *used,
                fragment_index: index,
            },
            _ => MbufFast::default(),
        };
    }

    /// Rebuild the fast cursor after an operation replaces or adopts the fragment list.
    pub(crate) fn rebuild_mbuf_fast(&mut self) {
        let index = self
            .fragments
            .iter()
            .rposition(|fragment| matches!(fragment, Fragment::Block { .. }));
        if let Some(index) = index {
            self.set_mbuf_fast(index);
        } else {
            self.mbuf_fast = MbufFast::default();
        }
    }

    #[inline]
    pub(crate) fn fragment_used_words(&self, index: usize, fragment: &Fragment) -> usize {
        if self.mbuf_fast.base != 0
            && self.mbuf_fast.fragment_index == index
            && let Fragment::Block { .. } = fragment
        {
            return self.mbuf_fast.used_size;
        }
        fragment.len()
    }

    /// Allocate a side fragment with spare capacity for subsequent BIF allocations.
    ///
    /// Port of erts/emulator/beam/utils.c:135-189 (`erts_heap_alloc`), OTP-29.1.1.
    pub fn heap_fragment_with_extra(&mut self, words: usize, extra: usize) -> *mut u64 {
        // Port of the MBUF fast path in erts/emulator/beam/utils.c:148-154, OTP-29.1.1.
        let mbuf = &mut self.mbuf_fast;
        if mbuf.base != 0 && words <= mbuf.alloc_size - mbuf.used_size {
            let ret = (mbuf.base as *mut u64).wrapping_add(mbuf.used_size);
            mbuf.used_size += words;
            self.fragment_words += words;
            return ret;
        }
        if self.detached
            && let Some(ptr) = self
                .owners
                .detached
                .as_deref_mut()
                .and_then(|heap| heap.alloc_with_extra(words, extra))
        {
            return ptr;
        }
        let block_words = words.checked_add(extra).unwrap_or(words);
        // Port of erts/emulator/beam/utils.c:173-186 (`erts_heap_alloc`), OTP-29.1.1.
        // ERTS initializes only the requested term span; the spare fragment capacity is untouched.
        let mut memory = if self.alloc_ix == NO_ALLOC_IX {
            AllocBlock::new(ErtsAlcType::HEAP_FRAG, block_words)
        } else {
            AllocBlock::new_at(
                usize::from(self.alloc_ix),
                ErtsAlcType::HEAP_FRAG,
                block_words,
            )
        }
        .expect("heap fragment allocation size is valid");
        let ptr = memory.as_mut_ptr();
        let alloc_size = memory.len();
        self.sync_mbuf_fast();
        let fragment_index = self.fragments.len();
        self.fragments.push(Fragment::Block {
            memory,
            used: words,
        });
        self.mbuf_fast = MbufFast {
            base: ptr as usize,
            alloc_size,
            used_size: words,
            fragment_index,
        };
        self.fragment_words += words;
        ptr
    }
    /// Move a standalone message heap into this process without copying its terms.
    ///
    /// The source must have no live stack or old generation. Terms allocated in
    /// it remain valid until this process next collects its fragments.
    pub fn adopt_message_fragment(&mut self, mut source: ProcessHeap) -> Result<(), AdoptError> {
        if source.stop_index() != source.words.len()
            || source.old_htop != 0
            || !source.old_words.is_empty()
        {
            return Err(AdoptError::NotStandalone);
        }
        // Dirty-shadow process heaps retain their separate ABI object until ownership moves.
        // Port of erts_flush_dirty_shadow_proc and erts_heap_alloc, OTP-29.1.1.
        source.sync_mbuf_fast();
        self.sync_mbuf_fast();
        let adopted_words = source.htop_index() + source.fragment_words;
        self.fragment_words += adopted_words;
        let used = source.htop_index();
        let block = std::mem::take(&mut source.words).into_alloc_block();
        source.abi.htop = std::ptr::null_mut();
        source.abi.stop = std::ptr::null_mut();
        let used = used.min(block.len());
        self.fragments.push(Fragment::Block {
            memory: block,
            used,
        });
        self.fragments.append(&mut source.fragments);
        self.rebuild_mbuf_fast();
        self.abandoned |= source.abandoned;
        self.absorb_fragment_owners(&mut source);
        Ok(())
    }

    /// Adopt a standalone `ErlHeapFragment` without copying its term words.
    // Port of erts_save_message_in_proc, OTP-29.1.1.
    pub fn adopt_message_heap_block(&mut self, source: crate::message::MessageHeapBlock) {
        let (block, used, off_heap, bin_vheap) = source.into_parts();
        self.sync_mbuf_fast();
        self.fragment_words += used;
        let used = used.min(block.len());
        let fragment_index = self.fragments.len();
        self.fragments.push(Fragment::Block {
            memory: block,
            used,
        });
        self.set_mbuf_fast(fragment_index);
        self.absorb_off_heap(off_heap, bin_vheap);
    }

    /// Keep the inline heap fragment of a received message as a fragment of this process,
    /// with its off-heap objects linked into this process's lists (`erts_save_message_in_proc`
    /// for an `ERTS_MSG_COMBINED_HFRAG` message). The words are not copied.
    // Port of erts/emulator/beam/erl_message.c (erts_save_message_in_proc), OTP-29.1.1.
    pub fn adopt_message_node(&mut self, mut fragment: crate::message::NodeFragment) {
        let (off_heap, bin_vheap) = fragment.take_owners();
        self.absorb_off_heap(off_heap, bin_vheap);
        self.fragment_words += fragment.len();
        self.fragments.push(Fragment::Node(fragment));
    }

    /// Adopt the data of a received message, wherever it was allocated.
    pub fn adopt_message_heap(
        &mut self,
        data: crate::message::MessageHeap,
    ) -> Result<(), AdoptError> {
        match data {
            crate::message::MessageHeap::Heap(heap) => {
                self.adopt_message_heap_block(heap);
                Ok(())
            }
            crate::message::MessageHeap::Node(fragment) => {
                self.adopt_message_node(fragment);
                Ok(())
            }
        }
    }

    /// Flush the heap a dirty job built into this process.
    ///
    /// Port of erts/emulator/beam/erl_nfunc_sched.h (erts_flush_dirty_shadow_proc) and
    /// erts/emulator/beam/erl_nif.c (alloc_heap, flush_env), OTP-29.1.1: a dirty NIF allocates
    /// on the process heap from `HEAP_TOP` up to `HEAP_LIMIT`, so what fits lies on the young
    /// heap and `c_p->htop` moves past it. Only when the job outgrew the free words do its
    /// words stay in heap fragments, which [`ProcessHeap::adopt_message_fragment`] adopts.
    ///
    /// `roots` are the terms outside the block that point into it. The block moves word for
    /// word, so unreachable words the job allocated stay as they are in erts.
    pub fn flush_dirty_shadow(
        &mut self,
        mut source: ProcessHeap,
        roots: &mut [&mut Term],
    ) -> Result<(), AdoptError> {
        if source.stop_index() != source.words.len()
            || source.old_htop != 0
            || !source.old_words.is_empty()
        {
            return Err(AdoptError::NotStandalone);
        }
        let used = source.htop_index();
        let fits = !self.detached
            && source.fragments.is_empty()
            && source.fragment_words == 0
            && !self.words.is_empty()
            && !source.detached
            && self.halloc_words_left().is_some_and(|left| used <= left)
            && Self::shadow_block_is_movable(
                &source.words.words()[..used],
                &(source.words.as_ptr() as usize..source.words.as_ptr() as usize + used * 8),
            );
        if !fits {
            return self.adopt_message_fragment(source);
        }
        let from = source.words.as_ptr() as usize;
        let to = self.words.as_ptr() as usize + self.htop_index() * 8;
        let delta = to.wrapping_sub(from) as u64;
        let range = from..from + used * 8;
        let rebase = |word: u64| {
            if word & 3 != 0 && word & 3 != 3 && range.contains(&((word & !7) as usize)) {
                word.wrapping_add(delta)
            } else {
                word
            }
        };
        {
            let htop = self.htop_index();
            let target = &mut self.words.words_mut()[htop..htop + used];
            target.copy_from_slice(&source.words.words()[..used]);
            let mut index = 0;
            while index < used {
                let word = target[index];
                if word & 3 != 0 {
                    target[index] = rebase(word);
                    index += 1;
                    continue;
                }
                match word & 63 {
                    BIN_REF => {
                        let next = target[index + 2];
                        if range.contains(&(next as usize)) {
                            target[index + 2] = next.wrapping_add(delta);
                        }
                        index += 1 + (word >> 6) as usize;
                    }
                    SUB_BITS => {
                        target[index + 4] = rebase(target[index + 4]);
                        index += 1 + (word >> 6) as usize;
                    }
                    ARITY => index += 1,
                    _ => index += 1 + (word >> 6) as usize,
                }
            }
        }
        for root in roots.iter_mut() {
            **root = Term(rebase(root.0));
        }
        let owners = &mut source.owners.0;
        for head in [&mut owners.off_heap_first, &mut owners.wrt_bins] {
            if range.contains(&*head) {
                *head = (*head as u64).wrapping_add(delta) as usize;
            }
        }
        self.set_htop_index(self.htop_index() + (used));
        self.absorb_fragment_owners(&mut source);
        Ok(())
    }

    /// Whether every object in the used words of a dirty shadow block can move with a plain
    /// word copy and pointer rebase: tuples, lists, numbers, heap binaries, binary
    /// references (their off-heap chain links lie in the block) and sub-binaries of those.
    fn shadow_block_is_movable(words: &[u64], block: &std::ops::Range<usize>) -> bool {
        let mut index = 0;
        while index < words.len() {
            let word = words[index];
            if word & 3 != 0 {
                index += 1;
                continue;
            }
            let object_words = 1 + (word >> 6) as usize;
            match word & 63 {
                ARITY => index += 1,
                POS_BIG | NEG_BIG | FLOAT | HEAP_BITS => index += object_words,
                BIN_REF => {
                    if index + 2 >= words.len() {
                        return false;
                    }
                    index += object_words;
                }
                SUB_BITS => {
                    let base = words.get(index + 1).copied().unwrap_or(0) as usize;
                    if index + object_words > words.len() || block.contains(&base) {
                        return false;
                    }
                    index += object_words;
                }
                _ => return false,
            }
        }
        index == words.len()
    }

    /// Words of message data held by a standalone message heap: the used part of its block
    /// and of each heap fragment.
    // Port of erts/emulator/beam/erl_message.h (erts_msg_attached_data_size), OTP-29.1.1.
    pub fn message_data_size(&self) -> usize {
        self.fragments
            .iter()
            .enumerate()
            .filter_map(|(index, fragment)| match fragment {
                Fragment::Block { .. } => Some(self.fragment_used_words(index, fragment)),
                Fragment::Node(fragment) => Some(fragment.len()),
                Fragment::Abandoned { .. } => None,
            })
            .fold(self.htop_index(), usize::saturating_add)
    }

    /// Link the off-heap objects of a message fragment into this process's off-heap list
    /// and add its virtual binary heap overhead.
    // Port of erts/emulator/beam/erl_message.c:980-990 (erts_save_message_in_proc) and
    // erl_gc.c:2524 (OH_OVERHEAD in erts_copy_one_frag), OTP-29.1.1.
    pub(crate) fn absorb_fragment_owners(&mut self, source: &mut ProcessHeap) {
        let owners = std::mem::take(&mut source.owners);
        self.absorb_owners(owners, source.bin_vheap);
    }

    /// [`ProcessHeap::absorb_fragment_owners`] of the off-heap owners and virtual binary heap
    /// words of a message fragment.
    pub(crate) fn absorb_off_heap(&mut self, mut source: OffHeapLists, bin_vheap: u64) {
        if source.off_heap_first == 0 && source.wrt_bins == 0 && source.overhead == 0 {
            return;
        }
        self.bin_vheap = self.bin_vheap.saturating_add(bin_vheap);
        let target = &mut *self.owners;
        Self::prepend_bin_ref_chain(
            &mut target.off_heap_first,
            std::mem::take(&mut source.off_heap_first),
        );
        Self::prepend_bin_ref_chain(&mut target.wrt_bins, std::mem::take(&mut source.wrt_bins));
        target.overhead = target.overhead.saturating_add(source.overhead);
    }

    pub(crate) fn absorb_owners(&mut self, mut source: LazyOwners, bin_vheap: u64) {
        if !source.is_allocated() {
            return;
        }
        self.bin_vheap = self.bin_vheap.saturating_add(bin_vheap);
        self.owners.vheap.old = self.owners.vheap.old.saturating_add(source.vheap.old);
        Self::prepend_bin_ref_chain(
            &mut self.owners.off_heap_first,
            std::mem::take(&mut source.off_heap_first),
        );
        Self::prepend_bin_ref_chain(
            &mut self.owners.wrt_bins,
            std::mem::take(&mut source.wrt_bins),
        );
        self.owners.overhead = self.owners.overhead.saturating_add(source.overhead);
    }

    fn prepend_bin_ref_chain(head: &mut usize, prefix: usize) {
        if prefix == 0 {
            return;
        }
        let mut tail = prefix;
        loop {
            let next = load((tail as *const u64).wrapping_add(2)) as usize;
            if next == 0 {
                break;
            }
            tail = next;
        }
        store((tail as *mut u64).wrapping_add(2), *head as u64);
        *head = prefix;
    }
    /// Number of off-heap binary owners retained by this process.
    pub fn off_heap_count(&self) -> usize {
        Self::bin_ref_chain_count(self.owners.off_heap_first)
            + Self::bin_ref_chain_count(self.owners.wrt_bins)
    }

    fn bin_ref_chain_count(mut head: usize) -> usize {
        let mut count = 0;
        while head != 0 {
            count += usize::from(off_heap_node_is_bin_ref(head));
            head = load((head as *const u64).wrapping_add(2)) as usize;
        }
        count
    }

    /// Number of bytes in the process's retained non-writable binaries.
    pub fn off_heap_binary_bytes(&self) -> u64 {
        let mut bytes = 0u64;
        let mut head = self.owners.off_heap_first;
        while head != 0 {
            if off_heap_node_is_bin_ref(head) {
                let val = load((head as *const u64).wrapping_add(1));
                bytes = bytes.saturating_add(if crate::bits::bin_ref_val_is_external(val) {
                    crate::bits::external_val_len(val) as u64
                } else {
                    load((val as *const u64).wrapping_add(3))
                });
            }
            head = load((head as *const u64).wrapping_add(2)) as usize;
        }
        bytes
    }

    /// Return one `(identity, byte length, refcount)` per retained refc binary reference.
    ///
    /// Port of erts/emulator/beam/erl_bif_info.c:179 (erts_bld_bin_list), OTP-29.1.1: every
    /// reference in the off-heap list is reported separately, newest first.
    pub fn off_heap_binary_info(&self) -> Vec<(usize, usize, usize)> {
        let o = &self.owners;
        let mut out = Vec::new();
        for mut head in [o.off_heap_first, o.wrt_bins] {
            while head != 0 {
                let bin_ref = head as *const u64;
                if off_heap_node_is_bin_ref(head) {
                    let val = load(bin_ref.wrapping_add(1));
                    if crate::bits::bin_ref_val_is_external(val) {
                        out.push((
                            crate::bits::external_val_ptr(val) as usize,
                            crate::bits::external_val_len(val),
                            crate::bits::external_val_strong_count(val),
                        ));
                    } else {
                        let binary = val as *const u64;
                        out.push((
                            binary as usize,
                            load(binary.wrapping_add(3)) as usize,
                            load(binary.wrapping_add(2)) as usize,
                        ));
                    }
                }
                head = load(bin_ref.wrapping_add(2)) as usize;
            }
        }
        out
    }

    /// Minimum virtual binary heap capacity, in machine words.
    pub fn min_bin_vheap_size(&self) -> u64 {
        self.owners.vheap.min
    }

    /// Current young virtual binary heap usage, in machine words.
    pub fn bin_vheap_used(&self) -> u64 {
        self.owners.overhead
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
        let min = words.max(46_422);
        self.bin_vheap_size = self.bin_vheap_size.max(min);
        // erts keeps `min_vheap_size` in the process; the owner box is created only when the
        // value differs from what it already holds (the default for a new process).
        if min == self.owners.vheap_min() && self.owners.vheap_old_size() >= min {
            return;
        }
        self.owners.vheap.min = min;
        self.owners.vheap.old_size = self.owners.vheap.old_size.max(min);
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
    // Port of erts/emulator/beam/erl_gc.h:132-139 (ERTS_IS_GC_DESIRED), OTP-29.1.1.
    #[inline(always)]
    pub fn bin_vheap_gc_due(&self) -> bool {
        self.owners.overhead > self.bin_vheap_size
    }

    /// Whether the epilogue of a BIF call collects: collection is enabled and heap fragments
    /// outgrew the free young area or the off-heap binary overhead passed its limit.
    // Port of erts/emulator/beam/erl_gc.h (ERTS_IS_GC_DESIRED) and erl_gc.c
    // (erts_gc_after_bif_call_lhf), OTP-29.1.1: one decision for both conditions, so a BIF
    // that trips both is collected once.
    #[inline(always)]
    pub fn gc_after_bif_desired(&self) -> bool {
        let desired = self.gc_enabled & (self.gc_desired() | self.bin_vheap_gc_due());
        if desired {
            self.live_frags_armed.set(true);
        } else {
            self.live_frag_valid.set(false);
        }
        desired
    }

    /// Record the fragment list as a BIF starts: the fragments added after this point are
    /// the BIF's and completely live when its epilogue collects.
    // Port of erts/emulator/beam/jit/arm/instr_bif.cpp:385 (`mbuf` spilled in
    // `emit_call_light_bif_shared`), OTP-29.1.1.
    #[inline(always)]
    pub fn note_bif_entry(&self) {
        self.live_frag_mark.set(self.fragments.len() as u32);
        self.live_frag_valid.set(true);
    }

    /// The fragment index from which a collection started by a BIF epilogue may treat the
    /// fragments as completely live (erts `live_hf_end`), consumed by the collection.
    // Port of erts/emulator/beam/erl_gc.c (`erts_gc_after_bif_call_lhf`), OTP-29.1.1.
    pub(crate) fn take_live_frags_from(&self) -> Option<usize> {
        let armed = self.live_frags_armed.replace(false);
        let valid = self.live_frag_valid.replace(false);
        let mark = self.live_frag_mark.replace(0) as usize;
        (armed && valid && mark <= self.fragments.len()).then_some(mark)
    }

    fn reservation_words_mut(
        &mut self,
        start: *mut u64,
        count: usize,
    ) -> Result<(&mut [u64], &mut LazyOwners, &mut u64), TermError> {
        self.sync_mbuf_fast();
        if self.detached {
            return Err(TermError::Unsupported("detached heap decode slice"));
        }
        let bytes = count
            .checked_mul(std::mem::size_of::<u64>())
            .ok_or(TermError::BadArg)?;
        let address = start as usize;
        let end = address.checked_add(bytes).ok_or(TermError::BadArg)?;
        let Self {
            words,
            abi,
            fragments,
            owners,
            bin_vheap,
            ..
        } = self;
        let young_base = words.as_ptr() as usize;
        let used_end = (abi.htop as usize).max(young_base);
        let used_words = (used_end - young_base) / std::mem::size_of::<u64>();
        let young_used_end = young_base.saturating_add(used_words.saturating_mul(8));
        if address >= young_base && end <= young_used_end {
            let offset = (address - young_base) / 8;
            let all = words.words_mut();
            return Ok((&mut all[offset..offset + count], owners, bin_vheap));
        }
        for fragment in fragments.iter_mut().rev() {
            if let Fragment::Block { memory, used } = fragment {
                let base = memory.as_ptr() as usize;
                let used_end = base.saturating_add(used.saturating_mul(8));
                if address >= base && end <= used_end {
                    let offset = (address - base) / 8;
                    return Ok((
                        &mut memory.as_mut_slice()[offset..offset + count],
                        owners,
                        bin_vheap,
                    ));
                }
            }
        }
        Err(TermError::BadArg)
    }
}
impl Default for ProcessHeap {
    fn default() -> Self {
        Self::new()
    }
}
impl HeapAlloc for ProcessHeap {
    fn allocator_identity(&self) -> usize {
        self.words.as_ptr() as usize
    }
    fn words_left(&self) -> Option<usize> {
        self.alloc_words_left()
    }
    // Port of erts/emulator/beam/erl_vm.h:164-173 (HRelease) and erl_process.h:1586-1598
    // (erts_heap_frag_shrink), OTP-29.1.1.
    fn release_needs_filler(&self, end: *mut u64, start: *mut u64) -> bool {
        if start == end || self.detached {
            return start != end;
        }
        let base = self.words.as_ptr() as usize;
        let top = base + self.htop_index() * 8;
        let address = start as usize;
        !(address >= base && address < top && end as usize == top)
    }
    fn release(&mut self, end: *mut u64, start: *mut u64) {
        if self.detached {
            if let Some(heap) = self.owners.detached.as_deref_mut() {
                heap.release(end, start);
            }
            return;
        }
        let mbuf = &mut self.mbuf_fast;
        let mbuf_end = mbuf.base + mbuf.used_size * std::mem::size_of::<u64>();
        if mbuf.base != 0
            && end as usize == mbuf_end
            && (start as usize) >= mbuf.base
            && (start as usize) <= mbuf_end
        {
            let new_used = (start as usize - mbuf.base) / std::mem::size_of::<u64>();
            let released = mbuf.used_size - new_used;
            mbuf.used_size = new_used;
            self.fragment_words -= released;
            return;
        }
        let base = self.words.as_ptr() as usize;
        let top = base + self.htop_index() * 8;
        let address = start as usize;
        if address >= base && address < top && end as usize == top {
            self.set_htop_index((address - base) / 8);
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
            self.fragment_words -= *used - new_used;
            *used = new_used;
        }
    }
    #[inline]
    fn alloc(&mut self, words: usize) -> Option<*mut u64> {
        if self.detached {
            return self.owners.detached.as_deref_mut()?.alloc(words);
        }
        let limit = if self.native_allocation || self.native_redzone {
            self.heap_limit_words()
        } else {
            self.stop_index()
        };
        let available = limit.saturating_sub(self.htop_index());
        if words > available {
            return None;
        }
        // SAFETY: htop is within the fixed boxed slice and capacity is checked.
        let ptr = unsafe {
            self.words
                .as_ptr()
                .add(self.htop_index())
                .cast::<u64>()
                .cast_mut()
        };
        self.set_htop_index(self.htop_index() + (words));
        Some(ptr)
    }
    #[inline]
    fn alloc_halloc(&mut self, words: usize) -> Option<*mut u64> {
        ProcessHeap::alloc_halloc(self, words)
    }
    #[inline]
    fn alloc_halloc_with_extra(&mut self, words: usize, extra: usize) -> Option<*mut u64> {
        ProcessHeap::alloc_halloc_with_extra(self, words, extra)
    }
    #[inline]
    fn alloc_with_extra(&mut self, words: usize, extra: usize) -> Option<*mut u64> {
        if self.detached {
            return self
                .owners
                .detached
                .as_deref_mut()?
                .alloc_with_extra(words, extra);
        }
        Some(
            self.alloc_halloc(words)
                .unwrap_or_else(|| self.heap_fragment_with_extra(words, extra)),
        )
    }
    fn alloc_fragment_only(&mut self, words: usize) -> Option<*mut u64> {
        // HeapFragOnlyAlloc reserves 512 extra words outside Valgrind builds.
        Some(self.heap_fragment_with_extra(words, 512))
    }
    #[inline(always)]
    fn shrink_fragment_tail(&mut self, start: *mut u64, allocated: usize, used: usize) {
        if self.detached {
            if let Some(heap) = self.owners.detached.as_deref_mut() {
                heap.shrink_fragment_tail(start, allocated, used);
            }
            return;
        }
        let released = allocated - used;
        self.mbuf_fast.used_size -= released;
        self.fragment_words -= released;
    }
    fn retain_binary(&mut self, binary: Arc<RefcBinary>) {
        if self.detached
            && let Some(heap) = self.owners.detached.as_deref_mut()
        {
            return heap.retain_binary(binary);
        }
        // Port of erts/emulator/beam/erl_message.h:85 (OH_OVERHEAD), OTP-29.1.1.
        self.bin_vheap = self.bin_vheap.saturating_add((binary.len() / 8) as u64);
        drop(binary);
    }
    fn link_bin_ref(
        &mut self,
        bin_ref: *mut u64,
        writable: bool,
        overhead_words: u64,
        owner: Option<arinsal_alloc::raw::OwnedBinaryRef>,
    ) -> Result<(), TermError> {
        if self.detached {
            if let Some(heap) = self.owners.0.detached.as_deref_mut() {
                return heap.link_bin_ref(bin_ref, writable, overhead_words, owner);
            }
            return Err(TermError::Unsupported("detached heap owner"));
        }
        let owners = &mut self.owners.0;
        let head = if writable {
            &mut owners.wrt_bins
        } else {
            &mut owners.off_heap_first
        };
        store(bin_ref.wrapping_add(2), *head as u64);
        *head = bin_ref as usize;
        if let Some(owner) = owner {
            owner.transfer_to_bin_ref(bin_ref);
        }
        owners.overhead = owners.overhead.saturating_add(overhead_words);
        Ok(())
    }
    fn add_bin_vheap(&mut self, words: u64) {
        if self.detached
            && let Some(heap) = self.owners.detached.as_deref_mut()
        {
            return heap.add_bin_vheap(words);
        }
        self.bin_vheap = self.bin_vheap.saturating_add(words);
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
        drop(binary);
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
        drop(binary);
        Ok(())
    }
    fn update_writable_binary_overhead(
        &mut self,
        source: Term,
        old_size_bits: usize,
        new_size_bits: usize,
    ) {
        let bin_ref = crate::bits::writable_bin_ref_address(source).unwrap_or(0);
        self.update_writable_binary_overhead_at(source, bin_ref, old_size_bits, new_size_bits);
    }
    #[inline(always)]
    fn update_writable_binary_overhead_at(
        &mut self,
        source: Term,
        bin_ref: usize,
        old_size_bits: usize,
        new_size_bits: usize,
    ) {
        if self.detached {
            if let Some(heap) = self.owners.0.detached.as_deref_mut() {
                heap.update_writable_binary_overhead(source, old_size_bits, new_size_bits);
            }
            return;
        }
        // Port of erl_bits.c:1660-1670 (`update_wb_overhead`), OTP-29.1.1.
        let increase = if new_size_bits > old_size_bits {
            (new_size_bits.div_ceil(8) / 8 - old_size_bits.div_ceil(8) / 8) as u64
        } else {
            0
        };
        let old_start = self.old_words.as_ptr() as usize;
        let old_end = old_start.wrapping_add(self.old_htop.wrapping_mul(8));
        let old_generation = bin_ref >= old_start && bin_ref < old_end;
        let owners = &mut self.owners.0;
        if old_generation {
            owners.vheap.old = owners.vheap.old.wrapping_add(increase);
        } else {
            owners.overhead = owners.overhead.wrapping_add(increase);
        }
    }
    fn supports_writable_binary(&self) -> bool {
        true
    }
    fn link_external_binary(
        &mut self,
        bin_ref: *mut u64,
        binary: Arc<ExternalBinary>,
    ) -> Result<(), TermError> {
        if self.detached
            && let Some(heap) = self.owners.detached.as_deref_mut()
        {
            return heap.link_external_binary(bin_ref, binary);
        }
        link_external_bin_ref(&mut self.owners.off_heap_first, bin_ref, binary);
        Ok(())
    }
    fn supports_external_binary(&self) -> bool {
        true
    }
    fn link_node(&mut self, thing: *mut u64, node: Arc<Node>) {
        if self.detached
            && let Some(heap) = self.owners.detached.as_deref_mut()
        {
            return heap.link_node(thing, node);
        }
        link_node_thing(&mut self.owners.off_heap_first, thing, node);
    }
    fn link_magic_ref(
        &mut self,
        thing: *mut u64,
        owner: Arc<crate::MagicRef>,
    ) -> Result<(), TermError> {
        if self.detached
            && let Some(heap) = self.owners.detached.as_deref_mut()
        {
            return heap.link_magic_ref(thing, owner);
        }
        let owners = &mut *self.owners;
        link_magic_thing(
            &mut owners.off_heap_first,
            &mut owners.overhead,
            thing,
            owner,
        );
        Ok(())
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
    off_heap_first: usize,
    wrt_bins: usize,
    overhead: u64,
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
        Self::with_initial_chunk_words(1024)
    }

    /// Create a growable heap whose first chunk has `words` capacity.
    pub fn with_initial_chunk_words(words: usize) -> Self {
        let words = words.max(1);
        Self {
            chunks: Vec::new(),
            off_heap_first: 0,
            wrt_bins: 0,
            overhead: 0,
            used: 0,
            total_used: 0,
            chunk_words: words,
        }
    }

    /// Clear allocated values and reuse the first chunk at the given initial capacity.
    pub fn reset(&mut self, initial_chunk_words: usize) {
        while self.chunks.len() > 1 {
            let chunk = self.chunks.pop().unwrap();
            #[cfg(any(feature = "validate-terms", debug_assertions, test))]
            crate::validate::forget_stable_range(chunk.as_ptr() as usize);
            drop(chunk);
        }
        crate::gc::release_off_heap_chain(self.off_heap_first);
        crate::gc::release_off_heap_chain(self.wrt_bins);
        self.off_heap_first = 0;
        self.wrt_bins = 0;
        self.overhead = 0;
        self.used = 0;
        self.total_used = 0;
        let literal = self.chunk_words & LITERAL_HEAP_BIT;
        self.chunk_words = initial_chunk_words.max(1) | literal;
    }
    /// Create a stable heap for module literal terms.
    pub fn new_literal() -> Self {
        let mut heap = Self::new();
        heap.chunk_words |= LITERAL_HEAP_BIT;
        heap
    }
    fn with_literal_chunk_words(words: usize) -> Self {
        let mut heap = Self::with_initial_chunk_words(words);
        heap.chunk_words |= LITERAL_HEAP_BIT;
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
        crate::gc::release_off_heap_chain(self.off_heap_first);
        crate::gc::release_off_heap_chain(self.wrt_bins);
        #[cfg(any(feature = "validate-terms", debug_assertions, test))]
        for chunk in &self.chunks {
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
        drop(binary);
    }
    fn link_bin_ref(
        &mut self,
        bin_ref: *mut u64,
        writable: bool,
        overhead_words: u64,
        owner: Option<arinsal_alloc::raw::OwnedBinaryRef>,
    ) -> Result<(), TermError> {
        let head = if writable {
            &mut self.wrt_bins
        } else {
            &mut self.off_heap_first
        };
        store(bin_ref.wrapping_add(2), *head as u64);
        *head = bin_ref as usize;
        if let Some(owner) = owner {
            owner.transfer_to_bin_ref(bin_ref);
        }
        self.overhead = self.overhead.saturating_add(overhead_words);
        Ok(())
    }
    fn add_bin_vheap(&mut self, _words: u64) {}
    fn retain_writable_binary(&mut self, binary: Arc<WritableBinary>) -> Result<(), TermError> {
        drop(binary);
        Ok(())
    }
    fn supports_writable_binary(&self) -> bool {
        true
    }
    fn link_external_binary(
        &mut self,
        bin_ref: *mut u64,
        binary: Arc<ExternalBinary>,
    ) -> Result<(), TermError> {
        link_external_bin_ref(&mut self.off_heap_first, bin_ref, binary);
        Ok(())
    }
    fn supports_external_binary(&self) -> bool {
        true
    }
    fn link_node(&mut self, thing: *mut u64, node: Arc<Node>) {
        link_node_thing(&mut self.off_heap_first, thing, node);
    }
    fn link_magic_ref(
        &mut self,
        thing: *mut u64,
        owner: Arc<crate::MagicRef>,
    ) -> Result<(), TermError> {
        link_magic_thing(&mut self.off_heap_first, &mut self.overhead, thing, owner);
        Ok(())
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

/// A reserved tuple whose elements can be filled in place before it is returned.
pub struct TupleBuilder<'a> {
    start: *mut u64,
    len: usize,
    _heap: std::marker::PhantomData<&'a mut ()>,
}

impl TupleBuilder<'_> {
    /// Replace one zero-based tuple element.
    pub fn set(&mut self, index: usize, value: Term) -> Result<(), TermError> {
        if index >= self.len {
            return Err(TermError::BadArg);
        }
        store(self.start.wrapping_add(index + 1), value.bits());
        Ok(())
    }

    /// Return the filled tuple.
    pub fn finish(self) -> Term {
        Term::from_ptr(self.start, 2)
    }
}

impl<'a, H: HeapAlloc + ?Sized> TermBuilder<'a, H> {
    /// Attach a builder to a heap.
    pub fn new(heap: &'a mut H) -> Self {
        Self { heap }
    }

    /// Reserve one contiguous HAlloc block for `len` cons cells.
    ///
    /// Push heads in reverse list order, then call [`ConsListBuilder::finish`] with the final tail.
    ///
    /// Port of erts/emulator/beam/erl_map.c:1222 and :2277, OTP-29.1.1.
    pub fn reserve_cons_list(&mut self, len: usize) -> Result<ConsListBuilder, TermError> {
        let words = len.checked_mul(2).ok_or(TermError::SystemLimit)?;
        let start = if words == 0 {
            std::ptr::null_mut()
        } else {
            self.words(words)?
        };
        Ok(ConsListBuilder {
            start: start as usize,
            len,
            written: 0,
            head: Term::NIL,
            first_cdr: None,
            last_cdr: None,
        })
    }
    /// Reserve a boxed heap object and fill its header and terms in allocation order.
    ///
    /// Port of `erts_produce_heap(factory, words, extra)` in
    /// erts/emulator/beam/erl_map.c:857-911, OTP-29.1.1. The reservation can live
    /// across a reduction yield while the object is filled.
    pub fn reserve_boxed_words(
        &mut self,
        words: usize,
        extra: usize,
    ) -> Result<HeapBlockBuilder, TermError> {
        if words == 0 {
            return Err(TermError::BadArg);
        }
        let start = self
            .heap
            .alloc_with_extra(words, extra)
            .ok_or(TermError::HeapFull)?;
        Ok(HeapBlockBuilder {
            start: start as usize,
            words,
            written: 0,
            slot_base: self.heap.term_slot(start),
        })
    }
    /// Reserve a tuple header and its element slots for an incremental decoder.
    ///
    /// Elements are written in decode order, so the block can stay in a parser
    /// frame while nested terms allocate later heap words. Port of the tuple
    /// reservation in `dec_term`, erts/emulator/beam/external.c, OTP-29.1.1.
    pub fn reserve_tuple_block(&mut self, arity: usize) -> Result<HeapBlockBuilder, TermError> {
        if arity == 0 {
            return Err(TermError::BadArg);
        }
        if arity > (1 << 24) - 1 {
            return Err(TermError::SystemLimit);
        }
        let words = arity.checked_add(1).ok_or(TermError::SystemLimit)?;
        let mut block = self.reserve_boxed_words(words, 0)?;
        block.write_header((arity as u64) << 6 | ARITY)?;
        Ok(block)
    }
    pub(crate) fn words(&mut self, words: usize) -> Result<*mut u64, TermError> {
        self.heap.alloc(words).ok_or(TermError::HeapFull)
    }
    /// Build a tuple with OTP's arity header.
    pub fn tuple(&mut self, values: &[Term]) -> Result<Term, TermError> {
        self.tuple_iter(values.len(), values.iter().copied())
    }

    /// Build a 2-tuple with the fixed `HAlloc(3)` layout used by map BIF results.
    ///
    /// Port of `maps_find_2` and `maps_take_2` in erts/emulator/beam/erl_map.c:225-267,
    /// OTP-29.1.1.
    #[inline(always)]
    pub fn tuple2(&mut self, first: Term, second: Term) -> Result<Term, TermError> {
        let start = self.words(3)?;
        store(start, (2 << 6) | ARITY);
        store(start.wrapping_add(1), first.bits());
        store(start.wrapping_add(2), second.bits());
        Ok(Term::from_ptr(start, 2))
    }

    /// Build a list of 2-tuples by consing each pair from one `5 * len` word reservation.
    ///
    /// Port of `pd_hash_get_all` in erts/emulator/beam/erl_process_dict.c, OTP-29.1.1.
    /// The caller supplies pairs in bucket scan order; the returned list is reversed as each
    /// tuple is consed onto the head.
    pub fn tuple2_list_from_iter_reversed(
        &mut self,
        len: usize,
        pairs: impl IntoIterator<Item = (Term, Term)>,
    ) -> Result<Term, TermError> {
        if len == 0 {
            return Ok(Term::NIL);
        }
        let words = len.checked_mul(5).ok_or(TermError::SystemLimit)?;
        let start = self.words(words)?;
        let mut result = Term::NIL;
        let mut count = 0;
        for (index, (key, value)) in pairs.into_iter().enumerate() {
            if index >= len {
                return Err(TermError::BadArg);
            }
            let tuple = start.wrapping_add(index * 5);
            store(tuple, (2 << 6) | ARITY);
            store(tuple.wrapping_add(1), key.bits());
            store(tuple.wrapping_add(2), value.bits());
            let cons = tuple.wrapping_add(3);
            store(cons, Term::from_ptr(tuple, 2).bits());
            store(cons.wrapping_add(1), result.bits());
            result = Term::from_ptr(cons, 1);
            count += 1;
        }
        if count != len {
            return Err(TermError::BadArg);
        }
        Ok(result)
    }

    /// Reserve and initialize a nonempty tuple so a BIF can apply indexed updates in place.
    /// Port of the `HAlloc` and element stores in `make_tuple_3`,
    /// erts/emulator/beam/bif.c:3033-3074, OTP-29.1.1.
    pub fn reserve_tuple(
        &mut self,
        len: usize,
        initial: Term,
    ) -> Result<TupleBuilder<'_>, TermError> {
        if len == 0 || len > (1 << 24) - 1 {
            return Err(if len == 0 {
                TermError::BadArg
            } else {
                TermError::SystemLimit
            });
        }
        let start = self.words(len + 1)?;
        store(start, (len as u64) << 6 | ARITY);
        for index in 0..len {
            store(start.wrapping_add(index + 1), initial.bits());
        }
        Ok(TupleBuilder {
            start,
            len,
            _heap: std::marker::PhantomData,
        })
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

    /// Copy a tuple and append one element in the same allocation.
    ///
    /// Port of `append_element_2`, erts/emulator/beam/bif.c:3083-3108, OTP-29.1.1.
    #[inline]
    pub fn tuple_append(
        &mut self,
        source: &crate::TupleRef<'_>,
        appended: Term,
    ) -> Result<Term, TermError> {
        let arity = source.len();
        let len = arity.checked_add(1).ok_or(TermError::BadArg)?;
        if len > (1 << 24) - 1 {
            return Err(TermError::BadArg);
        }
        let p = self.words(len + 1)?;
        store(p, (len as u64) << 6 | ARITY);
        let mut dst = p.wrapping_add(1);
        for value in source.iter() {
            store(dst, value.bits());
            dst = dst.wrapping_add(1);
        }
        store(dst, appended.bits());
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
}

// Port of erts/emulator/beam/big.c (small_to_big), OTP-29.1.1.
fn small_to_big_words(value: i64) -> [u64; 2] {
    let negative = value < 0;
    [
        (1 << 6) | if negative { NEG_BIG } else { POS_BIG },
        value.unsigned_abs(),
    ]
}

/// File and line of one MFA frame: `[{file, File}, {line, Line}]`.
///
/// `file_atom` and `line_atom` are the predefined `file` and `line` atoms.
/// `file` is the literal filename term (`fi->fname_ptr[file]`).
pub struct MfaLocation {
    /// The atom `file`.
    pub file_atom: Term,
    /// Literal filename.
    pub file: Term,
    /// The atom `line`.
    pub line_atom: Term,
    /// Source line as a small integer.
    pub line: Term,
}

impl<'a, H: HeapAlloc + ?Sized> TermBuilder<'a, H> {
    /// Box a positive bignum from little-endian digits without normalising to a small.
    pub fn pos_bignum_from_digits(&mut self, digits: &[u64]) -> Result<Term, TermError> {
        self.pos_bignum_fill(digits.len(), |index| digits[index])
    }

    /// Allocate a positive bignum and store each digit once.
    ///
    /// Port of `HAlloc` plus the stores into `struct StackTrace` in
    /// erts/emulator/beam/beam_common.c:884-893, OTP-29.1.1. `digit_at` runs while the
    /// words are written; there is no separate zero-filled buffer.
    pub fn pos_bignum_fill(
        &mut self,
        digits: usize,
        digit_at: impl FnMut(usize) -> u64,
    ) -> Result<Term, TermError> {
        if digits == 0 || digits > 65_535 {
            return Err(TermError::SystemLimit);
        }
        let p = self.words(1 + digits)?;
        self.write_bignum(p, digits, Sign::Plus, digit_at);
        Ok(Term::from_ptr(p, 2))
    }

    /// Allocate a negative bignum with an exact digit count and store each digit once.
    ///
    /// Port of `make_neg_bignum_header` and the `StackTrace` allocation in
    /// erts/emulator/beam/bif.c:1675-1685, OTP-29.1.1.
    pub fn neg_bignum_fill(
        &mut self,
        digits: usize,
        digit_at: impl FnMut(usize) -> u64,
    ) -> Result<Term, TermError> {
        if digits == 0 || digits > 65_535 {
            return Err(TermError::SystemLimit);
        }
        let p = self.words(1 + digits)?;
        self.write_bignum(p, digits, Sign::Minus, digit_at);
        Ok(Term::from_ptr(p, 2))
    }

    /// Allocate a positive bignum header and leave the digits for the caller to fill.
    ///
    /// Port of `HAlloc` of `struct StackTrace` in beam_common.c:889-893, OTP-29.1.1.
    /// The digit words are not a second buffer; `with_bignum_digits_mut` stores them.
    pub fn pos_bignum_reserve(&mut self, digits: usize) -> Result<Term, TermError> {
        if digits == 0 || digits > 65_535 {
            return Err(TermError::SystemLimit);
        }
        let p = self.words(1 + digits)?;
        store(p, ((digits as u64) << 6) | POS_BIG);
        for index in 0..digits {
            store(p.wrapping_add(1 + index), 0);
        }
        Ok(Term::from_ptr(p, 2))
    }

    /// Reserve a positive bignum as an incremental heap block, without touching its digits.
    ///
    /// The caller must initialize every digit it will later read before exposing the term.
    /// Port of the `HAlloc` and header store for `struct StackTrace` in
    /// erts/emulator/beam/beam_common.c:889-893, OTP-29.1.1.
    pub fn pos_bignum_block(&mut self, digits: usize) -> Result<HeapBlockBuilder, TermError> {
        if digits == 0 || digits > 65_535 {
            return Err(TermError::SystemLimit);
        }
        let words = digits.checked_add(1).ok_or(TermError::SystemLimit)?;
        let mut block = self.reserve_boxed_words(words, 0)?;
        block.write_header(((digits as u64) << 6) | POS_BIG)?;
        Ok(block)
    }

    /// Cons `{Module, Function, ArityOrArgs, Location}` onto `tail`.
    ///
    /// Without `location` the location is `[]`. The whole frame, including its
    /// list cell, is one allocation.
    // Port of erts/emulator/beam/utils.c:3430 (`erts_build_mfa_item`) and
    // beam_common.c:1280 (`CONS` of that item), OTP-29.1.1.
    pub fn cons_mfa_frame(
        &mut self,
        module: Term,
        function: Term,
        arity_or_args: Term,
        location: Option<MfaLocation>,
        tail: Term,
    ) -> Result<Term, TermError> {
        let words = if location.is_some() { 17 } else { 7 };
        let hp = self.words(words)?;
        let loc = if let Some(MfaLocation {
            file_atom,
            file: file_term,
            line_atom,
            line: line_term,
        }) = location
        {
            store(hp, (2 << 6) | ARITY);
            store(hp.wrapping_add(1), line_atom.bits());
            store(hp.wrapping_add(2), line_term.bits());
            let line_tuple = Term::from_ptr(hp, 2);
            store(hp.wrapping_add(3), line_tuple.bits());
            store(hp.wrapping_add(4), Term::NIL.bits());
            let line_cons = Term::from_ptr(hp.wrapping_add(3), 1);
            store(hp.wrapping_add(5), (2 << 6) | ARITY);
            store(hp.wrapping_add(6), file_atom.bits());
            store(hp.wrapping_add(7), file_term.bits());
            let file_tuple = Term::from_ptr(hp.wrapping_add(5), 2);
            store(hp.wrapping_add(8), file_tuple.bits());
            store(hp.wrapping_add(9), line_cons.bits());
            (Term::from_ptr(hp.wrapping_add(8), 1), 10)
        } else {
            (Term::NIL, 0)
        };
        let (loc, at) = loc;
        store(hp.wrapping_add(at), (4 << 6) | ARITY);
        store(hp.wrapping_add(at + 1), module.bits());
        store(hp.wrapping_add(at + 2), function.bits());
        store(hp.wrapping_add(at + 3), arity_or_args.bits());
        store(hp.wrapping_add(at + 4), loc.bits());
        let frame = Term::from_ptr(hp.wrapping_add(at), 2);
        let cell = at + 5;
        store(hp.wrapping_add(cell), frame.bits());
        store(hp.wrapping_add(cell + 1), tail.bits());
        Ok(Term::from_ptr(hp.wrapping_add(cell), 1))
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
        store(p, head.bits());
        store(p.wrapping_add(1), tail.bits());
        Ok(Term::from_ptr(p, 1))
    }
    /// Build a list in iteration order from one reservation of `2 * n` words.
    /// Port of the single `HAlloc(c_p, 2*n)` followed by `buf_to_intlist`
    /// (erts/emulator/beam/utils.c) that `integer_to_list` in
    /// erts/emulator/beam/bif.c issues: the whole run lands on the heap or in
    /// one heap fragment, never split across both.
    pub fn list_from_iter(
        &mut self,
        values: impl IntoIterator<Item = Term>,
    ) -> Result<Term, TermError> {
        let values: Vec<Term> = values.into_iter().collect();
        self.list_from_slice(&values)
    }
    /// Build a list from a reverse-scannable iterator with one heap reservation.
    ///
    /// Port of `erts_make_list_from_utf8_buf` in erts/emulator/beam/erl_unicode.c,
    /// OTP-29.1.1.
    pub fn list_from_reverse_iter(
        &mut self,
        len: usize,
        mut values: impl DoubleEndedIterator<Item = Term>,
    ) -> Result<Term, TermError> {
        if len == 0 {
            return Ok(Term::NIL);
        }
        let words = len.checked_mul(2).ok_or(TermError::SystemLimit)?;
        let run = self.words(words)?;
        let mut tail = Term::NIL;
        for index in 0..len {
            let value = values.next_back().ok_or(TermError::BadArg)?;
            let cell = run.wrapping_add(2 * index);
            store(cell, value.bits());
            store(cell.wrapping_add(1), tail.bits());
            tail = Term::from_ptr(cell, 1);
        }
        if values.next_back().is_some() {
            return Err(TermError::BadArg);
        }
        Ok(tail)
    }
    /// Build a list from a slice with one reservation of `2 * n` words.
    pub fn list_from_slice(&mut self, values: &[Term]) -> Result<Term, TermError> {
        if values.is_empty() {
            return Ok(Term::NIL);
        }
        let words = values.len().checked_mul(2).ok_or(TermError::SystemLimit)?;
        let run = self.words(words)?;
        let mut tail = Term::NIL;
        for (index, value) in values.iter().enumerate().rev() {
            let cell = run.wrapping_add(2 * index);
            store(cell, value.bits());
            store(cell.wrapping_add(1), tail.bits());
            tail = Term::from_ptr(cell, 1);
        }
        Ok(tail)
    }
    /// Build a list of the byte values of `bytes` with one reservation of `2 * n` words.
    // Port of erts/emulator/beam/utils.c (buf_to_intlist), OTP-29.1.1.
    pub fn bytes_to_list(&mut self, bytes: &[u8]) -> Result<Term, TermError> {
        if bytes.is_empty() {
            return Ok(Term::NIL);
        }
        let words = bytes.len().checked_mul(2).ok_or(TermError::SystemLimit)?;
        let run = self.words(words)?;
        let mut tail = Term::NIL;
        for (index, byte) in bytes.iter().enumerate().rev() {
            let cell = run.wrapping_add(2 * index);
            store(
                cell,
                Term::small(i64::from(*byte))
                    .ok_or(TermError::BadArg)?
                    .bits(),
            );
            store(cell.wrapping_add(1), tail.bits());
            tail = Term::from_ptr(cell, 1);
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
        store(p, (1 << 6) | FLOAT);
        store(p.wrapping_add(1), value.to_bits());
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
    /// Multiply two small integers using the temporary bignum used by `small_times`.
    ///
    /// Port of `small_times` in erts/emulator/beam/big.c and its stack-result copy in
    /// `erts_mixed_times`, erts/emulator/beam/erl_arith.c, OTP-29.1.1.
    pub fn small_times(&mut self, x: i64, y: i64) -> Result<Term, TermError> {
        if x == 0 || y == 0 {
            return Ok(Term::small(0).unwrap());
        }
        if x == 1 {
            return Term::small(y).ok_or(TermError::BadArg);
        }
        if y == 1 {
            return Term::small(x).ok_or(TermError::BadArg);
        }

        let negative = (x < 0) != (y < 0);
        let product = (x.unsigned_abs() as u128) * (y.unsigned_abs() as u128);
        let low = product as u64;
        let high = (product >> 64) as u64;
        let small_magnitude = if negative {
            MAX_SMALL as u64 + 1
        } else {
            MAX_SMALL as u64
        };
        if high == 0 && low <= small_magnitude {
            let value = if negative { -(low as i64) } else { low as i64 };
            return Ok(Term::small(value).unwrap());
        }

        let arity = if high == 0 { 1 } else { 2 };
        let mut temporary = [0_u64; 3];
        temporary[0] = ((arity as u64) << 6) | if negative { NEG_BIG } else { POS_BIG };
        temporary[1] = low;
        temporary[2] = high;

        let words = arity + 1;
        let p = self
            .heap
            .alloc_fragment_only(words)
            .ok_or(TermError::HeapFull)?;
        for (index, word) in temporary[..words].iter().copied().enumerate() {
            store(p.wrapping_add(index), word);
        }
        Ok(Term::from_ptr(p, 2))
    }

    /// Multiply boxed bignums and small integers directly into their result allocation.
    ///
    /// Port of `erts_mixed_times` in erts/emulator/beam/erl_arith.c and `big_times` in
    /// erts/emulator/beam/big.c, OTP-29.1.1.
    #[inline(always)]
    pub fn bignum_times(&mut self, a: Term, b: Term) -> Result<Term, TermError> {
        let mut operand_sizes = [0; 2];
        self.bignum_times_with_sizes(a, b, a.as_small(), b.as_small(), &mut operand_sizes)
    }

    /// Multiply and return the operand sizes already read by the tag dispatch.
    ///
    /// Port of `erts_mixed_times` and `big_times` in `erl_arith.c` and `big.c`, OTP-29.1.1.
    #[inline(always)]
    pub fn bignum_times_with_sizes(
        &mut self,
        a: Term,
        b: Term,
        a_small: Option<i64>,
        b_small: Option<i64>,
        operand_sizes: &mut [usize; 2],
    ) -> Result<Term, TermError> {
        *operand_sizes = [0; 2];
        match (a_small, b_small) {
            (Some(small), None) => b
                .with_bignum_parts_mut(|digits, negative| {
                    if small == 0 {
                        return Ok(Term::small(0).unwrap());
                    }
                    if small == 1 {
                        return Ok(b);
                    }
                    let digit_count = digits.len();
                    operand_sizes[0] = 1;
                    operand_sizes[1] = digit_count;
                    let temporary = small_to_big_words(small);
                    self.bignum_product(
                        &temporary[1..],
                        digits,
                        (small < 0) != negative,
                        digit_count + 3,
                    )
                })
                .ok_or(TermError::BadArg)?,
            (None, Some(small)) => a
                .with_bignum_parts_mut(|digits, negative| {
                    if small == 0 {
                        return Ok(Term::small(0).unwrap());
                    }
                    if small == 1 {
                        return Ok(a);
                    }
                    let digit_count = digits.len();
                    operand_sizes[0] = digit_count;
                    operand_sizes[1] = 1;
                    let temporary = small_to_big_words(small);
                    self.bignum_product(
                        digits,
                        &temporary[1..],
                        negative != (small < 0),
                        digit_count + 3,
                    )
                })
                .ok_or(TermError::BadArg)?,
            (None, None) => a
                .with_bignum_parts_mut(|x, x_negative| {
                    b.with_bignum_parts_mut(|y, y_negative| {
                        operand_sizes[0] = x.len();
                        operand_sizes[1] = y.len();
                        self.bignum_product(x, y, x_negative != y_negative, x.len() + y.len() + 1)
                    })
                    .ok_or(TermError::BadArg)?
                })
                .ok_or(TermError::BadArg)?,
            (Some(_), Some(_)) => Err(TermError::BadArg),
        }
    }

    fn bignum_product(
        &mut self,
        x: &[u64],
        y: &[u64],
        negative: bool,
        allocated_words: usize,
    ) -> Result<Term, TermError> {
        // Port of erl_arith.c:43-49 (`maybe_shrink`) and big.c:3827 (`big_times`), OTP-29.1.1.
        // The caller has already computed BIG_NEED_SIZE from the operand sizes.
        // Keep that exact reservation and trim only after big_norm reports the result arity.
        let p = self
            .heap
            .alloc_fragment_only(allocated_words)
            .ok_or(TermError::HeapFull)?;
        let r = p.wrapping_add(1);
        let result_digits = crate::bignum::times_into(x, y, r);

        if result_digits == 1 {
            let magnitude = load(r);
            let small_magnitude = if negative {
                MAX_SMALL as u64 + 1
            } else {
                MAX_SMALL as u64
            };
            if magnitude <= small_magnitude {
                self.heap.shrink_fragment_tail(p, allocated_words, 0);
                let value = if negative {
                    -(magnitude as i64)
                } else {
                    magnitude as i64
                };
                return Ok(Term::small(value).unwrap());
            }
        }

        if result_digits > 65_535 {
            self.heap.shrink_fragment_tail(p, allocated_words, 0);
            return Err(TermError::SystemLimit);
        }

        store(
            p,
            ((result_digits as u64) << 6) | if negative { NEG_BIG } else { POS_BIG },
        );
        let used_words = result_digits + 1;
        if used_words < allocated_words {
            self.heap
                .shrink_fragment_tail(p, allocated_words, used_words);
        }
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
        store(
            p,
            ((digits as u64) << 6)
                | if sign == Sign::Minus {
                    NEG_BIG
                } else {
                    POS_BIG
                },
        );
        for index in 0..digits {
            store(p.wrapping_add(index + 1), digit_at(index));
        }
    }
    /// Build a byte-aligned binary.
    // Port of erts/emulator/beam/erl_bits.c:2874-2878 (`erts_new_binary_from_data`), OTP-29.1.1.
    pub fn binary(&mut self, bytes: &[u8]) -> Result<Term, TermError> {
        let bit_len = bytes.len().checked_mul(8).ok_or(TermError::SystemLimit)?;
        if bytes.len() <= 64 {
            return self.heap_bitstring_with_data(bit_len, false, |destination| {
                destination.copy_from_slice(bytes);
            });
        }
        self.binary_from_fn(bytes.len(), |destination| {
            destination.copy_from_slice(bytes);
        })
    }

    /// Allocate a binary in its final heap or Binary storage before filling it.
    // Port of erts/emulator/beam/erl_bits.c:2841-2860 (erts_new_bitstring), OTP-29.1.1.
    pub fn binary_from_fn(
        &mut self,
        size: usize,
        fill: impl FnOnce(&mut [u8]),
    ) -> Result<Term, TermError> {
        self.binary_from_fn_with_len(size, |destination| {
            fill(destination);
            Ok(destination.len())
        })
    }

    /// Allocate a byte-aligned binary with capacity `size` and publish the callback's length.
    // Port of erts/emulator/beam/erl_bits.c:2881-2904 (`erts_shrink_binary_term`), OTP-29.1.1.
    pub fn binary_from_fn_with_len(
        &mut self,
        size: usize,
        fill: impl FnOnce(&mut [u8]) -> Result<usize, TermError>,
    ) -> Result<Term, TermError> {
        let bit_len = size.checked_mul(8).ok_or(TermError::SystemLimit)?;
        if size <= 64 {
            return self.heap_bitstring_with_data_len(bit_len, false, |destination| {
                fill(destination)?
                    .checked_mul(8)
                    .ok_or(TermError::SystemLimit)
            });
        }
        let mut binary = RefcBinary::new_zeroed(size)?;
        let written = fill(binary.bytes_mut_unique().ok_or(TermError::BadArg)?)?;
        if written > size {
            return Err(TermError::BadArg);
        }
        self.install_refc_binary(
            binary,
            written.checked_mul(8).ok_or(TermError::SystemLimit)?,
        )
    }
    /// Build a bitstring with high bits significant in its final byte.
    pub fn bitstring(&mut self, bytes: &[u8], bit_len: usize) -> Result<Term, TermError> {
        if bit_len > bytes.len().saturating_mul(8) {
            return Err(TermError::BadArg);
        }
        let count = bit_len.div_ceil(8);
        if count <= 64 {
            return self.heap_bitstring_from_parts(bytes, &[], bit_len);
        }
        // Port of erts/emulator/beam/external.c (`dec_term`, BINARY_EXT / BIT_BINARY_EXT),
        // OTP-29.1.1: allocate the final refc binary and copy the payload once.
        let mut binary = RefcBinary::new_zeroed(count)?;
        let data = binary.bytes_mut_unique().ok_or(TermError::BadArg)?;
        data.copy_from_slice(&bytes[..count]);
        if !bit_len.is_multiple_of(8)
            && let Some(last) = data.last_mut()
        {
            *last &= 0xff << (8 - bit_len % 8);
        }
        self.install_refc_binary(binary, bit_len)
    }

    /// Allocate the final bitstring and return its payload address for a native writer.
    ///
    /// The returned address remains valid while the term is rooted and the heap is not moved.
    // Port of erts/emulator/beam/erl_bits.c (`erts_bs_init_bits` allocation contract), OTP-29.1.1.
    pub fn bitstring_with_address(&mut self, bit_len: usize) -> Result<(Term, usize), TermError> {
        let count = bit_len.div_ceil(8);
        let mut address = 0;
        if count <= 64 {
            let term = self.heap_bitstring_with_data(bit_len, false, |destination| {
                address = destination.as_mut_ptr() as usize;
            })?;
            return Ok((term, address));
        }
        let binary = RefcBinary::new_zeroed(count)?;
        address = binary.as_ptr() as usize;
        let term = self.install_refc_binary(binary, bit_len)?;
        Ok((term, address))
    }

    /// A sub-binary of `len` bytes at `offset` of a refc binary the caller keeps, as the
    /// driver delivers a slice of its input buffer without copying it
    /// (`driver_deliver_term` with `ERL_DRV_BINARY`, io.c).
    pub fn refc_slice(
        &mut self,
        binary: &RefcBinary,
        offset: usize,
        len: usize,
    ) -> Result<Term, TermError> {
        if offset.checked_add(len).is_none_or(|end| end > binary.len()) {
            return Err(TermError::BadArg);
        }
        let owner = binary.share().ok_or(TermError::SystemLimit)?;
        self.install_refc_owner(
            owner,
            binary.as_ptr() as usize & 3,
            (binary.len() / 8) as u64,
            offset * 8,
            len * 8,
        )
    }

    /// Wrap a filled refc binary in its heap term: the `erts_build_proc_bin` step after
    /// `erts_bin_nrml_alloc` and the payload writes.
    pub fn refc_binary(&mut self, binary: RefcBinary, bit_len: usize) -> Result<Term, TermError> {
        if bit_len > binary.len().saturating_mul(8) {
            return Err(TermError::BadArg);
        }
        self.install_refc_binary(binary, bit_len)
    }

    fn install_refc_binary(
        &mut self,
        binary: RefcBinary,
        bit_len: usize,
    ) -> Result<Term, TermError> {
        let adjustment = binary.as_ptr() as usize & 3;
        let size_words = (binary.len() / 8) as u64;
        self.install_refc_owner(binary.into_reference(), adjustment, size_words, 0, bit_len)
    }

    fn install_refc_owner(
        &mut self,
        binary_owner: arinsal_alloc::raw::OwnedBinaryRef,
        adjustment: usize,
        size_words: u64,
        start_bit: usize,
        bit_len: usize,
    ) -> Result<Term, TermError> {
        let binary_header = binary_owner.header_ptr();
        let ref_ptr = self.words(8)?;
        // SAFETY: the same allocation reserves three BinRef and five SubBits words.
        let sub_ptr = unsafe { ref_ptr.add(3) };
        // SAFETY: both word ranges are reserved; the BinRef token owns the Binary.
        unsafe {
            *ref_ptr = (2 << 6) | BIN_REF;
            *ref_ptr.add(1) = binary_header as u64;
            *sub_ptr = (4 << 6) | SUB_BITS;
            *sub_ptr.add(1) = binary_header.wrapping_add(4) as u64 & !3;
            *sub_ptr.add(2) = (adjustment * 8 + start_bit) as u64;
            *sub_ptr.add(3) = (adjustment * 8 + start_bit + bit_len) as u64;
            *sub_ptr.add(4) = Term::from_ptr(ref_ptr, 2).bits();
        }
        self.heap
            .link_bin_ref(ref_ptr, false, size_words, Some(binary_owner))?;
        Ok(Term::from_ptr(sub_ptr, 2))
    }

    /// Build an on-heap bitstring by copying two byte ranges directly into its payload.
    ///
    /// The 64-byte bound matches `ERL_ONHEAP_BINARY_LIMIT`; larger bitstrings use the
    /// reference-counted path. Port of erts/emulator/beam/jit/arm/instr_bs.cpp:1882 and
    /// erts/emulator/beam/jit/beam_jit_common.cpp:816-849, OTP-29.1.1.
    pub fn heap_bitstring_from_parts(
        &mut self,
        prefix: &[u8],
        suffix: &[u8],
        bit_len: usize,
    ) -> Result<Term, TermError> {
        let available = prefix.len().saturating_add(suffix.len());
        if bit_len > available.saturating_mul(8) {
            return Err(TermError::BadArg);
        }
        let count = bit_len.div_ceil(8);
        if count > 64 {
            return Err(TermError::SystemLimit);
        }
        let prefix_count = prefix.len().min(count);
        let suffix_count = count - prefix_count;
        self.heap_bitstring_with_data(bit_len, false, |destination| {
            destination[..prefix_count].copy_from_slice(&prefix[..prefix_count]);
            destination[prefix_count..count].copy_from_slice(&suffix[..suffix_count]);
        })
    }

    /// Copy a bit range directly into an on-heap bitstring.
    ///
    /// Port of erts/emulator/beam/erl_bits.c:2641-2673 (`erts_build_sub_bitstring`) and
    /// erts/emulator/beam/erl_bits.h:541 (`copy_binary_to_buffer`), OTP-29.1.1.
    pub fn heap_bitstring_from_range(
        &mut self,
        source: &[u8],
        source_offset: usize,
        bit_len: usize,
    ) -> Result<Term, TermError> {
        self.heap_bitstring_from_range_with_fragment(source, source_offset, bit_len, false)
    }

    fn heap_bitstring_from_range_with_fragment(
        &mut self,
        source: &[u8],
        source_offset: usize,
        bit_len: usize,
        fragment_only: bool,
    ) -> Result<Term, TermError> {
        if source_offset
            .checked_add(bit_len)
            .is_none_or(|end| end > source.len().saturating_mul(8))
        {
            return Err(TermError::BadArg);
        }
        if bit_len.div_ceil(8) > 64 {
            return Err(TermError::SystemLimit);
        }
        self.heap_bitstring_with_data(bit_len, fragment_only, |destination| {
            if !source_offset.is_multiple_of(8) || !bit_len.is_multiple_of(8) {
                destination.fill(0);
            }
            crate::copy::copy_binary_to_buffer(destination, source, source_offset, bit_len);
        })
    }

    /// Build a BIF sub-bitstring, copying results within the on-heap limit.
    ///
    /// Port of erts/emulator/beam/erl_bits.c:2620-2654
    /// (`erts_build_sub_bitstring`), OTP-29.1.1.
    pub fn sub_binary_bif(
        &mut self,
        original: Term,
        start: usize,
        bit_len: usize,
    ) -> Result<Term, TermError> {
        self.sub_binary_inner(original, start, bit_len, true, true)
    }

    fn heap_bitstring_with_data(
        &mut self,
        bit_len: usize,
        fragment_only: bool,
        fill: impl FnOnce(&mut [u8]),
    ) -> Result<Term, TermError> {
        self.heap_bitstring_with_data_len(bit_len, fragment_only, |destination| {
            fill(destination);
            Ok(bit_len)
        })
    }

    fn heap_bitstring_with_data_len(
        &mut self,
        bit_len: usize,
        fragment_only: bool,
        fill: impl FnOnce(&mut [u8]) -> Result<usize, TermError>,
    ) -> Result<Term, TermError> {
        let count = bit_len.div_ceil(8);
        let words = 2 + count.div_ceil(8);
        let p = if fragment_only {
            self.heap.alloc_fragment_only(words)
        } else {
            self.heap.alloc(words)
        }
        .ok_or(TermError::HeapFull)?;
        // SAFETY: the allocation covers the complete heap-bitstring header and rounded payload.
        let written_bits = unsafe {
            *p = (((words - 1) as u64) << 6) | HEAP_BITS;
            *p.add(1) = bit_len as u64;
            let destination = std::slice::from_raw_parts_mut(p.add(2).cast::<u8>(), count);
            let written_bits = fill(destination)?;
            if written_bits > bit_len {
                return Err(TermError::BadArg);
            }
            *p.add(1) = written_bits as u64;
            let written_bytes = written_bits.div_ceil(8);
            if !written_bits.is_multiple_of(8) && written_bytes > 0 {
                destination[written_bytes - 1] &= 0xff << (8 - (written_bits % 8));
            }
            written_bits
        };
        let _ = written_bits;
        Ok(Term::from_ptr(p, 2))
    }
    /// Create a slice of a bitstring, retaining the original owner.
    pub fn sub_binary(
        &mut self,
        original: Term,
        start: usize,
        bit_len: usize,
    ) -> Result<Term, TermError> {
        self.sub_binary_inner(original, start, bit_len, false, false)
    }

    fn sub_binary_inner(
        &mut self,
        original: Term,
        start: usize,
        bit_len: usize,
        copy_bif_small: bool,
        fragment_only: bool,
    ) -> Result<Term, TermError> {
        if !copy_bif_small {
            crate::bits::writable_finalize(original);
        }
        // SAFETY: The original binary and heap remain live during construction.
        let view = unsafe { original.binary_ref() }.ok_or(TermError::BadArg)?;
        if copy_bif_small && !view.bit_len().is_multiple_of(8) {
            return Err(TermError::BadArg);
        }
        if start
            .checked_add(bit_len)
            .is_none_or(|end| end > view.bit_len())
        {
            return Err(TermError::BadArg);
        }
        if copy_bif_small && bit_len.div_ceil(8) <= 64 {
            let source_offset = view
                .start_bit()
                .checked_add(start)
                .ok_or(TermError::BadArg)?;
            return self.heap_bitstring_with_data(bit_len, fragment_only, |destination| {
                if !source_offset.is_multiple_of(8) || !bit_len.is_multiple_of(8) {
                    destination.fill(0);
                }
                crate::copy::copy_binary_to_buffer(
                    destination,
                    view.bytes(),
                    source_offset,
                    bit_len,
                );
            });
        }
        let mut owner = original;
        while owner.header().is_some_and(|h| h & 63 == SUB_BITS) {
            // SAFETY: a live SubBits has its original term in word four.
            owner = Term(unsafe { *owner.raw_ptr().add(4) });
        }
        let small_heap_source = owner.header().is_none_or(|h| h & 63 != BIN_REF);
        if small_heap_source && bit_len.div_ceil(8) <= 64 {
            let source_offset = view
                .start_bit()
                .checked_add(start)
                .ok_or(TermError::BadArg)?;
            return self.heap_bitstring_from_range_with_fragment(
                view.bytes(),
                source_offset,
                bit_len,
                fragment_only,
            );
        }
        if owner.header().is_none_or(|h| h & 63 != BIN_REF) {
            return Err(TermError::BadArg);
        }
        if !self.heap.supports_writable_binary() && crate::bits::binary_owner_is_writable(owner) {
            return Err(TermError::Unsupported("writable binary heap owner"));
        }
        let words = 5;
        let p = if fragment_only {
            self.heap.alloc_fragment_only(words)
        } else {
            self.heap.alloc(words)
        }
        .ok_or(TermError::HeapFull)?;
        let absolute = view.start_bit() + start;
        let adjustment = owner_adjustment(owner);
        // SAFETY: `words` reserves one five-word SUB_BITS; its original term is the
        // existing BinRef, which the source heap keeps live.
        unsafe {
            // Port of erts/emulator/beam/erl_bits.c (erts_build_sub_bitstring) and
            // erts_bs_get_binary_2, OTP-29.1.1: a sub-bitstring points at the existing
            // BinRef and neither adds a ProcBin to the off-heap list nor charges the
            // binary to the virtual heap again.
            let volatile = if crate::bits::binary_owner_is_writable(owner) {
                crate::bits::SUB_BITS_VOLATILE
            } else {
                0
            };
            *p = (4 << 6) | SUB_BITS;
            *p.add(1) = (binary_data(owner.raw_ptr()) as u64 & !3) | volatile;
            *p.add(2) = (absolute + adjustment * 8) as u64;
            *p.add(3) = (absolute + bit_len + adjustment * 8) as u64;
            *p.add(4) = owner.bits();
            Ok(Term::from_ptr(p, 2))
        }
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
    /// Construct the map of a decoded `MAP_EXT`: the pairs come in stream order, are sorted by
    /// key, and a repeated key is an error.
    // Port of erts/emulator/beam/external.c:5047-5060, 5428-5445 (dec_term maps: the keys are
    // sorted and a duplicate fails the decode), OTP-29.1.1.
    pub fn map_from_decoded_pairs(
        &mut self,
        pairs: &mut [(Term, Term)],
    ) -> Result<Term, TermError> {
        if pairs.is_empty() {
            return self.flatmap_from_pairs(&[]);
        }
        pairs.sort_by(|a, b| flat_key_cmp(a.0, b.0));
        if pairs.windows(2).any(|pair| exact_eq(pair[0].0, pair[1].0)) {
            return Err(TermError::BadArg);
        }
        if pairs.len() > 32 {
            return crate::hamt::build_hamt_from_unique(pairs, self.heap);
        }
        let keys: Vec<Term> = pairs.iter().map(|pair| pair.0).collect();
        let values: Vec<Term> = pairs.iter().map(|pair| pair.1).collect();
        self.flatmap_from_sorted_arrays(&keys, &values)
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
            *p = MAP_HEADER_FLATMAP;
            *p.add(1) = values.len() as u64;
            *p.add(2) = keys.bits();
            for (i, value) in values.iter().enumerate() {
                *p.add(3 + i) = value.bits();
            }
        }
        Ok(Term::from_ptr(p, 2))
    }
    /// Construct a flatmap from evaluated keys, sorting the owned key tuple in place.
    ///
    /// `keys` must be the fresh tuple produced while evaluating the map expression; OTP sorts
    /// that tuple and the map values together in its `matchMkFlatMap` instruction.
    // Port of erts/emulator/beam/erl_map.c:3218-3252 (erts_usort_flatmap), OTP-29.1.1.
    pub fn flatmap_with_key_tuple_usort(
        &mut self,
        keys: Term,
        values: &[Term],
    ) -> Result<Term, TermError> {
        let map = self.flatmap_with_key_tuple(keys, values)?;
        crate::raw::usort_flatmap_in_place(map);
        Ok(map)
    }
    /// Build a decoded flatmap from already sorted, distinct key and value arrays.
    ///
    /// The key tuple and map share one reservation, as `erts_map_from_ks_and_vs` does.
    pub fn flatmap_from_sorted_arrays(
        &mut self,
        keys: &[Term],
        values: &[Term],
    ) -> Result<Term, TermError> {
        if keys.len() != values.len() || keys.is_empty() || keys.len() > 32 {
            return Err(TermError::BadArg);
        }
        let size = keys.len();
        let words = size
            .checked_mul(2)
            .and_then(|words| words.checked_add(4))
            .ok_or(TermError::SystemLimit)?;
        let mut block = self.reserve_boxed_words(words, 0)?;
        block.write_header((size as u64) << 6)?;
        for key in keys {
            block.write_term(*key)?;
        }
        let key_tuple = block.term_at(0)?;
        block.write_header(MAP_HEADER_FLATMAP)?;
        block.write_header(size as u64)?;
        block.write_term(key_tuple)?;
        for value in values {
            block.write_term(*value)?;
        }
        block.finish_at(size + 1)
    }

    /// Build a flatmap from key and value arrays, sorting the reserved flatmap in place.
    ///
    /// Port of erts/emulator/beam/erl_map.c:673 (`erts_map_from_ks_and_vs`) and :3187
    /// (`erts_validate_and_sort_flatmap`), OTP-29.1.1.
    pub fn flatmap_from_arrays(
        &mut self,
        keys: &[Term],
        values: &[Term],
    ) -> Result<Term, TermError> {
        if keys.len() != values.len() || keys.is_empty() || keys.len() > 32 {
            return Err(TermError::BadArg);
        }
        let size = keys.len();
        let words = size
            .checked_mul(2)
            .and_then(|words| words.checked_add(4))
            .ok_or(TermError::SystemLimit)?;
        let mut block = self.reserve_boxed_words(words, 0)?;
        block.write_header((size as u64) << 6)?;
        for key in keys {
            block.write_term(*key)?;
        }
        let key_tuple = block.term_at(0)?;
        block.write_header(MAP_HEADER_FLATMAP)?;
        block.write_header(size as u64)?;
        block.write_term(key_tuple)?;
        for value in values {
            block.write_term(*value)?;
        }

        for ix in 1..size {
            let mut jx = ix;
            while jx > 0 {
                let key = block.term_at(1 + jx)?;
                let prior = block.term_at(jx)?;
                match flat_key_cmp(key, prior) {
                    Ordering::Equal => return Err(TermError::BadArg),
                    Ordering::Greater => break,
                    Ordering::Less => {
                        block.replace_term_at(1 + jx, prior)?;
                        block.replace_term_at(jx, key)?;
                        let value_offset = size + 4 + jx;
                        let prior_value_offset = value_offset - 1;
                        let value = block.term_at(value_offset)?;
                        let prior_value = block.term_at(prior_value_offset)?;
                        block.replace_term_at(value_offset, prior_value)?;
                        block.replace_term_at(prior_value_offset, value)?;
                        jx -= 1;
                    }
                }
            }
        }
        block.finish_at(size + 1)
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
    /// The permanent fun table keeps the entry alive after this builder returns.
    pub fn local_fun(&mut self, entry: &Arc<FunEntry>, free: &[Term]) -> Result<Term, TermError> {
        crate::fun::make_fun_entry_permanent(entry);
        let header =
            crate::fun::local_header(entry.arity, free.len()).ok_or(TermError::SystemLimit)?;
        let p = self.words(2 + free.len())?;
        // SAFETY: header, entry pointer, and environment words were reserved.
        unsafe {
            *p = header;
            *p.add(1) = Arc::as_ptr(entry) as u64;
            for (i, value) in free.iter().enumerate() {
                *p.add(2 + i) = value.bits();
            }
        }
        Ok(Term::from_ptr(p, 2))
    }
    /// Construct a decoded local fun, resolving its identity through the node fun table.
    // Port of erts/emulator/beam/external.c:5162-5168, OTP-29.1.1.
    pub fn local_fun_stub(
        &mut self,
        entry: Arc<FunEntry>,
        free: &[Term],
    ) -> Result<Term, TermError> {
        let entry = crate::fun::fun_entry_get_or_make_stub(entry);
        self.local_fun(&entry, free)
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
        crate::fun::export_lambda(entry)
    }

    /// Build the heap object referenced by a global `Export.lambda` literal.
    pub(crate) fn export_fun_in_heap(&mut self, entry: &ExportEntry) -> Result<Term, TermError> {
        let p = self.words(2)?;
        store(p, crate::fun::export_header(entry.arity));
        store(p.wrapping_add(1), std::ptr::from_ref(entry) as u64);
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
        self.heap.link_node(p, node);
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
        self.heap.link_node(p, node);
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
        self.heap.link_node(p, node);
        Ok(Term::from_ptr(p, 2))
    }
    /// Construct an ordinary local reference (three 32-bit components).
    #[inline]
    pub fn local_ref(&mut self, ids: [u32; 3]) -> Result<Term, TermError> {
        Term::local_ref(self.heap, ids)
    }

    /// Construct a local PID reference with its creator PID term.
    pub fn local_pid_ref(&mut self, ids: [u32; 3], pid: Term) -> Result<Term, TermError> {
        Term::local_pid_ref(self.heap, ids, pid)
    }

    /// Construct a local PID reference from its serialized creator PID words.
    pub fn local_pid_ref_from_words(
        &mut self,
        ids: [u32; 3],
        pid_low: u32,
        pid_high: u32,
    ) -> Result<Term, TermError> {
        Term::local_pid_ref_from_words(self.heap, ids, pid_low, pid_high)
    }
}

/// A boxed heap object filled in order after one contiguous allocation.
pub struct HeapBlockBuilder {
    start: usize,
    words: usize,
    written: usize,
    slot_base: HeapTermSlot,
}

impl HeapBlockBuilder {
    /// Append consecutive header and term words after one reservation check.
    #[inline(always)]
    pub(crate) fn write_words(&mut self, values: &[u64]) -> Result<(), TermError> {
        let end = self
            .written
            .checked_add(values.len())
            .filter(|end| *end <= self.words)
            .ok_or(TermError::BadArg)?;
        for (offset, value) in values.iter().copied().enumerate() {
            crate::raw::store(
                self.start + (self.written + offset) * std::mem::size_of::<u64>(),
                value,
            );
        }
        self.written = end;
        Ok(())
    }

    /// Append a non-term header word to the reserved object.
    #[inline(always)]
    pub fn write_header(&mut self, value: u64) -> Result<(), TermError> {
        self.write_word(value)
    }

    /// Append an Erlang term to the reserved object.
    #[inline(always)]
    pub fn write_term(&mut self, value: Term) -> Result<(), TermError> {
        self.write_word(value.bits())
    }

    /// Append a previously saved term word, such as one popped from a HAMT build stack.
    #[inline(always)]
    pub fn write_term_bits(&mut self, value: u64) -> Result<(), TermError> {
        self.write_word(value)
    }

    /// Append reserved words from last to first, as the HAMT builder's stack pop loop does.
    #[inline(always)]
    pub fn write_term_bits_reversed(&mut self, values: &[u64]) -> Result<(), TermError> {
        let end = self
            .written
            .checked_add(values.len())
            .filter(|end| *end <= self.words)
            .ok_or(TermError::BadArg)?;
        for (offset, value) in values.iter().rev().enumerate() {
            crate::raw::store(
                self.start + (self.written + offset) * std::mem::size_of::<u64>(),
                *value,
            );
        }
        self.written = end;
        Ok(())
    }

    /// A boxed term at a previously initialized word offset in the reservation.
    pub fn term_at(&self, word_offset: usize) -> Result<Term, TermError> {
        if word_offset >= self.written {
            return Err(TermError::BadArg);
        }
        Ok(Term::from_ptr(
            (self.start as *mut u64).wrapping_add(word_offset),
            2,
        ))
    }

    /// Replace a term in an initialized slot of the reservation.
    pub fn replace_term_at(&mut self, word_offset: usize, term: Term) -> Result<(), TermError> {
        if word_offset >= self.written {
            return Err(TermError::BadArg);
        }
        crate::raw::store(
            self.start + word_offset * std::mem::size_of::<u64>(),
            term.bits(),
        );
        Ok(())
    }

    /// Identify a term slot in the reserved object before it is initialized.
    pub fn term_slot(&self, word_offset: usize) -> Result<HeapTermSlot, TermError> {
        if word_offset >= self.words {
            return Err(TermError::BadArg);
        }
        if self.slot_base.indexed {
            Ok(HeapTermSlot::index(
                self.slot_base
                    .value
                    .checked_add(word_offset)
                    .ok_or(TermError::BadArg)?,
            ))
        } else {
            Ok(HeapTermSlot::address(
                self.start
                    .checked_add(word_offset * std::mem::size_of::<u64>())
                    .ok_or(TermError::BadArg)?,
            ))
        }
    }

    /// Initialize consecutive tuple slots as a reverse `dec_term` work chain.
    // Port of the `tuple_loop` slot chain in erts/emulator/beam/external.c (dec_term), OTP-29.1.1.
    #[inline(always)]
    pub fn write_next_chain(
        &self,
        first_word_offset: usize,
        count: usize,
        continuation: Option<HeapTermSlot>,
    ) -> Result<HeapTermSlot, TermError> {
        let end = first_word_offset
            .checked_add(count)
            .filter(|end| first_word_offset > 0 && *end <= self.words)
            .ok_or(TermError::BadArg)?;
        if count == 0 || !self.slot_base.indexed {
            return Err(TermError::BadArg);
        }
        let mut next = match continuation {
            Some(slot) if slot.indexed => slot.value.checked_add(1).ok_or(TermError::BadArg)?,
            Some(_) => return Err(TermError::BadArg),
            None => 0,
        };
        let first = self
            .slot_base
            .value
            .checked_add(first_word_offset)
            .ok_or(TermError::BadArg)?;
        for offset in (first_word_offset..end).rev() {
            let index = self
                .slot_base
                .value
                .checked_add(offset)
                .ok_or(TermError::BadArg)?;
            store((self.start as *mut u64).wrapping_add(offset), next as u64);
            next = index.checked_add(1).ok_or(TermError::BadArg)?;
        }
        Ok(HeapTermSlot::index(first))
    }

    /// Initialize the final cell of a decoded external list as the chain's tail.
    // Port of the final-cell setup in erts/emulator/beam/external.c (dec_term, LIST_EXT), OTP-29.1.1.
    #[inline(always)]
    pub fn write_list_tail(
        &self,
        continuation: Option<HeapTermSlot>,
    ) -> Result<HeapTermSlot, TermError> {
        if self.words < 2 || !self.words.is_multiple_of(2) || !self.slot_base.indexed {
            return Err(TermError::BadArg);
        }
        let car_offset = self.words - 2;
        let cdr_offset = self.words - 1;
        let car = self
            .slot_base
            .value
            .checked_add(car_offset)
            .ok_or(TermError::BadArg)?;
        let cdr = self
            .slot_base
            .value
            .checked_add(cdr_offset)
            .ok_or(TermError::BadArg)?;
        let continuation = match continuation {
            Some(slot) if slot.indexed => slot.value.checked_add(1).ok_or(TermError::BadArg)?,
            Some(_) => return Err(TermError::BadArg),
            None => 0,
        };
        store(
            (self.start as *mut u64).wrapping_add(cdr_offset),
            continuation as u64,
        );
        store(
            (self.start as *mut u64).wrapping_add(car_offset),
            cdr.checked_add(1).ok_or(TermError::BadArg)? as u64,
        );
        Ok(HeapTermSlot::index(car))
    }

    /// Link decoded list cells from the end toward the first unfilled element slot.
    // Port of the LIST_EXT loop in erts/emulator/beam/external.c (dec_term), OTP-29.1.1.
    #[inline(always)]
    pub fn write_list_chain(
        &self,
        first_cell: usize,
        count: usize,
        mut chain: HeapTermSlot,
    ) -> Result<HeapTermSlot, TermError> {
        let cells = self.words / 2;
        let end = first_cell
            .checked_add(count)
            .filter(|end| count > 0 && *end < cells && self.words.is_multiple_of(2))
            .ok_or(TermError::BadArg)?;
        if !self.slot_base.indexed || !chain.indexed {
            return Err(TermError::BadArg);
        }
        for cell in (first_cell..end).rev() {
            let car_offset = cell.checked_mul(2).ok_or(TermError::BadArg)?;
            let cdr_offset = car_offset.checked_add(1).ok_or(TermError::BadArg)?;
            let car = self
                .slot_base
                .value
                .checked_add(car_offset)
                .ok_or(TermError::BadArg)?;
            let next_cell =
                Term::from_ptr((self.start as *mut u64).wrapping_add(cdr_offset + 1), 1);
            store(
                (self.start as *mut u64).wrapping_add(cdr_offset),
                next_cell.bits(),
            );
            store(
                (self.start as *mut u64).wrapping_add(car_offset),
                chain.value.checked_add(1).ok_or(TermError::BadArg)? as u64,
            );
            chain = HeapTermSlot::index(car);
        }
        Ok(chain)
    }

    /// Return a list term pointing at two words in the reserved object.
    pub fn list_at(&self, word_offset: usize) -> Result<Term, TermError> {
        if word_offset >= self.words.saturating_sub(1) {
            return Err(TermError::BadArg);
        }
        Ok(Term::from_ptr(
            (self.start as *mut u64).wrapping_add(word_offset),
            1,
        ))
    }

    #[inline(always)]
    fn write_word(&mut self, value: u64) -> Result<(), TermError> {
        if self.written == self.words {
            return Err(TermError::BadArg);
        }
        let slot = (self.start as *mut u64).wrapping_add(self.written);
        store(slot, value);
        self.written += 1;
        Ok(())
    }

    /// Finish after every reserved word has been initialized.
    #[inline(always)]
    pub fn finish(self) -> Result<Term, TermError> {
        self.finish_at(0)
    }

    /// Finish and return a boxed term whose header starts at `word_offset`.
    pub fn finish_at(self, word_offset: usize) -> Result<Term, TermError> {
        if self.written != self.words {
            return Err(TermError::BadArg);
        }
        if word_offset >= self.words {
            return Err(TermError::BadArg);
        }
        Ok(Term::from_ptr(
            (self.start as *mut u64).wrapping_add(word_offset),
            2,
        ))
    }
}

/// A contiguous list reservation returned by [`TermBuilder::reserve_cons_list`].
pub struct ConsListBuilder {
    start: usize,
    len: usize,
    written: usize,
    head: Term,
    first_cdr: Option<usize>,
    last_cdr: Option<usize>,
}

impl ConsListBuilder {
    /// Build the reservation by prepending an exact reverse-order sequence to `tail`.
    /// The size check is outside the loop so each cell follows the HAlloc/CONS sequence directly.
    /// Port of `while(n--) { res = CONS(hp, value, res); hp += 2; }` in
    /// `erts/emulator/beam/erl_map.c:1222-1225` and :2277-2280, OTP-29.1.1.
    #[inline]
    pub fn prepend_exact_with_tail(
        self,
        mut values: impl Iterator<Item = Term>,
        tail: Term,
    ) -> Result<Term, TermError> {
        if self.written != 0 {
            return Err(TermError::BadArg);
        }
        let mut head = tail;
        let mut cell = self.start as *mut u64;
        let mut valid = true;
        for _ in 0..self.len {
            let value = values.next().unwrap_or_else(|| {
                valid = false;
                Term::NIL
            });
            store(cell, value.bits());
            store(cell.wrapping_add(1), head.bits());
            head = Term::from_ptr(cell, 1);
            cell = cell.wrapping_add(2);
        }
        valid &= values.next().is_none();
        if !valid {
            return Err(TermError::BadArg);
        }
        Ok(head)
    }

    /// Build an integer character list directly from its ASCII byte buffer.
    ///
    /// Port of `buf_to_intlist` in erts/emulator/beam/utils.c, OTP-29.1.1.
    #[inline(always)]
    pub fn prepend_bytes_with_tail(self, bytes: &[u8], tail: Term) -> Result<Term, TermError> {
        if self.written != 0 || bytes.len() != self.len {
            return Err(TermError::BadArg);
        }
        let mut head = tail;
        let mut cell = self.start as *mut u64;
        for &byte in bytes.iter().rev() {
            let value = Term::small(i64::from(byte)).ok_or(TermError::BadArg)?;
            store(cell, value.bits());
            store(cell.wrapping_add(1), head.bits());
            head = Term::from_ptr(cell, 1);
            cell = cell.wrapping_add(2);
        }
        Ok(head)
    }

    /// Build a list directly from a flatmap's stored tagged-word array.
    ///
    /// Port of the indexed `while(n--) { CONS(hp, ks[n], res); hp += 2; }`
    /// loops in erts/emulator/beam/erl_map.c:1222-1225 and :2277-2280,
    /// OTP-29.1.1.
    #[inline]
    pub fn prepend_exact_words_with_tail(
        self,
        values: &[u64],
        tail: Term,
    ) -> Result<Term, TermError> {
        if self.written != 0 || values.len() != self.len {
            return Err(TermError::BadArg);
        }
        let mut head = tail;
        let mut cell = self.start as *mut u64;
        for &value in values.iter().rev() {
            store(cell, value);
            store(cell.wrapping_add(1), head.bits());
            head = Term::from_ptr(cell, 1);
            cell = cell.wrapping_add(2);
        }
        Ok(head)
    }

    /// Build a tuple's list from element pairs, in the same order as `tuple_to_list_1`.
    ///
    /// OTP's optimized `while (n--)` copy handles two tuple elements per loop branch.
    // Port of erts/emulator/beam/bif.c:3762-3777 (tuple_to_list_1), OTP-29.1.1.
    #[inline(always)]
    pub fn prepend_tuple_words_with_tail(
        self,
        values: &[u64],
        tail: Term,
    ) -> Result<Term, TermError> {
        if self.written != 0 || values.len() != self.len {
            return Err(TermError::BadArg);
        }
        let mut head = tail;
        let mut cell = self.start as *mut u64;
        let (pairs, remainder) = values.as_chunks::<2>();
        if let Some(&value) = remainder.first() {
            store(cell, value);
            store(cell.wrapping_add(1), head.bits());
            head = Term((cell as u64).wrapping_add(1));
            cell = cell.wrapping_add(2);
        }
        for pair in pairs.iter().rev() {
            store(cell, pair[1]);
            store(cell.wrapping_add(1), head.bits());
            head = Term((cell as u64).wrapping_add(1));
            cell = cell.wrapping_add(2);

            store(cell, pair[0]);
            store(cell.wrapping_add(1), head.bits());
            head = Term((cell as u64).wrapping_add(1));
            cell = cell.wrapping_add(2);
        }
        Ok(head)
    }

    /// Fill the next reserved cons cell as an independent pair and return its term.
    /// Port of `CONS(hp, key, value)` in `erts/emulator/beam/erl_map.c:521`, OTP-29.1.1.
    #[inline(always)]
    pub fn cons_cell(&mut self, head: Term, tail: Term) -> Result<Term, TermError> {
        if self.written == self.len {
            return Err(TermError::BadArg);
        }
        let cell = (self.start as *mut u64).wrapping_add(2 * self.written);
        store(cell, head.bits());
        store(cell.wrapping_add(1), tail.bits());
        self.written += 1;
        Ok(Term::from_ptr(cell, 1))
    }

    /// Fill a bounded run of independent cons cells and report each leaf term.
    ///
    /// The output range is checked once before the loop, then the pointer advances like
    /// `hp += 2` in the bulk HAMT constructors. This keeps the per-entry loop free of a
    /// repeated destination-capacity check while remaining bounded by the reservation.
    /// Port of leaf construction in erts/emulator/beam/erl_map.c:513-531 and :732-739,
    /// OTP-29.1.1.
    #[inline(always)]
    pub fn fill_cons_cells_with(
        &mut self,
        count: usize,
        mut pairs: impl Iterator<Item = (Term, Term)>,
        mut on_cell: impl FnMut(usize, Term, Term, Term),
    ) -> Result<(), TermError> {
        let end = self
            .written
            .checked_add(count)
            .ok_or(TermError::SystemLimit)?;
        if end > self.len {
            return Err(TermError::BadArg);
        }
        let mut cell = (self.start as *mut u64).wrapping_add(2 * self.written);
        for index in self.written..end {
            let (head, tail) = pairs.next().ok_or(TermError::BadArg)?;
            store(cell, head.bits());
            store(cell.wrapping_add(1), tail.bits());
            on_cell(index, head, tail, Term::from_ptr(cell, 1));
            cell = cell.wrapping_add(2);
            self.written = index + 1;
        }
        Ok(())
    }

    /// Allocate the next cell and link it to the list built so far.
    ///
    /// Push values in reverse output order to match `res = CONS(hp, value, res); hp += 2`.
    /// Port of `CONS(hp, key, res)` in `erts/emulator/beam/erl_map.c:1225` and :2280.
    #[inline(always)]
    pub fn prepend(&mut self, value: Term) -> Result<(), TermError> {
        if self.written == self.len {
            return Err(TermError::BadArg);
        }
        let index = self.written;
        let cell = (self.start as *mut u64).wrapping_add(2 * index);
        store(cell, value.bits());
        store(cell.wrapping_add(1), self.head.bits());
        if index == 0 {
            self.first_cdr = Some(cell.wrapping_add(1) as usize);
        }
        self.head = Term::from_ptr(cell, 1);
        self.written += 1;
        Ok(())
    }

    /// Append one decoded list head in input order, linking it after the previous cell.
    /// Port of the forward `dec_term` LIST_EXT cell writes in external.c, OTP-29.1.1.
    #[inline(always)]
    pub fn append(&mut self, value: Term) -> Result<(), TermError> {
        if self.written == self.len {
            return Err(TermError::BadArg);
        }
        let cell = (self.start as *mut u64).wrapping_add(2 * self.written);
        store(cell, value.bits());
        store(cell.wrapping_add(1), Term::NIL.bits());
        let term = Term::from_ptr(cell, 1);
        if let Some(last_cdr) = self.last_cdr {
            store(last_cdr as *mut u64, term.bits());
        } else {
            self.head = term;
            self.first_cdr = Some(cell.wrapping_add(1) as usize);
        }
        self.last_cdr = Some(cell.wrapping_add(1) as usize);
        self.written += 1;
        Ok(())
    }

    /// Prepend a bounded run using the caller's exact count, checking capacity once per chunk.
    ///
    /// This keeps a resumable map projection's inner loop to the `CONS` stores and pointer
    /// advance used by `hashmap_keys`/`hashmap_values` in erl_map.c:2827-2879.
    #[inline]
    pub fn prepend_chunk(
        &mut self,
        count: usize,
        mut values: impl Iterator<Item = Term>,
    ) -> Result<(), TermError> {
        let end = self
            .written
            .checked_add(count)
            .ok_or(TermError::SystemLimit)?;
        if end > self.len {
            return Err(TermError::BadArg);
        }
        if count == 0 {
            return Ok(());
        }

        let mut cell = (self.start as *mut u64).wrapping_add(2 * self.written);
        if self.written == 0 {
            self.first_cdr = Some(cell.wrapping_add(1) as usize);
        }
        let mut head = self.head;
        for _ in 0..count {
            let value = values.next().ok_or(TermError::BadArg)?;
            store(cell, value.bits());
            store(cell.wrapping_add(1), head.bits());
            head = Term::from_ptr(cell, 1);
            cell = cell.wrapping_add(2);
        }
        self.head = head;
        self.written = end;
        Ok(())
    }

    /// Prepend bytes from one reserved binary range using OTP's backward `CONS` loop.
    ///
    /// Port of `erts_bin_bytes_to_list` in erts/emulator/beam/binary.c, OTP-29.1.1.
    #[inline(always)]
    pub fn prepend_binary_bytes(
        &mut self,
        bytes: &[u8],
        start: usize,
        count: usize,
        bitoffs: usize,
    ) -> Result<(), TermError> {
        let end_written = self
            .written
            .checked_add(count)
            .ok_or(TermError::SystemLimit)?;
        let end = start.checked_add(count).ok_or(TermError::SystemLimit)?;
        let required_end = end
            .checked_add(usize::from(bitoffs != 0))
            .ok_or(TermError::SystemLimit)?;
        if end_written > self.len || bitoffs >= 8 || (count != 0 && required_end > bytes.len()) {
            return Err(TermError::BadArg);
        }
        if count == 0 {
            return Ok(());
        }

        let mut cell = (self.start as *mut u64).wrapping_add(2 * self.written);
        if self.written == 0 {
            self.first_cdr = Some(cell.wrapping_add(1) as usize);
        }
        let mut head = self.head;
        if bitoffs == 0 {
            // The pre-sized source slice makes the down-counter bounds provable
            // while matching OTP's single backward induction variable.
            let source = &bytes[start..end];
            let mut remaining = source.len();
            while remaining != 0 {
                remaining -= 1;
                let byte = source[remaining];
                let value = Term::small(i64::from(byte)).expect("byte fits small integer");
                store(cell, value.bits());
                store(cell.wrapping_add(1), head.bits());
                head = Term((cell as u64).wrapping_add(1));
                cell = cell.wrapping_add(2);
            }
        } else {
            let mut remaining = count;
            let mut next = bytes[end];
            while remaining != 0 {
                let present = next;
                remaining -= 1;
                next = bytes[start + remaining];
                let byte = (present >> (8 - bitoffs)) | (next << bitoffs);
                let value = Term::small(i64::from(byte)).expect("byte fits small integer");
                store(cell, value.bits());
                store(cell.wrapping_add(1), head.bits());
                head = Term((cell as u64).wrapping_add(1));
                cell = cell.wrapping_add(2);
            }
        }
        self.head = head;
        self.written = end_written;
        Ok(())
    }

    /// Finish the list with `tail`; every reserved cell must have been filled.
    #[inline(always)]
    pub fn finish(self, tail: Term) -> Result<Term, TermError> {
        if self.written != self.len {
            return Err(TermError::BadArg);
        }
        if self.len == 0 {
            return Ok(tail);
        }
        store(
            self.last_cdr
                .or(self.first_cdr)
                .expect("nonempty list has a cdr slot") as *mut u64,
            tail.bits(),
        );
        Ok(self.head)
    }

    /// Finish a reservation filled with independent cons cells.
    pub fn finish_cells(self) -> Result<(), TermError> {
        if self.written == self.len {
            Ok(())
        } else {
            Err(TermError::BadArg)
        }
    }
}

impl Term {
    /// Construct an ordinary local reference (three 32-bit components) directly on any heap.
    #[inline]
    pub fn local_ref(
        heap: &mut (impl HeapAlloc + ?Sized),
        ids: [u32; 3],
    ) -> Result<Self, TermError> {
        Self::local_ref_with_pid(heap, ids, None)
    }

    /// Construct a local PID reference with its three reference numbers and creator PID.
    ///
    /// Port of erts/emulator/beam/erl_term.h:905-919 (`write_pid_ref_thing`), OTP-29.1.1.
    pub fn local_pid_ref(
        heap: &mut (impl HeapAlloc + ?Sized),
        ids: [u32; 3],
        pid: Term,
    ) -> Result<Self, TermError> {
        let pid_data = pid.as_pid_data().ok_or(TermError::BadArg)?;
        let pid_word = pid.tagged_word();
        debug_assert_eq!(Term(pid_word).as_pid_data(), Some(pid_data));
        Self::local_ref_with_pid(heap, ids, Some(pid_word))
    }

    /// Construct a local PID reference from the serialized creator PID words.
    pub fn local_pid_ref_from_words(
        heap: &mut (impl HeapAlloc + ?Sized),
        ids: [u32; 3],
        pid_low: u32,
        pid_high: u32,
    ) -> Result<Self, TermError> {
        let pid_data = u64::from(pid_low) | (u64::from(pid_high) << 32);
        if Term(pid_data).as_pid_data().is_none() {
            return Err(TermError::BadArg);
        }
        Self::local_ref_with_pid(heap, ids, Some(pid_data))
    }

    // Port of erts/emulator/beam/erl_term.h:844-919 (`write_ref_thing` / `write_pid_ref_thing`), OTP-29.1.1.
    fn local_ref_with_pid(
        heap: &mut (impl HeapAlloc + ?Sized),
        mut ids: [u32; 3],
        pid_data: Option<u64>,
    ) -> Result<Self, TermError> {
        if pid_data.is_some() {
            // Port of erts/emulator/beam/erl_bif_unique.h:108 (`ERTS_REF1_PID_MARKER_BIT__`),
            // OTP-29.1.1.
            ids[1] |= 1 << 16;
        }
        let words = if pid_data.is_some() { 4 } else { 3 };
        let p = heap.alloc(words).ok_or(TermError::HeapFull)?;
        // SAFETY: the allocation reserves the exact ordinary or PID-ref thing size, matching
        // the 64-bit little-endian ErtsORefThing/ErtsPRefThing layouts.
        unsafe {
            *p = if pid_data.is_some() {
                crate::PID_REF_THING_HEADER
            } else {
                crate::REF_THING_HEADER
            };
            *p.add(1) = ((ids[0] as u64) << 32) | 0xffff_ffff;
            *p.add(2) = ((ids[2] as u64) << 32) | ids[1] as u64;
            if let Some(pid_data) = pid_data {
                *p.add(3) = pid_data;
            }
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
        // erts_mk_magic_ref links the thing at the head of the off-heap list and charges
        // `mb->orig_size` to the virtual binary heap.
        store(p, crate::REF_THING_HEADER);
        store(p.wrapping_add(1), Arc::as_ptr(&owner) as u64);
        store(p.wrapping_add(2), 0);
        let words = (owner.orig_size() / 8) as u64;
        self.heap.link_magic_ref(p, owner)?;
        self.heap.add_bin_vheap(words);
        Ok(Term::from_ptr(p, 2))
    }
}

/// Borrowed bitstring view. An unaligned slice includes the surrounding bytes;
/// `start_bit` and `bit_len` identify the significant bit interval.
pub struct BinaryRef<'a> {
    bytes: &'a [u8],
    start: usize,
    bits: usize,
    referenced_size: usize,
    off_heap: bool,
    refc: bool,
}
impl<'a> BinaryRef<'a> {
    /// Whole backing bytes; unused bits may be present at the ends.
    pub fn bytes(&self) -> &'a [u8] {
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
    /// Size in bytes of the backing binary owner, or the heap bitstring itself.
    pub fn referenced_size(&self) -> usize {
        self.referenced_size
    }
    /// Whether an off-heap binary (refc, external or writable) owns the bytes, like a
    /// non-null `BinRef` from `ERTS_GET_BITSTRING_REF` in erts; on-heap bitstrings do not.
    pub fn is_off_heap(&self) -> bool {
        self.off_heap
    }
    /// Whether a reference-counted `Binary` owns the backing bytes.
    pub fn is_refc(&self) -> bool {
        self.refc
    }
}
impl Term {
    /// Borrow a binary's underlying bytes.
    ///
    /// # Safety
    /// The owning heap and any off-heap binary owner must remain live. No
    /// writable append may run while a view of its owner is retained.
    // Port of erts/emulator/beam/erl_bits.h:376-405 (`ERTS_GET_BITSTRING_REF`), OTP-29.1.1.
    #[inline(always)]
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
                referenced_size: bits.div_ceil(8),
                off_heap: false,
                refc: false,
            })
        } else if header & 63 == SUB_BITS {
            // SAFETY: SUB_BITS stores start/end and a live original in word four.
            let (start, end, original) =
                unsafe { (*p.add(2) as usize, *p.add(3) as usize, Term(*p.add(4))) };
            let adjustment = owner_adjustment(original) * 8;
            let off_heap = original.header().is_some_and(|h| h & 63 == BIN_REF);
            let mut refc = false;
            let (base, referenced_size) = if off_heap {
                // Port of erts/emulator/beam/erl_bif_binary.c:2520-2530, OTP-29.1.1.
                // SAFETY: original is a retained BinRef and the caller prevents mutation.
                unsafe {
                    let bin_ref = original.raw_ptr();
                    let owner = *bin_ref.add(1);
                    refc = !crate::bits::bin_ref_val_is_external(owner);
                    let size = if !refc {
                        (&*crate::bits::external_val_ptr(owner)).len()
                    } else {
                        *(owner as *const u64).add(3) as usize
                    };
                    (binary_data(bin_ref), size)
                }
            } else {
                // SAFETY: a match context may refer directly to live HeapBits data.
                unsafe {
                    let original_ptr = original.raw_ptr();
                    (
                        original_ptr.add(2).cast::<u8>(),
                        (*original_ptr.add(1) as usize).div_ceil(8),
                    )
                }
            };
            // SAFETY: The original allocation keeps this bit interval live.
            let bytes = unsafe { std::slice::from_raw_parts(base, (end - adjustment).div_ceil(8)) };
            Some(BinaryRef {
                bytes,
                start: start - adjustment,
                bits: end - start,
                referenced_size,
                off_heap,
                refc,
            })
        } else {
            None
        }
    }
}
#[cfg(test)]
mod heap_block_tests {
    use super::{
        HeapAlloc, HeapReservation, MbufFast, ProcessHeap, Term, TermBuilder, TermError, TermKind,
        VecHeap,
    };

    #[test]
    fn positive_bignum_block_leaves_digits_for_incremental_fill() {
        let mut heap = VecHeap::new();
        let mut block = TermBuilder::new(&mut heap).pos_bignum_block(3).unwrap();
        let term = block.term_at(0).unwrap();
        for digit in [11, 22, 33] {
            block.write_header(digit).unwrap();
        }
        similar_asserts::assert_eq!(block.finish_at(0).unwrap(), term);
        similar_asserts::assert_eq!(
            term.with_bignum_digits_mut(|digits| digits.to_vec()),
            Some(vec![11, 22, 33])
        );
    }

    #[test]
    #[ignore = "timing: cargo test --release -p arinsal-term heap_fragment_cycle_bench -- --ignored --nocapture"]
    fn heap_fragment_cycle_bench() {
        std::thread::spawn(|| {
            similar_asserts::assert_eq!(
                arinsal_alloc::register_thread(arinsal_alloc::ThreadKind::Scheduler(1)),
                Ok(1)
            );
            let mut state = 0x2545_f491_4f6c_dd1d_u64;
            let mut next = move || {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state
            };
            let cycles: usize = std::env::var("FRAG_CYCLES")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(200_000);
            let mut heap = ProcessHeap::with_words(64);
            if std::env::var_os("FRAG_TLS").is_none() {
                heap.set_alloc_ix(Some(arinsal_alloc::thread_alloc_ix()));
            }
            let mut best = f64::MAX;
            for _ in 0..5 {
                let started = std::time::Instant::now();
                for _ in 0..cycles {
                    for _ in 0..26 {
                        std::hint::black_box(heap.heap_fragment(1 + (next() % 12) as usize));
                    }
                    let mut fragments = std::mem::take(&mut heap.fragments);
                    heap.mbuf_fast = MbufFast::default();
                    heap.release_fragments(&mut fragments);
                    heap.fragments = fragments;
                    heap.fragment_words = 0;
                }
                best = best.min(started.elapsed().as_nanos() as f64 / (cycles as f64 * 26.0));
            }
            eprintln!("heap fragment path: {best:.2} ns per alloc+free pair");
        })
        .join()
        .unwrap();
    }

    #[test]
    fn vec_heap_reset_reuses_the_first_chunk_and_discards_overflow() {
        let mut heap = VecHeap::with_initial_chunk_words(8);
        let first = heap.alloc(8).unwrap();
        heap.alloc(8).unwrap();
        similar_asserts::assert_eq!(heap.chunks.len(), 2);

        heap.reset(8);

        similar_asserts::assert_eq!(heap.chunks.len(), 1);
        similar_asserts::assert_eq!(heap.alloc(8).unwrap(), first);
    }

    #[test]
    fn realloc_preserves_the_user_prefix_and_can_shrink() {
        let mut heap = ProcessHeap::with_words(64);
        assert!(heap.old_words.is_empty());
        heap.words.words_mut()[0] = 0x1111;
        heap.words.words_mut()[3] = 0x2222;
        heap.words.words_mut()[60] = 0x3333;
        heap.words.realloc(128);
        similar_asserts::assert_eq!(heap.words.len(), 128);
        similar_asserts::assert_eq!(heap.words.words()[0], 0x1111);
        similar_asserts::assert_eq!(heap.words.words()[3], 0x2222);
        similar_asserts::assert_eq!(heap.words.words()[60], 0x3333);
        heap.words.realloc(32);
        similar_asserts::assert_eq!(heap.words.len(), 32);
        similar_asserts::assert_eq!(heap.words.words()[0], 0x1111);
        similar_asserts::assert_eq!(heap.words.words()[3], 0x2222);
    }

    #[test]
    fn heap_fragment_reuses_hallocx_extra_words() {
        let mut heap = ProcessHeap::with_words(1);
        let first = heap.heap_fragment_with_extra(2, 200);
        let second = heap.heap_fragment_with_extra(3, 200);

        similar_asserts::assert_eq!(
            second as usize,
            first as usize + 2 * std::mem::size_of::<u64>()
        );
        similar_asserts::assert_eq!(heap.mbuf_size(), 5);
        let released_to = second as usize + std::mem::size_of::<u64>();
        let end = (second as usize + 3 * std::mem::size_of::<u64>()) as *mut u64;
        heap.release(end, released_to as *mut u64);
        similar_asserts::assert_eq!(heap.mbuf_size(), 3);
        similar_asserts::assert_eq!(heap.heap_fragment_with_extra(1, 200) as usize, released_to);
    }

    #[test]
    fn reserved_words_use_indices_for_term_slots_and_next_fixups() {
        let mut heap = ProcessHeap::with_words(64);
        let mut reservation = HeapReservation::new(&mut heap, 8).unwrap();
        let start = reservation.cursor();

        let tuple = reservation
            .with_words(|words| {
                let (tuple, first, second) = {
                    let mut builder = TermBuilder::new(words);
                    let block = builder.reserve_tuple_block(2)?;
                    (block.term_at(0)?, block.term_slot(1)?, block.term_slot(2)?)
                };
                words.write_next_slot(first, None)?;
                similar_asserts::assert_eq!(words.take_next_slot(first)?, None);
                words.write_next_slot(first, Some(second))?;
                similar_asserts::assert_eq!(words.take_next_slot(first)?, Some(second));
                let value = Term::small(7).unwrap();
                words.write_term_slot(first, value)?;
                words.write_term_slot(second, Term::NIL)?;
                similar_asserts::assert_eq!(words.read_term_slot(first)?, value);
                Ok::<_, TermError>(tuple)
            })
            .unwrap()
            .unwrap();

        similar_asserts::assert_eq!(reservation.cursor(), start.wrapping_add(3));
        similar_asserts::assert_eq!(tuple.classify(), TermKind::Tuple);
    }
}
