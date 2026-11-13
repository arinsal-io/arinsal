//! Signal and message nodes: one allocation per queued signal, which for a message also holds
//! the heap fragment of its data.
//!
//! Port of erts/emulator/beam/erl_message.h/.c (`ErtsMessage` with `ErlHeapFragment hfrag`
//! inline, `erts_alloc_message`, `ERTS_MSG_COMBINED_HFRAG`, `erts_free_message`,
//! `erts_save_message_in_proc`, `erts_cleanup_messages`), OTP-29.1.1. The queue links (`next`)
//! are used by the scheduler's signal queues; this module owns the allocation and release of
//! nodes and of their inline fragments. All raw work on node memory is confined here.

use std::alloc::Layout;
use std::cell::Cell;
use std::marker::PhantomData;
use std::ptr::NonNull;
use std::sync::Arc;

use crate::bits::{ExternalBinary, RefcBinary, WritableBinary};
use crate::heap::{
    HeapAlloc, OffHeapLists, link_external_bin_ref, link_magic_thing, link_node_thing, store,
};
use crate::{Node, Term, TermError};
use arinsal_alloc::typed::{AllocBlock, ErtsAlcType};

/// One signal (`ErtsSignalCommon`): the queue link, then the signal value. A message node may
/// be followed in the same allocation by a heap fragment (`ERTS_MSG_COMBINED_HFRAG`).
#[repr(C)]
pub struct SignalNode<T> {
    /// The next node of the queue holding this one (`next`).
    pub next: Option<NonNull<SignalNode<T>>>,
    /// Words of the inline heap fragment (`hfrag.alloc_size`), 0 for a node without one, or
    /// [`LAZY`] for a header overlaid on another structure.
    fragment_words: usize,
    /// The signal.
    pub value: T,
}

/// erts `ErlHeapFragment`, inline after a message node: the off-heap objects of its data
/// (`off_heap`), `alloc_size`, `used_size`, then the words (`mem`).
#[repr(C)]
pub(crate) struct HeapFragment {
    pub(crate) off_heap: crate::heap::OffHeapLists,
    pub(crate) bin_vheap: u64,
    alloc_size: usize,
    used_size: usize,
}

/// A standalone message heap fragment with its terms and linked off-heap owners.
/// Port of `ErlHeapFragment` in erts/emulator/beam/erl_message.h, OTP-29.1.1.
pub struct MessageHeapBlock {
    pub(crate) off_heap: OffHeapLists,
    pub(crate) bin_vheap: u64,
    memory: AllocBlock,
    used: usize,
}

impl MessageHeapBlock {
    /// Allocate one message fragment with room for `words` terms.
    pub fn with_words(words: usize) -> Self {
        let memory = AllocBlock::new(ErtsAlcType::HEAP_FRAG, words)
            .expect("message heap fragment allocation size is valid");
        Self {
            off_heap: OffHeapLists::default(),
            bin_vheap: 0,
            memory,
            used: 0,
        }
    }

    /// Number of initialized message words.
    pub fn len(&self) -> usize {
        self.used
    }

    /// Whether the fragment contains no message words.
    pub fn is_empty(&self) -> bool {
        self.used == 0
    }

    /// The initialized message words.
    pub fn words(&self) -> &[u64] {
        &self.memory.as_slice()[..self.used]
    }

    pub(crate) fn into_parts(self) -> (AllocBlock, usize, OffHeapLists, u64) {
        (self.memory, self.used, self.off_heap, self.bin_vheap)
    }
}

impl HeapAlloc for MessageHeapBlock {
    fn allocator_identity(&self) -> usize {
        self.memory.as_ptr() as usize
    }
    fn alloc(&mut self, words: usize) -> Option<*mut u64> {
        let end = self.used.checked_add(words)?;
        if end > self.memory.len() {
            return None;
        }
        let ptr = self.memory.as_mut_slice()[self.used..].as_mut_ptr();
        self.used = end;
        Some(ptr)
    }
    fn alloc_with_extra(&mut self, words: usize, extra: usize) -> Option<*mut u64> {
        if self.used.checked_add(words)?.checked_add(extra)? > self.memory.len() {
            return None;
        }
        self.alloc(words)
    }
    fn release(&mut self, end: *mut u64, start: *mut u64) {
        let base = self.memory.as_ptr() as usize;
        let used_end = base.saturating_add(self.used.saturating_mul(8));
        let start = start as usize;
        if start >= base
            && start <= used_end
            && end as usize == used_end
            && (start - base).is_multiple_of(8)
        {
            self.used = (start - base) / 8;
        }
    }
    fn retain_binary(&mut self, binary: Arc<RefcBinary>) {
        self.bin_vheap = self.bin_vheap.saturating_add((binary.len() / 8) as u64);
    }
    fn link_bin_ref(
        &mut self,
        bin_ref: *mut u64,
        writable: bool,
        overhead_words: u64,
        owner: Option<arinsal_alloc::raw::OwnedBinaryRef>,
    ) -> Result<(), TermError> {
        let head = if writable {
            &mut self.off_heap.wrt_bins
        } else {
            &mut self.off_heap.off_heap_first
        };
        store(bin_ref.wrapping_add(2), *head as u64);
        *head = bin_ref as usize;
        if let Some(owner) = owner {
            owner.transfer_to_bin_ref(bin_ref);
        }
        self.off_heap.overhead = self.off_heap.overhead.saturating_add(overhead_words);
        Ok(())
    }
    fn add_bin_vheap(&mut self, words: u64) {
        self.bin_vheap = self.bin_vheap.saturating_add(words);
    }
    fn retain_writable_binary(&mut self, binary: Arc<WritableBinary>) -> Result<(), TermError> {
        self.bin_vheap = self
            .bin_vheap
            .saturating_add((binary.capacity() / 8) as u64);
        Ok(())
    }
    fn retain_writable_binary_with_apparent_size(
        &mut self,
        _binary: Arc<WritableBinary>,
        bits: usize,
    ) -> Result<(), TermError> {
        self.bin_vheap = self.bin_vheap.saturating_add((bits.div_ceil(8) / 8) as u64);
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
        link_external_bin_ref(&mut self.off_heap.off_heap_first, bin_ref, binary);
        Ok(())
    }
    fn supports_external_binary(&self) -> bool {
        true
    }
    fn link_node(&mut self, thing: *mut u64, node: Arc<Node>) {
        link_node_thing(&mut self.off_heap.off_heap_first, thing, node);
    }
    fn link_magic_ref(
        &mut self,
        thing: *mut u64,
        owner: Arc<crate::MagicRef>,
    ) -> Result<(), TermError> {
        link_magic_thing(
            &mut self.off_heap.off_heap_first,
            &mut self.off_heap.overhead,
            thing,
            owner,
        );
        Ok(())
    }
    fn supports_magic(&self) -> bool {
        true
    }
}

/// Off-heap references owned by a copied term whose words live in caller-provided storage.
///
/// This is used when the owner stores its header and heap words in one allocation.
pub struct InlineHeapOwners(crate::heap::OffHeapLists);

impl InlineHeapOwners {
    /// Create an empty off-heap owner list.
    pub fn new() -> Self {
        Self(crate::heap::OffHeapLists::default())
    }
}

impl Default for InlineHeapOwners {
    fn default() -> Self {
        Self::new()
    }
}

/// A bounded heap allocator over caller-provided, uninitialized words.
pub struct InlineHeapAlloc<'a> {
    words: &'a mut [std::mem::MaybeUninit<u64>],
    owners: &'a mut InlineHeapOwners,
    used: usize,
}

impl<'a> InlineHeapAlloc<'a> {
    /// Borrow a word region and its owner header for a term copy.
    pub fn new(
        words: &'a mut [std::mem::MaybeUninit<u64>],
        owners: &'a mut InlineHeapOwners,
    ) -> Self {
        Self {
            words,
            owners,
            used: 0,
        }
    }
}

impl HeapAlloc for InlineHeapAlloc<'_> {
    fn allocator_identity(&self) -> usize {
        self.words.as_ptr() as usize
    }
    fn alloc(&mut self, words: usize) -> Option<*mut u64> {
        let end = self.used.checked_add(words)?;
        if end > self.words.len() {
            return None;
        }
        let pointer = self.words[self.used..].as_mut_ptr().cast::<u64>();
        self.used = end;
        Some(pointer)
    }
    fn retain_binary(&mut self, binary: Arc<RefcBinary>) {
        drop(binary);
    }
    fn add_bin_vheap(&mut self, _words: u64) {}
    fn retain_writable_binary(&mut self, binary: Arc<WritableBinary>) -> Result<(), TermError> {
        self.add_bin_vheap((binary.capacity() / 8) as u64);
        Ok(())
    }
    fn retain_writable_binary_with_apparent_size(
        &mut self,
        _binary: Arc<WritableBinary>,
        bits: usize,
    ) -> Result<(), TermError> {
        self.add_bin_vheap((bits.div_ceil(8) / 8) as u64);
        Ok(())
    }
    fn link_bin_ref(
        &mut self,
        bin_ref: *mut u64,
        writable: bool,
        overhead_words: u64,
        owner: Option<arinsal_alloc::raw::OwnedBinaryRef>,
    ) -> Result<(), TermError> {
        let head = if writable {
            &mut self.owners.0.wrt_bins
        } else {
            &mut self.owners.0.off_heap_first
        };
        store(bin_ref.wrapping_add(2), *head as u64);
        *head = bin_ref as usize;
        if let Some(owner) = owner {
            owner.transfer_to_bin_ref(bin_ref);
        }
        self.owners.0.overhead = self.owners.0.overhead.saturating_add(overhead_words);
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
        link_external_bin_ref(&mut self.owners.0.off_heap_first, bin_ref, binary);
        Ok(())
    }
    fn supports_external_binary(&self) -> bool {
        true
    }
    fn link_node(&mut self, thing: *mut u64, node: Arc<Node>) {
        link_node_thing(&mut self.owners.0.off_heap_first, thing, node);
    }
    fn link_magic_ref(
        &mut self,
        thing: *mut u64,
        owner: Arc<crate::MagicRef>,
    ) -> Result<(), TermError> {
        link_magic_thing(
            &mut self.owners.0.off_heap_first,
            &mut self.owners.0.overhead,
            thing,
            owner,
        );
        Ok(())
    }
    fn supports_magic(&self) -> bool {
        true
    }
}

/// The layout of a node of `T` with an inline fragment of `words`, and the offset of the
/// fragment header (0 when `words` is 0).
fn node_layout<T>(words: usize) -> (Layout, usize) {
    let node = Layout::new::<SignalNode<T>>();
    if words == 0 {
        return (node.pad_to_align(), 0);
    }
    let (with_header, header_offset) = node
        .extend(Layout::new::<HeapFragment>())
        .expect("message size fits");
    let (layout, _) = with_header
        .extend(Layout::array::<u64>(words).expect("message size fits"))
        .expect("message size fits");
    (layout.pad_to_align(), header_offset)
}

/// `fragment_words` of a node that is a header overlaid on another structure (a monitor
/// half); its signal value is made when the node is taken out of its queue.
const LAZY: usize = 1 << (usize::BITS - 1);

/// Bits of a lazy node's marker word that the host structure can use for what readers need
/// before the value exists (the sender and the kind of the signal).
pub const LAZY_META_MASK: u64 = !(LAZY as u64);

/// Whether a node's `fragment_words` word marks a lazy node.
const fn is_lazy_word(word: usize) -> bool {
    word & LAZY != 0
}

/// Size of the header of a lazy node, which its host structure has to leave free in transit.
pub const LAZY_HEADER_BYTES: usize = crate::raw::LAZY_HEADER_BYTES;

/// The words of a fragment start right after its header.
fn fragment_words_ptr(header: NonNull<HeapFragment>) -> *mut u64 {
    header
        .as_ptr()
        .cast::<u8>()
        .wrapping_add(std::mem::size_of::<HeapFragment>())
        .cast()
}

/// A signal node owned outside any queue: the sender before it enqueues, or the receiver after
/// it took the node out of a queue.
pub struct OwnedSignal<T> {
    /// A lazy node is replaced by an allocated one when a reader needs the value in place.
    node: Cell<NonNull<SignalNode<T>>>,
    _value: PhantomData<T>,
}

// SAFETY: the handle owns its node like a `Box` owns its value; the inline fragment holds only
// words and off-heap owners, which are `Send`.
unsafe impl<T: Send> Send for OwnedSignal<T> {}

impl<T> OwnedSignal<T> {
    /// A node for `value` without a heap fragment (`erts_alloc_message(0, NULL)`).
    pub fn new(value: T) -> Self {
        Self::with_heap_fragment(value, 0)
    }

    /// A node for `value` with an inline heap fragment of `words` (`erts_alloc_message(sz,
    /// &hp)`), empty until [`OwnedSignal::heap_fragment`] allocates in it.
    pub fn with_heap_fragment(value: T, words: usize) -> Self {
        let (layout, header_offset) = node_layout::<T>(words);
        assert!(
            layout.align() <= std::mem::align_of::<u64>(),
            "allocator blocks are word aligned"
        );
        let block = if words == 0 {
            arinsal_alloc::typed::msg_ref_alloc(layout.size()).map(|block| block.as_non_null())
        } else {
            arinsal_alloc::typed::msg_alloc(layout.size())
        };
        let Ok(block) = block else {
            std::alloc::handle_alloc_error(layout)
        };
        let node = block.cast::<SignalNode<T>>();
        // SAFETY: `node` is a fresh allocation of `layout`, which places the node at its start
        // and, when `words` is not 0, a fragment header at `header_offset` followed by `words`.
        unsafe {
            node.as_ptr().write(SignalNode {
                next: None,
                fragment_words: words,
                value,
            });
            if words != 0 {
                node.as_ptr()
                    .cast::<u8>()
                    .add(header_offset)
                    .cast::<HeapFragment>()
                    .write(HeapFragment {
                        off_heap: crate::heap::OffHeapLists::default(),
                        bin_vheap: 0,
                        alloc_size: words,
                        used_size: 0,
                    });
            }
        }
        Self {
            node: Cell::new(node),
            _value: PhantomData,
        }
    }

    /// A node that is the header of another structure, queued as the signal itself. `meta`
    /// (within [`LAZY_META_MASK`]) is kept for [`OwnedSignal::lazy_meta`]. `materialise` makes
    /// the signal value from the structure when the node is taken out of its queue, and gives up
    /// the structure to the value; until then no value exists.
    ///
    /// Contract: `header` points to [`LAZY_HEADER_BYTES`] bytes, word aligned, that nothing else
    /// uses until the node is taken out; `materialise(header)` is valid once, for that node.
    pub fn lazy(header: NonNull<u8>, meta: u64, materialise: unsafe fn(NonNull<u8>) -> T) -> Self {
        debug_assert_eq!(meta & !LAZY_META_MASK, 0);
        crate::raw::lazy_header_write(header, LAZY | meta as usize, materialise);
        Self {
            node: Cell::new(header.cast()),
            _value: PhantomData,
        }
    }

    fn marker(node: NonNull<SignalNode<T>>) -> usize {
        crate::raw::node_marker(node.cast())
    }

    /// Whether the node is still the header of its structure, with no value yet: always a
    /// non-message signal.
    pub fn is_lazy(&self) -> bool {
        is_lazy_word(Self::marker(self.node.get()))
    }

    /// The value of a node a queue holds; `None` for a lazy node, which has none yet.
    ///
    /// Contract: `node` is a live node of this type, not written while the reference is in use.
    pub fn value_of<'a>(node: NonNull<SignalNode<T>>) -> Option<&'a T> {
        (!is_lazy_word(Self::marker(node))).then(|| crate::raw::node_value(node))
    }

    /// [`OwnedSignal::value_of`], mutably.
    ///
    /// Contract: `node` is a live node of this type, not otherwise used while the reference is
    /// in use.
    pub fn value_mut_of<'a>(node: NonNull<SignalNode<T>>) -> Option<&'a mut T> {
        (!is_lazy_word(Self::marker(node))).then(|| crate::raw::node_value_mut(node))
    }

    /// The `meta` a lazy node was made with, readable before the value exists.
    pub fn lazy_meta(&self) -> Option<u64> {
        let word = Self::marker(self.node.get());
        is_lazy_word(word).then_some(word as u64 & LAZY_META_MASK)
    }

    /// [`OwnedSignal::lazy_meta`] of a node a queue holds.
    ///
    /// Contract: `node` is a live node of this type.
    pub fn lazy_meta_of(node: NonNull<SignalNode<T>>) -> Option<u64> {
        let word = Self::marker(node);
        is_lazy_word(word).then_some(word as u64 & LAZY_META_MASK)
    }

    /// Take the value of a lazy node out of its structure; the node is not used afterwards.
    fn materialise(node: NonNull<SignalNode<T>>) -> T {
        crate::raw::lazy_make(node.cast())
    }

    /// Give a lazy node the allocated storage of an ordinary one, for a reader that needs the
    /// value in place. The structure of the lazy node now belongs to the value.
    fn realise(&self) {
        if !self.is_lazy() {
            return;
        }
        let value = Self::materialise(self.node.get());
        let block = Self::new(value);
        self.node.set(block.into_raw());
    }

    fn header(&self) -> Option<NonNull<HeapFragment>> {
        let words = Self::marker(self.node.get());
        if words == 0 || is_lazy_word(words) {
            return None;
        }
        // The header sits where `node_layout` put it, inside the handle's allocation.
        let (_, offset) = node_layout::<T>(words);
        NonNull::new(
            self.node
                .get()
                .as_ptr()
                .cast::<u8>()
                .wrapping_add(offset)
                .cast(),
        )
    }

    /// The inline heap fragment, to allocate the message data in.
    pub fn heap_fragment(&mut self) -> Option<FragmentMut<'_>> {
        self.header().map(|header| FragmentMut {
            header,
            _node: PhantomData,
        })
    }

    /// The used words of the inline heap fragment.
    pub fn fragment_words(&self) -> Option<&[u64]> {
        let header = self.header()?;
        // SAFETY: the handle borrows the node; the first `used_size` words were written by
        // allocations of the fragment.
        unsafe {
            let used = (*header.as_ptr()).used_size;
            Some(std::slice::from_raw_parts(fragment_words_ptr(header), used))
        }
    }

    /// [`OwnedSignal::fragment_words`] of a node a queue holds.
    ///
    /// # Safety
    ///
    /// `node` is a live node of this type, not written while the returned words are in use.
    pub unsafe fn fragment_words_of<'a>(node: NonNull<SignalNode<T>>) -> Option<&'a [u64]> {
        let handle = std::mem::ManuallyDrop::new(Self {
            node: Cell::new(node),
            _value: PhantomData,
        });
        let header = handle.header()?;
        // SAFETY: the caller keeps the node live; the first `used_size` words were written by
        // allocations of the fragment.
        unsafe {
            let used = (*header.as_ptr()).used_size;
            Some(std::slice::from_raw_parts(fragment_words_ptr(header), used))
        }
    }

    /// The off-heap overhead the inline fragment adds to a receiver (`off_heap.overhead`
    /// plus the virtual binary heap words).
    pub fn fragment_bin_vheap(&self) -> u64 {
        // SAFETY: the handle borrows the node, so the header is live.
        self.header()
            .map_or(0, |header| unsafe { (*header.as_ptr()).bin_vheap })
    }

    /// Free the node, giving back the signal (`erts_free_message`). An inline fragment is
    /// released with it.
    pub fn into_value(self) -> T {
        let (value, fragment) = self.split_fragment();
        drop(fragment);
        value
    }

    /// Move the signal out and keep the inline fragment, if any, as a fragment of its own
    /// (`erts_shrink_message` to a message reference, the data left behind).
    pub fn split_fragment(self) -> (T, Option<NodeFragment>) {
        let header = self.header();
        let node = self.into_raw();
        // SAFETY: the handle owned the node; the value is read out exactly once, and the memory
        // either moves to the returned fragment, goes back to its embedding storage, or is
        // released here.
        unsafe {
            if is_lazy_word(Self::marker(node)) {
                return (Self::materialise(node), None);
            }
            let value = std::ptr::addr_of!((*node.as_ptr()).value).read();
            match header {
                Some(header) => {
                    if (*header.as_ptr()).used_size == 0 {
                        // `erts_shrink_message(..., 0, ...)` frees the combined MSG block; the
                        // caller that retains a queue node replaces it with a MSG_REF node.
                        std::ptr::drop_in_place(header.as_ptr());
                        arinsal_alloc::typed::msg_free(node.cast());
                        (value, None)
                    } else {
                        (
                            value,
                            Some(NodeFragment {
                                memory: node.cast(),
                                header,
                            }),
                        )
                    }
                }
                None => {
                    // SAFETY: this node was allocated by `msg_ref_alloc` in `OwnedSignal::new`.
                    arinsal_alloc::typed::msg_ref_free(
                        arinsal_alloc::typed::MessageRefBlock::from_node(node.cast()),
                    );
                    (value, None)
                }
            }
        }
    }

    /// Drop the signal and keep its inline fragment as the data of a received message
    /// (`erts_save_message_in_proc` keeps the message on `msg_frag`).
    pub fn into_fragment(self) -> Option<NodeFragment> {
        self.split_fragment().1
    }

    /// Give up ownership to a queue.
    pub fn into_raw(self) -> NonNull<SignalNode<T>> {
        let node = self.node.get();
        std::mem::forget(self);
        node
    }

    /// Take back ownership of a node a queue held.
    ///
    /// # Safety
    ///
    /// `node` came from [`OwnedSignal::into_raw`] of this type and no other owner is left.
    pub unsafe fn from_raw(node: NonNull<SignalNode<T>>) -> Self {
        Self {
            node: Cell::new(node),
            _value: PhantomData,
        }
    }
}

impl<T> std::ops::Deref for OwnedSignal<T> {
    type Target = T;

    fn deref(&self) -> &T {
        self.realise();
        // SAFETY: the handle owns the node, so it is live and not borrowed elsewhere.
        unsafe { &(*self.node.get().as_ptr()).value }
    }
}

impl<T> std::ops::DerefMut for OwnedSignal<T> {
    fn deref_mut(&mut self) -> &mut T {
        self.realise();
        // SAFETY: as in `deref`, and the handle is borrowed exclusively.
        unsafe { &mut (*self.node.get().as_ptr()).value }
    }
}

impl<T> Drop for OwnedSignal<T> {
    /// `erts_cleanup_messages` of one node: drop the signal and its fragment, then free it.
    fn drop(&mut self) {
        let header = self.header();
        // SAFETY: the handle owns the node; the value is dropped once, and the memory is
        // released by the fragment or here, or goes back to its embedding storage.
        unsafe {
            if is_lazy_word(Self::marker(self.node.get())) {
                drop(Self::materialise(self.node.get()));
                return;
            }
            std::ptr::drop_in_place(std::ptr::addr_of_mut!((*self.node.get().as_ptr()).value));
            if let Some(header) = header {
                drop(NodeFragment {
                    memory: self.node.get().cast(),
                    header,
                });
            } else {
                // SAFETY: this node was allocated by `msg_ref_alloc` in `OwnedSignal::new`.
                arinsal_alloc::typed::msg_ref_free(
                    arinsal_alloc::typed::MessageRefBlock::from_node(self.node.get().cast()),
                );
            }
        }
    }
}

/// The inline heap fragment of a message node whose signal is gone: kept with its node memory
/// while the data is in use (a received message on the process's fragment list).
pub struct NodeFragment {
    memory: NonNull<u8>,
    header: NonNull<HeapFragment>,
}

// SAFETY: the fragment owns its memory exclusively; its words and off-heap owners are `Send`.
unsafe impl Send for NodeFragment {}

impl NodeFragment {
    /// The first word (`mem`).
    pub fn as_ptr(&self) -> *const u64 {
        fragment_words_ptr(self.header)
    }

    /// Words that hold objects (`used_size`).
    pub fn len(&self) -> usize {
        // SAFETY: the fragment owns its header.
        unsafe { (*self.header.as_ptr()).used_size }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The used words.
    pub fn words(&self) -> &[u64] {
        // SAFETY: the first `used_size` words were written by allocations of the fragment.
        unsafe { std::slice::from_raw_parts(self.as_ptr(), self.len()) }
    }

    /// The off-heap owners and virtual binary heap words, taken over by a receiver.
    pub(crate) fn take_owners(&mut self) -> (crate::heap::OffHeapLists, u64) {
        // SAFETY: the fragment owns its header exclusively.
        unsafe {
            let header = &mut *self.header.as_ptr();
            (
                std::mem::take(&mut header.off_heap),
                std::mem::take(&mut header.bin_vheap),
            )
        }
    }

    /// The off-heap owners, for rebasing their chain after the words moved.
    pub(crate) fn owners_mut(&mut self) -> &mut crate::heap::OffHeapLists {
        // SAFETY: the fragment owns its header exclusively.
        unsafe { &mut (*self.header.as_ptr()).off_heap }
    }
}

impl Drop for NodeFragment {
    fn drop(&mut self) {
        // SAFETY: the fragment owns the header, which is dropped once before the node memory
        // goes back to the allocator.
        unsafe {
            std::ptr::drop_in_place(self.header.as_ptr());
        }
        arinsal_alloc::typed::msg_free(self.memory);
    }
}

/// The inline heap fragment of a node held by its owner: message data is allocated in it.
pub struct FragmentMut<'a> {
    header: NonNull<HeapFragment>,
    _node: PhantomData<&'a mut ()>,
}

impl FragmentMut<'_> {
    fn fragment(&mut self) -> &mut HeapFragment {
        // SAFETY: the view borrows the node exclusively, so the header is live and unshared.
        unsafe { &mut *self.header.as_ptr() }
    }

    /// Words allocated so far (`used_size`).
    pub fn used(&mut self) -> usize {
        self.fragment().used_size
    }
}

impl HeapAlloc for FragmentMut<'_> {
    fn alloc(&mut self, words: usize) -> Option<*mut u64> {
        let header = self.header;
        let fragment = self.fragment();
        if words > fragment.alloc_size - fragment.used_size {
            return None;
        }
        let at = fragment.used_size;
        fragment.used_size += words;
        Some(fragment_words_ptr(header).wrapping_add(at))
    }

    fn retain_binary(&mut self, binary: Arc<RefcBinary>) {
        // Port of erts/emulator/beam/erl_message.h (OH_OVERHEAD), OTP-29.1.1.
        let fragment = self.fragment();
        fragment.bin_vheap = fragment.bin_vheap.saturating_add((binary.len() / 8) as u64);
    }

    fn link_bin_ref(
        &mut self,
        bin_ref: *mut u64,
        writable: bool,
        overhead_words: u64,
        owner: Option<arinsal_alloc::raw::OwnedBinaryRef>,
    ) -> Result<(), TermError> {
        let owners = &mut self.fragment().off_heap;
        let head = if writable {
            &mut owners.wrt_bins
        } else {
            &mut owners.off_heap_first
        };
        crate::heap::store(bin_ref.wrapping_add(2), *head as u64);
        *head = bin_ref as usize;
        if let Some(owner) = owner {
            owner.transfer_to_bin_ref(bin_ref);
        }
        owners.overhead = owners.overhead.saturating_add(overhead_words);
        Ok(())
    }

    fn add_bin_vheap(&mut self, words: u64) {
        let fragment = self.fragment();
        fragment.bin_vheap = fragment.bin_vheap.saturating_add(words);
    }

    fn retain_writable_binary(&mut self, binary: Arc<WritableBinary>) -> Result<(), TermError> {
        let fragment = self.fragment();
        fragment.bin_vheap = fragment
            .bin_vheap
            .saturating_add((binary.capacity() / 8) as u64);
        Ok(())
    }

    fn retain_writable_binary_with_apparent_size(
        &mut self,
        _binary: Arc<WritableBinary>,
        apparent_size_bits: usize,
    ) -> Result<(), TermError> {
        // Port of erl_bits.c (`build_writable_bitstring`), OTP-29.1.1.
        let fragment = self.fragment();
        fragment.bin_vheap = fragment
            .bin_vheap
            .saturating_add((apparent_size_bits.div_ceil(8) / 8) as u64);
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

    fn update_writable_binary_overhead_at(
        &mut self,
        _source: Term,
        _bin_ref: usize,
        old_size_bits: usize,
        new_size_bits: usize,
    ) {
        // Port of erl_bits.c (`update_wb_overhead`): a fragment has no old generation.
        let increase = if new_size_bits > old_size_bits {
            (new_size_bits.div_ceil(8) / 8 - old_size_bits.div_ceil(8) / 8) as u64
        } else {
            0
        };
        let owners = &mut self.fragment().off_heap;
        owners.overhead = owners.overhead.wrapping_add(increase);
    }

    fn supports_writable_binary(&self) -> bool {
        true
    }

    fn link_external_binary(
        &mut self,
        bin_ref: *mut u64,
        binary: Arc<ExternalBinary>,
    ) -> Result<(), TermError> {
        link_external_bin_ref(
            &mut self.fragment().off_heap.off_heap_first,
            bin_ref,
            binary,
        );
        Ok(())
    }

    fn supports_external_binary(&self) -> bool {
        true
    }

    fn link_node(&mut self, thing: *mut u64, node: Arc<Node>) {
        link_node_thing(&mut self.fragment().off_heap.off_heap_first, thing, node);
    }

    fn link_magic_ref(
        &mut self,
        thing: *mut u64,
        owner: Arc<crate::MagicRef>,
    ) -> Result<(), TermError> {
        let owners = &mut self.fragment().off_heap;
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

/// The data of a message kept apart from its node: a standalone heap (a separately allocated
/// `ErlHeapFragment`, `data.heap_frag`) or the inline fragment of the node it came in.
pub enum MessageHeap {
    Heap(MessageHeapBlock),
    Node(NodeFragment),
}

/// Whether the heap objects in `words` hold a direct pointer that `is_area_pointer` accepts
/// (`any_heap_refs` over a message's inline fragment).
pub fn words_have_heap_reference(words: &[u64], is_area_pointer: impl FnMut(Term) -> bool) -> bool {
    crate::ProcessHeap::words_have_heap_reference(words, is_area_pointer)
}

impl MessageHeap {
    /// Words of the message data (`erts_msg_attached_data_size`).
    pub fn message_data_size(&self) -> usize {
        match self {
            Self::Heap(heap) => heap.len(),
            Self::Node(fragment) => fragment.len(),
        }
    }

    /// Words a literal-area check inspects.
    pub fn literal_scan_words(&self) -> usize {
        match self {
            Self::Heap(heap) => heap.len(),
            Self::Node(fragment) => fragment.len(),
        }
    }

    /// Whether the data holds a direct pointer that `is_area_pointer` accepts.
    pub fn has_heap_reference(&self, is_area_pointer: impl FnMut(Term) -> bool) -> bool {
        match self {
            Self::Heap(heap) => {
                crate::ProcessHeap::words_have_heap_reference(heap.words(), is_area_pointer)
            }
            Self::Node(fragment) => {
                crate::ProcessHeap::words_have_heap_reference(fragment.words(), is_area_pointer)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{TermBuilder, to_owned};
    use similar_asserts::assert_eq;

    #[test]
    fn a_message_is_built_in_its_node_and_kept_as_a_fragment() {
        let mut node = OwnedSignal::with_heap_fragment(String::from("value"), 8);
        let term = {
            let mut fragment = node.heap_fragment().expect("inline fragment");
            TermBuilder::new(&mut fragment)
                .tuple(&[Term::small(1).unwrap(), Term::small(2).unwrap()])
                .unwrap()
        };
        assert_eq!(node.fragment_words().map(<[u64]>::len), Some(3));
        assert_eq!(node.as_str(), "value");
        let fragment = node.into_fragment().expect("fragment kept");
        assert_eq!(fragment.len(), 3);
        assert_eq!(
            to_owned(term).unwrap(),
            arinsal_etf::OwnedTerm::tuple(vec![
                arinsal_etf::OwnedTerm::Int(1),
                arinsal_etf::OwnedTerm::Int(2),
            ])
        );
        drop(fragment);
        let empty = OwnedSignal::new(vec![1, 2, 3]);
        assert_eq!(*empty, vec![1, 2, 3]);
        assert!(empty.fragment_words().is_none());
        assert_eq!(empty.into_value(), vec![1, 2, 3]);
    }

    /// A host structure whose first words are a lazy node header, with a payload word after.
    #[repr(C)]
    struct Host {
        header: [u64; 3],
        payload: u64,
    }

    unsafe fn host_value(header: NonNull<u8>) -> String {
        // SAFETY: the test passes the start of a live `Host`.
        let host = unsafe { header.cast::<Host>().as_ref() };
        format!("host {}", host.payload)
    }

    #[test]
    fn a_lazy_node_makes_its_value_when_taken_out() {
        let mut host = Host {
            header: [0; 3],
            payload: 7,
        };
        let header = NonNull::from(&mut host).cast::<u8>();
        let node = OwnedSignal::lazy(header, 5, host_value);
        assert!(node.is_lazy());
        assert_eq!(node.lazy_meta(), Some(5));
        assert_eq!(node.into_value(), "host 7");
    }

    #[test]
    fn a_lazy_node_read_in_place_is_replaced_by_an_allocated_one() {
        let mut host = Host {
            header: [0; 3],
            payload: 9,
        };
        let header = NonNull::from(&mut host).cast::<u8>();
        let mut node = OwnedSignal::lazy(header, 5, host_value);
        assert_eq!(node.as_str(), "host 9");
        assert!(!node.is_lazy());
        node.push('!');
        assert_eq!(node.into_value(), "host 9!");
        let dropped = OwnedSignal::lazy(header, 5, host_value);
        drop(dropped);
    }

    #[test]
    fn a_fragment_that_is_full_refuses_more_words() {
        let mut node = OwnedSignal::with_heap_fragment((), 2);
        let mut fragment = node.heap_fragment().expect("inline fragment");
        assert!(fragment.alloc(2).is_some());
        assert!(fragment.alloc(1).is_none());
        assert_eq!(fragment.used(), 2);
    }

    #[test]
    fn an_unused_combined_fragment_releases_its_msg_block() {
        let node = OwnedSignal::with_heap_fragment((), 3);
        let (value, fragment) = node.split_fragment();
        assert_eq!(value, ());
        assert!(fragment.is_none());
        let replacement = OwnedSignal::new(value);
        assert!(replacement.fragment_words().is_none());
    }
}
