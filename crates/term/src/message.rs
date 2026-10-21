//! Signal and message nodes: one allocation per queued signal, which for a message also holds
//! the heap fragment of its data.
//!
//! Port of erts/emulator/beam/erl_message.h/.c (`ErtsMessage` with `ErlHeapFragment hfrag`
//! inline, `erts_alloc_message`, `ERTS_MSG_COMBINED_HFRAG`, `erts_free_message`,
//! `erts_save_message_in_proc`, `erts_cleanup_messages`), OTP-29.1.1. The queue links (`next`)
//! are used by the scheduler's signal queues; this module owns the allocation and release of
//! nodes and of their inline fragments. All raw work on node memory is confined here.

use std::alloc::Layout;
use std::marker::PhantomData;
use std::ptr::NonNull;
use std::sync::Arc;

use crate::bits::{ExternalBinary, RefcBinary, WritableBinary};
use crate::heap::{
    HeapAlloc, LazyOwners, link_external_bin_ref, link_magic_thing, link_node_thing,
};
use crate::{Node, Term, TermError};

/// One signal (`ErtsSignalCommon`): the queue link, then the signal value. A message node may
/// be followed in the same allocation by a heap fragment (`ERTS_MSG_COMBINED_HFRAG`).
#[repr(C)]
pub struct SignalNode<T> {
    /// The next node of the queue holding this one (`next`).
    pub next: Option<NonNull<SignalNode<T>>>,
    /// Words of the inline heap fragment (`hfrag.alloc_size`), 0 for a node without one.
    fragment_words: usize,
    /// The signal.
    pub value: T,
}

/// erts `ErlHeapFragment`, inline after a message node: the off-heap objects of its data
/// (`off_heap`), `alloc_size`, `used_size`, then the words (`mem`).
#[repr(C)]
pub(crate) struct HeapFragment {
    pub(crate) owners: LazyOwners,
    pub(crate) bin_vheap: u64,
    alloc_size: usize,
    used_size: usize,
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
    node: NonNull<SignalNode<T>>,
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
        // SAFETY: the layout has a nonzero size (it holds at least the `next` link).
        let raw = unsafe { std::alloc::alloc(layout) }.cast::<SignalNode<T>>();
        let Some(node) = NonNull::new(raw) else {
            std::alloc::handle_alloc_error(layout);
        };
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
                        owners: LazyOwners::default(),
                        bin_vheap: 0,
                        alloc_size: words,
                        used_size: 0,
                    });
            }
        }
        Self {
            node,
            _value: PhantomData,
        }
    }

    fn header(&self) -> Option<NonNull<HeapFragment>> {
        // SAFETY: the handle owns the node; the header sits where `node_layout` put it.
        unsafe {
            let words = (*self.node.as_ptr()).fragment_words;
            if words == 0 {
                return None;
            }
            let (_, offset) = node_layout::<T>(words);
            Some(NonNull::new_unchecked(
                self.node.as_ptr().cast::<u8>().add(offset).cast(),
            ))
        }
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
        // either moves to the returned fragment or is released here.
        unsafe {
            let value = std::ptr::addr_of!((*node.as_ptr()).value).read();
            let words = (*node.as_ptr()).fragment_words;
            let (layout, _) = node_layout::<T>(words);
            match header {
                Some(header) => (
                    value,
                    Some(NodeFragment {
                        memory: node.cast(),
                        layout,
                        header,
                    }),
                ),
                None => {
                    std::alloc::dealloc(node.as_ptr().cast(), layout);
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
        let node = self.node;
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
            node,
            _value: PhantomData,
        }
    }
}

impl<T> std::ops::Deref for OwnedSignal<T> {
    type Target = T;

    fn deref(&self) -> &T {
        // SAFETY: the handle owns the node, so it is live and not borrowed elsewhere.
        unsafe { &(*self.node.as_ptr()).value }
    }
}

impl<T> std::ops::DerefMut for OwnedSignal<T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: as in `deref`, and the handle is borrowed exclusively.
        unsafe { &mut (*self.node.as_ptr()).value }
    }
}

impl<T> Drop for OwnedSignal<T> {
    /// `erts_cleanup_messages` of one node: drop the signal and its fragment, then free it.
    fn drop(&mut self) {
        let header = self.header();
        // SAFETY: the handle owns the node; the value is dropped once, and the memory is
        // released by the fragment or here.
        unsafe {
            std::ptr::drop_in_place(std::ptr::addr_of_mut!((*self.node.as_ptr()).value));
            let words = (*self.node.as_ptr()).fragment_words;
            let (layout, _) = node_layout::<T>(words);
            if let Some(header) = header {
                drop(NodeFragment {
                    memory: self.node.cast(),
                    layout,
                    header,
                });
            } else {
                std::alloc::dealloc(self.node.as_ptr().cast(), layout);
            }
        }
    }
}

/// The inline heap fragment of a message node whose signal is gone: kept with its node memory
/// while the data is in use (a received message on the process's fragment list).
pub struct NodeFragment {
    memory: NonNull<u8>,
    layout: Layout,
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
    pub(crate) fn take_owners(&mut self) -> (LazyOwners, u64) {
        // SAFETY: the fragment owns its header exclusively.
        unsafe {
            let header = &mut *self.header.as_ptr();
            (
                std::mem::take(&mut header.owners),
                std::mem::take(&mut header.bin_vheap),
            )
        }
    }

    /// The off-heap owners, for rebasing their chain after the words moved.
    pub(crate) fn owners_mut(&mut self) -> &mut LazyOwners {
        // SAFETY: the fragment owns its header exclusively.
        unsafe { &mut (*self.header.as_ptr()).owners }
    }
}

impl Drop for NodeFragment {
    fn drop(&mut self) {
        // SAFETY: the fragment owns the header and the node memory, laid out by `layout`.
        unsafe {
            std::ptr::drop_in_place(self.header.as_ptr());
            std::alloc::dealloc(self.memory.as_ptr(), self.layout);
        }
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
        let owners = &mut *self.fragment().owners;
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
        let owners = &mut *self.fragment().owners;
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
        link_external_bin_ref(&mut self.fragment().owners.off_heap_first, bin_ref, binary);
        Ok(())
    }

    fn supports_external_binary(&self) -> bool {
        true
    }

    fn link_node(&mut self, thing: *mut u64, node: Arc<Node>) {
        link_node_thing(&mut self.fragment().owners.off_heap_first, thing, node);
    }

    fn link_magic_ref(
        &mut self,
        thing: *mut u64,
        owner: Arc<crate::MagicRef>,
    ) -> Result<(), TermError> {
        let owners = &mut *self.fragment().owners;
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
    Heap(crate::ProcessHeap),
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
            Self::Heap(heap) => heap.message_data_size(),
            Self::Node(fragment) => fragment.len(),
        }
    }

    /// Words a literal-area check inspects.
    pub fn literal_scan_words(&self) -> usize {
        match self {
            Self::Heap(heap) => heap.literal_scan_words(),
            Self::Node(fragment) => fragment.len(),
        }
    }

    /// Whether the data holds a direct pointer that `is_area_pointer` accepts.
    pub fn has_heap_reference(&self, is_area_pointer: impl FnMut(Term) -> bool) -> bool {
        match self {
            Self::Heap(heap) => heap.has_heap_reference(is_area_pointer),
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

    #[test]
    fn a_fragment_that_is_full_refuses_more_words() {
        let mut node = OwnedSignal::with_heap_fragment((), 2);
        let mut fragment = node.heap_fragment().expect("inline fragment");
        assert!(fragment.alloc(2).is_some());
        assert!(fragment.alloc(1).is_none());
        assert_eq!(fragment.used(), 2);
    }
}
