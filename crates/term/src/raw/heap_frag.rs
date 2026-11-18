// Port of erts/emulator/beam/erl_message.h:72-78 (ErlHeapFragment, ERTS_HEAP_FRAG_SIZE,
// ERTS_INIT_HEAP_FRAG) and erl_message.c (new_message_buffer, free_message_buffer), OTP-29.1.1.
//
//! The process heap fragment (`ErlHeapFragment`): one `ERTS_ALC_T_HEAP_FRAG` block holding the
//! `next` link of the `c_p->mbuf` list, the fragment's off-heap list, `alloc_size`,
//! `used_size` and then the words (`mem`). All `unsafe` for heap fragment headers lives here;
//! the rest of the crate holds a [`HeapFrag`] and calls its safe accessors.

use std::alloc::{Layout, handle_alloc_error};
use std::ptr::NonNull;

/// erts `ErlOffHeap` of a heap fragment: the head of the off-heap list of the objects in
/// `mem` and their virtual binary heap overhead.
// Port of erts/emulator/beam/erl_term.h (ErlOffHeap), OTP-29.1.1.
#[repr(C)]
#[derive(Default)]
pub(crate) struct ErlOffHeap {
    pub(crate) first: usize,
    pub(crate) overhead: u64,
}

/// erts `ErlHeapFragment`. The words follow the header in the same block.
#[repr(C)]
pub struct ErlHeapFragment {
    /// Next fragment of the list (`next`), null at its end.
    next: *mut ErlHeapFragment,
    /// Off-heap objects of the words (`off_heap`).
    off_heap: ErlOffHeap,
    /// Words allocated after the header (`alloc_size`).
    alloc_size: usize,
    /// Words in use (`used_size`).
    used_size: usize,
    mem: [u64; 0],
}

/// `offsetof(ErlHeapFragment, mem)`.
pub(crate) const HEAP_FRAG_MEM_OFFSET: usize = std::mem::offset_of!(ErlHeapFragment, mem);
const _: () = assert!(HEAP_FRAG_MEM_OFFSET == std::mem::size_of::<ErlHeapFragment>());

const NEXT: usize = std::mem::offset_of!(ErlHeapFragment, next);
const OFF_HEAP_FIRST: usize =
    std::mem::offset_of!(ErlHeapFragment, off_heap) + std::mem::offset_of!(ErlOffHeap, first);
const OFF_HEAP_OVERHEAD: usize =
    std::mem::offset_of!(ErlHeapFragment, off_heap) + std::mem::offset_of!(ErlOffHeap, overhead);
const ALLOC_SIZE: usize = std::mem::offset_of!(ErlHeapFragment, alloc_size);
const USED_SIZE: usize = std::mem::offset_of!(ErlHeapFragment, used_size);

/// `ERTS_INVALID_HFRAG_PTR` (erl_gc.h): `((ErlHeapFragment *) ~((UWord) 7))`, the value of
/// `live_hf_end` that names no fragment, as an address.
pub(crate) const INVALID_HFRAG_PTR: usize = !7;

/// One live heap fragment. The handle does not own the block: the list it is on does, and
/// [`free_message_buffer`] frees it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub(crate) struct HeapFrag(NonNull<ErlHeapFragment>);

impl HeapFrag {
    /// The fragment at `ptr`, `None` for null.
    ///
    /// Contract: a non-null `ptr` is a live fragment of [`HeapFrag::new_message_buffer`].
    #[inline(always)]
    pub(crate) fn from_ptr(ptr: *mut ErlHeapFragment) -> Option<Self> {
        NonNull::new(ptr).map(Self)
    }

    /// The fragment whose words start at `mem`.
    ///
    /// Contract: `mem` is the `mem` of a live fragment.
    #[inline(always)]
    pub(crate) fn from_mem(mem: *mut u64) -> Self {
        let header = mem
            .cast::<u8>()
            .wrapping_sub(HEAP_FRAG_MEM_OFFSET)
            .cast::<ErlHeapFragment>();
        Self(NonNull::new(header).expect("heap fragment words follow a header"))
    }

    /// `new_message_buffer(size)` with `used_size` set to `used` (`ERTS_INIT_HEAP_FRAG`): an
    /// `ERTS_ALC_T_HEAP_FRAG` block of `ERTS_HEAP_FRAG_SIZE(size)` bytes, unlinked, with an
    /// empty off-heap list. The words are not initialized.
    // Port of erts/emulator/beam/erl_message.c:69 (new_message_buffer) and
    // erl_message.h (ERTS_INIT_HEAP_FRAG), OTP-29.1.1.
    pub(crate) fn new_message_buffer(size: usize, used: usize) -> Self {
        debug_assert!(used <= size);
        let layout = Layout::new::<ErlHeapFragment>()
            .extend(Layout::array::<u64>(size).expect("heap fragment size fits"))
            .expect("heap fragment size fits")
            .0
            .pad_to_align();
        let Ok(block) = arinsal_alloc::typed::heap_frag_alloc(layout.size()) else {
            handle_alloc_error(layout)
        };
        let frag = Self(block.cast::<ErlHeapFragment>());
        // `ERTS_INIT_HEAP_FRAG`: the fresh block is the caller's alone.
        frag.store(NEXT, 0);
        frag.store(OFF_HEAP_FIRST, 0);
        frag.store(OFF_HEAP_OVERHEAD, 0);
        frag.store(ALLOC_SIZE, size as u64);
        frag.store(USED_SIZE, used as u64);
        frag
    }

    /// The header word at byte offset `field`; the handle names a live fragment.
    #[inline(always)]
    fn load(self, field: usize) -> u64 {
        crate::raw::load(self.0.as_ptr() as usize + field)
    }

    /// Writes the header word at byte offset `field`; the list owner is the caller.
    #[inline(always)]
    fn store(self, field: usize, value: u64) {
        crate::raw::store(self.0.as_ptr() as usize + field, value);
    }

    #[inline(always)]
    pub(crate) fn as_ptr(self) -> *mut ErlHeapFragment {
        self.0.as_ptr()
    }

    /// `bp->mem`.
    #[inline(always)]
    pub(crate) fn mem(self) -> *mut u64 {
        self.0
            .as_ptr()
            .cast::<u8>()
            .wrapping_add(HEAP_FRAG_MEM_OFFSET)
            .cast::<u64>()
    }

    /// `bp->next`.
    #[inline(always)]
    pub(crate) fn next(self) -> *mut ErlHeapFragment {
        self.load(NEXT) as *mut ErlHeapFragment
    }

    #[inline(always)]
    pub(crate) fn set_next(self, next: *mut ErlHeapFragment) {
        self.store(NEXT, next as u64);
    }

    /// `bp->alloc_size`.
    #[inline(always)]
    pub(crate) fn alloc_size(self) -> usize {
        self.load(ALLOC_SIZE) as usize
    }

    /// `bp->used_size`.
    #[inline(always)]
    pub(crate) fn used_size(self) -> usize {
        self.load(USED_SIZE) as usize
    }

    #[inline(always)]
    pub(crate) fn set_used_size(self, used: usize) {
        debug_assert!(used <= self.alloc_size());
        self.store(USED_SIZE, used as u64);
    }

    /// The `alloc_size` words of the fragment.
    ///
    /// Contract: the caller holds the list the fragment is on exclusively for `'a`.
    #[inline]
    pub(crate) fn words_mut<'a>(self) -> &'a mut [u64] {
        // SAFETY: the block holds `alloc_size` words after the header, owned by the caller.
        unsafe { std::slice::from_raw_parts_mut(self.mem(), self.alloc_size()) }
    }

    /// The `alloc_size` words of the fragment.
    ///
    /// Contract: the fragment stays live for `'a`.
    #[inline]
    pub(crate) fn words<'a>(self) -> &'a [u64] {
        // SAFETY: the block holds `alloc_size` words after the header.
        unsafe { std::slice::from_raw_parts(self.mem(), self.alloc_size()) }
    }

    /// Whether the fragment has off-heap objects of its own (`bp->off_heap.first`).
    #[inline]
    pub(crate) fn has_off_heap(self) -> bool {
        self.load(OFF_HEAP_FIRST) != 0
    }
}

/// Iterator over a fragment list from its head along `next`.
pub(crate) struct HeapFragIter(*mut ErlHeapFragment);

impl Iterator for HeapFragIter {
    type Item = HeapFrag;

    #[inline]
    fn next(&mut self) -> Option<HeapFrag> {
        let frag = HeapFrag::from_ptr(self.0)?;
        self.0 = frag.next();
        Some(frag)
    }
}

/// The fragments of the list starting at `head`, newest first.
///
/// Contract: `head` is null or a live list that does not change during the walk.
#[inline]
pub(crate) fn iter(head: *mut ErlHeapFragment) -> HeapFragIter {
    HeapFragIter(head)
}

/// `free_message_buffer(bp)`: free every fragment of the list starting at `bp`, with the
/// off-heap objects of each (`erts_cleanup_offheap(&bp->off_heap)`).
///
/// Contract: `bp` is the head of a list nothing else refers to any more.
// Port of erts/emulator/beam/erl_message.c:195 (free_message_buffer), OTP-29.1.1.
pub(crate) fn free_message_buffer(bp: HeapFrag) {
    let mut bp = Some(bp);
    while let Some(frag) = bp {
        bp = HeapFrag::from_ptr(frag.next());
        crate::gc::release_off_heap_chain(frag.load(OFF_HEAP_FIRST) as usize);
        arinsal_alloc::typed::heap_frag_free(frag.0.cast());
    }
}

/// The head of the `c_p->mbuf` list, which owns its fragments: dropping it frees them.
#[repr(transparent)]
pub struct MbufList(*mut ErlHeapFragment);

impl MbufList {
    /// `NULL`.
    pub(crate) const EMPTY: Self = Self(std::ptr::null_mut());

    /// `c_p->mbuf`.
    #[inline(always)]
    pub(crate) fn head(&self) -> Option<HeapFrag> {
        HeapFrag::from_ptr(self.0)
    }

    #[inline(always)]
    pub(crate) fn as_ptr(&self) -> *mut ErlHeapFragment {
        self.0
    }

    #[inline(always)]
    pub(crate) fn is_empty(&self) -> bool {
        self.0.is_null()
    }

    /// `bp->next = MBUF(p); MBUF(p) = bp;`.
    #[inline(always)]
    pub(crate) fn push(&mut self, bp: HeapFrag) {
        bp.set_next(self.0);
        self.0 = bp.as_ptr();
    }

    /// Take the whole list, leaving `NULL`.
    #[inline(always)]
    pub(crate) fn take(&mut self) -> Self {
        Self(std::mem::replace(&mut self.0, std::ptr::null_mut()))
    }

    /// Splice `other` in front of this list (erts_flush_dirty_shadow_proc).
    pub(crate) fn prepend(&mut self, mut other: Self) {
        let Some(first) = HeapFrag::from_ptr(other.0) else {
            return;
        };
        let mut last = first;
        while let Some(next) = HeapFrag::from_ptr(last.next()) {
            last = next;
        }
        last.set_next(self.0);
        self.0 = std::mem::replace(&mut other.0, std::ptr::null_mut());
    }

    /// Free the fragments from the head up to `keep` (not included), which becomes the head:
    /// the rollback of `erts_factory_undo`.
    pub(crate) fn free_until(&mut self, keep: *mut ErlHeapFragment) {
        while self.0 != keep {
            let Some(frag) = HeapFrag::from_ptr(self.0) else {
                return;
            };
            self.0 = frag.next();
            frag.set_next(std::ptr::null_mut());
            free_message_buffer(frag);
        }
    }

    /// The fragments, newest first.
    #[inline]
    pub(crate) fn iter(&self) -> HeapFragIter {
        iter(self.0)
    }
}

impl Default for MbufList {
    fn default() -> Self {
        Self::EMPTY
    }
}

impl Drop for MbufList {
    fn drop(&mut self) {
        if let Some(head) = self.head() {
            free_message_buffer(head);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_message_buffer_initializes_the_header() {
        let bp = HeapFrag::new_message_buffer(10, 4);
        assert_eq!(bp.alloc_size(), 10);
        assert_eq!(bp.used_size(), 4);
        assert!(bp.next().is_null());
        assert!(!bp.has_off_heap());
        assert_eq!(HeapFrag::from_mem(bp.mem()), bp);
        assert_eq!(
            bp.mem() as usize - bp.as_ptr() as usize,
            HEAP_FRAG_MEM_OFFSET
        );
        free_message_buffer(bp);
    }

    #[test]
    fn list_links_newest_first_and_frees_up_to_a_kept_fragment() {
        let mut list = MbufList::EMPTY;
        let a = HeapFrag::new_message_buffer(4, 1);
        let b = HeapFrag::new_message_buffer(4, 2);
        let c = HeapFrag::new_message_buffer(4, 3);
        list.push(a);
        list.push(b);
        list.push(c);
        let used: Vec<usize> = list.iter().map(HeapFrag::used_size).collect();
        assert_eq!(used, [3, 2, 1]);
        list.free_until(a.as_ptr());
        assert_eq!(list.head(), Some(a));
        assert_eq!(list.iter().count(), 1);

        let mut other = MbufList::EMPTY;
        other.push(HeapFrag::new_message_buffer(2, 2));
        other.push(HeapFrag::new_message_buffer(2, 1));
        list.prepend(other);
        let used: Vec<usize> = list.iter().map(HeapFrag::used_size).collect();
        assert_eq!(used, [1, 2, 1]);
        drop(list);
    }

    #[test]
    fn invalid_hfrag_ptr_is_erts_value() {
        assert_eq!(INVALID_HFRAG_PTR, usize::MAX - 7);
    }
}
