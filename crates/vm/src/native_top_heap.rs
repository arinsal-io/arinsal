//! A [`HeapAlloc`] that bumps `c_p->htop` in the native process header.
//!
//! The generated code keeps one heap top, `c_p->htop`, and `erts_maps_put` allocates on it with
//! `HAllocX`. The word-index copy that [`ProcessHeap`] keeps is only needed when a helper takes a
//! heap fragment or runs code that reads the index, so it is brought up to date on those paths
//! alone.

use crate::Process;
use arinsal_beamasm::ProcessHeader;
use arinsal_bifs::ProcessHeapHandle;
use arinsal_term::{
    ExportEntry, ExternalBinary, FunEntry, HeapAlloc, MagicRef, Node, OwnedBinaryRef, RefcBinary,
    S_REDZONE, Term, TermError, WritableBinary,
};
use std::sync::Arc;

/// `HAllocX` on the native heap top; every other operation goes through the [`ProcessHeap`].
// Port of erts/emulator/beam/erl_vm.h:150-173 (HAllocX, HRelease) and
// erts/emulator/beam/erl_process.h:990-998 (HEAP_LIMIT), OTP-29.1.1.
pub(crate) struct NativeTopHeap<'a> {
    header: &'a mut ProcessHeader,
    heap: ProcessHeapHandle<'a>,
    base: *mut u64,
}

impl<'a> NativeTopHeap<'a> {
    /// Borrows the process for a native allocation, or `None` when its heap top has to be
    /// read from the [`ProcessHeap`] (no published heap, or allocations redirected elsewhere).
    #[inline(always)]
    pub(crate) fn new(process: &'a mut Process) -> Option<Self> {
        let header = &mut process.header;
        if header.heap.is_null()
            || header.htop.is_null()
            || header.stop.is_null()
            || process.heap.is_detached()
        {
            return None;
        }
        let base = header.heap;
        Some(Self {
            header,
            heap: ProcessHeapHandle(&mut process.heap),
            base,
        })
    }

    #[inline(always)]
    fn top_alloc(&mut self, words: usize) -> Option<*mut u64> {
        let htop = self.header.htop;
        let limit = (self.header.stop as usize)
            .saturating_sub(S_REDZONE * 8)
            .max(htop as usize);
        if words > (limit - htop as usize) >> 3 {
            return None;
        }
        self.header.htop = htop.wrapping_add(words);
        Some(htop)
    }

    /// Hands the native cursors to the [`ProcessHeap`] and returns it.
    #[inline(always)]
    fn slow(&mut self) -> &mut ProcessHeapHandle<'a> {
        self.heap
            .0
            .set_native_cursors_at(self.base, self.header.htop, self.header.stop);
        &mut self.heap
    }

    /// Allocate a heap fragment after the native `HAllocX` test fails.
    // Port of erts/emulator/beam/erl_vm.h (HAllocX) and utils.c
    // (erts_heap_alloc), OTP-29.1.1.
    #[cold]
    #[inline(never)]
    fn alloc_slow(&mut self, words: usize) -> Option<*mut u64> {
        Some(self.slow().0.heap_fragment(words))
    }

    /// Allocate an extended heap fragment after the native `HAllocX` test fails.
    // Port of erts/emulator/beam/erl_vm.h (HAllocX) and utils.c
    // (erts_heap_alloc), OTP-29.1.1.
    #[cold]
    #[inline(never)]
    fn alloc_with_extra_slow(&mut self, words: usize, extra: usize) -> Option<*mut u64> {
        Some(self.slow().0.heap_fragment_with_extra(words, extra))
    }

    #[cold]
    #[inline(never)]
    fn release_slow(&mut self, end: *mut u64, start: *mut u64) {
        self.slow().release(end, start);
    }

    /// Publishes the native cursors to the [`ProcessHeap`] after the allocator is dropped.
    #[cold]
    #[inline(never)]
    pub(crate) fn commit(mut self) {
        self.slow();
    }
}

impl HeapAlloc for NativeTopHeap<'_> {
    #[inline(always)]
    fn words_left(&self) -> Option<usize> {
        let htop = self.header.htop as usize;
        let limit = (self.header.stop as usize)
            .saturating_sub(S_REDZONE * 8)
            .max(htop);
        Some((limit - htop) / 8)
    }
    #[inline(always)]
    fn alloc(&mut self, words: usize) -> Option<*mut u64> {
        if let Some(ptr) = self.top_alloc(words) {
            return Some(ptr);
        }
        self.alloc_slow(words)
    }
    #[inline(always)]
    fn alloc_with_extra(&mut self, words: usize, extra: usize) -> Option<*mut u64> {
        if let Some(ptr) = self.top_alloc(words) {
            return Some(ptr);
        }
        self.alloc_with_extra_slow(words, extra)
    }
    fn alloc_fragment_only(&mut self, words: usize) -> Option<*mut u64> {
        self.slow().alloc_fragment_only(words)
    }
    #[inline(always)]
    fn release_needs_filler(&self, end: *mut u64, start: *mut u64) -> bool {
        if start == end {
            return false;
        }
        let top = self.header.htop;
        !(start >= self.base && start < top && end == top)
    }
    #[inline(always)]
    fn release(&mut self, end: *mut u64, start: *mut u64) {
        let top = self.header.htop;
        if start >= self.base && start < top && end == top {
            self.header.htop = start;
            return;
        }
        self.release_slow(end, start);
    }
    fn retain_binary(&mut self, binary: Arc<RefcBinary>) {
        self.slow().retain_binary(binary)
    }
    fn link_bin_ref(
        &mut self,
        bin_ref: *mut u64,
        writable: bool,
        overhead_words: u64,
        owner: Option<OwnedBinaryRef>,
    ) -> Result<(), TermError> {
        self.slow()
            .link_bin_ref(bin_ref, writable, overhead_words, owner)
    }
    fn add_bin_vheap(&mut self, words: u64) {
        self.slow().add_bin_vheap(words)
    }
    fn retain_writable_binary(&mut self, binary: Arc<WritableBinary>) -> Result<(), TermError> {
        self.slow().retain_writable_binary(binary)
    }
    fn retain_writable_binary_with_apparent_size(
        &mut self,
        binary: Arc<WritableBinary>,
        apparent_size_bits: usize,
    ) -> Result<(), TermError> {
        self.slow()
            .retain_writable_binary_with_apparent_size(binary, apparent_size_bits)
    }
    fn update_writable_binary_overhead(
        &mut self,
        source: Term,
        old_size_bits: usize,
        new_size_bits: usize,
    ) {
        self.slow()
            .update_writable_binary_overhead(source, old_size_bits, new_size_bits)
    }
    fn update_writable_binary_overhead_at(
        &mut self,
        source: Term,
        bin_ref: usize,
        old_size_bits: usize,
        new_size_bits: usize,
    ) {
        self.slow().update_writable_binary_overhead_at(
            source,
            bin_ref,
            old_size_bits,
            new_size_bits,
        )
    }
    fn supports_writable_binary(&self) -> bool {
        self.heap.supports_writable_binary()
    }
    fn link_external_binary(
        &mut self,
        bin_ref: *mut u64,
        binary: Arc<ExternalBinary>,
    ) -> Result<(), TermError> {
        self.slow().link_external_binary(bin_ref, binary)
    }
    fn supports_external_binary(&self) -> bool {
        self.heap.supports_external_binary()
    }
    fn link_node(&mut self, thing: *mut u64, node: Arc<Node>) {
        self.slow().link_node(thing, node)
    }
    fn retain_fun(&mut self, entry: Arc<FunEntry>) {
        self.slow().retain_fun(entry)
    }
    fn retain_export(&mut self, entry: Arc<ExportEntry>) {
        self.slow().retain_export(entry)
    }
    fn link_magic_ref(&mut self, thing: *mut u64, owner: Arc<MagicRef>) -> Result<(), TermError> {
        self.slow().link_magic_ref(thing, owner)
    }
    fn supports_magic(&self) -> bool {
        self.heap.supports_magic()
    }
}
