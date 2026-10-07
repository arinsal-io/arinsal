//! Per-process copying collection with a young heap and an old heap.
//!
//! The high-water mark is the young heap top after collection. At the next
//! minor collection, reachable objects below it move to the old heap. A full
//! sweep copies both heaps into a new young heap. Stack frame pointers into the
//! current stack block are rebased; code pointers and CATCH words remain intact.

use crate::VecHeap;
use crate::bits::{binary_data, writable_gc_visit};
use crate::hamt::{boxed_object_words, boxed_term_range};
use crate::{
    ARITY, BIN_REF, EXTERNAL_PID, EXTERNAL_PORT, EXTERNAL_REF, ExportEntry, ExternalBinary, FUN,
    FunEntry, HEAP_BITS, HeapAlloc, MAGIC_REF, MAP, MagicRef, Node, ProcessHeap, RECORD,
    S_RESERVED, SUB_BITS, StackWord, Term, TermError, WritableBinary,
};
use std::sync::Arc;
use std::sync::OnceLock;
use std::time::Instant;

/// Counters for one collection. The caller may add them to process totals.
#[derive(Clone, Copy, Debug, Default)]
pub struct GcStats {
    /// Number of collections.
    pub collections: u64,
    /// Number of minor collections.
    pub minor_collections: u64,
    /// Number of full sweeps.
    pub major_collections: u64,
    /// Words copied into the young heap.
    pub words_copied: u64,
    /// Words promoted into the old heap.
    pub words_promoted: u64,
    /// Words reclaimed from the collected young generation, or both generations on a full sweep.
    pub words_reclaimed: u64,
    /// Time spent in collection, in nanoseconds.
    pub nanoseconds: u64,
}

/// Heap allocator that places every object in the process's message-buffer fragments.
pub struct FragmentAlloc<'a>(&'a mut ProcessHeap);

impl<'a> FragmentAlloc<'a> {
    /// Allocate objects into detached fragments owned by `heap` until its next collection.
    pub fn new(heap: &'a mut ProcessHeap) -> Self {
        Self(heap)
    }
}

impl HeapAlloc for FragmentAlloc<'_> {
    fn alloc(&mut self, words: usize) -> Option<*mut u64> {
        Some(self.0.gc_fragment(words))
    }
    fn retain_binary(&mut self, binary: Arc<Vec<u8>>) {
        HeapAlloc::retain_binary(self.0, binary);
    }
    fn retain_writable_binary(&mut self, binary: Arc<WritableBinary>) -> Result<(), TermError> {
        HeapAlloc::retain_writable_binary(self.0, binary)
    }
    fn supports_writable_binary(&self) -> bool {
        true
    }
    fn retain_external_binary(&mut self, binary: Arc<ExternalBinary>) -> Result<(), TermError> {
        HeapAlloc::retain_external_binary(self.0, binary)
    }
    fn supports_external_binary(&self) -> bool {
        true
    }
    fn retain_node(&mut self, node: Arc<Node>) {
        HeapAlloc::retain_node(self.0, node);
    }
    fn retain_fun(&mut self, entry: Arc<FunEntry>) {
        HeapAlloc::retain_fun(self.0, entry);
    }
    fn retain_export(&mut self, entry: Arc<ExportEntry>) {
        HeapAlloc::retain_export(self.0, entry);
    }
    fn retain_magic(&mut self, owner: Arc<MagicRef>) {
        HeapAlloc::retain_magic(self.0, owner);
    }
    fn supports_magic(&self) -> bool {
        true
    }
}

struct Copier<'a> {
    from: &'a mut ProcessHeap,
    to: &'a mut ProcessHeap,
    major: bool,
    young_scan: usize,
    old_scan: usize,
    fragment_ranges: Vec<(usize, usize)>,
    young_words: usize,
    promoted_words: usize,
    sub_bits: Vec<Term>,
    writable_refs: Vec<Term>,
    error: Option<TermError>,
}

impl Copier<'_> {
    #[inline]
    fn copy(&mut self, term: Term) -> Term {
        let tag = term.0 & 3;
        if tag != 1 && tag != 2 {
            return term;
        }
        let address = (term.0 & !7) as usize;
        let young_start = self.from.words.as_ptr() as usize;
        let young_end = young_start + self.from.htop * 8;
        let in_young = address >= young_start && address < young_end;
        if !in_young {
            let in_old = if self.major {
                let start = self.from.old_words.as_ptr() as usize;
                address >= start && address < start + self.from.old_htop * 8
            } else {
                false
            };
            if !in_old && !self.fragment_contains(address) {
                return term;
            }
        }

        let promote = !self.major && in_young && address < young_start + self.from.high_water * 8;
        // SAFETY: The source is in an owned, live heap or fragment. Collection
        // has exclusive process access, and source and destination do not overlap.
        unsafe {
            let source = term.raw_ptr().cast_mut();
            let first = *source;
            if tag == 1 {
                if first == 0 {
                    return Term(*source.add(1));
                }
            } else if first & 3 == 2 {
                return Term(first);
            }
            let words = if tag == 1 {
                2
            } else if first & 63 == ARITY || first & 63 == RECORD {
                1 + (first >> 6) as usize
            } else {
                boxed_object_words(first, source)
            };
            let destination = if promote {
                let top = self.to.old_htop;
                if words > self.to.old_words.len().saturating_sub(top) {
                    self.error = Some(TermError::HeapFull);
                    return term;
                }
                self.to.old_htop += words;
                self.promoted_words += words;
                self.to.old_words.as_ptr().add(top).cast::<u64>().cast_mut()
            } else {
                let top = self.to.htop;
                if words > self.to.stop.saturating_sub(top) {
                    self.error = Some(TermError::HeapFull);
                    return term;
                }
                self.to.htop += words;
                self.young_words += words;
                self.to.words.as_ptr().add(top).cast::<u64>().cast_mut()
            };
            std::ptr::copy_nonoverlapping(source, destination, words);
            let moved = Term::from_ptr(destination, tag);
            // Port of erts/emulator/beam/erl_gc.c:1639 (do_minor), OTP-29.1.1.
            // A boxed header cannot have the boxed pointer tag. Zero cannot be
            // a valid cons head, so its second word can hold the forwarding term.
            if tag == 1 {
                *source = 0;
                *source.add(1) = moved.0;
            } else {
                *source = moved.0;
                if matches!(
                    first & 63,
                    BIN_REF
                        | EXTERNAL_PID
                        | EXTERNAL_PORT
                        | EXTERNAL_REF
                        | FUN
                        | SUB_BITS
                        | MAGIC_REF
                ) {
                    self.retain_owner(first, destination, moved, promote);
                }
            }
            moved
        }
    }

    #[inline]
    fn fragment_contains(&self, address: usize) -> bool {
        let index = self
            .fragment_ranges
            .partition_point(|&(_, end)| end <= address);
        self.fragment_ranges
            .get(index)
            .is_some_and(|&(start, end)| start <= address && address < end)
    }

    fn retain_owner(&mut self, header: u64, ptr: *mut u64, term: Term, promote: bool) {
        // SAFETY: `ptr` is a complete copied object with the owner field in word one.
        let key = unsafe { *ptr.add(1) } as usize;
        match header & 63 {
            BIN_REF => {
                // SAFETY: BinRef word two contains its writable flag.
                let flags = unsafe { *ptr.add(2) };
                if flags & 0x100 != 0 {
                    let target = if promote {
                        &mut self.to.owners.old_external
                    } else {
                        &mut self.to.owners.external
                    };
                    if !target.iter().any(|arc| Arc::as_ptr(arc) as usize == key) {
                        let owner = self
                            .from
                            .owners
                            .external
                            .iter()
                            .chain(&self.from.owners.old_external)
                            .find(|arc| Arc::as_ptr(arc) as usize == key)
                            .cloned();
                        if let Some(owner) = owner {
                            self.to.off_heap_binary_bytes = self
                                .to
                                .off_heap_binary_bytes
                                .saturating_add(owner.len() as u64);
                            let vheap_words = (owner.len() / 8) as u64;
                            target.push(owner);
                            self.to.add_vheap(promote, vheap_words);
                        } else {
                            self.error = Some(TermError::BadArg);
                        }
                    }
                } else if flags & 1 != 0 {
                    let target = if promote {
                        &mut self.to.owners.old_writable
                    } else {
                        &mut self.to.owners.writable
                    };
                    if !target.iter().any(|arc| Arc::as_ptr(arc) as usize == key) {
                        let owner = self
                            .from
                            .owners
                            .writable
                            .iter()
                            .chain(&self.from.owners.old_writable)
                            .find(|arc| Arc::as_ptr(arc) as usize == key)
                            .cloned();
                        if let Some(owner) = owner {
                            let capacity = owner.capacity();
                            target.push(owner);
                            let vheap_words = (capacity / 8) as u64;
                            self.to.add_vheap(promote, vheap_words);
                            if promote {
                                self.to.owners.old_writable_refs.push(term);
                            } else {
                                self.writable_refs.push(term);
                            }
                        } else {
                            self.error = Some(TermError::BadArg);
                        }
                    }
                } else {
                    let target = if promote {
                        &mut self.to.owners.old_off_heap
                    } else {
                        &mut self.to.owners.off_heap
                    };
                    // erts keeps one ProcBin per reference in the MSO list (sweep_off_heap),
                    // so refc binaries are not deduplicated per Binary.
                    {
                        let owner = self
                            .from
                            .owners
                            .off_heap
                            .iter()
                            .chain(&self.from.owners.old_off_heap)
                            .find(|arc| Arc::as_ptr(arc) as usize == key)
                            .cloned();
                        if let Some(owner) = owner {
                            self.to.off_heap_binary_bytes = self
                                .to
                                .off_heap_binary_bytes
                                .saturating_add(owner.len() as u64);
                            let vheap_words = (owner.len() / 8) as u64;
                            target.push(owner);
                            self.to.add_vheap(promote, vheap_words);
                        } else {
                            self.error = Some(TermError::BadArg);
                        }
                    }
                }
            }
            EXTERNAL_PID | EXTERNAL_PORT | EXTERNAL_REF => {
                let target = if promote {
                    &mut self.to.owners.old_nodes
                } else {
                    &mut self.to.owners.nodes
                };
                if !target.iter().any(|arc| Arc::as_ptr(arc) as usize == key) {
                    let owner = self
                        .from
                        .owners
                        .nodes
                        .iter()
                        .chain(&self.from.owners.old_nodes)
                        .find(|arc| Arc::as_ptr(arc) as usize == key)
                        .cloned();
                    if let Some(owner) = owner {
                        target.push(owner);
                    } else {
                        self.error = Some(TermError::BadArg);
                    }
                }
            }
            FUN => {
                let fun = self
                    .from
                    .owners
                    .funs
                    .iter()
                    .chain(&self.from.owners.old_funs)
                    .find(|arc| Arc::as_ptr(arc) as usize == key)
                    .cloned();
                if let Some(owner) = fun {
                    let target = if promote {
                        &mut self.to.owners.old_funs
                    } else {
                        &mut self.to.owners.funs
                    };
                    if !target.iter().any(|arc| Arc::as_ptr(arc) as usize == key) {
                        target.push(owner);
                    }
                } else {
                    let target = if promote {
                        &mut self.to.owners.old_exports
                    } else {
                        &mut self.to.owners.exports
                    };
                    if !target.iter().any(|arc| Arc::as_ptr(arc) as usize == key) {
                        let owner = self
                            .from
                            .owners
                            .exports
                            .iter()
                            .chain(&self.from.owners.old_exports)
                            .find(|arc| Arc::as_ptr(arc) as usize == key)
                            .cloned();
                        if let Some(owner) = owner {
                            target.push(owner);
                        } else {
                            self.error = Some(TermError::BadArg);
                        }
                    }
                }
            }
            SUB_BITS => self.sub_bits.push(term),
            MAGIC_REF => {
                let target = if promote {
                    &mut self.to.owners.old_magic
                } else {
                    &mut self.to.owners.magic
                };
                if !target.iter().any(|arc| Arc::as_ptr(arc) as usize == key) {
                    let owner = self
                        .from
                        .owners
                        .magic
                        .iter()
                        .chain(&self.from.owners.old_magic)
                        .find(|arc| Arc::as_ptr(arc) as usize == key)
                        .cloned();
                    if let Some(owner) = owner {
                        target.push(owner);
                    } else {
                        self.error = Some(TermError::BadArg);
                    }
                }
            }
            _ => {}
        }
    }

    #[inline]
    fn scan_slot(&mut self, slot: *mut u64) {
        // SAFETY: `slot` is a term field in a copied object and this collector
        // alone mutates the destination heap during the stop-the-world pass.
        #[cfg_attr(not(debug_assertions), allow(unused_variables))]
        let copied = unsafe {
            let copied = self.copy(Term(*slot));
            *slot = copied.0;
            copied
        };
        #[cfg(debug_assertions)]
        crate::validate::verify_copied_term_after_collection(self.to, copied);
    }

    fn scan_space(&mut self, old: bool) {
        let index = if old { self.old_scan } else { self.young_scan };
        let base = if old {
            self.to.old_words.as_ptr()
        } else {
            self.to.words.as_ptr()
        };
        // SAFETY: The index is below the initialized top of a fixed allocation.
        let ptr = unsafe { base.add(index).cast::<u64>().cast_mut() };
        // SAFETY: Copied objects have their complete initialized layout.
        let first = unsafe { *ptr };
        if first & 3 != 0 {
            self.scan_slot(ptr);
            if old {
                self.old_scan += 1;
            } else {
                self.young_scan += 1;
            }
            return;
        }
        let header = first;
        let kind = header & 63;
        let (start, end, words) = if kind == ARITY || kind == RECORD {
            let words = 1 + (header >> 6) as usize;
            (1, words, words)
        } else if kind == MAP {
            // SAFETY: MAP headers and payloads use the shared HAMT layout.
            let words = unsafe { boxed_object_words(header, ptr) };
            // SAFETY: The copied MAP is complete and initialized.
            let range = unsafe { boxed_term_range(header, ptr) };
            (range.start, range.end, words)
        } else if kind == FUN {
            let words = 2 + ((header >> 16) & 255) as usize;
            (2, words, words)
        } else if kind == SUB_BITS {
            (4, 5, 5)
        } else {
            // SAFETY: Other boxed kinds have no tagged payload fields.
            (0, 0, unsafe { boxed_object_words(header, ptr) })
        };
        for offset in start..end {
            if offset + 1 < end {
                // The next child is commonly another heap object in tuple trees.
                // SAFETY: The copied object has initialized fields through `end`.
                prefetch_term(unsafe { Term(*ptr.add(offset + 1)) });
            }
            // SAFETY: The range selects initialized tagged fields of this object.
            self.scan_slot(unsafe { ptr.add(offset) });
        }
        if old {
            self.old_scan += words;
        } else {
            self.young_scan += words;
        }
    }

    fn drain(&mut self) {
        while self.young_scan < self.to.htop || self.old_scan < self.to.old_htop {
            if self.old_scan < self.to.old_htop {
                self.scan_space(true);
            }
            if self.young_scan < self.to.htop {
                self.scan_space(false);
            }
        }
    }

    fn finish_bits(&mut self) {
        // OTP visits writable owners even when their BinRefs are already old.
        // A volatile SUB_BITS resolves the current byte pointer through BinRef;
        // match contexts pin their owner before becoming mutable.
        for &bin_ref in self
            .writable_refs
            .iter()
            .chain(&self.to.owners.old_writable_refs)
        {
            // SAFETY: The process is stopped and each referenced owner is retained.
            unsafe { writable_gc_visit(bin_ref) };
        }
        for &sub in &self.sub_bits {
            // SAFETY: Its orig field has been rewritten by the scan; the owner is live.
            unsafe {
                let ptr = sub.raw_ptr().cast_mut();
                let orig = Term(*ptr.add(4));
                let base = match orig.header().map(|h| h & 63) {
                    Some(HEAP_BITS) => orig.raw_ptr().add(2).cast::<u8>(),
                    Some(BIN_REF) => binary_data(orig.raw_ptr()),
                    _ => continue,
                };
                *ptr.add(1) = (base as u64 & !3) | (*ptr.add(1) & 3);
            }
        }
    }
}

#[inline]
fn prefetch_term(term: Term) {
    #[cfg(all(target_arch = "aarch64", not(miri)))]
    if term.is_pointer() {
        let address = (term.0 & !7) as *const u8;
        // SAFETY: PRFM is a non-faulting read hint; no Rust reference is made.
        unsafe {
            std::arch::asm!(
                "prfm pldl1keep, [{address}]",
                address = in(reg) address,
                options(readonly, nostack, preserves_flags)
            );
        }
    }
    #[cfg(any(not(target_arch = "aarch64"), miri))]
    let _ = term;
}

impl ProcessHeap {
    /// Maximum heap, stack, and fragment words inspected by literal GC checks.
    // Port of erts/emulator/beam/beam_bif_load.c:976 (`erts_check_copy_literals_gc_need_max_reds`), OTP-29.1.1.
    pub fn literal_scan_words(&self) -> usize {
        self.htop
            .saturating_add(self.stack_words())
            .saturating_add(self.old_htop)
            .saturating_add(self.fragments.iter().map(|f| f.len()).sum::<usize>())
    }

    /// Return whether initialized process storage contains a direct pointer into an area.
    /// Port of erts/emulator/beam/beam_bif_load.c:1240 (`any_heap_refs`), OTP-29.1.1.
    pub fn has_heap_reference(&self, mut is_area_pointer: impl FnMut(Term) -> bool) -> bool {
        let young = Self::any_heap_reference_words(
            self.words.as_ptr().cast::<u64>(),
            0,
            self.htop,
            true,
            &mut is_area_pointer,
        );
        if young {
            return true;
        }
        let stack = Self::any_heap_reference_words(
            self.words.as_ptr().cast::<u64>(),
            self.stop,
            self.words.len() - self.stop,
            false,
            &mut is_area_pointer,
        );
        if stack {
            return true;
        }
        if Self::any_heap_reference_words(
            self.old_words.as_ptr().cast::<u64>(),
            0,
            self.old_htop,
            true,
            &mut is_area_pointer,
        ) {
            return true;
        }
        self.fragments.iter().any(|fragment| {
            Self::any_heap_reference_words(
                fragment.as_ptr(),
                0,
                fragment.len(),
                true,
                &mut is_area_pointer,
            )
        })
    }

    fn any_heap_reference_words(
        base: *const u64,
        start: usize,
        words: usize,
        heap_objects: bool,
        is_area_pointer: &mut impl FnMut(Term) -> bool,
    ) -> bool {
        let end = start.saturating_add(words);
        let mut index = start;
        while index < end {
            // SAFETY: Heap ranges contain complete initialized objects; stack
            // ranges contain initialized term or continuation words.
            let (word, sub_bits_orig, object_words) = unsafe {
                let word = *base.add(index);
                if heap_objects && word & 3 == 0 {
                    let kind = word & 63;
                    if kind == SUB_BITS {
                        (
                            word,
                            Some(*base.add(index + 4)),
                            Some(boxed_object_words(word, base.add(index))),
                        )
                    } else if kind != ARITY && kind != RECORD {
                        (word, None, Some(boxed_object_words(word, base.add(index))))
                    } else {
                        (word, None, None)
                    }
                } else {
                    (word, None, None)
                }
            };
            if word & 3 == 1 || word & 3 == 2 {
                let term = Term(word);
                if is_area_pointer(term) {
                    return true;
                }
            }
            if sub_bits_orig.is_some_and(|orig| is_area_pointer(Term(orig))) {
                return true;
            }
            if let Some(object_words) = object_words {
                index += object_words;
                continue;
            }
            index += 1;
        }
        false
    }

    /// Whether a pointer belongs to this process's initialized heap storage.
    pub fn owns_term(&self, term: Term) -> bool {
        if !term.is_pointer() {
            return false;
        }
        let address = (term.bits() & !7) as usize;
        self.words.contains_initialized(address, self.htop)
            || self.old_words.contains_initialized(address, self.old_htop)
            || self.fragments.iter().any(|fragment| {
                let start = fragment.as_ptr() as usize;
                address >= start && address < start.saturating_add(fragment.len() * 8)
            })
    }

    /// Like `owns_term`, but resolves fragment ownership through `index`, which
    /// is brought up to date first. Avoids a linear fragment scan per term when
    /// a root scan visits many terms of a heap with many fragments.
    pub fn owns_term_indexed(&self, term: Term, index: &mut FragmentIndex) -> bool {
        if !term.is_pointer() {
            return false;
        }
        let address = (term.bits() & !7) as usize;
        if self.words.contains_initialized(address, self.htop)
            || self.old_words.contains_initialized(address, self.old_htop)
        {
            return true;
        }
        index.sync(&self.fragments);
        index
            .ranges
            .range(..=address)
            .next_back()
            .is_some_and(|(_, end)| address < *end)
    }

    /// Allocate a heap fragment and return its pointer after it enters the owner list.
    pub fn gc_fragment(&mut self, words: usize) -> *mut u64 {
        self.heap_fragment(words)
    }

    /// Send every allocation to a separate growable heap until [`ProcessHeap::end_detached`].
    ///
    /// Port of erts/emulator/beam/erl_proc_sig_queue.c (handle_process_info), OTP-29.1.1: erts
    /// builds the answer to a signal request in the reply message's own heap fragment, so the
    /// target's young heap, fragments and off-heap lists never see it. Terms built meanwhile
    /// live only until `end_detached`.
    pub fn begin_detached(&mut self) {
        self.owners.detached = Some(Box::new(VecHeap::new()));
        self.detached = true;
    }

    /// Whether allocations currently go to the detached heap.
    pub fn is_detached(&self) -> bool {
        self.detached
    }

    /// Drop the detached heap and everything built in it.
    pub fn end_detached(&mut self) {
        self.detached = false;
        self.owners.detached = None;
    }

    /// Total words in the contiguous young heap and stack allocation.
    pub fn capacity_words(&self) -> usize {
        self.words.len()
    }

    /// Young heap capacity in words, for `process_info(heap_size)`.
    pub fn heap_size_words(&self) -> usize {
        self.words.len()
    }

    /// Young heap, old heap, and fragment capacity in words.
    pub fn total_heap_size_words(&self) -> usize {
        self.words.len() + self.old_words.len() + self.fragment_words as usize
    }

    /// Old generation capacity in words.
    pub fn old_heap_words(&self) -> usize {
        self.old_words.len()
    }

    /// Number of heap fragments attached to this heap.
    pub fn fragment_count(&self) -> usize {
        self.fragments.len()
    }

    /// Words held in heap fragments.
    pub fn fragment_words(&self) -> usize {
        self.fragments.iter().map(|fragment| fragment.len()).sum()
    }

    /// Allocated and block sizes behind `process_info(garbage_collection_info)`.
    // Port of erts/emulator/beam/erl_gc.c:3650-3728 (erts_process_gc_info), OTP-29.1.1.
    pub fn gc_info_words(&self) -> GcInfoWords {
        GcInfoWords {
            old_heap_block_size: self.old_words.len(),
            heap_block_size: self.words.len(),
            mbuf_size: self.fragments.iter().map(|fragment| fragment.len()).sum(),
            recent_size: self.high_water,
            stack_size: self.words.len() - self.stop,
            old_heap_size: self.old_htop,
            heap_size: self.htop,
        }
    }

    /// Number of allocated words in the old generation.
    pub fn old_used_words(&self) -> usize {
        self.old_htop
    }

    /// Capacity of the old heap block.
    pub fn old_heap_block_size(&self) -> usize {
        self.old_words.len()
    }

    /// Words allocated in the young heap at the last collection.
    pub fn recent_words(&self) -> usize {
        self.high_water
    }

    /// Minimum young heap size configured for this process.
    pub fn min_heap_size_words(&self) -> usize {
        self.min_heap_size as usize
    }

    /// Number of minor collections since the latest full sweep.
    pub fn minor_gcs(&self) -> u16 {
        self.minor_since_major
    }

    /// Minor collections allowed before a full sweep.
    pub fn fullsweep_after(&self) -> u16 {
        self.fullsweep_after
    }

    /// Whether the next collection is a full sweep.
    /// Port of erts/emulator/beam/erl_gc.c:787 (minor/major choice in `erts_garbage_collect_nobump`), OTP-29.1.1.
    pub fn collection_is_major(&self) -> bool {
        let promote_bound = self.old_htop.saturating_add(self.high_water);
        self.minor_since_major >= self.fullsweep_after
            || (!self.old_words.is_empty() && promote_bound > self.old_words.len())
    }

    /// Whether a collection that starts as minor cannot be one and continues as a full sweep.
    /// Port of erts/emulator/beam/erl_gc.c:1461-1488 and 1540 (`minor_collection` returning -1
    /// when there is no old heap to tenure into or `bin_old_vheap` reached `bin_old_vheap_sz`),
    /// OTP-29.1.1. erts traces the failed minor attempt before the major one.
    pub fn minor_falls_back_to_major(&self) -> bool {
        !self.collection_is_major()
            && ((self.old_words.is_empty() && self.high_water == 0)
                || (!self.old_words.is_empty()
                    && self.owners.vheap.old_size <= self.owners.vheap.old))
    }

    /// Whether heap fragments exceed the free young-generation area.
    /// Port of erl_gc.h:132-139 (`ERTS_IS_GC_DESIRED`), OTP-29.1.1.
    pub fn gc_desired(&self) -> bool {
        self.free_words() < self.fragment_words as usize
    }

    /// Whether a term points into the old generation.
    pub fn old_generation_contains(&self, term: Term) -> bool {
        if !term.is_pointer() {
            return false;
        }
        let address = (term.0 & !7) as usize;
        let start = self.old_words.as_ptr() as usize;
        address >= start && address < start + self.old_htop * 8
    }

    /// Check that every old-generation term field avoids the young heap and fragments.
    pub fn old_generation_is_closed(&self) -> bool {
        let young_start = self.words.as_ptr() as usize;
        let young_end = young_start + self.htop * 8;
        let mut index = 0;
        while index < self.old_htop {
            // SAFETY: The scan index is inside the initialized old heap.
            let ptr = unsafe { self.old_words.as_ptr().add(index).cast::<u64>() };
            // SAFETY: All copied objects have complete initialized layouts.
            let first = unsafe { *ptr };
            let (range, words) = if first & 3 != 0 {
                (0..1, 1)
            } else {
                // SAFETY: A header begins a complete boxed object.
                unsafe { (boxed_term_range(first, ptr), boxed_object_words(first, ptr)) }
            };
            for offset in range {
                // SAFETY: The range selects initialized tagged term fields.
                let word = unsafe { *ptr.add(offset) };
                if word & 3 == 1 || word & 3 == 2 {
                    let address = (word & !7) as usize;
                    if address >= young_start && address < young_end
                        || self.fragments.iter().any(|fragment| {
                            let start = fragment.as_ptr() as usize;
                            address >= start && address < start + fragment.len() * 8
                        })
                    {
                        return false;
                    }
                }
            }
            index += words;
        }
        true
    }

    /// Set the number of minor collections permitted before a full sweep.
    pub fn set_fullsweep_after(&mut self, count: u16) {
        self.fullsweep_after = count;
    }

    /// Set the minimum young heap capacity in words.
    pub fn set_min_heap_size(&mut self, words: usize) {
        // Port of erl_gc.c:345-349 (`next_heap_size`) and bif.c:2120-2129
        // (`min_heap_size`), OTP-29.1.1.
        self.min_heap_size = u32::try_from(normalize_heap_minimum(words)).unwrap_or(u32::MAX);
    }

    /// Number of live stack words.
    pub fn stack_words(&self) -> usize {
        self.words.len() - self.stop
    }

    /// Make the next collection sweep both generations.
    pub fn request_full_sweep(&mut self) {
        self.minor_since_major = self.fullsweep_after;
    }

    /// Read a stack word relative to the current stack pointer.
    pub fn stack_get(&self, index: usize) -> Option<Term> {
        self.words.get(self.stop + index).map(|word| {
            // SAFETY: A live stack slot is initialized before collection.
            let term = Term(unsafe { *word.get() });
            // g_asan
            #[cfg(any(feature = "validate-terms", debug_assertions))]
            crate::validate::check_if_active(self, term);
            term
        })
    }

    /// Replace a live stack word.
    pub fn stack_set(&mut self, index: usize, value: Term) -> bool {
        if let Some(word) = self.words.get(self.stop + index) {
            // SAFETY: Exclusive process access permits writing this live slot.
            unsafe { *word.get() = value.0 };
            true
        } else {
            false
        }
    }

    /// Discard words from the top of the stack.
    pub fn release_stack(&mut self, words: usize) -> bool {
        if words > self.stack_words() {
            return false;
        }
        self.stop += words;
        true
    }

    /// Copy reachable objects and rewrite X, stack, and extra roots.
    /// Literal and shared allocations retain their addresses.
    pub fn collect(
        &mut self,
        roots: &mut [Term],
        extra: &mut [Term],
        min_free: usize,
    ) -> Result<GcStats, TermError> {
        let start = Instant::now();
        let fragments = self.fragment_words as usize;
        let mut fragment_ranges = self
            .fragments
            .iter()
            .map(|fragment| {
                let start = fragment.as_ptr() as usize;
                (start, start + fragment.len() * 8)
            })
            .collect::<Vec<_>>();
        fragment_ranges.sort_unstable_by_key(|&(start, _)| start);
        // `MSO(p).overhead` before the sweep; erl_gc.c:3285 sizes the old virtual heap from it.
        let young_overhead = self.bin_vheap;
        let major = self.collection_is_major() || self.minor_falls_back_to_major();
        let stack = self.stack_words();
        let source_words = self
            .htop
            .checked_add(fragments)
            .ok_or(TermError::SystemLimit)?;
        // Port of erl_gc.c:642 (`young_gen_usage` heap top) and erl_gc.c:1875
        // (`major_collection` adds the old heap). Usage is an upper bound on
        // survivors: a copying collector cannot move more words than are allocated.
        let size_before = if major {
            source_words.saturating_add(self.old_htop)
        } else {
            source_words
        };
        // Port of erl_gc.c:1492 (`minor_collection`) and erl_gc.c:1879
        // (`major_collection`). erts sizes to-space from the larger of live
        // usage and the requested allocation, then adjusts after copying.
        // Minor GC adds S_RESERVED to `need` before sizing; major GC adds it
        // directly to the live-data total.
        // Port of erl_gc.c:1492-1493 and 1879, OTP-29.1.1.
        let new_sz = stack.saturating_add(if major {
            size_before.saturating_add(S_RESERVED)
        } else {
            size_before.max(min_free.saturating_add(S_RESERVED))
        });
        let mut capacity = next_heap_size(new_sz, 0, self.min_heap_size as usize)?;
        if major && self.heap_grow && capacity == self.words.len() {
            capacity = next_heap_size(capacity, 1, self.min_heap_size as usize)?;
        }
        let mut next = ProcessHeap::with_words(capacity);
        next.stop = capacity - stack;
        next.frame_pointer = self.frame_pointer;
        next.min_heap_size = self.min_heap_size;
        next.owners.vheap.min = self.owners.vheap.min;
        next.bin_vheap_size = self.bin_vheap_size;
        next.owners.vheap.old_size = self.owners.vheap.old_size;
        next.fullsweep_after = self.fullsweep_after;
        next.heap_grow = self.heap_grow;
        next.native_allocation = self.native_allocation;
        next.minor_since_major = if major {
            0
        } else {
            self.minor_since_major.saturating_add(1)
        };
        next.off_heap_binary_bytes = if major {
            0
        } else {
            self.owners
                .old_off_heap
                .iter()
                .map(|binary| binary.len() as u64)
                .chain(
                    self.owners
                        .old_external
                        .iter()
                        .map(|binary| binary.len() as u64),
                )
                .sum()
        };
        next.owners.vheap.old = if major { 0 } else { self.owners.vheap.old };
        if !major {
            next.old_words = std::mem::take(&mut self.old_words);
            if next.old_words.is_empty() && self.high_water > 0 {
                // Port of erl_gc.c:1471 (`erts_next_heap_size(size_before, 1)`):
                // the first old heap is one step larger than the mature data.
                let old_capacity = next_heap_size(source_words, 1, 0)?;
                next.old_words = ProcessHeap::with_words_for_type(
                    old_capacity,
                    arinsal_alloc::typed::ErtsAlcType::OLD_HEAP,
                )
                .words;
            }
            next.old_htop = self.old_htop;
            next.owners.old_off_heap = std::mem::take(&mut self.owners.old_off_heap);
            next.owners.old_writable = std::mem::take(&mut self.owners.old_writable);
            next.owners.old_external = std::mem::take(&mut self.owners.old_external);
            next.owners.old_nodes = std::mem::take(&mut self.owners.old_nodes);
            next.owners.old_funs = std::mem::take(&mut self.owners.old_funs);
            next.owners.old_exports = std::mem::take(&mut self.owners.old_exports);
            next.owners.old_magic = std::mem::take(&mut self.owners.old_magic);
            next.owners.old_writable_refs = std::mem::take(&mut self.owners.old_writable_refs);
        }
        let mut from = std::mem::replace(self, next);
        let old_frame_pointer = from.frame_pointer;
        let stack_move = MoveRange {
            old_start: from.words.as_ptr() as usize + from.stop * 8,
            old_end: from.words.as_ptr() as usize + from.words.len() * 8,
            new_start: self.words.as_ptr() as usize + self.stop * 8,
        };
        let code_ranges = crate::native_code::native_code_ranges();
        let code_ranges = code_ranges
            .as_deref()
            .map_or(&[][..], |ranges| ranges.as_slice());
        let old_scan = self.old_htop;
        let mut copier = Copier {
            from: &mut from,
            to: self,
            major,
            young_scan: 0,
            old_scan,
            fragment_ranges,
            young_words: 0,
            promoted_words: 0,
            sub_bits: Vec::new(),
            writable_refs: Vec::new(),
            error: None,
        };
        for root in roots.iter_mut().chain(extra.iter_mut()) {
            *root = copier.copy(*root);
        }
        for i in 0..stack {
            // SAFETY: The live source and reserved destination stack slots are distinct.
            unsafe {
                let raw = *copier.from.words[copier.from.stop + i].get();
                *copier.to.words[copier.to.stop + i].get() =
                    match classify_stack_word(raw, stack_move, code_ranges) {
                        StackWord::Term(term) => copier.copy(term).0,
                        StackWord::ReturnAddr(_) => raw,
                        StackWord::FramePtr(address) => rebase_address(address, stack_move) as u64,
                    };
            }
        }
        let new_frame_pointer = if old_frame_pointer == 0 {
            0
        } else {
            rebase_address(old_frame_pointer, stack_move)
        };
        copier.drain();
        copier.finish_bits();
        copier.to.high_water = copier.to.htop;
        let error = copier.error.take();
        let copied = copier.young_words as u64;
        let promoted = copier.promoted_words as u64;
        drop(copier);
        drop(from);
        self.frame_pointer = new_frame_pointer;
        if let Some(error) = error {
            return Err(error);
        }
        // The code range guard stays held: a second read acquisition could block behind a
        // queued writer (a module being registered) while this one is still held.
        self.adjust_young_heap(major, min_free, roots, extra, code_ranges)?;
        #[cfg(debug_assertions)]
        self.verify_frame_chain(code_ranges);
        // Verify all roots after collection so stale pointers fail where they enter.
        #[cfg(debug_assertions)]
        crate::validate::verify_roots_after_collection(self, roots, extra);
        let stats = GcStats {
            collections: 1,
            minor_collections: u64::from(!major),
            major_collections: u64::from(major),
            words_copied: copied,
            words_promoted: promoted,
            words_reclaimed: size_before.saturating_sub((copied + promoted) as usize) as u64,
            nanoseconds: start.elapsed().as_nanos() as u64,
        };
        // Port of erts/emulator/beam/erl_gc.c:3284-3289 (sweep_off_heap), OTP-29.1.1.
        if major {
            self.owners.vheap.old = 0;
            self.owners.vheap.old_size = next_vheap_size(
                young_overhead,
                self.owners.vheap.old_size,
                self.owners.vheap.min,
            );
        }
        self.bin_vheap_size =
            next_vheap_size(self.bin_vheap, self.bin_vheap_size, self.owners.vheap.min);
        Ok(stats)
    }

    /// Full sweep that leaves the young heap exactly as large as the live data,
    /// the stack, and `S_RESERVED`, with no old heap.
    // Port of erts/emulator/beam/erl_gc.c:1004 (garbage_collect_hibernate), OTP-29.1.1.
    pub fn collect_hibernate(
        &mut self,
        roots: &mut [Term],
        extra: &mut [Term],
    ) -> Result<GcStats, TermError> {
        self.request_full_sweep();
        let stats = self.collect(roots, extra, 0)?;
        self.fragments.clear();
        self.fragment_words = 0;
        let exact = self
            .htop
            .saturating_add(S_RESERVED)
            .saturating_add(self.stack_words());
        if exact != self.words.len() {
            let code_ranges = crate::native_code::native_code_ranges();
            let code_ranges = code_ranges
                .as_deref()
                .map_or(&[][..], |ranges| ranges.as_slice());
            self.relocate_young(exact, roots, extra, code_ranges);
        }
        self.heap_grow = false;
        Ok(stats)
    }

    /// Apply the post-copy heap policy used by erts.
    fn adjust_young_heap(
        &mut self,
        major: bool,
        min_free: usize,
        roots: &mut [Term],
        extra: &mut [Term],
        code_ranges: &[(usize, usize)],
    ) -> Result<(), TermError> {
        let stack = self.stack_words();
        let need_after = self
            .htop
            .saturating_add(min_free)
            .saturating_add(stack)
            .saturating_add(S_RESERVED);
        let capacity = self.words.len();
        let old_len = self.old_words.len();
        let wanted = if major {
            self.heap_grow = false;
            if need_after > capacity {
                // Port of erl_gc.c:2073 (`adjust_after_fullsweep`).
                Some(next_heap_size(need_after, 0, self.min_heap_size as usize)?)
            } else if need_after.saturating_mul(4) > capacity.saturating_mul(3) {
                // Port of erl_gc.c:2076 (`adjust_after_fullsweep`): defer growth.
                self.heap_grow = true;
                None
            } else if need_after.saturating_mul(4) < capacity
                && capacity > (self.min_heap_size as usize).max(233)
            {
                // Port of erl_gc.c:2081 (`adjust_after_fullsweep`).
                Some(next_heap_size(
                    need_after.saturating_mul(2),
                    0,
                    self.min_heap_size as usize,
                )?)
            } else {
                None
            }
        } else if need_after > capacity {
            // Port of erl_gc.c:1552 (`grow_new_heap`).
            Some(next_heap_size(need_after, 0, self.min_heap_size as usize)?)
        } else if capacity > 3000
            && need_after.saturating_mul(4) < capacity
            && (capacity > 8000 || capacity > old_len)
        {
            // Port of erl_gc.c:1527 (`minor_collection`): retain roughly 3x
            // post-GC need and at least one eighth of the old heap if needed.
            let mut wanted = need_after.saturating_mul(3);
            if wanted.saturating_mul(9) < old_len {
                wanted = wanted.max(old_len / 8);
            }
            let minimum = wanted.max(self.min_heap_size as usize);
            let minimum = next_heap_size(minimum, 0, self.min_heap_size as usize)?;
            (minimum < capacity).then_some(minimum)
        } else {
            None
        };
        if let Some(wanted) = wanted
            && wanted != capacity
        {
            self.relocate_young(wanted, roots, extra, code_ranges);
        }
        Ok(())
    }

    /// Move the young heap to a block of `new_words`, keeping object addresses consistent.
    fn relocate_young(
        &mut self,
        new_words: usize,
        roots: &mut [Term],
        extra: &mut [Term],
        code_ranges: &[(usize, usize)],
    ) {
        let stack = self.stack_words();
        debug_assert!(new_words >= self.htop.saturating_add(stack));
        let old_start = self.words.as_ptr() as usize;
        let old_end = old_start + self.htop * 8;
        let old_stack_start = self.words.as_ptr() as usize + self.stop * 8;
        let old_stack_end = self.words.as_ptr() as usize + self.words.len() * 8;
        let mut fresh = ProcessHeap::with_words(new_words);
        let block = std::mem::take(&mut fresh.words);
        let new_start = block.as_ptr() as usize;
        let new_stop = new_words - stack;
        let stack_move = MoveRange {
            old_start: old_stack_start,
            old_end: old_stack_end,
            new_start: new_start + new_stop * 8,
        };
        if self.frame_pointer != 0 {
            self.frame_pointer = rebase_address(self.frame_pointer, stack_move);
        }
        // SAFETY: `fresh` is exclusive, `htop` words were initialized by the copy,
        // and the live stack occupies `stack` words at `stop`. The blocks do not overlap.
        unsafe {
            let src = self.words.as_ptr().cast::<u64>();
            let dst = block.as_ptr().cast::<u64>().cast_mut();
            if self.htop > 0 {
                std::ptr::copy_nonoverlapping(src, dst, self.htop);
            }
            if stack > 0 {
                std::ptr::copy_nonoverlapping(src.add(self.stop), dst.add(new_stop), stack);
            }
            offset_young_objects(dst, self.htop, old_start, old_end, new_start);
            offset_stack_slots(
                dst.add(new_stop),
                stack,
                MoveRange {
                    old_start,
                    old_end,
                    new_start,
                },
                stack_move,
                code_ranges,
            );
        }
        for term in roots.iter_mut().chain(extra.iter_mut()) {
            term.0 = offset_word(
                term.0,
                MoveRange {
                    old_start,
                    old_end,
                    new_start,
                },
            );
        }
        self.words = block;
        self.stop = new_stop;
        #[cfg(debug_assertions)]
        self.verify_frame_chain(code_ranges);
    }

    #[cfg(debug_assertions)]
    fn verify_frame_chain(&self, code_ranges: &[(usize, usize)]) {
        let base = self.words.as_ptr() as usize;
        let stack_start = base + self.stop * 8;
        let stack_end = base + self.words.len() * 8;
        let stack_range = MoveRange {
            old_start: stack_start,
            old_end: stack_end,
            new_start: stack_start,
        };
        let mut frame_pointer = self.frame_pointer;
        if frame_pointer == 0 {
            for index in 0..self.stack_words() {
                let word = self
                    .stack_get(index)
                    .expect("live stack word is present")
                    .tagged_word();
                match classify_stack_word(word, stack_range, code_ranges) {
                    StackWord::Term(_) => {}
                    StackWord::ReturnAddr(address) => assert!(
                        code_ranges
                            .iter()
                            .any(|&(start, end)| address >= start && address < end)
                    ),
                    StackWord::FramePtr(address) => {
                        panic!("frame pointer {address:#x} exists without an active frame chain")
                    }
                }
            }
            return;
        }
        let max_frames = self.stack_words() / crate::FrameLayout::WORDS;
        for _ in 0..max_frames {
            assert!(frame_pointer >= stack_start && frame_pointer < stack_end);
            assert_eq!((frame_pointer - stack_start) % 8, 0);
            let fp_index = (frame_pointer - stack_start) / 8;
            let previous_word = self
                .stack_get(fp_index + crate::FrameLayout::FRAME_POINTER_WORD)
                .expect("frame pointer word is present")
                .tagged_word();
            let previous = match classify_stack_word(previous_word, stack_range, code_ranges) {
                StackWord::FramePtr(address) => address,
                StackWord::Term(term) if term.tagged_word() == 0 => 0,
                _ => panic!("invalid frame pointer word {previous_word:#x}"),
            };
            let return_word = self
                .stack_get(fp_index + crate::FrameLayout::RETURN_ADDRESS_WORD)
                .expect("return address word is present")
                .tagged_word();
            let StackWord::ReturnAddr(return_address) =
                classify_stack_word(return_word, stack_range, code_ranges)
            else {
                panic!("invalid return address word {return_word:#x}");
            };
            assert!(
                code_ranges
                    .iter()
                    .any(|&(start, end)| return_address >= start && return_address < end)
            );
            if previous == 0 {
                return;
            }
            assert!(
                previous >= frame_pointer && previous < stack_end,
                "invalid previous FP {previous:#x} from {frame_pointer:#x} (stack {stack_start:#x}..{stack_end:#x})"
            );
            frame_pointer = previous;
        }
        panic!("native frame chain exceeds the live stack");
    }
}

#[derive(Clone, Copy)]
struct MoveRange {
    old_start: usize,
    old_end: usize,
    new_start: usize,
}

fn offset_word(word: u64, range: MoveRange) -> u64 {
    let tag = word & 3;
    if tag != 1 && tag != 2 {
        return word;
    }
    let address = (word & !7) as usize;
    if address >= range.old_start && address < range.old_end {
        let updated = range.new_start + (address - range.old_start);
        (updated as u64) | (word & 7)
    } else {
        word
    }
}

// Port of erts/emulator/beam/erl_gc.c:3366-3400 (offset_stack), OTP-29.1.1.
#[inline]
fn classify_stack_word(
    word: u64,
    stack_range: MoveRange,
    code_ranges: &[(usize, usize)],
) -> StackWord {
    let address = word as usize;
    if word & 3 == 0 && address >= stack_range.old_start && address < stack_range.old_end {
        return StackWord::FramePtr(address);
    }
    if word & 3 == 0 {
        let range_index = code_ranges.partition_point(|range| range.0 <= address);
        if range_index > 0 && address < code_ranges[range_index - 1].1 {
            return StackWord::ReturnAddr(address);
        }
    }
    StackWord::Term(Term(word))
}

fn rebase_address(address: usize, range: MoveRange) -> usize {
    range.new_start + (address - range.old_start)
}

/// Rewrite tagged pointers in the copied young heap. Raw payloads (bignums,
/// floats, binary bytes) stay byte-for-byte; only term slots move.
fn offset_young_objects(
    base: *mut u64,
    htop: usize,
    old_start: usize,
    old_end: usize,
    new_start: usize,
) {
    let mut index = 0;
    while index < htop {
        // SAFETY: `index` stays below the initialized young top of `base`.
        let first = unsafe { *base.add(index) };
        if first & 3 != 0 {
            // SAFETY: A non-header word in the young heap is one term slot.
            unsafe {
                let slot = base.add(index);
                *slot = offset_word(
                    *slot,
                    MoveRange {
                        old_start,
                        old_end,
                        new_start,
                    },
                );
            }
            index += 1;
            continue;
        }
        // SAFETY: A header begins a complete object that the collector just copied.
        let (range, words) = unsafe {
            (
                boxed_term_range(first, base.add(index)),
                boxed_object_words(first, base.add(index)),
            )
        };
        if first & 63 == SUB_BITS {
            // Word 1 is an absolute byte pointer with flag bits in the low pair.
            // finish_bits stored it before this move. Term slot 4 is handled below.
            // SAFETY: SUB_BITS objects occupy at least five words.
            unsafe {
                let slot = base.add(index + 1);
                let data = *slot;
                let address = (data & !3) as usize;
                if address >= old_start && address < old_end {
                    let updated = (new_start + (address - old_start)) as u64;
                    *slot = (updated & !3) | (data & 3);
                }
            }
        }
        for offset in range {
            // SAFETY: `range` selects initialized term fields of this object.
            unsafe {
                let slot = base.add(index + offset);
                *slot = offset_word(
                    *slot,
                    MoveRange {
                        old_start,
                        old_end,
                        new_start,
                    },
                );
            }
        }
        index += words;
    }
}

// Port of erts/emulator/beam/erl_gc.c:3368-3400 (offset_stack), OTP-29.1.1.
fn offset_stack_slots(
    base: *mut u64,
    count: usize,
    heap_move: MoveRange,
    stack_move: MoveRange,
    code_ranges: &[(usize, usize)],
) {
    for index in 0..count {
        // SAFETY: `index` is inside the copied stack or root image.
        unsafe {
            let slot = base.add(index);
            let value = *slot;
            *slot = match classify_stack_word(value, stack_move, code_ranges) {
                StackWord::Term(term) => offset_word(term.0, heap_move),
                StackWord::ReturnAddr(address) => address as u64,
                StackWord::FramePtr(address) => rebase_address(address, stack_move) as u64,
            };
        }
    }
}

/// Port of erl_gc.c:265-291 (`heap_sizes[]`), OTP-29.1.1.
fn heap_sizes() -> &'static [usize] {
    static SIZES: OnceLock<Vec<usize>> = OnceLock::new();
    SIZES.get_or_init(|| {
        // Port of erl_gc.c:177-186 (`MAX_HEAP_SIZES`), OTP-29.1.1.
        let count = if usize::BITS == 64 { 154 } else { 59 };
        let mut sizes = Vec::with_capacity(count);
        sizes.push(12);
        sizes.push(38);
        for index in 2..23 {
            sizes.push(sizes[index - 1] + sizes[index - 2] + 1);
        }
        while sizes.len() < count {
            let previous = *sizes.last().expect("initial heap sizes exist");
            sizes.push(previous + previous / 5);
        }
        sizes
    })
}

pub(crate) fn normalize_heap_minimum(minimum: usize) -> usize {
    let minimum = minimum.max(233);
    next_heap_size(minimum, 0, 233).unwrap_or(minimum)
}

/// Select the table size at or above `minimum`, applying OTP's optional offset.
///
/// Port of erl_gc.c:311-335 (`erts_next_heap_size`) and erl_gc.c:345-349
/// (`next_heap_size`), OTP-29.1.1.
fn next_heap_size(minimum: usize, offset: usize, min_heap_size: usize) -> Result<usize, TermError> {
    let sizes = heap_sizes();
    if minimum < sizes[0] {
        return Ok(sizes[0].max(min_heap_size));
    }
    let target = minimum.max(sizes[0]);
    let index = sizes.partition_point(|&size| size < target);
    let index = index.checked_add(offset).ok_or(TermError::SystemLimit)?;
    sizes
        .get(index)
        .copied()
        .map(|size| size.max(min_heap_size))
        .ok_or(TermError::SystemLimit)
}

// Port of erts/emulator/beam/erl_gc.c:2915-2958 (do_next_vheap_size), OTP-29.1.1.
fn next_vheap_size(used: u64, current: u64, minimum: u64) -> u64 {
    let mut size = current;
    if used / 3 > size / 4 {
        loop {
            let grown = ((size as f64) * 1.618) as u64;
            if grown < size {
                break;
            }
            size = grown;
            if used / 3 <= size / 4 {
                break;
            }
        }
    } else if used < size / 4 {
        size >>= 1;
    }
    size.max(minimum)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literal_area_scan_finds_raw_heap_references() {
        let mut heap = ProcessHeap::with_words(16);
        let mut literals = ProcessHeap::with_words(16);
        assert!(heap.alloc(1).is_some());
        let literal = crate::TermBuilder::new(&mut literals)
            .tuple(&[Term::NIL])
            .unwrap();
        assert!(heap.debug_write_heap_word(0, literal.bits()));

        assert!(heap.has_heap_reference(|term| term == literal));
        assert!(!heap.has_heap_reference(|_| false));
    }

    #[test]
    fn fragment_pressure_tracks_allocated_and_adopted_fragment_words() {
        let mut heap = ProcessHeap::with_words(128);
        heap.gc_fragment(64);
        assert_eq!(heap.fragment_words, 64);
        assert!(!heap.gc_desired());
        heap.gc_fragment(65);
        assert_eq!(heap.fragment_words, 129);
        assert!(heap.gc_desired());

        let mut message_heap = ProcessHeap::with_words(32);
        message_heap.gc_fragment(7);
        heap.adopt_message_fragment(message_heap).unwrap();
        assert_eq!(heap.fragment_words, 168);
    }

    #[test]
    fn collection_relocates_frame_pointers_in_the_stack() {
        let mut heap = ProcessHeap::with_words(8_192);
        assert!(heap.alloc(4_000).is_some());
        assert!(heap.reserve_stack(8));
        heap.set_fullsweep_after(0);
        let old_stack_start = heap.heap_cursor().1;
        let code_pointer = 0x7000_0000_0000_usize;
        if !crate::is_native_code_pointer(code_pointer) {
            crate::register_native_code_range(code_pointer, code_pointer + 16).unwrap();
        }
        assert!(heap.stack_set(0, Term(old_stack_start.wrapping_add(2) as usize as u64)));
        assert!(heap.stack_set(1, Term(code_pointer as u64)));
        assert!(heap.stack_set(2, Term(0)));
        assert!(heap.stack_set(3, Term(code_pointer as u64)));
        heap.set_frame_pointer(old_stack_start as usize);

        heap.collect(&mut [], &mut [], 0).unwrap();

        let new_stack_start = heap.heap_cursor().1 as usize;
        assert_ne!(new_stack_start, old_stack_start as usize);
        assert_eq!(heap.frame_pointer(), new_stack_start);
        assert_eq!(
            heap.stack_get(0).unwrap().tagged_word(),
            new_stack_start as u64 + 16
        );
        assert_eq!(
            heap.stack_get(1).unwrap().tagged_word(),
            code_pointer as u64
        );
    }
}

/// Word counts reported by `process_info(Pid, garbage_collection_info)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GcInfoWords {
    /// Old-generation block size.
    pub old_heap_block_size: usize,
    /// Young heap block size.
    pub heap_block_size: usize,
    /// Words held in heap fragments.
    pub mbuf_size: usize,
    /// Words below the high-water mark.
    pub recent_size: usize,
    /// Live stack words.
    pub stack_size: usize,
    /// Used old-generation words.
    pub old_heap_size: usize,
    /// Used young-heap words.
    pub heap_size: usize,
}

/// Address index over a heap's fragments for repeated ownership queries.
#[derive(Default)]
pub struct FragmentIndex {
    synced: usize,
    ranges: std::collections::BTreeMap<usize, usize>,
}

impl FragmentIndex {
    /// Fragments are only ever appended between collections; a shorter list
    /// means a collection ran and the index is rebuilt.
    fn sync(&mut self, fragments: &[crate::heap::Fragment]) {
        if fragments.len() < self.synced {
            self.synced = 0;
            self.ranges.clear();
        }
        for fragment in &fragments[self.synced..] {
            let start = fragment.as_ptr() as usize;
            self.ranges
                .insert(start, start.saturating_add(fragment.len() * 8));
        }
        self.synced = fragments.len();
    }
}
