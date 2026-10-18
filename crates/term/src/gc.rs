//! Per-process copying collection with a young heap and an old heap.
//!
//! The high-water mark is the young heap top after collection. At the next
//! minor collection, reachable objects below it move to the old heap, together with the
//! young objects only they reach (do_minor sweeps the tenured area last). A full
//! sweep copies both heaps into a new young heap. Stack frame pointers into the
//! current stack block are rebased; code pointers and CATCH words remain intact.

use crate::VecHeap;
use crate::bits::{
    BINARY_FLAG_WRITABLE, bin_ref_is_legacy_external, binary_data, writable_gc_visit,
};
use crate::hamt::{boxed_object_words, boxed_term_range};
use crate::{
    ARITY, BIN_REF, EXTERNAL_PID, EXTERNAL_PORT, EXTERNAL_REF, ExportEntry, ExternalBinary, FUN,
    FunEntry, HEAP_BITS, HeapAlloc, MAP, MagicRef, Node, ProcessHeap, RECORD, REF, RefcBinary,
    S_RESERVED, SUB_BITS, StackWord, Term, TermError, WritableBinary,
};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Instant;

/// `erts_system_monitor_long_gc`: the collector reads the clock only while this is set.
// Port of erts/emulator/beam/erl_gc.c:803, OTP-29.1.1.
static GC_CLOCK_LONG: AtomicBool = AtomicBool::new(false);
/// `erts_msacc_enabled`: microstate accounting times the collector the same way.
// Port of erts/emulator/beam/erl_msacc.h:240 (`ERTS_MSACC_IS_ENABLED`), OTP-29.1.1.
static GC_CLOCK_MSACC: AtomicBool = AtomicBool::new(false);

/// Enable the monotonic clock around collections while `long_gc` monitoring is on.
pub fn set_gc_clock_for_long_gc(enabled: bool) {
    GC_CLOCK_LONG.store(enabled, Ordering::Relaxed);
}

/// Enable the monotonic clock around collections while microstate accounting is on.
pub fn set_gc_clock_for_msacc(enabled: bool) {
    GC_CLOCK_MSACC.store(enabled, Ordering::Relaxed);
}

#[inline]
fn gc_clock_active() -> bool {
    GC_CLOCK_LONG.load(Ordering::Relaxed) || GC_CLOCK_MSACC.load(Ordering::Relaxed)
}

/// Location and sizes of an abandoned young heap.
#[derive(Clone, Copy, Debug)]
pub(crate) struct AbandonedHeap {
    start: usize,
    used: usize,
    high_water: usize,
    block_words: usize,
}

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
    /// Reductions erts charges the process for the collection (`gc_cost`).
    pub reductions: u32,
}

/// Reductions charged for a collection that moved `moved_live_words` live words and, when the
/// young heap was resized, `resize_moved_words` more.
// Port of erts/emulator/beam/erl_gc.c, gc_cost, OTP-29.1.1.
pub fn gc_cost(moved_live_words: usize, resize_moved_words: usize) -> u32 {
    let reds = moved_live_words / 10 + resize_moved_words / 100;
    u32::try_from(reds.clamp(1, i32::MAX as usize)).unwrap_or(i32::MAX as u32)
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
    fn retain_binary(&mut self, binary: Arc<RefcBinary>) {
        HeapAlloc::retain_binary(self.0, binary);
    }
    fn link_bin_ref(
        &mut self,
        bin_ref: *mut u64,
        writable: bool,
        overhead_words: u64,
        owner: Option<arinsal_alloc::raw::OwnedBinaryRef>,
    ) -> Result<(), TermError> {
        HeapAlloc::link_bin_ref(self.0, bin_ref, writable, overhead_words, owner)
    }
    fn retain_writable_binary(&mut self, binary: Arc<WritableBinary>) -> Result<(), TermError> {
        HeapAlloc::retain_writable_binary(self.0, binary)
    }
    fn retain_writable_binary_with_apparent_size(
        &mut self,
        binary: Arc<WritableBinary>,
        apparent_size_bits: usize,
    ) -> Result<(), TermError> {
        HeapAlloc::retain_writable_binary_with_apparent_size(self.0, binary, apparent_size_bits)
    }
    fn update_writable_binary_overhead(
        &mut self,
        source: Term,
        old_size_bits: usize,
        new_size_bits: usize,
    ) {
        HeapAlloc::update_writable_binary_overhead(self.0, source, old_size_bits, new_size_bits)
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
    fn link_magic_ref(&mut self, thing: *mut u64, owner: Arc<MagicRef>) -> Result<(), TermError> {
        HeapAlloc::link_magic_ref(self.0, thing, owner)
    }
    fn supports_magic(&self) -> bool {
        true
    }
}

/// A half-open byte-address range: erts `ErtsInArea(ptr, start, size)`.
#[derive(Clone, Copy)]
struct Area {
    start: usize,
    end: usize,
}

impl Area {
    const EMPTY: Self = Self { start: 0, end: 0 };

    #[inline(always)]
    fn contains(self, address: usize) -> bool {
        address.wrapping_sub(self.start) < self.end.wrapping_sub(self.start)
    }
}

/// A destination heap top (`n_htop` or `old_htop` of do_minor) and its end, as addresses.
#[derive(Clone, Copy)]
struct HeapTop {
    at: usize,
    end: usize,
}

fn binref_chain_nodes(mut link: usize) -> Vec<usize> {
    let mut nodes = Vec::new();
    while link != 0 {
        nodes.push(link);
        link = crate::heap::load((link as *const u64).wrapping_add(2)) as usize;
    }
    nodes
}

fn rebase_binref_chains(
    heap: &mut ProcessHeap,
    nodes: &[usize],
    old_start: usize,
    old_end: usize,
    new_start: usize,
) {
    let rebase = |address: usize| {
        if address >= old_start && address < old_end {
            new_start + (address - old_start)
        } else {
            address
        }
    };
    let Some(owners) = heap.owners.as_mut() else {
        return;
    };
    owners.off_heap_first = rebase(owners.off_heap_first);
    owners.wrt_bins = rebase(owners.wrt_bins);
    for &old_node in nodes {
        let node = rebase(old_node) as *mut u64;
        let next = crate::heap::load(node.wrapping_add(2)) as usize;
        crate::heap::store(node.wrapping_add(2), rebase(next) as u64);
    }
}

/// Release the reference every node of an off-heap list holds: a refc Binary behind a BinRef
/// or the owner of a magic reference.
// Port of erts/emulator/beam/erl_binary.h (`erts_bin_release`), OTP-29.1.1.
pub(crate) fn release_off_heap_chain(mut head: usize) {
    while head != 0 {
        let ptr = head as *const u64;
        let next = crate::heap::load(ptr.wrapping_add(2)) as usize;
        release_off_heap_node(head);
        head = next;
    }
}

/// Release one off-heap list node that has not been forwarded.
fn release_off_heap_node(node: usize) {
    if crate::heap::off_heap_node_is_magic(node) {
        drop(MagicRef::thing_owner(
            crate::heap::load((node as *const u64).wrapping_add(1)),
            false,
        ));
    } else {
        release_binary_ref(node);
    }
}

fn release_binary_ref(bin_ref: usize) {
    let ptr = bin_ref as *const u64;
    let header = crate::heap::load(ptr.wrapping_add(1)) as *const u64;
    let capacity = crate::heap::load(header.wrapping_add(3)) as usize;
    // SAFETY: callers own the live heap or fragment containing this BinRef; its val field
    // names the refcounted Binary kept by that BinRef.
    let view =
        unsafe { arinsal_alloc::raw::BinaryView::from_header(header, 4 + capacity.div_ceil(8)) };
    arinsal_alloc::typed::BinaryBlock::release_view(view)
        .expect("live BinRef has allocator metadata");
}

struct Copier<'a> {
    from: &'a mut ProcessHeap,
    to: &'a mut ProcessHeap,
    major: bool,
    /// The young heap being evacuated: `HEAP_START(p)..HEAP_TOP(p)`.
    young: Area,
    /// do_minor's `mature`/`mature_size`: objects that a minor collection tenures.
    mature: Area,
    /// do_minor's `oh`/`oh_size`: the old heap a minor collection leaves in place.
    old: Area,
    /// `erts_literals_start`/`erts_literals_size`, read once for the collection.
    literals: Area,
    n_htop: HeapTop,
    old_htop: HeapTop,
    /// Sorted owned fragment ranges, kept only to check the erts rule in debug builds.
    #[cfg(debug_assertions)]
    fragment_ranges: Vec<(usize, usize)>,
    sub_bits: Vec<Term>,
    error: Option<TermError>,
}

impl Copier<'_> {
    /// `ErtsInYoungGen` for a pointer outside the young heap block: heap fragments and
    /// the abandoned heap are young; literals (`erts_is_literal`: the literal area and the
    /// global empty tuple) and, in a minor collection, the old heap are not.
    // Port of erts/emulator/beam/erl_gc.h:97 (ErtsInYoungGen), OTP-29.1.1.
    #[inline]
    fn in_young_gen(&self, address: usize) -> bool {
        if self.young.contains(address) {
            return true;
        }
        if self.old.contains(address)
            || self.literals.contains(address)
            || address == std::ptr::from_ref(&crate::EMPTY_TUPLE) as usize
        {
            return false;
        }
        #[cfg(debug_assertions)]
        self.check_owned(address);
        true
    }

    /// Evacuate the object `gval` points to, or follow its forwarding pointer. With
    /// `INTO_OLD` every young object goes to the old heap: the second sweep of do_minor
    /// over the tenured area.
    // Port of erts/emulator/beam/erl_gc.c:1688-1717 (do_minor root loop) and
    // erl_gc.h:42-94 (MOVE_CONS, MOVE_BOXED, move_cons, move_boxed), OTP-29.1.1.
    #[inline(always)]
    fn evacuate<const INTO_OLD: bool>(&mut self, gval: u64) -> u64 {
        let tag = gval & 3;
        if tag != 1 && tag != 2 {
            return gval;
        }
        let address = (gval & !7) as usize;
        // SAFETY: `gval` is a live list or boxed term of this process, so its first word
        // is readable (literal and old heap objects are never forwarded). Objects that
        // move are in owned, live from-space memory; the destination ranges were sized
        // before the copy and do not overlap the sources. The collector has exclusive
        // access to the process.
        unsafe {
            let ptr = address as *mut u64;
            let val = *ptr;
            if tag == 1 {
                // Port of erts/emulator/beam/erl_gc.h:42 (IS_MOVED_CONS): zero cannot be a
                // cons head, so a zero head marks a moved cell and the tail holds the new term.
                if val == 0 {
                    return *ptr.add(1);
                }
            } else if val & 3 == 2 {
                // IS_MOVED_BOXED: a header never has the boxed tag.
                return val;
            }
            let promote = if self.mature.contains(address) {
                true
            } else if self.in_young_gen(address) {
                INTO_OLD
            } else {
                return gval;
            };
            let top = if promote {
                &mut self.old_htop
            } else {
                &mut self.n_htop
            };
            if tag == 1 {
                if top.end - top.at < 16 {
                    self.error = Some(TermError::HeapFull);
                    return gval;
                }
                let destination = top.at as *mut u64;
                top.at += 16;
                *destination = val;
                *destination.add(1) = *ptr.add(1);
                let moved = destination as u64 | 1;
                *ptr = 0;
                *ptr.add(1) = moved;
                return moved;
            }
            let words = if val & 63 == ARITY || val & 63 == RECORD {
                1 + (val >> 6) as usize
            } else {
                boxed_object_words(val, ptr)
            };
            if (top.end - top.at) / 8 < words {
                self.error = Some(TermError::HeapFull);
                return gval;
            }
            let destination = top.at as *mut u64;
            top.at += words * 8;
            *destination = val;
            for i in 1..words {
                *destination.add(i) = *ptr.add(i);
            }
            let moved = destination as u64 | 2;
            *ptr = moved;
            if matches!(
                val & 63,
                BIN_REF | EXTERNAL_PID | EXTERNAL_PORT | EXTERNAL_REF | FUN | SUB_BITS
            ) || (val == crate::REF_THING_HEADER
                && crate::is_magic_ref_thing_with_hdr(val, *destination.add(1)))
            {
                self.retain_owner(val, destination, Term(moved), promote);
            }
            moved
        }
    }

    /// Sweep the objects copied to `n_htop` (or, with `INTO_OLD`, to `old_htop`) from
    /// `n_hp` until the scan catches up with the top.
    // Port of erts/emulator/beam/erl_gc.c:1728-1813 (do_minor sweep) and
    // erl_gc.c:2281 (sweep), OTP-29.1.1.
    fn sweep<const INTO_OLD: bool>(&mut self, mut n_hp: usize) {
        loop {
            let n_htop = if INTO_OLD {
                self.old_htop.at
            } else {
                self.n_htop.at
            };
            if n_hp >= n_htop {
                break;
            }
            let ptr = n_hp as *mut u64;
            // SAFETY: `n_hp` is below the destination top, so it addresses an initialized
            // word of a completely copied object; this collector alone writes to it.
            unsafe {
                let gval = *ptr;
                if gval & 3 != 0 {
                    *ptr = self.evacuate::<INTO_OLD>(gval);
                    #[cfg(debug_assertions)]
                    crate::validate::verify_copied_term_after_collection(self.to, Term(*ptr));
                    n_hp += 8;
                    continue;
                }
                let kind = gval & 63;
                let (start, words) = if kind == ARITY || kind == RECORD {
                    (1, 1 + (gval >> 6) as usize)
                } else if kind == FUN {
                    (2, 2 + ((gval >> 16) & 255) as usize)
                } else if kind == MAP {
                    let range = boxed_term_range(gval, ptr);
                    let object_words = range.end;
                    for offset in range {
                        let slot = ptr.add(offset);
                        *slot = self.evacuate::<INTO_OLD>(*slot);
                        #[cfg(debug_assertions)]
                        crate::validate::verify_copied_term_after_collection(self.to, Term(*slot));
                    }
                    // The map child range ends at the copied object's word count. Reuse
                    // that result, as `sweep` advances through the copied heap once.
                    // Port of erts/emulator/beam/erl_gc.c:2281 (`sweep`), OTP-29.1.1.
                    n_hp += object_words * 8;
                    continue;
                } else if kind == SUB_BITS {
                    // The orig field; the byte pointer is rebased in finish_bits.
                    (4, 5)
                } else {
                    // Things without term fields.
                    n_hp += boxed_object_words(gval, ptr) * 8;
                    continue;
                };
                for offset in start..words {
                    let slot = ptr.add(offset);
                    *slot = self.evacuate::<INTO_OLD>(*slot);
                    #[cfg(debug_assertions)]
                    crate::validate::verify_copied_term_after_collection(self.to, Term(*slot));
                }
                n_hp += words * 8;
            }
        }
    }

    /// Debug check of the erts invariant behind the ownership rule: a moved pointer that is
    /// outside the young heap lies in a heap fragment, the abandoned heap or the old heap.
    #[cfg(debug_assertions)]
    fn check_owned(&self, address: usize) {
        let index = self
            .fragment_ranges
            .partition_point(|&(_, end)| end <= address);
        let in_fragment = self
            .fragment_ranges
            .get(index)
            .is_some_and(|&(start, end)| start <= address && address < end);
        let old_start = self.from.old_words.as_ptr() as usize;
        let in_old = address >= old_start && address < old_start + self.from.old_htop * 8;
        assert!(
            in_fragment || (self.major && in_old),
            "collection found a pointer {address:#x} outside the process heap and literals"
        );
    }

    fn retain_owner(&mut self, header: u64, ptr: *mut u64, term: Term, promote: bool) {
        // SAFETY: `ptr` is a complete copied object with the owner field in word one.
        let key = crate::heap::load(ptr.wrapping_add(1)) as usize;
        match header & 63 {
            BIN_REF => {
                // SAFETY: BinRef word two is either the legacy external tag or an intrusive next.
                let next_or_flags = unsafe { *ptr.add(2) };
                if bin_ref_is_legacy_external(next_or_flags) {
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
                            let vheap_words = (owner.len() / 8) as u64;
                            target.push(owner);
                            self.to.add_vheap(promote, vheap_words);
                        } else {
                            self.error = Some(TermError::BadArg);
                        }
                    }
                } else {
                    // BinRef.val points directly at the erts Binary header.
                    // SAFETY: the copied BinRef retains the source Binary allocation.
                    let binary_flags = unsafe { *(key as *const u64) };
                    let writable = binary_flags & BINARY_FLAG_WRITABLE != 0;
                    // SAFETY: the same live Binary header contains `orig_size` in word three.
                    let orig_size = unsafe { *((key as *const u64).add(3)) } as usize;
                    // Port of erts/emulator/beam/erl_gc.c:3155-3178 (writable BinRef sweep),
                    // OTP-29.1.1: the vheap charges allocated Binary.orig_size, not apparent size.
                    let overhead_words = (orig_size / 8) as u64;
                    // SAFETY: the source BinRef owns this Binary through the collection.
                    let view = unsafe {
                        arinsal_alloc::raw::BinaryView::from_header(
                            key as *const u64,
                            4 + orig_size.div_ceil(8),
                        )
                    };
                    let Some(owner) = arinsal_alloc::raw::OwnedBinaryRef::clone_from_view(view)
                    else {
                        self.error = Some(TermError::BadArg);
                        return;
                    };
                    if self
                        .to
                        .link_bin_ref(ptr, writable, overhead_words, Some(owner))
                        .is_err()
                    {
                        self.error = Some(TermError::BadArg);
                    }
                    if writable {
                        self.to.add_vheap(promote, overhead_words);
                        return;
                    }
                    self.to.add_vheap(promote, overhead_words);
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
            REF if crate::is_magic_ref_thing_with_hdr(header, key as u64) => {
                // Port of erts/emulator/beam/erl_gc.c (sweep_off_heap, magic reference
                // case), OTP-29.1.1: the moved thing is linked into the new off-heap list
                // and carries the counted reference of its source; the vheap is charged
                // `mb->orig_size`.
                let owner = MagicRef::thing_owner(key as u64, false);
                let words = owner.orig_size() as u64 / 8;
                if self.to.link_magic_ref(ptr, owner).is_err() {
                    self.error = Some(TermError::BadArg);
                }
                self.to.add_vheap(promote, words);
            }
            _ => {}
        }
    }

    fn finish_bits(&mut self) {
        // Port of erts/emulator/beam/erl_gc.c:3149-3157 (wrt_bins traversal), OTP-29.1.1.
        // Visit every live writable BinRef, including entries that stayed in the old heap.
        if self.to.owners.is_allocated() {
            let mut writable = self.to.owners.wrt_bins as *mut u64;
            while !writable.is_null() {
                // SAFETY: sweep_off_heap linked only retained, complete BinRef objects here.
                unsafe {
                    let next = *writable.add(2) as *mut u64;
                    writable_gc_visit(Term::from_ptr(writable, 2));
                    writable = next;
                }
            }
        }
        // Match contexts pin their owner before becoming mutable; a volatile SUB_BITS
        // resolves the current byte pointer through its BinRef after any realloc.
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

    /// Keep moved and old BinRefs, and release unreachable young BinRefs.
    // Port of erts/emulator/beam/erl_gc.c:2996-3150 (sweep_off_heap), OTP-29.1.1.
    fn sweep_binary_chain(&mut self, writable: bool) {
        let source_head = if writable {
            self.from.owners.wrt_bins
        } else {
            self.from.owners.off_heap_first
        };
        if source_head == 0 && !self.to.owners.is_allocated() {
            return;
        }
        let mut old_head = 0usize;
        let mut old_tail = 0usize;
        let mut source = source_head;
        while source != 0 {
            let ptr = source as *mut u64;
            // SAFETY: the source chain contains live three-word BinRef objects in heap or
            // fragment storage; the collector has exclusive access while forwarding them.
            let thing = crate::heap::load(ptr);
            let next = crate::heap::load(ptr.wrapping_add(2)) as usize;
            let moved = thing & 3 == 2;
            if moved {
                // A forwarded magic reference thing handed its counted reference to the
                // copy linked into the new list; a BinRef copy took its own.
                if !crate::heap::off_heap_node_is_magic(source) {
                    release_binary_ref(source);
                }
            } else if !self.major && self.old.contains(source) {
                // Minor GC leaves old-generation BinRefs in place. Build the retained old
                // suffix in source-list order, matching `insert_old_here` in erts.
                if old_head == 0 {
                    old_head = source;
                } else {
                    crate::heap::store((old_tail as *mut u64).wrapping_add(2), source as u64);
                }
                old_tail = source;
            } else {
                release_off_heap_node(source);
            }
            source = next;
        }

        // The retained suffix was spliced into the destination chain above; all other
        // source references were released while sweeping.
        if writable {
            self.from.owners.wrt_bins = 0;
        } else {
            self.from.owners.off_heap_first = 0;
        }

        let destination_head = if writable {
            &mut self.to.owners.wrt_bins
        } else {
            &mut self.to.owners.off_heap_first
        };
        if old_head != 0 {
            if *destination_head == 0 {
                *destination_head = old_head;
            } else {
                let mut tail = *destination_head;
                loop {
                    // SAFETY: destination_head and every next link point to live BinRefs.
                    let next = crate::heap::load((tail as *const u64).wrapping_add(2)) as usize;
                    if next == 0 {
                        break;
                    }
                    tail = next;
                }
                crate::heap::store((tail as *mut u64).wrapping_add(2), old_head as u64);
            }
            crate::heap::store((old_tail as *mut u64).wrapping_add(2), 0);
        }
    }

    /// Sweep the refc list, then the separate writable list, before releasing from-space.
    // Port of erts/emulator/beam/erl_gc.c:2996-3289 (sweep_off_heap), OTP-29.1.1.
    fn sweep_off_heap(&mut self) {
        let (refc_head, writable_head) = self.from.owners.chain_heads();
        if refc_head == 0 && writable_head == 0 && !self.to.owners.is_allocated() {
            return;
        }
        self.sweep_binary_chain(false);
        self.sweep_binary_chain(true);
        if self.to.owners.is_allocated() {
            self.to.owners.overhead = self.to.bin_vheap;
        }
    }
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
    // erts `HEAP_SIZE(p)` keeps the size of an abandoned heap until the delayed collection.
    pub fn heap_size_words(&self) -> usize {
        self.abandoned_heap()
            .map_or(self.words.len(), |abandoned| abandoned.block_words)
    }

    /// Young heap, old heap, and fragment capacity in words.
    pub fn total_heap_size_words(&self) -> usize {
        self.heap_size_words() + self.old_words.len() + self.fragment_words as usize
    }

    /// Words allocated on the active heap since the high-water mark (`p->htop - p->high_water`).
    pub fn words_since_high_water(&self) -> usize {
        self.htop.saturating_sub(self.high_water)
    }

    /// Whether a delayed collection left a young heap behind (erts `p->abandoned_heap != NULL`).
    pub fn has_abandoned_heap(&self) -> bool {
        self.abandoned
    }

    /// The young heap a delayed collection abandoned, if any (erts `p->abandoned_heap`).
    pub(crate) fn abandoned_heap(&self) -> Option<AbandonedHeap> {
        if !self.abandoned {
            return None;
        }
        self.fragments.iter().find_map(|fragment| match fragment {
            crate::heap::Fragment::Abandoned {
                block,
                used,
                high_water,
            } => Some(AbandonedHeap {
                start: block.as_ptr() as usize,
                used: *used,
                high_water: *high_water,
                block_words: block.len(),
            }),
            _ => None,
        })
    }

    /// Words below the high-water mark that the next minor collection promotes.
    // Port of erts/emulator/beam/erl_gc.c:1446-1458 (minor_collection mature_size with
    // get_orig_heap), OTP-29.1.1.
    fn mature_words(&self) -> usize {
        self.abandoned_heap()
            .map_or(self.high_water, |abandoned| abandoned.high_water)
    }

    /// Words the young generation uses: heap, fragments and an abandoned heap.
    // Port of erts/emulator/beam/erl_gc.c:606-644 (young_gen_usage), OTP-29.1.1.
    pub fn young_gen_usage(&self) -> usize {
        let abandoned = self.abandoned_heap().map_or(0, |abandoned| abandoned.used);
        self.htop
            .saturating_add(self.fragment_words as usize)
            .saturating_add(abandoned)
    }

    /// Satisfy `need` words without collecting: the young heap is abandoned and a fresh
    /// heap fragment with the stack copied into it becomes the young heap. Objects stay
    /// where they are until the next collection.
    // Port of erts/emulator/beam/erl_gc.c:500-582 (delay_garbage_collection), OTP-29.1.1.
    pub fn delay_collection(&mut self, need: usize) {
        // erl_gc.c:497 (ERTS_DELAY_GC_EXTRA_FREE).
        const DELAY_GC_EXTRA_FREE: usize = 40;
        if need == 0 {
            return;
        }
        let stack = self.stack_words();
        let words = stack + need + DELAY_GC_EXTRA_FREE + S_RESERVED;
        let mut next =
            crate::heap::WordBlock::new(words, arinsal_alloc::typed::ErtsAlcType::HEAP_FRAG);
        let next_stop = words - stack;
        let stack_move = MoveRange {
            old_start: self.words.as_ptr() as usize + self.stop * 8,
            old_end: self.words.as_ptr() as usize + self.words.len() * 8,
            new_start: next.as_ptr() as usize + next_stop * 8,
        };
        let code_ranges = crate::native_code::native_code_ranges();
        let code_ranges = code_ranges
            .as_deref()
            .map_or(&[][..], |ranges| ranges.as_slice());
        // Port of erl_gc.c:520 (copy_erlang_stack): frame pointers move with the stack.
        for (destination, &word) in next.words_mut()[next_stop..]
            .iter_mut()
            .zip(&self.words.words()[self.stop..])
        {
            *destination = match classify_stack_word(word, stack_move, code_ranges) {
                StackWord::FramePtr(address) => rebase_address(address, stack_move) as u64,
                StackWord::Term(_) | StackWord::ReturnAddr(_) => word,
            };
        }
        // erl_gc.c:563-566: the hole above htop is one heap filler (erts_write_heap_filler), not
        // a clear of every word. A scan of the abandoned heap steps over it in O(1).
        let used = self.htop;
        let hole = self.words.len().saturating_sub(used);
        if hole > 0 {
            self.words.words_mut()[used] = ((hole as u64 - 1) << 6) | crate::POS_BIG;
        }
        let abandoned = std::mem::replace(&mut self.words, next);
        if self.abandoned_heap().is_some() {
            // Port of erl_gc.c:546-558: the active heap already is a fragment; it joins
            // the mbuf list.
            self.fragment_words = self
                .fragment_words
                .saturating_add(u32::try_from(used).unwrap_or(u32::MAX));
            self.fragments.push(crate::heap::Fragment::Block {
                memory: abandoned.into_alloc_block(),
                used,
            });
        } else {
            self.abandoned = true;
            self.fragments.push(crate::heap::Fragment::Abandoned {
                block: abandoned,
                used,
                high_water: self.high_water,
            });
        }
        self.htop = 0;
        self.stop = next_stop;
        // Port of erl_gc.c:578-581: the high-water mark points into the current heap.
        self.high_water = 0;
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
        let abandoned = self.abandoned_heap();
        GcInfoWords {
            old_heap_block_size: self.old_words.len(),
            heap_block_size: self.heap_size_words(),
            mbuf_size: self
                .fragments
                .iter()
                .filter(|fragment| !matches!(fragment, crate::heap::Fragment::Abandoned { .. }))
                .map(|fragment| fragment.len())
                .sum(),
            recent_size: abandoned.map_or(self.high_water, |abandoned| abandoned.high_water),
            stack_size: self.words.len() - self.stop,
            old_heap_size: self.old_htop,
            heap_size: abandoned.map_or(self.htop, |abandoned| abandoned.used),
        }
    }

    /// [`gc_info_words`](Self::gc_info_words) as `process_info(self(), garbage_collection_info)`
    /// reports it from the running process.
    ///
    /// Port of erts/emulator/beam/erl_bif_info.c (`ERTS_PI_IX_GARBAGE_COLLECTION_INFO`) with
    /// erl_message.c (`erts_factory_proc_init`, `erts_reserve_heap__`), OTP-29.1.1: the result
    /// factory of a process asking about itself sets `HEAP_TOP` to `HEAP_LIMIT` for as long as
    /// it is open, and the result list of `result_words` is produced before the values are
    /// read. When the list fits below the limit the young heap therefore reads as full up to
    /// `HEAP_LIMIT`; when it does not, the factory releases the reservation back to the real
    /// top and the list goes to a heap fragment that `mbuf_size` already counts.
    pub fn gc_info_words_with_result(&self, result_words: usize) -> GcInfoWords {
        let mut words = self.gc_info_words();
        let Some(left) = self.halloc_words_left() else {
            return words;
        };
        if result_words <= left {
            if !self.abandoned {
                words.heap_size = self.heap_limit_words();
            }
        } else {
            words.mbuf_size += result_words;
        }
        words
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
        self.minor_since_major >= self.fullsweep_after
    }

    /// Whether a collection that starts as minor cannot be one and continues as a full sweep.
    /// Port of erts/emulator/beam/erl_gc.c:1461-1488 and 1540 (`minor_collection` returning -1
    /// when the old heap has no room for the mature region or `bin_old_vheap` reached
    /// `bin_old_vheap_sz`), OTP-29.1.1. erts traces the failed minor attempt before the major one.
    pub fn minor_falls_back_to_major(&self) -> bool {
        if self.collection_is_major() {
            return false;
        }
        self.minor_attempt_fails(self.mature_words())
    }

    /// The `minor_collection` old-heap checks for a mature region of `mature` words.
    #[inline]
    fn minor_attempt_fails(&self, mature: usize) -> bool {
        (self.old_words.is_empty() && mature == 0)
            || (!self.old_words.is_empty()
                && (mature > self.old_words.len().saturating_sub(self.old_htop)
                    || self.owners.vheap_old_size() <= self.owners.vheap_old()))
    }

    /// Whether heap fragments exceed the free young-generation area.
    /// Port of erl_gc.h:132-139 (`ERTS_IS_GC_DESIRED`), OTP-29.1.1.
    #[inline(always)]
    pub fn gc_desired(&self) -> bool {
        self.bif_free_words() < self.fragment_words as usize
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

    /// Iterate over live stack words in stack order without an indexed bounds check per word.
    #[inline]
    pub fn stack_terms(&self) -> impl ExactSizeIterator<Item = Term> + '_ {
        self.words.words()[self.stop..].iter().copied().map(Term)
    }

    /// Make the next collection sweep both generations.
    pub fn request_full_sweep(&mut self) {
        self.minor_since_major = self.fullsweep_after;
    }

    /// Read a stack word relative to the current stack pointer.
    #[inline]
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
        self.collect_with_messages(roots, extra, min_free, &mut [])
    }

    /// [`ProcessHeap::collect`] for a process with an on-heap message queue: `messages`
    /// holds the queued messages whose data is still in their own heap fragment
    /// (`ErtsMessage` with `data.attached`). Their size counts as young-generation usage,
    /// and after copying they are moved onto the new heap; each moved entry's heap
    /// becomes `None` and its term points into this heap. The second element of an
    /// entry is the sequential trace token copied into the same fragment (`NIL` when
    /// there is none); it moves with the fragment like the message term.
    // Port of erts/emulator/beam/erl_gc.c:606-644 (young_gen_usage, FS_ON_HEAP_MSGQ) and
    // erl_gc.c:1500-1501, 1947-1948 (move_msgs_to_heap after do_minor/do_major), OTP-29.1.1.
    pub fn collect_with_messages(
        &mut self,
        roots: &mut [Term],
        extra: &mut [Term],
        min_free: usize,
        messages: &mut [(Term, Term, Option<ProcessHeap>)],
    ) -> Result<GcStats, TermError> {
        // Port of erl_gc.c:803-804: the clock is read only for long_gc monitoring.
        // Microstate accounting uses the same sample (`ERTS_MSACC_IS_ENABLED`).
        let start = gc_clock_active().then(Instant::now);
        let message_words = messages
            .iter()
            .filter_map(|(_, _, heap)| heap.as_ref())
            .map(ProcessHeap::message_data_size)
            .fold(0usize, usize::saturating_add);
        let abandoned = self.abandoned_heap();
        let abandoned_mature = abandoned.map_or((0, 0), |abandoned| {
            (abandoned.start, abandoned.start + abandoned.high_water * 8)
        });
        let mature_words = abandoned.map_or(self.high_water, |abandoned| abandoned.high_water);
        let fragments = (self.fragment_words as usize)
            .saturating_add(abandoned.map_or(0, |abandoned| abandoned.used))
            .saturating_add(message_words);
        #[cfg(debug_assertions)]
        let fragment_ranges = {
            let mut ranges = self
                .fragments
                .iter()
                .map(|fragment| {
                    let start = fragment.as_ptr() as usize;
                    (start, start + fragment.len() * 8)
                })
                .collect::<Vec<_>>();
            ranges.sort_unstable_by_key(|&(start, _)| start);
            ranges
        };
        // `erl_gc.c:3285` sizes the old virtual heap from MSO(p).overhead before sweep_off_heap.
        let off_heap_overhead = self.owners.overhead();
        let major = self.collection_is_major() || self.minor_attempt_fails(mature_words);
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
        if major && self.heap_grow && capacity == self.heap_size_words() {
            capacity = next_heap_size(capacity, 1, self.min_heap_size as usize)?;
        }
        let mut next = ProcessHeap::with_words_at(capacity, self.alloc_ix);
        next.stop = capacity - stack;
        next.min_heap_size = self.min_heap_size;
        next.bin_vheap_size = self.bin_vheap_size;
        next.fullsweep_after = self.fullsweep_after;
        next.heap_grow = self.heap_grow;
        next.native_allocation = self.native_allocation;
        next.bif_hidden_words = self.bif_hidden_words;
        next.minor_since_major = if major {
            0
        } else {
            self.minor_since_major.saturating_add(1)
        };
        // Match the embedded ERTS vheap state without materializing an empty owner
        // box when a previous collection left only default values behind.
        let copy_old_owner_state = self.owners.has_collection_state();
        if copy_old_owner_state {
            next.owners.vheap.min = self.owners.vheap_min();
            next.owners.vheap.old_size = self.owners.vheap_old_size();
            next.owners.vheap.old = if major { 0 } else { self.owners.vheap_old() };
        }
        if !major {
            next.old_words = std::mem::take(&mut self.old_words);
            if next.old_words.is_empty() && mature_words > 0 {
                // Port of erl_gc.c:1471 (`erts_next_heap_size(size_before, 1)`):
                // the first old heap is one step larger than the mature data.
                let old_capacity = next_heap_size(source_words, 1, 0)?;
                next.old_words =
                    next.new_block(old_capacity, arinsal_alloc::typed::ErtsAlcType::OLD_HEAP);
            }
            next.old_htop = self.old_htop;
            if copy_old_owner_state {
                next.owners.old_external = std::mem::take(&mut self.owners.old_external);
                next.owners.old_nodes = std::mem::take(&mut self.owners.old_nodes);
                next.owners.old_funs = std::mem::take(&mut self.owners.old_funs);
                next.owners.old_exports = std::mem::take(&mut self.owners.old_exports);
            }
        }
        let mut from = std::mem::replace(self, next);
        let stack_move = MoveRange {
            old_start: from.words.as_ptr() as usize + from.stop * 8,
            old_end: from.words.as_ptr() as usize + from.words.len() * 8,
            new_start: self.words.as_ptr() as usize + self.stop * 8,
        };
        let young_start = from.words.as_ptr() as usize;
        let young = Area {
            start: young_start,
            end: young_start + from.htop * 8,
        };
        // Port of erts/emulator/beam/erl_gc.c:1402-1427 (minor_collection): the mature
        // area is below the high-water mark of the abandoned heap if there is one, else
        // of the young heap. A full sweep tenures nothing and moves the old heap too.
        let (mature, old) = if major {
            (Area::EMPTY, Area::EMPTY)
        } else {
            let mature = if abandoned.is_some() {
                Area {
                    start: abandoned_mature.0,
                    end: abandoned_mature.1,
                }
            } else {
                Area {
                    start: young_start,
                    end: young_start + from.high_water * 8,
                }
            };
            let old_start = self.old_words.as_ptr() as usize;
            (
                mature,
                Area {
                    start: old_start,
                    end: old_start + self.old_htop * 8,
                },
            )
        };
        let n_heap = self.words.as_ptr() as usize;
        let old_heap = self.old_words.as_ptr() as usize;
        let tenured_from = old_heap + self.old_htop * 8;
        let mut copier = Copier {
            n_htop: HeapTop {
                at: n_heap,
                end: n_heap + self.stop * 8,
            },
            old_htop: HeapTop {
                at: tenured_from,
                end: old_heap + self.old_words.len() * 8,
            },
            from: &mut from,
            to: self,
            major,
            young,
            mature,
            old,
            literals: {
                let (start, end) = crate::literal::literal_area();
                Area { start, end }
            },
            #[cfg(debug_assertions)]
            fragment_ranges,
            sub_bits: Vec::new(),
            error: None,
        };
        for root in roots.iter_mut().chain(extra.iter_mut()) {
            root.0 = copier.evacuate::<false>(root.0);
        }
        // Port of erts/emulator/beam/erl_gc.c:1679-1720 (do_minor root loop over the stack)
        // and erl_gc.c:520 (copy_erlang_stack), OTP-29.1.1: words with the header tag are
        // continuation pointers or frame pointers; only frame pointers into the stack move.
        let source = copier.from.words.as_ptr() as usize + copier.from.stop * 8;
        let destination = copier.to.words.as_ptr() as usize + copier.to.stop * 8;
        for i in 0..stack {
            // SAFETY: The live source and reserved destination stack slots are distinct
            // words of two live heap blocks, `stack` words each.
            unsafe {
                let raw = *((source + i * 8) as *const u64);
                *((destination + i * 8) as *mut u64) = if raw & 3 != 0 {
                    copier.evacuate::<false>(raw)
                } else if stack_move.old_start <= raw as usize
                    && (raw as usize) < stack_move.old_end
                {
                    rebase_address(raw as usize, stack_move) as u64
                } else {
                    raw
                };
            }
        }
        // Port of erts/emulator/beam/erl_gc.c:1728-1823 (do_minor), OTP-29.1.1: sweep the
        // new heap, then the tenured objects, whose young referents are tenured as well.
        copier.sweep::<false>(n_heap);
        copier.sweep::<true>(tenured_from);
        copier.to.htop = (copier.n_htop.at - n_heap) / 8;
        copier.to.old_htop = (copier.old_htop.at - old_heap) / 8;
        copier.sweep_off_heap();
        copier.finish_bits();
        copier.to.high_water = copier.to.htop;
        let error = copier.error.take();
        let promoted = ((copier.old_htop.at - tenured_from) / 8) as u64;
        drop(copier);
        // ErlHeapFragment headers live inside the fragment block in erts; here the fragment
        // list is a Vec, so keep its buffer for the next cycle instead of a malloc/free per GC.
        let mut spare = std::mem::take(&mut from.fragments);
        from.release_fragments(&mut spare);
        if self.fragments.is_empty() {
            self.fragments = spare;
        }
        from.release_all();
        if let Some(error) = error {
            return Err(error);
        }
        let adjusted = if messages.is_empty() {
            self.adjust_young_heap(major, min_free, roots, extra)?
        } else {
            self.move_msgs_to_heap(messages)?;
            // erts resize_new_heap offsets the on-heap queue with the rest of the root set.
            let mut moved = extra.to_vec();
            moved.extend(messages.iter().flat_map(|(term, token, _)| [*term, *token]));
            let adjusted = self.adjust_young_heap(major, min_free, roots, &mut moved)?;
            extra.copy_from_slice(&moved[..extra.len()]);
            let (updated_pairs, _) = moved[extra.len()..].as_chunks::<2>();
            for ((term, token, _), updated) in messages.iter_mut().zip(updated_pairs) {
                *term = updated[0];
                *token = updated[1];
            }
            adjusted
        };
        // erl_gc.c:1506/1952: `size_after` includes the moved message data.
        let copied = self.htop as u64;
        #[cfg(debug_assertions)]
        {
            let code_ranges = crate::native_code::native_code_ranges();
            let code_ranges = code_ranges
                .as_deref()
                .map_or(&[][..], |ranges| ranges.as_slice());
            self.verify_stack_words(code_ranges);
        }
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
            nanoseconds: start.map_or(0, |start| start.elapsed().as_nanos() as u64),
            // Port of erl_gc.c (`minor_collection`, `major_collection`) `gc_cost(size_after,
            // adjust_size)`, OTP-29.1.1: a minor collection counts what it tenured as well,
            // and a resized heap adds its used words.
            reductions: gc_cost(
                copied as usize + if major { 0 } else { promoted as usize },
                if adjusted { copied as usize } else { 0 },
            ),
        };
        // Port of erts/emulator/beam/erl_gc.c:3284-3289 (sweep_off_heap), OTP-29.1.1.
        if major && self.owners.is_allocated() {
            self.owners.vheap.old = 0;
            self.owners.vheap.old_size = next_vheap_size(
                off_heap_overhead,
                self.owners.vheap_old_size(),
                self.owners.vheap_min(),
            );
        }
        self.bin_vheap_size =
            next_vheap_size(self.bin_vheap, self.bin_vheap_size, self.owners.vheap_min());
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
        self.abandoned = false;
        self.fragment_words = 0;
        let exact = self
            .htop
            .saturating_add(S_RESERVED)
            .saturating_add(self.stack_words());
        if exact != self.words.len() {
            self.relocate_young(exact, roots, extra);
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
    ) -> Result<bool, TermError> {
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
            self.relocate_young(wanted, roots, extra);
            return Ok(true);
        }
        Ok(false)
    }

    /// Move queued message fragments onto the heap top, rebasing their pointers, and free
    /// the fragments. The collection sized the heap to hold them.
    // Port of erts/emulator/beam/erl_proc_sig_queue.c:8851-8889 (move_msg_to_heap,
    // erts_proc_sig_move_msgs_to_heap), erl_gc.c:2514-2611 (erts_copy_one_frag) and
    // copy.c:2049 (erts_move_multi_frags), OTP-29.1.1.
    fn move_msgs_to_heap(
        &mut self,
        messages: &mut [(Term, Term, Option<ProcessHeap>)],
    ) -> Result<(), TermError> {
        let pre_overhead = self.bin_vheap;
        for (term, token, slot) in messages.iter_mut() {
            let Some(mut fragment) = slot.take() else {
                continue;
            };
            let mut blocks: Vec<&[u64]> = vec![&fragment.words.words()[..fragment.htop]];
            for block in &fragment.fragments {
                if let crate::heap::Fragment::Block { memory, used } = block {
                    blocks.push(&memory.as_slice()[..*used]);
                }
            }
            let words = blocks.iter().map(|block| block.len()).sum::<usize>();
            if self.htop.saturating_add(words) > self.stop {
                return Err(TermError::SystemLimit);
            }
            let start = self.htop;
            let mut ranges = Vec::with_capacity(blocks.len());
            for block in blocks {
                let at = self.htop;
                self.words.words_mut()[at..at + block.len()].copy_from_slice(block);
                ranges.push(MoveRange {
                    old_start: block.as_ptr() as usize,
                    old_end: block.as_ptr() as usize + block.len() * 8,
                    new_start: self.words.as_ptr() as usize + at * 8,
                });
                self.htop += block.len();
            }
            let base = self
                .words
                .as_ptr()
                .cast::<u64>()
                .cast_mut()
                .wrapping_add(start);
            // erts_copy_one_frag offsets every non-literal pointer by the fragment's distance;
            // pointers of a multi-fragment message are rebased per source block.
            for range in &ranges {
                offset_young_objects(base, words, range.old_start, range.old_end, range.new_start);
                term.0 = offset_word(term.0, *range);
                token.0 = offset_word(token.0, *range);
            }
            // The message heap is released after this loop. Its BinRef nodes live in
            // the copied blocks too, so move both intrusive lists before adopting them.
            rebase_binref_chains_to_ranges(&mut fragment, &ranges);
            self.absorb_fragment_owners(&mut fragment);
        }
        // Port of erts/emulator/beam/erl_gc.c:203-217 (move_msgs_to_heap), OTP-29.1.1.
        if pre_overhead != self.bin_vheap {
            self.bin_vheap_size =
                next_vheap_size(self.bin_vheap, self.bin_vheap_size, self.owners.vheap_min());
        }
        Ok(())
    }

    /// Resize the young heap with `ERTS_HEAP_REALLOC`. When the block stays put, only
    /// the stack (which moved within the block) is adjusted; a moved block rebases
    /// every young pointer, the way `resize_new_heap` does.
    // Port of erts/emulator/beam/erl_gc.c:2794 (`resize_new_heap`), OTP-29.1.1.
    fn relocate_young(&mut self, new_words: usize, roots: &mut [Term], extra: &mut [Term]) {
        let stack = self.stack_words();
        debug_assert!(new_words >= self.htop.saturating_add(stack));
        let prev_len = self.words.len();
        if new_words == prev_len {
            return;
        }
        let prev_heap = self.words.as_ptr() as usize;
        let mut binref_nodes = binref_chain_nodes(self.owners.off_heap_first);
        if self.owners.wrt_bins != 0 {
            binref_nodes.extend(binref_chain_nodes(self.owners.wrt_bins));
        }
        let prev_stop = self.stop;
        let prev_stack = prev_heap + prev_stop * 8;
        let prev_stack_end = prev_heap + prev_len * 8;
        let heap_end = prev_heap + self.htop * 8;
        // Shrinking discards the tail, so the stack has to sit inside the kept prefix first.
        if new_words < prev_len {
            let new_stop = new_words - stack;
            self.words
                .words_mut()
                .copy_within(prev_stop..prev_len, new_stop);
        }
        self.words.realloc(new_words);
        let new_heap = self.words.as_ptr() as usize;
        if new_heap != prev_heap {
            rebase_binref_chains(
                self,
                &binref_nodes,
                prev_heap,
                prev_heap.saturating_add(prev_len.saturating_mul(8)),
                new_heap,
            );
        }
        let new_stop = new_words - stack;
        if new_words > prev_len {
            // Realloc leaves the stack at its old index (or copies it there). Slide it to the end.
            let old_index = prev_len - stack;
            self.words
                .words_mut()
                .copy_within(old_index..old_index + stack, new_stop);
        }
        self.stop = new_stop;
        let new_stack = new_heap + new_stop * 8;
        let heap_move = MoveRange {
            old_start: prev_heap,
            old_end: heap_end,
            new_start: new_heap,
        };
        let stack_move = MoveRange {
            old_start: prev_stack,
            old_end: prev_stack_end,
            new_start: new_stack,
        };
        if new_heap != prev_heap {
            offset_young_objects(
                self.words.as_ptr().cast::<u64>().cast_mut(),
                self.htop,
                prev_heap,
                heap_end,
                new_heap,
            );
            for term in roots.iter_mut().chain(extra.iter_mut()) {
                term.0 = offset_word(term.0, heap_move);
            }
        }
        // Untagged stack words inside the old stack are frame pointers. Return
        // addresses fail that test and `offset_word` leaves them alone, so the
        // code-range registry is not consulted. Port of erl_gc.c:3368 (`offset_stack`).
        offset_stack_slots(
            self.words
                .as_ptr()
                .cast::<u64>()
                .cast_mut()
                .wrapping_add(new_stop),
            stack,
            heap_move,
            stack_move,
            &[],
        );
        #[cfg(debug_assertions)]
        {
            let code_ranges = crate::native_code::native_code_ranges();
            let code_ranges = code_ranges
                .as_deref()
                .map_or(&[][..], |ranges| ranges.as_slice());
            self.verify_stack_words(code_ranges);
        }
    }

    #[cfg(debug_assertions)]
    fn verify_stack_words(&self, code_ranges: &[(usize, usize)]) {
        let base = self.words.as_ptr() as usize;
        let stack_start = base + self.stop * 8;
        let stack_end = base + self.words.len() * 8;
        let stack_range = MoveRange {
            old_start: stack_start,
            old_end: stack_end,
            new_start: stack_start,
        };
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
                    panic!("frame pointer {address:#x} found on the live stack")
                }
            }
        }
    }
}

#[derive(Clone, Copy)]
struct MoveRange {
    old_start: usize,
    old_end: usize,
    new_start: usize,
}

// Port of erts/emulator/beam/erl_gc.c:2514-2611 (erts_copy_one_frag off-heap links),
// OTP-29.1.1. The source fragment is freed after its terms and off-heap ownership are adopted.
fn rebase_binref_chains_to_ranges(heap: &mut ProcessHeap, ranges: &[MoveRange]) {
    let Some(owners) = heap.owners.as_mut() else {
        return;
    };
    let nodes = binref_chain_nodes(owners.off_heap_first)
        .into_iter()
        .chain(binref_chain_nodes(owners.wrt_bins))
        .collect::<Vec<_>>();
    let rebase = |address: usize| {
        if address == 0 {
            return 0;
        }
        ranges
            .iter()
            .find_map(|range| {
                (address >= range.old_start && address < range.old_end)
                    .then_some(range.new_start + address - range.old_start)
            })
            .expect("message BinRef chain points outside copied heap fragments")
    };
    owners.off_heap_first = rebase(owners.off_heap_first);
    owners.wrt_bins = rebase(owners.wrt_bins);
    for source in nodes {
        let destination = rebase(source) as *mut u64;
        let next = crate::heap::load((source as *const u64).wrapping_add(2)) as usize;
        crate::heap::store(destination.wrapping_add(2), rebase(next) as u64);
    }
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

/// Words of the initial heap of a spawned process whose arguments and reserved words need
/// `heap_need`, with `min_heap` the process's minimum heap size.
///
/// Port of erts/emulator/beam/erl_process.c:12587-12591 (erl_create_process), OTP-29.1.1.
pub fn spawned_heap_words(heap_need: usize, min_heap: usize) -> Result<usize, TermError> {
    if heap_need < min_heap {
        Ok(min_heap)
    } else {
        next_heap_size(heap_need, 0, 0)
    }
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
        assert_eq!(heap.fragment_words, 136);

        let mut dirty_shadow = ProcessHeap::with_words(256);
        dirty_shadow.htop = 9;
        dirty_shadow.gc_fragment(5);
        heap.adopt_message_fragment(dirty_shadow).unwrap();
        assert_eq!(heap.fragment_words, 150);
    }

    #[test]
    fn list_that_fits_the_heap_lands_entirely_on_it() {
        let mut heap = ProcessHeap::with_words(64);
        crate::TermBuilder::new(&mut heap)
            .string_to_list("12345")
            .unwrap();
        assert_eq!(heap.fragment_words, 0);
        assert_eq!(heap.used_words(), 10);
    }

    #[test]
    fn adopted_message_fragment_exposes_only_the_words_below_its_heap_top() {
        // The message heap block is not cleared; words above its heap top are not objects, so a
        // literal-area scan must not walk them (heap fragment `used_size`).
        let mut message_heap = ProcessHeap::with_words(256);
        message_heap.htop = 3;
        let mut heap = ProcessHeap::with_words(64);
        heap.adopt_message_fragment(message_heap).unwrap();
        assert_eq!(heap.fragments.len(), 1);
        assert_eq!(heap.fragments[0].len(), 3);
        assert_eq!(heap.message_data_size(), 3);
    }

    #[test]
    fn minor_collection_does_not_reallocate_an_empty_owner_box() {
        let mut heap = ProcessHeap::with_words(128);
        heap.old_words = ProcessHeap::with_words(128).words;
        heap.owners.vheap.old = 0;

        heap.collect(&mut [], &mut [], 0).unwrap();

        assert!(!heap.collection_is_major());
        assert!(!heap.owners.is_allocated());
    }

    #[test]
    fn old_heap_capacity_failure_stays_a_minor_attempt_until_minor_collection() {
        let mut heap = ProcessHeap::with_words(512);
        heap.old_words = ProcessHeap::with_words(100).words;
        heap.old_htop = 25;
        heap.high_water = 80;

        assert!(!heap.collection_is_major());
        assert!(heap.minor_falls_back_to_major());

        heap.old_words = ProcessHeap::with_words(128).words;
        assert!(!heap.minor_falls_back_to_major());

        heap.request_full_sweep();
        assert!(heap.collection_is_major());
        assert!(!heap.minor_falls_back_to_major());
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
