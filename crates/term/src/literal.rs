//! Shared literal virtual range and the collector's literal purge area.
//!
//! erts allocates literal blocks from `literal_alloc` carriers inside one 1-GiB
//! range. `erts_is_literal` checks that range; the registry here tracks only the
//! area currently being purged by literal-aware copies.
// Port of erts/emulator/beam/global.h:1568 (erts_is_literal) and
// erts/emulator/beam/global.h:1116 (INITIALIZE_LITERAL_PURGE_AREA), OTP-29.1.1.
use arinsal_alloc::alloc_util::{AllocUtil, Allocation};
use arinsal_alloc::raw::RawRegion;
use std::cell::RefCell;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock, RwLock};

const LITERAL_VIRTUAL_AREA_SIZE: usize = 1024 * 1024 * 1024;
const LITERAL_AREA_HEADER_WORDS: usize = 2;

static GENERATION: AtomicU64 = AtomicU64::new(1);

/// Number of purge ranges in the registry, readable without the registry or its thread cache.
/// Port of erts/emulator/beam/copy.c (the purge area globals, null unless a literal area is
/// being purged), OTP-29.1.1.
static PURGE_RANGES: AtomicUsize = AtomicUsize::new(0);

thread_local! {
    static CACHE: RefCell<(u64, Arc<[LiteralRange]>)> = RefCell::new((0, Arc::from([])));
}

#[derive(Clone, Copy, Debug)]
struct LiteralRange {
    start: usize,
    end: usize,
}

fn registry() -> &'static RwLock<Arc<[LiteralRange]>> {
    static RANGES: OnceLock<RwLock<Arc<[LiteralRange]>>> = OnceLock::new();
    RANGES.get_or_init(|| RwLock::new(Arc::from(Vec::new())))
}

struct LiteralArena {
    allocator: AllocUtil,
}

impl LiteralArena {
    fn new() -> Result<Self, arinsal_alloc::raw::MapError> {
        // Port of erts/emulator/sys/common/erl_mmap.h:99 and erl_mmap.c:2447-2449,
        // OTP-29.1.1: every literal allocation occupies this one 1-GiB virtual range.
        let region = RawRegion::map(LITERAL_VIRTUAL_AREA_SIZE)?;
        let start = region.as_ptr() as usize;
        let end = start + region.len();
        let _ = literal_bounds().set((start, end));
        Ok(Self {
            allocator: AllocUtil::new_literal_alloc(region),
        })
    }

    fn allocate(&mut self, words: usize) -> Option<LiteralChunk> {
        // Port of ERTS_LITERAL_AREA_ALLOC_SIZE, global.h:946-950, and the
        // persistent_term allocation, erl_bif_persistent.c:754, OTP-29.1.1.
        let payload_words = words.checked_add(LITERAL_AREA_HEADER_WORDS)?;
        let bytes = payload_words.checked_mul(std::mem::size_of::<u64>())?;
        let allocation = self.allocator.alloc(bytes).ok()?;
        let base = self.allocator.allocation_ptr(allocation).ok()? as usize;
        let end = base.checked_add(bytes)?;
        let header = self.allocator.allocation_bytes_mut(allocation).ok()?;
        header.get_mut(..8)?.fill(0);
        header.get_mut(8..16)?.copy_from_slice(&end.to_ne_bytes());
        Some(LiteralChunk {
            allocation,
            base,
            words,
        })
    }
}

fn arena() -> Option<&'static Mutex<LiteralArena>> {
    static ARENA: OnceLock<Option<Mutex<LiteralArena>>> = OnceLock::new();
    ARENA
        .get_or_init(|| LiteralArena::new().ok().map(Mutex::new))
        .as_ref()
}

fn literal_bounds() -> &'static OnceLock<(usize, usize)> {
    static BOUNDS: OnceLock<(usize, usize)> = OnceLock::new();
    &BOUNDS
}

/// One stable chunk allocated inside the shared literal virtual range.
pub(crate) struct LiteralChunk {
    allocation: Allocation,
    base: usize,
    words: usize,
}

impl LiteralChunk {
    pub(crate) fn as_ptr(&self) -> *mut u64 {
        (self.base as *mut u64).wrapping_add(LITERAL_AREA_HEADER_WORDS)
    }

    pub(crate) fn capacity(&self) -> usize {
        self.words
    }

    pub(crate) fn initialize_words(&mut self, start: usize, end: usize) -> bool {
        if start > end || end > self.words {
            return false;
        }
        let Some(area_start) = LITERAL_AREA_HEADER_WORDS.checked_mul(8) else {
            return false;
        };
        let Some(from) = start
            .checked_mul(8)
            .and_then(|offset| area_start.checked_add(offset))
        else {
            return false;
        };
        let Some(to) = end
            .checked_mul(8)
            .and_then(|offset| area_start.checked_add(offset))
        else {
            return false;
        };
        let Some(arena) = arena() else {
            return false;
        };
        let mut arena = arena.lock().expect("literal arena poisoned");
        let Ok(bytes) = arena.allocator.allocation_bytes_mut(self.allocation) else {
            return false;
        };
        let Some(range) = bytes.get_mut(from..to) else {
            return false;
        };
        range.fill(0);
        true
    }
}

impl Drop for LiteralChunk {
    fn drop(&mut self) {
        let Some(arena) = arena() else { return };
        arena
            .lock()
            .expect("literal arena poisoned")
            .allocator
            .free(self.allocation)
            .expect("live literal allocation");
    }
}

pub(crate) fn allocate_chunk(words: usize) -> Option<LiteralChunk> {
    arena()?
        .lock()
        .expect("literal arena poisoned")
        .allocate(words)
}

fn update(edit: impl FnOnce(&mut Vec<LiteralRange>)) {
    let mut slot = registry().write().expect("literal registry poisoned");
    let mut ranges = slot.to_vec();
    edit(&mut ranges);
    PURGE_RANGES.store(ranges.len(), Ordering::Release);
    *slot = Arc::from(ranges);
    GENERATION.fetch_add(1, Ordering::Release);
}

fn snapshot() -> Arc<[LiteralRange]> {
    let generation = GENERATION.load(Ordering::Acquire);
    CACHE.with(|slot| {
        let mut slot = slot.borrow_mut();
        if slot.0 != generation {
            slot.1 = Arc::clone(&registry().read().expect("literal registry poisoned"));
            slot.0 = generation;
        }
        Arc::clone(&slot.1)
    })
}

/// The reserved literal range as `(start, end)`, or `(0, 0)` before any literal exists.
// Mirrors `erts_literals_start` and `erts_literals_size` in erl_alloc.h (OTP-29.1.1): a
// collection reads the globals once and tests every pointer against them.
#[inline]
pub(crate) fn literal_area() -> (usize, usize) {
    literal_bounds().get().copied().unwrap_or((0, 0))
}

fn precise(address: usize) -> bool {
    // Port of erts/emulator/beam/erl_alloc.h:337-348 (`ErtsInArea`), OTP-29.1.1.
    literal_bounds()
        .get()
        .is_some_and(|&(start, end)| address.wrapping_sub(start) < end - start)
}

/// Mark or unmark the chunk ranges of the literal area being released by the
/// literal-area collector. Terms in a marked range are copied by
/// literal-aware copies instead of being shared.
// Port of erts/emulator/beam/beam_bif_load.c:1794 (rla_switch_area publishing
// ERTS_COPY_LITERAL_AREA), OTP-29.1.1.
pub fn set_literal_purge_area(area: &[(usize, usize)], purge: bool) {
    update(|ranges| {
        if purge {
            for &(start, end) in area {
                if ranges
                    .iter()
                    .any(|range| range.start == start && range.end == end)
                {
                    continue;
                }
                let at = ranges.partition_point(|range| range.start < start);
                ranges.insert(at, LiteralRange { start, end });
            }
        } else {
            ranges.retain(|range| !area.contains(&(range.start, range.end)));
        }
    });
}

/// Whether `ptr` lies in the reserved literal range.
pub(crate) fn is_literal_pointer(ptr: *const u64) -> bool {
    is_literal_address(ptr as usize)
}

/// `erts_is_literal` for an address: the empty tuple or one range comparison.
// Port of erts/emulator/beam/erl_alloc.h:337 (`erts_is_in_literal_range`) and
// global.h:1572 (`erts_is_literal`), OTP-29.1.1.
#[inline]
pub(crate) fn is_literal_address(address: usize) -> bool {
    if address == std::ptr::from_ref(&crate::EMPTY_TUPLE) as usize {
        return true;
    }
    precise(address)
}

fn find(ranges: &[LiteralRange], address: usize) -> Option<&LiteralRange> {
    let at = ranges.partition_point(|range| range.start <= address);
    ranges[..at].last().filter(|range| address < range.end)
}

/// One consistent view of the collector's purge ranges during a copy.
#[derive(Clone)]
pub struct LiteralAreas {
    ranges: Option<Arc<[LiteralRange]>>,
}

impl LiteralAreas {
    /// Snapshot the current literal purge area. Without a purge in progress there is nothing
    /// to snapshot: the view is empty and no registry, thread cache or reference count is
    /// touched.
    #[inline]
    pub fn current() -> Self {
        if PURGE_RANGES.load(Ordering::Acquire) == 0 {
            return Self { ranges: None };
        }
        Self {
            ranges: Some(snapshot()),
        }
    }

    /// Whether a copy keeps `term` by reference: it is a literal outside the purge area.
    // Port of erts/emulator/beam/copy.c:83-86 (`in_literal_purge_area`) and
    // copy.c:105 (`erts_is_literal(obj,ptr) && !in_literal_purge_area(ptr)`), OTP-29.1.1.
    // A null purge pointer makes the range test false, so only `erts_is_literal` runs.
    #[inline]
    pub fn keeps(&self, address: u64) -> bool {
        if !is_literal_address(address as usize) {
            return false;
        }
        self.ranges
            .as_deref()
            .is_none_or(|ranges| ranges.is_empty() || find(ranges, address as usize).is_none())
    }

    /// Whether `term`'s object lies in any literal area, including the purge area.
    // Port of erts/emulator/beam/global.h:1568 (`erts_is_literal`), OTP-29.1.1.
    pub fn is_literal(&self, address: u64) -> bool {
        is_literal_address(address as usize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::HeapAlloc;

    #[test]
    fn literal_chunks_share_the_reserved_range_and_keep_purge_tracking() {
        let mut heap = crate::VecHeap::new_literal();
        let first = heap.alloc(1024).unwrap() as usize;
        heap.alloc(1025).unwrap();

        let (space_start, space_end) = *literal_bounds().get().unwrap();
        let ranges = heap.pointer_ranges();
        assert_eq!(ranges.len(), 2);
        for &(start, end) in &ranges {
            assert!(start >= space_start && end <= space_end);
            assert!(is_literal_address(start));
            assert!(is_literal_address(end - 1));
        }
        assert!(LiteralAreas::current().keeps(first as u64));

        set_literal_purge_area(&ranges, true);
        assert!(!LiteralAreas::current().keeps(first as u64));
        set_literal_purge_area(&ranges, false);
        assert!(LiteralAreas::current().keeps(first as u64));

        drop(heap);
        assert!(is_literal_address(first));
        assert!(LiteralAreas::current().is_literal(first as u64));
    }
}
