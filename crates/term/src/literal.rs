//! Shared literal virtual range and registry of module/persistent-term areas.
//!
//! erts allocates every literal inside one 1-GiB range and answers `erts_is_literal`
//! with a single `ErtsInArea` check. The area registry here tracks purge state for
//! literal-aware copies; collector membership uses the shared range directly.
// Port of erts/emulator/beam/global.h:1568 (erts_is_literal) and
// erts/emulator/beam/global.h:1116 (INITIALIZE_LITERAL_PURGE_AREA), OTP-29.1.1.
use std::cell::RefCell;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, RwLock};

const LITERAL_VIRTUAL_AREA_SIZE: usize = 1024 * 1024 * 1024;

static GENERATION: AtomicU64 = AtomicU64::new(1);

thread_local! {
    static CACHE: RefCell<(u64, Arc<[LiteralRange]>)> = RefCell::new((0, Arc::from([])));
}

#[derive(Clone, Copy, Debug)]
struct LiteralRange {
    start: usize,
    end: usize,
    /// The range belongs to the area the literal collector is currently releasing
    /// (`ERTS_COPY_LITERAL_AREA()`); copies must not keep references into it.
    purge: bool,
}

fn registry() -> &'static RwLock<Arc<[LiteralRange]>> {
    static RANGES: OnceLock<RwLock<Arc<[LiteralRange]>>> = OnceLock::new();
    RANGES.get_or_init(|| RwLock::new(Arc::from(Vec::new())))
}

struct LiteralArena {
    free: Vec<(usize, arinsal_alloc::raw::RawRegion)>,
}

impl LiteralArena {
    fn new() -> Result<Self, arinsal_alloc::raw::MapError> {
        // Port of erts/emulator/sys/common/erl_mmap.h:99 and erl_mmap.c:2447-2449,
        // OTP-29.1.1: every literal allocation occupies this one 1-GiB virtual range.
        let region = arinsal_alloc::raw::RawRegion::map(LITERAL_VIRTUAL_AREA_SIZE)?;
        let start = region.as_ptr() as usize;
        let end = start + region.len();
        let _ = literal_bounds().set((start, end));
        Ok(Self {
            free: vec![(start, region)],
        })
    }

    fn allocate(&mut self, words: usize) -> Option<LiteralChunk> {
        let bytes = words.checked_mul(std::mem::size_of::<u64>())?;
        let page = arinsal_alloc::raw::page_size();
        let mapped_bytes = bytes.checked_add(page - 1)? / page * page;
        let index = self
            .free
            .iter()
            .position(|(_, region)| region.len() >= mapped_bytes)?;
        let (start, region) = self.free.swap_remove(index);
        let allocated = if region.len() == mapped_bytes {
            region
        } else {
            let (allocated, tail) = region.split_at(mapped_bytes).ok()?;
            self.free.push((start + mapped_bytes, tail));
            allocated
        };
        Some(LiteralChunk {
            region: Some(allocated),
            words,
        })
    }

    fn release(&mut self, region: arinsal_alloc::raw::RawRegion) {
        self.free.push((region.as_ptr() as usize, region));
        self.free.sort_unstable_by_key(|(start, _)| *start);
        let mut merged: Vec<(usize, arinsal_alloc::raw::RawRegion)> = Vec::new();
        for (start, region) in std::mem::take(&mut self.free) {
            if let Some((previous_start, previous)) = merged.pop() {
                match previous.merge_adjacent(region) {
                    Ok(joined) => merged.push((previous_start, joined)),
                    Err((previous, region)) => {
                        merged.push((previous_start, previous));
                        merged.push((start, region));
                    }
                }
            } else {
                merged.push((start, region));
            }
        }
        self.free = merged;
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
    region: Option<arinsal_alloc::raw::RawRegion>,
    words: usize,
}

impl LiteralChunk {
    pub(crate) fn as_ptr(&self) -> *mut u64 {
        self.region
            .as_ref()
            .expect("live literal chunk")
            .as_ptr()
            .cast()
    }

    pub(crate) fn capacity(&self) -> usize {
        self.words
    }

    pub(crate) fn initialize_words(&mut self, start: usize, end: usize) -> bool {
        if start > end || end > self.words {
            return false;
        }
        let Some(bytes) = self
            .region
            .as_mut()
            .and_then(arinsal_alloc::raw::RawRegion::bytes_mut)
        else {
            return false;
        };
        let Some(range) = bytes.get_mut(start * 8..end * 8) else {
            return false;
        };
        range.fill(0);
        true
    }
}

impl Drop for LiteralChunk {
    fn drop(&mut self) {
        if let Some(region) = self.region.take()
            && let Some(arena) = arena()
        {
            arena
                .lock()
                .expect("literal arena poisoned")
                .release(region);
        }
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

fn precise(address: usize) -> bool {
    // Port of erts/emulator/beam/erl_alloc.h:337-348 (`ErtsInArea`), OTP-29.1.1.
    literal_bounds()
        .get()
        .is_some_and(|&(start, end)| address.wrapping_sub(start) < end - start)
}

pub(crate) fn register(start: usize, end: usize) {
    update(|ranges| {
        let at = ranges.partition_point(|range| range.start < start);
        ranges.insert(
            at,
            LiteralRange {
                start,
                end,
                purge: false,
            },
        );
    });
}

pub(crate) fn unregister(start: usize, end: usize) {
    update(|ranges| ranges.retain(|range| range.start != start || range.end != end));
}

/// Mark or unmark the chunk ranges of the literal area being released by the
/// literal-area collector. Terms in a marked range are copied by
/// literal-aware copies instead of being shared.
// Port of erts/emulator/beam/beam_bif_load.c:1794 (rla_switch_area publishing
// ERTS_COPY_LITERAL_AREA), OTP-29.1.1.
pub fn set_literal_purge_area(area: &[(usize, usize)], purge: bool) {
    update(|ranges| {
        for range in ranges.iter_mut() {
            if area.contains(&(range.start, range.end)) {
                range.purge = purge;
            }
        }
    });
}

/// Whether `ptr` lies in any registered literal area.
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

/// One consistent view of the literal ranges, the `erts_literal_area_t` of a copy.
#[derive(Clone)]
pub struct LiteralAreas {
    ranges: Arc<[LiteralRange]>,
}

impl LiteralAreas {
    /// Snapshot the currently registered literal areas and the purge area.
    pub fn current() -> Self {
        Self { ranges: snapshot() }
    }

    /// Whether a copy keeps `term` by reference: it is a literal outside the purge area.
    // Port of erts/emulator/beam/copy.c:105 (`erts_is_literal(obj,ptr) &&
    // !in_literal_purge_area(ptr)`), OTP-29.1.1.
    pub fn keeps(&self, address: u64) -> bool {
        !self.ranges.is_empty()
            && find(&self.ranges, address as usize).is_some_and(|range| !range.purge)
    }

    /// Whether `term`'s object lies in any literal area, including the purge area.
    pub fn is_literal(&self, address: u64) -> bool {
        !self.ranges.is_empty() && find(&self.ranges, address as usize).is_some()
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
        assert!(!LiteralAreas::current().is_literal(first as u64));
    }
}
