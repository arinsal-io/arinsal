//! Registry of literal areas (module literals and persistent-term areas).
//!
//! erts allocates every literal in `literal_alloc` and answers `erts_is_literal`
//! with an address-range check (`ErtsInArea`). Arinsal's literal heaps are
//! ordinary chunks, so their ranges are kept in one sorted, immutable snapshot
//! that copy operations read once and use for both sizing and copying.
// Port of erts/emulator/beam/global.h:1568 (erts_is_literal) and
// erts/emulator/beam/global.h:1116 (INITIALIZE_LITERAL_PURGE_AREA), OTP-29.1.1.
use std::cell::RefCell;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock, RwLock};

/// Hull of every literal range ever published. A miss is exact (the address was
/// never in a literal chunk). A hit falls through to the precise range list.
/// erts answers the same question with one super-carrier compare
/// (`erts_is_in_literal_range`).
static HULL_START: AtomicUsize = AtomicUsize::new(usize::MAX);
static HULL_END: AtomicUsize = AtomicUsize::new(0);
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

fn update(edit: impl FnOnce(&mut Vec<LiteralRange>)) {
    let mut slot = registry().write().expect("literal registry poisoned");
    let mut ranges = slot.to_vec();
    edit(&mut ranges);
    // Widen the hull before publishing the list, so a concurrent check cannot
    // miss a range that is already visible. The hull never shrinks: a freed
    // chunk stays inside it and the precise list rejects it.
    publish_hull(&ranges);
    *slot = Arc::from(ranges);
    GENERATION.fetch_add(1, Ordering::Release);
}

fn publish_hull(ranges: &[LiteralRange]) {
    let Some(start) = ranges.iter().map(|range| range.start).min() else {
        return;
    };
    let end = ranges.iter().map(|range| range.end).max().unwrap_or(start);
    HULL_START.fetch_min(start, Ordering::Release);
    HULL_END.fetch_max(end, Ordering::Release);
}

#[inline]
fn in_hull(address: usize) -> bool {
    let end = HULL_END.load(Ordering::Acquire);
    if end == 0 {
        return false;
    }
    let start = HULL_START.load(Ordering::Acquire);
    address >= start && address < end
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
    let generation = GENERATION.load(Ordering::Acquire);
    CACHE.with(|slot| {
        let mut slot = slot.borrow_mut();
        if slot.0 != generation {
            slot.1 = Arc::clone(&registry().read().expect("literal registry poisoned"));
            slot.0 = generation;
        }
        find(&slot.1, address).is_some()
    })
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

/// `erts_is_literal` for an address: the empty tuple, or a pointer inside the
/// literal hull that the precise range list confirms.
// Port of erts/emulator/beam/erl_alloc.h:337 (`erts_is_in_literal_range`) and
// global.h:1572 (`erts_is_literal`), OTP-29.1.1.
#[inline]
pub(crate) fn is_literal_address(address: usize) -> bool {
    if address == std::ptr::from_ref(&crate::EMPTY_TUPLE) as usize {
        return true;
    }
    if !in_hull(address) {
        return false;
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
