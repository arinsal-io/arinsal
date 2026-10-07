//! Registry of literal areas (module literals and persistent-term areas).
//!
//! erts allocates every literal in `literal_alloc` and answers `erts_is_literal`
//! with an address-range check (`ErtsInArea`). Arinsal's literal heaps are
//! ordinary chunks, so their ranges are kept in one sorted, immutable snapshot
//! that copy operations read once and use for both sizing and copying.
// Port of erts/emulator/beam/global.h:1568 (erts_is_literal) and
// erts/emulator/beam/global.h:1116 (INITIALIZE_LITERAL_PURGE_AREA), OTP-29.1.1.
use std::sync::{Arc, OnceLock, RwLock};

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
    *slot = Arc::from(ranges);
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
    let ranges = registry().read().expect("literal registry poisoned");
    find(&ranges, ptr as usize).is_some()
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
        Self {
            ranges: Arc::clone(&registry().read().expect("literal registry poisoned")),
        }
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
