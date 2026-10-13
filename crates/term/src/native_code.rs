//! Native code ranges used to distinguish BeamAsm continuation pointers from terms.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{OnceLock, RwLock, RwLockReadGuard};

/// Conservative hull of every range ever registered; lets stack scans reject most words
/// without taking the registry lock.
static HULL_START: AtomicUsize = AtomicUsize::new(usize::MAX);
static HULL_END: AtomicUsize = AtomicUsize::new(0);

/// Whether `address` may lie in a registered native code range (lock-free, no false negatives).
#[inline]
pub fn may_be_native_code_pointer(address: usize) -> bool {
    address >= HULL_START.load(Ordering::Acquire) && address < HULL_END.load(Ordering::Acquire)
}

/// Tests whether a stack word has the continuation-pointer tag bits.
// Port of erts/emulator/beam/erl_term.h:1378-1379 (`is_CP`), OTP-29.1.1.
#[inline]
pub fn is_cp(word: u64) -> bool {
    word & 3 == 0
}

fn ranges() -> &'static RwLock<Vec<(usize, usize)>> {
    static RANGES: OnceLock<RwLock<Vec<(usize, usize)>>> = OnceLock::new();
    RANGES.get_or_init(|| RwLock::new(Vec::new()))
}

/// Register a half-open native code range whose return addresses may appear on Erlang stacks.
pub fn register_native_code_range(start: usize, end: usize) -> Result<(), &'static str> {
    if start >= end {
        return Err("native code range must be non-empty");
    }
    let mut ranges = ranges()
        .write()
        .map_err(|_| "native code registry poisoned")?;
    // The registry stays sorted by start: only the neighbours can overlap.
    let index = ranges.partition_point(|range| range.0 < start);
    let overlaps_previous = index
        .checked_sub(1)
        .and_then(|previous| ranges.get(previous))
        .is_some_and(|&(_, previous_end)| start < previous_end);
    let overlaps_next = ranges
        .get(index)
        .is_some_and(|&(next_start, _)| next_start < end);
    if overlaps_previous || overlaps_next {
        return Err("native code ranges must not overlap");
    }
    ranges.insert(index, (start, end));
    HULL_START.fetch_min(start, Ordering::AcqRel);
    HULL_END.fetch_max(end, Ordering::AcqRel);
    Ok(())
}

/// Remove a native code range registered by [`register_native_code_range`] once its code is
/// purged and no stack can hold its return addresses.
pub fn unregister_native_code_range(start: usize, end: usize) {
    if let Ok(mut ranges) = ranges().write() {
        ranges.retain(|&range| range != (start, end));
    }
}

/// Whether an address lies in a registered native code range.
// Port of erts/emulator/beam/erl_term.h:1375-1379 (`is_CP`), OTP-29.1.1.
pub fn is_native_code_pointer(address: usize) -> bool {
    if !may_be_native_code_pointer(address) {
        return false;
    }
    let Ok(ranges) = ranges().read() else {
        return false;
    };
    let index = ranges.partition_point(|range| range.0 <= address);
    index > 0 && address < ranges[index - 1].1
}

pub(crate) fn native_code_ranges() -> Option<RwLockReadGuard<'static, Vec<(usize, usize)>>> {
    ranges().read().ok()
}
