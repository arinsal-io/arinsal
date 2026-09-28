//! Native code ranges used to distinguish BeamAsm continuation pointers from terms.

use std::sync::{OnceLock, RwLock, RwLockReadGuard};

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
    if ranges
        .iter()
        .any(|&(registered_start, registered_end)| start < registered_end && registered_start < end)
    {
        return Err("native code ranges must not overlap");
    }
    ranges.push((start, end));
    ranges.sort_unstable_by_key(|range| range.0);
    Ok(())
}

/// Whether an address lies in a registered native code range.
// Port of erts/emulator/beam/erl_term.h:1375-1379 (`is_CP`), OTP-29.1.1.
pub fn is_native_code_pointer(address: usize) -> bool {
    let Ok(ranges) = ranges().read() else {
        return false;
    };
    let index = ranges.partition_point(|range| range.0 <= address);
    index > 0 && address < ranges[index - 1].1
}

pub(crate) fn native_code_ranges() -> Option<RwLockReadGuard<'static, Vec<(usize, usize)>>> {
    ranges().read().ok()
}
