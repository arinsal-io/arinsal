//! Per-scheduler reference and unique-integer state.
//!
//! Port of erts/emulator/beam/erl_bif_unique.c and erl_bif_unique.h, OTP-29.1.1.

#[path = "unique/raw.rs"]
mod raw;

use std::cell::Cell;
use std::rc::Rc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Low 18 bits of a reference number (`REF_MASK` in `erl_term.h`).
const REF_MASK: u64 = (1 << 18) - 1;
/// Scheduler ID field in `ref[1]` (`ERTS_REF1_THR_ID_MASK__`).
const THR_ID_MASK: u32 = (1 << 16) - 1;
/// Counter bits held in the three reference words.
const REF1_NUM_MASK: u32 = !(THR_ID_MASK | (1 << 17) | (1 << 16));
/// Counter bits in the internal ordinary-reference identifier.
const VALUE_BITS: u32 = 48;
const VALUE_MASK: u64 = (1 << VALUE_BITS) - 1;
const MIN_SMALL: i128 = -(1_i128 << 59);

/// The `thr_id`, `unique` and `ref` fields of a scheduler's `SchedRefUnique`.
///
/// They are part of the scheduler's one data block (`crate::SchedRefUnique`). The
/// thread-local binding is erts' `erts_get_scheduler_data()` for code that has no `esdp`
/// at hand (VM and NIF calls); it holds a counted handle so the scheduler loop keeps
/// its `&mut esdp`.
// Port of erts/emulator/beam/erl_process.h:718-720 (`SchedRefUnique.thr_id`, `.unique`,
// `.ref`) and erl_process.c (`init_scheduler_data`), OTP-29.1.1.
pub struct SchedRefUnique {
    thr_id: Cell<u32>,
    ref_n: Cell<u64>,
    unique_n: Cell<u64>,
}

impl Default for SchedRefUnique {
    fn default() -> Self {
        Self {
            thr_id: Cell::new(0),
            ref_n: Cell::new(initial_ref()),
            unique_n: Cell::new(0),
        }
    }
}

impl SchedRefUnique {
    /// Allocate the service fields for one normal scheduler.
    pub fn new_normal(thr_id: u32) -> Self {
        Self {
            thr_id: Cell::new(thr_id & THR_ID_MASK),
            ..Self::default()
        }
    }

    /// Allocate the service fields for one dirty scheduler with its erts thread ID.
    pub fn new_dirty(thr_id: u32) -> Self {
        Self {
            thr_id: Cell::new(thr_id & THR_ID_MASK),
            ..Self::default()
        }
    }

    /// Bind these scheduler-owned counters for the lifetime of its worker thread.
    pub fn bind(self: &Rc<Self>) -> SchedulerDataGuard {
        SchedulerDataGuard {
            previous: raw::replace(self),
            _data: Rc::clone(self),
        }
    }

    fn bump_ref_words(&self) -> [u32; 3] {
        let value = self.ref_n.get();
        self.ref_n.set(value.wrapping_add(1));
        set_ref_numbers(self.thr_id.get(), value)
    }

    fn bump_unique(&self, positive: bool) -> i128 {
        let value = self.unique_n.get();
        self.unique_n.set(value.wrapping_add(1));
        combine_unique(
            u64::from(self.thr_id.get()),
            value,
            positive,
            unique_layout(),
        )
    }
}

/// Restores the previous scheduler binding when a task turn returns.
pub struct SchedulerDataGuard {
    previous: *const SchedRefUnique,
    /// Keeps the bound counters alive; `Rc` also keeps the guard on its thread.
    _data: Rc<SchedRefUnique>,
}

impl Drop for SchedulerDataGuard {
    fn drop(&mut self) {
        raw::restore(self.previous);
    }
}

// Port of erts/emulator/beam/erl_bif_unique.c (`init_reference`), OTP-29.1.1.
fn initial_ref() -> u64 {
    static INIT: OnceLock<u64> = OnceLock::new();
    *INIT.get_or_init(|| {
        let elapsed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        let mut value = elapsed.as_secs();
        let micros = elapsed.subsec_micros();
        value |= u64::from(micros) << 32;
        value = value.wrapping_mul(268_438_039);
        value = value.wrapping_add(u64::from(micros));
        value & VALUE_MASK
    })
}

fn ref_key(thr_id: u32, value: u64) -> u64 {
    (u64::from(thr_id & THR_ID_MASK) << VALUE_BITS) | (value & VALUE_MASK)
}

/// Reference words for an ordinary reference identifier.
// Port of erts/emulator/beam/erl_bif_unique.h (`erts_set_ref_numbers`), OTP-29.1.1.
#[inline]
pub fn ordinary_ref_words(id: u64) -> [u32; 3] {
    let thr_id = (id >> VALUE_BITS) as u32;
    let value = id & VALUE_MASK;
    set_ref_numbers(thr_id, value)
}

/// Identifier recovered from three ordinary-reference words.
// Port of erts/emulator/beam/erl_bif_unique.h (`erts_get_ref_numbers_value`), OTP-29.1.1.
#[inline]
pub fn ordinary_ref_key(ids: [u32; 3]) -> u64 {
    let thr_id = ids[1] & THR_ID_MASK;
    let value = (u64::from(ids[2]) << 32)
        | (u64::from(ids[1]) & u64::from(REF1_NUM_MASK))
        | (u64::from(ids[0]) & REF_MASK);
    ref_key(thr_id, value)
}

#[inline]
fn set_ref_numbers(thr_id: u32, value: u64) -> [u32; 3] {
    [
        (value & REF_MASK) as u32,
        (value as u32 & REF1_NUM_MASK) | (thr_id & THR_ID_MASK),
        (value >> 32) as u32,
    ]
}

/// Next ordinary-reference words from the current scheduler, or the global counter off-scheduler.
// Port of erts/emulator/beam/erl_bif_unique.c (`make_ref_in_array`) and erl_bif_unique.h
// (`erts_sched_make_ref_in_array`), OTP-29.1.1.
#[inline]
pub fn next_ref_words() -> [u32; 3] {
    raw::with_current(SchedRefUnique::bump_ref_words).unwrap_or_else(global_ref_words)
}

/// Next ordinary-reference identifier.
#[inline]
pub fn next_ref_id() -> u64 {
    ordinary_ref_key(next_ref_words())
}

#[cold]
#[inline(never)]
fn global_ref_words() -> [u32; 3] {
    let value = global_ref_counter()
        .fetch_add(1, Ordering::SeqCst)
        .wrapping_add(1);
    set_ref_numbers(0, value)
}

fn global_ref_counter() -> &'static AtomicU64 {
    static GLOBAL: OnceLock<AtomicU64> = OnceLock::new();
    GLOBAL.get_or_init(|| AtomicU64::new(initial_ref()))
}

#[derive(Clone, Copy)]
struct UniqueLayout {
    left_shift: u32,
    right_shift: u32,
    mask: u64,
}

static LAYOUT_BITS: AtomicU64 = AtomicU64::new(5);
static NORMAL_SCHEDULERS: AtomicU64 = AtomicU64::new(1);

/// Set the scheduler-count width used to interleave scheduler IDs and unique counters.
// Port of erts/emulator/beam/erl_bif_unique.c (`init_unique_integer`), OTP-29.1.1.
pub fn init_unique_scheduler_count(normal: u32, dirty_cpu: u32, dirty_io: u32) {
    NORMAL_SCHEDULERS.store(u64::from(normal.max(1)), Ordering::Relaxed);
    let max = u64::from(normal)
        .saturating_add(u64::from(dirty_cpu))
        .saturating_add(u64::from(dirty_io))
        .max(1);
    LAYOUT_BITS.store(u64::from(max.ilog2() + 1), Ordering::Relaxed);
}

/// Configured normal scheduler count used to number dirty schedulers.
// Port of erts/emulator/beam/erl_bif_unique.c (`init_unique_integer`), OTP-29.1.1.
pub fn normal_scheduler_count() -> u32 {
    NORMAL_SCHEDULERS.load(Ordering::Relaxed) as u32
}

#[inline]
fn unique_layout() -> UniqueLayout {
    layout_for(LAYOUT_BITS.load(Ordering::Relaxed).max(1))
}

fn layout_for(bits: u64) -> UniqueLayout {
    let bits = bits.min(63);
    UniqueLayout {
        left_shift: bits as u32,
        right_shift: 64 - bits as u32,
        mask: (1_u64 << bits) - 1,
    }
}

/// Next non-monotonic unique integer on the current scheduler.
// Port of erts/emulator/beam/erl_bif_unique.c (`unique_integer_bif`,
// `bld_unique_integer_term`), OTP-29.1.1.
#[inline]
pub fn next_unique_integer(positive: bool) -> i128 {
    raw::with_current(|data| data.bump_unique(positive)).unwrap_or_else(|| {
        let unique = GLOBAL_UNIQUE
            .fetch_add(1, Ordering::Relaxed)
            .wrapping_add(1);
        combine_unique(0, unique, positive, unique_layout())
    })
}

fn combine_unique(thr_id: u64, unique: u64, positive: bool, layout: UniqueLayout) -> i128 {
    let mut low = thr_id | unique.wrapping_shl(layout.left_shift);
    let mut high = if layout.right_shift >= 64 {
        0
    } else {
        (unique >> layout.right_shift) & layout.mask
    };
    if positive {
        low = low.wrapping_add(1);
        if low == 0 {
            high = high.wrapping_add(1);
        }
    } else if high == 0 && low < (1_u64 << 59) {
        return MIN_SMALL + i128::from(low);
    } else {
        if low < (1_u64 << 59) {
            high = high.wrapping_sub(1);
        }
        low = low.wrapping_add(MIN_SMALL as u64);
    }
    ((u128::from(high) << 64) | u128::from(low)) as i128
}

/// The integer produced by `erts_debug:get_internal_state({make_unique_integer, Val0, Val1})`.
// Port of erts/emulator/beam/erl_bif_unique.c (`erts_debug_make_unique_integer`), OTP-29.1.1.
pub fn debug_make_unique_integer(val0: u64, val1: u64) -> i128 {
    combine_unique(val0, val1, false, unique_layout())
}

static MONOTONIC: AtomicU64 = AtomicU64::new(0);
static GLOBAL_UNIQUE: AtomicU64 = AtomicU64::new(u64::MAX);

/// Next strictly monotonic unique integer, as `erlang:unique_integer([monotonic])`.
// Port of erts/emulator/beam/erl_bif_unique.c (`get_raw_unique_monotonic_integer`,
// `make_unique_monotonic_integer_value`), OTP-29.1.1.
pub fn next_unique_monotonic() -> i128 {
    MIN_SMALL + i128::from(MONOTONIC.fetch_add(1, Ordering::SeqCst))
}

/// Next strictly increasing positive monotonic unique integer.
pub fn next_unique_monotonic_positive() -> i128 {
    i128::from(MONOTONIC.fetch_add(1, Ordering::SeqCst).wrapping_add(1))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_unique_integer_follows_the_layout_width() {
        let build = |bits, val0, val1| combine_unique(val0, val1, false, layout_for(bits));
        assert_eq!(build(5, 0, 1), MIN_SMALL + 32);
        assert_eq!(build(6, 0, 1), MIN_SMALL + 64);
        assert_eq!(build(6, 3, 0), MIN_SMALL + 3);
    }

    #[test]
    fn ref_words_roundtrip_the_id() {
        let value = 0x1234_5678_9abc;
        let words = set_ref_numbers(3, value);
        assert_eq!(ordinary_ref_key(words), ref_key(3, value));
        assert_eq!(words[1] & THR_ID_MASK, 3);
        assert_eq!(ordinary_ref_words(ordinary_ref_key(words)), words);
    }

    #[test]
    fn scheduler_data_keeps_its_reference_counter() {
        let data = Rc::new(SchedRefUnique {
            thr_id: Cell::new(7),
            ref_n: Cell::new(9),
            unique_n: Cell::new(0),
        });
        let _guard = data.bind();
        let first = next_ref_words();
        let second = next_ref_words();
        assert_eq!(first, set_ref_numbers(7, 9));
        assert_eq!(second, set_ref_numbers(7, 10));
    }
}
