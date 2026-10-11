//! Per-scheduler reference and unique-integer counters.
//!
//! Port of erts/emulator/beam/erl_bif_unique.c and erl_bif_unique.h
//! (`erts_sched_make_ref_in_array`, `erts_set_ref_numbers`, `unique_integer_bif`),
//! OTP-29.1.1. Each scheduler thread owns one counter pair in thread-specific
//! data (`esdp->ref`, `esdp->unique`, `esdp->thr_id`). A non-scheduler thread
//! uses the global atomic, as `global_make_ref_in_array` does.

use std::cell::Cell;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use num_bigint::BigInt;

/// Low 18 bits of a reference number. `REF_MASK` in erl_term.h.
const REF_MASK: u64 = (1 << 18) - 1;
/// Bits of `ref[1]` that hold the scheduler thread id. `ERTS_REF1_THR_ID_MASK__`.
const THR_ID_MASK: u32 = (1 << 16) - 1;
/// Bits of `ref[1]` that hold reference-counter bits 18..31. `ERTS_REF1_NUM_MASK__`.
const REF1_NUM_MASK: u32 = !(THR_ID_MASK | (1 << 17) | (1 << 16));
/// Counter bits kept in the internal id. The thread id occupies the top 16 bits.
const VALUE_BITS: u32 = 48;
const VALUE_MASK: u64 = (1 << VALUE_BITS) - 1;
/// `MIN_SMALL` on a 64-bit term word.
const MIN_SMALL: i64 = -(1 << 59);
const MAX_SMALL: u64 = (1 << 59) - 1;

/// `ErtsSchedulerData` fields `thr_id`, `ref` and `unique` (erl_process.h:718-720).
///
/// One copy per thread, like `erts_get_scheduler_data`. The counters are plain
/// cells: only that scheduler thread writes them (`esdp->ref++`), so they are
/// not atomics.
struct Esdp {
    thr_id: Cell<u32>,
    bound: Cell<bool>,
    /// `esdp->ref`, initialized to `ref_init_value`.
    ref_n: Cell<u64>,
    /// `esdp->unique`.
    unique_n: Cell<u64>,
}

thread_local! {
    static ESDP: Esdp = const {
        Esdp {
            thr_id: Cell::new(0),
            bound: Cell::new(false),
            ref_n: Cell::new(0),
            unique_n: Cell::new(0),
        }
    };
}

/// Thread id of the scheduler whose counters this process turn uses.
///
/// The counters themselves stay in [`ESDP`]; this is only the id `run` compares
/// when the process moves to another scheduler.
#[derive(Clone, Copy)]
pub struct SchedulerRefState {
    thr_id: u32,
}

impl SchedulerRefState {
    /// Scheduler thread id mixed into reference numbers.
    pub fn thr_id(&self) -> u32 {
        self.thr_id
    }

    /// Next ordinary-reference id. The pre-increment value is the one published,
    /// matching `value = esdp->ref++`.
    pub fn bump_ref(&self) -> u64 {
        debug_assert!(ESDP.with(|esdp| !esdp.bound.get() || esdp.thr_id.get() == self.thr_id));
        ordinary_ref_key(next_ref_words())
    }

    /// Next non-monotonic `unique_integer` on this scheduler.
    // Port of erts/emulator/beam/erl_bif_unique.c:565-578 (`unique_integer_bif`), OTP-29.1.1.
    pub fn bump_unique(&self, positive: bool) -> UniqueInt {
        debug_assert!(ESDP.with(|esdp| !esdp.bound.get() || esdp.thr_id.get() == self.thr_id));
        next_unique_integer(positive)
    }
}

/// Install this thread's scheduler counters. Later calls on the same thread
/// return the counters created for the first `thr_id`.
// Port of erts/emulator/beam/erl_bif_unique.c:809-814 (erts_sched_bif_unique_init), OTP-29.1.1.
pub fn bind_scheduler_ref_state(thr_id: u32) -> SchedulerRefState {
    ESDP.with(|esdp| {
        if !esdp.bound.get() {
            esdp.thr_id.set(thr_id & THR_ID_MASK);
            // `esdp->ref = ref_init_value`, not an offset added on every bump.
            esdp.ref_n.set(initial_ref());
            esdp.unique_n.set(0);
            esdp.bound.set(true);
        }
        SchedulerRefState {
            thr_id: esdp.thr_id.get(),
        }
    })
}

/// Thread id for a process turn. A normal scheduler uses its 1-based id.
/// A dirty scheduler takes the next id above the normal scheduler count.
pub fn scheduler_thr_id(normal_id: Option<u32>, normal_count: u32) -> u32 {
    if let Some(id) = normal_id.filter(|id| *id != 0) {
        return id & THR_ID_MASK;
    }
    thread_local! {
        static DIRTY: Cell<u32> = const { Cell::new(0) };
    }
    static NEXT: AtomicU64 = AtomicU64::new(1);
    DIRTY.with(|cell| {
        let current = cell.get();
        if current != 0 {
            return current;
        }
        let id = normal_count.saturating_add(NEXT.fetch_add(1, Ordering::Relaxed) as u32);
        let id = id & THR_ID_MASK;
        cell.set(id.max(1));
        cell.get()
    })
}

// Port of erts/emulator/beam/erl_bif_unique.c:70-88 (init_reference), OTP-29.1.1.
fn initial_ref() -> u64 {
    static INIT: OnceLock<u64> = OnceLock::new();
    *INIT.get_or_init(|| {
        let elapsed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        let mut value = elapsed.as_secs();
        value |= u64::from(elapsed.subsec_micros()) << 32;
        value = value.wrapping_mul(268_438_039);
        value = value.wrapping_add(u64::from(elapsed.subsec_micros()));
        value & VALUE_MASK
    })
}

fn ref_key(thr_id: u32, value: u64) -> u64 {
    (u64::from(thr_id & THR_ID_MASK) << VALUE_BITS) | (value & VALUE_MASK)
}

/// Three reference words for an id from [`SchedulerRefState::bump_ref`].
// Port of erts/emulator/beam/erl_bif_unique.h:117-131 (erts_set_ref_numbers), OTP-29.1.1.
#[inline]
pub fn ordinary_ref_words(id: u64) -> [u32; 3] {
    let thr_id = (id >> VALUE_BITS) as u32;
    let value = id & VALUE_MASK;
    set_ref_numbers(thr_id, value)
}

/// Id recovered from the three words [`ordinary_ref_words`] wrote.
// Port of erts/emulator/beam/erl_bif_unique.h:158-167 (erts_get_ref_numbers_value), OTP-29.1.1.
#[inline]
pub fn ordinary_ref_key(ids: [u32; 3]) -> u64 {
    let thr_id = ids[1] & THR_ID_MASK;
    let value = ref_numbers_value(ids);
    ref_key(thr_id, value)
}

#[inline]
fn set_ref_numbers(thr_id: u32, value: u64) -> [u32; 3] {
    // Port of erts/emulator/beam/erl_bif_unique.h:118-131 (erts_set_ref_numbers), OTP-29.1.1.
    let r0 = (value & REF_MASK) as u32;
    let r1 = (value as u32 & REF1_NUM_MASK) | (thr_id & THR_ID_MASK);
    let r2 = (value >> 32) as u32;
    [r0, r1, r2]
}

fn ref_numbers_value(ids: [u32; 3]) -> u64 {
    (u64::from(ids[2]) << 32)
        | (u64::from(ids[1]) & u64::from(REF1_NUM_MASK))
        | (u64::from(ids[0]) & REF_MASK)
}

/// Next reference words. Scheduler threads increment `esdp->ref`; other threads
/// increment the global atomic.
// Port of erts/emulator/beam/erl_bif_unique.c:100-108 (`make_ref_in_array`) and
// erl_bif_unique.h:170-177 (`erts_sched_make_ref_in_array`), OTP-29.1.1.
#[inline]
pub fn next_ref_words() -> [u32; 3] {
    ESDP.with(|esdp| {
        if esdp.bound.get() {
            let value = esdp.ref_n.get();
            esdp.ref_n.set(value.wrapping_add(1));
            set_ref_numbers(esdp.thr_id.get(), value)
        } else {
            global_ref_words()
        }
    })
}

/// Next reference id. Scheduler threads use their own counter; other threads
/// share one global counter with thread id 0.
#[inline]
pub fn next_ref_id() -> u64 {
    ordinary_ref_key(next_ref_words())
}

#[cold]
#[inline(never)]
fn global_ref_words() -> [u32; 3] {
    // Port of erts/emulator/beam/erl_bif_unique.c:93-97 (`global_make_ref_in_array`):
    // `erts_atomic64_inc_read_mb` returns the value after the increment.
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

/// Bit width `init_unique_integer` computed for the largest scheduler thread id.
/// Starts at 5, `erts_fit_in_bits_int64` of the reference host's scheduler count (30).
static LAYOUT_BITS: AtomicU64 = AtomicU64::new(5);

/// Record how many scheduler threads exist so `unique_integer` can mix the
/// thread id into the low bits the way `init_unique_integer` does.
// Port of erts/emulator/beam/erl_bif_unique.c:458-470 (init_unique_integer), OTP-29.1.1.
pub fn init_unique_scheduler_count(normal: u32, dirty_cpu: u32, dirty_io: u32) {
    let max = u64::from(normal)
        .saturating_add(u64::from(dirty_cpu))
        .saturating_add(u64::from(dirty_io))
        .max(1);
    let bits = u64::from(max.ilog2() + 1);
    LAYOUT_BITS.store(bits, Ordering::Relaxed);
}

#[inline]
fn unique_layout() -> UniqueLayout {
    layout_for(LAYOUT_BITS.load(Ordering::Relaxed).max(1))
}

fn layout_for(bits: u64) -> UniqueLayout {
    // `erts_fit_in_bits_int64`: bit width of the largest thread id.
    let bits = bits.min(63);
    UniqueLayout {
        left_shift: bits as u32,
        right_shift: 64 - bits as u32,
        mask: (1_u64 << bits) - 1,
    }
}

/// A `unique_integer` result. Small values are the common case.
pub enum UniqueInt {
    Small(i64),
    Big(BigInt),
}

/// Next non-monotonic unique integer on this thread.
// Port of erts/emulator/beam/erl_bif_unique.c:565-578 and 474-563
// (`unique_integer_bif`, `bld_unique_integer_term`), OTP-29.1.1.
#[inline]
pub fn next_unique_integer(positive: bool) -> UniqueInt {
    // `unique_data.r.o` is process-wide, computed once in `init_unique_integer`.
    let layout = unique_layout();
    ESDP.with(|esdp| {
        if esdp.bound.get() {
            let unique = esdp.unique_n.get();
            esdp.unique_n.set(unique.wrapping_add(1));
            combine_unique(u64::from(esdp.thr_id.get()), unique, positive, layout)
        } else {
            global_unique(positive)
        }
    })
}

#[cold]
#[inline(never)]
fn global_unique(positive: bool) -> UniqueInt {
    // Port of erts/emulator/beam/erl_bif_unique.c:607-614 (`erts_raw_get_unique_integer`):
    // `inc_read_nob` from -1 yields 0 on the first call, matching `fetch_add` from 0.
    static UNIQUE: AtomicU64 = AtomicU64::new(0);
    let unique = UNIQUE.fetch_add(1, Ordering::Relaxed);
    combine_unique(0, unique, positive, unique_layout())
}

fn combine_unique(thr_id: u64, unique: u64, positive: bool, layout: UniqueLayout) -> UniqueInt {
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
        return UniqueInt::Small(MIN_SMALL + low as i64);
    } else {
        if low < (1_u64 << 59) {
            high = high.wrapping_sub(1);
        }
        low = low.wrapping_add(MIN_SMALL as u64);
    }
    if high == 0 && low <= MAX_SMALL {
        return UniqueInt::Small(low as i64);
    }
    if high == 0 {
        return UniqueInt::Big(BigInt::from(low));
    }
    UniqueInt::Big((BigInt::from(high) << 64) + BigInt::from(low))
}

static MONOTONIC: AtomicU64 = AtomicU64::new(0);

/// Next strictly monotonic unique integer, as `erlang:unique_integer([monotonic])`.
// Port of erts/emulator/beam/erl_bif_unique.c:668-707
// (`get_raw_unique_monotonic_integer`, `make_unique_monotonic_integer_value`), OTP-29.1.1.
pub fn next_unique_monotonic() -> i64 {
    let raw = MONOTONIC.fetch_add(1, Ordering::Relaxed);
    MIN_SMALL + raw as i64
}

/// `erlang:unique_integer([monotonic, positive])`: the raw counter plus one.
pub fn next_unique_monotonic_positive() -> u64 {
    MONOTONIC.fetch_add(1, Ordering::Relaxed).wrapping_add(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ref_words_roundtrip_the_id() {
        let value = 0x1234_5678_9abc;
        let words = set_ref_numbers(3, value);
        assert_eq!(ordinary_ref_key(words), ref_key(3, value));
        assert_eq!(words[1] & THR_ID_MASK, 3);
        assert_eq!(ordinary_ref_words(ordinary_ref_key(words)), words);
    }

    #[test]
    fn distinct_schedulers_do_not_share_a_reference() {
        let a = std::thread::spawn(|| {
            bind_scheduler_ref_state(1);
            next_ref_words()
        })
        .join()
        .expect("scheduler 1");
        let b = std::thread::spawn(|| {
            bind_scheduler_ref_state(2);
            let first = next_ref_words();
            let second = next_ref_words();
            (first, second)
        })
        .join()
        .expect("scheduler 2");
        assert_eq!(a[1] & THR_ID_MASK, 1);
        assert_eq!(b.0[1] & THR_ID_MASK, 2);
        assert_ne!(b.0, b.1);
        assert_ne!(a, b.0);
    }
}
