//! Flexible counters: a centralized atomic, or one cache-line padded slot per scheduler.
//!
//! Port of erts/emulator/beam/erl_flxctr.c and erl_flxctr.h, OTP-29.1.1.
//!
//! A decentralized counter keeps its slots in an array that is replaced as a whole by
//! [`FlxCtr::snapshot`]: the caller swaps in a fresh array, and once every thread has passed a
//! thread progress point nobody can still add to the old one, so the old slots are summed into
//! a result and into slot 0 of the new array. The process that asked is suspended meanwhile
//! (the [`SnapshotHost`] does that, as `erts_suspend` and `erts_schedule_thr_prgr_later_op`
//! are called from `erts_flxctr_snapshot` in erts).

use std::sync::Arc;
use std::sync::atomic::{AtomicIsize, AtomicPtr, Ordering};

/// `ERTS_FLXCTR_ATOMICS_PER_CACHE_LINE`: counters in one [`FlxCtr`] (`ERTS_CACHE_LINE_SIZE` 64).
pub const ATOMICS_PER_CACHE_LINE: usize = 8;
const CACHE_LINE_SIZE: usize = 64;

/// `ERTS_FLXCTR_SNAPSHOT_NOT_ONGOING`.
const SNAPSHOT_NOT_ONGOING: isize = 0;
/// `ERTS_FLXCTR_SNAPSHOT_ONGOING`.
const SNAPSHOT_ONGOING: isize = 1;
/// `ERTS_FLXCTR_SNAPSHOT_ONGOING_TP_THREAD_DO_FREE`: the owner is gone, the thread progress
/// operation frees the array.
const SNAPSHOT_ONGOING_TP_THREAD_DO_FREE: isize = 2;

/// `ErtsFlxCtrDecentralizedCtrArrayElem`: the counters of one scheduler on their own cache line.
#[repr(C, align(64))]
struct Elem {
    counters: [AtomicIsize; ATOMICS_PER_CACHE_LINE],
}

/// `ErtsFlxCtrDecentralizedCtrArray`.
struct CtrArray {
    snapshot_status: AtomicIsize,
    array: Box<[Elem]>,
}

/// The number of slots of a decentralized counter array: `reader_groups_array_size` of
/// erl_flxctr.c (`decentralized_counter_groups + 1`). The decentralized counter groups are the
/// reader groups of the scheduler set (one per scheduler), so the count comes from there.
// Port of erts/emulator/beam/erl_flxctr.c (erts_flxctr_setup) and erl_cpu_topology.c
// (erts_early_init_cpu_topology), OTP-29.1.1. erts passes the group count to `erts_flxctr_setup`
// from `erl_init.c`; the scheduler crate cannot depend on this one, so the count is read from
// the reader group array size that it publishes to the term crate.
fn no_slots() -> usize {
    arinsal_term::reader_group_slots().max(2)
}

/// `erts_flxctr_get_slot_index`: `esdp->flxctr_slot_no`, the slot of the calling scheduler.
/// A thread without scheduler data (a dirty scheduler or any other thread) has slot 0, the slot
/// a scheduler uses while it is suspended.
// Port of erts/emulator/beam/erl_flxctr.h (erts_flxctr_get_slot_index) and erl_cpu_topology.c
// (flxctr_groups_callback: `group + 1`, or 0 when suspended), OTP-29.1.1.
fn slot_index() -> usize {
    if arinsal_term::is_scheduler_thread() {
        arinsal_term::current_reader_group() % (no_slots() - 1) + 1
    } else {
        0
    }
}

fn create_decentralized_ctr_array(nr_of_counters: usize) -> *mut CtrArray {
    debug_assert!(nr_of_counters <= ATOMICS_PER_CACHE_LINE);
    let array = (0..no_slots())
        .map(|_| Elem {
            counters: std::array::from_fn(|_| AtomicIsize::new(0)),
        })
        .collect();
    Box::into_raw(Box::new(CtrArray {
        snapshot_status: AtomicIsize::new(SNAPSHOT_ONGOING),
        array,
    }))
}

/// `FLXCTR_FREE` of an array.
fn free_array(array: *mut CtrArray) {
    // SAFETY: `array` came from `create_decentralized_ctr_array` and the caller owns it: it was
    // unlinked from its counter (or never linked) and thread progress excluded every adder.
    drop(unsafe { Box::from_raw(array) });
}

/// `ErtsFlxCtr`.
pub struct FlxCtr {
    nr_of_counters: usize,
    is_decentralized: bool,
    /// `u.counters`, the centralized counters.
    counters: [AtomicIsize; ATOMICS_PER_CACHE_LINE],
    /// `u.counters_ptr`, the current [`CtrArray`] of a decentralized counter.
    counters_ptr: AtomicPtr<CtrArray>,
}

/// `ErtsFlxCtrSnapshotResult` (`ErtsFlxctrSnapshotResultType` and its fields).
pub enum SnapshotResult {
    /// `ERTS_FLXCTR_TRY_AGAIN_AFTER_TRAP`: the caller traps and calls again after it woke up.
    TryAgainAfterTrap,
    /// `ERTS_FLXCTR_DONE`: the counters, indexed by counter number.
    Done([isize; ATOMICS_PER_CACHE_LINE]),
    /// `ERTS_FLXCTR_GET_RESULT_AFTER_TRAP`: the caller traps with this state and reads the
    /// counters from it after it woke up.
    GetResultAfterTrap(Arc<SnapshotState>),
}

/// `DecentralizedReadSnapshotInfo.result`: filled by the thread progress operation before the
/// suspended caller is resumed.
#[derive(Default)]
pub struct SnapshotState {
    result: [AtomicIsize; ATOMICS_PER_CACHE_LINE],
}

impl SnapshotState {
    /// `erts_flxctr_get_snapshot_result_after_trap`.
    pub fn result(&self, counter_nr: usize) -> isize {
        self.result[counter_nr].load(Ordering::Acquire)
    }
}

/// The process side of a snapshot: `erts_suspend`, `ERTS_VBUMP_ALL_REDS`, the process
/// reference and `erts_schedule_thr_prgr_later_op` of erl_flxctr.c (`suspend_until_thr_prg`,
/// `erts_flxctr_snapshot`), which the VM provides because this crate has no processes.
pub trait SnapshotHost {
    /// Suspend the calling process and run `op` once thread progress happened, then resume the
    /// process unless it is exiting (`thr_prg_wake_up_and_count`, `thr_prg_wake_up_later`).
    fn suspend_and_run_later(&mut self, op: Box<dyn FnOnce() + Send + 'static>);
}

/// A raw array pointer handed to a thread progress operation.
struct ArrayPtr(*mut CtrArray);

// SAFETY: the pointer is owned by the operation that carries it (see `snapshot`); the array is
// only made of atomics.
unsafe impl Send for ArrayPtr {}

impl FlxCtr {
    /// `erts_flxctr_init`.
    pub fn new(is_decentralized: bool, nr_of_counters: usize) -> Self {
        debug_assert!(nr_of_counters <= ATOMICS_PER_CACHE_LINE);
        let counters_ptr = if is_decentralized {
            let array = create_decentralized_ctr_array(nr_of_counters);
            // SAFETY: the array was just created and is not shared yet.
            unsafe { &*array }
                .snapshot_status
                .store(SNAPSHOT_NOT_ONGOING, Ordering::Relaxed);
            array
        } else {
            std::ptr::null_mut()
        };
        Self {
            nr_of_counters,
            is_decentralized,
            counters: std::array::from_fn(|_| AtomicIsize::new(0)),
            counters_ptr: AtomicPtr::new(counters_ptr),
        }
    }

    /// `ErtsFlxCtr.is_decentralized`.
    pub fn is_decentralized(&self) -> bool {
        self.is_decentralized
    }

    /// `ERTS_FLXCTR_GET_CTR_ARRAY_PTR`.
    fn array(&self) -> &CtrArray {
        // SAFETY: a decentralized counter always has an array, and a replaced array is freed
        // only after thread progress, by which time no caller (a scheduler running a process)
        // still holds this reference.
        unsafe { &*self.counters_ptr.load(Ordering::Acquire) }
    }

    /// `ERTS_FLXCTR_GET_CTR_PTR`.
    fn slot_counter(&self, counter_nr: usize) -> &AtomicIsize {
        let array = self.array();
        let slot = slot_index();
        // A table made before a later runtime of the process reset the group count keeps its
        // own slot count.
        let slot = if slot < array.array.len() {
            slot
        } else {
            slot % array.array.len()
        };
        &array.array[slot].counters[counter_nr]
    }

    /// `erts_flxctr_add`.
    #[inline]
    pub fn add(&self, counter_nr: usize, to_add: isize) {
        debug_assert!(counter_nr < self.nr_of_counters);
        if self.is_decentralized {
            self.slot_counter(counter_nr)
                .fetch_add(to_add, Ordering::Relaxed);
        } else {
            self.counters[counter_nr].fetch_add(to_add, Ordering::Relaxed);
        }
    }

    /// `erts_flxctr_inc`.
    #[inline]
    pub fn inc(&self, counter_nr: usize) {
        self.add(counter_nr, 1);
    }

    /// `erts_flxctr_dec`.
    #[inline]
    pub fn dec(&self, counter_nr: usize) {
        self.add(counter_nr, -1);
    }

    /// `erts_flxctr_inc_read_centralized`.
    #[inline]
    pub fn inc_read_centralized(&self, counter_nr: usize) -> isize {
        debug_assert!(counter_nr < self.nr_of_counters && !self.is_decentralized);
        self.counters[counter_nr].fetch_add(1, Ordering::Relaxed) + 1
    }

    /// `erts_flxctr_dec_read_centralized`.
    #[inline]
    pub fn dec_read_centralized(&self, counter_nr: usize) -> isize {
        debug_assert!(counter_nr < self.nr_of_counters && !self.is_decentralized);
        self.counters[counter_nr].fetch_sub(1, Ordering::Relaxed) - 1
    }

    /// `erts_flxctr_read_centralized`.
    #[inline]
    pub fn read_centralized(&self, counter_nr: usize) -> isize {
        debug_assert!(counter_nr < self.nr_of_counters && !self.is_decentralized);
        self.counters[counter_nr].load(Ordering::Relaxed)
    }

    /// `erts_flxctr_read_approx`.
    pub fn read_approx(&self, counter_nr: usize) -> isize {
        if self.is_decentralized {
            self.array()
                .array
                .iter()
                .map(|elem| elem.counters[counter_nr].load(Ordering::Relaxed))
                .fold(0isize, isize::wrapping_add)
        } else {
            self.read_centralized(counter_nr)
        }
    }

    /// `erts_flxctr_reset`: unsafe to call while a snapshot may be active.
    pub fn reset(&self, counter_nr: usize) {
        if self.is_decentralized {
            for elem in &self.array().array {
                elem.counters[counter_nr].store(0, Ordering::Relaxed);
            }
        } else {
            self.counters[counter_nr].store(0, Ordering::Relaxed);
        }
    }

    /// `erts_flxctr_is_snapshot_ongoing`.
    pub fn is_snapshot_ongoing(&self) -> bool {
        self.is_decentralized
            && self.array().snapshot_status.load(Ordering::Acquire) != SNAPSHOT_NOT_ONGOING
    }

    /// `erts_flxctr_nr_of_allocated_bytes`: `ERTS_FLXCTR_DECENTRALIZED_COUNTER_ARRAY_SIZE`.
    pub fn nr_of_allocated_bytes(&self) -> usize {
        if self.is_decentralized {
            // The array header (block start pointer and status), the slots, and the padding
            // that aligns the first slot to a cache line.
            2 * std::mem::size_of::<usize>()
                + self.array().array.len() * CACHE_LINE_SIZE
                + CACHE_LINE_SIZE
        } else {
            0
        }
    }

    /// `erts_flxctr_suspend_until_thr_prg_if_snapshot_ongoing`: whether the caller got suspended
    /// and has to trap.
    pub fn suspend_until_thr_prg_if_snapshot_ongoing(&self, host: &mut dyn SnapshotHost) -> bool {
        if self.is_snapshot_ongoing() {
            suspend_until_thr_prg(host);
            true
        } else {
            false
        }
    }

    /// `erts_flxctr_snapshot`: an atomic read of every counter.
    pub fn snapshot(&self, host: &mut dyn SnapshotHost) -> SnapshotResult {
        if !self.is_decentralized {
            let mut result = [0; ATOMICS_PER_CACHE_LINE];
            for (counter_nr, value) in result.iter_mut().enumerate().take(self.nr_of_counters) {
                *value = self.read_centralized(counter_nr);
            }
            return SnapshotResult::Done(result);
        }
        let array = self.counters_ptr.load(Ordering::Acquire);
        if self.is_snapshot_ongoing() {
            // Let the caller try again later.
            suspend_until_thr_prg(host);
            return SnapshotResult::TryAgainAfterTrap;
        }
        let new_array = create_decentralized_ctr_array(self.nr_of_counters);
        if self
            .counters_ptr
            .compare_exchange(array, new_array, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            // Let the caller try again later.
            suspend_until_thr_prg(host);
            free_array(new_array);
            return SnapshotResult::TryAgainAfterTrap;
        }
        let state = Arc::new(SnapshotState::default());
        let nr_of_counters = self.nr_of_counters;
        let info_state = Arc::clone(&state);
        let (array, next) = (ArrayPtr(array), ArrayPtr(new_array));
        host.suspend_and_run_later(Box::new(move || {
            thr_prg_wake_up_and_count(&info_state, array, next, nr_of_counters);
        }));
        SnapshotResult::GetResultAfterTrap(state)
    }
}

/// `suspend_until_thr_prg`.
fn suspend_until_thr_prg(host: &mut dyn SnapshotHost) {
    host.suspend_and_run_later(Box::new(|| {}));
}

/// `thr_prg_wake_up_and_count`, run once thread progress made the old `array` quiescent.
fn thr_prg_wake_up_and_count(
    state: &SnapshotState,
    array: ArrayPtr,
    next: ArrayPtr,
    nr_of_counters: usize,
) {
    // SAFETY: both arrays are alive: `array` is freed below, and `next` is freed by whoever
    // loses the status exchange below.
    let (old, new) = unsafe { (&*array.0, &*next.0) };
    // Reset the result array and read the result from the snapshot.
    let mut sums = [0isize; ATOMICS_PER_CACHE_LINE];
    for elem in &old.array {
        for (sum, counter) in sums.iter_mut().zip(&elem.counters).take(nr_of_counters) {
            *sum = sum.wrapping_add(counter.load(Ordering::Relaxed));
        }
    }
    for (counter_nr, sum) in sums.iter().enumerate().take(nr_of_counters) {
        state.result[counter_nr].store(*sum, Ordering::Release);
        // Update the next decentralized counter array.
        new.array[0].counters[counter_nr].fetch_add(*sum, Ordering::Relaxed);
    }
    // Announce that the snapshot is done.
    if new
        .snapshot_status
        .compare_exchange(
            SNAPSHOT_ONGOING,
            SNAPSHOT_NOT_ONGOING,
            Ordering::SeqCst,
            Ordering::SeqCst,
        )
        .is_err()
    {
        // The counter was destroyed meanwhile, so this thread frees the next array.
        free_array(next.0);
    }
    // Free the memory that is no longer needed.
    free_array(array.0);
}

impl Drop for FlxCtr {
    /// `erts_flxctr_destroy`.
    fn drop(&mut self) {
        if !self.is_decentralized {
            return;
        }
        let array = *self.counters_ptr.get_mut();
        // SAFETY: the counter owns its current array.
        let status = &unsafe { &*array }.snapshot_status;
        if self.is_snapshot_ongoing() {
            // Try to delegate the responsibility of freeing to thr_prg_wake_up_and_count.
            if status
                .compare_exchange(
                    SNAPSHOT_ONGOING,
                    SNAPSHOT_ONGOING_TP_THREAD_DO_FREE,
                    Ordering::SeqCst,
                    Ordering::SeqCst,
                )
                .is_err()
            {
                // The delegation was unsuccessful: no snapshot is ongoing anymore, so the
                // freeing is done here.
                debug_assert!(!self.is_snapshot_ongoing());
                free_array(array);
            }
        } else {
            free_array(array);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Runs the operation at once, like a thread progress point that is already reached.
    struct Immediate(usize);

    impl SnapshotHost for Immediate {
        fn suspend_and_run_later(&mut self, op: Box<dyn FnOnce() + Send + 'static>) {
            self.0 += 1;
            op();
        }
    }

    /// Keeps the operation until `run` is called.
    #[derive(Default)]
    struct Deferred(Mutex<Vec<Box<dyn FnOnce() + Send + 'static>>>);

    impl SnapshotHost for &Deferred {
        fn suspend_and_run_later(&mut self, op: Box<dyn FnOnce() + Send + 'static>) {
            self.0.lock().unwrap().push(op);
        }
    }

    #[test]
    fn centralized_counters_read_and_snapshot() {
        let counters = FlxCtr::new(false, 2);
        counters.add(0, 5);
        counters.inc(0);
        counters.dec(1);
        assert_eq!(counters.inc_read_centralized(1), 0);
        assert_eq!(counters.read_centralized(0), 6);
        assert_eq!(counters.read_approx(1), 0);
        assert_eq!(counters.nr_of_allocated_bytes(), 0);
        let mut host = Immediate(0);
        let SnapshotResult::Done(result) = counters.snapshot(&mut host) else {
            panic!("a centralized snapshot is done at once");
        };
        assert_eq!(&result[..2], &[6, 0]);
        assert_eq!(host.0, 0);
        counters.reset(0);
        assert_eq!(counters.read_centralized(0), 0);
    }

    #[test]
    fn decentralized_snapshot_moves_the_sum_to_the_new_array() {
        let counters = FlxCtr::new(true, 2);
        counters.add(0, 7);
        counters.add(1, -3);
        assert!(counters.is_decentralized());
        assert!(counters.nr_of_allocated_bytes() > 0);
        let mut host = Immediate(0);
        let SnapshotResult::GetResultAfterTrap(state) = counters.snapshot(&mut host) else {
            panic!("a decentralized snapshot traps");
        };
        assert_eq!((state.result(0), state.result(1)), (7, -3));
        assert!(!counters.is_snapshot_ongoing());
        assert_eq!(counters.read_approx(0), 7);
        assert_eq!(counters.read_approx(1), -3);
        counters.inc(0);
        assert_eq!(counters.read_approx(0), 8);
    }

    #[test]
    fn a_second_snapshot_waits_while_the_first_is_ongoing() {
        let counters = FlxCtr::new(true, 2);
        counters.add(0, 2);
        let pending = Deferred::default();
        let first = counters.snapshot(&mut &pending);
        assert!(matches!(first, SnapshotResult::GetResultAfterTrap(_)));
        assert!(counters.is_snapshot_ongoing());
        assert!(matches!(
            counters.snapshot(&mut &pending),
            SnapshotResult::TryAgainAfterTrap
        ));
        assert!(counters.suspend_until_thr_prg_if_snapshot_ongoing(&mut Immediate(0)));
        let ops: Vec<_> = pending.0.lock().unwrap().drain(..).collect();
        assert_eq!(ops.len(), 2);
        for op in ops {
            op();
        }
        assert!(!counters.is_snapshot_ongoing());
        assert_eq!(counters.read_approx(0), 2);
        assert!(!counters.suspend_until_thr_prg_if_snapshot_ongoing(&mut Immediate(0)));
    }

    #[test]
    fn destroy_during_a_snapshot_leaves_the_free_to_the_operation() {
        let counters = FlxCtr::new(true, 2);
        let pending = Deferred::default();
        let SnapshotResult::GetResultAfterTrap(_) = counters.snapshot(&mut &pending) else {
            panic!("trap expected");
        };
        drop(counters);
        let ops: Vec<_> = pending.0.lock().unwrap().drain(..).collect();
        for op in ops {
            op();
        }
    }
}
