//! Reader/writer mutex of erts: `ETHR_RWMUTEX_TYPE_NORMAL` and
//! `ETHR_RWMUTEX_TYPE_FREQUENT_READ`.
//!
//! Port of erts/lib_src/common/ethr_mutex.c (`ethr_rwmutex_*`, `event_wait`,
//! `rwmutex_unlock_wake`, `wake_readers`, `write_lock_wait`, `rwmutex_normal_rlock_wait`,
//! `rwmutex_freqread_rlock`, `rwmutex_freqread_rdrs_dec_chk_wakeup`,
//! `rwmutex_try_complete_runlock`) and erts/include/internal/ethr_mutex.h, OTP-29.1.1, in its
//! cmpxchg flavour (`ETHR_RLOCK_WITH_INC_DEC` is disabled upstream).
//!
//! One 32 bit flag word holds the write flag, the write-wait and read-wait flags and, for the
//! normal type, the reader count. A frequent-read lock keeps its readers in per-group
//! indicators instead: a reader increments the indicator of its own group, issues a full
//! fence and reads the flag word; a writer sets its flags, then waits for every indicator to
//! reach zero (`rwmutex_try_complete_runlock`). Contenders spin on the flag word, then queue on
//! a per-lock wait queue and spin on their own event before they park. Wakers hand the lock
//! over: a woken writer owns it, and a woken reader group is granted its read locks by the
//! waker.
//!
//! The protected value lives in an `UnsafeCell` that is only reached through a guard the flag
//! protocol granted.

use std::cell::UnsafeCell;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicI32, AtomicU32, AtomicUsize, Ordering, fence};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::Thread;

const W_FLG: u32 = 1 << 31;
const W_WAIT_FLG: u32 = 1 << 30;
const R_WAIT_FLG: u32 = 1 << 29;
const WAIT_FLGS: u32 = W_WAIT_FLG | R_WAIT_FLG;
/// The lock is read locked through the reader groups (frequent-read type only).
const R_FLG: u32 = 1 << 28;
/// A reader took the lock back while a writer completed the read unlock.
const R_ABRT_UNLCK_FLG: u32 = 1 << 27;
/// Number of threads completing a read unlock.
const R_PEND_UNLCK_MASK: u32 = R_ABRT_UNLCK_FLG - 1;

/// `ETHR_MTX_MAX_FLGS_SPIN`: most spins on the flag word before waiting on the event.
const MAX_FLGS_SPIN: i32 = 10;
/// `ETHR_YIELD_AFTER_BUSY_LOOPS`.
const YIELD_AFTER_BUSY_LOOPS: u32 = 50;
/// `ETHR_MAX_TRYRLOCK_TRIES`.
const MAX_TRYRLOCK_TRIES: u32 = 5;
/// `ETHR_RWMTX_DEFAULT_*` spin counts.
const DEFAULT_MAIN_SPINCOUNT_MAX: i32 = 2000;
const DEFAULT_MAIN_SPINCOUNT_BASE: i32 = 800;
const DEFAULT_MAIN_SPINCOUNT_INC: i32 = 50;
const DEFAULT_AUX_SPINCOUNT: i32 = 50;

/// Number of main (scheduler) threads, `ethr_mutex_lib_late_init`'s `no_main_threads`.
static MAIN_THREADS: AtomicUsize = AtomicUsize::new(0);

/// Late init, as `ethr_mutex_lib_late_init` (ethr_mutex.c:163-166): the main spin count grows
/// with the number of schedulers.
pub fn set_main_threads(count: usize) {
    MAIN_THREADS.store(count, Ordering::Release);
}

fn default_main_spincount() -> i32 {
    let threads = match MAIN_THREADS.load(Ordering::Acquire) {
        0 => std::thread::available_parallelism().map_or(1, usize::from),
        count => count,
    };
    let count = DEFAULT_MAIN_SPINCOUNT_BASE
        .saturating_add((threads as i32).saturating_mul(DEFAULT_MAIN_SPINCOUNT_INC));
    count.min(DEFAULT_MAIN_SPINCOUNT_MAX)
}

/// A queued waiter: erts' `ethr_ts_event` with its `uaflgs`, event and reader group.
struct Waiter {
    /// The wait flag until the waker grants the lock, then zero.
    uaflgs: AtomicU32,
    thread: Thread,
}

enum QItem {
    Writer(Arc<Waiter>),
    /// The one batch of waiting readers (`rq_end` marks its end in erts).
    Readers(Vec<Arc<Waiter>>),
}

/// `mtxb.q` with its `qlck`.
#[derive(Default)]
struct Queue {
    items: VecDeque<QItem>,
}

impl Queue {
    fn writers(&self) -> usize {
        self.items
            .iter()
            .filter(|item| matches!(item, QItem::Writer(_)))
            .count()
    }

    fn reader_batch(&mut self) -> Option<&mut Vec<Arc<Waiter>>> {
        self.items.iter_mut().find_map(|item| match item {
            QItem::Readers(batch) => Some(batch),
            QItem::Writer(_) => None,
        })
    }
}

/// One reader group of a frequent-read lock: `ethr_rwmtx_readers_array__`, on a cache line of
/// its own.
#[repr(align(64))]
struct ReaderSlot {
    /// Read locks held through this group.
    readers: AtomicI32,
    /// Readers of this group waiting in the queue; changed under the queue lock only.
    waiting: AtomicU32,
}

/// The reader groups of a frequent-read lock; their number is a power of two so that a
/// scheduler's group is its id under a mask.
struct Readers {
    slots: Box<[ReaderSlot]>,
    mask: usize,
}

/// The lock proper: `ethr_rwmutex` of the normal or the frequent-read type.
pub struct RwMtx {
    flgs: AtomicU32,
    aux_scnt: i32,
    main_scnt: i32,
    q: Mutex<Queue>,
    /// Present for the frequent-read type.
    readers: Option<Readers>,
}

impl Default for RwMtx {
    fn default() -> Self {
        Self::new()
    }
}

impl RwMtx {
    /// `ethr_rwmutex_init` with the default spin counts (`mtxb_init`).
    pub fn new() -> Self {
        Self::with_readers(None)
    }

    /// `ethr_rwmutex_init_opt` of `ETHR_RWMUTEX_TYPE_FREQUENT_READ`.
    pub fn new_freq_read() -> Self {
        let len = arinsal_term::reader_group_slots()
            .max(1)
            .next_power_of_two();
        let slots = (0..len)
            .map(|_| ReaderSlot {
                readers: AtomicI32::new(0),
                waiting: AtomicU32::new(0),
            })
            .collect();
        Self::with_readers(Some(Readers {
            slots,
            mask: len - 1,
        }))
    }

    fn with_readers(readers: Option<Readers>) -> Self {
        let aux_scnt = DEFAULT_AUX_SPINCOUNT;
        Self {
            flgs: AtomicU32::new(0),
            aux_scnt,
            main_scnt: default_main_spincount().max(aux_scnt),
            q: Mutex::new(Queue::default()),
            readers,
        }
    }

    fn readers(&self) -> &Readers {
        self.readers
            .as_ref()
            .expect("a frequent-read lock has reader groups")
    }

    fn queue(&self) -> MutexGuard<'_, Queue> {
        self.q
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn initial_spincount(&self) -> i32 {
        self.aux_scnt.min(MAX_FLGS_SPIN)
    }

    /// `update_spincount`: returns whether to stop spinning on the flags and wait on the event
    /// with `*scnt` spins.
    fn update_spincount(&self, scnt_state: &mut i32, scnt: &mut i32) -> bool {
        let state = *scnt_state;
        if state <= 0 {
            // Here state is the maximum spin count on the event, negated.
            *scnt = -state;
        } else {
            // Here state is the initial spin count made on the flags.
            *scnt = if arinsal_term::is_scheduler_thread() {
                self.main_scnt
            } else {
                self.aux_scnt
            };
            if *scnt <= state {
                *scnt = 0;
            } else {
                if *scnt <= MAX_FLGS_SPIN {
                    *scnt_state = 0; // No spin on the event.
                } else {
                    // Spin on the event after the spin on the flags.
                    *scnt_state = -(*scnt - MAX_FLGS_SPIN);
                    *scnt = MAX_FLGS_SPIN;
                }
                *scnt -= state;
                return false;
            }
        }
        true
    }

    /// `ethr_rwmutex_tryrlock`; `group` is the caller's reader group (frequent-read type).
    pub fn try_read_lock(&self, group: usize) -> bool {
        if self.readers.is_some() {
            return self.freq_read_lock(group, true);
        }
        let mut expected = 0;
        let mut tries = 0;
        loop {
            match self.flgs.compare_exchange(
                expected,
                expected + 1,
                Ordering::Acquire,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(act) => {
                    if tries > MAX_TRYRLOCK_TRIES || act & (W_FLG | W_WAIT_FLG) != 0 {
                        return false;
                    }
                    tries += 1;
                    expected = act;
                }
            }
        }
    }

    /// `ethr_rwmutex_rlock`.
    #[inline]
    pub fn read_lock(&self, group: usize) {
        if self.readers.is_some() {
            self.freq_read_lock(group, false);
            return;
        }
        let mut expected = 0;
        loop {
            match self.flgs.compare_exchange(
                expected,
                expected + 1,
                Ordering::Acquire,
                Ordering::Relaxed,
            ) {
                Ok(_) => return,
                Err(act) => {
                    if act & (W_FLG | W_WAIT_FLG) != 0 {
                        self.read_lock_wait(act);
                        return;
                    }
                    expected = act;
                }
            }
        }
    }

    /// `ethr_rwmutex_runlock`.
    #[inline]
    pub fn read_unlock(&self, group: usize) {
        if let Some(readers) = &self.readers {
            let slot = &readers.slots[group & readers.mask];
            let act = slot.readers.fetch_sub(1, Ordering::Release) - 1;
            fence(Ordering::SeqCst);
            if act == 0 {
                let flgs = self.flgs.load(Ordering::Relaxed);
                if flgs != R_FLG {
                    self.freq_rdrs_dec_chk_wakeup(flgs);
                }
            }
            return;
        }
        let act = self.flgs.fetch_sub(1, Ordering::Release) - 1;
        if act & WAIT_FLGS != 0 && act & !WAIT_FLGS == 0 {
            self.unlock_wake(false, act, None);
        }
    }

    /// `ethr_rwmutex_tryrwlock`.
    pub fn try_write_lock(&self) -> bool {
        if self.readers.is_none() {
            return self
                .flgs
                .compare_exchange(0, W_FLG, Ordering::Acquire, Ordering::Relaxed)
                .is_ok();
        }
        let mut act = self.flgs.load(Ordering::Relaxed);
        loop {
            if act == 0 {
                match self
                    .flgs
                    .compare_exchange(0, W_FLG, Ordering::Acquire, Ordering::Relaxed)
                {
                    Ok(_) => return true,
                    Err(now) => act = now,
                }
            } else if act == R_FLG {
                return !self.try_complete_runlock(act, 0, false, true, true);
            } else {
                return false;
            }
        }
    }

    /// `ethr_rwmutex_rwlock`.
    #[inline]
    pub fn write_lock(&self) {
        if self.readers.is_none() {
            if let Err(act) =
                self.flgs
                    .compare_exchange(0, W_FLG, Ordering::Acquire, Ordering::Relaxed)
            {
                self.write_lock_wait(act);
            }
            return;
        }
        let mut act = self.flgs.load(Ordering::Relaxed);
        loop {
            if act != 0 {
                self.write_lock_wait(act);
                return;
            }
            match self
                .flgs
                .compare_exchange(0, W_FLG, Ordering::Acquire, Ordering::Relaxed)
            {
                Ok(_) => return,
                Err(now) => act = now,
            }
        }
    }

    /// `ethr_rwmutex_rwunlock`.
    #[inline]
    pub fn write_unlock(&self) {
        if let Err(act) = self
            .flgs
            .compare_exchange(W_FLG, 0, Ordering::Release, Ordering::Relaxed)
        {
            self.unlock_wake(true, act, None);
        }
    }

    /// `rwmutex_normal_rlock_wait`.
    fn read_lock_wait(&self, initial: u32) {
        let mut act = initial;
        let mut start_scnt = self.initial_spincount();
        let mut scnt = start_scnt;
        let mut until_yield = YIELD_AFTER_BUSY_LOOPS;
        // Spin trying to read lock for a while. If unsuccessful, wait on the event.
        loop {
            while act & (W_FLG | W_WAIT_FLG) != 0 {
                if scnt <= 0 && self.update_spincount(&mut start_scnt, &mut scnt) {
                    self.event_wait(scnt, R_WAIT_FLG, 0);
                    return;
                }
                std::hint::spin_loop();
                until_yield -= 1;
                if until_yield == 0 {
                    until_yield = YIELD_AFTER_BUSY_LOOPS;
                    std::thread::yield_now();
                }
                act = self.flgs.load(Ordering::Relaxed);
                scnt -= 1;
            }
            match self
                .flgs
                .compare_exchange(act, act + 1, Ordering::Acquire, Ordering::Relaxed)
            {
                Ok(_) => return,
                Err(now) => act = now,
            }
        }
    }

    /// `rwmutex_freqread_rlock`: true when the read lock was taken (it can fail only for a
    /// `trylock`).
    #[inline]
    fn freq_read_lock(&self, group: usize, trylock: bool) -> bool {
        let readers = self.readers();
        let group = group & readers.mask;
        readers.slots[group].readers.fetch_add(1, Ordering::Relaxed);
        fence(Ordering::SeqCst);
        let act = self.flgs.load(Ordering::Acquire);
        if act == R_FLG {
            return true;
        }
        self.freq_read_lock_slow(group, trylock, act)
    }

    #[cold]
    #[inline(never)]
    fn freq_read_lock_slow(&self, group: usize, trylock: bool, initial: u32) -> bool {
        let mut act = initial;
        let mut got = true;
        let mut wake_other_readers;
        loop {
            wake_other_readers = false;
            let new;
            if act == 0 {
                new = R_FLG;
            } else if act == R_FLG {
                break; // Got it.
            } else if act & (W_FLG | W_WAIT_FLG) != 0 {
                self.freq_restore_failed_tryrlock(group);
                if trylock {
                    got = false;
                } else {
                    self.freq_read_lock_wait(group);
                }
                break;
            } else if act & R_ABRT_UNLCK_FLG != 0 {
                // An aborted runlock, not write locked, and no write waiters: we got it.
                wake_other_readers = act & R_WAIT_FLG != 0;
                break;
            } else {
                let mut next = act | R_FLG;
                if act & R_PEND_UNLCK_MASK != 0 {
                    // Someone is doing tryrwlock (no writer and no write waiters); abort that.
                    next |= R_ABRT_UNLCK_FLG;
                }
                wake_other_readers = act & R_WAIT_FLG != 0;
                new = next;
            }
            match self
                .flgs
                .compare_exchange(act, new, Ordering::Acquire, Ordering::Relaxed)
            {
                Ok(_) => break,
                Err(now) => act = now,
            }
        }
        if wake_other_readers {
            self.transfer_read_lock(act, None);
        }
        got
    }

    /// `rwmutex_freqread_rlock_wait`.
    fn freq_read_lock_wait(&self, group: usize) {
        let mut start_scnt = self.initial_spincount();
        let mut scnt = start_scnt;
        let mut until_yield = YIELD_AFTER_BUSY_LOOPS;
        // Spin trying to read lock for a while. If unsuccessful, wait on the event.
        loop {
            let mut act = self.flgs.load(Ordering::Relaxed);
            while act & (W_FLG | W_WAIT_FLG) != 0 {
                if scnt <= 0 && self.update_spincount(&mut start_scnt, &mut scnt) {
                    self.event_wait(scnt, R_WAIT_FLG, group);
                    return;
                }
                std::hint::spin_loop();
                until_yield -= 1;
                if until_yield == 0 {
                    until_yield = YIELD_AFTER_BUSY_LOOPS;
                    std::thread::yield_now();
                }
                act = self.flgs.load(Ordering::Relaxed);
                scnt -= 1;
            }
            if self.freq_read_lock(group, true) {
                return;
            }
        }
    }

    /// `rwmutex_freqread_restore_failed_tryrlock`: undo the increment of a read lock that
    /// failed.
    fn freq_restore_failed_tryrlock(&self, group: usize) {
        let readers = self.readers();
        let act = readers.slots[group & readers.mask]
            .readers
            .fetch_sub(1, Ordering::Relaxed)
            - 1;
        fence(Ordering::SeqCst);
        if act == 0 {
            let flgs = self.flgs.load(Ordering::Relaxed);
            self.freq_rdrs_dec_chk_wakeup(flgs);
        }
    }

    /// `rwmutex_freqread_rdrs_dec_chk_wakeup`.
    fn freq_rdrs_dec_chk_wakeup(&self, initial: u32) {
        let mut act = initial;
        if act & (W_FLG | R_ABRT_UNLCK_FLG) != 0 {
            return;
        }
        if act & WAIT_FLGS == 0 {
            if act & R_PEND_UNLCK_MASK != 0 {
                // A writer that just enqueued may depend on us completing the runlock: we took
                // over that responsibility since we modified the reader groups.
                self.try_complete_runlock(act, 0, true, false, false);
            }
        } else if act & WAIT_FLGS == R_WAIT_FLG {
            self.transfer_read_lock(act, None);
        } else if act & WAIT_FLGS == W_WAIT_FLG {
            self.try_complete_runlock(act, 0, true, false, false);
        } else {
            // Don't know if readers or writers are first in the queue; peek.
            let q = self.queue();
            match q.items.front() {
                None => {}
                Some(QItem::Writer(_)) => {
                    act = self.flgs.load(Ordering::Relaxed);
                    drop(q);
                    if act & W_FLG == 0 {
                        self.try_complete_runlock(act, 0, true, false, false);
                    }
                }
                Some(QItem::Readers(_)) => {
                    act = self.flgs.load(Ordering::Relaxed);
                    if act & W_FLG == 0 {
                        self.transfer_read_lock(act, Some(q));
                    }
                }
            }
        }
    }

    /// `check_readers_array`: true (`EBUSY`) when a reader group still holds a read lock.
    fn check_readers_array(&self, start: usize) -> bool {
        let readers = self.readers();
        fence(Ordering::SeqCst);
        let length = readers.slots.len();
        let mut ix = start;
        loop {
            if readers.slots[ix].readers.load(Ordering::Relaxed) != 0 {
                return true;
            }
            ix += 1;
            if ix == length {
                ix = 0;
            }
            if ix == start {
                return false;
            }
        }
    }

    /// `rwmutex_try_complete_runlock`: finish the read unlock of the groups, then wake the
    /// waiters or (with `try_write_lock`) write lock. Returns true for `EBUSY`.
    fn try_complete_runlock(
        &self,
        initial: u32,
        group: usize,
        start_next_ix: bool,
        check_before_try: bool,
        try_write_lock: bool,
    ) -> bool {
        let readers = self.readers();
        let mut act = initial;
        if act & R_ABRT_UNLCK_FLG != 0 {
            return try_write_lock;
        }
        if act & WAIT_FLGS != 0 && act & !WAIT_FLGS == 0 {
            self.unlock_wake(false, act, None);
            return try_write_lock;
        }
        let mut six = group & readers.mask;
        if start_next_ix {
            six = (six + 1) & readers.mask;
        }
        if check_before_try {
            let busy = self.check_readers_array(six);
            fence(Ordering::SeqCst);
            if busy {
                return try_write_lock;
            }
        }
        'restart: loop {
            loop {
                match self
                    .flgs
                    .compare_exchange(act, act + 1, Ordering::AcqRel, Ordering::Relaxed)
                {
                    Ok(_) => {
                        act += 1;
                        break;
                    }
                    Err(now) => {
                        act = now;
                        if !try_write_lock {
                            if act == 0 || act & (W_FLG | R_ABRT_UNLCK_FLG) != 0 {
                                return false;
                            }
                            if act & WAIT_FLGS == 0 {
                                if act & R_FLG == 0 {
                                    return false;
                                }
                            } else if act & R_FLG == 0 {
                                if act & R_PEND_UNLCK_MASK != 0 {
                                    return false;
                                }
                                self.unlock_wake(false, act, None);
                                return false;
                            }
                        } else {
                            if act == 0 {
                                return self.try_rwlock();
                            }
                            if act & (W_FLG | R_ABRT_UNLCK_FLG) != 0 {
                                return true;
                            }
                        }
                    }
                }
            }
            let busy = self.check_readers_array(six);
            fence(Ordering::SeqCst);
            loop {
                let mut finished_abort = false;
                let mut new = act - 1;
                if act & R_ABRT_UNLCK_FLG != 0 {
                    if new & R_PEND_UNLCK_MASK == 0 {
                        new &= !R_ABRT_UNLCK_FLG;
                        finished_abort = true;
                    }
                } else if act & R_FLG != 0 && !busy {
                    new &= !R_FLG;
                }
                match self
                    .flgs
                    .compare_exchange(act, new, Ordering::AcqRel, Ordering::Relaxed)
                {
                    Ok(_) => {
                        act = new;
                        if act & W_FLG != 0 {
                            return try_write_lock;
                        }
                        if finished_abort && act & WAIT_FLGS != 0 {
                            continue 'restart;
                        }
                        if act & (R_FLG | R_ABRT_UNLCK_FLG | R_PEND_UNLCK_MASK) != 0 {
                            return try_write_lock;
                        }
                        break 'restart; // The read unlock completed.
                    }
                    Err(now) => act = now,
                }
            }
        }
        // Read unlock completed; wake the waiters or try to write lock.
        if act & WAIT_FLGS != 0 {
            self.unlock_wake(false, act, None);
            return try_write_lock;
        }
        if !try_write_lock {
            return false;
        }
        self.try_rwlock()
    }

    /// The final write lock attempt of `rwmutex_try_complete_runlock`; true for `EBUSY`.
    fn try_rwlock(&self) -> bool {
        self.flgs
            .compare_exchange(0, W_FLG, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
    }

    /// `write_lock_wait`.
    fn write_lock_wait(&self, initial: u32) {
        let freq = self.readers.is_some();
        let mut act = initial;
        let mut start_scnt = self.initial_spincount();
        let mut scnt = start_scnt;
        let mut until_yield = YIELD_AFTER_BUSY_LOOPS;
        // Spin trying to write lock for a while. If unsuccessful, wait on the event.
        loop {
            while act != 0 {
                let mut check_spin = false;
                if freq && act == R_FLG {
                    scnt -= 1;
                    if !self.try_complete_runlock(act, 0, false, false, true) {
                        return; // Got it.
                    }
                    if scnt <= 0 {
                        check_spin = true;
                    } else {
                        until_yield -= 1;
                        if until_yield == 0 {
                            until_yield = YIELD_AFTER_BUSY_LOOPS;
                            std::thread::yield_now();
                        }
                    }
                }
                if check_spin || scnt <= 0 {
                    scnt = 0;
                    if self.update_spincount(&mut start_scnt, &mut scnt) {
                        self.event_wait(scnt, W_WAIT_FLG, 0);
                        return;
                    }
                }
                std::hint::spin_loop();
                until_yield -= 1;
                if until_yield == 0 {
                    until_yield = YIELD_AFTER_BUSY_LOOPS;
                    std::thread::yield_now();
                }
                act = self.flgs.load(Ordering::Relaxed);
                scnt -= 1;
            }
            match self
                .flgs
                .compare_exchange(0, W_FLG, Ordering::Acquire, Ordering::Relaxed)
            {
                Ok(_) => return,
                Err(now) => act = now,
            }
        }
    }

    /// `event_wait`: set the wait bit and queue (or get the lock on the way), then wait on the
    /// event until the waker clears `uaflgs`. `group` is the reader group of a frequent-read
    /// reader.
    fn event_wait(&self, spincount: i32, kind: u32, group: usize) {
        let freq = self.readers.is_some();
        let waiter = Arc::new(Waiter {
            uaflgs: AtomicU32::new(kind),
            thread: std::thread::current(),
        });
        let mut q = self.queue();
        let mut act = self.flgs.load(Ordering::Relaxed);
        let mut need_try_complete_runlock = false;
        let mut transfer_read_lock = false;
        if act & kind != 0 {
            // The wait bit is already there: enqueue.
            if kind == W_WAIT_FLG {
                q.items.push_back(QItem::Writer(Arc::clone(&waiter)));
            } else {
                if let Some(batch) = q.reader_batch() {
                    batch.push(Arc::clone(&waiter));
                } else {
                    // The bit says readers wait; their batch is queued under the same lock.
                    q.items.push_back(QItem::Readers(vec![Arc::clone(&waiter)]));
                }
                if freq {
                    self.waiting_readers_inc(group);
                }
            }
        } else {
            // Set the wait bit.
            loop {
                need_try_complete_runlock = false;
                transfer_read_lock = false;
                let new = if kind == W_WAIT_FLG {
                    if freq && act == R_FLG {
                        need_try_complete_runlock = true;
                    }
                    if act != 0 { act | W_WAIT_FLG } else { W_FLG }
                } else if !freq {
                    if act & (W_FLG | W_WAIT_FLG) != 0 {
                        act | R_WAIT_FLG
                    } else {
                        act + 1
                    }
                } else {
                    if act & (W_FLG | W_WAIT_FLG) == 0 {
                        // Transfer the read lock to this thread.
                        transfer_read_lock = true;
                    }
                    act | R_WAIT_FLG
                };
                match self
                    .flgs
                    .compare_exchange(act, new, Ordering::Acquire, Ordering::Relaxed)
                {
                    Ok(_) => {
                        if new & kind == 0 {
                            return; // Got it.
                        }
                        act = new;
                        break;
                    }
                    Err(now) => act = now,
                }
            }
            if kind == W_WAIT_FLG {
                q.items.push_back(QItem::Writer(Arc::clone(&waiter)));
            } else {
                q.items.push_back(QItem::Readers(vec![Arc::clone(&waiter)]));
                if freq {
                    self.waiting_readers_inc(group);
                }
            }
        }
        if transfer_read_lock {
            // We are the only one in the queue and not write locked: transfer a read lock to the
            // first in the queue, which is us.
            self.transfer_read_lock(act, Some(q));
        } else {
            drop(q);
            if need_try_complete_runlock {
                // We were the only one in the queue and it was seemingly read locked: complete
                // the runlock, or we might wait forever.
                self.try_complete_runlock(act, group, false, true, false);
            }
        }
        // Wait: spin on the event, then park.
        let mut until_yield = YIELD_AFTER_BUSY_LOOPS;
        loop {
            let mut spins = spincount.max(0);
            loop {
                if waiter.uaflgs.load(Ordering::Acquire) == 0 {
                    return; // Got it.
                }
                if spins == 0 {
                    break;
                }
                spins -= 1;
                std::hint::spin_loop();
                until_yield -= 1;
                if until_yield == 0 {
                    until_yield = YIELD_AFTER_BUSY_LOOPS;
                    std::thread::yield_now();
                }
            }
            std::thread::park();
            if waiter.uaflgs.load(Ordering::Acquire) == 0 {
                return;
            }
        }
    }

    /// `rwmutex_freqread_wtng_rdrs_inc`; called with the queue locked.
    fn waiting_readers_inc(&self, group: usize) {
        let readers = self.readers();
        readers.slots[group & readers.mask]
            .waiting
            .fetch_add(1, Ordering::Relaxed);
    }

    fn grant(waiter: &Waiter) {
        waiter.uaflgs.store(0, Ordering::Release);
        waiter.thread.unpark();
    }

    /// `rwlock_wake_set_flags`: publish the flags of a handed-over lock, keeping the readers
    /// that are completing a read unlock.
    fn wake_set_flags(&self, new_initial: u32, act_initial: u32) {
        fence(Ordering::SeqCst);
        if self.readers.is_none() {
            // The reader count is always zero here.
            self.flgs.store(new_initial, Ordering::Release);
            return;
        }
        let chk_abrt_flg = new_initial & R_FLG != 0;
        let mut act = act_initial;
        loop {
            let mut new = new_initial + (act & R_PEND_UNLCK_MASK);
            if chk_abrt_flg && act & R_PEND_UNLCK_MASK != 0 {
                new |= R_ABRT_UNLCK_FLG;
            }
            match self
                .flgs
                .compare_exchange(act, new, Ordering::AcqRel, Ordering::Relaxed)
            {
                Ok(_) => return,
                Err(now) => act = now,
            }
        }
    }

    /// `rwmutex_transfer_read_lock`: wake the queued readers. With `q` the queue is already
    /// locked.
    fn transfer_read_lock(&self, initial: u32, q: Option<MutexGuard<'_, Queue>>) {
        let q = match q {
            Some(q) => q,
            None => {
                let q = self.queue();
                let act = self.flgs.load(Ordering::Relaxed);
                if act & W_FLG != 0 || !matches!(q.items.front(), Some(QItem::Readers(_))) {
                    return; // Someone else woke the readers up.
                }
                q
            }
        };
        self.unlock_wake(false, initial, Some(q));
    }

    /// `rwmutex_unlock_wake`: hand the lock to the first queued writer or to the whole batch of
    /// queued readers. `transfer` carries the locked queue of a read lock transfer.
    fn unlock_wake(&self, have_w: bool, initial: u32, transfer: Option<MutexGuard<'_, Queue>>) {
        let mut act = initial;
        let mut q = match transfer {
            Some(q) => q,
            None => {
                if act & WAIT_FLGS == 0 {
                    if !have_w {
                        return;
                    }
                    while act & WAIT_FLGS == 0 {
                        match self.flgs.compare_exchange(
                            act,
                            act & !W_FLG,
                            Ordering::AcqRel,
                            Ordering::Relaxed,
                        ) {
                            Ok(_) => return,
                            Err(now) => act = now,
                        }
                    }
                }
                let q = self.queue();
                if !have_w {
                    if q.items.is_empty() {
                        return; // Already served.
                    }
                    act = self.flgs.load(Ordering::Relaxed);
                    if act == R_WAIT_FLG | R_FLG {
                        // Readers wait behind a read locked lock.
                    } else if act & !WAIT_FLGS != 0 {
                        return; // Already served.
                    }
                }
                q
            }
        };
        match q.items.front() {
            None => {}
            Some(QItem::Writer(_)) => {
                if !have_w {
                    act = self.flgs.fetch_or(W_FLG, Ordering::AcqRel) | W_FLG;
                }
                // With several write waiters the flags stay; otherwise the write-wait bit is
                // cleared, keeping the read-wait bit if readers queue behind.
                if q.writers() <= 1 {
                    let mut new = W_FLG;
                    if q.items.len() > 1 {
                        new |= R_WAIT_FLG;
                    }
                    self.wake_set_flags(new, act);
                }
                let Some(QItem::Writer(writer)) = q.items.pop_front() else {
                    return;
                };
                drop(q);
                Self::grant(&writer);
            }
            Some(QItem::Readers(_)) => {
                let Some(QItem::Readers(batch)) = q.items.pop_front() else {
                    return;
                };
                // The read locks of the whole batch are granted at once.
                let mut new;
                if let Some(readers) = &self.readers {
                    for slot in &readers.slots {
                        let waiting = slot.waiting.swap(0, Ordering::Relaxed);
                        if waiting != 0 {
                            slot.readers.fetch_add(waiting as i32, Ordering::Relaxed);
                        }
                    }
                    new = R_FLG;
                } else {
                    new = batch.len() as u32;
                }
                if !q.items.is_empty() {
                    new |= W_WAIT_FLG;
                }
                self.wake_set_flags(new, act);
                drop(q);
                for reader in &batch {
                    Self::grant(reader);
                }
            }
        }
    }
}

/// A value protected by a [`RwMtx`].
pub struct RwMtxLock<T> {
    mtx: RwMtx,
    data: UnsafeCell<T>,
}

// SAFETY: the value is reached only through a read guard (shared access while no writer holds
// the mutex) or the write guard (exclusive access), which the mutex hands out as an
// `std::sync::RwLock` would.
unsafe impl<T: Send + Sync> Sync for RwMtxLock<T> {}

/// Shared access.
pub struct RwMtxReadGuard<'a, T> {
    lock: &'a RwMtxLock<T>,
    group: usize,
}

/// Exclusive access.
pub struct RwMtxWriteGuard<'a, T> {
    lock: &'a RwMtxLock<T>,
}

impl<T> RwMtxLock<T> {
    /// Create an unlocked lock of the normal type around `value`.
    pub fn new(value: T) -> Self {
        Self {
            mtx: RwMtx::new(),
            data: UnsafeCell::new(value),
        }
    }

    /// Create an unlocked frequent-read lock around `value`.
    pub fn new_freq_read(value: T) -> Self {
        Self {
            mtx: RwMtx::new_freq_read(),
            data: UnsafeCell::new(value),
        }
    }

    /// Access the value of a lock nobody else holds.
    pub fn get_mut(&mut self) -> &mut T {
        self.data.get_mut()
    }

    /// Lock for reading (`ethr_rwmutex_rlock`) as the calling thread's reader group.
    pub fn read(&self) -> RwMtxReadGuard<'_, T> {
        self.read_at(if self.mtx.readers.is_some() {
            arinsal_term::current_reader_group()
        } else {
            0
        })
    }

    /// Lock for reading in reader group `group`, the scheduler id of the caller.
    #[inline]
    pub fn read_at(&self, group: usize) -> RwMtxReadGuard<'_, T> {
        self.mtx.read_lock(group);
        RwMtxReadGuard { lock: self, group }
    }

    /// Try to lock for reading in reader group `group` (`ethr_rwmutex_tryrlock`).
    pub fn try_read_at(&self, group: usize) -> Option<RwMtxReadGuard<'_, T>> {
        self.mtx
            .try_read_lock(group)
            .then(|| RwMtxReadGuard { lock: self, group })
    }

    /// Lock for writing (`ethr_rwmutex_rwlock`).
    #[inline]
    pub fn write(&self) -> RwMtxWriteGuard<'_, T> {
        self.mtx.write_lock();
        RwMtxWriteGuard { lock: self }
    }

    /// Try to lock for writing (`ethr_rwmutex_tryrwlock`).
    pub fn try_write(&self) -> Option<RwMtxWriteGuard<'_, T>> {
        self.mtx
            .try_write_lock()
            .then(|| RwMtxWriteGuard { lock: self })
    }
}

impl<T> std::ops::Deref for RwMtxReadGuard<'_, T> {
    type Target = T;

    #[inline]
    fn deref(&self) -> &T {
        // SAFETY: this guard holds a read lock, so no writer holds the value.
        unsafe { &*self.lock.data.get() }
    }
}

impl<T> Drop for RwMtxReadGuard<'_, T> {
    #[inline]
    fn drop(&mut self) {
        self.lock.mtx.read_unlock(self.group);
    }
}

impl<T> std::ops::Deref for RwMtxWriteGuard<'_, T> {
    type Target = T;

    #[inline]
    fn deref(&self) -> &T {
        // SAFETY: this guard holds the write lock.
        unsafe { &*self.lock.data.get() }
    }
}

impl<T> std::ops::DerefMut for RwMtxWriteGuard<'_, T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: this guard holds the write lock, so it is the only access to the value.
        unsafe { &mut *self.lock.data.get() }
    }
}

impl<T> Drop for RwMtxWriteGuard<'_, T> {
    #[inline]
    fn drop(&mut self) {
        self.lock.mtx.write_unlock();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! lock_tests {
        ($module:ident, $new:expr) => {
            mod $module {
                use super::*;

                fn make<T>(value: T) -> RwMtxLock<T> {
                    $new(value)
                }

                #[test]
                fn writers_exclude_each_other_and_readers() {
                    let lock = Arc::new(make(0_u64));
                    let readers_ok = Arc::new(AtomicUsize::new(0));
                    let mut threads = Vec::new();
                    for id in 0..8 {
                        let lock = Arc::clone(&lock);
                        let readers_ok = Arc::clone(&readers_ok);
                        threads.push(std::thread::spawn(move || {
                            for round in 0..20_000 {
                                if (round + id) % 4 == 0 {
                                    let mut guard = lock.write();
                                    let before = *guard;
                                    *guard = before + 1;
                                } else {
                                    let guard = lock.read_at(id);
                                    let seen = *guard;
                                    assert!(seen <= 8 * 20_000);
                                    readers_ok.fetch_add(1, Ordering::Relaxed);
                                }
                            }
                        }));
                    }
                    for thread in threads {
                        thread.join().unwrap();
                    }
                    assert_eq!(*lock.read(), 8 * 5_000);
                    assert!(readers_ok.load(Ordering::Relaxed) > 0);
                }

                #[test]
                fn readers_never_see_a_torn_write() {
                    struct Pair {
                        a: u64,
                        b: u64,
                    }
                    let lock = Arc::new(make(Pair { a: 0, b: 0 }));
                    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
                    let mut threads = Vec::new();
                    for id in 0..6 {
                        let lock = Arc::clone(&lock);
                        let stop = Arc::clone(&stop);
                        threads.push(std::thread::spawn(move || {
                            while !stop.load(Ordering::Relaxed) {
                                let guard = lock.read_at(id);
                                assert_eq!(guard.a, guard.b);
                            }
                        }));
                    }
                    for round in 1..=3_000 {
                        let mut guard = lock.write();
                        guard.a = round;
                        guard.b = round;
                    }
                    stop.store(true, Ordering::Relaxed);
                    for thread in threads {
                        thread.join().unwrap();
                    }
                }

                #[test]
                fn a_waiting_writer_blocks_new_readers_then_hands_over() {
                    let lock = Arc::new(make(0_u32));
                    let reader = lock.read_at(1);
                    let writer = {
                        let lock = Arc::clone(&lock);
                        std::thread::spawn(move || {
                            *lock.write() += 1;
                        })
                    };
                    // Let the writer queue behind the read lock.
                    while lock.mtx.flgs.load(Ordering::Acquire) & W_WAIT_FLG == 0 {
                        std::thread::yield_now();
                    }
                    assert!(
                        lock.try_read_at(2).is_none(),
                        "the write-wait bit stops readers"
                    );
                    drop(reader);
                    writer.join().unwrap();
                    assert_eq!(*lock.read(), 1);
                }

                #[test]
                fn queued_readers_are_granted_together() {
                    let lock = Arc::new(make(7_u32));
                    let writing = lock.write();
                    let mut threads = Vec::new();
                    for id in 0..4 {
                        let lock = Arc::clone(&lock);
                        threads.push(std::thread::spawn(move || *lock.read_at(id)));
                    }
                    while lock.mtx.flgs.load(Ordering::Acquire) & R_WAIT_FLG == 0 {
                        std::thread::yield_now();
                    }
                    drop(writing);
                    for thread in threads {
                        assert_eq!(thread.join().unwrap(), 7);
                    }
                    // Every read lock was released again: a writer gets the lock.
                    assert!(lock.try_write().is_some());
                }

                #[test]
                fn mixed_blocking_and_try_operations_keep_the_lock_consistent() {
                    struct Pair {
                        a: u64,
                        b: u64,
                    }
                    let lock = Arc::new(make(Pair { a: 0, b: 0 }));
                    let writes = Arc::new(AtomicUsize::new(0));
                    let mut threads = Vec::new();
                    for id in 0..12_usize {
                        let lock = Arc::clone(&lock);
                        let writes = Arc::clone(&writes);
                        threads.push(std::thread::spawn(move || {
                            let mut state = (id as u64 + 1).wrapping_mul(0x9e37_79b9_7f4a_7c15);
                            for _ in 0..30_000 {
                                state ^= state << 13;
                                state ^= state >> 7;
                                state ^= state << 17;
                                match state % 8 {
                                    0 => {
                                        let mut guard = lock.write();
                                        guard.a += 1;
                                        guard.b += 1;
                                        writes.fetch_add(1, Ordering::Relaxed);
                                    }
                                    1 => {
                                        if let Some(mut guard) = lock.try_write() {
                                            guard.a += 1;
                                            guard.b += 1;
                                            writes.fetch_add(1, Ordering::Relaxed);
                                        }
                                    }
                                    2 => {
                                        if let Some(guard) = lock.try_read_at(id) {
                                            assert_eq!(guard.a, guard.b);
                                        }
                                    }
                                    _ => {
                                        let guard = lock.read_at(id % 3);
                                        assert_eq!(guard.a, guard.b);
                                    }
                                }
                            }
                        }));
                    }
                    for thread in threads {
                        thread.join().unwrap();
                    }
                    let guard = lock.write();
                    assert_eq!(guard.a as usize, writes.load(Ordering::Relaxed));
                    assert_eq!(guard.a, guard.b);
                }

                #[test]
                fn try_locks_report_a_busy_lock() {
                    let lock = make(0_u32);
                    {
                        let _read = lock.try_read_at(0).expect("free lock");
                        assert!(lock.try_write().is_none() || lock.mtx.readers.is_some());
                    }
                    let write = lock.try_write().expect("free lock");
                    assert!(lock.try_read_at(0).is_none());
                    assert!(lock.try_write().is_none());
                    drop(write);
                    assert!(lock.try_read_at(3).is_some());
                }
            }
        };
    }

    lock_tests!(normal, RwMtxLock::new);
    lock_tests!(frequent_read, RwMtxLock::new_freq_read);
}
