//! Reader/writer mutex of erts' `ETHR_RWMUTEX_TYPE_NORMAL`.
//!
//! Port of erts/lib_src/common/ethr_mutex.c (`ethr_rwmutex_*`, `event_wait`,
//! `rwmutex_unlock_wake`, `wake_readers`, `write_lock_wait`, `rwmutex_normal_rlock_wait`) and
//! erts/include/internal/ethr_mutex.h, OTP-29.1.1, in its cmpxchg flavour
//! (`ETHR_RLOCK_WITH_INC_DEC` is disabled upstream).
//!
//! One 32 bit flag word holds the write flag, the write-wait and read-wait flags and the
//! reader count. Contenders spin on it, then queue on a per-lock wait queue and spin on their
//! own event before they park. Wakers hand the lock over: a woken writer owns it, and a woken
//! reader group is granted its read locks by the waker.
//!
//! The protected value lives in a `std` lock that is only ever taken while the flag word grants
//! the access, so that it never blocks and the whole port needs no `unsafe`.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::thread::Thread;

const W_FLG: u32 = 1 << 31;
const W_WAIT_FLG: u32 = 1 << 30;
const R_WAIT_FLG: u32 = 1 << 29;
const WAIT_FLGS: u32 = W_WAIT_FLG | R_WAIT_FLG;

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

/// A queued waiter: erts' `ethr_ts_event` with its `uaflgs` and event.
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

/// The lock proper: `ethr_rwmutex` of type normal.
pub struct RwMtx {
    flgs: AtomicU32,
    aux_scnt: i32,
    main_scnt: i32,
    q: Mutex<Queue>,
}

impl Default for RwMtx {
    fn default() -> Self {
        Self::new()
    }
}

impl RwMtx {
    /// `ethr_rwmutex_init` with the default spin counts (`mtxb_init`).
    pub fn new() -> Self {
        let aux_scnt = DEFAULT_AUX_SPINCOUNT;
        Self {
            flgs: AtomicU32::new(0),
            aux_scnt,
            main_scnt: default_main_spincount().max(aux_scnt),
            q: Mutex::new(Queue::default()),
        }
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

    /// `ethr_rwmutex_tryrlock`.
    pub fn try_read_lock(&self) -> bool {
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
    pub fn read_lock(&self) {
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
    pub fn read_unlock(&self) {
        let act = self.flgs.fetch_sub(1, Ordering::Release) - 1;
        if act & WAIT_FLGS != 0 && act & !WAIT_FLGS == 0 {
            self.unlock_wake(false, act);
        }
    }

    /// `ethr_rwmutex_tryrwlock`.
    pub fn try_write_lock(&self) -> bool {
        self.flgs
            .compare_exchange(0, W_FLG, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
    }

    /// `ethr_rwmutex_rwlock`.
    pub fn write_lock(&self) {
        if let Err(act) = self
            .flgs
            .compare_exchange(0, W_FLG, Ordering::Acquire, Ordering::Relaxed)
        {
            self.write_lock_wait(act);
        }
    }

    /// `ethr_rwmutex_rwunlock`.
    pub fn write_unlock(&self) {
        if let Err(act) = self
            .flgs
            .compare_exchange(W_FLG, 0, Ordering::Release, Ordering::Relaxed)
        {
            self.unlock_wake(true, act);
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
                    self.event_wait(scnt, R_WAIT_FLG);
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

    /// `write_lock_wait` for the normal type.
    fn write_lock_wait(&self, initial: u32) {
        let mut act = initial;
        let mut start_scnt = self.initial_spincount();
        let mut scnt = start_scnt;
        let mut until_yield = YIELD_AFTER_BUSY_LOOPS;
        // Spin trying to write lock for a while. If unsuccessful, wait on the event.
        loop {
            while act != 0 {
                if scnt <= 0 {
                    scnt = 0;
                    if self.update_spincount(&mut start_scnt, &mut scnt) {
                        self.event_wait(scnt, W_WAIT_FLG);
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
    /// event until the waker clears `uaflgs`.
    fn event_wait(&self, spincount: i32, kind: u32) {
        let waiter = Arc::new(Waiter {
            uaflgs: AtomicU32::new(kind),
            thread: std::thread::current(),
        });
        let mut q = self.queue();
        let mut act = self.flgs.load(Ordering::Relaxed);
        if act & kind != 0 {
            // The wait bit is already there: enqueue.
            if kind == W_WAIT_FLG {
                q.items.push_back(QItem::Writer(Arc::clone(&waiter)));
            } else if let Some(batch) = q.reader_batch() {
                batch.push(Arc::clone(&waiter));
            } else {
                // The bit says readers wait; their batch is queued under the same lock.
                q.items.push_back(QItem::Readers(vec![Arc::clone(&waiter)]));
            }
        } else {
            // Set the wait bit.
            loop {
                let new = if kind == W_WAIT_FLG {
                    if act != 0 { act | W_WAIT_FLG } else { W_FLG }
                } else if act & (W_FLG | W_WAIT_FLG) != 0 {
                    act | R_WAIT_FLG
                } else {
                    act + 1
                };
                match self
                    .flgs
                    .compare_exchange(act, new, Ordering::Acquire, Ordering::Relaxed)
                {
                    Ok(_) => {
                        if new & kind == 0 {
                            return; // Got it.
                        }
                        break;
                    }
                    Err(now) => act = now,
                }
            }
            if kind == W_WAIT_FLG {
                q.items.push_back(QItem::Writer(Arc::clone(&waiter)));
            } else {
                q.items.push_back(QItem::Readers(vec![Arc::clone(&waiter)]));
            }
        }
        drop(q);
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

    fn grant(waiter: &Waiter) {
        waiter.uaflgs.store(0, Ordering::Release);
        waiter.thread.unpark();
    }

    /// `rwmutex_unlock_wake` for the normal type: hand the lock to the first queued writer or
    /// to the whole batch of queued readers.
    fn unlock_wake(&self, have_w: bool, initial: u32) {
        let mut act = initial;
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
        let mut q = self.queue();
        if !have_w {
            if q.items.is_empty() {
                return; // Already served.
            }
            act = self.flgs.load(Ordering::Relaxed);
            if act & !WAIT_FLGS != 0 {
                return; // Already served.
            }
        }
        match q.items.front() {
            None => {}
            Some(QItem::Writer(_)) => {
                if !have_w {
                    self.flgs.fetch_or(W_FLG, Ordering::AcqRel);
                }
                // With several write waiters the flags stay; otherwise the write-wait bit is
                // cleared, keeping the read-wait bit if readers queue behind.
                if q.writers() <= 1 {
                    let mut new = W_FLG;
                    if q.items.len() > 1 {
                        new |= R_WAIT_FLG;
                    }
                    self.flgs.store(new, Ordering::Release);
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
                let mut new = batch.len() as u32;
                if !q.items.is_empty() {
                    new |= W_WAIT_FLG;
                }
                self.flgs.store(new, Ordering::Release);
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
    data: RwLock<T>,
}

/// Shared access; the mutex is released after the value guard.
pub struct RwMtxReadGuard<'a, T> {
    lock: &'a RwMtxLock<T>,
    data: Option<RwLockReadGuard<'a, T>>,
}

/// Exclusive access; the mutex is released after the value guard.
pub struct RwMtxWriteGuard<'a, T> {
    lock: &'a RwMtxLock<T>,
    data: Option<RwLockWriteGuard<'a, T>>,
}

impl<T> RwMtxLock<T> {
    /// Create an unlocked lock around `value`.
    pub fn new(value: T) -> Self {
        Self {
            mtx: RwMtx::new(),
            data: RwLock::new(value),
        }
    }

    /// Lock for reading (`ethr_rwmutex_rlock`).
    pub fn read(&self) -> RwMtxReadGuard<'_, T> {
        self.mtx.read_lock();
        // Granted by the mutex, so the inner lock is free of writers.
        let data = self
            .data
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        RwMtxReadGuard {
            lock: self,
            data: Some(data),
        }
    }

    /// Lock for writing (`ethr_rwmutex_rwlock`).
    pub fn write(&self) -> RwMtxWriteGuard<'_, T> {
        self.mtx.write_lock();
        let data = self
            .data
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        RwMtxWriteGuard {
            lock: self,
            data: Some(data),
        }
    }
}

impl<T> std::ops::Deref for RwMtxReadGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &T {
        self.data.as_deref().expect("guard holds the value")
    }
}

impl<T> Drop for RwMtxReadGuard<'_, T> {
    fn drop(&mut self) {
        self.data = None;
        self.lock.mtx.read_unlock();
    }
}

impl<T> std::ops::Deref for RwMtxWriteGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &T {
        self.data.as_deref().expect("guard holds the value")
    }
}

impl<T> std::ops::DerefMut for RwMtxWriteGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        self.data.as_deref_mut().expect("guard holds the value")
    }
}

impl<T> Drop for RwMtxWriteGuard<'_, T> {
    fn drop(&mut self) {
        self.data = None;
        self.lock.mtx.write_unlock();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writers_exclude_each_other_and_readers() {
        let lock = Arc::new(RwMtxLock::new(0_u64));
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
                        let guard = lock.read();
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
    fn a_waiting_writer_blocks_new_readers_then_hands_over() {
        let lock = Arc::new(RwMtxLock::new(0_u32));
        let reader = lock.read();
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
            !lock.mtx.try_read_lock(),
            "the write-wait bit stops readers"
        );
        drop(reader);
        writer.join().unwrap();
        assert_eq!(*lock.read(), 1);
    }

    #[test]
    fn queued_readers_are_granted_together() {
        let lock = Arc::new(RwMtxLock::new(7_u32));
        let writing = lock.write();
        let mut threads = Vec::new();
        for _ in 0..4 {
            let lock = Arc::clone(&lock);
            threads.push(std::thread::spawn(move || *lock.read()));
        }
        while lock.mtx.flgs.load(Ordering::Acquire) & R_WAIT_FLG == 0 {
            std::thread::yield_now();
        }
        drop(writing);
        for thread in threads {
            assert_eq!(thread.join().unwrap(), 7);
        }
        assert_eq!(lock.mtx.flgs.load(Ordering::Acquire), 0);
    }
}
