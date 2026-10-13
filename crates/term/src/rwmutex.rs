//! Frequent-read reader/writer lock.
//!
//! Port of `ethr_rwmutex` with `ETHR_RWMUTEX_TYPE_FREQUENT_READ`
//! (`erts/lib_src/common/ethr_mutex.c:2200` `rwmutex_freqread_rlock`,
//! `erts/emulator/beam/erl_threads.h:349`), OTP-29.1.1.
//!
//! Each scheduler has its own cache-line reader indicator (`tse->rgix`). A reader
//! increments only that line, then checks the writer flag. A writer sets the flag
//! and waits until every indicator is zero. Uncontended readers do not share a
//! counter cache line.

use std::cell::Cell;
use std::ops::{Deref, DerefMut};
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicUsize, Ordering};
use std::sync::{Condvar, Mutex, MutexGuard};

/// Reader indicator slots a lock allocates. erts sizes its array from the scheduler count, so
/// the used length is `reader_groups_array_size`; this bounds it at 64 groups.
const READER_SLOTS: usize = 64;
/// `reader_groups_array_size` (ethr_mutex.c:145, 168-170). Set once at late init, before any
/// lock is used; a writer scans this many indicators and readers index modulo it.
static READER_GROUPS_ARRAY_SIZE: AtomicUsize = AtomicUsize::new(READER_SLOTS);

/// Late init of the reader groups from the scheduler count, as `ethr_mutex_lib_late_init`
/// (ethr_mutex.c:151-170) sets `reader_groups_array_size`: `1` for at most one group, else one
/// more than the group count.
pub fn set_reader_groups(no_reader_groups: usize) {
    let size = if no_reader_groups <= 1 {
        1
    } else {
        no_reader_groups + 1
    };
    READER_GROUPS_ARRAY_SIZE.store(size.min(READER_SLOTS), Ordering::Release);
}

fn reader_groups_array_size() -> usize {
    READER_GROUPS_ARRAY_SIZE.load(Ordering::Acquire)
}

thread_local! {
    static READER_GROUP: Cell<Option<usize>> = const { Cell::new(None) };
    static FALLBACK_SLOT: Cell<usize> = const { Cell::new(usize::MAX) };
}

static NEXT_FALLBACK: AtomicUsize = AtomicUsize::new(0);

/// Publish this thread's reader group. Schedulers pass their zero-based id,
/// which is `tse->rgix` for `ETHR_RWMUTEX_TYPE_FREQUENT_READ`.
pub fn set_reader_group(id: usize) {
    READER_GROUP.with(|slot| slot.set(Some(id)));
}

fn reader_index() -> usize {
    READER_GROUP.with(|group| {
        if let Some(id) = group.get() {
            return id % reader_groups_array_size();
        }
        FALLBACK_SLOT.with(|slot| {
            if slot.get() == usize::MAX {
                slot.set(
                    NEXT_FALLBACK.fetch_add(1, Ordering::Relaxed) % reader_groups_array_size(),
                );
            }
            slot.get()
        })
    })
}

#[repr(C, align(64))]
struct ReaderSlot {
    readers: AtomicI32,
}

/// `erts_rwmtx` created with `ERTS_RWMTX_TYPE_FREQUENT_READ`.
pub struct FrequentReadRwLock<T> {
    writing: AtomicBool,
    readers: Box<[ReaderSlot]>,
    gate: Mutex<()>,
    cv: Condvar,
    data: std::cell::UnsafeCell<T>,
}

// SAFETY: a read guard shares `&T` only while `writing` is false and this
// thread's reader slot is nonzero. The write guard is the only `&mut T`, and
// it is issued only after every reader slot is zero. The gate mutex orders
// those hand-offs. `T: Send + Sync` matches `std::sync::RwLock`.
unsafe impl<T: Send + Sync> Sync for FrequentReadRwLock<T> {}

impl<T> FrequentReadRwLock<T> {
    /// Create a lock in the unlocked state.
    pub fn new(value: T) -> Self {
        let readers = (0..READER_SLOTS)
            .map(|_| ReaderSlot {
                readers: AtomicI32::new(0),
            })
            .collect();
        Self {
            writing: AtomicBool::new(false),
            readers,
            gate: Mutex::new(()),
            cv: Condvar::new(),
            data: std::cell::UnsafeCell::new(value),
        }
    }

    /// Access the value exclusively borrowed through the lock itself.
    pub fn get_mut(&mut self) -> &mut T {
        self.data.get_mut()
    }

    /// Shared lock. Port of `rwmutex_freqread_rlock` (try path, then wait).
    pub fn read(&self) -> FrequentReadGuard<'_, T> {
        let index = reader_index();
        loop {
            self.readers[index].readers.fetch_add(1, Ordering::AcqRel);
            std::sync::atomic::fence(Ordering::SeqCst);
            if !self.writing.load(Ordering::Acquire) {
                return FrequentReadGuard { lock: self, index };
            }
            self.readers[index].readers.fetch_sub(1, Ordering::AcqRel);
            let mut gate = self.gate();
            self.cv.notify_all();
            while self.writing.load(Ordering::Acquire) {
                gate = self.cv.wait(gate).expect("frequent-read rwmutex");
            }
            drop(gate);
        }
    }

    /// Exclusive lock. Port of `rwmutex_freqread_rwlock_wait`: set the writer
    /// flag, then wait until every reader indicator is zero.
    pub fn write(&self) -> FrequentWriteGuard<'_, T> {
        let mut gate = self.gate();
        while self.writing.load(Ordering::Acquire) {
            gate = self.cv.wait(gate).expect("frequent-read rwmutex");
        }
        self.writing.store(true, Ordering::Release);
        drop(gate);
        loop {
            let gate = self.gate();
            if self.readers_are_zero() {
                drop(gate);
                break;
            }
            let _gate = self.cv.wait(gate).expect("frequent-read rwmutex");
        }
        FrequentWriteGuard { lock: self }
    }

    fn gate(&self) -> MutexGuard<'_, ()> {
        self.gate
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }

    fn readers_are_zero(&self) -> bool {
        self.readers[..reader_groups_array_size()]
            .iter()
            .all(|slot| slot.readers.load(Ordering::Acquire) == 0)
    }

    fn unlock_read(&self, index: usize) {
        let left = self.readers[index].readers.fetch_sub(1, Ordering::AcqRel) - 1;
        if left == 0 && self.writing.load(Ordering::Acquire) {
            let _gate = self.gate();
            self.cv.notify_all();
        }
    }

    fn unlock_write(&self) {
        let _gate = self.gate();
        self.writing.store(false, Ordering::Release);
        self.cv.notify_all();
    }
}

/// Shared guard for [`FrequentReadRwLock`].
pub struct FrequentReadGuard<'a, T> {
    lock: &'a FrequentReadRwLock<T>,
    index: usize,
}

impl<T> Deref for FrequentReadGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &T {
        // SAFETY: this thread holds a nonzero reader indicator and observed
        // `writing == false` after the increment, so no write guard exists.
        unsafe { &*self.lock.data.get() }
    }
}

impl<T> Drop for FrequentReadGuard<'_, T> {
    fn drop(&mut self) {
        self.lock.unlock_read(self.index);
    }
}

/// Exclusive guard for [`FrequentReadRwLock`].
pub struct FrequentWriteGuard<'a, T> {
    lock: &'a FrequentReadRwLock<T>,
}

impl<T> Deref for FrequentWriteGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &T {
        // SAFETY: `writing` is set and every reader indicator was zero when
        // this guard was created; new readers wait on the flag.
        unsafe { &*self.lock.data.get() }
    }
}

impl<T> DerefMut for FrequentWriteGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: same exclusion as `deref`; this guard is the unique writer.
        unsafe { &mut *self.lock.data.get() }
    }
}

impl<T> Drop for FrequentWriteGuard<'_, T> {
    fn drop(&mut self) {
        self.lock.unlock_write();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Pair {
        a: u64,
        b: u64,
    }

    #[test]
    fn readers_observe_only_complete_writes() {
        let lock = FrequentReadRwLock::new(Pair { a: 0, b: 0 });
        std::thread::scope(|scope| {
            for _ in 0..4 {
                scope.spawn(|| {
                    for _ in 0..2_000 {
                        let guard = lock.read();
                        assert_eq!(guard.a, guard.b);
                    }
                });
            }
            scope.spawn(|| {
                for i in 0..2_000 {
                    let mut guard = lock.write();
                    guard.a = i;
                    guard.b = i;
                }
            });
        });
    }
}
