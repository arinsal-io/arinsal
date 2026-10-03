//! Rust rwmutex backend for OTP's internal test callback table.

use std::hint::black_box;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Condvar, Mutex};

const EINVAL: isize = 22;
const EBUSY: isize = 16;

struct RwMutex {
    state: AtomicUsize,
    waiting_writers: AtomicUsize,
    wait_lock: Mutex<()>,
    changed: Condvar,
}

impl RwMutex {
    const WRITER: usize = 1usize << (usize::BITS - 1);
    const READERS: usize = !Self::WRITER;

    fn new() -> Self {
        Self {
            state: AtomicUsize::new(0),
            waiting_writers: AtomicUsize::new(0),
            wait_lock: Mutex::new(()),
            changed: Condvar::new(),
        }
    }

    fn try_acquire(&self, write: bool) -> bool {
        if write {
            return self
                .state
                .compare_exchange(0, Self::WRITER, Ordering::Acquire, Ordering::Relaxed)
                .is_ok();
        }
        let mut current = self.state.load(Ordering::Relaxed);
        loop {
            if current & Self::WRITER != 0
                || current & Self::READERS == Self::READERS
                || self.waiting_writers.load(Ordering::Relaxed) != 0
            {
                return false;
            }
            match self.state.compare_exchange_weak(
                current,
                current + 1,
                Ordering::Acquire,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(actual) => current = actual,
            }
        }
    }

    fn lock(&self, write: bool) {
        if write {
            self.waiting_writers.fetch_add(1, Ordering::Relaxed);
        }
        if self.try_acquire(write) {
            if write {
                self.waiting_writers.fetch_sub(1, Ordering::Relaxed);
            }
            return;
        }
        let mut guard = self
            .wait_lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        while !self.try_acquire(write) {
            guard = self
                .changed
                .wait(guard)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
        if write {
            self.waiting_writers.fetch_sub(1, Ordering::Relaxed);
        }
    }

    fn unlock(&self, write: bool) {
        if write {
            let _guard = self
                .wait_lock
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            self.state.store(0, Ordering::Release);
            self.changed.notify_all();
        } else {
            let previous = self.state.fetch_sub(1, Ordering::Release);
            if previous == 1 {
                let _guard = self
                    .wait_lock
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                self.changed.notify_all();
            }
        }
    }
}

// Port of erts/emulator/beam/erl_internal_test.c:32-49, OTP-29.1.1.
// The ABI adapters in shim.c store a boxed Rust lock in the rwmutex's opaque storage.
#[unsafe(no_mangle)]
pub extern "C" fn arinsal_internal_test_dispatch(op: u32, a: usize, _b: usize) -> isize {
    // SAFETY: shim.c passes a live lock handle returned by this dispatcher for lock operations;
    // destroy is called after its users have joined, matching ethr_rwmutex's lifetime contract.
    unsafe {
        match op {
            6 => {
                if a == 0 {
                    EINVAL
                } else {
                    Box::into_raw(Box::new(RwMutex::new())) as isize
                }
            }
            7 => {
                if a == 0 {
                    EINVAL
                } else {
                    drop(Box::from_raw(a as *mut RwMutex));
                    0
                }
            }
            8 => rwmutex_lock(&*(a as *const RwMutex), false, false),
            9 => rwmutex_unlock(&*(a as *const RwMutex), false),
            10 => rwmutex_lock(&*(a as *const RwMutex), true, false),
            11 => rwmutex_unlock(&*(a as *const RwMutex), true),
            12 => rwmutex_lock(&*(a as *const RwMutex), false, true),
            13 => rwmutex_lock(&*(a as *const RwMutex), true, true),
            _ => EINVAL,
        }
    }
}

fn rwmutex_lock(lock: &RwMutex, write: bool, try_lock: bool) -> isize {
    if try_lock {
        return if lock.try_acquire(write) { 0 } else { EBUSY };
    }
    lock.lock(write);
    0
}

fn rwmutex_unlock(lock: &RwMutex, write: bool) -> isize {
    lock.unlock(write);
    0
}

pub(crate) fn retain_exports() {
    black_box(arinsal_internal_test_dispatch as *const ());
}
