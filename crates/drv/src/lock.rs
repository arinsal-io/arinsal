//! Re-entrant callback lock.
//!
//! erts holds the port (or driver) lock across a callback, and a driver API
//! call made from inside that callback (e.g. `driver_failure` calling `stop`
//! through `terminate_port`) runs with the lock already held by the same
//! thread. Port of the locking discipline in erts/emulator/beam/io.c, OTP-29.1.1.

// parking_lot keeps the mutex and condvar inline; std's pthread-backed ones are two extra
// allocations per lock.
use parking_lot::{Condvar, Mutex};
use std::thread::{self, ThreadId};

#[derive(Default)]
pub(crate) struct ReentrantLock {
    state: Mutex<(Option<ThreadId>, usize)>,
    released: Condvar,
}

pub(crate) struct ReentrantGuard<'a>(&'a ReentrantLock);

impl ReentrantLock {
    pub(crate) fn lock(&self) -> ReentrantGuard<'_> {
        let me = thread::current().id();
        let mut state = self.state.lock();
        loop {
            match state.0 {
                None => {
                    *state = (Some(me), 1);
                    break;
                }
                Some(owner) if owner == me => {
                    state.1 += 1;
                    break;
                }
                Some(_) => self.released.wait(&mut state),
            }
        }
        ReentrantGuard(self)
    }
}

impl Drop for ReentrantGuard<'_> {
    fn drop(&mut self) {
        let mut state = self.0.state.lock();
        state.1 -= 1;
        if state.1 == 0 {
            state.0 = None;
            self.0.released.notify_one();
        }
    }
}

impl ReentrantLock {
    /// `erts_port_trylock`: `None` when another thread holds the lock.
    pub(crate) fn try_lock(&self) -> Option<ReentrantGuard<'_>> {
        let me = thread::current().id();
        let mut state = self.state.lock();
        match state.0 {
            None => *state = (Some(me), 1),
            Some(owner) if owner == me => state.1 += 1,
            Some(_) => return None,
        }
        Some(ReentrantGuard(self))
    }

    /// The calling thread holds the lock (`erts_lc_is_port_locked`).
    pub(crate) fn held_here(&self) -> bool {
        self.state.lock().0 == Some(thread::current().id())
    }
}
