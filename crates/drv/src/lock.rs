//! Re-entrant callback lock.
//!
//! erts holds the port (or driver) lock across a callback, and a driver API
//! call made from inside that callback (e.g. `driver_failure` calling `stop`
//! through `terminate_port`) runs with the lock already held by the same
//! thread. Port of the locking discipline in erts/emulator/beam/io.c, OTP-29.1.1.

use std::sync::{Condvar, Mutex};
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
        let mut state = self.state.lock().unwrap();
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
                Some(_) => state = self.released.wait(state).unwrap(),
            }
        }
        ReentrantGuard(self)
    }
}

impl Drop for ReentrantGuard<'_> {
    fn drop(&mut self) {
        let mut state = self.0.state.lock().unwrap();
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
        let mut state = self.state.lock().unwrap();
        match state.0 {
            None => *state = (Some(me), 1),
            Some(owner) if owner == me => state.1 += 1,
            Some(_) => return None,
        }
        Some(ReentrantGuard(self))
    }
}
