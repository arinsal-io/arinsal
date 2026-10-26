//! Re-entrant callback lock.
//!
//! erts holds the port (or driver) lock across a callback, and a driver API
//! call made from inside that callback (e.g. `driver_failure` calling `stop`
//! through `terminate_port`) runs with the lock already held by the same
//! thread. Port of the locking discipline in erts/emulator/beam/io.c, OTP-29.1.1.

use parking_lot::{ReentrantMutex, ReentrantMutexGuard};

/// One word of owner, one of count and the raw mutex; the owner is read with a cheap
/// per-thread address, not `std::thread::current()`.
#[derive(Default)]
pub(crate) struct ReentrantLock(ReentrantMutex<()>);

pub(crate) struct ReentrantGuard<'a>(#[allow(dead_code)] ReentrantMutexGuard<'a, ()>);

impl ReentrantLock {
    pub(crate) fn lock(&self) -> ReentrantGuard<'_> {
        ReentrantGuard(self.0.lock())
    }

    /// `erts_port_trylock`: `None` when another thread holds the lock.
    pub(crate) fn try_lock(&self) -> Option<ReentrantGuard<'_>> {
        self.0.try_lock().map(ReentrantGuard)
    }

    /// The calling thread holds the lock (`erts_lc_is_port_locked`).
    pub(crate) fn held_here(&self) -> bool {
        self.0.is_owned_by_current_thread()
    }
}
