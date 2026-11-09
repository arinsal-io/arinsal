use super::erts_poll_max_fds;
use parking_lot::{Mutex, MutexGuard};
use std::cell::UnsafeCell;
use std::io;
use std::ops::{Deref, DerefMut};
use std::os::fd::RawFd;
use std::sync::atomic::{AtomicUsize, Ordering};

const FD_LOCK_COUNT: usize = 128;
const FD_TABLE_MIN_LENGTH: usize = 1024;
const FD_TABLE_EXP_THRESHOLD: usize = 2048 * 1024;

/// Dense descriptor state with the fd-hashed locking used by Unix erts.
// Port of erts/emulator/sys/common/erl_check_io.c (grow_drv_ev_state, fd_mtx), OTP-29.1.1.
pub(super) struct FdStateTable<T> {
    states: UnsafeCell<Vec<T>>,
    len: AtomicUsize,
    grow_lock: Mutex<()>,
    locks: [Mutex<()>; FD_LOCK_COUNT],
    max_fds: usize,
}

// SAFETY: Access to each element requires its fd stripe. Reallocation takes every stripe.
unsafe impl<T: Send> Send for FdStateTable<T> {}
// SAFETY: Element access and vector growth are synchronized by the fd stripes.
unsafe impl<T: Send> Sync for FdStateTable<T> {}

impl<T: Default> Default for FdStateTable<T> {
    fn default() -> Self {
        Self {
            states: UnsafeCell::new(Vec::new()),
            len: AtomicUsize::new(0),
            grow_lock: Mutex::new(()),
            locks: std::array::from_fn(|_| Mutex::new(())),
            max_fds: erts_poll_max_fds(),
        }
    }
}

impl<T: Default> FdStateTable<T> {
    /// Lock and return the state for one fd. The global grow lock is absent from this path.
    pub(super) fn lock_slots(&self, fd: RawFd) -> io::Result<FdStateGuard<'_, T>> {
        let index = usize::try_from(fd)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "negative descriptor"))?;
        if index >= self.max_fds {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "descriptor exceeds the ERTS poll limit",
            ));
        }
        self.ensure_fd(index)?;

        let lock = &self.locks[index % FD_LOCK_COUNT];
        let guard = lock.lock();
        // SAFETY: The stripe guard prevents vector growth until it is dropped. The index was
        // initialized by ensure_fd, and distinct indices are only accessed under their stripes.
        let state = unsafe { (&mut *self.states.get()).as_mut_ptr().add(index) };
        Ok(FdStateGuard {
            state,
            _guard: guard,
        })
    }

    pub(super) fn with_all_states<R>(&self, f: impl FnOnce(&[T]) -> R) -> R {
        let _locks: [Option<MutexGuard<'_, ()>>; FD_LOCK_COUNT] =
            std::array::from_fn(|index| Some(self.locks[index].lock()));
        // SAFETY: All stripes are held, preventing vector reallocation and mutable element
        // access while the shared slice is in use.
        let states = unsafe { &*self.states.get() };
        f(states)
    }

    // Port of erts/emulator/sys/common/erl_check_io.c (grow_drv_ev_state): serialize growers,
    // lock every fd stripe, realloc and zero/init the new range, then publish the new length.
    fn ensure_fd(&self, index: usize) -> io::Result<()> {
        if index < self.len.load(Ordering::Acquire) {
            return Ok(());
        }
        let _grow = self.grow_lock.lock();
        let old_len = self.len.load(Ordering::Relaxed);
        if index < old_len {
            return Ok(());
        }

        let _locks: [Option<MutexGuard<'_, ()>>; FD_LOCK_COUNT] =
            std::array::from_fn(|index| Some(self.locks[index].lock()));
        let need_len = index + 1;
        let mut new_len;
        if need_len < FD_TABLE_MIN_LENGTH {
            new_len = FD_TABLE_MIN_LENGTH;
        } else {
            new_len = old_len.max(FD_TABLE_MIN_LENGTH);
            loop {
                new_len = if new_len < FD_TABLE_EXP_THRESHOLD {
                    new_len.saturating_mul(2)
                } else {
                    new_len.saturating_add(FD_TABLE_EXP_THRESHOLD)
                };
                if new_len >= need_len {
                    break;
                }
            }
        }
        new_len = new_len.min(self.max_fds);
        // SAFETY: All fd stripes are held, so no element reference or vector access can race
        // this resize. Grow lock serializes the only mutating vector operation.
        unsafe {
            let states = &mut *self.states.get();
            states.reserve_exact(new_len - old_len);
            states.resize_with(new_len, T::default);
        }
        self.len.store(new_len, Ordering::Release);
        Ok(())
    }
}

pub(super) struct FdStateGuard<'a, T> {
    state: *mut T,
    _guard: MutexGuard<'a, ()>,
}

impl<T> Deref for FdStateGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        // SAFETY: The held fd stripe pins the vector allocation and exclusively owns this fd.
        unsafe { &*self.state }
    }
}

impl<T> DerefMut for FdStateGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        // SAFETY: The held fd stripe is the exclusive lock for this fd's state.
        unsafe { &mut *self.state }
    }
}
