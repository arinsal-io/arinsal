//! Intrusive per-priority lists and the published migration path block.
//!
//! Port of erts/emulator/beam/erl_process.h (`ErtsRunPrioQueue` { first, last } and
//! `Process.next/prev`) and erl_process.c (`enqueue_process_internal`, `dequeue_process`,
//! `unqueue_process`, the `ERTS_PSFLG_PROXY` entries made by `active_sys_enqueue`), OTP-29.1.1.
//!
//! A node is either a process (links in `Process.rq_link`; `IN_RUNQ` lives in the process state word) or a
//! proxy (a small heap node that stands for a process already queued at a lower priority).
//! Every node in a list owns one counted reference to its process. The links are only touched
//! by the thread that holds the run queue lock, which is the argument of every SAFETY comment
//! below.

use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

use crate::proc_ref::ProcRef;
use crate::{Enqueue, PROC_QUEUES, Scheduled, Task};

/// The published contiguous migration path block (`erts_migration_paths`).
// Port of erts/emulator/beam/erl_process.c (ErtsMigrationPaths), OTP-29.1.1.
pub(crate) struct MigrationPaths {
    current: std::sync::atomic::AtomicPtr<crate::balance::MigrationPath>,
    len: usize,
    progress: std::sync::Arc<crate::thr_progress::ThrProgress>,
}

/// Ownership of a removed block, released when its scheduler readers pass thread progress.
pub(crate) struct RetiredMigrationPaths {
    ptr: usize,
    len: usize,
}

impl Drop for RetiredMigrationPaths {
    fn drop(&mut self) {
        if self.ptr != 0 {
            // SAFETY: only `MigrationPaths::swap` and `take` construct this owner, and both
            // transfer one complete allocation to it.
            unsafe {
                drop(Box::from_raw(std::ptr::slice_from_raw_parts_mut(
                    self.ptr as *mut crate::balance::MigrationPath,
                    self.len,
                )));
            }
        }
    }
}

struct MigrationReadDelay<'a> {
    progress: &'a crate::thr_progress::ThrProgress,
    handle: Option<crate::thr_progress::DelayHandle>,
}

#[derive(Clone, Copy)]
enum MigrationReadRequest {
    Flags(usize),
    Path(usize, usize),
    Snapshot,
}

enum MigrationReadResult {
    Flags(u32),
    Path(u32, crate::balance::MigrationPrio),
    Snapshot(Vec<crate::balance::MigrationPath>),
}

impl Drop for MigrationReadDelay<'_> {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            crate::thr_progress::unmanaged_continue(self.progress, handle);
        }
    }
}

impl MigrationPaths {
    /// Install the initial zeroed migration path block.
    pub(crate) fn new(
        len: usize,
        progress: std::sync::Arc<crate::thr_progress::ThrProgress>,
    ) -> Self {
        Self {
            current: std::sync::atomic::AtomicPtr::new(allocate_migration_paths(vec![
                crate::balance::MigrationPath::NONE;
                len
            ])),
            len,
            progress,
        }
    }

    fn delay_read(&self) -> MigrationReadDelay<'_> {
        let handle = crate::thr_progress::unmanaged_delay(&self.progress);
        MigrationReadDelay {
            progress: &self.progress,
            handle: match handle {
                crate::thr_progress::DelayHandle::Managed => None,
                unmanaged => Some(unmanaged),
            },
        }
    }

    /// Copy one path's flags while the calling managed thread holds the old block live.
    #[inline]
    pub(crate) fn flags(&self, ix: usize) -> u32 {
        match self.read(MigrationReadRequest::Flags(ix)) {
            Some(MigrationReadResult::Flags(flags)) => flags,
            _ => 0,
        }
    }

    /// Copy the flags and one priority path from the same published generation.
    #[inline]
    pub(crate) fn path(
        &self,
        ix: usize,
        prio: usize,
    ) -> Option<(u32, crate::balance::MigrationPrio)> {
        match self.read(MigrationReadRequest::Path(ix, prio)) {
            Some(MigrationReadResult::Path(flags, migration)) => Some((flags, migration)),
            _ => None,
        }
    }

    #[inline]
    fn read(&self, request: MigrationReadRequest) -> Option<MigrationReadResult> {
        let ix = match request {
            MigrationReadRequest::Flags(ix) | MigrationReadRequest::Path(ix, _) => Some(ix),
            MigrationReadRequest::Snapshot => None,
        };
        if let Some(ix) = ix {
            assert!(ix < self.len);
        }
        if let MigrationReadRequest::Path(_, prio) = request {
            assert!(prio < crate::balance::PRIO_LEVELS);
        }
        let _delay = if matches!(request, MigrationReadRequest::Snapshot) {
            Some(self.delay_read())
        } else {
            None
        };
        if !matches!(request, MigrationReadRequest::Snapshot)
            && !crate::thr_progress::is_managed_thread_of(&self.progress)
        {
            return None;
        }
        let ptr = self.current.load(std::sync::atomic::Ordering::Acquire);
        // SAFETY: publishers retire replaced blocks only after managed scheduler threads pass
        // thread progress, and this method copies its values before returning to the caller.
        unsafe {
            match request {
                MigrationReadRequest::Flags(ix) => {
                    Some(MigrationReadResult::Flags((*ptr.add(ix)).flags))
                }
                MigrationReadRequest::Path(ix, prio) => {
                    let path = &*ptr.add(ix);
                    Some(MigrationReadResult::Path(path.flags, path.prio[prio]))
                }
                MigrationReadRequest::Snapshot => Some(MigrationReadResult::Snapshot(
                    std::slice::from_raw_parts(ptr, self.len).to_vec(),
                )),
            }
        }
    }

    /// Copy a block for the serialized balance updater, which excludes other publishers.
    pub(crate) fn snapshot(&self) -> Vec<crate::balance::MigrationPath> {
        match self.read(MigrationReadRequest::Snapshot) {
            Some(MigrationReadResult::Snapshot(paths)) => paths,
            _ => unreachable!("a path snapshot is always available"),
        }
    }

    /// Replace the current block and return ownership of the old one to the caller.
    pub(crate) fn swap(&self, paths: Vec<crate::balance::MigrationPath>) -> RetiredMigrationPaths {
        assert_eq!(paths.len(), self.len);
        let old = self.current.swap(
            allocate_migration_paths(paths),
            std::sync::atomic::Ordering::AcqRel,
        );
        RetiredMigrationPaths {
            ptr: old as usize,
            len: self.len,
        }
    }

    /// Remove the current block when scheduler threads and all readers have stopped.
    pub(crate) fn take(&self) -> RetiredMigrationPaths {
        let old = self
            .current
            .swap(std::ptr::null_mut(), std::sync::atomic::Ordering::AcqRel);
        RetiredMigrationPaths {
            ptr: old as usize,
            len: self.len,
        }
    }
}

fn allocate_migration_paths(
    paths: Vec<crate::balance::MigrationPath>,
) -> *mut crate::balance::MigrationPath {
    Box::into_raw(paths.into_boxed_slice()).cast()
}

/// Tag bit of a node address that names a [`Proxy`].
const PROXY: usize = 1;

/// The `next`/`prev` links and queue state in a process (or proxy). Relaxed atomics: all
/// accesses are under the run queue lock, which orders them.
#[derive(Default)]
pub(crate) struct RqLink {
    next: AtomicUsize,
    prev: AtomicUsize,
    /// `Process.schedule_count`.
    schedule_count: AtomicU8,
    /// `ERTS_PSFLGS_GET_PRQ_PRIO` of the entry: the priority its run queue length counts.
    prio: AtomicU8,
}

/// `ERTS_PSFLG_PROXY` entry: a second queue entry of a process.
struct Proxy<T: Task> {
    link: RqLink,
    process: ProcRef<T>,
}

/// The lists of one run queue.
pub(crate) struct Lists<T: Task> {
    first: [usize; PROC_QUEUES],
    last: [usize; PROC_QUEUES],
    _marker: std::marker::PhantomData<ProcRef<T>>,
}

// SAFETY: the lists own counted references to `Process<T>`, which is `Send + Sync` (the bound
// `ProcRef<T>: Send` of proc_ref.rs); the raw addresses are never shared outside the lock.
unsafe impl<T: Task> Send for Lists<T> where ProcRef<T>: Send {}

/// Run `f` on the link and process of `node`.
///
/// # Safety
///
/// `node` is linked in a list the caller holds the lock of (so it owns a reference to its
/// process and, if tagged, its `Proxy` box is alive).
unsafe fn with_node<T: Task, R>(node: usize, f: impl FnOnce(&RqLink, &ProcRef<T>) -> R) -> R {
    if node & PROXY == 0 {
        // SAFETY: per the contract the list holds the reference `node` was made from.
        unsafe { ProcRef::<T>::with_borrowed(node as *mut (), |p| f(&p.rq_link, p)) }
    } else {
        // SAFETY: per the contract the box made by `push_back` is alive.
        let proxy = unsafe { &*((node & !PROXY) as *const Proxy<T>) };
        f(&proxy.link, &proxy.process)
    }
}

impl<T: Task> Lists<T> {
    pub(crate) fn new() -> Self {
        Self {
            first: [0; PROC_QUEUES],
            last: [0; PROC_QUEUES],
            _marker: std::marker::PhantomData,
        }
    }

    pub(crate) fn is_empty(&self, queue: usize) -> bool {
        self.first[queue] == 0
    }

    /// Link `item` at the tail of `queue` (`enqueue_process_internal`); a `proxy` entry is a
    /// second node for a process that is already linked.
    pub(crate) fn push_back(&mut self, queue: usize, item: Scheduled<T>, proxy: bool) {
        let Scheduled {
            process,
            schedule_count,
            prio,
            kind: _,
            queue: _,
        } = item;
        // Whether this entry is the process struct or a proxy was decided by the state word CAS
        // (`check_enqueue_in_prio_queue` set `IN_RUNQ` for exactly one real entry).
        let node = if proxy {
            let boxed = Box::new(Proxy {
                link: RqLink::default(),
                process,
            });
            Box::into_raw(boxed) as usize | PROXY
        } else {
            process.into_raw() as usize
        };
        let prev = self.last[queue];
        // SAFETY: `node` was just made from a reference given to the list, `prev` is the list's
        // last node, and the caller holds the lock.
        unsafe {
            with_node::<T, _>(node, |link, _| {
                link.next.store(0, Ordering::Relaxed);
                link.prev.store(prev, Ordering::Relaxed);
                link.schedule_count.store(schedule_count, Ordering::Relaxed);
                link.prio.store(prio, Ordering::Relaxed);
            });
            if prev == 0 {
                self.first[queue] = node;
            } else {
                with_node::<T, _>(prev, |link, _| link.next.store(node, Ordering::Relaxed));
            }
        }
        self.last[queue] = node;
    }

    /// Unlink `node` (whose predecessor is `prev`, 0 for the head) from `queue` and hand its
    /// reference back (`unqueue_process`).
    fn unlink(&mut self, queue: usize, node: usize, prev: usize) -> Scheduled<T> {
        // SAFETY: `node` is in `queue` and `prev` precedes it; the caller holds the lock.
        let (next, schedule_count, prio) = unsafe {
            with_node::<T, _>(node, |link, _| {
                (
                    link.next.load(Ordering::Relaxed),
                    link.schedule_count.load(Ordering::Relaxed),
                    link.prio.load(Ordering::Relaxed),
                )
            })
        };
        // SAFETY: as above for `prev` and `next`.
        unsafe {
            if prev == 0 {
                self.first[queue] = next;
            } else {
                with_node::<T, _>(prev, |link, _| link.next.store(next, Ordering::Relaxed));
            }
            if next == 0 {
                self.last[queue] = prev;
            } else {
                with_node::<T, _>(next, |link, _| link.prev.store(prev, Ordering::Relaxed));
            }
        }
        let proxy = node & PROXY != 0;
        let process = if node & PROXY == 0 {
            // SAFETY: the list held the reference `into_raw` gave up in `push_back`; the node
            // is unlinked, so this is its only owner.
            unsafe { ProcRef::<T>::from_raw(node as *mut ()) }
        } else {
            // SAFETY: the box made in `push_back`, unlinked now.
            let proxy = unsafe { Box::from_raw((node & !PROXY) as *mut Proxy<T>) };
            proxy.process.clone()
        };
        Scheduled {
            process,
            schedule_count,
            prio,
            kind: if proxy { Enqueue::Proxy } else { Enqueue::Real },
            queue,
        }
    }

    /// Unlink the head of `queue` (`dequeue_process`).
    pub(crate) fn pop_front(&mut self, queue: usize) -> Option<Scheduled<T>> {
        let node = self.first[queue];
        (node != 0).then(|| self.unlink(queue, node, 0))
    }

    /// `check_requeue_process`: count a head visit of the first entry; move it to the tail while
    /// it still has to wait and is not alone. Returns whether it moved.
    pub(crate) fn requeue_head(&mut self, queue: usize) -> bool {
        let node = self.first[queue];
        if node == 0 {
            return false;
        }
        // SAFETY: `node` is the head; the caller holds the lock.
        let (count, next) = unsafe {
            with_node::<T, _>(node, |link, _| {
                let count = link
                    .schedule_count
                    .load(Ordering::Relaxed)
                    .saturating_sub(1);
                link.schedule_count.store(count, Ordering::Relaxed);
                (count, link.next.load(Ordering::Relaxed))
            })
        };
        if count == 0 || next == 0 {
            return false;
        }
        let last = self.last[queue];
        // SAFETY: `node`, `next`, `last` are nodes of this list; the caller holds the lock.
        unsafe {
            with_node::<T, _>(next, |link, _| link.prev.store(0, Ordering::Relaxed));
            with_node::<T, _>(last, |link, _| link.next.store(node, Ordering::Relaxed));
            with_node::<T, _>(node, |link, _| {
                link.next.store(0, Ordering::Relaxed);
                link.prev.store(last, Ordering::Relaxed);
            });
        }
        self.first[queue] = next;
        self.last[queue] = node;
        true
    }

    /// Unlink up to `max` entries, front to back, whose process `accept`s.
    pub(crate) fn take(
        &mut self,
        queue: usize,
        max: usize,
        mut accept: impl FnMut(&ProcRef<T>) -> bool,
    ) -> Vec<Scheduled<T>> {
        let mut taken = Vec::new();
        let mut prev = 0;
        let mut node = self.first[queue];
        while node != 0 && taken.len() < max {
            // SAFETY: `node` is in `queue`; the caller holds the lock.
            let (next, ok) = unsafe {
                with_node::<T, _>(node, |link, process| {
                    (link.next.load(Ordering::Relaxed), accept(process))
                })
            };
            if ok {
                taken.push(self.unlink(queue, node, prev));
            } else {
                prev = node;
            }
            node = next;
        }
        taken
    }

    /// Unlink every entry of every queue.
    pub(crate) fn drain(&mut self) -> Vec<Scheduled<T>> {
        let mut all = Vec::new();
        for queue in 0..PROC_QUEUES {
            while let Some(item) = self.pop_front(queue) {
                all.push(item);
            }
        }
        all
    }
}

impl<T: Task> Drop for Lists<T> {
    fn drop(&mut self) {
        drop(self.drain());
    }
}

/// `rq->mtx`: an `erts_mtx_t` (`ethr_mutex`). On macOS erts builds it on `pthread_mutex_t`
/// initialised with default attributes, so the lock is the libc mutex; elsewhere the port of the
/// futex spin implementation is still to do, and a `parking_lot` lock stands in.
///
/// Port of erts/lib_src/common/ethr_mutex.c (`ethr_mutex_init`: `pthread_mutex_init(.., NULL)`;
/// `ethr_mutex_lock`/`trylock`/`unlock` are the pthread calls), OTP-29.1.1.
pub(crate) struct RqMutex<T> {
    /// Boxed so the mutex does not move after first use.
    #[cfg(target_os = "macos")]
    raw: Box<std::cell::UnsafeCell<libc::pthread_mutex_t>>,
    #[cfg(not(target_os = "macos"))]
    raw: parking_lot::Mutex<()>,
    data: std::cell::UnsafeCell<T>,
}

// SAFETY: access to `data` is only through a guard, which holds the lock.
unsafe impl<T: Send> Send for RqMutex<T> {}
// SAFETY: as above.
unsafe impl<T: Send> Sync for RqMutex<T> {}

/// The lock held; dropping it is `erts_mtx_unlock`.
pub(crate) struct RqGuard<'a, T> {
    mutex: &'a RqMutex<T>,
}

impl<T> RqMutex<T> {
    pub(crate) fn new(data: T) -> Self {
        #[cfg(target_os = "macos")]
        let raw = {
            let raw = Box::new(std::cell::UnsafeCell::new(libc::PTHREAD_MUTEX_INITIALIZER));
            // SAFETY: the box holds a mutex nothing uses yet; NULL attributes are the defaults
            // `ethr_mutex_init` passes.
            let rc = unsafe { libc::pthread_mutex_init(raw.get(), std::ptr::null()) };
            assert_eq!(rc, 0, "pthread_mutex_init");
            raw
        };
        #[cfg(not(target_os = "macos"))]
        let raw = parking_lot::Mutex::new(());
        Self {
            raw,
            data: std::cell::UnsafeCell::new(data),
        }
    }

    /// `erts_mtx_lock`.
    #[inline]
    pub(crate) fn lock(&self) -> RqGuard<'_, T> {
        #[cfg(target_os = "macos")]
        {
            // SAFETY: `raw` was initialised in `new` and lives as long as `self`.
            let rc = unsafe { libc::pthread_mutex_lock(self.raw.get()) };
            debug_assert_eq!(rc, 0);
        }
        #[cfg(not(target_os = "macos"))]
        std::mem::forget(self.raw.lock());
        RqGuard { mutex: self }
    }

    /// `erts_mtx_trylock`: `None` is EBUSY.
    #[inline]
    pub(crate) fn try_lock(&self) -> Option<RqGuard<'_, T>> {
        #[cfg(target_os = "macos")]
        {
            // SAFETY: as in `lock`.
            if unsafe { libc::pthread_mutex_trylock(self.raw.get()) } != 0 {
                return None;
            }
        }
        #[cfg(not(target_os = "macos"))]
        std::mem::forget(self.raw.try_lock()?);
        Some(RqGuard { mutex: self })
    }
}

#[cfg(target_os = "macos")]
impl<T> Drop for RqMutex<T> {
    fn drop(&mut self) {
        // SAFETY: no guard exists (they borrow the mutex) and it was initialised in `new`.
        unsafe { libc::pthread_mutex_destroy(self.raw.get()) };
    }
}

impl<T> std::ops::Deref for RqGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: the guard holds the lock.
        unsafe { &*self.mutex.data.get() }
    }
}

impl<T> std::ops::DerefMut for RqGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: the guard holds the lock, exclusively.
        unsafe { &mut *self.mutex.data.get() }
    }
}

impl<T> Drop for RqGuard<'_, T> {
    #[inline]
    fn drop(&mut self) {
        #[cfg(target_os = "macos")]
        // SAFETY: this guard owns the lock it releases.
        unsafe {
            libc::pthread_mutex_unlock(self.mutex.raw.get());
        }
        #[cfg(not(target_os = "macos"))]
        // SAFETY: this guard owns the lock whose guard `lock` forgot.
        unsafe {
            self.mutex.raw.force_unlock();
        }
    }
}
