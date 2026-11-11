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

use std::alloc::{Layout, alloc, dealloc};
use std::cell::UnsafeCell;
use std::sync::atomic::{AtomicPtr, AtomicU8, AtomicUsize, Ordering};

use crate::proc_ref::ProcRef;
use crate::{Enqueue, PROC_QUEUES, Scheduled, Task};

/// The published contiguous migration path block (`erts_migration_paths`).
// Port of erts/emulator/beam/erl_process.c (ErtsMigrationPaths), OTP-29.1.1.
pub(crate) struct MigrationPaths {
    current: AtomicPtr<MigrationPathBlock>,
    len: usize,
    progress: std::sync::Arc<crate::thr_progress::ThrProgress>,
    pool: UnsafeCell<MigrationPathPool>,
    pool_base: *mut u8,
    stride: usize,
}

// The block header is the intrusive free/retired list node and carries the retirement point,
// as `ErtsMigrationPaths.next` and `ErtsMigrationPaths.thr_prgr` do in erl_process.c.
#[repr(C)]
struct MigrationPathBlock {
    next: *mut MigrationPathBlock,
    retired_at: u64,
    backing: *mut u8,
}

struct MigrationPathPool {
    free: *mut MigrationPathBlock,
    retired_first: *mut MigrationPathBlock,
    retired_last: *mut MigrationPathBlock,
}

// SAFETY: callers mutate the pool only while holding Balance.state; readers only access
// `current` under scheduler thread progress, and the active pointer is atomic.
unsafe impl Send for MigrationPathBlock {}
// SAFETY: pool links are only accessed while Balance.state is held.
unsafe impl Send for MigrationPathPool {}
// SAFETY: MigrationPaths moves with its scheduler-owned Balance and never exposes pool pointers.
unsafe impl Send for MigrationPaths {}
// SAFETY: published blocks are immutable; pool links are serialized by Balance.state.
unsafe impl Sync for MigrationPaths {}

#[cfg(test)]
struct MigrationReadDelay<'a> {
    progress: &'a crate::thr_progress::ThrProgress,
    handle: Option<crate::thr_progress::DelayHandle>,
}

#[cfg(test)]
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
        let stride = align_up(
            block_paths_offset() + len * std::mem::size_of::<crate::balance::MigrationPath>(),
            64,
        );
        let layout = Layout::from_size_align(stride * 8, 64).unwrap();
        // SAFETY: the layout is non-zero and valid; allocation is initialized below.
        let pool_base = unsafe { alloc(layout) };
        assert!(
            !pool_base.is_null(),
            "migration path pool allocation failed"
        );
        let mut free = std::ptr::null_mut();
        let none = crate::balance::MigrationPath::NONE;
        for index in 0..8 {
            // SAFETY: each stride-sized slot belongs to the allocation and is 64-byte aligned.
            let block = unsafe { pool_base.add(index * stride).cast::<MigrationPathBlock>() };
            // SAFETY: the block header and path region are within this initialized pool slot.
            unsafe {
                block.write(MigrationPathBlock {
                    next: free,
                    retired_at: 0,
                    backing: std::ptr::null_mut(),
                });
                std::ptr::write_bytes(
                    block.cast::<u8>().add(block_paths_offset()),
                    0,
                    len * std::mem::size_of::<crate::balance::MigrationPath>(),
                );
                for path in 0..len {
                    block_paths(block).add(path).write(none);
                }
            }
            free = block;
        }
        let current = free;
        // SAFETY: current is the last initialized pool block; remove it from the free list.
        unsafe {
            free = (*current).next;
            (*current).next = std::ptr::null_mut();
        }
        Self {
            current: AtomicPtr::new(current),
            len,
            progress,
            pool: UnsafeCell::new(MigrationPathPool {
                free,
                retired_first: std::ptr::null_mut(),
                retired_last: std::ptr::null_mut(),
            }),
            pool_base,
            stride,
        }
    }

    #[cfg(test)]
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

    /// Read one published path while the calling managed thread holds the block live.
    #[inline]
    pub(crate) fn flags(&self, ix: usize) -> u32 {
        self.with_path(ix, |path| path.flags).unwrap_or(0)
    }

    #[inline]
    pub(crate) fn with_path<R>(
        &self,
        ix: usize,
        f: impl FnOnce(&crate::balance::MigrationPath) -> R,
    ) -> Option<R> {
        assert!(ix < self.len);
        if !crate::thr_progress::is_managed_thread_of(&self.progress) {
            return None;
        }
        let block = self.current.load(Ordering::Acquire);
        // SAFETY: a managed scheduler cannot pass thread progress during this scoped read.
        Some(unsafe { f(&*block_paths(block).add(ix)) })
    }

    /// Copy a block for the serialized balance updater, which excludes other publishers.
    #[cfg(test)]
    pub(crate) fn snapshot(&self) -> Vec<crate::balance::MigrationPath> {
        let _delay = self.delay_read();
        let block = self.current.load(Ordering::Acquire);
        // SAFETY: unmanaged delay prevents retirement while the snapshot is copied.
        unsafe { std::slice::from_raw_parts(block_paths(block), self.len).to_vec() }
    }

    /// Fill and publish a replacement while the previous block remains readable.
    pub(crate) fn publish_with(
        &self,
        fill: impl FnOnce(&mut [crate::balance::MigrationPath], &[crate::balance::MigrationPath]),
    ) {
        // SAFETY: every caller is a balance publisher holding Balance.state, the lock that
        // serializes OTP's alloc_mpaths and retire_mpaths operations.
        let pool = unsafe { &mut *self.pool.get() };
        self.sweep(pool);
        let new = if pool.free.is_null() {
            self.allocate_dynamic()
        } else {
            let block = pool.free;
            // SAFETY: free list is exclusively held by Balance.state.
            unsafe {
                pool.free = (*block).next;
                (*block).next = std::ptr::null_mut();
            }
            block
        };
        let old = self.current.load(Ordering::Acquire);
        // SAFETY: new is exclusively owned by this publisher; old remains current because
        // Balance.state serializes every writer until publication below.
        unsafe {
            fill(
                std::slice::from_raw_parts_mut(block_paths(new), self.len),
                std::slice::from_raw_parts(block_paths(old), self.len),
            );
        }
        let old = self.current.swap(new, Ordering::AcqRel);
        // Port of erl_process.c (retire_mpaths): the old block itself carries its progress value
        // and intrusive next link; no closure or per-publication owner is allocated.
        // SAFETY: old was the published block and Balance.state serializes its retirement.
        unsafe {
            (*old).retired_at = self.progress.later_value();
            (*old).next = std::ptr::null_mut();
        }
        if pool.retired_last.is_null() {
            pool.retired_first = old;
        } else {
            // SAFETY: retired_last is a live retired block protected by Balance.state.
            unsafe {
                (*pool.retired_last).next = old;
            }
        }
        pool.retired_last = old;
    }

    fn sweep(&self, pool: &mut MigrationPathPool) {
        while !pool.retired_first.is_null() {
            let block = pool.retired_first;
            // SAFETY: retired list is exclusively held by Balance.state.
            let (next, epoch, backing) =
                unsafe { ((*block).next, (*block).retired_at, (*block).backing) };
            if !self.progress.reached(epoch) {
                break;
            }
            pool.retired_first = next;
            if backing.is_null() {
                // SAFETY: the preallocated block returns to the intrusive freelist.
                unsafe {
                    (*block).next = pool.free;
                }
                pool.free = block;
            } else {
                // SAFETY: dynamically allocated block was allocated with this layout.
                unsafe {
                    dealloc(backing, self.block_layout());
                }
            }
        }
        if pool.retired_first.is_null() {
            pool.retired_last = std::ptr::null_mut();
        }
    }

    fn block_layout(&self) -> Layout {
        Layout::from_size_align(self.stride, 64).unwrap()
    }

    fn allocate_dynamic(&self) -> *mut MigrationPathBlock {
        // SAFETY: layout is valid; allocation is initialized before publication.
        let backing = unsafe { alloc(self.block_layout()) };
        assert!(!backing.is_null(), "migration path block allocation failed");
        let block = backing.cast::<MigrationPathBlock>();
        // SAFETY: backing is one aligned block allocation with enough trailing path space.
        unsafe {
            block.write(MigrationPathBlock {
                next: std::ptr::null_mut(),
                retired_at: 0,
                backing,
            });
            for path in 0..self.len {
                block_paths(block)
                    .add(path)
                    .write(crate::balance::MigrationPath::NONE);
            }
        }
        block
    }
}

fn align_up(value: usize, align: usize) -> usize {
    (value + align - 1) & !(align - 1)
}
fn block_paths_offset() -> usize {
    align_up(
        std::mem::size_of::<MigrationPathBlock>(),
        std::mem::align_of::<crate::balance::MigrationPath>(),
    )
}
unsafe fn block_paths(block: *mut MigrationPathBlock) -> *mut crate::balance::MigrationPath {
    // SAFETY: callers ensure `block` is a live block with trailing path storage.
    unsafe { block.cast::<u8>().add(block_paths_offset()).cast() }
}

impl Drop for MigrationPaths {
    fn drop(&mut self) {
        let current = self.current.load(Ordering::Relaxed);
        let dynamic_layout = Layout::from_size_align(self.stride, 64).unwrap();
        let pool_layout = Layout::from_size_align(self.stride * 8, 64).unwrap();
        let pool = self.pool.get_mut();
        // SAFETY: Drop runs after scheduler threads stop; all dynamic blocks are on current or
        // one of the intrusive lists, and the fixed pool is released as one allocation.
        unsafe {
            let mut block = pool.free;
            while !block.is_null() {
                let next = (*block).next;
                if !(*block).backing.is_null() {
                    dealloc((*block).backing, dynamic_layout);
                }
                block = next;
            }
            block = pool.retired_first;
            while !block.is_null() {
                let next = (*block).next;
                if !(*block).backing.is_null() {
                    dealloc((*block).backing, dynamic_layout);
                }
                block = next;
            }
            if !current.is_null() && !(*current).backing.is_null() {
                dealloc((*current).backing, dynamic_layout);
            }
            dealloc(self.pool_base, pool_layout);
        }
    }
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
