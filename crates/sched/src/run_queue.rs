//! The process part of an `ErtsRunQueue`: one lock, one FIFO list per priority queue, and the
//! non-empty mask of `rq->flags`.
//!
//! Port of erts/emulator/beam/erl_process.h (`ErtsRunQueue.procs`, `ErtsRunPrioQueue`,
//! `ERTS_RUNQ_FLGS_PROCS_QMASK`) and erts/emulator/beam/erl_process.c (`enqueue_process`,
//! `dequeue_process`, `check_requeue_process`, `unqueue_process`), OTP-29.1.1.
//!
//! The lists are intrusive like erts' (links in the process, see `raw`); a second entry of an
//! already queued process (`active_sys_enqueue`) is a proxy node.

pub(crate) mod raw;

use std::sync::atomic::{AtomicU32, Ordering};

use crate::{Scheduled, Task, first_process_queue};
pub(crate) use raw::RqLink;

/// Process queues of a scheduler's run queue.
pub(crate) struct ProcQueues<T: Task> {
    /// `rq->mtx` as far as the process lists are concerned.
    lists: raw::RqMutex<raw::Lists<T>>,
    /// One bit per non-empty priority queue, changed under `lists` and readable without the
    /// lock like `rq->flags`.
    qmask: AtomicU32,
    /// `rq->len`, `rq->max_len`, `rq->flags` (migration info), `rq->check_balance_reds` and
    /// `rq->waiting`: the rest of `ErtsRunQueue`, reached through `Deref`.
    pub(crate) info: crate::balance::RunQueueBalance,
}

impl<T: Task> std::ops::Deref for ProcQueues<T> {
    type Target = crate::balance::RunQueueBalance;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.info
    }
}

impl<T: Task> ProcQueues<T> {
    pub(crate) fn new() -> Self {
        Self {
            lists: raw::RqMutex::new(raw::Lists::new()),
            qmask: AtomicU32::new(0),
            info: crate::balance::RunQueueBalance::new(),
        }
    }

    /// Non-empty priority queues (`flags & ERTS_RUNQ_FLGS_PROCS_QMASK`).
    #[inline]
    pub(crate) fn qmask(&self) -> u32 {
        self.qmask.load(Ordering::Acquire)
    }

    #[inline]
    pub(crate) fn is_empty(&self) -> bool {
        self.qmask() == 0
    }

    /// Highest priority queue with an entry.
    pub(crate) fn best_priority(&self) -> Option<usize> {
        first_process_queue(self.qmask()).map(|(priority, _)| priority)
    }

    /// `erts_runq_lock`.
    #[inline]
    pub(crate) fn lock(&self) -> LockedRunQueue<'_, T> {
        LockedRunQueue {
            owner: self,
            lists: self.lists.lock(),
        }
    }

    /// `erts_mtx_trylock` on `rq->mtx`: `None` is EBUSY.
    #[inline]
    pub(crate) fn try_lock(&self) -> Option<LockedRunQueue<'_, T>> {
        self.lists
            .try_lock()
            .map(|lists| LockedRunQueue { owner: self, lists })
    }

    /// Lock, enqueue, unlock (`add2runq`).
    #[inline]
    pub(crate) fn push(&self, item: Scheduled<T>) {
        self.lock().push(item);
    }

    /// Lock, enqueue a proxy entry, unlock (`add2runq` with `enqueue < 0`).
    pub(crate) fn push_proxy(&self, item: Scheduled<T>) {
        self.lock().push_proxy(item);
    }

    /// Lock, take the next entry, unlock.
    pub(crate) fn pop_next(&self) -> Option<Scheduled<T>> {
        self.lock().pop_next()
    }

    /// Lock, unqueue up to `max` accepted entries, unlock.
    pub(crate) fn take(
        &self,
        queue: usize,
        max: usize,
        accept: impl FnMut(&crate::proc_ref::ProcRef<T>) -> bool,
    ) -> Vec<Scheduled<T>> {
        self.lock().take(queue, max, accept)
    }

    /// Lock, unqueue every entry, unlock.
    pub(crate) fn drain(&self) -> Vec<Scheduled<T>> {
        self.lock().drain()
    }
}

/// A run queue whose lock the caller holds: what an erts function that takes `ErtsRunQueue *rq`
/// documented as locked works on. Dropping it is `erts_runq_unlock`.
pub(crate) struct LockedRunQueue<'a, T: Task> {
    owner: &'a ProcQueues<T>,
    lists: raw::RqGuard<'a, raw::Lists<T>>,
}

impl<T: Task> LockedRunQueue<'_, T> {
    /// Append to the tail of the entry's priority queue (`enqueue_process`).
    #[inline]
    pub(crate) fn push(&mut self, item: Scheduled<T>) {
        let queue = item.queue();
        self.lists.push_back(queue, item, false);
        self.owner.qmask.fetch_or(1 << queue, Ordering::Release);
    }

    /// Append stolen entries in order under one lock (`try_steal_task_from_victim` links the
    /// whole stolen chain onto the thief's queue after taking `rq->mtx` once).
    pub(crate) fn push_all(&mut self, items: Vec<Scheduled<T>>) {
        for item in items {
            self.push(item);
        }
    }

    /// Append a second entry of a process that is already queued (`ERTS_PSFLG_PROXY`,
    /// `active_sys_enqueue`).
    pub(crate) fn push_proxy(&mut self, item: Scheduled<T>) {
        let queue = item.queue();
        self.lists.push_back(queue, item, true);
        self.owner.qmask.fetch_or(1 << queue, Ordering::Release);
    }

    /// The next entry of `pick_next_process` in `erts_schedule`: the first entry of the highest
    /// non-empty queue, a low priority entry requeued until it has been at the head
    /// `RESCHEDULE_LOW` times (`check_requeue_process`).
    pub(crate) fn pop_next(&mut self) -> Option<Scheduled<T>> {
        let qmask = &self.owner.qmask;
        loop {
            let (priority, bit) = first_process_queue(qmask.load(Ordering::Relaxed))?;
            if self.lists.requeue_head(priority) {
                continue;
            }
            let item = self.lists.pop_front(priority);
            if self.lists.is_empty(priority) {
                qmask.fetch_and(!bit, Ordering::Release);
            }
            if item.is_some() {
                return item;
            }
        }
    }

    /// Unqueue up to `max` entries from the head of priority queue `queue` that `accept`,
    /// leaving the others in place (`try_steal_task_from_victim` and `immigrate` skip a
    /// process `erts_try_change_runq_proc` refuses, i.e. one bound to another run queue).
    pub(crate) fn take(
        &mut self,
        queue: usize,
        max: usize,
        accept: impl FnMut(&crate::proc_ref::ProcRef<T>) -> bool,
    ) -> Vec<Scheduled<T>> {
        let taken = self.lists.take(queue, max, accept);
        if self.lists.is_empty(queue) {
            self.owner.qmask.fetch_and(!(1 << queue), Ordering::Release);
        }
        taken
    }

    /// Unqueue every entry (`evacuate_run_queue`).
    pub(crate) fn drain(&mut self) -> Vec<Scheduled<T>> {
        let all = self.lists.drain();
        self.owner.qmask.store(0, Ordering::Release);
        all
    }
}

/// A scheduler's hold on its own run queue across `erts_schedule`: the lock is taken after the
/// previous process is scheduled out and given up wherever erts calls `erts_runq_unlock`.
pub(crate) struct RqHold<'a, T: Task> {
    rq: &'a ProcQueues<T>,
    guard: Option<LockedRunQueue<'a, T>>,
}

impl<'a, T: Task> RqHold<'a, T> {
    /// A hold on `rq` that starts unlocked.
    pub(crate) fn new(rq: &'a ProcQueues<T>) -> Self {
        Self { rq, guard: None }
    }

    /// `erts_runq_lock`.
    pub(crate) fn lock(&mut self) {
        if self.guard.is_none() {
            self.guard = Some(self.rq.lock());
        }
    }

    /// `erts_runq_unlock`.
    pub(crate) fn unlock(&mut self) {
        self.guard = None;
    }

    /// The locked run queue; only valid between `lock` and `unlock`.
    pub(crate) fn locked(&mut self) -> &mut LockedRunQueue<'a, T> {
        self.guard.as_mut().expect("run queue is locked")
    }
}

impl<T: Task> crate::thr_progress::RunQueueHold for RqHold<'_, T> {
    fn is_held(&self) -> bool {
        self.guard.is_some()
    }
    fn release(&mut self) {
        self.unlock();
    }
    fn reacquire(&mut self) {
        self.guard = Some(self.rq.lock());
    }
}
