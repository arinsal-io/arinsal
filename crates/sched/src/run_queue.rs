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

use std::sync::Arc;
use std::sync::atomic::Ordering;

use crate::{RunPort, Scheduled, Task, first_process_queue};
pub(crate) use raw::RqLink;

/// Four callbacks are detached by one exec_misc_ops pass (ERTS_MAX_MISC_OPS - 1).
// Port of erts/emulator/beam/erl_process.h:375, OTP-29.1.1.
pub(crate) const MISC_OPS_PER_PASS: usize = 4;

/// Process queues of a scheduler's run queue.
pub(crate) struct ProcQueues<T: Task> {
    /// `rq->mtx` as far as the process lists are concerned.
    lists: raw::RqMutex<raw::Lists<T>>,
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
    /// `no_empty_run_queues`: the global count of a normal run queue, `None` for a dirty one.
    pub(crate) fn new(
        no_empty_run_queues: Option<std::sync::Arc<crate::balance::NoEmptyRunQueues>>,
    ) -> Self {
        Self {
            lists: raw::RqMutex::new(raw::Lists::new()),
            info: crate::balance::RunQueueBalance::new(no_empty_run_queues),
        }
    }

    /// Non-empty priority queues (`flags & ERTS_RUNQ_FLGS_PROCS_QMASK`).
    #[inline]
    pub(crate) fn qmask(&self) -> u32 {
        let priorities = self.info.process_qmask();
        (priorities & 0b11) | (u32::from(priorities & 0b1100 != 0) << 2)
    }

    #[inline]
    pub(crate) fn is_empty(&self) -> bool {
        self.qmask() == 0
    }

    /// Runnable process, port, or misc-op flags in the run queue.
    #[inline]
    pub(crate) fn has_runnable_work(&self) -> bool {
        self.info.has_runnable_work()
    }

    pub(crate) fn misc_ops_pending(&self) -> bool {
        self.info.flags.load(Ordering::Acquire) & crate::balance::FLG_MISC_OP != 0
    }

    pub(crate) fn ports_is_empty(&self) -> bool {
        self.lock().ports_is_empty()
    }

    pub(crate) fn enqueue_port(&self, port: Arc<dyn RunPort>) {
        self.lock().enqueue_port(port);
    }

    pub(crate) fn pop_port(&self) -> Option<Arc<dyn RunPort>> {
        self.lock().pop_port()
    }

    pub(crate) fn schedule_misc_op(&self, op: Box<raw::MiscOp>) {
        self.lock().schedule_misc_op(op);
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

    /// Lock, enqueue, unlock (`add2runq`). An entry of kind `Not` is not queued.
    #[inline]
    pub(crate) fn push(&self, item: Scheduled<T>) {
        if item.kind != crate::Enqueue::Not {
            self.lock().push(item);
        }
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
    /// Append to the tail of the entry's priority queue (`enqueue_process`); a `Proxy` entry
    /// is the second entry of an already queued process (`ERTS_PSFLG_PROXY`).
    #[inline]
    pub(crate) fn push(&mut self, item: Scheduled<T>) {
        // `ERTS_ENQUEUE_NOT`: the process already has an entry at this priority or higher.
        if item.kind == crate::Enqueue::Not {
            return;
        }
        let queue = item.queue();
        let proxy = item.kind == crate::Enqueue::Proxy;
        // Port of erts/emulator/beam/erl_process.c:3959 (enqueue_process:
        // erts_inc_runq_len), OTP-29.1.1: every entry, a proxy too, counts at its priority.
        let prio = item.prio;
        self.owner.info.add_len(usize::from(prio), 1);
        self.lists.push_back(queue, item, proxy);
        self.owner.info.set_rq_flag(1 << u32::from(prio));
    }

    /// `unqueue_process`: the entry leaves the lengths at the priority it was counted at
    /// (erl_process.c:3990 erts_dec_runq_len with `ERTS_PSFLGS_GET_PRQ_PRIO`).
    #[inline]
    fn uncount(&self, item: &Scheduled<T>) {
        let prio = usize::from(item.prio);
        self.owner.info.sub_len(prio, 1);
        if self.owner.info.len(prio) == 0 {
            self.owner.info.clear_rq_flag(1 << prio);
        }
    }

    /// The next entry of `pick_next_process` in `erts_schedule`: the first entry of the highest
    /// non-empty queue, a low priority entry requeued until it has been at the head
    /// `RESCHEDULE_LOW` times (`check_requeue_process`).
    pub(crate) fn pop_next(&mut self) -> Option<Scheduled<T>> {
        loop {
            let (priority, _) = first_process_queue(self.owner.qmask())?;
            if self.lists.requeue_head(priority) {
                continue;
            }
            let item = self.lists.pop_front(priority);
            if let Some(item) = item {
                self.uncount(&item);
                return Some(item);
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
        for item in &taken {
            self.uncount(item);
        }
        taken
    }

    /// Unqueue every entry (`evacuate_run_queue`).
    pub(crate) fn drain(&mut self) -> Vec<Scheduled<T>> {
        let all = self.lists.drain();
        for item in &all {
            self.uncount(item);
        }
        all
    }

    pub(crate) fn take_chain(
        &mut self,
        queue: usize,
        max: usize,
        accept: impl FnMut(&crate::proc_ref::ProcRef<T>) -> bool,
    ) -> raw::ProcessChain<T> {
        let chain = self.lists.take_chain(queue, max, accept);
        for (prio, count) in chain.counts().iter().copied().enumerate() {
            if count != 0 {
                self.owner.info.sub_len(prio, count as i32);
                if self.owner.info.len(prio) == 0 {
                    self.owner.info.clear_rq_flag(1 << prio);
                }
            }
        }
        chain
    }

    /// Append a stolen intrusive chain with one `rq->mtx` acquisition.
    pub(crate) fn append_chain(&mut self, mut chain: raw::ProcessChain<T>) {
        for (prio, count) in chain.counts().iter().copied().enumerate() {
            if count != 0 {
                self.owner.info.add_len(prio, count as i32);
                self.owner.info.set_rq_flag(1 << prio);
            }
        }
        self.lists.append_chain(&mut chain);
    }

    pub(crate) fn ports_is_empty(&self) -> bool {
        self.lists.ports_is_empty()
    }

    pub(crate) fn enqueue_port(&mut self, port: Arc<dyn RunPort>) {
        self.lists.enqueue_port(port);
        self.owner.info.add_len(crate::balance::PORT_PRIO_LEVEL, 1);
        self.owner.info.set_rq_flag(crate::balance::PORT_BIT);
    }

    pub(crate) fn pop_port(&mut self) -> Option<Arc<dyn RunPort>> {
        let port = self.lists.pop_port()?;
        self.owner.info.sub_len(crate::balance::PORT_PRIO_LEVEL, 1);
        if self.lists.ports_is_empty() {
            self.owner.info.clear_rq_flag(crate::balance::PORT_BIT);
        }
        Some(port)
    }

    pub(crate) fn schedule_misc_op(&mut self, op: Box<raw::MiscOp>) {
        self.lists.enqueue_misc_op(op);
        self.owner.info.set_rq_flag(crate::balance::FLG_MISC_OP);
        self.owner.info.non_empty_runq();
    }

    pub(crate) fn detach_misc_ops(&mut self, max: usize) -> Option<Box<raw::MiscOp>> {
        let ops = self.lists.detach_misc_ops(max);
        if self.lists.misc_ops_is_empty() {
            self.owner.info.clear_rq_flag(crate::balance::FLG_MISC_OP);
        }
        ops
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
