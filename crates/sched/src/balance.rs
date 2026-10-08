//! Run queue load balancing: per run queue length and reduction statistics, migration
//! paths, and the periodic balance check that computes them.
//!
//! Port of erts/emulator/beam/erl_process.c:3800-3870 (balance_info.no_runqs),
//! erl_process.c:4746-5530 (migration paths, check_balance, change_no_used_runqs) and
//! erl_process.h:131-215,789-875 (run queue flags and length bookkeeping), OTP-29.1.1.
//!
//! Ports with scheduled tasks are queued on the run queues at the port priority level
//! (`ERTS_PORT_PRIO_LEVEL`), which has its own statistics and migration path.

use std::sync::atomic::{
    AtomicBool, AtomicI32, AtomicI64, AtomicU32, AtomicU64, AtomicUsize, Ordering,
};
use std::sync::{Arc, Mutex};

// Port of erts/emulator/beam/erl_process.h:128-132, OTP-29.1.1.
/// Process priority levels (`ERTS_NO_PROC_PRIO_LEVELS`).
pub(crate) const PROC_PRIO_LEVELS: usize = 4;
/// The port level (`ERTS_PORT_PRIO_LEVEL`).
pub(crate) const PORT_PRIO_LEVEL: usize = PROC_PRIO_LEVELS;
/// Process levels plus the port level (`ERTS_NO_PRIO_LEVELS`).
pub(crate) const PRIO_LEVELS: usize = PROC_PRIO_LEVELS + 1;
pub(crate) const PRIORITY_NORMAL: usize = 2;
pub(crate) const PRIORITY_LOW: usize = 3;

// Port of erts/emulator/beam/erl_process.c:63-65, OTP-29.1.1.
const CONTEXT_REDS: i64 = 4_000;
pub(crate) const CHECK_BALANCE_REDS_PER_SCHED: i64 = 2000 * CONTEXT_REDS;
pub(crate) const CALL_CHECK_BALANCE_REDS: i64 = CHECK_BALANCE_REDS_PER_SCHED / 2;
// Port of erts/emulator/beam/erl_process.h:373-379, OTP-29.1.1.
pub(crate) const RESCHEDULE_LOW: u8 = 8;
const FULL_REDS_HISTORY_AVG_SHFT: u32 = 3;
const FULL_REDS_HISTORY_SIZE: usize = (1 << FULL_REDS_HISTORY_AVG_SHFT) - 1;

// Port of erts/emulator/beam/erl_process.h:136-187 (run queue flags), OTP-29.1.1.
const QMASK: u32 = (1 << PRIO_LEVELS) - 1;
const EMIGRATE_SHFT: u32 = 0;
const IMMIGRATE_SHFT: u32 = EMIGRATE_SHFT + PRIO_LEVELS as u32;
const EVACUATE_SHFT: u32 = IMMIGRATE_SHFT + PRIO_LEVELS as u32;
const FLG_BASE2: u32 = EVACUATE_SHFT + PRIO_LEVELS as u32;
pub(crate) const EMIGRATE_QMASK: u32 = QMASK << EMIGRATE_SHFT;
pub(crate) const IMMIGRATE_QMASK: u32 = QMASK << IMMIGRATE_SHFT;
pub(crate) const EVACUATE_QMASK: u32 = QMASK << EVACUATE_SHFT;
pub(crate) const FLG_OUT_OF_WORK: u32 = 1 << FLG_BASE2;
pub(crate) const FLG_HALFTIME_OUT_OF_WORK: u32 = 1 << (FLG_BASE2 + 1);
pub(crate) const FLG_INACTIVE: u32 = 1 << (FLG_BASE2 + 4);
const MIGRATION_QMASKS: u32 = EMIGRATE_QMASK | IMMIGRATE_QMASK | EVACUATE_QMASK;
const MIGRATION_INFO: u32 =
    MIGRATION_QMASKS | FLG_INACTIVE | FLG_OUT_OF_WORK | FLG_HALFTIME_OUT_OF_WORK;

pub(crate) const fn flg_emigrate(prio: usize) -> u32 {
    1 << (EMIGRATE_SHFT + prio as u32)
}
pub(crate) const fn flg_immigrate(prio: usize) -> u32 {
    1 << (IMMIGRATE_SHFT + prio as u32)
}
pub(crate) const fn flg_evacuate(prio: usize) -> u32 {
    1 << (EVACUATE_SHFT + prio as u32)
}

/// Balance statistics of one run queue.
///
/// Port of erts/emulator/beam/erl_process.h:440-515 (`ErtsRunQueueInfo` len, max_len and
/// reds; `ErtsRunQueue` len, max_len, flags, check_balance_reds, waiting), OTP-29.1.1.
#[repr(align(64))]
pub(crate) struct RunQueueBalance {
    len: [AtomicI32; PRIO_LEVELS],
    max_len: [AtomicI32; PRIO_LEVELS],
    reds: [AtomicI64; PRIO_LEVELS],
    total_len: AtomicI32,
    total_max_len: AtomicI32,
    /// Migration info flags (`ERTS_RUNQ_FLGS_MIGRATION_INFO` part of `rq->flags`).
    pub(crate) flags: AtomicU32,
    pub(crate) check_balance_reds: AtomicI64,
    /// The scheduler of this run queue sleeps waiting for work (`rq->waiting`).
    pub(crate) waiting: AtomicBool,
}

impl RunQueueBalance {
    fn new() -> Self {
        Self {
            len: std::array::from_fn(|_| AtomicI32::new(0)),
            max_len: std::array::from_fn(|_| AtomicI32::new(0)),
            reds: std::array::from_fn(|_| AtomicI64::new(0)),
            total_len: AtomicI32::new(0),
            total_max_len: AtomicI32::new(0),
            flags: AtomicU32::new(0),
            check_balance_reds: AtomicI64::new(CALL_CHECK_BALANCE_REDS),
            waiting: AtomicBool::new(false),
        }
    }

    /// Port of erts/emulator/beam/erl_process.h:798 (erts_add_runq_len), OTP-29.1.1.
    pub(crate) fn add_len(&self, prio: usize, n: i32) {
        let len = self.total_len.fetch_add(n, Ordering::Relaxed) + n;
        raise(&self.total_max_len, len);
        let len = self.len[prio].fetch_add(n, Ordering::Relaxed) + n;
        raise(&self.max_len[prio], len);
    }

    /// Port of erts/emulator/beam/erl_process.h:836 (erts_sub_runq_len), OTP-29.1.1.
    pub(crate) fn sub_len(&self, prio: usize, n: i32) {
        self.total_len.fetch_sub(n, Ordering::Relaxed);
        self.len[prio].fetch_sub(n, Ordering::Relaxed);
    }

    /// Port of erts/emulator/beam/erl_process.h:879 (RUNQ_READ_LEN), OTP-29.1.1.
    pub(crate) fn len(&self, prio: usize) -> i32 {
        self.len[prio].load(Ordering::Relaxed)
    }

    /// Port of erts/emulator/beam/erl_process.h:529 (ERTS_PROC_REDUCTIONS_EXECUTED),
    /// OTP-29.1.1.
    pub(crate) fn reductions_executed(&self, prio: usize, reds: i64) {
        self.reds[prio].fetch_add(reds, Ordering::Relaxed);
        self.check_balance_reds.fetch_sub(reds, Ordering::Relaxed);
    }

    /// Port of erts/emulator/beam/erl_process.c:4226 (resume_run_queue statistics reset),
    /// OTP-29.1.1.
    pub(crate) fn reset_statistics(&self) {
        self.check_balance_reds
            .store(CALL_CHECK_BALANCE_REDS, Ordering::Relaxed);
        for prio in 0..PRIO_LEVELS {
            let len = self.len[prio].load(Ordering::Relaxed);
            self.max_len[prio].store(len, Ordering::Relaxed);
            self.reds[prio].store(0, Ordering::Relaxed);
        }
        let len = self.total_len.load(Ordering::Relaxed);
        self.total_max_len.store(len, Ordering::Relaxed);
    }
}

/// `max = max(max, len)` without a write when the maximum already covers `len`.
fn raise(max: &AtomicI32, len: i32) {
    if len > max.load(Ordering::Relaxed) {
        max.fetch_max(len, Ordering::Relaxed);
    }
}

/// Migration limits and peer run queue of one priority.
///
/// Port of erts/emulator/beam/erl_process.h:417-428 (`ErtsMigrationPath.prio`), OTP-29.1.1.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct MigrationPrio {
    pub(crate) limit_here: i32,
    pub(crate) limit_other: i32,
    pub(crate) runq: Option<usize>,
    pub(crate) flags: u32,
}

impl MigrationPrio {
    const NONE: Self = Self {
        limit_here: -1,
        limit_other: -1,
        runq: None,
        flags: 0,
    };
}

/// Port of erts/emulator/beam/erl_process.h:417 (`ErtsMigrationPath`), OTP-29.1.1.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct MigrationPath {
    pub(crate) flags: u32,
    pub(crate) misc_evac_runq: Option<usize>,
    pub(crate) prio: [MigrationPrio; PRIO_LEVELS],
}

impl MigrationPath {
    const NONE: Self = Self {
        flags: 0,
        misc_evac_runq: None,
        prio: [MigrationPrio::NONE; PRIO_LEVELS],
    };
}

#[derive(Clone, Copy, Default)]
struct PrevRise {
    active_runqs: usize,
    max_len: i64,
    reds: i64,
}

#[derive(Clone, Copy)]
struct FullRedsHistory {
    entries: [i64; FULL_REDS_HISTORY_SIZE],
    sum: i64,
}

impl FullRedsHistory {
    // Port of erts/emulator/beam/erl_process.c:6159-6164, OTP-29.1.1.
    fn new() -> Self {
        Self {
            entries: [CHECK_BALANCE_REDS_PER_SCHED; FULL_REDS_HISTORY_SIZE],
            sum: CHECK_BALANCE_REDS_PER_SCHED * FULL_REDS_HISTORY_SIZE as i64,
        }
    }
}

/// Port of erts/emulator/beam/erl_process.c:304-322 (`balance_info` fields guarded by
/// `update_mtx` or `checking_balance`), OTP-29.1.1.
struct BalanceState {
    halftime: bool,
    forced_check_balance: bool,
    last_active_runqs: usize,
    prev_rise: PrevRise,
    full_reds_history_index: usize,
    /// `rq->full_reds_history` and `rq->full_reds_history_sum`; only check_balance
    /// touches them.
    history: Vec<FullRedsHistory>,
}

/// One run queue's balance statistics as read by check_balance.
///
/// Port of erts/emulator/beam/erl_process.c:4685 (`ErtsRunQueueBalance`), OTP-29.1.1.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Sample {
    pub(crate) flags: u32,
    pub(crate) max_len: [i64; PRIO_LEVELS],
    pub(crate) reds: [i64; PRIO_LEVELS],
    pub(crate) total_max_len: i64,
}

#[derive(Clone, Copy, Default)]
struct PrioBalance {
    max_len: i64,
    avail: i64,
    reds: i64,
    migration_limit: i64,
    emigrate_to: Option<usize>,
    immigrate_from: Option<usize>,
}

#[derive(Clone, Copy, Default)]
struct QueueBalance {
    flags: u32,
    prio: [PrioBalance; PRIO_LEVELS],
    full_reds: i64,
    full_reds_history_sum: i64,
    full_reds_history_change: i64,
    max_len: i64,
}

/// Result of one full balance check.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Plan {
    pub(crate) active: usize,
    /// New migration paths of the balanced (used) run queues.
    pub(crate) paths: Vec<MigrationPath>,
}

/// Port of erts/emulator/beam/erl_process.c:4760 (ERTS_PERCENT), OTP-29.1.1.
fn percent(x: i64, y: i64) -> i64 {
    if y == 0 {
        if x == 0 { 100 } else { i64::from(i32::MAX) }
    } else {
        (100 * x) / y
    }
}

/// Run queue balancing state shared by all normal schedulers.
pub(crate) struct Balance {
    pub(crate) rqs: Vec<RunQueueBalance>,
    checking_balance: AtomicBool,
    state: Mutex<BalanceState>,
    /// Completed balance checks (`balance_info.n`).
    n: AtomicU64,
    /// Active run queues (`balance_info.no_runqs` active part).
    no_active_runqs: AtomicUsize,
    /// Used run queues (`balance_info.no_runqs` used part).
    no_used_runqs: AtomicUsize,
    /// Published migration paths (`erts_migration_paths`).
    paths: Mutex<Arc<Vec<MigrationPath>>>,
    /// `paths[ix].flags`, readable without taking the paths lock.
    path_flags: Vec<AtomicU32>,
    compact_load: bool,
}

impl Balance {
    /// Port of erts/emulator/beam/erl_process.c:6330-6343 (balance_info initialization)
    /// and erl_process.c:4797 (init_migration_paths), OTP-29.1.1.
    pub(crate) fn new(schedulers: usize, online: usize, compact_load: bool) -> Self {
        Self {
            rqs: (0..schedulers).map(|_| RunQueueBalance::new()).collect(),
            checking_balance: AtomicBool::new(false),
            state: Mutex::new(BalanceState {
                halftime: true,
                forced_check_balance: false,
                last_active_runqs: schedulers,
                prev_rise: PrevRise::default(),
                full_reds_history_index: 0,
                history: vec![FullRedsHistory::new(); schedulers],
            }),
            n: AtomicU64::new(0),
            no_active_runqs: AtomicUsize::new(online),
            no_used_runqs: AtomicUsize::new(online),
            paths: Mutex::new(Arc::new(vec![MigrationPath::NONE; schedulers])),
            path_flags: (0..schedulers).map(|_| AtomicU32::new(0)).collect(),
            compact_load,
        }
    }

    /// Number of completed balance checks (`erts_debug:get_internal_state(nbalance)`).
    pub(crate) fn checks(&self) -> u64 {
        self.n.load(Ordering::Relaxed)
    }

    fn rq(&self, ix: usize) -> &RunQueueBalance {
        &self.rqs[ix.min(self.rqs.len() - 1)]
    }

    /// A process of priority `prio` joined run queue `ix`; `queued_prio` remembers the
    /// counted level for [`Self::dequeued`] (enqueue_process, erl_process.c:3951).
    pub(crate) fn enqueued(
        &self,
        prio: usize,
        queued_prio: &std::sync::atomic::AtomicU8,
        ix: usize,
    ) {
        queued_prio.store(prio as u8, Ordering::Relaxed);
        self.rq(ix).add_len(prio, 1);
    }

    /// A queued process left run queue `ix` to execute (dequeue_process,
    /// erl_process.c:4000).
    pub(crate) fn dequeued(&self, queued_prio: &std::sync::atomic::AtomicU8, ix: usize) {
        self.rq(ix)
            .sub_len(usize::from(queued_prio.load(Ordering::Relaxed)), 1);
    }

    /// A queued process moved from run queue `from` to `to` (erts_try_change_runq_proc).
    pub(crate) fn migrated(
        &self,
        queued_prio: &std::sync::atomic::AtomicU8,
        from: usize,
        to: usize,
    ) {
        let prio = usize::from(queued_prio.load(Ordering::Relaxed));
        self.rq(from).sub_len(prio, 1);
        self.rq(to).add_len(prio, 1);
    }

    /// Port of erts/emulator/beam/erl_process.c:3800 (get_no_runqs), OTP-29.1.1.
    pub(crate) fn no_runqs(&self) -> (usize, usize) {
        (
            self.no_active_runqs.load(Ordering::Acquire),
            self.no_used_runqs.load(Ordering::Acquire),
        )
    }

    /// Port of erts/emulator/beam/erl_process.c:3842 (try_inc_no_active_runqs), OTP-29.1.1.
    pub(crate) fn try_inc_no_active_runqs(&self, active: usize) -> bool {
        if self.no_used_runqs.load(Ordering::Acquire) < active {
            return false;
        }
        self.no_active_runqs
            .compare_exchange(active - 1, active, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    pub(crate) fn path_flags(&self, ix: usize) -> u32 {
        self.path_flags[ix].load(Ordering::Acquire)
    }

    pub(crate) fn migration_paths(&self) -> Arc<Vec<MigrationPath>> {
        self.paths.lock().unwrap().clone()
    }

    fn publish(&self, paths: Vec<MigrationPath>) {
        let mut published = self.paths.lock().unwrap();
        for (ix, path) in paths.iter().enumerate() {
            self.path_flags[ix].store(path.flags, Ordering::Release);
        }
        *published = Arc::new(paths);
    }

    /// Port of erts/emulator/beam/erl_process.c:2930 (sched_waiting) and erl_process.c:2942
    /// (sched_active) run queue part, OTP-29.1.1.
    pub(crate) fn set_waiting(&self, ix: usize, waiting: bool) {
        let rq = &self.rqs[ix];
        if waiting {
            rq.flags
                .fetch_or(FLG_OUT_OF_WORK | FLG_HALFTIME_OUT_OF_WORK, Ordering::AcqRel);
        }
        rq.waiting.store(waiting, Ordering::Release);
    }

    /// Port of erts/emulator/beam/erl_process.h:2486 (erts_check_emigration_need),
    /// OTP-29.1.1.
    pub(crate) fn check_emigration_need(&self, c_rq: usize, prio: usize) -> Option<usize> {
        if self.path_flags(c_rq) & flg_emigrate(prio) == 0 {
            return None;
        }
        let paths = self.migration_paths();
        let mp = &paths[c_rq];
        let flags = mp.flags;
        if flags & flg_emigrate(prio) == 0 {
            return None;
        }
        if flags & flg_evacuate(prio) != 0 {
            return mp.prio[prio].runq;
        }
        if flags & FLG_INACTIVE != 0
            && self.rqs[c_rq].flags.load(Ordering::Acquire) & FLG_INACTIVE != 0
        {
            return mp.prio[prio].runq;
        }
        if self.rqs[c_rq].len(prio) > mp.prio[prio].limit_here
            && let Some(n_rq) = mp.prio[prio].runq
            && self.rqs[n_rq].len(prio) < mp.prio[prio].limit_other
        {
            return Some(n_rq);
        }
        None
    }

    /// Port of erts/emulator/beam/erl_process.c:4071 (check_immigration_need), OTP-29.1.1.
    pub(crate) fn check_immigration_need(
        &self,
        c_rq: usize,
        mp: &MigrationPath,
        prio: usize,
    ) -> Option<usize> {
        let f_flags = mp.prio[prio].flags;
        let f_rq = mp.prio[prio].runq?;
        if f_flags & flg_evacuate(prio) != 0 {
            return Some(f_rq);
        }
        if self.rqs[f_rq].flags.load(Ordering::Acquire) & FLG_INACTIVE != 0 {
            return Some(f_rq);
        }
        if self.rqs[c_rq].len(prio) < mp.prio[prio].limit_here
            && self.rqs[f_rq].len(prio) > mp.prio[prio].limit_other
        {
            return Some(f_rq);
        }
        None
    }

    /// Port of erts/emulator/beam/erl_process.c:5476 (change_no_used_runqs), OTP-29.1.1.
    pub(crate) fn change_no_used_runqs(&self, used: usize) {
        let used = used.clamp(1, self.rqs.len());
        let mut state = self.state.lock().unwrap();
        self.no_used_runqs.store(used, Ordering::Release);
        let old = self.migration_paths();
        let mut paths = vec![MigrationPath::NONE; self.rqs.len()];
        for (qix, path) in paths.iter_mut().enumerate().take(used) {
            path.flags = old[qix].flags & !MIGRATION_QMASKS;
        }
        for (qix, path) in paths.iter_mut().enumerate().skip(used) {
            let to_rq = qix % used;
            path.flags = EMIGRATE_QMASK | EVACUATE_QMASK;
            path.misc_evac_runq = Some(to_rq);
            for prio in &mut path.prio {
                prio.runq = Some(to_rq);
            }
        }
        self.publish(paths);
        // Make sure that we balance soon...
        state.forced_check_balance = true;
        drop(state);
        self.rqs[0].check_balance_reds.store(0, Ordering::Release);
    }

    /// Port of erts/emulator/beam/erl_process.c:4894 (check_balance), OTP-29.1.1.
    ///
    /// `c_rq` is the run queue whose scheduler ran out of balance reductions.
    pub(crate) fn check_balance(&self, c_rq: usize) {
        if self.checking_balance.swap(true, Ordering::AcqRel) {
            self.rqs[c_rq]
                .check_balance_reds
                .store(i64::MAX, Ordering::Relaxed);
            return;
        }
        let (_, blnc_no_rqs) = self.no_runqs();
        if blnc_no_rqs == 1 {
            self.rqs[c_rq]
                .check_balance_reds
                .store(i64::MAX, Ordering::Relaxed);
            self.checking_balance.store(false, Ordering::Release);
            return;
        }
        let mut state = self.state.lock().unwrap();
        if state.halftime {
            state.halftime = false;
            self.checking_balance.store(false, Ordering::Release);
            for rq in &self.rqs {
                if rq.waiting.load(Ordering::Acquire) {
                    rq.flags
                        .fetch_or(FLG_HALFTIME_OUT_OF_WORK, Ordering::AcqRel);
                } else {
                    rq.flags
                        .fetch_and(!FLG_HALFTIME_OUT_OF_WORK, Ordering::AcqRel);
                }
                rq.check_balance_reds
                    .store(CALL_CHECK_BALANCE_REDS, Ordering::Relaxed);
            }
            return;
        }
        let forced = std::mem::take(&mut state.forced_check_balance);
        let (current_active, blnc_no_rqs) = self.no_runqs();
        if blnc_no_rqs == 1 {
            drop(state);
            self.rqs[c_rq]
                .check_balance_reds
                .store(i64::MAX, Ordering::Relaxed);
            self.checking_balance.store(false, Ordering::Release);
            return;
        }
        let blnc_no_rqs = blnc_no_rqs.min(self.rqs.len());
        // Read balance information for all run queues.
        let samples: Vec<Sample> = self.rqs[..blnc_no_rqs]
            .iter()
            .map(|rq| {
                rq.check_balance_reds.store(i64::MAX, Ordering::Relaxed);
                Sample {
                    flags: rq.flags.load(Ordering::Acquire),
                    max_len: std::array::from_fn(|p| {
                        i64::from(rq.max_len[p].load(Ordering::Relaxed))
                    }),
                    reds: std::array::from_fn(|p| rq.reds[p].load(Ordering::Relaxed)),
                    total_max_len: i64::from(rq.total_max_len.load(Ordering::Relaxed)),
                }
            })
            .collect();
        let freds_hist_ix = state.full_reds_history_index;
        let (plan, history) = plan(
            &mut state,
            &samples,
            current_active,
            forced,
            self.compact_load,
        );
        let active = plan.active;
        state.last_active_runqs = active;
        self.set_no_active_runqs(active);
        state.halftime = true;
        // Keep offline run queues as is.
        let old = self.migration_paths();
        let mut paths = plan.paths;
        paths.extend_from_slice(&old[blnc_no_rqs..]);
        let flags: Vec<u32> = paths[..blnc_no_rqs].iter().map(|path| path.flags).collect();
        self.publish(paths);
        // Reset balance statistics in all online queues.
        for (qix, rq) in self.rqs[..blnc_no_rqs].iter().enumerate() {
            let mut flags = flags[qix];
            if rq.waiting.load(Ordering::Acquire) {
                flags |= FLG_OUT_OF_WORK;
            }
            state.history[qix].sum = history[qix].0;
            state.history[qix].entries[freds_hist_ix] = history[qix].1;
            let _ = rq
                .flags
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |old| {
                    Some((old & !MIGRATION_INFO) | flags)
                });
            rq.total_max_len
                .store(rq.total_len.load(Ordering::Relaxed), Ordering::Relaxed);
            for prio in 0..PRIO_LEVELS {
                rq.max_len[prio].store(rq.len[prio].load(Ordering::Relaxed), Ordering::Relaxed);
                rq.reds[prio].store(0, Ordering::Relaxed);
            }
            rq.check_balance_reds
                .store(CALL_CHECK_BALANCE_REDS, Ordering::Relaxed);
        }
        self.checking_balance.store(false, Ordering::Release);
        self.n.fetch_add(1, Ordering::Relaxed);
    }

    /// Port of erts/emulator/beam/erl_process.c:3825 (set_no_active_runqs), OTP-29.1.1.
    fn set_no_active_runqs(&self, active: usize) {
        self.no_active_runqs.store(active, Ordering::Release);
    }
}

/// The computation part of check_balance: availability, migration limits and migration
/// paths of the `samples.len()` balanced run queues. Returns the plan and, per run queue,
/// its new full reductions history sum and history change.
///
/// Port of erts/emulator/beam/erl_process.c:4962-5395 (check_balance), OTP-29.1.1.
fn plan(
    state: &mut BalanceState,
    samples: &[Sample],
    current_active: usize,
    forced: bool,
    compact_load: bool,
) -> (Plan, Vec<(i64, i64)>) {
    let blnc_no_rqs = samples.len();
    let freds_hist_ix = state.full_reds_history_index;
    state.full_reds_history_index += 1;
    if state.full_reds_history_index >= FULL_REDS_HISTORY_SIZE {
        state.full_reds_history_index = 0;
    }
    let mut info: Vec<QueueBalance> = samples
        .iter()
        .enumerate()
        .map(|(qix, sample)| {
            let mut queue = QueueBalance {
                flags: sample.flags,
                full_reds_history_sum: state.history[qix].sum,
                full_reds_history_change: state.history[qix].entries[freds_hist_ix],
                max_len: sample.total_max_len,
                ..QueueBalance::default()
            };
            for pix in 0..PRIO_LEVELS {
                queue.prio[pix].max_len = sample.max_len[pix];
                queue.prio[pix].reds = sample.reds[pix];
            }
            queue
        })
        .collect();
    // Port of erts/emulator/beam/erl_process.c:4756 (ERTS_UPDATE_FULL_REDS), OTP-29.1.1.
    let update_full_reds = |queue: &mut QueueBalance, last_reds: i64| {
        queue.full_reds = (queue.full_reds_history_sum + last_reds) >> FULL_REDS_HISTORY_AVG_SHFT;
        queue.full_reds_history_sum -= queue.full_reds_history_change;
        queue.full_reds_history_sum += last_reds;
        queue.full_reds_history_change = last_reds;
    };

    let mut full_scheds = 0_i64;
    let mut half_full_scheds = 0_usize;
    let mut full_scheds_reds = 0_i64;
    let mut scheds_reds = 0_i64;
    let mut mmax_len = 0_i64;

    // Calculate availability for each priority in each run queue.
    for queue in &mut info {
        let mut treds = 0_i64;
        if queue.flags & FLG_OUT_OF_WORK != 0 {
            for prio in &mut queue.prio {
                prio.avail = 100;
                treds += prio.reds;
            }
            if queue.flags & FLG_HALFTIME_OUT_OF_WORK == 0 {
                half_full_scheds += 1;
            }
            update_full_reds(queue, CHECK_BALANCE_REDS_PER_SCHED);
        } else {
            for prio in &queue.prio {
                treds += prio.reds;
            }
            if treds == 0 {
                for prio in &mut queue.prio {
                    prio.avail = 0;
                }
            } else {
                let mut xreds = 0_i64;
                let procreds = treds - queue.prio[PORT_PRIO_LEVEL].reds;
                for pix in 0..PROC_PRIO_LEVELS {
                    let av = if xreds == 0 {
                        100
                    } else if procreds == xreds {
                        0
                    } else {
                        ((100 * (procreds - xreds)) / procreds).max(1)
                    };
                    queue.prio[pix].avail = av;
                    if pix < PRIORITY_NORMAL {
                        xreds += queue.prio[pix].reds;
                    }
                }
                queue.prio[PORT_PRIO_LEVEL].avail = 100;
            }
            update_full_reds(queue, treds);
            full_scheds_reds += queue.full_reds;
            full_scheds += 1;
            half_full_scheds += 1;
        }
        scheds_reds += treds;
        mmax_len = mmax_len.max(queue.max_len);
    }

    let mut active;
    let mut all_active = !compact_load;
    if !all_active && !forced && half_full_scheds != blnc_no_rqs {
        let min = half_full_scheds.max(1);
        active = if full_scheds != 0 {
            ((scheds_reds - 1) / CHECK_BALANCE_REDS_PER_SCHED + 1).max(0) as usize
        } else {
            state.last_active_runqs.saturating_sub(1)
        };
        if state.last_active_runqs < current_active {
            state.prev_rise = PrevRise {
                active_runqs: current_active,
                max_len: mmax_len,
                reds: scheds_reds,
            };
            active = current_active;
        } else if active < state.prev_rise.active_runqs
            && percent(mmax_len, state.prev_rise.max_len) >= 90
            && percent(scheds_reds, state.prev_rise.reds) >= 90
        {
            active = state.prev_rise.active_runqs;
        }
        if active < min {
            active = min;
        } else if active > blnc_no_rqs {
            active = blnc_no_rqs;
        }
        if active == blnc_no_rqs {
            all_active = true;
        } else {
            for queue in &mut info[..active] {
                queue.flags = 0;
                for prio in &mut queue.prio {
                    prio.emigrate_to = None;
                    prio.immigrate_from = None;
                    prio.migration_limit = 0;
                }
            }
            for (qix, queue) in info.iter_mut().enumerate().skip(active) {
                queue.flags = FLG_INACTIVE;
                for (pix, prio) in queue.prio.iter_mut().enumerate() {
                    queue.flags |= flg_emigrate(pix);
                    prio.emigrate_to = Some(qix % active);
                    prio.immigrate_from = None;
                    prio.migration_limit = 0;
                }
            }
        }
    } else {
        if state.last_active_runqs < current_active {
            state.prev_rise = PrevRise {
                active_runqs: current_active,
                max_len: mmax_len,
                reds: scheds_reds,
            };
        }
        all_active = true;
        active = blnc_no_rqs;
    }

    if all_active {
        active = blnc_no_rqs;
        let mut avg = [(0_i64, 0_i64); PRIO_LEVELS];
        for queue in &mut info {
            if full_scheds_reds > 0 && queue.flags & FLG_OUT_OF_WORK == 0 {
                // Calculate availability compared to other schedulers.
                let tmp = queue.full_reds * full_scheds;
                for prio in &mut queue.prio {
                    prio.avail = (prio.avail * tmp) / full_scheds_reds;
                }
            }
            // Calculate average max length.
            for (pix, prio) in queue.prio.iter_mut().enumerate() {
                prio.emigrate_to = None;
                prio.immigrate_from = None;
                avg[pix].0 += prio.max_len;
                avg[pix].1 += prio.avail;
            }
        }
        for (max_len, avail) in &mut avg {
            if *max_len != 0 && *avail != 0 {
                *max_len = (100 * *max_len - 1) / *avail + 1;
            }
        }
        // Calculate migration limits for all priority queues in all run queues.
        for queue in &mut info {
            queue.flags = 0;
            for (pix, prio) in queue.prio.iter_mut().enumerate() {
                prio.migration_limit = if avg[pix].0 == 0 || prio.avail == 0 {
                    0
                } else {
                    (avg[pix].0 * prio.avail - 1) / 100 + 1
                };
            }
        }
        // Setup migration paths for all priorities.
        for pix in 0..PRIO_LEVELS {
            setup_migration_paths(&mut info, pix);
        }
    }

    let paths = info
        .iter()
        .map(|queue| {
            let flags = queue.flags;
            let mut path = MigrationPath {
                flags,
                misc_evac_runq: None,
                prio: [MigrationPrio::NONE; PRIO_LEVELS],
            };
            for pix in 0..PRIO_LEVELS {
                let peer = if flags & flg_emigrate(pix) != 0 {
                    queue.prio[pix].emigrate_to
                } else if flags & flg_immigrate(pix) != 0 {
                    queue.prio[pix].immigrate_from
                } else {
                    None
                };
                if let Some(mqix) = peer {
                    path.prio[pix] = MigrationPrio {
                        limit_here: limit(queue.prio[pix].migration_limit),
                        limit_other: limit(info[mqix].prio[pix].migration_limit),
                        runq: Some(mqix),
                        flags: info[mqix].flags,
                    };
                }
            }
            path
        })
        .collect();
    let history = info
        .iter()
        .map(|queue| (queue.full_reds_history_sum, queue.full_reds_history_change))
        .collect();
    (Plan { active, paths }, history)
}

fn limit(value: i64) -> i32 {
    value.clamp(i64::from(i32::MIN), i64::from(i32::MAX)) as i32
}

/// Port of erts/emulator/beam/erl_process.c:5222-5357 (check_balance migration path
/// setup for one priority), OTP-29.1.1.
fn setup_migration_paths(info: &mut [QueueBalance], pix: usize) {
    let blnc_no_rqs = info.len();
    let mut low = 0;
    let mut high = 0;
    let mut compare: Vec<(usize, i64)> = info
        .iter()
        .enumerate()
        .map(|(qix, queue)| {
            let len_diff = queue.prio[pix].max_len - queue.prio[pix].migration_limit;
            if len_diff < 0 {
                low += 1;
            } else if len_diff > 0 {
                high += 1;
            }
            (qix, len_diff)
        })
        .collect();
    if low == 0 || high == 0 {
        return;
    }
    // qsort is not stable; any order of equal lengths is a valid erts outcome.
    compare.sort_by_key(|&(_, len)| len);
    let mut tix = 0_usize;
    let mut fix = blnc_no_rqs as isize - 1;
    let mut eof = false;
    let mut eot = false;
    loop {
        if compare[fix as usize].1 <= 0 {
            eof = true;
        }
        if compare[tix].1 >= 0 {
            eot = true;
        }
        if eof || eot {
            break;
        }
        let from_qix = compare[fix as usize].0;
        let to_qix = compare[tix].0;
        if info[from_qix].prio[pix].avail == 0 {
            info[from_qix].flags |= flg_evacuate(pix);
            info[to_qix].flags |= flg_evacuate(pix);
        }
        info[from_qix].flags |= flg_emigrate(pix);
        info[to_qix].flags |= flg_immigrate(pix);
        info[from_qix].prio[pix].emigrate_to = Some(to_qix);
        info[to_qix].prio[pix].immigrate_from = Some(from_qix);
        tix += 1;
        fix -= 1;
    }
    if !eot && eof {
        if fix < blnc_no_rqs as isize - 1 {
            fix += 1;
        }
        if compare[fix as usize].1 > 0 {
            let mut fix2: isize = -1;
            while (tix as isize) < fix {
                if compare[tix].1 >= 0 {
                    break;
                }
                if fix2 < fix {
                    fix2 = blnc_no_rqs as isize - 1;
                }
                let from_qix = compare[fix2 as usize].0;
                let to_qix = compare[tix].0;
                if info[from_qix].prio[pix].avail == 0 {
                    info[to_qix].flags |= flg_evacuate(pix);
                }
                info[to_qix].flags |= flg_immigrate(pix);
                info[to_qix].prio[pix].immigrate_from = Some(from_qix);
                tix += 1;
                fix2 -= 1;
            }
        }
    } else if !eof && eot {
        tix = tix.saturating_sub(1);
        if compare[tix].1 < 0 {
            let mut tix2 = 0_usize;
            while (tix as isize) < fix {
                if compare[fix as usize].1 <= 0 {
                    break;
                }
                if tix2 > tix {
                    tix2 = 0;
                }
                let from_qix = compare[fix as usize].0;
                let to_qix = compare[tix2].0;
                if info[from_qix].prio[pix].avail == 0 {
                    info[from_qix].flags |= flg_evacuate(pix);
                }
                info[from_qix].flags |= flg_emigrate(pix);
                info[from_qix].prio[pix].emigrate_to = Some(to_qix);
                fix -= 1;
                tix2 += 1;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(schedulers: usize) -> BalanceState {
        BalanceState {
            halftime: false,
            forced_check_balance: false,
            last_active_runqs: schedulers,
            prev_rise: PrevRise::default(),
            full_reds_history_index: 0,
            history: vec![FullRedsHistory::new(); schedulers],
        }
    }

    fn busy(normal_max_len: i64) -> Sample {
        Sample {
            flags: 0,
            max_len: [0, 0, normal_max_len, 0, 0],
            reds: [0, 0, CHECK_BALANCE_REDS_PER_SCHED, 0, 0],
            total_max_len: normal_max_len,
        }
    }

    #[test]
    fn long_queue_emigrates_to_short_queue() {
        let mut st = state(2);
        let (planned, _) = plan(&mut st, &[busy(100), busy(10)], 2, false, true);
        assert_eq!(planned.active, 2);
        // Average max length 55 at full availability.
        let from = planned.paths[0];
        let to = planned.paths[1];
        assert_ne!(from.flags & flg_emigrate(PRIORITY_NORMAL), 0);
        assert_ne!(to.flags & flg_immigrate(PRIORITY_NORMAL), 0);
        assert_eq!(from.prio[PRIORITY_NORMAL].runq, Some(1));
        assert_eq!(to.prio[PRIORITY_NORMAL].runq, Some(0));
        assert_eq!(from.prio[PRIORITY_NORMAL].limit_here, 55);
        assert_eq!(to.prio[PRIORITY_NORMAL].limit_here, 55);
    }

    #[test]
    fn long_port_queue_emigrates_to_short_queue() {
        let mut st = state(2);
        let ports = |max_len: i64| Sample {
            flags: 0,
            max_len: [0, 0, 0, 0, max_len],
            reds: [0, 0, 0, 0, CHECK_BALANCE_REDS_PER_SCHED],
            total_max_len: max_len,
        };
        let (planned, _) = plan(&mut st, &[ports(40), ports(0)], 2, false, true);
        let from = planned.paths[0];
        let to = planned.paths[1];
        assert_ne!(from.flags & flg_emigrate(PORT_PRIO_LEVEL), 0);
        assert_ne!(to.flags & flg_immigrate(PORT_PRIO_LEVEL), 0);
        assert_eq!(from.prio[PORT_PRIO_LEVEL].runq, Some(1));
        assert_eq!(to.prio[PORT_PRIO_LEVEL].runq, Some(0));
        // Ports are always fully available; process levels see no process reductions.
        assert_eq!(from.prio[PORT_PRIO_LEVEL].limit_here, 20);
        assert_eq!(from.flags & flg_emigrate(PRIORITY_NORMAL), 0);
    }

    #[test]
    fn balanced_queues_get_no_paths() {
        let mut st = state(2);
        let (planned, _) = plan(&mut st, &[busy(10), busy(10)], 2, false, true);
        assert!(planned.paths.iter().all(|path| path.flags == 0));
    }

    #[test]
    fn compact_load_deactivates_idle_run_queues() {
        let mut st = state(4);
        let idle = Sample {
            flags: FLG_OUT_OF_WORK | FLG_HALFTIME_OUT_OF_WORK,
            ..Sample::default()
        };
        let little = Sample {
            reds: [0, 0, 1000, 0, 0],
            ..Sample::default()
        };
        let (planned, _) = plan(&mut st, &[little, idle, idle, idle], 4, false, true);
        assert_eq!(planned.active, 1);
        for path in &planned.paths[1..] {
            assert_ne!(path.flags & FLG_INACTIVE, 0);
            assert_eq!(path.prio[PRIORITY_NORMAL].runq, Some(0));
        }
        // Without compact load every run queue stays active.
        let mut st = state(4);
        let (planned, _) = plan(&mut st, &[little, idle, idle, idle], 4, false, false);
        assert_eq!(planned.active, 4);
    }

    #[test]
    fn full_reds_history_rotates() {
        let mut st = state(2);
        let (_, history) = plan(&mut st, &[busy(1), busy(1)], 2, false, true);
        assert_eq!(st.full_reds_history_index, 1);
        assert_eq!(
            history[0],
            (FullRedsHistory::new().sum, CHECK_BALANCE_REDS_PER_SCHED)
        );
    }

    #[test]
    fn balance_counts_checks_after_halftime() {
        let balance = Balance::new(2, 2, true);
        balance.check_balance(0);
        assert_eq!(balance.checks(), 0);
        balance.check_balance(0);
        assert_eq!(balance.checks(), 1);
        assert_eq!(
            balance.rqs[1].check_balance_reds.load(Ordering::Relaxed),
            CALL_CHECK_BALANCE_REDS
        );
    }

    #[test]
    fn offline_run_queues_evacuate() {
        let balance = Balance::new(4, 4, true);
        balance.change_no_used_runqs(2);
        let paths = balance.migration_paths();
        assert_eq!(paths[3].prio[PRIORITY_LOW].runq, Some(1));
        assert_eq!(balance.check_emigration_need(3, 1), Some(1));
        assert_eq!(balance.check_emigration_need(1, 1), None);
    }
}
