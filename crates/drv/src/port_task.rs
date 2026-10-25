//! Port task scheduling: per-port task queues, the busy queue, busy port message queue
//! accounting and the port run queue.
//!
//! Port of erts/emulator/beam/erl_port_task.c and erl_port_task.h, OTP-29.1.1. Process to
//! port signals that cannot run immediately on the caller's thread are queued as tasks of
//! the port; the port is put on its run queue and a normal scheduler runs its tasks with
//! the port lock held (arinsal-sched executes [`RunPort`] entries between processes).

use parking_lot::{Mutex, MutexGuard};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::time::Instant;

use arinsal_sched::{PortExecution, PortRunQueue, RunPort};

use crate::{CALLBACK_VREDS, CONTEXT_REDS, DriverPort, REDS_EXECUTE};

mod intrusive;
use intrusive::{BusyCallerTable, Link, Queue};

// Port of erts/emulator/beam/erl_port_task.h:77-82 (ERTS_PT_FLG_*), OTP-29.1.1.
/// The task waits while the port is busy (`ERTS_PT_FLG_WAIT_BUSY`).
pub const PT_FLG_WAIT_BUSY: u32 = 1 << 0;
/// Signal order dependency on earlier tasks of the same caller (`ERTS_PT_FLG_SIG_DEP`).
pub const PT_FLG_SIG_DEP: u32 = 1 << 1;
/// Aborted when the port becomes busy (`ERTS_PT_FLG_NOSUSPEND`).
pub const PT_FLG_NOSUSPEND: u32 = 1 << 2;
/// Asynchronous nosuspend output (`ERTS_PT_FLG_ASYNC_NOSUSPEND`).
pub const PT_FLG_ASYNC_NOSUSPEND: u32 = 1 << 5;

// Port of erts/emulator/beam/erl_port_task.h:97-123 (ERTS_PTS_FLG_*), OTP-29.1.1.
/// The port is in a run queue.
pub const PTS_FLG_IN_RUNQ: u32 = 1 << 0;
/// A scheduler executes the port's tasks.
pub const PTS_FLG_EXEC: u32 = 1 << 1;
/// The in queue is not empty.
pub const PTS_FLG_HAVE_TASKS: u32 = 1 << 2;
/// The port is gone; no more tasks are accepted.
pub const PTS_FLG_EXIT: u32 = 1 << 3;
/// `set_busy_port(port, 1)`.
pub const PTS_FLG_BUSY_PORT: u32 = 1 << 4;
/// The busy port message queue is above its high limit.
pub const PTS_FLG_BUSY_PORT_Q: u32 = 1 << 5;
/// The busy port message queue may have dropped below its low limit.
pub const PTS_FLG_CHK_UNSET_BUSY_PORT_Q: u32 = 1 << 6;
/// The busy queue is not empty.
pub const PTS_FLG_HAVE_BUSY_TASKS: u32 = 1 << 7;
/// Nosuspend tasks are scheduled.
pub const PTS_FLG_HAVE_NS_TASKS: u32 = 1 << 8;
/// `{parallelism, true}`.
pub const PTS_FLG_PARALLELISM: u32 = 1 << 9;
/// Operations must be scheduled.
pub const PTS_FLG_FORCE_SCHED: u32 = 1 << 10;
/// The port is exiting.
pub const PTS_FLG_EXITING: u32 = 1 << 11;
/// A process runs a driver callback immediately.
pub const PTS_FLG_EXEC_IMM: u32 = 1 << 12;
/// `ERTS_PTS_FLGS_BUSY`.
pub const PTS_FLGS_BUSY: u32 = PTS_FLG_BUSY_PORT | PTS_FLG_BUSY_PORT_Q;
/// `ERTS_PTS_FLGS_FORCE_SCHEDULE_OP`: an operation cannot run immediately.
pub const PTS_FLGS_FORCE_SCHEDULE_OP: u32 = PTS_FLG_EXIT
    | PTS_FLG_HAVE_BUSY_TASKS
    | PTS_FLG_HAVE_TASKS
    | PTS_FLG_EXEC
    | PTS_FLG_EXEC_IMM
    | PTS_FLG_FORCE_SCHED
    | PTS_FLG_EXITING;

// erl_port_task.c:122-124 (ERTS_PT_STATE_*).
const STATE_SCHEDULED: u32 = 0;
const STATE_ABORTED: u32 = 1;
const STATE_EXECUTING: u32 = 2;

/// `ERTS_INVALID_PID`: the caller of a port to port signal.
pub const INVALID_CALLER: u64 = u64::MAX;

/// How a process to port signal callback is invoked (`ERTS_PROC2PORT_SIG_*`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SigOp {
    /// Execute the operation; the port lock is held.
    Exec,
    /// The signal was aborted.
    Abort,
    /// A nosuspend signal was aborted because the port became busy.
    AbortNosuspend,
    /// The port closed before the signal executed.
    AbortClosed,
}

/// `ErtsProc2PortSigCallback`: runs the operation or its abort; returns reductions.
pub type SigCallback = Box<dyn FnOnce(SigOp) -> i32 + Send>;

/// A process to port signal to schedule (`ErtsProc2PortSigData`).
pub struct ProcSig {
    /// Process data of the sending process, or [`INVALID_CALLER`].
    pub caller: u64,
    /// `PT_FLG_*` task flags; `PT_FLG_SIG_DEP` is always added.
    pub flags: u32,
    /// Command data bytes for the busy port message queue
    /// (`erts_proc2port_sig_command_data_size`).
    pub size: usize,
    /// Optional deadline for a task queued while the port is busy.
    pub deadline: Option<Instant>,
    /// The operation.
    pub callback: SigCallback,
}

enum TaskKind {
    Timeout(u64),
    /// `ERTS_PORT_TASK_INPUT` (`dir` 0) or `ERTS_PORT_TASK_OUTPUT` (`dir` 1) for poll
    /// registration `reg` of `fd`.
    Io {
        fd: i32,
        dir: usize,
        reg: u64,
    },
    ProcSig {
        caller: u64,
        size: usize,
        deadline: Option<Instant>,
        callback: Mutex<Option<SigCallback>>,
    },
    /// `ERTS_PORT_TASK_DIST_CMD`: the port drains the distribution output queue of its
    /// connection.
    DistCmd(Mutex<Option<SigCallback>>),
}

/// `ErtsPortTask`.
pub(crate) struct PortTask {
    state: AtomicU32,
    flags: u32,
    kind: TaskKind,
    queue_link: Link<PortTask>,
    nosuspend_link: Link<PortTask>,
}

/// I/O tasks scheduled and not yet freed (`erts_port_task_outstanding_io_tasks`).
static OUTSTANDING_IO_TASKS: AtomicUsize = AtomicUsize::new(0);

/// Whether an I/O task waits for a scheduler, so that scheduler polling can be skipped.
// Port of erts/emulator/beam/erl_port_task.h (erts_port_task_have_outstanding_io_tasks),
// OTP-29.1.1.
pub fn have_outstanding_io_tasks() -> bool {
    OUTSTANDING_IO_TASKS.load(Ordering::Acquire) != 0
}

impl Drop for PortTask {
    fn drop(&mut self) {
        if matches!(self.kind, TaskKind::Io { .. }) {
            OUTSTANDING_IO_TASKS.fetch_sub(1, Ordering::AcqRel);
        }
    }
}

impl PortTask {
    fn caller(&self) -> u64 {
        match &self.kind {
            TaskKind::ProcSig { caller, .. } => *caller,
            TaskKind::Timeout(_) | TaskKind::Io { .. } | TaskKind::DistCmd(_) => INVALID_CALLER,
        }
    }

    fn size(&self) -> usize {
        match &self.kind {
            TaskKind::ProcSig { size, .. } => *size,
            TaskKind::Timeout(_) | TaskKind::Io { .. } | TaskKind::DistCmd(_) => 0,
        }
    }

    fn deadline(&self) -> Option<Instant> {
        match &self.kind {
            TaskKind::ProcSig { deadline, .. } => *deadline,
            _ => None,
        }
    }

    fn take_callback(&self) -> Option<SigCallback> {
        match &self.kind {
            TaskKind::ProcSig { callback, .. } | TaskKind::DistCmd(callback) => {
                callback.lock().take()
            }
            TaskKind::Timeout(_) | TaskKind::Io { .. } => None,
        }
    }

    fn claim(&self, to: u32) -> bool {
        self.state
            .compare_exchange(STATE_SCHEDULED, to, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    fn is_scheduled(&self) -> bool {
        self.state.load(Ordering::Acquire) == STATE_SCHEDULED
    }
}

/// `ErtsPortTaskHandle` of a scheduled signal.
pub struct TaskHandle(Arc<PortTask>);

/// Why an immediate driver call was refused (`ErtsTryImmDrvCallResult`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ImmFail {
    /// Another thread holds the port lock.
    BusyLock,
    /// The port is closing or gone.
    InvalidPort,
    /// The scheduling flags (returned) forbid an immediate call.
    InvalidSchedFlags(u32),
}

/// An immediate driver call in progress (`try_imm_drv_call` .. `finalize_imm_drv_call`).
pub struct ImmCall<'a> {
    port: &'a DriverPort,
    _guard: crate::ReentrantGuard<'a>,
    where_: &'static str,
    reds_before: i32,
    /// Scheduling flags read when the call started.
    pub sched_flags: u32,
}

impl Drop for ImmCall<'_> {
    fn drop(&mut self) {
        // Port of erts/emulator/beam/io.c:1022 (finalize_imm_drv_call), OTP-29.1.1.
        let act = self
            .port
            .sched
            .flags
            .fetch_and(!PTS_FLG_EXEC_IMM, Ordering::AcqRel);
        if act & (PTS_FLG_IN_RUNQ | PTS_FLG_EXEC) == 0 {
            self.port.host.profile_runnable_port(self.port, false);
        }
        self.port
            .host
            .trace_sched_port(self.port, false, Some(self.where_));
    }
}

impl ImmCall<'_> {
    /// Reductions added by the driver callback during this immediate call.
    // Port of erts/emulator/beam/io.c:1022-1055 (finalize_imm_drv_call), OTP-29.1.1.
    pub fn reductions_used(&self) -> u32 {
        self.port
            .reds
            .load(Ordering::Acquire)
            .saturating_sub(self.reds_before)
            .max(0) as u32
    }
}

#[derive(Default)]
struct PortTaskQueues {
    incoming: Queue<PortTask>,
    nosuspend: Queue<PortTask>,
    exec: Queue<PortTask>,
    busy: Queue<PortTask>,
    /// `prt->suspended`: processes suspended on the busy port.
    suspended: Vec<u64>,
    /// The busy caller table: tasks per caller in the busy queue.
    callers: Option<Box<BusyCallerTable<PortTask>>>,
    processing_busy: bool,
}

/// `ErtsPortTaskSched` of one port.
#[derive(Default)]
pub(crate) struct PortSched {
    flags: AtomicU32,
    /// `taskq.in`, `taskq.local`, and `prt->suspended`, under `sched.mtx`.
    queues: Mutex<PortTaskQueues>,
    /// `bpq->size`.
    bpq_size: AtomicUsize,
}

impl PortSched {
    fn flags(&self) -> u32 {
        self.flags.load(Ordering::Acquire)
    }

    fn or(&self, bits: u32) -> u32 {
        self.flags.fetch_or(bits, Ordering::AcqRel)
    }

    fn and_not(&self, bits: u32) -> u32 {
        self.flags.fetch_and(!bits, Ordering::AcqRel)
    }

    fn queues(&self) -> MutexGuard<'_, PortTaskQueues> {
        self.queues.lock()
    }
}

// Port of erts/emulator/beam/erl_port_task.c:1576-1598 (enqueue port on run-queue),
// OTP-29.1.1.
fn enqueue_port(port: &Arc<DriverPort>) {
    port.host.enqueue_port(Arc::clone(port));
}

impl DriverPort {
    /// `pp->sched.flags`.
    pub fn sched_flags(&self) -> u32 {
        self.sched.flags()
    }

    /// Set or clear `ERTS_PTS_FLG_PARALLELISM` (`{parallelism, Bool}`).
    pub fn set_parallelism(&self, on: bool) {
        if on {
            self.sched.or(PTS_FLG_PARALLELISM);
        } else {
            self.sched.and_not(PTS_FLG_PARALLELISM);
        }
    }

    fn bpq_enabled(&self) -> bool {
        self.msgq_limits().enabled
    }

    // Port of erts/emulator/beam/erl_port_task.c:646 (check_unset_busy_port_q), OTP-29.1.1.
    fn check_unset_busy_port_q(&self, mut flags: u32) -> u32 {
        let mut resume = Vec::new();
        {
            let mut inq = self.sched.queues();
            let qsize = self.sched.bpq_size.load(Ordering::Acquire);
            let low = self.msgq_limits().low;
            if qsize < low {
                let old = self
                    .sched
                    .and_not(PTS_FLG_CHK_UNSET_BUSY_PORT_Q | PTS_FLG_BUSY_PORT_Q);
                flags = old & !(PTS_FLG_CHK_UNSET_BUSY_PORT_Q | PTS_FLG_BUSY_PORT_Q);
                if old & PTS_FLGS_BUSY == PTS_FLG_BUSY_PORT_Q {
                    resume = std::mem::take(&mut inq.suspended);
                }
            } else if flags & PTS_FLG_CHK_UNSET_BUSY_PORT_Q != 0 {
                flags = self.sched.and_not(PTS_FLG_CHK_UNSET_BUSY_PORT_Q)
                    & !PTS_FLG_CHK_UNSET_BUSY_PORT_Q;
            }
        }
        if !resume.is_empty() {
            self.host.resume_processes(self, resume);
        }
        flags
    }

    // Port of erts/emulator/beam/erl_port_task.c:679 (aborted_proc2port_data), OTP-29.1.1.
    fn aborted_proc2port_data(&self, size: usize) {
        if size == 0 || !self.bpq_enabled() {
            return;
        }
        let qsz = self
            .sched
            .bpq_size
            .fetch_sub(size, Ordering::AcqRel)
            .saturating_sub(size);
        let flags = self.sched.flags();
        if flags & (PTS_FLG_CHK_UNSET_BUSY_PORT_Q | PTS_FLG_BUSY_PORT_Q) != PTS_FLG_BUSY_PORT_Q {
            return;
        }
        if qsz < self.msgq_limits().low {
            self.sched.or(PTS_FLG_CHK_UNSET_BUSY_PORT_Q);
        }
    }

    // Port of erts/emulator/beam/erl_port_task.c:706 (dequeued_proc2port_data), OTP-29.1.1.
    fn dequeued_proc2port_data(&self, size: usize) {
        if size == 0 || !self.bpq_enabled() {
            return;
        }
        let qsz = self
            .sched
            .bpq_size
            .fetch_sub(size, Ordering::AcqRel)
            .saturating_sub(size);
        let flags = self.sched.flags();
        if flags & PTS_FLG_BUSY_PORT_Q == 0 {
            return;
        }
        if qsz < self.msgq_limits().low {
            self.check_unset_busy_port_q(flags);
        }
    }

    // Port of erts/emulator/beam/erl_port_task.c:730 (enqueue_proc2port_data), OTP-29.1.1.
    fn enqueue_proc2port_data(&self, size: usize, mut flags: u32) -> u32 {
        if size == 0 || !self.bpq_enabled() {
            return flags;
        }
        let qsz = self.sched.bpq_size.fetch_add(size, Ordering::AcqRel) + size;
        let limits = self.msgq_limits();
        if flags & PTS_FLG_BUSY_PORT_Q == 0 && qsz > limits.high {
            flags = self.sched.or(PTS_FLG_BUSY_PORT_Q) | PTS_FLG_BUSY_PORT_Q;
            if self.sched.bpq_size.load(Ordering::Acquire) < limits.low {
                flags =
                    self.sched.or(PTS_FLG_CHK_UNSET_BUSY_PORT_Q) | PTS_FLG_CHK_UNSET_BUSY_PORT_Q;
            }
        }
        flags
    }

    /// Busy port message queue limits were written: re-evaluate `BUSY_PORT_Q`
    /// (the tail of erl_port_task.c:772 erl_drv_busy_msgq_limits).
    pub(crate) fn bpq_limits_written(&self, low: usize, high: usize) {
        let _inq = self.sched.queues();
        let size = self.sched.bpq_size.load(Ordering::Acquire);
        if size > high {
            self.sched.or(PTS_FLG_BUSY_PORT_Q);
        } else if size < low {
            self.sched.or(PTS_FLG_CHK_UNSET_BUSY_PORT_Q);
        }
    }

    /// The busy port message queue was disabled (erl_port_task.c:791).
    pub(crate) fn bpq_disabled(&self) {
        let resume = {
            let mut inq = self.sched.queues();
            let old = self
                .sched
                .and_not(PTS_FLG_BUSY_PORT_Q | PTS_FLG_CHK_UNSET_BUSY_PORT_Q);
            if old & PTS_FLGS_BUSY == PTS_FLG_BUSY_PORT_Q {
                std::mem::take(&mut inq.suspended)
            } else {
                Vec::new()
            }
        };
        if !resume.is_empty() {
            self.host.resume_processes(self, resume);
        }
    }

    fn abort_signal_task(&self, task: &PortTask, op: SigOp, bpq_data: bool) {
        if let Some(callback) = task.take_callback() {
            callback(op);
        }
        if bpq_data {
            self.aborted_proc2port_data(task.size());
        }
    }

    // Port of erts/emulator/beam/erl_port_task.c:990 (enqueue_task), OTP-29.1.1.
    fn enqueue_task(&self, task: &Arc<PortTask>, nosuspend: bool) -> Result<u32, u32> {
        let mut fail = PTS_FLG_EXIT;
        if nosuspend {
            fail |= PTS_FLG_BUSY_PORT;
        }
        let mut inq = self.sched.queues();
        let flags = self.sched.flags();
        if flags & fail != 0 {
            return Err(flags);
        }
        if nosuspend {
            inq.nosuspend.push_back(task, &task.nosuspend_link);
            self.sched.or(PTS_FLG_HAVE_NS_TASKS);
        }
        inq.incoming.push_back(task, &task.queue_link);
        Ok(self.enqueue_proc2port_data(task.size(), flags))
    }

    /// Port of erts/emulator/beam/erl_port_task.c:1451 (erts_port_task_schedule) for a
    /// process to port signal. `None` when the port did not accept it; the callback has
    /// then run in abort mode.
    pub fn schedule_signal(self: &Arc<Self>, sig: ProcSig) -> Option<TaskHandle> {
        let task = Arc::new(PortTask {
            state: AtomicU32::new(STATE_SCHEDULED),
            flags: PT_FLG_SIG_DEP | sig.flags,
            kind: TaskKind::ProcSig {
                caller: sig.caller,
                size: sig.size,
                deadline: sig.deadline,
                callback: Mutex::new(Some(sig.callback)),
            },
            queue_link: Link::default(),
            nosuspend_link: Link::default(),
        });
        let nosuspend = task.flags & PT_FLG_NOSUSPEND != 0;
        match self.enqueue_task(&task, nosuspend) {
            Ok(act) => {
                self.activate(act);
                Some(TaskHandle(task))
            }
            Err(act) => {
                task.state.store(STATE_ABORTED, Ordering::Release);
                let op = if nosuspend && act & PTS_FLG_EXIT == 0 {
                    SigOp::AbortNosuspend
                } else {
                    SigOp::Abort
                };
                self.abort_signal_task(&task, op, false);
                None
            }
        }
    }

    /// The earliest deadline among queued port tasks.
    pub fn next_task_deadline(&self) -> Option<Instant> {
        let queues = self.sched.queues();
        let mut next = None;
        for queue in [&queues.incoming, &queues.exec, &queues.busy] {
            queue.for_each(|task| {
                if let Some(deadline) = task.deadline() {
                    next = Some(next.map_or(deadline, |current: Instant| current.min(deadline)));
                }
            });
        }
        next
    }

    /// Whether a task that waits for the port to become unbusy remains queued.
    pub fn has_busy_wait_tasks(&self) -> bool {
        let queues = self.sched.queues();
        let mut found = false;
        for queue in [&queues.incoming, &queues.exec, &queues.busy] {
            queue.for_each(|task| found |= task.flags & PT_FLG_WAIT_BUSY != 0);
        }
        found
    }

    /// Abort timed tasks whose deadline passed, preserving order in both scheduler queues.
    pub fn expire_task_deadlines(&self, now: Instant) -> usize {
        let mut expired = Vec::new();
        {
            let mut queues = self.sched.queues();
            expired.extend(queues.incoming.take_matching(
                |task| &task.queue_link,
                |task| task.deadline().is_some_and(|deadline| deadline <= now),
            ));
            let busy_expired = queues.busy.take_matching(
                |task| &task.queue_link,
                |task| task.deadline().is_some_and(|deadline| deadline <= now),
            );
            let PortTaskQueues {
                busy,
                callers: caller_table,
                ..
            } = &mut *queues;
            if let Some(callers) = caller_table.as_mut() {
                for task in &busy_expired {
                    callers.remove(task.caller());
                }
                busy.for_each(|task| callers.set_last(task.caller(), &task.queue_link));
            }
            expired.extend(busy_expired);
            if queues.busy.is_empty() {
                debug_assert!(queues.callers.as_ref().is_none_or(|table| table.is_empty()));
                queues.callers = None;
                self.sched.and_not(PTS_FLG_HAVE_BUSY_TASKS);
            }
            if queues.incoming.is_empty() && queues.exec.is_empty() {
                self.sched.and_not(PTS_FLG_HAVE_TASKS);
            }
        }
        let count = expired.len();
        let bpq = self.bpq_enabled();
        for task in expired {
            if task.claim(STATE_ABORTED) {
                self.abort_signal_task(&task, SigOp::Abort, bpq);
            }
        }
        count
    }

    /// Queue a distribution command task (`ERTS_PORT_TASK_DIST_CMD`, dist.c
    /// erts_schedule_dist_command). The callback runs with the port locked on a scheduler;
    /// it is called in an abort mode when the port closes first.
    pub fn schedule_dist_cmd(self: &Arc<Self>, callback: SigCallback) {
        let task = Arc::new(PortTask {
            state: AtomicU32::new(STATE_SCHEDULED),
            flags: 0,
            kind: TaskKind::DistCmd(Mutex::new(Some(callback))),
            queue_link: Link::default(),
            nosuspend_link: Link::default(),
        });
        match self.enqueue_task(&task, false) {
            Ok(act) => self.activate(act),
            Err(_) => {
                task.state.store(STATE_ABORTED, Ordering::Release);
                self.abort_signal_task(&task, SigOp::Abort, false);
            }
        }
    }

    /// Queue a timeout task (`ERTS_PORT_TASK_TIMEOUT`).
    pub(crate) fn schedule_timeout(self: &Arc<Self>, epoch: u64) {
        let task = Arc::new(PortTask {
            state: AtomicU32::new(STATE_SCHEDULED),
            flags: 0,
            kind: TaskKind::Timeout(epoch),
            queue_link: Link::default(),
            nosuspend_link: Link::default(),
        });
        if let Ok(act) = self.enqueue_task(&task, false) {
            self.activate(act);
        }
    }

    /// Queue an I/O task for a fired poll registration (`ERTS_PORT_TASK_INPUT` or
    /// `ERTS_PORT_TASK_OUTPUT`, erl_check_io.c:2102 iready/oready). `false` when the port
    /// accepts no more tasks.
    pub(crate) fn schedule_io(self: &Arc<Self>, fd: i32, dir: usize, reg: u64) -> bool {
        OUTSTANDING_IO_TASKS.fetch_add(1, Ordering::AcqRel);
        let task = Arc::new(PortTask {
            state: AtomicU32::new(STATE_SCHEDULED),
            flags: 0,
            kind: TaskKind::Io { fd, dir, reg },
            queue_link: Link::default(),
            nosuspend_link: Link::default(),
        });
        match self.enqueue_task(&task, false) {
            Ok(act) => {
                self.activate(act);
                true
            }
            Err(_) => false,
        }
    }

    // erl_port_task.c:1561-1609: mark the port as having tasks and put it in the run
    // queue unless it is queued or executing already.
    fn activate(self: &Arc<Self>, mut act: u32) {
        let add = PTS_FLG_HAVE_TASKS;
        loop {
            if act & add == add && act & (PTS_FLG_IN_RUNQ | PTS_FLG_EXEC) != 0 {
                return;
            }
            let mut new = act | add;
            if act & (PTS_FLG_IN_RUNQ | PTS_FLG_EXEC) == 0 {
                new |= PTS_FLG_IN_RUNQ;
            }
            match self
                .sched
                .flags
                .compare_exchange(act, new, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => {
                    if act & (PTS_FLG_IN_RUNQ | PTS_FLG_EXEC) != 0 {
                        return;
                    }
                    break;
                }
                Err(current) => {
                    act = current;
                    if act & PTS_FLG_EXIT != 0 {
                        return;
                    }
                }
            }
        }
        if act & PTS_FLG_EXEC_IMM == 0 {
            self.host.profile_runnable_port(self, true);
        }
        enqueue_port(self);
    }

    /// Port of erts/emulator/beam/erl_port_task.c:1310 (erts_port_task_abort): `true`
    /// when the task was still scheduled and is now aborted.
    pub fn abort_task(&self, handle: &TaskHandle) -> bool {
        let task = &handle.0;
        if !task.claim(STATE_ABORTED) {
            return false;
        }
        let op = if task.flags & (PT_FLG_NOSUSPEND | PT_FLG_ASYNC_NOSUSPEND) != 0 {
            SigOp::AbortNosuspend
        } else {
            SigOp::Abort
        };
        self.abort_signal_task(task, op, self.bpq_enabled());
        true
    }

    // Port of erts/emulator/beam/erl_port_task.c:1375 (erts_port_task_abort_nosuspend_tasks),
    // OTP-29.1.1.
    fn abort_nosuspend_tasks(&self) {
        let mut list = {
            let mut inq = self.sched.queues();
            self.sched.and_not(PTS_FLG_HAVE_NS_TASKS);
            std::mem::take(&mut inq.nosuspend)
        };
        let bpq = self.bpq_enabled();
        while let Some(task) = list.pop_front() {
            if task.claim(STATE_ABORTED) {
                self.abort_signal_task(&task, SigOp::AbortNosuspend, bpq);
            }
        }
    }

    /// Port of erts/emulator/beam/io.c:5203 (set_busy_port).
    pub fn set_busy_port(&self, on: bool) {
        if on {
            let flags = self.sched.or(PTS_FLG_BUSY_PORT);
            if flags & PTS_FLG_BUSY_PORT != 0 {
                return;
            }
            if flags & PTS_FLG_HAVE_NS_TASKS != 0 {
                self.abort_nosuspend_tasks();
            }
            self.host.set_busy(self, true);
        } else {
            let flags = self.sched.and_not(PTS_FLG_BUSY_PORT);
            if flags & PTS_FLG_BUSY_PORT == 0 {
                return;
            }
            self.host.set_busy(self, false);
            if flags & PTS_FLG_BUSY_PORT_Q == 0 {
                self.resume_procs();
            }
        }
    }

    /// Port of erts/emulator/beam/io.c:5261 (erts_port_resume_procs).
    fn resume_procs(&self) {
        let list = std::mem::take(&mut self.sched.queues().suspended);
        if !list.is_empty() {
            self.host.resume_processes(self, list);
        }
    }

    /// Port of erts/emulator/beam/io.c:519 (erts_save_suspend_process_on_port): queue
    /// process `pid` for resumption; `false` when the port is no longer busy.
    pub fn save_suspend_process(&self, pid: u64) -> bool {
        let mut inq = self.sched.queues();
        let flags = self.sched.flags();
        let saved = flags & PTS_FLGS_BUSY != 0 && flags & PTS_FLG_EXIT == 0;
        if saved {
            inq.suspended.push(pid);
        }
        saved
    }

    /// Port of erts/emulator/beam/io.c:923 (try_imm_drv_call): lock the port for a driver
    /// call on the caller's thread. `invalid_flags` are the scheduling flags that force
    /// the operation to be scheduled; `asynchronous` adds `PARALLELISM`.
    pub fn try_imm_call(
        &self,
        invalid_flags: u32,
        asynchronous: bool,
        where_: &'static str,
        reductions_left: u32,
    ) -> Result<ImmCall<'_>, ImmFail> {
        let mut invalid = PTS_FLGS_FORCE_SCHEDULE_OP | invalid_flags;
        if asynchronous {
            invalid |= PTS_FLG_PARALLELISM;
        }
        let lock = self
            .lock
            .as_deref()
            .or(self.driver.lock.as_ref())
            .expect("port or driver lock");
        let Some(guard) = lock.try_lock() else {
            return Err(ImmFail::BusyLock);
        };
        if !self.live() {
            return Err(ImmFail::InvalidPort);
        }
        let mut act = self.sched.flags();
        loop {
            if act & invalid != 0 {
                return Err(ImmFail::InvalidSchedFlags(act));
            }
            match self.sched.flags.compare_exchange(
                act,
                act | PTS_FLG_EXEC_IMM,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(current) => act = current,
            }
        }
        if act & (PTS_FLG_IN_RUNQ | PTS_FLG_EXEC) == 0 {
            self.host.profile_runnable_port(self, true);
        }
        let reds_before = CONTEXT_REDS.saturating_sub(reductions_left as i32);
        self.reds.store(reds_before, Ordering::Release);
        self.host.trace_sched_port(self, true, Some(where_));
        Ok(ImmCall {
            port: self,
            _guard: guard,
            where_,
            reds_before,
            sched_flags: act,
        })
    }

    /// Port of erts/emulator/beam/erl_port_task.c:1643 (erts_port_task_free_port): the
    /// port terminated; abort its tasks unless a scheduler executing the port does that.
    pub(crate) fn sched_free(&self) {
        let flags = {
            let _inq = self.sched.queues();
            self.sched.or(PTS_FLG_EXIT)
        };
        if flags & (PTS_FLG_IN_RUNQ | PTS_FLG_EXEC) == 0 {
            self.begin_port_cleanup();
        }
    }

    // Port of erts/emulator/beam/erl_port_task.c:1937 (begin_port_cleanup), OTP-29.1.1.
    fn begin_port_cleanup(&self) {
        let mut tasks: Vec<Arc<PortTask>> = Vec::new();
        {
            let mut local = self.sched.queues();
            // Busy queue, local queue, in queue: signal order.
            while let Some(task) = local.busy.pop_front() {
                tasks.push(task);
            }
            while let Some(task) = local.exec.pop_front() {
                tasks.push(task);
            }
            while let Some(task) = local.incoming.pop_front() {
                tasks.push(task);
            }
            local.callers = None;
            local.processing_busy = false;
            local
                .nosuspend
                .retain(|task| &task.nosuspend_link, |_| false);
        }
        let bpq = self.bpq_enabled();
        for task in &tasks {
            if task.claim(STATE_EXECUTING)
                && matches!(task.kind, TaskKind::ProcSig { .. } | TaskKind::DistCmd(_))
            {
                self.abort_signal_task(task, SigOp::AbortClosed, bpq);
            }
        }
        self.sched
            .and_not(PTS_FLG_HAVE_BUSY_TASKS | PTS_FLG_HAVE_TASKS | PTS_FLGS_BUSY);
        let suspended = std::mem::take(&mut self.sched.queues().suspended);
        if !suspended.is_empty() {
            self.host.resume_processes(self, suspended);
        }
    }
}

// Port of erts/emulator/beam/erl_port_task.c:258 (popped_from_busy_queue), OTP-29.1.1.
fn popped_from_busy_queue(port: &DriverPort, local: &mut PortTaskQueues, task: &PortTask) {
    let caller = task.caller();
    local
        .callers
        .as_mut()
        .expect("busy caller table")
        .remove(caller);
    if local.busy.is_empty() {
        debug_assert!(local.callers.as_ref().is_none_or(|table| table.is_empty()));
        local.callers = None;
        port.sched.and_not(PTS_FLG_HAVE_BUSY_TASKS);
    }
}

// Port of erts/emulator/beam/erl_port_task.c:308 (busy_wait_move_to_busy_queue), OTP-29.1.1.
fn busy_wait_move_to_busy_queue(
    port: &DriverPort,
    local: &mut PortTaskQueues,
    task: Arc<PortTask>,
) {
    if local.busy.is_empty() {
        port.sched.or(PTS_FLG_HAVE_BUSY_TASKS);
        local.callers = Some(Box::default());
    }
    local
        .callers
        .as_mut()
        .expect("busy caller table")
        .add(task.caller(), &task.queue_link);
    local.busy.push_back_owned(task, |task| &task.queue_link);
}

// Port of erts/emulator/beam/erl_port_task.c:376 (check_sig_dep_move_to_busy_queue): the
// task follows the caller's last task in the busy queue. `Err` gives the task back.
fn check_sig_dep_move_to_busy_queue(
    local: &mut PortTaskQueues,
    task: Arc<PortTask>,
) -> Result<(), Arc<PortTask>> {
    let caller = task.caller();
    let Some(previous) = local
        .callers
        .as_ref()
        .and_then(|callers| callers.last_link(caller))
    else {
        return Err(task);
    };
    local
        .callers
        .as_mut()
        .expect("busy caller table")
        .add(caller, &task.queue_link);
    local
        .busy
        .insert_after_link(task, |task| &task.queue_link, previous);
    Ok(())
}

// Port of erts/emulator/beam/erl_port_task.c:423 (no_sig_dep_move_from_busyq), OTP-29.1.1.
fn no_sig_dep_move_from_busyq(port: &DriverPort, local: &mut PortTaskQueues) {
    let (busy, exec, callers) = (&mut local.busy, &mut local.exec, &mut local.callers);
    busy.move_prefix_to_front(
        exec,
        |task| task.flags & PT_FLG_WAIT_BUSY == 0,
        |task| {
            callers
                .as_mut()
                .expect("busy caller table")
                .remove(task.caller())
        },
    );
    if busy.is_empty() {
        *callers = None;
        port.sched.and_not(PTS_FLG_HAVE_BUSY_TASKS);
    }
}

// Port of erts/emulator/beam/erl_port_task.c:1035 (prepare_exec), OTP-29.1.1.
fn prepare_exec(port: &DriverPort) {
    let act = port.sched.flags();
    {
        let mut local = port.sched.queues();
        local.processing_busy = !(local.busy.is_empty() || act & PTS_FLG_BUSY_PORT != 0);
    }
    let mut act = act;
    loop {
        let new = (act & !PTS_FLG_IN_RUNQ) | PTS_FLG_EXEC;
        match port
            .sched
            .flags
            .compare_exchange(act, new, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) => break,
            Err(current) => act = current,
        }
    }
}

// Port of erts/emulator/beam/erl_port_task.c:1069 (finalize_exec): `true` when the port
// must stay in the run queue.
fn finalize_exec(port: &DriverPort) -> bool {
    let mut act = port.sched.flags();
    if act & PTS_FLG_CHK_UNSET_BUSY_PORT_Q != 0 {
        act = port.check_unset_busy_port_q(act);
    }
    loop {
        let mut new = act & !PTS_FLG_EXEC;
        if act & PTS_FLG_HAVE_TASKS != 0 {
            new |= PTS_FLG_IN_RUNQ;
        }
        match port
            .sched
            .flags
            .compare_exchange(act, new, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) => break,
            Err(current) => act = current,
        }
    }
    port.host.trace_sched_port(port, false, None);
    if act & (PTS_FLG_EXEC_IMM | PTS_FLG_HAVE_TASKS) == 0 {
        port.host.profile_runnable_port(port, false);
    }
    act & PTS_FLG_HAVE_TASKS != 0
}

// Port of erts/emulator/beam/erl_port_task.c:1126 (select_queue_for_exec), OTP-29.1.1.
fn select_queue_for_exec(port: &DriverPort, local: &mut PortTaskQueues, flags: u32) -> u32 {
    if flags & PTS_FLG_BUSY_PORT != 0 {
        if local.processing_busy {
            if local
                .busy
                .front_matches(|task| task.flags & PT_FLG_WAIT_BUSY == 0)
            {
                no_sig_dep_move_from_busyq(port, local);
            }
            local.processing_busy = false;
        }
        return flags;
    }
    if !local.processing_busy && !local.busy.is_empty() {
        local.processing_busy = true;
    }
    flags
}

// Port of erts/emulator/beam/erl_port_task.c:1172 (check_task_for_exec), OTP-29.1.1.
// `Some` is the task to execute.
fn check_task_for_exec(
    port: &DriverPort,
    flags: u32,
    local: &mut PortTaskQueues,
    task: Arc<PortTask>,
) -> Option<Arc<PortTask>> {
    if !local.processing_busy {
        if flags & PTS_FLG_BUSY_PORT != 0 && task.flags & PT_FLG_WAIT_BUSY != 0 {
            busy_wait_move_to_busy_queue(port, local, task);
            return None;
        }
        if !local.busy.is_empty() && task.flags & PT_FLG_SIG_DEP != 0 {
            return check_sig_dep_move_to_busy_queue(local, task).err();
        }
    } else {
        popped_from_busy_queue(port, local, &task);
        if local.busy.is_empty() {
            local.processing_busy = false;
        }
    }
    Some(task)
}

// Port of erts/emulator/beam/erl_port_task.c:1225 (fetch_in_queue), OTP-29.1.1.
fn fetch_in_queue(port: &DriverPort, local: &mut PortTaskQueues) -> Option<Arc<PortTask>> {
    let task = local.incoming.pop_front();
    if task.is_some() {
        local.incoming.append_to(&mut local.exec);
    } else {
        port.sched.and_not(PTS_FLG_HAVE_TASKS);
    }
    if !local.nosuspend.is_empty() {
        local
            .nosuspend
            .retain(|task| &task.nosuspend_link, |task| task.is_scheduled());
        if local.nosuspend.is_empty() {
            port.sched.and_not(PTS_FLG_HAVE_NS_TASKS);
        }
    }
    task
}

// Port of erts/emulator/beam/erl_port_task.c:1254 (select_task_for_exec), OTP-29.1.1.
fn select_task_for_exec(port: &DriverPort) -> Option<Arc<PortTask>> {
    let mut flags = port.sched.flags();
    if flags & PTS_FLG_CHK_UNSET_BUSY_PORT_Q != 0 {
        flags = port.check_unset_busy_port_q(flags);
    }
    let mut local = port.sched.queues();
    let flags = select_queue_for_exec(port, &mut local, flags);
    loop {
        let next = if local.processing_busy {
            local.busy.pop_front()
        } else {
            local.exec.pop_front()
        };
        let task = match next {
            Some(task) => task,
            None => fetch_in_queue(port, &mut local)?,
        };
        if let Some(task) = check_task_for_exec(port, flags, &mut local, task) {
            return Some(task);
        }
    }
}

impl RunPort for DriverPort {
    fn run_queue(&self) -> &PortRunQueue {
        &self.run_queue
    }

    fn execute(&self) -> PortExecution {
        execute(self)
    }
}

/// Port of erts/emulator/beam/erl_port_task.c:1677 (erts_port_task_execute): run the
/// port's tasks until it runs out of tasks or reductions. The scheduler re-enqueues the
/// port when it is still active and accounts the returned reductions.
fn execute(port: &DriverPort) -> PortExecution {
    prepare_exec(port);
    let guard = port.guard();
    port.host.trace_sched_port(port, true, None);
    // erl_port_task.c:1730-1735: ERTS_PORT_REDS_EXECUTE, then the virtual reductions of
    // `begin_handle_tasks` before the first task.
    port.reds
        .store(REDS_EXECUTE + CALLBACK_VREDS, Ordering::Release);
    let mut vreds = CALLBACK_VREDS;
    let mut exited = port.sched.flags() & PTS_FLG_EXIT != 0;
    if exited {
        port.begin_port_cleanup();
    }
    while !exited {
        let Some(task) = select_task_for_exec(port) else {
            break;
        };
        if !task.claim(STATE_EXECUTING) {
            continue;
        }
        let started = std::time::Instant::now();
        let (reds, op) = match &task.kind {
            TaskKind::Timeout(epoch) => (port.run_timeout_task(*epoch), Some("timeout")),
            // The I/O callback reports its own long schedule (select.rs run_io).
            TaskKind::Io { fd, dir, reg } => (crate::select::ready(port, *fd, *dir, *reg), None),
            TaskKind::DistCmd(_) => {
                let reds = task
                    .take_callback()
                    .map_or(0, |callback| callback(SigOp::Exec));
                (reds, Some("dist_cmd"))
            }
            TaskKind::ProcSig { size, .. } => {
                let reds = task
                    .take_callback()
                    .map_or(0, |callback| callback(SigOp::Exec));
                port.dequeued_proc2port_data(*size);
                (reds, Some("proc_sig"))
            }
        };
        if let Some(op) = op {
            port.host
                .task_done(port, op, started.elapsed().as_nanos() as u64);
        }
        if port.sched.flags() & PTS_FLG_EXIT != 0 {
            // erl_port_task.c:1845-1850: the freed port's task reductions are not added.
            port.begin_port_cleanup();
            exited = true;
            continue;
        }
        vreds += CALLBACK_VREDS;
        let used = reds + CALLBACK_VREDS;
        if port.reds.fetch_add(used, Ordering::AcqRel) + used >= CONTEXT_REDS {
            break;
        }
    }
    let active = finalize_exec(port);
    let reds = port.reds.load(Ordering::Acquire) - vreds;
    drop(guard);
    PortExecution { active, reds }
}

#[cfg(test)]
mod layout_tests {
    #[test]
    fn reports_port_task_layout() {
        eprintln!(
            "PortSched={} PortTaskQueues={}",
            std::mem::size_of::<super::PortSched>(),
            std::mem::size_of::<super::PortTaskQueues>(),
        );
    }
}
