//! VM-independent process scheduling and ordered signal delivery.
//!
//! A VM process implements [`Task`]. Its heap and registers remain inside the
//! task; the scheduler only owns an opaque message envelope and typed signals.
//! Process-table lookups index lazily allocated pages and clone an epoch-protected
//! `Arc`; only slot allocation and reuse take a lock. A generation increment
//! prevents a recycled slot from resolving an old pid. Producers publish both
//! messages and signals through one MPSC head. Worker-local slabs batch events
//! by recipient; the receiver splices them into its inner queue.
//! Sends from one logical process must be serialized to preserve sender order.
//!
//! The real scheduler gives each worker a run queue (a Chase-Lev deque fed by a
//! queue for submissions from other threads) and steals from other run queues when idle.
//! The simulator uses the same task and mailbox protocol with seeded dispatch and
//! an injected virtual clock. [`RunCtx::consume`] lets the VM account for
//! reductions; a task returning [`RunOutcome::Yield`] receives a fresh budget.
//!
//! Wake protocol: a process is QUEUED, RUNNING, WAITING, or EXITED. A sender
//! publishes its mailbox node before attempting WAITING -> QUEUED; only the
//! successful claimant enqueues it. A RUNNING receiver stores WAITING, probes
//! the mailbox, and claims WAITING -> QUEUED if input arrived. Mailbox publish
//! and probe, the WAITING store, and the sender's claim are SeqCst. Thus a
//! sender that misses WAITING must have published before the receiver's probe;
//! a receiver that misses the message leaves WAITING visible to the sender.
//! The queue itself transfers message ownership with release/acquire ordering.
//!
//! Placement follows erts: a woken process joins the run queue it last ran on and only
//! that run queue's scheduler is woken, if it sleeps; a busy run queue wakes one more
//! scheduler through the wakeup-other check. Worker parking has a second handoff: an
//! enqueue publishes to the run queue, advances a SeqCst work epoch, and unparks the
//! target if it advertised parking. A worker reads the epoch, advertises parking with a
//! SeqCst store, then checks its run queue and the epoch again before parking. Either it
//! finds work or the enqueuer sees its parked flag. `thread::unpark` retains a
//! permit if it precedes `thread::park`.
//!
//! ```
//! use arinsal_sched::{Config, RunCtx, RunOutcome, Scheduler, Task};
//!
//! struct Echo;
//! impl Task for Echo {
//!     type Message = u64; // Replace with a VM heap-fragment envelope.
//!     type SchedulerData = ();
//!     fn run(&mut self, ctx: &mut RunCtx<Self::Message>, _: &mut (), _budget: u32) -> RunOutcome {
//!         if let Some(event) = ctx.receive() {
//!             if let arinsal_sched::Payload::Message(value) = event.payload {
//!                 let _ = ctx.send(event.from, value);
//!             }
//!         }
//!         RunOutcome::Wait { timeout_ms: None }
//!     }
//! }
//! let sched = Scheduler::<Echo>::simulation(Config::default(), 7);
//! let pid = sched.spawn(Echo).unwrap();
//! sched.send(pid, pid, 42).unwrap();
//! sched.step();
//! let timer = sched.start_timer(pid, 10, 99).unwrap();
//! assert_eq!(sched.read_timer(timer), Some(10));
//! sched.advance_ms(10);
//! ```

mod balance;
mod mailbox;
mod ports;
mod proc_ref;
mod sig_queue;
mod thr_progress;
mod timer;

pub use mailbox::{InSignal, Incoming, psflg};
pub use ports::{PortExecution, PortRunQueue, RunPort};
pub use sig_queue::{MessageQueueList, OwnedSignal, SignalQueue};
pub use timer::{TimerId, TimerRef};

use arinsal_term::ptab::{PTAB_ID_DATA_MASK, PtabIdRing};
use crossbeam_deque::{Steal, Stealer, Worker};
use crossbeam_queue::SegQueue;
pub use proc_ref::SignalProbe;
use proc_ref::{ErasedProcRef, ProcRef, TaskCell};
use std::any::Any;
use std::cell::RefCell;
use std::collections::VecDeque;
use std::fmt;
use std::rc::Rc;
use std::sync::atomic::{
    AtomicBool, AtomicI32, AtomicPtr, AtomicU8, AtomicU32, AtomicU64, AtomicUsize, Ordering,
};
use std::sync::mpsc;
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
use timer::{CanceledTimer, LinkEvent, TimerCommand, TimerPayload, Wheel};

/// The scheduler pollset of `erl_check_io.c` (`ERTS_POLL_USE_SCHEDULER_POLLING`): frequently
/// re-enabled read descriptors are polled by the schedulers themselves.
pub trait SchedPoll: Send + Sync + 'static {
    /// `erts_sched_poll_enabled`.
    fn enabled(&self) -> bool;
    /// `erts_check_io(ssi->psi, timeout)` on the scheduler pollset: handle ready descriptors
    /// (they schedule their port tasks), waiting up to `timeout` (`None` waits for an
    /// interrupt or an event).
    fn poll(&self, timeout: Option<Duration>);
    /// `erts_check_io_interrupt`.
    fn interrupt(&self);
    /// `erts_port_task_have_outstanding_io_tasks`.
    fn have_outstanding_io(&self) -> bool;
}

/// `ERTS_CONTEXT_REDS`.
const CONTEXT_REDS_SYS: u32 = 4000;

static SCHED_POLL: OnceLock<Arc<dyn SchedPoll>> = OnceLock::new();
/// `doing_sys_schedule`: one scheduler at a time owns the scheduler pollset.
static DOING_SYS_SCHEDULE: AtomicBool = AtomicBool::new(false);
/// `function_calls`: reductions since the last system-level check.
static FUNCTION_CALLS: AtomicU32 = AtomicU32::new(0);

/// The scheduler thread asleep in the scheduler pollset, for wakers that only know the thread
/// (`ssi_wake` of a managed thread, thread progress).
static POLL_SLEEPER: Mutex<Option<thread::ThreadId>> = Mutex::new(None);
static POLL_SLEEPER_SET: AtomicBool = AtomicBool::new(false);

/// Interrupt the scheduler pollset when `thread` is the scheduler sleeping in it.
// Port of erts/emulator/beam/erl_process.c (ssi_wake: ERTS_SSI_FLG_POLL_SLEEPING), OTP-29.1.1.
pub(crate) fn interrupt_if_poll_sleeper(thread: &thread::Thread) {
    if POLL_SLEEPER_SET.load(Ordering::SeqCst)
        && *POLL_SLEEPER.lock().unwrap() == Some(thread.id())
        && let Some(poll) = SCHED_POLL.get()
    {
        poll.interrupt();
    }
}

/// Install the scheduler pollset.
pub fn set_sched_poll(poll: Arc<dyn SchedPoll>) {
    let _ = SCHED_POLL.set(poll);
}

fn sched_poll() -> Option<&'static Arc<dyn SchedPoll>> {
    SCHED_POLL.get().filter(|poll| poll.enabled())
}

/// Port of erts/emulator/beam/erl_process.c (prepare_for_sys_schedule, try_set_sys_scheduling),
/// OTP-29.1.1: claim the scheduler pollset unless an I/O task already waits for a scheduler.
fn prepare_for_sys_schedule(poll: &Arc<dyn SchedPoll>) -> bool {
    while !poll.have_outstanding_io()
        && DOING_SYS_SCHEDULE
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    {
        if !poll.have_outstanding_io() {
            return true;
        }
        clear_sys_scheduling();
    }
    false
}

fn clear_sys_scheduling() {
    FUNCTION_CALLS.store(0, Ordering::Release);
    DOING_SYS_SCHEDULE.store(false, Ordering::SeqCst);
}

type ErasedTimerService = (usize, Box<dyn Any>);

/// The timer service of each scheduler this thread owns, by scheduler set. A thread owns one
/// in practice, so a scan of a few entries beats hashing; erts reaches the service straight
/// from `esdp`.
struct OwnerServices(Vec<(usize, ErasedTimerService)>);

impl OwnerServices {
    fn get(&self, inner_id: &usize) -> Option<&ErasedTimerService> {
        self.0
            .iter()
            .find(|(id, _)| id == inner_id)
            .map(|(_, service)| service)
    }

    fn insert(&mut self, inner_id: usize, service: ErasedTimerService) {
        self.remove(&inner_id);
        self.0.push((inner_id, service));
    }

    fn remove(&mut self, inner_id: &usize) {
        self.0.retain(|(id, _)| id != inner_id);
    }
}
type SchedulerAuxWork = Arc<dyn Fn(usize) + Send + Sync + 'static>;

thread_local! {
    static OWNER_TIMER_SERVICES: RefCell<OwnerServices> = const { RefCell::new(OwnerServices(Vec::new())) };
}

const QUEUED: u8 = 0;
/// Receive timeout armed on this worker, not yet inserted in the timer wheel.
const WAIT_TIMER_DEFERRED: u64 = u64::MAX;
const RUNNING: u8 = 1;
const WAITING: u8 = 2;
const EXITED: u8 = 3;
const UNSCHEDULED: u8 = 4;

/// The `ERTS_PSFLG_*` bits that hold the scheduler's run state.
const RUN_STATE_MASK: u32 = psflg::ACTIVE | psflg::IN_RUNQ | psflg::RUNNING | psflg::FREE;

/// The state word bits of each run state: `QUEUED` is active in a run queue, `RUNNING`
/// active and executing, `WAITING` inactive, `EXITED` free, and `UNSCHEDULED` (created,
/// not yet published) active outside any run queue.
// Port of erts/emulator/beam/erl_process.h:1231-1340 (ERTS_PSFLG_ACTIVE, ERTS_PSFLG_IN_RUNQ,
// ERTS_PSFLG_RUNNING, ERTS_PSFLG_FREE), OTP-29.1.1.
const fn run_state_bits(state: u8) -> u32 {
    match state {
        QUEUED => psflg::ACTIVE | psflg::IN_RUNQ,
        RUNNING => psflg::ACTIVE | psflg::RUNNING,
        EXITED => psflg::FREE,
        UNSCHEDULED => psflg::ACTIVE,
        _ => 0,
    }
}

const fn run_state_of(word: u32) -> u8 {
    if word & psflg::FREE != 0 {
        EXITED
    } else if word & psflg::RUNNING != 0 {
        RUNNING
    } else if word & psflg::IN_RUNQ != 0 {
        QUEUED
    } else if word & psflg::ACTIVE != 0 {
        UNSCHEDULED
    } else {
        WAITING
    }
}

/// The run state view of the process state word. Every change is a read-modify-write of
/// the whole word, so the signal-queue bits set concurrently by senders are kept.
// Port of erts/emulator/beam/erl_process.c:6899 (change_proc_schedule_state: a cmpxchg
// loop over `p->state`), OTP-29.1.1.
struct RunStateWord<'a>(&'a AtomicU32);

impl RunStateWord<'_> {
    fn load(&self, order: Ordering) -> u8 {
        run_state_of(self.0.load(order))
    }

    fn store(&self, state: u8, order: Ordering) {
        let bits = run_state_bits(state);
        let _ = self.0.fetch_update(order, load_order(order), |word| {
            Some(word & !RUN_STATE_MASK | bits)
        });
    }

    /// Make a waiting process active and queued; `false` when it is not waiting. The first
    /// read of the word decides, and the swap retries only while other bits change.
    // Port of erts/emulator/beam/erl_process.c:6899-7005 (change_proc_schedule_state setting
    // ERTS_PSFLG_ACTIVE: enqueue only when the result is active alone), OTP-29.1.1.
    fn schedule_waiting(&self, known: Option<u32>) -> bool {
        let (from, to) = (run_state_bits(WAITING), run_state_bits(QUEUED));
        // The state word the sender's own read-modify-write produced is the first guess;
        // an active receiver then needs no further access to the shared word.
        let mut word = match known {
            Some(word) => word,
            None => self.0.load(Ordering::SeqCst),
        };
        while word & RUN_STATE_MASK == from {
            match self.0.compare_exchange_weak(
                word,
                word & !RUN_STATE_MASK | to,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => return true,
                Err(current) => word = current,
            }
        }
        false
    }

    /// Leave `RUNNING` for `state`. Only the scheduler running the process changes the run
    /// state bits of a running process, so one atomic read-modify-write flips them.
    // Port of erts/emulator/beam/erl_process.c:10483-10520 (schedule: the RUNNING bit is
    // cleared with an atomic band/bset on `p->state`), OTP-29.1.1.
    ///
    /// Returns the state word before the change, which carries the in-queue signal bits a
    /// sender set while the process ran.
    fn store_from_running(&self, state: u8, order: Ordering) -> u32 {
        let flip = run_state_bits(RUNNING) ^ run_state_bits(state);
        let previous = self.0.fetch_xor(flip, order);
        debug_assert_eq!(run_state_of(previous), RUNNING);
        previous
    }

    fn compare_exchange(
        &self,
        current: u8,
        new: u8,
        success: Ordering,
        failure: Ordering,
    ) -> Result<u8, u8> {
        let (from, to) = (run_state_bits(current), run_state_bits(new));
        self.0
            .fetch_update(success, failure, |word| {
                (word & RUN_STATE_MASK == from).then_some(word & !RUN_STATE_MASK | to)
            })
            .map(run_state_of)
            .map_err(run_state_of)
    }
}

/// The load ordering that may accompany a store with `order`.
const fn load_order(order: Ordering) -> Ordering {
    match order {
        Ordering::SeqCst => Ordering::SeqCst,
        Ordering::AcqRel | Ordering::Acquire => Ordering::Acquire,
        _ => Ordering::Relaxed,
    }
}

const PID_LIMIT: u32 = 1 << 28;
const UNBOUND_WORKER: usize = usize::MAX;
const QUEUE_COUNT_SHIFT: u32 = 32;
const QUEUE_COUNT_UNIT: u64 = 1_u64 << QUEUE_COUNT_SHIFT;

/// OTP 29.1.1's default microstate categories for this build.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(usize)]
pub enum MsaccState {
    /// Scheduler auxiliary work.
    Aux = 0,
    /// Polling and descriptor checks.
    CheckIo = 1,
    /// Erlang process execution.
    Emulator = 2,
    /// Garbage collection.
    Gc = 3,
    /// Scheduler work outside process execution.
    Other = 4,
    /// Port driver work.
    Port = 5,
    /// Scheduler sleeping.
    Sleep = 6,
}

pub const MSACC_STATE_COUNT: usize = 7;
const ACCOUNTING_WALL: u8 = 1;
const ACCOUNTING_MSACC: u8 = 2;

/// Local pid: the 60-bit process-table data of erts (`serial << 28 | number`).
///
/// Ordering follows the data, as erts compares internal pids
/// (erts/emulator/beam/utils.c:1768, erts_cmp_compound), OTP-29.1.1.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Pid {
    data: u64,
}

fn signal_buffer_slot(pid: Pid) -> usize {
    // Port of erts/emulator/beam/erl_proc_sig_queue.c:10284, OTP-29.1.1.
    pid.to_term()
        .map(arinsal_term::internal_hash)
        .unwrap_or(u64::from(pid.number())) as usize
}

impl Pid {
    /// Pid from its number (at most 28 bits) and serial.
    pub fn new(number: u32, serial: u32) -> Self {
        debug_assert!(number <= arinsal_term::ptab::MAX_INTERNAL_PID_NUMBER);
        Self::from_data((u64::from(serial) << arinsal_term::ptab::PID_NUM_SIZE) | u64::from(number))
    }

    /// Pid from process-table data.
    pub const fn from_data(data: u64) -> Self {
        Self {
            data: data & PTAB_ID_DATA_MASK,
        }
    }

    /// Process-table data.
    pub const fn data(self) -> u64 {
        self.data
    }

    /// Number printed as `N` in `<0.N.S>`.
    pub const fn number(self) -> u32 {
        (self.data & arinsal_term::ptab::MAX_INTERNAL_PID_NUMBER as u64) as u32
    }

    /// Serial printed as `S` in `<0.N.S>`.
    pub const fn serial(self) -> u32 {
        (self.data >> arinsal_term::ptab::PID_NUM_SIZE) as u32
    }

    /// Convert to the term crate's tagged local pid.
    pub fn to_term(self) -> Option<arinsal_term::Term> {
        Some(arinsal_term::Term::pid_from_data(self.data))
    }

    /// Decode a tagged local pid.
    pub fn from_term(term: arinsal_term::Term) -> Option<Self> {
        term.as_pid_data().map(Self::from_data)
    }
}

/// Scheduler-facing priority; interpretation of Erlang process flags belongs to the VM.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Priority {
    Max,
    High,
    #[default]
    Normal,
    Low,
}

impl Priority {
    fn index(self) -> usize {
        match self {
            Self::Max => 0,
            Self::High => 1,
            Self::Normal => 2,
            Self::Low => 3,
        }
    }

    fn from_index(index: u8) -> Self {
        match index {
            0 => Self::Max,
            1 => Self::High,
            2 => Self::Normal,
            _ => Self::Low,
        }
    }
}

/// `sys_priority` value when no system task elevates the process.
const NO_SYS_PRIORITY: u8 = 4;

/// An object shared by the origin and target halves of one monitor (erts' `ErtsMonitorData`). The
/// scheduler does not look inside it; the VM downcasts it. Identity, not content, decides equality.
#[derive(Clone)]
pub struct SharedPayload(pub std::sync::Arc<dyn std::any::Any + Send + Sync>);

impl fmt::Debug for SharedPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SharedPayload")
    }
}

impl PartialEq for SharedPayload {
    fn eq(&self, other: &Self) -> bool {
        std::sync::Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Eq for SharedPayload {}

/// Control signals delivered in the same stream as messages.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Signal<M> {
    /// Link request.
    Link,
    /// Unlink request carrying its acknowledgement id.
    Unlink(u64),
    /// Unlink acknowledgement.
    UnlinkAck(u64),
    /// Acknowledgement for the link protocol's unlink operation.
    UnlinkAckSignal(u64),
    /// Monitor request carrying a VM reference and the monitor's shared data.
    Monitor {
        reference: u64,
        shared: SharedPayload,
    },
    /// Suspend monitor activation: the suspender's `SuspendMonitor` (erl_proc_sig_queue.c
    /// handle_suspend, erl_process.c:9140). The target applies it and marks the monitor active.
    Suspend { shared: SharedPayload },
    /// Suspend monitor release: the suspender dropped its last suspend, or exited (erl_proc_sig_queue.c:6609).
    SuspendRelease { shared: SharedPayload },
    /// The suspendee of a suspend monitor exited: the suspender drops its half (erts
    /// monitor-down of an ERTS_MON_TYPE_SUSPEND monitor, erl_process.c:13809).
    SuspendDown { shared: SharedPayload },
    /// Internal resume: undo one suspend the process took on itself (erl_process.c:9402 erts_resume).
    SuspendResume,
    /// Internal suspend of the receiving process, taken from another process (erts_suspend on a
    /// process the caller does not run as). The receiver applies it to itself.
    SuspendInternal,
    /// Synchronous or tagged suspend reply request (erl_proc_sig_queue.c:3192
    /// erts_proc_sig_send_sync_suspend): queued behind the suspend, the target sends `{tag, reply}`
    /// to `requester` once it handled everything before it, patching the result to its state.
    /// Boxed: the request is rare and would otherwise widen every queued event.
    SyncSuspend(Box<SyncSuspendRequest<M>>),
    /// `Monitor` could not be published because the target exited first.
    MonitorNoproc(u64),
    /// Demonitor request carrying a VM reference.
    Demonitor(u64),
    /// Demonitor request carrying the origin half of the monitor itself, as erts queues the
    /// origin node (erl_proc_sig_queue.c, erts_proc_sig_send_demonitor): the target reaches
    /// its own half through the data both halves share.
    DemonitorOrigin(SharedPayload),
    /// Exit signal (`exit/2`) carrying an opaque reason envelope.
    Exit(M),
    /// Exit signal of a link: removes the receiver's link to the sender.
    // Port of erts/emulator/beam/erl_proc_sig_queue.c:4640 (ERTS_SIG_Q_OP_EXIT_LINKED), OTP-29.1.1.
    ExitLinked(M),
    /// Port exit signal preserving the port term used as the signal origin.
    /// Boxed: the signal is rare and would otherwise widen every queued event.
    PortExit(Box<PortExitSignal<M>>),
    /// Monitor DOWN signal carrying an opaque reason envelope.
    MonitorDown { reference: u64, reason: M },
    /// Monitor DOWN message the sender already built (a non-immediate reason, erl_proc_sig_queue.c:2836-2900).
    MonitorDownMsg { reference: u64, message: M },
    /// Alias activation.
    Alias(u64),
    /// Alias deactivation.
    Unalias(u64),
    /// Ask a process to collect its heap at its next signal safe point.
    GarbageCollect,
    /// Ask a process to copy terms from a retiring literal area.
    /// Boxed: the request is rare and would otherwise widen every queued event.
    LiteralAreaCopy(Box<LiteralAreaCopyRequest<M>>),
    /// Execute the process-signal blocking callback on the target process.
    ProcSigBlock(i64),
}

/// The fields of [`Signal::SyncSuspend`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyncSuspendRequest<M> {
    pub requester: Pid,
    pub tag: M,
    /// Atom index of the reply when the target is suspended.
    pub reply: u32,
    pub async_: bool,
}

/// The fields of [`Signal::PortExit`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PortExitSignal<M> {
    pub port: M,
    pub reason: M,
}

/// The fields of [`Signal::LiteralAreaCopy`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LiteralAreaCopyRequest<M> {
    pub area_id: u64,
    pub request: M,
    pub how: LiteralCopyHow,
    pub requester: Pid,
}

/// Phase of a literal-area copy request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LiteralCopyHow {
    /// Drain earlier signals and inspect process roots.
    Init,
    /// Check whether literal copying needs a collection.
    CheckGc,
    /// Collect and copy every remaining reference.
    NeedGc,
}

/// Ordered contents of a process mailbox.
pub enum Payload<M> {
    Message(M),
    Signal(Signal<M>),
    /// An expired `start_timer`; the VM can form `{timeout, Ref, Msg}`.
    Timer {
        reference: TimerId,
        message: M,
    },
    /// An expired `send_after`; the VM retires the timer reference and delivers the message as-is.
    TimerMessage {
        reference: TimerId,
        message: M,
    },
}

/// One message or signal, including its logical sender.
pub struct Event<M> {
    /// Sender used by the VM for signal semantics.
    pub from: Pid,
    /// Opaque message or typed control signal.
    pub payload: Payload<M>,
}

/// A message envelope as the signal queue sees it.
pub trait SignalMessage: Send + 'static {
    /// A priority message or a message sent through an alias: erts sends it as an
    /// `ERTS_SIG_Q_OP_ALTACT_MSG` non-message signal (erl_proc_sig_queue.c, handle_altact_msg),
    /// OTP-29.1.1.
    fn is_altact_msg(&self) -> bool {
        false
    }
    /// The Erlang reference key of a BIF timer message: the timer is created with the key as its
    /// identity, so the reference alone finds it.
    fn timer_ref_key(&self) -> Option<u64> {
        None
    }
    /// The queue node of a non-message signal sent by `from`. A signal may live in storage of
    /// its own, as erts queues a monitor's own node as the monitor signal
    /// (erl_proc_sig_queue.c, erts_proc_sig_send_monitor); the default allocates a node.
    fn signal_node(from: Pid, signal: Signal<Self>) -> OwnedSignal<Event<Self>>
    where
        Self: Sized,
    {
        OwnedSignal::new(Event {
            from,
            payload: Payload::Signal(signal),
        })
    }
}

/// The queue node of `payload` sent by `from` (`erts_alloc_message` for a message).
fn event_node<M: SignalMessage>(from: Pid, payload: Payload<M>) -> OwnedSignal<Event<M>> {
    match payload {
        Payload::Signal(signal) => M::signal_node(from, signal),
        payload => OwnedSignal::new(Event { from, payload }),
    }
}

impl SignalMessage for () {}
impl SignalMessage for u32 {}
impl SignalMessage for u64 {}
impl SignalMessage for usize {}

// Port of erts/emulator/beam/erl_proc_sig_queue.h (ERTS_SIG_IS_MSG: messages, including
// timer timeouts, versus non-message signals), OTP-29.1.1.
impl<M: SignalMessage> InSignal for Event<M> {
    fn is_message(&self) -> bool {
        match &self.payload {
            Payload::Message(message) | Payload::TimerMessage { message, .. } => {
                !message.is_altact_msg()
            }
            Payload::Timer { .. } => true,
            Payload::Signal(_) => false,
        }
    }
}

/// A task's cooperative scheduling result.
pub enum RunOutcome {
    /// The task used its reductions budget and remains runnable.
    Yield,
    /// The task blocks in receive; an optional timeout wakes it.
    Wait { timeout_ms: Option<u64> },
    /// The task has terminated; reason interpretation belongs to the VM.
    Exit(u64),
    /// The task must continue on a dirty scheduler of this kind. A task that
    /// returns [`RunOutcome::Yield`] or [`RunOutcome::Wait`] from a dirty
    /// scheduler moves back to the normal run queues.
    Dirty(DirtyKind),
}

/// Dirty scheduler class requested by [`RunOutcome::Dirty`].
///
/// Port of erts/emulator/beam/erl_process.h (`ERTS_SCHED_DIRTY_CPU`, `ERTS_SCHED_DIRTY_IO`), OTP-29.1.1.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirtyKind {
    /// Dirty CPU scheduler pool.
    Cpu,
    /// Dirty I/O scheduler pool.
    Io,
}

impl DirtyKind {
    fn index(self) -> usize {
        match self {
            Self::Cpu => 0,
            Self::Io => 1,
        }
    }
}

/// Type of the scheduler thread executing the caller.
///
/// Port of erts/emulator/beam/erl_process.h:290 (`ErtsSchedType`), OTP-29.1.1.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SchedulerType {
    /// A normal scheduler, or a thread that is no scheduler at all.
    Normal,
    /// A dirty CPU scheduler.
    DirtyCpu,
    /// A dirty I/O scheduler.
    DirtyIo,
}

impl SchedulerType {
    /// Whether this is a dirty scheduler type.
    pub fn is_dirty(self) -> bool {
        self != Self::Normal
    }
}

impl From<DirtyKind> for SchedulerType {
    fn from(kind: DirtyKind) -> Self {
        match kind {
            DirtyKind::Cpu => Self::DirtyCpu,
            DirtyKind::Io => Self::DirtyIo,
        }
    }
}

/// A process monitor held on this scheduler until its target gets another signal or the
/// sending process is scheduled out. Port of erts `esdp->pending_signal`
/// (erl_proc_sig_queue.c:1102-1125, erts_proc_sig_send_pending), OTP-29.1.1.
#[derive(Clone)]
struct PendingProcMonitor {
    from: Pid,
    to: Pid,
    id: u64,
    shared: SharedPayload,
}

thread_local! {
    static PENDING_PROC_MONITOR: std::cell::RefCell<Option<PendingProcMonitor>> =
        const { std::cell::RefCell::new(None) };
    static SCHEDULER_TYPE: std::cell::Cell<SchedulerType> =
        const { std::cell::Cell::new(SchedulerType::Normal) };
    static NORMAL_SCHEDULER_ID: std::cell::Cell<Option<usize>> =
        const { std::cell::Cell::new(None) };
    static NORMAL_SCHEDULER_COUNT: std::cell::Cell<Option<usize>> =
        const { std::cell::Cell::new(None) };
}

/// Zero-based index of the normal scheduler running on the calling thread, like
/// `erts_get_scheduler_id() - 1`; `None` on other threads.
pub fn current_normal_scheduler() -> Option<usize> {
    NORMAL_SCHEDULER_ID.with(std::cell::Cell::get)
}

/// Number of normal schedulers in the calling scheduler thread's runtime.
pub fn current_normal_scheduler_count() -> Option<usize> {
    NORMAL_SCHEDULER_COUNT.with(std::cell::Cell::get)
}

/// Scheduler type of the calling thread, like `erts_get_scheduler_data()->type`.
pub fn current_scheduler_type() -> SchedulerType {
    SCHEDULER_TYPE.with(std::cell::Cell::get)
}

/// Take the held process monitor of this scheduler when it is for `to`, so the signal to `to`
/// is sent after it. Port of erl_proc_sig_queue.c:1141-1150, OTP-29.1.1.
fn take_held_monitor_for(to: Pid) -> Option<PendingProcMonitor> {
    PENDING_PROC_MONITOR.with(|slot| {
        let mut slot = slot.borrow_mut();
        if slot.as_ref().is_some_and(|held| held.to == to) {
            slot.take()
        } else {
            None
        }
    })
}

/// A VM process or a benchmark dummy task.
pub trait Task: Send + 'static {
    /// Opaque message envelope owned by the receiving process.
    type Message: SignalMessage;
    /// Task-side part of one scheduler's data (`ErtsSchedulerData`): created once per normal,
    /// dirty or simulated scheduler and lent to every [`Task::run`] on it.
    type SchedulerData: Default + Send + 'static;
    /// Execute cooperatively, consuming at most `budget` reductions, on the scheduler whose
    /// data is `data`.
    ///
    /// Port of erts/emulator/beam/erl_process.c:9607 (erts_schedule returns the process to
    /// run to process_main, which keeps `esdp` at hand), OTP-29.1.1.
    fn run(
        &mut self,
        ctx: &mut RunCtx<Self::Message>,
        data: &mut Self::SchedulerData,
        budget: u32,
    ) -> RunOutcome;
    /// Release task-owned runtime registrations after all workers have stopped.
    fn scheduler_shutdown(&mut self) {}
    /// Cumulative time spent collecting this task's heap.
    fn gc_nanoseconds(&self) -> u64 {
        0
    }
    /// Optional VM hook for a worker's transition between running and idle.
    fn scheduler_profile_event(
        &mut self,
        _pid: Pid,
        _scheduler_id: u32,
        _active: bool,
        _active_schedulers: u32,
    ) -> Option<(Pid, Self::Message)> {
        None
    }
    /// Signals that landed after the task decided to exit, before it left the table.
    fn reap_signals(&mut self, _pid: Pid, _events: Vec<Event<Self::Message>>) {}
    /// Release what the exited task owns on the scheduler it exited on; only the process
    /// struct waits for the lookups that may still reach it.
    ///
    /// Port of erts/emulator/beam/erl_process.c (delete_process, called at the end of
    /// erts_continue_exit_process), OTP-29.1.1.
    fn delete_process(&mut self) {}
    /// A dirty job this task wants to execute on the current dirty scheduler of `kind`
    /// without holding its task cell, so its signals can be handled meanwhile.
    ///
    /// Port of erts/emulator/beam/erl_nif.c:468 and bif.c:5803 (`erts_call_dirty_nif` and
    /// `erts_call_dirty_bif` release the main process lock around the call), OTP-29.1.1.
    fn take_dirty_job(&mut self, _kind: DirtyKind) -> Option<DirtyJob> {
        None
    }
    /// Hand the result of a job from [`Task::take_dirty_job`] back to the task, with
    /// its task cell locked again.
    fn finish_dirty_job(&mut self, _result: Box<dyn std::any::Any>) {}
}

/// A dirty job executed without the task cell, on the dirty scheduler thread that took it;
/// see [`Task::take_dirty_job`].
pub type DirtyJob = Box<dyn FnOnce() -> Box<dyn std::any::Any>>;

/// Callback run on another process's task with a context acting as it; true when done.
pub type TargetHandler<'a, M> = dyn FnMut(&mut dyn std::any::Any, &mut RunCtx<'_, M>) -> bool + 'a;

/// Outcome of [`RunCtx::handle_dirty_signals`], mirroring the results of
/// `erts_internal:dirty_process_handle_signals/1`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirtySignals {
    /// The pid identifies no live process.
    NoProc,
    /// The process is not in a dirty state; it handles its own signals.
    Normal,
    /// Nothing was queued.
    Idle,
    /// Another thread holds the task cell while the process is still dirty, or the
    /// callback ran out of reductions before handling every signal.
    More,
    /// The callback handled the queued signals.
    Handled,
}

/// Configuration for threaded and simulated execution.
pub struct Config {
    /// Number of worker threads; defaults to available parallelism minus two.
    pub workers: usize,
    /// Maximum live processes, bounded by the pid index representation.
    pub max_processes: u32,
    /// Reductions in a fresh scheduling quantum.
    pub reductions: u32,
    /// Dirty CPU scheduler threads (`+SDcpu`); erts defaults to one per scheduler.
    pub dirty_cpu_schedulers: usize,
    /// Dirty I/O scheduler threads (`+SDio`); erts defaults to ten.
    pub dirty_io_schedulers: usize,
    /// Compact load on as few run queues as possible (`+scl`); erts defaults to true.
    pub compact_load: bool,
    /// Utilization-driven run-queue balancing requested by `+sub`.
    pub utilization_balancing: bool,
    /// Busy-wait thresholds for normal, dirty CPU, and dirty I/O schedulers.
    pub busy_wait_thresholds: [Option<String>; 3],
    /// Wakeup thresholds for normal, dirty CPU, and dirty I/O schedulers.
    pub wakeup_thresholds: [Option<String>; 3],
    /// `+sfwi` forced wakeup interval.
    pub forced_wakeup_interval: Option<u64>,
    /// `+spp` port-parallelism scheduling hint.
    pub port_parallelism: Option<bool>,
    /// `+sbt` scheduler binding strategy.
    pub scheduler_bind_type: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        let available = arinsal_alloc::cpuinfo::default_schedulers().0;
        Self {
            workers: available.max(1),
            max_processes: 1_048_576,
            reductions: 4_000,
            dirty_cpu_schedulers: available.max(1),
            dirty_io_schedulers: 10,
            // Port of erts/emulator/beam/erl_init.c:803 (erts_sched_compact_load), OTP-29.1.1.
            compact_load: true,
            utilization_balancing: false,
            busy_wait_thresholds: [None, None, None],
            wakeup_thresholds: [None, None, None],
            forced_wakeup_interval: None,
            port_parallelism: None,
            scheduler_bind_type: None,
        }
    }
}

/// Recoverable scheduler operation error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Capacity,
    NoProcess,
    WrongMode,
}

/// Why [`Scheduler::spawn_unscheduled_init`] created no process.
#[derive(Debug)]
pub enum SpawnInitError<E> {
    /// The process table refused the process.
    Table(Error),
    /// The caller's initialization failed; the process was freed.
    Init(E),
}

/// Outcome of [`Scheduler::try_send_on_heap`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OnHeapSend {
    /// The main lock was not taken: the receiver is missing, not waiting, exiting,
    /// executing on a dirty scheduler, or the lock was already held.
    Unavailable,
    /// The lock was held, and the caller left the message on a heap fragment.
    Declined,
    /// The message was queued, or the receiver exited before the queue push.
    Queued,
    /// The lock was held and the queue push failed.
    Failed(Error),
}

/// Outcome of attempting an erts-style sig-free task lock.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignalFreeError {
    /// The pid is no longer in the process table.
    NoProcess,
    /// The task is running or has signals waiting to be handled.
    Busy,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for Error {}

/// Source of monotonically increasing milliseconds.
pub trait Clock: Send + Sync {
    /// Current virtual or real time.
    fn now_ms(&self) -> u64;

    /// Nanoseconds until the clock reaches wheel position `pos`.
    fn ns_until_pos(&self, pos: u64) -> u64 {
        pos.saturating_sub(self.now_ms()).saturating_mul(1_000_000)
    }

    /// The erts wheel position for a relative millisecond timeout.
    fn timeout_pos(&self, ms: u64) -> u64 {
        if ms == 0 {
            self.now_ms()
        } else {
            self.now_ms().saturating_add(ms)
        }
    }

    /// The erts clock position used to report a timer's remaining milliseconds.
    fn time_left_now_ms(&self) -> u64 {
        self.now_ms()
    }
}

/// Source of scheduling choices, local to one scheduler.
pub trait Rng: Send {
    /// Return the next pseudorandom word.
    fn next_u64(&mut self) -> u64;
}

/// Seeded, reproducible SplitMix64 generator.
pub struct SeededRng(u64);
impl SeededRng {
    /// Construct from a simulation seed.
    pub fn new(seed: u64) -> Self {
        Self(seed)
    }
}
impl Rng for SeededRng {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e3779b97f4a7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
        z ^ (z >> 31)
    }
}

struct RealClock(Instant);
impl Clock for RealClock {
    fn now_ms(&self) -> u64 {
        let elapsed = self.0.elapsed();
        elapsed
            .as_secs()
            .saturating_mul(1000)
            .saturating_add(u64::from(elapsed.subsec_millis()))
    }

    fn ns_until_pos(&self, pos: u64) -> u64 {
        let elapsed = u64::try_from(self.0.elapsed().as_nanos()).unwrap_or(u64::MAX);
        pos.saturating_mul(1_000_000).saturating_sub(elapsed)
    }

    fn timeout_pos(&self, ms: u64) -> u64 {
        if ms == 0 {
            return self.now_ms();
        }
        // Port of erts/emulator/beam/erl_hl_timer.c:670-679 (get_timeout_pos), OTP-29.1.1.
        let ticks = self.0.elapsed().as_nanos().saturating_sub(1) / 1_000_000;
        u64::try_from(ticks)
            .unwrap_or(u64::MAX)
            .saturating_add(ms)
            .saturating_add(1)
    }

    fn time_left_now_ms(&self) -> u64 {
        // Port of erts/emulator/beam/erl_hl_timer.c:682-689 (get_time_left), OTP-29.1.1.
        let nanos = self.0.elapsed().as_nanos();
        let ticks = nanos.saturating_sub(1) / 1_000_000 + u128::from(nanos != 0);
        u64::try_from(ticks).unwrap_or(u64::MAX)
    }
}

/// Manually advanced clock for deterministic simulation.
#[derive(Default)]
pub struct VirtualClock(AtomicU64);
impl VirtualClock {
    /// Advance virtual time; timers fire when the simulation is stepped.
    pub fn advance(&self, ms: u64) {
        self.0.fetch_add(ms, Ordering::Relaxed);
    }
}
impl Clock for VirtualClock {
    fn now_ms(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

/// Lock-free view of whether signals wait in one process's outer signal queue, for code that
/// runs the process without its [`RunCtx`] (native receive). It does not keep the process
/// alive; a probe of an exited process reports nothing pending.
// Port of erts/emulator/beam/erl_process.h:1291 (ERTS_PSFLG_MSG_SIG_IN_Q), OTP-29.1.1.
/// A child inserted by `spawn_unscheduled_handle*` and not yet scheduled. The spawner keeps the
/// process it created, as `erl_create_process` keeps its `Process *`, so scheduling needs no
/// process table lookup.
pub struct SpawnedProcess<M> {
    pid: Pid,
    process: ErasedProcRef,
    _message: std::marker::PhantomData<fn() -> M>,
}

impl<M> SpawnedProcess<M> {
    /// The child's pid.
    pub fn pid(&self) -> Pid {
        self.pid
    }

    /// Run `f` on the not yet scheduled child's task, under its main lock; `None` when the
    /// task type is not `T`.
    pub fn with_task<T: Task<Message = M>, R>(&self, f: impl FnOnce(&mut T) -> R) -> Option<R> {
        self.process
            .with_typed(|process: &ProcRef<T>| f(process.cell.lock().task_mut()))
    }
}

impl<M: SignalMessage> SignalProbe<M> {
    /// Whether the outer signal queue holds unfetched signals.
    pub fn has_pending(&self) -> bool {
        self.input().has_pending()
    }

    /// The process's state flags ([`proc_flags`]), read without a table lookup.
    pub fn proc_flags(&self) -> &AtomicU32 {
        self.flags()
    }

    /// Record whether the receiver's middle signal queue holds unhandled signals
    /// (`ERTS_PSFLG_SIG_Q`).
    pub fn set_sig_q(&self, unhandled: bool) {
        self.input().set_sig_q(unhandled);
    }

    /// Queue a message from the process to itself straight into its own outer signal queue.
    // Port of erts/emulator/beam/erl_message.c:532 (erts_queue_proc_message with
    // sender == receiver) and :698 (erts_send_message), OTP-29.1.1: the sender holds the
    // receiver, so there is no process-table lookup, and a running receiver is not scheduled.
    pub fn send_self(&self, pid: Pid, msg: M) -> Result<(), Error> {
        self.send_self_node(
            pid,
            OwnedSignal::new(Event {
                from: pid,
                payload: Payload::Message(msg),
            }),
        )
    }

    /// [`Self::send_self`] of a message node the sender allocated.
    pub fn send_self_node(&self, pid: Pid, signal: OwnedSignal<Event<M>>) -> Result<(), Error> {
        self.input()
            .push_routed_node(|| signal_buffer_slot(pid), signal)
            .map_err(|_| Error::NoProcess)?;
        self.input().backlog.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// Move the whole outer queue to the end of `into`, the receiver's middle queue. Each
    /// event taken from there is accounted with [`RunCtx::consume_fetched`].
    // Port of erts/emulator/beam/erl_proc_sig_queue.h:1997 (erts_proc_sig_fetch), OTP-29.1.1.
    pub fn fetch_all(&self, into: &mut SignalQueue<Event<M>>) {
        self.input().take_all(into);
    }

    /// Move the whole outer queue to `into` when it holds only messages that `accept` takes;
    /// otherwise leave it for the scheduler. Returns the number of signals moved.
    // Port of erts/emulator/beam/erl_proc_sig_queue.c:1332 (erts_proc_sig_fetch__), OTP-29.1.1.
    pub fn fetch_messages_if(
        &self,
        accept: impl Fn(&M) -> bool,
        into: &mut SignalQueue<Event<M>>,
    ) -> usize {
        self.input().take_all_if(
            |event| matches!(&event.payload, Payload::Message(message) if accept(message)),
            into,
        )
    }
}

impl<M> std::fmt::Debug for SignalProbe<M> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignalProbe").finish_non_exhaustive()
    }
}

/// Process-local words `erts_continue_exit_process` tests before taking a global table lock.
///
/// Low 16 bits are "this process has the resource" (`p->reg`, `F_USING_DB`, `p->bif_timers`,
/// trace flags, …). High 16 bits are "exit has finished that resource", so a late registration
/// can see the process is already gone and roll back. Port of erl_process.c:14301 (`bif_timers`),
/// 14362 (`F_USING_DB`), 14424 (`p->common.u.alive.reg`), 14215 (code-permission xstate) and
/// erl_process.c:13221 (`ERTS_P_ALL_TRACE_FLAGS`), OTP-29.1.1.
pub mod proc_flags {
    use std::sync::atomic::{AtomicU32, Ordering};

    pub const USING_DB: u32 = 1 << 0;
    pub const BIF_TIMERS: u32 = 1 << 1;
    pub const PORTS: u32 = 1 << 2;
    pub const DDLL: u32 = 1 << 3;
    pub const CODE_PERM: u32 = 1 << 4;
    pub const SYS_MON: u32 = 1 << 5;
    pub const NODE_MON: u32 = 1 << 6;
    pub const REG: u32 = 1 << 7;
    pub const TRACE: u32 = 1 << 8;
    pub const TRACER: u32 = 1 << 9;
    pub const OWNED_TIMERS: u32 = 1 << 11;
    /// A remote `process_info` / sys-task request is queued for this process
    /// (`erl_proc_sig_queue.c` request tables). Exit takes that table only then.
    pub const REQUESTS: u32 = 1 << 12;
    pub const ALL: u32 = (1 << 13) - 1;
    /// `ERTS_PSFLG_EXITING`, outside `ALL` so cleanup does not retire the bit.
    /// Port of erl_nif.c:2323 (`enif_is_process_alive` sees the state flag), OTP-29.1.1.
    pub const EXITING: u32 = 1 << 15;
    /// The process is parked in `erts_hibernate` (erl_process.c:9304 reads it for `status`).
    /// It is a state bit the process sets on itself, outside `ALL` like `EXITING`.
    pub const HIBERNATED: u32 = 1 << 14;
    /// `ERTS_PSFLG_SUSPENDED`: the process has an active suspend (erl_process.c:7235 suspend_process).
    /// Set by the suspend path, cleared when the last suspend is released. Outside `ALL`.
    pub const SUSPENDED: u32 = 1 << 13;
    /// Sets a state bit of the owning process (no cleanup bookkeeping).
    pub fn set_state(flags: &AtomicU32, bit: u32) {
        flags.fetch_or(bit, Ordering::AcqRel);
    }
    /// Clears a state bit of the owning process.
    pub fn clear_state(flags: &AtomicU32, bit: u32) {
        flags.fetch_and(!bit, Ordering::AcqRel);
    }
    const DONE_SHIFT: u32 = 16;

    /// Bits whose global tables exit must still visit.
    ///
    /// Port of the NULL / flag tests in `erts_continue_exit_process` (erl_process.c:14290-14430):
    /// a zero word skips the table. Unused bits are published as done so a registration that
    /// arrives during exit rolls itself back instead of leaking into the table.
    pub fn resources_to_clean(flags: &AtomicU32) -> u32 {
        let current = flags.load(Ordering::Acquire) & ALL;
        let unused = ALL & !current;
        if unused != 0 {
            flags.fetch_or(unused << DONE_SHIFT, Ordering::AcqRel);
        }
        flags.load(Ordering::Acquire) & ALL
    }

    /// Exit has already finished `bit` and will not look again.
    pub fn finished(flags: &AtomicU32, bit: u32) -> bool {
        flags.load(Ordering::Acquire) & (bit << DONE_SHIFT) != 0
    }

    /// Record that this process now has `bit`. False means exit already finished it.
    pub fn publish(flags: &AtomicU32, bit: u32) -> bool {
        let done = bit << DONE_SHIFT;
        flags.fetch_or(bit, Ordering::AcqRel) & done == 0
    }
}

struct Process<T: Task> {
    pid: Pid,
    /// Creation order of this incarnation, so a reused pid is distinguishable.
    /// Port of erts/emulator/beam/erl_ptab.c:530 (`u.alive.started_interval`), OTP-29.1.1.
    started_interval: u64,
    /// User priority (`process_flag(priority, _)`).
    /// Port of erl_process.h (`ERTS_PSFLGS_USR_PRIO_MASK`), OTP-29.1.1.
    user_priority: AtomicU8,
    /// erts `ERTS_PSFLG_ACTIVE` as seen by other processes: cleared when a slice ends
    /// waiting in a receive, set when it ends runnable.
    active: AtomicBool,
    /// Priority of the highest pending system task, [`NO_SYS_PRIORITY`] when none.
    /// The actual priority is the higher of the two.
    /// Port of erl_process.h (`ERTS_PSFLGS_ACT_PRIO_MASK`, `ERTS_PSFLG_SYS_TASKS`), OTP-29.1.1.
    sys_priority: AtomicU8,
    /// Bumped each time the process is scheduled in. A run queue entry made in an
    /// earlier epoch is stale: a system task enqueues the process a second time in a
    /// higher priority queue, and whichever entry runs first retires the other.
    /// Port of erl_process.h (`ERTS_PSFLGS_IN_PRQ_MASK`, proxy entries), OTP-29.1.1.
    run_epoch: AtomicU64,
    bound_worker: AtomicUsize,
    scheduler_id: AtomicUsize,
    wait_epoch: AtomicU64,
    timer_epoch_used: AtomicBool,
    /// Wheels that may hold BIF timers aimed at this process: bit `w` for scheduler `w`, the
    /// top bit for every scheduler from 63 on.
    ///
    /// Port of erts/emulator/beam/erl_hl_timer.c:1832-1840 (setup_bif_timer links the timer
    /// into the receiver's `bif_timers` tree), OTP-29.1.1: exit, pause and resume visit only
    /// the wheels that hold the receiver's timers, so a process without timers disturbs no
    /// other scheduler.
    bif_timer_wheels: AtomicU64,
    /// `p->bif_timers`: the BIF timers aimed at this process, timer id to the scheduler whose
    /// wheel holds it. Inserted when the timer is created, removed when it fires or is
    /// canceled, and walked on exit (erts_cancel_bif_timers). The lock is the timer's own
    /// (ERTS_PROC_LOCK_BTM), not a global one.
    btm: parking_lot::Mutex<ProcBtm<T::Message>>,
    /// See [`proc_flags`]. Read on exit without the process cell lock.
    exit_flags: AtomicU32,
    /// `p->common.u.alive.reg->name`, or [`u32::MAX`] when the process has no name.
    /// Port of erts/emulator/beam/erl_process.h (`common.u.alive.reg`), OTP-29.1.1.
    reg_atom: AtomicU32,
    wait_timer: AtomicU64,
    // Port of erts `Process.sig_inq`; shared with the task so receive can fetch in place.
    input: Incoming<Event<T::Message>>,
    /// Wheel that owns `wait_timer`, so cancel does not guess from the pid.
    wait_timer_worker: AtomicUsize,
    /// Dirty run queue that owns this process: 0 normal, 1 dirty CPU, 2 dirty I/O.
    /// Port of erl_process.h (`ERTS_PSFLG_DIRTY_CPU_PROC`, `ERTS_PSFLG_DIRTY_IO_PROC`), OTP-29.1.1.
    dirty: AtomicU8,
    /// One plus the dirty thread slot executing this process, 0 when not executing dirty.
    /// Port of erl_process.h (`ERTS_PSFLG_DIRTY_RUNNING`), OTP-29.1.1.
    dirty_runner: AtomicUsize,
    /// Priority level whose run queue length counts this queued process.
    queued_prio: AtomicU8,
    /// The process main lock: embedded in the process, as erts' `p->lock`, with no allocation.
    cell: parking_lot::Mutex<TaskCell<T>>,
}

impl<T: Task> Process<T> {
    /// The scheduling bits of the process state word (`p->state`).
    fn run_state(&self) -> RunStateWord<'_> {
        RunStateWord(self.input.state())
    }
    /// Actual priority: the user priority, elevated by pending system tasks.
    /// Port of erts/emulator/beam/erl_process.c:10737 (fetch_sys_task act prio), OTP-29.1.1.
    fn priority(&self) -> Priority {
        let user = self.user_priority.load(Ordering::Acquire);
        let sys = self.sys_priority.load(Ordering::Acquire);
        Priority::from_index(user.min(sys))
    }

    fn bound_worker(&self) -> Option<usize> {
        let worker = self.bound_worker.load(Ordering::Acquire);
        (worker != UNBOUND_WORKER).then_some(worker)
    }
}

/// Process table: erts' `ErtsPTab` slots plus its free identifier ring.
///
/// Port of erts/emulator/beam/erl_ptab.c (erts_ptab_new_element,
/// erts_ptab_delete_element, erts_ptab_test_next_id), OTP-29.1.1.
struct ProcessTable<T: Task> {
    ids: PtabIdRing,
    /// `ptab->list.data.rwmtx`: test_next_id excludes concurrent inserts and removals.
    /// Port of erts/emulator/beam/erl_ptab.c (erts_ptab_init_table:
    /// `ERTS_RWMTX_TYPE_EXTREMELY_FREQUENT_READ`), OTP-29.1.1: inserts and removals take it
    /// as readers, each on its own reader-group line.
    lock: arinsal_term::FrequentReadRwLock<()>,
    /// `ptab->list.data.interval`: read into each new element's `started_interval` and
    /// stepped only when a later interval is needed.
    interval: AtomicU64,
    /// `ptab->r.o.tab`: one slot per table index, allocated with the table as
    /// erts_ptab_init_table does. A slot holds the table's reference to its process.
    slots: Box<[AtomicPtr<()>]>,
    /// The thread progress that releases the table's references (erts_ptab_delete_element
    /// schedules the release as a later operation).
    progress: Arc<thr_progress::ThrProgress>,
    _process: std::marker::PhantomData<ProcRef<T>>,
}

impl<T: Task> ProcessTable<T> {
    fn new(capacity: u32, progress: Arc<thr_progress::ThrProgress>) -> Self {
        let ids = PtabIdRing::new(capacity);
        let slots = (0..ids.layout().max())
            .map(|_| AtomicPtr::new(std::ptr::null_mut()))
            .collect();
        Self {
            ids,
            lock: arinsal_term::FrequentReadRwLock::new(()),
            interval: AtomicU64::new(0),
            slots,
            progress,
            _process: std::marker::PhantomData,
        }
    }

    fn slot(&self, pix: u32) -> Option<&AtomicPtr<()>> {
        self.slots.get(pix as usize)
    }

    fn slot_occupied(&self, pix: u32) -> bool {
        self.slot(pix)
            .is_some_and(|slot| !slot.load(Ordering::Acquire).is_null())
    }

    /// Table index of a pid, the order `erlang:processes/0` reports.
    fn index(&self, pid: Pid) -> u32 {
        self.ids.layout().data2pix(pid.data())
    }

    fn insert(
        &self,
        task: T,
        priority: Priority,
        bound_worker: Option<usize>,
    ) -> Result<ProcRef<T>, Error> {
        self.insert_init(
            |slot| slot.write(task),
            |_| Ok::<(), std::convert::Infallible>(()),
            priority,
            bound_worker,
        )
        .map_err(|error| match error {
            SpawnInitError::Table(error) => error,
            SpawnInitError::Init(never) => match never {},
        })
    }

    /// Allocate a process struct with the task `make` builds, let `init` set the task up in
    /// place, then publish it in the table.
    ///
    /// Port of erts/emulator/beam/erl_process.c (erl_create_process: alloc_process takes the
    /// struct and its table entry, then the fields are initialized in place) and erl_ptab.c
    /// (erts_ptab_new_element), OTP-29.1.1. A failing `init` gives the identifier back.
    fn insert_init<E>(
        &self,
        make: impl for<'slot> FnOnce(&'slot mut std::mem::MaybeUninit<T>) -> &'slot mut T,
        init: impl FnOnce(&mut T) -> Result<(), E>,
        priority: Priority,
        bound_worker: Option<usize>,
    ) -> Result<ProcRef<T>, SpawnInitError<E>> {
        // Port of erts/emulator/beam/erl_ptab.c:500 (erts_ptab_new_element), OTP-29.1.1.
        let _shared = self.lock.read();
        let data = self
            .ids
            .reserve()
            .ok_or(SpawnInitError::Table(Error::Capacity))?;
        let pid = Pid::from_data(data);
        let pix = self.ids.layout().data2pix(data) as usize;
        let (process, initialized) = ProcRef::new_with(
            || Process {
                pid,
                // Port of erts/emulator/beam/erl_ptab.c (erts_ptab_new_element:
                // erts_current_interval_nob), OTP-29.1.1.
                started_interval: self.interval.load(Ordering::Relaxed),
                user_priority: AtomicU8::new(priority.index() as u8),
                active: AtomicBool::new(true),
                sys_priority: AtomicU8::new(NO_SYS_PRIORITY),
                run_epoch: AtomicU64::new(0),
                bound_worker: AtomicUsize::new(bound_worker.unwrap_or(UNBOUND_WORKER)),
                scheduler_id: AtomicUsize::new(0),
                wait_epoch: AtomicU64::new(0),
                timer_epoch_used: AtomicBool::new(false),
                bif_timer_wheels: AtomicU64::new(0),
                btm: parking_lot::Mutex::new(ProcBtm {
                    tree: std::collections::BTreeMap::new(),
                    paused: None,
                }),
                exit_flags: AtomicU32::new(0),
                reg_atom: AtomicU32::new(u32::MAX),
                wait_timer: AtomicU64::new(0),
                input: Incoming::default(),
                wait_timer_worker: AtomicUsize::new(0),
                dirty: AtomicU8::new(0),
                dirty_runner: AtomicUsize::new(0),
                queued_prio: AtomicU8::new(0),
                cell: parking_lot::Mutex::new(TaskCell::uninit()),
            },
            |process| {
                // alloc_process: the task is written straight into the allocated struct.
                let cell = process.cell.get_mut();
                cell.init_with(make);
                init(cell.task_mut())
            },
        );
        if let Err(error) = initialized {
            drop(process);
            self.ids.release(data);
            return Err(SpawnInitError::Init(error));
        }
        // The table's reference (erts `refc` 1 at erts_ptab_new_element).
        self.slots[pix].store(process.clone().into_raw(), Ordering::Release);
        Ok(process)
    }

    /// Run `f` on the process in slot `pix`. Thread progress keeps it alive: a managed thread
    /// passes no progress point meanwhile, and another thread delays progress.
    ///
    /// Port of erts/emulator/beam/erl_process.h (erts_proc_lookup_raw and the
    /// erts_thr_progress_unmanaged_delay of erts_proc_lookup_inc_refc), OTP-29.1.1.
    fn with_slot<R>(&self, pix: u32, f: impl FnOnce(&ProcRef<T>) -> R) -> Option<R> {
        let slot = self.slot(pix)?;
        let delay = thr_progress::unmanaged_delay(&self.progress);
        let raw = slot.load(Ordering::Acquire);
        let result = (!raw.is_null()).then(|| {
            let _lookup = thr_progress::LookupScope::enter();
            // SAFETY: `raw` was in the slot while this thread delays thread progress, and the
            // slot's reference is released only by a later operation after thread progress.
            unsafe { ProcRef::with_borrowed(raw, f) }
        });
        thr_progress::unmanaged_continue(&self.progress, delay);
        result
    }

    fn load_slot(&self, pix: u32) -> Option<ProcRef<T>> {
        self.with_slot(pix, ProcRef::clone)
    }

    fn lookup(&self, pid: Pid) -> Option<ProcRef<T>> {
        self.load_slot(self.index(pid))
            .filter(|process| process.pid == pid)
    }

    /// Run `f` on a live process without touching its reference count.
    // Port of erts/emulator/beam/erl_process.h (erts_proc_lookup_raw), OTP-29.1.1: thread
    // progress keeps the process struct alive during the lookup.
    fn with_live<R>(&self, pid: Pid, f: impl FnOnce(&ProcRef<T>) -> R) -> Option<R> {
        self.with_slot(self.index(pid), |process| {
            (process.pid == pid).then(|| f(process))
        })
        .flatten()
    }

    fn remove(&self, pid: Pid) {
        // Port of erts/emulator/beam/erl_ptab.c:675 (erts_ptab_delete_element), OTP-29.1.1.
        let _shared = self.lock.read();
        let slot = self.slot(self.index(pid)).expect("a live pid has a slot");
        let old = slot.swap(std::ptr::null_mut(), Ordering::AcqRel);
        if old.is_null() {
            return;
        }
        self.ids.release(pid.data());
        // erts_schedule_thr_prgr_later_cleanup_op(release_process, ...): a lookup that loaded
        // the slot before it was cleared may still use the process.
        thr_progress::schedule_later_op(&self.progress, ProcRef::<T>::release_later(old));
    }

    /// Detach every process at VM shutdown so the references they hold to shared runtime
    /// objects are released (the runtime owns the scheduler, the table owns the processes).
    fn release_all(&self) {
        let mut next = 0;
        loop {
            let (pids, after) = self.pids_in_range(next, u32::MAX, 4096);
            if pids.is_empty() {
                break;
            }
            for pid in pids {
                // A process still held by a blocked worker keeps its cell; it is only detached.
                if let Some(process) = self.load_slot(self.index(pid))
                    && let Some(mut cell) = process.cell.try_lock()
                {
                    cell.task_mut().scheduler_shutdown();
                }
                self.remove(pid);
            }
            next = after;
        }
    }

    fn live_count(&self) -> usize {
        self.slots
            .iter()
            .filter(|slot| !slot.load(Ordering::Acquire).is_null())
            .count()
    }

    /// Live pids in slots `first..limit`, at most `max`, and the slot after the last
    /// one inspected.
    ///
    /// Port of erts/emulator/beam/erl_ptab.c:1515 (erts_ptab_processes_next scan loop), OTP-29.1.1.
    fn pids_in_range(&self, first: u32, limit: u32, max: usize) -> (Vec<Pid>, u32) {
        let mut pids = Vec::new();
        let mut pix = first;
        let limit = limit.min(self.slots.len() as u32);
        while pix < limit && pids.len() < max {
            if let Some(process) = self.load_slot(pix) {
                pids.push(process.pid);
            }
            pix += 1;
        }
        (pids, pix)
    }

    fn scheduler_shutdown(&self) {
        for pix in 0..self.ids.layout().max() {
            if let Some(process) = self.load_slot(pix) {
                lock_cell(&process).task_mut().scheduler_shutdown();
            }
        }
    }

    fn test_next_id(&self, set: bool, next: u64) -> u64 {
        // Port of erts/emulator/beam/erl_ptab.c:1356 (erts_ptab_test_next_id), OTP-29.1.1.
        let _exclusive = self.lock.write();
        self.ids
            .test_next_id(set, next, |pix| self.slot_occupied(pix))
    }
}

struct Scheduled<T: Task> {
    process: ProcRef<T>,
    /// `run_epoch` of the process when this entry was queued.
    epoch: u64,
    /// Port of erts/emulator/beam/erl_process.h (`Process.schedule_count`), OTP-29.1.1:
    /// times the entry reaches the head of the normal queue before it runs.
    schedule_count: u8,
}

impl<T: Task> Scheduled<T> {
    fn new(process: ProcRef<T>) -> Self {
        let epoch = process.run_epoch.load(Ordering::Acquire);
        // Port of erts/emulator/beam/erl_process.c:3957 (enqueue_process), OTP-29.1.1.
        let schedule_count = if process.priority() == Priority::Low {
            balance::RESCHEDULE_LOW
        } else {
            1
        };
        Self {
            process,
            epoch,
            schedule_count,
        }
    }

    /// Run queue priority queue of this entry: low priority processes share the normal
    /// queue (erl_process.c:3961, enqueue_process).
    fn queue(&self) -> usize {
        queue_index(self.process.priority().index())
    }
}

/// Port of erts/emulator/beam/erl_process.c:3961 (enqueue_process), OTP-29.1.1: the low
/// priority level has no queue of its own.
fn queue_index(priority: usize) -> usize {
    priority.min(balance::PRIORITY_NORMAL)
}

struct TimerService<M> {
    wheel: Wheel<M>,
    commands: Arc<SegQueue<TimerCommand<M>>>,
    canceled: Arc<SegQueue<CanceledTimer>>,
}

struct LocalInit<T: Task> {
    worker_id: usize,
    balance: Arc<balance::Balance>,
    timer_service: TimerService<T::Message>,
    queues: [Worker<Scheduled<T>>; 4],
    message_slabs: Vec<Vec<OwnedSignal<Event<T::Message>>>>,
    pending_waits: Vec<PendingWait<T>>,
    check_time_reds: u32,
    /// Port of erts/emulator/beam/erl_process.h (ErtsSchedulerData.last_monotonic_time),
    /// OTP-29.1.1: the time of this scheduler's latest clock read.
    last_monotonic_ms: u64,
    profile_active: bool,
    last_process: Option<Pid>,
    metric_deltas: Vec<i64>,
    dirty_metrics: Vec<usize>,
    metric_marked: Vec<bool>,
    context_switches: u64,
    reductions: u64,
    active_ns: u64,
    active_started: Option<Instant>,
    wall_enabled: bool,
    msacc_ns: [u64; MSACC_STATE_COUNT],
    msacc_state: MsaccState,
    msacc_started: Option<Instant>,
    msacc_enabled: bool,
}

impl<T: Task> LocalInit<T> {
    fn into_local(self) -> Local<T> {
        Local {
            worker_id: self.worker_id,
            balance: self.balance,
            timer_service: Rc::new(RefCell::new(self.timer_service)),
            queues: self.queues,
            pinned_turn: false,
            message_slabs: self.message_slabs,
            pending_waits: self.pending_waits,
            check_time_reds: self.check_time_reds,
            last_monotonic_ms: self.last_monotonic_ms,
            fix_shrink_due_ms: 0,
            fix_shrink_dealloc: false,
            profile_active: self.profile_active,
            last_process: self.last_process,
            metric_deltas: self.metric_deltas,
            dirty_metrics: self.dirty_metrics,
            metric_marked: self.metric_marked,
            context_switches: self.context_switches,
            reductions: self.reductions,
            active_ns: self.active_ns,
            active_started: self.active_started,
            wall_enabled: self.wall_enabled,
            msacc_ns: self.msacc_ns,
            msacc_state: self.msacc_state,
            msacc_started: self.msacc_started,
            msacc_enabled: self.msacc_enabled,
            wakeup_other: 0,
            wakeup_other_reds: 0,
        }
    }
}
struct SimState<T: Task> {
    queue: VecDeque<Scheduled<T>>,
    rng: Box<dyn Rng>,
}

use thr_progress::LaterOp;
pub use thr_progress::thread_progress_wait;

fn progress_wait<R>(wait: impl FnOnce() -> R) -> R {
    thr_progress::thread_progress_wait(wait)
}

/// Lock a task cell; a contended lock is waited for as a thread progress wait, so a
/// thread that blocks thread progress while its process holds the cell is not waiting on
/// this scheduler (erl_thr_progress.c:884-913, erts_thr_progress_prepare_wait /
/// finalize_wait around a blocking wait, OTP-29.1.1).
/// The receiver is not executing, so its heap stays put for the caller that holds
/// the main lock. `RUNNING` owns the cell for the whole slice. `EXITED` is gone.
/// A dirty job sets `dirty_runner`. `QUEUED` and `WAITING` are stable: collection
/// fetches the outer queue before it scans (erl_gc.c:987).
/// Port of erts/emulator/beam/erl_message.c:621 (`erts_try_alloc_message_on_heap`
/// try-locks the main lock and rejects a volatile heap), OTP-29.1.1.
fn receiver_heap_stable<T: Task>(process: &Process<T>) -> bool {
    let state = process.run_state().load(Ordering::Acquire);
    state != RUNNING && state != EXITED && process.dirty_runner.load(Ordering::Acquire) == 0
}

fn lock_cell<T: Task>(process: &Process<T>) -> parking_lot::MutexGuard<'_, TaskCell<T>> {
    match process.cell.try_lock() {
        Some(cell) => cell,
        None => progress_wait(|| process.cell.lock()),
    }
}

struct Inner<T: Task> {
    config: Config,
    table: ProcessTable<T>,
    /// Per-scheduler run queues for unbound processes enqueued from elsewhere; the owner
    /// drains its queue into its local deques and idle schedulers steal from it.
    run_queues: Vec<[SegQueue<Scheduled<T>>; 4]>,
    /// Priority queues of each run queue other threads appended to since its scheduler last
    /// took them over, one bit per queue.
    // Port of erts/emulator/beam/erl_process.h:134 (ERTS_RUNQ_FLGS_PROCS_QMASK bits in
    // `rq->flags`, set by erts_inc_runq_len), OTP-29.1.1.
    run_queue_flags: Vec<AtomicU32>,
    pinned_injectors: Vec<[SegQueue<Scheduled<T>>; 4]>,
    stealers: Vec<[Stealer<Scheduled<T>>; 4]>,
    sim_timers: Option<Vec<Mutex<Wheel<T::Message>>>>,
    timer_commands: Vec<Arc<SegQueue<TimerCommand<T::Message>>>>,
    canceled_timers: Vec<Arc<SegQueue<CanceledTimer>>>,
    next_timer: AtomicU64,
    clock: Arc<dyn Clock>,
    sim: Option<Mutex<SimState<T>>>,
    /// Scheduler data of the simulated scheduler, which runs on the stepping thread.
    sim_data: Mutex<T::SchedulerData>,
    stopped: AtomicBool,
    halt_started: AtomicBool,
    halt_requested: AtomicBool,
    runq_halting: Arc<[AtomicBool]>,
    searching: AtomicU32,
    active_schedulers: AtomicUsize,
    worker_stats: Vec<WorkerCounters>,
    stats_requests: Vec<SegQueue<mpsc::Sender<LocalStatsSnapshot>>>,
    aux_work: Vec<SegQueue<SchedulerAuxWork>>,
    /// Kinds of auxiliary work requested from each scheduler (`AUX_WORK_*` bits).
    // Port of erts/emulator/beam/erl_process.c:2665 and erl_process.h (`ssi->aux_work`
    // ERTS_SSI_AUX_WORK_* flags, read once per scheduling decision), OTP-29.1.1.
    aux_work_flags: Vec<AtomicU32>,
    accounting_flags: AtomicU8,
    worker_counts: Vec<WorkerQueueCount>,
    online_schedulers: AtomicUsize,
    next_queue: AtomicUsize,
    scheduling_blocked: AtomicBool,
    scheduling_blocker: AtomicUsize,
    started_at: Instant,
    wall_start_requests: Mutex<Vec<Option<Instant>>>,
    /// Per-run-queue publication count. An enqueue on scheduler A must not
    /// make scheduler B abandon `scheduler_wait` and steal.
    work_epochs: Vec<AtomicU64>,
    /// Set while this scheduler is between tasks (wakeup check through dequeue).
    /// A steal of that run queue fails, the way `erts_mtx_trylock` returns EBUSY
    /// while the owner holds the run-queue lock in `schedule`.
    in_schedule: Vec<AtomicBool>,
    parked: Arc<[AtomicBool]>,
    /// A scheduler asleep in the scheduler pollset instead of parked (`ERTS_SSI_FLG_POLL_SLEEPING`).
    poll_sleeping: Vec<AtomicBool>,
    /// Port of erts/emulator/beam/erl_process.c:342 (`no_waiting_scheds`), OTP-29.1.1.
    waiting_schedulers: AtomicUsize,
    sleepers: Arc<[OnceLock<thread::Thread>]>,
    fanin_stats: bool,
    fanin_delivered: AtomicU64,
    fanin_peak_backlog: AtomicUsize,
    /// erts thread progress (erl_thr_progress.c) of the normal scheduler threads.
    progress: Arc<thr_progress::ThrProgress>,
    /// Dirty CPU and dirty I/O pools, indexed by [`DirtyKind::index`].
    dirty: [DirtyPool<T>; 2],
    /// Scheduler type allowed to execute while multi-scheduling is blocked.
    /// Port of erts/emulator/beam/erl_process.c:7580 (msb_scheduler_type_switch), OTP-29.1.1.
    msb_exec: Mutex<MsbExec>,
    msb_switch: Condvar,
    /// The `erts_dirty_process_signal_handler` processes and their notification message.
    dirty_signal_handlers: OnceLock<DirtySignalHandlers<T::Message>>,
    /// Run queue balancing statistics and migration paths.
    balance: Arc<balance::Balance>,
    /// `rq->ports` of each normal run queue.
    port_queues: Vec<ports::PortQueue>,
}

/// What an idle scheduler stole from a victim run queue.
enum Stolen<T: Task> {
    /// A process to run now.
    Process(Scheduled<T>),
    /// A port, now queued on the stealing run queue.
    Port,
}

/// Normal, high and max priority dirty signal handler processes.
///
/// Port of erts/emulator/beam/erl_proc_sig_queue.c:84-86
/// (`erts_dirty_process_signal_handler`, `_high`, `_max`), OTP-29.1.1.
struct DirtySignalHandlers<M> {
    normal: Pid,
    high: Pid,
    max: Pid,
    /// Builds the message telling a handler which process needs its signals handled.
    message: Box<dyn Fn(Pid) -> Option<M> + Send + Sync>,
}

/// Which of normal scheduler 1, dirty CPU scheduler 1 and dirty I/O scheduler 1 executes
/// while multi-scheduling is blocked, plus the dirty type that ran last.
#[derive(Clone, Copy)]
struct MsbExec {
    current: SchedulerType,
    last_dirty: SchedulerType,
}

/// One dirty scheduler pool: a single run queue shared by all of its threads.
///
/// Port of erts/emulator/beam/erl_process.c:6050 (`ERTS_DIRTY_CPU_RUNQ`,
/// `ERTS_DIRTY_IO_RUNQ`), OTP-29.1.1.
struct DirtyPool<T: Task> {
    queue: Mutex<DirtyQueue<T>>,
    online: AtomicUsize,
    threads: Vec<DirtyThread>,
    /// Global dirty slot of this pool's first thread.
    first_slot: usize,
}

struct DirtyQueue<T: Task> {
    /// Sleeping dirty schedulers of this pool, the most recent last.
    /// Port of erts/emulator/beam/erl_process.c (`ErtsRunQueue.sleepers`), OTP-29.1.1.
    sleepers: VecDeque<usize>,
    /// Queued processes with their `schedule_count`; low priority shares the normal queue.
    by_priority: [VecDeque<(ProcRef<T>, u8)>; 4],
    len: usize,
}

impl<T: Task> DirtyQueue<T> {
    /// Port of erts/emulator/beam/erl_process.c:3951 (enqueue_process), OTP-29.1.1.
    fn push(&mut self, process: ProcRef<T>) {
        let priority = process.priority().index();
        let schedule_count = if priority == balance::PRIORITY_LOW {
            balance::RESCHEDULE_LOW
        } else {
            1
        };
        self.by_priority[queue_index(priority)].push_back((process, schedule_count));
        self.len += 1;
    }

    /// Port of erts/emulator/beam/erl_process.c:4040 (check_requeue_process) and
    /// erl_process.c:9988-10020 (pick_next_process), OTP-29.1.1.
    fn pop(&mut self) -> Option<ProcRef<T>> {
        let queue = self
            .by_priority
            .iter_mut()
            .find(|queue| !queue.is_empty())?;
        loop {
            let (process, mut schedule_count) = queue.pop_front()?;
            schedule_count = schedule_count.saturating_sub(1);
            if schedule_count > 0 && !queue.is_empty() {
                queue.push_back((process, schedule_count));
                continue;
            }
            self.len -= 1;
            return Some(process);
        }
    }
}

/// Active ns, microstate ns, and run queue length per dirty pool (CPU, then I/O).
type DirtyStatsSnapshot = ([Vec<u64>; 2], [Vec<[u64; MSACC_STATE_COUNT]>; 2], [u64; 2]);

struct DirtyThread {
    handle: OnceLock<thread::Thread>,
    /// Set by whoever wakes this scheduler; the spinning wait polls it.
    /// Port of erts/emulator/beam/erl_process.h (`ERTS_SSI_FLG_WAITING`), OTP-29.1.1.
    wake: AtomicBool,
    stats: Mutex<DirtyStats>,
}

/// Wall-time and microstate counters measured on one dirty scheduler thread.
struct DirtyStats {
    active_ns: u64,
    active_started: Option<Instant>,
    msacc_ns: [u64; MSACC_STATE_COUNT],
    msacc_state: MsaccState,
    msacc_started: Instant,
    /// Counters advance only while microstate accounting is on (`erts_msacc_enabled`).
    msacc_enabled: bool,
}

impl DirtyStats {
    fn new() -> Self {
        Self {
            active_ns: 0,
            active_started: None,
            msacc_ns: [0; MSACC_STATE_COUNT],
            msacc_state: MsaccState::Other,
            msacc_started: Instant::now(),
            msacc_enabled: false,
        }
    }

    /// Switch accounting on or off, closing the open segment when it goes off.
    // Port of erts/emulator/beam/erl_msacc.c (reply_msacc and the unmanaged-thread
    // ERTS_MSACC_DISABLE branch of erts_msacc_request), OTP-29.1.1: a thread that slept
    // through the window still has its sleep time counted.
    fn set_msacc_enabled(&mut self, enabled: bool) {
        if self.msacc_enabled == enabled {
            return;
        }
        let now = Instant::now();
        if self.msacc_enabled {
            let elapsed = now.duration_since(self.msacc_started).as_nanos();
            let counter = &mut self.msacc_ns[self.msacc_state as usize];
            *counter = counter.saturating_add(u64::try_from(elapsed).unwrap_or(u64::MAX));
        }
        self.msacc_started = now;
        self.msacc_enabled = enabled;
    }

    // Port of erts/emulator/beam/erl_msacc.h:300 (erts_msacc_set_state_m), OTP-29.1.1.
    // Counters only advance while microstate accounting is enabled.
    fn set_state(&mut self, state: MsaccState) {
        let now = Instant::now();
        if self.msacc_enabled {
            let elapsed = now.duration_since(self.msacc_started).as_nanos();
            let counter = &mut self.msacc_ns[self.msacc_state as usize];
            *counter = counter.saturating_add(u64::try_from(elapsed).unwrap_or(u64::MAX));
        }
        self.msacc_state = state;
        self.msacc_started = now;
    }

    fn begin_active(&mut self) {
        self.set_state(MsaccState::Emulator);
        self.active_started = Some(Instant::now());
    }

    fn end_active(&mut self) {
        if let Some(started) = self.active_started.take() {
            let elapsed = u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX);
            self.active_ns = self.active_ns.saturating_add(elapsed);
        }
        self.set_state(MsaccState::Other);
    }

    fn snapshot(&self) -> (u64, [u64; MSACC_STATE_COUNT]) {
        let active = self.active_started.map_or(self.active_ns, |started| {
            self.active_ns
                .saturating_add(u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX))
        });
        let mut msacc = self.msacc_ns;
        if self.msacc_enabled {
            let current =
                u64::try_from(self.msacc_started.elapsed().as_nanos()).unwrap_or(u64::MAX);
            msacc[self.msacc_state as usize] =
                msacc[self.msacc_state as usize].saturating_add(current);
        }
        (active, msacc)
    }
}

impl<T: Task> DirtyPool<T> {
    /// Wake the scheduler that went to sleep last, which is the one most likely still
    /// spinning; nothing when all are busy.
    // Port of erts/emulator/beam/erl_process.c (wake_dirty_scheduler: `sleepers.list->next`
    // is the most recently inserted sleeper), OTP-29.1.1.
    fn wake_one(&self, queue: &mut DirtyQueue<T>) {
        let online = self.online.load(Ordering::Acquire);
        let Some(position) = queue.sleepers.iter().rposition(|&index| index < online) else {
            return;
        };
        if let Some(index) = queue.sleepers.remove(position) {
            self.wake_thread(index);
        }
    }

    /// Wake every dirty scheduler of the pool so it re-checks its conditions.
    fn wake_all(&self) {
        let mut queue = self.queue.lock().unwrap();
        queue.sleepers.clear();
        drop(queue);
        for index in 0..self.threads.len() {
            self.wake_thread(index);
        }
    }

    fn wake_thread(&self, index: usize) {
        let thread = &self.threads[index];
        thread.wake.store(true, Ordering::SeqCst);
        if let Some(handle) = thread.handle.get() {
            handle.unpark();
        }
    }

    fn new(threads: usize, first_slot: usize) -> Self {
        Self {
            queue: Mutex::new(DirtyQueue {
                sleepers: VecDeque::new(),
                by_priority: std::array::from_fn(|_| VecDeque::new()),
                len: 0,
            }),
            online: AtomicUsize::new(threads),
            threads: (0..threads)
                .map(|_| DirtyThread {
                    handle: OnceLock::new(),
                    wake: AtomicBool::new(false),
                    stats: Mutex::new(DirtyStats::new()),
                })
                .collect(),
            first_slot,
        }
    }
}

#[repr(align(64))]
struct WorkerCounters {
    context_switches: AtomicU64,
    reductions: AtomicU64,
    active_ns: AtomicU64,
}

#[repr(align(64))]
struct WorkerQueueCount(AtomicU64);

#[derive(Clone, Default)]
struct LocalStatsSnapshot {
    context_switches: u64,
    reductions: u64,
    active_ns: u64,
    msacc_ns: [u64; MSACC_STATE_COUNT],
    metric_deltas: Vec<i64>,
}

impl<T: Task> Inner<T> {
    /// Send the monitor this scheduler holds for `to` before another send to `to` goes out.
    // Port of erts/emulator/beam/erl_proc_sig_queue.c (erts_proc_sig_send_pending via
    // proc_queue_signal: the pending signal goes first when the next signal has the same
    // receiver), OTP-29.1.1. Every send path must call it, message sends included.
    fn publish_held_monitor_for(&self, to: Pid, mut local: Option<&mut Local<T>>) {
        let Some(held) = take_held_monitor_for(to) else {
            return;
        };
        let PendingProcMonitor {
            from,
            to,
            id,
            shared,
        } = held;
        let delivered = self.table.lookup(to).is_some_and(|process| {
            self.deliver_process(
                &process,
                from,
                Payload::Signal(Signal::Monitor {
                    reference: id,
                    shared,
                }),
                local.as_deref_mut(),
                false,
                false,
            )
            .is_ok()
        });
        if !delivered {
            let _ = self.deliver(to, from, Payload::Signal(Signal::MonitorNoproc(id)), local);
        }
    }

    // Port of erts/emulator/beam/erl_process.c:6403 (schedule_dirty / enqueue on the
    // dirty run queue), OTP-29.1.1.
    fn enqueue_dirty(&self, process: ProcRef<T>, kind: DirtyKind) {
        process
            .dirty
            .store(kind.index() as u8 + 1, Ordering::Release);
        let pool = &self.dirty[kind.index()];
        if let Some(sim) = &self.sim {
            sim.lock().unwrap().queue.push_back(Scheduled::new(process));
            return;
        }
        {
            let mut queue = pool.queue.lock().unwrap();
            queue.push(process);
            // While multi-scheduling is blocked a wake-up is a state change for everyone.
            if self.scheduling_blocked.load(Ordering::Acquire) {
                drop(queue);
                pool.wake_all();
            } else {
                pool.wake_one(&mut queue);
            }
        }
        // While multi-scheduling is blocked the blocking scheduler hands execution over.
        if self.scheduling_blocked.load(Ordering::Acquire) {
            let blocker = self.scheduling_blocker.load(Ordering::Acquire);
            if let Some(thread) = self.sleepers.get(blocker).and_then(OnceLock::get) {
                thread.unpark();
            }
            self.interrupt_poll_sleeper(blocker);
        }
    }

    /// Highest dirty priority (lowest index) queued in `kind`'s pool.
    fn dirty_best_priority(&self, kind: DirtyKind) -> Option<usize> {
        let queue = self.dirty[kind.index()].queue.lock().unwrap();
        queue.by_priority.iter().position(|queue| !queue.is_empty())
    }

    /// Hand execution from the blocking normal scheduler to a dirty scheduler when dirty
    /// work of at least the normal work's priority is queued, and wait until it is back.
    ///
    /// Port of erts/emulator/beam/erl_process.c:7580-7700 (msb_scheduler_type_switch),
    /// OTP-29.1.1.
    fn msb_switch_to_dirty(&self, normal_prio: Option<usize>) -> bool {
        const NONE: usize = usize::MAX;
        let nrml = normal_prio.unwrap_or(NONE);
        let dcpu = self.dirty_best_priority(DirtyKind::Cpu).unwrap_or(NONE);
        let dio = self.dirty_best_priority(DirtyKind::Io).unwrap_or(NONE);
        if dcpu == NONE && dio == NONE {
            return false;
        }
        let mut exec = SchedulerType::Normal;
        if dcpu < nrml {
            exec = if dio < dcpu {
                SchedulerType::DirtyIo
            } else {
                SchedulerType::DirtyCpu
            };
        } else if dio < nrml {
            exec = SchedulerType::DirtyIo;
        }
        if exec == SchedulerType::Normal {
            if dcpu == nrml {
                exec = SchedulerType::DirtyCpu;
            } else if dio == nrml {
                exec = SchedulerType::DirtyIo;
            } else {
                return false;
            }
        }
        let mut state = self.msb_exec.lock().unwrap();
        if dio == dcpu {
            exec = if state.last_dirty == SchedulerType::DirtyIo {
                SchedulerType::DirtyCpu
            } else {
                SchedulerType::DirtyIo
            };
        }
        state.current = exec;
        state.last_dirty = exec;
        // Dirty threads check `msb_exec` while holding their pool lock; never hold both here.
        drop(state);
        let kind = if exec == SchedulerType::DirtyCpu {
            DirtyKind::Cpu
        } else {
            DirtyKind::Io
        };
        self.dirty[kind.index()].wake_all();
        let mut state = self.msb_exec.lock().unwrap();
        while state.current != SchedulerType::Normal
            && self.scheduling_blocked.load(Ordering::Acquire)
            && !self.stopped.load(Ordering::Acquire)
        {
            state = self
                .msb_switch
                .wait_timeout(state, Duration::from_millis(10))
                .unwrap()
                .0;
        }
        state.current = SchedulerType::Normal;
        true
    }

    /// Whether dirty thread `index` of `kind` may execute a job now.
    fn dirty_may_execute(&self, kind: DirtyKind, index: usize) -> bool {
        if !self.scheduling_blocked.load(Ordering::Acquire) {
            return true;
        }
        index == 0 && self.msb_exec.lock().unwrap().current == SchedulerType::from(kind)
    }

    /// After one dirty job under blocked multi-scheduling, return to the normal scheduler.
    fn msb_dirty_done(&self, kind: DirtyKind) {
        let mut state = self.msb_exec.lock().unwrap();
        if state.current == SchedulerType::from(kind) {
            state.current = SchedulerType::Normal;
            self.msb_switch.notify_all();
        }
    }

    /// Port of erts/emulator/beam/erl_process.h:1367 (`ERTS_PROC_IN_DIRTY_STATE`), OTP-29.1.1:
    /// queued on or executing on a dirty scheduler.
    fn in_dirty_state(process: &Process<T>) -> bool {
        process.dirty.load(Ordering::SeqCst) != 0
            || process.dirty_runner.load(Ordering::SeqCst) != 0
    }

    /// Ask a dirty signal handler to handle the signals of `process`, which is in a dirty
    /// state. `priority` overrides the process's user priority.
    ///
    /// Port of erts/emulator/beam/erl_proc_sig_queue.c:979 (notify_dirty_signal_handler) and
    /// erl_proc_sig_queue.c:1039 (erts_ensure_dirty_proc_signals_handled), OTP-29.1.1.
    fn notify_dirty_signal_handler(&self, process: &Process<T>, priority: Option<Priority>) {
        let Some(handlers) = self.dirty_signal_handlers.get() else {
            return;
        };
        let priority = priority
            .unwrap_or_else(|| Priority::from_index(process.user_priority.load(Ordering::Acquire)));
        let handler = match priority {
            Priority::Max => handlers.max,
            Priority::High => handlers.high,
            Priority::Normal | Priority::Low => handlers.normal,
        };
        if let Some(message) = (handlers.message)(process.pid) {
            let _ = self.deliver(process.pid, handler, Payload::Message(message), None);
        }
    }

    fn dirty_stats(&self) -> DirtyStatsSnapshot {
        let mut active = [Vec::new(), Vec::new()];
        let mut msacc = [Vec::new(), Vec::new()];
        let mut lengths = [0; 2];
        for (index, pool) in self.dirty.iter().enumerate() {
            for thread in &pool.threads {
                let (thread_active, thread_msacc) = thread.stats.lock().unwrap().snapshot();
                active[index].push(thread_active);
                msacc[index].push(thread_msacc);
            }
            lengths[index] = pool.queue.lock().unwrap().len as u64;
        }
        (active, msacc, lengths)
    }

    fn request_aux_work_one(&self, worker: usize, work: SchedulerAuxWork) {
        let Some(queue) = self.aux_work.get(worker) else {
            return;
        };
        queue.push(work);
        self.aux_work_flags[worker].fetch_or(AUX_WORK_FUNC, Ordering::Release);
        self.wake_worker(worker);
    }

    /// Take the auxiliary work flags of `worker`; work requested after this sets them again.
    fn take_aux_work(&self, worker: usize) -> u32 {
        let flags = self.aux_work_flags[worker].load(Ordering::Acquire);
        if flags != 0 {
            self.aux_work_flags[worker].fetch_and(!flags, Ordering::AcqRel);
        }
        flags
    }

    fn request_aux_work_all(&self, work: SchedulerAuxWork) {
        for worker in 0..self.aux_work.len() {
            self.request_aux_work_one(worker, Arc::clone(&work));
        }
    }

    fn begin_halt(
        &self,
        pid: Pid,
        code: i32,
        timeout: Option<(u64, TimerCallback<T::Message>)>,
        actions: HaltActions,
        local: Option<&mut Local<T>>,
    ) -> bool {
        if self
            .halt_started
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return false;
        }
        let HaltActions {
            start,
            reap,
            complete,
        } = actions;
        let state = HaltProgress(Arc::new(HaltState {
            progress: AtomicI32::new(self.runq_halting.len() as i32),
            code,
            reap: Mutex::new(Some(reap)),
            complete: Mutex::new(Some(complete)),
        }));
        if let Some((ms, callback)) = timeout {
            let _ = self.start_timer(pid, ms, TimerPayload::Callback(pid, callback), local, None);
        }
        self.halt_requested.store(true, Ordering::Release);
        start();
        for pool in &self.dirty {
            pool.wake_all();
        }
        let halting = Arc::clone(&self.runq_halting);
        self.request_aux_work_all(Arc::new(move |worker| {
            halting[worker].store(true, Ordering::Release);
            state.scheduler_reached_halt();
        }));
        true
    }

    // Port of erts/emulator/beam/erl_process.c:2665 (handle_aux_work), OTP-29.1.1.
    fn handle_aux_work(&self, worker: usize) {
        while let Some(work) = self.aux_work[worker].pop() {
            work(worker);
        }
    }

    fn handle_local_aux_work(&self, worker: usize, local: &mut Local<T>, aux_work: u32) {
        // Port of erts/emulator/beam/erl_process.c:9803-9810 (schedule: a busy scheduler reads
        // the monotonic clock only once check_time_reds reaches ERTS_CHECK_TIME_REDS and bumps
        // its timers with that time), OTP-29.1.1. Receive timeouts are checked before the
        // timer wheel resets check_time_reds.
        // The scheduler loop polls them again right after this call with the cached time, so a
        // round without aux work and without a halt leaves them to that poll.
        let halting = self.halt_requested.load(Ordering::Acquire);
        if aux_work != 0 || halting {
            if !halting {
                self.poll_pending_waits(local, false);
            }
            // Port of erts/emulator/beam/erl_process.c:2719 (canceled timers before
            // debug-wait completion), OTP-29.1.1.
            self.poll_timers(worker, Some(local), halting);
        }
        if aux_work & AUX_WORK_FUNC != 0 {
            self.handle_aux_work(worker);
        }
    }

    fn wake_waiting(&self, pid: Pid) -> bool {
        let Some(process) = self.table.lookup(pid) else {
            return false;
        };
        if process
            .run_state()
            .compare_exchange(WAITING, QUEUED, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return false;
        }
        let wait_timer = process.wait_timer.load(Ordering::Acquire);
        if wait_timer != 0 {
            process.wait_epoch.fetch_add(1, Ordering::AcqRel);
            self.cancel_wait_timer(&process, wait_timer);
        }
        self.enqueue(Scheduled::new(process), false);
        true
    }

    fn fanin_delivery(&self, process: &Process<T>, count: usize) {
        if !self.fanin_stats {
            return;
        }
        let backlog = process.input.backlog.load(Ordering::Relaxed);
        self.fanin_peak_backlog
            .fetch_max(backlog, Ordering::Relaxed);
        let delivered = self
            .fanin_delivered
            .fetch_add(count as u64, Ordering::Relaxed)
            + count as u64;
        if delivered.is_multiple_of(250_000)
            || delivered / 250_000 > (delivered - count as u64) / 250_000
        {
            eprintln!(
                "ARINSAL_SCHED_STATS delivered={delivered} live={} target_backlog={backlog} peak_backlog={} process_peak_rss_mib={}",
                self.table.live_count(),
                self.fanin_peak_backlog.load(Ordering::Relaxed),
                process_peak_rss_bytes().map_or_else(
                    || "unavailable".to_owned(),
                    |bytes| format!("{:.1}", bytes as f64 / 1_048_576.0)
                )
            );
        }
    }

    /// Run queue a runnable process joins.
    ///
    /// Port of erts/emulator/beam/erl_process.c:6631 (select_enqueue_run_queue), OTP-29.1.1:
    /// an unbound process joins the run queue it last ran on (`p->run_queue`); a run queue
    /// that is offline or blocked by multi-scheduling emigrates its work to an online one.
    fn select_run_queue(&self, process: &Process<T>) -> usize {
        // Port of erts/emulator/beam/erl_process.c:8484-8540 (erts_block_multi_scheduling), OTP-29.1.1.
        if self.scheduling_blocked.load(Ordering::Acquire) {
            return self
                .scheduling_blocker
                .load(Ordering::Acquire)
                .min(self.worker_counts.len() - 1);
        }
        let online = self.online_schedulers.load(Ordering::Relaxed).max(1);
        let home = process
            .scheduler_id
            .load(Ordering::Relaxed)
            .min(self.worker_counts.len() - 1);
        if home < online { home } else { home % online }
    }

    /// Normal scheduler running on the current thread, if any.
    fn current_worker(&self) -> Option<usize> {
        let inner_id = self as *const Self as usize;
        OWNER_TIMER_SERVICES
            .try_with(|services| services.borrow().get(&inner_id).map(|(id, _)| *id))
            .ok()
            .flatten()
    }

    /// Port of erts/emulator/beam/erl_process.c:6868 (add2runq) and 6631
    /// (select_enqueue_run_queue), OTP-29.1.1: enqueue on the process's own run
    /// queue (`p->run_queue`), changed only by migration, emigration, or binding.
    /// `smp_notify_inc_runq` wakes that run queue's scheduler only if it sleeps.
    /// Another scheduler takes the process by `try_steal_task` after it ran out of
    /// work, or by `wakeup_other_check` once the surplus passes the limit.
    fn enqueue(&self, item: Scheduled<T>, already_active: bool) {
        if let Some(sim) = &self.sim {
            let scheduler = self.select_run_queue(&item.process);
            self.record_queued(&item.process, scheduler, already_active);
            sim.lock().unwrap().queue.push_back(item);
        } else if let Some(worker) = item.process.bound_worker() {
            self.record_queued(&item.process, worker, already_active);
            let queue = item.queue();
            self.pinned_injectors[worker][queue].push(item);
            self.run_queue_flags[worker]
                .fetch_or(1 << (PINNED_FLAGS_SHIFT + queue as u32), Ordering::Release);
            self.note_queued(worker);
            self.wake_scheduler(worker);
        } else {
            let scheduler = self.enqueue_run_queue(&item.process);
            self.push_run_queue(scheduler, item, already_active);
        }
    }

    /// Port of erts/emulator/beam/erl_process.c:6656-6672 (select_enqueue_run_queue for
    /// the normal queue), OTP-29.1.1: the process's run queue, unless the migration paths
    /// tell it to emigrate.
    fn enqueue_run_queue(&self, process: &Process<T>) -> usize {
        let runq = self.select_run_queue(process);
        if self.scheduling_blocked.load(Ordering::Acquire) {
            return runq;
        }
        match self
            .balance
            .check_emigration_need(runq, process.priority().index())
        {
            Some(to) if to < self.online_schedulers.load(Ordering::Acquire) => to,
            _ => runq,
        }
    }

    /// The entry is the process's live run queue entry, not a stale duplicate.
    fn is_current_entry(item: &Scheduled<T>) -> bool {
        item.process.run_epoch.load(Ordering::Acquire) == item.epoch
            && item.process.run_state().load(Ordering::Acquire) == QUEUED
    }

    /// Port of erts/emulator/beam/erl_process.c:4115 (immigrate), OTP-29.1.1: for each
    /// priority this run queue immigrates, move one process of that priority from the
    /// source run queue when check_immigration_need says so.
    fn immigrate(&self, local: &mut Local<T>) {
        let id = local.worker_id;
        let paths = self.balance.migration_paths();
        let mp = &paths[id];
        for prio in 0..balance::PRIO_LEVELS {
            if mp.flags & balance::flg_immigrate(prio) == 0 {
                continue;
            }
            let Some(from) = self.balance.check_immigration_need(id, mp, prio) else {
                continue;
            };
            if from == id || from >= self.stealers.len() {
                continue;
            }
            if prio == balance::PORT_PRIO_LEVEL {
                self.move_port(from, id);
                continue;
            }
            let queue = queue_index(prio);
            let Some(item) = self.take_queued(from, queue) else {
                continue;
            };
            if item.process.priority().index() != prio {
                // Low and normal share the queue; erts skips entries of the other level
                // and leaves them in the source run queue.
                self.inject(from, queue, item);
                continue;
            }
            if Self::is_current_entry(&item) {
                local.migrate_queued(&item.process, id);
            }
            local.queues[queue].push(item);
        }
    }

    /// The run queue a port joins: its own run queue unless the migration paths tell it
    /// to emigrate. Updates `prt->run_queue`.
    ///
    /// Port of erts/emulator/beam/erl_port_task.c:1580-1592 (erts_port_task_schedule) and
    /// erl_port_task.c:1886-1906 (erts_port_task_execute re-enqueue), OTP-29.1.1.
    fn port_enqueue_run_queue(&self, port: &dyn RunPort) -> usize {
        let last = self.port_queues.len() - 1;
        let runq = if self.scheduling_blocked.load(Ordering::Acquire) {
            // erl_process.c:8484 (erts_block_multi_scheduling): the other run queues are
            // evacuated to the blocking scheduler's run queue.
            self.scheduling_blocker.load(Ordering::Acquire).min(last)
        } else {
            let online = self.online_schedulers.load(Ordering::Acquire).max(1);
            let runq = port.run_queue().get().min(last);
            match self
                .balance
                .check_emigration_need(runq, balance::PORT_PRIO_LEVEL)
            {
                Some(to) if to < online => to,
                _ if runq >= online => runq % online,
                _ => runq,
            }
        };
        port.run_queue().set(runq);
        runq
    }

    /// Put a port with scheduled tasks on its run queue and notify the run queue's
    /// scheduler.
    ///
    /// Port of erts/emulator/beam/erl_port_task.c:1576-1598 (erts_port_task_schedule:
    /// enqueue port on run-queue), OTP-29.1.1.
    fn enqueue_port(&self, port: Arc<dyn RunPort>) {
        let runq = self.port_enqueue_run_queue(&*port);
        self.port_queues[runq].enqueue(&self.balance.rqs[runq], port);
        // Publish the queue change before a parker's final epoch check.
        self.note_queued(runq);
        self.wake_scheduler(runq);
    }

    /// Execute the first port of this scheduler's run queue, if any.
    ///
    /// Port of erts/emulator/beam/erl_port_task.c:1677 (erts_port_task_execute: pop_port,
    /// re-enqueue and ERTS_PORT_REDUCTIONS_EXECUTED), OTP-29.1.1.
    fn execute_port(&self, local: &mut Local<T>) -> bool {
        let id = local.worker_id;
        let Some(port) = self.port_queues[id].pop(&self.balance.rqs[id]) else {
            return false;
        };
        local.set_msacc_state(MsaccState::Port);
        let PortExecution { active, reds } = port.execute();
        local.set_msacc_state(MsaccState::Other);
        if active {
            let runq = self.port_enqueue_run_queue(&*port);
            self.port_queues[runq].enqueue(&self.balance.rqs[runq], port);
            if runq != id {
                // Emigrate port; no need to notify ourselves about an increase in our own
                // run queue.
                self.note_queued(runq);
                self.wake_scheduler(runq);
            }
        }
        let reds = reds.max(0);
        local.reductions += reds as u64;
        self.balance.rqs[id].reductions_executed(balance::PORT_PRIO_LEVEL, i64::from(reds));
        local.wakeup_other_reds += i64::from(reds);
        local.check_time_reds = local.check_time_reds.saturating_add(reds as u32);
        true
    }

    /// Move the first port of run queue `from` to run queue `to`.
    ///
    /// Port of erts/emulator/beam/erl_process.c:4160-4174 (immigrate),
    /// erl_process.c:4603-4614 (try_steal_task_from_victim) and erl_process.c:4351-4372
    /// (evacuate_run_queue) port parts, OTP-29.1.1.
    fn move_port(&self, from: usize, to: usize) -> bool {
        let Some(port) = self.port_queues[from].pop(&self.balance.rqs[from]) else {
            return false;
        };
        port.run_queue().set(to);
        self.port_queues[to].enqueue(&self.balance.rqs[to], port);
        true
    }

    /// Take the oldest entry of priority queue `queue` of run queue `rq`.
    fn take_queued(&self, rq: usize, queue: usize) -> Option<Scheduled<T>> {
        for _ in 0..8 {
            match self.stealers[rq][queue].steal() {
                Steal::Success(found) => return Some(found),
                Steal::Empty => break,
                Steal::Retry => {}
            }
        }
        self.run_queues[rq][queue].pop()
    }

    /// Port of erts/emulator/beam/erl_process.c:4640 (try_steal_task), OTP-29.1.1: an
    /// active run queue that ran out of work steals from the inactive run queues first and
    /// then from the other active ones, starting after its own index.
    fn try_steal_task(&self, local: &mut Local<T>) -> Option<Stolen<T>> {
        let id = local.worker_id;
        let (active, used) = self.balance.no_runqs();
        let used = used
            .min(self.online_schedulers.load(Ordering::Acquire))
            .clamp(1, self.stealers.len());
        let active = active.min(used);
        if id >= active {
            return None;
        }
        if active < used {
            let no = used - active;
            let stop = active + id % no;
            let mut vix = stop;
            loop {
                if let Some(found) = self.try_steal_task_from_victim(local, vix) {
                    return Some(found);
                }
                vix += 1;
                if vix >= used {
                    vix = active;
                }
                if vix == stop {
                    break;
                }
            }
        }
        let mut vix = id;
        loop {
            vix += 1;
            if vix >= active {
                vix = 0;
            }
            if vix == id {
                break;
            }
            if let Some(found) = self.try_steal_task_from_victim(local, vix) {
                return Some(found);
            }
        }
        None
    }

    /// Port of erts/emulator/beam/erl_process.c:4468 (try_steal_task_from_victim),
    /// OTP-29.1.1: steal half of the highest priority queue of the victim, at least one
    /// and at most 100 processes, run the first and queue the rest here. A victim without
    /// processes gives up its first runnable port instead.
    fn try_steal_task_from_victim(&self, local: &mut Local<T>, vix: usize) -> Option<Stolen<T>> {
        // Port of erts/emulator/beam/erl_process.c:4631 (check_possible_steal_victim
        // trylock EBUSY), OTP-29.1.1: skip a victim that is in schedule().
        if self
            .in_schedule
            .get(vix)
            .is_some_and(|flag| flag.load(Ordering::Acquire))
        {
            return None;
        }
        let id = local.worker_id;
        let rq = &self.balance.rqs[vix];
        for queue in 0..PROC_QUEUES {
            let mut len = rq.len(queue);
            if queue == balance::PRIORITY_NORMAL {
                len += rq.len(balance::PRIORITY_LOW);
            }
            if len <= 0
                && self.stealers[vix][queue].is_empty()
                && self.run_queues[vix][queue].is_empty()
            {
                continue;
            }
            let max = (len.max(0) as usize).div_ceil(2).clamp(1, 100);
            let mut first = None;
            for _ in 0..max {
                let Some(found) = self.take_queued(vix, queue) else {
                    break;
                };
                if first.is_none() {
                    first = Some(found);
                } else {
                    if Self::is_current_entry(&found) {
                        local.migrate_queued(&found.process, id);
                    }
                    local.queues[queue].push(found);
                }
            }
            if let Some(first) = first {
                return Some(Stolen::Process(first));
            }
        }
        // Port of erts/emulator/beam/erl_process.c:4603-4614 (check for a runnable port to
        // steal), OTP-29.1.1.
        if rq.len(balance::PORT_PRIO_LEVEL) > 0 && self.move_port(vix, id) {
            return Some(Stolen::Port);
        }
        None
    }

    /// Publish that `worker`'s run queue changed. Only that scheduler's sleep
    /// check observes it. Another scheduler stays in `scheduler_wait` until
    /// `wake_scheduler` or `wakeup_other_check` pokes it.
    ///
    /// Port of erts/emulator/beam/erl_process.c:3914 (smp_notify_inc_runq), OTP-29.1.1.
    fn note_queued(&self, worker: usize) {
        if let Some(epoch) = self.work_epochs.get(worker) {
            epoch.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// Enqueue an unbound process on `scheduler`'s run queue.
    /// Append `item` to priority queue `queue` of run queue `rq` and flag that queue.
    fn inject(&self, rq: usize, queue: usize, item: Scheduled<T>) {
        self.run_queues[rq][queue].push(item);
        self.run_queue_flags[rq].fetch_or(1 << queue, Ordering::Release);
    }

    /// Move what other threads appended to this scheduler's run queue into its local deques.
    // Port of erts/emulator/beam/erl_process.c:9824 (schedule: the run queue's
    // ERTS_RUNQ_FLGS_PROCS_QMASK flags say which priority queues hold processes), OTP-29.1.1.
    #[inline]
    fn take_injected(&self, local: &mut Local<T>) {
        let flags = self.run_queue_flags[local.worker_id].load(Ordering::Acquire)
            & ((1 << PINNED_FLAGS_SHIFT) - 1);
        if flags != 0 {
            self.drain_injected(local, flags);
        }
    }

    #[inline(never)]
    fn drain_injected(&self, local: &mut Local<T>, flags: u32) {
        let id = local.worker_id;
        // Clear before draining: an append that races with the drain sets its bit again.
        self.run_queue_flags[id].fetch_and(!flags, Ordering::AcqRel);
        for priority in 0..local.queues.len() {
            if flags & (1 << priority) != 0 {
                while let Some(found) = self.run_queues[id][priority].pop() {
                    local.queues[priority].push(found);
                }
            }
        }
    }

    fn push_run_queue(&self, scheduler: usize, item: Scheduled<T>, already_active: bool) {
        self.record_queued(&item.process, scheduler, already_active);
        self.inject(scheduler, item.queue(), item);
        // Publish the queue change before a parker's final epoch check.
        self.note_queued(scheduler);
        self.wake_scheduler(scheduler);
    }

    /// A process created outside any parent joins the current scheduler's run queue.
    ///
    /// Port of erts/emulator/beam/erl_process.c:12525-12531 (erl_create_process), OTP-29.1.1.
    /// A thread that is not a scheduler has no run queue of its own and spreads
    /// new processes across the online run queues.
    ///
    /// Port of erts/emulator/beam/erl_process.c:12525-12531 (erl_create_process), OTP-29.1.1.
    fn enqueue_new(&self, item: Scheduled<T>) {
        if self.sim.is_some() || item.process.bound_worker().is_some() {
            self.enqueue(item, false);
            return;
        }
        let online = self.online_schedulers.load(Ordering::Relaxed).max(1);
        let scheduler = self
            .current_worker()
            .unwrap_or_else(|| self.next_queue.fetch_add(1, Ordering::Relaxed))
            % online;
        item.process
            .scheduler_id
            .store(scheduler, Ordering::Relaxed);
        let scheduler = self.enqueue_run_queue(&item.process);
        self.push_run_queue(scheduler, item, false);
    }

    // Port of erts/emulator/beam/erl_process.c:9281 (erts_run_queues_len), OTP-29.1.1.
    fn record_queued(&self, process: &Process<T>, worker: usize, already_active: bool) {
        // Simulation runs one worker but keeps the configured scheduler ids.
        let worker = worker.min(self.worker_counts.len() - 1);
        let previous = process
            .scheduler_id
            .load(Ordering::Relaxed)
            .min(self.worker_counts.len() - 1);
        if already_active && previous != worker {
            self.worker_counts[previous]
                .0
                .fetch_sub(1, Ordering::Relaxed);
            self.worker_counts[worker]
                .0
                .fetch_add(QUEUE_COUNT_UNIT + 1, Ordering::Relaxed);
        } else {
            self.worker_counts[worker].0.fetch_add(
                QUEUE_COUNT_UNIT + u64::from(!already_active),
                Ordering::Relaxed,
            );
        }
        process.scheduler_id.store(worker, Ordering::Relaxed);
        self.balance
            .enqueued(process.priority().index(), &process.queued_prio, worker);
    }

    fn record_running(&self, process: &Process<T>, worker: usize) {
        let previous = process
            .scheduler_id
            .load(Ordering::Relaxed)
            .min(self.worker_counts.len() - 1);
        self.balance.dequeued(&process.queued_prio, previous);
        if previous == worker {
            self.worker_counts[worker]
                .0
                .fetch_sub(QUEUE_COUNT_UNIT, Ordering::Relaxed);
        } else {
            self.worker_counts[previous]
                .0
                .fetch_sub(QUEUE_COUNT_UNIT + 1, Ordering::Relaxed);
            self.worker_counts[worker].0.fetch_add(1, Ordering::Relaxed);
        }
        process.scheduler_id.store(worker, Ordering::Relaxed);
    }

    fn record_waiting(&self, process: &Process<T>) {
        let worker = process
            .scheduler_id
            .load(Ordering::Relaxed)
            .min(self.worker_counts.len() - 1);
        self.worker_counts[worker].0.fetch_sub(1, Ordering::Relaxed);
    }

    // Port of erts/emulator/beam/erl_process.c:5476-5510 (change_no_used_runqs), OTP-29.1.1.
    fn evacuate_offline_local(&self, local: &mut Local<T>) {
        let online = self.online_schedulers.load(Ordering::Acquire).max(1);
        // Port of erts/emulator/beam/erl_process.c (erts_block_multi_scheduling), OTP-29.1.1:
        // while multi-scheduling is blocked, all work moves to the blocking scheduler.
        let blocker = self
            .scheduling_blocked
            .load(Ordering::Acquire)
            .then(|| self.scheduling_blocker.load(Ordering::Acquire))
            .filter(|blocker| *blocker < online);
        // Port of erts/emulator/beam/erl_process.c:5503 (change_no_used_runqs evacuation
        // target `qix % used`), OTP-29.1.1.
        let target = blocker.unwrap_or(local.worker_id % online);
        // Port of erts/emulator/beam/erl_process.c:4305 (evacuate_run_queue), OTP-29.1.1.
        let worker = local.worker_id;
        if target != worker {
            // Port of erts/emulator/beam/erl_process.c:4351-4372 (evacuate scheduled
            // ports), OTP-29.1.1.
            let mut evacuated = false;
            while self.move_port(worker, target) {
                evacuated = true;
            }
            if evacuated {
                self.note_queued(target);
                self.wake_scheduler(target);
            }
        }
        let mut moved = Vec::new();
        for priority in 0..local.queues.len() {
            while let Some(item) = self.run_queues[worker][priority].pop() {
                moved.push(item);
            }
            while let Some(item) = local.queues[priority].pop() {
                moved.push(item);
            }
        }
        if target != worker {
            // Bound entries sit in the pinned injectors, not the ordinary run queue.
            // Leave them there and the blocked scheduler parks with the only copy of
            // the process (erl_process.c evacuate_run_queue moves every entry).
            for priority in 0..self.pinned_injectors[worker].len() {
                while let Some(item) = self.pinned_injectors[worker][priority].pop() {
                    moved.push(item);
                }
            }
        }
        for item in moved {
            if Self::is_current_entry(&item) {
                local.migrate_queued(&item.process, target);
            }
            self.inject(target, item.queue(), item);
            self.note_queued(target);
            self.wake_scheduler(target);
        }
    }

    fn take_wall_start(&self, worker: usize) -> Option<Instant> {
        self.wall_start_requests
            .lock()
            .expect("wall start requests")
            .get_mut(worker)
            .and_then(Option::take)
    }

    fn flush_local_metrics(&self, _local: &mut Local<T>) {
        // Worker-owned deltas remain local; statistics readers aggregate them on demand.
    }

    /// Queued ports of each run queue (`rq->ports.info.len`, part of `rq->len` in
    /// erl_process.c:9240 run_queues_len_aux).
    fn queued_ports(&self) -> Vec<u64> {
        (0..self.worker_counts.len())
            .map(|ix| {
                self.balance
                    .rqs
                    .get(ix)
                    .map_or(0, |rq| rq.len(balance::PORT_PRIO_LEVEL).max(0) as u64)
            })
            .collect()
    }

    fn simulation_stats(&self) -> SchedulerStats {
        let counts: Vec<u64> = self
            .worker_counts
            .iter()
            .map(|value| value.0.load(Ordering::Relaxed))
            .collect();
        let dirty = self.dirty_stats();
        let ports = self.queued_ports();
        SchedulerStats {
            run_queue_lengths: counts
                .iter()
                .zip(&ports)
                .map(|(value, ports)| (value >> QUEUE_COUNT_SHIFT) + ports)
                .collect(),
            active_tasks: counts
                .iter()
                .zip(&ports)
                .map(|(value, ports)| (value & (QUEUE_COUNT_UNIT - 1)) + ports)
                .collect(),
            active_ns: self
                .worker_stats
                .iter()
                .map(|value| value.active_ns.load(Ordering::Relaxed))
                .collect(),
            msacc_ns: vec![[0; MSACC_STATE_COUNT]; self.worker_stats.len()],
            context_switches: self
                .worker_stats
                .iter()
                .map(|value| value.context_switches.load(Ordering::Relaxed))
                .sum(),
            reductions: self
                .worker_stats
                .iter()
                .map(|value| value.reductions.load(Ordering::Relaxed))
                .sum(),
            active_schedulers: self.active_schedulers.load(Ordering::Relaxed) as u64,
            elapsed_ns: u64::try_from(self.started_at.elapsed().as_nanos()).unwrap_or(u64::MAX),
            dirty_active_ns: dirty.0,
            dirty_msacc_ns: dirty.1,
            dirty_run_queue_lengths: dirty.2,
        }
    }

    fn scheduler_stats(
        &self,
        current: Option<&Local<T>>,
        current_reductions: u64,
    ) -> SchedulerStats {
        if self.sim.is_some() {
            return self.simulation_stats();
        }
        let accounting_flags = self.accounting_flags.load(Ordering::Relaxed);
        let msacc_enabled = accounting_flags & ACCOUNTING_MSACC != 0;
        let wall_enabled = accounting_flags & ACCOUNTING_WALL != 0;
        let mut snapshots = Vec::with_capacity(self.stats_requests.len());
        for worker in 0..self.stats_requests.len() {
            if current.is_some_and(|local| local.worker_id == worker) {
                snapshots.push(
                    current
                        .expect("current worker checked")
                        .stats_snapshot(msacc_enabled, wall_enabled),
                );
                continue;
            }
            let (reply, receive) = mpsc::channel();
            self.stats_requests[worker].push(reply);
            self.aux_work_flags[worker].fetch_or(AUX_WORK_STATS, Ordering::Release);
            self.wake_worker(worker);
            // Two schedulers collecting statistics at once wait on each other, so the
            // waiting scheduler keeps answering requests addressed to it.
            let snapshot = progress_wait(|| {
                loop {
                    if let Some(local) = current {
                        while let Some(request) = self.stats_requests[local.worker_id].pop() {
                            let _ = request.send(
                                local.stats_snapshot(local.msacc_enabled, local.wall_enabled),
                            );
                        }
                    }
                    match receive.recv_timeout(Duration::from_millis(1)) {
                        Ok(snapshot) => break snapshot,
                        Err(mpsc::RecvTimeoutError::Timeout) => {}
                        Err(mpsc::RecvTimeoutError::Disconnected) => break Default::default(),
                    }
                }
            });
            snapshots.push(snapshot);
        }
        let mut counts: Vec<u64> = self
            .worker_counts
            .iter()
            .map(|value| value.0.load(Ordering::Relaxed))
            .collect();
        for snapshot in &snapshots {
            for (count, delta) in counts.iter_mut().zip(&snapshot.metric_deltas) {
                *count = count.wrapping_add(*delta as u64);
            }
        }
        let dirty = self.dirty_stats();
        let ports = self.queued_ports();
        SchedulerStats {
            run_queue_lengths: counts
                .iter()
                .zip(&ports)
                .map(|(value, ports)| (value >> QUEUE_COUNT_SHIFT) + ports)
                .collect(),
            active_tasks: counts
                .iter()
                .zip(&ports)
                .map(|(value, ports)| (value & (QUEUE_COUNT_UNIT - 1)) + ports)
                .collect(),
            active_ns: snapshots
                .iter()
                .map(|snapshot| snapshot.active_ns)
                .collect(),
            msacc_ns: snapshots.iter().map(|snapshot| snapshot.msacc_ns).collect(),
            context_switches: snapshots
                .iter()
                .map(|snapshot| snapshot.context_switches)
                .sum(),
            reductions: snapshots
                .iter()
                .map(|snapshot| snapshot.reductions)
                .sum::<u64>()
                .saturating_add(current_reductions),
            active_schedulers: self.active_schedulers.load(Ordering::Relaxed) as u64,
            elapsed_ns: u64::try_from(self.started_at.elapsed().as_nanos()).unwrap_or(u64::MAX),
            dirty_active_ns: dirty.0,
            dirty_msacc_ns: dirty.1,
            dirty_run_queue_lengths: dirty.2,
        }
    }

    /// Port of erts/emulator/beam/erl_process.c:3729 (wake_scheduler), OTP-29.1.1: `ssi_wake`
    /// only wakes a scheduler that sleeps; a running one finds the work on its next loop.
    fn wake_scheduler(&self, worker: usize) {
        if self.parked[worker].load(Ordering::SeqCst) {
            self.wake_worker(worker);
        }
    }

    /// Port of erts/emulator/beam/erl_process.c:3879 (wake_scheduler_on_empty_runq) and
    /// erl_process.c:3859 (chk_wake_sched), OTP-29.1.1: wake one sleeping scheduler of an
    /// online run queue other than `current`, searching downwards from `current`.
    fn wake_scheduler_on_empty_runq(&self, current: usize) {
        if self.scheduling_blocked.load(Ordering::Acquire) {
            return;
        }
        let (active, used) = self.balance.no_runqs();
        let used = used
            .min(self.online_schedulers.load(Ordering::Acquire))
            .clamp(1, self.parked.len());
        let active = active.min(used) as isize;
        let mut index = current as isize;
        let mut stop = index;
        if index >= active {
            index = active;
            stop = active;
        }
        // Try to wake a scheduler on an active run queue.
        loop {
            index -= 1;
            if index < 0 {
                if active == stop {
                    break;
                }
                index = active - 1;
            }
            if index == stop {
                break;
            }
            if self.chk_wake_sched(current, index as usize, false) {
                return;
            }
        }
        if (active as usize) < used {
            // Try to activate a new run queue and wake its scheduler.
            self.chk_wake_sched(current, active as usize, true);
        }
    }

    /// Port of erts/emulator/beam/erl_process.c:3858 (chk_wake_sched), OTP-29.1.1.
    fn chk_wake_sched(&self, current: usize, ix: usize, activate: bool) -> bool {
        if current == ix {
            return false;
        }
        if activate && self.balance.try_inc_no_active_runqs(ix + 1) {
            self.balance.rqs[ix]
                .flags
                .fetch_and(!balance::FLG_INACTIVE, Ordering::AcqRel);
        }
        if self.parked[ix].load(Ordering::SeqCst)
            && self.run_queues[ix].iter().all(SegQueue::is_empty)
        {
            self.wake_worker(ix);
            return true;
        }
        false
    }

    fn wake_worker(&self, worker: usize) {
        // Port of erts/emulator/beam/erl_process.c:3691 (ssi_wake), OTP-29.1.1: clearing the
        // waiting flag ends a spinning wait without a system call.
        self.parked[worker].store(false, Ordering::SeqCst);
        if let Some(thread) = self.sleepers[worker].get() {
            thread.unpark();
        }
        self.interrupt_poll_sleeper(worker);
    }

    /// Port of erts/emulator/beam/erl_process.c (ssi_wake: `erts_check_io_interrupt` for a
    /// scheduler in ERTS_SSI_FLG_POLL_SLEEPING), OTP-29.1.1.
    fn interrupt_poll_sleeper(&self, worker: usize) {
        if self.poll_sleeping[worker].load(Ordering::SeqCst)
            && let Some(poll) = SCHED_POLL.get()
        {
            poll.interrupt();
        }
    }

    fn wake_all_workers(&self) {
        for (worker, sleeper) in self.sleepers.iter().enumerate() {
            // Clearing `parked` is the real-wake signal. A spurious `park` return
            // leaves the flag set and the scheduler waits again.
            self.parked[worker].store(false, Ordering::SeqCst);
            if let Some(thread) = sleeper.get() {
                thread.unpark();
            }
            self.interrupt_poll_sleeper(worker);
        }
    }

    /// Applies the receiver-tree changes `wheel` recorded since the last call.
    // Port of erts/emulator/beam/erl_hl_timer.c:1832 (setup_bif_timer links the timer into
    // `p->bif_timers`) and :1500 (unlink on expiry or cancel), OTP-29.1.1.
    #[inline]
    fn apply_link_events(&self, wheel: &mut Wheel<T::Message>) {
        if wheel.has_link_events() {
            self.drain_link_events(wheel);
        }
    }

    #[inline(never)]
    fn drain_link_events(&self, wheel: &mut Wheel<T::Message>) {
        let worker = wheel.worker();
        // Applying an event can record more (a timer created for a paused receiver is
        // canceled again), so run until the wheel has none.
        while let Some(event) = wheel.pop_link_event() {
            {
                match event {
                    LinkEvent::Link(pid, id) => {
                        let stashed = self.table.with_live(pid, |process| {
                            // Port of erts/emulator/beam/erl_hl_timer.c:1838 (setup_bif_timer):
                            // a timer for a process whose timers are paused is created paused.
                            // The paused check and the link are one step under the paused lock,
                            // so a pause started meanwhile sees this timer in the tree.
                            let mut btm = process.btm.lock();
                            if btm.paused.is_some() {
                                return true;
                            }
                            btm.tree.insert(id, worker);
                            false
                        });
                        if stashed == Some(true)
                            && let Some((remaining, payload)) =
                                wheel.cancel_at(id, self.clock.time_left_now_ms())
                        {
                            self.stash_paused(wheel, pid, remaining, payload);
                        }
                    }
                    LinkEvent::Unlink(pid, id) => {
                        self.table.with_live(pid, |process| {
                            process.btm.lock().tree.remove(&id);
                        });
                    }
                    LinkEvent::Stash(pid, remaining, payload) => {
                        self.stash_paused(wheel, pid, remaining, payload);
                    }
                }
            }
        }
    }

    /// Adds a timer to the receiver's paused list; when the receiver was resumed in the
    /// meantime, the timer goes back on `wheel` with a fresh identity.
    fn stash_paused(
        &self,
        wheel: &mut Wheel<T::Message>,
        pid: Pid,
        remaining: u64,
        payload: TimerPayload<T::Message>,
    ) {
        let rejected = {
            let mut payload = Some(payload);
            self.table.with_live(pid, |process| {
                if let Some(paused) = process.btm.lock().paused.as_mut() {
                    paused
                        .list
                        .push((remaining, payload.take().expect("payload present")));
                }
            });
            payload
        };
        if let Some(payload) = rejected {
            wheel.insert(
                self.next_timer.fetch_add(1, Ordering::Relaxed),
                self.clock.timeout_pos(remaining),
                payload,
            );
        }
    }

    fn destroy_paused_bif_timers(&self, pid: Pid) {
        // Port of erts/emulator/beam/erl_hl_timer.c:2988 (erts_destroy_paused_bif_timers).
        self.table.with_live(pid, |process| {
            process.btm.lock().paused.take();
        });
    }

    /// The timers of `pid` that `worker`'s wheel holds, from the receiver's tree.
    fn bif_timer_ids(&self, pid: Pid, worker: usize) -> Vec<u64> {
        self.table
            .with_live(pid, |process| {
                process
                    .btm
                    .lock()
                    .tree
                    .iter()
                    .filter(|(_, owner)| **owner == worker)
                    .map(|(id, _)| *id)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Ask every timer wheel to pause or resume the timers aimed at `pid`.
    // Port of erts/emulator/beam/erl_hl_timer.c:2874 (erts_pause_bif_timers) and :2949
    // (erts_resume_paused_bif_timers), OTP-29.1.1: the paused list and its count belong to the
    // process; nested pauses only count.
    fn broadcast_target_timers(&self, pid: Pid, pause: bool) {
        let Some(process) = self.table.lookup(pid) else {
            return;
        };
        if !pause {
            self.resume_bif_timers(pid, &process);
            return;
        }
        {
            let mut btm = process.btm.lock();
            if let Some(paused) = btm.paused.as_mut() {
                paused.count += 1;
                return;
            }
            btm.paused = Some(PausedBifTimers {
                count: 1,
                list: Vec::new(),
            });
        }
        // Exit has to destroy the paused list (erts_destroy_paused_bif_timers).
        process.bif_timer_wheels.store(u64::MAX, Ordering::Release);
        proc_flags::publish(&process.exit_flags, proc_flags::BIF_TIMERS);
        if let Some(timers) = self.sim_timers.as_ref() {
            let now = self.clock.time_left_now_ms();
            for wheel in timers {
                let mut wheel = wheel.lock().unwrap();
                let ids = self.bif_timer_ids(pid, wheel.worker());
                wheel.pause_target(pid, &ids, now);
                self.apply_link_events(&mut wheel);
            }
            return;
        }
        for (worker, queue) in self.timer_commands.iter().enumerate() {
            let ids = self.bif_timer_ids(pid, worker);
            if ids.is_empty() {
                continue;
            }
            queue.push(TimerCommand::PauseTarget { pid, ids });
            self.wake_worker(worker);
        }
    }

    /// The last resume re-arms the held timers with the time they had left, each with a fresh
    /// identity, on the resuming scheduler's wheel.
    fn resume_bif_timers(&self, pid: Pid, process: &Process<T>) {
        let list = {
            let mut btm = process.btm.lock();
            let Some(held) = btm.paused.as_mut() else {
                return;
            };
            held.count -= 1;
            if held.count > 0 {
                return;
            }
            btm.paused.take().map(|held| held.list).unwrap_or_default()
        };
        let worker = self
            .current_worker()
            .filter(|worker| *worker < self.timer_commands.len())
            .unwrap_or(pid.number() as usize % self.timer_commands.len());
        for (remaining, payload) in list {
            process
                .bif_timer_wheels
                .fetch_or(timer_wheel_bit(worker), Ordering::AcqRel);
            let id = self.next_timer.fetch_add(1, Ordering::Relaxed);
            let _ = self.insert_timer(worker, id, payload, None, remaining);
        }
    }

    fn owner_timer_service(&self, worker: usize) -> Option<Rc<RefCell<TimerService<T::Message>>>> {
        let inner_id = self as *const Self as usize;
        OWNER_TIMER_SERVICES.with(|services| {
            let services = services.borrow();
            let (owner, service) = services.get(&inner_id)?;
            if *owner != worker {
                return None;
            }
            service
                .downcast_ref::<Rc<RefCell<TimerService<T::Message>>>>()
                .cloned()
        })
    }

    // Port of erts/emulator/beam/erl_process.c:7028 (active_sys_enqueue), OTP-29.1.1:
    // elevate the actual priority to the task priority and, when the process already
    // sits in a lower priority run queue, enqueue it once more at the task priority
    // (erts uses a proxy process struct for that second entry).
    fn deliver_sys_task(
        &self,
        from: Pid,
        to: Pid,
        payload: Payload<T::Message>,
        priority: Priority,
    ) -> Result<(), Error> {
        let process = self.table.lookup(to).ok_or(Error::NoProcess)?;
        let before = process.priority();
        process
            .sys_priority
            .fetch_min(priority.index() as u8, Ordering::AcqRel);
        self.deliver(from, to, payload, None)?;
        // Port of erts/emulator/beam/erl_proc_sig_queue.c:1275
        // (maybe_elevate_sig_handling_prio), OTP-29.1.1: a dirty target cannot run at the
        // elevated priority, so its matching dirty signal handler is notified.
        if Self::in_dirty_state(&process) {
            self.notify_dirty_signal_handler(&process, Some(priority));
        }
        if priority.index() < before.index() && process.dirty.load(Ordering::Acquire) == 0 {
            let item = Scheduled::new(process.clone());
            if process.run_state().load(Ordering::Acquire) == QUEUED {
                // The proxy entry is not counted in run queue lengths: the process is
                // already counted where its first entry sits.
                let queue = queue_index(priority.index());
                if let Some(sim) = &self.sim {
                    sim.lock().unwrap().queue.push_back(item);
                } else if let Some(worker) = process.bound_worker() {
                    self.pinned_injectors[worker][queue].push(item);
                    self.run_queue_flags[worker]
                        .fetch_or(1 << (PINNED_FLAGS_SHIFT + queue as u32), Ordering::Release);
                    self.note_queued(worker);
                    self.wake_scheduler(worker);
                } else {
                    // The proxy joins the run queue the process sits in (erts_get_runq_proc).
                    let scheduler = self.select_run_queue(&process);
                    self.inject(scheduler, queue, item);
                    self.note_queued(scheduler);
                    self.wake_scheduler(scheduler);
                }
            }
        }
        Ok(())
    }

    fn deliver(
        &self,
        from: Pid,
        to: Pid,
        payload: Payload<T::Message>,
        local: Option<&mut Local<T>>,
    ) -> Result<(), Error> {
        self.deliver_node(to, event_node(from, payload), local)
    }

    /// [`Self::deliver`] of a signal node the sender allocated.
    fn deliver_node(
        &self,
        to: Pid,
        signal: OwnedSignal<Event<T::Message>>,
        local: Option<&mut Local<T>>,
    ) -> Result<(), Error> {
        self.table
            .with_live(to, |process| self.deliver_live_node(process, signal, local))
            .ok_or(Error::NoProcess)?
    }

    fn deliver_live(
        &self,
        process: &ProcRef<T>,
        from: Pid,
        payload: Payload<T::Message>,
        local: Option<&mut Local<T>>,
    ) -> Result<(), Error> {
        self.deliver_live_node(process, event_node(from, payload), local)
    }

    fn deliver_live_node(
        &self,
        process: &ProcRef<T>,
        signal: OwnedSignal<Event<T::Message>>,
        local: Option<&mut Local<T>>,
    ) -> Result<(), Error> {
        // Port of erts/emulator/beam/erl_proc_sig_queue.c:1560-1563, OTP-29.1.1.
        // Literal-copy requests are non-message signals and enter a shared run queue.
        let force_enqueue = matches!(&signal.payload, Payload::Signal(Signal::LiteralAreaCopy(_)));
        self.fanin_delivery(process, 1);
        // The send pressure counts only a receiver that was not waiting. The state word comes
        // back from the enqueue's own read-modify-write, so the shared word is touched once;
        // the receiver tolerates a count that lags (it only decrements a non-zero backlog).
        let state = self.deliver_process_node(process, signal, local, true, force_enqueue)?;
        let state = run_state_of(state);
        if state != WAITING && state != UNSCHEDULED {
            process.input.backlog.fetch_add(1, Ordering::Relaxed);
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)] // `force_enqueue` routes literal-copy signals like erts.
    fn deliver_process(
        &self,
        process: &ProcRef<T>,
        from: Pid,
        payload: Payload<T::Message>,
        local: Option<&mut Local<T>>,
        wake: bool,
        force_enqueue: bool,
    ) -> Result<u32, Error> {
        self.deliver_process_node(
            process,
            event_node(from, payload),
            local,
            wake,
            force_enqueue,
        )
    }

    fn deliver_process_node(
        &self,
        process: &ProcRef<T>,
        signal: OwnedSignal<Event<T::Message>>,
        local: Option<&mut Local<T>>,
        wake: bool,
        force_enqueue: bool,
    ) -> Result<u32, Error> {
        // Port of erts/emulator/beam/erl_proc_sig_queue.c:712-800 (enqueue_signals), OTP-29.1.1:
        // an exited receiver is detected under the msgq lock, where its exit closed the queue.
        // No state load first: the closed in-queue rejects the signal, and the read-modify-write
        // that sets the in-queue bits returns the state word the wake decision works from.
        let from = signal.from;
        let Ok(state) = process
            .input
            .push_routed_node(|| signal_buffer_slot(from), signal)
        else {
            return Err(Error::NoProcess);
        };
        if wake {
            self.wake_after_publish(process, local, force_enqueue, Some(state));
        }
        Ok(state)
    }

    fn deliver_block(
        &self,
        process: &ProcRef<T>,
        events: &mut Vec<OwnedSignal<Event<T::Message>>>,
        local: Option<&mut Local<T>>,
        wake: bool,
        force_enqueue: bool,
    ) -> Result<(), Error> {
        if process.run_state().load(Ordering::Acquire) == EXITED {
            return Err(Error::NoProcess);
        }
        let count = events.len();
        process.input.backlog.fetch_add(count, Ordering::Relaxed);
        self.fanin_delivery(process, count);
        if process
            .input
            .push_block_routed(events, |event| signal_buffer_slot(event.from))
            .is_err()
        {
            process
                .input
                .backlog
                .fetch_sub(events.len(), Ordering::Relaxed);
            return Err(Error::NoProcess);
        }
        if wake {
            self.wake_after_publish(process, local, force_enqueue, None);
        }
        Ok(())
    }

    fn wake_after_publish(
        &self,
        process: &ProcRef<T>,
        local: Option<&mut Local<T>>,
        force_enqueue: bool,
        state: Option<u32>,
    ) {
        let wait_timer = process.wait_timer.load(Ordering::Acquire);
        // Port of erts/emulator/beam/erl_proc_sig_queue.h:2080 (erts_proc_notify_new_message),
        // OTP-29.1.1: read the state and schedule only a process that is not active. The
        // SeqCst load orders after the SeqCst enqueue (see the wake protocol above).
        if !process.run_state().schedule_waiting(state) {
            // Port of erts/emulator/beam/erl_proc_sig_queue.h:2072 (erts_proc_notify_new_sig),
            // OTP-29.1.1.
            if Self::in_dirty_state(process) {
                self.notify_dirty_signal_handler(process, None);
            }
        } else {
            if wait_timer != 0 {
                process.wait_epoch.fetch_add(1, Ordering::AcqRel);
                self.cancel_wait_timer(process, wait_timer);
            }
            let item = Scheduled::new(process.clone());
            if force_enqueue {
                self.enqueue(item, false);
            } else {
                self.place_runnable(item, local);
            }
        }
    }

    /// A woken process joins the tail of its own run queue (select_enqueue_run_queue,
    /// enqueue_process); a run queue of another scheduler gets its scheduler woken, if it
    /// sleeps.
    // Port of erts/emulator/beam/erl_process.c:3954 (enqueue_process appends to the priority
    // queue) and :6656-6672 (select_enqueue_run_queue), OTP-29.1.1.
    fn place_runnable(&self, item: Scheduled<T>, local: Option<&mut Local<T>>) {
        if let Some(local) = local
            && item.process.bound_worker().is_none()
            && self.sim.is_none()
            && self.online_schedulers.load(Ordering::Acquire) > 1
        {
            let scheduler = self.enqueue_run_queue(&item.process);
            if scheduler == local.worker_id {
                local.record_queued(&item.process, local.worker_id, false);
                local.queues[item.queue()].push(item);
            } else {
                self.push_run_queue(scheduler, item, false);
            }
            return;
        }
        self.enqueue(item, false);
    }

    fn cancel_wait_timer(&self, process: &Process<T>, id: u64) {
        if id == 0
            || process
                .wait_timer
                .compare_exchange(id, 0, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
        {
            return;
        }
        // Deferred receive timeouts are not in the wheel yet.
        if id == WAIT_TIMER_DEFERRED {
            return;
        }
        let worker = process.wait_timer_worker.load(Ordering::Relaxed);
        if let Some(timers) = self.sim_timers.as_ref() {
            if let Some(wheel) = timers.get(worker) {
                wheel
                    .lock()
                    .unwrap()
                    .cancel_at(id, self.clock.time_left_now_ms());
            }
        } else if let Some(queue) = self.canceled_timers.get(worker) {
            queue.push(CanceledTimer { id });
            self.wake_worker(worker);
        }
    }

    /// The scheduler's monotonic time for this pass.
    ///
    /// Port of erts/emulator/beam/erl_process.c (schedule: check_activities_to_run) and
    /// erl_time_sup.c (erts_get_monotonic_time), OTP-29.1.1: the clock is read once check_time_reds
    /// reaches ERTS_CHECK_TIME_REDS, the read resets check_time_reds and is kept in
    /// last_monotonic_time, and every other consumer in the pass uses that cached time.
    fn scheduler_time(&self, local: &mut Local<T>, force: bool) -> u64 {
        if force || local.check_time_reds >= self.config.reductions {
            local.last_monotonic_ms = self.clock.now_ms();
            local.check_time_reds = 0;
            fix_alloc_aux_work(local);
        }
        local.last_monotonic_ms
    }

    /// Fire receive timeouts that were kept off the wheel while this worker
    /// stayed busy. A reply clears the epoch, so the common `gen_server:call`
    /// path never locks the timer wheel.
    #[inline]
    fn poll_pending_waits(&self, local: &mut Local<T>, force: bool) {
        if !local.pending_waits.is_empty() {
            self.poll_pending_waits_due(local, force);
        }
    }

    #[inline(never)]
    fn poll_pending_waits_due(&self, local: &mut Local<T>, force: bool) {
        // Port of erts/emulator/beam/erl_process.c:9803 (schedule: a busy scheduler reads the
        // monotonic clock only once check_time_reds reaches ERTS_CHECK_TIME_REDS), OTP-29.1.1.
        if !force && local.check_time_reds < self.config.reductions {
            return;
        }
        local.pending_waits.retain(|entry| {
            entry.process.wait_epoch.load(Ordering::Acquire) == entry.epoch
                && entry.process.run_state().load(Ordering::Acquire) == WAITING
        });
        if local.pending_waits.is_empty() {
            return;
        }
        let now = self.scheduler_time(local, force);
        let mut index = 0;
        while index < local.pending_waits.len() {
            if local.pending_waits[index].deadline_ms > now {
                index += 1;
                continue;
            }
            let entry = local.pending_waits.swap_remove(index);
            let process = entry.process;
            if process.wait_epoch.load(Ordering::Acquire) == entry.epoch
                && process.wait_timer.load(Ordering::Acquire) == WAIT_TIMER_DEFERRED
                && process
                    .run_state()
                    .compare_exchange(WAITING, QUEUED, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
            {
                process.wait_timer.store(0, Ordering::Release);
                process.wait_epoch.fetch_add(1, Ordering::AcqRel);
                self.place_runnable(Scheduled::new(process), Some(local));
            }
        }
    }

    fn nearest_wait_ms(&self, local: &Local<T>) -> Option<u64> {
        let deadline = local
            .pending_waits
            .iter()
            .map(|entry| entry.deadline_ms)
            .min()?;
        Some(deadline.saturating_sub(self.clock.now_ms()))
    }

    fn poll_timers(&self, worker: usize, local: Option<&mut Local<T>>, force: bool) {
        if let Some(local) = local {
            debug_assert_eq!(local.worker_id, worker);
            // Port of erts/emulator/beam/erl_process.c:9803-9809 (schedule: one clock read per
            // ERTS_CHECK_TIME_REDS reductions, then the timers are bumped only when the cached
            // monotonic time has reached erts_next_timeout_time), OTP-29.1.1.
            let now = self.scheduler_time(local, force);
            {
                let service = local.timer_service.borrow();
                if service.commands.is_empty()
                    && service.canceled.is_empty()
                    && (!service.wheel.has_timers() || service.wheel.quiet_at(now))
                {
                    return;
                }
            }
            let due = {
                let mut service = local.timer_service.borrow_mut();
                let due = if service.wheel.next_timeout().is_some_and(|next| now >= next) {
                    service.wheel.advance(now)
                } else {
                    Vec::new()
                };
                self.apply_link_events(&mut service.wheel);
                due
            };
            for (id, event) in due {
                self.fire_timer(worker, id, event, Some(local));
            }
            // Port of erts/emulator/beam/erl_hl_timer.c:1922-1964 (access_btm), OTP-29.1.1:
            // expired timers cannot be canceled successfully.
            let queued = {
                let service = local.timer_service.borrow();
                !service.commands.is_empty() || !service.canceled.is_empty()
            };
            if queued {
                self.apply_timer_commands(local);
            }
            return;
        }
        let Some(timers) = self.sim_timers.as_ref() else {
            return;
        };
        let Some(wheel) = timers.get(worker) else {
            return;
        };
        if !wheel.lock().unwrap().has_timers() {
            return;
        }
        let now = self.clock.now_ms();
        let due = {
            let mut wheel = wheel.lock().unwrap();
            let due = wheel.advance(now);
            self.apply_link_events(&mut wheel);
            due
        };
        for (id, event) in due {
            self.fire_timer(worker, id, event, None);
        }
    }

    fn apply_timer_commands(&self, local: &mut Local<T>) {
        let service = Rc::clone(&local.timer_service);
        self.run_timer_commands(&mut service.borrow_mut());
    }

    /// Serve the timer requests other threads queued for this scheduler.
    ///
    /// Port of erts/emulator/beam/erl_hl_timer.c:2083 (bif_timer_access_request) and
    /// erl_hl_timer.c (scheduled_start_callback_timer, handle_canceled_queue), OTP-29.1.1:
    /// the owning scheduler answers from its aux work; requesters never wait on it.
    fn run_timer_commands(&self, service: &mut TimerService<T::Message>) {
        // Most scheduling rounds have nothing queued: skip the queue handle clones.
        if service.commands.is_empty() && service.canceled.is_empty() {
            return;
        }
        let commands = service.commands.clone();
        while let Some(command) = commands.pop() {
            match command {
                TimerCommand::Insert {
                    id,
                    deadline,
                    payload,
                } => {
                    if !service.wheel.has_timers() {
                        let _ = service.wheel.advance(self.clock.now_ms());
                    }
                    service.wheel.insert(id, deadline, payload);
                }
                TimerCommand::Read { id, callback } => {
                    callback(
                        service
                            .wheel
                            .remaining_at(id, self.clock.time_left_now_ms()),
                    );
                }
                TimerCommand::Cancel { id, callback } => {
                    let remaining = service
                        .wheel
                        .cancel_at(id, self.clock.time_left_now_ms())
                        .map(|(remaining, _)| remaining);
                    callback(remaining);
                }
                TimerCommand::CancelTarget { ids } => {
                    service.wheel.cancel_target(&ids);
                }
                TimerCommand::PauseTarget { pid, ids } => {
                    service
                        .wheel
                        .pause_target(pid, &ids, self.clock.time_left_now_ms());
                }
            }
        }
        let canceled_queue = service.canceled.clone();
        while let Some(canceled) = canceled_queue.pop() {
            service
                .wheel
                .cancel_at(canceled.id, self.clock.time_left_now_ms());
        }
        self.apply_link_events(&mut service.wheel);
    }

    /// The owner's wheel with every request queued before this call applied, so a
    /// request issued on the owner sees timers that other threads inserted earlier.
    fn owner_timer_service_synced(
        &self,
        worker: usize,
    ) -> Option<Rc<RefCell<TimerService<T::Message>>>> {
        let service = self.owner_timer_service(worker)?;
        if let Ok(mut borrowed) = service.try_borrow_mut() {
            self.run_timer_commands(&mut borrowed);
        }
        Some(service)
    }

    /// Block a non-owner thread on an asynchronous timer request.
    ///
    /// A scheduler thread keeps serving its own timer requests while it waits, so two
    /// schedulers that query each other's timers cannot deadlock.
    fn await_timer_reply(&self, receiver: mpsc::Receiver<Option<u64>>) -> Option<u64> {
        let own = self
            .current_worker()
            .and_then(|worker| self.owner_timer_service(worker));
        let Some(own) = own else {
            return progress_wait(|| receiver.recv()).ok().flatten();
        };
        progress_wait(|| {
            loop {
                match receiver.recv_timeout(Duration::from_micros(50)) {
                    Ok(remaining) => return remaining,
                    Err(mpsc::RecvTimeoutError::Disconnected) => return None,
                    Err(mpsc::RecvTimeoutError::Timeout) => {
                        if let Ok(mut service) = own.try_borrow_mut() {
                            self.run_timer_commands(&mut service);
                        }
                    }
                }
            }
        })
    }

    fn fire_timer(
        &self,
        worker: usize,
        id: u64,
        event: TimerPayload<T::Message>,
        local: Option<&mut Local<T>>,
    ) {
        match event {
            TimerPayload::Message(pid, message, wrapped) => {
                let payload = if wrapped {
                    Payload::Timer {
                        reference: TimerId(id),
                        message,
                    }
                } else {
                    Payload::TimerMessage {
                        reference: TimerId(id),
                        message,
                    }
                };
                let _ = self.deliver(pid, pid, payload, local);
            }
            TimerPayload::Callback(pid, callback) => {
                let mut ctx = CallbackCtx {
                    inner: self,
                    pid,
                    worker,
                    local,
                };
                callback(&mut ctx);
            }
            TimerPayload::Port(callback) => callback(),
            TimerPayload::ResolvedMessage(resolve, message, wrapped) => {
                if let Some(pid) = resolve() {
                    let payload = if wrapped {
                        Payload::Timer {
                            reference: TimerId(id),
                            message,
                        }
                    } else {
                        Payload::TimerMessage {
                            reference: TimerId(id),
                            message,
                        }
                    };
                    let _ = self.deliver(pid, pid, payload, local);
                }
            }
            TimerPayload::Wake(pid, epoch) => {
                if let Some(process) = self.table.lookup(pid)
                    && process.wait_epoch.load(Ordering::Acquire) == epoch
                    && process
                        .run_state()
                        .compare_exchange(WAITING, QUEUED, Ordering::AcqRel, Ordering::Acquire)
                        .is_ok()
                {
                    process.wait_epoch.fetch_add(1, Ordering::AcqRel);
                    let item = Scheduled::new(process);
                    self.place_runnable(item, local);
                }
            }
        }
    }

    fn start_timer(
        &self,
        pid: Pid,
        ms: u64,
        payload: TimerPayload<T::Message>,
        local: Option<&mut Local<T>>,
        owner: Option<usize>,
    ) -> Result<TimerRef, Error> {
        self.start_timer_payload(pid, ms, payload, local, owner)
    }

    fn start_resolved_timer(
        &self,
        owner: Pid,
        ms: u64,
        resolve: Arc<dyn Fn() -> Option<Pid> + Send + Sync>,
        message: T::Message,
        wrapped: bool,
        local: Option<&mut Local<T>>,
    ) -> Result<TimerRef, Error> {
        self.start_timer_payload(
            owner,
            ms,
            TimerPayload::ResolvedMessage(resolve, message, wrapped),
            local,
            None,
        )
    }

    fn start_port_timer(
        &self,
        ms: u64,
        callback: Box<dyn FnOnce() + Send>,
    ) -> Result<TimerRef, Error> {
        let wheels = self.timer_commands.len().max(1);
        let id = self.next_timer.fetch_add(1, Ordering::Relaxed);
        let worker = self
            .current_worker()
            .filter(|worker| *worker < wheels)
            .unwrap_or(id as usize % wheels);
        if ms == 0 {
            self.fire_timer(worker, id, TimerPayload::Port(callback), None);
            return Ok(TimerRef { worker, id });
        }
        self.insert_timer(worker, id, TimerPayload::Port(callback), None, ms)
    }

    fn start_timer_payload(
        &self,
        pid: Pid,
        ms: u64,
        payload: TimerPayload<T::Message>,
        local: Option<&mut Local<T>>,
        owner: Option<usize>,
    ) -> Result<TimerRef, Error> {
        let Some(process) = self.table.lookup(pid) else {
            return Err(Error::NoProcess);
        };
        let fallback = pid.number() as usize % self.timer_commands.len();
        let forced = match &payload {
            TimerPayload::Message(_, message, _) | TimerPayload::ResolvedMessage(_, message, _) => {
                message.timer_ref_key()
            }
            _ => None,
        }
        .map(|key| TimerRef::from_ref_key(key, self.timer_commands.len()));
        let worker = forced
            .map(|forced| forced.worker)
            .or(owner)
            .or_else(|| local.as_deref().map(|local| local.worker_id))
            .filter(|worker| *worker < self.timer_commands.len())
            .unwrap_or(fallback);
        let id = forced.map_or_else(|| self.next_timer.fetch_add(1, Ordering::Relaxed), |f| f.id);
        // Port of erts/emulator/beam/erl_hl_timer.c:1832-1840 (setup_bif_timer), OTP-29.1.1:
        // a timer aimed at a local process is linked to that receiver.
        if ms != 0
            && let TimerPayload::Message(target, _, _) = &payload
        {
            let receiver = if *target == pid {
                Some(process)
            } else {
                self.table.lookup(*target)
            };
            if let Some(receiver) = receiver {
                receiver
                    .bif_timer_wheels
                    .fetch_or(timer_wheel_bit(worker), Ordering::AcqRel);
                // p->bif_timers becomes non-NULL (erl_hl_timer.c:1832, erl_process.c:14301).
                proc_flags::publish(&receiver.exit_flags, proc_flags::BIF_TIMERS);
            }
        }
        if ms == 0 {
            self.fire_timer(worker, id, payload, local);
            return Ok(TimerRef { worker, id });
        }
        self.insert_timer(worker, id, payload, local, ms)
    }

    /// Puts a timer with identity `id` on the wheel of `worker`: directly when the caller owns
    /// the wheel, as a request to the owner otherwise.
    // Port of erts/emulator/beam/erl_hl_timer.c:2661-2695 (create_tw_timer / create_hl_timer).
    fn insert_timer(
        &self,
        worker: usize,
        id: u64,
        payload: TimerPayload<T::Message>,
        local: Option<&mut Local<T>>,
        ms: u64,
    ) -> Result<TimerRef, Error> {
        let now = self.clock.now_ms();
        let deadline = self.clock.timeout_pos(ms);
        if let Some(local) = local.filter(|local| local.worker_id == worker) {
            let mut service = local.timer_service.borrow_mut();
            if !service.wheel.has_timers() {
                let _ = service.wheel.advance(now);
            }
            service.wheel.insert(id, deadline, payload);
            self.apply_link_events(&mut service.wheel);
        } else if let Some(service) = self.owner_timer_service(worker) {
            let mut service = service.borrow_mut();
            if !service.wheel.has_timers() {
                let _ = service.wheel.advance(now);
            }
            service.wheel.insert(id, deadline, payload);
            self.apply_link_events(&mut service.wheel);
        } else if let Some(timers) = self.sim_timers.as_ref() {
            let Some(wheel) = timers.get(worker) else {
                return Err(Error::NoProcess);
            };
            let mut wheel = wheel.lock().unwrap();
            if !wheel.has_timers() {
                let _ = wheel.advance(now);
            }
            wheel.insert(id, deadline, payload);
            self.apply_link_events(&mut wheel);
        } else if let Some(queue) = self.timer_commands.get(worker) {
            // Port of erts/emulator/beam/erl_hl_timer.c:2731 (erts_start_timer_callback),
            // OTP-29.1.1: a thread that does not own the wheel schedules the insertion as
            // aux work on the owner and continues. Later requests for this timer use the
            // same queue, so they observe the insertion.
            queue.push(TimerCommand::Insert {
                id,
                deadline,
                payload,
            });
            self.wake_worker(worker);
        } else {
            return Err(Error::NoProcess);
        }
        // Port of erts/emulator/beam/erl_hl_timer.c:1825 (setup_bif_timer creates the timer
        // in the calling scheduler's own wheel), OTP-29.1.1: the owner of the wheel is the
        // running thread, which sees the new timeout before it sleeps, so there is nobody to
        // wake. A remote insertion above already woke the owner.
        Ok(TimerRef { worker, id })
    }

    /// Synchronous cancel for threads outside the scheduler (tests, drivers).
    fn cancel_timer(&self, reference: TimerRef) -> Option<u64> {
        let (reply, receiver) = mpsc::sync_channel(1);
        self.cancel_timer_async(
            reference,
            Box::new(move |remaining| {
                let _ = reply.send(remaining);
            }),
        );
        self.await_timer_reply(receiver)
    }

    // Port of erts/emulator/beam/erl_hl_timer.c:2237 (access_bif_timer), OTP-29.1.1:
    // the owning scheduler accesses its wheel directly; any other thread schedules the
    // request as aux work on the owner and gets the answer through `callback`.
    fn cancel_timer_async(
        &self,
        reference: TimerRef,
        callback: Box<dyn FnOnce(Option<u64>) + Send>,
    ) {
        if let Some(timers) = self.sim_timers.as_ref() {
            self.poll_timers(reference.worker, None, true);
            let remaining = timers
                .get(reference.worker)
                .and_then(|wheel| {
                    let mut wheel = wheel.lock().unwrap();
                    let canceled = wheel.cancel_at(reference.id, self.clock.time_left_now_ms());
                    self.apply_link_events(&mut wheel);
                    canceled
                })
                .map(|entry| entry.0);
            callback(remaining);
            return;
        }
        if let Some(service) = self.owner_timer_service_synced(reference.worker) {
            // The wheel's own `now` lags the clock between advances; remaining
            // time is measured against the current time.
            let remaining = {
                let mut service = service.borrow_mut();
                let canceled = service
                    .wheel
                    .cancel_at(reference.id, self.clock.time_left_now_ms());
                self.apply_link_events(&mut service.wheel);
                canceled.map(|(remaining, _)| remaining)
            };
            callback(remaining);
            return;
        }
        let Some(commands) = self.timer_commands.get(reference.worker) else {
            callback(None);
            return;
        };
        commands.push(TimerCommand::Cancel {
            id: reference.id,
            callback,
        });
        // Port of erts/emulator/beam/erl_hl_timer.c:2083 (bif_timer_access_request),
        // OTP-29.1.1: the owner answers from its next aux point.
        self.request_aux_work_one(reference.worker, Arc::new(|_| {}));
    }

    /// Cancels or reads a timer when the calling thread owns its wheel: the answer is immediate
    /// and nothing is allocated. `None` when another scheduler owns the wheel.
    // Port of erts/emulator/beam/erl_hl_timer.c:2237 (access_bif_timer): the owning scheduler
    // accesses its btm tree directly, only a foreign scheduler goes through a request.
    fn try_access_timer_local(&self, reference: TimerRef, cancel: bool) -> Option<Option<u64>> {
        if self.sim_timers.is_some() {
            return None;
        }
        let service = self.owner_timer_service_synced(reference.worker)?;
        self.access_service_timer(&service, reference, cancel)
    }

    /// The access itself, on the wheel of the scheduler the caller runs on.
    fn access_service_timer(
        &self,
        service: &Rc<RefCell<TimerService<T::Message>>>,
        reference: TimerRef,
        cancel: bool,
    ) -> Option<Option<u64>> {
        let now = self.clock.time_left_now_ms();
        let mut service = service.borrow_mut();
        Some(if cancel {
            let canceled = service.wheel.cancel_at(reference.id, now);
            self.apply_link_events(&mut service.wheel);
            canceled.map(|(remaining, _)| remaining)
        } else {
            service.wheel.remaining_at(reference.id, now)
        })
    }

    /// Synchronous read for threads outside the scheduler (tests, drivers).
    fn read_timer(&self, reference: TimerRef) -> Option<u64> {
        let (reply, receiver) = mpsc::sync_channel(1);
        self.read_timer_async(
            reference,
            Box::new(move |remaining| {
                let _ = reply.send(remaining);
            }),
        );
        self.await_timer_reply(receiver)
    }

    fn read_timer_async(&self, reference: TimerRef, callback: Box<dyn FnOnce(Option<u64>) + Send>) {
        if let Some(timers) = self.sim_timers.as_ref() {
            self.poll_timers(reference.worker, None, true);
            callback(timers.get(reference.worker).and_then(|wheel| {
                wheel
                    .lock()
                    .unwrap()
                    .remaining_at(reference.id, self.clock.time_left_now_ms())
            }));
            return;
        }
        if let Some(service) = self.owner_timer_service_synced(reference.worker) {
            let remaining = service
                .borrow()
                .wheel
                .remaining_at(reference.id, self.clock.time_left_now_ms());
            callback(remaining);
            return;
        }
        let Some(commands) = self.timer_commands.get(reference.worker) else {
            callback(None);
            return;
        };
        commands.push(TimerCommand::Read {
            id: reference.id,
            callback,
        });
        self.request_aux_work_one(reference.worker, Arc::new(|_| {}));
    }
}

struct PendingWait<T: Task> {
    process: ProcRef<T>,
    epoch: u64,
    deadline_ms: u64,
}

struct Local<T: Task> {
    worker_id: usize,
    balance: Arc<balance::Balance>,
    timer_service: Rc<RefCell<TimerService<T::Message>>>,
    queues: [Worker<Scheduled<T>>; 4],
    /// The previous pick took a bound process ahead of equal-priority shared work.
    pinned_turn: bool,
    message_slabs: Vec<Vec<OwnedSignal<Event<T::Message>>>>,
    /// Receive timeouts not yet published to the wheel.
    pending_waits: Vec<PendingWait<T>>,
    check_time_reds: u32,
    /// Port of erts/emulator/beam/erl_process.h (ErtsSchedulerData.last_monotonic_time),
    /// OTP-29.1.1: the time of this scheduler's latest clock read.
    last_monotonic_ms: u64,
    /// When the periodic fix_alloc shrink is due (erts aux work timeout of
    /// `ERTS_SSI_AUX_WORK_FIX_ALLOC_LOWER_LIM`).
    fix_shrink_due_ms: u64,
    /// The last shrink pass left blocks to give back (`ERTS_SSI_AUX_WORK_FIX_ALLOC_DEALLOC`).
    fix_shrink_dealloc: bool,
    profile_active: bool,
    last_process: Option<Pid>,
    metric_deltas: Vec<i64>,
    dirty_metrics: Vec<usize>,
    metric_marked: Vec<bool>,
    context_switches: u64,
    reductions: u64,
    active_ns: u64,
    active_started: Option<Instant>,
    wall_enabled: bool,
    msacc_ns: [u64; MSACC_STATE_COUNT],
    msacc_state: MsaccState,
    msacc_started: Option<Instant>,
    msacc_enabled: bool,
    /// Port of erts/emulator/beam/erl_process.h:501-502 (`wakeup_other`,
    /// `wakeup_other_reds`), OTP-29.1.1.
    wakeup_other: i64,
    wakeup_other_reds: i64,
}
impl<T: Task> Local<T> {
    fn set_wall_enabled(&mut self, enabled: bool) {
        self.set_wall_enabled_at(enabled, None);
    }

    fn set_wall_enabled_at(&mut self, enabled: bool, started_at: Option<Instant>) {
        if self.wall_enabled == enabled {
            return;
        }
        if let Some(started) = self.active_started.take() {
            self.active_ns = self
                .active_ns
                .saturating_add(u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX));
        }
        self.wall_enabled = enabled;
        if enabled {
            self.active_started = Some(started_at.unwrap_or_else(Instant::now));
        }
    }

    fn set_msacc_enabled(&mut self, enabled: bool) {
        if self.msacc_enabled != enabled {
            if self.msacc_enabled {
                self.switch_msacc_state(self.msacc_state);
                self.msacc_started = None;
            }
            self.msacc_enabled = enabled;
            if enabled {
                self.msacc_state = MsaccState::Other;
                self.msacc_started = Some(Instant::now());
            }
        }
    }

    fn stats_snapshot(&self, msacc_enabled: bool, wall_enabled: bool) -> LocalStatsSnapshot {
        let mut msacc_ns = self.msacc_ns;
        if msacc_enabled && let Some(started) = self.msacc_started {
            let elapsed = started.elapsed().as_nanos().min(u64::MAX as u128) as u64;
            msacc_ns[self.msacc_state as usize] =
                msacc_ns[self.msacc_state as usize].saturating_add(elapsed);
        }
        let active_ns = if wall_enabled {
            self.active_started.map_or(self.active_ns, |started| {
                self.active_ns
                    .saturating_add(u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX))
            })
        } else {
            self.active_ns
        };
        LocalStatsSnapshot {
            context_switches: self.context_switches,
            reductions: self.reductions,
            active_ns,
            msacc_ns,
            metric_deltas: self.metric_deltas.clone(),
        }
    }

    #[inline(always)]
    fn set_msacc_state(&mut self, state: MsaccState) {
        if self.msacc_enabled && self.msacc_state != state {
            self.switch_msacc_state(state);
        }
    }

    #[inline(never)]
    fn switch_msacc_state(&mut self, state: MsaccState) {
        let now = Instant::now();
        if let Some(started) = self.msacc_started.replace(now) {
            let elapsed = started.elapsed().as_nanos().min(u64::MAX as u128) as u64;
            let counter = &mut self.msacc_ns[self.msacc_state as usize];
            *counter = counter.saturating_add(elapsed);
        }
        self.msacc_state = state;
    }

    fn adjust_metric(&mut self, worker: usize, delta: i64) {
        if !self.metric_marked[worker] {
            self.metric_marked[worker] = true;
            self.dirty_metrics.push(worker);
        }
        self.metric_deltas[worker] += delta;
    }

    fn record_queued(&mut self, process: &Process<T>, worker: usize, already_active: bool) {
        process.scheduler_id.store(worker, Ordering::Relaxed);
        self.adjust_metric(worker, QUEUE_COUNT_UNIT as i64 + i64::from(!already_active));
        self.balance
            .enqueued(process.priority().index(), &process.queued_prio, worker);
    }

    fn record_running(&mut self, process: &Process<T>, worker: usize) {
        let previous = process
            .scheduler_id
            .load(Ordering::Relaxed)
            .min(self.metric_deltas.len() - 1);
        self.balance.dequeued(&process.queued_prio, previous);
        if previous == worker {
            self.adjust_metric(worker, -(QUEUE_COUNT_UNIT as i64));
        } else {
            self.adjust_metric(previous, -(QUEUE_COUNT_UNIT as i64 + 1));
            self.adjust_metric(worker, 1);
        }
        process.scheduler_id.store(worker, Ordering::Relaxed);
    }

    fn record_waiting(&mut self, process: &Process<T>) {
        let worker = process
            .scheduler_id
            .load(Ordering::Relaxed)
            .min(self.metric_deltas.len() - 1);
        self.adjust_metric(worker, -1);
    }

    fn migrate_queued(&mut self, process: &Process<T>, target: usize) {
        let previous = process
            .scheduler_id
            .load(Ordering::Relaxed)
            .min(self.metric_deltas.len() - 1);
        self.adjust_metric(previous, -(QUEUE_COUNT_UNIT as i64 + 1));
        self.adjust_metric(target, QUEUE_COUNT_UNIT as i64 + 1);
        self.balance
            .migrated(&process.queued_prio, previous, target);
        process.scheduler_id.store(target, Ordering::Relaxed);
    }

    fn lookup(&mut self, table: &ProcessTable<T>, pid: Pid) -> Option<ProcRef<T>> {
        // Port of erts/emulator/beam/erl_ptab.c (erts_ptab_lookup / pix to slot).
        // A side cache of Arcs kept exited processes alive until a later spawn
        // reused the slot, so delete_process ran on the spawner.
        table.lookup(pid)
    }
    /// Highest priority (lowest index) with runnable local work.
    fn best_priority(&self) -> Option<usize> {
        (0..self.queues.len()).find(|&priority| !self.queues[priority].is_empty())
    }
    fn pop(&mut self) -> Option<Scheduled<T>> {
        for priority in 0..PROC_QUEUES {
            let queue = &self.queues[priority];
            if let Some(item) =
                pop_requeue(|| queue.pop(), |item| queue.push(item), || queue.is_empty())
            {
                return Some(item);
            }
        }
        None
    }
}

/// Process priority queues of a run queue: max, high and normal (shared with low).
const PROC_QUEUES: usize = balance::PRIORITY_NORMAL + 1;

/// Take the next entry of a priority queue.
///
/// Port of erts/emulator/beam/erl_process.c:4040 (check_requeue_process), OTP-29.1.1: a
/// low priority entry goes back to the tail until it has reached the head
/// `RESCHEDULE_LOW` times, unless it is the only entry.
fn pop_requeue<T: Task>(
    mut pop: impl FnMut() -> Option<Scheduled<T>>,
    mut push: impl FnMut(Scheduled<T>),
    is_empty: impl Fn() -> bool,
) -> Option<Scheduled<T>> {
    loop {
        let mut item = pop()?;
        item.schedule_count = item.schedule_count.saturating_sub(1);
        if item.schedule_count > 0 && !is_empty() {
            push(item);
            continue;
        }
        return Some(item);
    }
}

/// Context passed to one invocation of `Task::run`.
/// A runtime timer callback; it runs on a scheduler thread when the timer expires.
pub type TimerCallback<M> = Box<dyn FnOnce(&mut dyn TimerCallbackCtx<M>) + Send>;

type HaltReap = Arc<dyn Fn(HaltProgress) + Send + Sync + 'static>;
type HaltStart = Box<dyn FnOnce() + Send + 'static>;
type HaltComplete = Box<dyn FnOnce(i32) + Send + 'static>;

struct HaltActions {
    start: HaltStart,
    reap: HaltReap,
    complete: HaltComplete,
}

struct HaltState {
    progress: AtomicI32,
    code: i32,
    reap: Mutex<Option<HaltReap>>,
    complete: Mutex<Option<HaltComplete>>,
}

/// Shared progress for an orderly runtime halt.
///
/// Port of erts/emulator/beam/erl_process.c:15228-15279 (`erts_halt_progress`), OTP-29.1.1.
#[derive(Clone)]
pub struct HaltProgress(Arc<HaltState>);

impl HaltProgress {
    /// Account for a live port before sending its `killed` exit signal.
    pub fn port_started(&self) {
        self.0.progress.fetch_add(1, Ordering::AcqRel);
    }

    /// Account for a port that completed its exit callback and driver stop.
    pub fn port_finished(&self) {
        if self.0.progress.fetch_sub(1, Ordering::AcqRel) == 1 {
            let complete = self.0.complete.lock().unwrap().take();
            if let Some(complete) = complete {
                complete(self.0.code);
            }
        }
    }

    fn scheduler_reached_halt(&self) {
        if self.0.progress.fetch_sub(1, Ordering::AcqRel) == 1 {
            // The sentinel keeps the halt alive while the last scheduler enumerates ports.
            self.0.progress.store(1, Ordering::Release);
            if let Some(reap) = self.0.reap.lock().unwrap().take() {
                reap(self.clone());
            }
            self.port_finished();
        }
    }
}

/// What a [`TimerCallback`] may do for the process that started it.
pub trait TimerCallbackCtx<M> {
    /// Start another callback timer for the same process.
    fn start_timer_callback(&mut self, ms: u64, callback: TimerCallback<M>);
    /// Queue a plain message to the process.
    fn send(&mut self, msg: M);
}

struct CallbackCtx<'a, T: Task> {
    inner: &'a Inner<T>,
    pid: Pid,
    worker: usize,
    local: Option<&'a mut Local<T>>,
}

impl<T: Task> TimerCallbackCtx<T::Message> for CallbackCtx<'_, T> {
    fn start_timer_callback(&mut self, ms: u64, callback: TimerCallback<T::Message>) {
        let _ = self.inner.start_timer(
            self.pid,
            ms,
            TimerPayload::Callback(self.pid, callback),
            self.local.as_deref_mut(),
            Some(self.worker),
        );
    }
    fn send(&mut self, msg: T::Message) {
        let _ = self.inner.deliver(
            self.pid,
            self.pid,
            Payload::Message(msg),
            self.local.as_deref_mut(),
        );
    }
}

pub struct RunCtx<'a, M: SignalMessage> {
    inner: &'a mut dyn ContextOps<M>,
    pid: Pid,
    input: &'a Incoming<Event<M>>,
    backlog: &'a AtomicUsize,
    bound_worker: &'a AtomicUsize,
    worker: Option<usize>,
    worker_count: usize,
    remaining: u32,
    budget: u32,
    msacc_enabled: bool,
    wall_enabled: bool,
    gc_accounted_total: u64,
    sched_type: SchedulerType,
    user_priority: &'a AtomicU8,
    sys_priority: &'a AtomicU8,
    active: &'a AtomicBool,
    /// [`proc_flags`] of the running process. Exit tests this before any global table.
    exit_flags: &'a AtomicU32,
    sys_task_run: bool,
    /// A dirty signal handler acts for a process whose dirty job is executing.
    dirty_running: bool,
    /// A dirty signal handler acts for a process queued on a dirty run queue but not yet
    /// executing (erts `ERTS_PSFLG_DIRTY_ACTIVE_SYS` without `ERTS_PSFLG_DIRTY_RUNNING`).
    dirty_queued: bool,
    /// The turn runs on a simulated scheduler, whose thread steps other runtimes too.
    simulated: bool,
}

trait ContextOps<M: SignalMessage> {
    fn process_priority(&self, pid: Pid) -> Option<Priority>;
    fn deliver(&mut self, from: Pid, to: Pid, payload: Payload<M>) -> Result<(), Error> {
        self.deliver_node(to, event_node(from, payload))
    }
    fn deliver_node(&mut self, to: Pid, signal: OwnedSignal<Event<M>>) -> Result<(), Error>;
    fn flush(&mut self);
    fn thread_progress_later(&self, op: LaterOp);
    fn block_thread_progress(&self, duration: Duration);
    fn signal_probe(&mut self, pid: Pid) -> Option<SignalProbe<M>>;
    fn total_reductions(&self) -> u64;
    fn scheduler_stats(&self) -> SchedulerStats;
    fn set_msacc_enabled(&mut self, enabled: bool);
    fn set_msacc_state(&mut self, state: MsaccState);
    fn reclassify_gc_ns(&mut self, nanoseconds: u64);
    fn set_wall_accounting_enabled(&mut self, enabled: bool);
    fn start_timer(
        &mut self,
        owner: Pid,
        target: Pid,
        ms: u64,
        msg: M,
        wrapped: bool,
    ) -> Result<TimerRef, Error>;
    fn start_resolved_timer(
        &mut self,
        owner: Pid,
        ms: u64,
        resolve: Arc<dyn Fn() -> Option<Pid> + Send + Sync>,
        msg: M,
        wrapped: bool,
    ) -> Result<TimerRef, Error>;
    fn start_timer_callback(
        &mut self,
        pid: Pid,
        ms: u64,
        callback: TimerCallback<M>,
    ) -> Result<TimerRef, Error>;
    fn start_timer_to(
        &mut self,
        pid: Pid,
        ms: u64,
        msg: M,
        wrapped: bool,
    ) -> Result<TimerRef, Error>;
    fn mark_exited(&mut self, pid: Pid);
    fn cancel_target_timers(&mut self, pid: Pid);
    fn schedule_spawn(&mut self, pid: Pid) -> Result<(), Error>;
    fn schedule_spawned(&mut self, spawned: SpawnedProcess<M>) -> Result<(), Error>;
    fn request_aux_work_all(&mut self, work: SchedulerAuxWork);
    fn begin_halt(
        &mut self,
        pid: Pid,
        code: i32,
        timeout: Option<(u64, TimerCallback<M>)>,
        actions: HaltActions,
    ) -> bool;
    fn deliver_sys_task(
        &mut self,
        from: Pid,
        to: Pid,
        payload: Payload<M>,
        priority: Priority,
    ) -> Result<(), Error>;
    fn handle_dirty_signals(
        &mut self,
        pid: Pid,
        remaining: u32,
        handle: &mut dyn FnMut(&mut dyn std::any::Any, &mut RunCtx<'_, M>) -> bool,
    ) -> DirtySignals;
    fn with_locked_target(
        &mut self,
        pid: Pid,
        remaining: u32,
        handle: &mut dyn FnMut(&mut dyn std::any::Any, &mut RunCtx<'_, M>),
    ) -> Result<(), SignalFreeError>;
}

impl<M: SignalMessage> RunCtx<'_, M> {
    fn consumed_event(&self) {
        if self.backlog.load(Ordering::Relaxed) != 0 {
            self.backlog.fetch_sub(1, Ordering::Relaxed);
        }
    }
    /// Pid of the running task.
    pub fn pid(&self) -> Pid {
        self.pid
    }
    /// Process-local exit words (`p->flags`, `p->reg`, `p->bif_timers`, trace flags).
    pub fn exit_flags(&self) -> &AtomicU32 {
        self.exit_flags
    }
    /// Return the scheduler worker currently running this process.
    pub fn worker_id(&self) -> Option<usize> {
        self.worker
    }
    /// Reject further mailbox publishes and delete this pid from the process table.
    /// In-flight publishers that already resolved the slot still land; a later
    /// enqueue sees the pid gone. The identifier may be reused immediately, so the
    /// slice epilogue must not delete the slot again.
    ///
    /// Port of erts/emulator/beam/erl_process.c:14438-14456
    /// (`erts_ptab_delete_element` at `ERTS_CONTINUE_EXIT_FREE`), OTP-29.1.1.
    pub fn begin_exit(&mut self) {
        self.inner.mark_exited(self.pid);
    }
    /// Cancel pending BIF timers aimed at a terminating process.
    pub fn cancel_target_timers(&mut self, pid: Pid) {
        self.inner.cancel_target_timers(pid);
    }
    /// Schedule a child inserted with [`Scheduler::spawn_unscheduled`].
    /// A worker-local child runs before this worker parks.
    pub fn schedule_spawn(&mut self, pid: Pid) -> Result<(), Error> {
        self.inner.schedule_spawn(pid)
    }
    /// Schedule a child returned by `Scheduler::spawn_unscheduled_handle` (no table lookup).
    pub fn schedule_spawned(&mut self, spawned: SpawnedProcess<M>) -> Result<(), Error> {
        self.inner.schedule_spawned(spawned)
    }
    /// Consume reductions; returns false when the quantum is exhausted.
    pub fn consume(&mut self, count: u32) -> bool {
        self.remaining = self.remaining.saturating_sub(count);
        self.remaining != 0
    }
    /// Number of scheduler workers available to this runtime.
    pub fn scheduler_count(&self) -> usize {
        self.worker_count
    }
    /// One-based id of the worker executing this process turn.
    pub fn scheduler_id(&self) -> Option<usize> {
        self.worker.map(|worker| worker + 1)
    }
    /// Whether this turn runs on a simulated scheduler: its thread is not dedicated to one
    /// scheduler, so thread-specific data must be selected for every turn.
    pub fn simulated(&self) -> bool {
        self.simulated
    }
    /// Type of the scheduler executing this process turn.
    pub fn scheduler_type(&self) -> SchedulerType {
        self.sched_type
    }
    /// Publish messages and signals this turn has buffered so far. A long dirty job
    /// calls this so its sends do not wait for the job to return.
    pub fn flush_pending(&mut self) {
        self.inner.flush();
    }
    /// Whether events wait in this process's shared input queue.
    pub fn has_pending_input(&self) -> bool {
        self.input.has_pending()
    }
    /// Whether non-message signals wait in this process's shared input queue. A process
    /// with only messages queued handles them in its receive, not at schedule-in.
    // Port of erts/emulator/beam/erl_process.c (schedule: signals are handled before Erlang
    // code only for ERTS_PSFLG_RUNNING_SYS, which a message does not set), OTP-29.1.1.
    pub fn has_pending_nmsg(&self) -> bool {
        self.input.has_pending_nmsg()
    }
    /// A handle that tells, without this context, whether signals wait in this process's
    /// shared input queue.
    pub fn signal_probe(&mut self) -> Option<SignalProbe<M>> {
        self.inner.signal_probe(self.pid)
    }
    /// Configure the receiver's parallel sender buffers for off heap mailboxes.
    // Port of erts/emulator/beam/erl_proc_sig_queue.c:10600-10694, OTP-29.1.1.
    pub fn set_parallel_signal_buffers(&mut self, enabled: bool) {
        self.input.set_buffers_enabled(enabled);
    }

    /// Force installation of parallel sender buffers for runtime regression tests.
    // Port of erts/emulator/beam/erl_proc_sig_queue.c:10700-10718, OTP-29.1.1.
    pub fn force_parallel_signal_buffers(&mut self) -> bool {
        self.input.force_buffers_enabled();
        true
    }
    /// Whether this context acts for a process executing on a dirty scheduler, on
    /// behalf of a dirty signal handler.
    ///
    /// Port of erts/emulator/beam/erl_process.h (`ERTS_PSFLG_DIRTY_RUNNING`), OTP-29.1.1.
    pub fn dirty_running(&self) -> bool {
        self.dirty_running
    }
    /// Whether a dirty signal handler acts for a process queued for a dirty scheduler and not
    /// executing. Port of erts/emulator/beam/erl_process.h (`ERTS_PSFLG_DIRTY_ACTIVE_SYS`).
    pub fn dirty_queued(&self) -> bool {
        self.dirty_queued
    }
    /// Handle the queued signals of process `pid` while it is in a dirty state, with its
    /// task cell locked and a context acting as that process.
    ///
    /// Port of erts/emulator/beam/erl_proc_sig_queue.c:8893
    /// (erts_internal_dirty_process_handle_signals_1), OTP-29.1.1.
    pub fn handle_dirty_signals(
        &mut self,
        pid: Pid,
        handle: &mut dyn FnMut(&mut dyn std::any::Any, &mut RunCtx<'_, M>) -> bool,
    ) -> DirtySignals {
        self.inner.handle_dirty_signals(pid, self.remaining, handle)
    }
    /// Run `body` with `pid`'s main lock held and a context acting as that process, as
    /// `erts_pid2proc(.., ERTS_PROC_LOCK_MAIN, ..)` lets the caller handle another process's
    /// signals. `Busy` means the target executes (erts would wait for the lock).
    ///
    /// Port of erts/emulator/beam/erl_bif_info.c:4626-4660 (`link_list` of another process),
    /// OTP-29.1.1.
    pub fn with_locked_target(
        &mut self,
        pid: Pid,
        body: &mut dyn FnMut(&mut dyn std::any::Any, &mut RunCtx<'_, M>),
    ) -> Result<(), SignalFreeError> {
        self.inner.with_locked_target(pid, self.remaining, body)
    }
    /// Run one copy of `work` on every scheduler at its next scheduling point.
    pub fn request_aux_work_all(&mut self, work: impl Fn(usize) + Send + Sync + 'static) {
        self.inner.request_aux_work_all(Arc::new(work));
    }

    /// Stop scheduling processes, reap ports, and complete after every port has exited.
    ///
    /// Port of erts/emulator/beam/erl_process.c:15228-15279 (`erts_halt`), OTP-29.1.1.
    pub fn begin_halt(
        &mut self,
        code: i32,
        timeout: Option<(u64, TimerCallback<M>)>,
        reap: impl Fn(HaltProgress) + Send + Sync + 'static,
        complete: impl FnOnce(i32) + Send + 'static,
    ) -> bool {
        self.begin_halt_with_start(code, timeout, || {}, reap, complete)
    }

    /// Start halt and run `start` only when this call wins the halt race.
    ///
    /// Port of erts/emulator/beam/erl_process.c:15239-15253, OTP-29.1.1.
    pub fn begin_halt_with_start(
        &mut self,
        code: i32,
        timeout: Option<(u64, TimerCallback<M>)>,
        start: impl FnOnce() + Send + 'static,
        reap: impl Fn(HaltProgress) + Send + Sync + 'static,
        complete: impl FnOnce(i32) + Send + 'static,
    ) -> bool {
        self.inner.begin_halt(
            self.pid,
            code,
            timeout,
            HaltActions {
                start: Box::new(start),
                reap: Arc::new(reap),
                complete: Box::new(complete),
            },
        )
    }

    /// Schedule a message timer on the scheduler currently running this process.
    pub fn schedule_timer(
        &mut self,
        target: Pid,
        ms: u64,
        message: M,
        wrapped: bool,
    ) -> Result<TimerRef, Error> {
        self.inner
            .start_timer(self.pid, target, ms, message, wrapped)
    }
    /// Schedule a timer whose registered process name is resolved when it expires.
    pub fn schedule_resolved_timer(
        &mut self,
        ms: u64,
        message: M,
        wrapped: bool,
        resolve: impl Fn() -> Option<Pid> + Send + Sync + 'static,
    ) -> Result<TimerRef, Error> {
        self.inner
            .start_resolved_timer(self.pid, ms, Arc::new(resolve), message, wrapped)
    }
    /// Change the process scheduler binding and return its previous scheduler id.
    /// Scheduler ids are one-based; zero clears the binding.
    pub fn bind_scheduler(&mut self, scheduler_id: usize) -> (usize, bool) {
        let target = scheduler_id.checked_sub(1).unwrap_or(UNBOUND_WORKER);
        let previous = self.bound_worker.swap(target, Ordering::AcqRel);
        let previous_id = if previous == UNBOUND_WORKER {
            0
        } else {
            previous + 1
        };
        let should_yield =
            target != UNBOUND_WORKER && self.worker.is_some_and(|worker| worker != target);
        (previous_id, should_yield)
    }
    /// Remaining reductions in this quantum.
    pub fn remaining(&self) -> u32 {
        self.remaining
    }
    /// Reductions consumed in this process turn so far.
    pub fn consumed(&self) -> u32 {
        self.budget.saturating_sub(self.remaining)
    }
    /// Scheduler-wide reductions committed before this process turn.
    pub fn total_reductions(&self) -> u64 {
        self.inner.total_reductions()
    }
    /// Scheduler-owned task and timing snapshot including this turn's pending changes.
    pub fn scheduler_stats(&self) -> SchedulerStats {
        let mut stats = self.inner.scheduler_stats();
        stats.reductions = stats.reductions.saturating_add(u64::from(self.consumed()));
        stats
    }
    /// Change the current scheduler worker's microstate category.
    pub fn set_msacc_state(&mut self, state: MsaccState) {
        if !self.msacc_enabled {
            return;
        }
        self.inner.set_msacc_state(state);
    }
    /// Change microstate accounting while this task is running.
    pub fn set_msacc_accounting_enabled(&mut self, enabled: bool) {
        if self.msacc_enabled != enabled {
            self.msacc_enabled = enabled;
            self.inner.set_msacc_enabled(enabled);
        }
    }
    /// Move measured heap collection time out of the enclosing emulator interval.
    pub fn reclassify_gc_ns(&mut self, nanoseconds: u64) {
        self.inner.reclassify_gc_ns(nanoseconds);
    }
    /// Account newly completed collection time before a live microstate snapshot.
    // Port of erts/emulator/beam/erl_gc.c:800 (collector state interval), OTP-29.1.1.
    pub fn account_gc_total(&mut self, total_nanoseconds: u64) {
        if self.msacc_enabled {
            let delta = total_nanoseconds.saturating_sub(self.gc_accounted_total);
            if delta != 0 {
                self.inner.reclassify_gc_ns(delta);
            }
            self.gc_accounted_total = self.gc_accounted_total.max(total_nanoseconds);
        }
    }
    /// Set the GC counter origin when accounting is enabled or reset mid-turn.
    pub fn set_gc_accounting_baseline(&mut self, total_nanoseconds: u64) {
        self.gc_accounted_total = total_nanoseconds;
    }
    /// Update this worker's active interval when scheduler wall time changes.
    pub fn set_wall_accounting_enabled(&mut self, enabled: bool) {
        if self.wall_enabled == enabled {
            return;
        }
        self.wall_enabled = enabled;
        self.inner.set_wall_accounting_enabled(enabled);
    }
    /// Take the oldest signal from the outer signal queue, for a task without an inner
    /// queue of its own (and for an exiting process absorbing what is left).
    // Port of erts/emulator/beam/erl_proc_sig_queue.c:7730-7790 (erts_proc_sig_receive_helper
    // fetches from the outer queue), OTP-29.1.1.
    pub fn receive(&mut self) -> Option<Event<M>> {
        self.inner.flush();
        self.input.fetch_first_if(|_| true)
    }
    /// Move every signal published to this process into `into`, after the signals it already
    /// holds: the process's inner signal queue receives the outer one. Each event taken out of
    /// `into` is accounted with [`Self::consume_fetched`].
    // Port of erts/emulator/beam/erl_proc_sig_queue.h:1997 (erts_proc_sig_fetch: the outer
    // queue is appended to the inner one), OTP-29.1.1.
    pub fn fetch_signals(&mut self, into: &mut SignalQueue<Event<M>>) {
        self.inner.flush();
        self.input.take_all(into);
    }
    /// Record whether this process's middle signal queue holds unhandled signals
    /// (`ERTS_PSFLG_SIG_Q`).
    pub fn set_sig_q(&self, unhandled: bool) {
        self.input.set_sig_q(unhandled);
    }
    /// Account one event taken from [`Self::fetch_signals`].
    pub fn consume_fetched(&self) {
        self.consumed_event();
    }
    /// Account `count` events taken from [`Self::fetch_signals`] at once.
    pub fn consume_fetched_many(&self, count: usize) {
        let backlog = self.backlog.load(Ordering::Relaxed);
        if backlog != 0 {
            self.backlog
                .fetch_sub(backlog.min(count), Ordering::Relaxed);
        }
    }
    /// Record whether this slice ends active (runnable) or waiting.
    // Port of erts/emulator/beam/erl_process.c (ERTS_PSFLG_ACTIVE in the process state
    // word, read by erts_process_state2status), OTP-29.1.1.
    pub fn set_active(&self, active: bool) {
        self.active.store(active, Ordering::Release);
    }
    /// Send an opaque envelope to another process.
    pub fn send(&mut self, to: Pid, msg: M) -> Result<(), Error> {
        self.inner.deliver(self.pid, to, Payload::Message(msg))
    }
    /// Send a message node this process allocated (erts queues the `ErtsMessage` it built).
    pub fn send_node(&mut self, to: Pid, signal: OwnedSignal<Event<M>>) -> Result<(), Error> {
        self.inner.deliver_node(to, signal)
    }
    /// Send an opaque envelope to this process itself (see [`SignalProbe::send_self`]).
    pub fn send_self(&mut self, msg: M) -> Result<(), Error> {
        let pid = self.pid;
        self.send_self_node(OwnedSignal::new(Event {
            from: pid,
            payload: Payload::Message(msg),
        }))
    }
    /// [`Self::send_self`] of a message node this process allocated.
    pub fn send_self_node(&mut self, signal: OwnedSignal<Event<M>>) -> Result<(), Error> {
        let pid = self.pid;
        self.input
            .push_routed_node(|| signal_buffer_slot(pid), signal)
            .map_err(|_| Error::NoProcess)?;
        self.backlog.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
    /// Set this process's user priority; it takes effect when the process is next queued.
    ///
    /// Port of erts/emulator/beam/erl_process.c (erts_set_process_priority), OTP-29.1.1.
    pub fn set_priority(&mut self, priority: Priority) {
        self.user_priority
            .store(priority.index() as u8, Ordering::Release);
    }
    /// Clear the active system-task priority after its queued work has drained.
    ///
    /// Port of erts/emulator/beam/erl_process.c:10737 (`fetch_sys_task`), OTP-29.1.1.
    pub fn clear_sys_task_priority(&self) {
        self.sys_priority.store(NO_SYS_PRIORITY, Ordering::Release);
    }
    /// Whether this run was scheduled for system tasks (erts `ERTS_PSFLG_RUNNING_SYS`).
    /// The task should handle its queued signals before executing code.
    pub fn sys_task_run(&self) -> bool {
        self.sys_task_run
    }
    /// User priority of a live process.
    pub fn process_priority(&self, pid: Pid) -> Option<Priority> {
        self.inner.process_priority(pid)
    }
    /// Send a control signal that carries a system task requested at `priority`.
    ///
    /// The target runs at least at `priority` until it has handled the signal, even
    /// when its own priority is lower. Port of erts/emulator/beam/erl_process.c:7221
    /// (schedule_process_sys_task) and :7028 (active_sys_enqueue), OTP-29.1.1.
    pub fn signal_sys_task(
        &mut self,
        to: Pid,
        signal: Signal<M>,
        priority: Priority,
    ) -> Result<(), Error> {
        self.inner
            .deliver_sys_task(self.pid, to, Payload::Signal(signal), priority)
    }
    /// Send an ordered control signal.
    pub fn signal(&mut self, to: Pid, signal: Signal<M>) -> Result<(), Error> {
        self.inner.deliver(self.pid, to, Payload::Signal(signal))
    }
    /// Start an Erlang-style timer. The VM may wrap the received envelope as `{timeout, Ref, Msg}`.
    pub fn start_timer(&mut self, ms: u64, msg: M) -> Result<TimerRef, Error> {
        self.inner.flush();
        self.inner.start_timer(self.pid, self.pid, ms, msg, true)
    }
    /// Schedule a plain message without a timer-reference wrapper.
    pub fn send_after(&mut self, ms: u64, msg: M) -> Result<TimerRef, Error> {
        self.inner.flush();
        self.inner.start_timer(self.pid, self.pid, ms, msg, false)
    }
    /// Start a runtime timer callback owned by this process.
    /// Port of erts/emulator/beam/erl_hl_timer.c (erts_start_timer_callback), OTP-29.1.1.
    pub fn start_timer_callback(
        &mut self,
        ms: u64,
        callback: TimerCallback<M>,
    ) -> Result<TimerRef, Error> {
        self.inner.flush();
        self.inner.start_timer_callback(self.pid, ms, callback)
    }
    /// Schedule a timer for a pid using this task's current scheduler worker.
    pub fn start_timer_to(
        &mut self,
        pid: Pid,
        ms: u64,
        msg: M,
        wrapped: bool,
    ) -> Result<TimerRef, Error> {
        self.inner.flush();
        self.inner.start_timer_to(pid, ms, msg, wrapped)
    }
    /// Runs `op` once every managed scheduler thread passed a thread progress point: every
    /// slice running now, this one included, ended. Never blocks; `op` runs on a scheduler
    /// thread outside every scheduler lock.
    // Port of erts/emulator/beam/erl_process.c:2351 (erts_schedule_thr_prgr_later_op) as
    // used by code_ix.c:556 (erts_schedule_code_barrier), OTP-29.1.1.
    pub fn thread_progress_later(&mut self, op: impl FnOnce() + Send + 'static) {
        self.inner
            .thread_progress_later(LaterOp::Boxed(Box::new(op)));
    }
    /// Port of erts/emulator/beam/erl_bif_info.c:5079-5091, OTP-29.1.1.
    /// Pause other running tasks until the callback returns.
    pub fn block_thread_progress(&mut self, duration: Duration) {
        self.inner.flush();
        self.inner.block_thread_progress(duration);
    }
}

/// Messages, exits, and DOWNs require the receiver to run. Link, monitor, and
/// demonitor only update control state and are applied the next time the
/// receiver is scheduled, including on exit.
fn payload_wakes<M>(payload: &Payload<M>) -> bool {
    match payload {
        Payload::Message(_) | Payload::Timer { .. } | Payload::TimerMessage { .. } => true,
        Payload::Signal(signal) => match signal {
            Signal::Exit(_)
            | Signal::ExitLinked(_)
            | Signal::PortExit(_)
            | Signal::MonitorDown { .. }
            | Signal::MonitorDownMsg { .. }
            | Signal::Suspend { .. }
            | Signal::SuspendRelease { .. }
            | Signal::SuspendDown { .. }
            | Signal::SuspendResume
            | Signal::SuspendInternal
            | Signal::SyncSuspend(_)
            | Signal::MonitorNoproc(_)
            | Signal::GarbageCollect
            | Signal::LiteralAreaCopy(_)
            | Signal::ProcSigBlock(_) => true,
            Signal::UnlinkAck(id) => *id != 0,
            Signal::UnlinkAckSignal(_) => true,
            Signal::Link
            | Signal::Unlink(_)
            | Signal::Monitor { .. }
            | Signal::Demonitor(_)
            | Signal::DemonitorOrigin(_)
            | Signal::Alias(_)
            | Signal::Unalias(_) => false,
        },
    }
}

fn take_lost_monitors<M>(events: &mut Vec<OwnedSignal<Event<M>>>) -> Vec<(Pid, u64)> {
    events
        .drain(..)
        .filter_map(|event| match event.payload {
            Payload::Signal(Signal::Monitor { reference, .. }) => Some((event.from, reference)),
            _ => None,
        })
        .collect()
}

fn process_peak_rss_bytes() -> Option<u64> {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::zeroed();
    // SAFETY: `usage` points to writable storage for the `RUSAGE_SELF` result.
    if unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) } != 0 {
        return None;
    }
    // SAFETY: getrusage initialized `usage` after returning success.
    let peak = unsafe { usage.assume_init() }.ru_maxrss as u64;
    #[cfg(target_os = "macos")]
    {
        Some(peak)
    }
    #[cfg(not(target_os = "macos"))]
    {
        Some(peak.saturating_mul(1024))
    }
}

struct Runner<'a, T: Task> {
    inner: &'a Inner<T>,
    local: Option<&'a RefCell<Local<T>>>,
}

impl<T: Task> Runner<'_, T> {
    fn bounce_monitors(&mut self, dead: Pid, lost: Vec<(Pid, u64)>) {
        for (watcher, id) in lost {
            let _ = self.inner.deliver(
                dead,
                watcher,
                Payload::Signal(Signal::MonitorNoproc(id)),
                self.local.map(RefCell::borrow_mut).as_deref_mut(),
            );
        }
    }
}
impl<T: Task> Runner<'_, T> {
    /// Publish an unscheduled child on a run queue.
    // Port of erts/emulator/beam/erl_process.c:12525 (erl_create_process), OTP-29.1.1: the
    // child joins its parent's run queue.
    fn schedule_process(&mut self, process: ProcRef<T>) -> Result<(), Error> {
        process
            .run_state()
            .compare_exchange(UNSCHEDULED, QUEUED, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| Error::NoProcess)?;
        let bound = process.bound_worker().is_some();
        let item = Scheduled::new(process);
        if bound {
            self.inner.enqueue(item, false);
        } else if let Some(local) = self.local.map(RefCell::borrow_mut).as_deref_mut() {
            // Port of erl_process.c:12525-12531 (`erl_create_process`) and
            // erl_process.c:3954 (`enqueue_process`), OTP-29.1.1: newly spawned
            // children join the caller's FIFO run queue behind earlier children.
            // The child joins the same local deque a woken process does (place_runnable), so
            // it runs before a process the parent wakes afterwards.
            if self.inner.sim.is_none() {
                local.record_queued(&item.process, local.worker_id, false);
                local.queues[item.queue()].push(item);
            } else {
                self.inner.push_run_queue(local.worker_id, item, false);
            }
        } else {
            self.inner.enqueue_new(item);
        }
        Ok(())
    }

    fn lookup(&mut self, pid: Pid) -> Option<ProcRef<T>> {
        if let Some(local) = self.local.map(RefCell::borrow_mut).as_deref_mut() {
            local.lookup(&self.inner.table, pid)
        } else {
            self.inner.table.lookup(pid)
        }
    }

    /// Publish the held monitor of this scheduler, if any.
    fn publish_deferred_monitor(&mut self) {
        if let Some(held) = PENDING_PROC_MONITOR.with(|slot| slot.borrow_mut().take()) {
            self.publish_monitor(held);
        }
    }

    /// Publish the held monitor only when it is for `to`, so the signal to `to` goes after it.
    fn publish_deferred_monitor_for(&mut self, to: Pid) {
        if let Some(held) = take_held_monitor_for(to) {
            self.publish_monitor(held);
        }
    }

    /// Send a held process monitor now. The monitor BIF has already returned, so a dead
    /// target must bounce DOWN (erl_proc_sig_queue.c:1131-1135, `noproc`).
    fn publish_monitor(&mut self, held: PendingProcMonitor) {
        let PendingProcMonitor {
            from,
            to,
            id,
            shared,
        } = held;
        let event: Event<T::Message> = Event {
            from,
            payload: Payload::Signal(Signal::Monitor {
                reference: id,
                shared,
            }),
        };
        let Event { from, payload } = event;
        let Some(process) = self.lookup(to) else {
            self.bounce_monitors(to, vec![(from, id)]);
            return;
        };
        if self
            .inner
            .deliver_process(
                &process,
                from,
                payload,
                self.local.map(RefCell::borrow_mut).as_deref_mut(),
                false,
                false,
            )
            .is_err()
        {
            self.bounce_monitors(to, vec![(from, id)]);
        }
    }
}

impl<T: Task> Runner<'_, T> {
    /// Run `handle` on the task of `process`, whose cell the caller has locked, with a
    /// context acting as that process.
    fn run_as_target(
        &mut self,
        process: &Process<T>,
        cell: &mut TaskCell<T>,
        pid: Pid,
        remaining: u32,
        handle: &mut TargetHandler<'_, T::Message>,
    ) -> bool {
        let workers = self.inner.config.workers;
        let simulated = self.inner.sim.is_some();
        let task = cell.task_mut();
        let mut ctx = RunCtx {
            inner: self,
            pid,
            input: &process.input,
            backlog: &process.input.backlog,
            bound_worker: &process.bound_worker,
            worker: None,
            worker_count: workers,
            remaining,
            budget: remaining,
            msacc_enabled: false,
            wall_enabled: false,
            gc_accounted_total: 0,
            sched_type: SchedulerType::Normal,
            user_priority: &process.user_priority,
            sys_priority: &process.sys_priority,
            active: &process.active,
            exit_flags: &process.exit_flags,
            sys_task_run: false,
            dirty_running: process.dirty_runner.load(Ordering::SeqCst) != 0,
            dirty_queued: process.dirty.load(Ordering::SeqCst) != 0
                && process.dirty_runner.load(Ordering::SeqCst) == 0,
            simulated,
        };
        handle(task, &mut ctx)
    }
}

impl<T: Task> ContextOps<T::Message> for Runner<'_, T> {
    fn thread_progress_later(&self, op: LaterOp) {
        thr_progress::schedule_later_op(&self.inner.progress, op);
    }
    // Port of erts/emulator/beam/erl_bif_info.c:5079-5091 (block, wait, unblock),
    // OTP-29.1.1: erts_thr_progress_block from a scheduler or an unmanaged thread.
    fn block_thread_progress(&self, duration: Duration) {
        thr_progress::block(&self.inner.progress);
        if !duration.is_zero() {
            thread::sleep(duration);
        }
        thr_progress::unblock(&self.inner.progress);
    }
    fn process_priority(&self, pid: Pid) -> Option<Priority> {
        let process = self.inner.table.lookup(pid)?;
        Some(Priority::from_index(
            process.user_priority.load(Ordering::Acquire),
        ))
    }
    // Port of erts/emulator/beam/erl_proc_sig_queue.c:8893
    // (erts_internal_dirty_process_handle_signals_1), OTP-29.1.1: the task cell is the
    // main process lock, taken with a try-lock.
    fn handle_dirty_signals(
        &mut self,
        pid: Pid,
        remaining: u32,
        handle: &mut dyn FnMut(&mut dyn std::any::Any, &mut RunCtx<'_, T::Message>) -> bool,
    ) -> DirtySignals {
        let inner = self.inner;
        let Some(process) = inner.table.lookup(pid) else {
            return DirtySignals::NoProc;
        };
        let state = |process: &Process<T>| {
            if process.run_state().load(Ordering::SeqCst) == EXITED {
                Some(DirtySignals::NoProc)
            } else if !Inner::in_dirty_state(process) {
                Some(DirtySignals::Normal)
            } else {
                None
            }
        };
        if let Some(result) = state(&process) {
            return result;
        }
        // `state & (ERTS_PSFLG_SIG_Q | ERTS_PSFLG_NMSG_SIG_IN_Q | ERTS_PSFLG_MSG_SIG_IN_Q)`.
        if process.input.state().load(Ordering::Acquire) & (psflg::SIG_Q | psflg::SIG_IN_Q) == 0
            && !process.input.has_pending()
        {
            return DirtySignals::Idle;
        }
        let mut cell = match process.cell.try_lock() {
            Some(cell) => cell,
            None => return state(&process).unwrap_or(DirtySignals::More),
        };
        if let Some(result) = state(&process) {
            return result;
        }
        let handled = self.run_as_target(&process, &mut cell, pid, remaining, handle);
        if handled {
            DirtySignals::Handled
        } else {
            DirtySignals::More
        }
    }
    fn with_locked_target(
        &mut self,
        pid: Pid,
        remaining: u32,
        handle: &mut dyn FnMut(&mut dyn std::any::Any, &mut RunCtx<'_, T::Message>),
    ) -> Result<(), SignalFreeError> {
        let process = self
            .inner
            .table
            .lookup(pid)
            .ok_or(SignalFreeError::NoProcess)?;
        // A dirty job runs without the main lock, so its process can be locked here too.
        let check = |process: &Process<T>| match process.run_state().load(Ordering::SeqCst) {
            EXITED => Err(SignalFreeError::NoProcess),
            RUNNING if process.dirty_runner.load(Ordering::SeqCst) == 0 => {
                Err(SignalFreeError::Busy)
            }
            _ => Ok(()),
        };
        check(&process)?;
        let mut cell = process.cell.try_lock().ok_or(SignalFreeError::Busy)?;
        check(&process)?;
        self.run_as_target(&process, &mut cell, pid, remaining, &mut |task, ctx| {
            handle(task, ctx);
            true
        });
        Ok(())
    }
    fn deliver_sys_task(
        &mut self,
        from: Pid,
        to: Pid,
        payload: Payload<T::Message>,
        priority: Priority,
    ) -> Result<(), Error> {
        // Keep signal order: a monitor deferred for `to` goes first.
        self.publish_deferred_monitor_for(to);
        self.inner.deliver_sys_task(from, to, payload, priority)
    }
    fn start_resolved_timer(
        &mut self,
        owner: Pid,
        ms: u64,
        resolve: Arc<dyn Fn() -> Option<Pid> + Send + Sync>,
        msg: T::Message,
        wrapped: bool,
    ) -> Result<TimerRef, Error> {
        self.inner.start_resolved_timer(
            owner,
            ms,
            resolve,
            msg,
            wrapped,
            self.local.map(RefCell::borrow_mut).as_deref_mut(),
        )
    }

    fn request_aux_work_all(&mut self, work: SchedulerAuxWork) {
        self.inner.request_aux_work_all(work);
    }

    fn begin_halt(
        &mut self,
        pid: Pid,
        code: i32,
        timeout: Option<(u64, TimerCallback<T::Message>)>,
        actions: HaltActions,
    ) -> bool {
        self.inner.begin_halt(
            pid,
            code,
            timeout,
            actions,
            self.local.map(RefCell::borrow_mut).as_deref_mut(),
        )
    }

    fn cancel_target_timers(&mut self, pid: Pid) {
        if let Some(timers) = self.inner.sim_timers.as_ref() {
            for wheel in timers {
                let mut wheel = wheel.lock().unwrap();
                let ids = self.inner.bif_timer_ids(pid, wheel.worker());
                wheel.cancel_target(&ids);
                self.inner.apply_link_events(&mut wheel);
            }
            self.inner.destroy_paused_bif_timers(pid);
            return;
        }
        // Port of erts/emulator/beam/erl_hl_timer.c:2455 (erts_cancel_bif_timers), OTP-29.1.1:
        // only the wheels holding the receiver's timers are visited; a canceled timer on
        // another scheduler is handed to it as aux work.
        self.inner.destroy_paused_bif_timers(pid);
        let wheels = self.inner.table.lookup(pid).map_or(u64::MAX, |process| {
            process.bif_timer_wheels.swap(0, Ordering::AcqRel)
        });
        if wheels == 0 {
            return;
        }
        let current_worker = self
            .local
            .map(RefCell::borrow)
            .as_deref()
            .map(|local| local.worker_id);
        if let Some(local) = self.local.map(RefCell::borrow_mut).as_deref_mut()
            && wheels & timer_wheel_bit(local.worker_id) != 0
        {
            let ids = self.inner.bif_timer_ids(pid, local.worker_id);
            let mut service = local.timer_service.borrow_mut();
            service.wheel.cancel_target(&ids);
            self.inner.apply_link_events(&mut service.wheel);
        }
        for worker in 0..self.inner.timer_commands.len() {
            if Some(worker) == current_worker || wheels & timer_wheel_bit(worker) == 0 {
                continue;
            }
            let ids = self.inner.bif_timer_ids(pid, worker);
            if let Some(service) = self.inner.owner_timer_service(worker) {
                let mut service = service.borrow_mut();
                service.wheel.cancel_target(&ids);
                self.inner.apply_link_events(&mut service.wheel);
                continue;
            }
            let Some(queue) = self.inner.timer_commands.get(worker) else {
                continue;
            };
            queue.push(TimerCommand::CancelTarget { ids });
            self.inner.wake_worker(worker);
        }
    }

    fn schedule_spawn(&mut self, pid: Pid) -> Result<(), Error> {
        let process = self.lookup(pid).ok_or(Error::NoProcess)?;
        self.schedule_process(process)
    }
    fn schedule_spawned(&mut self, spawned: SpawnedProcess<T::Message>) -> Result<(), Error> {
        let process = spawned.process.downcast::<T>().ok_or(Error::NoProcess)?;
        self.schedule_process(process)
    }
    fn deliver_node(
        &mut self,
        to: Pid,
        signal: OwnedSignal<Event<T::Message>>,
    ) -> Result<(), Error> {
        let from = signal.from;
        let monitor = matches!(signal.payload, Payload::Signal(Signal::Monitor { .. }));
        // Port of erts/emulator/beam/erl_proc_sig_queue.c:1102-1125 (esdp->pending_signal),
        // OTP-29.1.1: on a normal scheduler every process monitor is held; a monitor replaces
        // the held one, which goes out first.
        if let Payload::Signal(Signal::Monitor { reference, shared }) = &signal.payload
            && matches!(current_scheduler_type(), SchedulerType::Normal)
        {
            let held = PendingProcMonitor {
                from,
                to,
                id: *reference,
                shared: shared.clone(),
            };
            let previous = PENDING_PROC_MONITOR.with(|slot| slot.borrow_mut().replace(held));
            if let Some(previous) = previous {
                self.publish_monitor(previous);
            }
            return Ok(());
        }
        // Erts sends the held monitor first when the next signal goes to its target
        // (erl_proc_sig_queue.c:1141-1150); a signal to another target leaves it held.
        let deferred = take_held_monitor_for(to).map(|held| {
            T::Message::signal_node(
                held.from,
                Signal::Monitor {
                    reference: held.id,
                    shared: held.shared,
                },
            )
        });
        // Port of erts/emulator/beam/erl_process.h (erts_proc_lookup_raw), OTP-29.1.1: no
        // reference count is taken on the receiver.
        let inner = self.inner;
        inner
            .table
            .with_live(to, |process| -> Result<(), Error> {
                let waiting = process.run_state().load(Ordering::Acquire) == WAITING;
                let wakes = payload_wakes(&signal.payload);
                let force_enqueue =
                    matches!(&signal.payload, Payload::Signal(Signal::LiteralAreaCopy(_)));
                // A literal-copy request is never buffered: a request lost to an exiting target
                // would never be answered, so the sender must see `NoProcess` at once. Port of
                // erts/emulator/beam/erl_proc_sig_queue.c:3480 (erts_proc_sig_send_cla_request), OTP-29.1.1.
                // Neither is a link: erts enqueues it at once and `link/1` answers a target that is
                // already gone with a `noproc` link exit; a buffered link dropped at slice end would
                // lose the target's exit signal. Port of erts/emulator/beam/bif.c:180-183 (link_opt),
                // OTP-29.1.1.
                let link = matches!(&signal.payload, Payload::Signal(Signal::Link));
                if waiting || monitor || link || deferred.is_some() || force_enqueue {
                    if let Some(first) = deferred {
                        // The held monitor and this signal enter the queue together.
                        let second = signal;
                        let (first, second) = match process.input.push_pair(first, second) {
                            Ok(()) => {
                                self.inner.fanin_delivery(process, 2);
                                process.input.backlog.fetch_add(2, Ordering::Relaxed);
                                if wakes {
                                    self.inner.wake_after_publish(
                                        process,
                                        self.local.map(RefCell::borrow_mut).as_deref_mut(),
                                        force_enqueue,
                                        None,
                                    );
                                }
                                return Ok(());
                            }
                            Err(pair) => pair,
                        };
                        let mut events = self
                            .local
                            .map(RefCell::borrow_mut)
                            .as_deref_mut()
                            .and_then(|local| local.message_slabs.pop())
                            .unwrap_or_else(|| Vec::with_capacity(2));
                        events.push(first);
                        events.push(second);
                        let delivered = self.inner.deliver_block(
                            process,
                            &mut events,
                            self.local.map(RefCell::borrow_mut).as_deref_mut(),
                            wakes,
                            force_enqueue,
                        );
                        let lost = if delivered.is_err() {
                            take_lost_monitors(&mut events)
                        } else {
                            Vec::new()
                        };
                        events.clear();
                        if let Some(local) = self.local.map(RefCell::borrow_mut).as_deref_mut()
                            && local.message_slabs.len() < 64
                        {
                            local.message_slabs.push(events);
                        }
                        if delivered.is_err() {
                            self.bounce_monitors(to, lost);
                            return Err(Error::NoProcess);
                        }
                    } else {
                        self.inner.deliver_process_node(
                            process,
                            signal,
                            self.local.map(RefCell::borrow_mut).as_deref_mut(),
                            wakes,
                            force_enqueue,
                        )?;
                    }
                    // Port of erts/emulator/beam/erl_message.c:698 (erts_send_message), OTP-29.1.1.
                    // Message queue depth does not create a scheduler event for the sender.
                    return Ok(());
                }
                // Port of erts/emulator/beam/erl_message.c:698 (erts_send_message) and
                // erl_proc_sig_queue.c:712 (enqueue_signals), OTP-29.1.1: the signal is appended to
                // the receiver's in-queue now; erts keeps no per-sender buffer to publish later. A
                // receiver that is already gone drops it, as erts does for a dead receiver.
                let _ = self.inner.deliver_live_node(
                    process,
                    signal,
                    self.local.map(RefCell::borrow_mut).as_deref_mut(),
                );
                Ok(())
            })
            .ok_or(Error::NoProcess)?
    }
    fn flush(&mut self) {
        self.publish_deferred_monitor();
    }
    fn signal_probe(&mut self, pid: Pid) -> Option<SignalProbe<T::Message>> {
        let process = self.lookup(pid)?;
        Some(SignalProbe::of(&process))
    }
    fn total_reductions(&self) -> u64 {
        if self.inner.sim.is_some() {
            return self.inner.simulation_stats().reductions;
        }
        self.inner
            .scheduler_stats(self.local.map(RefCell::borrow).as_deref(), 0)
            .reductions
    }
    fn scheduler_stats(&self) -> SchedulerStats {
        self.inner
            .scheduler_stats(self.local.map(RefCell::borrow).as_deref(), 0)
    }
    fn set_msacc_state(&mut self, state: MsaccState) {
        if let Some(local) = self.local.map(RefCell::borrow_mut).as_deref_mut() {
            local.set_msacc_state(state);
        }
    }
    fn set_msacc_enabled(&mut self, enabled: bool) {
        if let Some(local) = self.local.map(RefCell::borrow_mut).as_deref_mut() {
            local.set_msacc_enabled(enabled);
        }
    }
    fn reclassify_gc_ns(&mut self, nanoseconds: u64) {
        if let Some(local) = self.local.map(RefCell::borrow_mut).as_deref_mut()
            && local.msacc_enabled
        {
            local.msacc_ns[MsaccState::Emulator as usize] =
                local.msacc_ns[MsaccState::Emulator as usize].saturating_sub(nanoseconds);
            local.msacc_ns[MsaccState::Gc as usize] =
                local.msacc_ns[MsaccState::Gc as usize].saturating_add(nanoseconds);
        }
    }
    fn set_wall_accounting_enabled(&mut self, enabled: bool) {
        if let Some(local) = self.local.map(RefCell::borrow_mut).as_deref_mut() {
            let _ = self.inner.take_wall_start(local.worker_id);
            local.set_wall_enabled(enabled);
        }
    }
    fn mark_exited(&mut self, pid: Pid) {
        // Port of erts/emulator/beam/erl_process.c:14448-14456
        // (`erts_ptab_delete_element` while this process is still current), OTP-29.1.1.
        // One delete: the free-id ring hands the slot to the next spawn, and a second
        // delete of the same pix would destroy that process.
        if let Some(process) = self.inner.table.lookup(pid) {
            process.run_state().store(EXITED, Ordering::SeqCst);
            self.inner.table.remove(pid);
        }
    }
    fn start_timer(
        &mut self,
        owner: Pid,
        target: Pid,
        ms: u64,
        msg: T::Message,
        wrapped: bool,
    ) -> Result<TimerRef, Error> {
        // Message timers may belong to another worker; receive timeouts do not
        // use this path.
        self.inner.start_timer(
            owner,
            ms,
            TimerPayload::Message(target, msg, wrapped),
            self.local.map(RefCell::borrow_mut).as_deref_mut(),
            None,
        )
    }
    fn start_timer_callback(
        &mut self,
        pid: Pid,
        ms: u64,
        callback: TimerCallback<T::Message>,
    ) -> Result<TimerRef, Error> {
        self.inner.start_timer(
            pid,
            ms,
            TimerPayload::Callback(pid, callback),
            self.local.map(RefCell::borrow_mut).as_deref_mut(),
            None,
        )
    }
    fn start_timer_to(
        &mut self,
        pid: Pid,
        ms: u64,
        msg: T::Message,
        wrapped: bool,
    ) -> Result<TimerRef, Error> {
        self.inner.start_timer(
            pid,
            ms,
            TimerPayload::Message(pid, msg, wrapped),
            self.local.map(RefCell::borrow_mut).as_deref_mut(),
            None,
        )
    }
}

/// Scheduler facade. Dropping it stops and joins worker threads.
pub struct Scheduler<T: Task> {
    inner: Arc<Inner<T>>,
    threads: Vec<JoinHandle<()>>,
    virtual_clock: Option<Arc<VirtualClock>>,
}

/// A point-in-time snapshot of scheduler work and execution counters.
#[derive(Clone, Debug)]
pub struct SchedulerStats {
    /// Runnable processes assigned to each worker.
    pub run_queue_lengths: Vec<u64>,
    /// Runnable or currently running processes assigned to each worker.
    pub active_tasks: Vec<u64>,
    /// Nanoseconds spent executing tasks on each worker while accounting was enabled.
    pub active_ns: Vec<u64>,
    /// Per-worker microstate nanoseconds in `MsaccState` order.
    pub msacc_ns: Vec<[u64; MSACC_STATE_COUNT]>,
    /// Number of task dispatches since scheduler creation.
    pub context_switches: u64,
    /// Number of reductions consumed by tasks since scheduler creation.
    pub reductions: u64,
    /// Workers currently executing a task.
    pub active_schedulers: u64,
    /// Nanoseconds since scheduler creation.
    pub elapsed_ns: u64,
    /// Nanoseconds each dirty CPU (index 0) and dirty I/O (index 1) thread spent executing tasks.
    pub dirty_active_ns: [Vec<u64>; 2],
    /// Per dirty CPU (index 0) and dirty I/O (index 1) thread microstate nanoseconds.
    pub dirty_msacc_ns: [Vec<[u64; MSACC_STATE_COUNT]>; 2],
    /// Processes waiting in the dirty CPU and dirty I/O run queues.
    pub dirty_run_queue_lengths: [u64; 2],
}

impl<T: Task> Scheduler<T> {
    /// Start real worker threads.
    pub fn new(config: Config) -> Self {
        arinsal_term::set_reader_groups(config.workers);
        // Port of erts/emulator/beam/erl_alloc.c (erts_alloc_init sizes the instances from
        // erts_no_schedulers), OTP-29.1.1. A launcher that already configured the allocators
        // (with `+Mdai`) or an earlier runtime in this process keeps its counts.
        let _ = arinsal_alloc::typed::configure(config.workers.max(1), 0);
        Self::build(config, Arc::new(RealClock(Instant::now())), None, None)
    }

    /// Build a single-threaded scheduler with a reproducible seed and virtual clock.
    pub fn simulation(config: Config, seed: u64) -> Self {
        let clock = Arc::new(VirtualClock::default());
        Self::build(
            config,
            clock.clone(),
            Some(Box::new(SeededRng::new(seed))),
            Some(clock),
        )
    }

    /// Build a simulator with injected clock and random generator.
    pub fn simulation_with(config: Config, clock: Arc<dyn Clock>, rng: Box<dyn Rng>) -> Self {
        Self::build(config, clock, Some(rng), None)
    }

    fn build(
        mut config: Config,
        clock: Arc<dyn Clock>,
        rng: Option<Box<dyn Rng>>,
        virtual_clock: Option<Arc<VirtualClock>>,
    ) -> Self {
        assert!(config.max_processes > 0 && config.max_processes <= PID_LIMIT);
        assert!(config.reductions > 0);
        config.workers = config.workers.max(1);
        let dirty_cpu = config.dirty_cpu_schedulers.max(1);
        let dirty_io = config.dirty_io_schedulers.max(1);
        let simulated = rng.is_some();
        let workers = if simulated { 1 } else { config.workers };
        let parked: Arc<[AtomicBool]> = (0..workers).map(|_| AtomicBool::new(false)).collect();
        let sleepers: Arc<[OnceLock<thread::Thread>]> =
            (0..workers).map(|_| OnceLock::new()).collect();
        // The simulated scheduler runs no scheduler threads, so it has no managed threads.
        let progress = Arc::new(if simulated {
            thr_progress::ThrProgress::new(Arc::from([]), Arc::from([]))
        } else {
            thr_progress::ThrProgress::new(Arc::clone(&parked), Arc::clone(&sleepers))
        });
        let balance = Arc::new(balance::Balance::new(workers, workers, config.compact_load));
        let now = clock.now_ms();
        let timer_commands: Vec<_> = (0..workers).map(|_| Arc::new(SegQueue::new())).collect();
        let canceled_timers: Vec<_> = (0..workers).map(|_| Arc::new(SegQueue::new())).collect();
        let mut locals = Vec::new();
        let mut stealers = Vec::new();
        for worker_id in 0..workers {
            let queues = std::array::from_fn(|_| Worker::new_fifo());
            stealers.push(std::array::from_fn(|i| queues[i].stealer()));
            locals.push(LocalInit {
                worker_id,
                balance: balance.clone(),
                timer_service: TimerService {
                    wheel: Wheel::new(now).for_worker(worker_id),
                    commands: timer_commands[worker_id].clone(),
                    canceled: canceled_timers[worker_id].clone(),
                },
                queues,
                message_slabs: Vec::new(),
                pending_waits: Vec::new(),
                check_time_reds: 0,
                last_monotonic_ms: now,
                profile_active: false,
                last_process: None,
                metric_deltas: vec![0; workers],
                dirty_metrics: Vec::new(),
                metric_marked: vec![false; workers],
                context_switches: 0,
                reductions: 0,
                active_ns: 0,
                active_started: None,
                wall_enabled: false,
                msacc_ns: [0; MSACC_STATE_COUNT],
                msacc_state: MsaccState::Other,
                msacc_started: None,
                msacc_enabled: false,
            });
        }
        let inner = Arc::new(Inner {
            table: ProcessTable::new(config.max_processes, Arc::clone(&progress)),
            config,
            run_queues: (0..workers)
                .map(|_| std::array::from_fn(|_| SegQueue::new()))
                .collect(),
            run_queue_flags: (0..workers).map(|_| AtomicU32::new(0)).collect(),
            pinned_injectors: (0..workers)
                .map(|_| std::array::from_fn(|_| SegQueue::new()))
                .collect(),
            stealers,
            sim_timers: simulated.then(|| {
                (0..workers)
                    .map(|worker| Mutex::new(Wheel::new(now).for_worker(worker)))
                    .collect()
            }),
            timer_commands,
            canceled_timers,
            next_timer: AtomicU64::new(1),
            clock,
            sim_data: Mutex::new(T::SchedulerData::default()),
            sim: rng.map(|rng| {
                Mutex::new(SimState {
                    queue: VecDeque::new(),
                    rng,
                })
            }),
            stopped: AtomicBool::new(false),
            halt_started: AtomicBool::new(false),
            halt_requested: AtomicBool::new(false),
            runq_halting: (0..workers)
                .map(|_| AtomicBool::new(false))
                .collect::<Vec<_>>()
                .into(),
            searching: AtomicU32::new(0),
            active_schedulers: AtomicUsize::new(0),
            worker_stats: (0..workers)
                .map(|_| WorkerCounters {
                    context_switches: AtomicU64::new(0),
                    reductions: AtomicU64::new(0),
                    active_ns: AtomicU64::new(0),
                })
                .collect(),
            stats_requests: (0..workers).map(|_| SegQueue::new()).collect(),
            aux_work: (0..workers).map(|_| SegQueue::new()).collect(),
            aux_work_flags: (0..workers).map(|_| AtomicU32::new(0)).collect(),
            accounting_flags: AtomicU8::new(0),
            worker_counts: (0..workers)
                .map(|_| WorkerQueueCount(AtomicU64::new(0)))
                .collect(),
            online_schedulers: AtomicUsize::new(workers),
            next_queue: AtomicUsize::new(0),
            scheduling_blocked: AtomicBool::new(false),
            scheduling_blocker: AtomicUsize::new(usize::MAX),
            started_at: Instant::now(),
            wall_start_requests: Mutex::new(vec![None; workers]),
            work_epochs: (0..workers).map(|_| AtomicU64::new(0)).collect(),
            in_schedule: (0..workers).map(|_| AtomicBool::new(false)).collect(),
            parked: Arc::clone(&parked),
            poll_sleeping: (0..workers).map(|_| AtomicBool::new(false)).collect(),
            waiting_schedulers: AtomicUsize::new(0),
            sleepers: Arc::clone(&sleepers),
            fanin_stats: std::env::var_os("ARINSAL_FANIN_STATS").is_some(),
            fanin_delivered: AtomicU64::new(0),
            fanin_peak_backlog: AtomicUsize::new(0),
            progress,
            dirty: [
                DirtyPool::new(dirty_cpu, 0),
                DirtyPool::new(dirty_io, dirty_cpu),
            ],
            msb_exec: Mutex::new(MsbExec {
                current: SchedulerType::Normal,
                last_dirty: SchedulerType::DirtyIo,
            }),
            msb_switch: Condvar::new(),
            dirty_signal_handlers: OnceLock::new(),
            balance,
            port_queues: (0..workers).map(|_| ports::PortQueue::default()).collect(),
        });
        let mut threads = Vec::new();
        if !simulated {
            for (id, local) in locals.into_iter().enumerate() {
                let inner = inner.clone();
                threads.push(thread::spawn(move || {
                    worker_loop(inner, id, local.into_local())
                }));
            }
            // Port of erts/emulator/beam/erl_process.c:8890 (erts_start_schedulers, dirty
            // scheduler threads), OTP-29.1.1.
            for (kind, count) in [(DirtyKind::Cpu, dirty_cpu), (DirtyKind::Io, dirty_io)] {
                for index in 0..count {
                    let inner = inner.clone();
                    let name = match kind {
                        DirtyKind::Cpu => format!("{}_dirty_cpu_scheduler", index + 1),
                        DirtyKind::Io => format!("{}_dirty_io_scheduler", index + 1),
                    };
                    let handle = thread::Builder::new()
                        .name(name)
                        .spawn(move || dirty_scheduler_loop(inner, kind, index))
                        .expect("spawn dirty scheduler thread");
                    threads.push(handle);
                }
            }
        }
        Self {
            inner,
            threads,
            virtual_clock,
        }
    }

    /// Run `f` on the process-local exit words of `pid`.
    ///
    /// The words live on the scheduler process, not behind the task cell, so a running
    /// process and another process can publish them without taking each other's cell lock.
    pub fn with_proc_flags<R>(&self, pid: Pid, f: impl FnOnce(&AtomicU32) -> R) -> Option<R> {
        // Port of erts/emulator/beam/erl_process_lock.h:1135 (erts_proc_lookup_raw),
        // OTP-29.1.1: the slot load does not increment the process refcount.
        self.inner
            .table
            .with_live(pid, |process| f(&process.exit_flags))
    }
    /// Whether signals wait in the outer signal queue of `pid`. `None` when the process is not
    /// alive. A light caller reads its own state only while this is false.
    // Port of erts/emulator/beam/erl_proc_sig_queue.c:1547 (pending signal probe), OTP-29.1.1.
    pub fn input_has_pending(&self, pid: Pid) -> Option<bool> {
        self.inner
            .table
            .with_live(pid, |process| process.input.has_pending())
    }
    /// Whether `pid` is alive with no exit started and no signals queued: the state word has none of
    /// `ERTS_PSFLG_EXITING | SIG_Q | MSG_SIG_IN_Q | NMSG_SIG_IN_Q`. `None` when the process is gone.
    // Port of erts/emulator/beam/erl_bif_info.c (is_process_alive_1: the state test before BIF_TRAP1),
    // OTP-29.1.1.
    pub fn is_quiet(&self, pid: Pid) -> Option<bool> {
        self.inner.table.with_live(pid, |process| {
            process.exit_flags.load(Ordering::Acquire) & proc_flags::EXITING == 0
                && process.input.state().load(Ordering::Acquire) & (psflg::SIG_Q | psflg::SIG_IN_Q)
                    == 0
        })
    }
    /// Spawn a normal-priority task.
    pub fn spawn(&self, task: T) -> Result<Pid, Error> {
        self.spawn_priority(task, Priority::Normal)
    }
    /// Insert a child whose caller will publish it with [`RunCtx::schedule_spawn`].
    /// The caller must schedule it exactly once, including after any later error.
    pub fn spawn_unscheduled(&self, task: T) -> Result<Pid, Error> {
        self.spawn_unscheduled_with_priority(task, Priority::Normal)
    }
    /// Insert an unscheduled task at a chosen priority.
    pub fn spawn_unscheduled_with_priority(
        &self,
        task: T,
        priority: Priority,
    ) -> Result<Pid, Error> {
        Ok(self.spawn_unscheduled_handle(task, priority)?.pid)
    }
    /// [`Self::spawn_unscheduled_with_priority`], returning the child for
    /// [`RunCtx::schedule_spawned`].
    pub fn spawn_unscheduled_handle(
        &self,
        task: T,
        priority: Priority,
    ) -> Result<SpawnedProcess<T::Message>, Error> {
        let process = self.inner.table.insert(task, priority, None)?;
        process.run_state().store(UNSCHEDULED, Ordering::Release);
        Ok(SpawnedProcess {
            pid: process.pid,
            process: process.erase(),
            _message: std::marker::PhantomData,
        })
    }
    /// Insert a child built by `make` and set up in place by `init` before it is published,
    /// on the one-based scheduler `scheduler_id` when given; the caller schedules it with
    /// [`RunCtx::schedule_spawned`].
    ///
    /// Port of erts/emulator/beam/erl_process.c (erl_create_process: alloc_process, then the
    /// fields initialized in place), OTP-29.1.1.
    pub fn spawn_unscheduled_init<E>(
        &self,
        make: impl for<'slot> FnOnce(&'slot mut std::mem::MaybeUninit<T>) -> &'slot mut T,
        init: impl FnOnce(&mut T) -> Result<(), E>,
        priority: Priority,
        scheduler_id: Option<usize>,
    ) -> Result<SpawnedProcess<T::Message>, SpawnInitError<E>> {
        let bound = match scheduler_id {
            Some(id) => {
                let worker = id
                    .checked_sub(1)
                    .filter(|worker| *worker < self.inner.config.workers)
                    .ok_or(SpawnInitError::Table(Error::Capacity))?;
                Some(worker)
            }
            None => None,
        };
        let process = self.inner.table.insert_init(make, init, priority, bound)?;
        process.run_state().store(UNSCHEDULED, Ordering::Release);
        Ok(SpawnedProcess {
            pid: process.pid,
            process: process.erase(),
            _message: std::marker::PhantomData,
        })
    }
    /// Insert a child whose caller publishes it on a one-based scheduler id.
    pub fn spawn_unscheduled_on(&self, task: T, scheduler_id: usize) -> Result<Pid, Error> {
        self.spawn_unscheduled_on_with_priority(task, scheduler_id, Priority::Normal)
    }
    /// Insert an unscheduled task on a chosen scheduler and at a chosen priority.
    pub fn spawn_unscheduled_on_with_priority(
        &self,
        task: T,
        scheduler_id: usize,
        priority: Priority,
    ) -> Result<Pid, Error> {
        Ok(self
            .spawn_unscheduled_on_handle(task, scheduler_id, priority)?
            .pid)
    }
    /// [`Self::spawn_unscheduled_on_with_priority`], returning the child for
    /// [`RunCtx::schedule_spawned`].
    pub fn spawn_unscheduled_on_handle(
        &self,
        task: T,
        scheduler_id: usize,
        priority: Priority,
    ) -> Result<SpawnedProcess<T::Message>, Error> {
        let worker = scheduler_id.checked_sub(1).ok_or(Error::Capacity)?;
        if worker >= self.inner.config.workers {
            return Err(Error::Capacity);
        }
        let process = self.inner.table.insert(task, priority, Some(worker))?;
        process.run_state().store(UNSCHEDULED, Ordering::Release);
        Ok(SpawnedProcess {
            pid: process.pid,
            process: process.erase(),
            _message: std::marker::PhantomData,
        })
    }
    /// Make an inserted child runnable after its caller publishes it.
    pub fn schedule_unscheduled(&self, pid: Pid) -> Result<(), Error> {
        let process = self.inner.table.lookup(pid).ok_or(Error::NoProcess)?;
        process
            .run_state()
            .compare_exchange(UNSCHEDULED, QUEUED, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| Error::NoProcess)?;
        self.inner.enqueue_new(Scheduled::new(process));
        Ok(())
    }
    /// Spawn onto one run queue without binding the process to that scheduler.
    ///
    /// Boot system processes are created on the boot scheduler's run queue. A
    /// non-scheduler thread would otherwise spread them, which wakes schedulers
    /// that are still in their initial `scheduler_wait`.
    pub fn spawn_priority_on(
        &self,
        task: T,
        priority: Priority,
        worker: usize,
    ) -> Result<Pid, Error> {
        if worker >= self.inner.parked.len() {
            return Err(Error::Capacity);
        }
        let process = self.inner.table.insert(task, priority, None)?;
        let pid = process.pid;
        process.run_state().store(QUEUED, Ordering::Release);
        process.scheduler_id.store(worker, Ordering::Relaxed);
        let item = Scheduled::new(process);
        let scheduler = self.inner.enqueue_run_queue(&item.process);
        self.inner.push_run_queue(scheduler, item, false);
        Ok(pid)
    }
    /// Spawn a task at a chosen scheduler priority.
    pub fn spawn_priority(&self, task: T, priority: Priority) -> Result<Pid, Error> {
        let process = self.inner.table.insert(task, priority, None)?;
        let pid = process.pid;
        process.run_state().store(QUEUED, Ordering::Release);
        self.inner.enqueue_new(Scheduled::new(process));
        Ok(pid)
    }
    /// Queue a message from one logical sender.
    pub fn send(&self, from: Pid, to: Pid, msg: T::Message) -> Result<(), Error> {
        self.inner.publish_held_monitor_for(to, None);
        self.inner.deliver(from, to, Payload::Message(msg), None)
    }
    /// [`Self::send`] of a message node the sender allocated.
    pub fn send_node(&self, to: Pid, signal: OwnedSignal<Event<T::Message>>) -> Result<(), Error> {
        self.inner.publish_held_monitor_for(to, None);
        self.inner.deliver_node(to, signal, None)
    }
    /// Queue an ordered block of messages from one logical sender and notify the receiver
    /// after the block is published.
    ///
    /// Port of erts/emulator/beam/erl_port_task.c (`erts_port_task_execute` runs port
    /// tasks to a scheduling boundary) and erl_proc_sig_queue.h
    /// (`erts_proc_notify_new_message`), OTP-29.1.1.
    pub fn send_block(&self, from: Pid, to: Pid, messages: Vec<T::Message>) -> Result<(), Error> {
        if messages.is_empty() {
            return Ok(());
        }
        self.send_node_block(
            to,
            messages
                .into_iter()
                .map(|message| {
                    OwnedSignal::new(Event {
                        from,
                        payload: Payload::Message(message),
                    })
                })
                .collect(),
        )
    }
    /// [`Self::send_block`] of message nodes the sender allocated.
    pub fn send_node_block(
        &self,
        to: Pid,
        mut events: Vec<OwnedSignal<Event<T::Message>>>,
    ) -> Result<(), Error> {
        if events.is_empty() {
            return Ok(());
        }
        self.inner.publish_held_monitor_for(to, None);
        let process = self.inner.table.lookup(to).ok_or(Error::NoProcess)?;
        self.inner
            .deliver_block(&process, &mut events, None, true, false)
    }
    /// [`Self::send`] for a sender running on one of this scheduler's normal threads: a woken
    /// receiver that belongs to that thread's run queue joins it directly. Any other thread
    /// takes the plain send.
    ///
    /// Port of erts/emulator/beam/erl_process.c (add2runq on the calling scheduler's own run
    /// queue, reached from erts_proc_notify_new_message), OTP-29.1.1.
    fn send_from_native(&self, from: Pid, to: Pid, msg: T::Message) -> Result<(), Error> {
        let inner = Arc::as_ptr(&self.inner) as usize;
        let mut msg = Some(msg);
        let mut sent = None;
        native_sender::with::<T::Message, _>(|handle| {
            if handle.belongs_to(inner) {
                match handle.send(from, to, msg.take().expect("message present")) {
                    Ok(result) => sent = Some(result),
                    Err(returned) => msg = Some(returned),
                }
            }
        });
        match sent {
            Some(result) => result,
            None => self.send(from, to, msg.take().expect("message not sent")),
        }
    }
    /// Queue a signal in the same ordered stream.
    pub fn signal(&self, from: Pid, to: Pid, signal: Signal<T::Message>) -> Result<(), Error> {
        self.inner.publish_held_monitor_for(to, None);
        self.inner.deliver(from, to, Payload::Signal(signal), None)
    }
    /// User priority of a live process.
    pub fn process_priority(&self, pid: Pid) -> Option<Priority> {
        self.inner.table.with_live(pid, |process| {
            Priority::from_index(process.user_priority.load(Ordering::Acquire))
        })
    }
    /// Send an ordered signal from a process running on this thread, without a turn context.
    /// The erts BIF path (`erts_proc_sig_send_*` from `c_p`) holds a process monitor on the
    /// scheduler, so this shares the turn's delivery rules and needs no `RunCtx`.
    pub fn signal_ordered(
        &self,
        from: Pid,
        to: Pid,
        signal: Signal<T::Message>,
    ) -> Result<(), Error> {
        let mut runner = Runner {
            inner: &self.inner,
            local: None,
        };
        <Runner<'_, T> as ContextOps<T::Message>>::deliver(
            &mut runner,
            from,
            to,
            Payload::Signal(signal),
        )
    }
    /// Run one copy of `work` on every scheduler at its next scheduling point.
    pub fn request_aux_work_all(&self, work: impl Fn(usize) + Send + Sync + 'static) {
        self.inner.request_aux_work_all(Arc::new(work));
    }
    /// Run `work` once on normal scheduler `ix` (clamped to the scheduler count) at its
    /// next scheduling point (`erts_schedule_misc_aux_work`).
    pub fn request_aux_work(&self, ix: usize, work: impl FnOnce() + Send + 'static) {
        let work = Mutex::new(Some(work));
        let ix = ix.min(self.inner.aux_work.len().saturating_sub(1));
        self.inner.request_aux_work_one(
            ix,
            Arc::new(move |_| {
                if let Some(work) = work.lock().unwrap_or_else(|e| e.into_inner()).take() {
                    work();
                }
            }),
        );
    }
    /// Put a port with scheduled tasks on its run queue (`prt->run_queue`), or the run
    /// queue the migration paths send it to, and notify that run queue's scheduler.
    pub fn enqueue_port(&self, port: Arc<dyn RunPort>) {
        self.inner.enqueue_port(port);
    }
    /// The run queue of a port created on the calling thread: the calling normal
    /// scheduler's run queue, else run queue 0.
    ///
    /// Port of erts/emulator/beam/io.c:352-359 (create_port), OTP-29.1.1.
    pub fn current_run_queue(&self) -> usize {
        self.inner.current_worker().unwrap_or(0)
    }
    /// Wake a task that is waiting without a mailbox event.
    pub fn wake(&self, pid: Pid) -> bool {
        self.inner.wake_waiting(pid)
    }
    /// Register the dirty signal handler processes for normal (and low), high and max
    /// priority processes. `message` builds the notification naming a process in a dirty
    /// state with signals to handle. Returns `false` when handlers are already set.
    ///
    /// Port of erts/emulator/beam/erl_init.c:2570-2597 (dirty signal handler startup),
    /// OTP-29.1.1.
    pub fn set_dirty_signal_handlers(
        &self,
        normal: Pid,
        high: Pid,
        max: Pid,
        message: impl Fn(Pid) -> Option<T::Message> + Send + Sync + 'static,
    ) -> bool {
        self.inner
            .dirty_signal_handlers
            .set(DirtySignalHandlers {
                normal,
                high,
                max,
                message: Box::new(message),
            })
            .is_ok()
    }
    /// Whether the task is currently executing on a dirty scheduler.
    ///
    /// Port of erts/emulator/beam/erl_process.c:9216
    /// (`erts_internal_is_process_executing_dirty_1`), OTP-29.1.1.
    pub fn is_executing_dirty(&self, pid: Pid) -> bool {
        self.inner
            .table
            .lookup(pid)
            .is_some_and(|process| process.dirty_runner.load(Ordering::Acquire) != 0)
    }
    /// Number of dirty CPU and dirty I/O scheduler threads.
    pub fn dirty_scheduler_counts(&self) -> (usize, usize) {
        (
            self.inner.dirty[0].threads.len(),
            self.inner.dirty[1].threads.len(),
        )
    }
    /// Set how many dirty CPU scheduler threads may execute dirty jobs.
    ///
    /// Port of erts/emulator/beam/erl_process.c:7266 (erts_set_schedulers_online, dirty CPU
    /// part), OTP-29.1.1: offline dirty CPU schedulers stop picking jobs from the shared queue.
    pub fn set_dirty_cpu_online(&self, online: usize) -> bool {
        let pool = &self.inner.dirty[0];
        if online == 0 || online > pool.threads.len() {
            return false;
        }
        pool.online.store(online, Ordering::Release);
        pool.wake_all();
        true
    }
    /// Whether a pid currently identifies a live task.
    pub fn lookup(&self, pid: Pid) -> bool {
        self.inner.table.with_live(pid, |_| ()).is_some()
    }
    /// The process table interval the live task with this pid started in.
    /// Port of erts/emulator/beam/erl_db.c (heir_started_interval), OTP-29.1.1.
    pub fn started_interval(&self, pid: Pid) -> Option<u64> {
        self.inner
            .table
            .lookup(pid)
            .map(|process| process.started_interval)
    }
    /// [`Self::started_interval`] of a new ETS heir, after making sure the table interval is
    /// later, so a later incarnation of the same pid starts in a different interval.
    ///
    /// Port of erts/emulator/beam/erl_db.c (set_heir) and utils.c
    /// (ensure_later_interval_nob), OTP-29.1.1.
    pub fn heir_started_interval(&self, pid: Pid) -> Option<u64> {
        let started = self.started_interval(pid)?;
        let interval = &self.inner.table.interval;
        if interval.load(Ordering::Relaxed) <= started {
            interval.fetch_add(1, Ordering::Relaxed);
        }
        Some(started)
    }
    /// Whether a live task's last slice ended active (erts `ERTS_PSFLG_ACTIVE`).
    pub fn is_active(&self, pid: Pid) -> Option<bool> {
        self.inner
            .table
            .with_live(pid, |process| process.active.load(Ordering::Acquire))
    }
    /// Whether a scheduler is executing the task right now.
    // Port of erts/emulator/beam/erl_process.c:9304 (erts_process_state2status: ERTS_PSFLG_RUNNING), OTP-29.1.1.
    pub fn is_running(&self, pid: Pid) -> bool {
        self.inner
            .table
            .lookup(pid)
            .is_some_and(|process| process.run_state().load(Ordering::Acquire) == RUNNING)
    }
    /// Inspect a task only while its scheduler state is `WAITING`.
    ///
    /// The task-cell mutex excludes worker execution while the callback reads
    /// task state; the state is checked again after acquiring that mutex.
    /// Inspect a waiting task while holding its scheduler-owned task cell.
    /// Port of erts/emulator/beam/erl_debugger.c:570-600, OTP-29.1.1.
    pub fn inspect_waiting<R>(&self, pid: Pid, inspect: impl FnOnce(&T) -> R) -> Option<R> {
        // A suspended process may still sit in a run queue (erts: not RUNNING); its task is
        // owned by the cell until a worker claims it, and claiming sets RUNNING first.
        let inspectable = |state| state == WAITING || state == QUEUED;
        let process = self.inner.table.lookup(pid)?;
        if !inspectable(process.run_state().load(Ordering::Acquire)) {
            return None;
        }
        let cell = lock_cell(&process);
        inspectable(process.run_state().load(Ordering::Acquire)).then(|| inspect(cell.task()))
    }
    /// Try the process main lock while its scheduler signal queues are empty.
    ///
    /// Port of erts/emulator/beam/erl_process.c:14836-14888
    /// (`erts_try_lock_sig_free_proc`) and `erl_bif_info.c:1381-1417`, OTP-29.1.1:
    /// a failed try-lock falls back to a process-info request signal.
    pub fn inspect_signal_free<R>(
        &self,
        pid: Pid,
        inspect: impl FnOnce(&T) -> R,
    ) -> Result<R, SignalFreeError> {
        let inspectable = |state| state == WAITING || state == QUEUED;
        let has_pending_signals = |process: &Process<T>| process.input.has_pending();
        // Port of erts/emulator/beam/erl_process.c:14836 (erts_try_lock_sig_free_proc):
        // `erts_proc_lookup_raw` takes no reference, then one try-lock attempt and a second
        // look at the state and the signal queue.
        self.inner
            .table
            .with_live(pid, |process| {
                let state = process.run_state().load(Ordering::Acquire);
                if state == EXITED {
                    return Err(SignalFreeError::NoProcess);
                }
                if !inspectable(state) || has_pending_signals(process) {
                    return Err(SignalFreeError::Busy);
                }
                // ERTS uses `erts_proc_trylock`; waiting for a running target here would
                // turn a cheap process_info into a scheduler stall.
                let cell = match process.cell.try_lock() {
                    Some(cell) => cell,
                    None => return Err(SignalFreeError::Busy),
                };
                let state = process.run_state().load(Ordering::Acquire);
                if state == EXITED {
                    return Err(SignalFreeError::NoProcess);
                }
                if !inspectable(state) || has_pending_signals(process) {
                    return Err(SignalFreeError::Busy);
                }
                Ok(inspect(cell.task()))
            })
            .unwrap_or(Err(SignalFreeError::NoProcess))
    }
    /// Mutate a task through its main lock while it is not executing and its signal queue is
    /// empty; otherwise the caller must send a signal.
    ///
    /// Port of erts/emulator/beam/erl_process.c:14836-14888 (`erts_try_lock_sig_free_proc`)
    /// as `erts_internal_suspend_process_2` uses it (erl_process.c:9140), OTP-29.1.1.
    pub fn modify_signal_free<R>(
        &self,
        pid: Pid,
        body: impl FnOnce(&mut T) -> R,
    ) -> Result<R, SignalFreeError> {
        let process = self
            .inner
            .table
            .lookup(pid)
            .ok_or(SignalFreeError::NoProcess)?;
        let state = process.run_state().load(Ordering::Acquire);
        if state == EXITED {
            return Err(SignalFreeError::NoProcess);
        }
        if !receiver_heap_stable(&process) || process.input.has_pending() {
            return Err(SignalFreeError::Busy);
        }
        let mut cell = match process.cell.try_lock() {
            Some(cell) => cell,
            None => return Err(SignalFreeError::Busy),
        };
        let state = process.run_state().load(Ordering::Acquire);
        if state == EXITED {
            return Err(SignalFreeError::NoProcess);
        }
        if !receiver_heap_stable(&process) || process.input.has_pending() {
            return Err(SignalFreeError::Busy);
        }
        Ok(body(cell.task_mut()))
    }
    /// Run `body` while holding `pid`'s main lock, when the receiver is not executing.
    ///
    /// The task-cell mutex is the process main lock: `run_slice` sets `RUNNING`
    /// and then holds the cell for the whole slice, and a dirty job does the
    /// same after setting `dirty_runner`. `std::sync::Mutex` is not reentrant,
    /// so a process that sends to itself fails the try-lock.
    ///
    /// Port of erts/emulator/beam/erl_message.c:661 (`erts_proc_trylock`) and
    /// the volatile-heap check in `erts_try_alloc_message_on_heap`, OTP-29.1.1.
    /// `None` means the caller should allocate a heap fragment instead.
    pub fn try_with_task<R>(&self, pid: Pid, body: impl FnOnce(&mut T) -> R) -> Option<R> {
        let process = self.inner.table.lookup(pid)?;
        if !receiver_heap_stable(&process) {
            return None;
        }
        let mut cell = process.cell.try_lock()?;
        if !receiver_heap_stable(&process) {
            return None;
        }
        Some(body(cell.task_mut()))
    }
    /// Copy helper for a sender that has no [`RunCtx`]: queue `prepare`'s message
    /// before the main lock drops. A [`RunCtx`] send must use [`Self::try_with_task`]
    /// and publish through that context, so the message stays on the sender's worker.
    ///
    /// Port of erts/emulator/beam/erl_message.c:874 (`erts_queue_proc_message` while
    /// the main lock is held), OTP-29.1.1.
    pub fn try_send_on_heap<E>(
        &self,
        from: Pid,
        to: Pid,
        prepare: impl FnOnce(&mut T) -> Result<Option<T::Message>, E>,
    ) -> Result<OnHeapSend, E> {
        let Some(process) = self.inner.table.lookup(to) else {
            return Ok(OnHeapSend::Unavailable);
        };
        if !receiver_heap_stable(&process) {
            return Ok(OnHeapSend::Unavailable);
        }
        let mut cell = match process.cell.try_lock() {
            Some(cell) => cell,
            None => return Ok(OnHeapSend::Unavailable),
        };
        if !receiver_heap_stable(&process) {
            return Ok(OnHeapSend::Unavailable);
        }
        let Some(message) = prepare(cell.task_mut())? else {
            return Ok(OnHeapSend::Declined);
        };
        let sent = if process.bound_worker().is_some() {
            self.send(from, to, message)
        } else {
            self.send_from_native(from, to, message)
        };
        match sent {
            Ok(()) | Err(Error::NoProcess) => Ok(OnHeapSend::Queued),
            Err(error) => Ok(OnHeapSend::Failed(error)),
        }
    }
    /// Number of live process table elements, O(1) like `erts_ptab_count`.
    pub fn process_count(&self) -> usize {
        self.inner.table.ids.count()
    }
    /// Number of live tasks; this scan is for diagnostics.
    pub fn live_count(&self) -> usize {
        self.inner.table.live_count()
    }
    /// Return scheduler-owned task counts and cumulative execution counters.
    pub fn stats(&self) -> SchedulerStats {
        self.inner.scheduler_stats(None, 0)
    }

    /// Enable or disable per worker execution time accounting.
    pub fn set_accounting_enabled(&self, enabled: bool) {
        if enabled {
            let previous = self
                .inner
                .accounting_flags
                .fetch_or(ACCOUNTING_WALL, Ordering::Relaxed);
            if previous & ACCOUNTING_WALL == 0 {
                let started = Instant::now();
                let mut requests = self
                    .inner
                    .wall_start_requests
                    .lock()
                    .expect("wall start requests");
                for (worker, request) in requests.iter_mut().enumerate() {
                    *request =
                        (!self.inner.parked[worker].load(Ordering::Relaxed)).then_some(started);
                }
            }
        } else {
            self.inner
                .accounting_flags
                .fetch_and(!ACCOUNTING_WALL, Ordering::Relaxed);
            self.inner
                .wall_start_requests
                .lock()
                .expect("wall start requests")
                .fill(None);
        }
        self.wake_all_workers();
        for pool in &self.inner.dirty {
            pool.wake_all();
        }
    }

    /// Enable or disable worker microstate counters.
    pub fn set_microstate_enabled(&self, enabled: bool) {
        if enabled {
            self.inner
                .accounting_flags
                .fetch_or(ACCOUNTING_MSACC, Ordering::Relaxed);
        } else {
            self.inner
                .accounting_flags
                .fetch_and(!ACCOUNTING_MSACC, Ordering::Relaxed);
        }
        // Port of erl_msacc.h:240 (`ERTS_MSACC_IS_ENABLED`): the collector reads the
        // clock only while accounting is on.
        arinsal_term::set_gc_clock_for_msacc(enabled);
        for pool in &self.inner.dirty {
            for thread in &pool.threads {
                thread.stats.lock().unwrap().set_msacc_enabled(enabled);
            }
            pool.wake_all();
        }
        self.wake_all_workers();
    }

    /// Set the number of worker threads allowed to dispatch tasks.
    pub fn set_online_schedulers(&self, online: usize) -> bool {
        if online == 0 || online > self.inner.config.workers {
            return false;
        }
        let previous = self.inner.online_schedulers.swap(online, Ordering::AcqRel);
        if previous == online {
            // erts_set_schedulers_online wakes only schedulers whose online state
            // changes (erl_process.c:8385-8389). Waking every sleeper here pulls a
            // scheduler out of its boot wait and makes it steal.
            return true;
        }
        // Port of erts/emulator/beam/erl_process.c:4226 (resume_run_queue), OTP-29.1.1.
        // Simulation keeps one run queue for all configured schedulers.
        let rqs = &self.inner.balance.rqs;
        for rq in &rqs[previous.min(online).min(rqs.len())..online.min(rqs.len())] {
            rq.reset_statistics();
        }
        if !self.inner.scheduling_blocked.load(Ordering::Acquire) {
            // Port of erts/emulator/beam/erl_process.c:8383,8421 (erts_set_schedulers_online),
            // OTP-29.1.1.
            self.inner.balance.change_no_used_runqs(online);
        }
        // Wake the schedulers that entered or left the online set so they notice.
        let (from, to) = if online > previous {
            (previous, online)
        } else {
            (online, previous)
        };
        let n = self.inner.parked.len();
        for worker in from..to {
            if worker < n {
                self.inner.wake_worker(worker);
            }
        }
        true
    }

    /// Completed run queue balance checks (`erts_debug:get_internal_state(nbalance)`).
    pub fn balance_checks(&self) -> u64 {
        self.inner.balance.checks()
    }

    /// Return the number of scheduler workers owned by this runtime.
    pub fn worker_count(&self) -> usize {
        self.inner.parked.len()
    }

    /// Return the configured number of normal scheduler workers.
    pub fn scheduler_count(&self) -> usize {
        self.inner.config.workers
    }

    /// Pause or resume all task dispatch on this scheduler.
    pub fn set_scheduling_blocked(&self, blocked: bool, caller: Option<usize>) {
        self.inner.scheduling_blocker.store(
            if blocked {
                caller.unwrap_or(usize::MAX)
            } else {
                usize::MAX
            },
            Ordering::Release,
        );
        self.inner
            .scheduling_blocked
            .store(blocked, Ordering::Release);
        // Port of erts/emulator/beam/erl_process.c:8559,8630 (erts_block_multi_scheduling),
        // OTP-29.1.1.
        self.inner.balance.change_no_used_runqs(if blocked {
            1
        } else {
            self.inner.online_schedulers.load(Ordering::Acquire)
        });
        if !blocked {
            for rq in &self.inner.balance.rqs {
                rq.reset_statistics();
            }
            self.wake_all_workers();
            self.inner.msb_switch.notify_all();
            for pool in &self.inner.dirty {
                pool.wake_all();
            }
        }
    }

    /// Pause normal-priority tasks while higher and lower priorities remain runnable.
    pub fn set_normal_scheduling_blocked(&self, blocked: bool) {
        self.set_scheduling_blocked(blocked, blocked.then_some(0));
    }

    fn wake_all_workers(&self) {
        self.inner.wake_all_workers();
    }

    /// Wake every scheduler. A signal dispatcher is not a scheduler, so its enqueue
    /// can lose the sleeping-flag race; the unconditional wake is the permit that
    /// `Thread::park` still observes.
    ///
    /// Port of erts/emulator/beam/erl_process.c:1575 (`erts_sched_poke` from the
    /// signal dispatcher), OTP-29.1.1.
    pub fn poke_schedulers(&self) {
        self.inner.wake_all_workers();
    }

    /// Inspect or set the next free process table id for internal-state tests.
    ///
    /// Returns the data of the next pid to hand out (the invalid data when the table is full).
    pub fn test_next_process_id(&self, set: bool, next_id: u64) -> u64 {
        self.inner.table.test_next_id(set, next_id)
    }

    /// Process-table slot of a pid; `erlang:processes/0` lists pids in this order.
    pub fn process_table_index(&self, pid: Pid) -> u32 {
        self.inner.table.index(pid)
    }

    /// Live pids in process-table slots `first..limit`, at most `max`, and the slot
    /// after the last one inspected (`erts_ptab_processes_next`).
    pub fn pids_in_table_range(&self, first: u32, limit: u32, max: usize) -> (Vec<Pid>, u32) {
        self.inner.table.pids_in_range(first, limit, max)
    }

    /// Process-table size (`erlang:system_info(process_limit)`).
    pub fn process_table_size(&self) -> u32 {
        self.inner.table.ids.layout().max()
    }
    /// Atom index stored in `p->common.u.alive.reg->name`, if this process has a name.
    pub fn registered_atom_index(&self, pid: Pid) -> Option<u32> {
        let process = self.inner.table.lookup(pid)?;
        let index = process.reg_atom.load(Ordering::Acquire);
        (index != u32::MAX).then_some(index)
    }

    /// Publish `p->common.u.alive.reg` for `pid`. The caller holds the register-table write lock.
    pub fn set_registered_atom_index(&self, pid: Pid, index: u32) {
        if let Some(process) = self.inner.table.lookup(pid) {
            process.reg_atom.store(index, Ordering::Release);
        }
    }

    /// Clear `p->common.u.alive.reg` when it still names `index`.
    pub fn clear_registered_atom_index(&self, pid: Pid, index: u32) -> bool {
        let Some(process) = self.inner.table.lookup(pid) else {
            return false;
        };
        process
            .reg_atom
            .compare_exchange(index, u32::MAX, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    /// Start a port timer on the timer wheel of the calling scheduler (or of a wheel picked by
    /// timer id from any other thread); `callback` runs on the wheel's scheduler when it
    /// expires.
    ///
    /// Port of erts/emulator/beam/erl_hl_timer.c:3031 (erts_set_port_timer), OTP-29.1.1.
    pub fn start_port_timer(
        &self,
        ms: u64,
        callback: Box<dyn FnOnce() + Send>,
    ) -> Result<TimerRef, Error> {
        self.inner.start_port_timer(ms, callback)
    }

    /// Cancel a port timer; the cancel is delivered to the owning wheel and need not finish
    /// before this returns.
    ///
    /// Port of erts/emulator/beam/erl_hl_timer.c:3063 (erts_cancel_port_timer), OTP-29.1.1.
    pub fn cancel_port_timer(&self, reference: TimerRef) {
        self.inner.cancel_timer_async(reference, Box::new(|_| {}));
    }

    /// Schedule an opaque envelope for future delivery.
    pub fn start_timer(&self, pid: Pid, ms: u64, msg: T::Message) -> Result<TimerRef, Error> {
        self.inner
            .start_timer(pid, ms, TimerPayload::Message(pid, msg, true), None, None)
    }
    /// Schedule a plain message, as `send_after` does in OTP.
    pub fn send_after(&self, pid: Pid, ms: u64, msg: T::Message) -> Result<TimerRef, Error> {
        self.inner
            .start_timer(pid, ms, TimerPayload::Message(pid, msg, false), None, None)
    }
    /// Maps the messages of every BIF timer through `f`, one result per timer.
    ///
    /// Each wheel belongs to its scheduler thread, so the other schedulers answer as aux work
    /// (erl_hl_timer.c reaches a foreign timer the same way); the wheel of the calling thread is
    /// read directly. Gives up on a scheduler that does not answer within two seconds.
    pub fn map_bif_timer_messages<R: Send + 'static>(
        &self,
        f: impl Fn(&T::Message) -> R + Send + Sync + 'static,
    ) -> Vec<R> {
        let f = Arc::new(f);
        let workers = self.inner.timer_commands.len();
        let mut results = Vec::new();
        let (reply, receiver) = mpsc::channel();
        let mut pending = 0;
        for worker in 0..workers {
            if let Some(sim) = self.inner.sim_timers.as_ref() {
                if let Some(wheel) = sim.get(worker) {
                    results.extend(
                        wheel
                            .lock()
                            .unwrap()
                            .bif_timer_messages()
                            .into_iter()
                            .map(&*f),
                    );
                }
            } else if let Some(service) = self.inner.owner_timer_service(worker) {
                results.extend(
                    service
                        .borrow()
                        .wheel
                        .bif_timer_messages()
                        .into_iter()
                        .map(&*f),
                );
            } else {
                let f = Arc::clone(&f);
                let reply = reply.clone();
                let inner = Arc::clone(&self.inner);
                self.inner.request_aux_work_one(
                    worker,
                    Arc::new(move |running| {
                        let found = inner.owner_timer_service(running).map(|service| {
                            service
                                .borrow()
                                .wheel
                                .bif_timer_messages()
                                .into_iter()
                                .map(&*f)
                                .collect::<Vec<_>>()
                        });
                        let _ = reply.send(found.unwrap_or_default());
                    }),
                );
                pending += 1;
            }
        }
        drop(reply);
        for _ in 0..pending {
            match receiver.recv_timeout(std::time::Duration::from_secs(2)) {
                Ok(found) => results.extend(found),
                Err(_) => break,
            }
        }
        results
    }

    /// The number of BIF timers on the wheel of `worker`, read from that scheduler's thread.
    pub fn bif_timer_count(&self, worker: usize) -> usize {
        if let Some(sim) = self.inner.sim_timers.as_ref() {
            return sim
                .get(worker)
                .map_or(0, |wheel| wheel.lock().unwrap().bif_timer_messages().len());
        }
        self.inner.owner_timer_service(worker).map_or(0, |service| {
            service.borrow().wheel.bif_timer_messages().len()
        })
    }

    /// [`TimerRef`] access without a request when this thread owns the wheel; see
    /// [`Inner::try_access_timer_local`]. The outer `None` means a request is needed.
    pub fn try_access_timer_local(&self, timer: TimerRef, cancel: bool) -> Option<Option<u64>> {
        self.inner.try_access_timer_local(timer, cancel)
    }

    /// The number of BIF timers in `pid`'s bif-timer tree (`p->bif_timers`).
    pub fn bif_timers_of(&self, pid: Pid) -> usize {
        self.inner
            .table
            .with_live(pid, |process| process.btm.lock().tree.len())
            .unwrap_or(0)
    }

    /// The BIF timer created with Erlang reference key `key`; see [`TimerRef::from_ref_key`].
    pub fn timer_for_ref_key(&self, key: u64) -> TimerRef {
        TimerRef::from_ref_key(key, self.inner.timer_commands.len())
    }
    /// Hold every BIF timer aimed at `pid` until [`Scheduler::resume_target_timers`]; used
    /// while the process is suspended.
    ///
    /// Port of erts/emulator/beam/erl_hl_timer.c:2874 (erts_pause_bif_timers), OTP-29.1.1.
    pub fn pause_target_timers(&self, pid: Pid) {
        self.inner.broadcast_target_timers(pid, true);
    }
    /// Re-arm the timers held by [`Scheduler::pause_target_timers`] with their remaining time.
    ///
    /// Port of erts/emulator/beam/erl_hl_timer.c:2949 (erts_resume_paused_bif_timers), OTP-29.1.1.
    pub fn resume_target_timers(&self, pid: Pid) {
        self.inner.broadcast_target_timers(pid, false);
    }
    /// Cancel a pending timer and return its remaining milliseconds.
    pub fn cancel_timer(&self, reference: TimerRef) -> Option<u64> {
        self.inner.cancel_timer(reference)
    }
    /// Cancel a timer and deliver its remaining time from the owning scheduler.
    pub fn cancel_timer_async(
        &self,
        reference: TimerRef,
        callback: impl FnOnce(Option<u64>) + Send + 'static,
    ) {
        self.inner.cancel_timer_async(reference, Box::new(callback));
    }
    /// Read remaining milliseconds, or `None` if fired or cancelled.
    pub fn read_timer(&self, reference: TimerRef) -> Option<u64> {
        self.inner.read_timer(reference)
    }
    /// Read remaining time and deliver the result from the owning scheduler.
    pub fn read_timer_async(
        &self,
        reference: TimerRef,
        callback: impl FnOnce(Option<u64>) + Send + 'static,
    ) {
        self.inner.read_timer_async(reference, Box::new(callback));
    }
    /// Advance the built-in simulation clock.
    pub fn advance_ms(&self, ms: u64) -> Result<(), Error> {
        self.virtual_clock
            .as_ref()
            .ok_or(Error::WrongMode)?
            .advance(ms);
        self.inner.poll_timers(0, None, true);
        Ok(())
    }
    /// Execute one deterministic scheduling turn. Returns false when no task is runnable.
    pub fn step(&self) -> bool {
        let Some(sim) = &self.inner.sim else {
            return false;
        };
        self.inner.handle_aux_work(0);
        self.inner.poll_timers(0, None, true);
        // Port of erts/emulator/beam/erl_process.c:9977-9986 (find a new port to run),
        // OTP-29.1.1.
        if let Some(port) = self.inner.port_queues[0].pop(&self.inner.balance.rqs[0]) {
            let PortExecution { active, reds } = port.execute();
            if active {
                port.run_queue().set(0);
                self.inner.port_queues[0].enqueue(&self.inner.balance.rqs[0], port);
            }
            let reds = reds.max(0);
            self.inner.balance.rqs[0]
                .reductions_executed(balance::PORT_PRIO_LEVEL, i64::from(reds));
            self.inner.worker_stats[0]
                .reductions
                .fetch_add(reds as u64, Ordering::Relaxed);
            return true;
        }
        let item = {
            let mut sim = sim.lock().unwrap();
            let len = sim.queue.len();
            if len == 0 {
                return false;
            }
            // Port of erts/emulator/beam/erl_process.c:9603 (priority queues), OTP-29.1.1:
            // max and high run before normal; normal and low share one class here.
            let class = |item: &Scheduled<T>| item.process.priority().index().min(2);
            let best = sim.queue.iter().map(class).min().unwrap_or(2);
            let ready: Vec<usize> = (0..len)
                .filter(|&index| class(&sim.queue[index]) == best)
                .collect();
            let index = ready[sim.rng.next_u64() as usize % ready.len()];
            sim.queue.remove(index).unwrap()
        };
        let dirty = match item.process.dirty.load(Ordering::Acquire) {
            1 => Some(DirtyKind::Cpu),
            2 => Some(DirtyKind::Io),
            _ => None,
        };
        // A task stepping a simulation from inside its own slice gets a scheduler of its own.
        match self.inner.sim_data.try_lock() {
            Ok(mut data) => run_one(&self.inner, item, &mut data, None, dirty),
            Err(_) => run_one(
                &self.inner,
                item,
                &mut T::SchedulerData::default(),
                None,
                dirty,
            ),
        }
        true
    }
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod in_signal_tests {
    use super::*;

    struct Envelope(bool);
    impl SignalMessage for Envelope {
        fn is_altact_msg(&self) -> bool {
            self.0
        }
    }

    #[test]
    fn priority_message_sets_nmsg_sig_in_q() {
        let input: Incoming<Event<Envelope>> = Incoming::default();
        let from = Pid::new(1, 0);
        input.push(Event {
            from,
            payload: Payload::Message(Envelope(false)),
        });
        assert_eq!(
            input.state().load(Ordering::SeqCst) & psflg::SIG_IN_Q,
            psflg::MSG_SIG_IN_Q
        );
        input.push(Event {
            from,
            payload: Payload::Message(Envelope(true)),
        });
        assert_eq!(
            input.state().load(Ordering::SeqCst) & psflg::SIG_IN_Q,
            psflg::SIG_IN_Q
        );
        let mut inner = SignalQueue::default();
        assert_eq!(input.take_all_if(InSignal::is_message, &mut inner), 0);
    }
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod msgq_stage_microbench {
    use super::*;

    struct Idle;

    impl Task for Idle {
        type Message = usize;
        type SchedulerData = ();

        fn run(&mut self, _ctx: &mut RunCtx<'_, usize>, _: &mut (), _budget: u32) -> RunOutcome {
            RunOutcome::Wait { timeout_ms: None }
        }
    }

    fn report(stage: &str, count: usize, started: Instant) {
        println!(
            "{stage}: {:.1} ns/op",
            started.elapsed().as_nanos() as f64 / count as f64
        );
    }

    #[test]
    #[ignore = "manual message queue stage benchmark"]
    fn stages() {
        const N: usize = 200_000;
        let table = ProcessTable::<Idle>::new(
            1,
            Arc::new(thr_progress::ThrProgress::new(Arc::from([]), Arc::from([]))),
        );
        let process = table.insert(Idle, Priority::Normal, None).unwrap();
        let pid = process.pid;
        let started = Instant::now();
        for _ in 0..N {
            std::hint::black_box(table.lookup(pid));
        }
        report("lookup", N, started);

        let ingress = Incoming::default();
        let sender = Pid::new(1, 0);
        let blocks: Vec<Vec<Event<usize>>> = (0..N / 32)
            .map(|block| {
                (0..32)
                    .map(|offset| Event {
                        from: sender,
                        payload: Payload::Message(block * 32 + offset),
                    })
                    .collect()
            })
            .collect();
        let mut blocks = blocks.into_iter();
        let started = Instant::now();
        for mut block in blocks.by_ref() {
            ingress.push_block_reuse(&mut block);
        }
        report("enqueue block", N, started);

        let mut fetched = SignalQueue::default();
        let started = Instant::now();
        ingress.take_all(&mut fetched);
        assert_eq!(fetched.len(), N);
        report("fetch batch", N, started);
        let mut inner_queue: VecDeque<_> = std::iter::from_fn(|| fetched.pop_front()).collect();

        let started = Instant::now();
        for expected in 0..N {
            let index = inner_queue
                .iter()
                .position(
                    |event| matches!(event.payload, Payload::Message(value) if value == expected),
                )
                .unwrap();
            std::hint::black_box(inner_queue.remove(index).unwrap());
        }
        report("receive match", N, started);

        let scheduler = Scheduler::<Idle>::simulation(Config::default(), 3);
        let process = scheduler.spawn(Idle).unwrap();
        let input = Incoming::default();
        let blocks = (0..N / 32)
            .map(|block| {
                (0..32)
                    .map(|offset| Event {
                        from: sender,
                        payload: Payload::Message(block * 32 + offset),
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>()
            .into_iter();
        for mut block in blocks {
            input.push_block_reuse(&mut block);
        }
        let mut receive_runner = Runner {
            inner: &scheduler.inner,
            local: None,
        };
        let backlog = AtomicUsize::new(N);
        let bound_worker = AtomicUsize::new(UNBOUND_WORKER);
        let user_priority = AtomicU8::new(Priority::Normal.index() as u8);
        let sys_priority = AtomicU8::new(NO_SYS_PRIORITY);
        let active = AtomicBool::new(true);
        let exit_flags = AtomicU32::new(0);
        let mut context = RunCtx {
            inner: &mut receive_runner,
            pid: process,
            input: &input,
            backlog: &backlog,
            bound_worker: &bound_worker,
            worker: None,
            worker_count: scheduler.inner.config.workers,
            remaining: 1_000,
            budget: 1_000,
            msacc_enabled: false,
            wall_enabled: false,
            gc_accounted_total: 0,
            sched_type: SchedulerType::Normal,
            user_priority: &user_priority,
            sys_priority: &sys_priority,
            active: &active,
            exit_flags: &exit_flags,
            sys_task_run: false,
            dirty_running: false,
            dirty_queued: false,
            simulated: scheduler.inner.sim.is_some(),
        };
        let started = Instant::now();
        let mut fetched = SignalQueue::default();
        context.fetch_signals(&mut fetched);
        assert_eq!(fetched.len(), N);
        while let Some(event) = fetched.pop_front() {
            context.consume_fetched();
            std::hint::black_box(event);
        }
        report("RunCtx batch fetch + pop", N, started);

        let scheduler = Scheduler::<Idle>::simulation(Config::default(), 1);
        let process = scheduler
            .inner
            .table
            .lookup(scheduler.spawn(Idle).unwrap())
            .unwrap();
        let started = Instant::now();
        for _ in 0..N {
            process.run_state().store(WAITING, Ordering::SeqCst);
            scheduler
                .inner
                .wake_after_publish(&process, None, false, None);
        }
        report("wake transition + schedule", N, started);
        scheduler
            .inner
            .sim
            .as_ref()
            .unwrap()
            .lock()
            .unwrap()
            .queue
            .clear();

        let scheduler = Scheduler::<Idle>::simulation(Config::default(), 2);
        let from = scheduler.spawn(Idle).unwrap();
        let to = scheduler.spawn(Idle).unwrap();
        let process = scheduler.inner.table.lookup(to).unwrap();
        process.run_state().store(RUNNING, Ordering::Relaxed);
        process.input.backlog.store(257, Ordering::Relaxed);
        let mut runner = Runner {
            inner: &scheduler.inner,
            local: None,
        };
        let started = Instant::now();
        for message in 0..N {
            <Runner<'_, Idle> as ContextOps<usize>>::deliver(
                &mut runner,
                from,
                to,
                Payload::Message(message),
            )
            .unwrap();
        }
        runner.flush();
        report("runner delivery high backlog", N, started);

        let scheduler = Scheduler::<Idle>::simulation(Config::default(), 4);
        let from = scheduler.spawn(Idle).unwrap();
        let to = scheduler.spawn(Idle).unwrap();
        let target = scheduler.inner.table.lookup(to).unwrap();
        target.run_state().store(RUNNING, Ordering::Relaxed);
        let mut inner_queue = SignalQueue::default();
        let started = Instant::now();
        for message in 0..N {
            let mut runner = Runner {
                inner: &scheduler.inner,
                local: None,
            };
            <Runner<'_, Idle> as ContextOps<usize>>::deliver(
                &mut runner,
                from,
                to,
                Payload::Message(message),
            )
            .unwrap();
            runner.flush();
            if message % 32 == 31 {
                target.input.take_all(&mut inner_queue);
                while inner_queue.pop_front().is_some() {}
            }
        }
        target.input.take_all(&mut inner_queue);
        while inner_queue.pop_front().is_some() {}
        report("one send per runner slice", N, started);
    }

    #[test]
    fn sends_preserve_order_and_wake_only_once() {
        let scheduler = Scheduler::<Idle>::simulation(Config::default(), 5);
        let from = scheduler.spawn(Idle).unwrap();
        let to = scheduler.spawn(Idle).unwrap();
        scheduler
            .inner
            .sim
            .as_ref()
            .unwrap()
            .lock()
            .unwrap()
            .queue
            .clear();
        let process = scheduler.inner.table.lookup(to).unwrap();
        process.run_state().store(WAITING, Ordering::Relaxed);
        let mut runner = Runner {
            inner: &scheduler.inner,
            local: None,
        };
        for value in 1..=3 {
            <Runner<'_, Idle> as ContextOps<usize>>::deliver(
                &mut runner,
                from,
                to,
                Payload::Message(value),
            )
            .unwrap();
            if value == 1 {
                process.run_state().store(RUNNING, Ordering::Relaxed);
            }
        }
        runner.flush();
        let ready = scheduler.inner.sim.as_ref().unwrap().lock().unwrap();
        assert_eq!(ready.queue.len(), 1);
        drop(ready);
        let mut inner_queue = SignalQueue::default();
        process.input.take_all(&mut inner_queue);
        let messages = (0..3)
            .map(|_| match inner_queue.pop_front().unwrap().payload {
                Payload::Message(value) => value,
                _ => panic!("unexpected control signal"),
            })
            .collect::<Vec<_>>();
        assert_eq!(messages, [1, 2, 3]);
    }
}

#[cfg(test)]
mod spawn_request_tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct LinkSignalProbe(Arc<AtomicUsize>);

    impl Task for LinkSignalProbe {
        type Message = ();
        type SchedulerData = ();

        fn run(&mut self, ctx: &mut RunCtx<'_, ()>, _: &mut (), _: u32) -> RunOutcome {
            while let Some(event) = ctx.receive() {
                if matches!(event.payload, Payload::Signal(Signal::Link)) {
                    self.0.fetch_add(1, Ordering::Relaxed);
                }
            }
            RunOutcome::Wait { timeout_ms: None }
        }
    }

    #[test]
    fn unscheduled_process_signals_do_not_publish_child() {
        let scheduler = Scheduler::simulation(
            Config {
                workers: 1,
                max_processes: 8,
                ..Config::default()
            },
            1,
        );
        let observed = Arc::new(AtomicUsize::new(0));
        let child = scheduler
            .spawn_unscheduled(LinkSignalProbe(Arc::clone(&observed)))
            .unwrap();
        scheduler
            .signal(Pid::new(7, 0), child, Signal::Link)
            .unwrap();

        assert!(!scheduler.step(), "setup signal scheduled the child");
        assert_eq!(observed.load(Ordering::Relaxed), 0);

        scheduler.schedule_unscheduled(child).unwrap();
        assert!(scheduler.step());
        assert_eq!(observed.load(Ordering::Relaxed), 1);
    }
}

#[cfg(test)]
mod dirty_state_tests {
    use super::*;

    struct Idle;

    impl Task for Idle {
        type Message = ();
        type SchedulerData = ();

        fn run(&mut self, _ctx: &mut RunCtx<'_, ()>, _: &mut (), _: u32) -> RunOutcome {
            RunOutcome::Wait { timeout_ms: None }
        }
    }

    #[test]
    fn dirty_wake_takes_the_most_recent_eligible_sleeper() {
        let pool = DirtyPool::<Idle>::new(4, 0);
        pool.online.store(3, Ordering::Release);
        let mut queue = pool.queue.lock().unwrap();
        queue.sleepers.extend([0, 1, 2, 3]);
        // Thread 3 is offline, so thread 2 slept last among those that may run.
        pool.wake_one(&mut queue);
        assert_eq!(Vec::from(queue.sleepers.clone()), vec![0, 1, 3]);
        pool.wake_one(&mut queue);
        pool.wake_one(&mut queue);
        pool.wake_one(&mut queue);
        assert_eq!(Vec::from(queue.sleepers.clone()), vec![3]);
        drop(queue);
        let woken: Vec<bool> = pool
            .threads
            .iter()
            .map(|thread| thread.wake.load(Ordering::SeqCst))
            .collect();
        assert_eq!(woken, vec![true, true, true, false]);
    }

    #[test]
    fn dirty_busy_wait_thresholds_match_erts_spin_counts() {
        let defaults = [None, None, None];
        assert!(scheduler_spin_count(&defaults, 0, "medium") == 10_000);
        assert!(scheduler_spin_count(&defaults, 1, "short") == 10_000);
        assert!(scheduler_spin_count(&defaults, 2, "short") == 10_000);

        for (threshold, expected) in [
            ("none", 0),
            ("very_short", 5_000),
            ("short", 10_000),
            ("medium", 10_000),
            ("long", 20_000),
            ("very_long", 40_000),
        ] {
            let configured = [None, Some(threshold.to_owned()), None];
            assert!(scheduler_spin_count(&configured, 1, "short") == expected);
        }
    }

    #[test]
    fn executing_dirty_excludes_queued_dirty_work() {
        let scheduler = Scheduler::<Idle>::simulation(Config::default(), 1);
        let pid = scheduler.spawn(Idle).unwrap();
        let process = scheduler.inner.table.lookup(pid).unwrap();
        process.dirty.store(1, Ordering::Release);

        assert!(!scheduler.is_executing_dirty(pid));

        process.dirty_runner.store(1, Ordering::Release);
        assert!(scheduler.is_executing_dirty(pid));
    }

    #[test]
    fn on_heap_send_requires_a_stable_receiver() {
        let scheduler = Scheduler::<Idle>::simulation(Config::default(), 1);
        let from = scheduler.spawn(Idle).unwrap();
        let to = scheduler.spawn(Idle).unwrap();
        let target = scheduler.inner.table.lookup(to).unwrap();
        // A queued receiver is not executing. Collection fetches the outer queue
        // before scanning, so the on-heap term is a root by then.
        assert!(matches!(
            scheduler
                .try_send_on_heap(from, to, |_| Ok::<_, ()>(Some(())))
                .unwrap(),
            OnHeapSend::Queued
        ));
        target.run_state().store(WAITING, Ordering::Release);
        assert!(matches!(
            scheduler
                .try_send_on_heap(from, to, |_| Ok::<_, ()>(Some(())))
                .unwrap(),
            OnHeapSend::Queued
        ));
        target.run_state().store(EXITED, Ordering::Release);
        assert!(matches!(
            scheduler
                .try_send_on_heap(from, to, |_| Ok::<_, ()>(Some(())))
                .unwrap(),
            OnHeapSend::Unavailable
        ));
        target.run_state().store(RUNNING, Ordering::Release);
        assert!(scheduler.try_with_task(to, |_| ()).is_none());
        target.run_state().store(WAITING, Ordering::Release);
        target.dirty_runner.store(1, Ordering::Release);
        assert!(scheduler.try_with_task(to, |_| ()).is_none());
        target.dirty_runner.store(0, Ordering::Release);
        let _held = target.cell.lock();
        assert!(scheduler.try_with_task(to, |_| ()).is_none());
    }
}

#[cfg(test)]
mod offline_scheduler_tests {
    use super::*;

    struct YieldForever;

    impl Task for YieldForever {
        type Message = ();
        type SchedulerData = ();

        fn run(&mut self, _ctx: &mut RunCtx<'_, ()>, _: &mut (), _budget: u32) -> RunOutcome {
            RunOutcome::Yield
        }
    }

    #[test]
    fn offlining_workers_migrates_runnable_processes() {
        let scheduler = Scheduler::new(Config {
            workers: 4,
            max_processes: 32,
            ..Config::default()
        });
        for _ in 0..10 {
            scheduler.spawn(YieldForever).unwrap();
        }
        std::thread::sleep(Duration::from_millis(20));

        assert!(scheduler.set_online_schedulers(1));
        std::thread::sleep(Duration::from_millis(20));

        let stats = scheduler.stats();
        assert!(stats.active_tasks[0] >= 10);
        assert!(stats.run_queue_lengths[0] >= 9);
    }
}

impl<T: Task> Drop for Scheduler<T> {
    fn drop(&mut self) {
        self.inner.stopped.store(true, Ordering::Release);
        for pool in &self.inner.dirty {
            pool.wake_all();
        }
        for (id, handle) in self.threads.iter().enumerate() {
            if let Some(flag) = self.inner.parked.get(id) {
                flag.store(false, Ordering::SeqCst);
            }
            handle.thread().unpark();
            interrupt_if_poll_sleeper(handle.thread());
        }
        // The last handle may drop on a worker (e.g. a process exiting while the owner already
        // released its handle); that worker cannot join itself and stops on its own.
        let current = std::thread::current().id();
        let mut on_worker = false;
        for handle in self.threads.drain(..) {
            if handle.thread().id() != current {
                let _ = handle.join();
            } else {
                on_worker = true;
            }
        }
        if on_worker {
            // This worker still holds the cell of the exiting process; shutting down inline would
            // lock that cell again and self-deadlock. A helper thread waits for the worker to
            // release it (it holds its own `Inner` reference, so the table stays alive).
            let inner = Arc::clone(&self.inner);
            let _ = std::thread::Builder::new()
                .name("sched-shutdown".into())
                .spawn(move || {
                    inner.table.scheduler_shutdown();
                    thr_progress::run_remaining_later_ops(&inner.progress);
                });
        } else {
            self.inner.table.scheduler_shutdown();
            // No managed thread runs any more: release what the table and the stopped
            // threads left for thread progress.
            thr_progress::run_remaining_later_ops(&self.inner.progress);
        }
    }
}

impl<T: Task> Scheduler<T> {
    /// Stop the workers and detach the table's processes without joining. The runtime keeps
    /// the scheduler for the VM lifetime, so its owner calls this at VM shutdown to break the
    /// runtime -> scheduler -> process -> runtime cycle; a worker blocked in a driver call
    /// cannot hold the caller up. The final `Drop` joins the threads.
    pub fn release(&self) {
        self.inner.stopped.store(true, Ordering::Release);
        for pool in &self.inner.dirty {
            pool.wake_all();
        }
        for (id, handle) in self.threads.iter().enumerate() {
            if let Some(flag) = self.inner.parked.get(id) {
                flag.store(false, Ordering::SeqCst);
            }
            handle.thread().unpark();
            interrupt_if_poll_sleeper(handle.thread());
        }
        self.inner.table.release_all();
    }
}

fn run_one<T: Task>(
    inner: &Inner<T>,
    item: Scheduled<T>,
    data: &mut T::SchedulerData,
    worker: Option<usize>,
    dirty: Option<DirtyKind>,
) {
    run_slice(inner, item, None, data, worker, dirty);
    // A runtime without managed threads runs later operations after the slice.
    thr_progress::run_unmanaged_later_ops();
}

fn run_slice<'a, T: Task>(
    inner: &'a Inner<T>,
    item: Scheduled<T>,
    local_cell: Option<&'a RefCell<Local<T>>>,
    data: &mut T::SchedulerData,
    worker: Option<usize>,
    dirty: Option<DirtyKind>,
) {
    // The scheduler-local state is lent out while the task runs: native code reaches this
    // scheduler's run queue through [`NativeSender`], like erts BIFs get `esdp`.
    let mut local_guard = local_cell.map(RefCell::borrow_mut);
    let mut local = local_guard.as_deref_mut();
    let process = item.process;
    // Claim this queue entry's epoch first: a stale duplicate entry (see
    // `Process::run_epoch`) must not run a process that was queued again later.
    if process
        .run_epoch
        .compare_exchange(
            item.epoch,
            item.epoch.wrapping_add(1),
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_err()
    {
        return;
    }
    if process
        .run_state()
        .compare_exchange(QUEUED, RUNNING, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return;
    }
    // Port of erts/emulator/beam/erl_process.c:7028-7134 (active_sys_enqueue), OTP-29.1.1:
    // keep the elevated priority while ordered system-task signals are still pending.
    // Dirty schedulers never execute system tasks (erl_process.c:10255).
    let sys_task_run =
        dirty.is_none() && process.sys_priority.load(Ordering::Acquire) != NO_SYS_PRIORITY;
    let worker_id = worker.unwrap_or(0);
    // A process on a dirty run queue left the normal run queue accounting when it migrated.
    if dirty.is_none() {
        if let Some(local) = local.as_deref_mut() {
            local.record_running(&process, local.worker_id);
            local.context_switches += 1;
        } else {
            inner.record_running(&process, worker_id);
            inner.worker_stats[worker_id]
                .context_switches
                .fetch_add(1, Ordering::Relaxed);
        }
    }
    // Port of erts/emulator/beam/erl_process.c:10183 (schedule: `reds = context_reds` for
    // every process scheduled in), OTP-29.1.1.
    let budget = inner.config.reductions;
    // Port of erts/emulator/beam/erl_thr_progress.c: dirty schedulers are unmanaged threads
    // and never delay thread progress, OTP-29.1.1.
    let accounting_flags = inner.accounting_flags.load(Ordering::Relaxed);
    let msacc_enabled = accounting_flags & ACCOUNTING_MSACC != 0;
    if let Some(local) = local {
        local.set_msacc_enabled(msacc_enabled);
        let wall_enabled = accounting_flags & ACCOUNTING_WALL != 0;
        let started_at = (wall_enabled && !local.wall_enabled)
            .then(|| inner.take_wall_start(local.worker_id))
            .flatten();
        local.set_wall_enabled_at(wall_enabled, started_at);
    }
    let accounting_started = (accounting_flags & ACCOUNTING_WALL != 0).then(Instant::now);
    let mut cell = lock_cell(&process);
    if let Some(kind) = dirty
        && let Some(job) = cell.task_mut().take_dirty_job(kind)
    {
        // Port of erts/emulator/beam/erl_nif.c:468-499 (erts_call_dirty_nif), OTP-29.1.1:
        // the job runs without the main lock, so a dirty signal handler can take it.
        drop(cell);
        // The simulator runs dirty jobs on its own thread; report the job's scheduler type.
        let thread_type = SCHEDULER_TYPE.with(|current| current.replace(kind.into()));
        let result = job();
        SCHEDULER_TYPE.with(|current| current.set(thread_type));
        cell = lock_cell(&process);
        cell.task_mut().finish_dirty_job(result);
    }
    drop(local_guard);
    let (outcome, remaining, active_ns) = {
        let mut runner = Runner {
            inner,
            local: local_cell,
        };
        let result = {
            let task = cell.task_mut();
            let mut ctx = RunCtx {
                inner: &mut runner,
                pid: process.pid,
                input: &process.input,
                backlog: &process.input.backlog,
                bound_worker: &process.bound_worker,
                worker,
                worker_count: inner.config.workers,
                remaining: budget,
                budget,
                msacc_enabled,
                wall_enabled: accounting_flags & ACCOUNTING_WALL != 0,
                gc_accounted_total: if msacc_enabled {
                    task.gc_nanoseconds()
                } else {
                    0
                },
                sched_type: dirty.map_or(SchedulerType::Normal, SchedulerType::from),
                user_priority: &process.user_priority,
                sys_priority: &process.sys_priority,
                active: &process.active,
                exit_flags: &process.exit_flags,
                sys_task_run,
                dirty_running: false,
                dirty_queued: false,
                simulated: inner.sim.is_some(),
            };
            if msacc_enabled {
                ctx.set_msacc_state(MsaccState::Emulator);
            }
            // The simulator runs dirty jobs on its own thread; report the job's scheduler type.
            // A normal scheduler thread already has its type, like `esdp->type`.
            let thread_type = worker
                .is_none()
                .then(|| SCHEDULER_TYPE.with(|current| current.replace(ctx.sched_type)));
            let outcome = task.run(&mut ctx, data, budget);
            if let Some(thread_type) = thread_type {
                SCHEDULER_TYPE.with(|current| current.set(thread_type));
            }
            if ctx.msacc_enabled {
                ctx.set_msacc_state(MsaccState::Other);
                ctx.account_gc_total(task.gc_nanoseconds());
            }
            let active_ns = accounting_started.map_or(0, |started| {
                started.elapsed().as_nanos().min(u64::MAX as u128) as u64
            });
            (outcome, ctx.remaining, active_ns)
        };
        runner.flush();
        result
    };
    let mut local_guard = local_cell.map(RefCell::borrow_mut);
    let mut local = local_guard.as_deref_mut();
    let consumed = u64::from(budget.saturating_sub(remaining));
    if dirty.is_none() {
        // Port of erts/emulator/beam/erl_process.c:10200 (ERTS_PROC_REDUCTIONS_EXECUTED
        // with the user priority), OTP-29.1.1.
        let worker = local.as_deref().map_or(worker_id, |local| local.worker_id);
        inner.balance.rqs[worker.min(inner.balance.rqs.len() - 1)].reductions_executed(
            usize::from(process.user_priority.load(Ordering::Relaxed)),
            consumed as i64,
        );
    }
    if dirty.is_some() {
        // Dirty schedulers keep no reduction or normal run queue counters.
    } else if let Some(local) = local.as_deref_mut() {
        local.reductions += consumed;
        if SCHED_POLL.get().is_some() {
            FUNCTION_CALLS.fetch_add(
                u32::try_from(consumed).unwrap_or(u32::MAX),
                Ordering::Relaxed,
            );
        }
    } else {
        inner.worker_stats[worker_id]
            .reductions
            .fetch_add(consumed, Ordering::Relaxed);
        inner.worker_stats[worker_id]
            .active_ns
            .fetch_add(active_ns, Ordering::Relaxed);
    }
    if let Some(local) = local.as_deref_mut() {
        local.check_time_reds = local
            .check_time_reds
            .saturating_add(budget.saturating_sub(remaining));
    }
    if dirty.is_some() {
        process.dirty.store(0, Ordering::Release);
    }
    match outcome {
        RunOutcome::Dirty(kind) => {
            // Port of erts/emulator/beam/erl_process.c:9873 (schedule_out to a dirty run
            // queue), OTP-29.1.1.
            if dirty.is_none() {
                if let Some(local) = local.as_deref_mut() {
                    local.record_waiting(&process);
                } else {
                    inner.record_waiting(&process);
                }
            }
            process
                .run_state()
                .store_from_running(QUEUED, Ordering::Release);
            inner.enqueue_dirty(process.clone(), kind);
            // Port of erts/emulator/beam/erl_process.c:9763 (ensure signals are handled while
            // scheduled dirty), OTP-29.1.1.
            if process.input.has_pending() {
                inner.notify_dirty_signal_handler(&process, Some(process.priority()));
            }
        }
        RunOutcome::Yield if dirty.is_some() => {
            // Port of erts/emulator/beam/erl_process.c:10190 (a finished dirty job moves the
            // process back to a normal run queue), OTP-29.1.1.
            process
                .run_state()
                .store_from_running(QUEUED, Ordering::Release);
            inner.enqueue(Scheduled::new(process.clone()), false);
        }
        RunOutcome::Yield => {
            process
                .run_state()
                .store_from_running(QUEUED, Ordering::Release);
            let next = Scheduled::new(process.clone());
            if process.bound_worker().is_some() {
                inner.enqueue(next, true);
            } else if let Some(local) = local.as_deref_mut() {
                let online = inner.online_schedulers.load(Ordering::Acquire);
                // Port of erts/emulator/beam/erl_process.c:6668 (schedule_out_process
                // checks emigration), OTP-29.1.1: a single online scheduler has no path to
                // emigrate to, so the process goes back on the run queue it ran from. A
                // process that ran on a scheduler that went offline goes to the only online
                // one.
                let emigrate = if online == 1 || inner.scheduling_blocked.load(Ordering::Acquire) {
                    None
                } else {
                    inner
                        .balance
                        .check_emigration_need(local.worker_id, process.priority().index())
                        .filter(|&to| to < online)
                };
                if online == 1 && local.worker_id != 0 {
                    inner.enqueue(next, true);
                } else if let Some(to) = emigrate {
                    inner.push_run_queue(to, next, true);
                } else {
                    // Port of erts/emulator/beam/erl_process.c:9603 (one FIFO run queue per
                    // scheduler and priority), OTP-29.1.1: processes this slice enqueued on
                    // the run queue (spawned, woken) were queued before the yielding process,
                    // so they join the local deques ahead of it.
                    inner.take_injected(local);
                    local.record_queued(&next.process, local.worker_id, true);
                    local.queues[next.queue()].push(next);
                }
            } else {
                inner.enqueue(next, true);
            }
        }
        RunOutcome::Wait { timeout_ms } => {
            let epoch = if timeout_ms.is_some() {
                process.timer_epoch_used.store(true, Ordering::Release);
                process.wait_epoch.fetch_add(1, Ordering::AcqRel) + 1
            } else if process.timer_epoch_used.load(Ordering::Acquire) {
                process.wait_epoch.fetch_add(1, Ordering::AcqRel) + 1
            } else {
                process.wait_epoch.load(Ordering::Relaxed)
            };
            let left_running = process
                .run_state()
                .store_from_running(WAITING, Ordering::SeqCst);
            if dirty.is_some() {
                // Already outside the normal run queue accounting.
            } else if let Some(local) = local.as_deref_mut() {
                local.record_waiting(&process);
            } else {
                inner.record_waiting(&process);
            }
            if let Some(ms) = timeout_ms {
                if ms == 0 {
                    if process
                        .run_state()
                        .compare_exchange(WAITING, QUEUED, Ordering::AcqRel, Ordering::Acquire)
                        .is_ok()
                    {
                        process.wait_epoch.fetch_add(1, Ordering::AcqRel);
                        let item = Scheduled::new(process.clone());
                        inner.place_runnable(item, local.as_deref_mut());
                        return;
                    }
                } else if let Some(local) = local.as_deref_mut().filter(|_| worker.is_some()) {
                    // Arm the timeout locally. The wheel insert waits until this
                    // worker is about to park, or until the deadline is due.
                    process
                        .wait_timer
                        .store(WAIT_TIMER_DEFERRED, Ordering::Release);
                    local.pending_waits.push(PendingWait {
                        process: process.clone(),
                        epoch,
                        deadline_ms: inner.clock.timeout_pos(ms),
                    });
                    if process.run_state().load(Ordering::Acquire) != WAITING
                        || process.wait_epoch.load(Ordering::Acquire) != epoch
                    {
                        process.wait_timer.store(0, Ordering::Release);
                    }
                } else if let Ok(reference) = inner.start_timer(
                    process.pid,
                    ms,
                    TimerPayload::Wake(process.pid, epoch),
                    None,
                    worker,
                ) {
                    process
                        .wait_timer_worker
                        .store(reference.worker, Ordering::Relaxed);
                    process.wait_timer.store(reference.id, Ordering::Release);
                    if process.run_state().load(Ordering::Acquire) != WAITING
                        || process.wait_epoch.load(Ordering::Acquire) != epoch
                    {
                        inner.cancel_wait_timer(&process, reference.id);
                    }
                }
            }
            // A signal that arrived while the process ran found it active and did not wake it.
            // Its in-queue bit is in the word the transition to WAITING returned, so no
            // further load is needed; one that arrives later sees WAITING and wakes it.
            // Port of erts/emulator/beam/erl_process.c:6695-6790 (schedule_out_process works
            // from the state word it read), OTP-29.1.1.
            if left_running & psflg::SIG_IN_Q != 0
                && process
                    .run_state()
                    .compare_exchange(WAITING, QUEUED, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
            {
                process.wait_epoch.fetch_add(1, Ordering::AcqRel);
                let id = process.wait_timer.load(Ordering::Acquire);
                inner.cancel_wait_timer(&process, id);
                let next = Scheduled::new(process.clone());
                inner.place_runnable(next, local.as_deref_mut());
            }
        }
        RunOutcome::Exit(_) => {
            process.run_state().store(EXITED, Ordering::SeqCst);
            if dirty.is_some() {
                // Already outside the normal run queue accounting.
            } else if let Some(local) = local.as_deref_mut() {
                local.record_waiting(&process);
            } else {
                inner.record_waiting(&process);
            }
            // Close the in-queue under the msgq lock and reap what it still holds; a later
            // enqueue fails and the sender sees the process gone.
            let mut remaining = SignalQueue::default();
            if process.input.close_into(&mut remaining) > 0 {
                let events = std::iter::from_fn(|| remaining.pop_front()).collect();
                cell.task_mut().reap_signals(process.pid, events);
            }
            cell.task_mut().delete_process();
            // `begin_exit` already deleted the element (erts deletes once, at
            // ERTS_CONTINUE_EXIT_FREE). The identifier may have been reused; deleting
            // this pix again would free the new occupant. A forced exit that never
            // reached `begin_exit` still owns the slot.
            if inner.table.lookup(process.pid).is_some() {
                inner.table.remove(process.pid);
            }
        }
    }
    if let Some(local) = local {
        inner.flush_local_metrics(local);
    }
    drop(cell);
}

/// Signal operations a task's native code performs on the normal scheduler it runs on.
trait NativeSend<M> {
    /// Deliver `msg` from `from` to `to`; a receiver woken on this scheduler's run queue is
    /// enqueued there directly. Gives the message back when the scheduler-local state is
    /// not available.
    fn send(&self, from: Pid, to: Pid, msg: M) -> Result<Result<(), Error>, M>;
    /// [`NativeSend::send`] of a message node the sender allocated.
    #[allow(clippy::type_complexity)] // The node comes back unchanged when it was not sent.
    fn send_node(
        &self,
        to: Pid,
        signal: OwnedSignal<Event<M>>,
    ) -> Result<Result<(), Error>, OwnedSignal<Event<M>>>;
    /// [`Scheduler::try_send_on_heap`] on this scheduler: the receiver is found without taking
    /// a reference, `prepare` builds the message on its heap, and the same lookup delivers it.
    /// `None` when the scheduler-local state is not available.
    fn send_on_heap(
        &self,
        from: Pid,
        to: Pid,
        prepare: &mut dyn FnMut(&mut dyn std::any::Any) -> Option<M>,
    ) -> Option<OnHeapSend>;
    /// Whether this handle belongs to the scheduler whose shared state sits at `inner`.
    fn belongs_to(&self, inner: usize) -> bool;
    /// Start a message timer for `target` owned by `owner` on this scheduler's wheel.
    /// Gives the message back when the scheduler-local state is not available.
    fn start_timer(
        &self,
        owner: Pid,
        target: Pid,
        ms: u64,
        msg: M,
        wrapped: bool,
    ) -> Result<Result<TimerRef, Error>, M>;
    /// [`NativeSend::start_timer`] for a target resolved when the timer expires.
    fn start_resolved_timer(
        &self,
        owner: Pid,
        ms: u64,
        resolve: Arc<dyn Fn() -> Option<Pid> + Send + Sync>,
        msg: M,
        wrapped: bool,
    ) -> Result<Result<TimerRef, Error>, M>;
    /// Cancel or read the BIF timer with reference key `key` when this scheduler's wheel owns
    /// it. The outer `None` means another scheduler owns it, or no wheel is reachable here.
    fn access_bif_timer(&self, key: u64, cancel: bool) -> Option<Option<u64>>;
}

/// The handle a normal scheduler thread installs for native code: its own run queue state
/// and the scheduler it belongs to.
struct WorkerSender<T: Task> {
    inner: Arc<Inner<T>>,
    local: std::rc::Weak<RefCell<Local<T>>>,
}

impl<T: Task> NativeSend<T::Message> for WorkerSender<T> {
    fn belongs_to(&self, inner: usize) -> bool {
        Arc::as_ptr(&self.inner) as usize == inner
    }

    // Port of erts/emulator/beam/erl_message.c (erts_try_alloc_message_on_heap under the
    // receiver's main lock, then erts_queue_proc_message), OTP-29.1.1, with the receiver found
    // by erts_proc_lookup_raw: one table lookup, no reference count, serves the lock, the
    // heap, the queue push and the wake.
    fn send_on_heap(
        &self,
        from: Pid,
        to: Pid,
        prepare: &mut dyn FnMut(&mut dyn std::any::Any) -> Option<T::Message>,
    ) -> Option<OnHeapSend> {
        let local = self.local.upgrade()?;
        let mut local = local.try_borrow_mut().ok()?;
        let outcome = self.inner.table.with_live(to, |process| {
            if !receiver_heap_stable(process) {
                return OnHeapSend::Unavailable;
            }
            let Some(mut cell) = process.cell.try_lock() else {
                return OnHeapSend::Unavailable;
            };
            if !receiver_heap_stable(process) {
                return OnHeapSend::Unavailable;
            }
            let Some(message) = prepare(cell.task_mut()) else {
                return OnHeapSend::Declined;
            };
            let mut local = process.bound_worker().is_none().then_some(&mut *local);
            self.inner
                .publish_held_monitor_for(to, local.as_deref_mut());
            match self
                .inner
                .deliver_live(process, from, Payload::Message(message), local)
            {
                Ok(()) | Err(Error::NoProcess) => OnHeapSend::Queued,
                Err(error) => OnHeapSend::Failed(error),
            }
        });
        Some(outcome.unwrap_or(OnHeapSend::Unavailable))
    }

    fn send(&self, from: Pid, to: Pid, msg: T::Message) -> Result<Result<(), Error>, T::Message> {
        let Some(local) = self.local.upgrade() else {
            return Err(msg);
        };
        let Ok(mut local) = local.try_borrow_mut() else {
            return Err(msg);
        };
        // Port of erts/emulator/beam/erl_message.c:698 (erts_send_message) and
        // erl_proc_sig_queue.h:2080 (erts_proc_notify_new_message -> erts_schedule_process),
        // OTP-29.1.1: the sender enqueues the woken receiver itself, on the run queue of the
        // scheduler it runs on when that is the receiver's run queue.
        self.inner.publish_held_monitor_for(to, Some(&mut local));
        Ok(self
            .inner
            .deliver(from, to, Payload::Message(msg), Some(&mut local)))
    }

    fn send_node(
        &self,
        to: Pid,
        signal: OwnedSignal<Event<T::Message>>,
    ) -> Result<Result<(), Error>, OwnedSignal<Event<T::Message>>> {
        let Some(local) = self.local.upgrade() else {
            return Err(signal);
        };
        let Ok(mut local) = local.try_borrow_mut() else {
            return Err(signal);
        };
        self.inner.publish_held_monitor_for(to, Some(&mut local));
        Ok(self.inner.deliver_node(to, signal, Some(&mut local)))
    }

    fn start_timer(
        &self,
        owner: Pid,
        target: Pid,
        ms: u64,
        msg: T::Message,
        wrapped: bool,
    ) -> Result<Result<TimerRef, Error>, T::Message> {
        let Some(local) = self.local.upgrade() else {
            return Err(msg);
        };
        let Ok(mut local) = local.try_borrow_mut() else {
            return Err(msg);
        };
        // Port of erts/emulator/beam/erl_hl_timer.c (erts_create_bif_timer on the calling
        // scheduler's timer wheel), OTP-29.1.1.
        Ok(self.inner.start_timer(
            owner,
            ms,
            TimerPayload::Message(target, msg, wrapped),
            Some(&mut local),
            None,
        ))
    }

    // Port of erts/emulator/beam/erl_hl_timer.c:2237 (access_bif_timer): the reference carries
    // the scheduler id; when it is the calling scheduler, its own btm tree answers.
    fn access_bif_timer(&self, key: u64, cancel: bool) -> Option<Option<u64>> {
        if self.inner.sim_timers.is_some() {
            return None;
        }
        let reference = TimerRef::from_ref_key(key, self.inner.timer_commands.len());
        let local = self.local.upgrade()?;
        let service = {
            let local = local.try_borrow().ok()?;
            if local.worker_id != reference.worker {
                return None;
            }
            Rc::clone(&local.timer_service)
        };
        if let Ok(mut borrowed) = service.try_borrow_mut() {
            self.inner.run_timer_commands(&mut borrowed);
        }
        self.inner.access_service_timer(&service, reference, cancel)
    }

    fn start_resolved_timer(
        &self,
        owner: Pid,
        ms: u64,
        resolve: Arc<dyn Fn() -> Option<Pid> + Send + Sync>,
        msg: T::Message,
        wrapped: bool,
    ) -> Result<Result<TimerRef, Error>, T::Message> {
        let Some(local) = self.local.upgrade() else {
            return Err(msg);
        };
        let Ok(mut local) = local.try_borrow_mut() else {
            return Err(msg);
        };
        Ok(self
            .inner
            .start_resolved_timer(owner, ms, resolve, msg, wrapped, Some(&mut local)))
    }
}

/// The current normal scheduler thread's [`NativeSend`] handle.
// Port of erts/emulator/beam/erl_process.h (erts_get_scheduler_data: the scheduler data of
// the calling scheduler thread, which BIFs called from JIT code reach through `esdp`),
// OTP-29.1.1.
mod native_sender {
    use super::NativeSend;
    use std::any::Any;
    use std::cell::RefCell;
    use std::rc::Rc;

    thread_local! {
        static CURRENT: RefCell<Option<Box<dyn Any>>> = const { RefCell::new(None) };
    }

    pub(super) fn install<M: 'static>(handle: Rc<dyn NativeSend<M>>) {
        CURRENT.with(|current| *current.borrow_mut() = Some(Box::new(handle)));
    }

    pub(super) fn clear() {
        CURRENT.with(|current| current.borrow_mut().take());
    }

    pub(super) fn with<M: 'static, R>(f: impl FnOnce(&Rc<dyn NativeSend<M>>) -> R) -> Option<R> {
        CURRENT.with(|current| {
            let current = current.try_borrow().ok()?;
            let handle = current.as_ref()?.downcast_ref::<Rc<dyn NativeSend<M>>>()?;
            Some(f(handle))
        })
    }
}

/// [`native_send`] of a message node the sender allocated.
#[allow(clippy::type_complexity)] // The node comes back unchanged when it was not sent.
pub fn native_send_node<M: SignalMessage>(
    to: Pid,
    signal: OwnedSignal<Event<M>>,
) -> Result<Result<(), Error>, OwnedSignal<Event<M>>> {
    let mut signal = Some(signal);
    let sent = native_sender::with::<M, _>(|handle| {
        handle.send_node(to, signal.take().expect("message present"))
    });
    match sent {
        Some(Ok(result)) => Ok(result),
        Some(Err(signal)) => Err(signal),
        None => Err(signal.take().expect("message not sent")),
    }
}

/// Send a message from a task's native code through the normal scheduler thread it runs on.
///
/// Returns the message when this thread is no normal scheduler (dirty schedulers, other
/// threads); the caller then sends it through [`Scheduler::send`].
pub fn native_send<M: SignalMessage>(from: Pid, to: Pid, msg: M) -> Result<Result<(), Error>, M> {
    let mut msg = Some(msg);
    let sent = native_sender::with::<M, _>(|handle| {
        handle.send(from, to, msg.take().expect("message present"))
    });
    match sent {
        Some(Ok(result)) => Ok(result),
        Some(Err(msg)) => Err(msg),
        None => Err(msg.take().expect("message not sent")),
    }
}

/// [`Scheduler::try_send_on_heap`] from a task's native code through the normal scheduler
/// thread it runs on. `prepare` gets the receiver task as `dyn Any` and builds the message on
/// its heap; the receiver is looked up once for the lock, the copy, the queue push and the wake.
///
/// `None` when this thread is no normal scheduler; the caller then goes through
/// [`Scheduler::try_send_on_heap`].
pub fn native_try_send_on_heap<M: SignalMessage>(
    from: Pid,
    to: Pid,
    prepare: &mut dyn FnMut(&mut dyn std::any::Any) -> Option<M>,
) -> Option<OnHeapSend> {
    native_sender::with::<M, _>(|handle| handle.send_on_heap(from, to, prepare)).flatten()
}

/// Start a message timer from native code on the calling scheduler's timer wheel.
///
/// Gives the message back when this thread is no normal scheduler (dirty schedulers, other
/// threads); the caller then goes through the scheduler context instead.
// Port of erts/emulator/beam/erl_hl_timer.c (erts_create_bif_timer reaches the timer wheel
// through the calling scheduler's `esdp`), OTP-29.1.1.
pub fn native_start_timer<M: SignalMessage>(
    owner: Pid,
    target: Pid,
    ms: u64,
    msg: M,
    wrapped: bool,
) -> Result<Result<TimerRef, Error>, M> {
    let mut msg = Some(msg);
    let started = native_sender::with::<M, _>(|handle| {
        handle.start_timer(
            owner,
            target,
            ms,
            msg.take().expect("message present"),
            wrapped,
        )
    });
    match started {
        Some(Ok(result)) => Ok(result),
        Some(Err(msg)) => Err(msg),
        None => Err(msg.take().expect("message not sent")),
    }
}

/// Cancels or reads the BIF timer with reference key `key` from native code, on the calling
/// scheduler's own wheel. `None` when another scheduler owns the timer or the thread is no
/// normal scheduler; the caller then goes through a request.
pub fn native_access_timer<M: SignalMessage>(key: u64, cancel: bool) -> Option<Option<u64>> {
    native_sender::with::<M, _>(|handle| handle.access_bif_timer(key, cancel)).flatten()
}

/// [`native_start_timer`] for a target resolved when the timer expires.
pub fn native_start_resolved_timer<M: SignalMessage>(
    owner: Pid,
    ms: u64,
    resolve: Arc<dyn Fn() -> Option<Pid> + Send + Sync>,
    msg: M,
    wrapped: bool,
) -> Result<Result<TimerRef, Error>, M> {
    let mut msg = Some(msg);
    let started = native_sender::with::<M, _>(|handle| {
        handle.start_resolved_timer(
            owner,
            ms,
            Arc::clone(&resolve),
            msg.take().expect("message present"),
            wrapped,
        )
    });
    match started {
        Some(Ok(result)) => Ok(result),
        Some(Err(msg)) => Err(msg),
        None => Err(msg.take().expect("message not sent")),
    }
}

/// Set once `erlang:halt/1,2` begins an orderly halt.
static HALTING: AtomicBool = AtomicBool::new(false);

/// Begin an orderly emulator halt: from now on no scheduler, normal or dirty, picks a
/// process to run.
///
/// Port of erts/emulator/beam/erl_process.c:15239 (erts_halt: ERTS_RUNQ_FLG_HALTING on all
/// run queues; "no processes will be scheduled, only ports"), OTP-29.1.1.
pub fn begin_halt() {
    HALTING.store(true, Ordering::Release);
}

fn halting() -> bool {
    HALTING.load(Ordering::Acquire)
}

/// The fix_alloc shrink aux work of a scheduler: the lower-limit pass once a second, then
/// deallocation passes until the blocks to give back are gone.
///
/// Port of erts/emulator/beam/erl_process.c (handle_fix_alloc on the aux work timeout set by
/// erl_alloc_util.c sched_fix_shrink) and erl_alloc_util.c (erts_alcu_fix_alloc_shrink),
/// OTP-29.1.1.
fn fix_alloc_aux_work<T: Task>(local: &mut Local<T>) {
    const FIX_SHRINK_INTERVAL_MS: u64 = 1000;
    let now = local.last_monotonic_ms;
    let lower_limit = now >= local.fix_shrink_due_ms;
    if !lower_limit && !local.fix_shrink_dealloc {
        return;
    }
    if lower_limit {
        local.fix_shrink_due_ms = now + FIX_SHRINK_INTERVAL_MS;
    }
    let shrink =
        arinsal_alloc::typed::fix_alloc_shrink(arinsal_alloc::thread_alloc_ix(), lower_limit);
    local.fix_shrink_dealloc = shrink.dealloc;
}

type OwnerWaker = Box<dyn Fn() + Send + Sync>;

/// Wakers of the normal schedulers that own an allocator instance, by instance number.
static ALLOC_OWNER_WAKERS: Mutex<Vec<(usize, OwnerWaker)>> = Mutex::new(Vec::new());

/// Wakes the scheduler owning allocator instance `instance` to run its allocator owner work.
///
/// Port of `erts_alloc_notify_delayed_dealloc` (erl_alloc.c), OTP-29.1.1: the owner is woken
/// through its aux work (`ERTS_SSI_AUX_WORK_DD`).
fn notify_alloc_owner(instance: usize) {
    let wakers = ALLOC_OWNER_WAKERS.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((_, wake)) = wakers.iter().find(|(owner, _)| *owner == instance) {
        wake();
    }
}

/// Registers a scheduler as the waker of its allocator instance for the life of its thread.
struct AllocOwnerWaker(usize);

impl AllocOwnerWaker {
    fn install<T: Task>(inner: &Arc<Inner<T>>, worker: usize) -> Self {
        let instance = worker + 1;
        let weak = Arc::downgrade(inner);
        let wake: OwnerWaker = Box::new(move || {
            if let Some(inner) = weak.upgrade() {
                inner.request_aux_work_one(
                    worker,
                    Arc::new(move |_| {
                        arinsal_alloc::typed::handle_owner_work(instance);
                    }),
                );
            }
        });
        ALLOC_OWNER_WAKERS
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push((instance, wake));
        let _ = arinsal_alloc::set_owner_notifier(notify_alloc_owner);
        Self(instance)
    }
}

impl Drop for AllocOwnerWaker {
    fn drop(&mut self) {
        ALLOC_OWNER_WAKERS
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|(instance, _)| *instance != self.0);
    }
}

fn worker_loop<T: Task>(inner: Arc<Inner<T>>, id: usize, local: Local<T>) {
    inner.sleepers[id]
        .set(thread::current())
        .expect("worker registers once");
    NORMAL_SCHEDULER_ID.with(|current| current.set(Some(id)));
    NORMAL_SCHEDULER_COUNT.with(|current| current.set(Some(inner.config.workers)));
    // Port of erts/emulator/beam/erl_alloc.c (erts_alloc_register_scheduler), OTP-29.1.1:
    // scheduler `no` owns allocator instance `no`. A refused registration leaves the thread on
    // instance 0, which is correct for a second runtime in the same process.
    let _owner_waker =
        match arinsal_alloc::register_thread(arinsal_alloc::ThreadKind::Scheduler(id + 1)) {
            Ok(instance) if instance == id + 1 => Some(AllocOwnerWaker::install(&inner, id)),
            _ => None,
        };
    arinsal_term::set_reader_group(id);
    // Port of erts/emulator/beam/erl_process.c:8861 (sched_thread_func registers the
    // scheduler as a managed thread), OTP-29.1.1.
    let managed_thread = thr_progress::register_managed_thread(&inner.progress, id);
    let inner_id = Arc::as_ptr(&inner) as usize;
    OWNER_TIMER_SERVICES.with(|services| {
        services
            .borrow_mut()
            .insert(inner_id, (id, Box::new(local.timer_service.clone())));
    });
    let local_cell = Rc::new(RefCell::new(local));
    // Port of erts/emulator/beam/erl_process.c:5994 (init_scheduler_data), OTP-29.1.1: one
    // data block per scheduler, owned by its thread for the scheduler's lifetime.
    let mut scheduler_data = T::SchedulerData::default();
    arinsal_term::initialize_scheduler_random(std::ptr::from_ref(&scheduler_data).cast());
    let spin_count = scheduler_spin_count(&inner.config.busy_wait_thresholds, 0, "medium");
    native_sender::install(Rc::new(WorkerSender {
        inner: Arc::clone(&inner),
        local: Rc::downgrade(&local_cell),
    }) as Rc<dyn NativeSend<T::Message>>);
    // Stealing starts after this scheduler has run, or after its first wait.
    // Until then an empty queue sleeps, matching a scheduler that reached
    // scheduler_wait at boot before any user process existed.
    let mut steal_armed = false;
    while !inner.stopped.load(Ordering::Acquire) {
        let mut local_guard = local_cell.borrow_mut();
        let local = &mut *local_guard;
        // Port of erts/emulator/beam/erl_process.c:9857-9866 (schedule: the progress point
        // between two scheduled processes), OTP-29.1.1.
        thr_progress::scheduler_progress(&managed_thread);
        if halting() {
            // The halting scheduler terminates the OS process; the others stay idle.
            thr_progress::scheduler_prepare_wait();
            thread::park();
            thr_progress::scheduler_finalize_wait();
            continue;
        }
        let accounting_flags = inner.accounting_flags.load(Ordering::Relaxed);
        let wall_enabled = accounting_flags & ACCOUNTING_WALL != 0;
        if local.msacc_enabled != (accounting_flags & ACCOUNTING_MSACC != 0)
            || local.wall_enabled != wall_enabled
        {
            local.set_msacc_enabled(accounting_flags & ACCOUNTING_MSACC != 0);
            let started_at = (wall_enabled && !local.wall_enabled)
                .then(|| inner.take_wall_start(id))
                .flatten();
            local.set_wall_enabled_at(wall_enabled, started_at);
        }
        local.set_msacc_state(MsaccState::Other);
        let aux_work = inner.take_aux_work(id);
        if aux_work & AUX_WORK_STATS != 0 {
            while let Some(reply) = inner.stats_requests[id].pop() {
                let _ = reply.send(local.stats_snapshot(local.msacc_enabled, local.wall_enabled));
            }
        }
        local.set_msacc_state(MsaccState::Aux);
        inner.handle_local_aux_work(id, &mut *local, aux_work);
        local.set_msacc_state(MsaccState::Other);
        if inner.runq_halting[id].load(Ordering::Acquire) {
            if inner.execute_port(local) {
                continue;
            }
            let observed = inner.work_epochs[id].load(Ordering::SeqCst);
            inner.parked[id].store(true, Ordering::SeqCst);
            local.set_msacc_state(MsaccState::Aux);
            inner.poll_timers(id, Some(&mut *local), true);
            inner.handle_aux_work(id);
            local.set_msacc_state(MsaccState::Other);
            if !inner.port_queues[id].is_empty()
                || !inner.aux_work[id].is_empty()
                || inner.work_epochs[id].load(Ordering::SeqCst) != observed
                // The sleeping flag is published: look at the thread progress value again
                // (scheduler_wait re-reads its aux work after ERTS_SSI_FLG_SLEEPING is set).
                || thr_progress::scheduler_later_op_ready()
            {
                inner.parked[id].store(false, Ordering::SeqCst);
                continue;
            }
            let timer_ms = local
                .timer_service
                .borrow_mut()
                .wheel
                .next_timeout()
                .map(|next| next.saturating_sub(inner.clock.now_ms()));
            local.set_wall_enabled(false);
            thr_progress::scheduler_prepare_wait();
            // Port of erts/emulator/beam/erl_process.c (scheduler_wait): the sleep state
            // covers only the blocking wait.
            local.set_msacc_state(MsaccState::Sleep);
            if let Some(ms) = timer_ms {
                thread::park_timeout(Duration::from_millis(ms.max(1)));
            } else {
                thread::park();
            }
            local.set_msacc_state(MsaccState::Other);
            thr_progress::scheduler_finalize_wait();
            inner.parked[id].store(false, Ordering::SeqCst);
            continue;
        }
        if id >= inner.online_schedulers.load(Ordering::Acquire)
            || (inner.scheduling_blocked.load(Ordering::Acquire)
                && id != inner.scheduling_blocker.load(Ordering::Acquire))
        {
            // An offline or blocked scheduler hands its queued work and due timers to the
            // schedulers still running.
            inner.poll_timers(id, Some(&mut *local), true);
            inner.poll_pending_waits(&mut *local, true);
            inner.evacuate_offline_local(&mut *local);
            local.set_wall_enabled(false);
            // Port of erts/emulator/beam/erl_process.c:3404 (scheduler_wait), OTP-29.1.1.
            // Publish the sleeping flag, then look again. An enqueue that does not
            // see the flag advances work_epochs; one that does calls ssi_wake.
            // Sleeping without this look loses the enqueue: the scheduler parks
            // with work on its queue, and a later SIGTERM notify never runs.
            let observed = inner.work_epochs[id].load(Ordering::SeqCst);
            inner.parked[id].store(true, Ordering::SeqCst);
            let still_suspended = id >= inner.online_schedulers.load(Ordering::Acquire)
                || (inner.scheduling_blocked.load(Ordering::Acquire)
                    && id != inner.scheduling_blocker.load(Ordering::Acquire));
            let arrived = inner.work_epochs[id].load(Ordering::SeqCst) != observed
                || thr_progress::scheduler_later_op_ready()
                || inner.run_queues[id].iter().any(|queue| !queue.is_empty())
                || local.queues.iter().any(|queue| !queue.is_empty())
                || !inner.port_queues[id].is_empty()
                || inner.pinned_injectors[id]
                    .iter()
                    .any(|queue| !queue.is_empty())
                || !inner.aux_work[id].is_empty()
                || !inner.stats_requests[id].is_empty()
                || inner.halt_requested.load(Ordering::Acquire)
                || !still_suspended;
            if arrived {
                inner.parked[id].store(false, Ordering::SeqCst);
                continue;
            }
            let has_local_timers =
                !local.pending_waits.is_empty() || local.timer_service.borrow().wheel.has_timers();
            thr_progress::scheduler_prepare_wait();
            // Port of erl_process.c:3065 (sched_spin_wait): a wake that lands in this
            // window clears `parked` and must not fall into a blocking park.
            let mut spins = spin_count;
            let mut until_yield = SCHED_SPIN_UNTIL_YIELD;
            while spins > 0 && inner.parked[id].load(Ordering::Acquire) {
                scheduler_spin_body();
                until_yield -= 1;
                if until_yield == 0 {
                    until_yield = SCHED_SPIN_UNTIL_YIELD;
                    thread::yield_now();
                }
                spins -= 1;
            }
            if inner.parked[id].load(Ordering::SeqCst) {
                local.set_msacc_state(MsaccState::Sleep);
                if has_local_timers {
                    thread::park_timeout(Duration::from_millis(10));
                } else {
                    while inner.parked[id].load(Ordering::SeqCst)
                        && !inner.stopped.load(Ordering::Acquire)
                        && !inner.halt_requested.load(Ordering::Acquire)
                    {
                        thread::park();
                    }
                }
                local.set_msacc_state(MsaccState::Other);
            }
            thr_progress::scheduler_finalize_wait();
            inner.parked[id].store(false, Ordering::SeqCst);
            continue;
        }
        // Port of erts/emulator/beam/erl_process.c:2683 (auxiliary work), OTP-29.1.1.
        local.set_msacc_state(MsaccState::Aux);
        // Port of erts/emulator/beam/erl_process.c:9803 (check_time_reds) and
        // erl_time_sup.c (erts_get_monotonic_time resets check_time_reds), OTP-29.1.1: a
        // busy scheduler reads the clock once per ERTS_CHECK_TIME_REDS reductions.
        let check_time = local.check_time_reds >= inner.config.reductions;
        inner.poll_pending_waits(&mut *local, check_time);
        inner.poll_timers(id, Some(&mut *local), false);
        if check_time {
            local.check_time_reds = 0;
        }
        local.set_msacc_state(MsaccState::Other);
        inner.flush_local_metrics(&mut *local);
        // Port of erts/emulator/beam/erl_process.c:9812-9822 (check_activities_to_run:
        // check_balance and immigrate), OTP-29.1.1.
        if inner.balance.rqs[id]
            .check_balance_reds
            .load(Ordering::Relaxed)
            <= 0
        {
            inner.balance.check_balance(id);
        }
        if inner.balance.path_flags(id) & balance::IMMIGRATE_QMASK != 0 {
            inner.immigrate(&mut *local);
        }
        // Processes enqueued on this run queue from other threads join the local deques in
        // arrival order, so the local queue is this scheduler's whole run queue.
        inner.take_injected(local);
        // Port of erts/emulator/beam/erl_process.c:9953 (schedule: "Schedule system-level
        // activities" once the schedulers executed twice a context's reductions), OTP-29.1.1.
        if FUNCTION_CALLS.load(Ordering::Relaxed) > 2 * CONTEXT_REDS_SYS
            && let Some(poll) = sched_poll().filter(|poll| prepare_for_sys_schedule(poll))
        {
            local.set_msacc_state(MsaccState::CheckIo);
            poll.poll(Some(Duration::ZERO));
            local.set_msacc_state(MsaccState::Other);
            clear_sys_scheduling();
        }
        // Hold the run-queue lock across the wakeup check. A scheduler woken here
        // must not steal the process this scheduler is about to run.
        // Port of erts/emulator/beam/erl_process.c:4631 (trylock EBUSY), OTP-29.1.1.
        inner.in_schedule[id].store(true, Ordering::Release);
        // Port of erts/emulator/beam/erl_process.c:9976 (wakeup_other check), OTP-29.1.1.
        wakeup_other_check(&inner, &mut *local);
        // Port execution releases the run queue, so another scheduler can steal a
        // port while this one is inside erts_port_task_execute. Without a queued port
        // the run queue stays held up to the dequeue below.
        let mut run_queue_held = true;
        let port_queued = inner.balance.rqs[id].len(balance::PORT_PRIO_LEVEL) > 0;
        if port_queued {
            inner.in_schedule[id].store(false, Ordering::Release);
            run_queue_held = false;
        }
        // Port of erts/emulator/beam/erl_process.c:9977-9986 (find a new port to run),
        // OTP-29.1.1.
        let ran_port = port_queued && {
            if !local.profile_active {
                let count = inner.active_schedulers.fetch_add(1, Ordering::Relaxed) + 1;
                local.profile_active = true;
                if let Some(process) = local.last_process.and_then(|pid| inner.table.lookup(pid)) {
                    profile_scheduler_transition(&inner, &process, id, true, count, &mut *local);
                }
            }
            inner.execute_port(&mut *local)
        };
        if inner.scheduling_blocked.load(Ordering::Acquire) && inner.sim.is_none() {
            inner.in_schedule[id].store(false, Ordering::Release);
            run_queue_held = false;
            let pinned = (0..4).find(|&p| !inner.pinned_injectors[id][p].is_empty());
            let normal_prio = match (local.best_priority(), pinned) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (a, b) => a.or(b),
            };
            if inner.dirty_best_priority(DirtyKind::Cpu).is_some()
                || inner.dirty_best_priority(DirtyKind::Io).is_some()
            {
                local.set_msacc_state(MsaccState::Sleep);
                local.set_wall_enabled(false);
                let switched = inner.msb_switch_to_dirty(normal_prio);
                local.set_msacc_state(MsaccState::Other);
                if switched {
                    inner.in_schedule[id].store(false, Ordering::Release);
                    continue;
                }
                local.set_wall_enabled(wall_enabled);
            }
        }
        // Dequeue holds the run queue again so a concurrent steal cannot take the
        // process this scheduler is about to run.
        if !run_queue_held {
            inner.in_schedule[id].store(true, Ordering::Release);
        }
        let mut item = None;
        // Port of erts/emulator/beam/erl_process.c:9603 (one run queue per scheduler,
        // FIFO within a priority), OTP-29.1.1: bound processes share their scheduler with
        // other work, so a yielding bound process alternates with equal-priority work and
        // never runs ahead of higher-priority work.
        let has_pinned =
            inner.run_queue_flags[id].load(Ordering::Acquire) >> PINNED_FLAGS_SHIFT != 0;
        let other = if has_pinned {
            local.best_priority()
        } else {
            None
        };
        for priority in 0..if has_pinned { PROC_QUEUES } else { 0 } {
            if let Some(other) = other
                && (other < priority || (other == priority && local.pinned_turn))
            {
                break;
            }
            let bit = 1 << (PINNED_FLAGS_SHIFT + priority as u32);
            if inner.run_queue_flags[id].load(Ordering::Acquire) & bit == 0 {
                continue;
            }
            let pinned = &inner.pinned_injectors[id][priority];
            item = pop_requeue(
                || pinned.pop(),
                |item| pinned.push(item),
                || pinned.is_empty(),
            );
            if pinned.is_empty() {
                // A push racing with this clear finds its bit cleared and sets it again
                // after its push; one that pushed before the clear is seen here.
                inner.run_queue_flags[id].fetch_and(!bit, Ordering::AcqRel);
                if !pinned.is_empty() {
                    inner.run_queue_flags[id].fetch_or(bit, Ordering::Release);
                }
            }
            if item.is_some() {
                break;
            }
        }
        local.pinned_turn = item.is_some();
        if item.is_none() {
            item = local.pop();
        }
        if item.is_none() && steal_armed {
            // Port of erts/emulator/beam/erl_process.c:4640 (try_steal_task), OTP-29.1.1.
            // A scheduler steals only after it has run out of work and been through
            // scheduler_wait, or after it has already executed. The first look at an
            // empty queue waits, the way a booted scheduler sleeps before user work
            // exists, so it does not take processes another scheduler just enqueued
            // on its own run queue.
            let limit = inner.config.workers.div_ceil(2) as u32;
            if inner.searching.fetch_add(1, Ordering::AcqRel) < limit {
                match inner.try_steal_task(&mut *local) {
                    Some(Stolen::Process(found)) => item = Some(found),
                    Some(Stolen::Port) => {
                        inner.searching.fetch_sub(1, Ordering::AcqRel);
                        inner.in_schedule[id].store(false, Ordering::Release);
                        continue;
                    }
                    None => {}
                }
            }
            inner.searching.fetch_sub(1, Ordering::AcqRel);
        }
        if item.is_none() {
            item = local.pop();
        }
        if let Some(item) = item {
            if !local.profile_active {
                let count = inner.active_schedulers.fetch_add(1, Ordering::Relaxed) + 1;
                local.profile_active = true;
                profile_scheduler_transition(&inner, &item.process, id, true, count, &mut *local);
            }
            local.last_process = Some(item.process.pid);
            let reductions = local.reductions;
            // The chosen process is off the run queue. Release the lock for the
            // slice so another scheduler can steal work that is still queued.
            inner.in_schedule[id].store(false, Ordering::Release);
            steal_armed = true;
            drop(local_guard);
            // A managed thread runs its later operations at its progress point
            // (`scheduler_progress`), so the unmanaged-runtime pass of `run_one` is not needed.
            run_slice(
                &inner,
                item,
                Some(&local_cell),
                &mut scheduler_data,
                Some(id),
                None,
            );
            let mut local = local_cell.borrow_mut();
            local.wakeup_other_reds += (local.reductions - reductions) as i64;
            continue;
        }
        if ran_port {
            // erl_process.c:10047 (no process to run after a port: check activities again).
            inner.in_schedule[id].store(false, Ordering::Release);
            continue;
        }
        inner.in_schedule[id].store(false, Ordering::Release);
        // A worker advertises parking before its final work check. An enqueuer
        // publishes to this run queue, advances this run queue's epoch, then
        // wakes this worker if it sleeps. The SeqCst order makes either this
        // check observe the publication or the enqueuer observe our parked
        // flag. Another run queue's enqueue does not abort this wait: that
        // scheduler is poked by smp_notify_inc_runq only when the work is
        // its own, or later by wakeup_other_check.
        let observed = inner.work_epochs[id].load(Ordering::SeqCst);
        // Port of erts/emulator/beam/erl_process.c:3404 (scheduler_wait), OTP-29.1.1.
        local.wakeup_other = 0;
        local.wakeup_other_reds = 0;
        inner.parked[id].store(true, Ordering::SeqCst);
        local.set_msacc_state(MsaccState::Aux);
        inner.poll_pending_waits(&mut *local, true);
        inner.poll_timers(id, Some(&mut *local), true);
        local.set_msacc_state(MsaccState::Other);
        if local.queues.iter().any(|queue| !queue.is_empty())
            || inner.run_queues[id].iter().any(|queue| !queue.is_empty())
            || !inner.port_queues[id].is_empty()
            || inner.pinned_injectors[id]
                .iter()
                .any(|queue| !queue.is_empty())
            || !local.timer_service.borrow().commands.is_empty()
            || !local.timer_service.borrow().canceled.is_empty()
            || !inner.stats_requests[id].is_empty()
            || !inner.aux_work[id].is_empty()
            || inner.work_epochs[id].load(Ordering::SeqCst) != observed
                // The sleeping flag is published: look at the thread progress value again
                // (scheduler_wait re-reads its aux work after ERTS_SSI_FLG_SLEEPING is set).
                || thr_progress::scheduler_later_op_ready()
        {
            inner.parked[id].store(false, Ordering::SeqCst);
            continue;
        }
        if local.profile_active {
            let count = inner.active_schedulers.fetch_sub(1, Ordering::Relaxed) - 1;
            local.profile_active = false;
            if let Some(process) = local.last_process.and_then(|pid| inner.table.lookup(pid)) {
                profile_scheduler_transition(&inner, &process, id, false, count, &mut *local);
            }
        }
        // Port of erts/emulator/beam/erl_process.c:3404 (scheduler_wait: sleep until the
        // next timeout, erts_check_next_timeout_time), OTP-29.1.1.
        let timer_ns = {
            let mut service = local.timer_service.borrow_mut();
            if !service.commands.is_empty() || !service.canceled.is_empty() {
                Some(1_000_000)
            } else {
                service
                    .wheel
                    .next_timeout()
                    .map(|next| inner.clock.ns_until_pos(next))
            }
        };
        let wait_ns = match (
            inner
                .nearest_wait_ms(&*local)
                .map(|ms| ms.saturating_mul(1_000_000)),
            timer_ns,
        ) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };

        local.set_wall_enabled(false);
        inner.waiting_schedulers.fetch_add(1, Ordering::Relaxed);
        inner.balance.set_waiting(id, true);
        // Port of erts/emulator/beam/erl_process.c:3576-3579 (erts_thr_progress_active(0),
        // erts_thr_progress_prepare_wait before the spin), OTP-29.1.1.
        thr_progress::scheduler_prepare_wait();
        // Port of erts/emulator/beam/erl_process.c:3065 (sched_spin_wait), OTP-29.1.1: spin
        // before sleeping so a wakeup that comes soon costs no system call.
        let mut spins = spin_count;
        let mut until_yield = SCHED_SPIN_UNTIL_YIELD;
        while spins > 0 && inner.parked[id].load(Ordering::Acquire) {
            scheduler_spin_body();
            until_yield -= 1;
            if until_yield == 0 {
                until_yield = SCHED_SPIN_UNTIL_YIELD;
                thread::yield_now();
            }
            spins -= 1;
        }
        if !inner.parked[id].load(Ordering::SeqCst) {
            // Woken while spinning.
        } else {
            // Port of erts/emulator/beam/erl_process.c (scheduler_wait): the sleep state
            // wraps only the blocking wait, the spin above counts as `other`.
            local.set_msacc_state(MsaccState::Sleep);
            if let Some(poll) = sched_poll().filter(|poll| prepare_for_sys_schedule(poll)) {
                // Port of erts/emulator/beam/erl_process.c (scheduler_wait: "We sleep in
                // check_io, only for normal schedulers"), OTP-29.1.1.
                inner.poll_sleeping[id].store(true, Ordering::SeqCst);
                *POLL_SLEEPER.lock().unwrap() = Some(thread::current().id());
                POLL_SLEEPER_SET.store(true, Ordering::SeqCst);
                if inner.parked[id].load(Ordering::SeqCst) && !inner.stopped.load(Ordering::Acquire)
                {
                    poll.poll(wait_ns.map(Duration::from_nanos));
                }
                POLL_SLEEPER_SET.store(false, Ordering::SeqCst);
                inner.poll_sleeping[id].store(false, Ordering::SeqCst);
                clear_sys_scheduling();
            } else if let Some(ns) = wait_ns {
                park_until(&inner, id, ns);
            } else {
                // `Thread::park` can return spuriously. A real wake clears `parked`
                // before `unpark` (ssi_wake). Stay asleep until that happens so a
                // spurious return does not fall into `try_steal_task`.
                while inner.parked[id].load(Ordering::SeqCst)
                    && !inner.stopped.load(Ordering::Acquire)
                {
                    thread::park();
                }
            }
            local.set_msacc_state(MsaccState::Other);
        }
        steal_armed = true;
        thr_progress::scheduler_finalize_wait();
        inner.waiting_schedulers.fetch_sub(1, Ordering::Relaxed);
        inner.balance.set_waiting(id, false);
        inner.parked[id].store(false, Ordering::SeqCst);
    }
    native_sender::clear();
    // A stopped scheduler waits forever: it must not hold back blockers.
    thr_progress::scheduler_prepare_wait();
    thr_progress::unregister_managed_thread();
    OWNER_TIMER_SERVICES.with(|services| {
        services.borrow_mut().remove(&inner_id);
    });
}

/// The timed sleep of an idle scheduler.
///
/// erts sleeps in the poll set with a kernel timeout that is accurate to about a hundred
/// microseconds; a plain `park_timeout` on macOS overshoots by 1.5 ms (timer coalescing),
/// which is a full extra millisecond on every timer. The coarse part of the sleep is
/// therefore shortened by the observed overshoot and the rest is waited for by yielding
/// until the deadline or a wake-up.
fn park_until<T: Task>(inner: &Inner<T>, id: usize, wait_ns: u64) {
    const SLACK_NS: u64 = if cfg!(target_os = "macos") {
        2_500_000
    } else {
        0
    };
    let deadline = Instant::now() + Duration::from_nanos(wait_ns);
    let coarse = wait_ns.saturating_sub(SLACK_NS);
    if coarse >= 200_000 || SLACK_NS == 0 {
        thread::park_timeout(Duration::from_nanos(coarse.max(1_000)));
    }
    if SLACK_NS == 0 {
        return;
    }
    while Instant::now() < deadline
        && inner.parked[id].load(Ordering::SeqCst)
        && !inner.stopped.load(Ordering::Acquire)
    {
        thread::yield_now();
    }
}

/// What the receiver's BTM lock (`ERTS_PROC_LOCK_BTM`) protects: `p->bif_timers`, the BIF
/// timers aimed at the process (timer id to the scheduler whose wheel holds it), inserted when
/// the timer is created, removed when it fires or is canceled and walked on exit
/// (erts_cancel_bif_timers); and `p->paused_bif_timers`, set while a suspend holds them, with the
/// timers taken off the wheels and the time each had left.
struct ProcBtm<M> {
    tree: std::collections::BTreeMap<u64, usize>,
    paused: Option<PausedBifTimers<M>>,
}

/// Port of erts/emulator/beam/erl_process.h (`ErtsPausedBifTimers`), OTP-29.1.1.
struct PausedBifTimers<M> {
    count: u32,
    list: Vec<(u64, TimerPayload<M>)>,
}

/// Bit of `Process::bif_timer_wheels` for scheduler `worker`'s timer wheel.
fn timer_wheel_bit(worker: usize) -> u64 {
    1 << worker.min(63)
}

/// Auxiliary work: queued closures (`request_aux_work_*`).
const AUX_WORK_FUNC: u32 = 1 << 0;
/// Auxiliary work: statistics snapshot requests.
const AUX_WORK_STATS: u32 = 1 << 1;
/// First `run_queue_flags` bit of the bound-process priority queues.
const PINNED_FLAGS_SHIFT: u32 = 8;

// Port of erts/emulator/beam/erl_process.c:69,75,84 (medium busy-wait threshold), OTP-29.1.1.
const SCHED_SPIN_UNTIL_YIELD: u32 = 100;

#[inline(always)]
fn scheduler_spin_body() {
    // Port of erts/emulator/beam/erl_process.c (sched_spin_wait), OTP-29.1.1:
    // ETHR_SPIN_BODY is a compiler barrier on AArch64, not a processor hint.
    std::sync::atomic::compiler_fence(Ordering::SeqCst);
}

// Port of erts/emulator/beam/erl_process.c:5564-5577 (medium wakeup-other threshold), OTP-29.1.1.
const CONTEXT_REDS: i64 = 4_000;
const WAKEUP_OTHER_LIMIT: i64 = 10 * CONTEXT_REDS;
const WAKEUP_OTHER_FIXED_INC: i64 = CONTEXT_REDS / 10;

/// Wake another scheduler once this run queue has kept more work than it runs.
///
/// Port of erts/emulator/beam/erl_process.c:5610 (wakeup_other_check), OTP-29.1.1, with the
/// default medium threshold (decrement shift 0, full mask).
fn wakeup_other_check<T: Task>(inner: &Inner<T>, local: &mut Local<T>) {
    let wo_reds = local.wakeup_other_reds;
    if wo_reds == 0 {
        return;
    }
    let left_len = i64::from(inner.balance.rqs[local.worker_id].total_len()) - 1;
    if left_len < 1 {
        local.wakeup_other = (local.wakeup_other - wo_reds).max(0);
    } else {
        local.wakeup_other += left_len * wo_reds + WAKEUP_OTHER_FIXED_INC;
        if local.wakeup_other > WAKEUP_OTHER_LIMIT {
            if inner.waiting_schedulers.load(Ordering::Relaxed) != 0 {
                inner.wake_scheduler_on_empty_runq(local.worker_id);
            }
            local.wakeup_other = 0;
        }
    }
    local.wakeup_other_reds = 0;
}

/// Main loop of one dirty scheduler thread.
///
/// Port of erts/emulator/beam/erl_process.c:9600 (erts_schedule for dirty schedulers) and
/// erl_process.c:3404 (scheduler_wait on a dirty run queue), OTP-29.1.1.
fn dirty_scheduler_loop<T: Task>(inner: Arc<Inner<T>>, kind: DirtyKind, index: usize) {
    SCHEDULER_TYPE.with(|current| current.set(kind.into()));
    // Port of erts/emulator/beam/erl_alloc.c (erts_alloc_register_scheduler), OTP-29.1.1: a dirty
    // scheduler uses instance 0 unless dirty allocator instances are configured.
    let _ = arinsal_alloc::register_thread(match kind {
        DirtyKind::Cpu => arinsal_alloc::ThreadKind::DirtyCpu(index + 1),
        DirtyKind::Io => arinsal_alloc::ThreadKind::DirtyIo(index + 1),
    });
    // Port of erts/emulator/beam/erl_process.c:5994 (init_scheduler_data for a dirty
    // scheduler), OTP-29.1.1.
    let mut scheduler_data = T::SchedulerData::default();
    arinsal_term::initialize_scheduler_random(std::ptr::from_ref(&scheduler_data).cast());
    let pool = &inner.dirty[kind.index()];
    let thread = &pool.threads[index];
    let slot = pool.first_slot + index;
    let spin_count = scheduler_spin_count(
        &inner.config.busy_wait_thresholds,
        match kind {
            DirtyKind::Cpu => 1,
            DirtyKind::Io => 2,
        },
        "short",
    );
    let _ = thread.handle.set(thread::current());
    thread.stats.lock().unwrap().set_state(MsaccState::Other);
    loop {
        let process = {
            let mut queue = pool.queue.lock().unwrap();
            loop {
                if inner.stopped.load(Ordering::Acquire)
                    || inner.halt_requested.load(Ordering::Acquire)
                {
                    return;
                }
                if index < pool.online.load(Ordering::Acquire)
                    && queue.len != 0
                    && inner.dirty_may_execute(kind, index)
                    && let Some(process) = queue.pop()
                {
                    break process;
                }
                // Port of erts/emulator/beam/erl_process.c (scheduler_wait for a dirty
                // scheduler): join the sleepers, spin for a wake-up (`sched_spin_wait`,
                // the "short" busy-wait threshold), then sleep.
                thread.wake.store(false, Ordering::SeqCst);
                if !queue.sleepers.contains(&index) {
                    queue.sleepers.push_back(index);
                }
                drop(queue);
                let mut spins = spin_count;
                let mut until_yield = SCHED_SPIN_UNTIL_YIELD;
                while spins > 0 && !thread.wake.load(Ordering::Acquire) {
                    scheduler_spin_body();
                    until_yield -= 1;
                    if until_yield == 0 {
                        until_yield = SCHED_SPIN_UNTIL_YIELD;
                        thread::yield_now();
                    }
                    spins -= 1;
                }
                if !thread.wake.load(Ordering::SeqCst) {
                    // Port of erts/emulator/beam/erl_process.c (scheduler_wait): dirty
                    // schedulers sleep on their TSE event after the configured spin threshold.
                    thread.stats.lock().unwrap().set_state(MsaccState::Sleep);
                    while !thread.wake.load(Ordering::SeqCst)
                        && !inner.stopped.load(Ordering::Acquire)
                        && !inner.halt_requested.load(Ordering::Acquire)
                    {
                        thread::park();
                    }
                    thread.stats.lock().unwrap().set_state(MsaccState::Other);
                }
                queue = pool.queue.lock().unwrap();
                if let Some(position) = queue.sleepers.iter().position(|&slot| slot == index) {
                    queue.sleepers.remove(position);
                }
            }
        };
        thread.stats.lock().unwrap().begin_active();
        process.dirty_runner.store(slot + 1, Ordering::SeqCst);
        run_one(
            &inner,
            Scheduled::new(process.clone()),
            &mut scheduler_data,
            None,
            Some(kind),
        );
        process.dirty_runner.store(0, Ordering::SeqCst);
        {
            let mut stats = thread.stats.lock().unwrap();
            stats.end_active();
        }
        // Port of erts/emulator/beam/erl_process.c:7600, OTP-29.1.1: under blocked
        // multi-scheduling a dirty scheduler executes one job, then switches back.
        inner.msb_dirty_done(kind);
    }
}

/// Return the erts spin count for `+sbwt`, `+sbwtdcpu`, or `+sbwtdio`.
// Port of erts/emulator/beam/erl_process.c:75-86,5852-5887, OTP-29.1.1.
fn scheduler_spin_count(thresholds: &[Option<String>; 3], index: usize, default: &str) -> u32 {
    let threshold = thresholds[index].as_deref().unwrap_or(default);
    let sys_sched = match threshold {
        "very_long" => 40,
        "long" => 20,
        "medium" | "short" => 10,
        "very_short" => 5,
        "none" => 0,
        _ => unreachable!("busy wait thresholds are validated at argument parsing"),
    };
    sys_sched * 1_000
}

fn profile_scheduler_transition<T: Task>(
    inner: &Inner<T>,
    process: &ProcRef<T>,
    scheduler_id: usize,
    active: bool,
    active_schedulers: usize,
    local: &mut Local<T>,
) {
    // A process executing a dirty job keeps its task cell for the whole job.
    if process.dirty.load(Ordering::Acquire) != 0
        || process.dirty_runner.load(Ordering::Acquire) != 0
    {
        return;
    }
    let Some((target, message)) = lock_cell(process).task_mut().scheduler_profile_event(
        process.pid,
        scheduler_id as u32 + 1,
        active,
        active_schedulers as u32,
    ) else {
        return;
    };
    let _ = inner.deliver(process.pid, target, Payload::Message(message), Some(local));
}

#[cfg(test)]
mod worker_drop_tests {
    use super::*;
    use std::sync::Mutex;
    use std::sync::mpsc;

    type Slot = Arc<Mutex<Option<Scheduler<DropFromWorker>>>>;

    struct DropFromWorker {
        slot: Option<Slot>,
        shutdown: mpsc::Sender<()>,
    }

    impl Task for DropFromWorker {
        type Message = ();
        type SchedulerData = ();

        fn run(&mut self, _ctx: &mut RunCtx<'_, ()>, _: &mut (), _budget: u32) -> RunOutcome {
            // The last scheduler handle drops on this worker while its cell is locked.
            match &self.slot {
                Some(slot) => {
                    drop(slot.lock().unwrap().take());
                    RunOutcome::Exit(0)
                }
                None => RunOutcome::Wait { timeout_ms: None },
            }
        }

        fn scheduler_shutdown(&mut self) {
            let _ = self.shutdown.send(());
        }
    }

    #[test]
    fn last_handle_dropped_by_exiting_worker_does_not_deadlock() {
        let scheduler = Scheduler::new(Config {
            workers: 1,
            max_processes: 8,
            ..Config::default()
        });
        let slot: Slot = Arc::new(Mutex::new(None));
        let (shutdown, shutdown_seen) = mpsc::channel();
        // A parked bystander proves the shutdown pass ran over the table.
        scheduler
            .spawn(DropFromWorker {
                slot: None,
                shutdown,
            })
            .unwrap();
        let (unused, _) = mpsc::channel();
        let task = DropFromWorker {
            slot: Some(Arc::clone(&slot)),
            shutdown: unused,
        };
        let mut guard = slot.lock().unwrap();
        scheduler.spawn(task).unwrap();
        *guard = Some(scheduler);
        drop(guard);
        shutdown_seen
            .recv_timeout(Duration::from_secs(10))
            .expect("scheduler shutdown must complete after the worker released its cell");
    }
}
