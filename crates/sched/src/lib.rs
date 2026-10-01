//! VM-independent process scheduling and ordered signal delivery.
//!
//! A VM process implements [`Task`]. Its heap and registers remain inside the
//! task; the scheduler only owns an opaque message envelope and typed signals.
//! Process-table lookups index lazily allocated pages and clone an epoch-protected
//! `Arc`; only slot allocation and reuse take a lock. A generation increment
//! prevents a recycled slot from resolving an old pid. Producers publish both
//! messages and signals through one MPSC head. Worker-local slabs batch events
//! by recipient; the receiver detaches ordered blocks into its private queue.
//! Sends from one logical process must be serialized to preserve sender order.
//!
//! The real scheduler uses per-worker Chase-Lev queues, an injector for
//! external submissions, neighbour-first half-queue stealing, and a bounded
//! `runnext` slot. The simulator uses the same task and mailbox protocol with seeded dispatch and
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
//! Worker parking has a second handoff. External enqueue publishes to an
//! injector, advances a SeqCst work epoch, and unparks one advertised worker.
//! A worker reads the epoch, advertises parking with a SeqCst store, then
//! checks local work, injectors, and the epoch again before parking. Either it
//! finds work or the enqueuer sees its parked flag. `thread::unpark` retains a
//! permit if it precedes `thread::park`.
//!
//! ```
//! use arinsal_sched::{Config, RunCtx, RunOutcome, Scheduler, Task};
//!
//! struct Echo;
//! impl Task for Echo {
//!     type Message = u64; // Replace with a VM heap-fragment envelope.
//!     fn run(&mut self, ctx: &mut RunCtx<Self::Message>, _budget: u32) -> RunOutcome {
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

mod mailbox;
mod timer;

pub use mailbox::{Incoming, Private, ReceiveMarker};
pub use timer::TimerRef;

use crossbeam_deque::{Injector, Steal, Stealer, Worker};
use crossbeam_epoch::{self as epoch, Atomic, Owned};
use crossbeam_queue::SegQueue;
use std::any::Any;
use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::fmt;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
use timer::{CanceledTimer, TimerCommand, TimerPayload, Wheel};

type ErasedTimerService = (usize, Box<dyn Any>);
type SchedulerAuxWork = Arc<dyn Fn(usize) + Send + Sync + 'static>;

thread_local! {
    static OWNER_TIMER_SERVICES: RefCell<HashMap<usize, ErasedTimerService>> = RefCell::new(HashMap::new());
}

const QUEUED: u8 = 0;
/// Receive timeout armed on this worker, not yet inserted in the timer wheel.
const WAIT_TIMER_DEFERRED: u64 = u64::MAX;
const RUNNING: u8 = 1;
const WAITING: u8 = 2;
const EXITED: u8 = 3;
const UNSCHEDULED: u8 = 4;
const PID_LIMIT: u32 = 1 << 28;
const PID_PAGE_SIZE: usize = 1024;
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

/// Local pid matching the 28-bit index and 32-bit generation in `arinsal-term`.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Pid {
    /// Process-table slot, at most 28 bits.
    pub index: u32,
    /// Incremented before a slot is reused.
    pub generation: u32,
}

impl Pid {
    /// Convert to the term crate's tagged local pid.
    pub fn to_term(self) -> Option<arinsal_term::Term> {
        arinsal_term::Term::pid(self.index, self.generation)
    }

    /// Decode a tagged local pid.
    pub fn from_term(term: arinsal_term::Term) -> Option<Self> {
        term.as_pid()
            .map(|(index, generation)| Self { index, generation })
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
}

/// Control signals delivered in the same stream as messages.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Signal<M> {
    /// Link request.
    Link,
    /// Unlink request carrying its acknowledgement id.
    Unlink(u64),
    /// Unlink acknowledgement.
    UnlinkAck(u64),
    /// Monitor request carrying a VM reference.
    Monitor(u64),
    /// `Monitor` could not be published because the target exited first.
    MonitorNoproc(u64),
    /// Demonitor request carrying a VM reference.
    Demonitor(u64),
    /// Exit signal carrying an opaque reason envelope.
    Exit(M),
    /// Port exit signal preserving the port term used as the signal origin.
    PortExit { port: M, reason: M },
    /// Monitor DOWN signal carrying an opaque reason envelope.
    MonitorDown { reference: u64, reason: M },
    /// Alias activation.
    Alias(u64),
    /// Alias deactivation.
    Unalias(u64),
    /// Ask a process to collect its heap at its next signal safe point.
    GarbageCollect,
    /// Ask a process to copy terms from a retiring literal area.
    LiteralAreaCopy {
        area_id: u64,
        request: M,
        how: LiteralCopyHow,
        requester: Pid,
    },
    /// Execute the process-signal blocking callback on the target process.
    ProcSigBlock(i64),
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
        reference: TimerRef,
        message: M,
    },
    /// An expired `send_after`; the VM retires the timer reference and delivers the message as-is.
    TimerMessage {
        reference: TimerRef,
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

thread_local! {
    static SCHEDULER_TYPE: std::cell::Cell<SchedulerType> =
        const { std::cell::Cell::new(SchedulerType::Normal) };
}

/// Scheduler type of the calling thread, like `erts_get_scheduler_data()->type`.
pub fn current_scheduler_type() -> SchedulerType {
    SCHEDULER_TYPE.with(std::cell::Cell::get)
}

/// A VM process or a benchmark dummy task.
pub trait Task: Send + 'static {
    /// Opaque message envelope owned by the receiving process.
    type Message: Send + 'static;
    /// Execute cooperatively, consuming at most `budget` reductions.
    fn run(&mut self, ctx: &mut RunCtx<Self::Message>, budget: u32) -> RunOutcome;
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
}

/// Configuration for threaded and simulated execution.
pub struct Config {
    /// Number of worker threads; defaults to available parallelism minus two.
    pub workers: usize,
    /// Maximum live processes, bounded by the pid index representation.
    pub max_processes: u32,
    /// Reductions in a fresh scheduling quantum.
    pub reductions: u32,
    /// Maximum consecutive inherited-budget `runnext` dispatches.
    pub runnext_limit: u8,
    /// Dirty CPU scheduler threads (`+SDcpu`); erts defaults to one per scheduler.
    pub dirty_cpu_schedulers: usize,
    /// Dirty I/O scheduler threads (`+SDio`); erts defaults to ten.
    pub dirty_io_schedulers: usize,
}

impl Default for Config {
    fn default() -> Self {
        let available = thread::available_parallelism().map_or(1, |n| n.get());
        Self {
            workers: available.max(1),
            max_processes: 1_048_576,
            reductions: 4_000,
            runnext_limit: 3,
            dirty_cpu_schedulers: available.max(1),
            dirty_io_schedulers: 10,
        }
    }
}

/// Recoverable scheduler operation error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Capacity,
    NoProcess,
    NameInUse,
    WrongMode,
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
        let whole_ms = elapsed.as_millis() as u64;
        // Port of erts/emulator/beam/erl_hl_timer.c:670-679
        // (get_timeout_pos), OTP-29.1.1: millisecond deadlines round up so
        // positive timers do not expire before their requested interval.
        whole_ms.saturating_add(u64::from(!elapsed.subsec_nanos().is_multiple_of(1_000_000)))
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

struct TaskCell<T: Task> {
    task: T,
    private: Private<Event<T::Message>>,
}
struct Process<T: Task> {
    pid: Pid,
    priority: Priority,
    bound_worker: AtomicUsize,
    state: AtomicU8,
    scheduler_id: AtomicUsize,
    wait_epoch: AtomicU64,
    timer_epoch_used: AtomicBool,
    wait_timer: AtomicU64,
    input: Incoming<Event<T::Message>>,
    backlog: AtomicUsize,
    /// Publishers between the EXITED check and the mailbox push.
    publish_inflight: AtomicUsize,
    /// Wheel that owns `wait_timer`, so cancel does not guess from the pid.
    wait_timer_worker: AtomicUsize,
    /// Dirty run queue that owns this process: 0 normal, 1 dirty CPU, 2 dirty I/O.
    /// Port of erl_process.h (`ERTS_PSFLG_DIRTY_CPU_PROC`, `ERTS_PSFLG_DIRTY_IO_PROC`), OTP-29.1.1.
    dirty: AtomicU8,
    /// One plus the dirty thread slot executing this process, 0 when not executing dirty.
    /// Port of erl_process.h (`ERTS_PSFLG_DIRTY_RUNNING`), OTP-29.1.1.
    dirty_runner: AtomicUsize,
    cell: Mutex<TaskCell<T>>,
}

impl<T: Task> Process<T> {
    fn bound_worker(&self) -> Option<usize> {
        let worker = self.bound_worker.load(Ordering::Acquire);
        (worker != UNBOUND_WORKER).then_some(worker)
    }
}

struct ProcessTable<T: Task> {
    pages: Vec<OnceLock<ProcessPage<T>>>,
    capacity: u32,
    next: AtomicU32,
    free: Mutex<Vec<u32>>,
}

struct ProcessPage<T: Task> {
    slots: Box<[Atomic<Arc<Process<T>>>]>,
    generations: Box<[AtomicU32]>,
}

impl<T: Task> ProcessPage<T> {
    fn new() -> Self {
        Self {
            slots: (0..PID_PAGE_SIZE).map(|_| Atomic::null()).collect(),
            generations: (0..PID_PAGE_SIZE).map(|_| AtomicU32::new(0)).collect(),
        }
    }
}

impl<T: Task> ProcessTable<T> {
    fn new(capacity: u32) -> Self {
        Self {
            pages: (0..(capacity as usize).div_ceil(PID_PAGE_SIZE))
                .map(|_| OnceLock::new())
                .collect(),
            capacity,
            next: AtomicU32::new(0),
            free: Mutex::new(Vec::new()),
        }
    }

    fn page(&self, index: u32) -> Option<(&ProcessPage<T>, usize)> {
        if index >= self.capacity {
            return None;
        }
        let index = index as usize;
        let page = self.pages[index / PID_PAGE_SIZE].get()?;
        Some((page, index % PID_PAGE_SIZE))
    }

    fn insert(
        &self,
        task: T,
        priority: Priority,
        bound_worker: Option<usize>,
    ) -> Result<Arc<Process<T>>, Error> {
        // Port of erts/emulator/beam/erl_process.c:12180 (alloc_process), OTP-29.1.1.
        // Fresh pids use the monotonic range without contending on the reuse pool.
        let mut next = self.next.load(Ordering::Relaxed);
        let index = loop {
            if next >= self.capacity {
                break self.free.lock().unwrap().pop().ok_or(Error::Capacity)?;
            }
            match self.next.compare_exchange_weak(
                next,
                next + 1,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break next,
                Err(actual) => next = actual,
            }
        };
        let page = self.pages[index as usize / PID_PAGE_SIZE].get_or_init(ProcessPage::new);
        let offset = index as usize % PID_PAGE_SIZE;
        let pid = Pid {
            index,
            generation: page.generations[offset].load(Ordering::Relaxed),
        };
        let process = Arc::new(Process {
            pid,
            priority,
            bound_worker: AtomicUsize::new(bound_worker.unwrap_or(UNBOUND_WORKER)),
            state: AtomicU8::new(WAITING),
            scheduler_id: AtomicUsize::new(0),
            wait_epoch: AtomicU64::new(0),
            timer_epoch_used: AtomicBool::new(false),
            wait_timer: AtomicU64::new(0),
            input: Incoming::default(),
            backlog: AtomicUsize::new(0),
            publish_inflight: AtomicUsize::new(0),
            wait_timer_worker: AtomicUsize::new(0),
            dirty: AtomicU8::new(0),
            dirty_runner: AtomicUsize::new(0),
            cell: Mutex::new(TaskCell {
                task,
                private: Private::default(),
            }),
        });
        // Publication needs only the release store. Flushing the epoch bag on
        // every spawn forced a global reclamation check in the hot path.
        page.slots[offset].store(Owned::new(process.clone()), Ordering::Release);
        Ok(process)
    }

    fn lookup(&self, pid: Pid) -> Option<Arc<Process<T>>> {
        let (page, offset) = self.page(pid.index)?;
        let slot = &page.slots[offset];
        let guard = &epoch::pin();
        let ptr = slot.load(Ordering::Acquire, guard);
        if ptr.is_null() {
            return None;
        }
        // SAFETY: the epoch guard keeps the stored Arc alive during clone.
        let process = unsafe { ptr.deref().clone() };
        (process.pid == pid).then_some(process)
    }

    fn remove(&self, pid: Pid) {
        let guard = &epoch::pin();
        let (page, offset) = self.page(pid.index).expect("live pid has a page");
        let slot = &page.slots[offset];
        let old = slot.swap(epoch::Shared::null(), Ordering::AcqRel, guard);
        if !old.is_null() {
            // SAFETY: the old pointer is detached; epochs protect concurrent lookups.
            unsafe { guard.defer_destroy(old) };
            page.generations[offset].fetch_add(1, Ordering::Relaxed);
            self.free.lock().unwrap().push(pid.index);
        }
    }

    fn live_count(&self) -> usize {
        let guard = &epoch::pin();
        self.pages
            .iter()
            .filter_map(OnceLock::get)
            .flat_map(|page| page.slots.iter())
            .filter(|slot| !slot.load(Ordering::Acquire, guard).is_null())
            .count()
    }

    fn scheduler_shutdown(&self) {
        let allocated = self.next.load(Ordering::Acquire).min(self.capacity);
        for index in 0..allocated {
            let Some((page, offset)) = self.page(index) else {
                continue;
            };
            let pid = Pid {
                index,
                generation: page.generations[offset].load(Ordering::Acquire),
            };
            if let Some(process) = self.lookup(pid) {
                process.cell.lock().unwrap().task.scheduler_shutdown();
            }
        }
    }

    fn test_next_id(&self, set: bool, next_id: u32) -> Option<u32> {
        // Port of erts/emulator/beam/erl_ptab.c:1356-1460 (`erts_ptab_test_next_id`), OTP-29.1.1.
        let current = self.next.load(Ordering::Relaxed);
        let start = if set {
            next_id.wrapping_add(1) % self.capacity
        } else {
            current % self.capacity
        };
        for offset in 0..self.capacity {
            let index = start.wrapping_add(offset) % self.capacity;
            let occupied = self.page(index).is_some_and(|(page, slot)| {
                !page.slots[slot]
                    .load(Ordering::Acquire, &epoch::pin())
                    .is_null()
            });
            if !occupied {
                if set {
                    self.next.store(index, Ordering::Relaxed);
                    self.free.lock().unwrap().retain(|free| *free != index);
                }
                return Some(index);
            }
        }
        None
    }
}

struct Scheduled<T: Task> {
    process: Arc<Process<T>>,
    inherited: Option<u32>,
}

struct TimerService<M> {
    wheel: Wheel<M>,
    commands: Arc<SegQueue<TimerCommand<M>>>,
    canceled: Arc<SegQueue<CanceledTimer>>,
}

struct LocalInit<T: Task> {
    worker_id: usize,
    timer_service: TimerService<T::Message>,
    queues: [Worker<Scheduled<T>>; 4],
    runnext: Option<Scheduled<T>>,
    streak: u8,
    normal_runs: u8,
    message_slabs: Vec<Vec<Event<T::Message>>>,
    pid_cache: Vec<Option<(Pid, Arc<Process<T>>)>>,
    pending_waits: Vec<PendingWait<T>>,
    check_time_reds: u32,
    profile_active: bool,
    last_process: Option<Arc<Process<T>>>,
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
            timer_service: Rc::new(RefCell::new(self.timer_service)),
            queues: self.queues,
            runnext: self.runnext,
            streak: self.streak,
            normal_runs: self.normal_runs,
            message_slabs: self.message_slabs,
            pid_cache: self.pid_cache,
            pending_waits: self.pending_waits,
            check_time_reds: self.check_time_reds,
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
        }
    }
}
struct SimState<T: Task> {
    queue: VecDeque<Scheduled<T>>,
    rng: Box<dyn Rng>,
}

#[derive(Default)]
struct ProgressState {
    active: usize,
    blocked: bool,
}

#[derive(Default)]
struct ThreadProgress {
    state: Mutex<ProgressState>,
    changed: Condvar,
}

struct ProgressGuard {
    progress: Arc<ThreadProgress>,
    active: bool,
}

impl ThreadProgress {
    fn enter(progress: Arc<Self>) -> ProgressGuard {
        let mut state = progress.state.lock().unwrap();
        while state.blocked {
            state = progress.changed.wait(state).unwrap();
        }
        state.active += 1;
        ProgressGuard {
            progress: Arc::clone(&progress),
            active: true,
        }
    }
}

impl ProgressGuard {
    fn block_for(&mut self, duration: Duration) {
        let mut state = self.progress.state.lock().unwrap();
        state.active -= usize::from(self.active);
        self.active = false;
        self.progress.changed.notify_all();
        while state.blocked {
            state = self.progress.changed.wait(state).unwrap();
        }
        state.blocked = true;
        while state.active != 0 {
            state = self.progress.changed.wait(state).unwrap();
        }
        drop(state);
        if !duration.is_zero() {
            thread::sleep(duration);
        }
        let mut state = self.progress.state.lock().unwrap();
        state.blocked = false;
        state.active += 1;
        self.active = true;
        self.progress.changed.notify_all();
    }
}

impl Drop for ProgressGuard {
    fn drop(&mut self) {
        if self.active {
            let mut state = self.progress.state.lock().unwrap();
            state.active -= 1;
            self.progress.changed.notify_all();
        }
    }
}

struct Inner<T: Task> {
    config: Config,
    table: ProcessTable<T>,
    names: Mutex<HashMap<String, Pid>>,
    injectors: [Injector<Scheduled<T>>; 4],
    pinned_injectors: Vec<[SegQueue<Scheduled<T>>; 4]>,
    stealers: Vec<[Stealer<Scheduled<T>>; 4]>,
    sim_timers: Option<Vec<Mutex<Wheel<T::Message>>>>,
    timer_commands: Vec<Arc<SegQueue<TimerCommand<T::Message>>>>,
    canceled_timers: Vec<Arc<SegQueue<CanceledTimer>>>,
    next_timer: AtomicU64,
    clock: Arc<dyn Clock>,
    sim: Option<Mutex<SimState<T>>>,
    stopped: AtomicBool,
    searching: AtomicU32,
    active_schedulers: AtomicUsize,
    worker_stats: Vec<WorkerCounters>,
    stats_requests: Vec<SegQueue<mpsc::Sender<LocalStatsSnapshot>>>,
    aux_work: Vec<SegQueue<SchedulerAuxWork>>,
    accounting_flags: AtomicU8,
    worker_counts: Vec<WorkerQueueCount>,
    online_schedulers: AtomicUsize,
    scheduling_blocked: AtomicBool,
    scheduling_blocker: AtomicUsize,
    next_queue: AtomicUsize,
    started_at: Instant,
    wall_start_requests: Mutex<Vec<Option<Instant>>>,
    work_epoch: AtomicU64,
    parked: Vec<AtomicBool>,
    sleepers: Vec<OnceLock<thread::Thread>>,
    next_sleeper: AtomicU32,
    fanin_stats: bool,
    fanin_delivered: AtomicU64,
    fanin_peak_backlog: AtomicUsize,
    progress: Arc<ThreadProgress>,
    /// Dirty CPU and dirty I/O pools, indexed by [`DirtyKind::index`].
    dirty: [DirtyPool<T>; 2],
}

/// One dirty scheduler pool: a single run queue shared by all of its threads.
///
/// Port of erts/emulator/beam/erl_process.c:6050 (`ERTS_DIRTY_CPU_RUNQ`,
/// `ERTS_DIRTY_IO_RUNQ`), OTP-29.1.1.
struct DirtyPool<T: Task> {
    queue: Mutex<DirtyQueue<T>>,
    ready: Condvar,
    online: AtomicUsize,
    threads: Vec<DirtyThread>,
    /// Global dirty slot of this pool's first thread.
    first_slot: usize,
}

struct DirtyQueue<T: Task> {
    by_priority: [VecDeque<Arc<Process<T>>>; 4],
    len: usize,
}

/// Active ns, microstate ns, and run queue length per dirty pool (CPU, then I/O).
type DirtyStatsSnapshot = ([Vec<u64>; 2], [Vec<[u64; MSACC_STATE_COUNT]>; 2], [u64; 2]);

struct DirtyThread {
    handle: OnceLock<thread::Thread>,
    stats: Mutex<DirtyStats>,
}

/// Wall-time and microstate counters measured on one dirty scheduler thread.
struct DirtyStats {
    active_ns: u64,
    active_started: Option<Instant>,
    msacc_ns: [u64; MSACC_STATE_COUNT],
    msacc_state: MsaccState,
    msacc_started: Instant,
}

impl DirtyStats {
    fn new() -> Self {
        Self {
            active_ns: 0,
            active_started: None,
            msacc_ns: [0; MSACC_STATE_COUNT],
            msacc_state: MsaccState::Other,
            msacc_started: Instant::now(),
        }
    }

    // Port of erts/emulator/beam/erl_msacc.h:300 (erts_msacc_set_state_m), OTP-29.1.1.
    // Counters only advance while microstate accounting is enabled.
    fn set_state(&mut self, state: MsaccState, msacc: bool) {
        let now = Instant::now();
        if msacc {
            let elapsed = now.duration_since(self.msacc_started).as_nanos();
            let counter = &mut self.msacc_ns[self.msacc_state as usize];
            *counter = counter.saturating_add(u64::try_from(elapsed).unwrap_or(u64::MAX));
        }
        self.msacc_state = state;
        self.msacc_started = now;
    }

    fn begin_active(&mut self, msacc: bool) {
        self.set_state(MsaccState::Emulator, msacc);
        self.active_started = Some(Instant::now());
    }

    fn end_active(&mut self, msacc: bool) {
        if let Some(started) = self.active_started.take() {
            let elapsed = u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX);
            self.active_ns = self.active_ns.saturating_add(elapsed);
        }
        self.set_state(MsaccState::Other, msacc);
    }

    fn snapshot(&self, msacc_enabled: bool) -> (u64, [u64; MSACC_STATE_COUNT]) {
        let active = self.active_started.map_or(self.active_ns, |started| {
            self.active_ns
                .saturating_add(u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX))
        });
        let mut msacc = self.msacc_ns;
        if msacc_enabled {
            let current =
                u64::try_from(self.msacc_started.elapsed().as_nanos()).unwrap_or(u64::MAX);
            msacc[self.msacc_state as usize] =
                msacc[self.msacc_state as usize].saturating_add(current);
        }
        (active, msacc)
    }
}

impl<T: Task> DirtyPool<T> {
    fn new(threads: usize, first_slot: usize) -> Self {
        Self {
            queue: Mutex::new(DirtyQueue {
                by_priority: std::array::from_fn(|_| VecDeque::new()),
                len: 0,
            }),
            ready: Condvar::new(),
            online: AtomicUsize::new(threads),
            threads: (0..threads)
                .map(|_| DirtyThread {
                    handle: OnceLock::new(),
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
    // Port of erts/emulator/beam/erl_process.c:6403 (schedule_dirty / enqueue on the
    // dirty run queue), OTP-29.1.1.
    fn enqueue_dirty(&self, process: Arc<Process<T>>, kind: DirtyKind) {
        process
            .dirty
            .store(kind.index() as u8 + 1, Ordering::Release);
        let pool = &self.dirty[kind.index()];
        if let Some(sim) = &self.sim {
            sim.lock().unwrap().queue.push_back(Scheduled {
                process,
                inherited: None,
            });
            return;
        }
        {
            let mut queue = pool.queue.lock().unwrap();
            queue.by_priority[process.priority.index()].push_back(process);
            queue.len += 1;
        }
        // Offline dirty CPU threads also wait on this condvar, so wake them all.
        pool.ready.notify_all();
    }

    fn dirty_thread(&self, slot: usize) -> Option<&DirtyThread> {
        let cpu = self.dirty[0].threads.len();
        if slot < cpu {
            self.dirty[0].threads.get(slot)
        } else {
            self.dirty[1].threads.get(slot - cpu)
        }
    }

    /// Wake the dirty thread executing `process`, so a dirty job waiting in
    /// [`RunCtx::dirty_wait`] can let its signals be handled.
    fn notify_dirty_runner(&self, process: &Process<T>) {
        let runner = process.dirty_runner.load(Ordering::SeqCst);
        if runner != 0
            && let Some(thread) = self.dirty_thread(runner - 1).and_then(|t| t.handle.get())
        {
            thread.unpark();
        }
    }

    fn msacc_accounting(&self) -> bool {
        self.accounting_flags.load(Ordering::Relaxed) & ACCOUNTING_MSACC != 0
    }

    fn dirty_stats(&self) -> DirtyStatsSnapshot {
        let mut active = [Vec::new(), Vec::new()];
        let mut msacc = [Vec::new(), Vec::new()];
        let mut lengths = [0; 2];
        let msacc_enabled = self.msacc_accounting();
        for (index, pool) in self.dirty.iter().enumerate() {
            for thread in &pool.threads {
                let (thread_active, thread_msacc) =
                    thread.stats.lock().unwrap().snapshot(msacc_enabled);
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
        self.wake_worker(worker);
    }

    fn request_aux_work_all(&self, work: SchedulerAuxWork) {
        for worker in 0..self.aux_work.len() {
            self.request_aux_work_one(worker, Arc::clone(&work));
        }
    }

    // Port of erts/emulator/beam/erl_process.c:2665 (handle_aux_work), OTP-29.1.1.
    fn handle_aux_work(&self, worker: usize) {
        while let Some(work) = self.aux_work[worker].pop() {
            work(worker);
        }
    }

    fn handle_local_aux_work(&self, worker: usize, local: &mut Local<T>) {
        // Port of erts/emulator/beam/erl_process.c:2719 (canceled timers before
        // debug-wait completion), OTP-29.1.1.
        self.poll_timers(worker, Some(local), false);
        self.poll_pending_waits(local);
        self.handle_aux_work(worker);
    }

    fn wake_waiting(&self, pid: Pid) -> bool {
        let Some(process) = self.table.lookup(pid) else {
            return false;
        };
        if process
            .state
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
        self.enqueue(
            Scheduled {
                process,
                inherited: None,
            },
            false,
        );
        true
    }

    fn fanin_delivery(&self, process: &Process<T>, count: usize) {
        if !self.fanin_stats {
            return;
        }
        let backlog = process.backlog.load(Ordering::Relaxed);
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

    fn enqueue(&self, item: Scheduled<T>, already_active: bool) {
        // Port of erts/emulator/beam/erl_process.c:8484-8540 (erts_block_multi_scheduling), OTP-29.1.1.
        let blocked = self.scheduling_blocked.load(Ordering::Acquire);
        let blocker = self.scheduling_blocker.load(Ordering::Acquire);
        let online = if blocked {
            1
        } else {
            self.online_schedulers.load(Ordering::Relaxed).max(1)
        };
        let scheduler = if blocked {
            blocker.min(self.worker_counts.len() - 1)
        } else if already_active {
            item.process
                .scheduler_id
                .load(Ordering::Relaxed)
                .min(online - 1)
        } else {
            self.next_queue.fetch_add(1, Ordering::Relaxed) % online
        };
        self.record_queued(&item.process, scheduler, already_active);
        if let Some(sim) = &self.sim {
            sim.lock().unwrap().queue.push_back(item);
        } else if let Some(worker) = item.process.bound_worker() {
            self.pinned_injectors[worker][item.process.priority.index()].push(item);
            self.work_epoch.fetch_add(1, Ordering::SeqCst);
            self.wake_worker(worker);
        } else {
            self.injectors[item.process.priority.index()].push(item);
            // Publish the queue change before a parker's final epoch check.
            self.work_epoch.fetch_add(1, Ordering::SeqCst);
            if blocked {
                // Port of erts/emulator/beam/erl_process.c:8484-8540 (wake the remaining scheduler), OTP-29.1.1.
                self.wake_worker(scheduler);
            } else {
                self.wake_one();
            }
        }
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
    }

    fn record_running(&self, process: &Process<T>, worker: usize) {
        let previous = process
            .scheduler_id
            .load(Ordering::Relaxed)
            .min(self.worker_counts.len() - 1);
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
        let target_of =
            || blocker.unwrap_or_else(|| self.next_queue.fetch_add(1, Ordering::Relaxed) % online);
        let mut moved = false;
        for priority in 0..local.queues.len() {
            while let Some(item) = local.queues[priority].pop() {
                let target = target_of();
                local.migrate_queued(&item.process, target);
                self.injectors[priority].push(item);
                moved = true;
            }
        }
        if let Some(item) = local.runnext.take() {
            let priority = item.process.priority.index();
            let target = target_of();
            local.migrate_queued(&item.process, target);
            self.injectors[priority].push(item);
            moved = true;
        }
        if moved {
            self.work_epoch.fetch_add(1, Ordering::SeqCst);
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

    fn simulation_stats(&self) -> SchedulerStats {
        let counts: Vec<u64> = self
            .worker_counts
            .iter()
            .map(|value| value.0.load(Ordering::Relaxed))
            .collect();
        let dirty = self.dirty_stats();
        SchedulerStats {
            run_queue_lengths: counts
                .iter()
                .map(|value| value >> QUEUE_COUNT_SHIFT)
                .collect(),
            active_tasks: counts
                .iter()
                .map(|value| value & (QUEUE_COUNT_UNIT - 1))
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
            self.wake_worker(worker);
            snapshots.push(receive.recv().unwrap_or_default());
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
        SchedulerStats {
            run_queue_lengths: counts
                .iter()
                .map(|value| value >> QUEUE_COUNT_SHIFT)
                .collect(),
            active_tasks: counts
                .iter()
                .map(|value| value & (QUEUE_COUNT_UNIT - 1))
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

    fn wake_one(&self) {
        // Offline (or multi-scheduling-blocked) schedulers do not run processes; waking one of
        // them would leave the queued work unnoticed.
        let online = self.online_schedulers.load(Ordering::Acquire).max(1);
        let blocker = self
            .scheduling_blocked
            .load(Ordering::Acquire)
            .then(|| self.scheduling_blocker.load(Ordering::Acquire))
            .filter(|blocker| *blocker < online);
        let start =
            self.next_sleeper.fetch_add(1, Ordering::Relaxed) as usize % self.sleepers.len();
        for offset in 0..self.sleepers.len() {
            let index = (start + offset) % self.sleepers.len();
            if index >= online || blocker.is_some_and(|blocker| blocker != index) {
                continue;
            }
            if self.parked[index].load(Ordering::SeqCst)
                && let Some(worker) = self.sleepers[index].get()
            {
                worker.unpark();
                break;
            }
        }
    }

    fn wake_worker(&self, worker: usize) {
        if let Some(thread) = self.sleepers[worker].get() {
            thread.unpark();
        }
    }

    fn wake_all_workers(&self) {
        for sleeper in &self.sleepers {
            if let Some(thread) = sleeper.get() {
                thread.unpark();
            }
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

    fn deliver(
        &self,
        from: Pid,
        to: Pid,
        payload: Payload<T::Message>,
        local: Option<&mut Local<T>>,
        remaining: u32,
    ) -> Result<(), Error> {
        let process = self.table.lookup(to).ok_or(Error::NoProcess)?;
        let state = process.state.load(Ordering::Acquire);
        let counted = state != WAITING && state != UNSCHEDULED;
        // Port of erts/emulator/beam/erl_proc_sig_queue.c:1560-1563, OTP-29.1.1.
        // Literal-copy requests are non-message signals and enter a shared run queue.
        let force_enqueue = matches!(&payload, Payload::Signal(Signal::LiteralAreaCopy { .. }));
        if counted {
            process.backlog.fetch_add(1, Ordering::Relaxed);
        }
        self.fanin_delivery(&process, 1);
        if let Err(error) = self.deliver_process(
            process.clone(),
            from,
            payload,
            local,
            remaining,
            true,
            force_enqueue,
        ) {
            if counted {
                process.backlog.fetch_sub(1, Ordering::Relaxed);
            }
            return Err(error);
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)] // `force_enqueue` routes literal-copy signals like erts.
    fn deliver_process(
        &self,
        process: Arc<Process<T>>,
        from: Pid,
        payload: Payload<T::Message>,
        local: Option<&mut Local<T>>,
        remaining: u32,
        wake: bool,
        force_enqueue: bool,
    ) -> Result<(), Error> {
        // Hold inflight across the EXITED load and the push so an exiting
        // receiver cannot detach an empty mailbox and then miss this event.
        process.publish_inflight.fetch_add(1, Ordering::AcqRel);
        if process.state.load(Ordering::SeqCst) == EXITED {
            process.publish_inflight.fetch_sub(1, Ordering::Release);
            return Err(Error::NoProcess);
        }
        process.input.push(Event { from, payload });
        if wake {
            self.wake_after_publish(process.clone(), local, remaining, force_enqueue);
        }
        process.publish_inflight.fetch_sub(1, Ordering::Release);
        Ok(())
    }

    fn deliver_block(
        &self,
        to: Pid,
        events: &mut Vec<Event<T::Message>>,
        local: Option<&mut Local<T>>,
        remaining: u32,
        wake: bool,
        force_enqueue: bool,
    ) -> Result<(), Error> {
        let process = self.table.lookup(to).ok_or(Error::NoProcess)?;
        process.publish_inflight.fetch_add(1, Ordering::AcqRel);
        if process.state.load(Ordering::SeqCst) == EXITED {
            process.publish_inflight.fetch_sub(1, Ordering::Release);
            return Err(Error::NoProcess);
        }
        process.backlog.fetch_add(events.len(), Ordering::Relaxed);
        self.fanin_delivery(&process, events.len());
        process.input.push_block_reuse(events);
        if wake {
            self.wake_after_publish(process.clone(), local, remaining, force_enqueue);
        }
        process.publish_inflight.fetch_sub(1, Ordering::Release);
        Ok(())
    }

    fn deliver_single(
        &self,
        process: Arc<Process<T>>,
        event: Event<T::Message>,
        local: Option<&mut Local<T>>,
        remaining: u32,
    ) -> Result<(), Error> {
        process.publish_inflight.fetch_add(1, Ordering::AcqRel);
        if process.state.load(Ordering::SeqCst) == EXITED {
            process.publish_inflight.fetch_sub(1, Ordering::Release);
            return Err(Error::NoProcess);
        }
        process.backlog.fetch_add(1, Ordering::Relaxed);
        self.fanin_delivery(&process, 1);
        process.input.push(event);
        self.wake_after_publish(process.clone(), local, remaining, false);
        process.publish_inflight.fetch_sub(1, Ordering::Release);
        // Port of erts/emulator/beam/erl_proc_sig_queue.c:712 (signal enqueue), OTP-29.1.1.
        Ok(())
    }

    fn wake_after_publish(
        &self,
        process: Arc<Process<T>>,
        local: Option<&mut Local<T>>,
        remaining: u32,
        force_enqueue: bool,
    ) {
        let wait_timer = process.wait_timer.load(Ordering::Acquire);
        if process
            .state
            .compare_exchange(WAITING, QUEUED, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            self.notify_dirty_runner(&process);
        } else {
            if wait_timer != 0 {
                process.wait_epoch.fetch_add(1, Ordering::AcqRel);
                self.cancel_wait_timer(&process, wait_timer);
            }
            let item = Scheduled {
                process,
                inherited: Some(remaining),
            };
            if force_enqueue {
                self.enqueue(item, false);
            } else {
                self.place_runnable(item, local);
            }
        }
    }

    /// Same-worker waiters stay on `runnext`. A cross-thread unpark costs more
    /// than a local ping-pong, so the peer runs here before this worker parks.
    fn place_runnable(&self, item: Scheduled<T>, local: Option<&mut Local<T>>) {
        if item.process.bound_worker().is_some() {
            self.enqueue(item, false);
            return;
        }
        if let Some(local) = local {
            if self.online_schedulers.load(Ordering::Acquire) == 1 {
                self.enqueue(item, false);
            } else {
                local.record_queued(&item.process, local.worker_id, false);
                local.push_next(item);
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
                wheel.lock().unwrap().cancel_at(id, self.clock.now_ms());
            }
        } else if let Some(queue) = self.canceled_timers.get(worker) {
            queue.push(CanceledTimer {
                id,
                reply: None,
                callback: None,
            });
            self.wake_worker(worker);
        }
    }

    /// Fire receive timeouts that were kept off the wheel while this worker
    /// stayed busy. A reply clears the epoch, so the common `gen_server:call`
    /// path never locks the timer wheel.
    fn poll_pending_waits(&self, local: &mut Local<T>) {
        if local.pending_waits.is_empty() {
            return;
        }
        local.pending_waits.retain(|entry| {
            entry.process.wait_epoch.load(Ordering::Acquire) == entry.epoch
                && entry.process.state.load(Ordering::Acquire) == WAITING
        });
        if local.pending_waits.is_empty() {
            return;
        }
        let now = self.clock.now_ms();
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
                    .state
                    .compare_exchange(WAITING, QUEUED, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
            {
                process.wait_timer.store(0, Ordering::Release);
                process.wait_epoch.fetch_add(1, Ordering::AcqRel);
                self.place_runnable(
                    Scheduled {
                        process,
                        inherited: None,
                    },
                    Some(local),
                );
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

    fn poll_timers(&self, worker: usize, mut local: Option<&mut Local<T>>, force: bool) {
        let due = if let Some(local) = local.as_deref_mut() {
            debug_assert_eq!(local.worker_id, worker);
            {
                let service = local.timer_service.borrow();
                if !service.wheel.has_timers()
                    && service.commands.is_empty()
                    && service.canceled.is_empty()
                {
                    return;
                }
            }
            self.apply_timer_commands(local);
            if !local.timer_service.borrow().wheel.has_timers() {
                return;
            }
            // Port of erts/emulator/beam/erl_process.c:9803 (ERTS_CHECK_TIME_REDS), OTP-29.1.1.
            if !force && local.check_time_reds < self.config.reductions {
                return;
            }
            local.check_time_reds = 0;
            let now = self.clock.now_ms();
            local.timer_service.borrow_mut().wheel.advance(now)
        } else if let Some(timers) = self.sim_timers.as_ref() {
            let Some(wheel) = timers.get(worker) else {
                return;
            };
            if !wheel.lock().unwrap().has_timers() {
                return;
            }
            let now = self.clock.now_ms();
            wheel.lock().unwrap().advance(now)
        } else {
            return;
        };
        for (id, event) in due {
            self.fire_timer(worker, id, event, local.as_deref_mut());
        }
    }

    fn apply_timer_commands(&self, local: &mut Local<T>) {
        let mut service = local.timer_service.borrow_mut();
        let commands = service.commands.clone();
        while let Some(command) = commands.pop() {
            match command {
                TimerCommand::Insert {
                    id,
                    deadline,
                    payload,
                    reply,
                } => {
                    if !service.wheel.has_timers() {
                        let _ = service.wheel.advance(self.clock.now_ms());
                    }
                    service.wheel.insert(id, deadline, payload);
                    let _ = reply.send(());
                }
                TimerCommand::Read {
                    id,
                    reply,
                    callback,
                } => {
                    let remaining = service.wheel.remaining_at(id, self.clock.now_ms());
                    if let Some(reply) = reply {
                        let _ = reply.send(remaining);
                    }
                    if let Some(callback) = callback {
                        callback(remaining);
                    }
                }
                TimerCommand::Cancel { id, callback } => {
                    let remaining = service
                        .wheel
                        .cancel_at(id, self.clock.now_ms())
                        .map(|(remaining, _)| remaining);
                    callback(remaining);
                }
                TimerCommand::CancelTarget { pid } => {
                    service.wheel.cancel_target(pid);
                }
            }
        }
        let canceled_queue = service.canceled.clone();
        while let Some(canceled) = canceled_queue.pop() {
            let remaining = service
                .wheel
                .cancel_at(canceled.id, self.clock.now_ms())
                .map(|(remaining, _)| remaining);
            if let Some(reply) = canceled.reply {
                let _ = reply.send(remaining);
            }
            if let Some(callback) = canceled.callback {
                callback(remaining);
            }
        }
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
                        reference: TimerRef { worker, id },
                        message,
                    }
                } else {
                    Payload::TimerMessage {
                        reference: TimerRef { worker, id },
                        message,
                    }
                };
                let _ = self.deliver(pid, pid, payload, local, 0);
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
            TimerPayload::ResolvedMessage(resolve, message, wrapped) => {
                if let Some(pid) = resolve() {
                    let payload = if wrapped {
                        Payload::Timer {
                            reference: TimerRef { worker, id },
                            message,
                        }
                    } else {
                        Payload::TimerMessage {
                            reference: TimerRef { worker, id },
                            message,
                        }
                    };
                    let _ = self.deliver(pid, pid, payload, local, 0);
                }
            }
            TimerPayload::Wake(pid, epoch) => {
                if let Some(process) = self.table.lookup(pid)
                    && process.wait_epoch.load(Ordering::Acquire) == epoch
                    && process
                        .state
                        .compare_exchange(WAITING, QUEUED, Ordering::AcqRel, Ordering::Acquire)
                        .is_ok()
                {
                    process.wait_epoch.fetch_add(1, Ordering::AcqRel);
                    let item = Scheduled {
                        process,
                        inherited: None,
                    };
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
        wake: bool,
    ) -> Result<TimerRef, Error> {
        self.start_timer_payload(pid, ms, payload, local, owner, wake)
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
            true,
        )
    }

    fn start_timer_payload(
        &self,
        pid: Pid,
        ms: u64,
        payload: TimerPayload<T::Message>,
        local: Option<&mut Local<T>>,
        owner: Option<usize>,
        wake: bool,
    ) -> Result<TimerRef, Error> {
        if self.table.lookup(pid).is_none() {
            return Err(Error::NoProcess);
        }
        let fallback = pid.index as usize % self.timer_commands.len();
        let worker = owner
            .or_else(|| local.as_deref().map(|local| local.worker_id))
            .filter(|worker| *worker < self.timer_commands.len())
            .unwrap_or(fallback);
        let id = self.next_timer.fetch_add(1, Ordering::Relaxed);
        if ms == 0 {
            self.fire_timer(worker, id, payload, local);
            return Ok(TimerRef { worker, id });
        }
        let now = self.clock.now_ms();
        let deadline = now.saturating_add(ms.max(1));
        if let Some(local) = local.filter(|local| local.worker_id == worker) {
            let mut service = local.timer_service.borrow_mut();
            if !service.wheel.has_timers() {
                let _ = service.wheel.advance(now);
            }
            service.wheel.insert(id, deadline, payload);
        } else if let Some(service) = self.owner_timer_service(worker) {
            let mut service = service.borrow_mut();
            if !service.wheel.has_timers() {
                let _ = service.wheel.advance(now);
            }
            service.wheel.insert(id, deadline, payload);
        } else if let Some(timers) = self.sim_timers.as_ref() {
            let Some(wheel) = timers.get(worker) else {
                return Err(Error::NoProcess);
            };
            let mut wheel = wheel.lock().unwrap();
            if !wheel.has_timers() {
                let _ = wheel.advance(now);
            }
            wheel.insert(id, deadline, payload);
        } else if let Some(queue) = self.timer_commands.get(worker) {
            let (reply, receiver) = mpsc::sync_channel(0);
            queue.push(TimerCommand::Insert {
                id,
                deadline,
                payload,
                reply,
            });
            self.wake_worker(worker);
            let _ = receiver.recv();
        } else {
            return Err(Error::NoProcess);
        }
        // A receive timeout lives on the worker that is running the process.
        // Unparking another thread here is a syscall on the gen_server:call path
        // for a timer that is cancelled as soon as the reply arrives.
        if wake && self.sim.is_none() {
            self.wake_worker(worker);
        }
        Ok(TimerRef { worker, id })
    }

    fn cancel_timer(&self, reference: TimerRef) -> Option<u64> {
        if let Some(timers) = self.sim_timers.as_ref() {
            self.poll_timers(reference.worker, None, true);
            return timers
                .get(reference.worker)?
                .lock()
                .unwrap()
                .cancel_at(reference.id, self.clock.now_ms())
                .map(|x| x.0);
        }
        if let Some(service) = self.owner_timer_service(reference.worker) {
            return service
                .borrow_mut()
                .wheel
                .cancel_at(reference.id, self.clock.now_ms())
                .map(|(remaining, _)| remaining);
        }
        let queue = self.canceled_timers.get(reference.worker)?;
        let (reply, receiver) = mpsc::sync_channel(0);
        queue.push(CanceledTimer {
            id: reference.id,
            reply: Some(reply),
            callback: None,
        });
        // Port of erts/emulator/beam/erl_hl_timer.c (cross-scheduler cancel
        // request), OTP-29.1.1. The owner drains its cancellation queue before
        // invoking this scheduling-point callback.
        self.request_aux_work_one(reference.worker, Arc::new(|_| {}));
        receiver.recv().ok().flatten()
    }

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
                    wheel
                        .lock()
                        .unwrap()
                        .cancel_at(reference.id, self.clock.now_ms())
                })
                .map(|entry| entry.0);
            callback(remaining);
            return;
        }
        if let Some(service) = self.owner_timer_service(reference.worker) {
            // The wheel's own `now` lags the clock between advances; remaining
            // time is measured against the current time like the sync paths.
            let remaining = service
                .borrow_mut()
                .wheel
                .cancel_at(reference.id, self.clock.now_ms())
                .map(|(remaining, _)| remaining);
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
        // Port of erts/emulator/beam/erl_hl_timer.c (cross-scheduler async
        // cancellation), OTP-29.1.1. The owner answers from its next aux point.
        self.request_aux_work_one(reference.worker, Arc::new(|_| {}));
    }

    fn read_timer(&self, reference: TimerRef) -> Option<u64> {
        if let Some(timers) = self.sim_timers.as_ref() {
            self.poll_timers(reference.worker, None, true);
            return timers
                .get(reference.worker)?
                .lock()
                .unwrap()
                .remaining_at(reference.id, self.clock.now_ms());
        }
        if let Some(service) = self.owner_timer_service(reference.worker) {
            return service
                .borrow()
                .wheel
                .remaining_at(reference.id, self.clock.now_ms());
        }
        let queue = self.timer_commands.get(reference.worker)?;
        let (reply, receiver) = mpsc::sync_channel(0);
        queue.push(TimerCommand::Read {
            id: reference.id,
            reply: Some(reply),
            callback: None,
        });
        self.wake_worker(reference.worker);
        receiver.recv().ok().flatten()
    }

    fn read_timer_async(&self, reference: TimerRef, callback: Box<dyn FnOnce(Option<u64>) + Send>) {
        if let Some(timers) = self.sim_timers.as_ref() {
            self.poll_timers(reference.worker, None, true);
            callback(timers.get(reference.worker).and_then(|wheel| {
                wheel
                    .lock()
                    .unwrap()
                    .remaining_at(reference.id, self.clock.now_ms())
            }));
            return;
        }
        if let Some(service) = self.owner_timer_service(reference.worker) {
            callback(
                service
                    .borrow()
                    .wheel
                    .remaining_at(reference.id, self.clock.now_ms()),
            );
            return;
        }
        let Some(commands) = self.timer_commands.get(reference.worker) else {
            callback(None);
            return;
        };
        commands.push(TimerCommand::Read {
            id: reference.id,
            reply: None,
            callback: Some(callback),
        });
        self.wake_worker(reference.worker);
    }
}

struct PendingWait<T: Task> {
    process: Arc<Process<T>>,
    epoch: u64,
    deadline_ms: u64,
}

struct Local<T: Task> {
    worker_id: usize,
    timer_service: Rc<RefCell<TimerService<T::Message>>>,
    queues: [Worker<Scheduled<T>>; 4],
    runnext: Option<Scheduled<T>>,
    streak: u8,
    normal_runs: u8,
    message_slabs: Vec<Vec<Event<T::Message>>>,
    pid_cache: Vec<Option<(Pid, Arc<Process<T>>)>>,
    /// Receive timeouts not yet published to the wheel.
    pending_waits: Vec<PendingWait<T>>,
    check_time_reds: u32,
    profile_active: bool,
    last_process: Option<Arc<Process<T>>>,
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
                self.set_msacc_state(self.msacc_state);
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

    fn set_msacc_state(&mut self, state: MsaccState) {
        if !self.msacc_enabled {
            return;
        }
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
    }

    fn record_running(&mut self, process: &Process<T>, worker: usize) {
        let previous = process
            .scheduler_id
            .load(Ordering::Relaxed)
            .min(self.metric_deltas.len() - 1);
        self.adjust_metric(previous, -(QUEUE_COUNT_UNIT as i64 + 1));
        self.adjust_metric(worker, 1);
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
        process.scheduler_id.store(target, Ordering::Relaxed);
    }

    fn lookup(&mut self, table: &ProcessTable<T>, pid: Pid) -> Option<Arc<Process<T>>> {
        if self.pid_cache.is_empty() {
            self.pid_cache = (0..1024).map(|_| None).collect();
        }
        let slot = pid.index as usize % self.pid_cache.len();
        let entry = &mut self.pid_cache[slot];
        if let Some((cached_pid, process)) = entry
            && *cached_pid == pid
            && process.state.load(Ordering::Acquire) != EXITED
        {
            return Some(process.clone());
        }
        let process = table.lookup(pid)?;
        *entry = Some((pid, process.clone()));
        Some(process)
    }
    fn order(&self) -> [usize; 4] {
        if self.normal_runs >= 8 {
            [0, 1, 3, 2]
        } else {
            [0, 1, 2, 3]
        }
    }
    fn picked(&mut self, priority: usize) {
        // Port of erts/emulator/beam/erl_process.c:9603, OTP-29.1.1.
        // Low-priority processes share the normal queue and are rescheduled less often.
        if priority == 2 {
            self.normal_runs = self.normal_runs.saturating_add(1);
        } else if priority == 3 {
            self.normal_runs = 0;
        }
    }
    /// Highest priority (lowest index) with runnable local work.
    fn best_priority(&self) -> Option<usize> {
        let queued = (0..self.queues.len()).find(|&priority| !self.queues[priority].is_empty());
        let next = self
            .runnext
            .as_ref()
            .map(|item| item.process.priority.index());
        match (queued, next) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }
    fn push_next(&mut self, item: Scheduled<T>) {
        if let Some(displaced) = self.runnext.replace(item) {
            self.queues[displaced.process.priority.index()].push(displaced);
        }
    }
    fn pop(&mut self, limit: u8) -> Option<Scheduled<T>> {
        if self.streak < limit
            && let Some(next) = self.runnext.take()
        {
            self.streak += 1;
            self.picked(next.process.priority.index());
            return Some(next);
        }
        self.streak = 0;
        for priority in self.order() {
            if let Some(item) = self.queues[priority].pop() {
                self.picked(priority);
                return Some(item);
            }
        }
        None
    }
}

/// Context passed to one invocation of `Task::run`.
/// A runtime timer callback; it runs on a scheduler thread when the timer expires.
pub type TimerCallback<M> = Box<dyn FnOnce(&mut dyn TimerCallbackCtx<M>) + Send>;

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
            true,
        );
    }
    fn send(&mut self, msg: T::Message) {
        let _ = self.inner.deliver(
            self.pid,
            self.pid,
            Payload::Message(msg),
            self.local.as_deref_mut(),
            0,
        );
    }
}

pub struct RunCtx<'a, M: Send + 'static> {
    inner: &'a mut dyn ContextOps<M>,
    pid: Pid,
    input: &'a Incoming<Event<M>>,
    private: &'a mut Private<Event<M>>,
    backlog: &'a AtomicUsize,
    bound_worker: &'a AtomicUsize,
    worker: Option<usize>,
    worker_count: usize,
    remaining: u32,
    budget: u32,
    private_wake: bool,
    progress: Option<ProgressGuard>,
    msacc_enabled: bool,
    wall_enabled: bool,
    gc_accounted_total: u64,
    sched_type: SchedulerType,
}

trait ContextOps<M> {
    fn deliver(
        &mut self,
        from: Pid,
        to: Pid,
        payload: Payload<M>,
        remaining: u32,
    ) -> Result<bool, Error>;
    fn flush(&mut self, remaining: u32);
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
    fn cancel_pending_monitor(&mut self, to: Pid, reference: u64) -> bool;
    fn request_aux_work_all(&mut self, work: SchedulerAuxWork);
}

impl<M: Send + 'static> RunCtx<'_, M> {
    fn consumed_event(&self) {
        if self.backlog.load(Ordering::Relaxed) != 0 {
            self.backlog.fetch_sub(1, Ordering::Relaxed);
        }
    }
    /// Pid of the running task.
    pub fn pid(&self) -> Pid {
        self.pid
    }
    /// Return the scheduler worker currently running this process.
    pub fn worker_id(&self) -> Option<usize> {
        self.worker
    }
    /// Reject further mailbox publishes. In-flight publishers still land and
    /// are drained before the pid leaves the process table.
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
    /// Cancel an unpublished monitor when a flushing demonitor follows it in
    /// the same process turn.
    pub fn cancel_pending_monitor(&mut self, to: Pid, reference: u64) -> bool {
        self.inner.cancel_pending_monitor(to, reference)
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
    /// Type of the scheduler executing this process turn.
    pub fn scheduler_type(&self) -> SchedulerType {
        self.sched_type
    }
    /// Publish messages and signals this turn has buffered so far. A long dirty job
    /// calls this so its sends do not wait for the job to return.
    pub fn flush_pending(&mut self) {
        self.inner.flush(self.remaining);
    }
    /// Whether events wait in this process's shared input queue.
    pub fn has_pending_input(&self) -> bool {
        self.input.has_pending()
    }
    /// Block a dirty job for at most `timeout`, returning early when a message or
    /// signal arrives for this process, so the job can let it be handled.
    ///
    /// Port of erts/emulator/beam/erl_proc_sig_queue.c:8893 (dirty process signal
    /// handling): erts handles those signals on a system process while the dirty job runs.
    pub fn dirty_wait(&mut self, timeout: Duration) {
        self.flush_pending();
        if !self.input.has_pending() {
            thread::park_timeout(timeout);
        }
    }
    /// Run one copy of `work` on every scheduler at its next scheduling point.
    pub fn request_aux_work_all(&mut self, work: impl Fn(usize) + Send + Sync + 'static) {
        self.inner.request_aux_work_all(Arc::new(work));
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
    /// Detach pending input and receive the oldest event.
    pub fn receive(&mut self) -> Option<Event<M>> {
        self.inner.flush(self.remaining);
        if let Some(event) = self.private.pop() {
            self.consumed_event();
            return Some(event);
        }
        self.input.drain_into(self.private);
        let event = self.private.pop();
        if event.is_some() {
            self.consumed_event();
        }
        event
    }
    /// Fetch one available signal snapshot into the receiver's private queue.
    // Port of erts/emulator/beam/erl_proc_sig_queue.c:1332 (erts_proc_sig_fetch), OTP-29.1.1.
    pub fn fetch_pending(&mut self) -> bool {
        self.inner.flush(self.remaining);
        if self.input.has_pending() {
            self.input.drain_into(self.private);
        }
        self.private_wake = self.private.has_saved();
        self.private_wake
    }
    /// Consume one event from a snapshot already fetched by [`Self::fetch_pending`].
    pub fn receive_fetched(&mut self) -> Option<Event<M>> {
        let event = self.private.pop();
        if event.is_some() {
            self.consumed_event();
        }
        event
    }
    /// Consume the next event at the current selective receive save position.
    pub fn receive_saved(&mut self) -> Option<Event<M>> {
        let event = self.private.pop_saved();
        if event.is_some() {
            self.consumed_event();
        }
        self.private_wake = self.private.has_saved();
        event
    }
    /// Selectively remove an event after the save position.
    pub fn receive_matching(&mut self, matches: impl FnMut(&Event<M>) -> bool) -> Option<Event<M>> {
        self.inner.flush(self.remaining);
        self.private_wake = false;
        self.input.drain_into(self.private);
        let event = self.private.find_remove(matches);
        if event.is_some() {
            self.consumed_event();
        }
        event
    }
    /// Restart a selective receive scan after changing the pattern.
    pub fn reset_save(&mut self) {
        self.private.reset_save();
    }
    /// Reserve a receive marker after all currently published messages.
    pub fn recv_marker_reserve(&mut self) -> ReceiveMarker {
        self.inner.flush(self.remaining);
        self.input.drain_into(self.private);
        self.private.marker_reserve()
    }
    /// Bind a reserved marker to a VM-provided reference key.
    pub fn recv_marker_bind(&mut self, marker: ReceiveMarker, reference: u64) -> bool {
        self.private.marker_bind(marker, reference)
    }
    /// Start a selective scan at the bound marker, or at the head if it is absent.
    pub fn recv_marker_use(&mut self, reference: u64) -> bool {
        self.private.marker_use(reference)
    }
    /// Whether a fetched event remains before a receive marker.
    pub fn recv_marker_has_saved_before(&self, marker: ReceiveMarker) -> bool {
        self.private.marker_has_saved_before(marker)
    }
    /// Clear the marker bound to a VM-provided reference key.
    pub fn recv_marker_clear(&mut self, reference: u64) -> bool {
        self.private.marker_clear(reference)
    }
    /// Send an opaque envelope to another process.
    pub fn send(&mut self, to: Pid, msg: M) -> Result<(), Error> {
        if self
            .inner
            .deliver(self.pid, to, Payload::Message(msg), self.remaining)?
        {
            self.remaining = 0;
        }
        Ok(())
    }
    /// Send an ordered control signal.
    pub fn signal(&mut self, to: Pid, signal: Signal<M>) -> Result<(), Error> {
        if self
            .inner
            .deliver(self.pid, to, Payload::Signal(signal), self.remaining)?
        {
            self.remaining = 0;
        }
        Ok(())
    }
    /// Start an Erlang-style timer. The VM may wrap the received envelope as `{timeout, Ref, Msg}`.
    pub fn start_timer(&mut self, ms: u64, msg: M) -> Result<TimerRef, Error> {
        self.inner.flush(self.remaining);
        self.inner.start_timer(self.pid, self.pid, ms, msg, true)
    }
    /// Schedule a plain message without a timer-reference wrapper.
    pub fn send_after(&mut self, ms: u64, msg: M) -> Result<TimerRef, Error> {
        self.inner.flush(self.remaining);
        self.inner.start_timer(self.pid, self.pid, ms, msg, false)
    }
    /// Start a runtime timer callback owned by this process.
    /// Port of erts/emulator/beam/erl_hl_timer.c (erts_start_timer_callback), OTP-29.1.1.
    pub fn start_timer_callback(
        &mut self,
        ms: u64,
        callback: TimerCallback<M>,
    ) -> Result<TimerRef, Error> {
        self.inner.flush(self.remaining);
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
        self.inner.flush(self.remaining);
        self.inner.start_timer_to(pid, ms, msg, wrapped)
    }
    /// Port of erts/emulator/beam/erl_bif_info.c:5079-5091, OTP-29.1.1.
    /// Pause other running tasks until the callback returns.
    pub fn block_thread_progress(&mut self, duration: Duration) {
        self.inner.flush(self.remaining);
        if let Some(progress) = &mut self.progress {
            progress.block_for(duration);
        } else if !duration.is_zero() {
            thread::sleep(duration);
        }
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
            | Signal::PortExit { .. }
            | Signal::MonitorDown { .. }
            | Signal::MonitorNoproc(_)
            | Signal::GarbageCollect
            | Signal::LiteralAreaCopy { .. }
            | Signal::ProcSigBlock(_) => true,
            Signal::UnlinkAck(id) => *id != 0,
            Signal::Link
            | Signal::Unlink(_)
            | Signal::Monitor(_)
            | Signal::Demonitor(_)
            | Signal::Alias(_)
            | Signal::Unalias(_) => false,
        },
    }
}

fn take_lost_monitors<M>(events: &mut Vec<Event<M>>) -> Vec<(Pid, u64)> {
    events
        .drain(..)
        .filter_map(|event| match event.payload {
            Payload::Signal(Signal::Monitor(id)) => Some((event.from, id)),
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
    local: Option<&'a mut Local<T>>,
    pending_single: Option<PendingSingle<T>>,
    pending: BTreeMap<Pid, Vec<Event<T::Message>>>,
    pending_order: Vec<Pid>,
    /// Process monitor held until the next signal to that pid, or slice end.
    ///
    /// Port of erts/emulator/beam/erl_proc_sig_queue.c:1104 (pending process
    /// monitor), OTP-29.1.1. `gen_server:call` monitors and then sends; one
    /// publication wakes the server once.
    deferred_monitor: Option<(Pid, Event<T::Message>)>,
}

struct PendingSingle<T: Task> {
    to: Pid,
    process: Arc<Process<T>>,
    event: Event<T::Message>,
}

impl<T: Task> Runner<'_, T> {
    fn flush_target(&mut self, to: Pid, remaining: u32) {
        if self
            .pending_single
            .as_ref()
            .is_some_and(|pending| pending.to == to)
            && let Some(pending) = self.pending_single.take()
        {
            let _ = self.inner.deliver_single(
                pending.process,
                pending.event,
                self.local.as_deref_mut(),
                remaining,
            );
        }
        // A target that exited before publication must still produce DOWN
        // for monitors that were accepted into this buffer.
        let lost = {
            let Some(events) = self.pending.get_mut(&to) else {
                return;
            };
            if events.is_empty() {
                return;
            }
            if self
                .inner
                .deliver_block(
                    to,
                    events,
                    self.local.as_deref_mut(),
                    remaining,
                    true,
                    false,
                )
                .is_err()
            {
                take_lost_monitors(events)
            } else {
                Vec::new()
            }
        };
        if !lost.is_empty() {
            self.bounce_monitors(to, lost, remaining);
        }
    }

    fn bounce_monitors(&mut self, dead: Pid, lost: Vec<(Pid, u64)>, remaining: u32) {
        for (watcher, id) in lost {
            let _ = self.inner.deliver(
                dead,
                watcher,
                Payload::Signal(Signal::MonitorNoproc(id)),
                self.local.as_deref_mut(),
                remaining,
            );
        }
    }

    fn release_slabs(&mut self) {
        if let Some(local) = self.local.as_deref_mut() {
            for (_, mut slab) in std::mem::take(&mut self.pending) {
                slab.clear();
                if local.message_slabs.len() < 64 {
                    local.message_slabs.push(slab);
                }
            }
        }
    }
}
impl<T: Task> Runner<'_, T> {
    fn lookup(&mut self, pid: Pid) -> Option<Arc<Process<T>>> {
        if let Some(local) = self.local.as_deref_mut() {
            local.lookup(&self.inner.table, pid)
        } else {
            self.inner.table.lookup(pid)
        }
    }

    /// Publish a monitor that was accepted while its target was waiting.
    /// The monitor BIF has already returned, so a dead target must bounce DOWN.
    fn publish_deferred_monitor(&mut self, remaining: u32) {
        let Some((to, event)) = self.deferred_monitor.take() else {
            return;
        };
        let Event { from, payload } = event;
        let monitor_id = match payload {
            Payload::Signal(Signal::Monitor(id)) => Some(id),
            _ => None,
        };
        let Some(process) = self.lookup(to) else {
            if let Some(id) = monitor_id {
                self.bounce_monitors(to, vec![(from, id)], remaining);
            }
            return;
        };
        if self
            .inner
            .deliver_process(
                process,
                from,
                payload,
                self.local.as_deref_mut(),
                remaining,
                false,
                false,
            )
            .is_err()
            && let Some(id) = monitor_id
        {
            self.bounce_monitors(to, vec![(from, id)], remaining);
        }
    }
}

impl<T: Task> ContextOps<T::Message> for Runner<'_, T> {
    fn start_resolved_timer(
        &mut self,
        owner: Pid,
        ms: u64,
        resolve: Arc<dyn Fn() -> Option<Pid> + Send + Sync>,
        msg: T::Message,
        wrapped: bool,
    ) -> Result<TimerRef, Error> {
        self.inner
            .start_resolved_timer(owner, ms, resolve, msg, wrapped, self.local.as_deref_mut())
    }

    fn request_aux_work_all(&mut self, work: SchedulerAuxWork) {
        self.inner.request_aux_work_all(work);
    }

    fn cancel_target_timers(&mut self, pid: Pid) {
        if let Some(timers) = self.inner.sim_timers.as_ref() {
            for wheel in timers {
                wheel.lock().unwrap().cancel_target(pid);
            }
            return;
        }
        let current_worker = self.local.as_deref().map(|local| local.worker_id);
        if let Some(local) = self.local.as_deref_mut() {
            local.timer_service.borrow_mut().wheel.cancel_target(pid);
        }
        for worker in 0..self.inner.timer_commands.len() {
            if Some(worker) == current_worker {
                continue;
            }
            if let Some(service) = self.inner.owner_timer_service(worker) {
                service.borrow_mut().wheel.cancel_target(pid);
                continue;
            }
            let Some(queue) = self.inner.timer_commands.get(worker) else {
                continue;
            };
            queue.push(TimerCommand::CancelTarget { pid });
            self.inner.wake_worker(worker);
        }
    }

    fn cancel_pending_monitor(&mut self, to: Pid, reference: u64) -> bool {
        if self.deferred_monitor.as_ref().is_some_and(|(pid, event)| {
            *pid == to
                && matches!(&event.payload, Payload::Signal(Signal::Monitor(id)) if *id == reference)
        }) {
            // Port of erts/emulator/beam/erl_proc_sig_queue.c:1104
            // (pending process monitor), OTP-29.1.1. `demonitor([flush])`
            // consumes any possible DOWN, so this unpublished monitor has no
            // target-visible effect.
            self.deferred_monitor = None;
            true
        } else {
            false
        }
    }
    fn schedule_spawn(&mut self, pid: Pid) -> Result<(), Error> {
        let process = self.lookup(pid).ok_or(Error::NoProcess)?;
        process
            .state
            .compare_exchange(UNSCHEDULED, QUEUED, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| Error::NoProcess)?;
        let item = Scheduled {
            process: process.clone(),
            inherited: None,
        };
        if process.bound_worker().is_some() {
            self.inner.enqueue(item, false);
        } else if let Some(local) = self.local.as_deref_mut() {
            local.record_queued(&process, local.worker_id, false);
            local.push_next(item);
        } else {
            self.inner.enqueue(item, false);
        }
        Ok(())
    }
    fn deliver(
        &mut self,
        from: Pid,
        to: Pid,
        payload: Payload<T::Message>,
        remaining: u32,
    ) -> Result<bool, Error> {
        if self
            .deferred_monitor
            .as_ref()
            .is_some_and(|(pid, _)| *pid != to)
        {
            self.publish_deferred_monitor(remaining);
        }
        let monitor = matches!(payload, Payload::Signal(Signal::Monitor(_)));
        // A waiting process cannot exit until a waking signal arrives, so its
        // monitor can ride with the following send. A running process is
        // published now: it may exit before this slice ends.
        if monitor && self.deferred_monitor.is_none() && !self.pending.contains_key(&to) {
            let process = self.lookup(to).ok_or(Error::NoProcess)?;
            if process.state.load(Ordering::Acquire) == WAITING {
                if self
                    .pending_single
                    .as_ref()
                    .is_some_and(|pending| pending.to == to)
                {
                    self.flush_target(to, remaining);
                }
                if process.state.load(Ordering::Acquire) == WAITING {
                    self.deferred_monitor = Some((to, Event { from, payload }));
                    return Ok(false);
                }
            }
        }
        let deferred = if self
            .deferred_monitor
            .as_ref()
            .is_some_and(|(pid, _)| *pid == to)
        {
            self.deferred_monitor.take().map(|(_, event)| event)
        } else {
            None
        };
        let process = self.lookup(to).ok_or(Error::NoProcess)?;
        let waiting = process.state.load(Ordering::Acquire) == WAITING;
        let wakes = payload_wakes(&payload);
        let force_enqueue = matches!(&payload, Payload::Signal(Signal::LiteralAreaCopy { .. }));
        // A literal-copy request is never buffered: a request lost to an exiting target
        // would never be answered, so the sender must see `NoProcess` at once. Port of
        // erts/emulator/beam/erl_proc_sig_queue.c:3480 (erts_proc_sig_send_cla_request), OTP-29.1.1.
        if waiting || monitor || deferred.is_some() || force_enqueue {
            self.flush_target(to, remaining);
            if let Some(first) = deferred {
                let mut events = self
                    .local
                    .as_deref_mut()
                    .and_then(|local| local.message_slabs.pop())
                    .unwrap_or_else(|| Vec::with_capacity(2));
                events.push(first);
                events.push(Event { from, payload });
                let delivered = self.inner.deliver_block(
                    to,
                    &mut events,
                    self.local.as_deref_mut(),
                    remaining,
                    wakes,
                    force_enqueue,
                );
                let lost = if delivered.is_err() {
                    take_lost_monitors(&mut events)
                } else {
                    Vec::new()
                };
                events.clear();
                if let Some(local) = self.local.as_deref_mut()
                    && local.message_slabs.len() < 64
                {
                    local.message_slabs.push(events);
                }
                if delivered.is_err() {
                    self.bounce_monitors(to, lost, remaining);
                    return Err(Error::NoProcess);
                }
            } else {
                self.inner.deliver_process(
                    process,
                    from,
                    payload,
                    self.local.as_deref_mut(),
                    remaining,
                    wakes,
                    force_enqueue,
                )?;
            }
            // Port of erts/emulator/beam/erl_message.c:698 (erts_send_message), OTP-29.1.1.
            // Message queue depth does not create a scheduler event for the sender.
            return Ok(false);
        }
        let event = Event { from, payload };
        if self.pending.is_empty() {
            if let Some(pending) = self.pending_single.take() {
                if pending.to == to {
                    let mut events = self
                        .local
                        .as_deref_mut()
                        .and_then(|local| local.message_slabs.pop())
                        .unwrap_or_else(|| Vec::with_capacity(32));
                    events.push(pending.event);
                    events.push(event);
                    self.pending.insert(to, events);
                    self.pending_order.push(to);
                    return Ok(false);
                } else {
                    let _ = self.inner.deliver_single(
                        pending.process,
                        pending.event,
                        self.local.as_deref_mut(),
                        remaining,
                    );
                    self.pending_single = Some(PendingSingle { to, process, event });
                    return Ok(false);
                }
            } else {
                self.pending_single = Some(PendingSingle { to, process, event });
                return Ok(false);
            }
        } else if !self.pending.contains_key(&to) {
            let slab = self
                .local
                .as_deref_mut()
                .and_then(|local| local.message_slabs.pop())
                .unwrap_or_else(|| Vec::with_capacity(32));
            self.pending.insert(to, slab);
            self.pending_order.push(to);
        }
        let events = self
            .pending
            .get_mut(&to)
            .expect("pending block initialized");
        events.push(event);
        let buffered = events.len();
        if buffered == 32 {
            self.flush_target(to, remaining);
        }
        // Port of erts/emulator/beam/erl_message.c:698 (erts_send_message), OTP-29.1.1.
        // Sending does not consume the sender's remaining reductions based on receiver backlog.
        Ok(false)
    }
    fn flush(&mut self, remaining: u32) {
        if self.pending_single.is_none()
            && self.pending_order.is_empty()
            && self.deferred_monitor.is_none()
        {
            return;
        }
        self.publish_deferred_monitor(remaining);
        if let Some(pending) = self.pending_single.take() {
            let _ = self.inner.deliver_single(
                pending.process,
                pending.event,
                self.local.as_deref_mut(),
                remaining,
            );
        }
        let order = self.pending_order.clone();
        for to in order {
            let lost = {
                let events = self.pending.get_mut(&to).expect("pending target recorded");
                if events.is_empty() {
                    Vec::new()
                } else if self
                    .inner
                    .deliver_block(
                        to,
                        events,
                        self.local.as_deref_mut(),
                        remaining,
                        true,
                        false,
                    )
                    .is_err()
                {
                    take_lost_monitors(events)
                } else {
                    Vec::new()
                }
            };
            if !lost.is_empty() {
                self.bounce_monitors(to, lost, remaining);
            }
        }
    }
    fn total_reductions(&self) -> u64 {
        if self.inner.sim.is_some() {
            return self.inner.simulation_stats().reductions;
        }
        self.inner
            .scheduler_stats(self.local.as_deref(), 0)
            .reductions
    }
    fn scheduler_stats(&self) -> SchedulerStats {
        self.inner.scheduler_stats(self.local.as_deref(), 0)
    }
    fn set_msacc_state(&mut self, state: MsaccState) {
        if let Some(local) = self.local.as_deref_mut() {
            local.set_msacc_state(state);
        }
    }
    fn set_msacc_enabled(&mut self, enabled: bool) {
        if let Some(local) = self.local.as_deref_mut() {
            local.set_msacc_enabled(enabled);
        }
    }
    fn reclassify_gc_ns(&mut self, nanoseconds: u64) {
        if let Some(local) = self.local.as_deref_mut()
            && local.msacc_enabled
        {
            local.msacc_ns[MsaccState::Emulator as usize] =
                local.msacc_ns[MsaccState::Emulator as usize].saturating_sub(nanoseconds);
            local.msacc_ns[MsaccState::Gc as usize] =
                local.msacc_ns[MsaccState::Gc as usize].saturating_add(nanoseconds);
        }
    }
    fn set_wall_accounting_enabled(&mut self, enabled: bool) {
        if let Some(local) = self.local.as_deref_mut() {
            let _ = self.inner.take_wall_start(local.worker_id);
            local.set_wall_enabled(enabled);
        }
    }
    fn mark_exited(&mut self, pid: Pid) {
        if let Some(process) = self.inner.table.lookup(pid) {
            process.state.store(EXITED, Ordering::SeqCst);
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
            self.local.as_deref_mut(),
            None,
            true,
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
            self.local.as_deref_mut(),
            None,
            true,
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
            self.local.as_deref_mut(),
            None,
            true,
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
                timer_service: TimerService {
                    wheel: Wheel::new(now),
                    commands: timer_commands[worker_id].clone(),
                    canceled: canceled_timers[worker_id].clone(),
                },
                queues,
                runnext: None,
                streak: 0,
                normal_runs: 0,
                message_slabs: Vec::new(),
                pid_cache: Vec::new(),
                pending_waits: Vec::new(),
                check_time_reds: 0,
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
            table: ProcessTable::new(config.max_processes),
            config,
            names: Mutex::new(HashMap::new()),
            injectors: std::array::from_fn(|_| Injector::new()),
            pinned_injectors: (0..workers)
                .map(|_| std::array::from_fn(|_| SegQueue::new()))
                .collect(),
            stealers,
            sim_timers: simulated
                .then(|| (0..workers).map(|_| Mutex::new(Wheel::new(now))).collect()),
            timer_commands,
            canceled_timers,
            next_timer: AtomicU64::new(1),
            clock,
            sim: rng.map(|rng| {
                Mutex::new(SimState {
                    queue: VecDeque::new(),
                    rng,
                })
            }),
            stopped: AtomicBool::new(false),
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
            accounting_flags: AtomicU8::new(0),
            worker_counts: (0..workers)
                .map(|_| WorkerQueueCount(AtomicU64::new(0)))
                .collect(),
            online_schedulers: AtomicUsize::new(workers),
            scheduling_blocked: AtomicBool::new(false),
            scheduling_blocker: AtomicUsize::new(usize::MAX),
            next_queue: AtomicUsize::new(0),
            started_at: Instant::now(),
            wall_start_requests: Mutex::new(vec![None; workers]),
            work_epoch: AtomicU64::new(0),
            parked: (0..workers).map(|_| AtomicBool::new(false)).collect(),
            sleepers: (0..workers).map(|_| OnceLock::new()).collect(),
            next_sleeper: AtomicU32::new(0),
            fanin_stats: std::env::var_os("ARINSAL_FANIN_STATS").is_some(),
            fanin_delivered: AtomicU64::new(0),
            fanin_peak_backlog: AtomicUsize::new(0),
            progress: Arc::new(ThreadProgress::default()),
            dirty: [
                DirtyPool::new(dirty_cpu, 0),
                DirtyPool::new(dirty_io, dirty_cpu),
            ],
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
        let process = self.inner.table.insert(task, priority, None)?;
        process.state.store(UNSCHEDULED, Ordering::Release);
        Ok(process.pid)
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
        let worker = scheduler_id.checked_sub(1).ok_or(Error::Capacity)?;
        if worker >= self.inner.config.workers {
            return Err(Error::Capacity);
        }
        let process = self.inner.table.insert(task, priority, Some(worker))?;
        process.state.store(UNSCHEDULED, Ordering::Release);
        Ok(process.pid)
    }
    /// Make an inserted child runnable after its caller publishes it.
    pub fn schedule_unscheduled(&self, pid: Pid) -> Result<(), Error> {
        let process = self.inner.table.lookup(pid).ok_or(Error::NoProcess)?;
        process
            .state
            .compare_exchange(UNSCHEDULED, QUEUED, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| Error::NoProcess)?;
        self.inner.enqueue(
            Scheduled {
                process,
                inherited: None,
            },
            false,
        );
        Ok(())
    }
    /// Spawn a task at a chosen scheduler priority.
    pub fn spawn_priority(&self, task: T, priority: Priority) -> Result<Pid, Error> {
        let process = self.inner.table.insert(task, priority, None)?;
        let pid = process.pid;
        process.state.store(QUEUED, Ordering::Release);
        self.inner.enqueue(
            Scheduled {
                process,
                inherited: None,
            },
            false,
        );
        Ok(pid)
    }
    /// Queue a message from one logical sender.
    pub fn send(&self, from: Pid, to: Pid, msg: T::Message) -> Result<(), Error> {
        self.inner.deliver(from, to, Payload::Message(msg), None, 0)
    }
    /// Queue a signal in the same ordered stream.
    pub fn signal(&self, from: Pid, to: Pid, signal: Signal<T::Message>) -> Result<(), Error> {
        self.inner
            .deliver(from, to, Payload::Signal(signal), None, 0)
    }
    /// Run one copy of `work` on every scheduler at its next scheduling point.
    pub fn request_aux_work_all(&self, work: impl Fn(usize) + Send + Sync + 'static) {
        self.inner.request_aux_work_all(Arc::new(work));
    }
    /// Wake a task that is waiting without a mailbox event.
    pub fn wake(&self, pid: Pid) -> bool {
        self.inner.wake_waiting(pid)
    }
    /// Whether the task is queued on or executing on a dirty scheduler.
    ///
    /// Port of erts/emulator/beam/erl_process.h (`ERTS_PROC_IN_DIRTY_STATE`), OTP-29.1.1.
    pub fn is_executing_dirty(&self, pid: Pid) -> bool {
        self.inner.table.lookup(pid).is_some_and(|process| {
            process.dirty.load(Ordering::Acquire) != 0
                || process.dirty_runner.load(Ordering::Acquire) != 0
        })
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
        pool.ready.notify_all();
        true
    }
    /// Whether a pid currently identifies a live task.
    pub fn lookup(&self, pid: Pid) -> bool {
        self.inner.table.lookup(pid).is_some()
    }
    /// Inspect a task only while its scheduler state is `WAITING`.
    ///
    /// The task-cell mutex excludes worker execution while the callback reads
    /// task state; the state is checked again after acquiring that mutex.
    /// Inspect a waiting task while holding its scheduler-owned task cell.
    /// Port of erts/emulator/beam/erl_debugger.c:570-600, OTP-29.1.1.
    pub fn inspect_waiting<R>(&self, pid: Pid, inspect: impl FnOnce(&T) -> R) -> Option<R> {
        let process = self.inner.table.lookup(pid)?;
        if process.state.load(Ordering::Acquire) != WAITING {
            return None;
        }
        let cell = process.cell.lock().unwrap();
        (process.state.load(Ordering::Acquire) == WAITING).then(|| inspect(&cell.task))
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
        self.wake_all_workers();
    }

    /// Set the number of worker threads allowed to dispatch tasks.
    pub fn set_online_schedulers(&self, online: usize) -> bool {
        if online == 0 || online > self.inner.config.workers {
            return false;
        }
        self.inner
            .online_schedulers
            .store(online, Ordering::Release);
        self.wake_all_workers();
        true
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
        if !blocked {
            self.wake_all_workers();
        }
    }

    /// Pause normal-priority tasks while higher and lower priorities remain runnable.
    pub fn set_normal_scheduling_blocked(&self, blocked: bool) {
        self.set_scheduling_blocked(blocked, blocked.then_some(0));
    }

    fn wake_all_workers(&self) {
        self.inner.wake_all_workers();
    }

    /// Inspect or set the next free process table id for internal-state tests.
    ///
    /// Returns `None` when the process table has no available id.
    pub fn test_next_process_id(&self, set: bool, next_id: u32) -> Option<u32> {
        self.inner.table.test_next_id(set, next_id)
    }
    /// Register a local name for a live pid.
    pub fn register(&self, name: impl Into<String>, pid: Pid) -> Result<(), Error> {
        if !self.lookup(pid) {
            return Err(Error::NoProcess);
        }
        let mut names = self.inner.names.lock().unwrap();
        let name = name.into();
        if let Some(&existing) = names.get(&name)
            && self.lookup(existing)
        {
            return Err(Error::NameInUse);
        }
        names.insert(name, pid);
        Ok(())
    }
    /// Remove a previously registered local name.
    pub fn unregister(&self, name: &str) -> Option<Pid> {
        self.inner.names.lock().unwrap().remove(name)
    }
    /// Resolve a registered local name, discarding names for exited tasks.
    pub fn whereis(&self, name: &str) -> Option<Pid> {
        let mut names = self.inner.names.lock().unwrap();
        let pid = names.get(name).copied()?;
        if self.lookup(pid) {
            Some(pid)
        } else {
            names.remove(name);
            None
        }
    }
    /// Schedule an opaque envelope for future delivery.
    pub fn start_timer(&self, pid: Pid, ms: u64, msg: T::Message) -> Result<TimerRef, Error> {
        self.inner.start_timer(
            pid,
            ms,
            TimerPayload::Message(pid, msg, true),
            None,
            None,
            true,
        )
    }
    /// Schedule a plain message, as `send_after` does in OTP.
    pub fn send_after(&self, pid: Pid, ms: u64, msg: T::Message) -> Result<TimerRef, Error> {
        self.inner.start_timer(
            pid,
            ms,
            TimerPayload::Message(pid, msg, false),
            None,
            None,
            true,
        )
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
        let item = {
            let mut sim = sim.lock().unwrap();
            let len = sim.queue.len();
            if len == 0 {
                return false;
            }
            // Port of erts/emulator/beam/erl_process.c:9603 (priority queues), OTP-29.1.1:
            // max and high run before normal; normal and low share one class here.
            let class = |item: &Scheduled<T>| item.process.priority.index().min(2);
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
        run_one(&self.inner, item, None, None, dirty);
        true
    }
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod msgq_stage_microbench {
    use super::*;

    struct Idle;

    impl Task for Idle {
        type Message = usize;

        fn run(&mut self, _ctx: &mut RunCtx<'_, usize>, _budget: u32) -> RunOutcome {
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
        let table = ProcessTable::<Idle>::new(1);
        let process = table.insert(Idle, Priority::Normal, None).unwrap();
        let pid = process.pid;
        let started = Instant::now();
        for _ in 0..N {
            std::hint::black_box(table.lookup(pid));
        }
        report("lookup", N, started);

        let ingress = Incoming::default();
        let sender = Pid {
            index: 1,
            generation: 0,
        };
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

        let mut private = Private::default();
        let started = Instant::now();
        let fetched = ingress.drain_into(&mut private);
        assert_eq!(fetched, N);
        report("fetch batch", N, started);

        let started = Instant::now();
        for expected in 0..N {
            let event = private
                .find_remove(
                    |event| matches!(event.payload, Payload::Message(value) if value == expected),
                )
                .unwrap();
            std::hint::black_box(event);
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
            pending_single: None,
            pending: BTreeMap::new(),
            pending_order: Vec::new(),
            deferred_monitor: None,
        };
        let mut receive_private = Private::default();
        let backlog = AtomicUsize::new(N);
        let bound_worker = AtomicUsize::new(UNBOUND_WORKER);
        let mut context = RunCtx {
            inner: &mut receive_runner,
            pid: process,
            input: &input,
            private: &mut receive_private,
            backlog: &backlog,
            bound_worker: &bound_worker,
            worker: None,
            worker_count: scheduler.inner.config.workers,
            remaining: 1_000,
            budget: 1_000,
            private_wake: false,
            progress: None,
            msacc_enabled: false,
            wall_enabled: false,
            gc_accounted_total: 0,
            sched_type: SchedulerType::Normal,
        };
        let started = Instant::now();
        assert!(context.fetch_pending());
        for _ in 0..N {
            std::hint::black_box(context.receive_fetched().unwrap());
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
            process.state.store(WAITING, Ordering::SeqCst);
            scheduler
                .inner
                .wake_after_publish(process.clone(), None, 0, false);
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
        process.state.store(RUNNING, Ordering::Relaxed);
        process.backlog.store(257, Ordering::Relaxed);
        let mut runner = Runner {
            inner: &scheduler.inner,
            local: None,
            pending_single: None,
            pending: BTreeMap::new(),
            pending_order: Vec::new(),
            deferred_monitor: None,
        };
        let started = Instant::now();
        let mut pressured = 0;
        for message in 0..N {
            pressured += usize::from(
                <Runner<'_, Idle> as ContextOps<usize>>::deliver(
                    &mut runner,
                    from,
                    to,
                    Payload::Message(message),
                    1_000,
                )
                .unwrap(),
            );
        }
        runner.flush(1_000);
        report("runner delivery high backlog", N, started);
        println!("high backlog pressure returns: {pressured}/{N}");

        let scheduler = Scheduler::<Idle>::simulation(Config::default(), 4);
        let from = scheduler.spawn(Idle).unwrap();
        let to = scheduler.spawn(Idle).unwrap();
        let target = scheduler.inner.table.lookup(to).unwrap();
        target.state.store(RUNNING, Ordering::Relaxed);
        let mut private = Private::default();
        let started = Instant::now();
        for message in 0..N {
            let mut runner = Runner {
                inner: &scheduler.inner,
                local: None,
                pending_single: None,
                pending: BTreeMap::new(),
                pending_order: Vec::new(),
                deferred_monitor: None,
            };
            <Runner<'_, Idle> as ContextOps<usize>>::deliver(
                &mut runner,
                from,
                to,
                Payload::Message(message),
                1_000,
            )
            .unwrap();
            runner.flush(1_000);
            if message % 32 == 31 {
                target.input.drain_into(&mut private);
                while private.pop().is_some() {}
            }
        }
        target.input.drain_into(&mut private);
        while private.pop().is_some() {}
        report("one send per runner slice", N, started);
    }

    #[test]
    fn pending_single_preserves_order_and_wakes_only_once() {
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
        process.state.store(WAITING, Ordering::Relaxed);
        let mut runner = Runner {
            inner: &scheduler.inner,
            local: None,
            pending_single: None,
            pending: BTreeMap::new(),
            pending_order: Vec::new(),
            deferred_monitor: None,
        };
        for value in 1..=3 {
            <Runner<'_, Idle> as ContextOps<usize>>::deliver(
                &mut runner,
                from,
                to,
                Payload::Message(value),
                100,
            )
            .unwrap();
            if value == 1 {
                process.state.store(RUNNING, Ordering::Relaxed);
            }
        }
        runner.flush(100);
        let ready = scheduler.inner.sim.as_ref().unwrap().lock().unwrap();
        assert_eq!(ready.queue.len(), 1);
        drop(ready);
        let mut private = Private::default();
        process.input.drain_into(&mut private);
        let messages = (0..3)
            .map(|_| match private.pop().unwrap().payload {
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

        fn run(&mut self, ctx: &mut RunCtx<'_, ()>, _: u32) -> RunOutcome {
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
            .signal(
                Pid {
                    index: 7,
                    generation: 0,
                },
                child,
                Signal::Link,
            )
            .unwrap();

        assert!(!scheduler.step(), "setup signal scheduled the child");
        assert_eq!(observed.load(Ordering::Relaxed), 0);

        scheduler.schedule_unscheduled(child).unwrap();
        assert!(scheduler.step());
        assert_eq!(observed.load(Ordering::Relaxed), 1);
    }
}

#[cfg(test)]
mod offline_scheduler_tests {
    use super::*;

    struct YieldForever;

    impl Task for YieldForever {
        type Message = ();

        fn run(&mut self, _ctx: &mut RunCtx<'_, ()>, _budget: u32) -> RunOutcome {
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
            pool.ready.notify_all();
        }
        for handle in &self.threads {
            handle.thread().unpark();
        }
        // The last handle may drop on a worker (e.g. a process exiting while the owner already
        // released its handle); that worker cannot join itself and stops on its own.
        let current = std::thread::current().id();
        for handle in self.threads.drain(..) {
            if handle.thread().id() != current {
                let _ = handle.join();
            }
        }
        self.inner.table.scheduler_shutdown();
    }
}

fn run_one<'a, T: Task>(
    inner: &'a Inner<T>,
    item: Scheduled<T>,
    mut local: Option<&'a mut Local<T>>,
    worker: Option<usize>,
    dirty: Option<DirtyKind>,
) {
    let process = item.process;
    if process
        .state
        .compare_exchange(QUEUED, RUNNING, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return;
    }
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
    let budget = item
        .inherited
        .filter(|&n| n > 0)
        .unwrap_or(inner.config.reductions);
    // Port of erts/emulator/beam/erl_thr_progress.c: dirty schedulers are unmanaged threads
    // and never delay thread progress, OTP-29.1.1.
    let progress = dirty
        .is_none()
        .then(|| ThreadProgress::enter(Arc::clone(&inner.progress)));
    let accounting_flags = inner.accounting_flags.load(Ordering::Relaxed);
    let msacc_enabled = accounting_flags & ACCOUNTING_MSACC != 0;
    if let Some(local) = local.as_deref_mut() {
        local.set_msacc_enabled(msacc_enabled);
        let wall_enabled = accounting_flags & ACCOUNTING_WALL != 0;
        let started_at = (wall_enabled && !local.wall_enabled)
            .then(|| inner.take_wall_start(local.worker_id))
            .flatten();
        local.set_wall_enabled_at(wall_enabled, started_at);
    }
    let accounting_started = (accounting_flags & ACCOUNTING_WALL != 0).then(Instant::now);
    let mut cell = process.cell.lock().unwrap();
    let (outcome, remaining, private_pending, active_ns) = {
        let mut runner = Runner {
            inner,
            local: local.take(),
            pending_single: None,
            pending: BTreeMap::new(),
            pending_order: Vec::new(),
            deferred_monitor: None,
        };
        let result = {
            let TaskCell { task, private } = &mut *cell;
            let mut ctx = RunCtx {
                inner: &mut runner,
                pid: process.pid,
                input: &process.input,
                private,
                backlog: &process.backlog,
                bound_worker: &process.bound_worker,
                worker,
                worker_count: inner.config.workers,
                remaining: budget,
                budget,
                private_wake: true,
                progress,
                msacc_enabled,
                wall_enabled: accounting_flags & ACCOUNTING_WALL != 0,
                gc_accounted_total: if msacc_enabled {
                    task.gc_nanoseconds()
                } else {
                    0
                },
                sched_type: dirty.map_or(SchedulerType::Normal, SchedulerType::from),
            };
            if msacc_enabled {
                ctx.set_msacc_state(MsaccState::Emulator);
            }
            // The simulator runs dirty jobs on its own thread; report the job's scheduler type.
            let thread_type = SCHEDULER_TYPE.with(|current| current.replace(ctx.sched_type));
            let outcome = task.run(&mut ctx, budget);
            SCHEDULER_TYPE.with(|current| current.set(thread_type));
            if ctx.msacc_enabled {
                ctx.set_msacc_state(MsaccState::Other);
                ctx.account_gc_total(task.gc_nanoseconds());
            }
            let active_ns = accounting_started.map_or(0, |started| {
                started.elapsed().as_nanos().min(u64::MAX as u128) as u64
            });
            (
                outcome,
                ctx.remaining,
                ctx.private_wake && !ctx.private.is_empty(),
                active_ns,
            )
        };
        runner.flush(result.1);
        runner.release_slabs();
        local = runner.local.take();
        result
    };
    let consumed = u64::from(budget.saturating_sub(remaining));
    if dirty.is_some() {
        // Dirty schedulers keep no reduction or normal run queue counters.
    } else if let Some(local) = local.as_deref_mut() {
        local.reductions += consumed;
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
            process.state.store(QUEUED, Ordering::Release);
            inner.enqueue_dirty(process.clone(), kind);
        }
        RunOutcome::Yield if dirty.is_some() => {
            // Port of erts/emulator/beam/erl_process.c:10190 (a finished dirty job moves the
            // process back to a normal run queue), OTP-29.1.1.
            process.state.store(QUEUED, Ordering::Release);
            inner.enqueue(
                Scheduled {
                    process: process.clone(),
                    inherited: None,
                },
                false,
            );
        }
        RunOutcome::Yield => {
            process.state.store(QUEUED, Ordering::Release);
            let next = Scheduled {
                process: process.clone(),
                inherited: None,
            };
            if process.bound_worker().is_some() {
                inner.enqueue(next, true);
            } else if let Some(local) = local.as_deref_mut() {
                if inner.online_schedulers.load(Ordering::Acquire) == 1 {
                    inner.enqueue(next, true);
                } else {
                    local.record_queued(&next.process, local.worker_id, true);
                    local.queues[next.process.priority.index()].push(next);
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
            process.state.store(WAITING, Ordering::SeqCst);
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
                        .state
                        .compare_exchange(WAITING, QUEUED, Ordering::AcqRel, Ordering::Acquire)
                        .is_ok()
                    {
                        process.wait_epoch.fetch_add(1, Ordering::AcqRel);
                        let item = Scheduled {
                            process: process.clone(),
                            inherited: None,
                        };
                        inner.place_runnable(item, local.as_deref_mut());
                        return;
                    }
                } else if let Some(local) = local.as_deref_mut().filter(|_| worker.is_some()) {
                    // Arm the timeout locally. The wheel insert waits until this
                    // worker is about to park, or until the deadline is due.
                    let now = inner.clock.now_ms();
                    process
                        .wait_timer
                        .store(WAIT_TIMER_DEFERRED, Ordering::Release);
                    local.pending_waits.push(PendingWait {
                        process: process.clone(),
                        epoch,
                        deadline_ms: now.saturating_add(ms.max(1)),
                    });
                    if process.state.load(Ordering::Acquire) != WAITING
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
                    false,
                ) {
                    process
                        .wait_timer_worker
                        .store(reference.worker, Ordering::Relaxed);
                    process.wait_timer.store(reference.id, Ordering::Release);
                    if process.state.load(Ordering::Acquire) != WAITING
                        || process.wait_epoch.load(Ordering::Acquire) != epoch
                    {
                        inner.cancel_wait_timer(&process, reference.id);
                    }
                }
            }
            if (private_pending || process.input.has_pending())
                && process
                    .state
                    .compare_exchange(WAITING, QUEUED, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
            {
                process.wait_epoch.fetch_add(1, Ordering::AcqRel);
                let id = process.wait_timer.load(Ordering::Acquire);
                inner.cancel_wait_timer(&process, id);
                let next = Scheduled {
                    process: process.clone(),
                    inherited: Some(remaining),
                };
                inner.place_runnable(next, local.as_deref_mut());
            }
        }
        RunOutcome::Exit(_) => {
            process.state.store(EXITED, Ordering::SeqCst);
            if dirty.is_some() {
                // Already outside the normal run queue accounting.
            } else if let Some(local) = local.as_deref_mut() {
                local.record_waiting(&process);
            } else {
                inner.record_waiting(&process);
            }
            // Publishers that observed RUNNING still hold `publish_inflight`
            // until their push. Spin until that push is visible, then reap it.
            let mut spins = 0u32;
            loop {
                let mut private = Private::default();
                let n = process.input.drain_into(&mut private);
                if n > 0 {
                    let mut events = Vec::with_capacity(n);
                    while let Some(event) = private.pop() {
                        events.push(event);
                    }
                    cell.task.reap_signals(process.pid, events);
                    spins = 0;
                    continue;
                }
                if process.publish_inflight.load(Ordering::Acquire) == 0
                    && !process.input.has_pending()
                {
                    break;
                }
                spins += 1;
                if spins > 1_000_000 {
                    break;
                }
                std::hint::spin_loop();
            }
            inner.table.remove(process.pid);
        }
    }
    if let Some(local) = local {
        inner.flush_local_metrics(local);
    }
    drop(cell);
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

fn worker_loop<T: Task>(inner: Arc<Inner<T>>, id: usize, mut local: Local<T>) {
    inner.sleepers[id]
        .set(thread::current())
        .expect("worker registers once");
    let inner_id = Arc::as_ptr(&inner) as usize;
    OWNER_TIMER_SERVICES.with(|services| {
        services
            .borrow_mut()
            .insert(inner_id, (id, Box::new(local.timer_service.clone())));
    });
    let mut rng = SeededRng::new(id as u64 + 1);
    while !inner.stopped.load(Ordering::Acquire) {
        if halting() {
            // The halting scheduler terminates the OS process; the others stay idle.
            thread::park();
            continue;
        }
        let accounting_flags = inner.accounting_flags.load(Ordering::Relaxed);
        local.set_msacc_enabled(accounting_flags & ACCOUNTING_MSACC != 0);
        let wall_enabled = accounting_flags & ACCOUNTING_WALL != 0;
        let started_at = (wall_enabled && !local.wall_enabled)
            .then(|| inner.take_wall_start(id))
            .flatten();
        local.set_wall_enabled_at(wall_enabled, started_at);
        local.set_msacc_state(MsaccState::Other);
        while let Some(reply) = inner.stats_requests[id].pop() {
            let _ = reply.send(local.stats_snapshot(local.msacc_enabled, local.wall_enabled));
        }
        local.set_msacc_state(MsaccState::Aux);
        inner.handle_local_aux_work(id, &mut local);
        local.set_msacc_state(MsaccState::Other);
        if id >= inner.online_schedulers.load(Ordering::Acquire)
            || (inner.scheduling_blocked.load(Ordering::Acquire)
                && id != inner.scheduling_blocker.load(Ordering::Acquire))
        {
            // An offline or blocked scheduler hands its queued work and due timers to the
            // schedulers still running.
            inner.poll_timers(id, Some(&mut local), true);
            inner.poll_pending_waits(&mut local);
            inner.evacuate_offline_local(&mut local);
            local.set_wall_enabled(false);
            local.set_msacc_state(MsaccState::Sleep);
            inner.parked[id].store(true, Ordering::SeqCst);
            let has_local_timers =
                !local.pending_waits.is_empty() || local.timer_service.borrow().wheel.has_timers();
            if has_local_timers {
                thread::park_timeout(Duration::from_millis(10));
            } else {
                thread::park();
            }
            inner.parked[id].store(false, Ordering::SeqCst);
            continue;
        }
        // Port of erts/emulator/beam/erl_process.c:2683 (auxiliary work), OTP-29.1.1.
        local.set_msacc_state(MsaccState::Aux);
        inner.poll_timers(id, Some(&mut local), false);
        inner.poll_pending_waits(&mut local);
        local.set_msacc_state(MsaccState::Other);
        inner.flush_local_metrics(&mut local);
        let mut item = None;
        for priority in local.order() {
            item = inner.pinned_injectors[id][priority].pop();
            if item.is_some() {
                break;
            }
        }
        // Port of erts/emulator/beam/erl_process.c (run queue priorities), OTP-29.1.1: work queued
        // from elsewhere joins this worker's queue before local work of a lower or equal
        // priority runs again, so a worker busy with yielding processes cannot starve it.
        if item.is_none()
            && let Some(best) = local.best_priority()
        {
            // A low-priority item may jump ahead of normal work once eight normal quanta ran.
            let limit = if best == 2 && local.normal_runs >= 8 {
                3
            } else {
                best
            };
            for priority in local
                .order()
                .into_iter()
                .filter(|&priority| priority <= limit)
            {
                if let Steal::Success(found) =
                    inner.injectors[priority].steal_batch_and_pop(&local.queues[priority])
                {
                    local.picked(priority);
                    item = Some(found);
                    break;
                }
            }
        }
        if item.is_none() {
            item = local.pop(inner.config.runnext_limit);
        }
        if item.is_none()
            && local.runnext.is_some()
            && inner.injectors.iter().all(Injector::is_empty)
        {
            local.streak = 1;
            item = local.runnext.take();
        }
        if item.is_none() {
            for priority in local.order() {
                if let Steal::Success(found) =
                    inner.injectors[priority].steal_batch_and_pop(&local.queues[priority])
                {
                    local.picked(priority);
                    item = Some(found);
                    break;
                }
            }
        }
        if item.is_none() {
            let limit = inner.config.workers.div_ceil(2) as u32;
            if inner.searching.fetch_add(1, Ordering::AcqRel) < limit {
                let len = inner.stealers.len();
                let right = (id + 1) % len;
                let left = (id + len - 1) % len;
                let start = rng.next_u64() as usize % len;
                let victims = [right, left].into_iter().chain(
                    (0..len)
                        .map(|offset| (start + offset) % len)
                        .filter(|&victim| victim != id && victim != right && victim != left),
                );
                for victim in victims {
                    if victim == id {
                        continue;
                    }
                    for priority in local.order() {
                        if let Steal::Success(found) = inner.stealers[victim][priority]
                            .steal_batch_and_pop(&local.queues[priority])
                        {
                            local.picked(priority);
                            item = Some(found);
                            break;
                        }
                    }
                    if item.is_some() {
                        break;
                    }
                }
            }
            inner.searching.fetch_sub(1, Ordering::AcqRel);
        }
        if item.is_none() {
            item = local.pop(inner.config.runnext_limit);
        }
        if let Some(item) = item {
            if !local.profile_active {
                let count = inner.active_schedulers.fetch_add(1, Ordering::Relaxed) + 1;
                local.profile_active = true;
                profile_scheduler_transition(&inner, &item.process, id, true, count, &mut local);
            }
            local.last_process = Some(item.process.clone());
            run_one(&inner, item, Some(&mut local), Some(id), None);
            continue;
        }
        // A worker advertises parking before its final work check. An enqueuer
        // publishes to the injector, advances work_epoch, then wakes one
        // advertised worker. The SeqCst order makes either this check observe
        // the publication or the enqueuer observe our parked flag.
        let observed = inner.work_epoch.load(Ordering::SeqCst);
        inner.parked[id].store(true, Ordering::SeqCst);
        local.set_msacc_state(MsaccState::Aux);
        inner.poll_pending_waits(&mut local);
        inner.poll_timers(id, Some(&mut local), true);
        local.set_msacc_state(MsaccState::Other);
        if local.runnext.as_ref().is_some()
            || local.queues.iter().any(|queue| !queue.is_empty())
            || inner.injectors.iter().any(|queue| !queue.is_empty())
            || !local.timer_service.borrow().commands.is_empty()
            || !local.timer_service.borrow().canceled.is_empty()
            || inner.work_epoch.load(Ordering::SeqCst) != observed
        {
            inner.parked[id].store(false, Ordering::SeqCst);
            continue;
        }
        if local.profile_active {
            let count = inner.active_schedulers.fetch_sub(1, Ordering::Relaxed) - 1;
            local.profile_active = false;
            if let Some(process) = local.last_process.clone() {
                profile_scheduler_transition(&inner, &process, id, false, count, &mut local);
            }
        }
        let wheel_armed = {
            let service = local.timer_service.borrow();
            service.wheel.has_timers()
                || !service.commands.is_empty()
                || !service.canceled.is_empty()
        };
        let wait_ms = inner.nearest_wait_ms(&local);
        local.set_msacc_state(MsaccState::Sleep);
        local.set_wall_enabled(false);
        if wheel_armed {
            // The wheel is polled on a 1 ms cadence.
            thread::park_timeout(Duration::from_millis(1));
        } else if let Some(ms) = wait_ms {
            thread::park_timeout(Duration::from_millis(ms.max(1)));
        } else {
            thread::park();
        }
        inner.parked[id].store(false, Ordering::SeqCst);
    }
    OWNER_TIMER_SERVICES.with(|services| {
        services.borrow_mut().remove(&inner_id);
    });
}

/// Main loop of one dirty scheduler thread.
///
/// Port of erts/emulator/beam/erl_process.c:9600 (erts_schedule for dirty schedulers) and
/// erl_process.c:3404 (scheduler_wait on a dirty run queue), OTP-29.1.1.
fn dirty_scheduler_loop<T: Task>(inner: Arc<Inner<T>>, kind: DirtyKind, index: usize) {
    SCHEDULER_TYPE.with(|current| current.set(kind.into()));
    let pool = &inner.dirty[kind.index()];
    let thread = &pool.threads[index];
    let slot = pool.first_slot + index;
    let _ = thread.handle.set(thread::current());
    thread
        .stats
        .lock()
        .unwrap()
        .set_state(MsaccState::Sleep, inner.msacc_accounting());
    loop {
        let process = {
            let mut queue = pool.queue.lock().unwrap();
            loop {
                if inner.stopped.load(Ordering::Acquire) || halting() {
                    return;
                }
                if index < pool.online.load(Ordering::Acquire)
                    && queue.len != 0
                    && let Some(process) =
                        queue.by_priority.iter_mut().find_map(VecDeque::pop_front)
                {
                    queue.len -= 1;
                    break process;
                }
                queue = pool
                    .ready
                    .wait_timeout(queue, Duration::from_millis(100))
                    .unwrap()
                    .0;
            }
        };
        thread
            .stats
            .lock()
            .unwrap()
            .begin_active(inner.msacc_accounting());
        process.dirty_runner.store(slot + 1, Ordering::SeqCst);
        run_one(
            &inner,
            Scheduled {
                process: process.clone(),
                inherited: None,
            },
            None,
            None,
            Some(kind),
        );
        process.dirty_runner.store(0, Ordering::SeqCst);
        let msacc = inner.msacc_accounting();
        let mut stats = thread.stats.lock().unwrap();
        stats.end_active(msacc);
        stats.set_state(MsaccState::Sleep, msacc);
    }
}

fn profile_scheduler_transition<T: Task>(
    inner: &Inner<T>,
    process: &Arc<Process<T>>,
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
    let Some((target, message)) = process.cell.lock().unwrap().task.scheduler_profile_event(
        process.pid,
        scheduler_id as u32 + 1,
        active,
        active_schedulers as u32,
    ) else {
        return;
    };
    let _ = inner.deliver(
        process.pid,
        target,
        Payload::Message(message),
        Some(local),
        0,
    );
}
