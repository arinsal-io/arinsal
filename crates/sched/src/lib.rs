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
use std::sync::{Arc, Mutex, OnceLock};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
use timer::{CanceledTimer, TimerCommand, TimerPayload, Wheel};

type ErasedTimerService = (usize, Box<dyn Any>);

thread_local! {
    static OWNER_TIMER_SERVICES: RefCell<HashMap<usize, ErasedTimerService>> = RefCell::new(HashMap::new());
}

const QUEUED: u8 = 0;
/// Receive timeout armed on this worker, not yet inserted in the timer wheel.
const WAIT_TIMER_DEFERRED: u64 = u64::MAX;
const RUNNING: u8 = 1;
const WAITING: u8 = 2;
const EXITED: u8 = 3;
const PID_LIMIT: u32 = 1 << 28;
const PID_PAGE_SIZE: usize = 1024;

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
    /// Monitor DOWN signal carrying an opaque reason envelope.
    MonitorDown { reference: u64, reason: M },
    /// Alias activation.
    Alias(u64),
    /// Alias deactivation.
    Unalias(u64),
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
}

/// A VM process or a benchmark dummy task.
pub trait Task: Send + 'static {
    /// Opaque message envelope owned by the receiving process.
    type Message: Send + 'static;
    /// Execute cooperatively, consuming at most `budget` reductions.
    fn run(&mut self, ctx: &mut RunCtx<Self::Message>, budget: u32) -> RunOutcome;
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
}

impl Default for Config {
    fn default() -> Self {
        let available = thread::available_parallelism().map_or(1, |n| n.get());
        Self {
            workers: available.max(1),
            max_processes: 1_048_576,
            reductions: 4_000,
            runnext_limit: 3,
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
        self.0.elapsed().as_millis() as u64
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
    bound_worker: Option<usize>,
    state: AtomicU8,
    wait_epoch: AtomicU64,
    timer_epoch_used: AtomicBool,
    wait_timer: AtomicU64,
    input: Incoming<Event<T::Message>>,
    backlog: AtomicUsize,
    /// Publishers between the EXITED check and the mailbox push.
    publish_inflight: AtomicUsize,
    /// Wheel that owns `wait_timer`, so cancel does not guess from the pid.
    wait_timer_worker: AtomicUsize,
    cell: Mutex<TaskCell<T>>,
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
            bound_worker,
            state: AtomicU8::new(QUEUED),
            wait_epoch: AtomicU64::new(0),
            timer_epoch_used: AtomicBool::new(false),
            wait_timer: AtomicU64::new(0),
            input: Incoming::default(),
            backlog: AtomicUsize::new(0),
            publish_inflight: AtomicUsize::new(0),
            wait_timer_worker: AtomicUsize::new(0),
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
        }
    }
}
struct SimState<T: Task> {
    queue: VecDeque<Scheduled<T>>,
    rng: Box<dyn Rng>,
}

struct Inner<T: Task> {
    config: Config,
    table: ProcessTable<T>,
    names: Mutex<HashMap<String, Pid>>,
    injectors: [Injector<Scheduled<T>>; 4],
    pinned_injectors: Vec<SegQueue<Scheduled<T>>>,
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
    work_epoch: AtomicU64,
    parked: Vec<AtomicBool>,
    sleepers: Vec<OnceLock<thread::Thread>>,
    next_sleeper: AtomicU32,
    fanin_stats: bool,
    fanin_delivered: AtomicU64,
    fanin_peak_backlog: AtomicUsize,
}

impl<T: Task> Inner<T> {
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

    fn enqueue(&self, item: Scheduled<T>) {
        if let Some(sim) = &self.sim {
            sim.lock().unwrap().queue.push_back(item);
        } else if let Some(worker) = item.process.bound_worker {
            self.pinned_injectors[worker].push(item);
            self.work_epoch.fetch_add(1, Ordering::SeqCst);
            self.wake_worker(worker);
        } else {
            self.injectors[item.process.priority.index()].push(item);
            // Publish the queue change before a parker's final epoch check.
            self.work_epoch.fetch_add(1, Ordering::SeqCst);
            self.wake_one();
        }
    }

    fn wake_one(&self) {
        let start =
            self.next_sleeper.fetch_add(1, Ordering::Relaxed) as usize % self.sleepers.len();
        for offset in 0..self.sleepers.len() {
            let index = (start + offset) % self.sleepers.len();
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
        let counted = process.state.load(Ordering::Acquire) != WAITING;
        if counted {
            process.backlog.fetch_add(1, Ordering::Relaxed);
        }
        self.fanin_delivery(&process, 1);
        if let Err(error) =
            self.deliver_process(process.clone(), from, payload, local, remaining, true)
        {
            if counted {
                process.backlog.fetch_sub(1, Ordering::Relaxed);
            }
            return Err(error);
        }
        Ok(())
    }

    fn deliver_process(
        &self,
        process: Arc<Process<T>>,
        from: Pid,
        payload: Payload<T::Message>,
        local: Option<&mut Local<T>>,
        remaining: u32,
        wake: bool,
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
            self.wake_after_publish(process.clone(), local, remaining);
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
            self.wake_after_publish(process.clone(), local, remaining);
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
        self.wake_after_publish(process.clone(), local, remaining);
        process.publish_inflight.fetch_sub(1, Ordering::Release);
        // Port of erts/emulator/beam/erl_proc_sig_queue.c:712 (signal enqueue), OTP-29.1.1.
        Ok(())
    }

    fn wake_after_publish(
        &self,
        process: Arc<Process<T>>,
        local: Option<&mut Local<T>>,
        remaining: u32,
    ) {
        let wait_timer = process.wait_timer.load(Ordering::Acquire);
        if process
            .state
            .compare_exchange(WAITING, QUEUED, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            if wait_timer != 0 {
                process.wait_epoch.fetch_add(1, Ordering::AcqRel);
                self.cancel_wait_timer(&process, wait_timer);
            }
            let item = Scheduled {
                process,
                inherited: Some(remaining),
            };
            self.place_runnable(item, local);
        }
    }

    /// Same-worker waiters stay on `runnext`. A cross-thread unpark costs more
    /// than a local ping-pong, so the peer runs here before this worker parks.
    fn place_runnable(&self, item: Scheduled<T>, local: Option<&mut Local<T>>) {
        if item.process.bound_worker.is_some() {
            self.enqueue(item);
            return;
        }
        if let Some(local) = local {
            local.push_next(item);
            return;
        }
        self.enqueue(item);
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
                wheel.lock().unwrap().cancel(id);
            }
        } else if let Some(queue) = self.canceled_timers.get(worker) {
            queue.push(CanceledTimer { id, reply: None });
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
                TimerCommand::Read { id, reply } => {
                    let _ = reply.send(service.wheel.remaining(id));
                }
            }
        }
        let canceled_queue = service.canceled.clone();
        while let Some(canceled) = canceled_queue.pop() {
            let remaining = service
                .wheel
                .cancel(canceled.id)
                .map(|(remaining, _)| remaining);
            if let Some(reply) = canceled.reply {
                let _ = reply.send(remaining);
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
                    Payload::Message(message)
                };
                let _ = self.deliver(pid, pid, payload, local, 0);
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
                .cancel(reference.id)
                .map(|x| x.0);
        }
        if let Some(service) = self.owner_timer_service(reference.worker) {
            return service
                .borrow_mut()
                .wheel
                .cancel(reference.id)
                .map(|(remaining, _)| remaining);
        }
        let queue = self.canceled_timers.get(reference.worker)?;
        let (reply, receiver) = mpsc::sync_channel(0);
        queue.push(CanceledTimer {
            id: reference.id,
            reply: Some(reply),
        });
        self.wake_worker(reference.worker);
        receiver.recv().ok().flatten()
    }

    fn read_timer(&self, reference: TimerRef) -> Option<u64> {
        if let Some(timers) = self.sim_timers.as_ref() {
            self.poll_timers(reference.worker, None, true);
            return timers
                .get(reference.worker)?
                .lock()
                .unwrap()
                .remaining(reference.id);
        }
        if let Some(service) = self.owner_timer_service(reference.worker) {
            return service.borrow().wheel.remaining(reference.id);
        }
        let queue = self.timer_commands.get(reference.worker)?;
        let (reply, receiver) = mpsc::sync_channel(0);
        queue.push(TimerCommand::Read {
            id: reference.id,
            reply,
        });
        self.wake_worker(reference.worker);
        receiver.recv().ok().flatten()
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
}
impl<T: Task> Local<T> {
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
        if priority == 2 {
            self.normal_runs = self.normal_runs.saturating_add(1);
        } else if priority == 3 {
            self.normal_runs = 0;
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
pub struct RunCtx<'a, M: Send + 'static> {
    inner: &'a mut dyn ContextOps<M>,
    pid: Pid,
    input: &'a Incoming<Event<M>>,
    private: &'a mut Private<Event<M>>,
    backlog: &'a AtomicUsize,
    remaining: u32,
    private_wake: bool,
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
    fn start_timer(&mut self, pid: Pid, ms: u64, msg: M, wrapped: bool) -> Result<TimerRef, Error>;
    fn mark_exited(&mut self, pid: Pid);
    fn schedule_spawn(&mut self, pid: Pid) -> Result<(), Error>;
    fn cancel_pending_monitor(&mut self, to: Pid, reference: u64) -> bool;
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
    /// Reject further mailbox publishes. In-flight publishers still land and
    /// are drained before the pid leaves the process table.
    pub fn begin_exit(&mut self) {
        self.inner.mark_exited(self.pid);
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
    /// Remaining reductions in this quantum.
    pub fn remaining(&self) -> u32 {
        self.remaining
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
        !self.private.is_empty()
    }
    /// Consume one event from a snapshot already fetched by [`Self::fetch_pending`].
    pub fn receive_fetched(&mut self) -> Option<Event<M>> {
        let event = self.private.pop();
        if event.is_some() {
            self.consumed_event();
        }
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
        self.inner.start_timer(self.pid, ms, msg, true)
    }
    /// Schedule a plain message without a timer-reference wrapper.
    pub fn send_after(&mut self, ms: u64, msg: M) -> Result<TimerRef, Error> {
        self.inner.flush(self.remaining);
        self.inner.start_timer(self.pid, ms, msg, false)
    }
}

/// Messages, exits, and DOWNs require the receiver to run. Link, monitor, and
/// demonitor only update control state and are applied the next time the
/// receiver is scheduled, including on exit.
fn payload_wakes<M>(payload: &Payload<M>) -> bool {
    match payload {
        Payload::Message(_) | Payload::Timer { .. } => true,
        Payload::Signal(signal) => match signal {
            Signal::Exit(_) | Signal::MonitorDown { .. } | Signal::MonitorNoproc(_) => true,
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
                .deliver_block(to, events, self.local.as_deref_mut(), remaining, true)
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
            )
            .is_err()
            && let Some(id) = monitor_id
        {
            self.bounce_monitors(to, vec![(from, id)], remaining);
        }
    }
}

impl<T: Task> ContextOps<T::Message> for Runner<'_, T> {
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
        let item = Scheduled {
            process: process.clone(),
            inherited: None,
        };
        if process.bound_worker.is_some() {
            self.inner.enqueue(item);
        } else if let Some(local) = self.local.as_deref_mut() {
            local.push_next(item);
        } else {
            self.inner.enqueue(item);
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
        if waiting || monitor || deferred.is_some() {
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
                    .deliver_block(to, events, self.local.as_deref_mut(), remaining, true)
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
    fn mark_exited(&mut self, pid: Pid) {
        if let Some(process) = self.inner.table.lookup(pid) {
            process.state.store(EXITED, Ordering::SeqCst);
        }
    }
    fn start_timer(
        &mut self,
        pid: Pid,
        ms: u64,
        msg: T::Message,
        wrapped: bool,
    ) -> Result<TimerRef, Error> {
        // Message timers may belong to another worker; receive timeouts do not
        // use this path.
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
            });
        }
        let inner = Arc::new(Inner {
            table: ProcessTable::new(config.max_processes),
            config,
            names: Mutex::new(HashMap::new()),
            injectors: std::array::from_fn(|_| Injector::new()),
            pinned_injectors: (0..workers).map(|_| SegQueue::new()).collect(),
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
            work_epoch: AtomicU64::new(0),
            parked: (0..workers).map(|_| AtomicBool::new(false)).collect(),
            sleepers: (0..workers).map(|_| OnceLock::new()).collect(),
            next_sleeper: AtomicU32::new(0),
            fanin_stats: std::env::var_os("ARINSAL_FANIN_STATS").is_some(),
            fanin_delivered: AtomicU64::new(0),
            fanin_peak_backlog: AtomicUsize::new(0),
        });
        let mut threads = Vec::new();
        if !simulated {
            for (id, local) in locals.into_iter().enumerate() {
                let inner = inner.clone();
                threads.push(thread::spawn(move || {
                    worker_loop(inner, id, local.into_local())
                }));
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
        self.inner
            .table
            .insert(task, Priority::Normal, None)
            .map(|process| process.pid)
    }
    /// Insert a child whose caller publishes it on a one-based scheduler id.
    pub fn spawn_unscheduled_on(&self, task: T, scheduler_id: usize) -> Result<Pid, Error> {
        let worker = scheduler_id.checked_sub(1).ok_or(Error::Capacity)?;
        if worker >= self.inner.config.workers {
            return Err(Error::Capacity);
        }
        self.inner
            .table
            .insert(task, Priority::Normal, Some(worker))
            .map(|process| process.pid)
    }
    /// Spawn a task at a chosen scheduler priority.
    pub fn spawn_priority(&self, task: T, priority: Priority) -> Result<Pid, Error> {
        let process = self.inner.table.insert(task, priority, None)?;
        let pid = process.pid;
        self.inner.enqueue(Scheduled {
            process,
            inherited: None,
        });
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
    /// Read remaining milliseconds, or `None` if fired or cancelled.
    pub fn read_timer(&self, reference: TimerRef) -> Option<u64> {
        self.inner.read_timer(reference)
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
        self.inner.poll_timers(0, None, true);
        let item = {
            let mut sim = sim.lock().unwrap();
            let len = sim.queue.len();
            if len == 0 {
                return false;
            }
            let index = sim.rng.next_u64() as usize % len;
            sim.queue.remove(index).unwrap()
        };
        run_one(&self.inner, item, None, None);
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
        let mut context = RunCtx {
            inner: &mut receive_runner,
            pid: process,
            input: &input,
            private: &mut receive_private,
            backlog: &backlog,
            remaining: 1_000,
            private_wake: false,
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
            scheduler.inner.wake_after_publish(process.clone(), None, 0);
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

impl<T: Task> Drop for Scheduler<T> {
    fn drop(&mut self) {
        self.inner.stopped.store(true, Ordering::Release);
        for handle in &self.threads {
            handle.thread().unpark();
        }
        for handle in self.threads.drain(..) {
            let _ = handle.join();
        }
    }
}

fn run_one<'a, T: Task>(
    inner: &'a Inner<T>,
    item: Scheduled<T>,
    mut local: Option<&'a mut Local<T>>,
    worker: Option<usize>,
) {
    let process = item.process;
    if process
        .state
        .compare_exchange(QUEUED, RUNNING, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return;
    }
    let budget = item
        .inherited
        .filter(|&n| n > 0)
        .unwrap_or(inner.config.reductions);
    let mut cell = process.cell.lock().unwrap();
    let (outcome, remaining, private_pending) = {
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
                remaining: budget,
                private_wake: true,
            };
            let outcome = task.run(&mut ctx, budget);
            (
                outcome,
                ctx.remaining,
                ctx.private_wake && !ctx.private.is_empty(),
            )
        };
        runner.flush(result.1);
        runner.release_slabs();
        local = runner.local.take();
        result
    };
    if let Some(local) = local.as_deref_mut() {
        local.check_time_reds = local
            .check_time_reds
            .saturating_add(budget.saturating_sub(remaining));
    }
    match outcome {
        RunOutcome::Yield => {
            process.state.store(QUEUED, Ordering::Release);
            let next = Scheduled {
                process: process.clone(),
                inherited: None,
            };
            if process.bound_worker.is_some() {
                inner.enqueue(next);
            } else if let Some(local) = local.as_deref_mut() {
                local.queues[next.process.priority.index()].push(next);
            } else {
                inner.enqueue(next);
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
                inner.place_runnable(next, local);
            }
        }
        RunOutcome::Exit(_) => {
            process.state.store(EXITED, Ordering::SeqCst);
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
    drop(cell);
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
        inner.poll_timers(id, Some(&mut local), false);
        inner.poll_pending_waits(&mut local);
        let mut item = inner.pinned_injectors[id].pop();
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
            run_one(&inner, item, Some(&mut local), Some(id));
            continue;
        }
        // A worker advertises parking before its final work check. An enqueuer
        // publishes to the injector, advances work_epoch, then wakes one
        // advertised worker. The SeqCst order makes either this check observe
        // the publication or the enqueuer observe our parked flag.
        let observed = inner.work_epoch.load(Ordering::SeqCst);
        inner.parked[id].store(true, Ordering::SeqCst);
        inner.poll_pending_waits(&mut local);
        inner.poll_timers(id, Some(&mut local), true);
        if local.runnext.is_some()
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

fn profile_scheduler_transition<T: Task>(
    inner: &Inner<T>,
    process: &Arc<Process<T>>,
    scheduler_id: usize,
    active: bool,
    active_schedulers: usize,
    local: &mut Local<T>,
) {
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
