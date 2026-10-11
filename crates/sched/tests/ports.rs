//! Ports on the normal run queues: execution between processes, re-enqueue while active,
//! reduction accounting, stealing by idle schedulers and evacuation of offline run queues
//! (erl_port_task.c erts_port_task_execute, erl_process.c schedule/try_steal_task).

use arinsal_sched::{
    Config, PortExecution, PortRunQueue, RunCtx, RunOutcome, RunPort, Scheduler, Task,
    current_normal_scheduler,
};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// A port that stays active for `rounds` executions and records where it ran.
struct TestPort {
    runq: PortRunQueue,
    rounds: AtomicU32,
    executions: AtomicU32,
    schedulers: Mutex<Vec<usize>>,
    /// Block the executing scheduler until released.
    hold: AtomicBool,
}

impl TestPort {
    fn new(runq: usize, rounds: u32) -> Arc<Self> {
        Arc::new(Self {
            runq: PortRunQueue::new(runq),
            rounds: AtomicU32::new(rounds),
            executions: AtomicU32::new(0),
            schedulers: Mutex::new(Vec::new()),
            hold: AtomicBool::new(false),
        })
    }
}

impl RunPort for TestPort {
    fn run_queue(&self) -> &PortRunQueue {
        &self.runq
    }

    fn execute(&self) -> PortExecution {
        self.executions.fetch_add(1, Ordering::SeqCst);
        self.schedulers
            .lock()
            .unwrap()
            .push(current_normal_scheduler().unwrap_or(usize::MAX));
        while self.hold.load(Ordering::SeqCst) {
            std::thread::yield_now();
        }
        let left = self.rounds.fetch_sub(1, Ordering::SeqCst) - 1;
        PortExecution {
            active: left > 0,
            reds: 1000,
        }
    }
}

struct Idle;

impl Task for Idle {
    type Message = ();
    type SchedulerData = ();
    fn run(&mut self, _: &mut RunCtx<()>, _: &mut (), _: u32) -> RunOutcome {
        RunOutcome::Exit(0)
    }
}

/// Burns its budget until stopped.
struct Busy(Arc<AtomicBool>, Arc<AtomicUsize>);

impl Task for Busy {
    type Message = ();
    type SchedulerData = ();
    fn run(&mut self, ctx: &mut RunCtx<()>, _: &mut (), _: u32) -> RunOutcome {
        if self.0.load(Ordering::Relaxed) {
            return RunOutcome::Exit(0);
        }
        self.1
            .store(ctx.scheduler_id().unwrap_or(usize::MAX), Ordering::Relaxed);
        while ctx.consume(100) {}
        RunOutcome::Yield
    }
}

fn wait_for(what: &str, mut done: impl FnMut() -> bool) {
    let started = Instant::now();
    while !done() {
        assert!(
            started.elapsed() < Duration::from_secs(20),
            "timeout: {what}"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
}

#[test]
fn active_port_runs_until_out_of_tasks_and_counts_reductions() {
    let scheduler = Scheduler::<Idle>::new(Config {
        workers: 2,
        ..Config::default()
    });
    let before = scheduler.stats().reductions;
    let port = TestPort::new(1, 5);
    scheduler.enqueue_port(port.clone());
    wait_for("five executions", || {
        port.executions.load(Ordering::SeqCst) == 5
    });
    std::thread::sleep(Duration::from_millis(20));
    assert_eq!(port.executions.load(Ordering::SeqCst), 5);
    assert!(scheduler.stats().reductions >= before + 5000);
}

#[test]
fn queued_ports_count_in_run_queue_lengths() {
    let scheduler = Scheduler::<Idle>::simulation(Config::default(), 7);
    let ports: Vec<_> = (0..3).map(|_| TestPort::new(0, 2)).collect();
    for port in &ports {
        scheduler.enqueue_port(port.clone());
    }
    assert_eq!(scheduler.stats().run_queue_lengths[0], 3);
    // FIFO: each port runs once, then goes back to the end while still active.
    for _ in 0..3 {
        assert!(scheduler.step());
    }
    assert!(
        ports
            .iter()
            .all(|port| port.executions.load(Ordering::SeqCst) == 1)
    );
    assert_eq!(scheduler.stats().run_queue_lengths[0], 3);
    for _ in 0..3 {
        assert!(scheduler.step());
    }
    assert_eq!(scheduler.stats().run_queue_lengths[0], 0);
    assert!(!scheduler.step());
    assert!(scheduler.stats().reductions >= 6000);
}

#[test]
fn idle_scheduler_steals_a_port() {
    let scheduler = Scheduler::<Idle>::new(Config {
        workers: 2,
        ..Config::default()
    });
    // Occupy one scheduler with a port so its other port can only run elsewhere.
    let blocker = TestPort::new(0, 1);
    blocker.hold.store(true, Ordering::SeqCst);
    scheduler.enqueue_port(blocker.clone());
    wait_for("blocker running", || {
        blocker.executions.load(Ordering::SeqCst) == 1
    });
    // An idle scheduler may already have stolen the blocker itself.
    let busy = blocker.schedulers.lock().unwrap()[0];
    let idle = 1 - busy;
    let stolen = TestPort::new(busy, 1);
    scheduler.enqueue_port(stolen.clone());
    // The idle scheduler runs out of work after this port and steals before it sleeps.
    let trigger = TestPort::new(idle, 1);
    scheduler.enqueue_port(trigger.clone());
    wait_for("stolen port executed", || {
        stolen.executions.load(Ordering::SeqCst) == 1
    });
    blocker.hold.store(false, Ordering::SeqCst);
    assert_eq!(*stolen.schedulers.lock().unwrap(), vec![idle]);
    assert_eq!(stolen.runq.get(), idle);
}

#[test]
fn offline_run_queue_evacuates_its_ports() {
    let scheduler = Scheduler::<Busy>::new(Config {
        workers: 2,
        ..Config::default()
    });
    assert!(scheduler.set_online_schedulers(1));
    let stop = Arc::new(AtomicBool::new(false));
    let seen = Arc::new(AtomicUsize::new(usize::MAX));
    scheduler
        .spawn(Busy(stop.clone(), seen.clone()))
        .expect("spawn");
    let port = TestPort::new(1, 3);
    scheduler.enqueue_port(port.clone());
    wait_for("port executed", || {
        port.executions.load(Ordering::SeqCst) == 3
    });
    stop.store(true, Ordering::Relaxed);
    assert!(port.schedulers.lock().unwrap().iter().all(|&ix| ix == 0));
}
