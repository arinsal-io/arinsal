use arinsal_sched::{Config, Event, Payload, Pid, RunCtx, RunOutcome, Scheduler, Signal, Task};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

type Recorded = (Pid, Pid, u32, bool);
struct Collector {
    output: Arc<Mutex<Vec<Recorded>>>,
}
impl Task for Collector {
    type Message = u32;
    fn run(&mut self, ctx: &mut RunCtx<u32>, _: u32) -> RunOutcome {
        while let Some(Event { from, payload }) = ctx.receive() {
            let entry = match payload {
                Payload::Message(n) => (ctx.pid(), from, n, false),
                Payload::Signal(Signal::Unlink(n)) => (ctx.pid(), from, n as u32, true),
                _ => panic!("unexpected signal"),
            };
            self.output.lock().unwrap().push(entry);
        }
        RunOutcome::Wait { timeout_ms: None }
    }
}

#[test]
fn seeded_ordering_across_messages_and_signals() {
    for seed in 0..64 {
        let config = Config {
            workers: 1,
            max_processes: 64,
            ..Config::default()
        };
        let sched = Scheduler::simulation(config, seed);
        let output = Arc::new(Mutex::new(Vec::new()));
        let receivers: Vec<_> = (0..4)
            .map(|_| {
                sched
                    .spawn(Collector {
                        output: output.clone(),
                    })
                    .unwrap()
            })
            .collect();
        let senders: Vec<_> = (0..8)
            .map(|_| {
                sched
                    .spawn(Collector {
                        output: output.clone(),
                    })
                    .unwrap()
            })
            .collect();
        let mut expected = vec![vec![Vec::new(); 8]; 4];
        let mut x = seed.wrapping_add(1);
        for sequence in 0..200 {
            x = x.wrapping_mul(6364136223846793005).wrapping_add(1);
            let r = ((x >> 32) as usize) % 4;
            let s = ((x >> 40) as usize) % 8;
            let signal = x & 1 == 0;
            if signal {
                sched
                    .signal(senders[s], receivers[r], Signal::Unlink(sequence))
                    .unwrap();
            } else {
                sched
                    .send(senders[s], receivers[r], sequence as u32)
                    .unwrap();
            }
            expected[r][s].push((sequence as u32, signal));
            if x & 15 == 0 {
                for _ in 0..3 {
                    sched.step();
                }
            }
        }
        while sched.step() {}
        let actual = output.lock().unwrap();
        for (r, receiver) in receivers.iter().enumerate() {
            for (s, sender) in senders.iter().enumerate() {
                let found: Vec<_> = actual
                    .iter()
                    .filter(|entry| entry.0 == *receiver && entry.1 == *sender)
                    .map(|entry| (entry.2, entry.3))
                    .collect();
                assert_eq!(
                    found, expected[r][s],
                    "seed={seed}, receiver={r}, sender={s}"
                );
            }
        }
    }
}

struct CountTask(Arc<AtomicUsize>);
impl Task for CountTask {
    type Message = ();
    fn run(&mut self, ctx: &mut RunCtx<()>, _: u32) -> RunOutcome {
        while ctx.receive().is_some() {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
        RunOutcome::Wait { timeout_ms: None }
    }
}

#[test]
fn million_tasks_ten_workers_no_lost_wakeup() {
    let counter = Arc::new(AtomicUsize::new(0));
    let sched = Scheduler::new(Config {
        workers: 10,
        max_processes: 1_000_000,
        ..Config::default()
    });
    let mut pids = Vec::with_capacity(1_000_000);
    for _ in 0..1_000_000 {
        pids.push(sched.spawn(CountTask(counter.clone())).unwrap());
    }
    let sends = 40_000;
    std::thread::scope(|scope| {
        for worker in 0..10 {
            let sched = &sched;
            let pids = &pids;
            scope.spawn(move || {
                let mut x = worker as u64 + 1;
                for _ in 0..sends / 10 {
                    x = x.wrapping_mul(6364136223846793005).wrapping_add(1);
                    let to = pids[(x as usize) % pids.len()];
                    sched.send(pids[worker], to, ()).unwrap();
                }
            });
        }
    });
    let deadline = Instant::now() + Duration::from_secs(90);
    while counter.load(Ordering::Relaxed) < sends && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(counter.load(Ordering::Relaxed), sends);
}

struct SchedulingProbe {
    active: Arc<AtomicUsize>,
    peak: Arc<AtomicUsize>,
    release: Arc<AtomicBool>,
    complete: Arc<AtomicUsize>,
}
impl Task for SchedulingProbe {
    type Message = ();
    fn run(&mut self, _ctx: &mut RunCtx<()>, _budget: u32) -> RunOutcome {
        let active = self.active.fetch_add(1, Ordering::AcqRel) + 1;
        self.peak.fetch_max(active, Ordering::AcqRel);
        while !self.release.load(Ordering::Acquire) {
            std::thread::yield_now();
        }
        self.active.fetch_sub(1, Ordering::AcqRel);
        self.complete.fetch_add(1, Ordering::Release);
        RunOutcome::Exit(0)
    }
}

struct PriorityCounter {
    count: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
}
impl Task for PriorityCounter {
    type Message = ();
    fn run(&mut self, _ctx: &mut RunCtx<()>, _budget: u32) -> RunOutcome {
        if self.stop.load(Ordering::Acquire) {
            return RunOutcome::Exit(0);
        }
        self.count.fetch_add(1, Ordering::Relaxed);
        RunOutcome::Yield
    }
}

#[test]
fn block_normal_limits_execution_to_one_normal_scheduler() {
    let scheduler = Scheduler::new(Config {
        workers: 2,
        max_processes: 16,
        ..Config::default()
    });
    let active = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));
    let release = Arc::new(AtomicBool::new(false));
    let complete = Arc::new(AtomicUsize::new(0));
    scheduler.set_normal_scheduling_blocked(true);
    scheduler
        .spawn_priority(
            SchedulingProbe {
                active: active.clone(),
                peak: peak.clone(),
                release: release.clone(),
                complete: complete.clone(),
            },
            arinsal_sched::Priority::Normal,
        )
        .unwrap();
    scheduler
        .spawn_priority(
            SchedulingProbe {
                active: active.clone(),
                peak: peak.clone(),
                release: release.clone(),
                complete: complete.clone(),
            },
            arinsal_sched::Priority::High,
        )
        .unwrap();

    let deadline = Instant::now() + Duration::from_secs(2);
    while active.load(Ordering::Acquire) == 0 && Instant::now() < deadline {
        std::thread::yield_now();
    }
    assert_eq!(active.load(Ordering::Acquire), 1);
    std::thread::sleep(Duration::from_millis(25));
    assert_eq!(peak.load(Ordering::Acquire), 1);

    release.store(true, Ordering::Release);
    scheduler.set_normal_scheduling_blocked(false);
    let deadline = Instant::now() + Duration::from_secs(2);
    while complete.load(Ordering::Acquire) < 2 && Instant::now() < deadline {
        std::thread::yield_now();
    }
    assert_eq!(complete.load(Ordering::Acquire), 2);
}

#[test]
fn low_priority_gets_one_quantum_per_eight_normal_quanta() {
    let scheduler = Scheduler::new(Config {
        workers: 2,
        max_processes: 16,
        ..Config::default()
    });
    let normal = Arc::new(AtomicUsize::new(0));
    let low = Arc::new(AtomicUsize::new(0));
    let stop = Arc::new(AtomicBool::new(false));
    scheduler.set_normal_scheduling_blocked(true);
    scheduler
        .spawn_priority(
            PriorityCounter {
                count: normal.clone(),
                stop: stop.clone(),
            },
            arinsal_sched::Priority::Normal,
        )
        .unwrap();
    scheduler
        .spawn_priority(
            PriorityCounter {
                count: low.clone(),
                stop: stop.clone(),
            },
            arinsal_sched::Priority::Low,
        )
        .unwrap();
    std::thread::sleep(Duration::from_millis(250));
    stop.store(true, Ordering::Release);
    scheduler.set_normal_scheduling_blocked(false);

    let normal = normal.load(Ordering::Relaxed) as f64;
    let low = low.load(Ordering::Relaxed) as f64;
    let low_share = low / (normal + low);
    assert!(
        low_share > 1.0 / 16.0 && low_share < 1.0 / 4.0,
        "low_share={low_share}; normal={normal}; low={low}"
    );
}

#[test]
fn hot_mailbox_repeated_waits_do_not_lose_wakes() {
    struct One(Arc<AtomicUsize>);
    impl Task for One {
        type Message = ();
        fn run(&mut self, ctx: &mut RunCtx<()>, _: u32) -> RunOutcome {
            if ctx.receive().is_some() {
                self.0.fetch_add(1, Ordering::Relaxed);
            }
            RunOutcome::Wait { timeout_ms: None }
        }
    }
    let count = Arc::new(AtomicUsize::new(0));
    let sched = Scheduler::new(Config {
        workers: 4,
        max_processes: 1,
        ..Config::default()
    });
    let pid = sched.spawn(One(count.clone())).unwrap();
    std::thread::scope(|scope| {
        for _ in 0..4 {
            let sched = &sched;
            scope.spawn(move || {
                for _ in 0..25_000 {
                    sched.send(pid, pid, ()).unwrap();
                }
            });
        }
    });
    let deadline = Instant::now() + Duration::from_secs(15);
    while count.load(Ordering::Relaxed) < 100_000 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(count.load(Ordering::Relaxed), 100_000);
}

#[test]
fn worker_blocks_preserve_sender_message_signal_order() {
    enum Work {
        Producer(Pid),
        Sink(Arc<Mutex<Vec<(Pid, u32)>>>),
    }
    impl Task for Work {
        type Message = u32;
        fn run(&mut self, ctx: &mut RunCtx<u32>, _: u32) -> RunOutcome {
            match self {
                Work::Producer(to) => {
                    for sequence in 0..1_000 {
                        if sequence % 2 == 0 {
                            ctx.send(*to, sequence).unwrap();
                        } else {
                            ctx.signal(*to, Signal::Unlink(sequence as u64)).unwrap();
                        }
                    }
                    RunOutcome::Exit(0)
                }
                Work::Sink(output) => {
                    while let Some(event) = ctx.receive() {
                        let sequence = match event.payload {
                            Payload::Message(value) => value,
                            Payload::Signal(Signal::Unlink(value)) => value as u32,
                            _ => panic!("unexpected event"),
                        };
                        output.lock().unwrap().push((event.from, sequence));
                    }
                    RunOutcome::Wait { timeout_ms: None }
                }
            }
        }
    }
    let output = Arc::new(Mutex::new(Vec::new()));
    let sched = Scheduler::new(Config {
        workers: 4,
        max_processes: 5,
        ..Config::default()
    });
    let sink = sched.spawn(Work::Sink(output.clone())).unwrap();
    let producers: Vec<_> = (0..4)
        .map(|_| sched.spawn(Work::Producer(sink)).unwrap())
        .collect();
    let deadline = Instant::now() + Duration::from_secs(10);
    while output.lock().unwrap().len() < 4_000 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(1));
    }
    let output = output.lock().unwrap();
    assert_eq!(output.len(), 4_000);
    for producer in producers {
        let found: Vec<_> = output
            .iter()
            .filter(|entry| entry.0 == producer)
            .map(|entry| entry.1)
            .collect();
        assert_eq!(found, (0..1_000).collect::<Vec<_>>());
    }
}

#[test]
fn bounded_runnext_gives_external_work_a_turn() {
    enum Work {
        Ping(Pid, Arc<AtomicUsize>),
        Observe(Arc<AtomicUsize>, Arc<AtomicUsize>),
    }
    const LIMIT: usize = 1_000_000;
    impl Task for Work {
        type Message = ();
        fn run(&mut self, ctx: &mut RunCtx<()>, _: u32) -> RunOutcome {
            match self {
                Work::Ping(to, count) => {
                    if ctx.receive().is_some() {
                        let value = count.fetch_add(1, Ordering::Relaxed) + 1;
                        if value < LIMIT {
                            ctx.send(*to, ()).unwrap();
                        }
                    }
                    RunOutcome::Wait { timeout_ms: None }
                }
                Work::Observe(count, observed) => {
                    observed.store(count.load(Ordering::Relaxed), Ordering::Release);
                    RunOutcome::Exit(0)
                }
            }
        }
    }
    let count = Arc::new(AtomicUsize::new(0));
    let observed = Arc::new(AtomicUsize::new(usize::MAX));
    let sched = Scheduler::new(Config {
        workers: 1,
        max_processes: 3,
        runnext_limit: 3,
        ..Config::default()
    });
    let first = Pid {
        index: 0,
        generation: 0,
    };
    let second = Pid {
        index: 1,
        generation: 0,
    };
    assert_eq!(
        sched.spawn(Work::Ping(second, count.clone())).unwrap(),
        first
    );
    assert_eq!(
        sched.spawn(Work::Ping(first, count.clone())).unwrap(),
        second
    );
    sched.send(first, first, ()).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while count.load(Ordering::Relaxed) < 100 && Instant::now() < deadline {
        std::thread::yield_now();
    }
    assert!(count.load(Ordering::Relaxed) >= 100);
    sched
        .spawn(Work::Observe(count.clone(), observed.clone()))
        .unwrap();
    while observed.load(Ordering::Acquire) == usize::MAX && Instant::now() < deadline {
        std::thread::yield_now();
    }
    assert!(observed.load(Ordering::Acquire) < LIMIT);
}

#[test]
fn pid_generation_and_timer_firing() {
    struct Exit;
    impl Task for Exit {
        type Message = ();
        fn run(&mut self, _: &mut RunCtx<()>, _: u32) -> RunOutcome {
            RunOutcome::Exit(0)
        }
    }
    let sched = Scheduler::simulation(
        Config {
            max_processes: 1,
            ..Config::default()
        },
        1,
    );
    let first = sched.spawn(Exit).unwrap();
    assert!(sched.step());
    assert!(!sched.lookup(first));
    let second = sched.spawn(Exit).unwrap();
    assert_eq!(first.index, second.index);
    assert_ne!(first.generation, second.generation);
    assert_eq!(Pid::from_term(second.to_term().unwrap()), Some(second));

    let counter = Arc::new(AtomicUsize::new(0));
    let sched = Scheduler::simulation(
        Config {
            max_processes: 2,
            ..Config::default()
        },
        2,
    );
    let pid = sched.spawn(CountTask(counter.clone())).unwrap();
    sched.step();
    let first = sched.start_timer(pid, 10, ()).unwrap();
    let cancelled = sched.start_timer(pid, 20, ()).unwrap();
    assert_eq!(sched.cancel_timer(cancelled), Some(20));
    sched.advance_ms(10).unwrap();
    assert_eq!(sched.cancel_timer(first), None);
    while sched.step() {}
    assert_eq!(counter.load(Ordering::Relaxed), 1);
}

#[test]
fn timer_envelope_and_wait_timeout_cancellation() {
    struct Timed {
        runs: Arc<AtomicUsize>,
        received: Arc<Mutex<Vec<&'static str>>>,
    }
    impl Task for Timed {
        type Message = ();
        fn run(&mut self, ctx: &mut RunCtx<()>, _: u32) -> RunOutcome {
            let n = self.runs.fetch_add(1, Ordering::Relaxed);
            while let Some(event) = ctx.receive() {
                let kind = match event.payload {
                    Payload::Message(()) => "plain",
                    Payload::Timer {
                        reference,
                        message: (),
                    } if reference.id() > 0 => "timer",
                    Payload::TimerMessage {
                        reference,
                        message: (),
                    } if reference.id() > 0 => "plain",
                    _ => panic!("unexpected event"),
                };
                self.received.lock().unwrap().push(kind);
            }
            RunOutcome::Wait {
                timeout_ms: (n == 0).then_some(100),
            }
        }
    }
    let sched = Scheduler::simulation(
        Config {
            max_processes: 1,
            ..Config::default()
        },
        13,
    );
    let runs = Arc::new(AtomicUsize::new(0));
    let received = Arc::new(Mutex::new(Vec::new()));
    let pid = sched
        .spawn(Timed {
            runs: runs.clone(),
            received: received.clone(),
        })
        .unwrap();
    sched.step();
    sched.send(pid, pid, ()).unwrap();
    sched.step();
    assert_eq!(runs.load(Ordering::Relaxed), 2);
    sched.advance_ms(100).unwrap();
    assert!(!sched.step());
    assert_eq!(runs.load(Ordering::Relaxed), 2);
    sched.start_timer(pid, 1, ()).unwrap();
    sched.send_after(pid, 1, ()).unwrap();
    sched.advance_ms(1).unwrap();
    while sched.step() {}
    assert_eq!(*received.lock().unwrap(), ["plain", "timer", "plain"]);
    let immediate = sched.start_timer(pid, 0, ()).unwrap();
    assert_eq!(sched.read_timer(immediate), None);
    assert_eq!(sched.cancel_timer(immediate), None);
    let plain = sched.send_after(pid, 0, ()).unwrap();
    assert_eq!(sched.read_timer(plain), None);
    while sched.step() {}
    assert_eq!(
        *received.lock().unwrap(),
        ["plain", "timer", "plain", "timer", "plain"]
    );
}

#[test]
fn timer_after_long_idle_uses_current_clock() {
    let counter = Arc::new(AtomicUsize::new(0));
    let sched = Scheduler::simulation(
        Config {
            max_processes: 1,
            ..Config::default()
        },
        31,
    );
    let pid = sched.spawn(CountTask(counter.clone())).unwrap();
    assert!(sched.step());
    sched.advance_ms(100_000).unwrap();
    sched.start_timer(pid, 10, ()).unwrap();
    sched.advance_ms(10).unwrap();
    while sched.step() {}
    assert_eq!(counter.load(Ordering::Relaxed), 1);
}

#[test]
fn threaded_timer_wakes_its_assigned_worker() {
    let count = Arc::new(AtomicUsize::new(0));
    let sched = Scheduler::new(Config {
        workers: 4,
        max_processes: 4,
        ..Config::default()
    });
    let pids: Vec<_> = (0..4)
        .map(|_| sched.spawn(CountTask(count.clone())).unwrap())
        .collect();
    sched.start_timer(pids[3], 20, ()).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while count.load(Ordering::Relaxed) == 0 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(count.load(Ordering::Relaxed), 1);
}

#[test]
fn simulation_seed_replays_dispatch_order() {
    struct Record(Arc<Mutex<Vec<u32>>>);
    impl Task for Record {
        type Message = ();
        fn run(&mut self, ctx: &mut RunCtx<()>, _: u32) -> RunOutcome {
            self.0.lock().unwrap().push(ctx.pid().index);
            RunOutcome::Exit(0)
        }
    }
    let trace = |seed| {
        let output = Arc::new(Mutex::new(Vec::new()));
        let sched = Scheduler::simulation(
            Config {
                max_processes: 20,
                ..Config::default()
            },
            seed,
        );
        for _ in 0..20 {
            sched.spawn(Record(output.clone())).unwrap();
        }
        while sched.step() {}
        let result = output.lock().unwrap().clone();
        drop(sched);
        result
    };
    assert_eq!(trace(9), trace(9));
    assert_ne!(trace(9), trace(10));
}

#[test]
fn simulation_replays_batched_multi_recipient_delivery() {
    enum Work {
        Sink(Arc<Mutex<Vec<(u32, u32)>>>),
        Sender(Vec<Pid>),
    }
    impl Task for Work {
        type Message = u32;
        fn run(&mut self, ctx: &mut RunCtx<u32>, _: u32) -> RunOutcome {
            match self {
                Work::Sink(output) => {
                    while let Some(event) = ctx.receive() {
                        if let Payload::Message(value) = event.payload {
                            output.lock().unwrap().push((ctx.pid().index, value));
                        }
                    }
                    RunOutcome::Wait { timeout_ms: None }
                }
                Work::Sender(targets) => {
                    for value in 0..90 {
                        ctx.send(targets[value as usize % targets.len()], value)
                            .unwrap();
                    }
                    RunOutcome::Exit(0)
                }
            }
        }
    }
    let run = || {
        let scheduler = Scheduler::simulation(
            Config {
                max_processes: 4,
                ..Config::default()
            },
            51,
        );
        let output = Arc::new(Mutex::new(Vec::new()));
        let targets: Vec<_> = (0..3)
            .map(|_| scheduler.spawn(Work::Sink(output.clone())).unwrap())
            .collect();
        scheduler.spawn(Work::Sender(targets)).unwrap();
        while scheduler.step() {}
        output.lock().unwrap().clone()
    };
    let first = run();
    assert_eq!(first.len(), 90);
    for _ in 0..20 {
        assert_eq!(run(), first);
    }
}

/// One scheduler blocks thread progress while another collects scheduler statistics,
/// which waits for every other scheduler. The collector must not hold thread progress
/// while it waits, or both schedulers wait for each other forever.
struct ProgressRacer {
    blocker: bool,
    rounds: Arc<AtomicUsize>,
    bound: bool,
}

impl Task for ProgressRacer {
    type Message = u32;
    fn run(&mut self, ctx: &mut RunCtx<u32>, _: u32) -> RunOutcome {
        if !self.bound {
            self.bound = true;
            ctx.bind_scheduler(if self.blocker { 1 } else { 2 });
            return RunOutcome::Yield;
        }
        for _ in 0..50 {
            if self.blocker {
                ctx.block_thread_progress(Duration::ZERO);
            } else {
                let _ = ctx.scheduler_stats();
            }
        }
        if self.rounds.fetch_add(1, Ordering::AcqRel) + 1 >= 400 {
            RunOutcome::Exit(0)
        } else {
            RunOutcome::Yield
        }
    }
}

#[test]
fn thread_progress_block_and_statistics_do_not_deadlock() {
    let sched = Scheduler::new(Config {
        workers: 2,
        max_processes: 16,
        ..Config::default()
    });
    let blocker_rounds = Arc::new(AtomicUsize::new(0));
    let stats_rounds = Arc::new(AtomicUsize::new(0));
    for (blocker, rounds) in [(true, &blocker_rounds), (false, &stats_rounds)] {
        sched
            .spawn(ProgressRacer {
                blocker,
                rounds: Arc::clone(rounds),
                bound: false,
            })
            .unwrap();
    }
    let deadline = Instant::now() + Duration::from_secs(20);
    while blocker_rounds.load(Ordering::Acquire) < 400 || stats_rounds.load(Ordering::Acquire) < 400
    {
        if Instant::now() >= deadline {
            let rounds = (
                blocker_rounds.load(Ordering::Acquire),
                stats_rounds.load(Ordering::Acquire),
            );
            // Deadlocked workers never finish, so dropping the scheduler would hang too.
            std::mem::forget(sched);
            panic!("thread progress deadlock after (blocker, stats) rounds {rounds:?}");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}
