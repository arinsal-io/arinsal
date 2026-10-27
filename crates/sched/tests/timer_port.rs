use arinsal_sched::{Config, Payload, RunCtx, RunOutcome, Scheduler, Task};
use std::sync::{Arc, Mutex, OnceLock, Weak, mpsc};
use std::thread;
use std::time::{Duration, Instant};

struct Sink(Arc<Mutex<Vec<u64>>>);

impl Task for Sink {
    type Message = u64;
    type SchedulerData = ();

    fn run(&mut self, ctx: &mut RunCtx<u64>, _: &mut (), _: u32) -> RunOutcome {
        while let Some(event) = ctx.receive() {
            match event.payload {
                Payload::Timer { message, .. } => self.0.lock().unwrap().push(*message),
                Payload::Message(message) => self.0.lock().unwrap().push(message),
                _ => unreachable!(),
            }
        }
        RunOutcome::Wait { timeout_ms: None }
    }
}

fn simulation() -> (Scheduler<Sink>, arinsal_sched::Pid, Arc<Mutex<Vec<u64>>>) {
    let scheduler = Scheduler::simulation(
        Config {
            max_processes: 1,
            ..Config::default()
        },
        1,
    );
    let output = Arc::new(Mutex::new(Vec::new()));
    let pid = scheduler.spawn(Sink(output.clone())).unwrap();
    scheduler.step();
    (scheduler, pid, output)
}

#[test]
fn soon_wheel_expiry_order() {
    let (scheduler, pid, output) = simulation();
    scheduler.start_timer(pid, 3, 3).unwrap();
    scheduler.start_timer(pid, 1, 1).unwrap();
    scheduler.start_timer(pid, 2, 2).unwrap();
    scheduler.advance_ms(3).unwrap();
    while scheduler.step() {}
    assert_eq!(*output.lock().unwrap(), [1, 2, 3]);
}

#[test]
fn later_wheel_cascade() {
    let (scheduler, pid, output) = simulation();
    let timer = scheduler.start_timer(pid, 20_000, 7).unwrap();
    scheduler.advance_ms(8_192).unwrap();
    scheduler.advance_ms(8_192).unwrap();
    assert_eq!(scheduler.read_timer(timer), Some(3_616));
    scheduler.advance_ms(3_615).unwrap();
    assert_eq!(scheduler.read_timer(timer), Some(1));
    scheduler.advance_ms(1).unwrap();
    while scheduler.step() {}
    assert_eq!(*output.lock().unwrap(), [7]);
}

#[test]
fn long_timer_rb_tree_beyond_wheel() {
    let (scheduler, pid, output) = simulation();
    let timeout = (1_u64 << 27) + 500;
    let timer = scheduler.start_timer(pid, timeout, 9).unwrap();
    scheduler.advance_ms(timeout - 1).unwrap();
    assert_eq!(scheduler.read_timer(timer), Some(1));
    scheduler.advance_ms(1).unwrap();
    while scheduler.step() {}
    assert_eq!(*output.lock().unwrap(), [9]);
}

#[test]
fn cancel_returns_remaining_ms_like_erts() {
    let (scheduler, pid, _) = simulation();
    let timer = scheduler.start_timer(pid, 50, 1).unwrap();
    scheduler.advance_ms(17).unwrap();
    assert_eq!(scheduler.cancel_timer(timer), Some(33));
    assert_eq!(scheduler.read_timer(timer), None);
}

#[test]
fn bump_yields_after_limit() {
    let (scheduler, pid, output) = simulation();
    for value in 0..20_050 {
        scheduler.start_timer(pid, 1, value).unwrap();
    }
    scheduler.advance_ms(1).unwrap();
    while output.lock().unwrap().len() < 20_050 {
        scheduler.advance_ms(0).unwrap();
        while scheduler.step() {}
    }
    assert_eq!(output.lock().unwrap().len(), 20_050);
}

#[test]
fn one_million_timers_insert_cancel() {
    let (scheduler, pid, _) = simulation();
    let start = Instant::now();
    for _ in 0..1_000_000 {
        let timer = scheduler.start_timer(pid, 60_000, 1).unwrap();
        assert_eq!(scheduler.cancel_timer(timer), Some(60_000));
    }
    let ns_per_op = start.elapsed().as_nanos() / 1_000_000;
    println!("timer set+cancel: {ns_per_op} ns/op");
    if !cfg!(debug_assertions) {
        assert!(ns_per_op <= 200, "timer set+cancel took {ns_per_op} ns/op");
    }
}

#[test]
fn cross_scheduler_cancel_via_owner_queue() {
    let scheduler = Scheduler::new(Config {
        workers: 2,
        max_processes: 4,
        ..Config::default()
    });
    let output = Arc::new(Mutex::new(Vec::new()));
    scheduler
        .spawn(Sink(Arc::new(Mutex::new(Vec::new()))))
        .unwrap();
    let owner_one_pid = scheduler.spawn(Sink(output)).unwrap();
    assert_eq!(owner_one_pid.number(), 1);
    let timer = scheduler.start_timer(owner_one_pid, 30_000, 17).unwrap();

    thread::scope(|scope| {
        let canceler = scope.spawn(|| scheduler.cancel_timer(timer));
        assert!(matches!(canceler.join().unwrap(), Some(remaining) if remaining <= 30_000));
    });
    assert_eq!(scheduler.read_timer(timer), None);
}

struct ReentrantTimerTask {
    scheduler: Arc<OnceLock<Weak<Scheduler<ReentrantTimerTask>>>>,
    result: mpsc::SyncSender<(Option<u64>, Option<u64>, Option<u64>)>,
}

impl Task for ReentrantTimerTask {
    type Message = u64;
    type SchedulerData = ();

    fn run(&mut self, ctx: &mut RunCtx<u64>, _: &mut (), _: u32) -> RunOutcome {
        let Some(scheduler) = self.scheduler.get().and_then(Weak::upgrade) else {
            return RunOutcome::Exit(1);
        };
        let Ok(timer) = scheduler.start_timer(ctx.pid(), 60_000, 1) else {
            return RunOutcome::Exit(2);
        };
        let remaining = scheduler.read_timer(timer);
        let canceled = scheduler.cancel_timer(timer);
        let after_cancel = scheduler.read_timer(timer);
        let _ = self.result.send((remaining, canceled, after_cancel));
        RunOutcome::Exit(0)
    }
}

#[test]
fn owner_worker_timer_facade_is_reentrant() {
    let scheduler_ref = Arc::new(OnceLock::new());
    let scheduler = Arc::new(Scheduler::new(Config {
        workers: 1,
        max_processes: 4,
        ..Config::default()
    }));
    assert!(scheduler_ref.set(Arc::downgrade(&scheduler)).is_ok());
    let (sender, receiver) = mpsc::sync_channel(1);
    scheduler
        .spawn(ReentrantTimerTask {
            scheduler: scheduler_ref,
            result: sender,
        })
        .unwrap();
    assert_eq!(
        receiver.recv_timeout(Duration::from_secs(2)).unwrap(),
        (Some(60_000), Some(60_000), None)
    );
}

type TimerSlots = Arc<Mutex<[Option<arinsal_sched::TimerRef>; 2]>>;

/// Cancels the timer of the task bound to the other worker while that task does the same.
struct CrossCancelTask {
    scheduler: Arc<OnceLock<Weak<Scheduler<CrossCancelTask>>>>,
    slots: TimerSlots,
    me: usize,
    result: mpsc::Sender<(usize, Option<u64>, Option<u64>)>,
}

impl Task for CrossCancelTask {
    type Message = u64;
    type SchedulerData = ();

    fn run(&mut self, ctx: &mut RunCtx<u64>, _: &mut (), _: u32) -> RunOutcome {
        let Some(scheduler) = self.scheduler.get().and_then(Weak::upgrade) else {
            return RunOutcome::Exit(1);
        };
        let Ok(timer) = scheduler.start_timer(ctx.pid(), 60_000, 1) else {
            return RunOutcome::Exit(2);
        };
        self.slots.lock().unwrap()[self.me] = Some(timer);
        let deadline = Instant::now() + Duration::from_secs(10);
        let other = loop {
            if let Some(other) = self.slots.lock().unwrap()[1 - self.me] {
                break other;
            }
            if Instant::now() > deadline {
                return RunOutcome::Exit(3);
            }
            thread::yield_now();
        };
        // Both workers now ask each other at the same time; erts serves such requests as
        // aux work, so neither may block the other.
        let read = scheduler.read_timer(other);
        let canceled = scheduler.cancel_timer(other);
        let _ = self.result.send((self.me, read, canceled));
        RunOutcome::Exit(0)
    }
}

#[test]
fn cross_scheduler_requests_do_not_deadlock() {
    let scheduler_ref = Arc::new(OnceLock::new());
    let scheduler = Arc::new(Scheduler::new(Config {
        workers: 2,
        max_processes: 8,
        ..Config::default()
    }));
    assert!(scheduler_ref.set(Arc::downgrade(&scheduler)).is_ok());
    let slots: TimerSlots = Arc::new(Mutex::new([None, None]));
    let (sender, receiver) = mpsc::channel();
    for me in 0..2 {
        let pid = scheduler
            .spawn_unscheduled_on(
                CrossCancelTask {
                    scheduler: scheduler_ref.clone(),
                    slots: slots.clone(),
                    me,
                    result: sender.clone(),
                },
                me + 1,
            )
            .unwrap();
        scheduler.schedule_unscheduled(pid).unwrap();
    }
    for _ in 0..2 {
        let (_, read, canceled) = receiver
            .recv_timeout(Duration::from_secs(5))
            .expect("cross-scheduler timer request deadlocked");
        assert!(matches!(read, Some(ms) if ms <= 60_000));
        assert!(matches!(canceled, Some(ms) if ms <= 60_000));
    }
}

#[test]
fn foreign_thread_insert_is_visible_to_later_requests() {
    let scheduler = Scheduler::new(Config {
        workers: 2,
        max_processes: 4,
        ..Config::default()
    });
    let pid = scheduler
        .spawn(Sink(Arc::new(Mutex::new(Vec::new()))))
        .unwrap();
    // Inserted asynchronously on the owning worker; the queued request order keeps
    // the following read and cancel behind the insertion.
    let timer = scheduler.start_timer(pid, 30_000, 5).unwrap();
    assert!(matches!(scheduler.read_timer(timer), Some(ms) if ms <= 30_000));
    assert!(matches!(scheduler.cancel_timer(timer), Some(ms) if ms <= 30_000));
    assert_eq!(scheduler.cancel_timer(timer), None);
}

/// Starts a timer to itself, then on a message cancels the timers aimed at it and exits,
/// like the VM's exit path.
struct Victim {
    own: mpsc::Sender<arinsal_sched::TimerRef>,
    done: mpsc::Sender<()>,
    started: bool,
}

impl Task for Victim {
    type Message = u64;
    type SchedulerData = ();

    fn run(&mut self, ctx: &mut RunCtx<u64>, _: &mut (), _: u32) -> RunOutcome {
        if !self.started {
            self.started = true;
            self.own.send(ctx.start_timer(60_000, 1).unwrap()).unwrap();
        }
        if ctx.receive().is_some() {
            ctx.cancel_target_timers(ctx.pid());
            self.done.send(()).unwrap();
            return RunOutcome::Exit(0);
        }
        RunOutcome::Wait { timeout_ms: None }
    }
}

// Port of erts/emulator/beam/erl_hl_timer.c:2455 (erts_cancel_bif_timers), OTP-29.1.1: exit
// cancels the receiver's timers on its own wheel and on other schedulers' wheels.
#[test]
fn exit_cancels_target_timers_on_every_wheel() {
    let scheduler = Scheduler::<Victim>::new(Config {
        workers: 4,
        max_processes: 16,
        ..Config::default()
    });
    let (own_tx, own_rx) = mpsc::channel();
    let (done_tx, done_rx) = mpsc::channel();
    let pid = scheduler
        .spawn(Victim {
            own: own_tx,
            done: done_tx,
            started: false,
        })
        .unwrap();
    let own = own_rx.recv_timeout(Duration::from_secs(10)).unwrap();
    let remote = scheduler.start_timer(pid, 60_000, 2).unwrap();
    assert!(scheduler.read_timer(own).is_some());
    assert!(scheduler.read_timer(remote).is_some());
    scheduler.send(pid, pid, 0).unwrap();
    done_rx.recv_timeout(Duration::from_secs(10)).unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while scheduler.read_timer(own).is_some() || scheduler.read_timer(remote).is_some() {
        assert!(Instant::now() < deadline, "timers survived their receiver");
        thread::sleep(Duration::from_millis(1));
    }
}
