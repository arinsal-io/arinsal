use arinsal_sched::{Config, Payload, RunCtx, RunOutcome, Scheduler, Task};
use std::sync::{Arc, Mutex, OnceLock, Weak, mpsc};
use std::thread;
use std::time::{Duration, Instant};

struct Sink(Arc<Mutex<Vec<u64>>>);

impl Task for Sink {
    type Message = u64;

    fn run(&mut self, ctx: &mut RunCtx<u64>, _: u32) -> RunOutcome {
        while let Some(event) = ctx.receive() {
            match event.payload {
                Payload::Timer { message, .. } => self.0.lock().unwrap().push(message),
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

    fn run(&mut self, ctx: &mut RunCtx<u64>, _: u32) -> RunOutcome {
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
