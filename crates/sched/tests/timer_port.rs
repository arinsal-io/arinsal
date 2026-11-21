use arinsal_sched::{Config, Payload, Scheduler, Task};
use std::sync::{Arc, Mutex, OnceLock, Weak, mpsc};
use std::thread;
use std::time::{Duration, Instant};

struct Sink(Arc<Mutex<Vec<u64>>>);

impl Task for Sink {
    type Message = u64;
    type SchedulerData = ();

    fn run(
        c_p: &mut arinsal_sched::CP<'_, Self>,
        esdp: &arinsal_sched::ErtsSchedulerData<Self>,
        _: u32,
        _calls: &mut u32,
    ) {
        esdp.with_ctx(c_p, |this, ctx| {
            while let Some(event) = ctx.receive() {
                match event.payload {
                    Payload::Timer { message, .. } => this.0.lock().unwrap().push(*message),
                    Payload::Message(message) => this.0.lock().unwrap().push(message),
                    _ => unreachable!(),
                }
            }
            {
                let _ = ctx.clear_active_unless_queued();
            }
        })
    }
}

fn sink() -> (Scheduler<Sink>, arinsal_sched::Pid, Arc<Mutex<Vec<u64>>>) {
    let scheduler = start_scheduler(Config {
        workers: 1,
        max_processes: 1,
        ..Config::default()
    });
    let output = Arc::new(Mutex::new(Vec::new()));
    let pid = scheduler.spawn(Sink(output.clone())).unwrap();
    (scheduler, pid, output)
}

fn wait_for_len(output: &Mutex<Vec<u64>>, len: usize) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while output.lock().unwrap().len() < len && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(1));
    }
}

#[test]
fn soon_wheel_expiry_order() {
    let (scheduler, pid, output) = sink();
    scheduler.start_timer(pid, 90, 3).unwrap();
    scheduler.start_timer(pid, 30, 1).unwrap();
    scheduler.start_timer(pid, 60, 2).unwrap();
    wait_for_len(&output, 3);
    assert_eq!(*output.lock().unwrap(), [1, 2, 3]);
}

#[test]
fn cancel_returns_remaining_ms_like_erts() {
    let (scheduler, pid, _) = sink();
    let timer = scheduler.start_timer(pid, 60_000, 1).unwrap();
    assert!(matches!(read_timer(&scheduler, timer), Some(ms) if (59_000..=60_000).contains(&ms)));
    assert!(matches!(cancel_timer(&scheduler, timer), Some(ms) if (59_000..=60_000).contains(&ms)));
    assert_eq!(read_timer(&scheduler, timer), None);
}

#[test]
fn bump_yields_after_limit() {
    let (scheduler, pid, output) = sink();
    for value in 0..20_050 {
        scheduler.start_timer(pid, 1, value).unwrap();
    }
    wait_for_len(&output, 20_050);
    assert_eq!(output.lock().unwrap().len(), 20_050);
}

#[test]
fn one_million_timers_insert_cancel() {
    let (scheduler, pid, _) = sink();
    let start = Instant::now();
    for _ in 0..1_000_000 {
        let timer = scheduler.start_timer(pid, 60_000, 1).unwrap();
        assert!(matches!(cancel_timer(&scheduler, timer), Some(ms) if ms <= 60_000));
    }
    let ns_per_op = start.elapsed().as_nanos() / 1_000_000;
    println!("timer set+cancel: {ns_per_op} ns/op");
    if !cfg!(debug_assertions) {
        assert!(ns_per_op <= 200, "timer set+cancel took {ns_per_op} ns/op");
    }
}

#[test]
fn cross_scheduler_cancel_via_owner_queue() {
    let scheduler = start_scheduler(Config {
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
        let canceler = scope.spawn(|| cancel_timer(&scheduler, timer));
        assert!(matches!(canceler.join().unwrap(), Some(remaining) if remaining <= 30_000));
    });
    assert_eq!(read_timer(&scheduler, timer), None);
}

struct ReentrantTimerTask {
    scheduler: Arc<OnceLock<Weak<Scheduler<ReentrantTimerTask>>>>,
    result: mpsc::SyncSender<(Option<u64>, Option<u64>, Option<u64>)>,
}

impl Task for ReentrantTimerTask {
    type Message = u64;
    type SchedulerData = ();

    fn run(
        c_p: &mut arinsal_sched::CP<'_, Self>,
        esdp: &arinsal_sched::ErtsSchedulerData<Self>,
        _: u32,
        _calls: &mut u32,
    ) {
        esdp.with_ctx(c_p, |this, ctx| {
            let Some(scheduler) = this.scheduler.get().and_then(Weak::upgrade) else {
                return {
                    ctx.erts_proc_exit_free(this);
                };
            };
            let Ok(timer) = scheduler.start_timer(ctx.pid(), 60_000, 1) else {
                return {
                    ctx.erts_proc_exit_free(this);
                };
            };
            // The owner accesses its own wheel at once (access_sched_local_btm).
            let remaining = read_timer(&scheduler, timer);
            let canceled = cancel_timer(&scheduler, timer);
            let after_cancel = read_timer(&scheduler, timer);
            let _ = this.result.send((remaining, canceled, after_cancel));
            {
                ctx.erts_proc_exit_free(this);
            }
        })
    }
}

#[test]
fn owner_worker_timer_facade_is_reentrant() {
    let scheduler_ref = Arc::new(OnceLock::new());
    let scheduler = Arc::new(start_scheduler(Config {
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
    result: mpsc::Sender<(usize, bool, Option<u64>)>,
}

impl Task for CrossCancelTask {
    type Message = u64;
    type SchedulerData = ();

    fn run(
        c_p: &mut arinsal_sched::CP<'_, Self>,
        esdp: &arinsal_sched::ErtsSchedulerData<Self>,
        _: u32,
        _calls: &mut u32,
    ) {
        esdp.with_ctx(c_p, |this, ctx| {
            let Some(scheduler) = this.scheduler.get().and_then(Weak::upgrade) else {
                return {
                    ctx.erts_proc_exit_free(this);
                };
            };
            let Ok(timer) = scheduler.start_timer(ctx.pid(), 60_000, 1) else {
                return {
                    ctx.erts_proc_exit_free(this);
                };
            };
            this.slots.lock().unwrap()[this.me] = Some(timer);
            let deadline = Instant::now() + Duration::from_secs(10);
            let other = loop {
                if let Some(other) = this.slots.lock().unwrap()[1 - this.me] {
                    break other;
                }
                if Instant::now() > deadline {
                    return {
                        ctx.erts_proc_exit_free(this);
                    };
                }
                thread::yield_now();
            };
            // Both workers now ask each other at the same time; erts serves such requests as
            // misc aux work (bif_timer_access_request) and the requester never waits on them.
            let me = this.me;
            let read = this.result.clone();
            scheduler.read_timer_async(other, move |remaining| {
                let _ = read.send((me, false, remaining));
            });
            let canceled = this.result.clone();
            scheduler.cancel_timer_async(other, move |remaining| {
                let _ = canceled.send((me, true, remaining));
            });
            {
                ctx.erts_proc_exit_free(this);
            }
        })
    }
}

#[test]
fn cross_scheduler_requests_do_not_deadlock() {
    let scheduler_ref = Arc::new(OnceLock::new());
    let scheduler = Arc::new(start_scheduler(Config {
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
    for _ in 0..4 {
        let (_, _, remaining) = receiver
            .recv_timeout(Duration::from_secs(5))
            .expect("cross-scheduler timer request deadlocked");
        assert!(matches!(remaining, Some(ms) if ms <= 60_000));
    }
}

#[test]
fn foreign_thread_insert_is_visible_to_later_requests() {
    let scheduler = start_scheduler(Config {
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
    assert!(matches!(read_timer(&scheduler, timer), Some(ms) if ms <= 30_000));
    assert!(matches!(cancel_timer(&scheduler, timer), Some(ms) if ms <= 30_000));
    assert_eq!(cancel_timer(&scheduler, timer), None);
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

    fn run(
        c_p: &mut arinsal_sched::CP<'_, Self>,
        esdp: &arinsal_sched::ErtsSchedulerData<Self>,
        _: u32,
        _calls: &mut u32,
    ) {
        esdp.with_ctx(c_p, |this, ctx| {
            if !this.started {
                this.started = true;
                this.own.send(ctx.start_timer(60_000, 1).unwrap()).unwrap();
            }
            if ctx.receive().is_some() {
                ctx.cancel_target_timers(ctx.pid());
                this.done.send(()).unwrap();
                return {
                    ctx.erts_proc_exit_free(this);
                };
            }
            {
                let _ = ctx.clear_active_unless_queued();
            }
        })
    }
}

// Port of erts/emulator/beam/erl_hl_timer.c:2455 (erts_cancel_bif_timers), OTP-29.1.1: exit
// cancels the receiver's timers on its own wheel and on other schedulers' wheels.
#[test]
fn exit_cancels_target_timers_on_every_wheel() {
    let scheduler = start_scheduler::<Victim>(Config {
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
    assert!(read_timer(&scheduler, own).is_some());
    assert!(read_timer(&scheduler, remote).is_some());
    scheduler.send(pid, pid, 0).unwrap();
    done_rx.recv_timeout(Duration::from_secs(10)).unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while read_timer(&scheduler, own).is_some() || read_timer(&scheduler, remote).is_some() {
        assert!(Instant::now() < deadline, "timers survived their receiver");
        thread::sleep(Duration::from_millis(1));
    }
}

/// The answer of an asynchronous read: a thread outside the owner gets it from the owner's
/// misc aux work (bif_timer_access_request).
fn read_timer<T: Task>(scheduler: &Scheduler<T>, timer: arinsal_sched::TimerRef) -> Option<u64> {
    let (reply, answer) = mpsc::channel();
    scheduler.read_timer_async(timer, move |remaining| {
        let _ = reply.send(remaining);
    });
    answer.recv_timeout(Duration::from_secs(10)).unwrap()
}

/// The answer of an asynchronous cancel, as [`read_timer`].
fn cancel_timer<T: Task>(scheduler: &Scheduler<T>, timer: arinsal_sched::TimerRef) -> Option<u64> {
    let (reply, answer) = mpsc::channel();
    scheduler.cancel_timer_async(timer, move |remaining| {
        let _ = reply.send(remaining);
    });
    answer.recv_timeout(Duration::from_secs(10)).unwrap()
}

/// A scheduler started the way `erl_start` starts one: erl_process.c:6090
/// (erts_init_scheduling), then erl_process.c:8909 (erts_start_schedulers).
fn start_scheduler<T: arinsal_sched::Task>(
    config: arinsal_sched::Config,
) -> arinsal_sched::Scheduler<T> {
    let dirty_cpu_online = config.dirty_cpu_schedulers.max(1);
    let scheduler = arinsal_sched::Scheduler::erts_init_scheduling(config, dirty_cpu_online);
    scheduler.erts_start_schedulers();
    scheduler
}
