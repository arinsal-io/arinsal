//! A scheduler stuck in a call that never yields (a long NIF, a blocking driver call). erts
//! wakes no other scheduler for work queued behind it, except through the run queue supervisor
//! (`+sfwi`, erl_process.c `runq_supervisor`), which is off by default: then the work waits
//! until the call returns. With the supervisor on, an idle scheduler takes the work over
//! (`wake_scheduler_on_empty_runq`, `try_steal_task`).
use arinsal_sched::{Config, Priority, RunCtx, RunOutcome, Scheduler, Task};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

enum Probe {
    Block {
        running: Arc<AtomicBool>,
        release: Arc<AtomicBool>,
    },
    Quick(Arc<AtomicUsize>),
}
impl Task for Probe {
    type Message = ();
    type SchedulerData = ();
    fn run(&mut self, _ctx: &mut RunCtx<()>, _: &mut (), _: u32) -> RunOutcome {
        match self {
            Probe::Block { running, release } => {
                running.store(true, Ordering::Release);
                while !release.load(Ordering::Acquire) {
                    std::thread::sleep(Duration::from_millis(1));
                }
            }
            Probe::Quick(done) => {
                done.fetch_add(1, Ordering::AcqRel);
            }
        }
        RunOutcome::Exit(0)
    }
}

/// Queue `queued` tasks on the run queue of a scheduler whose thread is blocked.
fn run_case(workers: usize, queued: usize, supervision_ms: Option<u64>) -> usize {
    let sched = Scheduler::new(Config {
        workers,
        forced_wakeup_interval: supervision_ms,
        max_processes: 1024,
        ..Config::default()
    });
    let running = Arc::new(AtomicBool::new(false));
    let release = Arc::new(AtomicBool::new(false));
    let done = Arc::new(AtomicUsize::new(0));
    sched
        .spawn_priority_on(
            Probe::Block {
                running: running.clone(),
                release: release.clone(),
            },
            Priority::Normal,
            0,
        )
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while !running.load(Ordering::Acquire) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(1));
    }
    assert!(running.load(Ordering::Acquire), "the blocker never ran");
    // Let every other scheduler go to sleep, then queue work behind the blocked one.
    std::thread::sleep(Duration::from_millis(200));
    for _ in 0..queued {
        sched
            .spawn_priority_on(Probe::Quick(done.clone()), Priority::Normal, 0)
            .unwrap();
    }
    let deadline = Instant::now() + Duration::from_secs(3);
    while done.load(Ordering::Acquire) < queued && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(1));
    }
    let finished = done.load(Ordering::Acquire);
    release.store(true, Ordering::Release);
    finished
}

#[test]
fn work_behind_a_blocked_scheduler_waits_without_the_supervisor() {
    // erts default: `erts_runq_supervision_interval` is 0.
    assert_eq!(run_case(4, 4, None), 0);
}

#[test]
fn supervisor_makes_idle_schedulers_take_over_blocked_run_queue() {
    assert_eq!(run_case(4, 1, Some(20)), 1);
    assert_eq!(run_case(4, 8, Some(20)), 8);
}
