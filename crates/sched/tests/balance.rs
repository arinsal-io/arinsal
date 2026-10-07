//! Run queue balancing and low priority scheduling, compared with the erts behaviour that
//! scheduler_SUITE (equal, many_low, few_low) checks.

use arinsal_sched::{Config, Priority, RunCtx, RunOutcome, Scheduler, Task};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Burns its whole budget each turn and counts the turns.
struct Busy {
    runs: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
}

impl Task for Busy {
    type Message = ();
    fn run(&mut self, ctx: &mut RunCtx<()>, _: u32) -> RunOutcome {
        if self.stop.load(Ordering::Relaxed) {
            return RunOutcome::Exit(0);
        }
        self.runs.fetch_add(1, Ordering::Relaxed);
        while ctx.consume(100) {}
        RunOutcome::Yield
    }
}

fn spawn_busy(
    scheduler: &Scheduler<Busy>,
    priority: Priority,
    count: usize,
    stop: &Arc<AtomicBool>,
) -> Vec<Arc<AtomicU64>> {
    (0..count)
        .map(|_| {
            let runs = Arc::new(AtomicU64::new(0));
            scheduler
                .spawn_priority(
                    Busy {
                        runs: runs.clone(),
                        stop: stop.clone(),
                    },
                    priority,
                )
                .unwrap();
            runs
        })
        .collect()
}

fn total(runs: &[Arc<AtomicU64>]) -> u64 {
    runs.iter().map(|runs| runs.load(Ordering::Relaxed)).sum()
}

/// erts runs a low priority process once per `RESCHEDULE_LOW` (8) passes over the shared
/// normal queue, so a low process gets about 1/8 of a normal process's turns whatever the
/// mix (scheduler_SUITE low_normal_test accepts 0.05..0.25).
#[test]
fn low_priority_gets_an_eighth_of_normal_turns() {
    for (normal, low) in [(4, 4), (2, 16), (16, 2)] {
        let scheduler = Scheduler::new(Config {
            workers: 1,
            ..Config::default()
        });
        let stop = Arc::new(AtomicBool::new(false));
        let normals = spawn_busy(&scheduler, Priority::Normal, normal, &stop);
        let lows = spawn_busy(&scheduler, Priority::Low, low, &stop);
        let started = Instant::now();
        while total(&lows) < 2_000 && started.elapsed() < Duration::from_secs(20) {
            std::thread::sleep(Duration::from_millis(10));
        }
        stop.store(true, Ordering::Relaxed);
        let low_avg = total(&lows) as f64 / low as f64;
        let normal_avg = total(&normals) as f64 / normal as f64;
        let ratio = low_avg / normal_avg;
        assert!(
            (0.05..=0.25).contains(&ratio),
            "{normal} normal, {low} low: low/normal ratio {ratio}"
        );
    }
}

/// Busy schedulers check the balance every `ERTS_RUNQ_CHECK_BALANCE_REDS_PER_SCHED`
/// reductions, which erts_debug:get_internal_state(nbalance) counts.
#[test]
fn busy_schedulers_check_balance() {
    let scheduler = Scheduler::new(Config {
        workers: 4,
        ..Config::default()
    });
    let stop = Arc::new(AtomicBool::new(false));
    let runs = spawn_busy(&scheduler, Priority::Normal, 64, &stop);
    let started = Instant::now();
    while scheduler.balance_checks() < 3 && started.elapsed() < Duration::from_secs(30) {
        std::thread::sleep(Duration::from_millis(10));
    }
    stop.store(true, Ordering::Relaxed);
    assert!(
        scheduler.balance_checks() >= 3,
        "{} balance checks after {} turns",
        scheduler.balance_checks(),
        total(&runs)
    );
    // Every process kept running: none starved on an unbalanced run queue.
    assert!(runs.iter().all(|runs| runs.load(Ordering::Relaxed) > 0));
}

/// A single online run queue never balances (check_balance with one balanced run queue).
#[test]
fn one_online_scheduler_does_not_balance() {
    let scheduler = Scheduler::new(Config {
        workers: 2,
        ..Config::default()
    });
    assert!(scheduler.set_online_schedulers(1));
    let stop = Arc::new(AtomicBool::new(false));
    let runs = spawn_busy(&scheduler, Priority::Normal, 8, &stop);
    let started = Instant::now();
    while total(&runs) < 5_000 && started.elapsed() < Duration::from_secs(20) {
        std::thread::sleep(Duration::from_millis(10));
    }
    stop.store(true, Ordering::Relaxed);
    assert_eq!(scheduler.balance_checks(), 0);
}
