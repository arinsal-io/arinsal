//! Run queue balancing and low priority scheduling, compared with the erts behaviour that
//! scheduler_SUITE (equal, many_low, few_low) checks.

use arinsal_sched::{Config, Priority, Scheduler, Task};
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
    type SchedulerData = ();
    fn run(
        c_p: &mut arinsal_sched::CP<'_, Self>,
        esdp: &arinsal_sched::ErtsSchedulerData<Self>,
        budget: u32,
        calls: &mut u32,
    ) {
        esdp.with_ctx(c_p, |this, ctx| {
            if this.stop.load(Ordering::Relaxed) {
                return {
                    ctx.erts_proc_exit_free(this);
                };
            }
            this.runs.fetch_add(1, Ordering::Relaxed);
            *calls = budget;
        })
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
/// One mix per test: erts has one runtime per OS process.
fn low_priority_gets_an_eighth_of_normal_turns(normal: usize, low: usize) {
    {
        let scheduler = start_scheduler(Config {
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

#[test]
fn low_priority_gets_an_eighth_of_normal_turns_even_mix() {
    low_priority_gets_an_eighth_of_normal_turns(4, 4);
}

#[test]
fn low_priority_gets_an_eighth_of_normal_turns_many_low() {
    low_priority_gets_an_eighth_of_normal_turns(2, 16);
}

#[test]
fn low_priority_gets_an_eighth_of_normal_turns_many_normal() {
    low_priority_gets_an_eighth_of_normal_turns(16, 2);
}

/// Busy schedulers complete the reductions-triggered balance checks counted by `nbalance`.
#[test]
fn busy_schedulers_check_balance() {
    let scheduler = start_scheduler(Config {
        workers: 4,
        ..Config::default()
    });
    let stop = Arc::new(AtomicBool::new(false));
    spawn_busy(&scheduler, Priority::Normal, 64, &stop);
    let started = Instant::now();
    while scheduler.balance_checks() < 3 && started.elapsed() < Duration::from_secs(30) {
        std::thread::sleep(Duration::from_millis(10));
    }
    stop.store(true, Ordering::Relaxed);
    assert!(
        scheduler.balance_checks() >= 3,
        "{} completed balance checks",
        scheduler.balance_checks()
    );
}

/// A single online run queue never balances (check_balance with one balanced run queue).
#[test]
fn one_online_scheduler_does_not_balance() {
    let scheduler = start_scheduler(Config {
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
    similar_asserts::assert_eq!(scheduler.balance_checks(), 0);
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
