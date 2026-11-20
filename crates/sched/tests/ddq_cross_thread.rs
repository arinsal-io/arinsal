//! Frees of blocks owned by one scheduler's allocator instance from the other scheduler (a
//! managed enqueue, protected by thread progress) and from an unmanaged thread (protected by the
//! queue's `um_refc`), while the owner keeps allocating and draining its delayed-dealloc queue.
//! Port of the protocol of `ddq_managed_thread_enqueue` / `ddq_check_incoming`
//! (erl_alloc_util.c) over the one thread progress of the process (erl_thr_progress.c).
//!
//! Ignored by default: it is a stress test, run with
//! `DDQ_STRESS_SECS=20 cargo test -p arinsal-sched --test ddq_cross_thread -- --ignored`.

use arinsal_alloc::typed::{AllocBlock, ErtsAlcType};
use arinsal_sched::{Config, Scheduler, Task};
use similar_asserts::assert_eq;
use std::sync::mpsc;
use std::time::{Duration, Instant};

struct Idle;

impl Task for Idle {
    type Message = ();
    type SchedulerData = ();
    fn run(
        c_p: &mut arinsal_sched::CP<'_, Self>,
        esdp: &arinsal_sched::ErtsSchedulerData<Self>,
        _: u32,
        _calls: &mut u32,
    ) {
        esdp.with_ctx(c_p, |this, ctx| {
            ctx.erts_proc_exit_free(this);
        })
    }
}

#[test]
#[ignore = "stress: DDQ_STRESS_SECS=20 cargo test -p arinsal-sched --test ddq_cross_thread -- --ignored"]
fn managed_and_unmanaged_frees_reach_the_owner() {
    let scheduler = start_scheduler::<Idle>(Config {
        workers: 2,
        ..Config::default()
    });
    let seconds = std::env::var("DDQ_STRESS_SECS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(20);
    let deadline = Instant::now() + Duration::from_secs(seconds);
    let mut rounds = 0u64;
    while Instant::now() < deadline {
        for owner in 0..2 {
            let (sender, receiver) = mpsc::channel();
            scheduler.erts_schedule_misc_aux_work(owner + 1, move || {
                let blocks: Vec<_> = (0..256)
                    .map(|_| AllocBlock::new(ErtsAlcType::HEAP, 4).unwrap())
                    .collect();
                sender.send(blocks).unwrap();
            });
            let blocks: Vec<AllocBlock> = receiver.recv_timeout(Duration::from_secs(30)).unwrap();
            assert_eq!(
                blocks[0].instance(),
                owner + 1,
                "worker n owns instance n + 1"
            );
            let (managed, unmanaged): (Vec<_>, Vec<_>) = blocks
                .into_iter()
                .enumerate()
                .partition(|(i, _)| i % 2 == 0);
            let (done, finished) = mpsc::channel();
            scheduler.erts_schedule_misc_aux_work(2 - owner, move || {
                drop(managed);
                done.send(()).unwrap();
            });
            // The test thread is not a managed thread: its frees take the unmanaged path.
            drop(unmanaged);
            finished.recv_timeout(Duration::from_secs(30)).unwrap();
        }
        rounds += 1;
    }
    eprintln!("{rounds} rounds");
}

/// A scheduler started the way `erl_start` starts one: erl_process.c:6090
/// (erts_init_scheduling), then erl_process.c:8909 (erts_start_schedulers).
fn start_scheduler<T: arinsal_sched::Task>(
    config: arinsal_sched::Config,
) -> arinsal_sched::Scheduler<T> {
    let dirty_cpu_online = config.dirty_cpu_schedulers.max(1);
    let scheduler = Scheduler::erts_init_scheduling(config, dirty_cpu_online);
    scheduler.erts_start_schedulers();
    scheduler
}
