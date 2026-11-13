//! Two schedulers in one process share the allocator instances, as every test binary that starts
//! more than one runtime does. A managed thread of runtime B frees blocks owned by a scheduler
//! instance of runtime A: the free goes to A's delayed-dealloc queue as a managed enqueue, which
//! erts protects with thread progress (erl_alloc_util.c, ddq_managed_thread_enqueue: the owner
//! releases a node only after every managed thread passed a progress point). One test per
//! process: allocator registration is global.
//!
//! Ignored by default: it is a stress reproduction, run with
//! `cargo test -p arinsal-sched --test ddq_cross_runtime -- --ignored`.

use arinsal_alloc::typed::{AllocBlock, ErtsAlcType};
use arinsal_sched::{Config, RunCtx, RunOutcome, Scheduler, Task};
use std::sync::mpsc;
use std::time::{Duration, Instant};

struct Idle;

impl Task for Idle {
    type Message = ();
    type SchedulerData = ();
    fn run(&mut self, _: &mut RunCtx<()>, _: &mut (), _: u32) -> RunOutcome {
        RunOutcome::Exit(0)
    }
}

#[test]
#[ignore = "stress: cargo test -p arinsal-sched --test ddq_cross_runtime -- --ignored"]
fn foreign_runtime_frees_into_a_scheduler_instance() {
    let config = || Config {
        workers: 2,
        ..Config::default()
    };
    // Runtime A's workers own instances 1 and 2; B's workers find them taken and use instance 0.
    let a = Scheduler::<Idle>::new(config());
    let b = Scheduler::<Idle>::new(config());
    let seconds = std::env::var("DDQ_STRESS_SECS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(20);
    let deadline = Instant::now() + Duration::from_secs(seconds);
    let mut rounds = 0u64;
    while Instant::now() < deadline {
        for worker in 0..2 {
            let (sender, receiver) = mpsc::channel();
            a.request_aux_work(worker, move || {
                let blocks: Vec<_> = (0..256)
                    .map(|_| AllocBlock::new(ErtsAlcType::HEAP, 4).unwrap())
                    .collect();
                sender.send(blocks).unwrap();
            });
            let blocks: Vec<AllocBlock> = receiver.recv_timeout(Duration::from_secs(30)).unwrap();
            assert_eq!(
                blocks[0].instance(),
                worker + 1,
                "runtime A owns instances 1 and 2"
            );
            let (half, rest): (Vec<_>, Vec<_>) = blocks
                .into_iter()
                .enumerate()
                .partition(|(i, _)| i % 2 == 0);
            let (done_a, finished_a) = mpsc::channel();
            let (done_b, finished_b) = mpsc::channel();
            b.request_aux_work(0, move || {
                assert_eq!(
                    arinsal_alloc::thread_alloc_ix(),
                    0,
                    "runtime B's worker uses instance 0"
                );
                drop(half);
                done_a.send(()).unwrap();
            });
            b.request_aux_work(1, move || {
                drop(rest);
                done_b.send(()).unwrap();
            });
            finished_a.recv_timeout(Duration::from_secs(30)).unwrap();
            finished_b.recv_timeout(Duration::from_secs(30)).unwrap();
        }
        rounds += 1;
    }
    eprintln!("{rounds} rounds");
    drop(b);
    drop(a);
}
