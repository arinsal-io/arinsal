//! Normal scheduler `n` allocates from allocator instance `n`; every other thread uses
//! instance 0 (erts_alloc_register_scheduler). One test per process: registration is global.

use arinsal_alloc::typed::{AllocBlock, ErtsAlcType, instance_count};
use arinsal_sched::{Config, RunCtx, RunOutcome, Scheduler, Task};
use std::sync::mpsc;
use std::time::Duration;

struct Idle;

impl Task for Idle {
    type Message = ();
    type SchedulerData = ();
    fn run(&mut self, _: &mut RunCtx<()>, _: &mut (), _: u32) -> RunOutcome {
        RunOutcome::Exit(0)
    }
}

fn block_instance() -> usize {
    AllocBlock::new(ErtsAlcType::HEAP, 4).unwrap().instance()
}

#[test]
fn scheduler_threads_own_their_instance() {
    let scheduler = Scheduler::<Idle>::new(Config {
        workers: 3,
        dirty_cpu_schedulers: 2,
        dirty_io_schedulers: 1,
        ..Config::default()
    });
    assert_eq!(instance_count("eheap_alloc"), Some(1 + 3));
    assert_eq!(block_instance(), 0);

    let (sender, receiver) = mpsc::channel();
    let sender = std::sync::Mutex::new(sender);
    scheduler.request_aux_work_all(move |worker| {
        let instance = block_instance();
        sender.lock().unwrap().send((worker, instance)).unwrap();
    });
    let mut seen = Vec::new();
    for _ in 0..3 {
        seen.push(receiver.recv_timeout(Duration::from_secs(30)).unwrap());
    }
    seen.sort_unstable();
    assert_eq!(seen, vec![(0, 1), (1, 2), (2, 3)]);
    assert_eq!(
        std::thread::spawn(block_instance).join().unwrap(),
        0,
        "an unregistered thread uses instance 0"
    );

    let block = arinsal_alloc::typed::AllocBlock::new(ErtsAlcType::HEAP, 4).unwrap();
    let (sender, receiver) = mpsc::channel();
    scheduler.request_aux_work(1, move || {
        let owned = AllocBlock::new(ErtsAlcType::HEAP, 4).unwrap();
        sender.send(owned).unwrap();
    });
    let owned = receiver.recv_timeout(Duration::from_secs(30)).unwrap();
    assert_eq!(owned.instance(), 2);
    drop(owned);
    drop(block);
    let (done, finished) = mpsc::channel();
    std::thread::spawn(move || {
        done.send(arinsal_alloc::typed::drain_owned_deallocations(2))
            .unwrap();
    });
    assert!(
        finished.recv_timeout(Duration::from_secs(30)).is_ok(),
        "the owner of instance 2 answers a drain request from this thread"
    );
}
