//! Virtual reductions end a slice but are not work: no scheduler counter sees them.
// Port of erts/emulator/beam/erl_process.c:9678 (`reds = actual_reds = calls -
// esdp->virtual_reds`) and erl_process.h:529 (ERTS_PROC_REDUCTIONS_EXECUTED), OTP-29.1.1.

use arinsal_sched::{Config, Scheduler, Task};
use std::sync::mpsc;
use std::time::Duration;

struct Slice {
    consumed: u32,
    virtual_reds: u32,
    done: mpsc::Sender<()>,
}

impl Task for Slice {
    type Message = ();
    type SchedulerData = ();
    fn run(
        c_p: &mut arinsal_sched::CP<'_, Self>,
        esdp: &arinsal_sched::ErtsSchedulerData<Self>,
        _: u32,
        calls: &mut u32,
    ) {
        esdp.with_ctx(c_p, |this, ctx| {
            *calls = this.consumed;
            ctx.add_virtual_reds(this.virtual_reds);
            let _ = this.done.send(());
            {
                ctx.erts_proc_exit_free(this);
            }
        })
    }
}

fn reductions_of(consumed: u32, virtual_reds: u32) -> u64 {
    let scheduler = start_scheduler::<Slice>(Config {
        workers: 1,
        ..Config::default()
    });
    let before = scheduler.stats().reductions;
    let (done, finished) = mpsc::channel();
    scheduler
        .spawn(Slice {
            consumed,
            virtual_reds,
            done,
        })
        .unwrap();
    finished.recv_timeout(Duration::from_secs(10)).unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        let reductions = scheduler.stats().reductions - before;
        if reductions > 0 || std::time::Instant::now() > deadline {
            return reductions;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

// One case per test: erts has one runtime per OS process.
#[test]
fn virtual_reductions_are_not_counted() {
    assert_eq!(reductions_of(3000, 2900), 100);
}

#[test]
fn consumed_reductions_are_counted() {
    assert_eq!(reductions_of(3000, 0), 3000);
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
