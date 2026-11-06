//! Virtual reductions end a slice but are not work: no scheduler counter sees them.
// Port of erts/emulator/beam/erl_process.c:9678 (`reds = actual_reds = calls -
// esdp->virtual_reds`) and erl_process.h:529 (ERTS_PROC_REDUCTIONS_EXECUTED), OTP-29.1.1.

use arinsal_sched::{Config, RunCtx, RunOutcome, Scheduler, Task};
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
    fn run(&mut self, ctx: &mut RunCtx<()>, _: &mut (), _: u32) -> RunOutcome {
        ctx.consume(self.consumed);
        ctx.add_virtual_reds(self.virtual_reds);
        let _ = self.done.send(());
        RunOutcome::Exit(0)
    }
}

fn reductions_of(consumed: u32, virtual_reds: u32) -> u64 {
    let scheduler = Scheduler::<Slice>::new(Config {
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

#[test]
fn virtual_reductions_are_not_counted() {
    assert_eq!(reductions_of(3000, 2900), 100);
    assert_eq!(reductions_of(3000, 0), 3000);
}
