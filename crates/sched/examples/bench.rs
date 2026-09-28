//! Release-mode dummy-task benchmarks: `cargo run -r -p arinsal-sched --example bench -- all`.

use arinsal_sched::{Config, Pid, RunCtx, RunOutcome, Scheduler, Task};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

enum Mode {
    Forward(Pid),
    Sink,
    Burst(Pid, usize),
    Fanout {
        receivers: Vec<Pid>,
        remaining: usize,
        next: usize,
    },
    Idle(Arc<AtomicUsize>),
}

struct Dummy {
    mode: Mode,
    count: Arc<AtomicUsize>,
    limit: usize,
}

impl Task for Dummy {
    type Message = ();
    fn run(&mut self, ctx: &mut RunCtx<()>, _: u32) -> RunOutcome {
        match &mut self.mode {
            Mode::Forward(to) => {
                while ctx.receive().is_some() {
                    let n = self.count.fetch_add(1, Ordering::Relaxed) + 1;
                    if n < self.limit {
                        ctx.send(*to, ()).unwrap();
                    }
                    if !ctx.consume(4) {
                        return RunOutcome::Yield;
                    }
                }
            }
            Mode::Sink => {
                while ctx.receive().is_some() {
                    self.count.fetch_add(1, Ordering::Relaxed);
                    if !ctx.consume(1) {
                        return RunOutcome::Yield;
                    }
                }
            }
            Mode::Burst(to, count) => {
                while *count > 0 {
                    ctx.send(*to, ()).unwrap();
                    *count -= 1;
                    if !ctx.consume(4) {
                        return RunOutcome::Yield;
                    }
                }
                return RunOutcome::Exit(0);
            }
            Mode::Fanout {
                receivers,
                remaining,
                next,
            } => {
                while *remaining > 0 {
                    ctx.send(receivers[*next], ()).unwrap();
                    *remaining -= 1;
                    *next = (*next + 1) % receivers.len();
                    if !ctx.consume(4) {
                        return RunOutcome::Yield;
                    }
                }
                return RunOutcome::Exit(0);
            }
            Mode::Idle(started) => {
                started.fetch_add(1, Ordering::Relaxed);
            }
        }
        RunOutcome::Wait { timeout_ms: None }
    }
}

fn wait_for(count: &AtomicUsize, target: usize) {
    let deadline = Instant::now() + Duration::from_secs(120);
    while count.load(Ordering::Relaxed) < target {
        assert!(Instant::now() < deadline, "benchmark timed out");
        std::thread::sleep(Duration::from_micros(50));
    }
}

fn config(workers: usize, capacity: u32) -> Config {
    Config {
        workers,
        max_processes: capacity,
        ..Config::default()
    }
}

fn pingpong(workers: usize) {
    let count = Arc::new(AtomicUsize::new(0));
    let sched = Scheduler::new(config(workers, 2));
    let limit = 2_000_000;
    let a = Pid {
        index: 0,
        generation: 0,
    };
    let b = Pid {
        index: 1,
        generation: 0,
    };
    assert_eq!(
        sched
            .spawn(Dummy {
                mode: Mode::Forward(b),
                count: count.clone(),
                limit
            })
            .unwrap(),
        a
    );
    assert_eq!(
        sched
            .spawn(Dummy {
                mode: Mode::Forward(a),
                count: count.clone(),
                limit
            })
            .unwrap(),
        b
    );
    let cpu_before = usage().0;
    let start = Instant::now();
    sched.send(a, a, ()).unwrap();
    wait_for(&count, limit);
    let (cpu_after, rss) = usage();
    println!(
        "pingpong: {:.1} ns/round trip, {:.1} ms total, {:.1} ms CPU, {:.2} MiB RSS",
        start.elapsed().as_nanos() as f64 / (limit / 2) as f64,
        start.elapsed().as_secs_f64() * 1000.0,
        (cpu_after - cpu_before) / 1_000.0,
        rss as f64 / 1_048_576.0,
    );
}

fn ring(workers: usize) {
    let count = Arc::new(AtomicUsize::new(0));
    let sched = Scheduler::new(config(workers, 1_000));
    let limit = 2_000_000;
    for i in 0..1_000 {
        let next = Pid {
            index: (i + 1) % 1_000,
            generation: 0,
        };
        sched
            .spawn(Dummy {
                mode: Mode::Forward(next),
                count: count.clone(),
                limit,
            })
            .unwrap();
    }
    let first = Pid {
        index: 0,
        generation: 0,
    };
    let cpu_before = usage().0;
    let start = Instant::now();
    sched.send(first, first, ()).unwrap();
    wait_for(&count, limit);
    println!(
        "ring: {:.1} ns/hop, {:.1} ms total, {:.1} ms CPU, {:.2} MiB RSS",
        start.elapsed().as_nanos() as f64 / limit as f64,
        start.elapsed().as_secs_f64() * 1000.0,
        (usage().0 - cpu_before) / 1_000.0,
        usage().1 as f64 / 1_048_576.0,
    );
}

fn fanin(workers: usize) {
    let count = Arc::new(AtomicUsize::new(0));
    let sched = Scheduler::new(config(workers, 1_001));
    let sink = sched
        .spawn(Dummy {
            mode: Mode::Sink,
            count: count.clone(),
            limit: 0,
        })
        .unwrap();
    let cpu_before = usage().0;
    let start = Instant::now();
    for _ in 0..1_000 {
        sched
            .spawn(Dummy {
                mode: Mode::Burst(sink, 2_000),
                count: count.clone(),
                limit: 0,
            })
            .unwrap();
    }
    wait_for(&count, 2_000_000);
    println!(
        "fanin 1000->1: {:.1} ns/message, {:.1} ms total, {:.1} ms CPU, {:.2} MiB RSS",
        start.elapsed().as_nanos() as f64 / 2_000_000.0,
        start.elapsed().as_secs_f64() * 1000.0,
        (usage().0 - cpu_before) / 1_000.0,
        usage().1 as f64 / 1_048_576.0,
    );
}

fn fanout(workers: usize) {
    let count = Arc::new(AtomicUsize::new(0));
    let sched = Scheduler::new(config(workers, 1_001));
    let receivers: Vec<_> = (0..1_000)
        .map(|_| {
            sched
                .spawn(Dummy {
                    mode: Mode::Sink,
                    count: count.clone(),
                    limit: 0,
                })
                .unwrap()
        })
        .collect();
    let cpu_before = usage().0;
    let start = Instant::now();
    sched
        .spawn(Dummy {
            mode: Mode::Fanout {
                receivers,
                remaining: 1_000_000,
                next: 0,
            },
            count: count.clone(),
            limit: 0,
        })
        .unwrap();
    wait_for(&count, 1_000_000);
    println!(
        "fanout 1->1000: {:.1} ns/message, {:.1} ms total, {:.1} ms CPU, {:.2} MiB RSS",
        start.elapsed().as_nanos() as f64 / 1_000_000.0,
        start.elapsed().as_secs_f64() * 1000.0,
        (usage().0 - cpu_before) / 1_000.0,
        usage().1 as f64 / 1_048_576.0,
    );
}

fn startup(workers: usize) {
    let before = usage().1;
    let scheduler = Scheduler::<Dummy>::new(config(workers, 1_048_576));
    std::thread::sleep(Duration::from_millis(10));
    let after = usage().1;
    println!(
        "startup: {:.3} MiB RSS delta, {:.2} MiB total",
        after.saturating_sub(before) as f64 / 1_048_576.0,
        after as f64 / 1_048_576.0,
    );
    drop(scheduler);
}

fn usage() -> (f64, u64) {
    // SAFETY: getrusage initializes the passed POD structure before it is read.
    let mut value: libc::rusage = unsafe { std::mem::zeroed() };
    // SAFETY: the pointer is valid and exclusively borrowed for this call.
    assert_eq!(unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut value) }, 0);
    let micros = |time: libc::timeval| time.tv_sec as f64 * 1_000_000.0 + time.tv_usec as f64;
    let rss = value.ru_maxrss as u64;
    (micros(value.ru_utime) + micros(value.ru_stime), rss)
}

fn idle() {
    let count = Arc::new(AtomicUsize::new(0));
    let baseline_rss = usage().1;
    let sched = Scheduler::new(config(8, 1_000_000));
    let start = Instant::now();
    for _ in 0..1_000_000 {
        sched
            .spawn(Dummy {
                mode: Mode::Idle(count.clone()),
                count: count.clone(),
                limit: 0,
            })
            .unwrap();
    }
    wait_for(&count, 1_000_000);
    let (_, rss) = usage();
    println!(
        "idle 1M: {:.1} MiB peak RSS, {:.0} bytes/task above baseline, {:.1} ms spawn+settle",
        rss as f64 / 1_048_576.0,
        rss.saturating_sub(baseline_rss) as f64 / 1_000_000.0,
        start.elapsed().as_secs_f64() * 1000.0
    );
    let before = usage().0;
    std::thread::sleep(Duration::from_secs(2));
    let cpu_ms = (usage().0 - before) / 1_000.0;
    println!(
        "idle CPU: {:.2}% over 2 s ({cpu_ms:.2} ms process CPU)",
        cpu_ms / 2000.0 * 100.0
    );
}

fn main() {
    let mut args = std::env::args().skip(1);
    let name = args.next().unwrap_or_else(|| "all".into());
    let workers = args
        .next()
        .map_or(4, |value| value.parse().expect("worker count"));
    match name.as_str() {
        "pingpong" => pingpong(workers),
        "ring" => ring(workers),
        "fanin" => fanin(workers),
        "fanout" => fanout(workers),
        "startup" => startup(workers),
        "idle" => idle(),
        "all" => {
            pingpong(workers);
            ring(workers);
            fanin(workers);
            fanout(workers);
            idle();
        }
        _ => panic!("unknown benchmark: {name}"),
    }
}
