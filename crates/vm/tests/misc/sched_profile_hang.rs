//! A scheduler's active/inactive transition took the task cell of a process (to build the
//! `system_profile` scheduler message) and could wait for it forever: a monitor/demonitor loop
//! with microstate accounting on stopped after a few runs with every scheduler asleep. erts reads
//! one global flag in `profile_scheduler` and takes no process lock; this runs the loop ten times
//! on two schedulers under a time limit.

use arinsal_difftest::RefErl;
use arinsal_term::{Term, global_atoms};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const CHILD: &str = "ARINSAL_SCHED_PROFILE_HANG_CHILD";
const MODULE: &str = "sched_profile_hang";
const RUNS: usize = 10;
const OPS: i64 = 300_000;
const LIMIT: Duration = Duration::from_secs(240);

const SOURCE: &str = r#"-module(sched_profile_hang).
-export([run/1]).

run(N) ->
    P = spawn(fun() -> receive stop -> ok end end),
    erlang:system_flag(microstate_accounting, true),
    loop(P, N),
    erlang:system_flag(microstate_accounting, false),
    P ! stop,
    ok.

loop(_, 0) -> ok;
loop(P, N) ->
    R = monitor(process, P),
    demonitor(R),
    loop(P, N - 1).
"#;

fn child() -> bool {
    let Some(beam_path) = std::env::var_os(CHILD) else {
        return false;
    };
    let beam = std::fs::read(&beam_path).unwrap();
    for run in 0..RUNS {
        let mut vm = crate::common::node();
        vm.load_bytes(&beam).unwrap();
        let arg = Term::small(OPS).unwrap();
        vm.eval_scheduled(MODULE, "run", &[arg], 2)
            .expect("scheduled run");
        println!("RUN:{run}:done");
    }
    true
}

#[test]
fn monitor_demonitor_loop_with_msacc_does_not_hang() {
    if child() {
        return;
    }
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping sched_profile_hang test");
        return;
    };
    let beam = reference
        .compile_named(MODULE, SOURCE, &[])
        .expect("compile sched_profile_hang");
    let _ = global_atoms();
    let dir =
        std::env::temp_dir().join(format!("arinsal-sched-profile-hang-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(format!("{MODULE}.beam"));
    std::fs::write(&path, &beam).unwrap();
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "monitor_demonitor_loop_with_msacc_does_not_hang",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD, &path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break Some(status);
        }
        if started.elapsed() > LIMIT {
            // A hung child ignores SIGTERM like the hung runtime does: kill it by pid.
            let _ = child.kill();
            let _ = child.wait();
            break None;
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    let _ = std::fs::remove_dir_all(&dir);
    let status =
        status.expect("the monitor/demonitor loop with msacc did not finish: scheduler hang");
    assert!(status.success(), "child failed: {status}");
}
