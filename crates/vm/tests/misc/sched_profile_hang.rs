//! A scheduler's active/inactive transition took the task cell of a process (to build the
//! `system_profile` scheduler message) and could wait for it forever: a monitor/demonitor loop
//! with microstate accounting on stopped after a few runs with every scheduler asleep. erts reads
//! one global flag in `profile_scheduler` and takes no process lock; this runs the loop ten times
//! on two schedulers under a time limit.

use arinsal_difftest::RefErl;
use arinsal_term::{Term, global_atoms};
use std::process::Command;
use std::time::{Duration, Instant};

const CHILD: &str = "ARINSAL_SCHED_PROFILE_HANG_CHILD";
const MODULE: &str = "sched_profile_hang";
const RUNS: usize = 10;
const OPS: i64 = 300_000;
// Hang detector, not a native-speed SLA. qemu-user finishes ~7 of these
// 300k monitor/demonitor runs in 240s; erts also uses clock_gettime on arm.
const LIMIT: Duration = Duration::from_secs(540);

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
    let progress = std::path::Path::new(&beam_path).with_file_name("progress");
    let t0 = Instant::now();
    for run in 0..RUNS {
        std::fs::write(
            &progress,
            format!("start {run} {}\n", t0.elapsed().as_millis()),
        )
        .unwrap();
        arinsal_vm::Vm::request_eval_plus_s(2);
        let mut vm = crate::common::node();
        vm.load_bytes(&beam).unwrap();
        let arg = Term::small(OPS).unwrap();
        vm.eval_scheduled(MODULE, "run", &[arg], 2)
            .expect("scheduled run");
        std::fs::write(
            &progress,
            format!("done {run} {}\n", t0.elapsed().as_millis()),
        )
        .unwrap();
        println!("RUN:{run}:done {}", t0.elapsed().as_millis());
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
    let stdout_path = dir.join("child.stdout");
    let stderr_path = dir.join("child.stderr");
    let stdout = std::fs::File::create(&stdout_path).unwrap();
    let stderr = std::fs::File::create(&stderr_path).unwrap();
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "monitor_demonitor_loop_with_msacc_does_not_hang",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD, &path)
        .env("RUST_BACKTRACE", "1")
        .stdout(stdout)
        .stderr(stderr)
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
    let progress = std::fs::read_to_string(dir.join("progress")).unwrap_or_default();
    let child_stdout = std::fs::read_to_string(&stdout_path).unwrap_or_default();
    let child_stderr = std::fs::read_to_string(&stderr_path).unwrap_or_default();
    let _ = std::fs::remove_dir_all(&dir);
    let status = status.unwrap_or_else(|| {
        panic!(
            "the monitor/demonitor loop with msacc did not finish: scheduler hang\nprogress:{progress}\nstdout:\n{child_stdout}\nstderr:\n{child_stderr}"
        )
    });
    assert!(
        status.success(),
        "child failed: {status}\nprogress:{progress}\nstdout:\n{child_stdout}\nstderr:\n{child_stderr}"
    );
}
