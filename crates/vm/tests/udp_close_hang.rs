//! Closing a `udp_inet` socket must not race the poll thread.
//!
//! The UDP driver used to take its socket in and out of the shared poll set with
//! one-shot waits and closed the descriptor without deselecting it first. A close that
//! raced the poll thread's `kevent` for the same descriptor never returned on macOS: the
//! closing thread stayed in `close(2)`, the process could not exit and became an
//! unkillable `?E` process after SIGKILL. erts deselects the descriptor before it is
//! closed (`driver_select` with `ERL_DRV_USE` off, then `inet_stop_select`).

use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const CYCLES: usize = 20000;
const CHILDREN: usize = 6;
const DEADLINE: Duration = Duration::from_secs(90);

fn arinsal() -> std::path::PathBuf {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/debug/arinsal");
    assert!(path.is_file(), "build target/debug/arinsal first");
    path
}

#[test]
fn concurrent_gen_udp_open_close_loops_finish() {
    let eval = format!(
        "lists:foreach(fun(_) -> {{ok, S}} = gen_udp:open(0, []), ok = gen_udp:close(S) end, \
                       lists:seq(1, {CYCLES})), \
         halt()."
    );
    let mut children: Vec<_> = (0..CHILDREN)
        .map(|_| {
            Command::new(arinsal())
                .args(["+S", "2:2", "-noshell", "-eval", &eval])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("spawn arinsal")
        })
        .collect();
    let started = Instant::now();
    let mut finished = vec![None; CHILDREN];
    while finished.iter().any(Option::is_none) {
        if started.elapsed() > DEADLINE {
            // A child stuck in close(2) cannot be reaped: signal it and fail without waiting.
            let stuck: Vec<u32> = children
                .iter_mut()
                .zip(&finished)
                .filter(|(_, status)| status.is_none())
                .map(|(child, _)| {
                    let _ = child.kill();
                    child.id()
                })
                .collect();
            panic!("arinsal children {stuck:?} did not exit within {DEADLINE:?}");
        }
        for (child, status) in children.iter_mut().zip(finished.iter_mut()) {
            if status.is_none() {
                *status = child.try_wait().expect("try_wait");
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    for status in finished.into_iter().flatten() {
        assert!(status.success(), "arinsal exited with {status}");
    }
}
