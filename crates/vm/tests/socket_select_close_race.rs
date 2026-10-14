//! A socket select must be ordered against `socket:close` by the per-socket lock.
//!
//! In erts the descriptor mutex orders `enif_select` (recv, accept, send, connect) against
//! close and stop: a request on a socket that is closing fails with `closed`, and the
//! descriptor is closed only after the select machinery let go of it. Each case runs child
//! `arinsal` processes that loop thousands of cycles where one process starts a request and
//! registers a select while another process closes the same socket (127.0.0.1 only). A
//! child that does not exit within the deadline is signalled and the test fails without
//! waiting for it.

use arinsal_difftest::RefErl;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const CHILDREN: usize = 3;
const DEADLINE: Duration = Duration::from_secs(240);
const SOURCE: &str = include_str!("fixtures/sock_race.erl");

fn arinsal() -> PathBuf {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/debug/arinsal");
    assert!(path.is_file(), "build target/debug/arinsal first");
    path
}

fn run_children(function: &str, cycles: u32) {
    // The cases share the per-user thread limit of the machine: run one at a time.
    static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _serial = SERIAL.lock().unwrap_or_else(|poison| poison.into_inner());
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping socket select/close race test");
        return;
    };
    let beam = reference
        .compile_named("sock_race", SOURCE, &[])
        .unwrap_or_else(|error| panic!("compile sock_race: {error:?}"));
    let dir = std::env::temp_dir().join(format!("sock_race_{}_{function}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("sock_race.beam"), beam).unwrap();
    let eval = format!("sock_race:{function}({cycles}), halt().");
    let mut children: Vec<Child> = (0..CHILDREN)
        .map(|_| {
            Command::new(arinsal())
                .args(["+S", "2:2", "-noshell", "-pa"])
                .arg(&dir)
                .args(["-eval", &eval])
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
            let stuck: Vec<u32> = children
                .iter_mut()
                .zip(&finished)
                .filter(|(_, status)| status.is_none())
                .map(|(child, _)| {
                    let _ = child.kill();
                    child.id()
                })
                .collect();
            let _ = std::fs::remove_dir_all(&dir);
            panic!("arinsal children {stuck:?} did not exit within {DEADLINE:?}");
        }
        for (child, status) in children.iter_mut().zip(finished.iter_mut()) {
            if status.is_none() {
                *status = child.try_wait().expect("try_wait");
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = std::fs::remove_dir_all(&dir);
    for status in finished.into_iter().flatten() {
        assert!(status.success(), "arinsal exited with {status}");
    }
}

#[test]
fn accept_select_races_close() {
    run_children("accept", 2000);
}

#[test]
fn recvfrom_select_races_close() {
    run_children("recvfrom", 2000);
}

#[test]
fn recv_select_races_close() {
    run_children("recv", 1000);
}

#[test]
fn send_select_races_close() {
    run_children("send", 500);
}

#[test]
fn connect_select_races_close() {
    run_children("connect", 2000);
}
