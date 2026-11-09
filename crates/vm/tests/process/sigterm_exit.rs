//! SIGTERM reaches `erl_signal_server`, whose default handler stops the node: a node blocked
//! in a receive exits with the status `erl` exits with when `timeout` sends it SIGTERM.
//! Port of erts/emulator/sys/unix/sys.c (signal_notify_requested) and
//! lib/kernel/src/erl_signal_handler.erl, OTP-29.1.1.

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Instant;

fn shim_dir() -> PathBuf {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let binary = root.join("target/release/arinsal");
    assert!(binary.is_file(), "build target/release/arinsal first");
    let dir = std::env::temp_dir().join(format!("arinsal-sigterm-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let link = dir.join("erl");
    let _ = std::fs::remove_file(&link);
    #[cfg(unix)]
    std::os::unix::fs::symlink(binary.canonicalize().unwrap(), &link).unwrap();
    dir
}

fn run(shim: Option<&PathBuf>, expression: &str) -> (Option<i32>, f64) {
    let mut path = Vec::new();
    if let Some(dir) = shim {
        path.push(dir.clone());
    }
    path.extend(std::env::split_paths(
        &std::env::var_os("PATH").unwrap_or_default(),
    ));
    let started = Instant::now();
    let status = Command::new("timeout")
        .args([
            "--preserve-status",
            "-k",
            "4",
            "3",
            "erl",
            "-noshell",
            "-eval",
            expression,
        ])
        .env("PATH", std::env::join_paths(path).unwrap())
        .env_remove("ERL_ROOTDIR")
        .env_remove("ARINSAL_OTP_ROOT")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("run timeout");
    (status.code(), started.elapsed().as_secs_f64())
}

#[test]
fn sigterm_matches_erts_when_the_vm_is_stalled() {
    let shim = shim_dir();
    let cases = [
        ("blocked receive", "receive after infinity -> ok end"),
        (
            "all schedulers busy",
            "N=erlang:system_info(schedulers_online), [spawn(fun F()->F() end) || _ <- lists:seq(1,N)], receive after infinity -> ok end",
        ),
        (
            "blocked code server",
            "R=sys:suspend(code_server), receive after infinity -> {ok,R} end",
        ),
    ];

    for (name, expression) in cases {
        let (reference, reference_elapsed) = run(None, expression);
        let (arinsal, arinsal_elapsed) = run(Some(&shim), expression);
        similar_asserts::assert_eq!(arinsal, reference, "{name}: exit status after SIGTERM");
        assert!(
            (arinsal_elapsed - reference_elapsed).abs() < 2.0,
            "{name}: Arinsal took {arinsal_elapsed:.2}s, erts took {reference_elapsed:.2}s"
        );
        assert!(
            arinsal_elapsed < 8.0,
            "{name}: SIGTERM was ignored for {arinsal_elapsed:.2}s"
        );
    }
}
