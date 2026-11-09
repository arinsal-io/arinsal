//! A socket closed while it has a pending select must leave the caller intact and the
//! per-iteration cost flat.
//!
//! `socket:close/1` ends in the dirty NIF `nif_finalize_close`. The abort message that
//! closing a pending `recvfrom(nowait)` sends to the caller (never received here, as in
//! erts) leaves signals queued for the caller when it is scheduled on a dirty scheduler.
//! Handling them used to yield the caller to a normal scheduler with its dirty NIF still
//! pending: it then resumed the dirty-NIF dispatch stub as an unresolved export and entered
//! `error_handler:undefined_function/3` with the socket reference as the module, after
//! some 15,000 iterations. The mailbox of abort messages, each carrying the socket
//! reference, also made every collection scan all retained magic references.
//!
//! The case runs a child `arinsal`; everything binds to 127.0.0.1.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

fn arinsal() -> PathBuf {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/debug/arinsal");
    assert!(path.is_file(), "build target/debug/arinsal first");
    path
}

const BATCHES: usize = 6;
const PER_BATCH: usize = 4000;

#[test]
fn pending_select_close_loop_keeps_the_caller_intact_and_flat() {
    let eval = format!(
        "T = fun() -> lists:foreach(fun(_) -> \
            {{ok, S}} = socket:open(inet, dgram, udp), \
            ok = socket:bind(S, #{{family => inet, addr => {{127,0,0,1}}, port => 0}}), \
            {{select, _}} = socket:recvfrom(S, 0, nowait), \
            ok = socket:close(S) \
         end, lists:seq(1, {PER_BATCH})) end, \
         lists:foreach(fun(_) -> {{Us, _}} = timer:tc(T), io:format(\"~p~n\", [Us]) end, \
                       lists:seq(1, {BATCHES})), \
         io:format(\"done~n\"), halt()."
    );
    let mut child = Command::new(arinsal())
        .args(["-noshell", "-eval", &eval])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn arinsal");
    let started = std::time::Instant::now();
    let deadline = Duration::from_secs(300);
    let status = loop {
        if let Some(status) = child.try_wait().expect("try_wait") {
            break status;
        }
        if started.elapsed() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("the select/close loop did not finish within {deadline:?}");
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    let output = child.wait_with_output().expect("output");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        status.success() && stdout.trim_end().ends_with("done"),
        "arinsal exited with {status}\nstdout: {stdout}\nstderr: {stderr}"
    );
    let batches: Vec<u64> = stdout
        .lines()
        .filter_map(|line| line.trim().parse().ok())
        .collect();
    assert_eq!(batches.len(), BATCHES, "batch timings in {stdout:?}");
    // The per-iteration cost grew from 3.8 s to 20 s per 1000 iterations before the fix.
    let first = batches[0];
    let last = batches[BATCHES - 1];
    assert!(
        last < first.saturating_mul(4),
        "the cost per iteration is not flat: {batches:?} microseconds per {PER_BATCH}"
    );
}
