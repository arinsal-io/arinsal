//! OS signal routing (`init_break_handler`, `erts_sys_unix_later_init`, `os:set_signal/2`)
//! against the installed OTP 29.1.1 emulator, `-noshell`, stdin at /dev/null.

use similar_asserts::assert_eq;
use std::io::{BufRead, BufReader, Read};
use std::os::unix::process::ExitStatusExt;
use std::process::{Command, Stdio};

const HANDLER: &str = "\
-module(sig_probe).
-behaviour(gen_event).
-export([init/1, handle_event/2, handle_call/2]).
init(_) -> {ok, []}.
handle_event(Ev, S) -> io:format(\"event ~p~n\", [Ev]), {ok, S}.
handle_call(_, S) -> {ok, S, S}.
";

type Outcome = (Option<i32>, Option<i32>, String);

/// Starts the emulator, waits for `ready` on stdout, delivers `signal`, and returns exit code,
/// terminating signal and the rest of stdout. A node that outlives its deadline is killed.
fn run(arinsal: bool, extra: &[&str], eval: &str, signal: &str) -> Outcome {
    let mut command = if arinsal {
        Command::new(env!("CARGO_BIN_EXE_arinsal"))
    } else {
        arinsal_difftest::reference::erl().expect("erl")
    };
    let mut child = command
        .args(extra)
        .args(["-noshell", "-eval", eval])
        .env("ERL_AFLAGS", "")
        .env("ERL_FLAGS", "")
        .env("ERL_ZFLAGS", "")
        .env("ERL_CRASH_DUMP", "/dev/null")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn emulator");
    let mut out = BufReader::new(child.stdout.take().expect("stdout"));
    let mut line = String::new();
    out.read_line(&mut line).expect("ready line");
    assert_eq!(line.trim(), "ready");
    Command::new("kill")
        .args([signal, &child.id().to_string()])
        .status()
        .expect("kill");
    let mut rest = String::new();
    let _ = out.read_to_string(&mut rest);
    let status = child.wait().expect("wait");
    // Report headers carry a timestamp.
    let rest = rest
        .lines()
        .filter(|l| !l.starts_with("=INFO REPORT===="))
        .collect::<Vec<_>>()
        .join("\n");
    (status.code(), status.signal(), rest)
}

fn both(extra: &[&str], eval: &str, signal: &str) -> Option<(Outcome, Outcome)> {
    arinsal_difftest::reference::erl()?;
    Some((
        run(false, extra, eval, signal),
        run(true, extra, eval, signal),
    ))
}

#[test]
fn sigquit_halts_through_erl_signal_server() {
    let eval = "io:format(\"ready~n\"), timer:sleep(20000), halt(3).";
    let Some((erl, ours)) = both(&[], eval, "-QUIT") else {
        eprintln!("erl unavailable; skipping");
        return;
    };
    assert_eq!(erl, ours);
    assert_eq!(erl.0, Some(0));
}

#[test]
fn sigterm_runs_init_stop() {
    let eval = "io:format(\"ready~n\"), timer:sleep(20000), halt(3).";
    let Some((erl, ours)) = both(&[], eval, "-TERM") else {
        eprintln!("erl unavailable; skipping");
        return;
    };
    assert_eq!(erl, ours);
    assert_eq!(erl.0, Some(0));
}

#[test]
fn sigterm_ignore_keeps_node_running() {
    let eval = "os:set_signal(sigterm, ignore), io:format(\"ready~n\"), timer:sleep(2000), \
                io:format(\"alive~n\"), init:stop().";
    let Some((erl, ours)) = both(&[], eval, "-TERM") else {
        eprintln!("erl unavailable; skipping");
        return;
    };
    assert_eq!(erl, ours);
    assert_eq!(erl.2.trim(), "alive");
}

#[test]
fn set_signal_handle_delivers_to_custom_handler() {
    let dir = std::env::temp_dir().join(format!("arinsal_ossig_{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("tmp dir");
    std::fs::write(dir.join("sig_probe.erl"), HANDLER).expect("write handler");
    let Some(root) = arinsal_difftest::reference::otp_root() else {
        eprintln!("erl unavailable; skipping");
        return;
    };
    assert!(
        Command::new(root.join("bin/erlc"))
            .current_dir(&dir)
            .arg("sig_probe.erl")
            .status()
            .expect("erlc")
            .success()
    );
    let pa = dir.to_str().expect("utf8 dir");
    // The default `erl_signal_handler` halts on sigusr1, so it is replaced by the probe.
    for (set, signal) in [
        ("sigusr1", "-USR1"),
        ("sigusr2", "-USR2"),
        ("sigwinch", "-WINCH"),
    ] {
        let eval = format!(
            "os:set_signal({set}, handle), \
             ok = gen_event:delete_handler(erl_signal_server, erl_signal_handler, []), \
             ok = gen_event:add_handler(erl_signal_server, sig_probe, []), \
             io:format(\"ready~n\"), timer:sleep(1500), halt(0)."
        );
        let Some((erl, ours)) = both(&["-pa", pa], &eval, signal) else {
            eprintln!("erl unavailable; skipping");
            break;
        };
        assert_eq!(erl, ours, "{set}");
        assert!(erl.2.contains(&format!("event {set}")), "{set}: {}", erl.2);
    }
    let _ = std::fs::remove_dir_all(&dir);
}
