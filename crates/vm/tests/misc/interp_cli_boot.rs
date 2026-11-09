//! The Arinsal CLI boots under `ARINSAL_INTERP=1` as it does under the JIT.
//!
//! The kernel starts the `user` process, which loads the line editor (`edlin`, `edlin_key`)
//! while the system boots. A module that failed to load there left `edlin_key:get_key_map/0`
//! undefined and the node without a `user` process, also for a plain `halt().`.

use std::io::Write;
use std::path::Path;
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

const DEADLINE: Duration = Duration::from_secs(120);

fn arinsal() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/debug/arinsal")
}

fn command(args: &[&str]) -> Command {
    let mut command = Command::new(arinsal());
    command
        .args(args)
        .env("ARINSAL_INTERP", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

fn finish(mut child: Child, input: &str) -> Output {
    let mut stdin = child.stdin.take().expect("stdin pipe");
    stdin.write_all(input.as_bytes()).expect("write stdin");
    drop(stdin);
    let start = Instant::now();
    loop {
        if child.try_wait().expect("try_wait").is_some() {
            return child.wait_with_output().expect("output");
        }
        if start.elapsed() > DEADLINE {
            child.kill().expect("kill");
            let output = child.wait_with_output().expect("output");
            panic!(
                "no exit within {DEADLINE:?}: {} {}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn run(args: &[&str], input: &str) -> (Output, String, String) {
    let output = finish(command(args).spawn().expect("spawn arinsal"), input);
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    (output, stdout, stderr)
}

fn assert_clean_boot(label: &str, output: &Output, stdout: &str, stderr: &str) {
    assert!(
        output.status.success(),
        "{label}: exit {:?}\nstdout: {stdout}\nstderr: {stderr}",
        output.status
    );
    for text in [stdout, stderr] {
        for marker in [
            "undef",
            "could not be loaded",
            "ERROR REPORT",
            "CRASH REPORT",
        ] {
            assert!(
                !text.contains(marker),
                "{label}: `{marker}` in output\nstdout: {stdout}\nstderr: {stderr}"
            );
        }
    }
}

const EVAL: &str =
    "io:format(\"~p ~p~n\",[erlang:system_info(emu_flavor),lists:sum(lists:seq(1,100))]),halt().";

#[test]
fn halt_boots_under_the_interpreter() {
    let (output, stdout, stderr) = run(&["-noshell", "-eval", "halt()."], "");
    assert_clean_boot("halt", &output, &stdout, &stderr);
    assert_eq!(stdout, "");
}

#[test]
fn eval_runs_under_the_interpreter() {
    let (output, stdout, stderr) = run(&["-noshell", "-eval", EVAL], "");
    assert_clean_boot("eval", &output, &stdout, &stderr);
    assert_eq!(stdout, "emu 5050\n");
}

#[test]
fn eval_runs_on_one_scheduler() {
    let (output, stdout, stderr) = run(&["+S1:1", "-noshell", "-eval", EVAL], "");
    assert_clean_boot("one scheduler", &output, &stdout, &stderr);
    assert_eq!(stdout, "emu 5050\n");
}

#[test]
fn edlin_key_loads_under_the_interpreter() {
    let eval = "io:format(\"~p~n\",[is_map(edlin_key:get_key_map())]),halt().";
    let (output, stdout, stderr) = run(&["-noshell", "-eval", eval], "");
    assert_clean_boot("edlin_key", &output, &stdout, &stderr);
    assert_eq!(stdout, "true\n");
}

#[test]
fn shell_over_a_pipe_runs_under_the_interpreter() {
    let (output, stdout, stderr) = run(
        &[],
        "io:format(\"sum=~p~n\",[lists:sum(lists:seq(1,100))]).\nhalt().\n",
    );
    assert_clean_boot("shell", &output, &stdout, &stderr);
    assert!(stdout.contains("Eshell"), "no shell banner: {stdout}");
    assert!(stdout.contains("sum=5050"), "no shell result: {stdout}");
}

#[test]
fn shell_with_stdin_closed_boots_under_the_interpreter() {
    let (_, stdout, stderr) = run(&[], "");
    assert!(
        !stdout.contains("undef") && !stderr.contains("undef"),
        "stdout: {stdout}\nstderr: {stderr}"
    );
    for marker in ["could not be loaded", "ERROR REPORT", "CRASH REPORT"] {
        assert!(
            !stdout.contains(marker) && !stderr.contains(marker),
            "`{marker}`\nstdout: {stdout}\nstderr: {stderr}"
        );
    }
}
