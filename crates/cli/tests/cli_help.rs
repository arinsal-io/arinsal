use std::io::Write;
use std::process::{Command, Output, Stdio};

#[derive(Clone, Copy)]
enum Input {
    Null,
    ClosedPipe,
    Bytes(&'static [u8]),
}

fn run(program: &str, input: Input) -> Output {
    let mut command = Command::new("timeout");
    command.arg("15s").arg(program);
    command.stdin(match input {
        Input::Null => Stdio::null(),
        Input::ClosedPipe | Input::Bytes(_) => Stdio::piped(),
    });
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|error| panic!("start {program} under timeout: {error}"));
    if let Input::Bytes(bytes) = input {
        child.stdin.take().unwrap().write_all(bytes).unwrap();
    } else {
        drop(child.stdin.take());
    }
    child.wait_with_output().expect("wait for timed process")
}

fn output_without_build_banner(output: &Output) -> Vec<u8> {
    let newline = output
        .stdout
        .iter()
        .position(|byte| *byte == b'\n')
        .expect("runtime banner has a newline");
    output.stdout[newline + 1..].to_vec()
}

fn assert_matches_otp(input: Input) {
    let expected = run("erl", input_variant(&input));
    let actual = run(env!("CARGO_BIN_EXE_arinsal"), input);
    assert_eq!(expected.status.code(), Some(0), "OTP timed out or failed");
    assert_eq!(
        actual.status.code(),
        expected.status.code(),
        "Arinsal timed out or failed"
    );
    assert_eq!(
        output_without_build_banner(&actual),
        output_without_build_banner(&expected),
        "stdout after runtime banner"
    );
    assert_eq!(actual.stderr, expected.stderr, "stderr");
    let stdout = String::from_utf8_lossy(&actual.stdout);
    assert_eq!(
        stdout
            .matches("*** Terminating erlang (nonode@nohost)")
            .count(),
        1
    );
}

fn run_file(program: &str, path: &std::path::Path) -> Output {
    Command::new("timeout")
        .arg("15s")
        .arg(program)
        .stdin(Stdio::from(std::fs::File::open(path).unwrap()))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap_or_else(|error| panic!("start {program} under timeout: {error}"))
}

fn input_variant(input: &Input) -> Input {
    match input {
        Input::Null => Input::Null,
        Input::ClosedPipe => Input::ClosedPipe,
        Input::Bytes(bytes) => Input::Bytes(bytes),
    }
}

#[test]
fn cli_help_stdin_dev_null_matches_otp() {
    assert_matches_otp(Input::Null);
}

#[test]
fn cli_help_stdin_closed_pipe_matches_otp() {
    assert_matches_otp(Input::ClosedPipe);
}

#[test]
fn cli_help_stdin_command_then_eof_matches_otp() {
    assert_matches_otp(Input::Bytes(b"io:format(\"x~n\").\n"));
}

#[test]
fn cli_help_stdin_file_matches_otp() {
    let path = std::env::temp_dir().join(format!("arinsal-cli-help-{}.erl", std::process::id()));
    std::fs::write(&path, b"io:format(\"x~n\").\n").unwrap();
    let expected = run_file("erl", &path);
    let actual = run_file(env!("CARGO_BIN_EXE_arinsal"), &path);
    assert_eq!(expected.status.code(), Some(0), "OTP timed out or failed");
    assert_eq!(
        actual.status.code(),
        expected.status.code(),
        "Arinsal timed out or failed"
    );
    assert_eq!(
        output_without_build_banner(&actual),
        output_without_build_banner(&expected)
    );
    assert_eq!(actual.stderr, expected.stderr);
    std::fs::remove_file(path).unwrap();
}
