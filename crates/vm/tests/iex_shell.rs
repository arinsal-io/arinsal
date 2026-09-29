use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::OnceLock;

fn shim_dir() -> &'static Path {
    static SHIM: OnceLock<PathBuf> = OnceLock::new();
    SHIM.get_or_init(|| {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
        let binary = root.join("target/release/arinsal");
        assert!(binary.is_file(), "build target/release/arinsal first");
        let dir = std::env::temp_dir().join(format!("arinsal-iex-shell-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(binary.canonicalize().unwrap(), dir.join("erl")).unwrap();
        dir
    })
}

fn env_path(shim: bool) -> String {
    let base = std::env::var_os("PATH").unwrap_or_default();
    let mut paths = Vec::new();
    if shim {
        paths.push(shim_dir().to_path_buf());
    }
    paths.extend(std::env::split_paths(&base));
    std::env::join_paths(paths)
        .unwrap()
        .to_string_lossy()
        .into_owned()
}

fn run(args: &[&str], input: &str, path: String, cwd: Option<&Path>) -> Output {
    let mut command = Command::new("/bin/sh");
    command
        .arg("-c")
        .arg("ulimit -u 1200; exec timeout 120 iex \"$@\"")
        .arg("iex_shell_test")
        .args(args)
        .env("PATH", path)
        .env_remove("ERL_ROOTDIR")
        .env_remove("ARINSAL_OTP_ROOT")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(cwd) = cwd {
        command.current_dir(cwd);
    }
    let mut child = command.spawn().expect("start capped IEx launcher");
    child
        .stdin
        .take()
        .expect("piped stdin")
        .write_all(input.as_bytes())
        .expect("write IEx input");
    child
        .wait_with_output()
        .expect("wait for capped IEx launcher")
}

fn normalized(stdout: &[u8]) -> String {
    let text = String::from_utf8_lossy(stdout).replace("\r\n", "\n");
    text.lines()
        .filter(|line| !line.starts_with("Erlang/OTP "))
        .collect::<Vec<_>>()
        .join("\n")
}

fn assert_success(output: &Output, label: &str) {
    assert!(
        output.status.success(),
        "{label} exited {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn iex_shell_piped_expressions_multiline_and_raise_match_otp() {
    let input = "x = Enum.sum(1..10)\nIO.puts(\"sum=#{x}\")\ncase [1, 2] do\n  [a, b] -> a + b\nend\nraise \"x\"\n";
    let reference = run(&[], input, env_path(false), None);
    let arinsal = run(&[], input, env_path(true), None);
    assert_success(&reference, "OTP IEx");
    assert_success(&arinsal, "Arinsal IEx");
    assert_eq!(normalized(&arinsal.stdout), normalized(&reference.stdout));
    assert!(String::from_utf8_lossy(&arinsal.stdout).contains("sum=55"));
}

#[test]
fn iex_shell_help_without_tab_matches_otp() {
    let input = "h Enum.map\nSystem.halt(0)\n";
    let reference = run(&[], input, env_path(false), None);
    let arinsal = run(&[], input, env_path(true), None);
    assert_success(&reference, "OTP IEx");
    assert_success(&arinsal, "Arinsal IEx");
    assert_eq!(normalized(&arinsal.stdout), normalized(&reference.stdout));
    assert!(String::from_utf8_lossy(&arinsal.stdout).contains("Enum.map"));
}

#[test]
fn iex_shell_eof_exit_status_matches_otp() {
    let reference = run(&[], "", env_path(false), None);
    let arinsal = run(&[], "", env_path(true), None);
    assert_success(&reference, "OTP IEx EOF");
    assert_eq!(arinsal.status.code(), reference.status.code());
    assert_eq!(normalized(&arinsal.stdout), normalized(&reference.stdout));
}

#[test]
fn iex_shell_pty_banner_and_prompts_match_otp() {
    fn pty(path: String) -> Output {
        let mut child = Command::new("/bin/sh")
            .arg("-c")
            .arg("ulimit -u 1200; exec timeout 120 script -q /dev/null iex")
            .env("PATH", path)
            .env_remove("ERL_ROOTDIR")
            .env_remove("ARINSAL_OTP_ROOT")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("start capped PTY launcher");
        let mut stdin = child.stdin.take().unwrap();
        let mut stdout = child.stdout.take().unwrap();
        let mut captured = Vec::new();
        read_until(&mut stdout, &mut captured, "iex(1)> ");
        stdin.write_all(b"IO.puts(:pty_ok)\n").unwrap();
        read_until(&mut stdout, &mut captured, "iex(2)> ");
        stdin.write_all(b"System.halt(0)\n").unwrap();
        drop(stdin);
        let status = child.wait().expect("wait for PTY launcher");
        stdout.read_to_end(&mut captured).unwrap();
        let mut stderr = Vec::new();
        child
            .stderr
            .take()
            .unwrap()
            .read_to_end(&mut stderr)
            .unwrap();
        Output {
            status,
            stdout: captured,
            stderr,
        }
    }
    fn read_until(stdout: &mut impl Read, captured: &mut Vec<u8>, marker: &str) {
        let marker = marker.as_bytes();
        let mut byte = [0];
        while !captured.ends_with(marker) {
            if stdout.read(&mut byte).expect("read PTY output") == 0 {
                break;
            }
            captured.push(byte[0]);
        }
        assert!(
            captured.ends_with(marker),
            "PTY closed before {}: {}",
            String::from_utf8_lossy(marker),
            String::from_utf8_lossy(captured)
        );
    }
    let reference = pty(env_path(false));
    let arinsal = pty(env_path(true));
    assert_success(&reference, "OTP IEx PTY");
    assert_success(&arinsal, "Arinsal IEx PTY");
    assert_eq!(arinsal.status.code(), reference.status.code());
    let reference = normalized(&reference.stdout);
    let arinsal = normalized(&arinsal.stdout);
    assert!(reference.contains("Interactive Elixir"));
    assert!(arinsal.contains("Interactive Elixir"));
    assert!(arinsal.contains("iex(1)>"));
    for marker in [
        "Interactive Elixir",
        "iex(1)> ",
        "IO.puts(:pty_ok)",
        "pty_ok",
        "iex(2)> ",
    ] {
        assert!(reference.contains(marker), "OTP PTY lacks {marker:?}");
        assert!(arinsal.contains(marker), "Arinsal PTY lacks {marker:?}");
    }
}

#[test]
fn iex_shell_mix_project_starts_and_evaluates() {
    fn project(suffix: &str) -> PathBuf {
        let project =
            std::env::temp_dir().join(format!("iex-shell-mix-{}-{suffix}", std::process::id()));
        std::fs::create_dir_all(project.join("lib")).unwrap();
        std::fs::write(
            project.join("mix.exs"),
            "defmodule IexShellMix.MixProject do\n  use Mix.Project\n  def project, do: [app: :iex_shell_mix, version: \"0.1.0\", deps: []]\nend\n",
        )
        .unwrap();
        std::fs::write(
            project.join(".tool-versions"),
            "erlang 29.1.1\nelixir 1.20.4-otp-29\n",
        )
        .unwrap();
        project
    }
    let reference_project = project("otp");
    let arinsal_project = project("arinsal");
    let reference = run(
        &["-S", "mix"],
        "IO.puts(:mix_ok)\nSystem.halt(0)\n",
        env_path(false),
        Some(&reference_project),
    );
    let arinsal = run(
        &["-S", "mix"],
        "IO.puts(:mix_ok)\nSystem.halt(0)\n",
        env_path(true),
        Some(&arinsal_project),
    );
    assert_success(&reference, "OTP IEx -S mix");
    assert_success(&arinsal, "Arinsal IEx -S mix");
    assert_eq!(arinsal.status.code(), reference.status.code());
    assert_eq!(normalized(&arinsal.stdout), normalized(&reference.stdout));
    assert!(String::from_utf8_lossy(&arinsal.stdout).contains("mix_ok"));
}
