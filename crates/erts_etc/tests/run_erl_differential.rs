use std::fs;
use std::io::{Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

const OTP_ROOTS: [&str; 2] = [
    "$HOME/.asdf/installs/erlang/29.1.1",
    "/home/ubuntu/.asdf/installs/erlang/29.1.1",
];

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct PidGuard {
    pid: u32,
    active: bool,
}

impl Drop for PidGuard {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        let _ = Command::new("/bin/kill")
            .args(["-KILL", &self.pid.to_string()])
            .status();
    }
}

impl PidGuard {
    fn kill(&mut self) {
        let _ = Command::new("/bin/kill")
            .args(["-KILL", &self.pid.to_string()])
            .status();
        self.active = false;
    }

    fn disarm(&mut self) {
        self.active = false;
    }
}

#[test]
fn run_erl_and_to_erl_match_otp_with_cat() {
    let root = std::env::temp_dir().join(format!("erts_etc_pty_{}", std::process::id()));
    let pipe_name = root.join("session.pipe");
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    let reference = run_session(
        &otp_program("run_erl"),
        &otp_program("to_erl"),
        &pipe_name,
        &root.join("otp_logs"),
    );
    let arinsal = run_session(
        Path::new(env!("CARGO_BIN_EXE_arinsal_run_erl")),
        Path::new(env!("CARGO_BIN_EXE_arinsal_to_erl")),
        &pipe_name,
        &root.join("arinsal_logs"),
    );
    similar_asserts::assert_eq!(reference.output, arinsal.output);
    similar_asserts::assert_eq!(reference.to_stderr, arinsal.to_stderr);
    similar_asserts::assert_eq!(reference.run_status, arinsal.run_status);
    similar_asserts::assert_eq!(reference.to_status, arinsal.to_status);
    similar_asserts::assert_eq!(reference.logs, arinsal.logs);
    similar_asserts::assert_eq!(reference.status, arinsal.status);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn run_erl_log_rotation_matches_otp() {
    let root = std::env::temp_dir().join(format!("erts_etc_rotation_{}", std::process::id()));
    let pipe_directory = root.join("pipes");
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&pipe_directory).unwrap();
    let pipe_name = PathBuf::from(format!("{}/", pipe_directory.display()));
    let reference = run_session_configured(
        &otp_program("run_erl"),
        &otp_program("to_erl"),
        &pipe_name,
        &root.join("otp_logs"),
        1000,
        true,
        false,
    );
    let arinsal = run_session_configured(
        Path::new(env!("CARGO_BIN_EXE_arinsal_run_erl")),
        Path::new(env!("CARGO_BIN_EXE_arinsal_to_erl")),
        &pipe_name,
        &root.join("arinsal_logs"),
        1000,
        true,
        false,
    );
    similar_asserts::assert_eq!(reference.output, arinsal.output);
    similar_asserts::assert_eq!(reference.to_stderr, arinsal.to_stderr);
    similar_asserts::assert_eq!(reference.run_status, arinsal.run_status);
    similar_asserts::assert_eq!(reference.to_status, arinsal.to_status);
    assert!(reference.logs.len() > 1, "OTP run_erl did not rotate logs");
    assert!(
        arinsal.logs.len() > 1,
        "Arinsal run_erl did not rotate logs"
    );
    for (_, log) in reference.logs.iter().chain(arinsal.logs.iter()) {
        assert!(log.starts_with(b"\n=====\n===== LOGGING STARTED <time>\n=====\n"));
    }
    let _ = fs::remove_dir_all(root);
}

#[test]
fn run_erl_daemon_mode_matches_otp_with_cat() {
    let root = std::env::temp_dir().join(format!("erts_etc_daemon_{}", std::process::id()));
    let pipe_name = root.join("session.pipe");
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    let reference = run_session_configured(
        &otp_program("run_erl"),
        &otp_program("to_erl"),
        &pipe_name,
        &root.join("otp_logs"),
        100_000,
        false,
        true,
    );
    let arinsal = run_session_configured(
        Path::new(env!("CARGO_BIN_EXE_arinsal_run_erl")),
        Path::new(env!("CARGO_BIN_EXE_arinsal_to_erl")),
        &pipe_name,
        &root.join("arinsal_logs"),
        100_000,
        false,
        true,
    );
    similar_asserts::assert_eq!(reference.output, arinsal.output);
    similar_asserts::assert_eq!(reference.to_stderr, arinsal.to_stderr);
    similar_asserts::assert_eq!(reference.run_status, arinsal.run_status);
    similar_asserts::assert_eq!(reference.to_status, arinsal.to_status);
    similar_asserts::assert_eq!(reference.logs, arinsal.logs);
    similar_asserts::assert_eq!(reference.status, arinsal.status);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn run_erl_and_to_erl_argument_errors_match_otp() {
    let reference_run_erl = otp_program("run_erl");
    let arinsal_run_erl = Path::new(env!("CARGO_BIN_EXE_arinsal_run_erl"));
    let reference = Command::new(&reference_run_erl)
        .arg0("run_erl")
        .env_clear()
        .output()
        .unwrap();
    let arinsal = Command::new(arinsal_run_erl)
        .arg0("run_erl")
        .env_clear()
        .output()
        .unwrap();
    similar_asserts::assert_eq!(reference.status.code(), arinsal.status.code());
    similar_asserts::assert_eq!(reference.stderr, arinsal.stderr);

    let reference_to_erl = otp_program("to_erl");
    let arinsal_to_erl = Path::new(env!("CARGO_BIN_EXE_arinsal_to_erl"));
    let reference = Command::new(&reference_to_erl)
        .arg0("to_erl")
        .arg("-q")
        .env_clear()
        .output()
        .unwrap();
    let arinsal = Command::new(arinsal_to_erl)
        .arg0("to_erl")
        .arg("-q")
        .env_clear()
        .output()
        .unwrap();
    similar_asserts::assert_eq!(reference.status.code(), arinsal.status.code());
    similar_asserts::assert_eq!(reference.stderr, arinsal.stderr);

    let missing_pipe =
        std::env::temp_dir().join(format!("erts_etc_missing_{}", std::process::id()));
    let reference = Command::new(&reference_to_erl)
        .arg0("to_erl")
        .arg(&missing_pipe)
        .env_clear()
        .output()
        .unwrap();
    let arinsal = Command::new(arinsal_to_erl)
        .arg0("to_erl")
        .arg(&missing_pipe)
        .env_clear()
        .output()
        .unwrap();
    similar_asserts::assert_eq!(reference.status.code(), arinsal.status.code());
    similar_asserts::assert_eq!(reference.stderr, arinsal.stderr);
}

struct SessionResult {
    output: Vec<u8>,
    to_stderr: Vec<u8>,
    run_status: Option<i32>,
    to_status: Option<i32>,
    logs: Vec<(String, Vec<u8>)>,
    status: Vec<u8>,
}

fn run_session(
    run_erl: &Path,
    to_erl: &Path,
    pipe_name: &Path,
    log_directory: &Path,
) -> SessionResult {
    run_session_configured(
        run_erl,
        to_erl,
        pipe_name,
        log_directory,
        100_000,
        false,
        false,
    )
}

fn run_session_configured(
    run_erl: &Path,
    to_erl: &Path,
    pipe_name: &Path,
    log_directory: &Path,
    max_log_size: u32,
    exercise_rotation: bool,
    daemon: bool,
) -> SessionResult {
    fs::create_dir_all(log_directory).unwrap();
    let actual_pipe_name = if pipe_name.as_os_str().as_bytes().last() == Some(&b'/') {
        pipe_name.join("erlang.pipe.1")
    } else {
        pipe_name.to_path_buf()
    };
    let mut run_command = Command::new(run_erl);
    if daemon {
        run_command.arg("-daemon");
    }
    let mut run_child = ChildGuard(
        run_command
            .arg(pipe_name)
            .arg(log_directory)
            .arg("/bin/cat")
            .env_clear()
            .env("TZ", "UTC")
            .env("RUN_ERL_LOG_ALIVE_IN_UTC", "1")
            .env("RUN_ERL_LOG_ALIVE_MINUTES", "5")
            .env("RUN_ERL_LOG_ACTIVITY_MINUTES", "2")
            .env("RUN_ERL_LOG_ALIVE_FORMAT", "%Y-%m-%d %H:%M:%S")
            .env("RUN_ERL_LOG_GENERATIONS", "3")
            .env("RUN_ERL_LOG_MAXSIZE", max_log_size.to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("run_erl starts"),
    );
    let launcher_status = if daemon {
        Some(finish_child(&mut run_child.0).code())
    } else {
        None
    };
    wait_until(|| log_directory.join("erlang.log.1").is_file());
    let shell_pid = wait_until_value(
        || status_pid(&log_directory.join("run_erl.log")),
        Duration::from_secs(10),
    );
    let run_pid = if daemon {
        wait_until_value(|| parent_pid(shell_pid), Duration::from_secs(10))
    } else {
        run_child.0.id()
    };
    let mut daemon_guard = daemon.then(|| PidGuard {
        pid: run_pid,
        active: true,
    });
    let mut shell_guard = PidGuard {
        pid: shell_pid,
        active: true,
    };

    let mut to_child = ChildGuard(
        Command::new(to_erl)
            .arg(pipe_name)
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("to_erl starts"),
    );
    let mut input = to_child.0.stdin.take().unwrap();
    let mut stdout = to_child.0.stdout.take().unwrap();
    let mut stderr = to_child.0.stderr.take().unwrap();
    let (sender, receiver) = mpsc::channel();
    let stdout_reader = std::thread::spawn(move || {
        let mut buffer = [0_u8; 4096];
        loop {
            match stdout.read(&mut buffer) {
                Ok(0) => break,
                Ok(count) => {
                    if sender.send(buffer[..count].to_vec()).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });
    if let Err(error) = input.write_all(b"hello\n") {
        drop(input);
        let _ = to_child.0.wait();
        let mut message = Vec::new();
        let _ = stderr.read_to_end(&mut message);
        panic!(
            "to_erl stdin closed early ({error}): {}",
            String::from_utf8_lossy(&message)
        );
    }
    input.flush().unwrap();
    let mut output = Vec::new();
    wait_for_cat_output(
        &receiver,
        &mut output,
        &mut stderr,
        &mut to_child.0,
        &mut run_child.0,
        run_pid,
    );
    if exercise_rotation {
        let rotated_payload = vec![b'x'; 2048];
        let rotated_output_start = output.len();
        input.write_all(&rotated_payload).unwrap();
        input.write_all(b"\n").unwrap();
        input.flush().unwrap();
        wait_for_output_length(
            &receiver,
            &mut output,
            rotated_output_start + rotated_payload.len() * 2 + 4,
        );
    }
    input.write_all(b"\x03").unwrap();
    input.flush().unwrap();
    drop(input);
    let fifo_read = PathBuf::from(format!("{}.r", actual_pipe_name.display()));
    let shutdown_wait = if daemon {
        Duration::from_secs(7)
    } else {
        Duration::from_secs(2)
    };
    if !wait_until_for(|| !fifo_read.exists(), shutdown_wait) {
        shell_guard.kill();
        if let Some(guard) = daemon_guard.as_mut() {
            guard.kill();
        }
    } else {
        shell_guard.disarm();
        if let Some(guard) = daemon_guard.as_mut() {
            guard.disarm();
        }
    }
    let run_status = launcher_status.unwrap_or_else(|| finish_child(&mut run_child.0).code());
    let to_status = finish_child(&mut to_child.0).code();
    let _ = stdout_reader.join();
    while let Ok(chunk) = receiver.try_recv() {
        output.extend_from_slice(&chunk);
    }
    let mut to_stderr = Vec::new();
    let _ = stderr.read_to_end(&mut to_stderr);
    to_stderr = normalize_pipe_path(&to_stderr, actual_pipe_name.as_os_str().as_bytes());
    let mut logs = fs::read_dir(log_directory)
        .unwrap()
        .map(Result::unwrap)
        .filter(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .starts_with("erlang.log.")
        })
        .map(|entry| {
            (
                entry.file_name().to_string_lossy().into_owned(),
                normalize_log(&fs::read(entry.path()).unwrap()),
            )
        })
        .collect::<Vec<_>>();
    logs.sort_by(|left, right| left.0.cmp(&right.0));
    let status = normalize_status(&fs::read(log_directory.join("run_erl.log")).unwrap());
    SessionResult {
        output,
        to_stderr,
        run_status,
        to_status,
        logs,
        status,
    }
}

fn normalize_pipe_path(message: &[u8], path: &[u8]) -> Vec<u8> {
    let mut normalized = Vec::new();
    let mut start = 0;
    while start < message.len() {
        if let Some(offset) = message[start..]
            .windows(path.len())
            .position(|window| window == path)
        {
            let end = start + offset;
            normalized.extend_from_slice(&message[start..end]);
            normalized.extend_from_slice(b"<pipe>");
            start = end + path.len();
        } else {
            normalized.extend_from_slice(&message[start..]);
            break;
        }
    }
    normalized
}

fn wait_for_cat_output(
    receiver: &mpsc::Receiver<Vec<u8>>,
    output: &mut Vec<u8>,
    stderr: &mut std::process::ChildStderr,
    child: &mut Child,
    run_child: &mut Child,
    run_pid: u32,
) {
    let start = Instant::now();
    while output
        .windows(5)
        .filter(|window| *window == b"hello")
        .count()
        < 2
    {
        let remaining = Duration::from_secs(10).saturating_sub(start.elapsed());
        assert!(
            !remaining.is_zero(),
            "run_erl/to_erl did not forward /bin/cat output"
        );
        match receiver.recv_timeout(remaining) {
            Ok(chunk) => output.extend_from_slice(&chunk),
            Err(error) => {
                let status = child.try_wait().unwrap();
                let run_status = run_child.try_wait().unwrap();
                let process_tree = Command::new("ps")
                    .args(["-o", "pid,ppid,stat,comm", "--ppid", &run_pid.to_string()])
                    .output()
                    .unwrap();
                let mut message = Vec::new();
                let _ = stderr.read_to_end(&mut message);
                panic!(
                    "to_erl output ended ({error}, status {status:?}; run_erl {run_status:?}; child tree {}): {}",
                    String::from_utf8_lossy(&process_tree.stdout),
                    String::from_utf8_lossy(&message)
                );
            }
        }
    }
}

fn wait_until(condition: impl FnMut() -> bool) {
    assert!(
        wait_until_for(condition, Duration::from_secs(10)),
        "run_erl did not start its logger"
    );
}

fn wait_until_for(mut condition: impl FnMut() -> bool, duration: Duration) -> bool {
    let start = Instant::now();
    while !condition() {
        if start.elapsed() >= duration {
            return false;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    true
}

fn wait_for_output_length(receiver: &mpsc::Receiver<Vec<u8>>, output: &mut Vec<u8>, length: usize) {
    let start = Instant::now();
    while output.len() < length {
        let remaining = Duration::from_secs(10).saturating_sub(start.elapsed());
        assert!(
            !remaining.is_zero(),
            "run_erl did not forward rotated log data"
        );
        match receiver.recv_timeout(remaining) {
            Ok(chunk) => output.extend_from_slice(&chunk),
            Err(error) => panic!("run_erl output ended before log rotation data: {error}"),
        }
    }
}

fn parent_pid(child: u32) -> Option<u32> {
    let output = Command::new("ps")
        .args(["-e", "-o", "pid=", "-o", "ppid="])
        .output()
        .ok()?;
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let pid = fields.next()?.parse::<u32>().ok()?;
            let ppid = fields.next()?.parse::<u32>().ok()?;
            (pid == child).then_some(ppid)
        })
        .next()
}

fn status_pid(status_file: &Path) -> Option<u32> {
    let contents = fs::read(status_file).ok()?;
    let line = contents.split(|byte| *byte == b'\n').next().unwrap();
    let start = line.iter().position(|byte| *byte == b'[')? + 1;
    let end = line.iter().position(|byte| *byte == b']')?;
    std::str::from_utf8(&line[start..end]).ok()?.parse().ok()
}

fn wait_until_value<T>(mut value: impl FnMut() -> Option<T>, duration: Duration) -> T {
    let start = Instant::now();
    loop {
        if let Some(value) = value() {
            return value;
        }
        assert!(
            start.elapsed() < duration,
            "run_erl did not start its shell"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn finish_child(child: &mut Child) -> std::process::ExitStatus {
    let start = Instant::now();
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status;
        }
        if start.elapsed() >= Duration::from_secs(5) {
            let _ = child.kill();
            return child.wait().unwrap();
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn normalize_log(bytes: &[u8]) -> Vec<u8> {
    let mut normalized = Vec::new();
    for line in bytes.split_inclusive(|byte| *byte == b'\n') {
        if line.starts_with(b"===== LOGGING STARTED ") {
            normalized.extend_from_slice(b"===== LOGGING STARTED <time>\n");
        } else {
            normalized.extend_from_slice(line);
        }
    }
    normalized
}

fn normalize_status(bytes: &[u8]) -> Vec<u8> {
    let mut normalized = Vec::new();
    for line in bytes.split_inclusive(|byte| *byte == b'\n') {
        if line.starts_with(b"run_erl [") {
            normalized.extend_from_slice(b"run_erl [pid] <time>\n");
        } else {
            normalized.extend_from_slice(line);
        }
    }
    normalized
}

fn otp_program(name: &str) -> PathBuf {
    if let Some(root) = std::env::var_os("ERL_ROOT") {
        let candidate = PathBuf::from(root).join(format!("erts-17.1/bin/{name}"));
        if candidate.is_file() {
            return candidate;
        }
    }
    OTP_ROOTS
        .iter()
        .map(|root| PathBuf::from(root).join(format!("erts-17.1/bin/{name}")))
        .find(|candidate| candidate.is_file())
        .expect("OTP-29.1.1 helper executable is required for differential tests")
}
