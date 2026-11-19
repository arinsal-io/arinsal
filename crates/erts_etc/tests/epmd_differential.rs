use std::ffi::OsString;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::os::unix::ffi::OsStringExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use similar_asserts::assert_eq;

const TEST_NODE: &str = "arinsal_epmd_diff";
const REGISTERED_PORT: u16 = 34_567;

struct EpmdProcess {
    child: Child,
    executable: PathBuf,
    port: u16,
}

impl EpmdProcess {
    fn start(
        executable: &Path,
        port: u16,
        relaxed: bool,
        from_environment: bool,
        extra_options: &[&str],
    ) -> Self {
        let mut command = Command::new("timeout");
        command
            .arg("--foreground")
            .arg("120")
            .arg(executable)
            .env_remove("ERL_EPMD_ADDRESS")
            .env_remove("ERL_EPMD_PORT")
            .env_remove("ERL_EPMD_RELAXED_COMMAND_CHECK")
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if from_environment {
            command
                .env("ERL_EPMD_ADDRESS", "127.0.0.1")
                .env("ERL_EPMD_PORT", port.to_string());
            if relaxed {
                command.env("ERL_EPMD_RELAXED_COMMAND_CHECK", "");
            }
        } else {
            command
                .args(["-address", "127.0.0.1", "-port"])
                .arg(port.to_string());
            if relaxed {
                command.arg("-relaxed_command_check");
            }
        }
        command.args(extra_options);
        let child = command
            .process_group(0)
            .spawn()
            .expect("start epmd under timeout");
        let mut process = Self {
            child,
            executable: executable.to_owned(),
            port,
        };
        process.wait_ready();
        process
    }

    fn wait_ready(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = self.child.try_wait().expect("poll epmd") {
                panic!("epmd exited before listening: {status}");
            }
            if TcpStream::connect(SocketAddr::from((Ipv4Addr::LOCALHOST, self.port))).is_ok() {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "epmd did not listen on {}",
                self.port
            );
            thread::sleep(Duration::from_millis(20));
        }
    }

    fn wait_stopped(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = self.child.try_wait().expect("poll epmd exit") {
                assert!(status.success(), "epmd exited with {status}");
                return;
            }
            assert!(Instant::now() < deadline, "epmd did not stop after -kill");
            thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for EpmdProcess {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = run_cli(&self.executable, self.port, &["-kill"]);
        }
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = Command::new("/bin/kill")
                .args(["-TERM", &format!("-{}", self.child.id())])
                .status();
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
    }
}

fn free_port() -> u16 {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind loopback port");
    let port = listener.local_addr().unwrap().port();
    assert_ne!(port, 4369);
    drop(listener);
    port
}

fn otp_root() -> PathBuf {
    arinsal_difftest::reference::otp_root()
        .expect("reference OTP is required; set ARINSAL_OTP_ROOT or put erl on PATH")
}

fn otp_epmd() -> PathBuf {
    let path = otp_root()
        .join("erts-17.1/bin")
        .join(arinsal_difftest::reference::program("epmd"));
    assert!(path.is_file(), "OTP epmd is missing at {}", path.display());
    path
}

fn arinsal_epmd() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_arinsal_epmd"))
}

fn run_cli(executable: &Path, port: u16, arguments: &[&str]) -> Output {
    let mut command = Command::new("timeout");
    command
        .arg("10")
        .arg(executable)
        .arg("-port")
        .arg(port.to_string())
        .args(arguments)
        .env_remove("ERL_EPMD_ADDRESS")
        .env_remove("ERL_EPMD_PORT")
        .env_remove("ERL_EPMD_RELAXED_COMMAND_CHECK");
    let output = command.output().expect("run epmd client under timeout");
    Output {
        status: output.status,
        stdout: output.stdout,
        stderr: output.stderr,
    }
}

fn run_cli_with_environment(executable: &Path, port: u16, arguments: &[&str]) -> Output {
    let output = Command::new("timeout")
        .arg("10")
        .arg(executable)
        .args(arguments)
        .env("ERL_EPMD_PORT", port.to_string())
        .env_remove("ERL_EPMD_ADDRESS")
        .env_remove("ERL_EPMD_RELAXED_COMMAND_CHECK")
        .output()
        .expect("run epmd client with environment port under timeout");
    Output {
        status: output.status,
        stdout: output.stdout,
        stderr: output.stderr,
    }
}

fn run_invalid_port(executable: &Path) -> Output {
    let output = Command::new("timeout")
        .args(["10"])
        .arg(executable)
        .args(["-port", "0"])
        .output()
        .expect("run epmd usage path under timeout");
    Output {
        status: output.status,
        stdout: output.stdout,
        stderr: output.stderr,
    }
}

struct Output {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

fn frame(payload: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(payload.len() + 2);
    result.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    result.extend_from_slice(payload);
    result
}

fn alive_request(name: &str, high_version: u16) -> Vec<u8> {
    let mut payload = vec![b'x'];
    payload.extend_from_slice(&REGISTERED_PORT.to_be_bytes());
    payload.extend_from_slice(&[77, 0]);
    payload.extend_from_slice(&high_version.to_be_bytes());
    payload.extend_from_slice(&5u16.to_be_bytes());
    payload.extend_from_slice(&(name.len() as u16).to_be_bytes());
    payload.extend_from_slice(name.as_bytes());
    payload.extend_from_slice(&0u16.to_be_bytes());
    frame(&payload)
}

fn port_request(name: &str) -> Vec<u8> {
    let mut payload = vec![b'z'];
    payload.extend_from_slice(name.as_bytes());
    frame(&payload)
}

fn send_alive(
    port: u16,
    name: &str,
    high_version: u16,
    response_size: usize,
) -> (Vec<u8>, TcpStream) {
    let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).expect("connect to epmd");
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    stream
        .write_all(&alive_request(name, high_version))
        .expect("send ALIVE2_REQ");
    let mut response = vec![0; response_size];
    stream.read_exact(&mut response).expect("read ALIVE2_RESP");
    (response, stream)
}

fn request_response(port: u16, payload: &[u8]) -> Vec<u8> {
    let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).expect("connect to epmd");
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    stream
        .write_all(&frame(payload))
        .expect("send protocol packet");
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .expect("read protocol response");
    response
}

fn exercise_standard_server(executable: &Path, port: u16) -> Vec<Vec<u8>> {
    let mut server = EpmdProcess::start(executable, port, false, false, &[]);
    let empty_names = request_response(port, b"n");
    let empty_dump = request_response(port, b"d");
    let (alive_response, alive_socket) = send_alive(port, TEST_NODE, 6, 6);
    assert_eq!(alive_response[0], b'v');
    assert_eq!(alive_response[1], 0);

    let (duplicate_x_response, duplicate_x_socket) = send_alive(port, TEST_NODE, 6, 6);
    drop(duplicate_x_socket);
    let (duplicate_y_response, duplicate_y_socket) = send_alive(port, TEST_NODE, 5, 4);
    drop(duplicate_y_socket);
    let port_reply = request_response(port, &port_request(TEST_NODE)[2..]);
    let names_active = request_response(port, b"n");
    let cli_names_active = run_cli(executable, port, &["-names"]);
    let cli_dump_empty = run_cli(executable, port, &["-dump"]);
    let cli_started = run_cli(executable, port, &["-started"]);
    assert_eq!(cli_started.status.code(), Some(0));
    let kill_denied = run_cli(executable, port, &["-kill"]);
    assert_eq!(kill_denied.status.code(), Some(1));

    drop(alive_socket);
    let deadline = Instant::now() + Duration::from_secs(5);
    let names_empty = loop {
        let names = request_response(port, b"n");
        if names == empty_names {
            break names;
        }
        assert!(
            Instant::now() < deadline,
            "ALIVE connection close did not unregister node"
        );
        thread::sleep(Duration::from_millis(20));
    };
    let cli_names_empty = run_cli(executable, port, &["-names"]);
    let kill_allowed = run_cli(executable, port, &["-kill"]);
    assert_eq!(kill_allowed.status.code(), Some(0));
    server.wait_stopped();

    vec![
        empty_names,
        empty_dump,
        duplicate_x_response,
        duplicate_y_response,
        port_reply,
        names_active,
        cli_names_active.stdout,
        cli_names_active.stderr,
        cli_dump_empty.stdout,
        cli_dump_empty.stderr,
        cli_started.stdout,
        cli_started.stderr,
        kill_denied.stdout,
        kill_denied.stderr,
        names_empty,
        cli_names_empty.stdout,
        cli_names_empty.stderr,
        kill_allowed.stdout,
        kill_allowed.stderr,
    ]
}

fn exercise_relaxed_stop(executable: &Path, port: u16) -> Vec<Vec<u8>> {
    let mut server = EpmdProcess::start(executable, port, true, false, &[]);
    let (_, alive_socket) = send_alive(port, "epmd_stop_diff", 6, 6);
    let stopped = run_cli(executable, port, &["-stop", "epmd_stop_diff"]);
    assert_eq!(
        stopped.status.code(),
        Some(0),
        "-stop failed: stdout={:?}, stderr={:?}",
        String::from_utf8_lossy(&stopped.stdout),
        String::from_utf8_lossy(&stopped.stderr)
    );
    assert_eq!(stopped.stdout, b"STOPPED\n");
    drop(alive_socket);
    let missing_stop = request_response(port, b"sepmd_stop_missing\0");
    let killed = run_cli(executable, port, &["-kill"]);
    assert_eq!(killed.status.code(), Some(0));
    server.wait_stopped();
    vec![
        stopped.stdout,
        stopped.stderr,
        missing_stop,
        killed.stdout,
        killed.stderr,
    ]
}

fn exercise_environment(executable: &Path, port: u16) -> Vec<Vec<u8>> {
    let mut server = EpmdProcess::start(executable, port, true, true, &[]);
    let (alive_response, alive_socket) = send_alive(port, "epmd_env_diff", 6, 6);
    assert_eq!(alive_response[1], 0);
    let result = run_cli_with_environment(executable, port, &["-names"]);
    assert!(result.status.success());
    assert!(String::from_utf8_lossy(&result.stdout).contains("name epmd_env_diff at port "));
    let killed = run_cli_with_environment(executable, port, &["-kill"]);
    assert!(killed.status.success());
    server.wait_stopped();
    drop(alive_socket);
    vec![result.stdout, result.stderr, killed.stdout, killed.stderr]
}

fn exercise_non_utf8_port_environment(executable: &Path, port: u16) -> Vec<Vec<u8>> {
    let mut port_value = port.to_string().into_bytes();
    port_value.push(0xff);
    let child = Command::new("timeout")
        .args(["--foreground", "120"])
        .arg(executable)
        .env_remove("ERL_EPMD_ADDRESS")
        .env_remove("ERL_EPMD_PORT")
        .env_remove("ERL_EPMD_RELAXED_COMMAND_CHECK")
        .env("ERL_EPMD_ADDRESS", "127.0.0.1")
        .env("ERL_EPMD_PORT", OsString::from_vec(port_value))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0)
        .spawn()
        .expect("start epmd with raw environment bytes");
    let mut server = EpmdProcess {
        child,
        executable: executable.to_owned(),
        port,
    };
    server.wait_ready();
    let names = request_response(port, b"n");
    let killed = run_cli(executable, port, &["-kill"]);
    assert!(killed.status.success());
    server.wait_stopped();
    vec![names, killed.stdout, killed.stderr]
}

fn exercise_debug_timing_options(executable: &Path, port: u16) -> Vec<Vec<u8>> {
    let mut server = EpmdProcess::start(
        executable,
        port,
        false,
        false,
        &[
            "-packet_timeout",
            "2",
            "-delay_accept",
            "1",
            "-delay_write",
            "1",
            "-d",
            "-debug",
        ],
    );
    let names = run_cli(executable, port, &["-names"]);
    let killed = run_cli(executable, port, &["-kill"]);
    assert!(names.status.success());
    assert!(killed.status.success());
    server.wait_stopped();
    vec![names.stdout, names.stderr, killed.stdout, killed.stderr]
}

struct DaemonGuard {
    executable: PathBuf,
    port: u16,
}

impl Drop for DaemonGuard {
    fn drop(&mut self) {
        let _ = run_cli(&self.executable, self.port, &["-kill"]);
    }
}

fn exercise_daemon(executable: &Path, port: u16) -> Vec<Vec<u8>> {
    let start = Command::new("timeout")
        .arg("10")
        .arg(executable)
        .args(["-daemon", "-address", "127.0.0.1", "-port"])
        .arg(port.to_string())
        .output()
        .expect("start epmd daemon under timeout");
    assert!(start.status.success());
    let _daemon = DaemonGuard {
        executable: executable.to_owned(),
        port,
    };
    wait_for_listener(port);
    let names = run_cli(executable, port, &["-names"]);
    let killed = run_cli(executable, port, &["-kill"]);
    assert!(names.status.success());
    assert!(killed.status.success());
    wait_for_unlistener(port);
    vec![
        start.stdout,
        start.stderr,
        names.stdout,
        names.stderr,
        killed.stdout,
        killed.stderr,
    ]
}

fn exercise_systemd_without_socket(executable: &Path, port: u16) -> i32 {
    let output = Command::new("timeout")
        .args(["10"])
        .arg(executable)
        .args(["-systemd", "-port"])
        .arg(port.to_string())
        .output()
        .expect("check systemd option under timeout");
    output.status.code().unwrap_or(-1)
}

fn wait_for_listener(port: u16) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if TcpStream::connect(SocketAddr::from((Ipv4Addr::LOCALHOST, port))).is_ok() {
            return;
        }
        thread::sleep(Duration::from_millis(20));
    }
    panic!("epmd daemon did not listen on {port}");
}

fn wait_for_unlistener(port: u16) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if TcpStream::connect(SocketAddr::from((Ipv4Addr::LOCALHOST, port))).is_err() {
            return;
        }
        thread::sleep(Duration::from_millis(20));
    }
    panic!("epmd daemon still listens on {port}");
}

#[test]
fn epmd_protocol_clients_environment_and_erl_registration_match_otp() {
    let reference = otp_epmd();
    let arinsal = arinsal_epmd();
    let port = free_port();

    let otp_usage = run_invalid_port(&reference);
    let arinsal_usage = run_invalid_port(&arinsal);
    assert_eq!(otp_usage.status.code(), Some(1));
    assert_eq!(arinsal_usage.status.code(), Some(1));
    assert_eq!(otp_usage.stdout, arinsal_usage.stdout);
    assert_eq!(otp_usage.stderr, arinsal_usage.stderr);

    let otp_protocol = exercise_standard_server(&reference, port);
    let arinsal_protocol = exercise_standard_server(&arinsal, port);
    assert_eq!(otp_protocol, arinsal_protocol);

    let otp_stop = exercise_relaxed_stop(&reference, port);
    let arinsal_stop = exercise_relaxed_stop(&arinsal, port);
    assert_eq!(otp_stop, arinsal_stop);

    let otp_environment = exercise_environment(&reference, port);
    let arinsal_environment = exercise_environment(&arinsal, port);
    assert_eq!(otp_environment, arinsal_environment);

    let otp_raw_environment = exercise_non_utf8_port_environment(&reference, port);
    let arinsal_raw_environment = exercise_non_utf8_port_environment(&arinsal, port);
    assert_eq!(otp_raw_environment, arinsal_raw_environment);

    let otp_debug_options = exercise_debug_timing_options(&reference, port);
    let arinsal_debug_options = exercise_debug_timing_options(&arinsal, port);
    assert_eq!(otp_debug_options, arinsal_debug_options);

    let otp_daemon = exercise_daemon(&reference, port);
    let arinsal_daemon = exercise_daemon(&arinsal, port);
    assert_eq!(otp_daemon, arinsal_daemon);
    assert_eq!(exercise_systemd_without_socket(&arinsal, port), 1);

    erl_registers_with_arinsal_epmd(&arinsal, port);
}

fn erl_registers_with_arinsal_epmd(arinsal: &Path, port: u16) {
    let root = otp_root();
    let erl = root.join("bin/erl");
    assert!(erl.is_file(), "OTP erl is missing at {}", erl.display());
    let mut server = EpmdProcess::start(arinsal, port, false, false, &[]);
    let node = format!("epmd_probe_{}", std::process::id());
    let mut child = Command::new("timeout")
        .args([
            "30",
            erl.to_str().unwrap(),
            "-sname",
            &node,
            "-noshell",
            "-noinput",
        ])
        .args(["-kernel", "inet_dist_use_interface", "{127,0,0,1}"])
        .args(["-eval", "timer:sleep(3000), halt()."])
        .env("ERL_EPMD_PORT", port.to_string())
        .env_remove("ERL_EPMD_ADDRESS")
        .env_remove("ERL_EPMD_RELAXED_COMMAND_CHECK")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .spawn()
        .expect("start OTP node under timeout");
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut registered = false;
    let mut last_names = None;
    while Instant::now() < deadline {
        let names = run_cli(arinsal, port, &["-names"]);
        if names.status.success()
            && String::from_utf8_lossy(&names.stdout).contains(&format!("name {node} at port "))
        {
            registered = true;
            break;
        }
        last_names = Some((names.status.code(), names.stdout, names.stderr));
        if child.try_wait().expect("poll erl").is_some() {
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    if !registered {
        let _ = Command::new("/bin/kill")
            .args(["-TERM", &format!("-{}", child.id())])
            .status();
        let _ = child.kill();
    }
    let output = child.wait_with_output().expect("wait for OTP node");
    let status = output.status;
    assert!(
        registered,
        "OTP node did not register with arinsal_epmd; stdout={:?}; stderr={:?}; last names={:?}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
        last_names
    );
    assert!(status.success(), "OTP node exited with {status}");
    let killed = run_cli(arinsal, port, &["-kill"]);
    assert!(killed.status.success());
    server.wait_stopped();
}
