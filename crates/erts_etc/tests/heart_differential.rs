use std::io::{Read, Write};
use std::os::unix::process::ExitStatusExt;
use std::path::PathBuf;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn heart_packets_match_otp() {
    let reference = otp_heart();
    let arinsal = PathBuf::from(env!("CARGO_BIN_EXE_arinsal_heart"));
    similar_asserts::assert_eq!(run_protocol(&reference), run_protocol(&arinsal));
}

#[test]
fn heart_crash_kill_environment_matches_otp() {
    let reference = otp_heart();
    let arinsal = PathBuf::from(env!("CARGO_BIN_EXE_arinsal_heart"));
    for (no_kill, signal) in [(false, None), (true, None), (false, Some("SIGABRT"))] {
        similar_asserts::assert_eq!(
            run_crash_case(&reference, no_kill, signal),
            run_crash_case(&arinsal, no_kill, signal)
        );
    }
}

#[test]
fn heart_heartbeat_timeout_matches_otp() {
    let reference = otp_heart();
    let arinsal = PathBuf::from(env!("CARGO_BIN_EXE_arinsal_heart"));
    let (reference_status, reference_error) = run_timeout(&reference);
    let (arinsal_status, arinsal_error) = run_timeout(&arinsal);
    similar_asserts::assert_eq!(reference_status, arinsal_status);
    assert!(
        reference_error
            .windows(b"heart-beat time-out".len())
            .any(|window| window == b"heart-beat time-out")
    );
    assert!(
        arinsal_error
            .windows(b"heart-beat time-out".len())
            .any(|window| window == b"heart-beat time-out")
    );
}

fn run_timeout(program: &PathBuf) -> (Option<i32>, Vec<u8>) {
    let mut child = ChildGuard(
        Command::new(program)
            .arg("-ht")
            .arg("11")
            .env_clear()
            .env("HEART_COMMAND", "/bin/true")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("heart starts"),
    );
    let _input = child.0.stdin.take().unwrap();
    let mut output = child.0.stdout.take().unwrap();
    similar_asserts::assert_eq!(read_packet(&mut output), vec![0, 1, 1]);
    let status = child.0.wait().expect("heart times out").code();
    let mut error = Vec::new();
    child
        .0
        .stderr
        .take()
        .unwrap()
        .read_to_end(&mut error)
        .unwrap();
    (status, error)
}

fn otp_heart() -> PathBuf {
    let root = arinsal_difftest::reference::otp_root()
        .expect("reference OTP is required; set ARINSAL_OTP_ROOT or put erl on PATH");
    root.join("erts-17.1/bin")
        .join(arinsal_difftest::reference::program("heart"))
}

fn run_protocol(program: &PathBuf) -> (Vec<Vec<u8>>, Option<i32>) {
    let mut child = ChildGuard(
        Command::new(program)
            .env_clear()
            .env("HEART_COMMAND", "original command")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("heart starts"),
    );
    let mut input = child.0.stdin.take().unwrap();
    let mut output = child.0.stdout.take().unwrap();
    let mut replies = vec![read_packet(&mut output)];

    send_packet(&mut input, 2, b"");
    send_packet(&mut input, 6, b"");
    replies.push(read_packet(&mut output));
    send_packet(&mut input, 4, b"replacement\0command tail");
    replies.push(read_packet(&mut output));
    send_packet(&mut input, 6, b"");
    replies.push(read_packet(&mut output));
    send_packet(&mut input, 5, b"");
    replies.push(read_packet(&mut output));
    send_packet(&mut input, 6, b"");
    replies.push(read_packet(&mut output));
    send_packet(&mut input, 3, b"");
    drop(input);
    let status = child.0.wait().expect("heart exits after SHUT_DOWN").code();
    (replies, status)
}

fn run_crash_case(
    program: &PathBuf,
    no_kill: bool,
    signal: Option<&str>,
) -> (Option<i32>, bool, Option<i32>) {
    let mut emulator = ChildGuard(
        Command::new("/bin/sh")
            .args(["-c", "ulimit -c 0; exec /bin/sleep 30"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("fake emulator starts"),
    );
    let mut command = Command::new(program);
    command
        .arg("-pid")
        .arg(emulator.0.id().to_string())
        .env_clear()
        .env("HEART_COMMAND", "/bin/true")
        .env("ERL_CRASH_DUMP_SECONDS", "0")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    if no_kill {
        command.env("HEART_NO_KILL", "TRUE");
    }
    if let Some(signal) = signal {
        command.env("HEART_KILL_SIGNAL", signal);
    }
    let mut heart = ChildGuard(command.spawn().expect("heart starts"));
    let mut input = heart.0.stdin.take().unwrap();
    let mut output = heart.0.stdout.take().unwrap();
    similar_asserts::assert_eq!(read_packet(&mut output), vec![0, 1, 1]);
    send_packet(&mut input, 8, b"");
    drop(input);
    let heart_status = heart
        .0
        .wait()
        .expect("heart handles PREPARING_CRASH")
        .code();
    let emulator_status = emulator.0.try_wait().unwrap();
    let remained_alive = emulator_status.is_none();
    let emulator_signal = emulator_status.and_then(|status| status.signal());
    if remained_alive {
        let _ = emulator.0.kill();
        let _ = emulator.0.wait();
    }
    (heart_status, remained_alive, emulator_signal)
}

fn send_packet(input: &mut ChildStdin, operation: u8, payload: &[u8]) {
    input
        .write_all(&((payload.len() + 1) as u16).to_be_bytes())
        .unwrap();
    input.write_all(&[operation]).unwrap();
    input.write_all(payload).unwrap();
    input.flush().unwrap();
}

fn read_packet(output: &mut ChildStdout) -> Vec<u8> {
    let mut header = [0; 2];
    output.read_exact(&mut header).unwrap();
    let length = usize::from(u16::from_be_bytes(header));
    let mut packet = Vec::with_capacity(length + 2);
    packet.extend_from_slice(&header);
    packet.resize(length + 2, 0);
    output.read_exact(&mut packet[2..]).unwrap();
    packet
}
