// Port of erts/etc/common/heart.c, OTP-29.1.1.

#[path = "../raw_os.rs"]
#[allow(dead_code)]
mod raw;

use std::ffi::{CString, OsString};
use std::io;
use std::os::fd::RawFd;
use std::os::unix::ffi::OsStrExt;

const MSG_HDR_SIZE: usize = 2;
const MSG_HDR_PLUS_OP_SIZE: usize = 3;
const MSG_BODY_SIZE: usize = 2048;
const MSG_TOTAL_SIZE: usize = MSG_HDR_SIZE + MSG_BODY_SIZE;
const PROGRAM_NAME_SIZE: usize = 256;
const SELECT_TIMEOUT: i64 = 5;

const HEART_ACK: u8 = 1;
const HEART_BEAT: u8 = 2;
const SHUT_DOWN: u8 = 3;
const SET_CMD: u8 = 4;
const CLEAR_CMD: u8 = 5;
const GET_CMD: u8 = 6;
const HEART_CMD: u8 = 7;
const PREPARING_CRASH: u8 = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Reason {
    Timeout,
    Closed,
    Error,
    ShutDown,
    Crashing,
}

struct Heart {
    program_name: [u8; PROGRAM_NAME_SIZE],
    heartbeat_timeout: i32,
    kill_pid: u64,
    command: [u8; MSG_BODY_SIZE],
}

// Port of erts/etc/common/heart.c (main), OTP-29.1.1.
fn main() {
    let args = std::env::args_os().collect::<Vec<_>>();
    let debug = std::env::var_os("HEART_DEBUG").is_some();
    if debug {
        eprintln!("heart: debug is ON!\r");
    }
    let (heartbeat_timeout, kill_pid) = parse_arguments(&args, debug);
    let mut program_name = [0; PROGRAM_NAME_SIZE];
    if let Some(value) = args.first() {
        let bytes = value.as_bytes();
        let length = bytes.len().min(PROGRAM_NAME_SIZE - 1);
        program_name[..length].copy_from_slice(&bytes[..length]);
    }
    let mut heart = Heart {
        program_name,
        heartbeat_timeout,
        kill_pid,
        command: [0; MSG_BODY_SIZE],
    };
    let _ = heart.notify_ack(1);
    let reason = heart.message_loop(0, 1);
    heart.do_terminate(0, reason);
}

// Port of erts/etc/common/heart.c (get_arguments), OTP-29.1.1.
fn parse_arguments(args: &[OsString], debug: bool) -> (i32, u64) {
    let mut heartbeat_timeout = 60;
    let mut kill_pid = 0;
    let mut h = -1;
    let mut p = 0;
    let mut i = 1;
    while i < args.len() {
        if let Some(b'-') = args[i].as_bytes().first().copied() {
            match args[i].as_bytes().get(1).copied() {
                Some(b'h') if args[i].as_bytes() == b"-ht" => {
                    if let Some(value) = args.get(i + 1).and_then(|s| parse_c_int(s.as_bytes())) {
                        h = value;
                        if h > 10 && h <= 65_535 {
                            heartbeat_timeout = h;
                            eprintln!("heart_beat_timeout = {h}");
                            i += 1;
                        }
                    }
                }
                Some(b'p') if args[i].as_bytes() == b"-pid" => {
                    if let Some(value) = args.get(i + 1).and_then(|s| parse_c_ulong(s.as_bytes())) {
                        p = value;
                        kill_pid = p;
                        eprintln!("heart_beat_kill_pid = {p}");
                        i += 1;
                    }
                }
                _ => {}
            }
        }
        i += 1;
    }
    if debug {
        eprintln!("Heart: arguments -ht {h} -pid {p}\r");
    }
    (heartbeat_timeout, kill_pid)
}

fn parse_c_int(bytes: &[u8]) -> Option<i32> {
    let mut index = 0;
    while bytes.get(index).is_some_and(u8::is_ascii_whitespace) {
        index += 1;
    }
    let negative = match bytes.get(index) {
        Some(b'-') => {
            index += 1;
            true
        }
        Some(b'+') => {
            index += 1;
            false
        }
        _ => false,
    };
    let base = if bytes.get(index) == Some(&b'0') {
        if matches!(bytes.get(index + 1), Some(b'x' | b'X')) {
            index += 2;
            16
        } else {
            8
        }
    } else {
        10
    };
    let start = index;
    let mut number = 0_i64;
    while let Some(digit) = bytes.get(index).and_then(|byte| match byte {
        b'0'..=b'9' => Some(u32::from(byte - b'0')),
        b'a'..=b'f' => Some(u32::from(byte - b'a' + 10)),
        b'A'..=b'F' => Some(u32::from(byte - b'A' + 10)),
        _ => None,
    }) {
        if digit >= base {
            break;
        }
        number = number
            .checked_mul(i64::from(base))?
            .checked_add(i64::from(digit))?;
        index += 1;
    }
    if index == start {
        return None;
    }
    if negative {
        number = -number;
    }
    i32::try_from(number).ok()
}

fn parse_c_ulong(bytes: &[u8]) -> Option<u64> {
    let mut index = 0;
    while bytes.get(index).is_some_and(u8::is_ascii_whitespace) {
        index += 1;
    }
    let negative = match bytes.get(index) {
        Some(b'-') => {
            index += 1;
            true
        }
        Some(b'+') => {
            index += 1;
            false
        }
        _ => false,
    };
    let start = index;
    let mut number = 0_u64;
    while let Some(digit @ b'0'..=b'9') = bytes.get(index) {
        number = number
            .checked_mul(10)?
            .checked_add(u64::from(digit - b'0'))?;
        index += 1;
    }
    (index != start).then_some(if negative {
        number.wrapping_neg()
    } else {
        number
    })
}

impl Heart {
    // Port of erts/etc/common/heart.c (message_loop), OTP-29.1.1.
    fn message_loop(&mut self, input_fd: RawFd, output_fd: RawFd) -> Reason {
        let mut last_received = self.timestamp();
        loop {
            let ready = match raw::select(&[input_fd], &[], Some(SELECT_TIMEOUT)) {
                Ok((ready, _, _)) => ready,
                Err(_) => {
                    self.print_error("error in select.");
                    return Reason::Error;
                }
            };
            let now = self.timestamp();
            if now > last_received + i64::from(self.heartbeat_timeout) {
                self.print_error(&format!(
                    "heart-beat time-out, no activity for {} seconds",
                    now - last_received
                ));
                return Reason::Timeout;
            }
            if ready == 0 {
                continue;
            }
            let (length, message) = match read_message(input_fd) {
                Ok(value) => value,
                Err(_) => {
                    self.print_error("error in read_message.");
                    return Reason::Error;
                }
            };
            if length > MSG_HDR_SIZE && length <= MSG_TOTAL_SIZE {
                match message[2] {
                    HEART_BEAT => last_received = self.timestamp(),
                    SHUT_DOWN => return Reason::ShutDown,
                    SET_CMD => {
                        let command_len = length - MSG_HDR_PLUS_OP_SIZE;
                        self.command[..command_len].copy_from_slice(
                            &message[MSG_HDR_PLUS_OP_SIZE..MSG_HDR_PLUS_OP_SIZE + command_len],
                        );
                        self.command[command_len] = 0;
                        let _ = self.notify_ack(output_fd);
                    }
                    CLEAR_CMD => {
                        self.command[0] = 0;
                        let _ = self.notify_ack(output_fd);
                    }
                    GET_CMD => {
                        let command = if self.command[0] != 0 {
                            self.command[..c_string_len(&self.command)].to_vec()
                        } else {
                            std::env::var_os("HEART_COMMAND")
                                .map(|value| value.as_os_str().as_bytes().to_vec())
                                .unwrap_or_default()
                        };
                        let _ = self.heart_cmd_reply(output_fd, &command);
                    }
                    PREPARING_CRASH => {
                        self.print_error("Erlang is crashing .. (waiting for crash dump file)");
                        return Reason::Crashing;
                    }
                    _ => {}
                }
            } else if length == 0 {
                self.print_error("Erlang has closed.");
                return Reason::Closed;
            }
        }
    }

    // Port of erts/etc/common/heart.c (do_terminate), OTP-29.1.1.
    fn do_terminate(&mut self, input_fd: RawFd, reason: Reason) {
        if reason == Reason::ShutDown {
            return;
        }
        if reason == Reason::Crashing
            && let Some(timeout) = std::env::var_os("ERL_CRASH_DUMP_SECONDS")
        {
            let timeout = c_atoi(timeout.as_bytes());
            self.print_error(&format!(
                "Waiting for dump - timeout set to {timeout} seconds."
            ));
            if wait_until_close_or_timeout(input_fd, timeout).is_err() {
                self.print_error("error in select.");
            }
        }

        if self.command[0] == 0 {
            if let Some(command) = std::env::var_os("HEART_COMMAND") {
                self.kill_old_erlang(reason);
                let command = command.as_os_str().as_bytes().to_vec();
                let status = CString::new(command.as_slice())
                    .map(|command| raw::system(&command))
                    .unwrap_or(-1);
                self.print_command_result(&command, status);
            } else {
                self.print_error("Would reboot. Terminating.");
            }
        } else {
            self.kill_old_erlang(reason);
            let command = &self.command[..c_string_len(&self.command)];
            let status = CString::new(command)
                .map(|command| raw::system(&command))
                .unwrap_or(-1);
            self.print_command_result(command, status);
        }
    }

    // Port of erts/etc/common/heart.c (kill_old_erlang), OTP-29.1.1.
    fn kill_old_erlang(&self, reason: Reason) {
        if std::env::var_os("HEART_NO_KILL").is_some_and(|value| value.as_bytes() == b"TRUE")
            || self.kill_pid == 0
        {
            return;
        }
        let pid = self.kill_pid as libc::pid_t;
        if reason == Reason::Closed {
            self.print_error("Wait 5 seconds for Erlang to terminate nicely");
            for _ in 0..5 {
                if raw::kill(pid, 0).is_err_and(|error| error.raw_os_error() == Some(libc::ESRCH)) {
                    return;
                }
                raw::sleep(1);
            }
            self.print_error("Erlang still alive, kill it");
        }
        let signal = if std::env::var_os("HEART_KILL_SIGNAL")
            .is_some_and(|value| value.as_bytes() == b"SIGABRT")
        {
            self.print_error("kill signal SIGABRT requested");
            libc::SIGABRT
        } else {
            libc::SIGKILL
        };
        let (mut succeeded, mut error_number) = raw::kill_with_errno(pid, signal);
        for _ in 0..5 {
            if !succeeded {
                break;
            }
            raw::sleep(1);
            (succeeded, error_number) = raw::kill_with_errno(pid, signal);
        }
        if error_number != libc::ESRCH {
            self.print_error("Unable to kill old process, kill failed (tried multiple times).");
        }
    }

    // Port of erts/etc/common/heart.c (notify_ack), OTP-29.1.1.
    fn notify_ack(&self, fd: RawFd) -> io::Result<()> {
        write_message(fd, HEART_ACK, &[]).map(|_| ())
    }

    // Port of erts/etc/common/heart.c (heart_cmd_reply), OTP-29.1.1.
    fn heart_cmd_reply(&self, fd: RawFd, command: &[u8]) -> io::Result<()> {
        if command.len() >= MSG_BODY_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "command too long",
            ));
        }
        write_message(fd, HEART_CMD, command).map(|_| ())
    }

    fn print_error(&self, message: &str) {
        self.print_error_bytes(message.as_bytes());
    }

    fn print_command_result(&self, command: &[u8], status: libc::c_int) {
        let mut message = b"Executed \"".to_vec();
        message.extend_from_slice(command);
        message.extend_from_slice(format!("\" -> {status}. Terminating.").as_bytes());
        self.print_error_bytes(&message);
    }

    fn print_error_bytes(&self, message: &[u8]) {
        let mut output = self.program_name[..c_string_len(&self.program_name)].to_vec();
        output.extend_from_slice(b": ");
        output.extend_from_slice(raw::ctime(raw::now()).as_bytes());
        output.extend_from_slice(b": ");
        output.extend_from_slice(message);
        output.extend_from_slice(b"\r\n");
        let _ = raw::write(2, &output);
    }

    // Port of erts/etc/common/heart.c (timestamp/sys_gethrtime), OTP-29.1.1.
    fn timestamp(&self) -> libc::time_t {
        match raw::monotonic_seconds() {
            Ok(timestamp) => timestamp,
            Err(error) => {
                self.print_error(&format!(
                    "Fatal, could not get clock_monotonic value, terminating! errno = {}\n",
                    error.raw_os_error().unwrap_or(0)
                ));
                std::process::exit(1);
            }
        }
    }
}

// Port of erts/etc/common/heart.c (read_message/read_skip), OTP-29.1.1.
fn read_message(fd: RawFd) -> io::Result<(usize, [u8; MSG_TOTAL_SIZE])> {
    let mut message = [0; MSG_TOTAL_SIZE];
    let header_len = read_fill(fd, &mut message[..MSG_HDR_SIZE])?;
    if header_len != MSG_HDR_SIZE {
        return Ok((header_len, message));
    }
    let payload_len = usize::from(u16::from_be_bytes([message[0], message[1]]));
    if payload_len == 0 {
        return Ok((MSG_HDR_SIZE, message));
    }
    if payload_len > MSG_BODY_SIZE {
        let copied = read_fill(fd, &mut message[MSG_HDR_SIZE..])?;
        if copied == 0 {
            return Ok((0, message));
        }
        let remaining = payload_len.saturating_sub(copied);
        let mut byte = [0];
        let mut consumed = 0;
        while consumed < remaining {
            let count = raw::read(fd, &mut byte)?;
            if count == 0 {
                return Ok((0, message));
            }
            consumed += count;
        }
        return Ok((payload_len + MSG_HDR_SIZE, message));
    }
    let read_len = read_fill(fd, &mut message[MSG_HDR_SIZE..MSG_HDR_SIZE + payload_len])?;
    if read_len == 0 {
        Ok((0, message))
    } else {
        Ok((read_len + MSG_HDR_SIZE, message))
    }
}

fn c_string_len(value: &[u8]) -> usize {
    value
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(value.len())
}

// Port of erts/etc/common/heart.c (read_fill), OTP-29.1.1.
fn read_fill(fd: RawFd, buffer: &mut [u8]) -> io::Result<usize> {
    let mut got = 0;
    while got < buffer.len() {
        match raw::read(fd, &mut buffer[got..]) {
            Ok(0) => return Ok(0),
            Ok(count) => got += count,
            Err(error) => return Err(error),
        }
    }
    Ok(got)
}

// Port of erts/etc/common/heart.c (write_message), OTP-29.1.1.
fn write_message(fd: RawFd, operation: u8, payload: &[u8]) -> io::Result<usize> {
    let body_len = payload.len() + 1;
    if body_len == 0 || body_len > MSG_BODY_SIZE {
        return Ok(MSG_HDR_SIZE);
    }
    let mut message = Vec::with_capacity(MSG_HDR_SIZE + body_len);
    message.extend_from_slice(&(body_len as u16).to_be_bytes());
    message.push(operation);
    message.extend_from_slice(payload);
    match raw::write(fd, &message) {
        Ok(count) if count == message.len() => Ok(count),
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "short packet write",
        )),
        Err(error) => Err(error),
    }
}

// Port of erts/etc/common/heart.c (wait_until_close_write_or_env_tmo), OTP-29.1.1.
fn wait_until_close_or_timeout(fd: RawFd, timeout: i32) -> io::Result<usize> {
    let timeout = (timeout >= 0).then_some(i64::from(timeout));
    raw::select(&[fd], &[], timeout).map(|(ready, _, _)| ready)
}

fn c_atoi(bytes: &[u8]) -> i32 {
    let bytes = bytes
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .map_or(&[][..], |start| &bytes[start..]);
    let (negative, digits) = match bytes.first() {
        Some(b'-') => (true, &bytes[1..]),
        Some(b'+') => (false, &bytes[1..]),
        _ => (false, bytes),
    };
    let mut number = 0_i32;
    for byte in digits {
        if !byte.is_ascii_digit() {
            break;
        }
        number = number.wrapping_mul(10).wrapping_add(i32::from(byte - b'0'));
    }
    if negative {
        number.wrapping_neg()
    } else {
        number
    }
}
