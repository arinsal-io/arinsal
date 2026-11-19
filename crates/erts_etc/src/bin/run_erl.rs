// Port of erts/etc/unix/run_erl.c and run_erl.h, OTP-29.1.1.

#[path = "../raw_os.rs"]
#[allow(dead_code)]
mod raw;
#[path = "../safe_string.rs"]
mod safe_string;

use std::ffi::{CStr, CString, OsString};
use std::io;
use std::os::fd::RawFd;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::PathBuf;
use std::process;

const DEFAULT_LOG_GENERATIONS: i32 = 5;
const LOG_MAX_GENERATIONS: i32 = 1000;
const LOG_MIN_GENERATIONS: i32 = 2;
const DEFAULT_LOG_MAXSIZE: i32 = 100_000;
const LOG_MIN_MAXSIZE: i32 = 1000;
const LOG_STUBNAME: &[u8] = b"erlang.log.";
const LOG_PERM: libc::mode_t = 0o664;
const DEFAULT_LOG_ACTIVITY_MINUTES: i32 = 5;
const DEFAULT_LOG_ALIVE_MINUTES: i32 = 15;
const DEFAULT_LOG_ALIVE_FORMAT: &[u8] = b"%a %b %e %T %Z %Y";
const ALIVE_BUFFSIZ: usize = 256;
const PERM: libc::mode_t = 0o600;
const STATUSFILENAME: &[u8] = b"/run_erl.log";
const PIPE_STUBNAME: &[u8] = b"erlang.pipe";
const FILENAME_MAX: usize = 250;
const RUN_ERL_HI_VER: u32 = 1;
const RUN_ERL_LO_VER: u32 = 0;
const BUF_SIZE: usize = libc::BUFSIZ as usize;

// Port of erts/etc/unix/run_erl.c (catch_sigchild), OTP-29.1.1.
extern "C" fn catch_sigchild(_signal: libc::c_int) {}

// Port of erts/etc/unix/run_erl.c (main), OTP-29.1.1.
fn main() {
    let args = std::env::args_os().collect::<Vec<_>>();
    let program_name = args
        .first()
        .map(|value| value.as_os_str().as_bytes().to_vec())
        .unwrap_or_default();
    if args.len() < 4 {
        usage(&program_name);
        process::exit(1);
    }

    let mut index = 1;
    let mut sleepy_child = false;
    let mut daemon = false;
    if args.get(index).is_some_and(|arg| arg == "-sleepy-child") {
        sleepy_child = true;
        index += 1;
    }
    if args.get(1).is_some_and(|arg| arg == "-daemon") {
        daemon = true;
        index += 1;
    }
    if daemon {
        daemon_init(&program_name);
    }
    let off_argv = index;
    let mut pipe_name = safe_string::copy(args[index].as_bytes(), FILENAME_MAX);
    index += 1;
    let log_directory = safe_string::copy(args[index].as_bytes(), FILENAME_MAX);
    let mut status_path = log_directory.clone();
    safe_string::append(&mut status_path, STATUSFILENAME, FILENAME_MAX);

    let mut log_config = LogConfig::from_environment(&program_name, daemon);
    let mut calculated_pipe_name = false;
    let mut highest_pipe_num = 0;
    if pipe_name.last() == Some(&b'/') {
        calculated_pipe_name = true;
        highest_pipe_num = highest_pipe_number(&pipe_name, &program_name, daemon);
        safe_string::append(&mut pipe_name, PIPE_STUBNAME, FILENAME_MAX);
        safe_string::append(&mut pipe_name, b".", FILENAME_MAX);
        safe_string::append(
            &mut pipe_name,
            (highest_pipe_num + 1).to_string().as_bytes(),
            FILENAME_MAX,
        );
    }

    let mut fifo1 = with_suffix(&pipe_name, b".r");
    let mut fifo2 = with_suffix(&pipe_name, b".w");
    let mut fifo1_c = c_path(&fifo1);
    let mut fifo2_c = c_path(&fifo2);
    create_fifo(&fifo1_c, &program_name, daemon, 363);
    loop {
        match sf_open(&fifo2_c, libc::O_WRONLY | libc::O_NONBLOCK, 0) {
            Ok(fd) => {
                raw::close(fd);
                if calculated_pipe_name {
                    highest_pipe_num += 1;
                    safe_string::append(&mut pipe_name, PIPE_STUBNAME, FILENAME_MAX);
                    safe_string::append(
                        &mut pipe_name,
                        format!(".{}", highest_pipe_num + 1).as_bytes(),
                        FILENAME_MAX,
                    );
                    fifo1 = with_suffix(&pipe_name, b".r");
                    fifo2 = with_suffix(&pipe_name, b".w");
                    fifo1_c = c_path(&fifo1);
                    fifo2_c = c_path(&fifo2);
                    create_fifo(&fifo1_c, &program_name, daemon, 363);
                    continue;
                }
                let mut message = b"Erlang already running on pipe ".to_vec();
                message.extend_from_slice(&pipe_name);
                message.extend_from_slice(b".\n");
                let _ = raw::write(2, &message);
                process::exit(1);
            }
            Err(error) if error.raw_os_error() == Some(libc::ENXIO) => {}
            Err(_) => {}
        }
        create_fifo(&fifo2_c, &program_name, daemon, 385);
        break;
    }

    let (master_fd, slave_name, slave_fd) = match raw::open_pty_master() {
        Ok(pty) => pty,
        Err(error) => {
            report_error(
                &program_name,
                daemon,
                396,
                "Could not open pty master",
                Some(error),
            );
            process::exit(1);
        }
    };
    let child_args = shell_arguments(&args[off_argv..]);
    let child_arg_pointers = child_args
        .iter()
        .map(|value| value.as_ptr())
        .collect::<Vec<_>>();
    let shell_path = c"/bin/sh";
    let (child_pid, status_file) = match raw::fork() {
        Ok(0) => {
            child_process(
                master_fd,
                slave_fd,
                &slave_name,
                &child_args,
                &child_arg_pointers,
                shell_path,
                &fifo1_c,
                sleepy_child,
                &program_name,
                &status_path,
                daemon,
            );
        }
        Ok(pid) => (pid, None),
        Err(error) => {
            report_error(&program_name, daemon, 405, "Cannot fork", Some(error));
            process::exit(1);
        }
    };

    let _ = raw::set_signal_ignored(libc::SIGPIPE, 0);
    let _ = raw::set_signal_handler(libc::SIGCHLD, catch_sigchild, libc::SA_NOCLDSTOP);
    let mut status_file = status_file;
    pass_on(
        child_pid,
        master_fd,
        &fifo1,
        &fifo2,
        &fifo1_c,
        &fifo2_c,
        &log_directory,
        &status_path,
        &program_name,
        &mut status_file,
        &mut log_config,
        daemon,
    );
}

#[derive(Clone)]
struct LogConfig {
    generations: i32,
    max_size: i32,
    alive_minutes: i32,
    activity_minutes: i32,
    alive_in_utc: bool,
    alive_format: Vec<u8>,
    protocol_version: u32,
}

impl LogConfig {
    // Port of erts/etc/unix/run_erl.c (main environment parsing), OTP-29.1.1.
    fn from_environment(program_name: &[u8], daemon: bool) -> Self {
        let mut config = Self {
            generations: DEFAULT_LOG_GENERATIONS,
            max_size: DEFAULT_LOG_MAXSIZE,
            alive_minutes: DEFAULT_LOG_ALIVE_MINUTES,
            activity_minutes: DEFAULT_LOG_ACTIVITY_MINUTES,
            alive_in_utc: false,
            alive_format: DEFAULT_LOG_ALIVE_FORMAT.to_vec(),
            protocol_version: RUN_ERL_LO_VER,
        };
        if let Some(value) = std::env::var_os("RUN_ERL_LOG_ALIVE_MINUTES") {
            config.alive_minutes = atoi(&value);
            if config.alive_minutes == 0 {
                let mut message =
                    b"Minimum value for RUN_ERL_LOG_ALIVE_MINUTES is 1 (current value is ".to_vec();
                message.extend_from_slice(value.as_bytes());
                message.push(b')');
                report_error_bytes(program_name, daemon, 286, &message, None);
            }
            config.activity_minutes = config.alive_minutes / 3;
            if config.activity_minutes == 0 {
                config.activity_minutes += 1;
            }
        }
        if let Some(value) = std::env::var_os("RUN_ERL_LOG_ACTIVITY_MINUTES") {
            config.activity_minutes = atoi(&value);
            if config.activity_minutes == 0 {
                let mut message =
                    b"Minimum value for RUN_ERL_LOG_ACTIVITY_MINUTES is 1 (current value is "
                        .to_vec();
                message.extend_from_slice(value.as_bytes());
                message.push(b')');
                report_error_bytes(program_name, daemon, 297, &message, None);
            }
        }
        if let Some(value) = std::env::var_os("RUN_ERL_LOG_ALIVE_FORMAT") {
            if value.as_bytes().len() > ALIVE_BUFFSIZ {
                report_error_bytes(
                    program_name,
                    daemon,
                    303,
                    b"RUN_ERL_LOG_ALIVE_FORMAT can contain a maximum of 256 characters",
                    None,
                );
            }
            config.alive_format = safe_string::copy(value.as_bytes(), ALIVE_BUFFSIZ + 1);
        }
        if let Some(value) = std::env::var_os("RUN_ERL_LOG_ALIVE_IN_UTC") {
            config.alive_in_utc = value.as_bytes() != b"0";
        }
        if let Some(value) = std::env::var_os("RUN_ERL_LOG_GENERATIONS") {
            config.generations = atoi(&value);
            if config.generations < LOG_MIN_GENERATIONS {
                report_error_bytes(
                    program_name,
                    daemon,
                    316,
                    b"Minimum RUN_ERL_LOG_GENERATIONS is 2",
                    None,
                );
            }
            if config.generations > LOG_MAX_GENERATIONS {
                report_error_bytes(
                    program_name,
                    daemon,
                    318,
                    b"Maximum RUN_ERL_LOG_GENERATIONS is 1000",
                    None,
                );
            }
        }
        if let Some(value) = std::env::var_os("RUN_ERL_LOG_MAXSIZE") {
            config.max_size = atoi(&value);
            if config.max_size < LOG_MIN_MAXSIZE {
                report_error_bytes(
                    program_name,
                    daemon,
                    324,
                    b"Minimum RUN_ERL_LOG_MAXSIZE is 1000",
                    None,
                );
            }
        }
        config
    }
}

struct OutputBuffer {
    bytes: Vec<u8>,
    input: usize,
    output: usize,
    total: usize,
}

impl OutputBuffer {
    // Port of erts/etc/unix/run_erl.c (init_outbuf), OTP-29.1.1.
    fn new() -> Self {
        Self {
            bytes: vec![0; BUF_SIZE],
            input: 0,
            output: 0,
            total: 1,
        }
    }

    fn size(&self) -> usize {
        self.input - self.output
    }

    fn clear(&mut self) {
        self.input = 0;
        self.output = 0;
    }

    fn first(&self) -> &[u8] {
        &self.bytes[self.output..self.input]
    }

    fn delete(&mut self, bytes: usize) {
        self.output += bytes;
        if self.output >= self.input {
            self.clear();
        }
    }

    // Port of erts/etc/unix/run_erl.c (outbuf_append), OTP-29.1.1.
    fn append(&mut self, bytes: &[u8]) {
        if self.total < self.input + bytes.len() {
            if self.output > 0 {
                let size = self.input - self.output;
                self.bytes.copy_within(self.output..self.input, 0);
                self.input = size;
                self.output = 0;
            }
            if self.total < self.input + bytes.len() {
                let size = self.input - self.output;
                self.total = size + bytes.len();
                if self.bytes.len() < self.total {
                    self.bytes.resize(self.total, 0);
                }
                self.output = 0;
                self.input = size;
            }
        }
        let end = self.input + bytes.len();
        self.bytes[self.input..end].copy_from_slice(bytes);
        self.input = end;
    }
}

// Port of erts/etc/unix/run_erl.c (exec_shell), OTP-29.1.1.
fn shell_arguments(args: &[OsString]) -> Vec<CString> {
    let mut result = Vec::with_capacity(args.len() + 1);
    result.push(c"sh".to_owned());
    result.push(c"-c".to_owned());
    for arg in args.iter().skip(2) {
        result.push(CString::new(arg.as_bytes()).expect("argv cannot contain NUL"));
    }
    result
}

#[allow(clippy::too_many_arguments)]
// Port of erts/etc/unix/run_erl.c (fork child branch of main), OTP-29.1.1.
fn child_process(
    master_fd: RawFd,
    mut slave_fd: RawFd,
    slave_name: &CStr,
    child_args: &[CString],
    child_arg_pointers: &[*const libc::c_char],
    shell_path: &CStr,
    fifo1: &CStr,
    sleepy_child: bool,
    program_name: &[u8],
    status_path: &[u8],
    daemon: bool,
) -> ! {
    if sleepy_child {
        raw::sleep(1);
    }
    raw::close(master_fd);
    let _ = raw::setsid();
    if slave_fd < 0 {
        slave_fd = match raw::open(slave_name, libc::O_RDWR, 0) {
            Ok(fd) => fd,
            Err(error) => {
                let mut message = b"Could not open pty slave '".to_vec();
                message.extend_from_slice(slave_name.to_bytes());
                message.extend_from_slice(b"'\n");
                report_error_bytes(program_name, daemon, 426, &message, Some(error));
                process::exit(1);
            }
        };
    } else {
        let _ = raw::set_controlling_terminal(slave_fd);
    }
    while slave_fd < 3 {
        slave_fd = raw::dup(slave_fd).unwrap_or(slave_fd);
    }
    if std::env::var_os("RUN_ERL_DISABLE_FLOWCNTRL").is_some() {
        match raw::tcgetattr(slave_fd) {
            Ok(mut mode) => {
                mode.c_iflag &= !libc::IXOFF;
                if raw::tcsetattr(slave_fd, libc::TCSANOW, &mode).is_err() {
                    eprintln!("Cannot disable terminal's flow control on input");
                    process::exit(255);
                }
                mode.c_iflag &= !libc::IXON;
                if raw::tcsetattr(slave_fd, libc::TCSANOW, &mode).is_err() {
                    eprintln!("Cannot disable terminal's flow control on output");
                    process::exit(255);
                }
            }
            Err(_) => {
                eprintln!("Cannot get terminal's current mode");
                process::exit(255);
            }
        }
    }
    if daemon {
        raw::closelog();
    }
    let mut status_file = None;
    raw::close(0);
    raw::close(1);
    raw::close(2);
    if raw::dup(slave_fd).unwrap_or(-1) != 0
        || raw::dup(slave_fd).unwrap_or(-1) != 1
        || raw::dup(slave_fd).unwrap_or(-1) != 2
    {
        status(&mut status_file, status_path, program_name, b"Cannot dup\n");
    }
    raw::close(slave_fd);
    status(
        &mut status_file,
        status_path,
        program_name,
        b"Args before exec of shell:\n",
    );
    for (index, argument) in child_args.iter().enumerate() {
        let mut message = format!("argv[{index}] = ").into_bytes();
        message.extend_from_slice(argument.as_bytes());
        message.push(b'\n');
        status(&mut status_file, status_path, program_name, &message);
    }
    drop(status_file);
    let _ = fifo1;
    match raw::execv(shell_path, child_arg_pointers) {
        Ok(()) => unreachable!(),
        Err(error) => {
            if daemon {
                let basename = program_name
                    .rsplit(|byte| *byte == b'/')
                    .next()
                    .unwrap_or(program_name);
                raw::openlog(basename);
            }
            report_error(program_name, daemon, 1152, "Could not execv", Some(error));
            process::exit(1);
        }
    }
}

// Port of erts/etc/unix/run_erl.c (pass_on), OTP-29.1.1.
#[allow(clippy::too_many_arguments)]
fn pass_on(
    child_pid: libc::pid_t,
    master_fd: RawFd,
    fifo1: &[u8],
    fifo2: &[u8],
    fifo1_c: &CStr,
    fifo2_c: &CStr,
    log_directory: &[u8],
    status_path: &[u8],
    program_name: &[u8],
    status_file: &mut Option<std::fs::File>,
    log_config: &mut LogConfig,
    daemon: bool,
) -> ! {
    let mut read_fd = match sf_open(fifo2_c, libc::O_RDONLY | libc::O_NONBLOCK, 0) {
        Ok(fd) => fd,
        Err(error) => {
            report_open_fifo_error(program_name, daemon, 534, fifo2, error);
            process::exit(1);
        }
    };
    let mut write_fd = 0;
    let mut output = OutputBuffer::new();
    let mut log_number =
        find_next_log_num(log_directory, log_config.generations, program_name, daemon);
    let mut log_fd = open_log(
        log_directory,
        log_number,
        libc::O_RDWR | libc::O_APPEND | libc::O_CREAT | libc::O_SYNC,
        log_config,
        status_path,
        status_file,
        program_name,
        daemon,
    );
    let mut last_activity;
    let mut got_some = false;
    let mut buffer = [0_u8; BUF_SIZE];

    loop {
        let readers = [read_fd, master_fd];
        let writers = if output.size() == 0 {
            Vec::new()
        } else {
            vec![write_fd]
        };
        last_activity = raw::now();
        let timeout = i64::from(log_config.alive_minutes) * 60;
        let selected = raw::select(&readers, &writers, Some(timeout));
        let (ready, mut readable, mut writable) = match selected {
            Ok((ready, readable, writable)) => (ready as i32, readable, writable),
            Err(error) if error.raw_os_error() == Some(libc::EINTR) => {
                if wait_child_exited(child_pid) {
                    raw::alarm(5);
                }
                (-1, Vec::new(), Vec::new())
            }
            Err(error) => {
                report_error(program_name, daemon, 580, "Error in select.", Some(error));
                process::exit(1);
            }
        };
        if ready >= 0 {
            if wait_child_exited(child_pid) {
                raw::alarm(5);
                readable.clear();
                writable.clear();
            }
            let now = raw::now();
            if ready == 0 || now - last_activity > i64::from(log_config.activity_minutes) * 60 {
                let stamp = format_time(&log_config.alive_format, now, log_config.alive_in_utc);
                let mut message = b"\n===== ".to_vec();
                if ready == 0 {
                    message.extend_from_slice(b"ALIVE ");
                }
                message.extend_from_slice(&stamp);
                message.push(b'\n');
                write_to_log(
                    &mut log_fd,
                    &mut log_number,
                    &message,
                    log_directory,
                    log_config,
                    status_path,
                    status_file,
                    program_name,
                    daemon,
                );
            }
        }

        if writable.contains(&write_fd) {
            let pending = output.first();
            match sf_write(write_fd, pending) {
                Ok(written) => output.delete(written),
                Err(error) if error.raw_os_error() == Some(libc::EAGAIN) => {}
                Err(_) => {
                    output.clear();
                    raw::close(write_fd);
                    write_fd = 0;
                }
            }
        }

        if readable.contains(&master_fd) {
            match sf_read(master_fd, &mut buffer) {
                Ok(0) => cleanup_and_exit(read_fd, write_fd, master_fd, fifo1_c, fifo2_c, 0),
                Err(error) => {
                    let saved_error = error;
                    cleanup_fds(read_fd, write_fd, master_fd, fifo1_c, fifo2_c);
                    if saved_error.raw_os_error() == Some(libc::EIO) {
                        report_error(
                            program_name,
                            daemon,
                            661,
                            "Erlang closed the connection.",
                            None,
                        );
                    } else {
                        report_error(
                            program_name,
                            daemon,
                            663,
                            "Error in reading from terminal",
                            Some(saved_error),
                        );
                    }
                    process::exit(1);
                }
                Ok(length) => {
                    write_to_log(
                        &mut log_fd,
                        &mut log_number,
                        &buffer[..length],
                        log_directory,
                        log_config,
                        status_path,
                        status_file,
                        program_name,
                        daemon,
                    );
                    if write_fd != 0 {
                        output.append(&buffer[..length]);
                    }
                }
            }
        }

        if readable.contains(&read_fd) {
            match sf_read(read_fd, &mut buffer) {
                Err(error) => {
                    cleanup_fds(read_fd, write_fd, master_fd, fifo1_c, fifo2_c);
                    report_error(
                        program_name,
                        daemon,
                        693,
                        "Error in reading from FIFO.",
                        Some(error),
                    );
                    process::exit(1);
                }
                Ok(0) => {
                    raw::close(read_fd);
                    read_fd = match sf_open(fifo2_c, libc::O_RDONLY | libc::O_NONBLOCK, 0) {
                        Ok(fd) => fd,
                        Err(error) => {
                            report_open_fifo_error(program_name, daemon, 702, fifo2, error);
                            process::exit(1);
                        }
                    };
                    got_some = false;
                }
                Ok(mut length) => {
                    if write_fd == 0 {
                        match sf_open(fifo1_c, libc::O_WRONLY | libc::O_NONBLOCK, 0) {
                            Ok(fd) => write_fd = fd,
                            Err(_) => {
                                let mut message = b"Client expected on FIFO ".to_vec();
                                message.extend_from_slice(fifo1);
                                message.extend_from_slice(
                                    format!(", but can't open (len={length})\n").as_bytes(),
                                );
                                status(status_file, status_path, program_name, &message);
                                raw::close(read_fd);
                                read_fd =
                                    match sf_open(fifo2_c, libc::O_RDONLY | libc::O_NONBLOCK, 0) {
                                        Ok(fd) => fd,
                                        Err(error) => {
                                            report_open_fifo_error(
                                                program_name,
                                                daemon,
                                                719,
                                                fifo2,
                                                error,
                                            );
                                            process::exit(1);
                                        }
                                    };
                            }
                        }
                    }
                    if !got_some && write_fd != 0 && buffer[0] == 0x1b && buffer[1] == b'l' {
                        output.append(
                            format!("[run_erl v{RUN_ERL_HI_VER}-{RUN_ERL_LO_VER}]\n").as_bytes(),
                        );
                    }
                    got_some = true;
                    length = extract_ctrl_seq(
                        &mut buffer[..length],
                        log_config,
                        master_fd,
                        program_name,
                        daemon,
                    );
                    if length == 1 && buffer[0] == 3 {
                        let _ = raw::kill(child_pid, libc::SIGINT);
                    } else if length > 0
                        && let Err(error) = write_all(master_fd, &buffer[..length])
                    {
                        cleanup_fds(read_fd, write_fd, master_fd, fifo1_c, fifo2_c);
                        report_error(
                            program_name,
                            daemon,
                            750,
                            "Error in writing to terminal.",
                            Some(error),
                        );
                        process::exit(1);
                    }
                }
            }
        }
    }
}

// Port of erts/etc/unix/run_erl.c (pass_on waitpid check), OTP-29.1.1.
fn wait_child_exited(child_pid: libc::pid_t) -> bool {
    raw::waitpid_nohang(child_pid).unwrap_or(false)
}

// Port of erts/etc/unix/run_erl.c (create_fifo), OTP-29.1.1.
fn create_fifo(path: &CStr, program_name: &[u8], daemon: bool, line: i32) {
    if let Err(error) = raw::mkfifo(path, PERM)
        && error.raw_os_error() != Some(libc::EEXIST)
    {
        let mut message = b"Cannot create FIFO ".to_vec();
        message.extend_from_slice(path.to_bytes());
        message.extend_from_slice(b" for writing.\n");
        report_error_bytes(program_name, daemon, line, &message, Some(error));
        process::exit(1);
    }
}

// Port of erts/etc/unix/run_erl.c (find_next_log_num), OTP-29.1.1.
fn find_next_log_num(
    log_directory: &[u8],
    generations: i32,
    program_name: &[u8],
    daemon: bool,
) -> i32 {
    let mut exists = [false; (LOG_MAX_GENERATIONS + 1) as usize];
    let directory = PathBuf::from(OsString::from_vec(log_directory.to_vec()));
    let entries = match std::fs::read_dir(&directory) {
        Ok(entries) => entries,
        Err(error) => {
            let mut message = b"Can't access log directory '".to_vec();
            message.extend_from_slice(log_directory);
            message.extend_from_slice(b"'\n");
            report_error_bytes(program_name, daemon, 806, &message, Some(error));
            process::exit(1);
        }
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.as_bytes();
        if let Some(suffix) = name.strip_prefix(LOG_STUBNAME) {
            let number = atoi_bytes(suffix);
            if number < 1 || number > generations {
                continue;
            }
            exists[number as usize] = true;
        }
    }
    let mut next_generation = 0;
    for index in (0..=generations).rev() {
        if exists[index as usize] {
            if next_generation != 0 {
                break;
            }
        } else {
            next_generation = index;
        }
    }
    if next_generation != 0 {
        prev_log(next_generation, generations)
    } else {
        1
    }
}

// Port of erts/etc/unix/run_erl.c (next_log), OTP-29.1.1.
fn next_log(number: i32, generations: i32) -> i32 {
    if number >= generations { 1 } else { number + 1 }
}

// Port of erts/etc/unix/run_erl.c (prev_log), OTP-29.1.1.
fn prev_log(number: i32, generations: i32) -> i32 {
    if number <= 1 { generations } else { number - 1 }
}

// Port of erts/etc/unix/run_erl.c (open_log), OTP-29.1.1.
#[allow(clippy::too_many_arguments)]
fn open_log(
    log_directory: &[u8],
    log_number: i32,
    flags: libc::c_int,
    config: &LogConfig,
    status_path: &[u8],
    status_file: &mut Option<std::fs::File>,
    program_name: &[u8],
    daemon: bool,
) -> RawFd {
    let next_name = log_path(log_directory, next_log(log_number, config.generations));
    raw::unlink(&c_path(&next_name));
    let path = log_path(log_directory, log_number);
    let fd = match sf_open(&c_path(&path), flags, LOG_PERM) {
        Ok(fd) => fd,
        Err(error) => {
            let mut message = b"Can't open log file '".to_vec();
            message.extend_from_slice(&path);
            message.extend_from_slice(b"'.\n");
            report_error_bytes(program_name, daemon, 866, &message, Some(error));
            process::exit(1);
        }
    };
    let stamp = format_time(&config.alive_format, raw::now(), config.alive_in_utc);
    let mut message = b"\n=====\n===== LOGGING STARTED ".to_vec();
    message.extend_from_slice(&stamp);
    message.extend_from_slice(b"\n=====\n");
    if write_all(fd, &message).is_err() {
        status(
            status_file,
            status_path,
            program_name,
            b"Error in writing to log.\n",
        );
    }
    let _ = raw::fsync(fd);
    fd
}

// Port of erts/etc/unix/run_erl.c (write_to_log), OTP-29.1.1.
#[allow(clippy::too_many_arguments)]
fn write_to_log(
    log_fd: &mut RawFd,
    log_number: &mut i32,
    bytes: &[u8],
    log_directory: &[u8],
    config: &LogConfig,
    status_path: &[u8],
    status_file: &mut Option<std::fs::File>,
    program_name: &[u8],
    daemon: bool,
) {
    let size = raw::lseek_end(*log_fd).unwrap_or(-1);
    if size + bytes.len() as libc::off_t > i64::from(config.max_size) as libc::off_t {
        raw::close(*log_fd);
        *log_number = next_log(*log_number, config.generations);
        *log_fd = open_log(
            log_directory,
            *log_number,
            libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC | libc::O_SYNC,
            config,
            status_path,
            status_file,
            program_name,
            daemon,
        );
    }
    if write_all(*log_fd, bytes).is_err() {
        status(
            status_file,
            status_path,
            program_name,
            b"Error in writing to log.\n",
        );
    }
    let _ = raw::fsync(*log_fd);
}

fn log_path(directory: &[u8], number: i32) -> Vec<u8> {
    let mut path = directory.to_vec();
    safe_string::append(&mut path, b"/", FILENAME_MAX);
    safe_string::append(&mut path, LOG_STUBNAME, FILENAME_MAX);
    safe_string::append(&mut path, number.to_string().as_bytes(), FILENAME_MAX);
    path
}

// Port of erts/etc/unix/run_erl.c (dynamic_strftime), OTP-29.1.1.
fn format_time(format: &[u8], timestamp: libc::time_t, utc: bool) -> Vec<u8> {
    let format = CString::new(format).expect("environment values cannot contain NUL");
    let mut buffer = [0_u8; ALIVE_BUFFSIZ];
    let length = raw::strftime(&format, timestamp, utc, &mut buffer);
    if length == 0 {
        b"(could not format time in 256 positions with current format string.)".to_vec()
    } else {
        buffer[..length].to_vec()
    }
}

// Port of erts/etc/unix/run_erl.c (extract_ctrl_seq), OTP-29.1.1.
fn extract_ctrl_seq(
    buffer: &mut [u8],
    config: &mut LogConfig,
    master_fd: RawFd,
    program_name: &[u8],
    daemon: bool,
) -> usize {
    let prefix = b"\x1b_";
    let suffix = b"\x1b\\";
    let mut length = buffer.len();
    let mut start = 0;
    while let Some(prefix_index) = safe_string::find(&buffer[start..length], prefix) {
        start += prefix_index;
        let command_start = start + prefix.len();
        let Some(suffix_index) = safe_string::find(&buffer[command_start..length], suffix) else {
            let mut message = b"Missing suffix in ctrl sequence '".to_vec();
            message.extend_from_slice(&buffer[start..length]);
            message.extend_from_slice(b"'\n\n");
            report_error_bytes(program_name, daemon, 1423, &message, None);
            break;
        };
        let command_end = command_start + suffix_index;
        let command = &buffer[command_start..command_end];
        if let Some(version) = parse_unsigned_after(command, b"version=") {
            config.protocol_version = version;
        } else if let Some((columns, rows)) = parse_winsize(command) {
            if let Err(error) = raw::set_window_size(master_fd, columns, rows) {
                report_error(
                    program_name,
                    daemon,
                    1438,
                    "Failed to set window size",
                    Some(error),
                );
            }
        } else {
            let mut message = b"Ignoring unknown ctrl command '".to_vec();
            message.extend_from_slice(command);
            message.extend_from_slice(b"'\n\n");
            report_error_bytes(program_name, daemon, 1413, &message, None);
        }
        let after = command_end + suffix.len();
        let removed = after - start;
        buffer.copy_within(after..length, start);
        length -= removed;
    }
    length
}

// Port of erts/etc/unix/run_erl.c (extract_ctrl_seq winsize parsing), OTP-29.1.1.
fn parse_winsize(command: &[u8]) -> Option<(u16, u16)> {
    let values = command.strip_prefix(b"winsize=")?;
    let (columns, end) = parse_scanf_u32(values, 0)?;
    if values.get(end) != Some(&b',') {
        return None;
    }
    let (rows, _) = parse_scanf_u32(values, end + 1)?;
    Some((columns as u16, rows as u16))
}

fn parse_unsigned_after(value: &[u8], prefix: &[u8]) -> Option<u32> {
    parse_scanf_u32(value.strip_prefix(prefix)?, 0).map(|(number, _)| number)
}

fn parse_scanf_u32(value: &[u8], mut index: usize) -> Option<(u32, usize)> {
    while value.get(index).is_some_and(u8::is_ascii_whitespace) {
        index += 1;
    }
    let negative = match value.get(index) {
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
    let mut result = 0_u32;
    while let Some(byte @ b'0'..=b'9') = value.get(index) {
        result = result.wrapping_mul(10).wrapping_add(u32::from(byte - b'0'));
        index += 1;
    }
    if index == start {
        None
    } else {
        Some((
            if negative {
                result.wrapping_neg()
            } else {
                result
            },
            index,
        ))
    }
}

// Port of erts/etc/unix/run_erl.c (main pipe directory scan), OTP-29.1.1.
fn highest_pipe_number(directory: &[u8], program_name: &[u8], daemon: bool) -> i32 {
    let path = OsString::from_vec(directory.to_vec());
    let entries = match std::fs::read_dir(&path) {
        Ok(entries) => entries,
        Err(error) => {
            let mut message = b"Can't access pipe directory '".to_vec();
            message.extend_from_slice(directory);
            message.extend_from_slice(b"'.\n");
            report_error_bytes(program_name, daemon, 340, &message, Some(error));
            process::exit(1);
        }
    };
    let mut highest = 0;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.as_bytes();
        if name.starts_with(PIPE_STUBNAME) {
            let suffix = &name[(PIPE_STUBNAME.len() + 1).min(name.len())..];
            highest = highest.max(atoi_bytes(suffix));
        }
    }
    highest
}

fn atoi(value: &OsString) -> i32 {
    atoi_bytes(value.as_bytes())
}

fn atoi_bytes(value: &[u8]) -> i32 {
    let mut index = 0;
    while value.get(index).is_some_and(u8::is_ascii_whitespace) {
        index += 1;
    }
    let negative = match value.get(index) {
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
    let mut number = 0_i32;
    while let Some(byte @ b'0'..=b'9') = value.get(index) {
        number = number.wrapping_mul(10).wrapping_add(i32::from(byte - b'0'));
        index += 1;
    }
    if negative {
        number.wrapping_neg()
    } else {
        number
    }
}

fn with_suffix(path: &[u8], suffix: &[u8]) -> Vec<u8> {
    let mut result = path.to_vec();
    safe_string::append(&mut result, suffix, FILENAME_MAX);
    result
}

fn c_path(value: &[u8]) -> CString {
    CString::new(value).expect("OS paths cannot contain NUL")
}

fn sf_open(path: &CStr, flags: libc::c_int, mode: libc::mode_t) -> io::Result<RawFd> {
    loop {
        match raw::open(path, flags, mode) {
            Err(error) if error.raw_os_error() == Some(libc::EINTR) => continue,
            result => return result,
        }
    }
}

fn sf_read(fd: RawFd, buffer: &mut [u8]) -> io::Result<usize> {
    loop {
        match raw::read(fd, buffer) {
            Err(error) if error.raw_os_error() == Some(libc::EINTR) => continue,
            result => return result,
        }
    }
}

fn sf_write(fd: RawFd, buffer: &[u8]) -> io::Result<usize> {
    loop {
        match raw::write(fd, buffer) {
            Err(error) if error.raw_os_error() == Some(libc::EINTR) => continue,
            result => return result,
        }
    }
}

fn write_all(fd: RawFd, mut buffer: &[u8]) -> io::Result<()> {
    while !buffer.is_empty() {
        let written = sf_write(fd, buffer)?;
        buffer = &buffer[written..];
    }
    Ok(())
}

// Port of erts/etc/unix/run_erl.c (status), OTP-29.1.1.
fn status(file: &mut Option<std::fs::File>, path: &[u8], _program_name: &[u8], message: &[u8]) {
    if file.is_none() {
        use std::os::unix::fs::OpenOptionsExt;
        *file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o666)
            .open(OsString::from_vec(path.to_vec()))
            .ok();
    }
    let Some(file) = file else { return };
    let prefix = format!("run_erl [{}] {}\n", raw::getpid(), raw::ctime(raw::now()));
    use std::io::Write;
    let _ = file.write_all(prefix.as_bytes());
    let _ = file.write_all(message);
    let _ = file.flush();
}

fn report_error(
    program_name: &[u8],
    daemon: bool,
    line: i32,
    message: &str,
    error: Option<io::Error>,
) {
    let mut message = message.as_bytes().to_vec();
    message.push(b'\n');
    report_error_bytes(program_name, daemon, line, &message, error);
}

fn report_open_fifo_error(
    program_name: &[u8],
    daemon: bool,
    line: i32,
    path: &[u8],
    error: io::Error,
) {
    let mut message = b"Could not open FIFO '".to_vec();
    message.extend_from_slice(path);
    message.extend_from_slice(b"' for reading.\n");
    report_error_bytes(program_name, daemon, line, &message, Some(error));
}

// Port of erts/etc/unix/run_erl.c (error_logf), OTP-29.1.1.
fn report_error_bytes(
    program_name: &[u8],
    daemon: bool,
    line: i32,
    message: &[u8],
    error: Option<io::Error>,
) {
    let mut body = Vec::new();
    if let Some(error) = error {
        let error_number = error.raw_os_error().unwrap_or(0);
        body.extend_from_slice(format!("errno={error_number} '").as_bytes());
        body.extend_from_slice(&raw::strerror(error_number));
        body.extend_from_slice(b"'\n");
    }
    body.extend_from_slice(message);
    if daemon {
        raw::syslog(libc::LOG_ERR, &body);
    } else {
        let mut output = format!(
            "run_erl:{line} [{}] {}\n",
            raw::getpid(),
            raw::ctime(raw::now())
        )
        .into_bytes();
        output.extend_from_slice(&body);
        let _ = raw::write(2, &output);
    }
    let _ = program_name;
}

fn usage(program_name: &[u8]) {
    let mut output = b"Usage: ".to_vec();
    output.extend_from_slice(program_name);
    output.extend_from_slice(
        b" (pipe_name|pipe_dir/) log_dir \"command [parameters ...]\"\n\nYou may also set the environment variables RUN_ERL_LOG_GENERATIONS\nand RUN_ERL_LOG_MAXSIZE to the number of log files to use and the\nsize of the log file when to switch to the next log file\n",
    );
    let _ = raw::write(2, &output);
}

fn cleanup_fds(read_fd: RawFd, write_fd: RawFd, master_fd: RawFd, fifo1: &CStr, fifo2: &CStr) {
    raw::close(read_fd);
    if write_fd != 0 {
        raw::close(write_fd);
    }
    raw::close(master_fd);
    raw::unlink(fifo1);
    raw::unlink(fifo2);
}

fn cleanup_and_exit(
    read_fd: RawFd,
    write_fd: RawFd,
    master_fd: RawFd,
    fifo1: &CStr,
    fifo2: &CStr,
    status: i32,
) -> ! {
    cleanup_fds(read_fd, write_fd, master_fd, fifo1, fifo2);
    process::exit(status)
}

// Port of erts/etc/unix/run_erl.c (daemon_init), OTP-29.1.1.
fn daemon_init(program_name: &[u8]) {
    let max_fd = raw::open_max();
    if raw::fork().unwrap_or(-1) != 0 {
        process::exit(0);
    }
    let _ = raw::setsid();
    let _ = raw::ignore_signal(libc::SIGHUP);
    if raw::fork().unwrap_or(-1) != 0 {
        process::exit(0);
    }
    for fd in 0..max_fd {
        raw::close(fd);
    }
    let null = c"/dev/null";
    let _ = raw::open(null, libc::O_RDONLY, 0);
    let _ = raw::open(null, libc::O_WRONLY, 0);
    let _ = raw::open(null, libc::O_WRONLY, 0);
    let basename = program_name
        .rsplit(|byte| *byte == b'/')
        .next()
        .unwrap_or(program_name);
    raw::openlog(basename);
}
