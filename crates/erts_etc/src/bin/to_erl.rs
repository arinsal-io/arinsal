// Port of erts/etc/unix/to_erl.c and run_erl.h, OTP-29.1.1.

#[path = "../raw_os.rs"]
#[allow(dead_code)]
mod raw;
#[path = "../safe_string.rs"]
mod safe_string;

use std::ffi::CString;
use std::io;
use std::os::fd::RawFd;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::sync::atomic::{AtomicI32, Ordering};

const PIPE_DIR: &[u8] = b"/tmp/";
const PIPE_STUBNAME: &[u8] = b"erlang.pipe";
const FILENAME_MAX: usize = 250;
const RUN_ERL_HI_VER: u32 = 1;
const RUN_ERL_LO_VER: u32 = 0;

static RECV_SIG: AtomicI32 = AtomicI32::new(0);

// Port of erts/etc/unix/to_erl.c (handle_ctrlc), OTP-29.1.1.
extern "C" fn handle_ctrlc(signal: libc::c_int) {
    let _ = raw::signal(signal, handle_ctrlc);
    RECV_SIG.store(signal, Ordering::Relaxed);
}

// Port of erts/etc/unix/to_erl.c (handle_sigwinch), OTP-29.1.1.
extern "C" fn handle_sigwinch(signal: libc::c_int) {
    RECV_SIG.store(signal, Ordering::Relaxed);
}

// Port of erts/etc/unix/to_erl.c (main), OTP-29.1.1.
fn main() {
    let args = std::env::args_os().collect::<Vec<_>>();
    let mut pipe_index = 1;
    let mut force_lock = false;
    if let Some(option) = args
        .get(1)
        .filter(|arg| arg.as_bytes().first() == Some(&b'-'))
    {
        match option.as_bytes().get(1) {
            Some(b'h') => {
                usage(args[0].as_bytes());
                std::process::exit(1);
            }
            Some(b'F') => force_lock = true,
            _ => {
                let mut message = b"Invalid option '".to_vec();
                message.extend_from_slice(option.as_bytes());
                message.extend_from_slice(b"'\n");
                write_stderr(&message);
                std::process::exit(1);
            }
        }
        pipe_index = 2;
    }
    let mut pipe_name = safe_string::copy(
        args.get(pipe_index)
            .map(|value| value.as_bytes())
            .unwrap_or(PIPE_DIR),
        FILENAME_MAX,
    );
    if pipe_name.last() == Some(&b'/') {
        let highest_pipe_num = highest_pipe_number(&pipe_name);
        safe_string::append(&mut pipe_name, PIPE_STUBNAME, FILENAME_MAX);
        if highest_pipe_num != 0 {
            safe_string::append(&mut pipe_name, b".", FILENAME_MAX);
            safe_string::append(
                &mut pipe_name,
                highest_pipe_num.to_string().as_bytes(),
                FILENAME_MAX,
            );
        }
    }
    let fifo_read = with_suffix(&pipe_name, b".r");
    let fifo_write = with_suffix(&pipe_name, b".w");
    let fifo_read_c = c_path(&fifo_read);
    let fifo_write_c = c_path(&fifo_write);

    if let Ok(fd) = raw::open(&fifo_read_c, libc::O_WRONLY | libc::O_NONBLOCK, 0) {
        raw::close(fd);
        let mut message = b"Another to_erl process already attached to pipe ".to_vec();
        message.extend_from_slice(&pipe_name);
        message.extend_from_slice(b".\n");
        write_stderr(&message);
        if force_lock {
            write_stderr(b"But we proceed anyway by force (-F).\n");
        } else {
            std::process::exit(1);
        }
    }

    let rfd = match raw::open(&fifo_read_c, libc::O_RDONLY | libc::O_NONBLOCK, 0) {
        Ok(fd) => fd,
        Err(error) => {
            let mut message = b"No running Erlang on pipe ".to_vec();
            message.extend_from_slice(&pipe_name);
            message.extend_from_slice(b": ");
            message.extend_from_slice(&raw::strerror(error.raw_os_error().unwrap_or(0)));
            message.push(b'\n');
            write_stderr(&message);
            std::process::exit(1);
        }
    };
    let wfd = match raw::open(&fifo_write_c, libc::O_WRONLY | libc::O_NONBLOCK, 0) {
        Ok(fd) => fd,
        Err(error) => {
            let mut message = b"No running Erlang on pipe ".to_vec();
            message.extend_from_slice(&pipe_name);
            message.extend_from_slice(b": ");
            message.extend_from_slice(&raw::strerror(error.raw_os_error().unwrap_or(0)));
            message.push(b'\n');
            write_stderr(&message);
            raw::close(rfd);
            std::process::exit(1);
        }
    };
    let mut message = b"Attaching to ".to_vec();
    message.extend_from_slice(&pipe_name);
    message.extend_from_slice(b" (^D to exit)\n\n");
    write_stderr(&message);

    let _ = raw::signal(libc::SIGINT, handle_ctrlc);
    let old_terminal = raw::tcgetattr(0).ok();
    if let Some(old_terminal) = old_terminal.as_ref() {
        let mut terminal = *old_terminal;
        terminal.c_iflag = libc::BRKINT | libc::IGNPAR;
        terminal.c_oflag = libc::OPOST | libc::XTABS;
        terminal.c_lflag = 0;
        terminal.c_cc[libc::VMIN] = 0;
        terminal.c_cc[libc::VTIME] = 0;
        terminal.c_cc[libc::VINTR] = 3;
        let _ = raw::tcsetattr(0, libc::TCSADRAIN, &terminal);
    }
    if raw::write(wfd, b"\x1bl").is_err() {
        eprintln!("Error in writing ^[l to FIFO.");
    }

    let mut protocol_version = RUN_ERL_LO_VER;
    let mut got_some = false;
    let mut buffer = [0_u8; libc::BUFSIZ as usize];
    loop {
        let (readable, _) = match raw::select(&[0, rfd], &[], None) {
            Ok((_, readable, _)) => (readable, true),
            Err(_) if RECV_SIG.load(Ordering::Relaxed) != 0 => (Vec::new(), false),
            Err(_) => {
                eprintln!("Error in select.");
                break;
            }
        };
        let mut length = 0;
        let signal = RECV_SIG.swap(0, Ordering::Relaxed);
        if signal != 0 {
            match signal {
                libc::SIGINT => {
                    eprint!("[Break]\n\r");
                    buffer[0] = 3;
                    length = 1;
                }
                libc::SIGWINCH => {
                    length = window_size_sequence(&mut buffer);
                }
                _ => eprintln!("Unexpected signal: {}", signal as u32),
            }
        } else if readable.contains(&0) {
            match raw::read(0, &mut buffer) {
                Ok(0) => {
                    raw::close(rfd);
                    raw::close(wfd);
                    eprint!("[EOF]\n\r");
                    break;
                }
                Err(_) => {
                    raw::close(rfd);
                    raw::close(wfd);
                    eprintln!("Error in reading from stdin.");
                    break;
                }
                Ok(count) => {
                    length = count;
                    if buffer[..length].contains(&4) {
                        eprint!("[Quit]\n\r");
                        break;
                    }
                }
            }
        }
        if length != 0 && write_all(wfd, &buffer[..length]).is_err() {
            eprintln!("Error in writing to FIFO.");
            raw::close(rfd);
            raw::close(wfd);
            break;
        }
        if readable.contains(&rfd) {
            match raw::read(rfd, &mut buffer) {
                Ok(0) => {
                    raw::close(rfd);
                    raw::close(wfd);
                    eprint!("[End]\n\r");
                    break;
                }
                Err(error) if error.raw_os_error() == Some(libc::EAGAIN) => {}
                Err(_) => {
                    raw::close(rfd);
                    raw::close(wfd);
                    eprintln!("Error in reading from FIFO.");
                    break;
                }
                Ok(mut len) => {
                    if !got_some {
                        match version_handshake(&mut buffer[..len], wfd, &mut protocol_version) {
                            Ok(new_len) => len = new_len,
                            Err(()) => {
                                raw::close(rfd);
                                raw::close(wfd);
                                break;
                            }
                        }
                        if protocol_version >= 1 {
                            let _ = raw::signal(libc::SIGWINCH, handle_sigwinch);
                            raw::raise(libc::SIGWINCH);
                        }
                        got_some = true;
                    }
                    if write_all(1, &buffer[..len]).is_err() {
                        eprintln!("Error in writing to terminal.");
                        raw::close(rfd);
                        raw::close(wfd);
                        break;
                    }
                }
            }
        }
    }
    if let Some(old_terminal) = old_terminal.as_ref() {
        let _ = raw::tcsetattr(0, libc::TCSADRAIN, old_terminal);
    }
}

// Port of erts/etc/unix/to_erl.c (main pipe directory scan), OTP-29.1.1.
fn highest_pipe_number(directory: &[u8]) -> i32 {
    let directory = std::ffi::OsString::from_vec(directory.to_vec());
    let entries = match std::fs::read_dir(&directory) {
        Ok(entries) => entries,
        Err(error) => {
            let mut message = b"Can't access pipe directory ".to_vec();
            message.extend_from_slice(directory.as_bytes());
            message.extend_from_slice(b": ");
            message.extend_from_slice(&raw::strerror(error.raw_os_error().unwrap_or(0)));
            message.push(b'\n');
            write_stderr(&message);
            std::process::exit(1);
        }
    };
    let mut highest = 0;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.as_bytes();
        if name.starts_with(PIPE_STUBNAME) {
            let start = (PIPE_STUBNAME.len() + 1).min(name.len());
            highest = highest.max(c_atoi_bytes(&name[start..]));
        }
    }
    highest
}

fn c_atoi_bytes(bytes: &[u8]) -> i32 {
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
    let mut number = 0_i32;
    while let Some(byte @ b'0'..=b'9') = bytes.get(index) {
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

// Port of erts/etc/unix/to_erl.c (usage), OTP-29.1.1.
fn usage(program_name: &[u8]) {
    let mut message = b"Usage: ".to_vec();
    message.extend_from_slice(program_name);
    message.extend_from_slice(
        b" [-h|-F] [pipe_name|pipe_dir/]\n\t-h\tThis help text.\n\t-F\tForce connection even though pipe is locked by other to_erl process.\n",
    );
    write_stderr(&message);
}

fn write_stderr(message: &[u8]) {
    let _ = raw::write(2, message);
}

// Port of erts/etc/unix/to_erl.c (write_all), OTP-29.1.1.
fn write_all(fd: RawFd, mut buffer: &[u8]) -> io::Result<()> {
    let length = buffer.len();
    while !buffer.is_empty() {
        let written = raw::write(fd, buffer)?;
        if written == buffer.len() {
            return Ok(());
        }
        buffer = &buffer[written..];
    }
    debug_assert_eq!(length, 0);
    Ok(())
}

// Port of erts/etc/unix/to_erl.c (window_size_seq), OTP-29.1.1.
fn window_size_sequence(buffer: &mut [u8]) -> usize {
    let Ok((columns, rows)) = raw::terminal_window_size(0) else {
        return 0;
    };
    let sequence = format!("\x1b_winsize={columns},{rows}\x1b\\");
    buffer[..sequence.len()].copy_from_slice(sequence.as_bytes());
    sequence.len()
}

// Port of erts/etc/unix/to_erl.c (version_handshake), OTP-29.1.1.
fn version_handshake(
    buffer: &mut [u8],
    write_fd: RawFd,
    protocol_version: &mut u32,
) -> Result<usize, ()> {
    let mut remote_high = 0;
    if let Some(end) = safe_string::find(buffer, b"]\n")
        && let Some((high, low)) = parse_version(&buffer[..end])
    {
        remote_high = high;
        let remote_low = low;
        if remote_low > RUN_ERL_HI_VER {
            eprintln!(
                "Incompatible versions: to_erl=v{}-{} run_erl=v{}-{}",
                RUN_ERL_HI_VER, RUN_ERL_LO_VER, remote_high, remote_low
            );
            return Err(());
        }
        *protocol_version = remote_high.min(RUN_ERL_HI_VER);
        let response = format!("\x1b_version={}\x1b\\", protocol_version);
        if write_all(write_fd, response.as_bytes()).is_err() {
            eprintln!("Failed to send version handshake");
            return Err(());
        }
        let rest = end + 2;
        buffer.copy_within(rest.., 0);
        let length = buffer.len().saturating_sub(rest);
        if remote_high != RUN_ERL_HI_VER {
            eprintln!(
                "run_erl has different version, using common protocol level {}",
                protocol_version
            );
        }
        return Ok(length);
    }
    *protocol_version = 0;
    if remote_high != RUN_ERL_HI_VER {
        eprintln!(
            "run_erl has different version, using common protocol level {}",
            protocol_version
        );
    }
    Ok(buffer.len())
}

fn parse_version(buffer: &[u8]) -> Option<(u32, u32)> {
    let prefix = b"[run_erl v";
    let value = buffer.strip_prefix(prefix)?;
    let (high, dash) = parse_scanf_u32(value, 0)?;
    if value.get(dash) != Some(&b'-') {
        return None;
    }
    let (low, _) = parse_scanf_u32(value, dash + 1)?;
    Some((high, low))
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
    let mut number = 0_u32;
    while let Some(byte @ b'0'..=b'9') = value.get(index) {
        number = number.wrapping_mul(10).wrapping_add(u32::from(byte - b'0'));
        index += 1;
    }
    if index == start {
        None
    } else {
        Some((
            if negative {
                number.wrapping_neg()
            } else {
                number
            },
            index,
        ))
    }
}
