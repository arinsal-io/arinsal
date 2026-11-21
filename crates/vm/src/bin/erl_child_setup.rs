// Port of erts/emulator/sys/unix/erl_child_setup.c (`main`, `start_new_child`,
// `handle_sigchld`), OTP-29.1.1.

#[path = "erl_child_setup/hash.rs"]
mod hash;
#[path = "erl_child_setup/raw.rs"]
mod raw;

use hash::Hash;
use raw::{Fork, UDS_FD};
use std::ffi::{CStr, CString, c_char};
use std::os::fd::RawFd;
use std::sync::atomic::{AtomicI32, Ordering};

const START: u32 = 0;
const GO: u32 = 2;
const SIGCHLD: u32 = 3;
const ACK: u32 = 4;
const FRAME_LEN: usize = 32;
const FORKER_FLAG_USE_STDIO: u32 = 1;
const FORKER_FLAG_DO_READ: u32 = 1 << 2;
const FORKER_FLAG_DO_WRITE: u32 = 1 << 3;
const THE_NON_VALUE: u64 = 0;
const SHELL: &CStr = c"/bin/sh";

static SIGCHLD_PIPE: [AtomicI32; 2] = [AtomicI32::new(-1), AtomicI32::new(-1)];

fn abort_msg(msg: &str) -> ! {
    eprint!("erl_child_setup: {msg}\r\n");
    raw::abort_now();
}

fn main() {
    let mut args = std::env::args_os();
    let _argv0 = args.next();
    let Some(max_files) = args
        .next()
        .and_then(|arg| arg.to_str()?.parse::<i32>().ok())
    else {
        abort_msg("Invalid arguments to child_setup");
    };

    // Port of erts/emulator/sys/unix/erl_child_setup.c (`main`): closefrom(4).
    raw::close_from(4, max_files);

    let sigchld_pipe = raw::pipe().unwrap_or_else(|error| {
        abort_msg(&format!(
            "Failed to setup sigchld pipe ({})",
            error.raw_os_error().unwrap_or(0)
        ));
    });
    if raw::set_cloexec(sigchld_pipe[0]).is_err() || raw::set_cloexec(sigchld_pipe[1]).is_err() {
        abort_msg("Failed to setup sigchld pipe (cloexec)");
    }
    SIGCHLD_PIPE[0].store(sigchld_pipe[0], Ordering::Relaxed);
    SIGCHLD_PIPE[1].store(sigchld_pipe[1], Ordering::Relaxed);

    if raw::install_sigchld(handle_sigchld as *const () as usize as libc::sighandler_t).is_err() {
        perror_exit();
    }
    // Ignore SIGTERM so container SIGTERM to every process does not kill the forker.
    if raw::set_sigterm(libc::SIG_IGN).is_err() {
        perror_exit();
    }
    if raw::set_cloexec(UDS_FD).is_err() {
        abort_msg("SET_CLOEXEC(uds_fd) failed");
    }

    let tty_mode = if raw::stdio_is_tty() {
        match raw::read_tty_mode(UDS_FD) {
            Ok(mode) => Some(mode),
            Err(error) => abort_msg(&format!(
                "Failed to read initial_tty_mode: -1 ({})",
                error.raw_os_error().unwrap_or(0)
            )),
        }
    } else {
        None
    };

    let mut children = Hash::new();
    let uds_fd = std::os::fd::AsRawFd::as_raw_fd(&raw::uds_fd());

    loop {
        let ready = match raw::select_read(uds_fd, sigchld_pipe[0]) {
            Ok(Some(ready)) => ready,
            Ok(None) => continue,
            Err(error) => abort_msg(&format!(
                "Select failed: -1 ({})",
                error.raw_os_error().unwrap_or(0)
            )),
        };

        if ready.0 {
            let mut proto = [0u8; FRAME_LEN];
            let mut pipes = [-1, -1, -1];
            match raw::sys_uds_read(uds_fd, &mut proto, &mut pipes, libc::MSG_DONTWAIT) {
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) | Ok(0) => {
                    if let Some(mode) = &tty_mode {
                        raw::restore_tty(mode);
                    }
                    raw::exit_now(0);
                }
                Ok(_) => {
                    let action = u32::from_ne_bytes(proto[0..4].try_into().unwrap());
                    if action != START {
                        abort_msg("invalid forker request");
                    }
                    let port_id = u64::from_ne_bytes(proto[8..16].try_into().unwrap());
                    raw::sigchld_block(true);
                    let os_pid = match raw::fork() {
                        Ok(Fork::Child) => start_new_child(&pipes),
                        Ok(Fork::Parent(pid)) => pid,
                        Err(_) => -1,
                    };
                    let errno = if os_pid < 0 { raw::last_errno() } else { 0 };
                    if port_id != THE_NON_VALUE {
                        children.put(os_pid, port_id);
                    }
                    let mut go = [0u8; FRAME_LEN];
                    go[0..4].copy_from_slice(&GO.to_ne_bytes());
                    go[8..12].copy_from_slice(&os_pid.to_ne_bytes());
                    go[12..16].copy_from_slice(&errno.to_ne_bytes());
                    let _ = raw::write_all(pipes[1], &go);
                    raw::sigchld_block(false);
                    raw::close(pipes[0]);
                    raw::close(pipes[1]);
                    raw::close(pipes[2]);
                }
            }
        }

        if ready.1 {
            let mut ibuff = [0u8; 8];
            if raw::read_all(sigchld_pipe[0], &mut ibuff).is_err() {
                abort_msg("Failed to read from sigchld pipe");
            }
            let pid = i32::from_ne_bytes(ibuff[0..4].try_into().unwrap());
            let status = i32::from_ne_bytes(ibuff[4..8].try_into().unwrap());
            let Some(port_id) = children.remove(pid) else {
                continue;
            };
            let mut frame = [0u8; FRAME_LEN];
            frame[0..4].copy_from_slice(&SIGCHLD.to_ne_bytes());
            frame[8..16].copy_from_slice(&port_id.to_ne_bytes());
            frame[16..20].copy_from_slice(&status.to_ne_bytes());
            let _ = raw::write_all(uds_fd, &frame);
        }
    }
}

/// `handle_sigchld`: reap with WNOHANG and write `{pid, status}` to the pipe.
// Port of erts/emulator/sys/unix/erl_child_setup.c (`handle_sigchld`), OTP-29.1.1.
extern "C" fn handle_sigchld(_sig: i32) {
    // waitpid's ECHILD must not leak into the select loop (OTP-3906 comment).
    let prev_errno = raw::last_errno();
    raw::sigchld_block(true);
    let write_fd = SIGCHLD_PIPE[1].load(Ordering::Relaxed);
    while let Some((pid, status)) = raw::waitpid_nohang() {
        let mut buff = [0u8; 8];
        buff[0..4].copy_from_slice(&pid.to_ne_bytes());
        buff[4..8].copy_from_slice(&status.to_ne_bytes());
        if raw::write_all(write_fd, &buff).is_err() {
            abort_msg("Failed to write to sigchld_pipe");
        }
    }
    raw::sigchld_block(false);
    raw::set_errno(prev_errno);
}

/// `start_new_child`: never returns.
// Port of erts/emulator/sys/unix/erl_child_setup.c (`start_new_child`), OTP-29.1.1.
fn start_new_child(pipes: &[RawFd; 3]) -> ! {
    if raw::set_sigterm(libc::SIG_DFL).is_err() {
        perror_exit();
    }

    let mut size = [0u8; 4];
    if raw::read_all(pipes[0], &mut size).is_err() {
        child_error();
    }
    let size = u32::from_ne_bytes(size) as usize;
    let mut buff = vec![0u8; size];
    if raw::read_all(pipes[0], &mut buff).is_err() {
        child_error();
    }

    let parsed = match parse_payload(&buff) {
        Ok(parsed) => parsed,
        Err(_) => {
            eprint!(
                "erl_child_setup: failed with protocol error {} on line 0",
                libc::EINVAL
            );
            raw::abort_now();
        }
    };

    let mut ack = [0u8; FRAME_LEN];
    if raw::read_all(pipes[0], &mut ack).is_err() {
        child_error();
    }
    if u32::from_ne_bytes(ack[0..4].try_into().unwrap()) != ACK {
        child_error();
    }

    let _ = raw::chdir(&parsed.cwd);
    if let Some(wd) = &parsed.wd
        && let Err(error) = raw::chdir(wd)
    {
        eprint!("spawn: Could not cd to {}\r\n", wd.to_string_lossy());
        raw::exit_now(error.raw_os_error().unwrap_or(libc::EIO));
    }

    let flags = parsed.flags;
    if flags & FORKER_FLAG_USE_STDIO != 0 {
        if flags & FORKER_FLAG_DO_WRITE != 0 && raw::dup2(pipes[0], 0).is_err() {
            child_error();
        }
        if flags & FORKER_FLAG_DO_READ != 0 && raw::dup2(pipes[1], 1).is_err() {
            child_error();
        }
    } else {
        if flags & FORKER_FLAG_DO_READ != 0 && raw::dup2(pipes[1], 4).is_err() {
            child_error();
        }
        if flags & FORKER_FLAG_DO_WRITE != 0 && raw::dup2(pipes[0], 3).is_err() {
            child_error();
        }
    }
    if raw::dup2(pipes[2], 2).is_err() {
        child_error();
    }

    raw::setsid();
    raw::close(pipes[0]);
    raw::close(pipes[1]);
    raw::close(pipes[2]);
    raw::sigchld_block(false);

    let mut env_ptrs: Vec<*const c_char> = parsed.env.iter().map(|e| e.as_ptr()).collect();
    env_ptrs.push(std::ptr::null());
    if let Some(args) = parsed.args {
        let mut argv: Vec<*const c_char> = args.iter().map(|a| a.as_ptr()).collect();
        argv.push(std::ptr::null());
        let err = raw::execve(&parsed.cmd, &argv, &env_ptrs);
        raw::exit_now(err.raw_os_error().unwrap_or(libc::EIO));
    }
    let sh = c"sh";
    let dash_c = c"-c";
    let argv = [
        sh.as_ptr(),
        dash_c.as_ptr(),
        parsed.cmd.as_ptr(),
        std::ptr::null(),
    ];
    let err = raw::execve(SHELL, &argv, &env_ptrs);
    raw::exit_now(err.raw_os_error().unwrap_or(libc::EIO));
}

struct Parsed {
    flags: u32,
    cmd: CString,
    cwd: CString,
    wd: Option<CString>,
    env: Vec<CString>,
    args: Option<Vec<CString>>,
}

fn parse_payload(buff: &[u8]) -> Result<Parsed, ()> {
    let mut offset = 0;
    let flags = get_int32(buff, &mut offset)?;
    let cmd = cstring(buff, &mut offset)?;
    let cwd = cstring(buff, &mut offset)?;
    let wd = if buff.get(offset).copied() == Some(0) {
        offset += 1;
        None
    } else {
        let wd = cstring(buff, &mut offset)?;
        offset += 1;
        Some(wd)
    };
    let env_len = get_int32(buff, &mut offset)? as usize;
    let mut env = Vec::with_capacity(env_len);
    for _ in 0..env_len {
        env.push(cstring(buff, &mut offset)?);
    }
    let args = if offset == buff.len() {
        None
    } else {
        let count = get_int32(buff, &mut offset)? as usize;
        let mut args = Vec::with_capacity(count);
        for _ in 0..count {
            args.push(cstring(buff, &mut offset)?);
        }
        Some(args)
    };
    if offset != buff.len() {
        return Err(());
    }
    Ok(Parsed {
        flags: flags as u32,
        cmd,
        cwd,
        wd,
        env,
        args,
    })
}

fn get_int32(buff: &[u8], offset: &mut usize) -> Result<i32, ()> {
    let end = offset
        .checked_add(4)
        .filter(|end| *end <= buff.len())
        .ok_or(())?;
    let value = i32::from_be_bytes(buff[*offset..end].try_into().unwrap());
    *offset = end;
    Ok(value)
}

fn cstring(buff: &[u8], offset: &mut usize) -> Result<CString, ()> {
    let rest = buff.get(*offset..).ok_or(())?;
    let n = rest.iter().position(|b| *b == 0).ok_or(())?;
    let bytes = rest[..n].to_vec();
    *offset += n + 1;
    CString::new(bytes).map_err(|_| ())
}

fn child_error() -> ! {
    eprint!(
        "erl_child_setup: failed with error {} on line 0\r\n",
        raw::last_errno()
    );
    raw::exit_now(raw::last_errno());
}

fn perror_exit() -> ! {
    raw::exit_now(1);
}
