// Port of erts/emulator/sys/unix/erl_child_setup.c and the forker protocol of
// erts/emulator/sys/unix/sys_drivers.c (forker_start, spawn_start), OTP-29.1.1.
//
//! `erl_child_setup`: the process that forks every OS port child, and the frames the forker
//! port and the spawn ports exchange with it.

use rustix::fd::{AsRawFd, IntoRawFd, OwnedFd, RawFd};
use rustix::fs::{OFlags, fcntl_setfl};
use rustix::io::{fcntl_dupfd_cloexec, write};
use std::ffi::{CString, OsString};
use std::io;
use std::os::unix::ffi::{OsStrExt, OsStringExt};

const START: u32 = 0;
const GO: u32 = 2;
const SIGCHLD: u32 = 3;
const ACK: u32 = 4;
const FRAME_LEN: usize = 32;
/// `THE_NON_VALUE` in a Start `port_id` when the spawn port does not want exit status.
const NO_PORT_ID: u64 = 0;

/// The pipes of a spawn port (spawn_start). The forker's `Go` frame (OS pid or errno)
/// arrives later on `output`; the port reads it as input.
pub(crate) struct SpawnedChild {
    pub(crate) input: OwnedFd,
    pub(crate) output: OwnedFd,
    /// Setup payload bytes the pipe did not take yet.
    pub(crate) setup_rest: Vec<u8>,
    /// The child's ends for the forker's Start request: `ofd[0]`, `ifd[1]`, `stderrfd`.
    pub(crate) child_fds: ChildFds,
}

/// The descriptors a Start request hands to `erl_child_setup`; the forker port closes them
/// once the request is sent (forker_deq).
pub(crate) struct ChildFds {
    input: OwnedFd,
    output: OwnedFd,
    /// A dup of the node's stderr; `None` when stderr goes to `output`.
    stderr: Option<OwnedFd>,
}

impl ChildFds {
    /// `proto->u.start` of spawn_start: the Start request carrying these descriptors and,
    /// when the exit status is wanted, the port id the forker's SigChld names. The
    /// descriptors now belong to the request.
    pub(crate) fn into_start(self, port_id: Option<u64>) -> [u8; FRAME_LEN] {
        let input = self.input.into_raw_fd();
        let output = self.output.into_raw_fd();
        let stderr = self.stderr.map_or(output, IntoRawFd::into_raw_fd);
        let mut frame = [0u8; FRAME_LEN];
        frame[0..4].copy_from_slice(&START.to_ne_bytes());
        frame[8..16].copy_from_slice(&port_id.unwrap_or(NO_PORT_ID).to_ne_bytes());
        for (index, fd) in [input, output, stderr].into_iter().enumerate() {
            let offset = 16 + index * std::mem::size_of::<i32>();
            frame[offset..offset + 4].copy_from_slice(&fd.to_ne_bytes());
        }
        frame
    }
}

/// `proto->u.start.fds` of a Start request.
pub(crate) fn start_fds(frame: &[u8; FRAME_LEN]) -> [RawFd; 3] {
    std::array::from_fn(|index| {
        let offset = 16 + index * std::mem::size_of::<i32>();
        i32::from_ne_bytes(frame[offset..offset + 4].try_into().unwrap())
    })
}

/// `proto->u.start.port_id` of a Start request.
pub(crate) fn start_port_id(frame: &[u8; FRAME_LEN]) -> u64 {
    u64::from_ne_bytes(frame[8..16].try_into().unwrap())
}

/// `proto->u.sigchld`: the port that wants the exit status and the raw wait status (or the
/// errno of a Start request the forker could not take).
pub(crate) struct SigChld {
    pub(crate) port_id: u64,
    pub(crate) status: i32,
}

/// A SigChld frame (forker_sigchld).
pub(crate) fn sigchld_frame(port_id: u64, error: i32) -> [u8; FRAME_LEN] {
    let mut frame = [0u8; FRAME_LEN];
    frame[0..4].copy_from_slice(&SIGCHLD.to_ne_bytes());
    frame[8..16].copy_from_slice(&port_id.to_ne_bytes());
    frame[16..20].copy_from_slice(&error.to_ne_bytes());
    frame
}

/// Decode a SigChld frame; `None` for any other frame.
pub(crate) fn parse_sigchld(frame: &[u8]) -> Option<SigChld> {
    let frame: &[u8; FRAME_LEN] = frame.try_into().ok()?;
    (u32::from_ne_bytes(frame[0..4].try_into().unwrap()) == SIGCHLD).then(|| SigChld {
        port_id: u64::from_ne_bytes(frame[8..16].try_into().unwrap()),
        status: i32::from_ne_bytes(frame[16..20].try_into().unwrap()),
    })
}

/// Length of a forker protocol frame (`ErtsSysForkerProto`).
pub(crate) const FORKER_FRAME_LEN: usize = FRAME_LEN;

/// A parsed `Go` frame: the child's OS pid, or the errno of a failed fork.
pub(crate) enum Go {
    Pid(u32),
    Errno(i32),
}

/// Decode the forker's reply to a start request.
// Port of erts/emulator/sys/unix/sys_drivers.c (`ready_input`, `dd->pid == 0` branch), OTP-29.1.1.
pub(crate) fn parse_go(frame: &[u8; FRAME_LEN]) -> io::Result<Go> {
    if u32::from_ne_bytes(frame[0..4].try_into().unwrap()) != GO {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid forker response",
        ));
    }
    let os_pid = i32::from_ne_bytes(frame[8..12].try_into().unwrap());
    let errno = i32::from_ne_bytes(frame[12..16].try_into().unwrap());
    Ok(if os_pid < 0 {
        Go::Errno(errno.max(1))
    } else {
        Go::Pid(os_pid as u32)
    })
}

/// The acknowledgement frame the port sends after `Go` (`ErtsSysForkerProtoAction_Ack`).
pub(crate) fn ack_frame() -> [u8; FRAME_LEN] {
    let mut ack = [0u8; FRAME_LEN];
    ack[0..4].copy_from_slice(&ACK.to_ne_bytes());
    ack
}

/// Start `erl_child_setup` with a unix domain socket to it (forker_start): the parent's end
/// of the socket.
// Port of erts/emulator/sys/unix/sys_drivers.c (`forker_start`), OTP-29.1.1.
pub(crate) fn start() -> io::Result<OwnedFd> {
    let bindir = crate::erl_osenv::get(b"BINDIR").filter(|value| !value.is_empty());
    let Some(bindir) = bindir else {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "Environment variable BINDIR is not set",
        ));
    };
    if bindir.first() != Some(&b'/') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Environment variable BINDIR does not contain an absolute path",
        ));
    }
    let mut path = OsString::from_vec(bindir);
    path.push("/");
    path.push("erl_child_setup");
    let executable = CString::new(path.as_bytes()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "erl_child_setup path contains NUL",
        )
    })?;
    let max_files = CString::new(crate::erl_poll::erts_poll_max_fds().to_string())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "max_files contains NUL"))?;
    // forker_start: socketpair(AF_UNIX, SOCK_STREAM, 0, fds) — no cloexec before fork.
    let (parent_fd, helper_fd) = crate::port::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0)?;
    crate::port::forker_fork_exec(&executable, helper_fd.as_raw_fd(), &max_files)?;
    // Parent: close(fds[1]).
    drop(helper_fd);
    if crate::port::stdio_is_tty() {
        crate::port::write_tty_mode(parent_fd.as_raw_fd())?;
    }
    // Parent end after fork. erts forker_start does not SET_CLOEXEC on forker_fd;
    // later execs of this OS process must not inherit it.
    crate::port::set_cloexec(parent_fd.as_raw_fd())?;
    Ok(parent_fd)
}

/// The pipes of a new spawn port and the command payload written into the child's input
/// (spawn_start up to the forker request).
// Port of erts/emulator/sys/unix/sys_drivers.c (`spawn_start`), OTP-29.1.1.
pub(crate) fn spawn_pipes(setup: &[u8], stderr_to_stdout: bool) -> io::Result<SpawnedChild> {
    let (parent_output, child_output) = crate::port::pipe()?;
    let max_files = crate::erl_poll::erts_poll_max_fds();
    if parent_output.as_raw_fd() as usize >= max_files {
        return Err(io::Error::from_raw_os_error(libc::EMFILE));
    }
    let (child_input, parent_input) = crate::port::pipe()?;
    if parent_input.as_raw_fd() as usize >= max_files {
        return Err(io::Error::from_raw_os_error(libc::EMFILE));
    }
    // Port of erts/emulator/sys/unix/sys_drivers.c:502, OTP-29.1.1.
    // `dup(2)` is part of spawn_start's capacity check when stderr is not redirected.
    let stderr = if stderr_to_stdout {
        None
    } else {
        Some(fcntl_dupfd_cloexec(std::io::stderr(), 0).map_err(to_io_error)?)
    };
    if stderr.as_ref().unwrap_or(&child_output).as_raw_fd() as usize >= max_files {
        return Err(io::Error::from_raw_os_error(libc::EMFILE));
    }
    // The setup payload goes into the pipe before the request reaches the forker, and what
    // the pipe does not take is queued for the port.
    fcntl_setfl(&parent_input, OFlags::NONBLOCK).map_err(to_io_error)?;
    fcntl_setfl(&parent_output, OFlags::NONBLOCK).map_err(to_io_error)?;
    let mut written = 0;
    while written < setup.len() {
        match write(&parent_input, &setup[written..]) {
            Ok(n) => written += n,
            Err(error) if error == rustix::io::Errno::INTR => continue,
            Err(error) if error == rustix::io::Errno::AGAIN => break,
            Err(error) => return Err(to_io_error(error)),
        }
    }
    Ok(SpawnedChild {
        input: parent_input,
        output: parent_output,
        setup_rest: setup[written..].to_vec(),
        child_fds: ChildFds {
            input: child_input,
            output: child_output,
            stderr,
        },
    })
}

fn to_io_error(error: impl Into<rustix::io::Errno>) -> io::Error {
    io::Error::from_raw_os_error(error.into().raw_os_error())
}
