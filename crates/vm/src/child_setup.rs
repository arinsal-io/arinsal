//! Unix child-setup service for operating-system ports.

use mio::unix::SourceFd;
use mio::{Events, Interest, Poll, Token};
use rustix::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd, RawFd};
use rustix::fs::{OFlags, fcntl_setfl};
use rustix::io::{FdFlags, fcntl_dupfd_cloexec, fcntl_setfd, write};
use rustix::net::{
    AddressFamily, RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, SendAncillaryBuffer,
    SendAncillaryMessage, SendFlags, SocketFlags, SocketType, recvmsg, sendmsg, socketpair,
};
use rustix::pipe::pipe;
use signal_hook_mio::v1_0::Signals;
use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::io::{self, IoSlice, IoSliceMut, Read, Write as _};
use std::mem::MaybeUninit;
use std::net::Shutdown;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};

const START: u32 = 0;
const GO: u32 = 2;
const SIGCHLD: u32 = 3;
const ACK: u32 = 4;
const FRAME_LEN: usize = 32;
const CHILD_USE_STDIO: u32 = 1;
const CHILD_DO_READ: u32 = 1 << 2;
const CHILD_DO_WRITE: u32 = 1 << 3;
const NO_PORT_ID: u64 = u64::MAX;
const SIGNAL_TOKEN: Token = Token(0);
const CONTROL_TOKEN: Token = Token(1);

/// The parent-side handle for the runtime's persistent `erl_child_setup` process.
pub(crate) struct ChildSetup {
    control: Mutex<UnixStream>,
    pending: Arc<Mutex<Pending>>,
    helper: Mutex<Option<Child>>,
    response_thread: Mutex<Option<std::thread::JoinHandle<()>>>,
}

#[derive(Default)]
struct Pending {
    status: HashMap<u64, Sender<i64>>,
}

/// Parent endpoints and status stream for a spawned port process.
pub(crate) struct SpawnedChild {
    pub(crate) os_pid: u32,
    pub(crate) input: Option<OwnedFd>,
    pub(crate) output: Option<OwnedFd>,
    pub(crate) status: Option<Receiver<i64>>,
}

/// Start the persistent forker before the runtime begins running BEAM code.
// Port of erts/emulator/sys/unix/sys_drivers.c (`forker_start`), OTP-29.1.1.
pub(crate) fn start() -> io::Result<Arc<ChildSetup>> {
    let executable = arinsal_executable().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "arinsal child-setup executable not found",
        )
    })?;
    let (parent_fd, helper_fd) = socketpair(
        AddressFamily::UNIX,
        SocketType::STREAM,
        SocketFlags::empty(),
        None,
    )
    .map_err(to_io_error)?;
    fcntl_setfd(&parent_fd, FdFlags::CLOEXEC).map_err(to_io_error)?;
    fcntl_setfd(&helper_fd, FdFlags::CLOEXEC).map_err(to_io_error)?;
    let vm_stdin = fcntl_dupfd_cloexec(std::io::stdin(), 3).map_err(to_io_error)?;
    let vm_stdout = fcntl_dupfd_cloexec(std::io::stdout(), 3).map_err(to_io_error)?;
    fcntl_setfd(&vm_stdin, FdFlags::empty()).map_err(to_io_error)?;
    fcntl_setfd(&vm_stdout, FdFlags::empty()).map_err(to_io_error)?;
    let parent = UnixStream::from(parent_fd);
    let read_stream = parent.try_clone()?;
    let mut command = Command::new(executable);
    command
        .arg("--child-setup")
        .stdin(Stdio::from(helper_fd))
        .stdout(Stdio::from(std::fs::File::from(vm_stdin)))
        .stderr(Stdio::from(std::fs::File::from(vm_stdout)))
        .process_group(0)
        .env_clear();
    let helper = command.spawn()?;
    let pending = Arc::new(Mutex::new(Pending::default()));
    let response_pending = Arc::clone(&pending);
    let response_thread = std::thread::Builder::new()
        .name("arinsal-child-setup-io".to_owned())
        .spawn(move || response_loop(read_stream, response_pending))?;
    Ok(Arc::new(ChildSetup {
        control: Mutex::new(parent),
        pending,
        helper: Mutex::new(Some(helper)),
        response_thread: Mutex::new(Some(response_thread)),
    }))
}

impl ChildSetup {
    pub(crate) fn shutdown(&self) {
        let _ = self.control.lock().unwrap().shutdown(Shutdown::Write);
        if let Some(mut helper) = self.helper.lock().unwrap().take() {
            let _ = helper.wait();
        }
        if let Some(response_thread) = self.response_thread.lock().unwrap().take() {
            let _ = response_thread.join();
        }
    }

    /// Launch a child through the persistent helper and complete the `Go`/`Ack` handshake.
    // Port of erts/emulator/sys/unix/sys_drivers.c (`spawn_start`), OTP-29.1.1.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn spawn(
        &self,
        port_id: u64,
        setup: &[u8],
        status_wanted: bool,
        _use_stdio: bool,
        read_write: u8,
        stderr_to_stdout: bool,
    ) -> io::Result<SpawnedChild> {
        let (parent_output, child_output) = pipe().map_err(to_io_error)?;
        let max_files = crate::erl_poll::erts_poll_max_fds();
        if parent_output.as_raw_fd() as usize >= max_files {
            return Err(io::Error::from_raw_os_error(libc::EMFILE));
        }
        let (child_input, parent_input) = pipe().map_err(to_io_error)?;
        if parent_input.as_raw_fd() as usize >= max_files {
            return Err(io::Error::from_raw_os_error(libc::EMFILE));
        }
        // Port of erts/emulator/sys/unix/sys_drivers.c:502, OTP-29.1.1.
        // `dup(2)` is part of spawn_start's capacity check when stderr is not redirected.
        let stderr_dup = if stderr_to_stdout {
            None
        } else {
            Some(fcntl_dupfd_cloexec(std::io::stderr(), 0).map_err(to_io_error)?)
        };
        let stderr = stderr_dup
            .as_ref()
            .map(AsFd::as_fd)
            .unwrap_or_else(|| child_output.as_fd());
        if stderr.as_raw_fd() as usize >= max_files {
            return Err(io::Error::from_raw_os_error(libc::EMFILE));
        }
        let fds: Vec<BorrowedFd<'_>> = vec![child_input.as_fd(), child_output.as_fd(), stderr];
        let (status_tx, status_rx) = mpsc::channel();
        {
            let mut pending = self.pending.lock().unwrap();
            if status_wanted {
                pending.status.insert(port_id, status_tx);
            }
        }
        let mut frame = [0u8; FRAME_LEN];
        frame[0..4].copy_from_slice(&START.to_ne_bytes());
        frame[8..16]
            .copy_from_slice(&(if status_wanted { port_id } else { NO_PORT_ID }).to_ne_bytes());
        for (index, fd) in fds.iter().enumerate() {
            let offset = 16 + index * std::mem::size_of::<i32>();
            frame[offset..offset + 4].copy_from_slice(&fd.as_raw_fd().to_ne_bytes());
        }
        if let Err(error) = self.send_start(&frame, &fds) {
            self.pending.lock().unwrap().status.remove(&port_id);
            return Err(error);
        }
        drop(child_input);
        drop(child_output);

        let mut go = [0u8; FRAME_LEN];
        if let Err(error) = read_exact_fd(&parent_output, &mut go) {
            self.pending.lock().unwrap().status.remove(&port_id);
            return Err(error);
        }
        if u32::from_ne_bytes(go[0..4].try_into().unwrap()) != GO {
            self.pending.lock().unwrap().status.remove(&port_id);
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid forker response",
            ));
        }
        let os_pid = i32::from_ne_bytes(go[8..12].try_into().unwrap());
        let errno = i32::from_ne_bytes(go[12..16].try_into().unwrap());
        if os_pid < 0 {
            self.pending.lock().unwrap().status.remove(&port_id);
            return Err(io::Error::from_raw_os_error(errno.max(1)));
        }
        if let Err(error) = write_all_fd(&parent_input, setup) {
            self.pending.lock().unwrap().status.remove(&port_id);
            return Err(error);
        }
        let mut ack = [0u8; FRAME_LEN];
        ack[0..4].copy_from_slice(&ACK.to_ne_bytes());
        if let Err(error) = write_all_fd(&parent_input, &ack) {
            self.pending.lock().unwrap().status.remove(&port_id);
            return Err(error);
        }

        let input = if read_write & 2 != 0 {
            fcntl_setfl(&parent_input, OFlags::NONBLOCK).map_err(to_io_error)?;
            Some(parent_input)
        } else {
            None
        };
        let output = if read_write & 1 != 0 {
            fcntl_setfl(&parent_output, OFlags::NONBLOCK).map_err(to_io_error)?;
            Some(parent_output)
        } else {
            None
        };
        Ok(SpawnedChild {
            os_pid: os_pid as u32,
            input,
            output,
            status: status_wanted.then_some(status_rx),
        })
    }

    fn send_start(&self, frame: &[u8; FRAME_LEN], fds: &[BorrowedFd<'_>]) -> io::Result<()> {
        let mut stream = self.control.lock().unwrap();
        let mut ancillary_space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(3))];
        let mut ancillary = SendAncillaryBuffer::new(&mut ancillary_space);
        if !ancillary.push(SendAncillaryMessage::ScmRights(fds)) {
            return Err(io::Error::other("forker descriptor message is too large"));
        }
        let sent = sendmsg(
            &*stream,
            &[IoSlice::new(frame)],
            &mut ancillary,
            SendFlags::empty(),
        )
        .map_err(to_io_error)?;
        if sent < frame.len() {
            stream.write_all(&frame[sent..])?;
        }
        Ok(())
    }
}

impl Drop for ChildSetup {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn response_loop(mut stream: UnixStream, pending: Arc<Mutex<Pending>>) {
    let mut frame = [0u8; FRAME_LEN];
    loop {
        if stream.read_exact(&mut frame).is_err() {
            break;
        }
        let action = u32::from_ne_bytes(frame[0..4].try_into().unwrap());
        if action == SIGCHLD {
            let port_id = u64::from_ne_bytes(frame[8..16].try_into().unwrap());
            let status = i32::from_ne_bytes(frame[16..20].try_into().unwrap());
            if let Some(sender) = pending.lock().unwrap().status.remove(&port_id) {
                let _ = sender.send(child_wait_status(status));
            }
        }
    }
}

/// Run in the persistent child-setup process selected by the CLI's hidden mode.
///
/// This is a public entry point only so the CLI binary can dispatch the helper mode.
// Port of erts/emulator/sys/unix/erl_child_setup.c (`main`), OTP-29.1.1.
pub fn run_child_setup() -> ! {
    if let Err(error) = forker_loop() {
        eprintln!("erl_child_setup: {error}");
        std::process::exit(1);
    }
    std::process::exit(0)
}

fn forker_loop() -> io::Result<()> {
    let stdin = std::io::stdin();
    let control = stdin.lock();
    let control_fd = control.as_raw_fd();
    // The launcher preserves the VM's standard streams on the helper's stdout and stderr.
    let vm_stdin = inheritable_dup(&std::io::stdout())?;
    let vm_stdout = inheritable_dup(&std::io::stderr())?;
    let mut poll = Poll::new()?;
    let mut control_source = SourceFd(&control_fd);
    poll.registry()
        .register(&mut control_source, CONTROL_TOKEN, Interest::READABLE)?;
    let mut signals = Signals::new([libc::SIGCHLD, libc::SIGTERM])?;
    poll.registry()
        .register(&mut signals, SIGNAL_TOKEN, Interest::READABLE)?;
    let mut events = Events::with_capacity(8);
    let mut children: HashMap<u32, TrackedChild> = HashMap::new();

    loop {
        if let Err(error) = poll.poll(&mut events, None) {
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        let mut got_control = false;
        let mut got_sigchld = false;
        for event in &events {
            match event.token() {
                CONTROL_TOKEN => got_control = true,
                SIGNAL_TOKEN => got_sigchld = true,
                _ => {}
            }
        }
        // mio registers the descriptor edge-triggered, while erl_child_setup.c polls it level-
        // triggered: serve every queued request, or a start frame that arrived with its
        // predecessor is never seen and its spawner waits for `Go` forever.
        while got_control {
            match recv_start(&control)? {
                Some((frame, fds)) => {
                    if u32::from_ne_bytes(frame[0..4].try_into().unwrap()) != START {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "invalid forker request",
                        ));
                    }
                    let port_id = u64::from_ne_bytes(frame[8..16].try_into().unwrap());
                    if fds.len() != 3 {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "forker start did not pass three descriptors",
                        ));
                    }
                    let child =
                        spawn_setup_child(fds, vm_stdin.as_raw_fd(), vm_stdout.as_raw_fd())?;
                    if let Some(child) = child {
                        children.insert(
                            child.id(),
                            TrackedChild {
                                child,
                                port_id: (port_id != NO_PORT_ID).then_some(port_id),
                            },
                        );
                    }
                }
                None => return Ok(()),
            }
            got_control = control_readable(&control)?;
        }
        if got_sigchld {
            let _ = signals.pending().count();
            reap_children(&mut children, &control)?;
        }
    }
}

struct TrackedChild {
    child: Child,
    port_id: Option<u64>,
}

/// Whether the control socket has another queued request (a zero-timeout level check).
fn control_readable(control: &impl AsFd) -> io::Result<bool> {
    use rustix::event::{PollFd, PollFlags, Timespec, poll};
    let mut fds = [PollFd::new(control, PollFlags::IN)];
    loop {
        match poll(
            &mut fds,
            Some(&Timespec {
                tv_sec: 0,
                tv_nsec: 0,
            }),
        ) {
            Ok(ready) => return Ok(ready > 0),
            Err(error) if error == rustix::io::Errno::INTR => continue,
            Err(error) => return Err(to_io_error(error)),
        }
    }
}

fn inheritable_dup(fd: &impl AsFd) -> io::Result<OwnedFd> {
    let duplicate = fcntl_dupfd_cloexec(fd, 5).map_err(to_io_error)?;
    fcntl_setfd(&duplicate, FdFlags::empty()).map_err(to_io_error)?;
    Ok(duplicate)
}

fn spawn_setup_child(
    fds: Vec<OwnedFd>,
    vm_stdin: RawFd,
    vm_stdout: RawFd,
) -> io::Result<Option<Child>> {
    let mut fds = fds.into_iter();
    let input = fds.next().unwrap();
    let output = fds.next().unwrap();
    let stderr = fds.next().unwrap();
    let go_output = fcntl_dupfd_cloexec(&output, 3).map_err(to_io_error)?;
    let Some(executable) = arinsal_executable() else {
        write_go(&go_output, -1, libc::ENOENT)?;
        return Ok(None);
    };
    let mut command = Command::new(executable);
    command
        .arg("--child-setup-exec")
        .stdin(Stdio::from(input))
        .stdout(Stdio::from(output))
        .stderr(Stdio::from(stderr))
        .process_group(0)
        .env_clear()
        .env("ARINSAL_CHILD_VM_STDIN", vm_stdin.to_string())
        .env("ARINSAL_CHILD_VM_STDOUT", vm_stdout.to_string());
    match command.spawn() {
        Ok(child) => Ok(Some(child)),
        Err(error) => {
            write_go(&go_output, -1, error.raw_os_error().unwrap_or(libc::EIO))?;
            Ok(None)
        }
    }
}

fn write_go(output: &impl AsFd, pid: i32, errno: i32) -> io::Result<()> {
    let mut frame = [0u8; FRAME_LEN];
    frame[0..4].copy_from_slice(&GO.to_ne_bytes());
    frame[8..12].copy_from_slice(&pid.to_ne_bytes());
    frame[12..16].copy_from_slice(&errno.to_ne_bytes());
    write_response(output, &frame)
}

fn reap_children(children: &mut HashMap<u32, TrackedChild>, control: &impl AsFd) -> io::Result<()> {
    let mut exited = Vec::new();
    for (pid, tracked) in children.iter_mut() {
        let status = loop {
            match tracked.child.try_wait() {
                Ok(status) => break status,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            }
        };
        if let Some(status) = status {
            if let Some(port_id) = tracked.port_id {
                let mut frame = [0u8; FRAME_LEN];
                frame[0..4].copy_from_slice(&SIGCHLD.to_ne_bytes());
                frame[8..16].copy_from_slice(&port_id.to_ne_bytes());
                frame[16..20].copy_from_slice(&wait_status(status).to_ne_bytes());
                write_response(control, &frame)?;
            }
            exited.push(*pid);
        }
    }
    for pid in exited {
        children.remove(&pid);
    }
    Ok(())
}

fn recv_start(control: &impl AsFd) -> io::Result<Option<([u8; FRAME_LEN], Vec<OwnedFd>)>> {
    let mut frame = [0u8; FRAME_LEN];
    let mut iov = [IoSliceMut::new(&mut frame)];
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(3))];
    let mut ancillary = RecvAncillaryBuffer::new(&mut space);
    let message = loop {
        match recvmsg(control, &mut iov, &mut ancillary, RecvFlags::empty()) {
            Ok(message) if message.bytes == 0 => return Ok(None),
            Ok(message) => break message,
            Err(error) if error == rustix::io::Errno::INTR => continue,
            Err(error) => return Err(to_io_error(error)),
        }
    };
    if message.bytes < FRAME_LEN {
        read_exact_fd(control, &mut frame[message.bytes..])?;
    }
    let mut fds = Vec::new();
    for message in ancillary.drain() {
        if let RecvAncillaryMessage::ScmRights(received) = message {
            fds.extend(received);
        }
    }
    Ok(Some((frame, fds)))
}

fn read_exact_fd(fd: &impl AsFd, buffer: &mut [u8]) -> io::Result<()> {
    let mut offset = 0;
    while offset < buffer.len() {
        match rustix::io::read(fd, &mut buffer[offset..]) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "forker socket closed",
                ));
            }
            Ok(read) => offset += read,
            Err(error) if error == rustix::io::Errno::INTR => continue,
            Err(error) => return Err(to_io_error(error)),
        }
    }
    Ok(())
}

fn write_response(control: &impl AsFd, frame: &[u8; FRAME_LEN]) -> io::Result<()> {
    let mut offset = 0;
    while offset < frame.len() {
        match write(control, &frame[offset..]) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "forker socket closed",
                ));
            }
            Ok(written) => offset += written,
            Err(error) if error == rustix::io::Errno::INTR => continue,
            Err(error) => return Err(to_io_error(error)),
        }
    }
    Ok(())
}

fn write_all_fd(fd: &impl AsFd, bytes: &[u8]) -> io::Result<()> {
    let mut offset = 0;
    while offset < bytes.len() {
        match write(fd, &bytes[offset..]) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "child pipe closed",
                ));
            }
            Ok(written) => offset += written,
            Err(error) if error == rustix::io::Errno::INTR => continue,
            Err(error) => return Err(to_io_error(error)),
        }
    }
    Ok(())
}

fn wait_status(status: ExitStatus) -> i32 {
    use std::os::unix::process::ExitStatusExt;
    status.into_raw()
}

fn child_wait_status(raw: i32) -> i64 {
    use std::os::unix::process::ExitStatusExt;
    let status = ExitStatus::from_raw(raw);
    match status.signal() {
        Some(signal) => 128 + i64::from(signal),
        None => i64::from(status.code().unwrap_or(0)),
    }
}

/// Execute a single staged spawn request, in the helper's child process.
///
/// This is dispatched by the CLI after the persistent forker forks the child.
// Port of erts/emulator/sys/unix/erl_child_setup.c (`start_new_child`), OTP-29.1.1.
pub fn run_child_setup_exec() -> ! {
    match child_setup_exec() {
        Ok(()) => std::process::exit(0),
        Err(error) => {
            eprintln!("erl_child_setup: {error}");
            std::process::exit(error.raw_os_error().unwrap_or(libc::EIO));
        }
    }
}

fn child_setup_exec() -> io::Result<()> {
    let stdin = std::io::stdin();
    let mut go = [0u8; FRAME_LEN];
    go[0..4].copy_from_slice(&GO.to_ne_bytes());
    go[8..12].copy_from_slice(&(std::process::id() as i32).to_ne_bytes());
    write_all_fd(&std::io::stdout(), &go)?;

    let mut size = [0u8; 4];
    read_exact_fd(&stdin, &mut size)?;
    let size = u32::from_ne_bytes(size) as usize;
    let mut payload = vec![0u8; size];
    read_exact_fd(&stdin, &mut payload)?;
    let config = ExecConfig::decode(&payload)?;
    let mut ack = [0u8; FRAME_LEN];
    read_exact_fd(&stdin, &mut ack)?;
    if u32::from_ne_bytes(ack[0..4].try_into().unwrap()) != ACK {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid child-setup acknowledgement",
        ));
    }

    let cwd = OsString::from_vec(config.cwd);
    let _ = std::env::set_current_dir(cwd);
    if let Some(wd) = config.wd
        && let Err(error) = std::env::set_current_dir(OsString::from_vec(wd.clone()))
    {
        eprintln!(
            "spawn: Could not cd to {}",
            OsStr::from_bytes(&wd).to_string_lossy()
        );
        return Err(error);
    }
    if !config.use_stdio {
        if config.do_write {
            let input = duplicate_into(stdin.as_fd(), 3)?;
            if input.as_raw_fd() != 3 {
                return Err(io::Error::other("unexpected child stdin descriptor"));
            }
            std::mem::forget(input);
        }
        if config.do_read {
            let output = duplicate_into(std::io::stdout().as_fd(), 4)?;
            if output.as_raw_fd() != 4 {
                return Err(io::Error::other("unexpected child stdout descriptor"));
            }
            std::mem::forget(output);
        }
    }
    let (vm_stdin_fd, vm_stdout_fd) = config.inherited_vm_fds;
    if !config.use_stdio || !config.do_write {
        nix::unistd::dup2(vm_stdin_fd, 0).map_err(to_nix_error)?;
    }
    if !config.use_stdio || !config.do_read {
        nix::unistd::dup2(vm_stdout_fd, 1).map_err(to_nix_error)?;
    }
    nix::unistd::close(vm_stdin_fd)
        .map_err(|error| io::Error::other(format!("close inherited stdin: {error}")))?;
    nix::unistd::close(vm_stdout_fd)
        .map_err(|error| io::Error::other(format!("close inherited stdout: {error}")))?;
    let mut kept = Vec::new();
    if !config.use_stdio {
        if config.do_write {
            kept.push(3);
        }
        if config.do_read {
            kept.push(4);
        }
    }
    close_child_descriptors(&kept)?;

    let mut command = if let Some(args) = config.args {
        let mut command = Command::new(OsString::from_vec(config.program));
        if let Some((arg0, rest)) = args.split_first() {
            command
                .arg0(OsString::from_vec(arg0.clone()))
                .args(rest.iter().map(|arg| OsString::from_vec(arg.clone())));
        }
        command
    } else {
        let mut command = Command::new("/bin/sh");
        command
            .arg0("sh")
            .arg("-c")
            .arg(OsString::from_vec(config.program));
        command
    };
    command.env_clear();
    command.envs(
        config
            .env
            .into_iter()
            .map(|(key, value)| (OsString::from_vec(key), OsString::from_vec(value))),
    );
    Err(command.exec())
}

fn duplicate_into(fd: impl AsFd, target: i32) -> io::Result<OwnedFd> {
    let duplicate = fcntl_dupfd_cloexec(fd, target).map_err(to_io_error)?;
    if duplicate.as_raw_fd() != target {
        return Err(io::Error::other("child descriptor slot is occupied"));
    }
    fcntl_setfd(&duplicate, FdFlags::empty()).map_err(to_io_error)?;
    Ok(duplicate)
}

fn close_child_descriptors(keep: &[i32]) -> io::Result<()> {
    // Port of erts/emulator/sys/unix/erl_child_setup.c (`main`), OTP-29.1.1.
    let descriptors = std::fs::read_dir("/dev/fd")?
        .filter_map(Result::ok)
        .filter_map(|entry| entry.file_name().to_string_lossy().parse::<i32>().ok())
        .filter(|fd| *fd >= 3 && !keep.contains(fd))
        .collect::<Vec<_>>();
    for fd in descriptors {
        let _ = nix::unistd::close(fd);
    }
    Ok(())
}

struct ExecConfig {
    use_stdio: bool,
    do_read: bool,
    do_write: bool,
    program: Vec<u8>,
    cwd: Vec<u8>,
    wd: Option<Vec<u8>>,
    env: Vec<(Vec<u8>, Vec<u8>)>,
    args: Option<Vec<Vec<u8>>>,
    inherited_vm_fds: (i32, i32),
}

impl ExecConfig {
    fn decode(payload: &[u8]) -> io::Result<Self> {
        let mut cursor = Cursor::new(payload);
        let flags = cursor.i32()? as u32;
        let program = cursor.cstring()?;
        let cwd = cursor.cstring()?;
        let wd = if cursor.peek()? == 0 {
            cursor.byte()?;
            None
        } else {
            let wd = cursor.cstring()?;
            if cursor.byte()? != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid child cwd separator",
                ));
            }
            Some(wd)
        };
        let env_count = cursor.i32()? as usize;
        let mut env = Vec::with_capacity(env_count);
        for _ in 0..env_count {
            let value = cursor.cstring()?;
            let separator = value.iter().position(|byte| *byte == b'=').ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid child environment entry",
                )
            })?;
            env.push((value[..separator].to_vec(), value[separator + 1..].to_vec()));
        }
        let args = if cursor.remaining() == 0 {
            None
        } else {
            let count = cursor.i32()? as usize;
            let mut args = Vec::with_capacity(count);
            for _ in 0..count {
                args.push(cursor.cstring()?);
            }
            Some(args)
        };
        if cursor.remaining() != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "trailing child config bytes",
            ));
        }
        let stdin_fd = std::env::var("ARINSAL_CHILD_VM_STDIN")
            .ok()
            .and_then(|fd| fd.parse::<i32>().ok())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing inherited stdin"))?;
        let stdout_fd = std::env::var("ARINSAL_CHILD_VM_STDOUT")
            .ok()
            .and_then(|fd| fd.parse::<i32>().ok())
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "missing inherited stdout")
            })?;
        Ok(Self {
            use_stdio: flags & CHILD_USE_STDIO != 0,
            do_read: flags & CHILD_DO_READ != 0,
            do_write: flags & CHILD_DO_WRITE != 0,
            program,
            cwd,
            wd,
            env,
            args,
            inherited_vm_fds: (stdin_fd, stdout_fd),
        })
    }
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn i32(&mut self) -> io::Result<i32> {
        let bytes = self.take(4)?;
        Ok(i32::from_be_bytes(bytes.try_into().unwrap()))
    }

    fn byte(&mut self) -> io::Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn peek(&self) -> io::Result<u8> {
        self.bytes
            .get(self.offset)
            .copied()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "short child config"))
    }

    fn cstring(&mut self) -> io::Result<Vec<u8>> {
        let bytes = self.take(self.remaining())?;
        let length = bytes.iter().position(|byte| *byte == 0).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "unterminated child config string",
            )
        })?;
        self.offset -= bytes.len() - length - 1;
        Ok(bytes[..length].to_vec())
    }

    fn take(&mut self, length: usize) -> io::Result<&'a [u8]> {
        let end = self
            .offset
            .checked_add(length)
            .filter(|end| *end <= self.bytes.len())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "short child config"))?;
        let bytes = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(bytes)
    }

    fn remaining(&self) -> usize {
        self.bytes.len() - self.offset
    }
}

fn arinsal_executable() -> Option<std::path::PathBuf> {
    if let Some(path) = std::env::var_os("ARINSAL_EXECUTABLE") {
        let path = std::path::PathBuf::from(path);
        if path.is_file() {
            return Some(path);
        }
    }
    // macOS reports the invoked path, which may be an `erl` symlink to this binary.
    let executable = std::env::current_exe().ok()?.canonicalize().ok()?;
    if executable.file_stem().is_some_and(|name| name == "arinsal") {
        return Some(executable);
    }
    let mut directory = executable.parent();
    while let Some(parent) = directory {
        let candidate = parent.join("arinsal");
        if candidate.is_file() {
            return Some(candidate);
        }
        directory = parent.parent();
    }
    None
}

fn to_io_error(error: impl Into<rustix::io::Errno>) -> io::Error {
    io::Error::from_raw_os_error(error.into().raw_os_error())
}

fn to_nix_error(error: nix::errno::Errno) -> io::Error {
    io::Error::from_raw_os_error(error as i32)
}
