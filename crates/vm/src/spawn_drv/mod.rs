// Port of erts/emulator/sys/unix/sys_drivers.c (the spawn driver: spawn_start's driver data,
// stop, output, ready_input, ready_output, port_inp_failure, spawn_control, stop_select),
// OTP-29.1.1.
//
//! The `spawn` driver of erts on the generic port machinery: the pipes to the child are
//! selected with `driver_select`, readiness comes back as port tasks on the port's run queue,
//! and every read, write and end of input runs in a driver callback under the port lock.

use std::os::fd::RawFd;
use std::sync::{Arc, OnceLock, Weak};

use arinsal_drv::{DriverPort, NativeDriver, SELECT_READ, SELECT_USE, SELECT_WRITE};
use parking_lot::Mutex;

use crate::port::PortHandle;

/// `MAX_VSIZE` of sys_drivers.c: entries handed to one `writev`.
const MAX_VSIZE: usize = 16;
/// `ERTS_SYS_READ_BUF_SZ`.
const READ_BUF_SZ: usize = 64 * 1024;
/// `ERL_DRV_FLAG_USE_PORT_LOCKING | ERL_DRV_FLAG_USE_INIT_ACK`.
const DRIVER_FLAGS: i32 = (1 << 0) | (1 << 3);

/// `spawn_driver_entry`.
pub(crate) fn driver() -> Arc<arinsal_drv::Driver> {
    static DRIVER: OnceLock<Arc<arinsal_drv::Driver>> = OnceLock::new();
    Arc::clone(
        DRIVER.get_or_init(|| arinsal_drv::Driver::native("spawn", DRIVER_FLAGS, Arc::new(Spawn))),
    )
}

/// `ErtsSysFdData`: one descriptor of the port and the packet being assembled from it. A
/// negative `fd` is closed after the forker handshake (`dd->ifd->fd *= -1` in spawn_start).
struct FdData {
    fd: RawFd,
    /// `buf`/`sz`: the packet whose body is still arriving.
    buf: Vec<u8>,
    /// `remain`: body bytes still missing from `buf`.
    remain: usize,
    /// `pbuf`/`psz`: the packet header read so far.
    pbuf: [u8; 4],
    psz: usize,
}

impl FdData {
    fn new(fd: RawFd) -> Self {
        Self {
            fd,
            buf: Vec::new(),
            remain: 0,
            pbuf: [0; 4],
            psz: 0,
        }
    }

    /// `clear_fd_data`.
    fn clear(&mut self) {
        self.buf = Vec::new();
        self.remain = 0;
        self.psz = 0;
    }
}

/// `ErtsSysDriverData` of a spawn port.
struct Dd {
    packet_bytes: usize,
    /// OS pid of the child: 0 until the forker's `Go`, -1 when the fork failed.
    pid: i32,
    /// 1: the exit status is wanted and the child runs; -1: it exited with `status`; 0: no
    /// exit status wanted.
    alive: i8,
    status: i64,
    /// The port ends once the queue drained: 1 after `fd_flush` (reason `normal`), 2 after
    /// end of input, `-errno` after a read error (blocking writes only).
    terminating: i32,
    ifd: Option<FdData>,
    ofd: Option<FdData>,
    /// `dd->ofd == dd->ifd`: an fd port reading and writing one descriptor.
    ofd_is_ifd: bool,
    /// `dd->blocking`: output goes through an async thread because the descriptor could not
    /// be made non-blocking (fd driver only).
    blocking: Option<Blocking>,
    busy: bool,
    high_watermark: usize,
    low_watermark: usize,
}

/// `ErtsSysBlocking`: the result of the last async write and the async queue key.
struct Blocking {
    result: Arc<Mutex<Result<usize, i32>>>,
    pkey: u32,
}

impl Dd {
    /// `dd->ofd` as erts reads it: the shared descriptor when input and output are one fd.
    fn ofd(&self) -> Option<&FdData> {
        if self.ofd_is_ifd {
            self.ifd.as_ref()
        } else {
            self.ofd.as_ref()
        }
    }
}

/// The driver data of a spawn port (`prt->drv_data`).
pub(crate) struct SysDriverData {
    dd: Mutex<Dd>,
    /// The port record, for `erl_drv_set_os_pid` and `driver_report_exit`.
    handle: Weak<PortHandle>,
}

/// What `spawn_start` hands the driver once the forker request is on its way.
pub(crate) struct SpawnStart {
    /// Read end of the child's stdout pipe (`ifd[0]`).
    pub(crate) ifd: RawFd,
    /// Write end of the child's stdin pipe (`ofd[1]`).
    pub(crate) ofd: RawFd,
    /// `{packet, N}`; 0 for a stream.
    pub(crate) packet_bytes: usize,
    pub(crate) exit_status: bool,
    pub(crate) do_read: bool,
    pub(crate) do_write: bool,
    pub(crate) high_watermark: usize,
    pub(crate) low_watermark: usize,
    /// The part of the command payload the pipe did not take (`driver_enq` in spawn_start).
    pub(crate) setup_rest: Vec<u8>,
    /// The child's ends of the pipes, for the forker's Start request.
    pub(crate) child_fds: crate::child_setup::ChildFds,
    pub(crate) runtime: &'static crate::process::Runtime,
}

/// The `start` of the spawn or the fd driver, split at the point the port is registered.
pub(crate) enum SysStart {
    Spawn(SpawnStart),
    Fd(FdStart),
}

impl SysStart {
    /// Install the driver data (`spawn_start` / `fd_start` up to create_driver_data).
    pub(crate) fn attach(&self, handle: &Arc<PortHandle>, port: &DriverPort) {
        match self {
            SysStart::Spawn(start) => attach(handle, port, start),
            SysStart::Fd(start) => fd_attach(handle, port, start),
        }
    }

    /// The selections of the start, made once the port is registered and its opener waits.
    pub(crate) fn begin(self, port: &DriverPort) {
        match self {
            SysStart::Spawn(start) => begin(port, start),
            SysStart::Fd(start) => fd_begin(port, &start),
        }
    }
}

/// Install the driver data of a new spawn port; nothing is selected yet.
fn attach(handle: &Arc<PortHandle>, port: &DriverPort, start: &SpawnStart) {
    // Port of sys_drivers.c:356 (create_driver_data); the sign of each descriptor carries
    // DO_READ / DO_WRITE (spawn_start:712-717).
    let dd = Dd {
        packet_bytes: start.packet_bytes,
        pid: 0,
        alive: if start.exit_status { 1 } else { 0 },
        status: 0,
        terminating: 0,
        ofd_is_ifd: false,
        blocking: None,
        ifd: Some(FdData::new(if start.do_read {
            start.ifd
        } else {
            -start.ifd
        })),
        ofd: Some(FdData::new(if start.do_write {
            start.ofd
        } else {
            -start.ofd
        })),
        busy: false,
        high_watermark: start.high_watermark,
        low_watermark: start.low_watermark,
    };
    port.start_native(Arc::new(SysDriverData {
        dd: Mutex::new(dd),
        handle: Arc::downgrade(handle),
    }));
}

/// The selections `spawn_start` makes, done once the port answers its opener's init ack:
/// the input pipe for the forker's `Go`, and the output pipe when the command payload did
/// not fit into it; then the Start request goes to the forker port.
fn begin(port: &DriverPort, start: SpawnStart) {
    port.serialized(|| {
        // Port of sys_drivers.c:678-686 (spawn_start: enqueue the rest of the payload).
        if !start.setup_rest.is_empty() {
            port.enq(&start.setup_rest);
            port.select(start.ofd, SELECT_WRITE | SELECT_USE, true);
        }
        // Port of sys_drivers.c:378 (create_driver_data: DO_READ selects ifd).
        port.select(start.ifd, SELECT_READ | SELECT_USE, true);
        // Port of sys_drivers.c:697-714 (spawn_start: send ofd[0] + ifd[1] + stderrfd to the
        // forker port).
        let proto = start
            .child_fds
            .into_start(start.exit_status.then(|| port.id()));
        if !request_start(start.runtime, proto) {
            // The forker port has been killed: closing both ends makes open_port fail with
            // epipe.
            let fds = crate::child_setup::start_fds(&proto);
            sys::close(fds[0]);
            sys::close(fds[1]);
        }
    });
}

/// `ERTS_SPAWN_DRV_CONTROL_MAGIC_NUMBER` (sys.h): the forker's SigChld for a spawn port.
pub(crate) const SPAWN_DRV_CONTROL_MAGIC_NUMBER: u32 = 0x04c7_6a00;

/// Port of sys_drivers.c:731 (spawn_control, ERTS_SPAWN_DRV_CONTROL_MAGIC_NUMBER).
fn spawn_control(port: &DriverPort, command: u32, buf: &[u8]) -> Option<arinsal_drv::ControlReply> {
    if command != SPAWN_DRV_CONTROL_MAGIC_NUMBER {
        return None;
    }
    let status = crate::child_setup::parse_sigchld(buf)?.status;
    let data = port.native_data::<SysDriverData>()?;
    let ifd = {
        let mut dd = data.dd.lock();
        dd.status = i64::from(status);
        dd.alive = -1;
        if let Some(ofd) = &dd.ofd {
            port.select(ofd.fd.abs(), SELECT_WRITE | SELECT_USE, true);
        }
        dd.ifd.as_ref().map(|ifd| ifd.fd.abs())
    };
    // erts calls ready_input directly: not every poll set reports an input event again on a
    // descriptor that already reported EOF.
    if let Some(fd) = ifd {
        ready_input(port, &data, fd);
    }
    Some(arinsal_drv::ControlReply::List(Vec::new().into()))
}

struct Spawn;

impl NativeDriver for Spawn {
    // Port of sys_drivers.c:1039 (stop).
    fn stop(&self, port: &DriverPort) {
        let Some(data) = port.native_data::<SysDriverData>() else {
            return;
        };
        let (ifd, ofd) = {
            let mut dd = data.dd.lock();
            (dd.ifd.take(), dd.ofd.take())
        };
        if let Some(mut ifd) = ifd {
            nbio_stop_fd(&mut ifd);
            port.select(ifd.fd.abs(), SELECT_USE, false);
        }
        if let Some(mut ofd) = ofd {
            nbio_stop_fd(&mut ofd);
            port.select(ofd.fd.abs(), SELECT_USE, false);
        }
    }

    fn output_owned(&self, port: &DriverPort, data: Vec<u8>) {
        output(port, &data);
    }

    fn ready_input(&self, port: &DriverPort, fd: i32) {
        if let Some(data) = port.native_data::<SysDriverData>() {
            ready_input(port, &data, fd);
        }
    }

    fn ready_output(&self, port: &DriverPort, fd: i32) {
        ready_output(port, fd);
    }

    fn control(
        &self,
        port: &DriverPort,
        command: u32,
        data: &[u8],
    ) -> Option<arinsal_drv::ControlReply> {
        spawn_control(port, command, data)
    }

    // Port of sys_drivers.c:1495 (stop_select).
    fn stop_select(&self, fd: i32) {
        sys::close(fd);
    }
}

/// Port of sys_drivers.c:1448 (ready_output).
fn ready_output(port: &DriverPort, fd: i32) {
    let Some(data) = port.native_data::<SysDriverData>() else {
        return;
    };
    let mut dd = data.dd.lock();
    if port.sizeq() == 0 {
        if dd.busy {
            dd.busy = false;
            port.set_busy(false);
        }
        port.select(fd, SELECT_WRITE, false);
        if dd.pid > 0 && dd.ofd().is_some_and(|ofd| ofd.fd < 0) {
            // Opened with `in`: the output pipe closes once the command was sent.
            port.select(fd, SELECT_WRITE | SELECT_USE, false);
            dd.ofd = None;
        }
        if dd.terminating != 0 {
            drop(dd);
            port.failure_atom("normal");
        }
        return;
    }
    match port.writev_queue(fd, MAX_VSIZE) {
        Ok(n) if n > 0 => match port.deq(n) {
            Some(left) => {
                if dd.busy && left < dd.low_watermark {
                    dd.busy = false;
                    port.set_busy(false);
                }
            }
            None => {
                drop(dd);
                port.failure_posix(libc::EINVAL);
            }
        },
        Ok(_) => {}
        Err(error) => {
            let errno = error.raw_os_error().unwrap_or(libc::EIO);
            if errno != libc::EAGAIN && errno != libc::EINTR {
                port.select(fd, SELECT_WRITE, false);
                drop(dd);
                port.failure_posix(errno);
            }
        }
    }
}

/// Port of sys_drivers.c:996 (nbio_stop_fd).
fn nbio_stop_fd(fdd: &mut FdData) {
    fdd.clear();
    sys::set_blocking(fdd.fd.abs());
}

/// The packet header of `len` bytes: `put_int32(len, lb); lbp = lb + (4 - pb)`.
fn packet_header(len: usize, pb: usize) -> Vec<u8> {
    (len as u32).to_be_bytes()[4 - pb..].to_vec()
}

/// Port of sys_drivers.c:1140 (output).
fn output(port: &DriverPort, buf: &[u8]) {
    let Some(data) = port.native_data::<SysDriverData>() else {
        return;
    };
    let mut dd = data.dd.lock();
    let pb = dd.packet_bytes;
    let len = buf.len();
    if (pb == 2 && len > 0xffff) || (pb == 1 && len > 0xff) || dd.pid == 0 {
        drop(dd);
        port.failure_posix(libc::EINVAL);
        return;
    }
    let header = packet_header(len, pb);
    let ofd = dd.ofd.as_ref().map_or(-1, |ofd| ofd.fd);
    let qsz = port.sizeq();
    let qsz = if qsz != 0 {
        port.enq(&header);
        port.enq(buf);
        qsz + len + pb
    } else {
        let n = match sys::writev2(ofd, &header, buf) {
            Ok(n) if n == pb + len => return,
            Ok(n) => n,
            Err(errno) if errno == libc::EINTR || errno == libc::EAGAIN => 0,
            Err(errno) => {
                drop(dd);
                port.failure_posix(errno);
                return;
            }
        };
        if n < pb {
            port.enq(&header[n..]);
            port.enq(buf);
        } else {
            port.enq(&buf[n - pb..]);
        }
        port.select(ofd, SELECT_WRITE | SELECT_USE, true);
        pb + len - n
    };
    if !dd.busy && qsz >= dd.high_watermark {
        dd.busy = true;
        port.set_busy(true);
    }
}

/// Port of sys_drivers.c:1205 (port_inp_failure): `res` is 0 for end of input, -1 for an
/// error `err`. The driver data is released before a failure ends the port, because `stop`
/// runs inside it.
fn port_inp_failure(
    port: &DriverPort,
    data: &SysDriverData,
    mut dd: parking_lot::MutexGuard<'_, Dd>,
    res: i32,
    err: i32,
) {
    if let Some(ifd) = dd.ifd.as_mut() {
        port.select(ifd.fd.abs(), SELECT_READ | SELECT_WRITE, false);
        ifd.clear();
    }
    if dd.blocking.is_some() && port.sizeq() > 0 {
        // Output is still being written by the async thread: fd_ready_async ends the port.
        dd.terminating = if res == 0 { 2 } else { -err };
        return;
    }
    if res == 0 {
        // EOF before the child exited waits: spawn_control brings us back here.
        if dd.alive != 1 {
            let exited = (dd.alive == -1).then_some(dd.status as i32);
            drop(dd);
            if let Some(status) = exited {
                // We need not be prepared for stopped/continued processes.
                let status = if libc::WIFSIGNALED(status) {
                    128 + libc::WTERMSIG(status)
                } else {
                    libc::WEXITSTATUS(status)
                };
                report_exit(port, data, i64::from(status));
            }
            port.failure_eof();
        }
    } else if dd.ifd.is_some() {
        let errno = if dd.alive == -1 {
            dd.status as i32
        } else {
            err
        };
        drop(dd);
        port.init_ack_errno(errno);
    } else {
        drop(dd);
        port.failure_posix(err);
    }
}

/// `driver_report_exit(port, status)` (io.c:5181).
fn report_exit(port: &DriverPort, data: &SysDriverData, status: i64) {
    if let Some(handle) = data.handle.upgrade() {
        crate::port::driver_report_exit(&handle, port.id(), status);
    }
}

/// Port of sys_drivers.c:1267 (ready_input).
fn ready_input(port: &DriverPort, data: &SysDriverData, ready_fd: RawFd) {
    let mut dd = data.dd.lock();
    let packet_bytes = dd.packet_bytes;
    if dd.ifd.is_none() {
        return;
    }
    if dd.pid == 0 {
        // The OS pid comes from erl_child_setup first; spawn driver only.
        let mut frame = [0u8; crate::child_setup::FORKER_FRAME_LEN];
        match sys::read(ready_fd, &mut frame) {
            Err(errno) if errno == libc::EAGAIN || errno == libc::EINTR => return,
            Err(errno) => {
                port_inp_failure(port, data, dd, -1, errno);
                return;
            }
            Ok(0) => {
                // Child setup closed the pipe too early.
                port_inp_failure(port, data, dd, -1, libc::EPIPE);
                return;
            }
            Ok(n) if n < frame.len() => {
                port_inp_failure(port, data, dd, -1, libc::EPROTO);
                return;
            }
            Ok(_) => {}
        }
        match crate::child_setup::parse_go(&frame) {
            Ok(crate::child_setup::Go::Pid(pid)) => dd.pid = pid as i32,
            Ok(crate::child_setup::Go::Errno(errno)) => {
                dd.pid = -1;
                port_inp_failure(port, data, dd, -1, errno);
                return;
            }
            Err(error) => {
                dd.pid = -1;
                port_inp_failure(
                    port,
                    data,
                    dd,
                    -1,
                    error.raw_os_error().unwrap_or(libc::EPROTO),
                );
                return;
            }
        }
        let ack = crate::child_setup::ack_frame();
        let ofd = dd.ofd.as_ref().map_or(-1, |ofd| ofd.fd.abs());
        if port.sizeq() > 0 {
            port.enq(&ack);
        } else if let Err(errno) = sys::write(ofd, &ack)
            && (errno == libc::EAGAIN || errno == libc::EINTR)
        {
            port.enq(&ack);
        }
        if dd.ifd.as_ref().is_some_and(|ifd| ifd.fd < 0) {
            port.select(ready_fd, SELECT_READ | SELECT_USE, false);
            dd.ifd = None;
        }
        if dd.ofd.as_ref().is_some_and(|ofd| ofd.fd < 0) || port.sizeq() > 0 {
            // Select to close the descriptor, or to write the queue.
            port.select(ofd, SELECT_WRITE | SELECT_USE, true);
        }
        port.set_os_pid(i64::from(dd.pid));
        port.init_ack_opened();
        return;
    }
    let Some(ifd) = dd.ifd.as_mut() else {
        return;
    };
    if packet_bytes == 0 {
        let mut read_buf = vec![0u8; READ_BUF_SZ];
        match sys::read(ready_fd, &mut read_buf) {
            Err(errno) if errno == libc::EAGAIN || errno == libc::EINTR => {}
            Err(errno) => port_inp_failure(port, data, dd, -1, errno),
            Ok(0) => port_inp_failure(port, data, dd, 0, 0),
            Ok(n) => port.driver_output(&read_buf[..n]),
        }
    } else if ifd.remain > 0 {
        // Read the rest of a split packet.
        let at = ifd.buf.len() - ifd.remain;
        match sys::read(ready_fd, &mut ifd.buf[at..]) {
            Err(errno) if errno == libc::EAGAIN || errno == libc::EINTR => {}
            Err(errno) => port_inp_failure(port, data, dd, -1, errno),
            Ok(0) => port_inp_failure(port, data, dd, 0, 0),
            Ok(n) if n == ifd.remain => {
                let packet = std::mem::take(&mut ifd.buf);
                ifd.clear();
                port.driver_output(&packet);
            }
            Ok(n) => ifd.remain -= n,
        }
    } else {
        let mut read_buf = vec![0u8; READ_BUF_SZ];
        let res = match sys::read(ready_fd, &mut read_buf) {
            Err(errno) if errno == libc::EAGAIN || errno == libc::EINTR => return,
            Err(errno) => {
                port_inp_failure(port, data, dd, -1, errno);
                return;
            }
            Ok(0) => {
                port_inp_failure(port, data, dd, 0, 0);
                return;
            }
            Ok(n) => n,
        };
        if res < packet_bytes - ifd.psz {
            ifd.pbuf[ifd.psz..ifd.psz + res].copy_from_slice(&read_buf[..res]);
            ifd.psz += res;
            return;
        }
        let mut cpos = 0;
        loop {
            while cpos < res && ifd.psz < packet_bytes {
                ifd.pbuf[ifd.psz] = read_buf[cpos];
                ifd.psz += 1;
                cpos += 1;
            }
            if ifd.psz < packet_bytes {
                break;
            }
            ifd.psz = 0;
            let h = match packet_bytes {
                1 => usize::from(ifd.pbuf[0]),
                2 => usize::from(u16::from_be_bytes([ifd.pbuf[0], ifd.pbuf[1]])),
                _ => u32::from_be_bytes(ifd.pbuf) as usize,
            };
            let left = res - cpos;
            if h <= left {
                port.driver_output(&read_buf[cpos..cpos + h]);
                cpos += h;
                continue;
            }
            // The last packet is split.
            let mut buf = vec![0u8; h];
            buf[..left].copy_from_slice(&read_buf[cpos..res]);
            ifd.buf = buf;
            ifd.remain = h - left;
            break;
        }
    }
}

/// `fd_driver_entry`.
pub(crate) fn fd_driver() -> Arc<arinsal_drv::Driver> {
    static DRIVER: OnceLock<Arc<arinsal_drv::Driver>> = OnceLock::new();
    Arc::clone(DRIVER.get_or_init(|| arinsal_drv::Driver::native("fd", 0, Arc::new(Fd))))
}

/// `ERTS_TTYSL_DRV_CONTROL_MAGIC_NUMBER`.
const TTYSL_DRV_CONTROL_MAGIC_NUMBER: u32 = 0x018b_0900;
/// `FD_CTRL_OP_GET_WINSIZE`.
const FD_CTRL_OP_GET_WINSIZE: u32 = 100;
/// `MAXIOV` of the async write.
const MAXIOV: usize = 1024;

/// What `fd_start` is given.
pub(crate) struct FdStart {
    pub(crate) ifd: RawFd,
    pub(crate) ofd: RawFd,
    pub(crate) packet_bytes: usize,
    pub(crate) do_read: bool,
    pub(crate) do_write: bool,
    pub(crate) high_watermark: usize,
    pub(crate) low_watermark: usize,
}

/// Port of sys_drivers.c:817 (fd_start): decide whether output may be non-blocking, then
/// create the driver data (create_driver_data with `pid = -1`).
fn fd_attach(handle: &Arc<PortHandle>, port: &DriverPort, start: &FdStart) {
    let mut non_blocking = false;
    if start.do_write && start.do_read && sys::isatty(start.ofd) {
        // When input is not the tty, the output tty is re-opened first so that non-blocking
        // mode does not reach whatever shares the original file description.
        if sys::isatty(start.ifd) || sys::reopen_tty(start.ofd) {
            non_blocking = true;
            sys::set_nonblocking(start.ofd);
        }
    }
    let same = start.do_read && start.do_write && start.ifd == start.ofd;
    let dd = Dd {
        packet_bytes: start.packet_bytes,
        pid: -1,
        alive: 0,
        status: 0,
        terminating: 0,
        ifd: start.do_read.then(|| FdData::new(start.ifd)),
        ofd: (start.do_write && !same).then(|| FdData::new(start.ofd)),
        ofd_is_ifd: same,
        blocking: (start.do_write && !non_blocking).then(|| Blocking {
            result: Arc::new(Mutex::new(Ok(0))),
            pkey: port.async_port_key(),
        }),
        busy: false,
        high_watermark: start.high_watermark,
        low_watermark: start.low_watermark,
    };
    port.start_native(Arc::new(SysDriverData {
        dd: Mutex::new(dd),
        handle: Arc::downgrade(handle),
    }));
}

/// The input selection of create_driver_data, made once the port is registered.
fn fd_begin(port: &DriverPort, start: &FdStart) {
    if start.do_read {
        port.serialized(|| port.select(start.ifd, SELECT_READ | SELECT_USE, true));
    }
}

struct Fd;

impl NativeDriver for Fd {
    fn has_outputv(&self) -> bool {
        true
    }

    // Port of sys_drivers.c:1002 (fd_stop): the descriptors stay open.
    fn stop(&self, port: &DriverPort) {
        let Some(data) = port.native_data::<SysDriverData>() else {
            return;
        };
        let (ifd, ofd) = {
            let mut dd = data.dd.lock();
            dd.blocking = None;
            let ofd = if dd.ofd_is_ifd { None } else { dd.ofd.take() };
            (dd.ifd.take(), ofd)
        };
        if let Some(mut ifd) = ifd {
            port.select(
                ifd.fd.abs(),
                arinsal_drv::SELECT_USE_NO_CALLBACK | SELECT_READ | SELECT_WRITE,
                false,
            );
            nbio_stop_fd(&mut ifd);
        }
        if let Some(mut ofd) = ofd {
            port.select(
                ofd.fd.abs(),
                arinsal_drv::SELECT_USE_NO_CALLBACK | SELECT_WRITE,
                false,
            );
            nbio_stop_fd(&mut ofd);
        }
    }

    fn output_owned(&self, port: &DriverPort, data: Vec<u8>) {
        fd_outputv(port, &data);
    }

    fn ready_input(&self, port: &DriverPort, fd: i32) {
        if let Some(data) = port.native_data::<SysDriverData>() {
            ready_input(port, &data, fd);
        }
    }

    fn ready_output(&self, port: &DriverPort, fd: i32) {
        ready_output(port, fd);
    }

    // Port of sys_drivers.c:1029 (fd_flush).
    fn flush(&self, port: &DriverPort) {
        if let Some(data) = port.native_data::<SysDriverData>() {
            let mut dd = data.dd.lock();
            if dd.terminating == 0 {
                dd.terminating = 1;
            }
        }
    }

    // Port of sys_drivers.c:776 (fd_control).
    fn control(
        &self,
        port: &DriverPort,
        command: u32,
        _data: &[u8],
    ) -> Option<arinsal_drv::ControlReply> {
        if command.wrapping_sub(TTYSL_DRV_CONTROL_MAGIC_NUMBER) != FD_CTRL_OP_GET_WINSIZE {
            return None;
        }
        let data = port.native_data::<SysDriverData>()?;
        let dd = data.dd.lock();
        let size = dd
            .ofd()
            .and_then(|ofd| sys::window_size(ofd.fd))
            .or_else(|| dd.ifd.as_ref().and_then(|ifd| sys::window_size(ifd.fd)))?;
        let mut reply = Vec::with_capacity(8);
        reply.extend_from_slice(&size.0.to_ne_bytes());
        reply.extend_from_slice(&size.1.to_ne_bytes());
        Some(arinsal_drv::ControlReply::List(reply.into()))
    }

    // Port of sys_drivers.c:1536 (fd_ready_async).
    fn ready_async(&self, port: &DriverPort) {
        let Some(data) = port.native_data::<SysDriverData>() else {
            return;
        };
        let mut dd = data.dd.lock();
        let Some(blocking) = dd.blocking.as_ref() else {
            return;
        };
        let result = *blocking.result.lock();
        match result {
            Ok(n) if n > 0 => {
                let Some(left) = port.deq(n) else {
                    drop(dd);
                    port.failure_posix(libc::EINVAL);
                    return;
                };
                if dd.busy && left < dd.low_watermark {
                    dd.busy = false;
                    port.set_busy(false);
                }
                if left == 0 {
                    let terminating = dd.terminating;
                    drop(dd);
                    match terminating {
                        // Ordered to terminate by fd_flush or port_inp_failure.
                        1 => port.failure_atom("normal"),
                        2 => port.failure_eof(),
                        errno if errno < 0 => port.failure_posix(-errno),
                        _ => {}
                    }
                } else {
                    // Data left to write.
                    fd_async(port, &mut dd);
                }
            }
            Ok(_) => {}
            Err(errno) if errno == libc::EAGAIN => fd_async(port, &mut dd),
            Err(errno) => {
                drop(dd);
                port.failure_posix(errno);
            }
        }
    }
}

/// Queue `fd_async` (sys_drivers.c:1502): write the head of the driver queue on the async
/// thread of the port's key.
fn fd_async(port: &DriverPort, dd: &mut Dd) {
    let Some(ofd) = dd.ofd().map(|ofd| ofd.fd) else {
        return;
    };
    let Some(blocking) = dd.blocking.as_mut() else {
        return;
    };
    let result = Arc::clone(&blocking.result);
    let target = port.arc();
    port.driver_async(
        &mut blocking.pkey,
        Box::new(move || {
            let res = loop {
                match target.writev_queue(ofd, MAXIOV) {
                    Err(error) if error.raw_os_error() == Some(libc::EINTR) => continue,
                    other => break other,
                }
            };
            *result.lock() = res.map_err(|error| error.raw_os_error().unwrap_or(libc::EIO));
        }),
    );
}

/// Port of sys_drivers.c:1058 (outputv) for a command already flattened.
fn fd_outputv(port: &DriverPort, buf: &[u8]) {
    let Some(data) = port.native_data::<SysDriverData>() else {
        return;
    };
    let mut dd = data.dd.lock();
    let pb = dd.packet_bytes;
    let len = buf.len();
    if (pb == 2 && len > 0xffff) || (pb == 1 && len > 0xff) {
        drop(dd);
        port.failure_posix(libc::EINVAL);
        return;
    }
    let header = packet_header(len, pb);
    let size = len + pb;
    let ofd = dd.ofd().map_or(-1, |ofd| ofd.fd);
    let qsz = port.sizeq();
    if qsz != 0 {
        port.enq(&header);
        port.enq(buf);
        if !dd.busy && qsz + size >= dd.high_watermark {
            dd.busy = true;
            port.set_busy(true);
        }
    } else if dd.blocking.is_none() {
        // A non-blocking descriptor is written directly.
        let n = match sys::writev2(ofd, &header, buf) {
            Ok(n) if n == size => return,
            Ok(n) => n,
            Err(errno) if errno == libc::EINTR || errno == libc::EAGAIN => 0,
            Err(errno) => {
                drop(dd);
                port.failure_posix(errno);
                return;
            }
        };
        if n < pb {
            port.enq(&header[n..]);
            port.enq(buf);
        } else {
            port.enq(&buf[n - pb..]);
        }
        if !dd.busy && size - n >= dd.high_watermark {
            dd.busy = true;
            port.set_busy(true);
        }
        port.select(ofd, SELECT_WRITE | SELECT_USE, true);
    } else if size != 0 {
        port.enq(&header);
        port.enq(buf);
        if !dd.busy && size >= dd.high_watermark {
            dd.busy = true;
            port.set_busy(true);
        }
        fd_async(port, &mut dd);
    }
}

mod forker;
mod sys;

pub(crate) use forker::{open_forker, request_start};
