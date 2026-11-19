// Port of erts/emulator/sys/unix/sys_drivers.c (the forker driver: erl_sys_late_init,
// forker_start, forker_stop, forker_deq, forker_sigchld, forker_ready_input,
// forker_ready_output, forker_control), OTP-29.1.1.
//
//! The `spawn_forker` driver: port zero of the node, owning the unix domain socket to
//! `erl_child_setup`. Start requests reach it as asynchronous controls from spawn ports and
//! wait in its driver queue until the socket takes them; the forker's SigChld replies are its
//! input, handed to the spawn port they name as an asynchronous control.

use std::os::fd::{IntoRawFd, RawFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};

use arinsal_drv::{DriverPort, NativeDriver, SELECT_READ, SELECT_USE, SELECT_WRITE};

use super::sys;
use crate::VmError;
use crate::child_setup::{FORKER_FRAME_LEN, SigChld};

/// `ERTS_FORKER_DRV_CONTROL_MAGIC_NUMBER` (sys.h).
const FORKER_DRV_CONTROL_MAGIC_NUMBER: u32 = 0x050a_7800;

/// `forker_driver_entry`.
fn driver() -> Arc<arinsal_drv::Driver> {
    static DRIVER: OnceLock<Arc<arinsal_drv::Driver>> = OnceLock::new();
    Arc::clone(
        DRIVER.get_or_init(|| arinsal_drv::Driver::native("spawn_forker", 0, Arc::new(Forker))),
    )
}

/// The forker port's driver data: `forker_fd` and the `first_call` of forker_control.
struct ForkerData {
    fd: RawFd,
    first_call: AtomicBool,
    runtime: &'static crate::process::Runtime,
}

/// Port of sys_drivers.c:170 (erl_sys_late_init): open the forker port, `forker_start`
/// starting `erl_child_setup`. The node's first port, so its id is zero.
pub(crate) fn open_forker(runtime: &'static crate::process::Runtime) -> Result<(), VmError> {
    let id = crate::port::open_sys_driver_port(runtime, driver(), "forker", |port| {
        // Port of sys_drivers.c:1589 (forker_start).
        // erts never waits for erl_child_setup: it exits on end of file of its socket when
        // the node's OS process ends.
        let (fd, _helper) = crate::child_setup::start()
            .map_err(|error| VmError::Load(format!("cannot start erl_child_setup: {error}")))?;
        let fd = fd.into_raw_fd();
        sys::set_nonblocking(fd);
        port.start_native(Arc::new(ForkerData {
            fd,
            first_call: AtomicBool::new(true),
            runtime,
        }));
        Ok(())
    })?;
    runtime
        .forker_port
        .set(id)
        .map_err(|_| VmError::Unsupported("forker port already open".into()))
}

/// `erl_drv_port_control(forker_port, ERTS_FORKER_DRV_CONTROL_MAGIC_NUMBER, proto)` of
/// spawn_start: hand a Start request to the forker port. `false` when the forker port is
/// gone; the caller then closes the child's ends of the pipes.
pub(crate) fn request_start(
    runtime: &crate::process::Runtime,
    proto: [u8; FORKER_FRAME_LEN],
) -> bool {
    runtime
        .forker_port
        .get()
        .and_then(|&id| runtime.ports.get(id))
        .and_then(|handle| handle.drv_port())
        .is_some_and(|port| {
            port.port_control_async(FORKER_DRV_CONTROL_MAGIC_NUMBER, proto.to_vec())
        })
}

/// Port of sys_drivers.c:1703 (forker_deq): close the descriptors the request handed over,
/// then drop it from the queue; the bytes left.
fn forker_deq(port: &DriverPort, proto: &[u8; FORKER_FRAME_LEN]) -> usize {
    let fds = crate::child_setup::start_fds(proto);
    sys::close(fds[0]);
    sys::close(fds[1]);
    if fds[1] != fds[2] {
        sys::close(fds[2]);
    }
    port.deq(FORKER_FRAME_LEN).unwrap_or(0)
}

/// Port of sys_drivers.c:1713 (forker_sigchld): an asynchronous control of the spawn port
/// `port_id`, as `command` is already the spawn driver's output.
fn forker_sigchld(runtime: &crate::process::Runtime, port_id: u64, error: i32) {
    if let Some(port) = runtime
        .ports
        .get(port_id)
        .and_then(|handle| handle.drv_port())
    {
        port.port_control_async(
            super::SPAWN_DRV_CONTROL_MAGIC_NUMBER,
            crate::child_setup::sigchld_frame(port_id, error).to_vec(),
        );
    }
}

struct Forker;

impl NativeDriver for Forker {
    // Port of sys_drivers.c:1697 (forker_stop): nothing; the port was closed by the user.
    fn stop(&self, _port: &DriverPort) {}

    // Port of sys_drivers.c:1728 (forker_ready_input), without FORKER_PROTO_START_ACK.
    fn ready_input(&self, port: &DriverPort, fd: i32) {
        let Some(data) = port.native_data::<ForkerData>() else {
            return;
        };
        let mut proto = [0u8; FORKER_FRAME_LEN];
        match sys::read(fd, &mut proto) {
            Err(errno) if errno == libc::EAGAIN || errno == libc::EINTR => {}
            Err(errno) => crate::natives::node::erts_exit_dump(&format!(
                "Failed to read from erl_child_setup: {errno}"
            )),
            Ok(0) => crate::natives::node::erts_exit_dump("erl_child_setup closed"),
            Ok(_) => {
                if let Some(SigChld { port_id, status }) = crate::child_setup::parse_sigchld(&proto)
                {
                    forker_sigchld(data.runtime, port_id, status);
                }
            }
        }
    }

    // Port of sys_drivers.c:1768 (forker_ready_output), without FORKER_PROTO_START_ACK.
    fn ready_output(&self, port: &DriverPort, fd: i32) {
        let Some(data) = port.native_data::<ForkerData>() else {
            return;
        };
        let mut loops = 10;
        while port.sizeq() > 0 && {
            loops -= 1;
            loops > 0
        } {
            let mut proto = [0u8; FORKER_FRAME_LEN];
            port.peek_head(&mut proto);
            if let Err(errno) = sys::uds_write(fd, &proto, &crate::child_setup::start_fds(&proto)) {
                if errno == libc::EAGAIN || errno == libc::EINTR {
                    return;
                } else if errno == libc::EMFILE {
                    forker_sigchld(
                        data.runtime,
                        crate::child_setup::start_port_id(&proto),
                        errno,
                    );
                    if forker_deq(port, &proto) == 0 {
                        port.select(fd, SELECT_WRITE, false);
                    }
                    return;
                }
                crate::natives::node::erts_exit_dump(&format!(
                    "Failed to write to erl_child_setup: {errno}"
                ));
            }
            if forker_deq(port, &proto) == 0 {
                port.select(fd, SELECT_WRITE, false);
            }
        }
    }

    // Port of sys_drivers.c:1802 (forker_control).
    fn control(
        &self,
        port: &DriverPort,
        command: u32,
        buf: &[u8],
    ) -> Option<arinsal_drv::ControlReply> {
        if command != FORKER_DRV_CONTROL_MAGIC_NUMBER {
            return None;
        }
        let data = port.native_data::<ForkerData>()?;
        let proto: [u8; FORKER_FRAME_LEN] = buf.try_into().ok()?;
        let done = Some(arinsal_drv::ControlReply::List(Vec::new().into()));
        if data.first_call.swap(false, Ordering::AcqRel) {
            // Do driver_select here when schedulers and their pollsets have started.
            port.select(data.fd, SELECT_READ | SELECT_USE, true);
        }
        port.enq(&proto);
        if port.sizeq() > FORKER_FRAME_LEN {
            return done;
        }
        if let Err(errno) = sys::uds_write(data.fd, &proto, &crate::child_setup::start_fds(&proto))
        {
            if errno == libc::EAGAIN || errno == libc::EINTR {
                port.select(data.fd, SELECT_WRITE | SELECT_USE, true);
                return done;
            } else if errno == libc::EMFILE {
                forker_sigchld(
                    data.runtime,
                    crate::child_setup::start_port_id(&proto),
                    errno,
                );
                forker_deq(port, &proto);
                return done;
            }
            crate::natives::node::erts_exit_dump(&format!(
                "Failed to write to erl_child_setup: {errno}"
            ));
        }
        forker_deq(port, &proto);
        done
    }
}
