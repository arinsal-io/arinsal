//! Closing a socket, the process monitors of a socket and `nif_cancel`.
//!
//! `nif_close` only prepares the close: the requestors are told, the select state is
//! stopped and the caller becomes the closer. The descriptor itself is closed by
//! `nif_finalize_close`, by the stop callback when the close had to wait for the select
//! machinery, or by the down handler when the closing or controlling process died.

use super::*;

/// `essio_close`.
pub(super) fn close(value: &O) -> Result<O, BifError> {
    let h = handle(value)?;
    let guard = h.socket.lock().unwrap();
    let mut st = h.state.lock().unwrap();
    if !state_bits::is_open(st.read_state) {
        return Ok(error("closed"));
    }
    let Some(me) = self_pid() else {
        return Err(BifError::BADARG);
    };
    st.closer = Some(me.clone());
    if h.owner.lock().unwrap().as_ref() != Some(&me) {
        st.closer_mon = monitor_process(&h, &me);
    }
    st.read_state |= state_bits::CLOSING;
    st.write_state |= state_bits::CLOSING;
    let fd = guard.as_ref().map(AsRawFd::as_raw_fd);
    if do_stop(&h, fd, &mut st) {
        let close_ref = new_close_ref();
        st.close_ref = Some(close_ref.clone());
        Ok(ok(close_ref))
    } else {
        Ok(atom("ok"))
    }
}

fn new_close_ref() -> O {
    let id = NEXT_CLOSE_REF.fetch_add(1, Ordering::Relaxed);
    O::Ref {
        node: "nonode@nohost".into(),
        creation: 0,
        ids: vec![MAGIC ^ 1, id as u32, (id >> 32) as u32],
    }
}

fn is_selected(st: &State) -> bool {
    (st.read_state | st.write_state) & state_bits::SELECTED != 0
}

/// `esock_stop_handle_current`: the current requestor never gets a select message, so
/// it is told that the socket is gone.
fn stop_handle_current(h: &Handle, requestor: &Requestor) {
    demonitor_process(requestor.mon);
    send_abort_msg(h, requestor, &atom("closed"));
}

/// `esock_inform_waiting_procs`.
fn inform_waiting_procs(h: &Handle, queue: &mut VecDeque<Requestor>, reason: &O) {
    for requestor in queue.drain(..) {
        send_abort_msg(h, &requestor, reason);
        demonitor_process(requestor.mon);
    }
}

/// `do_stop`: prepare for close and return whether the stop callback is scheduled.
fn do_stop(h: &Handle, fd: Option<i32>, st: &mut State) -> bool {
    let mut scheduled = false;
    let mut sres = 0;
    if is_selected(st)
        && let Some(fd) = fd
    {
        sres = select_stop(fd).max(0);
        scheduled = sres & crate::SELECT_STOP_CALLED == 0;
    }
    let closed = atom("closed");
    let write_cancelled = sres & crate::SELECT_WRITE_CANCELLED != 0;
    let read_cancelled = sres & crate::SELECT_READ_CANCELLED != 0;
    if let Some(writer) = st.current_writer.take() {
        if write_cancelled {
            stop_handle_current(h, &writer);
        }
        inform_waiting_procs(h, &mut st.writers_q, &closed);
    }
    if let Some(connector) = st.connector.take()
        && write_cancelled
    {
        stop_handle_current(h, &connector);
    }
    if let Some(reader) = st.current_reader.take() {
        if read_cancelled {
            stop_handle_current(h, &reader);
        }
        inform_waiting_procs(h, &mut st.readers_q, &closed);
    }
    if let Some(acceptor) = st.current_acceptor.take() {
        if read_cancelled {
            stop_handle_current(h, &acceptor);
        }
        inform_waiting_procs(h, &mut st.acceptors_q, &closed);
    }
    scheduled
}

/// `esock_close_socket` up to the descriptor close: the states and the counters.
fn mark_closed(h: &Handle, st: &mut State) {
    st.read_state |= state_bits::CLOSED;
    st.write_state |= state_bits::CLOSED;
    totals().update(h.domain, h.kind, h.protocol, false);
    h.otp_options.lock().unwrap().remove(&OTP_OPT_META);
}

/// `sock_close`: the errno of `close(2)`, or 0.
fn close_descriptor(socket: Socket) -> i32 {
    let fd = socket.into_raw_fd();
    // SAFETY: into_raw_fd released ownership, so fd is closed exactly once, here.
    if unsafe { libc::close(fd) } < 0 {
        io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO)
    } else {
        0
    }
}

/// The descriptor close of `esock_close_socket`, and the registry `del` message.
fn close_socket_fd(h: &Handle, socket: Option<Socket>) -> i32 {
    let err = socket.map_or(0, close_descriptor);
    h.sendfile_fd.lock().unwrap().take();
    if use_reg(h) {
        send_reg_msg("del", h);
    }
    err
}

/// `essio_fin_close`.
pub(super) fn finalize_close(value: &O) -> Result<O, BifError> {
    let h = handle(value)?;
    let mut guard = h.socket.lock().unwrap();
    let mut st = h.state.lock().unwrap();
    let Some(me) = self_pid() else {
        return Err(BifError::BADARG);
    };
    if state_bits::is_closed(st.read_state) {
        return Ok(error("closed"));
    }
    if !state_bits::is_closing(st.read_state) {
        return Err(raise_invalid("state"));
    }
    if is_selected(&st) && st.close_ref.is_some() {
        return Err(raise_invalid("state"));
    }
    if st.closer.as_ref() != Some(&me) {
        return Err(raise_invalid("state"));
    }
    st.closer = None;
    demonitor_process(st.closer_mon.take());
    *h.owner.lock().unwrap() = None;
    demonitor_process(st.ctrl_mon.take());
    let socket = guard.take();
    if let Some(socket) = socket.as_ref() {
        let _ = socket.set_nonblocking(false);
    }
    mark_closed(&h, &mut st);
    drop(st);
    drop(guard);
    let err = close_socket_fd(&h, socket);
    Ok(match err {
        0 => atom("ok"),
        libc::EAGAIN => error("timeout"),
        err => errno(err),
    })
}

/// `esock_send_close_msg`: `{'$socket', Socket, close, CloseRef}` to the closer.
fn send_close_msg(h: &Handle, closer: &O, close_ref: O) {
    if let Some(reactor) = active_reactor() {
        let message = O::tuple(vec![
            atom("$socket"),
            pair(atom("$socket"), h.reference.clone()),
            atom("close"),
            close_ref,
        ]);
        reactor.send(closer, &message);
    }
}

/// The stop callback (`esock_stop` with `is_direct_call` false): the select machinery
/// has let go of the descriptor. The closer is told to finalize, and without a closer
/// the descriptor is closed here.
pub(crate) fn stop(value: &O) {
    let Ok(h) = handle(value) else {
        return;
    };
    let mut guard = h.socket.lock().unwrap();
    let mut st = h.state.lock().unwrap();
    if let Some(closer) = st.closer.clone() {
        let close_ref = st.close_ref.take().unwrap_or_else(|| atom("undefined"));
        send_close_msg(&h, &closer, close_ref);
    } else {
        mark_closed(&h, &mut st);
        let socket = guard.take();
        drop(st);
        drop(guard);
        close_socket_fd(&h, socket);
    }
}

/// `essio_down_ctrl`: the controlling process is gone.
pub(super) fn down_ctrl(h: &Handle, guard: &mut Option<Socket>, st: &mut State) {
    let fd = guard.as_ref().map(AsRawFd::as_raw_fd);
    if !do_stop(h, fd, st) {
        mark_closed(h, st);
        close_socket_fd(h, guard.take());
    }
}

/// The process monitor of `pid` fired: `esock_down` and `essio_down`.
pub(crate) fn down(value: &O, pid: &O, monitor: u64) {
    let Ok(h) = handle(value) else {
        return;
    };
    essio_down(&h, pid, monitor);
}

fn essio_down(h: &Arc<Handle>, pid: &O, monitor: u64) {
    let mut guard = h.socket.lock().unwrap();
    let mut st = h.state.lock().unwrap();
    if st.closer.as_ref() == Some(pid) {
        st.closer = None;
        if st.closer_mon == Some(monitor) {
            st.closer_mon = None;
        } else {
            st.ctrl_mon = None;
            *h.owner.lock().unwrap() = None;
        }
        if st.close_ref.is_none() {
            mark_closed(h, &mut st);
            close_socket_fd(h, guard.take());
        } else {
            st.close_ref = None;
        }
    } else if st.ctrl_mon == Some(monitor) {
        st.ctrl_mon = None;
        *h.owner.lock().unwrap() = None;
        if state_bits::is_open(st.read_state) {
            down_ctrl(h, &mut guard, &mut st);
            st.read_state |= state_bits::CLOSING;
            st.write_state |= state_bits::CLOSING;
        }
    } else if st.connector.as_ref().and_then(|c| c.mon) == Some(monitor) {
        st.connector = None;
        st.write_state &= !state_bits::CONNECTING;
    } else if !state_bits::is_closed(st.read_state) {
        let fd = guard.as_ref().map(AsRawFd::as_raw_fd);
        if st.current_reader.is_some() {
            down_requestor(h, &mut st, fd, Kind::Reader, pid, monitor);
        }
        if st.current_acceptor.is_some() {
            down_requestor(h, &mut st, fd, Kind::Acceptor, pid, monitor);
        }
        if st.current_writer.is_some() {
            down_requestor(h, &mut st, fd, Kind::Writer, pid, monitor);
        }
    }
}

/// `essio_down_reader`, `essio_down_acceptor` and `essio_down_writer`.
fn down_requestor(h: &Handle, st: &mut State, fd: Option<i32>, kind: Kind, pid: &O, monitor: u64) {
    let is_current = st.current(kind).as_ref().and_then(|req| req.mon) == Some(monitor);
    if is_current {
        if let Some(current) = st.current(kind).as_mut() {
            current.mon = None;
        }
        let activated = fd.is_some_and(|fd| activate_next(h, st, fd, kind));
        if !activated {
            if kind == Kind::Acceptor {
                st.read_state &= !state_bits::ACCEPTING;
            }
            *st.current(kind) = None;
        }
    } else {
        st.unqueue(kind, None, pid);
    }
}

/// `essio_dtor`: the resource is gone. A descriptor that is still open is closed
/// without blocking, and the monitors of the resource are dropped.
pub(super) fn dtor(h: &Handle) {
    let mut guard = h.socket.lock().unwrap();
    let mut st = h.state.lock().unwrap();
    st.read_state |= state_bits::DTOR | state_bits::CLOSED;
    st.write_state |= state_bits::DTOR | state_bits::CLOSED;
    demonitor_process(st.ctrl_mon.take());
    demonitor_process(st.closer_mon.take());
    let current = [
        st.connector.take(),
        st.current_reader.take(),
        st.current_writer.take(),
        st.current_acceptor.take(),
    ];
    for requestor in current.into_iter().flatten() {
        demonitor_process(requestor.mon);
    }
    let queued = [
        std::mem::take(&mut st.readers_q),
        std::mem::take(&mut st.writers_q),
        std::mem::take(&mut st.acceptors_q),
    ];
    for requestor in queued.into_iter().flatten() {
        demonitor_process(requestor.mon);
    }
    h.sendfile_fd.lock().unwrap().take();
    guard.take();
}

/// `esock_cancel`: only the requestor that selected can cancel its operation.
pub(super) fn cancel(args: &[O]) -> Result<O, BifError> {
    let h = handle(&args[0])?;
    let Some(op) = name(&args[1]) else {
        return Err(BifError::BADARG);
    };
    if !matches!(args[2], O::Ref { .. }) {
        return Err(BifError::BADARG);
    }
    match op {
        "connect" => cancel_connect(&h, &args[2]),
        "accept" => cancel_requestor(&h, Kind::Acceptor, &args[2]),
        "recv" | "recvfrom" | "recvmmsg" | "recvmsg" => {
            cancel_requestor(&h, Kind::Reader, &args[2])
        }
        "send" | "sendfile" | "sendmmsg" | "sendmsg" | "sendto" | "sendv" => {
            cancel_requestor(&h, Kind::Writer, &args[2])
        }
        _ => {
            let st = h.state.lock().unwrap();
            if state_bits::is_open(st.read_state) {
                Err(BifError::BADARG)
            } else {
                Ok(error("closed"))
            }
        }
    }
}

/// `essio_cancel_connect`.
fn cancel_connect(h: &Arc<Handle>, op_ref: &O) -> Result<O, BifError> {
    let guard = h.socket.lock().unwrap();
    let mut st = h.state.lock().unwrap();
    let Some(me) = self_pid() else {
        return Err(BifError::BADARG);
    };
    if !state_bits::is_open(st.write_state) {
        return Ok(error("closed"));
    }
    match st.connector.as_ref() {
        Some(connector) if connector.pid == me && &connector.reference == op_ref => {
            let result = guard.as_ref().map_or_else(
                || atom("not_found"),
                |s| cancel_write_select(s.as_raw_fd(), op_ref),
            );
            requestor_release(&mut st.connector);
            st.write_state &= !state_bits::CONNECTING;
            Ok(result)
        }
        _ => Ok(error("not_found")),
    }
}

/// `essio_cancel_accept`, `essio_cancel_recv` and `essio_cancel_send`.
fn cancel_requestor(h: &Arc<Handle>, kind: Kind, op_ref: &O) -> Result<O, BifError> {
    let guard = h.socket.lock().unwrap();
    let mut st = h.state.lock().unwrap();
    let state = if kind == Kind::Writer {
        st.write_state
    } else {
        st.read_state
    };
    if !state_bits::is_open(state) {
        return Ok(error("closed"));
    }
    let Some(current) = st.current(kind).clone() else {
        return Ok(atom("not_found"));
    };
    let Some(me) = self_pid() else {
        return Err(BifError::BADARG);
    };
    if me != current.pid {
        return Ok(if st.unqueue(kind, Some(op_ref), &me) {
            atom("ok")
        } else {
            atom("not_found")
        });
    }
    if op_ref != &current.reference {
        return Ok(atom("not_found"));
    }
    let Some(fd) = guard.as_ref().map(AsRawFd::as_raw_fd) else {
        return Ok(atom("not_found"));
    };
    demonitor_process(current.mon);
    let result = if kind == Kind::Writer {
        cancel_write_select(fd, &current.reference)
    } else {
        cancel_read_select(fd, &current.reference)
    };
    if !activate_next(h, &mut st, fd, kind) {
        if kind == Kind::Acceptor {
            st.read_state &= !state_bits::ACCEPTING;
        }
        *st.current(kind) = None;
    }
    Ok(result)
}
