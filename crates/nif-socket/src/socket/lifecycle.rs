//! Closing a socket, the process monitors of a socket and `nif_cancel`.
//!
//! `nif_close` only prepares the close: the requestors are told, the select state is
//! stopped and the caller becomes the closer. The descriptor itself is closed by
//! `nif_finalize_close`, by the stop callback when the close had to wait for the select
//! machinery, or by the down handler when the closing or controlling process died.

use super::esock_descriptor::PATTERN_DTOR;
use super::*;

/// `essio_close`.
pub(super) fn close(value: &O) -> Result<O, BifError> {
    let h = handle(value)?;
    let mut st = h.lock_both();
    if !state_bits::is_open(st.read_state()) {
        return Ok(error("closed"));
    }
    let Some(me) = self_pid() else {
        return Err(BifError::BADARG);
    };
    st.set_closer(Some(&me));
    if st.ctrl_pid().as_ref() != Some(&me) {
        st.set_closer_mon(monitor_process(&h, &me));
    }
    st.or_read_state(state_bits::CLOSING);
    st.or_write_state(state_bits::CLOSING);
    let fd = st.sock();
    if do_stop(&h, fd, &mut st) {
        let close_ref = new_close_ref();
        st.set_close_ref(Some(&close_ref));
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
    (st.read_state() | st.write_state()) & state_bits::SELECTED != 0
}

/// `esock_stop_handle_current`: the current requestor never gets a select message, so
/// it is told that the socket is gone.
fn stop_handle_current(h: &Sock, requestor: &Requestor) {
    demonitor_process(h, &requestor.pid, requestor.mon);
    send_abort_msg(h, requestor, &atom("closed"));
}

/// `esock_inform_waiting_procs`.
fn inform_waiting_procs(h: &Sock, st: &mut State, kind: Kind, reason: &O) {
    for requestor in st.drain_queue(kind) {
        send_abort_msg(h, &requestor, reason);
        demonitor_process(h, &requestor.pid, requestor.mon);
    }
}

/// `do_stop`: prepare for close and return whether the stop callback is scheduled.
fn do_stop(h: &Sock, fd: Option<i32>, st: &mut State) -> bool {
    let mut scheduled = false;
    let mut sres = 0;
    if is_selected(st)
        && let Some(fd) = fd
    {
        sres = select_stop(h, fd).max(0);
        scheduled = sres & crate::SELECT_STOP_CALLED == 0;
    }
    let closed = atom("closed");
    let write_cancelled = sres & crate::SELECT_WRITE_CANCELLED != 0;
    let read_cancelled = sres & crate::SELECT_READ_CANCELLED != 0;
    if let Some(writer) = st.take_current(Kind::Writer) {
        if write_cancelled {
            stop_handle_current(h, &writer);
        }
        inform_waiting_procs(h, st, Kind::Writer, &closed);
    }
    if let Some(connector) = st.take_connector()
        && write_cancelled
    {
        stop_handle_current(h, &connector);
    }
    if let Some(reader) = st.take_current(Kind::Reader) {
        if read_cancelled {
            stop_handle_current(h, &reader);
        }
        inform_waiting_procs(h, st, Kind::Reader, &closed);
    }
    if let Some(acceptor) = st.take_current(Kind::Acceptor) {
        if read_cancelled {
            stop_handle_current(h, &acceptor);
        }
        inform_waiting_procs(h, st, Kind::Acceptor, &closed);
    }
    scheduled
}

/// `esock_close_socket` up to the descriptor close: the states and the counters.
fn mark_closed(h: &Handle, st: &mut State) {
    st.or_read_state(state_bits::CLOSED);
    st.or_write_state(state_bits::CLOSED);
    totals().update(h.domain, h.type_, h.protocol, false);
    st.clear_meta();
}

/// The descriptor close of `esock_close_socket`, and the registry `del` message.
/// `registered` is `descP->useReg` read under the mutex the caller already holds.
fn close_socket_fd(h: &Sock, fd: Option<i32>, sendfile: Option<i32>, registered: bool) -> i32 {
    let err = fd.map_or(0, raw::close_socket);
    if let Some(sendfile) = sendfile {
        raw::close_fd(sendfile);
    }
    if registered {
        send_reg_msg("del", h);
    }
    err
}

/// `essio_fin_close`.
pub(super) fn finalize_close(value: &O) -> Result<O, BifError> {
    let h = handle(value)?;
    let mut st = h.lock_both();
    let Some(me) = self_pid() else {
        return Err(BifError::BADARG);
    };
    if state_bits::is_closed(st.read_state()) {
        return Ok(error("closed"));
    }
    if !state_bits::is_closing(st.read_state()) {
        return Err(raise_invalid("state"));
    }
    if is_selected(&st) && st.close_ref().is_some() {
        return Err(raise_invalid("state"));
    }
    if st.closer().as_ref() != Some(&me) {
        return Err(raise_invalid("state"));
    }
    st.set_closer(None);
    demonitor_process(&h, &me, st.take_closer_mon());
    if let Some(owner) = st.ctrl_pid() {
        st.set_ctrl_pid(None);
        demonitor_process(&h, &owner, st.take_ctrl_mon());
    }
    let socket = st.take_sock();
    if let Some(fd) = socket {
        let _ = raw::with_sock(fd, |s| s.set_nonblocking(false));
    }
    let sendfile = st.take_sendfile_handle();
    let registered = st.use_reg();
    mark_closed(&h, &mut st);
    drop(st);
    let err = close_socket_fd(&h, socket, sendfile, registered);
    Ok(match err {
        0 => atom("ok"),
        libc::EAGAIN => error("timeout"),
        err => errno(err),
    })
}

/// `esock_send_close_msg`: `{'$socket', Socket, close, CloseRef}` to the closer.
fn send_close_msg(h: &Sock, closer: &O, close_ref: O) {
    if let Some(reactor) = active_reactor() {
        let message = O::tuple(vec![
            atom("$socket"),
            pair(atom("$socket"), h.reference()),
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
    stop_callback(&h);
    h.release_for_select();
}

fn stop_callback(h: &Sock) {
    let mut st = h.lock_both();
    if let Some(closer) = st.closer() {
        let close_ref = st.take_close_ref().unwrap_or_else(|| atom("undefined"));
        send_close_msg(h, &closer, close_ref);
    } else {
        mark_closed(h, &mut st);
        let socket = st.take_sock();
        let sendfile = st.take_sendfile_handle();
        let registered = st.use_reg();
        drop(st);
        close_socket_fd(h, socket, sendfile, registered);
    }
}

/// `essio_down_ctrl`: the controlling process is gone.
pub(super) fn down_ctrl(h: &Sock, st: &mut State) {
    let fd = st.sock();
    if !do_stop(h, fd, st) {
        mark_closed(h, st);
        let sendfile = st.take_sendfile_handle();
        let registered = st.use_reg();
        close_socket_fd(h, st.take_sock(), sendfile, registered);
    }
}

/// The process monitor of `pid` fired: `esock_down` and `essio_down`.
pub(crate) fn down(value: &O, pid: &O, monitor: u64) {
    let Ok(h) = handle(value) else {
        return;
    };
    essio_down(&h, pid, monitor);
}

fn essio_down(h: &Sock, pid: &O, monitor: u64) {
    let mut st = h.lock_both();
    if st.closer().as_ref() == Some(pid) {
        st.set_closer(None);
        if st.closer_mon() == Some(monitor) {
            st.set_closer_mon(None);
        } else {
            st.set_ctrl_mon(None);
            st.set_ctrl_pid(None);
        }
        if st.close_ref().is_none() {
            mark_closed(h, &mut st);
            let sendfile = st.take_sendfile_handle();
            let registered = st.use_reg();
            close_socket_fd(h, st.take_sock(), sendfile, registered);
        } else {
            st.set_close_ref(None);
        }
    } else if st.ctrl_mon() == Some(monitor) {
        st.set_ctrl_mon(None);
        st.set_ctrl_pid(None);
        if state_bits::is_open(st.read_state()) {
            down_ctrl(h, &mut st);
            st.or_read_state(state_bits::CLOSING);
            st.or_write_state(state_bits::CLOSING);
        }
    } else if st.connector().and_then(|c| c.mon) == Some(monitor) {
        st.set_connector(None);
        st.and_write_state(!state_bits::CONNECTING);
    } else if !state_bits::is_closed(st.read_state()) {
        let fd = st.sock();
        if st.current_reader().is_some() {
            down_requestor(h, &mut st, fd, Kind::Reader, pid, monitor);
        }
        if st.current_acceptor().is_some() {
            down_requestor(h, &mut st, fd, Kind::Acceptor, pid, monitor);
        }
        if st.current_writer().is_some() {
            down_requestor(h, &mut st, fd, Kind::Writer, pid, monitor);
        }
    }
}

/// `essio_down_reader`, `essio_down_acceptor` and `essio_down_writer`.
fn down_requestor(h: &Sock, st: &mut State, fd: Option<i32>, kind: Kind, pid: &O, monitor: u64) {
    let is_current = st.current(kind).and_then(|req| req.mon) == Some(monitor);
    if is_current {
        if let Some(mut current) = st.current(kind) {
            current.mon = None;
            st.set_current(kind, Some(current));
        }
        let activated = fd.is_some_and(|fd| activate_next(h, st, fd, kind));
        if !activated {
            if kind == Kind::Acceptor {
                st.and_read_state(!state_bits::ACCEPTING);
            }
            st.set_current(kind, None);
        }
    } else {
        st.unqueue(h, kind, None, pid);
    }
}

/// `essio_dtor`: the resource is gone. A descriptor that is still open is closed
/// without blocking, and the monitors of the resource are dropped.
pub(super) fn dtor(h: &mut Handle) {
    let mut st = h.lock_both();
    st.or_read_state(state_bits::DTOR | state_bits::CLOSED);
    st.or_write_state(state_bits::DTOR | state_bits::CLOSED);
    st.set_pattern(PATTERN_DTOR | state_bits::CLOSED);
    if let Some(owner) = st.ctrl_pid() {
        demonitor_process(h, &owner, st.take_ctrl_mon());
    }
    if let Some(closer) = st.closer() {
        demonitor_process(h, &closer, st.take_closer_mon());
    }
    let current = [
        st.take_connector(),
        st.take_current(Kind::Reader),
        st.take_current(Kind::Writer),
        st.take_current(Kind::Acceptor),
    ];
    for requestor in current.into_iter().flatten() {
        demonitor_process(h, &requestor.pid, requestor.mon);
    }
    let queued = [
        st.drain_queue(Kind::Reader),
        st.drain_queue(Kind::Writer),
        st.drain_queue(Kind::Acceptor),
    ];
    for requestor in queued.into_iter().flatten() {
        demonitor_process(h, &requestor.pid, requestor.mon);
    }
    let fd = st.take_sock();
    let sendfile = st.take_sendfile_handle();
    drop(st);
    if let Some(fd) = fd {
        raw::close_fd(fd);
    }
    if let Some(sendfile) = sendfile {
        raw::close_fd(sendfile);
    }
    raw::free_descriptor_storage(h);
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
            let st = h.lock_read();
            if state_bits::is_open(st.read_state()) {
                Err(BifError::BADARG)
            } else {
                Ok(error("closed"))
            }
        }
    }
}

/// `essio_cancel_connect`.
fn cancel_connect(h: &Sock, op_ref: &O) -> Result<O, BifError> {
    let mut st = h.lock_write();
    let Some(me) = self_pid() else {
        return Err(BifError::BADARG);
    };
    if !state_bits::is_open(st.write_state()) {
        return Ok(error("closed"));
    }
    match st.connector() {
        Some(connector) if connector.pid == me && &connector.reference == op_ref => {
            let result = st
                .sock()
                .map_or_else(|| atom("not_found"), |fd| cancel_write_select(fd, op_ref));
            if let Some(req) = st.take_connector() {
                demonitor_process(h, &req.pid, req.mon);
            }
            st.and_write_state(!state_bits::CONNECTING);
            Ok(result)
        }
        _ => Ok(error("not_found")),
    }
}

/// `essio_cancel_accept`, `essio_cancel_recv` and `essio_cancel_send`.
fn cancel_requestor(h: &Sock, kind: Kind, op_ref: &O) -> Result<O, BifError> {
    let mut st = if kind == Kind::Writer {
        h.lock_write()
    } else {
        h.lock_read()
    };
    let state = if kind == Kind::Writer {
        st.write_state()
    } else {
        st.read_state()
    };
    if !state_bits::is_open(state) {
        return Ok(error("closed"));
    }
    let Some(current) = st.current(kind) else {
        return Ok(atom("not_found"));
    };
    let Some(me) = self_pid() else {
        return Err(BifError::BADARG);
    };
    if me != current.pid {
        return Ok(if st.unqueue(h, kind, Some(op_ref), &me) {
            atom("ok")
        } else {
            atom("not_found")
        });
    }
    if op_ref != &current.reference {
        return Ok(atom("not_found"));
    }
    let Some(fd) = st.sock() else {
        return Ok(atom("not_found"));
    };
    demonitor_process(h, &current.pid, current.mon);
    let result = if kind == Kind::Writer {
        cancel_write_select(fd, &current.reference)
    } else {
        cancel_read_select(fd, &current.reference)
    };
    if !activate_next(h, &mut st, fd, kind) {
        if kind == Kind::Acceptor {
            st.and_read_state(!state_bits::ACCEPTING);
        }
        st.set_current(kind, None);
    }
    Ok(result)
}
