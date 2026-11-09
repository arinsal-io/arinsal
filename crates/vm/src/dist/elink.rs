//! External links: the distribution side of links between a local and a remote process.
//!
//! Port of the `ERTS_LNK_TYPE_DIST_PROC` paths of erts/emulator/beam/dist.c (DOP_LINK,
//! DOP_EXIT, DOP_EXIT2, DOP_UNLINK_ID, DOP_UNLINK_ID_ACK), erl_proc_sig_queue.c
//! (erts_proc_sig_send_dist_*, reply_dist_unlink_ack, erts_proc_sig_send_link_exit_noconnection),
//! erl_process.c (erts_proc_exit_handle_link) and bif.c (link_opt, unlink_1), OTP-29.1.1.

use super::{atom, badarg, control, emit_control_message_on_handle, local_pid_owned};
use crate::monitor_link::{ExternalPid, Link, node_type};
use crate::node_tables;
use crate::process::Message;
use arinsal_etf::OwnedTerm;
use arinsal_sched::{Pid, Signal};
use arinsal_term::{Term, global_atoms, to_owned};
use std::sync::Arc;

/// The proc half of an external link in transit as a [`Signal::DistLink`] (erts queues
/// `&ldp->proc` itself). A half dropped without reaching a link tree takes its dist half out of
/// the connection, as erts does when the signal cannot be queued.
pub(crate) struct DistLinkHalf(std::sync::Mutex<Option<Link>>);

impl DistLinkHalf {
    fn new(link: Link) -> Self {
        Self(std::sync::Mutex::new(Some(link)))
    }

    /// Take the link half.
    pub(crate) fn take_half(&self) -> Option<Link> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
    }

    /// Take the link half out of a [`Signal::DistLink`] payload.
    pub(crate) fn take(shared: &arinsal_sched::SharedPayload) -> Option<Link> {
        shared
            .0
            .downcast_ref::<Self>()?
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
    }
}

impl Drop for DistLinkHalf {
    fn drop(&mut self) {
        let link = self
            .0
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some(link) = link {
            let deleted = link.dist_delete_other();
            link.release_external(deleted);
        }
    }
}

/// The external link of a successful `spawn_request` with link, from `parent` to the child
/// `result`, its dist half put into the connection.
// Port of erts/emulator/beam/dist.c (erts_net_message, DOP_SPAWN_REPLY), OTP-29.1.1.
pub(super) fn spawn_reply_link(
    runtime: &crate::process::Runtime,
    handle: u64,
    parent: Pid,
    result: &OwnedTerm,
) -> Result<DistLinkHalf, crate::VmError> {
    let remote = external_pid(result).ok_or_else(badarg)?;
    let (_node, _connection_id, mld) = connection_of_handle(handle).ok_or_else(badarg)?;
    let (proc_half, dist_half) =
        Link::create_external(node_type::LINK_DIST_PROC, parent.data(), remote);
    if let Err(dist_half) = dist_half.dist_insert(&mld) {
        send_link_exit_noconnection(runtime, dist_half);
    }
    Ok(DistLinkHalf::new(proc_half))
}

/// `STORE_NC` of a decoded external pid: the key an external link has.
pub(crate) fn external_pid(term: &OwnedTerm) -> Option<ExternalPid> {
    let OwnedTerm::Pid {
        node,
        id,
        serial,
        creation,
    } = term
    else {
        return None;
    };
    let sysname = global_atoms().intern(node).ok()?.0;
    Some(ExternalPid {
        sysname,
        creation: *creation,
        number: *id,
        serial: *serial,
    })
}

/// The pid term of an external pid, for the wire.
pub(crate) fn external_pid_owned(pid: ExternalPid) -> Option<OwnedTerm> {
    let node = global_atoms()
        .text(arinsal_term::Atom(pid.sysname))?
        .to_owned();
    Some(OwnedTerm::Pid {
        node,
        id: pid.number,
        serial: pid.serial,
        creation: pid.creation,
    })
}

/// The external pid term on a process heap (erts copies it out of the signal's fragment).
pub(crate) fn external_pid_term(
    heap: &mut arinsal_term::ProcessHeap,
    pid: ExternalPid,
) -> Result<Term, crate::VmError> {
    let owned = external_pid_owned(pid).ok_or_else(badarg)?;
    arinsal_term::from_owned(&owned, heap).map_err(|_| badarg())
}

/// The node name, connection id and `mld` of the connection with handle `handle`.
fn connection_of_handle(
    handle: u64,
) -> Option<(String, u32, Arc<crate::monitor_link::MonLnkDist>)> {
    let tables = node_tables::lock();
    let entry = tables.entries.values().find(|entry| {
        entry
            .dist
            .as_ref()
            .is_some_and(|state| state.handle == handle)
    })?;
    Some((entry.name.clone(), entry.connection_id, entry.mld.clone()?))
}

/// `erts_dsig_prepare(dep)` with a connection id check, then send: queue `control` on the
/// connection to `nodename` only if it is still connection `connection_id` (connected or
/// pending). Never sets up a connection.
fn send_on_connection(
    runtime: &crate::process::Runtime,
    nodename: u32,
    connection_id: u32,
    control: OwnedTerm,
    payload: Option<OwnedTerm>,
) {
    let Some(node) = global_atoms().text(arinsal_term::Atom(nodename)) else {
        return;
    };
    let handle = {
        let mut tables = node_tables::lock();
        let local_name = tables.local_name.clone();
        let local_creation = tables.local_creation;
        let Some(entry) = tables.entries.get_mut(node) else {
            return;
        };
        if entry.connection_id != connection_id {
            return;
        }
        match entry.state {
            node_tables::ConnState::Connected => match entry.dist.as_ref() {
                Some(state) => state.handle,
                None => return,
            },
            node_tables::ConnState::Pending => {
                let control = node_tables::relabel_local_node(control, &local_name, local_creation);
                let payload = payload
                    .map(|m| node_tables::relabel_local_node(m, &local_name, local_creation));
                entry.pending_out.push_back((control, payload));
                return;
            }
            _ => return,
        }
    };
    let _ = emit_control_message_on_handle(runtime, handle, control, payload);
}

/// Whether the connection to `node` is up with this id (for a reply on the same connection).
fn exit_payload_flag(nodename: u32) -> bool {
    let Some(node) = global_atoms().text(arinsal_term::Atom(nodename)) else {
        return false;
    };
    node_tables::lock()
        .entries
        .get(node)
        .and_then(|entry| entry.dist.as_ref())
        .is_some_and(|state| state.flags & node_tables::DFLAG_EXIT_PAYLOAD != 0)
}

/// `erts_dsig_send_exit_tt(ctx, from, to, reason)` on connection `connection_id`.
fn send_exit(
    runtime: &crate::process::Runtime,
    nodename: u32,
    connection_id: u32,
    local: Pid,
    remote: ExternalPid,
    reason: OwnedTerm,
) {
    let Some(remote) = external_pid_owned(remote) else {
        return;
    };
    let (control, payload) = if exit_payload_flag(nodename) {
        (
            control(24, vec![local_pid_owned(local), remote]),
            Some(reason),
        )
    } else {
        (
            control(3, vec![local_pid_owned(local), remote, reason]),
            None,
        )
    };
    send_on_connection(runtime, nodename, connection_id, control, payload);
}

/// Incoming `DOP_LINK`: create the external link, put its dist half into the connection and
/// queue its proc half to the local process.
// Port of erts/emulator/beam/dist.c (erts_net_message, DOP_LINK), OTP-29.1.1.
pub(super) fn incoming_link(
    runtime: &crate::process::Runtime,
    handle: u64,
    proxy: Pid,
    from: &OwnedTerm,
    to: Option<Pid>,
) -> Result<(), crate::VmError> {
    let remote = external_pid(from).ok_or_else(badarg)?;
    let (_node, connection_id, mld) = connection_of_handle(handle).ok_or_else(badarg)?;
    if let Some(to) = to {
        let (proc_half, dist_half) =
            Link::create_external(node_type::LINK_DIST_PROC, to.data(), remote);
        let not_inserted = dist_half.dist_insert(&mld).err();
        let signal = Signal::DistLink(arinsal_sched::SharedPayload(Arc::new(DistLinkHalf::new(
            proc_half,
        ))));
        if runtime.scheduler()?.signal(proxy, to, signal).is_ok() {
            if let Some(dist_half) = not_inserted {
                // Race: connection already down => send link exit.
                send_link_exit_noconnection(runtime, dist_half);
            }
            return Ok(());
        }
        // The dropped signal took the dist half out of the connection and released both.
        drop(not_inserted);
    }
    // Old incarnation of this node or a dead process: reply noproc.
    send_exit_reply(runtime, mld.nodename, connection_id, to, remote, "noproc");
    Ok(())
}

fn send_exit_reply(
    runtime: &crate::process::Runtime,
    nodename: u32,
    connection_id: u32,
    to: Option<Pid>,
    remote: ExternalPid,
    reason: &str,
) {
    let Some(to) = to else {
        return;
    };
    send_exit(
        runtime,
        nodename,
        connection_id,
        to,
        remote,
        OwnedTerm::Atom(reason.into()),
    );
}

/// Port of erts/emulator/beam/erl_proc_sig_queue.c (erts_proc_sig_send_link_exit_noconnection),
/// OTP-29.1.1: the `noconnection` exit of the local end of `dist_half`, marked with the link's
/// connection so that it leaves a link made over a newer connection alone.
pub(crate) fn send_link_exit_noconnection(runtime: &crate::process::Runtime, dist_half: Link) {
    let view = dist_half.view();
    let (Some(from), Some(local)) = (view.external_pid(), view.external_local()) else {
        return;
    };
    let connection_id = view.external_dist().map_or(!0, |dist| dist.connection_id);
    let to = Pid::from_data(local);
    drop(dist_half);
    let Ok(reason) = Message::copy_from(atom("noconnection")) else {
        return;
    };
    if let Ok(scheduler) = runtime.scheduler() {
        let _ = scheduler.signal(
            to,
            to,
            Signal::DistExit(Box::new(arinsal_sched::DistExitSignal {
                from,
                linked: true,
                connection_lost: Some(connection_id),
                reason,
            })),
        );
    }
}

/// The links of a connection that went down (dist.c link_connection_down for each link of
/// `mld->links`).
pub(super) fn links_connection_down(
    runtime: &crate::process::Runtime,
    mld: Option<Arc<crate::monitor_link::MonLnkDist>>,
) {
    let Some(mld) = mld else {
        return;
    };
    for dist_half in mld.take_links() {
        send_link_exit_noconnection(runtime, dist_half);
    }
}

/// Incoming `DOP_EXIT`/`DOP_PAYLOAD_EXIT` (`linked`) or `DOP_EXIT2`/`DOP_PAYLOAD_EXIT2`.
// Port of erts/emulator/beam/erl_proc_sig_queue.c (erts_proc_sig_send_dist_link_exit and
// erts_proc_sig_send_dist_exit), OTP-29.1.1.
pub(super) fn incoming_exit(
    runtime: &crate::process::Runtime,
    proxy: Pid,
    from: &OwnedTerm,
    to: Pid,
    linked: bool,
    reason: Message,
) -> Result<(), crate::VmError> {
    let from = external_pid(from).ok_or_else(badarg)?;
    // A dead process takes the signal along (dist.c: "Process not alive").
    let _ = runtime.scheduler()?.signal(
        proxy,
        to,
        Signal::DistExit(Box::new(arinsal_sched::DistExitSignal {
            from,
            linked,
            connection_lost: None,
            reason,
        })),
    );
    Ok(())
}

/// Incoming `DOP_UNLINK_ID` (`ack == false`) or `DOP_UNLINK_ID_ACK`.
// Port of erts/emulator/beam/erl_proc_sig_queue.c (erts_proc_sig_send_dist_unlink and
// erts_proc_sig_send_dist_unlink_ack), OTP-29.1.1.
pub(super) fn incoming_unlink(
    runtime: &crate::process::Runtime,
    handle: u64,
    proxy: Pid,
    id: u64,
    from: &OwnedTerm,
    to: Pid,
    ack: bool,
) -> Result<(), crate::VmError> {
    let remote = external_pid(from).ok_or_else(badarg)?;
    let (_node, connection_id, mld) = connection_of_handle(handle).ok_or_else(badarg)?;
    let op = Box::new(arinsal_sched::DistUnlinkOp {
        nodename: mld.nodename,
        connection_id,
        local: to,
        remote,
        id,
    });
    let signal = if ack {
        Signal::DistUnlinkAck(op.clone())
    } else {
        Signal::DistUnlink(op.clone())
    };
    if runtime.scheduler()?.signal(proxy, to, signal).is_err() && !ack {
        reply_dist_unlink_ack(runtime, &op);
    }
    Ok(())
}

/// Port of erts/emulator/beam/erl_proc_sig_queue.c (reply_dist_unlink_ack), OTP-29.1.1: the
/// ack goes out only on the connection the unlink arrived on.
pub(crate) fn reply_dist_unlink_ack(
    runtime: &crate::process::Runtime,
    op: &arinsal_sched::DistUnlinkOp,
) {
    if op.id == 0 {
        return;
    }
    let Some(remote) = external_pid_owned(op.remote) else {
        return;
    };
    let control = control(
        36,
        vec![
            OwnedTerm::Int(op.id as i64),
            local_pid_owned(op.local),
            remote,
        ],
    );
    send_on_connection(runtime, op.nodename, op.connection_id, control, None);
}

/// The `ERTS_LNK_TYPE_DIST_PROC` case of erts_proc_exit_handle_link: the local process `local`
/// exits (or a link reached it while exiting, with `noproc`), so the remote end gets an exit
/// signal over the connection the link was made on, unless an unlink is pending.
// Port of erts/emulator/beam/erl_process.c (erts_proc_exit_handle_link), OTP-29.1.1.
pub(crate) fn proc_exit_handle_link(
    runtime: Option<&crate::process::Runtime>,
    local: Pid,
    link: Link,
    reason: Term,
) {
    let view = link.view();
    let remote = view.external_pid();
    let unlinking = view.unlinking() != 0;
    let dist = view
        .external_dist()
        .map(|dist| (dist.nodename, dist.connection_id));
    let deleted = link.dist_delete_other();
    link.release_external(deleted);
    if unlinking {
        return;
    }
    let (Some(runtime), Some(remote), Some((nodename, connection_id))) = (runtime, remote, dist)
    else {
        return;
    };
    let Ok(reason) = to_owned(reason) else {
        return;
    };
    send_exit(runtime, nodename, connection_id, local, remote, reason);
}

/// `link(Pid)` for an external pid.
// Port of erts/emulator/beam/bif.c (link_opt, is_external_pid), OTP-29.1.1.
pub(super) fn link_external(
    process: &mut crate::Process,
    ctx: &mut arinsal_sched::RunCtx<'_, Message>,
    node: &str,
    target: OwnedTerm,
) -> Result<Term, crate::VmError> {
    let remote = external_pid(&target).ok_or_else(badarg)?;
    let me = ctx.pid();
    // `created` comes with the new link's dist half; an existing link being unlinked comes
    // with the connection it was made on and a prepared replacement (`pelnk`).
    let (dist_half, old_connection, prepared) = {
        let (mut link, dist_half) =
            process
                .links
                .lookup_create_external(node_type::LINK_DIST_PROC, me.data(), remote);
        link.set_priority(false);
        match dist_half {
            Some(dist_half) => (Some(dist_half), None, None),
            None => {
                if link.view().unlinking() == 0 {
                    return Ok(atom("true"));
                }
                let old_connection = link.view().external_dist().map(|dist| dist.connection_id);
                let prepared = Link::create_external(node_type::LINK_DIST_PROC, me.data(), remote);
                (None, old_connection, Some(prepared))
            }
        }
    };
    let runtime = process.runtime.ok_or_else(badarg)?;
    match super::dsig_prepare(process, ctx, node)? {
        super::DsigPrepare::NotAlive | super::DsigPrepare::NotConnected => {
            let nodename = global_atoms().intern(node).map_err(|_| badarg())?.0;
            let mut dist_half = match (dist_half, prepared) {
                (Some(dist_half), _) => dist_half,
                // Unlinking an old link of an old connection: replace it with the prepared
                // one (`erts_link_tree_replace`, then `erts_link_release(rlnk)`).
                (None, Some((proc_half, dist_half))) => {
                    replace_proc_half(process, &remote, proc_half, false);
                    dist_half
                }
                (None, None) => unreachable!("an existing link is replaced"),
            };
            dist_half.view_mut().set_dead_dist(nodename);
            send_link_exit_noconnection(runtime, dist_half);
        }
        super::DsigPrepare::Connected { connection_id, mld } => {
            let inserting = match (dist_half, prepared) {
                (Some(dist_half), _) => Some(dist_half),
                (None, Some((proc_half, dist_half))) if old_connection != Some(connection_id) => {
                    // Unlinking an old link of an old connection: replace it, taking the old
                    // dist half out of its connection (`erts_link_dist_delete`).
                    replace_proc_half(process, &remote, proc_half, true);
                    Some(dist_half)
                }
                (None, prepared) => {
                    // The same connection: the unlink is cancelled; `pelnk` is released.
                    if let Some((proc_half, dist_half)) = prepared {
                        Link::release_both(proc_half, dist_half);
                    }
                    if let Some(mut link) = process.links.get_external_mut(&remote) {
                        link.set_unlinking(0);
                    }
                    None
                }
            };
            if let Some(dist_half) = inserting
                && let Err(dist_half) = dist_half.dist_insert(&mld)
            {
                // The connection went down after the prepare.
                send_link_exit_noconnection(runtime, dist_half);
            }
            super::queue_outgoing_on(
                process,
                ctx,
                node,
                connection_id,
                control(1, vec![local_pid_owned(me), target]),
                None,
            )?;
        }
    }
    Ok(atom("true"))
}

/// `erts_link_tree_replace` of the proc half keyed by `remote` with `proc_half`, then the
/// release of the old half: with its dist half when `delete_dist` takes that out of its
/// connection (`erts_link_release_both`), else alone (`erts_link_release`).
fn replace_proc_half(
    process: &mut crate::Process,
    remote: &ExternalPid,
    proc_half: Link,
    delete_dist: bool,
) {
    if let Some(old) = process.links.remove_external(remote) {
        let deleted = delete_dist && old.dist_delete_other();
        old.release_external(deleted);
    }
    process.links.insert(proc_half);
}

/// `unlink(Pid)` for an external pid.
// Port of erts/emulator/beam/bif.c (unlink_1, ERTS_LNK_TYPE_DIST_PROC), OTP-29.1.1.
pub(super) fn unlink_external(
    process: &mut crate::Process,
    ctx: &mut arinsal_sched::RunCtx<'_, Message>,
    node: &str,
    target: OwnedTerm,
) -> Result<Term, crate::VmError> {
    let Some(remote) = external_pid(&target) else {
        return Ok(atom("true"));
    };
    let id = process.next_ref();
    let connection_id = {
        let Some(mut link) = process.links.get_external_mut(&remote) else {
            return Ok(atom("true"));
        };
        if link.view().unlinking() != 0 {
            return Ok(atom("true"));
        }
        link.set_priority(false);
        link.set_unlinking(id);
        link.view().external_dist().map(|dist| dist.connection_id)
    };
    let current = node_tables::lock().entries.get(node).and_then(|entry| {
        matches!(
            entry.state,
            node_tables::ConnState::Connected | node_tables::ConnState::Pending
        )
        .then_some(entry.connection_id)
    });
    // Not connected, or connected over another connection than the one the link was set up
    // on: nothing is sent and the link waits, unlinking, for its `noconnection` exit.
    if current.is_some() && current == connection_id {
        super::queue_outgoing(
            process,
            ctx,
            node,
            control(
                35,
                vec![
                    OwnedTerm::Int(id as i64),
                    local_pid_owned(ctx.pid()),
                    target,
                ],
            ),
            None,
        )?;
    }
    Ok(atom("true"))
}
