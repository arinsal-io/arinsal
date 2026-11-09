//! External monitors of local processes: the `ERTS_MON_TYPE_DIST_PROC` monitors a remote
//! process holds on a local one.
//!
//! Port of the target-side paths of erts/emulator/beam/dist.c (DOP_MONITOR_P,
//! DOP_DEMONITOR_P, monitor_connection_down), erl_proc_sig_queue.c
//! (erts_proc_sig_send_dist_demonitor, ERTS_SIG_Q_TYPE_DIST_PROC_DEMONITOR) and
//! erl_process.c (erts_proc_exit_handle_monitor, target `ERTS_MON_TYPE_DIST_PROC`), OTP-29.1.1:
//! the origin half lives in the connection (`mld->monitors`, or `mld->orig_name_monitors` for a
//! monitor by name), the target half in the monitored process' monitor tree, and both share
//! the external watcher, the remote reference and the connection.

use super::elink::{connection_of_handle, exit_payload_flag, external_pid, send_on_connection};
use super::{badarg, control, local_pid, local_pid_owned, remote_ref_id};
use crate::monitor_link::{Monitor, MonitorReference, node_flag, node_type};
use crate::proc_create::{DistOrigin, MonitorInfo, OriginMonitor, ProcessMonitor};
use arinsal_etf::OwnedTerm;
use arinsal_sched::{Pid, Signal};
use arinsal_term::{Term, to_owned};

/// The local process a `DOP_MONITOR_P` / `DOP_DEMONITOR_P` names, and the name it was named
/// by. `Err` for a malformed `ToProc`.
fn watched_process(
    runtime: &crate::process::Runtime,
    watched: &OwnedTerm,
    local: &str,
) -> Result<(Option<Pid>, Option<String>), crate::VmError> {
    match watched {
        OwnedTerm::Atom(name) => Ok((runtime.reg.whereis_proc_str(name), Some(name.clone()))),
        // An old incarnation of this node does not resolve: reply noproc.
        OwnedTerm::Pid { .. } => Ok((local_pid(watched, local), None)),
        _ => Err(badarg()),
    }
}

/// Incoming `DOP_MONITOR_P`: create the monitor with the external `watcher` as origin, put
/// its origin half into the connection and queue its target half to the local process.
// Port of erts/emulator/beam/dist.c (erts_net_message, DOP_MONITOR_P), OTP-29.1.1.
pub(super) fn incoming_monitor(
    runtime: &crate::process::Runtime,
    handle: u64,
    proxy: Pid,
    watcher: &OwnedTerm,
    watched: &OwnedTerm,
    reference: &OwnedTerm,
    local: &str,
) -> Result<(), crate::VmError> {
    let remote = external_pid(watcher).ok_or_else(badarg)?;
    let OwnedTerm::Ref { .. } = reference else {
        return Err(badarg());
    };
    let id = remote_ref_id(reference).ok_or_else(badarg)?;
    let (pid, name) = watched_process(runtime, watched, local)?;
    let (_node, connection_id, mld) = connection_of_handle(handle).ok_or_else(badarg)?;
    if let Some(pid) = pid {
        let flags = if name.is_some() { node_flag::NAME } else { 0 };
        let info = MonitorInfo::dist_origin(
            DistOrigin {
                watcher: remote,
                reference: reference.clone(),
                dist: mld.clone(),
            },
            name,
        );
        let (origin, target): (ProcessMonitor, ProcessMonitor) = Monitor::create(
            node_type::MONITOR_DIST_PROC,
            MonitorReference::ordinary(id),
            0,
            pid.data(),
            flags,
            info,
            OriginMonitor::Distributed,
        );
        if let Err(origin) = mld.monitor_insert(origin) {
            // Race: connection down => do nothing.
            ProcessMonitor::release_both(origin, target);
            return Ok(());
        }
        let shared = target.into_shared();
        let kept = shared.clone();
        let signal = Signal::Monitor {
            reference: id,
            shared,
        };
        if runtime.scheduler()?.signal(proxy, pid, signal).is_ok() {
            return Ok(());
        }
        // Failed to send to the local process: take the origin half back out of the
        // connection (`erts_monitor_dist_delete(&mdp->origin)`) and release it.
        if let Some(target) = crate::proc_create::ProcessMonitorData::take_half(kept, true)
            && let Some(origin) = mld.monitor_delete_other(&target)
        {
            ProcessMonitor::release_both(origin, target);
        }
    }
    send_m_exit(
        runtime,
        mld.nodename,
        connection_id,
        watched.clone(),
        watcher.clone(),
        reference.clone(),
        OwnedTerm::Atom("noproc".into()),
    );
    Ok(())
}

/// Incoming `DOP_DEMONITOR_P`.
// Port of erts/emulator/beam/dist.c (erts_net_message, DOP_DEMONITOR_P), OTP-29.1.1.
pub(super) fn incoming_demonitor(
    runtime: &crate::process::Runtime,
    handle: u64,
    proxy: Pid,
    watcher: &OwnedTerm,
    watched: &OwnedTerm,
    reference: &OwnedTerm,
    local: &str,
) -> Result<(), crate::VmError> {
    external_pid(watcher).ok_or_else(badarg)?;
    let OwnedTerm::Ref { .. } = reference else {
        return Err(badarg());
    };
    let id = remote_ref_id(reference).ok_or_else(badarg)?;
    match watched {
        OwnedTerm::Pid { .. } => {
            // An old incarnation of this node is ignored.
            if let Some(pid) = local_pid(watched, local) {
                let _ = runtime
                    .scheduler()?
                    .signal(proxy, pid, Signal::DistDemonitor(id));
            }
        }
        OwnedTerm::Atom(_) => {
            let (_node, _connection_id, mld) = connection_of_handle(handle).ok_or_else(badarg)?;
            if let Some(origin) = mld.name_monitor_remove::<_, _, _>(id) {
                let origin: ProcessMonitor = origin;
                let to = Pid::from_data(origin.view().other());
                let _ = runtime.scheduler()?.signal(
                    proxy,
                    to,
                    Signal::DemonitorOrigin(origin.into_shared()),
                );
            }
        }
        _ => return Err(badarg()),
    }
    Ok(())
}

/// `erts_dsig_send_m_exit(ctx, watcher, watched, ref, reason)` on connection `connection_id`.
// Port of erts/emulator/beam/dist.c (erts_dsig_send_m_exit), OTP-29.1.1.
fn send_m_exit(
    runtime: &crate::process::Runtime,
    nodename: u32,
    connection_id: u32,
    watched: OwnedTerm,
    watcher: OwnedTerm,
    reference: OwnedTerm,
    reason: OwnedTerm,
) {
    let (control, payload) = if exit_payload_flag(nodename) {
        (control(28, vec![watched, watcher, reference]), Some(reason))
    } else {
        (control(21, vec![watched, watcher, reference, reason]), None)
    };
    send_on_connection(runtime, nodename, connection_id, control, payload);
}

/// The target `ERTS_MON_TYPE_DIST_PROC` case of erts_proc_exit_handle_monitor: the local
/// process `local` exits (or a monitor reached it while exiting, with `noproc`), so the
/// remote watcher gets `DOP_MONITOR_P_EXIT` over the connection the monitor was made on, and
/// the origin half leaves that connection.
// Port of erts/emulator/beam/erl_process.c (erts_proc_exit_handle_monitor), OTP-29.1.1.
pub(crate) fn proc_exit_handle_target(
    runtime: Option<&crate::process::Runtime>,
    local: Pid,
    monitor: ProcessMonitor,
    reason: Term,
) {
    let view = monitor.view();
    let info = view.info();
    let Some(origin) = info.external_origin() else {
        return;
    };
    if let (Some(runtime), Some(watcher), Ok(reason)) = (
        runtime,
        super::elink::external_pid_owned(origin.watcher),
        to_owned(reason),
    ) {
        let watched = match info.name() {
            Some(name) => OwnedTerm::Atom(name.to_owned()),
            None => local_pid_owned(local),
        };
        send_m_exit(
            runtime,
            origin.dist.nodename,
            origin.dist.connection_id,
            watched,
            watcher,
            origin.reference.clone(),
            reason,
        );
    }
    let dist = origin.dist.clone();
    match dist.monitor_delete_other(&monitor) {
        Some(origin) => ProcessMonitor::release_both(origin, monitor),
        None => drop(monitor),
    }
}

/// `ERTS_SIG_Q_TYPE_DIST_PROC_DEMONITOR`: take the target half `reference` out of the
/// receiver's monitor tree, and its origin half out of the connection.
// Port of erts/emulator/beam/erl_proc_sig_queue.c (erts_proc_sig_handle_incoming,
// ERTS_SIG_Q_OP_DEMONITOR), OTP-29.1.1.
pub(crate) fn handle_dist_demonitor(process: &mut crate::Process, reference: u64) -> bool {
    let Ok(Some(target)) = process.monitors.remove_if(reference, |flags| {
        flags & node_flag::TARGET != 0
            && flags & node_flag::TYPE_MASK == node_type::MONITOR_DIST_PROC
    }) else {
        return false;
    };
    let dist = target
        .view()
        .info()
        .external_origin()
        .map(|origin| origin.dist.clone());
    match dist.and_then(|dist| dist.monitor_delete_other(&target)) {
        Some(origin) => ProcessMonitor::release_both(origin, target),
        None => drop(target),
    }
    true
}

/// The monitors of a connection that went down (dist.c monitor_connection_down for each
/// monitor of `mld->monitors` and `mld->orig_name_monitors`): an origin half is a remote
/// watcher of a local process, which gets a demonitor signal carrying it.
pub(super) fn monitors_connection_down(
    runtime: &crate::process::Runtime,
    mld: Option<&std::sync::Arc<crate::monitor_link::MonLnkDist>>,
) {
    let Some(mld) = mld else {
        return;
    };
    let Ok(scheduler) = runtime.scheduler() else {
        return;
    };
    for monitor in mld.take_monitors::<_, _, _>() {
        let monitor: ProcessMonitor = monitor;
        if monitor.view().is_target() {
            // Target halves of local watchers of remote processes are kept by the
            // distribution tables (see `take_connection_monitors`).
            continue;
        }
        let to = Pid::from_data(monitor.view().other());
        let _ = scheduler.signal(to, to, Signal::DemonitorOrigin(monitor.into_shared()));
    }
}
