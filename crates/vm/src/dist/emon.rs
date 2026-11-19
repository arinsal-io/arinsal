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

use super::elink::{connection_of_handle, exit_payload_flag, send_on_connection};
use super::{CtlHeap, badarg, local_pid_term};
use crate::monitor_link::ExternalPid;
use crate::monitor_link::{Monitor, MonitorReference, node_flag, node_type};
use crate::proc_create::{DistOrigin, DistTarget, MonitorInfo, OriginMonitor, ProcessMonitor};
use arinsal_sched::{Pid, Signal};
use arinsal_term::{Term, global_atoms};

/// The local process a `DOP_MONITOR_P` names, and the name it was named by: an internal
/// pid, a registered name (`erts_whereis_name_to_id`; a port or nobody resolves to no
/// process), or an old incarnation of this node (no process). `Err` for anything else.
// Port of erts/emulator/beam/dist.c (erts_net_message, DOP_MONITOR_P: `watched`), OTP-29.1.1.
fn watched_process(
    runtime: &crate::process::Runtime,
    watched: Term,
) -> Result<(Option<Pid>, Option<String>), crate::VmError> {
    if let Some(pid) = watched.as_pid_data() {
        return Ok((Some(Pid::from_data(pid)), None));
    }
    if let Some(name) = watched.as_atom() {
        let text = arinsal_term::global_atoms()
            .text(name)
            .ok_or_else(badarg)?
            .to_owned();
        return Ok((runtime.reg.whereis_proc(name), Some(text)));
    }
    if super::ctl_external_pid(watched).is_some() && super::ctl_is_this_node(watched) {
        return Ok((None, None));
    }
    Err(badarg())
}

/// Incoming `DOP_MONITOR_P` from the external `remote`: create the monitor with `remote` as
/// origin, put its origin half into the connection and queue its target half to the local
/// process; a process that is not there gets a `noproc` `DOP_MONITOR_P_EXIT` back.
// Port of erts/emulator/beam/dist.c (erts_net_message, DOP_MONITOR_P), OTP-29.1.1.
pub(super) fn incoming_monitor(
    runtime: &crate::process::Runtime,
    handle: u64,
    proxy: Pid,
    remote: crate::monitor_link::ExternalPid,
    watched: Term,
    reference: Term,
) -> Result<(), crate::VmError> {
    let id = super::ctl_ref_id(reference).ok_or_else(badarg)?;
    let (pid, name) = watched_process(runtime, watched)?;
    let (_node, connection_id, mld) = connection_of_handle(handle).ok_or_else(badarg)?;
    if let Some(pid) = pid {
        let flags = if name.is_some() { node_flag::NAME } else { 0 };
        let info = MonitorInfo::dist_origin(DistOrigin::new(remote, reference, mld.clone()), name);
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
        watched,
        remote,
        reference,
        Term::atom(arinsal_term::atoms::NOPROC),
    );
    Ok(())
}

/// Incoming `DOP_DEMONITOR_P`: an internal pid gets the demonitor signal, an old incarnation
/// of this node is ignored, a name takes the origin half out of `mld->orig_name_monitors`.
// Port of erts/emulator/beam/dist.c (erts_net_message, DOP_DEMONITOR_P), OTP-29.1.1.
pub(super) fn incoming_demonitor(
    runtime: &crate::process::Runtime,
    handle: u64,
    proxy: Pid,
    watched: Term,
    reference: Term,
) -> Result<(), crate::VmError> {
    let id = super::ctl_ref_id(reference).ok_or_else(badarg)?;
    if let Some(pid) = watched.as_pid_data() {
        let _ = runtime
            .scheduler()?
            .signal(proxy, Pid::from_data(pid), Signal::DistDemonitor(id));
    } else if super::ctl_external_pid(watched).is_some() && super::ctl_is_this_node(watched) {
        // Old incarnation; ignore it.
    } else if watched.as_atom().is_some() {
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
    } else {
        return Err(badarg());
    }
    Ok(())
}

/// `erts_dsig_send_m_exit(ctx, watcher, watched, ref, reason)` on connection `connection_id`.
// Port of erts/emulator/beam/dist.c (erts_dsig_send_m_exit), OTP-29.1.1.
fn send_m_exit(
    runtime: &crate::process::Runtime,
    nodename: u32,
    connection_id: u32,
    watched: Term,
    watcher: ExternalPid,
    reference: Term,
    reason: Term,
) {
    let mut ctl = CtlHeap::new();
    let Ok(watcher) = ctl.external_pid(watcher) else {
        return;
    };
    let built = if exit_payload_flag(nodename) {
        ctl.control(28, &[watched, watcher, reference])
            .map(|c| (c, Some(reason)))
    } else {
        ctl.control(21, &[watched, watcher, reference, reason])
            .map(|c| (c, None))
    };
    if let Ok((control, payload)) = built {
        send_on_connection(runtime, nodename, connection_id, control, payload);
    }
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
    if let Some(runtime) = runtime {
        let watched = match info.name() {
            Some(name) => global_atoms().intern(name).map_or(Term::NIL, Term::atom),
            None => local_pid_term(local),
        };
        send_m_exit(
            runtime,
            origin.dist.nodename,
            origin.dist.connection_id,
            watched,
            origin.watcher,
            origin.reference(),
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
        let to = Pid::from_data(monitor.view().other());
        if monitor.view().is_target() {
            // A local watcher of a remote process: erts_proc_sig_send_monitor_down(NULL,
            // ..., mon, am_noconnection) with the target half.
            let reference = monitor.view().reference();
            drop(monitor);
            send_monitor_down_noconnection(scheduler, to, reference);
            continue;
        }
        let _ = scheduler.signal(to, to, Signal::DemonitorOrigin(monitor.into_shared()));
    }
    for monitor in mld.take_pend_spawn_exit::<_, _, _>() {
        dist_pend_spawn_exit_connection_down(monitor);
    }
}

/// A target half in `dist_pend_spawn_exit` of a connection that went down: resume the parent
/// waiting for a spawn result that will not come.
// Port of erts/emulator/beam/dist.c:326 (dist_pend_spawn_exit_connection_down), OTP-29.1.1.
fn dist_pend_spawn_exit_connection_down(monitor: ProcessMonitor) {
    if let Some(target) = monitor.view().info().dist_target()
        && target.target() == Term::atom(arinsal_term::atoms::PENDING)
        && let Some(waiter) = target.swap_waiter(None)
    {
        // erts_resume
        drop(waiter);
    }
}

/// The `noconnection` DOWN of the monitor `reference` of the local `watcher`, whose target
/// half left the connection (or never reached one).
// Port of erts/emulator/beam/erl_proc_sig_queue.c (erts_proc_sig_send_monitor_down with
// am_noconnection), OTP-29.1.1.
pub(crate) fn send_monitor_down_noconnection(
    scheduler: &arinsal_sched::Scheduler<crate::Process>,
    watcher: Pid,
    reference: u64,
) {
    let _ = scheduler.signal(
        watcher,
        watcher,
        Signal::MonitorDownImmediate {
            reference,
            reason: Term::atom(arinsal_term::atoms::NOCONNECTION).word(),
        },
    );
}

/// `ToProc` of the `DOP_DEMONITOR_P` of a monitor of a remote process: the name of a
/// monitor by name, otherwise the external pid.
fn watched_remote(info: &crate::proc_create::MonitorInfo, target: &DistTarget) -> Term {
    match info.name() {
        Some(name) => global_atoms().intern(name).map_or(Term::NIL, Term::atom),
        None => target.target(),
    }
}

/// Create a monitor of the remote `target` by the local `watcher` on connection `mld`, or a
/// dead-dist monitor when `mld` is `None` (bif.c monitor, `remote_process`): the origin half
/// goes to the caller, the target half into the connection (`erts_monitor_dist_insert`).
/// Returns the origin half and, when the target half did not reach a connection, `false`:
/// the caller then sends itself the `noconnection` DOWN.
// Port of erts/emulator/beam/bif.c (erts_internal_monitor_process_2, remote_process),
// OTP-29.1.1.
pub(crate) fn create_origin(
    ix: Option<usize>,
    reference: crate::monitor_link::MonitorReference,
    watcher: Pid,
    info: crate::proc_create::MonitorInfo,
    target: DistTarget,
) -> (ProcessMonitor, bool) {
    let dist = target.dist.clone();
    let named = info.name().is_some();
    let info = info.with_dist_target(target);
    let (origin, target) = Monitor::create_at(
        ix,
        node_type::MONITOR_DIST_PROC,
        reference,
        watcher.data(),
        0,
        if named { node_flag::NAME } else { 0 },
        info,
        OriginMonitor::Distributed,
    );
    match dist.monitor_insert(target) {
        Ok(()) => (origin, true),
        Err(target) => {
            drop(target);
            (origin, false)
        }
    }
}

/// [`create_origin`] followed by the `noconnection` DOWN when the target half reached no
/// connection, for an origin half the caller inserts itself.
pub(crate) fn create_origin_or_down(
    runtime: &crate::process::Runtime,
    ix: Option<usize>,
    reference: crate::monitor_link::MonitorReference,
    watcher: Pid,
    info: crate::proc_create::MonitorInfo,
    target: DistTarget,
) -> Result<ProcessMonitor, crate::VmError> {
    let (origin, connected) = create_origin(ix, reference, watcher, info, target);
    if !connected {
        send_monitor_down_noconnection(runtime.scheduler()?, watcher, origin.view().reference());
    }
    Ok(origin)
}

/// Release an origin half of a monitor of a remote process that leaves the watcher's
/// monitor tree, taking its target half out of the connection (`erts_monitor_dist_delete(
/// &mdp->u.target)`). Returns whether the target half was still in the connection.
pub(crate) fn release_origin(origin: ProcessMonitor) -> bool {
    let dist = origin
        .view()
        .info()
        .dist_target()
        .map(|target| target.dist.clone());
    match dist.and_then(|dist| dist.monitor_delete_other(&origin)) {
        Some(target) => {
            ProcessMonitor::release_both(origin, target);
            true
        }
        None => {
            drop(origin);
            false
        }
    }
}

/// `demonitor` of a monitor of a remote process, and its exit-time variant
/// `erts_proc_exit_dist_demonitor`: the target half leaves the connection and the remote
/// node gets `DOP_DEMONITOR_P` over the connection the monitor was made on.
// Port of erts/emulator/beam/bif.c (demonitor, ERTS_MON_TYPE_DIST_PROC) and
// erl_process.c (erts_proc_exit_handle_monitor, origin ERTS_MON_TYPE_DIST_PROC), OTP-29.1.1.
pub(crate) fn demonitor_remote(
    runtime: Option<&crate::process::Runtime>,
    watcher: Pid,
    origin: ProcessMonitor,
) {
    // bif.c demonitor: erts_monitor_dist_delete(&mdp->u.target), erts_dsig_send_demonitor
    // with `mdp->ref` from the monitor's heap, then erts_monitor_release.
    let dist = origin
        .view()
        .info()
        .dist_target()
        .map(|target| target.dist.clone());
    let target_half = dist
        .as_ref()
        .and_then(|dist| dist.monitor_delete_other(&origin));
    let view = origin.view();
    let info = view.info();
    if let (Some(runtime), Some(target)) = (runtime, info.dist_target()) {
        let mut ctl = CtlHeap::new();
        let fields = [
            local_pid_term(watcher),
            watched_remote(info, target),
            target.reference(),
        ];
        if let Ok(control) = ctl.control(20, &fields) {
            send_on_connection(
                runtime,
                target.dist.nodename,
                target.dist.connection_id,
                control,
                None,
            );
        }
    }
    match target_half {
        Some(target) => ProcessMonitor::release_both(origin, target),
        None => drop(origin),
    }
}

/// The monitored object of a DOWN or `process_info(monitors)` entry of a monitor of a remote
/// process: the external pid in the monitor's heap, or `{Name, Node}` for a monitor by name.
/// It refers to the monitor's heap: build it while the monitor is held.
#[derive(Clone, Copy)]
pub(crate) struct RemoteObject {
    name: Option<arinsal_term::Atom>,
    target: Term,
}

impl RemoteObject {
    /// The object on `heap`.
    // Port of erts/emulator/beam/erl_proc_sig_queue.c (convert_to_down_message: copy of
    // `mdep->md.origin.other.item` / TUPLE2(name, node)), OTP-29.1.1.
    pub(crate) fn build(
        self,
        heap: &mut impl arinsal_term::HeapAlloc,
    ) -> Result<Term, arinsal_term::TermError> {
        match self.name {
            Some(name) => {
                arinsal_term::TermBuilder::new(heap).tuple(&[Term::atom(name), self.target])
            }
            None => arinsal_term::copy_term(self.target, heap),
        }
    }
}

/// The [`RemoteObject`] of a monitor of a remote process.
pub(crate) fn remote_object(info: &crate::proc_create::MonitorInfo) -> Option<RemoteObject> {
    let target = info.dist_target()?;
    let name = match info.name() {
        Some(name) => Some(global_atoms().intern(name).ok()?),
        None => None,
    };
    Some(RemoteObject {
        name,
        target: target.target(),
    })
}

/// The monitor of a child spawned by a remote `spawn_request` with `monitor`: the origin half
/// (the remote parent) goes into the connection, the target half into the child's monitor
/// tree; both are released when the connection is gone.
// Port of erts/emulator/beam/erl_process.c (erl_create_process, SPO_MONITOR), OTP-29.1.1.
pub(crate) fn insert_spawn_child_monitor(child: &mut crate::Process, pid: Pid, origin: DistOrigin) {
    let Some(id) = super::ctl_ref_id(origin.reference()) else {
        return;
    };
    let dist = origin.dist.clone();
    let (origin, target): (ProcessMonitor, ProcessMonitor) = Monitor::create(
        node_type::MONITOR_DIST_PROC,
        MonitorReference::ordinary(id),
        0,
        pid.data(),
        0,
        MonitorInfo::dist_origin(origin, None),
        OriginMonitor::Distributed,
    );
    match dist.monitor_insert(origin) {
        Ok(()) => child.monitors.insert(target),
        Err(origin) => ProcessMonitor::release_both(origin, target),
    }
}
