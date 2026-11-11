//! Distribution controller state and the VM side of the controller BIFs.
//!
//! Control tuples and packet framing follow `erts/emulator/beam/dist.c` in
//! OTP-29.1.1. Socket ownership remains in Erlang's distribution modules.

use crate::node_tables::{self, DistState};
use crate::process::Message;
use crate::{Process, Vm, VmError};
use arinsal_etf::{DistributionHeader, OwnedTerm};
use arinsal_sched::{Event, Payload, Pid, RunCtx, Signal};
use arinsal_term::{Term, TermBuilder, from_owned, global_atoms, to_owned};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

mod elink;
mod emon;
pub(crate) use elink::{
    DistLinkHalf, external_pid_term, proc_exit_handle_link, reply_dist_unlink_ack,
};
pub(crate) use emon::{
    demonitor_remote, handle_dist_demonitor, insert_spawn_child_monitor, proc_exit_handle_target,
    release_origin, remote_object,
};

static NEXT_HANDLE: AtomicU64 = AtomicU64::new(1 << 40);
static NEXT_REMOTE_PID: AtomicU32 = AtomicU32::new(1 << 27);
/// Set once the first scheduler proxy for a remote pid exists. Until then no link, monitor or
/// signal sender can be a proxy, and the exit and signal paths skip the node table lookup, as
/// erts' local link and monitor nodes never touch distribution data.
static PROXIES_CREATED: AtomicBool = AtomicBool::new(false);

/// Whether `pid` may be a scheduler proxy for a remote pid.
fn may_be_proxy() -> bool {
    PROXIES_CREATED.load(Ordering::Acquire)
}

/// Distribution controller BIFs implemented by this module.
pub(crate) const IMPLEMENTED: &[(&str, &str, u8)] = &[
    ("erlang", "dist_ctrl_get_data", 1),
    ("erlang", "dist_ctrl_put_data", 2),
    ("erlang", "dist_ctrl_get_data_notification", 1),
    ("erlang", "dist_ctrl_input_handler", 2),
    ("erlang", "dist_ctrl_get_opt", 2),
    ("erlang", "dist_ctrl_set_opt", 3),
    ("erlang", "dist_get_stat", 1),
    // `disconnect_node/1` is `net_kernel:disconnect/1` in erlang.erl.
    ("erts_internal", "create_dist_channel", 3),
    ("erts_internal", "dist_spawn_request", 4),
    ("erts_internal", "new_connection", 1),
    ("erts_internal", "abort_pending_connection", 2),
    ("erts_internal", "get_dflags", 0),
    ("erts_internal", "get_creation", 0),
];

pub(crate) fn recognizes(module: &str, function: &str, arity: u8) -> bool {
    crate::natives::listed(IMPLEMENTED, module, function, arity)
}

pub(crate) fn call(
    vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    module: &str,
    function: &str,
    args: crate::natives::NativeArgs<'_>,
) -> Option<Result<Term, VmError>> {
    if !recognizes(module, function, args.len() as u8) {
        return None;
    }
    Some(args.with_values(process, |process, values| {
        dispatch(vm, process, ctx, module, function, values)
    }))
}

fn dispatch(
    vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    module: &str,
    function: &str,
    args: &[Term],
) -> Result<Term, VmError> {
    match (module, function, args.len()) {
        ("erts_internal", "create_dist_channel", 3) => create_channel(process, ctx, args),
        ("erts_internal", "dist_spawn_request", 4) => dist_spawn_request(vm, process, ctx, args),
        ("erts_internal", "new_connection", 1) => new_connection(process, args[0]),
        ("erts_internal", "abort_pending_connection", 2) => {
            abort_pending_connection(process, args[0], args[1])
        }
        ("erts_internal", "get_dflags", 0) => get_dflags(process),
        ("erts_internal", "get_creation", 0) => get_creation(),
        ("erlang", "dist_ctrl_get_data", 1) => get_data(process, ctx, args[0]),
        ("erlang", "dist_ctrl_put_data", 2) => put_data(vm, process, ctx, args[0], args[1]),
        ("erlang", "dist_ctrl_get_data_notification", 1) => get_data_notification(ctx, args[0]),
        ("erlang", "dist_ctrl_input_handler", 2) => input_handler(ctx, args[0], args[1]),
        ("erlang", "dist_ctrl_get_opt", 2) => get_opt(ctx, args[0], args[1]),
        ("erlang", "dist_ctrl_set_opt", 3) => set_opt(ctx, args[0], args[1], args[2]),
        ("erlang", "dist_get_stat", 1) => get_stat(process, ctx, args[0]),
        _ => Err(badarg()),
    }
}

/// Build the `erts_dflags` global literal.
// Port of erts/emulator/beam/dist.c:1155-1185 (init_dist), OTP-29.1.1. Guarded by a `Once`
// because a VM can boot more than once in one process.
pub(crate) fn init_dist_dflags_record() {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        let mut build = arinsal_term::global_literal_allocate(7);
        let record = arinsal_term::TermBuilder::new(&mut build)
            .tuple(&[
                Term::atom(arinsal_term::atoms::ERTS_DFLAGS),
                integer(node_tables::DFLAG_DIST_DEFAULT),
                integer(node_tables::DFLAG_DIST_MANDATORY),
                integer(node_tables::DFLAG_DIST_ADDABLE),
                integer(node_tables::DFLAG_DIST_REJECTABLE),
                integer(node_tables::DFLAG_DIST_STRICT_ORDER),
            ])
            .expect("dflags literal");
        arinsal_term::set_global_dflags_record(build.register(record));
    });
}

/// Port of erts/emulator/beam/dist.c:5543 (erts_internal_get_dflags_0), OTP-29.1.1.
fn get_dflags(process: &mut Process) -> Result<Term, VmError> {
    let mask = !node_tables::test_remove_dflags(None);
    if mask == u64::MAX {
        return Ok(arinsal_term::global_dflags_record());
    }
    tuple(
        process,
        vec![
            Term::atom(arinsal_term::atoms::ERTS_DFLAGS),
            integer(node_tables::DFLAG_DIST_DEFAULT & mask),
            integer(node_tables::DFLAG_DIST_MANDATORY & mask),
            integer(node_tables::DFLAG_DIST_ADDABLE & mask),
            integer(node_tables::DFLAG_DIST_REJECTABLE & mask),
            integer(node_tables::DFLAG_DIST_STRICT_ORDER & mask),
        ],
    )
}

/// Port of erts/emulator/beam/dist.c:5571 (erts_internal_get_creation_0), OTP-29.1.1.
fn get_creation() -> Result<Term, VmError> {
    let creation = node_tables::this_node().1;
    if creation == 0 {
        Ok(Term::atom(arinsal_term::atoms::UNDEFINED))
    } else {
        Ok(integer(u64::from(creation)))
    }
}

/// Port of erts/emulator/beam/dist.c:5588 (erts_internal_new_connection_1), OTP-29.1.1.
fn new_connection(process: &mut Process, node: Term) -> Result<Term, VmError> {
    let OwnedTerm::Atom(ref name) = owned(node)? else {
        return Err(badarg());
    };
    let (conn_id, entry_ref) = node_tables::lock()
        .new_connection(name)
        .ok_or_else(badarg)?;
    let reference = crate::signals::reference(process, entry_ref)?;
    tuple(process, vec![integer(u64::from(conn_id)), reference])
}

/// Port of erts/emulator/beam/dist.c:5693 (erts_internal_abort_pending_connection_2), OTP-29.1.1.
fn abort_pending_connection(process: &Process, node: Term, dhandle: Term) -> Result<Term, VmError> {
    let OwnedTerm::Atom(ref name) = owned(node)? else {
        return Err(badarg());
    };
    let (conn_id, entry_ref) = parse_dhandle(dhandle)?;
    let (result, spawn_downs, mld) = {
        let mut tables = node_tables::lock();
        // The pending connection's spawn-pending monitors are cleaned up with it
        // (dist.c:5681 abort_pending_connection: schedule_con_monitor_link_seq_cleanup).
        let aborts = tables
            .entries
            .get(name.as_str())
            .map(|dep| dep.lock())
            .is_some_and(|entry| {
                entry.entry_ref == entry_ref
                    && entry.connection_id == conn_id
                    && entry.state == node_tables::ConnState::Pending
            });
        let spawn_downs = if aborts {
            take_connection_spawn_requests(&mut tables, name)
        } else {
            Vec::new()
        };
        let mld = if aborts { tables.take_mld(name) } else { None };
        let result = tables
            .abort_pending(name, conn_id, entry_ref)
            .ok_or_else(badarg)?;
        (result, spawn_downs, mld)
    };
    if let Some(runtime) = process.runtime {
        elink::links_connection_down(runtime, mld.clone());
        emon::monitors_connection_down(runtime, mld.as_ref());
        notify_connection_spawn_requests(runtime, spawn_downs)?;
    }
    Ok(boolean(result))
}

fn parse_dhandle(term: Term) -> Result<(u32, u64), VmError> {
    let OwnedTerm::Tuple(ref parts) = owned(term)? else {
        return Err(badarg());
    };
    if parts.len() != 2 {
        return Err(badarg());
    }
    let conn_id = as_u32(&parts[0]).ok_or_else(badarg)?;
    let OwnedTerm::Ref { ids, .. } = &parts[1] else {
        return Err(badarg());
    };
    if ids.len() < 2 {
        return Err(badarg());
    }
    let entry_ref = u64::from(ids[0]) | (u64::from(ids[1]) << 32);
    Ok((conn_id, entry_ref))
}

fn create_channel(
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    args: &[Term],
) -> Result<Term, VmError> {
    // Port of erts/emulator/beam/dist.c:5127 (erts_internal_create_dist_channel_3), OTP-29.1.1.
    let node = owned(args[0])?;
    let OwnedTerm::Atom(node) = &node else {
        return Err(badarg());
    };
    let controller = owned(args[1])?;
    let port_controller = match &controller {
        OwnedTerm::Port { id, .. } => Some(*id),
        OwnedTerm::Pid { .. } => None,
        _ => return Err(badarg()),
    };
    let options = owned(args[2])?;
    let OwnedTerm::Tuple(options) = &options else {
        return Err(badarg());
    };
    if options.len() != 2 {
        return Err(badarg());
    }
    let flags = as_u64(&options[0]).ok_or_else(badarg)?;
    let creation = as_u32(&options[1]).ok_or_else(badarg)?;
    if flags & node_tables::DFLAG_DIST_MANDATORY != node_tables::DFLAG_DIST_MANDATORY {
        return Err(badarg());
    }
    let owner = ctx.pid();
    let visible = flags & 0x01 != 0; // DFLAG_PUBLISHED
    let mut tables = node_tables::lock();
    if !tables.alive || node == &tables.local_name {
        return Err(badarg());
    }
    let local_name = tables.local_name.clone();
    let local_creation = tables.local_creation;
    let busy_limit = tables.distribution_buffer_busy_limit;
    if !tables.entries.contains_key(node) {
        let _ = tables.new_connection(node);
    }
    let dep = tables.entries.get(node).cloned().ok_or_else(badarg)?;
    let mut entry = dep.lock();
    // Accept path may race ahead of new_connection; promote Idle → Pending.
    if entry.state == node_tables::ConnState::Idle {
        entry.connection_id = (entry.connection_id + 1) & 0x00ff_ffff;
        entry.state = node_tables::ConnState::Pending;
        entry.mld = Some(node_tables::new_mld(&entry.name, entry.connection_id));
    }
    if entry.state != node_tables::ConnState::Pending {
        return Err(badarg());
    }
    let conn_id = entry.connection_id;
    let entry_ref = entry.entry_ref;
    let handle = match port_controller {
        Some(port_id) => {
            // Port DistCtrlr: the real inet port is the channel.
            let owns_tcp_port = process.runtime.as_ref().is_some_and(|runtime| {
                runtime
                    .ports
                    .get(port_id)
                    .is_some_and(|handle| handle.tcp_driver_data().is_some())
            });
            if !owns_tcp_port {
                return Err(badarg());
            }
            port_id
        }
        None => NEXT_HANDLE.fetch_add(1, Ordering::Relaxed),
    };
    let mut state = DistState::new(handle, owner, flags);
    state.busy_limit = busy_limit;
    state.port_id = port_controller;
    state.read = 0;
    entry.creation = creation;
    entry.visible = visible;
    entry.connected = true;
    entry.state = node_tables::ConnState::Connected;
    let pending = std::mem::take(&mut entry.pending_out);
    let pending_spawn_requests = std::mem::take(&mut entry.pending_spawn_requests);
    entry.dist = Some(state);
    if let Some(state) = entry.dist.as_mut() {
        state.spawn_requests.extend(pending_spawn_requests);
    }
    // Port of erts/emulator/beam/dist.c:5299 (setup_connection): the controlling port
    // keeps a reference to the entry in its port-specific data.
    if let Some(port_id) = port_controller
        && let Some(port) = process
            .runtime
            .as_ref()
            .and_then(|runtime| runtime.ports.get(port_id))
    {
        port.set_dist_entry(Some(dep.clone()));
    }
    // Flush signals buffered during auto-connect (erts pending queue).
    let mut flush_notify = None;
    if let Some(state) = entry.dist.as_mut() {
        for (control, message) in pending {
            let control = node_tables::relabel_local_node(control, &local_name, local_creation);
            let message =
                message.map(|m| node_tables::relabel_local_node(m, &local_name, local_creation));
            if state.port_id.is_some() {
                let packets = state.encode_term(control, message).map_err(|_| badarg())?;
                state.written = state.written.saturating_add(1);
                enqueue_port_output_no_suspend_locked(state, packets);
            } else {
                state.queue_term(control, message).map_err(|_| badarg())?;
                if state.notify {
                    flush_notify = Some(state.owner);
                    state.notify = false;
                }
            }
        }
    }
    drop(entry);
    let nodeup_events = tables.nodes_monitor_events("nodeup", node, conn_id, visible, None);
    drop(tables);
    // OTP queues the net_kernel controller notification before node monitor
    // messages in setup_connection_epiloge_rwunlock.
    notify_dist_ctrlr(process, ctx, args[1], args[0])?;
    if let Some(port_id) = port_controller {
        flush_port_output(process.runtime.as_ref().ok_or_else(badarg)?, port_id)?;
    }
    send_nodes_monitor_events(process.runtime.as_ref().ok_or_else(badarg)?, nodeup_events)?;
    if let Some(handler) = flush_notify {
        ctx.send(
            handler,
            Message::copy_from(Term::atom(arinsal_term::atoms::DIST_DATA))?,
        )
        .map_err(|error| VmError::Unsupported(format!("dist data notification: {error}")))?;
    }
    let dhandle = dhandle_term(process, conn_id, entry_ref)?;
    tuple(process, vec![Term::atom(arinsal_term::atoms::OK), dhandle])
}

fn notify_dist_ctrlr(
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    ctrlr: Term,
    node: Term,
) -> Result<(), VmError> {
    let runtime = process.runtime.as_ref().ok_or_else(badarg)?;
    let net_kernel = runtime.reg.whereis_proc_str("net_kernel");
    let Some(net_kernel) = net_kernel else {
        return Ok(());
    };
    let msg = TermBuilder::new(&mut process.heap)
        .tuple(&[
            Term::atom(arinsal_term::atoms::DIST_CTRLR),
            ctrlr,
            node,
            ctx.pid().to_term().ok_or_else(badarg)?,
        ])
        .map_err(|_| badarg())?;
    ctx.send(net_kernel, Message::copy_from(msg)?)
        .map_err(|error| VmError::Unsupported(format!("dist_ctrlr notify: {error}")))?;
    Ok(())
}

fn dhandle_term(process: &mut Process, conn_id: u32, entry_ref: u64) -> Result<Term, VmError> {
    let reference = crate::signals::reference(process, entry_ref)?;
    tuple(process, vec![integer(u64::from(conn_id)), reference])
}

fn get_data(
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    handle: Term,
) -> Result<Term, VmError> {
    let bytes = with_dhandle(handle, ctx.pid(), true, |state| {
        let Some(packet) = state.output.pop_front() else {
            return Ok(None);
        };
        state.pending_bytes = state.pending_bytes.saturating_sub(packet.len() as u64);
        state.written = state.written.saturating_add(1);
        Ok(Some((packet, state.get_size)))
    })?;
    let Some((bytes, sized)) = bytes else {
        return Ok(Term::atom(arinsal_term::atoms::NONE));
    };
    let size = bytes.len() as u64;
    let list = from_owned(
        &OwnedTerm::list(vec![OwnedTerm::Binary(bytes)]),
        &mut process.heap,
    )
    .map_err(|_| badarg())?;
    if sized {
        tuple(process, vec![list, integer(size)])
    } else {
        Ok(list)
    }
}

fn put_data(
    vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    handle: Term,
    data: Term,
) -> Result<Term, VmError> {
    let data = owned(data)?;
    let bytes = match &data {
        OwnedTerm::Binary(bytes) => bytes.clone(),
        OwnedTerm::List { elems, tail } if **tail == OwnedTerm::Nil => elems
            .iter()
            .map(|item| as_u32(item).filter(|byte| *byte <= 255).map(|v| v as u8))
            .collect::<Option<Vec<_>>>()
            .ok_or_else(badarg)?,
        OwnedTerm::Nil => Vec::new(),
        _ => return Err(badarg()),
    };
    let local_name = node_tables::this_node().0.to_owned();
    let (handle_id, decoded) = with_dhandle_input(handle, ctx.pid(), |state| {
        state.read = state.read.saturating_add(1);
        let packet = arinsal_etf::decode_dist_packet_indexed(
            &bytes,
            &mut state.incoming_cache,
            |name| {
                arinsal_term::global_atoms()
                    .intern(name)
                    .ok()
                    .map(|atom| atom.0)
            },
            |index| {
                arinsal_term::global_atoms()
                    .text(arinsal_term::Atom(index))
                    .map(str::to_owned)
            },
        )
        .map_err(|_| badarg())?;
        let DistributionHeader::Start { .. } = packet.header else {
            return Ok((state.handle, Vec::new()));
        };
        let decoded = arinsal_etf::decode_dist_payload_with_sizes(&packet).map_err(|_| badarg())?;
        Ok((state.handle, decoded))
    })?;
    route_incoming(vm, process, ctx, handle_id, &local_name, decoded)?;
    Ok(Term::atom(arinsal_term::atoms::OK))
}

fn route_incoming(
    vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    handle: u64,
    local: &str,
    mut terms: Vec<(OwnedTerm, usize)>,
) -> Result<(), VmError> {
    if terms.is_empty() {
        return Ok(());
    }
    let (control, _) = terms.remove(0);
    let local_creation = node_tables::this_node().1;
    let terms: Vec<(OwnedTerm, usize)> = terms
        .into_iter()
        .map(|(term, heap_words)| {
            (
                internalize_local_node(term, local, local_creation),
                heap_words,
            )
        })
        .collect();
    let OwnedTerm::Tuple(parts) = &control else {
        return Err(badarg());
    };
    let Some(OwnedTerm::Int(op)) = parts.first() else {
        return Err(badarg());
    };
    match *op {
        // Port of dist.c:2519 (DOP_SEND), OTP-29.1.1.
        // Port of erts/emulator/beam/dist.c:2509-2539, OTP-29.1.1.
        2 | 22 if parts.len() == 3 => {
            let target = local_pid(&parts[2], local).ok_or_else(badarg)?;
            let from = if *op == 22 {
                remote_proxy(handle, &parts[1])?
            } else {
                target
            };
            for (term, _) in terms {
                let message = from_owned(&term, &mut process.heap).map_err(|_| badarg())?;
                ctx.send_node(
                    target,
                    arinsal_sched::OwnedSignal::new(Event {
                        from,
                        payload: Payload::Message(Message::copy_from(message)?),
                    }),
                )
                .map_err(|error| VmError::Unsupported(format!("dist send: {error}")))?;
            }
        }
        12 | 23 if parts.len() == 4 => {
            let target = local_pid(&parts[2], local).ok_or_else(badarg)?;
            let from = if *op == 23 {
                remote_proxy(handle, &parts[1])?
            } else {
                target
            };
            for (term, _) in terms {
                let message = from_owned(&term, &mut process.heap).map_err(|_| badarg())?;
                ctx.send_node(
                    target,
                    arinsal_sched::OwnedSignal::new(Event {
                        from,
                        payload: Payload::Message(Message::copy_from(message)?),
                    }),
                )
                .map_err(|error| VmError::Unsupported(format!("dist send: {error}")))?;
            }
        }
        // Port of dist.c:2468 (DOP_REG_SEND), OTP-29.1.1.
        6 if parts.len() == 4 => {
            let sender = &parts[1];
            let OwnedTerm::Atom(name) = &parts[3] else {
                return Err(badarg());
            };
            let _ = sender;
            let target = registered_pid(process, name).ok_or_else(badarg)?;
            for (term, _) in terms {
                let message = from_owned(&term, &mut process.heap).map_err(|_| badarg())?;
                ctx.send(target, Message::copy_from(message)?)
                    .map_err(|error| VmError::Unsupported(format!("dist send: {error}")))?;
            }
        }
        // Port of erts/emulator/beam/dist.c (DOP_LINK), OTP-29.1.1.
        1 if parts.len() == 3 => {
            let runtime = process.runtime.as_ref().ok_or_else(badarg)?;
            let from = remote_proxy(handle, &parts[1])?;
            let target = local_pid(&parts[2], local);
            elink::incoming_link(runtime, handle, from, &parts[1], target)?;
        }
        // Port of erts/emulator/beam/dist.c (DOP_EXIT, DOP_PAYLOAD_EXIT, DOP_EXIT2,
        // DOP_PAYLOAD_EXIT2), OTP-29.1.1.
        3 | 8 | 24 | 26 if parts.len() >= 3 => {
            let runtime = process.runtime.as_ref().ok_or_else(badarg)?;
            let from = remote_proxy(handle, &parts[1])?;
            let target = local_pid(&parts[2], local).ok_or_else(badarg)?;
            let reason = if parts.len() == 4 {
                &parts[3]
            } else {
                &terms.first().ok_or_else(badarg)?.0
            };
            let reason = owned_to_message(reason)?;
            elink::incoming_exit(
                runtime,
                from,
                &parts[1],
                target,
                matches!(*op, 3 | 24),
                reason,
            )?;
        }
        // Port of erts/emulator/beam/dist.c (DOP_UNLINK_ID, DOP_UNLINK_ID_ACK), OTP-29.1.1.
        35 | 36 if parts.len() == 4 => {
            let runtime = process.runtime.as_ref().ok_or_else(badarg)?;
            let unlink_id = as_u64(&parts[1]).ok_or_else(badarg)?;
            if *op == 35 && unlink_id == 0 {
                return Err(badarg());
            }
            let from = remote_proxy(handle, &parts[2])?;
            let target = local_pid(&parts[3], local).ok_or_else(badarg)?;
            elink::incoming_unlink(
                runtime,
                handle,
                from,
                unlink_id,
                &parts[2],
                target,
                *op == 36,
            )?;
        }
        // Port of erts/emulator/beam/dist.c (DOP_MONITOR_P, DOP_DEMONITOR_P), OTP-29.1.1.
        19 | 20 if parts.len() == 4 => {
            let runtime = process.runtime.as_ref().ok_or_else(badarg)?;
            let proxy = remote_proxy(handle, &parts[1])?;
            if *op == 19 {
                emon::incoming_monitor(
                    runtime, handle, proxy, &parts[1], &parts[2], &parts[3], local,
                )?;
            } else {
                emon::incoming_demonitor(
                    runtime, handle, proxy, &parts[1], &parts[2], &parts[3], local,
                )?;
            }
        }
        21 | 28 if (parts.len() == 5 && *op == 21) || (parts.len() == 4 && *op == 28) => {
            let target_owned = &parts[1];
            let watcher = local_pid(&parts[2], local).ok_or_else(badarg)?;
            let reference = remote_ref_id(&parts[3]).ok_or_else(badarg)?;
            let reason = if *op == 21 {
                &parts[4]
            } else {
                &terms.first().ok_or_else(badarg)?.0
            };
            // erts_proc_sig_send_dist_monitor_down: the watcher finds the origin half by
            // reference; the sender orders the DOWN behind the dead process' signals.
            let from = match target_owned {
                OwnedTerm::Pid { .. } => remote_proxy(handle, target_owned)?,
                OwnedTerm::Atom(_) => watcher,
                _ => return Err(badarg()),
            };
            let reason = if *op == 21 {
                from_owned(reason, &mut process.heap).map_err(|_| badarg())?
            } else {
                from_owned(&terms.first().ok_or_else(badarg)?.0, &mut process.heap)
                    .map_err(|_| badarg())?
            };
            publish_remote_signal(
                process,
                from,
                watcher,
                Signal::MonitorDown {
                    reference,
                    reason: Box::new(Message::copy_from(reason)?),
                },
            )?;
        }
        33 | 34 if (parts.len() == 3 && *op == 33) || (parts.len() == 4 && *op == 34) => {
            let OwnedTerm::Ref { .. } = &parts[2] else {
                return Err(badarg());
            };
            let reference = remote_ref_id(&parts[2]).ok_or_else(badarg)?;
            if let Some(target) = remote_alias_pid(&parts[2]) {
                for (term, _) in terms {
                    let message = from_owned(&term, &mut process.heap).map_err(|_| badarg())?;
                    ctx.send(target, Message::copy_from(message)?.with_alias(reference))
                        .map_err(|error| {
                            VmError::Unsupported(format!("dist alias send: {error}"))
                        })?;
                }
            }
        }
        29 if parts.len() == 6 && terms.len() == 1 => {
            handle_spawn_request(vm, process, ctx, handle, parts, &terms[0].0)?;
        }
        31 | 32 if (parts.len() == 5 && *op == 31) || (parts.len() == 6 && *op == 32) => {
            // Port of erts/emulator/beam/dist.c:3017-3124 (DOP_SPAWN_REPLY), OTP-29.1.1.
            let runtime = process.runtime.as_ref().ok_or_else(badarg)?;
            dist_spawn_reply(runtime, handle, parts)?;
        }
        30 | 31 => {
            return Err(VmError::Unsupported(format!(
                "distribution spawn control {op}"
            )));
        }
        // Unknown controls are malformed under OTP's negotiated protocol.
        _ => {
            return Err(VmError::Unsupported(format!(
                "unsupported distribution control {op}"
            )));
        }
    }
    Ok(())
}

fn remote_proxy(handle: u64, remote: &OwnedTerm) -> Result<Pid, VmError> {
    let OwnedTerm::Pid {
        node,
        id,
        serial,
        creation,
    } = remote
    else {
        return Err(badarg());
    };
    let key = (*id, *serial, *creation);
    let local_creation = node_tables::this_node().1;
    let dep = node_tables::find_dist_entry(node).ok_or_else(badarg)?;
    let mut entry = dep.lock();
    let state = entry
        .dist
        .as_mut()
        .filter(|state| state.handle == handle)
        .ok_or_else(badarg)?;
    if let Some(pid) = state.remote_pids.get(&key) {
        return Ok(*pid);
    }
    let pid = Pid::new(
        NEXT_REMOTE_PID.fetch_add(1, Ordering::Relaxed) & ((1 << 28) - 1),
        local_creation,
    );
    PROXIES_CREATED.store(true, Ordering::Release);
    state.remote_pids.insert(key, pid);
    state.proxy_to_remote.insert(pid, remote.clone());
    Ok(pid)
}

/// Resolve a scheduler proxy to the external PID used in a remote DOWN tuple.
// Port of erts/emulator/beam/dist.c:2689-2716 (DOP_MONITOR_P_EXIT), OTP-29.1.1.
pub(crate) fn remote_pid_term(process: &mut Process, proxy: Pid) -> Result<Option<Term>, VmError> {
    if !may_be_proxy() {
        return Ok(None);
    }
    let remote = {
        let tables = node_tables::lock();
        tables
            .entries
            .values()
            .map(|dep| dep.lock())
            .find_map(|entry| entry.dist.as_ref()?.proxy_to_remote.get(&proxy).cloned())
    };
    remote
        .map(|pid| from_owned(&pid, &mut process.heap).map_err(|_| badarg()))
        .transpose()
}

fn publish_remote_signal(
    process: &Process,
    from: Pid,
    to: Pid,
    signal: Signal<Message>,
) -> Result<(), VmError> {
    let runtime = process.runtime.as_ref().ok_or_else(badarg)?;
    runtime
        .scheduler()?
        .signal(from, to, signal)
        .map_err(|error| VmError::Unsupported(format!("incoming dist signal: {error}")))
}

fn queue_remote_control(
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    handle: u64,
    control: OwnedTerm,
) -> Result<(), VmError> {
    let (local_name, local_creation) = node_tables::this_node();
    let control = node_tables::relabel_local_node(control, local_name, local_creation);
    let dep = node_tables::lock()
        .dep_by_handle(handle)
        .ok_or_else(badarg)?;
    let mut entry = dep.lock();
    let state = entry.dist.as_mut().ok_or_else(badarg)?;
    if let Some(port_id) = state.port_id {
        let packets = state.encode_term(control, None).map_err(|_| badarg())?;
        state.written = state.written.saturating_add(1);
        enqueue_port_output_no_suspend_locked(state, packets);
        drop(entry);
        let runtime = process.runtime.ok_or_else(badarg)?;
        return flush_port_output(runtime, port_id);
    }
    state.queue_term(control, None).map_err(|_| badarg())?;
    let notify = state.notify.then_some(state.owner);
    state.notify = false;
    drop(entry);
    if let Some(handler) = notify {
        ctx.send(
            handler,
            Message::copy_from(Term::atom(arinsal_term::atoms::DIST_DATA))?,
        )
        .map_err(|error| VmError::Unsupported(format!("dist data notification: {error}")))?;
    }
    let _ = process;
    Ok(())
}

fn remote_ref_id(reference: &OwnedTerm) -> Option<u64> {
    let OwnedTerm::Ref { ids, .. } = reference else {
        return None;
    };
    if ids.len() >= 3 {
        return Some(arinsal_bifs::ordinary_ref_key([ids[0], ids[1], ids[2]]));
    }
    let mut value = 0_u64;
    for (index, id) in ids.iter().take(2).enumerate() {
        value |= u64::from(*id) << (index * 32);
    }
    Some(value)
}

fn remote_alias_pid(reference: &OwnedTerm) -> Option<Pid> {
    let OwnedTerm::Ref {
        node,
        creation,
        ids,
    } = reference
    else {
        return None;
    };
    // Port of erts_pid_ref_lookup (erl_bif_unique.h), OTP-29.1.1: ETF carries the
    // reference-number PID marker and creator PID, and only a local creator is routable.
    let (local_node, local_creation) = arinsal_term::this_node();
    if ids.len() != 5
        || ids[1] & (1 << 16) == 0
        || *creation != local_creation
        || global_atoms().text(local_node)? != node
    {
        return None;
    }
    Some(Pid::from_data(Term::local_pid_ref_data_from_words(
        ids[3], ids[4],
    )?))
}

fn registered_pid(process: &Process, name: &str) -> Option<Pid> {
    let runtime = process.runtime.as_ref()?;
    runtime.reg.whereis_proc_str(name)
}

/// Queue one remote signal packet using the destination's negotiated atom cache.
///
/// Port of erts/emulator/beam/dist.c (`erts_dsig_prepare` + pending queue), OTP-29.1.1.
/// When the peer is not yet connected, auto-connects via `{auto_connect, Node, DHandle}`
/// to `net_kernel` and buffers the signal until `create_dist_channel` succeeds.
pub(crate) fn queue_outgoing(
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    node: &str,
    control: OwnedTerm,
    message: Option<OwnedTerm>,
) -> Result<(), VmError> {
    match queue_outgoing_with_options(process, ctx, node, control, message, true, true, None)? {
        DistSendResult::Queued => Ok(()),
        DistSendResult::NotConnected | DistSendResult::WouldSuspend => Err(badarg()),
    }
}

/// The outcome of [`dsig_prepare`] (`ERTS_DSIG_PREP_*`, without the busy states).
pub(crate) enum DsigPrepare {
    /// `ERTS_DSIG_PREP_NOT_ALIVE`: this node is not distributed, or the auto-connect failed.
    NotAlive,
    /// `ERTS_DSIG_PREP_NOT_CONNECTED`: the connection is going down.
    NotConnected,
    /// `ERTS_DSIG_PREP_PENDING` or `ERTS_DSIG_PREP_CONNECTED`: connection `connection_id`
    /// with its `dep->mld`.
    Connected {
        connection_id: u32,
        mld: std::sync::Arc<crate::monitor_link::MonLnkDist>,
    },
}

/// Port of erts/emulator/beam/dist.c (erts_dsig_prepare with `connect`), OTP-29.1.1: the
/// state of the connection to `node`, set up with `erts_auto_connect` when idle. A signal
/// prepared here goes out with [`queue_outgoing_on`], which drops it when the connection is
/// no longer `connection_id`, as `erts_dsig_send` does.
pub(crate) fn dsig_prepare(
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    node: &str,
) -> Result<DsigPrepare, VmError> {
    loop {
        let (conn_id, entry_ref) = {
            if !node_tables::is_alive() {
                return Ok(DsigPrepare::NotAlive);
            }
            if node == node_tables::this_node().0 {
                return Err(badarg());
            }
            // The table lock covers the lookup only; the state is read under the entry lock.
            let dep = node_tables::find_dist_entry(node);
            match dep.as_ref().map(|dep| dep.lock()) {
                Some(entry)
                    if matches!(
                        entry.state,
                        node_tables::ConnState::Connected | node_tables::ConnState::Pending
                    ) =>
                {
                    return Ok(match entry.mld.clone() {
                        Some(mld) => DsigPrepare::Connected {
                            connection_id: entry.connection_id,
                            mld,
                        },
                        None => DsigPrepare::NotConnected,
                    });
                }
                Some(entry) if entry.state == node_tables::ConnState::Exiting => {
                    return Ok(DsigPrepare::NotConnected);
                }
                _ => {}
            }
            node_tables::lock()
                .new_connection(node)
                .ok_or_else(badarg)?
        };
        if !notify_auto_connect(process, ctx, node, conn_id, entry_ref)? {
            return Ok(DsigPrepare::NotAlive);
        }
    }
}

/// Queue a signal prepared by [`dsig_prepare`] on connection `connection_id`; a signal for a
/// connection that is gone is dropped (dist.c erts_dsig_send: "Not the same connection").
pub(crate) fn queue_outgoing_on(
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    node: &str,
    connection_id: u32,
    control: OwnedTerm,
    message: Option<OwnedTerm>,
) -> Result<(), VmError> {
    match queue_outgoing_with_options(
        process,
        ctx,
        node,
        control,
        message,
        false,
        true,
        Some(connection_id),
    )? {
        DistSendResult::Queued | DistSendResult::NotConnected => Ok(()),
        DistSendResult::WouldSuspend => Err(badarg()),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DistSendResult {
    Queued,
    NotConnected,
    WouldSuspend,
}

// Port of erts/emulator/beam/dist.c:3216-3280 (erts_dsig_prepare), OTP-29.1.1.
#[allow(clippy::too_many_arguments)]
fn queue_outgoing_with_options(
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    node: &str,
    control: OwnedTerm,
    message: Option<OwnedTerm>,
    connect: bool,
    suspend: bool,
    expect_connection: Option<u32>,
) -> Result<DistSendResult, VmError> {
    if !node_tables::is_alive() {
        return Ok(DistSendResult::NotConnected);
    }
    let (local_name, local_creation) = node_tables::this_node();
    if node == local_name {
        return Err(badarg());
    }
    let control = node_tables::relabel_local_node(control, local_name, local_creation);
    let message = message.map(|m| node_tables::relabel_local_node(m, local_name, local_creation));
    // The table lock is held for the membership lookup only (find_dist_entry); the send
    // itself runs under the entry's own lock, as erts_dsig_prepare/erts_dsig_send do.
    let mut dep = node_tables::find_dist_entry(node);
    // Port of dist.c:3260 (erts_auto_connect on Idle), OTP-29.1.1.
    let was_idle = match dep.as_ref().map(|dep| dep.lock()) {
        Some(entry) if entry.state == node_tables::ConnState::Exiting => {
            return Ok(DistSendResult::NotConnected);
        }
        Some(entry) => {
            if let Some(expected) = expect_connection
                && entry.connection_id != expected
            {
                return Ok(DistSendResult::NotConnected);
            }
            entry.state == node_tables::ConnState::Idle
        }
        None if expect_connection.is_some() => return Ok(DistSendResult::NotConnected),
        None => true,
    };
    if was_idle && !connect {
        return Ok(DistSendResult::NotConnected);
    }
    let mut conn = None;
    if was_idle {
        let mut tables = node_tables::lock();
        conn = Some(tables.new_connection(node).ok_or_else(badarg)?);
        dep = tables.entries.get(node).cloned();
    }
    let dep = dep.ok_or_else(badarg)?;
    let mut entry = dep.lock();
    let (conn_id, entry_ref) = conn.unwrap_or((entry.connection_id, entry.entry_ref));

    if entry.state == node_tables::ConnState::Exiting {
        return Ok(DistSendResult::NotConnected);
    }

    if entry.connected
        && let Some(state) = entry.dist.as_mut().filter(|state| state.handle != 0)
    {
        // Port of erts/emulator/beam/dist.c:3280, OTP-29.1.1.
        if !suspend && state.busy {
            return Ok(DistSendResult::WouldSuspend);
        }
        if let Some(port_id) = state.port_id {
            let packets = state.encode_term(control, message).map_err(|_| badarg())?;
            state.written = state.written.saturating_add(1);
            let should_suspend = if suspend {
                enqueue_port_packets_locked(process, state, ctx.pid(), packets)
            } else {
                enqueue_port_output_no_suspend_locked(state, packets);
                false
            };
            drop(entry);
            if suspend {
                finish_port_enqueue(process, ctx.pid(), port_id, should_suspend)?;
            } else {
                flush_port_output(process.runtime.as_ref().ok_or_else(badarg)?, port_id)?;
            }
            return Ok(DistSendResult::Queued);
        }
        state.queue_term(control, message).map_err(|_| badarg())?;
        if state.pending_bytes >= state.busy_limit {
            state.busy = true;
        }
        let notify = state.notify.then_some(state.owner);
        state.notify = false;
        drop(entry);
        if let Some(handler) = notify {
            ctx.send(
                handler,
                Message::copy_from(Term::atom(arinsal_term::atoms::DIST_DATA))?,
            )
            .map_err(|error| VmError::Unsupported(format!("dist data notification: {error}")))?;
        }
        let _ = process;
        return Ok(DistSendResult::Queued);
    }

    // Pending (or Connected without a controller yet): buffer until channel is up.
    entry.pending_out.push_back((control, message));
    let notify = was_idle.then(|| (node.to_string(), conn_id, entry_ref));
    drop(entry);
    if let Some((node, conn_id, entry_ref)) = notify
        && !notify_auto_connect(process, ctx, &node, conn_id, entry_ref)?
    {
        // dist.c erts_dsig_prepare: a failed auto-connect is ERTS_DSIG_PREP_NOT_ALIVE; the
        // aborted connection dropped the queued signal.
        return Ok(DistSendResult::NotConnected);
    }
    Ok(DistSendResult::Queued)
}

/// Port of erts/emulator/beam/dist.c:5713 (erts_auto_connect), OTP-29.1.1. Without a
/// `net_kernel` the pending connection is aborted (dist.c abort_pending_connection, with
/// schedule_con_monitor_link_seq_cleanup of its `mld`) and the result is `false`.
fn notify_auto_connect(
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    node: &str,
    conn_id: u32,
    entry_ref: u64,
) -> Result<bool, VmError> {
    let runtime = process.runtime.ok_or_else(badarg)?;
    let Some(net_kernel) = runtime.reg.whereis_proc_str("net_kernel") else {
        let mld = {
            let mut tables = node_tables::lock();
            let aborts = tables
                .entries
                .get(node)
                .map(|dep| dep.lock())
                .is_some_and(|entry| {
                    entry.entry_ref == entry_ref
                        && entry.connection_id == conn_id
                        && entry.state == node_tables::ConnState::Pending
                });
            let (mld, spawn_downs) = if aborts {
                (
                    tables.take_mld(node),
                    take_connection_spawn_requests(&mut tables, node),
                )
            } else {
                (None, Vec::new())
            };
            let _ = tables.abort_pending(node, conn_id, entry_ref);
            (mld, spawn_downs)
        };
        let (mld, spawn_downs) = mld;
        elink::links_connection_down(runtime, mld.clone());
        emon::monitors_connection_down(runtime, mld.as_ref());
        notify_connection_spawn_requests(runtime, spawn_downs)?;
        return Ok(false);
    };
    let (local_name, local_creation) = {
        let tables = node_tables::lock();
        (tables.local_name.clone(), tables.local_creation)
    };
    let msg = OwnedTerm::tuple(vec![
        OwnedTerm::Atom("auto_connect".into()),
        OwnedTerm::Atom(node.into()),
        OwnedTerm::tuple(vec![
            OwnedTerm::Int(i64::from(conn_id)),
            OwnedTerm::Ref {
                node: local_name,
                creation: local_creation,
                ids: arinsal_bifs::ordinary_ref_words(entry_ref).to_vec(),
            },
        ]),
    ]);
    ctx.send(net_kernel, owned_to_message(&msg)?)
        .map_err(|error| VmError::Unsupported(format!("auto_connect notify: {error}")))?;
    Ok(true)
}

/// Ingest one length-delimited distribution packet from a DistCtrlr inet port.
///
/// Port of erts/emulator/beam/dist.c:2017 (erts_net_message), OTP-29.1.1.
pub(crate) fn ingest_port_data(
    runtime: &'static crate::process::Runtime,
    dep: &node_tables::DistEntry,
    port_id: u64,
    bytes: &[u8],
) -> Result<(), VmError> {
    // A zero-length body is a distribution tick (packet header length 0).
    if bytes.is_empty() {
        return Ok(());
    }
    let (local_name, _) = node_tables::this_node();
    // The port's own `ERTS_PRTSD_DIST_ENTRY` reference: only the entry lock is taken.
    let (handle, decoded) = {
        let mut entry = dep.lock();
        let state = entry
            .dist
            .as_mut()
            .filter(|state| state.port_id == Some(port_id))
            .ok_or_else(badarg)?;
        state.read = state.read.saturating_add(1);
        let packet = arinsal_etf::decode_dist_packet_indexed(
            bytes,
            &mut state.incoming_cache,
            |name| {
                arinsal_term::global_atoms()
                    .intern(name)
                    .ok()
                    .map(|atom| atom.0)
            },
            |index| {
                arinsal_term::global_atoms()
                    .text(arinsal_term::Atom(index))
                    .map(str::to_owned)
            },
        )
        .map_err(|_| badarg())?;
        let Some(packet) = reassemble_port_fragment(state, packet)? else {
            return Ok(());
        };
        let decoded = arinsal_etf::decode_dist_payload_with_sizes(&packet).map_err(|_| badarg())?;
        (state.handle, decoded)
    };
    route_incoming_port(runtime, handle, local_name, decoded)
}

/// Reassemble one ordered OTP distribution signal before decoding its ETF terms.
///
/// Port of erts/emulator/beam/dist.c:2119-2165, OTP-29.1.1.
fn reassemble_port_fragment(
    state: &mut node_tables::DistState,
    packet: arinsal_etf::DistributionPacket,
) -> Result<Option<arinsal_etf::DistributionPacket>, VmError> {
    match &packet.header {
        DistributionHeader::Start {
            sequence_id: None,
            fragment_id: None,
            ..
        } => Ok(Some(packet)),
        DistributionHeader::Start {
            sequence_id: Some(sequence_id),
            fragment_id: Some(fragment_id),
            ..
        } if *fragment_id > 0 => {
            if state.flags & node_tables::DFLAG_FRAGMENTS == 0 {
                return Err(badarg());
            }
            if *fragment_id == 1 {
                return Ok(Some(packet));
            }
            let sequence_id = *sequence_id;
            let fragment_id = *fragment_id;
            if state
                .incoming_fragments
                .insert(
                    sequence_id,
                    node_tables::IncomingDistFragment {
                        next_fragment_id: fragment_id - 1,
                        packet,
                    },
                )
                .is_some()
            {
                return Err(badarg());
            }
            Ok(None)
        }
        DistributionHeader::Continuation {
            sequence_id,
            fragment_id,
        } => {
            if state.flags & node_tables::DFLAG_FRAGMENTS == 0 {
                return Err(badarg());
            }
            let sequence_id = *sequence_id;
            let fragment_id = *fragment_id;
            let Some(fragment) = state.incoming_fragments.get_mut(&sequence_id) else {
                return Err(badarg());
            };
            if fragment.next_fragment_id != fragment_id || fragment_id == 0 {
                state.incoming_fragments.remove(&sequence_id);
                return Err(badarg());
            }
            fragment.packet.payload.extend_from_slice(&packet.payload);
            if fragment_id > 1 {
                fragment.next_fragment_id -= 1;
                return Ok(None);
            }
            Ok(state
                .incoming_fragments
                .remove(&sequence_id)
                .map(|fragment| fragment.packet))
        }
        _ => Err(badarg()),
    }
}

/// Tear down a port-controlled connection after the peer socket closes.
pub(crate) fn port_connection_closed(
    runtime: &crate::process::Runtime,
    port: &crate::port::PortHandle,
) -> Result<(), VmError> {
    let port_id = port.id();
    // Port of erts/emulator/beam/io.c:3911-3917 (terminate_port): the port drops its
    // `ERTS_PRTSD_DIST_ENTRY` reference.
    let Some(dep) = port.set_dist_entry(None) else {
        return Ok(());
    };
    let node = dep.sysname.clone();
    let (watchers, node_events, spawn_downs, mld) = {
        let mut tables = node_tables::lock();
        let (connection_id, visible) = {
            let entry = dep.lock();
            // Port of erts/emulator/beam/dist.c:3599-3611 (discard output from an obsolete
            // connection), OTP-29.1.1.
            if !entry
                .dist
                .as_ref()
                .is_some_and(|state| state.port_id == Some(port_id))
            {
                return Ok(());
            }
            (entry.connection_id, entry.visible)
        };
        let spawn_downs = take_connection_spawn_requests(&mut tables, &node);
        let mld = tables.take_mld(&node);
        let watchers = tables.disconnect(&node);
        let events = tables.nodes_monitor_events(
            "nodedown",
            &node,
            connection_id,
            visible,
            Some("connection_closed"),
        );
        (watchers, events, spawn_downs, mld)
    };
    elink::links_connection_down(runtime, mld.clone());
    emon::monitors_connection_down(runtime, mld.as_ref());
    notify_node_watchers(runtime, &node, watchers)?;
    notify_connection_spawn_requests(runtime, spawn_downs)?;
    send_nodes_monitor_events(runtime, node_events)
}

/// Kill a connected distribution entry that has no port controller.
/// Port of erts/emulator/beam/dist.c:4788-4811 (`erts_kill_dist_connection`), OTP-29.1.1.
pub(crate) fn kill_connection(
    runtime: &crate::process::Runtime,
    node: &str,
    connection_id: u32,
) -> Result<bool, VmError> {
    let (watchers, node_events, spawn_downs, mld) = {
        let mut tables = node_tables::lock();
        let Some(entry) = tables.entries.get(node).map(|dep| dep.lock()) else {
            return Ok(false);
        };
        if !entry.connected || entry.connection_id != connection_id {
            return Ok(false);
        }
        let visible = entry.visible;
        drop(entry);
        let spawn_downs = take_connection_spawn_requests(&mut tables, node);
        let mld = tables.take_mld(node);
        let watchers = tables.disconnect(node);
        let events =
            tables.nodes_monitor_events("nodedown", node, connection_id, visible, Some("killed"));
        (watchers, events, spawn_downs, mld)
    };
    elink::links_connection_down(runtime, mld.clone());
    emon::monitors_connection_down(runtime, mld.as_ref());
    notify_node_watchers(runtime, node, watchers)?;
    notify_connection_spawn_requests(runtime, spawn_downs)?;
    send_nodes_monitor_events(runtime, node_events)?;
    Ok(true)
}

fn notify_node_watchers(
    runtime: &crate::process::Runtime,
    node: &str,
    watchers: Vec<node_tables::NodeMonitor>,
) -> Result<(), VmError> {
    let node_atom = crate::atom_cache::put(node);
    let sched = runtime.scheduler()?;
    for watcher in watchers {
        let mut heap = arinsal_term::ProcessHeap::with_words(16);
        let term = TermBuilder::new(&mut heap)
            .tuple(&[Term::atom(arinsal_term::atoms::NODEDOWN), node_atom])
            .map_err(|_| badarg())?;
        let message = Message::copy_from(term)?;
        let _ = sched.send(watcher.pid, watcher.pid, message);
    }
    Ok(())
}

/// The spawn-pending monitors of a connection that goes down, taken out of the tables before
/// the connection state is dropped.
///
/// Port of erts/emulator/beam/dist.c (monitor_connection_down for monitors with
/// ERTS_ML_FLG_SPAWN_PENDING, and dist.c:326 dist_pend_spawn_exit_connection_down), OTP-29.1.1.
fn take_connection_spawn_requests(
    tables: &mut node_tables::NodeTables,
    node: &str,
) -> Vec<(u64, node_tables::SpawnRequest)> {
    let Some(mut entry) = tables.entries.get(node).map(|dep| dep.lock()) else {
        return Vec::new();
    };
    let mut requests = std::mem::take(&mut entry.pending_spawn_requests);
    if let Some(state) = entry.dist.as_mut() {
        requests.append(&mut state.spawn_requests);
    }
    requests.into_iter().collect()
}

/// A spawn request whose connection went down, as its parent receives it: the monitor-down
/// signal of a spawn-pending monitor (erl_proc_sig_queue.c:4864 convert_to_down_message),
/// queued as a [`Signal::DistSpawnReply`].
pub(crate) struct DistSpawnNoconnection {
    id: u64,
    tag: OwnedTerm,
    /// ERTS_ML_FLG_SPAWN_ABANDONED or ERTS_ML_FLG_SPAWN_NO_EMSG: no message.
    quiet: bool,
}

/// Tell the parents of the spawn requests of a lost connection: a live parent gets
/// `{Tag, Ref, error, noconnection}`; a parent suspended in its exit is resumed by dropping
/// its waiter.
fn notify_connection_spawn_requests(
    runtime: &crate::process::Runtime,
    requests: Vec<(u64, node_tables::SpawnRequest)>,
) -> Result<(), VmError> {
    if requests.is_empty() {
        return Ok(());
    }
    let scheduler = runtime.scheduler()?;
    for (id, request) in requests {
        if request.parent_exiting {
            // dist_pend_spawn_exit_connection_down: erts_resume of a waiting parent.
            drop(request);
            continue;
        }
        let payload: std::sync::Arc<dyn std::any::Any + Send + Sync> =
            std::sync::Arc::new(DistSpawnNoconnection {
                id,
                tag: request.tag.clone(),
                quiet: request.abandoned || request.no_error_msg,
            });
        // A parent that is gone needs nothing more.
        let _ = scheduler.signal(
            request.caller,
            request.caller,
            Signal::DistSpawnReply(arinsal_sched::SharedPayload(payload)),
        );
    }
    Ok(())
}

/// The `{Tag, Ref, error, noconnection}` message of a spawn request whose connection went
/// down, or `None` when the request was abandoned or error replies are off.
///
/// Port of erts/emulator/beam/erl_proc_sig_queue.c:4864-4920 (convert_to_down_message for a
/// spawn-pending monitor), OTP-29.1.1.
pub(crate) fn spawn_noconnection_message(
    process: &mut Process,
    down: &DistSpawnNoconnection,
) -> Result<Option<Term>, VmError> {
    if down.quiet {
        return Ok(None);
    }
    let reference = crate::signals::reference(process, down.id)?;
    let tag = from_owned(&down.tag, &mut process.heap).map_err(|_| badarg())?;
    tuple(
        process,
        vec![
            tag,
            reference,
            Term::atom(arinsal_term::atoms::ERROR),
            Term::atom(arinsal_term::atoms::NOCONNECTION),
        ],
    )
    .map(Some)
}

fn send_nodes_monitor_events(
    runtime: &crate::process::Runtime,
    events: Vec<node_tables::NodesMonitorEvent>,
) -> Result<(), VmError> {
    let scheduler = runtime.scheduler()?;
    for event in events {
        let mut heap = arinsal_term::VecHeap::new();
        let term = arinsal_term::from_owned(&event.message, &mut heap)
            .map_err(|error| VmError::Unsupported(format!("node monitor event: {error:?}")))?;
        scheduler
            .send(event.pid, event.pid, Message::copy_from(term)?)
            .map_err(|error| VmError::Unsupported(format!("node monitor delivery: {error}")))?;
    }
    Ok(())
}

fn route_incoming_port(
    runtime: &'static crate::process::Runtime,
    handle: u64,
    local: &str,
    mut terms: Vec<(OwnedTerm, usize)>,
) -> Result<(), VmError> {
    if terms.is_empty() {
        return Ok(());
    }
    let (control, control_heap_words) = terms.remove(0);
    let OwnedTerm::Tuple(parts) = &control else {
        return Err(badarg());
    };
    let Some(OwnedTerm::Int(op)) = parts.first() else {
        return Err(badarg());
    };
    let sched = runtime.scheduler()?;
    match *op {
        // Port of erts/emulator/beam/dist.c:2509-2539, OTP-29.1.1.
        2 | 22 if parts.len() == 3 => {
            let target = local_pid(&parts[2], local).ok_or_else(badarg)?;
            let from = if *op == 22 {
                remote_proxy(handle, &parts[1])?
            } else {
                target
            };
            for (term, heap_words) in terms {
                let message = owned_to_message_with_heap_size(&term, heap_words)?;
                sched
                    .send(from, target, message)
                    .map_err(|error| VmError::Unsupported(format!("dist send: {error}")))?;
            }
        }
        12 | 23 if parts.len() == 4 => {
            let target = local_pid(&parts[2], local).ok_or_else(badarg)?;
            let from = if *op == 23 {
                remote_proxy(handle, &parts[1])?
            } else {
                target
            };
            for (term, heap_words) in terms {
                let message = owned_to_message_with_heap_size(&term, heap_words)?;
                sched
                    .send(from, target, message)
                    .map_err(|error| VmError::Unsupported(format!("dist send: {error}")))?;
            }
        }
        6 if parts.len() == 4 => {
            let OwnedTerm::Atom(name) = &parts[3] else {
                return Err(badarg());
            };
            let target = runtime.reg.whereis_proc_str(name).ok_or_else(badarg)?;
            for (term, heap_words) in terms {
                let message = owned_to_message_with_heap_size(&term, heap_words)?;
                sched
                    .send(target, target, message)
                    .map_err(|error| VmError::Unsupported(format!("dist send: {error}")))?;
            }
        }
        // Port of erts/emulator/beam/dist.c (DOP_LINK), OTP-29.1.1.
        1 if parts.len() == 3 => {
            let from = remote_proxy(handle, &parts[1])?;
            let target = local_pid(&parts[2], local);
            elink::incoming_link(runtime, handle, from, &parts[1], target)?;
        }
        // Port of erts/emulator/beam/dist.c (DOP_EXIT, DOP_PAYLOAD_EXIT, DOP_EXIT2,
        // DOP_PAYLOAD_EXIT2), OTP-29.1.1. Payload exits carry the reason outside the
        // control tuple so large reasons can use fragmented distribution frames.
        3 | 8 | 24 | 26 if parts.len() >= 3 => {
            let from = remote_proxy(handle, &parts[1])?;
            let target = local_pid(&parts[2], local).ok_or_else(badarg)?;
            let reason = if parts.len() == 4 {
                &parts[3]
            } else {
                &terms.first().ok_or_else(badarg)?.0
            };
            let heap_words = if parts.len() == 4 {
                control_heap_words
            } else {
                terms.first().ok_or_else(badarg)?.1
            };
            let reason = owned_to_message_with_heap_size(reason, heap_words)?;
            elink::incoming_exit(
                runtime,
                from,
                &parts[1],
                target,
                matches!(*op, 3 | 24),
                reason,
            )?;
        }
        // Port of erts/emulator/beam/dist.c (DOP_UNLINK_ID, DOP_UNLINK_ID_ACK), OTP-29.1.1.
        35 | 36 if parts.len() == 4 => {
            let unlink_id = as_u64(&parts[1]).ok_or_else(badarg)?;
            if *op == 35 && unlink_id == 0 {
                return Err(badarg());
            }
            let from = remote_proxy(handle, &parts[2])?;
            let target = local_pid(&parts[3], local).ok_or_else(badarg)?;
            elink::incoming_unlink(
                runtime,
                handle,
                from,
                unlink_id,
                &parts[2],
                target,
                *op == 36,
            )?;
        }
        // Port of dist.c:2341 (DOP_MONITOR_P); ToProc may be a pid or registered name.
        19 | 20 if parts.len() == 4 => {
            let proxy = remote_proxy(handle, &parts[1])?;
            if *op == 19 {
                emon::incoming_monitor(
                    runtime, handle, proxy, &parts[1], &parts[2], &parts[3], local,
                )?;
            } else {
                emon::incoming_demonitor(
                    runtime, handle, proxy, &parts[1], &parts[2], &parts[3], local,
                )?;
            }
        }
        // Port of dist.c (DOP_MONITOR_P_EXIT / payload exit).
        21 | 28 if (parts.len() == 5 && *op == 21) || (parts.len() == 4 && *op == 28) => {
            let target_owned = &parts[1];
            let watcher = local_pid(&parts[2], local).ok_or_else(badarg)?;
            let reference = remote_ref_id(&parts[3]).ok_or_else(badarg)?;
            let reason = if *op == 21 {
                &parts[4]
            } else {
                &terms.first().ok_or_else(badarg)?.0
            };
            // erts_proc_sig_send_dist_monitor_down: the watcher finds the origin half by
            // reference; the sender orders the DOWN behind the dead process' signals.
            let from = match target_owned {
                OwnedTerm::Pid { .. } => remote_proxy(handle, target_owned)?,
                OwnedTerm::Atom(_) => watcher,
                _ => return Err(badarg()),
            };
            let heap_words = if *op == 21 {
                control_heap_words
            } else {
                terms.first().ok_or_else(badarg)?.1
            };
            let reason_msg = owned_to_message_with_heap_size(reason, heap_words)?;
            sched
                .signal(
                    from,
                    watcher,
                    Signal::MonitorDown {
                        reference,
                        reason: Box::new(reason_msg),
                    },
                )
                .map_err(|error| VmError::Unsupported(format!("incoming dist signal: {error}")))?;
        }
        // Port of dist.c (DOP_ALIAS_SEND / DOP_ALIAS_SEND_TT).
        33 | 34 if (parts.len() == 3 && *op == 33) || (parts.len() == 4 && *op == 34) => {
            let OwnedTerm::Ref { .. } = &parts[2] else {
                return Err(badarg());
            };
            let reference = remote_ref_id(&parts[2]).ok_or_else(badarg)?;
            if let Some(target) = remote_alias_pid(&parts[2]) {
                for (term, heap_words) in terms {
                    let message =
                        owned_to_message_with_heap_size(&term, heap_words)?.with_alias(reference);
                    sched.send(target, target, message).map_err(|error| {
                        VmError::Unsupported(format!("dist alias send: {error}"))
                    })?;
                }
            }
        }
        // Port of dist.c:2580 (DOP_ALTACT_SIG_SEND), OTP-29.1.1.
        // `{37, Flags, SenderPid, To}` — alias bit delivers like DOP_ALIAS_SEND.
        37 if parts.len() >= 4 => {
            let flags = as_u64(&parts[1]).ok_or_else(badarg)?;
            const FLG_PRIO: u64 = 1 << 0;
            const FLG_ALIAS: u64 = 1 << 2;
            const FLG_NAME: u64 = 1 << 3;
            const FLG_EXIT: u64 = 1 << 4;
            let from = remote_proxy(handle, &parts[2])?;
            if flags & FLG_ALIAS != 0 {
                let reference = remote_ref_id(&parts[3]).ok_or_else(badarg)?;
                if let Some(target) = remote_alias_pid(&parts[3]) {
                    for (term, heap_words) in terms {
                        let message = owned_to_message_with_heap_size(&term, heap_words)?
                            .with_alias(reference);
                        let message = if flags & FLG_PRIO != 0 {
                            message.with_priority()
                        } else {
                            message
                        };
                        let result = if flags & FLG_EXIT != 0 {
                            sched.signal(from, target, Signal::Exit(Box::new(message)))
                        } else {
                            sched.send(from, target, message)
                        };
                        result.map_err(|error| {
                            VmError::Unsupported(format!("dist altact alias: {error}"))
                        })?;
                    }
                }
            } else if flags & FLG_NAME != 0 {
                let OwnedTerm::Atom(name) = &parts[3] else {
                    return Err(badarg());
                };
                let target = runtime.reg.whereis_proc_str(name);
                if let Some(target) = target {
                    for (term, heap_words) in terms {
                        let message = owned_to_message_with_heap_size(&term, heap_words)?;
                        let message = if flags & FLG_PRIO != 0 {
                            message.with_priority()
                        } else {
                            message
                        };
                        let result = if flags & FLG_EXIT != 0 {
                            sched.signal(from, target, Signal::Exit(Box::new(message)))
                        } else {
                            sched.send(from, target, message)
                        };
                        result.map_err(|error| {
                            VmError::Unsupported(format!("dist altact name: {error}"))
                        })?;
                    }
                }
            } else {
                let target = local_pid(&parts[3], local);
                if let Some(target) = target {
                    for (term, heap_words) in terms {
                        let message = owned_to_message_with_heap_size(&term, heap_words)?;
                        let message = if flags & FLG_PRIO != 0 {
                            message.with_priority()
                        } else {
                            message
                        };
                        let result = if flags & FLG_EXIT != 0 {
                            sched.signal(from, target, Signal::Exit(Box::new(message)))
                        } else {
                            sched.send(from, target, message)
                        };
                        result.map_err(|error| {
                            VmError::Unsupported(format!("dist altact pid: {error}"))
                        })?;
                    }
                }
            }
        }
        // Port of dist.c:2885 (DOP_SPAWN_REQUEST) / DOP_SPAWN_REPLY on Port DistCtrlr.
        29 if parts.len() == 6 && terms.len() == 1 => {
            handle_spawn_request_port(runtime, handle, local, parts, &terms[0].0)?;
        }
        31 | 32 if (parts.len() == 5 && *op == 31) || (parts.len() == 6 && *op == 32) => {
            // Port of erts/emulator/beam/dist.c:3017-3124 (DOP_SPAWN_REPLY), OTP-29.1.1.
            dist_spawn_reply(runtime, handle, parts)?;
        }
        other => {
            let _ = other;
            return Ok(());
        }
    }
    Ok(())
}

fn owned_to_message(term: &OwnedTerm) -> Result<Message, VmError> {
    owned_to_message_with_heap_size(term, 256)
}

fn owned_to_message_with_heap_size(
    term: &OwnedTerm,
    heap_words: usize,
) -> Result<Message, VmError> {
    let (local, creation) = {
        let tables = node_tables::lock();
        (tables.local_name.clone(), tables.local_creation)
    };
    let term = internalize_local_node(term.clone(), &local, creation);
    let mut heap = arinsal_term::ProcessHeap::with_words(heap_words);
    let term = from_owned(&term, &mut heap).map_err(|_| badarg())?;
    Message::copy_from(term)
}

/// Port of erts/emulator/beam/external.c (dec_is_this_node, dec_pid, dec_term), OTP-29.1.1.
/// Decode peer-encoded local identities as internal pids, ports, and references so they compare
/// equal to locally created terms.
fn internalize_local_node(mut term: OwnedTerm, local: &str, local_creation: u32) -> OwnedTerm {
    match &mut term {
        OwnedTerm::Pid { node, creation, .. }
        | OwnedTerm::Port { node, creation, .. }
        | OwnedTerm::Ref { node, creation, .. }
            if node.as_str() == local && *creation == local_creation =>
        {
            *node = "nonode@nohost".into();
            *creation = 0;
        }
        OwnedTerm::Tuple(parts) => {
            for part in parts.iter_mut() {
                let taken = std::mem::replace(part, OwnedTerm::Nil);
                *part = internalize_local_node(taken, local, local_creation);
            }
        }
        OwnedTerm::List { elems, tail } => {
            for elem in elems.iter_mut() {
                let taken = std::mem::replace(elem, OwnedTerm::Nil);
                *elem = internalize_local_node(taken, local, local_creation);
            }
            let taken = std::mem::replace(tail.as_mut(), OwnedTerm::Nil);
            *tail.as_mut() = internalize_local_node(taken, local, local_creation);
        }
        OwnedTerm::Map(entries) => {
            for (key, value) in entries.iter_mut() {
                let taken_k = std::mem::replace(key, OwnedTerm::Nil);
                *key = internalize_local_node(taken_k, local, local_creation);
                let taken_v = std::mem::replace(value, OwnedTerm::Nil);
                *value = internalize_local_node(taken_v, local, local_creation);
            }
        }
        OwnedTerm::Fun { pid, free_vars, .. } => {
            let creator = std::mem::replace(pid.as_mut(), OwnedTerm::Nil);
            **pid = internalize_local_node(creator, local, local_creation);
            for value in free_vars.iter_mut() {
                let taken = std::mem::replace(value, OwnedTerm::Nil);
                *value = internalize_local_node(taken, local, local_creation);
            }
        }
        OwnedTerm::Record { fields, .. } => {
            for (_, value) in fields {
                let taken = std::mem::replace(value, OwnedTerm::Nil);
                *value = internalize_local_node(taken, local, local_creation);
            }
        }
        _ => {}
    }
    term
}

fn dist_spawn_request(
    vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    args: &[Term],
) -> Result<Term, VmError> {
    // Port of erts/emulator/beam/dist.c:5827 (erts_internal_dist_spawn_request_4), OTP-29.1.1.
    let Some(node) = atom_name(args[0]) else {
        return fallback_dist_spawn(vm, process, ctx, args);
    };
    let (local, alive) = {
        let tables = node_tables::lock();
        (tables.local_name.clone(), tables.alive)
    };
    if node == local || node == "nonode@nohost" || !alive {
        return fallback_dist_spawn(vm, process, ctx, args);
    }
    // dist.c erts_internal_dist_spawn_request_4: ERTS_DSIG_PREP_NOT_ALIVE and
    // ERTS_DSIG_PREP_NOT_CONNECTED reply `{error, noconnection}` at once.
    let connection_id = match dsig_prepare(process, ctx, &node)? {
        DsigPrepare::Connected { connection_id, .. } => connection_id,
        DsigPrepare::NotAlive | DsigPrepare::NotConnected => {
            return fallback_dist_spawn(vm, process, ctx, args);
        }
    };
    let mfa = owned(args[1])?;
    let OwnedTerm::Tuple(values) = &mfa else {
        return Err(badarg());
    };
    if values.len() != 3
        || !matches!(&values[0], OwnedTerm::Atom(_))
        || !matches!(&values[1], OwnedTerm::Atom(_))
        || !matches!(&values[2], OwnedTerm::List { .. } | OwnedTerm::Nil)
    {
        return Err(badarg());
    }
    let options = owned(args[2])?;
    let kind = atom_name(args[3]).ok_or_else(badarg)?;
    let id = arinsal_bifs::next_ref_id();
    let reference = crate::signals::reference(process, id)?;
    let reference_owned = owned(reference)?;
    let mut tag = OwnedTerm::Atom("spawn_reply".into());
    let mut monitor = false;
    let mut link = false;
    let mut no_success_msg = false;
    let mut no_error_msg = false;
    let mut wire_opts = Vec::new();
    match &options {
        OwnedTerm::Nil => {}
        OwnedTerm::List { elems, tail } if **tail == OwnedTerm::Nil => {
            for option in elems {
                match option {
                    OwnedTerm::Atom(name) if name == "monitor" => {
                        monitor = true;
                        wire_opts.push(option.clone());
                    }
                    OwnedTerm::Atom(name) if name == "link" => {
                        // dist.c:5887 (monitor_oflags |= ERTS_ML_FLG_SPAWN_LINK).
                        link = true;
                        wire_opts.push(option.clone());
                    }
                    OwnedTerm::Tuple(pair) if pair.len() == 2 => match &pair[0] {
                        OwnedTerm::Atom(name) if name == "reply_tag" => {
                            if kind != "spawn_request" {
                                return Err(badarg());
                            }
                            tag = pair[1].clone();
                        }
                        OwnedTerm::Atom(name) if name == "reply" => match &pair[1] {
                            // dist.c:5900-5920: ERTS_ML_FLG_SPAWN_NO_SMSG / _NO_EMSG.
                            OwnedTerm::Atom(v) if v == "error_only" => {
                                no_success_msg = true;
                                no_error_msg = false;
                            }
                            OwnedTerm::Atom(v) if v == "no" => {
                                no_success_msg = true;
                                no_error_msg = true;
                            }
                            OwnedTerm::Atom(v) if v == "success_only" => {
                                no_success_msg = false;
                                no_error_msg = true;
                            }
                            OwnedTerm::Atom(v) if v == "yes" => {
                                no_success_msg = false;
                                no_error_msg = false;
                            }
                            _ => return Err(badarg()),
                        },
                        OwnedTerm::Atom(name) if name == "monitor" => {
                            monitor = true;
                            wire_opts.push(option.clone());
                        }
                        // dist.c:5954 (`{link, Prio}`: ERTS_ML_FLG_SPAWN_LINK).
                        OwnedTerm::Atom(name) if name == "link" => {
                            link = true;
                            wire_opts.push(option.clone());
                        }
                        _ => wire_opts.push(option.clone()),
                    },
                    _ => wire_opts.push(option.clone()),
                }
            }
        }
        _ => return Err(badarg()),
    }
    let wire_options = if wire_opts.is_empty() {
        OwnedTerm::Nil
    } else {
        OwnedTerm::List {
            elems: wire_opts,
            tail: Box::new(OwnedTerm::Nil),
        }
    };
    let mfa_control = OwnedTerm::tuple(vec![
        values[0].clone(),
        values[1].clone(),
        OwnedTerm::Int(list_owned_len(&values[2]).ok_or_else(badarg)? as i64),
    ]);
    let control = control(
        29,
        vec![
            reference_owned,
            local_pid_owned(ctx.pid()),
            local_pid_owned(ctx.pid()),
            mfa_control,
            wire_options,
        ],
    );
    // Port of erts/emulator/beam/dist.c:6112-6120 (erts_internal_dist_spawn_request_4), OTP-29.1.1:
    // the pending-spawn monitor of the request; its origin is found on exit through the
    // resource bit (erts: the process monitor tree).
    let _ =
        arinsal_sched::proc_flags::publish(ctx.exit_flags(), arinsal_sched::proc_flags::DIST_SPAWN);
    let request = node_tables::SpawnRequest {
        caller: ctx.pid(),
        tag,
        monitor,
        no_success_msg,
        no_error_msg,
        abandoned: false,
        link,
        parent_exiting: false,
        child: None,
        waiter: None,
    };
    // A node without a table entry gets it from the auto-connect of the first send
    // (erts_auto_connect, dist.c:3260); no reply can precede the connection, so the request is
    // registered right after that send in this case.
    let mut request = Some(request);
    {
        let tables = node_tables::lock();
        if let Some(mut entry) = tables.entries.get(&node).map(|dep| dep.lock()) {
            let request = request.take().expect("request present");
            if let Some(state) = entry.dist.as_mut() {
                state.spawn_requests.insert(id, request);
            } else {
                entry.pending_spawn_requests.insert(id, request);
            }
        }
    }
    if let Err(error) = queue_outgoing_on(
        process,
        ctx,
        &node,
        connection_id,
        control,
        Some(values[2].clone()),
    ) {
        let tables = node_tables::lock();
        if let Some(mut entry) = tables.entries.get(&node).map(|dep| dep.lock()) {
            entry.pending_spawn_requests.remove(&id);
            if let Some(state) = entry.dist.as_mut() {
                state.spawn_requests.remove(&id);
            }
        }
        return Err(error);
    }
    if let Some(request) = request {
        let tables = node_tables::lock();
        let mut entry = tables
            .entries
            .get(&node)
            .map(|dep| dep.lock())
            .ok_or_else(badarg)?;
        if let Some(state) = entry.dist.as_mut() {
            state.spawn_requests.insert(id, request);
        } else {
            entry.pending_spawn_requests.insert(id, request);
        }
    }
    if kind == "spawn_opt" {
        // Port of erts/emulator/beam/dist.c:6076 (ok_result = {Ref, SpawnsMonitor}), OTP-29.1.1.
        return tuple(process, vec![reference, boolean(monitor)]);
    }
    Ok(reference)
}

fn fallback_dist_spawn(
    vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    args: &[Term],
) -> Result<Term, VmError> {
    crate::natives::proc::call(
        vm,
        process,
        ctx,
        "erts_internal",
        "dist_spawn_request",
        crate::natives::NativeArgs::Slice(args),
    )
    .ok_or_else(badarg)?
}

fn list_owned_len(term: &OwnedTerm) -> Option<usize> {
    match term {
        OwnedTerm::Nil => Some(0),
        OwnedTerm::List { elems, tail } if **tail == OwnedTerm::Nil => Some(elems.len()),
        _ => None,
    }
}

/// `ERTS_DIST_SPAWN_FLAG_LINK` (dist.h:185) in the flags of DOP_SPAWN_REPLY.
const DIST_SPAWN_FLAG_LINK: u64 = 1 << 0;
/// `ERTS_DIST_SPAWN_FLAG_MONITOR` (dist.h:186) in the flags of DOP_SPAWN_REPLY.
const DIST_SPAWN_FLAG_MONITOR: u64 = 1 << 1;

/// A DOP_SPAWN_REPLY as its parent receives it in the [`Signal::DistSpawnReply`] signal.
///
/// Port of erts/emulator/beam/erl_proc_sig_queue.c (ErtsDistSpawnReplySigData), OTP-29.1.1.
/// erts builds the reply message on the sending side and patches the tag in on reception;
/// Arinsal keeps the parts and builds the message on the receiver heap.
pub(crate) struct DistSpawnReplyData {
    /// The connection the reply arrived on (erts: `dep` plus its connection id).
    handle: u64,
    /// Key of the request reference.
    id: u64,
    /// `datap->ref`.
    reference: OwnedTerm,
    /// The parent as the wire names it, for DOP_DEMONITOR.
    parent: OwnedTerm,
    /// `datap->result`: the child pid, or the error atom of a failed spawn.
    result: OwnedTerm,
    /// The DOP_SPAWN_REPLY flags.
    flags: u64,
    /// `datap->link`: the proc half of the external link to the child of a successful spawn
    /// with link, its dist half already in the connection.
    link: Option<elink::DistLinkHalf>,
    /// The origin half of the monitor of the child of a successful spawn with monitor, its
    /// target half already in the connection.
    monitor_half: Option<emon::DistMonitorHalf>,
}

impl DistSpawnReplyData {
    /// Key of the request reference (`datap->ref`).
    pub(crate) fn id(&self) -> u64 {
        self.id
    }

    /// The spawn succeeded: the result is the child pid.
    pub(crate) fn is_success(&self) -> bool {
        matches!(self.result, OwnedTerm::Pid { .. })
    }

    /// The remote monitors the child: the distribution half of the spawn monitor exists.
    fn monitor(&self) -> bool {
        self.is_success() && self.flags & DIST_SPAWN_FLAG_MONITOR != 0
    }

    /// Take the origin half of the spawn monitor.
    fn take_monitor_half(&self) -> Option<crate::proc_create::ProcessMonitor> {
        self.monitor_half
            .as_ref()
            .and_then(emon::DistMonitorHalf::take_half)
    }

    /// Take `datap->link`.
    pub(crate) fn link(&self) -> Option<crate::monitor_link::Link> {
        self.link.as_ref().and_then(elink::DistLinkHalf::take_half)
    }
}

/// Handle DOP_SPAWN_REPLY / DOP_SPAWN_REPLY_TT on connection `handle`: queue one
/// [`Signal::DistSpawnReply`] to the parent, or clean up when the parent is gone.
///
/// Port of erts/emulator/beam/dist.c:3017-3124 (DOP_SPAWN_REPLY), OTP-29.1.1.
fn dist_spawn_reply(
    runtime: &crate::process::Runtime,
    handle: u64,
    parts: &[OwnedTerm],
) -> Result<(), VmError> {
    let (local, node) = {
        let tables = node_tables::lock();
        let node = tables
            .entries
            .values()
            .map(|dep| dep.lock())
            .find(|entry| {
                entry
                    .dist
                    .as_ref()
                    .is_some_and(|state| state.handle == handle)
            })
            .map(|entry| entry.name.clone());
        (tables.local_name.clone(), node)
    };
    let Some(_node) = node else {
        // The connection went down while the reply was routed.
        return Ok(());
    };
    let Some(parent) = local_pid(&parts[2], &local) else {
        // Old incarnation of this node.
        return Ok(());
    };
    let id = remote_ref_id(&parts[1]).ok_or_else(badarg)?;
    let flags = as_u64(&parts[3]).ok_or_else(badarg)?;
    if flags >= 1 << 27 {
        return Err(badarg());
    }
    let result = parts[4].clone();
    let child = match &result {
        OwnedTerm::Pid { .. } => Some(remote_proxy(handle, &result)?),
        OwnedTerm::Atom(_) => None,
        _ => return Err(badarg()),
    };
    // Successful spawn-link: the link the parent inserts (dist.c DOP_SPAWN_REPLY:
    // erts_link_external_create, erts_link_dist_insert).
    let link = match child {
        Some(_) if flags & DIST_SPAWN_FLAG_LINK != 0 => {
            Some(elink::spawn_reply_link(runtime, handle, parent, &result)?)
        }
        _ => None,
    };
    // The spawn monitor of the child: its target half goes into the connection, which erts
    // does with the request (dist.c erts_internal_dist_spawn_request_4,
    // erts_monitor_dist_insert), and the parent's origin half travels with the reply.
    let monitor_half = if child.is_some() && flags & DIST_SPAWN_FLAG_MONITOR != 0 {
        let (_node, _connection_id, mld) =
            elink::connection_of_handle(handle).ok_or_else(badarg)?;
        let origin = emon::create_origin_or_down(
            runtime,
            None,
            crate::monitor_link::MonitorReference::ordinary(id),
            parent,
            crate::proc_create::MonitorInfo::default(),
            crate::proc_create::DistTarget {
                target: result.clone(),
                reference: parts[1].clone(),
                dist: mld,
            },
        )?;
        Some(emon::DistMonitorHalf::new(origin))
    } else {
        None
    };
    let data = std::sync::Arc::new(DistSpawnReplyData {
        handle,
        id,
        reference: parts[1].clone(),
        parent: parts[2].clone(),
        result,
        flags,
        link,
        monitor_half,
    });
    // Ordered against signals from the spawned process; a failed spawn is ordered from the
    // spawn service (erl_proc_sig_queue.c:3337-3352).
    let ordered_from = child.unwrap_or(parent);
    let payload: std::sync::Arc<dyn std::any::Any + Send + Sync> = data.clone();
    let sent = runtime
        .scheduler()?
        .signal(
            ordered_from,
            parent,
            Signal::DistSpawnReply(arinsal_sched::SharedPayload(payload)),
        )
        .is_ok();
    if !sent {
        spawn_reply_send_failed(runtime, &data);
    }
    Ok(())
}

/// erts_proc_sig_send_dist_spawn_reply failed: the parent left the process table. A
/// monitored child is demonitored, and for a spawn with link the result is saved so the
/// terminating parent can send the child an exit signal with the correct exit reason.
///
/// Port of erts/emulator/beam/dist.c:3090-3121 (DOP_SPAWN_REPLY), OTP-29.1.1. The link half
/// was never inserted in a process, so there is nothing to release.
pub(crate) fn spawn_reply_send_failed(
    runtime: &crate::process::Runtime,
    data: &DistSpawnReplyData,
) {
    if data.monitor() {
        spawn_reply_drop_monitor(data);
        spawn_reply_demonitor(
            runtime,
            data.handle,
            &data.parent,
            &data.result,
            &data.reference,
        );
    }
    if data.flags & DIST_SPAWN_FLAG_LINK != 0 {
        dist_pend_spawn_exit_save_child_result(data.handle, data.id, &data.result);
    }
}

/// Store the result of a spawn with link for its terminating parent and resume the parent if
/// it suspended waiting for it. A parent that did not reach its pending-spawn phase yet finds
/// the result in its request.
///
/// Port of erts/emulator/beam/dist.c:552-640 (dist_pend_spawn_exit_save_child_result),
/// OTP-29.1.1: erts_resume after `dist->mtx` is released.
fn dist_pend_spawn_exit_save_child_result(handle: u64, id: u64, result: &OwnedTerm) {
    let resume = {
        let dep = node_tables::lock().dep_by_handle(handle);
        let mut entry = dep.as_ref().map(|dep| dep.lock());
        let Some(state) = entry
            .as_mut()
            .and_then(|entry| entry.dist.as_mut())
            .filter(|state| state.handle == handle)
        else {
            // !dist->alive
            return;
        };
        state.spawn_requests.get_mut(&id).and_then(|request| {
            if request.child.is_none() {
                request.child = Some(result.clone());
            }
            request.waiter.take()
        })
    };
    drop(resume);
}

/// Take the live pending request `id` of `parent`: the spawn-pending origin monitor of
/// handle_dist_spawn_reply (erl_proc_sig_queue.c:5706 erts_monitor_tree_lookup with
/// ERTS_ML_FLG_SPAWN_PENDING). A request already moved aside by the exiting parent is not
/// live.
pub(crate) fn take_spawn_request(parent: Pid, id: u64) -> Option<node_tables::SpawnRequest> {
    let tables = node_tables::lock();
    for mut entry in tables.entries.values().map(|dep| dep.lock()) {
        let pending = &mut entry.pending_spawn_requests;
        if pending
            .get(&id)
            .is_some_and(|request| request.caller == parent && !request.parent_exiting)
        {
            return pending.remove(&id);
        }
        if let Some(state) = entry.dist.as_mut()
            && state
                .spawn_requests
                .get(&id)
                .is_some_and(|request| request.caller == parent && !request.parent_exiting)
        {
            return state.spawn_requests.remove(&id);
        }
    }
    None
}

/// The reply needs no monitor: release the distribution half the reply handler created
/// (erl_proc_sig_queue.c:5866-5880, `erts_monitor_dist_delete` without a demonitor signal).
pub(crate) fn spawn_reply_drop_monitor(data: &DistSpawnReplyData) {
    if let Some(origin) = data.take_monitor_half() {
        emon::release_origin(origin);
    }
}

/// Install the origin half of a successful monitored spawn in the caller's monitor tree.
///
/// Port of erts/emulator/beam/erl_proc_sig_queue.c:5740-5878
/// (handle_dist_spawn_reply), OTP-29.1.1.
pub(crate) fn spawn_reply_install_origin_monitor(process: &mut Process, data: &DistSpawnReplyData) {
    if let Some(origin) = data.take_monitor_half() {
        process.cold_mut().dist_monitors.insert(data.id);
        process.monitors.insert(origin);
    }
}

/// Mark the live pending request `id` of `parent` abandoned, or drop it when it has no link.
/// Returns false when `id` is not an outstanding request of `parent`.
///
/// Port of erts/emulator/beam/bif.c:1166 (spawn_request_abandon_1), OTP-29.1.1, for a
/// distributed request: one with link is left for the reply, which sends the child an
/// `abandoned` exit (erl_proc_sig_queue.c:5786-5830).
pub(crate) fn spawn_request_abandon(parent: Pid, id: u64) -> bool {
    let tables = node_tables::lock();
    for dep in tables.entries.values() {
        let mut guard = dep.lock();
        let entry = &mut *guard;
        let connected = entry.dist.as_mut().map(|state| &mut state.spawn_requests);
        for requests in std::iter::once(&mut entry.pending_spawn_requests).chain(connected) {
            let Some(request) = requests.get_mut(&id) else {
                continue;
            };
            if request.caller != parent || request.parent_exiting || request.abandoned {
                return false;
            }
            if request.link {
                // Leave it for reply...
                request.abandoned = true;
            } else {
                requests.remove(&id);
            }
            return true;
        }
    }
    false
}

/// The `{Tag, Ref, ok|error, Pid|ErrorAtom}` reply message on the parent's heap
/// (erl_proc_sig_queue.c:5741 patch point plus convert_prepared_sig_to_msg).
pub(crate) fn spawn_reply_message(
    process: &mut Process,
    tag: &OwnedTerm,
    data: &DistSpawnReplyData,
) -> Result<Term, VmError> {
    let status = if data.is_success() { "ok" } else { "error" };
    // The reference is the request's own local reference (erts `ref` of the spawn request):
    // an owned remote-style copy would not compare equal to it with `=:=`.
    let reference = crate::signals::reference(process, data.id)?;
    let tag = from_owned(tag, &mut process.heap).map_err(|_| badarg())?;
    let result = from_owned(&data.result, &mut process.heap).map_err(|_| badarg())?;
    let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
    TermBuilder::new(&mut heap)
        .tuple(&[tag, reference, crate::atom_cache::put(status), result])
        .map_err(|_| badarg())
}

/// The child term of a successful reply on the parent's heap, for the `link` trace event.
pub(crate) fn spawn_reply_child_term(
    process: &mut Process,
    data: &DistSpawnReplyData,
) -> Result<Term, VmError> {
    from_owned(&data.result, &mut process.heap).map_err(|_| badarg())
}

/// Handle a spawn reply that reaches its parent while the parent is exiting: a monitored child
/// is demonitored and a linked child gets the parent's exit reason, or `abandoned`.
///
/// Port of erts/emulator/beam/erl_proc_sig_queue.c:5927 (handle_dist_spawn_reply_exiting),
/// OTP-29.1.1. The pending-spawn monitors were moved aside by
/// [`pend_spawn_exit_parent_setup`] in the monitors phase before this runs.
pub(crate) fn handle_dist_spawn_reply_exiting(
    runtime: &crate::process::Runtime,
    parent: Pid,
    reason: Term,
    shared: &arinsal_sched::SharedPayload,
) {
    let Some(data) = shared.0.downcast_ref::<DistSpawnReplyData>() else {
        return;
    };
    // erts_monitor_tree_lookup(pe_ctxt_p->pend_spawn_monitors) with
    // erts_dist_pend_spawn_exit_delete: `connected` is false when the connection closed.
    let found = {
        let tables = node_tables::lock();
        let mut found = None;
        for mut entry in tables.entries.values().map(|dep| dep.lock()) {
            if entry
                .pending_spawn_requests
                .get(&data.id)
                .is_some_and(|request| request.caller == parent && request.parent_exiting)
            {
                found = entry
                    .pending_spawn_requests
                    .remove(&data.id)
                    .map(|request| (request, false));
                break;
            }
            if let Some(state) = entry.dist.as_mut()
                && state
                    .spawn_requests
                    .get(&data.id)
                    .is_some_and(|request| request.caller == parent && request.parent_exiting)
            {
                let connected = state.handle == data.handle;
                found = state
                    .spawn_requests
                    .remove(&data.id)
                    .map(|request| (request, connected));
                break;
            }
        }
        found
    };
    let Some((mut request, connected)) = found else {
        // May happen when the connection concurrently closed.
        spawn_reply_drop_monitor(data);
        return;
    };
    if let Some(waiter) = request.waiter.take() {
        // The parent runs this itself; it is not suspended on the request.
        waiter.cancel();
    }
    if !data.is_success() {
        return;
    }
    if request.monitor && connected {
        // erts_proc_exit_dist_demonitor.
        spawn_reply_drop_monitor(data);
        spawn_reply_demonitor(
            runtime,
            data.handle,
            &data.parent,
            &data.result,
            &data.reference,
        );
    } else {
        spawn_reply_drop_monitor(data);
    }
    if let Some(link) = data.link() {
        // erts_proc_exit_handle_link: the link exit carries the actual reason, unless the
        // operation was abandoned.
        let reason = if request.abandoned {
            Term::atom(arinsal_term::atoms::ABANDONED)
        } else {
            reason
        };
        proc_exit_handle_link(Some(runtime), parent, link, reason);
    }
}

/// DOP_DEMONITOR of a child spawned for a parent that no longer takes the reply.
// Port of erts/emulator/beam/dist.c:3092-3101 (erts_dsig_send_demonitor), OTP-29.1.1.
fn spawn_reply_demonitor(
    runtime: &crate::process::Runtime,
    handle: u64,
    parent: &OwnedTerm,
    child: &OwnedTerm,
    reference: &OwnedTerm,
) {
    let control = control(20, vec![parent.clone(), child.clone(), reference.clone()]);
    let _ = emit_control_message_on_handle(runtime, handle, control, None);
}

/// Pending-spawn monitors of an exiting parent are moved aside: replies that arrive from now
/// on are saved for the parent instead of delivered.
///
/// Port of erts/emulator/beam/erl_process.c:13932-13935 (proc_exit_handle_monitors) and
/// dist.c:665 (erts_dist_pend_spawn_exit_parent_setup), OTP-29.1.1.
pub(crate) fn pend_spawn_exit_parent_setup(parent: Pid) {
    let tables = node_tables::lock();
    for dep in tables.entries.values() {
        let mut guard = dep.lock();
        let entry = &mut *guard;
        let pending = entry.pending_spawn_requests.values_mut();
        let connected = entry
            .dist
            .iter_mut()
            .flat_map(|state| state.spawn_requests.values_mut());
        for request in pending.chain(connected) {
            if request.caller == parent {
                request.parent_exiting = true;
            }
        }
    }
}

/// Result of one pass of ERTS_CONTINUE_EXIT_DIST_PEND_SPAWN_MONITORS.
pub(crate) enum PendSpawnExit {
    /// Every pending-spawn monitor of the parent is handled.
    Done,
    /// The parent is suspended until a spawn reply or the loss of the connection resumes it.
    Wait,
}

/// Handle the pending-spawn monitors of exiting `parent`: drop those without link, send the
/// link exit to every child whose pid is known, and suspend on `waiter` for the others.
/// Without a waiter (a synchronous exit that cannot suspend) those are dropped.
///
/// Port of erts/emulator/beam/erl_process.c:13647-13780 (proc_exit_handle_pend_spawn_monitors)
/// with dist.c:641 (erts_dist_pend_spawn_exit_delete) and dist.c:758-790
/// (erts_dist_pend_spawn_exit_parent_wait), OTP-29.1.1. The table lock is erts' `dist->mtx`:
/// the suspend is recorded under it, so a reply cannot slip between test and suspend.
pub(crate) fn pend_spawn_exit(
    runtime: &crate::process::Runtime,
    parent: Pid,
    reason: Term,
    waiter: Option<&arinsal_sched::ExitWaiter<Process>>,
) -> PendSpawnExit {
    let mut exits: Vec<(u64, OwnedTerm, bool, bool)> = Vec::new();
    let mut wait = false;
    let (local_name, local_creation) = {
        let tables = node_tables::lock();
        let local = (tables.local_name.clone(), tables.local_creation);
        for mut entry in tables.entries.values().map(|dep| dep.lock()) {
            let mut visit = |connection: Option<(u64, bool)>,
                             requests: &mut std::collections::BTreeMap<
                u64,
                node_tables::SpawnRequest,
            >| {
                requests.retain(|_, request| {
                    if request.caller != parent || !request.parent_exiting {
                        return true;
                    }
                    if !request.link {
                        // Just cleanup.
                        return false;
                    }
                    match request.child.take() {
                        // A failed spawn (an atom) needs no exit signal.
                        Some(child) => {
                            let is_pid = matches!(child, OwnedTerm::Pid { .. });
                            if let (Some((handle, exit_payload)), true) = (connection, is_pid) {
                                exits.push((handle, child, exit_payload, request.abandoned));
                            }
                            false
                        }
                        None => match waiter {
                            Some(waiter) => {
                                // `erts_suspend` plus `mdp->u.target.other.ptr = c_p`; a
                                // waiter already stored from an earlier pass stays.
                                if request.waiter.is_none() {
                                    request.waiter = Some(waiter.clone());
                                }
                                wait = true;
                                true
                            }
                            None => false,
                        },
                    }
                });
            };
            visit(None, &mut entry.pending_spawn_requests);
            if let Some(state) = entry.dist.as_mut() {
                let exit_payload = state.flags & node_tables::DFLAG_EXIT_PAYLOAD != 0;
                visit(
                    Some((state.handle, exit_payload)),
                    &mut state.spawn_requests,
                );
            }
        }
        local
    };
    if !exits.is_empty()
        && let Ok(reason) = to_owned(reason)
    {
        let reason = node_tables::relabel_local_node(reason, &local_name, local_creation);
        let abandoned = OwnedTerm::Atom("abandoned".into());
        let from = OwnedTerm::Pid {
            node: local_name.clone(),
            id: parent.number(),
            serial: parent.serial(),
            creation: local_creation,
        };
        for (handle, child, exit_payload, was_abandoned) in exits {
            // erl_process.c:13715: ERTS_ML_FLG_SPAWN_ABANDONED exits the child with `abandoned`.
            let reason = if was_abandoned { &abandoned } else { &reason };
            // erts_dsig_send_exit_tt (dist.c:1773), as `forward_link_exit_if_proxy` encodes a
            // link exit; a connection that went away in between drops it, as the
            // connection-id test of erl_process.c:13722 does.
            let (control, payload) = if exit_payload {
                (control(24, vec![from.clone(), child]), Some(reason.clone()))
            } else {
                (control(3, vec![from.clone(), child, reason.clone()]), None)
            };
            let _ = emit_control_message_on_handle(runtime, handle, control, payload);
        }
    }
    if wait {
        PendSpawnExit::Wait
    } else {
        PendSpawnExit::Done
    }
}

fn handle_spawn_request(
    _vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    handle: u64,
    parts: &[OwnedTerm],
    arguments: &OwnedTerm,
) -> Result<(), VmError> {
    // Port of erts/emulator/beam/dist.c:2885 (DOP_SPAWN_REQUEST), OTP-29.1.1.
    let reference = parts[1].clone();
    let from = parts[2].clone();
    let mfa = &parts[4];
    let options = &parts[5];
    let local_name = node_tables::this_node().0.to_owned();
    let local_creation = node_tables::this_node().1;
    let arguments = internalize_local_node(arguments.clone(), &local_name, local_creation);
    let (module, function, arity) = match mfa {
        OwnedTerm::Tuple(items) if items.len() == 3 => (&items[0], &items[1], &items[2]),
        _ => return Err(badarg()),
    };
    let (OwnedTerm::Atom(_), OwnedTerm::Atom(_)) = (module, function) else {
        return Err(badarg());
    };
    if as_u64(arity) != list_owned_len(&arguments).map(|n| n as u64) {
        return Err(badarg());
    }
    let (OwnedTerm::List { .. } | OwnedTerm::Nil) = &arguments else {
        return Err(badarg());
    };
    let monitor = spawn_opts_want_monitor(options);
    let link = spawn_opts_want_link(options);
    let mut result = OwnedTerm::Atom("badopt".into());
    let mut child_to_schedule = None;
    if spawn_opts_acceptable(options) {
        let OwnedTerm::Atom(module) = module else {
            return Err(badarg());
        };
        let OwnedTerm::Atom(function) = function else {
            return Err(badarg());
        };
        let args = match &arguments {
            OwnedTerm::Nil => Vec::new(),
            OwnedTerm::List { elems, tail } if **tail == OwnedTerm::Nil => elems.clone(),
            _ => return Err(badarg()),
        };
        let runtime = process.runtime.as_ref().ok_or_else(badarg)?;
        // The link of the child still has a proxy origin.
        let watcher = link.then(|| remote_proxy(handle, &from)).transpose()?;
        let monitor_origin = spawn_child_monitor_origin(handle, monitor, &from, &reference);
        let child = runtime.spawn_mfa_unscheduled_watched(
            module,
            function,
            &args,
            link.then_some(watcher).flatten(),
            monitor_origin,
            &from,
        );
        if let Ok(child) = child {
            result = local_pid_owned(child);
            child_to_schedule = Some(child);
        }
    }
    // Port of erts/emulator/beam/dist.c:1875-1898 (erts_dsig_send_spawn_reply), OTP-29.1.1.
    let flags = if matches!(result, OwnedTerm::Pid { .. }) {
        (i64::from(monitor) << 1) | i64::from(link)
    } else {
        0
    };
    let reply = control(31, vec![reference, from, OwnedTerm::Int(flags), result]);
    queue_remote_control(process, ctx, handle, reply)?;
    if let Some(child) = child_to_schedule {
        process
            .runtime
            .as_ref()
            .ok_or_else(badarg)?
            .schedule_spawn(child)?;
    }
    Ok(())
}

fn spawn_opts_acceptable(options: &OwnedTerm) -> bool {
    match options {
        OwnedTerm::Nil => true,
        OwnedTerm::List { elems, tail } if **tail == OwnedTerm::Nil => elems.iter().all(|opt| {
            matches!(opt, OwnedTerm::Atom(_))
                || matches!(opt, OwnedTerm::Tuple(parts) if parts.len() == 2)
        }),
        _ => false,
    }
}

fn spawn_opts_want_monitor(options: &OwnedTerm) -> bool {
    match options {
        OwnedTerm::List { elems, tail } if **tail == OwnedTerm::Nil => elems.iter().any(|opt| {
            matches!(opt, OwnedTerm::Atom(name) if name == "monitor")
                || matches!(
                    opt,
                    OwnedTerm::Tuple(parts)
                        if parts.len() == 2 && parts[0] == OwnedTerm::Atom("monitor".into())
                )
        }),
        _ => false,
    }
}

fn spawn_opts_want_link(options: &OwnedTerm) -> bool {
    match options {
        OwnedTerm::List { elems, tail } if **tail == OwnedTerm::Nil => elems.iter().any(|opt| {
            matches!(opt, OwnedTerm::Atom(name) if name == "link")
                || matches!(
                    opt,
                    OwnedTerm::Tuple(parts)
                        if parts.len() == 2 && parts[0] == OwnedTerm::Atom("link".into())
                )
        }),
        _ => false,
    }
}

/// Port DistCtrlr path for DOP_SPAWN_REQUEST (no Vm/Process context).
fn handle_spawn_request_port(
    runtime: &'static crate::process::Runtime,
    handle: u64,
    local: &str,
    parts: &[OwnedTerm],
    arguments: &OwnedTerm,
) -> Result<(), VmError> {
    let reference = parts[1].clone();
    let from = parts[2].clone();
    let mfa = &parts[4];
    let options = &parts[5];
    let local_creation = node_tables::this_node().1;
    let arguments = internalize_local_node(arguments.clone(), local, local_creation);
    let (module, function, arity) = match mfa {
        OwnedTerm::Tuple(items) if items.len() == 3 => (&items[0], &items[1], &items[2]),
        _ => return Err(badarg()),
    };
    let (OwnedTerm::Atom(mod_name), OwnedTerm::Atom(fun_name)) = (module, function) else {
        return Err(badarg());
    };
    if as_u64(arity) != list_owned_len(&arguments).map(|n| n as u64) {
        return Err(badarg());
    }
    let monitor = spawn_opts_want_monitor(options);
    let link = spawn_opts_want_link(options);
    let mut result = OwnedTerm::Atom("badopt".into());
    let arg_list = match &arguments {
        OwnedTerm::Nil => Vec::new(),
        OwnedTerm::List { elems, tail } if **tail == OwnedTerm::Nil => elems.clone(),
        _ => return Err(badarg()),
    };
    let watcher = if link {
        Some(remote_proxy(handle, &from)?)
    } else {
        None
    };
    let monitor_origin = spawn_child_monitor_origin(handle, monitor, &from, &reference);
    let spawn_result = if spawn_opts_acceptable(options) {
        runtime.spawn_mfa_unscheduled_watched(
            mod_name,
            fun_name,
            &arg_list,
            link.then_some(watcher).flatten(),
            monitor_origin,
            &from,
        )
    } else {
        Err(VmError::Unsupported("bad spawn options".into()))
    };
    let mut child_to_schedule = None;
    if let Ok(child) = spawn_result {
        let tables = node_tables::lock();
        result = OwnedTerm::Pid {
            node: tables.local_name.clone(),
            id: child.number(),
            serial: child.serial(),
            creation: tables.local_creation,
        };
        drop(tables);
        child_to_schedule = Some(child);
    }
    let flags = if matches!(result, OwnedTerm::Pid { .. }) {
        (i64::from(monitor) << 1) | i64::from(link)
    } else {
        0
    };
    let reply = control(31, vec![reference, from, OwnedTerm::Int(flags), result]);
    let _ = local;
    let reply_result = emit_control_message_on_handle(runtime, handle, reply, None);
    if let Some(child) = child_to_schedule {
        runtime.schedule_spawn(child)?;
    }
    reply_result
}

/// The external parent of a child spawned by a remote `spawn_request` with `monitor`, with
/// the request reference and the connection it arrived on.
fn spawn_child_monitor_origin(
    handle: u64,
    monitor: bool,
    from: &OwnedTerm,
    reference: &OwnedTerm,
) -> Option<crate::proc_create::DistOrigin> {
    if !monitor {
        return None;
    }
    let watcher = elink::external_pid(from)?;
    let (_node, _connection_id, dist) = elink::connection_of_handle(handle)?;
    Some(crate::proc_create::DistOrigin {
        watcher,
        reference: reference.clone(),
        dist,
    })
}

fn emit_control_message_on_handle(
    runtime: &crate::process::Runtime,
    handle: u64,
    control: OwnedTerm,
    message: Option<OwnedTerm>,
) -> Result<(), VmError> {
    let dep = node_tables::lock()
        .dep_by_handle(handle)
        .ok_or_else(badarg)?;
    emit_control_message_on_entry(runtime, &dep, handle, control, message)
}

/// Encode and queue a control message on `dep`'s connection while it still has `handle`;
/// only the entry lock is taken.
pub(crate) fn emit_control_message_on_entry(
    runtime: &crate::process::Runtime,
    dep: &node_tables::DistEntry,
    handle: u64,
    control: OwnedTerm,
    message: Option<OwnedTerm>,
) -> Result<(), VmError> {
    let (local_name, local_creation) = node_tables::this_node();
    let control = node_tables::relabel_local_node(control, local_name, local_creation);
    let mut entry = dep.lock();
    let state = entry
        .dist
        .as_mut()
        .filter(|state| state.handle == handle)
        .ok_or_else(badarg)?;
    if let Some(port_id) = state.port_id {
        let packets = state.encode_term(control, message).map_err(|_| badarg())?;
        state.written = state.written.saturating_add(1);
        enqueue_port_output_no_suspend_locked(state, packets);
        drop(entry);
        return flush_port_output(runtime, port_id);
    }
    state.queue_term(control, message).map_err(|_| badarg())?;
    Ok(())
}

/// Send a process exit to a linked remote PID represented by a scheduler proxy.
// Port of erts/emulator/beam/dist.c:1773-1785 (`erts_dsig_send_exit`), OTP-29.1.1.
pub(crate) fn forward_link_exit_if_proxy(
    runtime: &crate::process::Runtime,
    watcher: Pid,
    deceased: Pid,
    reason: Term,
) -> bool {
    if !may_be_proxy() {
        return false;
    }
    let (remote_watcher, handle, local_name, local_creation, exit_payload) = {
        let tables = node_tables::lock();
        let local_name = tables.local_name.clone();
        let local_creation = tables.local_creation;
        let Some(mut entry) = tables.entries.values().map(|dep| dep.lock()).find(|entry| {
            entry
                .dist
                .as_ref()
                .is_some_and(|state| state.proxy_to_remote.contains_key(&watcher))
        }) else {
            return false;
        };
        let state = entry.dist.as_mut().unwrap();
        let Some(remote_watcher) = state.proxy_to_remote.get(&watcher).cloned() else {
            return false;
        };
        (
            remote_watcher,
            state.handle,
            local_name,
            local_creation,
            state.flags & node_tables::DFLAG_EXIT_PAYLOAD != 0,
        )
    };
    let Ok(reason) = to_owned(reason) else {
        return true;
    };
    let local = OwnedTerm::Pid {
        node: local_name.clone(),
        id: deceased.number(),
        serial: deceased.serial(),
        creation: local_creation,
    };
    let reason = node_tables::relabel_local_node(reason, &local_name, local_creation);
    let (control, payload) = if exit_payload {
        (control(24, vec![local, remote_watcher]), Some(reason))
    } else {
        (control(3, vec![local, remote_watcher, reason]), None)
    };
    let _ = emit_control_message_on_handle(runtime, handle, control, payload);
    true
}

/// Send directly to a remote pid, preserving `send/2`'s returned message.
pub(crate) fn native_send(
    _vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    args: &[Term],
) -> Result<Term, VmError> {
    send_to(process, ctx, args[0], args[1])?;
    Ok(args[1])
}

/// Port of erts/emulator/beam/bif.c:2697-2759 (`send_3`), OTP-29.1.1.
pub(crate) fn native_send3(
    vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    args: &[Term],
) -> Result<Term, VmError> {
    let mut want_priority = false;
    let mut noconnect = false;
    let mut nosuspend = false;
    let mut bad = false;
    // Port of erts/emulator/beam/bif.c (erlang:send/3 option loop): the list is walked in
    // place, no copy of the options.
    let walked = crate::signals::each_list_item(args[2], |option| {
        let atoms = arinsal_term::global_atoms();
        match option.as_atom().and_then(|a| atoms.text(a)) {
            Some("nosuspend") => nosuspend = true,
            Some("noconnect") => noconnect = true,
            Some("priority") => want_priority = true,
            _ => bad = true,
        }
    });
    if walked.is_none() || bad {
        return Err(badarg());
    }
    if is_remote_target(args[0])? {
        return match try_remote_send_with_options(
            process, ctx, args[0], args[1], !noconnect, !nosuspend,
        )? {
            RemoteSendOutcome::Sent => {
                crate::trace::emit_process(
                    Some(vm),
                    process,
                    ctx.pid(),
                    crate::trace::SEND,
                    "send",
                    &[args[1], args[0]],
                );
                let _ = want_priority;
                Ok(Term::atom(arinsal_term::atoms::OK))
            }
            RemoteSendOutcome::NotConnected => Ok(Term::atom(if noconnect {
                arinsal_term::atoms::NOCONNECT
            } else {
                arinsal_term::atoms::OK
            })),
            RemoteSendOutcome::WouldSuspend => Ok(Term::atom(arinsal_term::atoms::NOSUSPEND)),
            RemoteSendOutcome::NotRemote => Err(badarg()),
        };
    }
    if nosuspend {
        // Port of erts/emulator/beam/bif.c:2390 (send_3): a busy port gives `nosuspend`.
        let (sent, busy) = crate::port::send_nosuspend(|| {
            process.send_message_prio(Some(vm), Some(ctx), args[0], args[1], want_priority)
        });
        sent?;
        return Ok(Term::atom(if busy {
            arinsal_term::atoms::NOSUSPEND
        } else {
            arinsal_term::atoms::OK
        }));
    }
    // Local priority delivery needs the process send path (alias + flag).
    process.send_message_prio(Some(vm), Some(ctx), args[0], args[1], want_priority)?;
    Ok(Term::atom(arinsal_term::atoms::OK))
}

/// Route signal BIFs to the distribution controller when the peer is remote.
pub(crate) fn native_signal(
    vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    args: &[Term],
    function: &str,
) -> Result<Term, VmError> {
    let Some(node) = remote_node(args[0])? else {
        let handler =
            crate::signals::handler("erlang", function, args.len() as u8).ok_or_else(badarg)?;
        return handler(vm, process, ctx, crate::natives::NativeArgs::Slice(args))
            .ok_or_else(badarg)?;
    };
    let target = owned(args[0])?;
    match function {
        "link" => elink::link_external(process, ctx, &node, target),
        "unlink" => elink::unlink_external(process, ctx, &node, target),
        "exit" => {
            // Port of erts/emulator/beam/bif.c (exit_signal, external pid): an exit to a node
            // that is not alive or not connected is dropped.
            let reason = owned(args[1])?;
            if let DsigPrepare::Connected { connection_id, .. } = dsig_prepare(process, ctx, &node)?
            {
                queue_outgoing_on(
                    process,
                    ctx,
                    &node,
                    connection_id,
                    control(8, vec![local_pid_owned(ctx.pid()), target, reason]),
                    None,
                )?;
            }
            Ok(Term::atom(arinsal_term::atoms::TRUE))
        }
        _ => Err(badarg()),
    }
}

// Port of erts/emulator/beam/dist.c:1454 (erts_dsig_send_link), OTP-29.1.1.
pub(crate) fn native_link(
    vm: &mut Vm,
    p: &mut Process,
    c: &mut RunCtx<'_, Message>,
    a: &[Term],
) -> Result<Term, VmError> {
    native_signal(vm, p, c, a, "link")
}
// Port of erts/emulator/beam/dist.c:1461 (erts_dsig_send_unlink), OTP-29.1.1.
pub(crate) fn native_unlink(
    vm: &mut Vm,
    p: &mut Process,
    c: &mut RunCtx<'_, Message>,
    a: &[Term],
) -> Result<Term, VmError> {
    native_signal(vm, p, c, a, "unlink")
}
// Port of erts/emulator/beam/dist.c:1773 (erts_dsig_send_exit), OTP-29.1.1.
pub(crate) fn native_exit2(
    vm: &mut Vm,
    p: &mut Process,
    c: &mut RunCtx<'_, Message>,
    a: &[Term],
) -> Result<Term, VmError> {
    native_signal(vm, p, c, a, "exit")
}
/// The `remote_process` arm of `monitor/2,3` (bif.c `monitor`): an external pid or
/// `{Name, Node}` of another node.
// Port of erts/emulator/beam/bif.c (monitor: remote_process) and dist.c:1528
// (erts_dsig_send_monitor), OTP-29.1.1.
pub(crate) fn monitor_remote(
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    args: &[Term],
    node: String,
) -> Result<Term, VmError> {
    let target = owned(args[1])?;
    // Port of dist.c:1528 (erts_dsig_send_monitor), OTP-29.1.1.
    let (tag, alias_mode, priority) = crate::signals::monitor_options(args)?;
    // bif.c monitor: `{Name, Node}` on a node that is not alive is badarg.
    if matches!(&target, OwnedTerm::Tuple(parts) if parts.len() == 2) && !node_tables::is_alive() {
        return Err(badarg());
    }
    let id = arinsal_bifs::next_ref_id();
    let reference = if alias_mode.is_some() {
        crate::signals::pid_reference(process, id, ctx.pid())?
    } else {
        crate::signals::reference(process, id)?
    };
    if priority {
        process.cold_mut().prio_monitors.insert(id);
    }
    // DOP_MONITOR_P ToProc is a pid or registered name atom (not {Name,Node}).
    let wire_target = match &target {
        OwnedTerm::Tuple(parts) if parts.len() == 2 && matches!(&parts[0], OwnedTerm::Atom(_)) => {
            parts[0].clone()
        }
        _ => target.clone(),
    };
    let reference_owned = owned(reference)?;
    let name = match &target {
        OwnedTerm::Tuple(parts) if parts.len() == 2 => match &parts[0] {
            OwnedTerm::Atom(name) => Some(name.clone()),
            _ => None,
        },
        _ => None,
    };
    let info = crate::signals::monitor_info_for(tag, name.as_deref())?;
    let prepared = dsig_prepare(process, ctx, &node)?;
    let dist = match &prepared {
        DsigPrepare::Connected { mld, .. } => mld.clone(),
        DsigPrepare::NotAlive | DsigPrepare::NotConnected => {
            // bif.c monitor: erts_monitor_set_dead_dist.
            let sysname = global_atoms().intern(&node).map_err(|_| badarg())?.0;
            std::sync::Arc::new(crate::monitor_link::MonLnkDist::dead(sysname))
        }
    };
    let runtime = process.runtime.ok_or_else(badarg)?;
    // origin `other.item`: the external pid, or the node of a monitor by name.
    let remote = if name.is_some() {
        OwnedTerm::Atom(node.clone())
    } else {
        target.clone()
    };
    let origin = emon::create_origin_or_down(
        runtime,
        process.heap.alloc_ix(),
        crate::proc_create::monitor_reference(id, alias_mode, priority),
        ctx.pid(),
        info,
        crate::proc_create::DistTarget {
            target: remote,
            reference: reference_owned.clone(),
            dist,
        },
    )?;
    process.monitors.insert(origin);
    process.cold_mut().dist_monitors.insert(id);
    if let DsigPrepare::Connected { connection_id, .. } = prepared {
        queue_outgoing_on(
            process,
            ctx,
            &node,
            connection_id,
            control(
                19,
                vec![local_pid_owned(ctx.pid()), wire_target, reference_owned],
            ),
            None,
        )?;
    }
    Ok(reference)
}

pub(crate) fn remote_node(term: Term) -> Result<Option<String>, VmError> {
    let value = owned(term)?;
    let node = match &value {
        OwnedTerm::Pid { node, .. } | OwnedTerm::Ref { node, .. } => node.clone(),
        OwnedTerm::Tuple(parts) if parts.len() == 2 => match (&parts[0], &parts[1]) {
            (OwnedTerm::Atom(_), OwnedTerm::Atom(node))
                if node_tables::is_node_name(node) || node == "nonode@nohost" =>
            {
                node.clone()
            }
            _ => return Ok(None),
        },
        _ => return Ok(None),
    };
    let local = node_tables::this_node().0.to_owned();
    Ok((node != local && node != "nonode@nohost").then_some(node))
}

fn local_pid_owned(pid: Pid) -> OwnedTerm {
    let tables = node_tables::lock();
    OwnedTerm::Pid {
        node: tables.local_name.clone(),
        id: pid.number(),
        serial: pid.serial(),
        creation: tables.local_creation,
    }
}

fn control(op: i64, mut fields: Vec<OwnedTerm>) -> OwnedTerm {
    let mut tuple = Vec::with_capacity(fields.len() + 1);
    tuple.push(OwnedTerm::Int(op));
    tuple.append(&mut fields);
    OwnedTerm::tuple(tuple)
}

/// Send via the distribution controller when `target` is remote.
///
/// Returns `Ok(true)` when the message was queued remotely. Returns `Ok(false)`
/// when `target` is a local destination and the caller should deliver locally.
///
/// Port of erts/emulator/beam/erl_message.c / `erts_send` remote arm, OTP-29.1.1.
/// Whether `target` names a process, alias or registered name on another node, which only a
/// send with a scheduler context (the distribution output path) can reach.
pub(crate) fn is_remote_target(target: Term) -> Result<bool, VmError> {
    // Port of erts/emulator/beam/bif.c:2469-2480 (do_send): internal pids and atoms skip the
    // remote-destination checks.
    if target.as_pid_data().is_some() || target.as_atom().is_some() {
        return Ok(false);
    }
    // An internal reference (an alias) names this node.
    if target.local_ref_numbers().is_some() {
        return Ok(false);
    }
    let local = node_tables::this_node().0.to_owned();
    let remote = |node: &str| node != local && node != "nonode@nohost";
    if let Some((_, node)) = name_node_tuple(target)? {
        return Ok(remote(&node));
    }
    Ok(match &owned(target)? {
        OwnedTerm::Ref { node, .. } | OwnedTerm::Pid { node, .. } => remote(node),
        _ => false,
    })
}

pub(crate) fn try_remote_send(
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    target: Term,
    message: Term,
) -> Result<bool, VmError> {
    Ok(!matches!(
        try_remote_send_with_options(process, ctx, target, message, true, true)?,
        RemoteSendOutcome::NotRemote
    ))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RemoteSendOutcome {
    NotRemote,
    Sent,
    NotConnected,
    WouldSuspend,
}

fn queue_remote_send(
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    node: &str,
    control: OwnedTerm,
    message: Option<OwnedTerm>,
    connect: bool,
    suspend: bool,
) -> Result<RemoteSendOutcome, VmError> {
    if !node_tables::is_alive() {
        return Ok(RemoteSendOutcome::NotConnected);
    }
    Ok(
        match queue_outgoing_with_options(
            process, ctx, node, control, message, connect, suspend, None,
        )? {
            DistSendResult::Queued => RemoteSendOutcome::Sent,
            DistSendResult::NotConnected => RemoteSendOutcome::NotConnected,
            DistSendResult::WouldSuspend => RemoteSendOutcome::WouldSuspend,
        },
    )
}

// Port of erts/emulator/beam/bif.c:2381-2401 (`remote_send`), OTP-29.1.1.
pub(crate) fn try_remote_send_with_options(
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    target: Term,
    message: Term,
    connect: bool,
    suspend: bool,
) -> Result<RemoteSendOutcome, VmError> {
    // {Name, Node} — registered send on a (possibly remote) node.
    if let Some((name, node)) = name_node_tuple(target)? {
        let local = node_tables::this_node().0.to_owned();
        if node == local || node == "nonode@nohost" {
            return Ok(RemoteSendOutcome::NotRemote);
        }
        // Port of erts/emulator/beam/bif.c:2381-2401 (`remote_send`), OTP-29.1.1.
        // A send to a remote registered name on a non-distributed node is a successful
        // best-effort send; there is no distribution controller to queue it through.
        let control = control(
            6,
            vec![
                local_pid_owned(ctx.pid()),
                OwnedTerm::Atom(String::new()),
                OwnedTerm::Atom(name),
            ],
        );
        return queue_remote_send(
            process,
            ctx,
            &node,
            control,
            Some(owned(message)?),
            connect,
            suspend,
        );
    }
    let target_owned = owned(target)?;
    if let OwnedTerm::Ref { node, .. } = &target_owned {
        let target_node = node.clone();
        let local = node_tables::this_node().0.to_owned();
        if target_node == local || target_node == "nonode@nohost" {
            return Ok(RemoteSendOutcome::NotRemote);
        }
        // Port of erts/emulator/beam/bif.c:2381-2401 (`remote_send`), OTP-29.1.1.
        let control = control(33, vec![local_pid_owned(ctx.pid()), target_owned]);
        return queue_remote_send(
            process,
            ctx,
            &target_node,
            control,
            Some(owned(message)?),
            connect,
            suspend,
        );
    }
    let OwnedTerm::Pid {
        node,
        id,
        serial,
        creation,
    } = &target_owned
    else {
        return Ok(RemoteSendOutcome::NotRemote);
    };
    let local = node_tables::this_node().0.to_owned();
    if node == &local || node == "nonode@nohost" {
        return Ok(RemoteSendOutcome::NotRemote);
    }
    // Port of erts/emulator/beam/bif.c:2381-2401 (`remote_send`), OTP-29.1.1.
    let control = OwnedTerm::tuple(vec![
        OwnedTerm::Int(2),
        OwnedTerm::Atom(String::new()),
        OwnedTerm::Pid {
            node: node.clone(),
            id: *id,
            serial: *serial,
            creation: *creation,
        },
    ]);
    queue_remote_send(
        process,
        ctx,
        node,
        control,
        Some(owned(message)?),
        connect,
        suspend,
    )
}

// Port of erts/emulator/beam/dist.c:3629-3773 (distribution output queue busy state), OTP-29.1.1.
fn enqueue_port_packets_locked(
    process: &mut Process,
    state: &mut node_tables::DistState,
    sender: Pid,
    packets: Vec<Vec<u8>>,
) -> bool {
    let packet_count = packets.len();
    let send_count = (process.heap.abi.fcalls.max(10) as usize / 10)
        .max(1)
        .min(packet_count);
    let packet_bytes: Vec<u64> = packets.iter().map(|packet| packet.len() as u64).collect();
    let has_older_continuation = !state.fragment_continuations.is_empty();
    let ready_count = if has_older_continuation {
        0
    } else {
        send_count
    };
    let ready_bytes: u64 = packet_bytes.iter().take(ready_count).sum();
    let deferred_count = packet_count - ready_count;
    state.pending_bytes = state
        .pending_bytes
        .saturating_sub(packet_bytes.iter().sum::<u64>() - ready_bytes);
    state.output.extend(packets);
    state.output_ready_packets += ready_count;
    if deferred_count != 0 {
        state
            .fragment_continuations
            .push_back(node_tables::DistFragmentContinuation::new(
                Some(sender),
                deferred_count,
            ));
    }
    if deferred_count != 0 || has_older_continuation {
        process.set_force_yield(true);
    }
    process.heap.abi.fcalls = (process.heap.abi.fcalls - (ready_count as i32 * 10)).max(1);
    if state.pending_bytes >= state.busy_limit {
        state.busy = true;
    }
    state.pending_bytes >= state.busy_limit
}

fn finish_port_enqueue(
    process: &mut Process,
    sender: Pid,
    port_id: u64,
    should_suspend: bool,
) -> Result<(), VmError> {
    if should_suspend {
        let suspended = suspend_dist_sender(process, sender);
        if suspended {
            process.set_force_yield(true);
            if let Some(dep) = process
                .runtime
                .and_then(|runtime| node_tables::port_dist_entry(runtime, port_id))
                && let Some(state) = dep
                    .lock()
                    .dist
                    .as_mut()
                    .filter(|state| state.port_id == Some(port_id))
            {
                state.suspended_senders.push(sender);
            }
            crate::natives::erts_debug::notify_busy_dist_port(process, sender, port_id);
        }
    }
    flush_port_output(process.runtime.as_ref().ok_or_else(badarg)?, port_id)
}

/// Queue distribution signals sent from port/controller paths that cannot suspend a process.
// Port of erts/emulator/beam/dist.c:3645-3653 (`ctx->no_suspend`), OTP-29.1.1.
fn enqueue_port_output_no_suspend_locked(
    state: &mut node_tables::DistState,
    packets: Vec<Vec<u8>>,
) {
    let packet_bytes: u64 = packets.iter().map(|packet| packet.len() as u64).sum();
    if state.fragment_continuations.is_empty() {
        state.output_ready_packets += packets.len();
    } else {
        state.pending_bytes = state.pending_bytes.saturating_sub(packet_bytes);
        state
            .fragment_continuations
            .push_back(node_tables::DistFragmentContinuation::new(
                None,
                packets.len(),
            ));
    }
    state.output.extend(packets);
    if state.pending_bytes >= state.busy_limit {
        state.busy = true;
    }
}

/// Continue a fragmented dist send at the start of the sender's next slice.
// Port of erts/emulator/beam/dist.c:3749-3753 (fragmented-send continuation), OTP-29.1.1.
/// Whether any distribution entry has a deferred fragmented send, so a slice must visit
/// [`continue_fragmented_send`].
#[inline]
pub(crate) fn fragment_continuation_pending() -> bool {
    node_tables::FRAGMENT_CONTINUATIONS.load(std::sync::atomic::Ordering::Acquire) != 0
}

pub(crate) fn continue_fragmented_send(
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
) -> Result<(), VmError> {
    // Called every scheduling iteration: skip the global node-table lock while no
    // distribution entry has a deferred fragmented send (erts keeps this per process).
    if !fragment_continuation_pending() {
        return Ok(());
    }
    let sender = ctx.pid();
    let send_count = (ctx.remaining() as usize / 10).max(1);
    let has_sender = |state: &DistState| {
        state
            .fragment_continuations
            .iter()
            .any(|continuation| continuation.sender == Some(sender))
    };
    let Some(dep) = node_tables::lock()
        .entries
        .values()
        .find(|dep| dep.lock().dist.as_ref().is_some_and(has_sender))
        .cloned()
    else {
        return Ok(());
    };
    let (port_id, packet_count, more) = {
        let mut entry = dep.lock();
        let Some(state) = entry.dist.as_mut().filter(|state| has_sender(state)) else {
            return Ok(());
        };
        let port_id = state.port_id.ok_or_else(badarg)?;
        if state
            .fragment_continuations
            .front()
            .is_none_or(|continuation| continuation.sender != Some(sender))
        {
            process.set_force_yield(true);
            return Ok(());
        }
        let count = state
            .fragment_continuations
            .front()
            .map(|continuation| continuation.remaining_packets.min(send_count))
            .unwrap_or(0);
        let start = state.output_ready_packets;
        let queued_bytes: u64 = state
            .output
            .iter()
            .skip(start)
            .take(count)
            .map(|packet| packet.len() as u64)
            .sum();
        state.pending_bytes = state.pending_bytes.saturating_add(queued_bytes);
        state.output_ready_packets += count;
        let continuation = state
            .fragment_continuations
            .front_mut()
            .ok_or_else(badarg)?;
        continuation.remaining_packets -= count;
        let more = continuation.remaining_packets != 0;
        if !more {
            state.fragment_continuations.pop_front();
        }
        while state
            .fragment_continuations
            .front()
            .is_some_and(|continuation| continuation.sender.is_none())
        {
            let count = state
                .fragment_continuations
                .front()
                .map(|continuation| continuation.remaining_packets)
                .unwrap_or(0);
            let start = state.output_ready_packets;
            let queued_bytes: u64 = state
                .output
                .iter()
                .skip(start)
                .take(count)
                .map(|packet| packet.len() as u64)
                .sum();
            state.pending_bytes = state.pending_bytes.saturating_add(queued_bytes);
            state.output_ready_packets += count;
            state.fragment_continuations.pop_front();
        }
        (port_id, count, more)
    };
    process.heap.abi.fcalls = (process.heap.abi.fcalls - (packet_count as i32 * 10)).max(1);
    ctx.consume(packet_count as u32 * 10);
    if more {
        process.set_force_yield(true);
    }
    let busy = {
        let dep = node_tables::port_dist_entry(process.runtime.ok_or_else(badarg)?, port_id);
        let mut entry = dep.as_ref().map(|dep| dep.lock());
        let Some(state) = entry
            .as_mut()
            .and_then(|entry| entry.dist.as_mut())
            .filter(|state| state.port_id == Some(port_id))
        else {
            return Err(badarg());
        };
        if state.pending_bytes >= state.busy_limit {
            state.busy = true;
            true
        } else {
            false
        }
    };
    if busy && suspend_dist_sender(process, sender) {
        process.set_force_yield(true);
        if let Some(dep) = process
            .runtime
            .and_then(|runtime| node_tables::port_dist_entry(runtime, port_id))
            && let Some(state) = dep
                .lock()
                .dist
                .as_mut()
                .filter(|state| state.port_id == Some(port_id))
        {
            state.suspended_senders.push(sender);
        }
        crate::natives::erts_debug::notify_busy_dist_port(process, sender, port_id);
    }
    flush_port_output(process.runtime.as_ref().ok_or_else(badarg)?, port_id)
}

/// Schedule the dist command task that drains the entry's queued buffers into its port.
///
/// Port of erts/emulator/beam/dist.c (erts_schedule_dist_command): the output goes out in
/// a `ERTS_PORT_TASK_DIST_CMD` task of the connection's port, at most one scheduled at a time.
fn flush_port_output(runtime: &crate::process::Runtime, port_id: u64) -> Result<(), VmError> {
    let claimed = {
        let dep = node_tables::port_dist_entry(runtime, port_id);
        let mut entry = dep.as_ref().map(|dep| dep.lock());
        let Some(state) = entry
            .as_mut()
            .and_then(|entry| entry.dist.as_mut())
            .filter(|state| state.port_id == Some(port_id))
        else {
            return Ok(());
        };
        if state.port_busy || state.flushing_output || state.output_ready_packets == 0 {
            false
        } else {
            state.flushing_output = true;
            true
        }
    };
    if !claimed {
        return Ok(());
    }
    let handle = runtime.ports.get(port_id);
    let (Some(drv), Some(task_runtime)) = (
        handle.as_ref().and_then(|handle| handle.drv_port()),
        handle.as_ref().and_then(|handle| handle.runtime()),
    ) else {
        // The port is gone: erts drops the data and the port exit tears the connection down
        // (dist.c, dist_port_exit / erts_do_net_exits), OTP-29.1.1.
        dist_cmd_done(runtime, port_id);
        return Ok(());
    };
    drv.schedule_dist_cmd(Box::new(move |op| {
        if op == arinsal_drv::port_task::SigOp::Exec {
            dist_cmd(task_runtime, port_id)
        } else {
            dist_cmd_done(task_runtime, port_id);
            0
        }
    }));
    Ok(())
}

/// The dist command task is no longer scheduled or running.
fn dist_cmd_done(runtime: &crate::process::Runtime, port_id: u64) {
    if let Some(dep) = node_tables::port_dist_entry(runtime, port_id)
        && let Some(state) = dep
            .lock()
            .dist
            .as_mut()
            .filter(|state| state.port_id == Some(port_id))
    {
        state.flushing_output = false;
    }
}

/// Packets one dist command task writes before it yields the scheduler.
const DIST_CMD_PACKETS: usize = 64;

/// Port of erts/emulator/beam/dist.c (erts_dist_command, dist_port_commandv) and dist.c:4161-4178
/// (drain queue and resume senders), OTP-29.1.1. Runs in the connection port's task with the
/// port locked; returns its reductions.
fn dist_cmd(runtime: &crate::process::Runtime, port_id: u64) -> i32 {
    let mut written = 0usize;
    loop {
        if written >= DIST_CMD_PACKETS {
            // Out of reductions: stay scheduled by queueing the next slice.
            let again = node_tables::port_dist_entry(runtime, port_id).is_some_and(|dep| {
                dep.lock()
                    .dist
                    .as_ref()
                    .filter(|state| state.port_id == Some(port_id))
                    .is_some_and(|state| !state.port_busy && state.output_ready_packets != 0)
            });
            dist_cmd_done(runtime, port_id);
            if again {
                let _ = flush_port_output(runtime, port_id);
            }
            break;
        }
        let packet = {
            let dep = node_tables::port_dist_entry(runtime, port_id);
            let mut entry = dep.as_ref().map(|dep| dep.lock());
            let Some(state) = entry
                .as_mut()
                .and_then(|entry| entry.dist.as_mut())
                .filter(|state| state.port_id == Some(port_id))
            else {
                return 0;
            };
            if state.port_busy || state.output_ready_packets == 0 {
                state.flushing_output = false;
                None
            } else {
                state.output.pop_front()
            }
        };
        let Some(packet) = packet else {
            break;
        };
        let sock = {
            runtime
                .ports
                .get(port_id)
                .and_then(|handle| handle.tcp_driver_data())
        };
        let port_busy = sock
            .and_then(|sock| crate::inet_drv::dist_output(&sock, &packet).ok())
            .unwrap_or_default();
        written += 1;
        let resumed = {
            let dep = node_tables::port_dist_entry(runtime, port_id);
            let mut entry = dep.as_ref().map(|dep| dep.lock());
            let Some(state) = entry
                .as_mut()
                .and_then(|entry| entry.dist.as_mut())
                .filter(|state| state.port_id == Some(port_id))
            else {
                return 0;
            };
            state.pending_bytes = state.pending_bytes.saturating_sub(packet.len() as u64);
            state.output_ready_packets = state.output_ready_packets.saturating_sub(1);
            state.port_busy = port_busy;
            if port_busy {
                state.flushing_output = false;
            }
            if state.busy && !state.port_busy && state.pending_bytes < state.busy_limit {
                state.busy = false;
                std::mem::take(&mut state.suspended_senders)
            } else {
                Vec::new()
            }
        };
        resume_dist_senders(runtime, resumed);
        if port_busy {
            break;
        }
    }
    i32::try_from(written * 40).unwrap_or(i32::MAX).min(4000)
}

/// Suspends a dist sender: the running process takes it on itself, another process receives it as a
/// signal (erts_suspend on a busy sender). True when the suspend was taken or sent.
fn suspend_dist_sender(process: &mut Process, sender: Pid) -> bool {
    if process.self_pid == Some(sender) {
        return crate::suspend::suspend_self_true(process);
    }
    process
        .runtime
        .as_ref()
        .is_some_and(|runtime| runtime.suspend_internal_remote(sender))
}

fn resume_dist_senders(runtime: &crate::process::Runtime, senders: Vec<Pid>) {
    let Ok(scheduler) = runtime.scheduler() else {
        return;
    };
    for sender in senders {
        if runtime.resume_internal(sender) {
            let _ = scheduler.wake(sender);
        }
    }
}

/// Reconcile the inet port's busy state with the dist entry queue and resume senders.
// Port of erts/emulator/beam/dist.c:4161-4178 (dist_port_command queue drain), OTP-29.1.1.
pub(crate) fn distribution_port_state_changed(
    runtime: &crate::process::Runtime,
    port_id: u64,
    port_busy: bool,
) {
    let (senders, needs_flush) = {
        let dep = node_tables::port_dist_entry(runtime, port_id);
        let mut entry = dep.as_ref().map(|dep| dep.lock());
        let Some(state) = entry
            .as_mut()
            .and_then(|entry| entry.dist.as_mut())
            .filter(|state| state.port_id == Some(port_id))
        else {
            return;
        };
        state.port_busy = port_busy;
        let senders = if state.busy && !port_busy && state.pending_bytes < state.busy_limit {
            state.busy = false;
            std::mem::take(&mut state.suspended_senders)
        } else {
            Vec::new()
        };
        (senders, !port_busy && state.output_ready_packets != 0)
    };
    if needs_flush {
        let _ = flush_port_output(runtime, port_id);
    }
    resume_dist_senders(runtime, senders);
}

/// When `target` is `{Name, Node}` and Node is this node, return the Name atom.
pub(crate) fn local_reg_name(target: Term) -> Result<Option<Term>, VmError> {
    let Some((name, node)) = name_node_tuple(target)? else {
        return Ok(None);
    };
    let local = arinsal_term::this_node().0;
    let local = global_atoms().text(local).ok_or_else(badarg)?;
    if node != local && node != "nonode@nohost" {
        return Ok(None);
    }
    let name = global_atoms().get(&name).ok_or_else(badarg)?;
    Ok(Some(Term::atom(name)))
}

pub(crate) fn name_node_tuple(target: Term) -> Result<Option<(String, String)>, VmError> {
    // do_send: a pid or an atom target never builds anything here.
    if arinsal_term::raw::Tuple2::try_from(target).is_err() {
        return Ok(None);
    }
    let owned = owned(target)?;
    let OwnedTerm::Tuple(ref parts) = owned else {
        return Ok(None);
    };
    if parts.len() != 2 {
        return Ok(None);
    }
    let (OwnedTerm::Atom(name), OwnedTerm::Atom(node)) = (&parts[0], &parts[1]) else {
        return Ok(None);
    };
    // Port of erts/emulator/beam/bif.c:2614-2626 (`do_send` accepts every arity-two atom tuple as a remote destination), OTP-29.1.1.
    Ok(Some((name.clone(), node.clone())))
}

fn send_to(
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    target: Term,
    message: Term,
) -> Result<(), VmError> {
    // Port of erts/emulator/beam/bif.c:2469-2480,2511 (do_send), OTP-29.1.1: internal pids
    // and atoms skip the remote-destination checks.
    let local_destination = target.as_pid_data().is_some() || target.as_atom().is_some();
    if !local_destination && try_remote_send(process, ctx, target, message)? {
        return Ok(());
    }
    process
        .send_message_prio(None, Some(ctx), target, message, false)
        .map(|_| ())
}

fn local_pid(term: &OwnedTerm, local: &str) -> Option<Pid> {
    // Port of erts/emulator/beam/external.c:3127-3141, OTP-29.1.1.
    let OwnedTerm::Pid {
        node,
        id,
        serial,
        creation,
    } = term
    else {
        return None;
    };
    let local_creation = node_tables::this_node().1;
    if !local_pid_matches(node, *creation, local, local_creation)
        || *id > arinsal_term::ptab::MAX_INTERNAL_PID_NUMBER
    {
        return None;
    }
    Some(Pid::new(*id, *serial))
}

fn local_pid_matches(node: &str, creation: u32, local: &str, local_creation: u32) -> bool {
    // Port of erts/emulator/beam/external.c:3127-3141, OTP-29.1.1.
    node == local && creation == local_creation
}

fn get_data_notification(ctx: &mut RunCtx<'_, Message>, handle: Term) -> Result<Term, VmError> {
    let handler = with_dhandle(handle, ctx.pid(), true, |state| {
        if state.output.is_empty() {
            state.notify = true;
            Ok(None)
        } else {
            Ok(Some(state.owner))
        }
    })?;
    if let Some(handler) = handler {
        ctx.send(
            handler,
            Message::copy_from(Term::atom(arinsal_term::atoms::DIST_DATA))?,
        )
        .map_err(|error| VmError::Unsupported(format!("dist data notification: {error}")))?;
    }
    Ok(Term::atom(arinsal_term::atoms::OK))
}

fn input_handler(
    ctx: &mut RunCtx<'_, Message>,
    handle: Term,
    handler: Term,
) -> Result<Term, VmError> {
    let handler = Pid::from_term(handler).ok_or_else(badarg)?;
    with_dhandle(handle, ctx.pid(), true, |state| {
        state.input_handler = handler;
        Ok(())
    })?;
    Ok(Term::atom(arinsal_term::atoms::OK))
}

fn get_opt(ctx: &mut RunCtx<'_, Message>, handle: Term, option: Term) -> Result<Term, VmError> {
    if atom_name(option).as_deref() != Some("get_size") {
        return Err(badarg());
    }
    let value = with_dhandle(handle, ctx.pid(), true, |state| Ok(state.get_size))?;
    Ok(boolean(value))
}

fn set_opt(
    ctx: &mut RunCtx<'_, Message>,
    handle: Term,
    option: Term,
    value: Term,
) -> Result<Term, VmError> {
    if atom_name(option).as_deref() != Some("get_size") {
        return Err(badarg());
    }
    let Some(value) = boolean_value(value) else {
        return Err(badarg());
    };
    let previous = with_dhandle(handle, ctx.pid(), true, |state| {
        let previous = state.get_size;
        state.get_size = value;
        Ok(previous)
    })?;
    Ok(boolean(previous))
}

fn get_stat(
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    handle: Term,
) -> Result<Term, VmError> {
    let (read, written, pending) = with_dhandle(handle, ctx.pid(), false, |state| {
        Ok((state.read, state.written, state.pending_bytes))
    })?;
    tuple(
        process,
        vec![
            Term::atom(arinsal_term::atoms::OK),
            integer(read),
            integer(written),
            integer(pending),
        ],
    )
}

fn with_dhandle<R>(
    handle: Term,
    caller: Pid,
    require_owner: bool,
    f: impl FnOnce(&mut DistState) -> Result<R, VmError>,
) -> Result<R, VmError> {
    let (conn_id, entry_ref) = parse_dhandle(handle)?;
    let dep = node_tables::lock()
        .dep_by_dhandle(conn_id, entry_ref)
        .ok_or_else(badarg)?;
    let mut entry = dep.lock();
    let state = entry.dist.as_mut().ok_or_else(badarg)?;
    if require_owner && state.owner != caller {
        return Err(badarg());
    }
    f(state)
}

fn with_dhandle_input<R>(
    handle: Term,
    caller: Pid,
    f: impl FnOnce(&mut DistState) -> Result<R, VmError>,
) -> Result<R, VmError> {
    let (conn_id, entry_ref) = parse_dhandle(handle)?;
    let dep = node_tables::lock()
        .dep_by_dhandle(conn_id, entry_ref)
        .ok_or_else(badarg)?;
    let mut entry = dep.lock();
    let state = entry.dist.as_mut().ok_or_else(badarg)?;
    if state.input_handler != caller {
        return Err(badarg());
    }
    f(state)
}

fn owned(term: Term) -> Result<OwnedTerm, VmError> {
    to_owned(term).map_err(|_| badarg())
}

fn tuple(process: &mut Process, values: Vec<Term>) -> Result<Term, VmError> {
    TermBuilder::new(&mut process.heap)
        .tuple(&values)
        .map_err(|_| badarg())
}

fn atom_name(term: Term) -> Option<String> {
    global_atoms()
        .text(term.as_atom()?)
        .map(|name| name.to_string())
}

fn boolean(value: bool) -> Term {
    Term::atom(if value {
        arinsal_term::atoms::TRUE
    } else {
        arinsal_term::atoms::FALSE
    })
}
fn boolean_value(term: Term) -> Option<bool> {
    match atom_name(term)?.as_str() {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    }
}
fn integer(value: u64) -> Term {
    Term::small(value as i64).expect("controller statistic fits small int")
}
fn as_u64(term: &OwnedTerm) -> Option<u64> {
    match term {
        OwnedTerm::Int(value) if *value >= 0 => Some(*value as u64),
        OwnedTerm::BigInt(v) => num_traits::ToPrimitive::to_u64(v),
        _ => None,
    }
}
fn as_u32(term: &OwnedTerm) -> Option<u32> {
    as_u64(term).and_then(|value| u32::try_from(value).ok())
}
fn badarg() -> VmError {
    VmError::Trap(crate::exceptions::Trap::error(Term::atom(
        arinsal_term::atoms::BADARG,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node_tables::DistState;

    const SEND_TO_MISSING_NODES: &str = r#"
-module(dist_missing_send_diff).
-export([run/0]).
run() ->
    Small = {unregistered_small, node()} ! small,
    Big = {unregistered_big, node()} ! lists:duplicate(4096, payload),
    Remote = {'unregistered_remote', abc@boromir} ! remote_payload,
    ExportFun = [fun blipp:blapp/7],
    MissingNode = {dummy, dummy@dummy} ! ExportFun,
    {Small, length(Big), Remote, MissingNode}.
"#;

    #[test]
    fn sends_to_missing_registered_names_match_otp() {
        let Ok(reference) = arinsal_difftest::RefErl::start() else {
            eprintln!(
                "erl unavailable; skipping missing distribution destination differential test"
            );
            return;
        };
        let beam = reference
            .compile_named("dist_missing_send_diff", SEND_TO_MISSING_NODES, &[])
            .unwrap();
        reference.load("dist_missing_send_diff", &beam).unwrap();
        let expected = reference.call("dist_missing_send_diff", "run", &[]);
        let mut vm = crate::Vm::new([]);
        vm.load_bytes(&beam).unwrap();
        let actual = vm
            .eval_scheduled("dist_missing_send_diff", "run", &[], 2, None)
            .unwrap();
        assert_eq!(expected, arinsal_difftest::CallResult::Ok(actual.term));
    }

    #[test]
    fn dist_state_starts_empty_with_connection_caches() {
        let state = DistState::new(11, Pid::new(1, 2), 0);
        assert!(state.output.is_empty());
        assert_eq!(state.pending_bytes, 0);
        assert_eq!(state.incoming_cache.get(0), None);
        assert_eq!(state.outgoing_cache.get(0), None);
    }

    #[test]
    fn dist_output_encodes_distribution_header_and_send_control() {
        let mut state = DistState::new(11, Pid::new(1, 2), 0);
        let control = OwnedTerm::tuple(vec![
            OwnedTerm::Int(2),
            OwnedTerm::Atom("from@host".into()),
            OwnedTerm::Atom("to@host".into()),
        ]);
        state.queue_term(control, Some(OwnedTerm::Int(9))).unwrap();
        let packet = state.output.pop_front().unwrap();
        assert_eq!(&packet[..2], &[131, 68]);
        let mut cache = arinsal_etf::AtomCache::new();
        let decoded = arinsal_etf::decode_dist_packet(&packet, &mut cache).unwrap();
        let terms = arinsal_etf::decode_dist_payload(&decoded).unwrap();
        assert_eq!(
            terms[0],
            OwnedTerm::tuple(vec![
                OwnedTerm::Int(2),
                OwnedTerm::Atom("from@host".into()),
                OwnedTerm::Atom("to@host".into())
            ])
        );
        assert_eq!(terms[1], OwnedTerm::Int(9));
    }

    #[test]
    fn dist_queue_accounts_for_pending_bytes() {
        let mut state = DistState::new(12, Pid::new(1, 0), 0);
        state
            .queue_term(OwnedTerm::tuple(vec![OwnedTerm::Int(2)]), None)
            .unwrap();
        assert_eq!(
            state.pending_bytes,
            state.output.front().unwrap().len() as u64
        );
    }

    #[test]
    fn dist_local_pid_requires_matching_node_and_creation() {
        assert!(local_pid_matches("node@host", 4, "node@host", 4));
        assert!(!local_pid_matches("remote@host", 4, "node@host", 4));
        assert!(!local_pid_matches("node@host", 5, "node@host", 4));
    }

    #[test]
    fn dist_get_size_option_accepts_only_booleans() {
        assert_eq!(
            boolean_value(Term::atom(arinsal_term::atoms::TRUE)),
            Some(true)
        );
        assert_eq!(
            boolean_value(Term::atom(arinsal_term::atoms::FALSE)),
            Some(false)
        );
        assert_eq!(boolean_value(Term::atom(arinsal_term::atoms::OK)), None);
    }

    #[test]
    fn dist_cached_round_trip_costs_by_payload_size() {
        use std::time::Instant;

        for size in [0_usize, 32, 128, 1024] {
            let message = OwnedTerm::Binary(vec![0x5a; size]);
            let control = OwnedTerm::tuple(vec![
                OwnedTerm::Int(2),
                OwnedTerm::Pid {
                    node: "peer@localhost".into(),
                    id: 17,
                    serial: 3,
                    creation: 4,
                },
                OwnedTerm::Pid {
                    node: "local@localhost".into(),
                    id: 29,
                    serial: 5,
                    creation: 4,
                },
            ]);
            let mut outgoing = arinsal_etf::AtomCache::new();
            let first =
                arinsal_etf::encode_dist_packet_terms(&[&control, &message], &mut outgoing, None);
            let mut input = arinsal_etf::AtomCache::new();
            let _ = arinsal_etf::decode_dist_packet(&first, &mut input).unwrap();
            let iterations = 200;
            let encode_started = Instant::now();
            for _ in 0..iterations {
                let _packet = arinsal_etf::encode_dist_packet_terms(
                    &[&control, &message],
                    &mut outgoing,
                    None,
                );
            }
            let encode_ns = encode_started.elapsed().as_nanos() / iterations;
            let packet =
                arinsal_etf::encode_dist_packet_terms(&[&control, &message], &mut outgoing, None);
            let _decoded = arinsal_etf::decode_dist_packet(&packet, &mut input).unwrap();
            let decode_started = Instant::now();
            for _ in 0..iterations {
                let decoded = arinsal_etf::decode_dist_packet(&packet, &mut input).unwrap();
                assert_eq!(arinsal_etf::decode_dist_payload(&decoded).unwrap().len(), 2);
            }
            let decode_ns = decode_started.elapsed().as_nanos() / iterations;
            eprintln!("dist payload={size} bytes encode_ns={encode_ns} decode_ns={decode_ns}");
            assert!(!first.is_empty());
        }
    }
}
