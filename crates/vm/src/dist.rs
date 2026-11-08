//! Distribution controller state and the VM side of the controller BIFs.
//!
//! Control tuples and packet framing follow `erts/emulator/beam/dist.c` in
//! OTP-29.1.1. Socket ownership remains in Erlang's distribution modules.

use crate::node_tables::{self, DistState};
use crate::process::Message;
use crate::{Process, Vm, VmError};
use arinsal_etf::{DistributionHeader, OwnedTerm};
use arinsal_sched::{Pid, RunCtx, Signal};
use arinsal_term::{Term, TermBuilder, from_owned, global_atoms, to_owned};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

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
static NEXT_UNLINK_ID: AtomicU64 = AtomicU64::new(1);

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

/// Port of erts/emulator/beam/dist.c:5543 (erts_internal_get_dflags_0), OTP-29.1.1.
fn get_dflags(process: &mut Process) -> Result<Term, VmError> {
    let mask = !node_tables::test_remove_dflags(None);
    if mask == u64::MAX {
        return Ok(arinsal_term::global_dflags_record(
            global_atoms()
                .intern("erts_dflags")
                .expect("distribution atom"),
            [
                integer(node_tables::DFLAG_DIST_DEFAULT),
                integer(node_tables::DFLAG_DIST_MANDATORY),
                integer(node_tables::DFLAG_DIST_ADDABLE),
                integer(node_tables::DFLAG_DIST_REJECTABLE),
                integer(node_tables::DFLAG_DIST_STRICT_ORDER),
            ],
        ));
    }
    tuple(
        process,
        vec![
            atom("erts_dflags"),
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
    let creation = node_tables::lock().local_creation;
    if crate::debug_env::trace_dist() {
        eprintln!("DIST_GET_CREATION {creation}");
    }
    if creation == 0 {
        Ok(atom("undefined"))
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
    let (result, spawn_downs) = {
        let mut tables = node_tables::lock();
        // The pending connection's spawn-pending monitors are cleaned up with it
        // (dist.c:5681 abort_pending_connection: schedule_con_monitor_link_seq_cleanup).
        let aborts = tables.entries.get(name.as_str()).is_some_and(|entry| {
            entry.entry_ref == entry_ref
                && entry.connection_id == conn_id
                && entry.state == node_tables::ConnState::Pending
        });
        let spawn_downs = if aborts {
            take_connection_spawn_requests(&mut tables, name)
        } else {
            Vec::new()
        };
        let result = tables
            .abort_pending(name, conn_id, entry_ref)
            .ok_or_else(badarg)?;
        (result, spawn_downs)
    };
    if let Some(runtime) = process.runtime {
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
    if crate::debug_env::trace_dist() {
        let tables = node_tables::lock();
        eprintln!(
            "DIST_HANDSHAKE local={} local_creation={} remote={} remote_creation={} flags={flags:#x}",
            tables.local_name, tables.local_creation, node, creation
        );
    }
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
    let entry = tables.entries.get_mut(node).ok_or_else(badarg)?;
    // Accept path may race ahead of new_connection; promote Idle → Pending.
    if entry.state == node_tables::ConnState::Idle {
        entry.connection_id = (entry.connection_id + 1) & 0x00ff_ffff;
        entry.state = node_tables::ConnState::Pending;
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
    let pending_monitors = std::mem::take(&mut entry.pending_monitors);
    let pending_spawn_requests = std::mem::take(&mut entry.pending_spawn_requests);
    entry.dist = Some(state);
    if let Some(state) = entry.dist.as_mut() {
        state.remote_monitors.extend(pending_monitors);
        state.spawn_requests.extend(pending_spawn_requests);
    }
    if let Some(port_id) = port_controller {
        node_tables::register_dist_port(port_id, node.clone());
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
        ctx.send(handler, Message::copy_from(atom("dist_data"))?)
            .map_err(|error| VmError::Unsupported(format!("dist data notification: {error}")))?;
    }
    let dhandle = dhandle_term(process, conn_id, entry_ref)?;
    tuple(process, vec![atom("ok"), dhandle])
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
            atom("dist_ctrlr"),
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
        return Ok(atom("none"));
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
    let local_name = node_tables::lock().local_name.clone();
    let (handle_id, decoded) = with_dhandle_input(handle, ctx.pid(), |state| {
        state.read = state.read.saturating_add(1);
        let packet = arinsal_etf::decode_dist_packet(&bytes, &mut state.incoming_cache)
            .map_err(|_| badarg())?;
        let DistributionHeader::Start { .. } = packet.header else {
            return Ok((state.handle, Vec::new()));
        };
        let decoded = arinsal_etf::decode_dist_payload(&packet).map_err(|_| badarg())?;
        Ok((state.handle, decoded))
    })?;
    route_incoming(vm, process, ctx, handle_id, &local_name, decoded)?;
    Ok(atom("ok"))
}

fn route_incoming(
    vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    handle: u64,
    local: &str,
    mut terms: Vec<OwnedTerm>,
) -> Result<(), VmError> {
    if terms.is_empty() {
        return Ok(());
    }
    let control = terms.remove(0);
    let OwnedTerm::Tuple(parts) = &control else {
        return Err(badarg());
    };
    let Some(OwnedTerm::Int(op)) = parts.first() else {
        return Err(badarg());
    };
    if crate::debug_env::trace_dist() {
        let tables = node_tables::lock();
        let destination = match *op {
            2 | 12 | 22 | 23 => parts.get(2),
            6 => parts.get(3),
            33 | 34 => parts.get(2),
            _ => None,
        };
        eprintln!(
            "DIST_RX op={op} node={} creation={} destination={destination:?}",
            tables.local_name, tables.local_creation
        );
    }
    match *op {
        // Port of dist.c:2519 (DOP_SEND), OTP-29.1.1.
        // Port of erts/emulator/beam/dist.c:2509-2539, OTP-29.1.1.
        2 | 22 if parts.len() == 3 => {
            let target = local_pid(&parts[2], local).ok_or_else(badarg)?;
            for term in terms {
                let message = from_owned(&term, &mut process.heap).map_err(|_| badarg())?;
                ctx.send(target, Message::copy_from(message)?)
                    .map_err(|error| VmError::Unsupported(format!("dist send: {error}")))?;
            }
        }
        12 | 23 if parts.len() == 4 => {
            let target = local_pid(&parts[2], local).ok_or_else(badarg)?;
            for term in terms {
                let message = from_owned(&term, &mut process.heap).map_err(|_| badarg())?;
                ctx.send(target, Message::copy_from(message)?)
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
            for term in terms {
                let message = from_owned(&term, &mut process.heap).map_err(|_| badarg())?;
                ctx.send(target, Message::copy_from(message)?)
                    .map_err(|error| VmError::Unsupported(format!("dist send: {error}")))?;
            }
        }
        1 if parts.len() == 3 => {
            let from = remote_proxy(handle, &parts[1])?;
            let target = local_pid(&parts[2], local).ok_or_else(badarg)?;
            publish_remote_signal(process, from, target, Signal::Link { priority: false })?;
        }
        3 | 8 | 24 | 26 if parts.len() >= 3 => {
            let from = remote_proxy(handle, &parts[1])?;
            let target = local_pid(&parts[2], local).ok_or_else(badarg)?;
            let reason = if parts.len() == 4 {
                &parts[3]
            } else {
                terms.first().ok_or_else(badarg)?
            };
            let reason = from_owned(reason, &mut process.heap).map_err(|_| badarg())?;
            publish_remote_signal(
                process,
                from,
                target,
                Signal::Exit(Box::new(Message::copy_from(reason)?)),
            )?;
        }
        35 if parts.len() == 4 => {
            let unlink_id = as_u64(&parts[1]).ok_or_else(badarg)?;
            let from = remote_proxy(handle, &parts[2])?;
            let target = local_pid(&parts[3], local).ok_or_else(badarg)?;
            publish_remote_signal(process, from, target, Signal::Unlink(unlink_id))?;
            queue_remote_control(
                process,
                ctx,
                handle,
                OwnedTerm::tuple(vec![
                    OwnedTerm::Int(36),
                    OwnedTerm::Int(unlink_id as i64),
                    parts[3].clone(),
                    parts[2].clone(),
                ]),
            )?;
        }
        36 if parts.len() == 4 => {
            let unlink_id = as_u64(&parts[1]).ok_or_else(badarg)?;
            let from = remote_proxy(handle, &parts[2])?;
            let target = local_pid(&parts[3], local).ok_or_else(badarg)?;
            publish_remote_signal(process, from, target, Signal::UnlinkAck(unlink_id))?;
        }
        19 | 20 if parts.len() == 4 => {
            let watcher = remote_proxy(handle, &parts[1])?;
            let target = local_pid(&parts[2], local).ok_or_else(badarg)?;
            let reference = remote_ref_id(&parts[3]).ok_or_else(badarg)?;
            remember_remote_monitor_ref(handle, reference, &parts[3], *op == 19)?;
            publish_remote_signal(
                process,
                watcher,
                target,
                if *op == 19 {
                    crate::proc_create::remote_monitor_signal(reference, watcher, target)
                } else {
                    Signal::Demonitor(reference)
                },
            )?;
        }
        21 | 28 if (parts.len() == 5 && *op == 21) || (parts.len() == 4 && *op == 28) => {
            let target_owned = &parts[1];
            let watcher = local_pid(&parts[2], local).ok_or_else(badarg)?;
            let reference = remote_ref_id(&parts[3]).ok_or_else(badarg)?;
            let reason = if *op == 21 {
                &parts[4]
            } else {
                terms.first().ok_or_else(badarg)?
            };
            let from = remote_proxy(handle, target_owned)?;
            let reason = from_owned(reason, &mut process.heap).map_err(|_| badarg())?;
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
                for term in terms {
                    let message = from_owned(&term, &mut process.heap).map_err(|_| badarg())?;
                    ctx.send(target, Message::copy_from(message)?.with_alias(reference))
                        .map_err(|error| {
                            VmError::Unsupported(format!("dist alias send: {error}"))
                        })?;
                }
            }
        }
        29 if parts.len() == 6 && terms.len() == 1 => {
            handle_spawn_request(vm, process, ctx, handle, parts, &terms[0])?;
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
    let mut tables = node_tables::lock();
    let local_creation = tables.local_creation;
    let entry = tables
        .entries
        .values_mut()
        .find(|entry| {
            entry.name == *node
                && entry
                    .dist
                    .as_ref()
                    .is_some_and(|state| state.handle == handle)
        })
        .ok_or_else(badarg)?;
    let state = entry.dist.as_mut().ok_or_else(badarg)?;
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
        let mut tables = node_tables::lock();
        tables
            .entries
            .values()
            .find_map(|entry| entry.dist.as_ref()?.proxy_to_remote.get(&proxy).cloned())
            .or_else(|| tables.disconnected_monitor_pids.remove(&proxy))
    };
    remote
        .map(|pid| from_owned(&pid, &mut process.heap).map_err(|_| badarg()))
        .transpose()
}

/// Discard a closed-connection proxy when its DOWN raced with demonitor or process exit.
pub(crate) fn discard_disconnected_monitor_pid(proxy: Pid) {
    node_tables::lock().disconnected_monitor_pids.remove(&proxy);
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
    let mut tables = node_tables::lock();
    let local_name = tables.local_name.clone();
    let local_creation = tables.local_creation;
    let control = node_tables::relabel_local_node(control, &local_name, local_creation);
    let entry = tables
        .entries
        .values_mut()
        .find(|entry| {
            entry
                .dist
                .as_ref()
                .is_some_and(|state| state.handle == handle)
        })
        .ok_or_else(badarg)?;
    let state = entry.dist.as_mut().expect("matched dist state");
    if let Some(port_id) = state.port_id {
        let packets = state.encode_term(control, None).map_err(|_| badarg())?;
        state.written = state.written.saturating_add(1);
        enqueue_port_output_no_suspend_locked(state, packets);
        drop(tables);
        let runtime = process.runtime.ok_or_else(badarg)?;
        return flush_port_output(runtime, port_id);
    }
    state.queue_term(control, None).map_err(|_| badarg())?;
    let notify = state.notify.then_some(state.owner);
    state.notify = false;
    drop(tables);
    if let Some(handler) = notify {
        ctx.send(handler, Message::copy_from(atom("dist_data"))?)
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
    match queue_outgoing_with_options(process, ctx, node, control, message, true, true)? {
        DistSendResult::Queued => Ok(()),
        DistSendResult::NotConnected | DistSendResult::WouldSuspend => Err(badarg()),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DistSendResult {
    Queued,
    NotConnected,
    WouldSuspend,
}

// Port of erts/emulator/beam/dist.c:3216-3280 (erts_dsig_prepare), OTP-29.1.1.
fn queue_outgoing_with_options(
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    node: &str,
    control: OwnedTerm,
    message: Option<OwnedTerm>,
    connect: bool,
    suspend: bool,
) -> Result<DistSendResult, VmError> {
    if crate::debug_env::trace_dist()
        && matches!(&control, OwnedTerm::Tuple(parts) if matches!(parts.first(), Some(OwnedTerm::Int(6))) && matches!(parts.get(3), Some(OwnedTerm::Atom(name)) if name == "global_name_server"))
    {
        eprintln!("DIST_TX_GLOBAL node={node} control={control:?} message={message:?}");
    }
    let mut tables = node_tables::lock();
    if !tables.alive {
        return Ok(DistSendResult::NotConnected);
    }
    let local_name = tables.local_name.clone();
    let local_creation = tables.local_creation;
    if node == local_name {
        return Err(badarg());
    }
    let control = node_tables::relabel_local_node(control, &local_name, local_creation);
    let message = message.map(|m| node_tables::relabel_local_node(m, &local_name, local_creation));
    // Port of dist.c:3260 (erts_auto_connect on Idle), OTP-29.1.1.
    let was_idle = match tables.entries.get(node) {
        Some(entry) if entry.state == node_tables::ConnState::Exiting => {
            return Ok(DistSendResult::NotConnected);
        }
        Some(entry) => entry.state == node_tables::ConnState::Idle,
        None => true,
    };
    if was_idle && !connect {
        return Ok(DistSendResult::NotConnected);
    }
    let (conn_id, entry_ref) = if was_idle {
        tables.new_connection(node).ok_or_else(badarg)?
    } else {
        let entry = tables.entries.get(node).ok_or_else(badarg)?;
        (entry.connection_id, entry.entry_ref)
    };
    let entry = tables.entries.get_mut(node).ok_or_else(badarg)?;

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
            drop(tables);
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
        drop(tables);
        if let Some(handler) = notify {
            ctx.send(handler, Message::copy_from(atom("dist_data"))?)
                .map_err(|error| {
                    VmError::Unsupported(format!("dist data notification: {error}"))
                })?;
        }
        let _ = process;
        return Ok(DistSendResult::Queued);
    }

    // Pending (or Connected without a controller yet): buffer until channel is up.
    entry.pending_out.push_back((control, message));
    let notify = was_idle.then(|| (node.to_string(), conn_id, entry_ref));
    drop(tables);
    if let Some((node, conn_id, entry_ref)) = notify {
        notify_auto_connect(process, ctx, &node, conn_id, entry_ref)?;
    }
    Ok(DistSendResult::Queued)
}

/// Port of erts/emulator/beam/dist.c:5713 (erts_auto_connect), OTP-29.1.1.
fn notify_auto_connect(
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    node: &str,
    conn_id: u32,
    entry_ref: u64,
) -> Result<(), VmError> {
    let runtime = process.runtime.as_ref().ok_or_else(badarg)?;
    let Some(net_kernel) = runtime.reg.whereis_proc_str("net_kernel") else {
        let _ = node_tables::lock().abort_pending(node, conn_id, entry_ref);
        return Err(badarg());
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
    Ok(())
}

/// Ingest one length-delimited distribution packet from a DistCtrlr inet port.
///
/// Port of erts/emulator/beam/dist.c:2017 (erts_net_message), OTP-29.1.1.
pub(crate) fn ingest_port_data(
    runtime: &'static crate::process::Runtime,
    port_id: u64,
    bytes: &[u8],
) -> Result<(), VmError> {
    // A zero-length body is a distribution tick (packet header length 0).
    if bytes.is_empty() {
        return Ok(());
    }
    if crate::debug_env::trace_dist() {
        eprintln!("DIST_FRAME port={port_id} bytes={}", bytes.len());
    }
    let local_name = node_tables::lock().local_name.clone();
    let (handle, decoded) = {
        let mut tables = node_tables::lock();
        let entry = tables
            .entries
            .values_mut()
            .find(|entry| {
                entry
                    .dist
                    .as_ref()
                    .is_some_and(|state| state.port_id == Some(port_id))
            })
            .ok_or_else(badarg)?;
        let state = entry.dist.as_mut().ok_or_else(badarg)?;
        state.read = state.read.saturating_add(1);
        let packet =
            arinsal_etf::decode_dist_packet(bytes, &mut state.incoming_cache).map_err(|error| {
                if crate::debug_env::trace_dist() {
                    eprintln!("DIST_DECODE_HEADER_ERROR {error:?} bytes={}", bytes.len());
                }
                badarg()
            })?;
        let Some(packet) = reassemble_port_fragment(state, packet)? else {
            return Ok(());
        };
        let decoded = arinsal_etf::decode_dist_payload(&packet).map_err(|error| {
            if crate::debug_env::trace_dist() {
                eprintln!(
                    "DIST_DECODE_PAYLOAD_ERROR {error:?} payload={}",
                    packet.payload.len()
                );
            }
            badarg()
        })?;
        (state.handle, decoded)
    };
    route_incoming_port(runtime, handle, &local_name, decoded)
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
    port_id: u64,
) -> Result<(), VmError> {
    if crate::debug_env::trace_dist() {
        eprintln!("DIST_PORT_CLOSED port={port_id}");
    }
    let Some(node) = node_tables::unregister_dist_port(port_id) else {
        return Ok(());
    };
    let (watchers, node_events, monitor_downs, spawn_downs) = {
        let mut tables = node_tables::lock();
        let is_current_port = tables
            .entries
            .get(&node)
            .and_then(|entry| entry.dist.as_ref())
            .is_some_and(|state| state.port_id == Some(port_id));
        // Port of erts/emulator/beam/dist.c:3599-3611 (discard output from an obsolete connection), OTP-29.1.1.
        if !is_current_port {
            return Ok(());
        }
        let connection_id = tables
            .entries
            .get(&node)
            .map(|entry| entry.connection_id)
            .unwrap_or(u32::MAX);
        let visible = tables.entries.get(&node).is_some_and(|entry| entry.visible);
        let monitor_downs = take_connection_monitors(&mut tables, &node);
        let spawn_downs = take_connection_spawn_requests(&mut tables, &node);
        let watchers = tables.disconnect(&node);
        let events = tables.nodes_monitor_events(
            "nodedown",
            &node,
            connection_id,
            visible,
            Some("connection_closed"),
        );
        (watchers, events, monitor_downs, spawn_downs)
    };
    notify_node_watchers(runtime, &node, watchers)?;
    notify_connection_monitors(runtime, monitor_downs)?;
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
    if crate::debug_env::trace_dist() {
        eprintln!("DIST_KILL_CONNECTION node={node} connection_id={connection_id}");
    }
    let (watchers, node_events, monitor_downs, spawn_downs) = {
        let mut tables = node_tables::lock();
        let Some(entry) = tables.entries.get(node) else {
            return Ok(false);
        };
        if !entry.connected || entry.connection_id != connection_id {
            return Ok(false);
        }
        let visible = entry.visible;
        let monitor_downs = take_connection_monitors(&mut tables, node);
        let spawn_downs = take_connection_spawn_requests(&mut tables, node);
        let watchers = tables.disconnect(node);
        let events =
            tables.nodes_monitor_events("nodedown", node, connection_id, visible, Some("killed"));
        (watchers, events, monitor_downs, spawn_downs)
    };
    notify_node_watchers(runtime, node, watchers)?;
    notify_connection_monitors(runtime, monitor_downs)?;
    notify_connection_spawn_requests(runtime, spawn_downs)?;
    send_nodes_monitor_events(runtime, node_events)?;
    Ok(true)
}

fn notify_node_watchers(
    runtime: &crate::process::Runtime,
    node: &str,
    watchers: Vec<node_tables::NodeMonitor>,
) -> Result<(), VmError> {
    let node_atom = atom(node);
    let sched = runtime.scheduler()?;
    for watcher in watchers {
        let mut heap = arinsal_term::ProcessHeap::with_words(16);
        let term = TermBuilder::new(&mut heap)
            .tuple(&[atom("nodedown"), node_atom])
            .map_err(|_| badarg())?;
        let message = Message::copy_from(term)?;
        let _ = sched.send(watcher.pid, watcher.pid, message);
    }
    Ok(())
}

struct ConnectionMonitorDown {
    watcher: Pid,
    proxy: Pid,
    reference: u64,
}

/// Prepare one local monitor-down signal per remote monitor before dropping the connection tree.
// Port of erts/emulator/beam/dist.c (`monitor_connection_down`), OTP-29.1.1.
fn take_connection_monitors(
    tables: &mut node_tables::NodeTables,
    node: &str,
) -> Vec<ConnectionMonitorDown> {
    let local_creation = tables.local_creation;
    let Some(entry) = tables.entries.get_mut(node) else {
        return Vec::new();
    };
    let mut monitors = std::mem::take(&mut entry.pending_monitors);
    if let Some(state) = entry.dist.as_mut() {
        monitors.append(&mut state.remote_monitors);
    }
    if !monitors.is_empty() {
        PROXIES_CREATED.store(true, Ordering::Release);
    }
    if crate::debug_env::trace_dist() {
        eprintln!(
            "DIST_MONITOR_CONNECTION_DOWN node={node} monitors={}",
            monitors.len()
        );
    }
    monitors
        .into_iter()
        .map(|(reference, monitor)| {
            let proxy = Pid::new(
                NEXT_REMOTE_PID.fetch_add(1, Ordering::Relaxed) & ((1 << 28) - 1),
                local_creation,
            );
            tables
                .disconnected_monitor_pids
                .insert(proxy, monitor.target);
            ConnectionMonitorDown {
                watcher: monitor.watcher,
                proxy,
                reference,
            }
        })
        .collect()
}

/// Deliver `noconnection` through the same monitor signal path used for remote process exits.
fn notify_connection_monitors(
    runtime: &crate::process::Runtime,
    monitors: Vec<ConnectionMonitorDown>,
) -> Result<(), VmError> {
    let scheduler = runtime.scheduler()?;
    for monitor in monitors {
        let reason = Message::copy_from(atom("noconnection"))?;
        if scheduler
            .signal(
                monitor.proxy,
                monitor.watcher,
                Signal::MonitorDown {
                    reference: monitor.reference,
                    reason: Box::new(reason),
                },
            )
            .is_err()
        {
            discard_disconnected_monitor_pid(monitor.proxy);
        }
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
    let Some(entry) = tables.entries.get_mut(node) else {
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
        vec![tag, reference, atom("error"), atom("noconnection")],
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
    mut terms: Vec<OwnedTerm>,
) -> Result<(), VmError> {
    if terms.is_empty() {
        return Ok(());
    }
    let control = terms.remove(0);
    let OwnedTerm::Tuple(parts) = &control else {
        return Err(badarg());
    };
    let Some(OwnedTerm::Int(op)) = parts.first() else {
        return Err(badarg());
    };
    if crate::debug_env::trace_dist() {
        let tables = node_tables::lock();
        let destination = match *op {
            2 | 12 | 22 | 23 => parts.get(2),
            6 => parts.get(3),
            33 | 34 => parts.get(2),
            _ => None,
        };
        eprintln!(
            "DIST_RX_PORT op={op} arity={} node={} creation={} destination={destination:?}",
            parts.len(),
            tables.local_name,
            tables.local_creation
        );
        if matches!(*op, 28 | 31 | 32) {
            eprintln!("DIST_RX_PORT_CONTROL {control:?} payload={terms:?}");
        }
        if *op == 6
            && matches!(parts.get(3), Some(OwnedTerm::Atom(name)) if name == "global_name_server")
        {
            eprintln!("DIST_RX_GLOBAL control={control:?} payload={terms:?}");
        }
    }
    let sched = runtime.scheduler()?;
    match *op {
        // Port of erts/emulator/beam/dist.c:2509-2539, OTP-29.1.1.
        2 | 22 if parts.len() == 3 => {
            let target = local_pid(&parts[2], local).ok_or_else(badarg)?;
            for term in terms {
                let message = owned_to_message(&term)?;
                sched
                    .send(target, target, message)
                    .map_err(|error| VmError::Unsupported(format!("dist send: {error}")))?;
            }
        }
        12 | 23 if parts.len() == 4 => {
            let target = local_pid(&parts[2], local).ok_or_else(badarg)?;
            for term in terms {
                let message = owned_to_message(&term)?;
                sched
                    .send(target, target, message)
                    .map_err(|error| VmError::Unsupported(format!("dist send: {error}")))?;
            }
        }
        6 if parts.len() == 4 => {
            let OwnedTerm::Atom(name) = &parts[3] else {
                return Err(badarg());
            };
            let target = runtime.reg.whereis_proc_str(name).ok_or_else(badarg)?;
            for term in terms {
                let message = owned_to_message(&term)?;
                sched
                    .send(target, target, message)
                    .map_err(|error| VmError::Unsupported(format!("dist send: {error}")))?;
            }
        }
        1 if parts.len() == 3 => {
            let from = remote_proxy(handle, &parts[1])?;
            let target = local_pid(&parts[2], local).ok_or_else(badarg)?;
            sched
                .signal(from, target, Signal::Link { priority: false })
                .map_err(|error| VmError::Unsupported(format!("incoming dist signal: {error}")))?;
        }
        // Port of erts/emulator/beam/dist.c:2509-2539 (DOP_EXIT and
        // DOP_EXIT2), OTP-29.1.1. Payload exits carry the reason outside the
        // control tuple so large reasons can use fragmented distribution frames.
        3 | 8 | 24 | 26 if parts.len() >= 3 => {
            let from = remote_proxy(handle, &parts[1])?;
            let target = local_pid(&parts[2], local).ok_or_else(badarg)?;
            let reason = if parts.len() == 4 {
                &parts[3]
            } else {
                terms.first().ok_or_else(badarg)?
            };
            let reason = owned_to_message(reason)?;
            sched
                .signal(from, target, Signal::Exit(Box::new(reason)))
                .map_err(|error| VmError::Unsupported(format!("incoming dist signal: {error}")))?;
        }
        // Port of dist.c:2341 (DOP_MONITOR_P); ToProc may be a pid or registered name.
        19 | 20 if parts.len() == 4 => {
            let watcher = remote_proxy(handle, &parts[1])?;
            let target = match &parts[2] {
                OwnedTerm::Atom(name) => runtime.reg.whereis_proc_str(name),
                other => local_pid(other, local),
            };
            let reference = remote_ref_id(&parts[3]).ok_or_else(badarg)?;
            remember_remote_monitor_ref(handle, reference, &parts[3], *op == 19)?;
            if let Some(target) = target {
                let signal = if *op == 19 {
                    crate::proc_create::remote_monitor_signal(reference, watcher, target)
                } else {
                    Signal::Demonitor(reference)
                };
                sched.signal(watcher, target, signal).map_err(|error| {
                    VmError::Unsupported(format!("incoming dist signal: {error}"))
                })?;
            }
            // Missing local name/pid: OTP replies with MONITOR_P_EXIT noproc; deferred.
        }
        // Port of dist.c (DOP_MONITOR_P_EXIT / payload exit).
        21 | 28 if (parts.len() == 5 && *op == 21) || (parts.len() == 4 && *op == 28) => {
            let target_owned = &parts[1];
            let watcher = local_pid(&parts[2], local).ok_or_else(badarg)?;
            let reference = remote_ref_id(&parts[3]).ok_or_else(badarg)?;
            let reason = if *op == 21 {
                &parts[4]
            } else {
                terms.first().ok_or_else(badarg)?
            };
            let from = remote_proxy(handle, target_owned)?;
            let reason_msg = owned_to_message(reason)?;
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
                for term in terms {
                    let message = owned_to_message(&term)?.with_alias(reference);
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
            let (target, alias) = if flags & FLG_ALIAS != 0 {
                let reference = remote_ref_id(&parts[3]).ok_or_else(badarg)?;
                (remote_alias_pid(&parts[3]), Some(reference))
            } else if flags & FLG_NAME != 0 {
                let OwnedTerm::Atom(name) = &parts[3] else {
                    return Err(badarg());
                };
                (runtime.reg.whereis_proc_str(name), None)
            } else {
                (local_pid(&parts[3], local), None)
            };
            if let Some(target) = target {
                for term in terms {
                    let mut message = owned_to_message(&term)?;
                    if let Some(alias) = alias {
                        message = message.with_alias(alias);
                    }
                    if flags & FLG_PRIO != 0 {
                        message = message.with_priority();
                    }
                    let result = if flags & FLG_EXIT != 0 {
                        sched.signal(from, target, Signal::Exit(Box::new(message)))
                    } else {
                        sched.send(from, target, message)
                    };
                    result.map_err(|error| {
                        VmError::Unsupported(format!("dist altact send: {error}"))
                    })?;
                }
            }
        }
        // Port of dist.c:2885 (DOP_SPAWN_REQUEST) / DOP_SPAWN_REPLY on Port DistCtrlr.
        29 if parts.len() == 6 && terms.len() == 1 => {
            handle_spawn_request_port(runtime, handle, local, parts, &terms[0])?;
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
    let local = node_tables::lock().local_name.clone();
    let term = internalize_local_node(term.clone(), &local);
    let mut heap = arinsal_term::ProcessHeap::with_words(256);
    let term = from_owned(&term, &mut heap).map_err(|_| badarg())?;
    Message::copy_from(term)
}

/// Convert peer-encoded local identities back to internal `nonode@nohost` form
/// so they compare equal to locally created pids/refs (OTP external.c decode).
fn internalize_local_node(mut term: OwnedTerm, local: &str) -> OwnedTerm {
    match &mut term {
        OwnedTerm::Pid { node, creation, .. }
        | OwnedTerm::Port { node, creation, .. }
        | OwnedTerm::Ref { node, creation, .. }
            if node.as_str() == local =>
        {
            *node = "nonode@nohost".into();
            *creation = 0;
        }
        OwnedTerm::Tuple(parts) => {
            for part in parts.iter_mut() {
                let taken = std::mem::replace(part, OwnedTerm::Nil);
                *part = internalize_local_node(taken, local);
            }
        }
        OwnedTerm::List { elems, tail } => {
            for elem in elems.iter_mut() {
                let taken = std::mem::replace(elem, OwnedTerm::Nil);
                *elem = internalize_local_node(taken, local);
            }
            let taken = std::mem::replace(tail.as_mut(), OwnedTerm::Nil);
            *tail.as_mut() = internalize_local_node(taken, local);
        }
        OwnedTerm::Map(entries) => {
            for (key, value) in entries.iter_mut() {
                let taken_k = std::mem::replace(key, OwnedTerm::Nil);
                *key = internalize_local_node(taken_k, local);
                let taken_v = std::mem::replace(value, OwnedTerm::Nil);
                *value = internalize_local_node(taken_v, local);
            }
        }
        OwnedTerm::Record { fields, .. } => {
            for (_, value) in fields {
                let taken = std::mem::replace(value, OwnedTerm::Nil);
                *value = internalize_local_node(taken, local);
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
        let mut tables = node_tables::lock();
        if let Some(entry) = tables.entries.get_mut(&node) {
            let request = request.take().expect("request present");
            if let Some(state) = entry.dist.as_mut() {
                state.spawn_requests.insert(id, request);
            } else {
                entry.pending_spawn_requests.insert(id, request);
            }
        }
    }
    if let Err(error) = queue_outgoing(process, ctx, &node, control, Some(values[2].clone())) {
        let mut tables = node_tables::lock();
        if let Some(entry) = tables.entries.get_mut(&node) {
            entry.pending_spawn_requests.remove(&id);
            if let Some(state) = entry.dist.as_mut() {
                state.spawn_requests.remove(&id);
            }
        }
        return Err(error);
    }
    if let Some(request) = request {
        let mut tables = node_tables::lock();
        let entry = tables.entries.get_mut(&node).ok_or_else(badarg)?;
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
    /// `datap->link`: the proxy of the child of a successful spawn with link.
    link: Option<Pid>,
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

    /// `datap->link`.
    pub(crate) fn link(&self) -> Option<Pid> {
        self.link
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
            .find(|entry| {
                entry
                    .dist
                    .as_ref()
                    .is_some_and(|state| state.handle == handle)
            })
            .map(|entry| entry.name.clone());
        (tables.local_name.clone(), node)
    };
    let Some(node) = node else {
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
    // Successful spawn-link: the link the parent inserts (erts_link_external_create).
    let link = child.filter(|_| flags & DIST_SPAWN_FLAG_LINK != 0);
    let data = std::sync::Arc::new(DistSpawnReplyData {
        handle,
        id,
        reference: parts[1].clone(),
        parent: parts[2].clone(),
        result,
        flags,
        link,
    });
    if data.monitor() {
        // The distribution half of the spawn monitor, which erts creates with the request
        // (dist.c:6112 erts_internal_dist_spawn_request_4): it routes the child's DOWN.
        remember_monitor(&node, id, parent, data.result.clone())?;
    }
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
        let _ = take_monitor(data.id);
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
        let mut tables = node_tables::lock();
        let Some(state) = tables
            .entries
            .values_mut()
            .find_map(|entry| entry.dist.as_mut().filter(|state| state.handle == handle))
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
    let mut tables = node_tables::lock();
    for entry in tables.entries.values_mut() {
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
    if data.monitor() {
        let _ = take_monitor(data.id);
    }
}

/// Mark the live pending request `id` of `parent` abandoned, or drop it when it has no link.
/// Returns false when `id` is not an outstanding request of `parent`.
///
/// Port of erts/emulator/beam/bif.c:1166 (spawn_request_abandon_1), OTP-29.1.1, for a
/// distributed request: one with link is left for the reply, which sends the child an
/// `abandoned` exit (erl_proc_sig_queue.c:5786-5830).
pub(crate) fn spawn_request_abandon(parent: Pid, id: u64) -> bool {
    let mut tables = node_tables::lock();
    for entry in tables.entries.values_mut() {
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
        .tuple(&[tag, reference, crate::signals::atom(status), result])
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
        let mut tables = node_tables::lock();
        let mut found = None;
        for entry in tables.entries.values_mut() {
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
        let _ = take_monitor(data.id);
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
    if let Some(child) = data.link {
        // erts_proc_exit_handle_link: the link exit carries the actual reason, unless the
        // operation was abandoned.
        let reason = if request.abandoned {
            atom("abandoned")
        } else {
            reason
        };
        forward_link_exit_if_proxy(runtime, child, parent, reason);
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
    let mut tables = node_tables::lock();
    for entry in tables.entries.values_mut() {
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
        let mut tables = node_tables::lock();
        let local = (tables.local_name.clone(), tables.local_creation);
        for entry in tables.entries.values_mut() {
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
    let local_name = node_tables::lock().local_name.clone();
    let arguments = internalize_local_node(arguments.clone(), &local_name);
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
        let watcher = (monitor || link)
            .then(|| remote_proxy(handle, &from))
            .transpose()?;
        let monitor_ref = if monitor {
            remote_ref_id(&reference)
        } else {
            None
        };
        let child = runtime.spawn_mfa_unscheduled_watched(
            module,
            function,
            &args,
            link.then_some(watcher).flatten(),
            watcher.zip(monitor_ref),
            &from,
        );
        if let Ok(child) = child {
            result = local_pid_owned(child);
            child_to_schedule = Some(child);
            if let Some(ref_id) = monitor_ref {
                remember_remote_monitor_ref(handle, ref_id, &reference, true)?;
            }
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
    if crate::debug_env::trace_dist() {
        let tables = node_tables::lock();
        eprintln!(
            "DIST_SPAWN_IDENT_PORT local={} creation={} from={from:?} ref={reference:?}",
            tables.local_name, tables.local_creation
        );
    }
    let mfa = &parts[4];
    let options = &parts[5];
    let arguments = internalize_local_node(arguments.clone(), local);
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
    let watcher = if monitor || link {
        Some(remote_proxy(handle, &from)?)
    } else {
        None
    };
    let monitor_ref = if monitor {
        remote_ref_id(&reference)
    } else {
        None
    };
    let spawn_result = if spawn_opts_acceptable(options) {
        runtime.spawn_mfa_unscheduled_watched(
            mod_name,
            fun_name,
            &arg_list,
            link.then_some(watcher).flatten(),
            watcher.zip(monitor_ref),
            &from,
        )
    } else {
        Err(VmError::Unsupported("bad spawn options".into()))
    };
    if crate::debug_env::trace_dist() {
        eprintln!(
            "DIST_SPAWN_REQUEST {mod_name}:{fun_name}/{arity} args={arg_list:?} options={options:?} result={spawn_result:?}"
        );
    }
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
        if let Some(ref_id) = monitor_ref {
            remember_remote_monitor_ref(handle, ref_id, &reference, true)?;
        }
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

fn emit_control_message_on_handle(
    runtime: &crate::process::Runtime,
    handle: u64,
    control: OwnedTerm,
    message: Option<OwnedTerm>,
) -> Result<(), VmError> {
    if crate::debug_env::trace_dist()
        && matches!(&control, OwnedTerm::Tuple(parts) if matches!(parts.first(), Some(OwnedTerm::Int(21 | 31))))
    {
        eprintln!("DIST_TX_CONTROL {control:?}");
    }
    let mut tables = node_tables::lock();
    let local_name = tables.local_name.clone();
    let local_creation = tables.local_creation;
    let control = node_tables::relabel_local_node(control, &local_name, local_creation);
    let entry = tables
        .entries
        .values_mut()
        .find(|entry| {
            entry
                .dist
                .as_ref()
                .is_some_and(|state| state.handle == handle)
        })
        .ok_or_else(badarg)?;
    let state = entry.dist.as_mut().ok_or_else(badarg)?;
    if let Some(port_id) = state.port_id {
        let packets = state.encode_term(control, message).map_err(|_| badarg())?;
        state.written = state.written.saturating_add(1);
        enqueue_port_output_no_suspend_locked(state, packets);
        drop(tables);
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
        let mut tables = node_tables::lock();
        let local_name = tables.local_name.clone();
        let local_creation = tables.local_creation;
        let Some(entry) = tables.entries.values_mut().find(|entry| {
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

fn remember_remote_monitor_ref(
    handle: u64,
    id: u64,
    reference: &OwnedTerm,
    active: bool,
) -> Result<(), VmError> {
    let mut tables = node_tables::lock();
    let entry = tables
        .entries
        .values_mut()
        .find(|entry| {
            entry
                .dist
                .as_ref()
                .is_some_and(|state| state.handle == handle)
        })
        .ok_or_else(badarg)?;
    let state = entry.dist.as_mut().ok_or_else(badarg)?;
    if active {
        state.remote_monitor_refs.insert(id, reference.clone());
    } else {
        state.remote_monitor_refs.remove(&id);
    }
    Ok(())
}

/// When a local process exits and a dist proxy was monitoring it, emit MONITOR_P_EXIT.
pub(crate) fn forward_monitor_down_if_proxy(
    _runtime: &crate::process::Runtime,
    watcher: Pid,
    deceased: Pid,
    reference: u64,
    reason: Term,
) -> bool {
    if !may_be_proxy() {
        return false;
    }
    let (
        remote_watcher,
        reference_term,
        handle,
        deceased_term,
        local_name,
        local_creation,
        exit_payload,
    ) = {
        let mut tables = node_tables::lock();
        let local_name = tables.local_name.clone();
        let local_creation = tables.local_creation;
        let Some(entry) = tables.entries.values_mut().find(|entry| {
            entry
                .dist
                .as_ref()
                .is_some_and(|state| state.proxy_to_remote.contains_key(&watcher))
        }) else {
            return false;
        };
        let state = entry.dist.as_mut().unwrap();
        let Some(remote) = state.proxy_to_remote.get(&watcher).cloned() else {
            return false;
        };
        let reference_term = state
            .remote_monitor_refs
            .remove(&reference)
            .unwrap_or_else(|| OwnedTerm::Ref {
                node: "nonode@nohost".into(),
                creation: 0,
                ids: arinsal_bifs::ordinary_ref_words(reference).to_vec(),
            });
        let deceased_term = OwnedTerm::Pid {
            node: local_name.clone(),
            id: deceased.number(),
            serial: deceased.serial(),
            creation: local_creation,
        };
        let exit_payload = state.flags & node_tables::DFLAG_EXIT_PAYLOAD != 0;
        (
            remote,
            reference_term,
            state.handle,
            deceased_term,
            local_name,
            local_creation,
            exit_payload,
        )
    };
    let Ok(reason_owned) = to_owned(reason) else {
        return true;
    };
    let reason_owned = node_tables::relabel_local_node(reason_owned, &local_name, local_creation);
    // Port of erts/emulator/beam/dist.c:1497-1524 (`erts_dsig_send_m_exit`), OTP-29.1.1.
    let (control, payload) = if exit_payload {
        (
            control(28, vec![deceased_term, remote_watcher, reference_term]),
            Some(reason_owned),
        )
    } else {
        (
            control(
                21,
                vec![deceased_term, remote_watcher, reference_term, reason_owned],
            ),
            None,
        )
    };
    if crate::debug_env::trace_dist() {
        eprintln!("DIST_MONITOR_DOWN reference={reference} term={control:?}");
    }
    let _ = emit_control_message_on_handle(_runtime, handle, control, payload);
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
                Ok(atom("ok"))
            }
            RemoteSendOutcome::NotConnected => Ok(atom(if noconnect { "noconnect" } else { "ok" })),
            RemoteSendOutcome::WouldSuspend => Ok(atom("nosuspend")),
            RemoteSendOutcome::NotRemote => Err(badarg()),
        };
    }
    if nosuspend {
        // Port of erts/emulator/beam/bif.c:2390 (send_3): a busy port gives `nosuspend`.
        let (sent, busy) = crate::port::send_nosuspend(|| {
            process.send_message_prio(Some(vm), Some(ctx), args[0], args[1], want_priority)
        });
        sent?;
        return Ok(atom(if busy { "nosuspend" } else { "ok" }));
    }
    // Local priority delivery needs the process send path (alias + flag).
    process.send_message_prio(Some(vm), Some(ctx), args[0], args[1], want_priority)?;
    Ok(atom("ok"))
}

/// Route signal BIFs to the distribution controller when the peer is remote.
pub(crate) fn native_signal(
    vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    args: &[Term],
    function: &str,
) -> Result<Term, VmError> {
    // `monitor(Type, Item [, Opts])` — Item is args[1]; other BIFs take the
    // destination as args[0].
    let (remote, target_idx) = if function == "demonitor" {
        // An internal ref that this process did not use for a remote monitor is
        // not in any node table. erts looks up only `ERTS_P_MONITORS(c_p)`.
        let remote = crate::signals::ref_id(args[0])
            .filter(|id| {
                process
                    .cold
                    .as_ref()
                    .is_some_and(|cold| cold.dist_monitors.contains(id))
            })
            .and_then(monitor_node);
        (remote, 0usize)
    } else if function == "monitor" {
        if args.len() < 2 || args[0] != atom("process") {
            let handler =
                crate::signals::handler("erlang", function, args.len() as u8).ok_or_else(badarg)?;
            return handler(vm, process, ctx, crate::natives::NativeArgs::Slice(args))
                .ok_or_else(badarg)?;
        }
        (remote_node(args[1])?, 1usize)
    } else {
        (remote_node(args[0])?, 0usize)
    };
    let Some(node) = remote else {
        let handler =
            crate::signals::handler("erlang", function, args.len() as u8).ok_or_else(badarg)?;
        return handler(vm, process, ctx, crate::natives::NativeArgs::Slice(args))
            .ok_or_else(badarg)?;
    };
    let target = owned(args[target_idx])?;
    match function {
        "link" => {
            queue_outgoing(
                process,
                ctx,
                &node,
                control(1, vec![local_pid_owned(ctx.pid()), target]),
                None,
            )?;
            Ok(atom("true"))
        }
        "unlink" => {
            let unlink_id = NEXT_UNLINK_ID.fetch_add(1, Ordering::Relaxed);
            queue_outgoing(
                process,
                ctx,
                &node,
                control(
                    35,
                    vec![
                        OwnedTerm::Int(unlink_id as i64),
                        local_pid_owned(ctx.pid()),
                        target,
                    ],
                ),
                None,
            )?;
            Ok(atom("true"))
        }
        "exit" => {
            let reason = owned(args[1])?;
            queue_outgoing(
                process,
                ctx,
                &node,
                control(8, vec![local_pid_owned(ctx.pid()), target, reason]),
                None,
            )?;
            Ok(atom("true"))
        }
        "monitor" => {
            // Port of dist.c:1528 (erts_dsig_send_monitor), OTP-29.1.1.
            let (tag, alias_mode, priority) = crate::signals::monitor_options(args)?;
            let info = crate::signals::monitor_info_for(tag, None)?;
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
                OwnedTerm::Tuple(parts)
                    if parts.len() == 2 && matches!(&parts[0], OwnedTerm::Atom(_)) =>
                {
                    parts[0].clone()
                }
                _ => target.clone(),
            };
            let reference_owned = owned(reference)?;
            queue_outgoing(
                process,
                ctx,
                &node,
                control(
                    19,
                    vec![local_pid_owned(ctx.pid()), wire_target, reference_owned],
                ),
                None,
            )?;
            remember_monitor(&node, id, ctx.pid(), target)?;
            process.cold_mut().dist_monitors.insert(id);
            let (origin, _) = crate::proc_create::create_monitor_with_reference_at(
                process.heap.alloc_ix(),
                crate::proc_create::monitor_reference(id, alias_mode, priority),
                ctx.pid().data(),
                0,
                info,
                crate::proc_create::OriginMonitor::Distributed,
            );
            process.monitors.insert(origin);
            Ok(reference)
        }
        "demonitor" => {
            let id = crate::signals::ref_id(args[0]).or_else(|| crate::signals::ref_id(args[1]));
            let Some(id) = id else {
                return Err(badarg());
            };
            if args.len() == 2 && !valid_demonitor_options(args[1]) {
                return Err(badarg());
            }
            let origin = crate::signals::demonitor_origin(process, id);
            if matches!(origin, crate::signals::OriginDemonitor::Alias) {
                return Ok(atom("false"));
            }
            let Some((node, target)) = take_monitor(id) else {
                process.cold_mut().dist_monitors.remove(&id);
                return Ok(atom(if args.len() == 1 || !demonitor_info(args[1]) {
                    "true"
                } else {
                    "false"
                }));
            };
            process.cold_mut().dist_monitors.remove(&id);
            let wire_target = match &target {
                OwnedTerm::Tuple(parts)
                    if parts.len() == 2 && matches!(&parts[0], OwnedTerm::Atom(_)) =>
                {
                    parts[0].clone()
                }
                _ => target,
            };
            queue_outgoing(
                process,
                ctx,
                &node,
                control(
                    20,
                    vec![local_pid_owned(ctx.pid()), wire_target, owned(args[0])?],
                ),
                None,
            )?;
            Ok(atom("true"))
        }
        _ => Err(badarg()),
    }
}

fn valid_demonitor_options(term: Term) -> bool {
    let Ok(options) = owned(term) else {
        return false;
    };
    match &options {
        OwnedTerm::Nil => true,
        OwnedTerm::List { elems, tail } if **tail == OwnedTerm::Nil => elems.iter().all(
            |option| matches!(option, OwnedTerm::Atom(name) if name == "flush" || name == "info"),
        ),
        _ => false,
    }
}

fn demonitor_info(term: Term) -> bool {
    let Ok(options) = owned(term) else {
        return false;
    };
    matches!(&options, OwnedTerm::List { elems, tail } if **tail == OwnedTerm::Nil && elems.iter().any(|option| option == &OwnedTerm::Atom("info".into())))
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
// Port of erts/emulator/beam/dist.c:1528 (erts_dsig_send_monitor), OTP-29.1.1.
pub(crate) fn native_monitor(
    vm: &mut Vm,
    p: &mut Process,
    c: &mut RunCtx<'_, Message>,
    a: &[Term],
) -> Result<Term, VmError> {
    native_signal(vm, p, c, a, "monitor")
}
// Port of erts/emulator/beam/dist.c:1554 (erts_dsig_send_demonitor), OTP-29.1.1.
pub(crate) fn native_demonitor(
    vm: &mut Vm,
    p: &mut Process,
    c: &mut RunCtx<'_, Message>,
    a: &[Term],
) -> Result<Term, VmError> {
    native_signal(vm, p, c, a, "demonitor")
}

fn remote_node(term: Term) -> Result<Option<String>, VmError> {
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
    let local = node_tables::lock().local_name.clone();
    Ok((node != local && node != "nonode@nohost").then_some(node))
}

fn remember_monitor(node: &str, id: u64, watcher: Pid, target: OwnedTerm) -> Result<(), VmError> {
    let mut tables = node_tables::lock();
    let entry = tables.entries.get_mut(node).ok_or_else(badarg)?;
    if let Some(state) = entry.dist.as_mut() {
        state
            .remote_monitors
            .insert(id, node_tables::RemoteMonitor { watcher, target });
    } else {
        entry
            .pending_monitors
            .insert(id, node_tables::RemoteMonitor { watcher, target });
    }
    if crate::debug_env::trace_dist() {
        eprintln!("DIST_MONITOR_SET node={node} ref={id} watcher={watcher:?}");
    }
    Ok(())
}

pub(crate) fn take_monitor(id: u64) -> Option<(String, OwnedTerm)> {
    let mut tables = node_tables::lock();
    for (node, entry) in &mut tables.entries {
        if let Some(monitor) = entry.pending_monitors.remove(&id) {
            return Some((node.clone(), monitor.target));
        }
        if let Some(state) = entry.dist.as_mut()
            && let Some(monitor) = state.remote_monitors.remove(&id)
        {
            return Some((node.clone(), monitor.target));
        }
    }
    None
}

/// Send the remote demonitor caused by the first message through a reply_demonitor alias.
// Port of erts/emulator/beam/erl_proc_sig_queue.c (handle_alias_message), OTP-29.1.1.
pub(crate) fn demonitor_alias(
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    id: u64,
) -> Result<(), VmError> {
    process.cold_mut().dist_monitors.remove(&id);
    let Some((node, target)) = take_monitor(id) else {
        return Ok(());
    };
    let wire_target = match &target {
        OwnedTerm::Tuple(parts) if parts.len() == 2 && matches!(&parts[0], OwnedTerm::Atom(_)) => {
            parts[0].clone()
        }
        _ => target,
    };
    let reference = crate::signals::reference(process, id)?;
    queue_outgoing(
        process,
        ctx,
        &node,
        control(
            20,
            vec![local_pid_owned(ctx.pid()), wire_target, owned(reference)?],
        ),
        None,
    )
}

fn monitor_node(id: u64) -> Option<String> {
    let tables = node_tables::lock();
    tables.entries.iter().find_map(|(node, entry)| {
        if entry.pending_monitors.contains_key(&id) {
            return Some(node.clone());
        }
        entry
            .dist
            .as_ref()?
            .remote_monitors
            .contains_key(&id)
            .then(|| node.clone())
    })
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
    let local = node_tables::lock().local_name.clone();
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
    if !node_tables::lock().alive {
        return Ok(RemoteSendOutcome::NotConnected);
    }
    Ok(
        match queue_outgoing_with_options(process, ctx, node, control, message, connect, suspend)? {
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
        let local = node_tables::lock().local_name.clone();
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
        let local = node_tables::lock().local_name.clone();
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
    let local = node_tables::lock().local_name.clone();
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
        node_tables::ANY_FRAGMENT_CONTINUATION.store(true, std::sync::atomic::Ordering::Release);
        state
            .fragment_continuations
            .push_back(node_tables::DistFragmentContinuation {
                sender: Some(sender),
                remaining_packets: deferred_count,
            });
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
            let mut tables = node_tables::lock();
            if let Some(state) = tables.entries.values_mut().find_map(|entry| {
                entry
                    .dist
                    .as_mut()
                    .filter(|state| state.port_id == Some(port_id))
            }) {
                state.suspended_senders.push(sender);
            }
            drop(tables);
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
        node_tables::ANY_FRAGMENT_CONTINUATION.store(true, std::sync::atomic::Ordering::Release);
        state.pending_bytes = state.pending_bytes.saturating_sub(packet_bytes);
        state
            .fragment_continuations
            .push_back(node_tables::DistFragmentContinuation {
                sender: None,
                remaining_packets: packets.len(),
            });
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
    node_tables::ANY_FRAGMENT_CONTINUATION.load(std::sync::atomic::Ordering::Acquire)
}

pub(crate) fn continue_fragmented_send(
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
) -> Result<(), VmError> {
    // Called every scheduling iteration: skip the global node-table lock while no
    // distribution entry has a deferred fragmented send (erts keeps this per process).
    if !node_tables::ANY_FRAGMENT_CONTINUATION.load(std::sync::atomic::Ordering::Acquire) {
        return Ok(());
    }
    let sender = ctx.pid();
    let send_count = (ctx.remaining() as usize / 10).max(1);
    let (port_id, packet_count, more) = {
        let mut tables = node_tables::lock();
        let Some(state) = tables.entries.values_mut().find_map(|entry| {
            entry.dist.as_mut().filter(|state| {
                state
                    .fragment_continuations
                    .iter()
                    .any(|continuation| continuation.sender == Some(sender))
            })
        }) else {
            // Flag writers hold this lock, so clearing it here cannot lose a new push.
            if !tables.entries.values().any(|entry| {
                entry
                    .dist
                    .as_ref()
                    .is_some_and(|state| !state.fragment_continuations.is_empty())
            }) {
                node_tables::ANY_FRAGMENT_CONTINUATION
                    .store(false, std::sync::atomic::Ordering::Release);
            }
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
        let mut tables = node_tables::lock();
        let Some(state) = tables.entries.values_mut().find_map(|entry| {
            entry
                .dist
                .as_mut()
                .filter(|state| state.port_id == Some(port_id))
        }) else {
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
        let mut tables = node_tables::lock();
        if let Some(state) = tables.entries.values_mut().find_map(|entry| {
            entry
                .dist
                .as_mut()
                .filter(|state| state.port_id == Some(port_id))
        }) {
            state.suspended_senders.push(sender);
        }
        drop(tables);
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
        let mut tables = node_tables::lock();
        let Some(state) = tables.entries.values_mut().find_map(|entry| {
            entry
                .dist
                .as_mut()
                .filter(|state| state.port_id == Some(port_id))
        }) else {
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
        dist_cmd_done(port_id);
        return Ok(());
    };
    drv.schedule_dist_cmd(Box::new(move |op| {
        if op == arinsal_drv::port_task::SigOp::Exec {
            dist_cmd(task_runtime, port_id)
        } else {
            dist_cmd_done(port_id);
            0
        }
    }));
    Ok(())
}

/// The dist command task is no longer scheduled or running.
fn dist_cmd_done(port_id: u64) {
    let mut tables = node_tables::lock();
    if let Some(state) = tables.entries.values_mut().find_map(|entry| {
        entry
            .dist
            .as_mut()
            .filter(|state| state.port_id == Some(port_id))
    }) {
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
            let again = {
                let mut tables = node_tables::lock();
                tables
                    .entries
                    .values_mut()
                    .find_map(|entry| {
                        entry
                            .dist
                            .as_mut()
                            .filter(|state| state.port_id == Some(port_id))
                    })
                    .is_some_and(|state| !state.port_busy && state.output_ready_packets != 0)
            };
            dist_cmd_done(port_id);
            if again {
                let _ = flush_port_output(runtime, port_id);
            }
            break;
        }
        let packet = {
            let mut tables = node_tables::lock();
            let Some(state) = tables.entries.values_mut().find_map(|entry| {
                entry
                    .dist
                    .as_mut()
                    .filter(|state| state.port_id == Some(port_id))
            }) else {
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
            let mut tables = node_tables::lock();
            let Some(state) = tables.entries.values_mut().find_map(|entry| {
                entry
                    .dist
                    .as_mut()
                    .filter(|state| state.port_id == Some(port_id))
            }) else {
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
        let mut tables = node_tables::lock();
        let Some(state) = tables.entries.values_mut().find_map(|entry| {
            entry
                .dist
                .as_mut()
                .filter(|state| state.port_id == Some(port_id))
        }) else {
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
    let local_creation = node_tables::lock().local_creation;
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
        ctx.send(handler, Message::copy_from(atom("dist_data"))?)
            .map_err(|error| VmError::Unsupported(format!("dist data notification: {error}")))?;
    }
    Ok(atom("ok"))
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
    Ok(atom("ok"))
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
            atom("ok"),
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
    let mut tables = node_tables::lock();
    let entry = tables
        .entries
        .values_mut()
        .find(|entry| {
            entry.entry_ref == entry_ref && entry.connection_id == conn_id && entry.dist.is_some()
        })
        .ok_or_else(badarg)?;
    let state = entry.dist.as_mut().expect("matched controller state");
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
    let mut tables = node_tables::lock();
    let entry = tables
        .entries
        .values_mut()
        .find(|entry| {
            entry.entry_ref == entry_ref && entry.connection_id == conn_id && entry.dist.is_some()
        })
        .ok_or_else(badarg)?;
    let state = entry.dist.as_mut().expect("matched controller state");
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

fn atom(name: &str) -> Term {
    let id = global_atoms()
        .intern(name)
        .expect("short distribution atom");
    Term::atom(id)
}

fn atom_name(term: Term) -> Option<String> {
    global_atoms()
        .text(term.as_atom()?)
        .map(|name| name.to_string())
}

fn boolean(value: bool) -> Term {
    atom(if value { "true" } else { "false" })
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
    VmError::Trap(crate::exceptions::Trap::error(atom("badarg")))
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
        assert_eq!(boolean_value(atom("true")), Some(true));
        assert_eq!(boolean_value(atom("false")), Some(false));
        assert_eq!(boolean_value(atom("ok")), None);
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
