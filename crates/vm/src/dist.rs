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
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

static NEXT_HANDLE: AtomicU64 = AtomicU64::new(1 << 40);
static NEXT_REMOTE_PID: AtomicU32 = AtomicU32::new(1 << 27);
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
            abort_pending_connection(args[0], args[1])
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
fn abort_pending_connection(node: Term, dhandle: Term) -> Result<Term, VmError> {
    let OwnedTerm::Atom(ref name) = owned(node)? else {
        return Err(badarg());
    };
    let (conn_id, entry_ref) = parse_dhandle(dhandle)?;
    let result = node_tables::lock()
        .abort_pending(name, conn_id, entry_ref)
        .ok_or_else(badarg)?;
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
            if !crate::inet_drv::owns(port_id) {
                return Err(badarg());
            }
            port_id
        }
        None => NEXT_HANDLE.fetch_add(1, Ordering::Relaxed),
    };
    let mut state = DistState::new(handle, owner, flags);
    state.port_id = port_controller;
    state.read = 0;
    entry.creation = creation;
    entry.visible = visible;
    entry.connected = true;
    entry.state = node_tables::ConnState::Connected;
    let pending = std::mem::take(&mut entry.pending_out);
    let pending_monitors = std::mem::take(&mut entry.pending_monitors);
    entry.dist = Some(state);
    if let Some(state) = entry.dist.as_mut() {
        state.remote_monitors.extend(pending_monitors);
    }
    if let Some(port_id) = port_controller {
        node_tables::register_dist_port(port_id, node.clone());
    }
    // Flush signals buffered during auto-connect (erts pending queue).
    let mut flush_packets = Vec::new();
    let mut flush_notify = None;
    if let Some(state) = entry.dist.as_mut() {
        for (control, message) in pending {
            let control = node_tables::relabel_local_node(control, &local_name, local_creation);
            let message =
                message.map(|m| node_tables::relabel_local_node(m, &local_name, local_creation));
            if let Some(port_id) = state.port_id {
                let packet = state.encode_term(control, message);
                state.pending_bytes = state.pending_bytes.saturating_sub(packet.len() as u64);
                state.written = state.written.saturating_add(1);
                flush_packets.push((port_id, packet));
            } else {
                state.queue_term(control, message);
                if state.notify {
                    flush_notify = Some(state.owner);
                    state.notify = false;
                }
            }
        }
    }
    drop(tables);
    for (port_id, packet) in flush_packets {
        crate::inet_drv::dist_output(port_id, &packet)
            .map_err(|error| VmError::Unsupported(format!("dist port write: {error:?}")))?;
    }
    if let Some(handler) = flush_notify {
        ctx.send(handler, Message::copy_from(atom("dist_data"))?)
            .map_err(|error| VmError::Unsupported(format!("dist data notification: {error}")))?;
    }
    // Notify net_kernel: {dist_ctrlr, Ctrlr, Node, SetupPid}.
    notify_dist_ctrlr(process, ctx, args[1], args[0])?;
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
    let Some(net_kernel) = runtime
        .names
        .lock()
        .ok()
        .and_then(|names| names.get("net_kernel").copied())
    else {
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
    match *op {
        // Port of dist.c:2519 (DOP_SEND), OTP-29.1.1.
        2 if parts.len() == 3 => {
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
            publish_remote_signal(process, from, target, Signal::Link)?;
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
                Signal::Exit(Message::copy_from(reason)?),
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
            publish_remote_signal(
                process,
                watcher,
                target,
                if *op == 19 {
                    Signal::Monitor(reference)
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
                    reason: Message::copy_from(reason)?,
                },
            )?;
        }
        33 | 34 if (parts.len() == 3 && *op == 33) || (parts.len() == 4 && *op == 34) => {
            let OwnedTerm::Ref { .. } = &parts[2] else {
                return Err(badarg());
            };
            let reference = remote_ref_id(&parts[2]).ok_or_else(badarg)?;
            let runtime = process.runtime.as_ref().ok_or_else(badarg)?;
            if let Some(Some(target)) = runtime.alias_lookup(reference) {
                for term in terms {
                    let message = from_owned(&term, &mut process.heap).map_err(|_| badarg())?;
                    ctx.send(target, Message::copy_from(message)?)
                        .map_err(|error| {
                            VmError::Unsupported(format!("dist alias send: {error}"))
                        })?;
                }
            }
        }
        29 if parts.len() == 6 && terms.len() == 1 => {
            handle_spawn_request(vm, process, ctx, handle, parts, &terms[0])?;
        }
        32 if parts.len() == 5 => {
            let id = remote_ref_id(&parts[1]).ok_or_else(badarg)?;
            let result = parts[4].clone();
            if let Some(req) = take_spawn_request(handle, id) {
                let ok = matches!(result, OwnedTerm::Pid { .. });
                let status = if ok { "ok" } else { "error" };
                if ok && req.monitor {
                    // Activate local monitor using the spawn request ref.
                    remember_monitor(
                        node_tables::lock()
                            .entries
                            .values()
                            .find(|e| e.dist.as_ref().is_some_and(|s| s.handle == handle))
                            .map(|e| e.name.clone())
                            .ok_or_else(badarg)?
                            .as_str(),
                        id,
                        result.clone(),
                    )?;
                }
                if !(ok && req.no_success_msg) {
                    let reply = OwnedTerm::tuple(vec![
                        req.tag,
                        parts[1].clone(),
                        OwnedTerm::Atom(status.into()),
                        result,
                    ]);
                    let reply = from_owned(&reply, &mut process.heap).map_err(|_| badarg())?;
                    let envelope = Message::copy_from(reply)?;
                    ctx.send(req.caller, envelope).map_err(|error| {
                        VmError::Unsupported(format!("dist spawn reply: {error}"))
                    })?;
                }
            }
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
    let pid = Pid {
        index: NEXT_REMOTE_PID.fetch_add(1, Ordering::Relaxed) & ((1 << 28) - 1),
        generation: local_creation,
    };
    state.remote_pids.insert(key, pid);
    state.proxy_to_remote.insert(pid, remote.clone());
    Ok(pid)
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
    process: &Process,
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
        let packet = state.encode_term(control, None);
        state.pending_bytes = state.pending_bytes.saturating_sub(packet.len() as u64);
        state.written = state.written.saturating_add(1);
        drop(tables);
        crate::inet_drv::dist_output(port_id, &packet)
            .map_err(|error| VmError::Unsupported(format!("dist port write: {error:?}")))?;
        let _ = process;
        let _ = ctx;
        return Ok(());
    }
    state.queue_term(control, None);
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
    let mut value = 0_u64;
    for (index, id) in ids.iter().take(2).enumerate() {
        value |= u64::from(*id) << (index * 32);
    }
    Some(value)
}

fn registered_pid(process: &Process, name: &str) -> Option<Pid> {
    let runtime = process.runtime.as_ref()?;
    runtime.names.lock().ok()?.get(name).copied()
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
    let mut tables = node_tables::lock();
    if !tables.alive {
        return Err(badarg());
    }
    let local_name = tables.local_name.clone();
    let local_creation = tables.local_creation;
    if node == local_name {
        return Err(badarg());
    }
    let control = node_tables::relabel_local_node(control, &local_name, local_creation);
    let message = message.map(|m| node_tables::relabel_local_node(m, &local_name, local_creation));

    // Port of dist.c:3260 (erts_auto_connect on Idle), OTP-29.1.1.
    let was_idle = tables
        .entries
        .get(node)
        .map(|entry| entry.state == node_tables::ConnState::Idle)
        .unwrap_or(true);
    let (conn_id, entry_ref) = tables.new_connection(node).ok_or_else(badarg)?;
    let entry = tables.entries.get_mut(node).ok_or_else(badarg)?;

    if entry.state == node_tables::ConnState::Exiting {
        return Err(badarg());
    }

    if entry.connected
        && let Some(state) = entry.dist.as_mut().filter(|state| state.handle != 0)
    {
        if let Some(port_id) = state.port_id {
            let packet = state.encode_term(control, message);
            state.pending_bytes = state.pending_bytes.saturating_sub(packet.len() as u64);
            state.written = state.written.saturating_add(1);
            drop(tables);
            crate::inet_drv::dist_output(port_id, &packet)
                .map_err(|error| VmError::Unsupported(format!("dist port write: {error:?}")))?;
            let _ = process;
            let _ = ctx;
            return Ok(());
        }
        state.queue_term(control, message);
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
        return Ok(());
    }

    // Pending (or Connected without a controller yet): buffer until channel is up.
    entry.pending_out.push_back((control, message));
    let notify = was_idle.then(|| (node.to_string(), conn_id, entry_ref));
    drop(tables);
    if let Some((node, conn_id, entry_ref)) = notify {
        notify_auto_connect(process, ctx, &node, conn_id, entry_ref)?;
    }
    Ok(())
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
    let Some(net_kernel) = runtime
        .names
        .lock()
        .ok()
        .and_then(|names| names.get("net_kernel").copied())
    else {
        let _ = node_tables::lock().abort_pending(node, conn_id, entry_ref);
        return Err(badarg());
    };
    let msg = OwnedTerm::tuple(vec![
        OwnedTerm::Atom("auto_connect".into()),
        OwnedTerm::Atom(node.into()),
        OwnedTerm::tuple(vec![
            OwnedTerm::Int(i64::from(conn_id)),
            OwnedTerm::Ref {
                node: "nonode@nohost".into(),
                creation: 0,
                ids: vec![entry_ref as u32, (entry_ref >> 32) as u32, 0],
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
    runtime: &std::sync::Arc<crate::process::Runtime>,
    port_id: u64,
    bytes: &[u8],
) -> Result<(), VmError> {
    // A zero-length body is a distribution tick (packet header length 0).
    if bytes.is_empty() {
        return Ok(());
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
        let packet = arinsal_etf::decode_dist_packet(bytes, &mut state.incoming_cache)
            .map_err(|_| badarg())?;
        let DistributionHeader::Start { .. } = packet.header else {
            return Ok(());
        };
        let decoded = arinsal_etf::decode_dist_payload(&packet).map_err(|_| badarg())?;
        (state.handle, decoded)
    };
    route_incoming_port(runtime, handle, &local_name, decoded)
}

/// Tear down a port-controlled connection after the peer socket closes.
pub(crate) fn port_connection_closed(
    runtime: &crate::process::Runtime,
    port_id: u64,
) -> Result<(), VmError> {
    let Some(node) = node_tables::unregister_dist_port(port_id) else {
        return Ok(());
    };
    let watchers = node_tables::lock().disconnect(&node);
    let node_atom = atom(&node);
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

fn route_incoming_port(
    runtime: &std::sync::Arc<crate::process::Runtime>,
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
    let sched = runtime.scheduler()?;
    match *op {
        2 if parts.len() == 3 => {
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
            let target = runtime
                .names
                .lock()
                .ok()
                .and_then(|names| names.get(name).copied())
                .ok_or_else(badarg)?;
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
                .signal(from, target, Signal::Link)
                .map_err(|error| VmError::Unsupported(format!("incoming dist signal: {error}")))?;
        }
        // Port of dist.c:2341 (DOP_MONITOR_P); ToProc may be a pid or registered name.
        19 | 20 if parts.len() == 4 => {
            let watcher = remote_proxy(handle, &parts[1])?;
            let target = match &parts[2] {
                OwnedTerm::Atom(name) => runtime
                    .names
                    .lock()
                    .ok()
                    .and_then(|names| names.get(name).copied()),
                other => local_pid(other, local),
            };
            let reference = remote_ref_id(&parts[3]).ok_or_else(badarg)?;
            if let Some(target) = target {
                let signal = if *op == 19 {
                    Signal::Monitor(reference)
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
                        reason: reason_msg,
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
            if let Some(Some(target)) = runtime.alias_lookup(reference) {
                for term in terms {
                    let message = owned_to_message(&term)?;
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
            const FLG_ALIAS: u64 = 1 << 2;
            const FLG_NAME: u64 = 1 << 3;
            const FLG_EXIT: u64 = 1 << 4;
            if flags & FLG_EXIT != 0 {
                // Exit via altact not required for net_adm:ping; defer.
                return Ok(());
            }
            if flags & FLG_ALIAS != 0 {
                let reference = remote_ref_id(&parts[3]).ok_or_else(badarg)?;
                if let Some(Some(target)) = runtime.alias_lookup(reference) {
                    for term in terms {
                        let message = owned_to_message(&term)?;
                        sched.send(target, target, message).map_err(|error| {
                            VmError::Unsupported(format!("dist altact alias: {error}"))
                        })?;
                    }
                }
            } else if flags & FLG_NAME != 0 {
                let OwnedTerm::Atom(name) = &parts[3] else {
                    return Err(badarg());
                };
                let target = runtime
                    .names
                    .lock()
                    .ok()
                    .and_then(|names| names.get(name).copied())
                    .ok_or_else(badarg)?;
                for term in terms {
                    let message = owned_to_message(&term)?;
                    sched.send(target, target, message).map_err(|error| {
                        VmError::Unsupported(format!("dist altact name: {error}"))
                    })?;
                }
            } else {
                let target = local_pid(&parts[3], local).ok_or_else(badarg)?;
                for term in terms {
                    let message = owned_to_message(&term)?;
                    sched.send(target, target, message).map_err(|error| {
                        VmError::Unsupported(format!("dist altact pid: {error}"))
                    })?;
                }
            }
        }
        // Port of dist.c:2885 (DOP_SPAWN_REQUEST) / DOP_SPAWN_REPLY on Port DistCtrlr.
        29 if parts.len() == 6 && terms.len() == 1 => {
            handle_spawn_request_port(runtime, handle, local, parts, &terms[0])?;
        }
        32 if parts.len() == 5 => {
            let id = remote_ref_id(&parts[1]).ok_or_else(badarg)?;
            let result = parts[4].clone();
            if let Some(req) = take_spawn_request(handle, id) {
                let ok = matches!(result, OwnedTerm::Pid { .. });
                let status = if ok { "ok" } else { "error" };
                if ok && req.monitor {
                    let node = node_tables::lock()
                        .entries
                        .values()
                        .find(|e| e.dist.as_ref().is_some_and(|s| s.handle == handle))
                        .map(|e| e.name.clone())
                        .ok_or_else(badarg)?;
                    remember_monitor(&node, id, result.clone())?;
                }
                if !(ok && req.no_success_msg) {
                    let reply = OwnedTerm::tuple(vec![
                        req.tag,
                        parts[1].clone(),
                        OwnedTerm::Atom(status.into()),
                        result,
                    ]);
                    let message = owned_to_message(&reply)?;
                    sched
                        .send(req.caller, req.caller, message)
                        .map_err(|error| {
                            VmError::Unsupported(format!("dist spawn reply: {error}"))
                        })?;
                }
            }
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
    let local = node_tables::lock().local_name.clone();
    let connected = node_tables::lock()
        .entries
        .get(&node)
        .is_some_and(|entry| entry.connected && entry.dist.is_some());
    if node == local || node == "nonode@nohost" || !connected {
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
    let mut no_success_msg = false;
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
                            OwnedTerm::Atom(v) if v == "error_only" || v == "no" => {
                                no_success_msg = true;
                            }
                            OwnedTerm::Atom(v) if v == "yes" || v == "success_only" => {}
                            _ => return Err(badarg()),
                        },
                        OwnedTerm::Atom(name) if name == "monitor" => {
                            monitor = true;
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
    queue_outgoing(process, ctx, &node, control, Some(values[2].clone()))?;
    let mut tables = node_tables::lock();
    tables
        .entries
        .get_mut(&node)
        .and_then(|entry| entry.dist.as_mut())
        .ok_or_else(badarg)?
        .spawn_requests
        .insert(
            id,
            node_tables::SpawnRequest {
                caller: ctx.pid(),
                tag,
                monitor,
                no_success_msg,
            },
        );
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

fn take_spawn_request(handle: u64, id: u64) -> Option<node_tables::SpawnRequest> {
    let mut tables = node_tables::lock();
    tables.entries.values_mut().find_map(|entry| {
        let state = entry.dist.as_mut()?;
        (state.handle == handle)
            .then(|| state.spawn_requests.remove(&id))
            .flatten()
    })
}

fn handle_spawn_request(
    vm: &mut Vm,
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
    let mut result = OwnedTerm::Atom("badopt".into());
    if spawn_opts_acceptable(options) {
        let module = from_owned(module, &mut process.heap).map_err(|_| badarg())?;
        let function = from_owned(function, &mut process.heap).map_err(|_| badarg())?;
        let args = from_owned(&arguments, &mut process.heap).map_err(|_| badarg())?;
        if let Some(spawn) = crate::signals::handler("erlang", "spawn", 3)
            && let Some(Ok(pid)) = spawn(
                vm,
                process,
                ctx,
                crate::natives::NativeArgs::Slice(&[module, function, args]),
            )
        {
            result = to_owned(pid).map_err(|_| badarg())?;
            if monitor && let Some(ref_id) = remote_ref_id(&reference) {
                let watcher = remote_proxy(handle, &from)?;
                let child = Pid::from_term(pid).ok_or_else(badarg)?;
                let runtime = process.runtime.as_ref().ok_or_else(badarg)?;
                runtime
                    .scheduler()?
                    .signal(watcher, child, Signal::Monitor(ref_id))
                    .map_err(|error| VmError::Unsupported(format!("spawn monitor arm: {error}")))?;
            }
        }
    }
    let flags = if monitor && matches!(result, OwnedTerm::Pid { .. }) {
        1
    } else {
        0
    };
    let reply = control(32, vec![reference, from, OwnedTerm::Int(flags), result]);
    queue_remote_control(process, ctx, handle, reply)
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

/// Port DistCtrlr path for DOP_SPAWN_REQUEST (no Vm/Process context).
fn handle_spawn_request_port(
    runtime: &std::sync::Arc<crate::process::Runtime>,
    handle: u64,
    local: &str,
    parts: &[OwnedTerm],
    arguments: &OwnedTerm,
) -> Result<(), VmError> {
    let reference = parts[1].clone();
    let from = parts[2].clone();
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
    let mut result = OwnedTerm::Atom("badopt".into());
    let arg_list = match &arguments {
        OwnedTerm::Nil => Vec::new(),
        OwnedTerm::List { elems, tail } if **tail == OwnedTerm::Nil => elems.clone(),
        _ => return Err(badarg()),
    };
    if spawn_opts_acceptable(options)
        && let Ok(child) = runtime.spawn_mfa(mod_name, fun_name, &arg_list)
    {
        let tables = node_tables::lock();
        result = OwnedTerm::Pid {
            node: tables.local_name.clone(),
            id: child.index,
            serial: child.generation,
            creation: tables.local_creation,
        };
        drop(tables);
        if monitor && let Some(ref_id) = remote_ref_id(&reference) {
            let watcher = remote_proxy(handle, &from)?;
            runtime
                .scheduler()?
                .signal(watcher, child, Signal::Monitor(ref_id))
                .map_err(|error| VmError::Unsupported(format!("spawn monitor arm: {error}")))?;
        }
    }
    let flags = if monitor && matches!(result, OwnedTerm::Pid { .. }) {
        1
    } else {
        0
    };
    let reply = control(32, vec![reference, from, OwnedTerm::Int(flags), result]);
    let local_name = node_tables::lock().local_name.clone();
    let local_creation = node_tables::lock().local_creation;
    let reply = node_tables::relabel_local_node(reply, &local_name, local_creation);
    let _ = local;
    emit_control_on_handle(handle, reply)
}

fn emit_control_on_handle(handle: u64, control: OwnedTerm) -> Result<(), VmError> {
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
        let packet = state.encode_term(control, None);
        state.pending_bytes = state.pending_bytes.saturating_sub(packet.len() as u64);
        state.written = state.written.saturating_add(1);
        drop(tables);
        crate::inet_drv::dist_output(port_id, &packet)
            .map_err(|error| VmError::Unsupported(format!("dist port write: {error:?}")))?;
        return Ok(());
    }
    state.queue_term(control, None);
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
    let (remote_watcher, handle, deceased_term, local_name, local_creation) = {
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
        let deceased_term = OwnedTerm::Pid {
            node: local_name.clone(),
            id: deceased.index,
            serial: deceased.generation,
            creation: local_creation,
        };
        (
            remote,
            state.handle,
            deceased_term,
            local_name,
            local_creation,
        )
    };
    let Ok(reason_owned) = to_owned(reason) else {
        return true;
    };
    let reason_owned = node_tables::relabel_local_node(reason_owned, &local_name, local_creation);
    let control = control(
        21,
        vec![
            deceased_term,
            remote_watcher,
            OwnedTerm::Ref {
                node: "nonode@nohost".into(),
                creation: 0,
                ids: vec![reference as u32, (reference >> 32) as u32, 0],
            },
            reason_owned,
        ],
    );
    let _ = emit_control_on_handle(handle, control);
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

/// `send/3` validates its options before queueing the same remote DOP_SEND.
pub(crate) fn native_send3(
    vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    args: &[Term],
) -> Result<Term, VmError> {
    let options = owned(args[2])?;
    let names = match &options {
        OwnedTerm::Nil => Vec::new(),
        OwnedTerm::List { elems, tail } if **tail == OwnedTerm::Nil => elems.iter().collect(),
        _ => return Err(badarg()),
    };
    let mut want_priority = false;
    for option in &names {
        match option {
            OwnedTerm::Atom(name) if name == "nosuspend" || name == "noconnect" => {}
            OwnedTerm::Atom(name) if name == "priority" => want_priority = true,
            _ => return Err(badarg()),
        }
    }
    // Local priority delivery needs the process send path (alias + flag).
    process.send_message_prio(Some(vm), ctx, args[0], args[1], want_priority)?;
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
        (
            crate::signals::ref_id(args[0]).and_then(monitor_node),
            0usize,
        )
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
            let alias = if args.len() == 3 {
                monitor_alias_option(args[2])?
            } else {
                false
            };
            let id = arinsal_bifs::next_ref_id();
            let reference = crate::signals::reference(process, id)?;
            if alias {
                process.cold_mut().aliases.insert(id);
                let runtime = process.runtime.as_ref().ok_or_else(badarg)?;
                runtime.alias_bind(id, Some(ctx.pid()));
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
            remember_monitor(&node, id, target)?;
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
            let Some((node, target)) = take_monitor(id) else {
                return Ok(atom(if args.len() == 1 || !demonitor_info(args[1]) {
                    "true"
                } else {
                    "false"
                }));
            };
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

/// `[{alias, demonitor | reply_demonitor | explicit_unalias}]` (gen:call remote).
fn monitor_alias_option(term: Term) -> Result<bool, VmError> {
    let options = owned(term)?;
    match &options {
        OwnedTerm::Nil => Ok(false),
        OwnedTerm::List { elems, tail } if **tail == OwnedTerm::Nil => {
            let mut alias = false;
            for option in elems {
                match option {
                    OwnedTerm::Tuple(parts)
                        if parts.len() == 2
                            && parts[0] == OwnedTerm::Atom("alias".into())
                            && matches!(
                                &parts[1],
                                OwnedTerm::Atom(name)
                                    if name == "demonitor"
                                        || name == "reply_demonitor"
                                        || name == "explicit_unalias"
                            ) =>
                    {
                        alias = true;
                    }
                    _ => return Err(badarg()),
                }
            }
            Ok(alias)
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

fn remember_monitor(node: &str, id: u64, target: OwnedTerm) -> Result<(), VmError> {
    let mut tables = node_tables::lock();
    let entry = tables.entries.get_mut(node).ok_or_else(badarg)?;
    if let Some(state) = entry.dist.as_mut() {
        state.remote_monitors.insert(id, target);
    } else {
        entry.pending_monitors.insert(id, target);
    }
    Ok(())
}

fn take_monitor(id: u64) -> Option<(String, OwnedTerm)> {
    let mut tables = node_tables::lock();
    for (node, entry) in &mut tables.entries {
        if let Some(target) = entry.pending_monitors.remove(&id) {
            return Some((node.clone(), target));
        }
        if let Some(state) = entry.dist.as_mut()
            && let Some(target) = state.remote_monitors.remove(&id)
        {
            return Some((node.clone(), target));
        }
    }
    None
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
        id: pid.index,
        serial: pid.generation,
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
pub(crate) fn try_remote_send(
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    target: Term,
    message: Term,
) -> Result<bool, VmError> {
    // {Name, Node} — registered send on a (possibly remote) node.
    if let Some((name, node)) = name_node_tuple(target)? {
        let local = node_tables::lock().local_name.clone();
        if node == local || node == "nonode@nohost" {
            return Ok(false);
        }
        let control = control(
            6,
            vec![
                local_pid_owned(ctx.pid()),
                OwnedTerm::Atom(String::new()),
                OwnedTerm::Atom(name),
            ],
        );
        queue_outgoing(process, ctx, &node, control, Some(owned(message)?))?;
        return Ok(true);
    }
    let target_owned = owned(target)?;
    if let OwnedTerm::Ref { node, .. } = &target_owned {
        let target_node = node.clone();
        let local = node_tables::lock().local_name.clone();
        if target_node == local || target_node == "nonode@nohost" {
            return Ok(false);
        }
        let control = control(33, vec![local_pid_owned(ctx.pid()), target_owned]);
        queue_outgoing(process, ctx, &target_node, control, Some(owned(message)?))?;
        return Ok(true);
    }
    let OwnedTerm::Pid {
        node,
        id,
        serial,
        creation,
    } = &target_owned
    else {
        return Ok(false);
    };
    let local = node_tables::lock().local_name.clone();
    if node == &local || node == "nonode@nohost" {
        return Ok(false);
    }
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
    queue_outgoing(process, ctx, node, control, Some(owned(message)?))?;
    Ok(true)
}

/// When `target` is `{Name, Node}` and Node is this node, return the Name atom.
pub(crate) fn local_reg_name(target: Term) -> Result<Option<Term>, VmError> {
    let Some((name, node)) = name_node_tuple(target)? else {
        return Ok(None);
    };
    let local = node_tables::lock().local_name.clone();
    if node != local && node != "nonode@nohost" {
        return Ok(None);
    }
    Ok(Some(atom(&name)))
}

fn name_node_tuple(target: Term) -> Result<Option<(String, String)>, VmError> {
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
    if !node_tables::is_node_name(node) && node != "nonode@nohost" {
        return Ok(None);
    }
    Ok(Some((name.clone(), node.clone())))
}

fn send_to(
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    target: Term,
    message: Term,
) -> Result<(), VmError> {
    if try_remote_send(process, ctx, target, message)? {
        return Ok(());
    }
    process.send_message(ctx, target, message).map(|_| ())
}

fn local_pid(term: &OwnedTerm, local: &str) -> Option<Pid> {
    let OwnedTerm::Pid {
        node, id, serial, ..
    } = term
    else {
        return None;
    };
    if node != local && node != "nonode@nohost" {
        return None;
    }
    Some(Pid {
        index: *id,
        generation: *serial,
    })
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

    #[test]
    fn dist_state_starts_empty_with_connection_caches() {
        let state = DistState::new(
            11,
            Pid {
                index: 1,
                generation: 2,
            },
            0,
        );
        assert!(state.output.is_empty());
        assert_eq!(state.pending_bytes, 0);
        assert_eq!(state.incoming_cache.get(0), None);
        assert_eq!(state.outgoing_cache.get(0), None);
    }

    #[test]
    fn dist_output_encodes_distribution_header_and_send_control() {
        let mut state = DistState::new(
            11,
            Pid {
                index: 1,
                generation: 2,
            },
            0,
        );
        let control = OwnedTerm::tuple(vec![
            OwnedTerm::Int(2),
            OwnedTerm::Atom("from@host".into()),
            OwnedTerm::Atom("to@host".into()),
        ]);
        state.queue_term(control, Some(OwnedTerm::Int(9)));
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
        let mut state = DistState::new(
            12,
            Pid {
                index: 1,
                generation: 0,
            },
            0,
        );
        state.queue_term(OwnedTerm::tuple(vec![OwnedTerm::Int(2)]), None);
        assert_eq!(
            state.pending_bytes,
            state.output.front().unwrap().len() as u64
        );
    }

    #[test]
    fn dist_local_pid_requires_the_local_node_name() {
        assert_eq!(
            local_pid(
                &OwnedTerm::Pid {
                    node: "node@host".into(),
                    id: 4,
                    serial: 7,
                    creation: 4
                },
                "node@host"
            ),
            Some(Pid {
                index: 4,
                generation: 7
            })
        );
        assert_eq!(
            local_pid(
                &OwnedTerm::Pid {
                    node: "remote@host".into(),
                    id: 4,
                    serial: 7,
                    creation: 4
                },
                "node@host"
            ),
            None
        );
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
