//! Distribution controller state and the VM side of the controller BIFs.
//!
//! Control tuples and packet framing follow `erts/emulator/beam/dist.c` in
//! OTP-29.1.1. Socket ownership remains in Erlang's distribution modules.

use crate::node_tables::{self, DistState};
use crate::process::Message;
use crate::{Process, Vm, VmError};
use arinsal_etf::{DistributionHeader, OwnedTerm};
use arinsal_external::dist::{
    DistHeaderFinalize, DsigEncode, DsigEncodeResult, ErtsDistOutputBuf,
    erts_encode_ext_dist_header_finalize,
};
use arinsal_sched::{Pid, RunCtx, Signal};
use arinsal_term::{Term, TermBuilder, copy_term, from_owned, global_atoms, to_owned};
use std::collections::VecDeque;
use std::sync::Arc;
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
    ctx: &mut RunCtx<'_, crate::Process>,
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
    ctx: &mut RunCtx<'_, crate::Process>,
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
        ("erlang", "dist_ctrl_put_data", 2) => put_data(process, ctx, args[0], args[1]),
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
    let (result, mld) = {
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
        let mld = if aborts { tables.take_mld(name) } else { None };
        let result = tables
            .abort_pending(name, conn_id, entry_ref)
            .ok_or_else(badarg)?;
        (result, mld)
    };
    if let Some(runtime) = process.runtime {
        elink::links_connection_down(runtime, mld.clone());
        emon::monitors_connection_down(runtime, mld.as_ref());
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

/// The argument of `setup_connection_distctrl`.
// Port of erts/emulator/beam/dist.c:5108 (ErtsSetupConnDistCtrl), OTP-29.1.1.
struct SetupConnDistCtrl {
    dep: Arc<node_tables::DistEntry>,
    node: Term,
    dflags: u64,
    creation: u32,
    setup_pid: Pid,
}

// Port of erts/emulator/beam/dist.c:5127 (erts_internal_create_dist_channel_3), OTP-29.1.1:
// failures are returned as the atoms `badarg` / `system_limit`, which erlang:setnode/3 raises.
fn create_channel(
    process: &mut Process,
    ctx: &mut RunCtx<'_, crate::Process>,
    args: &[Term],
) -> Result<Term, VmError> {
    let badarg_res = Ok(Term::atom(arinsal_term::atoms::BADARG));
    // `net_kernel` must be the true net_kernel (ERTS_PROC_GET_DIST_ENTRY == this entry).
    let Some(runtime) = process.runtime else {
        return badarg_res;
    };
    if runtime.reg.whereis_proc_str("net_kernel").is_none() || !node_tables::is_alive() {
        return badarg_res;
    }
    // Node name...
    let OwnedTerm::Atom(ref node) = owned(args[0])? else {
        return badarg_res;
    };
    if !node.contains('@') {
        return badarg_res;
    }
    // Distribution controller...
    let port_controller = match owned(args[1])? {
        OwnedTerm::Port { id, .. } => Some(id),
        OwnedTerm::Pid { .. } => None,
        _ => return badarg_res,
    };
    let OwnedTerm::Tuple(ref options) = owned(args[2])? else {
        return badarg_res;
    };
    if options.len() != 2 {
        return badarg_res;
    }
    // Dist flags... Creation...
    let (Some(flags), Some(creation)) = (as_u64(&options[0]), as_u32(&options[1])) else {
        return badarg_res;
    };
    if flags & node_tables::DFLAG_DIST_MANDATORY != node_tables::DFLAG_DIST_MANDATORY {
        return badarg_res;
    }
    // erts_find_or_insert_dist_entry
    let dep = {
        let mut tables = node_tables::lock();
        if node == crate::node_tables::this_node().0 {
            return badarg_res;
        }
        if !tables.entries.contains_key(node.as_str()) {
            let _ = tables.new_connection(node);
        }
        match tables.entries.get(node.as_str()).cloned() {
            Some(dep) => dep,
            None => return Ok(Term::atom(arinsal_term::atoms::SYSTEM_LIMIT)),
        }
    };
    let (res_tag, res) = match port_controller {
        None => {
            let Some(ctrlr) = Pid::from_term(args[1]) else {
                return badarg_res;
            };
            let scdc = SetupConnDistCtrl {
                dep,
                node: args[0],
                dflags: flags,
                creation,
                setup_pid: ctx.pid(),
            };
            if ctrlr == ctx.pid() {
                let res =
                    setup_connection_distctrl(process, ctx, Some(Box::new(scdc)), None, None)?;
                // BUMP_REDS(BIF_P, 5)
                bump_reds(process, 5);
                if res == Term::atom(arinsal_term::atoms::BADARG) {
                    return badarg_res;
                }
                (arinsal_term::atoms::OK, res)
            } else {
                let Some(res) = crate::process::erts_proc_sig_send_rpc_request(
                    process,
                    ctx,
                    ctrlr,
                    true,
                    setup_connection_distctrl,
                    Some(Box::new(scdc)),
                )?
                else {
                    return badarg_res; // Was not able to send signal...
                };
                // Caller need to wait for dhandle in message
                (arinsal_term::atoms::MESSAGE, res)
            }
        }
        Some(port_id) => {
            let busy_limit = node_tables::lock().distribution_buffer_busy_limit;
            let mut entry = dep.lock();
            promote_pending(&mut entry);
            if entry.state != node_tables::ConnState::Pending {
                return badarg_res;
            }
            // Port DistCtrlr: a live inet port with ERL_DRV_FLAG_SOFT_BUSY.
            let owns_tcp_port = runtime
                .ports
                .get(port_id)
                .is_some_and(|handle| handle.tcp_driver_data().is_some());
            if !owns_tcp_port || entry.dist.is_some() {
                return badarg_res;
            }
            // erts_prtsd_set(pp, ERTS_PRTSD_DIST_ENTRY, dep)
            if let Some(port) = runtime.ports.get(port_id) {
                port.set_dist_entry(Some(dep.clone()));
            }
            let conn_id = entry.connection_id;
            let entry_ref = entry.entry_ref;
            if !setup_connection_epiloge_rwunlock(
                process,
                ctx,
                entry,
                args[1],
                Some(port_id),
                args[0],
                flags,
                creation,
                ctx.pid(),
                busy_limit,
            )? {
                if let Some(port) = runtime.ports.get(port_id) {
                    port.set_dist_entry(None);
                }
                return badarg_res;
            }
            (
                arinsal_term::atoms::OK,
                dhandle_term(process, conn_id, entry_ref)?,
            )
        }
    };
    tuple(process, vec![Term::atom(res_tag), res])
}

/// `BUMP_REDS(p, gc)` (bif.h): charge `reds` to the running BIF's process.
fn bump_reds(process: &mut Process, reds: i32) {
    process.heap.abi.fcalls = process.heap.abi.fcalls.saturating_sub(reds).max(0);
}

/// An auto-connect entry may still be idle when the accept side commits: it becomes pending.
fn promote_pending(entry: &mut node_tables::NodeEntry) {
    if entry.state == node_tables::ConnState::Idle {
        entry.connection_id = (entry.connection_id + 1) & 0x00ff_ffff;
        entry.state = node_tables::ConnState::Pending;
        entry.mld = Some(node_tables::new_mld(&entry.name, entry.connection_id));
    }
}

/// Commit a pending connection to controller `ctrlr`: notify net_kernel, then connect the entry,
/// output what was queued while pending and send the nodeup messages. `false` when net_kernel is
/// gone. The entry lock is released.
// Port of erts/emulator/beam/dist.c:5385 (setup_connection_epiloge_rwunlock), OTP-29.1.1.
#[allow(clippy::too_many_arguments)]
fn setup_connection_epiloge_rwunlock(
    c_p: &mut Process,
    ctx: &mut RunCtx<'_, crate::Process>,
    mut entry: parking_lot::MutexGuard<'_, node_tables::NodeEntry>,
    ctrlr: Term,
    port_id: Option<u64>,
    node: Term,
    flags: u64,
    creation: u32,
    setup_pid: Pid,
    busy_limit: u64,
) -> Result<bool, VmError> {
    let runtime = c_p.runtime.ok_or_else(badarg)?;
    // Notify net_kernel about the new dist controller...
    let Some(net_kernel) = runtime.reg.whereis_proc_str("net_kernel") else {
        return Ok(false);
    };
    notify_dist_ctrlr(c_p, ctx, net_kernel, ctrlr, node, setup_pid)?;
    entry.creation = creation;
    let visible = flags & 0x01 != 0; // DFLAG_PUBLISHED
    let owner = match port_id {
        Some(_) => setup_pid,
        None => Pid::from_term(ctrlr).ok_or_else(badarg)?,
    };
    let handle = port_id.unwrap_or_else(|| NEXT_HANDLE.fetch_add(1, Ordering::Relaxed));
    // erts_set_dist_entry_connected(dep, ctrlr, flags); create_cache with the atom cache flag.
    let mut state = DistState::new(handle, owner, flags);
    state.busy_limit = busy_limit;
    state.port_id = port_id;
    state.read = 0;
    entry.visible = visible;
    entry.connected = true;
    entry.state = node_tables::ConnState::Connected;
    let conn_id = entry.connection_id;
    let sysname = entry.name.clone();
    // The signals buffered while pending stay in the connection's output queue as encoded;
    // erts_encode_ext_dist_header_finalize transcodes them when they are output.
    let pending = std::mem::take(&mut entry.pending_out);
    let mut notify_proc = None;
    for signal in pending {
        let mut reds = 0;
        if let DistCmdKick::Notify(pid) = dsig_send_enqueue_locked(
            &mut state,
            &mut VecDeque::from([signal]),
            &mut reds,
            true,
            true,
        ) {
            notify_proc = Some(pid);
        }
    }
    entry.dist = Some(state);
    drop(entry);
    // `erts_schedule_dist_command(NULL, dep)` for a port with queued data.
    if let Some(port_id) = port_id {
        flush_port_output(runtime, port_id)?;
    }
    if let Some(handler) = notify_proc {
        ctx.send(
            handler,
            Message::copy_from(Term::atom(arinsal_term::atoms::DIST_DATA))?,
        )
        .map_err(|error| VmError::Unsupported(format!("dist data notification: {error}")))?;
    }
    node_tables::inc_no_nodes();
    let nodeup_events =
        node_tables::lock().nodes_monitor_events("nodeup", &sysname, conn_id, visible, None);
    send_nodes_monitor_events(runtime.scheduler()?, nodeup_events)?;
    Ok(true)
}

/// Make the calling process `c_p` the controller of the pending connection in `arg` and return
/// its dhandle, built on `c_p`'s heap for a direct call or in `*bpp` as an rpc request.
// Port of erts/emulator/beam/dist.c:5461 (setup_connection_distctrl), OTP-29.1.1.
fn setup_connection_distctrl(
    c_p: &mut Process,
    ctx: &mut RunCtx<'_, crate::Process>,
    arg: Option<Box<dyn std::any::Any + Send>>,
    mut redsp: Option<&mut i32>,
    bpp: Option<&mut Option<arinsal_term::message::MessageHeapBlock>>,
) -> Result<Term, VmError> {
    let scdcp = *arg
        .and_then(|arg| arg.downcast::<SetupConnDistCtrl>().ok())
        .expect("setup_connection_distctrl argument");
    let badarg_res = Ok(Term::atom(arinsal_term::atoms::BADARG));
    if let Some(redsp) = redsp.as_deref_mut() {
        *redsp = 1;
    }
    if ctx.proc_state().load(Ordering::Acquire) & arinsal_sched::psflg::EXITING != 0 {
        return badarg_res;
    }
    // The table lock comes before the entry lock.
    let busy_limit = node_tables::lock().distribution_buffer_busy_limit;
    let mut entry = scdcp.dep.lock();
    promote_pending(&mut entry);
    if entry.state != node_tables::ConnState::Pending {
        return badarg_res;
    }
    let conn_id = entry.connection_id;
    let entry_ref = entry.entry_ref;
    // is_not_nil(dep->cid)
    if entry.dist.is_some() {
        return badarg_res;
    }
    if let Some(redsp) = redsp {
        *redsp = 5;
    }
    let ctrlr = ctx.pid().to_term().ok_or_else(badarg)?;
    if !setup_connection_epiloge_rwunlock(
        c_p,
        ctx,
        entry,
        ctrlr,
        None,
        scdcp.node,
        scdcp.dflags,
        scdcp.creation,
        scdcp.setup_pid,
        busy_limit,
    )? {
        return badarg_res;
    }
    let Some(bpp) = bpp else {
        // called directly...
        return dhandle_term(c_p, conn_id, entry_ref);
    };
    // *bpp = new_message_buffer(ERTS_DHANDLE_SIZE)
    let mut bp = arinsal_term::message::MessageHeapBlock::with_words(3 + 3);
    let reference = Term::local_ref(
        &mut bp,
        arinsal_sched::unique::ordinary_ref_words(entry_ref),
    )
    .map_err(|error| VmError::Unsupported(format!("dhandle: {error:?}")))?;
    let dhandle = TermBuilder::new(&mut bp)
        .tuple(&[integer(u64::from(conn_id)), reference])
        .map_err(|error| VmError::Unsupported(format!("dhandle: {error:?}")))?;
    *bpp = Some(bp);
    Ok(dhandle)
}

fn notify_dist_ctrlr(
    process: &mut Process,
    ctx: &mut RunCtx<'_, crate::Process>,
    net_kernel: Pid,
    ctrlr: Term,
    node: Term,
    setup_pid: Pid,
) -> Result<(), VmError> {
    let msg = TermBuilder::new(&mut process.heap)
        .tuple(&[
            Term::atom(arinsal_term::atoms::DIST_CTRLR),
            ctrlr,
            node,
            setup_pid.to_term().ok_or_else(badarg)?,
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
    ctx: &mut RunCtx<'_, crate::Process>,
    handle: Term,
) -> Result<Term, VmError> {
    // Port of erts/emulator/beam/dist.c (dist_ctrl_get_data_1): the buffer is finalized for
    // the connection's flags when taken (erts_encode_ext_dist_header_finalize); senders
    // suspended on the busy queue resume once it is below half the busy limit.
    // `initial_reds = ERTS_BIF_REDS_LEFT(BIF_P)`; the call returns with
    // `BIF_RET2(res, initial_reds - reds)`.
    let initial_reds = i64::from(process.heap.abi.fcalls);
    let mut reds = initial_reds;
    let bytes = with_dhandle(handle, ctx.pid(), true, |state| {
        let Some(mut packet) = state.output.pop_front() else {
            return Ok(None);
        };
        state.pending_bytes = state.pending_bytes.saturating_sub(packet.size() as u64);
        let finalize = erts_encode_ext_dist_header_finalize(
            &mut packet,
            &mut state.outgoing_cache,
            state.flags,
            &mut reds,
        );
        state.written = state.written.saturating_add(1);
        let resume = if state.busy && state.pending_bytes < state.busy_limit / 2 {
            state.busy = false;
            std::mem::take(&mut state.suspended_senders)
        } else {
            Vec::new()
        };
        Ok(Some((
            packet,
            state.get_size,
            finalize,
            state.handle,
            resume,
        )))
    })?;
    let Some((packet, sized, finalize, conn_handle, resume)) = bytes else {
        return Ok(Term::atom(arinsal_term::atoms::NONE));
    };
    let runtime = process.runtime.ok_or_else(badarg)?;
    if let DistHeaderFinalize::SpawnNotSupported(ctl) = finalize {
        transcode_spawn_notsup(runtime, conn_handle, &ctl);
    }
    let resumed = resume_dist_senders(runtime, resume);
    reds -= resumed as i64 * ERTS_PORT_REDS_DIST_CMD_RESUMED;
    bump_reds(
        process,
        i32::try_from(initial_reds - reds).unwrap_or(i32::MAX),
    );
    let size = packet.size();
    // The buffer's I/O vector as a list of binaries referencing its Binaries
    // (erts_wrap_refc_bitstring), all in one HAlloc of `hsz` words; an empty buffer (a signal
    // transcoded into a tick) is the empty I/O vector. The header rewritten for the wire is in
    // a Binary of its own (erts rewrites it in place in the buffer's Binary).
    let (header, iov) = packet.into_iov();
    let mut elems = Vec::with_capacity(iov.len() + 1);
    if !header.is_empty() {
        let mut bin = arinsal_term::RefcBinary::new_uninit(header.len()).map_err(|_| badarg())?;
        bin.bytes_mut_unique()
            .ok_or_else(badarg)?
            .copy_from_slice(&header);
        elems.push(DistCtrlElem::Header(bin, header.len()));
    }
    elems.extend(iov.into_iter().map(DistCtrlElem::Iov));
    let mut hsz = (2 + ERL_REFC_BITS_SIZE) * elems.len();
    if sized {
        // 2-tuple; the size is a small.
        hsz += 3;
    }
    let mut hp =
        arinsal_term::HeapReservation::new(&mut process.heap, hsz).map_err(|_| badarg())?;
    let mut builder = arinsal_term::TermBuilder::new(&mut hp);
    let mut parts = Vec::with_capacity(elems.len());
    for elem in elems {
        parts.push(
            match elem {
                DistCtrlElem::Header(bin, len) => builder.refc_binary(bin, len * 8),
                DistCtrlElem::Iov(iov) => {
                    let (bin, offset, len) = iov.into_parts();
                    builder.wrap_refc_bitstring(bin, offset, len)
                }
            }
            .map_err(|_| badarg())?,
        );
    }
    let list = builder.list_from_slice(&parts).map_err(|_| badarg())?;
    if sized {
        let size = Term::small(size as i64).ok_or_else(badarg)?;
        builder.tuple(&[size, list]).map_err(|_| badarg())
    } else {
        Ok(list)
    }
}

/// Reductions per process resumed when a dist queue drains (dist.c).
const ERTS_PORT_REDS_DIST_CMD_RESUMED: i64 = 5;

/// One element of the I/O vector `dist_ctrl_get_data` returns.
enum DistCtrlElem {
    Header(arinsal_term::RefcBinary, usize),
    Iov(arinsal_external::dist::DistIov),
}

/// `ERL_REFC_BITS_SIZE` (erl_bits.h): the heap words of a BinRef and its SubBits.
const ERL_REFC_BITS_SIZE: usize = 3 + 5;

fn put_data(
    process: &mut Process,
    ctx: &mut RunCtx<'_, crate::Process>,
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
    // Port of erts/emulator/beam/dist.c (dist_ctrl_put_data_2), OTP-29.1.1: an empty
    // binary is a tick; the rest goes to erts_net_message, whose header decode and fragment
    // reassembly are shared with the port controller.
    if bytes.is_empty() {
        return Ok(Term::atom(arinsal_term::atoms::OK));
    }
    let (handle_id, sysname, connection_id, packet) =
        with_dhandle_input(handle, ctx.pid(), |state, sysname, connection_id| {
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
            .ok()
            .map(|packet| reassemble_fragment(state, packet));
            Ok((state.handle, sysname.to_owned(), connection_id, packet))
        })?;
    let runtime = process.runtime.ok_or_else(badarg)?;
    let packet = match packet {
        Some(Ok(Some(packet))) => packet,
        // A fragment of a signal still being reassembled.
        Some(Ok(None)) => return Ok(Term::atom(arinsal_term::atoms::OK)),
        // dist.c erts_net_message `data_error`: erts_kill_dist_connection.
        Some(Err(_)) | None => {
            let _ = kill_connection(runtime, &sysname, connection_id);
            return Ok(Term::atom(arinsal_term::atoms::OK));
        }
    };
    // Decode failures are ignored here; erts_net_message takes the connection down.
    erts_net_message(runtime, handle_id, &sysname, connection_id, packet);
    Ok(Term::atom(arinsal_term::atoms::OK))
}

/// The seq_trace token `term` of a `*_TT` control tuple (`None`: the operation has none,
/// `ERL_MESSAGE_TOKEN == NIL`). A token that is not `[]` or a token tuple is an invalid
/// control message.
// Port of erts/emulator/beam/dist.c (erts_net_message, `token = tuple[N]` / `token = NIL`),
// OTP-29.1.1.
fn dist_token(term: Option<Term>) -> Result<Option<Box<crate::seq_trace::Token>>, VmError> {
    let Some(term) = term else {
        return Ok(None);
    };
    let owned = to_owned(term).map_err(|_| badarg())?;
    crate::seq_trace::Token::from_dist(&owned).map_err(|()| badarg())
}

/// `is_external_pid(term)`: the stored external pid (`STORE_NC`).
// Port of erts/emulator/beam/erl_term.h (is_external_pid, external_pid_node), OTP-29.1.1.
fn ctl_external_pid(term: Term) -> Option<crate::monitor_link::ExternalPid> {
    if term.is_pid() || term.classify() != arinsal_term::TermKind::Pid {
        return None;
    }
    match term.identity()? {
        arinsal_term::Identity::Pid {
            node,
            creation,
            index,
            serial,
        } => Some(crate::monitor_link::ExternalPid {
            sysname: node.0,
            creation,
            number: index,
            serial,
        }),
        _ => None,
    }
}

/// `is_internal_pid(term)`.
fn ctl_internal_pid(term: Term) -> Option<Pid> {
    term.as_pid_data().map(Pid::from_data)
}

/// `is_pid(term)`.
fn ctl_is_pid(term: Term) -> bool {
    term.classify() == arinsal_term::TermKind::Pid
}

/// `is_ref(term)`.
fn ctl_is_ref(term: Term) -> bool {
    term.classify() == arinsal_term::TermKind::Ref
}

/// `is_internal_ref(term)`.
fn ctl_is_internal_ref(term: Term) -> bool {
    term.local_ref_numbers().is_some() || term.is_magic_ref()
}

/// `is_external(term) && external_dist_entry(term) == erts_this_dist_entry`: an external
/// pid, port or reference of an old incarnation of this node.
fn ctl_is_this_node(term: Term) -> bool {
    if term.is_pid() || term.is_port() || ctl_is_internal_ref(term) {
        return false;
    }
    let this = arinsal_term::this_node().0;
    matches!(
        term.identity(),
        Some(
            arinsal_term::Identity::Pid { node, .. }
                | arinsal_term::Identity::Port { node, .. }
                | arinsal_term::Identity::Ref { node, .. }
        ) if node == this
    )
}

/// The key of reference `term`: its first three numbers.
fn ctl_ref_id(term: Term) -> Option<u64> {
    match term.identity()? {
        arinsal_term::Identity::Ref { ids, .. } => ref_key(&ids),
        _ => None,
    }
}

/// `erts_get_pid_of_ref(to)` of an internal pid reference (an alias); other references name
/// no local process.
// Port of erts/emulator/beam/erl_bif_unique.h (erts_get_pid_of_ref), OTP-29.1.1.
fn ctl_alias_pid(term: Term) -> Option<Pid> {
    term.local_pid_ref_pid_data().map(Pid::from_data)
}

/// `term_to_Uint64(term, &value)`.
// Port of erts/emulator/beam/big.c (term_to_Uint64), OTP-29.1.1.
fn ctl_u64(term: Term) -> Option<u64> {
    match term.as_small() {
        Some(value) => u64::try_from(value).ok(),
        None => u64::try_from(arinsal_term::raw::big_value(term)?).ok(),
    }
}

/// The ALTACT flags byte: the least significant byte of a non-negative integer.
// Port of erts/emulator/beam/dist.c (erts_net_message, DOP_ALTACT_SIG_SEND flags), OTP-29.1.1.
fn ctl_altact_flags(term: Term) -> Option<u64> {
    match term.as_small() {
        Some(value) => (value >= 0).then_some((value & 0xff) as u64),
        None => {
            let big = arinsal_term::raw::big_value(term)?;
            if big.sign() == num_bigint::Sign::Minus {
                return None;
            }
            Some(big.iter_u64_digits().next().unwrap_or(0) & 0xff)
        }
    }
}

/// The scheduler sender of a signal from pid `from`: a local pid as itself, an external pid
/// through its proxy.
fn ctl_sender(handle: u64, from: Term) -> Result<Pid, VmError> {
    match ctl_internal_pid(from) {
        Some(pid) => Ok(pid),
        None => remote_proxy(handle, ctl_external_pid(from).ok_or_else(badarg)?),
    }
}

/// The `ErtsDistExternal` of a complete signal (`erts_prepare_dist_ext`): the bytes after the
/// distribution header, the atom translation table of the header, the connection it came in
/// on. The control message is decoded from it first, which moves `extp` to the payload.
// Port of erts/emulator/beam/external.c (erts_prepare_dist_ext), OTP-29.1.1.
fn dist_ext(
    packet: arinsal_etf::DistributionPacket,
    sysname: &str,
    connection_id: u32,
) -> Box<crate::natives::external_dist::ErtsDistExternal> {
    use crate::natives::external_dist::{
        ERTS_DIST_EXT_ATOM_TRANS_TAB, ERTS_DIST_EXT_DFLAG_HDR, ErtsDistExternal,
        ErtsDistExternalData,
    };
    let attab = match &packet.header {
        DistributionHeader::Start { translations, .. } => translations
            .atom_indices()
            .iter()
            .map(|index| arinsal_term::Atom(*index))
            .collect(),
        DistributionHeader::Continuation { .. } => Box::default(),
    };
    let binp = packet.payload.into_boxed_slice();
    Box::new(ErtsDistExternal {
        data: ErtsDistExternalData {
            extp: 0,
            ext_endp: binp.len(),
            binp,
        },
        flags: ERTS_DIST_EXT_DFLAG_HDR | ERTS_DIST_EXT_ATOM_TRANS_TAB,
        connection_id,
        heap_size: -1,
        dep: global_atoms()
            .intern(sysname)
            .unwrap_or(arinsal_term::atoms::NONAME),
        attab,
        size_state: Default::default(),
    })
}

/// `erts_net_message(prt, dep, conn_id, ...)`: one complete distribution signal from either
/// input path (the port controller or `erlang:dist_ctrl_put_data/2`). The control message is
/// decoded into a temporary heap; a message, an exit reason or a monitor-exit reason in the
/// payload is passed on still encoded (`ErtsDistExternal`) and decoded by the receiver. An
/// invalid signal takes the connection down (`invalid_message` / `decode_error` /
/// `data_error`: `erts_kill_dist_connection`).
// Port of erts/emulator/beam/dist.c (erts_net_message), OTP-29.1.1.
fn erts_net_message(
    runtime: &'static crate::process::Runtime,
    handle: u64,
    sysname: &str,
    connection_id: u32,
    packet: arinsal_etf::DistributionPacket,
) {
    if net_message(runtime, handle, sysname, connection_id, packet).is_err() {
        let _ = kill_connection(runtime, sysname, connection_id);
    }
}

/// The body of [`erts_net_message`]; an error is an invalid signal.
fn net_message(
    runtime: &'static crate::process::Runtime,
    handle: u64,
    sysname: &str,
    connection_id: u32,
    packet: arinsal_etf::DistributionPacket,
) -> Result<(), VmError> {
    use crate::natives::external_dist::{erts_decode_dist_ext, erts_decode_dist_ext_size};
    let mut edep = dist_ext(packet, sysname, connection_id);
    // `ctl_len = erts_decode_dist_ext_size(&ede, 1, 0)`; the connection is killed by the
    // caller on any error, as `data_error` / `decode_error` do.
    let ctl_len = erts_decode_dist_ext_size(None, &mut edep, false);
    if ctl_len < 0 {
        return Err(badarg());
    }
    // `erts_factory_tmp_init(&factory, ctl, ctl_len, ERTS_ALC_T_DCTRL_BUF)`: the control
    // message lives in this buffer until the signal is dispatched.
    let mut ctl = arinsal_term::message::NodeFragment::new_message_buffer(ctl_len as usize);
    let arg = {
        let mut target = ctl.fragment_mut();
        let mut factory = arinsal_term::HeapReservation::new(&mut target, ctl_len as usize)
            .map_err(|_| badarg())?;
        erts_decode_dist_ext(None, &mut factory, &mut edep, false).ok_or_else(badarg)?
    };
    // The payload is sized by its receiver (`erts_decode_dist_ext_size(edep, 1, 1)`).
    edep.heap_size = -1;
    let tuple = arinsal_term::raw::Tuple::try_from(arg).map_err(|_| badarg())?;
    // `tuple[1..=arity]`, `parts[0]` being `tuple[1]`.
    let parts: Vec<Term> = (0..tuple.arity()).filter_map(|i| tuple.get(i)).collect();
    let Some(op) = parts.first().and_then(|op| op.as_small()) else {
        return Err(badarg());
    };
    let result = net_message_dispatch(runtime, handle, sysname, op, &parts, edep);
    drop(ctl);
    result
}

/// The `switch (type)` of [`erts_net_message`] over the decoded control tuple `parts`
/// (`parts[i]` is erts' `tuple[i + 1]`).
// Port of erts/emulator/beam/dist.c (erts_net_message), OTP-29.1.1.
fn net_message_dispatch(
    runtime: &'static crate::process::Runtime,
    handle: u64,
    sysname: &str,
    op: i64,
    parts: &[Term],
    edep: Box<crate::natives::external_dist::ErtsDistExternal>,
) -> Result<(), VmError> {
    const FLG_PRIO: u64 = 1 << 0;
    const FLG_TOKEN: u64 = 1 << 1;
    const FLG_ALIAS: u64 = 1 << 2;
    const FLG_NAME: u64 = 1 << 3;
    const FLG_EXIT: u64 = 1 << 4;
    let arity = parts.len();
    let dep = global_atoms().intern(sysname).map_err(|_| badarg())?.0;
    // `is_external_pid(from) && dep == external_pid_dist_entry(from)`.
    let dep_pid = |term: Term| ctl_external_pid(term).filter(|pid| pid.sysname == dep);
    let sched = runtime.scheduler()?;
    match op {
        // DOP_LINK {1, From, To}
        1 => {
            if arity != 3 {
                return Err(badarg());
            }
            let (from, to) = (parts[1], parts[2]);
            let remote = dep_pid(from).ok_or_else(badarg)?;
            if ctl_external_pid(to).is_some() && !ctl_is_this_node(to) {
                return Err(badarg());
            }
            let proxy = remote_proxy(handle, remote)?;
            elink::incoming_link(runtime, handle, proxy, remote, to)?;
        }
        // DOP_UNLINK: the new link protocol is mandatory as of OTP 26.
        4 => return Err(badarg()),
        // DOP_UNLINK_ID {35, Id, From, To}, DOP_UNLINK_ID_ACK {36, Id, From, To}
        35 | 36 => {
            if arity != 4 {
                return Err(badarg());
            }
            let id = ctl_u64(parts[1]).ok_or_else(badarg)?;
            if op == 35 && id == 0 {
                return Err(badarg());
            }
            let remote = dep_pid(parts[2]).ok_or_else(badarg)?;
            // erts tests `erts_this_dist_entry == external_pid_dist_entry(from)` here, which
            // never holds for a pid of `dep`; an external `to` is an invalid message.
            let to = ctl_internal_pid(parts[3]).ok_or_else(badarg)?;
            let proxy = remote_proxy(handle, remote)?;
            elink::incoming_unlink(runtime, handle, proxy, id, remote, to, op == 36)?;
        }
        // DOP_MONITOR_P {19, Watcher, Watched, Ref}, DOP_DEMONITOR_P {20, ..}
        19 | 20 => {
            if arity != 4 {
                return Err(badarg());
            }
            let (watcher, watched, reference) = (parts[1], parts[2], parts[3]);
            if op == 19 {
                let remote = dep_pid(watcher).ok_or_else(badarg)?;
                if !ctl_is_ref(reference) {
                    return Err(badarg());
                }
                let proxy = remote_proxy(handle, remote)?;
                emon::incoming_monitor(runtime, handle, proxy, remote, watched, reference)?;
            } else {
                if !ctl_is_ref(reference) {
                    return Err(badarg());
                }
                let remote = dep_pid(watcher).ok_or_else(badarg)?;
                let proxy = remote_proxy(handle, remote)?;
                emon::incoming_demonitor(runtime, handle, proxy, watched, reference)?;
            }
        }
        // DOP_REG_SEND {6, From, '', ToName}, DOP_REG_SEND_TT {16, From, '', ToName, Token}
        6 | 16 => {
            if (op == 16 && arity != 5) || (op == 6 && arity != 4) {
                return Err(badarg());
            }
            let (from, to) = (parts[1], parts[3]);
            if !ctl_is_pid(from) {
                return Err(badarg());
            }
            let name = to.as_atom().ok_or_else(badarg)?;
            if let Some(rp) = runtime.reg.whereis_proc(name) {
                let token = dist_token((op == 16).then(|| parts[4]))?;
                crate::process::erts_queue_dist_message(sched, rp, edep, token, rp)?;
            }
        }
        // DOP_SEND {2, '', To}, DOP_SEND_SENDER {22, From, To}, DOP_SEND_TT {12, '', To, Token},
        // DOP_SEND_SENDER_TT {23, From, To, Token}
        2 | 22 | 12 | 23 => {
            let tt = matches!(op, 12 | 23);
            if arity != if tt { 4 } else { 3 } {
                return Err(badarg());
            }
            let token = dist_token(tt.then(|| parts[3]))?;
            let to = parts[2];
            if !ctl_is_pid(to) {
                return Err(badarg());
            }
            // `erts_proc_lookup(to)`: an external pid names no local process.
            if let Some(rp) = ctl_internal_pid(to) {
                let from = if matches!(op, 22 | 23) {
                    ctl_sender(handle, parts[1])?
                } else {
                    rp
                };
                crate::process::erts_queue_dist_message(sched, rp, edep, token, from)?;
            }
        }
        // DOP_ALIAS_SEND {33, From, Alias}, DOP_ALIAS_SEND_TT {34, From, Alias, Token}
        33 | 34 => {
            if arity != if op == 34 { 4 } else { 3 } {
                return Err(badarg());
            }
            let token = dist_token((op == 34).then(|| parts[3]))?;
            let to = parts[2];
            if !ctl_is_ref(to) {
                return Err(badarg());
            }
            erts_proc_sig_send_dist_altact_msg(
                sched,
                None,
                to,
                Message::dist_external(edep, token),
                false,
            )?;
        }
        // DOP_ALTACT_SIG_SEND {37, Flags, SenderPid, To} | {37, Flags, SenderPid, To, Token}
        37 => {
            if arity < 4 {
                return Err(badarg());
            }
            let flags = ctl_altact_flags(parts[1]).ok_or_else(badarg)?;
            let from = parts[2];
            if !ctl_is_pid(from) {
                return Err(badarg());
            }
            let mut to = parts[3];
            let token = if flags & FLG_TOKEN == 0 {
                None
            } else if arity < 5 {
                return Err(badarg());
            } else {
                dist_token(Some(parts[4]))?
            };
            if flags & FLG_ALIAS != 0 {
                if !ctl_is_ref(to) || flags & FLG_NAME != 0 {
                    return Err(badarg());
                }
            } else if flags & FLG_NAME != 0 {
                let name = to.as_atom().ok_or_else(badarg)?;
                match runtime.reg.whereis_proc(name) {
                    Some(pid) => to = Term::pid_from_data(pid.data()),
                    // No such process registered; drop message.
                    None => return Ok(()),
                }
            } else if !ctl_is_pid(to) {
                return Err(badarg());
            }
            let prio = flags & FLG_PRIO != 0;
            let sender = ctl_sender(handle, from)?;
            let message = Message::dist_external(edep, token);
            if flags & FLG_EXIT != 0 {
                // erts_proc_sig_send_dist_exit with the reason still encoded.
                erts_proc_sig_send_dist_altact_exit(sched, sender, to, message, prio)?;
            } else {
                erts_proc_sig_send_dist_altact_msg(sched, Some(sender), to, message, prio)?;
            }
        }
        // DOP_MONITOR_P_EXIT {21, Watched, Watcher, Ref, Reason},
        // DOP_PAYLOAD_MONITOR_P_EXIT {28, Watched, Watcher, Ref}:
        // erts_proc_sig_send_dist_monitor_down.
        21 | 28 => {
            if arity != if op == 28 { 4 } else { 5 } {
                return Err(badarg());
            }
            let (watched, watcher, reference) = (parts[1], parts[2], parts[3]);
            if !ctl_is_ref(reference) {
                return Err(badarg());
            }
            let watched_pid = ctl_external_pid(watched);
            if watched_pid.is_none() && watched.as_atom().is_none() {
                return Err(badarg());
            }
            let Some(watcher) = ctl_internal_pid(watcher) else {
                if ctl_external_pid(watcher).is_some() && ctl_is_this_node(watcher) {
                    // Monitored process not alive.
                    return Ok(());
                }
                return Err(badarg());
            };
            let id = ctl_ref_id(reference).ok_or_else(badarg)?;
            // The watcher finds the origin half by reference; the sender orders the DOWN
            // behind the dead process' signals.
            let from = match watched_pid {
                Some(pid) => remote_proxy(handle, pid)?,
                None => watcher,
            };
            let reason = if op == 21 {
                Message::copy_from(parts[4])?
            } else {
                Message::dist_external(edep, None)
            };
            // A dead watcher drops it ("Process not alive").
            let _ = sched.signal(
                from,
                watcher,
                Signal::MonitorDown {
                    reference: id,
                    reason: Box::new(reason),
                },
            );
        }
        // DOP_EXIT {3, From, To, Reason}, DOP_EXIT_TT {13, From, To, Token, Reason},
        // DOP_PAYLOAD_EXIT {24, From, To}, DOP_PAYLOAD_EXIT_TT {25, From, To, Token}:
        // erts_proc_sig_send_dist_link_exit.
        3 | 13 | 24 | 25 => {
            let expected = match op {
                3 => 4,
                13 => 5,
                24 => 3,
                _ => 4,
            };
            if arity != expected {
                return Err(badarg());
            }
            let token = dist_token(matches!(op, 13 | 25).then(|| parts[3]))?;
            let remote = dep_pid(parts[1]).ok_or_else(badarg)?;
            let to = ctl_internal_pid(parts[2]).ok_or_else(badarg)?;
            let reason = dist_exit_reason(op < 24, parts, edep, token)?;
            let proxy = remote_proxy(handle, remote)?;
            elink::incoming_exit(runtime, proxy, remote, to, true, reason)?;
        }
        // DOP_EXIT2 {8, ..}, DOP_EXIT2_TT {18, ..}, DOP_PAYLOAD_EXIT2 {26, ..},
        // DOP_PAYLOAD_EXIT2_TT {27, ..}: erts_proc_sig_send_dist_exit.
        8 | 18 | 26 | 27 => {
            let expected = match op {
                8 => 4,
                18 => 5,
                26 => 3,
                _ => 4,
            };
            if arity != expected {
                return Err(badarg());
            }
            let token = dist_token(matches!(op, 18 | 27).then(|| parts[3]))?;
            let from = parts[1];
            let remote = dep_pid(from).ok_or_else(badarg)?;
            let to = parts[2];
            let Some(to) = ctl_internal_pid(to) else {
                if ctl_external_pid(to).is_some() && ctl_is_this_node(to) {
                    // Old incarnation of this node.
                    return Ok(());
                }
                return Err(badarg());
            };
            let reason = dist_exit_reason(op < 24, parts, edep, token)?;
            let proxy = remote_proxy(handle, remote)?;
            elink::incoming_exit(runtime, proxy, remote, to, false, reason)?;
        }
        // DOP_SPAWN_REQUEST {29, ReqId, From, GroupLeader, {M,F,Arity}, Opts},
        // DOP_SPAWN_REQUEST_TT {30, .., Token} (token dropped, DIST-TOKEN-1); the argument
        // list in the payload.
        29 | 30 => {
            if arity != if op == 30 { 7 } else { 6 } {
                return Err(badarg());
            }
            handle_spawn_request(runtime, handle, parts, edep)?;
        }
        // DOP_SPAWN_REPLY {31, ReqId, To, Flags, Result}, DOP_SPAWN_REPLY_TT {32, .., Token}.
        31 | 32 => {
            if arity != if op == 32 { 6 } else { 5 } {
                return Err(badarg());
            }
            dist_spawn_reply(runtime, handle, parts)?;
        }
        _ => return Err(badarg()),
    }
    Ok(())
}

/// The reason of a `DOP_EXIT*` / `DOP_EXIT2*` signal: the last control element copied into
/// the signal (`reason = tuple[N]`, `edep = NULL`), or the payload still encoded for the
/// `DOP_PAYLOAD_*` variants; the token travels with it.
// Port of erts/emulator/beam/erl_proc_sig_queue.c (erts_proc_sig_send_dist_link_exit,
// erts_proc_sig_send_dist_exit: send_gen_exit_signal with `reason` or `edep`), OTP-29.1.1.
fn dist_exit_reason(
    in_control: bool,
    parts: &[Term],
    edep: Box<crate::natives::external_dist::ErtsDistExternal>,
    token: Option<Box<crate::seq_trace::Token>>,
) -> Result<Message, VmError> {
    if !in_control {
        return Ok(Message::dist_external(edep, token));
    }
    let mut reason = Message::copy_from(parts[parts.len() - 1])?;
    if let Some(token) = token {
        reason.attach_seq_token(token);
    }
    Ok(reason)
}

/// `erts_proc_sig_send_dist_altact_msg(from, to, edep, hfrag, token, prio)`: a message to a
/// pid or an alias, its payload still encoded. A target that names no local process drops it.
// Port of erts/emulator/beam/erl_proc_sig_queue.c (erts_proc_sig_send_dist_altact_msg),
// OTP-29.1.1.
fn erts_proc_sig_send_dist_altact_msg(
    sched: &arinsal_sched::Scheduler<Process>,
    from: Option<Pid>,
    to: Term,
    mut message: Message,
    prio: bool,
) -> Result<(), VmError> {
    let target = if ctl_is_ref(to) {
        message = message.with_alias(ctl_ref_id(to).ok_or_else(badarg)?);
        ctl_alias_pid(to)
    } else {
        ctl_internal_pid(to)
    };
    let Some(target) = target else {
        return Ok(());
    };
    if prio {
        message = message.with_priority();
    }
    sched
        .send(from.unwrap_or(target), target, message)
        .map_err(|error| VmError::Unsupported(format!("dist altact send: {error}")))
}

/// `erts_proc_sig_send_dist_exit(dep, from, to, edep, hfrag, THE_NON_VALUE, token, prio)` of a
/// `DOP_ALTACT_SIG_SEND` with `ERTS_DOP_ALTACT_SIG_FLG_EXIT`.
// Port of erts/emulator/beam/erl_proc_sig_queue.c (erts_proc_sig_send_dist_exit), OTP-29.1.1.
fn erts_proc_sig_send_dist_altact_exit(
    sched: &arinsal_sched::Scheduler<Process>,
    from: Pid,
    to: Term,
    mut message: Message,
    prio: bool,
) -> Result<(), VmError> {
    let target = if ctl_is_ref(to) {
        message = message.with_alias(ctl_ref_id(to).ok_or_else(badarg)?);
        ctl_alias_pid(to)
    } else {
        ctl_internal_pid(to)
    };
    let Some(target) = target else {
        return Ok(());
    };
    if prio {
        message = message.with_priority();
    }
    let _ = sched.signal(from, target, Signal::Exit(Box::new(message)));
    Ok(())
}

fn remote_proxy(handle: u64, remote: crate::monitor_link::ExternalPid) -> Result<Pid, VmError> {
    let key = (remote.number, remote.serial, remote.creation);
    let local_creation = node_tables::this_node().1;
    let node = global_atoms()
        .text(arinsal_term::Atom(remote.sysname))
        .ok_or_else(badarg)?;
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
    let owned = elink::external_pid_owned(remote).ok_or_else(badarg)?;
    let pid = Pid::new(
        NEXT_REMOTE_PID.fetch_add(1, Ordering::Relaxed) & ((1 << 28) - 1),
        local_creation,
    );
    PROXIES_CREATED.store(true, Ordering::Release);
    state.remote_pids.insert(key, pid);
    state.proxy_to_remote.insert(pid, owned);
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

/// The key of a reference with numbers `ids` (in ETF order).
fn ref_key(ids: &[u32]) -> Option<u64> {
    if ids.len() >= 3 {
        return Some(arinsal_sched::unique::ordinary_ref_key([
            ids[0], ids[1], ids[2],
        ]));
    }
    let mut value = 0_u64;
    for (index, id) in ids.iter().take(2).enumerate() {
        value |= u64::from(*id) << (index * 32);
    }
    Some(value)
}

/// Queue one remote signal packet using the destination's negotiated atom cache.
///
/// Port of erts/emulator/beam/dist.c (`erts_dsig_prepare` + pending queue), OTP-29.1.1.
/// When the peer is not yet connected, auto-connects via `{auto_connect, Node, DHandle}`
/// to `net_kernel` and buffers the signal until `create_dist_channel` succeeds.
pub(crate) fn queue_outgoing(
    process: &mut Process,
    ctx: &mut RunCtx<'_, crate::Process>,
    node: &str,
    control: Term,
    message: Option<Term>,
) -> Result<(), VmError> {
    match queue_outgoing_with_options(
        process, ctx, node, control, message, true, true, false, None,
    )? {
        DistSendResult::Queued => Ok(()),
        DistSendResult::NotConnected | DistSendResult::WouldSuspend => Err(badarg()),
        DistSendResult::Continue(_) => unreachable!("a no_trap send never leaves fragments"),
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
    ctx: &mut RunCtx<'_, crate::Process>,
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
    ctx: &mut RunCtx<'_, crate::Process>,
    node: &str,
    connection_id: u32,
    control: Term,
    message: Option<Term>,
) -> Result<(), VmError> {
    match queue_outgoing_with_options(
        process,
        ctx,
        node,
        control,
        message,
        false,
        true,
        false,
        Some(connection_id),
    )? {
        DistSendResult::Queued | DistSendResult::NotConnected => Ok(()),
        DistSendResult::WouldSuspend => Err(badarg()),
        DistSendResult::Continue(_) => unreachable!("a no_trap send never leaves fragments"),
    }
}

#[derive(Debug)]
enum DistSendResult {
    Queued,
    NotConnected,
    WouldSuspend,
    /// `ERTS_DSIG_SEND_CONTINUE`: the context holds the fragments still to send.
    Continue(DsigSendContext),
}

// Port of erts/emulator/beam/dist.c:3216-3280 (erts_dsig_prepare), OTP-29.1.1.
#[allow(clippy::too_many_arguments)]
fn queue_outgoing_with_options(
    process: &mut Process,
    ctx: &mut RunCtx<'_, crate::Process>,
    node: &str,
    control: Term,
    message: Option<Term>,
    connect: bool,
    suspend: bool,
    trap: bool,
    expect_connection: Option<u32>,
) -> Result<DistSendResult, VmError> {
    if !node_tables::is_alive() {
        return Ok(DistSendResult::NotConnected);
    }
    if node == node_tables::this_node().0 {
        return Err(badarg());
    }
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
        // erts_dsig_send with `ctx->no_trap = !trap` and `ctx->no_suspend = !suspend`, for a
        // port or a process controller alike: the encode phases run on the sender's
        // reductions and a trapping send continues in dsend_continue_trap/1.
        let mut encode = DsigEncode::new(
            control,
            message,
            state.flags,
            dsig_from(Some(ctx.pid())),
            arinsal_term::this_node,
        );
        let initial_reds = dsig_initial_reds(process);
        let mut reds = initial_reds;
        let res = encode.step(Some(&state.acmp), &mut reds, !trap);
        let mut send_ctx = DsigSendContext {
            dep: dep.clone(),
            connection_id: conn_id,
            encode: None,
            fragments: VecDeque::new(),
            no_suspend: !suspend,
            return_term: Term::NIL,
        };
        match res.map_err(|_| badarg())? {
            DsigEncodeResult::TooLarge => {
                drop(entry);
                dsig_bump_reds(process, initial_reds, reds);
                return Err(dsig_system_limit());
            }
            DsigEncodeResult::Continue => {
                // erts_dsend_export_trap_context.
                encode.export(Some(&state.acmp));
                send_ctx.encode = Some(Box::new(encode));
                drop(entry);
                dsig_bump_reds(process, initial_reds, reds);
                return Ok(DistSendResult::Continue(send_ctx));
            }
            DsigEncodeResult::Send => send_ctx.fragments = encode.take_obufs().into(),
        }
        drop(entry);
        dsig_bump_reds(process, initial_reds, reds);
        return Ok(match dsig_send(process, &mut send_ctx, ctx.pid(), !trap)? {
            DsigSend::Continue => DistSendResult::Continue(send_ctx),
            DsigSend::Ok | DsigSend::Yield => DistSendResult::Queued,
        });
    }

    // Pending (or Connected without a controller yet): encoded with DFLAG_PENDING_CONNECT
    // and buffered until the channel is up.
    let signal = node_tables::encode_pending(control, message, dsig_from(Some(ctx.pid())))
        .map_err(|_| badarg())?;
    entry.pending_out.push_back(signal);
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
    ctx: &mut RunCtx<'_, crate::Process>,
    node: &str,
    conn_id: u32,
    entry_ref: u64,
) -> Result<bool, VmError> {
    let runtime = process.runtime.ok_or_else(badarg)?;
    let Some(net_kernel) = runtime.reg.whereis_proc_str("net_kernel") else {
        abort_pending_connection_locally(runtime, node, conn_id, entry_ref)?;
        return Ok(false);
    };
    // {auto_connect, Node, DHandle} with the erts_build_dhandle {ConnId, Ref} handle.
    let mut heap = arinsal_term::VecHeap::with_initial_chunk_words(16);
    let conn = Term::small(i64::from(conn_id)).ok_or_else(badarg)?;
    let mut builder = TermBuilder::new(&mut heap);
    let dref = builder
        .local_ref(arinsal_sched::unique::ordinary_ref_words(entry_ref))
        .map_err(|_| badarg())?;
    let dhandle = builder.tuple(&[conn, dref]).map_err(|_| badarg())?;
    let msg = builder
        .tuple(&[atom_term("auto_connect")?, atom_term(node)?, dhandle])
        .map_err(|_| badarg())?;
    ctx.send(net_kernel, Message::copy_from(msg)?)
        .map_err(|error| VmError::Unsupported(format!("auto_connect notify: {error}")))?;
    Ok(true)
}

/// Abort a pending connection and release its links, monitors and spawn requests.
// Port of erts/emulator/beam/dist.c:5681 (abort_pending_connection), OTP-29.1.1.
fn abort_pending_connection_locally(
    runtime: &'static crate::process::Runtime,
    node: &str,
    conn_id: u32,
    entry_ref: u64,
) -> Result<(), VmError> {
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
        let mld = if aborts { tables.take_mld(node) } else { None };
        let _ = tables.abort_pending(node, conn_id, entry_ref);
        mld
    };
    elink::links_connection_down(runtime, mld.clone());
    emon::monitors_connection_down(runtime, mld.as_ref());
    Ok(())
}

/// `net_kernel` exited: kill every distribution controller port, abort the pending
/// connections and drop net_kernel's own `no_nodes` count; the node goes not-alive once the
/// last controller is gone.
// Port of erts/emulator/beam/dist.c:922 (erts_do_net_exits, `dep == erts_this_dist_entry`
// branch and the final dec_no_nodes), OTP-29.1.1.
pub(crate) fn net_kernel_exited(
    process: &mut Process,
    runtime: &'static crate::process::Runtime,
    reason: Term,
) -> Result<(), VmError> {
    let no_network = global_atoms().intern("no_network").ok();
    let nd_reason = if reason.as_atom().is_some() && reason.as_atom() == no_network {
        "no_network"
    } else {
        "net_kernel_terminated"
    };
    let (ports, pending) = {
        let tables = node_tables::lock();
        let mut ports = Vec::new();
        let mut pending = Vec::new();
        for (name, dep) in &tables.entries {
            let entry = dep.lock();
            if let Some(port_id) = entry.dist.as_ref().and_then(|state| state.port_id)
                && entry.state == node_tables::ConnState::Connected
            {
                ports.push(port_id);
            } else if entry.state == node_tables::ConnState::Pending {
                pending.push((name.clone(), entry.connection_id, entry.entry_ref));
            }
        }
        (ports, pending)
    };
    let reason_term = Term::atom(global_atoms().intern(nd_reason).map_err(|_| badarg())?);
    for port_id in ports {
        if let Some(port) = Term::port(port_id) {
            crate::port::exit_port(process, port, reason_term)?;
        }
    }
    for (name, conn_id, entry_ref) in pending {
        abort_pending_connection_locally(runtime, &name, conn_id, entry_ref)?;
    }
    node_tables::set_nodedown_reason(nd_reason);
    node_tables::dec_no_nodes(runtime);
    Ok(())
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
    // The port's own `ERTS_PRTSD_DIST_ENTRY` reference: only the entry lock is taken.
    let (handle, connection_id, packet) = {
        let mut entry = dep.lock();
        let connection_id = entry.connection_id;
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
        .ok()
        .map(|packet| reassemble_fragment(state, packet));
        (state.handle, connection_id, packet)
    };
    match packet {
        Some(Ok(Some(packet))) => {
            erts_net_message(runtime, handle, &dep.sysname, connection_id, packet);
        }
        // A fragment of a signal still being reassembled.
        Some(Ok(None)) => {}
        // dist.c erts_net_message `data_error`: erts_kill_dist_connection.
        Some(Err(_)) | None => {
            let _ = kill_connection(runtime, &dep.sysname, connection_id);
        }
    }
    Ok(())
}

/// Reassemble one ordered OTP distribution signal before decoding its ETF terms.
///
/// Port of erts/emulator/beam/dist.c:2119-2165, OTP-29.1.1.
fn reassemble_fragment(
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
    let (watchers, node_events, mld, suspendees) = {
        let mut tables = node_tables::lock();
        let (connection_id, visible, suspendees) = {
            let mut entry = dep.lock();
            // Port of erts/emulator/beam/dist.c:3599-3611 (discard output from an obsolete
            // connection), OTP-29.1.1.
            if !entry
                .dist
                .as_ref()
                .is_some_and(|state| state.port_id == Some(port_id))
            {
                return Ok(());
            }
            (
                entry.connection_id,
                entry.visible,
                get_suspended_on_de(&mut entry),
            )
        };
        let mld = tables.take_mld(&node);
        let watchers = tables.disconnect(&node);
        let events = tables.nodes_monitor_events(
            "nodedown",
            &node,
            connection_id,
            visible,
            Some("connection_closed"),
        );
        (watchers, events, mld, suspendees)
    };
    elink::links_connection_down(runtime, mld.clone());
    emon::monitors_connection_down(runtime, mld.as_ref());
    resume_dist_senders(runtime, suspendees);
    notify_node_watchers(runtime, &node, watchers)?;
    send_nodes_monitor_events(runtime.scheduler()?, node_events)?;
    // Port of erts/emulator/beam/dist.c:1114 (erts_do_net_exits: dec_no_nodes).
    node_tables::dec_no_nodes(runtime);
    Ok(())
}

/// Kill a connected distribution entry that has no port controller.
/// Port of erts/emulator/beam/dist.c:4788-4811 (`erts_kill_dist_connection`), OTP-29.1.1.
pub(crate) fn kill_connection(
    runtime: &crate::process::Runtime,
    node: &str,
    connection_id: u32,
) -> Result<bool, VmError> {
    let (watchers, node_events, mld, suspendees) = {
        let mut tables = node_tables::lock();
        let Some(mut entry) = tables.entries.get(node).map(|dep| dep.lock()) else {
            return Ok(false);
        };
        if !entry.connected || entry.connection_id != connection_id {
            return Ok(false);
        }
        let visible = entry.visible;
        let suspendees = get_suspended_on_de(&mut entry);
        drop(entry);
        let mld = tables.take_mld(node);
        let watchers = tables.disconnect(node);
        let events =
            tables.nodes_monitor_events("nodedown", node, connection_id, visible, Some("killed"));
        (watchers, events, mld, suspendees)
    };
    elink::links_connection_down(runtime, mld.clone());
    emon::monitors_connection_down(runtime, mld.as_ref());
    resume_dist_senders(runtime, suspendees);
    notify_node_watchers(runtime, node, watchers)?;
    send_nodes_monitor_events(runtime.scheduler()?, node_events)?;
    // Port of erts/emulator/beam/dist.c:1114 (erts_do_net_exits: dec_no_nodes).
    node_tables::dec_no_nodes(runtime);
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

pub(crate) fn send_nodes_monitor_events(
    scheduler: &arinsal_sched::Scheduler<Process>,
    events: Vec<node_tables::NodesMonitorEvent>,
) -> Result<(), VmError> {
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

fn dist_spawn_request(
    vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, crate::Process>,
    args: &[Term],
) -> Result<Term, VmError> {
    // Port of erts/emulator/beam/dist.c:5827 (erts_internal_dist_spawn_request_4), OTP-29.1.1.
    let Some(node) = atom_name(args[0]) else {
        return fallback_dist_spawn(vm, process, ctx, args);
    };
    let (local, alive) = {
        (
            crate::node_tables::this_node().0.to_owned(),
            node_tables::is_alive(),
        )
    };
    if node == local || node == "nonode@nohost" || !alive {
        return fallback_dist_spawn(vm, process, ctx, args);
    }
    // dist.c erts_internal_dist_spawn_request_4: ERTS_DSIG_PREP_NOT_ALIVE and
    // ERTS_DSIG_PREP_NOT_CONNECTED reply `{error, noconnection}` at once.
    let (connection_id, mld) = match dsig_prepare(process, ctx, &node)? {
        DsigPrepare::Connected { connection_id, mld } => (connection_id, mld),
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
    let option_terms = crate::signals::list(args[2]).ok_or_else(badarg)?;
    let kind = atom_name(args[3]).ok_or_else(badarg)?;
    let id = arinsal_sched::unique::next_ref_id();
    let reference = crate::signals::reference(process, id)?;
    let mut tag = Term::atom(arinsal_term::atoms::SPAWN_REPLY);
    let mut monitor_tag = None;
    let mut monitor = false;
    let mut monitor_priority = false;
    let mut link = false;
    let mut link_priority = false;
    let mut no_success_msg = false;
    let mut no_error_msg = false;
    let mut wire_opts = Vec::new();
    match &options {
        OwnedTerm::Nil => {}
        OwnedTerm::List { elems, tail } if **tail == OwnedTerm::Nil => {
            for (option, original) in elems.iter().zip(option_terms.iter().copied()) {
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
                            tag = crate::natives::proc::tuple2(original).ok_or_else(badarg)?.1;
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
                            let (down_tag, _, priority) = crate::signals::spawn_monitor_options(
                                crate::natives::proc::tuple2(original).ok_or_else(badarg)?.1,
                            )
                            .ok_or_else(badarg)?;
                            monitor_tag = down_tag;
                            monitor_priority = priority;
                            wire_opts.push(OwnedTerm::Atom("monitor".into()));
                        }
                        // dist.c:5954-5956: `{link, Prio}` sets SPAWN_LINK and optionally
                        // SPAWN_LINK_PRIO; the peer receives the normalized `link` option.
                        OwnedTerm::Atom(name) if name == "link" => {
                            let priority = crate::natives::bif::erts_link_opts(
                                crate::natives::proc::tuple2(original).ok_or_else(badarg)?.1,
                            )
                            .ok_or_else(badarg)?;
                            link = true;
                            link_priority |= priority;
                            wire_opts.push(OwnedTerm::Atom("link".into()));
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
    // dist.c dsig_send_spawn_request: {DOP_SPAWN_REQUEST, Ref, From, GL, {M,F,A}, Opts}
    // with the argument list as the payload.
    // dist.c erts_internal_dist_spawn_request_4: `dsig_send_spawn_request(&ctx, ref,
    // BIF_P->common.id, BIF_P->group_leader, ...)`, the caller's group leader.
    let me = ctx.pid();
    let leader = process.group_leader_pid(me);
    let group_leader = match remote_pid_term(process, leader)? {
        Some(remote) => remote,
        None => local_pid_term(leader),
    };
    let mut ctl = CtlHeap::new();
    let fields = [
        reference,
        local_pid_term(me),
        group_leader,
        ctl.owned(&mfa_control)?,
        ctl.owned(&wire_options)?,
    ];
    let control = ctl.control(29, &fields)?;
    let spawn_args = ctl.owned(&values[2])?;
    // Port of erts/emulator/beam/dist.c:6112-6125 (erts_internal_dist_spawn_request_4),
    // OTP-29.1.1: the pending-spawn monitor of the request. Its origin half, with `am_pending`
    // as other item and the reply tag in the monitor, goes into the caller's monitor tree;
    // its target half into the connection.
    use crate::monitor_link::node_flag;
    let mut oflags = node_flag::SPAWN_PENDING;
    for (set, flag) in [
        (monitor, node_flag::SPAWN_MONITOR),
        (link, node_flag::SPAWN_LINK),
        (link_priority, node_flag::SPAWN_LINK_PRIO),
        (no_success_msg, node_flag::SPAWN_NO_SMSG),
        (no_error_msg, node_flag::SPAWN_NO_EMSG),
        (monitor_priority, node_flag::PRIO_ML),
    ] {
        if set {
            oflags |= flag;
        }
    }
    let info = crate::proc_create::MonitorInfo::new(monitor_tag, None).with_dist_target(
        crate::proc_create::DistTarget::spawn_pending(reference, tag, mld.clone()),
    );
    let (mut origin, target) = crate::monitor_link::Monitor::create(
        crate::monitor_link::node_type::MONITOR_DIST_PROC,
        crate::monitor_link::MonitorReference::ordinary(id),
        me.data(),
        0,
        0,
        info,
        crate::proc_create::OriginMonitor::Distributed,
    );
    origin.add_flags(oflags);
    process.monitors.insert(origin);
    if let Err(target) = mld.monitor_insert(target) {
        // The connection went down after dsig_prepare: its monitor-down reaches this
        // request as if the target half had been in it.
        drop(target);
        emon::send_monitor_down_noconnection(
            process.runtime.as_ref().ok_or_else(badarg)?.scheduler()?,
            me,
            id,
        );
    }
    if monitor_priority {
        process.prio_item_added(crate::receive::PrioItemType::Monitor);
    }
    if let Err(error) = queue_outgoing_on(
        process,
        ctx,
        &node,
        connection_id,
        control,
        Some(spawn_args),
    ) {
        if let Some(origin) = process.monitors.remove(id) {
            if origin.view().prio_ml() {
                process.prio_item_deleted(crate::receive::PrioItemType::Monitor);
            }
            emon::release_origin(origin);
        }
        return Err(error);
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
    ctx: &mut RunCtx<'_, crate::Process>,
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
/// Arinsal copies the reference and the result into the signal's heap the same way
/// (`copy_struct` into `mp->hfrag`) and builds the message tuple on the receiver heap.
pub(crate) struct DistSpawnReplyData {
    /// The connection the reply arrived on (erts: `dep` plus its connection id).
    handle: u64,
    /// Key of the request reference.
    id: u64,
    /// `datap->ref`, in `heap`.
    reference: Term,
    /// The parent, for DOP_DEMONITOR.
    parent: Pid,
    /// `datap->result`: the child pid in `heap`, or the error atom of a failed spawn.
    result: Term,
    /// `mp->hfrag`: the copies of `reference` and `result`.
    _heap: crate::proc_create::HeapFrag,
    /// The DOP_SPAWN_REPLY flags.
    flags: u64,
    /// `datap->link`: the proc half of the external link to the child of a successful spawn
    /// with link, its dist half already in the connection.
    link: Option<elink::DistLinkHalf>,
}

impl DistSpawnReplyData {
    /// Key of the request reference (`datap->ref`).
    pub(crate) fn id(&self) -> u64 {
        self.id
    }

    /// `datap->result`: the child pid, or the error atom of a failed spawn.
    pub(crate) fn result(&self) -> Term {
        self.result
    }

    /// The spawn succeeded: the result is the child pid.
    pub(crate) fn is_success(&self) -> bool {
        self.result.as_atom().is_none()
    }

    /// The remote monitors the child.
    fn monitor(&self) -> bool {
        self.is_success() && self.flags & DIST_SPAWN_FLAG_MONITOR != 0
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
    parts: &[Term],
) -> Result<(), VmError> {
    let node = {
        let tables = node_tables::lock();
        tables
            .entries
            .values()
            .map(|dep| dep.lock())
            .find(|entry| {
                entry
                    .dist
                    .as_ref()
                    .is_some_and(|state| state.handle == handle)
            })
            .map(|entry| entry.name.clone())
    };
    let Some(_node) = node else {
        // The connection went down while the reply was routed.
        return Ok(());
    };
    let (reference, parent, flags_term, result) = (parts[1], parts[2], parts[3], parts[4]);
    let Some(parent_pid) = ctl_internal_pid(parent) else {
        if ctl_external_pid(parent).is_some() && ctl_is_this_node(parent) {
            // Old incarnation of this node.
            return Ok(());
        }
        return Err(badarg());
    };
    let parent = parent_pid;
    if !ctl_is_internal_ref(reference) {
        if ctl_is_ref(reference) && ctl_is_this_node(reference) {
            // Old incarnation of this node.
            return Ok(());
        }
        return Err(badarg());
    }
    let id = ctl_ref_id(reference).ok_or_else(badarg)?;
    let flags = flags_term
        .as_small()
        .and_then(|flags| u64::try_from(flags).ok())
        .ok_or_else(badarg)?;
    if flags >= 1 << 27 {
        return Err(badarg());
    }
    let remote_child = ctl_external_pid(result);
    if remote_child.is_none() && result.as_atom().is_none() {
        return Err(badarg());
    }
    let child = remote_child
        .map(|remote| remote_proxy(handle, remote))
        .transpose()?;
    // Successful spawn-link: the link the parent inserts (dist.c DOP_SPAWN_REPLY:
    // erts_link_external_create, erts_link_dist_insert).
    let link = match remote_child {
        Some(remote) if flags & DIST_SPAWN_FLAG_LINK != 0 => {
            Some(elink::spawn_reply_link(runtime, handle, parent, remote)?)
        }
        _ => None,
    };
    // erl_proc_sig_queue.c erts_proc_sig_send_dist_spawn_reply: ref and result copied into
    // the signal's heap fragment.
    let (heap, [reference, result]) = crate::proc_create::HeapFrag::copy([reference, result]);
    let data = std::sync::Arc::new(DistSpawnReplyData {
        handle,
        id,
        reference,
        parent,
        result,
        _heap: heap,
        flags,
        link,
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

/// A `DOP_SPAWN_REQUEST[_TT]` queued toward a pending connection whose peer turned out not to
/// support distributed spawn: decode its control message and answer the spawning process with
/// `notsup`.
// Port of erts/emulator/beam/external.c (transcode_dist_obuf: transcode_decode_ctl_msg,
// erts_proc_sig_send_dist_spawn_reply(dep->sysname, ref, pid, NULL, am_notsup, token)),
// OTP-29.1.1.
fn transcode_spawn_notsup(runtime: &crate::process::Runtime, handle: u64, ctl: &[u8]) {
    use crate::natives::external_dist::{
        ERTS_DIST_EXT_DFLAG_HDR, ErtsDistExternal, ErtsDistExternalData, erts_decode_dist_ext,
        erts_decode_dist_ext_size,
    };
    let mut edep = ErtsDistExternal {
        data: ErtsDistExternalData {
            extp: 0,
            ext_endp: ctl.len(),
            binp: ctl.into(),
        },
        flags: ERTS_DIST_EXT_DFLAG_HDR,
        connection_id: 0,
        heap_size: -1,
        dep: arinsal_term::atoms::NONAME,
        attab: Box::default(),
        size_state: Default::default(),
    };
    // This node encoded the control message, so it decodes.
    let Ok(hsz) = usize::try_from(erts_decode_dist_ext_size(None, &mut edep, false)) else {
        return;
    };
    let mut heap = arinsal_term::message::NodeFragment::new_message_buffer(hsz);
    let ctl_msg = {
        let mut target = heap.fragment_mut();
        let Ok(mut factory) = arinsal_term::HeapReservation::new(&mut target, hsz) else {
            return;
        };
        erts_decode_dist_ext(None, &mut factory, &mut edep, false)
    };
    let Some(tuple) = ctl_msg.and_then(|ctl| arinsal_term::raw::Tuple::try_from(ctl).ok()) else {
        return;
    };
    // {DOP_SPAWN_REPLY, Ref, Pid, 0, notsup}: the reply handling of dist_spawn_reply with an
    // error result inserts no link or monitor and only signals the parent.
    let (Some(reference), Some(pid), Ok(notsup)) =
        (tuple.get(1), tuple.get(2), atom_term("notsup"))
    else {
        return;
    };
    let parts = [
        Term::small(31).unwrap_or(Term::NIL),
        reference,
        pid,
        Term::small(0).unwrap_or(Term::NIL),
        notsup,
    ];
    let _ = dist_spawn_reply(runtime, handle, &parts);
    drop(heap);
}

/// erts_proc_sig_send_dist_spawn_reply failed: the parent left the process table. A
/// monitored child is demonitored, and for a spawn with link the result is saved so the
/// terminating parent can send the child an exit signal with the correct exit reason.
///
/// Port of erts/emulator/beam/dist.c:3090-3121 (DOP_SPAWN_REPLY), OTP-29.1.1. The link half
/// was never inserted in a process; it is released with the reply data.
pub(crate) fn spawn_reply_send_failed(
    runtime: &crate::process::Runtime,
    data: &DistSpawnReplyData,
) {
    if data.monitor() {
        spawn_reply_demonitor(
            runtime,
            data.handle,
            data.parent,
            data.result,
            data.reference,
        );
    }
    if data.flags & DIST_SPAWN_FLAG_LINK != 0
        && let Some((_node, _connection_id, mld)) = elink::connection_of_handle(data.handle)
    {
        dist_pend_spawn_exit_save_child_result(data.result, data.reference, data.id, &mld);
    }
}

/// The `am_pending` other item of a spawn request still waiting for its reply.
fn is_pending(item: Term) -> bool {
    item == Term::atom(arinsal_term::atoms::PENDING)
}

/// The distribution target of a pending-spawn monitor half.
fn spawn_target<'a>(
    monitor: crate::monitor_link::MonitorRef<
        'a,
        crate::proc_create::MonitorInfo,
        crate::proc_create::OriginMonitor,
        crate::proc_create::MonitorSignal,
    >,
) -> &'a crate::proc_create::DistTarget {
    monitor
        .info()
        .dist_target()
        .expect("a pending-spawn monitor has a distribution target")
}

/// Store the result of a spawn with link for its terminating parent and resume the parent if
/// it suspended waiting for it. A parent that did not reach its pending-spawn phase yet finds
/// the result in a record monitor in `dist_pend_spawn_exit`.
///
/// Port of erts/emulator/beam/dist.c:552-640 (dist_pend_spawn_exit_save_child_result),
/// OTP-29.1.1: erts_resume after `dist->mtx` is released.
fn dist_pend_spawn_exit_save_child_result(
    result: Term,
    reference: Term,
    id: u64,
    dist: &std::sync::Arc<crate::monitor_link::MonLnkDist>,
) {
    let mut new_mdp: Option<crate::proc_create::ProcessMonitor> = None;
    let mut resume = None;
    loop {
        let done = dist
            .with_pend_spawn_exit(|tree: &mut crate::proc_create::MonitorTree| {
                match tree.get(id) {
                    None => match new_mdp.take() {
                        Some(record) => {
                            // Save info so the parent can get the child pid when handling
                            // links during termination.
                            tree.insert(record);
                            true
                        }
                        None => false,
                    },
                    Some(monitor) => {
                        // The terminating parent is waiting for this signal: store the
                        // child's pid and resume the parent if it has suspended.
                        let target = spawn_target(monitor);
                        target.set_item(result);
                        resume = target.swap_waiter(None);
                        true
                    }
                }
            })
            // !dist->alive
            .unwrap_or(true);
        if done {
            break;
        }
        // No monitor previously saved by the parent; create one and store the child pid.
        let info = crate::proc_create::MonitorInfo::default().with_dist_target(
            crate::proc_create::DistTarget::new(result, reference, dist.clone()),
        );
        let (origin, target) = crate::monitor_link::Monitor::create(
            crate::monitor_link::node_type::MONITOR_DIST_PROC,
            crate::monitor_link::MonitorReference::ordinary(id),
            0,
            0,
            0,
            info,
            crate::proc_create::OriginMonitor::Distributed,
        );
        drop(origin);
        new_mdp = Some(target);
    }
    drop(resume);
    drop(new_mdp);
}

/// Mark the outstanding spawn request `id` of `process` abandoned, or drop it when it has no
/// link. Returns false when `id` is not an outstanding request of `process`.
///
/// Port of erts/emulator/beam/bif.c:1166 (spawn_request_abandon_1), OTP-29.1.1, for a
/// distributed request.
pub(crate) fn spawn_request_abandon(process: &mut Process, id: u64) -> bool {
    use crate::monitor_link::node_flag;
    let Some(flags) = process.monitors.get(id).map(|omon| omon.flags()) else {
        return false;
    };
    if flags & (node_flag::SPAWN_PENDING | node_flag::SPAWN_ABANDONED) != node_flag::SPAWN_PENDING
        || flags & node_flag::TARGET != 0
    {
        // Not an outstanding spawn_request of this process.
        return false;
    }
    if flags & node_flag::SPAWN_LINK != 0 {
        // Leave it for the reply.
        if let Some(mut omon) = process.monitors.get_mut(id) {
            omon.update_flags(node_flag::SPAWN_ABANDONED, node_flag::PRIO_ML);
        }
    } else if let Some(origin) = process.monitors.remove(id) {
        // We don't need it anymore; remove it.
        emon::release_origin(origin);
    }
    if flags & node_flag::PRIO_ML != 0 {
        process.prio_item_deleted(crate::receive::PrioItemType::Monitor);
    }
    true
}

/// The reply tag in the shared data `info` of a pending-spawn monitor (`mdep->u.name`).
pub(crate) fn spawn_reply_tag_of(info: &crate::proc_create::MonitorInfo) -> Term {
    info.dist_target()
        .and_then(crate::proc_create::DistTarget::reply_tag)
        .unwrap_or(Term::atom(arinsal_term::atoms::SPAWN_REPLY))
}

/// The reply tag of a pending-spawn monitor the process still holds, copied to its heap
/// (`get_heap_frag_eterm(&tag_hfrag, &mdep->u.name)`).
pub(crate) fn spawn_reply_tag(process: &mut Process, tag: Term) -> Result<Term, VmError> {
    copy_term(tag, &mut process.heap).map_err(|_| badarg())
}

/// The `{Tag, Ref, ok|error, Pid|ErrorAtom}` reply message on the parent's heap
/// (erl_proc_sig_queue.c:5741 patch point plus convert_prepared_sig_to_msg).
pub(crate) fn spawn_reply_message(
    process: &mut Process,
    tag: Term,
    data: &DistSpawnReplyData,
) -> Result<Term, VmError> {
    let status = if data.is_success() { "ok" } else { "error" };
    // The reference is the request's own local reference (erts `ref` of the spawn request):
    // an owned remote-style copy would not compare equal to it with `=:=`.
    let reference = crate::signals::reference(process, data.id)?;
    let result = copy_term(data.result, &mut process.heap).map_err(|_| badarg())?;
    let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
    TermBuilder::new(&mut heap)
        .tuple(&[tag, reference, crate::atom_cache::put(status), result])
        .map_err(|_| badarg())
}

/// The `{Tag, Ref, error, Reason}` message of a pending-spawn monitor whose connection went
/// down, on the parent's heap.
///
/// Port of erts/emulator/beam/erl_proc_sig_queue.c:4864-4900 (convert_to_down_message for a
/// spawn-pending monitor), OTP-29.1.1.
pub(crate) fn spawn_down_message(
    process: &mut Process,
    info: &crate::proc_create::MonitorInfo,
    id: u64,
    reason: Term,
) -> Result<Term, VmError> {
    let tag = spawn_reply_tag(process, spawn_reply_tag_of(info))?;
    let reference = crate::signals::reference(process, id)?;
    tuple(
        process,
        vec![
            tag,
            reference,
            Term::atom(arinsal_term::atoms::ERROR),
            reason,
        ],
    )
}

/// The child term of a successful reply on the parent's heap, for the `link` trace event.
pub(crate) fn spawn_reply_child_term(
    process: &mut Process,
    data: &DistSpawnReplyData,
) -> Result<Term, VmError> {
    copy_term(data.result, &mut process.heap).map_err(|_| badarg())
}

/// `erts_dist_pend_spawn_exit_delete(&mdp->u.target)`: take the target half of `origin` out of
/// `dist_pend_spawn_exit`, when the connection is alive and holds it.
// Port of erts/emulator/beam/dist.c:641 (erts_dist_pend_spawn_exit_delete), OTP-29.1.1.
fn dist_pend_spawn_exit_delete(
    origin: &crate::proc_create::ProcessMonitor,
) -> Option<crate::proc_create::ProcessMonitor> {
    let view = origin.view();
    let dist = spawn_target(view).dist.clone();
    let id = view.reference();
    dist.with_pend_spawn_exit(|tree: &mut crate::proc_create::MonitorTree| tree.remove(id))
        .flatten()
}

/// Handle a spawn reply that reaches its parent while the parent is exiting: a monitored child
/// is demonitored and a linked child gets the parent's exit reason, or `abandoned`.
///
/// Port of erts/emulator/beam/erl_proc_sig_queue.c:5927 (handle_dist_spawn_reply_exiting),
/// OTP-29.1.1, on the `pend_spawn_monitors` of the exit context.
pub(crate) fn handle_dist_spawn_reply_exiting(
    runtime: &crate::process::Runtime,
    parent: Pid,
    reason: Term,
    shared: &arinsal_sched::SharedPayload,
    pend_spawn_monitors: &mut crate::proc_create::MonitorTree,
) {
    use crate::monitor_link::node_flag;
    let Some(data) = shared.0.downcast_ref::<DistSpawnReplyData>() else {
        return;
    };
    let Some(omon) = pend_spawn_monitors.remove(data.id) else {
        // May happen when the connection concurrently closed; the link is released with the
        // reply data.
        return;
    };
    let flags = omon.view().flags();
    // `None`: the connection closed or is closing.
    let target = dist_pend_spawn_exit_delete(&omon);
    if let Some(waiter) = spawn_target(omon.view()).swap_waiter(None) {
        // The parent runs this itself; it is not suspended on the request.
        waiter.cancel();
    }
    if data.is_success() {
        if flags & node_flag::SPAWN_MONITOR != 0 && target.is_some() {
            // erts_proc_exit_dist_demonitor on the connection the monitor was made on.
            let dist = spawn_target(omon.view()).dist.clone();
            let mut ctl = CtlHeap::new();
            if let Ok(control) =
                ctl.control(20, &[local_pid_term(parent), data.result, data.reference])
            {
                elink::send_on_connection(
                    runtime,
                    dist.nodename,
                    dist.connection_id,
                    control,
                    None,
                );
            }
        }
        if let Some(link) = data.link() {
            // erts_proc_exit_handle_link: the link exit carries the actual reason, unless the
            // operation was abandoned.
            let reason = if flags & node_flag::SPAWN_ABANDONED != 0 {
                Term::atom(arinsal_term::atoms::ABANDONED)
            } else {
                reason
            };
            proc_exit_handle_link(Some(runtime), parent, link, reason);
        }
    }
    match target {
        Some(target) => crate::proc_create::ProcessMonitor::release_both(omon, target),
        None => drop(omon),
    }
}

/// DOP_DEMONITOR of a child spawned for a parent that no longer takes the reply.
// Port of erts/emulator/beam/dist.c:3092-3101 (erts_dsig_send_demonitor), OTP-29.1.1.
fn spawn_reply_demonitor(
    runtime: &crate::process::Runtime,
    handle: u64,
    parent: Pid,
    child: Term,
    reference: Term,
) {
    let mut ctl = CtlHeap::new();
    let Ok(control) = ctl.control(20, &[local_pid_term(parent), child, reference]) else {
        return;
    };
    let _ = emit_control_message_on_handle(runtime, handle, control, None);
}

/// The MONITORS phase of an exiting parent meets a pending-spawn origin monitor: move the
/// target half from the connection to `dist_pend_spawn_exit`, where a reply that arrives from
/// now on stores the child for this process. Returns false when the monitor is to be dropped:
/// the connection is closing, or the spawn already failed.
///
/// Port of erts/emulator/beam/dist.c:665 (erts_dist_pend_spawn_exit_parent_setup),
/// OTP-29.1.1.
pub(crate) fn pend_spawn_exit_parent_setup(origin: &crate::proc_create::ProcessMonitor) -> bool {
    let target = spawn_target(origin.view());
    let dist = target.dist.clone();
    let id = origin.view().reference();
    let Some(target_half) = dist.monitor_delete_other(origin) else {
        return false;
    };
    let mut target_half = Some(target_half);
    loop {
        // `mdp->u.target.other.ptr = NULL`
        if let Some(waiter) = target.swap_waiter(None) {
            waiter.cancel();
        }
        let found = dist.with_pend_spawn_exit(|tree: &mut crate::proc_create::MonitorTree| {
            let found = tree.remove(id);
            if found.is_none()
                && let Some(half) = target_half.take()
            {
                tree.insert(half);
            }
            found
        });
        match found {
            None => {
                // !dist->alive
                drop(target_half);
                return false;
            }
            Some(None) => return true,
            Some(Some(record)) => {
                // The child had responded: copy its pid, then store the original target end.
                let item = spawn_target(record.view()).target();
                drop(record);
                if item.as_atom().is_some() {
                    // The spawn failed; drop it.
                    drop(target_half);
                    return false;
                }
                // A result already stored means the peer sent more than one response.
                if is_pending(target.target()) {
                    target.set_item(item);
                }
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

/// Handle the pending-spawn monitors of exiting `parent`, in tree order: drop those without
/// link, send the link exit to every child whose pid is known, and suspend on `waiter` at the
/// first one still pending. Without a waiter (a synchronous exit that cannot suspend) a
/// pending one is dropped.
///
/// Port of erts/emulator/beam/erl_process.c:13647-13780 (proc_exit_handle_pend_spawn_monitors)
/// with dist.c:641 (erts_dist_pend_spawn_exit_delete) and dist.c:758-790
/// (erts_dist_pend_spawn_exit_parent_wait), OTP-29.1.1. The suspend is recorded under
/// `dist->mtx`, so a reply cannot slip between test and suspend. The monitor being waited
/// for stays first in the tree (erts: `wait_pend_spawn_monitor`).
pub(crate) fn pend_spawn_exit(
    runtime: &crate::process::Runtime,
    parent: Pid,
    reason: Term,
    waiter: Option<&arinsal_sched::ExitWaiter<Process>>,
    pend_spawn_monitors: &mut crate::proc_create::MonitorTree,
) -> PendSpawnExit {
    use crate::monitor_link::node_flag;
    let ids: Vec<u64> = pend_spawn_monitors.iter().map(|m| m.reference()).collect();
    for id in ids {
        let Some(view) = pend_spawn_monitors.get(id) else {
            continue;
        };
        let flags = view.flags();
        let target = spawn_target(view);
        let dist = target.dist.clone();
        if flags & node_flag::SPAWN_LINK == 0 {
            // Just cleanup.
            if let Some(omon) = pend_spawn_monitors.remove(id) {
                match dist_pend_spawn_exit_delete(&omon) {
                    Some(target) => crate::proc_create::ProcessMonitor::release_both(omon, target),
                    None => drop(omon),
                }
            }
            continue;
        }
        // erts_dist_pend_spawn_exit_parent_wait: > 0 the child pid is in the monitor, 0 the
        // connection is not alive, < 0 suspended.
        let code = dist.with_pend_spawn_exit(|tree: &mut crate::proc_create::MonitorTree| {
            if !is_pending(target.target()) {
                Ok(tree.remove(id))
            } else if let Some(waiter) = waiter {
                // `mdp->u.target.other.ptr = c_p` plus `erts_suspend`.
                if let Some(old) = target.swap_waiter(Some(waiter.clone())) {
                    old.cancel();
                }
                Err(())
            } else {
                // A synchronous exit cannot suspend: drop it.
                Ok(tree.remove(id))
            }
        });
        let (alive, target_half) = match code {
            Some(Err(())) => return PendSpawnExit::Wait,
            Some(Ok(target_half)) => (true, target_half),
            None => (false, None),
        };
        let Some(omon) = pend_spawn_monitors.remove(id) else {
            continue;
        };
        let item = spawn_target(omon.view()).target();
        // An atom: the spawn failed; `am_pending`: dropped without a result.
        if alive && let Some(child) = ctl_external_pid(item) {
            let reason = if flags & node_flag::SPAWN_ABANDONED != 0 {
                Term::atom(arinsal_term::atoms::ABANDONED)
            } else {
                reason
            };
            // erts_dsig_send_exit_tt when `dist->connection_id` is still the connection's.
            elink::send_exit(
                runtime,
                dist.nodename,
                dist.connection_id,
                parent,
                child,
                reason,
            );
        }
        match target_half {
            Some(target) => crate::proc_create::ProcessMonitor::release_both(omon, target),
            None => drop(omon),
        }
    }
    PendSpawnExit::Done
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

// Port of erts/emulator/beam/dist.c:2885 (erts_net_message, DOP_SPAWN_REQUEST), OTP-29.1.1.
fn handle_spawn_request(
    runtime: &'static crate::process::Runtime,
    handle: u64,
    parts: &[Term],
    mut edep: Box<crate::natives::external_dist::ErtsDistExternal>,
) -> Result<(), VmError> {
    use crate::natives::external_dist::{erts_decode_dist_ext, erts_decode_dist_ext_size};
    let (ref_term, from_term, gl, mfa, opts) = (parts[1], parts[2], parts[3], parts[4], parts[5]);
    if !ctl_is_ref(ref_term) || ctl_is_internal_ref(ref_term) {
        return Err(badarg());
    }
    let remote = ctl_external_pid(from_term).ok_or_else(badarg)?;
    if !ctl_is_pid(gl) {
        return Err(badarg());
    }
    let mfa = arinsal_term::raw::Tuple::try_from(mfa).map_err(|_| badarg())?;
    if mfa.arity() != 3 {
        return Err(badarg());
    }
    let (Some(module), Some(function), Some(arity)) = (
        mfa.get(0).and_then(Term::as_atom),
        mfa.get(1).and_then(Term::as_atom),
        mfa.get(2).and_then(Term::as_small),
    ) else {
        return Err(badarg());
    };
    let (Some(mod_name), Some(fun_name)) =
        (global_atoms().text(module), global_atoms().text(function))
    else {
        return Err(badarg());
    };
    // The argument list, the payload (erts decodes it on the child's heap in
    // erts_internal:dist_spawn_init from `so.edep`).
    let need = erts_decode_dist_ext_size(None, &mut edep, false);
    if need < 0 {
        return Err(badarg());
    }
    let mut hfrag = arinsal_term::message::NodeFragment::new_message_buffer(need as usize);
    let arguments = {
        let mut target = hfrag.fragment_mut();
        let mut factory =
            arinsal_term::HeapReservation::new(&mut target, need as usize).map_err(|_| badarg())?;
        let arguments =
            erts_decode_dist_ext(None, &mut factory, &mut edep, false).ok_or_else(badarg)?;
        to_owned(arguments).map_err(|_| badarg())?
    };
    drop(hfrag);
    let reference = to_owned(ref_term).map_err(|_| badarg())?;
    let from = to_owned(from_term).map_err(|_| badarg())?;
    let options = &to_owned(opts).map_err(|_| badarg())?;
    if Some(arity as u64) != list_owned_len(&arguments).map(|n| n as u64) {
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
        Some(remote_proxy(handle, remote)?)
    } else {
        None
    };
    let monitor_origin = spawn_child_monitor_origin(handle, monitor, from_term, ref_term);
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
            node: crate::node_tables::this_node().0.to_owned(),
            id: child.number(),
            serial: child.serial(),
            creation: crate::node_tables::this_node().1,
        };
        drop(tables);
        child_to_schedule = Some(child);
    }
    let flags = if matches!(result, OwnedTerm::Pid { .. }) {
        (i64::from(monitor) << 1) | i64::from(link)
    } else {
        0
    };
    // Port of erts/emulator/beam/dist.c:1875-1898 (erts_dsig_send_spawn_reply), OTP-29.1.1.
    let mut ctl = CtlHeap::new();
    let fields = [
        ctl.owned(&reference)?,
        ctl.owned(&from)?,
        Term::small(flags).ok_or_else(badarg)?,
        ctl.owned(&result)?,
    ];
    let reply = ctl.control(31, &fields)?;
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
    from: Term,
    reference: Term,
) -> Option<crate::proc_create::DistOrigin> {
    if !monitor {
        return None;
    }
    let watcher = ctl_external_pid(from)?;
    let (_node, _connection_id, dist) = elink::connection_of_handle(handle)?;
    Some(crate::proc_create::DistOrigin::new(
        watcher, reference, dist,
    ))
}

fn emit_control_message_on_handle(
    runtime: &crate::process::Runtime,
    handle: u64,
    control: Term,
    message: Option<Term>,
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
    control: Term,
    message: Option<Term>,
) -> Result<(), VmError> {
    let mut entry = dep.lock();
    let state = entry
        .dist
        .as_mut()
        .filter(|state| state.handle == handle)
        .ok_or_else(badarg)?;
    let kick = dsig_send_no_proc_locked(state, control, message)?;
    drop(entry);
    dist_cmd_kick(runtime, kick)
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
    let (remote_watcher, handle, exit_payload) = {
        let tables = node_tables::lock();
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
            state.flags & node_tables::DFLAG_EXIT_PAYLOAD != 0,
        )
    };
    let local = local_pid_term(deceased);
    let mut ctl = CtlHeap::new();
    let Ok(remote_watcher) = ctl.owned(&remote_watcher) else {
        return true;
    };
    let built = if exit_payload {
        ctl.control(24, &[local, remote_watcher])
            .map(|c| (c, Some(reason)))
    } else {
        ctl.control(3, &[local, remote_watcher, reason])
            .map(|c| (c, None))
    };
    if let Ok((control, payload)) = built {
        let _ = emit_control_message_on_handle(runtime, handle, control, payload);
    }
    true
}

/// The `is_external_pid` arm of `link_opt` for a pid of another node: `erts_dsig_prepare` with
/// the scheduler's distribution state, then `erts_dsig_send_link`.
// Port of erts/emulator/beam/bif.c (link_opt: is_external_pid) and dist.c
// (erts_dsig_send_link), OTP-29.1.1.
pub(crate) fn link_remote(
    process: &mut Process,
    ctx: &mut RunCtx<'_, crate::Process>,
    node: &str,
    target: Term,
    priority: bool,
) -> Result<Term, VmError> {
    elink::link_external(process, ctx, node, owned(target)?, priority)
}

/// The `is_external_pid` arm of `unlink_1` for a pid of another node.
// Port of erts/emulator/beam/bif.c (unlink_1: is_external_pid) and dist.c
// (erts_dsig_send_unlink), OTP-29.1.1.
pub(crate) fn unlink_remote(
    process: &mut Process,
    ctx: &mut RunCtx<'_, crate::Process>,
    node: &str,
    target: Term,
) -> Result<Term, VmError> {
    elink::unlink_external(process, ctx, node, owned(target)?)
}

/// The `is_external_pid || is_external_ref` arm of `send_exit_signal_bif` for an id of another
/// node: dropped when the node is not alive or not connected, else `erts_dsig_send_exit2`.
// Port of erts/emulator/beam/bif.c (send_exit_signal_bif: is_external_pid) and dist.c
// (erts_dsig_send_exit2), OTP-29.1.1.
pub(crate) fn exit2_remote(
    process: &mut Process,
    ctx: &mut RunCtx<'_, crate::Process>,
    node: &str,
    target: Term,
    reason: Term,
    prio: bool,
) -> Result<Term, VmError> {
    if let DsigPrepare::Connected { connection_id, .. } = dsig_prepare(process, ctx, node)? {
        let dflags = node_tables::find_dist_entry(node)
            .map_or(node_tables::DFLAG_PENDING_DFLAGS, |dep| dep.lock().dflags());
        let mut ctl = CtlHeap::new();
        if let Some((control, payload)) = dsig_send_exit2_ctl(
            &mut ctl,
            dflags,
            local_pid_term(ctx.pid()),
            target,
            reason,
            prio,
        )? {
            queue_outgoing_on(process, ctx, node, connection_id, control, payload)?;
        }
    }
    Ok(Term::atom(arinsal_term::atoms::TRUE))
}

/// The control message and payload of `erts_dsig_send_exit2`: `DOP_ALTACT_SIG_SEND` with
/// `ERTS_DOP_ALTACT_SIG_FLG_EXIT` for a priority or alias exit when the peer takes it, else
/// `DOP_PAYLOAD_EXIT2` / `DOP_EXIT2`; `None` drops an alias exit the peer cannot take.
// Port of erts/emulator/beam/dist.c (erts_dsig_send_exit2), OTP-29.1.1.
fn dsig_send_exit2_ctl(
    ctl: &mut CtlHeap,
    dflags: u64,
    local: Term,
    remote: Term,
    reason: Term,
    prio: bool,
) -> Result<Option<(Term, Option<Term>)>, VmError> {
    const ERTS_DOP_ALTACT_SIG_FLG_PRIO: i64 = 1 << 0;
    const ERTS_DOP_ALTACT_SIG_FLG_ALIAS: i64 = 1 << 2;
    const ERTS_DOP_ALTACT_SIG_FLG_EXIT: i64 = 1 << 4;
    let alias = ctl_is_ref(remote);
    if (prio || alias) && dflags & node_tables::DFLAG_ALTACT_SIG != 0 {
        let mut fs = ERTS_DOP_ALTACT_SIG_FLG_EXIT;
        if alias {
            fs |= ERTS_DOP_ALTACT_SIG_FLG_ALIAS;
        }
        if prio {
            fs |= ERTS_DOP_ALTACT_SIG_FLG_PRIO;
        }
        let flags = Term::small(fs).ok_or_else(badarg)?;
        return Ok(Some((
            ctl.control(37, &[flags, local, remote])?,
            Some(reason),
        )));
    }
    if alias {
        // Not supported by the receiver node; drop it.
        return Ok(None);
    }
    Ok(Some(if dflags & node_tables::DFLAG_EXIT_PAYLOAD != 0 {
        (ctl.control(26, &[local, remote])?, Some(reason))
    } else {
        (ctl.control(8, &[local, remote, reason])?, None)
    }))
}

/// The `remote_process` arm of `monitor/2,3` (bif.c `monitor`): an external pid or
/// `{Name, Node}` of another node.
// Port of erts/emulator/beam/bif.c (monitor: remote_process) and dist.c:1528
// (erts_dsig_send_monitor), OTP-29.1.1.
pub(crate) fn monitor_remote(
    process: &mut Process,
    ctx: &mut RunCtx<'_, crate::Process>,
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
    let id = arinsal_sched::unique::next_ref_id();
    let reference = if alias_mode.is_some() {
        crate::signals::pid_reference(process, id, ctx.pid())?
    } else {
        crate::signals::reference(process, id)?
    };
    // DOP_MONITOR_P ToProc is a pid or registered name atom (not {Name,Node}).
    let wire_target = match &target {
        OwnedTerm::Tuple(parts) if parts.len() == 2 && matches!(&parts[0], OwnedTerm::Atom(_)) => {
            parts[0].clone()
        }
        _ => target.clone(),
    };
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
        global_atoms()
            .intern(&node)
            .map(Term::atom)
            .map_err(|_| badarg())?
    } else {
        args[1]
    };
    let origin = emon::create_origin_or_down(
        runtime,
        process.heap.alloc_ix(),
        crate::natives::bif::prio_ml(
            crate::proc_create::monitor_reference(id, alias_mode, false),
            priority,
        ),
        ctx.pid(),
        info,
        crate::proc_create::DistTarget::new(remote, reference, dist),
    )?;
    process.monitors.insert(origin);
    process.cold_mut().dist_monitors.insert(id);
    // bif.c monitor `done:` (add_oflags & ERTS_ML_FLG_PRIO_ML).
    if priority {
        process.prio_item_added(crate::receive::PrioItemType::Monitor);
    }
    if let DsigPrepare::Connected { connection_id, .. } = prepared {
        let mut ctl = CtlHeap::new();
        let fields = [
            local_pid_term(ctx.pid()),
            ctl.owned(&wire_target)?,
            reference,
        ];
        let control = ctl.control(19, &fields)?;
        queue_outgoing_on(process, ctx, &node, connection_id, control, None)?;
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

/// An internal pid as a term; the dist encoder names it by `erts_this_node` (enc_pid).
pub(crate) fn local_pid_term(pid: Pid) -> Term {
    Term::pid_from_data(pid.data())
}

/// `ctx->ctl_heap` of an `erts_dsig_send_*`: the heap its control message is built on. It
/// lives until the signal is encoded.
// Port of erts/emulator/beam/dist.h (ErtsDSigSendContext.ctl_heap), OTP-29.1.1.
pub(crate) struct CtlHeap(arinsal_term::VecHeap);

impl CtlHeap {
    pub(crate) fn new() -> Self {
        Self(arinsal_term::VecHeap::with_initial_chunk_words(32))
    }

    /// Place a datum Arinsal keeps as an [`OwnedTerm`] (a monitor reference, a spawn tag, a
    /// seq_trace token, a stored exit reason) on the control heap.
    pub(crate) fn owned(&mut self, term: &OwnedTerm) -> Result<Term, VmError> {
        from_owned(term, &mut self.0).map_err(|_| badarg())
    }

    /// An external pid term.
    pub(crate) fn external_pid(
        &mut self,
        pid: crate::monitor_link::ExternalPid,
    ) -> Result<Term, VmError> {
        let owned = elink::external_pid_owned(pid).ok_or_else(badarg)?;
        self.owned(&owned)
    }

    /// The control tuple `{Op, Fields...}` (`TUPLEn(ctx->ctl_heap, make_small(DOP_*), ...)`).
    pub(crate) fn control(&mut self, op: i64, fields: &[Term]) -> Result<Term, VmError> {
        let mut tuple = Vec::with_capacity(fields.len() + 1);
        tuple.push(Term::small(op).ok_or_else(badarg)?);
        tuple.extend_from_slice(fields);
        TermBuilder::new(&mut self.0)
            .tuple(&tuple)
            .map_err(|_| badarg())
    }
}

/// The connection's `ctx->dflags` and the seq_trace part of `erts_dsig_send_msg`: with a token,
/// the sender's serial is bumped and the send is traced to `full_remote`; the token goes in the
/// control message when the peer can take it (`can_send_seqtrace_token`). A connection not yet
/// set up encodes with the pending entry's flags (`dep->dflags`, erts_dsig_prepare).
// Port of erts/emulator/beam/dist.c (erts_dsig_send_msg, seq_trace_update_serial,
// seq_trace_output SEQ_TRACE_SEND, can_send_seqtrace_token), OTP-29.1.1.
fn dsig_send_msg_token(
    process: &mut Process,
    ctx: &mut RunCtx<'_, crate::Process>,
    node: &str,
    full_remote: Term,
    message: Term,
) -> (u64, Option<OwnedTerm>) {
    // erts_dsig_prepare fails before any of this on a node that is not alive.
    if !node_tables::is_alive() {
        return (node_tables::DFLAG_PENDING_DFLAGS, None);
    }
    let dflags = node_tables::find_dist_entry(node)
        .map_or(node_tables::DFLAG_PENDING_DFLAGS, |dep| dep.lock().dflags());
    let sender = ctx.pid();
    let token = crate::seq_trace::on_send(process, Some(ctx), sender, full_remote, message)
        .filter(|token| token.can_send_to(dflags & node_tables::DFLAG_BIG_SEQTRACE_LABELS != 0))
        .map(|token| token.to_dist());
    (dflags, token)
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
    ctx: &mut RunCtx<'_, crate::Process>,
    target: Term,
    message: Term,
) -> Result<bool, VmError> {
    Ok(!matches!(
        try_remote_send_with_options(process, ctx, target, message, true, true, false, false)?,
        RemoteSendOutcome::NotRemote
    ))
}

#[derive(Debug)]
pub(crate) enum RemoteSendOutcome {
    NotRemote,
    Sent,
    NotConnected,
    WouldSuspend,
    /// `SEND_YIELD_CONTINUE`: the send traps to `dsend_continue_trap/1` with this context.
    Continue(DsigSendContext),
}

#[allow(clippy::too_many_arguments)]
fn queue_remote_send(
    process: &mut Process,
    ctx: &mut RunCtx<'_, crate::Process>,
    node: &str,
    control: Term,
    message: Option<Term>,
    connect: bool,
    suspend: bool,
    trap: bool,
) -> Result<RemoteSendOutcome, VmError> {
    if !node_tables::is_alive() {
        return Ok(RemoteSendOutcome::NotConnected);
    }
    Ok(
        match queue_outgoing_with_options(
            process, ctx, node, control, message, connect, suspend, trap, None,
        )? {
            DistSendResult::Queued => RemoteSendOutcome::Sent,
            DistSendResult::NotConnected => RemoteSendOutcome::NotConnected,
            DistSendResult::WouldSuspend => RemoteSendOutcome::WouldSuspend,
            DistSendResult::Continue(send_ctx) => RemoteSendOutcome::Continue(send_ctx),
        },
    )
}

// Port of erts/emulator/beam/bif.c:2381-2401 (`remote_send`), OTP-29.1.1.
#[allow(clippy::too_many_arguments)]
pub(crate) fn try_remote_send_with_options(
    process: &mut Process,
    ctx: &mut RunCtx<'_, crate::Process>,
    target: Term,
    message: Term,
    connect: bool,
    suspend: bool,
    trap: bool,
    prio: bool,
) -> Result<RemoteSendOutcome, VmError> {
    // {Name, Node}: a registered send on a (possibly remote) node; else a remote pid or alias.
    let (node, remote) = if let Some((name, node)) = name_node_tuple(target)? {
        (node, atom_term(&name)?)
    } else {
        match &owned(target)? {
            OwnedTerm::Ref { node, .. } | OwnedTerm::Pid { node, .. } => (node.clone(), target),
            _ => return Ok(RemoteSendOutcome::NotRemote),
        }
    };
    let local = node_tables::this_node().0.to_owned();
    if node == local || node == "nonode@nohost" {
        return Ok(RemoteSendOutcome::NotRemote);
    }
    let (dflags, token) = dsig_send_msg_token(process, ctx, &node, target, message);
    let mut ctl = CtlHeap::new();
    let token = token.map(|token| ctl.owned(&token)).transpose()?;
    let control = dsig_send_msg_ctl(
        &mut ctl,
        dflags,
        local_pid_term(ctx.pid()),
        remote,
        token,
        prio,
    )?;
    queue_remote_send(
        process,
        ctx,
        &node,
        control,
        Some(message),
        connect,
        suspend,
        trap,
    )
}

/// The control message of `erts_dsig_send_msg` for `remote` (an external pid or alias, or the
/// registered name of a `{Name, Node}` send): `DOP_ALTACT_SIG_SEND` for a priority or alias
/// message when the peer takes it, else `DOP_REG_SEND[_TT]`, `DOP_ALIAS_SEND[_TT]`,
/// `DOP_SEND_SENDER[_TT]` or `DOP_SEND[_TT]` with the empty cookie. `token` is set when it
/// goes in the control message (`can_send_seqtrace_token`).
// Port of erts/emulator/beam/dist.c (erts_dsig_send_msg), OTP-29.1.1.
fn dsig_send_msg_ctl(
    ctl: &mut CtlHeap,
    dflags: u64,
    sender: Term,
    remote: Term,
    token: Option<Term>,
    prio: bool,
) -> Result<Term, VmError> {
    const ERTS_DOP_ALTACT_SIG_FLG_PRIO: i64 = 1 << 0;
    const ERTS_DOP_ALTACT_SIG_FLG_TOKEN: i64 = 1 << 1;
    const ERTS_DOP_ALTACT_SIG_FLG_ALIAS: i64 = 1 << 2;
    const ERTS_DOP_ALTACT_SIG_FLG_NAME: i64 = 1 << 3;
    let alias = ctl_is_ref(remote);
    let name = remote.as_atom().is_some();
    let send_sender = dflags & node_tables::DFLAG_SEND_SENDER != 0;
    let (op, mut fields) = if (prio || alias) && dflags & node_tables::DFLAG_ALTACT_SIG != 0 {
        let mut fs = 0;
        if alias {
            fs |= ERTS_DOP_ALTACT_SIG_FLG_ALIAS;
        } else if name {
            fs |= ERTS_DOP_ALTACT_SIG_FLG_NAME;
        }
        if prio {
            fs |= ERTS_DOP_ALTACT_SIG_FLG_PRIO;
        }
        if token.is_some() {
            fs |= ERTS_DOP_ALTACT_SIG_FLG_TOKEN;
        }
        (
            37,
            vec![Term::small(fs).ok_or_else(badarg)?, sender, remote],
        )
    } else if name {
        (
            if token.is_some() { 16 } else { 6 },
            vec![sender, atom_term("")?, remote],
        )
    } else if alias {
        (if token.is_some() { 34 } else { 33 }, vec![sender, remote])
    } else if send_sender {
        (if token.is_some() { 23 } else { 22 }, vec![sender, remote])
    } else {
        (
            if token.is_some() { 12 } else { 2 },
            vec![atom_term("")?, remote],
        )
    };
    fields.extend(token);
    ctl.control(op, &fields)
}

/// An atom term (`am_*`) for a control message.
fn atom_term(name: &str) -> Result<Term, VmError> {
    global_atoms()
        .intern(name)
        .map(Term::atom)
        .map_err(|_| badarg())
}

/// The part of `ErtsDSigSendContext` that outlives the encode: the fragments not yet in the
/// distribution output queue, and the connection they belong to. It is the payload of the
/// magic binary a trapped send keeps in its `dsend_continue_trap/1` argument.
// Port of erts/emulator/beam/dist.h (ErtsDSigSendContext: dep, connection_id, obuf, fragments,
// no_suspend), OTP-29.1.1.
pub(crate) struct DsigSendContext {
    /// `ctx->dep`, kept referenced while the send is parked.
    dep: Arc<node_tables::DistEntry>,
    /// `ctx->connection_id`: the connection the signal was encoded for.
    connection_id: u32,
    /// The encode phases while the send is in `ERTS_DSIG_SEND_PHASE_MSG_SIZE` ..
    /// `ERTS_DSIG_SEND_PHASE_FIN`, `None` once it reached `ERTS_DSIG_SEND_PHASE_SEND`.
    encode: Option<Box<DsigEncode>>,
    /// `ctx->obuf[0..ctx->fragments]`: the encoded fragments still to be enqueued, in order.
    fragments: VecDeque<ErtsDistOutputBuf>,
    /// `ctx->no_suspend`.
    no_suspend: bool,
    /// `ctx->return_term`: a process-heap term, kept valid by disabling garbage collection
    /// while the send is parked.
    return_term: Term,
}

impl DsigSendContext {
    /// `ctx->return_term = ...` of `erts_dsend_export_trap_context`.
    pub(crate) fn set_return_term(&mut self, term: Term) {
        self.return_term = term;
    }

    /// `ctx->return_term`.
    pub(crate) fn return_term(&self) -> Term {
        self.return_term
    }
}

/// Finish the fragmented send a process left parked in `dsend_continue_trap/1` when it exits,
/// so that no incomplete fragmented signal stays queued at the receiver. The remaining
/// fragments are queued at once without suspending the exiting process.
// Port of erts/emulator/beam/erl_process.c:14525-14532, 14602-14633
// (erts_continue_exit_process, F_FRAGMENTED_SEND / ERTS_CONTINUE_EXIT_DIST_SEND), OTP-29.1.1.
pub(crate) fn dsend_exit(process: &mut Process, ctx: &mut DsigSendContext, sender: Pid) {
    ctx.no_suspend = true;
    // A send parked while encoding finishes the encode without trapping.
    if let Some(mut encode) = ctx.encode.take() {
        let mut reds = dsig_initial_reds(process);
        if let Ok(DsigEncodeResult::Send) = encode.step(None, &mut reds, true) {
            ctx.fragments = encode.take_obufs().into();
        }
    }
    // An error here is a vanished runtime; nothing is left to send to.
    let _ = dsig_send(process, ctx, sender, true);
}

/// `ctx->reds = ERTS_BIF_REDS_LEFT(c_p) * TERM_TO_BINARY_LOOP_FACTOR`.
fn dsig_initial_reds(process: &Process) -> i64 {
    i64::from(process.heap.abi.fcalls.max(0)) * DSIG_LOOP_FACTOR
}

/// `BUMP_REDS(c_p, (initial_reds - ctx->reds) / TERM_TO_BINARY_LOOP_FACTOR)`.
fn dsig_bump_reds(process: &mut Process, initial_reds: i64, reds: i64) {
    let bump = ((initial_reds - reds) / DSIG_LOOP_FACTOR).clamp(0, i64::from(i32::MAX)) as i32;
    process.heap.abi.fcalls = process.heap.abi.fcalls.saturating_sub(bump).max(0);
}

/// `ERTS_DSIG_SEND_TOO_LRG` → `SYSTEM_LIMIT` (bif.c remote_send, dsend_continue_trap_1).
fn dsig_system_limit() -> VmError {
    VmError::Trap(crate::exceptions::Trap::error(Term::atom(
        arinsal_term::atoms::SYSTEM_LIMIT,
    )))
}

impl std::fmt::Debug for DsigSendContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DsigSendContext")
            .field("fragments", &self.fragments.len())
            .finish()
    }
}

/// The result codes of `erts_dsig_send` that a sender acts on.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DsigSend {
    /// `ERTS_DSIG_SEND_OK`.
    Ok,
    /// `ERTS_DSIG_SEND_YIELD`: everything is queued and the sender was suspended on the busy
    /// distribution entry.
    Yield,
    /// `ERTS_DSIG_SEND_CONTINUE`: fragments are left in the context.
    Continue,
}

/// `ERTS_DSIG_SEND_PHASE_SEND`: verify that the connection still exists, enqueue as many
/// fragments as the reductions and the busy limit allow, suspend the sender when the queue
/// is busy, and tell the controller (dist command of a port, `dist_data` of a process).
// Port of erts/emulator/beam/dist.c:3594-3760 (erts_dsig_send, ERTS_DSIG_SEND_PHASE_SEND),
// OTP-29.1.1. `no_trap` is `ctx->no_trap`: every fragment is queued whatever the reductions.
fn dsig_send(
    process: &mut Process,
    ctx: &mut DsigSendContext,
    sender: Pid,
    no_trap: bool,
) -> Result<DsigSend, VmError> {
    let initial_reds = dsig_initial_reds(process);
    let mut reds = initial_reds;
    let dep = ctx.dep.clone();
    let mut entry = dep.lock();
    let connection_ok = entry.state != node_tables::ConnState::Exiting
        && entry.state != node_tables::ConnState::Idle
        && entry.connection_id == ctx.connection_id;
    let Some(state) = entry.dist.as_mut().filter(|_| connection_ok) else {
        // Not the same connection as when we started; drop message.
        ctx.fragments.clear();
        return Ok(DsigSend::Ok);
    };
    let kick = dsig_send_enqueue_locked(
        state,
        &mut ctx.fragments,
        &mut reds,
        no_trap,
        ctx.no_suspend,
    );
    let busy = state.busy && !ctx.no_suspend;
    let cid = match state.port_id {
        Some(port_id) => crate::natives::erts_debug::DistCid::Port(port_id),
        None => crate::natives::erts_debug::DistCid::Pid(state.owner),
    };
    let mut suspended = false;
    let mut resume = false;
    if busy {
        // The queue lock is released around erts_suspend, then the busy flag is read again.
        drop(entry);
        suspended = suspend_dist_sender(process, sender);
        if suspended {
            // erts_suspend + ERTS_BIF_PREP_YIELD on a busy distribution entry (dist.c
            // erts_dsig_send, ERTS_DSIG_SEND_YIELD): ERTS_VBUMP_ALL_REDS.
            crate::bif_traps::vbump_all_reds(process);
            let mut entry = dep.lock();
            match entry.dist.as_mut() {
                // Enqueue suspended process on dist entry (erts_proclist_store_last).
                Some(state) if state.busy => state.suspended_senders.push(sender),
                // was busy, but isn't now
                _ => resume = true,
            }
        }
    } else {
        drop(entry);
    }
    dsig_bump_reds(process, initial_reds, reds);
    dist_cmd_kick(process.runtime.ok_or_else(badarg)?, kick)?;
    if resume {
        // The caller still yields as if it suspended (erts_resume after the unlock).
        resume_dist_senders(process.runtime.ok_or_else(badarg)?, vec![sender]);
    }
    // monitor_busy_dist_port(ctx->c_p, cid), with fragments left (ERTS_DSIG_SEND_CONTINUE) or
    // after suspending (ERTS_DSIG_SEND_YIELD), unless the entry was no longer busy.
    if !resume && (suspended || !ctx.fragments.is_empty()) {
        crate::natives::erts_debug::monitor_busy_dist_port(process, sender, cid);
    }
    dist_cmd_kick(process.runtime.ok_or_else(badarg)?, kick)?;
    Ok(if !ctx.fragments.is_empty() {
        DsigSend::Continue
    } else if suspended {
        DsigSend::Yield
    } else {
        DsigSend::Ok
    })
}

/// What `ERTS_DSIG_SEND_PHASE_SEND` does once the entry is unlocked: schedule the dist
/// command of a port controller (`erts_schedule_dist_command`), or send `dist_data` to a
/// process controller that asked for it when its queue was empty (`notify_dist_data`).
#[derive(Clone, Copy, Debug)]
enum DistCmdKick {
    Port(u64),
    Notify(Pid),
    None,
}

/// The enqueue step of `ERTS_DSIG_SEND_PHASE_SEND` with the entry locked: the fragments that
/// fit the reductions and the busy limit go to the output queue (`update_qsizes`), the busy
/// flag is set at the limit.
// Port of erts/emulator/beam/dist.c:3612-3687 (erts_dsig_send, ERTS_DSIG_SEND_PHASE_SEND),
// OTP-29.1.1.
fn dsig_send_enqueue_locked(
    state: &mut node_tables::DistState,
    obufs: &mut VecDeque<ErtsDistOutputBuf>,
    reds: &mut i64,
    no_trap: bool,
    no_suspend: bool,
) -> DistCmdKick {
    let mut fragments = 0;
    let mut obsz = 0u64;
    while fragments < obufs.len()
        && ((*reds > 0 && state.pending_bytes + obsz < state.busy_limit) || no_trap || no_suspend)
    {
        if !no_trap && !no_suspend {
            *reds -= DSIG_FRAGMENT_REDS;
        }
        obsz += obufs[fragments].size() as u64;
        fragments += 1;
    }
    let empty_fill = state.pending_bytes == 0 && obsz > 0;
    state.pending_bytes += obsz;
    if state.pending_bytes >= state.busy_limit {
        state.busy = true;
    }
    state.output.extend(obufs.drain(..fragments));
    match state.port_id {
        Some(port_id) => {
            state.written = state.written.saturating_add(1);
            DistCmdKick::Port(port_id)
        }
        None if empty_fill && std::mem::take(&mut state.notify) => DistCmdKick::Notify(state.owner),
        None => DistCmdKick::None,
    }
}

/// Run the [`DistCmdKick`] of a send.
fn dist_cmd_kick(runtime: &crate::process::Runtime, kick: DistCmdKick) -> Result<(), VmError> {
    match kick {
        DistCmdKick::Port(port_id) => flush_port_output(runtime, port_id),
        DistCmdKick::Notify(pid) => notify_dist_data(runtime, pid),
        DistCmdKick::None => Ok(()),
    }
}

/// `notify_dist_data`: an empty `dist_data` message from the system to the controller.
// Port of erts/emulator/beam/dist.c (notify_dist_data), OTP-29.1.1.
fn notify_dist_data(runtime: &crate::process::Runtime, pid: Pid) -> Result<(), VmError> {
    runtime
        .scheduler()?
        .send(
            pid,
            pid,
            Message::copy_from(Term::atom(arinsal_term::atoms::DIST_DATA))?,
        )
        .map_err(|error| VmError::Unsupported(format!("dist data notification: {error}")))
}

/// `ctx->from` of `erts_dsig_prepare`: the sending process, or `am_undefined` without one. It
/// names the fragments of the signal (the sequence id of `DIST_FRAG_HEADER`).
// Port of erts/emulator/beam/dist.c (erts_dsig_prepare: `ctx->from = proc ?
// proc->common.id : am_undefined`), OTP-29.1.1.
pub(crate) fn dsig_from(sender: Option<Pid>) -> u64 {
    sender
        .and_then(Pid::to_term)
        .unwrap_or(Term::atom(arinsal_term::atoms::UNDEFINED))
        .word()
}

/// `erts_dsig_send` without a process (`ctx->c_p == NULL`: `no_trap` and `no_suspend`) on
/// a connected entry the caller holds locked: every phase runs to the end.
// Port of erts/emulator/beam/dist.c (erts_dsig_send, PHASE_INIT with `!ctx->c_p`),
// OTP-29.1.1.
fn dsig_send_no_proc_locked(
    state: &mut node_tables::DistState,
    control: Term,
    message: Option<Term>,
) -> Result<DistCmdKick, VmError> {
    let mut encode = DsigEncode::new(
        control,
        message,
        state.flags,
        dsig_from(None),
        arinsal_term::this_node,
    );
    let mut obufs: VecDeque<_> = node_tables::encode_no_trap(&mut encode, Some(&state.acmp))
        .map_err(|_| badarg())?
        .into();
    let mut reds = 0;
    Ok(dsig_send_enqueue_locked(
        state, &mut obufs, &mut reds, true, true,
    ))
}

/// `TERM_TO_BINARY_LOOP_FACTOR`: the loop units one reduction buys `erts_dsig_send`.
const DSIG_LOOP_FACTOR: i64 = 32;
/// The loop units `erts_dsig_send` charges per fragment it enqueues.
const DSIG_FRAGMENT_REDS: i64 = 10;

/// The outcome of `dsend_continue_trap/1`, mapped to what the trap does.
pub(crate) enum DsendContinue {
    /// `ERTS_DSIG_SEND_OK`: return the context's return term.
    Done,
    /// `ERTS_DSIG_SEND_YIELD`: `nosuspend` or `ERTS_BIF_YIELD_RETURN`.
    Yield { no_suspend: bool },
    /// `ERTS_DSIG_SEND_CONTINUE`: trap again.
    Continue,
    /// `ERTS_DSIG_SEND_TOO_LRG`: `system_limit`.
    TooLarge,
}

/// `dsend_continue_trap_1`: resume `erts_dsig_send` on the context of a parked send.
// Port of erts/emulator/beam/bif.c:2806-2840 (dsend_continue_trap_1), OTP-29.1.1.
pub(crate) fn dsend_continue(
    process: &mut Process,
    ctx: &mut DsigSendContext,
    sender: Pid,
) -> Result<DsendContinue, VmError> {
    // The encode phases first, on this slice's reductions (erts_dsig_send from ctx->phase).
    if let Some(encode) = ctx.encode.as_mut() {
        let initial_reds = dsig_initial_reds(process);
        let mut reds = initial_reds;
        let res = encode.step(None, &mut reds, false);
        dsig_bump_reds(process, initial_reds, reds);
        match res.map_err(|_| badarg())? {
            DsigEncodeResult::Continue => return Ok(DsendContinue::Continue),
            DsigEncodeResult::TooLarge => return Ok(DsendContinue::TooLarge),
            DsigEncodeResult::Send => {
                ctx.fragments = encode.take_obufs().into();
                ctx.encode = None;
            }
        }
    }
    Ok(match dsig_send(process, ctx, sender, false)? {
        DsigSend::Ok => DsendContinue::Done,
        DsigSend::Yield => DsendContinue::Yield {
            no_suspend: ctx.no_suspend,
        },
        DsigSend::Continue => DsendContinue::Continue,
    })
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
        if state.port_busy || state.flushing_output || state.output.is_empty() {
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
                    .is_some_and(|state| !state.port_busy && !state.output.is_empty())
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
            if state.port_busy || state.output.is_empty() {
                state.flushing_output = false;
                None
            } else {
                // erts_dist_command: erts_encode_ext_dist_header_finalize on the buffer it
                // is about to write.
                state.output.pop_front().map(|mut packet| {
                    let queued = packet.size();
                    // dist_cmd counts its reductions per packet, not erts_dist_command's.
                    let finalize = erts_encode_ext_dist_header_finalize(
                        &mut packet,
                        &mut state.outgoing_cache,
                        state.flags,
                        &mut 0,
                    );
                    (packet, queued, finalize, state.handle)
                })
            }
        };
        let Some((packet, queued, finalize, conn_handle)) = packet else {
            break;
        };
        if let DistHeaderFinalize::SpawnNotSupported(ctl) = finalize {
            transcode_spawn_notsup(runtime, conn_handle, &ctl);
        }
        let sock = {
            runtime
                .ports
                .get(port_id)
                .and_then(|handle| handle.tcp_driver_data())
        };
        // dist_port_commandv: the buffer's I/O vector, its binaries referenced.
        let (header, iov) = packet.into_iov();
        let mut eiov = arinsal_drv::CommandVector::new();
        if !header.is_empty() {
            eiov.push(arinsal_drv::CommandPiece::Bytes(header));
        }
        eiov.extend(iov.into_iter().map(|iov| {
            let (bin, offset, len) = iov.into_parts();
            arinsal_drv::CommandPiece::Refc(
                arinsal_drv::RefcSegment::new(bin, offset, len)
                    .expect("an I/O vector element lies inside its Binary"),
            )
        }));
        let port_busy = sock
            .and_then(|sock| crate::inet_drv::dist_outputv(&sock, eiov).ok())
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
            state.pending_bytes = state.pending_bytes.saturating_sub(queued as u64);
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

/// `get_suspended_on_de(dep, ERTS_DE_QFLGS_ALL)` of a connection going down: the processes
/// suspended on the busy entry, resumed once the entry is unlocked (`erts_do_net_exits`).
// Port of erts/emulator/beam/dist.c (get_suspended_on_de; erts_do_net_exits), OTP-29.1.1.
fn get_suspended_on_de(entry: &mut node_tables::NodeEntry) -> Vec<Pid> {
    entry
        .dist
        .as_mut()
        .map(|state| {
            state.busy = false;
            std::mem::take(&mut state.suspended_senders)
        })
        .unwrap_or_default()
}

/// `erts_resume_processes`: returns how many were resumed.
fn resume_dist_senders(runtime: &crate::process::Runtime, senders: Vec<Pid>) -> usize {
    let Ok(scheduler) = runtime.scheduler() else {
        return 0;
    };
    let mut resumed = 0;
    for sender in senders {
        if runtime.resume_internal(sender) {
            resumed += 1;
            let _ = scheduler.wake(sender);
        }
    }
    resumed
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
        (senders, !port_busy && !state.output.is_empty())
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

fn get_data_notification(
    ctx: &mut RunCtx<'_, crate::Process>,
    handle: Term,
) -> Result<Term, VmError> {
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
    ctx: &mut RunCtx<'_, crate::Process>,
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

fn get_opt(
    ctx: &mut RunCtx<'_, crate::Process>,
    handle: Term,
    option: Term,
) -> Result<Term, VmError> {
    if atom_name(option).as_deref() != Some("get_size") {
        return Err(badarg());
    }
    let value = with_dhandle(handle, ctx.pid(), true, |state| Ok(state.get_size))?;
    Ok(boolean(value))
}

fn set_opt(
    ctx: &mut RunCtx<'_, crate::Process>,
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
    ctx: &mut RunCtx<'_, crate::Process>,
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
    f: impl FnOnce(&mut DistState, &str, u32) -> Result<R, VmError>,
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
    f(state, &dep.sysname, conn_id)
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

/// `node/0`: `erts_this_node->sysname`.
// Port of erts/emulator/beam/dist.c (node_0), OTP-29.1.1.
pub(crate) extern "C" fn node_0(
    _c_p: *mut arinsal_beamasm::ProcessHeader,
    _reg: *mut u64,
    _i: u64,
) -> u64 {
    crate::native_hooks::raw(crate::natives::node::node_0_term())
}

/// `node/1`.
// Port of erts/emulator/beam/dist.c (node_1), OTP-29.1.1.
pub(crate) extern "C" fn node_1(
    c_p: *mut arinsal_beamasm::ProcessHeader,
    reg: *mut u64,
    i: u64,
) -> u64 {
    let [term] = crate::bif_table::bif_args::<1>(reg);
    let result = crate::natives::node::node(term);
    crate::natives::bif::bif_ret(c_p, i, result)
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
            .eval_scheduled("dist_missing_send_diff", "run", &[], 2)
            .unwrap();
        assert_eq!(expected, arinsal_difftest::CallResult::Ok(actual.term));
    }

    #[test]
    fn dist_state_starts_empty_with_connection_caches() {
        let state = DistState::new(11, Pid::new(1, 2), 0);
        assert!(state.output.is_empty());
        assert_eq!(state.pending_bytes, 0);
        assert_eq!(state.incoming_cache.get(0), None);
        assert_eq!(state.outgoing_cache.out(0), None);
    }

    fn heap_term(heap: &mut arinsal_term::VecHeap, term: &OwnedTerm) -> Term {
        from_owned(term, heap).unwrap()
    }

    /// Queue a signal as a send without a process does.
    fn queue(state: &mut DistState, control: Term, message: Option<Term>) {
        dsig_send_no_proc_locked(state, control, message).unwrap();
    }

    /// Take the next output buffer and finalize it as the output path does.
    fn pop_wire(state: &mut DistState) -> Vec<u8> {
        let mut packet = state.output.pop_front().unwrap();
        erts_encode_ext_dist_header_finalize(
            &mut packet,
            &mut state.outgoing_cache,
            state.flags,
            &mut 0,
        );
        packet.to_vec()
    }

    #[test]
    fn dist_output_encodes_distribution_header_and_send_control() {
        let mut state = DistState::new(11, Pid::new(1, 2), node_tables::DFLAG_DIST_DEFAULT);
        let mut heap = arinsal_term::VecHeap::new();
        let control_owned = OwnedTerm::tuple(vec![
            OwnedTerm::Int(2),
            OwnedTerm::Atom("from@host".into()),
            OwnedTerm::Atom("to@host".into()),
        ]);
        let control = heap_term(&mut heap, &control_owned);
        let message = heap_term(&mut heap, &OwnedTerm::Int(9));
        queue(&mut state, control, Some(message));
        let packet = pop_wire(&mut state);
        assert_eq!(&packet[..3], &[131, 68, 2]);
        let mut cache = arinsal_etf::AtomCache::new();
        let decoded = arinsal_etf::decode_dist_packet(&packet, &mut cache).unwrap();
        let terms = arinsal_etf::decode_dist_payload(&decoded).unwrap();
        assert_eq!(terms[0], control_owned);
        assert_eq!(terms[1], OwnedTerm::Int(9));
        // The second signal finds both atoms in the connection's cache: no atom text.
        queue(&mut state, control, Some(message));
        let again = pop_wire(&mut state);
        assert!(again.len() < packet.len());
        let decoded = arinsal_etf::decode_dist_packet(&again, &mut cache).unwrap();
        assert_eq!(
            arinsal_etf::decode_dist_payload(&decoded).unwrap()[0],
            control_owned
        );
    }

    #[test]
    fn dist_output_without_header_flags_is_pass_through() {
        let mut state = DistState::new(11, Pid::new(1, 2), 0);
        let mut heap = arinsal_term::VecHeap::new();
        let control = heap_term(
            &mut heap,
            &OwnedTerm::tuple(vec![OwnedTerm::Int(2), OwnedTerm::Atom("a".into())]),
        );
        let message = heap_term(&mut heap, &OwnedTerm::Int(9));
        queue(&mut state, control, Some(message));
        let packet = pop_wire(&mut state);
        assert_eq!(
            packet,
            vec![112, 131, 104, 2, 97, 2, 119, 1, b'a', 131, 97, 9]
        );
    }

    #[test]
    fn dist_pending_signal_is_finalized_with_the_connection_flags() {
        let mut heap = arinsal_term::VecHeap::new();
        let control = heap_term(
            &mut heap,
            &OwnedTerm::tuple(vec![OwnedTerm::Int(2), OwnedTerm::Atom("a".into())]),
        );
        let mut packet = node_tables::encode_pending(control, None, dsig_from(None)).unwrap();
        assert_eq!(
            erts_encode_ext_dist_header_finalize(
                &mut packet,
                &mut Default::default(),
                node_tables::DFLAG_DIST_DEFAULT,
                &mut 0
            ),
            DistHeaderFinalize::Done
        );
        assert_eq!(
            packet.to_vec(),
            vec![131, 68, 0, 104, 2, 97, 2, 119, 1, b'a']
        );
    }

    #[test]
    fn dist_queue_accounts_for_pending_bytes() {
        let mut state = DistState::new(12, Pid::new(1, 0), 0);
        let mut heap = arinsal_term::VecHeap::new();
        let control = heap_term(&mut heap, &OwnedTerm::tuple(vec![OwnedTerm::Int(2)]));
        queue(&mut state, control, None);
        assert_eq!(
            state.pending_bytes,
            state.output.front().unwrap().size() as u64
        );
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
