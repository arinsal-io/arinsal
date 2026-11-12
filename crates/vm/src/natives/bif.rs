//! The process BIFs of bif.c.
//!
//! Port of erts/emulator/beam/bif.c (monitor_2, monitor_3, monitor, demonitor_1, demonitor_2,
//! demonitor, self_0, group_leader_0, erts_internal_group_leader_2, process_flag_2,
//! ebif_bang_2, send_2, send_3, erl_send), OTP-29.1.1. Each BIF is `bif_table[].f`, called by
//! `call_light_bif_shared` / `call_bif_shared` with `(c_p, reg, I)`; GC after the BIF is the
//! fragment's. Only the arms that need it (a distributed monitor, a send that is not to an
//! internal pid of an untraced sender) reach the scheduler's data, as erts reaches `esdp`
//! through `erts_proc_sched_data(c_p)` only where a BIF needs it.

use crate::natives::erl_process::{
    CreateError, ErlSpawnOpts, ParseResult, erl_create_process, erts_parse_spawn_opts,
};
use crate::proc_create::{AliasMode, MonitorInfo, OriginMonitor};
use crate::process::Message;
use crate::signals::OriginDemonitor;
use crate::{Process, Vm, VmError};
use arinsal_beamasm::ProcessHeader;
use arinsal_sched::{Pid, RunCtx};
use arinsal_term::{Term, atoms};

/// The executor's scheduler data, when the executor calls the BIF by its MFA (an `apply` it
/// resolves, a traced call). Native code passes `None` and the distributed arm reaches the
/// data through the process.
type Sched<'a, 'c> = Option<(&'a mut Vm, &'a mut RunCtx<'c, Message>)>;

pub(crate) fn badarg() -> VmError {
    VmError::Trap(crate::exceptions::Trap::error(Term::atom(atoms::BADARG)))
}

/// `BIF_ERROR(c_p, BADARG | EXF_HAS_EXT_INFO)` with `c_p->fvalue = cause`.
fn badarg_cause(arity: usize, cause: arinsal_term::Atom) -> VmError {
    let mut trap = crate::exceptions::Trap::error(Term::atom(atoms::BADARG));
    trap.top = Some(crate::stacktrace::TopFrame::BifRegisters {
        module: atoms::ERLANG,
        function: atoms::MONITOR,
        arity,
        info: crate::stacktrace::BifErrorInfo::Cause(Term::atom(cause)),
    });
    VmError::Trap(trap)
}

/// `BIF_RET` / `BIF_ERROR` / `BIF_TRAP*` of a body below.
#[inline(always)]
pub(crate) fn bif_ret(c_p: *mut ProcessHeader, i: u64, result: Result<Term, VmError>) -> u64 {
    match result {
        Ok(value) => crate::native_hooks::raw(value),
        Err(error) => crate::native_helpers::bif_return_current(c_p, i, error),
    }
}

/// `monitor/2`.
// Port of erts/emulator/beam/bif.c (monitor_2), OTP-29.1.1.
pub(crate) extern "C" fn monitor_2(c_p: *mut ProcessHeader, _reg: *mut u64, i: u64) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let args = [process.x[0], process.x[1]];
    let result = monitor(process, None, &args);
    bif_ret(c_p, i, result)
}

/// `monitor/3`.
// Port of erts/emulator/beam/bif.c (monitor_3), OTP-29.1.1.
pub(crate) extern "C" fn monitor_3(c_p: *mut ProcessHeader, _reg: *mut u64, i: u64) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let args = [process.x[0], process.x[1], process.x[2]];
    let result = monitor(process, None, &args);
    bif_ret(c_p, i, result)
}

/// `demonitor/1`.
// Port of erts/emulator/beam/bif.c (demonitor_1), OTP-29.1.1.
pub(crate) extern "C" fn demonitor_1(c_p: *mut ProcessHeader, _reg: *mut u64, i: u64) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let args = [process.x[0]];
    let result = demonitor(process, &args);
    bif_ret(c_p, i, result)
}

/// `demonitor/2`.
// Port of erts/emulator/beam/bif.c (demonitor_2), OTP-29.1.1.
pub(crate) extern "C" fn demonitor_2(c_p: *mut ProcessHeader, _reg: *mut u64, i: u64) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let args = [process.x[0], process.x[1]];
    let result = demonitor(process, &args);
    bif_ret(c_p, i, result)
}

/// `monitor/2,3` called by the executor by MFA, with its scheduler data.
pub(crate) fn monitor_executor(
    vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    args: &[Term],
) -> Result<Term, VmError> {
    monitor(process, Some((vm, ctx)), args)
}

/// `demonitor/1,2` called by the executor by MFA.
pub(crate) fn demonitor_executor(
    _vm: &mut Vm,
    process: &mut Process,
    _ctx: &mut RunCtx<'_, Message>,
    args: &[Term],
) -> Result<Term, VmError> {
    demonitor(process, args)
}

/// `monitor(Type, Item [, Opts])`: `erts_monitor_opts` for `monitor/3`, then the type arms.
// Port of erts/emulator/beam/bif.c (monitor_3: erts_monitor_opts, am_badopt; monitor),
// OTP-29.1.1.
fn monitor(process: &mut Process, sched: Sched<'_, '_>, args: &[Term]) -> Result<Term, VmError> {
    let (tag, alias_mode, priority) = if args.len() == 3 {
        crate::signals::monitor_options(args).map_err(|_| badarg_cause(3, atoms::BADOPT))?
    } else {
        (Term::atom(atoms::DOWN), None, false)
    };
    let (kind, target) = (args[0], args[1]);
    let me = process.self_pid.ok_or_else(badarg)?;
    if kind == Term::atom(atoms::PROCESS) {
        // `is_internal_pid`, then `is_atom` (a local name).
        if let Some(pid) = Pid::from_term(target) {
            return monitor_process(
                process,
                me,
                Some(pid),
                None,
                target,
                (tag, alias_mode, priority),
            );
        }
        if let Some(name) = target.as_atom() {
            let runtime = process.runtime.ok_or_else(badarg)?;
            let pid = runtime.reg.whereis_proc(name);
            let name = arinsal_term::global_atoms().text(name).map(str::to_owned);
            return monitor_process(
                process,
                me,
                pid,
                name.as_deref(),
                target,
                (tag, alias_mode, priority),
            );
        }
        // `is_external_pid` or `{Name, Node}` of another node: the distribution.
        if let Some(node) = crate::dist::remote_node(target)? {
            return match sched {
                Some((_vm, ctx)) => crate::dist::monitor_remote(process, ctx, args, node),
                None => monitor_remote_native(process, args, node),
            };
        }
        // `{Name, Node}` of this node is a local name.
        if let Some((name, _node)) = crate::dist::name_node_tuple(target)? {
            let runtime = process.runtime.ok_or_else(badarg)?;
            let pid = runtime.reg.whereis_proc_str(&name);
            return monitor_process(
                process,
                me,
                pid,
                Some(&name),
                target,
                (tag, alias_mode, priority),
            );
        }
        // A pid of another incarnation of this node never matches a live process.
        if matches!(
            arinsal_term::to_owned(target),
            Ok(arinsal_etf::OwnedTerm::Pid { .. })
        ) {
            return monitor_process(process, me, None, None, target, (tag, alias_mode, priority));
        }
        return Err(badarg());
    }
    if kind == Term::atom(atoms::PORT) {
        return crate::signals::monitor_port(process, me, target, tag, alias_mode);
    }
    if kind == Term::atom(atoms::TIME_OFFSET) {
        // Port of erts/emulator/beam/erl_time_sup.c (erts_monitor_time_offset), OTP-29.1.1.
        // There is no clock warp source in this runtime; the monitor is a reference.
        if target != Term::atom(atoms::CLOCK_SERVICE) {
            return Err(badarg());
        }
        let id = process.next_ref();
        return crate::signals::reference(process, id);
    }
    Err(badarg_cause(args.len(), atoms::BADTYPE))
}

/// The `local_process` arm of `monitor`: one `erts_monitor_create` for both halves, the origin
/// into `ERTS_P_MONITORS(c_p)`, the target half sent by `erts_proc_sig_send_monitor`; a target
/// that does not exist gets the `noproc` DOWN.
// Port of erts/emulator/beam/bif.c (monitor: local_process) and erl_proc_sig_queue.c
// (erts_proc_sig_send_monitor), OTP-29.1.1.
fn monitor_process(
    process: &mut Process,
    me: Pid,
    pid: Option<Pid>,
    name: Option<&str>,
    target: Term,
    (tag, alias_mode, priority): (Term, Option<AliasMode>, bool),
) -> Result<Term, VmError> {
    let runtime = process.runtime.ok_or_else(badarg)?;
    let id = process.next_ref();
    let ref_term = if alias_mode.is_some() {
        crate::signals::pid_reference(process, id, me)?
    } else {
        crate::signals::reference(process, id)?
    };
    // No monitoring of self.
    if pid == Some(me) {
        return Ok(ref_term);
    }
    let info = if tag == Term::atom(atoms::DOWN) && name.is_none() {
        MonitorInfo::default()
    } else {
        crate::signals::monitor_info_for(tag, name)?
    };
    if priority {
        process.cold_mut().prio_monitors.insert(id);
    }
    let scheduler = runtime.scheduler()?;
    // erts_proc_sig_send_monitor: no lookup here. On a normal scheduler the monitor is held as
    // `esdp->pending_signal`; a target gone when it is published gets the `noproc` DOWN
    // (erl_proc_sig_queue.c, proc_queue_signal / erts_proc_sig_send_pending).
    if let Some(pid) = pid {
        let (origin, target_half) = crate::proc_create::create_monitor_with_reference_at(
            process.heap.alloc_ix(),
            crate::proc_create::monitor_reference(id, alias_mode, priority),
            me.data(),
            pid.data(),
            info,
            OriginMonitor::Process(crate::proc_create::OriginHalf),
        );
        process.monitors.insert(origin);
        // proc_queue_signal on a normal scheduler holds the monitor as the scheduler's
        // pending signal.
        let sent = scheduler.signal_ordered_from(
            me,
            pid,
            arinsal_sched::Signal::Monitor {
                reference: id,
                shared: target_half.into_shared(),
            },
            process.on_managed,
        );
        if let Err(error) = sent {
            process.monitors.remove(id);
            if error != arinsal_sched::Error::NoProcess {
                return Err(VmError::Unsupported(format!("monitor: {error}")));
            }
            crate::signals::send_noproc_down(
                process,
                me,
                id,
                name,
                Some(pid),
                target,
                tag,
                alias_mode,
            )?;
        }
    } else {
        crate::signals::send_noproc_down(process, me, id, name, pid, target, tag, alias_mode)?;
    }
    Ok(ref_term)
}

/// The `remote_process` arm called from native code: `erts_dsig_prepare` needs the
/// scheduler's distribution state, reached through the process.
// Port of erts/emulator/beam/bif.c (monitor: remote_process, erts_dsig_prepare with
// `c_p`), OTP-29.1.1.
#[cold]
#[inline(never)]
fn monitor_remote_native(
    process: &mut Process,
    args: &[Term],
    node: String,
) -> Result<Term, VmError> {
    // The call site a suspending BIF names (`c_p->i` at the call).
    if let Some((process, registers)) = crate::native_hooks::scheduler_registers(process) {
        process.native_call_pc = registers.tmp_mem[6] as usize;
    }
    let result = crate::process::sched_data::with_sched_data(process, |_vm, process, ctx| {
        crate::dist::monitor_remote(process, ctx, args, node)
    })
    .ok_or_else(|| VmError::Unsupported("monitor: no scheduler data".into()))?;
    process.native_call_pc = 0;
    result
}

/// `demonitor(Ref [, Opts])`: the option list walked in place, then `demonitor` by the type
/// of the origin found in `ERTS_P_MONITORS(c_p)`; a flush of a monitor already gone traps to
/// `erts_internal:flush_monitor_messages/3`.
// Port of erts/emulator/beam/bif.c (demonitor, demonitor_1, demonitor_2), OTP-29.1.1.
fn demonitor(process: &mut Process, args: &[Term]) -> Result<Term, VmError> {
    let reference = args[0];
    let (flush, info) = match args.get(1) {
        Some(options) => crate::signals::demonitor_flags(*options).ok_or_else(badarg)?,
        None => (false, false),
    };
    let id = crate::signals::ref_id(reference).ok_or_else(badarg)?;
    let me = process.self_pid.ok_or_else(badarg)?;
    // `am_true` / `am_false` of erts `demonitor`: whether a monitor was removed.
    let was_active = match crate::signals::demonitor_origin(process, id) {
        OriginDemonitor::Alias | OriginDemonitor::Missing => false,
        // ERTS_MON_TYPE_PROC: the origin half itself is the demonitor signal
        // (erts_proc_sig_send_demonitor).
        OriginDemonitor::Process(origin) => {
            let target = Pid::from_data(origin.view().other());
            let scheduler = process.runtime.ok_or_else(badarg)?.scheduler()?;
            let _ = scheduler.signal_ordered_from(
                me,
                target,
                arinsal_sched::Signal::DemonitorOrigin(origin.into_shared()),
                process.on_managed,
            );
            true
        }
        // ERTS_MON_TYPE_PORT: `erts_port_demonitor`; ERTS_MON_TYPE_DIST_PORT: released.
        OriginDemonitor::Port(port_id, origin) => {
            if let (Some(port_id), Some(origin)) = (port_id, origin) {
                crate::port::demonitor_port(process, me, port_id, origin);
            }
            true
        }
        // ERTS_MON_TYPE_DIST_PROC: erts_dsig_send_demonitor.
        OriginDemonitor::Distributed(origin) => {
            if let Some(cold) = process.cold.as_mut() {
                cold.dist_monitors.remove(&id);
            }
            crate::dist::demonitor_remote(process.runtime, me, origin);
            true
        }
    };
    // demonitor_1 returns `true` either way; demonitor_2 `false` for `am_false` with `info`.
    let result = Term::atom(if info && !was_active {
        atoms::FALSE
    } else {
        atoms::TRUE
    });
    if flush && !was_active {
        return Err(crate::signals::flush_monitor_trap(
            process, reference, result,
        ));
    }
    Ok(result)
}

/// `BIF_ERROR(c_p, BADARG | EXF_HAS_EXT_INFO)` with `c_p->fvalue = cause`, for `module:function`.
pub(crate) fn badarg_ext(
    module: arinsal_term::Atom,
    function: &str,
    arity: usize,
    cause: Term,
) -> VmError {
    let mut trap = crate::exceptions::Trap::error(Term::atom(atoms::BADARG));
    let function = crate::atom_cache::put(function)
        .as_atom()
        .expect("BIF name is an atom");
    trap.top = Some(crate::stacktrace::TopFrame::BifRegisters {
        module,
        function,
        arity,
        info: crate::stacktrace::BifErrorInfo::Cause(cause),
    });
    VmError::Trap(trap)
}

/// `self/0`: `c_p->common.id`, already the tagged pid on the header.
// Port of erts/emulator/beam/bif.c (self_0), OTP-29.1.1.
pub(crate) extern "C" fn self_0(c_p: *mut ProcessHeader, _reg: *mut u64, _i: u64) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.abi.self_pid
}

/// `group_leader/0`: `BIF_RET(BIF_P->group_leader)`.
// Port of erts/emulator/beam/bif.c (group_leader_0), OTP-29.1.1.
pub(crate) extern "C" fn group_leader_0(c_p: *mut ProcessHeader, _reg: *mut u64, i: u64) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    let result = process
        .self_pid
        .and_then(|me| process.group_leader_pid(me).to_term())
        .ok_or_else(badarg);
    bif_ret(c_p, i, result)
}

/// `erts_internal:group_leader/2`: sets the group leader of the caller itself, or of another
/// process whose main lock it would have to take; that one is reported busy (`false`) and the
/// Erlang wrapper `erlang:group_leader/2` sends the `group_leader/3` signal instead.
// Port of erts/emulator/beam/bif.c (erts_internal_group_leader_2), OTP-29.1.1.
pub(crate) extern "C" fn erts_internal_group_leader_2(
    c_p: *mut ProcessHeader,
    _reg: *mut u64,
    i: u64,
) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let (leader, target) = (process.x[0], process.x[1]);
    let result = group_leader_2(process, leader, target);
    bif_ret(c_p, i, result)
}

fn group_leader_2(process: &mut Process, leader: Term, target: Term) -> Result<Term, VmError> {
    let (Some(leader), Some(pid)) = (Pid::from_term(leader), Pid::from_term(target)) else {
        return Ok(Term::atom(atoms::BADARG));
    };
    if Some(pid) == process.self_pid {
        crate::natives::proc::set_group_leader(process, leader)?;
        return Ok(Term::atom(atoms::TRUE));
    }
    // erts_try_lock_sig_free_proc: a process that does not exist is `badarg`; any other is
    // treated as ERTS_PROC_LOCK_BUSY.
    if !crate::natives::proc::live(process, pid)? {
        return Ok(Term::atom(atoms::BADARG));
    }
    Ok(Term::atom(atoms::FALSE))
}

/// `process_flag/2`.
// Port of erts/emulator/beam/bif.c (process_flag_2), OTP-29.1.1.
pub(crate) extern "C" fn process_flag_2(c_p: *mut ProcessHeader, _reg: *mut u64, i: u64) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let (flag, value) = (process.x[0], process.x[1]);
    let result = process_flag(process, flag, value);
    bif_ret(c_p, i, result)
}

/// The arms of `process_flag_2`, then `process_flag_aux` (`save_calls`). The scheduling arms
/// change the process struct the scheduler reads (its user priority, run queue binding and
/// signal buffers) through the process itself, as erts changes them on `BIF_P`.
// Port of erts/emulator/beam/bif.c (process_flag_2, process_flag_aux), OTP-29.1.1.
fn process_flag(process: &mut Process, flag: Term, value: Term) -> Result<Term, VmError> {
    if flag == Term::atom(atoms::MONITOR_NODES) {
        return monitor_nodes(process, value, None);
    }
    // SAFETY: `flag` is a live term of the caller's heap (BIF_ARG_1).
    if let Some(tuple) = unsafe { flag.tuple_ref() }
        && tuple.len() == 2
        && tuple.get(0) == Some(Term::atom(atoms::MONITOR_NODES))
    {
        let options = tuple.get(1).expect("2-tuple");
        return monitor_nodes(process, value, Some(options));
    }
    let name = flag
        .as_atom()
        .and_then(|atom| arinsal_term::global_atoms().text(atom).map(str::to_owned));
    let erlang = atoms::ERLANG;
    match name.as_deref() {
        Some("scheduler") => {
            let scheduler_count = process
                .runtime
                .ok_or_else(badarg)?
                .scheduler()?
                .scheduler_count();
            let sched = value
                .as_small()
                .filter(|&sched| sched >= 0 && sched as usize <= scheduler_count)
                .ok_or_else(badarg)? as usize;
            let (old, moves) = process
                .signal_probe()
                .map_or((0, false), |probe| probe.bind_scheduler(sched));
            let old_value = Term::small(old as i64).ok_or_else(badarg)?;
            if moves {
                // ERTS_BIF_YIELD_RETURN_X(BIF_P, old_value, am_scheduler).
                crate::bif_traps::vbump_all_reds(process);
                return Err(VmError::TrapExport(crate::ExportTrap::new(
                    process,
                    crate::natives::sys::BIF_RETURN_TRAP,
                    vec![old_value, flag],
                )));
            }
            Ok(old_value)
        }
        Some("max_heap_size") => crate::natives::proc::max_heap_flag(process, value),
        Some("message_queue_data") => {
            // erts_change_message_queue_management.
            let off_heap = if value == Term::atom(atoms::OFF_HEAP) {
                true
            } else if value == Term::atom(atoms::ON_HEAP) {
                false
            } else {
                return Err(badarg());
            };
            let previous = process.cold.as_ref().is_some_and(|cold| cold.off_heap_msgq);
            process.cold_mut().off_heap_msgq = off_heap;
            if let Some(probe) = process.signal_probe() {
                probe.set_parallel_signal_buffers(off_heap);
            }
            Ok(Term::atom(if previous {
                atoms::OFF_HEAP
            } else {
                atoms::ON_HEAP
            }))
        }
        Some("priority") => {
            // erts_set_process_priority.
            let old = crate::natives::proc::flag(process, "priority", value)?;
            let priority = arinsal_term::global_atoms()
                .text(value.as_atom().ok_or_else(badarg)?)
                .and_then(crate::natives::proc::scheduler_priority)
                .ok_or_else(badarg)?;
            if let Some(probe) = process.signal_probe() {
                probe.set_user_priority(priority);
            }
            Ok(old)
        }
        Some("sensitive") => {
            let old = crate::natives::proc::flag(process, "sensitive", value)?;
            // BIF_RET2(old_value, CONTEXT_REDS): rescheduled at once so the setting takes
            // effect.
            process.heap.abi.fcalls = (process.heap.abi.fcalls - CONTEXT_REDS).max(0);
            Ok(old)
        }
        Some(
            name @ ("async_dist" | "error_handler" | "trap_exit" | "fullsweep_after"
            | "min_heap_size" | "min_bin_vheap_size"),
        ) => crate::natives::proc::flag(process, name, value),
        // process_flag_aux: `c_p->fvalue = am_none` for save_calls.
        Some("save_calls") => crate::natives::proc::save_calls_flag(process, value)
            .map_err(|_| badarg_ext(erlang, "process_flag", 2, Term::atom(atoms::NONE))),
        // process_flag_aux: `c_p->fvalue = am_badopt`.
        _ => Err(badarg_ext(
            erlang,
            "process_flag",
            2,
            Term::atom(atoms::BADOPT),
        )),
    }
}

/// `CONTEXT_REDS`.
const CONTEXT_REDS: i32 = 4000;

/// `erts_monitor_nodes(c_p, on, options)`: the previous count of node monitors of the caller.
// Port of erts/emulator/beam/dist.c (erts_monitor_nodes), OTP-29.1.1.
fn monitor_nodes(
    process: &mut Process,
    value: Term,
    options: Option<Term>,
) -> Result<Term, VmError> {
    let enabled = if value == Term::atom(atoms::TRUE) {
        true
    } else if value == Term::atom(atoms::FALSE) {
        false
    } else {
        return Err(badarg());
    };
    let options = match options {
        None => crate::node_tables::NodeMonitorOptions::default(),
        Some(options) => {
            let options = arinsal_term::to_owned(options).map_err(|_| badarg())?;
            crate::node_tables::parse_nodes_monitor_options(&options).map_err(|_| badarg())?
        }
    };
    let me = process.self_pid.ok_or_else(badarg)?;
    let mut nodes = crate::node_tables::lock();
    let previous = nodes.monitor_nodes(me, options, enabled);
    if enabled
        && let Some(runtime) = process.runtime.as_ref()
        && !runtime.publish_proc_flag(me, arinsal_sched::proc_flags::NODE_MON)
    {
        nodes.monitor_nodes(me, options, false);
    }
    drop(nodes);
    let count = process.cold.as_ref().map_or(0, |cold| cold.monitor_nodes);
    process.cold_mut().monitor_nodes = if enabled {
        count.saturating_add(1)
    } else {
        count.saturating_sub(1)
    };
    Term::small(previous as i64).ok_or_else(badarg)
}

/// `erlang:'!'/2` (`ebif_bang_2`): `erl_send`.
// Port of erts/emulator/beam/bif.c (ebif_bang_2), OTP-29.1.1.
pub(crate) extern "C" fn ebif_bang_2(c_p: *mut ProcessHeader, _reg: *mut u64, i: u64) -> u64 {
    erl_send(c_p, i)
}

/// `send/2`: `erl_send`. The `send` instruction calls it through the `send/2` export
/// (`emit_send`).
// Port of erts/emulator/beam/bif.c (send_2) and jit/arm/instr_bif.cpp (emit_send), OTP-29.1.1.
pub(crate) extern "C" fn send_2(c_p: *mut ProcessHeader, _reg: *mut u64, i: u64) -> u64 {
    erl_send(c_p, i)
}

/// `erl_send(c_p, BIF_ARG_1, BIF_ARG_2)`: `do_send`, then `ERTS_VBUMP_REDS(p, 4)` and the
/// message as the value, or `ERTS_BIF_PREP_YIELD_RETURN` when that used up the slice.
// Port of erts/emulator/beam/bif.c (erl_send), OTP-29.1.1.
#[inline(always)]
fn erl_send(c_p: *mut ProcessHeader, i: u64) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let (to, msg) = (process.x[0], process.x[1]);
    let result = match do_send(process, to, msg, SendOptions::default()) {
        Ok(Sent::Done) => send_return(process, msg),
        Ok(Sent::NoConnect) => Ok(msg),
        // The sender is suspended on the busy port; the send is redone through the send/2
        // export once it is resumed.
        Ok(Sent::Yield) => Err(send_yield(process, "erlang:send/2", vec![to, msg])),
        Ok(Sent::YieldReturn) => send_yield_return(process, msg),
        Err(error) => Err(error),
    };
    bif_ret(c_p, i, result)
}

/// `result >= 0`: `ERTS_VBUMP_REDS(p, 4)`, then the value, or `ERTS_BIF_PREP_YIELD_RETURN`
/// (`bif_return_trap/2`) when the send used up the slice (`ERTS_IS_PROC_OUT_OF_REDS`).
// Port of erts/emulator/beam/bif.c (erl_send, send_3: yield_return) and bif.h
// (ERTS_VBUMP_REDS, ERTS_IS_PROC_OUT_OF_REDS), OTP-29.1.1.
#[inline(always)]
fn send_return(process: &mut Process, value: Term) -> Result<Term, VmError> {
    crate::native_helpers::vbump_reds(process, 4);
    if process.heap.abi.fcalls > 0 {
        return Ok(value);
    }
    send_yield_return(process, value)
}

/// `ERTS_BIF_PREP_YIELD_RETURN(retval, p, value)`: `ERTS_VBUMP_ALL_REDS`, then the value
/// through `bif_return_trap/2`.
// Port of erts/emulator/beam/bif.h (ERTS_BIF_PREP_YIELD_RETURN_X), OTP-29.1.1.
#[cold]
#[inline(never)]
fn send_yield_return(process: &mut Process, value: Term) -> Result<Term, VmError> {
    crate::bif_traps::vbump_all_reds(process);
    Err(VmError::TrapExport(crate::ExportTrap::new(
        process,
        crate::natives::sys::BIF_RETURN_TRAP,
        vec![value, Term::atom(atoms::UNDEFINED)],
    )))
}

/// `do_send`: every local destination (internal pid, alias, registered name, `{Name, node()}`,
/// port) is sent from `c_p`; only `remote_send` reaches the scheduler's distribution state.
/// A sender with trace hooks (`trace_send`, seq trace, `save_calls`) evaluates them with the
/// scheduler's data, which Arinsal's trace evaluation needs.
// Port of erts/emulator/beam/bif.c (do_send, remote_send), OTP-29.1.1.
#[inline(always)]
fn do_send(process: &mut Process, to: Term, msg: Term, opts: SendOptions) -> Result<Sent, VmError> {
    if !crate::trace::send_hooks_idle(process) {
        return do_send_hooked(process, to, msg, opts);
    }
    // is_internal_pid(to): erts_proc_lookup_raw, then erts_send_message.
    if !opts.priority
        && let Some(pid) = Pid::from_term(to)
    {
        return match process.send_to_pid_idle(pid, msg) {
            Ok(_) => Ok(Sent::Done),
            Err(_) => Err(badarg()),
        };
    }
    if crate::dist::is_remote_target(to)? {
        return remote_send(process, to, msg, opts);
    }
    do_send_local(process, to, msg, opts)
}

/// The local arms of `do_send` other than an internal pid without `priority`: an alias, a
/// registered name, `{Name, node()}`, a port (`port_common`, with `nosuspend`).
// Port of erts/emulator/beam/bif.c (do_send: is_internal_ref, is_atom, is_internal_port,
// is_tuple with `dep == erts_this_dist_entry`, port_common), OTP-29.1.1.
fn do_send_local(
    process: &mut Process,
    to: Term,
    msg: Term,
    opts: SendOptions,
) -> Result<Sent, VmError> {
    let sent = process.send_message_prio(None, None, to, msg, opts.priority, !opts.nosuspend)?;
    Ok(Sent::from_port(sent))
}

/// `do_send` of a sender with trace hooks: `trace_send`, the seq trace token and
/// `save_calls(p, &exp_send)`, evaluated with the scheduler's data.
// Port of erts/emulator/beam/bif.c (do_send: trace_send, save_calls), OTP-29.1.1.
#[cold]
#[inline(never)]
fn do_send_hooked(
    process: &mut Process,
    to: Term,
    msg: Term,
    opts: SendOptions,
) -> Result<Sent, VmError> {
    if crate::trace::saves_calls(process) {
        crate::trace::save_call(process, crate::trace::SavedCall::Send);
    }
    if crate::dist::is_remote_target(to)? {
        return remote_send(process, to, msg, opts);
    }
    with_sched(process, |vm, process, ctx| {
        let sent = process.send_message_prio(
            Some(vm),
            Some(ctx),
            to,
            msg,
            opts.priority,
            !opts.nosuspend,
        )?;
        Ok(Sent::from_port(sent))
    })?
}

/// `remote_send`: the distribution entry is the scheduler's (`erts_dsig_prepare` with
/// `esdp`). `SEND_NOCONNECT` and a `nosuspend` busy entry come back as errors `send_3` maps.
// Port of erts/emulator/beam/bif.c (remote_send), OTP-29.1.1.
#[cold]
#[inline(never)]
fn remote_send(
    process: &mut Process,
    to: Term,
    msg: Term,
    opts: SendOptions,
) -> Result<Sent, VmError> {
    use crate::dist::RemoteSendOutcome;
    with_sched(
        process,
        |vm, process, ctx| match crate::dist::try_remote_send_with_options(
            process,
            ctx,
            to,
            msg,
            !opts.noconnect,
            !opts.nosuspend,
        )? {
            RemoteSendOutcome::Sent => {
                crate::trace::emit_process(
                    Some(vm),
                    process,
                    ctx.pid(),
                    crate::trace::SEND,
                    "send",
                    &[msg, to],
                );
                Ok(Sent::Done)
            }
            RemoteSendOutcome::NotConnected => Ok(Sent::NoConnect),
            RemoteSendOutcome::WouldSuspend => Ok(Sent::Yield),
            RemoteSendOutcome::NotRemote => Err(badarg()),
        },
    )?
}

/// The non-error results of `do_send` (its `Sint` result codes).
#[derive(Clone, Copy)]
enum Sent {
    /// `result >= 0`.
    Done,
    /// `SEND_NOCONNECT`: dropped, the node is not connected.
    NoConnect,
    /// `SEND_YIELD`: nothing was sent; with `suspend` on the sender is suspended on the busy
    /// port (`erts_suspend`).
    Yield,
    /// `SEND_YIELD_RETURN`: sent, and the sender is suspended on the busy port.
    YieldReturn,
}

impl Sent {
    /// `port_common`'s mapping of the `erts_port_command` result (`ERTS_PORT_OP_*`).
    // Port of erts/emulator/beam/bif.c (do_send: port_common), OTP-29.1.1.
    #[inline(always)]
    fn from_port(sent: crate::port::PortSend) -> Self {
        match sent {
            crate::port::PortSend::Sent => Self::Done,
            crate::port::PortSend::SentSuspended => Self::YieldReturn,
            crate::port::PortSend::Busy => Self::Yield,
        }
    }
}

/// `send/3`: the option list, then `do_send` with its `connect`/`suspend`/`prio` flags.
// Port of erts/emulator/beam/bif.c (send_3), OTP-29.1.1.
pub(crate) extern "C" fn send_3(c_p: *mut ProcessHeader, _reg: *mut u64, i: u64) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let (to, msg, list) = (process.x[0], process.x[1], process.x[2]);
    let Some(opts) = send_options(list) else {
        // `BIF_P->fvalue = am_badopt; BADARG | EXF_HAS_EXT_INFO`.
        let error = badarg_ext(atoms::ERLANG, "send", 3, Term::atom(atoms::BADOPT));
        return bif_ret(c_p, i, Err(error));
    };
    let ok = Term::atom(atoms::OK);
    let result = match do_send(process, to, msg, opts) {
        Ok(Sent::Done) => send_return(process, ok),
        Ok(Sent::NoConnect) => Ok(Term::atom(if opts.noconnect {
            atoms::NOCONNECT
        } else {
            atoms::OK
        })),
        Ok(Sent::Yield) if opts.nosuspend => Ok(Term::atom(atoms::NOSUSPEND)),
        Ok(Sent::Yield) => Err(send_yield(process, "erlang:send/3", vec![to, msg, list])),
        Ok(Sent::YieldReturn) if opts.nosuspend => Ok(Term::atom(atoms::NOSUSPEND)),
        Ok(Sent::YieldReturn) => send_yield_return(process, ok),
        Err(error) => Err(error),
    };
    bif_ret(c_p, i, result)
}

/// `ERTS_BIF_PREP_YIELD2(retval, BIF_TRAP_EXPORT(BIF_send_2), p, to, msg)` (`YIELD3` with the
/// options for `send/3`): `ERTS_VBUMP_ALL_REDS`, then a trap to the BIF's own export, which
/// the process runs again once the busy port resumes it.
// Port of erts/emulator/beam/bif.c (erl_send, send_3: SEND_YIELD) and bif.h
// (ERTS_BIF_PREP_YIELD2, ERTS_BIF_PREP_YIELD3), OTP-29.1.1.
#[cold]
#[inline(never)]
fn send_yield(process: &mut Process, export: &'static str, args: Vec<Term>) -> VmError {
    crate::bif_traps::vbump_all_reds(process);
    VmError::TrapExport(crate::ExportTrap::new(process, export, args))
}

/// The options `send_3` reads.
#[derive(Clone, Copy, Default)]
struct SendOptions {
    noconnect: bool,
    nosuspend: bool,
    priority: bool,
}

/// `send_3`'s option loop: a proper list of `noconnect`, `nosuspend` and `priority`.
// Port of erts/emulator/beam/bif.c (send_3: the option loop), OTP-29.1.1.
fn send_options(list: Term) -> Option<SendOptions> {
    let mut options = SendOptions::default();
    let mut bad = false;
    crate::signals::each_list_item(list, |option| match option.as_atom() {
        Some(atom) if atom == atoms::NOCONNECT => options.noconnect = true,
        Some(atom) if atom == atoms::NOSUSPEND => options.nosuspend = true,
        Some(atom) if atom == atoms::PRIORITY => options.priority = true,
        _ => bad = true,
    })?;
    (!bad).then_some(options)
}

/// `erts_proc_sched_data(c_p)` for a BIF arm that needs it. The call site a suspending BIF
/// names (`c_p->i` at the call) is recorded first.
// Port of erts/emulator/beam/erl_process.h (erts_proc_sched_data), OTP-29.1.1.
pub(crate) fn with_sched<R>(
    process: &mut Process,
    f: impl FnOnce(&mut Vm, &mut Process, &mut RunCtx<'_, Message>) -> R,
) -> Result<R, VmError> {
    if let Some((process, registers)) = crate::native_hooks::scheduler_registers(process) {
        process.native_call_pc = registers.tmp_mem[6] as usize;
    }
    let result = crate::process::sched_data::with_sched_data(process, f)
        .ok_or_else(|| VmError::Unsupported("BIF: no scheduler data".into()));
    process.native_call_pc = 0;
    result
}

/// `link/1`.
// Port of erts/emulator/beam/bif.c (link_1), OTP-29.1.1.
pub(crate) extern "C" fn link_1(c_p: *mut ProcessHeader, _reg: *mut u64, i: u64) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    let other = process.x[0];
    let result = link_opt(process, other, Term::NIL, 1);
    bif_ret(c_p, i, result)
}

/// `link/2`.
// Port of erts/emulator/beam/bif.c (link_2), OTP-29.1.1.
pub(crate) extern "C" fn link_2(c_p: *mut ProcessHeader, _reg: *mut u64, i: u64) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    let (other, opts) = (process.x[0], process.x[1]);
    let result = link_opt(process, other, opts, 2);
    bif_ret(c_p, i, result)
}

/// `erts_link_opts`: whether `priority` is in the proper option list, `None` for a bad list.
// Port of erts/emulator/beam/bif.c (erts_link_opts), OTP-29.1.1.
pub(crate) fn erts_link_opts(opts: Term) -> Option<bool> {
    let mut priority = false;
    let mut bad = false;
    crate::signals::each_list_item(opts, |opt| {
        if opt == Term::atom(atoms::PRIORITY) {
            priority = true;
        } else {
            bad = true;
        }
    })?;
    (!bad).then_some(priority)
}

/// The id kinds `link_opt`, `unlink_1` and `send_exit_signal_bif` tell apart after the internal
/// pid and port arms.
enum External {
    /// `is_external_pid` (or ref) of another node: the distribution.
    Remote(String),
    /// An id of an old incarnation of this node (`dep == erts_this_dist_entry`).
    ThisNode,
    /// Not an id of this kind.
    No,
}

/// `is_external_pid(id)` (`ref` too when `refs`), or `is_external_port(id)` when `port`, with
/// its dist entry.
fn external(id: Term, refs: bool, port: bool) -> External {
    if id.is_immed() {
        return External::No;
    }
    let owned = arinsal_term::to_owned(id);
    let node = match &owned {
        Ok(arinsal_etf::OwnedTerm::Pid { node, .. }) => node.clone(),
        Ok(arinsal_etf::OwnedTerm::Ref { node, .. }) if refs => node.clone(),
        Ok(arinsal_etf::OwnedTerm::Port { node, .. }) if port => node.clone(),
        _ => return External::No,
    };
    if node == crate::node_tables::this_node().0 || node == "nonode@nohost" {
        External::ThisNode
    } else {
        External::Remote(node)
    }
}

/// `link_opt(c_p, other, opts)`.
// Port of erts/emulator/beam/bif.c (link_opt), OTP-29.1.1.
fn link_opt(process: &mut Process, other: Term, opts: Term, arity: usize) -> Result<Term, VmError> {
    let me = process.self_pid.ok_or_else(badarg)?;
    if crate::trace::active() {
        trace_procs(process, me, "link", other);
    }
    let Some(priority) = erts_link_opts(opts) else {
        return Err(badarg_ext(
            atoms::ERLANG,
            "link",
            arity,
            Term::atom(atoms::BADOPT),
        ));
    };
    let ok = Ok(Term::atom(atoms::TRUE));
    if let Some(pid) = Pid::from_term(other) {
        if pid == me {
            return ok;
        }
        let runtime = process.runtime.ok_or_else(badarg)?;
        let scheduler = runtime.scheduler()?;
        if !process.trap_exit && !scheduler.lookup_from(pid, process.on_managed) {
            return link_no_proc(process);
        }
        // erts_link_internal_tree_lookup_create; a link that exists and is not unlinking sends
        // nothing.
        if !link_node_create(&mut process.links, pid, priority) {
            return ok;
        }
        if crate::trace::active() {
            send_link_trace_changes(process, me, pid);
        }
        let sent = scheduler.signal_ordered_from(
            me,
            pid,
            arinsal_sched::Signal::Link { priority },
            process.on_managed,
        );
        match sent {
            Ok(()) => {}
            // erts_proc_sig_send_link_exit(NULL, other, rlnk, am_noproc, NIL): the target is
            // gone; a `noproc` link exit from it dissolves the link.
            Err(arinsal_sched::Error::NoProcess) => {
                let reason = Message::copy_from(Term::atom(atoms::NOPROC))?;
                scheduler
                    .signal(pid, me, arinsal_sched::Signal::ExitLinked(Box::new(reason)))
                    .map_err(|_| badarg())?;
            }
            Err(arinsal_sched::Error::Capacity) => {
                return Err(VmError::Trap(crate::exceptions::Trap::error(Term::atom(
                    atoms::SYSTEM_LIMIT,
                ))));
            }
            Err(_) => return Err(badarg()),
        }
        if crate::trace::active() {
            wake_for_procs_trace(process, pid);
        }
        return ok;
    }
    if let Some(id) = other.as_port() {
        // `!prt && !(c_p->flags & F_TRAP_EXIT)`: res_no_proc.
        let live = crate::port::is_live(process, id);
        if !live && !process.trap_exit {
            return link_no_proc(process);
        }
        let linked = live && crate::port::link(process, other, me, true)?;
        // erts_link_internal_tree_lookup_create + link_modify_flags: the link (with its
        // priority flag) is in the caller's tree whatever the port answers, and an unlink in
        // progress is cancelled (`ilnk->unlinking = 0`), so its late acknowledgement leaves it.
        let key = crate::proc_create::port_link_key(id);
        if !linked && process.links.get(key).is_none() {
            process.links.insert(crate::proc_create::port_link(id));
        }
        if let Some(mut node) = process.links.get_mut(key) {
            node.set_priority(priority);
            node.set_unlinking(0);
        }
        if !linked {
            // ERTS_PORT_OP_BADARG: erts_proc_sig_send_link_exit(NULL, other, rlnk, am_noproc,
            // NIL). The link exit reaches this process through its signal in-queue, behind a
            // receive marker reserved before the call; handling it removes the link and, when
            // trapping exits, converts it into the `{'EXIT', Port, noproc}` message.
            let signal = arinsal_sched::Signal::PortExit(Box::new(arinsal_sched::PortExitSignal {
                port: Message::copy_from(other)?,
                reason: Message::copy_from(Term::atom(atoms::NOPROC))?,
            }));
            process
                .runtime
                .ok_or_else(badarg)?
                .scheduler()?
                .signal(me, me, signal)
                .map_err(|_| badarg())?;
        }
        return ok;
    }
    match external(other, false, false) {
        External::Remote(node) => with_sched(process, |_vm, process, ctx| {
            crate::dist::link_remote(process, ctx, &node, other)
        })?,
        // An old incarnation of this node: `noproc`, or its link exit when trapping exits.
        External::ThisNode if !process.trap_exit => link_no_proc(process),
        External::ThisNode => {
            let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
            let exit = arinsal_term::TermBuilder::new(&mut heap)
                .tuple(&[Term::atom(atoms::EXIT_2), other, Term::atom(atoms::NOPROC)])
                .map_err(|_| badarg())?;
            process.inbox.push_back(exit);
            ok
        }
        External::No => Err(badarg()),
    }
}

/// `res_no_proc`: `ERTS_BIF_PREP_ERROR(ret_val, c_p, EXC_NOPROC)`.
// Port of erts/emulator/beam/bif.c (link_opt: res_no_proc), OTP-29.1.1.
fn link_no_proc(process: &mut Process) -> Result<Term, VmError> {
    let reason = Term::atom(atoms::NOPROC);
    process.heap.abi.exc.fvalue = reason.tagged_word();
    Err(VmError::Trap(crate::exceptions::Trap::error(reason)))
}

/// `erts_link_internal_tree_lookup_create` with `link_modify_flags` and the `unlinking` reset
/// of `link_opt`: whether a link signal must be sent.
// Port of erts/emulator/beam/bif.c (link_opt: is_internal_pid), OTP-29.1.1.
fn link_node_create(links: &mut crate::proc_create::LinkTree, pid: Pid, priority: bool) -> bool {
    match links.get_mut(pid.data()) {
        Some(mut node) => {
            node.set_priority(priority);
            let unlinking = node.view().unlinking();
            node.set_unlinking(0);
            unlinking != 0
        }
        None => {
            links.insert(crate::proc_create::process_link(pid, priority));
            true
        }
    }
}

/// `trace_proc(c_p, ..., am_link | am_unlink, other)` when the caller traces `procs`.
// Port of erts/emulator/beam/bif.c (link_opt, unlink_1: ERTS_IS_P_TRACED_FL(F_TRACE_PROCS)),
// OTP-29.1.1.
#[cold]
#[inline(never)]
fn trace_procs(process: &mut Process, me: Pid, event: &str, other: Term) {
    let _ = with_sched(process, |vm, process, ctx| {
        crate::trace::emit(
            Some(vm),
            process,
            ctx,
            me,
            crate::trace::PROCS,
            event,
            &[other],
        );
    });
}

/// The `set_on_link` / `set_on_first_link` trace flags the new link passes to the target.
#[cold]
#[inline(never)]
fn send_link_trace_changes(process: &mut Process, me: Pid, pid: Pid) {
    let Some(scheduler) = process.runtime.and_then(|runtime| runtime.scheduler().ok()) else {
        return;
    };
    for change in crate::trace::linked(process, me) {
        let signal = arinsal_sched::Signal::TraceChangeState(arinsal_sched::SharedPayload(
            std::sync::Arc::new(change),
        ));
        if scheduler
            .signal_ordered_from(me, pid, signal, process.on_managed)
            .is_err()
        {
            break;
        }
    }
}

/// Link and unlink signals are applied lazily, but erts handles them on arrival, which is when a
/// `procs` trace reports getting_linked/getting_unlinked: wake a receiver that is traced for it.
// Port of erts/emulator/beam/erl_proc_sig_queue.c (getting_unlinked/getting_linked), OTP-29.1.1.
#[cold]
#[inline(never)]
fn wake_for_procs_trace(process: &Process, target: Pid) {
    if crate::trace::flags(process, target) & crate::trace::PROCS != 0
        && let Some(runtime) = process.runtime.as_ref()
        && let Ok(scheduler) = runtime.scheduler()
    {
        let _ = scheduler.wake(target);
    }
}

/// `unlink/1`.
// Port of erts/emulator/beam/bif.c (unlink_1), OTP-29.1.1.
pub(crate) extern "C" fn unlink_1(c_p: *mut ProcessHeader, _reg: *mut u64, i: u64) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    let other = process.x[0];
    let result = unlink(process, other);
    bif_ret(c_p, i, result)
}

/// The arms of `unlink_1`.
// Port of erts/emulator/beam/bif.c (unlink_1), OTP-29.1.1.
fn unlink(process: &mut Process, other: Term) -> Result<Term, VmError> {
    let me = process.self_pid.ok_or_else(badarg)?;
    let ok = Ok(Term::atom(atoms::TRUE));
    if crate::trace::active() && other.as_port().is_none() {
        trace_procs(process, me, "unlink", other);
    }
    if let Some(pid) = Pid::from_term(other) {
        // erts_link_tree_lookup; a link already unlinking sends nothing.
        if !process
            .links
            .get(pid.data())
            .is_some_and(|node| node.unlinking() == 0)
        {
            return ok;
        }
        let id = process.next_ref();
        let scheduler = process.runtime.ok_or_else(badarg)?.scheduler()?;
        let sent = scheduler
            .signal_ordered_from(
                me,
                pid,
                arinsal_sched::Signal::Unlink(id),
                process.on_managed,
            )
            .is_ok();
        // unlink_clear_prio, then `ilnk->unlinking = id`, or the link deleted when the target
        // is gone (erts_proc_sig_send_unlink returned 0).
        if sent {
            if let Some(mut node) = process.links.get_mut(pid.data()) {
                node.set_unlinking(id);
                node.set_priority(false);
            }
        } else {
            process.links.remove(pid.data());
        }
        if crate::trace::active() {
            wake_for_procs_trace(process, pid);
        }
        return ok;
    }
    if let Some(id) = other.as_port() {
        // The port traces `unlink` itself; a port that is gone has its link deleted.
        if crate::port::is_live(process, id) {
            crate::port::link(process, other, me, false)?;
        } else {
            process.links.remove(crate::proc_create::port_link_key(id));
        }
        return ok;
    }
    match external(other, false, false) {
        External::Remote(node) => with_sched(process, |_vm, process, ctx| {
            crate::dist::unlink_remote(process, ctx, &node, other)
        })?,
        External::ThisNode => ok,
        // is_external_port of this node: the link is released; links to remote ports are not
        // supported.
        External::No => match external(other, false, true) {
            External::ThisNode => ok,
            _ => Err(badarg()),
        },
    }
}

/// `exit/2`.
// Port of erts/emulator/beam/bif.c (exit_2), OTP-29.1.1.
pub(crate) extern "C" fn exit_2(c_p: *mut ProcessHeader, _reg: *mut u64, i: u64) -> u64 {
    exit_signal_bif(c_p, i, 2, true)
}

/// `exit/3`.
// Port of erts/emulator/beam/bif.c (exit_3), OTP-29.1.1.
pub(crate) extern "C" fn exit_3(c_p: *mut ProcessHeader, _reg: *mut u64, i: u64) -> u64 {
    exit_signal_bif(c_p, i, 3, true)
}

/// `exit_signal/2`.
// Port of erts/emulator/beam/bif.c (exit_signal_2), OTP-29.1.1.
pub(crate) extern "C" fn exit_signal_2(c_p: *mut ProcessHeader, _reg: *mut u64, i: u64) -> u64 {
    exit_signal_bif(c_p, i, 2, false)
}

/// `exit_signal/3`.
// Port of erts/emulator/beam/bif.c (exit_signal_3), OTP-29.1.1.
pub(crate) extern "C" fn exit_signal_3(c_p: *mut ProcessHeader, _reg: *mut u64, i: u64) -> u64 {
    exit_signal_bif(c_p, i, 3, false)
}

#[inline(always)]
fn exit_signal_bif(c_p: *mut ProcessHeader, i: u64, arity: usize, exit2: bool) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    let (id, reason) = (process.x[0], process.x[1]);
    let opts = if arity == 3 { process.x[2] } else { Term::NIL };
    let result = send_exit_signal_bif(process, id, reason, opts, exit2, arity);
    bif_ret(c_p, i, result)
}

/// `send_exit_signal_bif(c_p, id, reason, opts, exit2)`.
// Port of erts/emulator/beam/bif.c (send_exit_signal_bif), OTP-29.1.1.
fn send_exit_signal_bif(
    process: &mut Process,
    id: Term,
    reason: Term,
    opts: Term,
    exit2: bool,
    arity: usize,
) -> Result<Term, VmError> {
    let Some(prio) = erts_link_opts(opts) else {
        let function = if exit2 { "exit" } else { "exit_signal" };
        return Err(badarg_ext(
            atoms::ERLANG,
            function,
            arity,
            Term::atom(atoms::BADOPT),
        ));
    };
    let ok = Ok(Term::atom(atoms::TRUE));
    let me = process.self_pid.ok_or_else(badarg)?;
    // is_internal_pid(id) || is_internal_ref(id): an alias names its creator.
    let target = if let Some(pid) = Pid::from_term(id) {
        Some((pid, 0))
    } else if let (Some(pid_data), Some(alias)) =
        (id.local_pid_ref_pid_data(), crate::signals::ref_id(id))
    {
        Some((Pid::from_data(pid_data), alias))
    } else if id.local_ref_numbers().is_some() {
        // An internal reference that is not an alias of a process: no receiver.
        return ok;
    } else {
        None
    };
    if let Some((pid, alias)) = target {
        // "Preserve the very old and *very strange* behaviour of erlang:exit/2": the caller
        // terminates itself before exit/2 returns, even for `normal`, unless it traps exits.
        let exit2_suicide = exit2
            && alias == 0
            && pid == me
            && (reason == Term::atom(atoms::KILL) || !process.trap_exit);
        if exit2_suicide {
            // The self-signal is handled at once (await_exit_trap); `kill` becomes `killed`.
            if reason == Term::atom(atoms::KILL) {
                return Err(VmError::Trap(crate::exceptions::Trap::killed()));
            }
            process.heap.abi.exc.fvalue = reason.tagged_word();
            return Err(VmError::Trap(crate::exceptions::Trap::untrappable_exit(
                reason,
            )));
        }
        // erts_proc_sig_send_exit(&c_p->common, c_p->common.id, id, reason, NIL, 0, prio).
        let mut message = Message::copy_from(reason)?;
        if alias != 0 {
            message = message.with_alias(alias);
            if prio {
                message = message.with_priority();
            }
        }
        let scheduler = process.runtime.ok_or_else(badarg)?.scheduler()?;
        let _ = scheduler.signal_ordered_from(
            me,
            pid,
            arinsal_sched::Signal::Exit(Box::new(message)),
            process.on_managed,
        );
        return ok;
    }
    if let Some(port_id) = id.as_port() {
        // An exit signal to a port that is gone is dropped.
        if crate::port::is_live(process, port_id) {
            crate::port::exit_port(process, id, reason)?;
        }
        return ok;
    }
    match external(id, true, false) {
        External::Remote(node) => with_sched(process, |_vm, process, ctx| {
            crate::dist::exit2_remote(process, ctx, &node, id, reason)
        })?,
        External::ThisNode => ok,
        // is_external_port: an old incarnation of this node is `true`, another node `badarg`.
        External::No => match external(id, false, true) {
            External::ThisNode => ok,
            _ => Err(badarg()),
        },
    }
}

/// `spawn/3`.
// Port of erts/emulator/beam/bif.c (spawn_3), OTP-29.1.1.
pub(crate) extern "C" fn spawn_3(c_p: *mut ProcessHeader, _reg: *mut u64, i: u64) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    let (module, function, args) = (process.x[0], process.x[1], process.x[2]);
    let mut so = ErlSpawnOpts::new(process.runtime);
    let result = erl_create_process(process, module, function, args, &mut so)
        .map_err(CreateError::into_bif_error);
    bif_ret(c_p, i, result)
}

/// `spawn_link/3`: `spawn/3` with `SPO_LINK` and `link` in `so.opts`.
// Port of erts/emulator/beam/bif.c (spawn_link_3), OTP-29.1.1.
pub(crate) extern "C" fn spawn_link_3(c_p: *mut ProcessHeader, _reg: *mut u64, i: u64) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    let (module, function, args) = (process.x[0], process.x[1], process.x[2]);
    let mut so = ErlSpawnOpts::new(process.runtime);
    so.link = true;
    // `so.opts = CONS(&tmp_heap[0], am_link, so.opts)`: only seq_trace reads it.
    if crate::seq_trace::has_token(process) {
        let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
        match arinsal_term::TermBuilder::new(&mut heap).cons(Term::atom(atoms::LINK), so.opts) {
            Ok(opts) => so.opts = opts,
            Err(_) => return bif_ret(c_p, i, Err(crate::natives::erl_process::system_limit())),
        }
    }
    let result = erl_create_process(process, module, function, args, &mut so)
        .map_err(CreateError::into_bif_error);
    bif_ret(c_p, i, result)
}

/// `spawn_opt/4`. Fail order: bad types, then bad options; a bad option list is
/// `badarg` with `cause => badopt` whatever the MFA.
// Port of erts/emulator/beam/bif.c (spawn_opt_4), OTP-29.1.1.
pub(crate) extern "C" fn spawn_opt_4(c_p: *mut ProcessHeader, _reg: *mut u64, i: u64) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    let (module, function, args, opts) = (process.x[0], process.x[1], process.x[2], process.x[3]);
    let result = spawn_opt(process, module, function, args, opts);
    bif_ret(c_p, i, result)
}

fn spawn_opt(
    process: &mut Process,
    module: Term,
    function: Term,
    args: Term,
    opts: Term,
) -> Result<Term, VmError> {
    let mut so = ErlSpawnOpts::new(process.runtime);
    if erts_parse_spawn_opts(&mut so, process.runtime, opts, None, false) != ParseResult::Ok {
        // The arity cannot exceed MAX_SMALL here, so every failure is BADARG with badopt.
        return Err(badarg_ext(
            atoms::ERLANG,
            "spawn_opt",
            4,
            Term::atom(atoms::BADOPT),
        ));
    }
    so.opts = opts;
    so.tag = Term::atom(atoms::SPAWN_REPLY);
    let pid = erl_create_process(process, module, function, args, &mut so)
        .map_err(CreateError::into_bif_error)?;
    if so.monitor.is_none() {
        return Ok(pid);
    }
    let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
    arinsal_term::TermBuilder::new(&mut heap)
        .tuple(&[pid, so.mref])
        .map_err(|_| crate::natives::erl_process::system_limit())
}

/// `erts_internal:spawn_request/4`: the reference, or `badarg`/`badopt` as a value. The child
/// runs `erts_internal:spawn_init({M, F, A})` with `{M, F, length(A)}` as its initial call.
// Port of erts/emulator/beam/bif.c (erts_internal_spawn_request_4), OTP-29.1.1.
pub(crate) extern "C" fn erts_internal_spawn_request_4(
    c_p: *mut ProcessHeader,
    _reg: *mut u64,
    i: u64,
) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    let (module, function, args, opts) = (process.x[0], process.x[1], process.x[2], process.x[3]);
    let result = spawn_request(process, module, function, args, opts);
    bif_ret(c_p, i, result)
}

fn spawn_request(
    process: &mut Process,
    module: Term,
    function: Term,
    args: Term,
    opts: Term,
) -> Result<Term, VmError> {
    let badarg_atom = Ok(Term::atom(atoms::BADARG));
    let (Some(m), Some(f)) = (module.as_atom(), function.as_atom()) else {
        return badarg_atom;
    };
    let Some(arity) = crate::signals::list_length(args) else {
        return badarg_atom;
    };
    let mut so = ErlSpawnOpts::new(process.runtime);
    let mut tag = Term::NIL;
    let error = match erts_parse_spawn_opts(&mut so, process.runtime, opts, Some(&mut tag), true) {
        ParseResult::NotList => return Ok(Term::atom(atoms::BADOPT)),
        ParseResult::BadOpt => atoms::BADOPT,
        ParseResult::Ok => {
            // Argument list for erts_internal:spawn_init/1: [{M, F, A}].
            let init_args = {
                let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
                let mut builder = arinsal_term::TermBuilder::new(&mut heap);
                builder
                    .tuple(&[module, function, args])
                    .and_then(|mfa| builder.cons(mfa, Term::NIL))
                    .map_err(|_| crate::natives::erl_process::system_limit())?
            };
            so.mfa = Some((m, f, arity));
            so.r#async = true;
            so.tag = tag;
            so.opts = opts;
            match erl_create_process(
                process,
                Term::atom(atoms::ERTS_INTERNAL),
                Term::atom(atoms::SPAWN_INIT),
                init_args,
                &mut so,
            ) {
                Ok(_) => return Ok(so.mref),
                Err(CreateError::SystemLimit) => atoms::SYSTEM_LIMIT,
                Err(CreateError::Badarg) => {
                    return Err(VmError::Unsupported(
                        "unexpected error from erl_create_process()".into(),
                    ));
                }
                Err(CreateError::Vm(error)) => return Err(error),
            }
        }
    };
    // send_error: `{Tag, Ref, error, Error}` to the caller unless SPO_NO_EMSG.
    let reference = crate::signals::reference(process, process.next_ref())?;
    if !so.no_emsg {
        let me = process.self_pid.and_then(Pid::to_term).ok_or_else(badarg)?;
        let message = {
            let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
            arinsal_term::TermBuilder::new(&mut heap)
                .tuple(&[tag, reference, Term::atom(atoms::ERROR), Term::atom(error)])
                .map_err(|_| crate::natives::erl_process::system_limit())?
        };
        process.send_message(me, message)?;
    }
    Ok(reference)
}

/// `spawn_request_abandon/1`.
// Port of erts/emulator/beam/bif.c (spawn_request_abandon_1), OTP-29.1.1.
pub(crate) extern "C" fn spawn_request_abandon_1(
    c_p: *mut ProcessHeader,
    _reg: *mut u64,
    i: u64,
) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    let id = process.x[0];
    let result = if id.local_ref_numbers().is_none() {
        // is_not_internal_ref: `badarg` for a non-reference, otherwise not an outstanding
        // spawn_request of this process.
        if id.classify() == arinsal_term::TermKind::Ref {
            Ok(Term::atom(atoms::FALSE))
        } else {
            Err(badarg())
        }
    } else {
        // A local request has completed when spawn_request returned; only a distributed one
        // has a spawn-pending monitor (kept in the distribution tables).
        let me = process.self_pid.ok_or_else(badarg);
        me.map(|me| {
            let abandoned = crate::signals::ref_id(id)
                .is_some_and(|key| crate::dist::spawn_request_abandon(me, key));
            Term::atom(if abandoned { atoms::TRUE } else { atoms::FALSE })
        })
    };
    bif_ret(c_p, i, result)
}

/// `alias/1`.
// Port of erts/emulator/beam/bif.c (alias_1), OTP-29.1.1.
pub(crate) extern "C" fn alias_1(c_p: *mut ProcessHeader, _reg: *mut u64, i: u64) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    let opts = process.x[0];
    let result = alias(process, opts);
    bif_ret(c_p, i, result)
}

fn alias(process: &mut Process, opts: Term) -> Result<Term, VmError> {
    let mut mode = AliasMode::ExplicitUnalias;
    let mut priority = false;
    let mut bad = false;
    crate::signals::each_list_item(opts, |option| match option.as_atom() {
        Some(atom) if atom == atoms::EXPLICIT_UNALIAS => mode = AliasMode::ExplicitUnalias,
        Some(atom) if atom == atoms::REPLY => mode = AliasMode::ReplyDemonitor,
        Some(atom) if atom == atoms::PRIORITY => priority = true,
        _ => bad = true,
    })
    .ok_or_else(badarg)?;
    if bad {
        return Err(badarg());
    }
    let me = process.self_pid.ok_or_else(badarg)?;
    let id = process.next_ref();
    let reference = crate::signals::pid_reference(process, id, me)?;
    process
        .monitors
        .insert(crate::proc_create::origin_monitor_with_reference(
            crate::proc_create::monitor_reference(id, Some(mode), priority),
            me.data(),
            0,
            OriginMonitor::Alias,
        ));
    Ok(reference)
}

/// `unalias/1`.
// Port of erts/emulator/beam/bif.c (unalias_1), OTP-29.1.1.
pub(crate) extern "C" fn unalias_1(c_p: *mut ProcessHeader, _reg: *mut u64, i: u64) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    let reference = process.x[0];
    // erts_get_pid_of_ref: the pid of a pid reference, `undefined` for another reference.
    let result = if reference.classify() != arinsal_term::TermKind::Ref {
        Err(badarg())
    } else {
        let mine = reference
            .local_pid_ref_pid_data()
            .is_some_and(|pid| Some(pid) == process.self_pid.map(Pid::data));
        let unaliased = mine
            && crate::signals::ref_id(reference)
                .is_some_and(|id| crate::signals::unalias_origin(process, id));
        Ok(Term::atom(if unaliased {
            atoms::TRUE
        } else {
            atoms::FALSE
        }))
    };
    bif_ret(c_p, i, result)
}
