//! The monitor BIFs of bif.c.
//!
//! Port of erts/emulator/beam/bif.c (monitor_2, monitor_3, monitor, demonitor_1, demonitor_2,
//! demonitor), OTP-29.1.1. Each BIF is `bif_table[].f`, called by `call_light_bif_shared` /
//! `call_bif_shared` with `(c_p, reg, I)`; GC after the BIF is the fragment's. Only the
//! distributed arm of `monitor` reaches its scheduler's data, as erts reaches `esdp` through
//! `erts_proc_sched_data(c_p)` only where a BIF needs it.

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

fn badarg() -> VmError {
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
