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
fn bif_ret(c_p: *mut ProcessHeader, i: u64, result: Result<Term, VmError>) -> u64 {
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
    if let Some(pid) = pid.filter(|pid| scheduler.lookup_from(*pid, process.on_managed)) {
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
