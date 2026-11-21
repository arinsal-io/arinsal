//! The trace, seq_trace, system_profile and system_monitor BIFs of erl_bif_trace.c.
//!
//! Port of erts/emulator/beam/erl_bif_trace.c, OTP-29.1.1. Each BIF is `bif_table[].f` with
//! `(c_p, reg, I)`. Helpers erts keeps in erl_trace.c stay in `natives::misc` /
//! `natives::erts_debug` / `erl_trace.rs`. `erts_internal:trace/3,4` and `trace_pattern/3,4`
//! stay on the executor in `natives::proc` until their yield/barrier path is a table body.
// Port of erts/emulator/beam/erl_bif_trace.c

use crate::natives::bif::badarg;
use crate::{Process, VmError};
use arinsal_beamasm::ProcessHeader;
use arinsal_term::{Term, atoms, global_atoms};

/// `erts_trace_cleaner:check/0`.
// Port of erts/emulator/beam/erl_bif_trace.c:605 (erts_trace_cleaner_check_0), OTP-29.1.1.
pub(crate) extern "C" fn erts_trace_cleaner_check_0(
    c_p: *mut ProcessHeader,
    reg: *mut u64,
    i: u64,
) -> u64 {
    crate::natives::bif::bif_process(c_p, reg, i, |_, []| Ok(Term::atom(atoms::FALSE)))
}

/// `erts_trace_cleaner:send_trace_clean_signal/1`.
// Port of erts/emulator/beam/erl_bif_trace.c:650
// (erts_trace_cleaner_send_trace_clean_signal_1), OTP-29.1.1.
pub(crate) extern "C" fn erts_trace_cleaner_send_trace_clean_signal_1(
    c_p: *mut ProcessHeader,
    reg: *mut u64,
    i: u64,
) -> u64 {
    crate::natives::bif::bif_process(c_p, reg, i, |process, [to]| {
        crate::signals::trace_cleaner_send(process, to)
    })
}

/// `erts_internal:trace_session_create/3`.
// Port of erts/emulator/beam/erl_bif_trace.c:1232 (erts_internal_trace_session_create_3),
// OTP-29.1.1.
pub(crate) extern "C" fn erts_internal_trace_session_create_3(
    c_p: *mut ProcessHeader,
    reg: *mut u64,
    i: u64,
) -> u64 {
    crate::natives::bif::bif_process(c_p, reg, i, |process, [name, tracer, options]| {
        crate::natives::proc::trace_session_create(process, name, tracer, options)
    })
}

/// `erts_internal:trace_session_destroy/1`.
// Port of erts/emulator/beam/erl_bif_trace.c:1278 (erts_internal_trace_session_destroy_1),
// OTP-29.1.1.
pub(crate) extern "C" fn erts_internal_trace_session_destroy_1(
    c_p: *mut ProcessHeader,
    reg: *mut u64,
    i: u64,
) -> u64 {
    crate::natives::bif::bif_sched(c_p, reg, i, |vm, process, ctx, [session_term]| {
        crate::natives::proc::with_code_mod_permission(vm, process, ctx, |vm, process, _| {
            let session =
                crate::natives::proc::trace_session_id(process, session_term).ok_or_else(badarg)?;
            let destroyed = crate::trace::destroy_session(process, session);
            if destroyed {
                crate::natives::erts_debug::session_destroyed(process, session_term);
                crate::trace_bp::clear_session(process, session);
                vm.refresh_all_trace_breakpoints(process);
            }
            Ok(Term::atom(if destroyed {
                atoms::TRUE
            } else {
                atoms::FALSE
            }))
        })
    })
}

/// `erlang:trace_info/2`.
// Port of erts/emulator/beam/erl_bif_trace.c:1386 (trace_info_2), OTP-29.1.1.
pub(crate) extern "C" fn trace_info_2(c_p: *mut ProcessHeader, reg: *mut u64, i: u64) -> u64 {
    crate::natives::bif::bif_sched(c_p, reg, i, |_vm, process, ctx, [spec, item]| {
        crate::natives::proc::with_code_mod_permission(_vm, process, ctx, |_vm, process, ctx| {
            crate::natives::proc::trace_info(process, ctx, spec, item)
        })
    })
}

/// `erts_internal:trace_info/3`.
// Port of erts/emulator/beam/erl_bif_trace.c:1407 (erts_internal_trace_info_3), OTP-29.1.1.
pub(crate) extern "C" fn erts_internal_trace_info_3(
    c_p: *mut ProcessHeader,
    reg: *mut u64,
    i: u64,
) -> u64 {
    crate::natives::bif::bif_sched(c_p, reg, i, |_vm, process, ctx, [session, spec, item]| {
        crate::natives::proc::with_code_mod_permission(_vm, process, ctx, |_vm, process, ctx| {
            let session = if atom_name(session).as_deref() == Some("any") {
                0
            } else {
                crate::natives::proc::trace_session_id(process, session).ok_or_else(badarg)?
            };
            crate::natives::proc::trace_session_info(process, ctx, session, spec, item)
        })
    })
}

/// `erlang:seq_trace/2`.
// Port of erts/emulator/beam/erl_bif_trace.c:3025 (seq_trace_2), OTP-29.1.1.
pub(crate) extern "C" fn seq_trace_2(c_p: *mut ProcessHeader, reg: *mut u64, i: u64) -> u64 {
    crate::natives::bif::bif_process(c_p, reg, i, |process, [component, value]| {
        let pid = caller_pid(process)?;
        if component == Term::atom(atoms::SEQUENTIAL_TRACE_TOKEN) {
            crate::seq_trace::set_token_value(process, pid, value)
        } else {
            crate::seq_trace::set_component(process, pid, component, value)
        }
    })
}

/// `erlang:seq_trace_info/1`.
// Port of erts/emulator/beam/erl_bif_trace.c:3216 (seq_trace_info_1), OTP-29.1.1.
pub(crate) extern "C" fn seq_trace_info_1(c_p: *mut ProcessHeader, reg: *mut u64, i: u64) -> u64 {
    crate::natives::bif::bif_process(c_p, reg, i, |process, [component]| {
        crate::seq_trace::info(process, caller_pid(process)?, component)
    })
}

/// `erlang:seq_trace_print/1`.
// Port of erts/emulator/beam/erl_bif_trace.c:3229 (seq_trace_print_1), OTP-29.1.1.
pub(crate) extern "C" fn seq_trace_print_1(c_p: *mut ProcessHeader, reg: *mut u64, i: u64) -> u64 {
    crate::natives::bif::bif_process(c_p, reg, i, |process, [message]| {
        crate::seq_trace::print(process, caller_pid(process)?, None, message)
    })
}

/// `erlang:seq_trace_print/2`.
// Port of erts/emulator/beam/erl_bif_trace.c:3248 (seq_trace_print_2), OTP-29.1.1.
pub(crate) extern "C" fn seq_trace_print_2(c_p: *mut ProcessHeader, reg: *mut u64, i: u64) -> u64 {
    crate::natives::bif::bif_process(c_p, reg, i, |process, [label, message]| {
        crate::seq_trace::print(process, caller_pid(process)?, Some(label), message)
    })
}

/// `erts_internal:system_monitor/1`.
// Port of erts/emulator/beam/erl_bif_trace.c:3384 (erts_internal_system_monitor_1), OTP-29.1.1.
pub(crate) extern "C" fn erts_internal_system_monitor_1(
    c_p: *mut ProcessHeader,
    reg: *mut u64,
    i: u64,
) -> u64 {
    crate::natives::bif::bif_process(c_p, reg, i, |process, [session]| {
        crate::natives::erts_debug::system_monitor_get(process, session)
    })
}

/// `erts_internal:system_monitor/3`.
// Port of erts/emulator/beam/erl_bif_trace.c:3405 (erts_internal_system_monitor_3), OTP-29.1.1.
pub(crate) extern "C" fn erts_internal_system_monitor_3(
    c_p: *mut ProcessHeader,
    reg: *mut u64,
    i: u64,
) -> u64 {
    crate::natives::bif::bif_process(c_p, reg, i, |process, args: [Term; 3]| {
        crate::natives::erts_debug::system_monitor_set(process, &args)
    })
}

/// `erlang:system_profile/0`.
// Port of erts/emulator/beam/erl_bif_trace.c:3757 (system_profile_0), OTP-29.1.1.
pub(crate) extern "C" fn system_profile_0(c_p: *mut ProcessHeader, reg: *mut u64, i: u64) -> u64 {
    crate::natives::bif::bif_process(c_p, reg, i, |process, []| {
        crate::natives::misc::profile_get(process)
    })
}

/// `erlang:system_profile/2`.
// Port of erts/emulator/beam/erl_bif_trace.c:3762 (system_profile_2), OTP-29.1.1.
pub(crate) extern "C" fn system_profile_2(c_p: *mut ProcessHeader, reg: *mut u64, i: u64) -> u64 {
    crate::natives::bif::bif_process(c_p, reg, i, |process, args: [Term; 2]| {
        crate::natives::misc::profile_set(process, &args)
    })
}

/// `erlang:trace_delivered/1`.
// Port of erts/emulator/beam/erl_bif_trace.c:3900 (trace_delivered_1), OTP-29.1.1.
pub(crate) extern "C" fn trace_delivered_1(c_p: *mut ProcessHeader, reg: *mut u64, i: u64) -> u64 {
    crate::natives::bif::bif_sched(c_p, reg, i, |_vm, process, ctx, [target]| {
        crate::signals::trace_delivered(process, ctx, target)
    })
}

fn caller_pid(process: &Process) -> Result<arinsal_sched::Pid, VmError> {
    process.self_pid().ok_or_else(badarg)
}

fn atom_name(term: Term) -> Option<String> {
    Some(global_atoms().text(term.as_atom()?)?.to_string())
}
