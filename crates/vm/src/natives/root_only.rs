//! Natives that only root may call.
//!
//! A process inside a namespace that calls one of these gets `notsup`, except `erlang:halt`,
//! which destroys its namespace (see [`halt_destroys_namespace`]). The check runs at native
//! dispatch and costs nothing for root: the caller's namespace is tested first.
//!
//! The list names the lowest-level native of each feature, because the Erlang wrappers of
//! `erlang` (`halt/1`, `trace/3`, `open_port/2`, `suspend_process/1`, `system_monitor/2`, ...)
//! end in these. Natives that run in native code without the dispatcher (process BIFs of the
//! JIT, trapping BIFs) must not be listed; `natives::tests` checks that.

use super::Message;
use crate::{Process, VmError};
use arinsal_sched::{RunCtx, Signal};

/// Modules whose natives are all root only.
const ROOT_MODULES: &[&str] = &[
    "erts_debug",
    "erl_debugger",
    "erts_trace_cleaner",
    "erts_literal_area_collector",
    "erl_ddll",
];

/// Single natives that are root only.
pub(crate) const ROOT_ONLY: &[(&str, &str, u8)] = &[
    // Node lifecycle and node-wide flags.
    ("erlang", "halt", 2),
    ("erlang", "system_flag", 2),
    ("erlang", "system_profile", 0),
    ("erlang", "system_profile", 2),
    ("erts_internal", "system_monitor", 1),
    ("erts_internal", "system_monitor", 3),
    ("erts_internal", "spawn_system_process", 3),
    ("erts_internal", "system_check", 1),
    ("erts_internal", "scheduler_wall_time", 1),
    ("erts_internal", "gather_alloc_histograms", 1),
    ("erts_internal", "gather_carrier_info", 1),
    // Native code and drivers.
    ("erlang", "load_nif", 2),
    // Ports and sockets of the node.
    ("erts_internal", "open_port", 2),
    ("erts_internal", "port_call", 3),
    ("erts_internal", "port_close", 1),
    ("erts_internal", "port_command", 3),
    ("erts_internal", "port_connect", 2),
    ("erts_internal", "port_control", 3),
    ("erts_internal", "port_info", 1),
    ("erts_internal", "port_info", 2),
    ("erlang", "ports", 0),
    // Tracing.
    ("erlang", "trace_info", 2),
    ("erts_internal", "trace", 3),
    ("erts_internal", "trace", 4),
    ("erts_internal", "trace_info", 3),
    ("erts_internal", "trace_pattern", 3),
    ("erts_internal", "trace_pattern", 4),
    ("erts_internal", "trace_session_create", 3),
    ("erts_internal", "trace_session_destroy", 1),
    ("erts_internal", "notify_breakpoint_hit", 3),
    ("erlang", "seq_trace", 2),
    ("erlang", "seq_trace_info", 1),
    ("erlang", "seq_trace_print", 1),
    ("erlang", "seq_trace_print", 2),
    // Other processes' state and scheduling.
    ("erts_internal", "suspend_process", 2),
    ("erlang", "resume_process", 1),
    ("erts_internal", "process_flag", 3),
    ("erts_internal", "dirty_process_handle_signals", 1),
    // Distribution.
    ("erlang", "setnode", 2),
    ("erlang", "monitor_node", 2),
    ("erlang", "monitor_node", 3),
    ("erlang", "dist_ctrl_get_data", 1),
    ("erlang", "dist_ctrl_get_data_notification", 1),
    ("erlang", "dist_ctrl_get_opt", 2),
    ("erlang", "dist_ctrl_input_handler", 2),
    ("erlang", "dist_ctrl_put_data", 2),
    ("erlang", "dist_ctrl_set_opt", 3),
    ("erlang", "dist_get_stat", 1),
    ("erts_internal", "abort_pending_connection", 2),
    ("erts_internal", "create_dist_channel", 3),
    ("erts_internal", "dist_spawn_request", 4),
    ("erts_internal", "new_connection", 1),
    // OS level.
    ("os", "set_signal", 2),
];

/// Whether `module:function/arity` may only be called by root. Public for the isolation tests.
#[doc(hidden)]
pub fn root_only(module: &str, function: &str, arity: u8) -> bool {
    ROOT_MODULES.contains(&module) || super::listed(ROOT_ONLY, module, function, arity)
}

/// Whether `module:function/arity` is root only and implemented here, for the checks in
/// `natives::tests`.
#[cfg(test)]
pub(crate) fn root_modules() -> &'static [&'static str] {
    ROOT_MODULES
}

/// What a call of a root-only native from namespace `process.ns` does, or `None` for root.
///
/// `erlang:halt` destroys the caller's namespace and ends the caller. Everything else raises
/// `notsup`, the error OTP gives for a feature the node was built without.
pub(crate) fn refuse(
    process: &mut Process,
    ctx: Option<&mut RunCtx<'_, Message>>,
    module: &str,
    function: &str,
    arity: usize,
) -> Option<VmError> {
    if process.ns == 0 {
        return None;
    }
    let arity = u8::try_from(arity).ok()?;
    if !root_only(module, function, arity) {
        return None;
    }
    if module == "erlang"
        && function == "halt"
        && let Some(ctx) = ctx
    {
        return Some(halt_destroys_namespace(process, ctx));
    }
    Some(VmError::Trap(crate::exceptions::Trap::error(
        crate::signals::atom("notsup"),
    )))
}

/// `halt` inside a namespace: destroy the namespace instead of the node. The caller is killed
/// with the rest and does not return.
fn halt_destroys_namespace(process: &mut Process, ctx: &mut RunCtx<'_, Message>) -> VmError {
    destroy_namespace(process, ctx, process.ns);
    let reason = crate::signals::atom("killed");
    match process.note_exit_reason(reason) {
        Ok(()) => VmError::Trap(crate::exceptions::Trap::untrappable_exit(reason)),
        Err(error) => error,
    }
}

/// Mark `ns` destroyed and send `kill` to every process of it. Spawning into the namespace
/// fails from the moment it is marked, so the second scan finds the children that were
/// created while the first signals were in flight.
pub(crate) fn destroy_namespace(process: &Process, ctx: &mut RunCtx<'_, Message>, ns: u32) {
    let Some(runtime) = process.runtime.as_ref() else {
        return;
    };
    let closed = runtime.namespaces.close(ns);
    // The namespace's code names become unreachable now; its instances are freed once its
    // processes are gone.
    if closed && let Some(entry) = runtime.namespaces.get(ns) {
        crate::code_domains::drop_ns_code(
            runtime,
            ns,
            &crate::code_domains::NsCode {
                chain: entry.code_chain.clone(),
                owns_first: entry.owns_code_domain,
            },
        );
    }
    let Ok(scheduler) = runtime.scheduler() else {
        return;
    };
    for _ in 0..2 {
        for pid in scheduler.pids_in_ns(ns) {
            if let Ok(reason) = Message::copy_from(crate::signals::atom("kill")) {
                let _ = ctx.signal(pid, Signal::Exit(reason));
            }
        }
    }
}
