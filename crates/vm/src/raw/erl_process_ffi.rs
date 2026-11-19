//! The process exit entry points of erl_process.c with their C signatures, called by the
//! generated `normal_exit`, `continue_exit` and `handle_error` code of process_main.
// Port of erts/emulator/beam/erl_process.c (erts_do_exit_process,
// erts_continue_exit_process), OTP-29.1.1.

use arinsal_beamasm::ProcessHeader;

/// `void erts_do_exit_process(Process *p, Eterm reason)`: terminate `c_p` with `reason`. On
/// return the process is FREE in `p->state`, or its exit yielded with `p->u.terminate` set;
/// process_main goes to `do_schedule` either way.
// Port of erts/emulator/beam/erl_process.c:14171 (erts_do_exit_process), OTP-29.1.1.
#[unsafe(no_mangle)]
pub extern "C" fn erts_do_exit_process(c_p: *mut ProcessHeader, reason: u64) {
    let process = crate::native_hooks::process_from_header(c_p)
        .expect("erts_do_exit_process: c_p is the running process");
    let reason = crate::native_hooks::from_raw(reason);
    arinsal_sched::erts_proc_sched_data(process, |process, esdp| {
        arinsal_sched::RunCtx::with_current(esdp, |ctx| {
            process.erts_do_exit_process(&mut crate::Vm {}, ctx, reason)
        })
    })
    .flatten()
    .expect("erts_do_exit_process: called from the process's native slice");
}

/// `void erts_continue_exit_process(Process *p)`: resume the exit yielded into
/// `p->u.terminate`.
// Port of erts/emulator/beam/erl_process.c:14270 (erts_continue_exit_process), OTP-29.1.1.
#[unsafe(no_mangle)]
pub extern "C" fn erts_continue_exit_process(c_p: *mut ProcessHeader) {
    let process = crate::native_hooks::process_from_header(c_p)
        .expect("erts_continue_exit_process: c_p is the running process");
    arinsal_sched::erts_proc_sched_data(process, |process, esdp| {
        arinsal_sched::RunCtx::with_current(esdp, |ctx| {
            process.erts_continue_exit_process(&mut crate::Vm {}, ctx)
        })
    })
    .flatten()
    .expect("erts_continue_exit_process: called from the process's native slice");
}
