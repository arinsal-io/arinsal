//! The process inspection BIFs of erl_bif_info.c.
//!
//! Port of erts/emulator/beam/erl_bif_info.c (is_process_alive_1, is_process_alive_trap),
//! OTP-29.1.1. Each BIF is `bif_table[].f` with `(c_p, reg, I)`.

use crate::VmError;
use crate::natives::bif::{badarg, bif_ret};
use arinsal_beamasm::ProcessHeader;
use arinsal_sched::Pid;
use arinsal_term::{Term, atoms};

/// `is_process_alive_trap`: `erts_export_put(am_erts_internal, am_is_process_alive, 1)`, the
/// Erlang function that sends the `is alive` request through the target's signal queue and
/// waits for the answer.
// Port of erts/emulator/beam/erl_bif_info.c (erts_bif_info_init: is_process_alive_trap),
// OTP-29.1.1.
const IS_PROCESS_ALIVE_TRAP: &str = "erts_internal:is_process_alive/1";

/// `is_process_alive/1`.
// Port of erts/emulator/beam/erl_bif_info.c (is_process_alive_1), OTP-29.1.1.
pub(crate) extern "C" fn is_process_alive_1(
    c_p: *mut ProcessHeader,
    _reg: *mut u64,
    i: u64,
) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    let arg = process.x[0]; // BIF_ARG_1
    if let Some(pid) = Pid::from_term(arg) {
        if arg.tagged_word() == process.heap.abi.self_pid {
            return crate::native_hooks::raw(Term::atom(atoms::TRUE));
        }
        let Some(scheduler) = process
            .runtime
            .as_ref()
            .and_then(|runtime| runtime.scheduler_if_started())
        else {
            return bif_ret(c_p, i, Err(badarg()));
        };
        // erts_proc_lookup_raw, then `rp->state`: an exiting process or one with signals in
        // its queue traps to `is_process_alive_trap`, which orders the answer after them.
        let found = if process.on_managed {
            scheduler.is_quiet_word(arg.tagged_word())
        } else {
            scheduler.is_quiet_from(pid, false)
        };
        let result = match found {
            None => atoms::FALSE,
            Some(true) => atoms::TRUE,
            Some(false) => return bif_ret(c_p, i, Err(alive_trap(process, arg))),
        };
        // ERTS_PROC_HAS_INCOMING_SIGNALS(BIF_P): signals from the inspected process to us must
        // be handled before the answer. erts traps to `erts_bif_handle_signals_return/2`
        // (ERTS_BIF_HANDLE_SIGNALS_FROM_RETURN), which has no port here; the alive request
        // orders the answer after them too.
        let own_quiet = match process.signal_probe() {
            Some(probe) => probe.is_quiet(),
            None => process
                .self_pid
                .is_some_and(|me| scheduler.is_quiet_from(me, process.on_managed) == Some(true)),
        };
        if !own_quiet {
            return bif_ret(c_p, i, Err(alive_trap(process, arg)));
        }
        return crate::native_hooks::raw(Term::atom(result));
    }
    // is_external_pid of this node's old incarnation: `am_false`.
    if let Ok(arinsal_etf::OwnedTerm::Pid { node, .. }) = &arinsal_term::to_owned(arg)
        && node == crate::node_tables::this_node().0
    {
        return crate::native_hooks::raw(Term::atom(atoms::FALSE));
    }
    bif_ret(c_p, i, Err(badarg()))
}

/// `BIF_TRAP1(is_process_alive_trap, BIF_P, BIF_ARG_1)`.
#[cold]
#[inline(never)]
fn alive_trap(process: &mut crate::Process, pid: Term) -> VmError {
    VmError::TrapExport(crate::ExportTrap::new(
        process,
        IS_PROCESS_ALIVE_TRAP,
        vec![pid],
    ))
}
