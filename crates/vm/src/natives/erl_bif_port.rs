//! The port BIFs of erl_bif_port.c.
//!
//! Port of erts/emulator/beam/erl_bif_port.c (erts_internal_open_port_2,
//! erts_internal_port_command_3 stays on the executor: ERTS_BIF_YIELD3 on a busy port,
//! erts_internal_port_call_3, erts_internal_port_control_3, erts_internal_port_close_1,
//! erts_internal_port_connect_2, erts_internal_port_info_1, erts_internal_port_info_2,
//! port_set_data_2, port_get_data_1, decode_packet_3), OTP-29.1.1. Each BIF is
//! `bif_table[].f` with `(c_p, reg, I)`. `erts_internal:port_*` returns the reply
//! reference on `ERTS_PORT_OP_SCHEDULED`; erlang.erl receives.

use crate::natives::bif::{badarg_ext, bif_badarg, bif_ret, with_sched};
use crate::{Process, VmError};
use arinsal_beamasm::ProcessHeader;
use arinsal_bifs::ProcessHeapHandle;
use arinsal_packet::{DecodePacketError, decode_packet_on};
use arinsal_sched::RunCtx;
use arinsal_term::{Identity, Term, atoms};

/// `erts_internal` port ops `BIF_RET` an error atom; they do not `BIF_ERROR`.
fn port_reply(result: Result<Term, VmError>) -> Result<Term, VmError> {
    match result {
        Ok(term) => Ok(term),
        Err(VmError::Trap(trap)) => Ok(trap.reason),
        Err(error) => Err(error),
    }
}

/// How an erts_internal port BIF treats `ERTS_PSFLG_EXITING` after the op.
// Port of erts/emulator/beam/erl_bif_port.c (EXITING vs HAS_INCOMING_SIGNALS tails), OTP-29.1.1.
pub(crate) enum PortExiting {
    /// port_close / connect / info: no EXITING check.
    Ignore,
    /// port_call / control: `ERTS_BIF_EXITED`.
    Exited,
    /// port_command: `KILL_CATCHES` then `EXC_ERROR`.
    Error,
}

/// `from` of `ERTS_BIF_HANDLE_SIGNALS_FROM_RETURN` after a port op.
// Port of erts/emulator/beam/erl_bif_port.c:249-254 (and the copies at call/control/close/connect/info).
fn port_signal_from(arg: Term, prt: Option<Term>) -> Term {
    if arg.is_port() {
        arg
    } else if let Some(id) = prt {
        id
    } else {
        Term::NIL
    }
}

/// After a non-`BIF_RET(ref)` erts_internal port op: EXITING then `HAS_INCOMING_SIGNALS`.
// Port of erts/emulator/beam/erl_bif_port.c:238-258 (`erts_internal_port_command_3`) and the
// same tail on call/control/close/connect/info, OTP-29.1.1.
pub(crate) fn after_port_return(
    process: &mut Process,
    ctx: &RunCtx<'_, crate::Process>,
    arg: Term,
    prt: Option<Term>,
    retval: Term,
    exiting: PortExiting,
) -> Result<Term, VmError> {
    // `ERTS_PORT_OP_SCHEDULED`: `BIF_RET(ref)` before the handle-signals tail.
    if retval.local_ref_numbers().is_some() {
        return Ok(retval);
    }
    match exiting {
        PortExiting::Ignore => {}
        PortExiting::Exited if Process::erts_proc_is_exiting(ctx) => {
            return Process::erts_bif_chk_exited(process, ctx).map(|()| retval);
        }
        PortExiting::Error if Process::erts_proc_is_exiting(ctx) => {
            process.heap.abi.catches = 0;
            process.heap.abi.exc.freason = arinsal_term::exc::EXC_ERROR;
            return Err(VmError::Trap(crate::exceptions::Trap::error(
                crate::native_hooks::from_raw(process.heap.abi.exc.fvalue),
            )));
        }
        _ => {}
    }
    if ctx.has_incoming_signals() {
        return Err(crate::natives::sys::handle_signals_from_return(
            process,
            port_signal_from(arg, prt),
            retval,
        ));
    }
    Ok(retval)
}

fn finish_port_op(
    process: &mut Process,
    ctx: &RunCtx<'_, crate::Process>,
    arg: Term,
    prt: Option<Term>,
    result: Result<Term, VmError>,
    exiting: PortExiting,
) -> Result<Term, VmError> {
    port_reply(result).and_then(|retval| after_port_return(process, ctx, arg, prt, retval, exiting))
}

/// `erts_internal:open_port/2`.
// Port of erts/emulator/beam/erl_bif_port.c:60 (erts_internal_open_port_2), OTP-29.1.1.
pub(crate) extern "C" fn erts_internal_open_port_2(
    c_p: *mut ProcessHeader,
    reg: *mut u64,
    i: u64,
) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let [spec, opts] = crate::bif_table::bif_args::<2>(reg);
    let result = with_sched(process, reg, |vm, process, ctx| {
        let result = crate::port::start(vm, process, ctx, spec, opts);
        // `erts_internal_open_port_2` moves the caller's receive save pointer before
        // returning the init-ack reference, so the driver's reply cannot overtake it.
        if matches!(result.as_ref(), Ok(value) if matches!(value.identity(), Some(Identity::Ref { .. })))
        {
            crate::port::set_save_end(process, ctx);
        }
        result
    });
    bif_ret(c_p, i, result.and_then(port_reply))
}

/// `erts_internal:port_call/3`.
// Port of erts/emulator/beam/erl_bif_port.c:263 (erts_internal_port_call_3), OTP-29.1.1.
pub(crate) extern "C" fn erts_internal_port_call_3(
    c_p: *mut ProcessHeader,
    reg: *mut u64,
    i: u64,
) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let [port, op, data] = crate::bif_table::bif_args::<3>(reg);
    let Some(caller) = process.self_pid() else {
        return bif_ret(c_p, i, Ok(Term::atom(atoms::BADARG)));
    };
    let result = with_sched(process, reg, |_, process, ctx| {
        let prt = crate::port::resolved_port_term(process, port);
        let result = crate::port::port_call(process, caller, port, op, data);
        finish_port_op(process, ctx, port, prt, result, PortExiting::Exited)
    })
    .flatten();
    bif_ret(c_p, i, result)
}

/// `erts_internal:port_control/3`.
// Port of erts/emulator/beam/erl_bif_port.c:322 (erts_internal_port_control_3), OTP-29.1.1.
pub(crate) extern "C" fn erts_internal_port_control_3(
    c_p: *mut ProcessHeader,
    reg: *mut u64,
    i: u64,
) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let [port, op, data] = crate::bif_table::bif_args::<3>(reg);
    let result = with_sched(process, reg, |_, process, ctx| {
        let prt = crate::port::resolved_port_term(process, port);
        let result = crate::port::port_control(process, ctx, port, op, data);
        finish_port_op(process, ctx, port, prt, result, PortExiting::Exited)
    })
    .flatten();
    bif_ret(c_p, i, result)
}

/// `erts_internal:port_close/1`.
// Port of erts/emulator/beam/erl_bif_port.c:384 (erts_internal_port_close_1), OTP-29.1.1.
pub(crate) extern "C" fn erts_internal_port_close_1(
    c_p: *mut ProcessHeader,
    reg: *mut u64,
    i: u64,
) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let [port] = crate::bif_table::bif_args::<1>(reg);
    let result = with_sched(process, reg, |_, process, ctx| {
        let prt = crate::port::resolved_port_term(process, port);
        let caller = ctx.pid();
        let result = crate::port::port_close(process, Some(ctx), caller, port);
        finish_port_op(process, ctx, port, prt, result, PortExiting::Ignore)
    })
    .flatten();
    bif_ret(c_p, i, result)
}

/// `erts_internal:port_connect/2`.
// Port of erts/emulator/beam/erl_bif_port.c:438 (erts_internal_port_connect_2), OTP-29.1.1.
pub(crate) extern "C" fn erts_internal_port_connect_2(
    c_p: *mut ProcessHeader,
    reg: *mut u64,
    i: u64,
) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let [port, pid] = crate::bif_table::bif_args::<2>(reg);
    let result = with_sched(process, reg, |_, process, ctx| {
        let prt = crate::port::resolved_port_term(process, port);
        let result = crate::port::connect(process, port, pid, None);
        finish_port_op(process, ctx, port, prt, result, PortExiting::Ignore)
    })
    .flatten();
    bif_ret(c_p, i, result)
}

/// `erts_internal:port_info/1`.
// Port of erts/emulator/beam/erl_bif_port.c:486 (erts_internal_port_info_1), OTP-29.1.1.
pub(crate) extern "C" fn erts_internal_port_info_1(
    c_p: *mut ProcessHeader,
    reg: *mut u64,
    i: u64,
) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let [port] = crate::bif_table::bif_args::<1>(reg);
    let result = with_sched(process, reg, |_, process, ctx| {
        let prt = crate::port::resolved_port_term(process, port);
        let result = port_info_reply(process, port, None, false);
        finish_port_op(process, ctx, port, prt, result, PortExiting::Ignore)
    })
    .flatten();
    bif_ret(c_p, i, result)
}

/// `erts_internal:port_info/2`.
// Port of erts/emulator/beam/erl_bif_port.c:543 (erts_internal_port_info_2), OTP-29.1.1.
pub(crate) extern "C" fn erts_internal_port_info_2(
    c_p: *mut ProcessHeader,
    reg: *mut u64,
    i: u64,
) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let [port, item] = crate::bif_table::bif_args::<2>(reg);
    let result = with_sched(process, reg, |_, process, ctx| {
        let prt = crate::port::resolved_port_term(process, port);
        let result = port_info_reply(process, port, Some(item), true);
        finish_port_op(process, ctx, port, prt, result, PortExiting::Ignore)
    })
    .flatten();
    bif_ret(c_p, i, result)
}

fn port_info_reply(
    process: &mut Process,
    port: Term,
    item: Option<Term>,
    info_2: bool,
) -> Result<Term, VmError> {
    if port.is_port() || port.as_atom().is_some() {
        return port_reply(crate::port::port_info(process, port, item));
    }
    if let Some(Identity::Port { node, creation, .. }) = port.identity()
        && !port.is_port()
    {
        let this = arinsal_term::this_node();
        if node == this.0 && creation == this.1 {
            return Ok(Term::atom(atoms::UNDEFINED));
        }
        return Ok(Term::atom(if info_2 {
            atoms::BADTYPE
        } else {
            atoms::BADARG
        }));
    }
    Ok(Term::atom(if info_2 {
        atoms::BADTYPE
    } else {
        atoms::BADARG
    }))
}

/// `erlang:port_set_data/2`.
// Port of erts/emulator/beam/erl_bif_port.c:687 (port_set_data_2), OTP-29.1.1.
pub(crate) extern "C" fn port_set_data_2(c_p: *mut ProcessHeader, reg: *mut u64, i: u64) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let [port, data] = crate::bif_table::bif_args::<2>(reg);
    bif_ret(c_p, i, crate::port::port_set_data(process, port, data))
}

/// `erlang:port_get_data/1`.
// Port of erts/emulator/beam/erl_bif_port.c:734 (port_get_data_1), OTP-29.1.1.
pub(crate) extern "C" fn port_get_data_1(c_p: *mut ProcessHeader, reg: *mut u64, i: u64) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let [port] = crate::bif_table::bif_args::<1>(reg);
    bif_ret(c_p, i, crate::port::port_get_data(process, port))
}

/// `erlang:decode_packet/3`.
// Port of erts/emulator/beam/erl_bif_port.c:1476 (decode_packet_3), OTP-29.1.1.
pub(crate) extern "C" fn decode_packet_3(c_p: *mut ProcessHeader, reg: *mut u64, i: u64) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let [ty, data, opts] = crate::bif_table::bif_args::<3>(reg);
    let mut heap = ProcessHeapHandle(&mut process.heap);
    match decode_packet_on(&mut heap, ty, data, opts) {
        Ok(value) => crate::native_hooks::raw(value),
        Err(DecodePacketError::Badopt) => bif_ret(
            c_p,
            i,
            Err(badarg_ext(
                atoms::ERLANG,
                "decode_packet",
                3,
                Term::atom(atoms::BADOPT),
            )),
        ),
        Err(DecodePacketError::Badarg) => bif_badarg(c_p),
    }
}
