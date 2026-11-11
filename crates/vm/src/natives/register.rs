//! The name registry BIFs of register.c and bif.c.
//!
//! Port of erts/emulator/beam/register.c (erts_register_name, erts_whereis_name_to_id,
//! erts_unregister_name, registered_0) and erts/emulator/beam/bif.c (register_2, unregister_1,
//! whereis_1), OTP-29.1.1. Each BIF is `bif_table[].f` with `(c_p, reg, I)`; the table is the
//! runtime's `process_reg` (crate::register), reached through the process. Only a traced
//! register/unregister reaches the scheduler's data, which Arinsal's trace evaluation needs.

use crate::Process;
use crate::VmError;
use crate::natives::bif::{badarg, badarg_ext, bif_ret, with_sched};
use crate::register::RegId;
use arinsal_beamasm::ProcessHeader;
use arinsal_sched::Pid;
use arinsal_term::{Atom, HeapReservation, Term, TermBuilder, atoms};

/// `register/2`: `erts_register_name`; a failure is `BADARG | EXF_HAS_EXT_INFO` with the
/// cause it left in `c_p->fvalue`.
// Port of erts/emulator/beam/bif.c (register_2), OTP-29.1.1.
pub(crate) extern "C" fn register_2(c_p: *mut ProcessHeader, _reg: *mut u64, i: u64) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    let (name, id) = (process.x[0], process.x[1]);
    let result = match erts_register_name(process, name, id) {
        Ok(()) => Ok(Term::atom(atoms::TRUE)),
        Err(cause) => Err(badarg_ext(atoms::ERLANG, "register", 2, Term::atom(cause))),
    };
    bif_ret(c_p, i, result)
}

/// `erts_register_name(c_p, name, id)`: `Err(fvalue)` is `am_none`, `am_registered_name` or
/// `am_notalive`.
// Port of erts/emulator/beam/register.c (erts_register_name), OTP-29.1.1.
fn erts_register_name(process: &mut Process, name: Term, id: Term) -> Result<(), Atom> {
    let none = atoms::NONE;
    let name = name
        .as_atom()
        .filter(|&name| name != atoms::UNDEFINED)
        .ok_or(none)?;
    let rt = process.runtime.ok_or(none)?;
    if let Some(pid) = Pid::from_term(id) {
        let scheduler = rt.scheduler().map_err(|_| none)?;
        let mut table = rt.reg.write();
        if !scheduler.lookup_from(pid, process.on_managed) {
            return Err(crate::atom_cache::put("notalive").as_atom().ok_or(none)?);
        }
        if scheduler.registered_atom_index(pid).is_some() {
            return Err(registered_name());
        }
        // hash_put found the name taken by another process or port.
        if table.contains(name) {
            return Err(none);
        }
        if !rt.publish_proc_flag(pid, arinsal_sched::proc_flags::REG) {
            return Err(crate::atom_cache::put("notalive").as_atom().ok_or(none)?);
        }
        table.insert_proc(name, pid);
        scheduler.set_registered_atom_index(pid, name.0);
        drop(table);
        if crate::trace::active() {
            trace_register(process, pid, "register", name);
        }
        return Ok(());
    }
    let Some(port_id) = id.as_port() else {
        return Err(none);
    };
    // erts_id2port: a port that is gone is `am_none`.
    let handle = {
        let _ports = rt.ports.lock().unwrap();
        let handle = rt.ports.get(port_id).ok_or(none)?;
        if handle.exit_complete() {
            return Err(none);
        }
        handle
    };
    let mut table = rt.reg.write();
    if handle.registered_atom().is_some() {
        return Err(registered_name());
    }
    if handle.reg_closing() || table.contains(name) {
        return Err(none);
    }
    table.insert_port(name, port_id, handle.reg_word());
    handle.set_registered_atom(name);
    drop(table);
    crate::trace::emit_port_event(
        rt,
        port_id,
        crate::trace::PORTS,
        "register",
        &[Term::atom(name)],
    );
    Ok(())
}

fn registered_name() -> Atom {
    crate::atom_cache::put("registered_name")
        .as_atom()
        .expect("atom")
}

/// `trace_proc(proc, ..., am_register | am_unregister, name)` of the process that gets or loses
/// the name.
// Port of erts/emulator/beam/register.c (erts_register_name, erts_unregister_name:
// trace_proc), OTP-29.1.1.
#[cold]
#[inline(never)]
fn trace_register(process: &mut Process, pid: Pid, event: &str, name: Atom) {
    let _ = with_sched(process, |vm, process, ctx| {
        crate::trace::emit(
            Some(vm),
            process,
            ctx,
            pid,
            crate::trace::PROCS,
            event,
            &[Term::atom(name)],
        );
    });
}

/// `unregister/1`.
// Port of erts/emulator/beam/bif.c (unregister_1), OTP-29.1.1.
pub(crate) extern "C" fn unregister_1(c_p: *mut ProcessHeader, _reg: *mut u64, i: u64) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    let name = process.x[0];
    let result = match name.as_atom() {
        Some(name) if erts_unregister_name(process, name) => Ok(Term::atom(atoms::TRUE)),
        _ => Err(badarg()),
    };
    bif_ret(c_p, i, result)
}

/// `erts_unregister_name(c_p, ..., name)`: whether the name was registered.
// Port of erts/emulator/beam/register.c (erts_unregister_name), OTP-29.1.1.
fn erts_unregister_name(process: &mut Process, name: Atom) -> bool {
    let Some(rt) = process.runtime else {
        return false;
    };
    let mut table = rt.reg.write();
    match table.erase(name) {
        Some(RegId::Proc(pid)) => {
            if let Ok(scheduler) = rt.scheduler() {
                scheduler.clear_registered_atom_index(pid, name.0);
            }
            drop(table);
            if crate::trace::active() {
                trace_register(process, pid, "unregister", name);
            }
            true
        }
        Some(RegId::Port(port_id)) => {
            drop(table);
            crate::trace::emit_port_event(
                rt,
                port_id,
                crate::trace::PORTS,
                "unregister",
                &[Term::atom(name)],
            );
            true
        }
        None => false,
    }
}

/// `whereis/1`: `erts_whereis_name_to_id`.
// Port of erts/emulator/beam/bif.c (whereis_1), OTP-29.1.1.
pub(crate) extern "C" fn whereis_1(c_p: *mut ProcessHeader, _reg: *mut u64, i: u64) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    let Some(name) = process.x[0].as_atom() else {
        return bif_ret(c_p, i, Err(badarg()));
    };
    crate::native_hooks::raw(erts_whereis_name_to_id(process, name))
}

/// `erts_whereis_name_to_id(c_p, name)`: one fetch under the read lock; the pid, the port or
/// `undefined`.
// Port of erts/emulator/beam/register.c (erts_whereis_name_to_id), OTP-29.1.1.
pub(crate) fn erts_whereis_name_to_id(process: &Process, name: Atom) -> Term {
    let undefined = Term::atom(atoms::UNDEFINED);
    let Some(rt) = process.runtime else {
        return undefined;
    };
    match rt.reg.whereis(name) {
        Some(RegId::Proc(pid)) => pid.to_term().unwrap_or(undefined),
        Some(RegId::Port(id)) => Term::port(id).unwrap_or(undefined),
        None => undefined,
    }
}

/// `registered/0`.
// Port of erts/emulator/beam/register.c (registered_0), OTP-29.1.1.
pub(crate) extern "C" fn registered_0(c_p: *mut ProcessHeader, _reg: *mut u64, i: u64) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    let result = registered(process);
    bif_ret(c_p, i, result)
}

/// The count under the read lock, `HAlloc(need)`, then `registered_foreach` conses every name
/// before the lock is released.
// Port of erts/emulator/beam/register.c (registered_0, registered_foreach), OTP-29.1.1.
fn registered(process: &mut Process) -> Result<Term, VmError> {
    let rt = process.runtime.ok_or_else(badarg)?;
    let registry = rt.reg.read();
    let need = registry.registered_count() * 2;
    if need == 0 {
        return Ok(Term::NIL);
    }
    let system_limit = || {
        VmError::Trap(crate::exceptions::Trap::error(Term::atom(
            atoms::SYSTEM_LIMIT,
        )))
    };
    let mut heap = crate::ProcessHeapHandle(&mut process.heap);
    let mut block = HeapReservation::with_extra(&mut heap, need, 0).map_err(|_| system_limit())?;
    let mut builder = TermBuilder::new(&mut block);
    let mut res = Term::NIL;
    registry
        .try_for_each_registered_atom(|name| {
            res = builder.cons(Term::atom(name), res)?;
            Ok::<_, arinsal_term::TermError>(())
        })
        .map_err(|_| system_limit())?;
    Ok(res)
}
