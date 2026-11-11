//! The BIF timer BIFs of erl_hl_timer.c.
//!
//! Port of erts/emulator/beam/erl_hl_timer.c (send_after_3, send_after_4, start_timer_3,
//! start_timer_4, cancel_timer_1, cancel_timer_2, read_timer_1, read_timer_2,
//! setup_bif_timer, access_bif_timer, no_timer_result, parse_bif_timer_options), OTP-29.1.1.
//! Each BIF is `bif_table[].f`, called with `(c_p, reg, I)`. A timer is created on the wheel of
//! the scheduler the caller runs on, reached through the process (`erts_proc_sched_data(c_p)`);
//! a timer on another scheduler's wheel is accessed by a request to that scheduler, the
//! synchronous form then traps to `erts_internal:await_result/1` and the asynchronous form
//! gets its answer as a message.

use crate::process::Message;
use crate::signals::{ref_id, reference};
use crate::{Process, VmError};
use arinsal_beamasm::ProcessHeader;
use arinsal_etf::OwnedTerm;
use arinsal_sched::Pid;
use arinsal_term::{Term, atoms, to_owned};
use std::sync::Mutex;

fn badarg() -> VmError {
    VmError::Trap(crate::exceptions::Trap::error(Term::atom(atoms::BADARG)))
}

/// `BIF_ERROR(BIF_P, BADARG | EXF_HAS_EXT_INFO)` with `BIF_P->fvalue = cause`.
fn badarg_cause(function: &str, arity: usize, cause: &str) -> VmError {
    crate::natives::bif::badarg_ext(
        atoms::ERLANG,
        function,
        arity,
        crate::atom_cache::put(cause),
    )
}

macro_rules! timer_bif {
    ($name:ident, $arity:literal, $body:expr) => {
        #[doc = concat!("`", stringify!($name), "`.")]
        pub(crate) extern "C" fn $name(c_p: *mut ProcessHeader, _reg: *mut u64, i: u64) -> u64 {
            let Some(process) = crate::native_hooks::process_from_header(c_p) else {
                return 0;
            };
            process.heap.note_bif_entry();
            let mut args = [Term::NIL; $arity];
            args.copy_from_slice(&process.x[..$arity]);
            let body: fn(&mut Process, &[Term]) -> Result<Term, VmError> = $body;
            let result = body(process, &args);
            crate::natives::bif::bif_ret(c_p, i, result)
        }
    };
}

// Port of erts/emulator/beam/erl_hl_timer.c (send_after_3), OTP-29.1.1.
timer_bif!(send_after_3, 3, |p, a| bif_timer(p, a, false, "send_after"));
// Port of erts/emulator/beam/erl_hl_timer.c (send_after_4), OTP-29.1.1.
timer_bif!(send_after_4, 4, |p, a| bif_timer(p, a, false, "send_after"));
// Port of erts/emulator/beam/erl_hl_timer.c (start_timer_3), OTP-29.1.1.
timer_bif!(start_timer_3, 3, |p, a| bif_timer(
    p,
    a,
    true,
    "start_timer"
));
// Port of erts/emulator/beam/erl_hl_timer.c (start_timer_4), OTP-29.1.1.
timer_bif!(start_timer_4, 4, |p, a| bif_timer(
    p,
    a,
    true,
    "start_timer"
));
// Port of erts/emulator/beam/erl_hl_timer.c (cancel_timer_1), OTP-29.1.1.
timer_bif!(cancel_timer_1, 1, |p, a| access_bif_timer(
    p, a[0], true, false, true
));
// Port of erts/emulator/beam/erl_hl_timer.c (cancel_timer_2), OTP-29.1.1.
timer_bif!(cancel_timer_2, 2, |p, a| {
    let options = parse_bif_timer_options(a[1], true, true, false).ok_or_else(badarg)?;
    access_bif_timer(p, a[0], true, options.asynchronous, options.info)
});
// Port of erts/emulator/beam/erl_hl_timer.c (read_timer_1), OTP-29.1.1.
timer_bif!(read_timer_1, 1, |p, a| access_bif_timer(
    p, a[0], false, false, true
));
// Port of erts/emulator/beam/erl_hl_timer.c (read_timer_2), OTP-29.1.1.
timer_bif!(read_timer_2, 2, |p, a| {
    let options = parse_bif_timer_options(a[1], true, false, false).ok_or_else(badarg)?;
    access_bif_timer(p, a[0], false, options.asynchronous, true)
});

/// The options `parse_bif_timer_options` read.
#[derive(Clone, Copy, Default)]
struct TimerOptions {
    asynchronous: bool,
    info: bool,
    absolute: bool,
}

/// `parse_bif_timer_options`: each option the BIF does not take (its out pointer is NULL) is
/// a bad option, as is anything but a proper list of `{Name, Bool}`.
// Port of erts/emulator/beam/erl_hl_timer.c (parse_bif_timer_options), OTP-29.1.1.
fn parse_bif_timer_options(
    list: Term,
    takes_async: bool,
    takes_info: bool,
    takes_abs: bool,
) -> Option<TimerOptions> {
    let mut options = TimerOptions {
        info: true,
        ..TimerOptions::default()
    };
    for option in crate::signals::list(list)? {
        // SAFETY: the option is a live term of the caller's heap (a BIF argument).
        let tuple = unsafe { option.tuple_ref() }?;
        if tuple.len() != 2 {
            return None;
        }
        let value = match tuple.get(1)? {
            value if value == Term::atom(atoms::TRUE) => true,
            value if value == Term::atom(atoms::FALSE) => false,
            _ => return None,
        };
        match tuple.get(0)? {
            name if takes_async && name == Term::atom(atoms::ASYNC) => {
                options.asynchronous = value;
            }
            name if takes_info && name == Term::atom(atoms::INFO) => options.info = value,
            name if takes_abs && name == Term::atom(atoms::ABS) => options.absolute = value,
            _ => return None,
        }
    }
    Some(options)
}

/// `send_after_3,4` / `start_timer_3,4`: the options, `parse_timeout_pos`, then
/// `setup_bif_timer` on the calling scheduler's wheel.
// Port of erts/emulator/beam/erl_hl_timer.c (send_after_4, start_timer_4, parse_timeout_pos,
// setup_bif_timer), OTP-29.1.1.
fn bif_timer(
    process: &mut Process,
    args: &[Term],
    wrap: bool,
    function: &str,
) -> Result<Term, VmError> {
    let arity = args.len();
    let (time, receiver, message) = (args[0], args[1], args[2]);
    let absolute = match args.get(3) {
        Some(options) => {
            parse_bif_timer_options(*options, false, false, true)
                .ok_or_else(|| badarg_cause(function, arity, "badopt"))?
                .absolute
        }
        None => false,
    };
    // parse_timeout_pos: a small integer, not negative unless absolute.
    let time = time
        .as_small()
        .ok_or_else(|| badarg_cause(function, arity, "time"))?;
    let ms = if absolute {
        let now = arinsal_bifs::monotonic_time_milliseconds();
        (i128::from(time) - now).clamp(0, i128::from(u64::MAX)) as u64
    } else {
        u64::try_from(time).map_err(|_| badarg_cause(function, arity, "time"))?
    };
    // setup_bif_timer: `is_not_internal_pid(rcvr) && is_not_atom(rcvr)`.
    let pid = Pid::from_term(receiver);
    let name = match pid {
        Some(_) => None,
        None => Some(receiver.as_atom().ok_or_else(badarg)?),
    };
    let runtime = process.runtime.ok_or_else(badarg)?;
    let scheduler = runtime.scheduler()?;
    // erts_sched_make_ref_in_buffer(esdp, hp): the reference names the caller's scheduler.
    let id = process.next_ref();
    let reference = reference(process, id)?;
    // The timeout tuple is the timer's queued message, so expiry enqueues it as it is.
    let message = if wrap {
        process.tuple(&[Term::atom(atoms::TIMEOUT), reference, message])?
    } else {
        message
    };
    let message = Message::copy_from_timer(message, id, process.heap.alloc_ix())?;
    // A timer for a process that does not exist is destroyed at once.
    if let Some(pid) = pid
        && !scheduler.lookup_from(pid, process.on_managed)
    {
        return Ok(reference);
    }
    let me = process.self_pid.ok_or_else(badarg)?;
    let esdp = process.native_handle().ok_or_else(no_scheduler)?;
    let started = match (pid, name) {
        (Some(pid), _) => esdp.start_timer(me, pid, ms, message, false),
        (None, Some(name)) => esdp.start_resolved_timer(
            me,
            ms,
            std::sync::Arc::new(move || runtime.reg.whereis_proc(name)),
            message,
            false,
        ),
        (None, None) => unreachable!("receiver is a pid or an atom"),
    };
    let timer = started
        .map_err(|_| no_scheduler())?
        .map_err(|error| VmError::Unsupported(format!("timer: {error}")))?;
    // The receiver exited meanwhile; its exit may already have swept its timers.
    if let Some(pid) = pid
        && !scheduler.lookup_from(pid, process.on_managed)
    {
        scheduler.cancel_timer_async(timer, |_| {});
    }
    Ok(reference)
}

/// A process runs on a normal scheduler, whose data it reaches; any other thread has none.
fn no_scheduler() -> VmError {
    VmError::Unsupported("BIF timer outside a normal scheduler".into())
}

/// `access_bif_timer`: the timer on the caller's own wheel answers at once; one on another
/// scheduler's wheel is a request to that scheduler, answered by message (`async`) or awaited
/// in `erts_internal:await_result/1`.
// Port of erts/emulator/beam/erl_hl_timer.c (access_bif_timer, access_sched_local_btm,
// try_access_sched_remote_btm, bif_timer_access_request), OTP-29.1.1.
fn access_bif_timer(
    process: &mut Process,
    tref: Term,
    cancel: bool,
    asynchronous: bool,
    info: bool,
) -> Result<Term, VmError> {
    let Some(key) = ref_id(tref) else {
        // `is_not_ref(tref)` is badarg; a ref of another node names no timer.
        if !matches!(to_owned(tref), Ok(OwnedTerm::Ref { .. })) {
            return Err(badarg());
        }
        return no_timer_result(process, tref, cancel, asynchronous, info);
    };
    if !asynchronous
        && let Some(remaining) = process
            .native_handle()
            .and_then(|esdp| esdp.access_timer(key, cancel))
    {
        return Ok(timer_result(remaining, info));
    }
    let scheduler = std::sync::Arc::clone(process.runtime.ok_or_else(badarg)?.scheduler()?);
    let timer = scheduler.timer_for_ref_key(key);
    if asynchronous {
        let me = process.self_pid.ok_or_else(badarg)?;
        let reply = info
            .then(|| to_owned(tref))
            .transpose()
            .map_err(|error| VmError::Unsupported(format!("timer reference: {error:?}")))?;
        let tag = if cancel { "cancel_timer" } else { "read_timer" };
        let sender = std::sync::Arc::clone(&scheduler);
        let answer = move |remaining: Option<u64>| {
            let Some(reference) = reply else {
                return;
            };
            let term = OwnedTerm::Tuple(vec![
                OwnedTerm::atom(tag),
                reference,
                owned_result(remaining, true),
            ]);
            if let Ok(message) = Message::from_owned(&term) {
                let _ = sender.send(me, me, message);
            }
        };
        if cancel {
            scheduler.cancel_timer_async(timer, answer);
        } else {
            scheduler.read_timer_async(timer, answer);
        }
        return Ok(Term::atom(atoms::OK));
    }
    // try_access_sched_remote_btm: the owner's wheel answers without a request when it can.
    if let Some(remaining) = scheduler.try_access_timer_local(timer, cancel) {
        return Ok(timer_result(remaining, info));
    }
    let me = process.self_pid.ok_or_else(badarg)?;
    await_timer_access(process, me, tref, scheduler, timer, cancel, info)
}

/// `no_timer_result`: `false` (or `ok` without info); the asynchronous form queues
/// `{cancel_timer | read_timer, Ref, false}` to the caller.
// Port of erts/emulator/beam/erl_hl_timer.c (no_timer_result), OTP-29.1.1.
fn no_timer_result(
    process: &mut Process,
    tref: Term,
    cancel: bool,
    asynchronous: bool,
    info: bool,
) -> Result<Term, VmError> {
    if !asynchronous {
        return Ok(timer_result(None, info));
    }
    if info {
        let tag = crate::atom_cache::put(if cancel { "cancel_timer" } else { "read_timer" });
        let message = process.tuple(&[tag, tref, Term::atom(atoms::FALSE)])?;
        process.inbox.push_back(message);
    }
    Ok(Term::atom(atoms::OK))
}

fn timer_result(remaining: Option<u64>, info: bool) -> Term {
    if !info {
        return Term::atom(atoms::OK);
    }
    remaining
        .and_then(|ms| Term::small(ms as i64))
        .unwrap_or_else(|| Term::atom(atoms::FALSE))
}

fn owned_result(remaining: Option<u64>, info: bool) -> OwnedTerm {
    if !info {
        return OwnedTerm::atom("ok");
    }
    remaining.map_or_else(
        || OwnedTerm::atom("false"),
        |ms| match i64::try_from(ms) {
            Ok(value) => OwnedTerm::Int(value),
            Err(_) => OwnedTerm::BigInt(num_bigint::BigInt::from(ms)),
        },
    )
}

/// Where the answer of a synchronous access of another scheduler's timer goes.
enum TimerAccess {
    /// The owning scheduler has not answered yet and the caller is still in the BIF.
    Pending,
    /// Answered before the caller trapped.
    Done(Option<u64>),
    /// The caller waits in `erts_internal:await_result/1` for `{Rref, Result}`.
    Awaiting { target: Pid, reply: OwnedTerm },
}

/// The request half of `access_bif_timer` for a timer on another scheduler's wheel: the
/// request goes to the owner (`erts_schedule_misc_aux_work(sid, bif_timer_access_request)`),
/// and the caller traps to `erts_internal:await_result(Rref)`.
// Port of erts/emulator/beam/erl_hl_timer.c (access_bif_timer: the request arm,
// ERTS_BIF_PREP_TRAP1(erts_await_result, c_p, rref)), OTP-29.1.1.
fn await_timer_access(
    process: &mut Process,
    me: Pid,
    tref: Term,
    scheduler: std::sync::Arc<arinsal_sched::Scheduler<Process>>,
    timer: arinsal_sched::TimerRef,
    cancel: bool,
    info: bool,
) -> Result<Term, VmError> {
    let state = std::sync::Arc::new(Mutex::new(TimerAccess::Pending));
    let answer = std::sync::Arc::clone(&state);
    let sender = std::sync::Arc::clone(&scheduler);
    let callback = move |remaining: Option<u64>| {
        let mut state = answer.lock().unwrap();
        let TimerAccess::Awaiting { target, reply } =
            std::mem::replace(&mut *state, TimerAccess::Done(remaining))
        else {
            return;
        };
        let term = OwnedTerm::Tuple(vec![reply, owned_result(remaining, info)]);
        if let Ok(message) = Message::from_owned(&term) {
            let _ = sender.send(target, target, message);
        }
    };
    if cancel {
        scheduler.cancel_timer_async(timer, callback);
    } else {
        scheduler.read_timer_async(timer, callback);
    }
    let mut guard = state.lock().unwrap();
    if let TimerAccess::Done(remaining) = *guard {
        return Ok(timer_result(remaining, info));
    }
    // erts_sched_make_ref_in_buffer: the reply reference shares node and creation with the
    // (local) timer reference.
    let id = process.next_ref();
    let reply = match to_owned(tref) {
        Ok(OwnedTerm::Ref {
            ref node, creation, ..
        }) => OwnedTerm::Ref {
            node: node.clone(),
            creation,
            ids: arinsal_bifs::ordinary_ref_words(id).to_vec(),
        },
        _ => return Err(badarg()),
    };
    let rref = reference(process, id)?;
    *guard = TimerAccess::Awaiting { target: me, reply };
    drop(guard);
    Err(VmError::TrapExport(crate::ExportTrap::new(
        process,
        "erts_internal:await_result/1",
        vec![rref],
    )))
}
