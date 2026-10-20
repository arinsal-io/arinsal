//! Process to port signals of loaded-driver ports: an immediate driver call on the caller's
//! thread when the port is free, otherwise a port task.
//!
//! Port of erts/emulator/beam/io.c (try_imm_drv_call, erts_schedule_proc2port_signal,
//! port_sched_op_reply, erts_port_output, erts_port_exit, erts_port_connect,
//! erts_port_link, erts_port_unlink, erts_port_control), OTP-29.1.1.

use super::*;
use arinsal_drv::DriverPort;
use arinsal_drv::port_task::{
    ImmFail, PT_FLG_ASYNC_NOSUSPEND, PT_FLG_NOSUSPEND, PT_FLG_WAIT_BUSY, PTS_FLG_BUSY_PORT,
    PTS_FLG_EXIT, PTS_FLG_PARALLELISM, PTS_FLGS_BUSY, PTS_FLGS_FORCE_SCHEDULE_OP, ProcSig, SigOp,
};
use arinsal_sched::RunCtx;

// Port of erts/emulator/beam/erl_port.h:362-381 (ERTS_PORT_REDS_*), OTP-29.1.1.
const CONTEXT_REDS: i32 = 4000;
const REDS_CMD_OUTPUT: i32 = CONTEXT_REDS / 100;
const REDS_EXIT: i32 = CONTEXT_REDS / 100;
const REDS_CONNECT: i32 = CONTEXT_REDS / 200;
const REDS_LINK: i32 = CONTEXT_REDS / 200;
const REDS_UNLINK: i32 = CONTEXT_REDS / 200;
const REDS_DEMONITOR: i32 = CONTEXT_REDS / 200;
const REDS_CONTROL: i32 = CONTEXT_REDS / 100;

/// `ErtsPortOpResult`.
pub(crate) enum PortOp {
    /// `ERTS_PORT_OP_DONE`.
    Done,
    /// `ERTS_PORT_OP_DROPPED`.
    Dropped,
    /// `ERTS_PORT_OP_BADARG`.
    Badarg,
    /// `ERTS_PORT_OP_BUSY`: nothing was sent.
    Busy,
    /// `ERTS_PORT_OP_BUSY_SCHEDULED`: sent, but the port is busy now.
    BusyScheduled(Option<u64>),
    /// `ERTS_PORT_OP_SCHEDULED`, with the reply reference of a synchronous operation.
    Scheduled(Option<u64>),
}

/// `ERTS_PORT_SIG_FLG_*` of an output signal.
#[derive(Clone, Copy, Default)]
pub(crate) struct OutputFlags {
    pub(crate) bang: bool,
    pub(crate) nosuspend: bool,
    pub(crate) force: bool,
}

/// A `{Ref, Result}` reply to the caller of a scheduled synchronous operation
/// (`port_sched_op_reply`).
struct Reply {
    to: Pid,
    reference: u64,
    scheduler: Arc<Scheduler<Process>>,
}

/// The reference term of a reply on the caller's heap.
pub(crate) fn reference_term(process: &mut Process, reference: u64) -> Result<Term, VmError> {
    let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
    TermBuilder::new(&mut heap)
        .local_ref(arinsal_bifs::ordinary_ref_words(reference))
        .map_err(|_| badarg())
}

impl Reply {
    fn new(to: Pid, scheduler: Arc<Scheduler<Process>>) -> (Self, u64) {
        let reference = arinsal_bifs::next_ref_id();
        (
            Reply {
                to,
                reference,
                scheduler,
            },
            reference,
        )
    }

    fn send(self, build: impl FnOnce(&mut ProcessHeap) -> Option<Term>) {
        self.send_sized(64, build);
    }

    /// `send` for a value of up to `words` heap words (a control reply is a byte list).
    fn send_sized(self, words: usize, build: impl FnOnce(&mut ProcessHeap) -> Option<Term>) {
        let mut heap = ProcessHeap::with_words(64 + words);
        let Some(value) = build(&mut heap) else {
            return;
        };
        let reference = self.reference;
        let Ok(reference) =
            TermBuilder::new(&mut heap).local_ref(arinsal_bifs::ordinary_ref_words(reference))
        else {
            return;
        };
        let Ok(message) = TermBuilder::new(&mut heap).tuple(&[reference, value]) else {
            return;
        };
        if let Ok(message) = Message::copy_from(message) {
            let _ = self.scheduler.send(self.to, self.to, message);
        }
    }

    fn atom(self, name: &'static str) {
        self.send(|_| Some(atom(name)));
    }
}

fn caller_data(pid: Pid) -> u64 {
    packed_pid(pid)
}

/// The data of one `command` signal: a native driver takes one flat buffer, a loaded driver the
/// pieces of `erts_ioq_iolist_to_vec` (`true` marks a reference-counted binary).
enum CommandData {
    Flat(Vec<u8>),
    Pieces(Vec<(Vec<u8>, bool)>),
}

impl CommandData {
    fn size(&self) -> usize {
        match self {
            CommandData::Flat(bytes) => bytes.len(),
            CommandData::Pieces(pieces) => pieces.iter().map(|(bytes, _)| bytes.len()).sum(),
        }
    }
}

fn io_views(pieces: &[(Vec<u8>, bool)]) -> Vec<arinsal_drv::IoPiece<'_>> {
    pieces
        .iter()
        .map(|(bytes, refc)| {
            if *refc {
                arinsal_drv::IoPiece::Refc(bytes)
            } else {
                arinsal_drv::IoPiece::Copied(bytes)
            }
        })
        .collect()
}

/// Port of erts/emulator/beam/io.c:1468 (call_driver_output) and io.c:1354
/// (call_driver_outputv): the bang form checks the connected process first.
fn call_driver_output(
    handle: &PortHandle,
    drv: &DriverPort,
    bang: bool,
    caller: Pid,
    from: Pid,
    data: CommandData,
) {
    if bang && from != handle.owner_pid() {
        signal_badsig(handle, handle.id);
        return;
    }
    let size = data.size();
    let done = match data {
        CommandData::Flat(bytes) => drv.output_owned(bytes, caller_data(caller)),
        CommandData::Pieces(pieces) => drv.output(&io_views(&pieces), caller_data(caller)),
    };
    if done {
        handle.add_bytes_out(size);
    }
}

/// Port of erts/emulator/beam/io.c:1715 (erts_port_output). `want_ref` is a synchronous
/// `port_command` (`refp`); bang sends are asynchronous.
#[allow(clippy::too_many_arguments)]
pub(crate) fn output(
    process: &mut Process,
    ctx: Option<&mut RunCtx<'_, Message>>,
    caller: Pid,
    handle: &Arc<PortHandle>,
    drv: &Arc<DriverPort>,
    from: Pid,
    data: Term,
    flags: OutputFlags,
    want_ref: bool,
) -> PortOp {
    let asynchronous = !want_ref;
    let busy_flgs = if flags.force { 0 } else { PTS_FLGS_BUSY };
    let mut invalid_flags = busy_flgs;
    if !want_ref {
        invalid_flags |= PTS_FLG_PARALLELISM;
    }
    let sched_flags = drv.sched_flags();
    if sched_flags & (busy_flgs | PTS_FLG_EXIT) != 0 {
        return if sched_flags & PTS_FLG_EXIT != 0 {
            PortOp::Dropped
        } else {
            PortOp::Busy
        };
    }
    let async_nosuspend = asynchronous && flags.nosuspend && !flags.force;
    let try_call = sched_flags & (invalid_flags | PTS_FLGS_FORCE_SCHEDULE_OP) == 0;
    // A native driver has no `outputv`: its command data is one flat buffer.
    let command = if drv.driver().is_native() {
        iodata(data).map(CommandData::Flat)
    } else {
        let mut pieces = Vec::new();
        io_pieces(data, &mut pieces).map(|()| CommandData::Pieces(pieces))
    };
    let Some(command) = command else {
        // io.c:2160 bad_value: bad_port_signal.
        if flags.bang {
            signal_badsig(handle, handle.id);
            return PortOp::Dropped;
        }
        return PortOp::Badarg;
    };
    // erl_trace.c trace_port_receive for `command` (io.c:1503, call_driver_output).
    if crate::trace::tracing_enabled() {
        let views = match &command {
            CommandData::Flat(bytes) => vec![arinsal_drv::IoPiece::Copied(bytes)],
            CommandData::Pieces(pieces) => io_views(pieces),
        };
        let segments = drv.outputv_trace_segments(&views);
        let tracer = if flags.bang { from } else { caller };
        trace_command_received(process, tracer, handle.id, &views, segments);
    }
    if try_call {
        let reductions_left = ctx
            .as_deref()
            .map_or((CONTEXT_REDS / 10) as u32, |ctx| ctx.remaining());
        match drv.try_imm_call(invalid_flags, asynchronous, "command", reductions_left) {
            Ok(imm) => {
                // Port of erts/emulator/beam/io.c:1005-1055 (try_imm_drv_call and
                // finalize_imm_drv_call), OTP-29.1.1.
                trace_immediate_process(process, caller, "out");
                call_driver_output(handle, drv, flags.bang, caller, from, command);
                let reductions_used = imm.reductions_used();
                drop(imm);
                trace_immediate_process(process, caller, "in");
                if let Some(ctx) = ctx {
                    ctx.consume(reductions_used);
                }
                return PortOp::Done;
            }
            Err(ImmFail::InvalidPort) => return PortOp::Dropped,
            Err(ImmFail::InvalidSchedFlags(sched_flags))
                if async_nosuspend && sched_flags & (busy_flgs | PTS_FLG_EXIT) != 0 =>
            {
                return if sched_flags & PTS_FLG_EXIT != 0 {
                    PortOp::Dropped
                } else {
                    PortOp::Busy
                };
            }
            Err(_) => {}
        }
    }
    let mut task_flags = PT_FLG_WAIT_BUSY;
    if flags.force || flags.nosuspend {
        task_flags = 0;
        if flags.force {
        } else if async_nosuspend {
            task_flags = PT_FLG_WAIT_BUSY | PT_FLG_ASYNC_NOSUSPEND;
        } else {
            task_flags = PT_FLG_NOSUSPEND;
        }
    }
    let Ok(scheduler) = process
        .runtime
        .as_ref()
        .ok_or(())
        .and_then(|runtime| runtime.scheduler().map_err(|_| ()))
    else {
        return PortOp::Dropped;
    };
    let (reply, reference) = if want_ref {
        let (reply, reference) = Reply::new(caller, scheduler);
        (Some(reply), Some(reference))
    } else {
        (None, None)
    };
    // Port of erts/emulator/beam/io.c:1203 (erts_schedule_proc2port_signal): the caller moves its
    // save pointer before the signal is scheduled, so the reply cannot be queued before it.
    if let Some(ctx) = ctx.filter(|_| want_ref) {
        set_save_end(process, ctx);
    }
    let size = command.size();
    let task_handle = Arc::clone(handle);
    let task_drv = Arc::clone(drv);
    let bang = flags.bang;
    let callback = Box::new(move |op: SigOp| {
        // Port of erts/emulator/beam/io.c:1531 (port_sig_output), OTP-29.1.1.
        let result = match op {
            SigOp::Exec => {
                call_driver_output(&task_handle, &task_drv, bang, caller, from, command);
                "true"
            }
            SigOp::AbortNosuspend => "false",
            SigOp::Abort | SigOp::AbortClosed => "badarg",
        };
        if let Some(reply) = reply {
            reply.atom(result);
        }
        REDS_CMD_OUTPUT
    });
    let Some(task) = drv.schedule_signal(ProcSig {
        caller: caller_data(caller),
        flags: task_flags,
        size,
        callback,
    }) else {
        return PortOp::Scheduled(reference);
    };
    if !flags.force {
        let sched_flags = drv.sched_flags();
        if sched_flags & PTS_FLG_BUSY_PORT != 0 {
            if !async_nosuspend {
                return PortOp::BusyScheduled(reference);
            }
            if drv.abort_task(&task) {
                return PortOp::Busy;
            }
        }
    }
    PortOp::Scheduled(reference)
}

// Port of erts/emulator/beam/io.c:1005-1055 (try_imm_drv_call and
// finalize_imm_drv_call), OTP-29.1.1.
fn trace_immediate_process(process: &Process, pid: Pid, name: &str) {
    let Some(runtime) = process.runtime.as_ref() else {
        return;
    };
    crate::trace::emit_external_process_event(runtime, pid, crate::trace::RUNNING_PROCS, name, &[]);
}

/// Queue `op` as a port task (`erts_schedule_proc2port_signal`).
fn schedule(drv: &Arc<DriverPort>, caller: Pid, op: impl FnOnce(SigOp) -> i32 + Send + 'static) {
    let _ = drv.schedule_signal(ProcSig {
        caller: caller_data(caller),
        flags: 0,
        size: 0,
        callback: Box::new(op),
    });
}

/// Run `op` now when the port is free (`try_imm_drv_call`), else as a port task whose
/// callback gets the abort reason. `Err` is `ERTS_PORT_OP_DROPPED`/`BADARG`.
fn imm_or_schedule(
    drv: &Arc<DriverPort>,
    caller: Pid,
    asynchronous: bool,
    where_: &'static str,
    op: impl FnOnce(SigOp) -> i32 + Send + 'static,
) -> Result<bool, ()> {
    match drv.try_imm_call(0, asynchronous, where_, (CONTEXT_REDS / 10) as u32) {
        Ok(imm) => {
            op(SigOp::Exec);
            drop(imm);
            Ok(true)
        }
        Err(ImmFail::InvalidPort) => Err(()),
        Err(_) => {
            schedule(drv, caller, op);
            Ok(false)
        }
    }
}

/// Port of erts/emulator/beam/io.c:4268 (erts_port_control) for a loaded driver:
/// the reply term, or a reference the caller waits on.
pub(crate) fn control(
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    caller: Pid,
    drv: &Arc<DriverPort>,
    op: u32,
    bytes: Vec<u8>,
) -> Result<Term, VmError> {
    let runtime = process.runtime.clone().ok_or_else(badarg)?;
    let sched_flags = drv.sched_flags();
    if sched_flags & PTS_FLGS_FORCE_SCHEDULE_OP == 0 {
        match drv.try_imm_call(0, false, "control", (CONTEXT_REDS / 10) as u32) {
            Ok(imm) => {
                let reply = call_driver_control(&runtime, drv, caller, op, &bytes);
                drop(imm);
                let Some(reply) = reply else {
                    return Ok(atom("badarg"));
                };
                let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
                return control_term(&mut heap, reply).map_err(|_| badarg());
            }
            Err(ImmFail::InvalidPort) => return Ok(atom("badarg")),
            Err(_) => {}
        }
    }
    let (reply, reference) = Reply::new(caller, runtime.scheduler()?);
    // Port of erts/emulator/beam/io.c:1203 (erts_schedule_proc2port_signal), OTP-29.1.1.
    set_save_end(process, ctx);
    let task_drv = Arc::clone(drv);
    let _ = drv.schedule_signal(ProcSig {
        caller: caller_data(caller),
        flags: 0,
        size: 0,
        callback: Box::new(move |sig: SigOp| {
            // Port of erts/emulator/beam/io.c:4160 (port_sig_control), OTP-29.1.1.
            let result = match sig {
                SigOp::Exec => call_driver_control(&runtime, &task_drv, caller, op, &bytes),
                _ => None,
            };
            // A list reply takes two words per byte, a binary its bytes.
            let words = match &result {
                Some(arinsal_drv::ControlReply::List(bytes)) => bytes.len() * 2,
                Some(arinsal_drv::ControlReply::Binary(bytes)) => bytes.len() / 8 + 8,
                _ => 0,
            };
            reply.send_sized(words, |heap| match result {
                Some(result) => control_term(heap, result).ok(),
                None => Some(atom("badarg")),
            });
            REDS_CONTROL
        }),
    });
    reference_term(process, reference)
}

/// Port of erts/emulator/beam/io.c:4018 (call_driver_control) with its receive trace,
/// the `{Port, {control, Reply}}` send trace and long_schedule accounting.
fn call_driver_control(
    runtime: &Arc<crate::process::Runtime>,
    drv: &DriverPort,
    caller: Pid,
    op: u32,
    bytes: &[u8],
) -> Option<arinsal_drv::ControlReply> {
    let id = drv.id();
    trace_port_receive_indexed_rt(runtime, caller, id, "control", op, bytes);
    let started = std::time::Instant::now();
    let reply = drv.control(op, bytes, caller_data(caller));
    if let Some(port) = Term::port(id) {
        crate::natives::erts_debug::after_port_task(
            runtime,
            port,
            caller,
            "proc_sig",
            started.elapsed().as_nanos() as u64,
        );
    }
    let reply = reply?;
    if !crate::trace::tracing_enabled() {
        return Some(reply);
    }
    let handle = runtime.ports.get(id);
    if let Some(handle) = handle
        && let Some(port) = Term::port(id)
    {
        let response = match &reply {
            arinsal_drv::ControlReply::Nil => &[][..],
            arinsal_drv::ControlReply::Binary(bytes) | arinsal_drv::ControlReply::List(bytes) => {
                bytes.as_slice()
            }
        };
        let mut trace_heap = VecHeap::new();
        if let Ok(binary) = TermBuilder::new(&mut trace_heap).binary(response)
            && let Ok(control) = TermBuilder::new(&mut trace_heap).tuple(&[atom("control"), binary])
            && let Ok(message) = TermBuilder::new(&mut trace_heap).tuple(&[port, control])
        {
            trace_port_send(&handle.scheduler, handle.trace_scope, id, caller, message);
        }
    }
    Some(reply)
}

fn control_term<H: arinsal_term::HeapAlloc + ?Sized>(
    heap: &mut H,
    reply: arinsal_drv::ControlReply,
) -> Result<Term, arinsal_term::TermError> {
    let mut builder = TermBuilder::new(heap);
    match reply {
        arinsal_drv::ControlReply::Nil => Ok(Term::NIL),
        arinsal_drv::ControlReply::Binary(bytes) => builder.binary(&bytes),
        arinsal_drv::ControlReply::List(bytes) => builder.bytes_to_list(&bytes),
    }
}

/// Port of erts/emulator/beam/io.c:2164 (call_deliver_port_exit) for `port_close/1`,
/// `Port ! {Pid, close}` and `exit(Port, Reason)`: terminate the port with links and
/// monitors notified. `bang` checks the connected process.
fn deliver_exit(
    runtime: &crate::process::Runtime,
    handle: &PortHandle,
    bang: bool,
    from: Pid,
    reason: Term,
    closed_to: Option<Pid>,
) -> bool {
    let id = handle.id;
    if bang && from != handle.owner_pid() {
        signal_badsig(handle, id);
        return true;
    }
    let Ok(scheduler) = runtime.scheduler() else {
        return false;
    };
    // io.c:3841 (erts_deliver_port_exit): links and monitors first, then
    // terminate_port runs `stop`, whose output still reaches the connected process.
    crate::trace::emit_port_event(runtime, id, crate::trace::PORTS, "closed", &[reason]);
    if remove_and_notify(runtime, id, &scheduler, from, reason).is_none() {
        return false;
    }
    release_io(handle);
    if let Some(to) = closed_to {
        event_message(&scheduler, to, id, handle.trace_scope, atom("closed"));
    }
    // The port's trace state goes last: `{Port, closed}` above is still traced.
    crate::trace::port_closed(runtime, id);
    true
}

/// `trace_port_receive(prt, from, am_close)` (io.c:2196).
fn trace_close_receive(runtime: &crate::process::Runtime, id: u64, from: Pid) {
    let Some(caller) = from.to_term() else {
        return;
    };
    let mut heap = VecHeap::new();
    if let Ok(event) = TermBuilder::new(&mut heap).tuple(&[caller, atom("close")]) {
        crate::trace::emit_port_event(runtime, id, crate::trace::RECEIVE, "receive", &[event]);
    }
}

/// Port of erts/emulator/beam/io.c:2241 (erts_port_exit) for a loaded driver.
/// `want_ref` is `port_close/1`: its result goes to the returned reference id when
/// scheduled. `Err` is `badarg`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn exit(
    process: &mut Process,
    ctx: Option<&mut RunCtx<'_, Message>>,
    caller: Pid,
    handle: &Arc<PortHandle>,
    drv: &Arc<DriverPort>,
    bang: bool,
    from: Pid,
    reason: OwnedTerm,
    want_ref: bool,
) -> Result<Option<u64>, VmError> {
    let runtime = process.runtime.clone().ok_or_else(badarg)?;
    let closed_to = bang.then_some(from);
    // port_close/1 traces `receive {Caller, close}` when the signal executes
    // (io.c:2196 call_deliver_port_exit).
    let trace_close = want_ref;
    match drv.try_imm_call(0, !want_ref, "close", (CONTEXT_REDS / 10) as u32) {
        Ok(imm) => {
            if trace_close {
                trace_close_receive(&runtime, handle.id, from);
            }
            let mut heap = ProcessHeap::with_words(64);
            let reason = from_owned(&reason, &mut heap).unwrap_or_else(|_| atom("normal"));
            let done = deliver_exit(&runtime, handle, bang, from, reason, closed_to);
            drop(imm);
            return if done { Ok(None) } else { Err(badarg()) };
        }
        Err(ImmFail::InvalidPort) => return Err(badarg()),
        Err(_) => {}
    }
    let (reply, reference) = if want_ref {
        let (reply, reference) = Reply::new(caller, runtime.scheduler()?);
        (Some(reply), Some(reference))
    } else {
        (None, None)
    };
    // Port of erts/emulator/beam/io.c:1203 (erts_schedule_proc2port_signal), OTP-29.1.1.
    if want_ref {
        // A reply reference is only created for a process caller, which always has a context.
        let ctx = ctx.expect("a reply reference is created only for a process caller");
        set_save_end(process, ctx);
    }
    let task_handle = Arc::clone(handle);
    schedule(drv, caller, move |op| {
        // Port of erts/emulator/beam/io.c:2212 (port_sig_exit), OTP-29.1.1.
        if trace_close && op == SigOp::Exec {
            trace_close_receive(&runtime, task_handle.id, from);
        }
        let mut heap = ProcessHeap::with_words(64);
        let reason = from_owned(&reason, &mut heap).unwrap_or_else(|_| atom("normal"));
        let ok = op == SigOp::Exec
            && deliver_exit(&runtime, &task_handle, bang, from, reason, closed_to);
        if let Some(reply) = reply {
            reply.atom(if ok { "true" } else { "badarg" });
        }
        REDS_EXIT
    });
    Ok(reference)
}

/// Deliver the system's halt exit to a loaded driver, scheduling the callback if busy.
///
/// Port of erts/emulator/beam/erl_process.c:2570-2576 and io.c:2164-2198, OTP-29.1.1.
pub(crate) fn exit_for_halt(
    runtime: Arc<crate::process::Runtime>,
    handle: Arc<PortHandle>,
    from: Pid,
    reason: OwnedTerm,
) {
    let Some(drv) = handle.driver.get().cloned() else {
        return;
    };
    match drv.try_imm_call(0, true, "close", REDS_EXIT as u32) {
        Ok(imm) => {
            let mut heap = ProcessHeap::with_words(64);
            let reason = from_owned(&reason, &mut heap).unwrap_or_else(|_| atom("killed"));
            deliver_exit(&runtime, &handle, false, from, reason, None);
            drop(imm);
        }
        Err(ImmFail::InvalidPort) => {}
        Err(_) => {
            schedule(&drv, from, move |op| {
                if op == SigOp::Exec {
                    let mut heap = ProcessHeap::with_words(64);
                    let reason = from_owned(&reason, &mut heap).unwrap_or_else(|_| atom("killed"));
                    deliver_exit(&runtime, &handle, false, from, reason, None);
                }
                REDS_EXIT
            });
        }
    }
}

/// Queue the forced port exit used when a process exits while linked to a driver port.
/// Port of erts/emulator/beam/erl_process.c:14068 (`erts_proc_exit_handle_link`) and
/// erts/emulator/beam/io.c:2212 (`port_sig_exit`), OTP-29.1.1.
pub(crate) fn exit_for_process_termination(
    runtime: Arc<crate::process::Runtime>,
    handle: Arc<PortHandle>,
    from: Pid,
    reason: OwnedTerm,
) {
    let Some(drv) = handle.driver.get().cloned() else {
        return;
    };
    schedule(&drv, from, move |op| {
        if op == SigOp::Exec {
            // Port of erts/emulator/beam/io.c:2187 (`call_deliver_port_exit`),
            // OTP-29.1.1: the forced exit breaks the exiting process's port link.
            handle.links.lock().unwrap().remove(&from);
            let mut heap = ProcessHeap::with_words(64);
            let reason = from_owned(&reason, &mut heap).unwrap_or_else(|_| atom("normal"));
            deliver_exit(&runtime, &handle, false, from, reason, None);
        }
        REDS_EXIT
    });
}

/// Port of erts/emulator/beam/io.c:2434 (erts_port_connect) for `Port ! {From, {connect,
/// Pid}}` on a loaded driver.
pub(crate) fn connect(
    process: &Process,
    caller: Pid,
    handle: &Arc<PortHandle>,
    drv: &Arc<DriverPort>,
    from: Pid,
    pid: Pid,
) {
    let Some(runtime) = process.runtime.clone() else {
        return;
    };
    let task_handle = Arc::clone(handle);
    let _ = imm_or_schedule(drv, caller, true, "connect", move |op| {
        // Port of erts/emulator/beam/io.c:2366 (port_sig_connect), OTP-29.1.1.
        if op != SigOp::Exec {
            return REDS_CONNECT;
        }
        let handle = &task_handle;
        if from != handle.owner_pid() {
            signal_badsig(handle, handle.id);
            return REDS_CONNECT;
        }
        let Ok(scheduler) = runtime.scheduler() else {
            return REDS_CONNECT;
        };
        if !scheduler.lookup(pid) {
            signal_badsig(handle, handle.id);
            return REDS_CONNECT;
        }
        handle.links.lock().unwrap().insert(pid);
        *handle.owner.lock().unwrap() = pid;
        if !runtime.publish_proc_flag(pid, arinsal_sched::proc_flags::PORTS) {
            handle.links.lock().unwrap().remove(&pid);
            *handle.owner.lock().unwrap() = from;
            signal_badsig(handle, handle.id);
            return REDS_CONNECT;
        }
        connected_message(
            &runtime,
            &scheduler,
            from,
            handle.id,
            handle.trace_scope,
            true,
        );
        REDS_CONNECT
    });
}

/// Port of erts/emulator/beam/io.c:2698 (erts_port_link) and io.c:2541 (erts_port_unlink)
/// for a loaded driver. `false` when the port is gone (`ERTS_PORT_OP_BADARG`).
pub(crate) fn link(
    runtime: &Arc<crate::process::Runtime>,
    handle: &Arc<PortHandle>,
    drv: &Arc<DriverPort>,
    pid: Pid,
    linked: bool,
) -> bool {
    let task_runtime = Arc::clone(runtime);
    let task_handle = Arc::clone(handle);
    imm_or_schedule(
        drv,
        pid,
        true,
        if linked { "link" } else { "unlink" },
        move |op| {
            let handle = &task_handle;
            let live = op == SigOp::Exec && task_runtime.ports.contains(handle.id);
            if linked {
                // Port of erts/emulator/beam/io.c:2669 (port_sig_link), OTP-29.1.1.
                if live {
                    handle.links.lock().unwrap().insert(pid);
                    // erl_process.c:14084: the port link lives on the process, so exit
                    // must visit the port table.
                    if !task_runtime.publish_proc_flag(pid, arinsal_sched::proc_flags::PORTS) {
                        handle.links.lock().unwrap().remove(&pid);
                    } else {
                        trace_link(&task_runtime, handle.id, pid, "getting_linked");
                    }
                } else if let (Some(port), Ok(reason)) =
                    (Term::port(handle.id), Message::copy_from(atom("noproc")))
                    && let Ok(port) = Message::copy_from(port)
                {
                    let _ = handle.scheduler.signal(
                        pid,
                        pid,
                        arinsal_sched::Signal::PortExit { port, reason },
                    );
                }
                REDS_LINK
            } else {
                // Port of erts/emulator/beam/io.c:2507 (port_sig_unlink), OTP-29.1.1.
                if live {
                    handle.links.lock().unwrap().remove(&pid);
                    trace_link(&task_runtime, handle.id, pid, "getting_unlinked");
                }
                REDS_UNLINK
            }
        },
    )
    .is_ok()
}

/// Port of erts/emulator/beam/io.c:2850 (`erts_port_demonitor`) and :2836
/// (`port_sig_demonitor`), OTP-29.1.1. The origin monitor is already gone; this
/// deletes the target half on the port, or drops it when the signal is aborted.
pub(crate) fn demonitor(
    handle: &Arc<PortHandle>,
    drv: &Arc<DriverPort>,
    caller: Pid,
    reference: u64,
) {
    let task_handle = Arc::clone(handle);
    let _ = imm_or_schedule(drv, caller, true, "demonitor", move |op| {
        if op == SigOp::Exec {
            task_handle.monitors.lock().unwrap().remove(&reference);
        }
        REDS_DEMONITOR
    });
}

/// `trace_port(prt, am_getting_linked | am_getting_unlinked, Pid, F_TRACE_PORTS)`.
fn trace_link(runtime: &crate::process::Runtime, id: u64, pid: Pid, what: &str) {
    if let Some(pid_term) = pid.to_term() {
        crate::trace::emit_port_event(runtime, id, crate::trace::PORTS, what, &[pid_term]);
    }
}
