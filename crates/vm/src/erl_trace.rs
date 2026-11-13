//! The system message dispatcher.
//!
//! Port of erts/emulator/beam/erl_trace.c (`enqueue_sys_msg`, `sys_msg_dispatcher_func`,
//! `sys_msg_disp_failure`, `erts_queue_error_logger_message`), OTP-29.1.1. Producers queue
//! system messages (`system_monitor`, `system_profile` and logger events); one dispatcher
//! thread delivers them in order. `SYS_MSG_TYPE_PROC_MSG` is sent by `erts_send_sys_msg_proc`.

use crate::Process;
use crate::natives::sys::{print_otp_term, reset_system_logger};
use crate::process::{Message, Runtime};
use arinsal_etf::OwnedTerm;
use arinsal_sched::{Pid, Scheduler};
use arinsal_term::{Term, atoms, to_owned};
use std::collections::VecDeque;
use std::sync::{Arc, Condvar, Mutex, OnceLock};

/// `SYS_MSG_TYPE_*`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum SysMsgType {
    ProcMsg,
    Sysmon,
    Sysprof,
    Errlgr,
}

/// `ErtsSysMsgQ`: `to` is the receiver chosen at enqueue time (a pid, or for logger events the
/// system logger destination), `msg` the term in its own heap fragment.
struct SysMsgQ {
    ty: SysMsgType,
    from: Option<Pid>,
    to: Term,
    msg: Message,
}

struct NodeHandle {
    scheduler: Arc<Scheduler<Process>>,
    runtime: &'static Runtime,
}

// `smq_mtx`, `smq_cnd` and `sys_message_queue`.
struct SysMessageQueue {
    queue: Mutex<VecDeque<SysMsgQ>>,
    cnd: Condvar,
    node: OnceLock<NodeHandle>,
}

/// Port of erl_trace.c `init_sys_msg_dispatcher`, called from `erts_init_trace` at node start.
/// The queue and its thread are process-wide, as in erts.
pub(crate) fn init_sys_msg_dispatcher() {
    sys_message_queue();
}

fn sys_message_queue() -> &'static SysMessageQueue {
    static SMQ: OnceLock<&'static SysMessageQueue> = OnceLock::new();
    SMQ.get_or_init(|| {
        let smq: &'static SysMessageQueue = Box::leak(Box::new(SysMessageQueue {
            queue: Mutex::new(VecDeque::new()),
            cnd: Condvar::new(),
            node: OnceLock::new(),
        }));
        std::thread::Builder::new()
            .name("system message dispatcher".into())
            .spawn(move || sys_msg_dispatcher_func(smq))
            .expect("system message dispatcher thread");
        smq
    })
}

/// Install the single node's handles once its scheduler has been created.
pub(crate) fn set_node(runtime: &'static Runtime) {
    let Some(scheduler) = runtime.scheduler_if_started().cloned() else {
        return;
    };
    let _ = sys_message_queue()
        .node
        .set(NodeHandle { scheduler, runtime });
    sys_message_queue().cnd.notify_one();
}

/// Port of erl_trace.c `enqueue_sys_msg`: append to the queue and wake the dispatcher.
pub(crate) fn enqueue_sys_msg(ty: SysMsgType, from: Option<Pid>, to: Term, msg: Message) {
    let smq = sys_message_queue();
    smq.queue
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
        .push_back(SysMsgQ { ty, from, to, msg });
    smq.cnd.notify_one();
}

/// Port of erl_trace.c `erts_send_sys_msg_proc`: `SYS_MSG_TYPE_PROC_MSG` to a pid, delivered by
/// the dispatcher thread.
pub(crate) fn send_sys_msg_proc(from: Pid, to: Pid, msg: Message) {
    let Some(to) = to.to_term() else {
        return;
    };
    enqueue_sys_msg(SysMsgType::ProcMsg, Some(from), to, msg);
}

/// Port of erl_trace.c `erts_queue_error_logger_message`: queued to the system logger
/// destination read now.
pub(crate) fn queue_error_logger_message(
    runtime: &'static Runtime,
    from: Option<Pid>,
    msg: Message,
) {
    enqueue_sys_msg(
        SysMsgType::Errlgr,
        from,
        crate::natives::sys::runtime_system_logger(runtime),
        msg,
    );
}

fn sys_msg_dispatcher_func(smq: &'static SysMessageQueue) {
    loop {
        let batch = {
            let mut queue = smq
                .queue
                .lock()
                .unwrap_or_else(|poison| poison.into_inner());
            while queue.is_empty() || smq.node.get().is_none() {
                queue = smq
                    .cnd
                    .wait(queue)
                    .unwrap_or_else(|poison| poison.into_inner());
            }
            std::mem::take(&mut *queue)
        };
        for smqp in batch {
            dispatch(smqp, smq.node.get().expect("node set before dispatch"));
        }
    }
}

// The per-message body of `sys_msg_dispatcher_func`.
fn dispatch(smqp: SysMsgQ, node: &NodeHandle) {
    let mut receiver = smqp.to;
    // SYSMON and SYSPROF: `smqp->from == receiver` drops the message.
    if matches!(smqp.ty, SysMsgType::Sysmon | SysMsgType::Sysprof)
        && smqp.from.is_some()
        && smqp.from == Pid::from_term(receiver)
    {
        return;
    }
    if let Some(pid) = Pid::from_term(receiver) {
        if node.scheduler.lookup(pid) {
            let _ = node.scheduler.send(smqp.from.unwrap_or(pid), pid, smqp.msg);
            return;
        }
        if smqp.ty != SysMsgType::Errlgr {
            return disp_failure(&smqp, receiver, node);
        }
        // Bad logger process: reset to the kernel `logger` process and retry.
        reset_system_logger(node.runtime);
        receiver = Term::atom(atoms::LOGGER);
    }
    if receiver == Term::atom(atoms::LOGGER) {
        let Some(logger) = node.runtime.reg.whereis_proc_str("logger") else {
            return disp_failure(&smqp, receiver, node);
        };
        if smqp.from == Some(logger) {
            return;
        }
        let _ = node
            .scheduler
            .send(smqp.from.unwrap_or(logger), logger, smqp.msg);
    } else if receiver == Term::atom(atoms::UNDEFINED) {
        // dropped
    } else {
        disp_failure(&smqp, receiver, node);
    }
}

// Port of erl_trace.c `sys_msg_disp_failure`.
fn disp_failure(smqp: &SysMsgQ, receiver: Term, node: &NodeHandle) {
    match smqp.ty {
        // sys_msg_disp_failure has no PROC_MSG case: a dead receiver drops the message.
        SysMsgType::ProcMsg => {}
        SysMsgType::Sysmon => {
            if let Some(pid) = Pid::from_term(receiver) {
                crate::natives::erts_debug::system_monitor_clear_receiver(node.runtime, pid);
            }
        }
        SysMsgType::Sysprof => crate::natives::misc::system_profile_clear(),
        SysMsgType::Errlgr => {
            // erts_fprintf(stderr, ...) of an erl node ends the line with CR LF.
            const NO_LOGGER: &str = "(no logger present)";
            let Ok(msg) = to_owned(smqp.msg.term()) else {
                return;
            };
            let tag_and_args = (|| {
                let OwnedTerm::Tuple(outer) = &msg else {
                    return None;
                };
                if outer.len() != 2 {
                    return None;
                }
                let OwnedTerm::Tuple(inner) = &outer[1] else {
                    return None;
                };
                if inner.len() != 3 {
                    return None;
                }
                let OwnedTerm::Tuple(third) = &inner[2] else {
                    return None;
                };
                if third.len() != 3 {
                    return None;
                }
                let OwnedTerm::List { elems, .. } = &third[2] else {
                    return None;
                };
                Some((inner[0].clone(), elems.first()?.clone()))
            })();
            match tag_and_args {
                Some((tag, first)) => eprint!(
                    "{NO_LOGGER} {}: {}\r\n",
                    print_otp_term(&tag, usize::MAX),
                    print_otp_term(&first, usize::MAX)
                ),
                None => eprint!(
                    "{NO_LOGGER} unexpected logger message: {}\r\n",
                    print_otp_term(&msg, usize::MAX)
                ),
            }
        }
    }
}
