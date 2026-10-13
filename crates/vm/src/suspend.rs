//! The suspend protocol (erts erl_process.c:9013-9200, 7235-7330, 9369-9413, and the suspend
//! cases of erl_proc_sig_queue.c handle_suspend and the monitor-down path).
//!
//! A suspend by one process of another is a suspend monitor: the suspender holds the counter, the
//! suspendee holds the ACTIVE bit, both in one shared object (erts `ErtsMonitorSuspend`). The
//! suspendee counts its active suspends (erts `p->rcount`), and its `SUSPENDED` state bit is the
//! source of truth for "suspended", as erts' `ERTS_PSFLG_SUSPENDED` is.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use arinsal_sched::{Pid, RunCtx, SharedPayload, Signal, proc_flags};

use arinsal_term::Term;

use crate::process::{Message, Runtime};
use crate::{Process, VmError};

/// One suspend monitor, shared by its suspender (counter) and suspendee (ACTIVE).
pub(crate) struct SuspendMonitor {
    state: AtomicU64,
}

/// Set by the suspendee once it applied the suspends (`ERTS_MSUSPEND_STATE_FLG_ACTIVE`).
const ACTIVE: u64 = 1 << 32;
const COUNT_MASK: u64 = ACTIVE - 1;

impl SuspendMonitor {
    /// A new monitor with no suspends counted yet.
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            state: AtomicU64::new(0),
        })
    }

    /// The suspender's number of outstanding suspends.
    pub(crate) fn count(&self) -> u32 {
        (self.state.load(Ordering::Acquire) & COUNT_MASK) as u32
    }

    /// Whether the suspendee has applied the suspends.
    pub(crate) fn active(&self) -> bool {
        self.state.load(Ordering::Acquire) & ACTIVE != 0
    }

    /// Counts one more suspend; returns the new count.
    fn add(&self) -> u32 {
        (self.state.fetch_add(1, Ordering::AcqRel) + 1) as u32
    }

    /// Drops one suspend; returns the new count.
    fn sub(&self) -> u32 {
        (self.state.fetch_sub(1, Ordering::AcqRel) - 1) as u32
    }

    fn set_active(&self, on: bool) {
        if on {
            self.state.fetch_or(ACTIVE, Ordering::AcqRel);
        } else {
            self.state.fetch_and(!ACTIVE, Ordering::AcqRel);
        }
    }
}

/// Sets or clears the `SUSPENDED` state bit of `pid` (erts `ERTS_PSFLG_SUSPENDED`), written only by
/// the suspendee itself.
fn mirror_bit(runtime: &Runtime, pid: Pid, on: bool) {
    if let Ok(scheduler) = runtime.scheduler() {
        scheduler.with_proc_flags(pid, |flags| {
            if on {
                proc_flags::set_state(flags, proc_flags::SUSPENDED);
            } else {
                proc_flags::clear_state(flags, proc_flags::SUSPENDED);
            }
        });
    }
}

/// Whether `pid` is suspended, read from its state bit (cross-thread safe).
pub(crate) fn suspended_bit(runtime: &Runtime, pid: Pid) -> bool {
    runtime
        .scheduler()
        .ok()
        .and_then(|scheduler| {
            scheduler.with_proc_flags(pid, |flags| {
                flags.load(Ordering::Acquire) & proc_flags::SUSPENDED != 0
            })
        })
        .unwrap_or(false)
}

/// An ordered signal from the running process `me`, without a turn context (erts sends these
/// from `c_p`).
fn send_signal(
    process: &Process,
    me: Pid,
    to: Pid,
    signal: Signal<Message>,
) -> Result<(), arinsal_sched::Error> {
    let scheduler = process
        .runtime
        .as_ref()
        .ok_or(arinsal_sched::Error::NoProcess)?
        .scheduler()
        .map_err(|_| arinsal_sched::Error::NoProcess)?;
    scheduler.signal_ordered(me, to, signal)
}

/// What `erts_internal_suspend_process_2` decided (erl_process.c:9013-9163).
pub(crate) struct SuspendOutcome {
    /// The suspend count of this process changed (`res` is `true`).
    pub(crate) changed: bool,
    /// The caller waits for a `{Ref, Res}` reply (`sync`).
    pub(crate) sync: bool,
    /// The target is gone: the monitor was dropped again.
    pub(crate) noproc: bool,
}

/// `erts_internal_suspend_process_2` (erl_process.c:9013) for a remote target. `Err` is a full
/// counter. A target that is not running, not exiting and has no pending signals is suspended
/// directly under its main lock (`erts_try_lock_sig_free_proc`, `suspend_process`); any other
/// gets the suspend signal.
pub(crate) fn suspend_remote(
    process: &mut Process,
    origin: Pid,
    target: Pid,
    unless_suspending: bool,
    asynchronous: bool,
) -> Result<SuspendOutcome, ()> {
    if let Some(monitor) = process
        .cold
        .as_ref()
        .and_then(|cold| cold.suspend_monitors.get(&target))
    {
        let changed = if unless_suspending {
            false
        } else {
            if monitor.count() as u64 >= COUNT_MASK {
                return Err(());
            }
            monitor.add();
            true
        };
        return Ok(SuspendOutcome {
            changed,
            sync: !asynchronous && !monitor.active(),
            noproc: false,
        });
    }
    let monitor = SuspendMonitor::new();
    monitor.add();
    process
        .cold_mut()
        .suspend_monitors
        .insert(target, Arc::clone(&monitor));
    let direct = process
        .runtime
        .as_ref()
        .and_then(|runtime| runtime.scheduler().ok())
        .map(|scheduler| {
            scheduler.modify_signal_free(target, |rp| {
                activate(rp, target, origin, SharedPayload(Arc::clone(&monitor) as _));
            })
        });
    let (signalled, noproc) = match direct {
        Some(Ok(())) => (false, false),
        Some(Err(arinsal_sched::SignalFreeError::NoProcess)) => (false, true),
        _ => {
            let sent = send_signal(
                process,
                origin,
                target,
                Signal::Suspend {
                    shared: SharedPayload(monitor),
                },
            );
            (sent.is_ok(), sent.is_err())
        }
    };
    if noproc {
        process.cold_mut().suspend_monitors.remove(&target);
    }
    Ok(SuspendOutcome {
        changed: true,
        sync: signalled && !asynchronous,
        noproc,
    })
}

/// `erts_proc_sig_send_sync_suspend` (erl_proc_sig_queue.c:3192): queues the reply request behind
/// the suspend. A target that is gone is answered here, on the requester itself.
pub(crate) fn send_sync_suspend(
    process: &mut Process,
    me: Pid,
    target: Pid,
    tag: Term,
    reply: Term,
    asynchronous: bool,
) -> Result<(), VmError> {
    let signal = Signal::SyncSuspend {
        requester: me,
        tag: Message::copy_from(tag)?,
        reply: reply.as_atom().map_or(0, |atom| atom.0),
        async_: asynchronous,
    };
    if send_signal(process, me, target, signal).is_err() {
        let gone = crate::signals::atom(if asynchronous { "badarg" } else { "exited" });
        let message = process.tuple(&[tag, gone])?;
        // Not a traced `!`: the reply is queued without a send trace (erl_proc_sig_queue.c:3237).
        process.inbox.push_back(message);
    }
    Ok(())
}

/// `sync_suspend_reply` (erl_proc_sig_queue.c:5480): the target answers with its state at the
/// time it handles the request.
pub(crate) fn sync_reply(
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    requester: Pid,
    tag: Message,
    reply: u32,
    asynchronous: bool,
    exiting: bool,
) -> Result<(), VmError> {
    let state = ctx.exit_flags().load(Ordering::Acquire);
    let atom = if exiting || state & proc_flags::EXITING != 0 {
        Some(if asynchronous { "exited" } else { "badarg" })
    } else if state & proc_flags::SUSPENDED == 0 {
        Some(if asynchronous {
            "not_suspended"
        } else {
            "internal_error"
        })
    } else {
        None
    };
    let result = match atom {
        Some(name) => crate::signals::atom(name),
        None => Term::atom(arinsal_term::Atom(reply)),
    };
    let tag = tag.into_receiver(process)?;
    let tuple = process.tuple(&[tag, result])?;
    let message = Message::copy_from(tuple)?;
    let _ = ctx.send(requester, message);
    Ok(())
}

/// `resume_process_1` (erl_process.c:9181): drops one suspend of `target` this process holds.
/// `None` when this process holds none.
pub(crate) fn resume_remote(process: &mut Process, me: Pid, target: Pid) -> Option<()> {
    let monitor = process
        .cold
        .as_ref()?
        .suspend_monitors
        .get(&target)?
        .clone();
    if monitor.sub() == 0 {
        process.cold_mut().suspend_monitors.remove(&target);
        let _ = send_signal(
            process,
            me,
            target,
            Signal::SuspendRelease {
                shared: SharedPayload(monitor),
            },
        );
    }
    Some(())
}

/// Exit of a suspender (erl_process.c:13894): every suspend it holds is released at its target.
pub(crate) fn release_on_exit(process: &mut Process, ctx: &mut RunCtx<'_, Message>) {
    let monitors = process
        .cold
        .as_mut()
        .map(|cold| std::mem::take(&mut cold.suspend_monitors))
        .unwrap_or_default();
    for (target, monitor) in monitors {
        let _ = ctx.signal(
            target,
            Signal::SuspendRelease {
                shared: SharedPayload(monitor),
            },
        );
    }
}

/// Exit of a suspendee (erl_process.c:13809): every suspender drops its half of the monitor.
pub(crate) fn down_on_exit(process: &mut Process, ctx: &mut RunCtx<'_, Message>) {
    let monitors = process
        .cold
        .as_mut()
        .map(|cold| std::mem::take(&mut cold.suspended_by))
        .unwrap_or_default();
    for (origin, monitor) in monitors {
        monitor.set_active(false);
        let _ = ctx.signal(
            origin,
            Signal::SuspendDown {
                shared: SharedPayload(monitor),
            },
        );
    }
}

/// The suspendee `target` exited: this suspender forgets the monitor, so a later
/// `resume_process/1` is `badarg` (erl_proc_sig_queue.c handle_monitor_down).
pub(crate) fn suspendee_down(process: &mut Process, target: Pid, shared: SharedPayload) {
    let Ok(monitor) = shared.0.downcast::<SuspendMonitor>() else {
        return;
    };
    if let Some(cold) = process.cold.as_mut()
        && cold
            .suspend_monitors
            .get(&target)
            .is_some_and(|stored| Arc::ptr_eq(stored, &monitor))
    {
        cold.suspend_monitors.remove(&target);
    }
}

/// `process_info(P, suspending)` rows `{Suspendee, Active, Outstanding}` for this process
/// (erl_bif_info.c:727): an applied suspend is active, one not yet applied is outstanding.
pub(crate) fn suspending_of(process: &Process) -> Vec<(Pid, u32, u32)> {
    let Some(cold) = process.cold.as_ref() else {
        return Vec::new();
    };
    cold.suspend_monitors
        .iter()
        .map(|(&target, monitor)| {
            let count = monitor.count();
            if monitor.active() {
                (target, count, 0)
            } else {
                (target, 0, count)
            }
        })
        .collect()
}

/// Applies a suspend monitor on this process (erl_proc_sig_queue.c handle_suspend, erl_process.c:9140
/// activate_suspend_monitor): the process counts one more active suspend, and its timers pause.
pub(crate) fn activate(process: &mut Process, pid: Pid, origin: Pid, shared: SharedPayload) {
    let Ok(monitor) = shared.0.downcast::<SuspendMonitor>() else {
        return;
    };
    monitor.set_active(true);
    let cold = process.cold_mut();
    cold.suspended_by.insert(origin, monitor);
    cold.suspend_count += 1;
    let first = cold.suspend_count == 1;
    let runtime = process.runtime.clone();
    if let Some(runtime) = runtime {
        if first {
            mirror_bit(&runtime, pid, true);
        }
        runtime.erts_pause_proc_timer(process, pid);
    }
}

/// Releases a suspend monitor on this process (erl_proc_sig_queue.c:6609): its ACTIVE bit clears and
/// the count drops; the last release clears `SUSPENDED` and resumes the timers.
pub(crate) fn release(process: &mut Process, pid: Pid, origin: Pid, shared: SharedPayload) {
    let Ok(monitor) = shared.0.downcast::<SuspendMonitor>() else {
        return;
    };
    let cold = process.cold_mut();
    let Some(stored) = cold.suspended_by.get(&origin) else {
        return;
    };
    if !Arc::ptr_eq(stored, &monitor) {
        return;
    }
    cold.suspended_by.remove(&origin);
    monitor.set_active(false);
    cold.suspend_count = cold.suspend_count.saturating_sub(1);
    let last = cold.suspend_count == 0;
    let runtime = process.runtime.clone();
    if let Some(runtime) = runtime {
        if last {
            mirror_bit(&runtime, pid, false);
        }
        runtime.erts_resume_proc_timer(process, pid);
    }
}

/// Runtime-internal suspend of the calling process (erl_process.c:9369, erts_suspend): one suspend
/// it takes on itself, undone by [`resume_self`] or by [`Runtime::resume_internal`].
pub(crate) fn suspend_self(process: &mut Process) {
    let cold = process.cold_mut();
    cold.suspend_count += 1;
    let first = cold.suspend_count == 1;
    if let (Some(runtime), Some(pid), true) = (process.runtime.clone(), process.self_pid, first) {
        mirror_bit(&runtime, pid, true);
    }
}

/// [`suspend_self`] as a condition: always true, so it can sit in an `&&` chain.
pub(crate) fn suspend_self_true(process: &mut Process) -> bool {
    suspend_self(process);
    true
}

/// Undoes one [`suspend_self`] of the calling process (erl_process.c:9402, erts_resume).
pub(crate) fn resume_self(process: &mut Process) {
    let Some(cold) = process.cold.as_mut() else {
        return;
    };
    if cold.suspend_count == 0 {
        return;
    }
    cold.suspend_count -= 1;
    if let (0, Some(runtime), Some(pid)) = (
        cold.suspend_count,
        process.runtime.clone(),
        process.self_pid,
    ) {
        mirror_bit(&runtime, pid, false);
    }
}

impl Runtime {
    /// Internal resume of `pid` from any thread: a signal the process applies itself, so the count
    /// is only ever changed by its own thread (erts_resume_processes takes the process lock).
    pub(crate) fn resume_internal(&self, pid: Pid) -> bool {
        self.scheduler()
            .is_ok_and(|scheduler| scheduler.signal(pid, pid, Signal::SuspendResume).is_ok())
    }

    /// Internal suspend of `pid` from another thread: the receiver takes the suspend when it
    /// handles the signal, as erts applies a suspend signal to a busy process.
    pub(crate) fn suspend_internal_remote(&self, pid: Pid) -> bool {
        self.scheduler()
            .is_ok_and(|scheduler| scheduler.signal(pid, pid, Signal::SuspendInternal).is_ok())
    }

    /// Whether `pid` is suspended (its state bit).
    pub(crate) fn suspend_active(&self, pid: Pid) -> bool {
        suspended_bit(self, pid)
    }

    /// `1` while `pid` is suspended and `0` otherwise: callers test for zero, as erts tests the
    /// state bit (`ERTS_PSFLG_SUSPENDED`); the count itself lives on the suspended process.
    pub(crate) fn suspend_total_of(&self, pid: Pid) -> u32 {
        u32::from(suspended_bit(self, pid))
    }
}
