//! Introspection natives implemented by the emulator debug modules.

use crate::process::Message;
use crate::{Process, Vm, VmError, exceptions};
use arinsal_etf::OwnedTerm;
use arinsal_sched::{DirtyKind, Pid, RunCtx, SchedulerType};
use arinsal_term::{
    ProcessHeap, Term, TermBuilder, TermKind, copy_term, from_owned, global_atoms,
    hashmap_node_children, term_sequence, to_owned,
};
use num_bigint::BigInt;
use num_traits::ToPrimitive;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

static INTERNAL_STATE: AtomicBool = AtomicBool::new(false);

pub(crate) fn internal_state_enabled() -> bool {
    INTERNAL_STATE.load(Ordering::Relaxed)
}
static DEBUGGER_SUPPORT: AtomicBool = AtomicBool::new(false);
static JIT_ASM_DUMP: AtomicBool = AtomicBool::new(false);
static TEST_LONG_GC_SLEEP: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static UNIQUE_MONOTONIC_INTEGER_STATE: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(u64::MAX);
static BINARY_LOOP_LIMIT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static RE_LOOP_LIMIT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(64_000);
static UNICODE_LOOP_LIMIT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(40_000);
const MONITOR_LARGE_HEAP: u8 = 1;
const MONITOR_LONG_GC: u8 = 2;
const MONITOR_LONG_SCHEDULE: u8 = 4;
const MONITOR_LONG_MESSAGE_QUEUE: u8 = 8;
const MONITOR_BUSY_PORT: u8 = 16;
const MONITOR_BUSY_DIST_PORT: u8 = 32;

#[derive(Clone)]
pub(crate) struct SystemMonitorState {
    pub(crate) receiver: OwnedTerm,
    pub(crate) options: HashMap<&'static str, MonitorOption>,
}

#[derive(Clone)]
pub(crate) enum MonitorOption {
    Bool(bool),
    Limit(u64),
    Queue(u64, u64),
}

/// An exiting system monitor process stops being the monitor.
// Port of erts/emulator/beam/erl_process.c:14397-14400 (erts_continue_exit_process:
// erts_system_monitor_clear), OTP-29.1.1.
pub(crate) fn monitor_process_exited(process: &Process, pid: arinsal_sched::Pid) {
    let Some(runtime) = process.runtime.as_ref() else {
        return;
    };
    let Some(owned) = pid.to_term().and_then(|term| to_owned(term).ok()) else {
        return;
    };
    let mut changed = false;
    {
        let mut state = runtime.system_monitor.lock().unwrap();
        if state.as_ref().is_some_and(|state| state.receiver == owned) {
            *state = None;
            changed = true;
        }
    }
    {
        let mut sessions = runtime.session_monitors.lock().unwrap();
        let before = sessions.len();
        sessions.retain(|(_, state)| state.receiver != owned);
        changed |= sessions.len() != before;
    }
    if changed {
        runtime.long_message_queues.lock().unwrap().clear();
        refresh_system_monitor_flags(runtime);
    }
}

/// A destroyed trace session no longer has a system monitor.
// Port of erts/emulator/beam/erl_trace.c (erts_trace_session_destroy clears the session's
// system_monitor), OTP-29.1.1.
pub(crate) fn session_destroyed(process: &Process, session: Term) {
    let (Some(runtime), Ok(key)) = (process.runtime.as_ref(), to_owned(session)) else {
        return;
    };
    runtime
        .session_monitors
        .lock()
        .unwrap()
        .retain(|(owner, _)| *owner != key);
    runtime.long_message_queues.lock().unwrap().clear();
    refresh_system_monitor_flags(runtime);
}

/// Every active monitor: the legacy one and those of dynamic sessions.
fn monitor_states(runtime: &crate::process::Runtime) -> Vec<SystemMonitorState> {
    let mut states: Vec<_> = runtime
        .system_monitor
        .lock()
        .unwrap()
        .iter()
        .cloned()
        .collect();
    states.extend(
        runtime
            .session_monitors
            .lock()
            .unwrap()
            .iter()
            .map(|(_, state)| state.clone()),
    );
    states
}

fn refresh_system_monitor_flags(runtime: &crate::process::Runtime) {
    let mut flags = 0;
    for state in &monitor_states(runtime) {
        if matches!(
            state.options.get("large_heap"),
            Some(MonitorOption::Limit(_))
        ) {
            flags |= MONITOR_LARGE_HEAP;
        }
        if matches!(state.options.get("long_gc"), Some(MonitorOption::Limit(_))) {
            flags |= MONITOR_LONG_GC;
        }
        if matches!(
            state.options.get("long_schedule"),
            Some(MonitorOption::Limit(_))
        ) {
            flags |= MONITOR_LONG_SCHEDULE;
        }
        if matches!(
            state.options.get("long_message_queue"),
            Some(MonitorOption::Queue(_, _))
        ) {
            flags |= MONITOR_LONG_MESSAGE_QUEUE;
        }
        if matches!(
            state.options.get("busy_port"),
            Some(MonitorOption::Bool(true))
        ) {
            flags |= MONITOR_BUSY_PORT;
        }
        if matches!(
            state.options.get("busy_dist_port"),
            Some(MonitorOption::Bool(true))
        ) {
            flags |= MONITOR_BUSY_DIST_PORT;
        }
    }
    runtime.system_monitor_flags.store(flags, Ordering::Relaxed);
}

/// Emit the monitor events that are observable from the VM's collection hook.
// Port of erts/emulator/beam/erl_gc.c:904-920 and erl_trace.c:1604-1741, OTP-29.1.1.
pub(crate) fn after_collection(process: &mut Process, elapsed_nanoseconds: u64) {
    if let Some(runtime) = process.runtime.clone() {
        for state in monitor_states(&runtime) {
            after_collection_one(process, elapsed_nanoseconds, &state);
        }
    }
}

fn after_collection_one(
    process: &mut Process,
    elapsed_nanoseconds: u64,
    state: &SystemMonitorState,
) {
    let Some(runtime) = process.runtime.clone() else {
        return;
    };
    let flags = runtime.system_monitor_flags.load(Ordering::Relaxed);
    if flags == 0 {
        return;
    }
    let Some(pid) = runtime
        .processes
        .lock()
        .unwrap()
        .iter()
        .copied()
        .find(|pid| {
            pid.to_term()
                .is_some_and(|term| term.tagged_word() == process.header.self_pid)
        })
    else {
        return;
    };
    let OwnedTerm::Pid {
        node,
        id: receiver_id,
        serial: receiver_generation,
        creation: 0,
    } = &state.receiver
    else {
        return;
    };
    if node != "nonode@nohost" {
        return;
    }
    let receiver = arinsal_sched::Pid::new(*receiver_id, *receiver_generation);
    let heap_words = process.heap.capacity_words();
    let total_heap_words = process.heap.total_heap_size_words();
    let heap_used = process.heap.used_words();
    let mut events = Vec::new();
    if flags & MONITOR_LARGE_HEAP != 0
        && let Some(MonitorOption::Limit(limit)) = state.options.get("large_heap")
        && total_heap_words as u64 >= *limit
    {
        events.push((
            "large_heap",
            vec![
                ("old_heap_block_size", 0),
                ("heap_block_size", heap_words),
                ("mbuf_size", 0),
                ("stack_size", 0),
                ("old_heap_size", process.heap.old_used_words()),
                ("heap_size", heap_used),
            ],
        ));
    }
    if flags & MONITOR_LONG_GC != 0 {
        let delay = TEST_LONG_GC_SLEEP.load(Ordering::Relaxed);
        if delay != 0 {
            std::thread::sleep(std::time::Duration::from_millis(delay));
        }
    }
    let elapsed_ms = elapsed_nanoseconds / 1_000_000
        + if flags & MONITOR_LONG_GC != 0 {
            TEST_LONG_GC_SLEEP.load(Ordering::Relaxed)
        } else {
            0
        };
    if flags & MONITOR_LONG_GC != 0
        && elapsed_ms > 0
        && let Some(MonitorOption::Limit(limit)) = state.options.get("long_gc")
        && elapsed_ms > *limit
    {
        events.push((
            "long_gc",
            vec![
                ("timeout", elapsed_ms as usize),
                ("old_heap_block_size", 0),
                ("heap_block_size", heap_words),
                ("mbuf_size", 0),
                ("stack_size", 0),
                ("old_heap_size", process.heap.old_used_words()),
                ("heap_size", heap_used),
            ],
        ));
    }
    for (kind, values) in events {
        send_system_monitor_event(process, &runtime, pid, receiver, kind, values);
    }
}

fn send_system_monitor_event(
    process: &mut Process,
    runtime: &crate::process::Runtime,
    pid: arinsal_sched::Pid,
    receiver: arinsal_sched::Pid,
    kind: &str,
    values: Vec<(&str, usize)>,
) {
    // Port of erts/emulator/beam/erl_trace.c:2756-2765 (sys_msg_dispatcher_func): the monitor
    // is never told about its own events.
    if pid == receiver {
        return;
    }
    let Ok(scheduler) = runtime.scheduler() else {
        return;
    };
    let fields = values
        .into_iter()
        .map(|(name, value)| {
            OwnedTerm::tuple(vec![OwnedTerm::atom(name), OwnedTerm::Int(value as i64)])
        })
        .collect();
    let event = OwnedTerm::Tuple(vec![
        OwnedTerm::atom("monitor"),
        OwnedTerm::Pid {
            node: "nonode@nohost".into(),
            id: pid.number(),
            serial: pid.serial(),
            creation: 0,
        },
        OwnedTerm::atom(kind),
        OwnedTerm::list(fields),
    ]);
    if let Ok(term) = from_owned(
        &event,
        &mut arinsal_bifs::FragmentingHeap(&mut process.heap),
    ) && let Ok(message) = Message::copy_from(term)
    {
        let _ = scheduler.send(pid, receiver, message);
    }
}

/// Emit long-schedule events after a scheduler execution slice.
// Port of erts/emulator/beam/erl_trace.c:1510-1595, OTP-29.1.1.
pub(crate) fn after_schedule(process: &mut Process, elapsed_nanoseconds: u64) {
    if let Some(runtime) = process.runtime.clone() {
        for state in monitor_states(&runtime) {
            after_schedule_one(process, elapsed_nanoseconds, &state);
        }
    }
}

fn after_schedule_one(process: &mut Process, elapsed_nanoseconds: u64, state: &SystemMonitorState) {
    let Some(runtime) = process.runtime.clone() else {
        return;
    };
    let flags = runtime.system_monitor_flags.load(Ordering::Relaxed);
    if flags & MONITOR_LONG_SCHEDULE == 0 {
        return;
    }
    let Some(pid) = runtime
        .processes
        .lock()
        .unwrap()
        .iter()
        .copied()
        .find(|pid| {
            pid.to_term()
                .is_some_and(|term| term.tagged_word() == process.header.self_pid)
        })
    else {
        return;
    };
    let Some(MonitorOption::Limit(limit)) = state.options.get("long_schedule") else {
        return;
    };
    let elapsed_ms = elapsed_nanoseconds / 1_000_000;
    if elapsed_ms <= *limit {
        return;
    }
    let OwnedTerm::Pid {
        node,
        id: receiver_id,
        serial: receiver_generation,
        creation: 0,
    } = &state.receiver
    else {
        return;
    };
    if node != "nonode@nohost" {
        return;
    }
    let receiver = arinsal_sched::Pid::new(*receiver_id, *receiver_generation);
    let fields = OwnedTerm::list(vec![
        OwnedTerm::tuple(vec![
            OwnedTerm::atom("timeout"),
            OwnedTerm::Int(elapsed_ms as i64),
        ]),
        OwnedTerm::tuple(vec![OwnedTerm::atom("in"), OwnedTerm::atom("undefined")]),
        OwnedTerm::tuple(vec![OwnedTerm::atom("out"), OwnedTerm::atom("undefined")]),
    ]);
    let event = OwnedTerm::Tuple(vec![
        OwnedTerm::atom("monitor"),
        OwnedTerm::Pid {
            node: "nonode@nohost".into(),
            id: pid.number(),
            serial: pid.serial(),
            creation: 0,
        },
        OwnedTerm::atom("long_schedule"),
        fields,
    ]);
    if let Ok(term) = from_owned(
        &event,
        &mut arinsal_bifs::FragmentingHeap(&mut process.heap),
    ) && let Ok(message) = Message::copy_from(term)
        && let Ok(scheduler) = runtime.scheduler()
    {
        let _ = scheduler.send(pid, receiver, message);
    }
}

/// Emit a long-schedule event for a port task that ran longer than the monitor limit.
// Port of erts/emulator/beam/erl_trace.c:1591 (monitor_long_schedule_port), OTP-29.1.1.
pub(crate) fn after_port_task(
    runtime: &crate::process::Runtime,
    port: Term,
    from: arinsal_sched::Pid,
    operation: &str,
    elapsed_nanoseconds: u64,
) {
    if runtime.system_monitor_flags.load(Ordering::Relaxed) & MONITOR_LONG_SCHEDULE == 0 {
        return;
    }
    let (Ok(port), Ok(scheduler)) = (to_owned(port), runtime.scheduler()) else {
        return;
    };
    for state in monitor_states(runtime) {
        let Some(MonitorOption::Limit(limit)) = state.options.get("long_schedule") else {
            continue;
        };
        let elapsed_ms = elapsed_nanoseconds / 1_000_000;
        if elapsed_ms <= *limit {
            continue;
        }
        let OwnedTerm::Pid {
            node,
            id: receiver_id,
            serial: receiver_generation,
            creation: 0,
        } = &state.receiver
        else {
            continue;
        };
        if node != "nonode@nohost" {
            continue;
        }
        let receiver = arinsal_sched::Pid::new(*receiver_id, *receiver_generation);
        let event = OwnedTerm::Tuple(vec![
            OwnedTerm::atom("monitor"),
            port.clone(),
            OwnedTerm::atom("long_schedule"),
            OwnedTerm::list(vec![
                OwnedTerm::tuple(vec![
                    OwnedTerm::atom("timeout"),
                    OwnedTerm::Int(elapsed_ms as i64),
                ]),
                OwnedTerm::tuple(vec![OwnedTerm::atom("port_op"), OwnedTerm::atom(operation)]),
            ]),
        ]);
        let mut heap = ProcessHeap::with_words(64);
        if let Ok(term) = from_owned(&event, &mut heap)
            && let Ok(message) = Message::copy_from(term)
        {
            let _ = scheduler.send(from, receiver, message);
        }
    }
}

/// Emit long-message-queue events when the mailbox crosses its configured limits.
// Port of erts/emulator/beam/erl_trace.c:1863-1918, OTP-29.1.1.
pub(crate) fn after_message_queue_change(process: &mut Process) {
    if let Some(runtime) = process.runtime.clone() {
        for state in monitor_states(&runtime) {
            after_message_queue_change_one(process, &state);
        }
    }
}

fn after_message_queue_change_one(process: &mut Process, state: &SystemMonitorState) {
    let Some(runtime) = process.runtime.clone() else {
        return;
    };
    let flags = runtime.system_monitor_flags.load(Ordering::Relaxed);
    if flags & MONITOR_LONG_MESSAGE_QUEUE == 0 {
        return;
    }
    let Some(pid) = runtime
        .processes
        .lock()
        .unwrap()
        .iter()
        .copied()
        .find(|pid| {
            pid.to_term()
                .is_some_and(|term| term.tagged_word() == process.header.self_pid)
        })
    else {
        return;
    };
    let Some(MonitorOption::Queue(off, on)) = state.options.get("long_message_queue") else {
        return;
    };
    let count = process.inbox.len() as u64;
    let active = runtime.long_message_queues.lock().unwrap().contains(&pid);
    let value = if !active && count >= *on {
        runtime.long_message_queues.lock().unwrap().insert(pid);
        Some(true)
    } else if active && count <= *off {
        runtime.long_message_queues.lock().unwrap().remove(&pid);
        Some(false)
    } else {
        None
    };
    let Some(value) = value else {
        return;
    };
    let OwnedTerm::Pid {
        node,
        id: receiver_id,
        serial: receiver_generation,
        creation: 0,
    } = &state.receiver
    else {
        return;
    };
    if node != "nonode@nohost" {
        return;
    }
    let receiver = arinsal_sched::Pid::new(*receiver_id, *receiver_generation);
    let event = OwnedTerm::Tuple(vec![
        OwnedTerm::atom("monitor"),
        OwnedTerm::Pid {
            node: "nonode@nohost".into(),
            id: pid.number(),
            serial: pid.serial(),
            creation: 0,
        },
        OwnedTerm::atom("long_message_queue"),
        OwnedTerm::atom(if value { "true" } else { "false" }),
    ]);
    if let Ok(term) = from_owned(
        &event,
        &mut arinsal_bifs::FragmentingHeap(&mut process.heap),
    ) && let Ok(message) = Message::copy_from(term)
        && let Ok(scheduler) = runtime.scheduler()
    {
        let _ = scheduler.send(pid, receiver, message);
    }
}

/// Emit the event when a sender is suspended on a busy local port.
// Port of erts/emulator/beam/erl_process.c:9396-9397 and erl_trace.c:1928-1937, OTP-29.1.1.
pub(crate) fn notify_busy_port(process: &Process, sender: arinsal_sched::Pid, port_id: u64) {
    if let Some(runtime) = process.runtime.clone() {
        for state in monitor_states(&runtime) {
            notify_busy_port_one(process, sender, port_id, &state);
        }
    }
}

fn notify_busy_port_one(
    process: &Process,
    sender: arinsal_sched::Pid,
    port_id: u64,
    state: &SystemMonitorState,
) {
    let Some(runtime) = process.runtime.as_ref() else {
        return;
    };
    if runtime.system_monitor_flags.load(Ordering::Relaxed) & MONITOR_BUSY_PORT == 0 {
        return;
    }
    if !matches!(
        state.options.get("busy_port"),
        Some(MonitorOption::Bool(true))
    ) {
        return;
    }
    let OwnedTerm::Pid {
        node,
        id: receiver_id,
        serial: receiver_generation,
        creation: 0,
    } = &state.receiver
    else {
        return;
    };
    if node != "nonode@nohost" {
        return;
    }
    let receiver = arinsal_sched::Pid::new(*receiver_id, *receiver_generation);
    let Some(port) = Term::port(port_id) else {
        return;
    };
    let mut heap = arinsal_term::ProcessHeap::with_words(16);
    let Ok(event) = TermBuilder::new(&mut heap).tuple(&[
        atom("monitor"),
        sender.to_term().unwrap_or(Term::NIL),
        atom("busy_port"),
        port,
    ]) else {
        return;
    };
    if let Ok(message) = Message::copy_from(event)
        && let Ok(scheduler) = runtime.scheduler()
    {
        let _ = scheduler.send(sender, receiver, message);
    }
}

/// Emit the event when a sender is suspended on a busy distribution port.
// Port of erts/emulator/beam/erl_trace.c:1942-1948, OTP-29.1.1.
pub(crate) fn notify_busy_dist_port(process: &Process, sender: arinsal_sched::Pid, port_id: u64) {
    if let Some(runtime) = process.runtime.clone() {
        for state in monitor_states(&runtime) {
            notify_busy_dist_port_one(process, sender, port_id, &state);
        }
    }
}

fn notify_busy_dist_port_one(
    process: &Process,
    sender: arinsal_sched::Pid,
    port_id: u64,
    state: &SystemMonitorState,
) {
    let Some(runtime) = process.runtime.as_ref() else {
        return;
    };
    if runtime.system_monitor_flags.load(Ordering::Relaxed) & MONITOR_BUSY_DIST_PORT == 0 {
        return;
    }
    if !matches!(
        state.options.get("busy_dist_port"),
        Some(MonitorOption::Bool(true))
    ) {
        return;
    }
    let OwnedTerm::Pid {
        node,
        id: receiver_id,
        serial: receiver_generation,
        creation: 0,
    } = &state.receiver
    else {
        return;
    };
    if node != "nonode@nohost" {
        return;
    }
    let receiver = arinsal_sched::Pid::new(*receiver_id, *receiver_generation);
    let mut heap = arinsal_term::ProcessHeap::with_words(16);
    let event = OwnedTerm::Tuple(vec![
        OwnedTerm::atom("monitor"),
        OwnedTerm::Pid {
            node: "nonode@nohost".into(),
            id: sender.number(),
            serial: sender.serial(),
            creation: 0,
        },
        OwnedTerm::atom("busy_dist_port"),
        OwnedTerm::Port {
            node: "nonode@nohost".into(),
            id: port_id,
            creation: 0,
        },
    ]);
    if let Ok(term) = from_owned(&event, &mut arinsal_bifs::FragmentingHeap(&mut heap))
        && let Ok(message) = Message::copy_from(term)
        && let Ok(scheduler) = runtime.scheduler()
    {
        let _ = scheduler.send(sender, receiver, message);
    }
}

/// Implemented `erts_debug` and `erts_internal` debug BIFs.
pub(crate) const IMPLEMENTED: &[(&str, &str, u8)] = &[
    ("erts_debug", "copy_shared", 2),
    ("erts_debug", "dirty", 3),
    ("erts_debug", "dirty_cpu", 2),
    ("erts_debug", "dirty_io", 2),
    ("erts_debug", "disassemble", 1),
    ("erts_debug", "get_internal_state", 1),
    ("erts_debug", "instructions", 0),
    ("erts_debug", "interpreter_size", 0),
    ("erts_debug", "lcnt_clear", 0),
    ("erts_debug", "lcnt_collect", 0),
    ("erts_debug", "lcnt_control", 1),
    ("erts_debug", "lcnt_control", 2),
    ("erts_debug", "map_info", 1),
    ("erts_debug", "set_internal_state", 2),
    ("erts_debug", "size_shared", 1),
    ("erts_debug", "unaligned_bitstring", 2),
    ("erts_internal", "gather_alloc_histograms", 1),
    ("erts_internal", "gather_carrier_info", 1),
    ("erts_internal", "map_hashmap_children", 1),
    ("erts_internal", "map_to_tuple_keys", 1),
    ("erts_internal", "system_check", 1),
    ("erts_internal", "system_monitor", 1),
    ("erts_internal", "system_monitor", 3),
    ("erts_internal", "term_type", 1),
];

fn atom(name: &str) -> Term {
    Term::atom(global_atoms().intern(name).expect("built-in atom"))
}

fn badarg() -> VmError {
    VmError::Trap(exceptions::Trap::error(atom("badarg")))
}

fn badmap(process: &mut Process, value: Term) -> Result<Term, VmError> {
    tuple(process, &[atom("badmap"), value])
        .map_err(|_| VmError::Trap(exceptions::Trap::error(atom("system_limit"))))
}

fn undef() -> VmError {
    VmError::Trap(exceptions::Trap::error(atom("undef")))
}

fn arg_name(term: Term) -> Option<String> {
    global_atoms()
        .text(term.as_atom()?)
        .map(|text| text.to_string())
}

fn int(process: &mut Process, value: usize) -> Result<Term, VmError> {
    TermBuilder::new(&mut arinsal_bifs::FragmentingHeap(&mut process.heap))
        .int_from_i128(value as i128)
        .map_err(|_| VmError::Trap(exceptions::Trap::error(atom("system_limit"))))
}

fn list(process: &mut Process, values: &[Term]) -> Result<Term, VmError> {
    TermBuilder::new(&mut arinsal_bifs::FragmentingHeap(&mut process.heap))
        .list_from_iter(values.iter().copied())
        .map_err(|_| VmError::Trap(exceptions::Trap::error(atom("system_limit"))))
}

fn tuple(process: &mut Process, values: &[Term]) -> Result<Term, VmError> {
    TermBuilder::new(&mut arinsal_bifs::FragmentingHeap(&mut process.heap))
        .tuple(values)
        .map_err(|_| VmError::Trap(exceptions::Trap::error(atom("system_limit"))))
}

/// Port of erts/emulator/beam/beam_debug.c:377 (erts_debug_instructions_0), OTP-29.1.1.
fn instructions(process: &mut Process) -> Result<Term, VmError> {
    let mut names = Vec::new();
    for name in include_str!("erts_debug_instructions.txt").lines() {
        let bytes = name
            .bytes()
            .map(|byte| Term::small(i64::from(byte)).expect("instruction name byte"))
            .collect::<Vec<_>>();
        names.push(list(process, &bytes)?);
    }
    list(process, &names)
}

/// Retry the calling BIF on a scheduler of `wanted` type unless it already runs on one.
///
/// Port of erts/emulator/beam/erl_bif_info.c / bif.c (`erts_schedule_bif` and the static
/// dirty BIF table `erts_dirty_bif.tab`), OTP-29.1.1.
fn on_scheduler(ctx: &RunCtx<'_, Message>, wanted: SchedulerType) -> Result<(), VmError> {
    if ctx.scheduler_type() == wanted {
        return Ok(());
    }
    Err(match wanted {
        SchedulerType::DirtyCpu => VmError::Dirty(DirtyKind::Cpu),
        SchedulerType::DirtyIo => VmError::Dirty(DirtyKind::Io),
        // A dirty job returns to a normal scheduler when it yields.
        SchedulerType::Normal => VmError::Yield,
    })
}

fn scheduler_type_atom(kind: SchedulerType) -> Term {
    atom(match kind {
        SchedulerType::Normal => "normal",
        SchedulerType::DirtyCpu => "dirty_cpu",
        SchedulerType::DirtyIo => "dirty_io",
    })
}

/// Port of erts/emulator/beam/beam_debug.c:1474 (ms_wait), OTP-29.1.1.
fn ms_wait(milliseconds: i64, busy: bool) {
    let deadline = Instant::now() + Duration::from_millis(milliseconds.max(0) as u64);
    loop {
        let now = Instant::now();
        if now >= deadline {
            break;
        }
        if busy {
            std::thread::yield_now();
        } else {
            std::thread::sleep(deadline - now);
        }
    }
}

/// What `dirty_test` needs from the real process; on a dirty scheduler it runs as a
/// dirty job, like erts runs it on a shadow process.
struct DirtyTestEnv {
    pid: Pid,
    scheduler: Option<std::sync::Arc<arinsal_sched::Scheduler<Process>>>,
    exiting: std::sync::Arc<AtomicBool>,
}

/// Port of erts/emulator/beam/beam_debug.c:1431 (dirty_send_message), OTP-29.1.1.
fn dirty_send_message(env: &DirtyTestEnv, heap: &mut ProcessHeap, to: Term, tag: Term) {
    let (Some(to), Some(scheduler), Some(me)) = (
        Pid::from_term(to),
        env.scheduler.as_ref(),
        env.pid.to_term(),
    ) else {
        return;
    };
    let Ok(message) = TermBuilder::new(&mut arinsal_bifs::FragmentingHeap(heap)).tuple(&[tag, me])
    else {
        return;
    };
    if let Ok(message) = Message::copy_from(message) {
        let _ = scheduler.send(env.pid, to, message);
    }
}

/// Port of erts/emulator/beam/beam_debug.c:1248-1428 (dirty_test), OTP-29.1.1.
fn dirty_test_body(
    env: &DirtyTestEnv,
    heap: &mut ProcessHeap,
    busy: bool,
    operation: Term,
    value: Term,
) -> Result<Term, &'static str> {
    let system_limit = |_| "system_limit";
    match arg_name(operation).as_deref() {
        Some("scheduler") if value == atom("type") => {
            Ok(scheduler_type_atom(arinsal_sched::current_scheduler_type()))
        }
        Some("error") => match arg_name(value).as_deref() {
            Some("notsup") => Err("notsup"),
            Some("undef") => Err("undef"),
            Some("badarith") => Err("badarith"),
            Some("noproc") => Err("noproc"),
            Some("system_limit") => Err("system_limit"),
            _ => Err("badarg"),
        },
        Some("copy") => {
            let mut copies = Vec::with_capacity(1000);
            for _ in 0..1000 {
                copies.push(
                    copy_term(value, &mut arinsal_bifs::FragmentingHeap(heap))
                        .map_err(system_limit)?,
                );
            }
            TermBuilder::new(&mut arinsal_bifs::FragmentingHeap(heap))
                .list_from_iter(copies.iter().copied())
                .map_err(system_limit)
        }
        Some("send") => {
            dirty_send_message(env, heap, value, atom("ok"));
            Ok(atom("ok"))
        }
        Some("wait") => {
            let milliseconds = value.as_small().ok_or("badarg")?;
            ms_wait(milliseconds, busy);
            Ok(atom("ok"))
        }
        Some("reschedule") => {
            let rounds = value
                .as_small()
                .filter(|rounds| *rounds >= 0)
                .ok_or("badarg")?;
            if rounds % 2 != 0 {
                return Err("badarg");
            }
            Ok(atom("ok"))
        }
        Some("ready_wait6_done") => {
            dirty_send_message(env, heap, value, atom("ready"));
            ms_wait(6_000, false);
            dirty_send_message(env, heap, value, atom("done"));
            Ok(atom("ok"))
        }
        Some(op @ ("alive_waitexiting" | "alive_waitexitingonly")) => {
            let dirty_io = arinsal_sched::current_scheduler_type() == SchedulerType::DirtyIo;
            if env.exiting.load(Ordering::Acquire) {
                return Err("badarg");
            }
            dirty_send_message(env, heap, value, atom("alive"));
            // Wait until dead.
            while !env.exiting.load(Ordering::Acquire) {
                if dirty_io {
                    ms_wait(100, false);
                } else {
                    std::thread::yield_now();
                }
            }
            if op == "alive_waitexitingonly" {
                return Ok(atom("ok"));
            }
            ms_wait(1000, false);
            // Should still be able to allocate memory: a 9999-digit bignum of 4711 digits.
            let digit = BigInt::from(4711_u64);
            let mut big = BigInt::from(0_u64);
            for _ in 1..10_000 {
                big = (big << 64) + &digit;
            }
            let big = from_owned(
                &OwnedTerm::BigInt(big),
                &mut arinsal_bifs::FragmentingHeap(heap),
            )
            .map_err(system_limit)?;
            TermBuilder::new(&mut arinsal_bifs::FragmentingHeap(heap))
                .tuple(&[atom("ok"), big])
                .map_err(system_limit)
        }
        _ => Err("badarg"),
    }
}

/// Run `dirty_test` on the current scheduler; on a dirty one as a dirty job.
fn dirty_test(
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    scheduler: &str,
    operation: Term,
    value: Term,
) -> Result<Term, VmError> {
    let busy = scheduler == "dirty_cpu";
    let scheduler_handle = process
        .runtime
        .as_ref()
        .and_then(|runtime| runtime.scheduler().ok());
    let kind = match ctx.scheduler_type() {
        SchedulerType::Normal => None,
        SchedulerType::DirtyCpu => Some(DirtyKind::Cpu),
        SchedulerType::DirtyIo => Some(DirtyKind::Io),
    };
    let result = match kind {
        None => {
            let env = DirtyTestEnv {
                pid: ctx.pid(),
                scheduler: scheduler_handle,
                exiting: std::sync::Arc::new(AtomicBool::new(false)),
            };
            dirty_test_body(&env, &mut process.heap, busy, operation, value)
        }
        Some(kind) => {
            let env = DirtyTestEnv {
                pid: ctx.pid(),
                scheduler: scheduler_handle,
                exiting: process.dirty_exit_flag(),
            };
            process.dirty_bif(kind, move |heap| {
                dirty_test_body(&env, heap, busy, operation, value)
            })?
        }
    };
    result.map_err(|reason| VmError::Trap(exceptions::Trap::error(atom(reason))))
}

/// Port of erts/emulator/beam/beam_debug.c:1190 (erts_debug_dirty_3), OTP-29.1.1.
fn dirty(
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    args: &[Term],
) -> Result<Term, VmError> {
    let (scheduler, wanted) = match arg_name(args[0]).as_deref() {
        Some("normal") => ("normal", SchedulerType::Normal),
        Some("dirty_cpu") => ("dirty_cpu", SchedulerType::DirtyCpu),
        Some("dirty_io") => ("dirty_io", SchedulerType::DirtyIo),
        _ => return Err(badarg()),
    };
    on_scheduler(ctx, wanted)?;
    dirty_test(process, ctx, scheduler, args[1], args[2])
}

/// Port of erts/emulator/beam/beam_debug.c:86 (erts_debug_size_shared_1), OTP-29.1.1.
fn size_shared(process: &mut Process, value: Term) -> Result<Term, VmError> {
    int(process, arinsal_term::size_shared(value))
}

/// Port of erts/emulator/beam/beam_debug.c:170 (erts_debug_copy_shared_2), OTP-29.1.1.
fn copy_shared(process: &mut Process, args: &[Term]) -> Result<Term, VmError> {
    let copy_literals = if args[1] == atom("true") {
        true
    } else if args[1] == atom("false") {
        false
    } else {
        return Err(badarg());
    };
    arinsal_term::copy_shared(
        args[0],
        &mut arinsal_bifs::FragmentingHeap(&mut process.heap),
        copy_literals,
    )
    .map_err(|_| VmError::Trap(exceptions::Trap::error(atom("system_limit"))))
}

/// Port of erts/emulator/beam/erl_map.c:3301 (erts_debug_map_info_1), OTP-29.1.1.
fn map_info(process: &mut Process, value: Term) -> Result<Term, VmError> {
    if value.classify() != TermKind::Map {
        return Err(VmError::Trap(exceptions::Trap::error(badmap(
            process, value,
        )?)));
    }
    if !value.is_hashmap() {
        return Err(badarg());
    }
    // Port of erts/emulator/beam/erl_map.c:3425-3590 (hashmap_info), OTP-29.1.1.
    const LEVELS: usize = 18;
    let mut leaves = [0usize; LEVELS];
    let mut bitmaps = [0usize; 16];
    let mut collisions = [0usize; 16];
    let mut arrays = 0usize;
    let mut leaf_count = 0usize;
    let mut bitmap_count = 0usize;
    let mut collision_count = 0usize;
    let mut max_depth = 0usize;
    let mut stack = vec![(value, 0usize)];
    while let Some((node, depth)) = stack.pop() {
        if node.classify() == TermKind::List {
            leaf_count += 1;
            leaves[depth] += 1;
            continue;
        }
        let header = node.header().ok_or_else(badarg)?;
        let kind = ((header >> 6) & 3) as usize;
        let children = hashmap_node_children(node).ok_or_else(badarg)?;
        let next_depth = depth + 1;
        max_depth = max_depth.max(next_depth);
        match header & 63 {
            0 => {
                collision_count += 1;
                collisions[children.len().min(16) - 1] += 1;
            }
            0x2c if kind == 1 => {
                bitmap_count += 1;
                bitmaps[children.len() - 1] += 1;
            }
            0x2c if kind == 2 => arrays += 1,
            0x2c if kind == 3 => {
                bitmap_count += 1;
                bitmaps[children.len() - 1] += 1;
            }
            _ => return Err(badarg()),
        }
        if next_depth < LEVELS {
            stack.extend(children.into_iter().map(|child| (child, next_depth)));
        }
    }
    let mut heap = arinsal_bifs::FragmentingHeap(&mut process.heap);
    let mut builder = TermBuilder::new(&mut heap);
    let (leaf_info, bitmap_info, collision_info) = {
        let mut small_tuple = |values: &[usize]| {
            let values = values
                .iter()
                .map(|value| {
                    Term::small(*value as i64).expect("map statistic fits a small integer")
                })
                .collect::<Vec<_>>();
            builder
                .tuple(&values)
                .map_err(|_| VmError::Trap(exceptions::Trap::error(atom("system_limit"))))
        };
        (
            small_tuple(&leaves)?,
            small_tuple(&bitmaps)?,
            small_tuple(&collisions)?,
        )
    };
    let entries = [
        ("leafs", leaf_count, leaf_info),
        ("bitmaps", bitmap_count, bitmap_info),
        ("collisions", collision_count, collision_info),
    ];
    let mut result = Term::NIL;
    for (name, count, info) in entries {
        let item = builder
            .tuple(&[atom(name), Term::small(count as i64).unwrap(), info])
            .map_err(|_| VmError::Trap(exceptions::Trap::error(atom("system_limit"))))?;
        result = builder
            .cons(item, result)
            .map_err(|_| VmError::Trap(exceptions::Trap::error(atom("system_limit"))))?;
    }
    let arrays_item = builder
        .tuple(&[
            atom("arrays"),
            Term::small(arrays as i64).unwrap(),
            Term::NIL,
        ])
        .map_err(|_| VmError::Trap(exceptions::Trap::error(atom("system_limit"))))?;
    result = builder
        .cons(arrays_item, result)
        .map_err(|_| VmError::Trap(exceptions::Trap::error(atom("system_limit"))))?;
    let depth_item = builder
        .tuple(&[atom("depth"), Term::small(max_depth as i64).unwrap()])
        .map_err(|_| VmError::Trap(exceptions::Trap::error(atom("system_limit"))))?;
    builder
        .cons(depth_item, result)
        .map_err(|_| VmError::Trap(exceptions::Trap::error(atom("system_limit"))))
}

/// Port of erts/emulator/beam/beam_debug.c:101 (erts_debug_unaligned_bitstring_2), OTP-29.1.1.
fn unaligned_bitstring(process: &mut Process, args: &[Term]) -> Result<Term, VmError> {
    let offset = args[1]
        .as_small()
        .filter(|offset| (1..8).contains(offset))
        .ok_or_else(badarg)? as usize;
    let owned = to_owned(args[0]).map_err(|_| badarg())?;
    let (bytes, bit_len) = match &owned {
        OwnedTerm::Binary(bytes) => {
            let len = bytes.len() * 8;
            (bytes.as_slice(), len)
        }
        OwnedTerm::BitString { bytes, bits } => {
            let len = bytes
                .len()
                .checked_sub(1)
                .ok_or_else(badarg)?
                .checked_mul(8)
                .and_then(|n| n.checked_add(usize::from(*bits)))
                .ok_or_else(badarg)?;
            (bytes.as_slice(), len)
        }
        _ => return Err(badarg()),
    };
    // Port of beam_debug.c:140 (ERL_ONHEAP_BITS_LIMIT + 1), OTP-29.1.1.
    let target_bits = bit_len.saturating_add(offset).max(64 * 8 + 1);
    let mut target = vec![0u8; target_bits.div_ceil(8)];
    for index in 0..bit_len {
        let bit = (bytes[index / 8] >> (7 - index % 8)) & 1;
        let target_bit = index + offset;
        target[target_bit / 8] |= bit << (7 - target_bit % 8);
    }
    let mut heap = arinsal_bifs::FragmentingHeap(&mut process.heap);
    let mut builder = TermBuilder::new(&mut heap);
    let binary = builder
        .binary(&target)
        .map_err(|_| VmError::Trap(exceptions::Trap::error(atom("system_limit"))))?;
    builder
        .sub_binary(binary, offset, bit_len)
        .map_err(|_| VmError::Trap(exceptions::Trap::error(atom("system_limit"))))
}

/// Port of erts/emulator/beam/erl_map.c:3336 (erts_internal_term_type_1), OTP-29.1.1.
fn term_type(value: Term) -> Term {
    let name = match value.classify() {
        TermKind::Number => match value.header().map(|header| header & 63) {
            Some(0x18) => "hfloat",
            Some(0x08 | 0x0c) => "bignum",
            _ => "fixnum",
        },
        TermKind::Atom => "atom",
        TermKind::Ref => match value.header().map(|header| header & 63) {
            Some(0x10 | 0x3c) => "reference",
            _ => "external_reference",
        },
        TermKind::Fun => {
            if value.header().is_some_and(|header| (header >> 24) & 1 != 0) {
                "export"
            } else {
                "fun"
            }
        }
        TermKind::Port => {
            if value.header().is_some() {
                "external_port"
            } else {
                "port"
            }
        }
        TermKind::Pid => {
            if value.header().is_some() {
                "external_pid"
            } else {
                "pid"
            }
        }
        TermKind::Tuple => "tuple",
        TermKind::Record => "tuple",
        TermKind::Map => match value.header().map(|header| (header >> 6) & 3) {
            Some(0) => "flatmap",
            Some(1) => "hashmap_node",
            Some(2 | 3) => "hashmap",
            _ => "hashmap",
        },
        TermKind::Nil => "nil",
        TermKind::List => "list",
        TermKind::Bitstring => match value.header().map(|header| header & 63) {
            Some(0x20) => "heap_binary",
            Some(0x24) => "sub_binary",
            _ => "refc_binary",
        },
        TermKind::BinRef => "refc_binary",
        TermKind::Catch => "catch",
        TermKind::Invalid => "invalid",
    };
    atom(name)
}

fn build(
    vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    args: &[Term],
    module: &str,
    function: &str,
) -> Result<Term, VmError> {
    let _ = vm;
    match (module, function, args.len()) {
        ("erts_debug", "copy_shared", 2) => copy_shared(process, args),
        ("erts_debug", "size_shared", 1) => size_shared(process, args[0]),
        ("erts_debug", "interpreter_size", 0) => Ok(Term::small(0).unwrap()),
        ("erts_debug", "disassemble", 1) => Ok(atom("false")),
        ("erts_debug", "lcnt_clear", 0) | ("erts_debug", "lcnt_collect", 0) => Ok(atom("error")),
        ("erts_debug", "lcnt_control", 1 | 2) => Err(badarg()),
        ("erts_debug", "map_info", 1) => map_info(process, args[0]),
        ("erts_debug", "get_internal_state", 1) => internal_state_get(vm, process, ctx, args[0]),
        ("erts_debug", "set_internal_state", 2) => {
            internal_state_set(process, ctx, args[0], args[1])
        }
        ("erts_debug", "instructions", 0) => instructions(process),
        ("erts_debug", "dirty", 3) => dirty(process, ctx, args),
        ("erts_debug", "dirty_cpu", 2) => on_scheduler(ctx, SchedulerType::DirtyCpu)
            .and_then(|()| dirty_test(process, ctx, "dirty_cpu", args[0], args[1])),
        ("erts_debug", "dirty_io", 2) => on_scheduler(ctx, SchedulerType::DirtyIo)
            .and_then(|()| dirty_test(process, ctx, "dirty_io", args[0], args[1])),
        ("erts_debug", "unaligned_bitstring", 2) => unaligned_bitstring(process, args),
        ("erts_internal", "gather_alloc_histograms", 1) => {
            gather_allocator_info(process, ctx, args[0], false)
        }
        ("erts_internal", "gather_carrier_info", 1) => {
            gather_allocator_info(process, ctx, args[0], true)
        }
        ("erts_internal", "map_hashmap_children", 1) => map_hashmap_children(process, args[0]),
        ("erts_internal", "map_to_tuple_keys", 1) => map_to_tuple_keys(process, args[0]),
        ("erts_internal", "term_type", 1) => Ok(term_type(args[0])),
        ("erts_internal", "system_check", 1) => system_check(args[0]),
        ("erts_internal", "system_monitor", 1) => system_monitor_get(process, args[0]),
        ("erts_internal", "system_monitor", 3) => system_monitor_set(process, ctx, args),
        _ => Err(undef()),
    }
}

fn map_hashmap_children(process: &mut Process, value: Term) -> Result<Term, VmError> {
    if value.classify() != TermKind::Map {
        return Err(VmError::Trap(exceptions::Trap::error(badmap(
            process, value,
        )?)));
    }
    let children = hashmap_node_children(value).ok_or_else(badarg)?;
    list(process, &children.into_iter().rev().collect::<Vec<_>>())
}

/// Port of erts/emulator/beam/erl_map.c:3318-3324, OTP-29.1.1.
fn map_to_tuple_keys(process: &mut Process, value: Term) -> Result<Term, VmError> {
    if value.classify() != TermKind::Map {
        return Err(VmError::Trap(exceptions::Trap::error(badmap(
            process, value,
        )?)));
    }
    value.flatmap_keys_tuple().ok_or_else(badarg)
}

/// Port of erts/emulator/beam/erl_bif_info.c:5678-5728, OTP-29.1.1.
fn gather_allocator_info(
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    arg: Term,
    carrier: bool,
) -> Result<Term, VmError> {
    const ALLOCATORS: [&str; 10] = [
        "temp_alloc",
        "sl_alloc",
        "std_alloc",
        "ll_alloc",
        "eheap_alloc",
        "ets_alloc",
        "fix_alloc",
        "literal_alloc",
        "binary_alloc",
        "driver_alloc",
    ];
    let owned_arg = to_owned(arg).map_err(|_| badarg())?;
    let OwnedTerm::Tuple(fields) = &owned_arg else {
        return Err(badarg());
    };
    if fields.len() != 6 {
        return Err(badarg());
    }
    let OwnedTerm::Atom(allocator) = &fields[0] else {
        return Err(badarg());
    };
    if !ALLOCATORS.contains(&allocator.as_str()) {
        return Err(badarg());
    }
    let (Some(aux_id), Some(width), Some(start), Some(_flags)) = (
        owned_signed(&fields[1]),
        owned_signed(&fields[2]),
        owned_signed(&fields[3]),
        owned_signed(&fields[4]),
    ) else {
        return Err(badarg());
    };
    if !(0..11).contains(&aux_id) || !(1..=32).contains(&width) || start < 1 {
        return Err(badarg());
    }
    let OwnedTerm::Ref { .. } = &fields[5] else {
        return Err(badarg());
    };
    let reference = from_owned(
        &fields[5],
        &mut arinsal_bifs::FragmentingHeap(&mut process.heap),
    )
    .map_err(|_| VmError::Trap(exceptions::Trap::error(atom("system_limit"))))?;
    let message = if carrier {
        // OTP's default ETS allocator has no carrier records on this host.
        tuple(process, &[reference, Term::NIL])?
    } else {
        tuple(process, &[reference, Term::small(0).unwrap(), Term::NIL])?
    };
    if let Some(receiver) = ctx.pid().to_term() {
        let _ = process.send_message(receiver, message);
    }
    Ok(Term::small(1).unwrap())
}

fn owned_signed(value: &OwnedTerm) -> Option<i64> {
    match value {
        OwnedTerm::Int(value) => Some(*value),
        OwnedTerm::BigInt(value) => value.to_i64(),
        _ => None,
    }
}

fn internal_state_tuple_get(
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    selector: Term,
) -> Result<Option<Term>, VmError> {
    if let Some(fields) = term_sequence(selector)
        && let [name, value] = fields.as_slice()
        && name.as_atom().and_then(|name| global_atoms().text(name)) == Some("internal_hash")
    {
        // Port of erts/emulator/beam/erl_bif_info.c:4834-4835, OTP-29.1.1.
        let hash = OwnedTerm::BigInt(BigInt::from(arinsal_term::internal_hash(*value)));
        return from_owned(&hash, &mut arinsal_bifs::FragmentingHeap(&mut process.heap))
            .map(Some)
            .map_err(|_| VmError::Trap(exceptions::Trap::error(atom("system_limit"))));
    }
    let Ok(owned) = to_owned(selector) else {
        return Ok(None);
    };
    let OwnedTerm::Tuple(fields) = &owned else {
        return Ok(None);
    };
    if let [
        OwnedTerm::Atom(name),
        OwnedTerm::Atom(correction),
        OwnedTerm::Atom(mode),
    ] = fields.as_slice()
        && name == "check_time_config"
    {
        let valid_correction = matches!(correction.as_str(), "true" | "false");
        let valid_mode = matches!(
            mode.as_str(),
            "no_time_warp" | "single_time_warp" | "multi_time_warp"
        );
        return Ok((valid_correction && valid_mode).then(|| atom("true")));
    }
    if let [OwnedTerm::Atom(name), term, options] = fields.as_slice()
        && name == "term_to_binary"
    {
        let Some(options) = term_binary_options(options) else {
            return Ok(None);
        };
        let bytes = arinsal_etf::encode(term, options);
        return TermBuilder::new(&mut arinsal_bifs::FragmentingHeap(&mut process.heap))
            .binary(&bytes)
            .map(Some)
            .map_err(|_| VmError::Trap(exceptions::Trap::error(atom("system_limit"))));
    }
    if let [OwnedTerm::Atom(name), first, second] = fields.as_slice()
        && name == "make_unique_integer"
    {
        let (Some(first), Some(second)) = (owned_uint(first), owned_uint(second)) else {
            return Err(badarg());
        };
        // The reference host has ten normal, ten dirty CPU, and ten dirty I/O schedulers.
        let bits = 5_u32;
        let low = first | second.wrapping_shl(bits);
        let high = (second >> (64 - bits)) & ((1_u64 << bits) - 1);
        let result = (BigInt::from(high) << 64) + BigInt::from(low)
            - BigInt::from(576_460_752_303_423_488_i64);
        return from_owned(
            &OwnedTerm::BigInt(result),
            &mut arinsal_bifs::FragmentingHeap(&mut process.heap),
        )
        .map(Some)
        .map_err(|_| VmError::Trap(exceptions::Trap::error(atom("system_limit"))));
    }
    if let [OwnedTerm::Atom(name), OwnedTerm::Atom(node)] = fields.as_slice()
        && name == "connection_id"
    {
        let tables = crate::node_tables::lock();
        let Some(entry) = tables.entries.get(node).filter(|entry| entry.connected) else {
            return Err(badarg());
        };
        return int(process, entry.connection_id as usize).map(Some);
    }
    if let [OwnedTerm::Atom(name), _] = fields.as_slice()
        && name == "native_record_def"
    {
        return Ok(arinsal_term::term_sequence(selector)
            .and_then(|parts| parts.get(1).copied())
            .and_then(Term::record_snapshot)
            .map(|record| record.definition));
    }
    if let [OwnedTerm::Atom(name), OwnedTerm::Atom(mode)] = fields.as_slice()
        && name == "node_and_dist_references"
        && mode == "blocked"
    {
        if !crate::natives::sys::multi_scheduling_blocked(process) {
            return Err(badarg());
        }
        ctx.block_thread_progress(std::time::Duration::ZERO);
        return node_and_dist_references(process).map(Some);
    }
    let [OwnedTerm::Atom(name), value] = fields.as_slice() else {
        return Ok(None);
    };
    let selector_value =
        arinsal_term::term_sequence(selector).and_then(|parts| parts.get(1).copied());
    match (name.as_str(), value) {
        ("internal_hash", value) => {
            let value = from_owned(value, &mut arinsal_bifs::FragmentingHeap(&mut process.heap))
                .map_err(|_| VmError::Trap(exceptions::Trap::error(atom("system_limit"))))?;
            let hash = arinsal_term::internal_hash(value);
            let result = OwnedTerm::BigInt(hash.into());
            from_owned(
                &result,
                &mut arinsal_bifs::FragmentingHeap(&mut process.heap),
            )
            .map(Some)
            .map_err(|_| VmError::Trap(exceptions::Trap::error(atom("system_limit"))))
        }
        ("atom", index) => {
            let Some(index) = owned_uint(index).and_then(|index| usize::try_from(index).ok())
            else {
                return Err(badarg());
            };
            if index >= 1_048_576 {
                return Err(VmError::Trap(exceptions::Trap::error(atom("system_limit"))));
            }
            while global_atoms().len() <= index {
                let name = format!("am{:x}", global_atoms().len());
                if global_atoms().intern(&name).is_err() {
                    return Err(VmError::Trap(exceptions::Trap::error(atom("system_limit"))));
                }
            }
            let Some(name) = u32::try_from(index)
                .ok()
                .and_then(|index| global_atoms().text(arinsal_term::Atom(index)))
            else {
                return Ok(None);
            };
            Ok(global_atoms().intern(name).ok().map(Term::atom))
        }
        (
            "process_status",
            OwnedTerm::Pid {
                id,
                serial,
                creation: 0,
                node,
            },
        ) if node == "nonode@nohost" => {
            let pid = arinsal_sched::Pid::new(*id, *serial);
            if pid == ctx.pid() {
                return Ok(Some(atom("running")));
            }
            let status = process
                .runtime
                .as_ref()
                .and_then(|runtime| runtime.published.lock().unwrap().get(&pid).cloned())
                .map(|published| atom(published.status))
                .or_else(|| {
                    process.runtime.as_ref().and_then(|runtime| {
                        runtime
                            .processes
                            .lock()
                            .unwrap()
                            .contains(&pid)
                            .then(|| atom("runnable"))
                    })
                })
                .unwrap_or_else(|| atom("undefined"));
            Ok(Some(status))
        }
        (
            "link_list",
            OwnedTerm::Pid {
                id,
                serial,
                creation: 0,
                node,
            },
        ) if node == "nonode@nohost" => {
            let pid = arinsal_sched::Pid::new(*id, *serial);
            if pid != ctx.pid() {
                let published = process
                    .runtime
                    .as_ref()
                    .and_then(|runtime| runtime.published.lock().unwrap().get(&pid).cloned());
                return match published {
                    Some(published) => internal_link_list_from(process, &published.links).map(Some),
                    None => Ok(Some(atom("undefined"))),
                };
            }
            internal_link_list(process).map(Some)
        }
        (
            "monitor_list",
            OwnedTerm::Pid {
                id,
                serial,
                creation: 0,
                node,
            },
        ) if node == "nonode@nohost" => {
            let pid = arinsal_sched::Pid::new(*id, *serial);
            if pid != ctx.pid() {
                let published = process
                    .runtime
                    .as_ref()
                    .and_then(|runtime| runtime.published.lock().unwrap().get(&pid).cloned());
                return match published {
                    Some(published) => internal_monitor_list_from(
                        process,
                        &published.monitors,
                        &published.monitored_by,
                    )
                    .map(Some),
                    None => Ok(Some(atom("undefined"))),
                };
            }
            internal_monitor_list(process).map(Some)
        }
        ("channel_number", OwnedTerm::Atom(node)) if node == "nonode@nohost" => {
            Ok(Some(Term::small(0).unwrap()))
        }
        ("channel_number", OwnedTerm::Atom(node)) => {
            let tables = crate::node_tables::lock();
            let channel = tables
                .entries
                .get(node)
                .filter(|entry| entry.connected)
                .map(|entry| entry.connection_id);
            match channel {
                Some(channel) => int(process, channel as usize).map(Some),
                None => Ok(Some(atom("undefined"))),
            }
        }
        ("channel_number", _) => Ok(Some(atom("undefined"))),
        ("dist_ctrl", OwnedTerm::Atom(node)) => {
            let tables = crate::node_tables::lock();
            let controller = tables
                .entries
                .get(node)
                .filter(|entry| entry.connected)
                .and_then(|entry| {
                    entry.dist.as_ref().and_then(|state| {
                        state
                            .port_id
                            .and_then(Term::port)
                            .or_else(|| state.owner.to_term())
                    })
                });
            Ok(Some(controller.unwrap_or_else(|| atom("undefined"))))
        }
        ("dist_ctrl", _) => Ok(Some(atom("undefined"))),
        ("reader_groups_map", OwnedTerm::Int(groups))
            if *groups > 0 && Term::small(*groups).is_some() =>
        {
            Ok(Some(Term::NIL))
        }
        ("fake_scheduler_bindings", OwnedTerm::Atom(mode))
            if matches!(
                mode.as_str(),
                "default_bind"
                    | "spread"
                    | "processor_spread"
                    | "thread_spread"
                    | "thread_no_node_processor_spread"
                    | "no_node_processor_spread"
                    | "no_node_thread_spread"
                    | "no_spread"
                    | "unbound"
            ) =>
        {
            Ok(Some(atom("false")))
        }
        ("atom_out_cache_index", OwnedTerm::Atom(name)) => {
            let Some(index) = global_atoms().get(name).map(|atom| atom.0) else {
                return Ok(None);
            };
            int(process, index as usize).map(Some)
        }
        ("binary_info", OwnedTerm::Binary(bytes))
            if selector_value.is_some_and(|term| {
                term.classify() == arinsal_term::TermKind::Bitstring && bytes.len() > 64
            }) =>
        {
            let size = int(process, bytes.len())?;
            let binary_info = tuple(process, &[atom("binary"), size])?;
            tuple(
                process,
                &[
                    atom("refc_binary"),
                    size,
                    binary_info,
                    Term::small(0).unwrap(),
                ],
            )
            .map(Some)
        }
        ("binary_info", OwnedTerm::Binary(_) | OwnedTerm::BitString { .. }) => {
            Ok(Some(atom("heap_binary")))
        }
        ("magic_ref", _) => Ok(Some(atom(
            if selector_value.is_some_and(Term::is_magic_ref) {
                "true"
            } else {
                "false"
            },
        ))),
        _ => Ok(None),
    }
}

/// Port of erts/emulator/beam/erl_db.c:5765-5784 (`erts_ets_colliding_names`), OTP-29.1.1.
fn colliding_names(process: &mut Process, name: &str, count: u64) -> Result<Term, VmError> {
    const META_NAME_TAB_MASK: u64 = 8191;
    let Some(atom_index) = global_atoms().get(name).map(|atom| atom.0 as u64) else {
        return Err(badarg());
    };
    let count = usize::try_from(count)
        .map_err(|_| VmError::Trap(exceptions::Trap::error(atom("system_limit"))))?;
    let mut terms = Vec::new();
    terms
        .try_reserve_exact(count)
        .map_err(|_| VmError::Trap(exceptions::Trap::error(atom("system_limit"))))?;
    let mut index = atom_index & META_NAME_TAB_MASK;
    while terms.len() < count {
        if index != atom_index {
            while global_atoms().len() as u64 <= index {
                let next = global_atoms().len();
                let text = format!("am{next:x}");
                global_atoms()
                    .intern(&text)
                    .map_err(|_| VmError::Trap(exceptions::Trap::error(atom("system_limit"))))?;
            }
            let atom = u32::try_from(index)
                .ok()
                .map(arinsal_term::Atom)
                .and_then(|atom| Term::atom(atom).as_atom().map(Term::atom))
                .ok_or_else(badarg)?;
            terms.push(atom);
        }
        index = index
            .checked_add(META_NAME_TAB_MASK + 1)
            .ok_or_else(|| VmError::Trap(exceptions::Trap::error(atom("system_limit"))))?;
    }
    terms.reverse();
    list(process, &terms)
}

fn term_binary_options(options: &OwnedTerm) -> Option<arinsal_etf::EncodeOptions> {
    let mut encoded = arinsal_etf::EncodeOptions::default();
    let entries = match options {
        OwnedTerm::Nil => return Some(encoded),
        OwnedTerm::List { elems, tail } if **tail == OwnedTerm::Nil => elems,
        _ => return None,
    };
    for option in entries {
        match option {
            OwnedTerm::Atom(name) if name == "deterministic" => encoded.deterministic = true,
            OwnedTerm::Tuple(fields) if fields.len() == 2 => {
                let OwnedTerm::Atom(name) = &fields[0] else {
                    return None;
                };
                let value = &fields[1];
                match name.as_str() {
                    "compressed" => {
                        let level = match value {
                            OwnedTerm::Atom(value) if value == "true" => 6,
                            OwnedTerm::Int(value) => u8::try_from(*value).ok()?,
                            _ => return None,
                        };
                        if level > 9 {
                            return None;
                        }
                        encoded.compressed = Some(level);
                    }
                    "minor_version" => {
                        let version = owned_uint(value)?;
                        if version > 2 {
                            return None;
                        }
                        encoded.minor_version = Some(version as u8);
                    }
                    _ => return None,
                }
            }
            _ => return None,
        }
    }
    Some(encoded)
}

/// Port of erts_get_node_and_dist_references called by erl_bif_info.c:4354, OTP-29.1.1.
fn node_and_dist_references(process: &mut Process) -> Result<Term, VmError> {
    let local_node = atom("nonode@nohost");
    let system = atom("system");
    let undefined = atom("undefined");
    let system_reference = tuple(process, &[system, Term::small(1).unwrap()])?;
    let system_owner = tuple(process, &[system, undefined])?;
    let system_references = list(process, &[system_reference])?;
    let system_entry = tuple(process, &[system_owner, system_references])?;
    let local_reference = tuple(process, &[local_node, Term::small(0).unwrap()])?;
    let local_owners = list(process, &[system_entry])?;
    let node_ref_entry = tuple(
        process,
        &[local_reference, Term::small(1).unwrap(), local_owners],
    )?;
    let node_references = list(process, &[node_ref_entry])?;
    let node_owner = tuple(process, &[atom("node"), local_reference])?;
    let node_reference = tuple(process, &[atom("node"), Term::small(1).unwrap()])?;
    let node_owners = list(process, &[node_reference])?;
    let node_entry = tuple(process, &[node_owner, node_owners])?;
    let dist_references = list(process, &[system_entry, node_entry])?;
    let dist_entry = tuple(
        process,
        &[local_node, Term::small(2).unwrap(), dist_references],
    )?;
    let dist_entries = list(process, &[dist_entry])?;
    let node_pair = tuple(process, &[atom("node_references"), node_references])?;
    let dist_pair = tuple(process, &[atom("dist_references"), dist_entries])?;
    tuple(process, &[node_pair, dist_pair])
}

/// Port of erl_bif_info.c:make_link_list for the current process, OTP-29.1.1.
fn internal_link_list(process: &mut Process) -> Result<Term, VmError> {
    let links = process
        .cold
        .as_ref()
        .map(|cold| cold.links.iter().copied().collect::<Vec<_>>())
        .unwrap_or_default();
    internal_link_list_from(process, &links)
}

fn internal_link_list_from(
    process: &mut Process,
    links: &[arinsal_sched::Pid],
) -> Result<Term, VmError> {
    let mut records = Vec::with_capacity(links.len());
    for &pid in links {
        let Some(pid_term) = pid.to_term() else {
            continue;
        };
        let id = int(process, pid.number() as usize)?;
        records.push(tuple(
            process,
            &[
                atom("erl_link"),
                atom("process"),
                pid_term,
                atom("linked"),
                id,
            ],
        )?);
    }
    list(process, &records)
}

/// Port of erl_bif_info.c:make_monitor_list for the current process, OTP-29.1.1.
fn internal_monitor_list(process: &mut Process) -> Result<Term, VmError> {
    let Some(cold) = process.cold.as_ref() else {
        return Ok(Term::NIL);
    };
    let origins = cold
        .monitors
        .iter()
        .map(|(&id, &pid)| {
            let tag = cold.monitor_tags.get(&id).cloned();
            (id, pid, tag)
        })
        .collect::<Vec<_>>();
    let targets = cold
        .monitored_by
        .iter()
        .map(|(&id, &pid)| (id, pid))
        .collect::<Vec<_>>();
    internal_monitor_list_from(process, &origins, &targets)
}

fn internal_monitor_list_from(
    process: &mut Process,
    origins: &[(u64, arinsal_sched::Pid, Option<OwnedTerm>)],
    targets: &[(u64, arinsal_sched::Pid)],
) -> Result<Term, VmError> {
    let mut records = Vec::with_capacity(origins.len() + targets.len());
    for &(id, pid, ref tag) in origins {
        let Some(pid) = pid.to_term() else {
            continue;
        };
        let reference = crate::signals::reference(process, id)?;
        let tag = tag
            .as_ref()
            .map(|tag| {
                from_owned(tag, &mut arinsal_bifs::FragmentingHeap(&mut process.heap))
                    .map_err(|_| VmError::Trap(exceptions::Trap::error(atom("system_limit"))))
            })
            .transpose()?
            .unwrap_or(Term::NIL);
        records.push(tuple(
            process,
            &[
                atom("erl_monitor"),
                atom("process"),
                atom("origin"),
                reference,
                pid,
                tag,
            ],
        )?);
    }
    for (id, pid) in targets {
        let Some(pid) = pid.to_term() else {
            continue;
        };
        let reference = crate::signals::reference(process, *id)?;
        records.push(tuple(
            process,
            &[
                atom("erl_monitor"),
                atom("process"),
                atom("target"),
                reference,
                pid,
                Term::NIL,
            ],
        )?);
    }
    list(process, &records)
}

/// Port of erts/emulator/beam/erl_bif_info.c:4339-4947, OTP-29.1.1.
fn internal_state_get(
    vm: &Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    selector: Term,
) -> Result<Term, VmError> {
    if !INTERNAL_STATE.load(Ordering::Relaxed) {
        return Err(undef());
    }
    if let Some(result) = internal_state_tuple_get(process, ctx, selector)? {
        return Ok(result);
    }
    match arg_name(selector).as_deref() {
        Some("reds_left") => int(process, process.reductions.max(0) as usize),
        Some("available_internal_state") => Ok(atom("true")),
        Some("force_heap_frags" | "scheduler_dump" | "hashmap_collision_bonanza") => {
            Ok(atom("false"))
        }
        Some("debugger_support") => Ok(atom(if DEBUGGER_SUPPORT.load(Ordering::Relaxed) {
            "true"
        } else {
            "false"
        })),
        Some("lc_graph" | "flxctr_memory_usage") => Ok(atom("notsup")),
        Some("re_yield_coverage") => Ok(atom("undefined")),
        Some("dirty_gc_limit") => Ok(Term::small(131_072).unwrap()),
        Some("max_atom_out_cache_index") => Ok(Term::small(2038).unwrap()),
        Some("process_info_args") => {
            let names = [
                "registered_name",
                "current_function",
                "initial_call",
                "status",
                "messages",
                "message_queue_len",
                "links",
                "monitors",
                "monitored_by",
                "dictionary",
                "trap_exit",
                "error_handler",
                "heap_size",
                "stack_size",
                "memory",
                "garbage_collection",
                "group_leader",
                "reductions",
                "priority",
                "trace",
                "binary",
                "sequential_trace_token",
                "catchlevel",
                "backtrace",
                "last_calls",
                "total_heap_size",
                "suspending",
                "min_heap_size",
                "min_bin_vheap_size",
                "max_heap_size",
                "current_location",
                "current_stacktrace",
                "message_queue_data",
                "garbage_collection_info",
                "magic_ref",
                "fullsweep_after",
                "parent",
                "async_dist",
                "dictionary",
                "label",
                "priority_messages",
            ];
            let names = names.iter().map(|name| atom(name)).collect::<Vec<_>>();
            list(process, &names)
        }
        Some("DbTable_words") => tuple(
            process,
            &[Term::small(56).unwrap(), Term::small(7).unwrap()],
        ),
        Some("check_io_debug") => {
            let stats = crate::check_io::debug_info();
            tuple(
                process,
                &[
                    Term::small(0).unwrap(),
                    Term::small(stats.used_fds as i64).unwrap(),
                    Term::small(stats.driver_selects as i64).unwrap(),
                    Term::small(stats.nif_selects as i64).unwrap(),
                ],
            )
        }
        Some("mmap") => Ok(atom("undefined")),
        Some("stack_check") => Ok(Term::small(1_026_385).unwrap()),
        Some("unique_monotonic_integer_state") => {
            TermBuilder::new(&mut arinsal_bifs::FragmentingHeap(&mut process.heap))
                .int_from_i128(UNIQUE_MONOTONIC_INTEGER_STATE.load(Ordering::Relaxed) as i128)
                .map_err(|_| VmError::Trap(exceptions::Trap::error(atom("system_limit"))))
        }
        Some("persistent_term") => {
            let map = OwnedTerm::Map(vec![(OwnedTerm::atom("table"), OwnedTerm::Int(64))]);
            from_owned(&map, &mut arinsal_bifs::FragmentingHeap(&mut process.heap))
                .map_err(|_| VmError::Trap(exceptions::Trap::error(atom("system_limit"))))
        }
        Some("min_unique_monotonic_integer" | "min_unique_integer") => {
            TermBuilder::new(&mut arinsal_bifs::FragmentingHeap(&mut process.heap))
                .int_from_i128(-576_460_752_303_423_488)
                .map_err(|_| VmError::Trap(exceptions::Trap::error(atom("system_limit"))))
        }
        Some("nbalance") => Ok(Term::small(0).unwrap()),
        Some("monitoring_nodes") => {
            let Some(runtime) = &process.runtime else {
                return Ok(Term::NIL);
            };
            let pids = runtime.processes.lock().unwrap().clone();
            let mut by_pid = pids
                .into_iter()
                .map(|pid| (pid, Vec::<Term>::new()))
                .collect::<std::collections::BTreeMap<_, _>>();
            let tables = crate::node_tables::lock();
            for monitor in &tables.monitors {
                if let Some(nodes) = by_pid.get_mut(&monitor.pid)
                    && let Ok(node) = global_atoms().intern(&monitor.node)
                {
                    let node = Term::atom(node);
                    if !nodes.contains(&node) {
                        nodes.push(node);
                    }
                }
            }
            let mut entries = Vec::with_capacity(by_pid.len());
            for (pid, nodes) in by_pid {
                let Some(pid) = pid.to_term() else { continue };
                let nodes = list(process, &nodes)?;
                entries.push(tuple(process, &[pid, nodes])?);
            }
            list(process, &entries)
        }
        Some("node_and_dist_references") => {
            ctx.block_thread_progress(std::time::Duration::ZERO);
            node_and_dist_references(process)
        }
        Some("memory") => {
            ctx.block_thread_progress(std::time::Duration::ZERO);
            crate::natives::sys::snapshot_process(process, process.gc_live);
            let values = crate::natives::sys::memory_values(vm, process);
            let mut entries = Vec::with_capacity(values.len());
            for (name, value) in values {
                let value = int(process, value as usize)?;
                entries.push(tuple(process, &[atom(name), value])?);
            }
            list(process, &entries)
        }
        Some("processes") => {
            let processes = process
                .runtime
                .as_ref()
                .map(|runtime| {
                    let mut pids = runtime.processes.lock().unwrap().clone();
                    pids.extend(runtime.system_processes.lock().unwrap().iter().copied());
                    pids.iter()
                        .filter_map(|pid| pid.to_term())
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            list(process, &processes)
        }
        Some("processes_bif_info") => tuple(
            process,
            &[
                atom("ptab_list_bif_info"),
                Term::small(40).unwrap(),
                Term::small(1049).unwrap(),
                Term::small(1000).unwrap(),
                Term::small(25).unwrap(),
                Term::small(1).unwrap(),
                Term::small(10).unwrap(),
                Term::small(40).unwrap(),
                Term::small(75).unwrap(),
                Term::small(0).unwrap(),
            ],
        ),
        Some("next_pid") => {
            let next = process
                .runtime
                .as_ref()
                .and_then(|runtime| runtime.scheduler().ok())
                .map(|scheduler| scheduler.test_next_process_id(false, 0));
            match next {
                Some(next) => {
                    TermBuilder::new(&mut arinsal_bifs::FragmentingHeap(&mut process.heap))
                        .int_from_i128(i128::from(next))
                        .map_err(|_| VmError::Trap(exceptions::Trap::error(atom("system_limit"))))
                }
                None => Ok(atom("false")),
            }
        }
        Some("next_port") => {
            let next = process
                .runtime
                .as_ref()
                .and_then(|runtime| crate::port::test_next_port_id(runtime, false, 0));
            match next {
                Some(next) => {
                    TermBuilder::new(&mut arinsal_bifs::FragmentingHeap(&mut process.heap))
                        .int_from_i128(next as i128)
                        .map_err(|_| VmError::Trap(exceptions::Trap::error(atom("system_limit"))))
                }
                None => Ok(atom("false")),
            }
        }
        _ => Err(badarg()),
    }
}

/// One scheduler-wide round of `erts_debug:set_internal_state(wait, _)`.
///
/// Port of erts/emulator/beam/erl_process.c:2372-2530 (init_thr_debug_wait_completed,
/// later_thr_debug_wait_completed, setup_thr_debug_wait_completed, thr_debug_wait_completed),
/// OTP-29.1.1. erts flushes later-ops on every scheduler, waits for thread progress, sets up
/// the wait flags on every scheduler and finally lets each scheduler run the flagged work (which
/// drains its delayed deallocations and canceled timers first); the last scheduler resumes the
/// waiter. Each phase needs every scheduler to reach its aux-work point, so a phase is one round.
fn debug_wait_round(
    owner: std::sync::Weak<crate::process::Runtime>,
    schedulers: usize,
    pid: arinsal_sched::Pid,
    completion: std::sync::Arc<std::sync::atomic::AtomicBool>,
    rounds_left: u32,
    request: &mut dyn FnMut(Box<dyn Fn(usize) + Send + Sync>),
) {
    let remaining = std::sync::atomic::AtomicUsize::new(schedulers);
    request(Box::new(move |_worker| {
        if remaining.fetch_sub(1, Ordering::AcqRel) != 1 {
            return;
        }
        let Some(runtime) = owner.upgrade() else {
            return;
        };
        let Ok(scheduler) = runtime.scheduler() else {
            return;
        };
        if rounds_left > 1 {
            let next = scheduler.clone();
            debug_wait_round(
                owner.clone(),
                schedulers,
                pid,
                completion.clone(),
                rounds_left - 1,
                &mut |work| next.request_aux_work_all(work),
            );
            return;
        }
        completion.store(true, Ordering::Release);
        runtime.debug_wait_active.store(false, Ordering::Release);
        debug_wait_wake(scheduler, pid, completion.clone());
    }));
}

/// Wake the waiter once its latch is set. A waiter that is not WAITING is runnable or
/// running and re-checks the latch at the end of its slice; only the short window in which
/// another scheduler is still parking it needs a retry, so the retry is bounded instead of
/// spinning forever on the scheduler that has to run it.
fn debug_wait_wake(
    scheduler: std::sync::Arc<arinsal_sched::Scheduler<Process>>,
    pid: arinsal_sched::Pid,
    completion: std::sync::Arc<std::sync::atomic::AtomicBool>,
) {
    for _ in 0..10_000 {
        if std::sync::Arc::strong_count(&completion) <= 1
            || !scheduler.lookup(pid)
            || scheduler.wake(pid)
        {
            return;
        }
        std::thread::yield_now();
    }
}

/// Port of erts/emulator/beam/erl_bif_info.c:5036-5500, OTP-29.1.1.
fn internal_state_set(
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    selector: Term,
    value: Term,
) -> Result<Term, VmError> {
    if selector == atom("available_internal_state") {
        if value != atom("true") && value != atom("false") {
            return Err(badarg());
        }
        let previous = INTERNAL_STATE.swap(value == atom("true"), Ordering::Relaxed);
        return Ok(atom(if previous { "true" } else { "false" }));
    }
    if !INTERNAL_STATE.load(Ordering::Relaxed) {
        return Err(undef());
    }
    if arg_name(selector).as_deref() == Some("wait") {
        let kind = arg_name(value).ok_or_else(badarg)?;
        if !matches!(
            kind.as_str(),
            "deallocations" | "timer_cancellations" | "aux_work" | "thread_progress"
        ) {
            return Err(badarg());
        }
        let runtime = process.runtime.as_ref().ok_or_else(badarg)?.clone();
        if let Some(completion) = process.cold_mut().debug_wait_completion.clone() {
            if completion.load(Ordering::Acquire) {
                process.cold_mut().debug_wait_completion = None;
                runtime.debug_wait_active.store(false, Ordering::Release);
                return Ok(atom("ok"));
            }
            process.force_yield = true;
            return Ok(atom("ok"));
        }
        // Port of erts/emulator/beam/erl_process.c:2499 (erts_debug_wait_completed): only one
        // process at a time can wait.
        if runtime
            .debug_wait_active
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(VmError::Trap(exceptions::Trap::error(atom("system_limit"))));
        }
        let completion = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        process.cold_mut().debug_wait_completion = Some(completion.clone());
        let rounds = if kind == "aux_work" { 1 } else { 4 };
        debug_wait_round(
            std::sync::Arc::downgrade(&runtime),
            ctx.scheduler_count(),
            ctx.pid(),
            completion,
            rounds,
            &mut |work| ctx.request_aux_work_all(work),
        );
        process.force_yield = true;
        return Ok(atom("ok"));
    }
    match arg_name(selector).as_deref() {
        Some("reds_left") => {
            let Some(reductions) = to_owned(value).ok().and_then(|term| owned_signed(&term)) else {
                return Err(badarg());
            };
            if (0..=4000).contains(&reductions) {
                process.reductions = reductions as i32;
            }
            return Ok(atom("true"));
        }
        Some("block" | "sleep" | "block_scheduler") => {
            let Some(milliseconds) = to_owned(value).ok().and_then(|term| owned_signed(&term))
            else {
                return Err(badarg());
            };
            if milliseconds > 0 {
                let duration = std::time::Duration::from_millis(milliseconds as u64);
                if arg_name(selector).as_deref() == Some("block") {
                    ctx.block_thread_progress(duration);
                } else {
                    std::thread::sleep(duration);
                }
            }
            return Ok(atom("true"));
        }
        Some("test_long_gc_sleep") => {
            let Some(milliseconds) = to_owned(value).ok().and_then(|term| owned_uint(&term)) else {
                return Err(badarg());
            };
            TEST_LONG_GC_SLEEP.store(milliseconds, Ordering::Relaxed);
            return Ok(atom("true"));
        }
        Some("multizero_timeout_in_timeout") => {
            let Some(timeout) = to_owned(value).ok().and_then(|term| owned_signed(&term)) else {
                return Err(badarg());
            };
            if process.runtime.is_none() {
                return Err(VmError::Trap(exceptions::Trap::error(atom("system_limit"))));
            }
            // Port of erts/emulator/beam/erl_bif_info.c:4976-4996,5402-5412, OTP-29.1.1: a
            // timer callback that starts a zero timer callback from within a timer callback.
            let done = Message::copy_from(atom("multizero_timeout_in_timeout_done"))?;
            ctx.start_timer_callback(
                timeout.max(0) as u64,
                Box::new(move |timers| {
                    timers.start_timer_callback(
                        0,
                        Box::new(move |timers| {
                            timers
                                .start_timer_callback(0, Box::new(move |timers| timers.send(done)));
                        }),
                    );
                }),
            )
            .map_err(|_| VmError::Trap(exceptions::Trap::error(atom("system_limit"))))?;
            return Ok(atom("ok"));
        }
        Some("next_pid") | Some("next_port") => {
            let Some(next) = to_owned(value).ok().and_then(|term| owned_uint(&term)) else {
                return Err(badarg());
            };
            let result = match arg_name(selector).as_deref() {
                Some("next_pid") => process
                    .runtime
                    .as_ref()
                    .and_then(|runtime| runtime.scheduler().ok())
                    .map(|scheduler| i128::from(scheduler.test_next_process_id(true, next))),
                _ => process
                    .runtime
                    .as_ref()
                    .and_then(|runtime| crate::port::test_next_port_id(runtime, true, next))
                    .map(i128::from),
            };
            return match result {
                Some(result) => {
                    TermBuilder::new(&mut arinsal_bifs::FragmentingHeap(&mut process.heap))
                        .int_from_i128(result)
                        .map_err(|_| VmError::Trap(exceptions::Trap::error(atom("system_limit"))))
                }
                None => Ok(atom("false")),
            };
        }
        Some("force_gc") => {
            let Some(pid) = arinsal_sched::Pid::from_term(value) else {
                return Ok(atom("false"));
            };
            let found = process
                .runtime
                .as_ref()
                .is_some_and(|runtime| runtime.processes.lock().unwrap().contains(&pid));
            if !found {
                return Ok(atom("false"));
            }
            if pid == ctx.pid() {
                process.force_gc()?;
            } else {
                ctx.signal(pid, arinsal_sched::Signal::GarbageCollect)
                    .map_err(|_| VmError::Trap(exceptions::Trap::error(atom("system_limit"))))?;
            }
            return Ok(atom("true"));
        }
        Some("unique_monotonic_integer_state") => {
            let Some(state) = to_owned(value).ok().and_then(|term| {
                owned_signed(&term)
                    .map(|value| value as u64)
                    .or_else(|| owned_uint(&term))
            }) else {
                return Err(badarg());
            };
            UNIQUE_MONOTONIC_INTEGER_STATE.store(state, Ordering::Relaxed);
            return Ok(atom("true"));
        }
        Some("binary_loop_limit" | "re_loop_limit" | "unicode_loop_limit") => {
            let (limit, default) = match arg_name(selector).as_deref() {
                Some("binary_loop_limit") => (&BINARY_LOOP_LIMIT, 0),
                Some("re_loop_limit") => (&RE_LOOP_LIMIT, 64_000),
                _ => (&UNICODE_LOOP_LIMIT, 40_000),
            };
            let next = if value == atom("default") {
                default
            } else {
                let Some(value) = to_owned(value).ok().and_then(|term| owned_uint(&term)) else {
                    return Err(badarg());
                };
                value
            };
            let previous = limit.swap(next, Ordering::Relaxed);
            return int(process, previous as usize);
        }
        Some("gc_state") if value == atom("true") || value == atom("false") => {
            let previous = process.set_gc_enabled(value == atom("true"));
            return Ok(atom(if previous { "true" } else { "false" }));
        }
        Some("inconsistent_heap") if value == atom("start") => {
            process.set_gc_enabled(false);
            let index = process.heap.used_words();
            let broken = tuple(process, &[atom("ok")])?;
            let base = process.heap.heap_bounds().0 as usize;
            let address = broken.tagged_word() & !7;
            let Some(word_index) = address
                .checked_sub(base as u64)
                .and_then(|offset| usize::try_from(offset / 8).ok())
            else {
                return Err(badarg());
            };
            if word_index != index
                || !process.heap.debug_write_heap_word(word_index, 1234 << 6)
                || !process.heap.debug_write_heap_word(word_index + 1, u64::MAX)
            {
                return Err(badarg());
            }
            return Ok(broken);
        }
        Some("inconsistent_heap") => {
            let address = value.tagged_word() & !7;
            let base = process.heap.heap_bounds().0 as usize;
            let Some(word_index) = address
                .checked_sub(base as u64)
                .and_then(|offset| usize::try_from(offset / 8).ok())
            else {
                return Err(badarg());
            };
            if !process.heap.debug_write_heap_word(word_index, 1 << 6)
                || !process
                    .heap
                    .debug_write_heap_word(word_index + 1, atom("ok").tagged_word())
            {
                return Err(badarg());
            }
            process.set_gc_enabled(true);
            return Ok(atom("ok"));
        }
        Some("debugger_support") if value == atom("true") => {
            DEBUGGER_SUPPORT.store(true, Ordering::Relaxed);
            return Ok(atom("ok"));
        }
        Some("debugger_support") => return Ok(atom("badarg")),
        Some("jit_asm_dump") if value == atom("true") || value == atom("false") => {
            let previous = JIT_ASM_DUMP.swap(value == atom("true"), Ordering::Relaxed);
            return Ok(atom(if previous { "true" } else { "false" }));
        }
        Some("ets_force_split" | "ets_debug_random_split_join") => {
            let Ok(owned) = to_owned(value) else {
                return Err(badarg());
            };
            let OwnedTerm::Tuple(parts) = &owned else {
                return Err(badarg());
            };
            let [OwnedTerm::Ref { ids, .. }, on] = parts.as_slice() else {
                return Err(badarg());
            };
            let Some(&[tag, low, high]) = ids.get(..3) else {
                return Err(badarg());
            };
            if tag != 0x4554_5329 {
                return Err(badarg());
            }
            let tid = arinsal_ets::Tid(u64::from(low) | (u64::from(high) << 32));
            let random = arg_name(selector).as_deref() == Some("ets_debug_random_split_join");
            let enabled = matches!(on, OwnedTerm::Atom(name) if name == "true");
            let changed = process.runtime.as_ref().is_some_and(|runtime| {
                runtime
                    .ets
                    .read()
                    .unwrap()
                    .debug_set_catree_mode(tid, random, enabled)
            });
            return if changed {
                Ok(atom("ok"))
            } else {
                Err(badarg())
            };
        }
        Some("ets_force_trap") => return Ok(atom("notsup")),
        Some("proc_sig_buffers") if value == atom("true") => {
            return Ok(atom(
                if process.message_queue_data() == crate::process::MessageQueueData::OffHeap
                    && ctx.force_parallel_signal_buffers()
                {
                    "true"
                } else {
                    "false"
                },
            ));
        }
        Some("proc_sig_buffers") => return Ok(atom("notsup")),
        Some("abort") => {
            let reason = to_owned(value).map_err(|_| badarg())?;
            eprintln!("{reason}");
            std::process::abort();
        }
        Some("broken_halt") => {
            let reason = to_owned(value).map_err(|_| badarg())?;
            eprintln!("{reason}");
            std::process::exit(1);
        }
        Some("kill_dist_connection") => {
            let Some(node) = arg_name(value) else {
                return Ok(atom("false"));
            };
            let Some(runtime) = process.runtime.as_ref() else {
                return Ok(atom("false"));
            };
            let (port_id, connection_id) = {
                let tables = crate::node_tables::lock();
                let Some(entry) = tables.entries.get(&node).filter(|entry| entry.connected) else {
                    return Ok(atom("false"));
                };
                (
                    entry.dist.as_ref().and_then(|state| state.port_id),
                    entry.connection_id,
                )
            };
            if let Some(port_id) = port_id {
                if !crate::port::close_by_id(process, ctx, port_id)? {
                    return Ok(atom("false"));
                }
                crate::dist::port_connection_closed(runtime, port_id)?;
                return Ok(atom("true"));
            }
            return Ok(atom(
                if crate::dist::kill_connection(runtime, &node, connection_id)? {
                    "true"
                } else {
                    "false"
                },
            ));
        }
        Some("wait")
            if [
                "deallocations",
                "timer_cancellations",
                "aux_work",
                "thread_progress",
            ]
            .iter()
            .any(|name| value == atom(name)) =>
        {
            if value == atom("thread_progress") {
                ctx.block_thread_progress(std::time::Duration::ZERO);
            }
            return Ok(atom("ok"));
        }
        Some("colliding_names") => {
            let Ok(owned) = to_owned(value) else {
                return Err(badarg());
            };
            let OwnedTerm::Tuple(parts) = &owned else {
                return Err(badarg());
            };
            let [OwnedTerm::Atom(name), count] = parts.as_slice() else {
                return Err(badarg());
            };
            let Some(count) = owned_uint(count) else {
                return Err(badarg());
            };
            return colliding_names(process, name, count);
        }
        Some("fill_heap") => {
            let Some(fill_fullsweep) = to_owned(value).ok().and_then(|term| match &term {
                OwnedTerm::Atom(name) if name == "true" => Some(true),
                OwnedTerm::Atom(name) if name == "false" => Some(false),
                _ => None,
            }) else {
                return Err(badarg());
            };
            let left = process.heap.free_words();
            if left > 1 {
                let filler = BigInt::from(1_u8) << ((left - 2) * 64);
                from_owned(&OwnedTerm::BigInt(filler), &mut process.heap)
                    .map_err(|_| VmError::Trap(exceptions::Trap::error(atom("system_limit"))))?;
            }
            if fill_fullsweep {
                process.heap.set_fullsweep_after(0);
            }
            return Ok(atom("ok"));
        }
        Some("mbuf") => {
            return arinsal_term::copy_term(
                value,
                &mut arinsal_term::FragmentAlloc::new(&mut process.heap),
            )
            .map_err(|_| VmError::Trap(exceptions::Trap::error(atom("system_limit"))));
        }
        Some("make") if value == atom("magic_ref") => {
            let owner = arinsal_term::MagicRef::new(());
            let address = std::sync::Arc::as_ptr(&owner) as usize;
            let reference = TermBuilder::new(&mut process.heap)
                .magic_ref(owner)
                .map_err(|_| VmError::Trap(exceptions::Trap::error(atom("system_limit"))))?;
            let address = TermBuilder::new(&mut arinsal_bifs::FragmentingHeap(&mut process.heap))
                .int_from_i128(address as i128)
                .map_err(|_| VmError::Trap(exceptions::Trap::error(atom("system_limit"))))?;
            return tuple(process, &[reference, address]);
        }
        Some("binary") => {
            let Some(size) = to_owned(value).ok().and_then(|term| owned_signed(&term)) else {
                return Err(badarg());
            };
            let Ok(size) = usize::try_from(size) else {
                return Ok(atom("false"));
            };
            let mut bytes = Vec::new();
            if bytes.try_reserve_exact(size).is_err() {
                return Ok(atom("false"));
            }
            bytes.resize(size, 0);
            return TermBuilder::new(&mut arinsal_bifs::FragmentingHeap(&mut process.heap))
                .binary(&bytes)
                .map_err(|_| VmError::Trap(exceptions::Trap::error(atom("system_limit"))));
        }
        Some("node_tab_delayed_delete") => {
            let Some(timeout) = to_owned(value).ok().and_then(|term| owned_signed(&term)) else {
                return Err(badarg());
            };
            ctx.block_thread_progress(std::time::Duration::ZERO);
            crate::node_tables::test_node_tab_delayed_delete(timeout);
            return Ok(atom("ok"));
        }
        Some("remove_dflags") => {
            let Some(flags) = to_owned(value).ok().and_then(|term| owned_uint(&term)) else {
                return Err(badarg());
            };
            if flags & crate::node_tables::DFLAG_DIST_MANDATORY != 0 {
                return Err(badarg());
            }
            crate::node_tables::test_remove_dflags(Some(flags));
            return Ok(atom("ok"));
        }
        Some("code_mod_permission") => {
            let acquire = match arg_name(value).as_deref() {
                Some("true") => true,
                Some("false") => false,
                _ => return Err(badarg()),
            };
            if !process.runtime.as_ref().is_some_and(|runtime| {
                crate::natives::code::try_code_mod_permission(runtime, ctx.pid(), acquire)
            }) {
                return Err(VmError::Unsupported(
                    "code_mod_permission must resume through its BIF continuation".into(),
                ));
            }
            if !acquire {
                crate::natives::code::wake_code_mod_permission_waiter(process, ctx);
            }
            return Ok(atom("true"));
        }
        Some("process_uniq_counter") => {
            let Some(counter) = to_owned(value).ok().and_then(|term| owned_signed(&term)) else {
                return Err(badarg());
            };
            process.uniq_counter = counter;
            return Ok(atom("ok"));
        }
        Some("proc_sig_block") => {
            let Ok(owned) = to_owned(value) else {
                return Err(badarg());
            };
            let OwnedTerm::Tuple(parts) = &owned else {
                return Err(badarg());
            };
            let [
                OwnedTerm::Pid {
                    node,
                    id,
                    serial,
                    creation: 0,
                },
                time,
            ] = parts.as_slice()
            else {
                return Err(badarg());
            };
            let Some(milliseconds) = owned_signed(time) else {
                return Err(badarg());
            };
            if node != "nonode@nohost" {
                return Err(badarg());
            }
            let pid = arinsal_sched::Pid::new(*id, *serial);
            let Some(runtime) = process.runtime.as_ref() else {
                return Ok(atom("false"));
            };
            if !runtime.processes.lock().unwrap().contains(&pid) {
                return Ok(atom("false"));
            }
            return Ok(atom(
                if ctx
                    .signal(pid, arinsal_sched::Signal::ProcSigBlock(milliseconds))
                    .is_ok()
                {
                    "true"
                } else {
                    "false"
                },
            ));
        }
        _ => {}
    }
    Err(badarg())
}

fn system_check(selector: Term) -> Result<Term, VmError> {
    if selector == atom("schedulers") {
        Ok(atom("ok"))
    } else {
        Err(badarg())
    }
}

/// Port of erts/emulator/beam/erl_bif_trace.c:3276-3388, OTP-29.1.1.
fn system_monitor_get(process: &mut Process, session: Term) -> Result<Term, VmError> {
    let runtime = process.runtime.clone().ok_or_else(badarg)?;
    let state = if session == atom("legacy") {
        runtime.system_monitor.lock().unwrap().clone()
    } else {
        let key = to_owned(session).map_err(|_| badarg())?;
        runtime
            .session_monitors
            .lock()
            .unwrap()
            .iter()
            .find(|(owner, _)| *owner == key)
            .map(|(_, state)| state.clone())
    };
    let Some(state) = state else {
        return Ok(atom("undefined"));
    };
    let owned = OwnedTerm::Tuple(vec![
        state.receiver,
        OwnedTerm::list(monitor_options(&state.options)),
    ]);
    from_owned(
        &owned,
        &mut arinsal_bifs::FragmentingHeap(&mut process.heap),
    )
    .map_err(|_| VmError::Trap(exceptions::Trap::error(atom("system_limit"))))
}

fn monitor_options(options: &HashMap<&'static str, MonitorOption>) -> Vec<OwnedTerm> {
    let mut result = Vec::new();
    for name in ["busy_dist_port", "busy_port"] {
        if matches!(options.get(name), Some(MonitorOption::Bool(true))) {
            result.push(OwnedTerm::atom(name));
        }
    }
    for name in ["large_heap", "long_schedule", "long_gc"] {
        if let Some(MonitorOption::Limit(value)) = options.get(name) {
            result.push(OwnedTerm::tuple(vec![
                OwnedTerm::atom(name),
                OwnedTerm::Int(*value as i64),
            ]));
        }
    }
    if let Some(MonitorOption::Queue(off, on)) = options.get("long_message_queue") {
        result.push(OwnedTerm::tuple(vec![
            OwnedTerm::atom("long_message_queue"),
            OwnedTerm::tuple(vec![
                OwnedTerm::Int(*off as i64),
                OwnedTerm::Int(*on as i64),
            ]),
        ]));
    }
    result
}

fn owned_uint(value: &OwnedTerm) -> Option<u64> {
    match value {
        OwnedTerm::Int(value) => u64::try_from(*value).ok(),
        OwnedTerm::BigInt(value) => value.to_u64(),
        _ => None,
    }
}

fn parse_monitor_options(term: Term) -> Option<HashMap<&'static str, MonitorOption>> {
    let owned = to_owned(term).ok()?;
    let entries = match &owned {
        OwnedTerm::Nil => Vec::new(),
        OwnedTerm::List { elems, tail } if **tail == OwnedTerm::Nil => elems.clone(),
        _ => return None,
    };
    let mut options = HashMap::new();
    for entry in &entries {
        let (name, value) = match entry {
            OwnedTerm::Atom(name) => (name.as_str(), OwnedTerm::Atom("true".into())),
            OwnedTerm::Tuple(pair) if pair.len() == 2 => {
                let OwnedTerm::Atom(name) = &pair[0] else {
                    return None;
                };
                (name.as_str(), pair[1].clone())
            }
            _ => return None,
        };
        let (key, parsed) = match name {
            "busy_port" | "busy_dist_port" => {
                let OwnedTerm::Atom(value) = &value else {
                    return None;
                };
                let enabled = match value.as_str() {
                    "true" => true,
                    "false" => false,
                    _ => return None,
                };
                (
                    if name == "busy_port" {
                        "busy_port"
                    } else {
                        "busy_dist_port"
                    },
                    MonitorOption::Bool(enabled),
                )
            }
            "long_gc" | "long_schedule" | "large_heap" => {
                let minimum = if name == "large_heap" { 16_384 } else { 1 };
                match &value {
                    OwnedTerm::Atom(value) if value == "false" => continue,
                    value => {
                        let value = owned_uint(value)?;
                        let key = match name {
                            "long_gc" => "long_gc",
                            "long_schedule" => "long_schedule",
                            _ => "large_heap",
                        };
                        (key, MonitorOption::Limit(value.max(minimum)))
                    }
                }
            }
            "long_message_queue" => match &value {
                OwnedTerm::Atom(value) if value == "false" => continue,
                OwnedTerm::Tuple(pair) if pair.len() == 2 => {
                    let (Some(off), Some(on)) = (owned_uint(&pair[0]), owned_uint(&pair[1])) else {
                        return None;
                    };
                    if off >= on || on == 0 {
                        return None;
                    }
                    ("long_message_queue", MonitorOption::Queue(off, on))
                }
                _ => return None,
            },
            _ => return None,
        };
        options.insert(key, parsed);
    }
    Some(options)
}

/// Port of erts/emulator/beam/erl_bif_trace.c:3560-3715, OTP-29.1.1.
fn system_monitor_set(
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    args: &[Term],
) -> Result<Term, VmError> {
    let runtime = process.runtime.clone().ok_or_else(badarg)?;
    // `None` is the legacy (global) monitor, `Some` the monitor of a dynamic trace session.
    let key = if args[0] == atom("legacy") {
        None
    } else {
        Some(to_owned(args[0]).map_err(|_| badarg())?)
    };
    let store = |state: Option<SystemMonitorState>| {
        match &key {
            None => *runtime.system_monitor.lock().unwrap() = state,
            Some(key) => {
                let mut sessions = runtime.session_monitors.lock().unwrap();
                sessions.retain(|(owner, _)| owner != key);
                if let Some(state) = state {
                    sessions.push((key.clone(), state));
                }
            }
        }
        runtime.long_message_queues.lock().unwrap().clear();
        refresh_system_monitor_flags(&runtime);
    };
    let old = match &key {
        None => runtime.system_monitor.lock().unwrap().clone(),
        Some(key) => runtime
            .session_monitors
            .lock()
            .unwrap()
            .iter()
            .find(|(owner, _)| owner == key)
            .map(|(_, state)| state.clone()),
    };
    let old_term = if let Some(state) = old {
        from_owned(
            &OwnedTerm::Tuple(vec![
                state.receiver,
                OwnedTerm::list(monitor_options(&state.options)),
            ]),
            &mut arinsal_bifs::FragmentingHeap(&mut process.heap),
        )
        .map_err(|_| VmError::Trap(exceptions::Trap::error(atom("system_limit"))))?
    } else {
        atom("undefined")
    };
    let options = parse_monitor_options(args[2]).ok_or_else(badarg)?;
    if args[1] == atom("undefined") || args[2] == Term::NIL {
        store(None);
        return Ok(old_term);
    }
    let receiver = to_owned(args[1]).map_err(|_| badarg())?;
    let OwnedTerm::Pid {
        node, creation: 0, ..
    } = &receiver
    else {
        return Err(badarg());
    };
    if node != "nonode@nohost" {
        return Err(badarg());
    }
    let matches_live_pid = process.runtime.as_ref().is_some_and(|runtime| {
        runtime
            .processes
            .lock()
            .unwrap()
            .iter()
            .filter_map(|pid| pid.to_term())
            .filter_map(|pid| to_owned(pid).ok())
            .any(|pid| pid == receiver)
    }) || ctx
        .pid()
        .to_term()
        .and_then(|pid| to_owned(pid).ok())
        .as_ref()
        == Some(&receiver);
    if !matches_live_pid {
        return Err(badarg());
    }
    let state = SystemMonitorState { receiver, options };
    store(Some(state));
    Ok(old_term)
}

/// Native-family dispatcher.
pub(crate) fn call(
    vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    module: &str,
    function: &str,
    args: super::NativeArgs<'_>,
) -> Option<Result<Term, VmError>> {
    if !super::listed(IMPLEMENTED, module, function, args.len() as u8) {
        return None;
    }
    Some(args.with_values(process, |process, values| {
        build(vm, process, ctx, values, module, function)
    }))
}

#[allow(dead_code)]
fn _keep_helpers_visible() {
    let _ = arg_name as fn(Term) -> Option<String>;
}

#[cfg(test)]
mod check_io_tests {
    use super::*;
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;

    #[test]
    fn check_io_debug_counts_live_nif_selection() {
        let previous = INTERNAL_STATE.swap(true, Ordering::Relaxed);
        let (reader, _writer) = UnixStream::pair().unwrap();
        let registration = crate::check_io::register(
            reader.as_raw_fd(),
            crate::check_io::InterestSet {
                readable: true,
                writable: false,
            },
            |_, _| {},
        )
        .unwrap();
        // Same counters the `check_io_debug` selector reports as {0, UsedFds, DriverSelects, NifSelects}.
        let stats = crate::check_io::debug_info();
        assert_eq!(
            (stats.used_fds, stats.driver_selects, stats.nif_selects),
            (1, 0, 1)
        );
        crate::check_io::deregister(registration);
        INTERNAL_STATE.store(previous, Ordering::Relaxed);
    }
}
