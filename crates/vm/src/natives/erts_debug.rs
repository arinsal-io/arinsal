//! Introspection natives implemented by the emulator debug modules.

use crate::dirty::{DirtyBifException, DirtyBifOutcome};
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
static JIT_ASM_DUMP: AtomicBool = AtomicBool::new(false);
static TEST_LONG_GC_SLEEP: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static UNIQUE_MONOTONIC_INTEGER_STATE: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(u64::MAX);
static BINARY_LOOP_LIMIT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static RE_LOOP_LIMIT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(64_000);
static UNICODE_LOOP_LIMIT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(40_000);

/// The `binary_loop_limit` debug state: zero means no limit.
pub(crate) fn binary_loop_limit() -> u64 {
    BINARY_LOOP_LIMIT.load(Ordering::Relaxed)
}
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
    key: Option<u64>,
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
    let Some(runtime) = process.runtime else {
        return;
    };
    system_monitor_clear_receiver(runtime, pid);
}

/// `erts_system_monitor_clear` for the monitors whose receiver is `pid`.
// Port of erts/emulator/beam/erl_trace.c (erts_system_monitor_clear), OTP-29.1.1.
pub(crate) fn system_monitor_clear_receiver(
    runtime: &crate::process::Runtime,
    pid: arinsal_sched::Pid,
) {
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
    let (Some(runtime), Some(key)) = (
        process.runtime.as_ref(),
        crate::natives::proc::trace_session_id(process, session),
    ) else {
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
        .map(|mut state| {
            state.key = None;
            state
        })
        .collect();
    states.extend(
        runtime
            .session_monitors
            .lock()
            .unwrap()
            .iter()
            .map(|(key, state)| {
                let mut state = state.clone();
                state.key = Some(*key);
                state
            }),
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
    // Port of erl_gc.c:803 (`if (erts_system_monitor_long_gc)`), OTP-29.1.1.
    arinsal_term::set_gc_clock_for_long_gc(flags & MONITOR_LONG_GC != 0);
}

/// Emit the monitor events that are observable from the VM's collection hook.
// Port of erts/emulator/beam/erl_gc.c:904-920 and erl_trace.c:1604-1741, OTP-29.1.1.
pub(crate) fn after_collection(process: &mut Process, elapsed_nanoseconds: u64) {
    // Port of erl_gc.c:904-920: long_gc and large_heap are global flags tested
    // before any monitor state is touched.
    let Some(runtime) = process.runtime.as_ref() else {
        return;
    };
    if runtime.system_monitor_flags.load(Ordering::Relaxed) == 0 {
        return;
    }
    for state in monitor_states(runtime) {
        after_collection_one(process, elapsed_nanoseconds, &state);
    }
}

fn after_collection_one(
    process: &mut Process,
    elapsed_nanoseconds: u64,
    state: &SystemMonitorState,
) {
    let Some(runtime) = process.runtime else {
        return;
    };
    let flags = runtime.system_monitor_flags.load(Ordering::Relaxed);
    if flags == 0 {
        return;
    }
    let Some(pid) = process.self_pid else {
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
    let sizes = crate::natives::proc::monitor_heap_sizes(process);
    let mut events = Vec::new();
    if flags & MONITOR_LARGE_HEAP != 0
        && let Some(MonitorOption::Limit(limit)) = state.options.get("large_heap")
        // erl_gc.c: `size = HEAP_SIZE(p) + (OLD_HEND(p) - OLD_HEAP(p))`.
        && (sizes[1].1 + sizes[0].1) as u64 >= *limit
    {
        events.push(("large_heap", sizes.to_vec()));
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
        let mut values = vec![("timeout", elapsed_ms as usize)];
        values.extend(sizes);
        events.push(("long_gc", values));
    }
    for (kind, values) in events {
        send_system_monitor_event(process, runtime, pid, receiver, kind, values);
    }
}

fn send_system_monitor_event(
    process: &mut Process,
    runtime: &'static crate::process::Runtime,
    pid: arinsal_sched::Pid,
    receiver: arinsal_sched::Pid,
    kind: &str,
    values: Vec<(&str, usize)>,
) {
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
        &mut arinsal_bifs::ProcessHeapHandle(&mut process.heap),
    ) && let Ok(message) = Message::copy_from(term)
    {
        enqueue_sysmon(runtime, pid, receiver, message);
    }
}

/// Emit long-schedule events after a scheduler execution slice.
// Port of erts/emulator/beam/erl_trace.c:1510-1595, OTP-29.1.1.
/// Whether a long_schedule system monitor is active, so a schedule-in records its start time.
// Port of erts/emulator/beam/jit/arm/process_main.cpp:84-85,173-180 (start_time only set when
// erts_system_monitor_long_schedule != 0), OTP-29.1.1.
pub(crate) fn long_schedule_monitored(process: &Process) -> bool {
    process.runtime.as_ref().is_some_and(|runtime| {
        runtime.system_monitor_flags.load(Ordering::Relaxed) & MONITOR_LONG_SCHEDULE != 0
    })
}

pub(crate) fn after_schedule(process: &mut Process, elapsed_nanoseconds: u64) {
    if let Some(runtime) = process.runtime {
        for state in monitor_states(runtime) {
            after_schedule_one(process, elapsed_nanoseconds, &state);
        }
    }
}

fn after_schedule_one(process: &mut Process, elapsed_nanoseconds: u64, state: &SystemMonitorState) {
    let Some(runtime) = process.runtime else {
        return;
    };
    let flags = runtime.system_monitor_flags.load(Ordering::Relaxed);
    if flags & MONITOR_LONG_SCHEDULE == 0 {
        return;
    }
    let Some(pid) = process.self_pid else {
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
        &mut arinsal_bifs::ProcessHeapHandle(&mut process.heap),
    ) && let Ok(message) = Message::copy_from(term)
    {
        enqueue_sysmon(runtime, pid, receiver, message);
    }
}

/// Emit a long-schedule event for a port task that ran longer than the monitor limit.
// Port of erts/emulator/beam/erl_trace.c:1591 (monitor_long_schedule_port), OTP-29.1.1.
/// Whether a `long_schedule` system monitor is on.
pub(crate) fn runtime_long_schedule_monitored(runtime: &crate::process::Runtime) -> bool {
    runtime.system_monitor_flags.load(Ordering::Relaxed) & MONITOR_LONG_SCHEDULE != 0
}

pub(crate) fn after_port_task(
    runtime: &'static crate::process::Runtime,
    port: Term,
    from: arinsal_sched::Pid,
    operation: &str,
    elapsed_nanoseconds: u64,
) {
    if runtime.system_monitor_flags.load(Ordering::Relaxed) & MONITOR_LONG_SCHEDULE == 0 {
        return;
    }
    let Ok(port) = to_owned(port) else {
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
            enqueue_sysmon(runtime, from, receiver, message);
        }
    }
}

/// Emit long-message-queue events when the mailbox crosses its configured limits.
// Port of erts/emulator/beam/erl_trace.c:1863-1918, OTP-29.1.1.
pub(crate) fn after_message_queue_change(process: &mut Process) {
    // Port of erts/emulator/beam/erl_proc_sig_queue.h:1978-1994 (erts_chk_sys_mon_long_msgq_on/off),
    // OTP-29.1.1: without a long_message_queue monitor the check is one flag test.
    if process.runtime.as_ref().is_none_or(|runtime| {
        runtime.system_monitor_flags.load(Ordering::Relaxed) & MONITOR_LONG_MESSAGE_QUEUE == 0
    }) {
        return;
    }
    if let Some(runtime) = process.runtime {
        for state in monitor_states(runtime) {
            after_message_queue_change_one(process, &state);
        }
    }
}

fn after_message_queue_change_one(process: &mut Process, state: &SystemMonitorState) {
    let Some(runtime) = process.runtime else {
        return;
    };
    let flags = runtime.system_monitor_flags.load(Ordering::Relaxed);
    if flags & MONITOR_LONG_MESSAGE_QUEUE == 0 {
        return;
    }
    let Some(pid) = process.self_pid else {
        return;
    };
    let Some(MonitorOption::Queue(off, on)) = state.options.get("long_message_queue") else {
        return;
    };
    let count = process.inbox.len() as u64;
    let monitor_key = (pid, state.key);
    let active = runtime
        .long_message_queues
        .lock()
        .unwrap()
        .contains(&monitor_key);
    let value = if !active && count >= *on {
        let mut queues = runtime.long_message_queues.lock().unwrap();
        if !active {
            queues.push(monitor_key);
        }
        Some(true)
    } else if active && count <= *off {
        runtime
            .long_message_queues
            .lock()
            .unwrap()
            .retain(|key| key != &monitor_key);
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
        &mut arinsal_bifs::ProcessHeapHandle(&mut process.heap),
    ) && let Ok(message) = Message::copy_from(term)
    {
        enqueue_sysmon(runtime, pid, receiver, message);
    }
}

/// Emit the event when a sender is suspended on a busy local port.
// Port of erts/emulator/beam/erl_process.c:9396-9397 and erl_trace.c:1928-1937, OTP-29.1.1.
pub(crate) fn notify_busy_port(process: &Process, sender: arinsal_sched::Pid, port_id: u64) {
    if let Some(runtime) = process.runtime {
        for state in monitor_states(runtime) {
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
        Term::atom(arinsal_term::atoms::MONITOR),
        sender.to_term().unwrap_or(Term::NIL),
        Term::atom(arinsal_term::atoms::BUSY_PORT),
        port,
    ]) else {
        return;
    };
    if let Ok(message) = Message::copy_from(event) {
        enqueue_sysmon(runtime, sender, receiver, message);
    }
}

/// Emit the event when a sender is suspended on a busy distribution port.
// Port of erts/emulator/beam/erl_trace.c:1942-1948, OTP-29.1.1.
pub(crate) fn notify_busy_dist_port(process: &Process, sender: arinsal_sched::Pid, port_id: u64) {
    if let Some(runtime) = process.runtime {
        for state in monitor_states(runtime) {
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
    if let Ok(term) = from_owned(&event, &mut arinsal_bifs::ProcessHeapHandle(&mut heap))
        && let Ok(message) = Message::copy_from(term)
    {
        enqueue_sysmon(runtime, sender, receiver, message);
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

fn badarg() -> VmError {
    VmError::Trap(exceptions::Trap::error(Term::atom(
        arinsal_term::atoms::BADARG,
    )))
}

fn badmap(process: &mut Process, value: Term) -> Result<Term, VmError> {
    tuple(process, &[Term::atom(arinsal_term::atoms::BADMAP), value]).map_err(|_| {
        VmError::Trap(exceptions::Trap::error(Term::atom(
            arinsal_term::atoms::SYSTEM_LIMIT,
        )))
    })
}

fn undef() -> VmError {
    VmError::Trap(exceptions::Trap::error(Term::atom(
        arinsal_term::atoms::UNDEF,
    )))
}

fn arg_name(term: Term) -> Option<String> {
    global_atoms()
        .text(term.as_atom()?)
        .map(|text| text.to_string())
}

fn int(process: &mut Process, value: usize) -> Result<Term, VmError> {
    TermBuilder::new(&mut arinsal_bifs::ProcessHeapHandle(&mut process.heap))
        .int_from_i128(value as i128)
        .map_err(|_| {
            VmError::Trap(exceptions::Trap::error(Term::atom(
                arinsal_term::atoms::SYSTEM_LIMIT,
            )))
        })
}

fn list(process: &mut Process, values: &[Term]) -> Result<Term, VmError> {
    TermBuilder::new(&mut arinsal_bifs::ProcessHeapHandle(&mut process.heap))
        .list_from_iter(values.iter().copied())
        .map_err(|_| {
            VmError::Trap(exceptions::Trap::error(Term::atom(
                arinsal_term::atoms::SYSTEM_LIMIT,
            )))
        })
}

fn tuple(process: &mut Process, values: &[Term]) -> Result<Term, VmError> {
    TermBuilder::new(&mut arinsal_bifs::ProcessHeapHandle(&mut process.heap))
        .tuple(values)
        .map_err(|_| {
            VmError::Trap(exceptions::Trap::error(Term::atom(
                arinsal_term::atoms::SYSTEM_LIMIT,
            )))
        })
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

fn scheduler_type_atom(kind: SchedulerType) -> Term {
    Term::atom(match kind {
        SchedulerType::Normal => arinsal_term::atoms::NORMAL,
        SchedulerType::DirtyCpu => arinsal_term::atoms::DIRTY_CPU,
        SchedulerType::DirtyIo => arinsal_term::atoms::DIRTY_IO,
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
    let Ok(message) =
        TermBuilder::new(&mut arinsal_bifs::ProcessHeapHandle(heap)).tuple(&[tag, me])
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
        Some("scheduler") if value == Term::atom(arinsal_term::atoms::TYPE) => {
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
                    copy_term(value, &mut arinsal_bifs::ProcessHeapHandle(heap))
                        .map_err(system_limit)?,
                );
            }
            TermBuilder::new(&mut arinsal_bifs::ProcessHeapHandle(heap))
                .list_from_iter(copies.iter().copied())
                .map_err(system_limit)
        }
        Some("send") => {
            dirty_send_message(env, heap, value, Term::atom(arinsal_term::atoms::OK));
            Ok(Term::atom(arinsal_term::atoms::OK))
        }
        Some("wait") => {
            let milliseconds = value.as_small().ok_or("badarg")?;
            ms_wait(milliseconds, busy);
            Ok(Term::atom(arinsal_term::atoms::OK))
        }
        Some("reschedule") => {
            let rounds = value
                .as_small()
                .filter(|rounds| *rounds >= 0)
                .ok_or("badarg")?;
            if rounds % 2 != 0 {
                return Err("badarg");
            }
            Ok(Term::atom(arinsal_term::atoms::OK))
        }
        Some("ready_wait6_done") => {
            dirty_send_message(env, heap, value, crate::atom_cache::put("ready"));
            ms_wait(6_000, false);
            dirty_send_message(env, heap, value, crate::atom_cache::put("done"));
            Ok(Term::atom(arinsal_term::atoms::OK))
        }
        Some(op @ ("alive_waitexiting" | "alive_waitexitingonly")) => {
            let dirty_io = arinsal_sched::current_scheduler_type() == SchedulerType::DirtyIo;
            if env.exiting.load(Ordering::Acquire) {
                return Err("badarg");
            }
            dirty_send_message(env, heap, value, Term::atom(arinsal_term::atoms::ALIVE));
            // Wait until dead.
            while !env.exiting.load(Ordering::Acquire) {
                if dirty_io {
                    ms_wait(100, false);
                } else {
                    std::thread::yield_now();
                }
            }
            if op == "alive_waitexitingonly" {
                return Ok(Term::atom(arinsal_term::atoms::OK));
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
                &mut arinsal_bifs::ProcessHeapHandle(heap),
            )
            .map_err(system_limit)?;
            TermBuilder::new(&mut arinsal_bifs::ProcessHeapHandle(heap))
                .tuple(&[Term::atom(arinsal_term::atoms::OK), big])
                .map_err(system_limit)
        }
        _ => Err("badarg"),
    }
}

/// Run `dirty_test` on the current scheduler; on a dirty one as a dirty job.
fn dirty_test(
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    scheduler: &'static str,
    operation: Term,
    value: Term,
    original_mfa: (&'static str, &'static str, u8),
    original_args: &[Term],
) -> Result<Term, VmError> {
    let scheduler_handle = process
        .runtime
        .as_ref()
        .and_then(|runtime| runtime.scheduler_arc().ok());
    if scheduler == "normal" && arg_name(operation).as_deref() == Some("reschedule") {
        let mut scheduler = "normal";
        let mut operation = operation;
        let mut value = value;
        loop {
            match dirty_reschedule_step(scheduler, operation, value) {
                DirtyBifOutcome::Complete(result) => {
                    return result.map_err(|exception| {
                        dirty_bif_error(process, original_mfa, original_args, exception)
                    });
                }
                DirtyBifOutcome::Trap { target, args }
                | DirtyBifOutcome::Reschedule { target, args } => {
                    let next_scheduler = match (target.1, target.2) {
                        ("dirty_cpu", 2) => "dirty_cpu",
                        ("dirty_io", 2) => "dirty_io",
                        ("dirty", 3) => "normal",
                        _ => return Err(VmError::Unsupported("dirty BIF trap target".into())),
                    };
                    if next_scheduler == "normal" {
                        scheduler = next_scheduler;
                        operation = args[1];
                        value = args[2];
                        continue;
                    }
                    let kind = if next_scheduler == "dirty_cpu" {
                        DirtyKind::Cpu
                    } else {
                        DirtyKind::Io
                    };
                    let next_operation = args[0];
                    let next_value = args[1];
                    process.set_dirty_bif_original(original_mfa, original_args);
                    let result = process.dirty_bif(
                        kind,
                        target,
                        &[next_operation, next_value],
                        move |_, args| dirty_reschedule_step(next_scheduler, args[0], args[1]),
                    )?;
                    return match result {
                        DirtyBifOutcome::Complete(result) => result.map_err(|exception| {
                            dirty_bif_error(process, original_mfa, original_args, exception)
                        }),
                        DirtyBifOutcome::Trap { .. } | DirtyBifOutcome::Reschedule { .. } => {
                            Err(VmError::Unsupported(
                                "dirty BIF continuation escaped its scheduler".into(),
                            ))
                        }
                    };
                }
            }
        }
    }
    let busy = scheduler == "dirty_cpu";
    let kind = match scheduler {
        "dirty_cpu" => Some(DirtyKind::Cpu),
        "dirty_io" => Some(DirtyKind::Io),
        "normal" => None,
        _ => return Err(badarg()),
    };
    let result = match kind {
        None => {
            let env = DirtyTestEnv {
                pid: ctx.pid(),
                scheduler: scheduler_handle,
                exiting: std::sync::Arc::new(AtomicBool::new(false)),
            };
            DirtyBifOutcome::Complete(
                dirty_test_body(&env, &mut process.heap, busy, operation, value)
                    .map_err(dirty_bif_exception),
            )
        }
        Some(kind) => {
            let env = DirtyTestEnv {
                pid: ctx.pid(),
                scheduler: scheduler_handle,
                exiting: process.dirty_exit_flag(),
            };
            let function = if busy { "dirty_cpu" } else { "dirty_io" };
            process.set_dirty_bif_original(original_mfa, original_args);
            // Port of erts/emulator/beam/beam_debug.c:1190 (erts_debug_dirty_3 passes
            // `argv` to erts_schedule_bif): the body reads its arguments from the registers.
            process.dirty_bif(
                kind,
                ("erts_debug", function, 2),
                &[operation, value],
                move |heap, args| {
                    let (operation, value) = (args[0], args[1]);
                    if arg_name(operation).as_deref() == Some("reschedule") {
                        dirty_reschedule_step(scheduler, operation, value)
                    } else {
                        DirtyBifOutcome::Complete(
                            dirty_test_body(&env, heap, busy, operation, value)
                                .map_err(dirty_bif_exception),
                        )
                    }
                },
            )?
        }
    };
    match result {
        DirtyBifOutcome::Complete(result) => result
            .map_err(|exception| dirty_bif_error(process, original_mfa, original_args, exception)),
        DirtyBifOutcome::Trap { .. } | DirtyBifOutcome::Reschedule { .. } => Err(
            VmError::Unsupported("dirty BIF continuation escaped its scheduler".into()),
        ),
    }
}

fn dirty_bif_exception(reason: &'static str) -> DirtyBifException {
    DirtyBifException {
        freason: arinsal_term::exc::EXC_ERROR,
        reason: crate::atom_cache::put(reason),
        stacktrace: None,
    }
}

fn dirty_bif_error(
    process: &mut Process,
    mfa: (&'static str, &'static str, u8),
    args: &[Term],
    exception: DirtyBifException,
) -> VmError {
    let class = match exception.freason & 3 {
        2 => arinsal_bifs::Class::Exit,
        3 => arinsal_bifs::Class::Throw,
        _ => arinsal_bifs::Class::Error,
    };
    exceptions::dirty_bif_exception(
        process,
        mfa.0,
        mfa.1,
        args,
        arinsal_bifs::BifError::Raise {
            class,
            reason: exception.reason,
            stacktrace: exception.stacktrace,
        },
    )
    .unwrap_or_else(|error| error)
}

/// Port of erts/emulator/beam/beam_debug.c:1304-1369 (`reschedule`), OTP-29.1.1.
fn dirty_reschedule_step(scheduler: &'static str, operation: Term, value: Term) -> DirtyBifOutcome {
    let Some(rounds) = value.as_small().filter(|rounds| *rounds >= 0) else {
        return DirtyBifOutcome::Complete(Err(dirty_bif_exception("badarg")));
    };
    if rounds % 2 != 0 {
        return DirtyBifOutcome::Complete(Err(dirty_bif_exception("badarg")));
    }
    if rounds == 0 {
        return DirtyBifOutcome::Complete(Ok(Term::atom(arinsal_term::atoms::OK)));
    }
    let next_scheduler = if rounds % 4 != 0 {
        scheduler
    } else {
        match scheduler {
            "dirty_cpu" => "dirty_io",
            "dirty_io" => "normal",
            "normal" => "dirty_cpu",
            _ => return DirtyBifOutcome::Complete(Err(dirty_bif_exception("badarg"))),
        }
    };
    let next_rounds = Term::small(rounds - 2).expect("reschedule count stays a small integer");
    if next_scheduler == "normal" {
        DirtyBifOutcome::Reschedule {
            target: ("erts_debug", "dirty", 3),
            args: vec![
                Term::atom(arinsal_term::atoms::NORMAL),
                operation,
                next_rounds,
            ],
        }
    } else {
        DirtyBifOutcome::Reschedule {
            target: (
                "erts_debug",
                if next_scheduler == "dirty_cpu" {
                    "dirty_cpu"
                } else {
                    "dirty_io"
                },
                2,
            ),
            args: vec![operation, next_rounds],
        }
    }
}

/// Port of erts/emulator/beam/beam_debug.c:1190 (erts_debug_dirty_3), OTP-29.1.1.
fn dirty(
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    args: &[Term],
) -> Result<Term, VmError> {
    let scheduler = match arg_name(args[0]).as_deref() {
        Some("normal") => "normal",
        Some("dirty_cpu") => "dirty_cpu",
        Some("dirty_io") => "dirty_io",
        _ => return Err(badarg()),
    };
    dirty_test(
        process,
        ctx,
        scheduler,
        args[1],
        args[2],
        ("erts_debug", "dirty", 3),
        args,
    )
}

/// Port of erts/emulator/beam/beam_debug.c:86 (erts_debug_size_shared_1), OTP-29.1.1.
fn size_shared(process: &mut Process, value: Term) -> Result<Term, VmError> {
    int(process, arinsal_term::size_shared(value))
}

/// Port of erts/emulator/beam/beam_debug.c:170 (erts_debug_copy_shared_2), OTP-29.1.1.
fn copy_shared(process: &mut Process, args: &[Term]) -> Result<Term, VmError> {
    let copy_literals = if args[1] == Term::atom(arinsal_term::atoms::TRUE) {
        true
    } else if args[1] == Term::atom(arinsal_term::atoms::FALSE) {
        false
    } else {
        return Err(badarg());
    };
    arinsal_term::copy_shared(
        args[0],
        &mut arinsal_bifs::ProcessHeapHandle(&mut process.heap),
        copy_literals,
    )
    .map_err(|_| {
        VmError::Trap(exceptions::Trap::error(Term::atom(
            arinsal_term::atoms::SYSTEM_LIMIT,
        )))
    })
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
    let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
    let mut builder = TermBuilder::new(&mut heap);
    let (leaf_info, bitmap_info, collision_info) = {
        let mut small_tuple = |values: &[usize]| {
            let values = values
                .iter()
                .map(|value| {
                    Term::small(*value as i64).expect("map statistic fits a small integer")
                })
                .collect::<Vec<_>>();
            builder.tuple(&values).map_err(|_| {
                VmError::Trap(exceptions::Trap::error(Term::atom(
                    arinsal_term::atoms::SYSTEM_LIMIT,
                )))
            })
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
            .tuple(&[
                crate::atom_cache::put(name),
                Term::small(count as i64).unwrap(),
                info,
            ])
            .map_err(|_| {
                VmError::Trap(exceptions::Trap::error(Term::atom(
                    arinsal_term::atoms::SYSTEM_LIMIT,
                )))
            })?;
        result = builder.cons(item, result).map_err(|_| {
            VmError::Trap(exceptions::Trap::error(Term::atom(
                arinsal_term::atoms::SYSTEM_LIMIT,
            )))
        })?;
    }
    let arrays_item = builder
        .tuple(&[
            crate::atom_cache::put("arrays"),
            Term::small(arrays as i64).unwrap(),
            Term::NIL,
        ])
        .map_err(|_| {
            VmError::Trap(exceptions::Trap::error(Term::atom(
                arinsal_term::atoms::SYSTEM_LIMIT,
            )))
        })?;
    result = builder.cons(arrays_item, result).map_err(|_| {
        VmError::Trap(exceptions::Trap::error(Term::atom(
            arinsal_term::atoms::SYSTEM_LIMIT,
        )))
    })?;
    let depth_item = builder
        .tuple(&[
            crate::atom_cache::put("depth"),
            Term::small(max_depth as i64).unwrap(),
        ])
        .map_err(|_| {
            VmError::Trap(exceptions::Trap::error(Term::atom(
                arinsal_term::atoms::SYSTEM_LIMIT,
            )))
        })?;
    builder.cons(depth_item, result).map_err(|_| {
        VmError::Trap(exceptions::Trap::error(Term::atom(
            arinsal_term::atoms::SYSTEM_LIMIT,
        )))
    })
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
    let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
    let mut builder = TermBuilder::new(&mut heap);
    let binary = builder.binary(&target).map_err(|_| {
        VmError::Trap(exceptions::Trap::error(Term::atom(
            arinsal_term::atoms::SYSTEM_LIMIT,
        )))
    })?;
    builder.sub_binary(binary, offset, bit_len).map_err(|_| {
        VmError::Trap(exceptions::Trap::error(Term::atom(
            arinsal_term::atoms::SYSTEM_LIMIT,
        )))
    })
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
            Some(0x10) => "reference",
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
    crate::atom_cache::put(name)
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
        ("erts_debug", "disassemble", 1) => Ok(Term::atom(arinsal_term::atoms::FALSE)),
        ("erts_debug", "lcnt_clear", 0) | ("erts_debug", "lcnt_collect", 0) => {
            Ok(Term::atom(arinsal_term::atoms::ERROR))
        }
        ("erts_debug", "lcnt_control", 1 | 2) => Err(badarg()),
        ("erts_debug", "map_info", 1) => map_info(process, args[0]),
        ("erts_debug", "get_internal_state", 1) => internal_state_get(vm, process, ctx, args[0]),
        ("erts_debug", "set_internal_state", 2) => {
            internal_state_set(process, ctx, args[0], args[1])
        }
        ("erts_debug", "instructions", 0) => instructions(process),
        ("erts_debug", "dirty", 3) => dirty(process, ctx, args),
        ("erts_debug", "dirty_cpu", 2) => dirty_test(
            process,
            ctx,
            "dirty_cpu",
            args[0],
            args[1],
            ("erts_debug", "dirty_cpu", 2),
            args,
        ),
        ("erts_debug", "dirty_io", 2) => dirty_test(
            process,
            ctx,
            "dirty_io",
            args[0],
            args[1],
            ("erts_debug", "dirty_io", 2),
            args,
        ),
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
        &mut arinsal_bifs::ProcessHeapHandle(&mut process.heap),
    )
    .map_err(|_| {
        VmError::Trap(exceptions::Trap::error(Term::atom(
            arinsal_term::atoms::SYSTEM_LIMIT,
        )))
    })?;
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
    _vm: &mut Vm,
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
        return from_owned(
            &hash,
            &mut arinsal_bifs::ProcessHeapHandle(&mut process.heap),
        )
        .map(Some)
        .map_err(|_| {
            VmError::Trap(exceptions::Trap::error(Term::atom(
                arinsal_term::atoms::SYSTEM_LIMIT,
            )))
        });
    }
    if let Some(fields) = term_sequence(selector)
        && let [name, term, opts] = fields.as_slice()
        && name.as_atom().and_then(|name| global_atoms().text(name)) == Some("term_to_binary")
    {
        // Port of erts/emulator/beam/erl_bif_info.c:4920-4921, OTP-29.1.1.
        return crate::natives::external::erts_debug_term_to_binary(process, *term, *opts)
            .map(Some);
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
        return Ok((valid_correction && valid_mode).then(|| Term::atom(arinsal_term::atoms::TRUE)));
    }
    if let [OwnedTerm::Atom(name), first, second] = fields.as_slice()
        && name == "make_unique_integer"
    {
        let (Some(first), Some(second)) = (owned_uint(first), owned_uint(second)) else {
            return Err(badarg());
        };
        let value = match arinsal_bifs::debug_make_unique_integer(first, second) {
            arinsal_bifs::UniqueInt::Small(value) => BigInt::from(value),
            arinsal_bifs::UniqueInt::Big(value) => value,
        };
        return from_owned(
            &OwnedTerm::BigInt(value),
            &mut arinsal_bifs::ProcessHeapHandle(&mut process.heap),
        )
        .map(Some)
        .map_err(|_| {
            VmError::Trap(exceptions::Trap::error(Term::atom(
                arinsal_term::atoms::SYSTEM_LIMIT,
            )))
        });
    }
    if let [OwnedTerm::Atom(name), OwnedTerm::Atom(node)] = fields.as_slice()
        && name == "connection_id"
    {
        let tables = crate::node_tables::lock();
        let Some(entry) = tables
            .entries
            .get(node)
            .map(|dep| dep.lock())
            .filter(|entry| entry.connected)
        else {
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
            let value = from_owned(
                value,
                &mut arinsal_bifs::ProcessHeapHandle(&mut process.heap),
            )
            .map_err(|_| {
                VmError::Trap(exceptions::Trap::error(Term::atom(
                    arinsal_term::atoms::SYSTEM_LIMIT,
                )))
            })?;
            let hash = arinsal_term::internal_hash(value);
            let result = OwnedTerm::BigInt(hash.into());
            from_owned(
                &result,
                &mut arinsal_bifs::ProcessHeapHandle(&mut process.heap),
            )
            .map(Some)
            .map_err(|_| {
                VmError::Trap(exceptions::Trap::error(Term::atom(
                    arinsal_term::atoms::SYSTEM_LIMIT,
                )))
            })
        }
        ("atom", index) => {
            let Some(index) = owned_uint(index).and_then(|index| usize::try_from(index).ok())
            else {
                return Err(badarg());
            };
            if index >= 1_048_576 {
                return Err(VmError::Trap(exceptions::Trap::error(Term::atom(
                    arinsal_term::atoms::SYSTEM_LIMIT,
                ))));
            }
            while global_atoms().len() <= index {
                let name = format!("am{:x}", global_atoms().len());
                if global_atoms().intern(&name).is_err() {
                    return Err(VmError::Trap(exceptions::Trap::error(Term::atom(
                        arinsal_term::atoms::SYSTEM_LIMIT,
                    ))));
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
                return Ok(Some(Term::atom(arinsal_term::atoms::RUNNING)));
            }
            // Port of erts/emulator/beam/erl_process.c:9304 (erts_process_status), OTP-29.1.1.
            let status = process
                .runtime
                .as_ref()
                .and_then(|runtime| {
                    runtime
                        .process_alive(pid)
                        .then(|| crate::atom_cache::put(runtime.remote_status(pid)))
                })
                .unwrap_or_else(|| Term::atom(arinsal_term::atoms::UNDEFINED));
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
                return match remote_relations(process, ctx, pid)? {
                    Some(relations) => internal_link_list_from(process, &relations.links).map(Some),
                    None => Ok(Some(Term::atom(arinsal_term::atoms::UNDEFINED))),
                };
            }
            match current_relations(process, ctx)? {
                Some(relations) => internal_link_list_from(process, &relations.links).map(Some),
                None => Ok(Some(Term::atom(arinsal_term::atoms::UNDEFINED))),
            }
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
                return match remote_relations(process, ctx, pid)? {
                    Some(relations) => internal_monitor_list_from(
                        process,
                        &relations.monitors,
                        &relations.monitored_by,
                    )
                    .map(Some),
                    None => Ok(Some(Term::atom(arinsal_term::atoms::UNDEFINED))),
                };
            }
            match current_relations(process, ctx)? {
                Some(relations) => internal_monitor_list_from(
                    process,
                    &relations.monitors,
                    &relations.monitored_by,
                )
                .map(Some),
                None => Ok(Some(Term::atom(arinsal_term::atoms::UNDEFINED))),
            }
        }
        ("channel_number", OwnedTerm::Atom(node)) if node == "nonode@nohost" => {
            Ok(Some(Term::small(0).unwrap()))
        }
        ("channel_number", OwnedTerm::Atom(node)) => {
            let tables = crate::node_tables::lock();
            let channel = tables
                .entries
                .get(node)
                .map(|dep| dep.lock())
                .filter(|entry| entry.connected)
                .map(|entry| entry.connection_id);
            match channel {
                Some(channel) => int(process, channel as usize).map(Some),
                None => Ok(Some(Term::atom(arinsal_term::atoms::UNDEFINED))),
            }
        }
        ("channel_number", _) => Ok(Some(Term::atom(arinsal_term::atoms::UNDEFINED))),
        ("dist_ctrl", OwnedTerm::Atom(node)) => {
            let tables = crate::node_tables::lock();
            let controller = tables
                .entries
                .get(node)
                .map(|dep| dep.lock())
                .filter(|entry| entry.connected)
                .and_then(|entry| {
                    entry.dist.as_ref().and_then(|state| {
                        state
                            .port_id
                            .and_then(Term::port)
                            .or_else(|| state.owner.to_term())
                    })
                });
            Ok(Some(controller.unwrap_or_else(|| {
                Term::atom(arinsal_term::atoms::UNDEFINED)
            })))
        }
        ("dist_ctrl", _) => Ok(Some(Term::atom(arinsal_term::atoms::UNDEFINED))),
        ("reader_groups_map", OwnedTerm::Int(groups))
            if *groups > 0 && Term::small(*groups).is_some() =>
        {
            crate::natives::sys::reader_groups_map(process, *groups).map(Some)
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
            Ok(Some(Term::atom(arinsal_term::atoms::FALSE)))
        }
        ("atom_out_cache_index", OwnedTerm::Atom(name)) => {
            let Some(index) = global_atoms().get(name).map(|atom| atom.0) else {
                return Ok(None);
            };
            int(process, index as usize % 2039).map(Some)
        }
        ("binary_info", OwnedTerm::Binary(bytes))
            if selector_value.is_some_and(|term| {
                term.classify() == arinsal_term::TermKind::Bitstring && bytes.len() > 64
            }) =>
        {
            let size = int(process, bytes.len())?;
            let binary_info = tuple(process, &[Term::atom(arinsal_term::atoms::BINARY), size])?;
            tuple(
                process,
                &[
                    crate::atom_cache::put("refc_binary"),
                    size,
                    binary_info,
                    Term::small(0).unwrap(),
                ],
            )
            .map(Some)
        }
        ("binary_info", OwnedTerm::Binary(_) | OwnedTerm::BitString { .. }) => {
            Ok(Some(crate::atom_cache::put("heap_binary")))
        }
        ("magic_ref", _) => {
            let Some(reference) = selector_value.filter(|term| term.is_magic_ref()) else {
                return Ok(Some(Term::atom(arinsal_term::atoms::FALSE)));
            };
            let Some(owner) = reference.magic_owner() else {
                return Ok(Some(Term::atom(arinsal_term::atoms::FALSE)));
            };
            let address = std::sync::Arc::as_ptr(&owner) as usize;
            let references = std::sync::Arc::strong_count(&owner).saturating_sub(1);
            let address = int(process, address)?;
            let references = int(process, references)?;
            tuple(
                process,
                &[address, references, Term::atom(arinsal_term::atoms::TRUE)],
            )
            .map(Some)
        }
        _ => Ok(None),
    }
}

/// Port of erts/emulator/beam/erl_db.c:5765-5784 (`erts_ets_colliding_names`), OTP-29.1.1.
fn colliding_names(process: &mut Process, name: &str, count: u64) -> Result<Term, VmError> {
    const META_NAME_TAB_MASK: u64 = 8191;
    let Some(atom_index) = global_atoms().get(name).map(|atom| atom.0 as u64) else {
        return Err(badarg());
    };
    let count = usize::try_from(count).map_err(|_| {
        VmError::Trap(exceptions::Trap::error(Term::atom(
            arinsal_term::atoms::SYSTEM_LIMIT,
        )))
    })?;
    let mut terms = Vec::new();
    terms.try_reserve_exact(count).map_err(|_| {
        VmError::Trap(exceptions::Trap::error(Term::atom(
            arinsal_term::atoms::SYSTEM_LIMIT,
        )))
    })?;
    let mut index = atom_index & META_NAME_TAB_MASK;
    while terms.len() < count {
        if index != atom_index {
            while global_atoms().len() as u64 <= index {
                let next = global_atoms().len();
                let text = format!("am{next:x}");
                global_atoms().intern(&text).map_err(|_| {
                    VmError::Trap(exceptions::Trap::error(Term::atom(
                        arinsal_term::atoms::SYSTEM_LIMIT,
                    )))
                })?;
            }
            let atom = u32::try_from(index)
                .ok()
                .map(arinsal_term::Atom)
                .and_then(|atom| Term::atom(atom).as_atom().map(Term::atom))
                .ok_or_else(badarg)?;
            terms.push(atom);
        }
        index = index.checked_add(META_NAME_TAB_MASK + 1).ok_or_else(|| {
            VmError::Trap(exceptions::Trap::error(Term::atom(
                arinsal_term::atoms::SYSTEM_LIMIT,
            )))
        })?;
    }
    terms.reverse();
    list(process, &terms)
}

/// Port of erts_get_node_and_dist_references called by erl_bif_info.c:4354, OTP-29.1.1.
fn node_and_dist_references(process: &mut Process) -> Result<Term, VmError> {
    let local_node = Term::atom(arinsal_term::atoms::NONAME);
    let system = Term::atom(arinsal_term::atoms::SYSTEM);
    let undefined = Term::atom(arinsal_term::atoms::UNDEFINED);
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
    let mut node_reference_entries = vec![node_ref_entry];
    let (ets_identity_counts, match_identity_counts, timer_identity_counts) =
        process.runtime.as_ref().map_or_else(
            || (HashMap::new(), HashMap::new(), HashMap::new()),
            |runtime| {
                let ets = runtime.ets.read().unwrap();
                // Timer messages live on their scheduler's wheel; ask the wheels on demand.
                let mut timer_counts = HashMap::new();
                if let Ok(scheduler) = runtime.scheduler() {
                    for message in scheduler
                        .map_bif_timer_messages(|message| {
                            arinsal_term::to_owned(message.term()).ok()
                        })
                        .into_iter()
                        .flatten()
                    {
                        count_owned_external_identities(&message, &mut timer_counts);
                    }
                }
                (
                    ets.external_identity_counts(),
                    ets.match_program_identity_counts(),
                    timer_counts,
                )
            },
        );
    let mut counts = HashMap::new();
    for (key, count) in ets_identity_counts {
        counts.entry(key).or_insert([0, 0, 0])[0] = count;
    }
    for (key, count) in match_identity_counts {
        counts.entry(key).or_insert([0, 0, 0])[1] = count;
    }
    for (key, count) in timer_identity_counts {
        counts.entry(key).or_insert([0, 0, 0])[2] = count;
    }
    for ((node, creation), [ets_count, binary_count, timer_count]) in counts {
        if ets_count == 0 && binary_count == 0 && timer_count == 0
            || node == arinsal_term::atoms::NONAME
        {
            continue;
        }
        let node_id = tuple(
            process,
            &[Term::atom(node), Term::small(i64::from(creation)).unwrap()],
        )?;
        let mut categories = Vec::new();
        if ets_count > 0 {
            let count_term = int(process, ets_count)?;
            categories.push(tuple(
                process,
                &[Term::atom(arinsal_term::atoms::ETS), count_term],
            )?);
        }
        if binary_count > 0 {
            let count_term = int(process, binary_count)?;
            categories.push(tuple(
                process,
                &[Term::atom(arinsal_term::atoms::BINARY), count_term],
            )?);
        }
        if timer_count > 0 {
            let count_term = int(process, timer_count)?;
            categories.push(tuple(
                process,
                &[crate::atom_cache::put("timer"), count_term],
            )?);
        }
        let count = ets_count + binary_count + timer_count;
        let count_term = int(process, count)?;
        let categories = list(process, &categories)?;
        let owner_id = tuple(
            process,
            &[Term::atom(arinsal_term::atoms::SYSTEM), undefined],
        )?;
        let owner = tuple(process, &[owner_id, categories])?;
        let owners = list(process, &[owner])?;
        node_reference_entries.push(tuple(process, &[node_id, count_term, owners])?);
    }
    let node_references = list(process, &node_reference_entries)?;
    let node_owner = tuple(
        process,
        &[Term::atom(arinsal_term::atoms::NODE), local_reference],
    )?;
    let node_reference = tuple(
        process,
        &[
            Term::atom(arinsal_term::atoms::NODE),
            Term::small(1).unwrap(),
        ],
    )?;
    let node_owners = list(process, &[node_reference])?;
    let node_entry = tuple(process, &[node_owner, node_owners])?;
    let dist_references = list(process, &[system_entry, node_entry])?;
    let dist_entry = tuple(
        process,
        &[local_node, Term::small(2).unwrap(), dist_references],
    )?;
    let dist_entries = list(process, &[dist_entry])?;
    let node_pair = tuple(
        process,
        &[crate::atom_cache::put("node_references"), node_references],
    )?;
    let dist_pair = tuple(
        process,
        &[crate::atom_cache::put("dist_references"), dist_entries],
    )?;
    tuple(process, &[node_pair, dist_pair])
}

fn count_owned_external_identities(
    term: &OwnedTerm,
    counts: &mut HashMap<(arinsal_term::Atom, u32), usize>,
) {
    let mut pending = vec![term];
    while let Some(term) = pending.pop() {
        match term {
            OwnedTerm::Pid { node, creation, .. }
            | OwnedTerm::Port { node, creation, .. }
            | OwnedTerm::Ref { node, creation, .. }
                if node != "nonode@nohost" =>
            {
                if let Ok(node) = global_atoms().intern(node) {
                    *counts.entry((node, *creation)).or_default() += 1;
                }
            }
            OwnedTerm::Tuple(items) => pending.extend(items),
            OwnedTerm::List { elems, tail } => {
                pending.extend(elems);
                pending.push(tail);
            }
            OwnedTerm::Map(pairs) => {
                pending.extend(pairs.iter().flat_map(|(key, value)| [key, value]));
            }
            _ => {}
        }
    }
}

fn internal_link_list_from(
    process: &mut Process,
    links: &[(arinsal_sched::Pid, bool)],
) -> Result<Term, VmError> {
    let mut records = Vec::with_capacity(links.len());
    for &(pid, unlinking) in links {
        let Some(pid_term) = pid.to_term() else {
            continue;
        };
        let id = int(process, pid.number() as usize)?;
        let state = if unlinking {
            crate::atom_cache::put("unlinking")
        } else {
            crate::atom_cache::put("linked")
        };
        records.push(tuple(
            process,
            &[
                crate::atom_cache::put("erl_link"),
                Term::atom(arinsal_term::atoms::PROCESS),
                pid_term,
                state,
                id,
            ],
        )?);
    }
    list(process, &records)
}

/// The links and monitors of one process, copied out under its main lock.
struct Relations {
    links: Vec<(arinsal_sched::Pid, bool)>,
    monitors: Vec<(u64, arinsal_sched::Pid, Option<OwnedTerm>)>,
    monitored_by: Vec<(u64, arinsal_sched::Pid, Option<OwnedTerm>)>,
}

impl Relations {
    fn of(process: &Process) -> Self {
        Self {
            links: process
                .links
                .iter()
                .map(|node| {
                    (
                        arinsal_sched::Pid::from_data(node.other()),
                        node.unlinking() != 0,
                    )
                })
                .collect(),
            monitors: process
                .monitors
                .iter()
                .filter_map(|monitor| {
                    let crate::proc_create::OriginMonitor::Process(_) = monitor.origin_state()?
                    else {
                        return None;
                    };
                    // The name wins over the tag, as make_monitor_list shows a registered name.
                    Some((
                        monitor.reference(),
                        arinsal_sched::Pid::from_data(monitor.other()),
                        monitor_extra(monitor.info()),
                    ))
                })
                .collect(),
            monitored_by: process
                .lt_monitors
                .iter()
                .chain(
                    process
                        .monitors
                        .iter()
                        .filter(|monitor| monitor.is_target()),
                )
                .map(|monitor| {
                    (
                        monitor.reference(),
                        arinsal_sched::Pid::from_data(monitor.other()),
                        monitor_extra(monitor.info()),
                    )
                })
                .collect(),
        }
    }
}

/// The relations of another process after its incoming signals were handled by the caller.
///
/// Port of erts/emulator/beam/erl_bif_info.c:4626-4700 (`link_list`, `monitor_list`): erts takes
/// the target's main lock, fetches its signals and runs `erts_proc_sig_handle_incoming` on it
/// until all are handled or it is exiting, then reads the relations. A running target holds
/// the lock, so the BIF yields and retries where erts waits for it.
fn remote_relations(
    process: &Process,
    ctx: &mut RunCtx<'_, Message>,
    pid: arinsal_sched::Pid,
) -> Result<Option<Relations>, VmError> {
    let mut relations = None;
    let mut signal_error = None;
    // The caller's reductions left bound the target's signal handling.
    let reds = u32::try_from(process.heap.abi.fcalls.max(1)).unwrap_or(1);
    let locked = ctx.with_locked_target(pid, reds, &mut |task, target_ctx| {
        let Some(target) = task.downcast_mut::<Process>() else {
            return;
        };
        let exiting = |target: &Process| target.dirty_exiting() || target.has_exit_cont();
        if !exiting(target)
            && let Err(error) = target.drain(target_ctx)
        {
            signal_error = Some(error);
        }
        if signal_error.is_none() && !exiting(target) {
            relations = Some(Relations::of(target));
        }
    });
    match locked {
        Ok(()) => {}
        Err(arinsal_sched::SignalFreeError::NoProcess) => return Ok(None),
        Err(arinsal_sched::SignalFreeError::Busy) => return Err(VmError::Yield),
    }
    match signal_error {
        Some(error) => Err(error),
        None => Ok(relations),
    }
}

/// Fetch and handle the current process's incoming signals before reading its link tree.
///
/// Port of erts/emulator/beam/erl_bif_info.c:4650-4668 (`link_list` and `monitor_list`),
/// OTP-29.1.1: the debug introspection path drains pending signals even for the caller itself.
fn current_relations(
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
) -> Result<Option<Relations>, VmError> {
    let exiting = |target: &Process| target.dirty_exiting() || target.has_exit_cont();
    if !exiting(process) {
        process.drain(ctx)?;
    }
    Ok((!exiting(process)).then(|| Relations::of(process)))
}

fn internal_monitor_list_from(
    process: &mut Process,
    origins: &[(u64, arinsal_sched::Pid, Option<OwnedTerm>)],
    targets: &[(u64, arinsal_sched::Pid, Option<OwnedTerm>)],
) -> Result<Term, VmError> {
    let mut records = Vec::with_capacity(origins.len() + targets.len());
    for &(id, pid, ref tag) in origins {
        let Some(pid) = pid.to_term() else {
            continue;
        };
        let reference = crate::signals::reference(process, id)?;
        let tag = monitor_extra_term(process, tag.as_ref())?;
        records.push(tuple(
            process,
            &[
                crate::atom_cache::put("erl_monitor"),
                Term::atom(arinsal_term::atoms::PROCESS),
                crate::atom_cache::put("origin"),
                reference,
                pid,
                tag,
            ],
        )?);
    }
    for (id, pid, extra) in targets {
        let Some(pid) = pid.to_term() else {
            continue;
        };
        let reference = crate::signals::reference(process, *id)?;
        let extra = monitor_extra_term(process, extra.as_ref())?;
        records.push(tuple(
            process,
            &[
                crate::atom_cache::put("erl_monitor"),
                Term::atom(arinsal_term::atoms::PROCESS),
                crate::atom_cache::put("target"),
                reference,
                pid,
                extra,
            ],
        )?);
    }
    list(process, &records)
}

fn monitor_extra(data: &crate::proc_create::MonitorInfo) -> Option<OwnedTerm> {
    data.name()
        .map(|name| OwnedTerm::Atom(name.to_owned()))
        .or_else(|| data.tag().cloned())
}

fn monitor_extra_term(process: &mut Process, extra: Option<&OwnedTerm>) -> Result<Term, VmError> {
    extra
        .map(|extra| {
            from_owned(
                extra,
                &mut arinsal_bifs::ProcessHeapHandle(&mut process.heap),
            )
            .map_err(|_| {
                VmError::Trap(exceptions::Trap::error(Term::atom(
                    arinsal_term::atoms::SYSTEM_LIMIT,
                )))
            })
        })
        .transpose()
        .map(|extra| extra.unwrap_or(Term::NIL))
}

/// Port of erts/emulator/beam/erl_bif_info.c:4339-4947, OTP-29.1.1.
fn internal_state_get(
    vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    selector: Term,
) -> Result<Term, VmError> {
    if !INTERNAL_STATE.load(Ordering::Relaxed) {
        return Err(undef());
    }
    if let Some(result) = internal_state_tuple_get(vm, process, ctx, selector)? {
        return Ok(result);
    }
    match arg_name(selector).as_deref() {
        Some("reds_left") => int(process, process.heap.abi.fcalls.max(0) as usize),
        Some("available_internal_state") => Ok(Term::atom(arinsal_term::atoms::TRUE)),
        Some("force_heap_frags" | "scheduler_dump" | "hashmap_collision_bonanza") => {
            Ok(Term::atom(arinsal_term::atoms::FALSE))
        }
        Some("debugger_support") => Ok(Term::atom(if crate::trace_bp::debugger_supported() {
            arinsal_term::atoms::TRUE
        } else {
            arinsal_term::atoms::FALSE
        })),
        Some("lc_graph" | "flxctr_memory_usage") => Ok(Term::atom(arinsal_term::atoms::NOTSUP)),
        Some("re_yield_coverage") => Ok(Term::atom(arinsal_term::atoms::UNDEFINED)),
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
            let names = names
                .iter()
                .map(|name| crate::atom_cache::put(name))
                .collect::<Vec<_>>();
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
        Some("mmap") => Ok(Term::atom(arinsal_term::atoms::UNDEFINED)),
        // Port of erts/emulator/beam/erl_bif_info.c (erts_debug_get_internal_state_1,
        // stack_check), OTP-29.1.1.
        Some("stack_check") => {
            use arinsal_alloc::ethr::stack_marker;
            let c = stack_marker();
            let size = if erts_is_above_stack_limit(c) {
                erts_check_stack_recursion_downwards(c, c)
            } else {
                erts_check_stack_recursion_upwards(c, c)
            };
            TermBuilder::new(&mut arinsal_bifs::ProcessHeapHandle(&mut process.heap))
                .int_from_i128(size as i128)
                .map_err(|_| {
                    VmError::Trap(exceptions::Trap::error(Term::atom(
                        arinsal_term::atoms::SYSTEM_LIMIT,
                    )))
                })
        }
        Some("unique_monotonic_integer_state") => {
            TermBuilder::new(&mut arinsal_bifs::ProcessHeapHandle(&mut process.heap))
                .int_from_i128(UNIQUE_MONOTONIC_INTEGER_STATE.load(Ordering::Relaxed) as i128)
                .map_err(|_| {
                    VmError::Trap(exceptions::Trap::error(Term::atom(
                        arinsal_term::atoms::SYSTEM_LIMIT,
                    )))
                })
        }
        Some("persistent_term") => {
            let map = OwnedTerm::Map(vec![(OwnedTerm::atom("table"), OwnedTerm::Int(64))]);
            from_owned(
                &map,
                &mut arinsal_bifs::ProcessHeapHandle(&mut process.heap),
            )
            .map_err(|_| {
                VmError::Trap(exceptions::Trap::error(Term::atom(
                    arinsal_term::atoms::SYSTEM_LIMIT,
                )))
            })
        }
        Some("min_unique_monotonic_integer" | "min_unique_integer") => {
            TermBuilder::new(&mut arinsal_bifs::ProcessHeapHandle(&mut process.heap))
                .int_from_i128(-576_460_752_303_423_488)
                .map_err(|_| {
                    VmError::Trap(exceptions::Trap::error(Term::atom(
                        arinsal_term::atoms::SYSTEM_LIMIT,
                    )))
                })
        }
        // Port of erts/emulator/beam/erl_process.c:5538 (erts_debug_nbalance),
        // OTP-29.1.1.
        Some("nbalance") => {
            let checks = process
                .runtime
                .as_ref()
                .and_then(|runtime| runtime.scheduler().ok())
                .map_or(0, |scheduler| scheduler.balance_checks());
            TermBuilder::new(&mut arinsal_bifs::ProcessHeapHandle(&mut process.heap))
                .int_from_i128(i128::from(checks))
                .map_err(|_| {
                    VmError::Trap(exceptions::Trap::error(Term::atom(
                        arinsal_term::atoms::SYSTEM_LIMIT,
                    )))
                })
        }
        Some("monitoring_nodes") => {
            let Some(runtime) = &process.runtime else {
                return Ok(Term::NIL);
            };
            let pids = runtime.process_pids();
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
            let values = crate::natives::sys::memory_values(vm, process);
            let mut entries = Vec::with_capacity(values.len());
            for (name, value) in values {
                let value = int(process, value as usize)?;
                entries.push(tuple(process, &[crate::atom_cache::put(name), value])?);
            }
            list(process, &entries)
        }
        Some("processes") => {
            let processes = process
                .runtime
                .as_ref()
                .map(|runtime| {
                    let mut pids = runtime.process_pids();
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
                crate::atom_cache::put("ptab_list_bif_info"),
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
                    TermBuilder::new(&mut arinsal_bifs::ProcessHeapHandle(&mut process.heap))
                        .int_from_i128(i128::from(next))
                        .map_err(|_| {
                            VmError::Trap(exceptions::Trap::error(Term::atom(
                                arinsal_term::atoms::SYSTEM_LIMIT,
                            )))
                        })
                }
                None => Ok(Term::atom(arinsal_term::atoms::FALSE)),
            }
        }
        Some("next_port") => {
            let next = process
                .runtime
                .as_ref()
                .and_then(|runtime| crate::port::test_next_port_id(runtime, false, 0));
            match next {
                Some(next) => {
                    TermBuilder::new(&mut arinsal_bifs::ProcessHeapHandle(&mut process.heap))
                        .int_from_i128(next as i128)
                        .map_err(|_| {
                            VmError::Trap(exceptions::Trap::error(Term::atom(
                                arinsal_term::atoms::SYSTEM_LIMIT,
                            )))
                        })
                }
                None => Ok(Term::atom(arinsal_term::atoms::FALSE)),
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
/// waiter. For `deallocations` every scheduler drains the delayed frees of its own allocator
/// instance in each round, and the waiter drains the instances no scheduler owns. Each phase needs every scheduler to reach its aux-work point, so a phase is one round.
fn debug_wait_round(
    owner: &'static crate::process::Runtime,
    schedulers: usize,
    pid: arinsal_sched::Pid,
    completion: std::sync::Arc<std::sync::atomic::AtomicBool>,
    rounds_left: u32,
    drain_owned: bool,
    request: &mut dyn FnMut(Box<dyn Fn(usize) + Send + Sync>),
) {
    let remaining = std::sync::atomic::AtomicUsize::new(schedulers);
    let retry = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    request(Box::new(move |worker| {
        if drain_owned {
            let status = arinsal_alloc::typed::flush_owned_deallocations(worker + 1);
            if status.more_work || status.need_thr_progress {
                retry.store(true, Ordering::Release);
            }
        }
        if remaining.fetch_sub(1, Ordering::AcqRel) != 1 {
            return;
        }
        if drain_owned && retry.load(Ordering::Acquire) {
            debug_wait_round(
                owner,
                schedulers,
                pid,
                completion.clone(),
                rounds_left,
                drain_owned,
                &mut |work| {
                    let Ok(scheduler) = owner.scheduler() else {
                        return;
                    };
                    scheduler.request_aux_work_all(work);
                },
            );
            return;
        }
        let runtime = owner;
        let Ok(scheduler) = runtime.scheduler() else {
            return;
        };
        if rounds_left > 1 {
            let next = scheduler.clone();
            debug_wait_round(
                owner,
                schedulers,
                pid,
                completion.clone(),
                rounds_left - 1,
                drain_owned,
                &mut |work| next.request_aux_work_all(work),
            );
            return;
        }
        completion.store(true, Ordering::Release);
        runtime.debug_wait_active.store(false, Ordering::Release);
        debug_wait_wake(scheduler.clone(), pid, completion.clone());
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
    if selector == crate::atom_cache::put("available_internal_state") {
        if value != Term::atom(arinsal_term::atoms::TRUE)
            && value != Term::atom(arinsal_term::atoms::FALSE)
        {
            return Err(badarg());
        }
        let previous = INTERNAL_STATE.swap(
            value == Term::atom(arinsal_term::atoms::TRUE),
            Ordering::Relaxed,
        );
        if value == Term::atom(arinsal_term::atoms::TRUE)
            && let (Some(runtime), Some(pid)) = (process.runtime, ctx.pid().to_term())
        {
            let arinsal_etf::OwnedTerm::Pid {
                id,
                serial,
                creation,
                ..
            } = arinsal_term::to_owned(pid).expect("process identifier")
            else {
                unreachable!("process identifier is a pid")
            };
            let text = format!(
                "Process <{id}.{serial}.{creation}> enabled access to the emulator internal state.\nNOTE: This is an erts internal test feature and should *only* be used by OTP test-suites.\n"
            );
            let group_leader = process
                .group_leader_pid(ctx.pid())
                .to_term()
                .unwrap_or(Term::NIL);
            crate::utils::send_warning_to_logger_str(runtime, ctx.pid(), group_leader, &text);
        }
        return Ok(Term::atom(if previous {
            arinsal_term::atoms::TRUE
        } else {
            arinsal_term::atoms::FALSE
        }));
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
        // Port of erts/emulator/beam/erl_process.c:2103 (handle_delayed_dealloc), OTP-29.1.1.
        // Refc binaries released with a literal area are queued on the allocating
        // scheduler; this wait is what code_SUITE uses before erlang:memory(binary).
        let drain_owned = kind == "deallocations";
        if drain_owned {
            arinsal_alloc::typed::drain_shared_deallocations();
        }
        let runtime = process.runtime.ok_or_else(badarg)?;
        // Port of erts/emulator/beam/erl_process.c (erts_debug_wait_completed), OTP-29.1.1:
        // erts yields and returns `ok` once, without re-running the BIF. A latch left by a
        // finished wait therefore belongs to that earlier call, not to this one; reusing it
        // made every second `wait` return at once (the BEAM JIT resumes after the call).
        let pending_wait = process
            .slice()
            .and_then(|work| work.debug_wait_completion.clone());
        if let Some(completion) = pending_wait {
            if !completion.load(Ordering::Acquire) {
                // ERTS_BIF_YIELD_RETURN (bif.h): ERTS_VBUMP_ALL_REDS.
                crate::bif_traps::vbump_all_reds(process);
                return Ok(Term::atom(arinsal_term::atoms::OK));
            }
            process.slice_mut().debug_wait_completion = None;
        }
        // Port of erts/emulator/beam/erl_process.c:2499 (erts_debug_wait_completed): only one
        // process at a time can wait.
        if runtime
            .debug_wait_active
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(VmError::Trap(exceptions::Trap::error(Term::atom(
                arinsal_term::atoms::SYSTEM_LIMIT,
            ))));
        }
        let completion = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        process.slice_mut().debug_wait_completion = Some(completion.clone());
        let rounds = if kind == "aux_work" || drain_owned {
            1
        } else {
            4
        };
        debug_wait_round(
            runtime,
            ctx.scheduler_count(),
            ctx.pid(),
            completion,
            rounds,
            drain_owned,
            &mut |work| ctx.request_aux_work_all(work),
        );
        // erl_bif_info.c:5260-5261: ERTS_BIF_YIELD_RETURN (ERTS_VBUMP_ALL_REDS).
        crate::bif_traps::vbump_all_reds(process);
        return Ok(Term::atom(arinsal_term::atoms::OK));
    }
    match arg_name(selector).as_deref() {
        Some("reds_left") => {
            let Some(reductions) = to_owned(value).ok().and_then(|term| owned_signed(&term)) else {
                return Err(badarg());
            };
            if (0..=4000).contains(&reductions) {
                process.heap.abi.fcalls = reductions as i32;
            }
            return Ok(Term::atom(arinsal_term::atoms::TRUE));
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
            return Ok(Term::atom(arinsal_term::atoms::TRUE));
        }
        Some("test_long_gc_sleep") => {
            let Some(milliseconds) = to_owned(value).ok().and_then(|term| owned_uint(&term)) else {
                return Err(badarg());
            };
            TEST_LONG_GC_SLEEP.store(milliseconds, Ordering::Relaxed);
            return Ok(Term::atom(arinsal_term::atoms::TRUE));
        }
        Some("multizero_timeout_in_timeout") => {
            let Some(timeout) = to_owned(value).ok().and_then(|term| owned_signed(&term)) else {
                return Err(badarg());
            };
            if process.runtime.is_none() {
                return Err(VmError::Trap(exceptions::Trap::error(Term::atom(
                    arinsal_term::atoms::SYSTEM_LIMIT,
                ))));
            }
            // Port of erts/emulator/beam/erl_bif_info.c:4976-4996,5402-5412, OTP-29.1.1: a
            // timer callback that starts a zero timer callback from within a timer callback.
            let done =
                Message::copy_from(crate::atom_cache::put("multizero_timeout_in_timeout_done"))?;
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
            .map_err(|_| {
                VmError::Trap(exceptions::Trap::error(Term::atom(
                    arinsal_term::atoms::SYSTEM_LIMIT,
                )))
            })?;
            return Ok(Term::atom(arinsal_term::atoms::OK));
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
                    TermBuilder::new(&mut arinsal_bifs::ProcessHeapHandle(&mut process.heap))
                        .int_from_i128(result)
                        .map_err(|_| {
                            VmError::Trap(exceptions::Trap::error(Term::atom(
                                arinsal_term::atoms::SYSTEM_LIMIT,
                            )))
                        })
                }
                None => Ok(Term::atom(arinsal_term::atoms::FALSE)),
            };
        }
        Some("force_gc") => {
            let Some(pid) = arinsal_sched::Pid::from_term(value) else {
                return Ok(Term::atom(arinsal_term::atoms::FALSE));
            };
            let found = process
                .runtime
                .as_ref()
                .is_some_and(|runtime| runtime.process_alive(pid));
            if !found {
                return Ok(Term::atom(arinsal_term::atoms::FALSE));
            }
            // Port of erts/emulator/beam/erl_bif_info.c:5124-5133 and
            // erts/emulator/beam/erl_gc.h:146-153, OTP-29.1.1. The target PID is only
            // checked for existence; ERTS_FORCE_GC collects the calling process.
            process.force_gc()?;
            return Ok(Term::atom(arinsal_term::atoms::TRUE));
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
            return Ok(Term::atom(arinsal_term::atoms::TRUE));
        }
        Some("binary_loop_limit" | "re_loop_limit" | "unicode_loop_limit") => {
            let (limit, default) = match arg_name(selector).as_deref() {
                Some("binary_loop_limit") => (&BINARY_LOOP_LIMIT, 0),
                Some("re_loop_limit") => (&RE_LOOP_LIMIT, 64_000),
                _ => (&UNICODE_LOOP_LIMIT, 40_000),
            };
            let next = if value == Term::atom(arinsal_term::atoms::DEFAULT) {
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
        Some("gc_state")
            if value == Term::atom(arinsal_term::atoms::TRUE)
                || value == Term::atom(arinsal_term::atoms::FALSE) =>
        {
            let previous = process.set_gc_enabled(value == Term::atom(arinsal_term::atoms::TRUE));
            return Ok(Term::atom(if previous {
                arinsal_term::atoms::TRUE
            } else {
                arinsal_term::atoms::FALSE
            }));
        }
        Some("inconsistent_heap") if value == Term::atom(arinsal_term::atoms::START) => {
            process.set_gc_enabled(false);
            let index = process.heap.used_words();
            let broken = tuple(process, &[Term::atom(arinsal_term::atoms::OK)])?;
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
                || !process.heap.debug_write_heap_word(
                    word_index + 1,
                    Term::atom(arinsal_term::atoms::OK).tagged_word(),
                )
            {
                return Err(badarg());
            }
            process.set_gc_enabled(true);
            return Ok(Term::atom(arinsal_term::atoms::OK));
        }
        Some("debugger_support") if value == Term::atom(arinsal_term::atoms::TRUE) => {
            crate::trace_bp::enable_debugger_support();
            return Ok(Term::atom(arinsal_term::atoms::OK));
        }
        Some("debugger_support") => return Ok(Term::atom(arinsal_term::atoms::BADARG)),
        Some("jit_asm_dump")
            if value == Term::atom(arinsal_term::atoms::TRUE)
                || value == Term::atom(arinsal_term::atoms::FALSE) =>
        {
            let previous = JIT_ASM_DUMP.swap(
                value == Term::atom(arinsal_term::atoms::TRUE),
                Ordering::Relaxed,
            );
            return Ok(Term::atom(if previous {
                arinsal_term::atoms::TRUE
            } else {
                arinsal_term::atoms::FALSE
            }));
        }
        Some("ets_force_split" | "ets_debug_random_split_join") => {
            let Some([table, on]) = super::ets::tuple_items(value)
                .as_deref()
                .and_then(|items| <&[Term; 2]>::try_from(items).ok().copied())
            else {
                return Err(badarg());
            };
            let Some(tid) = arinsal_ets::Tid::from_term(table) else {
                return Err(badarg());
            };
            let random = arg_name(selector).as_deref() == Some("ets_debug_random_split_join");
            let enabled = on == Term::atom(arinsal_term::atoms::TRUE);
            let changed = process.runtime.as_ref().is_some_and(|runtime| {
                runtime
                    .ets
                    .read()
                    .unwrap()
                    .debug_set_catree_mode(tid, random, enabled)
            });
            return if changed {
                Ok(Term::atom(arinsal_term::atoms::OK))
            } else {
                Err(badarg())
            };
        }
        Some("ets_force_trap") => return Ok(Term::atom(arinsal_term::atoms::NOTSUP)),
        Some("proc_sig_buffers") if value == Term::atom(arinsal_term::atoms::TRUE) => {
            return Ok(Term::atom(
                if process.message_queue_data() == crate::process::MessageQueueData::OffHeap
                    && ctx.force_parallel_signal_buffers()
                {
                    arinsal_term::atoms::TRUE
                } else {
                    arinsal_term::atoms::FALSE
                },
            ));
        }
        Some("proc_sig_buffers") => return Ok(Term::atom(arinsal_term::atoms::NOTSUP)),
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
                return Ok(Term::atom(arinsal_term::atoms::FALSE));
            };
            let Some(runtime) = process.runtime.as_ref() else {
                return Ok(Term::atom(arinsal_term::atoms::FALSE));
            };
            let (port_id, connection_id) = {
                let tables = crate::node_tables::lock();
                let Some(entry) = tables
                    .entries
                    .get(&node)
                    .map(|dep| dep.lock())
                    .filter(|entry| entry.connected)
                else {
                    return Ok(Term::atom(arinsal_term::atoms::FALSE));
                };
                (
                    entry.dist.as_ref().and_then(|state| state.port_id),
                    entry.connection_id,
                )
            };
            if let Some(port_id) = port_id {
                let port = runtime.ports.get(port_id);
                if !crate::port::close_by_id(process, ctx, port_id)? {
                    return Ok(Term::atom(arinsal_term::atoms::FALSE));
                }
                if let Some(port) = port {
                    crate::dist::port_connection_closed(runtime, &port)?;
                }
                return Ok(Term::atom(arinsal_term::atoms::TRUE));
            }
            return Ok(Term::atom(
                if crate::dist::kill_connection(runtime, &node, connection_id)? {
                    arinsal_term::atoms::TRUE
                } else {
                    arinsal_term::atoms::FALSE
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
            .any(|name| value == crate::atom_cache::put(name)) =>
        {
            if value == crate::atom_cache::put("thread_progress") {
                ctx.block_thread_progress(std::time::Duration::ZERO);
            }
            return Ok(Term::atom(arinsal_term::atoms::OK));
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
            // Port of erts/emulator/beam/erl_bif_info.c (fill_heap): HeapWordsLeft is bounded
            // by HEAP_LIMIT, which leaves the redzone free.
            let left = process.heap.words_left();
            if left > 1 {
                let filler = BigInt::from(1_u8) << ((left - 2) * 64);
                from_owned(&OwnedTerm::BigInt(filler), &mut process.heap).map_err(|_| {
                    VmError::Trap(exceptions::Trap::error(Term::atom(
                        arinsal_term::atoms::SYSTEM_LIMIT,
                    )))
                })?;
            }
            if fill_fullsweep {
                process.heap.set_fullsweep_after(0);
            }
            return Ok(Term::atom(arinsal_term::atoms::OK));
        }
        Some("mbuf") => {
            return arinsal_term::copy_term(
                value,
                &mut arinsal_term::FragmentAlloc::new(&mut process.heap),
            )
            .map_err(|_| {
                VmError::Trap(exceptions::Trap::error(Term::atom(
                    arinsal_term::atoms::SYSTEM_LIMIT,
                )))
            });
        }
        Some("make") if value == Term::atom(arinsal_term::atoms::MAGIC_REF) => {
            // Port of erts/emulator/beam/erl_bif_info.c (erts_debug_get_internal_state):
            // this probe creates a zero-payload magic binary.
            let owner = arinsal_term::MagicRef::with_erts_payload_size_and_refn(
                (),
                0,
                arinsal_bifs::ordinary_ref_words(process.next_ref()),
            );
            let address = std::sync::Arc::as_ptr(&owner) as usize;
            let reference = TermBuilder::new(&mut process.heap)
                .magic_ref(owner)
                .map_err(|_| {
                    VmError::Trap(exceptions::Trap::error(Term::atom(
                        arinsal_term::atoms::SYSTEM_LIMIT,
                    )))
                })?;
            let address = TermBuilder::new(&mut arinsal_bifs::ProcessHeapHandle(&mut process.heap))
                .int_from_i128(address as i128)
                .map_err(|_| {
                    VmError::Trap(exceptions::Trap::error(Term::atom(
                        arinsal_term::atoms::SYSTEM_LIMIT,
                    )))
                })?;
            return tuple(process, &[reference, address]);
        }
        Some("binary") => {
            let Some(size) = to_owned(value).ok().and_then(|term| owned_signed(&term)) else {
                return Err(badarg());
            };
            let Ok(size) = usize::try_from(size) else {
                return Ok(Term::atom(arinsal_term::atoms::FALSE));
            };
            let mut bytes = Vec::new();
            if bytes.try_reserve_exact(size).is_err() {
                return Ok(Term::atom(arinsal_term::atoms::FALSE));
            }
            bytes.resize(size, 0);
            return TermBuilder::new(&mut arinsal_bifs::ProcessHeapHandle(&mut process.heap))
                .binary(&bytes)
                .map_err(|_| {
                    VmError::Trap(exceptions::Trap::error(Term::atom(
                        arinsal_term::atoms::SYSTEM_LIMIT,
                    )))
                });
        }
        Some("node_tab_delayed_delete") => {
            let Some(timeout) = to_owned(value).ok().and_then(|term| owned_signed(&term)) else {
                return Err(badarg());
            };
            ctx.block_thread_progress(std::time::Duration::ZERO);
            crate::node_tables::test_node_tab_delayed_delete(timeout);
            return Ok(Term::atom(arinsal_term::atoms::OK));
        }
        Some("remove_dflags") => {
            let Some(flags) = to_owned(value).ok().and_then(|term| owned_uint(&term)) else {
                return Err(badarg());
            };
            if flags & crate::node_tables::DFLAG_DIST_MANDATORY != 0 {
                return Err(badarg());
            }
            crate::node_tables::test_remove_dflags(Some(flags));
            return Ok(Term::atom(arinsal_term::atoms::OK));
        }
        Some("code_mod_permission") => {
            let acquire = match arg_name(value).as_deref() {
                Some("true") => true,
                Some("false") => false,
                _ => return Err(badarg()),
            };
            // Port of erts/emulator/beam/erl_bif_info.c:5385-5400, OTP-29.1.1: a failed seize
            // yields through the BIF continuation (bif_traps.rs), so only a release gets here.
            if acquire {
                return Err(VmError::Unsupported(
                    "code_mod_permission must resume through its BIF continuation".into(),
                ));
            }
            if let Some(runtime) = &process.runtime {
                crate::natives::code::release_code_mod_permission(runtime);
            }
            return Ok(Term::atom(arinsal_term::atoms::TRUE));
        }
        Some("process_uniq_counter") => {
            let Some(counter) = to_owned(value).ok().and_then(|term| owned_signed(&term)) else {
                return Err(badarg());
            };
            process.uniq_counter = counter;
            return Ok(Term::atom(arinsal_term::atoms::OK));
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
                return Ok(Term::atom(arinsal_term::atoms::FALSE));
            };
            if !runtime.process_alive(pid) {
                return Ok(Term::atom(arinsal_term::atoms::FALSE));
            }
            return Ok(Term::atom(
                if ctx
                    .signal(pid, arinsal_sched::Signal::ProcSigBlock(milliseconds))
                    .is_ok()
                {
                    arinsal_term::atoms::TRUE
                } else {
                    arinsal_term::atoms::FALSE
                },
            ));
        }
        _ => {}
    }
    Err(badarg())
}

fn system_check(selector: Term) -> Result<Term, VmError> {
    if selector == crate::atom_cache::put("schedulers") {
        Ok(Term::atom(arinsal_term::atoms::OK))
    } else {
        Err(badarg())
    }
}

/// Port of erts/emulator/beam/erl_bif_trace.c:3276-3388, OTP-29.1.1.
fn system_monitor_get(process: &mut Process, session: Term) -> Result<Term, VmError> {
    let runtime = process.runtime.ok_or_else(badarg)?;
    let state = if session == Term::atom(arinsal_term::atoms::LEGACY) {
        runtime.system_monitor.lock().unwrap().clone()
    } else {
        let key = crate::natives::proc::trace_session_id(process, session).ok_or_else(badarg)?;
        runtime
            .session_monitors
            .lock()
            .unwrap()
            .iter()
            .find(|(owner, _)| *owner == key)
            .map(|(_, state)| state.clone())
    };
    let Some(state) = state else {
        return Ok(Term::atom(arinsal_term::atoms::UNDEFINED));
    };
    let owned = OwnedTerm::Tuple(vec![
        state.receiver,
        OwnedTerm::list(monitor_options_for_trace_info(&state.options)),
    ]);
    from_owned(
        &owned,
        &mut arinsal_bifs::ProcessHeapHandle(&mut process.heap),
    )
    .map_err(|_| {
        VmError::Trap(exceptions::Trap::error(Term::atom(
            arinsal_term::atoms::SYSTEM_LIMIT,
        )))
    })
}

pub(crate) fn monitor_options_for_trace_info(
    options: &HashMap<&'static str, MonitorOption>,
) -> Vec<OwnedTerm> {
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

/// Apply one `system_monitor` option to `options`.
// Port of erts/emulator/beam/erl_bif_trace.c:3587-3668 (system_monitor option switch,
// term_to_limit, term_to_boolean), OTP-29.1.1.
fn apply_monitor_option(
    options: &mut HashMap<&'static str, MonitorOption>,
    entry: &OwnedTerm,
) -> Option<()> {
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
    let is_false = matches!(&value, OwnedTerm::Atom(value) if value == "false");
    match name {
        "busy_port" | "busy_dist_port" => {
            let enabled = match &value {
                OwnedTerm::Atom(value) if value == "true" => true,
                OwnedTerm::Atom(value) if value == "false" => false,
                _ => return None,
            };
            let key = if name == "busy_port" {
                "busy_port"
            } else {
                "busy_dist_port"
            };
            options.insert(key, MonitorOption::Bool(enabled));
        }
        "long_gc" | "long_schedule" | "large_heap" => {
            let key = match name {
                "long_gc" => "long_gc",
                "long_schedule" => "long_schedule",
                _ => "large_heap",
            };
            if is_false {
                options.remove(key);
            } else {
                // 16 Kword is not an unnatural heap size.
                let minimum = if name == "large_heap" { 16_384 } else { 1 };
                options.insert(key, MonitorOption::Limit(owned_uint(&value)?.max(minimum)));
            }
        }
        "long_message_queue" => {
            if is_false {
                options.remove("long_message_queue");
            } else if let OwnedTerm::Tuple(pair) = &value
                && pair.len() == 2
            {
                let off = owned_uint(&pair[0])?;
                let on = if matches!(&pair[1], OwnedTerm::Atom(value) if value == "false") {
                    0
                } else {
                    owned_uint(&pair[1])?
                };
                if on == 0 || off >= on {
                    return None;
                }
                options.insert("long_message_queue", MonitorOption::Queue(off, on));
            } else {
                return None;
            }
        }
        _ => return None,
    }
    Some(())
}

/// Port of erts/emulator/beam/erl_bif_trace.c:3560-3715 (system_monitor), OTP-29.1.1.
fn system_monitor_set(
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    args: &[Term],
) -> Result<Term, VmError> {
    let runtime = process.runtime.ok_or_else(badarg)?;
    // `None` is the legacy (global) monitor, `Some` the monitor of a dynamic trace session.
    let key = if args[0] == Term::atom(arinsal_term::atoms::LEGACY) {
        None
    } else {
        Some(crate::natives::proc::trace_session_id(process, args[0]).ok_or_else(badarg)?)
    };
    // `ERTS_TRACER_IS_NIL(session->tracer)` selects the old erlang:system_monitor API.
    let session_tracer = match key {
        None => crate::trace::Tracer::Default,
        Some(key) => crate::trace::session_tracer(process, key).ok_or_else(badarg)?,
    };
    // erl_bif_trace.c:3584: a list that is neither a list nor nil.
    let list = to_owned(args[2]).map_err(|_| badarg())?;
    let entries = match &list {
        OwnedTerm::Nil => Vec::new(),
        OwnedTerm::List { elems, tail } if **tail == OwnedTerm::Nil => elems.clone(),
        _ => return Err(badarg()),
    };
    let store = |state: Option<SystemMonitorState>| {
        match &key {
            None => *runtime.system_monitor.lock().unwrap() = state,
            Some(key) => {
                let mut sessions = runtime.session_monitors.lock().unwrap();
                sessions.retain(|(owner, _)| owner != key);
                if let Some(state) = state {
                    sessions.push((*key, state));
                }
            }
        }
        runtime.long_message_queues.lock().unwrap().clear();
        refresh_system_monitor_flags(runtime);
    };
    let prev = match &key {
        None => runtime.system_monitor.lock().unwrap().clone(),
        Some(key) => runtime
            .session_monitors
            .lock()
            .unwrap()
            .iter()
            .find(|(owner, _)| owner == key)
            .map(|(_, state)| state.clone()),
    };
    let (receiver, mut options, return_term) = match session_tracer {
        crate::trace::Tracer::Default => {
            // Old API: `args[1]` is the monitor and the list is the whole new state.
            let return_term = match prev.clone() {
                Some(state) => from_owned(
                    &OwnedTerm::Tuple(vec![
                        state.receiver,
                        OwnedTerm::list(monitor_options_for_trace_info(&state.options)),
                    ]),
                    &mut arinsal_bifs::ProcessHeapHandle(&mut process.heap),
                )
                .map_err(|_| {
                    VmError::Trap(exceptions::Trap::error(Term::atom(
                        arinsal_term::atoms::SYSTEM_LIMIT,
                    )))
                })?,
                None => Term::atom(arinsal_term::atoms::UNDEFINED),
            };
            if args[1] == Term::atom(arinsal_term::atoms::UNDEFINED) || entries.is_empty() {
                store(None);
                return Ok(return_term);
            }
            (
                to_owned(args[1]).map_err(|_| badarg())?,
                HashMap::new(),
                return_term,
            )
        }
        crate::trace::Tracer::Pid(pid) => {
            // New API: the session tracer receives, `args[1]` must be `session` and the
            // list is a diff.
            if args[1] != Term::atom(arinsal_term::atoms::SESSION) {
                return Err(badarg());
            }
            (
                to_owned(pid.to_term().ok_or_else(badarg)?).map_err(|_| badarg())?,
                prev.map(|state| state.options).unwrap_or_default(),
                Term::atom(arinsal_term::atoms::OK),
            )
        }
        // ToDo in erts: ports and NIFs are not supported for system_monitor.
        _ => return Err(badarg()),
    };
    for entry in &entries {
        apply_monitor_option(&mut options, entry).ok_or_else(badarg)?;
    }
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
            .process_pids()
            .into_iter()
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
    let monitor_pid = match &receiver {
        OwnedTerm::Pid { id, serial, .. } => Some(Pid::new(*id, *serial)),
        _ => None,
    };
    store(Some(SystemMonitorState {
        receiver,
        options,
        key,
    }));
    // erl_process.c:14200 (erts_trace_check_exiting) only matters for the receiver.
    if let Some(pid) = monitor_pid {
        let _ = runtime.publish_proc_flag(pid, arinsal_sched::proc_flags::SYS_MON);
    }
    Ok(return_term)
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

// Port of erts/emulator/beam/beam_debug.c (erts_check_stack_recursion_downwards), OTP-29.1.1:
// body recursive on purpose, to measure how deep the native stack reaches before the limit.
#[inline(never)]
fn erts_check_stack_recursion_downwards(start_c: usize, prev_c: usize) -> usize {
    use arinsal_alloc::ethr;
    let limit = ethr::erts_get_stacklimit();
    let c = ethr::stack_marker();
    if prev_c == c {
        return 0;
    }
    if ethr::erts_check_below_limit(c, limit.wrapping_add(1024)) {
        return start_c - c;
    }
    let res = erts_check_stack_recursion_downwards(start_c, c);
    std::hint::black_box(c);
    res
}

// Port of erts/emulator/beam/beam_debug.c (erts_check_stack_recursion_upwards), OTP-29.1.1.
#[inline(never)]
fn erts_check_stack_recursion_upwards(start_c: usize, prev_c: usize) -> usize {
    use arinsal_alloc::ethr;
    let limit = ethr::erts_get_stacklimit();
    let c = ethr::stack_marker();
    if prev_c == c {
        return 0;
    }
    if ethr::erts_check_above_limit(c, limit.wrapping_sub(1024)) {
        return c - start_c;
    }
    let res = erts_check_stack_recursion_upwards(start_c, c);
    std::hint::black_box(c);
    res
}

// Port of erts/emulator/beam/beam_debug.c (erts_is_above_stack_limit), OTP-29.1.1.
fn erts_is_above_stack_limit(ptr: usize) -> bool {
    ptr > arinsal_alloc::ethr::erts_get_stacklimit()
}

// `enqueue_sys_msg(SYS_MSG_TYPE_SYSMON, from, receiver, ...)` of the monitor senders.
fn enqueue_sysmon(
    runtime: &'static crate::process::Runtime,
    from: arinsal_sched::Pid,
    receiver: arinsal_sched::Pid,
    message: Message,
) {
    if runtime.scheduler().is_ok()
        && let Some(to) = receiver.to_term()
    {
        crate::erl_trace::enqueue_sys_msg(
            crate::erl_trace::SysMsgType::Sysmon,
            Some(from),
            to,
            message,
        );
    }
}

#[cfg(test)]
mod check_io_tests {
    use super::*;
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;

    #[test]
    fn check_io_debug_counts_live_nif_selection() {
        let _guard = crate::check_io::tests::TEST_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
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
