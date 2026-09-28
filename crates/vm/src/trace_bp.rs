//! Function call trace patterns and call counters.

use crate::Process;
use arinsal_etf::OwnedTerm;
use arinsal_sched::Pid;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

#[derive(Clone)]
pub(crate) struct Pattern {
    pub(crate) session: u64,
    pub(crate) flags: Vec<String>,
    pub(crate) match_spec: Option<OwnedTerm>,
    pub(crate) meta: Option<OwnedTerm>,
    pub(crate) count: u64,
    pub(crate) paused: bool,
}

type Key = (usize, u64, String, String, Option<u8>);

static DEBUGGER_SUPPORT: AtomicBool = AtomicBool::new(false);
static LINE_BREAKPOINT_INSTRUMENTATION: AtomicBool = AtomicBool::new(true);

/// Apply the emulator's initial `+D` and `+Dibpl` flags before loading OTP code.
pub(crate) fn configure_debugger(supported: bool, line_breakpoints: bool) {
    DEBUGGER_SUPPORT.store(supported, Ordering::Release);
    LINE_BREAKPOINT_INSTRUMENTATION.store(line_breakpoints, Ordering::Release);
}

pub(crate) fn debugger_supported() -> bool {
    DEBUGGER_SUPPORT.load(Ordering::Acquire)
}

pub(crate) fn line_breakpoints_instrumented() -> bool {
    debugger_supported() && LINE_BREAKPOINT_INSTRUMENTATION.load(Ordering::Acquire)
}

pub(crate) fn set_line_breakpoint_instrumentation(enabled: bool) {
    LINE_BREAKPOINT_INSTRUMENTATION.store(enabled, Ordering::Release);
}

fn patterns() -> &'static Mutex<HashMap<Key, Pattern>> {
    static PATTERNS: OnceLock<Mutex<HashMap<Key, Pattern>>> = OnceLock::new();
    PATTERNS.get_or_init(|| Mutex::new(HashMap::new()))
}

type LineKey = (usize, usize, u32);
fn line_breakpoints() -> &'static Mutex<HashMap<LineKey, bool>> {
    static BREAKPOINTS: OnceLock<Mutex<HashMap<LineKey, bool>>> = OnceLock::new();
    BREAKPOINTS.get_or_init(|| Mutex::new(HashMap::new()))
}

type DebugBreakKey = (usize, String, String, Option<i64>);
fn debug_breakpoints() -> &'static Mutex<HashMap<DebugBreakKey, bool>> {
    static BREAKPOINTS: OnceLock<Mutex<HashMap<DebugBreakKey, bool>>> = OnceLock::new();
    BREAKPOINTS.get_or_init(|| Mutex::new(HashMap::new()))
}

pub(crate) fn set_debug_breakpoint(
    process: &Process,
    module: String,
    function: String,
    arity: Option<i64>,
    enabled: bool,
) {
    debug_breakpoints()
        .lock()
        .unwrap()
        .insert((scope(process), module, function, arity), enabled);
}

pub(crate) fn debug_breakpoint_enabled(
    process: &Process,
    module: &str,
    function: &str,
    arity: u8,
) -> bool {
    debug_breakpoints()
        .lock()
        .unwrap()
        .iter()
        .any(|((owner, m, f, a), enabled)| {
            *enabled
                && *owner == scope(process)
                && (m == "_" || m == module)
                && (f == "_" || f == function)
                && a.is_none_or(|a| a == i64::from(arity))
        })
}

#[derive(Clone, Copy)]
pub(crate) struct DebuggerRegistration {
    pub(crate) pid: Pid,
    pub(crate) session: u64,
}

fn registrations() -> &'static Mutex<HashMap<usize, DebuggerRegistration>> {
    static REGISTRATIONS: OnceLock<Mutex<HashMap<usize, DebuggerRegistration>>> = OnceLock::new();
    REGISTRATIONS.get_or_init(|| Mutex::new(HashMap::new()))
}

pub(crate) fn debugger_registration(process: &Process) -> Option<DebuggerRegistration> {
    let runtime = scope(process);
    let registration = registrations().lock().unwrap().get(&runtime).copied()?;
    let runtime_ref = process.runtime.as_ref()?;
    runtime_ref
        .scheduler()
        .ok()?
        .lookup(registration.pid)
        .then_some(registration)
}

pub(crate) fn register_debugger(process: &Process, pid: Pid) -> Result<u64, ()> {
    let runtime = scope(process);
    let mut registrations = registrations().lock().unwrap();
    if registrations.get(&runtime).is_some_and(|entry| {
        process
            .runtime
            .as_ref()
            .is_some_and(|r| r.scheduler().is_ok_and(|s| s.lookup(entry.pid)))
    }) {
        return Err(());
    }
    static NEXT_SESSION: AtomicU64 = AtomicU64::new(1);
    let session = NEXT_SESSION.fetch_add(1, Ordering::Relaxed).max(1);
    registrations.insert(runtime, DebuggerRegistration { pid, session });
    Ok(session)
}

pub(crate) fn unregister_debugger(process: &Process, pid: Pid, session: u64) -> Result<(), bool> {
    let runtime = scope(process);
    let mut registrations = registrations().lock().unwrap();
    if let Some(entry) = registrations.get(&runtime).copied()
        && entry.pid == pid
    {
        if entry.session != session {
            return Err(false);
        }
        registrations.remove(&runtime);
    }
    Ok(())
}

pub(crate) fn set_line_breakpoint(process: &Process, module_id: usize, line: u32, enabled: bool) {
    line_breakpoints()
        .lock()
        .unwrap()
        .insert((scope(process), module_id, line), enabled);
}

pub(crate) fn line_breakpoint_enabled(process: &Process, module_id: usize, line: u32) -> bool {
    line_breakpoints()
        .lock()
        .unwrap()
        .get(&(scope(process), module_id, line))
        .copied()
        .unwrap_or(false)
}

fn active() -> &'static AtomicBool {
    static ACTIVE: AtomicBool = AtomicBool::new(false);
    &ACTIVE
}

fn scope(process: &Process) -> usize {
    process
        .runtime
        .as_ref()
        .map_or(0, |runtime| std::sync::Arc::as_ptr(runtime) as usize)
}

// Runtime-scoped breakpoint entries must not keep the global gate enabled
// after the owning VM runtime has been dropped.
impl Drop for crate::process::Runtime {
    fn drop(&mut self) {
        crate::trace::clear_runtime(self as *const Self as usize);
        clear_scope(self as *const Self as usize);
    }
}

fn clear_scope(runtime: usize) {
    let mut entries = patterns().lock().unwrap();
    entries.retain(|(scope, _, _, _, _), _| *scope != runtime);
    active().store(!entries.is_empty(), Ordering::Relaxed);
    registrations()
        .lock()
        .unwrap()
        .retain(|scope, _| *scope != runtime);
    line_breakpoints()
        .lock()
        .unwrap()
        .retain(|(scope, _, _), _| *scope != runtime);
    debug_breakpoints()
        .lock()
        .unwrap()
        .retain(|(scope, _, _, _), _| *scope != runtime);
}

pub(crate) fn set(
    process: &Process,
    session: u64,
    module: String,
    function: String,
    arity: Option<u8>,
    pattern: Option<Pattern>,
) -> bool {
    let key = (scope(process), session, module, function, arity);
    let mut entries = patterns().lock().unwrap();
    let existed = if let Some(pattern) = pattern {
        entries.insert(key, pattern).is_some()
    } else {
        entries.remove(&key).is_some()
    };
    active().store(!entries.is_empty(), Ordering::Relaxed);
    existed
}

pub(crate) fn pause(
    process: &Process,
    session: u64,
    module: &str,
    function: &str,
    arity: Option<u8>,
    paused: bool,
) {
    if let Some(pattern) = patterns().lock().unwrap().get_mut(&(
        scope(process),
        session,
        module.to_owned(),
        function.to_owned(),
        arity,
    )) {
        pattern.paused = paused;
        if !paused {
            pattern.count = 0;
        }
    }
}

pub(crate) fn matching(
    process: &Process,
    module: &str,
    function: &str,
    arity: u8,
    local: bool,
) -> Vec<Pattern> {
    let entries = patterns().lock().unwrap();
    entries
        .iter()
        .filter(|((runtime, _, m, f, a), pattern)| {
            *runtime == scope(process)
                && (m == "_" || m == module)
                && (f == "_" || f == function)
                && a.is_none_or(|a| a == arity)
                && pattern
                    .flags
                    .iter()
                    .any(|flag| flag == if local { "local" } else { "global" })
        })
        .map(|(_, pattern)| pattern.clone())
        .collect()
}

pub(crate) fn increment(process: &Process, module: &str, function: &str, arity: u8, local: bool) {
    for ((runtime, _, m, f, a), pattern) in patterns().lock().unwrap().iter_mut() {
        if *runtime == scope(process)
            && (m == "_" || m == module)
            && (f == "_" || f == function)
            && a.is_none_or(|a| a == arity)
            && pattern.flags.iter().any(|flag| flag == "call_count")
            && (pattern
                .flags
                .iter()
                .any(|flag| flag == if local { "local" } else { "global" })
                || (local
                    && !pattern
                        .flags
                        .iter()
                        .any(|flag| flag == "local" || flag == "global")))
        {
            pattern.count = pattern.count.saturating_add(1);
        }
    }
}

pub(crate) fn info(
    process: &Process,
    module: &str,
    function: &str,
    arity: u8,
    item: &str,
) -> Option<OwnedTerm> {
    let entries = patterns().lock().unwrap();
    let pattern = entries.get(&(
        scope(process),
        0,
        module.to_owned(),
        function.to_owned(),
        Some(arity),
    ));
    let false_atom = || OwnedTerm::Atom("false".into());
    let traced = || {
        pattern.map_or_else(false_atom, |pattern| {
            OwnedTerm::Atom(
                if pattern.flags.iter().any(|flag| flag == "global") {
                    "global"
                } else {
                    "local"
                }
                .into(),
            )
        })
    };
    let match_spec = || {
        pattern
            .and_then(|pattern| pattern.match_spec.clone())
            .unwrap_or(OwnedTerm::Nil)
    };
    let call_count = || {
        pattern.map_or_else(false_atom, |pattern| {
            if pattern.flags.iter().any(|flag| flag == "call_count") {
                OwnedTerm::Int(pattern.count as i64)
            } else {
                false_atom()
            }
        })
    };
    match item {
        "traced" => Some(traced()),
        "match_spec" => Some(match_spec()),
        "meta" => Some(
            pattern
                .and_then(|pattern| pattern.meta.clone())
                .unwrap_or_else(false_atom),
        ),
        "meta_match_spec" | "call_memory" | "call_time" => Some(false_atom()),
        "call_count" => Some(call_count()),
        "all" => {
            let values = [
                ("traced", traced()),
                ("match_spec", match_spec()),
                (
                    "meta",
                    pattern
                        .and_then(|pattern| pattern.meta.clone())
                        .unwrap_or_else(false_atom),
                ),
                ("meta_match_spec", false_atom()),
                ("call_memory", false_atom()),
                ("call_time", false_atom()),
                ("call_count", call_count()),
            ];
            Some(OwnedTerm::List {
                elems: values
                    .into_iter()
                    .map(|(key, value)| OwnedTerm::Tuple(vec![OwnedTerm::Atom(key.into()), value]))
                    .collect(),
                tail: Box::new(OwnedTerm::Nil),
            })
        }
        _ => None,
    }
}

pub(crate) fn breakpoint_kinds(
    process: &Process,
    module: &str,
    function: &str,
    arity: u8,
) -> (bool, bool) {
    let runtime = scope(process);
    let entries = patterns().lock().unwrap();
    let patterns = entries.iter().filter_map(|((owner, _, m, f, a), pattern)| {
        (*owner == runtime
            && (m == "_" || m == module)
            && (f == "_" || f == function)
            && a.is_none_or(|a| a == arity))
        .then_some(pattern)
    });
    let mut local = crate::trace::return_to_enabled(process)
        || debug_breakpoint_enabled(process, module, function, arity);
    let mut global = false;
    for pattern in patterns {
        if pattern.flags.iter().any(|flag| flag == "global") {
            global = true;
        } else if pattern.flags.iter().any(|flag| flag == "local")
            || (pattern.flags.iter().any(|flag| flag == "call_count")
                && !pattern
                    .flags
                    .iter()
                    .any(|flag| flag == "local" || flag == "global"))
        {
            local = true;
        }
    }
    (local, global)
}
