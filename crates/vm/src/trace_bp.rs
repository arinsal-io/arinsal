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
    /// Write order; the newest pattern covering a function decides its state.
    pub(crate) seq: u64,
    /// Marks a `false` pattern that overrides older wildcard patterns.
    pub(crate) off: bool,
}

type Key = (usize, u64, String, String, Option<u8>);

fn covers(spec: (&str, &str, Option<u8>), module: &str, function: &str, arity: Option<u8>) -> bool {
    (spec.0 == "_" || spec.0 == module)
        && (spec.1 == "_" || spec.1 == function)
        && spec.2.is_none_or(|a| Some(a) == arity)
}

fn overlaps(a: (&str, &str, Option<u8>), b: (&str, &str, Option<u8>)) -> bool {
    (a.0 == "_" || b.0 == "_" || a.0 == b.0)
        && (a.1 == "_" || b.1 == "_" || a.1 == b.1)
        && (a.2.is_none() || b.2.is_none() || a.2 == b.2)
}

/// Per session, the newest pattern covering the function, unless it disables tracing.
/// Port of the per-function breakpoint state of erts/emulator/beam/beam_bp.c, OTP-29.1.1.
fn winners<'a>(
    entries: &'a HashMap<Key, Pattern>,
    runtime: usize,
    code: u64,
    session: Option<u64>,
    module: &str,
    function: &str,
    arity: u8,
) -> Vec<(&'a Key, &'a Pattern)> {
    let mut best: HashMap<u64, (&Key, &Pattern)> = HashMap::new();
    let cutoff = module_cutoff(code, module);
    for (key, pattern) in entries {
        if key.0 != runtime
            || pattern.seq < cutoff
            || session.is_some_and(|wanted| wanted != key.1)
            || !covers((&key.2, &key.3, key.4), module, function, Some(arity))
        {
            continue;
        }
        let slot = best.entry(key.1).or_insert((key, pattern));
        if pattern.seq > slot.1.seq {
            *slot = (key, pattern);
        }
    }
    best.into_values()
        .filter(|(_, pattern)| !pattern.off)
        .collect()
}

/// Memo of `winners` over all sessions per function. Every call into a traced function asks for
/// it several times and the pattern table can hold thousands of entries (a session tracing all
/// exports), so scanning per call starves the traced process. Cleared (while the pattern table
/// lock is held) by everything that changes the table or the module cutoffs.
type WinnerCache = HashMap<(usize, u64, u8, String, String), Vec<Key>>;

fn winner_cache() -> &'static Mutex<WinnerCache> {
    static CACHE: OnceLock<Mutex<WinnerCache>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn invalidate_winners() {
    winner_cache().lock().unwrap().clear();
}

fn winners_all<'a>(
    entries: &'a HashMap<Key, Pattern>,
    runtime: usize,
    code: u64,
    module: &str,
    function: &str,
    arity: u8,
) -> Vec<(&'a Key, &'a Pattern)> {
    let probe = (runtime, code, arity, module.to_owned(), function.to_owned());
    if let Some(keys) = winner_cache().lock().unwrap().get(&probe) {
        return keys
            .iter()
            .filter_map(|key| entries.get_key_value(key))
            .collect();
    }
    let found = winners(entries, runtime, code, None, module, function, arity);
    let keys = found.iter().map(|(key, _)| (*key).clone()).collect();
    winner_cache().lock().unwrap().insert(probe, keys);
    found
}

static SEQUENCE: AtomicU64 = AtomicU64::new(1);

fn cutoffs() -> &'static Mutex<HashMap<(u64, String), u64>> {
    static CUTOFFS: OnceLock<Mutex<HashMap<(u64, String), u64>>> = OnceLock::new();
    CUTOFFS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn module_cutoff(code: u64, module: &str) -> u64 {
    cutoffs()
        .lock()
        .unwrap()
        .get(&(code, module.to_owned()))
        .copied()
        .unwrap_or(0)
}

fn code_scope(process: &Process) -> u64 {
    process
        .runtime
        .as_ref()
        .map_or(0, |runtime| runtime.code_scope)
}

/// Breakpoints belong to a code instance: a patterns set before a module was
/// loaded, upgraded or deleted never applies to the module's later code.
// Port of erts/emulator/beam/beam_bif_load.c:470-480 and 714-720
// (erts_clear_module_break on finish_loading / delete_module), OTP-29.1.1.
pub(crate) fn module_code_changed(code: u64, module: &str) {
    let _entries = patterns().lock().unwrap();
    let seq = SEQUENCE.load(Ordering::Relaxed);
    cutoffs()
        .lock()
        .unwrap()
        .insert((code, module.to_owned()), seq);
    invalidate_winners();
}

/// Session state of `trace_pattern(on_load, ...)`: the pattern applied to every module when it
/// is loaded.
// Port of erts/emulator/beam/erl_bif_trace.c:2523-2603 (change_on_load_trace_pattern), OTP-29.1.1.
#[derive(Clone, Default)]
pub(crate) struct OnLoadPattern {
    /// Subset of `local`, `call_count`; empty means a global call trace.
    pub flags: Vec<String>,
    pub match_spec: Option<OwnedTerm>,
}

fn on_load_patterns() -> &'static Mutex<HashMap<(usize, u64), OnLoadPattern>> {
    static ON_LOAD: OnceLock<Mutex<HashMap<(usize, u64), OnLoadPattern>>> = OnceLock::new();
    ON_LOAD.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Apply `trace_pattern(on_load, ...)` to a session. `on` is false for a `false` pattern.
pub(crate) fn change_on_load(
    process: &Process,
    session: u64,
    on: bool,
    flags: &[String],
    match_spec: Option<OwnedTerm>,
) {
    let breakpoint = |names: &[String]| names.iter().any(|n| n == "local" || n == "call_count");
    let key = (scope(process), session);
    let mut map = on_load_patterns().lock().unwrap();
    let new_flags: Vec<String> = flags.iter().filter(|n| *n != "global").cloned().collect();
    let new_breakpoint = breakpoint(&new_flags);
    let Some(current) = map.get_mut(&key) else {
        // Off -> on; turning an absent pattern off changes nothing.
        if on {
            map.insert(
                key,
                OnLoadPattern {
                    flags: new_flags,
                    match_spec,
                },
            );
        }
        return;
    };
    let current_breakpoint = breakpoint(&current.flags);
    if current_breakpoint && new_breakpoint {
        // Breakpoint trace -> breakpoint trace: merge or subtract the flags.
        if on {
            for name in new_flags {
                if !current.flags.contains(&name) {
                    current.flags.push(name);
                }
            }
        } else {
            current.flags.retain(|name| !new_flags.contains(name));
            if !breakpoint(&current.flags) {
                map.remove(&key);
                return;
            }
        }
        if flags.iter().any(|n| n == "local") || !flags.iter().any(|n| n == "call_count") {
            current.match_spec = match_spec;
        }
    } else if !current_breakpoint && !new_breakpoint {
        if on {
            current.match_spec = match_spec;
        } else {
            map.remove(&key);
        }
    } else if on {
        // Switching between global and breakpoint trace replaces the pattern.
        *current = OnLoadPattern {
            flags: new_flags,
            match_spec,
        };
    }
}

pub(crate) fn on_load_pattern(process: &Process, session: u64) -> Option<OnLoadPattern> {
    on_load_patterns()
        .lock()
        .unwrap()
        .get(&(scope(process), session))
        .cloned()
}

/// The on_load patterns of all sessions of this runtime.
pub(crate) fn on_load_patterns_of(process: &Process) -> Vec<(u64, OnLoadPattern)> {
    let runtime = scope(process);
    on_load_patterns()
        .lock()
        .unwrap()
        .iter()
        .filter(|((owner, _), _)| *owner == runtime)
        .map(|((_, session), pattern)| (*session, pattern.clone()))
        .collect()
}

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
    on_load_patterns()
        .lock()
        .unwrap()
        .retain(|(scope, _), _| *scope != runtime);
    invalidate_winners();
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
    let runtime = scope(process);
    let spec = (module.as_str(), function.as_str(), arity);
    let mut entries = patterns().lock().unwrap();
    // A new pattern replaces every older pattern of the session it covers.
    let before = entries.len();
    entries.retain(|key, _| {
        key.0 != runtime || key.1 != session || !covers(spec, &key.2, &key.3, key.4)
    });
    let existed = entries.len() != before;
    let seq = SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let key = (runtime, session, module.clone(), function.clone(), arity);
    if let Some(mut pattern) = pattern {
        pattern.seq = seq;
        pattern.off = false;
        entries.insert(key, pattern);
    } else if entries.iter().any(|(old, _)| {
        old.0 == runtime && old.1 == session && overlaps((&old.2, &old.3, old.4), spec)
    }) {
        // An older, wider pattern still covers part of this spec: remember the exception.
        entries.insert(
            key,
            Pattern {
                session,
                flags: Vec::new(),
                match_spec: None,
                meta: None,
                count: 0,
                paused: false,
                seq,
                off: true,
            },
        );
    }
    invalidate_winners();
    active().store(entries.values().any(|p| !p.off), Ordering::Relaxed);
    existed
}

/// Remove all MFA breakpoint patterns owned by a destroyed trace session.
// Port of erts/emulator/beam/erl_bif_trace.c:1352-1375, OTP-29.1.1.
pub(crate) fn clear_session(process: &Process, session: u64) {
    let runtime = scope(process);
    let mut entries = patterns().lock().unwrap();
    entries.retain(|(owner, id, _, _, _), _| *owner != runtime || *id != session);
    on_load_patterns()
        .lock()
        .unwrap()
        .remove(&(runtime, session));
    invalidate_winners();
    active().store(entries.values().any(|p| !p.off), Ordering::Relaxed);
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

// Port of erts/emulator/beam/beam_bp.c:1115-1285, OTP-29.1.1.
pub(crate) fn matching(
    process: &Process,
    module: &str,
    function: &str,
    arity: u8,
    local: bool,
) -> Vec<Pattern> {
    let entries = patterns().lock().unwrap();
    winners_all(
        &entries,
        scope(process),
        code_scope(process),
        module,
        function,
        arity,
    )
    .into_iter()
    .filter(|(_, pattern)| {
        let has_global = pattern.flags.iter().any(|flag| flag == "global");
        let has_local = pattern.flags.iter().any(|flag| flag == "local");
        // No flag at all means a plain global call trace; call_count alone only counts.
        let has_trace = pattern.flags.is_empty()
            || pattern.flags.iter().any(|flag| flag != "call_count")
            || pattern.match_spec.is_some();
        has_trace
            && if local {
                has_local
            } else {
                has_global || (!has_local && !has_global)
            }
    })
    .map(|(_, pattern)| pattern.clone())
    .collect()
}

/// True while some runtime holds a function trace pattern; keeps untraced BIF calls on the fast path.
pub(crate) fn any_pattern() -> bool {
    active().load(Ordering::Relaxed)
}

/// Whether a pattern of any session or runtime selects this function.
// Port of erts/emulator/beam/beam_bp.c:321-330 (erts_export_is_bif_traced), OTP-29.1.1.
pub(crate) fn selects(module: &str, function: &str, arity: u8) -> bool {
    patterns()
        .lock()
        .unwrap()
        .iter()
        .any(|((_, _, m, f, a), pattern)| {
            !pattern.off && covers((m, f, *a), module, function, Some(arity))
        })
}

pub(crate) fn increment(process: &Process, module: &str, function: &str, arity: u8, local: bool) {
    let mut entries = patterns().lock().unwrap();
    let keys = winners_all(
        &entries,
        scope(process),
        code_scope(process),
        module,
        function,
        arity,
    )
    .into_iter()
    .filter(|(_, pattern)| {
        pattern.flags.iter().any(|flag| flag == "call_count")
            && (pattern
                .flags
                .iter()
                .any(|flag| flag == if local { "local" } else { "global" })
                || (local
                    && !pattern
                        .flags
                        .iter()
                        .any(|flag| flag == "local" || flag == "global")))
    })
    .map(|(key, _)| key.clone())
    .collect::<Vec<_>>();
    for key in keys {
        if let Some(pattern) = entries.get_mut(&key) {
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
    info_session(process, 0, module, function, arity, item)
}

pub(crate) fn info_session(
    process: &Process,
    session: u64,
    module: &str,
    function: &str,
    arity: u8,
    item: &str,
) -> Option<OwnedTerm> {
    // Port of erts/emulator/beam/erl_bif_trace.c:1403-1465, OTP-29.1.1.
    let entries = patterns().lock().unwrap();
    let pattern = winners(
        &entries,
        scope(process),
        code_scope(process),
        Some(session),
        module,
        function,
        arity,
    )
    .into_iter()
    .next()
    .map(|(_, pattern)| pattern);
    let false_atom = || OwnedTerm::Atom("false".into());
    let traced = || {
        pattern.map_or_else(false_atom, |pattern| {
            OwnedTerm::Atom(
                if pattern.flags.iter().any(|flag| flag == "global")
                    || !pattern.flags.iter().any(|flag| flag == "local")
                {
                    "global"
                } else {
                    "local"
                }
                .into(),
            )
        })
    };
    // An untraced function reports `{match_spec, false}`; a traced one without a match
    // specification reports `[]`.
    let match_spec = || {
        pattern.map_or_else(false_atom, |pattern| {
            pattern.match_spec.clone().unwrap_or(OwnedTerm::Nil)
        })
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

// Port of erts/emulator/beam/erl_bif_trace.c:498 and 2721, OTP-29.1.1.
pub(crate) fn breakpoint_kinds(
    process: &Process,
    module: &str,
    function: &str,
    arity: u8,
) -> (bool, bool) {
    let entries = patterns().lock().unwrap();
    let patterns = winners_all(
        &entries,
        scope(process),
        code_scope(process),
        module,
        function,
        arity,
    )
    .into_iter()
    .map(|(_, pattern)| pattern);
    let mut local = crate::trace::return_to_enabled(process)
        || debug_breakpoint_enabled(process, module, function, arity);
    let mut global = false;
    for pattern in patterns {
        if pattern.flags.iter().any(|flag| flag == "call_count") {
            local = true;
        }
        if pattern.flags.iter().any(|flag| flag == "global")
            || !pattern
                .flags
                .iter()
                .any(|flag| flag == "local" || flag == "global")
        {
            global = true;
        } else if pattern.flags.iter().any(|flag| flag == "local") {
            local = true;
        }
    }
    (local, global)
}
