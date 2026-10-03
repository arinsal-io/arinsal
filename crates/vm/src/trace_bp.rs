//! Function call trace breakpoints and call counters.
//!
//! Port of the per-function breakpoint data of erts/emulator/beam/beam_bp.c (GenericBp,
//! GenericBpData), OTP-29.1.1: `trace_pattern` writes breakpoint data into every matched
//! function, so a traced call finds its data with one lookup, independent of how many
//! patterns were set.

use crate::Process;
use arinsal_etf::OwnedTerm;
use arinsal_sched::Pid;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock, RwLock};

// Port of erts/emulator/beam/beam_bp.c:55-66 (ERTS_BPF_*), OTP-29.1.1. Call time, call memory
// and debug breakpoints are not stored here: the first two are not supported, debug
// breakpoints live in `debug_breakpoints`.
const BPF_LOCAL_TRACE: u32 = 0x01;
const BPF_META_TRACE: u32 = 0x02;
const BPF_COUNT: u32 = 0x04;
const BPF_COUNT_ACTIVE: u32 = 0x08;
const BPF_GLOBAL_TRACE: u32 = 0x80;
const BPF_ALL: u32 = 0x3FF;

/// Port of erts/emulator/beam/beam_bp.h:104-109 (enum erts_break_op), OTP-29.1.1.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum BreakOp {
    Nop,
    Set,
    Restart,
    Pause,
}

/// Port of erts/emulator/beam/erl_bif_trace.c (struct trace_pattern_flags), OTP-29.1.1.
#[derive(Clone, Copy, Default)]
pub(crate) struct TracePatternFlags {
    /// Any of the flags below: a code breakpoint rather than export (global) tracing.
    pub(crate) breakpoint: bool,
    pub(crate) local: bool,
    pub(crate) meta: bool,
    pub(crate) call_count: bool,
}

/// A function matched by a trace pattern (erts BpFunction).
pub(crate) struct BpFunction {
    pub(crate) module: String,
    pub(crate) function: String,
    pub(crate) arity: u8,
    /// Has an export entry, which is where global call tracing lives.
    pub(crate) exported: bool,
}

/// A trace match specification with its compiled program, built on first use.
// Port of erts/emulator/beam/beam_bp.c (MatchSetRef / erts_match_set_compile), OTP-29.1.1: erts
// compiles the match set once in `trace_pattern` and every call runs the stored Binary.
pub(crate) struct MatchSpec {
    pub(crate) source: OwnedTerm,
    /// The spec calls `{process_dump}`; erts captures the dump only then.
    pub(crate) uses_process_dump: bool,
    /// The spec calls `{caller}` or `{caller_line}`.
    pub(crate) uses_caller: bool,
    program: OnceLock<Result<arinsal_ets::match_spec::MatchProgram, ()>>,
}

impl MatchSpec {
    fn new(source: OwnedTerm) -> Self {
        fn uses(term: &OwnedTerm, name: &str) -> bool {
            match term {
                OwnedTerm::Tuple(fields) => {
                    matches!(fields.as_slice(), [OwnedTerm::Atom(atom)] if atom == name)
                        || fields.iter().any(|field| uses(field, name))
                }
                OwnedTerm::List { elems, tail } => {
                    elems.iter().any(|elem| uses(elem, name)) || uses(tail, name)
                }
                OwnedTerm::Map(pairs) => pairs
                    .iter()
                    .any(|(key, value)| uses(key, name) || uses(value, name)),
                _ => false,
            }
        }
        Self {
            uses_process_dump: uses(&source, "process_dump"),
            uses_caller: uses(&source, "caller") || uses(&source, "caller_line"),
            source,
            program: OnceLock::new(),
        }
    }

    /// The compiled program; `compile` builds it from the source on first use.
    pub(crate) fn program(
        &self,
        compile: impl FnOnce(&OwnedTerm) -> Result<arinsal_ets::match_spec::MatchProgram, ()>,
    ) -> Result<&arinsal_ets::match_spec::MatchProgram, ()> {
        self.program
            .get_or_init(|| compile(&self.source))
            .as_ref()
            .map_err(|_| ())
    }
}

/// Port of erts/emulator/beam/beam_bp.h:75-83 (GenericBpData), OTP-29.1.1.
#[derive(Clone, Default)]
struct GenericBpData {
    flags: u32,
    local_ms: Option<Arc<MatchSpec>>,
    meta_ms: Option<Arc<MatchSpec>>,
    count: Option<Arc<AtomicU64>>,
}

/// Port of erts/emulator/beam/beam_bp.h:85-94 (GenericBp), OTP-29.1.1: one per trace session
/// and function. Runtime and code scope tag the VM instance the function belongs to.
struct GenericBp {
    runtime: usize,
    code: u64,
    session: u64,
    data: [GenericBpData; 2],
}

/// The breakpoints of one function, by module, name and arity; borrowed-key lookups keep the
/// traced call path allocation free.
type BpTable = HashMap<String, HashMap<String, HashMap<u8, Vec<GenericBp>>>>;

fn breakpoints() -> &'static RwLock<BpTable> {
    static TABLE: OnceLock<RwLock<BpTable>> = OnceLock::new();
    TABLE.get_or_init(|| RwLock::new(HashMap::new()))
}

/// Port of erts/emulator/beam/beam_bp.h:230-238 (erts_active_bp_ix, erts_staging_bp_ix),
/// OTP-29.1.1. Only changed with the table write lock held.
static ACTIVE_BP_IX: AtomicUsize = AtomicUsize::new(0);

fn active_bp_ix() -> usize {
    ACTIVE_BP_IX.load(Ordering::Acquire)
}

fn staging_bp_ix() -> usize {
    active_bp_ix() ^ 1
}

/// The breakpoints of one function in this VM, any session.
fn function_bps<'a>(
    table: &'a BpTable,
    runtime: usize,
    code: u64,
    module: &str,
    function: &str,
    arity: u8,
) -> impl Iterator<Item = &'a GenericBp> {
    table
        .get(module)
        .and_then(|functions| functions.get(function))
        .and_then(|arities| arities.get(&arity))
        .into_iter()
        .flatten()
        .filter(move |g| g.runtime == runtime && g.code == code)
}

fn code_scope(process: &Process) -> u64 {
    process
        .runtime
        .as_ref()
        .map_or(0, |runtime| runtime.code_scope)
}

fn update_active(table: &BpTable) {
    active().store(
        table
            .values()
            .flat_map(|functions| functions.values())
            .flat_map(|arities| arities.values())
            .any(|bps| !bps.is_empty()),
        Ordering::Relaxed,
    );
}

/// Breakpoints belong to a code instance: breakpoints set before a module was loaded,
/// upgraded or deleted never apply to the module's later code.
// Port of erts/emulator/beam/beam_bp.c:854-900 (erts_clear_module_break), called from
// erts/emulator/beam/beam_bif_load.c:470-480 and 714-720, OTP-29.1.1.
pub(crate) fn module_code_changed(code: u64, module: &str) {
    let mut table = breakpoints().write().unwrap();
    if let Some(functions) = table.get_mut(module) {
        for bps in functions
            .values_mut()
            .flat_map(|arities| arities.values_mut())
        {
            bps.retain(|g| g.code != code);
        }
        functions.retain(|_, arities| {
            arities.retain(|_, bps| !bps.is_empty());
            !arities.is_empty()
        });
        if functions.is_empty() {
            table.remove(module);
        }
    }
    update_active(&table);
}

/// Port of erts/emulator/beam/beam_bp.c (set_function_break), OTP-29.1.1, for the staging
/// copy of one session's breakpoint of one function.
fn set_function_break(
    bps: &mut Vec<GenericBp>,
    tag: (usize, u64, u64),
    match_spec: Option<&Arc<MatchSpec>>,
    break_flags: u32,
    count_op: BreakOp,
) {
    let ix = staging_bp_ix();
    let (runtime, code, session) = tag;
    let position = bps
        .iter()
        .position(|g| g.runtime == runtime && g.code == code && g.session == session);
    // Global trace lives in the export entry's own GenericBp in erts: a code breakpoint exists
    // only while some code breakpoint flag is staged.
    let exists = position.is_some_and(|index| {
        break_flags == BPF_GLOBAL_TRACE || bps[index].data[ix].flags & !BPF_GLOBAL_TRACE != 0
    });
    if !exists && matches!(count_op, BreakOp::Restart | BreakOp::Pause) {
        // Do not insert a new breakpoint.
        return;
    }
    let index = match position {
        Some(index) => index,
        None => {
            bps.push(GenericBp {
                runtime,
                code,
                session,
                data: Default::default(),
            });
            bps.len() - 1
        }
    };
    let bp = &mut bps[index].data[ix];
    let common = break_flags & bp.flags;
    if common & BPF_COUNT != 0 {
        if count_op == BreakOp::Pause {
            bp.flags &= !BPF_COUNT_ACTIVE;
        } else {
            bp.flags |= BPF_COUNT_ACTIVE;
            if let Some(count) = &bp.count {
                count.store(0, Ordering::Relaxed);
            }
        }
        return;
    }
    if break_flags & (BPF_LOCAL_TRACE | BPF_GLOBAL_TRACE) != 0 {
        bp.local_ms = match_spec.cloned();
    } else if break_flags & BPF_META_TRACE != 0 {
        bp.meta_ms = match_spec.cloned();
    } else if break_flags & BPF_COUNT != 0 {
        bp.count = Some(Arc::new(AtomicU64::new(0)));
    }
    bp.flags |= break_flags;
}

/// Port of erts/emulator/beam/beam_bp.c (clear_function_break_session), OTP-29.1.1.
fn clear_function_break(bps: &mut [GenericBp], tag: (usize, u64, u64), break_flags: u32) {
    let ix = staging_bp_ix();
    let (runtime, code, session) = tag;
    let Some(g) = bps
        .iter_mut()
        .find(|g| g.runtime == runtime && g.code == code && g.session == session)
    else {
        return;
    };
    let bp = &mut g.data[ix];
    let common = bp.flags & break_flags;
    if common == 0 {
        return;
    }
    bp.flags &= !break_flags;
    if common & (BPF_LOCAL_TRACE | BPF_GLOBAL_TRACE) != 0 {
        bp.local_ms = None;
    }
    if common & BPF_META_TRACE != 0 {
        bp.meta_ms = None;
    }
    if common & BPF_COUNT != 0 {
        bp.count = None;
    }
}

/// Copy the active data to the staging area and unlink disabled breakpoints after a commit.
// Port of erts/emulator/beam/beam_bp.c:443-560 (consolidate_bp_data,
// consolidate_bp_data_session), OTP-29.1.1.
fn consolidate_bp_data(bps: &mut Vec<GenericBp>) {
    let (active, staging) = (active_bp_ix(), staging_bp_ix());
    for g in bps.iter_mut() {
        g.data[staging] = g.data[active].clone();
    }
    bps.retain(|g| g.data[active].flags != 0);
}

fn function_entry<'a>(
    table: &'a mut BpTable,
    module: &str,
    function: &str,
    arity: u8,
) -> &'a mut Vec<GenericBp> {
    table
        .entry(module.to_owned())
        .or_default()
        .entry(function.to_owned())
        .or_default()
        .entry(arity)
        .or_default()
}

/// Commit the staged breakpoints of the given functions and consolidate them.
// Port of erts/emulator/beam/beam_bp.c:562-569 (erts_commit_staged_bp) and the consolidation
// step of erts/emulator/beam/erl_bif_trace.c (erts_finish_breakpointing), OTP-29.1.1.
fn commit_and_consolidate(table: &mut BpTable, functions: &[BpFunction]) {
    ACTIVE_BP_IX.store(staging_bp_ix(), Ordering::Release);
    for function in functions {
        let Some(arities) = table
            .get_mut(&function.module)
            .and_then(|functions| functions.get_mut(&function.function))
        else {
            continue;
        };
        if let Some(bps) = arities.get_mut(&function.arity) {
            consolidate_bp_data(bps);
            if bps.is_empty() {
                arities.remove(&function.arity);
            }
        }
        if arities.is_empty() {
            let functions = table.get_mut(&function.module).unwrap();
            functions.remove(&function.function);
            if functions.is_empty() {
                table.remove(&function.module);
            }
        }
    }
    update_active(table);
}

/// Set or clear the breakpoints of one session in the matched functions.
// Port of erts/emulator/beam/erl_bif_trace.c:2621-2725 (erts_set_trace_pattern), OTP-29.1.1.
pub(crate) fn set_trace_pattern(
    process: &Process,
    session: u64,
    functions: &[BpFunction],
    match_spec: Option<OwnedTerm>,
    on: BreakOp,
    flags: TracePatternFlags,
) {
    let tag = (scope(process), code_scope(process), session);
    let match_spec = match_spec.map(|source| Arc::new(MatchSpec::new(source)));
    let mut table = breakpoints().write().unwrap();
    // First the code breakpoints ("local" tracing).
    for function in functions {
        let bps = function_entry(
            &mut table,
            &function.module,
            &function.function,
            function.arity,
        );
        if on != BreakOp::Nop {
            if !flags.breakpoint {
                clear_function_break(bps, tag, BPF_ALL & !BPF_GLOBAL_TRACE);
            } else {
                if flags.local {
                    set_function_break(
                        bps,
                        tag,
                        match_spec.as_ref(),
                        BPF_LOCAL_TRACE,
                        BreakOp::Nop,
                    );
                }
                if flags.meta {
                    set_function_break(bps, tag, match_spec.as_ref(), BPF_META_TRACE, BreakOp::Nop);
                }
                if flags.call_count {
                    set_function_break(bps, tag, None, BPF_COUNT | BPF_COUNT_ACTIVE, on);
                }
            }
        } else {
            if flags.local {
                clear_function_break(bps, tag, BPF_LOCAL_TRACE);
            }
            if flags.meta {
                clear_function_break(bps, tag, BPF_META_TRACE);
            }
            if flags.call_count {
                clear_function_break(bps, tag, BPF_COUNT | BPF_COUNT_ACTIVE);
            }
        }
    }
    // Then the export entries, once the code breakpoints are set.
    for function in functions.iter().filter(|function| function.exported) {
        let bps = function_entry(
            &mut table,
            &function.module,
            &function.function,
            function.arity,
        );
        if on != BreakOp::Nop && !flags.breakpoint {
            set_function_break(
                bps,
                tag,
                match_spec.as_ref(),
                BPF_GLOBAL_TRACE,
                BreakOp::Nop,
            );
        } else if on == BreakOp::Nop && flags.breakpoint {
            // Turning off breakpoint tracing leaves global tracing alone.
        } else {
            // Turn off global tracing, explicitly or before turning on breakpoint tracing.
            clear_function_break(bps, tag, BPF_GLOBAL_TRACE);
        }
    }
    commit_and_consolidate(&mut table, functions);
}

/// Remove all breakpoints owned by a destroyed trace session.
// Port of erts/emulator/beam/erl_bif_trace.c:2727-2760 (prepare_clear_all_trace_pattern) and
// 1352-1375, OTP-29.1.1.
pub(crate) fn clear_session(process: &Process, session: u64) {
    let runtime = scope(process);
    let mut table = breakpoints().write().unwrap();
    table.retain(|_, functions| {
        functions.retain(|_, arities| {
            arities.retain(|_, bps| {
                bps.retain(|g| g.runtime != runtime || g.session != session);
                !bps.is_empty()
            });
            !arities.is_empty()
        });
        !functions.is_empty()
    });
    update_active(&table);
    drop(table);
    on_load_patterns()
        .lock()
        .unwrap()
        .remove(&(runtime, session));
}

/// The trace data of one session's breakpoint that fires on a call.
pub(crate) struct Pattern {
    pub(crate) session: u64,
    pub(crate) match_spec: Option<Arc<MatchSpec>>,
}

/// The sessions tracing a call: local (code breakpoint) or global (export) call trace.
// Port of erts/emulator/beam/beam_bp.c:1017-1060 (do_session_breakpoint), OTP-29.1.1.
pub(crate) fn matching(
    process: &Process,
    module: &str,
    function: &str,
    arity: u8,
    local: bool,
) -> Vec<Pattern> {
    let wanted = if local {
        BPF_LOCAL_TRACE
    } else {
        BPF_GLOBAL_TRACE
    };
    let table = breakpoints().read().unwrap();
    let ix = active_bp_ix();
    function_bps(
        &table,
        scope(process),
        code_scope(process),
        module,
        function,
        arity,
    )
    .filter(|g| g.data[ix].flags & wanted != 0)
    .map(|g| Pattern {
        session: g.session,
        match_spec: g.data[ix].local_ms.clone(),
    })
    .collect()
}

/// True while some runtime holds a function breakpoint; keeps untraced BIF calls on the fast path.
pub(crate) fn any_pattern() -> bool {
    active().load(Ordering::Relaxed)
}

/// Whether a breakpoint of any session or runtime is set on this function.
// Port of erts/emulator/beam/beam_bp.c:321-330 (erts_export_is_bif_traced), OTP-29.1.1.
pub(crate) fn selects(module: &str, function: &str, arity: u8) -> bool {
    let table = breakpoints().read().unwrap();
    let ix = active_bp_ix();
    table
        .get(module)
        .and_then(|functions| functions.get(function))
        .and_then(|arities| arities.get(&arity))
        .is_some_and(|bps| bps.iter().any(|g| g.data[ix].flags != 0))
}

/// Count a call entering the function's code.
// Port of erts/emulator/beam/beam_bp.c:1090-1092 (do_session_breakpoint, ERTS_BPF_COUNT_ACTIVE),
// OTP-29.1.1. Call counters live in the function's code breakpoint, which global (export)
// breakpoint hits do not reach.
pub(crate) fn increment(process: &Process, module: &str, function: &str, arity: u8, local: bool) {
    if !local || !any_pattern() {
        return;
    }
    let table = breakpoints().read().unwrap();
    let ix = active_bp_ix();
    for g in function_bps(
        &table,
        scope(process),
        code_scope(process),
        module,
        function,
        arity,
    ) {
        let bp = &g.data[ix];
        if bp.flags & BPF_COUNT_ACTIVE != 0
            && let Some(count) = &bp.count
        {
            count.fetch_add(1, Ordering::Relaxed);
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
    // Port of erts/emulator/beam/erl_bif_trace.c:1793-1850 (function_is_traced) and
    // 2132-2230 (trace_info_func_epilogue), OTP-29.1.1.
    let table = breakpoints().read().unwrap();
    let ix = active_bp_ix();
    let bp = function_bps(
        &table,
        scope(process),
        code_scope(process),
        module,
        function,
        arity,
    )
    .find(|g| g.session == session)
    .map(|g| g.data[ix].clone())
    .unwrap_or_default();
    drop(table);
    let false_atom = || OwnedTerm::Atom("false".into());
    let traced = || {
        if bp.flags & BPF_GLOBAL_TRACE != 0 {
            OwnedTerm::Atom("global".into())
        } else if bp.flags & BPF_LOCAL_TRACE != 0 {
            OwnedTerm::Atom("local".into())
        } else {
            false_atom()
        }
    };
    // An untraced function reports `{match_spec, false}`; a traced one without a match
    // specification reports `[]`.
    let match_spec = || {
        if bp.flags & (BPF_GLOBAL_TRACE | BPF_LOCAL_TRACE) != 0 {
            bp.local_ms
                .as_deref()
                .map_or(OwnedTerm::Nil, |spec| spec.source.clone())
        } else {
            false_atom()
        }
    };
    let call_count = || match &bp.count {
        Some(count) if bp.flags & BPF_COUNT != 0 => {
            OwnedTerm::Int(count.load(Ordering::Relaxed) as i64)
        }
        _ => false_atom(),
    };
    match item {
        "traced" => Some(traced()),
        "match_spec" => Some(match_spec()),
        "meta" | "meta_match_spec" | "call_memory" | "call_time" => Some(false_atom()),
        "call_count" => Some(call_count()),
        "all" => {
            let values = [
                ("traced", traced()),
                ("match_spec", match_spec()),
                ("meta", false_atom()),
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

/// Which breakpoints the function needs: a code breakpoint (`local`) and/or an export
/// breakpoint (`global`).
// Port of erts/emulator/beam/beam_bp.c:585-760 (erts_install_breakpoints,
// erts_uninstall_breakpoints) and erts/emulator/beam/erl_bif_trace.c:2690-2715, OTP-29.1.1.
pub(crate) fn breakpoint_kinds(
    process: &Process,
    module: &str,
    function: &str,
    arity: u8,
) -> (bool, bool) {
    let mut local = crate::trace::return_to_enabled(process)
        || debug_breakpoint_enabled(process, module, function, arity);
    let mut global = false;
    let table = breakpoints().read().unwrap();
    let ix = active_bp_ix();
    for g in function_bps(
        &table,
        scope(process),
        code_scope(process),
        module,
        function,
        arity,
    ) {
        let flags = g.data[ix].flags;
        local |= flags & !BPF_GLOBAL_TRACE != 0;
        global |= flags & BPF_GLOBAL_TRACE != 0;
    }
    (local, global)
}

fn active() -> &'static AtomicBool {
    static ACTIVE: AtomicBool = AtomicBool::new(false);
    &ACTIVE
}

fn scope(process: &Process) -> usize {
    process
        .runtime
        .as_ref()
        .map_or(0, |runtime| runtime.code_scope as usize)
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
    {
        let mut table = breakpoints().write().unwrap();
        table.retain(|_, functions| {
            functions.retain(|_, arities| {
                arities.retain(|_, bps| {
                    bps.retain(|g| g.runtime != runtime);
                    !bps.is_empty()
                });
                !arities.is_empty()
            });
            !functions.is_empty()
        });
        update_active(&table);
    }
    on_load_patterns()
        .lock()
        .unwrap()
        .retain(|(scope, _), _| *scope != runtime);
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

/// Enable debugger BIFs after the emulator's internal debugger flag is set.
///
/// Port of erts/emulator/beam/erl_bif_info.c:5470-5475, OTP-29.1.1.
pub(crate) fn enable_debugger_support() {
    DEBUGGER_SUPPORT.store(true, Ordering::Release);
}

pub(crate) fn line_breakpoints_instrumented() -> bool {
    debugger_supported() && LINE_BREAKPOINT_INSTRUMENTATION.load(Ordering::Acquire)
}

pub(crate) fn set_line_breakpoint_instrumentation(enabled: bool) {
    LINE_BREAKPOINT_INSTRUMENTATION.store(enabled, Ordering::Release);
}

type LineKey = (usize, usize, u32);
fn line_breakpoints() -> &'static Mutex<HashMap<LineKey, bool>> {
    static BREAKPOINTS: OnceLock<Mutex<HashMap<LineKey, bool>>> = OnceLock::new();
    BREAKPOINTS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Forget line sites when a module slot is reused for another code generation.
pub(crate) fn clear_module_line_breakpoints(runtime: u64, module_id: usize) {
    line_breakpoints()
        .lock()
        .unwrap()
        .retain(|(scope, id, _), _| *scope != runtime as usize || *id != module_id);
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
