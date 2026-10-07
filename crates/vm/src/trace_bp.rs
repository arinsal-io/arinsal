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

// Port of erts/emulator/beam/beam_bp.c:55-66 (ERTS_BPF_*), OTP-29.1.1. Debug breakpoints are
// not stored here, they live in `debug_breakpoints`.
const BPF_LOCAL_TRACE: u32 = 0x01;
const BPF_META_TRACE: u32 = 0x02;
const BPF_COUNT: u32 = 0x04;
const BPF_COUNT_ACTIVE: u32 = 0x08;
const BPF_TIME_TRACE: u32 = 0x20;
pub(crate) const BPF_TIME_TRACE_ACTIVE: u32 = 0x40;
const BPF_GLOBAL_TRACE: u32 = 0x80;
const BPF_MEM_TRACE: u32 = 0x100;
pub(crate) const BPF_MEM_TRACE_ACTIVE: u32 = 0x200;
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
    pub(crate) call_time: bool,
    pub(crate) call_memory: bool,
}

/// A function matched by a trace pattern (erts BpFunction).
pub(crate) struct BpFunction {
    pub(crate) module: String,
    pub(crate) function: String,
    pub(crate) arity: u8,
    /// Interpreted entry whose breakpoint data this MFA owns.
    pub(crate) entry: usize,
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
    /// The spec calls `{current_stacktrace}`.
    pub(crate) uses_current_stacktrace: bool,
    program: OnceLock<Result<arinsal_ets::match_spec::MatchProgram, ()>>,
}

impl MatchSpec {
    fn new(source: OwnedTerm) -> Self {
        fn uses(term: &OwnedTerm, name: &str) -> bool {
            match term {
                OwnedTerm::Tuple(fields) => {
                    matches!(fields.first(), Some(OwnedTerm::Atom(atom)) if atom == name)
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
            uses_current_stacktrace: uses(&source, "current_stacktrace"),
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

/// Port of erts/emulator/beam/beam_bp.h:63-66 (BpMetaTracer), OTP-29.1.1. Trace frames refer to
/// it by `id`, a small integer in the meta range of the session ids, so a frame outlives the
/// breakpoint like erts' copy of the tracer in the frame does.
pub(crate) struct MetaTracer {
    pub(crate) id: u64,
    tracer: Mutex<crate::trace::Tracer>,
}

impl MetaTracer {
    pub(crate) fn tracer(&self) -> crate::trace::Tracer {
        self.tracer.lock().unwrap().clone()
    }

    /// The tracer module asked to remove the tracer (`am_remove`), or it is gone.
    pub(crate) fn clear(&self) {
        *self.tracer.lock().unwrap() = crate::trace::Tracer::Default;
    }
}

/// First id of the meta tracer range: below the session range, above any counter.
const META_ID_BASE: u64 = 1 << 57;

/// Whether a trace frame's session id names a meta tracer.
pub(crate) fn is_meta_id(id: u64) -> bool {
    id & META_ID_BASE != 0 && id & (META_ID_BASE << 1) == 0
}

/// The registry only maps ids to live tracers: an entry goes away with its last holder (the
/// breakpoints that use the tracer and the processes with a return frame naming it).
fn meta_registry() -> &'static Mutex<HashMap<u64, std::sync::Weak<MetaTracer>>> {
    static REGISTRY: OnceLock<Mutex<HashMap<u64, std::sync::Weak<MetaTracer>>>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

impl Drop for MetaTracer {
    fn drop(&mut self) {
        meta_registry().lock().unwrap().remove(&self.id);
    }
}

fn new_meta_tracer(tracer: crate::trace::Tracer) -> Arc<MetaTracer> {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    let id = META_ID_BASE | NEXT.fetch_add(1, Ordering::Relaxed);
    let meta = Arc::new(MetaTracer {
        id,
        tracer: Mutex::new(tracer),
    });
    meta_registry()
        .lock()
        .unwrap()
        .insert(id, Arc::downgrade(&meta));
    meta
}

/// The meta tracer a trace frame names.
pub(crate) fn meta_tracer_by_id(id: u64) -> Option<Arc<MetaTracer>> {
    meta_registry()
        .lock()
        .unwrap()
        .get(&id)
        .and_then(std::sync::Weak::upgrade)
}

/// A return frame naming the meta tracer `id` was pushed on `process`: the frame keeps the
/// tracer alive like erts' copy of the tracer in the frame does.
// Port of erts/emulator/beam/beam_bp.c:1213-1244 (do_call_trace, ERTS_TRACER_COPY of the meta
// tracer into the frame), OTP-29.1.1.
pub(crate) fn hold_meta_frame(process: &mut Process, id: u64) {
    if let Some(meta) = meta_tracer_by_id(id) {
        process.cold_mut().meta_frames.push(meta);
    }
}

/// The return frame of the meta tracer `id` is gone.
// Port of erts/emulator/beam/beam_bp.c:1352-1415 (erts_call_trace_return, ERTS_TRACER_CLEAR),
// OTP-29.1.1.
pub(crate) fn release_meta_frame(process: &mut Process, id: u64) {
    let Some(cold) = process.cold.as_mut() else {
        return;
    };
    if let Some(index) = cold.meta_frames.iter().rposition(|meta| meta.id == id) {
        cold.meta_frames.swap_remove(index);
    }
}

/// Port of erts/emulator/beam/beam_bp.h:30-40 (bp_pid_timem_bucket_t, BpTimemTrace),
/// OTP-29.1.1: per-process call count and accumulated time (nanoseconds) or memory (words)
/// of one function. erts keeps one hash per scheduler to avoid contention; one lock suffices
/// here.
pub(crate) struct TimemTrace {
    /// One bucket map per shard of the process table, like erts' hash per scheduler: processes
    /// running in parallel do not contend on one lock.
    shards: [Mutex<TimemInner>; TIMEM_SHARDS],
}

const TIMEM_SHARDS: usize = 16;

struct TimemInner {
    buckets: HashMap<Pid, (i64, i64), FastHash>,
}

impl Default for TimemTrace {
    fn default() -> Self {
        Self {
            shards: std::array::from_fn(|_| {
                Mutex::new(TimemInner {
                    buckets: HashMap::default(),
                })
            }),
        }
    }
}

impl TimemTrace {
    fn shard(&self, pid: Pid) -> &Mutex<TimemInner> {
        &self.shards[crate::process::pid_table_index(pid) as usize % TIMEM_SHARDS]
    }

    // Port of erts/emulator/beam/beam_bp.c:1990-2008 (bp_hash_accum). Pausing only clears the
    // ACTIVE flag of the breakpoint data; the trace_pattern code barrier guarantees no call
    // that saw the flag set is still being counted.
    fn accum(&self, pid: Pid, count: i64, accumulator: i64) {
        let mut inner = self.shard(pid).lock().unwrap();
        let bucket = inner.buckets.entry(pid).or_default();
        bucket.0 += count;
        bucket.1 += accumulator;
    }

    // Port of erts/emulator/beam/beam_bp.c:2012-2016 (bp_hash_reset).
    fn reset(&self) {
        for shard in &self.shards {
            shard.lock().unwrap().buckets.clear();
        }
    }

    /// `(pid, count, accumulator)` of every process that called the function.
    pub(crate) fn snapshot(&self) -> Vec<(Pid, i64, i64)> {
        self.shards
            .iter()
            .flat_map(|shard| {
                shard
                    .lock()
                    .unwrap()
                    .buckets
                    .iter()
                    .map(|(pid, (count, accumulator))| (*pid, *count, *accumulator))
                    .collect::<Vec<_>>()
            })
            .collect()
    }
}

/// Port of erts/emulator/beam/beam_bp.h:75-83 (GenericBpData), OTP-29.1.1.
#[derive(Clone, Default)]
struct GenericBpData {
    flags: u32,
    local_ms: Option<Arc<MatchSpec>>,
    meta_ms: Option<Arc<MatchSpec>>,
    meta_tracer: Option<Arc<MetaTracer>>,
    count: Option<Arc<AtomicU64>>,
    time: Option<Arc<TimemTrace>>,
    memory: Option<Arc<TimemTrace>>,
}

/// Port of erts/emulator/beam/beam_bp.h:85-94 (GenericBp), OTP-29.1.1: one per trace session
/// and function. Runtime and code scope tag the VM instance the function belongs to.
#[derive(Clone)]
struct GenericBp {
    runtime: usize,
    code: u64,
    session: u64,
    data: [GenericBpData; 2],
}

/// A small, fast hasher for the short keys of the traced call path (FNV-1a); the table is not
/// exposed to untrusted keys that could collide on purpose.
#[derive(Default)]
pub(crate) struct FnvHasher(u64);

impl std::hash::Hasher for FnvHasher {
    fn write(&mut self, bytes: &[u8]) {
        let mut hash = if self.0 == 0 {
            0xcbf2_9ce4_8422_2325
        } else {
            self.0
        };
        for byte in bytes {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x0100_0000_01b3);
        }
        self.0 = hash;
    }

    fn finish(&self) -> u64 {
        self.0
    }
}

pub(crate) type FastHash = std::hash::BuildHasherDefault<FnvHasher>;

/// The breakpoints of one function, by module, name and arity; borrowed-key lookups keep the
/// traced call path allocation free.
type BpTable =
    HashMap<String, HashMap<String, HashMap<u8, Vec<GenericBp>, FastHash>, FastHash>, FastHash>;

/// The breakpoint table as readers see it: an immutable snapshot that writers replace
/// wholesale. Calls only clone the snapshot pointer, so a writer building a new table (which
/// can take milliseconds with a breakpoint on every function) never stalls running processes.
// Port of the idea of erts/emulator/beam/beam_bp.c (staging and active breakpoint indices,
// writers publish with a code barrier, readers never lock), OTP-29.1.1.
struct BpTables {
    current: RwLock<Arc<BpTable>>,
    writer: Mutex<()>,
}

impl BpTables {
    fn read(&self) -> std::sync::LockResult<Arc<BpTable>> {
        Ok(self.current.read().unwrap().clone())
    }

    /// A copy-on-write handle: the table is copied when first modified and published when the
    /// handle is dropped; handles are serialized.
    fn write(&self) -> std::sync::LockResult<BpWriteGuard<'_>> {
        let guard = self.writer.lock().unwrap();
        let base = self.current.read().unwrap().clone();
        Ok(BpWriteGuard {
            tables: self,
            _guard: guard,
            base,
            copy: None,
        })
    }
}

struct BpWriteGuard<'a> {
    tables: &'a BpTables,
    _guard: std::sync::MutexGuard<'a, ()>,
    base: Arc<BpTable>,
    copy: Option<BpTable>,
}

impl std::ops::Deref for BpWriteGuard<'_> {
    type Target = BpTable;

    fn deref(&self) -> &BpTable {
        self.copy.as_ref().unwrap_or(&self.base)
    }
}

impl std::ops::DerefMut for BpWriteGuard<'_> {
    fn deref_mut(&mut self) -> &mut BpTable {
        let base = &self.base;
        self.copy.get_or_insert_with(|| (**base).clone())
    }
}

impl Drop for BpWriteGuard<'_> {
    fn drop(&mut self) {
        if let Some(copy) = self.copy.take() {
            *self.tables.current.write().unwrap() = Arc::new(copy);
            // Readers that cached the old table under the epoch bumped before the publish.
            BP_EPOCH.fetch_add(1, Ordering::AcqRel);
        }
    }
}

fn breakpoints() -> &'static BpTables {
    static TABLE: OnceLock<BpTables> = OnceLock::new();
    TABLE.get_or_init(|| BpTables {
        current: RwLock::new(Arc::new(HashMap::default())),
        writer: Mutex::new(()),
    })
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
    BP_EPOCH.fetch_add(1, Ordering::AcqRel);
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

/// Port of erts/emulator/beam/beam_bp.c:2145-2295 (set_function_break), OTP-29.1.1, for the
/// staging copy of one session's breakpoint of one function.
fn set_function_break(
    bps: &mut Vec<GenericBp>,
    tag: (usize, u64, u64),
    match_spec: Option<&Arc<MatchSpec>>,
    break_flags: u32,
    count_op: BreakOp,
    tracer: Option<&crate::trace::Tracer>,
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
    // Only one kind of breakpoint is set per call, so the chain mirrors erts' else-if.
    if common & (BPF_LOCAL_TRACE | BPF_GLOBAL_TRACE) != 0 {
        // The old match specification is replaced below.
    } else if common & BPF_META_TRACE != 0 {
        // The old match specification and tracer are replaced below.
    } else if common & BPF_COUNT != 0 {
        if count_op == BreakOp::Pause {
            bp.flags &= !BPF_COUNT_ACTIVE;
        } else {
            bp.flags |= BPF_COUNT_ACTIVE;
            if let Some(count) = &bp.count {
                count.store(0, Ordering::Relaxed);
            }
        }
        return;
    } else if common & BPF_TIME_TRACE != 0 {
        if count_op == BreakOp::Pause {
            bp.flags &= !BPF_TIME_TRACE_ACTIVE;
        } else {
            bp.flags |= BPF_TIME_TRACE_ACTIVE;
            if let Some(time) = &bp.time {
                time.reset();
            }
        }
        return;
    } else if common & BPF_MEM_TRACE != 0 {
        if count_op == BreakOp::Pause {
            bp.flags &= !BPF_MEM_TRACE_ACTIVE;
        } else {
            bp.flags |= BPF_MEM_TRACE_ACTIVE;
            if let Some(memory) = &bp.memory {
                memory.reset();
            }
        }
        return;
    }
    if break_flags & (BPF_LOCAL_TRACE | BPF_GLOBAL_TRACE) != 0 {
        bp.local_ms = match_spec.cloned();
    } else if break_flags & BPF_META_TRACE != 0 {
        bp.meta_ms = match_spec.cloned();
        bp.meta_tracer = Some(new_meta_tracer(tracer.cloned().unwrap_or_default()));
    } else if break_flags & BPF_COUNT != 0 {
        bp.count = Some(Arc::new(AtomicU64::new(0)));
    } else if break_flags & BPF_TIME_TRACE != 0 {
        bp.time = Some(Arc::new(TimemTrace::default()));
    } else if break_flags & BPF_MEM_TRACE != 0 {
        bp.memory = Some(Arc::new(TimemTrace::default()));
    }
    bp.flags |= break_flags;
}

/// Port of erts/emulator/beam/beam_bp.c:2332-2362 (clear_function_break_session), OTP-29.1.1.
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
    // erts keeps the global trace's match specification in the export entry, apart from the
    // code breakpoint's; here both live in one field, which stays while the other kind is set.
    if common & (BPF_LOCAL_TRACE | BPF_GLOBAL_TRACE) != 0
        && bp.flags & (BPF_LOCAL_TRACE | BPF_GLOBAL_TRACE) == 0
    {
        bp.local_ms = None;
    }
    if common & BPF_META_TRACE != 0 {
        bp.meta_ms = None;
        bp.meta_tracer = None;
    }
    if common & BPF_COUNT != 0 {
        bp.count = None;
    }
    if common & BPF_TIME_TRACE != 0 {
        bp.time = None;
    }
    if common & BPF_MEM_TRACE != 0 {
        bp.memory = None;
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

/// Make the staged breakpoint data active.
// Port of erts/emulator/beam/beam_bp.c:562-569 (erts_commit_staged_bp), OTP-29.1.1.
pub(crate) fn commit_staged() {
    let table = breakpoints().write().unwrap();
    ACTIVE_BP_IX.store(staging_bp_ix(), Ordering::Release);
    update_active(&table);
}

/// Copy the active data of `functions` to the staging area and unlink disabled breakpoints.
// Port of erts/emulator/beam/erl_bif_trace.c (erts_finish_breakpointing case 3,
// erts_consolidate_all_bp_data), OTP-29.1.1.
pub(crate) fn consolidate_staged(functions: &[BpFunction]) {
    let mut table = breakpoints().write().unwrap();
    consolidate_functions(&mut table, functions);
}

fn consolidate_functions(table: &mut BpTable, functions: &[BpFunction]) {
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

thread_local! {
    /// While set, `breakpoint_kinds` also counts breakpoints that are only staged: the install
    /// stage of erts_finish_breakpointing enables code for them before they are committed.
    static INSTALL_VIEW: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Runs `patch` with the install view of `breakpoint_kinds`.
pub(crate) fn with_install_view<R>(patch: impl FnOnce() -> R) -> R {
    INSTALL_VIEW.with(|view| view.set(true));
    let result = patch();
    INSTALL_VIEW.with(|view| view.set(false));
    result
}

/// Serializes staged breakpoint changes like erts' code modification permission: a waiter
/// keeps passing code barriers so the holder's barriers can complete.
// Port of erts/emulator/beam/code_ix.c:378 (erts_try_seize_code_mod_permission), OTP-29.1.1.
pub(crate) fn seize_staging(
    ctx: &mut arinsal_sched::RunCtx<'_, crate::process::Message>,
) -> std::sync::MutexGuard<'static, ()> {
    static STAGING: Mutex<()> = Mutex::new(());
    loop {
        match STAGING.try_lock() {
            Ok(guard) => return guard,
            Err(std::sync::TryLockError::Poisoned(error)) => return error.into_inner(),
            Err(std::sync::TryLockError::WouldBlock) => {
                ctx.block_thread_progress(std::time::Duration::ZERO)
            }
        }
    }
}

/// Set or clear the breakpoints of one session in the matched functions.
// Port of erts/emulator/beam/erl_bif_trace.c:2621-2725 (erts_set_trace_pattern), OTP-29.1.1.
#[allow(clippy::too_many_arguments)] // The arguments of erts_set_trace_pattern.
pub(crate) fn set_trace_pattern(
    process: &Process,
    session: u64,
    functions: &[BpFunction],
    match_spec: Option<OwnedTerm>,
    meta_match_spec: Option<OwnedTerm>,
    on: BreakOp,
    flags: TracePatternFlags,
    meta_tracer: &crate::trace::Tracer,
) {
    stage_trace_pattern(
        process,
        session,
        functions,
        match_spec,
        meta_match_spec,
        on,
        flags,
        meta_tracer,
    );
    commit_staged();
    consolidate_staged(functions);
}

/// Stage the breakpoints of one session in the matched functions; nothing is active until
/// `commit_staged`.
#[allow(clippy::too_many_arguments)] // The arguments of erts_set_trace_pattern.
pub(crate) fn stage_trace_pattern(
    process: &Process,
    session: u64,
    functions: &[BpFunction],
    match_spec: Option<OwnedTerm>,
    meta_match_spec: Option<OwnedTerm>,
    on: BreakOp,
    flags: TracePatternFlags,
    meta_tracer: &crate::trace::Tracer,
) {
    let tag = (scope(process), code_scope(process), session);
    let match_spec = match_spec.map(|source| Arc::new(MatchSpec::new(source)));
    let meta_match_spec = meta_match_spec.map(|source| Arc::new(MatchSpec::new(source)));
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
                        None,
                    );
                }
                if flags.meta {
                    set_function_break(
                        bps,
                        tag,
                        meta_match_spec.as_ref(),
                        BPF_META_TRACE,
                        BreakOp::Nop,
                        Some(meta_tracer),
                    );
                }
                if flags.call_count {
                    set_function_break(bps, tag, None, BPF_COUNT | BPF_COUNT_ACTIVE, on, None);
                }
                if flags.call_time {
                    set_function_break(
                        bps,
                        tag,
                        None,
                        BPF_TIME_TRACE | BPF_TIME_TRACE_ACTIVE,
                        on,
                        None,
                    );
                }
                if flags.call_memory {
                    set_function_break(
                        bps,
                        tag,
                        None,
                        BPF_MEM_TRACE | BPF_MEM_TRACE_ACTIVE,
                        on,
                        None,
                    );
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
            if flags.call_time {
                clear_function_break(bps, tag, BPF_TIME_TRACE | BPF_TIME_TRACE_ACTIVE);
            }
            if flags.call_memory {
                clear_function_break(bps, tag, BPF_MEM_TRACE | BPF_MEM_TRACE_ACTIVE);
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
                None,
            );
        } else if on == BreakOp::Nop && flags.breakpoint {
            // Turning off breakpoint tracing leaves global tracing alone.
        } else {
            // Turn off global tracing, explicitly or before turning on breakpoint tracing.
            clear_function_break(bps, tag, BPF_GLOBAL_TRACE);
        }
    }
}

/// Remove all breakpoints owned by a destroyed trace session.
// Port of erts/emulator/beam/erl_bif_trace.c:2727-2760 (prepare_clear_all_trace_pattern) and
// 1352-1375, OTP-29.1.1.
pub(crate) fn clear_session(process: &Process, session: u64) {
    clear_session_scope(scope(process), session);
}

pub(crate) fn clear_session_scope(runtime: usize, session: u64) {
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

/// The active breakpoint data of one session in a function that is called.
pub(crate) struct Hit {
    pub(crate) session: u64,
    pub(crate) flags: u32,
    pub(crate) count: Option<Arc<AtomicU64>>,
    pub(crate) local_ms: Option<Arc<MatchSpec>>,
    pub(crate) meta_ms: Option<Arc<MatchSpec>>,
    pub(crate) meta_tracer: Option<Arc<MetaTracer>>,
    pub(crate) time: Option<Arc<TimemTrace>>,
    pub(crate) memory: Option<Arc<TimemTrace>>,
}

/// The sessions with a breakpoint in a function.
// Port of erts/emulator/beam/beam_bp.c:994-1015 (erts_generic_breakpoint, the GenericBp loop),
// OTP-29.1.1.
pub(crate) fn hits(process: &Process, module: &str, function: &str, arity: u8) -> Vec<Hit> {
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
    .filter(|g| g.data[ix].flags != 0)
    .map(|g| {
        let data = &g.data[ix];
        Hit {
            session: g.session,
            flags: data.flags,
            count: if data.flags & BPF_COUNT_ACTIVE != 0 {
                data.count.clone()
            } else {
                None
            },
            local_ms: data.local_ms.clone(),
            meta_ms: data.meta_ms.clone(),
            meta_tracer: data.meta_tracer.clone(),
            time: data.time.clone(),
            memory: data.memory.clone(),
        }
    })
    .collect()
}

/// `Hit::flags` bits: global call trace of the export entry.
pub(crate) const HIT_GLOBAL: u32 = BPF_GLOBAL_TRACE;
/// `Hit::flags` bits: local call trace of the code breakpoint.
pub(crate) const HIT_LOCAL: u32 = BPF_LOCAL_TRACE;
/// `Hit::flags` bits: meta trace.
pub(crate) const HIT_META: u32 = BPF_META_TRACE;
/// `Hit::flags` bits: an active call counter.
pub(crate) const HIT_COUNT_ACTIVE: u32 = BPF_COUNT_ACTIVE;

/// The breakpoints a native trampoline hit finds in its function, for one runtime and code
/// scope; valid while no breakpoint and no native code changed.
struct SiteBreakpoints {
    site: usize,
    runtime: usize,
    code: u64,
    epoch: u64,
    generation: u64,
    bps: Vec<SiteBp>,
}

struct SiteBp {
    session: u64,
    /// Active flags without the export entry's global trace, which a code entry never runs.
    flags: u32,
    count: Option<Arc<AtomicU64>>,
}

const SITE_CACHE_SIZE: usize = 64;

thread_local! {
    /// Direct-mapped, per scheduler thread: a hit costs two atomic loads and a compare.
    static SITE_CACHE: std::cell::RefCell<[Option<Arc<SiteBreakpoints>>; SITE_CACHE_SIZE]> =
        const { std::cell::RefCell::new([const { None }; SITE_CACHE_SIZE]) };
}

fn site_breakpoints(process: &Process, site: usize) -> Option<Arc<SiteBreakpoints>> {
    let runtime = scope(process);
    let code = code_scope(process);
    let slot = (site >> 2) % SITE_CACHE_SIZE;
    let epoch = BP_EPOCH.load(Ordering::Acquire);
    let generation = crate::native_bridge::native_registry_generation();
    if let Some(found) = SITE_CACHE.with(|cache| {
        cache.borrow()[slot]
            .as_ref()
            .filter(|entry| {
                entry.site == site
                    && entry.runtime == runtime
                    && entry.code == code
                    && entry.epoch == epoch
                    && entry.generation == generation
            })
            .cloned()
    }) {
        return Some(found);
    }
    let ix = active_bp_ix();
    let table = breakpoints().current.read().unwrap();
    let bps = crate::native_bridge::with_native_function_at(site, |function| {
        function_bps(
            &table,
            runtime,
            code,
            &function.module,
            &function.function,
            function.arity,
        )
        .map(|g| SiteBp {
            session: g.session,
            flags: g.data[ix].flags & !BPF_GLOBAL_TRACE,
            count: g.data[ix].count.clone(),
        })
        .collect::<Vec<_>>()
    })?;
    drop(table);
    let entry = Arc::new(SiteBreakpoints {
        site,
        runtime,
        code,
        epoch,
        generation,
        bps,
    });
    SITE_CACHE.with(|cache| cache.borrow_mut()[slot] = Some(entry.clone()));
    Some(entry)
}

/// Native-code `erts_generic_breakpoint` of the trampoline at `site`: whether every breakpoint
/// on the function only counts calls for this process. When so, the counters are incremented
/// and the call proceeds without a trace event; otherwise nothing is touched.
// Port of erts/emulator/beam/beam_bp.c:994-1060 (erts_generic_breakpoint, do_session_breakpoint),
// OTP-29.1.1.
pub(crate) fn native_breakpoint_noop(process: &Process, pid: Pid, site: usize) -> bool {
    if crate::trace::is_sensitive(process, pid) {
        return true;
    }
    let Some(entry) = site_breakpoints(process, site) else {
        return false;
    };
    let acc = BPF_TIME_TRACE_ACTIVE | BPF_MEM_TRACE_ACTIVE;
    // The debug and return_to checks need the function name, but only when one is in use.
    if DEBUG_BREAKPOINTS_USED.load(Ordering::Relaxed)
        && crate::native_bridge::with_native_function_at(site, |function| {
            debug_breakpoint_enabled(
                process,
                &function.module,
                &function.function,
                function.arity,
            )
        })
        .unwrap_or(true)
        || crate::trace::return_to_enabled(process)
    {
        return false;
    }
    if !entry.bps.iter().all(|bp| {
        bp.flags & BPF_META_TRACE == 0
            && (bp.flags & (BPF_LOCAL_TRACE | acc) == 0
                || crate::trace::session_flags(process, bp.session, pid) & crate::trace::CALL == 0)
    }) {
        return false;
    }
    for bp in &entry.bps {
        if bp.flags & BPF_COUNT_ACTIVE != 0
            && let Some(count) = &bp.count
        {
            count.fetch_add(1, Ordering::Relaxed);
        }
    }
    true
}

/// The functions among `functions` that have a breakpoint of any session: clearing, pausing or
/// restarting a breakpoint only concerns them.
pub(crate) fn with_breakpoints(process: &Process, functions: Vec<BpFunction>) -> Vec<BpFunction> {
    let table = breakpoints().read().unwrap();
    let runtime = scope(process);
    let code = code_scope(process);
    functions
        .into_iter()
        .filter(|function| {
            function_bps(
                &table,
                runtime,
                code,
                &function.module,
                &function.function,
                function.arity,
            )
            .next()
            .is_some()
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

/// What `trace_info` reports about one function of one session.
pub(crate) struct FunctionInfo {
    /// Breakpoint flags of the session restricted to the ones the key asks for.
    pub(crate) got: u32,
    pub(crate) local_ms: Option<OwnedTerm>,
    pub(crate) meta_ms: Option<OwnedTerm>,
    pub(crate) meta: crate::trace::Tracer,
    pub(crate) count: u64,
    /// `(pid, count, nanoseconds)` per process, when call_time is set.
    pub(crate) time: Option<Vec<(Pid, i64, i64)>>,
    /// `(pid, count, words)` per process, when call_memory is set.
    pub(crate) memory: Option<Vec<(Pid, i64, i64)>>,
    /// An active call_time or call_memory counter was asked for: erts traps the caller until
    /// the schedulers have stopped touching the counters.
    pub(crate) counters_active: bool,
}

/// `want` bits of `function_info`.
pub(crate) const WANT_TRACE: u32 = BPF_LOCAL_TRACE | BPF_GLOBAL_TRACE;
pub(crate) const WANT_META: u32 = BPF_META_TRACE;
pub(crate) const WANT_COUNT: u32 = BPF_COUNT;
pub(crate) const WANT_TIME: u32 = BPF_TIME_TRACE;
pub(crate) const WANT_MEMORY: u32 = BPF_MEM_TRACE;
pub(crate) const GOT_GLOBAL: u32 = BPF_GLOBAL_TRACE;
pub(crate) const GOT_LOCAL: u32 = BPF_LOCAL_TRACE;
pub(crate) const GOT_META: u32 = BPF_META_TRACE;
pub(crate) const GOT_COUNT: u32 = BPF_COUNT;
pub(crate) const GOT_TIME: u32 = BPF_TIME_TRACE;
pub(crate) const GOT_MEMORY: u32 = BPF_MEM_TRACE;

// Port of erts/emulator/beam/erl_bif_trace.c:1793-1850 (function_is_traced) and
// erts/emulator/beam/beam_bp.c:1418-1486 (erts_is_trace_break, erts_is_mtrace_break,
// erts_is_count_break, erts_is_time_break, erts_is_memory_break), OTP-29.1.1.
pub(crate) fn function_info(
    process: &Process,
    session: u64,
    module: &str,
    function: &str,
    arity: u8,
    want: u32,
) -> FunctionInfo {
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
    let mut got = bp.flags & want;
    if got & BPF_GLOBAL_TRACE != 0 {
        got = BPF_GLOBAL_TRACE;
    }
    let source = |spec: &Option<Arc<MatchSpec>>| spec.as_deref().map(|spec| spec.source.clone());
    FunctionInfo {
        got,
        counters_active: bp.flags
            & ((BPF_TIME_TRACE_ACTIVE | BPF_MEM_TRACE_ACTIVE)
                & ((want & BPF_TIME_TRACE) << 1 | (want & BPF_MEM_TRACE) << 1))
            != 0,
        local_ms: source(&bp.local_ms),
        meta_ms: source(&bp.meta_ms),
        meta: bp
            .meta_tracer
            .as_ref()
            .map(|meta| meta.tracer())
            .unwrap_or_default(),
        count: bp
            .count
            .as_ref()
            .map_or(0, |count| count.load(Ordering::Relaxed)),
        time: (got & BPF_TIME_TRACE != 0)
            .then(|| bp.time.as_ref().map(|bdt| bdt.snapshot()))
            .flatten(),
        memory: (got & BPF_MEM_TRACE != 0)
            .then(|| bp.memory.as_ref().map(|bdt| bdt.snapshot()))
            .flatten(),
    }
}

/// Trace sessions with an active pattern on the specified function.
// Port of erts/emulator/beam/erl_bif_trace.c:2427-2468 (trace_info_sessions), OTP-29.1.1.
pub(crate) fn sessions_for_function(
    process: &Process,
    module: &str,
    function: &str,
    arity: u8,
) -> Vec<u64> {
    let table = breakpoints().read().unwrap();
    let ix = active_bp_ix();
    let mut sessions = function_bps(
        &table,
        scope(process),
        code_scope(process),
        module,
        function,
        arity,
    )
    .filter_map(|bp| (bp.data[ix].flags != 0).then_some(bp.session))
    .collect::<Vec<_>>();
    sessions.sort_unstable();
    sessions.dedup();
    sessions
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
        let mut flags = g.data[ix].flags;
        if INSTALL_VIEW.with(std::cell::Cell::get) {
            flags |= g.data[staging_bp_ix()].flags;
        }
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
// Port of erts/emulator/beam/erl_bif_trace.c:2523-2603 (change_on_load_trace_pattern) and
// erts/emulator/beam/erl_trace.h (ErtsTraceSession on_load_* fields), OTP-29.1.1.
#[derive(Clone, Default)]
pub(crate) struct OnLoadPattern {
    pub is_on: bool,
    pub flags: TracePatternFlags,
    pub match_spec: Option<OwnedTerm>,
    pub meta_match_spec: Option<OwnedTerm>,
    pub meta_tracer: crate::trace::Tracer,
}

fn on_load_patterns() -> &'static Mutex<HashMap<(usize, u64), OnLoadPattern>> {
    static ON_LOAD: OnceLock<Mutex<HashMap<(usize, u64), OnLoadPattern>>> = OnceLock::new();
    ON_LOAD.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Apply `trace_pattern(on_load, ...)` to a session.
pub(crate) fn change_on_load(
    process: &Process,
    session: u64,
    on: BreakOp,
    mut flags: TracePatternFlags,
    match_spec: Option<OwnedTerm>,
    meta_tracer: &crate::trace::Tracer,
) {
    let mut map = on_load_patterns().lock().unwrap();
    let s = map.entry((scope(process), session)).or_default();
    if flags.local || !flags.breakpoint {
        s.match_spec = match_spec.clone();
    }
    if flags.meta {
        s.meta_match_spec = match_spec;
        s.meta_tracer = meta_tracer.clone();
    } else if !flags.breakpoint {
        s.meta_match_spec = None;
        s.meta_tracer = crate::trace::Tracer::Default;
    }
    let on_set = on == BreakOp::Set;
    let on_any = on != BreakOp::Nop;
    if s.flags.breakpoint && flags.breakpoint {
        // Breakpoint trace -> breakpoint trace.
        if on_any {
            s.flags.local |= flags.local;
            s.flags.meta |= flags.meta;
            s.flags.call_count |= on_set && flags.call_count;
            s.flags.call_time |= on_set && flags.call_time;
            s.flags.call_memory |= on_set && flags.call_memory;
        } else {
            s.flags.local &= !flags.local;
            s.flags.meta &= !flags.meta;
            s.flags.call_count &= !flags.call_count;
            s.flags.call_time &= !flags.call_time;
            s.flags.call_memory &= !flags.call_memory;
            s.flags.breakpoint = s.flags.local
                | s.flags.meta
                | s.flags.call_count
                | s.flags.call_time
                | s.flags.call_memory;
            if !s.flags.breakpoint {
                s.is_on = on_any;
            }
        }
    } else if !s.flags.breakpoint && !flags.breakpoint {
        // Global call trace -> global call trace.
        s.is_on = on_any;
    } else if s.flags.breakpoint && !flags.breakpoint {
        // Breakpoint trace -> global call trace.
        if on_any {
            s.flags = flags;
            s.is_on = on_any;
        }
    } else if on_any {
        // Global call trace -> breakpoint trace.
        if !on_set {
            flags.call_count = false;
            flags.call_time = false;
            flags.call_memory = false;
        }
        flags.breakpoint =
            flags.local | flags.meta | flags.call_count | flags.call_time | flags.call_memory;
        s.flags = flags;
        s.is_on = flags.breakpoint;
    }
}

/// Whether any session of this runtime has an active on_load pattern.
pub(crate) fn any_on_load_pattern(process: &Process) -> bool {
    let runtime = scope(process);
    on_load_patterns()
        .lock()
        .unwrap()
        .iter()
        .any(|((owner, _), pattern)| *owner == runtime && pattern.is_on)
}

pub(crate) fn on_load_pattern(process: &Process, session: u64) -> Option<OnLoadPattern> {
    on_load_patterns()
        .lock()
        .unwrap()
        .get(&(scope(process), session))
        .filter(|pattern| pattern.is_on)
        .cloned()
}

/// The on_load patterns of all sessions of this runtime.
pub(crate) fn on_load_patterns_of(process: &Process) -> Vec<(u64, OnLoadPattern)> {
    let runtime = scope(process);
    on_load_patterns()
        .lock()
        .unwrap()
        .iter()
        .filter(|((owner, _), pattern)| *owner == runtime && pattern.is_on)
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

/// Set once a debug breakpoint was enabled; until then no table scan can find one.
static DEBUG_BREAKPOINTS_USED: AtomicBool = AtomicBool::new(false);

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
    if enabled {
        DEBUG_BREAKPOINTS_USED.store(true, Ordering::Relaxed);
    }
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
    if !DEBUG_BREAKPOINTS_USED.load(Ordering::Relaxed) {
        return false;
    }
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

/// Per-process call time or call memory state of one session.
// Port of erts/emulator/beam/beam_bp.h:75-83 (process_breakpoint_trace_t), OTP-29.1.1. `ci` names
// the function that currently accumulates, by id (`func_id`).
#[derive(Clone)]
pub(crate) struct ProcBpTrace {
    pub(crate) session: u64,
    pub(crate) ci: Option<u32>,
    pub(crate) accumulator: i64,
    /// Adjustment for GC and messages on the heap (call_memory only).
    pub(crate) allocated: i64,
    /// The counters of function `.0` as of breakpoint epoch `.2`: a tight loop of calls would
    /// otherwise look the same function up by name on every call and return.
    cache: Option<(u32, u64, Arc<TimemTrace>)>,
}

/// Incremented whenever breakpoints change; invalidates `ProcBpTrace::cache`.
static BP_EPOCH: AtomicU64 = AtomicU64::new(0);

type FuncName = (String, String, u8);

/// Function ids: nested by name so a lookup does not allocate.
#[derive(Default)]
struct FuncIds {
    names: Vec<FuncName>,
    ids: HashMap<String, FunctionIds, FastHash>,
}

type FunctionIds = HashMap<String, HashMap<u8, u32, FastHash>, FastHash>;

fn func_ids() -> &'static RwLock<FuncIds> {
    static IDS: OnceLock<RwLock<FuncIds>> = OnceLock::new();
    IDS.get_or_init(|| RwLock::new(FuncIds::default()))
}

/// A small id of a function, stored in trace frames in place of erts' `ErtsCodeInfo` pointer.
pub(crate) fn func_id(module: &str, function: &str, arity: u8) -> u32 {
    if let Some(id) = func_ids()
        .read()
        .unwrap()
        .ids
        .get(module)
        .and_then(|functions| functions.get(function))
        .and_then(|arities| arities.get(&arity))
    {
        return *id;
    }
    let mut ids = func_ids().write().unwrap();
    let id = ids.names.len() as u32;
    ids.names
        .push((module.to_owned(), function.to_owned(), arity));
    ids.ids
        .entry(module.to_owned())
        .or_default()
        .entry(function.to_owned())
        .or_default()
        .insert(arity, id);
    id
}

fn func_name(id: u32) -> Option<FuncName> {
    func_ids().read().unwrap().names.get(id as usize).cloned()
}

// Port of erts/emulator/beam/beam_bp.c:2410-2442 (get_time_break, get_memory_break,
// check_break), OTP-29.1.1.
fn timem_break(process: &Process, session: u64, id: u32, memory: bool) -> Option<Arc<TimemTrace>> {
    let (module, function, arity) = func_name(id)?;
    let table = breakpoints().read().unwrap();
    let ix = active_bp_ix();
    let bp = function_bps(
        &table,
        scope(process),
        code_scope(process),
        &module,
        &function,
        arity,
    )
    .find(|g| g.session == session)
    .map(|g| &g.data[ix])?;
    if memory {
        (bp.flags & BPF_MEM_TRACE != 0).then(|| bp.memory.clone())?
    } else {
        (bp.flags & BPF_TIME_TRACE != 0).then(|| bp.time.clone())?
    }
}

/// The call time or memory counters of function `id`, from the session's per-process cache.
fn cached_timem_break(
    process: &mut Process,
    session: u64,
    id: u32,
    memory: bool,
) -> Option<Arc<TimemTrace>> {
    let epoch = BP_EPOCH.load(Ordering::Acquire);
    if let Some((cached_id, cached_epoch, bdt)) = pbt_list(process, memory)
        .iter()
        .find(|pbt| pbt.session == session)
        .and_then(|pbt| pbt.cache.as_ref())
        && *cached_id == id
        && *cached_epoch == epoch
    {
        return Some(bdt.clone());
    }
    let found = timem_break(process, session, id, memory)?;
    if let Some(pbt) = pbt_list(process, memory)
        .iter_mut()
        .find(|pbt| pbt.session == session)
    {
        pbt.cache = Some((id, epoch, found.clone()));
    }
    Some(found)
}

fn pbt_list(process: &mut Process, memory: bool) -> &mut Vec<ProcBpTrace> {
    let cold = process.cold_mut();
    if memory {
        &mut cold.call_memory
    } else {
        &mut cold.call_time
    }
}

/// The adjustment the session's `call_memory` state holds, `None` before its first call.
pub(crate) fn call_memory_adjustment(process: &mut Process, session: u64) -> Option<i64> {
    pbt_list(process, true)
        .iter()
        .find(|pbt| pbt.session == session)
        .map(|pbt| pbt.allocated)
}

/// Account a call of `ci` and the time or memory used since the previous call; returns the
/// function the process was accounted to before.
// Port of erts/emulator/beam/beam_bp.c:1277-1334 (erts_trace_call_acc), OTP-29.1.1.
pub(crate) fn trace_call_acc(
    process: &mut Process,
    pid: Pid,
    session: u64,
    memory: bool,
    ci: u32,
    accum: i64,
    bdt: &TimemTrace,
) -> Option<u32> {
    let known = pbt_list(process, memory)
        .iter()
        .find(|pbt| pbt.session == session)
        .map(|pbt| (pbt.ci, pbt.accumulator));
    match known {
        None => {
            // First call of the process to an instrumented function.
            pbt_list(process, memory).push(ProcBpTrace {
                session,
                ci: None,
                accumulator: 0,
                allocated: 0,
                cache: None,
            });
        }
        Some((Some(previous), accumulator)) => {
            // Add time/allocation to the previous code; none if its breakpoint was removed.
            if let Some(previous_bdt) = cached_timem_break(process, session, previous, memory) {
                previous_bdt.accum(pid, 0, accum - accumulator);
            }
        }
        // The caller is not call_time traced.
        Some((None, _)) => {}
    }
    bdt.accum(pid, 1, 0);
    let pbt = pbt_list(process, memory)
        .iter_mut()
        .find(|pbt| pbt.session == session)
        .expect("pbt exists");
    let prev = pbt.ci.replace(ci);
    pbt.accumulator = accum;
    prev
}

/// The frame of a traced call returns: account the time or memory to the function entered
/// from.
// Port of erts/emulator/beam/beam_bp.c:1352-1415 (erts_call_trace_return), OTP-29.1.1.
pub(crate) fn call_trace_return(
    process: &mut Process,
    pid: Pid,
    session: u64,
    bp_flags: u32,
    prev: Option<u32>,
) {
    if bp_flags & BPF_TIME_TRACE_ACTIVE != 0 {
        let found = pbt_list(process, false)
            .iter()
            .find(|pbt| pbt.session == session)
            .map(|pbt| (pbt.ci, pbt.accumulator));
        if let Some((ci, accumulator)) = found {
            let time = arinsal_bifs::monotonic_time_nanos() as i64;
            // Might have been removed by trace_pattern(false).
            if let Some(bdt) = ci.and_then(|ci| cached_timem_break(process, session, ci, false)) {
                bdt.accum(pid, 0, time - accumulator);
            }
            let pbt = pbt_list(process, false)
                .iter_mut()
                .find(|pbt| pbt.session == session)
                .expect("pbt exists");
            pbt.ci = prev;
            pbt.accumulator = time;
        }
    }
    if bp_flags & BPF_MEM_TRACE_ACTIVE != 0 {
        let found = pbt_list(process, true)
            .iter()
            .find(|pbt| pbt.session == session)
            .map(|pbt| (pbt.ci, pbt.accumulator, pbt.allocated));
        if let Some((ci, accumulator, allocated)) = found {
            let words = process.allocated_words(allocated);
            if let Some(bdt) = ci.and_then(|ci| cached_timem_break(process, session, ci, true)) {
                bdt.accum(pid, 0, words - accumulator);
            }
            let pbt = pbt_list(process, true)
                .iter_mut()
                .find(|pbt| pbt.session == session)
                .expect("pbt exists");
            pbt.ci = prev;
            pbt.accumulator = words;
        }
    }
}

/// A process is scheduled in or out: restart or close the running time slice of its call_time
/// accounting.
// Port of erts/emulator/beam/beam_bp.c:2017-2073 (erts_schedule_time_break), OTP-29.1.1.
pub(crate) fn schedule_time_break(process: &mut Process, pid: Pid, out: bool) {
    let now = arinsal_bifs::monotonic_time_nanos() as i64;
    let entries = pbt_list(process, false).clone();
    if out {
        // When a process is scheduled out, add its delta to the previous breakpoint.
        for pbt in &entries {
            if let Some(ci) = pbt.ci
                && let Some(bdt) = timem_break(process, pbt.session, ci, false)
            {
                bdt.accum(pid, 0, now - pbt.accumulator);
            }
        }
    } else {
        // When a process is scheduled in, remove the previous timestamp.
        for pbt in pbt_list(process, false).iter_mut() {
            pbt.accumulator = now;
        }
    }
}

/// Adjust the memory accounting of a process (heap words freed by GC or received).
// Port of erts/emulator/beam/beam_bp.h:240-254 (erts_adjust_memory_break), OTP-29.1.1.
pub(crate) fn adjust_memory_break(process: &mut Process, adjustment: i64) {
    if let Some(cold) = process.cold.as_mut() {
        for pbt in &mut cold.call_memory {
            pbt.allocated += adjustment;
        }
    }
}
