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
    /// Interpreted entry whose breakpoint data this MFA owns; zero for an export-only BIF.
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

/// Port of erts/emulator/beam/beam_bp.h (bp_pid_timem_bucket_t, bp_pid_timem_hash_t,
/// BpTimemTrace), OTP-29.1.1: per-process call count and accumulated time or memory for one
/// function, with one bucket hash per normal scheduler and a shared dirty-scheduler hash.
pub(crate) struct TimemTrace {
    shards: Vec<Mutex<TimemInner>>,
}

#[derive(Clone, Copy)]
struct TimemBucket {
    pid: Pid,
    count: i64,
    accumulator: i64,
}

struct TimemHash {
    buckets: Vec<Option<TimemBucket>>,
    used: usize,
}

impl TimemHash {
    fn new(capacity: usize) -> Self {
        Self {
            buckets: vec![None; capacity],
            used: 0,
        }
    }

    fn index(pid: Pid, capacity: usize) -> usize {
        // An Erlang pid term's low four bits are its tag, so `Pid::data()` is `Eterm >> 4`.
        pid.data() as usize % capacity
    }

    fn find(&self, pid: Pid) -> Option<usize> {
        let mut index = Self::index(pid, self.buckets.len());
        loop {
            match self.buckets[index] {
                Some(bucket) if bucket.pid == pid => return Some(index),
                None => return None,
                _ => index = (index + 1) % self.buckets.len(),
            }
        }
    }

    fn put(&mut self, bucket: TimemBucket) {
        if self.used as f32 / self.buckets.len() as f32 > 0.7_f32 {
            self.rehash(self.buckets.len() * 2);
        }
        let mut index = Self::index(bucket.pid, self.buckets.len());
        while self.buckets[index].is_some() {
            index = (index + 1) % self.buckets.len();
        }
        self.buckets[index] = Some(bucket);
        self.used += 1;
    }

    fn rehash(&mut self, capacity: usize) {
        let mut buckets = Self::new(capacity);
        for bucket in self.buckets.iter().flatten().copied() {
            let mut index = Self::index(bucket.pid, buckets.buckets.len());
            while buckets.buckets[index].is_some() {
                index = (index + 1) % buckets.buckets.len();
            }
            buckets.buckets[index] = Some(bucket);
            buckets.used += 1;
        }
        *self = buckets;
    }

    fn accum(&mut self, pid: Pid, count: i64, accumulator: i64) {
        if self.buckets.is_empty() {
            *self = Self::new(32);
        }
        if let Some(index) = self.find(pid) {
            let bucket = self.buckets[index].as_mut().unwrap();
            bucket.count += count;
            bucket.accumulator += accumulator;
        } else {
            self.put(TimemBucket {
                pid,
                count,
                accumulator,
            });
        }
    }

    fn merge_into(&self, merged: &mut HashMap<Pid, (i64, i64), FastHash>) {
        for bucket in self.buckets.iter().flatten() {
            let total = merged.entry(bucket.pid).or_default();
            total.0 += bucket.count;
            total.1 += bucket.accumulator;
        }
    }
}

struct TimemInner {
    buckets: TimemHash,
}

impl Default for TimemInner {
    fn default() -> Self {
        Self {
            buckets: TimemHash::new(0),
        }
    }
}

impl TimemInner {
    fn accum(&mut self, pid: Pid, count: i64, accumulator: i64) {
        self.buckets.accum(pid, count, accumulator);
    }

    fn merge_into(&self, merged: &mut HashMap<Pid, (i64, i64), FastHash>) {
        self.buckets.merge_into(merged);
    }
}

impl Default for TimemTrace {
    fn default() -> Self {
        let normal_schedulers = arinsal_sched::current_normal_scheduler_count()
            .unwrap_or(1)
            .max(1);
        Self {
            shards: (0..=normal_schedulers)
                .map(|_| Mutex::new(TimemInner::default()))
                .collect(),
        }
    }
}

impl TimemTrace {
    /// The bucket map of the calling scheduler; dirty schedulers share the last map.
    // Port of erts/emulator/beam/beam_bp.c (acquire_bp_sched_ix, release_bp_sched_ix), OTP-29.1.1.
    fn shard(&self) -> &Mutex<TimemInner> {
        let ix = arinsal_sched::current_normal_scheduler().unwrap_or(self.shards.len() - 1);
        &self.shards[ix]
    }

    // Port of erts/emulator/beam/beam_bp.c (bp_hash_get, bp_hash_put, bp_hash_accum), OTP-29.1.1.
    fn accum(&self, pid: Pid, count: i64, accumulator: i64) {
        self.shard().lock().unwrap().accum(pid, count, accumulator);
    }

    /// `(pid, count, accumulator)` of every process that called the function, the per-scheduler
    /// maps merged.
    // Port of erts/emulator/beam/beam_bp.c:2306-2378 (bp_hash_merge in the trace_info path),
    // OTP-29.1.1.
    pub(crate) fn snapshot(&self) -> Vec<(Pid, i64, i64)> {
        let mut merged: HashMap<Pid, (i64, i64), FastHash> = HashMap::default();
        for shard in &self.shards {
            shard.lock().unwrap().merge_into(&mut merged);
        }
        merged
            .into_iter()
            .map(|(pid, (count, accumulator))| (pid, count, accumulator))
            .collect()
    }

    /// Merge a stable temporary counter set into the active counter set.
    fn merge_entries(&self, entries: &[(Pid, i64, i64)]) {
        for &(pid, count, accumulator) in entries {
            self.accum(pid, count, accumulator);
        }
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

/// The breakpoint data of one function: erts hangs a `GenericBp` chain off the function's
/// `ErtsCodeInfo`; here the chain hangs off the function's id (`func_id`, the `ci` stored in
/// trace frames), so one lookup reaches it and writers only touch the matched functions.
// Port of erts/emulator/beam/beam_bp.h:85-94 (ErtsCodeInfo.u.gen_bp), OTP-29.1.1.
pub(crate) struct FunctionBp {
    id: u32,
    module: String,
    function: String,
    arity: u8,
    /// One `GenericBp` per runtime and session. Readers only use the active slot, writers
    /// (serialized by the node's `writer`) only the staging slot, as in erts; the lock only
    /// guards the chain itself.
    bps: RwLock<Vec<GenericBp>>,
    /// Bumped with every write of `bps`, under its write lock: caches of the active data of this
    /// function compare it together with the node's active index.
    version: AtomicU64,
}

impl FunctionBp {
    fn read(&self) -> std::sync::RwLockReadGuard<'_, Vec<GenericBp>> {
        self.bps.read().unwrap()
    }

    /// Modify the chain; keeps `node`'s breakpoint count and the cache version current.
    fn write<R>(&self, node: &BpNode, change: impl FnOnce(&mut Vec<GenericBp>) -> R) -> R {
        let runtime = node.code_scope as usize;
        let mut bps = self.bps.write().unwrap();
        let before = bps.iter().filter(|g| g.runtime == runtime).count();
        let result = change(&mut bps);
        let after = bps.iter().filter(|g| g.runtime == runtime).count();
        self.version.fetch_add(1, Ordering::AcqRel);
        drop(bps);
        node.adjust(after as isize - before as isize);
        result
    }
}

/// The breakpoint data of one node (a runtime and its code scope): erts keeps the active
/// breakpoint index per node, and only the holder of that node's code modification permission
/// changes breakpoints.
// Port of erts/emulator/beam/beam_bp.c:73-80 (erts_active_bp_index, erts_staging_bp_index)
// and beam_bp.h:230-238 (erts_active_bp_ix, erts_staging_bp_ix), OTP-29.1.1.
pub(crate) struct BpNode {
    code_scope: u64,
    /// Serializes writers (erts: the code modification permission).
    writer: Mutex<()>,
    /// Only changed with `writer` held.
    active_ix: AtomicUsize,
    /// `GenericBp`s of this node in all functions; while non-zero the node counts in
    /// `ACTIVE_NODES`. Only changed with `writer` held.
    entries: AtomicUsize,
}

/// Nodes in this OS process that hold a function breakpoint.
static ACTIVE_NODES: AtomicUsize = AtomicUsize::new(0);

impl BpNode {
    pub(crate) fn new(code_scope: u64) -> Self {
        BpNode {
            code_scope,
            writer: Mutex::new(()),
            active_ix: AtomicUsize::new(0),
            entries: AtomicUsize::new(0),
        }
    }

    fn active_bp_ix(&self) -> usize {
        self.active_ix.load(Ordering::Acquire)
    }

    fn staging_bp_ix(&self) -> usize {
        self.active_bp_ix() ^ 1
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, ()> {
        self.writer
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn has_entries(&self) -> bool {
        self.entries.load(Ordering::Acquire) != 0
    }

    fn adjust(&self, delta: isize) {
        if delta == 0 {
            return;
        }
        let before = self.entries.load(Ordering::Acquire);
        let after = before.wrapping_add_signed(delta);
        self.entries.store(after, Ordering::Release);
        match (before, after) {
            (0, _) => {
                ACTIVE_NODES.fetch_add(1, Ordering::AcqRel);
            }
            (_, 0) => {
                ACTIVE_NODES.fetch_sub(1, Ordering::AcqRel);
            }
            _ => {}
        }
    }
}

impl Drop for BpNode {
    fn drop(&mut self) {
        if !self.has_entries() {
            return;
        }
        let runtime = self.code_scope as usize;
        for cell in all_cells() {
            if cell.read().iter().any(|g| g.runtime == runtime) {
                cell.write(self, |bps| bps.retain(|g| g.runtime != runtime));
            }
        }
    }
}

/// The breakpoint node of `process`; a process without a runtime has a node of its own kind.
fn bp_node(process: &Process) -> &BpNode {
    static DETACHED: OnceLock<BpNode> = OnceLock::new();
    match process.runtime {
        Some(runtime) => &runtime.breakpoints,
        None => DETACHED.get_or_init(|| BpNode::new(0)),
    }
}

/// The breakpoints of one function in this VM, any session.
fn function_bps(bps: &[GenericBp], runtime: usize, code: u64) -> impl Iterator<Item = &GenericBp> {
    bps.iter()
        .filter(move |g| g.runtime == runtime && g.code == code)
}

fn code_scope(process: &Process) -> u64 {
    process
        .runtime
        .as_ref()
        .map_or(0, |runtime| runtime.code_scope)
}

/// Breakpoints belong to a code instance: breakpoints set before a module was loaded,
/// upgraded or deleted never apply to the module's later code.
// Port of erts/emulator/beam/beam_bp.c:854-900 (erts_clear_module_break), called from
// erts/emulator/beam/beam_bif_load.c:470-480 and 714-720, OTP-29.1.1.
pub(crate) fn module_code_changed(process: &Process, code: u64, module: &str) {
    let node = bp_node(process);
    if !node.has_entries() {
        return;
    }
    let _permission = node.lock();
    for cell in module_cells(module) {
        if cell.read().iter().any(|g| g.code == code) {
            cell.write(node, |bps| bps.retain(|g| g.code != code));
        }
    }
}

/// Port of erts/emulator/beam/beam_bp.c:2145-2295 (set_function_break), OTP-29.1.1, for the
/// staging copy of one session's breakpoint of one function.
fn set_function_break(
    ix: usize,
    bps: &mut Vec<GenericBp>,
    tag: (usize, u64, u64),
    match_spec: Option<&Arc<MatchSpec>>,
    break_flags: u32,
    count_op: BreakOp,
    tracer: Option<&crate::trace::Tracer>,
) {
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
            if bp.time.is_some() {
                // Port of bp_hash_reset: a restart installs fresh per-scheduler hashes.
                bp.time = Some(Arc::new(TimemTrace::default()));
            }
        }
        return;
    } else if common & BPF_MEM_TRACE != 0 {
        if count_op == BreakOp::Pause {
            bp.flags &= !BPF_MEM_TRACE_ACTIVE;
        } else {
            bp.flags |= BPF_MEM_TRACE_ACTIVE;
            if bp.memory.is_some() {
                bp.memory = Some(Arc::new(TimemTrace::default()));
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
fn clear_function_break(
    ix: usize,
    bps: &mut [GenericBp],
    tag: (usize, u64, u64),
    break_flags: u32,
) {
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
fn consolidate_bp_data(node: &BpNode, bps: &mut Vec<GenericBp>) {
    let runtime = node.code_scope as usize;
    let (active, staging) = (node.active_bp_ix(), node.staging_bp_ix());
    for g in bps.iter_mut().filter(|g| g.runtime == runtime) {
        g.data[staging] = g.data[active].clone();
    }
    bps.retain(|g| g.runtime != runtime || g.data[active].flags != 0);
}

/// Make the staged breakpoint data active: only the node's index flips, no function is touched.
// Port of erts/emulator/beam/beam_bp.c:562-569 (erts_commit_staged_bp), OTP-29.1.1.
pub(crate) fn commit_staged(process: &Process) {
    let node = bp_node(process);
    let _permission = node.lock();
    node.active_ix
        .store(node.staging_bp_ix(), Ordering::Release);
}

/// Copy the active data of `functions` to the staging area and unlink disabled breakpoints.
// Port of erts/emulator/beam/erl_bif_trace.c (erts_finish_breakpointing case 3,
// erts_consolidate_all_bp_data), OTP-29.1.1.
pub(crate) fn consolidate_staged(process: &Process, functions: &[BpFunction]) {
    let node = bp_node(process);
    let _permission = node.lock();
    let runtime = node.code_scope as usize;
    for function in functions {
        let Some(cell) = lookup_cell(&function.module, &function.function, function.arity) else {
            continue;
        };
        let traced = cell.write(node, |bps| {
            consolidate_bp_data(node, bps);
            // Port of erts/emulator/beam/beam_bp.c:374 (ep->is_bif_traced), OTP-29.1.1.
            let ix = node.active_bp_ix();
            bps.iter()
                .any(|bp| bp.runtime == runtime && bp.data[ix].flags != 0)
        });
        crate::beamasm_integration::set_bif_traced(
            &function.module,
            &function.function,
            function.arity,
            traced,
        );
    }
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

/// A stage of erts_finish_breakpointing; each one runs after a code barrier.
// Port of erts/emulator/beam/erl_bif_trace.c:2842-2935 (erts_finish_breakpointing), OTP-29.1.1.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FinishStage {
    /// Stage 0: code for the new breakpoints, which are still disabled.
    Install,
    /// Stage 1: switch the active breakpoint data.
    Commit,
    /// Stage 2: remove the code of disabled breakpoints.
    Uninstall,
    /// Stage 3: make the staged data equal to the active one.
    Consolidate,
    /// A phase that only waits for the barrier (event patterns, trace_info_finisher).
    Wait,
    /// Commit temporary call counters after the first trace-info barrier.
    TimemCommitBack,
    /// Consolidate the temporary counters after the final trace-info barrier.
    TimemConsolidate,
}

/// A breakpoint update that a trace BIF caller, suspended between code barriers, finishes
/// stage by stage (erts `finish_bp` and `trace_info_state`).
pub(crate) struct TraceFinish {
    pub(crate) functions: Vec<BpFunction>,
    pub(crate) stages: std::collections::VecDeque<FinishStage>,
    /// Session whose active call counters are being collected by a trace-info barrier.
    pub(crate) timem_session: Option<u64>,
    pub(crate) timem_time_base: Option<TimemSnapshot>,
    pub(crate) timem_memory_base: Option<TimemSnapshot>,
    pub(crate) timem_time: Option<TimemSnapshot>,
    pub(crate) timem_memory: Option<TimemSnapshot>,
    /// The BIF result once every stage ran; `None` when the BIF builds it again
    /// (bif_trace_info_finish_trap).
    pub(crate) result: Option<i64>,
}

impl TraceFinish {
    /// The stages of erts_finish_breakpointing for a staged trace pattern.
    pub(crate) fn breakpoints(functions: Vec<BpFunction>, install: bool, result: i64) -> Self {
        let mut stages = std::collections::VecDeque::new();
        if install {
            stages.push_back(FinishStage::Install);
        }
        stages.extend([
            FinishStage::Commit,
            FinishStage::Uninstall,
            FinishStage::Consolidate,
        ]);
        TraceFinish {
            functions,
            stages,
            timem_session: None,
            timem_time_base: None,
            timem_memory_base: None,
            timem_time: None,
            timem_memory: None,
            result: Some(result),
        }
    }

    /// Only waits for `barriers` code barriers.
    pub(crate) fn wait(barriers: usize, result: Option<i64>) -> Self {
        TraceFinish {
            functions: Vec::new(),
            stages: std::iter::repeat_n(FinishStage::Wait, barriers.saturating_sub(1)).collect(),
            timem_session: None,
            timem_time_base: None,
            timem_memory_base: None,
            timem_time: None,
            timem_memory: None,
            result,
        }
    }

    /// The three barrier phases of `trace_info_finisher` for active call counters.
    pub(crate) fn timem(function: BpFunction, session: u64) -> Self {
        TraceFinish {
            functions: vec![function],
            stages: [
                FinishStage::Commit,
                FinishStage::TimemCommitBack,
                FinishStage::TimemConsolidate,
            ]
            .into(),
            timem_session: Some(session),
            timem_time_base: None,
            timem_memory_base: None,
            timem_time: None,
            timem_memory: None,
            result: None,
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
    commit_staged(process);
    consolidate_staged(process, functions);
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
    let node = bp_node(process);
    let ix = node.staging_bp_ix();
    let _permission = node.lock();
    // First the code breakpoints ("local" tracing), each in the staging slot of the matched
    // function's own chain.
    for function in functions {
        let cell = function_cell(&function.module, &function.function, function.arity);
        cell.write(node, |bps| {
            if on != BreakOp::Nop {
                if !flags.breakpoint {
                    clear_function_break(ix, bps, tag, BPF_ALL & !BPF_GLOBAL_TRACE);
                } else {
                    if flags.local {
                        set_function_break(
                            ix,
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
                            ix,
                            bps,
                            tag,
                            meta_match_spec.as_ref(),
                            BPF_META_TRACE,
                            BreakOp::Nop,
                            Some(meta_tracer),
                        );
                    }
                    if flags.call_count {
                        set_function_break(
                            ix,
                            bps,
                            tag,
                            None,
                            BPF_COUNT | BPF_COUNT_ACTIVE,
                            on,
                            None,
                        );
                    }
                    if flags.call_time {
                        set_function_break(
                            ix,
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
                            ix,
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
                    clear_function_break(ix, bps, tag, BPF_LOCAL_TRACE);
                }
                if flags.meta {
                    clear_function_break(ix, bps, tag, BPF_META_TRACE);
                }
                if flags.call_count {
                    clear_function_break(ix, bps, tag, BPF_COUNT | BPF_COUNT_ACTIVE);
                }
                if flags.call_time {
                    clear_function_break(ix, bps, tag, BPF_TIME_TRACE | BPF_TIME_TRACE_ACTIVE);
                }
                if flags.call_memory {
                    clear_function_break(ix, bps, tag, BPF_MEM_TRACE | BPF_MEM_TRACE_ACTIVE);
                }
            }
        });
    }
    // Then the export entries, once the code breakpoints are set.
    for function in functions.iter().filter(|function| function.exported) {
        let cell = function_cell(&function.module, &function.function, function.arity);
        cell.write(node, |bps| {
            if on != BreakOp::Nop && !flags.breakpoint {
                set_function_break(
                    ix,
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
                clear_function_break(ix, bps, tag, BPF_GLOBAL_TRACE);
            }
        });
    }
}

/// Remove all breakpoints owned by a destroyed trace session.
// Port of erts/emulator/beam/erl_bif_trace.c:2727-2760 (prepare_clear_all_trace_pattern) and
// 1352-1375, OTP-29.1.1.
pub(crate) fn clear_session(process: &Process, session: u64) {
    clear_session_node(bp_node(process), session);
}

/// [`clear_session`] for the node that created the session.
pub(crate) fn clear_session_node(node: &BpNode, session: u64) {
    let runtime = node.code_scope as usize;
    if node.has_entries() {
        let _permission = node.lock();
        // Port of erts/emulator/beam/erl_bif_trace.c (erts_bp_match_functions over all code):
        // a destroyed session is cleared from every function.
        for cell in all_cells() {
            let owned = |g: &GenericBp| g.runtime == runtime && g.session == session;
            if cell.read().iter().any(owned) {
                cell.write(node, |bps| bps.retain(|g| !owned(g)));
            }
        }
    }
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
    let ix = bp_node(process).active_bp_ix();
    with_function_bps(module, function, arity, |bps| {
        function_bps(bps, scope(process), code_scope(process))
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
    })
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
/// scope; valid while the function's chain (`version`), the node's active index and the native
/// code are unchanged.
struct SiteBreakpoints {
    site: usize,
    runtime: usize,
    code: u64,
    /// The function's breakpoint chain (erts: the code info the trampoline belongs to).
    cell: Arc<FunctionBp>,
    version: u64,
    ix: usize,
    generation: u64,
    bps: Vec<SiteBp>,
    /// The traced function's `func_id`.
    ci: u32,
}

struct SiteBp {
    session: u64,
    /// Active flags without the export entry's global trace, which a code entry never runs.
    flags: u32,
    count: Option<Arc<AtomicU64>>,
    time: Option<Arc<TimemTrace>>,
    memory: Option<Arc<TimemTrace>>,
}

const SITE_CACHE_SIZE: usize = 64;

thread_local! {
    /// Direct-mapped, per scheduler thread: a hit costs three atomic loads and a compare.
    static SITE_CACHE: std::cell::RefCell<[Option<Arc<SiteBreakpoints>>; SITE_CACHE_SIZE]> =
        const { std::cell::RefCell::new([const { None }; SITE_CACHE_SIZE]) };
}

fn site_breakpoints(process: &Process, site: usize) -> Option<Arc<SiteBreakpoints>> {
    let runtime = scope(process);
    let code = code_scope(process);
    let slot = (site >> 2) % SITE_CACHE_SIZE;
    let ix = bp_node(process).active_bp_ix();
    let generation = crate::native_bridge::native_registry_generation();
    if let Some(found) = SITE_CACHE.with(|cache| {
        cache.borrow()[slot]
            .as_ref()
            .filter(|entry| {
                entry.site == site
                    && entry.runtime == runtime
                    && entry.code == code
                    && entry.ix == ix
                    && entry.generation == generation
                    && entry.version == entry.cell.version.load(Ordering::Acquire)
            })
            .cloned()
    }) {
        return Some(found);
    }
    let (module, function_name, arity) =
        crate::native_bridge::with_native_function_at(site, |function| {
            (
                function.module.to_owned(),
                function.function.to_owned(),
                function.arity,
            )
        })?;
    let cell = function_cell(&module, &function_name, arity);
    let (version, bps) = {
        let chain = cell.read();
        let bps = function_bps(&chain, runtime, code)
            .map(|g| SiteBp {
                session: g.session,
                flags: g.data[ix].flags & !BPF_GLOBAL_TRACE,
                count: g.data[ix].count.clone(),
                time: g.data[ix].time.clone(),
                memory: g.data[ix].memory.clone(),
            })
            .collect::<Vec<_>>();
        (cell.version.load(Ordering::Acquire), bps)
    };
    let entry = Arc::new(SiteBreakpoints {
        site,
        runtime,
        code,
        ci: cell.id,
        cell,
        version,
        ix,
        generation,
        bps,
    });
    SITE_CACHE.with(|cache| cache.borrow_mut()[slot] = Some(entry.clone()));
    Some(entry)
}

/// What a native trampoline hit did when it needs no trace event: the counters are
/// incremented and the call time or memory accounted. `actions` are the return frames to push.
pub(crate) struct NativeBreakpointHit {
    pub(crate) action: Option<crate::trace::NativeTraceAction>,
    pub(crate) arity: u8,
}

/// Native-code `erts_generic_breakpoint` of the trampoline at `site` for a function whose
/// breakpoints for this process only count and account call time or memory. `None` means a
/// trace event, a debug breakpoint or a frame the native code cannot judge is involved, and
/// nothing has been touched: the executor must run the breakpoint.
// Port of erts/emulator/beam/beam_bp.c:994-1160 (erts_generic_breakpoint, do_session_breakpoint
// for ERTS_BPF_COUNT_ACTIVE, ERTS_BPF_TIME_TRACE_ACTIVE and ERTS_BPF_MEM_TRACE_ACTIVE),
// OTP-29.1.1, as the JIT trampoline fragment calls it without leaving native code.
pub(crate) fn native_breakpoint_accounting(
    process: &mut Process,
    pid: Pid,
    site: usize,
) -> Option<NativeBreakpointHit> {
    if crate::trace::is_sensitive(process, pid) {
        return Some(NativeBreakpointHit {
            action: None,
            arity: 0,
        });
    }
    let entry = site_breakpoints(process, site)?;
    let acc = BPF_TIME_TRACE_ACTIVE | BPF_MEM_TRACE_ACTIVE;
    if DEBUG_BREAKPOINTS_USED.load(Ordering::Relaxed)
        && debug_breakpoint_enabled(
            process,
            &entry.cell.module,
            &entry.cell.function,
            entry.cell.arity,
        )
        || crate::trace::return_to_enabled(process)
    {
        return None;
    }
    // A session that does not trace calls of this process runs nothing but the counters.
    let mut traced = [false; 4];
    let mut any_acc = false;
    if entry.bps.len() > traced.len() {
        return None;
    }
    for (index, bp) in entry.bps.iter().enumerate() {
        if bp.flags & BPF_META_TRACE != 0 {
            return None;
        }
        if bp.flags & (BPF_LOCAL_TRACE | acc) != 0 {
            traced[index] = crate::trace::session_flags_cached(process, bp.session, pid)
                & crate::trace::CALL
                != 0;
            if traced[index] && bp.flags & BPF_LOCAL_TRACE != 0 {
                return None;
            }
            any_acc |= traced[index] && bp.flags & acc != 0;
        }
    }
    // The call acc frame is not pushed on top of another trace frame (tail recursion).
    let mut frame_on_top = false;
    if any_acc {
        let top = process.heap.stack_get(0)?.tagged_word() as usize;
        if top == crate::native_bridge::native_trace_return_address() {
            frame_on_top = true;
        } else if !crate::native_bridge::is_native_function_at(top) {
            return None;
        }
        if entry.cell.arity > 6 {
            return None;
        }
    }
    let mut action = None;
    for (index, bp) in entry.bps.iter().enumerate() {
        let bp_flags = if traced[index] || bp.flags & (BPF_LOCAL_TRACE | acc) == 0 {
            bp.flags
        } else {
            bp.flags & !(BPF_LOCAL_TRACE | acc)
        };
        if bp_flags & BPF_COUNT_ACTIVE != 0
            && let Some(count) = &bp.count
        {
            count.fetch_add(1, Ordering::Relaxed);
        }
        if bp_flags & acc == 0 {
            continue;
        }
        let mut prev = None;
        if bp_flags & BPF_TIME_TRACE_ACTIVE != 0
            && let Some(bdt) = bp.time.as_ref()
        {
            let time = arinsal_bifs::monotonic_time_raw_nanos();
            prev = trace_call_acc(process, pid, bp.session, false, entry.ci, time, bdt);
        }
        if bp_flags & BPF_MEM_TRACE_ACTIVE != 0
            && let Some(bdt) = bp.memory.as_ref()
        {
            let adjustment = call_memory_adjustment(process, bp.session);
            // The initial call of a process starts counting from zero.
            let allocated = if adjustment.is_none()
                && crate::trace::is_initial_call(
                    process,
                    &entry.cell.module,
                    &entry.cell.function,
                    entry.cell.arity,
                ) {
                0
            } else {
                process.allocated_words(adjustment.unwrap_or(0))
            };
            prev = trace_call_acc(process, pid, bp.session, true, entry.ci, allocated, bdt);
        }
        if !frame_on_top && action.is_none() {
            action = Some(crate::trace::NativeTraceAction {
                session: bp.session,
                return_trace: false,
                exception_trace: false,
                return_to: false,
                acc: Some(crate::trace::CallAcc {
                    flags: bp_flags & acc,
                    prev,
                }),
            });
        }
    }
    Some(NativeBreakpointHit {
        action,
        arity: entry.cell.arity,
    })
}

/// The functions among `functions` that have a breakpoint of any session: clearing, pausing or
/// restarting a breakpoint only concerns them.
pub(crate) fn with_breakpoints(process: &Process, functions: Vec<BpFunction>) -> Vec<BpFunction> {
    let runtime = scope(process);
    let code = code_scope(process);
    functions
        .into_iter()
        .filter(|function| {
            with_function_bps(
                &function.module,
                &function.function,
                function.arity,
                |bps| function_bps(bps, runtime, code).next().is_some(),
            )
        })
        .collect()
}

/// True while some runtime holds a function breakpoint; keeps untraced BIF calls on the fast path.
pub(crate) fn any_pattern() -> bool {
    ACTIVE_NODES.load(Ordering::Relaxed) != 0
}

/// Whether a breakpoint of any session or runtime is set on this function.
// Port of erts/emulator/beam/beam_bp.c:321-330 (erts_export_is_bif_traced), OTP-29.1.1.
pub(crate) fn selects(process: &Process, module: &str, function: &str, arity: u8) -> bool {
    let ix = bp_node(process).active_bp_ix();
    let runtime = scope(process);
    with_function_bps(module, function, arity, |bps| {
        bps.iter()
            .any(|g| g.runtime == runtime && g.data[ix].flags != 0)
    })
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

pub(crate) type TimemSnapshot = Vec<(Pid, i64, i64)>;
type TimemInfoSnapshot = (Option<TimemSnapshot>, Option<TimemSnapshot>);

/// Install empty staging hashes before the first active-counter trace-info barrier.
// Port of erts/emulator/beam/beam_bp.c:1486-1561 (erts_prepare_timem_trace_info), OTP-29.1.1.
pub(crate) fn prepare_timem_info(
    process: &Process,
    session: u64,
    module: &str,
    function: &str,
    arity: u8,
    want: u32,
) {
    let node = bp_node(process);
    let _permission = node.lock();
    let staging = node.staging_bp_ix();
    let Some(cell) = lookup_cell(module, function, arity) else {
        return;
    };
    let tag = (scope(process), code_scope(process), session);
    cell.write(node, |bps| {
        let Some(bp) = bps
            .iter_mut()
            .find(|bp| (bp.runtime, bp.code, bp.session) == tag)
        else {
            return;
        };
        let data = &mut bp.data[staging];
        if want & WANT_TIME != 0 && data.flags & BPF_TIME_TRACE_ACTIVE != 0 {
            data.time = Some(Arc::new(TimemTrace::default()));
        }
        if want & WANT_MEMORY != 0 && data.flags & BPF_MEM_TRACE_ACTIVE != 0 {
            data.memory = Some(Arc::new(TimemTrace::default()));
        }
    });
}

/// Collect the old counters after the temporary hashes have become active.
// Port of erts/emulator/beam/beam_bp.c:1564-1575 (erts_timem_info_collect), OTP-29.1.1.
pub(crate) fn collect_timem_info(
    process: &Process,
    session: u64,
    module: &str,
    function: &str,
    arity: u8,
) -> TimemInfoSnapshot {
    let staging = bp_node(process).staging_bp_ix();
    let tag = (scope(process), code_scope(process), session);
    with_function_bps(module, function, arity, |bps| {
        let Some(bp) = bps
            .iter()
            .find(|bp| (bp.runtime, bp.code, bp.session) == tag)
        else {
            return (None, None);
        };
        let data = &bp.data[staging];
        let time = (data.flags & BPF_TIME_TRACE_ACTIVE != 0)
            .then(|| data.time.as_ref().map(|bdt| bdt.snapshot()))
            .flatten();
        let memory = (data.flags & BPF_MEM_TRACE_ACTIVE != 0)
            .then(|| data.memory.as_ref().map(|bdt| bdt.snapshot()))
            .flatten();
        (time, memory)
    })
}

// Port of erts/emulator/beam/beam_bp.c:1621-1645 (erts_timem_info_consolidate), OTP-29.1.1.
fn merge_timem_snapshots(base: TimemSnapshot, temporary: TimemSnapshot) -> TimemSnapshot {
    let mut merged: HashMap<Pid, (i64, i64), FastHash> = HashMap::default();
    for (pid, count, accumulator) in base.into_iter().chain(temporary) {
        let total = merged.entry(pid).or_default();
        total.0 += count;
        total.1 += accumulator;
    }
    merged
        .into_iter()
        .map(|(pid, (count, accumulator))| (pid, count, accumulator))
        .collect()
}

/// Consolidate the stable temporary hashes into the restored active hashes.
// Port of erts/emulator/beam/beam_bp.c:1564-1595 (erts_timem_info_consolidate), OTP-29.1.1.
pub(crate) fn consolidate_timem_info(
    process: &Process,
    session: u64,
    module: &str,
    function: &str,
    arity: u8,
    time_base: Option<TimemSnapshot>,
    memory_base: Option<TimemSnapshot>,
) -> TimemInfoSnapshot {
    let node = bp_node(process);
    let _permission = node.lock();
    let (active, staging) = (node.active_bp_ix(), node.staging_bp_ix());
    let Some(cell) = lookup_cell(module, function, arity) else {
        return (time_base, memory_base);
    };
    let tag = (scope(process), code_scope(process), session);
    cell.write(node, |bps| {
        let Some(bp) = bps
            .iter_mut()
            .find(|bp| (bp.runtime, bp.code, bp.session) == tag)
        else {
            return (time_base, memory_base);
        };
        let data = &mut bp.data;
        let mut time_result = None;
        let mut memory_result = None;
        if data[active].flags & BPF_TIME_TRACE_ACTIVE != 0
            && let (Some(real), Some(temporary)) = (&data[active].time, &data[staging].time)
            && !Arc::ptr_eq(real, temporary)
        {
            let temporary_snapshot = temporary.snapshot();
            real.merge_entries(&temporary_snapshot);
            time_result = Some(merge_timem_snapshots(
                time_base.unwrap_or_default(),
                temporary_snapshot,
            ));
            data[staging].time = Some(Arc::clone(real));
        }
        if data[active].flags & BPF_MEM_TRACE_ACTIVE != 0
            && let (Some(real), Some(temporary)) = (&data[active].memory, &data[staging].memory)
            && !Arc::ptr_eq(real, temporary)
        {
            let temporary_snapshot = temporary.snapshot();
            real.merge_entries(&temporary_snapshot);
            memory_result = Some(merge_timem_snapshots(
                memory_base.unwrap_or_default(),
                temporary_snapshot,
            ));
            data[staging].memory = Some(Arc::clone(real));
        }
        (time_result, memory_result)
    })
}

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
    snapshot_active: bool,
) -> FunctionInfo {
    let ix = bp_node(process).active_bp_ix();
    let bp = with_function_bps(module, function, arity, |bps| {
        function_bps(bps, scope(process), code_scope(process))
            .find(|g| g.session == session)
            .map(|g| g.data[ix].clone())
            .unwrap_or_default()
    });
    let mut got = bp.flags & want;
    if got & BPF_GLOBAL_TRACE != 0 {
        got = BPF_GLOBAL_TRACE;
    }
    let source = |spec: &Option<Arc<MatchSpec>>| spec.as_deref().map(|spec| spec.source.clone());
    let time = (got & BPF_TIME_TRACE != 0
        && (snapshot_active || bp.flags & BPF_TIME_TRACE_ACTIVE == 0))
        .then(|| bp.time.as_ref().map(|bdt| bdt.snapshot()))
        .flatten();
    let memory = (got & BPF_MEM_TRACE != 0
        && (snapshot_active || bp.flags & BPF_MEM_TRACE_ACTIVE == 0))
        .then(|| bp.memory.as_ref().map(|bdt| bdt.snapshot()))
        .flatten();
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
        time,
        memory,
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
    let ix = bp_node(process).active_bp_ix();
    let mut sessions = with_function_bps(module, function, arity, |bps| {
        function_bps(bps, scope(process), code_scope(process))
            .filter_map(|bp| (bp.data[ix].flags != 0).then_some(bp.session))
            .collect::<Vec<_>>()
    });
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
    let (ix, staging) = (
        bp_node(process).active_bp_ix(),
        bp_node(process).staging_bp_ix(),
    );
    let install = INSTALL_VIEW.with(std::cell::Cell::get);
    with_function_bps(module, function, arity, |bps| {
        for g in function_bps(bps, scope(process), code_scope(process)) {
            let mut flags = g.data[ix].flags;
            if install {
                flags |= g.data[staging].flags;
            }
            local |= flags & !BPF_GLOBAL_TRACE != 0;
            global |= flags & BPF_GLOBAL_TRACE != 0;
        }
    });
    (local, global)
}

/// Whether some session has any breakpoint flag on the function, as `breakpoint_kinds` sees it.
// Port of erts/emulator/beam/beam_bp.c:321-330 (erts_export_is_bif_traced), OTP-29.1.1.
pub(crate) fn any_breakpoint(process: &Process, module: &str, function: &str, arity: u8) -> bool {
    let (ix, staging) = (
        bp_node(process).active_bp_ix(),
        bp_node(process).staging_bp_ix(),
    );
    let install = INSTALL_VIEW.with(std::cell::Cell::get);
    with_function_bps(module, function, arity, |bps| {
        function_bps(bps, scope(process), code_scope(process)).any(|g| {
            let mut flags = g.data[ix].flags;
            if install {
                flags |= g.data[staging].flags;
            }
            flags != 0
        })
    })
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
    /// The counters of the function last looked up: a tight loop of calls would otherwise
    /// look its chain up on every call and return.
    cache: Option<PbtCache>,
}

/// The active call time or memory counters of one function, valid while the function's chain
/// version and the node's active index are unchanged (erts reads `ci->gen_bp` directly).
#[derive(Clone)]
struct PbtCache {
    cell: Arc<FunctionBp>,
    version: u64,
    ix: usize,
    bdt: Arc<TimemTrace>,
}

/// Function ids and their breakpoint chains, nested by name so a lookup does not allocate.
#[derive(Default)]
struct FuncIds {
    cells: Vec<Arc<FunctionBp>>,
    ids: HashMap<String, FunctionIds, FastHash>,
}

type FunctionIds = HashMap<String, HashMap<u8, u32, FastHash>, FastHash>;

fn func_ids() -> &'static RwLock<FuncIds> {
    static IDS: OnceLock<RwLock<FuncIds>> = OnceLock::new();
    IDS.get_or_init(|| RwLock::new(FuncIds::default()))
}

/// The breakpoint chain of a function, if it ever had an id.
fn lookup_cell(module: &str, function: &str, arity: u8) -> Option<Arc<FunctionBp>> {
    let ids = func_ids().read().unwrap();
    let id = *ids.ids.get(module)?.get(function)?.get(&arity)?;
    Some(ids.cells[id as usize].clone())
}

/// The breakpoint chain of a function, created with its id.
fn function_cell(module: &str, function: &str, arity: u8) -> Arc<FunctionBp> {
    if let Some(cell) = lookup_cell(module, function, arity) {
        return cell;
    }
    let mut ids = func_ids().write().unwrap();
    if let Some(&id) = ids
        .ids
        .get(module)
        .and_then(|functions| functions.get(function))
        .and_then(|arities| arities.get(&arity))
    {
        return ids.cells[id as usize].clone();
    }
    let id = ids.cells.len() as u32;
    let cell = Arc::new(FunctionBp {
        id,
        module: module.to_owned(),
        function: function.to_owned(),
        arity,
        bps: RwLock::new(Vec::new()),
        version: AtomicU64::new(0),
    });
    ids.cells.push(cell.clone());
    ids.ids
        .entry(module.to_owned())
        .or_default()
        .entry(function.to_owned())
        .or_default()
        .insert(arity, id);
    cell
}

fn cell_by_id(id: u32) -> Option<Arc<FunctionBp>> {
    func_ids().read().unwrap().cells.get(id as usize).cloned()
}

/// Every function chain (erts: all code infos of all loaded modules).
fn all_cells() -> Vec<Arc<FunctionBp>> {
    func_ids().read().unwrap().cells.clone()
}

/// The function chains of one module.
fn module_cells(module: &str) -> Vec<Arc<FunctionBp>> {
    let ids = func_ids().read().unwrap();
    ids.ids
        .get(module)
        .into_iter()
        .flat_map(|functions| functions.values())
        .flat_map(|arities| arities.values())
        .map(|&id| ids.cells[id as usize].clone())
        .collect()
}

/// Runs `read` on the breakpoint chain of a function, empty when it has none.
fn with_function_bps<R>(
    module: &str,
    function: &str,
    arity: u8,
    read: impl FnOnce(&[GenericBp]) -> R,
) -> R {
    match lookup_cell(module, function, arity) {
        Some(cell) => read(&cell.read()),
        None => read(&[]),
    }
}

/// A small id of a function, stored in trace frames in place of erts' `ErtsCodeInfo` pointer.
pub(crate) fn func_id(module: &str, function: &str, arity: u8) -> u32 {
    function_cell(module, function, arity).id
}

// Port of erts/emulator/beam/beam_bp.c:2410-2442 (get_time_break, get_memory_break,
// check_break), OTP-29.1.1.
fn timem_break(process: &Process, session: u64, id: u32, memory: bool) -> Option<Arc<TimemTrace>> {
    let cell = cell_by_id(id)?;
    timem_break_of(process, &cell, session, memory)
}

fn timem_break_of(
    process: &Process,
    cell: &FunctionBp,
    session: u64,
    memory: bool,
) -> Option<Arc<TimemTrace>> {
    let ix = bp_node(process).active_bp_ix();
    let bps = cell.read();
    let bp = function_bps(&bps, scope(process), code_scope(process))
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
    pbt_index: usize,
    id: u32,
    memory: bool,
) -> Option<Arc<TimemTrace>> {
    let ix = bp_node(process).active_bp_ix();
    if let Some(cache) = pbt_list(process, memory).get(pbt_index)?.cache.as_ref()
        && cache.cell.id == id
        && cache.ix == ix
        && cache.version == cache.cell.version.load(Ordering::Acquire)
    {
        return Some(cache.bdt.clone());
    }
    let session = pbt_list(process, memory).get(pbt_index)?.session;
    let cell = cell_by_id(id)?;
    // Read the version before the data: a later write makes the cache entry stale, not wrong.
    let version = cell.version.load(Ordering::Acquire);
    let found = timem_break_of(process, &cell, session, memory)?;
    pbt_list(process, memory).get_mut(pbt_index)?.cache = Some(PbtCache {
        cell,
        version,
        ix,
        bdt: found.clone(),
    });
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
    let pbt_index = if let Some(index) = pbt_list(process, memory)
        .iter()
        .position(|pbt| pbt.session == session)
    {
        index
    } else {
        pbt_list(process, memory).push(ProcBpTrace {
            session,
            ci: None,
            accumulator: 0,
            allocated: 0,
            cache: None,
        });
        pbt_list(process, memory).len() - 1
    };
    let (previous, accumulator) = {
        let pbt = &pbt_list(process, memory)[pbt_index];
        (pbt.ci, pbt.accumulator)
    };
    let mut counted = false;
    if let Some(previous) = previous {
        // Add time/allocation to the previous code; none if its breakpoint was removed.
        if let Some(previous_bdt) = cached_timem_break(process, pbt_index, previous, memory) {
            if std::ptr::eq(&*previous_bdt, bdt) {
                // Recursion: one bucket update takes the call and the time.
                previous_bdt.accum(pid, 1, accum - accumulator);
                counted = true;
            } else {
                previous_bdt.accum(pid, 0, accum - accumulator);
            }
        }
    }
    if !counted {
        bdt.accum(pid, 1, 0);
    }
    let pbt = &mut pbt_list(process, memory)[pbt_index];
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
        let pbt_index = pbt_list(process, false)
            .iter()
            .position(|pbt| pbt.session == session);
        if let Some(pbt_index) = pbt_index {
            let (ci, accumulator) = {
                let pbt = &pbt_list(process, false)[pbt_index];
                (pbt.ci, pbt.accumulator)
            };
            let time = arinsal_bifs::monotonic_time_raw_nanos();
            // Might have been removed by trace_pattern(false).
            if let Some(bdt) = ci.and_then(|ci| cached_timem_break(process, pbt_index, ci, false)) {
                bdt.accum(pid, 0, time - accumulator);
            }
            let pbt = &mut pbt_list(process, false)[pbt_index];
            pbt.ci = prev;
            pbt.accumulator = time;
        }
    }
    if bp_flags & BPF_MEM_TRACE_ACTIVE != 0 {
        let pbt_index = pbt_list(process, true)
            .iter()
            .position(|pbt| pbt.session == session);
        if let Some(pbt_index) = pbt_index {
            let (ci, accumulator, allocated) = {
                let pbt = &pbt_list(process, true)[pbt_index];
                (pbt.ci, pbt.accumulator, pbt.allocated)
            };
            let words = process.allocated_words(allocated);
            if let Some(bdt) = ci.and_then(|ci| cached_timem_break(process, pbt_index, ci, true)) {
                bdt.accum(pid, 0, words - accumulator);
            }
            let pbt = &mut pbt_list(process, true)[pbt_index];
            pbt.ci = prev;
            pbt.accumulator = words;
        }
    }
}

/// A process is scheduled in or out: restart or close the running time slice of its call_time
/// accounting.
// Port of erts/emulator/beam/beam_bp.c:2017-2073 (erts_schedule_time_break), OTP-29.1.1.
pub(crate) fn schedule_time_break(process: &mut Process, pid: Pid, out: bool) {
    let now = arinsal_bifs::monotonic_time_raw_nanos();
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
