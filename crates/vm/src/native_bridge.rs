//! Native execution bridge and registered code metadata.

use super::*;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

fn perf_map_file() -> &'static Mutex<Option<File>> {
    static FILE: OnceLock<Mutex<Option<File>>> = OnceLock::new();
    FILE.get_or_init(|| Mutex::new(open_perf_map()))
}

// Port of erts/emulator/beam/jit/beam_jit_metadata.cpp:470-501 (JitPerfMap), OTP-29.1.1.
fn open_perf_map() -> Option<File> {
    let flags = arinsal_args::active_emulator_flags();
    let mut enabled = false;
    let mut directory = PathBuf::from("/tmp");
    for flag in &flags.ignored {
        match (flag.name.as_str(), flag.value.as_deref()) {
            ("+JPperf", Some("true" | "map")) => enabled = true,
            ("+JPperf", Some("false")) => enabled = false,
            ("+JPperfdirectory", Some(path)) => directory = PathBuf::from(path),
            _ => {}
        }
    }
    if !enabled {
        return None;
    }
    let path = std::env::var_os("ERL_SYM_MAP_FILE")
        .map(PathBuf::from)
        .unwrap_or_else(|| directory.join(format!("perf-{}.map", std::process::id())));
    match OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&path)
    {
        Ok(file) => Some(file),
        Err(error) => {
            eprintln!("perf: Failed to open {} ({error})", path.display());
            None
        }
    }
}

// Port of erts/emulator/beam/jit/beam_jit_metadata.cpp:535-552 (JitPerfSupport::update), OTP-29.1.1.
fn update_perf_map(info: &NativeFunction) {
    let mut file = perf_map_file()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(file) = file.as_mut() {
        let symbol = format!("${}:{}/{}", info.module, info.function, info.arity);
        let _ = writeln!(
            file,
            "{:#x} {:x} {symbol}",
            info.start,
            info.end - info.start
        );
        let _ = file.flush();
    }
}

/// Symbolic information attached to one executable native code range.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeFunction {
    /// Code scope (node) the code belongs to; 0 registers it for every node.
    pub scope: u64,
    /// Inclusive first byte of generated code.
    pub start: usize,
    /// Exclusive end of generated code.
    pub end: usize,
    /// Erlang module name.
    pub module: String,
    /// Module atom resolved when the native function was registered.
    pub module_atom: arinsal_term::Atom,
    /// Erlang function name.
    pub function: String,
    /// Function atom resolved when the native function was registered.
    pub function_atom: arinsal_term::Atom,
    /// Erlang function arity.
    pub arity: u8,
    /// Source line, when known.
    pub line: Option<u32>,
    /// Source file, when known.
    pub file: Option<Arc<str>>,
    /// Cached literal filename list, when source location metadata is available.
    pub file_term: Option<Term>,
    /// Native PCs and their source locations, sorted by address.
    pub line_table: Vec<NativeLine>,
}

/// One native PC to source location mapping.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeLine {
    /// Native address at which this source line becomes current.
    pub address: usize,
    /// Source filename.
    pub file: Arc<str>,
    /// Cached literal filename list from the owning BEAM module.
    pub file_term: Option<Term>,
    /// One-based source line.
    pub line: u32,
}

impl NativeFunction {
    /// Resolve a native return PC to the nearest preceding BEAM line marker.
    pub fn line_at(&self, address: usize) -> Option<(&str, u32)> {
        let index = self
            .line_table
            .partition_point(|entry| entry.address <= address)
            .checked_sub(1)?;
        // Line 0 marks a location erts cannot represent (LINE_INVALID_LOCATION).
        self.line_table
            .get(index)
            .filter(|entry| entry.line != 0)
            .map(|entry| (entry.file.as_ref(), entry.line))
    }
}

#[derive(Clone)]
pub(crate) struct NativeStackFrame {
    pub module_atom: arinsal_term::Atom,
    pub function_atom: arinsal_term::Atom,
    pub arity: u8,
    pub line: Option<u32>,
    pub file_term: Option<Term>,
    pub file: Option<Arc<str>>,
}

/// One native function inside a module range. The line table is shared, not cloned per frame.
#[derive(Clone)]
pub(crate) struct FunctionRange {
    start: usize,
    end: usize,
    module_atom: arinsal_term::Atom,
    function_atom: arinsal_term::Atom,
    arity: u8,
    /// `loc_tab` entries retain the literal filename term used by the module.
    // Port of erts/emulator/beam/beam_ranges.c:353-357, OTP-29.1.1.
    locs: Arc<[LineLoc]>,
    /// `lines[i].address`, packed so `find_line` does not chase the filename Arc.
    /// Port of beam_ranges.c:331 (`lookup_loc` binary-searches `func_tab` pointers,
    /// then indexes `loc_tab`), OTP-29.1.1.
    line_addrs: Arc<[usize]>,
}

struct LineLoc {
    line: u32,
    file_term: Option<Term>,
    file: Arc<str>,
}

/// One module's native code in the active code index, sorted by `start`.
///
/// Port of erts/emulator/beam/beam_ranges.c:33-66 (`Range`) and :245 (`erts_lookup_function_info`),
/// OTP-29.1.1. `find_range` binary-searches the module, then the function inside it.
#[derive(Clone)]
pub(crate) struct ModuleRange {
    start: usize,
    end: usize,
    module_atom: arinsal_term::Atom,
    functions: Arc<[FunctionRange]>,
    /// `functions[i].start`. `erts_lookup_function_info` binary-searches an array of
    /// code pointers, not the function records (beam_ranges.c:262-278), OTP-29.1.1.
    fn_starts: Arc<[usize]>,
}

fn scope0_ranges() -> &'static arc_swap::ArcSwap<Vec<ModuleRange>> {
    static RANGES: OnceLock<arc_swap::ArcSwap<Vec<ModuleRange>>> = OnceLock::new();
    RANGES.get_or_init(|| arc_swap::ArcSwap::new(Arc::new(Vec::new())))
}

/// Scope-0 ranges a new node's code indexes start from.
pub(crate) fn scope0_code_ranges() -> Arc<Vec<ModuleRange>> {
    scope0_ranges().load_full()
}

fn function_range(info: &NativeFunction) -> FunctionRange {
    let line_addrs: Arc<[usize]> = info.line_table.iter().map(|entry| entry.address).collect();
    let locs: Arc<[LineLoc]> = info
        .line_table
        .iter()
        .map(|entry| LineLoc {
            line: entry.line,
            file_term: entry.file_term,
            file: entry.file.clone(),
        })
        .collect();
    FunctionRange {
        start: info.start,
        end: info.end,
        module_atom: info.module_atom,
        function_atom: info.function_atom,
        arity: info.arity,
        locs,
        line_addrs,
    }
}

fn module_range(
    start: usize,
    end: usize,
    module_atom: arinsal_term::Atom,
    functions: Vec<FunctionRange>,
) -> ModuleRange {
    let fn_starts: Arc<[usize]> = functions.iter().map(|function| function.start).collect();
    ModuleRange {
        start,
        end,
        module_atom,
        functions: Arc::from(functions),
        fn_starts,
    }
}

/// Inserts `fun` into the sorted module ranges. Adjacent or overlapping functions of the
/// same module share one range; a gap stays two ranges so another module can sit between them.
fn insert_function_range(ranges: &mut Vec<ModuleRange>, fun: FunctionRange) {
    if ranges.iter().any(|range| {
        range
            .functions
            .iter()
            .any(|function| function.start == fun.start)
    }) {
        return;
    }
    let module = fun.module_atom;
    if let Some(index) = ranges.iter().position(|range| {
        range.module_atom == module && fun.start <= range.end && range.start <= fun.end
    }) {
        let range = &ranges[index];
        let mut functions = range.functions.to_vec();
        let at = functions.partition_point(|function| function.start < fun.start);
        let start = range.start.min(fun.start);
        let end = range.end.max(fun.end);
        functions.insert(at, fun);
        ranges[index] = module_range(start, end, module, functions);
        ranges.sort_by_key(|range| range.start);
        return;
    }
    let start = fun.start;
    let end = fun.end;
    let entry = module_range(start, end, module, vec![fun]);
    let index = ranges.partition_point(|range| range.start < start);
    ranges.insert(index, entry);
}

fn remove_function_range(ranges: &mut Vec<ModuleRange>, start: usize) {
    let Some(index) = ranges
        .iter()
        .position(|range| range.start <= start && start < range.end)
    else {
        return;
    };
    let module_atom = ranges[index].module_atom;
    let functions = ranges[index]
        .functions
        .iter()
        .filter(|function| function.start != start)
        .cloned()
        .collect::<Vec<_>>();
    if functions.is_empty() {
        ranges.remove(index);
        return;
    }
    let range_start = functions
        .iter()
        .map(|function| function.start)
        .min()
        .unwrap_or(start);
    let range_end = functions
        .iter()
        .map(|function| function.end)
        .max()
        .unwrap_or(start);
    ranges[index] = module_range(range_start, range_end, module_atom, functions);
    ranges.sort_by_key(|range| range.start);
}

fn rewrite_ranges(
    indexes: &crate::code_ix::CodeIndexes,
    change: impl FnOnce(&mut Vec<ModuleRange>),
) {
    let mut ranges = indexes.code_ranges().as_ref().clone();
    change(&mut ranges);
    indexes.store_code_ranges(Arc::new(ranges));
}

/// Publishes `info` into its node's active code-index ranges. Scope 0 is visible to every node.
/// Callers hold the registry write lock, so two publishes cannot drop each other's insert.
fn publish_function_range(info: &NativeFunction) {
    let fun = function_range(info);
    if info.scope == 0 {
        let mut seed = scope0_ranges().load_full().as_ref().clone();
        insert_function_range(&mut seed, fun);
        let seed = Arc::new(seed);
        scope0_ranges().store(Arc::clone(&seed));
        crate::code_ix::with_all_scopes(|indexes| {
            rewrite_ranges(indexes, |ranges| {
                insert_function_range(ranges, function_range(info))
            });
        });
        return;
    }
    rewrite_ranges(&crate::code_ix::for_scope(info.scope), |ranges| {
        insert_function_range(ranges, fun);
    });
}

fn unpublish_function_range(info: &NativeFunction) {
    if info.scope == 0 {
        let mut seed = scope0_ranges().load_full().as_ref().clone();
        remove_function_range(&mut seed, info.start);
        scope0_ranges().store(Arc::new(seed));
        crate::code_ix::with_all_scopes(|indexes| {
            rewrite_ranges(indexes, |ranges| remove_function_range(ranges, info.start));
        });
        return;
    }
    let Some(indexes) = crate::code_ix::existing_scope(info.scope) else {
        return;
    };
    rewrite_ranges(&indexes, |ranges| remove_function_range(ranges, info.start));
}

/// `find_range` (beam_ranges.c:307-327), OTP-29.1.1. The search starts at the last module
/// that matched (`r[active].mid`); a miss falls back to the binary search and stores the hit.
fn find_range(ranges: &[ModuleRange], address: usize) -> Option<&ModuleRange> {
    static RANGE_MID: AtomicUsize = AtomicUsize::new(0);
    let len = ranges.len();
    if len == 0 {
        return None;
    }
    let cached = RANGE_MID.load(Ordering::Relaxed).min(len - 1);
    let mid = &ranges[cached];
    if address >= mid.start && address < mid.end {
        return Some(mid);
    }
    let index = ranges.partition_point(|range| range.start <= address);
    let found = index.checked_sub(1)?;
    let range = ranges.get(found)?;
    if address >= range.end {
        return None;
    }
    RANGE_MID.store(found, Ordering::Relaxed);
    Some(range)
}

/// `erts_lookup_function_info` over the ranges published with the active code index.
// Port of erts/emulator/beam/beam_ranges.c:245-280 and :307-327, OTP-29.1.1.
fn frame_in(ranges: &[ModuleRange], address: usize) -> Option<NativeStackFrame> {
    let range = find_range(ranges, address)?;
    let index = range.fn_starts.partition_point(|start| *start <= address);
    let function = range.functions.get(index.checked_sub(1)?)?;
    if address >= function.end {
        return None;
    }
    // Port of beam_ranges.c:331 (`lookup_loc`): binary search the function's pc table,
    // then index its parallel location table. Filenames remain module literals.
    let loc = function
        .line_addrs
        .partition_point(|start| *start <= address)
        .checked_sub(1)
        .and_then(|index| function.locs.get(index))
        .filter(|entry| entry.line != 0);
    let file_term = loc.as_ref().and_then(|entry| entry.file_term);
    // `fi->fname_ptr[file]` is a literal. The string is only needed when it is absent.
    let file = loc
        .as_ref()
        .filter(|_| file_term.is_none())
        .map(|entry| entry.file.clone());
    Some(NativeStackFrame {
        module_atom: function.module_atom,
        function_atom: function.function_atom,
        arity: function.arity,
        line: loc.map(|entry| entry.line),
        file_term,
        file,
    })
}

/// Stack frame for `address` in `ranges`, the active code index's module ranges.
/// `None` ranges (a process with no node) falls back to the registry.
// Port of erts/emulator/beam/beam_ranges.c:245 (`erts_lookup_function_info`), OTP-29.1.1.
pub(crate) fn stack_frame_in(
    ranges: Option<&[ModuleRange]>,
    address: usize,
) -> Option<NativeStackFrame> {
    let Some(ranges) = ranges else {
        if !arinsal_term::may_be_native_code_pointer(address) {
            return None;
        }
        return native_stack_frame_at(address);
    };
    frame_in(ranges, address)
}

/// The registry of native code ranges. Every process entry and return reads it, so readers
/// take only their own reader-group line, as erts' frequent-read rwlocks do
/// (`ERTS_RWMTX_TYPE_FREQUENT_READ`).
fn native_functions() -> &'static arinsal_term::FrequentReadRwLock<Vec<NativeFunction>> {
    static FUNCTIONS: OnceLock<arinsal_term::FrequentReadRwLock<Vec<NativeFunction>>> =
        OnceLock::new();
    FUNCTIONS.get_or_init(|| arinsal_term::FrequentReadRwLock::new(Vec::new()))
}

fn native_generation() -> &'static AtomicU64 {
    static GENERATION: AtomicU64 = AtomicU64::new(0);
    &GENERATION
}

/// One catch-table slot. Native handlers are code addresses; interpreted handlers are a
/// module id and an instruction index. Slots stay in the published table until the module
/// is purged (`beam_catches_delmod`).
#[derive(Clone, Copy, Debug)]
pub(crate) enum CatchTarget {
    Native(usize),
    Interpreted { module: usize, ip: usize },
}

/// Code scope of `process`, or 0 when it has no node.
pub(crate) fn process_code_scope(process: &Process) -> u64 {
    process
        .runtime
        .as_ref()
        .map(|runtime| runtime.code_scope)
        .unwrap_or(0)
}

fn catch_indexes(scope: u64) -> std::sync::Arc<crate::code_ix::CodeIndexes> {
    crate::code_ix::for_scope(scope)
}

/// Port of erts/emulator/beam/beam_catches.c:146 (`beam_catches_car`), OTP-29.1.1.
/// Indexes `bccix[erts_active_code_ix()]`. The active index is the node's atomic.
fn catch_slot(scope: u64, index: u32) -> Option<CatchTarget> {
    crate::code_ix::for_scope(scope)
        .with_active_catches(|table| table.get(usize::try_from(index).ok()?).copied().flatten())
}

/// Publishes `change` into the listed code indexes. Readers keep the previous `Arc`.
fn publish_catches(scope: u64, indexes: &[usize], change: impl Fn(&mut Vec<Option<CatchTarget>>)) {
    let code = catch_indexes(scope);
    let _publish = code.lock_catch_publish();
    let mut seen = [false; arinsal_term::ERTS_NUM_CODE_IX];
    for &index in indexes {
        if index >= arinsal_term::ERTS_NUM_CODE_IX || seen[index] {
            continue;
        }
        seen[index] = true;
        let mut table = code.catch_table_at(index).as_ref().clone();
        change(&mut table);
        code.store_catch_table(index, table);
    }
}

fn place_catch(table: &mut Vec<Option<CatchTarget>>, index: u32, target: CatchTarget) {
    let Some(index) = usize::try_from(index).ok() else {
        return;
    };
    if table.len() <= index {
        table.resize(index + 1, None);
    }
    table[index] = Some(target);
}

/// Whether a stack word is a catch tag registered by native code (`catch`/`try` in a BeamAsm
/// frame), whose handler only `next_catch` can resolve.
pub(crate) fn is_native_catch_tag(scope: u64, word: Term) -> bool {
    let raw = word.tagged_word();
    raw & 63 == 0x1b
        && u32::try_from(raw >> 6)
            .is_ok_and(|index| matches!(catch_slot(scope, index), Some(CatchTarget::Native(_))))
}

pub(crate) fn register_native_catches(scope: u64, base: u32, handlers: &[*const u8]) -> Vec<u32> {
    let ids = (0..handlers.len())
        .filter_map(|offset| u32::try_from(offset).ok()?.checked_add(base))
        .collect::<Vec<_>>();
    // Port of erts/emulator/beam/beam_catches.c:108-143 (`beam_catches_cons` writes the
    // staging pool), OTP-29.1.1. The commit that ends this staging area makes that pool active.
    let staging = catch_indexes(scope).staging();
    publish_catches(scope, &[staging], |table| {
        for (&id, handler) in ids.iter().zip(handlers) {
            place_catch(table, id, CatchTarget::Native(*handler as usize));
        }
    });
    ids
}

pub(crate) fn unregister_native_catches(scope: u64, ids: &[u32]) {
    // A purged module's handlers must not stay reachable from any code index still published.
    let all = [0, 1, 2];
    publish_catches(scope, &all, |table| {
        for id in ids {
            if let Ok(index) = usize::try_from(*id)
                && let Some(slot) = table.get_mut(index)
            {
                *slot = None;
            }
        }
    });
}

pub(crate) fn register_interpreted_catch(scope: u64, index: u32, module: usize, ip: usize) {
    // Interpreter catches are installed while code runs, so the active table has to see
    // them immediately. An open staging area copied the table at its start and would drop
    // the slot at commit unless it is published there too.
    let code = catch_indexes(scope);
    let active = code.active();
    let staging = code.staging();
    publish_catches(scope, &[active, staging], |table| {
        place_catch(table, index, CatchTarget::Interpreted { module, ip });
    });
}

pub(crate) fn interpreted_catch(scope: u64, index: u32) -> Option<(usize, usize)> {
    match catch_slot(scope, index)? {
        CatchTarget::Interpreted { module, ip } => Some((module, ip)),
        CatchTarget::Native(_) => None,
    }
}

/// Native handler address of a catch-table index, if it names native code.
pub(crate) fn native_catch(scope: u64, index: u32) -> Option<usize> {
    match catch_slot(scope, index)? {
        CatchTarget::Native(address) => Some(address),
        CatchTarget::Interpreted { .. } => None,
    }
}

pub(crate) enum CatchHandler {
    Native(usize),
    Interpreted,
}

/// A catch the scan found. The stack is unchanged until [`commit_catch`].
#[derive(Clone, Copy)]
pub(crate) struct LocatedCatch {
    /// Stack index of the catch tag.
    index: usize,
    /// Stack index `E` resumes at: the catching frame's first Y slot.
    resume: usize,
    target: CatchTarget,
    /// An exception-trace frame sits above the catch. The scheduler unwind emits
    /// `exception_from` for those frames; the native resolver leaves them to it.
    /// Word-sized on purpose: a trailing `bool` made the compiler move this struct with
    /// overlapping sub-word copies, which stall on store-to-load forwarding at ~25 ns a raise.
    traced: usize,
}

/// Port of erts/emulator/beam/beam_common.c:580-648 (`next_catch` up to `found_catch`),
/// OTP-29.1.1. The scan only reads the stack and the active catch table. It does not move
/// `stop`, so a miss leaves the scheduler's unwind the same stack erts would walk.
fn locate_catch(process: &mut Process, native_only: bool) -> Option<LocatedCatch> {
    if process.header.catches == 0 {
        return None;
    }
    let heap = &process.heap;
    if let (Some(runtime), Some(cold)) = (process.runtime.as_ref(), process.cold.as_mut()) {
        let table = runtime
            .code_indexes()
            .active_catches_cached(&mut cold.catch_cache);
        return scan_catch(heap, table, native_only);
    }
    if let Some(runtime) = process.runtime.as_ref() {
        return runtime.with_active_catches(|table| scan_catch(heap, table, native_only));
    }
    crate::code_ix::for_scope(process_code_scope(process))
        .with_active_catches(|table| scan_catch(heap, table, native_only))
}

fn scan_catch(
    heap: &arinsal_term::ProcessHeap,
    table: &[Option<CatchTarget>],
    native_only: bool,
) -> Option<LocatedCatch> {
    let mut stack = heap.stack_terms().enumerate();
    let mut previous_cp = 0usize;
    let mut seen_cp = false;
    let mut traced = 0usize;
    while let Some((index, word)) = stack.next() {
        let raw = word.tagged_word();
        let address = raw as usize;
        if address == native_trace_return_address() {
            traced = 1;
            let actions = heap
                .stack_get(index + 3)
                .and_then(Term::as_small)
                .and_then(|count| usize::try_from(count).ok())
                .unwrap_or(0);
            let words = 4usize.saturating_add(actions.saturating_mul(2));
            // The whole trace frame sits below the catching frame's Y slots.
            previous_cp = index + words - arinsal_term::CP_WORDS;
            seen_cp = true;
            for _ in 1..words {
                if stack.next().is_none() {
                    break;
                }
            }
            continue;
        }
        // Port of erl_term.h:1378-1379 (`is_CP`), OTP-29.1.1.
        if arinsal_term::is_cp(raw) {
            previous_cp = index;
            seen_cp = true;
            for _ in 0..arinsal_term::CP_WORDS.saturating_sub(1) {
                stack.next();
            }
            continue;
        }
        if raw & 63 == 0x1b
            && let Some(catch_index) = u32::try_from(raw >> 6).ok()
            && let Some(target) = usize::try_from(catch_index)
                .ok()
                .and_then(|slot| table.get(slot).copied().flatten())
        {
            if native_only && !matches!(target, CatchTarget::Native(_)) {
                continue;
            }
            // Both native and interpreted frames keep the caller-pushed CP above their Y slots
            // (a call pushes the CP, `allocate` then reserves the Y slots below it), so the
            // resumed E is the first Y slot after the last CP below the catch, or the stack top
            // when the catching frame is the topmost one.
            let resume = if seen_cp {
                previous_cp + arinsal_term::CP_WORDS
            } else {
                0
            };
            return Some(LocatedCatch {
                index,
                resume,
                target,
                traced,
            });
        }
        if crate::stacktrace::decode_tag(word).is_some_and(|(handler, _, _)| !handler) {
            previous_cp = index;
            seen_cp = true;
            for _ in 0..arinsal_term::CP_WORDS.saturating_sub(1) {
                stack.next();
            }
        }
    }
    None
}

/// Find the nearest catch without moving the stack cursor; only native handlers resume here.
// Port of erts/emulator/beam/beam_common.c (`next_catch`), OTP-29.1.1.
pub(crate) fn next_native_catch(process: &mut Process) -> Option<LocatedCatch> {
    let found = locate_catch(process, false)?;
    (found.traced == 0 && matches!(found.target, CatchTarget::Native(_))).then_some(found)
}

fn exception_class_atom(class: arinsal_bifs::Class) -> Term {
    // erts `exception_tag[]` (beam_common.c). These atoms are predefined; interning them
    // on every throw is not part of the catch path.
    let atom = match class {
        arinsal_bifs::Class::Error => arinsal_term::atoms::ERROR,
        arinsal_bifs::Class::Exit => arinsal_term::atoms::EXIT,
        arinsal_bifs::Class::Throw => arinsal_term::atoms::THROW,
    };
    Term::atom(atom)
}

pub(crate) fn next_catch(
    process: &mut Process,
    class: arinsal_bifs::Class,
    reason: Term,
    trace: Term,
    native_only: bool,
) -> Option<CatchHandler> {
    let found = locate_catch(process, native_only)?;
    // An exception-trace frame above the catch is emitted by the scheduler unwind
    // (`exception_from`). erts does that inside `next_catch` before `found_catch`.
    // The native resolver has no trace session, so it leaves the stack unmoved.
    if native_only && found.traced != 0 {
        return None;
    }
    Some(commit_catch(process, found, class, reason, trace))
}

/// Port of erts/emulator/beam/beam_common.c:650-678 (`found_catch`), OTP-29.1.1.
/// The stack and catch tag are changed only after the target is known.
pub(crate) fn commit_catch(
    process: &mut Process,
    found: LocatedCatch,
    class: arinsal_bifs::Class,
    reason: Term,
    trace: Term,
) -> CatchHandler {
    // Port of erts/emulator/beam/beam_common.c:650-678 (`found_catch`): `stop` and the catch
    // word are written only after the handler is known.
    process.heap.stack_set(found.index, Term::NIL);
    let base = process.heap.heap_cursor().1;
    process
        .heap
        .set_stack_pointer(base.wrapping_add(found.resume));
    process.x.ensure_x(4);
    // Port of erts/emulator/beam/beam_common.c (handle_error), OTP-29.1.1:
    // x0 = non-value marker, x1 = reason, x2 = raw stacktrace, x3 = class.
    process.x[0] = Term::catch(0);
    process.x[1] = reason;
    process.x[2] = trace;
    process.x[3] = exception_class_atom(class);
    process.exc_class = Some(class);
    // Port of erts/emulator/beam/beam_common.c (handle_error), OTP-29.1.1.
    // The catch registers own the expanded reason and raw trace now, so stale native error
    // metadata must not survive this transfer.
    process.header.freason = 0;
    process.header.fvalue = Term::NIL.tagged_word();
    if let Some(cold) = process.cold.as_mut() {
        cold.native_bif_error = None;
        cold.native_trap = None;
        cold.pending_trace_top = None;
        cold.explicit_raise = None;
    }
    process.sync_native_header();
    match found.target {
        CatchTarget::Native(handler) => {
            process.native_continuation_resume = true;
            process.set_native_resume_arity(4);
            CatchHandler::Native(handler)
        }
        CatchTarget::Interpreted { module, ip } => {
            process.module = module;
            process.ip = ip;
            CatchHandler::Interpreted
        }
    }
}

fn register_bridge_continuation() -> Result<(), &'static str> {
    static REGISTERED: OnceLock<Result<(), &'static str>> = OnceLock::new();
    *REGISTERED.get_or_init(|| {
        let address = arinsal_beamasm::rt::arinsal_enter_native_return as *const () as usize;
        arinsal_term::register_native_code_range(address, address + 4)?;
        let trace_return =
            arinsal_beamasm::rt::arinsal_enter_native_trace_return as *const () as usize;
        arinsal_term::register_native_code_range(trace_return, trace_return + 4)
    })
}

/// The native exit bridge: the return address of a call without a native caller, erts'
/// `beam_normal_exit`.
pub(crate) fn bridge_return_address() -> usize {
    arinsal_beamasm::rt::arinsal_enter_native_return as *const () as usize
}

/// Push the exit bridge as the only stack word of a process the interpreter runs from its
/// first call, the way erts starts every process with `beam_normal_exit` as its return
/// address: `process_info` then counts and prints the terminate frame, and the entry
/// function's return pops it into the process exit.
pub(crate) fn push_exit_bridge(process: &mut Process) {
    if register_bridge_continuation().is_err() || !process.heap.reserve_stack(1) {
        return;
    }
    process.heap.stack_set(
        0,
        crate::proc_create::native_continuation_term(bridge_return_address()),
    );
}

pub(crate) fn native_trace_return_address() -> usize {
    arinsal_beamasm::rt::arinsal_enter_native_trace_return as *const () as usize
}

/// Register a native code range for GC continuation recognition and stack traces.
pub fn register_native_function(info: NativeFunction) -> Result<(), &'static str> {
    if info.start >= info.end {
        return Err("native code range must be non-empty");
    }
    let start = info.start;
    arinsal_term::register_native_code_range(info.start, info.end)?;
    let mut functions = native_functions().write();
    // The registry stays sorted by start: only the neighbours can overlap.
    let index = functions.partition_point(|function| function.start < info.start);
    let overlaps_previous = index
        .checked_sub(1)
        .and_then(|previous| functions.get(previous))
        .is_some_and(|previous| info.start < previous.end);
    let overlaps_next = functions
        .get(index)
        .is_some_and(|next| next.start < info.end);
    if overlaps_previous || overlaps_next {
        return Err("native function ranges must not overlap");
    }
    update_perf_map(&info);
    functions.insert(index, info);
    publish_function_range(&functions[index]);
    if crate::native_bridge::lifetime_trace_enabled() {
        let function = functions
            .iter()
            .find(|function| function.start == start)
            .expect("registered native function is present");
        eprintln!(
            "[beamasm-lifetime] native register {}/{}:{} range={:#x}..{:#x}",
            function.module, function.function, function.arity, function.start, function.end
        );
    }
    native_generation().fetch_add(1, Ordering::Release);
    Ok(())
}

/// Unregisters native function entries when their owning module version is purged.
pub(crate) fn unregister_native_functions(entries: &[NativeFunction]) {
    let mut functions = native_functions().write();
    let before = functions.len();
    functions.retain(|registered| !entries.contains(registered));
    for entry in entries {
        arinsal_term::unregister_native_code_range(entry.start, entry.end);
        unpublish_function_range(entry);
    }
    let removed = before - functions.len();
    if removed == 0 {
        return;
    }
    if crate::native_bridge::lifetime_trace_enabled() {
        for entry in entries {
            eprintln!(
                "[beamasm-lifetime] native unregister {}/{}:{} range={:#x}..{:#x}",
                entry.module, entry.function, entry.arity, entry.start, entry.end
            );
        }
    }
    native_generation().fetch_add(1, Ordering::Release);
}

/// Unregisters scoped native entries when their owning VM code scope is released.
pub(crate) fn unregister_native_scope(scope: u64) {
    if scope == 0 {
        return;
    }
    let mut functions = native_functions().write();
    let mut removed = Vec::new();
    functions.retain(|function| {
        if function.scope == scope {
            removed.push(function.clone());
            false
        } else {
            true
        }
    });
    for function in &removed {
        arinsal_term::unregister_native_code_range(function.start, function.end);
        unpublish_function_range(function);
    }
    native_generation().fetch_add(1, Ordering::Release);
}

pub(crate) fn native_registry_generation() -> u64 {
    native_generation().load(Ordering::Acquire)
}

/// Runtime hook for native code to raise a BEAM exception through the scheduler.
/// Class values are 1 (`error`), 2 (`exit`), and 3 (`throw`).
///
/// # Safety
/// `header` must point to the active process header for the current native frame.
pub unsafe extern "C" fn arinsal_native_raise(header: *mut ProcessHeader, class: u64, reason: u64) {
    if header.is_null() || !(1..=3).contains(&class) {
        return;
    }
    // SAFETY: Native code passes the active ProcessHeader in x21 for this hook.
    let header = unsafe { &mut *header };
    header.freason = class;
    header.fvalue = reason;
}

/// Find metadata for a native instruction or continuation address.
pub fn native_function_at(address: usize) -> Option<NativeFunction> {
    if !arinsal_term::may_be_native_code_pointer(address) {
        return None;
    }
    let functions = native_functions().read();
    let index = functions.partition_point(|function| function.start <= address);
    functions
        .get(index.checked_sub(1)?)
        .filter(|function| address < function.end)
        .cloned()
}

/// Runs `visit` on the native function containing `address` without cloning its metadata.
/// `visit` runs under the registry read lock and must not register or unregister code.
pub(crate) fn with_native_function_at<R>(
    address: usize,
    visit: impl FnOnce(&NativeFunction) -> R,
) -> Option<R> {
    if !arinsal_term::may_be_native_code_pointer(address) {
        return None;
    }
    let functions = native_functions().read();
    let index = functions.partition_point(|function| function.start <= address);
    functions
        .get(index.checked_sub(1)?)
        .filter(|function| address < function.end)
        .map(visit)
}

/// Test native code membership without cloning function metadata.
pub(crate) fn is_native_function_at(address: usize) -> bool {
    if !arinsal_term::may_be_native_code_pointer(address) {
        return false;
    }
    let functions = native_functions().read();
    let index = functions.partition_point(|function| function.start <= address);
    let Some(function) = index.checked_sub(1).and_then(|index| functions.get(index)) else {
        return false;
    };
    address < function.end
}

/// A word the interpreter returns into by continuing native code: a native return address, or
/// the stub of a traced native function's return frame.
pub(crate) fn is_native_continuation(address: usize) -> bool {
    address == native_trace_return_address() || is_native_function_at(address)
}

pub(crate) fn native_stack_frame_at(address: usize) -> Option<NativeStackFrame> {
    if !arinsal_term::may_be_native_code_pointer(address) {
        return None;
    }
    let functions = native_functions().read();
    let index = functions.partition_point(|function| function.start <= address);
    let function = functions
        .get(index.checked_sub(1)?)
        .filter(|function| address < function.end)?;
    let line = function
        .line_table
        .partition_point(|entry| entry.address <= address)
        .checked_sub(1)
        .and_then(|index| function.line_table.get(index))
        .filter(|entry| entry.line != 0);
    let file_term = line.and_then(|entry| entry.file_term);
    // `fi->fname_ptr[file]` is a literal. The string is only needed when it is absent.
    let file = line
        .filter(|_| file_term.is_none())
        .map(|entry| Arc::clone(&entry.file));
    Some(NativeStackFrame {
        module_atom: function.module_atom,
        function_atom: function.function_atom,
        arity: function.arity,
        line: line.map(|entry| entry.line),
        file_term,
        file,
    })
}

/// Every registered native function of `module`, keyed by name and arity, restricted to the
/// module version whose native code spans `range` when one is given.
// The registry holds every loaded version (current and old) ordered by address, so the
// version must be selected before the entries collapse into one per name and arity: a newer
// version placed below the old one in memory would otherwise lose its entries to the old ones.
pub(crate) fn native_functions_of(
    scope: u64,
    module: &str,
    range: Option<(usize, usize)>,
) -> std::collections::HashMap<(String, u8), NativeFunction> {
    let functions = native_functions().read();
    let in_version = |entry: &&NativeFunction| {
        entry.module == module
            && range.is_none_or(|(start, end)| start <= entry.start && entry.start < end)
    };
    let mut scoped = functions
        .iter()
        .filter(|entry| entry.scope == scope)
        .filter(in_version)
        .map(|entry| ((entry.function.clone(), entry.arity), entry.clone()))
        .collect::<std::collections::HashMap<_, _>>();
    if scope != 0 {
        for entry in functions
            .iter()
            .filter(|entry| entry.scope == 0)
            .filter(in_version)
        {
            scoped
                .entry((entry.function.clone(), entry.arity))
                .or_insert_with(|| entry.clone());
        }
    }
    scoped
}

pub(crate) fn native_function_for(
    scope: u64,
    module: &str,
    function: &str,
    arity: u8,
) -> Option<NativeFunction> {
    native_functions()
        .read()
        .iter()
        .find(|entry| {
            (entry.scope == scope || entry.scope == 0)
                && entry.module == module
                && entry.function == function
                && entry.arity == arity
        })
        .cloned()
}

/// Enter one native function and commit its ABI state before returning to the scheduler.
///
/// `CallUnported` returns to the scheduler with the interpreter target in `process.ip`;
/// a later native continuation is resumed by calling this function at its saved PC.
// Port of erts/emulator/beam/jit/arm/process_main.cpp:235-317, OTP-29.1.1
pub fn run_native(
    process: &mut Process,
    registers: &mut SchedulerRegisters,
    code_address: usize,
) -> Result<ExitReason, VmError> {
    debug_assert!(
        process.x.is_attached(),
        "native code runs on the scheduler's X array: attach the registers first"
    );
    // Debug knobs are environment switches held in one byte: read once per entry.
    let debug = crate::debug_env::slice::get();
    let return_trace = debug & crate::debug_env::slice::RETURN_TRACE != 0;
    let exception_trace = debug & crate::debug_env::slice::EXCEPTION_TRACE != 0;
    let lifetime_trace = debug & crate::debug_env::slice::LIFETIME_TRACE != 0;
    if debug & crate::debug_env::slice::BRIDGE_REGISTERED == 0 {
        register_bridge_continuation().map_err(|error| VmError::Unsupported(error.into()))?;
        crate::debug_env::slice::set_bridge_registered();
    }
    if return_trace && let Some(function) = native_function_at(code_address) {
        eprintln!(
            "[native-before-ensure] {}:{}/{} x0={:#x}",
            function.module,
            function.function,
            function.arity,
            process.x[0].tagged_word()
        );
    }
    process.native_error_pc = 0;
    registers.tmp_mem[6] = 0;
    registers.tmp_mem[5] =
        crate::native_helpers::arinsal_beamasm_native_trace_return as *const () as usize as u64;
    let resuming_continuation = std::mem::take(&mut process.native_continuation_resume);
    // A resumed call return has only x0 live and an exception handler x0..x3, whatever
    // the arity of the function the native code belongs to.
    let arity_set = std::mem::take(&mut process.native_arity_set);
    // Port of erts/emulator/beam/erl_process.c:10550 and jit/arm/process_main.cpp (a process
    // resumes with the `c_p->arity` live registers its yield site saved), OTP-29.1.1: only a
    // call entry needs the function's arity from the code registry.
    // One registry lookup gives both the arity of a call entry and whether the address
    // starts a function.
    let function = (!arity_set || !resuming_continuation)
        .then(|| {
            with_native_function_at(code_address, |function| {
                (function.arity, function.start == code_address)
            })
        })
        .flatten();
    let arity = if arity_set {
        process.header.arity
    } else {
        function.map(|(arity, _)| arity).ok_or_else(|| {
            VmError::Unsupported(format!("unregistered native entry: {code_address:#x}"))
        })?
    };
    let live = usize::from(arity);
    // erts does no collection at swap-in (process_main restores the registers and jumps); the
    // heap invariant `HTOP + S_RESERVED <= E` is all native code needs on entry, and `ensure`
    // already demands S_RESERVED while the heap is native. A later instruction that really needs
    // heap collects inside the callee, with the callee's continuation word on the stack. Asking
    // for more here collected at resume, one stack word and one collection away from erts.
    // Port of erts/emulator/beam/erl_process.h (HEAP_LIMIT), OTP-29.1.1: erts allocates below
    // `E - S_REDZONE`, so native code always finds room to push its continuation. The
    // interpreter allocates up to the stack pointer; entering native code arms the redzone
    // first so the check below leaves it free.
    process.heap.arm_native_redzone();
    process.ensure_entry(0, live)?;
    // Port of erts/emulator/beam/jit/arm/instr_call.cpp:256-261 (emit_i_apply_only),
    // OTP-29.1.1: a call the scheduler performs for native code (fun/apply, BIF traps,
    // breakpoint handlers) pops the caller's continuation into LR, so the callee's frame
    // holds that one CP. With no native caller (a new process) LR is the exit bridge,
    // erts' `beam_normal_exit`.
    registers.entry_return = 0;
    if !resuming_continuation
        && function.is_some_and(|(_, starts)| starts)
        && let Some(word) = process.heap.stack_get(0)
    {
        let raw = word.tagged_word() as usize;
        if raw == bridge_return_address() || is_native_continuation(raw) {
            process.heap.release_stack(1);
            registers.entry_return = raw as u64;
        }
    }
    let code_ptr = code_address as *const std::ffi::c_void;
    if return_trace && let Some(function) = native_function_at(code_address) {
        eprintln!(
            "[native-enter] {}:{}/{} pc={code_address:#x} x0={:#x} freason={:#x}",
            function.module,
            function.function,
            function.arity,
            process.x[0].tagged_word(),
            process.header.freason
        );
    }
    process.sync_header();
    // Port of erts/emulator/beam/beam_common.c:2394 (`erts_current_reductions`), OTP-29.1.1:
    // `REDS_IN` is FCALLS at slice entry. `process_info(reductions)` adds what this
    // slice has consumed before the scheduler folds it into `reductions_used`.
    process.native_reds_in = process.header.fcalls;
    process.header.i = code_ptr;
    process.header.arity = arity;
    if let Some(cold) = process.cold.as_mut() {
        cold.native_bif_error = None;
        cold.native_trap = None;
    }
    let saved_ftrace = process.header.ftrace;
    process.header.ftrace = (registers as *mut SchedulerRegisters).cast();
    registers.tmp_mem[3] = 0;
    process.heap.set_native_allocation(true);
    // The scheduler set `esdp->current_process` when it scheduled the process in
    // (Executor::run), so the NIF services native code calls already see this process.
    if lifetime_trace {
        eprintln!(
            "[beamasm-lifetime] enter code={code_address:#x} owner={}",
            crate::beamasm_integration::owns_native_address(code_address)
        );
    }
    // Native hooks add their thread-local context setup here; keep this bridge
    // entry call structurally isolated from that setup.
    // SAFETY: The caller supplies a registered executable function using the BeamAsm ABI.
    let exit =
        unsafe { arinsal_beamasm::enter_native_raw(&mut process.header, registers, code_ptr) };
    process.heap.set_native_allocation(false);
    let native_ftrace = process.header.ftrace as u64;
    process.header.ftrace = saved_ftrace;
    if exception_trace {
        let (base, end) = process.heap.heap_bounds();
        let (_, current_stop) = process.heap.heap_cursor();
        let requested_stop = process.header.stop as usize;
        if requested_stop < base as usize || requested_stop > end as usize {
            let module = native_function_at(code_address)
                .map_or_else(|| "?".to_owned(), |function| function.module);
            eprintln!(
                "native return stack pointer out of range module={} pc={code_address:#x} exit={exit:?} base={base:p} end={end:p} current_stop={current_stop:p} requested_stop={:#x} htop={:p}",
                module, requested_stop, process.header.htop
            );
        }
    }
    // Native returns may release stack slots and allocate into the newly freed gap.
    process.heap.set_stack_pointer(process.header.stop);
    process.heap.set_heap_top(process.header.htop);
    process.reductions = process.header.fcalls;
    if return_trace && let Some(function) = native_function_at(code_address) {
        eprintln!(
            "[native-exit] {}:{}/{} pc={code_address:#x} exit={exit:?} x0={:#x} i={:p} stop={:p}",
            function.module,
            function.function,
            function.arity,
            process.x[0].tagged_word(),
            process.header.i,
            process.header.stop
        );
    }
    // Port of erts/emulator/beam/jit/arm/instr_bif.cpp:533-540, OTP-29.1.1.
    // A VM-backed light BIF leaves TRAP for the scheduler when it exits native code.
    // A call handed to the scheduler keeps its call site too, for a BIF that raises there.
    if process.header.freason != 0 || matches!(exit, ExitReason::CallUnported { .. }) {
        process.native_error_pc = registers.tmp_mem[6] as usize;
    }
    if process.header.freason != 0 && process.header.freason != 1 << 10 && exception_trace {
        eprintln!(
            "native exception freason={:#x} fvalue={:?} at {:?}",
            process.header.freason,
            arinsal_term::to_owned(crate::native_hooks::from_raw(process.header.fvalue))
                .map(|term| format!("{term}").chars().take(200).collect::<String>()),
            native_function_at(registers.tmp_mem[6] as usize).map(|function| format!(
                "{}:{}/{} +{:#x}",
                function.module,
                function.function,
                function.arity,
                registers.tmp_mem[6] as usize - function.start
            ))
        );
    }
    // Port of erts/emulator/beam/beam_common.c (handle_error), OTP-29.1.1:
    // save the raw trace before reducing the failure state to its primary class or clearing it.
    let trapped_bif =
        process.header.freason == 1 << 10 && matches!(exit, ExitReason::CallUnported { .. });
    if trapped_bif {
        process.header.freason = 0;
    } else if process.header.freason == arinsal_beamasm::module::EXC_FUNCTION_CLAUSE {
        // Port of erts/emulator/beam/beam_common.c (save_stacktrace, EXC_FUNCTION_CLAUSE):
        // the top frame carries the current function's arguments.
        process.header.freason = 0;
        let arity = native_function_at(registers.tmp_mem[6] as usize)
            .map_or(0, |function| usize::from(function.arity));
        let args = process.x[..arity].to_vec();
        if exception_trace {
            eprintln!(
                "native function_clause in {:?} args={:?}",
                native_function_at(registers.tmp_mem[6] as usize)
                    .map(|f| format!("{}:{}/{}", f.module, f.function, f.arity)),
                args.iter()
                    .map(|arg| format!("{:#x}", arg.tagged_word()))
                    .collect::<Vec<_>>()
            );
        }
        let args = arinsal_term::TermBuilder::new(&mut crate::ProcessHeapHandle(&mut process.heap))
            .list_from_iter(args)
            .map_err(|error| VmError::Unsupported(format!("function_clause args {error:?}")))?;
        let mut trap = exceptions::native_trap(1, process.header.fvalue)?;
        trap.top = Some(crate::stacktrace::TopFrame::CurrentArgs(args));
        return Err(VmError::Trap(trap));
    } else if process.header.freason != 0
        && let Some(raised) = process
            .cold
            .as_mut()
            .and_then(|cold| cold.native_trap.take())
        && raised.freason == process.header.freason
        && raised.fvalue == process.header.fvalue
    {
        return Err(VmError::Trap(raised.trap));
    } else if process.header.freason != 0
        && let Some(failure) = process
            .cold
            .as_mut()
            .and_then(|cold| cold.native_bif_error.take())
        && failure.freason == process.header.freason
        && failure.fvalue == process.header.fvalue
    {
        // `save_raw` also matches the pending BIF frame against this reason/value pair.
        let error = match failure.call {
            crate::proc_create::NativeBifCall::Export(export) => {
                let args = process.x[..usize::from(export.arity)].to_vec();
                exceptions::bif_error(
                    process,
                    &export.module,
                    &export.function,
                    &args,
                    failure.error,
                )
            }
            crate::proc_create::NativeBifCall::Registers {
                module,
                function,
                arity,
            } => {
                let module = arinsal_term::global_atoms()
                    .text(module)
                    .unwrap_or("erlang");
                let function = arinsal_term::global_atoms().text(function).unwrap_or("+");
                let args = process.x[..usize::from(arity)].to_vec();
                exceptions::bif_error(process, module, function, &args, failure.error)
            }
            crate::proc_create::NativeBifCall::Owned {
                module,
                function,
                args,
            } => exceptions::bif_error(process, &module, &function, &args, failure.error),
        };
        return Err(error);
    } else if process.header.freason != 0 && registers.tmp_mem[7] != 0 {
        // Port of erts/emulator/beam/jit/arm/beam_asm_global.cpp (emit_raise_badarg): an inline
        // BIF failure names the BIF, with its arguments from X0.., as the top frame.
        let slot = std::mem::take(&mut registers.tmp_mem[7]) as usize;
        let (module, function, arity) = arinsal_beamasm::guard::BADARG_MFAS[slot - 1];
        let args = process.x[..usize::from(arity)].to_vec();
        let tag = match process.header.freason {
            arinsal_beamasm::guard::EXC_BADMAP => Some("badmap"),
            arinsal_beamasm::guard::EXC_BADKEY => Some("badkey"),
            _ => None,
        };
        let error = if let Some(tag) = tag {
            let value = crate::native_hooks::from_raw(process.header.fvalue);
            let reason =
                arinsal_term::TermBuilder::new(&mut crate::ProcessHeapHandle(&mut process.heap))
                    .tuple(&[crate::signals::atom(tag), value])
                    .map_err(|error| VmError::Unsupported(format!("{tag} {error:?}")))?;
            arinsal_bifs::BifError::Error(reason)
        } else {
            arinsal_bifs::BifError::BADARG
        };
        process.header.freason = 0;
        return Err(exceptions::bif_error(
            process, module, function, &args, error,
        ));
    } else if process.header.freason
        & (arinsal_beamasm::catch::RAW_RAISE | arinsal_beamasm::catch::RERAISE)
        != 0
    {
        // Port of erts/emulator/beam/beam_common.c:1148-1178 (raw_raise) and the i_raise
        // instruction, OTP-29.1.1: both re-raise the stacktrace in `c_p->ftrace`.
        let raw_rethrow = process.header.freason & arinsal_beamasm::catch::RAW_RAISE != 0;
        let class = match process.header.freason & 3 {
            1 => arinsal_bifs::Class::Error,
            2 => arinsal_bifs::Class::Exit,
            _ => arinsal_bifs::Class::Throw,
        };
        process.header.freason = 0;
        let trace = crate::native_hooks::from_raw(native_ftrace);
        if raw_rethrow {
            // raw_raise stores the new class in the stacktrace too, so a later i_raise of
            // the same trace keeps it. The compiler only passes stacktraces here.
            crate::stacktrace::set_raw_class(process, trace, class);
        }
        return Err(VmError::Trap(exceptions::Trap {
            class,
            reason: crate::native_hooks::from_raw(process.header.fvalue),
            trace: Some(trace),
            top: None,
            raw_rethrow,
            untrappable: false,
        }));
    } else if process.header.freason > 3 && process.header.freason & 0x3ff == 0x50 {
        // Port of erts/emulator/beam/beam_common.c:742-775 (expand_error_value), OTP-29.1.1.
        let index = process.header.freason >> 10;
        process.header.freason = 0;
        let value = crate::native_hooks::from_raw(process.header.fvalue);
        let tag = match index {
            5 => "badmatch",
            7 => "case_clause",
            8 => "if_clause",
            16 => "try_clause",
            19 => "badkey",
            20 => "badrecord",
            _ => {
                return Err(VmError::Unsupported(format!(
                    "native exception index {index}"
                )));
            }
        };
        let tag = crate::signals::atom(tag);
        let reason = if index == 8 {
            tag
        } else {
            arinsal_term::TermBuilder::new(&mut crate::ProcessHeapHandle(&mut process.heap))
                .tuple(&[tag, value])
                .map_err(|error| VmError::Unsupported(format!("error value {error:?}")))?
        };
        return Err(VmError::Trap(exceptions::native_trap(
            1,
            crate::native_hooks::raw(reason),
        )?));
    } else if process.header.freason != 0 {
        let class = process.header.freason;
        let reason = process.header.fvalue;
        let mut trap = exceptions::native_trap(class, reason)?;
        if let Some(info) = process
            .cold
            .as_mut()
            .and_then(|cold| cold.native_error_info.take())
        {
            let arity = native_function_at(registers.tmp_mem[6] as usize)
                .map_or(0, |function| i64::from(function.arity));
            trap.top = Some(crate::stacktrace::TopFrame::CurrentArgsWithInfo(
                Term::small(arity),
                info,
            ));
        }
        return Err(VmError::Trap(trap));
    }
    let outcome = match exit {
        ExitReason::CallUnported { .. } => {
            process.native_pc = None;
            exit
        }
        ExitReason::Yield => {
            let resume = process.header.i as usize;
            let bridge_return =
                arinsal_beamasm::rt::arinsal_enter_native_return as *const () as usize;
            if resume == bridge_return {
                // The native function has returned into the exit bridge: the normal
                // return path continues with what lies below (an interpreter caller,
                // or nothing when the process is done).
                process.native_pc = None;
                ExitReason::Returned
            } else {
                process.native_continuation_resume = true;
                // The yield site stored its live X register count in `c_p->arity`.
                process.native_arity_set = true;
                process.gc_live = usize::from(process.header.arity);
                process.native_pc = Some(if resume == 0 {
                    code_ptr as usize
                } else {
                    resume
                });
                ExitReason::Yield
            }
        }
        ExitReason::Returned => {
            process.native_pc = None;
            ExitReason::Returned
        }
        ExitReason::Unsupported => {
            process.native_pc = None;
            ExitReason::Unsupported
        }
    };
    Ok(outcome)
}

/// `ARINSAL_BEAMASM_RETURN_TRACE`: log native entries and exits.
#[inline]
pub(crate) fn return_trace_enabled() -> bool {
    crate::debug_env::slice::get() & crate::debug_env::slice::RETURN_TRACE != 0
}

/// Install a SIGSEGV dump when `ARINSAL_CRASH_DUMP=1`.
///
/// The dump records the faulting native function and whether the tuple in x25
/// sits in the live young heap, the free gap, or the stack. It is off unless
/// the variable is set, so ordinary runs do not install a handler.
pub fn install_crash_dump() {
    if std::env::var_os("ARINSAL_CRASH_DUMP").as_deref() != Some(std::ffi::OsStr::new("1")) {
        return;
    }
    // SAFETY: sigemptyset initializes the mask. sa_sigaction is the three-argument
    // handler selected by SA_SIGINFO (0x40, Darwin <signal.h>). The handler only
    // writes a file and reads the faulting thread's registers and the process header.
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        if libc::sigemptyset(&mut action.sa_mask) != 0 {
            return;
        }
        action.sa_flags = 0x40;
        action.sa_sigaction = crash_dump_handler as *const () as libc::sighandler_t;
        libc::sigaction(libc::SIGSEGV, &action, std::ptr::null_mut());
    }
}

extern "C" fn crash_dump_handler(
    _sig: libc::c_int,
    _info: *mut libc::c_void,
    ctx: *mut libc::c_void,
) {
    use std::sync::atomic::{AtomicBool, Ordering};
    static DUMPING: AtomicBool = AtomicBool::new(false);
    if DUMPING.swap(true, Ordering::Relaxed) || ctx.is_null() {
        return;
    }
    // SAFETY: SA_SIGINFO passes a ucontext_t. uc_mcontext is at byte 48 and points
    // at __darwin_mcontext64; the thread state x0 starts at byte 16 of that context
    // (Darwin <sys/ucontext.h> and <mach/arm/_structs.h>).
    let mcontext = unsafe { ctx.cast::<u8>().add(48).cast::<*const u8>().read() };
    if mcontext.is_null() {
        return;
    }
    let reg = |index: usize| {
        // SAFETY: `mcontext` is the faulting thread's __darwin_mcontext64; GPR `index`
        // is one u64 at byte 16 of that state.
        unsafe { mcontext.add(16 + index * 8).cast::<u64>().read() }
    };
    let pc = reg(32);
    let lr = reg(30);
    let x0 = reg(0);
    let x9 = reg(9);
    let x13 = reg(13);
    let x20 = reg(20);
    let x21 = reg(21);
    let x23 = reg(23);
    let x25 = reg(25);
    let mut path = *b"/tmp/arinsal-crash-00000000.txt\0";
    // SAFETY: getpid reads the calling process id and has no preconditions.
    let pid = unsafe { libc::getpid() } as u32;
    for i in 0..8 {
        let nibble = ((pid >> (28 - i * 4)) & 0xf) as usize;
        path[19 + i] = b"0123456789abcdef"[nibble];
    }
    // SAFETY: `path` is a NUL-terminated stack buffer. open creates that file.
    let fd = unsafe {
        libc::open(
            path.as_ptr().cast(),
            libc::O_CREAT | libc::O_TRUNC | libc::O_WRONLY,
            0o644,
        )
    };
    if fd < 0 {
        return;
    }
    let mut line = [0u8; 192];
    let mut write_line = |text: &str| {
        let n = text.len().min(line.len() - 1);
        line[..n].copy_from_slice(&text.as_bytes()[..n]);
        line[n] = b'\n';
        // SAFETY: `fd` is the dump file and `line` is a stack buffer of `n + 1` bytes.
        unsafe {
            libc::write(fd, line.as_ptr().cast(), n + 1);
        }
    };
    let hex = |value: u64| {
        let mut buf = [0u8; 18];
        buf[0] = b'0';
        buf[1] = b'x';
        for i in 0..16 {
            let nibble = ((value >> (60 - i * 4)) & 0xf) as u8;
            buf[2 + i] = b"0123456789abcdef"[nibble as usize];
        }
        buf
    };
    let mut scratch = [0u8; 160];
    let mut emit = |prefix: &str, value: u64| {
        let h = hex(value);
        let mut n = 0;
        for byte in prefix.bytes() {
            if n < scratch.len() {
                scratch[n] = byte;
                n += 1;
            }
        }
        if n + 18 < scratch.len() {
            scratch[n..n + 18].copy_from_slice(&h);
            n += 18;
        }
        scratch[n] = b'\n';
        // SAFETY: `fd` is the dump file and `scratch` is a stack buffer of `n + 1` bytes.
        unsafe {
            libc::write(fd, scratch.as_ptr().cast(), n + 1);
        }
    };
    emit("pc ", pc);
    emit("lr ", lr);
    emit("x0 ", x0);
    emit("x9 ", x9);
    emit("x13 ", x13);
    emit("x20 ", x20);
    emit("x21 ", x21);
    emit("x23 ", x23);
    emit("x25 ", x25);
    let word = |addr: u64| -> u64 {
        if addr == 0 || !addr.is_multiple_of(8) {
            return 0;
        }
        // SAFETY: `addr` is a non-null aligned word in the faulting process. The read is
        // volatile so a second fault is not elided; the handler then exits.
        unsafe { (addr as *const u64).read_volatile() }
    };
    let htop = word(x21);
    let stop = word(x21.wrapping_add(8));
    let heap = word(x21.wrapping_add(16));
    let hend = word(x21.wrapping_add(24));
    emit("htop ", htop);
    emit("stop ", stop);
    emit("heap ", heap);
    emit("hend ", hend);
    let tuple = x25 & !7;
    emit("tuple ", tuple);
    for index in 0..4 {
        emit("tw ", word(tuple.wrapping_add(index * 8)));
    }
    let place = if heap != 0 && heap <= tuple && tuple < htop {
        "place live-young"
    } else if htop != 0 && htop <= tuple && tuple < stop {
        "place free-gap"
    } else if stop != 0 && stop <= tuple && tuple < hend {
        "place stack"
    } else {
        "place outside"
    };
    write_line(place);
    let _ = with_native_function_at(pc as usize, |function| {
        let (file, line_no) = function.line_at(pc as usize).unwrap_or(("?", 0));
        let mut text = [0u8; 240];
        let mut n = 0;
        for part in [
            function.module.as_str(),
            ":",
            function.function.as_str(),
            "/",
        ] {
            for byte in part.bytes() {
                if n < text.len() {
                    text[n] = byte;
                    n += 1;
                }
            }
        }
        let mut value = u32::from(function.arity);
        let mut digits = [0u8; 3];
        let mut count = 0;
        if value == 0 {
            digits[0] = b'0';
            count = 1;
        }
        while value > 0 {
            digits[count] = b'0' + (value % 10) as u8;
            value /= 10;
            count += 1;
        }
        for i in (0..count).rev() {
            if n < text.len() {
                text[n] = digits[i];
                n += 1;
            }
        }
        for byte in b" " {
            if n < text.len() {
                text[n] = *byte;
                n += 1;
            }
        }
        for byte in file.bytes().take(80) {
            if n < text.len() {
                text[n] = byte;
                n += 1;
            }
        }
        if n < text.len() {
            text[n] = b':';
            n += 1;
        }
        let mut digits = [0u8; 8];
        let mut value = line_no;
        let mut count = 0;
        if value == 0 {
            digits[0] = b'0';
            count = 1;
        }
        while value > 0 && count < digits.len() {
            digits[count] = b'0' + (value % 10) as u8;
            value /= 10;
            count += 1;
        }
        for i in (0..count).rev() {
            if n < text.len() {
                text[n] = digits[i];
                n += 1;
            }
        }
        text[n] = b'\n';
        // SAFETY: `fd` is the dump file and `text` is a stack buffer of `n + 1` bytes.
        unsafe {
            libc::write(fd, text.as_ptr().cast(), n + 1);
        }
    });
    // SAFETY: `fd` is the dump file. _exit terminates this faulting process with the
    // conventional SIGSEGV status and does not unwind.
    unsafe {
        libc::close(fd);
        libc::_exit(139);
    }
}

/// `ARINSAL_BEAMASM_LIFETIME=1`: log native code memory lifetimes.
#[inline]
pub(crate) fn lifetime_trace_enabled() -> bool {
    crate::debug_env::slice::get() & crate::debug_env::slice::LIFETIME_TRACE != 0
}

#[cfg(test)]
mod version_selection_tests {
    use super::*;

    fn function(scope: u64, start: usize, module: &str) -> NativeFunction {
        let atoms = arinsal_term::global_atoms();
        NativeFunction {
            scope,
            start,
            end: start + 16,
            module: module.to_owned(),
            module_atom: atoms.intern(module).expect("module atom"),
            function: "spin".to_owned(),
            function_atom: atoms.intern("spin").expect("function atom"),
            arity: 0,
            line: None,
            file: None,
            file_term: None,
            line_table: Vec::new(),
        }
    }

    // An old and a current version of one module are registered at once; the current one
    // may be placed below the old one in memory. Each version must still find its own code.
    #[test]
    fn native_functions_of_selects_the_requested_version() {
        let memory: &'static [u8] = Box::leak(vec![0_u8; 256].into_boxed_slice());
        let base = memory.as_ptr() as usize;
        let module = "native_bridge_version_selection";
        let old = function(7, base + 128, module);
        let current = function(7, base, module);
        register_native_function(old.clone()).expect("register old version");
        register_native_function(current.clone()).expect("register current version");
        let key = ("spin".to_owned(), 0);
        let selected = native_functions_of(7, module, Some((base, base + 64)));
        assert_eq!(selected.get(&key), Some(&current));
        let selected = native_functions_of(7, module, Some((base + 128, base + 192)));
        assert_eq!(selected.get(&key), Some(&old));
        unregister_native_functions(&[old, current]);
    }
}
