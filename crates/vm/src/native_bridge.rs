//! Native execution bridge and registered code metadata.

use super::*;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};

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

/// Whether the perf map is being written.
fn perf_map_enabled() -> bool {
    perf_map_file()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .is_some()
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
    /// Process-wide fragment code, published into every code index; module code is staged.
    pub fragment: bool,
    /// Inclusive first byte of generated code.
    pub start: usize,
    /// Exclusive end of generated code.
    pub end: usize,
    /// Erlang module name: the text of `module_atom`, which the atom table keeps for good.
    pub module: &'static str,
    /// Module atom resolved when the native function was registered.
    pub module_atom: arinsal_term::Atom,
    /// Erlang function name: the text of `function_atom`.
    pub function: &'static str,
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
    /// Native PCs and their source locations, sorted by address: the function's part of the
    /// module's one location table (`BeamCodeLineTab::loc_tab` of erts).
    pub line_table: NativeLines,
}

/// A function's window onto the location table its module shares between all its functions.
// Port of erts/emulator/beam/beam_file.h (BeamCodeLineTab: one `loc_tab` per module,
// `func_tab` pointing into it), OTP-29.1.1.
#[derive(Clone, Debug, Default)]
pub struct NativeLines {
    table: Option<Arc<[NativeLine]>>,
    /// The module's native PCs alone, parallel to `table`: the search keys of
    /// `lookup_loc`, so a probe touches eight bytes (erts keeps `loc_tab` compact).
    addresses: Option<Arc<[usize]>>,
    files: Option<Arc<[NativeFile]>>,
    lo: u32,
    hi: u32,
}

impl NativeLines {
    /// The entries `lo..hi` of `table`; `addresses` holds their native PCs in the same order.
    pub fn window(
        table: &Arc<[NativeLine]>,
        addresses: &Arc<[usize]>,
        files: &Arc<[NativeFile]>,
        lo: usize,
        hi: usize,
    ) -> Self {
        debug_assert_eq!(table.len() + 1, addresses.len());
        Self {
            table: Some(Arc::clone(table)),
            addresses: Some(Arc::clone(addresses)),
            files: Some(Arc::clone(files)),
            lo: lo as u32,
            hi: hi as u32,
        }
    }

    /// Whether a line entry of this window names source line `line`.
    pub(crate) fn has_line(&self, line: u32) -> bool {
        self.table.as_deref().is_some_and(|table| {
            table
                .get(self.lo as usize..self.hi as usize)
                .unwrap_or_default()
                .iter()
                .any(|entry| entry.location != 0 && entry.location & 0x00ff_ffff == line)
        })
    }

    /// The entry at the nearest preceding native PC, like erts' `lookup_loc`
    /// (beam_ranges.c): a branching binary search over the compact PC table.
    #[inline]
    fn find(&self, address: usize) -> Option<&NativeLine> {
        let keys = self.addresses.as_deref()?;
        let (mut low, mut high) = (self.lo as usize, self.hi as usize);
        while high > low {
            let mid = low + (high - low) / 2;
            if address < keys[mid] {
                high = mid;
            } else if address < keys[mid + 1] {
                return self.table.as_deref()?.get(mid);
            } else {
                low = mid + 1;
            }
        }
        None
    }
}

/// One entry in the module's `BeamCodeLineTab.fname_ptr` table.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeFile {
    pub name: Arc<str>,
    pub file_term: Option<Term>,
}

impl std::ops::Deref for NativeLines {
    type Target = [NativeLine];
    fn deref(&self) -> &[NativeLine] {
        self.table
            .as_deref()
            .map_or(&[], |table| &table[self.lo as usize..self.hi as usize])
    }
}

impl PartialEq for NativeLines {
    fn eq(&self, other: &Self) -> bool {
        **self == **other
    }
}
impl Eq for NativeLines {}

/// One native PC to source location mapping.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeLine {
    /// Native address at which this source line becomes current.
    pub address: usize,
    /// Packed `MAKE_LOCATION(file, line)` value; zero is invalid.
    pub location: u32,
}

impl NativeFunction {
    /// Resolve a native return PC to the nearest preceding BEAM line marker.
    pub fn line_at(&self, address: usize) -> Option<(&str, u32)> {
        let location = self.line_table.find(address)?.location;
        if location == 0 {
            return None;
        }
        let file = self
            .line_table
            .files
            .as_deref()?
            .get((location >> 24) as usize)?;
        Some((file.name.as_ref(), location & 0x00ff_ffff))
    }
}

#[derive(Clone)]
pub(crate) struct NativeStackFrame {
    pub module_atom: arinsal_term::Atom,
    pub function_atom: arinsal_term::Atom,
    pub arity: u8,
    /// Resolved source location, like `FunctionInfo.loc` plus `fname_ptr[file]` in erts.
    pub location: Option<(Term, u64)>,
    pub line: Option<u32>,
    pub file_term: Option<Term>,
}

/// `FunctionInfo` filled by `erts_lookup_function_info` for one native PC.
// Port of erts/emulator/beam/global.h:964-973 (`FunctionInfo`), OTP-29.1.1.
#[derive(Clone, Copy)]
struct FunctionInfo<'a> {
    mfa: Option<&'a NativeFunction>,
    needed: usize,
    loc: Option<&'a NativeLine>,
    fname_ptr: Option<&'a [NativeFile]>,
}

impl<'a> FunctionInfo<'a> {
    fn new() -> Self {
        Self {
            mfa: None,
            needed: 5,
            loc: None,
            fname_ptr: None,
        }
    }
}

/// The functions of one native module version, ordered by address: the function table of its
/// code header. The compiled version owns it and the range entries of the module point at the
/// same table, as the `Range` of erts points at the `BeamCodeHeader` of its module.
// Port of erts/emulator/beam/beam_ranges.c:33-66 (Range.mid, the code header), and
// beam_code.h (BeamCodeHeader.functions), OTP-29.1.1.
pub(crate) type FunctionTable = Arc<[NativeFunction]>;

/// One module's native code in the active code index, sorted by `start`.
///
/// Port of erts/emulator/beam/beam_ranges.c:33-66 (`Range`) and :245 (`erts_lookup_function_info`),
/// OTP-29.1.1. `find_range` binary-searches the module, then the function inside it.
#[derive(Clone)]
pub(crate) struct ModuleRange {
    /// Fragment ranges are published into every code index; module ranges are staged.
    fragment: bool,
    start: usize,
    /// Shared across code-index snapshots so purge invalidates copies made during staging.
    end: Arc<AtomicUsize>,
    /// The code header's function table. `erts_lookup_function_info` binary-searches the
    /// function start addresses (beam_ranges.c:262-278), OTP-29.1.1.
    functions: FunctionTable,
    /// `BeamCodeHeader.functions` search keys, including its one-past-last sentinel.
    function_starts: Arc<[usize]>,
}

impl ModuleRange {
    pub(crate) fn start(&self) -> usize {
        self.start
    }

    pub(crate) fn end(&self) -> usize {
        self.end.load(Ordering::Acquire)
    }

    /// Marks a purged range dead before its executable span can be reused.
    // Port of erts/emulator/beam/beam_ranges.c:221-227 (erts_remove_from_ranges), OTP-29.1.1.
    pub(crate) fn retire(&self) {
        self.end.store(self.start, Ordering::Release);
    }
}

fn fragment_ranges() -> &'static arc_swap::ArcSwap<Vec<ModuleRange>> {
    static RANGES: OnceLock<arc_swap::ArcSwap<Vec<ModuleRange>>> = OnceLock::new();
    RANGES.get_or_init(|| arc_swap::ArcSwap::new(Arc::new(Vec::new())))
}

/// The fragment ranges the code indexes start from.
pub(crate) fn code_ranges() -> Arc<Vec<ModuleRange>> {
    fragment_ranges().load_full()
}

/// The range entry of a module version whose functions are `functions`.
fn module_range(start: usize, end: usize, functions: FunctionTable) -> ModuleRange {
    let fragment = functions.first().is_some_and(|function| function.fragment);
    ModuleRange {
        fragment,
        start,
        end: Arc::new(AtomicUsize::new(end)),
        function_starts: functions
            .iter()
            .map(|function| function.start)
            .chain(std::iter::once(end))
            .collect::<Vec<_>>()
            .into(),
        functions,
    }
}

/// Every module range, ordered by address. `erts_lookup_function_info` searches
/// the ranges of one code index; the code of different nodes lives at different addresses, so
/// one table answers a lookup by address for all of them. Readers take a snapshot without a
/// lock; writers serialize on [`ranges_writers`].
fn all_ranges() -> &'static arc_swap::ArcSwap<Vec<ModuleRange>> {
    static RANGES: OnceLock<arc_swap::ArcSwap<Vec<ModuleRange>>> = OnceLock::new();
    RANGES.get_or_init(|| arc_swap::ArcSwap::new(Arc::new(Vec::new())))
}

fn ranges_writers() -> &'static Mutex<()> {
    static WRITERS: Mutex<()> = Mutex::new(());
    &WRITERS
}

/// Adds `range` to [`all_ranges`]; a range that overlaps a live one is refused.
fn insert_global_range(range: &ModuleRange) -> Result<(), &'static str> {
    let _writer = ranges_writers()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut ranges = all_ranges().load_full().as_ref().clone();
    ranges.retain(|entry| entry.end() > entry.start);
    let at = ranges.partition_point(|entry| entry.start < range.start);
    if at > 0 && ranges[at - 1].end() > range.start {
        return Err("native function ranges must not overlap");
    }
    if at < ranges.len() && range.end() > ranges[at].start {
        return Err("native function ranges must not overlap");
    }
    ranges.insert(at, range.clone());
    all_ranges().store(Arc::new(ranges));
    Ok(())
}

/// Removes the ranges `matching` selects from [`all_ranges`], retires them and returns their
/// start and end.
fn remove_global_ranges(matching: impl Fn(&ModuleRange) -> bool) -> Vec<(usize, usize)> {
    let _writer = ranges_writers()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut ranges = all_ranges().load_full().as_ref().clone();
    let mut removed = Vec::new();
    ranges.retain(|entry| {
        if entry.end() > entry.start && matching(entry) {
            removed.push((entry.start, entry.end()));
            entry.retire();
            false
        } else {
            entry.end() > entry.start
        }
    });
    all_ranges().store(Arc::new(ranges));
    removed
}

// Port of erts/emulator/beam/beam_ranges.c:137-180 (erts_end_staging_ranges), OTP-29.1.1.
fn insert_module_range(ranges: &mut Vec<ModuleRange>, range: ModuleRange) {
    ranges.retain(|entry| entry.end() > entry.start());
    let at = ranges.partition_point(|entry| entry.start < range.start);
    assert!(
        at == 0 || ranges[at - 1].end() <= range.start,
        "native module ranges overlap"
    );
    assert!(
        at == ranges.len() || range.end() <= ranges[at].start,
        "native module ranges overlap"
    );
    ranges.insert(at, range);
}

// Port of erts/emulator/beam/beam_ranges.c:194-219 (erts_update_ranges), OTP-29.1.1.
fn publish_native_module_range(range: ModuleRange) {
    if !range.fragment {
        crate::code_ix::global().add_staging_code_range(range);
        return;
    }
    let mut seed = fragment_ranges().load_full().as_ref().clone();
    insert_module_range(&mut seed, range.clone());
    fragment_ranges().store(Arc::new(seed));
    // Fragments exist before the code indexes (beamasm_init runs first, as in erl_init.c).
    if let Some(indexes) = crate::code_ix::existing() {
        let mut ranges = indexes.with_code_ranges(<[_]>::to_vec);
        insert_module_range(&mut ranges, range);
        indexes.store_code_ranges(Arc::new(ranges));
    }
}

// Port of erts/emulator/beam/beam_ranges.c:221-227 (erts_remove_from_ranges), OTP-29.1.1.
fn unpublish_native_module_range(start: usize, end: usize) {
    for range in fragment_ranges().load().iter() {
        if range.start == start && range.end() == end {
            range.retire();
        }
    }
    if let Some(indexes) = crate::code_ix::existing() {
        indexes.remove_code_range(start, end);
    }
}

/// `find_range` (beam_ranges.c:307-327), OTP-29.1.1. The search begins at the cached midpoint,
/// narrows the module interval, and stores a hit as the next midpoint.
fn find_range_with<'a>(
    ranges: &'a [ModuleRange],
    address: usize,
    hint: &AtomicUsize,
) -> Option<&'a ModuleRange> {
    let len = ranges.len();
    if len == 0 {
        return None;
    }
    let (mut low, mut high) = (0usize, len);
    let mut mid = hint.load(Ordering::Relaxed).min(len - 1);
    while low < high {
        let range = &ranges[mid];
        if address < range.start {
            high = mid;
        } else if address >= range.end() {
            low = mid + 1;
        } else {
            hint.store(mid, Ordering::Relaxed);
            return Some(range);
        }
        mid = low + (high - low) / 2;
    }
    None
}

/// `erts_lookup_function_info` over the ranges published with the active code index.
// Port of erts/emulator/beam/beam_ranges.c:245-280 and :307-327, OTP-29.1.1.
fn frame_in(
    ranges: &[ModuleRange],
    address: usize,
    hint: &AtomicUsize,
) -> Option<NativeStackFrame> {
    let range = find_range_with(ranges, address, hint)?;
    let info = lookup_function_info(range, address, true);
    let function = info.mfa?;
    let loc = info.loc.map(|entry| entry.location).filter(|&loc| loc != 0);
    let file = loc.and_then(|location| info.fname_ptr?.get((location >> 24) as usize));
    let file_term = file.and_then(|file| file.file_term);
    let location =
        loc.and_then(|location| file_term.map(|file| (file, u64::from(location & 0x00ff_ffff))));
    debug_assert_eq!(info.needed, if location.is_some() { 15 } else { 5 });
    Some(NativeStackFrame {
        module_atom: function.module_atom,
        function_atom: function.function_atom,
        arity: function.arity,
        location,
        line: loc.map(|location| location & 0x00ff_ffff),
        file_term,
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
        return native_frame_at(address);
    };
    static HINT: AtomicUsize = AtomicUsize::new(0);
    // Code-index ranges carry the owning module's cached file term on each line entry, like
    // erts' BeamCodeLineTab.
    frame_in(ranges, address, &HINT)
}

/// Runs `visit` on the function of a registered native module that contains `address`.
/// Every process entry and return comes through here; the ranges are read without a lock.
// Port of erts/emulator/beam/beam_ranges.c:245-280 (erts_lookup_function_info), OTP-29.1.1.
fn lookup_function<R>(address: usize, visit: impl FnOnce(&NativeFunction) -> R) -> Option<R> {
    static HINT: AtomicUsize = AtomicUsize::new(0);
    let ranges = all_ranges().load();
    let range = find_range_with(&ranges, address, &HINT)?;
    let function = function_in(range, address)?;
    Some(visit(function))
}

// Port of erts/emulator/beam/beam_ranges.c:262-280 (`erts_lookup_function_info`), OTP-29.1.1.
fn lookup_function_info<'a>(
    range: &'a ModuleRange,
    address: usize,
    full_info: bool,
) -> FunctionInfo<'a> {
    let mut info = FunctionInfo::new();
    let starts = &*range.function_starts;
    let (mut low, mut high) = (0usize, range.functions.len());
    while low < high {
        let mid = low + (high - low) / 2;
        if address < starts[mid] {
            high = mid;
        } else if address < starts[mid + 1] {
            let function = &range.functions[mid];
            info.mfa = Some(function);
            if full_info {
                lookup_loc(&mut info, function, address);
            }
            return info;
        } else {
            low = mid + 1;
        }
    }
    info
}

// Port of erts/emulator/beam/beam_ranges.c:331-363 (`lookup_loc`), OTP-29.1.1.
fn lookup_loc<'a>(info: &mut FunctionInfo<'a>, function: &'a NativeFunction, address: usize) {
    info.fname_ptr = function.line_table.files.as_deref();
    info.loc = function.line_table.find(address);
    if info.loc.is_some_and(|entry| entry.location == 0) {
        return;
    }
    if info.loc.is_some() {
        info.needed += 3 + 2 + 3 + 2;
    }
}

// Port of erts/emulator/beam/beam_ranges.c:262-280 (`erts_lookup_function_info`), OTP-29.1.1.
fn function_in(range: &ModuleRange, address: usize) -> Option<&NativeFunction> {
    lookup_function_info(range, address, false).mfa
}

/// Port of erts/emulator/beam/beam_catches.c:146 (`beam_catches_car`), OTP-29.1.1.
/// Indexes `bccix[erts_active_code_ix()]`. The active index is the node's atomic.
fn catch_slot(index: u32) -> Option<usize> {
    crate::beam_catches::beam_catches_car(crate::code_ix::global(), index)
}

/// Whether a stack word is a catch tag registered by native code (`catch`/`try` in a BeamAsm
/// frame), whose handler only `next_catch` can resolve.
pub(crate) fn is_native_catch_tag(word: Term) -> bool {
    let raw = word.tagged_word();
    raw & 63 == 0x1b && u32::try_from(raw >> 6).is_ok_and(|index| catch_slot(index).is_some())
}

/// Native handler address of a catch-table index, if it names native code.
pub(crate) fn native_catch(index: u32) -> Option<usize> {
    catch_slot(index)
}

/// A catch the scan found. The stack is unchanged until [`commit_catch`].
#[derive(Clone, Copy)]
pub(crate) struct LocatedCatch {
    /// Stack index of the catch tag.
    index: usize,
    /// Stack index `E` resumes at: the catching frame's first Y slot.
    resume: usize,
    target: usize,
}

/// What `next_catch`'s walk found: the catch, if any, and whether trace frames lie above it
/// (on the whole stack when there is no catch). Word-sized on purpose: a trailing `bool` made
/// the compiler move this struct with overlapping sub-word copies, which stall on
/// store-to-load forwarding at ~25 ns a raise.
#[derive(Clone, Copy)]
struct CatchScan {
    found: Option<LocatedCatch>,
    traced: usize,
}

/// Port of erts/emulator/beam/beam_common.c:580-648 (`next_catch` up to `found_catch`),
/// OTP-29.1.1. The scan only reads the stack and the active catch table. It does not move
/// `stop`.
fn locate_catch(process: &mut Process) -> CatchScan {
    let heap = &process.heap;
    // Port of erts/emulator/beam/beam_catches.c:146-154 (`beam_catches_car` reads
    // `bccix[erts_active_code_ix()]`), OTP-29.1.1: the slot is read directly, a raise allocates
    // nothing on the process.
    if let Some(runtime) = process.runtime.as_ref() {
        return scan_catch(heap, runtime.code_indexes());
    }
    scan_catch(heap, crate::code_ix::global())
}

fn scan_catch(heap: &arinsal_term::ProcessHeap, code: &crate::code_ix::CodeIndexes) -> CatchScan {
    let mut stack = heap.stack_terms().enumerate();
    let mut previous_cp = 0usize;
    let mut seen_cp = false;
    let mut traced = 0usize;
    let catches = heap.abi.catches != 0;
    while let Some((index, word)) = stack.next() {
        let raw = word.tagged_word();
        if catches
            && raw & 63 == 0x1b
            && let Some(catch_index) = u32::try_from(raw >> 6).ok()
            && let Some(target) = crate::beam_catches::beam_catches_car(code, catch_index)
        {
            // A frame keeps the caller-pushed CP above its Y slots (a call pushes the CP,
            // `allocate` then reserves the Y slots below it), so the
            // resumed E is the first Y slot after the last CP below the catch, or the stack top
            // when the catching frame is the topmost one.
            let resume = if seen_cp {
                previous_cp + arinsal_term::CP_WORDS
            } else {
                0
            };
            return CatchScan {
                found: Some(LocatedCatch {
                    index,
                    resume,
                    target,
                }),
                traced,
            };
        }
        // Port of erl_term.h:1378-1379 (`is_CP`), OTP-29.1.1.
        if arinsal_term::is_cp(raw) {
            // Port of erts/emulator/beam/beam_common.c:604-635 (next_catch), OTP-29.1.1: a
            // trace frame is a CP followed by its data words.
            if let Some(kind) = crate::trace::TraceFrameKind::of(raw as usize) {
                traced = 1;
                previous_cp = index;
                seen_cp = true;
                for _ in 0..kind.data_words() {
                    if stack.next().is_none() {
                        break;
                    }
                }
                continue;
            }
            previous_cp = index;
            seen_cp = true;
            for _ in 0..arinsal_term::CP_WORDS.saturating_sub(1) {
                stack.next();
            }
        }
    }
    CatchScan {
        found: None,
        traced,
    }
}

/// Port of erts/emulator/beam/beam_common.c:532-678 (`handle_error` once the trace is saved,
/// `next_catch`, `found_catch`), OTP-29.1.1: one scan of the stack; the trace frames it
/// passes report their exception events (`next_catch`), then `found_catch` writes the catch
/// word, `stop`, x0..x3 and the failure words. Returns the native handler, or `None` when the
/// stack has no catch and `handle_error` terminates the process.
#[inline]
pub(crate) fn native_found_catch(
    process: &mut Process,
    reg: &mut [Term],
    class: arinsal_bifs::Class,
    reason: Term,
    trace: Term,
) -> Option<usize> {
    // Port of erts/emulator/beam/beam_common.c:529-530 (handle_error: `(c_p->catches > 0 ||
    // c_p->return_trace_frames > 0) && !(c_p->freason & EXF_PANIC)`), OTP-29.1.1.
    if (process.heap.abi.catches == 0 && process.return_trace_frames == 0)
        || process.heap.abi.exc.freason & arinsal_term::exc::EXF_PANIC != 0
    {
        return None;
    }
    let scan = locate_catch(process);
    if scan.traced != 0 {
        next_catch_trace(process, class, reason, scan.found);
    }
    let Some(found) = scan.found else {
        // Port of erts/emulator/beam/beam_common.c:568 (handle_error), OTP-29.1.1.
        assert!(process.heap.abi.catches == 0, "Catch not found");
        return None;
    };
    found_catch(process, reg, found, class, reason, trace);
    Some(found.target)
}

/// The trace part of `next_catch`: every exception_trace frame between the stack top and the
/// catch (the whole stack without one) reports `exception_from`, a plain return_trace frame
/// is released, and the sessions of the return_to frames passed give the catching function
/// its `return_to` event.
// Port of erts/emulator/beam/beam_common.c:600-640 (next_catch: erts_trace_exception for
// exception_trace frames, return_trace_frames--, return_to marking), OTP-29.1.1.
#[inline(never)]
fn next_catch_trace(
    process: &mut Process,
    class: arinsal_bifs::Class,
    reason: Term,
    found: Option<LocatedCatch>,
) {
    let upto = found.map_or(process.heap.stack_words(), |found| found.index);
    arinsal_sched::erts_proc_sched_data(process, |process, esdp| {
        arinsal_sched::RunCtx::with_current(esdp, |ctx| -> Result<(), VmError> {
            let vm = &mut Vm {};
            let mut sessions: Vec<u64> = process
                .cold
                .as_mut()
                .map(|cold| std::mem::take(&mut cold.bif_return_to))
                .unwrap_or_default();
            let mut index = 0;
            while index < upto {
                let Some((frame, frame_words)) = crate::trace::trace_frame_at(&process.heap, index)
                else {
                    index += 1;
                    continue;
                };
                match frame {
                    crate::trace::TraceFrame::Return {
                        exception: true,
                        function_pc,
                        session,
                    } => {
                        let class_reason = exceptions::trace_class_reason(process, class, reason)?;
                        crate::trace::native_return_event(
                            vm,
                            process,
                            ctx,
                            function_pc,
                            session,
                            class_reason,
                            true,
                        )?;
                    }
                    crate::trace::TraceFrame::Return { session, .. } => {
                        crate::trace::release_return_frame(process, session);
                    }
                    crate::trace::TraceFrame::ReturnTo { session } => sessions.push(session),
                    crate::trace::TraceFrame::CallAcc => {}
                }
                index += frame_words;
            }
            if let Some(found) = found {
                let target = crate::native_function_at(found.target).map(|function| {
                    (
                        function.module.to_owned(),
                        function.function.to_owned(),
                        function.arity,
                    )
                });
                crate::trace::unwound_return_to(vm, process, ctx, &sessions, target)?;
            }
            Ok(())
        })
    })
    .flatten()
    .expect("next_catch runs in the process's slice")
    .expect("next_catch: exception trace event");
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
    reg: &mut [Term],
    class: arinsal_bifs::Class,
    reason: Term,
    trace: Term,
) -> Option<usize> {
    let found = locate_catch(process).found?;
    // The scheduler resumes the handler through `native_prepare`; the native resolver branches to
    // it directly, so these Rust-side resume records are this caller's, not `found_catch`'s.
    process.exc_class = Some(class);
    found_catch(process, reg, found, class, reason, trace);
    let handler = found.target;
    process.native_continuation_resume = true;
    process.set_native_resume_arity(4);
    Some(handler)
}

/// Port of erts/emulator/beam/beam_common.c:532-570 (`handle_error` register writes) and
/// :650-678 (`found_catch`), OTP-29.1.1. The stack and catch word change only once the scan
/// found the handler.
// A function of its own, as `found_catch` in beam_common.c: inlined into the exception
// resolver it made `try … catch` 6% slower (the resolver's frame and register pressure grew).
#[inline(never)]
fn found_catch(
    process: &mut Process,
    reg: &mut [Term],
    found: LocatedCatch,
    class: arinsal_bifs::Class,
    reason: Term,
    trace: Term,
) {
    // `found_catch` clears the catch word, then `c_p->stop = prev; c_p->stop += CP_SIZE`.
    process.heap.stack_set(found.index, Term::NIL);
    process.heap.release_stack(found.resume);
    // x0 = non-value marker, x1 = reason, x2 = raw stacktrace, x3 = class.
    reg[0] = Term::catch(0);
    reg[1] = reason;
    reg[2] = trace;
    reg[3] = exception_class_atom(class);
    // `handle_error` leaves PRIMARY_EXCEPTION in `c_p->freason` across `found_catch`; the catch
    // code consumes it after the non-value marker in x0 (beam_common.c:517-525, :650-678).
    process.heap.abi.exc.ftrace = 0;
}

fn register_bridge_continuation() -> Result<(), &'static str> {
    static REGISTERED: OnceLock<Result<(), &'static str>> = OnceLock::new();
    *REGISTERED.get_or_init(|| {
        let address = arinsal_beamasm::rt::arinsal_enter_native_return as *const () as usize;
        arinsal_term::register_native_code_range(address, address + 4)?;
        for kind in [
            crate::trace::TraceFrameKind::ReturnTrace,
            crate::trace::TraceFrameKind::ExceptionTrace,
            crate::trace::TraceFrameKind::ReturnToTrace,
            crate::trace::TraceFrameKind::CallTraceReturn,
        ] {
            let stub = kind.address();
            arinsal_term::register_native_code_range(stub, stub + 4)?;
        }
        Ok(())
    })
}

/// The native exit bridge: the return address of a call without a native caller, erts'
/// `beam_normal_exit`.
pub(crate) fn bridge_return_address() -> usize {
    arinsal_beamasm::rt::arinsal_enter_native_return as *const () as usize
}

/// Register a native code range for GC continuation recognition and stack traces.
pub fn register_native_function(info: NativeFunction) -> Result<(), &'static str> {
    if info.start >= info.end {
        return Err("native code range must be non-empty");
    }
    let (start, end) = (info.start, info.end);
    arinsal_term::register_native_code_range(start, end)?;
    update_perf_map(&info);
    let range = module_range(start, end, Arc::from(vec![info]));
    if let Err(error) = insert_global_range(&range) {
        arinsal_term::unregister_native_code_range(start, end);
        return Err(error);
    }
    if crate::native_bridge::lifetime_trace_enabled() {
        let function = &range.functions[0];
        eprintln!(
            "[beamasm-lifetime] native register {}/{}:{} range={:#x}..{:#x}",
            function.module, function.function, function.arity, function.start, function.end
        );
    }
    publish_native_module_range(range);
    Ok(())
}

/// Installs one compiled module's native functions with one range entry in the code index,
/// matching `erts_update_ranges`' per-module entry. `functions` is the function table of the
/// module's code header, ordered by address.
// Port of erts/emulator/beam/beam_ranges.c:194-219 (erts_update_ranges), OTP-29.1.1.
pub(crate) fn register_native_module(
    functions: &FunctionTable,
    code_start: usize,
    code_end: usize,
) -> Result<(), &'static str> {
    if code_start >= code_end || functions.is_empty() {
        return Err("native module range must be non-empty");
    }
    let first = &functions[0];
    if functions.iter().any(|function| {
        function.fragment != first.fragment
            || function.module_atom != first.module_atom
            || function.start < code_start
            || function.end > code_end
            || function.start >= function.end
    }) || functions.windows(2).any(|pair| pair[0].end > pair[1].start)
    {
        return Err("native functions must belong to one module code range");
    }
    arinsal_term::register_native_code_range(code_start, code_end)?;
    let range = module_range(code_start, code_end, Arc::clone(functions));
    if let Err(error) = insert_global_range(&range) {
        arinsal_term::unregister_native_code_range(code_start, code_end);
        return Err(error);
    }
    if perf_map_enabled() {
        functions.iter().for_each(update_perf_map);
    }
    publish_native_module_range(range);
    Ok(())
}

/// Removes a purged module's range from the code indexes and the address table.
// Port of erts/emulator/beam/beam_ranges.c:221-227 (erts_remove_from_ranges), OTP-29.1.1.
pub(crate) fn unregister_native_module(code_start: usize, code_end: usize) {
    remove_global_ranges(|range| range.start == code_start && range.end() == code_end);
    arinsal_term::unregister_native_code_range(code_start, code_end);
    unpublish_native_module_range(code_start, code_end);
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
    // The hook's class numbers are its own ABI; the process holds the erts exit code.
    header.exc.freason = match class {
        1 => arinsal_beamasm::exc::EXC_ERROR,
        2 => arinsal_beamasm::exc::EXC_EXIT,
        _ => arinsal_beamasm::exc::EXC_THROWN,
    };
    header.exc.fvalue = reason;
}

/// Find metadata for a native instruction or continuation address.
pub fn native_function_at(address: usize) -> Option<NativeFunction> {
    if !arinsal_term::may_be_native_code_pointer(address) {
        return None;
    }
    lookup_function(address, NativeFunction::clone)
}

/// Runs `visit` on the native function containing `address` without cloning its metadata.
pub(crate) fn with_native_function_at<R>(
    address: usize,
    visit: impl FnOnce(&NativeFunction) -> R,
) -> Option<R> {
    if !arinsal_term::may_be_native_code_pointer(address) {
        return None;
    }
    lookup_function(address, visit)
}

/// Test native code membership without cloning function metadata.
pub(crate) fn is_native_function_at(address: usize) -> bool {
    if !arinsal_term::may_be_native_code_pointer(address) {
        return false;
    }
    lookup_function(address, |_| ()).is_some()
}

/// A word the interpreter returns into by continuing native code: a native return address, or
/// the return address of a trace frame.
pub(crate) fn is_native_continuation(address: usize) -> bool {
    crate::trace::TraceFrameKind::of(address).is_some() || is_native_function_at(address)
}

pub(crate) fn native_stack_frame_at(address: usize) -> Option<NativeStackFrame> {
    native_frame_at(address)
}

// Port of erts/emulator/beam/beam_ranges.c:245-280 (`erts_lookup_function_info`), OTP-29.1.1.
fn native_frame_at(address: usize) -> Option<NativeStackFrame> {
    static HINT: AtomicUsize = AtomicUsize::new(0);
    if !arinsal_term::may_be_native_code_pointer(address) {
        return None;
    }
    frame_in(&all_ranges().load(), address, &HINT)
}

/// The native entry [`native_prepare`] set up: what [`native_exit`] needs once the native
/// code returns to the scheduler loop.
#[derive(Clone, Copy, Debug)]
pub(crate) struct NativeEntry {
    /// `c_p->i` the process is entered at.
    pub(crate) code_address: usize,
    /// The debug knobs read once for this entry.
    debug: u8,
}

/// Set up the entry at `code_address`: everything process_main does between `erts_schedule`
/// returning and `jmp c_p->i` (copy_in_registers, the heap invariant, `c_p->i`/`c_p->arity`).
/// A native continuation (`native_arity_set`) with no debug knob set needs no registry
/// lookup, entry-return peek or bridge registration; a function entry does.
// Port of erts/emulator/beam/jit/x86/process_main.cpp:265-300 and
// jit/arm/process_main.cpp:235-317 (copy_in_registers, `br c_p->i`), OTP-29.1.1.
#[inline(always)]
pub(crate) fn native_prepare(
    process: &mut Process,
    registers: &mut SchedulerRegisters,
    code_address: usize,
) -> Result<NativeEntry, VmError> {
    let debug = crate::debug_env::slice::get();
    if !crate::debug_env::slice::plain_entry(debug)
        || !process.native_continuation_resume
        || !process.native_arity_set
    {
        return native_prepare_entry(process, registers, code_address);
    }
    process.native_continuation_resume = false;
    process.native_arity_set = false;
    process.native_error_pc = 0;
    registers.tmp_mem[6] = 0;
    let arity = process.heap.abi.arity;
    process.heap.arm_native_redzone();
    let objv = registers
        .x_reg_array
        .get_mut(..usize::from(arity))
        .ok_or_else(|| VmError::Unsupported("live X register count".into()))?;
    process.ensure_entry(0, objv);
    registers.entry_return = 0;
    // process_main's schedule-in is `jmp c_p->i`: `c_p->current` stays what the process left
    // (ERTS_BIF_PREP_TRAP's trap export, read by beam_bif_export_trap).
    // Port of erts/emulator/beam/jit/x86/process_main.cpp (process_main), OTP-29.1.1.
    process.heap.abi.i = code_address as *const std::ffi::c_void;
    process.heap.abi.arity = arity;
    registers.tmp_mem[3] = 0;
    process.heap.set_native_allocation(true);
    Ok(NativeEntry {
        code_address,
        debug,
    })
}

/// Enter native code at the prepared `c_p->i`; returns when the native code leaves to the
/// scheduler loop.
// Port of erts/emulator/beam/jit/arm/process_main.cpp (`br c_p->i`), OTP-29.1.1.
#[cfg(target_arch = "aarch64")]
#[inline(always)]
pub(crate) fn native_enter(
    process: &mut Process,
    registers: &mut SchedulerRegisters,
    entry: &NativeEntry,
) -> ExitReason {
    // SAFETY: native_prepare checked that the address is a registered executable function
    // using the BeamAsm ABI (or a continuation inside one) and set up its entry state.
    unsafe {
        arinsal_beamasm::enter_native_raw(
            &mut process.heap.abi,
            registers,
            entry.code_address as *const std::ffi::c_void,
        )
    }
}

/// [`native_prepare`] for a function entry or a debug-knob run.
// Port of erts/emulator/beam/jit/arm/process_main.cpp:235-317, OTP-29.1.1
fn native_prepare_entry(
    process: &mut Process,
    registers: &mut SchedulerRegisters,
    code_address: usize,
) -> Result<NativeEntry, VmError> {
    debug_assert!(
        process.x.is_attached(),
        "native code runs on the scheduler's X array: attach the registers first"
    );
    // Debug knobs are environment switches held in one byte: read once per entry.
    let debug = crate::debug_env::slice::get();
    let return_trace = debug & crate::debug_env::slice::RETURN_TRACE != 0;
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
            registers.x_reg_array[0].tagged_word()
        );
    }
    process.native_error_pc = 0;
    registers.tmp_mem[6] = 0;
    #[cfg(target_arch = "aarch64")]
    crate::beamasm_integration::set_trace_return_hook(registers);
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
        process.heap.abi.arity
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
    let objv = registers
        .x_reg_array
        .get_mut(..live)
        .ok_or_else(|| VmError::Unsupported("live X register count".into()))?;
    process.ensure_entry(0, objv);
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
            registers.x_reg_array[0].tagged_word(),
            process.heap.abi.exc.freason
        );
    }
    // `jmp c_p->i` leaves `c_p->current` as the process left it (see native_prepare).
    process.heap.abi.i = code_ptr;
    process.heap.abi.arity = arity;
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
    Ok(NativeEntry {
        code_address,
        debug,
    })
}

/// Whether `erts_do_exit_process` ran in this slice (handle_error's terminate_proc): the exit
/// yielded with `p->u.terminate` set, or the process is FREE in `p->state`.
fn terminated_in_slice(process: &mut Process) -> bool {
    process.has_exit_cont()
        || arinsal_sched::erts_proc_sched_data(process, |_, esdp| {
            arinsal_sched::RunCtx::with_current(esdp, |ctx| {
                ctx.proc_state().load(Ordering::Acquire) & arinsal_sched::psflg::FREE != 0
            })
        })
        .flatten()
        .unwrap_or(false)
}

/// Leaves native code: classifies the exit, raises the exception it carries, or sets the
/// continuation the process resumes at.
// Port of erts/emulator/beam/jit/arm/process_main.cpp (the code after a native call returns
// to `process_main`) and beam_common.c (handle_error), OTP-29.1.1.
pub(crate) fn native_exit(
    process: &mut Process,
    registers: &mut SchedulerRegisters,
    entry: NativeEntry,
    exit: ExitReason,
) -> Result<ExitReason, VmError> {
    let NativeEntry {
        code_address,
        debug,
    } = entry;
    process.heap.set_native_allocation(false);
    let return_trace = debug & crate::debug_env::slice::RETURN_TRACE != 0;
    let exception_trace = debug & crate::debug_env::slice::EXCEPTION_TRACE != 0;
    if exception_trace {
        let (base, end) = process.heap.heap_bounds();
        let (_, current_stop) = process.heap.heap_cursor();
        let requested_stop = process.heap.abi.stop as usize;
        if requested_stop < base as usize || requested_stop > end as usize {
            let module = native_function_at(code_address)
                .map_or_else(|| "?".to_owned(), |function| function.module.to_owned());
            eprintln!(
                "native return stack pointer out of range module={} pc={code_address:#x} exit={exit:?} base={base:p} end={end:p} current_stop={current_stop:p} requested_stop={:#x} htop={:p}",
                module, requested_stop, process.heap.abi.htop
            );
        }
    }
    if return_trace && let Some(function) = native_function_at(code_address) {
        eprintln!(
            "[native-exit] {}:{}/{} pc={code_address:#x} exit={exit:?} x0={:#x} i={:p} stop={:p}",
            function.module,
            function.function,
            function.arity,
            registers.x_reg_array[0].tagged_word(),
            process.heap.abi.i,
            process.heap.abi.stop
        );
    }
    // Port of erts/emulator/beam/jit/arm/instr_bif.cpp:533-540, OTP-29.1.1.
    // A VM-backed light BIF leaves TRAP for the scheduler when it exits native code.
    // A call handed to the scheduler keeps its call site too, for a BIF that raises there.
    if process.heap.abi.exc.freason == arinsal_term::exc::TRAP
        || matches!(exit, ExitReason::CallUnported { .. })
    {
        process.native_error_pc = registers.tmp_mem[6] as usize;
    }
    if process.heap.abi.exc.freason != 0
        && process.heap.abi.exc.freason != 1 << 10
        && exception_trace
    {
        eprintln!(
            "native exception freason={:#x} fvalue={:?} at {:?}",
            process.heap.abi.exc.freason,
            arinsal_term::to_owned(crate::native_hooks::from_raw(process.heap.abi.exc.fvalue))
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
    // TRAP is not an exception class: erts' bif/nif epilogue (jit/arm/instr_bif.cpp:676-700,
    // emit_bif_nif_epilogue) only uses it to pick the context switch, and nothing reads it
    // after `context_switch_simplified`.
    if process.heap.abi.exc.freason == arinsal_term::exc::TRAP {
        process.heap.abi.exc.freason = 0;
    }
    // Port of erts/emulator/beam/jit/x86/beam_asm_global.cpp:304-385 (process_exit /
    // raise_exception_shared), OTP-29.1.1: every raise in generated code calls handle_error,
    // which branches to the catch or terminates the process in place and returns NULL; the
    // code then goes to `do_schedule`. A failure word left nonzero here is the
    // PRIMARY_EXCEPTION a caught exception keeps, not a pending failure.
    if terminated_in_slice(process) {
        return Err(VmError::Yield);
    }
    let outcome = match exit {
        ExitReason::CallUnported { .. } => {
            process.set_native_pc(None);
            exit
        }
        ExitReason::Yield => {
            let resume = process.heap.abi.i as usize;
            let bridge_return =
                arinsal_beamasm::rt::arinsal_enter_native_return as *const () as usize;
            if resume == bridge_return {
                // The native function has returned into the exit bridge: the normal
                // return path continues with what lies below (an interpreter caller,
                // or nothing when the process is done).
                process.set_native_pc(None);
                ExitReason::Returned
            } else {
                process.native_continuation_resume = true;
                // The yield site stored its live X register count in `c_p->arity`.
                process.native_arity_set = true;
                process.gc_live = usize::from(process.heap.abi.arity);
                process.set_native_pc(Some(if resume == 0 { code_address } else { resume }));
                ExitReason::Yield
            }
        }
        ExitReason::Returned => {
            process.set_native_pc(None);
            ExitReason::Returned
        }
        ExitReason::Unsupported => {
            process.set_native_pc(None);
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
        for part in [function.module, ":", function.function, "/"] {
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

    fn function(start: usize, module: &str) -> NativeFunction {
        let atoms = arinsal_term::global_atoms();
        NativeFunction {
            fragment: false,
            start,
            end: start + 16,
            module: atoms
                .text(atoms.intern(module).expect("module atom"))
                .expect("text"),
            module_atom: atoms.intern(module).expect("module atom"),
            function: "spin",
            function_atom: atoms.intern("spin").expect("function atom"),
            arity: 0,
            line: None,
            file: None,
            file_term: None,
            line_table: NativeLines::default(),
        }
    }

    #[test]
    fn function_lookup_uses_function_boundaries_with_end_sentinel() {
        let first = function(0x1000, "native_bridge_compact_functions");
        let second = function(0x1020, "native_bridge_compact_functions");
        let range = module_range(
            0x1000,
            0x1040,
            Arc::from(vec![first.clone(), second.clone()]),
        );

        similar_asserts::assert_eq!(range.function_starts.as_ref(), &[0x1000, 0x1020, 0x1040]);
        similar_asserts::assert_eq!(
            function_in(&range, 0x100f).map(|f| f.start),
            Some(first.start)
        );
        // `functions[mid + 1]` bounds a function in erts, so intervening code bytes stay
        // assigned to the preceding function until the next code-info entry.
        similar_asserts::assert_eq!(
            function_in(&range, 0x1010).map(|f| f.start),
            Some(first.start)
        );
        similar_asserts::assert_eq!(
            function_in(&range, 0x1020).map(|f| f.start),
            Some(second.start)
        );
    }

    // A load can snapshot the active range while purge retires that version. The next load
    // may then reuse the same executable span; it must replace the retired staging entry.
    #[test]
    fn purge_reload_replaces_ranges_after_a_staging_snapshot() {
        // A private instance: the test replaces the whole range table.
        let indexes = Arc::new(crate::code_ix::CodeIndexes::new());
        let atoms = arinsal_term::global_atoms();
        let module_atom = atoms
            .intern("native_bridge_purge_reload")
            .expect("module atom");
        let function_atom = atoms.intern("f").expect("function atom");
        let start = 0x1000;
        let end = 0x1100;
        let function = NativeFunction {
            fragment: false,
            start,
            end,
            module: "native_bridge_purge_reload",
            module_atom,
            function: "f",
            function_atom,
            arity: 0,
            line: None,
            file: None,
            file_term: None,
            line_table: NativeLines::default(),
        };
        let range = || module_range(start, end, Arc::from(vec![function.clone()]));
        indexes.store_code_ranges(Arc::new(vec![range()]));

        for _ in 0..32 {
            // Starting a new code load snapshots the old module's range into staging.
            let staging = indexes.start_staging();
            // Purge removes it before executable memory can be returned to the allocator.
            indexes.remove_code_range(start, end);
            // The allocator reuses that span for a reload before this staging commit.
            indexes.add_staging_code_range(range());
            drop(staging);

            indexes.with_code_ranges(|ranges| {
                similar_asserts::assert_eq!(ranges.len(), 1);
                similar_asserts::assert_eq!((ranges[0].start(), ranges[0].end()), (start, end));
            });
        }
    }
}
