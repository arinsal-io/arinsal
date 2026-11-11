//! Module tables of an OTP 29 BEAM file: imports, exports, literals, lambdas, line and debug tables.

use arinsal_beam::{BeamFile, Instr as BeamInstr, Operand};
use arinsal_bifs::BifFn;
use arinsal_spec::Opcode;
use arinsal_term::{Atom, Term, TermBuilder, VecHeap, from_owned, global_atoms};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicU32, AtomicU64, AtomicUsize, Ordering};

// ---- vm_funs ----
mod funs;
pub use funs::{FunSlot, beamfile_chunk, module_uniq};

fn is_line_debug_instruction(file: &BeamFile, instruction: &BeamInstr) -> bool {
    instruction.op == Opcode::DebugLine
        && matches!(instruction.args.first(), Some(Operand::Atom(index)) if file.atom(*index).is_some_and(|kind| kind != "entry"))
}

/// How an import slot is called. Fixed at load and updated when the VM
/// binds process-aware natives. The hot path loads this tag and makes one
/// indirect call.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ImportClass {
    /// Not classified yet.
    Fresh = 0,
    /// Pure BIF or static NIF. [`Import::bif`] or [`Import::bif_fn`] is set.
    Pure = 1,
    /// Process-aware native resolved to one function pointer.
    Native = 2,
    /// `erlang:apply`, `make_fun`, or `fun_info`.
    Fun = 3,
    /// Erlang export whose slot may still need a load.
    Remote = 5,
    /// `bif.tab` entry with no implementation.
    Unsupported = 6,
    /// A native that depends on VM state or has a miss side effect.
    Dynamic = 7,
}

/// Resolved external call.
pub struct Import {
    /// Module name: the text of `module_atom`.
    pub module: &'static str,
    /// Function name: the text of `function_atom`.
    pub function: &'static str,
    /// Module atom resolved while loading the BEAM import.
    pub module_atom: Atom,
    /// Function atom resolved while loading the BEAM import.
    pub function_atom: Atom,
    /// Arity.
    pub arity: u8,
    /// Bound BIF function when implemented.
    pub bif: Option<BifFn>,
    class: AtomicU8,
    /// Packed native entry. Zero when [`ImportClass`] is not [`ImportClass::Native`].
    native: AtomicUsize,
    /// Static NIF pointer when the loader's BIF table had none.
    extra_bif: AtomicUsize,
}
impl Clone for Import {
    fn clone(&self) -> Self {
        Self {
            module: self.module,
            function: self.function,
            module_atom: self.module_atom,
            function_atom: self.function_atom,
            arity: self.arity,
            bif: self.bif,
            class: AtomicU8::new(self.class.load(Ordering::Acquire)),
            native: AtomicUsize::new(self.native.load(Ordering::Acquire)),
            extra_bif: AtomicUsize::new(self.extra_bif.load(Ordering::Acquire)),
        }
    }
}

impl Import {
    /// Call classification. [`ImportClass::Fresh`] until the VM binds the slot.
    #[inline]
    pub fn class(&self) -> ImportClass {
        match self.class.load(Ordering::Acquire) {
            1 => ImportClass::Pure,
            2 => ImportClass::Native,
            3 => ImportClass::Fun,
            5 => ImportClass::Remote,
            6 => ImportClass::Unsupported,
            7 => ImportClass::Dynamic,
            _ => ImportClass::Fresh,
        }
    }
    /// Publish the classification. Safe to call before the module is shared.
    pub fn set_class(&self, class: ImportClass) {
        self.class.store(class as u8, Ordering::Release);
    }
    /// Opaque native entry written by the VM resolver.
    pub fn set_native_bits(&self, bits: usize) {
        self.native.store(bits, Ordering::Release);
    }
    /// Opaque native entry. Zero when this import is not a process-aware native.
    pub fn native_bits(&self) -> usize {
        self.native.load(Ordering::Acquire)
    }
    /// Remember a static NIF that the BIF table did not list.
    pub fn set_extra_bif(&self, bif: BifFn) {
        self.extra_bif.store(bif as usize, Ordering::Release);
    }
    /// Pure BIF or static NIF pointer.
    #[inline]
    pub fn bif_fn(&self) -> Option<BifFn> {
        if let Some(bif) = self.bif {
            return Some(bif);
        }
        let extra = self.extra_bif.load(Ordering::Acquire);
        if extra == 0 {
            return None;
        }
        // SAFETY: `set_extra_bif` stores only a `BifFn` function pointer.
        Some(unsafe { std::mem::transmute::<usize, BifFn>(extra) })
    }
}

/// An exported function of a module.
pub struct ExportSlot {
    /// Module name: the text of `module_atom`.
    pub module: &'static str,
    /// Function name: the text of `function_atom`.
    pub function: &'static str,
    /// Arity.
    pub arity: u8,
    /// Module atom index used by the VM export table.
    pub module_atom: Atom,
    /// Function atom index used by the VM export table.
    pub function_atom: Atom,
    target_index: usize,
}
impl ExportSlot {
    /// Entry offset of the exported function.
    pub fn target(&self) -> usize {
        self.target_index
    }
}

/// Executable module and its out-of-line data.
pub struct Module {
    /// Module atom text.
    pub name: String,
    /// Module atom resolved while loading this code.
    pub name_atom: Atom,
    /// Native record definitions decoded from this module's `Recs` chunk.
    pub records: Vec<arinsal_beam::NativeRecord>,
    /// `[Definition | Defaults]` literal of each of `records`, in the module's literal area.
    pub record_defs: Vec<Term>,
    /// Resolved imports.
    pub imports: Vec<Import>,
    /// Replaceable exports.
    pub exports: Vec<Arc<ExportSlot>>,
    /// Export slots indexed by stable atom identities and arity.
    pub export_atoms: HashMap<(Atom, u8), usize>,
    /// Module string table used by bit syntax string segments.
    pub strings: Box<[u8]>,
    /// Literal file-name lists indexed by source filename.
    pub line_file_terms: HashMap<String, Term>,
    /// Function names and arities at their `func_info` instruction offsets.
    pub functions: Vec<(usize, &'static str, u8)>,
    /// Function atoms parallel to `functions`.
    pub function_atoms: Vec<Atom>,
    /// Functions whose code starts with `nif_start`: the stubs `erlang:load_nif/2` may bind.
    /// `None` when the module has no `nif_start` at all, in which case any function may.
    // Port of erts `BeamCodeHeader.are_nifs` (erts/emulator/beam/beam_code.h:127), OTP-29.1.1.
    pub nif_stubs: Option<Vec<(&'static str, u8)>>,
    /// The NIF body bound to each function of `functions` (an index into the node's native
    /// function table), or [`NO_NIF_BODY`]. Written by the loader for static NIFs and by
    /// `load_nif`.
    // Port of erts/emulator/beam/erl_nif.c (the call_nif code `load_nif_1st_finisher` patches
    // behind a NIF function's prologue), OTP-29.1.1.
    pub nif_bodies: Box<[AtomicU32]>,
    /// Original function entry indices parallel to `exports`.
    pub export_entry_targets: Box<[usize]>,
    /// Coverage state allocated only when coverage was enabled at load time.
    pub coverage: Option<Coverage>,
    /// Whether this module was loaded with OTP's line breakpoint instrumentation.
    pub line_breakpoints_supported: bool,
    /// Retained compiler debug points as `(instruction, line, live-register-count)`.
    pub debug_line_points: Vec<(usize, u32, u16)>,
    /// `(DbgB item index, line)` of each debug line probe, in code order.
    pub debug_line_items: Vec<(u32, u32)>,
    /// Synthetic `error_handler:breakpoint/3` import used by debug breakpoints.
    pub debug_breakpoint_import: u32,
    // ---- vm_funs ----
    /// Local lambda entries retained by closures.
    pub funs: Vec<FunSlot>,
    _literals: LiteralArea,
    /// Module literals by BEAM literal index, in this module's literal area. Native code
    /// of the module refers to these same terms, like erts' single literal area per module.
    literal_terms: Arc<HashMap<u32, Term>>,
}
/// The value of a [`Module::nif_bodies`] slot with no NIF body.
pub const NO_NIF_BODY: u32 = u32::MAX;

fn unbound_nif_bodies(count: usize) -> Box<[AtomicU32]> {
    (0..count).map(|_| AtomicU32::new(NO_NIF_BODY)).collect()
}

impl Clone for Module {
    fn clone(&self) -> Self {
        Self {
            name: self.name.clone(),
            name_atom: self.name_atom,
            records: self.records.clone(),
            record_defs: self.record_defs.clone(),
            imports: self.imports.clone(),
            exports: self.exports.clone(),
            export_atoms: self.export_atoms.clone(),
            strings: self.strings.clone(),
            line_file_terms: self.line_file_terms.clone(),
            functions: self.functions.clone(),
            function_atoms: self.function_atoms.clone(),
            nif_stubs: self.nif_stubs.clone(),
            nif_bodies: self
                .nif_bodies
                .iter()
                .map(|body| AtomicU32::new(body.load(Ordering::Acquire)))
                .collect(),
            export_entry_targets: self.export_entry_targets.clone(),
            coverage: self.coverage.clone(),
            line_breakpoints_supported: self.line_breakpoints_supported,
            debug_line_points: self.debug_line_points.clone(),
            debug_line_items: self.debug_line_items.clone(),
            debug_breakpoint_import: self.debug_breakpoint_import,
            funs: self.funs.iter().map(FunSlot::clone).collect(),
            _literals: self._literals.clone(),
            literal_terms: Arc::clone(&self.literal_terms),
        }
    }
}

/// A module's literal heap, shared by every clone of the module and by its native code.
/// Purge hands the heap to the literal-area release queue and empties the slot, so the module
/// table entry and native code no longer keep literal refc binaries alive.
// Port of erts/emulator/beam/beam_bif_load.c (erts_internal:purge_module_2 -> literal area
// queued for release, erts_queue_release_literals), OTP-29.1.1.
#[derive(Clone)]
pub struct LiteralArea(Arc<std::sync::Mutex<Option<Arc<VecHeap>>>>);

impl LiteralArea {
    fn new(heap: VecHeap) -> Self {
        Self(Arc::new(std::sync::Mutex::new(Some(Arc::new(heap)))))
    }

    fn empty() -> Self {
        Self(Arc::new(std::sync::Mutex::new(None)))
    }

    /// Removes the literal heap from the module; `None` when it was already released.
    pub fn take(&self) -> Option<Arc<VecHeap>> {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).take()
    }
}

/// Coverage modes accepted by `code:set_coverage_mode/1`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum CoverageMode {
    /// No coverage instrumentation.
    #[default]
    None,
    /// Function flags.
    Function,
    /// Function counters.
    FunctionCounters,
    /// Executable-line flags.
    Line,
    /// Executable-line counters.
    LineCounters,
}

/// Atomic coverage storage updated by BeamAsm code.
#[derive(Clone)]
pub struct Coverage {
    /// Mode selected when the module was loaded.
    pub mode: CoverageMode,
    /// Function or line counters, indexed by the probe metadata.
    storage: CoverageStorage,
    /// Line number for each line probe.
    pub lines: Box<[u32]>,
    /// Compiler cover identifier for each line probe.
    pub cover_ids: Box<[u32]>,
    /// BEAM line-table location index for each line probe.
    pub locations: Box<[u32]>,
    /// Compiler marker IDs and counter slots for each executable-line instruction.
    pub line_probe_mappings: Box<[(u32, u32, u32)]>,
    /// Function-table index owning each probe.
    pub function_owners: Box<[u32]>,
}

#[derive(Clone)]
enum CoverageStorage {
    Flags(Arc<[AtomicU8]>),
    Counters(Arc<[AtomicU64]>),
}

impl Coverage {
    fn new(mode: CoverageMode, count: usize) -> Self {
        let storage = match mode {
            CoverageMode::Function | CoverageMode::Line => CoverageStorage::Flags(
                (0..count)
                    .map(|_| AtomicU8::new(0))
                    .collect::<Vec<_>>()
                    .into(),
            ),
            CoverageMode::FunctionCounters | CoverageMode::LineCounters => {
                CoverageStorage::Counters(
                    (0..count)
                        .map(|_| AtomicU64::new(0))
                        .collect::<Vec<_>>()
                        .into(),
                )
            }
            CoverageMode::None => CoverageStorage::Counters(Arc::from([])),
        };
        Self {
            mode,
            storage,
            lines: Box::new([]),
            cover_ids: Box::new([]),
            locations: Box::new([]),
            line_probe_mappings: Box::new([]),
            function_owners: Box::new([]),
        }
    }

    /// Number of function or line probes retained by this code version.
    pub fn len(&self) -> usize {
        match &self.storage {
            CoverageStorage::Flags(values) => values.len(),
            CoverageStorage::Counters(values) => values.len(),
        }
    }

    /// Whether this code version has no function or line probes.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Whether this mode stores one-byte flags rather than machine-word counters.
    pub fn stores_flags(&self) -> bool {
        matches!(&self.storage, CoverageStorage::Flags(_))
    }

    /// Read the counter for `index`, if it exists.
    pub fn load(&self, index: usize) -> Option<u64> {
        Some(match &self.storage {
            CoverageStorage::Flags(values) => u64::from(values.get(index)?.load(Ordering::Relaxed)),
            CoverageStorage::Counters(values) => values.get(index)?.load(Ordering::Relaxed),
        })
    }

    /// Mark a flag or increment a counter, matching the storage selected by the mode.
    pub fn hit(&self, index: usize) {
        match &self.storage {
            CoverageStorage::Flags(values) => {
                if let Some(flag) = values.get(index) {
                    flag.store(1, Ordering::Relaxed);
                }
            }
            CoverageStorage::Counters(values) => {
                if let Some(counter) = values.get(index) {
                    counter.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }

    /// Clear every probe.
    pub fn reset(&self) {
        match &self.storage {
            CoverageStorage::Flags(values) => {
                for flag in values.iter() {
                    flag.store(0, Ordering::Relaxed);
                }
            }
            CoverageStorage::Counters(values) => {
                for counter in values.iter() {
                    counter.store(0, Ordering::Relaxed);
                }
            }
        }
    }

    /// Stable address of a probe retained by this code version.
    pub fn probe_address(&self, index: usize) -> Option<usize> {
        Some(match &self.storage {
            CoverageStorage::Flags(values) => values.get(index)?.as_ptr() as usize,
            CoverageStorage::Counters(values) => values.get(index)?.as_ptr() as usize,
        })
    }
}

impl Module {
    /// Drop code and code-specific metadata after no process can reference this version.
    /// Callers must queue its literal area first; export and lambda entries remain alive.
    // Port of erts/emulator/beam/beam_bif_load.c
    // (erts_internal_purge_module_2 complete frees old.code_hdr), OTP-29.1.1.
    pub fn release_code(&mut self) {
        self.records = Vec::new();
        self.record_defs = Vec::new();
        self.imports = Vec::new();
        self.export_atoms = HashMap::new();
        self.strings = Box::new([]);
        self.line_file_terms = HashMap::new();
        self.functions = Vec::new();
        self.function_atoms = Vec::new();
        self.nif_stubs = None;
        self.nif_bodies = Box::new([]);
        self.export_entry_targets = Box::new([]);
        self.coverage = None;
        self.line_breakpoints_supported = false;
        self.debug_line_points = Vec::new();
        self.debug_line_items = Vec::new();
        self.debug_breakpoint_import = 0;
        self.literal_terms = Arc::new(HashMap::new());
        self._literals = LiteralArea::empty();
    }

    /// Retain this code version's literal heap for process root scanning.
    pub fn literal_area(&self) -> LiteralArea {
        self._literals.clone()
    }

    /// The literal-area term of BEAM literal `index` (every literal of the file is decoded when
    /// the module is loaded, as `beamfile_read` does).
    pub fn literal_term(&self, index: u32) -> Option<Term> {
        self.literal_terms.get(&index).copied()
    }

    /// Find an exported function and arity.
    pub fn export(&self, function: &str, arity: u8) -> Option<usize> {
        self.export_slot(function, arity).map(ExportSlot::target)
    }
    /// Find the atomic export entry for a function and arity.
    pub fn export_slot(&self, function: &str, arity: u8) -> Option<&ExportSlot> {
        self.exports
            .iter()
            .find(|e| e.function == function && e.arity == arity)
            .map(Arc::as_ref)
    }
    /// Find an export using stable atom identities.
    #[inline]
    pub fn export_slot_atom(&self, function: Atom, arity: u8) -> Option<&ExportSlot> {
        self.export_atoms
            .get(&(function, arity))
            .and_then(|index| self.exports.get(*index))
            .map(Arc::as_ref)
    }
    /// Name and arity of the function containing a code offset.
    pub fn function_at(&self, ip: usize) -> Option<(&str, u8)> {
        self.functions
            .iter()
            .rev()
            .find(|(start, _, _)| *start <= ip)
            .map(|(_, name, arity)| (*name, *arity))
    }
    /// The ordinal in `functions` of the function whose entry is code offset `entry`.
    pub fn function_by_entry(&self, entry: usize) -> Option<usize> {
        let index = self
            .functions
            .partition_point(|(start, _, _)| start.saturating_add(1) < entry);
        (self.functions.get(index)?.0.saturating_add(1) == entry).then_some(index)
    }
    /// The NIF body bound to function `ordinal`, if any.
    pub fn nif_body(&self, ordinal: usize) -> Option<u32> {
        let body = self.nif_bodies.get(ordinal)?.load(Ordering::Acquire);
        (body != NO_NIF_BODY).then_some(body)
    }
    /// Binds NIF body `index` to function `ordinal`.
    pub fn set_nif_body(&self, ordinal: usize, index: u32) {
        if let Some(slot) = self.nif_bodies.get(ordinal) {
            slot.store(index, Ordering::Release);
        }
    }
    /// Atom and arity of the function containing a code offset.
    pub fn function_atom_at(&self, ip: usize) -> Option<(Atom, u8)> {
        let index = self.functions.partition_point(|(start, _, _)| *start <= ip);
        let index = index.checked_sub(1)?;
        Some((*self.function_atoms.get(index)?, self.functions[index].2))
    }
}

/// Malformed module or exhausted atom table.
#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    /// Invalid index.
    #[error("invalid {0} index {1}")]
    Index(&'static str, u32),
    /// Atom table rejected an atom.
    #[error("atom table rejected {0}")]
    Atom(String),
    /// Module exceeds an internal limit.
    #[error("module exceeds instruction index limit")]
    Limit,
}

/// The coverage table of a module whose code goes to BeamAsm only: the counters the emitted
/// `emit_coverage` sequences update and the metadata `code:get_coverage/2` reports. `None`
/// when the module gets no coverage. `file` must have its instructions decoded.
// Port of erts/emulator/beam/jit/asm_load.c:73-135 (beam_load_prepare_emit: coverage mode and
// table allocation) and :681-711, :752-769 (the table slots of executable_line / functions),
// OTP-29.1.1.
pub fn native_coverage(
    file: &BeamFile,
    requested_mode: CoverageMode,
) -> Result<Option<Coverage>, LoadError> {
    let CoverageScan {
        coverage_mode,
        count,
        coverage_enabled,
        function_mode,
        source_functions,
        counter_lines,
        counter_ids,
        counter_locations,
        line_probe_mappings,
        mut function_owners,
        ..
    } = scan_coverage(file, requested_mode)?;
    if !coverage_enabled {
        return Ok(None);
    }
    if function_mode {
        // One slot per function that has a body.
        for (owner, start) in source_functions.iter().enumerate() {
            if start.saturating_add(1) < count {
                function_owners.push(owner as u32);
            }
        }
    }
    let coverage_count = function_owners.len();
    Ok(Some(Coverage {
        lines: counter_lines.into_boxed_slice(),
        cover_ids: counter_ids.into_boxed_slice(),
        locations: counter_locations.into_boxed_slice(),
        line_probe_mappings: line_probe_mappings.into_boxed_slice(),
        function_owners: function_owners.into_boxed_slice(),
        ..Coverage::new(coverage_mode, coverage_count)
    }))
}

/// Installs the debugger line metadata of a module whose code goes to BeamAsm only and was
/// loaded with line breakpoint instrumentation: whether it supports line breakpoints, its
/// debug points and the `DbgB` item of each. A point is keyed by the entry slot of its
/// function in the numbering [`Module::finish_native`] gives (`2 * ordinal + 1`), as the
/// module has no instruction stream. `file` must have its instructions decoded.
// Port of erts/emulator/beam/jit/asm_load.c:714-737 (i_debug_line entries of the line table)
// and erl_debugger.c (the per-function line sets), OTP-29.1.1.
pub fn set_native_debug_lines(module: &mut Module, file: &BeamFile) {
    let mut ordinal = None::<usize>;
    let mut points = Vec::new();
    let mut items = Vec::new();
    for instruction in &file.code.instructions {
        if instruction.op == Opcode::FuncInfo {
            ordinal = Some(ordinal.map_or(0, |ordinal| ordinal + 1));
            continue;
        }
        if !is_line_debug_instruction(file, instruction) {
            continue;
        }
        let Some(ordinal) = ordinal else { continue };
        let kind = instruction.args.first().and_then(|operand| match operand {
            Operand::Atom(index) => file.atom(*index),
            _ => None,
        });
        let line = instruction
            .args
            .get(1)
            .and_then(|operand| match operand {
                Operand::U(index) => usize::try_from(*index).ok(),
                _ => None,
            })
            .and_then(|index| {
                file.lines
                    .as_ref()
                    .and_then(|table| index.checked_sub(1).and_then(|i| table.items.get(i)))
            })
            .and_then(|item| u32::try_from(item.line).ok());
        let live = instruction.args.get(3).and_then(|operand| match operand {
            Operand::U(live) => u16::try_from(*live).ok(),
            _ => None,
        });
        if kind == Some("line")
            && let (Some(line), Some(live)) = (line, live)
            && line > 0
        {
            points.push((2 * ordinal + 1, line, live));
            if let Some(Operand::U(index)) = instruction.args.get(2)
                && let Some(index) = index.checked_sub(1)
            {
                items.push((index as u32, line));
            }
        }
    }
    module.line_breakpoints_supported = file
        .code
        .instructions
        .iter()
        .any(|instruction| is_line_debug_instruction(file, instruction));
    module.debug_line_points = points;
    module.debug_line_items = items;
}

/// Whether a module loaded now gets coverage tables (asm_load.c:79-95 resolves its mode to
/// something other than none).
pub fn coverage_enabled_for(file: &BeamFile, requested_mode: CoverageMode) -> bool {
    !matches!(
        effective_coverage_mode(file, requested_mode),
        CoverageMode::None
    )
}

// Port of erts/emulator/beam/jit/asm_load.c:79-95, OTP-29.1.1.
fn effective_coverage_mode(file: &BeamFile, requested_mode: CoverageMode) -> CoverageMode {
    match (file.lines.as_ref(), requested_mode) {
        (Some(lines), _) if lines.flags & 2 != 0 => CoverageMode::LineCounters,
        (lines, CoverageMode::Line | CoverageMode::LineCounters)
            if lines.is_none_or(|lines| lines.flags & 1 == 0) =>
        {
            CoverageMode::None
        }
        (_, mode) => mode,
    }
}

/// What the first pass over the instructions finds: the module's coverage mode and table
/// layout.
struct CoverageScan {
    coverage_mode: CoverageMode,
    count: usize,
    coverage_enabled: bool,
    function_mode: bool,
    source_functions: Vec<usize>,
    counter_lines: Vec<u32>,
    counter_ids: Vec<u32>,
    counter_locations: Vec<u32>,
    line_probe_mappings: Vec<(u32, u32, u32)>,
    function_owners: Vec<u32>,
}

fn scan_coverage(file: &BeamFile, requested_mode: CoverageMode) -> Result<CoverageScan, LoadError> {
    let coverage_mode = effective_coverage_mode(file, requested_mode);
    let mut count = 0_usize;
    let coverage_enabled = matches!(
        coverage_mode,
        CoverageMode::Function
            | CoverageMode::FunctionCounters
            | CoverageMode::Line
            | CoverageMode::LineCounters
    );
    let function_mode = matches!(
        coverage_mode,
        CoverageMode::Function | CoverageMode::FunctionCounters
    );
    let mut source_functions = Vec::new();
    let mut counter_lines = Vec::new();
    let mut counter_ids = Vec::new();
    let mut counter_locations = Vec::new();
    let mut line_probe_mappings = Vec::new();
    let mut function_owners = Vec::new();
    let mut previous_line_location = None;
    let mut previous_line_probe = None;
    let line_mode = matches!(
        coverage_mode,
        CoverageMode::Line | CoverageMode::LineCounters
    );
    for instruction in &file.code.instructions {
        if instruction.op == Opcode::Label {
            // Labels take no slot of their own.
        } else if instruction.op == Opcode::Line {
            // Port of erts/emulator/beam/jit/asm_load.c:318-348 (add_line_entry), OTP-29.1.1.
            if let Some(Operand::U(location)) = instruction.args.first()
                && *location != 0
                && let Ok(location) = u32::try_from(*location)
                && previous_line_location != Some(location)
            {
                previous_line_location = Some(location);
                previous_line_probe = None;
            }
        } else if instruction.op == Opcode::DebugLine {
            // Port of erts/emulator/beam/jit/asm_load.c:715-735, OTP-29.1.1: debugger line
            // entries keep duplicates, so a following executable-line marker gets its own slot.
            if let Some(Operand::U(location)) = instruction.args.get(1)
                && let Ok(location) = u32::try_from(*location)
            {
                previous_line_location = Some(location);
                previous_line_probe = None;
            }
        } else if instruction.op != Opcode::Line && instruction.op != Opcode::NifStart {
            if instruction.op == Opcode::FuncInfo {
                // Port of erts/emulator/beam/jit/asm_load.c:642-647 (func_line), OTP-29.1.1:
                // each function's coverage locations start at its recorded line-table boundary.
                if line_mode {
                    previous_line_location = None;
                    previous_line_probe = None;
                }
                source_functions.push(count);
            }
            if instruction.op == Opcode::ExecutableLine {
                let location = instruction.args.first().and_then(|arg| match arg {
                    Operand::U(value) => usize::try_from(*value).ok(),
                    _ => None,
                });
                let cover_id = instruction.args.get(1).and_then(|arg| match arg {
                    Operand::U(value) => u32::try_from(*value).ok(),
                    _ => None,
                });
                if line_mode && let (Some(location), Some(cover_id)) = (location, cover_id) {
                    let line = file
                        .lines
                        .as_ref()
                        .and_then(|table| location.checked_sub(1).and_then(|i| table.items.get(i)))
                        .and_then(|item| u32::try_from(item.line).ok())
                        .unwrap_or(0);
                    if let Ok(location) = u32::try_from(location) {
                        // Port of erts/emulator/beam/jit/asm_load.c:681-711: consecutive line
                        // markers for one location share the line table's coverage slot.
                        let counter = if previous_line_location == Some(location) {
                            if let Some(counter) = previous_line_probe {
                                counter
                            } else {
                                let counter = counter_lines.len();
                                let owner = source_functions.len().saturating_sub(1) as u32;
                                counter_lines.push(line);
                                counter_ids.push(cover_id);
                                counter_locations.push(location);
                                function_owners.push(owner);
                                previous_line_probe = Some(counter);
                                counter
                            }
                        } else {
                            let counter = counter_lines.len();
                            let owner = source_functions.len().saturating_sub(1) as u32;
                            counter_lines.push(line);
                            counter_ids.push(cover_id);
                            counter_locations.push(location);
                            function_owners.push(owner);
                            previous_line_location = Some(location);
                            previous_line_probe = Some(counter);
                            counter
                        };
                        if let Some(existing_id) = counter_ids.get_mut(counter) {
                            *existing_id = cover_id;
                        }
                        line_probe_mappings.push((
                            location,
                            cover_id,
                            u32::try_from(counter).map_err(|_| LoadError::Limit)?,
                        ));
                    }
                }
            }
            count += 1;
        }
    }
    if count > u32::MAX as usize {
        return Err(LoadError::Limit);
    }
    Ok(CoverageScan {
        coverage_mode,
        count,
        coverage_enabled,
        function_mode,
        source_functions,
        counter_lines,
        counter_ids,
        counter_locations,
        line_probe_mappings,
        function_owners,
    })
}

/// What the emitter found out about one function: the facts [`Module::finish_native`] builds the
/// function table, the exports and the lambda targets from.
#[derive(Clone, Copy, Debug)]
pub struct NativeFunction {
    /// The global atom of the function name.
    pub atom: Atom,
    /// Function arity.
    pub arity: u8,
    /// The entry label: the label that follows the function's `func_info`.
    pub entry_label: u32,
    /// Whether a `nif_start` follows the entry label.
    pub nif_stub: bool,
}

/// Build `ERTS_GLOBAL_LIT_ERL_FILE_SUFFIX`, the list `".erl"`.
// Port of erts/emulator/beam/beam_file.c (beamfile_init), OTP-29.1.1. Guarded by a `Once`
// because a VM can boot more than once in one process.
pub fn beamfile_init() {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        let mut build = arinsal_term::global_literal_allocate(8);
        let suffix = TermBuilder::new(&mut build)
            .string_to_list(".erl")
            .expect("file suffix literal");
        arinsal_term::set_global_erl_file_suffix(build.register(suffix));
    });
}

/// The tables of a function-only module, before its code is emitted: the atoms, literals,
/// lambdas, imports and records that `beam_load_prepare_emit` and `beamfile_read` of erts have
/// built when `load_code` starts. The function table, the exports and the lambda targets come
/// from [`Module::finish_native`], once the emitter has seen the functions
/// (`beam_load_finalize_code`). erts has no other form of a module: its code goes from
/// `beamfile_read` through the transform engine to the emitter.
pub fn load_native(file: &BeamFile) -> Result<Module, LoadError> {
    // Port of erts/emulator/beam/beam_file.c:242-291, OTP-29.1.1.
    let atom_ids = file_atoms(file)?;
    let name_atom = Atom(atom_ids[0]);
    let (mut literals, literal_terms) = decode_literals(file)?;
    let funs = funs::load_funs(file)?;
    let mut imports = build_imports(file)?;
    let debug_breakpoint_import = push_breakpoint_import(&mut imports)?;
    // The file names of the line table, as the terms stack traces carry.
    let mut line_file_terms = HashMap::new();
    if let Some(table) = &file.lines {
        let default = format!("{}.erl", file.module);
        // Port of beam_file.c (beamfile_read_lines): the implicit entry is the module
        // name's characters with ERTS_GLOBAL_LIT_ERL_FILE_SUFFIX as the tail.
        let term = TermBuilder::new(&mut literals)
            .string_to_list_with_tail(&file.module, arinsal_term::global_erl_file_suffix())
            .map_err(|_| LoadError::Limit)?;
        line_file_terms.insert(default.clone(), term);
        let names = table
            .names
            .iter()
            .map(String::as_str)
            .filter(|name| !name.is_empty());
        for name in names {
            if !line_file_terms.contains_key(name) {
                let term = TermBuilder::new(&mut literals)
                    .string_to_list(name)
                    .map_err(|_| LoadError::Limit)?;
                line_file_terms.insert(name.to_owned(), term);
            }
        }
    }
    let record_defs = build_record_defs(file, name_atom, &mut literals)?;
    Ok(Module {
        name: file.module.clone(),
        name_atom,
        records: file.records.clone(),
        record_defs,
        imports,
        exports: Vec::new(),
        export_atoms: HashMap::new(),
        strings: file.strings.clone().into_boxed_slice(),
        line_file_terms,
        functions: Vec::new(),
        function_atoms: Vec::new(),
        nif_stubs: None,
        nif_bodies: unbound_nif_bodies(0),
        export_entry_targets: Box::new([]),
        coverage: None,
        line_breakpoints_supported: false,
        debug_line_points: Vec::new(),
        debug_line_items: Vec::new(),
        debug_breakpoint_import,
        funs,
        _literals: LiteralArea::new(literals),
        literal_terms: Arc::new(literal_terms),
    })
}

impl Module {
    /// Whether this module came from [`load_native`] and still awaits
    /// [`finish_native`](Self::finish_native).
    pub fn awaits_native_functions(&self) -> bool {
        self.functions.is_empty()
    }

    /// Completes the module that [`load_native`] began with what the emitter found: the function
    /// table, the NIF stubs, the exports and the targets of the lambdas.
    // Port of erts/emulator/beam/jit/asm_load.c:1177-1260 (beam_load_finalize_code: the code
    // header's function table, then `erts_export_put` per export), OTP-29.1.1.
    pub fn finish_native(
        &mut self,
        file: &BeamFile,
        found: &[NativeFunction],
    ) -> Result<(), LoadError> {
        if 2 * found.len() > u32::MAX as usize {
            return Err(LoadError::Limit);
        }
        let mut labels = HashMap::with_capacity(found.len());
        let mut functions = Vec::with_capacity(found.len());
        let mut function_atoms = Vec::with_capacity(found.len());
        let mut nif_stubs: Option<Vec<(&'static str, u8)>> = None;
        for function in found {
            let name = global_atoms()
                .text(function.atom)
                .ok_or(LoadError::Index("atom", function.atom.0))?;
            // A native-only module has no instruction stream; a function is named by the
            // virtual offset of its `func_info` slot, two per function, and its entry is the one
            // after.
            let start = 2 * functions.len();
            functions.push((start, name, function.arity));
            function_atoms.push(function.atom);
            if function.nif_stub {
                nif_stubs
                    .get_or_insert_with(Vec::new)
                    .push((name, function.arity));
            }
            labels.insert(function.entry_label, start + 1);
        }
        for (slot, lambda) in self.funs.iter_mut().zip(&file.lambdas) {
            slot.target = *labels
                .get(&lambda.label)
                .ok_or(LoadError::Index("label", lambda.label))?;
        }
        let exports = build_exports(file, &labels)?;
        self.export_atoms = exports
            .iter()
            .enumerate()
            .map(|(index, export)| ((export.function_atom, export.arity), index))
            .collect();
        self.export_entry_targets = exports
            .iter()
            .map(|export| export.target())
            .collect::<Vec<_>>()
            .into_boxed_slice();
        self.exports = exports;
        self.nif_bodies = unbound_nif_bodies(functions.len());
        self.functions = functions;
        self.function_atoms = function_atoms;
        self.nif_stubs = nif_stubs;
        Ok(())
    }
}

/// Port of erts/emulator/beam/beam_file.c:1373 (parse_decompressed_literals), OTP-29.1.1: the
/// literal chunk is decoded in index order right after the atom chunk, so atoms first seen in
/// literals get erts' table indices.
pub(crate) fn decode_literals(file: &BeamFile) -> Result<(VecHeap, HashMap<u32, Term>), LoadError> {
    let mut literals = VecHeap::new_literal();
    let mut literal_terms = HashMap::with_capacity(file.literals.len());
    for (index, raw) in file.literals.iter().enumerate() {
        // A literal that does not decode fails the load, as `LoadAssert(!is_non_value(value))`
        // does in erts.
        let term = arinsal_term::decode_literal(&raw.0, &mut literals)
            .ok_or(LoadError::Index("literal", index as u32))?;
        literal_terms.insert(index as u32, term);
    }
    Ok((literals, literal_terms))
}

/// The global atom of each entry of the atom table of `file`, put once per file.
// Port of erts/emulator/beam/beam_file.c (parse_atom_chunk), OTP-29.1.1.
pub fn file_atoms(file: &BeamFile) -> Result<&[u32], LoadError> {
    file.resolved_atoms(|names| {
        global_atoms()
            .intern_all(names.iter())
            .map(|atoms| atoms.into_iter().map(|atom| atom.0).collect())
            .map_err(|(index, _)| LoadError::Atom(names.get(index).unwrap_or_default().to_owned()))
    })
}

/// The import table of a module.
pub(crate) fn build_imports(file: &BeamFile) -> Result<Vec<Import>, LoadError> {
    let atom_ids = file_atoms(file)?;
    file.imports
        .iter()
        .map(|item| {
            let module_atom = Atom(
                *atom_ids
                    .get(item.module_atom as usize - 1)
                    .ok_or(LoadError::Index("atom", item.module_atom))?,
            );
            let function_atom = Atom(
                *atom_ids
                    .get(item.function_atom as usize - 1)
                    .ok_or(LoadError::Index("atom", item.function_atom))?,
            );
            // The names are the text of the atoms the file's table put.
            let module = global_atoms()
                .text(module_atom)
                .ok_or(LoadError::Index("atom", item.module_atom))?;
            let function = global_atoms()
                .text(function_atom)
                .ok_or(LoadError::Index("atom", item.function_atom))?;
            Ok(Import {
                bif: arinsal_bifs::lookup(module, function, item.arity as u8),
                module_atom,
                function_atom,
                module,
                function,
                arity: item.arity as u8,
                class: AtomicU8::new(ImportClass::Fresh as u8),
                native: AtomicUsize::new(0),
                extra_bif: AtomicUsize::new(0),
            })
        })
        .collect::<Result<Vec<_>, LoadError>>()
}

/// The import every module gets for `error_handler:breakpoint/3`.
pub(crate) fn push_breakpoint_import(imports: &mut Vec<Import>) -> Result<u32, LoadError> {
    let index = u32::try_from(imports.len()).map_err(|_| LoadError::Limit)?;
    imports.push(Import {
        bif: None,
        module: "error_handler",
        function: "breakpoint",
        module_atom: global_atoms()
            .intern("error_handler")
            .map_err(|_| LoadError::Atom("error_handler".into()))?,
        function_atom: global_atoms()
            .intern("breakpoint")
            .map_err(|_| LoadError::Atom("breakpoint".into()))?,
        arity: 3,
        class: AtomicU8::new(ImportClass::Fresh as u8),
        native: AtomicUsize::new(0),
        extra_bif: AtomicUsize::new(0),
    });
    Ok(index)
}

/// The export slots of a module; `labels` maps an entry label to its code index.
pub(crate) fn build_exports(
    file: &BeamFile,
    labels: &HashMap<u32, usize>,
) -> Result<Vec<Arc<ExportSlot>>, LoadError> {
    let atom_ids = file_atoms(file)?;
    file.exports
        .iter()
        .map(|item| {
            let target = *labels
                .get(&item.label)
                .ok_or(LoadError::Index("label", item.label))?;
            let module_atom = Atom(atom_ids[0]);
            let function_atom = Atom(
                *atom_ids
                    .get(item.function_atom as usize - 1)
                    .ok_or(LoadError::Index("atom", item.function_atom))?,
            );
            let names = global_atoms();
            Ok(Arc::new(ExportSlot {
                module: names.text(module_atom).ok_or(LoadError::Index("atom", 1))?,
                function: names
                    .text(function_atom)
                    .ok_or(LoadError::Index("atom", item.function_atom))?,
                arity: item.arity as u8,
                module_atom,
                function_atom,
                target_index: target,
            }))
        })
        .collect::<Result<Vec<_>, LoadError>>()
}

/// The definition and default values of every record live in the module's literal area.
pub(crate) fn build_record_defs(
    file: &BeamFile,
    name_atom: Atom,
    literals: &mut VecHeap,
) -> Result<Vec<Term>, LoadError> {
    let mut record_defs = Vec::with_capacity(file.records.len());
    for record in &file.records {
        let name = global_atoms()
            .intern(&record.name)
            .map_err(|_| LoadError::Limit)?;
        let mut fields = Vec::with_capacity(record.fields.len());
        for (field, default) in &record.fields {
            let field = global_atoms().intern(field).map_err(|_| LoadError::Limit)?;
            let default = default
                .as_ref()
                .map(|default| from_owned(default, &mut *literals))
                .transpose()
                .map_err(|_| LoadError::Limit)?;
            fields.push((field, default));
        }
        let cons = TermBuilder::new(&mut *literals)
            .native_record_literal(name_atom, name, record.is_exported, &fields)
            .map_err(|_| LoadError::Limit)?;
        record_defs.push(cons);
    }
    Ok(record_defs)
}
