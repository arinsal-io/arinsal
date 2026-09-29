//! Resolution of OTP 29 generic BEAM instructions into compact interpreter code.

use arinsal_beam::{BeamFile, BeamType, Instr as BeamInstr, Operand};
use arinsal_bifs::BifFn;
use arinsal_spec::Opcode;
use arinsal_term::{Atom, Term, TermBuilder, VecHeap, from_owned, global_atoms};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicPtr, AtomicU8, AtomicU64, AtomicUsize, Ordering};

mod specialize;
// ---- vm_maps_bits ----
mod maps_bits;
pub use maps_bits::{BitCommand, BitCommandKind};
pub use specialize::{GenericOp, Instr, SelectTable, specialize_bif_calls};
// ---- vm_funs ----
mod funs;
pub use funs::{FunSlot, beamfile_chunk, module_uniq};

fn is_line_debug_instruction(file: &BeamFile, instruction: &BeamInstr) -> bool {
    instruction.op == Opcode::DebugLine
        && matches!(instruction.args.first(), Some(Operand::Atom(index)) if file.atom(*index).is_some_and(|kind| kind != "entry"))
}

/// A source or destination operand with a 60-bit payload.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Arg(pub u64);
impl Arg {
    const PAYLOAD_MASK: u64 = (1_u64 << 60) - 1;
    /// Missing operand.
    pub const NONE: Self = Self(0);
    /// X register.
    pub const X: u8 = 1;
    /// Y stack slot.
    pub const Y: u8 = 2;
    /// Float register.
    pub const FR: u8 = 3;
    /// A raw immediate term.
    pub const TERM: u8 = 4;
    /// An unsigned instruction value.
    pub const U: u8 = 5;
    /// A resolved code index.
    pub const LABEL: u8 = 6;
    /// An out-of-line operand list.
    pub const LIST: u8 = 7;
    /// An immediate signed integer.
    pub const INT: u8 = 8;
    /// A literal that cannot be represented yet.
    pub const UNSUPPORTED: u8 = 9;
    /// Pack an addressing mode and a payload spanning the small-integer range.
    pub const fn new(kind: u8, payload: u64) -> Self {
        assert!(kind < 16);
        if kind != Self::INT {
            assert!(payload & !Self::PAYLOAD_MASK == 0);
        }
        Self(((kind as u64) << 60) | (payload & Self::PAYLOAD_MASK))
    }
    /// Addressing mode.
    pub const fn kind(self) -> u8 {
        (self.0 >> 60) as u8
    }
    /// Unsigned payload.
    pub const fn value(self) -> u64 {
        self.0 & Self::PAYLOAD_MASK
    }
    /// Sign-extended integer payload.
    pub const fn signed(self) -> i64 {
        ((self.value() << 4) as i64) >> 4
    }
    /// Decode a tagged term from the literal area or an immediate.
    pub const fn term(self) -> Term {
        // SAFETY: Operand construction only stores valid tagged terms here.
        unsafe { std::mem::transmute::<u64, Term>(self.value()) }
    }
}

/// Compatibility name for code consumers moving to [`Instr`].
pub type Op = Instr;

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
    /// Module name.
    pub module: String,
    /// Function name.
    pub function: String,
    /// Arity.
    pub arity: u8,
    /// Bound BIF function when implemented.
    pub bif: Option<BifFn>,
    /// Small-integer arithmetic recognized during loading.
    pub fast: FastBif,
    /// Typed interpreter fast path selected from the import at load time.
    pub fast_op: ImportFastOp,
    class: AtomicU8,
    /// Packed native entry. Zero when [`ImportClass`] is not [`ImportClass::Native`].
    native: AtomicUsize,
    /// Static NIF pointer when the loader's BIF table had none.
    extra_bif: AtomicUsize,
    export: AtomicPtr<ExportSlot>,
    target_module: AtomicUsize,
}
impl Clone for Import {
    fn clone(&self) -> Self {
        Self {
            module: self.module.clone(),
            function: self.function.clone(),
            arity: self.arity,
            bif: self.bif,
            fast: self.fast,
            fast_op: self.fast_op,
            class: AtomicU8::new(self.class.load(Ordering::Acquire)),
            native: AtomicUsize::new(self.native.load(Ordering::Acquire)),
            extra_bif: AtomicUsize::new(self.extra_bif.load(Ordering::Acquire)),
            export: AtomicPtr::new(self.export.load(Ordering::Acquire)),
            target_module: AtomicUsize::new(self.target_module.load(Ordering::Acquire)),
        }
    }
}

/// Import operations with dedicated interpreter implementations.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ImportFastOp {
    /// No dedicated interpreter implementation.
    #[default]
    None,
    /// `erlang:element/2`.
    Element,
    /// `erlang:setelement/3`.
    SetElement,
    /// `erlang:rem/2`.
    Rem,
    /// Type and tuple-size guard BIFs.
    IsInteger,
    IsFloat,
    IsNumber,
    IsAtom,
    IsTuple,
    IsList,
    IsMap,
    IsFunction,
    TupleSize,
    /// Comparison guard BIFs.
    Less,
    LessEqual,
    Greater,
    GreaterEqual,
    Equal,
    NotEqual,
    ExactEqual,
    ExactNotEqual,
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
    /// Cached export address without dereferencing it. A code purge may have
    /// retired the allocation before the next caller checks the cache.
    pub fn resolved(&self) -> Option<(usize, *const ExportSlot)> {
        let ptr = self.export.load(Ordering::Acquire);
        if ptr.is_null() {
            return None;
        }
        Some((self.target_module.load(Ordering::Relaxed), ptr.cast_const()))
    }
    /// Cache an export entry once the target module has loaded.
    ///
    /// # Safety
    /// The export's Vec allocation must outlive this import entry.
    pub unsafe fn resolve(&self, module: usize, export: &ExportSlot) {
        self.target_module.store(module, Ordering::Relaxed);
        self.export.store(
            export as *const ExportSlot as *mut ExportSlot,
            Ordering::Release,
        );
    }
}

/// Inlined arithmetic operation for interpreter fast paths.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum FastBif {
    /// No inline implementation.
    #[default]
    None,
    /// `erlang:'+'/2`.
    Add,
    /// `erlang:'-'/2`.
    Sub,
    /// `erlang:'*'/2`.
    Mul,
}

/// A replaceable export target for future hot code loading.
pub struct ExportSlot {
    /// Module name.
    pub module: String,
    /// Function name.
    pub function: String,
    /// Arity.
    pub arity: u8,
    /// Module atom index used by the VM export table.
    pub module_atom: Atom,
    /// Function atom index used by the VM export table.
    pub function_atom: Atom,
    target_index: AtomicUsize,
    code_len: AtomicUsize,
    code_base: AtomicPtr<Instr>,
    target: AtomicPtr<Instr>,
}
impl ExportSlot {}
impl ExportSlot {
    /// Current instruction index.
    pub fn target(&self) -> usize {
        self.target_index.load(Ordering::Acquire)
    }
    /// Current executable code pointer.
    pub fn code_ptr(&self) -> *const Instr {
        self.target.load(Ordering::Acquire)
    }
    /// Publish a replacement code index.
    pub fn replace(&self, target: usize) {
        assert!(target < self.code_len.load(Ordering::Acquire));
        let base = self.code_base.load(Ordering::Acquire);
        if !base.is_null() {
            // `target < code_len` was asserted above, so the offset stays in this module.
            self.target
                .store(base.wrapping_add(target), Ordering::Release);
        }
        self.target_index.store(target, Ordering::Release);
    }
    fn bind_code(&self, base: *const Instr, len: usize) {
        let target = self.target();
        self.code_len.store(len, Ordering::Release);
        self.code_base.store(base.cast_mut(), Ordering::Release);
        // `target` was checked against this module's code length.
        self.target
            .store(base.wrapping_add(target).cast_mut(), Ordering::Release);
    }
}

/// Executable module and its out-of-line data.
pub struct Module {
    /// Module atom text.
    pub name: String,
    /// Native record definitions decoded from this module's `Recs` chunk.
    pub records: Vec<arinsal_beam::NativeRecord>,
    /// Compact code.
    pub code: Box<[Instr]>,
    /// Rare instructions retained in the generic operand format.
    pub generic: Vec<GenericOp>,
    /// Decoded select dispatch tables.
    pub selects: Vec<SelectTable>,
    /// Resolved imports.
    pub imports: Vec<Import>,
    /// Replaceable exports.
    pub exports: Vec<Arc<ExportSlot>>,
    /// Export slots indexed by stable atom identities and arity.
    pub export_atoms: HashMap<(Atom, u8), usize>,
    /// Out-of-line operand tails.
    pub tails: Vec<Box<[Arg]>>,
    /// Extended list operands.
    pub lists: Vec<Box<[Arg]>>,
    // vm_binparse2
    /// Command kinds and boundaries decoded from each list operand.
    pub bit_commands: Vec<Option<Box<[BitCommand]>>>,
    // ---- vm_maps_bits ----
    /// Module string table used by bit syntax string segments.
    pub strings: Box<[u8]>,
    /// Type metadata, indexed by code index and operand position.
    pub types: Vec<Vec<(usize, BeamType)>>,
    /// Source line for each instruction.
    pub lines: Vec<Option<(String, u64)>>,
    /// Opcodes not yet executable, with occurrence counts.
    pub unsupported: HashMap<String, usize>,
    /// Reason for each explicit unsupported opcode.
    pub unsupported_reasons: Vec<String>,
    /// Function names and arities at their `func_info` instruction offsets.
    pub functions: Vec<(usize, String, u8)>,
    /// Owning function for `JitHook::on_entry`, or `u32::MAX` when none applies.
    ///
    /// Slot `ip` holds the last function whose `func_info` offset is strictly
    /// below `ip`, matching a binary search on `start < ip` with one load.
    pub on_entry_fn: Box<[u32]>,
    /// `arity + 1` at each function entry instruction; `0` when the index is
    /// not an entry. Tail calls read the callee live count from this table.
    pub entry_arity: Box<[u16]>,
    /// Original entry instructions retained while a trace breakpoint is installed.
    pub breakpoint_originals: HashMap<usize, Instr>,
    /// Instruction indices used by stack continuations for tracing.
    pub return_trace_ip: usize,
    pub return_to_trace_ip: usize,
    /// First per-export global breakpoint trampoline.
    pub export_breakpoint_base: usize,
    /// Original function entry indices parallel to `exports`.
    pub export_entry_targets: Box<[usize]>,
    /// Coverage state allocated only when coverage was enabled at load time.
    pub coverage: Option<Coverage>,
    /// Metadata for each probe instruction.
    pub coverage_probes: Vec<CoverageProbe>,
    /// Whether this module was loaded with OTP's line breakpoint instrumentation.
    pub line_breakpoints_supported: bool,
    /// Retained compiler debug points as `(instruction, line, live-register-count)`.
    pub debug_line_points: Vec<(usize, u32, u16)>,
    /// Synthetic `error_handler:breakpoint/3` import used by debug breakpoints.
    pub debug_breakpoint_import: u32,
    // ---- vm_funs ----
    /// Local lambda entries retained by closures.
    pub funs: Vec<FunSlot>,
    _literals: Arc<VecHeap>,
}
impl Clone for Module {
    fn clone(&self) -> Self {
        Self {
            name: self.name.clone(),
            records: self.records.clone(),
            code: self.code.clone(),
            generic: self.generic.clone(),
            selects: self.selects.iter().map(SelectTable::clone).collect(),
            imports: self.imports.clone(),
            exports: self.exports.clone(),
            export_atoms: self.export_atoms.clone(),
            tails: self.tails.clone(),
            lists: self.lists.clone(),
            bit_commands: self.bit_commands.clone(),
            strings: self.strings.clone(),
            types: self.types.clone(),
            lines: self.lines.clone(),
            unsupported: self.unsupported.clone(),
            unsupported_reasons: self.unsupported_reasons.clone(),
            functions: self.functions.clone(),
            on_entry_fn: self.on_entry_fn.clone(),
            entry_arity: self.entry_arity.clone(),
            breakpoint_originals: self.breakpoint_originals.clone(),
            return_trace_ip: self.return_trace_ip,
            return_to_trace_ip: self.return_to_trace_ip,
            export_breakpoint_base: self.export_breakpoint_base,
            export_entry_targets: self.export_entry_targets.clone(),
            coverage: self.coverage.clone(),
            coverage_probes: self.coverage_probes.clone(),
            line_breakpoints_supported: self.line_breakpoints_supported,
            debug_line_points: self.debug_line_points.clone(),
            debug_breakpoint_import: self.debug_breakpoint_import,
            funs: self.funs.iter().map(FunSlot::clone).collect(),
            _literals: Arc::clone(&self._literals),
        }
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

/// Atomic coverage storage for an interpreted module.
///
/// BeamAsm native execution does not run these probes yet, so coverage queries
/// for a module executing natively reflect only interpreted calls.
pub struct Coverage {
    /// Mode selected when the module was loaded.
    pub mode: CoverageMode,
    /// Function or line counters, indexed by the probe metadata.
    pub counters: Box<[AtomicU64]>,
    /// Line number for each line probe.
    pub lines: Box<[u32]>,
    /// Compiler cover identifier for each line probe.
    pub cover_ids: Box<[u32]>,
    /// Function-table index owning each probe.
    pub function_owners: Box<[u32]>,
}

impl Clone for Coverage {
    fn clone(&self) -> Self {
        Self {
            mode: self.mode,
            counters: self
                .counters
                .iter()
                .map(|counter| AtomicU64::new(counter.load(Ordering::Relaxed)))
                .collect::<Vec<_>>()
                .into_boxed_slice(),
            lines: self.lines.clone(),
            cover_ids: self.cover_ids.clone(),
            function_owners: self.function_owners.clone(),
        }
    }
}

/// Metadata for an instrumented code location.
#[derive(Clone, Copy, Debug)]
pub struct CoverageProbe {
    /// Counter index.
    pub counter: u32,
}
impl Module {
    /// Patch one interpreted function entry, preserving the instruction to run after tracing.
    pub fn set_trace_breakpoint(&mut self, entry: usize, enabled: bool) -> bool {
        if enabled {
            if self.breakpoint_originals.contains_key(&entry) {
                return false;
            }
            let Some(instruction) = self.code.get_mut(entry) else {
                return false;
            };
            let Ok(index) = u32::try_from(entry) else {
                return false;
            };
            self.breakpoint_originals.insert(entry, *instruction);
            *instruction = Instr::Breakpoint { index };
        } else if let Some(original) = self.breakpoint_originals.remove(&entry) {
            let Some(instruction) = self.code.get_mut(entry) else {
                return false;
            };
            *instruction = original;
        } else {
            return false;
        }
        for export in &self.exports {
            export.bind_code(self.code.as_ptr(), self.code.len());
        }
        true
    }

    /// Redirect one exported entry through its generic breakpoint trampoline.
    pub fn set_global_trace_breakpoint(&self, index: usize, enabled: bool) {
        if let Some(export) = self.exports.get(index) {
            let target = if enabled {
                self.export_breakpoint_base + index
            } else {
                self.export_entry_targets[index]
            };
            export.replace(target);
        }
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
    /// Fetch a resolved argument, including an out-of-line tail.
    #[inline]
    pub fn arg(&self, op: &GenericOp, position: usize) -> Arg {
        let GenericOp { meta, args } = op;
        if position < 3 {
            args[position]
        } else {
            self.tails[(meta & 0x00ff_ffff) as usize][position - 3]
        }
    }
    /// Name and arity of the function containing a code offset.
    pub fn function_at(&self, ip: usize) -> Option<(&str, u8)> {
        self.functions
            .iter()
            .rev()
            .find(|(start, _, _)| *start <= ip)
            .map(|(_, name, arity)| (name.as_str(), *arity))
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

struct Decoder<'a> {
    file: &'a BeamFile,
    labels: &'a HashMap<u32, usize>,
    literals: &'a mut VecHeap,
    literal_terms: &'a mut HashMap<u32, Term>,
    lists: &'a mut Vec<Box<[Arg]>>,
    types: &'a mut Vec<(usize, BeamType)>,
}
impl Decoder<'_> {
    fn arg(&mut self, operand: &Operand, position: usize) -> Result<Arg, LoadError> {
        Ok(match operand {
            Operand::X(n) => Arg::new(Arg::X, *n as u64),
            Operand::Y(n) => Arg::new(Arg::Y, *n as u64),
            Operand::FR(n) => Arg::new(Arg::FR, *n as u64),
            Operand::U(n) => Arg::new(Arg::U, *n),
            Operand::Label(0) => Arg::new(Arg::LABEL, u32::MAX as u64),
            Operand::Label(n) => Arg::new(
                Arg::LABEL,
                *self.labels.get(n).ok_or(LoadError::Index("label", *n))? as u64,
            ),
            Operand::Atom(n) => {
                let name = self.file.atom(*n).ok_or(LoadError::Index("atom", *n))?;
                let atom = global_atoms()
                    .intern(name)
                    .map_err(|_| LoadError::Atom(name.into()))?;
                // SAFETY: Tagged atoms contain no heap address.
                Arg::new(Arg::TERM, unsafe { Term::atom(atom).raw_bits() })
            }
            Operand::Nil => {
                // SAFETY: NIL is an immediate.
                Arg::new(Arg::TERM, unsafe { Term::NIL.raw_bits() })
            }
            Operand::Int(n) if Term::small(*n).is_some() => Arg::new(Arg::INT, *n as u64),
            Operand::Int(n) => {
                let term = TermBuilder::new(self.literals)
                    .int_from_i64(*n)
                    .map_err(|_| LoadError::Limit)?;
                // SAFETY: The literal area retains this term.
                Arg::new(Arg::TERM, unsafe { term.raw_bits() })
            }
            Operand::BigInt(n) => {
                let term = TermBuilder::new(self.literals)
                    .int_from_bigint(n)
                    .map_err(|_| LoadError::Limit)?;
                // SAFETY: The literal area retains this term.
                Arg::new(Arg::TERM, unsafe { term.raw_bits() })
            }
            Operand::Char(n) => Arg::new(Arg::INT, *n as u64),
            Operand::Literal(n) => match self.literal_term(*n)? {
                Some(term) if term.as_small().is_some() => {
                    Arg::new(Arg::INT, term.as_small().unwrap() as u64)
                }
                Some(term) => {
                    // SAFETY: The literal area retains this term.
                    Arg::new(Arg::TERM, unsafe { term.raw_bits() })
                }
                None => Arg::new(Arg::UNSUPPORTED, *n as u64),
            },
            Operand::List(items) => {
                let mut list = Vec::with_capacity(items.len());
                for item in items {
                    list.push(self.arg(item, position)?);
                }
                let index = self.lists.len();
                self.lists.push(list.into_boxed_slice());
                Arg::new(Arg::LIST, index as u64)
            }
            Operand::Alloc(items) => {
                let words: u64 = items
                    .iter()
                    .map(|item| {
                        item.count
                            * match item.kind {
                                arinsal_beam::AllocKind::Words => 1,
                                arinsal_beam::AllocKind::Floats => 2,
                                arinsal_beam::AllocKind::Funs => 3,
                            }
                    })
                    .sum();
                Arg::new(Arg::U, words)
            }
            Operand::TypedReg { reg, type_index } => {
                if let Some(table) = &self.file.types
                    && let Some(ty) = table.entries.get(*type_index as usize)
                {
                    self.types.push((position, ty.clone()));
                }
                self.arg(reg, position)?
            }
        })
    }

    fn literal_term(&mut self, index: u32) -> Result<Option<Term>, LoadError> {
        // Port of erts/emulator/beam/beam_file.c:1977-1998, OTP-29.1.1.
        // BEAM literal indices designate stable terms in the module literal area.
        if let Some(term) = self.literal_terms.get(&index) {
            return Ok(Some(*term));
        }
        let Ok(owned) = self.file.literal(index) else {
            return Ok(None);
        };
        let term = from_owned(&owned, self.literals).map_err(|_| LoadError::Limit)?;
        self.literal_terms.insert(index, term);
        Ok(Some(term))
    }
}

/// Call a resolved pure BIF or static NIF.
///
/// `args` is a view of the caller's registers (or a stack copy of them).
/// This does not allocate. The interpreter and the JIT share this entry.
#[inline(always)]
pub fn call_bif(
    heap: &mut dyn arinsal_term::HeapAlloc,
    target: BifFn,
    args: &[Term],
) -> Result<Term, arinsal_bifs::BifError> {
    let mut ctx = arinsal_bifs::Ctx::new(heap);
    target(&mut ctx, args)
}

/// Resolve one parsed BEAM module without rejecting unknown executable opcodes.
pub fn load(file: &BeamFile) -> Result<Module, LoadError> {
    load_with_coverage(file, CoverageMode::None)
}

/// Resolve a module and add coverage probes only when its load-time mode enables them.
pub fn load_with_coverage(
    file: &BeamFile,
    requested_mode: CoverageMode,
) -> Result<Module, LoadError> {
    load_with_instrumentations(file, requested_mode, false)
}

/// Resolve a module with the requested load-time line breakpoint instrumentation.
pub fn load_with_instrumentations(
    file: &BeamFile,
    requested_mode: CoverageMode,
    debugger_lines: bool,
) -> Result<Module, LoadError> {
    // Port of erts/emulator/beam/beam_file.c:242-291, OTP-29.1.1.
    // OTP interns the complete Atom chunk in index order before resolving code.
    for atom in &file.atoms {
        global_atoms()
            .intern(atom)
            .map_err(|_| LoadError::Atom(atom.clone()))?;
    }
    // Port of erts/emulator/beam/jit/asm_load.c:79-95, OTP-29.1.1.
    let coverage_mode = match (file.lines.as_ref(), requested_mode) {
        (Some(lines), _) if lines.flags & 2 != 0 => CoverageMode::LineCounters,
        (lines, CoverageMode::Line | CoverageMode::LineCounters)
            if lines.is_none_or(|lines| lines.flags & 1 == 0) =>
        {
            CoverageMode::None
        }
        (_, mode) => mode,
    };
    let mut labels = HashMap::new();
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
    let mut source_lines = Vec::new();
    for instruction in &file.code.instructions {
        if instruction.op == Opcode::Label {
            if let Some(Operand::U(n)) = instruction.args.first() {
                labels.insert(*n as u32, count);
            }
        } else if instruction.op == Opcode::DebugLine {
            if debugger_lines && is_line_debug_instruction(file, instruction) {
                count += 2;
            }
        } else if instruction.op != Opcode::Line && instruction.op != Opcode::NifStart {
            if instruction.op == Opcode::FuncInfo {
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
                if let (Some(location), Some(cover_id)) = (location, cover_id) {
                    let line = file
                        .lines
                        .as_ref()
                        .and_then(|table| location.checked_sub(1).and_then(|i| table.items.get(i)))
                        .and_then(|item| u32::try_from(item.line).ok())
                        .unwrap_or(0);
                    source_lines.push((count, line, cover_id));
                }
            }
            count += 1;
        }
    }
    if count > u32::MAX as usize {
        return Err(LoadError::Limit);
    }
    let mut insertions: HashMap<usize, Vec<(u32, u32, u32)>> = HashMap::new();
    if coverage_enabled {
        if function_mode {
            for (owner, start) in source_functions.iter().enumerate() {
                let body = start.saturating_add(1);
                if body < count {
                    insertions
                        .entry(body)
                        .or_default()
                        .push((0, 0, owner as u32));
                }
            }
        } else {
            for (ip, line, cover_id) in source_lines {
                let owner = source_functions
                    .iter()
                    .rposition(|start| start.saturating_add(1) <= ip)
                    .unwrap_or(0) as u32;
                insertions
                    .entry(ip)
                    .or_default()
                    .push((line, cover_id, owner));
            }
        }
    }
    let insertion_count = insertions.values().map(Vec::len).sum::<usize>();
    if count.saturating_add(insertion_count) > u32::MAX as usize {
        return Err(LoadError::Limit);
    }
    let remap = |target: usize| {
        target
            + insertions
                .iter()
                .filter(|(ip, _)| **ip <= target)
                .map(|(_, probes)| probes.len())
                .sum::<usize>()
    };
    for target in labels.values_mut() {
        *target = remap(*target);
    }
    // ---- vm_funs ----
    let funs = funs::load_funs(file, &labels)?;
    let mut imports = file
        .imports
        .iter()
        .map(|item| {
            let module = file
                .atom(item.module_atom)
                .ok_or(LoadError::Index("atom", item.module_atom))?
                .to_owned();
            let function = file
                .atom(item.function_atom)
                .ok_or(LoadError::Index("atom", item.function_atom))?
                .to_owned();
            Ok(Import {
                bif: arinsal_bifs::lookup(&module, &function, item.arity as u8),
                fast: match (module.as_str(), function.as_str(), item.arity) {
                    ("erlang", "+", 2) => FastBif::Add,
                    ("erlang", "-", 2) => FastBif::Sub,
                    ("erlang", "*", 2) => FastBif::Mul,
                    _ => FastBif::None,
                },
                fast_op: match (module.as_str(), function.as_str(), item.arity) {
                    ("erlang", "element", 2) => ImportFastOp::Element,
                    ("erlang", "setelement", 3) => ImportFastOp::SetElement,
                    ("erlang", "rem", 2) => ImportFastOp::Rem,
                    ("erlang", "is_integer", 1) => ImportFastOp::IsInteger,
                    ("erlang", "is_float", 1) => ImportFastOp::IsFloat,
                    ("erlang", "is_number", 1) => ImportFastOp::IsNumber,
                    ("erlang", "is_atom", 1) => ImportFastOp::IsAtom,
                    ("erlang", "is_tuple", 1) => ImportFastOp::IsTuple,
                    ("erlang", "is_list", 1) => ImportFastOp::IsList,
                    ("erlang", "is_map", 1) => ImportFastOp::IsMap,
                    ("erlang", "is_function", 1) => ImportFastOp::IsFunction,
                    ("erlang", "tuple_size", 1) => ImportFastOp::TupleSize,
                    ("erlang", "<", 2) => ImportFastOp::Less,
                    ("erlang", "=<", 2) => ImportFastOp::LessEqual,
                    ("erlang", ">", 2) => ImportFastOp::Greater,
                    ("erlang", ">=", 2) => ImportFastOp::GreaterEqual,
                    ("erlang", "==", 2) => ImportFastOp::Equal,
                    ("erlang", "/=", 2) => ImportFastOp::NotEqual,
                    ("erlang", "=:=", 2) => ImportFastOp::ExactEqual,
                    ("erlang", "=/=", 2) => ImportFastOp::ExactNotEqual,
                    _ => ImportFastOp::None,
                },
                module,
                function,
                arity: item.arity as u8,
                class: AtomicU8::new(ImportClass::Fresh as u8),
                native: AtomicUsize::new(0),
                extra_bif: AtomicUsize::new(0),
                export: AtomicPtr::new(std::ptr::null_mut()),
                target_module: AtomicUsize::new(0),
            })
        })
        .collect::<Result<Vec<_>, LoadError>>()?;
    let has_debug_line = debugger_lines
        && file
            .code
            .instructions
            .iter()
            .any(|instruction| is_line_debug_instruction(file, instruction));
    let debug_line_import = if has_debug_line {
        let index = u32::try_from(imports.len()).map_err(|_| LoadError::Limit)?;
        imports.push(Import {
            bif: None,
            fast: FastBif::None,
            fast_op: ImportFastOp::None,
            module: "erts_internal".into(),
            function: "breakpoint".into(),
            arity: 4,
            class: AtomicU8::new(ImportClass::Fresh as u8),
            native: AtomicUsize::new(0),
            extra_bif: AtomicUsize::new(0),
            export: AtomicPtr::new(std::ptr::null_mut()),
            target_module: AtomicUsize::new(0),
        });
        Some(index)
    } else {
        None
    };
    let debug_breakpoint_import = u32::try_from(imports.len()).map_err(|_| LoadError::Limit)?;
    imports.push(Import {
        bif: None,
        fast: FastBif::None,
        fast_op: ImportFastOp::None,
        module: "error_handler".into(),
        function: "breakpoint".into(),
        arity: 3,
        class: AtomicU8::new(ImportClass::Fresh as u8),
        native: AtomicUsize::new(0),
        extra_bif: AtomicUsize::new(0),
        export: AtomicPtr::new(std::ptr::null_mut()),
        target_module: AtomicUsize::new(0),
    });
    let exports = file
        .exports
        .iter()
        .map(|item| {
            let function = file
                .atom(item.function_atom)
                .ok_or(LoadError::Index("atom", item.function_atom))?
                .to_owned();
            let target = *labels
                .get(&item.label)
                .ok_or(LoadError::Index("label", item.label))?;
            let module_atom = global_atoms()
                .intern(&file.module)
                .map_err(|_| LoadError::Atom(file.module.clone()))?;
            let function_atom = global_atoms()
                .intern(&function)
                .map_err(|_| LoadError::Atom(function.clone()))?;
            Ok(Arc::new(ExportSlot {
                module: file.module.clone(),
                function,
                arity: item.arity as u8,
                module_atom,
                function_atom,
                target_index: AtomicUsize::new(target),
                code_len: AtomicUsize::new(0),
                code_base: AtomicPtr::new(std::ptr::null_mut()),
                target: AtomicPtr::new(std::ptr::null_mut()),
            }))
        })
        .collect::<Result<Vec<_>, LoadError>>()?;
    let export_atoms = exports
        .iter()
        .enumerate()
        .map(|(index, export)| ((export.function_atom, export.arity), index))
        .collect();
    let mut code = Vec::with_capacity(count);
    let mut generic = Vec::new();
    let mut selects = Vec::new();
    let mut tails = Vec::new();
    let mut lists = Vec::new();
    let mut types = Vec::new();
    let mut lines = Vec::new();
    let mut literals = VecHeap::new_literal();
    let mut literal_terms = HashMap::new();
    let mut current_line = None;
    let mut unsupported = HashMap::new();
    let mut unsupported_reasons = Vec::new();
    let mut functions = Vec::new();
    let mut debug_line_points = Vec::new();
    let mut notify_breakpoint_stub = None;
    let mut coverage_probes = Vec::new();
    let mut counter_lines = Vec::new();
    let mut counter_ids = Vec::new();
    let mut function_owners = Vec::new();
    let mut source_ip = 0_usize;
    for instruction in &file.code.instructions {
        if instruction.op == Opcode::Label {
            continue;
        }
        if instruction.op == Opcode::DebugLine
            && (!debugger_lines || !is_line_debug_instruction(file, instruction))
        {
            continue;
        }
        if instruction.op == Opcode::Line {
            if let Some(Operand::U(n)) = instruction.args.first()
                && let Some(table) = &file.lines
                // ---- vm_exc ---- OTP keeps an implicit undefined item at index zero.
                && let Some(item) = n.checked_sub(1).and_then(|i| table.items.get(i as usize))
            {
                let name = if item.name_index == 0 {
                    format!("{}.erl", file.module)
                } else {
                    table
                        .names
                        .get(item.name_index as usize - 1)
                        .cloned()
                        .filter(|name| !name.is_empty())
                        .unwrap_or_else(|| format!("{}.erl", file.module))
                };
                current_line = Some((name, item.line));
            }
            continue;
        }
        // nif_start only marks a NIF stub's entry; it executes nothing.
        if instruction.op == Opcode::NifStart {
            continue;
        }
        if file.module == "erts_internal"
            && instruction.op == Opcode::CallExtOnly
            && let Some((function_ip, function, 3)) = functions.last()
            && function == "notify_breakpoint_hit"
            && let Some(Operand::U(import_index)) = instruction.args.get(1)
            && file
                .imports
                .get(*import_index as usize)
                .is_some_and(|import| {
                    file.atom(import.module_atom) == Some("erlang")
                        && file.atom(import.function_atom) == Some("nif_error")
                        && import.arity == 1
                })
        {
            // Port of erts/emulator/beam/erl_debugger.c:411-444, OTP-29.1.1.
            let import = u32::try_from(imports.len()).map_err(|_| LoadError::Limit)?;
            imports.push(Import {
                bif: None,
                fast: FastBif::None,
                fast_op: ImportFastOp::None,
                module: "erts_internal".into(),
                function: "notify_breakpoint_hit".into(),
                arity: 3,
                class: AtomicU8::new(ImportClass::Fresh as u8),
                native: AtomicUsize::new(0),
                extra_bif: AtomicUsize::new(0),
                export: AtomicPtr::new(std::ptr::null_mut()),
                target_module: AtomicUsize::new(0),
            });
            notify_breakpoint_stub = Some((*function_ip, import));
        }
        if let Some(probes) = insertions.get(&source_ip) {
            for (line, cover_id, owner) in probes {
                let probe = u32::try_from(coverage_probes.len()).map_err(|_| LoadError::Limit)?;
                let counter = u32::try_from(coverage_probes.len()).map_err(|_| LoadError::Limit)?;
                coverage_probes.push(CoverageProbe { counter });
                counter_lines.push(*line);
                counter_ids.push(*cover_id);
                function_owners.push(*owner);
                code.push(Instr::CoverageProbe { index: probe });
                types.push(Vec::new());
                lines.push(current_line.clone());
            }
        }
        if !executable(instruction.op) {
            *unsupported
                .entry(instruction.op.name().to_owned())
                .or_insert(0) += 1;
            let reason = u32::try_from(unsupported_reasons.len()).map_err(|_| LoadError::Limit)?;
            unsupported_reasons.push(format!("opcode {}", instruction.op.name()));
            code.push(Instr::Unsupported(reason));
            types.push(Vec::new());
            lines.push(current_line.clone());
            source_ip += 1;
            continue;
        }
        let mut type_meta = Vec::new();
        let mut decoder = Decoder {
            file,
            labels: &labels,
            literals: &mut literals,
            literal_terms: &mut literal_terms,
            lists: &mut lists,
            types: &mut type_meta,
        };
        let mut args = [Arg::NONE; 3];
        let mut tail = Vec::new();
        for (index, operand) in instruction.args.iter().enumerate() {
            let arg = decoder.arg(operand, index)?;
            if index < 3 {
                args[index] = arg;
            } else {
                tail.push(arg);
            }
        }
        let target_arg = match instruction.op {
            Opcode::Jump => Some(args[0]),
            Opcode::Call | Opcode::CallLast | Opcode::CallOnly => Some(args[1]),
            _ => None,
        };
        if let Some(target) = target_arg
            && (target.kind() != Arg::LABEL
                || target.value() == u32::MAX as u64
                || target.value() as usize > count)
        {
            return Err(LoadError::Index("label", 0));
        }
        let specialized =
            specialize::specialize(instruction.op, args, &tail, &imports, &lists, &mut selects);
        let extra = if tail.is_empty() {
            0x00ff_ffff
        } else {
            let index = u32::try_from(tails.len()).map_err(|_| LoadError::Limit)?;
            if index >= 0x00ff_ffff {
                return Err(LoadError::Limit);
            }
            tails.push(tail.into_boxed_slice());
            index
        };
        if instruction.op == Opcode::FuncInfo {
            let name = args[1]
                .term()
                .as_atom()
                .and_then(|atom| global_atoms().text(atom))
                .map(|name| name.to_string())
                .unwrap_or_else(|| "?".into());
            functions.push((code.len(), name, args[2].value() as u8));
        }
        let raw = GenericOp::execute(instruction.op, args, extra)?;
        let debug_line = if instruction.op == Opcode::DebugLine {
            if let Some(import) = debug_line_import {
                let kind = instruction.args.first().and_then(|operand| match operand {
                    Operand::Atom(index) => file.atom(*index),
                    _ => None,
                });
                let loc_index = instruction.args.get(1).and_then(|operand| match operand {
                    Operand::U(index) => usize::try_from(*index).ok(),
                    _ => None,
                });
                let live = instruction.args.get(3).and_then(|operand| match operand {
                    Operand::U(live) => u16::try_from(*live).ok(),
                    _ => None,
                });
                if kind == Some("line")
                    && let (Some(location), Some(live)) = (
                        loc_index.and_then(|index| {
                            file.lines
                                .as_ref()
                                .and_then(|table| {
                                    index.checked_sub(1).and_then(|i| table.items.get(i))
                                })
                                .and_then(|item| u32::try_from(item.line).ok())
                        }),
                        live,
                    )
                    && location > 0
                {
                    let point_ip = code.len();
                    debug_line_points.push((point_ip, location, live));
                    Some((
                        Instr::DebugLine {
                            line: location,
                            live,
                            import,
                        },
                        Instr::DebugLineCleanup { live },
                    ))
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        };
        if let Some((probe, cleanup)) = debug_line {
            code.push(probe);
            code.push(cleanup);
        } else {
            code.push(if let Some(instr) = specialized {
                instr
            // ---- vm_maps_bits ----
            } else if maps_bits::handles(instruction.op) {
                let index = u32::try_from(generic.len()).map_err(|_| LoadError::Limit)?;
                generic.push(raw);
                Instr::MapsBits(index)
            } else {
                let index = u32::try_from(generic.len()).map_err(|_| LoadError::Limit)?;
                generic.push(raw);
                Instr::Generic(index)
            });
        }
        types.push(type_meta);
        lines.push(current_line.clone());
        source_ip += if instruction.op == Opcode::DebugLine {
            2
        } else {
            1
        };
    }
    if let Some((function_ip, import)) = notify_breakpoint_stub {
        code[function_ip + 1] = Instr::CallExternal {
            import,
            arity: 3,
            dealloc: 0,
            tail: true,
        };
    }
    // A trailing sentinel makes a fallthrough from the final BEAM opcode safe
    // without checking the instruction pointer on every dispatch.
    code.push(Instr::CodeEnd);
    let return_trace_ip = code.len();
    code.push(Instr::ReturnTrace);
    let return_to_trace_ip = code.len();
    code.push(Instr::ReturnToTrace);
    let breakpoint_originals = HashMap::new();
    let export_entry_targets = exports
        .iter()
        .map(|export| export.target())
        .collect::<Vec<_>>();
    let export_breakpoint_base = code.len();
    for index in 0..exports.len() {
        code.push(Instr::ExportBreakpoint {
            index: u32::try_from(index).map_err(|_| LoadError::Limit)?,
        });
    }
    let entry_points: HashSet<usize> = labels.values().copied().collect();
    for index in 0..code.len().saturating_sub(1) {
        if entry_points.contains(&(index + 1)) {
            continue;
        }
        let fused = match (code[index], code[index + 1]) {
            (Instr::MoveXX { src, dst }, Instr::CallLocal { target }) => {
                Some(Instr::MoveCallLocal { src, dst, target })
            }
            (Instr::Deallocate { slots }, Instr::ReturnInstr) => {
                Some(Instr::DeallocateReturn { slots })
            }
            (Instr::IsLtXC { a, b, fail }, Instr::ReturnInstr) => {
                Some(Instr::IsLtXCReturn { a, b, fail })
            }
            (
                Instr::GetTupleElementXX { src, index, dst },
                Instr::FmoveXFr {
                    src: float_src,
                    dst: dst_fr,
                },
            ) if dst == float_src => Some(Instr::GetTupleFloat {
                src,
                index,
                dst_x: dst,
                dst_fr,
            }),
            (
                Instr::IsTupleX {
                    src,
                    fail: fail_type,
                },
                Instr::TestArityX {
                    src: arity_src,
                    arity,
                    fail: fail_arity,
                },
            ) if src == arity_src => Some(Instr::IsTupleOfArity {
                src,
                arity,
                fail_type,
                fail_arity,
            }),
            _ => None,
        };
        if let Some(instr) = fused {
            code[index] = instr;
            code[index + 1] = Instr::CodeEnd;
        }
    }
    // vm_binparse2: specialize bit commands independently of function shape.
    maps_bits::specialize_bit_commands(&mut code, &generic, &lists, &tails);
    let coverage = if coverage_enabled {
        Some(Coverage {
            mode: coverage_mode,
            counters: (0..coverage_probes.len())
                .map(|_| AtomicU64::new(0))
                .collect::<Vec<_>>()
                .into_boxed_slice(),
            lines: counter_lines.into_boxed_slice(),
            cover_ids: counter_ids.into_boxed_slice(),
            function_owners: function_owners.into_boxed_slice(),
        })
    } else {
        None
    };
    let mut bit_commands = maps_bits::decode_commands(&lists);
    // vm_binparse2: drop spare decode capacity before large process binaries arrive.
    generic.shrink_to_fit();
    selects.shrink_to_fit();
    tails.shrink_to_fit();
    lists.shrink_to_fit();
    types.iter_mut().for_each(Vec::shrink_to_fit);
    types.resize_with(code.len(), Vec::new);
    types.shrink_to_fit();
    lines.resize(code.len(), None);
    lines.shrink_to_fit();
    functions.shrink_to_fit();
    unsupported_reasons.shrink_to_fit();
    bit_commands.shrink_to_fit();
    let mut on_entry_fn = vec![u32::MAX; code.len()];
    let mut entry_arity = vec![0_u16; code.len()];
    let mut owner = u32::MAX;
    let mut next_fn = 0_usize;
    for (ip, slot) in on_entry_fn.iter_mut().enumerate() {
        while next_fn < functions.len() && functions[next_fn].0 < ip {
            owner = next_fn as u32;
            next_fn += 1;
        }
        *slot = owner;
    }
    for (start, _, arity) in &functions {
        let entry = start.saturating_add(1);
        if entry < entry_arity.len() {
            entry_arity[entry] = u16::from(*arity).saturating_add(1);
        }
    }
    let on_entry_fn = on_entry_fn.into_boxed_slice();
    let entry_arity = entry_arity.into_boxed_slice();
    let code = code.into_boxed_slice();
    for export in &exports {
        export.bind_code(code.as_ptr(), code.len());
    }
    Ok(Module {
        name: file.module.clone(),
        records: file.records.clone(),
        code,
        generic,
        selects,
        imports,
        exports,
        export_atoms,
        tails,
        lists,
        bit_commands,
        // ---- vm_maps_bits ----
        strings: file.strings.clone().into_boxed_slice(),
        types,
        lines,
        unsupported,
        unsupported_reasons,
        functions,
        on_entry_fn,
        entry_arity,
        breakpoint_originals,
        return_trace_ip,
        return_to_trace_ip,
        export_breakpoint_base,
        export_entry_targets: export_entry_targets.into_boxed_slice(),
        coverage,
        coverage_probes,
        line_breakpoints_supported: has_debug_line,
        debug_line_points,
        debug_breakpoint_import,
        // ---- vm_funs ----
        funs,
        _literals: Arc::new(literals),
    })
}

fn executable(op: Opcode) -> bool {
    // ---- vm_maps_bits ----
    if maps_bits::handles(op) {
        return true;
    }
    matches!(
        op.name(),
        "func_info"
            | "executable_line"
            // ---- vm_exc ----
            | "try"
            | "try_end"
            | "try_case"
            | "try_case_end"
            | "catch"
            | "catch_end"
            | "raise"
            | "raw_raise"
            | "build_stacktrace"
            | "badrecord"
            | "int_code_end"
            | "move"
            | "swap"
            | "return"
            | "call"
            | "call_last"
            | "call_only"
            | "call_ext"
            | "call_ext_last"
            | "call_ext_only"
            | "allocate"
            | "allocate_heap"
            | "deallocate"
            | "trim"
            | "test_heap"
            | "init_yregs"
            | "jump"
            | "select_val"
            | "select_tuple_arity"
            | "is_lt"
            | "is_ge"
            | "is_eq"
            | "is_ne"
            | "is_eq_exact"
            | "is_ne_exact"
            | "is_tuple"
            | "test_arity"
            | "is_nil"
            | "is_nonempty_list"
            | "is_list"
            | "is_integer"
            | "is_float"
            | "is_number"
            | "is_atom"
            | "is_binary"
            | "is_map"
            | "is_pid"
            | "is_boolean"
            | "update_record"
            | "is_port"
            | "is_reference"
            | "is_any_native_record"
            | "put_record"
            | "get_tuple_element"
            | "put_tuple2"
            | "put_list"
            | "get_list"
            | "get_hd"
            | "get_tl"
            | "gc_bif1"
            | "gc_bif2"
            | "gc_bif3"
            | "bif0"
            | "bif1"
            | "bif2"
            | "bif3"
            | "on_load"
            | "fmove"
            | "fconv"
            | "fadd"
            | "fsub"
            | "fmul"
            | "fdiv"
            | "fnegate"
            | "is_function"
            | "send"
            | "loop_rec"
            | "loop_rec_end"
            | "remove_message"
            | "wait"
            | "wait_timeout"
            | "timeout"
            | "is_tagged_tuple"
            | "recv_marker_reserve"
            | "recv_marker_bind"
            | "recv_marker_clear"
            | "recv_marker_use"
            // ---- vm_funs ----
            | "make_fun3"
            | "call_fun"
            | "call_fun2"
            | "apply"
            | "apply_last"
            | "is_function2"
            | "badmatch"
            | "case_end"
            | "if_end"
            | "debug_line"
    )
}
