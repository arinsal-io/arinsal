//! The x86 side of the VM's BeamAsm load: the loader environment of the x86 module assembler
//! and the module instance it produces.
// Port of erts/emulator/beam/jit/asm_load.c (beam_load_finish_emit, beam_load_finalize_code),
// erts/emulator/beam/jit/beam_jit_main.cpp (beamasm_codegen, beamasm_patch_*) and
// erts/emulator/beam/jit/beam_asm.h (erts_asm_bp_set_flag, erts_asm_bp_unset_flag),
// OTP-29.1.1.

use super::*;
use arinsal_beam::BeamFile;
use arinsal_beamasm::beam_asm_module::{BeamCodeHeader, BeamModuleAssembler};
use arinsal_beamasm::common::beam_asm_h::{
    BREAKPOINT_FLAG_OFFSET, ERTS_ASM_BP_FLAG_BP, ErtsCodeInfo,
};
use arinsal_beamjit::CodeMemory;
use arinsal_beamjit::LoaderEnv;
use arinsal_term::{Term, TermBuilder, VecHeap, from_owned, global_atoms};
use num_bigint::BigInt;
use std::cell::RefCell;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Mutex, PoisonError, Weak};

/// `ERTS_DEBUGGER_LINE_BREAKPOINTS`.
// Port of erts/emulator/beam/erl_debugger.h:27, OTP-29.1.1.
const ERTS_DEBUGGER_LINE_BREAKPOINTS: u64 = 1 << 1;

fn raw_word(term: Term) -> u64 {
    term.tagged_word()
}

/// The loader state's view of the module being loaded: the literals of the file (already
/// in the module's literal area), those the load adds, and `stp->bif_imports`.
// Port of erts/emulator/beam/jit/asm_load.c (LoaderState: beam.static_literals,
// beam.dynamic_literals, bif_imports), OTP-29.1.1.
struct X86LoaderEnv<'a> {
    literal_heap: RefCell<&'a mut VecHeap>,
    dynamic_integer_literals: RefCell<HashMap<BigInt, u64>>,
    literals: Vec<u64>,
    added_literals: RefCell<Vec<Option<u64>>>,
    zero_capture_funs: HashMap<u32, u64>,
    bif_imports: Vec<usize>,
}

impl<'a> X86LoaderEnv<'a> {
    fn new(
        beam: &BeamFile,
        module: &arinsal_loader::Module,
        literal_heap: &'a mut VecHeap,
        bif_imports: Vec<usize>,
    ) -> Result<Self, String> {
        let mut literals = Vec::with_capacity(beam.literals.len());
        for index in 0..beam.literals.len() {
            let term = module
                .literal_term(index as u32)
                .ok_or_else(|| format!("literal {index} is not decoded"))?;
            literals.push(raw_word(term));
        }
        // Port of erts/emulator/beam/generators.tab:255-295 (gen.create_local_record): the
        // definition literal of every record follows the BEAM literals.
        literals.extend(module.record_defs.iter().map(|cons| raw_word(*cons)));
        // Port of erts/emulator/beam/jit/asm_load.c:1213-1222 (a lambda without free variables
        // is a literal fun of its fun entry), OTP-29.1.1.
        let mut zero_capture_funs = HashMap::new();
        for lambda in beam.lambdas.iter().filter(|lambda| lambda.num_free == 0) {
            let slot = module
                .funs
                .iter()
                .find(|slot| slot.entry.old_index == lambda.index)
                .ok_or_else(|| format!("zero-capture fun {} has no loaded entry", lambda.index))?;
            let term = TermBuilder::new(literal_heap)
                .local_fun(&slot.entry, &[])
                .map_err(|error| format!("zero-capture fun {}: {error:?}", lambda.index))?;
            zero_capture_funs.insert(lambda.index, raw_word(term));
        }
        Ok(Self {
            literal_heap: RefCell::new(literal_heap),
            dynamic_integer_literals: RefCell::new(HashMap::new()),
            literals,
            added_literals: RefCell::new(Vec::new()),
            zero_capture_funs,
            bif_imports,
        })
    }

    // Port of erts/emulator/beam/beam_file.c (beamfile_add_literal), OTP-29.1.1.
    fn intern_integer(&self, value: BigInt) -> Result<u64, String> {
        if let Some(word) = self.dynamic_integer_literals.borrow().get(&value).copied() {
            return Ok(word);
        }
        let mut heap = self.literal_heap.borrow_mut();
        let word = from_owned(&arinsal_etf::OwnedTerm::BigInt(value.clone()), &mut **heap)
            .map(raw_word)
            .map_err(|error| format!("integer literal: {error:?}"))?;
        self.dynamic_integer_literals
            .borrow_mut()
            .insert(value, word);
        Ok(word)
    }

    /// Every literal word an instruction may refer to: those of the file, then the added ones.
    fn literal_words(&self) -> Vec<u64> {
        let mut words = self.literals.clone();
        words.extend(self.added_literals.borrow().iter().flatten().copied());
        words.extend(self.dynamic_integer_literals.borrow().values().copied());
        words
    }
}

impl LoaderEnv for X86LoaderEnv<'_> {
    fn atom(&self, _beam: &BeamFile, index: u32) -> Result<u64, String> {
        // The atoms of the transformed code are global atom indexes.
        let atom = arinsal_term::Atom(index);
        global_atoms()
            .text(atom)
            .ok_or_else(|| format!("atom index {index} is out of range"))?;
        Ok(raw_word(Term::atom(atom)))
    }

    fn literal(&self, _beam: &BeamFile, index: u32) -> Result<u64, String> {
        if let Some(word) = self.literals.get(index as usize) {
            return Ok(*word);
        }
        let at = (index as usize).wrapping_sub(self.literals.len());
        self.added_literals
            .borrow()
            .get(at)
            .copied()
            .flatten()
            .ok_or_else(|| format!("literal index {index} is out of range"))
    }

    fn add_literal(&self, index: u32, word: u64) -> Result<(), String> {
        let at = (index as usize)
            .checked_sub(self.literals.len())
            .ok_or_else(|| format!("added literal {index} overlaps those of the file"))?;
        let mut added = self.added_literals.borrow_mut();
        if added.len() <= at {
            added.resize(at + 1, None);
        }
        added[at] = Some(word);
        Ok(())
    }

    fn integer_literal(&self, value: i64) -> Result<u64, String> {
        self.intern_integer(BigInt::from(value))
    }

    fn bigint_literal(&self, decimal: &str) -> Result<u64, String> {
        let value = decimal
            .parse::<BigInt>()
            .map_err(|error| format!("bignum literal: {error}"))?;
        self.intern_integer(value)
    }

    fn zero_capture_fun(&self, _beam: &BeamFile, lambda: u32) -> Result<u64, String> {
        self.zero_capture_funs
            .get(&lambda)
            .copied()
            .ok_or_else(|| format!("lambda {lambda} has no fun without free variables"))
    }

    fn tuple_literal(&self, elements: &[u64]) -> Result<u64, String> {
        let terms = elements
            .iter()
            .map(|word| crate::native_hooks::from_raw(*word))
            .collect::<Vec<_>>();
        let mut heap = self.literal_heap.borrow_mut();
        TermBuilder::new(&mut **heap)
            .tuple(&terms)
            .map(raw_word)
            .map_err(|error| format!("tuple literal: {error:?}"))
    }

    fn bif_import(&self, _beam: &BeamFile, index: u32) -> Result<u64, String> {
        self.bif_imports
            .get(index as usize)
            .map(|f| *f as u64)
            .ok_or_else(|| format!("import index {index} is out of range"))
    }

    // Port of erts/emulator/beam/jit/x86/instr_bif.cpp:912 (emit_call_bif_mfa), OTP-29.1.1:
    // the active export of M:F/A, then its `bif_table[e->bif_number].f`.
    fn bif_mfa_function(&self, module: &str, function: &str, arity: u8) -> Result<u64, String> {
        let entry = bif_mfa_entry(module, function, arity)
            .ok_or_else(|| format!("no BIF export for {module}:{function}/{arity}"))?;
        let bif = export_dispatch(entry).map_or(0, |export| export.bif_table_function());
        (bif != 0)
            .then_some(bif as u64)
            .ok_or_else(|| format!("no BIF function for {module}:{function}/{arity}"))
    }

    // Port of erts/emulator/beam/jit/x86/instr_bif.cpp:691-705 (emit_send), OTP-29.1.1:
    // `BIF_TRAP_EXPORT(BIF_send_2)` and `send_2`, which the emitted call passes to the shared
    // BIF call fragment.
    fn send_target(&self) -> Result<(u64, u64), String> {
        let export = Arc::as_ptr(
            make_export((arinsal_term::atoms::ERLANG, arinsal_term::atoms::SEND, 2))
                .ok_or("no erlang:send/2 export")?,
        ) as usize;
        let bif =
            crate::bif_table::function(crate::raw::jit_ffi::export_entry(export).bif_number());
        (bif != 0)
            .then_some((export as u64, bif as u64))
            .ok_or_else(|| "no erlang:send/2 BIF function".into())
    }
}

/// The loaded module instance (`struct erl_module_instance` with its code header) of x86
/// code: the executable region, the code header in it, and the module assembler until
/// `beam_load_finalize_code` has patched the code (`beamasm_delete_assembler`).
// Port of erts/emulator/beam/module.h (erl_module_instance: code_hdr, code_length,
// executable_region, writable_region, catches) and erts/emulator/beam/jit/asm_load.c
// (LoaderState.ba), OTP-29.1.1.
pub(crate) struct CompiledVersion {
    module: String,
    /// The `-on_load` function the emitter found.
    pub(crate) on_load: Option<(String, u8)>,
    /// `stp->ba` until the finalize; then deleted.
    ba: Mutex<Option<BeamModuleAssembler>>,
    /// `executable_region` / `writable_region`.
    memory: Mutex<CodeMemory>,
    code_start: usize,
    code_end: usize,
    installed: AtomicBool,
    /// `inst_p->catches`.
    catch_head: AtomicU32,
    /// The export entry of each import, patched into the code at the finalize.
    import_bindings: Vec<(Mfa, &'static Arc<arinsal_term::ExportEntry>)>,
    /// `beamasm_get_code(ba, entry->label)` of every export.
    export_addresses: Vec<(Mfa, usize)>,
    /// Each lambda's fun entry and `beamasm_get_lambda` code.
    lambda_targets: Vec<(u32, Arc<arinsal_term::FunEntry>, usize)>,
    lambda_entries: Vec<Arc<arinsal_term::FunEntry>>,
    /// `erts_update_ranges` data: each function's code range and line table.
    native_functions: crate::native_bridge::FunctionTable,
    /// `ErtsCodeInfo` address of each function, keyed by name and arity.
    code_infos: HashMap<(arinsal_term::Atom, u8), usize>,
    /// Addresses of the line-breakpoint trampolines by source line.
    line_breakpoints: Vec<(u32, usize)>,
    literal_heap: Mutex<Option<Arc<VecHeap>>>,
    _module_literals: arinsal_loader::LiteralArea,
    /// The coverage tables the code header points at.
    _coverage: Option<Box<[u64]>>,
    _line_coverage_valid: Option<Vec<u8>>,
    _loc_index_to_cover_id: Option<Vec<u32>>,
}

fn compiled_versions() -> &'static RwLock<Vec<Weak<CompiledVersion>>> {
    static VERSIONS: OnceLock<RwLock<Vec<Weak<CompiledVersion>>>> = OnceLock::new();
    VERSIONS.get_or_init(|| RwLock::new(Vec::new()))
}

/// Whether `address` lies in the code of a loaded module version.
// Port of erts/emulator/beam/beam_ranges.c (erts_find_function_from_pc over the ranges),
// OTP-29.1.1.
pub(crate) fn owns_native_address(address: usize) -> bool {
    let Ok(versions) = compiled_versions().read() else {
        return false;
    };
    versions.iter().any(|version| {
        version
            .upgrade()
            .is_some_and(|version| version.contains_code(address))
    })
}

fn versions_of(module: &str) -> Vec<Arc<CompiledVersion>> {
    compiled_versions()
        .read()
        .map(|versions| {
            versions
                .iter()
                .filter_map(Weak::upgrade)
                .filter(|version| version.module == module)
                .collect()
        })
        .unwrap_or_default()
}

/// Sets or clears `ERTS_ASM_BP_FLAG_BP` on the traced functions of `module`.
// Port of erts/emulator/beam/beam_bp.c (consolidate_bp_data: erts_asm_bp_set_flag /
// erts_asm_bp_unset_flag with ERTS_ASM_BP_FLAG_BP), OTP-29.1.1.
pub(crate) fn patch_native_breakpoints(module: &str, wanted: &[(&str, u8, bool)]) {
    if wanted.is_empty() {
        return;
    }
    let atoms = global_atoms();
    for version in versions_of(module) {
        for &(function, arity, enabled) in wanted {
            let Some(&ci) = atoms
                .get(function)
                .and_then(|atom| version.code_infos.get(&(atom, arity)))
            else {
                continue;
            };
            if enabled {
                version.erts_asm_bp_set_flag(ci, ERTS_ASM_BP_FLAG_BP);
            } else {
                version.erts_asm_bp_unset_flag(ci, ERTS_ASM_BP_FLAG_BP);
            }
        }
    }
}

/// Whether the line table of `module` has an entry for source line `line`.
// Port of erts/emulator/beam/beam_ranges.c (erts_find_next_code_for_line: a search of the
// code header's line table), OTP-29.1.1.
pub(crate) fn native_code_has_line(module: &str, line: u32) -> bool {
    versions_of(module).iter().any(|version| {
        version
            .native_functions
            .iter()
            .any(|function| function.line_table.has_line(line))
    })
}

/// Enables or disables the line-breakpoint trampolines of `line` in `module`.
// Port of erts/emulator/beam/beam_bp.c:1755-1790 (erts_install_line_breakpoint /
// erts_uninstall_line_breakpoint: erts_asm_bp_enable / erts_asm_bp_disable of the
// trampoline), OTP-29.1.1.
pub(crate) fn patch_native_line_breakpoint(module: &str, line: u32, enabled: bool) {
    for version in versions_of(module) {
        for &(site_line, address) in &version.line_breakpoints {
            if site_line == line {
                version.erts_asm_bp_toggle(address, enabled);
            }
        }
    }
}

impl CompiledVersion {
    fn with_memory<R>(&self, f: impl FnOnce(&mut CodeMemory) -> R) -> R {
        f(&mut self.memory.lock().unwrap_or_else(PoisonError::into_inner))
    }

    fn read_byte(&self, address: usize) -> u8 {
        let mut byte = [0];
        self.with_memory(|memory| memory.read(address - self.code_start, &mut byte))
            .expect("address inside the module's code");
        byte[0]
    }

    /// `erts_asm_bp_enable` / `erts_asm_bp_disable`: retargets the short jump at `address`
    /// (`jmp short .next; nop; .enabled: call breakpoint_handler; .next:`).
    // Port of erts/emulator/beam/jit/beam_asm.h:185-225 (x86_64 branch), OTP-29.1.1.
    fn erts_asm_bp_toggle(&self, address: usize, enable: bool) {
        let (from, to) = if enable { (0x06, 0x01) } else { (0x01, 0x06) };
        debug_assert_eq!(self.read_byte(address), 0xEB);
        debug_assert_eq!(self.read_byte(address + 1), from);
        self.with_memory(|memory| memory.write(address + 1 - self.code_start, &[to]))
            .expect("breakpoint site inside the module's code");
    }

    // Port of erts/emulator/beam/jit/beam_asm.h:227-242 (erts_asm_bp_set_flag), OTP-29.1.1.
    pub(crate) fn erts_asm_bp_set_flag(&self, ci: usize, flag: u8) {
        let at = ci + BREAKPOINT_FLAG_OFFSET;
        let current = self.read_byte(at);
        if current == 0 {
            self.erts_asm_bp_toggle(ci + std::mem::size_of::<ErtsCodeInfo>(), true);
        }
        self.with_memory(|memory| memory.write(at - self.code_start, &[current | flag]))
            .expect("code info inside the module's code");
    }

    // Port of erts/emulator/beam/jit/beam_asm.h:244-262 (erts_asm_bp_unset_flag), OTP-29.1.1.
    pub(crate) fn erts_asm_bp_unset_flag(&self, ci: usize, flag: u8) {
        let at = ci + BREAKPOINT_FLAG_OFFSET;
        let current = self.read_byte(at);
        if current == 0 {
            return;
        }
        let next = current & !flag;
        self.with_memory(|memory| memory.write(at - self.code_start, &[next]))
            .expect("code info inside the module's code");
        if next == 0 {
            self.erts_asm_bp_toggle(ci + std::mem::size_of::<ErtsCodeInfo>(), false);
        }
    }

    /// Address of the code entry for this version's `-on_load` function.
    // Port of erts/emulator/beam/jit/x86/instr_bif.cpp:1136 (get_on_load_address), OTP-29.1.1.
    pub(crate) fn on_load_address(&self) -> Option<usize> {
        let (name, arity) = self.on_load.as_ref()?;
        self.native_functions
            .iter()
            .find(|native| native.function == *name && native.arity == *arity)
            .map(|native| native.start)
    }

    /// The `ErtsCodeInfo` address of the code of `function/arity`.
    pub(crate) fn code_info(&self, function: arinsal_term::Atom, arity: u8) -> Option<usize> {
        self.code_infos.get(&(function, arity)).copied()
    }

    /// Copies `call_nif` code over the function whose `ErtsCodeInfo` is at `ci`, from
    /// `prologue` bytes into its code on.
    // Port of erts/emulator/beam/erl_nif.c:5149-5160 (load_nif_1st_finisher: sys_memcpy behind
    // BEAM_ASM_FUNC_PROLOGUE_SIZE), OTP-29.1.1.
    pub(crate) fn copy_call_nif(&self, ci: usize, code: &[u8], prologue: usize) {
        let code_rw = ci + std::mem::size_of::<ErtsCodeInfo>() - self.code_start;
        self.with_memory(|memory| memory.write(code_rw + prologue, &code[prologue..]))
            .expect("function body inside the module's code");
    }

    /// Whether `address` lies in this version's code.
    pub(crate) fn contains_code(&self, address: usize) -> bool {
        (self.code_start..self.code_end).contains(&address)
    }

    /// Resolves a PC to its function in this module version.
    // Port of erts/emulator/beam/beam_ranges.c:245-289 (erts_lookup_function_info), OTP-29.1.1.
    pub(crate) fn native_function_for_pc(&self, pc: usize) -> Option<&crate::NativeFunction> {
        let index = self
            .native_functions
            .partition_point(|function| function.start <= pc);
        self.native_functions
            .get(index.checked_sub(1)?)
            .filter(|function| pc < function.end)
    }

    /// `beam_load_finalize_code`: ranges, catches, exports, imports and lambdas, then the
    /// module assembler is deleted.
    // Port of erts/emulator/beam/jit/asm_load.c:1135-1235 (beam_load_finalize_code), OTP-29.1.1.
    pub(crate) fn install(
        self: &Arc<Self>,
        module: &arinsal_loader::Module,
        deferred: bool,
    ) -> bool {
        let Some(ba) = self
            .ba
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
        else {
            return false;
        };
        // erts_update_ranges.
        if crate::native_bridge::register_native_module(
            &self.native_functions,
            self.code_start,
            self.code_end,
        )
        .is_err()
        {
            return false;
        }
        let patched = self.with_memory(|rw| -> Result<(), arinsal_beamasm::beam_asm::AsmError> {
            // inst_p->catches = beamasm_patch_catches(stp->ba, stp->writable_region).
            let catches = arinsal_beamjit::beamasm_patch_catches(&ba, rw)?;
            self.catch_head.store(catches, Ordering::Relaxed);
            for (index, (_, entry)) in self.import_bindings.iter().enumerate() {
                let import = Arc::as_ptr(entry) as usize;
                arinsal_beamjit::beamasm_patch_import(&ba, rw, index as u32, import)?;
            }
            for (index, entry, _) in &self.lambda_targets {
                let fe = Arc::as_ptr(entry) as usize;
                arinsal_beamjit::beamasm_patch_lambda(&ba, rw, *index, fe)?;
            }
            Ok(())
        });
        if patched.is_err() {
            return false;
        }
        let code_index = crate::code_ix::global().staging();
        for (_, entry, target) in &self.lambda_targets {
            entry.set_fun_code(code_index, *target);
        }
        if let Ok(mut versions) = compiled_versions().write() {
            versions.retain(|version| version.strong_count() != 0);
            versions.push(Arc::downgrade(self));
        }
        self.installed.store(true, Ordering::Release);
        publish_module(
            module,
            &self.export_addresses,
            &self.import_bindings,
            deferred,
        );
        true
    }

    /// Releases the version's catches and queues its literals for release.
    // Port of erts/emulator/beam/beam_bif_load.c:2269-2341 (purge complete:
    // beam_catches_delmod, erts_queue_release_literals), OTP-29.1.1.
    pub(crate) fn unpublish(&self) {
        let code = crate::code_ix::global();
        crate::beam_catches::beam_catches_delmod(
            code,
            self.catch_head
                .swap(crate::beam_catches::BEAM_CATCHES_NIL, Ordering::Relaxed),
            self.code_start,
            self.code_end - self.code_start,
            code.active(),
        );
        self.retire_literals();
    }

    fn retire_literals(&self) {
        let heap = self
            .literal_heap
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if let Some(heap) = heap {
            arinsal_pterm::global_store().retire_module_area(heap);
        }
    }

    /// The half-open address range of this version's code.
    pub(crate) fn code_range(&self) -> (usize, usize) {
        (self.code_start, self.code_end)
    }
}

impl Drop for CompiledVersion {
    fn drop(&mut self) {
        // Port of erts/emulator/beam/erl_fun.c:157-179 (fun_purge_foreach: entries of the
        // purged code enter beam_unloaded_fun), OTP-29.1.1.
        let unloaded = arinsal_term::beam_unloaded_fun();
        for entry in &self.lambda_entries {
            for ix in 0..arinsal_term::ERTS_NUM_CODE_IX {
                let target = entry.dispatch_target.address(ix);
                if self.code_start <= target && target < self.code_end {
                    if entry.pend_purge_address.load(Ordering::Acquire) == 0 {
                        entry.set_fun_code(ix, unloaded);
                    } else {
                        entry.dispatch_target.set_address(ix, unloaded);
                    }
                }
            }
        }
        if self.installed.load(Ordering::Acquire) {
            self.retire_literals();
            crate::native_bridge::unregister_native_module(self.code_start, self.code_end);
        }
    }
}

/// `ERTS_COV_*` of the code index's coverage mode.
fn coverage_mode(mode: arinsal_loader::CoverageMode) -> arinsal_beamjit::CoverageMode {
    match mode {
        arinsal_loader::CoverageMode::None => arinsal_beamjit::CoverageMode::None,
        arinsal_loader::CoverageMode::Function => arinsal_beamjit::CoverageMode::Function,
        arinsal_loader::CoverageMode::FunctionCounters => {
            arinsal_beamjit::CoverageMode::FunctionCounters
        }
        arinsal_loader::CoverageMode::Line => arinsal_beamjit::CoverageMode::Line,
        arinsal_loader::CoverageMode::LineCounters => arinsal_beamjit::CoverageMode::LineCounters,
    }
}

/// `beamasm_is_line_breakpoint_trampoline`: the code at `offset` is a disabled or enabled
/// line-breakpoint trampoline.
// Port of erts/emulator/beam/jit/x86/beam_asm_module.cpp:343-380
// (is_line_breakpoint_trampoline), OTP-29.1.1.
fn is_line_breakpoint_trampoline(memory: &CodeMemory, offset: usize) -> bool {
    use arinsal_beamasm::beam_asm_global::GlobalLabels;
    let mut code = [0u8; 8];
    if memory.read(offset, &mut code).is_err()
        || code[0] != 0xEB
        || !matches!(code[1], 0x01 | 0x06)
        || code[2] != 0x90
        || code[3] != 0xE8
    {
        return false;
    }
    let call_offset = i32::from_le_bytes([code[4], code[5], code[6], code[7]]) as isize;
    let target = (memory.as_ptr() as usize + offset + 8).wrapping_add_signed(call_offset);
    crate::beam_jit_main::bga()
        .bga
        .get_ptr(GlobalLabels::ILineBreakpointTrampolineShared)
        == Some(target)
}

/// Loads `beam` with the x86 module assembler: `load_code` with `stp->ba`, then
/// `beam_load_finish_emit` (`beamasm_codegen`, the literal and string patches). The
/// rest of the patches wait for `beam_load_finalize_code` ([`CompiledVersion::install`]).
// Port of erts/emulator/beam/beam_load.c (erts_prepare_loading, load_code) and
// erts/emulator/beam/jit/asm_load.c:972-1132 (beam_load_finish_emit), OTP-29.1.1.
pub(crate) fn compile(
    beam: &BeamFile,
    module: &mut arinsal_loader::Module,
    md5: Option<[u8; 16]>,
    line_breakpoints: bool,
    code_ix: &crate::code_ix::CodeIndexes,
    failure: &mut Option<arinsal_beamjit::CompileError>,
) -> Option<Arc<CompiledVersion>> {
    arinsal_loader::file_atoms(beam).ok()?;
    let (_, import_bindings) = import_entries(module)?;
    let bif_imports = import_bindings
        .iter()
        .map(|(_, entry)| {
            crate::bif_table::function(entry.bif_number.load(std::sync::atomic::Ordering::Relaxed))
        })
        .collect();
    let mut literal_heap = Box::new(VecHeap::new_literal());
    let env = X86LoaderEnv::new(beam, module, &mut literal_heap, bif_imports).ok()?;
    let debugger_flags = if line_breakpoints {
        ERTS_DEBUGGER_LINE_BREAKPOINTS
    } else {
        0
    };
    let fail = |failure: &mut Option<arinsal_beamjit::CompileError>, error: String| {
        *failure = Some(arinsal_beamjit::CompileError::Assemble(format!(
            "{}: {error}",
            beam.module
        )));
    };
    let mut stp = match arinsal_beamjit::beam_load_prepare_emit(
        crate::beam_jit_main::bga(),
        beam,
        &env,
        coverage_mode(code_ix.coverage_mode()),
        debugger_flags,
    ) {
        Ok(stp) => stp,
        Err(error) => {
            fail(failure, error.to_string());
            return None;
        }
    };
    if let Err(error) = arinsal_beamjit::load_code(&mut stp, line_breakpoints) {
        *failure = Some(error);
        return None;
    }
    let Some(md5) = md5 else {
        fail(failure, "module checksum is missing".to_owned());
        return None;
    };
    // Port of erts/emulator/beam/jit/asm_load.c:987-1000: copy the string table, optional
    // ETF chunks, and module checksum into the assembler's read-only data section.
    for (label, bytes) in [
        ("str", beam.strings.as_slice()),
        ("attr", beam.attributes.as_deref().unwrap_or_default()),
        ("compile", beam.compile_info.as_deref().unwrap_or_default()),
        ("md5", md5.as_slice()),
    ] {
        if let Err(error) = stp.ba.embed_rodata(label, bytes) {
            fail(failure, error.to_string());
            return None;
        }
    }
    // Port of erts/emulator/beam/jit/asm_load.c:1002-1008: the coverage tables move to the
    // prepared code.
    let coverage = stp.coverage.take();
    let line_coverage_valid = stp.line_coverage_valid.take();
    let loc_index_to_cover_id = stp.loc_index_to_cover_id.take();
    let mut load_hdr = stp.load_hdr;
    load_hdr.coverage = coverage.as_ref().map_or(0, |table| table.as_ptr() as usize);
    load_hdr.line_coverage_valid = line_coverage_valid
        .as_ref()
        .map_or(0, |table| table.as_ptr() as usize);
    load_hdr.loc_index_to_cover_id = loc_index_to_cover_id
        .as_ref()
        .map_or(0, |table| table.as_ptr() as usize);
    if let Some(attributes) = beam.attributes.as_deref().filter(|bytes| !bytes.is_empty()) {
        load_hdr.attr_size = attributes.len() as u64;
        load_hdr.attr_size_on_heap = match arinsal_etf::decode_ext_size(attributes) {
            Ok(size) => size as u64,
            Err(error) => {
                fail(
                    failure,
                    format!("bad external term representation of module attributes: {error}"),
                );
                return None;
            }
        };
    }
    if let Some(compile_info) = beam
        .compile_info
        .as_deref()
        .filter(|bytes| !bytes.is_empty())
    {
        load_hdr.compile_size = compile_info.len() as u64;
        load_hdr.compile_size_on_heap = match arinsal_etf::decode_ext_size(compile_info) {
            Ok(size) => size as u64,
            Err(error) => {
                fail(
                    failure,
                    format!("bad external term representation of compilation information: {error}"),
                );
                return None;
            }
        };
    }
    let line_instr = stp.line_instr.take().unwrap_or_default();
    // Port of erts/emulator/beam/jit/asm_load.c:1177-1260 (beam_load_finalize_code: the code
    // header's function table is the assembler's `functions`), OTP-29.1.1.
    let functions: Vec<_> = std::mem::take(&mut stp.functions)
        .into_iter()
        .map(|function| arinsal_loader::NativeFunction {
            atom: arinsal_term::Atom(function.atom),
            arity: function.arity,
            entry_label: function.entry_label,
            nif_stub: function.nif_stub,
        })
        .collect();
    let mut ba = stp.ba;
    let (mut memory, code_hdr) = match arinsal_beamjit::beamasm_codegen(&mut ba, &load_hdr) {
        Ok(generated) => generated,
        Err(error) => {
            fail(failure, error.to_string());
            return None;
        }
    };
    let code_start = arinsal_beamjit::beamasm_get_base(&ba)?;
    let code_end = code_start + arinsal_beamjit::beamasm_get_offset(&ba);
    // Port of erts/emulator/beam/jit/asm_load.c:1081-1122: fill chunk pointers after codegen,
    // then use the embedded string table for its instruction patches.
    let code_hdr_offset = code_hdr.checked_sub(code_start)?;
    for (field_offset, pointer) in [
        (
            core::mem::offset_of!(BeamCodeHeader, attr_ptr),
            ba.get_rodata("attr").unwrap_or(0),
        ),
        (
            core::mem::offset_of!(BeamCodeHeader, compile_ptr),
            ba.get_rodata("compile").unwrap_or(0),
        ),
        (
            core::mem::offset_of!(BeamCodeHeader, md5_ptr),
            ba.get_rodata("md5")?,
        ),
    ] {
        if let Err(error) = memory.write(
            code_hdr_offset + field_offset,
            &(pointer as u64).to_le_bytes(),
        ) {
            fail(failure, format!("writing module code header: {error}"));
            return None;
        }
    }
    // Literals: Arinsal's loader built them in the literal area already, so every literal
    // patch writes the word the emitter recorded. erts patches each literal index once
    // (beam_load.c, `beamasm_patch_literal` per index); the patches here are keyed by the
    // word, so each distinct word is one key, patched once.
    let mut words = env.literal_words();
    words.sort_unstable();
    words.dedup();
    for word in words {
        arinsal_beamjit::beamasm_patch_literal(&ba, &mut memory, word, word).ok()?;
    }
    if !beam.strings.is_empty() {
        let string_table = ba.get_rodata("str")?;
        arinsal_beamjit::beamasm_patch_strings(&ba, &mut memory, string_table).ok()?;
    }
    drop(env);
    if module.awaits_native_functions() {
        if let Err(error) = module.finish_native(beam, &functions) {
            fail(failure, format!("{error:?}"));
            return None;
        }
        crate::load::bind_native_static_nifs(module, code_ix);
    }
    let module = &*module;
    let module_text = global_atoms().text(module.name_atom)?;
    // `BeamCodeHeader.functions[]` holds the `ErtsCodeInfo` of each function in code order.
    let mut code_infos = HashMap::with_capacity(functions.len());
    let mut function_starts = Vec::with_capacity(functions.len());
    for function in &functions {
        let entry = arinsal_beamjit::beamasm_get_code(&ba, function.entry_label)?;
        let ci = entry - std::mem::size_of::<ErtsCodeInfo>();
        code_infos.insert((function.atom, function.arity), ci);
        function_starts.push((ci, function));
    }
    function_starts.sort_unstable_by_key(|(ci, _)| *ci);
    // Port of erts/emulator/beam/jit/asm_load.c (finish_line_table): `loc_tab` with each
    // line instruction's native address.
    let line_items = beam.lines.as_ref();
    let mut file_names: Vec<crate::NativeFile> = Vec::new();
    let mut file_indices = HashMap::new();
    let mut line_breakpoints = Vec::new();
    let location_table: Arc<[crate::NativeLine]> = line_instr
        .iter()
        .map(|instr| {
            let address = code_start + instr.pos;
            let item = line_items.and_then(|lines| {
                lines
                    .items
                    .get((instr.loc as usize).checked_sub(1)?)
                    .map(|item| (lines, item))
            });
            let Some((lines, item)) = item else {
                return crate::NativeLine {
                    address,
                    location: 0,
                };
            };
            let file_index = *file_indices.entry(item.name_index).or_insert_with(|| {
                let name: Arc<str> = match item.name_index.checked_sub(1) {
                    Some(at) => lines.names.get(at as usize).cloned().unwrap_or_default(),
                    None => format!("{}.erl", beam.module),
                }
                .into();
                file_names.push(crate::NativeFile {
                    file_term: module.line_file_terms.get(&*name).copied(),
                    name,
                });
                file_names.len() - 1
            });
            // Port of erts/emulator/beam/beam_code.h:31-39 (MAKE_LOCATION).
            let location = if file_index < 255 && item.line < (1 << 24) - 1 {
                ((file_index as u32) << 24) | item.line as u32
            } else {
                0
            };
            // Port of erts/emulator/beam/erl_debugger.c:290-300 (erts_find_next_code_for_line,
            // then beamasm_is_line_breakpoint_trampoline): a line entry whose code is
            // `jmp short .next; nop; call` is a trampoline.
            if debugger_flags & ERTS_DEBUGGER_LINE_BREAKPOINTS != 0
                && is_line_breakpoint_trampoline(&memory, instr.pos)
            {
                line_breakpoints.push((item.line as u32, address));
            }
            crate::NativeLine { address, location }
        })
        .collect();
    let file_names: Arc<[crate::NativeFile]> = file_names.into();
    let location_addresses: Arc<[usize]> = location_table
        .iter()
        .map(|entry| entry.address)
        .chain(std::iter::once(code_end))
        .collect();
    let mut native_functions = Vec::with_capacity(function_starts.len());
    for (at, (ci, function)) in function_starts.iter().enumerate() {
        let start = ci + std::mem::size_of::<ErtsCodeInfo>();
        let end = function_starts
            .get(at + 1)
            .map_or(code_end, |(next, _)| *next);
        let first = location_table
            .partition_point(|entry| entry.address <= start)
            .saturating_sub(1);
        let last = location_table
            .partition_point(|entry| entry.address < end)
            .max(first);
        native_functions.push(crate::NativeFunction {
            fragment: false,
            start,
            end,
            module: module_text,
            module_atom: module.name_atom,
            function: global_atoms().text(function.atom)?,
            function_atom: function.atom,
            arity: function.arity,
            line: None,
            file: None,
            line_table: crate::NativeLines::window(
                &location_table,
                &location_addresses,
                &file_names,
                first,
                last,
            ),
            file_term: None,
        });
    }
    // Port of erts/emulator/beam/jit/asm_load.c:1162-1176 (exports: beamasm_get_code of each
    // export label).
    let mut export_addresses = Vec::with_capacity(beam.exports.len());
    for export in &beam.exports {
        let name = beam.atom(export.function_atom)?;
        let arity = u8::try_from(export.arity).ok()?;
        // BIF exports retain their `call_bif` dispatch address.
        if arinsal_spec::bif_lookup(&beam.module, name, arity).is_some() {
            continue;
        }
        let atom = global_atoms().get(name)?;
        module.export_slot_atom(atom, arity)?;
        export_addresses.push((
            (module.name_atom, atom, arity),
            arinsal_beamjit::beamasm_get_code(&ba, export.label)?,
        ));
    }
    // Port of erts/emulator/beam/jit/asm_load.c:1196-1225 (fun entries and their code).
    let lambda_entries = module
        .funs
        .iter()
        .map(|slot| Arc::clone(&slot.entry))
        .collect::<Vec<_>>();
    let mut lambda_targets = Vec::with_capacity(beam.lambdas.len());
    for lambda in &beam.lambdas {
        let entry = lambda_entries
            .iter()
            .find(|entry| entry.old_index == lambda.index)?;
        let code = arinsal_beamjit::beamasm_get_lambda(&ba, lambda.index)?;
        lambda_targets.push((lambda.index, Arc::clone(entry), code));
    }
    let on_load = arinsal_beamjit::beamasm_get_on_load(&ba).and_then(|ci| {
        code_infos
            .iter()
            .find(|(_, found)| **found == ci)
            .and_then(|((atom, arity), _)| Some((global_atoms().text(*atom)?.to_owned(), *arity)))
    });
    Some(Arc::new(CompiledVersion {
        module: module.name.clone(),
        on_load,
        ba: Mutex::new(Some(ba)),
        memory: Mutex::new(memory),
        code_start,
        code_end,
        installed: AtomicBool::new(false),
        catch_head: AtomicU32::new(crate::beam_catches::BEAM_CATCHES_NIL),
        import_bindings,
        export_addresses,
        lambda_targets,
        lambda_entries,
        native_functions: Arc::from(native_functions),
        code_infos,
        line_breakpoints,
        literal_heap: Mutex::new(Some(Arc::from(literal_heap))),
        _module_literals: module.literal_area(),
        _coverage: coverage,
        _line_coverage_valid: line_coverage_valid,
        _loc_index_to_cover_id: loc_index_to_cover_id,
    }))
}
