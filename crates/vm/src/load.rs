//! Module loading and code index management.

use super::*;
use arinsal_term::{Atom, FunEntry, global_atoms};
use std::hash::{BuildHasherDefault, Hash, Hasher};

#[derive(Clone)]
pub(crate) struct SharedTable<T: Clone>(Arc<T>);

impl<T: Clone> SharedTable<T> {
    fn new(value: T) -> Self {
        Self(Arc::new(value))
    }
}

impl<T: Clone> std::ops::Deref for SharedTable<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T: Clone> std::ops::DerefMut for SharedTable<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        Arc::make_mut(&mut self.0)
    }
}

/// A module name usable as a [`ModuleIndex`] key: an atom, or text that is resolved to one.
pub(crate) trait ModuleKey {
    fn atom(&self) -> Option<Atom>;
}

impl ModuleKey for Atom {
    fn atom(&self) -> Option<Atom> {
        Some(*self)
    }
}

impl ModuleKey for str {
    fn atom(&self) -> Option<Atom> {
        global_atoms().get(self)
    }
}

impl ModuleKey for String {
    fn atom(&self) -> Option<Atom> {
        self.as_str().atom()
    }
}

impl<K: ModuleKey + ?Sized> ModuleKey for &K {
    fn atom(&self) -> Option<Atom> {
        (**self).atom()
    }
}

/// Current modules by name atom: module.c's `module_tables[ix]` is keyed by the module atom
/// index, so a lookup from a BIF hashes a word, not a string.
// Port of erts/emulator/beam/module.c:47 (module_tables), OTP-29.1.1.
#[derive(Clone, Default)]
pub(crate) struct ModuleIndex(
    HashMap<Atom, usize, std::hash::BuildHasherDefault<crate::process::IdHasher>>,
);

impl ModuleIndex {
    pub(crate) fn get<K: ModuleKey + ?Sized>(&self, key: &K) -> Option<&usize> {
        self.0.get(&key.atom()?)
    }

    pub(crate) fn contains_key<K: ModuleKey + ?Sized>(&self, key: &K) -> bool {
        key.atom().is_some_and(|atom| self.0.contains_key(&atom))
    }

    pub(crate) fn insert(&mut self, name: &str, id: usize) -> Option<usize> {
        let atom = global_atoms().intern(name).ok()?;
        self.0.insert(atom, id)
    }

    pub(crate) fn remove<K: ModuleKey + ?Sized>(&mut self, key: &K) -> Option<usize> {
        self.0.remove(&key.atom()?)
    }

    pub(crate) fn keys(&self) -> impl Iterator<Item = &str> {
        self.0.keys().filter_map(|atom| global_atoms().text(*atom))
    }

    pub(crate) fn values(&self) -> impl Iterator<Item = &usize> {
        self.0.values()
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct FunKey {
    module: Atom,
    index: u32,
    arity: u8,
    uniq: [u8; 16],
}

impl From<&FunEntry> for FunKey {
    fn from(entry: &FunEntry) -> Self {
        Self {
            module: entry.module,
            index: entry.index,
            arity: entry.arity,
            uniq: entry.uniq,
        }
    }
}

impl Hash for FunKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // Port of erts/emulator/beam/erl_fun.c:60-74 (fun_hash), OTP-29.1.1.
        let first = u64::from_ne_bytes(self.uniq[..8].try_into().expect("eight bytes"));
        let second = u64::from_ne_bytes(self.uniq[8..].try_into().expect("eight bytes"));
        state.write_u64(first ^ second ^ u64::from(self.index));
    }
}

#[derive(Default)]
pub(crate) struct FunTableHasher(u64);

impl Hasher for FunTableHasher {
    fn finish(&self) -> u64 {
        self.0
    }

    fn write(&mut self, bytes: &[u8]) {
        if let Ok(bytes) = <[u8; 8]>::try_from(bytes) {
            self.0 = u64::from_ne_bytes(bytes);
        }
    }
}

type FunEntries = HashMap<FunKey, Arc<FunEntry>, BuildHasherDefault<FunTableHasher>>;

/// Key of `loaded_nifs`: NIF libraries are tracked per code instance, like erts' `Module.curr.nif`.
pub(crate) fn nif_key(name: &str, id: usize) -> String {
    format!("{name}#{id}")
}

/// The code tables of one code index: module.c `module_tables[ix]` (current, old and on_load
/// instances by module), export.c's export table and the instances' code and ranges.
// Port of erts/emulator/beam/module.c:47 (module_tables), export.c (export_tables) and
// beam_ranges.c:58 (r), OTP-29.1.1.
#[derive(Clone)]
pub(crate) struct CodeTables {
    pub(crate) code_scope: u64,
    /// The published version of these tables; see [`crate::code_ix::next_generation`].
    pub(crate) generation: u64,
    pub(crate) modules: SharedTable<Vec<Arc<Module>>>,
    pub(crate) loaded: SharedTable<ModuleIndex>,
    pub(crate) old: SharedTable<HashMap<String, usize>>,
    pub(crate) pending_on_load: SharedTable<HashMap<String, usize>>,
    pub(crate) deleted: SharedTable<std::collections::HashSet<String>>,
    pub(crate) code_meta: SharedTable<Vec<Option<Arc<CodeMeta>>>>,
    pub(crate) registers: SharedTable<Vec<(usize, usize)>>,
    pub(crate) loaded_nifs: SharedTable<std::collections::HashSet<String>>,
    // g_code_fix
    pub(crate) exports: SharedTable<ExportIndex>,
    /// OTP's global local-fun table, staged with the node's code indexes.
    funs: SharedTable<FunEntries>,
    pub(crate) free_ids: SharedTable<Vec<usize>>,
    pub(crate) module_live: SharedTable<Vec<bool>>,
    pub(crate) module_files: SharedTable<HashMap<String, arinsal_etf::OwnedTerm>>,
    pub(crate) condemned: SharedTable<Vec<usize>>,
    // g_code_fix: a module entry survives purge, so later delete_module stays true.
    pub(crate) known_modules: SharedTable<HashSet<String>>,
    // arl: code domains.
    /// Module overlays of the non-base code domains.
    pub(crate) domains: SharedTable<crate::code_domains::Domains>,
}

fn bind_import_targets(module: &mut Module) {
    for import in &mut module.imports {
        if import.bif.is_none()
            && let Some(bif) =
                natives::plain_static_nif_lookup(&import.module, &import.function, import.arity)
        {
            import.set_extra_bif(bif);
        }
        let (class, bits) = natives::classify(
            &import.module,
            &import.function,
            import.arity,
            import.bif_fn().is_some(),
        );
        // Publish the pointer before the class so a reader that sees `Native`
        // also sees the entry.
        if bits != 0 {
            import.set_native_bits(bits);
        }
        import.set_class(class);
        if class == arinsal_loader::ImportClass::Pure
            && import.fast_op == arinsal_loader::ImportFastOp::None
            && crate::bif_traps::traps(&import.module, &import.function, import.arity)
        {
            import.fast_op = arinsal_loader::ImportFastOp::Trapping;
        }
    }
}

fn bind_static_nifs(module: &mut Module, code_ix: &crate::code_ix::CodeIndexes) {
    // Classify every import before the module is shared, including modules
    // that have no static NIF body.
    bind_import_targets(module);
    if !matches!(
        module.name.as_str(),
        "prim_file"
            | "prim_buffer"
            | "zlib"
            | "zstd"
            | "prim_tty"
            | "prim_socket"
            | "prim_net"
            | "re"
            | "erts_debug"
    ) {
        arinsal_loader::specialize_bif_calls(module);
        return;
    }
    for (entry, function, arity) in &module.functions {
        let Some(native) =
            natives::static_nif_lookup(&module.name, function, *arity).or_else(|| {
                (module.name == "erts_debug")
                    .then(|| arinsal_bifs::lookup(&module.name, function, *arity))
                    .flatten()
            })
        else {
            continue;
        };
        let Some(index) = code_ix.push_native_fn(crate::natives::nif::NativeFn::Bif(native)) else {
            continue;
        };
        if let Some(body) = module.code.get_mut(entry.saturating_add(1)) {
            *body = Instr::NativeBody { index };
        }
    }
    arinsal_loader::specialize_bif_calls(module);
}
#[derive(Clone)]
pub(crate) struct CodeMeta {
    pub(crate) beam: BeamFile,
    pub(crate) md5: Option<[u8; 16]>,
    pub(crate) on_load: Option<(String, u8)>,
    /// The loader was given the original BEAM bytes, so this instance can be compiled.
    /// The bytes themselves are not kept: erts discards the file after `beam_load`.
    pub(crate) has_beam_bytes: bool,
    pub(crate) beamasm: Option<Arc<beamasm_integration::CompiledVersion>>,
}
/// Native code range of the module version in slot `id`, when it was compiled by BeamAsm.
pub(crate) fn native_code_range(
    code_meta: &[Option<Arc<CodeMeta>>],
    id: usize,
) -> Option<(usize, usize)> {
    code_meta
        .get(id)?
        .as_ref()?
        .beamasm
        .as_ref()
        .map(|version| version.code_range())
}

/// Native function metadata of the module version in slot `id`, when it was compiled by BeamAsm.
pub(crate) fn native_code_version(
    code_meta: &[Option<Arc<CodeMeta>>],
    id: usize,
) -> Option<&Arc<beamasm_integration::CompiledVersion>> {
    code_meta.get(id)?.as_ref()?.beamasm.as_ref()
}

/// Whether `address` belongs to the native code of one compiled module version.
// Port of erts/emulator/beam/beam_ranges.c:245-289 (erts_lookup_function_info), OTP-29.1.1.
pub(crate) fn native_code_contains(
    version: Option<&beamasm_integration::CompiledVersion>,
    address: usize,
) -> bool {
    version.is_some_and(|version| {
        version.contains_code(address) || version.native_function_for_pc(address).is_some()
    })
}
impl CodeMeta {
    pub(crate) fn from_beam(beam: &BeamFile, bytes: Option<&[u8]>) -> Self {
        // OTP encodes -on_load as a Code instruction following that function's label.
        let mut function = None;
        let mut on_load = None;
        for instruction in &beam.code.instructions {
            if instruction.op == arinsal_spec::Opcode::FuncInfo {
                function = match (instruction.args.get(1), instruction.args.get(2)) {
                    (
                        Some(arinsal_beam::Operand::Atom(name)),
                        Some(arinsal_beam::Operand::U(arity)),
                    ) => beam.atom(*name).and_then(|name| {
                        u8::try_from(*arity)
                            .ok()
                            .map(|arity| (name.to_owned(), arity))
                    }),
                    _ => None,
                };
            } else if instruction.op == arinsal_spec::Opcode::OnLoad {
                on_load = function.clone();
                break;
            }
        }
        Self {
            beam: beam.clone(),
            md5: bytes.and_then(|bytes| arinsal_loader::module_uniq(bytes).ok()),
            on_load,
            has_beam_bytes: bytes.is_some(),
            beamasm: None,
        }
    }
}

// g_code_fix: insertion-order export index. module_info(exports) walks it
// from the start and conses, so the Erlang list is reverse insertion order.
//
// Port of erts/emulator/beam/jit/beam_jit_main.cpp:117 (install_bifs),
// erts/emulator/beam/erl_init.c:314 (erts_init_bif_re then erts_init_unicode),
// erts/emulator/beam/jit/asm_load.c:1180 (beam_load_finalize_code exports then
// imports), and erts/emulator/beam/erl_bif_info.c:5825 (exported_from_module),
// OTP-29.1.1.
#[derive(Clone)]
pub(crate) struct ExportIndex {
    /// Insertion order of export entries. Atoms, as in erts' export table
    /// (`export.c` / `index.c`), so staging copies the index without cloning MFA strings.
    pub(crate) order: Vec<(Atom, Atom, u8)>,
    seen: HashSet<(Atom, Atom, u8)>,
    /// Atom-keyed erts exports, including each JIT dispatch address vector.
    // Port of erts/emulator/beam/export.c:38-58, OTP-29.1.1.
    entries: HashMap<(Atom, Atom, u8), ExportIndexEntry, crate::beamasm_integration::ExportHasher>,
}

#[derive(Clone, Copy, Default)]
struct ExportIndexEntry {
    dispatch: Option<&'static arinsal_beamasm::bif::ExportEntry>,
}

impl ExportIndex {
    fn new() -> Self {
        let mut index = Self {
            order: Vec::new(),
            seen: HashSet::new(),
            entries: HashMap::with_hasher(crate::beamasm_integration::ExportHasher),
        };
        for line in include_str!("../../../spec/otp-29.1.1/bif.tab").lines() {
            if let Some((module, function, arity)) = parse_bif_mfa(line) {
                index.put(&module, &function, arity);
            }
        }
        // Port of erts/emulator/beam/erl_bif_re.c:222 (erts_init_bif_re) and
        // erts/emulator/beam/erl_unicode.c:103 (erts_init_unicode), OTP-29.1.1.
        // These trap entries are inserted after install_bifs and before any
        // module, so they keep that index even though they also appear in ExpT.
        for (module, function, arity) in [
            ("re", "grun", 3),
            ("re", "urun", 3),
            ("re", "ucompile", 2),
            ("unicode", "characters_to_binary_int", 2),
            ("unicode", "characters_to_list_int", 2),
        ] {
            index.put(module, function, arity);
        }
        index
    }

    // Port of erts/emulator/beam/export.c (erts_export_put) and
    // erts/emulator/beam/index.c (index_put_entry), OTP-29.1.1.
    // An MFA already in the index keeps its original position. Keys are atoms,
    // the same layout as erts' export entries, not owned MFA strings.
    fn put(&mut self, module: &str, function: &str, arity: u8) {
        let (Ok(module_atom), Ok(function_atom)) = (
            global_atoms().intern(module),
            global_atoms().intern(function),
        ) else {
            return;
        };
        self.put_atoms(module_atom, function_atom, arity);
    }

    fn put_atoms(&mut self, module: Atom, function: Atom, arity: u8) {
        // Port of erts/emulator/beam/export.c (erts_export_put): one entry per MFA.
        self.entries.entry((module, function, arity)).or_default();
        if self.seen.insert((module, function, arity)) {
            self.order.push((module, function, arity));
        }
    }

    fn note_module(&mut self, module: &Module) {
        for export in &module.exports {
            self.put_atoms(export.module_atom, export.function_atom, export.arity);
        }
        for import in &module.imports {
            self.put_atoms(import.module_atom, import.function_atom, import.arity);
        }
    }

    fn note_beam(&mut self, beam: &BeamFile) {
        for export in &beam.exports {
            let Some(function) = beam.atom(export.function_atom) else {
                continue;
            };
            self.put(&beam.module, function, export.arity as u8);
        }
        for import in &beam.imports {
            let (Some(module), Some(function)) = (
                beam.atom(import.module_atom),
                beam.atom(import.function_atom),
            ) else {
                continue;
            };
            self.put(module, function, import.arity as u8);
        }
    }

    pub(crate) fn bind_dispatch(
        &mut self,
        key: (Atom, Atom, u8),
        dispatch: &'static arinsal_beamasm::bif::ExportEntry,
    ) {
        self.entries.entry(key).or_default().dispatch = Some(dispatch);
    }

    pub(crate) fn dispatch(
        &self,
        key: (Atom, Atom, u8),
    ) -> Option<&'static arinsal_beamasm::bif::ExportEntry> {
        self.entries.get(&key)?.dispatch
    }
}

fn parse_bif_mfa(line: &str) -> Option<(String, String, u8)> {
    let line = line.split('#').next()?.trim();
    let mut parts = line.split_whitespace();
    let kind = parts.next()?;
    if !matches!(kind, "bif" | "ubif" | "hbif") {
        return None;
    }
    let mfa = parts.next()?;
    let (module, rest) = mfa.split_once(':')?;
    let (name, arity) = rest.rsplit_once('/')?;
    let name = name.trim_matches('\'');
    Some((module.to_owned(), name.to_owned(), arity.parse().ok()?))
}

pub(crate) fn path_charlist(path: &Path) -> arinsal_etf::OwnedTerm {
    arinsal_etf::OwnedTerm::charlist(&path.display().to_string())
}

// g_code_fix
struct SlotTable<'a> {
    modules: &'a mut Vec<Arc<Module>>,
    registers: &'a mut Vec<(usize, usize)>,
    code_meta: &'a mut Vec<Option<Arc<CodeMeta>>>,
    live: &'a mut Vec<bool>,
    free_ids: &'a mut Vec<usize>,
}

// g_code_fix
fn alloc_slot(
    table: &mut SlotTable<'_>,
    stored: Arc<Module>,
    regs: (usize, usize),
    meta: Option<CodeMeta>,
) -> usize {
    if let Some(id) = table.free_ids.pop() {
        table.modules[id] = stored;
        table.registers[id] = regs;
        table.code_meta[id] = meta.map(Arc::new);
        table.live[id] = true;
        id
    } else {
        let id = table.modules.len();
        table.modules.push(stored);
        table.registers.push(regs);
        table.code_meta.push(meta.map(Arc::new));
        table.live.push(true);
        id
    }
}

// g_code_fix
fn release_slot(
    live: &mut [bool],
    meta: &mut [Option<Arc<CodeMeta>>],
    free_ids: &mut Vec<usize>,
    id: usize,
) {
    if id >= live.len() || !live[id] || free_ids.contains(&id) {
        return;
    }
    live[id] = false;
    if id < meta.len() {
        meta[id] = None;
    }
    free_ids.push(id);
}

impl CodeTables {
    pub(crate) fn new(code_scope: u64) -> Self {
        Self {
            code_scope,
            generation: crate::code_ix::next_generation(),
            modules: SharedTable::new(Vec::new()),
            loaded: SharedTable::new(ModuleIndex::default()),
            old: SharedTable::new(HashMap::new()),
            pending_on_load: SharedTable::new(HashMap::new()),
            deleted: SharedTable::new(std::collections::HashSet::new()),
            code_meta: SharedTable::new(Vec::new()),
            registers: SharedTable::new(Vec::new()),
            loaded_nifs: SharedTable::new(std::collections::HashSet::new()),
            exports: SharedTable::new(ExportIndex::new()),
            funs: SharedTable::new(HashMap::with_hasher(BuildHasherDefault::default())),
            free_ids: SharedTable::new(Vec::new()),
            module_live: SharedTable::new(Vec::new()),
            module_files: SharedTable::new(HashMap::new()),
            condemned: SharedTable::new(Vec::new()),
            known_modules: SharedTable::new(HashSet::new()),
            // arl: code domains.
            domains: SharedTable::new(crate::code_domains::Domains::default()),
        }
    }

    /// Canonicalizes one lambda entry through the staged global fun table.
    // Port of erts/emulator/beam/erl_fun.c:270-309 (init_fun_template/entry_put/get_or_make_stub), OTP-29.1.1.
    pub(crate) fn intern_fun_entry(&mut self, candidate: Arc<FunEntry>) -> Arc<FunEntry> {
        let key = FunKey::from(candidate.as_ref());
        Arc::clone(self.funs.entry(key).or_insert(candidate))
    }

    /// Canonicalizes the module's lambda slots through the staged global fun table.
    pub(crate) fn intern_fun_entries(&mut self, module: &mut Module) {
        for slot in &mut module.funs {
            slot.entry = self.intern_fun_entry(Arc::clone(&slot.entry));
        }
    }

    /// Applies `fun_stage` to every active-table entry when code staging starts.
    pub(crate) fn stage_fun_entries(&self, active: usize, staging: usize) {
        for entry in self.funs.values() {
            entry.stage_fun_code(active, staging);
        }
    }

    /// Iterates the current global fun-table objects for purge preparation.
    pub(crate) fn fun_entries(&self) -> impl Iterator<Item = &Arc<FunEntry>> {
        self.funs.values()
    }

    /// Adds a module instance and returns its id.
    pub(crate) fn alloc(
        &mut self,
        module: Arc<Module>,
        registers: (usize, usize),
        meta: Option<CodeMeta>,
    ) -> usize {
        self.exports.note_module(&module);
        let id = alloc_slot(
            &mut SlotTable {
                modules: &mut self.modules,
                registers: &mut self.registers,
                code_meta: &mut self.code_meta,
                live: &mut self.module_live,
                free_ids: &mut self.free_ids,
            },
            module,
            registers,
            meta,
        );
        crate::trace_bp::clear_module_line_breakpoints(self.code_scope, id);
        id
    }

    // arl: code domains.
    /// Adds a module instance of a non-base code domain and returns its id. Unlike
    /// [`CodeTables::alloc`] it leaves the node's export index alone: domain modules are not
    /// exports of the node.
    pub(crate) fn alloc_in_domain(
        &mut self,
        module: Arc<Module>,
        registers: (usize, usize),
        meta: Option<CodeMeta>,
    ) -> usize {
        let id = alloc_slot(
            &mut SlotTable {
                modules: &mut self.modules,
                registers: &mut self.registers,
                code_meta: &mut self.code_meta,
                live: &mut self.module_live,
                free_ids: &mut self.free_ids,
            },
            module,
            registers,
            meta,
        );
        crate::trace_bp::clear_module_line_breakpoints(self.code_scope, id);
        id
    }

    /// Module slot that the next `alloc` will assign in this staging table.
    pub(crate) fn next_module_id(&self) -> usize {
        self.free_ids.last().copied().unwrap_or(self.modules.len())
    }

    /// Makes instance `id` the current code of `name` and returns the instance it replaces.
    pub(crate) fn make_current(&mut self, name: &str, id: usize) -> Option<usize> {
        let previous = self.loaded.insert(name, id);
        activate_module_records(self.code_scope, &self.modules[id]);
        self.deleted.remove(name);
        self.known_modules.insert(name.to_owned());
        previous
    }

    /// Frees the slot of a purged instance and returns its native code, which the caller
    /// unpublishes (`CompiledVersion::unpublish`) once it may stage, like the explicit free of
    /// the old code header in erts `erts_internal:purge_module/2` `complete`. Nothing unpublishes
    /// from a destructor.
    // Port of erts/emulator/beam/beam_bif_load.c (purge_module complete: delete_code frees the
    // old code explicitly under the code modification permission), OTP-29.1.1.
    #[must_use]
    pub(crate) fn release(
        &mut self,
        id: usize,
    ) -> Option<Arc<beamasm_integration::CompiledVersion>> {
        let native = self
            .code_meta
            .get(id)
            .and_then(Option::as_ref)
            .and_then(|meta| meta.beamasm.clone());
        crate::trace_bp::clear_module_line_breakpoints(self.code_scope, id);
        // Port of erts/emulator/beam/erl_nif.c (erts_unload_nif on purge), OTP-29.1.1: a NIF
        // library belongs to its code instance, so purging it lets a later load bind again.
        if self.module_live.get(id).copied() == Some(true)
            && let Some(module) = self.modules.get(id)
        {
            crate::code_ix::for_scope(self.code_scope).release_native_fns(module);
            let key = nif_key(&module.name, id);
            self.loaded_nifs.remove(&key);
            crate::natives::nif::unload_instance(self.code_scope, id);
            if let Some(area) = self.modules[id].literal_area().take() {
                arinsal_pterm::store_for(self.code_scope).retire_module_area(area);
            }
        }
        release_slot(
            &mut self.module_live,
            &mut self.code_meta,
            &mut self.free_ids,
            id,
        );
        native
    }
}

/// Port of erts/emulator/beam/erl_record.c:171-193 (erts_record_put,
/// erts_record_module_delete), OTP-29.1.1: make the record definitions of the code that
/// becomes current for its module the canonical ones, replacing those of the previous code.
pub(crate) fn activate_module_records(scope: u64, module: &Module) {
    arinsal_term::delete_module_record_definitions(scope, module.name_atom);
    let atoms = global_atoms();
    for (record, cons) in module.records.iter().zip(&module.record_defs) {
        let (Ok(name), Some((definition, _))) =
            (atoms.intern(&record.name), crate::lists::split(*cons))
        else {
            continue;
        };
        arinsal_term::put_record_definition(scope, module.name_atom, name, *cons, definition);
    }
}

/// Port of erts/emulator/beam/beam_bif_load.c:2451 (erts_record_module_delete) at the point
/// where the current code of `module` becomes old.
pub(crate) fn retract_module_records(scope: u64, module: &str) {
    if let Ok(atom) = global_atoms().intern(module) {
        arinsal_term::delete_module_record_definitions(scope, atom);
    }
}

// VM load implementation.

/// Modules of `erlang:finish_loading/1` staged in an ended staging area, waiting for the
/// loader's code barrier before the commit.
pub(crate) struct StagedLoad {
    /// `None` when the staging area was nested in an outer one, which commits it.
    pub(crate) ended: Option<crate::code_ix::EndedStaging>,
    /// Set for a scheduler-backed load; its thread-progress callback owns the commit.
    pub(crate) barrier_passed: Option<Arc<std::sync::atomic::AtomicBool>>,
    ids: Vec<usize>,
    /// Names of the staged modules.
    pub(crate) names: Vec<String>,
    on_load: Vec<String>,
}

impl Vm {
    /// Resolve a native record definition from the active module version.
    pub(crate) fn native_record_definition(
        &self,
        module: &str,
        name: &str,
    ) -> Option<&arinsal_beam::NativeRecord> {
        let id = *self.code.loaded.get(module)?;
        self.code
            .modules
            .get(id)?
            .records
            .iter()
            .find(|record| record.name == name)
    }

    /// Resolve an MFA through the atom-keyed export table, loading a stub's module if needed.
    pub(crate) fn spawn_export(
        &mut self,
        module_atom: Atom,
        function_atom: Atom,
        arity: u8,
    ) -> Result<(usize, usize), VmError> {
        // Port of erts/emulator/beam/export.c:228-242 (erts_export_get_or_make_stub), OTP-29.1.1.
        let key = (module_atom, function_atom, arity);
        if !self.code.exports.entries.contains_key(&key) {
            self.code_ix.update_active(|tables| {
                tables.exports.entries.entry(key).or_default();
            });
        }
        let module_name = global_atoms()
            .text(module_atom)
            .ok_or_else(|| VmError::Load("invalid module atom".into()))?;
        let module_id = self.load_named(module_name)?;
        let module = &self.code.modules[module_id];
        let Some(export) = module.export_slot_atom(function_atom, arity) else {
            return Err(VmError::Trap(crate::exceptions::Trap::error(
                crate::signals::atom("undef"),
            )));
        };
        Ok((module_id, export.target()))
    }

    /// Construct a VM. Explicit paths precede the current directory and OTP libraries.
    pub fn new(paths: impl IntoIterator<Item = PathBuf>) -> Self {
        // Fixes the execution mode, which erlang:system_info(emu_flavor) reports.
        crate::beamasm_integration::enabled();
        let otp = std::env::var_os("ARINSAL_OTP_ROOT")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("ERL_ROOTDIR").map(PathBuf::from))
            .or_else(|| {
                // Discovery runs the `erl` launcher (~100 ms); every VM of a process shares it.
                static DISCOVERED: std::sync::OnceLock<Option<PathBuf>> =
                    std::sync::OnceLock::new();
                DISCOVERED
                    .get_or_init(|| {
                        arinsal_args::discover_otp_root(&arinsal_args::ProcessEnv)
                            .map(PathBuf::from)
                    })
                    .clone()
            })
            .unwrap_or_default();
        Self::new_with_otp_root(paths, otp)
    }

    /// Construct a VM with a known OTP root, without querying the `erl` launcher.
    pub(crate) fn new_with_otp_root(
        paths: impl IntoIterator<Item = PathBuf>,
        otp: PathBuf,
    ) -> Self {
        let mut paths: Vec<PathBuf> = paths.into_iter().collect();
        paths.push(PathBuf::from("."));
        paths.push(PathBuf::from("bench/out/ebin"));
        if let Ok(entries) = std::fs::read_dir(otp.join("lib")) {
            let mut dirs: Vec<_> = entries
                .filter_map(Result::ok)
                .map(|entry| entry.path().join("ebin"))
                .filter(|p| p.is_dir())
                .collect();
            dirs.sort();
            paths.extend(dirs);
        }
        paths.push(otp.join("lib/erts-17.1/ebin"));
        let code_scope = beamasm_integration::new_code_scope();
        Self::for_code_scope(paths, Some(otp), code_scope, false)
    }

    fn for_code_scope(
        paths: Vec<PathBuf>,
        otp_root: Option<PathBuf>,
        code_scope: u64,
        replica: bool,
    ) -> Self {
        crate::fun_dispatch::set_thread_code_scope(code_scope);
        let code_ix = crate::code_ix::for_scope(code_scope);
        Self {
            paths,
            statistics_origins: if replica {
                crate::natives::sys::StatisticsOrigins::now()
            } else {
                crate::natives::sys::initialize_statistics_origins()
            },
            otp_root,
            code: code_ix.active_tables(),
            native_fns: code_ix.native_fns(),
            purge_state: Arc::clone(&code_ix.purge_state),
            beamasm_targets: beamasm_integration::NativeTargetCache::new(code_scope),
            code_scope,
            code_ix,
            replica,
            backtrace_depth: 8,
        }
    }

    /// A scheduler's VM over the code of the node with code scope `code_scope`.
    pub(crate) fn shared_replica(code_scope: u64, paths: &[PathBuf]) -> Self {
        Self::for_code_scope(paths.to_vec(), None, code_scope, true)
    }

    /// Construct a VM with OTP's debugger startup flags applied before any module is loaded.
    pub fn new_with_debugger_flags(
        paths: impl IntoIterator<Item = PathBuf>,
        debugger_support: bool,
        line_breakpoints: bool,
    ) -> Self {
        crate::trace_bp::configure_debugger(debugger_support, line_breakpoints);
        Self::new(paths)
    }

    /// Record a BEAM file's exports then imports in global export-index order
    /// without installing the module.
    ///
    /// Replaying `lists:reverse(erlang:loaded())` this way reproduces
    /// `module_info(exports)` on a booted node.
    pub fn note_beam_exports(&mut self, bytes: &[u8]) -> Result<(), VmError> {
        let beam = arinsal_beam::parse(bytes).map_err(|e| VmError::Load(e.to_string()))?;
        let staging = self.code_ix.start_staging();
        staging.with(|tables| tables.exports.note_beam(&beam));
        drop(staging);
        self.refresh_code();
        Ok(())
    }

    /// Live module versions. A purged version is omitted once its slot can be reused.
    pub fn module_storage_count(&self) -> usize {
        self.code.module_live.iter().filter(|live| **live).count()
    }

    /// Module-table length, including slots retained for reuse after a purge.
    pub fn module_table_len(&self) -> usize {
        self.code.modules.len()
    }

    /// The coverage mode modules loaded now get (`code:get_coverage_mode/0`).
    pub(crate) fn coverage_mode(&self) -> arinsal_loader::CoverageMode {
        self.code_ix.coverage_mode()
    }

    pub(crate) fn set_coverage_mode(&mut self, mode: arinsal_loader::CoverageMode) {
        self.code_ix.set_coverage_mode(mode);
    }

    /// Prepares a module instance from a parsed BEAM file: loader, fun identities, static NIFs.
    pub(crate) fn prepare_module(
        &self,
        beam: &BeamFile,
        bytes: Option<&[u8]>,
    ) -> Result<Module, VmError> {
        let mut module = arinsal_loader::load_with_instrumentations(
            beam,
            self.coverage_mode(),
            crate::trace_bp::line_breakpoints_instrumented(),
        )
        .map_err(|e| VmError::Load(e.to_string()))?;
        if let Some(bytes) = bytes {
            funs::set_module_uniq(&mut module, bytes)?;
        }
        bind_static_nifs(&mut module, &self.code_ix);
        Ok(module)
    }

    /// Compiles `module` with BeamAsm into `meta` when `bytes` are known.
    // Like `beam_load.c:417` and `asm_load.c:1177-1198` (OTP-29.1.1), compile after the module
    // body and its exported entries are resolved.
    fn compile_native(&self, module: &Module, meta: &mut CodeMeta, module_id: usize) {
        if !meta.has_beam_bytes {
            return;
        }
        // The BEAM was parsed in prepare_loading. erts does not parse it again here.
        if let Some(native) = beamasm_integration::compile(
            &meta.beam,
            module,
            self.code_scope,
            module_id,
            crate::trace_bp::line_breakpoints_instrumented(),
        ) {
            native.publish(module);
            meta.beamasm = Some(native);
        }
    }

    /// Install the next version of a module, reclaiming a purged predecessor.
    ///
    /// Mirrors `code:load_binary` after `code:delete` and `code:purge`: the
    /// previous old version's slot is reused, so the table does not grow with
    /// every generation.
    pub fn load_next_version(&mut self, bytes: &[u8]) -> Result<(), VmError> {
        let beam = arinsal_beam::parse(bytes).map_err(|e| VmError::Load(e.to_string()))?;
        let mut module = self.prepare_module(&beam, Some(bytes))?;
        let name = module.name.clone();
        let registers = process::register_requirements(&beam);
        let mut meta = CodeMeta::from_beam(&beam, Some(bytes));
        let staging = self.code_ix.start_staging();
        let mut released = None;
        let module_id = staging.with(|tables| {
            if let Some(old_id) = tables.old.remove(&name) {
                released = tables.release(old_id);
            }
            tables.intern_fun_entries(&mut module);
            tables.next_module_id()
        });
        // The caller holds the staging permission, so this stages without waiting.
        if let Some(native) = released {
            native.unpublish();
        }
        let module = Arc::new(module);
        self.compile_native(&module, &mut meta, module_id);
        let id = staging.with(|tables| {
            let id = tables.alloc(module, registers, Some(meta));
            if let Some(previous) = tables.make_current(&name, id) {
                tables.old.insert(name.clone(), previous);
            }
            id
        });
        drop(staging);
        self.refresh_code();
        self.register_native_targets(id);
        Ok(())
    }

    fn register_native_targets(&mut self, id: usize) {
        if let Some(module) = self.code.modules.get(id) {
            self.beamasm_targets.register_module(id, module);
        }
    }

    /// Load bytes without executing module-level code.
    pub fn load_bytes(&mut self, bytes: &[u8]) -> Result<usize, VmError> {
        self.load_bytes_internal(bytes, true)
    }
    /// Load bytes for the interpreter only, without BeamAsm code (native code for its
    /// functions may be registered separately).
    pub fn load_bytes_interpreted(&mut self, bytes: &[u8]) -> Result<usize, VmError> {
        self.load_bytes_internal(bytes, false)
    }
    pub(crate) fn load_bytes_internal(
        &mut self,
        bytes: &[u8],
        compile_native: bool,
    ) -> Result<usize, VmError> {
        let beam = arinsal_beam::parse(bytes).map_err(|e| VmError::Load(e.to_string()))?;
        self.load_current(&beam, Some(bytes), compile_native, None)
    }
    /// Load a parsed module.
    pub fn load_beam(&mut self, beam: &BeamFile) -> Result<usize, VmError> {
        self.load_current(beam, None, false, None)
    }

    /// Loads `beam` as the current code of its module unless it already has current code,
    /// staging it and committing the staging code index.
    fn load_current(
        &mut self,
        beam: &BeamFile,
        bytes: Option<&[u8]>,
        compile_native: bool,
        file: Option<(&str, &Path)>,
    ) -> Result<usize, VmError> {
        self.refresh_code();
        if let Some(&id) = self.code.loaded.get(&beam.module) {
            return Ok(id);
        }
        let mut module = self.prepare_module(beam, bytes)?;
        let registers = process::register_requirements(beam);
        let mut meta = CodeMeta::from_beam(beam, bytes);
        let staging = self.code_ix.start_staging();
        // Another scheduler may have loaded the module since this one looked.
        if let Some(id) = staging.with(|tables| tables.loaded.get(&beam.module).copied()) {
            staging.abort();
            self.refresh_code();
            return Ok(id);
        }
        let module_id = staging.with(|tables| {
            tables.intern_fun_entries(&mut module);
            tables.next_module_id()
        });
        let module = Arc::new(module);
        if compile_native {
            self.compile_native(&module, &mut meta, module_id);
        }
        let name = module.name.clone();
        let id = staging.with(|tables| {
            let id = tables.alloc(module, registers, Some(meta));
            tables.make_current(&name, id);
            if let Some((requested, path)) = file {
                tables
                    .module_files
                    .insert(requested.to_owned(), path_charlist(path));
            }
            id
        });
        drop(staging);
        self.refresh_code();
        self.register_native_targets(id);
        Ok(id)
    }

    /// Stages the prepared modules of `erlang:finish_loading/1` and ends staging; the
    /// returned load commits through [`Vm::commit_staged`] once the loader's code barrier passed.
    pub(crate) fn stage_prepared(
        &mut self,
        prepared: Vec<(Module, (usize, usize), CodeMeta)>,
    ) -> Result<StagedLoad, (&'static str, Vec<String>)> {
        let names: Vec<_> = prepared
            .iter()
            .map(|(module, _, _)| module.name.clone())
            .collect();
        let mut seen = std::collections::HashSet::new();
        let duplicates: Vec<_> = names
            .iter()
            .filter(|name| !seen.insert(*name))
            .cloned()
            .collect();
        if !duplicates.is_empty() {
            return Err(("duplicated", duplicates));
        }
        if prepared.len() > 1 && prepared.iter().any(|(_, _, meta)| meta.on_load.is_some()) {
            return Err(("system_limit", names));
        }
        // Port of erts/emulator/beam/beam_bif_load.c:422 and 511-548 (finish_loading:
        // erts_start_staging_code_ix, then end and commit in staging_epilogue, or
        // erts_abort_staging_code_ix), OTP-29.1.1: the modules of this load become current
        // together.
        let staging = self.code_ix.start_staging();
        let not_purged: Vec<_> = staging.with(|tables| {
            names
                .iter()
                .filter(|name| tables.loaded.contains_key(*name) && tables.old.contains_key(*name))
                .cloned()
                .collect()
        });
        if !not_purged.is_empty() {
            staging.abort();
            return Err(("not_purged", not_purged));
        }
        let mut on_load = Vec::new();
        let mut ids = Vec::new();
        for (mut module, registers, mut meta) in prepared {
            let name = module.name.clone();
            let pending = meta.on_load.is_some();
            let module_id = staging.with(|tables| {
                tables.intern_fun_entries(&mut module);
                tables.next_module_id()
            });
            self.compile_native(&module, &mut meta, module_id);
            let module = Arc::new(module);
            ids.push(staging.with(|tables| {
                let id = tables.alloc(module, registers, Some(meta));
                tables.known_modules.insert(name.clone());
                if pending {
                    tables.pending_on_load.insert(name.clone(), id);
                } else if let Some(previous) = tables.make_current(&name, id) {
                    tables.old.insert(name.clone(), previous);
                }
                id
            }));
            if pending {
                on_load.push(name);
            }
        }
        Ok(StagedLoad {
            ended: staging.end(),
            barrier_passed: None,
            ids,
            names,
            on_load,
        })
    }

    /// Commits a load of [`Vm::stage_prepared`] and starts reading the new active code;
    /// returns the modules with `on_load`.
    // Port of erts/emulator/beam/beam_bif_load.c:301-320 (commit_code_ix), OTP-29.1.1.
    pub(crate) fn commit_staged(&mut self, staged: StagedLoad) -> Vec<String> {
        debug_assert!(
            staged
                .barrier_passed
                .as_ref()
                .is_none_or(|passed| { passed.load(std::sync::atomic::Ordering::Acquire) })
        );
        if let Some(ended) = staged.ended {
            ended.commit();
        }
        self.refresh_code();
        for id in staged.ids {
            self.register_native_targets(id);
        }
        staged.on_load
    }

    /// Whether `address` lies in the native code of module instance `id`.
    pub(crate) fn native_code_contains(&self, id: usize, address: usize) -> bool {
        self.code
            .code_meta
            .get(id)
            .and_then(|meta| meta.as_ref())
            .and_then(|meta| meta.beamasm.as_ref())
            .is_some_and(|version| {
                let (start, end) = version.code_range();
                start <= address && address < end
            })
    }

    /// Makes this VM read the tables of `erts_active_code_ix()`. A VM keeps the tables it
    /// looked at last until its next code access point, like erts' processes keep the code
    /// index they were scheduled in with.
    pub(crate) fn refresh_code(&mut self) {
        if self.code.generation != self.code_ix.active_generation() {
            self.code = self.code_ix.active_tables();
            self.native_fns = self.code_ix.native_fns();
        }
    }

    /// Generation of the tables this VM reads; interpreter caches are valid only within it.
    pub(crate) fn code_generation(&self) -> u64 {
        self.code.generation
    }

    pub(crate) fn sync_module(&mut self, id: usize) {
        if id >= self.code.modules.len() || id >= self.code.registers.len() {
            self.refresh_code();
        }
    }

    /// NIF body `index` of a `NativeBody` instruction, borrowed from this VM's cache.
    pub(crate) fn native_fn(
        &self,
        index: usize,
    ) -> Option<std::borrow::Cow<'_, crate::natives::nif::NativeFn>> {
        match self.native_fns.get(index) {
            Some(native) => native.as_ref().map(std::borrow::Cow::Borrowed),
            None => self
                .code_ix
                .native_fns()
                .get(index)
                .cloned()
                .flatten()
                .map(std::borrow::Cow::Owned),
        }
    }

    /// Patch the breakpoints of several functions of one module, publishing the module once:
    /// a per-function publication made `return_to` (which touches every loaded function) take
    /// minutes.
    pub(crate) fn patch_trace_functions(
        &mut self,
        module_id: usize,
        targets: &[(usize, String, u8)],
        process: &Process,
    ) {
        let Some(module) = self.code.modules.get(module_id).cloned() else {
            return;
        };
        let mut local_patches = Vec::new();
        let mut global_patches = Vec::new();
        let mut native_patches = Vec::new();
        for (entry, function, arity) in targets {
            let (local, global) =
                crate::trace_bp::breakpoint_kinds(process, &module.name, function, *arity);
            if self
                .beamasm_targets
                .function_for_target(
                    module_id,
                    &module,
                    native_code_range(&self.code.code_meta, module_id),
                    *entry,
                )
                .is_some()
            {
                native_patches.push((function.as_str(), *arity, local));
            }
            if module.breakpoint_originals.contains_key(entry) != local {
                local_patches.push((*entry, local));
            }
            global_patches.push((
                function.as_str(),
                *arity,
                global,
                global || crate::trace_bp::any_breakpoint(process, &module.name, function, *arity),
            ));
        }
        crate::beamasm_integration::patch_native_breakpoints(
            self.code_scope,
            &module.name,
            &native_patches,
        );
        let mut exports_retargeted = false;
        let global_patches = global_patches
            .into_iter()
            .map(|(function, arity, global, traced)| ((function, arity), (global, traced)))
            .collect::<HashMap<_, _>>();
        for (index, export) in module.exports.iter().enumerate() {
            if let Some(&(global, bif_traced)) =
                global_patches.get(&(export.function.as_str(), export.arity))
            {
                module.set_global_trace_breakpoint(index, global);
                exports_retargeted = true;
                crate::beamasm_integration::set_global_breakpoint(
                    self.code_scope,
                    &module.name,
                    &export.function,
                    export.arity,
                    export.target(),
                    global,
                    bif_traced,
                );
            }
        }
        let patched = (!local_patches.is_empty())
            .then(|| {
                let mut patched = Module::clone(&module);
                patched
                    .set_trace_breakpoints(&local_patches)
                    .then(|| Arc::new(patched))
            })
            .flatten();
        if patched.is_none() && !exports_retargeted {
            return;
        }
        // Breakpoints patch code that every code index shares; the new table generations also
        // make import caches holding the old export target resolve again.
        self.code_ix.patch_all(|tables| {
            if let Some(patched) = &patched
                && tables
                    .modules
                    .get(module_id)
                    .is_some_and(|current| Arc::ptr_eq(current, &module))
            {
                tables.modules[module_id] = Arc::clone(patched);
            }
        });
        self.refresh_code();
        self.register_native_targets(module_id);
    }

    /// Patch the code of exactly these functions after their breakpoints changed.
    pub(crate) fn refresh_trace_functions(
        &mut self,
        process: &Process,
        functions: &[crate::trace_bp::BpFunction],
    ) {
        // Port of erts/emulator/beam/beam_bp.c:183-260 (erts_bp_match_functions), OTP-29.1.1:
        // each matched breakpoint carries its function entry, so refreshing it must not rescan
        // every loaded function to recover the same MFA.
        let mut by_module: HashMap<usize, Vec<(usize, String, u8)>> = HashMap::new();
        for function in functions {
            let Some(&module_id) = self.code.loaded.get(&function.module) else {
                continue;
            };
            if self
                .code
                .modules
                .get(module_id)
                .is_some_and(|module| module.name == function.module)
            {
                by_module.entry(module_id).or_default().push((
                    function.entry,
                    function.function.clone(),
                    function.arity,
                ));
            }
        }
        for (module_id, functions) in by_module {
            self.patch_trace_functions(module_id, &functions, process);
        }
    }

    pub(crate) fn refresh_trace_pattern(
        &mut self,
        process: &Process,
        module_name: &str,
        function_name: &str,
        arity: Option<u8>,
    ) {
        let targets = self
            .code
            .modules
            .iter()
            .enumerate()
            .filter(|(_, module)| module_name == "_" || module.name == module_name)
            .map(|(module_id, module)| {
                let functions = module
                    .functions
                    .iter()
                    .filter(|(_, function, function_arity)| {
                        (function_name == "_" || function == function_name)
                            && arity.is_none_or(|arity| arity == *function_arity)
                    })
                    .map(|(start, function, arity)| (start + 1, function.clone(), *arity))
                    .collect::<Vec<_>>();
                (module_id, functions)
            })
            .collect::<Vec<_>>();
        for (module_id, functions) in targets {
            self.patch_trace_functions(module_id, &functions, process);
        }
    }

    pub(crate) fn refresh_all_trace_breakpoints(&mut self, process: &Process) {
        let targets = self
            .code
            .modules
            .iter()
            .enumerate()
            .map(|(module_id, module)| {
                let functions = module
                    .functions
                    .iter()
                    .map(|(start, function, arity)| (start + 1, function.clone(), *arity))
                    .collect::<Vec<_>>();
                (module_id, functions)
            })
            .collect::<Vec<_>>();
        for (module_id, functions) in targets {
            self.patch_trace_functions(module_id, &functions, process);
        }
    }

    /// The module is not current, `code_server` is up, and its beam has `-on_load`.
    pub(crate) fn unloaded_on_load(&self, process: &Process, name: &str) -> bool {
        if self.code.loaded.contains_key(name) || !self.should_autoload(process, name) {
            return false;
        }
        let file = format!("{name}.beam");
        for dir in &self.paths {
            let path = dir.join(&file);
            if !path.is_file() {
                continue;
            }
            let Ok(bytes) = std::fs::read(&path) else {
                continue;
            };
            let Ok(beam) = arinsal_beam::parse(&bytes) else {
                continue;
            };
            return beam
                .code
                .instructions
                .iter()
                .any(|instruction| instruction.op == arinsal_spec::Opcode::OnLoad);
        }
        false
    }
    /// `load_named` for a call that loads a missing module: the `trace_pattern(on_load, ...)`
    /// patterns of the calling process's runtime apply to a module this call loaded.
    // Port of erts/emulator/beam/beam_bif_load.c:944-975 (set_on_load_trace_pattern), OTP-29.1.1.
    pub(crate) fn load_named_traced(
        &mut self,
        process: &Process,
        name: &str,
    ) -> Result<usize, VmError> {
        self.refresh_code();
        let was_loaded = self.code.loaded.contains_key(name);
        // Port of erts/emulator/beam/beam_common.c (call_error_handler), OTP-29.1.1: once the
        // code server runs, a call into a module that is not loaded goes through
        // error_handler:undefined_function/3, and the code server loads it with the staging and
        // code barrier protocol. The scheduler thread never loads it inline.
        if !was_loaded && self.should_autoload(process, name) {
            return Err(VmError::Load(format!("module {name} not found")));
        }
        let id = self.load_named(name)?;
        if !was_loaded && crate::trace_bp::any_on_load_pattern(process) {
            crate::natives::code::apply_on_load_patterns(self, process, name);
        }
        Ok(id)
    }

    /// Instruction index of a module's `-on_load` function, exported or local.
    pub(crate) fn on_load_entry(
        module: &arinsal_loader::Module,
        function: &str,
        arity: u8,
    ) -> Option<usize> {
        module.export(function, arity).or_else(|| {
            module
                .functions
                .iter()
                .find(|(_, name, found)| name == function && *found == arity)
                .map(|(start, _, _)| start + 1)
        })
    }

    pub(crate) fn load_named(&mut self, name: &str) -> Result<usize, VmError> {
        self.refresh_code();
        if let Some(&id) = self.code.loaded.get(name) {
            return Ok(id);
        }
        if self.code.deleted.contains(name) || self.code.pending_on_load.contains_key(name) {
            return Err(VmError::Load(format!("module {name} not found")));
        }
        let file = format!("{name}.beam");
        let path = self
            .paths
            .iter()
            .map(|dir| dir.join(&file))
            .find(|path| path.is_file())
            .ok_or_else(|| VmError::Load(format!("module {name} not found")))?;
        if crate::calls::trace_boot_enabled() {
            eprintln!("arinsal boot: load {}", path.display());
        }
        let bytes = std::fs::read(&path).map_err(|e| VmError::Load(e.to_string()))?;
        let beam = arinsal_beam::parse(&bytes).map_err(|e| VmError::Load(e.to_string()))?;
        self.load_current(&beam, Some(&bytes), true, Some((name, &path)))?;
        self.code
            .loaded
            .get(name)
            .copied()
            .ok_or_else(|| VmError::Load(format!("module {name} not found")))
    }
}

#[cfg(test)]
mod purge_free_tests {
    use crate::Vm;
    use std::process::Command;

    fn beam(source: &str) -> Option<Vec<u8>> {
        let dir = std::env::temp_dir().join(format!("arinsal-purge-free-{}", std::process::id()));
        std::fs::create_dir_all(&dir).ok()?;
        std::fs::write(dir.join("purge_free_mod.erl"), source).ok()?;
        let status = Command::new("erlc")
            .arg("-o")
            .arg(&dir)
            .arg(dir.join("purge_free_mod.erl"))
            .status()
            .ok()?;
        let bytes = status
            .success()
            .then(|| std::fs::read(dir.join("purge_free_mod.beam")).ok())
            .flatten();
        let _ = std::fs::remove_dir_all(&dir);
        bytes
    }

    // Freeing old code is explicit (purge `complete`): dropping the last reference to a
    // version never stages, so it cannot wait for the permission a prepared purge holds.
    #[test]
    fn dropping_freed_native_code_does_not_wait_for_the_purge_permission() {
        let Some(beam) = beam("-module(purge_free_mod).\n-export([f/0]).\nf() -> ok.\n") else {
            eprintln!("erlc unavailable; skipping purge free test");
            return;
        };
        let mut vm = Vm::new([]);
        // A module whose load did not make it current (a failed on_load) stays published, so
        // freeing it has to unpublish its exports.
        let id = vm.load_bytes(&beam).unwrap();
        vm.purge_state.hold_stage_permission_for_test(true);
        let released = vm.code_ix.update_active(|tables| tables.release(id));
        vm.refresh_code();
        let native = released.expect("native code of the old version");
        drop(native);
        vm.purge_state.hold_stage_permission_for_test(false);
    }
}
