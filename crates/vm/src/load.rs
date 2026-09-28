//! Module loading and code index management.

use super::*;
use arinsal_term::{Atom, global_atoms};

pub(crate) struct SharedCode {
    pub(crate) coverage_mode: arinsal_loader::CoverageMode,
    pub(crate) modules: Vec<Arc<Module>>,
    pub(crate) loaded: HashMap<String, usize>,
    pub(crate) old: HashMap<String, usize>,
    pub(crate) pending_on_load: HashMap<String, usize>,
    pub(crate) purge_prepared: std::collections::HashSet<String>,
    pub(crate) deleted: std::collections::HashSet<String>,
    pub(crate) code_meta: Vec<Option<Arc<CodeMeta>>>,
    pub(crate) epoch: Arc<std::sync::atomic::AtomicU64>,
    pub(crate) registers: Vec<(usize, usize)>,
    pub(crate) native_fns: Vec<arinsal_bifs::BifFn>,
    pub(crate) loaded_nifs: std::collections::HashSet<String>,
    // g_code_fix
    pub(crate) exports: ExportIndex,
    pub(crate) free_ids: Vec<usize>,
    pub(crate) module_live: Vec<bool>,
    pub(crate) module_files: HashMap<String, arinsal_etf::OwnedTerm>,
    pub(crate) condemned: Vec<usize>,
    // g_code_fix
    pub(crate) known_modules: HashSet<String>,
}

fn bind_import_targets(module: &mut Module) {
    for import in &mut module.imports {
        if import.bif.is_none()
            && let Some(bif) =
                natives::static_nif_lookup(&import.module, &import.function, import.arity)
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
    }
}

fn bind_static_nifs(module: &mut Module, native_fns: &mut Vec<arinsal_bifs::BifFn>) {
    // Classify every import before the module is shared, including modules
    // that have no static NIF body.
    bind_import_targets(module);
    if !matches!(
        module.name.as_str(),
        "prim_file" | "prim_buffer" | "zlib" | "prim_tty" | "prim_socket" | "prim_net" | "re"
    ) {
        arinsal_loader::specialize_bif_calls(module);
        return;
    }
    for (entry, function, arity) in &module.functions {
        let Some(native) = natives::static_nif_lookup(&module.name, function, *arity) else {
            continue;
        };
        let Ok(index) = u32::try_from(native_fns.len()) else {
            continue;
        };
        native_fns.push(native);
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
    pub(crate) beam_bytes: Option<Arc<Vec<u8>>>,
    pub(crate) beamasm: Option<Arc<beamasm_integration::CompiledVersion>>,
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
            beam_bytes: bytes.map(|bytes| Arc::new(bytes.to_vec())),
            beamasm: None,
        }
    }
}

// g_code_fix: insertion-order export index. module_info(exports) walks it
// from the start and conses, so the Erlang list is reverse insertion order.
// Port of erts/emulator/beam/jit/beam_jit_main.cpp:117 (install_bifs),
// erts/emulator/beam/erl_init.c:314 (erts_init_bif_re then erts_init_unicode),
// erts/emulator/beam/jit/asm_load.c:1180 (beam_load_finalize_code exports then
// imports), and erts/emulator/beam/erl_bif_info.c:5825 (exported_from_module),
// OTP-29.1.1.
#[derive(Clone)]
pub(crate) struct ExportIndex {
    pub(crate) order: Vec<(String, String, u8)>,
    seen: HashSet<(String, String, u8)>,
    /// Atom-keyed export entries. `false` is an unresolved export stub.
    entries: HashMap<(Atom, Atom, u8), bool>,
}

impl ExportIndex {
    fn new() -> Self {
        let mut index = Self {
            order: Vec::new(),
            seen: HashSet::new(),
            entries: HashMap::new(),
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
    // An MFA already in the index keeps its original position.
    fn put(&mut self, module: &str, function: &str, arity: u8) {
        if let (Ok(module_atom), Ok(function_atom)) = (
            global_atoms().intern(module),
            global_atoms().intern(function),
        ) {
            self.entries
                .entry((module_atom, function_atom, arity))
                .or_insert(false);
        }
        let key = (module.to_owned(), function.to_owned(), arity);
        if self.seen.insert(key.clone()) {
            self.order.push(key);
        }
    }

    fn note_module(&mut self, module: &Module) {
        for export in &module.exports {
            self.put(&export.module, &export.function, export.arity);
            self.entries.insert(
                (export.module_atom, export.function_atom, export.arity),
                true,
            );
        }
        for import in &module.imports {
            self.put(&import.module, &import.function, import.arity);
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
    module: Module,
    regs: (usize, usize),
    meta: Option<CodeMeta>,
) -> usize {
    let stored = Arc::new(module);
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

impl SharedCode {
    #[cfg(test)]
    pub(crate) fn blank() -> Self {
        Self {
            coverage_mode: arinsal_loader::CoverageMode::None,
            modules: Vec::new(),
            loaded: HashMap::new(),
            old: HashMap::new(),
            pending_on_load: HashMap::new(),
            purge_prepared: std::collections::HashSet::new(),
            deleted: std::collections::HashSet::new(),
            code_meta: Vec::new(),
            epoch: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            registers: Vec::new(),
            native_fns: Vec::new(),
            loaded_nifs: std::collections::HashSet::new(),
            exports: ExportIndex::new(),
            free_ids: Vec::new(),
            module_live: Vec::new(),
            module_files: HashMap::new(),
            condemned: Vec::new(),
            known_modules: HashSet::new(),
        }
    }

    fn alloc(
        &mut self,
        module: Module,
        registers: (usize, usize),
        meta: Option<CodeMeta>,
    ) -> usize {
        self.exports.note_module(&module);
        alloc_slot(
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
        )
    }

    pub(crate) fn release(&mut self, id: usize) {
        release_slot(
            &mut self.module_live,
            &mut self.code_meta,
            &mut self.free_ids,
            id,
        );
    }
}

// VM load implementation.

impl Vm {
    /// Resolve a native record definition from the active module version.
    pub(crate) fn native_record_definition(
        &self,
        module: &str,
        name: &str,
    ) -> Option<&arinsal_beam::NativeRecord> {
        let id = *self.loaded.get(module)?;
        self.modules
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
        self.exports
            .entries
            .entry((module_atom, function_atom, arity))
            .or_insert(false);
        let module_name = global_atoms()
            .text(module_atom)
            .ok_or_else(|| VmError::Load("invalid module atom".into()))?;
        let module_id = self.load_named(&module_name)?;
        let module = &self.modules[module_id];
        let Some(export) = module.export_slot_atom(function_atom, arity) else {
            return Err(VmError::Trap(crate::exceptions::Trap::error(
                crate::signals::atom("undef"),
            )));
        };
        let target = export.target();
        self.exports
            .entries
            .insert((module_atom, function_atom, arity), true);
        Ok((module_id, target))
    }

    /// Construct a VM. Explicit paths precede the current directory and OTP libraries.
    pub fn new(paths: impl IntoIterator<Item = PathBuf>) -> Self {
        let mut paths: Vec<PathBuf> = paths.into_iter().collect();
        paths.push(PathBuf::from("."));
        paths.push(PathBuf::from("bench/out/ebin"));
        let otp = std::env::var_os("ARINSAL_OTP_ROOT")
            .map(PathBuf::from)
            .or_else(|| {
                std::process::Command::new("erl")
                    .args([
                        "-noshell",
                        "-eval",
                        "io:format(\"~s\",[code:root_dir()]),halt().",
                    ])
                    .output()
                    .ok()
                    .filter(|output| output.status.success())
                    .and_then(|output| String::from_utf8(output.stdout).ok())
                    .map(PathBuf::from)
            })
            .unwrap_or_default();
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
        Self {
            paths,
            modules: Vec::new(),
            loaded: HashMap::new(),
            old: HashMap::new(),
            pending_on_load: HashMap::new(),
            purge_prepared: std::collections::HashSet::new(),
            deleted: std::collections::HashSet::new(),
            code_meta: Vec::new(),
            code_epoch: None,
            seen_epoch: 0,
            beamasm_targets: beamasm_integration::NativeTargetCache::default(),
            registers: Vec::new(),
            native_fns: Vec::new(),
            loaded_nifs: std::collections::HashSet::new(),
            shared: None,
            // ---- vm_exc ----
            backtrace_depth: 8,
            // g_code_fix
            exports: ExportIndex::new(),
            free_ids: Vec::new(),
            module_live: Vec::new(),
            module_files: HashMap::new(),
            condemned: Vec::new(),
            known_modules: HashSet::new(),
            coverage_mode: arinsal_loader::CoverageMode::None,
        }
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
        if let Some(shared) = self.shared.clone() {
            let mut code = shared.lock().unwrap();
            code.exports.note_beam(&beam);
            self.sync_shared(&code);
        } else {
            self.exports.note_beam(&beam);
        }
        Ok(())
    }

    /// Live module versions. A purged version is omitted once its slot can be reused.
    pub fn module_storage_count(&self) -> usize {
        self.module_live.iter().filter(|live| **live).count()
    }

    /// Module-table length, including slots retained for reuse after a purge.
    pub fn module_table_len(&self) -> usize {
        self.modules.len()
    }

    /// Install the next version of a module, reclaiming a purged predecessor.
    ///
    /// Mirrors `code:load_binary` after `code:delete` and `code:purge`: the
    /// previous old version's slot is reused, so the table does not grow with
    /// every generation.
    pub fn load_next_version(&mut self, bytes: &[u8]) -> Result<(), VmError> {
        let beam = arinsal_beam::parse(bytes).map_err(|e| VmError::Load(e.to_string()))?;
        let mut module = arinsal_loader::load_with_instrumentations(
            &beam,
            self.coverage_mode,
            crate::trace_bp::line_breakpoints_instrumented(),
        )
        .map_err(|e| VmError::Load(e.to_string()))?;
        funs::set_module_uniq(&mut module, bytes)?;
        bind_static_nifs(&mut module, &mut self.native_fns);
        let name = module.name.clone();
        if let Some(old_id) = self.old.remove(&name) {
            self.release_module_slot(old_id);
        }
        let registers = process::register_requirements(&beam);
        let meta = CodeMeta::from_beam(&beam, Some(bytes));
        let previous = self.loaded.get(&name).copied();
        let id = self.alloc_local(module, registers, Some(meta));
        self.loaded.insert(name.clone(), id);
        if let Some(native) = beamasm_integration::compile(bytes, &self.modules[id]) {
            native.publish(&self.modules[id]);
            if let Some(meta) = self.code_meta[id].as_mut() {
                Arc::make_mut(meta).beamasm = Some(native);
            }
        }
        if let Some(previous) = previous {
            self.old.insert(name.clone(), previous);
        }
        self.deleted.remove(&name);
        self.known_modules.insert(name);
        Ok(())
    }

    pub(crate) fn release_module_slot(&mut self, id: usize) {
        release_slot(
            &mut self.module_live,
            &mut self.code_meta,
            &mut self.free_ids,
            id,
        );
    }

    pub(crate) fn alloc_local(
        &mut self,
        module: Module,
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
        self.beamasm_targets.register_module(id, &self.modules[id]);
        id
    }

    pub(crate) fn snapshot_shared(&self) -> SharedCode {
        SharedCode {
            coverage_mode: self.coverage_mode,
            modules: self.modules.clone(),
            loaded: self.loaded.clone(),
            old: self.old.clone(),
            pending_on_load: self.pending_on_load.clone(),
            purge_prepared: self.purge_prepared.clone(),
            deleted: self.deleted.clone(),
            code_meta: self.code_meta.clone(),
            epoch: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            registers: self.registers.clone(),
            native_fns: self.native_fns.clone(),
            loaded_nifs: self.loaded_nifs.clone(),
            exports: self.exports.clone(),
            free_ids: self.free_ids.clone(),
            module_live: self.module_live.clone(),
            module_files: self.module_files.clone(),
            condemned: self.condemned.clone(),
            known_modules: self.known_modules.clone(),
        }
    }
    /// Load bytes without executing module-level code.
    pub fn load_bytes(&mut self, bytes: &[u8]) -> Result<usize, VmError> {
        self.load_bytes_internal(bytes, true)
    }
    pub(crate) fn load_bytes_internal(
        &mut self,
        bytes: &[u8],
        compile_native: bool,
    ) -> Result<usize, VmError> {
        let beam = arinsal_beam::parse(bytes).map_err(|e| VmError::Load(e.to_string()))?;
        if let Some(&id) = self.loaded.get(&beam.module) {
            return Ok(id);
        }
        let mut module = arinsal_loader::load_with_instrumentations(
            &beam,
            self.coverage_mode,
            crate::trace_bp::line_breakpoints_instrumented(),
        )
        .map_err(|e| VmError::Load(e.to_string()))?;
        funs::set_module_uniq(&mut module, bytes)?;
        bind_static_nifs(&mut module, &mut self.native_fns);
        let registers = process::register_requirements(&beam);
        let id = self.insert_module(module, registers);
        self.code_meta[id] = Some(Arc::new(CodeMeta::from_beam(&beam, Some(bytes))));
        if compile_native {
            // Like `beam_load.c:417` and `asm_load.c:1177-1198` (OTP-29.1.1),
            // compile after the module body and its exported entries are resolved.
            if let Some(native) = beamasm_integration::compile(bytes, &self.modules[id]) {
                native.publish(&self.modules[id]);
                if let Some(meta) = self.code_meta[id].as_mut() {
                    Arc::make_mut(meta).beamasm = Some(native);
                }
            }
        }
        Ok(id)
    }
    /// Load a parsed module.
    pub fn load_beam(&mut self, beam: &BeamFile) -> Result<usize, VmError> {
        if let Some(shared) = self.shared.clone() {
            let mut code = shared.lock().unwrap();
            if !code.loaded.contains_key(&beam.module) {
                // boot_loop1: prepared code must be published before another
                // scheduler replica can use the module index.
                let mut module = arinsal_loader::load_with_instrumentations(
                    beam,
                    self.coverage_mode,
                    crate::trace_bp::line_breakpoints_instrumented(),
                )
                .map_err(|e| VmError::Load(e.to_string()))?;
                bind_static_nifs(&mut module, &mut code.native_fns);
                let name = module.name.clone();
                let id = code.alloc(
                    module,
                    process::register_requirements(beam),
                    Some(CodeMeta::from_beam(beam, None)),
                );
                code.loaded.insert(name.clone(), id);
                code.known_modules.insert(name);
                code.epoch
                    .fetch_add(1, std::sync::atomic::Ordering::Release);
            }
            self.sync_shared(&code);
            return self
                .loaded
                .get(&beam.module)
                .copied()
                .ok_or_else(|| VmError::Load(format!("module {} not found", beam.module)));
        }
        if let Some(&id) = self.loaded.get(&beam.module) {
            return Ok(id);
        }
        let mut module = arinsal_loader::load_with_instrumentations(
            beam,
            self.coverage_mode,
            crate::trace_bp::line_breakpoints_instrumented(),
        )
        .map_err(|e| VmError::Load(e.to_string()))?;
        bind_static_nifs(&mut module, &mut self.native_fns);
        let registers = process::register_requirements(beam);
        let id = self.insert_module(module, registers);
        self.code_meta[id] = Some(Arc::new(CodeMeta::from_beam(beam, None)));
        Ok(id)
    }
    pub(crate) fn insert_module(&mut self, module: Module, registers: (usize, usize)) -> usize {
        // g_code_fix: reuse a purged slot instead of appending forever.
        let name = module.name.clone();
        let id = self.alloc_local(module, registers, None);
        self.loaded.insert(name.clone(), id);
        self.known_modules.insert(name);
        id
    }
    pub(crate) fn publish_prepared(
        &mut self,
        prepared: Vec<(Module, (usize, usize), CodeMeta)>,
    ) -> Result<Vec<String>, (&'static str, Vec<String>)> {
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
        self.sync_code_epoch();
        let shared_arc = self.shared.clone();
        let mut shared = shared_arc.as_ref().map(|code| code.lock().unwrap());
        let (loaded, old) = if let Some(code) = shared.as_deref() {
            (&code.loaded, &code.old)
        } else {
            (&self.loaded, &self.old)
        };
        let not_purged: Vec<_> = names
            .iter()
            .filter(|name| loaded.contains_key(*name) && old.contains_key(*name))
            .cloned()
            .collect();
        if !not_purged.is_empty() {
            return Err(("not_purged", not_purged));
        }
        let previous: HashMap<_, _> = names
            .iter()
            .filter_map(|name| loaded.get(name).map(|id| (name.clone(), *id)))
            .collect();
        let mut on_load = Vec::new();
        if let Some(code) = shared.as_deref_mut() {
            for (module, registers, mut meta) in prepared {
                let name = module.name.clone();
                let pending = meta.on_load.is_some();
                if let Some(bytes) = meta.beam_bytes.as_deref()
                    && let Some(native) = beamasm_integration::compile(bytes, &module)
                {
                    native.publish(&module);
                    meta.beamasm = Some(native);
                }
                let id = code.alloc(module, registers, Some(meta));
                code.known_modules.insert(name.clone());
                if pending {
                    code.pending_on_load.insert(name.clone(), id);
                    on_load.push(name);
                } else {
                    if let Some(previous) = code.loaded.insert(name.clone(), id) {
                        code.old.insert(name.clone(), previous);
                    }
                    code.deleted.remove(&name);
                }
            }
            code.epoch
                .fetch_add(1, std::sync::atomic::Ordering::Release);
            self.sync_shared(code);
        } else {
            for (module, registers, mut meta) in prepared {
                let name = module.name.clone();
                let pending = meta.on_load.is_some();
                if let Some(bytes) = meta.beam_bytes.as_deref()
                    && let Some(native) = beamasm_integration::compile(bytes, &module)
                {
                    native.publish(&module);
                    meta.beamasm = Some(native);
                }
                let id = self.insert_module(module, registers);
                self.code_meta[id] = Some(Arc::new(meta));
                if pending {
                    if let Some(previous) = previous.get(&name) {
                        self.loaded.insert(name.clone(), *previous);
                    } else {
                        self.loaded.remove(&name);
                    }
                    self.pending_on_load.insert(name.clone(), id);
                    on_load.push(name.clone());
                } else if let Some(previous) = previous.get(&name) {
                    self.old.insert(name.clone(), *previous);
                }
                self.deleted.remove(&name);
            }
        }
        Ok(on_load)
    }
    pub(crate) fn sync_shared(&mut self, shared: &SharedCode) {
        self.coverage_mode = shared.coverage_mode;
        // g_code_fix: a reused module id replaces its slot; only a new id appends.
        for (id, module) in shared.modules.iter().enumerate() {
            if id == self.modules.len() {
                self.modules.push(Arc::clone(module));
                self.beamasm_targets.register_module(id, module);
            } else if !Arc::ptr_eq(&self.modules[id], module) {
                self.modules[id] = Arc::clone(module);
                self.beamasm_targets.register_module(id, module);
            }
        }
        self.registers = shared.registers.clone();
        self.native_fns = shared.native_fns.clone();
        self.loaded_nifs = shared.loaded_nifs.clone();
        self.loaded = shared.loaded.clone();
        self.old = shared.old.clone();
        self.pending_on_load = shared.pending_on_load.clone();
        self.purge_prepared = shared.purge_prepared.clone();
        self.deleted = shared.deleted.clone();
        self.code_meta = shared.code_meta.clone();
        self.exports = shared.exports.clone();
        self.free_ids = shared.free_ids.clone();
        self.module_live = shared.module_live.clone();
        self.module_files = shared.module_files.clone();
        self.condemned = shared.condemned.clone();
        self.known_modules = shared.known_modules.clone();
        self.seen_epoch = shared.epoch.load(std::sync::atomic::Ordering::Acquire);
    }

    pub(crate) fn set_coverage_mode(&mut self, mode: arinsal_loader::CoverageMode) {
        self.coverage_mode = mode;
        if let Some(shared) = self.shared.clone() {
            let mut code = shared.lock().unwrap();
            code.coverage_mode = mode;
            code.epoch
                .fetch_add(1, std::sync::atomic::Ordering::Release);
            self.sync_shared(&code);
        }
    }
    pub(crate) fn sync_code_epoch(&mut self) {
        if let Some(epoch) = &self.code_epoch
            && epoch.load(std::sync::atomic::Ordering::Acquire) != self.seen_epoch
        {
            let shared = self.shared.as_ref().unwrap().clone();
            self.sync_shared(&shared.lock().unwrap());
        }
    }
    pub(crate) fn sync_module(&mut self, id: usize) {
        if (id >= self.modules.len() || id >= self.registers.len())
            && let Some(shared) = self.shared.clone()
        {
            self.sync_shared(&shared.lock().unwrap());
        }
    }

    pub(crate) fn patch_trace_function(
        &mut self,
        module_id: usize,
        entry: usize,
        function: &str,
        arity: u8,
        process: &Process,
    ) {
        let Some(module) = self.modules.get_mut(module_id) else {
            return;
        };
        let (local, global) =
            crate::trace_bp::breakpoint_kinds(process, &module.name, function, arity);
        let needs_local_patch = module.breakpoint_originals.contains_key(&entry) != local;
        let changed = if needs_local_patch {
            Arc::make_mut(module).set_trace_breakpoint(entry, local)
        } else {
            false
        };
        if let Some(module) = self.modules.get(module_id) {
            for (index, export) in module.exports.iter().enumerate() {
                if export.function == function && export.arity == arity {
                    module.set_global_trace_breakpoint(index, global);
                }
            }
        }
        if !changed {
            return;
        }
        let Some(module) = self.modules.get(module_id) else {
            return;
        };
        self.beamasm_targets.register_module(module_id, module);
        if let Some(shared) = self.shared.clone() {
            let mut shared = shared.lock().unwrap();
            shared.modules[module_id] = Arc::clone(module);
            self.seen_epoch = shared
                .epoch
                .fetch_add(1, std::sync::atomic::Ordering::AcqRel)
                + 1;
        } else {
            self.seen_epoch = self.seen_epoch.wrapping_add(1);
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
            .modules
            .iter()
            .enumerate()
            .filter(|(_, module)| module.name == module_name)
            .flat_map(|(module_id, module)| {
                module
                    .functions
                    .iter()
                    .filter_map(move |(start, function, function_arity)| {
                        ((function_name == "_" || function == function_name)
                            && arity.is_none_or(|arity| arity == *function_arity))
                        .then_some((module_id, start + 1, function.clone(), *function_arity))
                    })
            })
            .collect::<Vec<_>>();
        for (module_id, entry, function, arity) in targets {
            self.patch_trace_function(module_id, entry, &function, arity, process);
        }
    }

    pub(crate) fn refresh_all_trace_breakpoints(&mut self, process: &Process) {
        let targets = self
            .modules
            .iter()
            .enumerate()
            .flat_map(|(module_id, module)| {
                module
                    .functions
                    .iter()
                    .map(move |(start, function, arity)| {
                        (module_id, start + 1, function.clone(), *arity)
                    })
            })
            .collect::<Vec<_>>();
        for (module_id, entry, function, arity) in targets {
            self.patch_trace_function(module_id, entry, &function, arity, process);
        }
    }

    /// The module is not current, `code_server` is up, and its beam has `-on_load`.
    pub(crate) fn unloaded_on_load(&self, process: &Process, name: &str) -> bool {
        if self.loaded.contains_key(name) || !self.should_autoload(process, name) {
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
    pub(crate) fn shared_replica(code: Arc<Mutex<SharedCode>>, paths: &[PathBuf]) -> Self {
        let mut vm = Self {
            paths: paths.to_vec(),
            modules: Vec::new(),
            loaded: HashMap::new(),
            old: HashMap::new(),
            pending_on_load: HashMap::new(),
            purge_prepared: std::collections::HashSet::new(),
            deleted: std::collections::HashSet::new(),
            code_meta: Vec::new(),
            code_epoch: Some(Arc::clone(&code.lock().unwrap().epoch)),
            seen_epoch: 0,
            beamasm_targets: beamasm_integration::NativeTargetCache::default(),
            registers: Vec::new(),
            native_fns: Vec::new(),
            loaded_nifs: std::collections::HashSet::new(),
            shared: Some(Arc::clone(&code)),
            backtrace_depth: 8,
            exports: ExportIndex::new(),
            free_ids: Vec::new(),
            module_live: Vec::new(),
            module_files: HashMap::new(),
            condemned: Vec::new(),
            known_modules: HashSet::new(),
            coverage_mode: arinsal_loader::CoverageMode::None,
        };
        vm.sync_shared(&code.lock().unwrap());
        vm
    }
    pub(crate) fn load_named(&mut self, name: &str) -> Result<usize, VmError> {
        self.sync_code_epoch();
        if let Some(&id) = self.loaded.get(name) {
            return Ok(id);
        }
        if self.deleted.contains(name) || self.pending_on_load.contains_key(name) {
            return Err(VmError::Load(format!("module {name} not found")));
        }
        if let Some(shared) = self.shared.clone() {
            let mut code = shared.lock().unwrap();
            if !code.loaded.contains_key(name) {
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
                let mut module = arinsal_loader::load_with_instrumentations(
                    &beam,
                    self.coverage_mode,
                    crate::trace_bp::line_breakpoints_instrumented(),
                )
                .map_err(|e| VmError::Load(e.to_string()))?;
                funs::set_module_uniq(&mut module, &bytes)?;
                bind_static_nifs(&mut module, &mut code.native_fns);
                let module_name = module.name.clone();
                let id = code.alloc(
                    module,
                    process::register_requirements(&beam),
                    Some(CodeMeta::from_beam(&beam, Some(&bytes))),
                );
                code.loaded.insert(module_name.clone(), id);
                if let Some(native) = beamasm_integration::compile(&bytes, &code.modules[id]) {
                    native.publish(&code.modules[id]);
                    if let Some(meta) = code.code_meta[id].as_mut() {
                        Arc::make_mut(meta).beamasm = Some(native);
                    }
                }
                code.known_modules.insert(module_name);
                code.module_files
                    .insert(name.to_owned(), path_charlist(&path));
                code.epoch
                    .fetch_add(1, std::sync::atomic::Ordering::Release);
            }
            self.sync_shared(&code);
            return self
                .loaded
                .get(name)
                .copied()
                .ok_or_else(|| VmError::Load(format!("module {name} not found")));
        }
        let file = format!("{name}.beam");
        for dir in &self.paths {
            let path = dir.join(&file);
            if path.is_file() {
                if crate::calls::trace_boot_enabled() {
                    eprintln!("arinsal boot: load {}", path.display());
                }
                let bytes = std::fs::read(&path).map_err(|e| VmError::Load(e.to_string()))?;
                let id = self.load_bytes_internal(&bytes, true)?;
                self.module_files
                    .insert(name.to_owned(), path_charlist(&path));
                return Ok(id);
            }
        }
        Err(VmError::Load(format!("module {name} not found")))
    }
}
