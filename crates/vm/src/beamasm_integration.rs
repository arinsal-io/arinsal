//! Loading and registration for the incremental BeamAsm compiler: the export entries and
//! dispatch targets every backend shares. The backend's own module environment lives in
//! `arm` (jit/arm); the code pointers of the global code in [`crate::beam_jit_main`].
use arinsal_term::global_atoms;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::{OnceLock, RwLock};

// Port of erts/emulator/beam/export.c:59-72 (export_hash, export_cmp), OTP-29.1.1: exports
// are keyed by their module and function atoms.
type Mfa = (arinsal_term::Atom, arinsal_term::Atom, u8);

/// The export key of `module:function/arity`; `None` when either name is not an atom yet,
/// so no export can have it.
fn existing_mfa(module: &str, function: &str, arity: u8) -> Option<Mfa> {
    let atoms = global_atoms();
    Some((atoms.get(module)?, atoms.get(function)?, arity))
}

/// Function-indexed BeamAsm target cache, invalidated when native code is published.
pub(crate) struct NativeTargetCache {
    /// The start address of the native code of each function, or 0.
    targets: Vec<Vec<usize>>,
    generations: Vec<u64>,
    module_identities: Vec<usize>,
    /// Native code range each cached module instance was resolved against.
    ranges: Vec<Option<(usize, usize)>>,
}

impl NativeTargetCache {
    pub(crate) fn new() -> Self {
        Self {
            targets: Vec::new(),
            generations: Vec::new(),
            module_identities: Vec::new(),
            ranges: Vec::new(),
        }
    }

    pub(crate) fn register_module(&mut self, module_id: usize, module: &arinsal_loader::Module) {
        let targets = vec![0; module.functions.len()];
        if module_id == self.targets.len() {
            self.targets.push(targets);
            self.generations.push(u64::MAX);
            self.module_identities
                .push(std::ptr::from_ref(module) as usize);
        } else if module_id < self.targets.len() {
            self.targets[module_id] = targets;
            self.generations[module_id] = u64::MAX;
            self.module_identities[module_id] = std::ptr::from_ref(module) as usize;
        } else {
            self.targets.resize_with(module_id, Vec::new);
            self.targets.push(targets);
            self.generations.resize(module_id, u64::MAX);
            self.generations.push(u64::MAX);
            self.module_identities.resize(module_id, 0);
            self.module_identities
                .push(std::ptr::from_ref(module) as usize);
        }
    }

    /// The native function entered at interpreted `target` of module instance `module_id`,
    /// whose native code (when it has a version of its own) spans `range`.
    pub(crate) fn function_for_target(
        &mut self,
        module_id: usize,
        module: &arinsal_loader::Module,
        range: Option<(usize, usize)>,
        target: usize,
    ) -> Option<crate::NativeFunction> {
        // Only a function entry enters native code at the function's start; any other
        // target (an export breakpoint stub, a label inside a function) stays interpreted.
        let index = module.function_by_entry(target)?;
        let identity = std::ptr::from_ref(module) as usize;
        if self.module_identities.get(module_id).copied() != Some(identity) {
            self.register_module(module_id, module);
        }
        let generation = crate::native_bridge::native_registry_generation();
        if self.generations.get(module_id).copied()? != generation
            || self.ranges.get(module_id).copied().flatten() != range
        {
            // One registry pass per module: a lookup per function would be quadratic. An old
            // instance of the module may still be registered (a reused module id can even
            // reuse the `Module` address), so only this instance's own code counts.
            let mut natives = crate::native_bridge::native_functions_of(&module.name, range);
            let cache = self.targets.get_mut(module_id)?;
            cache.clear();
            cache.extend(module.functions.iter().map(|(_, function, arity)| {
                natives
                    .remove(&((*function).to_owned(), *arity))
                    .map_or(0, |native| native.start)
            }));
            self.generations[module_id] = generation;
            if self.ranges.len() <= module_id {
                self.ranges.resize(module_id + 1, None);
            }
            self.ranges[module_id] = range;
        }
        let start = *self.targets.get(module_id)?.get(index)?;
        crate::native_function_at(start)
    }
}

#[derive(Clone)]
#[repr(C)]
pub(crate) struct DispatchTarget {
    /// The node's export entry; export funs of this MFA hold it too (`Export.lambda`).
    slot: &'static Arc<arinsal_term::ExportEntry>,
    pub module: String,
    pub function: String,
    pub module_atom: arinsal_term::Atom,
    pub function_atom: arinsal_term::Atom,
    pub arity: u8,
    pub class: arinsal_loader::ImportClass,
    pub native_bits: usize,
    /// The MFA is a light (not heap) BIF in the BIF table (erts `Export.bif_number` with the
    /// light-BIF kind), looked up once at intern.
    pub light_kind: bool,
    /// The process BIF a light BIF call runs straight away, for a native that needs only its
    /// process (see `natives::ProcessBif`); the executor still runs it for interpreted code.
    pub light_process_bif: Option<crate::natives::ProcessBif>,
}

/// Whether `module:function/arity` is a light BIF of the BIF table.
fn light_kind(module: &str, function: &str, arity: u8) -> bool {
    arinsal_spec::bif_lookup(module, function, arity)
        .is_some_and(|bif| bif.kind != arinsal_spec::BifKind::Hbif)
}

impl DispatchTarget {
    /// The stable `Export *` passed to erts' `save_calls`.
    // Port of erts/emulator/beam/export.h (`Export` allocation), OTP-29.1.1.
    pub(crate) fn export_entry_address(&self) -> usize {
        Arc::as_ptr(self.slot) as usize
    }

    /// `Export.is_bif_traced`: the one decision whether a BIF call enters the export's
    /// breakpoint.
    // Port of erts/emulator/beam/jit/arm/instr_bif.cpp:391 (call_light_bif_shared), OTP-29.1.1.
    pub(crate) fn is_bif_traced(&self) -> bool {
        self.slot
            .is_bif_traced
            .load(std::sync::atomic::Ordering::Acquire)
            != 0
    }

    /// `Export.info.mfa` of this export.
    pub(crate) fn mfa(&self) -> &'static arinsal_term::ErtsCodeMfa {
        self.slot.mfa()
    }

    /// The shared owner of this MFA's `Export`, which the code indexes' export tables hold.
    pub(crate) fn export_object(&self) -> &'static Arc<arinsal_term::ExportEntry> {
        self.slot
    }

    /// Whether `bif_table[].f` of this export runs the BIF itself, as `i_bif*` calls it: a body
    /// of its own, or the plain adapter of its `arinsal_bifs` body. Not an entry that parks the
    /// call in the executor.
    // Port of erts/emulator/beam/jit/arm/instr_bif.cpp:110-151 (`bif->f`), OTP-29.1.1.
    pub(crate) fn bif_table_runs_bif(&self) -> bool {
        crate::bif_table::is_body(self.bif_table_function())
    }

    /// Whether this export has the `bif.tab` index that call fragments pass to `bif_table`.
    // Port of erts/emulator/beam/jit/beam_jit_main.cpp (`install_bifs`), OTP-29.1.1.
    pub(crate) fn is_bif_export(&self) -> bool {
        self.slot.bif_number() >= 0
    }

    /// `bif_table[ep->bif_number].f` of this export, or 0.
    pub(crate) fn bif_table_function(&self) -> usize {
        crate::bif_table::function(self.slot.bif_number())
    }

    /// Trapping BIFs keep continuation state that only the executor's call site handles.
    pub(crate) fn runs_in_executor(&self) -> bool {
        matches!(
            self.class,
            arinsal_loader::ImportClass::Native
                | arinsal_loader::ImportClass::Dynamic
                | arinsal_loader::ImportClass::Fun
        )
    }
}

// Port of erts/emulator/beam/export.c:73-98 (export_init), OTP-29.1.1.
// The entry is never freed: it lives as long as the export table, like erts' export entries.
fn new_export_slot(
    mfa: Mfa,
    address: usize,
    save_calls: usize,
) -> &'static Arc<arinsal_term::ExportEntry> {
    let export = Box::leak(Box::new(Arc::new(
        arinsal_term::ExportEntry::with_addresses(mfa.0, mfa.1, mfa.2, address, save_calls),
    )));
    // Port of erts/emulator/beam/jit/beam_jit_main.cpp (install_bifs: `ep->bif_number = i`
    // for every BIF table entry), OTP-29.1.1.
    if let (Some(module), Some(function)) = (global_atoms().text(mfa.0), global_atoms().text(mfa.1))
        && let Some(bif) = arinsal_spec::bif_lookup(module, function, mfa.2)
    {
        export.set_bif_number(i32::from(bif.index));
    }
    // Port of erts/emulator/beam/bif.c (erts_init_trap_export: `bif_number = -1`,
    // `trampoline.bif.address = bif`), OTP-29.1.1.
    if let (Some(module), Some(function)) = (global_atoms().text(mfa.0), global_atoms().text(mfa.1))
        && let Some(function) = crate::bif_table::trap_function(module, function, mfa.2)
    {
        export.set_trampoline_address(function);
    }
    export
}

/// One node's export state, like an erts code index: import slots, interpreted and native
/// export targets and global call breakpoints.
#[derive(Default)]
struct ExportTable {
    // One slot per MFA, shared by every import and export.
    dispatch: HashMap<Mfa, Arc<DispatchTarget>, ExportHasher>,
}

/// Hashes an export key like erts' export table.
#[derive(Default, Clone, Copy)]
pub(crate) struct ExportHasher;

impl std::hash::BuildHasher for ExportHasher {
    type Hasher = ExportHashState;
    fn build_hasher(&self) -> ExportHashState {
        ExportHashState::default()
    }
}

/// Folds the module atom, function atom and arity of an [`Mfa`] in the order it hashes them.
#[derive(Default)]
pub(crate) struct ExportHashState {
    words: [u64; 3],
    count: usize,
}

impl ExportHashState {
    fn push(&mut self, value: u64) {
        if let Some(word) = self.words.get_mut(self.count) {
            *word = value;
        } else {
            self.words[2] = self.words[2].rotate_left(8) ^ value;
        }
        self.count += 1;
    }
}

impl std::hash::Hasher for ExportHashState {
    // Port of erts/emulator/beam/export.c:59-64 (export_hash), OTP-29.1.1:
    // atom_val(module) * atom_val(function) ^ arity. The product is small, so it is spread
    // over the high bits the hash table's control bytes are taken from.
    fn finish(&self) -> u64 {
        (self.words[0].wrapping_mul(self.words[1]) ^ self.words[2])
            .wrapping_mul(0x9e37_79b9_7f4a_7c15)
    }
    fn write(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            self.push(u64::from(byte));
        }
    }
    fn write_u8(&mut self, value: u8) {
        self.push(u64::from(value));
    }
    fn write_u32(&mut self, value: u32) {
        self.push(u64::from(value));
    }
}

#[derive(Default)]
struct DispatchRegistry {
    exports: ExportTable,
    // Leaked on first registration: native BIF calls read these on every call, and a shared
    // reference count would bounce between schedulers. Each is a few hundred bytes per import.
    by_identity: HashMap<usize, &'static DispatchTarget>,
    // Slots for `call_bif_mfa`; unlike imports they always enter the BIF itself.
    bif_mfas: HashMap<Mfa, Arc<DispatchTarget>>,
}

impl DispatchRegistry {
    fn intern_identity(
        &mut self,
        identity: usize,
        entry: &Arc<DispatchTarget>,
    ) -> &'static DispatchTarget {
        self.by_identity.entry(identity).or_insert_with(|| {
            let mut leaked = DispatchTarget::clone(entry);
            // Port of erts/emulator/beam/jit/arm/instr_bif.cpp:378-471 (call_light_bif_shared),
            // OTP-29.1.1: erts calls every BIF from the generated code with `c_p`, so a native
            // that needs only its process is called the same way.
            leaked.light_process_bif = if leaked.class == arinsal_loader::ImportClass::Native
                || (leaked.class == arinsal_loader::ImportClass::Fun
                    && leaked.module == "erlang"
                    && ((leaked.function == "fun_info" && leaked.arity == 2)
                        || (leaked.function == "make_fun" && leaked.arity == 3)))
            {
                crate::natives::process_bif(&leaked.module, &leaked.function, leaked.arity)
            } else {
                None
            };
            let target: &'static DispatchTarget = Box::leak(Box::new(leaked));
            // Port of erts/emulator/beam/jit/beam_jit_main.cpp (install_bifs:
            // `trampoline.bif.op = op_call_bif_W`), OTP-29.1.1: a BIF, or a native the runtime
            // implements in place of Erlang code, is called by the trampoline; any other
            // export's trampoline calls the error handler (export_init).
            if target.slot.bif_number() != -1 || target.class != arinsal_loader::ImportClass::Remote
            {
                target.slot.set_trampoline_op(arinsal_term::OP_CALL_BIF_W);
            }
            // Port of erts/emulator/beam/jit/beam_jit_main.cpp (install_bifs: `bif_table[i].f`
            // reached through `ep->bif_number = i`), OTP-29.1.1: the call fragments index the
            // table by the export's bif_number. An export outside bif.tab has no entry.
            if let Some(func) = crate::native_helpers::light_entry(target) {
                crate::bif_table::install(target.slot.bif_number(), func);
            }
            target
        })
    }
}

fn dispatch_registry() -> &'static RwLock<DispatchRegistry> {
    static REGISTRY: OnceLock<RwLock<DispatchRegistry>> = OnceLock::new();
    REGISTRY.get_or_init(|| RwLock::new(DispatchRegistry::default()))
}

/// What the export table already holds for each import of `imports`: its class,
/// native entry bits and whether its BIF traps. An import to an MFA that some module of the
/// node imported or defined needs no classification again.
// Port of erts/emulator/beam/export.c:154-180 (the export entry of an MFA carries its BIF
// number and trap information), OTP-29.1.1.
pub(crate) fn known_imports(
    imports: &[arinsal_loader::Import],
) -> Vec<Option<(arinsal_loader::ImportClass, usize)>> {
    let Ok(registry) = dispatch_registry().read() else {
        return vec![None; imports.len()];
    };
    let exports = &registry.exports;
    imports
        .iter()
        .map(|import| {
            let mfa = (import.module_atom, import.function_atom, import.arity);
            exports
                .dispatch
                .get(&mfa)
                .map(|target| (target.class, target.native_bits))
        })
        .collect()
}

// Port of erts/emulator/beam/export.c:59-98 (MFA-keyed export lookup and initialization), OTP-29.1.1.
fn dispatch_entry(
    key: Mfa,
    create: impl FnOnce() -> Option<DispatchTarget>,
) -> Option<&'static DispatchTarget> {
    let mut registry = dispatch_registry().write().ok()?;
    let existing = registry.exports.dispatch.get(&key).cloned();
    let entry = match existing {
        Some(entry) => entry,
        None => {
            let entry = Arc::new(create()?);
            registry.exports.dispatch.insert(key, Arc::clone(&entry));
            entry
        }
    };
    let identity = Arc::as_ptr(entry.slot) as usize;
    Some(registry.intern_identity(identity, &entry))
}

/// The `Export` object of `mfa`, allocated (entering the export trampoline) when the
/// node has none. It is not entered in any code index's export table: [`crate::export`] does
/// that, as `export_staged_put` / `export_staged_upsert` insert the blob erts allocates here.
// Port of erts/emulator/beam/export.c:73-98 (export_init) and erl_code_staged.h (the blob
// allocation of put/upsert), OTP-29.1.1.
pub(crate) fn make_export(mfa: Mfa) -> Option<&'static Arc<arinsal_term::ExportEntry>> {
    if let Ok(registry) = dispatch_registry().read()
        && let Some(entry) = registry.exports.dispatch.get(&mfa)
    {
        return Some(entry.slot);
    }
    let trampoline = crate::beam_jit_main::beam_export_trampoline();
    let save_calls = crate::beam_jit_main::beam_save_calls_export();
    let module = global_atoms().text(mfa.0)?.to_string();
    let function = global_atoms().text(mfa.1)?.to_string();
    let entry = dispatch_entry(mfa, || {
        let has_bif = arinsal_spec::bif_lookup(&module, &function, mfa.2).is_some();
        let (class, bits) = crate::natives::classify(&module, &function, mfa.2, has_bif);
        Some(DispatchTarget {
            // Port of erts/emulator/beam/export.c:73-98 (export_init), OTP-29.1.1.
            slot: new_export_slot(mfa, trampoline, save_calls),
            light_kind: light_kind(&module, &function, mfa.2),
            module: module.clone(),
            function: function.clone(),
            module_atom: mfa.0,
            function_atom: mfa.1,
            arity: mfa.2,
            class,
            native_bits: bits,
            light_process_bif: None,
        })
    })?;
    Some(entry.export_object())
}

/// Export descriptor returned by the native line-breakpoint prepare helper.
// Port of erts/emulator/beam/beam_bp.c:1828-1830
// (erts_line_breakpoint_hit__prepare_call), OTP-29.1.1.
pub(crate) fn line_breakpoint_export(code_ix: usize) -> Option<&'static arinsal_term::ExportEntry> {
    let atoms = arinsal_term::global_atoms();
    let mfa = (
        atoms.intern("erts_internal").ok()?,
        atoms.intern("breakpoint").ok()?,
        4,
    );
    crate::export::find_export_entry(crate::code_ix::global(), mfa, code_ix)
}

/// The dispatch entry of every import: its identity for the emitter, and its binding for the
/// export table of the code index, which the install makes.
type ImportEntries = (
    Vec<usize>,
    Vec<(Mfa, &'static Arc<arinsal_term::ExportEntry>)>,
);

fn import_entries(module: &arinsal_loader::Module) -> Option<ImportEntries> {
    let trampoline = crate::beam_jit_main::beam_export_trampoline();
    let save_calls = crate::beam_jit_main::beam_save_calls_export();
    let mut identities = Vec::with_capacity(module.imports.len());
    let mut bindings = Vec::with_capacity(module.imports.len());
    for import in &module.imports {
        let mfa = (import.module_atom, import.function_atom, import.arity);
        let entry = dispatch_entry(mfa, || {
            // A module can be compiled before the VM classified its imports.
            let (class, bits) = if import.class() == arinsal_loader::ImportClass::Fresh {
                crate::natives::classify(
                    import.module,
                    import.function,
                    import.arity,
                    arinsal_spec::bif_lookup(import.module, import.function, import.arity)
                        .is_some(),
                )
            } else {
                (import.class(), import.native_bits())
            };
            Some(DispatchTarget {
                // Port of erts/emulator/beam/export.c:73-98 (export_init), OTP-29.1.1.
                slot: new_export_slot(mfa, trampoline, save_calls),
                light_kind: light_kind(import.module, import.function, import.arity),
                module: import.module.to_owned(),
                function: import.function.to_owned(),
                module_atom: import.module_atom,
                function_atom: import.function_atom,
                arity: import.arity,
                class,
                native_bits: bits,
                light_process_bif: None,
            })
        })?;
        bindings.push((mfa, entry.export_object()));
        identities.push(Arc::as_ptr(entry.slot) as usize);
    }
    Some((identities, bindings))
}

/// The export the BIF `module:function/arity` runs under when its export entry is called
/// (`call_bif_mfa`): `c_p->current` while its `bif_table[].f` runs.
// Port of erts/emulator/beam/jit/arm/instr_bif.cpp:819-838 (call_bif_mfa) and 729-739
// (call_bif_shared stores `&ep->info.mfa` in `c_p->current`), OTP-29.1.1.
pub(crate) fn bif_mfa_export(module: &str, function: &str, arity: u8) -> Option<ExportDispatch> {
    export_dispatch(bif_mfa_entry(module, function, arity)?)
}

/// Returns the dispatch slot that runs the BIF `module:function/arity` from its stub body.
fn bif_mfa_entry(module: &str, function: &str, arity: u8) -> Option<usize> {
    let trampoline = crate::beam_jit_main::beam_export_trampoline();
    let save_calls = crate::beam_jit_main::beam_save_calls_export();
    let mut registry = dispatch_registry().write().ok()?;
    let module_atom = global_atoms().get(module)?;
    let function_atom = global_atoms().get(function)?;
    let key = (module_atom, function_atom, arity);
    let entry = Arc::clone(registry.bif_mfas.entry(key).or_insert_with(|| {
        let has_bif = arinsal_spec::bif_lookup(module, function, arity).is_some();
        let (class, bits) = crate::natives::classify(module, function, arity, has_bif);
        Arc::new(DispatchTarget {
            slot: new_export_slot(key, trampoline, save_calls),
            light_kind: light_kind(module, function, arity),
            module: module.to_owned(),
            function: function.to_owned(),
            module_atom,
            function_atom,
            arity,
            class,
            native_bits: bits,
            light_process_bif: None,
        })
    }));
    let identity = Arc::as_ptr(entry.slot) as usize;
    registry.intern_identity(identity, &entry);
    Some(identity)
}

// Port of erts/emulator/beam/export.c:154-180 (find an export) and erts_export_put, OTP-29.1.1.
fn publish_module(
    module: &arinsal_loader::Module,
    native: &[(Mfa, usize)],
    imports: &[(Mfa, &'static Arc<arinsal_term::ExportEntry>)],
    deferred: bool,
) {
    let trampoline = crate::beam_jit_main::beam_export_trampoline();
    let save_calls = crate::beam_jit_main::beam_save_calls_export();
    let mut dispatch_entries = Vec::with_capacity(module.exports.len());
    for export in &module.exports {
        let function_atom = export.function_atom;
        let mfa = (module.name_atom, function_atom, export.arity);
        let has_bif =
            arinsal_spec::bif_lookup(&module.name, export.function, export.arity).is_some();
        let (class, bits) =
            crate::natives::classify(&module.name, export.function, export.arity, has_bif);
        let target = dispatch_entry(mfa, || {
            Some(DispatchTarget {
                // Port of erts/emulator/beam/export.c:73-98 (export_init), OTP-29.1.1.
                slot: new_export_slot(mfa, trampoline, save_calls),
                light_kind: light_kind(&module.name, export.function, export.arity),
                module: module.name.clone(),
                function: export.function.to_owned(),
                module_atom: module.name_atom,
                function_atom,
                arity: export.arity,
                class,
                native_bits: bits,
                light_process_bif: None,
            })
        });
        if let Some(target) = target {
            dispatch_entries.push((mfa, target));
        }
    }
    // Port of erts/emulator/beam/jit/asm_load.c:1177-1206 (beam_load_finalize_code: exports
    // then imports through erts_export_put; each export's code address is written into
    // `addresses[staging_ix]`), OTP-29.1.1.
    let exports: Vec<_> = dispatch_entries
        .iter()
        .map(|(mfa, target)| (*mfa, target.export_object()))
        .collect();
    crate::export::finish_loading(module, &exports, imports, native, deferred);
}

/// The address a process saving calls continues with after recording the call of the export
/// with `identity`: the export's address in its node's active code index.
// Port of erts/emulator/beam/jit/arm/instr_call.cpp:141-147 (emit_dispatch_save_calls_export:
// "Keep going with the actual code index"), OTP-29.1.1.
pub(crate) fn save_calls_continuation(export: Option<ExportDispatch>) -> usize {
    export.map_or_else(crate::beam_jit_main::beam_export_trampoline, |target| {
        let active = crate::code_ix::global().active();
        target.slot.address(active)
    })
}

/// Publishes `Export.is_bif_traced` on every slot of `module:function/arity`.
// Port of erts/emulator/beam/beam_bp.c:360-375 (consolidate_export_bp_data), OTP-29.1.1.
pub(crate) fn set_bif_traced(module: &str, function: &str, arity: u8, traced: bool) {
    let Some(mfa) = existing_mfa(module, function, arity) else {
        return;
    };
    let Ok(registry) = dispatch_registry().read() else {
        return;
    };
    if let Some(target) = registry.exports.dispatch.get(&mfa) {
        target.slot.set_bif_traced(traced);
    }
    if let Some(target) = registry.bif_mfas.get(&mfa) {
        target.slot.set_bif_traced(traced);
    }
}

/// Descriptor addressed directly by the native export slot.
pub(crate) type ExportDispatch = &'static DispatchTarget;

thread_local! {
    /// Per-scheduler copy of `by_identity`: an identity is the address of a slot the cached
    /// target keeps alive, so a stale entry can only be a target nothing calls any more. It
    /// keeps native BIF calls off the shared registry lock and its hash map.
    static TARGET_CACHE: std::cell::RefCell<HashMap<usize, &'static DispatchTarget, IdentityHasher>> =
        const { std::cell::RefCell::new(HashMap::with_hasher(IdentityHasher)) };
}

/// Hasher for keys that are already well-spread addresses.
#[derive(Default, Clone, Copy)]
pub(crate) struct IdentityHasher;

impl std::hash::BuildHasher for IdentityHasher {
    type Hasher = IdentityState;
    fn build_hasher(&self) -> IdentityState {
        IdentityState(0)
    }
}

pub(crate) struct IdentityState(u64);

impl std::hash::Hasher for IdentityState {
    fn finish(&self) -> u64 {
        self.0
    }
    fn write(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            self.0 = (self.0 << 8) ^ u64::from(byte);
        }
    }
    fn write_usize(&mut self, value: usize) {
        // Slot addresses are 8-aligned; fold the high bits down so buckets differ.
        self.0 = (value as u64) ^ ((value as u64) >> 12);
    }
}

fn target_for_identity(identity: usize) -> Option<&'static DispatchTarget> {
    if let Some(found) = TARGET_CACHE.with(|cache| cache.borrow().get(&identity).copied()) {
        return Some(found);
    }
    let registry = dispatch_registry().read().ok()?;
    let target = *registry.by_identity.get(&identity)?;
    drop(registry);
    TARGET_CACHE.with(|cache| cache.borrow_mut().insert(identity, target));
    Some(target)
}

pub(crate) fn export_dispatch(identity: usize) -> Option<ExportDispatch> {
    target_for_identity(identity)
}

/// The return address of a raising call when the native pc names its call site: arm's BIF
/// call sites tag that pc (`arm::tagged_return_site`); x86 call sites pass the plain return
/// address, as erts does on both.
#[inline]
pub(crate) fn native_return_site(pc: usize) -> Option<usize> {
    #[cfg(target_arch = "aarch64")]
    return arm::tagged_return_site(pc);
    #[cfg(not(target_arch = "aarch64"))]
    {
        let _ = pc;
        None
    }
}

/// The native pc a raising call is attributed to when `return_address` is the continuation
/// of its frame (`erts_inspect_frame`): the plain return address, as erts passes it to
/// `handle_error` on both targets; arm marks it as a return site (the inverse of
/// [`native_return_site`]).
#[inline]
pub(crate) fn return_address_pc(return_address: usize) -> usize {
    #[cfg(target_arch = "aarch64")]
    return arm::tag_return_site(return_address);
    #[cfg(not(target_arch = "aarch64"))]
    return_address
}

#[cfg(target_arch = "x86_64")]
mod x86;
#[cfg(target_arch = "x86_64")]
pub(crate) use x86::*;

#[cfg(target_arch = "aarch64")]
mod arm;
#[cfg(target_arch = "aarch64")]
pub(crate) use arm::*;
