//! Loading and registration for the incremental BeamAsm compiler.
use arinsal_beam::BeamFile;
use arinsal_beamasm::{
    arith::ArithHelper,
    construct::GcHook,
    dispatch::DispatchFragments,
    guard::{GuardHelper, GuardHelper3},
};
use arinsal_beamjit::{
    BifMfaHelper, MapLookupHelper, ModuleEnv, compile_parsed_module_with_options,
};
use arinsal_term::{Term, TermBuilder, VecHeap, from_owned, global_atoms};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{OnceLock, RwLock, Weak};

type Mfa = (String, String, u8);

/// Function-indexed BeamAsm target cache, invalidated when native code is published.
pub(crate) struct NativeTargetCache {
    scope: u64,
    targets: Vec<Vec<Option<crate::NativeFunction>>>,
    generations: Vec<u64>,
    module_identities: Vec<usize>,
    /// Native code range each cached module instance was resolved against.
    ranges: Vec<Option<(usize, usize)>>,
}

impl NativeTargetCache {
    pub(crate) fn new(scope: u64) -> Self {
        Self {
            scope,
            targets: Vec::new(),
            generations: Vec::new(),
            module_identities: Vec::new(),
            ranges: Vec::new(),
        }
    }

    pub(crate) fn register_module(&mut self, module_id: usize, module: &arinsal_loader::Module) {
        let targets = vec![None; module.functions.len()];
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
        if module.entry_arity.get(target).copied().unwrap_or(0) == 0 {
            return None;
        }
        let index = *module.on_entry_fn.get(target)?;
        if index == u32::MAX {
            return None;
        }
        let index = index as usize;
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
            let mut natives = crate::native_bridge::native_functions_of(self.scope, &module.name);
            if let Some((start, end)) = range {
                natives.retain(|_, native| start <= native.start && native.start < end);
            }
            let cache = self.targets.get_mut(module_id)?;
            cache.clear();
            cache.extend(
                module
                    .functions
                    .iter()
                    .map(|(_, function, arity)| natives.remove(&(function.clone(), *arity))),
            );
            self.generations[module_id] = generation;
            if self.ranges.len() <= module_id {
                self.ranges.resize(module_id + 1, None);
            }
            self.ranges[module_id] = range;
        }
        self.targets.get(module_id)?.get(index)?.clone()
    }
}

#[derive(Clone)]
pub(crate) struct DispatchTarget {
    slot: Arc<arinsal_beamasm::bif::ExportEntry>,
    /// Code scope whose code indexes select the slot's address; zero for scope-free slots.
    scope: u64,
    pub module: String,
    pub function: String,
    pub module_atom: arinsal_term::Atom,
    pub function_atom: arinsal_term::Atom,
    pub arity: u8,
    bif: Option<arinsal_bifs::BifFn>,
    pub class: arinsal_loader::ImportClass,
    pub native_bits: usize,
    /// The BIF has a continuation entry in `bif_traps`; others skip that table on every call.
    pub trap_entry: bool,
    /// Runs the BIF inside native code, see `natives::ets::DirectEts`.
    pub direct_ets: Option<crate::natives::ets::DirectEts>,
}

/// One node's export state, like an erts code index: import slots, interpreted and native
/// export targets and global call breakpoints.
#[derive(Default)]
struct ScopeExports {
    // Keyed by importing module, import index and the imported MFA: a reloaded module whose
    // import table differs must not reuse another function's slot.
    imports: HashMap<(String, u32, Mfa), Arc<DispatchTarget>>,
    target_indices: HashMap<Mfa, usize>,
    native_targets: HashMap<Mfa, usize>,
    // Exports with a global call breakpoint: their callers go through the export
    // trampoline, whose interpreted export entry is the breakpoint.
    global_breakpoints: std::collections::HashSet<Mfa>,
}

#[derive(Default)]
struct DispatchRegistry {
    scopes: HashMap<u64, ScopeExports>,
    // Leaked on first registration: native BIF calls read these on every call, and a shared
    // reference count would bounce between schedulers. Each is a few hundred bytes per import.
    by_identity: HashMap<usize, &'static DispatchTarget>,
    // Slots for `call_bif_mfa`; unlike imports they always enter the BIF itself.
    bif_mfas: HashMap<Mfa, Arc<DispatchTarget>>,
}

impl DispatchRegistry {
    fn intern_identity(&mut self, identity: usize, entry: &Arc<DispatchTarget>) {
        self.by_identity
            .entry(identity)
            .or_insert_with(|| Box::leak(Box::new(DispatchTarget::clone(entry))));
    }
}

fn dispatch_registry() -> &'static RwLock<DispatchRegistry> {
    static REGISTRY: OnceLock<RwLock<DispatchRegistry>> = OnceLock::new();
    REGISTRY.get_or_init(|| RwLock::new(DispatchRegistry::default()))
}

/// Allocates the code scope of a new node.
pub(crate) fn new_code_scope() -> u64 {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

/// Forgets the export state of a node whose code is gone.
pub(crate) fn release_code_scope(scope: u64) {
    arinsal_term::drop_record_scope(scope);
    crate::native_bridge::unregister_native_scope(scope);
    crate::code_ix::release_scope(scope);
    let Ok(mut registry) = dispatch_registry().write() else {
        return;
    };
    if let Some(exports) = registry.scopes.remove(&scope) {
        for entry in exports.imports.values() {
            registry
                .by_identity
                .remove(&(Arc::as_ptr(&entry.slot) as usize));
        }
    }
}

fn fragments() -> Option<&'static DispatchFragments> {
    static FRAGMENTS: OnceLock<Option<DispatchFragments>> = OnceLock::new();
    FRAGMENTS
        .get_or_init(|| {
            DispatchFragments::new(
                crate::native_helpers::arinsal_beamasm_export_trampoline as *const () as usize,
                crate::native_helpers::arinsal_beamasm_call_light_bif_shared as *const () as usize,
                crate::native_helpers::arinsal_beamasm_exception_resolver as *const () as usize,
                crate::native_helpers::arinsal_beamasm_save_calls_export as *const () as usize,
            )
            .ok()
        })
        .as_ref()
}

fn import_entries(scope: u64, module: &arinsal_loader::Module) -> Option<Vec<usize>> {
    let trampoline = fragments()?.export_trampoline();
    let save_calls = fragments()?.save_calls_export();
    let mut registry = dispatch_registry().write().ok()?;
    let mut identities = Vec::with_capacity(module.imports.len());
    for (index, import) in module.imports.iter().enumerate() {
        let mfa = (import.module.clone(), import.function.clone(), import.arity);
        let key = (module.name.clone(), index as u32, mfa.clone());
        let exports = registry.scopes.entry(scope).or_default();
        let address = import_slot_address(exports, &mfa, trampoline);
        let entry = Arc::clone(exports.imports.entry(key).or_insert_with(|| {
            // A module can be compiled before the VM classified its imports.
            let (class, bits) = if import.class() == arinsal_loader::ImportClass::Fresh {
                crate::natives::classify(
                    &import.module,
                    &import.function,
                    import.arity,
                    import.bif_fn().is_some(),
                )
            } else {
                (import.class(), import.native_bits())
            };
            Arc::new(DispatchTarget {
                // Port of erts/emulator/beam/export.c:73-98 (export_init), OTP-29.1.1.
                slot: Arc::new(arinsal_beamasm::bif::ExportEntry::with_save_calls(
                    address, save_calls,
                )),
                scope,
                trap_entry: crate::bif_traps::traps(&import.module, &import.function, import.arity),
                direct_ets: crate::natives::ets::direct_entry(
                    &import.module,
                    &import.function,
                    import.arity,
                ),
                module: import.module.clone(),
                function: import.function.clone(),
                module_atom: import.module_atom,
                function_atom: import.function_atom,
                arity: import.arity,
                bif: import.bif_fn(),
                class,
                native_bits: bits,
            })
        }));
        let identity = Arc::as_ptr(&entry.slot) as usize;
        registry.intern_identity(identity, &entry);
        identities.push(identity);
    }
    Some(identities)
}

/// Returns the dispatch slot that runs the BIF `module:function/arity` from its stub body.
fn bif_mfa_entry(module: &str, function: &str, arity: u8) -> Option<usize> {
    let trampoline = fragments()?.export_trampoline();
    let save_calls = fragments()?.save_calls_export();
    let mut registry = dispatch_registry().write().ok()?;
    let key = (module.to_owned(), function.to_owned(), arity);
    let module_atom = global_atoms().get(module)?;
    let function_atom = global_atoms().get(function)?;
    let entry = Arc::clone(registry.bif_mfas.entry(key).or_insert_with(|| {
        let bif = arinsal_bifs::lookup(module, function, arity);
        let (class, bits) = crate::natives::classify(module, function, arity, bif.is_some());
        Arc::new(DispatchTarget {
            slot: Arc::new(arinsal_beamasm::bif::ExportEntry::with_save_calls(
                trampoline, save_calls,
            )),
            scope: 0,
            trap_entry: crate::bif_traps::traps(module, function, arity),
            direct_ets: crate::natives::ets::direct_entry(module, function, arity),
            module: module.to_owned(),
            function: function.to_owned(),
            module_atom,
            function_atom,
            arity,
            bif,
            class,
            native_bits: bits,
        })
    }));
    let identity = Arc::as_ptr(&entry.slot) as usize;
    registry.intern_identity(identity, &entry);
    Some(identity)
}

fn publish_module(scope: u64, module: &arinsal_loader::Module, native: &[(Mfa, usize)]) {
    staged(scope, |exports| {
        publish_module_exports(exports, module, native);
    });
}

fn publish_module_exports(
    exports: &mut ScopeExports,
    module: &arinsal_loader::Module,
    native: &[(Mfa, usize)],
) {
    exports
        .target_indices
        .retain(|(name, _, _), _| name != &module.name);
    exports
        .native_targets
        .retain(|(name, _, _), _| name != &module.name);
    for export in &module.exports {
        exports.target_indices.insert(
            (module.name.clone(), export.function.clone(), export.arity),
            export.target(),
        );
    }
    for (mfa, address) in native {
        exports.native_targets.insert(mfa.clone(), *address);
    }
}

/// Copies every export's active address of `scope` into the staging code index when the
/// node opens a staging area.
// Port of erts/emulator/beam/export.c:100-106 (export_stage) and 277-280
// (export_start_staging), OTP-29.1.1.
pub(crate) fn stage_dispatch(scope: u64) {
    let Ok(mut registry) = dispatch_registry().write() else {
        return;
    };
    let exports = registry.scopes.entry(scope).or_default();
    let code_ix = crate::code_ix::for_scope(scope);
    let (active, staging) = (code_ix.active(), code_ix.staging());
    for entry in exports.imports.values() {
        entry.slot.stage(active, staging);
    }
}

/// Applies `change` to the exports of `scope` in the staging code index. Outside a load's
/// staging area the change is staged and committed on its own, like the code changes erts
/// makes under the code modification permission (delete_module, trace patterns).
fn staged(scope: u64, change: impl FnOnce(&mut ScopeExports)) {
    let code_ix = crate::code_ix::for_scope(scope);
    let staging = code_ix.start_staging();
    let Ok(mut registry) = dispatch_registry().write() else {
        return;
    };
    let exports = registry.scopes.entry(scope).or_default();
    change(exports);
    refresh_import_slots(exports, staging.ix());
    drop(registry);
    drop(staging);
}

/// Sends native callers of a deleted module's exports to the export trampoline, whose
/// interpreted dispatch finds no current module and calls the error handler.
// Port of erts/emulator/beam/beam_bif_load.c:679-720 (delete_module_1: export addresses
// point at the error handler stub), OTP-29.1.1.
pub(crate) fn unpublish_module_exports(scope: u64, name: &str) {
    if !has_scope(scope) {
        return;
    }
    staged(scope, |exports| {
        exports
            .target_indices
            .retain(|(module, _, _), _| module != name);
        exports
            .native_targets
            .retain(|(module, _, _), _| module != name);
    });
}

fn unpublish_module(scope: u64, native: &[(Mfa, usize)]) {
    // Only exports still entering this version need a staged change.
    let current = dispatch_registry().read().is_ok_and(|registry| {
        registry.scopes.get(&scope).is_some_and(|exports| {
            native
                .iter()
                .any(|(mfa, address)| exports.native_targets.get(mfa) == Some(address))
        })
    });
    if !current {
        return;
    }
    staged(scope, |exports| {
        for (mfa, address) in native {
            if exports.native_targets.get(mfa) == Some(address) {
                exports.native_targets.remove(mfa);
            }
        }
    });
}

fn has_scope(scope: u64) -> bool {
    dispatch_registry()
        .read()
        .is_ok_and(|registry| registry.scopes.contains_key(&scope))
}

// Port of erts/emulator/beam/beam_bp.c:1180-1230 (erts_set_trace_pattern: a global
// breakpoint redirects the export's addresses to its trampoline), OTP-29.1.1.
fn import_slot_address(exports: &ScopeExports, mfa: &Mfa, trampoline: usize) -> usize {
    if exports.global_breakpoints.contains(mfa) {
        return trampoline;
    }
    exports
        .native_targets
        .get(mfa)
        .copied()
        .unwrap_or(trampoline)
}

/// Writes every import slot's address in code index `ix` from the export tables.
fn refresh_import_slots(exports: &ScopeExports, ix: usize) {
    let trampoline = fragments().map_or(0, DispatchFragments::export_trampoline);
    for entry in exports.imports.values() {
        let mfa = (entry.module.clone(), entry.function.clone(), entry.arity);
        entry
            .slot
            .set_address(ix, import_slot_address(exports, &mfa, trampoline));
    }
}

/// The address a process saving calls continues with after recording the call of the export
/// with `identity`: the export's address in its node's active code index.
// Port of erts/emulator/beam/jit/arm/instr_call.cpp:141-147 (emit_dispatch_save_calls_export:
// "Keep going with the actual code index"), OTP-29.1.1.
pub(crate) fn save_calls_continuation(identity: usize) -> usize {
    target_for_identity(identity).map_or_else(
        || fragments().map_or(0, DispatchFragments::export_trampoline),
        |target| {
            let active = crate::code_ix::for_scope(target.scope).active();
            target.slot.address(active)
        },
    )
}

/// Routes native callers of an export through its interpreted entry, `target`, while a
/// global call breakpoint is set on it.
pub(crate) fn set_global_breakpoint(
    scope: u64,
    module: &str,
    function: &str,
    arity: u8,
    target: usize,
    enabled: bool,
) {
    let mfa = (module.to_owned(), function.to_owned(), arity);
    let set_target = |exports: &mut ScopeExports| {
        if let Some(index) = exports.target_indices.get_mut(&mfa) {
            *index = target;
        }
    };
    let routed = dispatch_registry().read().is_ok_and(|registry| {
        registry
            .scopes
            .get(&scope)
            .is_some_and(|exports| exports.global_breakpoints.contains(&mfa))
    });
    if routed == enabled {
        if let Ok(mut registry) = dispatch_registry().write() {
            set_target(registry.scopes.entry(scope).or_default());
        }
        return;
    }
    // Port of erts/emulator/beam/beam_bp.c:1180-1230 (erts_set_trace_pattern), OTP-29.1.1:
    // rerouting the export's callers is a staged code change.
    staged(scope, |exports| {
        if enabled {
            exports.global_breakpoints.insert(mfa.clone());
        } else {
            exports.global_breakpoints.remove(&mfa);
        }
        set_target(exports);
    });
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

/// Returns the published native entry for an MFA, if this module was BeamAsm-compiled.
pub(crate) fn native_target_for(
    scope: u64,
    module: &str,
    function: &str,
    arity: u8,
) -> Option<usize> {
    let registry = dispatch_registry().read().ok()?;
    registry
        .scopes
        .get(&scope)?
        .native_targets
        .get(&(module.to_owned(), function.to_owned(), arity))
        .copied()
}

/// Shared fragment that exits native code so the scheduler can interpret a fun call.
pub(crate) fn call_fun_unported_entry() -> usize {
    fragments().map_or(0, DispatchFragments::call_fun_unported)
}

/// Native entry for an exported MFA; local functions must stay unreachable through `apply`.
pub(crate) fn exported_native_target(
    scope: u64,
    module: &str,
    function: &str,
    arity: u8,
) -> Option<usize> {
    let registry = dispatch_registry().read().ok()?;
    let exports = registry.scopes.get(&scope)?;
    let key = (module.to_owned(), function.to_owned(), arity);
    exports.target_indices.contains_key(&key).then_some(())?;
    if exports.global_breakpoints.contains(&key) {
        return None;
    }
    exports.native_targets.get(&key).copied()
}

/// Shared fragment that exits native code so the scheduler can interpret `apply Arity`.
pub(crate) fn apply_fixed_unported_entry() -> usize {
    fragments().map_or(0, DispatchFragments::apply_fixed_unported)
}

/// Shared fragment that exits native code so the scheduler can interpret `apply/3`.
pub(crate) fn apply3_unported_entry() -> usize {
    fragments().map_or(0, DispatchFragments::apply3_unported)
}

pub(crate) fn dispatch_bif(identity: usize) -> Option<(arinsal_bifs::BifFn, u8)> {
    let target = target_for_identity(identity)?;
    Some((target.bif?, target.arity))
}

pub(crate) fn interpreted_target(
    scope: u64,
    module: &str,
    function: &str,
    arity: u8,
) -> Option<usize> {
    dispatch_registry()
        .read()
        .ok()?
        .scopes
        .get(&scope)?
        .target_indices
        .get(&(module.to_owned(), function.to_owned(), arity))
        .copied()
}

static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
static MODULES: AtomicU64 = AtomicU64::new(0);
static NATIVE: AtomicU64 = AtomicU64::new(0);
static UNPORTED: AtomicU64 = AtomicU64::new(0);
static NATIVE_CALLS: AtomicU64 = AtomicU64::new(0);
static INTERP_SLICES: AtomicU64 = AtomicU64::new(0);
static INTERP_NATIVE_STARTS: AtomicU64 = AtomicU64::new(0);
static NATIVE_YIELDS: AtomicU64 = AtomicU64::new(0);
static CALL_UNPORTED: AtomicU64 = AtomicU64::new(0);
static PRINTED: AtomicBool = AtomicBool::new(false);

fn lifetime_trace_enabled() -> bool {
    crate::native_bridge::lifetime_trace_enabled()
}

/// Owns a compiled module version and the heap that backs its embedded literals.
pub(crate) struct CompiledVersion {
    module: String,
    scope: u64,
    memory: std::sync::Mutex<arinsal_a64::exec::CodeMemory>,
    trace_breakpoints: Vec<(Mfa, usize, u32)>,
    // Line breakpoint patch sites: source line, branch word offset, original branch.
    line_breakpoints: Vec<(u32, usize, u32)>,
    // Return addresses of enabled line-breakpoint hits, ascending.
    line_breakpoint_returns: Vec<(usize, usize)>,
    // Function, arity, call-NIF identity and the patch word that enables its body.
    nif_patches: Vec<(String, u8, usize, usize)>,
    literal_heap: Option<Box<VecHeap>>,
    // The module's literal area, which native code refers to directly.
    _module_literals: Arc<VecHeap>,
    native_functions: Vec<crate::NativeFunction>,
    native_targets: Vec<(Mfa, usize)>,
    code_start: usize,
    code_end: usize,
    catch_ids: Vec<u32>,
    lambda_entries: Vec<Arc<arinsal_term::FunEntry>>,
}

/// Enable or remove native entry breakpoints for a traced function.
// Port of erts/emulator/beam/jit/arm/beam_asm_module.cpp:231-250, OTP-29.1.1.
pub(crate) fn patch_native_breakpoint(
    scope: u64,
    module: &str,
    function: &str,
    arity: u8,
    enabled: bool,
) {
    let Ok(mut versions) = compiled_versions().write() else {
        return;
    };
    versions.retain(|version| version.strong_count() != 0);
    for version in versions
        .iter()
        .filter_map(Weak::upgrade)
        .filter(|version| version.scope == scope)
    {
        for ((owner, name, found_arity), offset, branch) in &version.trace_breakpoints {
            if owner != module || name != function || *found_arity != arity {
                continue;
            }
            let instruction = if enabled { 0xd503_201f_u32 } else { *branch };
            if let Ok(mut memory) = version.memory.lock() {
                let _ = memory.write_bytes(*offset, &instruction.to_le_bytes());
            }
        }
    }
}

/// The address standing for the instrumented function in the stack frame of a native
/// line-breakpoint hit whose breakpoint call returns to `address`; `None` when `address` is
/// not such a return address.
pub(crate) fn line_breakpoint_site(address: usize) -> Option<usize> {
    let versions = compiled_versions().read().ok()?;
    versions
        .iter()
        .filter_map(Weak::upgrade)
        .find_map(|version| {
            if !(version.code_start..version.code_end).contains(&address) {
                return None;
            }
            let index = version
                .line_breakpoint_returns
                .binary_search_by_key(&address, |(resume, _)| *resume)
                .ok()?;
            Some(version.line_breakpoint_returns[index].1)
        })
}

/// Whether `address` is the return address of a native line-breakpoint hit, the
/// continuation that restores the registers spilled for `erts_internal:breakpoint/4`.
pub(crate) fn is_line_breakpoint_return(address: usize) -> bool {
    line_breakpoint_site(address).is_some()
}

/// Enable or disable the native line-breakpoint sites of `line` in `module`.
// Port of erts/emulator/beam/jit/arm/beam_asm_module.cpp:337-348, OTP-29.1.1: the `b next`
// that skips the trampoline is rewritten to a NOP when the breakpoint is enabled.
pub(crate) fn patch_native_line_breakpoint(scope: u64, module: &str, line: u32, enabled: bool) {
    let Ok(mut versions) = compiled_versions().write() else {
        return;
    };
    versions.retain(|version| version.strong_count() != 0);
    for version in versions
        .iter()
        .filter_map(Weak::upgrade)
        .filter(|version| version.scope == scope && version.module == module)
    {
        for &(site_line, offset, branch) in &version.line_breakpoints {
            if site_line != line {
                continue;
            }
            let instruction = if enabled { 0xd503_201f_u32 } else { branch };
            if let Ok(mut memory) = version.memory.lock() {
                let _ = memory.write_bytes(offset, &instruction.to_le_bytes());
            }
        }
    }
}

impl CompiledVersion {
    /// Whether this version has native code for `function/arity`.
    pub(crate) fn has_native_function(&self, function: &str, arity: u8) -> bool {
        self.native_functions
            .iter()
            .any(|native| native.function == function && native.arity == arity)
    }

    /// Start address of this version's native code for `function/arity`.
    pub(crate) fn native_function_start(&self, function: &str, arity: u8) -> Option<usize> {
        self.native_functions
            .iter()
            .find(|native| native.function == function && native.arity == arity)
            .map(|native| native.start)
    }

    /// Makes native entries of `function/arity` run the NIF `entry` loaded by `load_nif`.
    // Port of erts/emulator/beam/erl_nif.c:5050-5260 (patch_call_nif_early and the load_nif
    // finishers), OTP-29.1.1.
    pub(crate) fn bind_nif(&self, function: &str, arity: u8, entry: arinsal_bifs::BifFn) -> bool {
        let Some((_, _, identity, offset)) = self
            .nif_patches
            .iter()
            .find(|(name, found, _, _)| name == function && *found == arity)
        else {
            return false;
        };
        if !crate::native_helpers::bind_nif_slot(*identity, entry) {
            return false;
        }
        let Ok(mut memory) = self.memory.lock() else {
            return false;
        };
        memory
            .write_bytes(*offset, &0xd503_201f_u32.to_le_bytes())
            .is_ok()
    }

    pub(crate) fn publish(&self, module: &arinsal_loader::Module) {
        publish_module(self.scope, module, &self.native_targets);
    }
    /// The half-open address range of this version's native code.
    pub(crate) fn code_range(&self) -> (usize, usize) {
        (self.code_start, self.code_end)
    }
}

/// Literal heaps of purged native module versions. Process heaps may still reference their
/// literals (a zero-capture fun, a constant), and no literal area collector copies them out
/// yet (erts_literal_area_collector: nothing is queued), so they stay allocated, like the
/// interpreter's literal areas.
// The heaps stay boxed: literal terms point at them, so they must not move.
#[allow(clippy::vec_box)]
fn retired_literal_heaps() -> &'static std::sync::Mutex<Vec<Box<VecHeap>>> {
    static RETIRED: OnceLock<std::sync::Mutex<Vec<Box<VecHeap>>>> = OnceLock::new();
    RETIRED.get_or_init(|| std::sync::Mutex::new(Vec::new()))
}

impl Drop for CompiledVersion {
    fn drop(&mut self) {
        // Port of erts/emulator/beam/beam_bif_load.c (purge: fun entries of the purged code
        // dispatch to the unloaded-fun handler), OTP-29.1.1: a cleared slot sends the call
        // to the call_fun resolver, which raises through the error handler.
        for entry in &self.lambda_entries {
            if entry
                .get_dispatch_target(0)
                .is_some_and(|target| self.code_start <= target && target < self.code_end)
            {
                entry.set_dispatch_target(0, 0);
            }
        }
        if let Some(heap) = self.literal_heap.take()
            && let Ok(mut retired) = retired_literal_heaps().lock()
        {
            retired.push(heap);
        }
        crate::native_helpers::release_nif_slots(
            self.nif_patches.iter().map(|(_, _, identity, _)| *identity),
        );
        crate::native_bridge::unregister_native_functions(&self.native_functions);
        crate::native_bridge::unregister_native_catches(&self.catch_ids);
        unpublish_module(self.scope, &self.native_targets);
        if lifetime_trace_enabled() {
            eprintln!(
                "[beamasm-lifetime] CodeMemory drop module={} range={:#x}..{:#x}",
                self.module, self.code_start, self.code_end
            );
        }
    }
}

fn compiled_versions() -> &'static RwLock<Vec<Weak<CompiledVersion>>> {
    static VERSIONS: OnceLock<RwLock<Vec<Weak<CompiledVersion>>>> = OnceLock::new();
    VERSIONS.get_or_init(|| RwLock::new(Vec::new()))
}

pub(crate) fn owns_native_address(address: usize) -> bool {
    let Ok(versions) = compiled_versions().read() else {
        return false;
    };
    versions.iter().any(|version| {
        version
            .upgrade()
            .is_some_and(|version| version.code_start <= address && address < version.code_end)
    })
}

pub(crate) fn enabled() -> bool {
    *ENABLED.get_or_init(|| {
        let enabled = beamasm_enabled(
            std::env::var_os("ARINSAL_INTERP"),
            std::env::var_os("ARINSAL_BEAMASM"),
        );
        arinsal_bifs::set_emu_flavor_jit(enabled);
        enabled
    })
}

fn beamasm_enabled(
    interp: Option<std::ffi::OsString>,
    beamasm: Option<std::ffi::OsString>,
) -> bool {
    interp.as_deref() != Some(std::ffi::OsStr::new("1"))
        && beamasm.as_deref() != Some(std::ffi::OsStr::new("0"))
}

struct VmModuleEnv<'a> {
    literal_heap: std::cell::RefCell<&'a mut VecHeap>,
    literals: Vec<u64>,
    zero_capture_funs: HashMap<u32, u64>,
    lambda_entries: HashMap<u32, Arc<arinsal_term::FunEntry>>,
    export_entries: Vec<usize>,
    export_trampoline: usize,
    light_bif_fragment: usize,
    send_fragment: usize,
    native_bodies: HashMap<(String, u8), (usize, usize)>,
    module_name: String,
    // Call-NIF bodies reserved for functions a later load_nif may replace.
    dynamic_nifs: std::cell::RefCell<HashMap<(String, u8), usize>>,
    _lifetime: std::marker::PhantomData<&'a BeamFile>,
}

impl<'a> VmModuleEnv<'a> {
    fn new(
        beam: &'a BeamFile,
        module: &arinsal_loader::Module,
        literal_heap: &'a mut VecHeap,
        export_entries: Vec<usize>,
        fragments: &DispatchFragments,
    ) -> Result<Self, String> {
        let mut literals = Vec::with_capacity(beam.literals.len());
        for index in 0..beam.literals.len() {
            // Port of erts/emulator/beam/jit/asm_load.c (beamasm_codegen: literals live in the
            // module's literal area), OTP-29.1.1: native code refers to the same literal terms
            // as the interpreter's code of this module.
            if let Some(term) = module.literal_term(index as u32) {
                literals.push(raw_word(term));
                continue;
            }
            let value = beam
                .literal(index as u32)
                .map_err(|error| error.to_string())?;
            let term = from_owned(&value, literal_heap).map_err(|error| format!("{error:?}"))?;
            literals.push(raw_word(term));
        }
        // Port of erts/emulator/beam/generators.tab:255-295 (gen.create_local_record): the
        // definition literal of every record follows the BEAM literals.
        literals.extend(module.record_defs.iter().map(|cons| raw_word(*cons)));
        let mut zero_capture_funs = HashMap::new();
        let lambda_entries = module
            .funs
            .iter()
            .map(|slot| (slot.entry.old_index, Arc::clone(&slot.entry)))
            .collect();
        for lambda in beam.lambdas.iter().filter(|lambda| lambda.num_free == 0) {
            let slot = module
                .funs
                .iter()
                .find(|slot| slot.entry.old_index == lambda.index)
                .ok_or_else(|| format!("zero-capture fun {} has no loaded entry", lambda.index))?;
            let term = TermBuilder::new(literal_heap)
                .local_fun(Arc::clone(&slot.entry), &[])
                .map_err(|error| format!("zero-capture fun {}: {error:?}", lambda.index))?;
            zero_capture_funs.insert(lambda.index, raw_word(term));
        }
        // Port of erts/emulator/beam/jit/arm/asm_load.c:651, OTP-29.1.1: loader-patched static
        // NIF bodies call their Rust body through the shared runtime helper.
        let mut native_bodies = HashMap::new();
        for (entry, function, arity) in &module.functions {
            let patched = module
                .code
                .get(entry.saturating_add(1))
                .is_some_and(|instruction| {
                    matches!(instruction, arinsal_loader::Instr::NativeBody { .. })
                });
            if !patched {
                continue;
            }
            if let Some(nif) = crate::natives::static_nif_lookup(&module.name, function, *arity) {
                let identity = crate::native_helpers::register_static_nif(
                    module.name.clone(),
                    function.clone(),
                    *arity,
                    nif,
                );
                native_bodies.insert(
                    (function.clone(), *arity),
                    (
                        identity,
                        crate::native_helpers::arinsal_beamasm_static_nif as *const () as usize,
                    ),
                );
            }
        }
        Ok(Self {
            literal_heap: std::cell::RefCell::new(literal_heap),
            literals,
            zero_capture_funs,
            lambda_entries,
            export_entries,
            export_trampoline: fragments.export_trampoline(),
            light_bif_fragment: fragments.call_light_bif(),
            send_fragment: fragments.send(),
            native_bodies,
            module_name: module.name.clone(),
            dynamic_nifs: std::cell::RefCell::new(HashMap::new()),
            _lifetime: std::marker::PhantomData,
        })
    }
}

impl ModuleEnv for VmModuleEnv<'_> {
    fn integer_literal(&self, value: i64) -> Result<u64, String> {
        let mut heap = self.literal_heap.borrow_mut();
        from_owned(&arinsal_etf::OwnedTerm::Int(value), &mut **heap)
            .map(raw_word)
            .map_err(|error| format!("integer literal: {error:?}"))
    }

    fn match_string(&self, bytes: &[u8]) -> Result<u64, String> {
        Ok(crate::native_helpers::register_match_string(bytes))
    }

    fn bigint_literal(&self, decimal: &str) -> Result<u64, String> {
        let value = decimal
            .parse::<num_bigint::BigInt>()
            .map_err(|error| format!("bignum literal: {error}"))?;
        let mut heap = self.literal_heap.borrow_mut();
        from_owned(&arinsal_etf::OwnedTerm::BigInt(value), &mut **heap)
            .map(raw_word)
            .map_err(|error| format!("bignum literal: {error:?}"))
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

    fn sort_map_keys(&self, keys: &[u64]) -> Result<Vec<usize>, String> {
        let terms = keys
            .iter()
            .map(|word| crate::native_hooks::from_raw(*word))
            .collect::<Vec<_>>();
        let mut order = (0..terms.len()).collect::<Vec<_>>();
        order.sort_by(|&a, &b| arinsal_maps::flatmap_key_cmp(terms[a], terms[b]));
        Ok(order)
    }

    fn atom(&self, beam: &BeamFile, index: u32) -> Result<u64, String> {
        let name = beam
            .atom(index)
            .ok_or_else(|| format!("atom index {index} is out of range"))?;
        let atom = global_atoms()
            .intern(name)
            .map_err(|error| format!("atom {name}: {error:?}"))?;
        Ok(raw_word(Term::atom(atom)))
    }

    fn literal(&self, _beam: &BeamFile, index: u32) -> Result<u64, String> {
        if let Some(lambda_index) = u32::MAX.checked_sub(index)
            && let Some(fun) = self.zero_capture_funs.get(&lambda_index)
        {
            return Ok(*fun);
        }
        self.literals
            .get(index as usize)
            .copied()
            .ok_or_else(|| format!("literal index {index} is out of range"))
    }

    fn import(&self, beam: &BeamFile, index: u32) -> Result<u32, String> {
        let import = beam
            .imports
            .get(index as usize)
            .ok_or_else(|| format!("import index {index} is out of range"))?;
        beam.atom(import.module_atom)
            .ok_or_else(|| format!("import module atom {} is missing", import.module_atom))?;
        beam.atom(import.function_atom)
            .ok_or_else(|| format!("import function atom {} is missing", import.function_atom))?;
        // Preserve the BEAM import slot; OTP patches this slot after export publication
        // in `jit/asm_load.c:532-547` (OTP-29.1.1).
        Ok(index)
    }

    fn export_entry(&self, _beam: &BeamFile, index: u32) -> Result<usize, String> {
        self.export_entries
            .get(index as usize)
            .copied()
            .ok_or_else(|| format!("external export slot {index} is out of range"))
    }

    fn lambda_fun_entry(&self, _beam: &BeamFile, index: u32) -> Result<(usize, u8), String> {
        self.lambda_entries
            .get(&index)
            .map(|entry| {
                crate::native_helpers::register_native_fun_owner(entry);
                (Arc::as_ptr(entry) as usize, entry.arity)
            })
            .ok_or_else(|| format!("lambda {index} has no loaded fun entry"))
    }

    fn record_runtime(&self) -> arinsal_beamasm::records::RecordRuntime {
        arinsal_beamasm::records::RecordRuntime {
            get_field: crate::native_records::arinsal_beamasm_get_record_field,
            get_local_field: crate::native_records::arinsal_beamasm_get_local_record_field,
            create_local: crate::native_records::arinsal_beamasm_create_local_record,
            create: crate::native_records::arinsal_beamasm_create_record,
            get_elements: crate::native_records::arinsal_beamasm_get_record_elements,
            update: crate::native_records::arinsal_beamasm_update_record,
        }
    }

    fn retain_fun_helper(&self) -> usize {
        crate::native_helpers::arinsal_beamasm_retain_fun_owner as *const () as usize
    }

    fn raise_class_helper(&self) -> usize {
        crate::native_helpers::arinsal_beamasm_raise_class as *const () as usize
    }

    fn local_node_helper(&self) -> usize {
        crate::native_helpers::arinsal_beamasm_local_node as *const () as usize
    }

    fn build_stacktrace_helper(&self) -> Option<arinsal_beamasm::catch::BuildStacktraceHook> {
        Some(crate::native_helpers::arinsal_beamasm_build_stacktrace)
    }

    fn process_dictionary_get_helper(&self) -> usize {
        crate::native_helpers::arinsal_beamasm_process_dictionary_get as *const () as usize
    }

    fn native_body(&self, name: &str, arity: u8) -> Option<(usize, usize)> {
        self.native_bodies.get(&(name.to_owned(), arity)).copied()
    }

    fn dynamic_nif_body(&self, name: &str, arity: u8) -> Option<(usize, usize)> {
        let identity = *self
            .dynamic_nifs
            .borrow_mut()
            .entry((name.to_owned(), arity))
            .or_insert_with(|| {
                crate::native_helpers::reserve_nif_slot(
                    self.module_name.clone(),
                    name.to_owned(),
                    arity,
                )
            });
        Some((
            identity,
            crate::native_helpers::arinsal_beamasm_static_nif as *const () as usize,
        ))
    }

    fn publish_lambda_target(
        &self,
        _beam: &BeamFile,
        index: u32,
        target: usize,
    ) -> Result<(), String> {
        let entry = self
            .lambda_entries
            .get(&index)
            .ok_or_else(|| format!("lambda {index} has no loaded fun entry"))?;
        entry.set_dispatch_target(0, target);
        Ok(())
    }

    fn export_trampoline(&self) -> usize {
        self.export_trampoline
    }

    fn light_bif_fragment(&self) -> usize {
        self.light_bif_fragment
    }
    fn send_fragment(&self) -> usize {
        self.send_fragment
    }

    fn arithmetic_helper(&self) -> ArithHelper {
        crate::arinsal_beamasm_arith
    }
    fn guard_helper(&self) -> GuardHelper {
        crate::arinsal_beamasm_guard
    }
    fn guard_helper3(&self) -> GuardHelper3 {
        crate::arinsal_beamasm_guard3
    }
    fn gc_hook(&self) -> GcHook {
        crate::native_helpers::arinsal_beamasm_gc_sync
    }
    fn map_lookup_helper(&self) -> MapLookupHelper {
        crate::arinsal_beamasm_map_lookup
    }
    fn bif_mfa_helper(&self) -> BifMfaHelper {
        crate::arinsal_beamasm_bif_mfa
    }

    fn bif_mfa_entry(&self, module: &str, function: &str, arity: u8) -> Result<usize, String> {
        bif_mfa_entry(module, function, arity)
            .ok_or_else(|| format!("no BIF dispatch slot for {module}:{function}/{arity}"))
    }
    fn bs_match_helper(&self) -> arinsal_beamasm::bs_match::BsMatchHelper {
        crate::native_helpers::arinsal_beamasm_bs_match
    }
    fn map_runtime(&self) -> arinsal_beamasm::map::MapRuntime {
        arinsal_beamasm::map::MapRuntime {
            get: crate::native_helpers::arinsal_beamasm_map_get,
            get_elements: crate::native_helpers::arinsal_beamasm_map_get_elements,
            new_map: crate::native_helpers::arinsal_beamasm_map_new,
            update_assoc: crate::native_helpers::arinsal_beamasm_map_assoc,
            update_exact: crate::native_helpers::arinsal_beamasm_map_exact,
        }
    }
    fn bif_identity_helper(&self) -> arinsal_beamasm::bif::BifIdentityHelper {
        crate::native_helpers::arinsal_beamasm_bif_by_identity
    }
    fn plain_bif_identity(&self, _beam: &BeamFile, index: u32) -> Option<usize> {
        let identity = *self.export_entries.get(index as usize)?;
        dispatch_bif(identity).is_some().then_some(identity)
    }
    fn bs_match_cmd_helper(&self) -> arinsal_beamasm::bs_match::BsMatchCmdHelper {
        crate::native_helpers::arinsal_beamasm_bs_match_command
    }
    fn bs_create_bin_helper(&self) -> arinsal_beamasm::bs_construct::BsCreateBinHelper {
        crate::native_helpers::arinsal_beamasm_bs_create_bin
    }
    fn binary_literal(&self, bytes: &[u8]) -> Result<u64, String> {
        let mut heap = self.literal_heap.borrow_mut();
        TermBuilder::new(&mut **heap)
            .bitstring(bytes, bytes.len() * 8)
            .map(raw_word)
            .map_err(|error| format!("binary literal: {error:?}"))
    }
    fn exception_resolver(&self) -> arinsal_beamasm::catch::ExceptionResolver {
        crate::native_helpers::arinsal_beamasm_exception_resolver
    }
    fn fun_resolver(&self) -> arinsal_beamasm::fun::FunResolver {
        crate::native_helpers::arinsal_beamasm_fun_resolver
    }
    fn add_stacktrace_helper(&self) -> arinsal_beamasm::catch::AddStacktraceHook {
        crate::native_helpers::arinsal_beamasm_add_stacktrace
    }
    fn big_to_float_helper(&self) -> arinsal_beamasm::float::BigToFloat {
        crate::native_helpers::arinsal_beamasm_big_to_float
    }
    fn bs_init_writable_helper(&self) -> arinsal_beamasm::bs_construct::BsInitWritableHelper {
        crate::native_helpers::arinsal_beamasm_bs_init_writable
    }
    fn receive_hooks(&self) -> arinsal_beamasm::receive::ReceiveHooks {
        use crate::native_helpers as h;
        arinsal_beamasm::receive::ReceiveHooks {
            recv_marker_reserve: h::arinsal_beamasm_recv_marker_reserve,
            recv_marker_bind: h::arinsal_beamasm_recv_marker_bind,
            recv_marker_clear: h::arinsal_beamasm_recv_marker_clear,
            recv_marker_use: h::arinsal_beamasm_recv_marker_use,
            loop_rec: h::arinsal_beamasm_loop_rec,
            remove_message: h::arinsal_beamasm_remove_message,
            set_save_next: h::arinsal_beamasm_set_save_next,
            wait_unlocked: h::arinsal_beamasm_wait,
            wait_locked: h::arinsal_beamasm_wait,
            take_receive_lock: h::arinsal_beamasm_take_receive_lock,
            wait_timeout: h::arinsal_beamasm_wait_timeout,
            timeout_locked: h::arinsal_beamasm_timeout,
            timeout: h::arinsal_beamasm_timeout,
        }
    }
    fn apply_runtime(&self) -> arinsal_beamasm::misc::ApplyRuntime {
        let fragments = fragments();
        arinsal_beamasm::misc::ApplyRuntime {
            resolver: crate::native_helpers::arinsal_beamasm_apply_resolver,
            apply2_fragment: fragments.map_or(0, DispatchFragments::apply2_unported),
            apply3_fragment: fragments.map_or(0, DispatchFragments::apply3_unported),
        }
    }
}

/// Compile a module and retain both its executable mapping and embedded literals.
pub(crate) fn compile(
    bytes: &[u8],
    module: &arinsal_loader::Module,
    scope: u64,
    line_breakpoints: bool,
) -> Option<Arc<CompiledVersion>> {
    if !enabled() {
        return None;
    }
    if let Ok(allowlist) = std::env::var("ARINSAL_BEAMASM_MODULES")
        && !allowlist
            .split(',')
            .map(str::trim)
            .any(|name| name == module.name)
    {
        return None;
    }
    if std::env::var("ARINSAL_BEAMASM_SKIP")
        .ok()
        .is_some_and(|skip| skip.split(',').any(|name| name == module.name))
    {
        return None;
    }
    if lifetime_trace_enabled() {
        eprintln!(
            "[beamasm-lifetime] compile module={} module_ptr={:p}",
            module.name, module
        );
    }
    let function_allowlist = std::env::var("ARINSAL_BEAMASM_FUNCS").ok();
    let beam = arinsal_beam::parse(bytes).ok()?;
    let fragments = fragments()?;
    let export_entries = import_entries(scope, module)?;
    // Literals no loaded instruction uses; a literal heap so literal checks see them as such.
    let mut literal_heap = Box::new(VecHeap::new_literal());
    let env = VmModuleEnv::new(&beam, module, &mut literal_heap, export_entries, fragments).ok()?;
    let trace = crate::calls::trace_boot_enabled();
    if trace {
        eprintln!("arinsal boot: beamasm compiling {}", beam.module);
    }
    let compiled = match compile_parsed_module_with_options(
        &beam,
        &env,
        function_allowlist.as_deref(),
        line_breakpoints,
    ) {
        Ok(compiled) => compiled,
        Err(error) => {
            eprintln!(
                "arinsal boot: beamasm compile failed for {}: {error:?}",
                beam.module
            );
            return None;
        }
    };
    let runtime_functions = compiled
        .functions
        .iter()
        .filter(|function| !is_loader_native_body(module, function))
        .collect::<Vec<_>>();
    if let Some(directory) = std::env::var_os("ARINSAL_BEAMASM_DUMP")
        && let Err(error) = arinsal_beamasm::write_global_note(std::path::Path::new(&directory))
    {
        eprintln!("arinsal beamasm dump: could not write global.asm: {error}");
    }
    if trace {
        eprintln!(
            "arinsal boot: beamasm compiled {} native={} unported={}",
            compiled.name,
            runtime_functions.len(),
            compiled.unported.len()
        );
        for function in &runtime_functions {
            eprintln!(
                "arinsal boot: beamasm native function {}/{}",
                function.name, function.arity
            );
        }
        for function in &compiled.unported {
            eprintln!(
                "arinsal boot: beamasm unported function {}/{}: {} ({:?})",
                function.name,
                function.arity,
                function.missing_ops.join(","),
                function.reason
            );
        }
    }
    // Fun entries whose dispatch this version may publish; purging the version resets them.
    let lambda_entries = env.lambda_entries.values().cloned().collect::<Vec<_>>();
    let reserved = env.dynamic_nifs.take();
    let nif_patches = compiled
        .native
        .nif_patches
        .iter()
        .filter_map(|(&label, &offset)| {
            let function = compiled
                .functions
                .iter()
                .find(|function| function.label == label)?;
            let identity = *reserved.get(&(function.name.clone(), function.arity))?;
            Some((function.name.clone(), function.arity, identity, offset))
        })
        .collect::<Vec<_>>();
    let unused = reserved
        .values()
        .copied()
        .filter(|identity| !nif_patches.iter().any(|patch| patch.2 == *identity))
        .collect::<Vec<_>>();
    crate::native_helpers::release_nif_slots(unused);
    drop(env);
    MODULES.fetch_add(1, Ordering::Relaxed);
    NATIVE.fetch_add(runtime_functions.len() as u64, Ordering::Relaxed);
    UNPORTED.fetch_add(compiled.unported.len() as u64, Ordering::Relaxed);
    // Loader-patched NIF bodies stay out of the export targets (exports run them through the
    // interpreter's NativeBody), but native local calls still enter their compiled code, so
    // their ranges must be registered for return addresses, yields and stack walks.
    let mut function_starts = compiled
        .functions
        .iter()
        .filter_map(|function| compiled.native.entries.get(&function.label))
        .map(|entry| *entry as usize + arinsal_beamasm::module::FUNC_INFO_BYTES)
        .collect::<Vec<_>>();
    function_starts.sort_unstable();
    let code_start = compiled.native.memory.as_ptr() as usize;
    let Some(code_end) = compiled
        .native
        .memory
        .blocks()
        .iter()
        .filter_map(|block| block.offset.checked_add(block.size))
        .chain([compiled.native.memory.used()])
        .max()
        .and_then(|end| code_start.checked_add(end))
    else {
        if lifetime_trace_enabled() {
            eprintln!(
                "[beamasm-lifetime] CodeMemory drop module={} range={:#x}..unknown reason=invalid code block",
                compiled.name, code_start
            );
        }
        return None;
    };
    if lifetime_trace_enabled() {
        eprintln!(
            "[beamasm-lifetime] CodeMemory alloc module={} range={:#x}..{:#x}",
            compiled.name, code_start, code_end
        );
    }
    let native_targets = runtime_functions
        .iter()
        .filter_map(|function| {
            // Port of erts/emulator/beam/jit/asm_load.c:185-192, OTP-29.1.1.
            // BIF exports retain their `call_bif` dispatch address.
            if arinsal_spec::bif_lookup(&compiled.name, &function.name, function.arity).is_some() {
                return None;
            }
            module.export_slot(&function.name, function.arity)?;
            compiled.native.entries.get(&function.label).map(|entry| {
                (
                    (compiled.name.clone(), function.name.clone(), function.arity),
                    *entry as usize + arinsal_beamasm::module::FUNC_INFO_BYTES,
                )
            })
        })
        .collect::<Vec<_>>();
    let mut native_functions = Vec::with_capacity(compiled.functions.len());
    for function in &compiled.functions {
        let Some(start) = compiled
            .native
            .entries
            .get(&function.label)
            .map(|entry| *entry as usize + arinsal_beamasm::module::FUNC_INFO_BYTES)
        else {
            if lifetime_trace_enabled() {
                eprintln!(
                    "[beamasm-lifetime] CodeMemory drop module={} range={:#x}..{:#x} reason=missing entry {}:{}",
                    compiled.name, code_start, code_end, function.name, function.arity
                );
            }
            return None;
        };
        let end = function_starts
            .iter()
            .copied()
            .find(|entry| *entry > start)
            .unwrap_or(code_end);
        native_functions.push(crate::NativeFunction {
            scope,
            start,
            end,
            module: compiled.name.clone(),
            module_atom: global_atoms().get(&compiled.name)?,
            function: function.name.clone(),
            function_atom: global_atoms().get(&function.name)?,
            arity: function.arity,
            line: None,
            file: None,
            // A `line` instruction before the function's `func_info` still names its first
            // instructions, so the nearest preceding entry belongs to the function.
            line_table: {
                let mut entries = compiled
                    .native
                    .line_table
                    .iter()
                    .map(|entry| (code_start + entry.offset, entry))
                    .collect::<Vec<_>>();
                entries.sort_by_key(|(address, _)| *address);
                let before = entries.partition_point(|(address, _)| *address <= start);
                let first = before.saturating_sub(1);
                entries
                    .into_iter()
                    .skip(first)
                    .take_while(|(address, _)| *address < end)
                    .map(|(address, entry)| crate::NativeLine {
                        address: address.max(start),
                        file: Arc::from(entry.file.as_str()),
                        file_term: module.line_file_terms.get(&entry.file).copied(),
                        // Port of erts/emulator/beam/beam_code.h:32-38 (MAKE_LOCATION),
                        // OTP-29.1.1: a line that does not fit in 24 bits has no location.
                        line: if u64::from(entry.line) < (1 << 24) - 1 {
                            entry.line
                        } else {
                            0
                        },
                    })
                    .collect()
            },
            file_term: None,
        });
    }
    if lifetime_trace_enabled() {
        eprintln!(
            "[beamasm-lifetime] compiled module={} range={:#x}..{:#x} native={}",
            compiled.name,
            code_start,
            code_end,
            native_functions.len()
        );
    }
    let trace_breakpoints = compiled
        .native
        .trace_breakpoints
        .iter()
        .filter_map(|(&label, &(offset, branch))| {
            compiled
                .functions
                .iter()
                .find(|function| function.label == label)
                .map(|function| {
                    (
                        (compiled.name.clone(), function.name.clone(), function.arity),
                        offset,
                        branch,
                    )
                })
        })
        .collect();
    let catch_ids = crate::native_bridge::register_native_catches(
        compiled.native.catch_base,
        &compiled.native.catch_table,
    );
    let version = Arc::new(CompiledVersion {
        module: compiled.name.clone(),
        scope,
        memory: std::sync::Mutex::new(compiled.native.memory),
        trace_breakpoints,
        line_breakpoints: compiled.native.line_breakpoints.clone(),
        line_breakpoint_returns: compiled
            .native
            .line_breakpoint_returns
            .iter()
            .map(|(resume, site)| (code_start + resume, code_start + site))
            .collect(),
        nif_patches,
        literal_heap: Some(literal_heap),
        _module_literals: module.literal_area(),
        native_functions,
        native_targets,
        code_start,
        code_end,
        catch_ids,
        lambda_entries,
    });
    for function in &version.native_functions {
        if crate::register_native_function(function.clone()).is_err() {
            return None;
        }
    }
    version.publish(module);
    if let Ok(mut versions) = compiled_versions().write() {
        versions.retain(|version| version.strong_count() != 0);
        versions.push(Arc::downgrade(&version));
    }
    Some(version)
}

// Port of erts/emulator/beam/jit/arm/asm_load.c:651, OTP-29.1.1.
fn is_loader_native_body(
    module: &arinsal_loader::Module,
    function: &arinsal_beamjit::CompiledFunction,
) -> bool {
    module
        .functions
        .iter()
        .find(|(_, name, arity)| name == &function.name && *arity == function.arity)
        .and_then(|(entry, _, _)| module.code.get(entry.saturating_add(1)))
        .is_some_and(|instruction| matches!(instruction, arinsal_loader::Instr::NativeBody { .. }))
}

fn raw_word(term: Term) -> u64 {
    term.tagged_word()
}

pub(crate) fn count_native_call() {
    NATIVE_CALLS.fetch_add(1, Ordering::Relaxed);
}
/// Counts an interpreter slice; `at_native_entry` marks one that started at a function entry
/// which has native code (a process that erts would have started natively).
pub(crate) fn count_interp_slice(at_native_entry: bool) {
    INTERP_SLICES.fetch_add(1, Ordering::Relaxed);
    if at_native_entry {
        INTERP_NATIVE_STARTS.fetch_add(1, Ordering::Relaxed);
    }
}

/// Interpreter slices that began at a function entry with native code.
pub fn interp_native_starts() -> u64 {
    INTERP_NATIVE_STARTS.load(Ordering::Relaxed)
}

/// Interpreter slices run so far.
pub fn interp_slices() -> u64 {
    INTERP_SLICES.load(Ordering::Relaxed)
}

pub(crate) fn count_native_yield() {
    NATIVE_YIELDS.fetch_add(1, Ordering::Relaxed);
}
pub(crate) fn count_call_unported() {
    CALL_UNPORTED.fetch_add(1, Ordering::Relaxed);
}

pub(crate) fn print_stats() {
    if std::env::var_os("ARINSAL_BEAMASM_STATS").as_deref() != Some(std::ffi::OsStr::new("1"))
        || PRINTED.swap(true, Ordering::Relaxed)
    {
        return;
    }
    eprintln!(
        "ARINSAL_BEAMASM_STATS modules={} native_functions={} unported_functions={} native_calls={} interp_slices={} interp_native_starts={} native_yields={} call_unported={}",
        MODULES.load(Ordering::Relaxed),
        NATIVE.load(Ordering::Relaxed),
        UNPORTED.load(Ordering::Relaxed),
        NATIVE_CALLS.load(Ordering::Relaxed),
        INTERP_SLICES.load(Ordering::Relaxed),
        INTERP_NATIVE_STARTS.load(Ordering::Relaxed),
        NATIVE_YIELDS.load(Ordering::Relaxed),
        CALL_UNPORTED.load(Ordering::Relaxed)
    );
}

#[cfg(test)]
mod selection_tests {
    use super::beamasm_enabled;
    use std::ffi::OsString;

    #[test]
    fn beamasm_is_the_default_and_interpreter_flags_override_it() {
        assert!(beamasm_enabled(None, None));
        assert!(beamasm_enabled(None, Some(OsString::from("1"))));
        assert!(!beamasm_enabled(Some(OsString::from("1")), None));
        assert!(!beamasm_enabled(None, Some(OsString::from("0"))));
        assert!(!beamasm_enabled(
            Some(OsString::from("1")),
            Some(OsString::from("1"))
        ));
    }
}
