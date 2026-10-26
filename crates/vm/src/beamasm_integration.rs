//! Loading and registration for the incremental BeamAsm compiler.
use arinsal_beam::BeamFile;
use arinsal_beamasm::{
    arith::ArithHelper,
    construct::GcHook,
    dispatch::CompareHelpers,
    dispatch::DispatchFragments,
    guard::{CompareShared, GuardHelper, GuardHelper3},
};
use arinsal_beamjit::{
    BifMfaHelper, MapLookupHelper, ModuleEnv, compile_parsed_module_with_options,
};
use arinsal_term::{Term, TermBuilder, VecHeap, from_owned, global_atoms};
use num_bigint::BigInt;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{OnceLock, RwLock, Weak};

// Port of erts/emulator/beam/export.c:59-72 (export_hash, export_cmp), OTP-29.1.1: exports
// are keyed by their module and function atoms.
type Mfa = (arinsal_term::Atom, arinsal_term::Atom, u8);

/// The export key of `module:function/arity`; `None` when either name is not an atom yet,
/// so no export can have it.
fn existing_mfa(module: &str, function: &str, arity: u8) -> Option<Mfa> {
    let atoms = global_atoms();
    Some((atoms.get(module)?, atoms.get(function)?, arity))
}

/// The export key of `module:function/arity`, interning its names.
fn interned_mfa(module: &str, function: &str, arity: u8) -> Option<Mfa> {
    let atoms = global_atoms();
    Some((
        atoms.intern(module).ok()?,
        atoms.intern(function).ok()?,
        arity,
    ))
}

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
            let mut natives =
                crate::native_bridge::native_functions_of(self.scope, &module.name, range);
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

/// A BIF whose hot path is the scheduler-local counter in `erl_bif_unique.c`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SchedulerCounterBif {
    /// `erlang:make_ref/0`.
    MakeRef,
    /// `erlang:unique_integer/0`.
    Unique0,
    /// `erlang:unique_integer/1`.
    Unique1,
}

#[derive(Clone)]
pub(crate) struct DispatchTarget {
    /// The node's export entry; export funs of this MFA hold it too (`Export.lambda`).
    slot: &'static Arc<arinsal_beamasm::bif::ExportEntry>,
    /// Code scope whose code indexes select the slot's address; zero for scope-free slots.
    scope: u64,
    pub module: String,
    pub function: String,
    pub module_atom: arinsal_term::Atom,
    pub function_atom: arinsal_term::Atom,
    pub arity: u8,
    pub bif: Option<arinsal_bifs::BifFn>,
    pub class: arinsal_loader::ImportClass,
    pub native_bits: usize,
    /// The BIF has a continuation entry in `bif_traps`; others skip that table on every call.
    pub trap_entry: bool,
    /// The MFA is a light (not heap) BIF in the BIF table (erts `Export.bif_number` with the
    /// light-BIF kind), looked up once at intern.
    pub light_kind: bool,
    /// `lists:keyfind/3`, `member/2`, `++` and `--`. Set once at intern so the
    /// light-BIF path does not compare the MFA strings on every call. The scan
    /// still runs as the plain BIF; trap state is built only when its counter
    /// runs out.
    pub list_slice: bool,
    /// Runs the BIF inside native code, without a trap back into the executor.
    /// ETS uses this, and so do `erlang:put/2` and `erlang:erase/1`: those are
    /// heap BIFs in erts (`call_ext`), and trapping once per key dominated the
    /// dictionary benchmark.
    pub direct_ets: Option<crate::natives::ets::DirectEts>,
    /// The BIF a light BIF call runs straight away: set when it neither traps nor runs in
    /// the executor nor on the table fast path, so the call checks one word.
    pub light_bif: Option<arinsal_bifs::BifFn>,
    /// `make_ref/0` or `unique_integer/0,1`, which bump the scheduler's own counter.
    pub scheduler_counter: Option<SchedulerCounterBif>,
    /// The process BIF a light BIF call runs straight away, for a native that needs only its
    /// process (see `natives::ProcessBif`); the executor still runs it for interpreted code.
    pub light_process_bif: Option<crate::natives::ProcessBif>,
    /// The trapping BIF a light BIF call runs straight away; it leaves native code only when
    /// it traps (see `bif_traps::call_light`).
    pub(crate) light_trap_bif: Option<&'static crate::bif_traps::Entry>,
}

/// Whether `module:function/arity` is a light BIF of the BIF table.
fn light_kind(module: &str, function: &str, arity: u8) -> bool {
    arinsal_spec::bif_lookup(module, function, arity)
        .is_some_and(|bif| bif.kind != arinsal_spec::BifKind::Hbif)
}

impl DispatchTarget {
    pub(crate) fn export_entry(&self) -> &'static arinsal_beamasm::bif::ExportEntry {
        self.slot
    }

    /// Trapping BIFs keep continuation state that only the executor's call site handles.
    pub(crate) fn runs_in_executor(&self) -> bool {
        matches!(
            self.class,
            arinsal_loader::ImportClass::Native
                | arinsal_loader::ImportClass::Dynamic
                | arinsal_loader::ImportClass::Fun
        ) || self.trap_entry
    }
}

// Port of erts/emulator/beam/export.c:73-98 (export_init), OTP-29.1.1.
// The entry is never freed: it lives as long as the export table, like erts' export entries.
fn new_export_slot(
    mfa: Mfa,
    address: usize,
    save_calls: usize,
) -> &'static Arc<arinsal_beamasm::bif::ExportEntry> {
    Box::leak(Box::new(Arc::new(
        arinsal_beamasm::bif::ExportEntry::with_addresses(mfa.0, mfa.1, mfa.2, address, save_calls),
    )))
}

/// One node's export state, like an erts code index: import slots, interpreted and native
/// export targets and global call breakpoints.
#[derive(Default)]
struct ScopeExports {
    // One slot per MFA, shared by every import and export in this code scope.
    dispatch: HashMap<Mfa, Arc<DispatchTarget>, ExportHasher>,
    target_indices: HashMap<Mfa, usize, ExportHasher>,
    native_targets: HashMap<Mfa, usize, ExportHasher>,
    // Exports with a global call breakpoint: their callers go through the export
    // trampoline, whose interpreted export entry is the breakpoint.
    global_breakpoints: std::collections::HashSet<Mfa, ExportHasher>,
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
    scopes: HashMap<u64, ScopeExports, IdentityHasher>,
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
            leaked.list_slice = matches!(
                (
                    leaked.module.as_str(),
                    leaked.function.as_str(),
                    leaked.arity
                ),
                ("lists", "keyfind" | "keymember" | "keysearch", 3)
                    | ("lists", "member", 2)
                    | ("erlang", "++" | "append" | "--" | "subtract", 2)
            );
            leaked.light_bif = leaked
                .bif
                .filter(|_| leaked.direct_ets.is_none() && !leaked.runs_in_executor());
            leaked.scheduler_counter = match (
                leaked.module.as_str(),
                leaked.function.as_str(),
                leaked.arity,
            ) {
                ("erlang", "make_ref", 0) => Some(SchedulerCounterBif::MakeRef),
                ("erlang", "unique_integer", 0) => Some(SchedulerCounterBif::Unique0),
                ("erlang", "unique_integer", 1) => Some(SchedulerCounterBif::Unique1),
                _ => None,
            };
            // Port of erts/emulator/beam/jit/arm/instr_bif.cpp:378-471 (call_light_bif_shared),
            // OTP-29.1.1: erts calls every BIF from the generated code with `c_p`, so a native
            // that needs only its process is called the same way.
            leaked.light_process_bif = if leaked.class == arinsal_loader::ImportClass::Native
                && !leaked.trap_entry
                && leaked.direct_ets.is_none()
            {
                crate::natives::process_bif(&leaked.module, &leaked.function, leaked.arity)
            } else {
                None
            };
            // Port of erts/emulator/beam/jit/arm/instr_bif.cpp:378-540 (call_light_bif_shared),
            // OTP-29.1.1: a trapping BIF is a BIF like any other at its call site.
            leaked.light_trap_bif = if leaked.trap_entry
                && leaked.direct_ets.is_none()
                && !matches!(
                    leaked.class,
                    arinsal_loader::ImportClass::Dynamic | arinsal_loader::ImportClass::Fun
                ) {
                crate::bif_traps::light_entry(&leaked.module, &leaked.function, leaked.arity)
            } else {
                None
            };
            let target: &'static DispatchTarget = Box::leak(Box::new(leaked));
            // Port of erts/emulator/beam/export.h:38-58 (Export), OTP-29.1.1: the slot holds
            // its descriptor's address, which generated code passes to the runtime helpers
            // as a typed reference, like erts passes the Export* itself.
            target
                .slot
                .set_info(std::ptr::from_ref::<DispatchTarget>(target) as usize);
            // Port of erts/emulator/beam/erl_bif_table.c (`bif_table[].f`), OTP-29.1.1:
            // every BIF's export is published with the function `call_light_bif_shared`
            // branches to. The choice is made once, here, not by the call fragment.
            if let Some(func) = crate::native_helpers::light_entry(target) {
                target.slot.set_light_bif_func(func);
            }
            target
        })
    }
}

fn dispatch_registry() -> &'static RwLock<DispatchRegistry> {
    static REGISTRY: OnceLock<RwLock<DispatchRegistry>> = OnceLock::new();
    REGISTRY.get_or_init(|| RwLock::new(DispatchRegistry::default()))
}

// Port of erts/emulator/beam/export.c:59-98 (MFA-keyed export lookup and initialization), OTP-29.1.1.
fn dispatch_entry(
    scope: u64,
    key: Mfa,
    create: impl FnOnce() -> Option<DispatchTarget>,
) -> Option<&'static DispatchTarget> {
    let mut registry = dispatch_registry().write().ok()?;
    let existing = registry
        .scopes
        .get(&scope)
        .and_then(|exports| exports.dispatch.get(&key))
        .cloned();
    let entry = match existing {
        Some(entry) => entry,
        None => {
            let entry = Arc::new(create()?);
            registry
                .scopes
                .entry(scope)
                .or_default()
                .dispatch
                .insert(key, Arc::clone(&entry));
            entry
        }
    };
    let identity = Arc::as_ptr(entry.slot) as usize;
    Some(registry.intern_identity(identity, &entry))
}

/// Allocates the code scope of a new node.
pub(crate) fn new_code_scope() -> u64 {
    // The fun dispatch fragments must exist before the node creates fun entries.
    let _ = fragments();
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
        for entry in exports.dispatch.values() {
            registry
                .by_identity
                .remove(&(Arc::as_ptr(entry.slot) as usize));
        }
    }
}

fn fragments() -> Option<&'static DispatchFragments> {
    static FRAGMENTS: OnceLock<Option<DispatchFragments>> = OnceLock::new();
    FRAGMENTS
        .get_or_init(|| {
            let fragments = DispatchFragments::with_line_breakpoint_helpers(
                arinsal_beamasm::dispatch::DispatchRuntimeHelpers {
                    export: crate::native_helpers::arinsal_beamasm_export_trampoline as *const ()
                        as usize,
                    light_bif: crate::native_helpers::arinsal_beamasm_call_light_bif_shared
                        as *const () as usize,
                    light_bif_gc: crate::native_helpers::arinsal_beamasm_light_bif_gc as *const ()
                        as usize,
                    light_gc: light_gc_offsets(),
                    exception_resolver: crate::native_helpers::arinsal_beamasm_exception_resolver
                        as *const () as usize,
                    save_calls_export: crate::native_helpers::arinsal_beamasm_save_calls_export
                        as *const () as usize,
                    unloaded_fun: crate::native_helpers::arinsal_beamasm_fun_resolver as *const ()
                        as usize,
                    save_calls_fun: crate::fun_dispatch::arinsal_beamasm_save_calls_fun as *const ()
                        as usize,
                    compare: CompareHelpers {
                        eq: crate::native_hooks::arinsal_eq as *const () as usize,
                        cmp_atoms: crate::native_hooks::arinsal_cmp_atoms as *const () as usize,
                        cmp_compound: crate::native_hooks::arinsal_cmp_compound as *const ()
                            as usize,
                    },
                    line_breakpoint: arinsal_beamasm::dispatch::LineBreakpointHelpers {
                        garbage_collect: crate::native_helpers::arinsal_beamasm_gc_sync as *const ()
                            as usize,
                        prepare_call: crate::native_helpers::arinsal_beamasm_line_breakpoint_prepare
                            as *const () as usize,
                        cleanup: crate::native_helpers::arinsal_beamasm_line_breakpoint_cleanup
                            as *const () as usize,
                    },
                    apply3_resolver: crate::native_helpers::arinsal_beamasm_apply3_resolver
                        as *const () as usize,
                },
            )
            .ok()?;
            crate::fun_dispatch::init(fragments.unloaded_fun(), fragments.save_calls_fun());
            if let Some((start, end)) = fragments.run_process() {
                // The beam_run_process stub is a code range of its own (no module), so
                // `enter_native_function` finds its arity: apply/3 takes three arguments.
                // The stub has no module or function name, and erts creates no atom for it: the
                // atom fields name an existing atom, so registration interns nothing at boot.
                let names = arinsal_term::global_atoms();
                let module = "$beam_run_process";
                let undefined = names.get("undefined").expect("predefined atom");
                let info = crate::NativeFunction {
                    scope: 0,
                    start,
                    end,
                    module: module.to_owned(),
                    module_atom: undefined,
                    function: module.to_owned(),
                    function_atom: undefined,
                    arity: 3,
                    line: None,
                    file: None,
                    file_term: None,
                    line_table: Vec::new(),
                };
                crate::register_native_function(info).expect("register run-process stub");
            }
            Some(fragments)
        })
        .as_ref()
}

/// The beam_run_process stub, `(start, end)`, when native code is in use.
pub(crate) fn run_process_entry() -> Option<(usize, usize)> {
    fragments().and_then(DispatchFragments::run_process)
}

/// The unresolved or interpreted export entry used to distinguish an export table stub from
/// a published native target.
pub(crate) fn export_trampoline() -> usize {
    fragments().map_or(0, DispatchFragments::export_trampoline)
}

fn yield_fragments() -> Option<&'static arinsal_beamasm::yield_frag::YieldFragments> {
    static FRAGMENTS: OnceLock<Option<arinsal_beamasm::yield_frag::YieldFragments>> =
        OnceLock::new();
    FRAGMENTS
        .get_or_init(|| arinsal_beamasm::yield_frag::YieldFragments::new().ok())
        .as_ref()
}

fn raise_fragments() -> Option<&'static arinsal_beamasm::raise_frag::RaiseFragments> {
    static FRAGMENTS: OnceLock<Option<arinsal_beamasm::raise_frag::RaiseFragments>> =
        OnceLock::new();
    FRAGMENTS
        .get_or_init(|| {
            arinsal_beamasm::raise_frag::RaiseFragments::new(
                crate::native_helpers::arinsal_beamasm_exception_resolver as *const () as usize,
                crate::native_helpers::arinsal_beamasm_raise_class as *const () as usize,
            )
            .ok()
        })
        .as_ref()
}

fn receive_fragments() -> Option<&'static arinsal_beamasm::receive_frag::ReceiveFragments> {
    static FRAGMENTS: OnceLock<Option<arinsal_beamasm::receive_frag::ReceiveFragments>> =
        OnceLock::new();
    FRAGMENTS
        .get_or_init(|| {
            arinsal_beamasm::receive_frag::ReceiveFragments::new(
                crate::native_helpers::arinsal_beamasm_loop_rec,
                crate::native_helpers::arinsal_beamasm_wait,
                crate::native_helpers::arinsal_beamasm_wait,
                yield_fragments()?.context_switch(),
                Some(arinsal_beamasm::receive_frag::InlinePeek {
                    save_term_offset: u32::try_from(
                        std::mem::offset_of!(crate::Process, inbox)
                            + crate::process::MessageQueue::SAVE_TERM_OFFSET,
                    )
                    .ok()?,
                    delay_gc_offset: u16::try_from(std::mem::offset_of!(crate::Process, delay_gc))
                        .ok()?,
                }),
            )
            .ok()
        })
        .as_ref()
}

fn map_fragments() -> Option<&'static arinsal_beamasm::map::MapFragments> {
    static FRAGMENTS: OnceLock<Option<arinsal_beamasm::map::MapFragments>> = OnceLock::new();
    FRAGMENTS
        .get_or_init(|| {
            arinsal_beamasm::map::MapFragments::with_helpers(
                crate::native_helpers::arinsal_beamasm_map_get,
                crate::native_helpers::arinsal_beamasm_map_update_single,
                crate::native_helpers::arinsal_beamasm_map_put_single,
                crate::native_helpers::arinsal_beamasm_map_assoc,
                crate::native_helpers::arinsal_beamasm_map_exact,
            )
            .ok()
        })
        .as_ref()
}

/// The export entry of `mfa` in `scope`, creating a stub entry (entering the export
/// trampoline) when the scope has none. Export funs point at it.
// Port of erts/emulator/beam/export.c:200-245 (erts_export_get_or_make_stub), OTP-29.1.1.
pub(crate) fn export_get_or_make_stub(
    scope: u64,
    mfa: Mfa,
) -> Option<Arc<arinsal_beamasm::bif::ExportEntry>> {
    if let Ok(registry) = dispatch_registry().read()
        && let Some(entry) = registry
            .scopes
            .get(&scope)
            .and_then(|exports| exports.dispatch.get(&mfa))
    {
        return Some(Arc::clone(entry.slot));
    }
    let trampoline = fragments()?.export_trampoline();
    let save_calls = fragments()?.save_calls_export();
    let module = global_atoms().text(mfa.0)?.to_string();
    let function = global_atoms().text(mfa.1)?.to_string();
    let entry = dispatch_entry(scope, mfa, || {
        let bif = arinsal_bifs::lookup(&module, &function, mfa.2);
        let (class, bits) = crate::natives::classify(&module, &function, mfa.2, bif.is_some());
        Some(DispatchTarget {
            // Port of erts/emulator/beam/export.c:73-98 (export_init), OTP-29.1.1.
            slot: new_export_slot(mfa, trampoline, save_calls),
            scope,
            trap_entry: crate::bif_traps::traps(&module, &function, mfa.2),
            light_kind: light_kind(&module, &function, mfa.2),
            list_slice: false,
            direct_ets: crate::natives::ets::direct_entry(&module, &function, mfa.2)
                .or_else(|| crate::natives::proc::direct_dictionary(&module, &function, mfa.2)),
            module: module.clone(),
            function: function.clone(),
            module_atom: mfa.0,
            function_atom: mfa.1,
            arity: mfa.2,
            bif,
            class,
            native_bits: bits,
            light_bif: None,
            scheduler_counter: None,
            light_process_bif: None,
            light_trap_bif: None,
        })
    })?;
    crate::code_ix::for_scope(scope).update_active(|tables| {
        tables.exports.bind_dispatch(mfa, entry.export_entry());
    });
    Some(Arc::clone(entry.slot))
}

/// Export descriptor returned by the native line-breakpoint prepare helper.
// Port of erts/emulator/beam/beam_bp.c:1828-1830
// (erts_line_breakpoint_hit__prepare_call), OTP-29.1.1.
pub(crate) fn line_breakpoint_export(
    scope: u64,
    code_ix: usize,
) -> Option<&'static arinsal_beamasm::bif::ExportEntry> {
    let atoms = arinsal_term::global_atoms();
    let mfa = (
        atoms.intern("erts_internal").ok()?,
        atoms.intern("breakpoint").ok()?,
        4,
    );
    crate::code_ix::for_scope(scope)
        .with_tables_for_code_ix(code_ix, |tables| tables.exports.dispatch(mfa))
        .flatten()
}

fn import_entries(scope: u64, module: &arinsal_loader::Module) -> Option<Vec<usize>> {
    let trampoline = fragments()?.export_trampoline();
    let save_calls = fragments()?.save_calls_export();
    let mut identities = Vec::with_capacity(module.imports.len());
    let mut bindings = Vec::with_capacity(module.imports.len());
    for import in &module.imports {
        let mfa = (import.module_atom, import.function_atom, import.arity);
        let entry = dispatch_entry(scope, mfa, || {
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
            Some(DispatchTarget {
                // Port of erts/emulator/beam/export.c:73-98 (export_init), OTP-29.1.1.
                slot: new_export_slot(mfa, trampoline, save_calls),
                scope,
                trap_entry: crate::bif_traps::traps(&import.module, &import.function, import.arity),
                light_kind: light_kind(&import.module, &import.function, import.arity),
                list_slice: false,
                direct_ets: crate::natives::ets::direct_entry(
                    &import.module,
                    &import.function,
                    import.arity,
                )
                .or_else(|| {
                    crate::natives::proc::direct_dictionary(
                        &import.module,
                        &import.function,
                        import.arity,
                    )
                }),
                module: import.module.clone(),
                function: import.function.clone(),
                module_atom: import.module_atom,
                function_atom: import.function_atom,
                arity: import.arity,
                bif: import.bif_fn(),
                class,
                native_bits: bits,
                light_bif: None,
                scheduler_counter: None,
                light_process_bif: None,
                light_trap_bif: None,
            })
        })?;
        bindings.push((mfa, entry.export_entry()));
        identities.push(Arc::as_ptr(entry.slot) as usize);
    }
    // Port of erts/emulator/beam/jit/asm_load.c (beam_load_finalize_code): the exports of all
    // imports are put into the staged export table together, under one code-index update.
    crate::code_ix::for_scope(scope).update_active(|tables| {
        for (mfa, dispatch) in &bindings {
            tables.exports.bind_dispatch(*mfa, dispatch);
        }
    });
    Some(identities)
}

/// Returns the dispatch slot that runs the BIF `module:function/arity` from its stub body.
fn bif_mfa_entry(module: &str, function: &str, arity: u8) -> Option<usize> {
    let trampoline = fragments()?.export_trampoline();
    let save_calls = fragments()?.save_calls_export();
    let mut registry = dispatch_registry().write().ok()?;
    let module_atom = global_atoms().get(module)?;
    let function_atom = global_atoms().get(function)?;
    let key = (module_atom, function_atom, arity);
    let entry = Arc::clone(registry.bif_mfas.entry(key).or_insert_with(|| {
        let bif = arinsal_bifs::lookup(module, function, arity);
        let (class, bits) = crate::natives::classify(module, function, arity, bif.is_some());
        Arc::new(DispatchTarget {
            slot: new_export_slot(key, trampoline, save_calls),
            scope: 0,
            trap_entry: crate::bif_traps::traps(module, function, arity),
            light_kind: light_kind(module, function, arity),
            list_slice: false,
            direct_ets: crate::natives::ets::direct_entry(module, function, arity)
                .or_else(|| crate::natives::proc::direct_dictionary(module, function, arity)),
            module: module.to_owned(),
            function: function.to_owned(),
            module_atom,
            function_atom,
            arity,
            bif,
            class,
            native_bits: bits,
            light_bif: None,
            scheduler_counter: None,
            light_process_bif: None,
            light_trap_bif: None,
        })
    }));
    let identity = Arc::as_ptr(entry.slot) as usize;
    registry.intern_identity(identity, &entry);
    Some(identity)
}

// Port of erts/emulator/beam/export.c:154-180 (find an export) and erts_export_put, OTP-29.1.1.
fn publish_module(scope: u64, module: &arinsal_loader::Module, native: &[(Mfa, usize)]) {
    let trampoline = fragments().map_or(0, DispatchFragments::export_trampoline);
    let save_calls = fragments().map_or(0, DispatchFragments::save_calls_export);
    let mut dispatch_entries = Vec::with_capacity(module.exports.len());
    for export in &module.exports {
        let Ok(function_atom) = global_atoms().intern(&export.function) else {
            continue;
        };
        let mfa = (module.name_atom, function_atom, export.arity);
        let bif = arinsal_bifs::lookup(&module.name, &export.function, export.arity);
        let (class, bits) =
            crate::natives::classify(&module.name, &export.function, export.arity, bif.is_some());
        let target = dispatch_entry(scope, mfa, || {
            Some(DispatchTarget {
                // Port of erts/emulator/beam/export.c:73-98 (export_init), OTP-29.1.1.
                slot: new_export_slot(mfa, trampoline, save_calls),
                scope,
                trap_entry: crate::bif_traps::traps(&module.name, &export.function, export.arity),
                light_kind: light_kind(&module.name, &export.function, export.arity),
                list_slice: false,
                direct_ets: crate::natives::ets::direct_entry(
                    &module.name,
                    &export.function,
                    export.arity,
                )
                .or_else(|| {
                    crate::natives::proc::direct_dictionary(
                        &module.name,
                        &export.function,
                        export.arity,
                    )
                }),
                module: module.name.clone(),
                function: export.function.clone(),
                module_atom: module.name_atom,
                function_atom,
                arity: export.arity,
                bif,
                class,
                native_bits: bits,
                light_bif: None,
                scheduler_counter: None,
                light_process_bif: None,
                light_trap_bif: None,
            })
        });
        if let Some(target) = target {
            dispatch_entries.push((mfa, target));
        }
    }
    crate::code_ix::for_scope(scope).update_active(|tables| {
        for (mfa, target) in &dispatch_entries {
            tables.exports.bind_dispatch(*mfa, target.export_entry());
        }
    });
    staged(scope, |exports| {
        publish_module_exports(exports, module, native)
    });
}

fn publish_module_exports(
    exports: &mut ScopeExports,
    module: &arinsal_loader::Module,
    native: &[(Mfa, usize)],
) -> Vec<Mfa> {
    let name = module.name_atom;
    let mut affected = Vec::new();
    exports
        .target_indices
        .retain(|(module, function, arity), _| {
            if *module == name {
                affected.push((*module, *function, *arity));
                false
            } else {
                true
            }
        });
    exports
        .native_targets
        .retain(|(module, function, arity), _| {
            if *module == name {
                affected.push((*module, *function, *arity));
                false
            } else {
                true
            }
        });
    for export in &module.exports {
        let Ok(function) = global_atoms().intern(&export.function) else {
            continue;
        };
        let mfa = (name, function, export.arity);
        exports.target_indices.insert(mfa, export.target());
        affected.push(mfa);
    }
    for (mfa, address) in native {
        exports.native_targets.insert(*mfa, *address);
        affected.push(*mfa);
    }
    affected
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
    for entry in exports.dispatch.values() {
        entry.slot.stage(active, staging);
    }
}

/// Applies `change` to the exports of `scope` in the staging code index. Outside a load's
/// staging area the change is staged and committed on its own, like the code changes erts
/// makes under the code modification permission (delete_module, trace patterns).
/// Native address of an export in `scope` (erts `ep->dispatch.addresses[code_ix]`).
pub(crate) fn export_native_target(
    scope: u64,
    module: arinsal_term::Atom,
    function: arinsal_term::Atom,
    arity: u8,
) -> Option<usize> {
    let registry = dispatch_registry().read().ok()?;
    registry
        .scopes
        .get(&scope)?
        .native_targets
        .get(&(module, function, arity))
        .copied()
}

fn staged(scope: u64, change: impl FnOnce(&mut ScopeExports) -> Vec<Mfa>) {
    let code_ix = crate::code_ix::for_scope(scope);
    let staging = code_ix.start_staging();
    let Ok(mut registry) = dispatch_registry().write() else {
        return;
    };
    let exports = registry.scopes.entry(scope).or_default();
    let affected = change(exports);
    refresh_import_slots(exports, staging.ix(), &affected);
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
    let Some(name) = global_atoms().get(name) else {
        return;
    };
    staged(scope, |exports| {
        let mut affected = Vec::new();
        exports
            .target_indices
            .retain(|(module, function, arity), _| {
                if *module == name {
                    affected.push((*module, *function, *arity));
                    false
                } else {
                    true
                }
            });
        exports
            .native_targets
            .retain(|(module, function, arity), _| {
                if *module == name {
                    affected.push((*module, *function, *arity));
                    false
                } else {
                    true
                }
            });
        affected
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
        let mut affected = Vec::new();
        for (mfa, address) in native {
            if exports.native_targets.get(mfa) == Some(address) {
                exports.native_targets.remove(mfa);
                affected.push(*mfa);
            }
        }
        affected
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

/// Writes the address of import slots that call an MFA in `affected` into code index `ix`.
///
/// `stage_dispatch` has already copied every slot from the active index, so an export
/// whose address did not change keeps that copy. erts updates the one `Export` callers
/// share (`export.c`); each call site here has its own slot, and only those sites change.
fn refresh_import_slots(exports: &ScopeExports, ix: usize, affected: &[Mfa]) {
    let trampoline = fragments().map_or(0, DispatchFragments::export_trampoline);
    for mfa in affected {
        let Some(entry) = exports.dispatch.get(mfa) else {
            continue;
        };
        entry
            .slot
            .set_address(ix, import_slot_address(exports, mfa, trampoline));
    }
}

/// The address a process saving calls continues with after recording the call of the export
/// with `identity`: the export's address in its node's active code index.
// Port of erts/emulator/beam/jit/arm/instr_call.cpp:141-147 (emit_dispatch_save_calls_export:
// "Keep going with the actual code index"), OTP-29.1.1.
pub(crate) fn save_calls_continuation(export: Option<ExportDispatch>) -> usize {
    export.map_or_else(
        || fragments().map_or(0, DispatchFragments::export_trampoline),
        |target| {
            let active = crate::code_ix::for_scope(target.scope).active();
            target.slot.address(active)
        },
    )
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
    for exports in registry.scopes.values() {
        if let Some(target) = exports.dispatch.get(&mfa) {
            target.slot.set_bif_traced(traced);
        }
    }
    if let Some(target) = registry.bif_mfas.get(&mfa) {
        target.slot.set_bif_traced(traced);
    }
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
    bif_traced: bool,
) {
    let Some(mfa) = interned_mfa(module, function, arity) else {
        return;
    };
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
            exports.global_breakpoints.insert(mfa);
        } else {
            exports.global_breakpoints.remove(&mfa);
        }
        if let Some(target) = exports.dispatch.get(&mfa) {
            // Port of erts/emulator/beam/beam_bp.c:374 (ep->is_bif_traced), OTP-29.1.1: any
            // session's local or global trace of a BIF sends its callers through the trace path.
            target.slot.set_bif_traced(bif_traced);
        }
        set_target(exports);
        vec![mfa]
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

/// `Export.info` as the light-BIF fragment loaded it.
///
/// Port of erts/emulator/beam/jit/arm/instr_bif.cpp:434-445, OTP-29.1.1: the call
/// site already holds the `Export*`, and `info` is the descriptor published at
/// intern. The callee does not look the export up.
pub(crate) fn export_from_info(info: u64) -> Option<ExportDispatch> {
    if info == 0 {
        return None;
    }
    // SAFETY: `intern_identity` leaks this `DispatchTarget` and stores its
    // address in `Export.info` before any generated call can run. The export
    // table never frees it.
    Some(unsafe { &*(info as *const DispatchTarget) })
}

/// Shared fragment that exits native code so the scheduler can interpret a fun call.
pub(crate) fn call_fun_unported_entry() -> usize {
    fragments().map_or(0, DispatchFragments::call_fun_unported)
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
        .get(&existing_mfa(module, function, arity)?)
        .copied()
}

static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
static MODULES: AtomicU64 = AtomicU64::new(0);
static NATIVE: AtomicU64 = AtomicU64::new(0);
static NATIVE_CALLS: AtomicU64 = AtomicU64::new(0);
static INTERP_SLICES: AtomicU64 = AtomicU64::new(0);
static INTERP_NATIVE_STARTS: AtomicU64 = AtomicU64::new(0);
static NATIVE_YIELDS: AtomicU64 = AtomicU64::new(0);
static CALL_UNPORTED: AtomicU64 = AtomicU64::new(0);
static PRINTED: AtomicBool = AtomicBool::new(false);
static NEXT_MODULE_HANDLE: AtomicU64 = AtomicU64::new(1);
static MODULE_HANDLES: OnceLock<RwLock<HashMap<u64, Weak<CompiledVersion>>>> = OnceLock::new();

fn module_handles() -> &'static RwLock<HashMap<u64, Weak<CompiledVersion>>> {
    MODULE_HANDLES.get_or_init(|| RwLock::new(HashMap::new()))
}

/// Resolves native code identity to the version-specific tables retained with its code header.
// Port of erts/emulator/beam/jit/asm_load.c:1025-1026 and jit/asm_load.c:1149-1155,
// OTP-29.1.1: emitted code is tied to its prepared BeamCodeHeader, not a code-table slot.
pub(crate) fn map_lookup_version(handle: u64) -> Option<Arc<CompiledVersion>> {
    let mut handles = module_handles().write().ok()?;
    let version = handles.get(&handle).and_then(Weak::upgrade);
    if version.is_none() {
        handles.remove(&handle);
    }
    version
}

fn lifetime_trace_enabled() -> bool {
    crate::native_bridge::lifetime_trace_enabled()
}

/// Owns a compiled module version and the heap that backs its embedded literals.
pub(crate) struct CompiledVersion {
    module: String,
    /// Functions of the module BeamAsm could not compile: they run in the interpreter.
    scope: u64,
    module_handle: u64,
    installed: AtomicBool,
    pub(crate) map_lookups: Box<[arinsal_beamasm::map::MapLookupTable]>,
    memory: std::sync::Mutex<arinsal_a64::exec::CodeMemory>,
    trace_breakpoints: Vec<((String, String, u8), usize, u32)>,
    // Line breakpoint patch sites: source line, branch word offset, original branch.
    line_breakpoints: Vec<(u32, usize, u32)>,
    // Return addresses of enabled line-breakpoint hits, ascending.
    line_breakpoint_returns: Vec<(usize, usize)>,
    // Function, arity, call-NIF site (an index into `nif_sites`) and the patch word that
    // enables its body.
    nif_patches: Vec<(String, u8, usize, usize)>,
    // Every call-NIF site compiled into this version's code, which refers to their addresses;
    // each site is boxed so its address stays put.
    #[allow(clippy::vec_box)]
    nif_sites: Vec<Box<crate::native_helpers::NativeNifSite>>,
    literal_heap: std::sync::Mutex<Option<Arc<VecHeap>>>,
    // The module's literal area, which native code refers to directly.
    _module_literals: arinsal_loader::LiteralArea,
    // Coverage pointers embedded in native code remain valid through the code version's lifetime.
    _coverage: Option<arinsal_loader::Coverage>,
    native_functions: Vec<crate::NativeFunction>,
    native_targets: Vec<(Mfa, usize)>,
    code_start: usize,
    code_end: usize,
    catch_base: u32,
    catch_table: Vec<usize>,
    catch_ids: std::sync::Mutex<Vec<u32>>,
    lambda_entries: Vec<Arc<arinsal_term::FunEntry>>,
    lambda_targets: Vec<(Arc<arinsal_term::FunEntry>, usize)>,
}

/// Enable or remove native entry breakpoints for traced functions of one module.
// Port of erts/emulator/beam/jit/arm/beam_asm_module.cpp:231-250, OTP-29.1.1.
// Batched per module: a per-function call rescanned every version's breakpoint table, which made
// a `{'_','_','_'}` trace pattern quadratic in the loaded code.
pub(crate) fn patch_native_breakpoints(scope: u64, module: &str, wanted: &[(&str, u8, bool)]) {
    if wanted.is_empty() {
        return;
    }
    let Ok(versions) = compiled_versions().read() else {
        return;
    };
    let wanted = wanted
        .iter()
        .map(|&(function, arity, enabled)| ((function, arity), enabled))
        .collect::<HashMap<_, _>>();
    for version in versions
        .iter()
        .filter_map(Weak::upgrade)
        .filter(|version| version.scope == scope && version.module == module)
    {
        let Ok(mut memory) = version.memory.lock() else {
            continue;
        };
        for ((owner, name, found_arity), offset, branch) in &version.trace_breakpoints {
            if owner != module {
                continue;
            }
            let Some(&enabled) = wanted.get(&(name.as_str(), *found_arity)) else {
                continue;
            };
            let instruction = if enabled { 0xd503_201f_u32 } else { *branch };
            let _ = memory.write_bytes(*offset, &instruction.to_le_bytes());
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

/// Whether `address` is OTP's shared line-breakpoint cleanup continuation.
// Port of erts/emulator/beam/erl_process.c:14945-14946 and
// erts/emulator/beam/jit/arm/beam_asm_module.cpp:312-322, OTP-29.1.1.
pub(crate) fn is_line_breakpoint_cleanup(address: usize) -> bool {
    fragments().is_some_and(|fragments| fragments.line_breakpoint_cleanup() == address)
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
    /// Whether `address` lies in this version's generated code.
    pub(crate) fn contains_code(&self, address: usize) -> bool {
        (self.code_start..self.code_end).contains(&address)
    }

    pub(crate) fn native_function_start(&self, function: &str, arity: u8) -> Option<usize> {
        self.native_functions
            .iter()
            .find(|native| native.function == function && native.arity == arity)
            .map(|native| native.start)
    }

    /// Resolves a native PC to its function in this compiled module version.
    // Port of erts/emulator/beam/beam_ranges.c:245-289 (erts_lookup_function_info), OTP-29.1.1.
    pub(crate) fn native_function_for_pc(&self, pc: usize) -> Option<&crate::NativeFunction> {
        let index = self
            .native_functions
            .partition_point(|function| function.start <= pc);
        self.native_functions
            .get(index.checked_sub(1)?)
            .filter(|function| pc < function.end)
    }

    fn nif_patch(&self, function: &str, arity: u8) -> Option<(usize, usize)> {
        self.nif_patches
            .iter()
            .find(|(name, found, _, _)| name == function && *found == arity)
            .map(|(_, _, site, offset)| (*site, *offset))
    }

    /// Writes the `call_nif` operands of `function/arity`, loaded by `load_nif`, into its
    /// call-NIF site.
    // Port of erts/emulator/beam/erl_nif.c:5149-5160 (load_nif_1st_finisher), OTP-29.1.1.
    pub(crate) fn bind_nif(
        &self,
        function: &str,
        arity: u8,
        native: crate::natives::nif::NativeFn,
    ) -> bool {
        self.nif_patch(function, arity)
            .and_then(|(site, _)| self.nif_sites.get(site))
            .is_some_and(|site| site.bind(native))
    }

    /// Makes native entries of `function/arity` run their bound NIF.
    // Port of erts/emulator/beam/erl_nif.c:5248-5250 (load_nif_2nd_finisher removes the
    // call_nif_early breakpoint), OTP-29.1.1.
    pub(crate) fn enable_nif(&self, function: &str, arity: u8) -> bool {
        let Some((_, offset)) = self.nif_patch(function, arity) else {
            return false;
        };
        let Ok(mut memory) = self.memory.lock() else {
            return false;
        };
        memory
            .write_bytes(offset, &0xd503_201f_u32.to_le_bytes())
            .is_ok()
    }

    // Port of erts/emulator/beam/beam_load.c:258 and jit/asm_load.c:1149-1218, OTP-29.1.1.
    pub(crate) fn install(self: &Arc<Self>, module: &arinsal_loader::Module) -> bool {
        if !self.native_functions.is_empty()
            && crate::native_bridge::register_native_module(
                &self.native_functions,
                self.code_start,
                self.code_end,
            )
            .is_err()
        {
            return false;
        }
        let catch_ids = crate::native_bridge::register_native_catches(
            self.scope,
            self.catch_base,
            &self
                .catch_table
                .iter()
                .map(|address| *address as *const u8)
                .collect::<Vec<_>>(),
        );
        *self.catch_ids.lock().unwrap() = catch_ids;
        let code_index = crate::code_ix::for_scope(self.scope).staging();
        for (entry, target) in &self.lambda_targets {
            entry.set_fun_code(code_index, *target);
        }
        if let Ok(mut versions) = compiled_versions().write() {
            versions.retain(|version| version.strong_count() != 0);
            versions.push(Arc::downgrade(self));
        }
        if let Ok(mut handles) = module_handles().write() {
            handles.retain(|_, version| version.strong_count() != 0);
            handles.insert(self.module_handle, Arc::downgrade(self));
        }
        self.installed.store(true, Ordering::Release);
        publish_module(self.scope, module, &self.native_targets);
        true
    }
    /// Sends native callers of this version's exports to the export trampoline and queues the
    /// version's literals for release. Run when the version is freed explicitly (purge
    /// `complete`, a load that reclaims it), never from drop: the code is gone at that point
    /// whatever else still holds this value, like the explicit free of the old code header in
    /// erts.
    // Port of erts/emulator/beam/beam_bif_load.c (erts_internal_purge_module_2 complete:
    // erts_queue_release_literals after the code is freed), OTP-29.1.1.
    pub(crate) fn unpublish(&self) {
        unpublish_module(self.scope, &self.native_targets);
        self.retire_literals();
    }

    fn retire_literals(&self) {
        let heap = self
            .literal_heap
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some(heap) = heap {
            // Port of erts/emulator/beam/beam_bif_load.c:2341
            // (erts_queue_release_literals), OTP-29.1.1: purged code literals
            // are copied out by the same collector as interpreter literals.
            if lifetime_trace_enabled() {
                eprintln!(
                    "[beamasm-lifetime] retire literal heap module={} words={}",
                    self.module,
                    heap.used_words()
                );
            }
            arinsal_pterm::store_for(self.scope).retire_module_area(heap);
        }
    }
    /// The half-open address range of this version's native code.
    pub(crate) fn code_range(&self) -> (usize, usize) {
        (self.code_start, self.code_end)
    }
}

impl Drop for CompiledVersion {
    fn drop(&mut self) {
        // Port of erts/emulator/beam/beam_bif_load.c (purge: fun entries of the purged code
        // dispatch to the unloaded-fun handler), OTP-29.1.1: a cleared slot sends the call
        // to the call_fun resolver, which raises through the error handler.
        // Port of erts/emulator/beam/erl_fun.c:157-179 (fun_purge_foreach: entries of the
        // purged code enter beam_unloaded_fun), OTP-29.1.1.
        let unloaded = arinsal_term::beam_unloaded_fun();
        for entry in &self.lambda_entries {
            for ix in 0..arinsal_term::ERTS_NUM_CODE_IX {
                let target = entry.dispatch_target.address(ix);
                if self.code_start <= target && target < self.code_end {
                    // set_fun_code refuses a pending purge (erl_fun.c erts_set_fun_code).
                    // fun_purge_foreach already stored the old address in the marker and
                    // unloaded one index; the other indexes may still enter this area.
                    if entry
                        .pend_purge_address
                        .load(std::sync::atomic::Ordering::Acquire)
                        == 0
                    {
                        entry.set_fun_code(ix, unloaded);
                    } else {
                        entry.dispatch_target.set_address(ix, unloaded);
                    }
                }
            }
        }
        if self.installed.load(Ordering::Acquire) {
            self.retire_literals();
        }
        if self.installed.load(Ordering::Acquire) && !self.native_functions.is_empty() {
            crate::native_bridge::unregister_native_module(
                &self.native_functions,
                self.code_start,
                self.code_end,
                self.scope,
            );
        }
        crate::native_bridge::unregister_native_catches(
            self.scope,
            &self
                .catch_ids
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );
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
        // `-emu_flavor emu` is the start flag; `ARINSAL_INTERP=1` is an alias of it.
        let flavor_emu = arinsal_args::active_emulator_flags().interpreter;
        let enabled = !flavor_emu
            && beamasm_enabled(
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
    dynamic_integer_literals: std::cell::RefCell<HashMap<BigInt, u64>>,
    literals: Vec<u64>,
    /// The literals the load added after those of the file, by literal index.
    added_literals: std::cell::RefCell<HashMap<u32, u64>>,
    zero_capture_funs: HashMap<u32, u64>,
    lambda_entries: HashMap<u32, Arc<arinsal_term::FunEntry>>,
    export_entries: Vec<usize>,
    export_trampoline: usize,
    light_bif_fragment: usize,
    light_bif_helper_fragment: usize,
    breakpoint_fragment: usize,
    line_breakpoint_fragment: usize,
    send_fragment: usize,
    native_bodies: HashMap<(String, u8), (usize, usize)>,
    module_name: String,
    functions: Vec<(String, u8)>,
    coverage: Option<arinsal_loader::Coverage>,
    module_handle: u64,
    lambda_targets: std::cell::RefCell<HashMap<u32, usize>>,
    // Call-NIF sites of functions a later load_nif may replace.
    dynamic_nifs:
        std::cell::RefCell<HashMap<(String, u8), Box<crate::native_helpers::NativeNifSite>>>,
    _lifetime: std::marker::PhantomData<&'a BeamFile>,
}

impl<'a> VmModuleEnv<'a> {
    fn new(
        beam: &'a BeamFile,
        module: &arinsal_loader::Module,
        literal_heap: &'a mut VecHeap,
        export_entries: Vec<usize>,
        fragments: &DispatchFragments,
        module_handle: u64,
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
                .local_fun(&slot.entry, &[])
                .map_err(|error| format!("zero-capture fun {}: {error:?}", lambda.index))?;
            zero_capture_funs.insert(lambda.index, raw_word(term));
        }
        // Port of erts/emulator/beam/jit/arm/asm_load.c:651, OTP-29.1.1: loader-patched static
        // NIF bodies call their Rust body through the shared runtime helper.
        let mut native_bodies = HashMap::new();
        for (ordinal, (_, function, arity)) in module.functions.iter().enumerate() {
            if module.nif_body(ordinal).is_none() {
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
            dynamic_integer_literals: std::cell::RefCell::new(HashMap::new()),
            literals,
            added_literals: std::cell::RefCell::new(HashMap::new()),
            zero_capture_funs,
            lambda_entries,
            export_entries,
            export_trampoline: fragments.export_trampoline(),
            light_bif_fragment: fragments.call_light_bif(),
            light_bif_helper_fragment: fragments.call_light_bif_helper(),
            breakpoint_fragment: fragments.breakpoint(),
            line_breakpoint_fragment: fragments.line_breakpoint(),
            send_fragment: fragments.send(),
            native_bodies,
            module_name: module.name.clone(),
            functions: module
                .functions
                .iter()
                .map(|(_, function, arity)| (function.clone(), *arity))
                .collect(),
            coverage: module.coverage.clone(),
            module_handle,
            lambda_targets: std::cell::RefCell::new(HashMap::new()),
            dynamic_nifs: std::cell::RefCell::new(HashMap::new()),
            _lifetime: std::marker::PhantomData,
        })
    }
}

impl VmModuleEnv<'_> {
    // Port of erts/emulator/beam/beam_file.c (beamfile_add_literal), OTP-29.1.1.
    fn intern_dynamic_integer_literal(&self, value: BigInt) -> Result<u64, String> {
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
}

impl ModuleEnv for VmModuleEnv<'_> {
    fn function_coverage_probe(
        &self,
        function: &str,
        arity: u8,
    ) -> Option<arinsal_beamjit::CoverageProbe> {
        let coverage = self.coverage.as_ref()?;
        if !matches!(
            coverage.mode,
            arinsal_loader::CoverageMode::Function | arinsal_loader::CoverageMode::FunctionCounters
        ) {
            return None;
        }
        let owner = self
            .functions
            .iter()
            .position(|(name, found_arity)| name == function && *found_arity == arity)?;
        let index = coverage
            .function_owners
            .iter()
            .position(|owner_index| *owner_index as usize == owner)?;
        Some(arinsal_beamjit::CoverageProbe {
            address: coverage.probe_address(index)?,
            flags: coverage.stores_flags(),
        })
    }

    fn line_coverage_probe(
        &self,
        location: u32,
        cover_id: u32,
    ) -> Option<arinsal_beamjit::CoverageProbe> {
        let coverage = self.coverage.as_ref()?;
        if !matches!(
            coverage.mode,
            arinsal_loader::CoverageMode::Line | arinsal_loader::CoverageMode::LineCounters
        ) {
            return None;
        }
        let index = coverage.line_probe_mappings.iter().find_map(
            |(found_location, found_cover_id, counter)| {
                (*found_location == location && *found_cover_id == cover_id)
                    .then_some(*counter as usize)
            },
        )?;
        Some(arinsal_beamjit::CoverageProbe {
            address: coverage.probe_address(index)?,
            flags: coverage.stores_flags(),
        })
    }

    fn integer_literal(&self, value: i64) -> Result<u64, String> {
        self.intern_dynamic_integer_literal(BigInt::from(value))
    }

    fn match_string(&self, bytes: &[u8]) -> Result<u64, String> {
        Ok(crate::native_helpers::register_match_string(bytes))
    }

    fn bigint_literal(&self, decimal: &str) -> Result<u64, String> {
        let value = decimal
            .parse::<num_bigint::BigInt>()
            .map_err(|error| format!("bignum literal: {error}"))?;
        self.intern_dynamic_integer_literal(value)
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

    fn map_key_hash(&self, key: arinsal_beamasm::module::ArgVal) -> u64 {
        match key {
            arinsal_beamasm::module::ArgVal::Immediate(word)
            | arinsal_beamasm::module::ArgVal::Literal(word) => {
                arinsal_term::internal_hash(crate::native_hooks::from_raw(word))
            }
            _ => 0,
        }
    }

    fn atom(&self, _beam: &BeamFile, index: u32) -> Result<u64, String> {
        // The atoms of the transformed code are global atom indexes.
        let atom = arinsal_term::Atom(index);
        global_atoms()
            .text(atom)
            .ok_or_else(|| format!("atom index {index} is out of range"))?;
        Ok(raw_word(Term::atom(atom)))
    }

    fn add_literal(&self, index: u32, word: u64) -> Result<(), String> {
        self.added_literals.borrow_mut().insert(index, word);
        Ok(())
    }

    fn literal(&self, _beam: &BeamFile, index: u32) -> Result<u64, String> {
        if let Some(word) = self.added_literals.borrow().get(&index) {
            return Ok(*word);
        }
        self.literals
            .get(index as usize)
            .copied()
            .ok_or_else(|| format!("literal index {index} is out of range"))
    }

    fn zero_capture_fun(&self, _beam: &BeamFile, lambda: u32) -> Result<u64, String> {
        self.zero_capture_funs
            .get(&lambda)
            .copied()
            .ok_or_else(|| format!("lambda {lambda} has no fun without free variables"))
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
            .map(|entry| (Arc::as_ptr(entry) as usize, entry.arity))
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

    fn raise_class_helper(&self) -> usize {
        crate::native_helpers::arinsal_beamasm_raise_class as *const () as usize
    }

    fn sys_perf_counter(&self) -> usize {
        arinsal_bifs::sys_perf_counter as *const () as usize
    }

    fn this_node_sysname(&self) -> usize {
        std::ptr::from_ref(crate::node_tables::this_node_sysname()) as usize
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
        let mut sites = self.dynamic_nifs.borrow_mut();
        let site = sites.entry((name.to_owned(), arity)).or_insert_with(|| {
            crate::native_helpers::NativeNifSite::new(
                self.module_name.clone(),
                name.to_owned(),
                arity,
            )
        });
        Some((
            std::ptr::from_ref::<crate::native_helpers::NativeNifSite>(site) as usize,
            crate::native_helpers::arinsal_beamasm_call_nif as *const () as usize,
        ))
    }

    fn publish_lambda_target(
        &self,
        _beam: &BeamFile,
        index: u32,
        target: usize,
    ) -> Result<(), String> {
        let _entry = self
            .lambda_entries
            .get(&index)
            .ok_or_else(|| format!("lambda {index} has no loaded fun entry"))?;
        // Port of erts/emulator/beam/erl_fun.c:48-53 (erts_set_fun_code), OTP-29.1.1.
        self.lambda_targets.borrow_mut().insert(index, target);
        Ok(())
    }

    fn export_trampoline(&self) -> usize {
        self.export_trampoline
    }

    fn light_bif_fragment(&self) -> usize {
        self.light_bif_fragment
    }
    fn light_bif_helper_fragment(&self) -> usize {
        self.light_bif_helper_fragment
    }
    // Port of erts/emulator/beam/jit/arm/instr_bif.cpp:595-610 (emit_call_light_bif, the BIF
    // pointer passed in ARG8), OTP-29.1.1.
    fn light_bif_func(&self, entry: usize) -> usize {
        // SAFETY: `entry` is an export slot address taken from `export_entries`. Slots are
        // leaked when created and never freed, like erts' export entries.
        let slot = unsafe { &*(entry as *const arinsal_beamasm::bif::ExportEntry) };
        slot.light_bif_func
            .load(std::sync::atomic::Ordering::Acquire)
    }
    fn breakpoint_fragment(&self) -> usize {
        self.breakpoint_fragment
    }
    fn line_breakpoint_fragment(&self) -> usize {
        self.line_breakpoint_fragment
    }
    fn yield_fragments(&self) -> Option<(usize, usize, usize)> {
        yield_fragments().map(|fragments| {
            (
                fragments.dispatch_return(),
                fragments.i_test_yield_shared(),
                fragments.context_switch(),
            )
        })
    }
    fn raise_fragments(&self) -> Option<(usize, usize)> {
        raise_fragments().map(|fragments| (fragments.raise_shared(), fragments.raise_exception()))
    }
    fn map_error_fragments(&self) -> Option<(usize, usize, usize)> {
        raise_fragments().map(|fragments| {
            (
                fragments.map_get_badmap(),
                fragments.map_get_badkey(),
                fragments.map_size_error(),
            )
        })
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
    fn compare_shared(&self) -> CompareShared {
        let mut shared = fragments().map_or(CompareShared::default(), |fragments| CompareShared {
            eq_exact: fragments.bif_is_eq_exact_shared(),
            ne_exact: fragments.bif_is_ne_exact_shared(),
            arith: fragments.arith_compare_shared(),
            element_guard: fragments.bif_element_guard_shared(),
            eq: 0,
        });
        // The general path of `=:=` / `=/=` calls `eq` directly, with or without fragments.
        shared.eq = crate::native_hooks::arinsal_eq as *const () as usize;
        shared
    }
    fn atom_word_by_name(&self, name: &str) -> Option<u64> {
        global_atoms()
            .intern(name)
            .ok()
            .map(|atom| raw_word(Term::atom(atom)))
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
            lookup_module: self.module_handle,
            new_map: crate::native_helpers::arinsal_beamasm_map_new,
            update_assoc: crate::native_helpers::arinsal_beamasm_map_assoc,
            update_exact: crate::native_helpers::arinsal_beamasm_map_exact,
            put_single: crate::native_helpers::arinsal_beamasm_map_put_single,
            update_single_exact_shared: map_fragments().map_or(
                0,
                arinsal_beamasm::map::MapFragments::update_single_exact_shared,
            ),
            update_single_assoc_shared: map_fragments().map_or(
                0,
                arinsal_beamasm::map::MapFragments::update_single_assoc_shared,
            ),
            update_assoc_shared: map_fragments()
                .map_or(0, arinsal_beamasm::map::MapFragments::update_assoc_shared),
            update_exact_shared: map_fragments()
                .map_or(0, arinsal_beamasm::map::MapFragments::update_exact_shared),
            get_element_shared: map_fragments()
                .map_or(0, arinsal_beamasm::map::MapFragments::get_element_shared),
            get_element_hash_shared: map_fragments().map_or(
                0,
                arinsal_beamasm::map::MapFragments::get_element_hash_shared,
            ),
        }
    }
    fn bif_identity_helper(&self) -> arinsal_beamasm::bif::BifIdentityHelper {
        crate::native_helpers::arinsal_beamasm_bif_by_identity as *const () as usize
    }
    fn plain_bif_identity(&self, _beam: &BeamFile, index: u32) -> Option<usize> {
        let identity = *self.export_entries.get(index as usize)?;
        dispatch_bif(identity).is_some().then_some(identity)
    }
    fn bs_match_cmd_helper(&self) -> arinsal_beamasm::bs_match::BsMatchCmdHelper {
        crate::native_helpers::arinsal_beamasm_bs_match_command
    }
    fn bs_create_bin_helper(&self) -> arinsal_beamasm::bs_construct::BsCreateBinHelper {
        arinsal_beamasm::bs_construct::install_bs_append_binary(
            crate::erl_bits::append_binary as *const () as usize,
        );
        arinsal_beamasm::bs_construct::install_bs_gc(self.gc_hook());
        arinsal_beamasm::bs_construct::install_bs_private_append(
            crate::native_helpers::arinsal_beamasm_bs_private_append_fast as *const () as usize,
            crate::native_helpers::arinsal_beamasm_bs_private_append_checked as *const () as usize,
        );
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
            loop_rec_shared: receive_fragments().map_or(
                0,
                arinsal_beamasm::receive_frag::ReceiveFragments::loop_rec_shared,
            ),
            remove_message: h::arinsal_beamasm_remove_message,
            set_save_next: h::arinsal_beamasm_set_save_next,
            wait_unlocked_shared: receive_fragments().map_or(
                0,
                arinsal_beamasm::receive_frag::ReceiveFragments::wait_unlocked_shared,
            ),
            wait_locked_shared: receive_fragments().map_or(
                0,
                arinsal_beamasm::receive_frag::ReceiveFragments::wait_locked_shared,
            ),
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
            apply3_resolver: crate::native_helpers::arinsal_beamasm_apply3_resolver,
            apply_fun_shared: fragments.map_or(0, DispatchFragments::apply_fun_shared),
            fun_resolver: crate::native_helpers::arinsal_beamasm_fun_resolver,
            apply2_fragment: fragments.map_or(0, DispatchFragments::apply2_unported),
            apply3_fragment: fragments.map_or(0, DispatchFragments::apply3_unported),
        }
    }
}

/// Compile a module and retain both its executable mapping and embedded literals.
// Port of erts/emulator/beam/beam_load.c:125-230 and jit/asm_load.c:947-1155, OTP-29.1.1.
pub(crate) fn compile(
    beam: &arinsal_beam::BeamFile,
    module: &arinsal_loader::Module,
    scope: u64,
    line_breakpoints: bool,
) -> Option<Arc<CompiledVersion>> {
    if !enabled() {
        return None;
    }
    if lifetime_trace_enabled() {
        eprintln!(
            "[beamasm-lifetime] compile module={} module_ptr={:p}",
            module.name, module
        );
    }
    let fragments = fragments()?;
    let export_entries = import_entries(scope, module)?;
    let module_handle = NEXT_MODULE_HANDLE
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |handle| {
            handle.checked_add(1)
        })
        .ok()?;
    // Literals no loaded instruction uses; a literal heap so literal checks see them as such.
    let mut literal_heap = Box::new(VecHeap::new_literal());
    let env = VmModuleEnv::new(
        beam,
        module,
        &mut literal_heap,
        export_entries,
        fragments,
        module_handle,
    )
    .ok()?;
    let trace = crate::calls::trace_boot_enabled();
    if trace {
        eprintln!("arinsal boot: beamasm compiling {}", beam.module);
    }
    let compiled = match compile_parsed_module_with_options(beam, &env, line_breakpoints) {
        Ok(compiled) => compiled,
        Err(error) => {
            eprintln!(
                "arinsal boot: beamasm compile failed for {}: {error:?}",
                beam.module
            );
            return None;
        }
    };
    let native_body_functions = module
        .functions
        .iter()
        .enumerate()
        .filter(|(ordinal, _)| module.nif_body(*ordinal).is_some())
        .map(|(_, (_, name, arity))| (name.as_str(), *arity))
        .collect::<std::collections::HashSet<_>>();
    let runtime_functions = compiled
        .functions
        .iter()
        .filter(|function| {
            !native_body_functions.contains(&(function.name.as_str(), function.arity))
        })
        .collect::<Vec<_>>();
    if let Some(directory) = crate::debug_env::beamasm_dump()
        && let Err(error) = arinsal_beamasm::write_global_note(std::path::Path::new(directory))
    {
        eprintln!("arinsal beamasm dump: could not write global.asm: {error}");
    }
    if trace {
        eprintln!(
            "arinsal boot: beamasm compiled {} native={}",
            compiled.name,
            runtime_functions.len()
        );
        for function in &runtime_functions {
            eprintln!(
                "arinsal boot: beamasm native function {}/{}",
                function.name, function.arity
            );
        }
    }
    // Fun entries whose dispatch this version may publish; purging the version resets them.
    let lambda_entries = env.lambda_entries.values().cloned().collect::<Vec<_>>();
    let lambda_targets = env
        .lambda_targets
        .borrow()
        .iter()
        .filter_map(|(index, target)| {
            env.lambda_entries
                .get(index)
                .cloned()
                .map(|entry| (entry, *target))
        })
        .collect();
    // Every site stays with the code: the code of a function whose compilation failed may
    // still hold the address of its site.
    let mut site_index = HashMap::new();
    let mut nif_sites = Vec::new();
    for (key, site) in env.dynamic_nifs.take() {
        site_index.insert(key, nif_sites.len());
        nif_sites.push(site);
    }
    let nif_patches = compiled
        .native
        .nif_patches
        .iter()
        .filter_map(|(&label, &offset)| {
            let function = compiled
                .functions
                .iter()
                .find(|function| function.label == label)?;
            let site = *site_index.get(&(function.name.clone(), function.arity))?;
            Some((function.name.clone(), function.arity, site, offset))
        })
        .collect::<Vec<_>>();
    drop(env);
    MODULES.fetch_add(1, Ordering::Relaxed);
    NATIVE.fetch_add(runtime_functions.len() as u64, Ordering::Relaxed);
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
            let name = global_atoms().intern(&function.name).ok()?;
            module.export_slot_atom(name, function.arity)?;
            let entry = compiled.native.entries.get(&function.label)?;
            Some((
                (module.name_atom, name, function.arity),
                *entry as usize + arinsal_beamasm::module::FUNC_INFO_BYTES,
            ))
        })
        .collect::<Vec<_>>();
    let mut native_functions = Vec::with_capacity(compiled.functions.len());
    let mut line_entries = compiled
        .native
        .line_table
        .iter()
        .map(|entry| (code_start + entry.offset, entry))
        .collect::<Vec<_>>();
    line_entries.sort_by_key(|(address, _)| *address);
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
            .get(function_starts.partition_point(|entry| *entry <= start))
            .copied()
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
                let before = line_entries.partition_point(|(address, _)| *address <= start);
                let first = before.saturating_sub(1);
                line_entries[first..]
                    .iter()
                    .take_while(|(address, _)| *address < end)
                    .map(|&(address, entry)| crate::NativeLine {
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
    // BeamCodeHeader.functions is ordered by code address for erts_lookup_function_info.
    native_functions.sort_unstable_by_key(|function| function.start);
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
    let version = Arc::new(CompiledVersion {
        module: compiled.name.clone(),
        scope,
        module_handle,
        installed: AtomicBool::new(false),
        map_lookups: compiled.native.map_lookups,
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
        nif_sites,
        literal_heap: std::sync::Mutex::new(Some(Arc::from(literal_heap))),
        _module_literals: module.literal_area(),
        _coverage: module.coverage.clone(),
        native_functions,
        native_targets,
        code_start,
        code_end,
        catch_base: compiled.native.catch_base,
        catch_table: compiled
            .native
            .catch_table
            .iter()
            .map(|address| *address as usize)
            .collect(),
        catch_ids: std::sync::Mutex::new(Vec::new()),
        lambda_entries,
        lambda_targets,
    });
    Some(version)
}

fn raw_word(term: Term) -> u64 {
    term.tagged_word()
}

pub(crate) fn count_native_call() {
    // Debug statistics only: a counter shared by every scheduler thread is a contended
    // cache line on the scheduling path.
    if crate::debug_env::beamasm_stats() {
        NATIVE_CALLS.fetch_add(1, Ordering::Relaxed);
    }
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
    // Debug statistics only: a counter shared by every scheduler thread is a contended
    // cache line on the scheduling path.
    if crate::debug_env::beamasm_stats() {
        NATIVE_YIELDS.fetch_add(1, Ordering::Relaxed);
    }
}
pub(crate) fn count_call_unported() {
    // Debug statistics only: a counter shared by every scheduler thread is a contended
    // cache line on the scheduling path.
    if crate::debug_env::beamasm_stats() {
        CALL_UNPORTED.fetch_add(1, Ordering::Relaxed);
    }
}

pub(crate) fn print_stats() {
    if !crate::debug_env::beamasm_stats() || PRINTED.swap(true, Ordering::Relaxed) {
        return;
    }
    eprintln!(
        "ARINSAL_BEAMASM_STATS modules={} native_functions={} native_calls={} interp_slices={} interp_native_starts={} native_yields={} call_unported={}",
        MODULES.load(Ordering::Relaxed),
        NATIVE.load(Ordering::Relaxed),
        NATIVE_CALLS.load(Ordering::Relaxed),
        INTERP_SLICES.load(Ordering::Relaxed),
        INTERP_NATIVE_STARTS.load(Ordering::Relaxed),
        NATIVE_YIELDS.load(Ordering::Relaxed),
        CALL_UNPORTED.load(Ordering::Relaxed)
    );
}

/// Offsets from `c_p` of the process fields the light-BIF fragment's collection test reads.
// Port of erts/emulator/beam/erl_gc.h:132-139 (ERTS_IS_GC_DESIRED) and
// erts/emulator/beam/jit/arm/instr_bif.cpp:488-523, OTP-29.1.1: the native code reads
// `mbuf_sz`, `bin_vheap_sz`, `off_heap.overhead` and `F_DISABLE_GC` from the process itself.
fn light_gc_offsets() -> arinsal_beamasm::dispatch::LightGcOffsets {
    let heap = std::mem::offset_of!(crate::Process, heap);
    arinsal_beamasm::dispatch::LightGcOffsets {
        fragment_words: (heap + arinsal_term::ProcessHeap::FRAGMENT_WORDS_OFFSET) as u32,
        owners_pointer: (heap + arinsal_term::ProcessHeap::OWNERS_POINTER_OFFSET) as u32,
        off_heap_overhead: arinsal_term::ProcessHeap::OWNERS_OVERHEAD_OFFSET as u32,
        bin_vheap_size: (heap + arinsal_term::ProcessHeap::BIN_VHEAP_SIZE_OFFSET) as u32,
        gc_enabled: (heap + arinsal_term::ProcessHeap::GC_ENABLED_OFFSET) as u32,
    }
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
