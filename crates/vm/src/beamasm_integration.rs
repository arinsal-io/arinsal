//! Loading and registration for the incremental BeamAsm compiler.
use arinsal_beam::BeamFile;
use arinsal_beamasm::{
    arith::ArithHelper,
    construct::GcHook,
    dispatch::DispatchFragments,
    guard::{GuardHelper, GuardHelper3},
};
use arinsal_beamjit::{
    BifMfaHelper, MapLookupHelper, ModuleEnv, compile_module_with_env_and_funcs,
};
use arinsal_term::{Term, TermBuilder, VecHeap, from_owned, global_atoms};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{OnceLock, RwLock, Weak};

type Mfa = (String, String, u8);

/// Function-indexed BeamAsm target cache, invalidated when native code is published.
#[derive(Default)]
pub(crate) struct NativeTargetCache {
    targets: Vec<Vec<Option<crate::NativeFunction>>>,
    generations: Vec<u64>,
}

impl NativeTargetCache {
    pub(crate) fn register_module(&mut self, module_id: usize, module: &arinsal_loader::Module) {
        let targets = vec![None; module.functions.len()];
        if module_id == self.targets.len() {
            self.targets.push(targets);
            self.generations.push(u64::MAX);
        } else if module_id < self.targets.len() {
            self.targets[module_id] = targets;
            self.generations[module_id] = u64::MAX;
        } else {
            self.targets.resize_with(module_id, Vec::new);
            self.targets.push(targets);
            self.generations.resize(module_id, u64::MAX);
            self.generations.push(u64::MAX);
        }
    }

    pub(crate) fn function_for_target(
        &mut self,
        module_id: usize,
        module: &arinsal_loader::Module,
        target: usize,
    ) -> Option<crate::NativeFunction> {
        let index = *module.on_entry_fn.get(target)?;
        if index == u32::MAX {
            return None;
        }
        let index = index as usize;
        let generation = crate::native_bridge::native_registry_generation();
        if self.generations.get(module_id).copied()? != generation {
            let cache = self.targets.get_mut(module_id)?;
            cache.clear();
            cache.extend(module.functions.iter().map(|(_, function, arity)| {
                crate::native_function_for(&module.name, function, *arity)
            }));
            self.generations[module_id] = generation;
        }
        self.targets.get(module_id)?.get(index)?.clone()
    }
}

struct DispatchTarget {
    slot: Arc<arinsal_beamasm::bif::ExportEntry>,
    module: String,
    function: String,
    arity: u8,
    bif: Option<arinsal_bifs::BifFn>,
    class: arinsal_loader::ImportClass,
    native_bits: usize,
}

#[derive(Default)]
struct DispatchRegistry {
    imports: HashMap<(String, u32), Arc<DispatchTarget>>,
    by_identity: HashMap<usize, Arc<DispatchTarget>>,
    target_indices: HashMap<Mfa, usize>,
    native_targets: HashMap<Mfa, usize>,
}

fn dispatch_registry() -> &'static RwLock<DispatchRegistry> {
    static REGISTRY: OnceLock<RwLock<DispatchRegistry>> = OnceLock::new();
    REGISTRY.get_or_init(|| RwLock::new(DispatchRegistry::default()))
}

fn fragments() -> Option<&'static DispatchFragments> {
    static FRAGMENTS: OnceLock<Option<DispatchFragments>> = OnceLock::new();
    FRAGMENTS
        .get_or_init(|| {
            DispatchFragments::new(
                crate::native_helpers::arinsal_beamasm_export_trampoline as *const () as usize,
                crate::native_helpers::arinsal_beamasm_call_light_bif_shared as *const () as usize,
            )
            .ok()
        })
        .as_ref()
}

fn import_entries(module: &arinsal_loader::Module) -> Option<Vec<usize>> {
    let trampoline = fragments()?.export_trampoline();
    let mut registry = dispatch_registry().write().ok()?;
    Some(
        module
            .imports
            .iter()
            .enumerate()
            .map(|(index, import)| {
                let key = (module.name.clone(), index as u32);
                let entry = Arc::clone(registry.imports.entry(key).or_insert_with(|| {
                    Arc::new(DispatchTarget {
                        slot: Arc::new(arinsal_beamasm::bif::ExportEntry::new(trampoline)),
                        module: import.module.clone(),
                        function: import.function.clone(),
                        arity: import.arity,
                        bif: import.bif_fn(),
                        class: import.class(),
                        native_bits: import.native_bits(),
                    })
                }));
                let identity = Arc::as_ptr(&entry.slot) as usize;
                registry.by_identity.insert(identity, Arc::clone(&entry));
                identity
            })
            .collect(),
    )
}

fn publish_module(module: &arinsal_loader::Module, native: &[(Mfa, usize)]) {
    let Ok(mut registry) = dispatch_registry().write() else {
        return;
    };
    registry
        .target_indices
        .retain(|(name, _, _), _| name != &module.name);
    registry
        .native_targets
        .retain(|(name, _, _), _| name != &module.name);
    for export in &module.exports {
        registry.target_indices.insert(
            (module.name.clone(), export.function.clone(), export.arity),
            export.target(),
        );
    }
    for (mfa, address) in native {
        registry.native_targets.insert(mfa.clone(), *address);
    }
    let trampoline = fragments().map_or(0, DispatchFragments::export_trampoline);
    for entry in registry.imports.values() {
        let mfa = (entry.module.clone(), entry.function.clone(), entry.arity);
        let address = registry
            .native_targets
            .get(&mfa)
            .copied()
            .unwrap_or(trampoline);
        entry.slot.update(address);
    }
}

fn unpublish_module(native: &[(Mfa, usize)]) {
    let Ok(mut registry) = dispatch_registry().write() else {
        return;
    };
    for (mfa, address) in native {
        if registry.native_targets.get(mfa) == Some(address) {
            registry.native_targets.remove(mfa);
        }
    }
    let trampoline = fragments().map_or(0, DispatchFragments::export_trampoline);
    for entry in registry.imports.values() {
        let mfa = (entry.module.clone(), entry.function.clone(), entry.arity);
        let address = registry
            .native_targets
            .get(&mfa)
            .copied()
            .unwrap_or(trampoline);
        entry.slot.update(address);
    }
}

/// Descriptor addressed directly by the native export slot.
pub(crate) struct ExportDispatch {
    pub module: String,
    pub function: String,
    pub arity: u8,
    pub class: arinsal_loader::ImportClass,
    pub native_bits: usize,
}

pub(crate) fn export_dispatch(identity: usize) -> Option<ExportDispatch> {
    let registry = dispatch_registry().read().ok()?;
    let target = registry.by_identity.get(&identity)?;
    Some(ExportDispatch {
        module: target.module.clone(),
        function: target.function.clone(),
        arity: target.arity,
        class: target.class,
        native_bits: target.native_bits,
    })
}

/// Returns the published native entry for an MFA, if this module was BeamAsm-compiled.
pub(crate) fn native_target_for(module: &str, function: &str, arity: u8) -> Option<usize> {
    let registry = dispatch_registry().read().ok()?;
    registry
        .native_targets
        .get(&(module.to_owned(), function.to_owned(), arity))
        .copied()
}

/// Shared fragment that exits native code so the scheduler can interpret a fun call.
pub(crate) fn call_fun_unported_entry() -> usize {
    fragments().map_or(0, DispatchFragments::call_fun_unported)
}

pub(crate) fn dispatch_bif(identity: usize) -> Option<(arinsal_bifs::BifFn, u8)> {
    let registry = dispatch_registry().read().ok()?;
    let target = registry.by_identity.get(&identity)?;
    Some((target.bif?, target.arity))
}

pub(crate) fn interpreted_target(module: &str, function: &str, arity: u8) -> Option<usize> {
    dispatch_registry()
        .read()
        .ok()?
        .target_indices
        .get(&(module.to_owned(), function.to_owned(), arity))
        .copied()
}

static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
static MODULES: AtomicU64 = AtomicU64::new(0);
static NATIVE: AtomicU64 = AtomicU64::new(0);
static UNPORTED: AtomicU64 = AtomicU64::new(0);
static NATIVE_CALLS: AtomicU64 = AtomicU64::new(0);
static NATIVE_YIELDS: AtomicU64 = AtomicU64::new(0);
static CALL_UNPORTED: AtomicU64 = AtomicU64::new(0);
static PRINTED: AtomicBool = AtomicBool::new(false);

fn lifetime_trace_enabled() -> bool {
    std::env::var_os("ARINSAL_BEAMASM_LIFETIME").as_deref() == Some(std::ffi::OsStr::new("1"))
}

/// Owns a compiled module version and the heap that backs its embedded literals.
pub(crate) struct CompiledVersion {
    module: String,
    _memory: Box<dyn std::any::Any + Send + Sync>,
    _literal_heap: Box<VecHeap>,
    native_functions: Vec<crate::NativeFunction>,
    native_targets: Vec<(Mfa, usize)>,
    code_start: usize,
    code_end: usize,
}

impl CompiledVersion {
    pub(crate) fn publish(&self, module: &arinsal_loader::Module) {
        publish_module(module, &self.native_targets);
    }
}

impl Drop for CompiledVersion {
    fn drop(&mut self) {
        crate::native_bridge::unregister_native_functions(&self.native_functions);
        unpublish_module(&self.native_targets);
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
        std::env::var_os("ARINSAL_BEAMASM").as_deref() == Some(std::ffi::OsStr::new("1"))
    })
}

struct VmModuleEnv<'a> {
    literals: Vec<u64>,
    zero_capture_funs: HashMap<u32, u64>,
    lambda_entries: HashMap<u32, Arc<arinsal_term::FunEntry>>,
    export_entries: Vec<usize>,
    export_trampoline: usize,
    light_bif_fragment: usize,
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
            let value = beam
                .literal(index as u32)
                .map_err(|error| error.to_string())?;
            let term = from_owned(&value, literal_heap).map_err(|error| format!("{error:?}"))?;
            literals.push(raw_word(term));
        }
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
        Ok(Self {
            literals,
            zero_capture_funs,
            lambda_entries,
            export_entries,
            export_trampoline: fragments.export_trampoline(),
            light_bif_fragment: fragments.call_light_bif(),
            _lifetime: std::marker::PhantomData,
        })
    }
}

impl ModuleEnv for VmModuleEnv<'_> {
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
            .map(|entry| (Arc::as_ptr(entry) as usize, entry.arity))
            .ok_or_else(|| format!("lambda {index} has no loaded fun entry"))
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
    fn bs_construct_helpers(
        &self,
    ) -> (
        arinsal_beamasm::bs_construct::BsConstructHelper,
        arinsal_beamasm::bs_construct::BsConstructErrorHelper,
    ) {
        (
            crate::native_helpers::arinsal_beamasm_bs_construct,
            crate::native_helpers::arinsal_beamasm_bs_construct_error,
        )
    }
    fn exception_resolver(&self) -> arinsal_beamasm::catch::ExceptionResolver {
        crate::native_helpers::arinsal_beamasm_exception_resolver
    }
    fn fun_resolver(&self) -> arinsal_beamasm::fun::FunResolver {
        crate::native_helpers::arinsal_beamasm_fun_resolver
    }
}

/// Compile a module and retain both its executable mapping and embedded literals.
pub(crate) fn compile(
    bytes: &[u8],
    module: &arinsal_loader::Module,
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
    let export_entries = import_entries(module)?;
    let mut literal_heap = Box::new(VecHeap::new());
    let env = VmModuleEnv::new(&beam, module, &mut literal_heap, export_entries, fragments).ok()?;
    let trace = crate::calls::trace_boot_enabled();
    if trace {
        eprintln!("arinsal boot: beamasm compiling {}", beam.module);
    }
    let compiled =
        match compile_module_with_env_and_funcs(bytes, &env, function_allowlist.as_deref()) {
            Ok(compiled) => compiled,
            Err(error) => {
                eprintln!(
                    "arinsal boot: beamasm compile failed for {}: {error:?}",
                    beam.module
                );
                return None;
            }
        };
    if let Some(directory) = std::env::var_os("ARINSAL_BEAMASM_DUMP")
        && let Err(error) = arinsal_beamasm::write_global_note(std::path::Path::new(&directory))
    {
        eprintln!("arinsal beamasm dump: could not write global.asm: {error}");
    }
    if trace {
        eprintln!(
            "arinsal boot: beamasm compiled {} native={} unported={}",
            compiled.name,
            compiled.functions.len(),
            compiled.unported.len()
        );
        for function in &compiled.functions {
            eprintln!(
                "arinsal boot: beamasm native function {}/{}",
                function.name, function.arity
            );
        }
        for function in &compiled.unported {
            eprintln!(
                "arinsal boot: beamasm unported function {}/{}: {}",
                function.name,
                function.arity,
                function.missing_ops.join(",")
            );
        }
    }
    drop(env);
    MODULES.fetch_add(1, Ordering::Relaxed);
    NATIVE.fetch_add(compiled.functions.len() as u64, Ordering::Relaxed);
    UNPORTED.fetch_add(compiled.unported.len() as u64, Ordering::Relaxed);
    let mut function_starts = compiled
        .functions
        .iter()
        .filter_map(|function| compiled.native.entries.get(&function.label))
        .map(|entry| *entry as usize)
        .collect::<Vec<_>>();
    function_starts.sort_unstable();
    let code_start = compiled.native.memory.as_ptr() as usize;
    let Some(code_end) = compiled
        .native
        .memory
        .block_size(0)
        .and_then(|size| code_start.checked_add(size))
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
    let native_targets = compiled
        .functions
        .iter()
        .filter_map(|function| {
            module.export_slot(&function.name, function.arity)?;
            compiled.native.entries.get(&function.label).map(|entry| {
                (
                    (compiled.name.clone(), function.name.clone(), function.arity),
                    *entry as usize,
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
            .map(|entry| *entry as usize)
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
            start,
            end,
            module: compiled.name.clone(),
            function: function.name.clone(),
            arity: function.arity,
            line: None,
            file: None,
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
    let version = Arc::new(CompiledVersion {
        module: compiled.name.clone(),
        _memory: Box::new(compiled.native.memory),
        _literal_heap: literal_heap,
        native_functions,
        native_targets,
        code_start,
        code_end,
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

fn raw_word(term: Term) -> u64 {
    term.tagged_word()
}

pub(crate) fn count_native_call() {
    NATIVE_CALLS.fetch_add(1, Ordering::Relaxed);
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
        "ARINSAL_BEAMASM_STATS modules={} native_functions={} unported_functions={} native_calls={} native_yields={} call_unported={}",
        MODULES.load(Ordering::Relaxed),
        NATIVE.load(Ordering::Relaxed),
        UNPORTED.load(Ordering::Relaxed),
        NATIVE_CALLS.load(Ordering::Relaxed),
        NATIVE_YIELDS.load(Ordering::Relaxed),
        CALL_UNPORTED.load(Ordering::Relaxed)
    );
}
