//! The arm side of the VM's BeamAsm load: the module environment of the arm emitters,
//! their fragment sets and the compiled version they produce.

use super::*;
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

/// The arm `beamasm_init`: the shared fragments and the run-process stub, whose code pointers
/// are published as erts' `beam_*` globals.
// Port of erts/emulator/beam/jit/beam_jit_main.cpp:243-397 (beamasm_init), OTP-29.1.1.
pub(crate) fn beamasm_init() {
    // erts_exit(ERTS_ABORT_EXIT, ...) when the global code cannot be generated.
    let fragments = fragments().expect("beamasm_init: the arm fragments");
    crate::beam_jit_main::publish(&crate::beam_jit_main::BeamCodePtrs {
        run_process: fragments.run_process().map_or(0, |(start, _)| start),
        export_trampoline: fragments.export_trampoline(),
        save_calls_export: fragments.save_calls_export(),
        save_calls_fun: fragments.save_calls_fun(),
        unloaded_fun: fragments.unloaded_fun(),
        i_line_breakpoint_cleanup: fragments.line_breakpoint_cleanup(),
    });
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
                    bif_table: crate::bif_table::table_address(),
                    light_bif_gc: crate::raw::gc_ffi::erts_gc_after_bif_call_lhf as *const ()
                        as usize,
                    exception_resolver: crate::native_helpers::arinsal_beamasm_exception_resolver
                        as *const () as usize,
                    save_calls_export: crate::native_helpers::arinsal_beamasm_save_calls_export
                        as *const () as usize,
                    unloaded_fun: crate::native_helpers::arinsal_beamasm_fun_resolver as *const ()
                        as usize,
                    save_calls_fun: crate::fun_dispatch::arinsal_beamasm_save_calls_fun as *const ()
                        as usize,
                    compare: CompareHelpers {
                        eq: crate::utils::eq as *const () as usize,
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
                    call_error_handler: crate::native_helpers::arinsal_beamasm_call_error_handler
                        as *const () as usize,
                },
            )
            .ok()?;
            if let Some((start, end)) = fragments.run_process() {
                // The beam_run_process stub is a code range of its own (no module), so
                // `enter_native_function` finds its arity: apply/3 takes three arguments.
                // The stub has no module or function name, and erts creates no atom for it: the
                // atom fields name an existing atom, so registration interns nothing at boot.
                let names = arinsal_term::global_atoms();
                let module = "$beam_run_process";
                let undefined = names.get("undefined").expect("predefined atom");
                let info = crate::NativeFunction {
                    fragment: true,
                    start,
                    end,
                    module,
                    module_atom: undefined,
                    function: module,
                    function_atom: undefined,
                    arity: 3,
                    line: None,
                    file: None,
                    file_term: None,
                    line_table: Default::default(),
                };
                crate::register_native_function(info).expect("register run-process stub");
            }
            Some(fragments)
        })
        .as_ref()
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
                crate::receive::erts_proc_sig_receive_helper,
                crate::beam_jit_common::beam_jit_wait_unlocked,
                crate::beam_jit_common::beam_jit_wait_locked,
                yield_fragments()?.context_switch(),
                arinsal_beamasm::receive_frag::MsgOffsets {
                    sig_qs_save: crate::PROCESS_SIGQ_SAVE_OFFSET as u32,
                    message_term: crate::ERTS_MESSAGE_TERM_OFFSET as u32,
                    state: crate::PROCESS_STATE_OFFSET as u32,
                },
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

static MODULES: AtomicU64 = AtomicU64::new(0);
static NATIVE: AtomicU64 = AtomicU64::new(0);
static NATIVE_CALLS: AtomicU64 = AtomicU64::new(0);
static NATIVE_YIELDS: AtomicU64 = AtomicU64::new(0);
static CALL_UNPORTED: AtomicU64 = AtomicU64::new(0);
/// `CallUnported` exits per target, kept only under `ARINSAL_BEAMASM_STATS`.
static CALL_UNPORTED_TARGETS: std::sync::Mutex<std::collections::BTreeMap<String, u64>> =
    std::sync::Mutex::new(std::collections::BTreeMap::new());
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
    /// The `-on_load` function the emitter found.
    pub(crate) on_load: Option<(String, u8)>,
    /// The dispatch entry of each import, put into the export table when the version is
    /// installed (`erts_export_put` of `beam_load_finalize_code`).
    import_bindings: Vec<(Mfa, &'static Arc<arinsal_term::ExportEntry>)>,
    /// Functions of the module BeamAsm could not compile: they run in the interpreter.
    module_handle: u64,
    installed: AtomicBool,
    pub(crate) map_lookups: Box<[arinsal_beamasm::map::MapLookupTable]>,
    memory: std::sync::Mutex<arinsal_a64::exec::CodeMemory>,
    /// The native entry breakpoint of each function: its name atom and arity, the patch site
    /// and the branch the site holds while the breakpoint is off.
    trace_breakpoints: Vec<((arinsal_term::Atom, u8), usize, u32)>,
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
    native_functions: crate::native_bridge::FunctionTable,
    /// The code address of each exported function (`beamasm_get_code` of its label), which
    /// `erts_finish_loading` writes into the export.
    export_addresses: Vec<(Mfa, usize)>,
    code_start: usize,
    code_end: usize,
    /// The `catches` of the module assembler: (code-memory offset of the tag load, handler address).
    catches: Vec<(usize, usize)>,
    /// `catches` of the module (`ErtsCodeIndex`-independent list head into `bccix`), set by
    /// `patch_catches` at install.
    catch_head: std::sync::atomic::AtomicU32,
    lambda_entries: Vec<Arc<arinsal_term::FunEntry>>,
    lambda_targets: Vec<(Arc<arinsal_term::FunEntry>, usize)>,
}

/// Enable or remove native entry breakpoints for traced functions of one module.
// Port of erts/emulator/beam/jit/arm/beam_asm_module.cpp:231-250, OTP-29.1.1.
// Batched per module: a per-function call rescanned every version's breakpoint table, which made
// a `{'_','_','_'}` trace pattern quadratic in the loaded code.
pub(crate) fn patch_native_breakpoints(module: &str, wanted: &[(&str, u8, bool)]) {
    if wanted.is_empty() {
        return;
    }
    let Ok(versions) = compiled_versions().read() else {
        return;
    };
    let atoms = global_atoms();
    let wanted = wanted
        .iter()
        .filter_map(|&(function, arity, enabled)| Some(((atoms.get(function)?, arity), enabled)))
        .collect::<HashMap<_, _>>();
    for version in versions
        .iter()
        .filter_map(Weak::upgrade)
        .filter(|version| version.module == module)
    {
        let Ok(mut memory) = version.memory.lock() else {
            continue;
        };
        for (key, offset, branch) in &version.trace_breakpoints {
            let Some(&enabled) = wanted.get(key) else {
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

/// Enable or disable the native line-breakpoint sites of `line` in `module`.
// Port of erts/emulator/beam/jit/arm/beam_asm_module.cpp:337-348, OTP-29.1.1: the `b next`
// that skips the trampoline is rewritten to a NOP when the breakpoint is enabled.
/// Whether the native line table of `module` has an entry for source line `line`.
// Port of erts/emulator/beam/beam_ranges.c (erts_find_next_code_for_line: a search of the
// code header's line table), OTP-29.1.1.
pub(crate) fn native_code_has_line(module: &str, line: u32) -> bool {
    let Ok(versions) = compiled_versions().read() else {
        return false;
    };
    versions
        .iter()
        .filter_map(Weak::upgrade)
        .filter(|version| version.module == module)
        .any(|version| {
            version
                .native_functions
                .iter()
                .any(|function| function.line_table.has_line(line))
        })
}

pub(crate) fn patch_native_line_breakpoint(module: &str, line: u32, enabled: bool) {
    let Ok(mut versions) = compiled_versions().write() else {
        return;
    };
    versions.retain(|version| version.strong_count() != 0);
    for version in versions
        .iter()
        .filter_map(Weak::upgrade)
        .filter(|version| version.module == module)
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

    /// Whether `address` lies in this version's generated code.
    pub(crate) fn contains_code(&self, address: usize) -> bool {
        (self.code_start..self.code_end).contains(&address)
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
    /// `deferred` is set for code with an on_load function: its exports are written into
    /// `trampoline.not_loaded.deferred` until erlang:finish_after_on_load/2.
    pub(crate) fn install(
        self: &Arc<Self>,
        module: &arinsal_loader::Module,
        deferred: bool,
    ) -> bool {
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
        self.patch_catches();
        let code_index = crate::code_ix::global().staging();
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
        publish_module(
            module,
            &self.export_addresses,
            &self.import_bindings,
            deferred,
        );
        true
    }
    /// Queues the version's literals for release; its exports were redirected by
    /// `delete_code` when it stopped being current. Run when the version is freed explicitly (purge
    /// `complete`, a load that reclaims it), never from drop: the code is gone at that point
    /// whatever else still holds this value, like the explicit free of the old code header in
    /// erts.
    // Port of erts/emulator/beam/beam_bif_load.c (erts_internal_purge_module_2 complete:
    // erts_queue_release_literals after the code is freed), OTP-29.1.1.
    pub(crate) fn unpublish(&self) {
        // Port of erts/emulator/beam/beam_bif_load.c:2269 (beam_catches_delmod in purge
        // complete), OTP-29.1.1.
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

    // Port of erts/emulator/beam/jit/beam_jit_common.cpp:507-530 (patchCatches) and
    // jit/asm_load.c:1175 (`inst_p->catches = beamasm_patch_catches`), OTP-29.1.1: every catch of
    // the module is consed onto the staging pool and its tag written into the `mov` that loads it.
    fn patch_catches(&self) {
        let mut catch_no = crate::beam_catches::BEAM_CATCHES_NIL;
        let mut memory = self
            .memory
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for &(patch, handler) in &self.catches {
            catch_no =
                crate::beam_catches::beam_catches_cons(handler, catch_no, std::ptr::null_mut());
            let tag = arinsal_beamasm::catch::make_catch(catch_no);
            // With the current tag scheme, more than 33 million catches can exist at once.
            assert!(tag >> 31 == 0, "catch table exhausted");
            // `movz w9, #lo; movk w9, #hi, lsl 16`.
            let movz = 0x5280_0009_u32 | (((tag & 0xffff) as u32) << 5);
            let movk = 0x72a0_0009_u32 | ((((tag >> 16) & 0xffff) as u32) << 5);
            let mut words = [0u8; 8];
            words[..4].copy_from_slice(&movz.to_le_bytes());
            words[4..].copy_from_slice(&movk.to_le_bytes());
            memory
                .write_bytes(patch, &words)
                .expect("catch tag site is inside the module's code");
        }
        self.catch_head.store(catch_no, Ordering::Relaxed);
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
            arinsal_pterm::global_store().retire_module_area(heap);
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
            crate::native_bridge::unregister_native_module(self.code_start, self.code_end);
        }
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

struct VmModuleEnv<'a> {
    literal_heap: std::cell::RefCell<&'a mut VecHeap>,
    dynamic_integer_literals: std::cell::RefCell<HashMap<BigInt, u64>>,
    literals: Vec<u64>,
    /// The literals the load added after those of the file, by literal index.
    /// The words of the added literals, by literal index minus `literals.len()`.
    added_literals: std::cell::RefCell<Vec<Option<u64>>>,
    zero_capture_funs: HashMap<u32, u64>,
    lambda_entries: HashMap<u32, Arc<arinsal_term::FunEntry>>,
    export_entries: Vec<usize>,
    export_trampoline: usize,
    light_bif_fragment: usize,
    light_bif_helper_fragment: usize,
    breakpoint_fragment: usize,
    line_breakpoint_fragment: usize,
    /// `BIF_TRAP_EXPORT(BIF_send_2)`: the `erlang:send/2` export of the module's code.
    send_export: usize,
    module_name: String,
    /// The module's NIFs are in this runtime (`static_nif_module`).
    static_nifs: bool,
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
        send_export: usize,
        fragments: &DispatchFragments,
        module_handle: u64,
    ) -> Result<Self, String> {
        let mut literals = Vec::with_capacity(beam.literals.len());
        for index in 0..beam.literals.len() {
            // Port of erts/emulator/beam/jit/asm_load.c (beamasm_codegen: literals live in the
            // module's literal area), OTP-29.1.1: native code refers to the same literal terms
            // as the interpreter's code of this module.
            let term = module
                .literal_term(index as u32)
                .ok_or_else(|| format!("literal {index} is not decoded"))?;
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
        Ok(Self {
            literal_heap: std::cell::RefCell::new(literal_heap),
            dynamic_integer_literals: std::cell::RefCell::new(HashMap::new()),
            literals,
            added_literals: std::cell::RefCell::new(Vec::new()),
            zero_capture_funs,
            lambda_entries,
            export_entries,
            export_trampoline: fragments.export_trampoline(),
            light_bif_fragment: fragments.call_light_bif(),
            light_bif_helper_fragment: fragments.call_light_bif_helper(),
            breakpoint_fragment: fragments.breakpoint(),
            line_breakpoint_fragment: fragments.line_breakpoint(),
            send_export,
            module_name: module.name.clone(),
            static_nifs: crate::load::static_nif_module(&module.name),
            functions: if module.awaits_native_functions() {
                // A module without the interpreter form: its functions in code order, the
                // indices of its function coverage slots (asm_load.c:757-769).
                beam.code
                    .instructions
                    .iter()
                    .filter(|instruction| instruction.op == arinsal_spec::Opcode::FuncInfo)
                    .filter_map(|instruction| {
                        let name = match instruction.args.get(1)? {
                            arinsal_beam::Operand::Atom(index) => beam.atom(*index)?,
                            _ => return None,
                        };
                        let arity = match instruction.args.get(2)? {
                            arinsal_beam::Operand::U(arity) => u8::try_from(*arity).ok()?,
                            _ => return None,
                        };
                        Some((name.to_owned(), arity))
                    })
                    .collect()
            } else {
                module
                    .functions
                    .iter()
                    .map(|(_, function, arity)| ((*function).to_owned(), *arity))
                    .collect()
            },
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

    fn raw_raise_helper(&self) -> usize {
        crate::exceptions::raw_raise as *const () as usize
    }

    fn sys_perf_counter(&self) -> usize {
        arinsal_bifs::sys_perf_counter as *const () as usize
    }

    fn erts_this_node(&self) -> usize {
        arinsal_term::erts_this_node_addr()
    }

    fn build_stacktrace_helper(&self) -> Option<arinsal_beamasm::catch::BuildStacktraceHook> {
        Some(crate::exceptions::build_stacktrace)
    }

    fn process_dictionary_get_helper(&self) -> usize {
        crate::natives::erl_process_dict::erts_pd_hash_get as *const () as usize
    }

    fn native_body(&self, name: &str, arity: u8) -> Option<(usize, usize)> {
        // Almost no module has a static NIF.
        if !self.static_nifs {
            return None;
        }
        // Port of erts/emulator/beam/jit/arm/asm_load.c:651, OTP-29.1.1: loader-patched static
        // NIF bodies call their Rust body through the shared runtime helper.
        let nif = crate::natives::static_nif_lookup(&self.module_name, name, arity)?;
        let identity = crate::native_helpers::register_static_nif(
            self.module_name.clone(),
            name.to_owned(),
            arity,
            nif,
        );
        Some((
            identity,
            crate::native_helpers::arinsal_beamasm_static_nif as *const () as usize,
        ))
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
        let slot = crate::raw::jit_ffi::export_entry(entry);
        crate::bif_table::function(slot.bif_number())
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
    fn send_export_entry(&self) -> usize {
        self.send_export
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
            eq_exact_list: fragments.is_eq_exact_list_shared(),
            eq: 0,
        });
        // The general path of `=:=` / `=/=` calls `eq` directly, with or without fragments.
        shared.eq = crate::utils::eq as *const () as usize;
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
    // Port of erts/emulator/beam/jit/arm/instr_bif.cpp:110-151 (i_bif*: `mov ARG, bif->f`), OTP-29.1.1:
    // the BIF function is bound when the call site is emitted, never looked up by name per call.
    fn bif_function(&self, identity: usize) -> usize {
        export_dispatch(identity).map_or(0, |export| export.bif_table_function())
    }
    // Port of erts/emulator/beam/jit/arm/instr_bif.cpp:110-151 (`bif->f`) and beam_load.c (BIF
    // import resolution), OTP-29.1.1: an import is a plain BIF when `bif_table` has its body.
    fn plain_bif_identity(&self, _beam: &BeamFile, index: u32) -> Option<usize> {
        let identity = *self.export_entries.get(index as usize)?;
        export_dispatch(identity)?
            .bif_table_runs_bif()
            .then_some(identity)
    }
    // Port of erts/emulator/beam/jit/arm/instr_bif.cpp:110-151, OTP-29.1.1:
    // `bif_mfa` is the stable address of the export descriptor's MFA.
    fn plain_bif_mfa(&self, _beam: &BeamFile, index: u32) -> Option<usize> {
        let identity = *self.export_entries.get(index as usize)?;
        let target = target_for_identity(identity)?;
        Some(std::ptr::from_ref(target.slot.mfa()) as usize)
    }
    fn bs_match_cmd_helper(&self) -> arinsal_beamasm::bs_match::BsMatchCmdHelper {
        crate::native_helpers::arinsal_beamasm_bs_match_command
    }
    fn bs_create_bin_helper(&self) -> arinsal_beamasm::bs_construct::BsCreateBinHelpers {
        arinsal_beamasm::bs_construct::install_bs_append_binary(
            crate::erl_bits::append_binary as *const () as usize,
        );
        arinsal_beamasm::bs_construct::install_bs_append_checked(
            crate::native_helpers::bs_construct_raw::append_checked as *const () as usize,
        );
        arinsal_beamasm::bs_construct::install_bs_gc(self.gc_hook());
        arinsal_beamasm::bs_construct::install_bs_private_append(
            crate::native_helpers::arinsal_beamasm_bs_private_append_checked as *const () as usize,
        );
        use arinsal_beamasm::bs_construct::BsCreateBinHelpers;
        BsCreateBinHelpers {
            append_checked: crate::native_helpers::bs_construct_raw::append_checked,
            private_append: crate::native_helpers::bs_construct_raw::private_append,
            init_bits: crate::native_helpers::bs_construct_raw::init_bits,
            bit_size: crate::native_helpers::bs_construct_raw::bit_size,
            utf8_size: crate::native_helpers::bs_construct_raw::utf8_size,
            utf16_size: crate::native_helpers::bs_construct_raw::utf16_size,
            utf32_size: crate::native_helpers::bs_construct_raw::utf32_size,
            fail: crate::native_helpers::bs_construct_raw::fail,
            put_integer: crate::native_helpers::bs_construct_raw::put_integer,
            put_binary: crate::native_helpers::bs_construct_raw::put_binary,
            put_binary_all: crate::native_helpers::bs_construct_raw::put_binary_all,
            put_float: crate::native_helpers::bs_construct_raw::put_float,
            put_utf8: crate::native_helpers::bs_construct_raw::put_utf8,
            put_utf16: crate::native_helpers::bs_construct_raw::put_utf16,
            put_utf32: crate::native_helpers::bs_construct_raw::put_utf32,
            put_string: crate::native_helpers::bs_construct_raw::put_string,
        }
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
        crate::beam_common::add_stacktrace
    }
    fn big_to_float_helper(&self) -> arinsal_beamasm::float::BigToFloat {
        crate::big::big_to_double
    }
    fn bs_init_writable_helper(&self) -> arinsal_beamasm::bs_construct::BsInitWritableHelper {
        crate::erl_bits::erts_bs_init_writable
    }
    fn receive_hooks(&self) -> arinsal_beamasm::receive::ReceiveHooks {
        arinsal_beamasm::receive::ReceiveHooks {
            recv_marker_reserve: crate::receive::erts_msgq_recv_marker_insert,
            recv_marker_bind: crate::receive::erts_msgq_recv_marker_bind,
            recv_marker_clear: crate::receive::erts_msgq_recv_marker_clear,
            recv_marker_use: crate::receive::erts_msgq_recv_marker_set_save,
            loop_rec_shared: receive_fragments().map_or(
                0,
                arinsal_beamasm::receive_frag::ReceiveFragments::loop_rec_shared,
            ),
            remove_message: crate::beam_jit_common::beam_jit_remove_message,
            set_save_next: crate::receive::erts_msgq_set_save_next,
            wait_unlocked_shared: receive_fragments().map_or(
                0,
                arinsal_beamasm::receive_frag::ReceiveFragments::wait_unlocked_shared,
            ),
            wait_locked_shared: receive_fragments().map_or(
                0,
                arinsal_beamasm::receive_frag::ReceiveFragments::wait_locked_shared,
            ),
            take_receive_lock: crate::beam_jit_common::beam_jit_take_receive_lock,
            wait_timeout: crate::beam_jit_common::beam_jit_wait_timeout,
            timeout_locked: crate::beam_jit_common::beam_jit_timeout_locked,
            timeout: crate::beam_jit_common::beam_jit_timeout,
        }
    }
    fn apply_runtime(&self) -> arinsal_beamasm::misc::ApplyRuntime {
        let fragments = fragments();
        arinsal_beamasm::misc::ApplyRuntime {
            resolver: crate::native_helpers::arinsal_beamasm_apply_resolver,
            apply3_resolver: crate::native_helpers::arinsal_beamasm_apply3_resolver,
            apply_fun_shared: fragments.map_or(0, DispatchFragments::apply_fun_shared),
            fun_resolver: crate::native_helpers::arinsal_beamasm_fun_resolver,
        }
    }
}

/// Compile a module and retain both its executable mapping and embedded literals.
// Port of erts/emulator/beam/beam_load.c:125-230 and jit/asm_load.c:947-1155, OTP-29.1.1.
pub(crate) fn compile(
    beam: &arinsal_beam::BeamFile,
    module: &mut arinsal_loader::Module,
    line_breakpoints: bool,
    code_ix: &crate::code_ix::CodeIndexes,
    failure: &mut Option<arinsal_beamjit::CompileError>,
) -> Option<Arc<CompiledVersion>> {
    if lifetime_trace_enabled() {
        eprintln!(
            "[beamasm-lifetime] compile module={} module_ptr={:p}",
            module.name, module
        );
    }
    let fragments = fragments()?;
    arinsal_loader::file_atoms(beam).ok()?;
    let (export_entries, import_bindings) = import_entries(module)?;
    // Port of erts/emulator/beam/jit/arm/instr_bif.cpp:612-624 (emit_send: the `send/2`
    // export is the one `send` calls), OTP-29.1.1.
    let send_export = Arc::as_ptr(make_export((
        arinsal_term::atoms::ERLANG,
        arinsal_term::atoms::SEND,
        2,
    ))?) as usize;
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
        send_export,
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
            *failure = Some(error);
            return None;
        }
    };
    // Port of erts/emulator/beam/jit/asm_load.c:1177-1260 (beam_load_finalize_code): the
    // function table and the exports of a module that was not decoded come from what the
    // emitter found.
    if module.awaits_native_functions() {
        let found = compiled
            .functions
            .iter()
            .map(|function| arinsal_loader::NativeFunction {
                atom: arinsal_term::Atom(function.atom),
                arity: function.arity,
                entry_label: function.entry_label,
                nif_stub: function.nif_stub,
            })
            .collect::<Vec<_>>();
        if let Err(error) = module.finish_native(beam, &found) {
            eprintln!(
                "arinsal boot: beamasm finish failed for {}: {error:?}",
                beam.module
            );
            return None;
        }
        crate::load::bind_native_static_nifs(module, code_ix);
    }
    let module = &*module;
    // Port of erts/emulator/beam/jit/asm_load.c:1177-1195 (beam_load_finalize_code), OTP-29.1.1:
    // every function of the module, a static NIF's call-NIF body included, is native code the
    // export addresses point at.
    let runtime_functions = compiled.functions.iter().collect::<Vec<_>>();
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
            let site = *site_index.get(&(function.name.to_owned(), function.arity))?;
            Some((function.name.to_owned(), function.arity, site, offset))
        })
        .collect::<Vec<_>>();
    drop(env);
    MODULES.fetch_add(1, Ordering::Relaxed);
    NATIVE.fetch_add(runtime_functions.len() as u64, Ordering::Relaxed);
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
    let export_addresses = runtime_functions
        .iter()
        .filter_map(|function| {
            // Port of erts/emulator/beam/jit/asm_load.c:185-192, OTP-29.1.1.
            // BIF exports retain their `call_bif` dispatch address.
            if arinsal_spec::bif_lookup(&compiled.name, function.name, function.arity).is_some() {
                return None;
            }
            let name = arinsal_term::Atom(function.atom);
            module.export_slot_atom(name, function.arity)?;
            let entry = compiled.native.entries.get(&function.label)?;
            Some((
                (module.name_atom, name, function.arity),
                *entry as usize + arinsal_beamasm::module::FUNC_INFO_BYTES,
            ))
        })
        .collect::<Vec<_>>();
    let module_text = global_atoms().text(module.name_atom)?;
    let mut native_functions = Vec::with_capacity(compiled.functions.len());
    let mut line_entries = compiled
        .native
        .line_table
        .iter()
        .map(|entry| (code_start + entry.offset, entry))
        .collect::<Vec<_>>();
    line_entries.sort_by_key(|(address, _)| *address);
    // `BeamCodeLineTab` keeps packed file/line values in `loc_tab` and one shared filename
    // table; each function points at its window in the module-wide PC table.
    let mut file_indices = HashMap::new();
    let mut file_names = Vec::new();
    let location_table: Arc<[crate::NativeLine]> = line_entries
        .iter()
        .map(|&(address, entry)| {
            let file_identity = Arc::as_ptr(&entry.file) as *const () as usize;
            let file_index = *file_indices.entry(file_identity).or_insert_with(|| {
                let index = file_names.len();
                file_names.push(crate::NativeFile {
                    name: Arc::clone(&entry.file),
                    file_term: module.line_file_terms.get(&*entry.file).copied(),
                });
                index
            });
            // Port of beam_code.h:31-39 (`MAKE_LOCATION`): file indices must fit in eight
            // bits with 255 reserved, and line numbers in the lower 24 bits.
            let location = if file_index < 255 && u64::from(entry.line) < (1 << 24) - 1 {
                ((file_index as u32) << 24) | entry.line
            } else {
                0
            };
            crate::NativeLine { address, location }
        })
        .collect();
    let file_names: Arc<[crate::NativeFile]> = file_names.into();
    let location_addresses: Arc<[usize]> = location_table
        .iter()
        .map(|entry| entry.address)
        .chain(std::iter::once(code_end))
        .collect();
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
            fragment: false,
            start,
            end,
            module: module_text,
            module_atom: module.name_atom,
            function: global_atoms().text(arinsal_term::Atom(function.atom))?,
            function_atom: arinsal_term::Atom(function.atom),
            arity: function.arity,
            line: None,
            file: None,
            // A `line` instruction before the function's `func_info` still names its first
            // instructions, so the nearest preceding entry belongs to the function.
            line_table: {
                let before = location_table.partition_point(|entry| entry.address <= start);
                let first = before.saturating_sub(1);
                let last = location_table
                    .partition_point(|entry| entry.address < end)
                    .max(first);
                crate::NativeLines::window(
                    &location_table,
                    &location_addresses,
                    &file_names,
                    first,
                    last,
                )
            },
            file_term: None,
        });
    }
    // BeamCodeHeader.functions is ordered by code address for erts_lookup_function_info.
    native_functions.sort_unstable_by_key(|function| function.start);
    let native_functions: crate::native_bridge::FunctionTable = Arc::from(native_functions);
    if lifetime_trace_enabled() {
        eprintln!(
            "[beamasm-lifetime] compiled module={} range={:#x}..{:#x} native={}",
            compiled.name,
            code_start,
            code_end,
            native_functions.len()
        );
    }
    let by_label = compiled
        .functions
        .iter()
        .map(|function| (function.label, function))
        .collect::<HashMap<_, _>>();
    let trace_breakpoints = compiled
        .native
        .trace_breakpoints
        .iter()
        .filter_map(|(&label, &(offset, branch))| {
            let function = by_label.get(&label)?;
            let atom = arinsal_term::Atom(function.atom);
            Some(((atom, function.arity), offset, branch))
        })
        .collect();
    let version = Arc::new(CompiledVersion {
        module: compiled.name.clone(),
        import_bindings,
        on_load: compiled
            .on_load
            .and_then(|index| compiled.functions.get(index))
            .map(|function| (function.name.to_owned(), function.arity)),
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
        export_addresses,
        code_start,
        code_end,
        catches: compiled
            .native
            .catches
            .iter()
            .map(|site| (site.patch, site.handler as usize))
            .collect(),
        catch_head: std::sync::atomic::AtomicU32::new(crate::beam_catches::BEAM_CATCHES_NIL),
        lambda_entries,
        lambda_targets,
    });
    Some(version)
}

fn raw_word(term: Term) -> u64 {
    term.tagged_word()
}

/// Installs the arm trace-return hook in `tmp_mem[5]`: arm's `return_trace`,
/// `i_return_to_trace` and `i_call_trace_return` stubs call it (erts calls
/// `beam_jit_return_to_trace` and friends by address instead).
pub(crate) fn set_trace_return_hook(registers: &mut arinsal_beamasm::SchedulerRegisters) {
    registers.tmp_mem[5] =
        crate::native_helpers::arinsal_beamasm_native_trace_return as *const () as usize as u64;
}

/// The return address of a raising call when `pc` carries arm's
/// [`arinsal_beamasm::module::RETURN_SITE_TAG`].
pub(crate) fn tagged_return_site(pc: usize) -> Option<usize> {
    let tag = arinsal_beamasm::module::RETURN_SITE_TAG;
    (pc & tag != 0).then_some(pc & !tag)
}

pub(crate) fn count_native_call() {
    // Debug statistics only: a counter shared by every scheduler thread is a contended
    // cache line on the scheduling path.
    if crate::debug_env::beamasm_stats() {
        NATIVE_CALLS.fetch_add(1, Ordering::Relaxed);
    }
}

pub(crate) fn count_native_yield() {
    // Debug statistics only: a counter shared by every scheduler thread is a contended
    // cache line on the scheduling path.
    if crate::debug_env::beamasm_stats() {
        NATIVE_YIELDS.fetch_add(1, Ordering::Relaxed);
    }
}
/// Marks the next `CallUnported` as the scheduler redoing a parked call, not a native exit.
pub(crate) fn note_call_retry() {
    if crate::debug_env::beamasm_stats() {
        CALL_RETRY.with(|flag| flag.set(true));
    }
}

thread_local! {
    static CALL_RETRY: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Counts a `CallUnported` exit and attributes it to its target (sentinel kind or export MFA).
pub(crate) fn count_call_unported(
    target_pc: usize,
    trapped: Option<(arinsal_term::Atom, arinsal_term::Atom, usize)>,
    x0: Term,
) {
    // Debug statistics only: a counter shared by every scheduler thread is a contended
    // cache line on the scheduling path.
    if !crate::debug_env::beamasm_stats() {
        return;
    }
    // A redone call after a schedule-in is not a native exit: erts resumes it at `c_p->i`.
    let retry = CALL_RETRY.with(|flag| flag.replace(false));
    if !retry {
        CALL_UNPORTED.fetch_add(1, Ordering::Relaxed);
    }
    use arinsal_beamasm::dispatch as d;
    let atoms = arinsal_term::global_atoms();
    let name = match target_pc {
        d::RETURN_TO_DISPATCH_IDENTITY => "return_to_dispatch".to_owned(),
        d::DIRTY_NIF_DISPATCH_IDENTITY => "dirty_nif".to_owned(),
        d::BREAKPOINT_DISPATCH_IDENTITY => "breakpoint".to_owned(),
        pc if d::decode_line_breakpoint_identity(pc).is_some() => "line_breakpoint".to_owned(),
        pc if pc == crate::bif_traps::bif_export_trap_pc() => match trapped {
            Some((m, f, a)) => format!(
                "bif_export_trap {}:{}/{a}",
                atoms.text(m).unwrap_or("?"),
                atoms.text(f).unwrap_or("?")
            ),
            None => "bif_export_trap ?".to_owned(),
        },
        pc => match export_dispatch(pc) {
            Some(export) => format!(
                "export {}:{}/{} class={:?} light={}{}",
                export.module,
                export.function,
                export.arity,
                export.class,
                export.light_kind,
                x0.as_atom()
                    .and_then(|atom| atoms.text(atom))
                    .filter(|_| export.arity > 0)
                    .map(|text| format!(" x0={text}"))
                    .unwrap_or_default()
            ),
            None => format!("unknown {pc:#x}"),
        },
    };
    let name = if retry {
        format!("(retry) {name}")
    } else {
        name
    };
    let mut table = CALL_UNPORTED_TARGETS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    *table.entry(name).or_insert(0) += 1;
}

pub(crate) fn print_stats() {
    if !crate::debug_env::beamasm_stats() || PRINTED.swap(true, Ordering::Relaxed) {
        return;
    }
    eprintln!(
        "ARINSAL_BEAMASM_STATS modules={} native_functions={} native_calls={} native_yields={} call_unported={}",
        MODULES.load(Ordering::Relaxed),
        NATIVE.load(Ordering::Relaxed),
        NATIVE_CALLS.load(Ordering::Relaxed),
        NATIVE_YIELDS.load(Ordering::Relaxed),
        CALL_UNPORTED.load(Ordering::Relaxed)
    );
    let table = CALL_UNPORTED_TARGETS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut rows: Vec<_> = table.iter().collect();
    rows.sort_by(|a, b| b.1.cmp(a.1));
    for (name, count) in rows {
        eprintln!("ARINSAL_BEAMASM_STATS call_unported {count} {name}");
    }
}
