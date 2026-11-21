//! `erlang:load_nif/2`, dynamic `.so` bindings, and the static `erl_tracer` NIFs.
//!
//! Dirty NIFs and dirty `enif_schedule_nif` continuations move the calling process
//! to the dirty scheduler pools (see [`DirtyNifJob`]).

use crate::code_ix::{code_tables, erts_active_code_ix};
use std::collections::{HashMap, HashSet};
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::{SystemTime, UNIX_EPOCH};

use arinsal_bifs::{BifError, BifFn, Ctx, ProcessHeapHandle};
use arinsal_sched::{Pid, RunCtx, Scheduler, SchedulerType};
use arinsal_term::{
    HeapAlloc, Term, TermBuilder, TermKind, VecHeap, exact_eq, from_owned, global_atoms,
};

use crate::calls;
use crate::process::Message;
use crate::{Process, Vm, VmError};

const TRACER_FUNCTIONS: &[(&str, u8)] = &[
    ("trace", 5),
    ("enabled", 3),
    ("trace_send", 5),
    ("trace_receive", 5),
    ("trace_call", 5),
    ("trace_running_procs", 5),
    ("trace_running_ports", 5),
    ("trace_garbage_collection", 5),
    ("trace_procs", 5),
    ("trace_ports", 5),
    ("enabled_send", 3),
    ("enabled_receive", 3),
    ("enabled_call", 3),
    ("enabled_running_procs", 3),
    ("enabled_running_ports", 3),
    ("enabled_garbage_collection", 3),
    ("enabled_procs", 3),
    ("enabled_ports", 3),
];

struct CachedTracerCallbacks {
    generation: u64,
    callbacks: HashMap<(String, u8), NativeFn>,
}

static TRACER_CALLBACKS: OnceLock<Mutex<HashMap<String, CachedTracerCallbacks>>> = OnceLock::new();

fn tracer_callbacks() -> &'static Mutex<HashMap<String, CachedTracerCallbacks>> {
    TRACER_CALLBACKS.get_or_init(Default::default)
}

/// Drops cached callback pointers when new active code is published.
// Port of erts/emulator/beam/code_ix.c:169 and erl_trace.c:3553-3596
// (erts_tracer_nif_clear), OTP-29.1.1.
pub(crate) fn invalidate_tracer_callbacks() {
    tracer_callbacks()
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .clear();
}

fn tracer_callback(module_name: &str, function: &str, arity: u8) -> Option<NativeFn> {
    let code = crate::code_ix::global().active_tables();
    let generation = code.generation;
    let key = module_name.to_owned();
    {
        let cache = tracer_callbacks()
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if let Some(cached) = cache.get(&key)
            && cached.generation == generation
        {
            return cached.callbacks.get(&(function.to_owned(), arity)).cloned();
        }
    }

    // Port of erts/emulator/beam/erl_trace.c:3017-3060 (load_tracer_nif), OTP-29.1.1: the
    // callbacks are the `ErlNifFunc`s of the library loaded into the module's current instance
    // (`erts_nif_get_funcs(instance->nif)`), matched by name and arity.
    let mut callbacks = HashMap::new();
    let current = code.loaded.get(module_name).copied();
    if let Some(lib) = current.and_then(instance_nif) {
        for (index, function) in lib.library.functions().into_iter().enumerate() {
            let (name, arity, _, _) = function;
            if !TRACER_FUNCTIONS
                .iter()
                .any(|&(wanted, wanted_arity)| name == wanted && arity == u32::from(wanted_arity))
            {
                continue;
            }
            let Ok(index) = u32::try_from(index) else {
                continue;
            };
            let Ok(arity) = u8::try_from(arity) else {
                continue;
            };
            callbacks.insert(
                (name, arity),
                NativeFn::Nif(NifBinding {
                    lib: Arc::clone(&lib),
                    index,
                }),
            );
        }
    } else if let Some(module) = current.and_then(|id| code.modules.get(id)) {
        // erl_tracer is not yet a static NIF library (erl_tracer.c via erts_static_nif_tab):
        // its callbacks are the bodies bind_tracer gave its entries.
        let native_fns = crate::code_ix::global().native_fns();
        for &(name, expected_arity) in TRACER_FUNCTIONS {
            let Some(ordinal) = module.functions.iter().position(|(_, found, found_arity)| {
                *found == name && *found_arity == expected_arity
            }) else {
                continue;
            };
            let Some(index) = module.nif_body(ordinal) else {
                continue;
            };
            if let Some(callback) = native_fns.get(index as usize).cloned().flatten() {
                callbacks.insert((name.to_owned(), expected_arity), callback);
            }
        }
    }
    let selected = callbacks.get(&(function.to_owned(), arity)).cloned();
    tracer_callbacks()
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .insert(
            key,
            CachedTracerCallbacks {
                generation,
                callbacks,
            },
        );
    selected
}

/// A NIF library bound to one module instance by `load_nif`.
// Port of erts/emulator/beam/erl_nif.c:93-124 (struct erl_module_nif), OTP-29.1.1. The `Arc`
// count plays `refc`: the code patched with the library's [`NifBinding`]s and the module
// instance (its [`MODULE_NIFS`] entry) refer to the struct. `dynlib_refc` counts the module
// instance and every ongoing dirty call or scheduled continuation; when it reaches zero the
// library is closed (`unload` runs), whatever still refers to the struct.
pub(crate) struct ModuleNif {
    library: arinsal_nif::NifLibrary,
    /// `mod` and `mi_copy`: the module instance the library is loaded into.
    owner: usize,
    dynlib_refc: std::sync::atomic::AtomicUsize,
    /// `ERTS_MOD_NIF_FLG_LOADING` until every function is published: callers then wait for
    /// the publication, as `call_nif_early` does.
    publishing: std::sync::atomic::AtomicBool,
    /// The schedulers that run the aux work closing the library.
    scheduler: Weak<Scheduler<Process>>,
    /// `finish` under `load_mtx`: the stubs of a load whose finishers have not all run.
    finish: Mutex<Option<ErtsNifFinish>>,
    /// `lib->barrier` of erl_nif.c: the later-op node of each load-nif code barrier.
    barrier: crate::code_ix::ErtsCodeBarrier,
}

impl ModuleNif {
    fn function(&self, index: usize) -> Result<&arinsal_nif::NifFunction, BifError> {
        self.library.function(index).ok_or(BifError::BADARG)
    }

    /// Drop one `dynlib_refc` reference; the last one closes the library.
    // Port of erts/emulator/beam/erl_nif.c:3362-3368 (nfunc_cleanup_nif_mod) and 5369-5370
    // (erts_unload_nif), OTP-29.1.1.
    fn dynlib_deref(self: &Arc<Self>) {
        if self
            .dynlib_refc
            .fetch_sub(1, std::sync::atomic::Ordering::AcqRel)
            == 1
        {
            close_dynlib(Arc::clone(self));
        }
    }
}

/// The `dynlib_refc` of a library as seen by its resource types.
struct ModuleRefs(Arc<ModuleNif>);

impl arinsal_nif::LibraryRefs for ModuleRefs {
    fn dynlib_inc(&self) {
        self.0
            .dynlib_refc
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
    }

    fn dynlib_dec(&self) {
        self.0.dynlib_deref();
    }
}

/// Close a library whose last `dynlib_refc` reference is gone: the unload callbacks run as aux
/// work of the calling normal scheduler, or of the first one when called elsewhere.
// Port of erts/emulator/beam/erl_nif.c:2542-2557 (close_dynlib) and 2559-2618
// (close_dynlib_aux, really_close_dynlib), OTP-29.1.1. Arinsal does not seize the code
// modification permission for it.
fn close_dynlib(lib: Arc<ModuleNif>) {
    let Some(scheduler) = lib.scheduler.upgrade() else {
        lib.library.close();
        return;
    };
    let sched_ix = arinsal_sched::current_normal_scheduler().map_or(0, |ix| ix + 1);
    scheduler.erts_schedule_misc_aux_work(sched_ix, move || lib.library.close());
}

/// `erts_nif_call_tab` with `erts_nif_call_tab_lock`: the stub of every function of a library
/// being loaded, keyed by its `code_info_ptr`. `erts_call_nif_early` reads it until the
/// `call_nif` code is in place.
// Port of erts/emulator/beam/erl_nif.c:4654-4700 (erts_nif_call_tab, nif_call_hash,
// nif_call_cmp, nif_call_table_init), OTP-29.1.1.
static ERTS_NIF_CALL_TAB: std::sync::LazyLock<std::sync::RwLock<HashMap<usize, usize>>> =
    std::sync::LazyLock::new(|| std::sync::RwLock::new(HashMap::with_capacity(100)));

/// One function of a library being loaded: the `ErtsCodeInfo` it replaces and the
/// `call_nif` code `beamasm_emit_call_nif` built for it.
// Port of erts/emulator/beam/erl_nif.c:4628-4641 (ErtsNifBeamStub), OTP-29.1.1.
#[repr(C)]
pub(crate) struct ErtsNifBeamStub {
    code_info_ptr: usize,
    /// `info` (the `ErtsCodeInfo`) followed by `code.call_nif`.
    info: [u8; FUNC_INFO_BYTES + NIF_STUB_CODE_BYTES],
}

use arinsal_beamasm::common::beam_asm_h::{FUNC_INFO_BYTES, NIF_STUB_CODE_BYTES};

impl ErtsNifBeamStub {
    /// `&bs->code` of the stub at `stub`: the phony `I` that `call_nif_shared` reads the
    /// `call_nif` operands from.
    fn code_at(stub: usize) -> usize {
        stub + std::mem::offset_of!(ErtsNifBeamStub, info) + FUNC_INFO_BYTES
    }
}

/// The stubs of a library being loaded and the code they patch (`lib->finish` with
/// `lib->mi_copy`).
// Port of erts/emulator/beam/erl_nif.c:4643-4646 (ErtsNifFinish), OTP-29.1.1.
pub(crate) struct ErtsNifFinish {
    version: Arc<crate::beamasm_integration::CompiledVersion>,
    #[allow(clippy::vec_box)] // erts_call_nif_early hands out addresses into the stubs.
    beam_stubv: Vec<Box<ErtsNifBeamStub>>,
}

/// The `call_nif` operands patched into the code of one NIF function.
// Port of erts/emulator/beam/erl_nif.c:4903-4940 (stub->code.call_nif), OTP-29.1.1:
// `call_nif[1]` is the function called on a normal scheduler, `call_nif[2]` the library and
// `call_nif[3]` the dirty function. For a dirty NIF `call_nif[1]` is
// static_schedule_dirty_{io,cpu}_nif (erl_nif.c:3437-3483), which `flags` selects here.
#[derive(Clone)]
pub(crate) struct NifBinding {
    lib: Arc<ModuleNif>,
    /// The `ErlNifFunc` of the library entry.
    index: u32,
}

/// What a `NativeBody` instruction runs: a Rust body or a NIF of a loaded library.
#[derive(Clone)]
pub(crate) enum NativeFn {
    /// A loader-bound static NIF or BIF body.
    Bif(BifFn),
    /// A function of a library loaded by `load_nif`.
    Nif(NifBinding),
}

/// Invoke a native body with the arguments of the function it replaces.
pub(crate) fn call_native(
    heap: &mut arinsal_term::ProcessHeap,
    native: &NativeFn,
    args: &[Term],
) -> Result<Term, BifError> {
    match native {
        NativeFn::Bif(function) => calls::call_bif(heap, *function, args),
        NativeFn::Nif(binding) => binding.call(heap, args),
    }
}

impl NifBinding {
    /// Run the NIF for the calling process.
    // Port of erts/emulator/beam/emu/bif_instrs.tab:480-543 (call_nif) and
    // erts/emulator/beam/jit/beam_jit_common.cpp:623-677 (beam_jit_call_nif), OTP-29.1.1:
    // `call_nif[1]` runs with `call_nif[2]` as the environment's library and takes no
    // reference to it; the code of a running call is not purged. A dirty NIF's
    // `call_nif[1]` (static_schedule_dirty_nif, erl_nif.c:3437-3471) moves the process to a
    // dirty scheduler instead.
    pub(crate) fn call(
        &self,
        heap: &mut arinsal_term::ProcessHeap,
        args: &[Term],
    ) -> Result<Term, BifError> {
        let lib = &self.lib;
        // Port of erts/emulator/beam/erl_nif.c:5109-5122 (erts_call_nif_early), OTP-29.1.1: a
        // function reached while its library is being published waits until every function of
        // the library is.
        if lib.publishing.load(std::sync::atomic::Ordering::Acquire) {
            drop(
                ERTS_NIF_CALL_TAB
                    .read()
                    .unwrap_or_else(|poison| poison.into_inner()),
            );
        }
        let index = self.index as usize;
        let function = lib.function(index)?;
        if args.len() != function.arity as usize {
            return Err(BifError::BADARG);
        }
        // Port of erts/emulator/beam/erl_nif.c (erts_nif_call_function), OTP-29.1.1: a tracer
        // callback is called directly with an environment of the calling process.
        let pid = thread_hub().and_then(|hub| hub.pid.to_term());
        let value = function.call_with_pid(heap, args, pid);
        nif_outcome(heap, value)
    }
}

/// `esdp->current_nif` with `esdp->registers`: the NIF call running on this thread, which
/// `enif_schedule_nif` and the scheduling wrappers find through `execution_state`.
#[derive(Clone, Copy)]
pub(crate) struct CurrentNif {
    /// `c_p` on a normal scheduler; null in a dirty job, whose process is scheduled out.
    c_p: *mut Process,
    /// `esdp->registers->x_reg_array`.
    reg: *mut Term,
    reg_len: usize,
    /// `env->mod_nif`: `Arc::as_ptr` of the library.
    mod_nif: usize,
    /// A dirty job: the wrapper, the shadow process and `c_p->current`.
    dirty: Option<DirtyNifCall>,
}

#[derive(Clone, Copy)]
struct DirtyNifCall {
    nep: *mut crate::erl_nfunc_sched::ErtsNativeFunc,
    shadow: *mut arinsal_term::ProcessHeap,
    current: *const arinsal_term::ErtsCodeMfa,
    /// The process, for its `ERTS_PSFLG_DIRTY_*_PROC` state bits.
    runtime: Option<&'static crate::process::Runtime>,
    pid: Option<Pid>,
}

/// `erts_get_scheduler_data()->current_nif`; `None` off a scheduler thread.
fn current_nif() -> Option<CurrentNif> {
    arinsal_sched::erts_get_scheduler_data::<Process, _>(|esdp| {
        arinsal_sched::erts_sched_registers(esdp).current_nif.get()
    })
    .flatten()
}

/// Run `call` with `current` as `esdp->current_nif`, restoring the previous value after it
/// (erts_pre_nif / erts_post_nif, erl_nif.c).
fn with_current_nif<R>(current: CurrentNif, call: impl FnOnce() -> R) -> R {
    let saved = arinsal_sched::erts_get_scheduler_data::<Process, _>(|esdp| {
        arinsal_sched::erts_sched_registers(esdp)
            .current_nif
            .replace(Some(current))
    });
    let result = call();
    if let Some(saved) = saved {
        arinsal_sched::erts_get_scheduler_data::<Process, _>(|esdp| {
            arinsal_sched::erts_sched_registers(esdp)
                .current_nif
                .set(saved);
        });
    }
    result
}

/// The NIF part of `beam_jit_call_nif`: `fp` of library `nif_mod` with the arguments in `reg`.
/// An exception or a TRAP (`enif_schedule_nif`) returns `THE_NON_VALUE` with `c_p->freason`
/// set.
// Port of erts/emulator/beam/jit/beam_jit_common.cpp:623-677 (beam_jit_call_nif: erts_pre_nif
// with `NifMod`, `(*fp)(&env, arity, reg)`, `exception_thrown` -> THE_NON_VALUE,
// erts_post_nif), OTP-29.1.1.
pub(crate) fn beam_jit_call_nif(
    c_p: &mut Process,
    (fp, nif_mod): (usize, usize),
    reg: &mut [Term],
    arity: usize,
) -> Term {
    let Some(fptr) = crate::natives::raw::nif_fptr(fp) else {
        c_p.heap.abi.exc.freason = arinsal_term::exc::EXC_BADARG;
        return Term::NON_VALUE;
    };
    let lib = crate::natives::raw::nif_mod(nif_mod);
    let pid = thread_hub().and_then(|hub| hub.pid.to_term());
    let current = CurrentNif {
        c_p: std::ptr::from_mut(c_p),
        reg: reg.as_mut_ptr(),
        reg_len: reg.len(),
        mod_nif: nif_mod,
        dirty: None,
    };
    // `(*fp)(&env, arity, reg)`: the arguments are the register array itself.
    with_current_nif(current, || {
        lib.library
            .call(&mut c_p.heap, (fptr, current.reg, arity), pid, false)
    })
}

/// Unload the NIF library bound to module instance `id`.
// Port of erts/emulator/beam/beam_bif_load.c:2254-2258 (purge complete) and
// erts/emulator/beam/erl_nif.c:5334-5373 (erts_unload_nif), OTP-29.1.1: purging a code
// instance drops its `dynlib_refc` reference; the library closes once no dirty call or
// scheduled continuation of it is left.
pub(crate) fn unload_instance(id: usize) {
    let released = {
        let mut libs = MODULE_NIFS
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let (released, kept) = std::mem::take(&mut *libs)
            .into_iter()
            .partition::<Vec<_>, _>(|lib| lib.owner == id);
        *libs = kept;
        released
    };
    for lib in released {
        // Port of erts/emulator/beam/erl_nif.c:5352 (erts_unload_nif: release_beam_stubs),
        // OTP-29.1.1.
        release_beam_stubs(&lib);
        lib.library.unload_resource_types();
        lib.dynlib_deref();
    }
}

/// The library loaded into module instance `id` (`erl_module_instance.nif`).
fn instance_nif(id: usize) -> Option<Arc<ModuleNif>> {
    MODULE_NIFS
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
        .iter()
        .find(|lib| lib.owner == id)
        .cloned()
}

/// Name and arity of the functions of the library loaded into module instance `id` of
/// `scope`, in the order of its entry.
// Port of erts/emulator/beam/erl_nif.c:5406-5411 (erts_nif_get_funcs), OTP-29.1.1.
pub(crate) fn instance_nif_functions(id: usize) -> Option<Vec<(String, u32)>> {
    let lib = instance_nif(id)?;
    Some(
        lib.library
            .functions()
            .into_iter()
            .map(|(name, arity, _, _)| (name, arity))
            .collect(),
    )
}

/// `erl_module_instance.nif` of every module instance with a loaded library. Only loading,
/// purging and halting read it; a NIF call reaches its library through its [`NifBinding`].
static MODULE_NIFS: Mutex<Vec<Arc<ModuleNif>>> = Mutex::new(Vec::new());
/// Runtimes whose processes have called NIFs. erts has one runtime and one process
/// table; a pid is resolved against the tables registered here (see [`hub_for_pid`]).
static RUNTIME_HUBS: Mutex<Vec<Hub>> = Mutex::new(Vec::new());
static SOCKET_REACTOR: OnceLock<Arc<NifSelectReactor>> = OnceLock::new();

fn halt_libraries() -> Vec<Arc<ModuleNif>> {
    MODULE_NIFS
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
        .clone()
}

/// Port of erts/emulator/beam/erl_nif.c:5566-5595 (`erts_nif_notify_halt`), OTP-29.1.1.
pub(crate) fn notify_halt() {
    for lib in halt_libraries() {
        lib.library.execute_on_halt();
    }
}

/// Execute callbacks registered after the initial halt notification.
/// Port of erts/emulator/beam/erl_init.c:2683-2687, OTP-29.1.1.
pub(crate) fn execute_late_on_halt() {
    notify_halt();
}

/// Port of erts/emulator/beam/erl_nif.c:5626-5649 (`erts_nif_wait_calls`), OTP-29.1.1.
pub(crate) fn wait_for_halt_calls() {
    for lib in halt_libraries() {
        lib.library.wait_for_halt_calls();
    }
}

#[derive(Clone)]
struct Hub {
    scheduler: Weak<Scheduler<Process>>,
    pid: Pid,
    runtime: &'static crate::process::Runtime,
    /// The hub a scheduler thread installed for itself: it acts for that scheduler's
    /// `esdp->current_process`; copies handed out carry the resolved `pid` instead.
    current: bool,
}

impl Hub {
    /// The process this hub acts for: `esdp->current_process` (erts_schedule sets it,
    /// erl_process.c:10180) on the hub of a scheduler thread that runs a process.
    fn current_pid(&self) -> Pid {
        if !self.current {
            return self.pid;
        }
        arinsal_sched::erts_get_scheduler_data::<Process, _>(|esdp| {
            arinsal_sched::RunCtx::with_current(esdp, |ctx| ctx.pid())
        })
        .flatten()
        .unwrap_or(self.pid)
    }

    /// A copy that keeps the current process as of now, like the hub value it replaces.
    fn resolved(&self) -> Hub {
        Hub {
            pid: self.current_pid(),
            current: false,
            ..self.clone()
        }
    }

    fn set_pid(&mut self, pid: Pid) {
        self.pid = pid;
    }
}

/// This thread's hub, resolved to its current process.
fn thread_hub() -> Option<Hub> {
    HUB.with(|hub| hub.borrow().as_ref().map(Hub::resolved))
}

/// The process this thread's scheduler runs, as an immediate pid term: erts' `enif_self` of
/// the built-in `zstd` NIFs reads `esdp->current_process` instead of a per-slice store.
pub(crate) fn scheduler_caller() -> Option<Term> {
    HUB.with(|hub| {
        hub.borrow()
            .as_ref()
            .and_then(|hub| hub.current_pid().to_term())
    })
}

/// The hub of the most recent NIF caller: NIF-created threads and the poller have no
/// thread-local hub, but erts has one global runtime.
static GLOBAL_HUB: Mutex<Option<Hub>> = Mutex::new(None);

fn current_hub() -> Option<Hub> {
    thread_hub().or_else(|| GLOBAL_HUB.lock().unwrap().clone())
}

/// The runtime that owns `pid`: the calling thread's runtime when the pid lives there,
/// else a registered runtime whose process table holds it, else the calling runtime.
// Port of erts/emulator/beam/erl_process.h (erts_proc_lookup on the one process table),
// OTP-29.1.1.
fn hub_for_pid(pid: Pid) -> Option<Hub> {
    let owns = |hub: &Hub| {
        hub.scheduler
            .upgrade()
            .is_some_and(|scheduler| scheduler.lookup(pid))
    };
    let current = current_hub();
    if let Some(hub) = current.as_ref().filter(|hub| owns(hub)) {
        return Some(Hub {
            pid,
            current: false,
            ..hub.clone()
        });
    }
    let registered = RUNTIME_HUBS
        .lock()
        .unwrap()
        .iter()
        .find(|hub| owns(hub))
        .cloned();
    registered.or(current).map(|hub| Hub {
        pid,
        current: false,
        ..hub
    })
}

fn owned_local_pid(term: &arinsal_etf::OwnedTerm) -> Option<Pid> {
    let arinsal_etf::OwnedTerm::Pid {
        node, id, serial, ..
    } = term
    else {
        return None;
    };
    (node == "nonode@nohost").then(|| Pid::new(*id, *serial))
}

struct SelectRegistration {
    id: u64,
    fd: i32,
    readable: bool,
    registration: Option<crate::check_io::Registration>,
}

struct NifSelectReactor {
    next_id: std::sync::atomic::AtomicU64,
    pending: Arc<Mutex<Vec<SelectRegistration>>>,
}

impl Default for NifSelectReactor {
    fn default() -> Self {
        Self {
            next_id: std::sync::atomic::AtomicU64::new(1),
            pending: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

impl arinsal_nif_socket::Reactor for NifSelectReactor {
    fn self_pid(&self) -> Option<arinsal_etf::OwnedTerm> {
        let pid = current_hub()?.current_pid();
        arinsal_term::to_owned(pid.to_term()?).ok()
    }

    fn register_read(
        &self,
        fd: i32,
        pid: &arinsal_etf::OwnedTerm,
        handle: &arinsal_etf::OwnedTerm,
        reference: &arinsal_etf::OwnedTerm,
    ) -> i32 {
        self.register(fd, pid, handle, reference, true)
    }

    fn register_write(
        &self,
        fd: i32,
        pid: &arinsal_etf::OwnedTerm,
        handle: &arinsal_etf::OwnedTerm,
        reference: &arinsal_etf::OwnedTerm,
    ) -> i32 {
        self.register(fd, pid, handle, reference, false)
    }

    fn cancel(&self, fd: i32, read: bool, _reference: &arinsal_etf::OwnedTerm) -> i32 {
        let cancelled = !self
            .remove(|entry| entry.fd == fd && entry.readable == read)
            .is_empty();
        match (cancelled, read) {
            (false, _) => 0,
            (true, true) => arinsal_nif_socket::SELECT_READ_CANCELLED,
            (true, false) => arinsal_nif_socket::SELECT_WRITE_CANCELLED,
        }
    }

    fn stop(&self, fd: i32) -> i32 {
        let removed = self.remove(|entry| entry.fd == fd);
        let mut result = arinsal_nif_socket::SELECT_STOP_CALLED;
        if removed.contains(&true) {
            result |= arinsal_nif_socket::SELECT_READ_CANCELLED;
        }
        if removed.contains(&false) {
            result |= arinsal_nif_socket::SELECT_WRITE_CANCELLED;
        }
        result
    }

    fn monitor(
        &self,
        pid: &arinsal_etf::OwnedTerm,
        make_target: &mut dyn FnMut(u64) -> arinsal_nif::ResourceMonitor,
    ) -> Option<u64> {
        let id = arinsal_sched::unique::next_ref_id();
        let monitor = Arc::new(make_target(id));
        let target = owned_local_pid(pid)?;
        let hub = hub_for_pid(target)?;
        let scheduler = hub.scheduler.upgrade()?;
        let sender = current_hub().map_or(hub.pid, |current| current.current_pid());
        scheduler
            .signal(
                sender,
                target,
                arinsal_sched::Signal::MonitorOpaque {
                    reference: id,
                    shared: Box::new(arinsal_sched::SharedPayload(monitor)),
                },
            )
            .is_ok()
            .then_some(id)
    }

    fn demonitor(&self, pid: &arinsal_etf::OwnedTerm, monitor: u64) {
        let Some(target) = owned_local_pid(pid) else {
            return;
        };
        let Some(hub) = hub_for_pid(target) else {
            return;
        };
        if let Some(scheduler) = hub.scheduler.upgrade() {
            let sender = current_hub().map_or(hub.pid, |current| current.current_pid());
            let _ = scheduler.signal(sender, target, arinsal_sched::Signal::Demonitor(monitor));
        }
    }

    fn send(&self, pid: &arinsal_etf::OwnedTerm, message: &arinsal_etf::OwnedTerm) -> bool {
        let arinsal_etf::OwnedTerm::Pid {
            node, id, serial, ..
        } = pid
        else {
            return false;
        };
        if node != "nonode@nohost" {
            return false;
        }
        let pid = Pid::new(*id, *serial);
        let Some(hub) = hub_for_pid(pid) else {
            return false;
        };
        let Some(scheduler) = hub.scheduler.upgrade() else {
            return false;
        };
        let mut heap = VecHeap::new();
        let Ok(term) = from_owned(message, &mut heap) else {
            return false;
        };
        let Ok(envelope) = Message::copy_from(term) else {
            return false;
        };
        let sender = current_hub().map_or(hub.pid, |current| current.current_pid());
        scheduler.send(sender, pid, envelope).is_ok()
    }
}

impl NifSelectReactor {
    /// Drop the selections `matches` accepts; the result is the `readable` flag of each.
    fn remove(&self, matches: impl Fn(&SelectRegistration) -> bool) -> Vec<bool> {
        let (registrations, removed) = {
            let mut pending = self.pending.lock().unwrap();
            let mut registrations = Vec::new();
            let mut removed = Vec::new();
            pending.retain(|entry| {
                let keep = !matches(entry);
                if !keep {
                    registrations.push(entry.registration);
                    removed.push(entry.readable);
                }
                keep
            });
            (registrations, removed)
        };
        for registration in registrations.into_iter().flatten() {
            crate::check_io::deregister(registration);
        }
        removed
    }

    fn register(
        &self,
        fd: i32,
        pid_term: &arinsal_etf::OwnedTerm,
        handle: &arinsal_etf::OwnedTerm,
        reference: &arinsal_etf::OwnedTerm,
        readable: bool,
    ) -> i32 {
        let failed = i32::MIN | arinsal_nif_socket::SELECT_FAILED;
        let arinsal_etf::OwnedTerm::Pid {
            node, id, serial, ..
        } = pid_term
        else {
            return failed;
        };
        if node != "nonode@nohost" {
            return failed;
        }
        let pid = Pid::new(*id, *serial);
        let Some(hub) = hub_for_pid(pid) else {
            return failed;
        };
        self.remove(|entry| entry.fd == fd && entry.readable == readable);
        let id = self
            .next_id
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.pending.lock().unwrap().push(SelectRegistration {
            id,
            fd,
            readable,
            registration: None,
        });
        let pending = Arc::clone(&self.pending);
        let reference = reference.clone();
        let handle = handle.clone();
        let pid_sender = hub.pid;
        let registration = crate::check_io::register(
            fd,
            crate::check_io::InterestSet {
                readable,
                writable: !readable,
            },
            move |_, _| {
                pending.lock().unwrap().retain(|entry| entry.id != id);
                let Some(scheduler) = hub.scheduler.upgrade() else {
                    return;
                };
                let message = arinsal_nif_socket::select_message(&handle, &reference);
                let mut heap = VecHeap::new();
                let Ok(term) = from_owned(&message, &mut heap) else {
                    return;
                };
                let Ok(envelope) = Message::copy_from(term) else {
                    return;
                };
                let _ = scheduler.send(pid_sender, pid, envelope);
            },
        );
        if let Ok(registration) = registration {
            if let Some(entry) = self
                .pending
                .lock()
                .unwrap()
                .iter_mut()
                .find(|entry| entry.id == id)
            {
                entry.registration = Some(registration);
            }
            0
        } else {
            self.pending.lock().unwrap().retain(|entry| entry.id != id);
            failed
        }
    }
}

thread_local! {
    static HUB: std::cell::RefCell<Option<Hub>> = const { std::cell::RefCell::new(None) };
    /// Runtime whose scheduler `HUB` refers to, so a repeated install can be skipped.
    static HUB_RUNTIME: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    /// Prevents sends made by a trace callback from recursively tracing that callback.
    static DIRTY_TRACE_EMISSION: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

struct DirtyTraceEmissionGuard;

impl Drop for DirtyTraceEmissionGuard {
    fn drop(&mut self) {
        DIRTY_TRACE_EMISSION.set(false);
    }
}

/// Run a dirty-scheduler trace callback without recursively tracing sends it makes.
pub(crate) fn with_dirty_trace_emission<R>(run: impl FnOnce() -> R) -> Option<R> {
    let entered = DIRTY_TRACE_EMISSION.with(|emitting| {
        if emitting.get() {
            false
        } else {
            emitting.set(true);
            true
        }
    });
    if !entered {
        return None;
    }
    let _guard = DirtyTraceEmissionGuard;
    Some(run())
}

fn badarg() -> VmError {
    VmError::Trap(crate::exceptions::Trap::error(Term::atom(
        arinsal_term::atoms::BADARG,
    )))
}

fn alloc(error: impl std::fmt::Debug) -> VmError {
    VmError::Unsupported(format!("nif term: {error:?}"))
}

fn tuple(process: &mut Process, items: &[Term]) -> Result<Term, VmError> {
    let mut heap = ProcessHeapHandle(&mut process.heap);
    TermBuilder::new(&mut heap).tuple(items).map_err(alloc)
}

fn charlist(process: &mut Process, text: &str) -> Result<Term, VmError> {
    let mut heap = ProcessHeapHandle(&mut process.heap);
    let mut builder = TermBuilder::new(&mut heap);
    let mut list = Term::NIL;
    for ch in text.chars().rev() {
        let small = Term::small(ch as i64).ok_or_else(|| alloc(ch))?;
        list = builder.cons(small, list).map_err(alloc)?;
    }
    Ok(list)
}

fn error_reason(process: &mut Process, reason: &str, message: &str) -> Result<Term, VmError> {
    let message = charlist(process, message)?;
    let inner = tuple(process, &[crate::atom_cache::put(reason), message])?;
    tuple(process, &[Term::atom(arinsal_term::atoms::ERROR), inner])
}

fn cons_pair(term: Term) -> Option<(Term, Term)> {
    if term.classify() != TermKind::List {
        return None;
    }
    // SAFETY: the caller keeps this process heap stable for the BIF call.
    unsafe { term.cons_ref() }
}

fn filename_bytes(term: Term) -> Option<Vec<u8>> {
    if term == Term::NIL {
        return Some(Vec::new());
    }
    // SAFETY: a binary view is copied before the heap can move.
    if let Some(bytes) = unsafe { term.binary_ref() } {
        return Some(bytes.bytes().to_vec());
    }
    if term.classify() != TermKind::List {
        return None;
    }
    let mut points = Vec::new();
    let mut tail = term;
    while let Some((head, next)) = cons_pair(tail) {
        let point = head.as_small()?;
        let point = u32::try_from(point).ok()?;
        points.push(char::from_u32(point)?);
        tail = next;
    }
    if tail != Term::NIL {
        return None;
    }
    let mut bytes = Vec::new();
    for ch in points {
        let mut buf = [0_u8; 4];
        bytes.extend(ch.encode_utf8(&mut buf).as_bytes());
    }
    Some(bytes)
}

/// The functions `module` declares as NIF stubs: those whose code starts with `nif_start`, or
/// `None` when the module has no `nif_start` at all, in which case any function may become a NIF.
// Port of erts/emulator/beam/erl_nif.c:4700-4704 (check_is_nifable: `!are_nifs ||
// are_nifs[func_ix]`) with `are_nifs` from erts/emulator/beam/jit/asm_load.c:651-661 (allocated
// at the first `nif_start`, NULL without one), OTP-29.1.1. The loaded module is the source, not
// a beam file on a path, so a module loaded from a binary works.
fn declared_nifs(module: &arinsal_loader::Module) -> Option<HashSet<(String, u8)>> {
    module.nif_stubs.as_ref().map(|stubs| {
        stubs
            .iter()
            .map(|(name, arity)| ((*name).to_owned(), *arity))
            .collect()
    })
}

/// The outcome of one NIF call for the native-call boundary of a tracer callback:
/// `THE_NON_VALUE` carries the exception `enif_raise_exception` left in `c_p->freason` /
/// `fvalue` (beam_jit_call_nif, beam_jit_common.cpp:623-677, OTP-29.1.1).
fn nif_outcome(heap: &arinsal_term::ProcessHeap, value: Term) -> Result<Term, BifError> {
    if !value.is_non_value() {
        return Ok(value);
    }
    Err(match heap.abi.exc.freason {
        arinsal_term::exc::EXC_BADARG => BifError::BADARG,
        _ => BifError::Error(crate::native_hooks::from_raw(heap.abi.exc.fvalue)),
    })
}

/// `nfunc_cleanup_nif_mod`: drop the wrapper's `dynlib_refc` reference to its library.
// Port of erts/emulator/beam/erl_nif.c:3360-3375 (nfunc_cleanup_nif_mod,
// erts_nfunc_cleanup_nif_mod), OTP-29.1.1.
pub(crate) fn erts_nfunc_cleanup_nif_mod(ep: &mut crate::erl_nfunc_sched::ErtsNativeFunc) {
    let lib = crate::natives::raw::nif_mod_from_raw(std::mem::take(&mut ep.m));
    lib.dynlib_deref();
}

/// Port of erts/emulator/beam/erl_nif.c:3377-3383 (nfunc_restore), OTP-29.1.1.
fn nfunc_restore(c_p: &mut Process, ep: *mut crate::erl_nfunc_sched::ErtsNativeFunc) {
    let ep = crate::erl_nfunc_sched::nfunc_at(ep);
    crate::erl_nfunc_sched::erts_nfunc_restore(&mut c_p.heap.abi.current, ep);
    erts_nfunc_cleanup_nif_mod(ep);
}

/// The wrapper `c_p->current` is the trampoline MFA of:
/// `ErtsContainerStruct(proc->current, ErtsNativeFunc, trampoline.info.mfa)`.
fn current_nfunc(c_p: &Process) -> *mut crate::erl_nfunc_sched::ErtsNativeFunc {
    let mfa_offset =
        std::mem::offset_of!(crate::erl_nfunc_sched::ErtsNativeFunc, trampoline.info.mfa);
    (c_p.heap.abi.current as usize - mfa_offset) as *mut _
}

/// `execution_state(env, &c_p, NULL)` on a normal scheduler: the process of the running NIF.
fn current_proc<'a>() -> Option<&'a mut Process> {
    let current = current_nif()?;
    crate::natives::raw::current_nif_proc(current.c_p)
}

/// `erts_atomic32_read_bset_nob(&proc->state, DIRTY_CPU_PROC | DIRTY_IO_PROC, flag)` on the
/// state word of the process running on this normal scheduler.
fn bset_running_dirty_psflg(c_p: &mut Process, flag: u32) {
    arinsal_sched::erts_proc_sched_data(c_p, |_, esdp| {
        arinsal_sched::RunCtx::with_current(esdp, |ctx| bset_dirty_bits(ctx.proc_state(), flag))
    });
}

fn bset_dirty_bits(state: &std::sync::atomic::AtomicU32, flag: u32) {
    use arinsal_sched::psflg;
    let _ = state.fetch_update(
        std::sync::atomic::Ordering::AcqRel,
        std::sync::atomic::Ordering::Acquire,
        |word| Some((word & !(psflg::DIRTY_CPU_PROC | psflg::DIRTY_IO_PROC)) | flag),
    );
}

/// [`bset_running_dirty_psflg`] for a process that is not running on this thread (its dirty
/// job, or the dirty scheduler that takes the job), through the process table.
fn bset_dirty_psflg(
    runtime: Option<&'static crate::process::Runtime>,
    pid: Option<Pid>,
    flag: u32,
) {
    let (Some(runtime), Some(pid)) = (runtime, pid) else {
        return;
    };
    if let Ok(scheduler) = runtime.scheduler() {
        scheduler.with_proc_state(pid, |state| bset_dirty_bits(state, flag));
    }
}

/// Schedule `direct_fp` (called by `call_nif` through the wrapper's trampoline, with
/// `indirect_fp` as the function it calls) as the process's next call.
// Port of erts/emulator/beam/erl_nif.c:367-404 (schedule), OTP-29.1.1.
fn schedule(
    direct_fp: usize,
    indirect_fp: usize,
    (module, func_name): (Term, Term),
    argv: &[Term],
) -> Term {
    let Some(current) = current_nif() else {
        return Term::NON_VALUE;
    };
    let instr = arinsal_term::OP_CALL_NIF_WWW;
    let reg = crate::natives::raw::current_nif_reg(current.reg, current.reg_len);
    let nep = match current.dirty {
        None => {
            let Some(c_p) = crate::natives::raw::current_nif_proc(current.c_p) else {
                return Term::NON_VALUE;
            };
            // erts_inspect_frame(c_p->stop, &caller): the continuation on top of the stack.
            let caller = c_p
                .heap
                .stack_get(0)
                .map_or(0, |word| word.tagged_word() as usize);
            let mfa = c_p.heap.abi.current.cast::<arinsal_term::ErtsCodeMfa>();
            crate::bif_traps::vbump_all_reds(c_p);
            let arity = crate::natives::raw::code_mfa(mfa as usize).arity;
            let nep = crate::erl_nfunc_sched::erts_get_proc_nfunc(c_p, arity).as_ptr();
            let abi = &mut c_p.heap.abi;
            let nep_ref = crate::erl_nfunc_sched::nfunc_at(nep);
            let saved = crate::erl_nfunc_sched::nfunc_argv(nep);
            crate::erl_nfunc_sched::erts_nfunc_schedule(
                nep_ref,
                Some((
                    saved,
                    crate::natives::raw::code_mfa(mfa as usize),
                    caller,
                    mfa,
                )),
                crate::erl_nfunc_sched::UsedProc {
                    i: &mut abi.i,
                    arity: &mut abi.arity,
                    freason: &mut abi.exc.freason,
                },
                reg,
                (instr, direct_fp, indirect_fp),
                (module, func_name),
                argv,
            );
            nep
        }
        Some(dirty) => {
            let shadow = crate::natives::raw::shadow_heap(dirty.shadow);
            let abi = &mut shadow.abi;
            crate::erl_nfunc_sched::erts_nfunc_schedule(
                crate::erl_nfunc_sched::nfunc_at(dirty.nep),
                None,
                crate::erl_nfunc_sched::UsedProc {
                    i: &mut abi.i,
                    arity: &mut abi.arity,
                    freason: &mut abi.exc.freason,
                },
                reg,
                (instr, direct_fp, indirect_fp),
                (module, func_name),
                argv,
            );
            dirty.nep
        }
    };
    let ep = crate::erl_nfunc_sched::nfunc_at(nep);
    if ep.m == 0 {
        // First time this call is scheduled: erts_refc_inc(&env->mod_nif->dynlib_refc, 2).
        let lib = crate::natives::raw::nif_mod(current.mod_nif);
        lib.dynlib_refc
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        ep.m = Arc::into_raw(lib) as usize;
    }
    Term::NON_VALUE
}

/// NIF execution wrapper used by `enif_schedule_nif` for regular NIFs: it calls the actual
/// NIF, restores the original NIF MFA once it is done, and returns the NIF result.
// Port of erts/emulator/beam/erl_nif.c:3485-3537 (execute_nif), OTP-29.1.1.
extern "C" fn execute_nif(
    env: *mut arinsal_nif::ErlNifEnv,
    argc: std::ffi::c_int,
    argv: *const Term,
) -> Term {
    let Some(proc) = current_proc() else {
        return Term::NON_VALUE;
    };
    let ep = current_nfunc(proc);
    let fp = crate::erl_nfunc_sched::nfunc_at(ep).func;
    let result = crate::natives::raw::call_nif_fn(fp, env, argc, argv);
    let Some(proc) = current_proc() else {
        return result;
    };
    if !result.is_non_value() || proc.heap.abi.exc.freason != arinsal_term::exc::TRAP {
        // Done (not rescheduled).
        if arinsal_nif::enif_has_pending_exception(env, std::ptr::null_mut()) == 0 {
            nfunc_restore(proc, ep);
        } else {
            erts_nfunc_cleanup_nif_mod(crate::erl_nfunc_sched::nfunc_at(ep));
            // Restore the original info for the error and clear the wrapper in handle_error().
            proc.heap.abi.exc.freason |= arinsal_term::exc::EXF_RESTORE_NFUNC;
        }
    }
    result
}

/// Finalize a dirty NIF call on the normal scheduler the process returned to.
// Port of erts/emulator/beam/erl_nif.c:3385-3407 (dirty_nif_finalizer), OTP-29.1.1.
extern "C" fn dirty_nif_finalizer(
    _env: *mut arinsal_nif::ErlNifEnv,
    _argc: std::ffi::c_int,
    argv: *const Term,
) -> Term {
    let Some(proc) = current_proc() else {
        return Term::NON_VALUE;
    };
    let result = crate::natives::raw::nif_argv(argv, 1)[0];
    let ep = crate::erl_nfunc_sched::get_nfunc_trap_wrapper(proc)
        .expect("dirty_nif_finalizer with a wrapper")
        .as_ptr();
    nfunc_restore(proc, ep);
    result
}

/// Finalize a dirty NIF call that raised an exception.
// Port of erts/emulator/beam/erl_nif.c:3409-3433 (dirty_nif_exception), OTP-29.1.1.
extern "C" fn dirty_nif_exception(
    env: *mut arinsal_nif::ErlNifEnv,
    _argc: std::ffi::c_int,
    argv: *const Term,
) -> Term {
    let Some(proc) = current_proc() else {
        return Term::NON_VALUE;
    };
    let exception = crate::natives::raw::nif_argv(argv, 1)[0];
    let ep = crate::erl_nfunc_sched::get_nfunc_trap_wrapper(proc)
        .expect("dirty_nif_exception with a wrapper");
    erts_nfunc_cleanup_nif_mod(ep.get_mut());
    let ret = arinsal_nif::enif_raise_exception(env, exception);
    // Restore the original info for the error and clear the wrapper in handle_error().
    proc.heap.abi.exc.freason |= arinsal_term::exc::EXF_RESTORE_NFUNC;
    ret
}

/// Schedules the dirty NIF of the function the process was called through on a dirty
/// scheduler: the `call_nif` code of a dirty NIF calls these as its normal function.
// Port of erts/emulator/beam/erl_nif.c:3435-3483 (static_schedule_dirty_nif,
// static_schedule_dirty_io_nif, static_schedule_dirty_cpu_nif), OTP-29.1.1: `current` points
// into code laid out like an `ErtsNativeFunc`, whose `func` is the dirty NIF.
fn static_schedule_dirty_nif(dirty_psflg: u32, argc: std::ffi::c_int, argv: *const Term) -> Term {
    let Some(proc) = current_proc() else {
        return Term::NON_VALUE;
    };
    let current = proc.heap.abi.current as usize;
    let mfa = crate::natives::raw::code_mfa(current);
    let (module, func) = (
        crate::native_hooks::from_raw(mfa.module),
        crate::native_hooks::from_raw(mfa.function),
    );
    let fp = crate::erl_nfunc_sched::container_func(current);
    bset_running_dirty_psflg(proc, dirty_psflg);
    let argv = crate::natives::raw::nif_argv(argv, argc.max(0) as usize).to_vec();
    schedule(fp, 0, (module, func), &argv)
}

extern "C" fn static_schedule_dirty_io_nif(
    _env: *mut arinsal_nif::ErlNifEnv,
    argc: std::ffi::c_int,
    argv: *const Term,
) -> Term {
    static_schedule_dirty_nif(arinsal_sched::psflg::DIRTY_IO_PROC, argc, argv)
}

extern "C" fn static_schedule_dirty_cpu_nif(
    _env: *mut arinsal_nif::ErlNifEnv,
    argc: std::ffi::c_int,
    argv: *const Term,
) -> Term {
    static_schedule_dirty_nif(arinsal_sched::psflg::DIRTY_CPU_PROC, argc, argv)
}

/// `MAX_ARG` (erl_vm.h).
const MAX_ARG: std::ffi::c_int = 255;

/// Port of erts/emulator/beam/erl_nif.c:3539-3583 (enif_schedule_nif), OTP-29.1.1.
#[unsafe(no_mangle)]
pub extern "C" fn enif_schedule_nif(
    env: *mut arinsal_nif::ErlNifEnv,
    fun_name: *const std::ffi::c_char,
    flags: std::ffi::c_int,
    fp: Option<arinsal_nif::NifFn>,
    argc: std::ffi::c_int,
    argv: *const Term,
) -> Term {
    if !(0..=MAX_ARG).contains(&argc) {
        return arinsal_nif::enif_make_badarg(env);
    }
    let fun_name_atom = arinsal_nif::enif_make_atom(env, fun_name);
    if arinsal_nif::enif_is_exception(env, fun_name_atom) != 0 {
        return fun_name_atom;
    }
    let Some(current) = current_nif() else {
        // `scheduler == 0`: not called from a NIF of a process.
        return arinsal_nif::enif_make_badarg(env);
    };
    let (module, dirty) = match current.dirty {
        None => {
            let Some(proc) = crate::natives::raw::current_nif_proc(current.c_p) else {
                return arinsal_nif::enif_make_badarg(env);
            };
            (
                crate::natives::raw::code_mfa(proc.heap.abi.current as usize).module,
                None,
            )
        }
        Some(dirty) => (
            crate::natives::raw::code_mfa(dirty.current as usize).module,
            Some((dirty.runtime, dirty.pid)),
        ),
    };
    let module = crate::native_hooks::from_raw(module);
    let fp = fp.map_or(0, |fp| fp as usize);
    let argv = crate::natives::raw::nif_argv(argv, argc as usize).to_vec();
    let dirty_bits =
        arinsal_nif::ERL_NIF_DIRTY_JOB_IO_BOUND | arinsal_nif::ERL_NIF_DIRTY_JOB_CPU_BOUND;
    let flags = flags as u32;
    if flags == 0 {
        schedule(
            execute_nif as *const () as usize,
            fp,
            (module, fun_name_atom),
            &argv,
        )
    } else if flags & !dirty_bits == 0 {
        let flag = if flags == arinsal_nif::ERL_NIF_DIRTY_JOB_CPU_BOUND {
            arinsal_sched::psflg::DIRTY_CPU_PROC
        } else {
            arinsal_sched::psflg::DIRTY_IO_PROC
        };
        match dirty {
            None => match crate::natives::raw::current_nif_proc(current.c_p) {
                Some(proc) => bset_running_dirty_psflg(proc, flag),
                None => return arinsal_nif::enif_make_badarg(env),
            },
            Some((runtime, pid)) => bset_dirty_psflg(runtime, pid, flag),
        }
        schedule(fp, 0, (module, fun_name_atom), &argv)
    } else {
        arinsal_nif::enif_make_badarg(env)
    }
}

/// A dirty NIF call taken by a dirty scheduler: the wrapper's `dfunc` with the argument
/// registers, run without the process.
// Port of erts/emulator/beam/erl_nif.c:425-520 (erts_call_dirty_nif), OTP-29.1.1.
pub(crate) struct DirtyNifJob {
    nep: crate::erl_nfunc_sched::NfuncPtr,
    lib: Arc<ModuleNif>,
    dirty_nif: usize,
    args: Vec<Term>,
    current: usize,
    runtime: Option<&'static crate::process::Runtime>,
    pid: Option<Pid>,
}

/// What the dirty NIF left for `erts_call_dirty_nif` to schedule on the process.
pub(crate) enum DirtyNifResult {
    /// `env.exception_thrown`: `dirty_nif_exception(fvalue)`.
    Exception(Term),
    /// A value: `dirty_nif_finalizer(result)`.
    Value(Term),
    /// The NIF rescheduled itself: the shadow's `i`, `arity` and argument registers.
    Rescheduled { i: usize, reg: Vec<Term> },
    /// `THE_NON_VALUE` without TRAP: `badreturn`.
    BadReturn,
}

impl DirtyNifJob {
    /// The job for the call at `c_p->i` (a wrapper trampoline) with arguments `args`.
    pub(crate) fn new(process: &mut Process) -> Option<Self> {
        let i = process.heap.abi.i as usize;
        let nep = crate::erl_nfunc_sched::i_beam_op_to_nfunc(i);
        let ep = crate::erl_nfunc_sched::nfunc_at(nep);
        let arity = ep.trampoline.info.mfa.arity;
        let lib = crate::natives::raw::nif_mod(ep.m);
        let args = process.x.get(..arity)?.to_vec();
        // erts_atomic32_read_band_mb(&c_p->state, ~(DIRTY_CPU_PROC | DIRTY_IO_PROC)).
        bset_dirty_psflg(process.runtime, process.self_pid(), 0);
        refresh_hub_native(process);
        Some(Self {
            nep: crate::erl_nfunc_sched::NfuncPtr(nep),
            lib,
            dirty_nif: ep.trampoline.dfunc,
            args,
            current: process.heap.abi.current as usize,
            runtime: process.runtime,
            pid: process.self_pid(),
        })
    }

    /// Call the dirty NIF on the shadow heap `shadow`.
    pub(crate) fn run(self, shadow: &mut arinsal_term::ProcessHeap) -> DirtyNifResult {
        let Some(fptr) = crate::natives::raw::nif_fptr(self.dirty_nif) else {
            return DirtyNifResult::BadReturn;
        };
        shadow.abi.exc.freason = 0;
        shadow.abi.exc.fvalue = crate::native_hooks::raw(Term::NIL);
        shadow.abi.exc.ftrace = crate::native_hooks::raw(Term::NIL);
        let mut reg = vec![Term::NIL; MAX_ARG as usize + 1];
        let pid = thread_hub().and_then(|hub| hub.pid.to_term());
        let current = CurrentNif {
            c_p: std::ptr::null_mut(),
            reg: reg.as_mut_ptr(),
            reg_len: reg.len(),
            mod_nif: Arc::as_ptr(&self.lib) as usize,
            dirty: Some(DirtyNifCall {
                nep: self.nep.0,
                shadow: std::ptr::from_mut(shadow),
                current: self.current as *const _,
                runtime: self.runtime,
                pid: self.pid,
            }),
        };
        let result = with_current_nif(current, || {
            self.lib.library.call(
                shadow,
                (fptr, self.args.as_ptr(), self.args.len()),
                pid,
                true,
            )
        });
        if !result.is_non_value() {
            DirtyNifResult::Value(result)
        } else if shadow.abi.exc.freason == arinsal_term::exc::TRAP {
            // Rescheduled by the dirty NIF call.
            let arity = usize::from(shadow.abi.arity);
            reg.truncate(arity);
            DirtyNifResult::Rescheduled {
                i: shadow.abi.i as usize,
                reg,
            }
        } else if shadow.abi.exc.freason != 0 {
            DirtyNifResult::Exception(crate::native_hooks::from_raw(shadow.abi.exc.fvalue))
        } else {
            DirtyNifResult::BadReturn
        }
    }
}

/// The part of `erts_call_dirty_nif` after the call, with the process locked again:
/// schedule `dirty_nif_finalizer` or `dirty_nif_exception`, or take the call the NIF
/// rescheduled, into `c_p->i`, `c_p->arity` and the argument registers.
// Port of erts/emulator/beam/erl_nif.c:483-516 (erts_call_dirty_nif), OTP-29.1.1.
pub(crate) fn erts_call_dirty_nif_finish(c_p: &mut Process, result: DirtyNifResult) {
    if c_p.dirty_exiting() {
        return;
    }
    let atom = |name: &str| {
        Term::atom(
            arinsal_term::global_atoms()
                .intern(name)
                .expect("dirty NIF atom"),
        )
    };
    let (fp, name, value) = match result {
        DirtyNifResult::Rescheduled { i, reg } => {
            c_p.heap.abi.i = i as *const _;
            c_p.heap.abi.arity = reg.len() as u8;
            c_p.x.ensure_x(reg.len());
            c_p.x[..reg.len()].copy_from_slice(&reg);
            return;
        }
        DirtyNifResult::Exception(fvalue) => (
            dirty_nif_exception as *const () as usize,
            "dirty_nif_exception",
            fvalue,
        ),
        DirtyNifResult::Value(value) => (
            dirty_nif_finalizer as *const () as usize,
            "dirty_nif_finalizer",
            value,
        ),
        // User returned garbage: enif_raise_exception(&env, badreturn).
        DirtyNifResult::BadReturn => (
            dirty_nif_exception as *const () as usize,
            "dirty_nif_exception",
            atom("badreturn"),
        ),
    };
    let Some(nep) = crate::erl_nfunc_sched::get_nfunc_trap_wrapper(c_p).map(|nep| nep.as_ptr())
    else {
        return;
    };
    c_p.x.ensure_x(1);
    let mut shadow_freason = 0;
    let abi = &mut c_p.heap.abi;
    crate::erl_nfunc_sched::erts_nfunc_schedule(
        crate::erl_nfunc_sched::nfunc_at(nep),
        None,
        crate::erl_nfunc_sched::UsedProc {
            i: &mut abi.i,
            arity: &mut abi.arity,
            // `env.proc` is the shadow process: its TRAP stays there; only `i` and `arity`
            // move to `c_p`.
            freason: &mut shadow_freason,
        },
        &mut c_p.x[..],
        (arinsal_term::OP_CALL_NIF_WWW, fp, 0),
        (atom("erts_internal"), atom(name)),
        &[value],
    );
}
/// Invoke one patched tracer NIF synchronously on the tracee's scheduler.
pub(crate) fn invoke_tracer(
    process: &mut Process,
    module: &str,
    function: &str,
    specialized: Option<&str>,
    args: &[Term],
) -> Option<Term> {
    let arity = u8::try_from(args.len()).ok()?;
    let native = specialized
        .and_then(|specialized| tracer_callback(module, specialized, arity))
        .or_else(|| tracer_callback(module, function, arity))?;
    call_native(&mut process.heap, &native, args).ok()
}

pub(crate) fn has_tracer_nifs(module_name: &str) -> bool {
    tracer_callback(module_name, "enabled", 3).is_some()
        && tracer_callback(module_name, "trace", 5).is_some()
}

/// Binds the NIF library `key` to its module instance in the active code index.
// Port of erts/emulator/beam/erl_nif.c:4748 (load_nif: `module_p->curr.nif`), OTP-29.1.1.
fn publish(key: &str) {
    crate::code_ix::global().update_active(|tables| {
        tables.loaded_nifs.insert(key.to_owned());
    });
}

fn patch_native(module: &arinsal_loader::Module, entry: usize, index: u32) -> Result<(), VmError> {
    let slot = entry.saturating_add(1);
    let Some(ordinal) = module.function_by_entry(slot) else {
        return Err(VmError::Unsupported("nif entry".into()));
    };
    module.set_nif_body(ordinal, index);
    Ok(())
}

fn push_native(function: NativeFn) -> Result<u32, VmError> {
    crate::code_ix::global()
        .push_native_fn(function)
        .ok_or_else(|| VmError::Unsupported("native table".into()))
}

fn nif_open_error(
    process: &mut Process,
    path: &[u8],
    error: arinsal_nif::NifError,
) -> Result<Term, VmError> {
    let message = match error {
        arinsal_nif::NifError::Link(detail) => {
            let text = if detail
                .as_bytes()
                .windows(path.len())
                .any(|window| window == path)
            {
                format!("Failed to load NIF library: '{detail}'")
            } else {
                format!(
                    "Failed to load NIF library {}: '{detail}'",
                    String::from_utf8_lossy(path)
                )
            };
            return error_reason(process, "load_failed", &text);
        }
        arinsal_nif::NifError::MissingInit(detail) => {
            format!("Failed to find library init function: '{detail}'")
        }
        arinsal_nif::NifError::BadLibrary(detail) => detail,
        arinsal_nif::NifError::LoadRejected(code) => {
            return error_reason(
                process,
                "load",
                &format!("Library load-call unsuccessful ({code})."),
            );
        }
        arinsal_nif::NifError::UpgradeUnsupported => {
            return error_reason(
                process,
                "upgrade",
                "Upgrade not supported by this NIF library.",
            );
        }
        arinsal_nif::NifError::UpgradeRejected(code) => {
            return error_reason(
                process,
                "upgrade",
                &format!("Library upgrade-call unsuccessful ({code})."),
            );
        }
    };
    error_reason(process, "bad_lib", &message)
}

fn validate_image(
    module_id: usize,
    caller: &str,
    image: &arinsal_nif::NifImage,
) -> Result<Vec<(usize, usize)>, String> {
    let module = code_tables(erts_active_code_ix())
        .modules
        .get(module_id)
        .ok_or_else(|| format!("module {caller} is not loaded"))?;
    let declared = declared_nifs(module);
    let mut seen = HashSet::new();
    let mut binds = Vec::new();
    for (index, function) in image.functions().iter().enumerate() {
        let Some(arity) = u8::try_from(function.arity).ok() else {
            return Err(format!(
                "Function not found {caller}:{}/{}",
                function.name, function.arity
            ));
        };
        let Some(entry) = module.functions.iter().find_map(|(entry, name, found)| {
            (*name == function.name && *found == arity).then_some(*entry)
        }) else {
            return Err(format!(
                "Function not found {caller}:{}/{}",
                function.name, function.arity
            ));
        };
        if declared
            .as_ref()
            .is_some_and(|declared| !declared.contains(&(function.name.clone(), arity)))
        {
            return Err(format!(
                "Function not declared as nif {caller}:{}/{}",
                function.name, function.arity
            ));
        }
        if !matches!(function.flags, 0..=2) {
            return Err(format!(
                "Illegal flags field value {} for NIF {caller}:{}/{}",
                function.flags, function.name, function.arity
            ));
        }
        if !seen.insert((function.name.clone(), arity)) {
            return Err(format!(
                "Duplicate NIF entry for {caller}:{}/{}",
                function.name, function.arity
            ));
        }
        binds.push((entry, index));
    }
    Ok(binds)
}

/// Bind the functions of `library`, loaded for module instance `module_id`, to the code they
/// replace and make them callable.
// Port of erts/emulator/beam/erl_nif.c:4840-4942 (the ErtsNifBeamStub of every function, built
// by beamasm_emit_call_nif and hashed in erts_nif_call_tab) and 4993-5011 (`this_mi->nif =
// lib`, patch_call_nif_early under erts_nif_call_tab_lock, then the code barrier to
// load_nif_1st_finisher), OTP-29.1.1. Functions without native code run in the interpreter,
// whose entries get the library's `NifBinding` under the same lock.
fn install_stubs(
    module_id: usize,
    library: arinsal_nif::NifLibrary,
    binds: &[(usize, usize)],
    scheduler: Weak<Scheduler<Process>>,
) -> Result<(), VmError> {
    // The library resolves `enif_schedule_nif` from this binary's dynamic symbols.
    std::hint::black_box(enif_schedule_nif as *const () as usize);
    let lib = Arc::new(ModuleNif {
        library,
        owner: module_id,
        dynlib_refc: std::sync::atomic::AtomicUsize::new(1),
        publishing: std::sync::atomic::AtomicBool::new(true),
        scheduler,
        finish: Mutex::new(None),
        barrier: crate::code_ix::ErtsCodeBarrier::new(),
    });
    let result = finish_stubs(module_id, &lib, binds);
    match result {
        Ok(()) => {
            // Port of erts/emulator/beam/erl_nif.c:4997 (`prepare_opened_rt`): the resource
            // types the load callback opened become live and reference the library.
            lib.library
                .commit_resource_types(&(Arc::new(ModuleRefs(Arc::clone(&lib))) as Arc<_>));
            MODULE_NIFS
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .push(Arc::clone(&lib));
            // Port of erts/emulator/beam/erl_nif.c:5004-5011 (erts_load_nif), OTP-29.1.1:
            // no process may run the functions being patched, and the call_nif_early
            // breakpoints must be in effect, before the module code is patched.
            erts_schedule_code_barrier(&lib, load_nif_1st_finisher);
        }
        // Port of erts/emulator/beam/erl_nif.c:5019-5031 (erts_load_nif error path), OTP-29.1.1:
        // a library that did not get bound is released.
        Err(_) => {
            release_beam_stubs(&lib);
            lib.dynlib_deref();
        }
    }
    result
}

fn finish_stubs(
    module_id: usize,
    lib: &Arc<ModuleNif>,
    binds: &[(usize, usize)],
) -> Result<(), VmError> {
    let module = Arc::clone(&code_tables(erts_active_code_ix()).modules[module_id]);
    let version = native_version(module_id);
    let mut interpreted = Vec::new();
    let mut beam_stubv = Vec::new();
    for &(entry, index) in binds {
        let function = lib.function(index).map_err(|_| badarg())?;
        let (_, name, arity) = module
            .functions
            .iter()
            .find(|(start, _, _)| *start == entry)
            .ok_or_else(|| VmError::Unsupported("nif entry".into()))?;
        let code_info = version.as_ref().and_then(|version| {
            let atom = arinsal_term::global_atoms().get(name)?;
            version.code_info(atom, *arity)
        });
        match code_info {
            Some(ci) => beam_stubv.push(beam_stub(ci, lib, function)?),
            None => {
                let binding = NativeFn::Nif(NifBinding {
                    lib: Arc::clone(lib),
                    index: u32::try_from(index)
                        .map_err(|_| VmError::Unsupported("nif index".into()))?,
                });
                interpreted.push((entry, push_native(binding)?));
            }
        }
    }
    if let Some(version) = version.filter(|_| !beam_stubv.is_empty()) {
        {
            let mut tab = ERTS_NIF_CALL_TAB
                .write()
                .unwrap_or_else(|poison| poison.into_inner());
            for stub in &beam_stubv {
                let address = std::ptr::from_ref::<ErtsNifBeamStub>(stub) as usize;
                if tab.insert(stub.code_info_ptr, address).is_some() {
                    return Err(VmError::Unsupported("duplicate NIF stub".into()));
                }
            }
        }
        *lib.finish
            .lock()
            .unwrap_or_else(|poison| poison.into_inner()) = Some(ErtsNifFinish {
            version,
            beam_stubv,
        });
    }
    // patch_call_nif_early: under the call table lock every function becomes callable at once.
    let _publication = ERTS_NIF_CALL_TAB
        .write()
        .unwrap_or_else(|poison| poison.into_inner());
    if let Some(finish) = &*lib
        .finish
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
    {
        for stub in &finish.beam_stubv {
            finish.version.erts_asm_bp_set_flag(
                stub.code_info_ptr,
                arinsal_beamasm::common::beam_asm_h::ERTS_ASM_BP_FLAG_CALL_NIF_EARLY,
            );
        }
    }
    for (entry, body) in interpreted {
        patch_native(&module, entry, body)?;
    }
    lib.publishing
        .store(false, std::sync::atomic::Ordering::Release);
    Ok(())
}

/// The stub of `function`, whose native code begins at the `ErtsCodeInfo` `ci`.
// Port of erts/emulator/beam/erl_nif.c:4890-4938 (`stub->info = *ci` and
// beamasm_emit_call_nif with static_schedule_dirty_{io,cpu}_nif for a dirty NIF), OTP-29.1.1.
fn beam_stub(
    ci: usize,
    lib: &Arc<ModuleNif>,
    function: &arinsal_nif::NifFunction,
) -> Result<Box<ErtsNifBeamStub>, VmError> {
    let (normal_fptr, dirty_fptr) = match function.flags {
        0 => (function.fptr as usize, 0),
        arinsal_nif::ERL_NIF_DIRTY_JOB_IO_BOUND => (
            static_schedule_dirty_io_nif as *const () as usize,
            function.fptr as usize,
        ),
        _ => (
            static_schedule_dirty_cpu_nif as *const () as usize,
            function.fptr as usize,
        ),
    };
    let mut stub = Box::new(ErtsNifBeamStub {
        code_info_ptr: ci,
        info: [0; FUNC_INFO_BYTES + NIF_STUB_CODE_BYTES],
    });
    crate::beam_jit_main::beamasm_emit_call_nif(
        crate::natives::raw::code_info(ci),
        (normal_fptr, Arc::as_ptr(lib) as usize, dirty_fptr),
        &mut stub.info,
    )?;
    Ok(stub)
}

/// Runs `later_function` once every scheduler passed a code barrier: no process still executes
/// code patched before it, and every scheduler sees the code written before it.
// Port of erts/emulator/beam/code_ix.c:558-575 (erts_schedule_code_barrier, scheduled as a
// thread progress later op), OTP-29.1.1. Without schedulers (`Vm::eval`) nothing else runs
// code, so the function runs at once.
fn erts_schedule_code_barrier(lib: &ModuleNif, later_function: fn(*mut ())) {
    let later_data = lib as *const ModuleNif as *mut ();
    match lib.scheduler.upgrade() {
        Some(scheduler) => crate::code_ix::erts_schedule_code_barrier(
            &scheduler,
            &lib.barrier,
            later_function,
            later_data,
        ),
        None => later_function(later_data),
    }
}

/// Copies the `call_nif` code of every stub over the body of its function, behind the
/// breakpoint trampoline.
// Port of erts/emulator/beam/erl_nif.c:5124-5203 (load_nif_1st_finisher), OTP-29.1.1.
fn load_nif_1st_finisher(data: *mut ()) {
    let lib = crate::code_ix::later_data::<ModuleNif>(data);
    let fin = lib
        .finish
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    if let Some(fin) = &*fin {
        for stub in &fin.beam_stubv {
            fin.version.copy_call_nif(
                stub.code_info_ptr,
                &stub.info[FUNC_INFO_BYTES..],
                arinsal_beamasm::common::beam_asm_h::BEAM_ASM_FUNC_PROLOGUE_SIZE,
            );
        }
    }
    let unloaded = fin.is_none();
    drop(fin);
    // Unloaded: the Arc of the later op is the reference erts drops with deref_nifmod.
    if !unloaded {
        // The `call_nif` code is visible before the breakpoints are disabled.
        erts_schedule_code_barrier(lib, load_nif_2nd_finisher);
    }
}

/// Clears the `call_nif_early` breakpoint flag of every function.
// Port of erts/emulator/beam/erl_nif.c:5205-5275 (load_nif_2nd_finisher), OTP-29.1.1.
fn load_nif_2nd_finisher(data: *mut ()) {
    let lib = crate::code_ix::later_data::<ModuleNif>(data);
    let fin = lib
        .finish
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    if let Some(fin) = &*fin {
        for stub in &fin.beam_stubv {
            fin.version.erts_asm_bp_unset_flag(
                stub.code_info_ptr,
                arinsal_beamasm::common::beam_asm_h::ERTS_ASM_BP_FLAG_CALL_NIF_EARLY,
            );
        }
    }
    let unloaded = fin.is_none();
    drop(fin);
    if !unloaded {
        // The breakpoints are gone and nobody executes them before the stubs are freed.
        erts_schedule_code_barrier(lib, load_nif_3rd_finisher);
    }
}

// Port of erts/emulator/beam/erl_nif.c:5277-5283 (load_nif_3rd_finisher), OTP-29.1.1.
fn load_nif_3rd_finisher(data: *mut ()) {
    let lib = crate::code_ix::later_data::<ModuleNif>(data);
    release_beam_stubs(lib);
}

/// Erases the stubs of `lib` from the call table and frees them.
// Port of erts/emulator/beam/erl_nif.c:5285-5312 (release_beam_stubs, erase_hashed_stubs),
// OTP-29.1.1.
fn release_beam_stubs(lib: &ModuleNif) {
    let fin = lib
        .finish
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
        .take();
    if let Some(fin) = fin {
        let mut tab = ERTS_NIF_CALL_TAB
            .write()
            .unwrap_or_else(|poison| poison.into_inner());
        for stub in &fin.beam_stubv {
            tab.remove(&stub.code_info_ptr);
        }
    }
}

/// The `call_nif` code of the stub of the function whose `ErtsCodeInfo` is `ci`, for a call
/// that reached the function while its library is being loaded.
// Port of erts/emulator/beam/erl_nif.c:5109-5122 (erts_call_nif_early), OTP-29.1.1.
#[unsafe(no_mangle)]
pub extern "C" fn erts_call_nif_early(
    _c_p: *mut arinsal_beamasm::ProcessHeader,
    ci: *const arinsal_beamasm::common::beam_asm_h::ErtsCodeInfo,
) -> usize {
    let tab = ERTS_NIF_CALL_TAB
        .read()
        .unwrap_or_else(|poison| poison.into_inner());
    let stub = tab.get(&(ci as usize)).copied();
    drop(tab);
    // erts ASSERTs the stub; the call table holds it until load_nif_3rd_finisher, which runs
    // after the code barrier that follows the removal of the call_nif_early breakpoint.
    stub.map_or(0, ErtsNifBeamStub::code_at)
}

/// The native code of `module_id`, when the module was compiled by BeamAsm.
fn native_version(module_id: usize) -> Option<Arc<crate::beamasm_integration::CompiledVersion>> {
    code_tables(erts_active_code_ix())
        .code_meta
        .get(module_id)
        .and_then(|meta| meta.as_ref())
        .and_then(|meta| meta.beamasm.clone())
}

fn bind_tracer(module_id: usize) -> Result<(), VmError> {
    let module = Arc::clone(&code_tables(erts_active_code_ix()).modules[module_id]);
    let find = |wanted: &str, wanted_arity: u8| {
        module.functions.iter().find_map(|(entry, name, arity)| {
            (*name == wanted && *arity == wanted_arity).then_some(*entry)
        })
    };
    let (Some(enabled), Some(trace)) = (find("enabled", 3), find("trace", 5)) else {
        return Err(VmError::Unsupported(
            "erl_tracer enabled/3 or trace/5 is missing".into(),
        ));
    };
    // The tracer callbacks of the trace delivery are these entries; native erl_tracer code is
    // not bound until erl_tracer.c is a static NIF library with ErlNifFunc entries.
    for (entry, body) in [
        (enabled, tracer_enabled as BifFn),
        (trace, tracer_trace as BifFn),
    ] {
        let index = push_native(NativeFn::Bif(body))?;
        patch_native(&module, entry, index)?;
    }
    Ok(())
}

fn load_dynamic(
    process: &mut Process,
    (caller_id, prev_id): (usize, Option<usize>),
    caller: &str,
    path: &[u8],
    info: Term,
) -> Result<Term, VmError> {
    let file = Path::new(OsStr::from_bytes(path));
    let image = match arinsal_nif::open_nif(file, caller) {
        Ok(image) => image,
        Err(error) => return nif_open_error(process, path, error),
    };
    let binds = match validate_image(caller_id, caller, &image) {
        Ok(binds) => binds,
        Err(message) => return error_reason(process, "bad_lib", &message),
    };
    // Port of erts/emulator/beam/erl_nif.c:4956-4987 (erts_load_nif), OTP-29.1.1: when the
    // previous code of the module has a NIF library the new one is upgraded from it, else
    // loaded. erts runs the upgrade with thread progress blocked; Arinsal does not block the
    // other schedulers.
    let pid = process.self_pid().and_then(|pid| pid.to_term());
    let prev = prev_id.and_then(instance_nif);
    let committed = match &prev {
        Some(prev) => image.upgrade(info, &prev.library, pid),
        None => image.commit_for(info, pid),
    };
    let library = match committed {
        Ok(library) => library,
        Err(error) => return nif_open_error(process, path, error),
    };
    let scheduler = process
        .runtime
        .as_ref()
        .and_then(|runtime| runtime.scheduler().ok())
        .map_or_else(Weak::new, Arc::downgrade);
    install_stubs(caller_id, library, &binds, scheduler)?;
    Ok(Term::atom(arinsal_term::atoms::OK))
}

/// Run the atom side of a static NIF library's `load` callback.
// Port of erts/emulator/beam/erl_nif.c:4980-4982 (erts_load_nif calling the
// library's load callback), OTP-29.1.1.
fn intern_load_atoms(module: &str) -> Result<(), VmError> {
    for name in super::nif_load_atoms::load_atoms(module) {
        global_atoms()
            .intern(name)
            .map_err(|_| VmError::Unsupported("atom table full".into()))?;
    }
    Ok(())
}

// Port of erts/emulator/beam/emu/bif_instrs.tab:i_load_nif: the load runs holding the code
// modification permission; a caller that is not given it yields and retries the call.
fn load_nif(process: &mut Process, args: &[Term]) -> Result<Term, VmError> {
    let runtime = process.runtime;
    let pid = process.self_pid();
    if let (Some(runtime), Some(pid)) = (&runtime, pid)
        && !crate::natives::code::try_seize_code_mod_permission(runtime, process, pid)
    {
        return Err(VmError::Yield);
    }
    let [path, info] = *args else {
        return Err(badarg());
    };
    // The call site (`I`) names the caller.
    let result = crate::natives::proc::native_call_site(process)
        .ok_or_else(|| VmError::Unsupported("load_nif without a call site".into()))
        .and_then(|(_, pc)| erts_load_nif(process, pc, path, info));
    if let (Some(runtime), Some(_)) = (&runtime, pid) {
        crate::natives::code::release_code_mod_permission(runtime);
    }
    result
}

/// Loads the NIF library `filename` for the module whose code `i` is in.
// Port of erts/emulator/beam/erl_nif.c:4708-5040 (erts_load_nif), OTP-29.1.1.
pub(crate) fn erts_load_nif(
    process: &mut Process,
    i: usize,
    path: Term,
    info: Term,
) -> Result<Term, VmError> {
    // Port of erts/emulator/beam/erl_nif.c:4736 (erts_load_nif filename), OTP-29.1.1.
    // A filename that cannot be encoded is `badarg` before the static-module shortcut.
    let Some(mut bytes) = filename_bytes(path) else {
        return Err(badarg());
    };
    bytes.extend(b".so");
    // The caller's code (and its native version) may have been loaded by another scheduler.
    // Port of erts/emulator/beam/erl_nif.c:4744-4772 (erts_load_nif), OTP-29.1.1: the library
    // binds to the module whose code called load_nif (`erts_find_function_from_pc`); a pending
    // on_load instance takes it, and a call from old code is refused.
    let pc = i;
    let function = crate::native_function_at(pc)
        .ok_or_else(|| VmError::Unsupported("load_nif without a call site".into()))?;
    let caller_instance = [
        code_tables(erts_active_code_ix())
            .pending_on_load
            .get(function.module),
        code_tables(erts_active_code_ix())
            .loaded
            .get(function.module),
        code_tables(erts_active_code_ix()).old.get(function.module),
    ]
    .into_iter()
    .flatten()
    .copied()
    .find(|&id| {
        crate::load::native_code_range(&code_tables(erts_active_code_ix()).code_meta, id)
            .is_some_and(|(start, end)| (start..end).contains(&pc))
    });
    let caller = function.module.to_owned();
    if caller_instance.is_some()
        && caller_instance == code_tables(erts_active_code_ix()).old.get(&caller).copied()
    {
        return error_reason(
            process,
            "old_code",
            &format!("Calling load_nif from old module '{caller}' not allowed"),
        );
    }
    let caller_id = code_tables(erts_active_code_ix())
        .pending_on_load
        .get(&caller)
        .or_else(|| code_tables(erts_active_code_ix()).loaded.get(&caller))
        .copied()
        .or(caller_instance)
        .ok_or_else(|| VmError::Unsupported("load_nif caller".into()))?;
    // Port of erts/emulator/beam/erl_nif.c:4758-4772 (erts_load_nif), OTP-29.1.1: `prev_mi` is
    // the old code, or for a pending on_load instance the current code when there is one.
    let prev_id = if code_tables(erts_active_code_ix())
        .pending_on_load
        .get(&caller)
        == Some(&caller_id)
    {
        code_tables(erts_active_code_ix())
            .loaded
            .get(&caller)
            .or_else(|| code_tables(erts_active_code_ix()).old.get(&caller))
    } else {
        code_tables(erts_active_code_ix()).old.get(&caller)
    }
    .copied()
    .filter(|&id| id != caller_id);
    if caller == "erlang" {
        return error_reason(
            process,
            "bad_lib",
            "load_nif/2 must be explicitly called from the NIF module. It cannot be called through apply/3.",
        );
    }
    if code_tables(erts_active_code_ix())
        .loaded_nifs
        .contains(&crate::load::nif_key(&caller, caller_id))
    {
        return error_reason(
            process,
            "reload",
            "NIF library already loaded (reload disallowed since OTP 20).",
        );
    }
    let loaded = match caller.as_str() {
        "prim_file" | "prim_buffer" | "zlib" | "zstd" | "prim_tty" | "prim_socket" | "prim_net" => {
            intern_load_atoms(&caller)?;
            if caller == "prim_socket"
                && let Ok(info) = arinsal_term::to_owned(info)
            {
                arinsal_nif_socket::load_info(&info);
            }
            Term::atom(arinsal_term::atoms::OK)
        }
        "erl_tracer" => {
            bind_tracer(caller_id)?;
            intern_load_atoms(&caller)?;
            Term::atom(arinsal_term::atoms::OK)
        }
        _ => {
            let term = load_dynamic(process, (caller_id, prev_id), &caller, &bytes, info)?;
            if term != Term::atom(arinsal_term::atoms::OK) {
                return Ok(term);
            }
            crate::ddll::add_taint(&caller);
            term
        }
    };
    if loaded == Term::atom(arinsal_term::atoms::OK) {
        let key = crate::load::nif_key(&caller, caller_id);
        publish(&key);
    }
    Ok(loaded)
}

fn state_alive(process: &Process, state: Term) -> Option<bool> {
    if let Some(pid) = Pid::from_term(state) {
        let runtime = process.runtime.as_ref()?;
        return Some(runtime.scheduler().ok()?.lookup(pid));
    }
    if let Some(id) = state.as_port() {
        let runtime = process.runtime.as_ref()?;
        return Some(runtime.ports.contains(id));
    }
    None
}

fn enabled_term(default_remove: bool, alive: Option<bool>, same: bool) -> Term {
    let default = Term::atom(if default_remove {
        arinsal_term::atoms::REMOVE
    } else {
        arinsal_term::atoms::DISCARD
    });
    if alive == Some(true) && !same {
        Term::atom(arinsal_term::atoms::TRACE)
    } else if alive == Some(true) && same {
        Term::atom(arinsal_term::atoms::DISCARD)
    } else {
        default
    }
}

fn tracer_enabled_term(args: &[Term], alive: Option<bool>) -> Term {
    let default_remove = exact_eq(args[0], Term::atom(arinsal_term::atoms::TRACE_STATUS));
    let same = exact_eq(args[1], args[2]);
    enabled_term(default_remove, alive, same)
}

fn tracer_enabled(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    let _ = ctx;
    if args.len() != 3 {
        return Err(BifError::BADARG);
    }
    let alive = (|| {
        let hub = thread_hub()?;
        let scheduler = hub.scheduler.upgrade()?;
        if let Some(pid) = Pid::from_term(args[1]) {
            return Some(scheduler.lookup(pid));
        }
        if args[1].as_port().is_some() {
            return Some(false);
        }
        None
    })();
    Ok(tracer_enabled_term(args, alive))
}

fn small_or_zero(value: i64) -> Term {
    Term::small(value).unwrap_or_else(|| Term::small(0).expect("zero"))
}

fn monotonic_ns() -> i64 {
    static BASE: OnceLock<std::time::Instant> = OnceLock::new();
    let base = BASE.get_or_init(std::time::Instant::now);
    i64::try_from(base.elapsed().as_nanos()).unwrap_or(i64::MAX)
}

fn timestamp_term<H: HeapAlloc>(heap: &mut H, kind: Term) -> Option<Term> {
    let mut builder = TermBuilder::new(heap);
    if exact_eq(kind, Term::atom(arinsal_term::atoms::MONOTONIC)) {
        return Some(small_or_zero(monotonic_ns()));
    }
    if exact_eq(kind, Term::atom(arinsal_term::atoms::STRICT_MONOTONIC)) {
        static UNIQUE: std::sync::atomic::AtomicI64 = std::sync::atomic::AtomicI64::new(1);
        let unique = UNIQUE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        return builder
            .tuple(&[small_or_zero(monotonic_ns()), small_or_zero(unique)])
            .ok();
    }
    if exact_eq(kind, Term::atom(arinsal_term::atoms::TIMESTAMP)) {
        let micros = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_micros())
            .unwrap_or(0);
        let mega = (micros / 1_000_000) / 1_000_000;
        let sec = (micros / 1_000_000) % 1_000_000;
        let micro = micros % 1_000_000;
        return builder
            .tuple(&[
                small_or_zero(mega as i64),
                small_or_zero(sec as i64),
                small_or_zero(micro as i64),
            ])
            .ok();
    }
    if exact_eq(kind, Term::atom(arinsal_term::atoms::CPU_TIMESTAMP)) {
        return Some(small_or_zero(monotonic_ns()));
    }
    None
}

fn map_value(map: Term, key: &str) -> Option<Term> {
    arinsal_maps::get(map, crate::atom_cache::put(key))
        .ok()
        .flatten()
}

/// Build the trace tuple from `erl_tracer_nif.c` `trace/5`. `None` means do not send.
fn build_trace<H: HeapAlloc>(heap: &mut H, args: &[Term]) -> Option<Term> {
    let opts = args[4];
    let opts_sz = arinsal_maps::size(opts).unwrap_or(0);
    let mut parts = Vec::new();
    if opts_sz > 0
        && let Some(extra) = map_value(opts, "extra")
    {
        parts.extend([
            Term::atom(arinsal_term::atoms::TRACE),
            args[2],
            args[0],
            args[3],
            extra,
        ]);
    } else if exact_eq(args[0], Term::atom(arinsal_term::atoms::SEQ_TRACE)) {
        parts.extend([Term::atom(arinsal_term::atoms::SEQ_TRACE), args[2], args[3]]);
    } else {
        parts.extend([
            Term::atom(arinsal_term::atoms::TRACE),
            args[2],
            args[0],
            args[3],
        ]);
    }
    if opts_sz > 0
        && let Some(value) = map_value(opts, "match_spec_result")
    {
        parts.push(value);
    }
    if opts_sz > 0
        && let Some(value) = map_value(opts, "scheduler_id")
    {
        parts.push(value);
    }
    if opts_sz > 0
        && let Some(kind) = map_value(opts, "timestamp")
    {
        let stamp = timestamp_term(heap, kind)?;
        parts.push(stamp);
        if exact_eq(parts[0], Term::atom(arinsal_term::atoms::TRACE)) {
            parts[0] = crate::atom_cache::put("trace_ts");
        }
    }
    TermBuilder::new(heap).tuple(&parts).ok()
}

fn deliver_trace(process: &mut Process, _ctx: &mut RunCtx<'_, crate::Process>, args: &[Term]) {
    let message = {
        let mut heap = ProcessHeapHandle(&mut process.heap);
        build_trace(&mut heap, args)
    };
    let Some(message) = message else {
        return;
    };
    if Pid::from_term(args[1]).is_some() {
        let _ = process.send_message(args[1], message);
        return;
    }
    if args[1].as_port().is_some() {
        let _ = crate::port::trace_command(process, args[1], message);
    }
}

struct HeapAdapter<'a, H: HeapAlloc + ?Sized>(&'a mut H);

impl<H: HeapAlloc + ?Sized> HeapAlloc for HeapAdapter<'_, H> {
    fn alloc(&mut self, words: usize) -> Option<*mut u64> {
        self.0.alloc(words)
    }
    fn retain_binary(&mut self, binary: std::sync::Arc<arinsal_term::RefcBinary>) {
        self.0.retain_binary(binary);
    }
    fn link_bin_ref(
        &mut self,
        bin_ref: *mut u64,
        writable: bool,
        overhead_words: u64,
        owner: Option<arinsal_term::OwnedBinaryRef>,
    ) {
        HeapAlloc::link_bin_ref(self.0, bin_ref, writable, overhead_words, owner)
    }
    fn retain_writable_binary(&mut self, binary: std::sync::Arc<arinsal_term::WritableBinary>) {
        self.0.retain_writable_binary(binary)
    }
    fn retain_writable_binary_with_apparent_size(
        &mut self,
        binary: std::sync::Arc<arinsal_term::WritableBinary>,
        apparent_size_bits: usize,
    ) {
        self.0
            .retain_writable_binary_with_apparent_size(binary, apparent_size_bits)
    }
    fn add_bin_vheap(&mut self, words: u64) {
        self.0.add_bin_vheap(words)
    }
    fn update_writable_binary_overhead(
        &mut self,
        source: Term,
        old_size_bits: usize,
        new_size_bits: usize,
    ) {
        self.0
            .update_writable_binary_overhead(source, old_size_bits, new_size_bits)
    }
    fn supports_writable_binary(&self) -> bool {
        self.0.supports_writable_binary()
    }
    fn link_external_binary(
        &mut self,
        bin_ref: *mut u64,
        binary: std::sync::Arc<arinsal_term::ExternalBinary>,
    ) {
        self.0.link_external_binary(bin_ref, binary)
    }
    fn supports_external_binary(&self) -> bool {
        self.0.supports_external_binary()
    }
    fn link_node(&mut self, thing: *mut u64, node: arinsal_term::Node) {
        self.0.link_node(thing, node);
    }
    fn link_magic_ref(&mut self, thing: *mut u64, owner: arinsal_term::MagicBin) {
        self.0.link_magic_ref(thing, owner)
    }
    fn supports_magic(&self) -> bool {
        self.0.supports_magic()
    }
}

fn tracer_trace(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    if args.len() != 5 {
        return Err(BifError::BADARG);
    }
    if Pid::from_term(args[1]).is_none() && args[1].as_port().is_none() {
        return Ok(Term::atom(arinsal_term::atoms::OK));
    }
    let Some(message) = build_trace(&mut HeapAdapter(&mut ctx.heap), args) else {
        return Ok(Term::atom(arinsal_term::atoms::OK));
    };
    if let Some(pid) = Pid::from_term(args[1])
        && let Some(hub) = thread_hub()
        && let Some(scheduler) = hub.scheduler.upgrade()
        && let Ok(envelope) = Message::copy_from(message)
    {
        let _ = scheduler.send(hub.pid, pid, envelope);
    }
    Ok(Term::atom(arinsal_term::atoms::OK))
}

#[inline(never)]
pub(crate) fn refresh_hub(process: &Process, ctx: &RunCtx<'_, crate::Process>) {
    let pid = ctx.pid();
    let current = HUB.with(|hub| {
        hub.borrow()
            .as_ref()
            .is_some_and(|hub| hub.current_pid() == pid)
    });
    if !current {
        install_hub(process, ctx);
    }
}

fn install_hub(process: &Process, ctx: &RunCtx<'_, crate::Process>) {
    install_hub_for(process, ctx.pid());
}

#[inline(never)]
pub(crate) fn refresh_hub_native(process: &Process) {
    let Some(ref pid) = process.self_pid() else {
        return;
    };
    // Every native BIF call lands here: when this thread already serves this process the
    // hub, its registry entry and the global hooks are all in place, so skip the global
    // locks they would take.
    let runtime = process
        .runtime
        .as_ref()
        .map_or(0, |rt| *rt as *const crate::process::Runtime as usize);
    if HUB_RUNTIME.get() == runtime {
        // The scheduler thread already has this node's hub. Only the current
        // pid changes; erts does not republish a global process table for that.
        HUB.with(|hub| {
            if let Some(hub) = hub.borrow_mut().as_mut() {
                hub.set_pid(*pid);
            }
        });
        return;
    }
    install_hub_for(process, *pid);
}

/// Install this scheduler thread's hub for `process`'s runtime, once per scheduler thread: the
/// installed hub reads the scheduler's `esdp->current_process`, so scheduling a process in
/// stores nothing here.
#[inline]
pub(crate) fn bind_scheduler_hub(process: &Process) {
    let runtime = process
        .runtime
        .as_ref()
        .map_or(0, |rt| *rt as *const crate::process::Runtime as usize);
    if runtime == 0 || HUB_RUNTIME.get() == runtime {
        return;
    }
    if let Some(pid) = process.self_pid() {
        install_hub_for(process, pid);
    }
}

fn install_hub_for(process: &Process, pid: Pid) {
    let Some(runtime) = process.runtime.as_ref() else {
        return;
    };
    let Ok(scheduler) = runtime.scheduler() else {
        return;
    };
    // erts hands NIFs the calling process through the env; switching processes on a
    // scheduler thread registers nothing globally. Only the thread's caller changes.
    let runtime_id = *runtime as *const crate::process::Runtime as usize;
    if HUB_RUNTIME.get() == runtime_id
        && HUB.with(|hub| {
            hub.borrow_mut()
                .as_mut()
                .map(|hub| hub.set_pid(pid))
                .is_some()
        })
    {
        return;
    }
    let hub = Hub {
        scheduler: Arc::downgrade(scheduler),
        pid,
        runtime,
        current: false,
    };
    // A scheduler thread's own hub acts for its `esdp->current_process`; the copies published
    // to other threads keep `pid`.
    let on_scheduler = arinsal_sched::erts_get_scheduler_data::<Process, _>(|_| ()).is_some();
    HUB.with(|current| {
        *current.borrow_mut() = Some(Hub {
            current: on_scheduler,
            ..hub.clone()
        });
    });
    HUB_RUNTIME.set(runtime_id);
    *GLOBAL_HUB.lock().unwrap() = Some(hub.clone());
    {
        let mut runtimes = RUNTIME_HUBS.lock().unwrap();
        if !runtimes
            .iter()
            .any(|known| std::ptr::eq(known.runtime, hub.runtime))
        {
            runtimes.push(hub);
        }
    }
    let reactor = SOCKET_REACTOR.get_or_init(|| {
        let reactor = Arc::new(NifSelectReactor::default());
        arinsal_nif_socket::set_reactor(Some(reactor.clone()));
        reactor
    });
    arinsal_nif_socket::set_reactor(Some(reactor.clone()));
    arinsal_nif::set_vm_hooks(arinsal_nif::VmHooks {
        send: Some(nif_send_hook),
        select: Some(nif_select_hook),
        whereis_pid: Some(nif_whereis_pid_hook),
        whereis_port: Some(nif_whereis_port_hook),
        port_alive: Some(nif_port_alive_hook),
        port_command: Some(nif_port_command_hook),
        is_process_alive: Some(nif_is_process_alive),
        thread_type: Some(nif_thread_type),
        current_process_exiting: Some(crate::dirty::current_process_exiting),
        resource_monitor: Some(nif_resource_monitor),
        resource_demonitor: Some(nif_resource_demonitor),
    });
}

// Port of erts/emulator/beam/erl_nif.c:3150-3180 (enif_monitor_process: erts_monitor_create and
// erts_proc_sig_send_monitor): the target half goes into the monitored process's monitor tree.
fn nif_resource_monitor(
    target: Term,
    id: u64,
    monitor: std::sync::Arc<arinsal_nif::ResourceMonitor>,
) -> bool {
    let (Some(hub), Some(pid)) = (current_hub(), Pid::from_term(target)) else {
        return false;
    };
    let Some(scheduler) = hub.scheduler.upgrade() else {
        return false;
    };
    scheduler
        .signal(
            hub.pid,
            pid,
            arinsal_sched::Signal::MonitorOpaque {
                reference: id,
                shared: Box::new(arinsal_sched::SharedPayload(monitor)),
            },
        )
        .is_ok()
}

// erl_nif.c: erts_proc_sig_send_demonitor for a resource monitor.
fn nif_resource_demonitor(target: Term, id: u64) {
    let (Some(hub), Some(pid)) = (current_hub(), Pid::from_term(target)) else {
        return;
    };
    if let Some(scheduler) = hub.scheduler.upgrade() {
        let _ = scheduler.signal(hub.pid, pid, arinsal_sched::Signal::Demonitor(id));
    }
}

// Port of erts/emulator/beam/erl_nif.c:3586 (enif_thread_type / is_scheduler), OTP-29.1.1.
// No scheduler data is `ERL_NIF_THR_UNDEFINED` (0). A dirty job publishes its type on the
// thread even when that thread also has a normal scheduler id; the type wins, as `esdp->type` does.
fn nif_thread_type() -> std::ffi::c_int {
    match arinsal_sched::current_scheduler_type() {
        SchedulerType::DirtyCpu => return 2,
        SchedulerType::DirtyIo => return 3,
        SchedulerType::Normal => {}
    }
    if arinsal_sched::current_normal_scheduler().is_some() {
        1
    } else {
        0
    }
}

fn nif_is_process_alive(caller: Term, target: Term) -> bool {
    let (Some(caller), Some(target)) = (Pid::from_term(caller), Pid::from_term(target)) else {
        return false;
    };
    let Some(hub) = hub_for_pid(caller) else {
        return false;
    };
    hub.scheduler
        .upgrade()
        .is_some_and(|scheduler| scheduler.lookup(target))
        && !crate::signals::has_begun_exit(hub.runtime, target)
}

// Port of erts/emulator/beam/erl_nif.c:860-1075 (enif_send), OTP-29.1.1.
//
// `execution_state(env, &c_p, &scheduler)` resolves the caller: `c_p == NULL` for a `NULL`
// or process-independent env (an `enif_alloc_env` env has `proc->common.id == ERTS_INVALID_PID`),
// so `from = c_p ? c_p->common.id : am_undefined`. The receiver is looked up against the
// process table (`erts_proc_lookup` on a normal scheduler, `erts_pid2proc_opt` elsewhere),
// not against the caller's scheduler. Arinsal's hook receives the caller pid (or `None`)
// from `enif_send` and resolves the target's runtime with `hub_for_pid`; it never attributes
// the send to the `GLOBAL_HUB` process.
fn nif_send_hook(caller: Option<Term>, target: Term, message: Term) -> bool {
    let Some(pid) = Pid::from_term(target) else {
        return false;
    };
    let sender = caller
        .and_then(Pid::from_term)
        .unwrap_or(arinsal_sched::UNDEFINED_PID);
    let trace_message = message;
    let Ok(message) = Message::copy_from(message) else {
        return false;
    };
    let Some(hub) = hub_for_pid(pid) else {
        return false;
    };
    let Some(scheduler) = hub.scheduler.upgrade() else {
        return false;
    };
    let deliverable = scheduler.lookup(pid);
    if deliverable && !sender.is_undefined() && crate::trace::active() {
        // Port of erts/emulator/beam/erl_nif.c:998-1007 (trace_send), OTP-29.1.1: only a
        // resolved caller (`c_p`) is traced. A `NULL` or process-independent env has no
        // process, so the send is not a traced `send` from `GLOBAL_HUB`'s pid either.
        let _ = with_dirty_trace_emission(|| {
            crate::trace::emit_dirty_send(hub.runtime, sender, target, trace_message)
        });
    }
    let sent = scheduler.send(sender, pid, message).is_ok();
    if crate::debug_env::literal_trace() {
        eprintln!("resource_send from={:?} to={:?} sent={sent}", sender, pid);
    }
    sent
}

/// A resource that an `enif_select` keeps selected in the check-io table.
struct SelectedResource {
    data: usize,
    runtime: &'static crate::process::Runtime,
}

impl arinsal_drv::NifSelectResource for SelectedResource {
    fn id(&self) -> usize {
        self.data
    }

    fn type_name(&self) -> String {
        arinsal_nif::resource_type_name(self.data)
    }

    fn keep(&self) {
        arinsal_nif::enif_keep_resource(self.data as *mut std::ffi::c_void);
    }

    fn release(&self) {
        arinsal_nif::enif_release_resource(self.data as *mut std::ffi::c_void);
    }

    fn stop(&self, fd: i32, direct: bool) {
        arinsal_nif::resource_stop_data(self.data, fd, direct);
    }

    fn log_error(&self, text: &str) {
        crate::port::log_error_for(self.runtime, text);
    }
}

/// A prepared `enif_select` message on its way to the recipient (`send_select_msg`).
struct SelectEvent {
    hub: Hub,
    recipient: Pid,
    message: arinsal_nif::SelectMessage,
}

impl arinsal_drv::NifSelectMessage for SelectEvent {
    fn deliver(self: Box<Self>) {
        let Some(scheduler) = self.hub.scheduler.upgrade() else {
            return;
        };
        let Ok(envelope) = Message::copy_from(self.message.message) else {
            return;
        };
        let _ = scheduler.send(self.hub.pid, self.recipient, envelope);
    }

    fn recipient(&self) -> String {
        format!("{:?}", self.recipient)
    }
}

// Port of erts/emulator/sys/common/erl_check_io.c:1236 (enif_select_x), OTP-29.1.1: the
// NIF selection lives in the same fd table as `driver_select`.
fn nif_select_hook(request: arinsal_nif::SelectRequest) -> i32 {
    let Some(hub) = current_hub() else {
        return i32::MIN | 8;
    };
    crate::port::install_poll_backend();
    let resource = Arc::new(SelectedResource {
        data: request.resource,
        runtime: hub.runtime,
    });
    let messages = request.messages.map(|message| {
        let message = message?;
        let recipient = Pid::from_term(message.recipient)?;
        Some(Box::new(SelectEvent {
            hub: hub.clone(),
            recipient,
            message,
        }) as Box<dyn arinsal_drv::NifSelectMessage>)
    });
    arinsal_drv::nif_select(resource, request.fd, request.flags, messages)
}

// Port of erts/emulator/beam/erl_nif.c:1149 (call_whereis): the process or port a name
// is registered for; `enif_get_local_pid`/`enif_get_local_port` check the type.
fn nif_whereis_pid_hook(name: Term) -> Option<Term> {
    let runtime = current_hub()?.runtime;
    let pid = runtime.reg.whereis_proc(name.as_atom()?)?;
    pid.to_term()
}

fn nif_whereis_port_hook(name: Term) -> Option<Term> {
    let runtime = current_hub()?.runtime;
    let id = runtime.reg.whereis_port(name.as_atom()?)?;
    Term::port(id)
}

// Port of erts/emulator/beam/erl_nif.c:2340 (enif_is_port_alive).
fn nif_port_alive_hook(port: Term) -> bool {
    let Some(hub) = current_hub() else {
        return false;
    };
    let runtime = hub.runtime;
    let Some(id) = port.as_port() else {
        return false;
    };
    crate::port::runtime_port_live(runtime, id)
}

// Port of erts/emulator/beam/erl_nif.c:1097 (enif_port_command).
fn nif_port_command_hook(from: Option<Term>, port: Term, data: Term) -> bool {
    let Some(hub) = current_hub() else {
        return false;
    };
    let runtime = hub.runtime;
    let from = from.and_then(Pid::from_term).unwrap_or(hub.pid);
    crate::port::nif_port_command(runtime, port, from, data)
}

/// Scheduler-path natives in this family that always handle the MFA.
///
/// `erl_tracer` stays out of the table because its entry points are conditional.
/// `nif_error` of any other arity still falls through to [`call`].
pub(crate) const IMPLEMENTED: &[(&str, &str, u8)] = &[
    ("erlang", "load_nif", 2),
    ("erlang", "nif_error", 1),
    ("erlang", "nif_error", 2),
];

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn recognizes(module: &str, function: &str, arity: u8) -> bool {
    super::listed(IMPLEMENTED, module, function, arity)
}

type Handler =
    fn(&mut Vm, &mut Process, &mut RunCtx<'_, crate::Process>, &[Term]) -> Result<Term, VmError>;

pub(crate) fn handler(module: &str, function: &str, arity: u8) -> Option<Handler> {
    match (module, function, arity) {
        ("erlang", "load_nif", 2) => Some(call_load_nif),
        ("erlang", "nif_error", 1 | 2) => Some(call_nif_error),
        _ => None,
    }
}

/// `erlang:load_nif/2`, with the scheduler's NIF hub bound as `nif::call` binds it.
// Port of erts/emulator/beam/erl_nif.c (load_nif_2), OTP-29.1.1.
pub(crate) fn load_nif_2(
    vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, crate::Process>,
    args: &[Term],
) -> Result<Term, VmError> {
    install_hub(process, ctx);
    call_load_nif(vm, process, ctx, args)
}

fn call_load_nif(
    _vm: &mut Vm,
    process: &mut Process,
    _ctx: &mut RunCtx<'_, crate::Process>,
    args: &[Term],
) -> Result<Term, VmError> {
    load_nif(process, args)
}

fn call_nif_error(
    _vm: &mut Vm,
    _process: &mut Process,
    _ctx: &mut RunCtx<'_, crate::Process>,
    args: &[Term],
) -> Result<Term, VmError> {
    let reason = args
        .first()
        .copied()
        .unwrap_or_else(|| Term::atom(arinsal_term::atoms::BADARG));
    Err(VmError::Trap(crate::exceptions::Trap::error(reason)))
}

/// Dispatches `load_nif`, dynamic NIF entry, and `erl_tracer` on the scheduler.
pub(crate) fn call(
    vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, crate::Process>,
    module: &str,
    function: &str,
    args: super::NativeArgs<'_>,
) -> Option<Result<Term, VmError>> {
    args.with_values(process, |process, values| {
        call_values(vm, process, ctx, module, function, values)
    })
}

fn call_values(
    vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, crate::Process>,
    module: &str,
    function: &str,
    args: &[Term],
) -> Option<Result<Term, VmError>> {
    install_hub(process, ctx);
    if let Some(handle) = handler(module, function, args.len() as u8) {
        return Some(handle(vm, process, ctx, args));
    }
    if module == "erlang" && function == "nif_error" {
        let reason = args
            .first()
            .copied()
            .unwrap_or_else(|| Term::atom(arinsal_term::atoms::BADARG));
        return Some(Err(VmError::Trap(crate::exceptions::Trap::error(reason))));
    }
    if module == "erl_tracer"
        && code_tables(erts_active_code_ix())
            .loaded_nifs
            .iter()
            .any(|key| key.starts_with("erl_tracer#"))
    {
        if function == "enabled" && args.len() == 3 {
            return Some(Ok(tracer_enabled_term(args, state_alive(process, args[1]))));
        }
        if function == "trace" && args.len() == 5 {
            if Pid::from_term(args[1]).is_none() && args[1].as_port().is_none() {
                return Some(Ok(Term::atom(arinsal_term::atoms::OK)));
            }
            deliver_trace(process, ctx, args);
            return Some(Ok(Term::atom(arinsal_term::atoms::OK)));
        }
    }
    None
}

pub(crate) fn lookup(module: &str, function: &str, arity: u8) -> Option<BifFn> {
    match module {
        "prim_file" => arinsal_nif_file::lookup(module, function, arity),
        "prim_buffer" => arinsal_nif_buffer::lookup(module, function, arity),
        "zlib" | "zstd" => arinsal_nif_zlib::lookup(module, function, arity),
        "prim_tty" => arinsal_nif_tty::lookup(module, function, arity),
        "prim_socket" | "prim_net" => arinsal_nif_socket::lookup(module, function, arity),
        _ => None,
    }
}
