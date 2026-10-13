//! `erlang:load_nif/2`, dynamic `.so` bindings, and the static `erl_tracer` NIFs.
//!
//! Dirty NIFs and dirty `enif_schedule_nif` continuations move the calling process
//! to the dirty scheduler pools (see [`PendingNif`]).

use std::collections::{HashMap, HashSet};
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::{SystemTime, UNIX_EPOCH};

use arinsal_bifs::{BifError, BifFn, Ctx, ProcessHeapHandle, SchedulerClass};
use arinsal_loader::Instr;
use arinsal_sched::{Pid, RunCtx, Scheduler, SchedulerType};
use arinsal_term::{
    HeapAlloc, Term, TermBuilder, TermKind, VecHeap, exact_eq, from_owned, global_atoms,
};

use crate::calls;
use crate::process::Message;
use crate::{Process, Vm, VmError};

const TRAMPOLINES: usize = 160;

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
    callbacks: HashMap<(String, u8), BifFn>,
}

static TRACER_CALLBACKS: OnceLock<Mutex<HashMap<(u64, String), CachedTracerCallbacks>>> =
    OnceLock::new();

fn tracer_callbacks() -> &'static Mutex<HashMap<(u64, String), CachedTracerCallbacks>> {
    TRACER_CALLBACKS.get_or_init(Default::default)
}

/// Drops cached callback pointers when a scope publishes new active code.
// Port of erts/emulator/beam/code_ix.c:169 and erl_trace.c:3553-3596
// (erts_tracer_nif_clear), OTP-29.1.1.
pub(crate) fn invalidate_tracer_callbacks(scope: u64) {
    tracer_callbacks()
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .retain(|(cached_scope, _), _| *cached_scope != scope);
}

fn tracer_callback(vm: &Vm, module_name: &str, function: &str, arity: u8) -> Option<BifFn> {
    let code = vm.code_ix.active_tables();
    let generation = code.generation;
    let key = (vm.code_scope, module_name.to_owned());
    {
        let cache = tracer_callbacks()
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if let Some(cached) = cache.get(&key)
            && cached.generation == generation
        {
            return cached.callbacks.get(&(function.to_owned(), arity)).copied();
        }
    }

    // Port of erts/emulator/beam/erl_trace.c:3017-3060 (load_tracer_nif), OTP-29.1.1.
    let mut callbacks = HashMap::new();
    if let Some(module) = code
        .loaded
        .get(module_name)
        .and_then(|&id| code.modules.get(id))
    {
        let native_fns = vm.code_ix.native_fns();
        for &(name, expected_arity) in TRACER_FUNCTIONS {
            let Some(entry) = module
                .functions
                .iter()
                .find_map(|(entry, found, found_arity)| {
                    (found == name && *found_arity == expected_arity).then_some(*entry)
                })
            else {
                continue;
            };
            let Some(Instr::NativeBody { index }) =
                entry.checked_add(1).and_then(|body| module.code.get(body))
            else {
                continue;
            };
            if let Some(callback) = native_fns.get(*index as usize).copied().flatten() {
                callbacks.insert((name.to_owned(), expected_arity), callback);
            }
        }
    }
    let selected = callbacks.get(&(function.to_owned(), arity)).copied();
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

struct DynSlot {
    library: Arc<arinsal_nif::NifLibrary>,
    index: usize,
    /// The code scope and module instance the library is bound to.
    owner: (u64, usize),
}

/// Unload the NIF library bound to module instance `id` of `scope`, freeing its trampolines.
// Port of erts/emulator/beam/beam_bif_load.c:2254-2258 (purge complete) and
// erts/emulator/beam/erl_nif.c:5334-5360 (erts_unload_nif), OTP-29.1.1: purging a code instance
// unloads its library; `unload` runs once no NIF call of it is still in flight.
pub(crate) fn unload_instance(scope: u64, id: usize) {
    let released = {
        let mut slots = SLOTS.lock().unwrap_or_else(|poison| poison.into_inner());
        slots
            .iter_mut()
            .filter(|slot| slot.as_ref().is_some_and(|slot| slot.owner == (scope, id)))
            .filter_map(Option::take)
            .collect::<Vec<_>>()
    };
    // The library's `unload` callback runs outside the slot lock.
    drop(released);
}

static SLOTS: Mutex<Vec<Option<DynSlot>>> = Mutex::new(Vec::new());
/// Runtimes whose processes have called NIFs. erts has one runtime and one process
/// table; a pid is resolved against the tables registered here (see [`hub_for_pid`]).
static RUNTIME_HUBS: Mutex<Vec<Hub>> = Mutex::new(Vec::new());
static SOCKET_REACTOR: OnceLock<Arc<NifSelectReactor>> = OnceLock::new();

fn halt_libraries() -> Vec<Arc<arinsal_nif::NifLibrary>> {
    let slots = SLOTS.lock().unwrap_or_else(|poison| poison.into_inner());
    let mut libraries: Vec<Arc<arinsal_nif::NifLibrary>> = Vec::new();
    for slot in slots.iter().flatten() {
        if !libraries
            .iter()
            .any(|library| Arc::ptr_eq(library, &slot.library))
        {
            libraries.push(Arc::clone(&slot.library));
        }
    }
    libraries
}

/// Port of erts/emulator/beam/erl_nif.c:5566-5595 (`erts_nif_notify_halt`), OTP-29.1.1.
pub(crate) fn notify_halt() {
    for library in halt_libraries() {
        library.execute_on_halt();
    }
}

/// Execute callbacks registered after the initial halt notification.
/// Port of erts/emulator/beam/erl_init.c:2683-2687, OTP-29.1.1.
pub(crate) fn execute_late_on_halt() {
    notify_halt();
}

/// Port of erts/emulator/beam/erl_nif.c:5626-5649 (`erts_nif_wait_calls`), OTP-29.1.1.
pub(crate) fn wait_for_halt_calls() {
    for library in halt_libraries() {
        library.wait_for_halt_calls();
    }
}

#[derive(Clone)]
struct Hub {
    scheduler: Weak<Scheduler<Process>>,
    pid: Pid,
    runtime: Weak<crate::process::Runtime>,
    /// The scheduler's current-process slot, on the hub a scheduler thread installed for
    /// itself; copies handed out carry the resolved `pid` instead.
    current: Option<CurrentProcess>,
}

/// A scheduler's `esdp->current_process`: written by the scheduler when it schedules a
/// process in, read by the NIF services running on that scheduler thread.
// Port of erts/emulator/beam/erl_process.h:687 (ErtsSchedulerData_::current_process) and
// erl_process.c:10180 (erts_schedule sets it), OTP-29.1.1.
pub(crate) type CurrentProcess = Arc<std::sync::atomic::AtomicU64>;

impl Hub {
    /// The process this hub acts for: the scheduler's current process when bound to one.
    fn current_pid(&self) -> Pid {
        self.current.as_ref().map_or(self.pid, |current| {
            Pid::from_data(current.load(std::sync::atomic::Ordering::Relaxed))
        })
    }

    /// A copy that keeps the current process as of now, like the hub value it replaces.
    fn resolved(&self) -> Hub {
        Hub {
            pid: self.current_pid(),
            current: None,
            ..self.clone()
        }
    }

    fn set_pid(&mut self, pid: Pid) {
        match &self.current {
            Some(current) => current.store(pid.data(), std::sync::atomic::Ordering::Relaxed),
            None => self.pid = pid,
        }
    }
}

/// This thread's hub, resolved to its current process.
fn thread_hub() -> Option<Hub> {
    HUB.with(|hub| hub.borrow().as_ref().map(Hub::resolved))
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
            current: None,
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
        current: None,
        ..hub
    })
}

struct SelectRegistration {
    id: u64,
    fd: i32,
    reference: arinsal_etf::OwnedTerm,
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
    // Port of enif_select in erl_check_io.c:1228, OTP-29.1.1.
    fn register_read(
        &self,
        fd: i32,
        pid: &arinsal_etf::OwnedTerm,
        handle: &arinsal_etf::OwnedTerm,
        reference: &arinsal_etf::OwnedTerm,
    ) {
        self.register(fd, pid, handle, reference, true);
    }

    fn register_write(
        &self,
        fd: i32,
        pid: &arinsal_etf::OwnedTerm,
        handle: &arinsal_etf::OwnedTerm,
        reference: &arinsal_etf::OwnedTerm,
    ) {
        self.register(fd, pid, handle, reference, false);
    }

    fn cancel(&self, fd: i32, reference: &arinsal_etf::OwnedTerm) {
        let registrations = {
            let mut pending = self.pending.lock().unwrap();
            let mut registrations = Vec::new();
            pending.retain(|entry| {
                let keep = entry.fd != fd || &entry.reference != reference;
                if !keep && let Some(registration) = entry.registration {
                    registrations.push(registration);
                }
                keep
            });
            registrations
        };
        for registration in registrations {
            crate::check_io::deregister(registration);
        }
    }
}

impl NifSelectReactor {
    fn register(
        &self,
        fd: i32,
        pid_term: &arinsal_etf::OwnedTerm,
        handle: &arinsal_etf::OwnedTerm,
        reference: &arinsal_etf::OwnedTerm,
        readable: bool,
    ) {
        let arinsal_etf::OwnedTerm::Pid {
            node, id, serial, ..
        } = pid_term
        else {
            return;
        };
        if node != "nonode@nohost" {
            return;
        }
        let pid = Pid::new(*id, *serial);
        let Some(hub) = hub_for_pid(pid) else {
            return;
        };
        let id = self
            .next_id
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.pending.lock().unwrap().push(SelectRegistration {
            id,
            fd,
            reference: reference.clone(),
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
        } else {
            self.pending.lock().unwrap().retain(|entry| entry.id != id);
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

fn atom(name: &str) -> Term {
    Term::atom(global_atoms().intern(name).expect("built-in atom"))
}

fn badarg() -> VmError {
    VmError::Trap(crate::exceptions::Trap::error(atom("badarg")))
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
    let inner = tuple(process, &[atom(reason), message])?;
    tuple(process, &[atom("error"), inner])
}

fn atom_name(term: Term) -> Option<String> {
    global_atoms()
        .text(term.as_atom()?)
        .map(|text| text.to_string())
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

fn declared_nifs(vm: &Vm, module: &str) -> Result<HashSet<(String, u8)>, String> {
    let file = format!("{module}.beam");
    let path = vm
        .paths
        .iter()
        .map(|dir| dir.join(&file))
        .find(|path| path.is_file())
        .ok_or_else(|| format!("module {module} beam not found"))?;
    let bytes = std::fs::read(&path).map_err(|error| error.to_string())?;
    let beam = arinsal_beam::parse(&bytes).map_err(|error| error.to_string())?;
    let mut current: Option<(String, u8)> = None;
    let mut declared = HashSet::new();
    for instruction in &beam.code.instructions {
        match instruction.op {
            arinsal_spec::Opcode::FuncInfo => {
                let name = instruction
                    .args
                    .get(1)
                    .and_then(|arg| match arg {
                        arinsal_beam::Operand::Atom(index) if *index > 0 => {
                            beam.atoms.get(*index as usize - 1).cloned()
                        }
                        _ => None,
                    })
                    .unwrap_or_else(|| "?".into());
                let arity = instruction
                    .args
                    .get(2)
                    .and_then(|arg| match arg {
                        arinsal_beam::Operand::U(value) => u8::try_from(*value).ok(),
                        _ => None,
                    })
                    .unwrap_or(0);
                current = Some((name, arity));
            }
            arinsal_spec::Opcode::NifStart => {
                if let Some(function) = &current {
                    declared.insert(function.clone());
                }
            }
            _ => {}
        }
    }
    Ok(declared)
}

fn dyn_call<const N: usize>(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    let (library, function) = {
        let slots = SLOTS.lock().unwrap_or_else(|poison| poison.into_inner());
        let Some(slot) = slots.get(N).and_then(|slot| slot.as_ref()) else {
            return Err(BifError::BADARG);
        };
        let function = slot
            .library
            .function(slot.index)
            .cloned()
            .ok_or(BifError::BADARG)?;
        (Arc::clone(&slot.library), function)
    };
    if args.len() != function.arity as usize {
        return Err(BifError::BADARG);
    }
    let trap = arinsal_nif::NifTrap {
        fptr: function.fptr,
        flags: function.flags,
        args: args.to_vec(),
    };
    run_nif(
        ctx,
        PendingNif {
            library,
            function,
            trap,
            done: None,
        },
    )
}

/// A dirty NIF call or `enif_schedule_nif` continuation waiting for a scheduler of
/// another class. The process keeps it while it migrates and re-executes its
/// `NativeBody` there; `trap.args` are GC roots meanwhile.
///
/// Port of erts/emulator/beam/erl_nfunc_sched.h (`ErtsNativeFunc` trap wrapper), OTP-29.1.1.
pub(crate) struct PendingNif {
    library: Arc<arinsal_nif::NifLibrary>,
    function: arinsal_nif::NifFunction,
    trap: arinsal_nif::NifTrap,
    /// Outcome of the call once a dirty scheduler executed it as a dirty job; its heap
    /// is already part of the process heap.
    done: Option<Result<arinsal_nif::NifCall, BifError>>,
}

impl PendingNif {
    pub(crate) fn roots_mut(&mut self) -> &mut [Term] {
        match &mut self.done {
            Some(Ok(arinsal_nif::NifCall::Return(value))) => std::slice::from_mut(value),
            Some(Ok(arinsal_nif::NifCall::Schedule(trap))) => &mut trap.args,
            _ => &mut self.trap.args,
        }
    }

    /// Scheduler class this call or continuation must execute on.
    pub(crate) fn class(&self) -> SchedulerClass {
        arinsal_nif::scheduler_class(self.trap.flags)
    }

    /// Whether a dirty job already executed this call.
    pub(crate) fn is_done(&self) -> bool {
        self.done.is_some()
    }

    /// Internal continuation MFA selected after this dirty callback returns.
    pub(crate) fn finalizer_mfa(&self) -> Option<(&'static str, &'static str, u8)> {
        match self.done.as_ref()? {
            Ok(_) => Some(("erts_internal", "dirty_nif_finalizer", 1)),
            Err(_) => Some(("erts_internal", "dirty_nif_exception", 1)),
        }
    }

    /// MFA of the NIF entry or continuation that this dirty job invokes.
    pub(crate) fn trace_mfa(&self) -> (&str, &str, u8) {
        (
            self.library.module_name(),
            &self.function.name,
            self.function.arity as u8,
        )
    }

    /// Execute the call on the current dirty scheduler without the process: results are
    /// built on `heap`, which the process adopts afterwards.
    ///
    /// Port of erts/emulator/beam/erl_nif.c:426 (erts_call_dirty_nif), OTP-29.1.1: the NIF
    /// runs on a shadow process whose heap fragments move to the real process.
    pub(crate) fn run_dirty(&mut self, heap: &mut arinsal_term::ProcessHeap) {
        let current = current_class();
        let pid = thread_hub().and_then(|hub| hub.pid.to_term());
        let mut fragment = ProcessHeapHandle(heap);
        let mut fcalls = 4_000;
        let mut ctx = Ctx::with_fcalls(&mut fragment, &mut fcalls);
        let (function, trap) = (&self.function, &self.trap);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            function.call_on(&mut ctx, trap.fptr, &trap.args, pid, current)
        }))
        .unwrap_or_else(|_| {
            Err(BifError::Error(Term::atom(
                global_atoms().intern("error").expect("built-in atom"),
            )))
        });
        self.done = Some(result);
    }
}

thread_local! {
    /// Continuation handed from a native body that returned `BifError::Dirty` to the VM.
    static RESCHEDULED: std::cell::RefCell<Option<PendingNif>> =
        const { std::cell::RefCell::new(None) };
}

fn current_class() -> SchedulerClass {
    match arinsal_sched::current_scheduler_type() {
        SchedulerType::Normal => SchedulerClass::Normal,
        SchedulerType::DirtyCpu => SchedulerClass::DirtyCpu,
        SchedulerType::DirtyIo => SchedulerClass::DirtyIo,
    }
}

// Port of erts/emulator/beam/erl_nif.c:3460 (static_schedule_dirty_nif) and erl_nif.c:440
// (erts_call_dirty_nif), OTP-29.1.1: a NIF or continuation runs only on a scheduler of
// the class its flags select; otherwise the process is rescheduled there.
fn run_nif(ctx: &mut Ctx<'_>, pending: PendingNif) -> Result<Term, BifError> {
    let current = current_class();
    let target = arinsal_nif::scheduler_class(pending.trap.flags);
    if pending.done.is_none()
        && target != current
        && !(target == SchedulerClass::Normal && pending.is_entry())
    {
        RESCHEDULED.with(|slot| *slot.borrow_mut() = Some(pending));
        return Err(BifError::Dirty(target));
    }
    let PendingNif {
        library,
        function,
        trap,
        done,
    } = pending;
    let result = match done {
        Some(result) => result,
        // Port of erts/emulator/beam/erl_nif.c:468 (erts_call_dirty_nif), OTP-29.1.1: on a
        // dirty scheduler the call runs as a dirty job without the main process lock.
        None if current != SchedulerClass::Normal && target == current => {
            RESCHEDULED.with(|slot| {
                *slot.borrow_mut() = Some(PendingNif {
                    library,
                    function,
                    trap,
                    done: None,
                })
            });
            return Err(BifError::Dirty(current));
        }
        None => {
            let pid = thread_hub().and_then(|hub| hub.pid.to_term());
            function.call_on(ctx, trap.fptr, &trap.args, pid, current)
        }
    };
    match result? {
        arinsal_nif::NifCall::Return(value) => Ok(value),
        arinsal_nif::NifCall::Schedule(trap) => {
            let target = arinsal_nif::scheduler_class(trap.flags);
            RESCHEDULED.with(|slot| {
                *slot.borrow_mut() = Some(PendingNif {
                    library,
                    function,
                    trap,
                    done: None,
                })
            });
            Err(BifError::Dirty(target))
        }
    }
}

impl PendingNif {
    /// A plain (non-dirty) NIF entry runs wherever the process executes.
    fn is_entry(&self) -> bool {
        self.trap.flags == 0 && self.trap.fptr as usize == self.function.fptr as usize
    }
}

/// Take the continuation a native body left behind with `BifError::Dirty`.
pub(crate) fn take_rescheduled() -> Option<PendingNif> {
    RESCHEDULED.with(|slot| slot.borrow_mut().take())
}

/// Resume a rescheduled NIF continuation on the current scheduler.
pub(crate) fn resume_pending(
    heap: &mut arinsal_term::ProcessHeap,
    fcalls: &mut i32,
    pending: PendingNif,
) -> Result<Term, BifError> {
    let mut fragment = arinsal_bifs::ProcessHeapHandle(heap);
    let mut ctx = Ctx::with_fcalls(&mut fragment, fcalls);
    run_nif(&mut ctx, pending)
}

/// Invoke one patched tracer NIF synchronously on the tracee's scheduler.
pub(crate) fn invoke_tracer(
    vm: &Vm,
    process: &mut Process,
    module: &str,
    function: &str,
    specialized: Option<&str>,
    args: &[Term],
) -> Option<Term> {
    let arity = u8::try_from(args.len()).ok()?;
    let native = specialized
        .and_then(|specialized| tracer_callback(vm, module, specialized, arity))
        .or_else(|| tracer_callback(vm, module, function, arity))?;
    calls::call_bif(&mut process.heap, &mut process.reductions, native, args).ok()
}

pub(crate) fn has_tracer_nifs(vm: &Vm, module_name: &str) -> bool {
    tracer_callback(vm, module_name, "enabled", 3).is_some()
        && tracer_callback(vm, module_name, "trace", 5).is_some()
}

fn trampolines() -> &'static [BifFn] {
    const TABLE: &[BifFn] = include!(concat!(env!("OUT_DIR"), "/nif_trampolines.rs"));
    TABLE
}

/// Binds the NIF library `key` to its module instance in the active code index; the patched
/// `NativeBody` instructions are code shared by every code index.
// Port of erts/emulator/beam/erl_nif.c:4748 (load_nif: `module_p->curr.nif`), OTP-29.1.1.
fn publish(vm: &mut Vm, key: &str) {
    vm.code_ix.update_active(|tables| {
        tables.loaded_nifs.insert(key.to_owned());
    });
    vm.refresh_code();
}

fn patch_native(module: &arinsal_loader::Module, entry: usize, index: u32) -> Result<(), VmError> {
    let slot = entry.saturating_add(1);
    if slot >= module.code.len() {
        return Err(VmError::Unsupported("nif entry".into()));
    }
    let ptr = module.code.as_ptr().cast_mut();
    // SAFETY: `code` is a boxed slice shared by every `Arc<Module>` clone.
    // `load_nif` overwrites the Erlang stub with `NativeBody`, matching
    // `patch_call_nif_early` in erts. `Instr` is `Copy`. This scheduler is
    // inside `load_nif`, not inside the patched function.
    unsafe {
        ptr.add(slot).write(Instr::NativeBody { index });
    }
    Ok(())
}

fn push_native(vm: &mut Vm, function: BifFn) -> Result<u32, VmError> {
    vm.code_ix
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
    };
    error_reason(process, "bad_lib", &message)
}

fn validate_image(
    vm: &Vm,
    module_id: usize,
    caller: &str,
    image: &arinsal_nif::NifImage,
) -> Result<Vec<(usize, usize)>, String> {
    let module = vm
        .code
        .modules
        .get(module_id)
        .ok_or_else(|| format!("module {caller} is not loaded"))?;
    let declared = declared_nifs(vm, caller)?;
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
        if !declared.contains(&(function.name.clone(), arity)) {
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

fn install_dynamic(
    vm: &mut Vm,
    module_id: usize,
    library: Arc<arinsal_nif::NifLibrary>,
    binds: &[(usize, usize)],
) -> Result<(), VmError> {
    let owner = (vm.code_scope, module_id);
    let assigned = {
        let mut slots = SLOTS.lock().unwrap_or_else(|poison| poison.into_inner());
        // Trampolines of purged libraries are reused.
        let free = slots
            .iter()
            .enumerate()
            .filter_map(|(slot, used)| used.is_none().then_some(slot))
            .chain(slots.len()..TRAMPOLINES)
            .take(binds.len())
            .collect::<Vec<_>>();
        if free.len() < binds.len() {
            return Err(VmError::Unsupported("dynamic NIF table is full".into()));
        }
        for (&slot, (_, index)) in free.iter().zip(binds) {
            if slot >= slots.len() {
                slots.resize_with(slot + 1, || None);
            }
            slots[slot] = Some(DynSlot {
                library: Arc::clone(&library),
                index: *index,
                owner,
            });
        }
        free
    };
    for (&slot, (entry, _)) in assigned.iter().zip(binds) {
        let function = trampolines()
            .get(slot)
            .copied()
            .ok_or_else(|| VmError::Unsupported("dynamic NIF trampoline".into()))?;
        let index = push_native(vm, function)?;
        patch_native(&vm.code.modules[module_id], *entry, index)?;
        bind_native_code(vm, module_id, *entry, function)?;
    }
    Ok(())
}

/// Makes the module's native code run the NIF too, like the interpreter's patched entry.
// Port of erts/emulator/beam/erl_nif.c:5050-5106 (patch_call_nif_early), OTP-29.1.1.
fn bind_native_code(
    vm: &Vm,
    module_id: usize,
    entry: usize,
    function: BifFn,
) -> Result<(), VmError> {
    let Some(version) = vm
        .code
        .code_meta
        .get(module_id)
        .and_then(|meta| meta.as_ref())
        .and_then(|meta| meta.beamasm.clone())
    else {
        return Ok(());
    };
    let Some((_, name, arity)) = vm.code.modules[module_id]
        .functions
        .iter()
        .find(|(start, _, _)| *start == entry)
    else {
        return Err(VmError::Unsupported("nif entry".into()));
    };
    // A function without native code runs in the interpreter, which is patched already.
    if version.has_native_function(name, *arity) && !version.bind_nif(name, *arity, function) {
        return Err(VmError::Unsupported(format!(
            "native code of {name}/{arity} has no NIF patch site"
        )));
    }
    Ok(())
}

fn bind_tracer(vm: &mut Vm, module_id: usize) -> Result<(), VmError> {
    let functions = vm.code.modules[module_id].functions.clone();
    let enabled = functions
        .iter()
        .find_map(|(entry, name, arity)| (name == "enabled" && *arity == 3).then_some(*entry));
    let trace = functions
        .iter()
        .find_map(|(entry, name, arity)| (name == "trace" && *arity == 5).then_some(*entry));
    let (Some(enabled), Some(trace)) = (enabled, trace) else {
        return Err(VmError::Unsupported(
            "erl_tracer enabled/3 or trace/5 is missing".into(),
        ));
    };
    let enabled_index = push_native(vm, tracer_enabled)?;
    patch_native(&vm.code.modules[module_id], enabled, enabled_index)?;
    bind_native_code(vm, module_id, enabled, tracer_enabled)?;
    let trace_index = push_native(vm, tracer_trace)?;
    patch_native(&vm.code.modules[module_id], trace, trace_index)?;
    bind_native_code(vm, module_id, trace, tracer_trace)?;
    Ok(())
}

fn load_dynamic(
    vm: &mut Vm,
    process: &mut Process,
    caller_id: usize,
    caller: &str,
    path: &[u8],
    info: Term,
) -> Result<Term, VmError> {
    let file = Path::new(OsStr::from_bytes(path));
    let image = match arinsal_nif::open_nif(file, caller) {
        Ok(image) => image,
        Err(error) => return nif_open_error(process, path, error),
    };
    let binds = match validate_image(vm, caller_id, caller, &image) {
        Ok(binds) => binds,
        Err(message) => return error_reason(process, "bad_lib", &message),
    };
    let library = match image.commit(info) {
        Ok(library) => Arc::new(library),
        Err(error) => return nif_open_error(process, path, error),
    };
    install_dynamic(vm, caller_id, library, &binds)?;
    Ok(atom("ok"))
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

fn load_nif(vm: &mut Vm, process: &mut Process, args: &[Term]) -> Result<Term, VmError> {
    let [path, info] = *args else {
        return Err(badarg());
    };
    // Port of erts/emulator/beam/erl_nif.c:4736 (erts_load_nif filename), OTP-29.1.1.
    // A filename that cannot be encoded is `badarg` before the static-module shortcut.
    let Some(mut bytes) = filename_bytes(path) else {
        return Err(badarg());
    };
    bytes.extend(b".so");
    // The caller's code (and its native version) may have been loaded by another scheduler.
    vm.refresh_code();
    // Port of erts/emulator/beam/erl_nif.c:4744-4772 (erts_load_nif), OTP-29.1.1: the library
    // binds to the module whose code called load_nif (`erts_find_function_from_pc`); a pending
    // on_load instance takes it, and a call from old code is refused. Native code does not keep
    // `process.module` current, so its call site names the caller.
    let (caller, caller_instance) = match crate::natives::proc::native_call_site(process) {
        Some((function, pc)) => {
            let instance = [
                vm.code.pending_on_load.get(&function.module),
                vm.code.loaded.get(&function.module),
                vm.code.old.get(&function.module),
            ]
            .into_iter()
            .flatten()
            .copied()
            .find(|&id| {
                crate::load::native_code_range(&vm.code.code_meta, id)
                    .is_some_and(|(start, end)| (start..end).contains(&pc))
            });
            (function.module, instance)
        }
        None => {
            let name = vm
                .code
                .modules
                .get(process.module)
                .map(|module| module.name.clone())
                .ok_or_else(|| VmError::Unsupported("load_nif caller".into()))?;
            (name, Some(process.module))
        }
    };
    if caller_instance.is_some() && caller_instance == vm.code.old.get(&caller).copied() {
        return error_reason(
            process,
            "old_code",
            &format!("Calling load_nif from old module '{caller}' not allowed"),
        );
    }
    let caller_id = vm
        .code
        .pending_on_load
        .get(&caller)
        .or_else(|| vm.code.loaded.get(&caller))
        .copied()
        .or(caller_instance)
        .ok_or_else(|| VmError::Unsupported("load_nif caller".into()))?;
    if caller == "erlang" {
        return error_reason(
            process,
            "bad_lib",
            "load_nif/2 must be explicitly called from the NIF module. It cannot be called through apply/3.",
        );
    }
    if vm
        .code
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
        "prim_file" | "prim_buffer" | "zlib" | "prim_tty" | "prim_socket" | "prim_net" => {
            intern_load_atoms(&caller)?;
            atom("ok")
        }
        "erl_tracer" => {
            bind_tracer(vm, caller_id)?;
            intern_load_atoms(&caller)?;
            atom("ok")
        }
        _ => {
            let term = load_dynamic(vm, process, caller_id, &caller, &bytes, info)?;
            if term != atom("ok") {
                return Ok(term);
            }
            crate::ddll::add_taint(&caller);
            term
        }
    };
    if loaded == atom("ok") {
        let key = crate::load::nif_key(&caller, caller_id);
        publish(vm, &key);
    }
    Ok(loaded)
}

fn push_continuation(process: &mut Process, module: usize, ip: usize) -> Result<(), VmError> {
    let module = u64::try_from(module).map_err(|_| VmError::Unsupported("module index".into()))?;
    let ip = u32::try_from(ip).map_err(|_| VmError::Unsupported("code index".into()))?;
    if module >= 1 << 26 {
        return Err(VmError::Unsupported("module index".into()));
    }
    process.ensure(1, 0)?;
    if !process.heap.reserve_stack(1) {
        return Err(VmError::Unsupported("continuation stack".into()));
    }
    let cp = crate::stacktrace::continuation_tag(module as usize, ip as usize)?;
    process.heap.stack_set(0, cp);
    Ok(())
}

fn call_on_load(vm: &mut Vm, process: &mut Process, module: Term) -> Result<Term, VmError> {
    let name = atom_name(module).ok_or_else(badarg)?;
    // Port of erts/emulator/beam/beam_bif_load.c:793 (call_on_load_function_1), OTP-29.1.1: the
    // function of the code instance being loaded runs, not the still current previous version.
    vm.refresh_code();
    let id = match vm.code.pending_on_load.get(&name).copied() {
        Some(id) => id,
        None => vm.load_named(&name).map_err(|_| badarg())?,
    };
    let entry = vm.code.modules[id]
        .functions
        .iter()
        .find_map(|(entry, function, arity)| {
            (function == "on_load" && *arity == 0).then_some(*entry)
        })
        .ok_or_else(badarg)?;
    let caller = process.module;
    let return_ip = process.ip.saturating_add(1);
    push_continuation(process, caller, return_ip)?;
    // `call_import` advances `ip` by one. The BEAM `on_load` opcode is only a
    // marker; skip that unsupported instruction and land on the real body.
    let mut landing = entry;
    if let Some(Instr::Unsupported(reason)) = vm.code.modules[id].code.get(entry + 1)
        && vm.code.modules[id]
            .unsupported_reasons
            .get(*reason as usize)
            .is_some_and(|text| text.contains("on_load"))
    {
        landing = entry + 1;
    }
    process.module = id;
    process.ip = landing;
    Ok(atom("ok"))
}

fn state_alive(process: &Process, state: Term) -> Option<bool> {
    if let Some(pid) = Pid::from_term(state) {
        let runtime = process.runtime.as_ref()?;
        return Some(runtime.scheduler().ok()?.lookup(pid));
    }
    if let Some(id) = state.as_port() {
        let runtime = process.runtime.as_ref()?;
        return Some(runtime.ports.lock().unwrap().contains_key(&id));
    }
    None
}

fn enabled_term(default_remove: bool, alive: Option<bool>, same: bool) -> Term {
    let default = atom(if default_remove { "remove" } else { "discard" });
    if alive == Some(true) && !same {
        atom("trace")
    } else if alive == Some(true) && same {
        atom("discard")
    } else {
        default
    }
}

fn tracer_enabled_term(args: &[Term], alive: Option<bool>) -> Term {
    let default_remove = exact_eq(args[0], atom("trace_status"));
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
    if exact_eq(kind, atom("monotonic")) {
        return Some(small_or_zero(monotonic_ns()));
    }
    if exact_eq(kind, atom("strict_monotonic")) {
        static UNIQUE: std::sync::atomic::AtomicI64 = std::sync::atomic::AtomicI64::new(1);
        let unique = UNIQUE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        return builder
            .tuple(&[small_or_zero(monotonic_ns()), small_or_zero(unique)])
            .ok();
    }
    if exact_eq(kind, atom("timestamp")) {
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
    if exact_eq(kind, atom("cpu_timestamp")) {
        return Some(small_or_zero(monotonic_ns()));
    }
    None
}

fn map_value(map: Term, key: &str) -> Option<Term> {
    arinsal_maps::get(map, atom(key)).ok().flatten()
}

/// Build the trace tuple from `erl_tracer_nif.c` `trace/5`. `None` means do not send.
fn build_trace<H: HeapAlloc>(heap: &mut H, args: &[Term]) -> Option<Term> {
    let opts = args[4];
    let opts_sz = arinsal_maps::size(opts).unwrap_or(0);
    let mut parts = Vec::new();
    if opts_sz > 0
        && let Some(extra) = map_value(opts, "extra")
    {
        parts.extend([atom("trace"), args[2], args[0], args[3], extra]);
    } else if exact_eq(args[0], atom("seq_trace")) {
        parts.extend([atom("seq_trace"), args[2], args[3]]);
    } else {
        parts.extend([atom("trace"), args[2], args[0], args[3]]);
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
        if exact_eq(parts[0], atom("trace")) {
            parts[0] = atom("trace_ts");
        }
    }
    TermBuilder::new(heap).tuple(&parts).ok()
}

fn deliver_trace(process: &mut Process, _ctx: &mut RunCtx<'_, Message>, args: &[Term]) {
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
    fn retain_node(&mut self, node: std::sync::Arc<arinsal_term::Node>) {
        self.0.retain_node(node);
    }
    fn retain_fun(&mut self, entry: std::sync::Arc<arinsal_term::FunEntry>) {
        self.0.retain_fun(entry);
    }
    fn retain_export(&mut self, entry: std::sync::Arc<arinsal_term::ExportEntry>) {
        self.0.retain_export(entry);
    }
}

fn tracer_trace(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    if args.len() != 5 {
        return Err(BifError::BADARG);
    }
    if Pid::from_term(args[1]).is_none() && args[1].as_port().is_none() {
        return Ok(atom("ok"));
    }
    let Some(message) = build_trace(&mut HeapAdapter(&mut ctx.heap), args) else {
        return Ok(atom("ok"));
    };
    if let Some(pid) = Pid::from_term(args[1])
        && let Some(hub) = thread_hub()
        && let Some(scheduler) = hub.scheduler.upgrade()
        && let Ok(envelope) = Message::copy_from(message)
    {
        let _ = scheduler.send(hub.pid, pid, envelope);
    }
    Ok(atom("ok"))
}

pub(crate) fn refresh_hub(process: &Process, ctx: &RunCtx<'_, Message>) {
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

fn install_hub(process: &Process, ctx: &RunCtx<'_, Message>) {
    install_hub_for(process, ctx.pid());
}

pub(crate) fn refresh_hub_native(process: &Process) {
    let Some(pid) = process.self_pid.as_ref() else {
        return;
    };
    // Every native BIF call lands here: when this thread already serves this process the
    // hub, its registry entry and the global hooks are all in place, so skip the global
    // locks they would take.
    let runtime = process
        .runtime
        .as_ref()
        .map_or(0, |rt| Arc::as_ptr(rt) as usize);
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

/// Install this scheduler thread's hub for `process`'s runtime and bind it to the
/// scheduler's current-process slot, so scheduling a process in is a plain store.
/// Returns whether the hub is bound.
pub(crate) fn bind_scheduler_hub(process: &Process, current: &CurrentProcess) -> bool {
    let Some(pid) = process.self_pid else {
        return false;
    };
    current.store(pid.data(), std::sync::atomic::Ordering::Relaxed);
    install_hub_for(process, pid);
    HUB.with(|hub| {
        hub.borrow_mut().as_mut().is_some_and(|hub| {
            hub.current = Some(Arc::clone(current));
            true
        })
    })
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
    let runtime_id = Arc::as_ptr(runtime) as usize;
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
        scheduler: Arc::downgrade(&scheduler),
        pid,
        runtime: Arc::downgrade(runtime),
        current: None,
    };
    HUB.with(|current| *current.borrow_mut() = Some(hub.clone()));
    HUB_RUNTIME.set(runtime_id);
    *GLOBAL_HUB.lock().unwrap() = Some(hub.clone());
    {
        let mut runtimes = RUNTIME_HUBS.lock().unwrap();
        runtimes.retain(|known| known.runtime.strong_count() != 0);
        if !runtimes
            .iter()
            .any(|known| Weak::ptr_eq(&known.runtime, &hub.runtime))
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
        ..arinsal_nif::VmHooks::default()
    });
}

// Port of erts/emulator/beam/erl_nif.c:3593 (enif_thread_type), OTP-29.1.1.
fn nif_thread_type() -> std::ffi::c_int {
    match arinsal_sched::current_scheduler_type() {
        SchedulerType::Normal => 1,
        SchedulerType::DirtyCpu => 2,
        SchedulerType::DirtyIo => 3,
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
        && !hub
            .runtime
            .upgrade()
            .is_some_and(|runtime| crate::signals::has_begun_exit(&runtime, target))
}

fn nif_send_hook(target: Term, message: Term) -> bool {
    let Some(pid) = Pid::from_term(target) else {
        return false;
    };
    let Some(hub) = current_hub() else {
        return false;
    };
    let Some(scheduler) = hub.scheduler.upgrade() else {
        return false;
    };
    let trace_message = message;
    let Ok(message) = Message::copy_from(message) else {
        return false;
    };
    let deliverable = scheduler.lookup(pid);
    let dirty_scheduler = arinsal_sched::current_scheduler_type() != SchedulerType::Normal;
    if deliverable
        && dirty_scheduler
        && let Some(runtime) = hub.runtime.upgrade()
    {
        // Port of erts/emulator/beam/erl_nif.c:1005 (trace_send), OTP-29.1.1.
        let _ = with_dirty_trace_emission(|| {
            crate::trace::emit_dirty_send(&runtime, hub.pid, target, trace_message)
        });
    }
    let sent = scheduler.send(hub.pid, pid, message).is_ok();
    if crate::debug_env::literal_trace() {
        eprintln!("resource_send from={:?} to={:?} sent={sent}", hub.pid, pid);
    }
    sent
}

/// A resource that an `enif_select` keeps selected in the check-io table.
struct SelectedResource {
    data: usize,
    runtime: Weak<crate::process::Runtime>,
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
        crate::port::log_error_for(&self.runtime, text);
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
        runtime: hub.runtime.clone(),
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
    let runtime = current_hub()?.runtime.upgrade()?;
    let pid = runtime.reg.whereis_proc(name.as_atom()?)?;
    pid.to_term()
}

fn nif_whereis_port_hook(name: Term) -> Option<Term> {
    let runtime = current_hub()?.runtime.upgrade()?;
    let id = runtime.reg.whereis_port(name.as_atom()?)?;
    Term::port(id)
}

// Port of erts/emulator/beam/erl_nif.c:2340 (enif_is_port_alive).
fn nif_port_alive_hook(port: Term) -> bool {
    let Some(runtime) = current_hub().and_then(|hub| hub.runtime.upgrade()) else {
        return false;
    };
    let Some(id) = port.as_port() else {
        return false;
    };
    crate::port::runtime_port_live(&runtime, id)
}

// Port of erts/emulator/beam/erl_nif.c:1097 (enif_port_command).
fn nif_port_command_hook(from: Option<Term>, port: Term, data: Term) -> bool {
    let Some(hub) = current_hub() else {
        return false;
    };
    let Some(runtime) = hub.runtime.upgrade() else {
        return false;
    };
    let from = from.and_then(Pid::from_term).unwrap_or(hub.pid);
    crate::port::nif_port_command(&runtime, port, from, data)
}

/// Scheduler-path natives in this family that always handle the MFA.
///
/// `erl_tracer` stays out of the table because its entry points are conditional.
/// `nif_error` of any other arity still falls through to [`call`].
pub(crate) const IMPLEMENTED: &[(&str, &str, u8)] = &[
    ("erlang", "load_nif", 2),
    ("erlang", "nif_error", 1),
    ("erlang", "nif_error", 2),
    ("erlang", "call_on_load_function", 1),
];

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn recognizes(module: &str, function: &str, arity: u8) -> bool {
    super::listed(IMPLEMENTED, module, function, arity)
}

type Handler =
    fn(&mut Vm, &mut Process, &mut RunCtx<'_, Message>, &[Term]) -> Result<Term, VmError>;

pub(crate) fn handler(module: &str, function: &str, arity: u8) -> Option<Handler> {
    match (module, function, arity) {
        ("erlang", "load_nif", 2) => Some(call_load_nif),
        ("erlang", "nif_error", 1 | 2) => Some(call_nif_error),
        ("erlang", "call_on_load_function", 1) => Some(call_on_load_bif),
        _ => None,
    }
}

fn call_load_nif(
    vm: &mut Vm,
    process: &mut Process,
    _ctx: &mut RunCtx<'_, Message>,
    args: &[Term],
) -> Result<Term, VmError> {
    load_nif(vm, process, args)
}

fn call_nif_error(
    _vm: &mut Vm,
    _process: &mut Process,
    _ctx: &mut RunCtx<'_, Message>,
    args: &[Term],
) -> Result<Term, VmError> {
    let reason = args.first().copied().unwrap_or_else(|| atom("badarg"));
    Err(VmError::Trap(crate::exceptions::Trap::error(reason)))
}

fn call_on_load_bif(
    vm: &mut Vm,
    process: &mut Process,
    _ctx: &mut RunCtx<'_, Message>,
    args: &[Term],
) -> Result<Term, VmError> {
    call_on_load(vm, process, args[0])
}

/// Dispatches `load_nif`, dynamic NIF entry, and `erl_tracer` on the scheduler.
pub(crate) fn call(
    vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
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
    ctx: &mut RunCtx<'_, Message>,
    module: &str,
    function: &str,
    args: &[Term],
) -> Option<Result<Term, VmError>> {
    install_hub(process, ctx);
    if let Some(handle) = handler(module, function, args.len() as u8) {
        return Some(handle(vm, process, ctx, args));
    }
    if module == "erlang" && function == "nif_error" {
        let reason = args.first().copied().unwrap_or_else(|| atom("badarg"));
        return Some(Err(VmError::Trap(crate::exceptions::Trap::error(reason))));
    }
    if module == "erl_tracer"
        && vm
            .code
            .loaded_nifs
            .iter()
            .any(|key| key.starts_with("erl_tracer#"))
    {
        if function == "enabled" && args.len() == 3 {
            return Some(Ok(tracer_enabled_term(args, state_alive(process, args[1]))));
        }
        if function == "trace" && args.len() == 5 {
            if Pid::from_term(args[1]).is_none() && args[1].as_port().is_none() {
                return Some(Ok(atom("ok")));
            }
            deliver_trace(process, ctx, args);
            return Some(Ok(atom("ok")));
        }
    }
    None
}

pub(crate) fn lookup(module: &str, function: &str, arity: u8) -> Option<BifFn> {
    match module {
        "prim_file" => arinsal_nif_file::lookup(module, function, arity),
        "prim_buffer" => arinsal_nif_buffer::lookup(module, function, arity),
        "zlib" => arinsal_nif_zlib::lookup(module, function, arity),
        "prim_tty" => arinsal_nif_tty::lookup(module, function, arity),
        "prim_socket" | "prim_net" => arinsal_nif_socket::lookup(module, function, arity),
        _ => None,
    }
}
