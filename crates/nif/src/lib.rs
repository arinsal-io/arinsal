//! OTP 29.1.1 native function ABI hosted in the Arinsal executable.
#![allow(clippy::not_unsafe_ptr_arg_deref)]

mod extras;
mod iterators;
mod resources;
mod terms;

pub use extras::{
    SelectMessage, SelectRequest, SentMessage, VmHooks, set_vm_hooks, take_test_messages,
};
pub use resources::{
    enif_keep_resource, enif_release_resource, resource_down, resource_stop, resource_stop_data,
    resource_type_name,
};

// C ABI entry points implemented by shim.c and resolved by dynamically loaded NIFs.
pub const C_SHIM_EXPORTS: &[&str] = &[
    "enif_make_tuple",
    "enif_make_list",
    "enif_set_option",
    "enif_dlopen",
    "enif_dlsym",
    "enif_mutex_create",
    "enif_mutex_destroy",
    "enif_mutex_trylock",
    "enif_mutex_lock",
    "enif_mutex_unlock",
    "enif_mutex_name",
    "enif_cond_create",
    "enif_cond_destroy",
    "enif_cond_signal",
    "enif_cond_broadcast",
    "enif_cond_wait",
    "enif_cond_name",
    "enif_rwlock_create",
    "enif_rwlock_destroy",
    "enif_rwlock_tryrlock",
    "enif_rwlock_rlock",
    "enif_rwlock_runlock",
    "enif_rwlock_tryrwlock",
    "enif_rwlock_rwlock",
    "enif_rwlock_rwunlock",
    "enif_rwlock_name",
    "enif_tsd_key_create",
    "enif_tsd_key_destroy",
    "enif_tsd_set",
    "enif_tsd_get",
    "enif_thread_opts_create",
    "enif_thread_opts_destroy",
    "enif_thread_create",
    "enif_thread_self",
    "enif_equal_tids",
    "enif_thread_exit",
    "enif_thread_join",
    "enif_thread_name",
    "enif_system_info",
    "enif_fprintf",
    "enif_snprintf",
    "enif_vfprintf",
    "enif_vsnprintf",
    "enif_ioq_create",
    "enif_ioq_destroy",
    "enif_ioq_enq_binary",
    "enif_ioq_enqv",
    "enif_ioq_size",
    "enif_ioq_deq",
    "enif_ioq_peek",
    "enif_ioq_peek_head",
    "enif_inspect_iovec",
    "enif_free_iovec",
];

use arinsal_bifs::{BifError, Ctx, SchedulerClass};
use arinsal_term::{
    ExportEntry, ExternalBinary, FunEntry, HeapAlloc, MagicRef, Node, Term, VecHeap, WritableBinary,
};
pub(crate) use libloading::os::unix::Library;
use std::ffi::{CStr, c_char, c_int, c_uint, c_void};
use std::path::Path;
use std::ptr;
use std::sync::{Arc, Condvar, Mutex};

#[allow(non_upper_case_globals)]
mod layout {
    include!(concat!(env!("OUT_DIR"), "/layout.rs"));
}

/// Installed OTP 29 NIF callback signature.
pub type NifFn = unsafe extern "C" fn(*mut ErlNifEnv, c_int, *const Term) -> Term;
type LoadFn = unsafe extern "C" fn(*mut ErlNifEnv, *mut *mut c_void, Term) -> c_int;
type UpgradeFn =
    unsafe extern "C" fn(*mut ErlNifEnv, *mut *mut c_void, *mut *mut c_void, Term) -> c_int;
type UnloadFn = unsafe extern "C" fn(*mut ErlNifEnv, *mut c_void);
#[repr(C)]
struct EntryVersion {
    major: c_int,
    minor: c_int,
}
#[repr(C)]
struct EntryBase {
    major: c_int,
    minor: c_int,
    name: *const c_char,
    num_of_funcs: c_int,
    funcs: *const c_void,
    load: Option<LoadFn>,
    reload: Option<LoadFn>,
    upgrade: Option<UpgradeFn>,
    unload: Option<UnloadFn>,
}
#[repr(C)]
struct ErlNifFuncV1 {
    name: *const c_char,
    arity: c_uint,
    fptr: Option<NifFn>,
}

/// ABI mirror of OTP's function entry.
#[repr(C)]
pub struct ErlNifFunc {
    name: *const c_char,
    arity: c_uint,
    fptr: Option<NifFn>,
    flags: c_uint,
}
/// ABI mirror of OTP's library entry.
#[repr(C)]
pub struct ErlNifEntry {
    major: c_int,
    minor: c_int,
    name: *const c_char,
    num_of_funcs: c_int,
    funcs: *const ErlNifFunc,
    load: Option<LoadFn>,
    reload: Option<LoadFn>,
    upgrade: Option<UpgradeFn>,
    unload: Option<UnloadFn>,
    vm_variant: *const c_char,
    options: c_uint,
    resource_init_size: usize,
    min_erts: *const c_char,
}
/// ABI mirror of OTP's binary descriptor.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ErlNifBinary {
    /// Number of bytes.
    pub size: usize,
    /// Byte pointer.
    pub data: *mut u8,
    ref_bin: *mut c_void,
    spare: [*mut c_void; 2],
}
impl Default for ErlNifBinary {
    fn default() -> Self {
        Self {
            size: 0,
            data: ptr::null_mut(),
            ref_bin: ptr::null_mut(),
            spare: [ptr::null_mut(); 2],
        }
    }
}
/// ABI mirror of OTP's resource callbacks.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct ErlNifResourceTypeInit {
    dtor: Option<unsafe extern "C" fn(*mut ErlNifEnv, *mut c_void)>,
    stop: Option<unsafe extern "C" fn(*mut ErlNifEnv, *mut c_void, c_int, c_int)>,
    down: Option<unsafe extern "C" fn(*mut ErlNifEnv, *mut c_void, *mut c_void, *mut c_void)>,
    members: c_int,
    dyncall: Option<unsafe extern "C" fn(*mut ErlNifEnv, *mut c_void, *mut c_void)>,
}
macro_rules! layout_check {
    ($ty:ident, $size:ident, $($field:ident => $off:ident),+ $(,)?) => {
        const _: () = assert!(size_of::<$ty>() == layout::$size);
        $(const _: () = assert!(std::mem::offset_of!($ty, $field) == layout::$off);)+
    };
}
layout_check!(ErlNifFunc, SIZE_ErlNifFunc, name => OFF_ErlNifFunc_name,
    arity => OFF_ErlNifFunc_arity, fptr => OFF_ErlNifFunc_fptr, flags => OFF_ErlNifFunc_flags);
layout_check!(ErlNifEntry, SIZE_ErlNifEntry, major => OFF_ErlNifEntry_major,
    minor => OFF_ErlNifEntry_minor, name => OFF_ErlNifEntry_name,
    num_of_funcs => OFF_ErlNifEntry_num_of_funcs, funcs => OFF_ErlNifEntry_funcs,
    load => OFF_ErlNifEntry_load, reload => OFF_ErlNifEntry_reload,
    upgrade => OFF_ErlNifEntry_upgrade, unload => OFF_ErlNifEntry_unload,
    vm_variant => OFF_ErlNifEntry_vm_variant, options => OFF_ErlNifEntry_options,
    resource_init_size => OFF_ErlNifEntry_sizeof_ErlNifResourceTypeInit,
    min_erts => OFF_ErlNifEntry_min_erts);
layout_check!(ErlNifBinary, SIZE_ErlNifBinary, size => OFF_ErlNifBinary_size,
    data => OFF_ErlNifBinary_data, ref_bin => OFF_ErlNifBinary_ref_bin,
    spare => OFF_ErlNifBinary___spare__);
layout_check!(ErlNifResourceTypeInit, SIZE_ErlNifResourceTypeInit,
    dtor => OFF_ErlNifResourceTypeInit_dtor, stop => OFF_ErlNifResourceTypeInit_stop,
    down => OFF_ErlNifResourceTypeInit_down, members => OFF_ErlNifResourceTypeInit_members,
    dyncall => OFF_ErlNifResourceTypeInit_dyncall);
const _: () = assert!(size_of::<Term>() == layout::SIZE_ERL_NIF_TERM);

enum EnvHeap {
    Owned(VecHeap),
    Bound(*mut dyn HeapAlloc),
}
impl HeapAlloc for EnvHeap {
    fn alloc(&mut self, n: usize) -> Option<*mut u64> {
        match self {
            Self::Owned(h) => h.alloc(n),
            Self::Bound(h) =>
            // SAFETY: The environment and loaded library remain live throughout this callback.
            unsafe { (&mut **h).alloc(n) },
        }
    }
    fn retain_binary(&mut self, x: Arc<Vec<u8>>) {
        match self {
            Self::Owned(h) => h.retain_binary(x),
            Self::Bound(h) =>
            // SAFETY: The environment and loaded library remain live throughout this callback.
            unsafe { (&mut **h).retain_binary(x) },
        }
    }
    fn retain_writable_binary(
        &mut self,
        x: Arc<WritableBinary>,
    ) -> Result<(), arinsal_term::TermError> {
        match self {
            Self::Owned(h) => h.retain_writable_binary(x),
            Self::Bound(h) =>
            // SAFETY: The environment and loaded library remain live throughout this callback.
            unsafe { (&mut **h).retain_writable_binary(x) },
        }
    }
    fn supports_writable_binary(&self) -> bool {
        match self {
            Self::Owned(h) => h.supports_writable_binary(),
            Self::Bound(h) =>
            // SAFETY: The environment and loaded library remain live throughout this callback.
            unsafe { (&**h).supports_writable_binary() },
        }
    }
    fn retain_external_binary(
        &mut self,
        x: Arc<ExternalBinary>,
    ) -> Result<(), arinsal_term::TermError> {
        match self {
            Self::Owned(h) => h.retain_external_binary(x),
            Self::Bound(h) => {
                // SAFETY: The bound heap remains live and exclusive for this callback.
                unsafe { (&mut **h).retain_external_binary(x) }
            }
        }
    }
    fn supports_external_binary(&self) -> bool {
        match self {
            Self::Owned(h) => h.supports_external_binary(),
            Self::Bound(h) => {
                // SAFETY: The bound heap remains live for this callback.
                unsafe { (&**h).supports_external_binary() }
            }
        }
    }
    fn retain_node(&mut self, x: Arc<Node>) {
        match self {
            Self::Owned(h) => h.retain_node(x),
            Self::Bound(h) =>
            // SAFETY: The environment and loaded library remain live throughout this callback.
            unsafe { (&mut **h).retain_node(x) },
        }
    }
    fn retain_fun(&mut self, x: Arc<FunEntry>) {
        match self {
            Self::Owned(h) => h.retain_fun(x),
            Self::Bound(h) =>
            // SAFETY: The environment and loaded library remain live throughout this callback.
            unsafe { (&mut **h).retain_fun(x) },
        }
    }
    fn retain_export(&mut self, x: Arc<ExportEntry>) {
        match self {
            Self::Owned(h) => h.retain_export(x),
            Self::Bound(h) =>
            // SAFETY: The environment and loaded library remain live throughout this callback.
            unsafe { (&mut **h).retain_export(x) },
        }
    }
    fn retain_magic(&mut self, x: Arc<MagicRef>) {
        match self {
            Self::Owned(h) => h.retain_magic(x),
            Self::Bound(h) =>
            // SAFETY: The environment and loaded library remain live throughout this callback.
            unsafe { (&mut **h).retain_magic(x) },
        }
    }
    fn supports_magic(&self) -> bool {
        match self {
            Self::Owned(h) => h.supports_magic(),
            Self::Bound(h) =>
            // SAFETY: The environment and loaded library remain live throughout this callback.
            unsafe { (&**h).supports_magic() },
        }
    }
}

#[repr(C)]
#[derive(Default)]
struct EnvOptions {
    loading: bool,
    flags: u8,
    on_halt: Option<extern "C" fn(*mut c_void)>,
    on_unload_thread: Option<extern "C" fn(*mut c_void)>,
}

/// Callback environment. C callers treat this as opaque.
#[repr(C)]
pub struct ErlNifEnv {
    options: EnvOptions,
    heap: EnvHeap,
    priv_data: *mut c_void,
    module: Option<String>,
    library: Option<Arc<Library>>,
    pid: Option<Term>,
    pending: Option<Term>,
    scheduled: Option<(NifFn, c_int, Vec<Term>)>,
    independent: bool,
    scratch: Vec<Vec<u8>>,
    owned_binary_allocations: Vec<usize>,
}
impl ErlNifEnv {
    /// Create a process-independent environment with stable owned allocations.
    pub fn independent() -> Self {
        Self {
            heap: EnvHeap::Owned(VecHeap::new()),
            options: EnvOptions::default(),
            priv_data: ptr::null_mut(),
            module: None,
            library: None,
            pid: None,
            pending: None,
            scheduled: None,
            independent: true,
            scratch: Vec::new(),
            owned_binary_allocations: Vec::new(),
        }
    }
    /// Bind a callback to the caller's infallible heap.
    /// The environment must be dropped before the heap can move or be reused.
    pub fn bound(heap: &mut dyn HeapAlloc, pid: Option<Term>) -> Self {
        // SAFETY: the caller keeps this exclusive heap borrow alive for the callback.
        let raw = unsafe { std::mem::transmute::<&mut dyn HeapAlloc, *mut dyn HeapAlloc>(heap) };
        Self {
            heap: EnvHeap::Bound(raw),
            options: EnvOptions::default(),
            priv_data: ptr::null_mut(),
            module: None,
            library: None,
            pid,
            pending: None,
            scheduled: None,
            independent: false,
            scratch: Vec::new(),
            owned_binary_allocations: Vec::new(),
        }
    }
}
impl Drop for ErlNifEnv {
    fn drop(&mut self) {
        for allocation in self.owned_binary_allocations.drain(..) {
            let mut binary = ErlNifBinary {
                size: 0,
                data: allocation as *mut u8,
                ref_bin: allocation as *mut c_void,
                spare: [ptr::null_mut(); 2],
            };
            terms::enif_release_binary(&mut binary);
        }
    }
}
/// Module name and argument term passed to the load callback.
pub struct LoadInfo<'a> {
    pub module: &'a str,
    pub term: Term,
}
/// Checked NIF load or call failure.
#[derive(Debug)]
pub enum NifError {
    /// `dlopen` failed. The string is `dlerror()`.
    Link(String),
    /// `nif_init` / `_nif_init` was not found. The string is `dlerror()`.
    MissingInit(String),
    /// Entry metadata is incompatible with OTP 29.1.1.
    /// The string is the `bad_lib` text erts would return.
    BadLibrary(String),
    /// Load callback rejected the load information.
    LoadRejected(i32),
    /// The new library does not provide an upgrade callback.
    UpgradeUnsupported,
}
impl std::fmt::Display for NifError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for NifError {}

/// A library callback with the same input and output contract as a BIF.
#[derive(Clone)]
pub struct NifFunction {
    pub name: String,
    pub arity: u32,
    pub fptr: NifFn,
    pub flags: u32,
    priv_data: *mut c_void,
    halt_calls: Arc<HaltCalls>,
}
impl NifFunction {
    /// Invoke through a process-bound environment and convert NIF exceptions.
    ///
    /// Continuations scheduled with `enif_schedule_nif` run inline; use
    /// [`NifFunction::call_on`] where they may have to move to another scheduler.
    pub fn call(&self, ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
        self.call_with_pid(ctx, args, None)
    }
    /// Invoke with the calling process ID for `enif_self` and `enif_send`.
    pub fn call_with_pid(
        &self,
        ctx: &mut Ctx<'_>,
        args: &[Term],
        pid: Option<Term>,
    ) -> Result<Term, BifError> {
        if args.len() != self.arity as usize {
            return Err(BifError::BADARG);
        }
        let mut next = (self.fptr, args.to_vec());
        loop {
            match self.step(ctx, next.0, &next.1, pid)? {
                NifCall::Return(value) => return Ok(value),
                NifCall::Schedule(trap) => next = (trap.fptr, trap.args),
            }
        }
    }
    /// Scheduler class this function's dirty flags request.
    pub fn scheduler_class(&self) -> SchedulerClass {
        scheduler_class(self.flags)
    }
    /// Invoke `fptr` (this function or one of its scheduled continuations) on a
    /// scheduler of class `current`.
    ///
    /// Port of erts/emulator/beam/erl_nif.c:3540 (enif_schedule_nif) and
    /// erl_nif.c:440 (erts_call_dirty_nif), OTP-29.1.1: a continuation scheduled
    /// with flags `0` runs at once on a normal scheduler. Any other continuation,
    /// and every continuation scheduled from a dirty scheduler, is returned so
    /// the caller reschedules the process on the requested scheduler class.
    pub fn call_on(
        &self,
        ctx: &mut Ctx<'_>,
        fptr: NifFn,
        args: &[Term],
        pid: Option<Term>,
        current: SchedulerClass,
    ) -> Result<NifCall, BifError> {
        let mut result = self.step(ctx, fptr, args, pid)?;
        while let NifCall::Schedule(trap) = &result {
            if current != SchedulerClass::Normal || scheduler_class(trap.flags) != current {
                break;
            }
            let NifCall::Schedule(trap) = result else {
                unreachable!()
            };
            result = self.step(ctx, trap.fptr, &trap.args, pid)?;
        }
        Ok(result)
    }
    fn step(
        &self,
        ctx: &mut Ctx<'_>,
        fptr: NifFn,
        args: &[Term],
        pid: Option<Term>,
    ) -> Result<NifCall, BifError> {
        let _call = (self.flags != 0).then(|| self.halt_calls.enter()).flatten();
        let mut env = ErlNifEnv::bound(ctx.heap, pid);
        env.priv_data = self.priv_data;
        // SAFETY: the pointer belongs to a loaded library; arguments remain live.
        let result = unsafe { fptr(&mut env, args.len() as c_int, args.as_ptr()) };
        if let Some(reason) = env.pending {
            return Err(BifError::Error(reason));
        }
        if let Some((fptr, flags, args)) = env.scheduled.take() {
            return Ok(NifCall::Schedule(NifTrap {
                fptr,
                flags: flags as u32,
                args,
            }));
        }
        Ok(NifCall::Return(result))
    }
}

/// Map `ErlNifFunc.flags` or `enif_schedule_nif` flags to a scheduler class.
///
/// Port of erts/emulator/beam/erl_nif.c:3566-3572 (enif_schedule_nif), OTP-29.1.1:
/// any dirty flag other than exactly `ERL_NIF_DIRTY_JOB_CPU_BOUND` selects I/O.
pub fn scheduler_class(flags: u32) -> SchedulerClass {
    match flags {
        0 => SchedulerClass::Normal,
        ERL_NIF_DIRTY_JOB_CPU_BOUND => SchedulerClass::DirtyCpu,
        _ => SchedulerClass::DirtyIo,
    }
}

/// `ERL_NIF_DIRTY_JOB_CPU_BOUND` from erl_nif.h.
pub const ERL_NIF_DIRTY_JOB_CPU_BOUND: u32 = 1;
/// `ERL_NIF_DIRTY_JOB_IO_BOUND` from erl_nif.h.
pub const ERL_NIF_DIRTY_JOB_IO_BOUND: u32 = 2;

/// Outcome of one NIF invocation.
pub enum NifCall {
    /// The NIF returned this term.
    Return(Term),
    /// The NIF called `enif_schedule_nif`; the continuation still has to run.
    Schedule(NifTrap),
}

/// A continuation scheduled with `enif_schedule_nif`.
///
/// Port of erts/emulator/beam/erl_nfunc_sched.h (`ErtsNativeFunc`), OTP-29.1.1.
/// `args` are process heap terms; the owner keeps them as GC roots.
#[derive(Clone)]
pub struct NifTrap {
    /// Function to call next.
    pub fptr: NifFn,
    /// `enif_schedule_nif` flags selecting its scheduler class.
    pub flags: u32,
    /// Arguments for `fptr`.
    pub args: Vec<Term>,
}
struct HaltCalls {
    enabled: bool,
    in_flight: Mutex<usize>,
    idle: Condvar,
}
impl HaltCalls {
    fn enter(&self) -> Option<HaltCall<'_>> {
        if !self.enabled {
            return None;
        }
        *self
            .in_flight
            .lock()
            .unwrap_or_else(|poison| poison.into_inner()) += 1;
        Some(HaltCall(self))
    }
    /// Port of erts/emulator/beam/erl_nif.c:5626-5649, OTP-29.1.1.
    pub fn wait(&self) {
        if !self.enabled {
            return;
        }
        let mut in_flight = self
            .in_flight
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        while *in_flight != 0 {
            in_flight = self
                .idle
                .wait(in_flight)
                .unwrap_or_else(|poison| poison.into_inner());
        }
    }
}
struct HaltCall<'a>(&'a HaltCalls);
impl Drop for HaltCall<'_> {
    fn drop(&mut self) {
        let mut in_flight = self
            .0
            .in_flight
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        *in_flight -= 1;
        if *in_flight == 0 {
            self.0.idle.notify_all();
        }
    }
}

#[cfg(test)]
mod halt_tests {
    use super::HaltCalls;
    use std::sync::{Arc, Barrier, Condvar, Mutex, mpsc};
    use std::time::Duration;

    #[test]
    fn nif_api2_delay_halt_waits_for_dirty_calls() {
        let calls = Arc::new(HaltCalls {
            enabled: true,
            in_flight: Mutex::new(0),
            idle: Condvar::new(),
        });
        let call = calls.enter().expect("enabled call tracking");
        let barrier = Arc::new(Barrier::new(2));
        let (sent, received) = mpsc::channel();
        let waiter_calls = Arc::clone(&calls);
        let waiter_barrier = Arc::clone(&barrier);
        let waiter = std::thread::spawn(move || {
            waiter_barrier.wait();
            waiter_calls.wait();
            sent.send(()).unwrap();
        });
        barrier.wait();
        assert!(received.recv_timeout(Duration::from_millis(25)).is_err());
        drop(call);
        received
            .recv_timeout(Duration::from_secs(1))
            .expect("halt continues when the dirty call returns");
        waiter.join().unwrap();
    }
}
/// Loaded library and copied function table. Drop calls the unload callback.
pub struct NifLibrary {
    _library: Arc<Library>,
    module: String,
    functions: Vec<NifFunction>,
    unload: Option<UnloadFn>,
    on_halt: Option<extern "C" fn(*mut c_void)>,
    on_unload_thread: Option<extern "C" fn(*mut c_void)>,
    priv_data: *mut c_void,
    halt_calls: Arc<HaltCalls>,
}
impl NifLibrary {
    /// Return name, arity, address, and dirty flags for each entry.
    pub fn functions(&self) -> Vec<(String, u32, NifFn, u32)> {
        self.functions
            .iter()
            .map(|f| (f.name.clone(), f.arity, f.fptr, f.flags))
            .collect()
    }
    /// Resolve a callback by name and arity.
    pub fn lookup(&self, name: &str, arity: usize) -> Option<&NifFunction> {
        self.functions
            .iter()
            .find(|f| f.name == name && f.arity as usize == arity)
    }
    /// Callback at a table index, in `ErlNifEntry` order.
    pub fn function(&self, index: usize) -> Option<&NifFunction> {
        self.functions.get(index)
    }
    /// Run the callback registered with `ERL_NIF_OPT_ON_HALT`.
    pub fn execute_on_halt(&self) {
        if let Some(callback) = self.on_halt {
            callback(self.priv_data);
        }
    }
    /// Wait for calls in a library that requested `ERL_NIF_OPT_DELAY_HALT`.
    pub fn wait_for_halt_calls(&self) {
        self.halt_calls.wait();
    }
}
// SAFETY: after `load` returns, OTP invokes NIF entry points from any scheduler.
// `priv_data` is published before the library is callable and the host does not
// mutate it. The dynamic library itself is `Send + Sync`.
unsafe impl Send for NifLibrary {}
// SAFETY: same as `Send`. Concurrent NIF calls only read `priv_data` and the
// loaded code after `load` has published them.
unsafe impl Sync for NifLibrary {}

impl Drop for NifLibrary {
    fn drop(&mut self) {
        if let Some(callback) = self.on_unload_thread {
            callback(self.priv_data);
        }
        if let Some(unload) = self.unload {
            let mut env = ErlNifEnv::independent();
            env.module = Some(self.module.clone());
            // SAFETY: the library stays open until Drop completes.
            unsafe { unload(&mut env, self.priv_data) };
        }
    }
}
/// A loaded NIF image whose `load` callback has not run yet.
///
/// Dropping it closes the dynamic library without calling `unload`.
pub struct NifImage {
    library: Arc<Library>,
    module: String,
    functions: Vec<NifFunction>,
    load: Option<LoadFn>,
    upgrade: Option<UpgradeFn>,
    unload: Option<UnloadFn>,
}
impl NifImage {
    /// Function table in `ErlNifEntry` order. Dirty flags are `0`, `1` (CPU), or `2` (I/O).
    pub fn functions(&self) -> &[NifFunction] {
        &self.functions
    }
    /// Run the load callback and return the callable library.
    pub fn commit(self, term: Term) -> Result<NifLibrary, NifError> {
        self.finish(term, None)
    }
    fn finish(
        mut self,
        term: Term,
        old_priv_data: Option<&mut *mut c_void>,
    ) -> Result<NifLibrary, NifError> {
        let mut env = ErlNifEnv::independent();
        env.module = Some(self.module.clone());
        env.library = Some(Arc::clone(&self.library));
        env.options.loading = true;
        let mut priv_data = ptr::null_mut();
        let code = if let Some(old) = old_priv_data {
            let upgrade = self.upgrade.ok_or(NifError::UpgradeUnsupported)?;
            // SAFETY: this loaded library declares its upgrade ABI and both data pointers are live.
            unsafe { upgrade(&mut env, &mut priv_data, old, term) }
        } else if let Some(load) = self.load {
            // SAFETY: the library's callback follows its declared entry ABI.
            unsafe { load(&mut env, &mut priv_data, term) }
        } else {
            0
        };
        env.options.loading = false;
        if code != 0 {
            return Err(NifError::LoadRejected(code));
        }
        let halt_calls = Arc::new(HaltCalls {
            enabled: env.options.flags & 1 != 0,
            in_flight: Mutex::new(0),
            idle: Condvar::new(),
        });
        for function in &mut self.functions {
            function.priv_data = priv_data;
            function.halt_calls = Arc::clone(&halt_calls);
        }
        Ok(NifLibrary {
            _library: self.library,
            module: self.module,
            functions: self.functions,
            unload: self.unload,
            on_halt: env.options.on_halt,
            on_unload_thread: env.options.on_unload_thread,
            priv_data,
            halt_calls,
        })
    }
}
/// Open `path`, check the OTP 29 entry, and return it before the load callback.
///
/// `dlopen` uses `RTLD_NOW | RTLD_LOCAL` (flags `0x6` on macOS), matching OTP 29.1.1.
/// Symbol lookup tries `nif_init` and then `_nif_init`, as `erts_sys_ddll_load_nif_init` does.
pub fn open_nif(path: &Path, module: &str) -> Result<NifImage, NifError> {
    ensure_exports();
    // SAFETY: the opened code remains loaded in the returned image.
    let library = Arc::new(
        unsafe {
            Library::open(
                Some(path),
                libloading::os::unix::RTLD_NOW | libloading::os::unix::RTLD_LOCAL,
            )
        }
        .map_err(|error| NifError::Link(error.to_string()))?,
    );
    // SAFETY: Unix NIFs export this fixed-signature entry function.
    let init = unsafe {
        library
            .get::<unsafe extern "C" fn() -> *const EntryVersion>(b"nif_init\0")
            .or_else(|_| library.get(b"_nif_init\0"))
            .map_err(|error| NifError::MissingInit(error.to_string()))?
    };
    // SAFETY: a non-null entry points to static data while the library stays loaded.
    let version = unsafe { (*init)().as_ref() }
        .ok_or_else(|| NifError::BadLibrary("Library init-call unsuccessful".into()))?;
    // Port of erts/emulator/beam/erl_nif.c:4799 (erts_load_nif version checks), OTP-29.1.1.
    if version.major > 2 || (version.major == 2 && version.minor > 18) {
        let raw = version as *const EntryVersion as *const ErlNifEntry;
        // SAFETY: a too-new entry is at least 2.14 and carries min_erts.
        let min_erts_ptr = unsafe { std::ptr::addr_of!((*raw).min_erts).read() };
        let min_erts = if min_erts_ptr.is_null() {
            "erts-?".to_owned()
        } else {
            // SAFETY: min_erts is a terminated string in the loaded library.
            unsafe { CStr::from_ptr(min_erts_ptr) }
                .to_string_lossy()
                .into_owned()
        };
        return Err(NifError::BadLibrary(format!(
            "That '{module}' NIF library needs {min_erts} or newer. Either try to recompile the NIF lib or use a newer erts runtime."
        )));
    }
    if version.major < 2 || (version.major == 2 && version.minor == 5) || version.minor < 0 {
        return Err(NifError::BadLibrary(format!(
            "That old NIF library ({}.{}) is not compatible with this erts runtime (2.18). Try recompile the NIF lib.",
            version.major, version.minor
        )));
    }
    // Port of erts/emulator/beam/erl_nif.c:4565 (create_lib), OTP-29.1.1.
    // SAFETY: every supported entry has the base fields through unload.
    let base = unsafe { &*(version as *const EntryVersion as *const EntryBase) };
    let raw = version as *const EntryVersion as *const ErlNifEntry;
    let variant = if version.minor >= 1 {
        // SAFETY: the 2.1 entry added vm_variant at this offset.
        unsafe { std::ptr::addr_of!((*raw).vm_variant).read() }
    } else {
        c"beam.vanilla".as_ptr()
    };
    let entry = ErlNifEntry {
        major: base.major,
        minor: base.minor,
        name: base.name,
        num_of_funcs: base.num_of_funcs,
        funcs: base.funcs.cast(),
        load: base.load,
        reload: base.reload,
        upgrade: base.upgrade,
        unload: base.unload,
        vm_variant: variant,
        options: 0,
        resource_init_size: 0,
        min_erts: ptr::null(),
    };
    if entry.name.is_null()
        || entry.vm_variant.is_null()
        || entry.num_of_funcs < 0
        || entry.num_of_funcs > 10_000
        || entry.funcs.is_null()
    {
        return Err(NifError::BadLibrary("invalid entry fields".into()));
    }
    // SAFETY: validated pointers refer to terminated strings in the loaded library.
    let name = unsafe { CStr::from_ptr(entry.name) }.to_string_lossy();
    // SAFETY: validated pointers refer to terminated strings in the loaded library.
    let variant = unsafe { CStr::from_ptr(entry.vm_variant) }.to_string_lossy();
    if variant != "beam.vanilla" {
        return Err(NifError::BadLibrary(format!(
            "Library ({variant}) not compiled for this vm variant (beam.vanilla)."
        )));
    }
    if name != module {
        return Err(NifError::BadLibrary(format!(
            "Library module name '{name}' does not match calling module '{module}'"
        )));
    }
    let mut functions = Vec::with_capacity(entry.num_of_funcs as usize);
    for index in 0..entry.num_of_funcs as usize {
        let (fname_ptr, arity, fptr, flags) = if entry.minor >= 7 {
            // SAFETY: the 2.7+ function table has four fields per entry.
            let func = unsafe { &*entry.funcs.add(index) };
            (func.name, func.arity, func.fptr, func.flags)
        } else {
            // SAFETY: earlier function tables have three fields per entry.
            let func = unsafe { &*entry.funcs.cast::<ErlNifFuncV1>().add(index) };
            (func.name, func.arity, func.fptr, 0)
        };
        if fname_ptr.is_null() {
            return Err(NifError::BadLibrary("invalid NIF function".into()));
        }
        // SAFETY: entry function names are terminated strings.
        let fname = unsafe { CStr::from_ptr(fname_ptr) }
            .to_string_lossy()
            .into_owned();
        let fptr = fptr.ok_or_else(|| NifError::BadLibrary("null NIF function".into()))?;
        // Port of erts/emulator/beam/erl_nif.c:4868 (erts_load_nif flag check), OTP-29.1.1.
        if flags != 0 && flags != ERL_NIF_DIRTY_JOB_IO_BOUND && flags != ERL_NIF_DIRTY_JOB_CPU_BOUND
        {
            return Err(NifError::BadLibrary(format!(
                "Illegal flags field value {flags} for NIF {module}:{fname}/{arity}"
            )));
        }
        functions.push(NifFunction {
            name: fname,
            arity,
            fptr,
            flags,
            priv_data: ptr::null_mut(),
            halt_calls: Arc::new(HaltCalls {
                enabled: false,
                in_flight: Mutex::new(0),
                idle: Condvar::new(),
            }),
        });
    }
    Ok(NifImage {
        library,
        module: module.to_owned(),
        functions,
        load: entry.load,
        upgrade: entry.upgrade,
        unload: entry.unload,
    })
}
/// Load a NIF library, validate its entry, and invoke its load callback.
pub fn load_nif(path: &Path, info: LoadInfo<'_>) -> Result<NifLibrary, NifError> {
    open_nif(path, info.module)?.commit(info.term)
}
/// Load a replacement library and pass the old private data to its upgrade callback.
pub fn upgrade_nif(
    path: &Path,
    info: LoadInfo<'_>,
    old: &mut NifLibrary,
) -> Result<NifLibrary, NifError> {
    open_nif(path, info.module)?.finish(info.term, Some(&mut old.priv_data))
}
unsafe extern "C" {
    fn arinsal_nif_shim_anchor();
}
/// Force the C shim and its exported symbols into the final executable.
pub fn ensure_exports() {
    // SAFETY: the anchor has no arguments or side effects.
    unsafe { arinsal_nif_shim_anchor() };
    terms::retain_exports();
    resources::retain_exports();
    extras::retain_exports();
    iterators::retain_exports();
}
pub(crate) fn term(bits: u64) -> Term {
    // SAFETY: callers obtain bits from existing terms or the NIF ABI.
    unsafe { std::mem::transmute::<u64, Term>(bits) }
}
pub(crate) fn bits(term: Term) -> u64 {
    // SAFETY: the term remains on a live heap during the call.
    unsafe { term.raw_bits() }
}
