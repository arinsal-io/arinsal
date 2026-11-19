//! OTP 29.1.1 native function ABI hosted in the Arinsal executable.
#![allow(clippy::not_unsafe_ptr_arg_deref)]

mod binref;
mod extras;
mod internal_test;
mod ioq;
mod iovec;
mod iterators;
mod raw;
mod res_monitor;
mod resources;
mod terms;
pub use terms::{
    enif_has_pending_exception, enif_is_exception, enif_make_atom, enif_make_badarg,
    enif_raise_exception,
};

pub use extras::{
    SelectMessage, SelectRequest, SendHook, SentMessage, VmHooks, set_vm_hooks, take_test_messages,
};
pub use raw::MonitoredResourcePayload;
pub use res_monitor::{
    DownFn, MonitorsOf, ResourceMonitor, ResourceMonitorCount, ResourceMonitors,
};
pub use resources::{
    LibraryRefs, enif_keep_resource, enif_release_resource, resource_down, resource_stop,
    resource_stop_data, resource_type_name,
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

use crate::raw::{cstr, deref, deref_mut};
use arinsal_bifs::SchedulerClass;
use arinsal_term::exc::ExcFields;
use arinsal_term::{
    ExternalBinary, HeapAlloc, MagicBin, Node, ProcessHeap, Term, VecHeap, WritableBinary,
};
pub(crate) use libloading::os::unix::Library;
use std::ffi::{c_char, c_int, c_uint, c_void};
use std::path::Path;
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicPtr, Ordering};
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

/// `MIN_HEAP_FRAG_SZ` (erl_nif.c): the extra words of a heap fragment `alloc_heap_heavy` adds.
const MIN_HEAP_FRAG_SZ: usize = 200;

/// The process heap part of `struct enif_environment_t`: `proc`, `hp`, `hp_end` and
/// `heap_frag` (`heap_frag` as the `mem` of the fragment `hp` points into, or null).
///
/// Port of erts/emulator/beam/global.h:57-72 (struct enif_environment_t), OTP-29.1.1.
pub(crate) struct ProcEnv {
    proc: *mut ProcessHeap,
    hp: *mut u64,
    hp_end: *mut u64,
    heap_frag: *mut u64,
}
impl ProcEnv {
    pub(crate) fn proc_mut(&mut self) -> &mut ProcessHeap {
        // SAFETY: `erts_pre_nif` ties `proc` to the running process for the whole callback.
        deref_mut(self.proc)
    }
    fn proc_ref(&self) -> &ProcessHeap {
        // SAFETY: `erts_pre_nif` ties `proc` to the running process for the whole callback.
        deref(self.proc)
    }
    /// Port of erts/emulator/beam/erl_nif.c:207-215 (alloc_heap), OTP-29.1.1.
    #[inline(always)]
    fn alloc_heap(&mut self, need: usize) -> *mut u64 {
        let hp = self.hp;
        let end = hp.wrapping_add(need);
        if end <= self.hp_end {
            self.hp = end;
            return hp;
        }
        self.alloc_heap_heavy(need, hp)
    }
    /// Port of erts/emulator/beam/erl_nif.c:217-237 (alloc_heap_heavy), OTP-29.1.1.
    #[cold]
    fn alloc_heap_heavy(&mut self, need: usize, hp: *mut u64) -> *mut u64 {
        self.hp = hp;
        if self.heap_frag.is_null() {
            debug_assert_eq!(self.proc_ref().heap_limit(), self.hp_end);
            let top = self.hp;
            self.proc_mut().abi.htop = top;
        } else {
            let usz = (self.hp as usize - self.heap_frag as usize) / 8;
            self.proc_mut().set_mbuf_head_used(usz);
        }
        let hp = self
            .proc_mut()
            .heap_fragment_with_extra(need, MIN_HEAP_FRAG_SZ);
        let (mem, _, alloc_size) = self.proc_ref().mbuf_head().expect("erts_heap_alloc MBUF");
        self.heap_frag = mem;
        self.hp = hp.wrapping_add(need);
        self.hp_end = mem.wrapping_add(alloc_size);
        hp
    }
    /// Port of erts/emulator/beam/erl_nif.c:571-590 (flush_env), OTP-29.1.1: write the cached
    /// heap pointers back so an ordinary `HAlloc` can run.
    pub(crate) fn flush_env(&mut self) {
        if self.heap_frag.is_null() {
            debug_assert_eq!(self.hp_end, self.proc_ref().heap_limit());
            debug_assert!(self.hp >= self.proc_ref().abi.htop);
            let top = self.hp;
            self.proc_mut().abi.htop = top;
        } else {
            debug_assert_eq!(
                self.proc_ref().mbuf_head().map(|h| h.0),
                Some(self.heap_frag)
            );
            let usz = (self.hp as usize - self.heap_frag as usize) / 8;
            self.proc_mut().set_mbuf_head_used(usz);
        }
    }
    /// Port of erts/emulator/beam/erl_nif.c:592-607 (cache_env), OTP-29.1.1: reload the
    /// heap pointers after an ordinary `HAlloc`.
    pub(crate) fn cache_env(&mut self) {
        match self.proc_ref().mbuf_head() {
            None => {
                self.heap_frag = ptr::null_mut();
                self.hp = self.proc_ref().abi.htop;
                self.hp_end = self.proc_ref().heap_limit();
            }
            Some((mem, used, alloc_size)) => {
                self.heap_frag = mem;
                self.hp = mem.wrapping_add(used);
                self.hp_end = mem.wrapping_add(alloc_size);
            }
        }
    }
}

/// Where the terms of an environment live: a process (`env->proc`) or the heap of a
/// process-independent environment with the `freason`/`fvalue` words of its phony process.
pub(crate) enum EnvHeap {
    Owned(Box<VecHeap>, ExcFields),
    Proc(ProcEnv),
}
macro_rules! env_heap_forward {
    ($self:ident, $h:ident => $e:expr) => {
        match $self {
            EnvHeap::Owned($h, _) => $e,
            EnvHeap::Proc(p) => {
                let $h = p.proc_mut();
                $e
            }
        }
    };
}
macro_rules! env_heap_forward_ref {
    ($self:ident, $h:ident => $e:expr) => {
        match $self {
            EnvHeap::Owned($h, _) => $e,
            EnvHeap::Proc(p) => {
                let $h = p.proc_ref();
                $e
            }
        }
    };
}
impl EnvHeap {
    /// `env->proc->freason` / `fvalue` (`phony_proc` for an independent environment).
    pub(crate) fn exc_mut(&mut self) -> &mut ExcFields {
        match self {
            EnvHeap::Owned(_, exc) => exc,
            EnvHeap::Proc(p) => &mut p.proc_mut().abi.exc,
        }
    }
    pub(crate) fn exc(&self) -> &ExcFields {
        match self {
            EnvHeap::Owned(_, exc) => exc,
            EnvHeap::Proc(p) => &p.proc_ref().abi.exc,
        }
    }
    /// `env->proc` when the environment is bound to a process.
    pub(crate) fn proc_env(&mut self) -> Option<&mut ProcEnv> {
        match self {
            EnvHeap::Owned(..) => None,
            EnvHeap::Proc(p) => Some(p),
        }
    }
}
impl HeapAlloc for EnvHeap {
    #[inline(always)]
    fn alloc(&mut self, n: usize) -> Option<*mut u64> {
        match self {
            Self::Owned(h, _) => h.alloc(n),
            Self::Proc(p) => Some(p.alloc_heap(n)),
        }
    }
    fn alloc_fragment_only(&mut self, n: usize) -> Option<*mut u64> {
        match self {
            Self::Owned(h, _) => h.alloc_fragment_only(n),
            // Port of erts/emulator/beam/erl_nif.c (flush_env; HAlloc; cache_env), OTP-29.1.1.
            Self::Proc(p) => {
                p.flush_env();
                let hp = p.proc_mut().alloc_fragment_only(n);
                p.cache_env();
                hp
            }
        }
    }
    fn words_left(&self) -> Option<usize> {
        match self {
            Self::Owned(h, _) => h.words_left(),
            Self::Proc(p) => Some((p.hp_end as usize).saturating_sub(p.hp as usize) / 8),
        }
    }
    fn release(&mut self, end: *mut u64, start: *mut u64) {
        match self {
            Self::Owned(h, _) => h.release(end, start),
            // HRelease on the cached window: only the newest words move back.
            Self::Proc(p) => {
                if end == p.hp && start <= end {
                    p.hp = start;
                }
            }
        }
    }
    fn release_needs_filler(&self, end: *mut u64, start: *mut u64) -> bool {
        match self {
            Self::Owned(h, _) => h.release_needs_filler(end, start),
            Self::Proc(p) => start != end && end != p.hp,
        }
    }
    fn retain_binary(&mut self, x: Arc<arinsal_term::RefcBinary>) {
        env_heap_forward!(self, h => h.retain_binary(x))
    }
    fn link_bin_ref(
        &mut self,
        bin_ref: *mut u64,
        writable: bool,
        overhead_words: u64,
        owner: Option<arinsal_term::OwnedBinaryRef>,
    ) -> Result<(), arinsal_term::TermError> {
        env_heap_forward!(self, h => h.link_bin_ref(bin_ref, writable, overhead_words, owner))
    }
    fn add_bin_vheap(&mut self, words: u64) {
        env_heap_forward!(self, h => h.add_bin_vheap(words))
    }
    fn retain_writable_binary(
        &mut self,
        x: Arc<WritableBinary>,
    ) -> Result<(), arinsal_term::TermError> {
        env_heap_forward!(self, h => h.retain_writable_binary(x))
    }
    fn retain_writable_binary_with_apparent_size(
        &mut self,
        x: Arc<WritableBinary>,
        apparent_size_bits: usize,
    ) -> Result<(), arinsal_term::TermError> {
        env_heap_forward!(self, h => h.retain_writable_binary_with_apparent_size(x, apparent_size_bits))
    }
    fn update_writable_binary_overhead(
        &mut self,
        source: Term,
        old_size_bits: usize,
        new_size_bits: usize,
    ) {
        env_heap_forward!(self, h => h.update_writable_binary_overhead(source, old_size_bits, new_size_bits))
    }
    fn supports_writable_binary(&self) -> bool {
        env_heap_forward_ref!(self, h => h.supports_writable_binary())
    }
    fn link_external_binary(
        &mut self,
        bin_ref: *mut u64,
        x: Arc<ExternalBinary>,
    ) -> Result<(), arinsal_term::TermError> {
        env_heap_forward!(self, h => h.link_external_binary(bin_ref, x))
    }
    fn supports_external_binary(&self) -> bool {
        env_heap_forward_ref!(self, h => h.supports_external_binary())
    }
    fn link_node(&mut self, thing: *mut u64, x: Node) {
        env_heap_forward!(self, h => h.link_node(thing, x))
    }
    fn link_magic_ref(
        &mut self,
        thing: *mut u64,
        x: MagicBin,
    ) -> Result<(), arinsal_term::TermError> {
        env_heap_forward!(self, h => h.link_magic_ref(thing, x))
    }
    fn supports_magic(&self) -> bool {
        env_heap_forward_ref!(self, h => h.supports_magic())
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
    /// The `priv_data` slot a load or upgrade callback writes through its `void **priv`
    /// argument; `enif_priv_data` reads it during the callback (erts `env->mod_nif->priv_data`).
    priv_cell: Option<Arc<AtomicPtr<c_void>>>,
    module: Option<String>,
    library: Option<Arc<Library>>,
    pid: Option<Term>,
    /// `exception_thrown`: `enif_raise_exception` left the reason in `env->proc->fvalue`.
    exception_thrown: bool,
    independent: bool,
    scratch: Vec<Vec<u8>>,
    owned_binary_allocations: Vec<usize>,
    /// `opened_rt_list`: resource types this load callback created or took over.
    opened: Vec<resources::OpenedType>,
    /// I/O vectors attached to this environment by `enif_inspect_iovec` (`alloc_tmp_obj`).
    tmp_iovecs: Vec<Vec<u64>>,
    /// `Binary*` handles attached to this environment: freed with it.
    tmp_handles: Vec<usize>,
}
impl ErlNifEnv {
    fn with_heap(heap: EnvHeap, pid: Option<Term>, independent: bool) -> Self {
        Self {
            heap,
            options: EnvOptions::default(),
            priv_data: ptr::null_mut(),
            priv_cell: None,
            module: None,
            library: None,
            pid,
            exception_thrown: false,
            independent,
            scratch: Vec::new(),
            owned_binary_allocations: Vec::new(),
            opened: Vec::new(),
            tmp_iovecs: Vec::new(),
            tmp_handles: Vec::new(),
        }
    }
    /// Create a process-independent environment with stable owned allocations.
    pub fn independent() -> Self {
        Self::with_heap(
            EnvHeap::Owned(Box::new(VecHeap::new()), ExcFields::default()),
            None,
            true,
        )
    }
    /// `erts_pre_nif`: bind an environment to the process heap `p` (`env->proc`) and cache
    /// `HEAP_TOP(p)` / `HEAP_LIMIT(p)` in `hp` / `hp_end`. [`ErlNifEnv::post_nif`] must run
    /// before anything else allocates on `p`.
    ///
    /// Port of erts/emulator/beam/erl_nif.c:249-282 (erts_pre_nif), OTP-29.1.1.
    pub fn pre_nif(p: &mut ProcessHeap, pid: Option<Term>) -> Self {
        let hp = p.abi.htop;
        let hp_end = p.heap_limit();
        Self::with_heap(
            EnvHeap::Proc(ProcEnv {
                proc: p,
                hp,
                hp_end,
                heap_frag: ptr::null_mut(),
            }),
            pid,
            false,
        )
    }
    /// `erts_post_nif`: write the cached heap pointers back to the process (`full_flush_env`)
    /// and free the temporary objects of the call (`free_tmp_objs`, by drop).
    ///
    /// Port of erts/emulator/beam/erl_nif.c:350-355 (erts_post_nif) and erl_nif.c:546-552
    /// (full_flush_env), OTP-29.1.1. A dirty call's shadow heap is flushed into the real
    /// process by the dirty executor (`erts_flush_dirty_shadow_proc`).
    pub fn post_nif(mut self) -> bool {
        if let Some(p) = self.heap.proc_env() {
            p.flush_env();
        }
        self.exception_thrown
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
        for handle in self.tmp_handles.drain(..) {
            binref::handle_free(handle as *mut c_void);
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
    /// Upgrade callback rejected the load information.
    UpgradeRejected(i32),
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
    /// The library's `priv_data`, shared so an upgrade of a newer library can replace it.
    priv_data: Arc<AtomicPtr<c_void>>,
    halt_calls: Arc<HaltCalls>,
}
impl NifFunction {
    /// Invoke on the process heap `p`. An exception returns `THE_NON_VALUE` with the reason in
    /// `p`'s `freason`/`fvalue`, as `beam_jit_call_nif` sees it.
    ///
    /// Continuations scheduled with `enif_schedule_nif` run inline; use
    /// [`NifFunction::call_on`] where they may have to move to another scheduler.
    pub fn call(&self, p: &mut ProcessHeap, args: &[Term]) -> Term {
        self.call_with_pid(p, args, None)
    }
    /// Invoke with the calling process ID for `enif_self` and `enif_send`.
    pub fn call_with_pid(&self, p: &mut ProcessHeap, args: &[Term], pid: Option<Term>) -> Term {
        if args.len() != self.arity as usize {
            // BIF_ERROR(p, BADARG) (bif.h).
            p.abi.exc.freason = arinsal_term::exc::EXC_BADARG;
            return Term::NON_VALUE;
        }
        self.step(p, self.fptr, args, pid)
    }
    /// Scheduler class this function's dirty flags request.
    pub fn scheduler_class(&self) -> SchedulerClass {
        scheduler_class(self.flags)
    }
    /// One call of `fptr` between `erts_pre_nif` and `erts_post_nif`.
    // Port of erts/emulator/beam/jit/beam_jit_common.cpp:623-677 (beam_jit_call_nif: pre_nif,
    // `fp(&env, arity, reg)`, `exception_thrown` -> THE_NON_VALUE, post_nif), OTP-29.1.1.
    fn step(&self, p: &mut ProcessHeap, fptr: NifFn, args: &[Term], pid: Option<Term>) -> Term {
        step(
            (&self.priv_data, &self.halt_calls, self.flags != 0),
            p,
            fptr,
            (args.as_ptr(), args.len()),
            pid,
        )
    }
}

/// One call of `fptr` between `erts_pre_nif` and `erts_post_nif`, with the library's
/// `priv_data`; a dirty call counts for the library's on-halt wait.
// Port of erts/emulator/beam/jit/beam_jit_common.cpp:623-677 (beam_jit_call_nif: pre_nif,
// `fp(&env, arity, reg)`, `exception_thrown` -> THE_NON_VALUE, post_nif), OTP-29.1.1.
fn step(
    (priv_data, halt_calls, dirty): (&AtomicPtr<c_void>, &HaltCalls, bool),
    p: &mut ProcessHeap,
    fptr: NifFn,
    (argv, argc): (*const Term, usize),
    pid: Option<Term>,
) -> Term {
    let _call = dirty.then(|| halt_calls.enter()).flatten();
    let mut env = ErlNifEnv::pre_nif(p, pid);
    env.priv_data = priv_data.load(Ordering::Acquire);
    // SAFETY: the pointer belongs to a loaded library; `argv` holds `argc` live terms (the
    // caller's argument registers, which a scheduling NIF may overwrite as in erts).
    let result = unsafe { fptr(&mut env, argc as c_int, argv) };
    if env.post_nif() {
        return Term::NON_VALUE;
    }
    result
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
/// Loaded library and copied function table. [`NifLibrary::close`] (or Drop) calls the unload
/// callback.
pub struct NifLibrary {
    /// The `dlopen` handle, released by [`NifLibrary::close`].
    library: Mutex<Option<Arc<Library>>>,
    closed: AtomicBool,
    module: String,
    functions: Vec<NifFunction>,
    unload: Option<UnloadFn>,
    on_halt: Option<extern "C" fn(*mut c_void)>,
    on_unload_thread: Option<extern "C" fn(*mut c_void)>,
    /// `erl_module_nif.priv_data`, which an upgrade of a newer library may replace.
    priv_data: Arc<AtomicPtr<c_void>>,
    halt_calls: Arc<HaltCalls>,
    on_halt_called: AtomicBool,
    /// This library as the owner of resource types.
    owner: Arc<resources::ResourceOwner>,
    /// Types opened by the load callback, applied by [`NifLibrary::commit_resource_types`].
    pending_types: Mutex<Vec<resources::OpenedType>>,
}
impl NifLibrary {
    /// Make the resource types the load callback opened live; `refs` is this library's
    /// `dynlib_refc`.
    // Port of erts/emulator/beam/erl_nif.c:4997 (prepare_opened_rt, commit_opened_rt and
    // cleanup_opened_rt in erts_load_nif), OTP-29.1.1.
    pub fn commit_resource_types(&self, refs: &Arc<dyn resources::LibraryRefs>) {
        let opened = std::mem::take(&mut *self.pending_types.lock().unwrap());
        resources::commit_opened(opened, &self.owner, refs);
    }
    /// [`NifLibrary::commit_resource_types`] for a library loaded by [`load_nif`] or
    /// [`upgrade_nif`], which has no module instance holding `dynlib_refc`.
    pub fn commit_standalone_types(&self) {
        self.commit_resource_types(&(Arc::new(StandaloneRefs) as Arc<dyn LibraryRefs>));
    }
    /// Discard the resource types the load callback opened (a load that fails after the
    /// callback ran).
    pub fn rollback_resource_types(&self) {
        let opened = std::mem::take(&mut *self.pending_types.lock().unwrap());
        resources::rollback_opened(opened);
    }
    /// Remove this library's resource types from the type list (the purge of its module).
    // Port of erts/emulator/beam/erl_nif.c:5345-5366 (erts_unload_nif), OTP-29.1.1.
    pub fn unload_resource_types(&self) {
        resources::unload_types(&self.owner);
    }
    /// Module name exported by this NIF library.
    pub fn module_name(&self) -> &str {
        &self.module
    }

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
    /// Invoke `fptr`, a function of this library or a function a wrapper scheduled. `dirty`
    /// marks a call of a dirty NIF, which the on-halt callback waits for. An exception or a
    /// TRAP (`enif_schedule_nif`) returns `THE_NON_VALUE` with `p`'s `freason` set.
    // Port of erts/emulator/beam/jit/beam_jit_common.cpp:623-677 (beam_jit_call_nif with
    // `NifMod`: the environment takes `priv_data` from the library), OTP-29.1.1.
    pub fn call(
        &self,
        p: &mut ProcessHeap,
        (fptr, argv, argc): (NifFn, *const Term, usize),
        pid: Option<Term>,
        dirty: bool,
    ) -> Term {
        step(
            (&self.priv_data, &self.halt_calls, dirty),
            p,
            fptr,
            (argv, argc),
            pid,
        )
    }
    /// Run the callback registered with `ERL_NIF_OPT_ON_HALT`.
    pub fn execute_on_halt(&self) {
        if !self.on_halt_called.swap(true, Ordering::AcqRel)
            && let Some(callback) = self.on_halt
        {
            callback(self.priv_data.load(Ordering::Acquire));
        }
    }
    /// Wait for calls in a library that requested `ERL_NIF_OPT_DELAY_HALT`.
    pub fn wait_for_halt_calls(&self) {
        self.halt_calls.wait();
    }
    /// Run the unload callbacks and release the `dlopen` handle, once. No function of the
    /// library may be called afterwards.
    // Port of erts/emulator/beam/erl_nif.c:2602-2618 (really_close_dynlib), OTP-29.1.1.
    pub fn close(&self) {
        if self.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        let priv_data = self.priv_data.load(Ordering::Acquire);
        if let Some(callback) = self.on_unload_thread {
            callback(priv_data);
        }
        if let Some(unload) = self.unload {
            let mut env = ErlNifEnv::independent();
            env.module = Some(self.module.clone());
            // SAFETY: the library is still open; its handle is released below.
            unsafe { unload(&mut env, priv_data) };
        }
        drop(
            self.library
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .take(),
        );
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
        self.rollback_resource_types();
        self.unload_resource_types();
        self.close();
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
        self.finish(term, None, None)
    }
    /// Like [`NifImage::commit`], for a load called by process `pid`, which `enif_self` reports
    /// inside the callback (erts binds the load environment to the calling process).
    pub fn commit_for(self, term: Term, pid: Option<Term>) -> Result<NifLibrary, NifError> {
        self.finish(term, None, pid)
    }
    /// Run the upgrade callback with the private data of `old`, the library of the previous
    /// code of the module, and return the callable library.
    // Port of erts/emulator/beam/erl_nif.c:4956-4979 (erts_load_nif upgrade), OTP-29.1.1:
    // the callback may replace the old library's `priv_data`; a veto restores it.
    pub fn upgrade(
        self,
        term: Term,
        old: &NifLibrary,
        pid: Option<Term>,
    ) -> Result<NifLibrary, NifError> {
        if self.upgrade.is_none() {
            return Err(NifError::UpgradeUnsupported);
        }
        let prev_old_data = old.priv_data.load(Ordering::Acquire);
        let mut old_data = prev_old_data;
        let result = self.finish(term, Some(&mut old_data), pid);
        old.priv_data.store(
            if result.is_ok() {
                old_data
            } else {
                prev_old_data
            },
            Ordering::Release,
        );
        result
    }
    fn finish(
        mut self,
        term: Term,
        old_priv_data: Option<&mut *mut c_void>,
        pid: Option<Term>,
    ) -> Result<NifLibrary, NifError> {
        let mut env = ErlNifEnv::independent();
        env.pid = pid;
        env.module = Some(self.module.clone());
        env.library = Some(Arc::clone(&self.library));
        env.options.loading = true;
        let cell = Arc::new(AtomicPtr::new(ptr::null_mut()));
        env.priv_cell = Some(Arc::clone(&cell));
        let upgrading = old_priv_data.is_some();
        let code = if let Some(old) = old_priv_data {
            let upgrade = self.upgrade.ok_or(NifError::UpgradeUnsupported)?;
            // SAFETY: this loaded library declares its upgrade ABI and both data pointers are live.
            unsafe { upgrade(&mut env, cell.as_ptr(), old, term) }
        } else if let Some(load) = self.load {
            // SAFETY: the library's callback follows its declared entry ABI.
            unsafe { load(&mut env, cell.as_ptr(), term) }
        } else {
            0
        };
        env.options.loading = false;
        env.priv_cell = None;
        let opened = std::mem::take(&mut env.opened);
        if code != 0 {
            resources::rollback_opened(opened);
            return Err(if upgrading {
                NifError::UpgradeRejected(code)
            } else {
                NifError::LoadRejected(code)
            });
        }
        // The slot the callback wrote stays the library's `priv_data`.
        let priv_data = cell;
        let halt_calls = Arc::new(HaltCalls {
            enabled: env.options.flags & 1 != 0,
            in_flight: Mutex::new(0),
            idle: Condvar::new(),
        });
        for function in &mut self.functions {
            function.priv_data = Arc::clone(&priv_data);
            function.halt_calls = Arc::clone(&halt_calls);
        }
        let module_name = self.module.clone();
        let owner_priv_data = Arc::clone(&priv_data);
        Ok(NifLibrary {
            library: Mutex::new(Some(self.library)),
            closed: AtomicBool::new(false),
            module: self.module,
            functions: self.functions,
            unload: self.unload,
            on_halt: env.options.on_halt,
            on_unload_thread: env.options.on_unload_thread,
            priv_data,
            halt_calls,
            on_halt_called: AtomicBool::new(false),
            owner: resources::ResourceOwner::new(module_name, owner_priv_data),
            pending_types: Mutex::new(opened),
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
            cstr(min_erts_ptr).to_string_lossy().into_owned()
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
    let name = cstr(entry.name).to_string_lossy();
    // SAFETY: validated pointers refer to terminated strings in the loaded library.
    let variant = cstr(entry.vm_variant).to_string_lossy();
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
        let fname = cstr(fname_ptr).to_string_lossy().into_owned();
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
            priv_data: Arc::default(),
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
    let library = open_nif(path, info.module)?.commit(info.term)?;
    library.commit_standalone_types();
    Ok(library)
}
/// Load a replacement library and pass the old private data to its upgrade callback.
pub fn upgrade_nif(
    path: &Path,
    info: LoadInfo<'_>,
    old: &NifLibrary,
) -> Result<NifLibrary, NifError> {
    let library = open_nif(path, info.module)?.upgrade(info.term, old, None)?;
    library.commit_standalone_types();
    Ok(library)
}
/// `dynlib_refc` of a library that is not bound to a module instance: nothing to count.
struct StandaloneRefs;
impl LibraryRefs for StandaloneRefs {
    fn dynlib_inc(&self) {}
    fn dynlib_dec(&self) {}
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
    internal_test::retain_exports();
    iovec::retain_exports();
    ioq::retain_exports();
}
/// Write `value` through an out-parameter of the C caller; a NULL pointer is ignored.
pub(crate) fn put<T>(out: *mut T, value: T) {
    if !out.is_null() {
        // SAFETY: a non-NULL out-parameter of a NIF API call is writable by contract.
        unsafe { *out = value }
    }
}
/// `is_scheduler()`: 1 on a normal scheduler, -1 on a dirty one (0 off-scheduler threads
/// report as normal here).
// Port of erts/emulator/beam/erl_nif.c:168-177 (is_scheduler), OTP-29.1.1.
pub(crate) fn is_scheduler() -> c_int {
    match arinsal_sched::current_scheduler_type() {
        arinsal_sched::SchedulerType::Normal => 1,
        _ => -1,
    }
}
/// `BUMP_REDS(p, gc)`: take `gc` reductions from `p->fcalls`, not below zero.
// Port of erts/emulator/beam/bif.h:71-78 (BUMP_REDS), OTP-29.1.1.
pub(crate) fn bump_reds(p: &mut ProcessHeap, gc: i32) {
    p.abi.fcalls = (p.abi.fcalls - gc).max(0);
}
pub(crate) fn term(bits: u64) -> Term {
    // SAFETY: callers obtain bits from existing terms or the NIF ABI.
    unsafe { std::mem::transmute::<u64, Term>(bits) }
}
pub(crate) fn bits(term: Term) -> u64 {
    // SAFETY: the term remains on a live heap during the call.
    unsafe { term.raw_bits() }
}
