//! C resource headers and magic reference ownership.
use crate::Library;
use crate::raw::{cstr, deref, deref_mut};
use crate::{ErlNifEnv, ErlNifResourceTypeInit, put, terms};
use arinsal_term::{ExternalBinary, MagicBin, Term, TermBuilder};
use std::collections::HashMap;
use std::ffi::{c_char, c_int, c_void};
use std::hint::black_box;
use std::ptr::{self, NonNull};
use std::sync::atomic::AtomicPtr;
use std::sync::{Arc, Mutex, OnceLock, RwLock, Weak};

/// What resource types need of the library that owns them (`struct erl_module_nif`): its
/// `priv_data`, which callbacks see through `enif_priv_data`, and its module name.
pub struct ResourceOwner {
    module: String,
    priv_data: Arc<AtomicPtr<c_void>>,
}
impl ResourceOwner {
    pub(crate) fn new(module: String, priv_data: Arc<AtomicPtr<c_void>>) -> Arc<Self> {
        Arc::new(Self { module, priv_data })
    }
}
/// The `dynlib_refc` of the owning library. A type with callbacks holds one reference, so the
/// library is not closed (`unload` does not run) while a resource of such a type is alive.
pub trait LibraryRefs: Send + Sync {
    /// `erts_refc_inc(&lib->dynlib_refc)`.
    fn dynlib_inc(&self);
    /// `erts_refc_dectest(&lib->dynlib_refc)`; the last reference closes the library.
    fn dynlib_dec(&self);
}
struct TypeOwner {
    owner: Arc<ResourceOwner>,
    /// `lib->refc`: keeps the library struct alive while it owns the type.
    refs: Arc<dyn LibraryRefs>,
}
/// Port of `struct enif_resource_type_t` (erts/emulator/beam/erl_nif.c), OTP-29.1.1. The
/// `Arc` count plays `refc`: the type list (while the owner is loaded) and every live
/// resource hold one reference; the last one released frees the type.
struct ResourceType {
    /// `fn_real`; callbacks are copied out before they run, so a takeover never waits for one.
    callbacks: RwLock<ErlNifResourceTypeInit>,
    owner: Mutex<Option<TypeOwner>>,
    _library: Mutex<Arc<Library>>,
}
impl Drop for ResourceType {
    // Port of erts/emulator/beam/erl_nif.c:3022-3029 (nif_resource_dtor), 5359-5363.
    fn drop(&mut self) {
        steal_resource_type(self);
        all_types()
            .lock()
            .unwrap()
            .remove(&(self as *const Self as usize));
    }
}
/// Port of erts/emulator/beam/erl_nif.c:2683 (struct opened_resource_type), OTP-29.1.1: a
/// create or take-over made by a load callback, applied only if the load succeeds.
pub(crate) struct OpenedType {
    op: c_int,
    ty: Arc<ResourceType>,
    key: String,
    callbacks: ErlNifResourceTypeInit,
    library: Arc<Library>,
}
/// Every live type by address, to resolve the `ErlNifResourceType*` a NIF hands back.
static ALL_TYPES: OnceLock<Mutex<HashMap<usize, Weak<ResourceType>>>> = OnceLock::new();
fn all_types() -> &'static Mutex<HashMap<usize, Weak<ResourceType>>> {
    ALL_TYPES.get_or_init(|| Mutex::new(HashMap::new()))
}
fn type_for(address: *mut c_void) -> Option<Arc<ResourceType>> {
    all_types()
        .lock()
        .unwrap()
        .get(&(address as usize))?
        .upgrade()
}
fn type_address(ty: &Arc<ResourceType>) -> *mut c_void {
    Arc::as_ptr(ty).cast_mut().cast()
}
fn have_callbacks(init: &ErlNifResourceTypeInit) -> bool {
    init.dtor.is_some()
}
unsafe extern "C" fn resource_dtor_nop(_: *mut ErlNifEnv, _: *mut c_void) {}
impl ResourceType {
    fn callbacks(&self) -> ErlNifResourceTypeInit {
        *self.callbacks.read().unwrap()
    }
    /// Port of pre_nif_noproc (erl_nif.c): an environment of the owning library.
    fn env(&self) -> ErlNifEnv {
        let mut env = ErlNifEnv::independent();
        if let Some(owner) = self.owner.lock().unwrap().as_ref() {
            env.module = Some(owner.owner.module.clone());
            env.priv_cell = Some(Arc::clone(&owner.owner.priv_data));
        }
        env
    }
}
/// Port of erts/emulator/beam/erl_nif.c:2620 (steal_resource_type): the type leaves its owner.
fn steal_resource_type(ty: &ResourceType) {
    let owner = ty.owner.lock().unwrap().take();
    if let Some(owner) = owner
        && have_callbacks(&ty.callbacks())
    {
        owner.refs.dynlib_dec();
    }
}
/// Port of erts/emulator/beam/erl_nif.c:2879 (rollback_opened_resource_types).
pub(crate) fn rollback_opened(opened: Vec<OpenedType>) {
    // A created type was never published: dropping the entry frees it.
    drop(opened);
}
/// Port of erts/emulator/beam/erl_nif.c:2807-2870 (prepare_opened_rt, commit_opened_rt,
/// cleanup_opened_rt), OTP-29.1.1.
pub(crate) fn commit_opened(
    opened: Vec<OpenedType>,
    owner: &Arc<ResourceOwner>,
    refs: &Arc<dyn LibraryRefs>,
) {
    for entry in opened.into_iter().rev() {
        let ty = &entry.ty;
        if entry.op == 1 {
            types().lock().unwrap().insert(entry.key, Arc::clone(ty));
        } else {
            steal_resource_type(ty);
        }
        *ty.owner.lock().unwrap() = Some(TypeOwner {
            owner: Arc::clone(owner),
            refs: Arc::clone(refs),
        });
        if have_callbacks(&entry.callbacks) {
            refs.dynlib_inc();
        }
        *ty.callbacks.write().unwrap() = entry.callbacks;
        *ty._library.lock().unwrap() = entry.library;
    }
}
/// Port of erts/emulator/beam/erl_nif.c:5345-5366 (erts_unload_nif): the purged library's
/// types leave the type list; those without resources are freed.
pub(crate) fn unload_types(owner: &Arc<ResourceOwner>) {
    let removed: Vec<Arc<ResourceType>> = {
        let mut table = types().lock().unwrap();
        let keys: Vec<String> = table
            .iter()
            .filter(|(_, ty)| {
                ty.owner
                    .lock()
                    .unwrap()
                    .as_ref()
                    .is_some_and(|t| Arc::ptr_eq(&t.owner, owner))
            })
            .map(|(key, _)| key.clone())
            .collect();
        keys.iter().filter_map(|key| table.remove(key)).collect()
    };
    // The list reference goes away; a type without resources is freed here.
    drop(removed);
}

/// Alignment of a resource's user data (`ErtsResource.data`).
const DATA_ALIGN: usize = 16;

/// `ErtsResource`: the head of a resource's magic binary data. The user data follows it in the
/// same block (the trailing bytes of the magic binary), so `obj` pointers handed to C map back
/// to the binary by address (`DATA_TO_RESOURCE`, `ERTS_MAGIC_BIN_FROM_UNALIGNED_DATA`).
// Port of erts/emulator/beam/global.h (ErtsResource, ErtsResourceMonitors), OTP-29.1.1.
pub(crate) struct Resource {
    /// `type`: the resource holds one reference to its type (`erts_refc_inc(&type->refc)`).
    kind: Arc<ResourceType>,
    /// `monitors`: present when the type has a `down` callback.
    pub(crate) monitors: Option<ResourceMonitors>,
    /// `monitors->user_data_sz`, kept for every type here.
    size: usize,
}

/// `ErtsResourceMonitors`: the origin halves of the process monitors a resource holds.
pub(crate) struct ResourceMonitors {
    /// `lock` with `root`, `refc` and the dying flag it protects.
    pub(crate) lock: Mutex<MonitorState>,
}

/// The state behind `ErtsResourceMonitors.lock`.
#[derive(Default)]
pub(crate) struct MonitorState {
    /// `root`: target pid and monitor reference of each active monitor.
    pub(crate) root: Vec<(Term, u64)>,
    /// `rmon_refc`: target halves still referring to this resource's memory.
    pub(crate) refc: usize,
    /// `rmon_is_dying`: the resource's count reached zero and its destructor started.
    pub(crate) dying: bool,
}

// SAFETY: `nif_resource_dtor_prologue` is defined once, for `Resource` only; it drops the
// payload exactly once and frees the block itself (it returns 0, like erts).
unsafe impl arinsal_term::MagicPayload for Resource {
    const DESTRUCTOR: arinsal_term::MagicDestructor = nif_resource_dtor_prologue;
}

/// `NIF_RESOURCE_DTOR`: the last count of a resource's magic binary is gone.
// Port of erts/emulator/beam/erl_nif.c (nif_resource_dtor_prologue), OTP-29.1.1. erts
// schedules `run_resource_dtor` as misc aux work; here it runs in the releasing thread.
#[inline(never)]
unsafe fn nif_resource_dtor_prologue(bin: NonNull<arinsal_term::MagicRef>) -> bool {
    // SAFETY: the count is zero and the payload is live until `run_resource_dtor` frees it.
    unsafe { run_resource_dtor(bin) };
    false
}

/// Port of erts/emulator/beam/erl_nif.c (run_resource_dtor), OTP-29.1.1: demonitor every
/// monitored process, wait for outstanding monitor references, run the type's destructor,
/// release the type and free the binary.
///
/// # Safety
/// `bin` is a resource binary whose count is zero.
unsafe fn run_resource_dtor(bin: NonNull<arinsal_term::MagicRef>) {
    // SAFETY: the payload is not dropped before the end of this function.
    let resource = unsafe { arinsal_term::MagicRef::payload_of::<Resource>(bin) };
    if let Some(rm) = &resource.monitors {
        let (root, refc) = {
            let mut state = rm.lock.lock().unwrap();
            let root = if state.dying {
                Vec::new()
            } else {
                state.dying = true;
                std::mem::take(&mut state.root)
            };
            (root, state.refc)
        };
        for (target, id) in root {
            crate::res_monitor::send_demonitor(target, id);
        }
        // Outstanding monitor references call `erts_bin_free` again when the last goes away.
        if refc != 0 {
            return;
        }
    }
    let kind = &resource.kind;
    if let Some(dtor) = kind.callbacks().dtor {
        let mut env = kind.env();
        // SAFETY: the user data is live until the block is freed below.
        unsafe { dtor(&mut env, resource_data(bin).cast()) };
    }
    // SAFETY: the payload (and with it the type reference, erl_nif.c:3022-3029) is dropped
    // once, and the block is ours to free since the prologue returned 0.
    unsafe {
        arinsal_term::raw::magic_bin::drop_payload::<Resource>(bin);
        MagicBin::magic_binary_free(bin);
    }
}

/// `resource->data` of a resource binary.
fn resource_data(bin: NonNull<arinsal_term::MagicRef>) -> *mut u8 {
    // SAFETY: a resource binary always has its user data after the `Resource` head.
    unsafe { bin.as_ref() }
        .trailing_ptr::<Resource>(DATA_ALIGN)
        .expect("a resource binary")
}

/// `DATA_TO_RESOURCE` + `ERTS_MAGIC_BIN_FROM_UNALIGNED_DATA`: the binary of the resource whose
/// user data is at `obj`.
///
/// # Safety
/// `obj` was returned by `enif_alloc_resource` and the resource is still referenced.
pub(crate) unsafe fn resource_bin(obj: *mut c_void) -> NonNull<arinsal_term::MagicRef> {
    // SAFETY: forwarded caller contract.
    unsafe { MagicBin::block_from_trailing::<Resource>(obj.cast(), DATA_ALIGN) }
}

/// The `Resource` head of the resource whose user data is at `obj`.
///
/// # Safety
/// As for [`resource_bin`]; the borrow must not outlive the caller's reference.
pub(crate) unsafe fn resource_at<'a>(obj: *mut c_void) -> &'a Resource {
    // SAFETY: forwarded caller contract.
    unsafe { arinsal_term::MagicRef::payload_of::<Resource>(resource_bin(obj)) }
}

/// `mb->orig_size` for a resource of `size` user bytes, with the monitors block that a type
/// with a `down` callback adds after the user data.
pub(crate) fn resource_magic_orig_size(size: usize, has_down: bool) -> usize {
    // offsetof(ErtsMagicBinary, u.unaligned.data) - offsetof(Binary, orig_bytes).
    const MAGIC_DATA_OFFSET: usize = 24;
    // offsetof(ErtsResource, data): the `type` and `monitors` pointers.
    const RESOURCE_DATA_OFFSET: usize = 16;
    // sizeof(ErtsResourceMonitors): erts_mtx_t (a 64-byte pthread mutex on the reference
    // macOS arm64 host), `root`, `refc` and `user_data_sz`.
    const MONITORS_SIZE: usize = 64 + 3 * 8;
    // ERTS_ALLOC_ALIGN_BYTES
    const ALLOC_ALIGN: usize = 8;
    let base = MAGIC_DATA_OFFSET + RESOURCE_DATA_OFFSET;
    if has_down {
        base + size.next_multiple_of(ALLOC_ALIGN) + MONITORS_SIZE
    } else {
        base + size
    }
}

/// The resource binary a reference term names, as `enif_get_resource` reads it.
fn from_reference(reference: Term) -> Option<MagicBin> {
    reference
        .magic_owner()
        .filter(|bin| bin.downcast_ref::<Resource>().is_some())
}
/// Deliver a monitored process exit to a live resource's down callback.
pub fn resource_down(reference: Term, pid: Term, monitor: &[u8; 32]) -> bool {
    let Some(bin) = from_reference(reference) else {
        return false;
    };
    call_down(&bin, pid, monitor)
}
/// Deliver a reactor stop event to a live resource's stop callback.
pub fn resource_stop(reference: Term, event: i32, direct: bool) -> bool {
    let Some(bin) = from_reference(reference) else {
        return false;
    };
    erts_resource_stop(&bin, event, direct)
}
/// The resource at `data` as a magic reference term on `heap`.
pub(crate) fn resource_term(data: *mut c_void, heap: &mut arinsal_term::VecHeap) -> Option<Term> {
    // SAFETY: a selected resource is kept by its select entry while a message is prepared.
    let bin = unsafe { MagicBin::retain_raw_block(resource_bin(data)) };
    TermBuilder::new(heap).magic_ref(bin).ok()
}
/// `Module:Name` of the type of the resource at `data`.
pub fn resource_type_name(data: usize) -> String {
    // SAFETY: the check-io entry asking keeps the resource.
    let resource = unsafe { resource_at(data as *mut c_void) };
    types()
        .lock()
        .unwrap()
        .iter()
        .find(|(_, candidate)| Arc::ptr_eq(candidate, &resource.kind))
        .map(|(name, _)| name.clone())
        .unwrap_or_default()
}
/// Port of erts/emulator/beam/erl_nif.c:1318 (erts_resource_stop) for the resource at
/// `data`; `false` when its type has no stop callback.
pub fn resource_stop_data(data: usize, event: i32, direct: bool) -> bool {
    // SAFETY: the check-io entry stopping it keeps the resource.
    let bin = unsafe { MagicBin::retain_raw_block(resource_bin(data as *mut c_void)) };
    erts_resource_stop(&bin, event, direct)
}
// Port of erts/emulator/beam/erl_nif.c (erts_resource_stop), OTP-29.1.1.
fn erts_resource_stop(bin: &MagicBin, event: i32, direct: bool) -> bool {
    let resource = bin.downcast_ref::<Resource>().expect("a resource binary");
    let kind = &resource.kind;
    let Some(callback) = kind.callbacks().stop else {
        return false;
    };
    let mut env = kind.env();
    // SAFETY: the NIF callback sees a live environment and resource allocation.
    unsafe {
        callback(
            &mut env,
            resource_data(into_block(bin)).cast(),
            event,
            i32::from(direct),
        )
    };
    true
}
fn into_block(bin: &MagicBin) -> NonNull<arinsal_term::MagicRef> {
    NonNull::from(&**bin)
}
// SAFETY: the user data is the C owner's to synchronize; the head is immutable apart from the
// monitor state behind its lock.
unsafe impl Send for Resource {}
// SAFETY: as above.
unsafe impl Sync for Resource {}

static TYPES: OnceLock<Mutex<HashMap<String, Arc<ResourceType>>>> = OnceLock::new();
fn types() -> &'static Mutex<HashMap<String, Arc<ResourceType>>> {
    TYPES.get_or_init(|| Mutex::new(HashMap::new()))
}
fn name(p: *const c_char) -> Option<String> {
    if p.is_null() {
        None
    } else {
        Some(
            // SAFETY: The resource allocation and callback remain live during this access.
            cstr(p).to_string_lossy().into_owned(),
        )
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn enif_open_resource_type(
    e: *mut ErlNifEnv,
    module: *const c_char,
    kind: *const c_char,
    dtor: Option<unsafe extern "C" fn(*mut ErlNifEnv, *mut c_void)>,
    flags: c_int,
    tried: *mut c_int,
) -> *mut c_void {
    let Some(kind_name) = name(kind) else {
        return ptr::null_mut();
    };
    let _ = module;
    if e.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: the NIF load callback receives a live environment.
    let env = deref(e);
    let module = env.module.as_deref().unwrap_or_default();
    let key = format!("{module}:{kind_name}");
    let init = ErlNifResourceTypeInit {
        dtor,
        ..ErlNifResourceTypeInit::default()
    };
    open_type(e, &key, &init, flags, tried)
}
#[unsafe(no_mangle)]
pub extern "C" fn enif_open_resource_type_x(
    e: *mut ErlNifEnv,
    kind: *const c_char,
    init: *const ErlNifResourceTypeInit,
    flags: c_int,
    tried: *mut c_int,
) -> *mut c_void {
    let (Some(kind_name), Some(init)) = (
        name(kind),
        // SAFETY: The resource allocation and callback remain live during this access.
        unsafe { init.as_ref() },
    ) else {
        return ptr::null_mut();
    };
    if e.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: the NIF load callback receives a live environment.
    let env = deref(e);
    let module = env.module.as_deref().unwrap_or_default();
    let init = ErlNifResourceTypeInit {
        dtor: init.dtor,
        stop: init.stop,
        down: init.down,
        members: 3,
        dyncall: None,
    };
    open_type(e, &format!("{module}:{kind_name}"), &init, flags, tried)
}
#[unsafe(no_mangle)]
pub extern "C" fn enif_init_resource_type(
    e: *mut ErlNifEnv,
    kind: *const c_char,
    init: *const ErlNifResourceTypeInit,
    flags: c_int,
    tried: *mut c_int,
) -> *mut c_void {
    let (Some(kind_name), Some(init)) = (
        name(kind),
        // SAFETY: the caller provides the initialized callback members.
        unsafe { init.as_ref() },
    ) else {
        return ptr::null_mut();
    };
    if e.is_null() || !(0..=4).contains(&init.members) {
        return ptr::null_mut();
    }
    // SAFETY: the NIF load callback receives a live environment.
    let env = deref(e);
    let module = env.module.as_deref().unwrap_or_default();
    let callbacks = ErlNifResourceTypeInit {
        dtor: if init.members >= 1 { init.dtor } else { None },
        stop: if init.members >= 2 { init.stop } else { None },
        down: if init.members >= 3 { init.down } else { None },
        members: init.members,
        dyncall: if init.members >= 4 {
            init.dyncall
        } else {
            None
        },
    };
    open_type(
        e,
        &format!("{module}:{kind_name}"),
        &callbacks,
        flags,
        tried,
    )
}
/// Port of erts/emulator/beam/erl_nif.c:2697 (open_resource_type), OTP-29.1.1: `tried`
/// always receives the operation that was attempted (`flags` when nothing matched).
fn open_type(
    e: *mut ErlNifEnv,
    key: &str,
    init: &ErlNifResourceTypeInit,
    flags: c_int,
    tried: *mut c_int,
) -> *mut c_void {
    // SAFETY: callers checked the load environment pointer.
    let env = deref_mut(e);
    let (op, address) = open_type_op(env, key, init, flags);
    if !tried.is_null() {
        put(tried, op)
    }
    address
}
fn open_type_op(
    env: &mut ErlNifEnv,
    key: &str,
    init: &ErlNifResourceTypeInit,
    flags: c_int,
) -> (c_int, *mut c_void) {
    if !env.options.loading {
        return (flags, ptr::null_mut());
    }
    let Some(library) = env.library.clone() else {
        return (flags, ptr::null_mut());
    };
    let found = types().lock().unwrap().get(key).cloned();
    let (op, ty) = match found {
        None if flags & 1 != 0 => {
            let ty = Arc::new(ResourceType {
                callbacks: RwLock::new(ErlNifResourceTypeInit::default()),
                owner: Mutex::new(None),
                _library: Mutex::new(Arc::clone(&library)),
            });
            all_types()
                .lock()
                .unwrap()
                .insert(Arc::as_ptr(&ty) as usize, Arc::downgrade(&ty));
            (1, ty)
        }
        Some(ty) if flags & 2 != 0 => (2, ty),
        _ => return (flags, ptr::null_mut()),
    };
    let mut callbacks = *init;
    if callbacks.dtor.is_none()
        && (callbacks.down.is_some() || callbacks.stop.is_some() || callbacks.dyncall.is_some())
    {
        // Dummy dtor for fast rt_have_callbacks().
        callbacks.dtor = Some(resource_dtor_nop);
    }
    let address = type_address(&ty);
    env.opened.push(OpenedType {
        op,
        ty,
        key: key.to_owned(),
        callbacks,
        library,
    });
    (op, address)
}
/// Port of erts/emulator/beam/erl_nif.c (enif_alloc_resource), OTP-29.1.1: one magic binary
/// holds the `ErtsResource` head, the user data and the monitors; the caller owns the first
/// count until `enif_release_resource`.
#[unsafe(no_mangle)]
pub extern "C" fn enif_alloc_resource(kind: *mut c_void, size: usize) -> *mut c_void {
    let Some(kind) = type_for(kind) else {
        return ptr::null_mut();
    };
    let has_down = kind.callbacks().down.is_some();
    let orig_size = resource_magic_orig_size(size, has_down);
    let bin = MagicBin::with_trailing_and_refn(
        Resource {
            kind,
            monitors: has_down.then(|| ResourceMonitors {
                lock: Mutex::new(MonitorState::default()),
            }),
            size,
        },
        size.max(1),
        DATA_ALIGN,
        orig_size,
        arinsal_bifs::next_ref_words(),
    );
    let data = resource_data(into_block(&bin));
    let _ = MagicBin::into_raw_block(bin);
    data.cast()
}
/// Port of erts/emulator/beam/erl_nif.c (enif_keep_resource): `erts_refc_inc`.
#[unsafe(no_mangle)]
pub extern "C" fn enif_keep_resource(data: *mut c_void) {
    // SAFETY: the NIF holds a reference to the resource it keeps.
    let _ = MagicBin::into_raw_block(unsafe { MagicBin::retain_raw_block(resource_bin(data)) });
}
/// Port of erts/emulator/beam/erl_nif.c (enif_release_resource): `erts_bin_release`.
#[unsafe(no_mangle)]
pub extern "C" fn enif_release_resource(data: *mut c_void) {
    // SAFETY: the NIF gives back a count it holds (from alloc or keep).
    drop(unsafe { MagicBin::from_raw_block(resource_bin(data)) });
}
/// Port of erts/emulator/beam/erl_nif.c (enif_sizeof_resource).
#[unsafe(no_mangle)]
pub extern "C" fn enif_sizeof_resource(data: *mut c_void) -> usize {
    // SAFETY: the NIF holds a reference to the resource.
    unsafe { resource_at(data) }.size
}
/// Port of erts/emulator/beam/erl_nif.c (enif_make_resource): `erts_mk_magic_ref`.
#[unsafe(no_mangle)]
pub extern "C" fn enif_make_resource(e: *mut ErlNifEnv, data: *mut c_void) -> Term {
    // SAFETY: the NIF holds a reference to the resource.
    let bin = unsafe { MagicBin::retain_raw_block(resource_bin(data)) };
    // SAFETY: the host passes a live environment to this callback.
    let env = deref_mut(e);
    TermBuilder::new(&mut env.heap)
        .magic_ref(bin)
        .unwrap_or_else(|_| terms::enif_make_badarg(e))
}
/// Port of erts/emulator/beam/erl_nif.c (enif_get_resource): the destructor and the type
/// identify the resource.
#[unsafe(no_mangle)]
pub extern "C" fn enif_get_resource(
    _: *mut ErlNifEnv,
    t: Term,
    kind: *mut c_void,
    out: *mut *mut c_void,
) -> c_int {
    // SAFETY: the term's heap is live through the callback.
    let Some(magic) = (unsafe {
        t.magic_ref()
            .or_else(|| arinsal_term::external_binary_magic(t))
    }) else {
        return 0;
    };
    let Some(resource) = magic.downcast_ref::<Resource>() else {
        return 0;
    };
    if type_address(&resource.kind) != kind {
        return 0;
    };
    if !out.is_null() {
        put(out, resource_data(NonNull::from(magic)).cast())
    };
    1
}
/// Port of erts/emulator/beam/erl_nif.c (enif_make_resource_binary).
#[unsafe(no_mangle)]
pub extern "C" fn enif_make_resource_binary(
    e: *mut ErlNifEnv,
    data: *mut c_void,
    bytes: *const c_void,
    size: usize,
) -> Term {
    if bytes.is_null() && size > 0 {
        return terms::enif_make_badarg(e);
    };
    // SAFETY: the NIF holds a reference to the resource.
    let bin = unsafe { MagicBin::retain_raw_block(resource_bin(data)) };
    // SAFETY: the magic binary retains the native resource containing these bytes.
    let external = unsafe { ExternalBinary::new(bytes.cast::<u8>(), size, bin) };
    // SAFETY: The resource allocation and callback remain live during this access.
    let env = deref_mut(e);
    TermBuilder::new(&mut env.heap)
        .external_binary(external)
        .unwrap_or_else(|_| terms::enif_make_badarg(e))
}
#[unsafe(no_mangle)]
pub extern "C" fn enif_dynamic_resource_call(
    e: *mut ErlNifEnv,
    module: Term,
    name: Term,
    reference: Term,
    call_data: *mut c_void,
) -> c_int {
    let Some(module) =
        arinsal_term::global_atoms().text(module.as_atom().unwrap_or(arinsal_term::Atom(u32::MAX)))
    else {
        return 1;
    };
    let Some(name) =
        arinsal_term::global_atoms().text(name.as_atom().unwrap_or(arinsal_term::Atom(u32::MAX)))
    else {
        return 1;
    };
    let key = format!("{module}:{name}");
    let Some(kind) = types().lock().unwrap().get(&key).cloned() else {
        return 1;
    };
    let kind = type_address(&kind);
    let mut object = ptr::null_mut();
    if enif_get_resource(e, reference, kind, &mut object) == 0 {
        return 1;
    };
    let dyncall = type_for(kind).and_then(|ty| ty.callbacks().dyncall);
    if let Some(f) = dyncall {
        // SAFETY: a registered callback and its resource are live during this invocation.
        unsafe { f(e, object, call_data) };
        0
    } else {
        1
    }
}
pub(crate) fn retain_exports() {
    let exports: &[usize] = &[
        enif_open_resource_type as *const () as usize,
        enif_alloc_resource as *const () as usize,
        enif_release_resource as *const () as usize,
        enif_make_resource as *const () as usize,
        enif_get_resource as *const () as usize,
    ];
    black_box(exports);
}

/// Run the `down` callback of the resource in `bin` for the exit of monitored process `pid`;
/// `false` when its type has none.
// Port of erts/emulator/beam/erl_nif.c (erts_fire_nif_monitor: the `fn.down` call), OTP-29.1.1.
pub(crate) fn call_down(bin: &MagicBin, pid: Term, monitor: &[u8; 32]) -> bool {
    let resource = bin.downcast_ref::<Resource>().expect("a resource binary");
    let kind = &resource.kind;
    let Some(callback) = kind.callbacks().down else {
        return false;
    };
    let mut env = kind.env();
    let mut pid = pid;
    // SAFETY: the NIF callback sees live environment, resource, pid, and monitor storage.
    unsafe {
        callback(
            &mut env,
            resource_data(into_block(bin)).cast(),
            (&mut pid as *mut Term).cast(),
            monitor.as_ptr().cast_mut().cast(),
        )
    };
    true
}

#[cfg(test)]
mod orig_size_tests {
    use super::resource_magic_orig_size;

    #[test]
    fn orig_size_follows_enif_alloc_resource() {
        // 24 magic data offset + 16 ErtsResource head + user data.
        assert_eq!(resource_magic_orig_size(4, false), 44);
        assert_eq!(resource_magic_orig_size(0, false), 40);
        // The monitors block follows the user data rounded up to 8 bytes.
        assert_eq!(resource_magic_orig_size(4, true), 40 + 8 + 88);
        assert_eq!(resource_magic_orig_size(16, true), 40 + 16 + 88);
    }
}
