//! C resource headers and magic reference ownership.
use crate::Library;
use crate::raw::{cstr, deref, deref_mut};
use crate::{ErlNifEnv, ErlNifResourceTypeInit, put, terms};
use arinsal_term::{ExternalBinary, MagicRef, Term, TermBuilder};
use std::alloc::{Layout, alloc_zeroed, dealloc};
use std::collections::HashMap;
use std::ffi::{c_char, c_int, c_void};
use std::hint::black_box;
use std::ptr;
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

pub(crate) struct Resource {
    kind: Arc<ResourceType>,
    data: *mut u8,
    size: usize,
    /// Identity shared by every term of this resource while one is alive (erts: all
    /// magic refs point at the same magic binary). Weak: the payload owns the resource.
    magic: Mutex<Weak<MagicRef>>,
    /// Process monitors this resource holds (`ErtsResourceMonitors`): target pid and monitor.
    pub(crate) monitors: Mutex<Vec<(Term, u64)>>,
}
impl Resource {
    pub(crate) fn magic_ref(self: &Arc<Self>) -> Arc<MagicRef> {
        let mut slot = self.magic.lock().unwrap();
        if let Some(magic) = slot.upgrade() {
            return magic;
        }
        let magic = MagicRef::with_orig_size(Arc::clone(self), self.magic_orig_size());
        *slot = Arc::downgrade(&magic);
        magic
    }

    /// `mb->orig_size` of the magic binary `enif_alloc_resource` creates for this resource:
    /// the unaligned magic data offset plus `offsetof(ErtsResource, data)` and the user data,
    /// followed by an aligned `ErtsResourceMonitors` when the type has a `down` callback.
    // Port of erts/emulator/beam/erl_nif.c (enif_alloc_resource) and erl_binary.h
    // (erts_create_magic_binary_x, ERTS_MAGIC_BIN_UNALIGNED_ORIG_SIZE), OTP-29.1.1, 64-bit.
    fn magic_orig_size(&self) -> usize {
        resource_magic_orig_size(self.size, self.kind.callbacks().down.is_some())
    }
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

fn from_reference(reference: Term) -> Option<Arc<Resource>> {
    // SAFETY: the caller retains the reference term and its heap during the callback.
    let magic = unsafe { reference.magic_ref() }?;
    magic.downcast_ref::<Arc<Resource>>().cloned()
}
/// Deliver a monitored process exit to a live resource's down callback.
pub fn resource_down(reference: Term, pid: Term, monitor: &[u8; 32]) -> bool {
    let Some(owner) = from_reference(reference) else {
        return false;
    };
    let kind = &owner.kind;
    let Some(callback) = kind.callbacks().down else {
        return false;
    };
    let mut env = kind.env();
    let mut pid = pid;
    // SAFETY: the NIF callback sees live environment, resource, pid, and monitor storage.
    unsafe {
        callback(
            &mut env,
            owner.data.cast(),
            (&mut pid as *mut Term).cast(),
            monitor.as_ptr().cast_mut().cast(),
        )
    };
    true
}
/// Deliver a reactor stop event to a live resource's stop callback.
pub fn resource_stop(reference: Term, event: i32, direct: bool) -> bool {
    let Some(owner) = from_reference(reference) else {
        return false;
    };
    let kind = &owner.kind;
    let Some(callback) = kind.callbacks().stop else {
        return false;
    };
    let mut env = kind.env();
    // SAFETY: the NIF callback sees a live environment and resource allocation.
    unsafe { callback(&mut env, owner.data.cast(), event, i32::from(direct)) };
    true
}
/// The resource at `data` as a magic reference term on `heap`.
pub(crate) fn resource_term(data: *mut c_void, heap: &mut arinsal_term::VecHeap) -> Option<Term> {
    let owner = owner_for(data)?;
    TermBuilder::new(heap).magic_ref(owner.magic_ref()).ok()
}
/// `Module:Name` of the type of the resource at `data`.
pub fn resource_type_name(data: usize) -> String {
    let Some(owner) = owner_for(data as *mut c_void) else {
        return String::new();
    };
    types()
        .lock()
        .unwrap()
        .iter()
        .find(|(_, candidate)| Arc::ptr_eq(candidate, &owner.kind))
        .map(|(name, _)| name.clone())
        .unwrap_or_default()
}
/// Port of erts/emulator/beam/erl_nif.c:1318 (erts_resource_stop) for the resource at
/// `data`; `false` when its type has no stop callback.
pub fn resource_stop_data(data: usize, event: i32, direct: bool) -> bool {
    let Some(owner) = owner_for(data as *mut c_void) else {
        return false;
    };
    let kind = &owner.kind;
    let Some(callback) = kind.callbacks().stop else {
        return false;
    };
    let mut env = kind.env();
    // SAFETY: the NIF callback sees a live environment and resource allocation.
    unsafe { callback(&mut env, owner.data.cast(), event, i32::from(direct)) };
    true
}
// SAFETY: the native resource contract requires consumers to synchronize access.
unsafe impl Send for Resource {}
// SAFETY: the native resource contract requires consumers to synchronize access.
unsafe impl Sync for Resource {}

fn literal_trace() -> bool {
    static FLAG: OnceLock<bool> = OnceLock::new();
    *FLAG.get_or_init(|| std::env::var_os("ARINSAL_LITERAL_TRACE").is_some())
}

impl Drop for Resource {
    fn drop(&mut self) {
        if literal_trace() {
            eprintln!("resource_drop data={:p}", self.data);
        }
        // Port of erts/emulator/beam/erl_nif.c:2960-3010 (nif_resource_dtor_prologue): the
        // monitors the resource holds are removed before its destructor runs.
        crate::res_monitor::demonitor_all(self);
        let kind = &self.kind;
        if let Some(dtor) = kind.callbacks().dtor {
            let mut env = kind.env();
            // SAFETY: the data is live until this drop ends.
            unsafe { dtor(&mut env, self.data.cast()) };
        }
        // The `kind` reference is released after this body: the last resource of an unlisted
        // type frees the type (erl_nif.c:3022-3029).
        owners().lock().unwrap().remove(&(self.data as usize));
        // SAFETY: the last owner has gone away and the original layout is unchanged.
        unsafe {
            dealloc(
                self.data,
                Layout::from_size_align_unchecked(self.size.max(1), 16),
            );
        }
    }
}
struct Kept {
    _owner: Arc<Resource>,
    count: usize,
}
static TYPES: OnceLock<Mutex<HashMap<String, Arc<ResourceType>>>> = OnceLock::new();
static KEPT: OnceLock<Mutex<HashMap<usize, Kept>>> = OnceLock::new();
/// Live resources by data address: the resource and its size (still readable while its dtor runs).
type OwnerMap = HashMap<usize, (Weak<Resource>, usize)>;
static OWNERS: OnceLock<Mutex<OwnerMap>> = OnceLock::new();
fn types() -> &'static Mutex<HashMap<String, Arc<ResourceType>>> {
    TYPES.get_or_init(|| Mutex::new(HashMap::new()))
}
fn kept() -> &'static Mutex<HashMap<usize, Kept>> {
    KEPT.get_or_init(|| Mutex::new(HashMap::new()))
}
fn owners() -> &'static Mutex<OwnerMap> {
    OWNERS.get_or_init(|| Mutex::new(HashMap::new()))
}
pub(crate) fn owner_for(data: *mut c_void) -> Option<Arc<Resource>> {
    owners().lock().unwrap().get(&(data as usize))?.0.upgrade()
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
#[unsafe(no_mangle)]
pub extern "C" fn enif_alloc_resource(kind: *mut c_void, size: usize) -> *mut c_void {
    let Some(kind) = type_for(kind) else {
        return ptr::null_mut();
    };
    let Ok(layout) = Layout::from_size_align(size.max(1), 16) else {
        return ptr::null_mut();
    };
    // SAFETY: layout is valid; the returned allocation is exclusively owned.
    let data = unsafe { alloc_zeroed(layout) };
    if data.is_null() {
        return ptr::null_mut();
    };
    let owner = Arc::new(Resource {
        kind,
        data,
        size,
        magic: Mutex::new(Weak::new()),
        monitors: Mutex::new(Vec::new()),
    });
    owners()
        .lock()
        .unwrap()
        .insert(data as usize, (Arc::downgrade(&owner), size));
    kept().lock().unwrap().insert(
        data as usize,
        Kept {
            _owner: owner,
            count: 1,
        },
    );
    data.cast()
}
#[unsafe(no_mangle)]
pub extern "C" fn enif_keep_resource(data: *mut c_void) {
    let Some(owner) = owner_for(data) else { return };
    let mut map = kept().lock().unwrap();
    if let Some(k) = map.get_mut(&(data as usize)) {
        k.count += 1;
    } else {
        map.insert(
            data as usize,
            Kept {
                _owner: owner,
                count: 1,
            },
        );
    }
}
#[unsafe(no_mangle)]
pub extern "C" fn enif_release_resource(data: *mut c_void) {
    let mut map = kept().lock().unwrap();
    let removed = if let Some(k) = map.get_mut(&(data as usize)) {
        k.count -= 1;
        if k.count == 0 {
            map.remove(&(data as usize))
        } else {
            None
        }
    } else {
        None
    };
    drop(map);
    drop(removed)
}
#[unsafe(no_mangle)]
pub extern "C" fn enif_sizeof_resource(data: *mut c_void) -> usize {
    owners()
        .lock()
        .unwrap()
        .get(&(data as usize))
        .map_or(0, |entry| entry.1)
}
#[unsafe(no_mangle)]
pub extern "C" fn enif_make_resource(e: *mut ErlNifEnv, data: *mut c_void) -> Term {
    let owner = owner_for(data);
    let Some(owner) = owner else {
        return terms::enif_make_badarg(e);
    };
    let magic = owner.magic_ref();
    // SAFETY: the host passes a live environment to this callback.
    let env = deref_mut(e);
    TermBuilder::new(&mut env.heap)
        .magic_ref(magic)
        .unwrap_or_else(|_| terms::enif_make_badarg(e))
}
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
    let Some(owner) = magic.downcast_ref::<Arc<Resource>>() else {
        return 0;
    };
    if type_address(&owner.kind) != kind {
        return 0;
    };
    if !out.is_null() {
        put(out, owner.data.cast())
    };
    1
}
#[unsafe(no_mangle)]
pub extern "C" fn enif_make_resource_binary(
    e: *mut ErlNifEnv,
    data: *mut c_void,
    bytes: *const c_void,
    size: usize,
) -> Term {
    let owner = owner_for(data);
    let Some(owner) = owner else {
        return terms::enif_make_badarg(e);
    };
    if bytes.is_null() && size > 0 {
        return terms::enif_make_badarg(e);
    };
    // SAFETY: the magic owner retains the native resource containing these bytes.
    let external = unsafe { ExternalBinary::new(bytes.cast::<u8>(), size, owner.magic_ref()) };
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

/// Run the `down` callback of `resource`'s type for the exit of monitored process `pid`.
// Port of erts/emulator/beam/erl_nif.c:3086-3110 (erts_fire_nif_monitor), OTP-29.1.1.
pub(crate) fn call_down(resource: &Arc<Resource>, pid: Term, monitor: &[u8; 32]) {
    let kind = &resource.kind;
    let Some(callback) = kind.callbacks().down else {
        return;
    };
    let mut env = kind.env();
    let mut pid = pid;
    // SAFETY: the NIF callback sees live environment, resource, pid, and monitor storage.
    unsafe {
        callback(
            &mut env,
            resource.data.cast(),
            (&mut pid as *mut Term).cast(),
            monitor.as_ptr().cast_mut().cast(),
        )
    };
}
/// Whether the type of `resource` has a `down` callback.
pub(crate) fn has_down(resource: &Resource) -> bool {
    resource.kind.callbacks().down.is_some()
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
