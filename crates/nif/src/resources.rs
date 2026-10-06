//! C resource headers and magic reference ownership.
use crate::Library;
use crate::{ErlNifEnv, ErlNifResourceTypeInit, terms};
use arinsal_term::{ExternalBinary, MagicRef, Term, TermBuilder};
use std::alloc::{Layout, alloc_zeroed, dealloc};
use std::collections::HashMap;
use std::ffi::{CStr, c_char, c_int, c_void};
use std::hint::black_box;
use std::ptr;
use std::sync::{Arc, Mutex, OnceLock, Weak};

struct ResourceType {
    callbacks: ErlNifResourceTypeInit,
    _library: Arc<Library>,
}
// SAFETY: callbacks are function pointers into a loaded library. NIFs synchronize mutable payload access.
unsafe impl Send for ResourceType {}
// SAFETY: callbacks are immutable after registration; NIFs synchronize mutable payload access.
unsafe impl Sync for ResourceType {}
struct Resource {
    kind: *mut ResourceType,
    data: *mut u8,
    size: usize,
    /// Identity shared by every term of this resource while one is alive (erts: all
    /// magic refs point at the same magic binary). Weak: the payload owns the resource.
    magic: Mutex<Weak<MagicRef>>,
}
impl Resource {
    fn magic_ref(self: &Arc<Self>) -> Arc<MagicRef> {
        let mut slot = self.magic.lock().unwrap();
        if let Some(magic) = slot.upgrade() {
            return magic;
        }
        let magic = MagicRef::new(Arc::clone(self));
        *slot = Arc::downgrade(&magic);
        magic
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
    // SAFETY: the resource owner keeps its registered callback and payload live.
    let Some(callback) = (unsafe { (*owner.kind).callbacks.down }) else {
        return false;
    };
    let mut env = ErlNifEnv::independent();
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
    // SAFETY: the resource owner keeps its registered callback and payload live.
    let Some(callback) = (unsafe { (*owner.kind).callbacks.stop }) else {
        return false;
    };
    let mut env = ErlNifEnv::independent();
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
    let kind = owner.kind as usize;
    types()
        .lock()
        .unwrap()
        .iter()
        .find(|(_, candidate)| **candidate == kind)
        .map(|(name, _)| name.clone())
        .unwrap_or_default()
}
/// Port of erts/emulator/beam/erl_nif.c:1318 (erts_resource_stop) for the resource at
/// `data`; `false` when its type has no stop callback.
pub fn resource_stop_data(data: usize, event: i32, direct: bool) -> bool {
    let Some(owner) = owner_for(data as *mut c_void) else {
        return false;
    };
    // SAFETY: the resource owner keeps its registered callback and payload live.
    let Some(callback) = (unsafe { (*owner.kind).callbacks.stop }) else {
        return false;
    };
    let mut env = ErlNifEnv::independent();
    // SAFETY: the NIF callback sees a live environment and resource allocation.
    unsafe { callback(&mut env, owner.data.cast(), event, i32::from(direct)) };
    true
}
// SAFETY: the native resource contract requires consumers to synchronize access.
unsafe impl Send for Resource {}
// SAFETY: the native resource contract requires consumers to synchronize access.
unsafe impl Sync for Resource {}
impl Drop for Resource {
    fn drop(&mut self) {
        if std::env::var_os("ARINSAL_LITERAL_TRACE").is_some() {
            eprintln!("resource_drop data={:p}", self.data);
        }
        // SAFETY: a registered type remains allocated, and data is live until this drop ends.
        unsafe {
            if let Some(dtor) = (*self.kind).callbacks.dtor {
                let mut env = ErlNifEnv::independent();
                dtor(&mut env, self.data.cast());
            }
        }
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
static TYPES: OnceLock<Mutex<HashMap<String, usize>>> = OnceLock::new();
static KEPT: OnceLock<Mutex<HashMap<usize, Kept>>> = OnceLock::new();
static OWNERS: OnceLock<Mutex<HashMap<usize, Weak<Resource>>>> = OnceLock::new();
fn types() -> &'static Mutex<HashMap<String, usize>> {
    TYPES.get_or_init(|| Mutex::new(HashMap::new()))
}
fn kept() -> &'static Mutex<HashMap<usize, Kept>> {
    KEPT.get_or_init(|| Mutex::new(HashMap::new()))
}
fn owners() -> &'static Mutex<HashMap<usize, Weak<Resource>>> {
    OWNERS.get_or_init(|| Mutex::new(HashMap::new()))
}
fn owner_for(data: *mut c_void) -> Option<Arc<Resource>> {
    owners().lock().unwrap().get(&(data as usize))?.upgrade()
}
fn name(p: *const c_char) -> Option<String> {
    if p.is_null() {
        None
    } else {
        Some(
            // SAFETY: The resource allocation and callback remain live during this access.
            unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned(),
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
    let env = unsafe { &*e };
    let Some(module) = env.module.as_deref() else {
        return ptr::null_mut();
    };
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
    let env = unsafe { &*e };
    let Some(module) = env.module.as_deref() else {
        return ptr::null_mut();
    };
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
    let env = unsafe { &*e };
    let Some(module) = env.module.as_deref() else {
        return ptr::null_mut();
    };
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
fn open_type(
    e: *mut ErlNifEnv,
    key: &str,
    init: &ErlNifResourceTypeInit,
    flags: c_int,
    tried: *mut c_int,
) -> *mut c_void {
    // SAFETY: callers checked the load environment pointer.
    let env = unsafe { &*e };
    if !env.options.loading {
        return ptr::null_mut();
    }
    let Some(library) = env.library.clone() else {
        return ptr::null_mut();
    };
    let mut table = types().lock().unwrap();
    if let Some(&address) = table.get(key) {
        if flags & 2 == 0 {
            return ptr::null_mut();
        };
        // SAFETY: the type is intentionally process-lifetime allocated.
        unsafe {
            (*(address as *mut ResourceType)).callbacks = *init;
            (*(address as *mut ResourceType))._library = library;
        };
        if !tried.is_null() {
            // SAFETY: The resource allocation and callback remain live during this access.
            unsafe { *tried = 2 }
        };
        return address as *mut c_void;
    }
    if flags & 1 == 0 {
        return ptr::null_mut();
    };
    let address = Box::into_raw(Box::new(ResourceType {
        callbacks: *init,
        _library: library,
    })) as usize;
    table.insert(key.to_owned(), address);
    if !tried.is_null() {
        // SAFETY: The resource allocation and callback remain live during this access.
        unsafe { *tried = 1 }
    };
    address as *mut c_void
}
#[unsafe(no_mangle)]
pub extern "C" fn enif_alloc_resource(kind: *mut c_void, size: usize) -> *mut c_void {
    if kind.is_null() {
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
        kind: kind.cast(),
        data,
        size,
        magic: Mutex::new(Weak::new()),
    });
    owners()
        .lock()
        .unwrap()
        .insert(data as usize, Arc::downgrade(&owner));
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
    owner_for(data).map_or(0, |owner| owner.size)
}
#[unsafe(no_mangle)]
pub extern "C" fn enif_make_resource(e: *mut ErlNifEnv, data: *mut c_void) -> Term {
    let owner = owner_for(data);
    let Some(owner) = owner else {
        return terms::enif_make_badarg(e);
    };
    let magic = owner.magic_ref();
    // SAFETY: the host passes a live environment to this callback.
    let env = unsafe { &mut *e };
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
    let Some(magic) = (unsafe { t.magic_ref() }) else {
        return 0;
    };
    let Some(owner) = magic.downcast_ref::<Arc<Resource>>() else {
        return 0;
    };
    if owner.kind.cast::<c_void>() != kind {
        return 0;
    };
    if !out.is_null() {
        // SAFETY: The resource allocation and callback remain live during this access.
        unsafe { *out = owner.data.cast() }
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
    let env = unsafe { &mut *e };
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
    let Some(&kind) = types().lock().unwrap().get(&key) else {
        return 1;
    };
    let mut object = ptr::null_mut();
    if enif_get_resource(e, reference, kind as *mut c_void, &mut object) == 0 {
        return 1;
    };
    // SAFETY: a registered callback and its resource are live during this invocation.
    unsafe {
        if let Some(f) = (*(kind as *const ResourceType)).callbacks.dyncall {
            f(e, object, call_data);
            0
        } else {
            1
        }
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
