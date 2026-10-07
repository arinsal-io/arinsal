//! Minimal host for probing the Unix Erlang NIF ABI.

// These exports are called only through C function pointers; their pointer contracts
// are checked at the boundary where the host constructs the callback environment.
#![allow(clippy::not_unsafe_ptr_arg_deref)]

use libloading::{Library, Symbol};
use std::collections::HashMap;
use std::ffi::{CStr, c_char, c_int, c_long, c_uint, c_ulong, c_void};
use std::hint::black_box;
use std::path::Path;
use std::ptr;
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

#[allow(non_upper_case_globals)]
mod layout {
    include!(concat!(env!("OUT_DIR"), "/layout.rs"));
}
#[allow(dead_code)]
mod stubs {
    include!(concat!(env!("OUT_DIR"), "/stubs.rs"));
}

type Term = u64;
#[repr(C)]
struct EntryVersion {
    major: c_int,
    minor: c_int,
}
type NifFn = unsafe extern "C" fn(*mut Env, c_int, *const Term) -> Term;
type LoadFn = unsafe extern "C" fn(*mut Env, *mut *mut c_void, Term) -> c_int;
type ReloadFn = LoadFn;
type UpgradeFn = unsafe extern "C" fn(*mut Env, *mut *mut c_void, *mut *mut c_void, Term) -> c_int;
type UnloadFn = unsafe extern "C" fn(*mut Env, *mut c_void);

#[repr(C)]
struct ErlNifFunc {
    name: *const c_char,
    arity: c_uint,
    fptr: Option<NifFn>,
    flags: c_uint,
}
#[repr(C)]
struct ErlNifEntry {
    major: c_int,
    minor: c_int,
    name: *const c_char,
    num_of_funcs: c_int,
    funcs: *const ErlNifFunc,
    load: Option<LoadFn>,
    reload: Option<ReloadFn>,
    upgrade: Option<UpgradeFn>,
    unload: Option<UnloadFn>,
    vm_variant: *const c_char,
    options: c_uint,
    resource_init_size: usize,
    min_erts: *const c_char,
}
#[repr(C)]
/// Installed OTP 29.1.1 binary descriptor.
pub struct ErlNifBinary {
    size: usize,
    data: *mut u8,
    ref_bin: *mut c_void,
    spare: [*mut c_void; 2],
}
#[repr(C)]
struct ErlNifResourceTypeInit {
    dtor: Option<unsafe extern "C" fn(*mut Env, *mut c_void)>,
    stop: Option<unsafe extern "C" fn(*mut Env, *mut c_void, c_int, c_int)>,
    down: Option<unsafe extern "C" fn(*mut Env, *mut c_void, *mut c_void, *mut c_void)>,
    members: c_int,
    dyncall: Option<unsafe extern "C" fn(*mut Env, *mut c_void, *mut c_void)>,
}
macro_rules! layout_check {
    ($ty:ident, $size:ident, $($field:ident => $off:ident),+ $(,)?) => {
        const _: () = assert!(size_of::<$ty>() == layout::$size);
        $(const _: () = assert!(std::mem::offset_of!($ty, $field) == layout::$off);)+
    };
}
layout_check!(ErlNifFunc, SIZE_ErlNifFunc,
    name => OFF_ErlNifFunc_name, arity => OFF_ErlNifFunc_arity,
    fptr => OFF_ErlNifFunc_fptr, flags => OFF_ErlNifFunc_flags);
layout_check!(ErlNifEntry, SIZE_ErlNifEntry,
    major => OFF_ErlNifEntry_major, minor => OFF_ErlNifEntry_minor,
    name => OFF_ErlNifEntry_name, num_of_funcs => OFF_ErlNifEntry_num_of_funcs,
    funcs => OFF_ErlNifEntry_funcs, load => OFF_ErlNifEntry_load,
    reload => OFF_ErlNifEntry_reload, upgrade => OFF_ErlNifEntry_upgrade,
    unload => OFF_ErlNifEntry_unload, vm_variant => OFF_ErlNifEntry_vm_variant,
    options => OFF_ErlNifEntry_options,
    resource_init_size => OFF_ErlNifEntry_sizeof_ErlNifResourceTypeInit,
    min_erts => OFF_ErlNifEntry_min_erts);
layout_check!(ErlNifBinary, SIZE_ErlNifBinary,
    size => OFF_ErlNifBinary_size, data => OFF_ErlNifBinary_data,
    ref_bin => OFF_ErlNifBinary_ref_bin, spare => OFF_ErlNifBinary___spare__);
layout_check!(ErlNifResourceTypeInit, SIZE_ErlNifResourceTypeInit,
    dtor => OFF_ErlNifResourceTypeInit_dtor, stop => OFF_ErlNifResourceTypeInit_stop,
    down => OFF_ErlNifResourceTypeInit_down, members => OFF_ErlNifResourceTypeInit_members,
    dyncall => OFF_ErlNifResourceTypeInit_dyncall);
const _: () = assert!(size_of::<Term>() == layout::SIZE_ERL_NIF_TERM);

const NIL: Term = 5;
const BADARG: Term = 6;
struct ListCell {
    head: Term,
    tail: Term,
}
struct Binary {
    bytes: Box<[u8]>,
}
struct Tuple {
    elements: Box<[Term]>,
}
#[repr(C)]
/// Toy environment passed to NIF callbacks.
// A Vec<Box<T>> keeps term addresses stable while the environment grows.
#[allow(clippy::vec_box)]
pub struct Env {
    priv_data: *mut c_void,
    lists: Vec<Box<ListCell>>,
    binaries: Vec<Box<Binary>>,
    tuples: Vec<Box<Tuple>>,
}
impl Env {
    fn new() -> Self {
        Self {
            priv_data: ptr::null_mut(),
            lists: vec![],
            binaries: vec![],
            tuples: vec![],
        }
    }
    fn list(&mut self, values: &[i64]) -> Term {
        values.iter().rev().fold(NIL, |tail, &head| {
            let mut cell = Box::new(ListCell {
                head: small(head),
                tail,
            });
            let term = (&mut *cell as *mut ListCell as u64) | 1;
            self.lists.push(cell);
            term
        })
    }
    fn binary(&mut self, values: &[u8]) -> Term {
        let mut bin = Box::new(Binary {
            bytes: values.into(),
        });
        let term = (&mut *bin as *mut Binary as u64) | 2;
        self.binaries.push(bin);
        term
    }
    fn tuple(&mut self, values: &[Term]) -> Term {
        let mut tuple = Box::new(Tuple {
            elements: values.into(),
        });
        let term = (&mut *tuple as *mut Tuple as u64) | 3;
        self.tuples.push(tuple);
        term
    }
}
fn small(value: i64) -> Term {
    ((value as u64) << 4) | 15
}
fn integer(term: Term) -> Option<i64> {
    (term & 15 == 15).then_some((term as i64) >> 4)
}
static ATOMS: OnceLock<Mutex<HashMap<String, Term>>> = OnceLock::new();
unsafe extern "C" {
    fn malloc(size: usize) -> *mut c_void;
    fn free(ptr: *mut c_void);
}
unsafe extern "C" {
    fn nif_spike_shim_anchor();
}

/// Return private data from a toy NIF environment.
#[unsafe(no_mangle)]
pub extern "C" fn enif_priv_data(env: *mut Env) -> *mut c_void {
    // SAFETY: A NIF callback receives a live environment from this host.
    unsafe { (*env).priv_data }
}
/// Allocate memory on the C heap.
#[unsafe(no_mangle)]
pub extern "C" fn enif_alloc(size: usize) -> *mut c_void {
    // SAFETY: libc malloc accepts any size.
    unsafe { malloc(size) }
}
/// Free memory allocated by enif_alloc.
#[unsafe(no_mangle)]
pub extern "C" fn enif_free(ptr: *mut c_void) {
    // SAFETY: The NIF contract requires a pointer from enif_alloc.
    unsafe { free(ptr) }
}
/// Read a tagged small integer as a long.
#[unsafe(no_mangle)]
pub extern "C" fn enif_get_long(_env: *mut Env, term: Term, out: *mut c_long) -> c_int {
    if let Some(n) = integer(term) {
        // SAFETY: The NIF supplies writable output storage.
        unsafe {
            *out = n as c_long;
        }
        1
    } else {
        0
    }
}
/// Construct a tagged small integer from a long.
#[unsafe(no_mangle)]
pub extern "C" fn enif_make_long(_env: *mut Env, n: c_long) -> Term {
    small(n)
}
/// Read a tagged small integer as an int.
#[unsafe(no_mangle)]
pub extern "C" fn enif_get_int(_env: *mut Env, term: Term, out: *mut c_int) -> c_int {
    if let Some(n) = integer(term).and_then(|n| c_int::try_from(n).ok()) {
        // SAFETY: The NIF supplies writable output storage.
        unsafe {
            *out = n;
        }
        1
    } else {
        0
    }
}
/// Construct a tagged small integer from an int.
#[unsafe(no_mangle)]
pub extern "C" fn enif_make_int(_env: *mut Env, n: c_int) -> Term {
    small(n.into())
}
/// Construct a tagged small integer from an unsigned long.
#[unsafe(no_mangle)]
pub extern "C" fn enif_make_ulong(_env: *mut Env, n: c_ulong) -> Term {
    small(n as i64)
}
/// Inspect a toy binary.
#[unsafe(no_mangle)]
pub extern "C" fn enif_inspect_binary(_env: *mut Env, term: Term, out: *mut ErlNifBinary) -> c_int {
    if term & 15 != 2 {
        return 0;
    }
    // SAFETY: Binary terms point into stable boxes owned by the environment.
    unsafe {
        let bin = &*((term & !15) as *const Binary);
        *out = ErlNifBinary {
            size: bin.bytes.len(),
            data: bin.bytes.as_ptr() as *mut u8,
            ref_bin: ptr::null_mut(),
            spare: [ptr::null_mut(); 2],
        };
    }
    1
}
/// Read one toy list cell.
#[unsafe(no_mangle)]
pub extern "C" fn enif_get_list_cell(
    _env: *mut Env,
    term: Term,
    head: *mut Term,
    tail: *mut Term,
) -> c_int {
    if term & 15 != 1 {
        return 0;
    }
    // SAFETY: List terms point into stable boxes owned by the environment.
    unsafe {
        let cell = &*((term & !15) as *const ListCell);
        *head = cell.head;
        *tail = cell.tail;
    }
    1
}
/// Identify a toy list or empty list.
#[unsafe(no_mangle)]
pub extern "C" fn enif_is_list(_env: *mut Env, term: Term) -> c_int {
    i32::from(term == NIL || term & 15 == 1)
}
/// Intern an atom in the toy atom table.
#[unsafe(no_mangle)]
pub extern "C" fn enif_make_atom(_env: *mut Env, name: *const c_char) -> Term {
    // SAFETY: NIF atom names are null-terminated.
    let name = unsafe { CStr::from_ptr(name) }
        .to_string_lossy()
        .into_owned();
    let mut atoms = ATOMS
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .expect("atom lock");
    let next = ((atoms.len() as u64 + 1) << 4) | 4;
    *atoms.entry(name).or_insert(next)
}
/// Return the toy badarg sentinel.
#[unsafe(no_mangle)]
pub extern "C" fn enif_make_badarg(_env: *mut Env) -> Term {
    BADARG
}
/// Read a toy tuple.
#[unsafe(no_mangle)]
pub extern "C" fn enif_get_tuple(
    _env: *mut Env,
    term: Term,
    arity: *mut c_int,
    elements: *mut *const Term,
) -> c_int {
    if term & 15 != 3 {
        return 0;
    }
    // SAFETY: Tuple terms point into stable boxes owned by the environment.
    unsafe {
        let tuple = &*((term & !15) as *const Tuple);
        *arity = tuple.elements.len() as c_int;
        *elements = tuple.elements.as_ptr();
    }
    1
}
/// Allocate a temporary ErlNifBinary on the C heap.
#[unsafe(no_mangle)]
pub extern "C" fn enif_alloc_binary(size: usize, out: *mut ErlNifBinary) -> c_int {
    // SAFETY: malloc provides C-owned storage, and the NIF passes writable output.
    unsafe {
        let data = malloc(size).cast::<u8>();
        if data.is_null() {
            return 0;
        }
        *out = ErlNifBinary {
            size,
            data,
            ref_bin: ptr::null_mut(),
            spare: [ptr::null_mut(); 2],
        };
    }
    1
}
/// Release a temporary ErlNifBinary.
#[unsafe(no_mangle)]
pub extern "C" fn enif_release_binary(bin: *mut ErlNifBinary) {
    // SAFETY: This host allocated the buffer with malloc.
    unsafe {
        free((*bin).data.cast());
        (*bin).data = ptr::null_mut();
        (*bin).size = 0;
    }
}

/// Register a toy resource type so crypto's load path can continue.
#[unsafe(no_mangle)]
pub extern "C" fn enif_open_resource_type(
    _env: *mut Env,
    _module: *const c_char,
    name: *const c_char,
    _dtor: Option<unsafe extern "C" fn(*mut Env, *mut c_void)>,
    flags: c_int,
    tried: *mut c_int,
) -> *mut c_void {
    // SAFETY: The callback supplies a terminated name and optional writable flags.
    let name = unsafe { CStr::from_ptr(name) }.to_string_lossy();
    println!("open resource type: {name}");
    if !tried.is_null() {
        // SAFETY: A non-null tried pointer is supplied by the NIF.
        unsafe {
            *tried = flags;
        }
    }
    Box::into_raw(Box::new(0_u8)).cast()
}

fn validate(entry: &ErlNifEntry, expected: &str) -> Result<(), String> {
    // Port of erts/emulator/beam/erl_nif.c:4797 (erts_load_nif), OTP-29.1.1.
    if entry.major != 2 || entry.minor > 18 || entry.minor == 5 || entry.minor < 14 {
        return Err(format!(
            "unsupported NIF version {}.{}",
            entry.major, entry.minor
        ));
    }
    if entry.name.is_null() {
        return Err("null module name".into());
    }
    // SAFETY: A valid NIF entry contains terminated names.
    let name = unsafe { CStr::from_ptr(entry.name) }.to_string_lossy();
    if name != expected {
        return Err(format!("module name {name} != {expected}"));
    }
    if entry.minor >= 1 {
        if entry.vm_variant.is_null() {
            return Err("null VM variant".into());
        }
        // SAFETY: The 2.1+ entry contains a terminated VM variant.
        let variant = unsafe { CStr::from_ptr(entry.vm_variant) }.to_string_lossy();
        if variant != "beam.vanilla" {
            return Err(format!("VM variant {variant}"));
        }
    }
    if !(0..=10000).contains(&entry.num_of_funcs) || entry.funcs.is_null() {
        return Err("invalid function table".into());
    }
    Ok(())
}

fn run(path: &Path, expected: &str, invoke_load: bool) -> Result<(), String> {
    // SAFETY: The anchor has no arguments or side effects; it keeps the C shim linked.
    unsafe {
        nif_spike_shim_anchor();
    }
    for stub in stubs::STUBS {
        black_box(stub as usize);
    }
    println!("generated API declarations: {}", stubs::API_COUNT);
    // SAFETY: The library stays alive throughout entry and callback use.
    let lib = unsafe { Library::new(path) }.map_err(|e| format!("dlopen: {e}"))?;
    // SAFETY: Unix NIFs export nif_init with this signature.
    let init: Symbol<unsafe extern "C" fn() -> *const EntryVersion> =
        unsafe { lib.get(b"nif_init\0") }.map_err(|e| format!("nif_init: {e}"))?;
    // SAFETY: nif_init returns a static entry while its library is loaded.
    let version = unsafe { init().as_ref() }.ok_or("nif_init returned null")?;
    if version.major != 2 || version.minor > 18 || version.minor == 5 || version.minor < 14 {
        return Err(format!(
            "unsupported NIF entry layout {}.{} (spike supports 2.14 through 2.18)",
            version.major, version.minor
        ));
    }
    // SAFETY: NIF entries from 2.14 onward contain every field in this mirror.
    let entry = unsafe { &*(version as *const EntryVersion as *const ErlNifEntry) };
    validate(entry, expected)?;
    println!(
        "entry: {} version {}.{} funcs {} options {} resource_init_size {}",
        expected,
        entry.major,
        entry.minor,
        entry.num_of_funcs,
        entry.options,
        entry.resource_init_size
    );
    let mut env = Env::new();
    if let Some(load) = entry.load {
        if invoke_load {
            let info = if expected == "crypto" {
                let version = small(302);
                let path_bin = env.binary(path.to_string_lossy().as_bytes());
                let fips = enif_make_atom(&mut env, c"false".as_ptr());
                env.tuple(&[version, path_bin, fips])
            } else {
                NIL
            };
            let mut priv_data = ptr::null_mut();
            println!("calling load");
            // SAFETY: The callback takes this live environment and toy load_info.
            let result = unsafe { load(&mut env, &mut priv_data, info) };
            env.priv_data = priv_data;
            println!("load returned {result}");
        }
    } else {
        println!("load callback: absent");
    }
    if expected == "nb" {
        // SAFETY: The validated function array belongs to the loaded library.
        let funcs = unsafe { std::slice::from_raw_parts(entry.funcs, entry.num_of_funcs as usize) };
        let call = |name: &str, args: &[Term], env: &mut Env| -> Result<Term, String> {
            let function = funcs
                .iter()
                .find(|f| {
                    // SAFETY: NIF function names are terminated strings.
                    unsafe { CStr::from_ptr(f.name) }.to_bytes() == name.as_bytes()
                        && f.arity as usize == args.len()
                })
                .ok_or_else(|| format!("missing {name}/{}", args.len()))?;
            let fp = function
                .fptr
                .ok_or_else(|| format!("null {name} function"))?;
            // SAFETY: Function pointer and arguments follow the declared NIF ABI.
            Ok(unsafe { fp(env, args.len() as c_int, args.as_ptr()) })
        };
        let list = env.list(&[1, 2, 3]);
        let binary = env.binary(&[1, 2, 3]);
        for (name, args) in [
            ("noop", vec![small(7)]),
            ("add", vec![small(2), small(3)]),
            ("bsum", vec![binary]),
            ("lsum", vec![list]),
        ] {
            let value = call(name, &args, &mut env)?;
            println!("{name}: {}", integer(value).ok_or("noninteger result")?);
        }
        let iterations = 10_000_000;
        let args = [small(2), small(3)];
        let add = funcs
            .iter()
            .find(|f| {
                // SAFETY: The NIF function table contains terminated names.
                unsafe { CStr::from_ptr(f.name) }.to_bytes() == b"add" && f.arity == 2
            })
            .and_then(|f| f.fptr)
            .ok_or("missing add/2")?;
        let start = Instant::now();
        for _ in 0..iterations {
            // SAFETY: add/2 is the validated callback with two toy small integers.
            black_box(unsafe { add(black_box(&mut env), 2, black_box(args.as_ptr())) });
        }
        println!(
            "add direct callback: {:.2} ns/call ({iterations} calls)",
            start.elapsed().as_nanos() as f64 / iterations as f64
        );
    }
    Ok(())
}

fn main() {
    let mut args = std::env::args().skip(1);
    let Some(path) = args.next() else {
        eprintln!("usage: nif_spike <nb.so|crypto.so> [--load]");
        std::process::exit(2);
    };
    let path = Path::new(&path);
    let name = if path.file_name().is_some_and(|n| n == "crypto.so") {
        "crypto"
    } else {
        "nb"
    };
    let invoke_load = args.any(|x| x == "--load") || name == "nb";
    if let Err(error) = run(path, name, invoke_load) {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn toy_terms_round_trip() {
        let mut env = Env::new();
        let list = env.list(&[1, 2, 3]);
        let mut head = 0;
        let mut tail = 0;
        assert_eq!(enif_get_list_cell(&mut env, list, &mut head, &mut tail), 1);
        assert_eq!(integer(head), Some(1));
        assert_eq!(enif_is_list(&mut env, tail), 1);
        let bin = env.binary(&[1, 2, 3]);
        let mut inspected = ErlNifBinary {
            size: 0,
            data: ptr::null_mut(),
            ref_bin: ptr::null_mut(),
            spare: [ptr::null_mut(); 2],
        };
        assert_eq!(enif_inspect_binary(&mut env, bin, &mut inspected), 1);
        assert_eq!(inspected.size, 3);
    }
}
