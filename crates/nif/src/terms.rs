//! Term-oriented NIF entry points.
use crate::{ErlNifBinary, ErlNifEnv, bits, term};
use arinsal_term::{
    ListIter, Term, TermBuilder, TermKind, cmp, copy_term, exact_eq, global_atoms,
    internal_salted_hash, make_hash2, size_object, writable_bytes_mut,
};
use num_traits::ToPrimitive;
use std::ffi::{CStr, c_char, c_int, c_long, c_uint, c_ulong, c_void};
use std::hint::black_box;
use std::ptr;

fn env<'a>(p: *mut ErlNifEnv) -> &'a mut ErlNifEnv {
    // SAFETY: all NIF callbacks are passed a live host environment.
    unsafe { &mut *p }
}
fn integer(t: Term) -> Option<i128> {
    if let Some(n) = t.as_small() {
        return Some(n as i128);
    }
    // SAFETY: caller keeps the term's heap live during inspection.
    unsafe { t.big_ref() }?.to_bigint().to_i128()
}
fn atom_text(t: Term) -> Option<&'static str> {
    global_atoms().text(t.as_atom()?)
}
fn decode(bytes: &[u8], encoding: c_int) -> Option<String> {
    match encoding {
        1 => Some(bytes.iter().map(|b| char::from(*b)).collect()),
        2 => std::str::from_utf8(bytes).ok().map(str::to_owned),
        _ => None,
    }
}
fn encode(text: &str, encoding: c_int) -> Option<Vec<u8>> {
    match encoding {
        1 => text.chars().map(|c| u8::try_from(c as u32).ok()).collect(),
        2 => Some(text.as_bytes().to_vec()),
        _ => None,
    }
}
fn binary_bytes(t: Term) -> Option<&'static [u8]> {
    // SAFETY: the caller owns the term's live heap throughout this ABI call.
    let view = unsafe { t.binary_ref() }?;
    if view.start_bit() % 8 != 0 || view.bit_len() % 8 != 0 {
        return None;
    }
    // SAFETY: the returned slice is used only during the live callback.
    Some(
        // SAFETY: The NIF caller retains live term heaps and provides ABI-valid storage.
        unsafe {
            std::slice::from_raw_parts(
                view.bytes().as_ptr().add(view.start_bit() / 8),
                view.bit_len() / 8,
            )
        },
    )
}
fn built(
    e: &mut ErlNifEnv,
    f: impl FnOnce(&mut TermBuilder<'_, super::EnvHeap>) -> Result<Term, arinsal_term::TermError>,
) -> Term {
    f(&mut TermBuilder::new(&mut e.heap)).unwrap_or_else(|_| enif_make_badarg(e))
}
#[unsafe(no_mangle)]
pub extern "C" fn enif_priv_data(e: *mut ErlNifEnv) -> *mut c_void {
    env(e).priv_data
}
unsafe extern "C" {
    fn malloc(n: usize) -> *mut c_void;
    fn realloc(p: *mut c_void, n: usize) -> *mut c_void;
    fn free(p: *mut c_void);
}
#[unsafe(no_mangle)]
pub extern "C" fn enif_alloc(n: usize) -> *mut c_void {
    // SAFETY: The NIF caller retains live term heaps and provides ABI-valid storage.
    unsafe { malloc(n) }
}
#[unsafe(no_mangle)]
pub extern "C" fn enif_realloc(p: *mut c_void, n: usize) -> *mut c_void {
    // SAFETY: The NIF caller retains live term heaps and provides ABI-valid storage.
    unsafe { realloc(p, n) }
}
#[unsafe(no_mangle)]
pub extern "C" fn enif_free(p: *mut c_void) {
    // SAFETY: The NIF caller retains live term heaps and provides ABI-valid storage.
    unsafe { free(p) }
}

macro_rules! is_kind { ($name:ident, $($pat:pat_param)|+) => {
    #[unsafe(no_mangle)] pub extern "C" fn $name(_: *mut ErlNifEnv, t: Term) -> c_int { i32::from(matches!(t.classify(), $($pat)|+)) }
}; }
is_kind!(enif_is_atom, TermKind::Atom);
is_kind!(enif_is_ref, TermKind::Ref);
is_kind!(enif_is_fun, TermKind::Fun);
is_kind!(enif_is_pid, TermKind::Pid);
is_kind!(enif_is_port, TermKind::Port);
is_kind!(enif_is_map, TermKind::Map);
is_kind!(enif_is_tuple, TermKind::Tuple);
is_kind!(enif_is_number, TermKind::Number);
is_kind!(enif_is_list, TermKind::List | TermKind::Nil);
#[unsafe(no_mangle)]
pub extern "C" fn enif_is_empty_list(_: *mut ErlNifEnv, t: Term) -> c_int {
    i32::from(t == Term::NIL)
}
#[unsafe(no_mangle)]
pub extern "C" fn enif_is_binary(_: *mut ErlNifEnv, t: Term) -> c_int {
    i32::from(binary_bytes(t).is_some())
}
#[unsafe(no_mangle)]
pub extern "C" fn enif_is_identical(a: Term, b: Term) -> c_int {
    i32::from(exact_eq(a, b))
}
#[unsafe(no_mangle)]
pub extern "C" fn enif_compare(a: Term, b: Term) -> c_int {
    match cmp(a, b) {
        std::cmp::Ordering::Less => -1,
        std::cmp::Ordering::Equal => 0,
        std::cmp::Ordering::Greater => 1,
    }
}
#[unsafe(no_mangle)]
pub extern "C" fn enif_hash(kind: c_int, t: Term, salt: u64) -> u64 {
    match kind {
        1 => internal_salted_hash(t, salt),
        2 => (make_hash2(t) & ((1 << 27) - 1)) as u64,
        _ => 0,
    }
}
#[unsafe(no_mangle)]
pub extern "C" fn enif_term_size(t: Term) -> usize {
    size_object(t) * size_of::<u64>()
}
#[unsafe(no_mangle)]
pub extern "C" fn enif_term_type(_: *mut ErlNifEnv, t: Term) -> c_int {
    match t.classify() {
        TermKind::Atom => 1,
        TermKind::Bitstring => 2,
        // SAFETY: The NIF caller retains live term heaps and provides ABI-valid storage.
        TermKind::Number if t.as_small().is_none() && unsafe { t.float_ref() }.is_some() => 3,
        TermKind::Number => 5,
        TermKind::Fun => 4,
        TermKind::List | TermKind::Nil => 6,
        TermKind::Map => 7,
        TermKind::Pid => 8,
        TermKind::Port => 9,
        TermKind::Ref => 10,
        TermKind::Tuple => 11,
        _ => -1,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn enif_get_long(_: *mut ErlNifEnv, t: Term, out: *mut c_long) -> c_int {
    if let Some(n) = integer(t).and_then(|n| c_long::try_from(n).ok()) {
        if !out.is_null() {
            // SAFETY: The NIF caller retains live term heaps and provides ABI-valid storage.
            unsafe { *out = n }
        }
        1
    } else {
        0
    }
}
#[unsafe(no_mangle)]
pub extern "C" fn enif_get_int(_: *mut ErlNifEnv, t: Term, out: *mut c_int) -> c_int {
    if let Some(n) = integer(t).and_then(|n| c_int::try_from(n).ok()) {
        if !out.is_null() {
            // SAFETY: The NIF caller retains live term heaps and provides ABI-valid storage.
            unsafe { *out = n }
        }
        1
    } else {
        0
    }
}
#[unsafe(no_mangle)]
pub extern "C" fn enif_get_ulong(_: *mut ErlNifEnv, t: Term, out: *mut c_ulong) -> c_int {
    if let Some(n) = integer(t).and_then(|n| c_ulong::try_from(n).ok()) {
        if !out.is_null() {
            // SAFETY: The NIF caller retains live term heaps and provides ABI-valid storage.
            unsafe { *out = n }
        }
        1
    } else {
        0
    }
}
#[unsafe(no_mangle)]
pub extern "C" fn enif_get_uint(_: *mut ErlNifEnv, t: Term, out: *mut c_uint) -> c_int {
    if let Some(n) = integer(t).and_then(|n| c_uint::try_from(n).ok()) {
        if !out.is_null() {
            // SAFETY: The NIF caller retains live term heaps and provides ABI-valid storage.
            unsafe { *out = n }
        }
        1
    } else {
        0
    }
}
#[unsafe(no_mangle)]
pub extern "C" fn enif_get_double(_: *mut ErlNifEnv, t: Term, out: *mut f64) -> c_int {
    if let Some(n) =
        // SAFETY: The NIF caller retains live term heaps and provides ABI-valid storage.
        unsafe { t.float_ref() }
    {
        if !out.is_null() {
            // SAFETY: The NIF caller retains live term heaps and provides ABI-valid storage.
            unsafe { *out = n.get() }
        }
        1
    } else {
        0
    }
}
#[unsafe(no_mangle)]
pub extern "C" fn enif_make_long(e: *mut ErlNifEnv, n: c_long) -> Term {
    built(env(e), |b| b.int_from_i64(n))
}
#[unsafe(no_mangle)]
pub extern "C" fn enif_make_int(e: *mut ErlNifEnv, n: c_int) -> Term {
    enif_make_long(e, n as c_long)
}
#[unsafe(no_mangle)]
pub extern "C" fn enif_make_ulong(e: *mut ErlNifEnv, n: c_ulong) -> Term {
    built(env(e), |b| b.int_from_i128(n as i128))
}
#[unsafe(no_mangle)]
pub extern "C" fn enif_make_uint(e: *mut ErlNifEnv, n: c_uint) -> Term {
    enif_make_ulong(e, n as c_ulong)
}
#[unsafe(no_mangle)]
pub extern "C" fn enif_get_int64(e: *mut ErlNifEnv, t: Term, out: *mut i64) -> c_int {
    enif_get_long(e, t, out)
}
#[unsafe(no_mangle)]
pub extern "C" fn enif_get_uint64(e: *mut ErlNifEnv, t: Term, out: *mut u64) -> c_int {
    enif_get_ulong(e, t, out)
}
#[unsafe(no_mangle)]
pub extern "C" fn enif_make_int64(e: *mut ErlNifEnv, n: i64) -> Term {
    enif_make_long(e, n)
}
#[unsafe(no_mangle)]
pub extern "C" fn enif_make_uint64(e: *mut ErlNifEnv, n: u64) -> Term {
    enif_make_ulong(e, n)
}
#[unsafe(no_mangle)]
pub extern "C" fn enif_make_double(e: *mut ErlNifEnv, n: f64) -> Term {
    // Port of erts/emulator/beam/erl_nif.c:2203 (enif_make_double): NaN and infinity raise badarg.
    if !n.is_finite() {
        return enif_make_badarg(e);
    }
    built(env(e), |b| b.float(n))
}

#[unsafe(no_mangle)]
pub extern "C" fn enif_make_atom(e: *mut ErlNifEnv, name: *const c_char) -> Term {
    if name.is_null() {
        return enif_make_badarg(e);
    };
    // SAFETY: The NIF caller retains live term heaps and provides ABI-valid storage.
    let bytes = unsafe { CStr::from_ptr(name) }.to_bytes();
    enif_make_atom_len(e, bytes.as_ptr().cast(), bytes.len())
}
#[unsafe(no_mangle)]
pub extern "C" fn enif_make_atom_len(e: *mut ErlNifEnv, name: *const c_char, len: usize) -> Term {
    if name.is_null() {
        return enif_make_badarg(e);
    };
    // SAFETY: The NIF caller retains live term heaps and provides ABI-valid storage.
    let bytes = unsafe { std::slice::from_raw_parts(name.cast::<u8>(), len) };
    let Some(s) = decode(bytes, 1) else {
        return enif_make_badarg(e);
    };
    global_atoms()
        .intern(&s)
        .map(Term::atom)
        .unwrap_or_else(|_| enif_make_badarg(e))
}
#[unsafe(no_mangle)]
pub extern "C" fn enif_make_existing_atom(
    e: *mut ErlNifEnv,
    name: *const c_char,
    out: *mut Term,
    enc: c_int,
) -> c_int {
    if name.is_null() {
        return 0;
    };
    // SAFETY: The NIF caller retains live term heaps and provides ABI-valid storage.
    let bytes = unsafe { CStr::from_ptr(name) }.to_bytes();
    enif_make_existing_atom_len(e, bytes.as_ptr().cast(), bytes.len(), out, enc)
}
#[unsafe(no_mangle)]
pub extern "C" fn enif_make_existing_atom_len(
    _: *mut ErlNifEnv,
    name: *const c_char,
    len: usize,
    out: *mut Term,
    enc: c_int,
) -> c_int {
    if name.is_null() {
        return 0;
    };
    // SAFETY: The NIF caller retains live term heaps and provides ABI-valid storage.
    let bytes = unsafe { std::slice::from_raw_parts(name.cast::<u8>(), len) };
    let Some(s) = decode(bytes, enc) else {
        return 0;
    };
    if let Some(a) = global_atoms().get(&s) {
        if !out.is_null() {
            // SAFETY: The NIF caller retains live term heaps and provides ABI-valid storage.
            unsafe { *out = Term::atom(a) }
        };
        1
    } else {
        0
    }
}
#[unsafe(no_mangle)]
pub extern "C" fn enif_make_new_atom(
    e: *mut ErlNifEnv,
    name: *const c_char,
    out: *mut Term,
    enc: c_int,
) -> c_int {
    if name.is_null() {
        return 0;
    };
    // SAFETY: The NIF caller retains live term heaps and provides ABI-valid storage.
    let bytes = unsafe { CStr::from_ptr(name) }.to_bytes();
    enif_make_new_atom_len(e, bytes.as_ptr().cast(), bytes.len(), out, enc)
}
#[unsafe(no_mangle)]
pub extern "C" fn enif_make_new_atom_len(
    _: *mut ErlNifEnv,
    name: *const c_char,
    len: usize,
    out: *mut Term,
    enc: c_int,
) -> c_int {
    if name.is_null() {
        return 0;
    };
    // SAFETY: The NIF caller retains live term heaps and provides ABI-valid storage.
    let bytes = unsafe { std::slice::from_raw_parts(name.cast::<u8>(), len) };
    let Some(s) = decode(bytes, enc) else {
        return 0;
    };
    if let Ok(a) = global_atoms().intern(&s) {
        if !out.is_null() {
            // SAFETY: The NIF caller retains live term heaps and provides ABI-valid storage.
            unsafe { *out = Term::atom(a) }
        };
        1
    } else {
        0
    }
}
#[unsafe(no_mangle)]
pub extern "C" fn enif_get_atom_length(
    _: *mut ErlNifEnv,
    t: Term,
    out: *mut c_uint,
    enc: c_int,
) -> c_int {
    let Some(bytes) = atom_text(t).and_then(|s| encode(s, enc)) else {
        return 0;
    };
    if !out.is_null() {
        // SAFETY: The NIF caller retains live term heaps and provides ABI-valid storage.
        unsafe { *out = bytes.len() as c_uint }
    };
    1
}
#[unsafe(no_mangle)]
pub extern "C" fn enif_get_atom(
    _: *mut ErlNifEnv,
    t: Term,
    out: *mut c_char,
    len: c_uint,
    enc: c_int,
) -> c_int {
    let Some(bytes) = atom_text(t).and_then(|s| encode(s, enc)) else {
        return 0;
    };
    if out.is_null() || len as usize <= bytes.len() {
        return 0;
    };
    // SAFETY: The NIF caller retains live term heaps and provides ABI-valid storage.
    unsafe {
        ptr::copy_nonoverlapping(bytes.as_ptr(), out.cast(), bytes.len());
        *out.add(bytes.len()) = 0
    };
    (bytes.len() + 1) as c_int
}
#[unsafe(no_mangle)]
pub extern "C" fn enif_get_atom_cache_index(_: *mut ErlNifEnv, t: Term, out: *mut c_uint) -> c_int {
    if let Some(a) = t.as_atom() {
        if !out.is_null() {
            // SAFETY: The NIF caller retains live term heaps and provides ABI-valid storage.
            unsafe { *out = a.0 }
        };
        1
    } else {
        0
    }
}
#[unsafe(no_mangle)]
pub extern "C" fn enif_max_atom_cache_index() -> c_uint {
    2047
}

#[unsafe(no_mangle)]
pub extern "C" fn enif_get_list_cell(
    _: *mut ErlNifEnv,
    t: Term,
    head: *mut Term,
    tail: *mut Term,
) -> c_int {
    if let Some((h, tl)) =
        // SAFETY: The NIF caller retains live term heaps and provides ABI-valid storage.
        unsafe { t.cons_ref() }
    {
        // SAFETY: The NIF caller retains live term heaps and provides ABI-valid storage.
        unsafe {
            if !head.is_null() {
                *head = h
            };
            if !tail.is_null() {
                *tail = tl
            }
        };
        1
    } else {
        0
    }
}
#[unsafe(no_mangle)]
pub extern "C" fn enif_get_list_length(_: *mut ErlNifEnv, t: Term, out: *mut c_uint) -> c_int {
    let mut next = t;
    let mut n = 0u32;
    while let Some((_, tail)) =
        // SAFETY: The NIF caller retains live term heaps and provides ABI-valid storage.
        unsafe { next.cons_ref() }
    {
        let Some(x) = n.checked_add(1) else { return 0 };
        n = x;
        next = tail
    }
    if next != Term::NIL {
        return 0;
    };
    if !out.is_null() {
        // SAFETY: The NIF caller retains live term heaps and provides ABI-valid storage.
        unsafe { *out = n }
    };
    1
}
#[unsafe(no_mangle)]
pub extern "C" fn enif_get_tuple(
    _: *mut ErlNifEnv,
    t: Term,
    arity: *mut c_int,
    array: *mut *const Term,
) -> c_int {
    // SAFETY: The NIF caller retains live term heaps and provides ABI-valid storage.
    let Some(v) = (unsafe { t.tuple_ref() }) else {
        return 0;
    };
    if !arity.is_null() {
        // SAFETY: The NIF caller retains live term heaps and provides ABI-valid storage.
        unsafe { *arity = v.len() as c_int }
    };
    if !array.is_null() {
        // SAFETY: The NIF caller retains live term heaps and provides ABI-valid storage.
        unsafe { *array = t.raw_ptr().add(1).cast() }
    };
    1
}
#[unsafe(no_mangle)]
pub extern "C" fn enif_make_list_cell(e: *mut ErlNifEnv, h: Term, t: Term) -> Term {
    built(env(e), |b| b.cons(h, t))
}
#[unsafe(no_mangle)]
pub extern "C" fn enif_make_list_from_array(
    e: *mut ErlNifEnv,
    arr: *const Term,
    n: c_uint,
) -> Term {
    if arr.is_null() && n > 0 {
        return enif_make_badarg(e);
    };
    // SAFETY: The NIF caller retains live term heaps and provides ABI-valid storage.
    let items = unsafe { std::slice::from_raw_parts(arr, n as usize) };
    built(env(e), |b| b.list_from_iter(items.iter().copied()))
}
#[unsafe(no_mangle)]
pub extern "C" fn enif_make_tuple_from_array(
    e: *mut ErlNifEnv,
    arr: *const Term,
    n: c_uint,
) -> Term {
    if arr.is_null() && n > 0 {
        return enif_make_badarg(e);
    };
    // SAFETY: The NIF caller retains live term heaps and provides ABI-valid storage.
    let items = unsafe { std::slice::from_raw_parts(arr, n as usize) };
    built(env(e), |b| b.tuple(items))
}
#[unsafe(no_mangle)]
pub extern "C" fn arinsal_nif_tuple(e: *mut ErlNifEnv, arr: *const Term, n: c_uint) -> Term {
    enif_make_tuple_from_array(e, arr, n)
}
#[unsafe(no_mangle)]
pub extern "C" fn arinsal_nif_list(e: *mut ErlNifEnv, arr: *const Term, n: c_uint) -> Term {
    enif_make_list_from_array(e, arr, n)
}
#[unsafe(no_mangle)]
pub extern "C" fn enif_make_reverse_list(e: *mut ErlNifEnv, mut t: Term, out: *mut Term) -> c_int {
    let mut result = Term::NIL;
    while let Some((h, tail)) =
        // SAFETY: The NIF caller retains live term heaps and provides ABI-valid storage.
        unsafe { t.cons_ref() }
    {
        result = enif_make_list_cell(e, h, result);
        t = tail
    }
    if t != Term::NIL {
        return 0;
    };
    if !out.is_null() {
        // SAFETY: The NIF caller retains live term heaps and provides ABI-valid storage.
        unsafe { *out = result }
    };
    1
}
#[unsafe(no_mangle)]
pub extern "C" fn enif_make_string(e: *mut ErlNifEnv, s: *const c_char, enc: c_int) -> Term {
    if s.is_null() {
        return enif_make_badarg(e);
    };
    // SAFETY: The NIF caller retains live term heaps and provides ABI-valid storage.
    let b = unsafe { CStr::from_ptr(s) }.to_bytes();
    enif_make_string_len(e, b.as_ptr().cast(), b.len(), enc)
}
#[unsafe(no_mangle)]
pub extern "C" fn enif_make_string_len(
    e: *mut ErlNifEnv,
    s: *const c_char,
    n: usize,
    enc: c_int,
) -> Term {
    if s.is_null() {
        return enif_make_badarg(e);
    };
    // SAFETY: The NIF caller retains live term heaps and provides ABI-valid storage.
    let b = unsafe { std::slice::from_raw_parts(s.cast::<u8>(), n) };
    let Some(text) = decode(b, enc) else {
        return enif_make_badarg(e);
    };
    built(env(e), |builder| builder.string_to_list(&text))
}
#[unsafe(no_mangle)]
pub extern "C" fn enif_get_string_length(
    _: *mut ErlNifEnv,
    t: Term,
    out: *mut c_uint,
    enc: c_int,
) -> c_int {
    let mut count = 0u32;
    // SAFETY: The NIF caller retains live term heaps and provides ABI-valid storage.
    let mut iter = unsafe { ListIter::new(t) };
    for item in iter.by_ref() {
        let Some(n) = item.as_small() else { return 0 };
        if (enc == 1 && !(0..=255).contains(&n)) || (enc == 2 && char::from_u32(n as u32).is_none())
        {
            return 0;
        };
        count += if enc == 2 {
            char::from_u32(n as u32).unwrap().len_utf8() as u32
        } else {
            1
        };
    }
    if iter.tail() != Term::NIL {
        return 0;
    };
    if !out.is_null() {
        // SAFETY: The NIF caller retains live term heaps and provides ABI-valid storage.
        unsafe { *out = count }
    };
    1
}
#[unsafe(no_mangle)]
pub extern "C" fn enif_get_string(
    e: *mut ErlNifEnv,
    t: Term,
    out: *mut c_char,
    len: c_uint,
    enc: c_int,
) -> c_int {
    let mut needed = 0;
    if len == 0 || out.is_null() {
        return 0;
    };
    if enif_get_string_length(e, t, &mut needed, enc) == 0 {
        // SAFETY: the caller provides at least one writable byte.
        unsafe { *out = 0 };
        return 0;
    };
    let mut data = Vec::new();
    for item in
        // SAFETY: The NIF caller retains live term heaps and provides ABI-valid storage.
        unsafe { ListIter::new(t) }
    {
        let n = item.as_small().unwrap() as u32;
        if enc == 1 {
            data.push(n as u8)
        } else {
            let mut b = [0; 4];
            data.extend_from_slice(char::from_u32(n).unwrap().encode_utf8(&mut b).as_bytes())
        }
    }
    let mut copy = data.len().min(len as usize - 1);
    if enc == 2 && copy < data.len() {
        while copy > 0 && std::str::from_utf8(&data[..copy]).is_err() {
            copy -= 1;
        }
    }
    // SAFETY: The NIF caller retains live term heaps and provides ABI-valid storage.
    unsafe {
        ptr::copy_nonoverlapping(data.as_ptr(), out.cast(), copy);
        *out.add(copy) = 0
    };
    if copy < data.len() {
        -((copy + 1) as c_int)
    } else {
        (copy + 1) as c_int
    }
}
#[unsafe(no_mangle)]
pub extern "C" fn enif_make_copy(e: *mut ErlNifEnv, t: Term) -> Term {
    copy_term(t, &mut env(e).heap).unwrap_or_else(|_| enif_make_badarg(e))
}
#[unsafe(no_mangle)]
pub extern "C" fn enif_make_ref(e: *mut ErlNifEnv) -> Term {
    let id = arinsal_bifs::next_ref_id();
    built(env(e), |b| b.local_ref([id as u32, (id >> 32) as u32, 0]))
}
#[unsafe(no_mangle)]
pub extern "C" fn enif_make_badarg(e: *mut ErlNifEnv) -> Term {
    let bad = Term::atom(global_atoms().get("badarg").expect("preloaded badarg"));
    env(e).pending = Some(bad);
    term(0)
}
#[unsafe(no_mangle)]
pub extern "C" fn enif_raise_exception(e: *mut ErlNifEnv, reason: Term) -> Term {
    env(e).pending = Some(reason);
    term(0)
}
#[unsafe(no_mangle)]
pub extern "C" fn enif_has_pending_exception(e: *mut ErlNifEnv, reason: *mut Term) -> c_int {
    if let Some(r) = env(e).pending {
        if !reason.is_null() {
            // SAFETY: The NIF caller retains live term heaps and provides ABI-valid storage.
            unsafe { *reason = r }
        };
        1
    } else {
        0
    }
}
#[unsafe(no_mangle)]
pub extern "C" fn enif_is_exception(e: *mut ErlNifEnv, t: Term) -> c_int {
    i32::from(bits(t) == 0 && env(e).pending.is_some())
}

#[unsafe(no_mangle)]
pub extern "C" fn enif_alloc_binary(size: usize, out: *mut ErlNifBinary) -> c_int {
    if out.is_null() {
        return 0;
    };
    // SAFETY: The NIF caller retains live term heaps and provides ABI-valid storage.
    let data = unsafe { malloc(size.max(1)) }.cast::<u8>();
    if data.is_null() {
        return 0;
    };
    // SAFETY: The NIF caller retains live term heaps and provides ABI-valid storage.
    unsafe {
        *out = ErlNifBinary {
            size,
            data,
            ref_bin: data.cast(),
            spare: [ptr::null_mut(); 2],
        }
    };
    1
}
#[unsafe(no_mangle)]
pub extern "C" fn enif_realloc_binary(bin: *mut ErlNifBinary, size: usize) -> c_int {
    // SAFETY: The NIF caller retains live term heaps and provides ABI-valid storage.
    if bin.is_null() || unsafe { (*bin).ref_bin.is_null() } {
        return 0;
    };
    // SAFETY: The NIF caller retains live term heaps and provides ABI-valid storage.
    let new = unsafe { realloc((*bin).data.cast(), size.max(1)) }.cast::<u8>();
    if new.is_null() {
        return 0;
    };
    // SAFETY: The NIF caller retains live term heaps and provides ABI-valid storage.
    unsafe {
        (*bin).data = new;
        (*bin).ref_bin = new.cast();
        (*bin).size = size
    };
    1
}
#[unsafe(no_mangle)]
pub extern "C" fn enif_release_binary(bin: *mut ErlNifBinary) {
    if bin.is_null() {
        return;
    };
    // SAFETY: The NIF caller retains live term heaps and provides ABI-valid storage.
    unsafe {
        if !(*bin).ref_bin.is_null() {
            free((*bin).data.cast())
        };
        *bin = ErlNifBinary::default()
    }
}
#[unsafe(no_mangle)]
pub extern "C" fn enif_inspect_binary(_: *mut ErlNifEnv, t: Term, out: *mut ErlNifBinary) -> c_int {
    let Some(data) = binary_bytes(t) else {
        return 0;
    };
    if out.is_null() {
        return 0;
    };
    // SAFETY: The NIF caller retains live term heaps and provides ABI-valid storage.
    unsafe {
        *out = ErlNifBinary {
            size: data.len(),
            data: data.as_ptr().cast_mut(),
            ref_bin: ptr::null_mut(),
            spare: [ptr::null_mut(); 2],
        }
    };
    1
}
#[unsafe(no_mangle)]
pub extern "C" fn enif_make_binary(e: *mut ErlNifEnv, bin: *mut ErlNifBinary) -> Term {
    if bin.is_null() {
        return enif_make_badarg(e);
    };
    // SAFETY: The NIF caller retains live term heaps and provides ABI-valid storage.
    let b = unsafe { &mut *bin };
    if b.data.is_null() && b.size > 0 {
        return enif_make_badarg(e);
    };
    // Port of erts/emulator/beam/erl_nif.c:1698 (enif_make_binary), OTP-29.1.1.
    // A zero-length NIF binary may legally carry a null data pointer.
    let data = if b.data.is_null() {
        ptr::NonNull::<u8>::dangling().as_ptr()
    } else {
        b.data
    };
    // SAFETY: The NIF caller retains live term heaps and provides ABI-valid storage.
    let bytes = unsafe { std::slice::from_raw_parts(data, b.size) };
    let result = built(env(e), |builder| builder.binary(bytes));
    if !b.ref_bin.is_null() {
        let allocations = &mut env(e).owned_binary_allocations;
        if !allocations.contains(&(b.data as usize)) {
            allocations.push(b.data as usize);
        }
        b.ref_bin = ptr::null_mut();
    };
    result
}
#[unsafe(no_mangle)]
pub extern "C" fn enif_make_new_binary(e: *mut ErlNifEnv, size: usize, out: *mut Term) -> *mut u8 {
    if out.is_null() || size > isize::MAX as usize {
        return ptr::null_mut();
    };
    let zeros = vec![0u8; size];
    let result = built(env(e), |builder| {
        builder.writable_binary(&zeros, size * 8, size)
    });
    if bits(result) == 0 {
        return ptr::null_mut();
    };
    // SAFETY: The NIF caller retains live term heaps and provides ABI-valid storage.
    unsafe { *out = result };
    // SAFETY: writable_binary returns an exclusive, live owner held by the environment.
    unsafe { writable_bytes_mut(result) }.map_or(ptr::null_mut(), |b| b.as_mut_ptr())
}
#[unsafe(no_mangle)]
pub extern "C" fn enif_make_sub_binary(
    e: *mut ErlNifEnv,
    t: Term,
    pos: usize,
    size: usize,
) -> Term {
    let Some(start) = pos.checked_mul(8) else {
        return enif_make_badarg(e);
    };
    let Some(len) = size.checked_mul(8) else {
        return enif_make_badarg(e);
    };
    built(env(e), |b| b.sub_binary(t, start, len))
}
fn append_iolist(t: Term, out: &mut Vec<u8>) -> bool {
    if let Some(bytes) = binary_bytes(t) {
        out.extend_from_slice(bytes);
        return true;
    };
    if let Some(n) = t.as_small() {
        if let Ok(b) = u8::try_from(n) {
            out.push(b);
            return true;
        }
        return false;
    };
    if t == Term::NIL {
        return true;
    };
    let mut next = t;
    while let Some((head, tail)) =
        // SAFETY: The NIF caller retains live term heaps and provides ABI-valid storage.
        unsafe { next.cons_ref() }
    {
        if !append_iolist(head, out) {
            return false;
        };
        next = tail
    }
    next == Term::NIL
        || binary_bytes(next).is_some_and(|b| {
            out.extend_from_slice(b);
            true
        })
}
#[unsafe(no_mangle)]
pub extern "C" fn enif_inspect_iolist_as_binary(
    e: *mut ErlNifEnv,
    t: Term,
    out: *mut ErlNifBinary,
) -> c_int {
    if out.is_null() {
        return 0;
    };
    if enif_inspect_binary(e, t, out) == 1 {
        return 1;
    };
    let mut data = Vec::new();
    if !append_iolist(t, &mut data) {
        return 0;
    };
    let env = env(e);
    env.scratch.push(data);
    let b = env.scratch.last().unwrap();
    // SAFETY: The NIF caller retains live term heaps and provides ABI-valid storage.
    unsafe {
        *out = ErlNifBinary {
            size: b.len(),
            data: b.as_ptr().cast_mut(),
            ref_bin: ptr::null_mut(),
            spare: [ptr::null_mut(); 2],
        }
    };
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn enif_is_current_process_alive(e: *mut ErlNifEnv) -> c_int {
    // Port of erts/emulator/beam/erl_nif.c:2304 (enif_is_current_process_alive), OTP-29.1.1:
    // `!ERTS_PROC_IS_EXITING(c_p)`; a dirty NIF sees its process exit while it runs.
    if env(e).pid.is_none() {
        return 0;
    }
    let hook = crate::extras::hooks()
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
        .current_process_exiting;
    i32::from(!hook.is_some_and(|exiting| exiting()))
}
#[unsafe(no_mangle)]
pub extern "C" fn enif_self(e: *mut ErlNifEnv, out: *mut Term) -> *mut Term {
    let Some(pid) = env(e).pid else {
        return ptr::null_mut();
    };
    if out.is_null() {
        return ptr::null_mut();
    };
    // SAFETY: The NIF caller retains live term heaps and provides ABI-valid storage.
    unsafe { *out = pid };
    out
}
#[unsafe(no_mangle)]
pub extern "C" fn enif_get_local_pid(_: *mut ErlNifEnv, t: Term, out: *mut Term) -> c_int {
    if t.as_pid().is_none() || out.is_null() {
        return 0;
    };
    // SAFETY: The NIF caller retains live term heaps and provides ABI-valid storage.
    unsafe { *out = t };
    1
}
#[unsafe(no_mangle)]
pub extern "C" fn enif_set_pid_undefined(out: *mut Term) {
    if !out.is_null() {
        // SAFETY: The NIF caller retains live term heaps and provides ABI-valid storage.
        unsafe { *out = term(0) }
    }
}
#[unsafe(no_mangle)]
pub extern "C" fn enif_is_pid_undefined(pid: *const Term) -> c_int {
    i32::from(
        // SAFETY: The NIF caller retains live term heaps and provides ABI-valid storage.
        pid.is_null() || unsafe { bits(*pid) } == 0,
    )
}
#[unsafe(no_mangle)]
pub extern "C" fn enif_get_local_port(_: *mut ErlNifEnv, t: Term, out: *mut Term) -> c_int {
    if t.as_port().is_none() || out.is_null() {
        return 0;
    };
    // SAFETY: The NIF caller retains live term heaps and provides ABI-valid storage.
    unsafe { *out = t };
    1
}
#[unsafe(no_mangle)]
pub extern "C" fn enif_consume_timeslice(_: *mut ErlNifEnv, _: c_int) -> c_int {
    0
}
#[unsafe(no_mangle)]
pub extern "C" fn enif_schedule_nif(
    e: *mut ErlNifEnv,
    _name: *const c_char,
    flags: c_int,
    f: Option<unsafe extern "C" fn(*mut ErlNifEnv, c_int, *const Term) -> Term>,
    argc: c_int,
    argv: *const Term,
) -> Term {
    let Some(f) = f else {
        return enif_make_badarg(e);
    };
    // Port of erts/emulator/beam/erl_nif.c:3540 (enif_schedule_nif), OTP-29.1.1.
    // Flags other than 0 or a combination of the two dirty job bits raise badarg; a
    // combination of both selects the I/O pool (see `scheduler_class`).
    if argc < 0 || (argc > 0 && argv.is_null()) || !(0..=3).contains(&flags) || env(e).independent {
        return enif_make_badarg(e);
    };
    // SAFETY: NIF passes a live argument array whose terms remain on the bound heap.
    let args = if argc == 0 {
        Vec::new()
    } else {
        // SAFETY: a positive arity requires a live argument array.
        unsafe { std::slice::from_raw_parts(argv, argc as usize) }.to_vec()
    };
    env(e).scheduled = Some((f, flags, args));
    term(0)
}

#[unsafe(no_mangle)]
pub extern "C" fn enif_make_new_map(e: *mut ErlNifEnv) -> Term {
    built(env(e), |b| b.flatmap_from_pairs(&[]))
}
#[unsafe(no_mangle)]
pub extern "C" fn enif_get_map_size(_: *mut ErlNifEnv, t: Term, out: *mut usize) -> c_int {
    let Ok(size) = arinsal_maps::size(t) else {
        return 0;
    };
    if !out.is_null() {
        // SAFETY: The NIF caller retains live term heaps and provides ABI-valid storage.
        unsafe { *out = size }
    };
    1
}
#[unsafe(no_mangle)]
pub extern "C" fn enif_get_map_value(
    _: *mut ErlNifEnv,
    t: Term,
    key: Term,
    out: *mut Term,
) -> c_int {
    let Ok(Some(v)) = arinsal_maps::get(t, key) else {
        return 0;
    };
    if !out.is_null() {
        // SAFETY: The NIF caller retains live term heaps and provides ABI-valid storage.
        unsafe { *out = v }
    };
    1
}
#[unsafe(no_mangle)]
pub extern "C" fn enif_make_map_put(
    e: *mut ErlNifEnv,
    t: Term,
    key: Term,
    val: Term,
    out: *mut Term,
) -> c_int {
    let Ok(m) = arinsal_maps::put(t, key, val, &mut env(e).heap) else {
        return 0;
    };
    if !out.is_null() {
        // SAFETY: The NIF caller retains live term heaps and provides ABI-valid storage.
        unsafe { *out = m }
    };
    1
}
#[unsafe(no_mangle)]
pub extern "C" fn enif_make_map_update(
    e: *mut ErlNifEnv,
    t: Term,
    key: Term,
    val: Term,
    out: *mut Term,
) -> c_int {
    let Ok(m) = arinsal_maps::update(t, key, val, &mut env(e).heap) else {
        return 0;
    };
    if !out.is_null() {
        // SAFETY: The NIF caller retains live term heaps and provides ABI-valid storage.
        unsafe { *out = m }
    };
    1
}
#[unsafe(no_mangle)]
pub extern "C" fn enif_make_map_remove(
    e: *mut ErlNifEnv,
    t: Term,
    key: Term,
    out: *mut Term,
) -> c_int {
    let Ok(m) = arinsal_maps::remove(t, key, &mut env(e).heap) else {
        return 0;
    };
    if !out.is_null() {
        // SAFETY: The NIF caller retains live term heaps and provides ABI-valid storage.
        unsafe { *out = m }
    };
    1
}
#[unsafe(no_mangle)]
pub extern "C" fn enif_make_map_from_arrays(
    e: *mut ErlNifEnv,
    keys: *const Term,
    vals: *const Term,
    n: usize,
    out: *mut Term,
) -> c_int {
    if (keys.is_null() || vals.is_null()) && n > 0 {
        return 0;
    };
    // SAFETY: The NIF caller retains live term heaps and provides ABI-valid storage.
    let k = unsafe { std::slice::from_raw_parts(keys, n) };
    // SAFETY: The NIF caller retains live term heaps and provides ABI-valid storage.
    let v = unsafe { std::slice::from_raw_parts(vals, n) };
    let pairs: Vec<_> = k.iter().copied().zip(v.iter().copied()).collect();
    let Ok(m) = arinsal_maps::from_pairs(&pairs, &mut env(e).heap) else {
        return 0;
    };
    if !out.is_null() {
        // SAFETY: The NIF caller retains live term heaps and provides ABI-valid storage.
        unsafe { *out = m }
    };
    1
}

/// Keep each export reachable from the executable link graph.
pub(crate) fn retain_exports() {
    let exports: &[usize] = &[
        enif_priv_data as *const () as usize,
        enif_alloc as *const () as usize,
        enif_free as *const () as usize,
        enif_realloc as *const () as usize,
        enif_get_int as *const () as usize,
        enif_get_long as *const () as usize,
        enif_get_uint as *const () as usize,
        enif_get_ulong as *const () as usize,
        enif_make_int as *const () as usize,
        enif_make_long as *const () as usize,
        enif_make_uint as *const () as usize,
        enif_make_ulong as *const () as usize,
        enif_inspect_binary as *const () as usize,
        enif_get_list_cell as *const () as usize,
        enif_make_atom as *const () as usize,
        enif_make_badarg as *const () as usize,
        enif_get_tuple as *const () as usize,
        enif_alloc_binary as *const () as usize,
        enif_release_binary as *const () as usize,
        enif_make_binary as *const () as usize,
        enif_make_new_binary as *const () as usize,
        enif_make_list_cell as *const () as usize,
        enif_make_list_from_array as *const () as usize,
        enif_make_tuple_from_array as *const () as usize,
        enif_make_new_map as *const () as usize,
        enif_get_map_value as *const () as usize,
        enif_make_map_from_arrays as *const () as usize,
        enif_inspect_iolist_as_binary as *const () as usize,
        enif_make_copy as *const () as usize,
        enif_schedule_nif as *const () as usize,
        enif_raise_exception as *const () as usize,
    ];
    black_box(exports);
}

fn render_term(t: Term, out: &mut String, depth: usize) {
    use std::fmt::Write;
    if depth > 64 {
        out.push_str("...");
        return;
    }
    if let Some(n) = integer(t) {
        let _ = write!(out, "{n}");
        return;
    }
    if let Some(a) = atom_text(t) {
        out.push_str(a);
        return;
    }
    match t.classify() {
        TermKind::Nil => out.push_str("[]"),
        TermKind::Tuple => {
            out.push('{');
            // SAFETY: the NIF callback retains this tuple's heap while formatting.
            if let Some(v) = unsafe { t.tuple_ref() } {
                for (i, item) in v.iter().enumerate() {
                    if i > 0 {
                        out.push(',')
                    };
                    render_term(item, out, depth + 1);
                }
            }
            out.push('}');
        }
        TermKind::List => {
            out.push('[');
            // SAFETY: the NIF callback retains this list's heap while formatting.
            let mut iter = unsafe { ListIter::new(t) };
            let mut i = 0;
            for item in iter.by_ref() {
                if i > 0 {
                    out.push(',')
                };
                render_term(item, out, depth + 1);
                i += 1;
                if i >= 1024 {
                    out.push_str(",...");
                    break;
                }
            }
            if iter.tail() != Term::NIL {
                out.push('|');
                render_term(iter.tail(), out, depth + 1)
            }
            out.push(']');
        }
        TermKind::Bitstring => {
            if let Some(b) = binary_bytes(t) {
                out.push_str("<<");
                for (i, byte) in b.iter().enumerate() {
                    if i > 0 {
                        out.push(',')
                    };
                    let _ = write!(out, "{byte}");
                }
                out.push_str(">>")
            } else {
                out.push_str("<<...>>")
            }
        }
        _ => {
            let _ = write!(out, "{t:?}");
        }
    }
}
/// Format a live term for the C shim's `%T` conversion.
#[unsafe(no_mangle)]
pub extern "C" fn arinsal_nif_format_term(t: Term) -> *mut c_char {
    let mut s = String::new();
    render_term(t, &mut s, 0);
    std::ffi::CString::new(s).map_or(ptr::null_mut(), std::ffi::CString::into_raw)
}
/// Release a `%T` formatted string returned to the C shim.
#[unsafe(no_mangle)]
pub extern "C" fn arinsal_nif_free_formatted(p: *mut c_char) {
    if !p.is_null() {
        // SAFETY: arinsal_nif_format_term allocated this CString.
        unsafe {
            drop(std::ffi::CString::from_raw(p));
        }
    }
}
