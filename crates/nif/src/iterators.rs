//! ErlNifMapIterator ABI over native map order.
use crate::ErlNifEnv;
use crate::raw::{deref, deref_mut};
use arinsal_term::Term;
use std::hint::black_box;

/// Layout from OTP 29.1.1 erl_nif.h. The flat/hash union stores owned pairs.
#[repr(C)]
pub struct ErlNifMapIterator {
    map: Term,
    size: usize,
    idx: usize,
    entries: *mut Vec<(Term, Term)>,
    unused_union: usize,
    spare: [usize; 2],
}
#[unsafe(no_mangle)]
pub extern "C" fn enif_map_iterator_create(
    _: *mut ErlNifEnv,
    map: Term,
    out: *mut ErlNifMapIterator,
    entry: i32,
) -> i32 {
    if out.is_null() || !matches!(entry, 1 | 2) {
        return 0;
    };
    let Ok(entries) = arinsal_maps::to_list(map) else {
        return 0;
    };
    let size = entries.len();
    // SAFETY: the C caller provides a full ErlNifMapIterator output buffer.
    unsafe {
        *out = ErlNifMapIterator {
            map,
            size,
            idx: if size == 0 {
                0
            } else if entry == 1 {
                1
            } else {
                size
            },
            entries: Box::into_raw(Box::new(entries)),
            unused_union: 0,
            spare: [0; 2],
        }
    };
    1
}
#[unsafe(no_mangle)]
pub extern "C" fn enif_map_iterator_destroy(_: *mut ErlNifEnv, iter: *mut ErlNifMapIterator) {
    if iter.is_null() {
        return;
    };
    // SAFETY: The iterator remains live until its destroy call.
    let p = unsafe { (*iter).entries };
    if !p.is_null() {
        // SAFETY: create allocated this vector and destroy is called once.
        unsafe {
            drop(Box::from_raw(p));
            (*iter).entries = std::ptr::null_mut()
        };
    }
}
#[unsafe(no_mangle)]
pub extern "C" fn enif_map_iterator_is_head(
    _: *mut ErlNifEnv,
    iter: *mut ErlNifMapIterator,
) -> i32 {
    if iter.is_null() {
        return 0;
    };
    // SAFETY: The iterator remains live until its destroy call.
    i32::from(unsafe { (*iter).idx == 0 || (*iter).size == 0 })
}
#[unsafe(no_mangle)]
pub extern "C" fn enif_map_iterator_is_tail(
    _: *mut ErlNifEnv,
    iter: *mut ErlNifMapIterator,
) -> i32 {
    if iter.is_null() {
        return 0;
    };
    // SAFETY: The iterator remains live until its destroy call.
    i32::from(unsafe { (*iter).idx > (*iter).size || (*iter).size == 0 })
}
#[unsafe(no_mangle)]
pub extern "C" fn enif_map_iterator_next(_: *mut ErlNifEnv, iter: *mut ErlNifMapIterator) -> i32 {
    if iter.is_null() {
        return 0;
    };
    // SAFETY: The iterator remains live until its destroy call.
    let it = deref_mut(iter);
    if it.idx <= it.size {
        it.idx += 1
    };
    i32::from(it.idx <= it.size)
}
#[unsafe(no_mangle)]
pub extern "C" fn enif_map_iterator_prev(_: *mut ErlNifEnv, iter: *mut ErlNifMapIterator) -> i32 {
    if iter.is_null() {
        return 0;
    };
    // SAFETY: The iterator remains live until its destroy call.
    let it = deref_mut(iter);
    if it.idx > 0 {
        it.idx -= 1
    };
    i32::from(it.idx > 0)
}
#[unsafe(no_mangle)]
pub extern "C" fn enif_map_iterator_get_pair(
    _: *mut ErlNifEnv,
    iter: *mut ErlNifMapIterator,
    key: *mut Term,
    value: *mut Term,
) -> i32 {
    if iter.is_null() || key.is_null() || value.is_null() {
        return 0;
    };
    // SAFETY: The iterator remains live until its destroy call.
    let it = deref(iter);
    if it.idx == 0 || it.idx > it.size {
        return 0;
    };
    // SAFETY: The iterator remains live until its destroy call.
    let entries = unsafe { &*it.entries };
    let (k, v) = entries[it.idx - 1];
    // SAFETY: The iterator remains live until its destroy call.
    unsafe {
        *key = k;
        *value = v
    };
    1
}
pub(crate) fn retain_exports() {
    black_box(enif_map_iterator_create as *const ());
}
