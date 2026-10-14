//! Checked views of the raw pointers and terms a NIF passes through the C ABI.
//!
//! Each helper holds the one `unsafe` block for its pattern, with the contract of the NIF API
//! as its safety argument, so call sites stay free of repeated blocks.
use arinsal_term::{BinaryRef, FloatRef, ListIter, Term, TupleRef};
use std::ffi::{CStr, c_char};

/// A shared reference to the object behind a pointer the NIF API contract makes valid.
pub(crate) fn deref<'a, T>(p: *const T) -> &'a T {
    // SAFETY: NIF API calls take live objects; the reference does not outlive the call.
    unsafe { &*p }
}

/// An exclusive reference to the object behind a pointer the NIF API contract makes valid.
pub(crate) fn deref_mut<'a, T>(p: *mut T) -> &'a mut T {
    // SAFETY: NIF API calls take live objects; the reference does not outlive the call.
    unsafe { &mut *p }
}

/// The NUL-terminated string a NIF passed.
pub(crate) fn cstr<'a>(p: *const c_char) -> &'a CStr {
    // SAFETY: the NIF passes a NUL-terminated string valid for the call.
    unsafe { CStr::from_ptr(p) }
}

/// The `n` elements a NIF passed at `p`.
pub(crate) fn slice<'a, T>(p: *const T, n: usize) -> &'a [T] {
    // SAFETY: the NIF passes `n` readable elements valid for the call.
    unsafe { std::slice::from_raw_parts(p, n) }
}

/// Head and tail of a list cell. The term's heap is live throughout the NIF call.
pub(crate) fn cons(t: Term) -> Option<(Term, Term)> {
    // SAFETY: the term's heap stays live and unmoved for the NIF call.
    unsafe { t.cons_ref() }
}

/// Iterator over the cells of a list term. The term's heap is live throughout the NIF call.
pub(crate) fn list_iter(t: Term) -> ListIter {
    // SAFETY: the term's heap stays live and unmoved for the NIF call.
    unsafe { ListIter::new(t) }
}

/// View of a bitstring term. The term's heap is live throughout the NIF call.
pub(crate) fn binary_view<'a>(t: Term) -> Option<BinaryRef<'a>> {
    // SAFETY: the term's heap and owner stay live and unmoved for the NIF call.
    unsafe { t.binary_ref() }
}

/// View of a float term. The term's heap is live throughout the NIF call.
pub(crate) fn float_view<'a>(t: Term) -> Option<FloatRef<'a>> {
    // SAFETY: the term's heap stays live and unmoved for the NIF call.
    unsafe { t.float_ref() }
}

/// View of a tuple term. The term's heap is live throughout the NIF call.
pub(crate) fn tuple_view<'a>(t: Term) -> Option<TupleRef<'a>> {
    // SAFETY: the term's heap stays live and unmoved for the NIF call.
    unsafe { t.tuple_ref() }
}
