//! Checked raw-term access needed by native BIF bodies.
//!
//! Port of erts/emulator/beam/erl_term.h (typed term accessors), OTP-29.1.1. Heap terms passed
//! here are live in the running process and stay unmoved until the accessor returns.

use arinsal_term::{FunRef, Term};
use num_bigint::BigInt;

/// The integer represented by a small integer or live bignum.
pub(crate) fn integer(term: Term) -> Option<BigInt> {
    if let Some(value) = term.as_small() {
        return Some(BigInt::from(value));
    }
    big_integer(term)
}

fn big_integer(term: Term) -> Option<BigInt> {
    // SAFETY: BIF arguments are rooted in the running process heap for the whole call.
    unsafe { term.big_ref() }.map(|value| value.to_bigint())
}

/// The IEEE 754 value of a live float term.
pub(crate) fn float(term: Term) -> Option<f64> {
    // SAFETY: BIF arguments are rooted in the running process heap for the whole call.
    unsafe { term.float_ref() }.map(|value| value.get())
}

/// Arity of a local or exported function term.
pub(crate) fn fun_arity(term: Term) -> Option<u8> {
    // SAFETY: the term and any local fun entry remain live for the whole BIF call.
    match unsafe { term.fun_ref() }? {
        FunRef::Local { entry, .. } => Some(entry.arity),
        FunRef::Export { entry } => Some(entry.arity()),
    }
}
