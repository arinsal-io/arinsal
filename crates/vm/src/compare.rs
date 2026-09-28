//! Comparisons on decoded register and immediate operands.

use arinsal_term::{Term, cmp, exact_eq, loose_eq};

#[cold]
#[inline(never)]
fn slow_lt(a: Term, b: Term) -> bool {
    cmp(a, b).is_lt()
}

#[cold]
#[inline(never)]
fn slow_eq(a: Term, b: Term) -> bool {
    loose_eq(a, b)
}

#[cold]
#[inline(never)]
fn slow_exact_eq(a: Term, b: Term) -> bool {
    exact_eq(a, b)
}

#[inline(always)]
pub(super) fn lt(a: Term, b: Term) -> bool {
    match (a.as_small(), b.as_small()) {
        (Some(a), Some(b)) => a < b,
        _ => slow_lt(a, b),
    }
}

#[inline(always)]
pub(super) fn ge(a: Term, b: Term) -> bool {
    !lt(a, b)
}

#[inline(always)]
pub(super) fn eq(a: Term, b: Term) -> bool {
    a == b || slow_eq(a, b)
}

#[inline(always)]
pub(super) fn ne(a: Term, b: Term) -> bool {
    !eq(a, b)
}

#[inline(always)]
pub(super) fn eq_exact(a: Term, b: Term) -> bool {
    a == b || slow_exact_eq(a, b)
}

#[inline(always)]
pub(super) fn ne_exact(a: Term, b: Term) -> bool {
    !eq_exact(a, b)
}
