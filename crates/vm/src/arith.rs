//! Numeric fast paths for decoded arithmetic instructions.

use arinsal_loader::FastBif;
use arinsal_term::{Term, small_add, small_mul, small_sub};

/// Tagged small arithmetic; a miss goes to the bound BIF.
#[inline(always)]
pub(super) fn small(kind: FastBif, a: Term, b: Term) -> Option<Term> {
    match kind {
        FastBif::Add => small_add(a, b),
        FastBif::Sub => small_sub(a, b),
        FastBif::Mul => small_mul(a, b),
        FastBif::None => None,
    }
}
