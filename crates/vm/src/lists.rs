//! List cell construction and access.

use arinsal_term::Term;

#[inline(always)]
pub(super) fn split(list: Term) -> Option<(Term, Term)> {
    // SAFETY: The caller retains the source heap for this instruction.
    let bits = unsafe { list.raw_bits() };
    if bits & 3 != 1 {
        return None;
    }
    let ptr = (bits & !7) as *const u64;
    // SAFETY: The cons tag points to a live two-word cell.
    unsafe {
        Some((
            std::mem::transmute::<u64, Term>(*ptr),
            std::mem::transmute::<u64, Term>(*ptr.add(1)),
        ))
    }
}
