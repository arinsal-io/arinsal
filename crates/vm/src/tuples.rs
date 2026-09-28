//! Tuple access on decoded register operands.

use arinsal_term::Term;

/// Write a pair into three words reserved by the interpreter cursor.
#[inline(always)]
pub(super) fn pair(ptr: *mut u64, a: Term, b: Term) -> Term {
    // SAFETY: The caller reserved the arity header and both elements.
    unsafe {
        *ptr = 2 << 6;
        *ptr.add(1) = a.raw_bits();
        *ptr.add(2) = b.raw_bits();
        std::mem::transmute::<u64, Term>((ptr as u64) | 2)
    }
}

#[inline(always)]
pub(super) fn element(tuple: Term, index: usize) -> Option<Term> {
    // SAFETY: The caller retains the tuple's heap throughout this instruction.
    let bits = unsafe { tuple.raw_bits() };
    if bits & 3 != 2 {
        return None;
    }
    let ptr = (bits & !7) as *const u64;
    // SAFETY: A boxed term has a live header; the arity bounds its elements.
    unsafe {
        let header = *ptr;
        if header & 63 != 0 || index >= (header >> 6) as usize {
            return None;
        }
        Some(std::mem::transmute::<u64, Term>(*ptr.add(index + 1)))
    }
}
