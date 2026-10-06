//! Unboxed float register helpers.

use arinsal_term::Term;

/// Write a finite float into two words reserved by the interpreter cursor.
#[inline(always)]
pub(super) fn box_float(ptr: *mut u64, value: f64) -> Term {
    // SAFETY: The caller reserved the header and one float payload word.
    unsafe {
        *ptr = (1 << 6) | 0x18;
        *ptr.add(1) = value.to_bits();
        std::mem::transmute::<u64, Term>((ptr as u64) | 2)
    }
}

#[inline(always)]
pub(super) fn number(term: Term) -> Option<f64> {
    arinsal_arith::number_to_f64(term).ok()
}
