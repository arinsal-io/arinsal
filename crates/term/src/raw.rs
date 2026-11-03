//! Raw heap word access for the collector: the one place where `crates/term` code that
//! moves objects dereferences a heap address. Callers pass addresses, never references, and
//! uphold the contract of each primitive.

/// Reads the word at `address`.
///
/// Contract: `address` is word-aligned and names an initialized word of a live heap block,
/// heap fragment or reserved destination that the calling collection owns.
#[inline(always)]
pub(crate) fn load(address: usize) -> u64 {
    // SAFETY: the contract above; the collector has exclusive access to the process heap.
    unsafe { *(address as *const u64) }
}

/// Writes `value` to the word at `address`.
///
/// Contract: `address` is word-aligned and inside a live heap block, heap fragment or
/// destination range the calling collection owns exclusively, with no live Rust reference
/// to the word.
#[inline(always)]
pub(crate) fn store(address: usize, value: u64) {
    // SAFETY: the contract above.
    unsafe { *(address as *mut u64) = value }
}

/// Copies `words` words from `src` to `dst`.
///
/// Contract: both ranges are word-aligned, inside owned live blocks, readable respectively
/// writable for `words` words, and do not overlap.
#[inline(always)]
pub(crate) fn copy_words(src: usize, dst: usize, words: usize) {
    // SAFETY: the contract above.
    unsafe { std::ptr::copy_nonoverlapping(src as *const u64, dst as *mut u64, words) }
}

/// Words of the boxed object with header `header` at `address` (header word included).
///
/// Contract: `address` names a live boxed object of an owned heap block or fragment with
/// its complete payload initialized (see `hamt::boxed_object_words`).
#[inline(always)]
pub(crate) fn boxed_words(header: u64, address: usize) -> usize {
    // SAFETY: the contract above.
    unsafe { crate::hamt::boxed_object_words(header, address as *const u64) }
}
