//! Raw access to ETF bytes already checked by `decoded_size`.

use arinsal_etf::ValidatedEtfBody;
use std::num::NonZeroUsize;

// Port of erts/emulator/beam/external.c:4308-5445 (`dec_term`), OTP-29.1.1.

/// Read a range whose tag and length were validated by `DecodedSizeWalk`.
#[inline(always)]
pub(super) fn take_validated(body: ValidatedEtfBody<'_>, at: usize, length: usize) -> &[u8] {
    let bytes = body.as_bytes();
    debug_assert!(at <= bytes.len());
    debug_assert!(length <= bytes.len() - at);
    // SAFETY: the sizing pass validated every ETF field boundary in this same byte slice;
    // `ValidatedEtfBody` binds the decoder to that slice and its checked term end.
    unsafe { std::slice::from_raw_parts(bytes.as_ptr().add(at), length) }
}

/// A slot address inside the heap reservation held by an active ETF decode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub(super) struct HeapSlotPtr(NonZeroUsize);

impl HeapSlotPtr {
    /// Retain an in-range heap slot as an address for the decoder's `next` chain.
    #[inline(always)]
    pub(super) fn at(words: &mut [u64], index: usize) -> Option<Self> {
        words
            .get_mut(index)
            .and_then(|word| NonZeroUsize::new(word as *mut u64 as usize).map(Self))
    }

    /// Return the address stored in a term word, as used by erts' `next` chain.
    #[inline(always)]
    pub(super) fn address(self) -> u64 {
        self.0.get() as u64
    }

    /// Clear this destination and take its chained child slot.
    #[inline(always)]
    pub(super) fn take_next(self) -> Option<Self> {
        // SAFETY: `HeapSlotPtr` is created from an in-range reserved heap word or from a
        // pointer previously stored in such a word. `DecodeWalk` retains the reservation
        // across yields, and a failed decode drops the cursor before factory rollback.
        let address = unsafe {
            let slot = self.0.get() as *mut u64;
            let address = *slot;
            *slot = 0;
            address
        };
        NonZeroUsize::new(address as usize).map(Self)
    }

    /// Store an encoded term or chain link in this destination word.
    #[inline(always)]
    pub(super) fn store(self, word: u64) {
        // SAFETY: this cursor points into the live reservation, which is retained until the
        // decode finishes or is rolled back after the cursor is discarded.
        unsafe { (self.0.get() as *mut u64).write(word) };
    }
}

/// Get a reserved word's index when a safe heap builder API requires an indexed handle.
#[inline(always)]
pub(super) fn slot_index(base: usize, length: usize, slot: HeapSlotPtr) -> Option<usize> {
    let offset = slot.0.get().checked_sub(base)?;
    if !offset.is_multiple_of(std::mem::size_of::<u64>()) {
        return None;
    }
    let index = offset / std::mem::size_of::<u64>();
    (index < length).then_some(index)
}

/// Encode a reserved heap word's address as erts stores it in `next` chains.
#[inline(always)]
pub(super) fn slot_address(base: usize, index: usize) -> u64 {
    base.wrapping_add(index * std::mem::size_of::<u64>()) as u64
}
