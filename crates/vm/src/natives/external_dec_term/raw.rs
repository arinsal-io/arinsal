//! Validated external-term reads corresponding to `dec_term`'s pointer cursor.
//!
//! Port of erts/emulator/beam/external.c (`dec_term`), OTP-29.1.1. The caller has completed
//! `decoded_size` over these bytes before constructing a `Reader`.

use super::super::external_dec_size::ValidatedBytes;
use arinsal_term::raw::HeapSlotPtr;

#[inline(always)]
pub(super) fn take_validated(bytes: ValidatedBytes<'_>, at: usize, len: usize) -> &[u8] {
    let bytes = bytes.as_slice();
    debug_assert!(at <= bytes.len() && len <= bytes.len() - at);
    // SAFETY: `decoded_size` checked each encoded length before `dec_term` reads the input.
    unsafe { std::slice::from_raw_parts(bytes.as_ptr().add(at), len) }
}

#[inline(always)]
pub(super) fn u8_validated(bytes: ValidatedBytes<'_>, at: usize) -> u8 {
    let bytes = bytes.as_slice();
    debug_assert!(at < bytes.len());
    // SAFETY: `decoded_size` verified the tag and its complete payload are in `bytes`.
    unsafe { bytes.as_ptr().add(at).read() }
}

#[inline(always)]
pub(super) fn u16_validated(bytes: ValidatedBytes<'_>, at: usize) -> u16 {
    let bytes = bytes.as_slice();
    debug_assert!(at <= bytes.len() && 2 <= bytes.len() - at);
    // SAFETY: `decoded_size` verified the length field and its payload are in `bytes`.
    unsafe { u16::from_be(bytes.as_ptr().add(at).cast::<u16>().read_unaligned()) }
}

#[inline(always)]
pub(super) fn u32_validated(bytes: ValidatedBytes<'_>, at: usize) -> u32 {
    let bytes = bytes.as_slice();
    debug_assert!(at <= bytes.len() && 4 <= bytes.len() - at);
    // SAFETY: `decoded_size` verified the length field and its payload are in `bytes`.
    unsafe { u32::from_be(bytes.as_ptr().add(at).cast::<u32>().read_unaligned()) }
}

#[inline(always)]
pub(super) fn u64_validated(bytes: ValidatedBytes<'_>, at: usize) -> u64 {
    let bytes = bytes.as_slice();
    debug_assert!(at <= bytes.len() && 8 <= bytes.len() - at);
    // SAFETY: `decoded_size` verified the length field and its payload are in `bytes`.
    unsafe { u64::from_be(bytes.as_ptr().add(at).cast::<u64>().read_unaligned()) }
}

#[inline(always)]
pub(super) fn copy_to_heap_payload(destination: HeapSlotPtr, source: &[u8]) {
    // SAFETY: `dec_term` reserved the heap-bits words for this payload. The input ETF bytes and
    // the newly reserved heap range are distinct, as for `sys_memcpy` in `dec_term`.
    unsafe {
        std::ptr::copy_nonoverlapping(
            source.as_ptr(),
            destination.as_ptr().cast::<u8>(),
            source.len(),
        )
    }
}
