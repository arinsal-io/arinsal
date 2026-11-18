//! Validated external-term reads corresponding to `dec_term`'s pointer cursor.
//!
//! Port of erts/emulator/beam/external.c (`dec_term`), OTP-29.1.1. The caller has completed
//! `decoded_size` over these bytes before constructing a `Reader`.

use super::super::external_dec_size::ValidatedBytes;
use arinsal_term::raw::HeapSlotPtr;

/// `dec_term`'s `ep`: a pointer into input that `decoded_size` validated, so a hot loop keeps
/// one register for the cursor as the C code does.
// Port of erts/emulator/beam/external.c (dec_term, `const byte *ep`), OTP-29.1.1.
#[derive(Clone, Copy)]
pub(super) struct Cursor<'a> {
    ptr: *const u8,
    _bytes: std::marker::PhantomData<&'a [u8]>,
}

impl<'a> Cursor<'a> {
    /// The cursor at offset `at` of validated input.
    #[inline(always)]
    pub(super) fn at(bytes: ValidatedBytes<'a>, at: usize) -> Self {
        let bytes = bytes.as_slice();
        debug_assert!(at <= bytes.len());
        // SAFETY: `at` is the offset of a term boundary inside the validated input (at most its
        // length), so the result stays in or one past the allocation.
        let ptr = unsafe { bytes.as_ptr().add(at) };
        Self {
            ptr,
            _bytes: std::marker::PhantomData,
        }
    }

    /// The offset of the cursor in `bytes`.
    #[inline(always)]
    pub(super) fn offset(self, bytes: ValidatedBytes<'a>) -> usize {
        (self.ptr as usize) - (bytes.as_slice().as_ptr() as usize)
    }

    /// Move the cursor back over a tag byte it just passed.
    #[inline(always)]
    pub(super) fn back(&mut self, n: usize) {
        self.ptr = self.ptr.wrapping_sub(n);
    }

    #[inline(always)]
    pub(super) fn skip(&mut self, n: usize) {
        self.ptr = self.ptr.wrapping_add(n);
    }

    #[inline(always)]
    pub(super) fn peek(self) -> u8 {
        // SAFETY: the caller reads a byte `decoded_size` verified to be in the input.
        unsafe { self.ptr.read() }
    }

    #[inline(always)]
    pub(super) fn take(&mut self, len: usize) -> &'a [u8] {
        // SAFETY: `decoded_size` checked each encoded length before `dec_term` reads the input.
        let part = unsafe { std::slice::from_raw_parts(self.ptr, len) };
        self.ptr = self.ptr.wrapping_add(len);
        part
    }

    #[inline(always)]
    pub(super) fn u8(&mut self) -> u8 {
        // SAFETY: `decoded_size` verified the tag and its complete payload are in the input.
        let value = unsafe { self.ptr.read() };
        self.ptr = self.ptr.wrapping_add(1);
        value
    }

    #[inline(always)]
    pub(super) fn u16(&mut self) -> u16 {
        // SAFETY: `decoded_size` verified the length field and its payload are in the input.
        let value = u16::from_be(unsafe { self.ptr.cast::<u16>().read_unaligned() });
        self.ptr = self.ptr.wrapping_add(2);
        value
    }

    #[inline(always)]
    pub(super) fn u32(&mut self) -> u32 {
        // SAFETY: `decoded_size` verified the length field and its payload are in the input.
        let value = u32::from_be(unsafe { self.ptr.cast::<u32>().read_unaligned() });
        self.ptr = self.ptr.wrapping_add(4);
        value
    }

    #[inline(always)]
    pub(super) fn u64(&mut self) -> u64 {
        // SAFETY: `decoded_size` verified the length field and its payload are in the input.
        let value = u64::from_be(unsafe { self.ptr.cast::<u64>().read_unaligned() });
        self.ptr = self.ptr.wrapping_add(8);
        value
    }
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
