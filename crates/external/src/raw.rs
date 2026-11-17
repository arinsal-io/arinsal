//! Pointer writes for the final, pre-sized ETF output buffer.
//!
//! Port of erts/emulator/beam/external.c (`enc_term_int`), OTP-29.1.1. The size pass computed
//! the required output length before `enc_term_int` writes through its byte pointer.

#[inline(always)]
pub(crate) fn write_byte_validated(output: &mut [u8], at: usize, value: u8) {
    debug_assert!(at < output.len());
    // SAFETY: the encode-size pass reserved the full output and the encoder cursor stays in it.
    unsafe { output.as_mut_ptr().add(at).write(value) }
}

#[inline(always)]
pub(crate) fn write_validated(output: &mut [u8], at: usize, bytes: &[u8]) {
    debug_assert!(at <= output.len() && bytes.len() <= output.len() - at);
    // SAFETY: the encode-size pass reserved this range; immutable source bytes cannot alias the
    // exclusively borrowed destination slice.
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), output.as_mut_ptr().add(at), bytes.len())
    }
}

#[inline(always)]
pub(crate) fn zero_validated(output: &mut [u8], at: usize, len: usize) {
    debug_assert!(at <= output.len() && len <= output.len() - at);
    // SAFETY: the encode-size pass reserved this range in the final output buffer.
    unsafe { std::ptr::write_bytes(output.as_mut_ptr().add(at), 0, len) }
}

#[inline(always)]
pub(crate) fn mask_validated(output: &mut [u8], at: usize, mask: u8) {
    debug_assert!(at < output.len());
    // SAFETY: the encoder masks the final byte it has just written inside the reserved output.
    unsafe {
        let byte = output.as_mut_ptr().add(at);
        byte.write(byte.read() & mask);
    }
}
