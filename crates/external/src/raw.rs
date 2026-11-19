//! Pointer writes for the final, pre-sized ETF output buffer, and the Binary behind a
//! referenced dist payload.
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

/// The refc Binary that holds the payload of a byte-aligned off-heap bitstring and the
/// payload's byte offset in it, with one reference taken (`erts_refc_inc` of
/// `store_in_vec_aux`). `None` when the payload is not referenceable: on heap, not
/// byte-aligned, a NIF resource binary, or a binary still writable. The encoder pins the
/// term's writable binary first (`ERTS_PIN_BITSTRING`), so only a binary whose writer is not
/// this term stays writable.
// Port of erts/emulator/beam/external.c (enc_term_int, BITSTRING_DEF: ERTS_PIN_BITSTRING
// and `store_in_vec(ctx, ep, br->val, obj, base, BYTE_SIZE(size))`), OTP-29.1.1.
pub(crate) fn refc_payload(
    term: arinsal_term::Term,
) -> Option<(arinsal_alloc::raw::OwnedBinaryRef, usize)> {
    let arinsal_term::BinaryOwner::Binary(owner) = arinsal_term::binary_owner(term)? else {
        return None;
    };
    if owner.is_writable() {
        return None;
    }
    // SAFETY: the encoded term and its BinRef are live for the encode; the view does not
    // escape this function.
    let view = unsafe { term.binary_ref() }?;
    if !view.is_off_heap() || !view.start_bit().is_multiple_of(8) {
        return None;
    }
    let base = view.bytes().as_ptr() as usize + view.start_bit() / 8;
    let offset = base.checked_sub(owner.payload_ptr() as usize)?;
    Some((owner, offset))
}
