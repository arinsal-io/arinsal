//! Bitstring helpers of `erl_bits.c` that the encoders share.
use crate::Term;
use crate::raw::BinRef;

/// The range does not fit the bitstring or the output.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BadRange;

/// `bitstring_size`: the bit length of a bitstring term, `None` for any other term.
// Port of erts/emulator/beam/erl_bits.h (bitstring_size), OTP-29.1.1.
#[inline]
pub fn bitstring_bit_len(term: Term) -> Option<usize> {
    BinRef::try_from(term).ok().map(BinRef::bit_len)
}

/// Copy `bit_count` bits of `term` from bit `start` into `output`, most significant bit first,
/// zero-filling the rest of `output`.
// Port of erts/emulator/beam/erl_bits.c (erts_copy_bits_fwd), OTP-29.1.1.
pub fn copy_bitstring_range(
    term: Term,
    start: usize,
    output: &mut [u8],
    bit_count: usize,
) -> Result<(), BadRange> {
    let view = BinRef::try_from(term).map_err(|_| BadRange)?;
    let output_bits = output.len().checked_mul(8).ok_or(BadRange)?;
    if bit_count > output_bits
        || start
            .checked_add(bit_count)
            .is_none_or(|end| end > view.bit_len())
    {
        return Err(BadRange);
    }
    let source_start = view.start_bit().checked_add(start).ok_or(BadRange)?;
    let window = view.window();
    if source_start.is_multiple_of(8) && bit_count.is_multiple_of(8) {
        let from = source_start / 8;
        let byte_count = bit_count / 8;
        let source_end = from.checked_add(byte_count).ok_or(BadRange)?;
        output[..byte_count].copy_from_slice(window.get(from..source_end).ok_or(BadRange)?);
        output[byte_count..].fill(0);
    } else {
        output.fill(0);
        for index in 0..bit_count {
            let source = source_start + index;
            let bit = (window[source / 8] >> (7 - source % 8)) & 1;
            output[index / 8] |= bit << (7 - index % 8);
        }
    }
    Ok(())
}
