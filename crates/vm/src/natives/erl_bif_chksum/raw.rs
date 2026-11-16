//! Port of erts/emulator/beam/erl_bif_chksum.c: raw term and zlib access for checksum BIFs.

use arinsal_term::Term;

/// `CAR` and `CDR` of a live process term.
// Port of erts/emulator/beam/erl_term.h (CAR, CDR), OTP-29.1.1.
pub(super) fn cons_cell(term: Term) -> Option<(Term, Term)> {
    // SAFETY: checksum arguments and all list elements remain on the active process heap for the
    // duration of the BIF call; the walker never stores a borrowed view past that call.
    unsafe { term.cons_ref() }
}

/// Feed the chunk through `adler32` / `crc32`, preserving zlib's running checksum.
// Port of erts/emulator/beam/erl_bif_chksum.c (adler32_wrap, crc32_wrap), OTP-29.1.1.
pub(super) fn zlib_sum(
    adler: bool,
    mut value: std::ffi::c_ulong,
    bytes: &[u8],
) -> std::ffi::c_ulong {
    for chunk in bytes.chunks(u32::MAX as usize) {
        // SAFETY: `chunk` remains readable through the call, and zlib does not retain its pointer.
        value = unsafe {
            if adler {
                libz_sys::adler32(value, chunk.as_ptr(), chunk.len() as u32)
            } else {
                libz_sys::crc32(value, chunk.as_ptr(), chunk.len() as u32)
            }
        };
    }
    value
}

/// Combine two zlib checksums.
// Port of erts/emulator/beam/erl_bif_chksum.c (crc32_combine_3, adler32_combine_3), OTP-29.1.1.
pub(super) fn zlib_combine(adler: bool, a: u32, b: u32, length: u32) -> std::ffi::c_ulong {
    if adler && length == 0 {
        return a.into();
    }
    // SAFETY: zlib receives integer values only and retains no pointers.
    unsafe {
        if adler {
            libz_sys::adler32_combine(a.into(), b.into(), length.into())
        } else {
            libz_sys::crc32_combine(a.into(), b.into(), length.into())
        }
    }
}
