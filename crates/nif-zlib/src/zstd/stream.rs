//! `compress_stream_nif` and `decompress_stream_nif`, with their shared worker `codec_nif`.
//!
//! The data argument is read in place (`enif_inspect_binary`, see [`inspect_binary`]) and the
//! unconsumed rest of it is returned as a sub-binary of the argument, not as a copy. There is
//! one output buffer per call; the Erlang side (`zstd.erl`) loops until zstd reports `done`.

use arinsal_bifs::{BifError, Ctx};
use arinsal_term::{Term, TermBuilder, TermError};
use zstd_sys as z;

use super::{CtxState, Kind, atom_term, get_int, get_zstd_context, is_error, zstd_error};
use crate::Heap;

/// `ZSTD_CONTENTSIZE_UNKNOWN` and `ZSTD_CONTENTSIZE_ERROR`.
const CONTENTSIZE_UNKNOWN: u64 = u64::MAX;
const CONTENTSIZE_ERROR: u64 = u64::MAX - 1;

/// `BYTES_PER_REDUCTION` of zstd_nif.c.
const BYTES_PER_REDUCTION: usize = 1024;

/// `CONTEXT_REDS`: the reductions of one time slice.
const CONTEXT_REDS: usize = 4000;

unsafe extern "C" {
    /// `ZSTD_compressStream2` with the end directive as the plain `int` the NIF receives, which
    /// zstd rejects when it is not one of its directives.
    #[link_name = "ZSTD_compressStream2"]
    fn compress_stream_any(
        ctx: *mut z::ZSTD_CCtx,
        output: *mut z::ZSTD_outBuffer,
        input: *mut z::ZSTD_inBuffer,
        directive: i32,
    ) -> usize;
}

/// `enif_inspect_binary`: the bytes of a whole-byte bitstring, `None` for any other term.
///
/// A binary that starts on a byte boundary is borrowed in place. One that does not is copied
/// into `scratch` and the copy is returned.
pub(crate) fn inspect_binary(term: Term, scratch: &mut Vec<u8>) -> Option<&[u8]> {
    // SAFETY: `term` is an argument of the running NIF call; its heap and the owner of its
    // bytes stay live and unmoved until the call returns, and no writable append runs
    // while the call borrows it.
    let view = unsafe { term.binary_ref() }?;
    if view.bit_len() % 8 != 0 {
        return None;
    }
    let start_bit = view.start_bit();
    let size = view.bit_len() / 8;
    let first = start_bit / 8;
    if start_bit % 8 == 0 {
        return Some(&view.bytes()[first..first + size]);
    }
    let shift = start_bit % 8;
    let source = view.bytes();
    scratch.clear();
    scratch.extend((0..size).map(|index| {
        let high = source[first + index] << shift;
        let low = source
            .get(first + index + 1)
            .map_or(0, |next| next >> (8 - shift));
        high | low
    }));
    Some(scratch.as_slice())
}

/// `ZSTD_CStreamOutSize()` or `ZSTD_DStreamOutSize()`: the output buffer of one call.
fn stream_out_size(kind: Kind) -> usize {
    // SAFETY: the size functions have no preconditions.
    unsafe {
        match kind {
            Kind::Compress => z::ZSTD_CStreamOutSize(),
            Kind::Decompress => z::ZSTD_DStreamOutSize(),
        }
    }
}

/// The reductions `enif_consume_timeslice(env, percent)` charges.
fn timeslice_reductions(percent: usize) -> usize {
    CONTEXT_REDS.div_ceil(100) * percent.clamp(1, 100)
}

/// `codec_nif`: run the codec over `input` until it is consumed or the one output buffer of
/// `chunk_size` bytes is full, and build the result.
fn codec_nif(
    ctx: &mut Ctx<'_>,
    state: &mut CtxState,
    kind: Kind,
    input_term: Term,
    flush_term: Term,
    chunk_size: usize,
) -> Result<Term, BifError> {
    let flush = get_int(flush_term).ok_or(BifError::BADARG)?;
    let mut scratch = Vec::new();
    let input = inspect_binary(input_term, &mut scratch).ok_or(BifError::BADARG)?;
    let mut output = Vec::new();
    output
        .try_reserve_exact(chunk_size)
        .map_err(|_| BifError::BADARG)?;
    output.resize(chunk_size, 0u8);

    let mut out_buffer = z::ZSTD_outBuffer {
        dst: output.as_mut_ptr().cast(),
        size: output.len(),
        pos: 0,
    };
    let mut in_buffer = z::ZSTD_inBuffer {
        src: input.as_ptr().cast(),
        size: input.len(),
        pos: 0,
    };
    let mut remaining;
    loop {
        // SAFETY: the context is open and of `kind`, and both buffers describe live memory.
        remaining = unsafe {
            match kind {
                Kind::Compress => {
                    compress_stream_any(state.ptr.cast(), &mut out_buffer, &mut in_buffer, flush)
                }
                Kind::Decompress => {
                    z::ZSTD_decompressStream(state.ptr.cast(), &mut out_buffer, &mut in_buffer)
                }
            }
        };
        if is_error(remaining) {
            return Err(zstd_error(ctx, remaining));
        }
        if in_buffer.pos >= in_buffer.size || out_buffer.pos >= out_buffer.size {
            break;
        }
    }
    let output_full = out_buffer.pos == out_buffer.size;
    let (in_pos, in_size) = (in_buffer.pos, in_buffer.size);
    output.truncate(out_buffer.pos);

    ctx.charge_reductions(timeslice_reductions(in_pos / BYTES_PER_REDUCTION));

    let mut heap = Heap(&mut ctx.heap);
    let mut builder = TermBuilder::new(&mut heap);
    let output = builder.binary(&output).map_err(system_limit)?;
    if flush != 0 && in_pos == in_size {
        let tag = if output_full && remaining > 0 {
            "flush"
        } else {
            "done"
        };
        return builder
            .tuple(&[atom_term(tag)?, output])
            .map_err(system_limit);
    }
    if in_pos < in_size {
        let rest = builder
            .sub_binary_bif(input_term, in_pos * 8, (in_size - in_pos) * 8)
            .map_err(system_limit)?;
        builder
            .tuple(&[atom_term("continue")?, rest, output])
            .map_err(system_limit)
    } else {
        builder
            .tuple(&[atom_term("continue")?, output])
            .map_err(system_limit)
    }
}

fn system_limit(_: TermError) -> BifError {
    BifError::SystemLimit
}

/// Port of compress_stream_nif (zstd_nif.c).
pub(super) fn compress_stream_nif(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    let context = get_zstd_context(args[0], Kind::Compress)?;
    let mut state = context.lock();
    let chunk_size = stream_out_size(Kind::Compress);
    let result = codec_nif(
        ctx,
        &mut state,
        Kind::Compress,
        args[1],
        args[2],
        chunk_size,
    );
    if result.is_err() {
        state.reset(Kind::Compress);
    }
    result
}

/// Port of decompress_stream_nif (zstd_nif.c).
pub(super) fn decompress_stream_nif(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    let context = get_zstd_context(args[0], Kind::Decompress)?;
    let mut state = context.lock();
    let mut chunk_size = stream_out_size(Kind::Decompress);

    if !state.in_use {
        let mut scratch = Vec::new();
        let bin = inspect_binary(args[1], &mut scratch).ok_or(BifError::BADARG)?;

        if bin.is_empty() && args[2] == atom_term("true")? {
            let mut heap = Heap(&mut ctx.heap);
            let mut builder = TermBuilder::new(&mut heap);
            let output = builder.binary(bin).map_err(system_limit)?;
            return builder
                .tuple(&[atom_term("done")?, output])
                .map_err(system_limit);
        }

        // SAFETY: `bin` describes live memory.
        let decompressed_size =
            unsafe { z::ZSTD_findDecompressedSize(bin.as_ptr().cast(), bin.len()) };
        if decompressed_size != CONTENTSIZE_UNKNOWN
            && decompressed_size != CONTENTSIZE_ERROR
            && decompressed_size < chunk_size as u64
        {
            chunk_size = decompressed_size as usize;
        }
        state.in_use = true;
    }

    let result = codec_nif(
        ctx,
        &mut state,
        Kind::Decompress,
        args[1],
        args[2],
        chunk_size,
    );
    if result.is_err() {
        state.reset(Kind::Decompress);
    }
    result
}

#[cfg(test)]
mod tests {
    use arinsal_bifs::ProcessHeapHandle;
    use arinsal_term::{ProcessHeap, Term, TermBuilder};

    use super::{inspect_binary, timeslice_reductions};

    #[test]
    fn timeslice_reductions_match_enif_consume_timeslice() {
        assert_eq!(timeslice_reductions(0), 40);
        assert_eq!(timeslice_reductions(1), 40);
        assert_eq!(timeslice_reductions(50), 2000);
        assert_eq!(timeslice_reductions(100), 4000);
        assert_eq!(timeslice_reductions(5000), 4000);
    }

    fn with_builder<T>(f: impl FnOnce(&mut TermBuilder<'_, ProcessHeapHandle<'_>>) -> T) -> T {
        let mut heap = ProcessHeap::with_words(1 << 16);
        let mut handle = ProcessHeapHandle(&mut heap);
        f(&mut TermBuilder::new(&mut handle))
    }

    fn pattern(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i * 7 + 3) as u8).collect()
    }

    #[test]
    fn inspect_binary_reads_aligned_binaries_in_place() {
        with_builder(|builder| {
            for len in [0, 10, 64, 65, 1000] {
                let bytes = pattern(len);
                let term = builder.binary(&bytes).unwrap();
                let mut scratch = Vec::new();
                let view = inspect_binary(term, &mut scratch).unwrap();
                assert_eq!(view, bytes.as_slice());
                assert_eq!(scratch.capacity(), 0, "len {len} was copied");
            }
        });
    }

    #[test]
    fn inspect_binary_reads_an_aligned_sub_binary_in_place() {
        with_builder(|builder| {
            let bytes = pattern(400);
            let whole = builder.binary(&bytes).unwrap();
            let part = builder.sub_binary_bif(whole, 100 * 8, 200 * 8).unwrap();
            let mut scratch = Vec::new();
            let view = inspect_binary(part, &mut scratch).unwrap();
            assert_eq!(view, &bytes[100..300]);
            assert_eq!(scratch.capacity(), 0);
        });
    }

    #[test]
    fn inspect_binary_copies_an_unaligned_sub_binary() {
        with_builder(|builder| {
            let bytes = pattern(400);
            let whole = builder.binary(&bytes).unwrap();
            for shift in 1..8 {
                let part = builder.sub_binary_bif(whole, shift, 300 * 8).unwrap();
                let mut scratch = Vec::new();
                let view = inspect_binary(part, &mut scratch).unwrap().to_vec();
                let expected: Vec<u8> = (0..300)
                    .map(|i| (bytes[i] << shift) | (bytes[i + 1] >> (8 - shift)))
                    .collect();
                assert_eq!(view, expected, "shift {shift}");
                assert_eq!(scratch, expected);
            }
        });
    }

    #[test]
    fn inspect_binary_rejects_other_terms() {
        with_builder(|builder| {
            let bytes = pattern(100);
            let bits = builder.bitstring(&bytes, 100 * 8 - 3).unwrap();
            let tuple = builder.tuple(&[Term::NIL]).unwrap();
            let mut scratch = Vec::new();
            for term in [bits, tuple, Term::NIL, Term::small(7).unwrap()] {
                assert!(inspect_binary(term, &mut scratch).is_none());
            }
        });
    }
}
