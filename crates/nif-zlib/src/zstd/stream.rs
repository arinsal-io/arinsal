//! `compress_stream_nif` and `decompress_stream_nif`.

use arinsal_bifs::{BifError, Ctx};
use arinsal_etf::OwnedTerm as O;
use arinsal_term::{Term, to_owned};
use zstd_sys as z;

use super::{CtxState, Kind, get_zstd_context, is_error, outcome, zstd_error};
use crate::{Fault, Outcome, atom, number, pair, tuple};

unsafe extern "C" {
    #[link_name = "ZSTD_compressStream2"]
    fn compress_stream_any(
        ctx: *mut z::ZSTD_CCtx,
        output: *mut z::ZSTD_outBuffer,
        input: *mut z::ZSTD_inBuffer,
        directive: i32,
    ) -> usize;
}

fn stream(state: &mut CtxState, kind: Kind, data: &O, flush: &O) -> Result<Outcome, usize> {
    let O::Binary(input) = data else {
        return Ok(Err(Fault::Badarg));
    };
    if kind == Kind::Decompress && !state.in_use && input.is_empty() && flush == &atom("true") {
        return Ok(Ok(pair(atom("done"), O::Binary(Vec::new()))));
    }
    let Ok(directive) = number(flush) else {
        return Ok(Err(Fault::Badarg));
    };
    // SAFETY: size functions have no preconditions.
    let mut out_len = unsafe {
        match kind {
            Kind::Compress => z::ZSTD_CStreamOutSize(),
            Kind::Decompress => z::ZSTD_DStreamOutSize(),
        }
    };
    if kind == Kind::Decompress && !state.in_use {
        // SAFETY: input's allocation remains live during this call.
        let size = unsafe { z::ZSTD_findDecompressedSize(input.as_ptr().cast(), input.len()) };
        if size < out_len as u64 {
            out_len = size as usize;
        }
        state.in_use = true;
    }
    let mut out = vec![0u8; out_len.max(1)];
    let mut ib = z::ZSTD_inBuffer {
        src: input.as_ptr().cast(),
        size: input.len(),
        pos: 0,
    };
    let mut ob = z::ZSTD_outBuffer {
        dst: out.as_mut_ptr().cast(),
        size: out_len,
        pos: 0,
    };
    let mut remaining;
    loop {
        // SAFETY: the context matches `kind`, is open, and both buffers remain live.
        let result = unsafe {
            match kind {
                Kind::Compress => {
                    compress_stream_any(state.ptr.cast(), &mut ob, &mut ib, directive)
                }
                Kind::Decompress => z::ZSTD_decompressStream(state.ptr.cast(), &mut ob, &mut ib),
            }
        };
        if is_error(result) {
            state.reset(kind);
            return Err(result);
        }
        remaining = result;
        if ib.pos >= ib.size || ob.pos >= ob.size {
            break;
        }
    }
    out.truncate(ob.pos);
    let output = O::Binary(out);
    Ok(Ok(if directive != 0 && ib.pos == ib.size {
        let tag = if ob.pos == ob.size && remaining > 0 {
            "flush"
        } else {
            "done"
        };
        pair(atom(tag), output)
    } else if ib.pos < ib.size {
        tuple(vec![
            atom("continue"),
            O::Binary(input[ib.pos..].to_vec()),
            output,
        ])
    } else {
        pair(atom("continue"), output)
    }))
}

fn stream_nif(ctx: &mut Ctx<'_>, args: &[Term], kind: Kind) -> Result<Term, BifError> {
    let context = get_zstd_context(args[0], kind)?;
    let data = to_owned(args[1]).map_err(|_| BifError::BADARG)?;
    let flush = to_owned(args[2]).map_err(|_| BifError::BADARG)?;
    let result = stream(&mut context.lock(), kind, &data, &flush);
    match result {
        Ok(result) => outcome(ctx, result),
        Err(code) => Err(zstd_error(ctx, code)),
    }
}

pub(super) fn compress_stream_nif(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    stream_nif(ctx, args, Kind::Compress)
}

pub(super) fn decompress_stream_nif(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    stream_nif(ctx, args, Kind::Decompress)
}
