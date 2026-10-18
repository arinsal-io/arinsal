//! Context lifecycle NIFs of zstd_nif.c: `init_*`, `*_reset`, `*_close`, and
//! `set_pledged_src_size_nif`.

use std::ffi::c_void;
use std::sync::Mutex;

use arinsal_bifs::{BifError, Ctx};
use arinsal_term::Term;
use zstd_sys as z;

use super::{
    CtxBox, CtxState, Kind, ZSTD_CTX_MAGIC_ORIG_SIZE, atom_term, get_uint64, get_zstd_context,
    is_error, make_resource, zstd_error,
};
use crate::caller;

/// `init_compress_nif` / `init_decompress_nif`: a resource owned by the calling process.
/// When zstd cannot allocate the context the resource is still returned, closed from the
/// start, and every later call on it raises `badarg`.
fn init(ctx: &mut Ctx<'_>, kind: Kind) -> Result<Term, BifError> {
    // SAFETY: the constructors have no preconditions and return an independently owned context.
    let ptr: *mut c_void = unsafe {
        match kind {
            Kind::Compress => z::ZSTD_createCCtx().cast(),
            Kind::Decompress => z::ZSTD_createDCtx().cast(),
        }
    };
    make_resource(
        ctx,
        CtxBox {
            kind,
            state: Mutex::new(CtxState {
                ptr,
                owner: caller(),
                dict: None,
                in_use: false,
            }),
        },
        ZSTD_CTX_MAGIC_ORIG_SIZE,
    )
}

pub(super) fn init_compress_nif(ctx: &mut Ctx<'_>, _args: &[Term]) -> Result<Term, BifError> {
    init(ctx, Kind::Compress)
}

pub(super) fn init_decompress_nif(ctx: &mut Ctx<'_>, _args: &[Term]) -> Result<Term, BifError> {
    init(ctx, Kind::Decompress)
}

/// `compress_reset_nif` / `decompress_reset_nif`. A closed, foreign or wrong-type context raises,
/// because the pending exception of `get_zstd_context` overrides the `ok` C returns.
fn reset(args: &[Term], kind: Kind) -> Result<Term, BifError> {
    get_zstd_context(args[0], kind)?.lock().reset(kind);
    atom_term("ok")
}

pub(super) fn compress_reset_nif(_ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    reset(args, Kind::Compress)
}

pub(super) fn decompress_reset_nif(_ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    reset(args, Kind::Decompress)
}

/// `compress_close_nif` / `decompress_close_nif`: free the zstd context and release its
/// dictionary. The resource stays until it is collected; closing twice raises `badarg`.
fn close(args: &[Term], kind: Kind) -> Result<Term, BifError> {
    get_zstd_context(args[0], kind)?.lock().close(kind);
    atom_term("ok")
}

pub(super) fn compress_close_nif(_ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    close(args, Kind::Compress)
}

pub(super) fn decompress_close_nif(_ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    close(args, Kind::Decompress)
}

/// `set_pledged_src_size_nif`: the context is checked before the size.
pub(super) fn set_pledged_src_size_nif(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    let context = get_zstd_context(args[0], Kind::Compress)?;
    let size = get_uint64(args[1]).ok_or(BifError::BADARG)?;
    // SAFETY: `get_zstd_context` returned an open compression context.
    let result = unsafe { z::ZSTD_CCtx_setPledgedSrcSize(context.lock().ptr.cast(), size) };
    if is_error(result) {
        return Err(zstd_error(ctx, result));
    }
    atom_term("ok")
}
