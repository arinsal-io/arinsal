//! Dictionary NIFs: `load_*`, `ref_*`, `create_*`, the `getDictId_*` family and
//! `get_frame_header_nif`.

use std::ffi::c_void;
use std::sync::Arc;

use arinsal_bifs::{BifError, Ctx};
use arinsal_etf::OwnedTerm as O;
use arinsal_term::{Term, to_owned};
use zstd_sys as z;

use super::{
    DictBox, Kind, atom_term, get_zstd_context, get_zstd_dict, is_error, make_resource, outcome,
    zstd_error,
};
use crate::{Fault, Outcome, atom, bytes, int, number, pair};

fn owned(term: Term) -> Result<O, BifError> {
    to_owned(term).map_err(|_| BifError::BADARG)
}

fn load(ctx: &mut Ctx<'_>, args: &[Term], kind: Kind) -> Result<Term, BifError> {
    let context = get_zstd_context(args[0], kind)?;
    let data = bytes(&owned(args[1])?).map_err(|_| BifError::BADARG)?;
    let mut state = context.lock();
    state.dict = None;
    // SAFETY: the context is open and zstd copies the dictionary.
    let result = unsafe {
        match kind {
            Kind::Compress => {
                z::ZSTD_CCtx_loadDictionary(state.ptr.cast(), data.as_ptr().cast(), data.len())
            }
            Kind::Decompress => {
                z::ZSTD_DCtx_loadDictionary(state.ptr.cast(), data.as_ptr().cast(), data.len())
            }
        }
    };
    drop(state);
    if is_error(result) {
        return Err(zstd_error(ctx, result));
    }
    atom_term("ok")
}

pub(super) fn load_compress_dictionary_nif(
    ctx: &mut Ctx<'_>,
    args: &[Term],
) -> Result<Term, BifError> {
    load(ctx, args, Kind::Compress)
}

pub(super) fn load_decompress_dictionary_nif(
    ctx: &mut Ctx<'_>,
    args: &[Term],
) -> Result<Term, BifError> {
    load(ctx, args, Kind::Decompress)
}

fn reference(ctx: &mut Ctx<'_>, args: &[Term], kind: Kind) -> Result<Term, BifError> {
    let context = get_zstd_context(args[0], kind)?;
    let dict = get_zstd_dict(args[1], kind).ok_or(BifError::BADARG)?;
    let mut state = context.lock();
    // SAFETY: the context is open and the `Arc` keeps the dictionary alive with it.
    let result = unsafe {
        match kind {
            Kind::Compress => z::ZSTD_CCtx_refCDict(state.ptr.cast(), dict.ptr.cast()),
            Kind::Decompress => z::ZSTD_DCtx_refDDict(state.ptr.cast(), dict.ptr.cast()),
        }
    };
    if is_error(result) {
        drop(state);
        return Err(zstd_error(ctx, result));
    }
    state.dict = Some(dict);
    atom_term("ok")
}

pub(super) fn ref_compress_dictionary_nif(
    ctx: &mut Ctx<'_>,
    args: &[Term],
) -> Result<Term, BifError> {
    reference(ctx, args, Kind::Compress)
}

pub(super) fn ref_decompress_dictionary_nif(
    ctx: &mut Ctx<'_>,
    args: &[Term],
) -> Result<Term, BifError> {
    reference(ctx, args, Kind::Decompress)
}

fn create(
    ctx: &mut Ctx<'_>,
    kind: Kind,
    input: &Term,
    level: Option<&Term>,
) -> Result<Term, BifError> {
    let mut input = owned(*input)?;
    let O::Binary(data) = &mut input else {
        return Err(BifError::BADARG);
    };
    let data = std::mem::take(data);
    let level = level
        .map(|level| number(&owned(*level)?).map_err(|_| BifError::BADARG))
        .transpose()?
        .unwrap_or(0);
    let memory = z::ZSTD_customMem {
        customAlloc: None,
        customFree: None,
        opaque: std::ptr::null_mut(),
    };
    // SAFETY: `data` is moved into the `DictBox` below, which outlives the dictionary.
    let ptr: *mut c_void = unsafe {
        match kind {
            Kind::Compress => z::ZSTD_createCDict_advanced(
                data.as_ptr().cast(),
                data.len(),
                z::ZSTD_dictLoadMethod_e::ZSTD_dlm_byRef,
                z::ZSTD_dictContentType_e::ZSTD_dct_auto,
                z::ZSTD_getCParams(level, 0, data.len()),
                memory,
            )
            .cast(),
            Kind::Decompress => z::ZSTD_createDDict_advanced(
                data.as_ptr().cast(),
                data.len(),
                z::ZSTD_dictLoadMethod_e::ZSTD_dlm_byRef,
                z::ZSTD_dictContentType_e::ZSTD_dct_auto,
                memory,
            )
            .cast(),
        }
    };
    if ptr.is_null() {
        let name = match kind {
            Kind::Compress => "invalid_compress_dict",
            Kind::Decompress => "invalid_decompress_dict",
        };
        return outcome(ctx, Ok(pair(atom("error"), atom(name))));
    }
    make_resource(ctx, Arc::new(DictBox { kind, ptr, data }))
}

pub(super) fn create_cdict_nif(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    create(ctx, Kind::Compress, &args[0], Some(&args[1]))
}

pub(super) fn create_ddict_nif(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    create(ctx, Kind::Decompress, &args[0], None)
}

#[derive(Clone, Copy)]
enum IdOf {
    CDict,
    DDict,
    Dict,
    Frame,
}

fn dict_id(ctx: &mut Ctx<'_>, args: &[Term], from: IdOf) -> Result<Term, BifError> {
    let (dict, data) = match from {
        IdOf::CDict => (get_zstd_dict(args[0], Kind::Compress), Vec::new()),
        IdOf::DDict => (get_zstd_dict(args[0], Kind::Decompress), Vec::new()),
        IdOf::Dict | IdOf::Frame => (None, bytes(&owned(args[0])?).map_err(|_| BifError::BADARG)?),
    };
    if dict.is_none() && matches!(from, IdOf::CDict | IdOf::DDict) {
        return Err(BifError::BADARG);
    }
    // SAFETY: the dictionary pointer is valid while its `Arc` is held, and zstd reads only
    // the supplied bytes.
    let id = unsafe {
        let ptr = dict.as_ref().map_or(std::ptr::null_mut(), |dict| dict.ptr);
        match from {
            IdOf::CDict => z::ZSTD_getDictID_fromCDict(ptr.cast()),
            IdOf::DDict => z::ZSTD_getDictID_fromDDict(ptr.cast()),
            IdOf::Dict => z::ZSTD_getDictID_fromDict(data.as_ptr().cast(), data.len()),
            IdOf::Frame => z::ZSTD_getDictID_fromFrame(data.as_ptr().cast(), data.len()),
        }
    };
    outcome(ctx, Ok(int(u64::from(id))))
}

pub(super) fn get_dict_id_from_cdict_nif(
    ctx: &mut Ctx<'_>,
    args: &[Term],
) -> Result<Term, BifError> {
    dict_id(ctx, args, IdOf::CDict)
}

pub(super) fn get_dict_id_from_ddict_nif(
    ctx: &mut Ctx<'_>,
    args: &[Term],
) -> Result<Term, BifError> {
    dict_id(ctx, args, IdOf::DDict)
}

pub(super) fn get_dict_id_from_dict_nif(
    ctx: &mut Ctx<'_>,
    args: &[Term],
) -> Result<Term, BifError> {
    dict_id(ctx, args, IdOf::Dict)
}

pub(super) fn get_dict_id_from_frame_nif(
    ctx: &mut Ctx<'_>,
    args: &[Term],
) -> Result<Term, BifError> {
    dict_id(ctx, args, IdOf::Frame)
}

fn frame_header(input: &O) -> Result<Outcome, usize> {
    let Ok(data) = bytes(input) else {
        return Ok(Err(Fault::Badarg));
    };
    // SAFETY: this C POD may be zero initialized before ZSTD_getFrameHeader fills it, and the
    // data remains live during header decoding.
    let (hdr, result) = unsafe {
        let mut hdr: z::ZSTD_FrameHeader = std::mem::zeroed();
        let result = z::ZSTD_getFrameHeader(&mut hdr, data.as_ptr().cast(), data.len());
        (hdr, result)
    };
    if is_error(result) {
        return Err(result);
    }
    if result > 0 {
        return Ok(Err(Fault::Badarg));
    }
    let fields = vec![
        (
            atom("frameContentSize"),
            if hdr.frameContentSize == u64::MAX {
                atom("undefined")
            } else {
                int(hdr.frameContentSize)
            },
        ),
        (atom("windowSize"), int(hdr.windowSize)),
        (atom("blockSizeMax"), int(u64::from(hdr.blockSizeMax))),
        (
            atom("frameType"),
            atom(if hdr.frameType == z::ZSTD_FrameType_e::ZSTD_frame {
                "ZSTD_frame"
            } else {
                "ZSTD_skippableFrame"
            }),
        ),
        (atom("headerSize"), int(u64::from(hdr.headerSize))),
        (atom("dictID"), int(u64::from(hdr.dictID))),
        (
            atom("checksumFlag"),
            atom(if hdr.checksumFlag != 0 {
                "true"
            } else {
                "false"
            }),
        ),
    ];
    Ok(Ok(pair(atom("ok"), O::Map(fields))))
}

pub(super) fn get_frame_header_nif(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    let input = owned(args[0])?;
    match frame_header(&input) {
        Ok(result) => outcome(ctx, result),
        Err(code) => Err(zstd_error(ctx, code)),
    }
}
