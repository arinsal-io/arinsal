//! `set_compress_parameter_nif`, `get_compress_parameter_nif`,
//! `set_decompress_parameter_nif` and `get_decompress_parameter_nif`.

use arinsal_bifs::{BifError, Ctx};
use arinsal_term::Term;
use zstd_sys as z;

use super::{
    Kind, atom_name, atom_term, get_int, get_zstd_context, invalid_key, invalid_value, is_error,
    zstd_error,
};

fn cparam(key: Term) -> Option<z::ZSTD_cParameter> {
    use z::ZSTD_cParameter as P;
    Some(match atom_name(key)? {
        "compressionLevel" => P::ZSTD_c_compressionLevel,
        "windowLog" => P::ZSTD_c_windowLog,
        "hashLog" => P::ZSTD_c_hashLog,
        "chainLog" => P::ZSTD_c_chainLog,
        "searchLog" => P::ZSTD_c_searchLog,
        "minMatch" => P::ZSTD_c_minMatch,
        "targetLength" => P::ZSTD_c_targetLength,
        "strategy" => P::ZSTD_c_strategy,
        "targetCBlockSize" => P::ZSTD_c_targetCBlockSize,
        "enableLongDistanceMatching" => P::ZSTD_c_enableLongDistanceMatching,
        "ldmHashLog" => P::ZSTD_c_ldmHashLog,
        "ldmMinMatch" => P::ZSTD_c_ldmMinMatch,
        "ldmBucketSizeLog" => P::ZSTD_c_ldmBucketSizeLog,
        "ldmHashRateLog" => P::ZSTD_c_ldmHashRateLog,
        "contentSizeFlag" => P::ZSTD_c_contentSizeFlag,
        "checksumFlag" => P::ZSTD_c_checksumFlag,
        "dictIDFlag" => P::ZSTD_c_dictIDFlag,
        _ => return None,
    })
}
fn dparam(key: Term) -> Option<z::ZSTD_dParameter> {
    (atom_name(key) == Some("windowLogMax")).then_some(z::ZSTD_dParameter::ZSTD_d_windowLogMax)
}
fn boolean_param(p: z::ZSTD_cParameter) -> bool {
    use z::ZSTD_cParameter as P;
    matches!(
        p,
        P::ZSTD_c_enableLongDistanceMatching
            | P::ZSTD_c_contentSizeFlag
            | P::ZSTD_c_checksumFlag
            | P::ZSTD_c_dictIDFlag
    )
}
const STRATEGIES: [&str; 9] = [
    "fast", "dfast", "greedy", "lazy", "lazy2", "btlazy2", "btopt", "btultra", "btultra2",
];
fn param_value(p: z::ZSTD_cParameter, value: Term) -> Option<i32> {
    if p == z::ZSTD_cParameter::ZSTD_c_strategy {
        let name = atom_name(value)?;
        if name == "default" {
            return Some(0);
        }
        STRATEGIES
            .iter()
            .position(|strategy| *strategy == name)
            .map(|index| index as i32 + 1)
    } else if boolean_param(p) {
        match atom_name(value)? {
            "true" => Some(1),
            "false" => Some(0),
            _ => None,
        }
    } else {
        get_int(value)
    }
}

pub(super) fn set_compress_parameter_nif(
    ctx: &mut Ctx<'_>,
    args: &[Term],
) -> Result<Term, BifError> {
    let context = get_zstd_context(args[0], Kind::Compress)?;
    let p = cparam(args[1]).ok_or_else(|| invalid_key(ctx, args[1]))?;
    let value = param_value(p, args[2]).ok_or_else(|| invalid_value(ctx, args[2]))?;
    // SAFETY: the resource contains a live compression context.
    let result = unsafe { z::ZSTD_CCtx_setParameter(context.lock().ptr.cast(), p, value) };
    if is_error(result) {
        return Err(zstd_error(ctx, result));
    }
    atom_term("ok")
}

pub(super) fn get_compress_parameter_nif(
    ctx: &mut Ctx<'_>,
    args: &[Term],
) -> Result<Term, BifError> {
    let context = get_zstd_context(args[0], Kind::Compress)?;
    let p = cparam(args[1]).ok_or_else(|| invalid_key(ctx, args[1]))?;
    let mut value = 0;
    // SAFETY: the resource contains a live compression context.
    let result = unsafe { z::ZSTD_CCtx_getParameter(context.lock().ptr.cast(), p, &mut value) };
    if is_error(result) {
        return Err(zstd_error(ctx, result));
    }
    // The NIF converts the success return code, rather than the fetched value, to bool.
    if boolean_param(p) {
        atom_term("false")
    } else if p == z::ZSTD_cParameter::ZSTD_c_strategy {
        match value {
            0 => atom_term("default"),
            1..=9 => atom_term(STRATEGIES[(value - 1) as usize]),
            _ => Err(BifError::BADARG),
        }
    } else {
        Term::small(i64::from(value)).ok_or(BifError::SystemLimit)
    }
}

pub(super) fn set_decompress_parameter_nif(
    ctx: &mut Ctx<'_>,
    args: &[Term],
) -> Result<Term, BifError> {
    let context = get_zstd_context(args[0], Kind::Decompress)?;
    let value = get_int(args[2]).ok_or(BifError::BADARG)?;
    let p = dparam(args[1]).ok_or_else(|| invalid_key(ctx, args[1]))?;
    // SAFETY: the resource contains a live decompression context.
    let result = unsafe { z::ZSTD_DCtx_setParameter(context.lock().ptr.cast(), p, value) };
    if is_error(result) {
        return Err(zstd_error(ctx, result));
    }
    atom_term("ok")
}

pub(super) fn get_decompress_parameter_nif(
    ctx: &mut Ctx<'_>,
    args: &[Term],
) -> Result<Term, BifError> {
    let context = get_zstd_context(args[0], Kind::Decompress)?;
    let p = dparam(args[1]).ok_or_else(|| invalid_key(ctx, args[1]))?;
    let mut value = 0;
    // SAFETY: the resource contains a live decompression context.
    let result = unsafe { z::ZSTD_DCtx_getParameter(context.lock().ptr.cast(), p, &mut value) };
    if is_error(result) {
        return Err(zstd_error(ctx, result));
    }
    Term::small(i64::from(value)).ok_or(BifError::SystemLimit)
}
