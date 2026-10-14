//! Port of erts/emulator/nifs/common/zstd_nif.c, OTP-29.1.1.
//!
//! One `BifFn` per NIF, named like the C function. The files of this module split them by
//! concern: `ctx` (context lifecycle, `set_pledged_src_size_nif`), `stream` (the codec
//! NIFs), `dict` (dictionaries, dictionary ids, frame header) and `param` (the parameter
//! NIFs). This file holds what they share:
//!
//! - the resource payloads: [`CtxBox`] for `ZstdCompressContext`/`ZstdDecompressContext`
//!   and `Arc<DictBox>` for `ZstdCompressDict`, both carried by a `MagicRef`, so the payload's
//!   `Drop` is the resource destructor;
//! - [`get_zstd_context`], [`get_zstd_dict`] and [`make_resource`], the resource calls;
//! - the error constructors [`zstd_error`], [`invalid_key`] and [`invalid_value`];
//! - the argument readers [`get_int`], [`get_uint64`] and [`atom_term`].
//!
//! A NIF fails by returning `Err`. C records a pending exception and the NIF's return value
//! is dropped; the `Result` is that.

mod ctx;
mod dict;
mod param;
mod stream;

use std::any::Any;
use std::ffi::{CStr, c_void};
use std::sync::{Arc, Mutex, MutexGuard};

use arinsal_bifs::{BifError, BifFn, Ctx};
use arinsal_etf::OwnedTerm as O;
use arinsal_term::{MagicRef, Term, TermBuilder, from_owned, global_atoms, to_owned};
use num_traits::ToPrimitive;
use zstd_sys as z;

use crate::{Fault, Heap, Outcome, caller};

/// Which of the two context or dictionary resource types a value is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    Compress,
    Decompress,
}

/// Payload of a `ZstdCompressContext` or `ZstdDecompressContext` resource.
///
/// Port of the `ZstdCtx` resource of zstd_nif.c. `kind` selects the resource type: a
/// context of the other kind is not accepted by [`get_zstd_context`].
pub(crate) struct CtxBox {
    pub(crate) kind: Kind,
    state: Mutex<CtxState>,
}

/// The mutable part of a context, `ZstdCtx` without its type tag.
pub(crate) struct CtxState {
    /// The `ZSTD_CCtx` or `ZSTD_DCtx`; null once the context is closed (`handle.c == NULL`).
    pub(crate) ptr: *mut c_void,
    /// `ZstdCtx.owner`: the process that created the context.
    pub(crate) owner: Option<Term>,
    /// `ZstdCtx.dict`: the dictionary resource kept alive for `ZSTD_*Ctx_ref*Dict`.
    pub(crate) dict: Option<Arc<DictBox>>,
    /// `ZstdCtx.in_use`: a decompress stream has started.
    pub(crate) in_use: bool,
}

// SAFETY: a context is used only while its mutex is held, and zstd contexts have no
// thread affinity.
unsafe impl Send for CtxState {}

impl CtxBox {
    /// Lock the context state.
    pub(crate) fn lock(&self) -> MutexGuard<'_, CtxState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl CtxState {
    /// `close_compress_context` / `close_decompress_context`: free the zstd context, null the
    /// handle and release the referenced dictionary.
    pub(crate) fn close(&mut self, kind: Kind) {
        if !self.ptr.is_null() {
            // SAFETY: `ptr` came from the constructor of `kind` and is freed once, then nulled.
            unsafe {
                match kind {
                    Kind::Compress => z::ZSTD_freeCCtx(self.ptr.cast()),
                    Kind::Decompress => z::ZSTD_freeDCtx(self.ptr.cast()),
                };
            }
            self.ptr = std::ptr::null_mut();
            self.dict = None;
        }
    }

    /// `reset_compress_context` / `reset_decompress_context`: end the session, keep the
    /// parameters and dictionaries, and clear `in_use`.
    pub(crate) fn reset(&mut self, kind: Kind) {
        if !self.ptr.is_null() {
            let directive = z::ZSTD_ResetDirective::ZSTD_reset_session_only;
            // SAFETY: `ptr` is a live context of `kind`.
            unsafe {
                match kind {
                    Kind::Compress => z::ZSTD_CCtx_reset(self.ptr.cast(), directive),
                    Kind::Decompress => z::ZSTD_DCtx_reset(self.ptr.cast(), directive),
                };
            }
        }
        self.in_use = false;
    }
}

impl Drop for CtxBox {
    /// `compress_context_dtor` / `decompress_context_dtor`.
    fn drop(&mut self) {
        let kind = self.kind;
        self.state
            .get_mut()
            .unwrap_or_else(|e| e.into_inner())
            .close(kind);
    }
}

/// Payload of a `ZstdCompressDict` resource (`ZstdDict`). The resource is an `Arc<DictBox>`,
/// so a context can hold the dictionary alive by cloning it.
pub(crate) struct DictBox {
    pub(crate) kind: Kind,
    /// The `ZSTD_CDict` or `ZSTD_DDict`.
    pub(crate) ptr: *mut c_void,
    /// The dictionary content `ptr` references (`ZSTD_dlm_byRef`); dropped after `Drop::drop`
    /// freed the dictionary.
    #[allow(dead_code)]
    pub(crate) data: Vec<u8>,
}

// SAFETY: a digested dictionary is immutable and zstd permits shared use.
unsafe impl Send for DictBox {}
// SAFETY: a digested dictionary is immutable and zstd permits shared use.
unsafe impl Sync for DictBox {}

impl Drop for DictBox {
    /// `compress_dict_dtor` / `decompress_dict_dtor`.
    fn drop(&mut self) {
        // SAFETY: `ptr` came from the matching dictionary constructor and is freed once.
        unsafe {
            match self.kind {
                Kind::Compress => z::ZSTD_freeCDict(self.ptr.cast()),
                Kind::Decompress => z::ZSTD_freeDDict(self.ptr.cast()),
            };
        }
    }
}

/// Port of get_zstd_context (zstd_nif.c).
///
/// `Err(badarg)` if `term` is not a context resource of `kind` (a magic reference restored by
/// `binary_to_term` is not) or the context is closed; `Err(error:not_on_controlling_process)`
/// if the calling process is not the owner. The checks run in that order, like C.
///
/// The returned borrow is of the resource `term` names, which the calling process's heap keeps
/// alive for the NIF call.
pub(crate) fn get_zstd_context<'a>(term: Term, kind: Kind) -> Result<&'a CtxBox, BifError> {
    // SAFETY: `term` is an argument of the running NIF call; the heap that owns the magic
    // reference is neither collected nor freed until the call returns.
    let owner = unsafe { term.magic_ref() }.ok_or(BifError::BADARG)?;
    let boxed = owner
        .downcast_ref::<CtxBox>()
        .filter(|boxed| boxed.kind == kind)
        .ok_or(BifError::BADARG)?;
    let state = boxed.lock();
    if state.ptr.is_null() {
        return Err(BifError::BADARG);
    }
    if state.owner != caller() {
        return Err(BifError::Error(atom_term("not_on_controlling_process")?));
    }
    drop(state);
    Ok(boxed)
}

/// `enif_get_resource` for the `ZstdCompressDict` (`Kind::Compress`) or the decompress dictionary
/// resource type. The returned `Arc` is `enif_make_copy` of the dictionary term into a context.
pub(crate) fn get_zstd_dict(term: Term, kind: Kind) -> Option<Arc<DictBox>> {
    // SAFETY: `term` is an argument of the running NIF call; the heap that owns the magic
    // reference is neither collected nor freed until the call returns.
    let owner = unsafe { term.magic_ref() }?;
    owner
        .downcast_ref::<Arc<DictBox>>()
        .filter(|dict| dict.kind == kind)
        .cloned()
}

/// `enif_alloc_resource` + `enif_make_resource` + `enif_release_resource`: a magic reference
/// that is the only owner of `payload`, which is dropped when the last term that references it is
/// collected.
pub(crate) fn make_resource<T: Any + Send + Sync>(
    ctx: &mut Ctx<'_>,
    payload: T,
) -> Result<Term, BifError> {
    TermBuilder::new(&mut Heap(&mut ctx.heap))
        .magic_ref(MagicRef::new(payload))
        .map_err(|_| BifError::SystemLimit)
}

/// `ZSTD_isError`.
pub(crate) fn is_error(code: usize) -> bool {
    // SAFETY: any zstd result may be passed to ZSTD_isError.
    unsafe { z::ZSTD_isError(code) != 0 }
}

/// `make_zstd_error` (zstd_nif.c): `error:{zstd_error, <<Name>>}`, the name from
/// `ZSTD_getErrorName(code)` as a binary.
pub(crate) fn zstd_error(ctx: &mut Ctx<'_>, code: usize) -> BifError {
    // SAFETY: zstd returns a static NUL-terminated error name for any code.
    let name = unsafe { CStr::from_ptr(z::ZSTD_getErrorName(code)) }.to_bytes();
    let Ok(tag) = atom_term("zstd_error") else {
        return BifError::SystemLimit;
    };
    let mut heap = Heap(&mut ctx.heap);
    let mut builder = TermBuilder::new(&mut heap);
    match builder
        .binary(name)
        .and_then(|name| builder.tuple(&[tag, name]))
    {
        Ok(reason) => BifError::Error(reason),
        Err(_) => BifError::SystemLimit,
    }
}

/// `error:{badarg, {invalid_key, Key}}`, raised for an unknown parameter.
pub(crate) fn invalid_key(ctx: &mut Ctx<'_>, key: Term) -> BifError {
    badarg_reason(ctx, "invalid_key", key)
}

/// `error:{badarg, {invalid_value, Value}}`, raised for a parameter value of the wrong type.
pub(crate) fn invalid_value(ctx: &mut Ctx<'_>, value: Term) -> BifError {
    badarg_reason(ctx, "invalid_value", value)
}

fn badarg_reason(ctx: &mut Ctx<'_>, what: &str, term: Term) -> BifError {
    let (Ok(badarg), Ok(what)) = (atom_term("badarg"), atom_term(what)) else {
        return BifError::SystemLimit;
    };
    let mut heap = Heap(&mut ctx.heap);
    let mut builder = TermBuilder::new(&mut heap);
    match builder
        .tuple(&[what, term])
        .and_then(|detail| builder.tuple(&[badarg, detail]))
    {
        Ok(reason) => BifError::Error(reason),
        Err(_) => BifError::SystemLimit,
    }
}

/// `enif_make_atom`.
pub(crate) fn atom_term(name: &str) -> Result<Term, BifError> {
    global_atoms()
        .intern(name)
        .map(Term::atom)
        .map_err(|_| BifError::SystemLimit)
}

/// The name of an atom term, `None` for any other term.
pub(crate) fn atom_name(term: Term) -> Option<&'static str> {
    term.as_atom().and_then(|atom| global_atoms().text(atom))
}

/// `enif_get_int`: a C `int`.
pub(crate) fn get_int(term: Term) -> Option<i32> {
    term.as_small().and_then(|value| i32::try_from(value).ok())
}

/// `enif_get_uint64`: a non-negative integer below 2^64. Only a one-digit bignum is copied out;
/// any other boxed term, a binary included, is rejected without being read.
pub(crate) fn get_uint64(term: Term) -> Option<u64> {
    match term.as_small() {
        Some(value) => u64::try_from(value).ok(),
        None if term.is_negative_bignum() => None,
        None if term.bignum_digit_count() == Some(1) => match to_owned(term) {
            Ok(O::BigInt(ref value)) => value.to_u64(),
            _ => None,
        },
        None => None,
    }
}

/// Bridge for the argument and result shapes that still go through `OwnedTerm`: raise a
/// [`Fault`] or build the result term.
pub(crate) fn outcome(ctx: &mut Ctx<'_>, result: Outcome) -> Result<Term, BifError> {
    let mut heap = Heap(&mut ctx.heap);
    match result {
        Ok(term) => from_owned(&term, &mut heap).map_err(|_| BifError::SystemLimit),
        Err(Fault::Badarg) => Err(BifError::BADARG),
        Err(Fault::Reason(reason)) => Err(BifError::Error(
            from_owned(&reason, &mut heap).map_err(|_| BifError::SystemLimit)?,
        )),
    }
}

/// The entry of `zstd:name/arity` in `nif_funcs`.
pub(crate) fn lookup(name: &str, arity: u8) -> Option<BifFn> {
    Some(match (name, arity) {
        ("init_compress_nif", 0) => ctx::init_compress_nif,
        ("init_decompress_nif", 0) => ctx::init_decompress_nif,
        ("compress_reset_nif", 1) => ctx::compress_reset_nif,
        ("decompress_reset_nif", 1) => ctx::decompress_reset_nif,
        ("compress_close_nif", 1) => ctx::compress_close_nif,
        ("decompress_close_nif", 1) => ctx::decompress_close_nif,
        ("set_pledged_src_size_nif", 2) => ctx::set_pledged_src_size_nif,
        ("compress_stream_nif", 3) => stream::compress_stream_nif,
        ("decompress_stream_nif", 3) => stream::decompress_stream_nif,
        ("load_compress_dictionary_nif", 2) => dict::load_compress_dictionary_nif,
        ("load_decompress_dictionary_nif", 2) => dict::load_decompress_dictionary_nif,
        ("ref_compress_dictionary_nif", 2) => dict::ref_compress_dictionary_nif,
        ("ref_decompress_dictionary_nif", 2) => dict::ref_decompress_dictionary_nif,
        ("create_cdict_nif", 2) => dict::create_cdict_nif,
        ("create_ddict_nif", 1) => dict::create_ddict_nif,
        ("getDictId_fromCDict_nif", 1) => dict::get_dict_id_from_cdict_nif,
        ("getDictId_fromDDict_nif", 1) => dict::get_dict_id_from_ddict_nif,
        ("getDictId_fromDict_nif", 1) => dict::get_dict_id_from_dict_nif,
        ("getDictId_fromFrame_nif", 1) => dict::get_dict_id_from_frame_nif,
        ("get_frame_header_nif", 1) => dict::get_frame_header_nif,
        ("set_compress_parameter_nif", 3) => param::set_compress_parameter_nif,
        ("get_compress_parameter_nif", 2) => param::get_compress_parameter_nif,
        ("set_decompress_parameter_nif", 3) => param::set_decompress_parameter_nif,
        ("get_decompress_parameter_nif", 2) => param::get_decompress_parameter_nif,
        _ => return None,
    })
}
