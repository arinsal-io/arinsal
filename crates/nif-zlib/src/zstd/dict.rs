//! Dictionary NIFs: `load_*`, `ref_*`, `create_*`, the `getDictId_*` family and
//! `get_frame_header_nif`.
//!
//! A load copies the dictionary into the zstd context and keeps nothing of the argument. A ref
//! stores the dictionary resource in the context (`CtxState::dict`), which keeps the `cdict` or
//! `ddict` alive for as long as the context may use it. The dictionary arguments are read in
//! place, as `enif_inspect_binary` and `enif_inspect_iolist_as_binary` do.

use std::ffi::c_void;
use std::sync::Arc;

use arinsal_bifs::{BifError, Ctx};
use arinsal_term::{Term, TermBuilder};
use zstd_sys as z;

use super::{
    DictBox, Kind, atom_term, bitstring, copy_bits_fwd, get_int, get_zstd_context, get_zstd_dict,
    inspect_binary, is_error, make_resource, zstd_error,
};
use crate::Heap;

/// The cell of a list, `None` for any other term.
fn cell(list: Term) -> Option<(Term, Term)> {
    // SAFETY: `list` is (part of) an argument of the running NIF call, whose heap stays live
    // and unmoved until the call returns.
    unsafe { list.cons_ref() }
}

/// Append the bytes of a whole-byte bitstring to `out`; `None` if it is not one.
fn append_binary(term: Term, out: &mut Vec<u8>) -> Option<()> {
    let view = bitstring(term)?;
    if view.bit_len() % 8 != 0 {
        return None;
    }
    let (start, len) = (view.start_bit(), view.bit_len() / 8);
    let at = out.len();
    out.resize(at + len, 0);
    copy_bits_fwd(&mut out[at..], view.bytes(), start);
    Some(())
}

/// `enif_inspect_iolist_as_binary`: a binary is read as `enif_inspect_binary` does, `[]` is
/// empty and any other iolist is flattened into `scratch`. `None` for a term that is not an
/// iolist.
pub(super) fn inspect_iolist_as_binary(term: Term, scratch: &mut Vec<u8>) -> Option<&[u8]> {
    if bitstring(term).is_some() {
        return inspect_binary(term, scratch);
    }
    if term == Term::NIL {
        return Some(&[]);
    }
    scratch.clear();
    let mut pending = Vec::new();
    let mut obj = term;
    loop {
        while let Some((head, tail)) = cell(obj) {
            if let Some(byte) = head.as_small() {
                scratch.push(u8::try_from(byte).ok()?);
            } else if bitstring(head).is_some() {
                append_binary(head, scratch)?;
            } else if cell(head).is_some() {
                pending.push(tail);
                obj = head;
                continue;
            } else if head != Term::NIL {
                return None;
            }
            obj = tail;
        }
        if bitstring(obj).is_some() {
            append_binary(obj, scratch)?;
        } else if obj != Term::NIL {
            return None;
        }
        match pending.pop() {
            Some(tail) => obj = tail,
            None => break,
        }
    }
    Some(scratch)
}

/// `enif_make_uint` / `enif_make_ulong`.
fn unsigned(ctx: &mut Ctx<'_>, value: u64) -> Result<Term, BifError> {
    TermBuilder::new(&mut Heap(&mut ctx.heap))
        .int_from_u64(value)
        .map_err(|_| BifError::SystemLimit)
}

/// `enif_make_tuple2`.
fn pair(ctx: &mut Ctx<'_>, first: Term, second: Term) -> Result<Term, BifError> {
    TermBuilder::new(&mut Heap(&mut ctx.heap))
        .tuple(&[first, second])
        .map_err(|_| BifError::SystemLimit)
}

/// `load_compress_dictionary_nif` / `load_decompress_dictionary_nif`.
///
/// The dictionary the context referenced is dropped before zstd loads the new one. When zstd
/// refuses the load (a stream is in progress) the context still points at the old dictionary,
/// so it is put back instead of being left dangling.
fn load(ctx: &mut Ctx<'_>, args: &[Term], kind: Kind) -> Result<Term, BifError> {
    let context = get_zstd_context(args[0], kind)?;
    let mut scratch = Vec::new();
    let data = inspect_iolist_as_binary(args[1], &mut scratch).ok_or(BifError::BADARG)?;
    let mut state = context.lock();
    let previous = state.dict.take();
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
    if is_error(result) {
        state.dict = previous;
        drop(state);
        return Err(zstd_error(ctx, result));
    }
    drop(state);
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

/// `ref_compress_dictionary_nif` / `ref_decompress_dictionary_nif`. The context keeps the
/// dictionary resource only after zstd accepted it; on an error the old one stays.
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
    drop(state);
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

/// `create_cdict_nif` / `create_ddict_nif`: digest a copy of the dictionary binary, which the
/// resource owns for as long as zstd references it. A dictionary zstd cannot digest gives
/// `{error, invalid_compress_dict}` / `{error, invalid_decompress_dict}`.
fn create(ctx: &mut Ctx<'_>, args: &[Term], kind: Kind) -> Result<Term, BifError> {
    let mut scratch = Vec::new();
    let input = inspect_binary(args[0], &mut scratch).ok_or(BifError::BADARG)?;
    let level = match kind {
        Kind::Compress => get_int(args[1]).ok_or(BifError::BADARG)?,
        Kind::Decompress => 0,
    };
    let data = input.to_vec();
    let memory = z::ZSTD_customMem {
        customAlloc: None,
        customFree: None,
        opaque: std::ptr::null_mut(),
    };
    // SAFETY: `data` is moved into the `DictBox` below, which outlives the dictionary, and its
    // buffer does not move with it.
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
        let (error, name) = (atom_term("error")?, atom_term(name)?);
        return pair(ctx, error, name);
    }
    make_resource(ctx, Arc::new(DictBox { kind, ptr, data }))
}

pub(super) fn create_cdict_nif(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    create(ctx, args, Kind::Compress)
}

pub(super) fn create_ddict_nif(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    create(ctx, args, Kind::Decompress)
}

/// What a `getDictId_*_nif` reads the dictionary id of.
#[derive(Clone, Copy)]
enum IdOf {
    CDict,
    DDict,
    Dict,
    Frame,
}

/// The `getDictId_*_nif` family. A resource argument of the other dictionary type is `badarg`; a
/// dictionary or frame is an iolist, and input zstd cannot read has id 0.
fn dict_id(ctx: &mut Ctx<'_>, args: &[Term], of: IdOf) -> Result<Term, BifError> {
    let mut scratch = Vec::new();
    let (dict, data) = match of {
        IdOf::CDict => (get_zstd_dict(args[0], Kind::Compress), &[][..]),
        IdOf::DDict => (get_zstd_dict(args[0], Kind::Decompress), &[][..]),
        IdOf::Dict | IdOf::Frame => (
            None,
            inspect_iolist_as_binary(args[0], &mut scratch).ok_or(BifError::BADARG)?,
        ),
    };
    if dict.is_none() && matches!(of, IdOf::CDict | IdOf::DDict) {
        return Err(BifError::BADARG);
    }
    // SAFETY: a dictionary pointer is valid while its `Arc` is held, and zstd reads only the
    // `data.len()` bytes supplied.
    let id = unsafe {
        let ptr = dict.as_ref().map_or(std::ptr::null_mut(), |dict| dict.ptr);
        match of {
            IdOf::CDict => z::ZSTD_getDictID_fromCDict(ptr.cast()),
            IdOf::DDict => z::ZSTD_getDictID_fromDDict(ptr.cast()),
            IdOf::Dict => z::ZSTD_getDictID_fromDict(data.as_ptr().cast(), data.len()),
            IdOf::Frame => z::ZSTD_getDictID_fromFrame(data.as_ptr().cast(), data.len()),
        }
    };
    unsigned(ctx, u64::from(id))
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

/// `get_frame_header_nif`: `{ok, Header}` for the frame header at the start of an iolist.
///
/// Only an error from `ZSTD_getFrameHeader` raises. A positive result means zstd needs more
/// input; the map is built from the header zstd filled in anyway. The keys are created before
/// the argument is inspected, in C order, which fixes the order of the map's keys.
pub(super) fn get_frame_header_nif(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    let keys = [
        atom_term("frameContentSize")?,
        atom_term("windowSize")?,
        atom_term("blockSizeMax")?,
        atom_term("frameType")?,
        atom_term("headerSize")?,
        atom_term("dictID")?,
        atom_term("checksumFlag")?,
    ];
    let mut scratch = Vec::new();
    let data = inspect_iolist_as_binary(args[0], &mut scratch).ok_or(BifError::BADARG)?;
    // SAFETY: this C POD may be zero initialized before ZSTD_getFrameHeader fills it, and
    // zstd reads only the `data.len()` bytes supplied.
    let (hdr, result) = unsafe {
        let mut hdr: z::ZSTD_FrameHeader = std::mem::zeroed();
        let result = z::ZSTD_getFrameHeader(&mut hdr, data.as_ptr().cast(), data.len());
        (hdr, result)
    };
    if is_error(result) {
        return Err(zstd_error(ctx, result));
    }
    let content_size = if hdr.frameContentSize == u64::MAX {
        atom_term("undefined")?
    } else {
        unsigned(ctx, hdr.frameContentSize)?
    };
    let window_size = unsigned(ctx, hdr.windowSize)?;
    let block_size_max = unsigned(ctx, u64::from(hdr.blockSizeMax))?;
    let frame_type = atom_term(if hdr.frameType == z::ZSTD_FrameType_e::ZSTD_frame {
        "ZSTD_frame"
    } else {
        "ZSTD_skippableFrame"
    })?;
    let header_size = unsigned(ctx, u64::from(hdr.headerSize))?;
    let dict_id = unsigned(ctx, u64::from(hdr.dictID))?;
    let checksum = atom_term(if hdr.checksumFlag != 0 {
        "true"
    } else {
        "false"
    })?;
    let values = [
        content_size,
        window_size,
        block_size_max,
        frame_type,
        header_size,
        dict_id,
        checksum,
    ];
    let pairs: Vec<(Term, Term)> = keys.into_iter().zip(values).collect();
    let map = TermBuilder::new(&mut Heap(&mut ctx.heap))
        .flatmap_from_pairs(&pairs)
        .map_err(|_| BifError::SystemLimit)?;
    let ok = atom_term("ok")?;
    pair(ctx, ok, map)
}

#[cfg(test)]
mod tests {
    use arinsal_bifs::ProcessHeapHandle;
    use arinsal_term::ProcessHeap;

    use super::*;

    fn pattern(len: usize) -> Vec<u8> {
        (0..len).map(|index| (index * 7 + 3) as u8).collect()
    }

    /// Run `body` with a builder on a fresh process heap.
    fn with_builder<T>(body: impl FnOnce(&mut TermBuilder<'_, ProcessHeapHandle<'_>>) -> T) -> T {
        let mut heap = ProcessHeap::with_words(1 << 16);
        let mut alloc = ProcessHeapHandle(&mut heap);
        body(&mut TermBuilder::new(&mut alloc))
    }

    fn base_of(term: Term) -> *const u8 {
        bitstring(term).expect("binary").bytes().as_ptr()
    }

    #[test]
    fn aligned_binaries_are_read_in_place() {
        with_builder(|builder| {
            for len in [0usize, 10, 64, 65, 200] {
                let data = pattern(len);
                let term = builder.binary(&data).unwrap();
                let mut scratch = Vec::new();
                let bytes = inspect_binary(term, &mut scratch).expect("binary");
                assert_eq!(bytes, &data[..]);
                assert_eq!(bytes.as_ptr(), base_of(term), "length {len}");
                assert_eq!(scratch.capacity(), 0, "length {len}");
                let bytes = inspect_iolist_as_binary(term, &mut scratch).expect("iolist");
                assert_eq!(bytes.as_ptr(), base_of(term), "length {len}");
                assert_eq!(scratch.capacity(), 0, "length {len}");
            }
        });
    }

    #[test]
    fn aligned_sub_binary_is_read_in_place() {
        with_builder(|builder| {
            let data = pattern(200);
            let whole = builder.binary(&data).unwrap();
            let sub = builder.sub_binary(whole, 10 * 8, 100 * 8).unwrap();
            let mut scratch = Vec::new();
            let bytes = inspect_binary(sub, &mut scratch).expect("binary");
            assert_eq!(bytes, &data[10..110]);
            assert_eq!(bytes.as_ptr(), base_of(whole).wrapping_add(10));
            assert_eq!(scratch.capacity(), 0);
        });
    }

    #[test]
    fn unaligned_sub_binary_is_copied() {
        with_builder(|builder| {
            let data = pattern(200);
            let whole = builder.binary(&data).unwrap();
            let sub = builder.sub_binary(whole, 3, 100 * 8).unwrap();
            let mut scratch = Vec::new();
            let bytes = inspect_binary(sub, &mut scratch).expect("binary");
            let expected: Vec<u8> = (0..100)
                .map(|index| (data[index] << 3) | (data[index + 1] >> 5))
                .collect();
            assert_eq!(bytes, &expected[..]);
            let mut scratch = Vec::new();
            let flattened = inspect_iolist_as_binary(sub, &mut scratch).expect("iolist");
            assert_eq!(flattened, &expected[..]);
        });
    }

    #[test]
    fn a_bitstring_that_is_not_whole_bytes_is_refused() {
        with_builder(|builder| {
            let bits = builder.bitstring(&[0xff, 0xe0], 11).unwrap();
            let mut scratch = Vec::new();
            assert!(inspect_binary(bits, &mut scratch).is_none());
            assert!(inspect_iolist_as_binary(bits, &mut scratch).is_none());
            let nested = builder.list_from_slice(&[bits]).unwrap();
            assert!(inspect_iolist_as_binary(nested, &mut scratch).is_none());
        });
    }

    #[test]
    fn an_iolist_is_flattened_like_iolist_to_binary() {
        with_builder(|builder| {
            let small = |value: i64| Term::small(value).unwrap();
            let big = pattern(100);
            let binary = builder.binary(&big).unwrap();
            let bytes = builder.binary(&[7, 8, 9]).unwrap();
            let inner = builder.list_from_slice(&[small(2), small(3)]).unwrap();
            let items = [small(1), inner, binary, Term::NIL, bytes];
            let list = builder.list_from_slice(&items).unwrap();
            let improper = builder.cons(small(5), bytes).unwrap();
            let both = builder.list_from_slice(&[list, improper]).unwrap();
            let mut scratch = Vec::new();
            let flat = inspect_iolist_as_binary(both, &mut scratch).expect("iolist");
            let mut expected = vec![1, 2, 3];
            expected.extend_from_slice(&big);
            expected.extend_from_slice(&[7, 8, 9, 5, 7, 8, 9]);
            assert_eq!(flat, &expected[..]);
            assert_eq!(
                inspect_iolist_as_binary(Term::NIL, &mut scratch),
                Some(&[][..])
            );
        });
    }

    #[test]
    fn a_deeply_nested_iolist_does_not_recurse() {
        with_builder(|builder| {
            let mut list = builder.list_from_slice(&[Term::small(1).unwrap()]).unwrap();
            for _ in 0..2000 {
                list = builder
                    .list_from_slice(&[list, Term::small(2).unwrap()])
                    .unwrap();
            }
            let mut scratch = Vec::new();
            let flat = inspect_iolist_as_binary(list, &mut scratch).expect("iolist");
            assert_eq!(flat.len(), 2001);
            assert_eq!(flat[0], 1);
            assert!(flat[1..].iter().all(|byte| *byte == 2));
        });
    }

    #[test]
    fn terms_that_are_not_iolists_are_refused() {
        with_builder(|builder| {
            let mut scratch = Vec::new();
            let atom = atom_term("not_iodata").unwrap();
            let tuple = builder.tuple(&[Term::small(1).unwrap()]).unwrap();
            let bits = builder.bitstring(&[0x80], 1).unwrap();
            let cases = [
                atom,
                tuple,
                Term::small(5).unwrap(),
                builder
                    .list_from_slice(&[Term::small(256).unwrap()])
                    .unwrap(),
                builder
                    .list_from_slice(&[Term::small(-1).unwrap()])
                    .unwrap(),
                builder.list_from_slice(&[atom]).unwrap(),
                builder.list_from_slice(&[bits]).unwrap(),
                builder
                    .cons(Term::small(1).unwrap(), Term::small(2).unwrap())
                    .unwrap(),
                builder.cons(Term::small(1).unwrap(), atom).unwrap(),
            ];
            for (index, term) in cases.into_iter().enumerate() {
                assert!(
                    inspect_iolist_as_binary(term, &mut scratch).is_none(),
                    "case {index}"
                );
            }
        });
    }

    #[test]
    fn a_context_holds_a_referenced_dictionary_until_a_load_or_the_close() {
        use arinsal_bifs::Ctx;

        use crate::zstd::lookup;

        let mut heap = ProcessHeap::with_words(1 << 16);
        let mut alloc = ProcessHeapHandle(&mut heap);
        let mut ctx = Ctx::new(&mut alloc);
        let call = |ctx: &mut Ctx<'_>, name: &str, args: &[Term]| {
            lookup(name, args.len() as u8).expect("zstd NIF")(ctx, args)
        };
        let content = TermBuilder::new(&mut Heap(&mut ctx.heap))
            .binary(&pattern(300))
            .unwrap();
        let level = Term::small(3).unwrap();
        let cdict = call(&mut ctx, "create_cdict_nif", &[content, level]).unwrap();
        let held = get_zstd_dict(cdict, Kind::Compress).expect("compress dictionary");
        assert!(get_zstd_dict(cdict, Kind::Decompress).is_none());
        let base = Arc::strong_count(&held);
        let compress = call(&mut ctx, "init_compress_nif", &[]).unwrap();
        let ok = atom_term("ok").unwrap();
        assert_eq!(
            call(&mut ctx, "ref_compress_dictionary_nif", &[compress, cdict]).unwrap(),
            ok
        );
        assert_eq!(Arc::strong_count(&held), base + 1);
        assert_eq!(
            call(&mut ctx, "ref_compress_dictionary_nif", &[compress, cdict]).unwrap(),
            ok
        );
        assert_eq!(Arc::strong_count(&held), base + 1);
        assert_eq!(
            call(
                &mut ctx,
                "load_compress_dictionary_nif",
                &[compress, content]
            )
            .unwrap(),
            ok
        );
        assert_eq!(Arc::strong_count(&held), base);
        assert_eq!(
            call(&mut ctx, "ref_compress_dictionary_nif", &[compress, cdict]).unwrap(),
            ok
        );
        assert_eq!(Arc::strong_count(&held), base + 1);
        assert_eq!(
            call(&mut ctx, "compress_close_nif", &[compress]).unwrap(),
            ok
        );
        assert_eq!(Arc::strong_count(&held), base);
        let other = call(&mut ctx, "init_decompress_nif", &[]).unwrap();
        assert!(call(&mut ctx, "ref_decompress_dictionary_nif", &[other, cdict]).is_err());
        assert_eq!(Arc::strong_count(&held), base);
    }
}
