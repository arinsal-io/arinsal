//! Port of erts/emulator/nifs/common/zstd_nif.c, OTP-29.1.1.

use std::collections::HashMap;
use std::ffi::{CStr, c_void};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use arinsal_etf::OwnedTerm as O;
use zstd_sys as z;

use crate::{
    Fault, Outcome, atom, bytes, int, number, owner_check, pair, reference, reference_id, tuple,
    unsigned,
};

const CMAGIC: u32 = 0x5a53_5443;
const DMAGIC: u32 = 0x5a53_5444;
const CDMAGIC: u32 = 0x5a53_4344;
const DDMAGIC: u32 = 0x5a53_4444;
static NEXT_ID: AtomicU64 = AtomicU64::new(1);
unsafe extern "C" {
    #[link_name = "ZSTD_compressStream2"]
    fn compress_stream_any(
        ctx: *mut z::ZSTD_CCtx,
        output: *mut z::ZSTD_outBuffer,
        input: *mut z::ZSTD_inBuffer,
        directive: i32,
    ) -> usize;
}
unsafe extern "C" fn alloc(_: *mut c_void, size: usize) -> *mut c_void {
    // SAFETY: libc returns a suitably aligned allocation for zstd.
    unsafe { libc::malloc(size) }
}
unsafe extern "C" fn free(_: *mut c_void, ptr: *mut c_void) {
    // SAFETY: zstd passes only pointers allocated by `alloc`.
    unsafe { libc::free(ptr) }
}
static CONTEXTS: OnceLock<Mutex<HashMap<u64, Arc<Mutex<Context>>>>> = OnceLock::new();
static DICTS: OnceLock<Mutex<HashMap<u64, Arc<Dict>>>> = OnceLock::new();
fn contexts() -> &'static Mutex<HashMap<u64, Arc<Mutex<Context>>>> {
    CONTEXTS.get_or_init(|| Mutex::new(HashMap::new()))
}
fn dicts() -> &'static Mutex<HashMap<u64, Arc<Dict>>> {
    DICTS.get_or_init(|| Mutex::new(HashMap::new()))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Compress,
    Decompress,
}
struct Context {
    ptr: *mut c_void,
    kind: Kind,
    owner: Option<O>,
    referenced_dict: Option<Arc<Dict>>,
    in_use: bool,
}
// SAFETY: a context is used only while its Mutex is held; zstd never shares it.
unsafe impl Send for Context {}
impl Drop for Context {
    fn drop(&mut self) {
        self.close();
    }
}
impl Context {
    fn close(&mut self) {
        if !self.ptr.is_null() {
            // SAFETY: ptr came from the matching zstd context constructor.
            unsafe {
                if self.kind == Kind::Compress {
                    z::ZSTD_freeCCtx(self.ptr.cast());
                } else {
                    z::ZSTD_freeDCtx(self.ptr.cast());
                }
            }
            self.ptr = std::ptr::null_mut();
            self.referenced_dict = None;
        }
    }
}
struct Dict {
    ptr: *mut c_void,
    kind: Kind,
    _data: Vec<u8>,
}
// SAFETY: digested dictionaries are immutable and zstd permits shared use.
unsafe impl Send for Dict {}
// SAFETY: digested dictionaries are immutable and zstd permits shared use.
unsafe impl Sync for Dict {}
impl Drop for Dict {
    fn drop(&mut self) {
        // SAFETY: ptr came from the matching zstd dictionary constructor.
        unsafe {
            if self.kind == Kind::Compress {
                z::ZSTD_freeCDict(self.ptr.cast());
            } else {
                z::ZSTD_freeDDict(self.ptr.cast());
            }
        }
    }
}
fn zerror(code: usize) -> Fault {
    // SAFETY: zstd returns a static NUL-terminated error name for any code.
    let name = unsafe { CStr::from_ptr(z::ZSTD_getErrorName(code)) }
        .to_bytes()
        .to_vec();
    Fault::Reason(pair(atom("zstd_error"), O::Binary(name)))
}
fn checked(code: usize) -> Result<(), Fault> {
    // SAFETY: any zstd result may be passed to ZSTD_isError.
    if unsafe { z::ZSTD_isError(code) } != 0 {
        Err(zerror(code))
    } else {
        Ok(())
    }
}
fn bad_key(key: &O) -> Fault {
    Fault::Reason(pair(atom("badarg"), pair(atom("invalid_key"), key.clone())))
}
fn bad_value(value: &O) -> Fault {
    Fault::Reason(pair(
        atom("badarg"),
        pair(atom("invalid_value"), value.clone()),
    ))
}
fn context(value: &O, kind: Kind) -> Result<Arc<Mutex<Context>>, Fault> {
    let magic = if kind == Kind::Compress {
        CMAGIC
    } else {
        DMAGIC
    };
    let id = reference_id(value, magic)?;
    let ctx = contexts()
        .lock()
        .unwrap()
        .get(&id)
        .cloned()
        .ok_or(Fault::Badarg)?;
    Ok(ctx)
}
fn dict(value: &O, kind: Kind) -> Result<Arc<Dict>, Fault> {
    let magic = if kind == Kind::Compress {
        CDMAGIC
    } else {
        DDMAGIC
    };
    let id = reference_id(value, magic)?;
    let d = dicts()
        .lock()
        .unwrap()
        .get(&id)
        .cloned()
        .ok_or(Fault::Badarg)?;
    Ok(d)
}
fn cparam(value: &O) -> Result<z::ZSTD_cParameter, Fault> {
    use z::ZSTD_cParameter as P;
    let O::Atom(key) = value else {
        return Err(bad_key(value));
    };
    Ok(match key.as_str() {
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
        _ => return Err(bad_key(value)),
    })
}
fn dparam(value: &O) -> Result<z::ZSTD_dParameter, Fault> {
    if value == &atom("windowLogMax") {
        Ok(z::ZSTD_dParameter::ZSTD_d_windowLogMax)
    } else {
        Err(bad_key(value))
    }
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
fn param_value(p: z::ZSTD_cParameter, value: &O) -> Result<i32, Fault> {
    if p == z::ZSTD_cParameter::ZSTD_c_strategy {
        if value == &atom("default") {
            return Ok(0);
        }
        if let O::Atom(s) = value
            && let Some(i) = STRATEGIES.iter().position(|v| *v == s)
        {
            return Ok(i as i32 + 1);
        }
        Err(bad_value(value))
    } else if boolean_param(p) {
        if value == &atom("true") {
            Ok(1)
        } else if value == &atom("false") {
            Ok(0)
        } else {
            Err(bad_value(value))
        }
    } else {
        number(value).map_err(|_| bad_value(value))
    }
}
fn stream(ctx: &mut Context, data: &O, flush: &O) -> Outcome {
    let O::Binary(input) = data else {
        return Err(Fault::Badarg);
    };
    // Port of zstd_nif.c:730, OTP-29.1.1. The direct NIF accepts this
    // special atom although the public Erlang wrapper passes integer 2.
    if ctx.kind == Kind::Decompress && !ctx.in_use && input.is_empty() && flush == &atom("true") {
        return Ok(pair(atom("done"), O::Binary(Vec::new())));
    }
    let directive = number(flush)?;
    let mut out_len = {
        // SAFETY: size functions have no preconditions.
        unsafe {
            if ctx.kind == Kind::Compress {
                z::ZSTD_CStreamOutSize()
            } else {
                z::ZSTD_DStreamOutSize()
            }
        }
    };
    if ctx.kind == Kind::Decompress && !ctx.in_use {
        // Port of zstd_nif.c:731 (decompress_stream_nif), OTP-29.1.1.
        // SAFETY: input's allocation remains live during this call.
        let size = unsafe { z::ZSTD_findDecompressedSize(input.as_ptr().cast(), input.len()) };
        if size < out_len as u64 {
            out_len = size as usize;
        }
        ctx.in_use = true;
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
        // SAFETY: context matches the selected codec and both buffers remain live.
        let result = unsafe {
            if ctx.kind == Kind::Compress {
                compress_stream_any(ctx.ptr.cast(), &mut ob, &mut ib, directive)
            } else {
                z::ZSTD_decompressStream(ctx.ptr.cast(), &mut ob, &mut ib)
            }
        };
        if let Err(error) = checked(result) {
            // SAFETY: the reset directive is valid for either context kind.
            unsafe {
                if ctx.kind == Kind::Compress {
                    z::ZSTD_CCtx_reset(
                        ctx.ptr.cast(),
                        z::ZSTD_ResetDirective::ZSTD_reset_session_only,
                    );
                } else {
                    z::ZSTD_DCtx_reset(
                        ctx.ptr.cast(),
                        z::ZSTD_ResetDirective::ZSTD_reset_session_only,
                    );
                }
            }
            ctx.in_use = false;
            return Err(error);
        }
        remaining = result;
        if ib.pos >= ib.size || ob.pos >= ob.size {
            break;
        }
    }
    out.truncate(ob.pos);
    let output = O::Binary(out);
    if directive != 0 && ib.pos == ib.size {
        let tag = if ob.pos == ob.size && remaining > 0 {
            "flush"
        } else {
            "done"
        };
        Ok(pair(atom(tag), output))
    } else if ib.pos < ib.size {
        Ok(tuple(vec![
            atom("continue"),
            O::Binary(input[ib.pos..].to_vec()),
            output,
        ]))
    } else {
        Ok(pair(atom("continue"), output))
    }
}
fn new_context(kind: Kind, caller: &Option<O>) -> Outcome {
    // SAFETY: constructors return an independently owned context pointer.
    let ptr: *mut c_void = unsafe {
        if kind == Kind::Compress {
            z::ZSTD_createCCtx().cast()
        } else {
            z::ZSTD_createDCtx().cast()
        }
    };
    if ptr.is_null() {
        return Err(Fault::Reason(atom("error")));
    }
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    contexts().lock().unwrap().insert(
        id,
        Arc::new(Mutex::new(Context {
            ptr,
            kind,
            owner: caller.clone(),
            referenced_dict: None,
            in_use: false,
        })),
    );
    Ok(reference(
        if kind == Kind::Compress {
            CMAGIC
        } else {
            DMAGIC
        },
        id,
    ))
}
fn new_dict(kind: Kind, input: &O, level: Option<&O>) -> Outcome {
    let O::Binary(data) = input else {
        return Err(Fault::Badarg);
    };
    let level = level.map(number).transpose()?.unwrap_or(0);
    let stored = data.clone();
    // Port of zstd_nif.c:831 and :883 (create_cdict_nif/create_ddict_nif), OTP-29.1.1.
    // SAFETY: the owned `stored` allocation remains stable for the life of Dict.
    let ptr: *mut c_void = unsafe {
        let memory = z::ZSTD_customMem {
            customAlloc: Some(alloc),
            customFree: Some(free),
            opaque: std::ptr::null_mut(),
        };
        if kind == Kind::Compress {
            let params = z::ZSTD_getCParams(level, 0, stored.len());
            z::ZSTD_createCDict_advanced(
                stored.as_ptr().cast(),
                stored.len(),
                z::ZSTD_dictLoadMethod_e::ZSTD_dlm_byRef,
                z::ZSTD_dictContentType_e::ZSTD_dct_auto,
                params,
                memory,
            )
            .cast()
        } else {
            z::ZSTD_createDDict_advanced(
                stored.as_ptr().cast(),
                stored.len(),
                z::ZSTD_dictLoadMethod_e::ZSTD_dlm_byRef,
                z::ZSTD_dictContentType_e::ZSTD_dct_auto,
                memory,
            )
            .cast()
        }
    };
    if ptr.is_null() {
        return Ok(pair(
            atom("error"),
            atom(if kind == Kind::Compress {
                "invalid_compress_dict"
            } else {
                "invalid_decompress_dict"
            }),
        ));
    }
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    dicts().lock().unwrap().insert(
        id,
        Arc::new(Dict {
            ptr,
            kind,
            _data: stored,
        }),
    );
    Ok(reference(
        if kind == Kind::Compress {
            CDMAGIC
        } else {
            DDMAGIC
        },
        id,
    ))
}
fn frame_header(input: &O) -> Outcome {
    let data = bytes(input)?;
    // SAFETY: this C POD may be zero initialized before ZSTD_getFrameHeader fills it.
    let mut hdr: z::ZSTD_FrameHeader = unsafe { std::mem::zeroed() };
    // SAFETY: the data remains live during header decoding.
    let result = unsafe { z::ZSTD_getFrameHeader(&mut hdr, data.as_ptr().cast(), data.len()) };
    checked(result)?;
    if result > 0 {
        return Err(Fault::Badarg);
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
        (atom("blockSizeMax"), int(hdr.blockSizeMax as u64)),
        (
            atom("frameType"),
            atom(if hdr.frameType == z::ZSTD_FrameType_e::ZSTD_frame {
                "ZSTD_frame"
            } else {
                "ZSTD_skippableFrame"
            }),
        ),
        (atom("headerSize"), int(hdr.headerSize as u64)),
        (atom("dictID"), int(hdr.dictID as u64)),
        (
            atom("checksumFlag"),
            atom(if hdr.checksumFlag != 0 {
                "true"
            } else {
                "false"
            }),
        ),
    ];
    Ok(pair(atom("ok"), O::Map(fields)))
}

pub(super) fn dispatch(name: &str, args: &[O], caller: &Option<O>) -> Outcome {
    match (name, args) {
        ("init_compress_nif", []) => return new_context(Kind::Compress, caller),
        ("init_decompress_nif", []) => return new_context(Kind::Decompress, caller),
        ("create_cdict_nif", [data, level]) => return new_dict(Kind::Compress, data, Some(level)),
        ("create_ddict_nif", [data]) => return new_dict(Kind::Decompress, data, None),
        ("getDictId_fromCDict_nif", [term]) => {
            let d = dict(term, Kind::Compress)?;
            // SAFETY: the dictionary pointer is valid while Arc is held.
            return Ok(int(
                unsafe { z::ZSTD_getDictID_fromCDict(d.ptr.cast()) } as u64
            ));
        }
        ("getDictId_fromDDict_nif", [term]) => {
            let d = dict(term, Kind::Decompress)?;
            // SAFETY: the dictionary pointer is valid while Arc is held.
            return Ok(int(
                unsafe { z::ZSTD_getDictID_fromDDict(d.ptr.cast()) } as u64
            ));
        }
        ("getDictId_fromDict_nif", [term]) | ("getDictId_fromFrame_nif", [term]) => {
            let data = bytes(term)?;
            // SAFETY: zstd reads only the supplied data bytes.
            let id = unsafe {
                if name == "getDictId_fromDict_nif" {
                    z::ZSTD_getDictID_fromDict(data.as_ptr().cast(), data.len())
                } else {
                    z::ZSTD_getDictID_fromFrame(data.as_ptr().cast(), data.len())
                }
            };
            return Ok(int(id as u64));
        }
        ("get_frame_header_nif", [term]) => return frame_header(term),
        _ => {}
    }
    let Some(first) = args.first() else {
        return Err(Fault::Badarg);
    };
    let kind = if name.contains("decompress") {
        Kind::Decompress
    } else {
        Kind::Compress
    };
    let c = context(first, kind)?;
    let mut c = c.lock().unwrap();
    if c.ptr.is_null() {
        return Err(Fault::Badarg);
    }
    owner_check(&c.owner, caller)?;
    match (name, args) {
        ("compress_close_nif" | "decompress_close_nif", [_]) => {
            c.close();
            Ok(atom("ok"))
        }
        ("compress_reset_nif" | "decompress_reset_nif", [_]) => {
            // SAFETY: the resource pointer matches the selected reset function.
            unsafe {
                if kind == Kind::Compress {
                    z::ZSTD_CCtx_reset(
                        c.ptr.cast(),
                        z::ZSTD_ResetDirective::ZSTD_reset_session_only,
                    );
                } else {
                    z::ZSTD_DCtx_reset(
                        c.ptr.cast(),
                        z::ZSTD_ResetDirective::ZSTD_reset_session_only,
                    );
                }
            }
            c.in_use = false;
            Ok(atom("ok"))
        }
        ("load_compress_dictionary_nif" | "load_decompress_dictionary_nif", [_, term]) => {
            let data = bytes(term)?;
            c.referenced_dict = None;
            // SAFETY: zstd copies the dictionary into the live context.
            let result = unsafe {
                if kind == Kind::Compress {
                    z::ZSTD_CCtx_loadDictionary(c.ptr.cast(), data.as_ptr().cast(), data.len())
                } else {
                    z::ZSTD_DCtx_loadDictionary(c.ptr.cast(), data.as_ptr().cast(), data.len())
                }
            };
            checked(result)?;
            Ok(atom("ok"))
        }
        ("ref_compress_dictionary_nif" | "ref_decompress_dictionary_nif", [_, term]) => {
            let d = dict(term, kind)?;
            // SAFETY: Arc keeps the referenced dictionary alive with the context.
            let result = unsafe {
                if kind == Kind::Compress {
                    z::ZSTD_CCtx_refCDict(c.ptr.cast(), d.ptr.cast())
                } else {
                    z::ZSTD_DCtx_refDDict(c.ptr.cast(), d.ptr.cast())
                }
            };
            checked(result)?;
            c.referenced_dict = Some(d);
            Ok(atom("ok"))
        }
        ("set_compress_parameter_nif", [_, key, value]) => {
            let p = cparam(key)?;
            let value = param_value(p, value)?;
            // SAFETY: the resource contains a live compression context.
            checked(unsafe { z::ZSTD_CCtx_setParameter(c.ptr.cast(), p, value) })?;
            Ok(atom("ok"))
        }
        ("get_compress_parameter_nif", [_, key]) => {
            let p = cparam(key)?;
            let mut value = 0;
            // SAFETY: the resource contains a live compression context.
            checked(unsafe { z::ZSTD_CCtx_getParameter(c.ptr.cast(), p, &mut value) })?;
            // Port of zstd_nif.c:463, OTP-29.1.1: the NIF converts the
            // success return code, rather than the fetched value, to bool.
            if boolean_param(p) {
                Ok(atom("false"))
            } else if p == z::ZSTD_cParameter::ZSTD_c_strategy {
                Ok(atom(if value == 0 {
                    "default"
                } else {
                    STRATEGIES.get((value - 1) as usize).ok_or(Fault::Badarg)?
                }))
            } else {
                Ok(O::Int(value as i64))
            }
        }
        ("set_decompress_parameter_nif", [_, key, value]) => {
            let v = number(value)?;
            let p = dparam(key)?;
            // SAFETY: the resource contains a live decompression context.
            checked(unsafe { z::ZSTD_DCtx_setParameter(c.ptr.cast(), p, v) })?;
            Ok(atom("ok"))
        }
        ("get_decompress_parameter_nif", [_, key]) => {
            let p = dparam(key)?;
            let mut value = 0;
            // SAFETY: the resource contains a live decompression context.
            checked(unsafe { z::ZSTD_DCtx_getParameter(c.ptr.cast(), p, &mut value) })?;
            Ok(O::Int(value as i64))
        }
        ("set_pledged_src_size_nif", [_, size]) => {
            let n = unsigned(size)?;
            // SAFETY: the resource contains a live compression context.
            checked(unsafe { z::ZSTD_CCtx_setPledgedSrcSize(c.ptr.cast(), n) })?;
            Ok(atom("ok"))
        }
        ("compress_stream_nif" | "decompress_stream_nif", [_, data, flush]) => {
            stream(&mut c, data, flush)
        }
        _ => Err(Fault::Badarg),
    }
}
