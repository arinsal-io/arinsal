//! OTP 29.1.1 `zlib` and `zstd` NIFs backed by stock zlib and zstd 1.5.7.
//!
//! Resource handles are local refs until stage 4 adds VM resource terms. The
//! `call_with_pid` entry point checks the owner; `lookup` uses an anonymous
//! caller because the frozen `Ctx` contract has no process identity yet.

use std::sync::Arc;

use arinsal_bifs::{BifError, BifFn, Ctx};
use arinsal_etf::OwnedTerm as O;
use arinsal_term::{ExportEntry, FunEntry, HeapAlloc, Node, Term, from_owned, to_owned};
use num_traits::ToPrimitive;

mod zlib;
mod zstd;

pub(crate) type Outcome = Result<O, Fault>;

#[derive(Debug)]
pub(crate) enum Fault {
    Badarg,
    Reason(O),
}

pub(crate) fn atom(name: &str) -> O {
    O::atom(name)
}
pub(crate) fn tuple(items: impl Into<Vec<O>>) -> O {
    O::Tuple(items.into())
}
pub(crate) fn pair(a: O, b: O) -> O {
    tuple(vec![a, b])
}
pub(crate) fn number(n: &O) -> Result<i32, Fault> {
    match n {
        O::Int(x) => (*x).try_into().map_err(|_| Fault::Badarg),
        O::BigInt(x) => x.to_i32().ok_or(Fault::Badarg),
        _ => Err(Fault::Badarg),
    }
}
pub(crate) fn unsigned(n: &O) -> Result<u64, Fault> {
    match n {
        O::Int(x) => (*x).try_into().map_err(|_| Fault::Badarg),
        O::BigInt(x) => x.to_u64().ok_or(Fault::Badarg),
        _ => Err(Fault::Badarg),
    }
}
pub(crate) fn int(n: u64) -> O {
    i64::try_from(n)
        .map(O::Int)
        .unwrap_or_else(|_| O::BigInt(n.into()))
}
pub(crate) fn bytes(term: &O) -> Result<Vec<u8>, Fault> {
    fn append(term: &O, out: &mut Vec<u8>, depth: usize) -> Result<(), Fault> {
        if depth > 1024 {
            return Err(Fault::Badarg);
        }
        match term {
            O::Binary(b) => out.extend_from_slice(b),
            O::Nil => {}
            O::Int(n) if (0..=255).contains(n) => out.push(*n as u8),
            O::List { elems, tail } => {
                for elem in elems {
                    append(elem, out, depth + 1)?;
                }
                append(tail, out, depth + 1)?;
            }
            _ => return Err(Fault::Badarg),
        }
        Ok(())
    }
    let mut out = Vec::new();
    append(term, &mut out, 0)?;
    Ok(out)
}
pub(crate) fn reference(magic: u32, id: u64) -> O {
    O::Ref {
        node: "nonode@nohost".into(),
        creation: 0,
        ids: vec![magic, id as u32, (id >> 32) as u32],
    }
}
pub(crate) fn reference_id(term: &O, magic: u32) -> Result<u64, Fault> {
    match term {
        O::Ref {
            node,
            creation,
            ids,
        } if node == "nonode@nohost" && *creation == 0 && ids.len() == 3 && ids[0] == magic => {
            Ok(u64::from(ids[1]) | (u64::from(ids[2]) << 32))
        }
        _ => Err(Fault::Badarg),
    }
}
pub(crate) fn owner_check(expected: &Option<O>, caller: &Option<O>) -> Result<(), Fault> {
    if expected == caller {
        Ok(())
    } else {
        Err(Fault::Reason(atom("not_on_controlling_process")))
    }
}

struct Heap<'a, H: HeapAlloc + ?Sized>(&'a mut H);
impl<H: HeapAlloc + ?Sized> HeapAlloc for Heap<'_, H> {
    fn alloc(&mut self, words: usize) -> Option<*mut u64> {
        self.0.alloc(words)
    }
    fn retain_binary(&mut self, value: Arc<arinsal_term::RefcBinary>) {
        self.0.retain_binary(value)
    }
    fn retain_writable_binary(
        &mut self,
        value: Arc<arinsal_term::WritableBinary>,
    ) -> Result<(), arinsal_term::TermError> {
        self.0.retain_writable_binary(value)
    }
    fn supports_writable_binary(&self) -> bool {
        self.0.supports_writable_binary()
    }
    fn retain_node(&mut self, value: Arc<Node>) {
        self.0.retain_node(value)
    }
    fn retain_fun(&mut self, value: Arc<FunEntry>) {
        self.0.retain_fun(value)
    }
    fn retain_export(&mut self, value: Arc<ExportEntry>) {
        self.0.retain_export(value)
    }
}

/// Invoke a registered NIF with the VM caller PID for resource ownership checks.
/// `caller` must be a local PID term, supplied by the VM when it gains pid-aware
/// NIF dispatch. `None` is reserved for the frozen `BifFn` compatibility path.
pub fn call_with_pid(
    ctx: &mut Ctx<'_>,
    module: &str,
    name: &str,
    args: &[Term],
    caller: Option<Term>,
) -> Result<Term, BifError> {
    let owned = args
        .iter()
        .map(|t| to_owned(*t).map_err(|_| BifError::BADARG))
        .collect::<Result<Vec<_>, _>>()?;
    let pid = caller
        .map(|t| to_owned(t).map_err(|_| BifError::BADARG))
        .transpose()?;
    if !matches!(pid, None | Some(O::Pid { .. })) {
        return Err(BifError::BADARG);
    }
    let result = match module {
        "zlib" => zlib::dispatch(name, &owned, &pid),
        "zstd" => zstd::dispatch(name, &owned, &pid),
        _ => return Err(BifError::Unsupported("unknown NIF module")),
    };
    let mut heap = Heap(&mut ctx.heap);
    match result {
        Ok(term) => from_owned(&term, &mut heap).map_err(|_| BifError::SystemLimit),
        Err(Fault::Badarg) => Err(BifError::BADARG),
        Err(Fault::Reason(reason)) => Err(BifError::Error(
            from_owned(&reason, &mut heap).map_err(|_| BifError::SystemLimit)?,
        )),
    }
}

macro_rules! entry {
    ($function:ident, $module:literal, $name:literal) => {
        fn $function(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
            call_with_pid(ctx, $module, $name, args, None)
        }
    };
}
entry!(z_open, "zlib", "open_nif");
entry!(z_close, "zlib", "close_nif");
entry!(z_controller, "zlib", "set_controller_nif");
entry!(z_di, "zlib", "deflateInit_nif");
entry!(z_dsd, "zlib", "deflateSetDictionary_nif");
entry!(z_dr, "zlib", "deflateReset_nif");
entry!(z_de, "zlib", "deflateEnd_nif");
entry!(z_dp, "zlib", "deflateParams_nif");
entry!(z_d, "zlib", "deflate_nif");
entry!(z_ii, "zlib", "inflateInit_nif");
entry!(z_isd, "zlib", "inflateSetDictionary_nif");
entry!(z_igd, "zlib", "inflateGetDictionary_nif");
entry!(z_ir, "zlib", "inflateReset_nif");
entry!(z_ie, "zlib", "inflateEnd_nif");
entry!(z_i, "zlib", "inflate_nif");
entry!(z_cs, "zlib", "clearStash_nif");
entry!(z_ss, "zlib", "setStash_nif");
entry!(z_gs, "zlib", "getStash_nif");
entry!(z_enq, "zlib", "enqueue_nif");
entry!(s_ic, "zstd", "init_compress_nif");
entry!(s_id, "zstd", "init_decompress_nif");
entry!(s_lcd, "zstd", "load_compress_dictionary_nif");
entry!(s_l2d, "zstd", "load_decompress_dictionary_nif");
entry!(s_rcd, "zstd", "ref_compress_dictionary_nif");
entry!(s_rdd, "zstd", "ref_decompress_dictionary_nif");
entry!(s_scp, "zstd", "set_compress_parameter_nif");
entry!(s_gcp, "zstd", "get_compress_parameter_nif");
entry!(s_sdp, "zstd", "set_decompress_parameter_nif");
entry!(s_gdp, "zstd", "get_decompress_parameter_nif");
entry!(s_ps, "zstd", "set_pledged_src_size_nif");
entry!(s_c, "zstd", "compress_stream_nif");
entry!(s_d, "zstd", "decompress_stream_nif");
entry!(s_cr, "zstd", "compress_reset_nif");
entry!(s_dr, "zstd", "decompress_reset_nif");
entry!(s_cc, "zstd", "compress_close_nif");
entry!(s_dc, "zstd", "decompress_close_nif");
entry!(s_cd, "zstd", "create_cdict_nif");
entry!(s_dd, "zstd", "create_ddict_nif");
entry!(s_gcid, "zstd", "getDictId_fromCDict_nif");
entry!(s_gdid, "zstd", "getDictId_fromDDict_nif");
entry!(s_gid, "zstd", "getDictId_fromDict_nif");
entry!(s_gfid, "zstd", "getDictId_fromFrame_nif");
entry!(s_fh, "zstd", "get_frame_header_nif");

/// Return the implementation of a `zlib` or `zstd` NIF entry.
pub fn lookup(module: &str, name: &str, arity: u8) -> Option<BifFn> {
    Some(match (module, name, arity) {
        ("zlib", "open_nif", 0) => z_open,
        ("zlib", "close_nif", 1) => z_close,
        ("zlib", "set_controller_nif", 2) => z_controller,
        ("zlib", "deflateInit_nif", 6) => z_di,
        ("zlib", "deflateSetDictionary_nif", 2) => z_dsd,
        ("zlib", "deflateReset_nif", 1) => z_dr,
        ("zlib", "deflateEnd_nif", 1) => z_de,
        ("zlib", "deflateParams_nif", 3) => z_dp,
        ("zlib", "deflate_nif", 4) => z_d,
        ("zlib", "inflateInit_nif", 3) => z_ii,
        ("zlib", "inflateSetDictionary_nif", 2) => z_isd,
        ("zlib", "inflateGetDictionary_nif", 1) => z_igd,
        ("zlib", "inflateReset_nif", 1) => z_ir,
        ("zlib", "inflateEnd_nif", 1) => z_ie,
        ("zlib", "inflate_nif", 4) => z_i,
        ("zlib", "clearStash_nif", 1) => z_cs,
        ("zlib", "setStash_nif", 2) => z_ss,
        ("zlib", "getStash_nif", 1) => z_gs,
        ("zlib", "enqueue_nif", 2) => z_enq,
        ("zstd", "init_compress_nif", 0) => s_ic,
        ("zstd", "init_decompress_nif", 0) => s_id,
        ("zstd", "load_compress_dictionary_nif", 2) => s_lcd,
        ("zstd", "load_decompress_dictionary_nif", 2) => s_l2d,
        ("zstd", "ref_compress_dictionary_nif", 2) => s_rcd,
        ("zstd", "ref_decompress_dictionary_nif", 2) => s_rdd,
        ("zstd", "set_compress_parameter_nif", 3) => s_scp,
        ("zstd", "get_compress_parameter_nif", 2) => s_gcp,
        ("zstd", "set_decompress_parameter_nif", 3) => s_sdp,
        ("zstd", "get_decompress_parameter_nif", 2) => s_gdp,
        ("zstd", "set_pledged_src_size_nif", 2) => s_ps,
        ("zstd", "compress_stream_nif", 3) => s_c,
        ("zstd", "decompress_stream_nif", 3) => s_d,
        ("zstd", "compress_reset_nif", 1) => s_cr,
        ("zstd", "decompress_reset_nif", 1) => s_dr,
        ("zstd", "compress_close_nif", 1) => s_cc,
        ("zstd", "decompress_close_nif", 1) => s_dc,
        ("zstd", "create_cdict_nif", 2) => s_cd,
        ("zstd", "create_ddict_nif", 1) => s_dd,
        ("zstd", "getDictId_fromCDict_nif", 1) => s_gcid,
        ("zstd", "getDictId_fromDDict_nif", 1) => s_gdid,
        ("zstd", "getDictId_fromDict_nif", 1) => s_gid,
        ("zstd", "getDictId_fromFrame_nif", 1) => s_gfid,
        ("zstd", "get_frame_header_nif", 1) => s_fh,
        _ => return None,
    })
}

#[cfg(test)]
mod tests;
