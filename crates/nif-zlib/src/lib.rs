//! OTP 29.1.1 `zlib` and `zstd` NIFs backed by stock zlib and zstd 1.5.7.
//!
//! `zlib` resource handles are local refs until stage 4 adds VM resource terms. The
//! `call_with_pid` entry point checks the owner; the `zlib` entries of `lookup` use an
//! anonymous caller because the frozen `Ctx` contract has no process identity yet.
//!
//! The `zstd` NIFs take their arguments as terms. Their resources are magic references
//! and `enif_self` is the scheduler thread's current process ([`set_scheduler_caller`]), or the
//! process a dirty `zstd` job pins with [`with_caller`].

use std::cell::Cell;
use std::sync::Arc;

use arinsal_bifs::{BifError, BifFn, Ctx};
use arinsal_etf::OwnedTerm as O;
use arinsal_term::{ExportEntry, FunEntry, HeapAlloc, Node, Term, from_owned, to_owned};
use num_traits::ToPrimitive;

mod zlib;
mod zstd;

pub(crate) type Outcome = Result<O, Fault>;

thread_local! {
    static CALLER: Cell<Option<Option<Term>>> = const { Cell::new(None) };
}

static SCHEDULER_CALLER: std::sync::OnceLock<fn() -> Option<Term>> = std::sync::OnceLock::new();

/// Name the function that reports the process a scheduler thread runs.
///
/// This is `enif_self` for the `zstd` NIFs: `BifFn` has no process identity, so the NIF reads
/// the scheduler's current process (erts' `esdp->current_process`) when it needs it, instead
/// of the scheduler storing the pid on every slice. The function returns an immediate local
/// pid term, `None` outside a scheduler.
pub fn set_scheduler_caller(current: fn() -> Option<Term>) {
    let _ = SCHEDULER_CALLER.set(current);
}

/// Pin the process that runs the built-in `zstd` NIFs on this thread, overriding the
/// scheduler's current process until the previous pin is restored.
pub fn set_caller(pid: Option<Term>) {
    CALLER.with(|caller| caller.set(Some(pid)));
}

/// Run `f` with `pid` pinned as the calling process, then restore the previous pin.
pub fn with_caller<R>(pid: Option<Term>, f: impl FnOnce() -> R) -> R {
    let previous = CALLER.with(|pinned| pinned.replace(Some(pid)));
    let result = f();
    CALLER.with(|pinned| pinned.set(previous));
    result
}

/// The calling process: the pinned one, else the scheduler thread's current process.
pub(crate) fn caller() -> Option<Term> {
    CALLER
        .with(Cell::get)
        .unwrap_or_else(|| SCHEDULER_CALLER.get().and_then(|current| current()))
}

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
    fn link_bin_ref(
        &mut self,
        bin_ref: *mut u64,
        writable: bool,
        overhead_words: u64,
        owner: Option<arinsal_term::OwnedBinaryRef>,
    ) -> Result<(), arinsal_term::TermError> {
        HeapAlloc::link_bin_ref(self.0, bin_ref, writable, overhead_words, owner)
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
    fn link_node(&mut self, thing: *mut u64, value: Arc<Node>) {
        self.0.link_node(thing, value)
    }
    fn retain_fun(&mut self, value: Arc<FunEntry>) {
        self.0.retain_fun(value)
    }
    fn retain_export(&mut self, value: Arc<ExportEntry>) {
        self.0.retain_export(value)
    }
    fn link_magic_ref(
        &mut self,
        thing: *mut u64,
        value: Arc<arinsal_term::MagicRef>,
    ) -> Result<(), arinsal_term::TermError> {
        self.0.link_magic_ref(thing, value)
    }
    fn supports_magic(&self) -> bool {
        self.0.supports_magic()
    }
}

/// Invoke a registered NIF with the VM caller PID for resource ownership checks.
/// `caller` must be a local PID term. `None` is reserved for the frozen `BifFn`
/// compatibility path. A `zstd` NIF runs with `caller` as its [`set_caller`] process.
pub fn call_with_pid(
    ctx: &mut Ctx<'_>,
    module: &str,
    name: &str,
    args: &[Term],
    caller: Option<Term>,
) -> Result<Term, BifError> {
    if module == "zstd" {
        let function = u8::try_from(args.len())
            .ok()
            .and_then(|arity| zstd::lookup(name, arity))
            .ok_or(BifError::Unsupported("unknown NIF"))?;
        let previous = CALLER.with(|pinned| pinned.replace(Some(caller)));
        let result = function(ctx, args);
        CALLER.with(|pinned| pinned.set(previous));
        return result;
    }
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
        ("zstd", name, arity) => return zstd::lookup(name, arity),
        _ => return None,
    })
}

/// `zstd` NIF entries in `nif_funcs` order: name, arity and whether erts flags the entry
/// `ERL_NIF_DIRTY_JOB_CPU_BOUND`.
pub(crate) const ZSTD_NIF_FUNCS: [(&str, u8, bool); 24] = [
    ("init_compress_nif", 0, false),
    ("init_decompress_nif", 0, false),
    ("load_compress_dictionary_nif", 2, true),
    ("ref_compress_dictionary_nif", 2, false),
    ("set_compress_parameter_nif", 3, false),
    ("get_compress_parameter_nif", 2, false),
    ("set_pledged_src_size_nif", 2, false),
    ("load_decompress_dictionary_nif", 2, true),
    ("ref_decompress_dictionary_nif", 2, false),
    ("set_decompress_parameter_nif", 3, false),
    ("get_decompress_parameter_nif", 2, false),
    ("compress_stream_nif", 3, false),
    ("decompress_stream_nif", 3, false),
    ("compress_reset_nif", 1, false),
    ("decompress_reset_nif", 1, false),
    ("compress_close_nif", 1, false),
    ("decompress_close_nif", 1, false),
    ("create_cdict_nif", 2, true),
    ("create_ddict_nif", 1, true),
    ("getDictId_fromCDict_nif", 1, false),
    ("getDictId_fromDDict_nif", 1, false),
    ("getDictId_fromDict_nif", 1, false),
    ("getDictId_fromFrame_nif", 1, false),
    ("get_frame_header_nif", 1, false),
];

/// Whether the built-in `zstd` NIF `name/arity` runs on a dirty CPU scheduler
/// (`ERL_NIF_DIRTY_JOB_CPU_BOUND` in erts' `nif_funcs`).
pub fn dirty_cpu(module: &str, name: &str, arity: u8) -> bool {
    module == "zstd"
        && ZSTD_NIF_FUNCS
            .iter()
            .any(|&(entry, entry_arity, dirty)| dirty && entry == name && entry_arity == arity)
}

#[cfg(test)]
mod tests;
