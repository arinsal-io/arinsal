//! OTP 29.1.1 `re` BIFs using the patched PCRE2 engine.
//!
//! PCRE2's loop counter is retained in `ar_re_match`; matching resumes there
//! synchronously until scheduler support can pass a reduction budget.

use std::cell::Cell;
use std::ffi::c_void;
use std::ptr;
use std::sync::Arc;

use arinsal_bifs::with_binary_bytes;
use arinsal_bifs::{BifError, BifFn, Ctx, IolistCopyWalk, IolistSizeWalk, for_each_list_term};
use arinsal_etf::OwnedTerm as O;
use arinsal_term::{
    BinaryOwner, HeapAlloc, MagicRef, Node, Term, TermBuilder, TermKind, from_owned, global_atoms,
    to_owned,
};
use num_traits::ToPrimitive;

const ANCHORED: u32 = 0x8000_0000;
const NO_UTF_CHECK: u32 = 0x4000_0000;
const UTF: u32 = 0x0008_0000;
const DUPNAMES: u32 = 0x40;
const INFO_BSR: u32 = 3;
const INFO_CAPTURES: u32 = 4;
const INFO_NAME_COUNT: u32 = 17;
const INFO_NAME_SIZE: u32 = 18;
const INFO_NAME_TABLE: u32 = 19;
const INFO_NEWLINE: u32 = 20;
const UNSET: usize = usize::MAX;
thread_local! {
    static LOOP_BUDGET: Cell<i32> = const { Cell::new(1_000_000) };
    static LAST_LOOP_COUNT: Cell<u64> = const { Cell::new(0) };
}

/// Set the PCRE2 loop budget used between synchronous restarts.
///
/// A scheduler can use this knob with the patched engine until BIF yielding is available.
pub fn set_loop_budget(limit: i32) -> Result<(), BifError> {
    if limit <= 0 {
        return Err(BifError::BADARG);
    }
    LOOP_BUDGET.with(|budget| budget.set(limit));
    Ok(())
}

/// PCRE2 loop iterations consumed by the last match on this thread.
pub fn last_loop_count() -> u64 {
    LAST_LOOP_COUNT.with(Cell::get)
}

#[repr(C)]
struct MatchResult {
    rc: i32,
    loops_consumed: u64,
}

#[repr(C)]
#[derive(Default)]
struct MatchSession {
    data: usize,
    context: usize,
    restart: usize,
}

unsafe extern "C" {
    fn ar_re_compile(
        pattern: *const u8,
        len: usize,
        options: u32,
        newline: u32,
        bsr: u32,
        error: *mut i32,
        offset: *mut usize,
    ) -> *mut c_void;
    fn ar_re_code_free(code: *mut c_void);
    fn ar_re_info_u32(code: *const c_void, what: u32, out: *mut u32) -> i32;
    fn ar_re_info_ptr(code: *const c_void, what: u32, out: *mut *const u8) -> i32;
    fn ar_re_error_message(code: i32, out: *mut u8, cap: usize) -> i32;
    fn ar_re_version(out: *mut u8) -> i32;
    fn ar_re_serialize(code: *const c_void, out: *mut *mut u8, len: *mut usize) -> i32;
    fn ar_re_serial_free(bytes: *mut u8);
    fn ar_re_deserialize(bytes: *const u8, len: usize, code: *mut *mut c_void) -> i32;
    fn ar_re_capture_name(code: *const c_void, name: *const u8) -> i32;
    fn ar_re_capture_name_range(
        code: *const c_void,
        name: *const u8,
        first: *mut *const u8,
        last: *mut *const u8,
    ) -> i32;
    fn ar_re_match(
        code: *const c_void,
        subject: *const u8,
        len: usize,
        offset: usize,
        options: u32,
        match_limit: i32,
        depth_limit: i32,
        ovector: *mut usize,
        ovec_count: u32,
        loop_budget: i32,
        session: *mut MatchSession,
        mode: i32,
    ) -> MatchResult;
}

struct Code(*mut c_void);
impl Drop for Code {
    fn drop(&mut self) {
        // SAFETY: this pointer came from PCRE2 and is owned by this wrapper.
        unsafe { ar_re_code_free(self.0) }
    }
}
impl Code {
    /// The code's address, giving up ownership; a [`RunState`] frees it.
    fn into_raw(self) -> usize {
        let address = self.0 as usize;
        std::mem::forget(self);
        address
    }
    fn info(&self, what: u32) -> u32 {
        let mut value = 0;
        // SAFETY: `self.0` is a live PCRE2 code and `value` is writable.
        let rc = unsafe { ar_re_info_u32(self.0, what, &mut value) };
        assert_eq!(rc, 0, "PCRE2 pattern info");
        value
    }
    fn serialize(&self) -> Result<Vec<u8>, BifError> {
        let mut data = ptr::null_mut();
        let mut len = 0;
        // SAFETY: the output pointers are writable and PCRE2 owns the returned buffer.
        let rc = unsafe { ar_re_serialize(self.0, &mut data, &mut len) };
        if rc != 1 {
            return Err(BifError::SystemLimit);
        }
        // SAFETY: successful serialization returned `len` initialized bytes.
        let bytes = unsafe { std::slice::from_raw_parts(data, len).to_vec() };
        // SAFETY: `data` was allocated by `pcre2_serialize_encode`.
        unsafe { ar_re_serial_free(data) };
        Ok(bytes)
    }
    fn names(&self) -> Vec<(Vec<u8>, u32)> {
        let count = self.info(INFO_NAME_COUNT) as usize;
        if count == 0 {
            return Vec::new();
        }
        let size = self.info(INFO_NAME_SIZE) as usize;
        let mut table = ptr::null();
        // SAFETY: PCRE2 writes the table pointer for this live code.
        let rc = unsafe { ar_re_info_ptr(self.0, INFO_NAME_TABLE, &mut table) };
        assert_eq!(rc, 0);
        let mut out = Vec::with_capacity(count);
        for i in 0..count {
            // SAFETY: PCRE2's name table has `count` entries of `size` bytes.
            let entry = unsafe { std::slice::from_raw_parts(table.add(i * size), size) };
            let end = entry[2..].iter().position(|b| *b == 0).unwrap_or(size - 2);
            out.push((
                entry[2..2 + end].to_vec(),
                u32::from_be_bytes([0, 0, entry[0], entry[1]]),
            ));
        }
        out
    }
}

/// Return the native implementation of an OTP `re` BIF.
pub fn lookup(module: &str, name: &str, arity: u8) -> Option<BifFn> {
    if module != "re" {
        return None;
    }
    Some(match (name, arity) {
        ("version", 0) => version,
        ("compile", 1) => compile_1,
        ("compile", 2) => compile_2,
        ("run", 2) => run_2,
        ("run", 3) => run_3,
        ("internal_run", 4) => internal_run_4,
        ("inspect", 2) => inspect,
        ("import", 1) => import,
        _ => return None,
    })
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
    fn link_magic_ref(
        &mut self,
        thing: *mut u64,
        value: Arc<MagicRef>,
    ) -> Result<(), arinsal_term::TermError> {
        self.0.link_magic_ref(thing, value)
    }
    fn supports_magic(&self) -> bool {
        self.0.supports_magic()
    }
    fn link_node(&mut self, thing: *mut u64, value: Arc<Node>) {
        self.0.link_node(thing, value)
    }
}
fn call(
    ctx: &mut Ctx<'_>,
    args: &[Term],
    op: impl FnOnce(&[O]) -> Result<O, BifError>,
) -> Result<Term, BifError> {
    let args = args
        .iter()
        .map(|term| to_owned(*term).map_err(|_| BifError::BADARG))
        .collect::<Result<Vec<_>, _>>()?;
    let result = op(&args)?;
    from_owned(&result, &mut Heap(&mut ctx.heap)).map_err(|_| BifError::SystemLimit)
}
fn atom(name: &str) -> O {
    O::atom(name)
}
fn pair(a: O, b: O) -> O {
    O::Tuple(vec![a, b])
}
fn success(value: O) -> O {
    pair(atom("ok"), value)
}
fn error(value: O) -> O {
    pair(atom("error"), value)
}
fn atom_name(value: &O) -> Option<&str> {
    if let O::Atom(s) = value {
        Some(s)
    } else {
        None
    }
}
fn number(value: &O) -> Option<i64> {
    match value {
        O::Int(n) => Some(*n),
        O::BigInt(n) => n.to_i64(),
        _ => None,
    }
}
// Port of erts/emulator/beam/erl_bif_re.c (re_compile, re_run), OTP-29.1.1.
fn badopt_error() -> BifError {
    global_atoms()
        .intern("badopt")
        .map(Term::atom)
        .map(|cause| BifError::Badarg { cause: Some(cause) })
        .unwrap_or(BifError::SystemLimit)
}
fn list(value: &O) -> Result<&[O], BifError> {
    match value {
        O::Nil => Ok(&[]),
        O::List { elems, tail } if **tail == O::Nil => Ok(elems),
        _ => Err(BifError::BADARG),
    }
}
fn iodata(value: &O, unicode: bool) -> Result<Vec<u8>, BifError> {
    let mut out = Vec::new();
    fn append_element(value: &O, unicode: bool, out: &mut Vec<u8>) -> Result<(), BifError> {
        match value {
            O::Binary(bytes) => out.extend(bytes),
            O::Nil => (),
            O::List { .. } => append_list(value, unicode, out)?,
            O::Int(n) => {
                if unicode {
                    let ch = u32::try_from(*n)
                        .ok()
                        .and_then(char::from_u32)
                        .ok_or(BifError::BADARG)?;
                    let mut buf = [0; 4];
                    out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                } else {
                    out.push(u8::try_from(*n).map_err(|_| BifError::BADARG)?);
                }
            }
            _ => return Err(BifError::BADARG),
        }
        Ok(())
    }
    fn append_list(value: &O, unicode: bool, out: &mut Vec<u8>) -> Result<(), BifError> {
        let O::List { elems, tail } = value else {
            return append_element(value, unicode, out);
        };
        for item in elems {
            append_element(item, unicode, out)?;
        }
        match tail.as_ref() {
            O::Nil => Ok(()),
            O::Binary(bytes) => {
                out.extend(bytes);
                Ok(())
            }
            O::List { .. } => append_list(tail, unicode, out),
            _ => Err(BifError::BADARG),
        }
    }
    match value {
        O::Binary(bytes) => out.extend(bytes),
        O::Nil => (),
        O::List { .. } => append_list(value, unicode, &mut out)?,
        _ => return Err(BifError::BADARG),
    }
    Ok(out)
}

// Port of erts_iolist_size and erts_iolist_to_buf used by erl_bif_re.c, OTP-29.1.1.
fn term_iodata(value: Term) -> Result<Vec<u8>, BifError> {
    let mut size = IolistSizeWalk::new(value);
    let (complete, _) = size.step(usize::MAX).map_err(|(error, _)| error)?;
    if !complete {
        return Err(BifError::SystemLimit);
    }
    let mut bytes = Vec::new();
    let length = size.take_size();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| BifError::SystemLimit)?;
    bytes.resize(length, 0);
    let mut copy = IolistCopyWalk::new(value);
    let (complete, _) = copy
        .step(&mut bytes, usize::MAX)
        .map_err(|(error, _)| error)?;
    if !complete {
        return Err(BifError::SystemLimit);
    }
    Ok(bytes)
}

#[derive(Default)]
struct Options {
    compile: u32,
    match_flags: u32,
    newline: u32,
    bsr: u32,
    unicode: bool,
    global: bool,
    report_errors: bool,
    export: bool,
    unique_compile: bool,
    unique_exec: bool,
    offset: usize,
    match_limit: i32,
    depth_limit: i32,
    capture: Option<(CaptureSpec, CaptureType)>,
}
#[derive(Clone)]
enum CaptureSpec {
    Owned(O),
    Term(Term),
}
#[derive(Clone, Copy)]
enum CaptureType {
    Index,
    List,
    Binary,
}
fn options(value: &O) -> Result<Options, BifError> {
    // Port of erts/emulator/beam/erl_bif_re.c:310-530 (parse_options), OTP-29.1.1.
    let mut result = Options {
        match_limit: -1,
        depth_limit: -1,
        ..Options::default()
    };
    for item in list(value).map_err(|_| badopt_error())? {
        if let O::Tuple(fields) = item {
            let key = fields
                .first()
                .and_then(atom_name)
                .ok_or_else(badopt_error)?;
            match (key, fields.as_slice()) {
                ("capture", [_, spec]) => {
                    result.capture = Some((CaptureSpec::Owned(spec.clone()), CaptureType::Index));
                    result.unique_exec = true;
                }
                ("capture", [_, spec, ty]) => {
                    let kind = match atom_name(ty) {
                        Some("index") => CaptureType::Index,
                        Some("list") => CaptureType::List,
                        Some("binary") => CaptureType::Binary,
                        _ => return Err(badopt_error()),
                    };
                    result.capture = Some((CaptureSpec::Owned(spec.clone()), kind));
                    result.unique_exec = true;
                }
                ("offset", [_, n]) => {
                    result.offset = usize::try_from(number(n).ok_or_else(badopt_error)?)
                        .map_err(|_| badopt_error())?;
                    if result.offset > i32::MAX as usize {
                        return Err(badopt_error());
                    }
                    result.unique_exec = true;
                }
                ("match_limit", [_, n]) => {
                    result.match_limit = i32::try_from(number(n).ok_or_else(badopt_error)?)
                        .map_err(|_| badopt_error())?;
                    if result.match_limit < 0 {
                        return Err(badopt_error());
                    }
                    result.unique_exec = true;
                }
                ("match_limit_recursion", [_, n]) => {
                    result.depth_limit = i32::try_from(number(n).ok_or_else(badopt_error)?)
                        .map_err(|_| badopt_error())?;
                    if result.depth_limit < 0 {
                        return Err(badopt_error());
                    }
                    result.unique_exec = true;
                }
                ("newline", [_, value]) => {
                    result.newline = match atom_name(value) {
                        Some("cr") => 1,
                        Some("lf") => 2,
                        Some("crlf") => 3,
                        Some("any") => 4,
                        Some("anycrlf") => 5,
                        Some("nul") => 6,
                        _ => return Err(badopt_error()),
                    }
                }
                _ => return Err(badopt_error()),
            }
            continue;
        }
        let name = atom_name(item).ok_or_else(badopt_error)?;
        match name {
            "anchored" => {
                result.compile |= ANCHORED;
                result.match_flags |= ANCHORED;
            }
            "caseless" => result.compile |= 0x8,
            "dollar_endonly" => result.compile |= 0x10,
            "dotall" => result.compile |= 0x20,
            "dupnames" => result.compile |= DUPNAMES,
            "extended" => result.compile |= 0x80,
            "firstline" => result.compile |= 0x100,
            "multiline" => result.compile |= 0x400,
            "never_utf" => result.compile |= 0x1000,
            "no_auto_capture" => result.compile |= 0x2000,
            "no_start_optimize" => result.compile |= 0x10000,
            "ucp" => result.compile |= 0x20000,
            "ungreedy" => result.compile |= 0x40000,
            "unicode" => {
                result.compile |= UTF;
                result.unicode = true;
            }
            "notbol" => result.match_flags |= 1,
            "noteol" => result.match_flags |= 2,
            "notempty" => result.match_flags |= 4,
            "notempty_atstart" => result.match_flags |= 8,
            "bsr_unicode" => result.bsr = 1,
            "bsr_anycrlf" => result.bsr = 2,
            "global" => result.global = true,
            "report_errors" => result.report_errors = true,
            "export" => result.export = true,
            _ => return Err(badopt_error()),
        }
        match name {
            "caseless" | "dollar_endonly" | "dotall" | "dupnames" | "extended" | "firstline"
            | "multiline" | "never_utf" | "no_auto_capture" | "no_start_optimize" | "ucp"
            | "ungreedy" | "unicode" | "export" => result.unique_compile = true,
            "notbol" | "noteol" | "notempty" | "notempty_atstart" | "global" | "report_errors" => {
                result.unique_exec = true
            }
            _ => (),
        }
    }
    Ok(result)
}

// Port of erts/emulator/beam/erl_bif_re.c:350-530 (parse_options), OTP-29.1.1.
fn options_term(value: Term) -> Result<Options, BifError> {
    let mut result = Options {
        match_limit: -1,
        depth_limit: -1,
        ..Options::default()
    };
    for_each_list_term(value, |item| {
        if item.classify() == TermKind::Tuple {
            let arity = arinsal_bifs::tuple_arity(item).map_err(|_| badopt_error())?;
            let key =
                term_atom_name(arinsal_bifs::tuple_element(item, 0).map_err(|_| badopt_error())?)
                    .ok_or_else(badopt_error)?;
            match (key, arity) {
                ("capture", 2) => {
                    let spec = arinsal_bifs::tuple_element(item, 1).map_err(|_| badopt_error())?;
                    result.capture = Some((CaptureSpec::Term(spec), CaptureType::Index));
                    result.unique_exec = true;
                }
                ("capture", 3) => {
                    let spec = arinsal_bifs::tuple_element(item, 1).map_err(|_| badopt_error())?;
                    let ty = arinsal_bifs::tuple_element(item, 2).map_err(|_| badopt_error())?;
                    let kind = match term_atom_name(ty) {
                        Some("index") => CaptureType::Index,
                        Some("list") => CaptureType::List,
                        Some("binary") => CaptureType::Binary,
                        _ => return Err(badopt_error()),
                    };
                    result.capture = Some((CaptureSpec::Term(spec), kind));
                    result.unique_exec = true;
                }
                ("offset", 2) => {
                    let n = arinsal_bifs::tuple_element(item, 1).map_err(|_| badopt_error())?;
                    result.offset = usize::try_from(term_number(n).ok_or_else(badopt_error)?)
                        .map_err(|_| badopt_error())?;
                    if result.offset > i32::MAX as usize {
                        return Err(badopt_error());
                    }
                    result.unique_exec = true;
                }
                ("match_limit", 2) => {
                    let n = arinsal_bifs::tuple_element(item, 1).map_err(|_| badopt_error())?;
                    result.match_limit = i32::try_from(term_number(n).ok_or_else(badopt_error)?)
                        .map_err(|_| badopt_error())?;
                    if result.match_limit < 0 {
                        return Err(badopt_error());
                    }
                    result.unique_exec = true;
                }
                ("match_limit_recursion", 2) => {
                    let n = arinsal_bifs::tuple_element(item, 1).map_err(|_| badopt_error())?;
                    result.depth_limit = i32::try_from(term_number(n).ok_or_else(badopt_error)?)
                        .map_err(|_| badopt_error())?;
                    if result.depth_limit < 0 {
                        return Err(badopt_error());
                    }
                    result.unique_exec = true;
                }
                ("newline", 2) => {
                    let value = arinsal_bifs::tuple_element(item, 1).map_err(|_| badopt_error())?;
                    result.newline = match term_atom_name(value) {
                        Some("cr") => 1,
                        Some("lf") => 2,
                        Some("crlf") => 3,
                        Some("any") => 4,
                        Some("anycrlf") => 5,
                        Some("nul") => 6,
                        _ => return Err(badopt_error()),
                    }
                }
                _ => return Err(badopt_error()),
            }
            return Ok(());
        }

        let name = term_atom_name(item).ok_or_else(badopt_error)?;
        match name {
            "anchored" => {
                result.compile |= ANCHORED;
                result.match_flags |= ANCHORED;
            }
            "caseless" => result.compile |= 0x8,
            "dollar_endonly" => result.compile |= 0x10,
            "dotall" => result.compile |= 0x20,
            "dupnames" => result.compile |= DUPNAMES,
            "extended" => result.compile |= 0x80,
            "firstline" => result.compile |= 0x100,
            "multiline" => result.compile |= 0x400,
            "never_utf" => result.compile |= 0x1000,
            "no_auto_capture" => result.compile |= 0x2000,
            "no_start_optimize" => result.compile |= 0x10000,
            "ucp" => result.compile |= 0x20000,
            "ungreedy" => result.compile |= 0x40000,
            "unicode" => {
                result.compile |= UTF;
                result.unicode = true;
            }
            "notbol" => result.match_flags |= 1,
            "noteol" => result.match_flags |= 2,
            "notempty" => result.match_flags |= 4,
            "notempty_atstart" => result.match_flags |= 8,
            "bsr_unicode" => result.bsr = 1,
            "bsr_anycrlf" => result.bsr = 2,
            "global" => result.global = true,
            "report_errors" => result.report_errors = true,
            "export" => result.export = true,
            _ => return Err(badopt_error()),
        }
        match name {
            "caseless" | "dollar_endonly" | "dotall" | "dupnames" | "extended" | "firstline"
            | "multiline" | "never_utf" | "no_auto_capture" | "no_start_optimize" | "ucp"
            | "ungreedy" | "unicode" | "export" => result.unique_compile = true,
            "notbol" | "noteol" | "notempty" | "notempty_atstart" | "global" | "report_errors" => {
                result.unique_exec = true
            }
            _ => (),
        }
        Ok(())
    })
    .map_err(|_| badopt_error())?;
    Ok(result)
}

fn term_atom_name(term: Term) -> Option<&'static str> {
    global_atoms().text(term.as_atom()?)
}

fn term_number(term: Term) -> Option<i64> {
    term.as_small()
        .or_else(|| to_owned(term).ok().and_then(|value| number(&value)))
}

fn compile_code(pattern: &[u8], opts: &Options) -> Result<Code, (i32, usize)> {
    let mut error = 0;
    let mut offset = 0;
    // SAFETY: pointers cover the given byte slice; PCRE2 owns the returned code.
    let code = unsafe {
        ar_re_compile(
            pattern.as_ptr(),
            pattern.len(),
            opts.compile,
            opts.newline,
            opts.bsr,
            &mut error,
            &mut offset,
        )
    };
    if code.is_null() {
        Err((error, offset))
    } else {
        Ok(Code(code))
    }
}
fn compile_error(err: i32, offset: usize, run: bool) -> O {
    let mut bytes = [0u8; 120];
    // SAFETY: `bytes` is writable for its full length.
    let len = unsafe { ar_re_error_message(err, bytes.as_mut_ptr(), bytes.len()) };
    let message = if len < 0 {
        format!("Unknown error ({err})").into_bytes()
    } else {
        bytes[..len as usize].to_vec()
    };
    let detail = pair(
        O::list(message.into_iter().map(|b| O::Int(i64::from(b))).collect()),
        O::Int(offset as i64),
    );
    if run {
        error(pair(atom("compile"), detail))
    } else {
        error(detail)
    }
}
fn compiled_tuple(code: &Code, unicode: bool) -> Result<O, BifError> {
    let newline = code.info(INFO_NEWLINE);
    Ok(O::Tuple(vec![
        atom("re_pattern"),
        O::Int(i64::from(code.info(INFO_CAPTURES))),
        O::Int(i64::from(unicode)),
        O::Int(i64::from(matches!(newline, 3..=5))),
        O::Binary(code.serialize()?),
    ]))
}
fn compile_owned(args: &[O]) -> Result<O, BifError> {
    let opts = options(args.get(1).unwrap_or(&O::Nil))?;
    if opts.unique_exec {
        return Err(badopt_error());
    }
    let pattern = iodata(&args[0], opts.unicode)?;
    let code = match compile_code(&pattern, &opts) {
        Ok(c) => c,
        Err((e, p)) => return Ok(compile_error(e, p, false)),
    };
    if opts.export {
        return exported_pattern(&pattern, args.get(1).unwrap_or(&O::Nil), &opts, &code);
    }
    Ok(success(compiled_tuple(&code, opts.unicode)?))
}

fn exported_pattern(
    pattern: &[u8],
    original_options: &O,
    opts: &Options,
    code: &Code,
) -> Result<O, BifError> {
    let bytes = code.serialize()?;
    let checksum = crc32(&bytes);
    let mut header = b"re-PCRE2".to_vec();
    header.extend(checksum.to_be_bytes());
    header.extend([1, u8::from(opts.unicode)]);
    Ok(success(O::Tuple(vec![
        atom("re_exported_pattern"),
        O::Binary(header),
        O::Binary(pattern.to_vec()),
        original_options.clone(),
        O::Binary(bytes),
    ])))
}
fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = !0u32;
    for b in bytes {
        crc ^= u32::from(*b);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb8_8320 & (0u32.wrapping_sub(crc & 1)));
        }
    }
    !crc
}
fn decode(value: &O) -> Result<(Code, bool), BifError> {
    let O::Tuple(fields) = value else {
        return Err(BifError::BADARG);
    };
    if fields.len() != 5 || atom_name(&fields[0]) != Some("re_pattern") {
        return Err(BifError::BADARG);
    }
    let count = number(&fields[1]).ok_or(BifError::BADARG)?;
    let unicode = number(&fields[2]).ok_or(BifError::BADARG)? != 0;
    number(&fields[3]).ok_or(BifError::BADARG)?;
    let O::Binary(bytes) = &fields[4] else {
        return Err(BifError::BADARG);
    };
    if bytes.len() < 32 {
        return Err(BifError::BADARG);
    }
    let mut code = ptr::null_mut();
    // SAFETY: serialized data was produced by the vendored PCRE2 encoder.
    let rc = unsafe { ar_re_deserialize(bytes.as_ptr(), bytes.len(), &mut code) };
    if rc != 1 || code.is_null() {
        return Err(BifError::BADARG);
    }
    let code = Code(code);
    if count != i64::from(code.info(INFO_CAPTURES)) {
        return Err(BifError::BADARG);
    }
    Ok((code, unicode))
}
fn version(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    call(ctx, args, |_| {
        let mut bytes = [0; 32];
        // SAFETY: PCRE2 writes a version string shorter than this buffer.
        let size = unsafe { ar_re_version(bytes.as_mut_ptr()) };
        Ok(O::Binary(bytes[..(size - 1) as usize].to_vec()))
    })
}
fn compile_1(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    call(ctx, args, compile_owned)
}
fn compile_2(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    call(ctx, args, compile_owned)
}
fn run_2(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    run_direct(ctx, "run", args)
}
fn run_3(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    run_direct(ctx, "run", args)
}
fn internal_run_4(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    run_direct(ctx, "internal_run", args)
}

// Port of erts/emulator/beam/erl_bif_re.c (re_run), OTP-29.1.1.
fn run_direct(ctx: &mut Ctx<'_>, name: &str, args: &[Term]) -> Result<Term, BifError> {
    let mut state = None;
    let mut total = 0;
    loop {
        let (progress, loops) =
            run_slice(ctx, name, args, state.take(), LOOP_BUDGET.with(Cell::get))?;
        total += loops;
        match progress {
            Progress::Done(value) => {
                LAST_LOOP_COUNT.with(|count| count.set(total));
                return Ok(value);
            }
            Progress::Yield(next) => state = Some(next),
        }
    }
}
fn inspect(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    call(ctx, args, |a| {
        if atom_name(&a[1]) != Some("namelist") {
            return Err(BifError::BADARG);
        }
        let (code, _) = decode(&a[0])?;
        let mut names = code
            .names()
            .into_iter()
            .map(|(name, _)| O::Binary(name))
            .collect::<Vec<_>>();
        names.dedup();
        Ok(pair(atom("namelist"), O::list(names)))
    })
}
fn import(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    call(ctx, args, |a| {
        let O::Tuple(fields) = &a[0] else {
            return Err(BifError::BADARG);
        };
        if fields.len() != 5 || atom_name(&fields[0]) != Some("re_exported_pattern") {
            return Err(BifError::BADARG);
        }
        let O::Binary(header) = &fields[1] else {
            return Err(BifError::BADARG);
        };
        if header.len() < 14 || &header[..8] != b"re-PCRE2" {
            return Err(BifError::BADARG);
        }
        if header[12] == 1 {
            let O::Binary(bytes) = &fields[4] else {
                return Err(BifError::BADARG);
            };
            if bytes.len() < 32
                || crc32(bytes) != u32::from_be_bytes(header[8..12].try_into().unwrap())
            {
                return Err(BifError::BADARG);
            }
            let mut code = ptr::null_mut();
            // SAFETY: CRC and header identify a serialized PCRE2 pattern.
            let rc = unsafe { ar_re_deserialize(bytes.as_ptr(), bytes.len(), &mut code) };
            if rc == 1 && !code.is_null() {
                return compiled_tuple(&Code(code), header[13] != 0);
            }
            if rc != -32 && rc != -31 {
                return Err(BifError::BADARG);
            }
        }
        let O::Binary(pattern) = &fields[2] else {
            return Err(BifError::BADARG);
        };
        let opts = options(&fields[3])?;
        let code = compile_code(pattern, &opts).map_err(|_| BifError::BADARG)?;
        compiled_tuple(&code, opts.unicode)
    })
}

/// Dispatch an OTP `re` BIF while representing compiled patterns with an
/// opaque magic reference, as ERTS does. The serialized PCRE2 code is retained
/// by the reference so copied BEAM terms remain valid for their heap lifetime.
pub fn invoke(ctx: &mut Ctx<'_>, name: &str, args: &[Term]) -> Result<Term, BifError> {
    if name == "compile" && matches!(args.len(), 1 | 2) {
        return compile_magic(ctx, args);
    }
    let bif = lookup("re", name, args.len() as u8).ok_or(BifError::BADARG)?;
    if name == "inspect"
        && args.len() == 2
        && let Some(compiled) = magic_code(args[0])?
    {
        return inspect_magic(ctx, compiled, args[1]);
    }
    let result = bif(ctx, args)?;
    if name == "import" {
        return magic_compile_result(ctx, result);
    }
    Ok(result)
}

struct CompiledCode {
    code: usize,
    capture_count: u32,
    unicode: bool,
    owner: Arc<MagicRef>,
}

// Port of erts/emulator/beam/erl_bif_re.c:1568-1592 (precompiled pattern validation), OTP-29.1.1.
fn magic_code(term: Term) -> Result<Option<CompiledCode>, BifError> {
    if arinsal_bifs::tuple_arity(term).ok() != Some(5) {
        return Ok(None);
    }
    if term_atom_name(arinsal_bifs::tuple_element(term, 0)?) != Some("re_pattern") {
        return Ok(None);
    }
    let capture_count = arinsal_bifs::tuple_element(term, 1)?
        .as_small()
        .and_then(|n| u32::try_from(n).ok())
        .ok_or(BifError::BADARG)?;
    let unicode = arinsal_bifs::tuple_element(term, 2)?
        .as_small()
        .ok_or(BifError::BADARG)?
        != 0;
    if arinsal_bifs::tuple_element(term, 3)?.as_small().is_none() {
        return Err(BifError::BADARG);
    }
    let reference = arinsal_bifs::tuple_element(term, 4)?;
    let Some(owner) = reference.magic_owner() else {
        return Ok(None);
    };
    let Some(handle) = owner.downcast_ref::<RegexHandle>() else {
        return Ok(None);
    };
    Ok(Some(CompiledCode {
        code: handle.0,
        capture_count,
        unicode,
        owner,
    }))
}

struct RegexHandle(usize);

impl Drop for RegexHandle {
    fn drop(&mut self) {
        drop(Code(self.0 as *mut c_void));
    }
}

// Port of erts/emulator/beam/erl_bif_re.c:544-574 and :591-612 (compile and build_compile_result), OTP-29.1.1.
fn compile_magic(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    let options_arg = args.get(1).copied().unwrap_or(Term::NIL);
    let opts = options_term(options_arg)?;
    if opts.unique_exec {
        return Err(badopt_error());
    }
    let (pattern, result) = if opts.export || args[0].classify() != TermKind::Bitstring {
        let pattern = if opts.unicode && args[0].classify() == TermKind::List {
            iodata(&to_owned(args[0]).map_err(|_| BifError::BADARG)?, true)?
        } else {
            term_iodata(args[0])?
        };
        let result = compile_code(&pattern, &opts);
        (Some(pattern), result)
    } else {
        let result = with_binary_bytes(args[0], |view| {
            if !view.start_bit().is_multiple_of(8) || !view.bit_len().is_multiple_of(8) {
                return None;
            }
            let start = view.start_bit() / 8;
            let end = start.checked_add(view.bit_len() / 8)?;
            let pattern = view.bytes().get(start..end)?;
            Some(compile_code(pattern, &opts))
        })?
        .ok_or(BifError::BADARG)?;
        (None, result)
    };
    let code = match result {
        Ok(code) => code,
        Err((error, offset)) => {
            return from_owned(
                &compile_error(error, offset, false),
                &mut Heap(&mut ctx.heap),
            )
            .map_err(|_| BifError::SystemLimit);
        }
    };
    if opts.export {
        let pattern = pattern.as_deref().ok_or(BifError::BADARG)?;
        let options_owned = to_owned(options_arg).map_err(|_| BifError::BADARG)?;
        let result = exported_pattern(pattern, &options_owned, &opts, &code)?;
        return from_owned(&result, &mut Heap(&mut ctx.heap)).map_err(|_| BifError::SystemLimit);
    }
    compiled_magic_term(ctx, code, opts.unicode, true)
}

fn compiled_magic_term(
    ctx: &mut Ctx<'_>,
    code: Code,
    unicode: bool,
    with_ok: bool,
) -> Result<Term, BifError> {
    let captures = code.info(INFO_CAPTURES);
    let newline = code.info(INFO_NEWLINE);
    let mut heap = Heap(&mut ctx.heap);
    let captures = i64::from(captures);
    let owner = MagicRef::with_erts_payload_size(RegexHandle(code.into_raw()), 8);
    let fields = [
        atom_term("re_pattern")?,
        small_term(captures)?,
        small_term(i64::from(unicode))?,
        small_term(i64::from(matches!(newline, 3..=5)))?,
        TermBuilder::new(&mut heap)
            .magic_ref(owner)
            .map_err(|_| BifError::SystemLimit)?,
    ];
    let compiled = TermBuilder::new(&mut heap)
        .tuple(&fields)
        .map_err(|_| BifError::SystemLimit)?;
    if with_ok {
        let ok = atom_term("ok")?;
        TermBuilder::new(&mut heap)
            .tuple(&[ok, compiled])
            .map_err(|_| BifError::SystemLimit)
    } else {
        Ok(compiled)
    }
}

// Port of erts/emulator/beam/erl_bif_re.c:1920-1976 (re_inspect_2), OTP-29.1.1.
fn inspect_magic(
    ctx: &mut Ctx<'_>,
    compiled: CompiledCode,
    option: Term,
) -> Result<Term, BifError> {
    if atom_name(&to_owned(option).map_err(|_| BifError::BADARG)?) != Some("namelist") {
        return Err(BifError::BADARG);
    }
    let code = std::mem::ManuallyDrop::new(Code(compiled.code as *mut c_void));
    let mut names = code
        .names()
        .into_iter()
        .map(|(name, _)| O::Binary(name))
        .collect::<Vec<_>>();
    names.dedup();
    from_owned(
        &pair(atom("namelist"), O::list(names)),
        &mut Heap(&mut ctx.heap),
    )
    .map_err(|_| BifError::SystemLimit)
}

fn magic_compile_result(ctx: &mut Ctx<'_>, result: Term) -> Result<Term, BifError> {
    let owned = to_owned(result).map_err(|_| BifError::SystemLimit)?;
    let O::Tuple(outer) = &owned else {
        return Ok(result);
    };
    let (wrapper, pattern_term) = if outer.len() == 2 && atom_name(&outer[0]) == Some("ok") {
        (Some(&outer[0]), &outer[1])
    } else if outer.len() == 5 && atom_name(&outer[0]) == Some("re_pattern") {
        (None, &owned)
    } else {
        return Ok(result);
    };
    let O::Tuple(pattern) = pattern_term else {
        return Ok(result);
    };
    if pattern.len() != 5 || atom_name(&pattern[0]) != Some("re_pattern") {
        return Ok(result);
    }
    let (code, _) = decode(pattern_term)?;
    let mut heap = Heap(&mut ctx.heap);
    let mut terms = pattern[..4]
        .iter()
        .map(|item| from_owned(item, &mut heap).map_err(|_| BifError::SystemLimit))
        .collect::<Result<Vec<_>, _>>()?;
    // Port of erts/emulator/beam/erl_bif_re.c (struct regex_magic_indirect): one code pointer.
    let reference = TermBuilder::new(&mut heap)
        .magic_ref(MagicRef::with_erts_payload_size(
            RegexHandle(code.into_raw()),
            8,
        ))
        .map_err(|_| BifError::SystemLimit)?;
    terms.push(reference);
    let compiled = TermBuilder::new(&mut heap)
        .tuple(&terms)
        .map_err(|_| BifError::SystemLimit)?;
    if let Some(ok) = wrapper {
        let ok = from_owned(ok, &mut heap).map_err(|_| BifError::SystemLimit)?;
        TermBuilder::new(&mut heap)
            .tuple(&[ok, compiled])
            .map_err(|_| BifError::SystemLimit)
    } else {
        Ok(compiled)
    }
}

#[derive(Clone)]
enum Selection {
    All,
    AllButFirst,
    None,
    Specific(Vec<CaptureKey>),
}
#[derive(Clone)]
enum CaptureKey {
    Number(i32),
    Name(Vec<u8>),
}
fn selection(
    code: &Code,
    spec: Option<&(CaptureSpec, CaptureType)>,
) -> Result<(Selection, CaptureType), BifError> {
    let Some((value, kind)) = spec else {
        return Ok((Selection::All, CaptureType::Index));
    };
    let chosen = match value {
        CaptureSpec::Owned(value) => selection_owned(code, value)?,
        CaptureSpec::Term(value) => selection_term(code, *value)?,
    };
    Ok((chosen, *kind))
}

fn selection_owned(code: &Code, value: &O) -> Result<Selection, BifError> {
    let chosen = match atom_name(value) {
        Some("all") => Selection::All,
        Some("all_but_first") => Selection::AllButFirst,
        Some("first") => Selection::Specific(vec![CaptureKey::Number(0)]),
        Some("none") => Selection::None,
        Some("all_names") => {
            let mut names = code.names().into_iter().map(|(n, _)| n).collect::<Vec<_>>();
            names.dedup();
            if names.is_empty() {
                Selection::None
            } else {
                Selection::Specific(names.into_iter().map(CaptureKey::Name).collect())
            }
        }
        Some(_) => return Err(BifError::BADARG),
        None => {
            let mut keys = Vec::new();
            for item in list(value)? {
                if let Some(n) = number(item) {
                    keys.push(CaptureKey::Number(
                        i32::try_from(n).map_err(|_| BifError::BADARG)?,
                    ));
                } else if let Some(name) = atom_name(item) {
                    keys.push(CaptureKey::Name(name.as_bytes().to_vec()));
                } else {
                    keys.push(CaptureKey::Name(iodata(item, false)?));
                }
            }
            if keys.is_empty() {
                Selection::None
            } else {
                Selection::Specific(keys)
            }
        }
    };
    Ok(chosen)
}

fn selection_term(code: &Code, value: Term) -> Result<Selection, BifError> {
    let chosen = match term_atom_name(value) {
        Some("all") => Selection::All,
        Some("all_but_first") => Selection::AllButFirst,
        Some("first") => Selection::Specific(vec![CaptureKey::Number(0)]),
        Some("none") => Selection::None,
        Some("all_names") => all_names_selection(code),
        Some(_) => return Err(BifError::BADARG),
        None => {
            let mut keys = Vec::new();
            for_each_list_term(value, |item| {
                if let Some(number) = term_number(item) {
                    keys.push(CaptureKey::Number(
                        i32::try_from(number).map_err(|_| BifError::BADARG)?,
                    ));
                } else if let Some(name) = term_atom_name(item) {
                    keys.push(CaptureKey::Name(name.as_bytes().to_vec()));
                } else {
                    keys.push(CaptureKey::Name(term_iodata(item)?));
                }
                Ok(())
            })?;
            if keys.is_empty() {
                Selection::None
            } else {
                Selection::Specific(keys)
            }
        }
    };
    Ok(chosen)
}

fn all_names_selection(code: &Code) -> Selection {
    let mut names = code
        .names()
        .into_iter()
        .map(|(name, _)| name)
        .collect::<Vec<_>>();
    names.dedup();
    if names.is_empty() {
        Selection::None
    } else {
        Selection::Specific(names.into_iter().map(CaptureKey::Name).collect())
    }
}
fn selected_key(
    code: &Code,
    key: &CaptureKey,
    capture_count: usize,
    ovector: &[usize],
) -> Option<usize> {
    match key {
        CaptureKey::Number(n) => usize::try_from(*n).ok(),
        CaptureKey::Name(name) => {
            let mut zname = name.clone();
            zname.push(0);
            // SAFETY: `zname` is NUL-terminated and `code` is live.
            let idx = unsafe { ar_re_capture_name(code.0, zname.as_ptr()) };
            if idx >= 0 {
                return Some(idx as usize);
            }
            let mut first = ptr::null();
            let mut last = ptr::null();
            // SAFETY: PCRE2 writes valid name table pointers for this code.
            let size =
                unsafe { ar_re_capture_name_range(code.0, zname.as_ptr(), &mut first, &mut last) };
            if size <= 0 || first.is_null() {
                return None;
            }
            let count = (last as usize - first as usize) / size as usize + 1;
            for i in 0..count {
                // SAFETY: name-table scan returned this inclusive range and stride.
                let entry = unsafe { std::slice::from_raw_parts(first.add(i * size as usize), 2) };
                let index = (usize::from(entry[0]) << 8) | usize::from(entry[1]);
                if index < capture_count && ovector[index * 2] != UNSET {
                    return Some(index);
                }
            }
            None
        }
    }
}

fn for_each_selected_index(
    code: &Code,
    selection: &Selection,
    capture_count: usize,
    ovector: &[usize],
    mut visit: impl FnMut(Option<usize>) -> Result<(), BifError>,
) -> Result<(), BifError> {
    match selection {
        Selection::None => Ok(()),
        Selection::All => (0..capture_count).try_for_each(|index| visit(Some(index))),
        Selection::AllButFirst => (1..capture_count).try_for_each(|index| visit(Some(index))),
        Selection::Specific(keys) => keys
            .iter()
            .try_for_each(|key| visit(selected_key(code, key, capture_count, ovector))),
    }
}

fn selected_indices(
    code: &Code,
    selection: &Selection,
    rc: i32,
    ovector: &[usize],
) -> Vec<Option<usize>> {
    let mut indexes = Vec::new();
    for_each_selected_index(code, selection, rc as usize, ovector, |index| {
        indexes.push(index);
        Ok(())
    })
    .expect("collecting selected capture indexes cannot fail");
    indexes
}
enum MatchFailure {
    Badarg,
    Limit(&'static str),
}
enum Subject {
    Bytes(Vec<u8>),
    Binary {
        data: usize,
        len: usize,
        _owner: BinaryOwner,
    },
}

struct RunSubject {
    prepared: Option<Subject>,
    original: Option<Term>,
}

impl Subject {
    fn as_ptr(&self) -> *const u8 {
        match self {
            Self::Bytes(bytes) => bytes.as_ptr(),
            Self::Binary { data, .. } => *data as *const u8,
        }
    }

    fn len(&self) -> usize {
        match self {
            Self::Bytes(bytes) => bytes.len(),
            Self::Binary { len, .. } => *len,
        }
    }

    fn as_slice(&self) -> Option<&[u8]> {
        match self {
            Self::Bytes(bytes) => Some(bytes),
            Self::Binary { .. } => None,
        }
    }

    fn empty() -> Self {
        Self::Bytes(Vec::new())
    }
}

// Port of erts/emulator/beam/erl_bif_re.c:1660-1687 (pin bitstring subjects), OTP-29.1.1.
fn prepared_subject(term: Term) -> Result<Option<Subject>, BifError> {
    if term.classify() != TermKind::Bitstring {
        return Ok(None);
    }
    let owner = arinsal_term::binary_owner(term);
    with_binary_bytes(term, |view| {
        if !view.start_bit().is_multiple_of(8) || !view.bit_len().is_multiple_of(8) {
            return None;
        }
        let start = view.start_bit() / 8;
        let len = view.bit_len() / 8;
        let end = start.checked_add(len)?;
        let bytes = view.bytes().get(start..end)?;
        if view.is_off_heap()
            && len > 64
            && let Some(owner) = owner
        {
            return Some(Subject::Binary {
                data: bytes.as_ptr() as usize,
                len,
                _owner: owner,
            });
        }
        Some(Subject::Bytes(bytes.to_vec()))
    })
}

// Port of lib/stdlib/src/re.erl:1887-1915 (forward/forward2), OTP-29.1.1.
fn subject_byte_at(state: &RunState, subject: Option<Term>, index: usize) -> Option<u8> {
    if let Some(bytes) = state.subject.as_slice() {
        return bytes.get(index).copied();
    }
    let subject = subject?;
    with_binary_bytes(subject, |view| {
        if !view.start_bit().is_multiple_of(8)
            || !view.bit_len().is_multiple_of(8)
            || index >= view.bit_len() / 8
        {
            return None;
        }
        view.bytes().get(view.start_bit() / 8 + index).copied()
    })
    .ok()
    .flatten()
}

/// A match that ran out of its loop budget, with everything needed to continue it.
///
/// Port of erts/emulator/beam/erl_bif_re.c:1660-1680 (`RestartContext`), OTP-29.1.1. The
/// compiled code, subject storage and PCRE2 match state are retained here; addresses are plain
/// integers so the state can sit in a magic reference.
pub struct RunState {
    code: usize,
    code_owner: Option<Arc<MagicRef>>,
    capture_count: usize,
    subject: Subject,
    session: MatchSession,
    matched: bool,
    match_rc: i32,
    ovector: Vec<usize>,
    unicode: bool,
    selection: Selection,
    capture_type: CaptureType,
    flags: u32,
    offset: usize,
    matches: Vec<Vec<Option<(usize, usize)>>>,
    suppress_duplicate: Option<(usize, usize)>,
    phase: Phase,
    /// The call's options, kept so a resumed run needs none of its arguments, as erts' trap
    /// export is called with the restart state in place of the options.
    opts: Options,
}
#[derive(Clone, Copy)]
enum Phase {
    /// The next match starts at `offset`.
    Main,
    /// An empty match at `start` is retried anchored and non-empty (`PCRE2_NOTEMPTY_ATSTART`).
    Retry { start: usize },
}
impl RunState {
    fn code(&self) -> std::mem::ManuallyDrop<Code> {
        std::mem::ManuallyDrop::new(Code(self.code as *mut c_void))
    }

    // Port of erts/emulator/beam/erl_bif_re.c:1732-1739, OTP-29.1.1.
    fn rebind_restart(&mut self) {
        if self.session.data != 0 {
            ffi_match(
                self.code,
                self.subject.as_ptr(),
                self.subject.len(),
                self.offset,
                self.flags,
                (self.opts.match_limit, self.opts.depth_limit),
                &mut self.ovector,
                (self.capture_count + 1) as u32,
                0,
                &mut self.session,
                2,
            );
        }
    }
}
impl Drop for RunState {
    fn drop(&mut self) {
        if self.session.data != 0 {
            let mut ovector = [0usize; 0];
            ffi_match(
                self.code,
                ptr::null(),
                0,
                0,
                0,
                (-1, -1),
                &mut ovector,
                0,
                0,
                &mut self.session,
                1,
            );
        }
        if self.code_owner.is_none() && self.code != 0 {
            drop(Code(self.code as *mut c_void));
        }
    }
}

/// The only call into the PCRE2 matcher. `session` is the unfinished match state, zero when
/// there is none; mode 1 frees it and mode 2 rebinds its restart-data pointer after a move.
#[allow(clippy::too_many_arguments)]
fn ffi_match(
    code: usize,
    subject: *const u8,
    subject_len: usize,
    offset: usize,
    flags: u32,
    limits: (i32, i32),
    ovector: &mut [usize],
    count: u32,
    budget: i32,
    session: &mut MatchSession,
    mode: i32,
) -> MatchResult {
    // SAFETY: `subject` is backed by the live Subject held in RunState, and `ovector` is writable;
    // `code` is live and, while the inline restart context is set, code and subject are the
    // original inputs. The bridge's session layout matches this stack or trapped state.
    unsafe {
        ar_re_match(
            code as *const c_void,
            subject,
            subject_len,
            offset,
            flags,
            limits.0,
            limits.1,
            ovector.as_mut_ptr(),
            count,
            budget,
            session,
            mode,
        )
    }
}

enum Slice {
    Done(Option<i32>),
    Yield,
}
/// Runs or resumes one `pcre2_match`, for at most `budget` loops.
fn match_slice(
    state: &mut RunState,
    offset: usize,
    flags: u32,
    opts: &Options,
    budget: i32,
    loops: &mut u64,
) -> Result<Slice, MatchFailure> {
    let count = state.capture_count + 1;
    let result = ffi_match(
        state.code,
        state.subject.as_ptr(),
        state.subject.len(),
        offset,
        flags,
        (opts.match_limit, opts.depth_limit),
        &mut state.ovector,
        count as u32,
        budget,
        &mut state.session,
        0,
    );
    *loops += result.loops_consumed;
    match result.rc {
        PCRE2_ERROR_LOOP_LIMIT => Ok(Slice::Yield),
        rc if rc > 0 => Ok(Slice::Done(Some(rc))),
        -1 | -52 | -63 => Ok(Slice::Done(None)),
        -47 if opts.report_errors => Err(MatchFailure::Limit("match_limit")),
        -53 if opts.report_errors => Err(MatchFailure::Limit("match_limit_recursion")),
        -47 | -53 => Ok(Slice::Done(None)),
        _ => Err(MatchFailure::Badarg),
    }
}
const PCRE2_ERROR_LOOP_LIMIT: i32 = -76;

/// What a slice of a run produced.
enum Step {
    Done(O),
    Yield,
}

// Keep the non-trapping RestartContext inline, as re_run does on the C stack.
#[allow(clippy::large_enum_variant)]
enum RunExecState {
    Inline(RunState),
    Trapped(Box<RunState>),
}

impl RunExecState {
    fn as_ref(&self) -> &RunState {
        match self {
            Self::Inline(state) => state,
            Self::Trapped(state) => state,
        }
    }

    fn as_mut(&mut self) -> &mut RunState {
        match self {
            Self::Inline(state) => state,
            Self::Trapped(state) => state,
        }
    }

    // Port of erts/emulator/beam/erl_bif_re.c:1730-1743, OTP-29.1.1.
    fn into_trap_state(self) -> Box<RunState> {
        match self {
            Self::Inline(state) => {
                let mut trapped = Box::new(state);
                trapped.rebind_restart();
                trapped
            }
            Self::Trapped(state) => state,
        }
    }
}

/// Port of lib/stdlib/src/re.erl:1823-1906 (do_grun/loopexec), OTP-29.1.1, as a state machine
/// that can stop in the middle of any match and continue later.
fn advance(
    state: &mut RunState,
    subject: Option<Term>,
    budget: i32,
    loops: &mut u64,
) -> Result<Step, BifError> {
    // The options live in the state; the matcher borrows the state mutably.
    let opts = std::mem::take(&mut state.opts);
    let result = advance_with(state, subject, &opts, budget, loops);
    state.opts = opts;
    result
}

fn advance_with(
    state: &mut RunState,
    subject: Option<Term>,
    opts: &Options,
    budget: i32,
    loops: &mut u64,
) -> Result<Step, BifError> {
    loop {
        match state.phase {
            Phase::Main => {
                if state.offset > state.subject.len() {
                    break;
                }
                let found = match match_slice(state, state.offset, state.flags, opts, budget, loops)
                {
                    Ok(Slice::Yield) => return Ok(Step::Yield),
                    Ok(Slice::Done(found)) => found,
                    Err(MatchFailure::Limit(reason)) => return Ok(Step::Done(error(atom(reason)))),
                    Err(MatchFailure::Badarg) => return Err(BifError::BADARG),
                };
                let Some(rc) = found else {
                    break;
                };
                let start = state.ovector[0];
                let end = state.ovector[1];
                let duplicate = state.suppress_duplicate.take() == Some((start, end));
                if !duplicate {
                    state.matched = true;
                    state.match_rc = rc;
                    if opts.global && !matches!(state.selection, Selection::None) {
                        push_match(
                            &mut state.matches,
                            state.code,
                            &state.selection,
                            rc,
                            &state.ovector,
                        );
                    }
                }
                if !opts.global {
                    break;
                }
                if end > start {
                    state.offset = end;
                    state.flags |= NO_UTF_CHECK;
                } else {
                    state.phase = Phase::Retry { start };
                }
            }
            Phase::Retry { start } => {
                let retry = match match_slice(
                    state,
                    state.offset,
                    state.flags | ANCHORED | 8,
                    opts,
                    budget,
                    loops,
                ) {
                    Ok(Slice::Yield) => return Ok(Step::Yield),
                    Ok(Slice::Done(found)) => found,
                    Err(MatchFailure::Limit(reason)) => return Ok(Step::Done(error(atom(reason)))),
                    Err(MatchFailure::Badarg) => return Err(BifError::BADARG),
                };
                if let Some(retry_rc) = retry
                    && (state.ovector[0], state.ovector[1]) != (start, start)
                {
                    // PCRE2's NOTEMPTY_ATSTART rejects an empty engine match. `\\K` may still
                    // reset the returned start to its end, so the ovector can be empty here.
                    state.matched = true;
                    state.match_rc = retry_rc;
                    if opts.global && !matches!(state.selection, Selection::None) {
                        push_match(
                            &mut state.matches,
                            state.code,
                            &state.selection,
                            retry_rc,
                            &state.ovector,
                        );
                    }
                    state.offset = state.ovector[1];
                    state.flags |= NO_UTF_CHECK;
                    state.phase = Phase::Main;
                    continue;
                }
                if start >= state.subject.len() {
                    break;
                }
                if state.offset != start {
                    state.offset = start;
                    state.flags |= NO_UTF_CHECK;
                    state.suppress_duplicate = Some((start, start));
                    state.phase = Phase::Main;
                    continue;
                }
                let step = if state.unicode {
                    let b = subject_byte_at(state, subject, start).unwrap_or(0);
                    if b & 0xe0 == 0xc0 {
                        2
                    } else if b & 0xf0 == 0xe0 {
                        3
                    } else if b & 0xf8 == 0xf0 {
                        4
                    } else {
                        1
                    }
                } else if matches!(state.code().info(INFO_NEWLINE), 3..=5)
                    && subject_byte_at(state, subject, start) == Some(b'\r')
                    && subject_byte_at(state, subject, start + 1) == Some(b'\n')
                {
                    2
                } else {
                    1
                };
                state.offset = start + step;
                state.flags |= NO_UTF_CHECK;
                state.phase = Phase::Main;
            }
        }
    }
    Ok(Step::Done(atom(if !state.matched {
        "nomatch"
    } else {
        "match"
    })))
}

fn push_match(
    matches: &mut Vec<Vec<Option<(usize, usize)>>>,
    code: usize,
    selection: &Selection,
    rc: i32,
    ovector: &[usize],
) {
    let code = std::mem::ManuallyDrop::new(Code(code as *mut c_void));
    let indexes = selected_indices(&code, selection, rc, ovector);
    let ranges = indexes
        .into_iter()
        .map(|index| {
            index
                .filter(|i| *i < rc as usize && ovector[*i * 2] != UNSET)
                .map(|i| (ovector[i * 2], ovector[i * 2 + 1] - ovector[i * 2]))
        })
        .collect();
    matches.push(ranges);
}

/// Where a `re:run`/`re:internal_run` call stands after one slice.
pub enum Progress {
    /// The finished result.
    Done(Term),
    /// The loop budget ran out; resume with this state.
    Yield(Box<RunState>),
}

/// The result of preparing the `re:grun/3` continuation for a global run.
pub enum GlobalRun {
    /// The pattern failed to compile with `report_errors`, which returns immediately.
    Return(Term),
    /// Unicode inputs require the `re:urun/3` conversion export first.
    UnicodeTrap,
    /// The compiled pattern and options tuple passed to `re:grun/3`.
    Trap { pattern: Term, options: Term },
}

/// Whether a run continues in PCRE2 or traps to `re:grun/3`.
pub enum RunDispatch {
    /// A regular run slice and its PCRE2 loop count.
    Run { progress: Progress, loops: u64 },
    /// The global run's result or export trap.
    Global(GlobalRun),
}

/// Prepare the `re:grun/3` export trap for a global `re:run` call.
// Port of erts/emulator/beam/erl_bif_re.c:1542-1603 (global branches of re_run), OTP-29.1.1.
fn prepare_global_run(
    ctx: &mut Ctx<'_>,
    name: &str,
    args: &[Term],
    opts: &Options,
) -> Result<GlobalRun, BifError> {
    let options_term = args.get(2).copied().unwrap_or(Term::NIL);
    if opts.export {
        return Err(badopt_error());
    }

    if name == "internal_run" {
        match args.get(3).and_then(|first| term_atom_name(*first)) {
            Some("true" | "false") => (),
            _ => return Err(BifError::BADARG),
        }
    }

    let subject = *args.first().ok_or(BifError::BADARG)?;
    let pattern_term = *args.get(1).ok_or(BifError::BADARG)?;
    let precompiled = arinsal_bifs::tuple_arity(pattern_term).ok() == Some(5);
    let (pattern, trap_options) = if precompiled {
        if opts.unique_compile {
            return Err(BifError::BADARG);
        }
        let Some(compiled) = magic_code(pattern_term)? else {
            return Err(BifError::BADARG);
        };
        if compiled.unicode && subject.classify() != TermKind::Bitstring {
            return Ok(GlobalRun::UnicodeTrap);
        }
        let code = std::mem::ManuallyDrop::new(Code(compiled.code as *mut c_void));
        if opts.newline != 0 && opts.newline != code.info(INFO_NEWLINE) {
            return Err(BifError::BADARG);
        }
        if opts.bsr != 0 && opts.bsr != code.info(INFO_BSR) {
            return Err(BifError::BADARG);
        }
        let no_clean = from_owned(&atom("false"), &mut Heap(&mut ctx.heap))
            .map_err(|_| BifError::SystemLimit)?;
        let options = TermBuilder::new(&mut Heap(&mut ctx.heap))
            .tuple(&[options_term, no_clean])
            .map_err(|_| BifError::SystemLimit)?;
        (pattern_term, options)
    } else {
        if opts.unicode
            && (subject.classify() != TermKind::Bitstring
                || pattern_term.classify() != TermKind::Bitstring)
        {
            return Ok(GlobalRun::UnicodeTrap);
        }
        let pattern_bytes = term_iodata(pattern_term)?;
        let code = match compile_code(&pattern_bytes, opts) {
            Ok(code) => code,
            Err((error, offset)) if opts.report_errors => {
                let value = from_owned(
                    &compile_error(error, offset, true),
                    &mut Heap(&mut ctx.heap),
                )
                .map_err(|_| BifError::SystemLimit)?;
                return Ok(GlobalRun::Return(value));
            }
            Err(_) => return Err(BifError::BADARG),
        };
        let compiled = compiled_magic_term(ctx, code, opts.unicode, false)?;
        let need_clean = from_owned(
            &atom(if opts.unique_compile { "true" } else { "false" }),
            &mut Heap(&mut ctx.heap),
        )
        .map_err(|_| BifError::SystemLimit)?;
        let options = TermBuilder::new(&mut Heap(&mut ctx.heap))
            .tuple(&[options_term, need_clean, pattern_term])
            .map_err(|_| BifError::SystemLimit)?;
        (compiled, options)
    };

    Ok(GlobalRun::Trap {
        pattern,
        options: trap_options,
    })
}

/// Loops PCRE2 runs per reduction (`LOOP_FACTOR`, erl_bif_re.c:42).
pub const LOOP_FACTOR: i32 = 16;

/// Runs `re:run/2,3` or `re:internal_run/4` for at most `loop_budget` PCRE2 loops. `state` is
/// the unfinished run of an earlier slice, with the call's original arguments. Gives the
/// progress and the loops used.
///
/// Port of erts/emulator/beam/erl_bif_re.c:1495-1795 (re_run) and :1841-1900 (re_exec_trap),
/// OTP-29.1.1.
pub fn run_slice(
    ctx: &mut Ctx<'_>,
    name: &str,
    args: &[Term],
    state: Option<Box<RunState>>,
    loop_budget: i32,
) -> Result<(Progress, u64), BifError> {
    run_slice_inner(ctx, name, args, state, loop_budget, None)
}

/// Run one slice, or prepare the OTP `re:grun/3` continuation for a global call.
///
/// Port of erts/emulator/beam/erl_bif_re.c:1542-1603 (global branches of re_run), OTP-29.1.1.
pub fn run_slice_or_global(
    ctx: &mut Ctx<'_>,
    name: &str,
    args: &[Term],
    state: Option<Box<RunState>>,
    loop_budget: i32,
) -> Result<RunDispatch, BifError> {
    let Some(state) = state else {
        let options_arg = args.get(2).copied().unwrap_or(Term::NIL);
        let opts = options_term(options_arg)?;
        if opts.global {
            return Ok(RunDispatch::Global(prepare_global_run(
                ctx, name, args, &opts,
            )?));
        }
        let (progress, loops) = run_slice_inner(ctx, name, args, None, loop_budget, Some(opts))?;
        return Ok(RunDispatch::Run { progress, loops });
    };
    let (progress, loops) = run_slice_inner(ctx, name, args, Some(state), loop_budget, None)?;
    Ok(RunDispatch::Run { progress, loops })
}

fn run_slice_inner(
    ctx: &mut Ctx<'_>,
    name: &str,
    args: &[Term],
    state: Option<Box<RunState>>,
    loop_budget: i32,
    initial_options: Option<Options>,
) -> Result<(Progress, u64), BifError> {
    let compiled = if state.is_none() {
        args.get(1)
            .map(|pattern| magic_code(*pattern))
            .transpose()?
            .flatten()
    } else {
        None
    };
    let (owned, first, parsed_options, subject) = if state.is_some() {
        // A trapped call continues from its restart state alone.
        (Vec::new(), false, None, None)
    } else {
        let parsed_options = match initial_options {
            Some(options) => options,
            None => options_term(args.get(2).copied().unwrap_or(Term::NIL))?,
        };
        let subject = match (compiled.is_some(), args.first()) {
            (true, Some(term)) => prepared_subject(*term)?,
            _ => None,
        };
        let first = match (name, args.len()) {
            ("run", 2 | 3) => true,
            ("internal_run", 4) => match term_atom_name(args[3]) {
                Some("true") => true,
                Some("false") => false,
                _ => return Err(BifError::BADARG),
            },
            _ => return Err(BifError::BADARG),
        };
        let owned = if compiled.is_some() {
            if subject.is_some() {
                Vec::new()
            } else {
                vec![
                    to_owned(*args.first().ok_or(BifError::BADARG)?)
                        .map_err(|_| BifError::BADARG)?,
                ]
            }
        } else {
            args.iter()
                .map(|term| to_owned(*term).map_err(|_| BifError::BADARG))
                .collect::<Result<Vec<_>, _>>()?
        };
        (owned, first, Some(parsed_options), subject)
    };
    let (step, loops) = run_owned_slice(
        &owned,
        first,
        state,
        loop_budget,
        compiled,
        parsed_options,
        RunSubject {
            prepared: subject,
            original: args.first().copied(),
        },
    )?;
    match step {
        (Step::Done(result), state) => {
            let heap = &mut Heap(&mut ctx.heap);
            let value = match atom_name(&result) {
                Some("match") => build_exec_return(state.as_ref(), args.first().copied(), heap)?,
                Some("nomatch") => atom_term("nomatch")?,
                _ => from_owned(&result, heap).map_err(|_| BifError::SystemLimit)?,
            };
            Ok((Progress::Done(value), loops))
        }
        (Step::Yield, state) => Ok((Progress::Yield(state.into_trap_state()), loops)),
    }
}

fn atom_term(name: &str) -> Result<Term, BifError> {
    global_atoms()
        .intern(name)
        .map(Term::atom)
        .map_err(|_| BifError::SystemLimit)
}

fn small_term(value: i64) -> Result<Term, BifError> {
    Term::small(value).ok_or(BifError::SystemLimit)
}

// Port of erts/emulator/beam/erl_bif_re.c:1030-1262 (build_exec_return), OTP-29.1.1.
fn build_exec_return<H: HeapAlloc + ?Sized>(
    state: &RunState,
    subject: Option<Term>,
    heap: &mut H,
) -> Result<Term, BifError> {
    let tag = atom_term("match")?;
    if matches!(state.selection, Selection::None) {
        return Ok(tag);
    }
    let can_reference = subject
        .filter(|term| term.classify() == TermKind::Bitstring)
        .map(|term| {
            with_binary_bytes(term, |view| {
                view.is_off_heap()
                    && view.start_bit().is_multiple_of(8)
                    && view.bit_len().is_multiple_of(8)
                    && view.bit_len() > 64 * 8
            })
        })
        .transpose()?
        .unwrap_or(false);
    let captures = if state.opts.global {
        let mut matches = Vec::with_capacity(state.matches.len());
        for row in &state.matches {
            matches.push(build_capture_row(row, state, subject, can_reference, heap)?);
        }
        TermBuilder::new(&mut *heap)
            .list_from_slice(&matches)
            .map_err(|_| BifError::SystemLimit)?
    } else {
        build_capture_current(state, subject, can_reference, heap)?
    };
    TermBuilder::new(&mut *heap)
        .tuple(&[tag, captures])
        .map_err(|_| BifError::SystemLimit)
}

// Port of erts/emulator/beam/erl_bif_re.c:1120-1258 (capture result construction), OTP-29.1.1.
fn build_capture_row<H: HeapAlloc + ?Sized>(
    ranges: &[Option<(usize, usize)>],
    state: &RunState,
    subject: Option<Term>,
    can_reference: bool,
    heap: &mut H,
) -> Result<Term, BifError> {
    let mut captures = Vec::with_capacity(ranges.len());
    for range in ranges.iter().copied() {
        captures.push(build_capture_value(
            range,
            state,
            subject,
            can_reference,
            heap,
        )?);
    }
    TermBuilder::new(&mut *heap)
        .list_from_slice(&captures)
        .map_err(|_| BifError::SystemLimit)
}

fn build_capture_current<H: HeapAlloc + ?Sized>(
    state: &RunState,
    subject: Option<Term>,
    can_reference: bool,
    heap: &mut H,
) -> Result<Term, BifError> {
    let code = state.code();
    let rc = state.match_rc.max(0) as usize;
    let mut captures = Vec::new();
    for_each_selected_index(&code, &state.selection, rc, &state.ovector, |index| {
        let range = index
            .filter(|index| *index < rc && state.ovector[*index * 2] != UNSET)
            .map(|index| {
                (
                    state.ovector[index * 2],
                    state.ovector[index * 2 + 1] - state.ovector[index * 2],
                )
            });
        captures.push(build_capture_value(
            range,
            state,
            subject,
            can_reference,
            heap,
        )?);
        Ok(())
    })?;
    TermBuilder::new(&mut *heap)
        .list_from_slice(&captures)
        .map_err(|_| BifError::SystemLimit)
}

fn build_capture_value<H: HeapAlloc + ?Sized>(
    range: Option<(usize, usize)>,
    state: &RunState,
    subject: Option<Term>,
    can_reference: bool,
    heap: &mut H,
) -> Result<Term, BifError> {
    match (state.capture_type, range) {
        (CaptureType::Index, None) => TermBuilder::new(&mut *heap)
            .tuple(&[small_term(-1)?, small_term(0)?])
            .map_err(|_| BifError::SystemLimit),
        (CaptureType::Index, Some((start, length))) => {
            let start = i64::try_from(start).map_err(|_| BifError::SystemLimit)?;
            let length = i64::try_from(length).map_err(|_| BifError::SystemLimit)?;
            TermBuilder::new(&mut *heap)
                .tuple(&[small_term(start)?, small_term(length)?])
                .map_err(|_| BifError::SystemLimit)
        }
        (CaptureType::Binary, None) => TermBuilder::new(&mut *heap)
            .binary(&[])
            .map_err(|_| BifError::SystemLimit),
        (CaptureType::Binary, Some((start, length))) if can_reference => {
            let subject = subject.ok_or(BifError::BADARG)?;
            TermBuilder::new(&mut *heap)
                .sub_binary_bif(subject, start * 8, length * 8)
                .map_err(|_| BifError::SystemLimit)
        }
        (CaptureType::Binary, Some((start, length))) => {
            with_subject_range(state, subject, start, length, |bytes| {
                TermBuilder::new(&mut *heap)
                    .binary(bytes)
                    .map_err(|_| BifError::SystemLimit)
            })
        }
        (CaptureType::List, None) => Ok(Term::NIL),
        (CaptureType::List, Some((start, length))) => {
            with_subject_range(state, subject, start, length, |bytes| {
                let capture = if state.unicode {
                    match std::str::from_utf8(bytes) {
                        Ok(text) => build_charlist(text, heap)?,
                        Err(error) => {
                            let valid = std::str::from_utf8(&bytes[..error.valid_up_to()])
                                .expect("validated UTF-8 prefix");
                            let tag = atom_term(if error.error_len().is_some() {
                                "error"
                            } else {
                                "incomplete"
                            })?;
                            let valid = build_charlist(valid, heap)?;
                            let rest = TermBuilder::new(&mut *heap)
                                .binary(&bytes[error.valid_up_to()..])
                                .map_err(|_| BifError::SystemLimit)?;
                            TermBuilder::new(&mut *heap)
                                .tuple(&[tag, valid, rest])
                                .map_err(|_| BifError::SystemLimit)?
                        }
                    }
                } else {
                    TermBuilder::new(&mut *heap)
                        .bytes_to_list(bytes)
                        .map_err(|_| BifError::SystemLimit)?
                };
                Ok(capture)
            })
        }
    }
}

// Port of erts/emulator/beam/erl_bif_re.c:1140-1225 (read captures from the original subject), OTP-29.1.1.
fn with_subject_range<T>(
    state: &RunState,
    subject: Option<Term>,
    start: usize,
    length: usize,
    f: impl FnOnce(&[u8]) -> Result<T, BifError>,
) -> Result<T, BifError> {
    let end = start.checked_add(length).ok_or(BifError::BADARG)?;
    if let Some(bytes) = state.subject.as_slice() {
        return f(bytes.get(start..end).ok_or(BifError::BADARG)?);
    }
    let subject = subject.ok_or(BifError::BADARG)?;
    with_binary_bytes(subject, |view| {
        if !view.start_bit().is_multiple_of(8)
            || !view.bit_len().is_multiple_of(8)
            || end > view.bit_len() / 8
        {
            return Err(BifError::BADARG);
        }
        let start = (view.start_bit() / 8)
            .checked_add(start)
            .ok_or(BifError::BADARG)?;
        let end = start.checked_add(length).ok_or(BifError::BADARG)?;
        f(view.bytes().get(start..end).ok_or(BifError::BADARG)?)
    })?
}

fn build_charlist<H: HeapAlloc + ?Sized>(text: &str, heap: &mut H) -> Result<Term, BifError> {
    let values = text
        .chars()
        .map(|ch| small_term(i64::from(u32::from(ch))))
        .collect::<Result<Vec<_>, _>>()?;
    TermBuilder::new(heap)
        .list_from_slice(&values)
        .map_err(|_| BifError::SystemLimit)
}

// Port of erts/emulator/beam/erl_bif_re.c:1495-1795 (re_run), OTP-29.1.1.
fn run_owned_slice(
    args: &[O],
    first: bool,
    state: Option<Box<RunState>>,
    loop_budget: i32,
    compiled_code: Option<CompiledCode>,
    parsed_options: Option<Options>,
    run_subject: RunSubject,
) -> Result<((Step, RunExecState), u64), BifError> {
    let RunSubject {
        prepared: prepared_subject,
        original: subject_term,
    } = run_subject;
    let mut state = match state {
        Some(state) => RunExecState::Trapped(state),
        None => {
            let opts = parsed_options.ok_or(BifError::BADARG)?;
            if opts.export {
                return Err(badopt_error());
            }
            let compiled = compiled_code.is_none()
                && matches!(args.get(1), Some(O::Tuple(fields)) if fields.len() == 5);
            let (code, capture_count, code_owner, unicode) = if let Some(compiled) = compiled_code {
                if opts.unique_compile {
                    return Err(BifError::BADARG);
                }
                let CompiledCode {
                    code,
                    capture_count,
                    unicode,
                    owner,
                } = compiled;
                let code_info = std::mem::ManuallyDrop::new(Code(code as *mut c_void));
                if opts.newline != 0 && opts.newline != code_info.info(INFO_NEWLINE) {
                    return Err(BifError::BADARG);
                }
                if opts.bsr != 0 && opts.bsr != code_info.info(INFO_BSR) {
                    return Err(BifError::BADARG);
                }
                (code, capture_count as usize, Some(owner), unicode)
            } else if compiled {
                if opts.unique_compile {
                    return Err(BifError::BADARG);
                }
                let (code, unicode) = decode(&args[1])?;
                if opts.newline != 0 && opts.newline != code.info(INFO_NEWLINE) {
                    return Err(BifError::BADARG);
                }
                if opts.bsr != 0 && opts.bsr != code.info(INFO_BSR) {
                    return Err(BifError::BADARG);
                }
                let capture_count = code.info(INFO_CAPTURES) as usize;
                (code.into_raw(), capture_count, None, unicode)
            } else {
                let pattern = iodata(&args[1], opts.unicode)?;
                match compile_code(&pattern, &opts) {
                    Ok(code) => {
                        let capture_count = code.info(INFO_CAPTURES) as usize;
                        (code.into_raw(), capture_count, None, opts.unicode)
                    }
                    Err((err, pos)) if opts.report_errors => {
                        return Ok((
                            (
                                Step::Done(compile_error(err, pos, true)),
                                RunExecState::Inline(RunState::empty()),
                            ),
                            0,
                        ));
                    }
                    Err(_) => return Err(BifError::BADARG),
                }
            };
            let subject = match prepared_subject {
                Some(subject) => subject,
                None => match iodata(&args[0], unicode) {
                    Ok(subject) => Subject::Bytes(subject),
                    Err(error) => {
                        if code_owner.is_none() {
                            drop(Code(code as *mut c_void));
                        }
                        return Err(error);
                    }
                },
            };
            if opts.offset > subject.len() && !opts.global {
                if code_owner.is_none() {
                    drop(Code(code as *mut c_void));
                }
                return Err(BifError::BADARG);
            }
            let code_info = std::mem::ManuallyDrop::new(Code(code as *mut c_void));
            let (selection, capture_type) = match selection(&code_info, opts.capture.as_ref()) {
                Ok(selection) => selection,
                Err(error) => {
                    if code_owner.is_none() {
                        drop(Code(code as *mut c_void));
                    }
                    return Err(error);
                }
            };
            RunExecState::Inline(RunState {
                code,
                code_owner,
                capture_count,
                subject,
                suppress_duplicate: None,
                session: MatchSession::default(),
                matched: false,
                match_rc: 0,
                ovector: vec![UNSET; (capture_count + 1) * 2],
                unicode,
                selection,
                capture_type,
                flags: if first {
                    opts.match_flags
                } else {
                    opts.match_flags | NO_UTF_CHECK
                },
                offset: opts.offset,
                matches: Vec::new(),
                phase: Phase::Main,
                opts,
            })
        }
    };
    let mut loops = 0;
    let step = advance(state.as_mut(), subject_term, loop_budget, &mut loops)?;
    Ok(((step, state), loops))
}
impl RunState {
    /// A state that owns nothing, for results that need no match.
    fn empty() -> Self {
        RunState {
            code: 0,
            code_owner: None,
            capture_count: 0,
            subject: Subject::empty(),
            suppress_duplicate: None,
            session: MatchSession::default(),
            matched: false,
            match_rc: 0,
            ovector: Vec::new(),
            unicode: false,
            selection: Selection::None,
            capture_type: CaptureType::Index,
            flags: 0,
            offset: 0,
            matches: Vec::new(),
            phase: Phase::Main,
            opts: Options::default(),
        }
    }
}
