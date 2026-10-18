//! OTP 29.1.1 `re` BIFs using the patched PCRE2 engine.
//!
//! PCRE2's loop counter is retained in `ar_re_match`; matching resumes there
//! synchronously until scheduler support can pass a reduction budget.

use std::cell::Cell;
use std::ffi::c_void;
use std::ptr;
use std::sync::Arc;

use arinsal_bifs::with_binary_bytes;
use arinsal_bifs::{BifError, BifFn, Ctx};
use arinsal_etf::OwnedTerm as O;
use arinsal_term::{
    ExportEntry, FunEntry, HeapAlloc, MagicRef, Node, Term, TermBuilder, from_owned, global_atoms,
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
        session: *mut *mut c_void,
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
    fn retain_fun(&mut self, value: Arc<FunEntry>) {
        self.0.retain_fun(value)
    }
    fn retain_export(&mut self, value: Arc<ExportEntry>) {
        self.0.retain_export(value)
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
    capture: Option<(O, CaptureType)>,
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
                    result.capture = Some((spec.clone(), CaptureType::Index));
                    result.unique_exec = true;
                }
                ("capture", [_, spec, ty]) => {
                    let kind = match atom_name(ty) {
                        Some("index") => CaptureType::Index,
                        Some("list") => CaptureType::List,
                        Some("binary") => CaptureType::Binary,
                        _ => return Err(badopt_error()),
                    };
                    result.capture = Some((spec.clone(), kind));
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
        let bytes = code.serialize()?;
        let checksum = crc32(&bytes);
        let mut header = b"re-PCRE2".to_vec();
        header.extend(checksum.to_be_bytes());
        header.extend([1, u8::from(opts.unicode)]);
        return Ok(success(O::Tuple(vec![
            atom("re_exported_pattern"),
            O::Binary(header),
            O::Binary(pattern),
            args.get(1).cloned().unwrap_or(O::Nil),
            O::Binary(bytes),
        ])));
    }
    Ok(success(compiled_tuple(&code, opts.unicode)?))
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
    let mut adapted = args.to_vec();
    if matches!(
        (name, args.len()),
        ("run", 2 | 3) | ("internal_run", 4) | ("inspect", 2)
    ) {
        let pattern_index = if name == "inspect" { 0 } else { 1 };
        if let Some(pattern) = args.get(pattern_index)
            && let Some(owned) = magic_pattern(*pattern)?
        {
            adapted[pattern_index] =
                from_owned(&owned, &mut Heap(&mut ctx.heap)).map_err(|_| BifError::SystemLimit)?;
        }
    }
    let bif = lookup("re", name, args.len() as u8).ok_or(BifError::BADARG)?;
    let result = bif(ctx, &adapted)?;
    if name == "compile" || name == "import" {
        return magic_compile_result(ctx, result);
    }
    Ok(result)
}

fn magic_pattern(term: Term) -> Result<Option<O>, BifError> {
    // SAFETY: arguments remain rooted in their process heap for this call.
    let Some(fields) = (unsafe { term.tuple_ref() }) else {
        return Ok(None);
    };
    if fields.len() != 5
        || atom_name(&to_owned(fields.get(0).unwrap()).map_err(|_| BifError::BADARG)?)
            != Some("re_pattern")
    {
        return Ok(None);
    }
    let reference = fields.get(4).unwrap();
    // SAFETY: the magic reference owner is retained by the argument heap.
    let Some(handle) =
        (unsafe { reference.magic_ref() }).and_then(|owner| owner.downcast_ref::<RegexHandle>())
    else {
        return Ok(None);
    };
    let mut owned = Vec::with_capacity(5);
    for index in 0..4 {
        owned.push(to_owned(fields.get(index).unwrap()).map_err(|_| BifError::BADARG)?);
    }
    owned.push(O::Binary(handle.0.clone()));
    Ok(Some(O::Tuple(owned)))
}

struct RegexHandle(Vec<u8>);

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
    let O::Binary(serialized) = &pattern[4] else {
        return Err(BifError::BADARG);
    };
    let serialized = serialized.clone();
    let mut heap = Heap(&mut ctx.heap);
    let mut terms = pattern[..4]
        .iter()
        .map(|item| from_owned(item, &mut heap).map_err(|_| BifError::SystemLimit))
        .collect::<Result<Vec<_>, _>>()?;
    let reference = TermBuilder::new(&mut heap)
        .magic_ref(MagicRef::new(RegexHandle(serialized)))
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
    spec: Option<&(O, CaptureType)>,
) -> Result<(Selection, CaptureType), BifError> {
    let Some((value, kind)) = spec else {
        return Ok((Selection::All, CaptureType::Index));
    };
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
    Ok((chosen, *kind))
}
fn selected_indices(
    code: &Code,
    selection: &Selection,
    rc: i32,
    ovector: &[usize],
) -> Vec<Option<usize>> {
    match selection {
        Selection::None => Vec::new(),
        Selection::All => (0..rc as usize).map(Some).collect(),
        Selection::AllButFirst => (1..rc as usize).map(Some).collect(),
        Selection::Specific(keys) => keys
            .iter()
            .map(|key| match key {
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
                    let size = unsafe {
                        ar_re_capture_name_range(code.0, zname.as_ptr(), &mut first, &mut last)
                    };
                    if size <= 0 || first.is_null() {
                        return None;
                    }
                    let count = (last as usize - first as usize) / size as usize + 1;
                    for i in 0..count {
                        // SAFETY: name-table scan returned this inclusive range and stride.
                        let entry =
                            unsafe { std::slice::from_raw_parts(first.add(i * size as usize), 2) };
                        let index = (usize::from(entry[0]) << 8) | usize::from(entry[1]);
                        if index < rc as usize && ovector[index * 2] != UNSET {
                            return Some(index);
                        }
                    }
                    None
                }
            })
            .collect(),
    }
}
fn capture_values(
    code: &Code,
    selection: &Selection,
    kind: CaptureType,
    rc: i32,
    ovector: &[usize],
    subject: &[u8],
    unicode: bool,
) -> (O, Vec<Option<(usize, usize)>>) {
    // Port of erts/emulator/beam/erl_bif_re.c:1030-1262 (build_exec_return), OTP-29.1.1.
    let indexes = selected_indices(code, selection, rc, ovector);
    let mut binary_ranges = Vec::with_capacity(indexes.len());
    let captures = indexes
        .into_iter()
        .map(|index| {
            let (start, end) = index
                .filter(|i| *i < rc as usize && ovector[*i * 2] != UNSET)
                .map(|i| (ovector[2 * i], ovector[2 * i + 1]))
                .unwrap_or((UNSET, UNSET));
            binary_ranges.push(if matches!(kind, CaptureType::Binary) && start != UNSET {
                Some((start, end - start))
            } else {
                None
            });
            match kind {
                CaptureType::Index => {
                    if start == UNSET {
                        pair(O::Int(-1), O::Int(0))
                    } else {
                        pair(O::Int(start as i64), O::Int((end - start) as i64))
                    }
                }
                CaptureType::Binary => O::Binary(if start == UNSET {
                    Vec::new()
                } else {
                    subject[start..end].to_vec()
                }),
                CaptureType::List => {
                    let bytes = if start == UNSET {
                        &[][..]
                    } else {
                        &subject[start..end]
                    };
                    if unicode {
                        match std::str::from_utf8(bytes) {
                            Ok(s) => O::charlist(s),
                            Err(err) => {
                                let valid = std::str::from_utf8(&bytes[..err.valid_up_to()])
                                    .expect("validated prefix");
                                O::Tuple(vec![
                                    atom(if err.error_len().is_some() {
                                        "error"
                                    } else {
                                        "incomplete"
                                    }),
                                    O::charlist(valid),
                                    O::Binary(bytes[err.valid_up_to()..].to_vec()),
                                ])
                            }
                        }
                    } else {
                        O::list(bytes.iter().map(|b| O::Int(i64::from(*b))).collect())
                    }
                }
            }
        })
        .collect();
    (O::list(captures), binary_ranges)
}
enum MatchFailure {
    Badarg,
    Limit(&'static str),
}
/// A match that ran out of its loop budget, with everything needed to continue it.
///
/// Port of erts/emulator/beam/erl_bif_re.c:1660-1680 (`RestartContext`), OTP-29.1.1. The
/// compiled code, the subject copy and the PCRE2 match state are owned here; the addresses
/// are plain integers so the state can sit in a magic reference.
pub struct RunState {
    code: usize,
    subject: Vec<u8>,
    session: usize,
    unicode: bool,
    flags: u32,
    offset: usize,
    matches: Vec<O>,
    binary_ranges: Vec<Vec<Option<(usize, usize)>>>,
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
}
impl Drop for RunState {
    fn drop(&mut self) {
        if self.session != 0 {
            let mut ovector = [0usize; 0];
            ffi_match(
                self.code,
                &[],
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
        drop(Code(self.code as *mut c_void));
    }
}

/// The only call into the PCRE2 matcher. `session` is the unfinished match state, zero when
/// there is none; mode 1 frees it.
#[allow(clippy::too_many_arguments)]
fn ffi_match(
    code: usize,
    subject: &[u8],
    offset: usize,
    flags: u32,
    limits: (i32, i32),
    ovector: &mut [usize],
    count: u32,
    budget: i32,
    session: &mut usize,
    mode: i32,
) -> MatchResult {
    let mut slot = *session as *mut c_void;
    // SAFETY: the pointers cover live byte and ovector buffers; `code` is a live PCRE2 code
    // and, while `session` is set, `code` and `subject` are the ones it was started with.
    let result = unsafe {
        ar_re_match(
            code as *const c_void,
            subject.as_ptr(),
            subject.len(),
            offset,
            flags,
            limits.0,
            limits.1,
            ovector.as_mut_ptr(),
            count,
            budget,
            &mut slot,
            mode,
        )
    };
    *session = slot as usize;
    result
}

enum Slice {
    Done(Option<(i32, Vec<usize>)>),
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
    let count = state.code().info(INFO_CAPTURES) as usize + 1;
    let mut ovector = vec![UNSET; count * 2];
    let result = ffi_match(
        state.code,
        &state.subject,
        offset,
        flags,
        (opts.match_limit, opts.depth_limit),
        &mut ovector,
        count as u32,
        budget,
        &mut state.session,
        0,
    );
    *loops += result.loops_consumed;
    match result.rc {
        PCRE2_ERROR_LOOP_LIMIT => Ok(Slice::Yield),
        rc if rc > 0 => Ok(Slice::Done(Some((rc, ovector)))),
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

/// Port of lib/stdlib/src/re.erl:1823-1906 (do_grun/loopexec), OTP-29.1.1, as a state machine
/// that can stop in the middle of any match and continue later.
fn advance(state: &mut RunState, budget: i32, loops: &mut u64) -> Result<Step, BifError> {
    // The options live in the state; the matcher borrows the state mutably.
    let opts = std::mem::take(&mut state.opts);
    let result = advance_with(state, &opts, budget, loops);
    state.opts = opts;
    result
}

fn advance_with(
    state: &mut RunState,
    opts: &Options,
    budget: i32,
    loops: &mut u64,
) -> Result<Step, BifError> {
    let (selection, kind) = {
        let code = state.code();
        selection(&code, opts.capture.as_ref())?
    };
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
                let Some((rc, ov)) = found else {
                    break;
                };
                let start = ov[0];
                let end = ov[1];
                let duplicate = state.suppress_duplicate.take() == Some((start, end));
                if !duplicate {
                    push_match(state, &selection, kind, rc, &ov);
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
                if let Some((retry_rc, retry_ov)) = retry
                    && (retry_ov[0], retry_ov[1]) != (start, start)
                {
                    // PCRE2's NOTEMPTY_ATSTART rejects an empty engine match. `\\K` may still
                    // reset the returned start to its end, so the ovector can be empty here.
                    push_match(state, &selection, kind, retry_rc, &retry_ov);
                    state.offset = retry_ov[1];
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
                    let b = state.subject[start];
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
                    && state.subject.get(start..start + 2) == Some(b"\r\n")
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
    let mut matches = state.matches.clone();
    if matches.is_empty() {
        return Ok(Step::Done(atom("nomatch")));
    }
    Ok(Step::Done(if opts.global {
        if matches!(selection, Selection::None) {
            atom("match")
        } else {
            pair(atom("match"), O::list(matches))
        }
    } else if matches!(selection, Selection::None) {
        atom("match")
    } else {
        pair(atom("match"), matches.remove(0))
    }))
}

fn push_match(
    state: &mut RunState,
    selection: &Selection,
    kind: CaptureType,
    rc: i32,
    ovector: &[usize],
) {
    if matches!(selection, Selection::None) {
        state.matches.push(O::Nil);
        state.binary_ranges.push(Vec::new());
    } else {
        let code = state.code();
        let (value, ranges) = capture_values(
            &code,
            selection,
            kind,
            rc,
            ovector,
            &state.subject,
            state.unicode,
        );
        state.matches.push(value);
        state.binary_ranges.push(ranges);
    }
}

/// Where a `re:run`/`re:internal_run` call stands after one slice.
pub enum Progress {
    /// The finished result.
    Done(Term),
    /// The loop budget ran out; resume with this state.
    Yield(Box<RunState>),
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
    let owned = if state.is_some() {
        // A trapped call continues from its restart state alone.
        Vec::new()
    } else {
        let mut adapted = args.to_vec();
        let pattern_index = 1;
        if let Some(pattern) = args.get(pattern_index)
            && let Some(owned) = magic_pattern(*pattern)?
        {
            adapted[pattern_index] =
                from_owned(&owned, &mut Heap(&mut ctx.heap)).map_err(|_| BifError::SystemLimit)?;
        }
        adapted
            .iter()
            .map(|term| to_owned(*term).map_err(|_| BifError::BADARG))
            .collect::<Result<Vec<_>, _>>()?
    };
    let first = if state.is_some() {
        false
    } else {
        match (name, owned.len()) {
            ("run", 2 | 3) => true,
            ("internal_run", 4) => match atom_name(&owned[3]) {
                Some("true") => true,
                Some("false") => false,
                _ => return Err(BifError::BADARG),
            },
            _ => return Err(BifError::BADARG),
        }
    };
    let (step, loops) = run_owned_slice(&owned, first, state, loop_budget)?;
    match step {
        (Step::Done(result), state) => {
            let heap = &mut Heap(&mut ctx.heap);
            let value = match binary_capture_result(&result, &state, args.first().copied(), heap)? {
                Some(value) => value,
                None => from_owned(&result, heap).map_err(|_| BifError::SystemLimit)?,
            };
            Ok((Progress::Done(value), loops))
        }
        (Step::Yield, state) => Ok((Progress::Yield(state), loops)),
    }
}

fn binary_capture_result<H: HeapAlloc + ?Sized>(
    result: &O,
    state: &RunState,
    subject: Option<Term>,
    heap: &mut H,
) -> Result<Option<Term>, BifError> {
    if !state
        .opts
        .capture
        .as_ref()
        .is_some_and(|(_, kind)| matches!(kind, CaptureType::Binary))
    {
        return Ok(None);
    }
    let O::Tuple(fields) = result else {
        return Ok(None);
    };
    if fields.len() != 2 || atom_name(&fields[0]) != Some("match") {
        return Ok(None);
    }
    let Some(subject) = subject.filter(|term| term.classify() == arinsal_term::TermKind::Bitstring)
    else {
        return Ok(None);
    };
    let can_reference = with_binary_bytes(subject, |view| {
        view.is_off_heap()
            && view.start_bit().is_multiple_of(8)
            && view.bit_len().is_multiple_of(8)
            && view.bit_len() > 64 * 8
    })?;
    let value = if state.opts.global {
        let matches = state
            .binary_ranges
            .iter()
            .map(|ranges| binary_capture_list(ranges, state, subject, can_reference, heap))
            .collect::<Result<Vec<_>, _>>()?;
        let matches = TermBuilder::new(&mut *heap)
            .list_from_slice(&matches)
            .map_err(|_| BifError::SystemLimit)?;
        let tag =
            from_owned(&atom("match"), &mut Heap(&mut *heap)).map_err(|_| BifError::SystemLimit)?;
        TermBuilder::new(&mut *heap)
            .tuple(&[tag, matches])
            .map_err(|_| BifError::SystemLimit)?
    } else {
        let Some(ranges) = state.binary_ranges.first() else {
            return Ok(None);
        };
        let captures = binary_capture_list(ranges, state, subject, can_reference, heap)?;
        let tag =
            from_owned(&atom("match"), &mut Heap(&mut *heap)).map_err(|_| BifError::SystemLimit)?;
        TermBuilder::new(&mut *heap)
            .tuple(&[tag, captures])
            .map_err(|_| BifError::SystemLimit)?
    };
    Ok(Some(value))
}

fn binary_capture_list<H: HeapAlloc + ?Sized>(
    ranges: &[Option<(usize, usize)>],
    state: &RunState,
    subject: Term,
    can_reference: bool,
    heap: &mut H,
) -> Result<Term, BifError> {
    let mut captures = Vec::with_capacity(ranges.len());
    for range in ranges {
        let capture = match (can_reference, range) {
            (true, Some((start, length))) => TermBuilder::new(&mut *heap)
                .sub_binary_bif(subject, start * 8, length * 8)
                .map_err(|_| BifError::SystemLimit)?,
            (_, None) => from_owned(&O::Binary(Vec::new()), &mut Heap(&mut *heap))
                .map_err(|_| BifError::SystemLimit)?,
            (false, Some((start, length))) => from_owned(
                &O::Binary(state.subject[*start..*start + *length].to_vec()),
                &mut Heap(&mut *heap),
            )
            .map_err(|_| BifError::SystemLimit)?,
        };
        captures.push(capture);
    }
    TermBuilder::new(&mut *heap)
        .list_from_slice(&captures)
        .map_err(|_| BifError::SystemLimit)
}

fn run_owned_slice(
    args: &[O],
    first: bool,
    state: Option<Box<RunState>>,
    loop_budget: i32,
) -> Result<((Step, Box<RunState>), u64), BifError> {
    let mut state = match state {
        Some(state) => state,
        None => {
            let opts = options(args.get(2).unwrap_or(&O::Nil))?;
            if opts.export {
                return Err(badopt_error());
            }
            let compiled = matches!(&args[1], O::Tuple(fields) if fields.len() == 5);
            let (code, unicode) = if compiled {
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
                (code, unicode)
            } else {
                let pattern = iodata(&args[1], opts.unicode)?;
                match compile_code(&pattern, &opts) {
                    Ok(code) => (code, opts.unicode),
                    Err((err, pos)) if opts.report_errors => {
                        return Ok((
                            (
                                Step::Done(compile_error(err, pos, true)),
                                Box::new(RunState::empty()),
                            ),
                            0,
                        ));
                    }
                    Err(_) => return Err(BifError::BADARG),
                }
            };
            let subject = iodata(&args[0], unicode)?;
            if opts.offset > subject.len() && !opts.global {
                return Err(BifError::BADARG);
            }
            Box::new(RunState {
                code: code.into_raw(),
                subject,
                binary_ranges: Vec::new(),
                suppress_duplicate: None,
                session: 0,
                unicode,
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
    let step = advance(&mut state, loop_budget, &mut loops)?;
    Ok(((step, state), loops))
}
impl RunState {
    /// A state that owns nothing, for results that need no match.
    fn empty() -> Self {
        RunState {
            code: 0,
            subject: Vec::new(),
            binary_ranges: Vec::new(),
            suppress_duplicate: None,
            session: 0,
            unicode: false,
            flags: 0,
            offset: 0,
            matches: Vec::new(),
            phase: Phase::Main,
            opts: Options::default(),
        }
    }
}
