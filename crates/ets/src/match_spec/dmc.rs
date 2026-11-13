//! Match program compiler.
//!
//! Port of erts/emulator/beam/erl_db_util.c:1717 (db_match_compile) and the `dmc_*` code
//! generators (:4047-5720), OTP-29.1.1. The program is a flat vector of [`Op`]s, one enum
//! variant per `matchXxx` opcode; label operands are indices into that vector instead of
//! word offsets.

use super::{cons, is_float_term, tuple_view, variable};
use crate::EtsError;
use arinsal_term::{HeapAlloc, Term, TermBuilder, TermError, TermKind, VecHeap, global_atoms};

/// `DCOMP_TABLE`: ETS and dets.
pub(super) const DCOMP_TABLE: u32 = 1;
/// `DCOMP_TRACE`.
pub(super) const DCOMP_TRACE: u32 = 4;
/// `DCOMP_FAKE_DESTRUCTIVE`: `erlang:match_spec_test/3` must not change process state.
pub(super) const DCOMP_FAKE_DESTRUCTIVE: u32 = 8;
/// `DCOMP_DIALECT_MASK`.
const DCOMP_DIALECT_MASK: u32 = 7;
/// `DCOMP_ALLOW_TRACE_OPS`.
pub(super) const DCOMP_ALLOW_TRACE_OPS: u32 = 0x10;
/// `DCOMP_CALL_TRACE`.
pub(super) const DCOMP_CALL_TRACE: u32 = 0x20;

const DBIF_GUARD: u32 = 0;
const DBIF_BODY: u32 = 1;
const DBIF_TABLE_GUARD: u32 = 1 << (DCOMP_TABLE + DBIF_GUARD);
const DBIF_TABLE_BODY: u32 = 1 << (DCOMP_TABLE + DBIF_BODY);
const DBIF_TRACE_GUARD: u32 = 1 << (DCOMP_TRACE + DBIF_GUARD);
const DBIF_TRACE_BODY: u32 = 1 << (DCOMP_TRACE + DBIF_BODY);
const DBIF_ALL: u32 = DBIF_TABLE_GUARD | DBIF_TABLE_BODY | DBIF_TRACE_GUARD | DBIF_TRACE_BODY;

/// `DMCRet` without `retOk`.
// Port of erts/emulator/beam/erl_db_util.c (DMCRet), OTP-29.1.1.
#[derive(Debug)]
pub(super) enum DmcFail {
    /// `retFail`.
    Fail,
    /// `retRestart`: a variable number outside the variable table; compile again compacted.
    Restart,
}

/// `DMCRet`, with `Ok` for `retOk`.
type DmcResult<T> = Result<T, DmcFail>;

impl From<EtsError> for DmcFail {
    fn from(_: EtsError) -> Self {
        Self::Fail
    }
}

impl From<TermError> for DmcFail {
    fn from(_: TermError) -> Self {
        Self::Fail
    }
}

/// `DMC_ERR_STR_LEN`: `vsnprintf` into the error buffer keeps one byte less.
const DMC_ERR_STR_LEN: usize = 100;

/// `DMCError`. The `WARNING`, `VAR_WARNING` and `TERM_WARNING` macros that would add a
/// `dmcWarning` are never used in OTP-29.1.1, so every entry is an error.
struct DmcError {
    /// Variable number the message is about, `-1` for none.
    variable: i32,
    /// The formatted string; `%d` stands for the variable number.
    error_string: Vec<u8>,
}

/// Error list of one compilation (`DMCErrInfo`), in the order the errors were added.
// Port of erts/emulator/beam/erl_db_util.c (DMCErrInfo, db_new_dmc_err_info), OTP-29.1.1;
// erts links the errors in reverse to ease the formatting, a vector in order does the same.
#[derive(Default)]
pub(super) struct DmcErrInfo {
    /// `var_trans`: original variable numbers by compacted number.
    var_trans: Option<Vec<usize>>,
    error_added: bool,
    errors: Vec<DmcError>,
}

impl DmcErrInfo {
    pub(super) fn new() -> Self {
        Self::default()
    }

    // Port of erts/emulator/beam/erl_db_util.c (vadd_dmc_err), OTP-29.1.1.
    fn add(&mut self, variable: i32, mut text: Vec<u8>) {
        text.truncate(DMC_ERR_STR_LEN - 1);
        self.errors.push(DmcError {
            variable,
            error_string: text,
        });
        self.error_added = true;
    }

    /// Port of erts/emulator/beam/erl_db_util.c (add_dmc_err with `dmcError`) for the
    /// shape errors of `db_match_set_lint`.
    pub(super) fn add_error(&mut self, text: &[u8]) {
        self.add(-1, text.to_vec());
    }

    /// `add_dmc_err(..., "<prefix>%T<suffix>", term)`.
    pub(super) fn add_term_error(&mut self, prefix: &str, term: Term, suffix: &str) {
        let text = term_message(prefix, term, suffix);
        self.add(-1, text);
    }

    // Port of erts/emulator/beam/erl_db_util.c (db_format_dmc_err_info), OTP-29.1.1.
    pub(super) fn format<H: HeapAlloc>(&self, dst: &mut H) -> Result<Term, EtsError> {
        let mut builder = TermBuilder::new(dst);
        let mut list = Term::NIL;
        let mut entries = Vec::with_capacity(self.errors.len());
        for error in &self.errors {
            let variable = usize::try_from(error.variable).ok();
            let vnum = match (variable, &self.var_trans) {
                (Some(index), Some(trans)) if index < trans.len() => Some(trans[index]),
                (variable, _) => variable,
            };
            let text = match vnum {
                Some(vnum) => {
                    replace_first(&error.error_string, b"%d", vnum.to_string().as_bytes())
                }
                None => error.error_string.clone(),
            };
            let chars = text
                .iter()
                .map(|&byte| Term::small(i64::from(byte)).ok_or(EtsError::BadArg))
                .collect::<Result<Vec<_>, _>>()?;
            let text = builder.list_from_iter(chars)?;
            entries.push(
                builder.tuple(&[
                    Term::atom(
                        global_atoms()
                            .intern("error")
                            .map_err(|_| EtsError::BadArg)?,
                    ),
                    text,
                ])?,
            );
        }
        for entry in entries.into_iter().rev() {
            list = builder.cons(entry, list)?;
        }
        Ok(list)
    }
}

fn replace_first(text: &[u8], pattern: &[u8], with: &[u8]) -> Vec<u8> {
    match text
        .windows(pattern.len())
        .position(|window| window == pattern)
    {
        Some(at) => [&text[..at], with, &text[at + pattern.len()..]].concat(),
        None => text.to_vec(),
    }
}

/// `erts_vsnprintf` of `"<prefix>%T<suffix>"`: the term printed, the result cut to fit the
/// error buffer.
fn term_message(prefix: &str, term: Term, suffix: &str) -> Vec<u8> {
    let mut text = prefix.as_bytes().to_vec();
    // `%T` without precision: the default print budget; the buffer only truncates.
    arinsal_term::printf_term::erts_printf_t(&mut text, term, -1);
    text.extend_from_slice(suffix.as_bytes());
    text.truncate(DMC_ERR_STR_LEN - 1);
    text
}

/// `DMC_DEFAULT_SIZE`: variables numbered at or above this force a compaction.
const DMC_DEFAULT_SIZE: usize = 100;

/// Guard BIFs with an allocation-free small-integer or type-test implementation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Fast {
    Eq,
    Ne,
    ExactEq,
    ExactNe,
    Gt,
    Ge,
    Lt,
    Le,
    Add,
    Sub,
    Mul,
    Div,
    Rem,
    Band,
    Bor,
    Bxor,
    IsAtom,
    IsInteger,
    IsTuple,
    IsList,
    IsNumber,
    Not,
    Element,
    TupleSize,
    None,
}

/// One entry of `guard_tab`.
// Port of erts/emulator/beam/erl_db_util.c:572 (guard_tab), OTP-29.1.1.
#[derive(Debug)]
pub(super) struct GuardBif {
    pub name: &'static str,
    pub arity: usize,
    flags: u32,
    pub fast_fn: Option<super::pam::FastBifFn>,
}

macro_rules! bif {
    ($name:expr, $arity:expr, $flags:expr, $fast:ident) => {
        GuardBif {
            name: $name,
            arity: $arity,
            flags: $flags,
            fast_fn: super::pam::fast_fn_for(Fast::$fast),
        }
    };
}

static GUARD_TAB: &[GuardBif] = &[
    bif!("is_atom", 1, DBIF_ALL, IsAtom),
    bif!("is_float", 1, DBIF_ALL, None),
    bif!("is_integer", 1, DBIF_ALL, IsInteger),
    bif!("is_integer", 3, DBIF_ALL, None),
    bif!("is_list", 1, DBIF_ALL, IsList),
    bif!("is_number", 1, DBIF_ALL, IsNumber),
    bif!("is_pid", 1, DBIF_ALL, None),
    bif!("is_port", 1, DBIF_ALL, None),
    bif!("is_reference", 1, DBIF_ALL, None),
    bif!("is_tuple", 1, DBIF_ALL, IsTuple),
    bif!("is_map", 1, DBIF_ALL, None),
    bif!("is_binary", 1, DBIF_ALL, None),
    bif!("is_bitstring", 1, DBIF_ALL, None),
    bif!("is_boolean", 1, DBIF_ALL, None),
    bif!("is_function", 1, DBIF_ALL, None),
    bif!("is_function", 2, DBIF_ALL, None),
    bif!("is_record", 3, DBIF_ALL, None),
    bif!("abs", 1, DBIF_ALL, None),
    bif!("element", 2, DBIF_ALL, Element),
    bif!("hd", 1, DBIF_ALL, None),
    bif!("length", 1, DBIF_ALL, None),
    bif!("max", 2, DBIF_ALL, None),
    bif!("min", 2, DBIF_ALL, None),
    bif!("node", 1, DBIF_ALL, None),
    bif!("node", 0, DBIF_ALL, None),
    bif!("round", 1, DBIF_ALL, None),
    bif!("size", 1, DBIF_ALL, None),
    bif!("map_size", 1, DBIF_ALL, None),
    bif!("map_get", 2, DBIF_ALL, None),
    bif!("is_map_key", 2, DBIF_ALL, None),
    bif!("bit_size", 1, DBIF_ALL, None),
    bif!("byte_size", 1, DBIF_ALL, None),
    bif!("tuple_size", 1, DBIF_ALL, TupleSize),
    bif!("binary_part", 2, DBIF_ALL, None),
    bif!("binary_part", 3, DBIF_ALL, None),
    bif!("tl", 1, DBIF_ALL, None),
    bif!("trunc", 1, DBIF_ALL, None),
    bif!("float", 1, DBIF_ALL, None),
    bif!("ceil", 1, DBIF_ALL, None),
    bif!("floor", 1, DBIF_ALL, None),
    bif!("+", 1, DBIF_ALL, None),
    bif!("-", 1, DBIF_ALL, None),
    bif!("+", 2, DBIF_ALL, Add),
    bif!("-", 2, DBIF_ALL, Sub),
    bif!("*", 2, DBIF_ALL, Mul),
    bif!("/", 2, DBIF_ALL, None),
    bif!("div", 2, DBIF_ALL, Div),
    bif!("rem", 2, DBIF_ALL, Rem),
    bif!("band", 2, DBIF_ALL, Band),
    bif!("bor", 2, DBIF_ALL, Bor),
    bif!("bxor", 2, DBIF_ALL, Bxor),
    bif!("bnot", 1, DBIF_ALL, None),
    bif!("bsl", 2, DBIF_ALL, None),
    bif!("bsr", 2, DBIF_ALL, None),
    bif!(">", 2, DBIF_ALL, Gt),
    bif!(">=", 2, DBIF_ALL, Ge),
    bif!("<", 2, DBIF_ALL, Lt),
    bif!("=<", 2, DBIF_ALL, Le),
    bif!("==", 2, DBIF_ALL, Eq),
    bif!("=:=", 2, DBIF_ALL, ExactEq),
    bif!("/=", 2, DBIF_ALL, Ne),
    bif!("=/=", 2, DBIF_ALL, ExactNe),
    bif!("not", 1, DBIF_ALL, Not),
    bif!("xor", 2, DBIF_ALL, None),
    bif!("get_tcw", 0, DBIF_TRACE_GUARD | DBIF_TRACE_BODY, None),
    bif!("set_tcw", 1, DBIF_TRACE_BODY, None),
];

/// Port of erts/emulator/beam/erl_db_util.c:5720 (dmc_lookup_bif), OTP-29.1.1.
fn dmc_lookup_bif(name: &str, arity: usize) -> Option<&'static GuardBif> {
    GUARD_TAB
        .iter()
        .find(|bif| bif.name == name && bif.arity == arity)
}

/// The `matchXxx` instruction set of erl_db_util.h (`MatchOps`).
#[derive(Clone, Copy, Debug)]
pub(super) enum Op {
    TryMeElse(usize),
    Array(usize),
    ArrayPrefix(usize),
    ArrayBind(usize),
    Tuple(usize),
    PushT(usize),
    List,
    PushL,
    Map(usize),
    PushM(usize),
    Key(Term),
    Pop,
    Swap,
    Bind(usize),
    Cmp(usize),
    EqBin(Term),
    EqFloat(u64),
    EqRef(Term),
    EqBig(Term),
    Eq(Term),
    Skip,
    PushC(Term),
    ConsA,
    ConsB,
    MkTuple(usize),
    MkFlatMap(usize),
    MkHashMap(usize),
    Call0(&'static GuardBif),
    Call1(&'static GuardBif),
    Call2(&'static GuardBif),
    Call3(&'static GuardBif),
    PushVResult(usize),
    PushV(usize),
    PushExpr,
    PushArrayAsList,
    PushArrayAsListU,
    True,
    Or(usize),
    And(usize),
    OrElse(usize),
    AndAlso(usize),
    Jump(usize),
    SelfPid,
    Waste,
    Return,
    ProcessDump,
    Display,
    SetReturnTrace,
    SetExceptionTrace,
    IsSeqTrace,
    SetSeqToken,
    SetSeqTokenFake,
    GetSeqToken,
    EnableTrace,
    EnableTrace2,
    DisableTrace,
    DisableTrace2,
    Caller,
    CallerLine,
    CurrentStacktrace,
    Silent,
    Trace2,
    Trace3,
    Catch,
    Halt,
}

impl Op {
    /// Number of `UWord`s emitted for this instruction by OTP's DMC compiler.
    // Port of erts/emulator/beam/erl_db_util.c (DMC_PUSH/DMC_PUSH2), OTP-29.1.1.
    pub(super) fn erts_word_size(self) -> usize {
        match self {
            Self::TryMeElse(_)
            | Self::Array(_)
            | Self::ArrayPrefix(_)
            | Self::ArrayBind(_)
            | Self::Tuple(_)
            | Self::PushT(_)
            | Self::Map(_)
            | Self::PushM(_)
            | Self::Key(_)
            | Self::Bind(_)
            | Self::Cmp(_)
            | Self::EqBin(_)
            | Self::EqFloat(_)
            | Self::Eq(_)
            | Self::PushC(_)
            | Self::MkTuple(_)
            | Self::MkFlatMap(_)
            | Self::MkHashMap(_)
            | Self::Call0(_)
            | Self::Call1(_)
            | Self::Call2(_)
            | Self::Call3(_)
            | Self::PushVResult(_)
            | Self::PushV(_)
            | Self::Or(_)
            | Self::And(_)
            | Self::OrElse(_)
            | Self::AndAlso(_)
            | Self::Jump(_) => 2,
            Self::EqRef(term) | Self::EqBig(term) => 1 + arinsal_term::size_object(term),
            Self::List
            | Self::PushL
            | Self::Pop
            | Self::Swap
            | Self::Skip
            | Self::ConsA
            | Self::ConsB
            | Self::PushExpr
            | Self::PushArrayAsList
            | Self::PushArrayAsListU
            | Self::True
            | Self::SelfPid
            | Self::Waste
            | Self::Return
            | Self::ProcessDump
            | Self::Display
            | Self::SetReturnTrace
            | Self::SetExceptionTrace
            | Self::IsSeqTrace
            | Self::SetSeqToken
            | Self::SetSeqTokenFake
            | Self::GetSeqToken
            | Self::EnableTrace
            | Self::EnableTrace2
            | Self::DisableTrace
            | Self::DisableTrace2
            | Self::Caller
            | Self::CallerLine
            | Self::CurrentStacktrace
            | Self::Silent
            | Self::Trace2
            | Self::Trace3
            | Self::Catch
            | Self::Halt => 1,
        }
    }
}

/// `MatchProg` minus the saved terms, which live in the program's heap.
pub(super) struct Compiled {
    pub text: Vec<Op>,
    pub num_bindings: usize,
    pub stack_need: usize,
}

#[derive(Clone, Copy, Default)]
struct DmcVariable {
    is_bound: bool,
    is_in_body: bool,
}

struct Dmc<'a> {
    heap: &'a mut VecHeap,
    text: Vec<Op>,
    vars: Vec<DmcVariable>,
    vars_used: usize,
    cflags: u32,
    is_guard: bool,
    special: bool,
    stack_used: isize,
    stack_need: isize,
    num_match: usize,
    current_match: usize,
    matchexpr: Vec<Term>,
    guardexpr: Vec<Term>,
    bodyexpr: Vec<Term>,
    is_prefix: &'a [bool],
    /// `erts_get_stacklimit()` of the compiling thread.
    stack_limit: usize,
    /// `context->err_info`: when set, errors are recorded and the compilation goes on.
    err_info: Option<&'a mut DmcErrInfo>,
    /// `context->freason`: `system_limit` when the nesting guard fired, else `badarg`.
    system_limit: bool,
}

fn atom_is(term: Term, text: &str) -> bool {
    term.as_atom()
        .is_some_and(|atom| global_atoms().text(atom) == Some(text))
}

fn fail<T>() -> DmcResult<T> {
    Err(DmcFail::Fail)
}

/// Elements of a tuple term, empty for anything else.
fn tuple_items(term: Term) -> Vec<Term> {
    tuple_view(term)
        .map(|view| view.iter().collect())
        .unwrap_or_default()
}

fn map_pairs(term: Term) -> DmcResult<Vec<(Term, Term)>> {
    arinsal_maps::to_list(term).map_err(|_| DmcFail::Fail)
}

/// Port of erts/emulator/beam/erl_db_util.c:5916 (my_copy_struct), OTP-29.1.1: the term a
/// constant expression stands for, with `{const, X}` and `{{...}}` unwrapped.
fn const_value(term: Term, heap: &mut VecHeap) -> DmcResult<Term> {
    match term.classify() {
        TermKind::List => {
            let (head, tail) = cons(term).ok_or(DmcFail::Fail)?;
            let head = const_value(head, heap)?;
            let tail = const_value(tail, heap)?;
            Ok(TermBuilder::new(heap).cons(head, tail)?)
        }
        TermKind::Tuple => {
            let items = tuple_items(term);
            if items.len() == 1 && items[0].classify() == TermKind::Tuple {
                let inner = tuple_items(items[0]);
                let mut values = Vec::with_capacity(inner.len());
                for element in inner {
                    values.push(const_value(element, heap)?);
                }
                return Ok(TermBuilder::new(heap).tuple(&values)?);
            }
            if items.len() == 2 && atom_is(items[0], "const") {
                return Ok(items[1]);
            }
            fail()
        }
        TermKind::Map => {
            let mut pairs = Vec::new();
            for (key, value) in map_pairs(term)? {
                pairs.push((const_value(key, heap)?, const_value(value, heap)?));
            }
            Ok(TermBuilder::new(heap).flatmap_from_pairs(&pairs)?)
        }
        _ => Ok(term),
    }
}

impl Dmc<'_> {
    // Port of erts/emulator/beam/erl_db_util.c (RETURN_ERROR_X), OTP-29.1.1: with error
    // information the error is added and the expression counts as non-constant, without it
    // the compilation fails.
    fn error_x(&mut self, variable: i32, text: Vec<u8>) -> DmcResult<bool> {
        match self.err_info.as_deref_mut() {
            Some(info) => {
                info.add(variable, text);
                Ok(false)
            }
            None => fail(),
        }
    }

    /// `RETURN_ERROR`.
    fn return_error(&mut self, text: &str) -> DmcResult<bool> {
        if self.err_info.is_none() {
            return fail();
        }
        self.error_x(-1, text.as_bytes().to_vec())
    }

    /// `RETURN_TERM_ERROR` with the message `<prefix>%T<suffix>`.
    fn return_term_error(&mut self, prefix: &str, term: Term, suffix: &str) -> DmcResult<bool> {
        if self.err_info.is_none() {
            return fail();
        }
        self.error_x(-1, term_message(prefix, term, suffix))
    }

    fn bump_need(&mut self) {
        if self.stack_used > self.stack_need {
            self.stack_need = self.stack_used;
        }
    }

    // Port of erts/emulator/beam/erl_db_util.c:4047 (dmc_one_term), OTP-29.1.1: the part for
    // a variable number beyond the variable table ("Ouch, big integer in match variable").
    fn restart_compacted(&mut self, stack: &mut Vec<Term>) -> DmcResult<()> {
        let num_match = self.num_match;
        let all: Vec<Term> = self
            .matchexpr
            .iter()
            .chain(&self.guardexpr)
            .chain(&self.bodyexpr)
            .copied()
            .collect();
        let (compacted, size) = match_compact(&all, self.heap, self.err_info.as_deref_mut())?;
        self.matchexpr = compacted[..num_match].to_vec();
        self.guardexpr = compacted[num_match..2 * num_match].to_vec();
        self.bodyexpr = compacted[2 * num_match..].to_vec();
        self.vars = vec![DmcVariable::default(); size];
        stack.clear();
        self.text.clear();
        Err(DmcFail::Restart)
    }

    // Port of erts/emulator/beam/erl_db_util.c:4047 (dmc_one_term), OTP-29.1.1.
    fn one_term(&mut self, stack: &mut Vec<Term>, c: Term) -> DmcResult<()> {
        if !c.is_pointer() {
            if let Some(n) = variable(c) {
                if n >= self.vars.len() {
                    return self.restart_compacted(stack);
                }
                if self.vars[n].is_bound {
                    self.text.push(Op::Cmp(n));
                } else {
                    if n >= self.vars_used {
                        self.vars_used = n + 1;
                    }
                    self.text.push(Op::Bind(n));
                    self.vars[n].is_bound = true;
                }
            } else if atom_is(c, "_") {
                self.text.push(Op::Skip);
            } else {
                self.text.push(Op::Eq(c));
            }
            return Ok(());
        }
        match c.classify() {
            TermKind::List => {
                self.text.push(Op::PushL);
                self.stack_used += 1;
                stack.push(c);
            }
            TermKind::Tuple => {
                self.text.push(Op::PushT(tuple_items(c).len()));
                self.stack_used += 1;
                stack.push(c);
            }
            TermKind::Map => {
                let n = arinsal_maps::size(c).map_err(|_| DmcFail::Fail)?;
                self.text.push(Op::PushM(n));
                self.stack_used += 1;
                stack.push(c);
            }
            TermKind::Ref => self.text.push(Op::EqRef(c)),
            TermKind::Number if is_float_term(c) => {
                self.text.push(Op::EqFloat(super::float_bits(c)?));
            }
            TermKind::Number => self.text.push(Op::EqBig(c)),
            _ => self.text.push(Op::EqBin(c)),
        }
        Ok(())
    }

    // Port of erts/emulator/beam/erl_db_util.c:4200 (do_emit_constant), OTP-29.1.1.
    fn emit_constant(&mut self, t: Term) -> DmcResult<()> {
        let value = const_value(t, self.heap)?;
        self.text.push(Op::PushC(value));
        self.stack_used += 1;
        self.bump_need();
        Ok(())
    }

    /// Emit `elements` as the constant tuple `{{...}}` would produce.
    fn emit_constant_tuple(&mut self, elements: &[Term]) -> DmcResult<()> {
        let mut values = Vec::with_capacity(elements.len());
        for &element in elements {
            values.push(const_value(element, self.heap)?);
        }
        let tuple = TermBuilder::new(self.heap).tuple(&values)?;
        self.text.push(Op::PushC(tuple));
        self.stack_used += 1;
        self.bump_need();
        Ok(())
    }

    // Port of erts/emulator/beam/erl_db_util.c:4269 (dmc_list), OTP-29.1.1.
    fn list(&mut self, t: Term) -> DmcResult<bool> {
        let (head, tail) = cons(t).ok_or(DmcFail::Fail)?;
        let c1 = self.expr(head)?;
        let c2 = self.expr(tail)?;
        if c1 && c2 {
            return Ok(true);
        }
        if !c1 {
            // The CAR is not a constant, so if the CDR is, we just push it, otherwise it is
            // already pushed.
            if c2 {
                self.emit_constant(tail)?;
            }
            self.text.push(Op::ConsA);
        } else {
            self.emit_constant(head)?;
            self.text.push(Op::ConsB);
        }
        self.stack_used -= 1;
        Ok(false)
    }

    // Port of erts/emulator/beam/erl_db_util.c:4308 (dmc_rearrange_constants), OTP-29.1.1.
    fn rearrange_constants(&mut self, textpos: usize, p: &[Term]) -> DmcResult<()> {
        let saved = self.text.split_off(textpos);
        for &element in p.iter().rev() {
            self.emit_constant(element)?;
        }
        self.text.extend(saved);
        Ok(())
    }

    // Port of erts/emulator/beam/erl_db_util.c:4324 (dmc_array), OTP-29.1.1.
    fn array(&mut self, p: &[Term]) -> DmcResult<bool> {
        let nelems = p.len();
        let mut all_constant = true;
        let textpos = self.text.len();
        let mut preventive_bumps = 0;
        for i in (0..nelems).rev() {
            let c = self.expr(p[i])?;
            if !c && all_constant {
                all_constant = false;
                if i + 1 < nelems {
                    // Revert preventive stack bumps as they will now be done again for real
                    // by emit_constant().
                    self.stack_used -= preventive_bumps;
                    self.rearrange_constants(textpos, &p[i + 1..])?;
                }
            } else if c {
                if all_constant {
                    // OTP-17379: the constants may later become matchPushC, so account for
                    // their stack use now.
                    self.stack_used += 1;
                    preventive_bumps += 1;
                } else {
                    self.emit_constant(p[i])?;
                }
            }
        }
        if all_constant {
            self.stack_used -= preventive_bumps;
        }
        Ok(all_constant)
    }

    // Port of erts/emulator/beam/erl_db_util.c:4384 (dmc_tuple), OTP-29.1.1.
    fn tuple_elements(&mut self, p: &[Term]) -> DmcResult<bool> {
        let all_constant = self.array(p)?;
        if all_constant {
            return Ok(true);
        }
        self.text.push(Op::MkTuple(p.len()));
        self.stack_used -= p.len() as isize - 1;
        Ok(false)
    }

    // Port of erts/emulator/beam/erl_db_util.c:4411 (dmc_map), OTP-29.1.1.
    fn map(&mut self, t: Term) -> DmcResult<bool> {
        let pairs = map_pairs(t)?;
        let nelems = pairs.len();
        if !t.is_hashmap() {
            let keys: Vec<Term> = pairs.iter().map(|pair| pair.0).collect();
            let values: Vec<Term> = pairs.iter().map(|pair| pair.1).collect();
            let textpos = self.text.len();
            let constant_values = self.array(&values)?;
            if constant_values {
                // We may have to convert all values to individual matchPushC instructions,
                // which needs more stack than estimated, so bump it for dmc_tuple.
                self.stack_used += nelems as isize;
            }
            let constant_keys = self.tuple_elements(&keys)?;
            if constant_values {
                self.stack_used -= nelems as isize;
            }
            if constant_values && constant_keys {
                return Ok(true);
            }
            if constant_values {
                // Nothing was emitted by the first array: put the constants first and the
                // key tuple after.
                self.rearrange_constants(textpos, &values)?;
            } else if constant_keys {
                self.emit_constant_tuple(&keys)?;
            }
            self.text.push(Op::MkFlatMap(nelems));
            self.stack_used -= nelems as isize;
            return Ok(false);
        }
        // Hashmap: iterate from the last entry like hashmap_iterator_prev.
        let mut iter = pairs.iter().rev();
        let mut c = false;
        let textpos = self.text.len();
        let mut preventive_bumps: isize = 0;
        // Check if all keys and values are constants, bumping the stack for each constant
        // found so a later non-constant sees the right depth.
        for &(key, value) in pairs.iter().rev() {
            c = self.expr(key)?;
            if !c {
                break;
            }
            self.stack_used += 1;
            preventive_bumps += 1;
            c = self.expr(value)?;
            if !c {
                break;
            }
            self.stack_used += 1;
            preventive_bumps += 1;
        }
        self.stack_used -= preventive_bumps;
        if c {
            debug_assert_eq!(self.text.len(), textpos);
            return Ok(true);
        }
        if preventive_bumps != 0 {
            // Save the instructions of the non-constant, re-emit the constants before it.
            let saved = self.text.split_off(textpos);
            for &(key, value) in iter.by_ref() {
                self.emit_constant(key)?;
                preventive_bumps -= 1;
                if preventive_bumps == 0 {
                    break;
                }
                self.emit_constant(value)?;
                preventive_bumps -= 1;
                if preventive_bumps == 0 {
                    preventive_bumps = -1;
                    break;
                }
            }
            self.text.extend(saved);
        } else {
            preventive_bumps = -1;
        }
        // If the first variable was a key, only its value is emitted this iteration.
        if preventive_bumps == -1 {
            let &(_, value) = iter.next().ok_or(DmcFail::Fail)?;
            let c = self.expr(value)?;
            if c {
                self.emit_constant(value)?;
            }
        }
        for &(key, value) in iter {
            if self.expr(key)? {
                self.emit_constant(key)?;
            }
            if self.expr(value)? {
                self.emit_constant(value)?;
            }
        }
        self.text.push(Op::MkHashMap(nelems));
        self.stack_used -= 2 * nelems as isize - 1;
        Ok(false)
    }

    // Port of erts/emulator/beam/erl_db_util.c:4599 (dmc_whole_expression), OTP-29.1.1.
    fn whole_expression(&mut self) -> bool {
        if self.cflags & DCOMP_TRACE != 0 {
            // Convert the array to a list.
            self.text.push(if self.special {
                Op::PushArrayAsListU
            } else {
                Op::PushArrayAsList
            });
        } else {
            self.text.push(Op::PushExpr);
        }
        self.stack_used += 1;
        self.bump_need();
        false
    }

    // Port of erts/emulator/beam/erl_db_util.c:4626 (dmc_add_pushv_variant), OTP-29.1.1.
    fn add_pushv_variant(&mut self, n: usize) {
        let mut instr = Op::PushV(n);
        if !self.is_guard && !self.vars[n].is_in_body {
            instr = Op::PushVResult(n);
            self.vars[n].is_in_body = true;
        }
        self.text.push(instr);
    }

    // Port of erts/emulator/beam/erl_db_util.c:4643 (dmc_variable), OTP-29.1.1.
    fn variable(&mut self, n: usize) -> DmcResult<bool> {
        if n >= self.vars_used || !self.vars[n].is_bound {
            return self.error_x(n as i32, b"Variable $%d is unbound.".to_vec());
        }
        self.add_pushv_variant(n);
        self.stack_used += 1;
        self.bump_need();
        Ok(false)
    }

    // Port of erts/emulator/beam/erl_db_util.c:4664 (dmc_all_bindings), OTP-29.1.1.
    fn all_bindings(&mut self) -> bool {
        self.text.push(Op::PushC(Term::NIL));
        for i in (0..self.vars_used).rev() {
            if self.vars[i].is_bound {
                self.add_pushv_variant(i);
                self.text.push(Op::ConsB);
            }
        }
        self.stack_used += 1;
        if self.stack_used + 1 > self.stack_need {
            self.stack_need = self.stack_used + 1;
        }
        false
    }

    /// Emit the arguments of a special form (last argument first), constants included.
    fn push_args(&mut self, p: &[Term], from: usize) -> DmcResult<()> {
        for i in (from..p.len()).rev() {
            if self.expr(p[i])? {
                self.emit_constant(p[i])?;
            }
        }
        Ok(())
    }

    // Port of erts/emulator/beam/erl_db_util.c:4701 (dmc_and) and :4730 (dmc_or).
    fn and_or(&mut self, t: Term, p: &[Term], and: bool) -> DmcResult<bool> {
        let a = p.len();
        if a < 2 {
            return self.return_term_error(
                if and {
                    "Special form 'and' called without arguments in "
                } else {
                    "Special form 'or' called without arguments in "
                },
                t,
                ".",
            );
        }
        self.push_args(p, 1)?;
        self.text
            .push(if and { Op::And(a - 1) } else { Op::Or(a - 1) });
        self.stack_used -= a as isize - 2;
        Ok(false)
    }

    // Port of erts/emulator/beam/erl_db_util.c:4760 (dmc_andalso) and :4809 (dmc_orelse).
    fn andalso_orelse(&mut self, t: Term, p: &[Term], andalso: bool) -> DmcResult<bool> {
        let a = p.len();
        if a < 2 {
            return self.return_term_error(
                if andalso {
                    "Special form 'andalso' called without arguments in "
                } else {
                    "Special form 'orelse' called without arguments in "
                },
                t,
                ".",
            );
        }
        let mut lbl: Option<usize> = None;
        for (i, &element) in p.iter().enumerate().skip(1) {
            if self.expr(element)? {
                self.emit_constant(element)?;
            }
            let link = lbl.unwrap_or(usize::MAX);
            self.text.push(if i == a - 1 {
                Op::Jump(link)
            } else if andalso {
                Op::AndAlso(link)
            } else {
                Op::OrElse(link)
            });
            lbl = Some(self.text.len() - 1);
            self.stack_used -= 1;
        }
        self.text.push(Op::PushC(super::bool_term(andalso)));
        let lbl_val = self.text.len();
        while let Some(index) = lbl {
            // Back-patch the chain of jump operands with the offset to the end.
            let next = match self.text[index] {
                Op::Jump(next) | Op::AndAlso(next) | Op::OrElse(next) => next,
                _ => return fail(),
            };
            let offset = lbl_val - index - 1;
            self.text[index] = match self.text[index] {
                Op::Jump(_) => Op::Jump(offset),
                Op::AndAlso(_) => Op::AndAlso(offset),
                _ => Op::OrElse(offset),
            };
            lbl = (next != usize::MAX).then_some(next);
        }
        self.stack_used += 1;
        self.bump_need();
        Ok(false)
    }

    /// Port of erts/emulator/beam/erl_db_util.c:4977 (check_trace), OTP-29.1.1. `false` means
    /// an error was added and the form is done.
    fn check_trace(&mut self, op: &str, need_cflags: u32, allow_in_guard: bool) -> DmcResult<bool> {
        let message = if self.cflags & DCOMP_TRACE == 0 {
            "used in wrong dialect."
        } else if self.cflags & need_cflags != need_cflags {
            "not allow for this trace event."
        } else if self.is_guard && !allow_in_guard {
            "called in guard context."
        } else {
            return Ok(true);
        };
        self.error_x(-1, format!("Special form '{op}' {message}").into_bytes())?;
        Ok(false)
    }

    /// A form that pushes one fresh value, like `self` or `return_trace`.
    fn push_one(&mut self, op: Op) -> bool {
        self.text.push(op);
        self.stack_used += 1;
        self.bump_need();
        false
    }

    /// The checks every trace-only special form opens with: `check_trace`, then the arity.
    /// `Ok(false)` means an error was added and the form is done.
    fn trace_form(
        &mut self,
        t: Term,
        name: &str,
        check_name: &str,
        need_cflags: u32,
        allow_in_guard: bool,
        arity_ok: bool,
    ) -> DmcResult<bool> {
        if !self.check_trace(check_name, need_cflags, allow_in_guard)? {
            return Ok(false);
        }
        if !arity_ok {
            let wrong = if matches!(name, "set_seq_token" | "silent") {
                "wrong number of arguments"
            } else {
                "arguments"
            };
            self.return_term_error(
                &format!("Special form '{name}' called with {wrong} in "),
                t,
                ".",
            )?;
            return Ok(false);
        }
        Ok(true)
    }

    /// The dialect, guard and arity checks of `message` and `display`.
    fn message_form(&mut self, t: Term, name: &str, arity_ok: bool) -> DmcResult<bool> {
        if self.cflags & DCOMP_TRACE == 0 {
            self.return_error(&format!("Special form '{name}' used in wrong dialect."))?;
            return Ok(false);
        }
        if self.is_guard {
            self.return_error(&format!("Special form '{name}' called in guard context."))?;
            return Ok(false);
        }
        if !arity_ok {
            self.return_term_error(
                &format!("Special form '{name}' called with wrong number of arguments in "),
                t,
                ".",
            )?;
            return Ok(false);
        }
        Ok(true)
    }

    // Port of erts/emulator/beam/erl_db_util.c:5460 (dmc_fun), OTP-29.1.1.
    fn fun(&mut self, t: Term) -> DmcResult<bool> {
        let p: Vec<Term> = tuple_items(t);
        let a = p.len();
        let name = p[0]
            .as_atom()
            .and_then(|atom| global_atoms().text(atom))
            .ok_or(DmcFail::Fail)?;
        const WRONG: &str = "wrong number of arguments";
        // Special forms.
        match name {
            "const" => {
                // dmc_const
                if a != 2 {
                    return self.return_term_error(
                        "Special form 'const' called with more than one argument in ",
                        t,
                        ".",
                    );
                }
                return Ok(true);
            }
            "and" => return self.and_or(t, &p, true),
            "or" => return self.and_or(t, &p, false),
            "andalso" | "andthen" => return self.andalso_orelse(t, &p, true),
            "orelse" => return self.andalso_orelse(t, &p, false),
            "self" => {
                if a != 1 {
                    return self.return_term_error(
                        "Special form 'self' called with arguments in ",
                        t,
                        ".",
                    );
                }
                return Ok(self.push_one(Op::SelfPid));
            }
            "message" => {
                if !self.message_form(t, "message", a == 2)? {
                    return Ok(false);
                }
                self.push_args(&p, 1)?;
                self.text.push(Op::Return);
                self.text.push(Op::PushC(super::bool_term(true)));
                return Ok(false);
            }
            "is_seq_trace" => {
                if !self.trace_form(t, name, name, DCOMP_ALLOW_TRACE_OPS, true, a == 1)? {
                    return Ok(false);
                }
                return Ok(self.push_one(Op::IsSeqTrace));
            }
            "set_seq_token" => {
                // The check names the form "set_seq_trace" in erts.
                if !self.trace_form(
                    t,
                    name,
                    "set_seq_trace",
                    DCOMP_ALLOW_TRACE_OPS,
                    false,
                    a == 3,
                )? {
                    return Ok(false);
                }
                self.push_args(&p, 1)?;
                self.text
                    .push(if self.cflags & DCOMP_FAKE_DESTRUCTIVE != 0 {
                        Op::SetSeqTokenFake
                    } else {
                        Op::SetSeqToken
                    });
                self.stack_used -= 1;
                return Ok(false);
            }
            "get_seq_token" => {
                if !self.trace_form(t, name, name, DCOMP_ALLOW_TRACE_OPS, false, a == 1)? {
                    return Ok(false);
                }
                return Ok(self.push_one(Op::GetSeqToken));
            }
            "return_trace" | "exception_trace" => {
                if self.cflags & DCOMP_TRACE == 0 {
                    return self
                        .return_error(&format!("Special form '{name}' used in wrong dialect."));
                }
                if self.is_guard {
                    return self
                        .return_error(&format!("Special form '{name}' called in guard context."));
                }
                if a != 1 {
                    return self.return_term_error(
                        &format!("Special form '{name}' called with arguments in "),
                        t,
                        ".",
                    );
                }
                return Ok(self.push_one(if name == "return_trace" {
                    Op::SetReturnTrace
                } else {
                    Op::SetExceptionTrace
                }));
            }
            "display" => {
                if !self.message_form(t, "display", a == 2)? {
                    return Ok(false);
                }
                self.push_args(&p, 1)?;
                self.text.push(Op::Display);
                return Ok(false);
            }
            "process_dump" => {
                if !self.trace_form(t, name, name, DCOMP_ALLOW_TRACE_OPS, false, a == 1)? {
                    return Ok(false);
                }
                return Ok(self.push_one(Op::ProcessDump));
            }
            "enable_trace" | "disable_trace" => {
                if !self.check_trace(name, DCOMP_ALLOW_TRACE_OPS, false)? {
                    return Ok(false);
                }
                let enable = name == "enable_trace";
                match a {
                    2 => {
                        self.push_args(&p, 1)?;
                        self.text.push(if enable {
                            Op::EnableTrace
                        } else {
                            Op::DisableTrace
                        });
                    }
                    3 => {
                        self.push_args(&p, 1)?;
                        self.text.push(if enable {
                            Op::EnableTrace2
                        } else {
                            Op::DisableTrace2
                        });
                        self.stack_used -= 1;
                    }
                    _ => {
                        return self.return_term_error(
                            &format!("Special form '{name}' called with {WRONG} in "),
                            t,
                            ".",
                        );
                    }
                }
                return Ok(false);
            }
            "trace" => {
                if !self.check_trace(name, DCOMP_ALLOW_TRACE_OPS, false)? {
                    return Ok(false);
                }
                match a {
                    3 => {
                        self.push_args(&p, 1)?;
                        self.text.push(Op::Trace2);
                        self.stack_used -= 1;
                    }
                    4 => {
                        self.push_args(&p, 1)?;
                        self.text.push(Op::Trace3);
                        self.stack_used -= 2;
                    }
                    _ => {
                        return self.return_term_error(
                            &format!("Special form 'trace' called with {WRONG} in "),
                            t,
                            ".",
                        );
                    }
                }
                return Ok(false);
            }
            "caller" | "caller_line" => {
                if !self.trace_form(
                    t,
                    name,
                    name,
                    DCOMP_CALL_TRACE | DCOMP_ALLOW_TRACE_OPS,
                    false,
                    a == 1,
                )? {
                    return Ok(false);
                }
                return Ok(self.push_one(if name == "caller" {
                    Op::Caller
                } else {
                    Op::CallerLine
                }));
            }
            "current_stacktrace" => {
                if !self.check_trace(name, DCOMP_CALL_TRACE | DCOMP_ALLOW_TRACE_OPS, false)? {
                    return Ok(false);
                }
                let depth = match a {
                    1 => MAX_BACKTRACE_SIZE,
                    2 => {
                        let Some(depth) = p[1].as_small() else {
                            return self.return_error(
                                "Special form 'current_stacktrace' called with non small argument.",
                            );
                        };
                        if depth < 0 {
                            return self.return_error(
                                "Special form 'current_stacktrace' called with negative integer argument.",
                            );
                        }
                        (depth as usize).min(MAX_BACKTRACE_SIZE)
                    }
                    _ => {
                        return self.return_term_error(
                            &format!("Special form 'current_stacktrace' called with {WRONG} in "),
                            t,
                            ".",
                        );
                    }
                };
                self.emit_constant(Term::small(depth as i64).ok_or(DmcFail::Fail)?)?;
                self.text.push(Op::CurrentStacktrace);
                return Ok(false);
            }
            "silent" => {
                if !self.trace_form(t, name, name, DCOMP_ALLOW_TRACE_OPS, false, a == 2)? {
                    return Ok(false);
                }
                self.push_args(&p, 1)?;
                self.text.push(Op::Silent);
                self.text.push(Op::PushC(super::bool_term(true)));
                return Ok(false);
            }
            _ => {}
        }
        let Some(b) = dmc_lookup_bif(name, a - 1) else {
            return self.return_term_error(
                "Function ",
                p[0],
                &format!("/{} does_not_exist.", a - 1),
            );
        };
        let context_bit = 1
            << ((self.cflags & DCOMP_DIALECT_MASK)
                + if self.is_guard { DBIF_GUARD } else { DBIF_BODY });
        if b.flags & context_bit == 0 {
            // Body clause used in wrong context.
            return self.return_term_error(
                "Function ",
                p[0],
                &format!("/{} cannot be called in this context.", a - 1),
            );
        }
        self.push_args(&p, 1)?;
        self.text.push(match b.arity {
            0 => Op::Call0(b),
            1 => Op::Call1(b),
            2 => Op::Call2(b),
            3 => Op::Call3(b),
            _ => return fail(),
        });
        self.stack_used -= a as isize - 2;
        self.bump_need();
        Ok(false)
    }

    // Port of erts/emulator/beam/erl_db_util.c:5592 (dmc_expr), OTP-29.1.1.
    fn expr(&mut self, t: Term) -> DmcResult<bool> {
        if super::stack_guard(self.stack_limit) {
            self.system_limit = true;
            return self.return_term_error("Excessive nesting; system limit reached near: ", t, "");
        }
        match t.classify() {
            TermKind::List => self.list(t),
            TermKind::Map => self.map(t),
            TermKind::Tuple => {
                let p = tuple_items(t);
                if p.len() == 1 && p[0].classify() == TermKind::Tuple {
                    self.tuple_elements(&tuple_items(p[0]))
                } else if !p.is_empty() && p[0].as_atom().is_some() && variable(p[0]).is_none() {
                    self.fun(t)
                } else {
                    // Neither a function call nor a tuple ({{...}} is how tuples are written).
                    self.return_term_error(
                        "",
                        t,
                        " is neither a function call, nor a tuple (tuples are written {{ ... }}).",
                    )
                }
            }
            TermKind::Atom => {
                if let Some(n) = variable(t) {
                    self.variable(n)
                } else if atom_is(t, "$_") {
                    Ok(self.whole_expression())
                } else if atom_is(t, "$$") {
                    Ok(self.all_bindings())
                } else {
                    Ok(true)
                }
            }
            _ => Ok(true),
        }
    }

    // Port of erts/emulator/beam/erl_db_util.c:5663 (compile_guard_expr), OTP-29.1.1.
    fn compile_guard_expr(&mut self, mut l: Term) -> DmcResult<()> {
        if l == Term::NIL {
            return Ok(());
        }
        if l.classify() != TermKind::List {
            return self
                .return_error("Match expression is not a list.")
                .map(|_| ());
        }
        if !self.is_guard {
            self.text.push(Op::Catch);
        }
        while l.classify() == TermKind::List {
            let (t, rest) = cons(l).ok_or(DmcFail::Fail)?;
            if self.expr(t)? {
                self.emit_constant(t)?;
            }
            l = rest;
            self.text
                .push(if self.is_guard { Op::True } else { Op::Waste });
            self.stack_used -= 1;
        }
        if l != Term::NIL {
            return self
                .return_error("Match expression is not a proper list.")
                .map(|_| ());
        }
        if !self.is_guard && self.cflags & DCOMP_TABLE != 0 {
            // Same impact on the stack as matchWaste.
            self.text.pop();
            self.text.push(Op::Return);
        }
        Ok(())
    }

    /// `if (context.err_info) add_dmc_err(context.err_info, text, -1, 0UL, dmcError)`.
    fn add_head_error(&mut self, text: &str) {
        if let Some(info) = self.err_info.as_deref_mut() {
            info.add(-1, text.as_bytes().to_vec());
        }
    }

    /// The head compiler of db_match_compile's per-clause loop, `matchexpr` already
    /// converted to its array form for tracing.
    fn compile_head(&mut self, mut t: Term) -> DmcResult<()> {
        let mut stack: Vec<Term> = vec![Term::NIL];
        let mut structure_checked = false;
        loop {
            match t.classify() {
                TermKind::Map => {
                    let pairs = map_pairs(t)?;
                    if !structure_checked {
                        self.text.push(Op::Map(pairs.len()));
                    }
                    for (key, value) in pairs {
                        if variable(key).is_some() {
                            self.add_head_error("Variable found in map key.");
                            return fail();
                        } else if atom_is(key, "_") {
                            self.add_head_error("Underscore found in map key.");
                            return fail();
                        }
                        self.text.push(Op::Key(key));
                        self.stack_used += 1;
                        let old_stack = self.stack_used;
                        self.one_term(&mut stack, value)?;
                        if old_stack != self.stack_used {
                            self.text.push(Op::Swap);
                        }
                        self.bump_need();
                        self.text.push(Op::Pop);
                        self.stack_used -= 1;
                    }
                }
                TermKind::Tuple => {
                    let items = tuple_items(t);
                    if !structure_checked {
                        self.text.push(Op::Tuple(items.len()));
                    }
                    for element in items {
                        self.one_term(&mut stack, element)?;
                    }
                }
                TermKind::List => {
                    if !structure_checked {
                        self.text.push(Op::List);
                    }
                    structure_checked = false;
                    let (head, tail) = cons(t).ok_or(DmcFail::Fail)?;
                    self.one_term(&mut stack, head)?;
                    t = tail;
                    continue;
                }
                _ => {
                    // Nil and non proper tail ends or single terms as match expressions.
                    self.one_term(&mut stack, t)?;
                }
            }
            // The program's stack just grows while one composite structure is traversed.
            self.bump_need();
            // At the end of one composite structure, pop substructures and emit matchPop.
            t = stack.pop().ok_or(DmcFail::Fail)?;
            if t == Term::NIL {
                break;
            }
            self.text.push(Op::Pop);
            structure_checked = true;
            self.stack_used -= 1;
        }
        Ok(())
    }
}

/// `MAX_BACKTRACE_SIZE` (error.h:206).
const MAX_BACKTRACE_SIZE: usize = 64;

/// Compact the variables of the whole specification, `{$1, $100, $1000}` becoming
/// `{$0, $1, $2}`.
///
/// Port of erts/emulator/beam/erl_db_util.c:5769 (match_compact), OTP-29.1.1.
fn match_compact(
    terms: &[Term],
    heap: &mut VecHeap,
    err_info: Option<&mut DmcErrInfo>,
) -> DmcResult<(Vec<Term>, usize)> {
    fn collect(term: Term, seen: &mut Vec<usize>) {
        match term.classify() {
            TermKind::Atom => {
                if let Some(n) = variable(term)
                    && !seen.contains(&n)
                {
                    seen.push(n);
                }
            }
            TermKind::List => {
                let mut rest = term;
                while let Some((head, tail)) = cons(rest) {
                    collect(head, seen);
                    rest = tail;
                }
                collect(rest, seen);
            }
            TermKind::Tuple => {
                for element in tuple_items(term) {
                    collect(element, seen);
                }
            }
            TermKind::Map => {
                if let Ok(pairs) = map_pairs(term) {
                    for (key, value) in pairs {
                        collect(key, seen);
                        collect(value, seen);
                    }
                }
            }
            _ => {}
        }
    }
    fn rewrite(term: Term, map: &[usize], heap: &mut VecHeap) -> DmcResult<Term> {
        Ok(match term.classify() {
            TermKind::Atom => match variable(term) {
                Some(n) => {
                    let index = map.iter().position(|&old| old == n).ok_or(DmcFail::Fail)?;
                    Term::atom(
                        global_atoms()
                            .intern(&format!("${index}"))
                            .map_err(|_| DmcFail::Fail)?,
                    )
                }
                None => term,
            },
            TermKind::List => {
                let (head, tail) = cons(term).ok_or(DmcFail::Fail)?;
                let head = rewrite(head, map, heap)?;
                let tail = rewrite(tail, map, heap)?;
                TermBuilder::new(heap).cons(head, tail)?
            }
            TermKind::Tuple => {
                let mut values = Vec::new();
                for element in tuple_items(term) {
                    values.push(rewrite(element, map, heap)?);
                }
                TermBuilder::new(heap).tuple(&values)?
            }
            TermKind::Map => {
                let mut pairs = Vec::new();
                for (key, value) in map_pairs(term)? {
                    pairs.push((rewrite(key, map, heap)?, rewrite(value, map, heap)?));
                }
                TermBuilder::new(heap).flatmap_from_pairs(&pairs)?
            }
            _ => term,
        })
    }
    let mut seen = Vec::new();
    for &term in terms {
        collect(term, &mut seen);
    }
    seen.sort_unstable();
    // Lint needs a translation table.
    if let Some(info) = err_info {
        info.var_trans = Some(seen.clone());
    }
    let rewritten = terms
        .iter()
        .map(|&term| rewrite(term, &seen, heap))
        .collect::<DmcResult<Vec<_>>>()?;
    Ok((rewritten, seen.len()))
}

/// Port of erts/emulator/beam/erl_db_util.c:1717 (db_match_compile), OTP-29.1.1.
///
/// `matchexpr`, `guards` and `body` hold one entry per clause and live in `heap`, which also
/// receives the constants of the program. With `err_info` the compilation records the errors
/// of the clause it stops at, as `db_match_set_lint` wants them.
pub(super) fn db_match_compile(
    heap: &mut VecHeap,
    matchexpr: &[Term],
    guards: &[Term],
    body: &[Term],
    cflags: u32,
    is_prefix: &[bool],
    err_info: Option<&mut DmcErrInfo>,
) -> Result<Compiled, EtsError> {
    let num_progs = matchexpr.len();
    let mut dmc = Dmc {
        heap,
        text: Vec::new(),
        vars: vec![DmcVariable::default(); DMC_DEFAULT_SIZE],
        vars_used: 0,
        cflags,
        is_guard: false,
        special: false,
        stack_used: 0,
        stack_need: 0,
        num_match: num_progs,
        current_match: 0,
        matchexpr: matchexpr.to_vec(),
        guardexpr: guards.to_vec(),
        bodyexpr: body.to_vec(),
        is_prefix,
        stack_limit: arinsal_alloc::ethr::erts_get_stacklimit(),
        err_info,
        system_limit: false,
    };
    // `restart:` of erts, taken when a variable number does not fit the variable table.
    let compiled = loop {
        dmc.vars_used = 0;
        match dmc.compile_clauses() {
            Err(DmcFail::Restart) => continue,
            result => break result,
        }
    };
    match compiled {
        Ok(()) => Ok(Compiled {
            num_bindings: dmc.vars_used,
            stack_need: dmc.stack_need.max(0) as usize,
            text: dmc.text,
        }),
        Err(_) if dmc.system_limit => Err(EtsError::Term(TermError::SystemLimit)),
        Err(_) => Err(EtsError::BadArg),
    }
}

impl Dmc<'_> {
    /// The clause loop of db_match_compile ("This loop is long, too long").
    fn compile_clauses(&mut self) -> DmcResult<()> {
        let cflags = self.cflags;
        for current_match in 0..self.num_match {
            self.current_match = current_match;
            self.vars.fill(DmcVariable::default());
            let t = self.matchexpr[current_match];
            self.stack_used = 0;
            let mut current_try_label = None;
            if current_match < self.num_match - 1 {
                self.text.push(Op::TryMeElse(0));
                current_try_label = Some(self.text.len() - 1);
            }
            // The "special" test needs it.
            let clause_start = self.text.len();
            self.compile_head(t)?;
            // There is one single top variable in the match expression iff the text is the
            // single instruction 'matchBind', or it is only a skip.
            self.special = self.text.len() == clause_start + 1
                && matches!(self.text[clause_start], Op::Bind(_) | Op::Skip);
            let special_bind = self.special && matches!(self.text[clause_start], Op::Bind(_));
            if cflags & DCOMP_TRACE != 0 {
                if self.special {
                    if special_bind && let Op::Bind(n) = self.text[clause_start] {
                        self.text[clause_start] = Op::ArrayBind(n);
                    }
                } else {
                    let Some(&Op::Tuple(n)) = self.text.get(clause_start) else {
                        // The head is not a tuple: invalid when matching an array.
                        self.add_head_error("Match head is invalid in this context.");
                        return fail();
                    };
                    self.text[clause_start] =
                        if self.is_prefix.get(current_match).copied().unwrap_or(false) {
                            Op::ArrayPrefix(n)
                        } else {
                            Op::Array(n)
                        };
                }
            }
            // ... and the guards
            self.is_guard = true;
            self.compile_guard_expr(self.guardexpr[current_match])?;
            self.is_guard = false;
            if cflags & DCOMP_TABLE != 0
                && self.bodyexpr[current_match].classify() != TermKind::List
            {
                self.add_head_error("Body clause does not return anything.");
                return fail();
            }
            self.compile_guard_expr(self.bodyexpr[current_match])?;
            // The compilation does not bail out when error information is requested, so
            // we need to detect that here...
            if self.err_info.as_ref().is_some_and(|info| info.error_added) {
                return fail();
            }
            // If the match program comes here, the match is successful.
            self.text.push(Op::Halt);
            // Fill in the try-me-else label if there is one.
            if let Some(label) = current_try_label {
                let end = self.text.len();
                self.text[label] = Op::TryMeElse(end);
            }
        }
        Ok(())
    }
}
