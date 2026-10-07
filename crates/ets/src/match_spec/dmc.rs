//! Match program compiler.
//!
//! Port of erts/emulator/beam/erl_db_util.c:1717 (db_match_compile) and the `dmc_*` code
//! generators (:4047-5720), OTP-29.1.1. The program is a flat vector of [`Op`]s, one enum
//! variant per `matchXxx` opcode; label operands are indices into that vector instead of
//! word offsets.

use super::{cons, is_float_term, tuple_view, variable};
use crate::EtsError;
use arinsal_term::{Term, TermBuilder, TermKind, VecHeap, global_atoms};

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

/// `DMC_DEFAULT_SIZE`: variables numbered at or above this force a compaction.
const DMC_DEFAULT_SIZE: usize = 100;

/// Guard BIFs with an allocation-free small-integer or type-test fast path.
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
    pub fast: Fast,
}

macro_rules! bif {
    ($name:expr, $arity:expr, $flags:expr, $fast:ident) => {
        GuardBif {
            name: $name,
            arity: $arity,
            flags: $flags,
            fast: Fast::$fast,
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
    matchexpr: &'a [Term],
    guardexpr: &'a [Term],
    bodyexpr: &'a [Term],
    is_prefix: &'a [bool],
}

fn atom_is(term: Term, text: &str) -> bool {
    term.as_atom()
        .is_some_and(|atom| global_atoms().text(atom) == Some(text))
}

fn fail<T>() -> Result<T, EtsError> {
    Err(EtsError::BadArg)
}

/// Elements of a tuple term, empty for anything else.
fn tuple_items(term: Term) -> Vec<Term> {
    tuple_view(term)
        .map(|view| view.iter().collect())
        .unwrap_or_default()
}

fn map_pairs(term: Term) -> Result<Vec<(Term, Term)>, EtsError> {
    arinsal_maps::to_list(term).map_err(|_| EtsError::BadArg)
}

/// Port of erts/emulator/beam/erl_db_util.c:5916 (my_copy_struct), OTP-29.1.1: the term a
/// constant expression stands for, with `{const, X}` and `{{...}}` unwrapped.
fn const_value(term: Term, heap: &mut VecHeap) -> Result<Term, EtsError> {
    match term.classify() {
        TermKind::List => {
            let (head, tail) = cons(term).ok_or(EtsError::BadArg)?;
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
    fn bump_need(&mut self) {
        if self.stack_used > self.stack_need {
            self.stack_need = self.stack_used;
        }
    }

    // Port of erts/emulator/beam/erl_db_util.c:4047 (dmc_one_term), OTP-29.1.1.
    fn one_term(&mut self, stack: &mut Vec<Term>, c: Term) -> Result<(), EtsError> {
        if !c.is_pointer() {
            if let Some(n) = variable(c) {
                if n >= self.vars.len() {
                    return fail();
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
                let n = arinsal_maps::size(c).map_err(|_| EtsError::BadArg)?;
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
    fn emit_constant(&mut self, t: Term) -> Result<(), EtsError> {
        let value = const_value(t, self.heap)?;
        self.text.push(Op::PushC(value));
        self.stack_used += 1;
        self.bump_need();
        Ok(())
    }

    /// Emit `elements` as the constant tuple `{{...}}` would produce.
    fn emit_constant_tuple(&mut self, elements: &[Term]) -> Result<(), EtsError> {
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
    fn list(&mut self, t: Term) -> Result<bool, EtsError> {
        let (head, tail) = cons(t).ok_or(EtsError::BadArg)?;
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
    fn rearrange_constants(&mut self, textpos: usize, p: &[Term]) -> Result<(), EtsError> {
        let saved = self.text.split_off(textpos);
        for &element in p.iter().rev() {
            self.emit_constant(element)?;
        }
        self.text.extend(saved);
        Ok(())
    }

    // Port of erts/emulator/beam/erl_db_util.c:4324 (dmc_array), OTP-29.1.1.
    fn array(&mut self, p: &[Term]) -> Result<bool, EtsError> {
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
    fn tuple_elements(&mut self, p: &[Term]) -> Result<bool, EtsError> {
        let all_constant = self.array(p)?;
        if all_constant {
            return Ok(true);
        }
        self.text.push(Op::MkTuple(p.len()));
        self.stack_used -= p.len() as isize - 1;
        Ok(false)
    }

    // Port of erts/emulator/beam/erl_db_util.c:4411 (dmc_map), OTP-29.1.1.
    fn map(&mut self, t: Term) -> Result<bool, EtsError> {
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
            let &(_, value) = iter.next().ok_or(EtsError::BadArg)?;
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
    fn variable(&mut self, n: usize) -> Result<bool, EtsError> {
        if n >= self.vars_used || !self.vars[n].is_bound {
            return fail();
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
    fn push_args(&mut self, p: &[Term], from: usize) -> Result<(), EtsError> {
        for i in (from..p.len()).rev() {
            if self.expr(p[i])? {
                self.emit_constant(p[i])?;
            }
        }
        Ok(())
    }

    // Port of erts/emulator/beam/erl_db_util.c:4701 (dmc_and) and :4730 (dmc_or).
    fn and_or(&mut self, p: &[Term], and: bool) -> Result<bool, EtsError> {
        let a = p.len();
        if a < 2 {
            return fail();
        }
        self.push_args(p, 1)?;
        self.text
            .push(if and { Op::And(a - 1) } else { Op::Or(a - 1) });
        self.stack_used -= a as isize - 2;
        Ok(false)
    }

    // Port of erts/emulator/beam/erl_db_util.c:4760 (dmc_andalso) and :4809 (dmc_orelse).
    fn andalso_orelse(&mut self, p: &[Term], andalso: bool) -> Result<bool, EtsError> {
        let a = p.len();
        if a < 2 {
            return fail();
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

    /// Port of erts/emulator/beam/erl_db_util.c:4977 (check_trace), OTP-29.1.1.
    fn check_trace(&self, need_cflags: u32, allow_in_guard: bool) -> Result<(), EtsError> {
        if self.cflags & DCOMP_TRACE == 0
            || self.cflags & need_cflags != need_cflags
            || (self.is_guard && !allow_in_guard)
        {
            return fail();
        }
        Ok(())
    }

    /// A form that pushes one fresh value, like `self` or `return_trace`.
    fn push_one(&mut self, op: Op) -> bool {
        self.text.push(op);
        self.stack_used += 1;
        self.bump_need();
        false
    }

    // Port of erts/emulator/beam/erl_db_util.c:5460 (dmc_fun), OTP-29.1.1.
    fn fun(&mut self, t: Term) -> Result<bool, EtsError> {
        let p: Vec<Term> = tuple_items(t);
        let a = p.len();
        let name = p[0]
            .as_atom()
            .and_then(|atom| global_atoms().text(atom))
            .ok_or(EtsError::BadArg)?;
        let trace = self.cflags & DCOMP_TRACE != 0;
        // Special forms.
        match name {
            "const" => {
                // dmc_const
                if a != 2 {
                    return fail();
                }
                return Ok(true);
            }
            "and" => return self.and_or(&p, true),
            "or" => return self.and_or(&p, false),
            "andalso" | "andthen" => return self.andalso_orelse(&p, true),
            "orelse" => return self.andalso_orelse(&p, false),
            "self" => {
                if a != 1 {
                    return fail();
                }
                return Ok(self.push_one(Op::SelfPid));
            }
            "message" => {
                // dmc_message
                if !trace || self.is_guard || a != 2 {
                    return fail();
                }
                self.push_args(&p, 1)?;
                self.text.push(Op::Return);
                self.text.push(Op::PushC(super::bool_term(true)));
                return Ok(false);
            }
            "is_seq_trace" => {
                self.check_trace(DCOMP_ALLOW_TRACE_OPS, true)?;
                if a != 1 {
                    return fail();
                }
                return Ok(self.push_one(Op::IsSeqTrace));
            }
            "set_seq_token" => {
                self.check_trace(DCOMP_ALLOW_TRACE_OPS, false)?;
                if a != 3 {
                    return fail();
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
                self.check_trace(DCOMP_ALLOW_TRACE_OPS, false)?;
                if a != 1 {
                    return fail();
                }
                return Ok(self.push_one(Op::GetSeqToken));
            }
            "return_trace" | "exception_trace" => {
                if !trace || self.is_guard || a != 1 {
                    return fail();
                }
                return Ok(self.push_one(if name == "return_trace" {
                    Op::SetReturnTrace
                } else {
                    Op::SetExceptionTrace
                }));
            }
            "display" => {
                if !trace || self.is_guard || a != 2 {
                    return fail();
                }
                self.push_args(&p, 1)?;
                self.text.push(Op::Display);
                return Ok(false);
            }
            "process_dump" => {
                self.check_trace(DCOMP_ALLOW_TRACE_OPS, false)?;
                if a != 1 {
                    return fail();
                }
                return Ok(self.push_one(Op::ProcessDump));
            }
            "enable_trace" | "disable_trace" => {
                self.check_trace(DCOMP_ALLOW_TRACE_OPS, false)?;
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
                    _ => return fail(),
                }
                return Ok(false);
            }
            "trace" => {
                self.check_trace(DCOMP_ALLOW_TRACE_OPS, false)?;
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
                    _ => return fail(),
                }
                return Ok(false);
            }
            "caller" | "caller_line" => {
                self.check_trace(DCOMP_CALL_TRACE | DCOMP_ALLOW_TRACE_OPS, false)?;
                if a != 1 {
                    return fail();
                }
                return Ok(self.push_one(if name == "caller" {
                    Op::Caller
                } else {
                    Op::CallerLine
                }));
            }
            "current_stacktrace" => {
                self.check_trace(DCOMP_CALL_TRACE | DCOMP_ALLOW_TRACE_OPS, false)?;
                let depth = match a {
                    1 => MAX_BACKTRACE_SIZE,
                    2 => {
                        let depth = p[1].as_small().ok_or(EtsError::BadArg)?;
                        if depth < 0 {
                            return fail();
                        }
                        (depth as usize).min(MAX_BACKTRACE_SIZE)
                    }
                    _ => return fail(),
                };
                self.emit_constant(Term::small(depth as i64).ok_or(EtsError::BadArg)?)?;
                self.text.push(Op::CurrentStacktrace);
                return Ok(false);
            }
            "silent" => {
                self.check_trace(DCOMP_ALLOW_TRACE_OPS, false)?;
                if a != 2 {
                    return fail();
                }
                self.push_args(&p, 1)?;
                self.text.push(Op::Silent);
                self.text.push(Op::PushC(super::bool_term(true)));
                return Ok(false);
            }
            _ => {}
        }
        let Some(b) = dmc_lookup_bif(name, a - 1) else {
            return fail();
        };
        let context_bit = 1
            << ((self.cflags & DCOMP_DIALECT_MASK)
                + if self.is_guard { DBIF_GUARD } else { DBIF_BODY });
        if b.flags & context_bit == 0 {
            // Body clause used in wrong context.
            return fail();
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
    fn expr(&mut self, t: Term) -> Result<bool, EtsError> {
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
                    fail()
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
    fn compile_guard_expr(&mut self, mut l: Term) -> Result<(), EtsError> {
        if l == Term::NIL {
            return Ok(());
        }
        if l.classify() != TermKind::List {
            return fail();
        }
        if !self.is_guard {
            self.text.push(Op::Catch);
        }
        while l.classify() == TermKind::List {
            let (t, rest) = cons(l).ok_or(EtsError::BadArg)?;
            if self.expr(t)? {
                self.emit_constant(t)?;
            }
            l = rest;
            self.text
                .push(if self.is_guard { Op::True } else { Op::Waste });
            self.stack_used -= 1;
        }
        if l != Term::NIL {
            return fail();
        }
        if !self.is_guard && self.cflags & DCOMP_TABLE != 0 {
            // Same impact on the stack as matchWaste.
            self.text.pop();
            self.text.push(Op::Return);
        }
        Ok(())
    }

    /// The head compiler of db_match_compile's per-clause loop, `matchexpr` already
    /// converted to its array form for tracing.
    fn compile_head(&mut self, mut t: Term) -> Result<(), EtsError> {
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
                        if variable(key).is_some() || atom_is(key, "_") {
                            // Variable or underscore found in map key.
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
                    let (head, tail) = cons(t).ok_or(EtsError::BadArg)?;
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
            t = stack.pop().ok_or(EtsError::BadArg)?;
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
fn match_compact(terms: &[Term], heap: &mut VecHeap) -> Result<Vec<Term>, EtsError> {
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
    fn rewrite(term: Term, map: &[usize], heap: &mut VecHeap) -> Result<Term, EtsError> {
        Ok(match term.classify() {
            TermKind::Atom => match variable(term) {
                Some(n) => {
                    let index = map
                        .iter()
                        .position(|&old| old == n)
                        .ok_or(EtsError::BadArg)?;
                    Term::atom(
                        global_atoms()
                            .intern(&format!("${index}"))
                            .map_err(|_| EtsError::BadArg)?,
                    )
                }
                None => term,
            },
            TermKind::List => {
                let (head, tail) = cons(term).ok_or(EtsError::BadArg)?;
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
    terms
        .iter()
        .map(|&term| rewrite(term, &seen, heap))
        .collect()
}

/// Port of erts/emulator/beam/erl_db_util.c:1717 (db_match_compile), OTP-29.1.1.
///
/// `matchexpr`, `guards` and `body` hold one entry per clause and live in `heap`, which also
/// receives the constants of the program.
pub(super) fn db_match_compile(
    heap: &mut VecHeap,
    matchexpr: &[Term],
    guards: &[Term],
    body: &[Term],
    cflags: u32,
    is_prefix: &[bool],
) -> Result<Compiled, EtsError> {
    let num_progs = matchexpr.len();
    // Variables numbered DMC_DEFAULT_SIZE or more in a head make erts restart with a compacted
    // numbering; compacting up front yields the same program.
    let mut big_variable = false;
    {
        fn scan(term: Term, big: &mut bool) {
            match term.classify() {
                TermKind::Atom => {
                    if variable(term).is_some_and(|n| n >= DMC_DEFAULT_SIZE) {
                        *big = true;
                    }
                }
                TermKind::List => {
                    let mut rest = term;
                    while let Some((head, tail)) = cons(rest) {
                        scan(head, big);
                        rest = tail;
                    }
                    scan(rest, big);
                }
                TermKind::Tuple => {
                    for element in tuple_items(term) {
                        scan(element, big);
                    }
                }
                TermKind::Map => {
                    if let Ok(pairs) = map_pairs(term) {
                        for (key, value) in pairs {
                            scan(key, big);
                            scan(value, big);
                        }
                    }
                }
                _ => {}
            }
        }
        for &term in matchexpr {
            scan(term, &mut big_variable);
        }
    }
    let (matchexpr, guards, body): (Vec<Term>, Vec<Term>, Vec<Term>) = if big_variable {
        let all: Vec<Term> = matchexpr
            .iter()
            .chain(guards)
            .chain(body)
            .copied()
            .collect();
        let compacted = match_compact(&all, heap)?;
        (
            compacted[..num_progs].to_vec(),
            compacted[num_progs..2 * num_progs].to_vec(),
            compacted[2 * num_progs..].to_vec(),
        )
    } else {
        (matchexpr.to_vec(), guards.to_vec(), body.to_vec())
    };
    let vars_size = if big_variable {
        // All variables were renumbered into 0..count.
        count_variables(&matchexpr, &guards, &body)
    } else {
        DMC_DEFAULT_SIZE
    };
    let mut dmc = Dmc {
        heap,
        text: Vec::new(),
        vars: vec![DmcVariable::default(); vars_size.max(1)],
        vars_used: 0,
        cflags,
        is_guard: false,
        special: false,
        stack_used: 0,
        stack_need: 0,
        num_match: num_progs,
        current_match: 0,
        matchexpr: &matchexpr,
        guardexpr: &guards,
        bodyexpr: &body,
        is_prefix,
    };
    for current_match in 0..dmc.num_match {
        dmc.current_match = current_match;
        dmc.vars.fill(DmcVariable::default());
        let t = dmc.matchexpr[current_match];
        dmc.stack_used = 0;
        let mut current_try_label = None;
        if current_match < dmc.num_match - 1 {
            dmc.text.push(Op::TryMeElse(0));
            current_try_label = Some(dmc.text.len() - 1);
        }
        // The "special" test needs it.
        let clause_start = dmc.text.len();
        dmc.compile_head(t)?;
        // There is one single top variable in the match expression iff the text is the single
        // instruction 'matchBind', or it is only a skip.
        dmc.special = dmc.text.len() == clause_start + 1
            && matches!(dmc.text[clause_start], Op::Bind(_) | Op::Skip);
        let special_bind = dmc.special && matches!(dmc.text[clause_start], Op::Bind(_));
        if cflags & DCOMP_TRACE != 0 {
            if dmc.special {
                if special_bind && let Op::Bind(n) = dmc.text[clause_start] {
                    dmc.text[clause_start] = Op::ArrayBind(n);
                }
            } else {
                let Some(&Op::Tuple(n)) = dmc.text.get(clause_start) else {
                    // The head is not a tuple: invalid when matching an array.
                    return fail();
                };
                dmc.text[clause_start] =
                    if dmc.is_prefix.get(current_match).copied().unwrap_or(false) {
                        Op::ArrayPrefix(n)
                    } else {
                        Op::Array(n)
                    };
            }
        }
        // ... and the guards
        dmc.is_guard = true;
        dmc.compile_guard_expr(dmc.guardexpr[current_match])?;
        dmc.is_guard = false;
        if cflags & DCOMP_TABLE != 0 && dmc.bodyexpr[current_match].classify() != TermKind::List {
            // Body clause does not return anything.
            return fail();
        }
        dmc.compile_guard_expr(dmc.bodyexpr[current_match])?;
        // If the match program comes here, the match is successful.
        dmc.text.push(Op::Halt);
        // Fill in the try-me-else label if there is one.
        if let Some(label) = current_try_label {
            let end = dmc.text.len();
            dmc.text[label] = Op::TryMeElse(end);
        }
    }
    Ok(Compiled {
        num_bindings: dmc.vars_used,
        stack_need: dmc.stack_need.max(0) as usize,
        text: dmc.text,
    })
}

/// Distinct variable count, used to size the variable table after a compaction.
fn count_variables(matchexpr: &[Term], guards: &[Term], body: &[Term]) -> usize {
    fn walk(term: Term, highest: &mut usize) {
        match term.classify() {
            TermKind::Atom => {
                if let Some(n) = variable(term) {
                    *highest = (*highest).max(n + 1);
                }
            }
            TermKind::List => {
                let mut rest = term;
                while let Some((head, tail)) = cons(rest) {
                    walk(head, highest);
                    rest = tail;
                }
                walk(rest, highest);
            }
            TermKind::Tuple => {
                for element in tuple_items(term) {
                    walk(element, highest);
                }
            }
            TermKind::Map => {
                if let Ok(pairs) = map_pairs(term) {
                    for (key, value) in pairs {
                        walk(key, highest);
                        walk(value, highest);
                    }
                }
            }
            _ => {}
        }
    }
    let mut highest = 0;
    for &term in matchexpr.iter().chain(guards).chain(body) {
        walk(term, &mut highest);
    }
    highest
}
