//! Match program interpreter.
//!
//! Port of erts/emulator/beam/erl_db_util.c:2172 (db_prog_match), OTP-29.1.1. The C code walks
//! raw `Eterm*` cursors; here a [`Cursor`] names the tuple, list cell, map or array a cursor
//! points into, and the evaluation stack is a vector.

use super::dmc::{Fast, GuardBif, Op};
use super::{MatchContext, MatchProgram, bool_term, boolean, builtin, float_bits, is_float_term};
use super::{cons, tuple_view};
use crate::EtsError;
use arinsal_term::{Term, TermBuilder, TermKind, TupleRef, VecHeap, cmp, exact_eq};
use std::cmp::Ordering;

/// The `Eterm*` cursors of db_prog_match: where the next match instruction reads.
enum Cursor<'a> {
    /// The object itself, or the value found by `matchKey`.
    Single(Term),
    /// Element `index` of a tuple.
    Tuple { tuple: TupleRef<'a>, index: usize },
    /// The head (index 0) or tail (index 1) of a cons cell.
    Cell {
        head: Term,
        tail: Term,
        index: usize,
    },
    /// The map matched by `matchMap`, the base of `matchKey` lookups.
    Map(Term),
    /// Argument `index` of the trace argument array.
    Array(usize),
    /// Past the last element: erts reads nothing from it.
    Past,
}

/// Safe instruction pointer over the compiled DMC stream.
// Port of erts/emulator/beam/erl_db_util.c (db_prog_match `pc`), OTP-29.1.1.
struct InstructionCursor<'a> {
    remaining: &'a [super::dmc::Op],
}

impl<'a> InstructionCursor<'a> {
    fn new(text: &'a [super::dmc::Op], start: usize) -> Self {
        Self {
            remaining: text.get(start..).unwrap_or_default(),
        }
    }

    #[inline]
    fn next(&mut self) -> Option<super::dmc::Op> {
        let (op, remaining) = self.remaining.split_first()?;
        self.remaining = remaining;
        Some(*op)
    }

    #[inline]
    fn advance(&mut self, count: usize) {
        self.remaining = self.remaining.get(count..).unwrap_or_default();
    }
}

impl Cursor<'_> {
    // Port of erts/emulator/beam/erl_db_util.c:2313 (matchPushT), OTP-29.1.1: retain the
    // current tuple element view until the next DMC instruction advances `ep`.
    fn get(&self, array: &[Term]) -> Option<Term> {
        match self {
            Self::Single(term) => Some(*term),
            Self::Tuple { tuple, index } => tuple.get(*index),
            Self::Cell { head, tail, index } => match index {
                0 => Some(*head),
                1 => Some(*tail),
                _ => None,
            },
            Self::Array(index) => array.get(*index).copied(),
            Self::Map(_) | Self::Past => None,
        }
    }

    /// `ep++`.
    // Port of erts/emulator/beam/erl_db_util.c (db_prog_match), OTP-29.1.1.
    fn next(&mut self) {
        match self {
            Self::Tuple { index, .. } | Self::Cell { index, .. } | Self::Array(index) => {
                *index += 1;
            }
            Self::Single(_) | Self::Map(_) | Self::Past => *self = Self::Past,
        }
    }
}

/// A cursor saved across DMC instructions without borrowing from the current object.
#[derive(Clone, Copy)]
enum SavedCursor {
    Tuple {
        tuple: Term,
        index: usize,
    },
    Cell {
        head: Term,
        tail: Term,
        index: usize,
    },
    Map(Term),
}

/// The match pseudo process: heap, evaluation stack and variable table, reused per thread.
pub(super) struct PamState {
    pub heap: VecHeap,
    esp: Vec<Term>,
    sp: Vec<SavedCursor>,
    variables: Vec<Term>,
}

impl PamState {
    pub fn new(stack_need: usize, num_bindings: usize) -> Self {
        Self {
            // Port of erl_db_util.c:431-455 (ERTS_DEFAULT_MS_HEAP_SIZE and
            // match-pseudo-process cleanup), OTP-29.1.1.
            heap: VecHeap::with_initial_chunk_words(128),
            esp: Vec::with_capacity(stack_need),
            sp: Vec::with_capacity(stack_need),
            variables: vec![Term::NIL; num_bindings],
        }
    }

    /// Size the arrays for another program, as `get_match_pseudo_process` does when the
    /// thread's process is reused. A state made by `new` for the program needs no call.
    pub fn prepare(&mut self, stack_need: usize, num_bindings: usize) {
        if self.esp.capacity() < stack_need {
            self.esp.reserve(stack_need);
        }
        if self.sp.capacity() < stack_need {
            self.sp.reserve(stack_need);
        }
        if self.variables.len() != num_bindings {
            self.variables.resize(num_bindings, Term::NIL);
        }
    }
}

/// `am_EXIT`, the result of a failed guard BIF under `catch`. `EXIT_2` is the atom `EXIT`;
/// the generated `EXIT` is `exit`.
const fn exit_atom() -> Term {
    Term::atom(arinsal_term::atoms::EXIT_2)
}

fn small_pair(a: Term, b: Term) -> Option<(i64, i64)> {
    Some((a.as_small()?, b.as_small()?))
}

/// Run a guard BIF found in the program's `Call0..3` instruction.
// Port of erts/emulator/beam/erl_db_util.c (db_prog_match matchCall0..matchCall3), OTP-29.1.1:
// the compiler-selected BIF entry is invoked directly.
fn call_bif<C: MatchContext>(
    bif: &GuardBif,
    args: &[Term],
    heap: &mut VecHeap,
    context: &C,
) -> Result<Term, EtsError> {
    if let Some(fast_fn) = bif.fast_fn
        && let Some(value) = fast_fn(args)
    {
        return Ok(value);
    }
    match (bif.name, bif.arity) {
        ("node", 0) => {
            return context
                .node_name()
                .ok_or(EtsError::Unsupported("node context"));
        }
        ("node", 1) => return context.node_of(args[0]).ok_or(EtsError::BadArg),
        ("get_tcw", 0) => {
            return context
                .trace_control_word()
                .ok_or(EtsError::Unsupported("trace control word"));
        }
        ("set_tcw", 1) => return context.trace_operation("set_tcw", args),
        _ => {}
    }
    builtin(bif.name, args, heap)
}

/// A guard operation selected while compiling its DMC call instruction.
pub(super) type FastBifFn = fn(&[Term]) -> Option<Term>;

/// Port of erts/emulator/beam/erl_db_util.c (`matchCall0..matchCall3`), OTP-29.1.1: DMC
/// instructions carry the selected BIF entry, so dispatch does not inspect its name per object.
pub(super) const fn fast_fn_for(fast: Fast) -> Option<FastBifFn> {
    match fast {
        Fast::Eq => Some(fast_eq),
        Fast::Ne => Some(fast_ne),
        Fast::ExactEq => Some(fast_exact_eq),
        Fast::ExactNe => Some(fast_exact_ne),
        Fast::Gt => Some(fast_gt),
        Fast::Ge => Some(fast_ge),
        Fast::Lt => Some(fast_lt),
        Fast::Le => Some(fast_le),
        Fast::Add => Some(fast_add),
        Fast::Sub => Some(fast_sub),
        Fast::Mul => Some(fast_mul),
        Fast::Div => Some(fast_div),
        Fast::Rem => Some(fast_rem),
        Fast::Band => Some(fast_band),
        Fast::Bor => Some(fast_bor),
        Fast::Bxor => Some(fast_bxor),
        Fast::IsAtom => Some(fast_is_atom),
        Fast::IsInteger => Some(fast_is_integer),
        Fast::IsTuple => Some(fast_is_tuple),
        Fast::IsList => Some(fast_is_list),
        Fast::IsNumber => Some(fast_is_number),
        Fast::Not => Some(fast_not),
        Fast::Element => Some(fast_element),
        Fast::TupleSize => Some(fast_tuple_size),
        Fast::None => None,
    }
}

#[inline(always)]
fn fast_compare(args: &[Term], predicate: impl FnOnce(Ordering) -> bool) -> Option<Term> {
    let order = match small_pair(args[0], args[1]) {
        Some((a, b)) => a.cmp(&b),
        None => cmp(args[0], args[1]),
    };
    Some(bool_term(predicate(order)))
}

macro_rules! fast_compare {
    ($name:ident, $predicate:expr) => {
        fn $name(args: &[Term]) -> Option<Term> {
            fast_compare(args, $predicate)
        }
    };
}

fast_compare!(fast_eq, |order| order == Ordering::Equal);
fast_compare!(fast_ne, |order| order != Ordering::Equal);
fast_compare!(fast_gt, |order| order == Ordering::Greater);
fast_compare!(fast_ge, |order| order != Ordering::Less);
fast_compare!(fast_lt, |order| order == Ordering::Less);
fast_compare!(fast_le, |order| order != Ordering::Greater);

fn fast_exact_eq(args: &[Term]) -> Option<Term> {
    Some(bool_term(exact_eq(args[0], args[1])))
}

fn fast_exact_ne(args: &[Term]) -> Option<Term> {
    Some(bool_term(!exact_eq(args[0], args[1])))
}

#[inline(always)]
fn fast_arith(args: &[Term], f: impl FnOnce(i64, i64) -> Option<i64>) -> Option<Term> {
    small_pair(args[0], args[1])
        .and_then(|(a, b)| f(a, b))
        .and_then(Term::small)
}

macro_rules! fast_arith {
    ($name:ident, $operation:path) => {
        fn $name(args: &[Term]) -> Option<Term> {
            fast_arith(args, $operation)
        }
    };
}

fast_arith!(fast_add, i64::checked_add);
fast_arith!(fast_sub, i64::checked_sub);
fast_arith!(fast_mul, i64::checked_mul);
fast_arith!(fast_div, i64::checked_div);
fast_arith!(fast_rem, i64::checked_rem);

fn fast_band(args: &[Term]) -> Option<Term> {
    fast_arith(args, |a, b| Some(a & b))
}

fn fast_bor(args: &[Term]) -> Option<Term> {
    fast_arith(args, |a, b| Some(a | b))
}

fn fast_bxor(args: &[Term]) -> Option<Term> {
    fast_arith(args, |a, b| Some(a ^ b))
}

fn fast_is_atom(args: &[Term]) -> Option<Term> {
    Some(bool_term(args[0].classify() == TermKind::Atom))
}

fn fast_is_integer(args: &[Term]) -> Option<Term> {
    args[0].as_small().map(|_| bool_term(true))
}

fn fast_is_tuple(args: &[Term]) -> Option<Term> {
    Some(bool_term(args[0].classify() == TermKind::Tuple))
}

fn fast_is_list(args: &[Term]) -> Option<Term> {
    Some(bool_term(matches!(
        args[0].classify(),
        TermKind::List | TermKind::Nil
    )))
}

fn fast_is_number(args: &[Term]) -> Option<Term> {
    Some(bool_term(args[0].classify() == TermKind::Number))
}

fn fast_not(args: &[Term]) -> Option<Term> {
    boolean(args[0]).map(|value| bool_term(!value))
}

fn fast_element(args: &[Term]) -> Option<Term> {
    args[0].as_small().and_then(|index| {
        let index = usize::try_from(index.checked_sub(1)?).ok()?;
        tuple_view(args[1])?.get(index)
    })
}

fn fast_tuple_size(args: &[Term]) -> Option<Term> {
    tuple_view(args[0]).and_then(|view| Term::small(view.len() as i64))
}

/// `dpm_array_to_list`.
fn array_to_list(array: &[Term], heap: &mut VecHeap) -> Result<Term, EtsError> {
    Ok(TermBuilder::new(heap).list_from_slice(array)?)
}

/// Result of a successful run.
pub(super) struct Outcome {
    pub value: Term,
    /// A `matchReturn` ran: `{message, X}` or the table body's result.
    pub returned: bool,
}

/// Port of erts/emulator/beam/erl_db_util.c:2172 (db_prog_match), OTP-29.1.1.
///
/// `term` is the object for table programs; `array` holds the call arguments for trace
/// programs. Returns `None` when no clause matched (`THE_NON_VALUE`). Results live in
/// `state.heap`.
pub(super) fn db_prog_match<C: MatchContext>(
    prog: &MatchProgram,
    state: &mut PamState,
    term: Term,
    array: &[Term],
    context: &C,
) -> Result<Option<Outcome>, EtsError> {
    let text = &prog.text;
    let arity = array.len();
    let PamState {
        heap,
        esp,
        sp,
        variables,
    } = state;
    // Port of erts/emulator/beam/erl_db_util.c (db_prog_match): the pseudo-process retains
    // its variable and stack arrays across objects, and matchBind initializes each binding.
    let true_term = bool_term(true);
    let false_term = bool_term(false);
    let fail_term = exit_atom();
    let mut start = 0;
    'restart: loop {
        let mut pc = InstructionCursor::new(text, start);
        let mut ep = Cursor::Single(term);
        esp.clear();
        sp.clear();
        let mut ret = true_term;
        let mut returned = false;
        let mut do_catch = false;
        let mut fail_label: Option<usize> = None;
        // `FAIL()`: leave the instruction loop with `false`.
        let success = 'exec: loop {
            let Some(op) = pc.next() else {
                break 'exec false;
            };
            macro_rules! fail {
                () => {
                    break 'exec false
                };
            }
            macro_rules! deref {
                () => {
                    match ep.get(array) {
                        Some(value) => value,
                        None => fail!(),
                    }
                };
            }
            macro_rules! pop {
                () => {
                    match esp.pop() {
                        Some(value) => value,
                        None => fail!(),
                    }
                };
            }
            match op {
                Op::TryMeElse(label) => fail_label = Some(label),
                Op::Array(n) => {
                    // Only when tracing: always the first instruction.
                    if n != arity {
                        fail!();
                    }
                    ep = Cursor::Array(0);
                }
                Op::ArrayPrefix(n) => {
                    if n > arity {
                        fail!();
                    }
                    ep = Cursor::Array(0);
                }
                Op::ArrayBind(n) => variables[n] = array_to_list(array, heap)?,
                Op::Tuple(n) => {
                    let value = deref!();
                    match tuple_view(value) {
                        Some(view) if view.len() == n => {
                            ep = Cursor::Tuple {
                                tuple: view,
                                index: 0,
                            }
                        }
                        _ => fail!(),
                    }
                }
                Op::PushT(n) => {
                    let value = deref!();
                    match tuple_view(value) {
                        Some(view) if view.len() == n => {
                            sp.push(SavedCursor::Tuple {
                                tuple: value,
                                index: 0,
                            });
                            ep.next();
                        }
                        _ => fail!(),
                    }
                }
                Op::List => {
                    let value = deref!();
                    match cons(value) {
                        Some((head, tail)) => {
                            ep = Cursor::Cell {
                                head,
                                tail,
                                index: 0,
                            }
                        }
                        None => fail!(),
                    }
                }
                Op::PushL => {
                    let value = deref!();
                    match cons(value) {
                        Some((head, tail)) => {
                            sp.push(SavedCursor::Cell {
                                head,
                                tail,
                                index: 0,
                            });
                            ep.next();
                        }
                        None => fail!(),
                    }
                }
                Op::Map(n) => {
                    let value = deref!();
                    if value.classify() != TermKind::Map
                        || arinsal_maps::size(value).map_err(|_| EtsError::BadArg)? < n
                    {
                        fail!();
                    }
                    ep = Cursor::Map(value);
                }
                Op::PushM(n) => {
                    let value = deref!();
                    if value.classify() != TermKind::Map
                        || arinsal_maps::size(value).map_err(|_| EtsError::BadArg)? < n
                    {
                        fail!();
                    }
                    sp.push(SavedCursor::Map(value));
                    ep.next();
                }
                Op::Key(key) => {
                    let Cursor::Map(map) = &ep else { fail!() };
                    match arinsal_maps::get(*map, key).map_err(|_| EtsError::BadArg)? {
                        Some(value) => {
                            sp.push(SavedCursor::Map(*map));
                            ep = Cursor::Single(value);
                        }
                        None => fail!(),
                    }
                }
                Op::Pop => match sp.pop() {
                    Some(SavedCursor::Tuple { tuple, index }) => match tuple_view(tuple) {
                        Some(tuple) => ep = Cursor::Tuple { tuple, index },
                        None => fail!(),
                    },
                    Some(SavedCursor::Cell { head, tail, index }) => {
                        ep = Cursor::Cell { head, tail, index }
                    }
                    Some(SavedCursor::Map(map)) => ep = Cursor::Map(map),
                    None => fail!(),
                },
                Op::Swap => {
                    let len = sp.len();
                    if len < 2 {
                        fail!();
                    }
                    sp.swap(len - 1, len - 2);
                }
                Op::Bind(n) => {
                    variables[n] = deref!();
                    ep.next();
                }
                Op::Cmp(n) => {
                    if !exact_eq(variables[n], deref!()) {
                        fail!();
                    }
                    ep.next();
                }
                Op::EqBin(t) | Op::EqRef(t) | Op::EqBig(t) => {
                    if !exact_eq(t, deref!()) {
                        fail!();
                    }
                    ep.next();
                }
                Op::EqFloat(bits) => {
                    let value = deref!();
                    if !is_float_term(value) || float_bits(value)? != bits {
                        fail!();
                    }
                    ep.next();
                }
                Op::Eq(t) => {
                    if t != deref!() {
                        fail!();
                    }
                    ep.next();
                }
                Op::Skip => ep.next(),
                // Here come the guard and body instructions.
                Op::PushC(t) => esp.push(t),
                Op::ConsA => {
                    let tail = pop!();
                    let Some(head) = esp.last_mut() else { fail!() };
                    *head = TermBuilder::new(heap).cons(*head, tail)?;
                }
                Op::ConsB => {
                    let head = pop!();
                    let Some(tail) = esp.last_mut() else { fail!() };
                    *tail = TermBuilder::new(heap).cons(head, *tail)?;
                }
                Op::MkTuple(n) => {
                    if esp.len() < n {
                        fail!();
                    }
                    let base = esp.len() - n;
                    esp[base..].reverse();
                    let tuple = TermBuilder::new(heap).tuple(&esp[base..])?;
                    esp.truncate(base);
                    esp.push(tuple);
                }
                Op::MkFlatMap(n) => {
                    let keys_term = pop!();
                    let Some(keys) = tuple_view(keys_term) else {
                        fail!()
                    };
                    if esp.len() < n {
                        fail!();
                    }
                    let base = esp.len() - n;
                    esp[base..].reverse();
                    for index in 0..n {
                        if keys.get(index).is_none() {
                            fail!();
                        }
                    }
                    let map = TermBuilder::new(heap)
                        .flatmap_with_key_tuple_usort(keys_term, &esp[base..])?;
                    esp.truncate(base);
                    esp.push(map);
                }
                Op::MkHashMap(n) => {
                    if esp.len() < 2 * n {
                        fail!();
                    }
                    let base = esp.len() - 2 * n;
                    let pairs: Vec<(Term, Term)> = esp[base..]
                        .as_chunks::<2>()
                        .0
                        .iter()
                        .map(|[key, value]| (*key, *value))
                        .collect();
                    esp.truncate(base);
                    esp.push(TermBuilder::new(heap).flatmap_from_pairs(&pairs)?);
                }
                Op::Call0(bif) => match call_bif(bif, &[], heap, context) {
                    Ok(value) => esp.push(value),
                    Err(_) if do_catch => esp.push(fail_term),
                    Err(_) => fail!(),
                },
                Op::Call1(bif) => {
                    let Some(&a) = esp.last() else { fail!() };
                    match call_bif(bif, &[a], heap, context) {
                        Ok(value) => *esp.last_mut().unwrap() = value,
                        Err(_) if do_catch => *esp.last_mut().unwrap() = fail_term,
                        Err(_) => fail!(),
                    }
                }
                Op::Call2(bif) => {
                    let len = esp.len();
                    if len < 2 {
                        fail!();
                    }
                    let args = [esp[len - 1], esp[len - 2]];
                    let result = call_bif(bif, &args, heap, context);
                    let value = match result {
                        Ok(value) => value,
                        Err(_) if do_catch => fail_term,
                        Err(_) => fail!(),
                    };
                    esp.pop();
                    *esp.last_mut().unwrap() = value;
                }
                Op::Call3(bif) => {
                    let len = esp.len();
                    if len < 3 {
                        fail!();
                    }
                    let args = [esp[len - 1], esp[len - 2], esp[len - 3]];
                    let result = call_bif(bif, &args, heap, context);
                    let value = match result {
                        Ok(value) => value,
                        Err(_) if do_catch => fail_term,
                        Err(_) => fail!(),
                    };
                    esp.truncate(len - 2);
                    *esp.last_mut().unwrap() = value;
                }
                // Results are copied to the caller's heap when the run ends, so both variants
                // of matchPushV(Result) read the variable.
                Op::PushVResult(n) | Op::PushV(n) => esp.push(variables[n]),
                Op::PushExpr => esp.push(term),
                Op::PushArrayAsList | Op::PushArrayAsListU => esp.push(array_to_list(array, heap)?),
                Op::True => {
                    if pop!() != true_term {
                        fail!();
                    }
                }
                Op::Or(n) | Op::And(n) => {
                    let and = matches!(op, Op::And(_));
                    let (neutral, absorbing) = if and {
                        (true_term, false_term)
                    } else {
                        (false_term, true_term)
                    };
                    let mut result = neutral;
                    let mut remaining = n;
                    while remaining > 0 {
                        remaining -= 1;
                        let value = pop!();
                        if value == absorbing {
                            result = absorbing;
                        } else if value != neutral {
                            // `esp -= n`: drop the operands not yet looked at.
                            let keep = esp.len().saturating_sub(remaining);
                            esp.truncate(keep);
                            if do_catch {
                                result = fail_term;
                                break;
                            }
                            fail!();
                        }
                    }
                    esp.push(result);
                }
                Op::OrElse(n) => {
                    let value = pop!();
                    if value == true_term {
                        esp.push(value);
                        pc.advance(n);
                    } else if value != false_term {
                        if do_catch {
                            esp.push(fail_term);
                            pc.advance(n);
                        } else {
                            fail!();
                        }
                    }
                }
                Op::AndAlso(n) => {
                    let value = pop!();
                    if value == false_term {
                        esp.push(value);
                        pc.advance(n);
                    } else if value != true_term {
                        if do_catch {
                            esp.push(fail_term);
                            pc.advance(n);
                        } else {
                            fail!();
                        }
                    }
                }
                Op::Jump(n) => {
                    pc.advance(n);
                }
                Op::SelfPid => match context.self_pid() {
                    Some(pid) => esp.push(pid),
                    None => fail!(),
                },
                Op::Waste => {
                    pop!();
                }
                Op::Return => {
                    ret = pop!();
                    returned = true;
                }
                Op::ProcessDump => match context.trace_operation("process_dump", &[]) {
                    Ok(value) => esp.push(value),
                    Err(_) => fail!(),
                },
                Op::Display => {
                    let Some(&value) = esp.last() else { fail!() };
                    match context.trace_operation("display", &[value]) {
                        Ok(result) => *esp.last_mut().unwrap() = result,
                        Err(_) => fail!(),
                    }
                }
                Op::SetReturnTrace => match context.trace_operation("return_trace", &[]) {
                    Ok(value) => esp.push(value),
                    Err(_) => fail!(),
                },
                Op::SetExceptionTrace => match context.trace_operation("exception_trace", &[]) {
                    Ok(value) => esp.push(value),
                    Err(_) => fail!(),
                },
                Op::IsSeqTrace => match context.trace_operation("is_seq_trace", &[]) {
                    Ok(value) => esp.push(value),
                    Err(_) => fail!(),
                },
                // Both read the token through the context; the fake one is the test dialect's.
                Op::SetSeqToken | Op::SetSeqTokenFake => {
                    let len = esp.len();
                    if len < 2 {
                        fail!();
                    }
                    let args = [esp[len - 1], esp[len - 2]];
                    esp.pop();
                    esp[len - 2] = context
                        .trace_operation("set_seq_token", &args)
                        .unwrap_or(fail_term);
                }
                Op::GetSeqToken => match context.trace_operation("get_seq_token", &[]) {
                    Ok(value) => esp.push(value),
                    Err(_) => fail!(),
                },
                Op::EnableTrace | Op::DisableTrace => {
                    let name = if matches!(op, Op::EnableTrace) {
                        "enable_trace"
                    } else {
                        "disable_trace"
                    };
                    let Some(&flag) = esp.last() else { fail!() };
                    *esp.last_mut().unwrap() =
                        context.trace_operation(name, &[flag]).unwrap_or(fail_term);
                }
                Op::EnableTrace2 | Op::DisableTrace2 => {
                    let name = if matches!(op, Op::EnableTrace2) {
                        "enable_trace"
                    } else {
                        "disable_trace"
                    };
                    let len = esp.len();
                    if len < 2 {
                        fail!();
                    }
                    let args = [esp[len - 1], esp[len - 2]];
                    esp.pop();
                    *esp.last_mut().unwrap() =
                        context.trace_operation(name, &args).unwrap_or(fail_term);
                }
                Op::Caller => match context.trace_operation("caller", &[]) {
                    Ok(value) => esp.push(value),
                    Err(_) => fail!(),
                },
                Op::CallerLine => match context.trace_operation("caller_line", &[]) {
                    Ok(value) => esp.push(value),
                    Err(_) => fail!(),
                },
                Op::CurrentStacktrace => {
                    let depth = pop!();
                    match context.trace_operation("current_stacktrace", &[depth]) {
                        Ok(value) => esp.push(value),
                        Err(_) => fail!(),
                    }
                }
                Op::Silent => {
                    let value = pop!();
                    let _ = context.trace_operation("silent", &[value]);
                }
                Op::Trace2 => {
                    let len = esp.len();
                    if len < 2 {
                        fail!();
                    }
                    let args = [esp[len - 1], esp[len - 2]];
                    esp.pop();
                    *esp.last_mut().unwrap() =
                        context.trace_operation("trace", &args).unwrap_or(fail_term);
                }
                Op::Trace3 => {
                    let len = esp.len();
                    if len < 3 {
                        fail!();
                    }
                    let args = [esp[len - 1], esp[len - 2], esp[len - 3]];
                    esp.truncate(len - 2);
                    *esp.last_mut().unwrap() =
                        context.trace_operation("trace", &args).unwrap_or(fail_term);
                }
                // Match success, now build the result.
                Op::Catch => do_catch = true,
                Op::Halt => break 'exec true,
            }
        };
        if success {
            return Ok(Some(Outcome {
                value: ret,
                returned,
            }));
        }
        if let Some(label) = fail_label {
            // We failed during a "TryMeElse": restart with the next match program.
            start = label;
            continue 'restart;
        }
        return Ok(None);
    }
}
