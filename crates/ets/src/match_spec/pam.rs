//! Match program interpreter.
//!
//! Port of erts/emulator/beam/erl_db_util.c:2172 (db_prog_match), OTP-29.1.1. The C code walks
//! raw `Eterm*` cursors; here a [`Cursor`] names the tuple, list cell, map or array a cursor
//! points into, and the evaluation stack is a vector.

use super::dmc::{Fast, GuardBif, Op};
use super::{MatchContext, MatchProgram, bool_term, boolean, builtin, float_bits, is_float_term};
use super::{cons, tuple_view};
use crate::EtsError;
use arinsal_term::{Atom, Term, TermBuilder, TermKind, VecHeap, cmp, exact_eq, global_atoms};
use std::cmp::Ordering;

/// The `Eterm*` cursors of db_prog_match: where the next match instruction reads.
#[derive(Clone, Copy)]
enum Cursor {
    /// The object itself, or the value found by `matchKey`.
    Single(Term),
    /// Element `index` of a tuple.
    Tuple { tuple: Term, index: usize },
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

impl Cursor {
    fn get(self, array: &[Term]) -> Option<Term> {
        match self {
            Self::Single(term) => Some(term),
            Self::Tuple { tuple, index } => tuple_view(tuple)?.get(index),
            Self::Cell { head, tail, index } => match index {
                0 => Some(head),
                1 => Some(tail),
                _ => None,
            },
            Self::Array(index) => array.get(index).copied(),
            Self::Map(_) | Self::Past => None,
        }
    }

    /// `ep++`.
    fn next(self) -> Self {
        match self {
            Self::Tuple { tuple, index } => Self::Tuple {
                tuple,
                index: index + 1,
            },
            Self::Cell { head, tail, index } => Self::Cell {
                head,
                tail,
                index: index + 1,
            },
            Self::Array(index) => Self::Array(index + 1),
            Self::Single(_) | Self::Map(_) | Self::Past => Self::Past,
        }
    }
}

/// The match pseudo process: heap, evaluation stack and variable table, reused per thread.
pub(super) struct PamState {
    pub heap: VecHeap,
    esp: Vec<Term>,
    sp: Vec<Cursor>,
    variables: Vec<Term>,
}

impl PamState {
    pub fn new() -> Self {
        Self {
            // Port of erl_db_util.c:431-455 (ERTS_DEFAULT_MS_HEAP_SIZE and
            // match-pseudo-process cleanup), OTP-29.1.1.
            heap: VecHeap::with_initial_chunk_words(128),
            esp: Vec::new(),
            sp: Vec::new(),
            variables: Vec::new(),
        }
    }
}

fn exit_atom() -> Term {
    static EXIT: std::sync::OnceLock<Atom> = std::sync::OnceLock::new();
    Term::atom(*EXIT.get_or_init(|| global_atoms().intern("EXIT").unwrap()))
}

fn small_pair(a: Term, b: Term) -> Option<(i64, i64)> {
    Some((a.as_small()?, b.as_small()?))
}

/// Run a guard BIF found in the program's `Call0..3` instruction.
fn call_bif<C: MatchContext>(
    bif: &GuardBif,
    args: &[Term],
    heap: &mut VecHeap,
    context: &C,
) -> Result<Term, EtsError> {
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
    fast_call(bif, args, heap)
}

fn fast_call(bif: &GuardBif, args: &[Term], heap: &mut VecHeap) -> Result<Term, EtsError> {
    #[inline(always)]
    fn arith(args: &[Term], f: impl FnOnce(i64, i64) -> Option<i64>) -> Option<Term> {
        small_pair(args[0], args[1])
            .and_then(|(a, b)| f(a, b))
            .and_then(Term::small)
    }
    let fast = match bif.fast {
        Fast::Eq | Fast::Ne | Fast::Gt | Fast::Ge | Fast::Lt | Fast::Le => {
            let order = match small_pair(args[0], args[1]) {
                Some((a, b)) => a.cmp(&b),
                None => cmp(args[0], args[1]),
            };
            Some(bool_term(match bif.fast {
                Fast::Eq => order == Ordering::Equal,
                Fast::Ne => order != Ordering::Equal,
                Fast::Gt => order == Ordering::Greater,
                Fast::Ge => order != Ordering::Less,
                Fast::Lt => order == Ordering::Less,
                _ => order != Ordering::Greater,
            }))
        }
        Fast::ExactEq => Some(bool_term(exact_eq(args[0], args[1]))),
        Fast::ExactNe => Some(bool_term(!exact_eq(args[0], args[1]))),
        Fast::Add => arith(args, i64::checked_add),
        Fast::Sub => arith(args, i64::checked_sub),
        Fast::Mul => arith(args, i64::checked_mul),
        Fast::Div => arith(args, i64::checked_div),
        Fast::Rem => arith(args, i64::checked_rem),
        Fast::Band => arith(args, |a, b| Some(a & b)),
        Fast::Bor => arith(args, |a, b| Some(a | b)),
        Fast::Bxor => arith(args, |a, b| Some(a ^ b)),
        Fast::IsAtom => Some(bool_term(args[0].classify() == TermKind::Atom)),
        Fast::IsInteger => args[0].as_small().map(|_| bool_term(true)),
        Fast::IsTuple => Some(bool_term(args[0].classify() == TermKind::Tuple)),
        Fast::IsList => Some(bool_term(matches!(
            args[0].classify(),
            TermKind::List | TermKind::Nil
        ))),
        Fast::IsNumber => Some(bool_term(args[0].classify() == TermKind::Number)),
        Fast::Not => boolean(args[0]).map(|value| bool_term(!value)),
        Fast::Element => args[0].as_small().and_then(|index| {
            let index = usize::try_from(index.checked_sub(1)?).ok()?;
            tuple_view(args[1])?.get(index)
        }),
        Fast::TupleSize => tuple_view(args[0]).and_then(|view| Term::small(view.len() as i64)),
        Fast::None => None,
    };
    match fast {
        Some(value) => Ok(value),
        None => builtin(bif.name, args, heap),
    }
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
    // Port of erts/emulator/beam/erl_db_util.c (db_prog_match): a binding is initialized by
    // its matchBind instruction before any guarded or result read.
    if variables.len() < prog.num_bindings {
        variables.resize(prog.num_bindings, Term::NIL);
    } else {
        variables.truncate(prog.num_bindings);
    }
    esp.reserve(prog.stack_need);
    let true_term = bool_term(true);
    let false_term = bool_term(false);
    let fail_term = exit_atom();
    let mut start = 0;
    'restart: loop {
        let mut pc = start;
        let mut ep = Cursor::Single(term);
        esp.clear();
        sp.clear();
        let mut ret = true_term;
        let mut returned = false;
        let mut do_catch = false;
        let mut fail_label: Option<usize> = None;
        // `FAIL()`: leave the instruction loop with `false`.
        let success = 'exec: loop {
            let op = text[pc];
            pc += 1;
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
                                tuple: value,
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
                            sp.push(Cursor::Tuple {
                                tuple: value,
                                index: 0,
                            });
                            ep = ep.next();
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
                            sp.push(Cursor::Cell {
                                head,
                                tail,
                                index: 0,
                            });
                            ep = ep.next();
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
                    sp.push(Cursor::Map(value));
                    ep = ep.next();
                }
                Op::Key(key) => {
                    let Cursor::Map(map) = ep else { fail!() };
                    match arinsal_maps::get(map, key).map_err(|_| EtsError::BadArg)? {
                        Some(value) => {
                            sp.push(ep);
                            ep = Cursor::Single(value);
                        }
                        None => fail!(),
                    }
                }
                Op::Pop => match sp.pop() {
                    Some(cursor) => ep = cursor,
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
                    ep = ep.next();
                }
                Op::Cmp(n) => {
                    if !exact_eq(variables[n], deref!()) {
                        fail!();
                    }
                    ep = ep.next();
                }
                Op::EqBin(t) | Op::EqRef(t) | Op::EqBig(t) => {
                    if !exact_eq(t, deref!()) {
                        fail!();
                    }
                    ep = ep.next();
                }
                Op::EqFloat(bits) => {
                    let value = deref!();
                    if !is_float_term(value) || float_bits(value)? != bits {
                        fail!();
                    }
                    ep = ep.next();
                }
                Op::Eq(t) => {
                    if t != deref!() {
                        fail!();
                    }
                    ep = ep.next();
                }
                Op::Skip => ep = ep.next(),
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
                    let mut elements = Vec::with_capacity(n);
                    for _ in 0..n {
                        elements.push(pop!());
                    }
                    esp.push(TermBuilder::new(heap).tuple(&elements)?);
                }
                Op::MkFlatMap(n) => {
                    let keys = pop!();
                    let Some(keys) = tuple_view(keys) else {
                        fail!()
                    };
                    let mut pairs = Vec::with_capacity(n);
                    for index in 0..n {
                        let value = pop!();
                        let Some(key) = keys.get(index) else { fail!() };
                        pairs.push((key, value));
                    }
                    esp.push(TermBuilder::new(heap).flatmap_from_pairs(&pairs)?);
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
                        pc += n;
                    } else if value != false_term {
                        if do_catch {
                            esp.push(fail_term);
                            pc += n;
                        } else {
                            fail!();
                        }
                    }
                }
                Op::AndAlso(n) => {
                    let value = pop!();
                    if value == false_term {
                        esp.push(value);
                        pc += n;
                    } else if value != true_term {
                        if do_catch {
                            esp.push(fail_term);
                            pc += n;
                        } else {
                            fail!();
                        }
                    }
                }
                Op::Jump(n) => pc += n,
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
