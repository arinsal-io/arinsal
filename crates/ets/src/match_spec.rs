//! Match specification compilation and execution, independent of ETS storage.

use crate::EtsError;
use arinsal_etf::OwnedTerm;
use arinsal_term::{
    Atom, HeapAlloc, Identity, Term, TermBuilder, TermKind, VecHeap, cmp, copy_shallow,
    copy_struct, copy_term, exact_eq, from_owned, global_atoms, to_owned,
};
use num_bigint::BigInt;
use num_traits::{Signed, ToPrimitive, Zero};
use std::cell::Cell;
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
mod dmc;
mod pam;

use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};

/// One clause of the specification as written, kept for the key analysis.
struct Clause {
    head: Term,
    guards: Vec<Term>,
    body: Vec<Term>,
}

/// The key a clause head gives, for choosing the buckets of a hash table traversal.
pub(crate) enum HeadKey {
    /// The head is a variable: every object can match.
    Variable,
    /// The head has a key that is not fully bound.
    Unbound,
    /// The head has no key (not a tuple, or too small).
    Missing,
    /// The head has a fully bound key.
    Bound(Term),
}

/// How the clause heads of a program name the key of an ordered table.
// Port of `enum ms_key_boundness` and `struct mp_info` in erts/emulator/beam/erl_db_tree.c,
// OTP-29.1.1.
pub(crate) enum TreeKeys {
    /// No clause head can match any object.
    Impossible,
    /// Some clause matches any key.
    Unbound,
    /// Every key a clause names lies between `least` and `most`, both possibly partly bound.
    Partial { least: Term, most: Term },
    /// Every clause names the same fully bound key.
    Bound,
}

/// A stored object whose size is known, and its block when that can be copied word by word.
#[derive(Clone, Copy)]
pub(crate) struct KnownObject<'a> {
    pub(crate) size: usize,
    pub(crate) block: Option<&'a [u64]>,
}

/// An immutable match program reusable by ETS and tracing.
pub struct MatchProgram {
    // Clauses point into this stable, private heap.
    heap: VecHeap,
    clauses: Vec<Clause>,
    /// The flat match program (`MatchProg::text`) and its binding count.
    text: Vec<dmc::Op>,
    num_bindings: usize,
    stack_need: usize,
    id: u64,
    trace: bool,
}

/// Match pseudo-process state kept for one whole table traversal.
// Port of erts/emulator/beam/erl_db_hash.c (match_traverse reuses the process
// match state for each DbTerm), OTP-29.1.1.
pub(crate) struct MatchRunner<'a> {
    program: &'a MatchProgram,
    state: pam::PamState,
}

static NEXT_PROGRAM_ID: AtomicU64 = AtomicU64::new(1);

/// Process and tracing values supplied by the VM when a match program runs.
pub trait MatchContext {
    /// Process identifier returned by `self/0`.
    fn self_pid(&self) -> Option<Term> {
        None
    }

    /// Local node name returned by `node/0`.
    fn node_name(&self) -> Option<Term> {
        None
    }

    /// Trace control word returned by `get_tcw/0`.
    fn trace_control_word(&self) -> Option<Term> {
        None
    }

    /// Resolve the node owning a pid, port, or reference.
    fn node_of(&self, term: Term) -> Option<Term> {
        let node = match term.identity()? {
            arinsal_term::Identity::Pid { node, .. }
            | arinsal_term::Identity::Port { node, .. }
            | arinsal_term::Identity::Ref { node, .. } => node,
        };
        Some(Term::atom(node))
    }

    /// Execute a tracing-only match-spec operation.
    fn trace_operation(&self, _name: &str, _arguments: &[Term]) -> Result<Term, EtsError> {
        Err(EtsError::Unsupported("trace match specification context"))
    }

    /// Flags collected by a tracing match-spec test run.
    fn trace_flags(&self) -> Vec<Term> {
        Vec::new()
    }
}

impl MatchContext for () {}

pub(crate) struct EmptyContext;
impl MatchContext for EmptyContext {
    fn node_name(&self) -> Option<Term> {
        Some(Term::atom(global_atoms().intern("nonode@nohost").ok()?))
    }
}

/// Match-spec dialect selected by `erlang:match_spec_test/3`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MatchDialect {
    /// ETS table match specifications.
    Table,
    /// Process tracing match specifications.
    Trace,
}

/// Execute a match spec with the `erlang:match_spec_test/3` return shape.
pub fn match_spec_test<H: HeapAlloc, C: MatchContext>(
    against: Term,
    specification: Term,
    dialect: MatchDialect,
    dst: &mut H,
    context: &C,
) -> Result<Term, EtsError> {
    struct TestContext<'a, C> {
        inner: &'a C,
        flags: Cell<u8>,
        trace_control_word: Cell<Option<Term>>,
    }
    impl<C: MatchContext> MatchContext for TestContext<'_, C> {
        fn self_pid(&self) -> Option<Term> {
            self.inner.self_pid()
        }
        fn node_name(&self) -> Option<Term> {
            self.inner.node_name()
        }
        fn trace_control_word(&self) -> Option<Term> {
            self.trace_control_word.get()
        }
        fn node_of(&self, term: Term) -> Option<Term> {
            self.inner.node_of(term)
        }
        fn trace_operation(&self, name: &str, arguments: &[Term]) -> Result<Term, EtsError> {
            match name {
                "message" => Ok(arguments[0]),
                "set_tcw" => {
                    let previous = self
                        .trace_control_word
                        .get()
                        .and_then(Term::as_small)
                        .unwrap_or(0);
                    self.trace_control_word.set(arguments.first().copied());
                    Term::small(previous).ok_or(EtsError::BadArg)
                }
                "set_seq_token" => Ok(truth(true)),
                "caller" | "caller_line" => {
                    Ok(Term::atom(global_atoms().intern("undefined").unwrap()))
                }
                "return_trace" => {
                    self.flags.set(self.flags.get() | 1);
                    Ok(truth(true))
                }
                "exception_trace" => {
                    self.flags.set(self.flags.get() | 2);
                    Ok(truth(true))
                }
                _ => self
                    .inner
                    .trace_operation(name, arguments)
                    .or_else(|_| Ok(truth(true))),
            }
        }
        fn trace_flags(&self) -> Vec<Term> {
            let mut flags = self.inner.trace_flags();
            if self.flags.get() & 1 != 0 {
                flags.push(Term::atom(global_atoms().intern("return_trace").unwrap()));
            }
            if self.flags.get() & 2 != 0 {
                flags.push(Term::atom(
                    global_atoms().intern("exception_trace").unwrap(),
                ));
            }
            flags
        }
    }
    if dialect == MatchDialect::Trace
        && !matches!(against.classify(), TermKind::List | TermKind::Nil)
    {
        return Err(EtsError::BadArg);
    }
    let compiled = MatchProgram::compile_test(specification, dialect == MatchDialect::Trace);
    let program = match compiled {
        Ok(program) => program,
        Err(_) => {
            return compiler_error_result(specification, dialect == MatchDialect::Trace, dst);
        }
    };
    let test_context = TestContext {
        inner: context,
        flags: Cell::new(0),
        trace_control_word: Cell::new(context.trace_control_word()),
    };
    let result = program
        .run_with_context(against, dst, &test_context)?
        .unwrap_or_else(|| truth(false));
    let flags = test_context
        .trace_flags()
        .into_iter()
        .map(|flag| copy_term(flag, dst))
        .collect::<Result<Vec<_>, _>>()?;
    let flags = TermBuilder::new(dst).list_from_iter(flags)?;
    Ok(TermBuilder::new(dst).tuple(&[
        Term::atom(global_atoms().intern("ok").unwrap()),
        result,
        flags,
        Term::NIL,
    ])?)
}

fn compiler_error_result<H: HeapAlloc>(
    specification: Term,
    trace: bool,
    dst: &mut H,
) -> Result<Term, EtsError> {
    let messages = compiler_diagnostics(specification, trace);
    let mut builder = TermBuilder::new(dst);
    let mut diagnostics = Vec::with_capacity(messages.len());
    for message in messages {
        let text = builder.string_to_list(&message)?;
        diagnostics
            .push(builder.tuple(&[Term::atom(global_atoms().intern("error").unwrap()), text])?);
    }
    let diagnostics = builder.list_from_iter(diagnostics)?;
    Ok(builder.tuple(&[
        Term::atom(global_atoms().intern("error").unwrap()),
        diagnostics,
    ])?)
}

/// Key interval inferred from a single ordered-table match clause.
#[derive(Clone, Copy)]
pub struct KeyBounds {
    /// Lower key and whether it is inclusive.
    pub lower: Option<(Term, bool)>,
    /// Upper key and whether it is inclusive.
    pub upper: Option<(Term, bool)>,
    /// Lowest key pattern any clause head can match (possibly partly bound).
    pub least: Option<Term>,
    /// Highest key pattern any clause head can match (possibly partly bound).
    pub most: Option<Term>,
}

impl KeyBounds {
    /// Whether `key` sorts before every key the match specification can select.
    #[inline]
    pub fn is_below(&self, key: Term) -> bool {
        self.lower.is_some_and(|(bound, inclusive)| {
            let order = cmp(key, bound);
            order == Ordering::Less || (order == Ordering::Equal && !inclusive)
        }) || self
            .least
            .is_some_and(|least| cmp_partly_bound(least, key) > 0)
    }

    /// Whether `key` sorts after every key the match specification can select.
    #[inline]
    pub fn is_above(&self, key: Term) -> bool {
        self.upper.is_some_and(|(bound, inclusive)| {
            let order = cmp(key, bound);
            order == Ordering::Greater || (order == Ordering::Equal && !inclusive)
        }) || self
            .most
            .is_some_and(|most| cmp_partly_bound(most, key) < 0)
    }
}

/// Whether a term is `'_'` or a `'$N'` match variable.
fn is_match_variable(term: Term) -> bool {
    let Some(atom) = term.as_atom() else {
        return false;
    };
    global_atoms().text(atom).is_some_and(|text| {
        text == "_"
            || text
                .strip_prefix('$')
                .is_some_and(|d| !d.is_empty() && d.bytes().all(|b| b.is_ascii_digit()))
    })
}

fn sign(order: Ordering) -> i32 {
    order as i32
}

/// Port of erts/emulator/beam/erl_db_tree.c (do_cmp_partly_bound), OTP-29.1.1.
fn do_cmp_partly_bound(a: Term, b: Term, done: &mut bool) -> i32 {
    if is_match_variable(a) {
        *done = true;
        return 0;
    }
    if a == b {
        return 0;
    }
    match a.classify() {
        TermKind::List if b.classify() == TermKind::List => {
            let (mut a, mut b) = (a, b);
            loop {
                let (Some((ah, at)), Some((bh, bt))) = (cons(a), cons(b)) else {
                    return sign(cmp(a, b));
                };
                let j = do_cmp_partly_bound(ah, bh, done);
                if j != 0 || *done {
                    return j;
                }
                if at == bt {
                    return 0;
                }
                if at.classify() != TermKind::List || bt.classify() != TermKind::List {
                    return do_cmp_partly_bound(at, bt, done);
                }
                a = at;
                b = bt;
            }
        }
        TermKind::Tuple if b.classify() == TermKind::Tuple => {
            let (Some(at), Some(bt)) = (tuple_view(a), tuple_view(b)) else {
                return sign(cmp(a, b));
            };
            if at.len() != bt.len() {
                return if at.len() < bt.len() { -1 } else { 1 };
            }
            for (x, y) in at.iter().zip(bt.iter()) {
                let j = do_cmp_partly_bound(x, y, done);
                if j != 0 || *done {
                    return j;
                }
            }
            0
        }
        _ => sign(cmp(a, b)),
    }
}

/// Port of erts/emulator/beam/erl_db_tree.c (cmp_partly_bound), OTP-29.1.1.
pub(crate) fn cmp_partly_bound(partly_bound_key: Term, bound_key: Term) -> i32 {
    do_cmp_partly_bound(partly_bound_key, bound_key, &mut false)
}

/// Shared walk of `do_partly_bound_can_match_lesser/greater`; `lesser` picks the direction.
// Port of erts/emulator/beam/erl_db_tree.c and :4059, OTP-29.1.1.
fn do_partly_bound_can_match(a: Term, b: Term, lesser: bool, done: &mut bool) -> bool {
    let want = |order: i32| if lesser { order < 0 } else { order > 0 };
    if is_match_variable(a) {
        *done = true;
        return !is_match_variable(b);
    } else if is_match_variable(b) {
        *done = true;
        return false;
    }
    if a == b {
        return false;
    }
    match (a.classify(), b.classify()) {
        (TermKind::Tuple, TermKind::Tuple) => {
            let (Some(at), Some(bt)) = (tuple_view(a), tuple_view(b)) else {
                return false;
            };
            if at.len() != bt.len() {
                return (at.len() < bt.len()) == lesser;
            }
            for (x, y) in at.iter().zip(bt.iter()) {
                let j = do_partly_bound_can_match(x, y, lesser, done);
                if j || *done {
                    return j;
                }
            }
            false
        }
        (TermKind::List, TermKind::List) => {
            let (mut a, mut b) = (a, b);
            loop {
                let (Some((ah, at)), Some((bh, bt))) = (cons(a), cons(b)) else {
                    return false;
                };
                let j = do_partly_bound_can_match(ah, bh, lesser, done);
                if j || *done {
                    return j;
                }
                if at == bt {
                    return false;
                }
                if at.classify() != TermKind::List || bt.classify() != TermKind::List {
                    return do_partly_bound_can_match(at, bt, lesser, done);
                }
                a = at;
                b = bt;
            }
        }
        _ => {
            // Differing tags and same-tag scalars both reduce to CMP.
            let order = sign(cmp(a, b));
            if order != 0 {
                *done = true;
            }
            want(order)
        }
    }
}

/// Whether `a` (a key pattern) can match a key lesser than `b`'s.
fn partly_bound_can_match_lesser(a: Term, b: Term) -> bool {
    do_partly_bound_can_match(a, b, true, &mut false)
}

/// Whether `a` (a key pattern) can match a key greater than `b`'s.
fn partly_bound_can_match_greater(a: Term, b: Term) -> bool {
    do_partly_bound_can_match(a, b, false, &mut false)
}

/// Port of erts/emulator/beam/erl_db_util.c (db_is_fully_bound), OTP-29.1.1.
/// Maps count as variable, like in erts.
fn is_fully_bound(term: Term) -> bool {
    match term.classify() {
        TermKind::List => {
            let mut rest = term;
            while let Some((head, tail)) = cons(rest) {
                if !is_fully_bound(head) {
                    return false;
                }
                rest = tail;
            }
            is_fully_bound(rest)
        }
        TermKind::Tuple => tuple_view(term).is_some_and(|items| items.iter().all(is_fully_bound)),
        TermKind::Map => false,
        _ => !is_match_variable(term),
    }
}

/// Port of erts/emulator/beam/erl_db_util.c (db_has_map), OTP-29.1.1.
fn has_map(term: Term) -> bool {
    match term.classify() {
        TermKind::Map => true,
        TermKind::List => {
            let mut rest = term;
            while let Some((head, tail)) = cons(rest) {
                if has_map(head) {
                    return true;
                }
                rest = tail;
            }
            has_map(rest)
        }
        TermKind::Tuple => tuple_view(term).is_some_and(|items| items.iter().any(has_map)),
        _ => false,
    }
}

fn atom_name(term: Term) -> Option<String> {
    global_atoms()
        .text(term.as_atom()?)
        .map(|name| name.to_string())
}

fn proper_list(mut term: Term) -> Result<Vec<Term>, EtsError> {
    // Port of erts/emulator/beam/erl_db_util.c, OTP-29.1.1 (dmc_list).
    let mut values = Vec::new();
    while term != Term::NIL {
        let (head, tail) = cons(term).ok_or(EtsError::BadArg)?;
        values.push(head);
        term = tail;
    }
    Ok(values)
}

/// Borrowed tuple view of a term held by a live source or program heap.
fn tuple_view<'a>(term: Term) -> Option<arinsal_term::TupleRef<'a>> {
    // SAFETY: every term handled here lives in the caller's source or program heap,
    // which stays pinned for the duration of the borrow.
    unsafe { term.tuple_ref() }
}

/// Head and tail of a list cell held by a live source or program heap.
fn cons(term: Term) -> Option<(Term, Term)> {
    // SAFETY: as for `tuple_view`.
    unsafe { term.cons_ref() }
}

fn tuple(term: Term) -> Result<Vec<Term>, EtsError> {
    // Port of erts/emulator/beam/erl_db_util.c, OTP-29.1.1 (dmc_tuple).
    let view = tuple_view(term).ok_or(EtsError::BadArg)?;
    Ok(view.iter().collect())
}

fn variable(term: Term) -> Option<usize> {
    // Port of erts/emulator/beam/erl_db_util.c, OTP-29.1.1 (db_is_variable).
    let text = global_atoms().text(term.as_atom()?)?;
    let digits = text.strip_prefix('$')?;
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse::<usize>().ok()
}

// Port of erts/emulator/beam/erl_db_util.c, OTP-29.1.1 (dmc_one_term).
fn head_variables(term: Term, bound: &mut HashSet<usize>) -> Result<(), EtsError> {
    // Port of erts/emulator/beam/erl_db_util.c, OTP-29.1.1 (matchPushV).
    if let Some(index) = variable(term) {
        bound.insert(index);
        return Ok(());
    }
    match term.classify() {
        TermKind::Tuple => {
            // Port of erts/emulator/beam/erl_db_util.c, OTP-29.1.1 (matchTuple).
            for element in tuple(term)? {
                head_variables(element, bound)?;
            }
        }
        TermKind::List => {
            // Port of erts/emulator/beam/erl_db_util.c, OTP-29.1.1 (matchList).
            let (head, tail) = cons(term).ok_or(EtsError::BadArg)?;
            head_variables(head, bound)?;
            head_variables(tail, bound)?;
        }
        TermKind::Map => {
            // Port of erts/emulator/beam/erl_db_util.c, OTP-29.1.1 (matchMap).
            let OwnedTerm::Map(pairs) = &to_owned(term)? else {
                return Err(EtsError::BadArg);
            };
            let mut heap = VecHeap::new();
            for (key, value) in pairs {
                let key = from_owned(key, &mut heap)?;
                if variable(key).is_some() || atom_name(key).as_deref() == Some("_") {
                    return Err(EtsError::BadArg);
                }
                let value = from_owned(value, &mut heap)?;
                head_variables(value, bound)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn unbound_variable(term: Term, bound: &HashSet<usize>) -> Option<usize> {
    if let Some(index) = variable(term) {
        return (!bound.contains(&index)).then_some(index);
    }
    match term.classify() {
        TermKind::List => owned_unbound_variable(&to_owned(term).ok()?, bound),
        TermKind::Map => {
            let owned = to_owned(term).ok()?;
            owned_unbound_variable(&owned, bound)
        }
        TermKind::Tuple => {
            let parts = tuple(term).ok()?;
            if parts.first().and_then(|&head| atom_name(head)).as_deref() == Some("const") {
                return None;
            }
            parts
                .into_iter()
                .skip(1)
                .find_map(|part| unbound_variable(part, bound))
        }
        _ => None,
    }
}

fn owned_unbound_variable(term: &OwnedTerm, bound: &HashSet<usize>) -> Option<usize> {
    match term {
        OwnedTerm::Atom(name) => {
            let index = name.strip_prefix('$')?.parse::<usize>().ok()?;
            (!bound.contains(&index)).then_some(index)
        }
        OwnedTerm::Tuple(parts) => {
            if matches!(parts.first(), Some(OwnedTerm::Atom(name)) if name == "const") {
                return None;
            }
            parts
                .iter()
                .skip(1)
                .find_map(|part| owned_unbound_variable(part, bound))
        }
        OwnedTerm::List { elems, tail } => elems
            .iter()
            .find_map(|part| owned_unbound_variable(part, bound))
            .or_else(|| owned_unbound_variable(tail, bound)),
        OwnedTerm::Map(pairs) => pairs.iter().find_map(|(key, value)| {
            owned_unbound_variable(key, bound).or_else(|| owned_unbound_variable(value, bound))
        }),
        _ => None,
    }
}

// Port of erts/emulator/beam/erl_db_util.c, OTP-29.1.1 (match_spec_test).
fn compiler_diagnostics(specification: Term, trace: bool) -> Vec<String> {
    const INVALID: &str = "Invalid match specification.";
    let Ok(clauses) = proper_list(specification) else {
        return vec![INVALID.into()];
    };
    if clauses.is_empty() {
        return vec![INVALID.into()];
    }
    let mut messages = Vec::new();
    for clause in clauses {
        let Ok(parts) = tuple(clause) else {
            messages.push(INVALID.into());
            continue;
        };
        if parts.len() != 3 {
            messages.push(INVALID.into());
            continue;
        }
        let Ok(guards) = proper_list(parts[1]) else {
            messages.push(INVALID.into());
            continue;
        };
        let Ok(body) = proper_list(parts[2]) else {
            messages.push(INVALID.into());
            continue;
        };
        if body.is_empty() && !trace {
            messages.push("Body clause does not return anything.".into());
            continue;
        }
        let mut bound = HashSet::new();
        if head_variables(parts[0], &mut bound).is_err() {
            messages.push(INVALID.into());
            continue;
        }
        for (expressions, is_guard) in [(&guards, true), (&body, false)] {
            for expression in expressions {
                let valid = validate_expr(*expression, is_guard, &bound, trace, 0);
                if valid == Err(EtsError::Term(arinsal_term::TermError::SystemLimit)) {
                    // Port of erts/emulator/beam/erl_db_util.c, OTP-29.1.1.
                    messages.push("Excessive nesting; system limit reached.".into());
                } else if let Some(index) = unbound_variable(*expression, &bound) {
                    messages.push(format!("Variable ${index} is unbound."));
                } else if valid.is_err() {
                    messages.push(INVALID.into());
                }
            }
        }
    }
    if messages.is_empty() {
        messages.push(INVALID.into());
    }
    messages
}

/// Deepest expression nesting a match specification may use before compilation fails with
/// `system_limit` (erl 29.1.1 on this machine gives up after roughly 1300 levels).
const MAX_NESTING: usize = 1000;

// Port of erts/emulator/beam/erl_db_util.c, OTP-29.1.1 (guard_tab).
fn validate_expr(
    term: Term,
    guard: bool,
    bound: &HashSet<usize>,
    trace: bool,
    depth: usize,
) -> Result<(), EtsError> {
    // Port of erts/emulator/beam/erl_db_util.c (dmc_expr stack_guard), OTP-29.1.1.
    // erts bounds the compiler recursion by the remaining C stack; a fixed nesting bound
    // keeps the same system_limit outcome without reading the native stack.
    if depth > MAX_NESTING {
        return Err(EtsError::Term(arinsal_term::TermError::SystemLimit));
    }
    let depth = depth + 1;
    if let Some(index) = variable(term) {
        return if bound.contains(&index) {
            Ok(())
        } else {
            Err(EtsError::BadArg)
        };
    }
    if term.classify() == TermKind::List {
        // Port of erts/emulator/beam/erl_db_util.c, OTP-29.1.1 (dmc_list).
        // Walk the spine iteratively: long lists are not nesting.
        let mut rest = term;
        while rest.classify() == TermKind::List {
            let (head, tail) = cons(rest).ok_or(EtsError::BadArg)?;
            validate_expr(head, guard, bound, trace, depth)?;
            rest = tail;
        }
        return validate_expr(rest, guard, bound, trace, depth);
    }
    if term.classify() == TermKind::Map {
        // Port of erts/emulator/beam/erl_db_util.c, OTP-29.1.1 (dmc_map).
        let owned = to_owned(term)?;
        let OwnedTerm::Map(pairs) = &owned else {
            return Err(EtsError::BadArg);
        };
        let mut heap = VecHeap::new();
        for (key, value) in pairs {
            let key = from_owned(key, &mut heap)?;
            validate_expr(key, guard, bound, trace, depth)?;
            let value = from_owned(value, &mut heap)?;
            validate_expr(value, guard, bound, trace, depth)?;
        }
        return Ok(());
    }
    if term.classify() != TermKind::Tuple {
        return Ok(());
    }
    let elements = tuple(term)?;
    if elements.is_empty() {
        return Err(EtsError::BadArg);
    }
    if elements.len() == 1 && elements[0].classify() == TermKind::Tuple {
        // Port of erts/emulator/beam/erl_db_util.c, OTP-29.1.1 (dmc_tuple).
        return validate_construct(elements[0], bound, trace, depth);
    }
    let Some(name) = atom_name(elements[0]) else {
        return Err(EtsError::BadArg);
    };
    if name == "const" && elements.len() == 2 {
        return Ok(());
    }
    let arity = elements.len() - 1;
    // Port of erts/emulator/beam/erl_db_util.c (guard_tab and dmc_fun), OTP-29.1.1.
    let supported = match name.as_str() {
        "==" | "/=" | "=:=" | "=/=" | ">" | ">=" | "<" | "=<" | "*" | "/" | "xor" | "element"
        | "div" | "rem" | "band" | "bor" | "bxor" | "bsl" | "bsr" | "max" | "min" | "map_get"
        | "is_map_key" => arity == 2,
        "and" | "or" | "andalso" | "andthen" | "orelse" => arity >= 1,
        "+" | "-" => arity == 1 || arity == 2,
        "not" | "is_atom" | "is_float" | "is_number" | "is_tuple" | "is_list" | "is_map"
        | "is_binary" | "is_boolean" | "is_reference" | "is_pid" | "is_port" | "tuple_size"
        | "length" | "abs" | "hd" | "tl" | "is_bitstring" | "size" | "map_size" | "bit_size"
        | "byte_size" | "round" | "trunc" | "float" | "ceil" | "floor" | "bnot" => arity == 1,
        "is_function" => arity == 1 || arity == 2,
        "node" => arity == 0 || arity == 1,
        "is_integer" => arity == 1 || arity == 3,
        "is_record" => arity == 3,
        "binary_part" => arity == 2 || arity == 3,
        "self" => arity == 0,
        "get_tcw" if trace => arity == 0,
        "set_tcw" if trace && !guard => arity == 1,
        "message" | "display" | "silent" if trace && !guard => arity == 1,
        "set_seq_token" if trace && !guard => arity == 2,
        "is_seq_trace" if trace => arity == 0,
        "return_trace" | "exception_trace" | "process_dump" | "caller" | "caller_line"
        | "get_seq_token"
            if trace && !guard =>
        {
            arity == 0
        }
        "current_stacktrace" if trace && !guard => {
            arity == 0 || (arity == 1 && elements[1].as_small().is_some_and(|depth| depth >= 0))
        }
        "enable_trace" | "disable_trace" if trace && !guard => arity == 1 || arity == 2,
        "trace" if trace && !guard => arity == 2 || arity == 3,
        _ => false,
    };
    if !supported {
        return Err(EtsError::BadArg);
    }
    for &argument in &elements[1..] {
        validate_expr(argument, guard, bound, trace, depth)?;
    }
    Ok(())
}

// Port of erts/emulator/beam/erl_db_util.c, OTP-29.1.1 (dmc_tuple).
fn validate_construct(
    term: Term,
    bound: &HashSet<usize>,
    trace: bool,
    depth: usize,
) -> Result<(), EtsError> {
    if depth > MAX_NESTING {
        return Err(EtsError::Term(arinsal_term::TermError::SystemLimit));
    }
    if term.classify() == TermKind::Tuple {
        // Port of erts/emulator/beam/erl_db_util.c (dmc_tuple), OTP-29.1.1: each
        // element of a constructed tuple is an expression of its own.
        for element in tuple(term)? {
            validate_expr(element, false, bound, trace, depth + 1)?;
        }
    } else {
        validate_expr(term, false, bound, trace, depth)?;
    }
    Ok(())
}

impl MatchProgram {
    /// Payload bytes used by OTP's `MatchProg` magic binary for this program.
    // Port of erts/emulator/beam/erl_db_util.c (match program allocation), OTP-29.1.1.
    pub fn erts_magic_payload_size(&self) -> usize {
        // sizeof(MatchProg) - sizeof(UWord) is 56 bytes on macOS arm64.
        56 + self
            .text
            .iter()
            .map(|op| op.erts_word_size())
            .sum::<usize>()
            * 8
    }

    pub(crate) fn runner(&self) -> MatchRunner<'_> {
        MatchRunner {
            program: self,
            state: pam::PamState::new(),
        }
    }

    /// Count external identities retained by a compiled program.
    pub fn external_identity_counts(&self) -> HashMap<(Atom, u32), usize> {
        let mut counts = HashMap::new();
        let mut pending = Vec::new();
        for clause in &self.clauses {
            pending.push(clause.head);
            pending.extend(clause.guards.iter().copied());
            pending.extend(clause.body.iter().copied());
        }
        while let Some(term) = pending.pop() {
            match term.classify() {
                TermKind::Pid | TermKind::Port | TermKind::Ref => match term.identity() {
                    Some(Identity::Pid { node, creation, .. })
                    | Some(Identity::Port { node, creation, .. })
                    | Some(Identity::Ref { node, creation, .. })
                        if node != arinsal_term::atoms::NONAME =>
                    {
                        *counts.entry((node, creation)).or_default() += 1;
                    }
                    _ => {}
                },
                TermKind::Tuple | TermKind::Record | TermKind::List => {
                    if let Some(items) = arinsal_term::term_sequence(term) {
                        pending.extend(items);
                    }
                }
                TermKind::Map => {
                    if let Some(pairs) = arinsal_term::record_map_pairs(term) {
                        pending.extend(pairs.into_iter().flat_map(|(key, value)| [key, value]));
                    }
                }
                _ => {}
            }
        }
        counts
    }

    /// Compile an ETS `match` or `match_object` head without guards.
    pub fn from_pattern(pattern: Term, whole_object: bool) -> Result<Self, EtsError> {
        let mut heap = VecHeap::new();
        let marker = Term::atom(
            global_atoms()
                .intern(if whole_object { "$_" } else { "$$" })
                .map_err(|_| EtsError::BadArg)?,
        );
        // One heap for pattern and specification: the program keeps the pattern terms.
        let pattern = copy_term(pattern, &mut heap)?;
        let mut builder = TermBuilder::new(&mut heap);
        let body = builder.list_from_iter([marker])?;
        let clause = builder.tuple(&[pattern, Term::NIL, body])?;
        let spec = builder.list_from_iter([clause])?;
        Self::compile_in(heap, spec, dmc::DCOMP_TABLE)
    }

    /// Compile a match specification term, rejecting invalid or unsupported syntax.
    pub fn compile(specification: Term) -> Result<Self, EtsError> {
        Self::compile_with_flags(specification, dmc::DCOMP_TABLE)
    }

    /// Compile a tracing match specification, including effectful trace forms.
    pub fn compile_trace(specification: Term) -> Result<Self, EtsError> {
        Self::compile_with_flags(
            specification,
            dmc::DCOMP_TRACE | dmc::DCOMP_CALL_TRACE | dmc::DCOMP_ALLOW_TRACE_OPS,
        )
    }

    /// Compile a `send` or `receive` event match specification.
    ///
    /// `send` patterns drop the call-only forms; `receive` patterns also drop the
    /// effectful trace forms.
    // Port of erts/emulator/beam/erl_db_util.c (erts_match_set_compile_trace flags),
    // OTP-29.1.1; `check_trace` in the compiler enforces them.
    pub fn compile_trace_event(specification: Term, receive: bool) -> Result<Self, EtsError> {
        Self::compile_with_flags(
            specification,
            if receive {
                dmc::DCOMP_TRACE
            } else {
                dmc::DCOMP_TRACE | dmc::DCOMP_ALLOW_TRACE_OPS
            },
        )
    }

    /// Compile for `erlang:match_spec_test/3`: no process state may change.
    fn compile_test(specification: Term, trace: bool) -> Result<Self, EtsError> {
        Self::compile_with_flags(
            specification,
            dmc::DCOMP_FAKE_DESTRUCTIVE
                | if trace {
                    dmc::DCOMP_TRACE | dmc::DCOMP_CALL_TRACE | dmc::DCOMP_ALLOW_TRACE_OPS
                } else {
                    dmc::DCOMP_TABLE
                },
        )
    }

    fn compile_with_flags(specification: Term, cflags: u32) -> Result<Self, EtsError> {
        let mut heap = VecHeap::new();
        let specification = copy_term(specification, &mut heap)?;
        Self::compile_in(heap, specification, cflags)
    }

    /// Compile a specification that already lives in `heap`, which the program then owns.
    // Port of erts/emulator/beam/erl_db_util.c (db_match_set_compile), OTP-29.1.1.
    fn compile_in(mut heap: VecHeap, specification: Term, cflags: u32) -> Result<Self, EtsError> {
        let trace = cflags & dmc::DCOMP_TRACE != 0;
        let mut clauses = Vec::new();
        let mut matches = Vec::new();
        let mut guard_exprs = Vec::new();
        let mut body_exprs = Vec::new();
        let mut is_prefix = Vec::new();
        for clause in proper_list(specification)? {
            let triple = tuple(clause)?;
            if triple.len() != 3 {
                return Err(EtsError::BadArg);
            }
            let guards = proper_list(triple[1])?;
            let body = proper_list(triple[2])?;
            if body.is_empty() && !trace {
                return Err(EtsError::BadArg);
            }
            let mut bound = HashSet::new();
            head_variables(triple[0], &mut bound)?;
            for &guard in &guards {
                validate_expr(guard, true, &bound, trace, 0)?;
            }
            for &expr in &body {
                validate_expr(expr, false, &bound, trace, 0)?;
            }
            // When tracing, a list head is converted to a tuple and matched against the
            // argument array; a '_' tail makes it a prefix match.
            let mut prefix = false;
            let head = if trace && matches!(triple[0].classify(), TermKind::List | TermKind::Nil) {
                let mut elements = Vec::new();
                let mut rest = triple[0];
                while let Some((head, tail)) = cons(rest) {
                    elements.push(head);
                    rest = tail;
                }
                if atom_name(rest).as_deref() == Some("_") {
                    prefix = true;
                } else if rest != Term::NIL {
                    return Err(EtsError::BadArg);
                }
                TermBuilder::new(&mut heap).tuple(&elements)?
            } else {
                triple[0]
            };
            matches.push(head);
            guard_exprs.push(triple[1]);
            body_exprs.push(triple[2]);
            is_prefix.push(prefix);
            clauses.push(Clause {
                head: triple[0],
                guards,
                body,
            });
        }
        if clauses.is_empty() {
            return Err(EtsError::BadArg);
        }
        let compiled = dmc::db_match_compile(
            &mut heap,
            &matches,
            &guard_exprs,
            &body_exprs,
            cflags,
            &is_prefix,
        )?;
        Ok(Self {
            heap,
            clauses,
            text: compiled.text,
            num_bindings: compiled.num_bindings,
            stack_need: compiled.stack_need,
            id: NEXT_PROGRAM_ID.fetch_add(1, AtomicOrdering::Relaxed),
            trace,
        })
    }

    /// Opaque reference for the compiled program in a continuation term.
    pub fn reference<H: HeapAlloc>(&self, dst: &mut H) -> Result<Term, EtsError> {
        Ok(TermBuilder::new(dst).local_ref([
            0x4554_534d,
            self.id as u32,
            (self.id >> 32) as u32,
        ])?)
    }

    pub(crate) fn matches_reference(&self, term: Term) -> bool {
        matches!(term.identity(), Some(arinsal_term::Identity::Ref { ids, .. }) if ids == [0x4554_534d, self.id as u32, (self.id >> 32) as u32])
    }

    /// Return the stable identifier carried by this compiled program's reference.
    pub fn id(&self) -> u64 {
        self.id
    }

    /// Decode a reference created by `reference`.
    pub fn reference_id(term: Term) -> Option<u64> {
        match term.identity()? {
            arinsal_term::Identity::Ref { ids, .. } if ids.len() == 3 && ids[0] == 0x4554_534d => {
                Some(ids[1] as u64 | ((ids[2] as u64) << 32))
            }
            _ => None,
        }
    }

    /// Whether a term is a reference produced by a compiled match program.
    pub fn is_compiled_reference(term: Term) -> bool {
        Self::reference_id(term).is_some()
    }

    /// Run the first matching clause and copy its result into the caller's heap.
    pub fn run<H: HeapAlloc>(&self, object: Term, dst: &mut H) -> Result<Option<Term>, EtsError> {
        self.run_with_context(object, dst, &EmptyContext)
    }

    /// Run `ets:match_spec_run/2` over a list of objects.
    pub fn run_many<H: HeapAlloc>(
        &self,
        objects: &[Term],
        dst: &mut H,
    ) -> Result<Vec<Term>, EtsError> {
        let mut results = Vec::new();
        for &object in objects {
            if let Some(result) = self.run(object, dst)? {
                results.push(result);
            }
        }
        Ok(results)
    }

    /// Run a match program with process or tracing context supplied by the VM.
    pub fn run_with_context<H: HeapAlloc, C: MatchContext>(
        &self,
        object: Term,
        dst: &mut H,
        context: &C,
    ) -> Result<Option<Term>, EtsError> {
        // The match pseudo process (heap, stack, variables) is cached per thread like erts's
        // `match_pseudo_process`; creating one per object dominated select over big tables.
        thread_local! {
            static STATE: Cell<Option<Box<pam::PamState>>> = const { Cell::new(None) };
        }
        let mut state = STATE
            .take()
            .unwrap_or_else(|| Box::new(pam::PamState::new()));
        let result = self.run_program(object, dst, context, &mut state, None);
        if state.heap.used_words() != 0 {
            state.heap.reset(128);
        }
        STATE.set(Some(state));
        result
    }

    fn run_program<H: HeapAlloc, C: MatchContext>(
        &self,
        object: Term,
        dst: &mut H,
        context: &C,
        state: &mut pam::PamState,
        object_size: Option<KnownObject<'_>>,
    ) -> Result<Option<Term>, EtsError> {
        let _keep_live = &self.heap;
        let outcome = if self.trace {
            // The trace argument list is the array the program matches.
            let array = proper_list(object)?;
            pam::db_prog_match(self, state, Term::NIL, &array, context)?
        } else {
            pam::db_prog_match(self, state, object, &[], context)?
        };
        let Some(outcome) = outcome else {
            return Ok(None);
        };
        if self.trace && outcome.returned {
            // erts_call_trace reads the program's return value; the VM's context takes it as
            // the `{message, Term}` payload.
            let _ = context.trace_operation("message", &[outcome.value]);
        }
        let result = if outcome.value == object {
            match object_size {
                // Port of erts/emulator/beam/erl_db_util.c (db_prog_match, `$_` of the
                // object itself: copy_shallow of the stored block), OTP-29.1.1.
                Some(KnownObject {
                    block: Some(block), ..
                }) => copy_shallow(outcome.value, block, dst)?,
                Some(known) => copy_struct(outcome.value, dst, known.size)?,
                None => copy_term(outcome.value, dst)?,
            }
        } else {
            copy_term(outcome.value, dst)?
        };
        Ok(Some(result))
    }

    /// Infer a key interval only when one clause has direct key comparisons.
    // Port of erts/emulator/beam/erl_db_util.c, OTP-29.1.1 (db_getkey).
    pub fn key_bounds(&self, keypos: usize) -> Option<KeyBounds> {
        let mut bounds = self.guard_bounds(keypos).unwrap_or(KeyBounds {
            lower: None,
            upper: None,
            least: None,
            most: None,
        });
        if let Some((least, most)) = self.head_key_range(keypos) {
            bounds.least = Some(least);
            bounds.most = Some(most);
        }
        (bounds.lower.is_some()
            || bounds.upper.is_some()
            || bounds.least.is_some()
            || bounds.most.is_some())
        .then_some(bounds)
    }

    /// How the clause heads bound the key of an ordered table.
    // Port of erts/emulator/beam/erl_db_tree.c, analyze_pattern and key_boundness, OTP-29.1.1.
    pub(crate) fn tree_keys(&self, keypos: usize) -> TreeKeys {
        const UNBOUND: u8 = 0;
        const PARTIAL: u8 = 1;
        const BOUND: u8 = 2;
        const IMPOSSIBLE: u8 = 3;
        let mut boundness = IMPOSSIBLE;
        let mut least: Option<Term> = None;
        let mut most: Option<Term> = None;
        for clause in &self.clauses {
            let head = clause.head;
            let (kind, key) = if is_match_variable(head) {
                (UNBOUND, None)
            } else {
                match keypos
                    .checked_sub(1)
                    .and_then(|index| tuple_view(head)?.get(index))
                {
                    None => (IMPOSSIBLE, None),
                    Some(key) if is_fully_bound(key) => (BOUND, Some(key)),
                    Some(key) if !is_match_variable(key) && !has_map(key) => (PARTIAL, Some(key)),
                    Some(_) => (UNBOUND, None),
                }
            };
            if let Some(key) = key {
                if least.is_none_or(|l| partly_bound_can_match_lesser(key, l)) {
                    least = Some(key);
                }
                if most.is_none_or(|m| partly_bound_can_match_greater(key, m)) {
                    most = Some(key);
                }
            }
            boundness = boundness.min(kind);
        }
        match (boundness, least, most) {
            (IMPOSSIBLE, ..) => TreeKeys::Impossible,
            (BOUND, Some(least), Some(most)) if exact_eq(least, most) => TreeKeys::Bound,
            (BOUND | PARTIAL, Some(least), Some(most)) => TreeKeys::Partial { least, most },
            _ => TreeKeys::Unbound,
        }
    }

    /// How each clause head names the key, as `analyze_pattern` classifies it for a hash table.
    // Port of erts/emulator/beam/erl_db_hash.c, analyze_pattern, OTP-29.1.1.
    pub(crate) fn head_keys(&self, keypos: usize) -> Vec<HeadKey> {
        self.clauses
            .iter()
            .map(|clause| {
                let head = clause.head;
                if is_match_variable(head) {
                    return HeadKey::Variable;
                }
                let key = keypos
                    .checked_sub(1)
                    .and_then(|index| tuple_view(head)?.get(index));
                match key {
                    None => HeadKey::Missing,
                    Some(key) if is_fully_bound(key) => HeadKey::Bound(key),
                    Some(_) => HeadKey::Unbound,
                }
            })
            .collect()
    }

    /// Return the key pattern when the sole clause binds it completely.
    // Port of erts/emulator/beam/erl_db_hash.c (analyze_pattern) and
    // erl_db_util.c (db_is_fully_bound), OTP-29.1.1.
    pub fn exact_key_pattern(&self, keypos: usize) -> Option<Term> {
        let [clause] = self.clauses.as_slice() else {
            return None;
        };
        let items = tuple_view(clause.head)?;
        let key = items.get(keypos.checked_sub(1)?)?;
        is_fully_bound(key).then_some(key)
    }

    /// Least and most key pattern over all clause heads when the keys are bound or
    /// partly bound in every clause that can match at all.
    // Port of erts/emulator/beam/erl_db_tree.c (analyze_pattern) and :3828
    // (key_boundness), OTP-29.1.1.
    fn head_key_range(&self, keypos: usize) -> Option<(Term, Term)> {
        let (mut least, mut most): (Option<Term>, Option<Term>) = (None, None);
        let mut ranged = false;
        for clause in &self.clauses {
            let head = clause.head;
            if is_match_variable(head) {
                return None;
            }
            let Some(items) = tuple_view(head) else {
                continue;
            };
            let Some(key) = items.get(keypos.checked_sub(1)?) else {
                continue;
            };
            if !is_fully_bound(key) && (is_match_variable(key) || has_map(key)) {
                return None;
            }
            ranged = true;
            if least.is_none_or(|l| partly_bound_can_match_lesser(key, l)) {
                least = Some(key);
            }
            if most.is_none_or(|m| partly_bound_can_match_greater(key, m)) {
                most = Some(key);
            }
        }
        if !ranged {
            return None;
        }
        Some((least?, most?))
    }

    fn guard_bounds(&self, keypos: usize) -> Option<KeyBounds> {
        let [clause] = self.clauses.as_slice() else {
            return None;
        };
        let head = tuple(clause.head).ok()?;
        let key_var = variable(*head.get(keypos - 1)?)?;
        let mut bounds = KeyBounds {
            lower: None,
            upper: None,
            least: None,
            most: None,
        };
        for &guard in &clause.guards {
            let expr = tuple(guard).ok()?;
            if expr.len() != 3 {
                continue;
            }
            let op = atom_name(expr[0])?;
            if variable(expr[1]) != Some(key_var)
                || variable(expr[2]).is_some()
                || expr[2].classify() == TermKind::Tuple
            {
                continue;
            }
            match op.as_str() {
                ">" => bounds.lower = Some((expr[2], false)),
                ">=" => bounds.lower = Some((expr[2], true)),
                "<" => bounds.upper = Some((expr[2], false)),
                "=<" => bounds.upper = Some((expr[2], true)),
                _ => {}
            }
        }
        if bounds.lower.is_some() || bounds.upper.is_some() {
            Some(bounds)
        } else {
            None
        }
    }

    /// Whether every compiled clause reconstructs the matched object with the same key.
    pub(crate) fn keeps_key(&self, keypos: usize) -> bool {
        // Port of erts/emulator/beam/erl_db_util.c, OTP-29.1.1 (db_match_keeps_key).
        self.clauses.iter().all(|clause| {
            if clause.body.len() != 1 {
                return false;
            }
            if atom_name(clause.body[0]).as_deref() == Some("$_") {
                return true;
            }
            let Ok(match_key) = key_at(clause.head, keypos) else {
                return false;
            };
            let Ok(body_parts) = tuple(clause.body[0]) else {
                return false;
            };
            let (replacement, constant) =
                if body_parts.len() == 2 && atom_name(body_parts[0]).as_deref() == Some("const") {
                    (body_parts[1], true)
                } else if body_parts.len() == 1 && body_parts[0].classify() == TermKind::Tuple {
                    (body_parts[0], false)
                } else {
                    return false;
                };
            let Ok(replacement_key) = key_at(replacement, keypos) else {
                return false;
            };
            if match_eq_body(match_key, replacement_key, constant) {
                return true;
            }
            if constant {
                return false;
            }
            let Ok(element) = tuple(replacement_key) else {
                return false;
            };
            element.len() == 3
                && atom_name(element[0]).as_deref() == Some("element")
                && element[1].as_small() == i64::try_from(keypos).ok()
                && atom_name(element[2]).as_deref() == Some("$_")
        })
    }

    /// Return the constant result when the inferred key interval proves a clause matches.
    // This shortcut applies only when the inferred key interval covers every match condition.
    pub(crate) fn range_result(&self, keypos: usize) -> Option<Term> {
        let [clause] = self.clauses.as_slice() else {
            return None;
        };
        let head = tuple(clause.head).ok()?;
        let key_index = keypos.checked_sub(1)?;
        let key_variable = variable(*head.get(key_index)?)?;
        let mut seen = HashSet::from([key_variable]);
        if head.iter().enumerate().any(|(index, term)| {
            if index == key_index {
                return false;
            }
            match variable(*term) {
                Some(index) => !seen.insert(index),
                None => atom_name(*term).as_deref() != Some("_"),
            }
        }) || clause.guards.len() != 1
        {
            return None;
        }
        let guard = tuple(clause.guards[0]).ok()?;
        if guard.len() != 3
            || variable(guard[1]) != Some(key_variable)
            || variable(guard[2]).is_some()
            || atom_name(guard[0]).is_none_or(|op| !matches!(op.as_str(), ">" | ">=" | "<" | "=<"))
            || clause.body.len() != 1
            || atom_name(clause.body[0]).as_deref() != Some("true")
        {
            return None;
        }
        self.guard_bounds(keypos)?;
        Some(Term::atom(global_atoms().intern("true").ok()?))
    }
}

impl MatchRunner<'_> {
    pub(crate) fn run<H: HeapAlloc>(
        &mut self,
        object: Term,
        dst: &mut H,
    ) -> Result<Option<Term>, EtsError> {
        self.run_with_context(object, dst, &EmptyContext)
    }

    pub(crate) fn run_with_context<H: HeapAlloc, C: MatchContext>(
        &mut self,
        object: Term,
        dst: &mut H,
        context: &C,
    ) -> Result<Option<Term>, EtsError> {
        self.run_with_context_sized(object, dst, context, None)
    }

    /// Run a stored ETS object, reusing its known size if the clause returns that object.
    // Port of erts/emulator/beam/erl_db_util.h:425 (db_copy_object_from_ets), OTP-29.1.1.
    pub(crate) fn run_with_context_sized<H: HeapAlloc, C: MatchContext>(
        &mut self,
        object: Term,
        dst: &mut H,
        context: &C,
        object_size: Option<KnownObject<'_>>,
    ) -> Result<Option<Term>, EtsError> {
        let result = self
            .program
            .run_program(object, dst, context, &mut self.state, object_size);
        if self.state.heap.used_words() != 0 {
            self.state.heap.reset(128);
        }
        result
    }

    pub(crate) fn run_sized<H: HeapAlloc>(
        &mut self,
        object: Term,
        dst: &mut H,
        object_size: Option<KnownObject<'_>>,
    ) -> Result<Option<Term>, EtsError> {
        self.run_with_context_sized(object, dst, &EmptyContext, object_size)
    }
}

fn key_at(term: Term, keypos: usize) -> Result<Term, EtsError> {
    tuple(term)?
        .get(keypos.checked_sub(1).ok_or(EtsError::BadArg)?)
        .copied()
        .ok_or(EtsError::BadArg)
}

fn match_eq_body(match_term: Term, body_term: Term, constant: bool) -> bool {
    let (Ok(match_owned), Ok(body_owned)) = (to_owned(match_term), to_owned(body_term)) else {
        return false;
    };
    owned_match_eq_body(&match_owned, &body_owned, constant)
}

/// Whether the body term rebuilds exactly the matched term.
// Port of erts/emulator/beam/erl_db_util.c (db_match_eq_body), OTP-29.1.1.
fn owned_match_eq_body(a: &OwnedTerm, b: &OwnedTerm, constant: bool) -> bool {
    match b {
        OwnedTerm::List { .. } => {
            let (Some((a_head, a_tail)), Some((b_head, b_tail))) = (uncons(a), uncons(b)) else {
                return false;
            };
            owned_match_eq_body(a_head, b_head, constant)
                && owned_match_eq_body(&a_tail, &b_tail, constant)
        }
        OwnedTerm::Tuple(body) => {
            let mut body = body.as_slice();
            if !constant {
                match body {
                    [OwnedTerm::Tuple(inner)] => body = inner.as_slice(),
                    [OwnedTerm::Atom(name), value] if name == "const" => {
                        return owned_match_eq_body(a, value, true);
                    }
                    _ => return false,
                }
            }
            let OwnedTerm::Tuple(head) = a else {
                return false;
            };
            head.len() == body.len()
                && head
                    .iter()
                    .zip(body)
                    .all(|(left, right)| owned_match_eq_body(left, right, constant))
        }
        OwnedTerm::Map(_) => false,
        OwnedTerm::Atom(name) => {
            a == b
                && !matches!(name.as_str(), "_" | "$$" | "$_")
                && !(constant && owned_is_variable(name))
        }
        _ => a == b,
    }
}

/// `db_is_variable(a) >= 0`: an atom `'$N'`.
fn owned_is_variable(name: &str) -> bool {
    name.strip_prefix('$').is_some_and(|digits| {
        !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit())
    })
}

/// Split a list into its first cell's head and tail.
fn uncons(term: &OwnedTerm) -> Option<(&OwnedTerm, OwnedTerm)> {
    let OwnedTerm::List { elems, tail } = term else {
        return None;
    };
    let (head, rest) = elems.split_first()?;
    let rest = if rest.is_empty() {
        (**tail).clone()
    } else {
        OwnedTerm::List {
            elems: rest.to_vec(),
            tail: tail.clone(),
        }
    };
    Some((head, rest))
}

fn bool_atoms() -> (Atom, Atom) {
    static ATOMS: std::sync::OnceLock<(Atom, Atom)> = std::sync::OnceLock::new();
    *ATOMS.get_or_init(|| {
        let atoms = global_atoms();
        (
            atoms.intern("true").unwrap(),
            atoms.intern("false").unwrap(),
        )
    })
}

fn bool_term(value: bool) -> Term {
    truth(value)
}

fn truth(value: bool) -> Term {
    let (true_atom, false_atom) = bool_atoms();
    Term::atom(if value { true_atom } else { false_atom })
}

fn boolean(value: Term) -> Option<bool> {
    let atom = value.as_atom()?;
    let (true_atom, false_atom) = bool_atoms();
    if atom == true_atom {
        Some(true)
    } else if atom == false_atom {
        Some(false)
    } else {
        None
    }
}

fn integer(value: Term) -> Option<BigInt> {
    if let Some(small) = value.as_small() {
        return Some(BigInt::from(small));
    }
    // SAFETY: the match source or scratch heap owns this boxed value.
    unsafe { value.big_ref() }.map(|number| number.to_bigint())
}

fn float(value: Term) -> Option<f64> {
    // SAFETY: the match source or scratch heap owns this boxed value.
    unsafe { value.float_ref() }
        .map(|number| number.get())
        .or_else(|| integer(value)?.to_f64())
}

fn boxed_int(value: BigInt, scratch: &mut VecHeap) -> Result<Term, EtsError> {
    Ok(TermBuilder::new(scratch).int_from_bigint(&value)?)
}

fn boxed_float(value: f64, scratch: &mut VecHeap) -> Result<Term, EtsError> {
    if !value.is_finite() {
        return Err(EtsError::BadArg);
    }
    Ok(TermBuilder::new(scratch).float(value)?)
}

fn integral_float_to_bigint(value: f64) -> Result<BigInt, EtsError> {
    if !value.is_finite() {
        return Err(EtsError::BadArg);
    }
    let bits = value.to_bits();
    let exponent = ((bits >> 52) & 0x7ff) as i32 - 1023;
    if exponent < 0 {
        return Ok(BigInt::zero());
    }
    let mantissa = (bits & ((1_u64 << 52) - 1)) | (1_u64 << 52);
    let magnitude = if exponent >= 52 {
        BigInt::from(mantissa) << (exponent - 52) as usize
    } else {
        BigInt::from(mantissa >> (52 - exponent))
    };
    Ok(if bits >> 63 != 0 {
        -magnitude
    } else {
        magnitude
    })
}

fn map_get(key: Term, map: Term, _scratch: &mut VecHeap) -> Result<Option<Term>, EtsError> {
    if map.classify() != TermKind::Map {
        return Err(EtsError::BadArg);
    }
    // SAFETY: the match source or scratch heap owns the map and its keys.
    if let Some(flat) = unsafe { map.flatmap_ref() } {
        return Ok(flat.get(key));
    }
    // Port of erts/emulator/beam/erl_map.c (erts_maps_get), OTP-29.1.1.
    // Keep HAMT lookups logarithmic instead of decoding and scanning the whole map per key.
    arinsal_maps::get(map, key).map_err(|_| EtsError::BadArg)
}

// Port of erts/emulator/beam/erl_db_util.c, OTP-29.1.1 (dmc_expr).
/// Evaluate an already-argument-evaluated guard BIF.
// Port of erts/emulator/beam/erl_db_util.c (guard_tab), OTP-29.1.1.
fn builtin(name: &str, args: &[Term], scratch: &mut VecHeap) -> Result<Term, EtsError> {
    let a = args[0];
    let result = match name {
        // Port of erts/emulator/beam/erl_db_util.c, OTP-29.1.1 (matchCmp).
        "==" => truth(cmp(a, args[1]) == Ordering::Equal),
        "/=" => truth(cmp(a, args[1]) != Ordering::Equal),
        // Port of erts/emulator/beam/erl_db_util.c, OTP-29.1.1 (matchEq).
        "=:=" => truth(exact_eq(a, args[1])),
        "=/=" => truth(!exact_eq(a, args[1])),
        ">" => truth(cmp(a, args[1]) == Ordering::Greater),
        ">=" => truth(cmp(a, args[1]) != Ordering::Less),
        "<" => truth(cmp(a, args[1]) == Ordering::Less),
        "=<" => truth(cmp(a, args[1]) != Ordering::Greater),
        "+" | "-" | "*" => {
            if args.len() == 1 {
                if name == "+" {
                    // Port of erts/emulator/beam/erl_db_util.c (guard_tab), OTP-29.1.1:
                    // the unary plus BIF accepts numbers only, even though it returns them intact.
                    if integer(a).is_some() || float(a).is_some() {
                        a
                    } else {
                        return Err(EtsError::BadArg);
                    }
                } else if let Some(n) = integer(a) {
                    boxed_int(-n, scratch)?
                } else {
                    boxed_float(-float(a).ok_or(EtsError::BadArg)?, scratch)?
                }
            } else if let (Some(lhs), Some(rhs)) = (integer(a), integer(args[1])) {
                boxed_int(
                    match name {
                        "+" => lhs + rhs,
                        "-" => lhs - rhs,
                        _ => lhs * rhs,
                    },
                    scratch,
                )?
            } else {
                let lhs = float(a).ok_or(EtsError::BadArg)?;
                let rhs = float(args[1]).ok_or(EtsError::BadArg)?;
                boxed_float(
                    match name {
                        "+" => lhs + rhs,
                        "-" => lhs - rhs,
                        _ => lhs * rhs,
                    },
                    scratch,
                )?
            }
        }
        "/" => boxed_float(
            float(a).ok_or(EtsError::BadArg)? / float(args[1]).ok_or(EtsError::BadArg)?,
            scratch,
        )?,
        "not" => truth(!boolean(a).ok_or(EtsError::BadArg)?),
        // Port of erts/emulator/beam/erl_db_util.c, OTP-29.1.1 (dmc_and).
        "and" | "or" => {
            let mut result = name == "and";
            for &argument in args {
                let value = boolean(argument).ok_or(EtsError::BadArg)?;
                if name == "and" {
                    result &= value;
                } else {
                    result |= value;
                }
            }
            truth(result)
        }
        "xor" => {
            truth(boolean(a).ok_or(EtsError::BadArg)? ^ boolean(args[1]).ok_or(EtsError::BadArg)?)
        }
        // Port of erts/emulator/beam/erl_db_util.c, OTP-29.1.1 (guard_tab type tests).
        "is_atom" => truth(a.classify() == TermKind::Atom),
        "is_integer" if args.len() == 1 => truth(integer(a).is_some()),
        "is_integer" => {
            let lower = integer(args[1]).ok_or(EtsError::BadArg)?;
            let upper = integer(args[2]).ok_or(EtsError::BadArg)?;
            truth(integer(a).is_some_and(|value| lower <= value && value <= upper))
        }
        "is_float" => {
            truth(a.classify() == TermKind::Number && a.header().is_some_and(|h| h & 63 == 24))
        }
        "is_number" => truth(a.classify() == TermKind::Number),
        "is_tuple" => truth(a.classify() == TermKind::Tuple),
        "is_list" => truth(matches!(a.classify(), TermKind::List | TermKind::Nil)),
        "is_bitstring" => truth(a.classify() == TermKind::Bitstring),
        "is_map" => truth(a.classify() == TermKind::Map),
        "is_binary" => truth(
            a.classify() == TermKind::Bitstring && {
                // SAFETY: the source or scratch heap retains the binary allocation.
                unsafe { a.binary_ref() }.is_some_and(|b| b.bit_len().is_multiple_of(8))
            },
        ),
        "is_boolean" => truth(boolean(a).is_some()),
        "is_reference" => truth(a.classify() == TermKind::Ref),
        "is_pid" => truth(a.classify() == TermKind::Pid),
        "is_port" => truth(a.classify() == TermKind::Port),
        "is_function" if args.len() == 1 => truth(a.classify() == TermKind::Fun),
        "is_function" => {
            let arity = integer(args[1]).ok_or(EtsError::BadArg)?;
            if arity < BigInt::from(0) {
                return Err(EtsError::BadArg);
            }
            // SAFETY: the match source or scratch heap owns the fun.
            truth(unsafe { a.fun_ref() }.is_some_and(|fun| match fun {
                arinsal_term::FunRef::Local { entry, .. } => BigInt::from(entry.arity) == arity,
                arinsal_term::FunRef::Export { entry } => BigInt::from(entry.arity) == arity,
            }))
        }
        "is_record" => {
            if args[1].as_atom().is_none()
                || (args[2].as_atom().is_none() && args[2].as_small().is_none())
            {
                return Err(EtsError::BadArg);
            }
            truth(
                a.classify() == TermKind::Tuple
                    && args[2].as_small().is_some_and(|size| {
                        size >= 1
                            && tuple(a).is_ok_and(|elements| {
                                elements.len() == size as usize && exact_eq(elements[0], args[1])
                            })
                    }),
            )
        }
        "tuple_size" => Term::small(tuple(a)?.len() as i64).ok_or(EtsError::BadArg)?,
        "size" => match a.classify() {
            TermKind::Tuple => Term::small(tuple(a)?.len() as i64).ok_or(EtsError::BadArg)?,
            TermKind::Bitstring => {
                // SAFETY: the source or scratch heap retains the binary allocation.
                let bits = unsafe { a.binary_ref() }.ok_or(EtsError::BadArg)?.bit_len();
                if !bits.is_multiple_of(8) {
                    return Err(EtsError::BadArg);
                }
                Term::small((bits / 8) as i64).ok_or(EtsError::BadArg)?
            }
            _ => return Err(EtsError::BadArg),
        },
        "map_size" => {
            if a.classify() != TermKind::Map {
                return Err(EtsError::BadArg);
            }
            // SAFETY: map heads store their entry count in word one and remain live.
            let size = unsafe { *a.raw_ptr().add(1) };
            Term::small(size as i64).ok_or(EtsError::BadArg)?
        }
        "map_get" => map_get(a, args[1], scratch)?.ok_or(EtsError::BadArg)?,
        "is_map_key" => truth(map_get(a, args[1], scratch)?.is_some()),
        "byte_size" | "bit_size" => {
            // SAFETY: the match source or scratch heap owns the bitstring.
            let bits = unsafe { a.binary_ref() }.ok_or(EtsError::BadArg)?.bit_len();
            if name == "byte_size" && !bits.is_multiple_of(8) {
                return Err(EtsError::BadArg);
            }
            boxed_int(
                BigInt::from(if name == "bit_size" { bits } else { bits / 8 }),
                scratch,
            )?
        }
        "length" => Term::small(proper_list(a)?.len() as i64).ok_or(EtsError::BadArg)?,
        "hd" => {
            // SAFETY: the source or scratch heap retains the cons cell.
            unsafe { a.cons_ref() }.ok_or(EtsError::BadArg)?.0
        }
        "tl" => {
            // SAFETY: the source or scratch heap retains the cons cell.
            unsafe { a.cons_ref() }.ok_or(EtsError::BadArg)?.1
        }
        "max" => {
            if cmp(a, args[1]) == Ordering::Less {
                args[1]
            } else {
                a
            }
        }
        "min" => {
            if cmp(a, args[1]) == Ordering::Greater {
                args[1]
            } else {
                a
            }
        }
        "div" | "rem" => {
            let lhs = integer(a).ok_or(EtsError::BadArg)?;
            let rhs = integer(args[1]).ok_or(EtsError::BadArg)?;
            if rhs.is_zero() {
                return Err(EtsError::BadArg);
            }
            boxed_int(if name == "div" { lhs / rhs } else { lhs % rhs }, scratch)?
        }
        "band" | "bor" | "bxor" => {
            let lhs = integer(a).ok_or(EtsError::BadArg)?;
            let rhs = integer(args[1]).ok_or(EtsError::BadArg)?;
            boxed_int(
                match name {
                    "band" => lhs & rhs,
                    "bor" => lhs | rhs,
                    _ => lhs ^ rhs,
                },
                scratch,
            )?
        }
        "bnot" => boxed_int(!integer(a).ok_or(EtsError::BadArg)?, scratch)?,
        "bsl" | "bsr" => {
            let lhs = integer(a).ok_or(EtsError::BadArg)?;
            let shift = integer(args[1])
                .and_then(|n| n.to_i64())
                .ok_or(EtsError::BadArg)?;
            let shift = if name == "bsr" { -shift } else { shift };
            if shift.unsigned_abs() > 1_000_000 {
                return Err(EtsError::BadArg);
            }
            boxed_int(
                if shift >= 0 {
                    lhs << shift as usize
                } else {
                    lhs >> (-shift) as usize
                },
                scratch,
            )?
        }
        "abs" => {
            if let Some(value) = integer(a) {
                boxed_int(value.abs(), scratch)?
            } else {
                boxed_float(float(a).ok_or(EtsError::BadArg)?.abs(), scratch)?
            }
        }
        "float" => boxed_float(float(a).ok_or(EtsError::BadArg)?, scratch)?,
        "round" | "trunc" | "ceil" | "floor" => {
            if let Some(value) = integer(a) {
                boxed_int(value, scratch)?
            } else {
                let value = float(a).ok_or(EtsError::BadArg)?;
                let rounded = match name {
                    "round" => value.round(),
                    "trunc" => value.trunc(),
                    "ceil" => value.ceil(),
                    _ => value.floor(),
                };
                boxed_int(integral_float_to_bigint(rounded)?, scratch)?
            }
        }
        // Port of erts/emulator/beam/erl_db_util.c, OTP-29.1.1 (guard_tab element/2).
        "element" => {
            let index = a.as_small().ok_or(EtsError::BadArg)?;
            if index <= 0 {
                return Err(EtsError::BadArg);
            }
            *tuple(args[1])?
                .get(index as usize - 1)
                .ok_or(EtsError::BadArg)?
        }
        "binary_part" => {
            let (start, length) = if args.len() == 2 {
                let pair = tuple(args[1])?;
                if pair.len() != 2 {
                    return Err(EtsError::BadArg);
                }
                (integer(pair[0]), integer(pair[1]))
            } else {
                (integer(args[1]), integer(args[2]))
            };
            let start = start.and_then(|n| n.to_i64()).ok_or(EtsError::BadArg)?;
            let length = length.and_then(|n| n.to_i64()).ok_or(EtsError::BadArg)?;
            let actual_start = start.checked_add(length.min(0)).ok_or(EtsError::BadArg)?;
            if actual_start < 0 {
                return Err(EtsError::BadArg);
            }
            let length = length.unsigned_abs() as usize;
            let start_bits = (actual_start as usize)
                .checked_mul(8)
                .ok_or(EtsError::BadArg)?;
            let length_bits = length.checked_mul(8).ok_or(EtsError::BadArg)?;
            TermBuilder::new(scratch).sub_binary(a, start_bits, length_bits)?
        }
        _ => return Err(EtsError::Unsupported("match specification expression")),
    };
    Ok(result)
}

/// Whether `term` is a boxed float.
fn is_float_term(term: Term) -> bool {
    term.classify() == TermKind::Number && term.header().is_some_and(|h| h & 63 == 24)
}

/// The IEEE bits of a float term, as `matchEqFloat` compares them.
fn float_bits(term: Term) -> Result<u64, EtsError> {
    float(term).map(f64::to_bits).ok_or(EtsError::BadArg)
}
