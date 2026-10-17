//! List BIFs. The per-element loops follow `erl_bif_lists.c` and `erl_bif_guard.c`.
//!
//! `erlang:'++'/2`, `erlang:'--'/2`, `lists:member/2`, `lists:keyfind/3`
//! (and keymember/keysearch), and `lists:reverse/2` stop on the same reduction
//! budget as erts and resume through the same continuations.

use arinsal_term::{
    ConsHeapChain, HeapAlloc, HeapReservation, Term, TermBuilder, atoms, exact_eq, loose_eq,
};

#[path = "rbtree.rs"]
mod rbtree;

use crate::pure::{bool_term, integer, tuple_build};
use crate::{BifError, Ctx};
use rbtree::RbTree;

const BADARG: BifError = BifError::BADARG;

/// CAR and CDR of a tagged list word.
///
/// A list tag of 1 places the head at `tagged - 1` and the tail at `tagged + 7`
/// (`CAR`/`CDR`/`list_val` in erl_term.h). The caller is already in `unsafe`.
macro_rules! car_cdr {
    ($bits:expr) => {{
        let base = ($bits) as *const u8;
        (
            base.offset(-1).cast::<u64>().read_unaligned(),
            base.add(7).cast::<u64>().read_unaligned(),
        )
    }};
}

/// `is_list`: primary tag bit 1 is clear only for a cons (`tbz` in the erts loops).
#[inline(always)]
fn is_list_bits(bits: u64) -> bool {
    bits & 2 == 0
}

pub(super) fn lookup<V: crate::BifTableVisitor>(
    module: &str,
    name: &str,
    arity: u8,
    v: &mut V,
) -> Option<V::Output> {
    let f = match (module, name, arity) {
        ("erlang", "length", 1) => v.entry::<bodies::length>(),
        ("erlang", "++" | "append", 2) => v.entry::<bodies::append>(),
        ("erlang", "--" | "subtract", 2) => v.entry::<bodies::subtract>(),
        ("lists", "reverse", 2) => v.entry::<bodies::reverse>(),
        ("lists", "member", 2) => v.entry::<bodies::member>(),
        ("lists", "keyfind", 3) => v.entry::<bodies::keyfind>(),
        ("lists", "keymember", 3) => v.entry::<bodies::keymember>(),
        ("lists", "keysearch", 3) => v.entry::<bodies::keysearch>(),
        _ => return None,
    };
    arinsal_spec::bif_lookup(module, name, arity).map(|_| f)
}

/// CAR/CDR of a cons cell.
#[inline(always)]
fn cons_cell(term: Term) -> Option<(Term, Term)> {
    // SAFETY: BIF arguments stay on the live process heap for this call.
    unsafe { term.cons_ref() }
}

fn proper_len(mut list: Term) -> Result<usize, BifError> {
    let mut count = 0usize;
    while let Some((_, tail)) = cons_cell(list) {
        count += 1;
        list = tail;
    }
    if list != Term::NIL {
        return Err(BADARG);
    }
    Ok(count)
}

fn length(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    // Port of erts/emulator/beam/erl_bif_guard.c:270 (erts_trapping_length_1), OTP-29.1.1.
    // The reduction trap is a later task; this counts the whole proper list.
    // `gc_bif length` in native code uses the inlined walk in `emit_bif_length`.
    integer(ctx, proper_len(args[0])?)
}

/// Cells of `erlang:'++'/2` per reduction on the alloc path.
/// Port of `CELLS_PER_RED` at `erl_bif_lists.c:112`, OTP-29.1.1.
pub const APPEND_ALLOC_PER_RED: usize = 40;
/// Cells of `erlang:'++'/2` per reduction on the on-heap path.
/// Port of `CELLS_PER_RED` at `erl_bif_lists.c:177`, OTP-29.1.1.
pub const APPEND_ONHEAP_PER_RED: usize = 60;
/// Elements scanned per reduction when `++` only checks a nil right-hand side.
/// Port of `ELEMENTS_PER_RED` at `erl_bif_lists.c:62`, OTP-29.1.1.
pub const APPEND_EMPTY_PER_RED: usize = 32;
/// Elements of `lists:member/2` per reduction.
/// Port of `16 * ERTS_BIF_REDS_LEFT` at `erl_bif_lists.c:1115`, OTP-29.1.1.
pub const MEMBER_PER_RED: usize = 16;
/// Elements of `lists:keyfind/3` before it traps. Not scaled by reductions left.
/// Port of `10 * CONTEXT_REDS` at `erl_bif_lists.c:1304`, OTP-29.1.1.
pub const KEYFIND_MAX_ITER: usize = 10 * 4_000;

/// Resume state of `erlang:'++'/2`.
///
/// Port of `ErtsAppendContext` at `erl_bif_lists.c:47-55`, OTP-29.1.1.
pub struct AppendCont {
    lhs_original: Term,
    rhs: Term,
    iterator: Term,
    result: Term,
    /// Last cons written, or `[]` when the result is still empty. Its tail is `[]`
    /// until the next chunk or the final right-hand side overwrites it.
    last: Term,
}

impl AppendCont {
    /// Start from the two arguments of `++`.
    pub fn start(lhs: Term, rhs: Term) -> Self {
        Self {
            lhs_original: lhs,
            rhs,
            iterator: lhs,
            result: Term::NIL,
            last: Term::NIL,
        }
    }

    /// List cells not yet copied.
    pub fn iterator(&self) -> Term {
        self.iterator
    }

    /// Right-hand side. Nil selects the scan-only budget.
    pub fn rhs(&self) -> Term {
        self.rhs
    }
}

/// One chunk of `erlang:'++'/2`.
pub enum AppendStep {
    /// The left-hand side was consumed.
    Done(Term),
    /// `BIF_TRAP2` with this context.
    More(AppendCont),
}

/// Resume arguments of `lists:member/2`.
pub struct MemberCont {
    term: Term,
    list: Term,
}

impl MemberCont {
    /// Element being sought.
    pub fn term(&self) -> Term {
        self.term
    }

    /// Cons not yet visited.
    pub fn list(&self) -> Term {
        self.list
    }
}

/// One chunk of `lists:member/2`.
pub enum MemberStep {
    /// `true` or `false`.
    Done(bool),
    /// `BIF_TRAP2` with the term and the remaining list.
    More(MemberCont),
}

/// Resume arguments of `lists:keyfind/3` and its wrappers.
pub struct KeyfindCont {
    key: Term,
    pos: Term,
    list: Term,
}

impl KeyfindCont {
    /// Key that was sought.
    pub fn key(&self) -> Term {
        self.key
    }

    /// 1-based tuple position.
    pub fn pos(&self) -> Term {
        self.pos
    }

    /// Cons not yet visited.
    pub fn list(&self) -> Term {
        self.list
    }
}

/// One chunk of `keyfind` before keymember/keysearch wrap the tuple.
pub enum KeyfindStep {
    /// The matching tuple, or `None` for `false`.
    Done(Option<Term>),
    /// `BIF_TRAP3` with the key, the position, and the remaining list.
    More(KeyfindCont),
}

/// Which export wraps a `keyfind` result.
#[derive(Clone, Copy)]
pub enum KeyOp {
    /// `lists:keyfind/3`.
    Find,
    /// `lists:keymember/3`.
    Member,
    /// `lists:keysearch/3`.
    Search,
}

/// Continuation built only after a slice's counter runs out.
pub enum DeferredTrap {
    /// `erlang:binary_to_list/1` and `/3`.
    BinaryToList(crate::pure::BinaryToListWalk),
    /// `lists:keyfind/3`, `keymember/3`, or `keysearch/3`.
    Key(KeyfindCont),
    /// `lists:member/2`.
    Member(MemberCont),
    /// `lists:reverse/2`.
    Reverse(ReverseCont),
    /// `erlang:'++'/2` or `erlang:append/2`.
    Append(AppendCont),
    /// `erlang:'--'/2` or `erlang:subtract/2`.
    Subtract(SubtractWalk),
}

/// A finished key BIF, or a trap back to the same export.
pub enum KeyOutcome {
    /// The Erlang return value.
    Done(Term),
    /// Resume arguments.
    More(KeyfindCont),
}

/// Copy at most `onheap_cells` conses onto the young heap, then at most
/// `alloc_cells` more. `usize::MAX` finishes a finite list.
///
/// Port of `append_continue`, `lists_append_onheap`, `lists_append_alloc`, and
/// `append_empty_rhs` (`erl_bif_lists.c:61-251`), OTP-29.1.1.
pub fn lists_append(
    ctx: &mut Ctx<'_>,
    state: AppendCont,
    onheap_cells: usize,
    alloc_cells: usize,
) -> Result<AppendStep, BifError> {
    if state.iterator == Term::NIL {
        let value = if state.result != Term::NIL {
            state.result
        } else if state.rhs == Term::NIL {
            state.lhs_original
        } else {
            state.rhs
        };
        return Ok(AppendStep::Done(value));
    }
    if state.rhs == Term::NIL && state.result == Term::NIL {
        return append_empty_rhs(ctx, state, onheap_cells);
    }
    // SAFETY: source cons cells stay live. Destination words come from one
    // HAlloc of the young-heap window (or of this chunk's remainder). CAR/CDR
    // use the tagged offsets from lists_append_onheap; the previous CDR slot
    // is linked with make_list, and the right-hand side is stored once at the end.
    unsafe {
        let mut list_bits = state.iterator.raw_bits();
        let rhs_bits = state.rhs.raw_bits();
        if !is_list_bits(list_bits) {
            return Err(BADARG);
        }
        let nil_bits = Term::NIL.raw_bits();
        let mut head_bits = state.result.raw_bits();
        let mut last_cdr: *mut u64 = if state.last == Term::NIL {
            std::ptr::null_mut()
        } else {
            (state.last.raw_bits() as *mut u8).add(7).cast()
        };
        let mut built_onheap = 0usize;
        let mut ran_onheap = false;
        if onheap_cells > 0
            && let Some(left) = ctx.heap.words_left()
            && left > 8
        {
            ran_onheap = true;
            let words = left - 1;
            let mut reserved =
                HeapReservation::new(&mut ctx.heap, words).expect("infallible BIF heap");
            let mut alloc_top = reserved.cursor();
            let alloc_end = reserved.limit().wrapping_sub(1);
            while alloc_top < alloc_end && is_list_bits(list_bits) && built_onheap < onheap_cells {
                let (car, next) = car_cdr!(list_bits);
                let cell = (alloc_top as u64) | 1;
                if last_cdr.is_null() {
                    head_bits = cell;
                } else {
                    last_cdr.write(cell);
                }
                alloc_top.write(car);
                last_cdr = alloc_top.add(1);
                alloc_top = alloc_top.add(2);
                list_bits = next;
                built_onheap += 1;
            }
            reserved.set_cursor(alloc_top);
        }
        let finite = onheap_cells != usize::MAX;
        let lhs_original = state.lhs_original;
        let rhs_term = state.rhs;
        let charge = |ctx: &mut Ctx<'_>, built_onheap: usize, built_alloc: usize| {
            if finite {
                ctx.charge_reductions(
                    built_onheap / APPEND_ONHEAP_PER_RED + built_alloc / APPEND_ALLOC_PER_RED,
                );
            }
        };
        let pause = |ctx: &mut Ctx<'_>,
                     list_bits: u64,
                     head_bits: u64,
                     last_cdr: *mut u64,
                     built_onheap: usize,
                     built_alloc: usize|
         -> AppendStep {
            if finite {
                ctx.charge_reductions(
                    built_onheap / APPEND_ONHEAP_PER_RED + built_alloc / APPEND_ALLOC_PER_RED,
                );
            }
            let last = if last_cdr.is_null() {
                Term::NIL
            } else {
                Term::from_raw_bits((last_cdr as u64).wrapping_sub(8) | 1)
            };
            AppendStep::More(AppendCont {
                lhs_original,
                rhs: rhs_term,
                iterator: Term::from_raw_bits(list_bits),
                result: Term::from_raw_bits(head_bits),
                last,
            })
        };
        if !is_list_bits(list_bits) {
            if list_bits != nil_bits {
                if !last_cdr.is_null() {
                    last_cdr.write(nil_bits);
                }
                charge(ctx, built_onheap, 0);
                return Err(BADARG);
            }
            if last_cdr.is_null() {
                return Ok(AppendStep::Done(rhs_term));
            }
            last_cdr.write(rhs_bits);
            charge(ctx, built_onheap, 0);
            return Ok(AppendStep::Done(Term::from_raw_bits(head_bits)));
        }
        // lists_append_onheap falls into alloc only while more than one
        // reduction of its budget remains. A young heap of 8 words or fewer
        // skips on-heap and uses the alloc budget (append_continue).
        let alloc_budget = if alloc_cells == usize::MAX {
            usize::MAX
        } else if !ran_onheap {
            alloc_cells
        } else {
            let cells_left = onheap_cells.saturating_sub(built_onheap);
            if cells_left > APPEND_ONHEAP_PER_RED {
                let reds_after = (onheap_cells / APPEND_ONHEAP_PER_RED)
                    .saturating_sub(built_onheap / APPEND_ONHEAP_PER_RED);
                reds_after.saturating_mul(APPEND_ALLOC_PER_RED)
            } else {
                0
            }
        };
        let mut count = 0usize;
        let mut scan = list_bits;
        while count < alloc_budget && is_list_bits(scan) {
            let (_, next) = car_cdr!(scan);
            scan = next;
            count += 1;
        }
        if !is_list_bits(scan) && scan != nil_bits {
            if !last_cdr.is_null() {
                last_cdr.write(nil_bits);
            }
            charge(ctx, built_onheap, count);
            return Err(BADARG);
        }
        if count == 0 {
            if !last_cdr.is_null() {
                last_cdr.write(nil_bits);
            }
            return Ok(pause(ctx, list_bits, head_bits, last_cdr, built_onheap, 0));
        }
        let words = count.checked_mul(2).ok_or(BifError::SystemLimit)?;
        let alloc_top = HeapAlloc::alloc(&mut ctx.heap, words).expect("infallible BIF heap");
        let mut hp = alloc_top;
        for _ in 0..count {
            let (car, next) = car_cdr!(list_bits);
            let cell = (hp as u64) | 1;
            if last_cdr.is_null() {
                head_bits = cell;
            } else {
                last_cdr.write(cell);
            }
            hp.write(car);
            last_cdr = hp.add(1);
            hp = hp.add(2);
            list_bits = next;
        }
        if is_list_bits(list_bits) {
            last_cdr.write(nil_bits);
            return Ok(pause(
                ctx,
                list_bits,
                head_bits,
                last_cdr,
                built_onheap,
                count,
            ));
        }
        last_cdr.write(rhs_bits);
        charge(ctx, built_onheap, count);
        Ok(AppendStep::Done(Term::from_raw_bits(head_bits)))
    }
}

fn append_empty_rhs(
    ctx: &mut Ctx<'_>,
    state: AppendCont,
    budget: usize,
) -> Result<AppendStep, BifError> {
    let mut iterator = state.iterator;
    let mut scanned = 0usize;
    while scanned < budget {
        match cons_cell(iterator) {
            Some((_, tail)) => {
                iterator = tail;
                scanned += 1;
            }
            None => {
                if iterator != Term::NIL {
                    return Err(BADARG);
                }
                if budget != usize::MAX {
                    ctx.charge_reductions(scanned / APPEND_EMPTY_PER_RED);
                }
                return Ok(AppendStep::Done(state.lhs_original));
            }
        }
    }
    if budget != usize::MAX {
        ctx.charge_reductions(scanned / APPEND_EMPTY_PER_RED);
    }
    // A budget that lands exactly on the end is a finish, not a trap
    // (append_empty_rhs checks is_nil after the counted loop).
    if iterator == Term::NIL {
        return Ok(AppendStep::Done(state.lhs_original));
    }
    Ok(AppendStep::More(AppendCont { iterator, ..state }))
}

fn append(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    // The VM trap passes a finite budget. A direct call finishes the list.
    if args[0] == Term::NIL {
        return Ok(args[1]);
    }
    let budget = ctx.reduction_budget();
    if budget != usize::MAX {
        let state = AppendCont::start(args[0], args[1]);
        let (onheap, alloc) = if args[1] == Term::NIL {
            (budget.saturating_mul(APPEND_EMPTY_PER_RED), 0)
        } else {
            (
                budget.saturating_mul(APPEND_ONHEAP_PER_RED),
                budget.saturating_mul(APPEND_ALLOC_PER_RED),
            )
        };
        return match lists_append(ctx, state, onheap, alloc)? {
            AppendStep::Done(value) => Ok(value),
            AppendStep::More(cont) => {
                // Trap state is built only when this slice's counter runs out.
                ctx.defer_trap(DeferredTrap::Append(cont));
                Ok(Term::NIL)
            }
        };
    }
    let mut state = AppendCont::start(args[0], args[1]);
    loop {
        match lists_append(ctx, state, usize::MAX, usize::MAX)? {
            AppendStep::Done(value) => return Ok(value),
            AppendStep::More(next) => state = next,
        }
    }
}

fn subtract(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    // Port of erts/emulator/beam/erl_bif_lists.c:367-1020 (subtract stages),
    // OTP-29.1.1. A finite budget is one slice of `SubtractWalk`; the walk is
    // boxed only when that slice traps. An unbounded call is the direct BIF.
    if ctx.reduction_budget() != usize::MAX {
        let mut walk = SubtractWalk::new(args[0], args[1])?;
        return match walk.step(ctx, ctx.reduction_budget())? {
            Some(value) => Ok(value),
            None => {
                ctx.defer_trap(DeferredTrap::Subtract(walk));
                Ok(Term::NIL)
            }
        };
    }
    if !matches!(
        args[0].classify(),
        arinsal_term::TermKind::List | arinsal_term::TermKind::Nil
    ) || !matches!(
        args[1].classify(),
        arinsal_term::TermKind::List | arinsal_term::TermKind::Nil
    ) {
        return Err(BADARG);
    }

    const LHS_THRESHOLD: usize = 16;
    const RHS_THRESHOLD: usize = 16;

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Stage {
        Start,
        LenLhs,
        NaiveLhs,
        LenRhs,
        NaiveRhs,
        SetBuild,
        SetFinish,
    }

    enum Scratch {
        Empty,
        Lhs([Term; LHS_THRESHOLD]),
        Rhs([Term; RHS_THRESHOLD]),
        Set(RbTree),
    }

    let mut stage = Stage::Start;
    let mut lhs_remaining = 0usize;
    let mut rhs_remaining = 0usize;
    let mut iterator = Term::NIL;
    let mut scratch = Scratch::Empty;

    loop {
        match stage {
            Stage::Start => stage = Stage::LenLhs,
            Stage::LenLhs => {
                lhs_remaining = subtract_get_length(ctx, args[0])?;
                if lhs_remaining > 0
                    && lhs_remaining <= LHS_THRESHOLD
                    && args[1].classify() == arinsal_term::TermKind::List
                {
                    let mut elements = [Term::NIL; LHS_THRESHOLD];
                    iterator = args[0];
                    for element in elements.iter_mut().take(lhs_remaining) {
                        let (head, tail) = cons_cell(iterator).ok_or(BADARG)?;
                        *element = head;
                        iterator = tail;
                    }
                    iterator = args[1];
                    scratch = Scratch::Lhs(elements);
                    stage = Stage::NaiveLhs;
                } else {
                    iterator = args[1];
                    stage = Stage::LenRhs;
                }
            }
            Stage::NaiveLhs => {
                let Scratch::Lhs(elements) = &mut scratch else {
                    unreachable!("naive LHS stage owns its fixed array")
                };
                let mut checks = 0usize;
                while let Some((value, next)) = cons_cell(iterator) {
                    let mut found_at = None;
                    for (index, element) in elements.iter().take(lhs_remaining).enumerate() {
                        if exact_eq(value, *element) {
                            found_at = Some(index);
                            break;
                        }
                    }
                    if let Some(found_at) = found_at {
                        elements.copy_within(found_at + 1..lhs_remaining, found_at);
                        lhs_remaining -= 1;
                    }
                    checks = checks.saturating_add(lhs_remaining.max(1));
                    iterator = next;
                }
                if iterator != Term::NIL {
                    return Err(BADARG);
                }
                ctx.charge_reductions(checks / 16);
                return subtract_list_from_slice(ctx, &elements[..lhs_remaining], Term::NIL);
            }
            Stage::LenRhs => {
                rhs_remaining = subtract_get_length(ctx, args[1])?;
                if lhs_remaining == 0 {
                    return Ok(Term::NIL);
                }
                if rhs_remaining == 0 {
                    return Ok(args[0]);
                }
                if rhs_remaining <= RHS_THRESHOLD {
                    let mut elements = [Term::NIL; RHS_THRESHOLD];
                    iterator = args[1];
                    for element in elements.iter_mut().take(rhs_remaining) {
                        let (head, tail) = cons_cell(iterator).ok_or(BADARG)?;
                        *element = head;
                        iterator = tail;
                    }
                    iterator = args[0];
                    scratch = Scratch::Rhs(elements);
                    stage = Stage::NaiveRhs;
                } else {
                    iterator = args[1];
                    scratch = Scratch::Set(RbTree::with_capacity(rhs_remaining));
                    stage = Stage::SetBuild;
                }
            }
            Stage::NaiveRhs => {
                let Scratch::Rhs(elements) = &mut scratch else {
                    unreachable!("naive RHS stage owns its fixed array")
                };
                let mut checks = 0usize;
                let mut result = SubtractResultBuilder::new(&mut ctx.heap);
                while let Some((value, next)) = cons_cell(iterator) {
                    let found_at = (0..rhs_remaining)
                        .rev()
                        .find(|&index| exact_eq(value, elements[index]));
                    if let Some(found_at) = found_at {
                        if rhs_remaining == 1 {
                            let output = result.finish(next);
                            ctx.charge_reductions(checks / 16);
                            return Ok(output);
                        }
                        rhs_remaining -= 1;
                        elements[found_at] = elements[rhs_remaining];
                    } else {
                        result.push(value, lhs_remaining)?;
                    }
                    checks = checks.saturating_add(rhs_remaining);
                    iterator = next;
                    lhs_remaining -= 1;
                }
                let output = result.finish(Term::NIL);
                ctx.charge_reductions(checks / 16);
                debug_assert_eq!(lhs_remaining, 0);
                return Ok(output);
            }
            Stage::SetBuild => {
                let Scratch::Set(tree) = &mut scratch else {
                    unreachable!("set build stage owns its red-black tree")
                };
                let mut insertions = 0usize;
                while let Some((value, next)) = cons_cell(iterator) {
                    tree.insert(value);
                    insertions += 1;
                    iterator = next;
                }
                ctx.charge_reductions(insertions / 16);
                stage = Stage::SetFinish;
                iterator = args[0];
            }
            Stage::SetFinish => {
                let Scratch::Set(tree) = &mut scratch else {
                    unreachable!("set finish stage owns its red-black tree")
                };
                let mut checks = 0usize;
                let mut result = SubtractResultBuilder::new(&mut ctx.heap);
                while let Some((value, next)) = cons_cell(iterator) {
                    if let Some(node) = tree.lookup(value) {
                        debug_assert!(rhs_remaining > 0);
                        if rhs_remaining == 1 {
                            let output = result.finish(next);
                            ctx.charge_reductions(checks / 8);
                            return Ok(output);
                        }
                        rhs_remaining -= 1;
                        tree.consume(node);
                    } else {
                        result.push(value, lhs_remaining)?;
                    }
                    iterator = next;
                    lhs_remaining -= 1;
                    checks += 1;
                }
                let output = result.finish(Term::NIL);
                ctx.charge_reductions(checks / 8);
                debug_assert_eq!(lhs_remaining, 0);
                return Ok(output);
            }
        }
    }
}

/// Resumable state for `erlang:'--'/2`.
///
/// Port of `ErtsSubtractContext` and `subtract_continue` in
/// `erts/emulator/beam/erl_bif_lists.c:390-1014`, OTP-29.1.1.
pub struct SubtractWalk {
    stage: SubtractStage,
    lhs: Term,
    rhs: Term,
    lhs_remaining: usize,
    rhs_remaining: usize,
    iterator: Term,
    result: Option<ConsHeapChain>,
    scratch: SubtractScratch,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SubtractStage {
    Start,
    LenLhs,
    NaiveLhs,
    LenRhs,
    NaiveRhs,
    SetBuild,
    SetFinish,
}

enum SubtractScratch {
    Empty,
    Lhs([Term; 16]),
    Rhs([Term; 16]),
    Set(RbTree),
}

impl SubtractWalk {
    /// Start after the argument-kind checks in OTP `subtract/2`.
    /// Port of `subtract_start` and `subtract` at `erl_bif_lists.c:1017-1077`.
    pub fn new(lhs: Term, rhs: Term) -> Result<Self, BifError> {
        if !matches!(
            lhs.classify(),
            arinsal_term::TermKind::List | arinsal_term::TermKind::Nil
        ) || !matches!(
            rhs.classify(),
            arinsal_term::TermKind::List | arinsal_term::TermKind::Nil
        ) {
            return Err(BADARG);
        }
        Ok(Self {
            stage: SubtractStage::Start,
            lhs,
            rhs,
            lhs_remaining: 0,
            rhs_remaining: 0,
            iterator: Term::NIL,
            result: None,
            scratch: SubtractScratch::Empty,
        })
    }

    /// Run up to `reductions_left` BIF reductions; `None` means trap and resume.
    /// Port of `subtract_continue` at `erl_bif_lists.c:931-1014`.
    pub fn step(
        &mut self,
        ctx: &mut Ctx<'_>,
        reductions_left: usize,
    ) -> Result<Option<Term>, BifError> {
        loop {
            match self.stage {
                SubtractStage::Start => {
                    self.stage = SubtractStage::LenLhs;
                    self.iterator = self.lhs;
                }
                SubtractStage::LenLhs => {
                    let budget = subtract_budget(ctx, reductions_left, 32);
                    if !subtract_get_length_chunk(
                        ctx,
                        &mut self.iterator,
                        &mut self.lhs_remaining,
                        budget,
                    )? {
                        return Ok(None);
                    }
                    if self.lhs_remaining > 0
                        && self.lhs_remaining <= 16
                        && self.rhs.classify() == arinsal_term::TermKind::List
                    {
                        let mut elements = [Term::NIL; 16];
                        let mut iterator = self.lhs;
                        for element in elements.iter_mut().take(self.lhs_remaining) {
                            let (head, tail) = cons_cell(iterator).ok_or(BADARG)?;
                            *element = head;
                            iterator = tail;
                        }
                        self.iterator = self.rhs;
                        self.scratch = SubtractScratch::Lhs(elements);
                        self.stage = SubtractStage::NaiveLhs;
                    } else {
                        self.iterator = self.rhs;
                        self.stage = SubtractStage::LenRhs;
                    }
                }
                SubtractStage::NaiveLhs => {
                    let budget = subtract_budget(ctx, reductions_left, 16);
                    let SubtractScratch::Lhs(elements) = &mut self.scratch else {
                        unreachable!("naive LHS stage owns its fixed array")
                    };
                    let mut checks = 0usize;
                    while checks < budget {
                        let Some((value, next)) = cons_cell(self.iterator) else {
                            break;
                        };
                        let mut found_at = None;
                        for (index, element) in elements.iter().take(self.lhs_remaining).enumerate()
                        {
                            if exact_eq(value, *element) {
                                found_at = Some(index);
                                break;
                            }
                        }
                        if let Some(found_at) = found_at {
                            let old_remaining = self.lhs_remaining;
                            self.lhs_remaining -= 1;
                            elements.copy_within(found_at + 1..old_remaining, found_at);
                        }
                        checks = checks.saturating_add(self.lhs_remaining.max(1));
                        self.iterator = next;
                    }
                    ctx.charge_reductions(checks.min(budget) / 16);
                    if self.iterator != Term::NIL {
                        if self.iterator.classify() != arinsal_term::TermKind::List {
                            return Err(BADARG);
                        }
                        return Ok(None);
                    }
                    return subtract_list_from_slice(
                        ctx,
                        &elements[..self.lhs_remaining],
                        Term::NIL,
                    )
                    .map(Some);
                }
                SubtractStage::LenRhs => {
                    let budget = subtract_budget(ctx, reductions_left, 32);
                    if !subtract_get_length_chunk(
                        ctx,
                        &mut self.iterator,
                        &mut self.rhs_remaining,
                        budget,
                    )? {
                        return Ok(None);
                    }
                    if self.lhs_remaining == 0 {
                        return Ok(Some(Term::NIL));
                    }
                    if self.rhs_remaining == 0 {
                        return Ok(Some(self.lhs));
                    }
                    if self.rhs_remaining <= 16 {
                        let mut elements = [Term::NIL; 16];
                        let mut iterator = self.rhs;
                        for element in elements.iter_mut().take(self.rhs_remaining) {
                            let (head, tail) = cons_cell(iterator).ok_or(BADARG)?;
                            *element = head;
                            iterator = tail;
                        }
                        self.iterator = self.lhs;
                        self.result = Some(ConsHeapChain::new());
                        self.scratch = SubtractScratch::Rhs(elements);
                        self.stage = SubtractStage::NaiveRhs;
                    } else {
                        self.iterator = self.rhs;
                        self.scratch =
                            SubtractScratch::Set(RbTree::with_capacity(self.rhs_remaining));
                        self.stage = SubtractStage::SetBuild;
                    }
                }
                SubtractStage::NaiveRhs => return self.step_naive_rhs(ctx, reductions_left),
                SubtractStage::SetBuild => {
                    if !self.step_set_build(ctx, reductions_left)? {
                        return Ok(None);
                    }
                }
                SubtractStage::SetFinish => return self.step_set_finish(ctx, reductions_left),
            }
        }
    }

    // Port of `subtract_naive_rhs` at `erl_bif_lists.c:723-795`, OTP-29.1.1.
    fn step_naive_rhs(
        &mut self,
        ctx: &mut Ctx<'_>,
        reductions_left: usize,
    ) -> Result<Option<Term>, BifError> {
        let budget = subtract_budget(ctx, reductions_left, 16);
        let SubtractScratch::Rhs(elements) = &mut self.scratch else {
            unreachable!("naive RHS stage owns its fixed array")
        };
        let mut checks = 0usize;
        while checks < budget {
            let Some((value, next)) = cons_cell(self.iterator) else {
                break;
            };
            let found_at = (0..self.rhs_remaining)
                .rev()
                .find(|&i| exact_eq(value, elements[i]));
            if let Some(found_at) = found_at {
                if self.rhs_remaining == 1 {
                    ctx.charge_reductions(checks.min(budget) / 16);
                    return Ok(Some(
                        self.result
                            .take()
                            .expect("naive RHS output chain")
                            .finish(next),
                    ));
                }
                self.rhs_remaining -= 1;
                elements[found_at] = elements[self.rhs_remaining];
            } else {
                self.result
                    .as_mut()
                    .expect("naive RHS output chain")
                    .push(&mut ctx.heap, value, self.lhs_remaining)
                    .map_err(|_| BifError::SystemLimit)?;
            }
            checks = checks.saturating_add(self.rhs_remaining);
            self.iterator = next;
            self.lhs_remaining -= 1;
        }
        if self.iterator != Term::NIL && self.iterator.classify() != arinsal_term::TermKind::List {
            return Err(BADARG);
        }
        self.result
            .as_ref()
            .expect("naive RHS output chain")
            .suspend();
        ctx.charge_reductions(checks.min(budget) / 16);
        if self.iterator == Term::NIL {
            return Ok(Some(
                self.result
                    .take()
                    .expect("naive RHS output chain")
                    .finish(Term::NIL),
            ));
        }
        Ok(None)
    }

    // Port of `subtract_set_build` at `erl_bif_lists.c:813-857`, OTP-29.1.1.
    fn step_set_build(
        &mut self,
        ctx: &mut Ctx<'_>,
        reductions_left: usize,
    ) -> Result<bool, BifError> {
        let budget = subtract_budget(ctx, reductions_left, 16);
        let SubtractScratch::Set(tree) = &mut self.scratch else {
            unreachable!("set build stage owns its red-black tree")
        };
        let mut insertions = 0usize;
        while insertions < budget {
            let Some((value, next)) = cons_cell(self.iterator) else {
                break;
            };
            tree.insert(value);
            insertions += 1;
            self.iterator = next;
        }
        ctx.charge_reductions(insertions / 16);
        if self.iterator != Term::NIL && self.iterator.classify() != arinsal_term::TermKind::List {
            return Err(BADARG);
        }
        if self.iterator != Term::NIL {
            return Ok(false);
        }
        self.stage = SubtractStage::SetFinish;
        self.iterator = self.lhs;
        self.result = Some(ConsHeapChain::new());
        Ok(true)
    }

    // Port of `subtract_set_finish` at `erl_bif_lists.c:869-918`, OTP-29.1.1.
    fn step_set_finish(
        &mut self,
        ctx: &mut Ctx<'_>,
        reductions_left: usize,
    ) -> Result<Option<Term>, BifError> {
        let budget = subtract_budget(ctx, reductions_left, 8);
        let SubtractScratch::Set(tree) = &mut self.scratch else {
            unreachable!("set finish stage owns its red-black tree")
        };
        let mut checks = 0usize;
        while checks < budget {
            let Some((value, next)) = cons_cell(self.iterator) else {
                break;
            };
            if let Some(node) = tree.lookup(value) {
                debug_assert!(self.rhs_remaining > 0);
                if self.rhs_remaining == 1 {
                    ctx.charge_reductions(checks.min(budget) / 8);
                    return Ok(Some(
                        self.result.take().expect("set output chain").finish(next),
                    ));
                }
                self.rhs_remaining -= 1;
                tree.consume(node);
            } else {
                self.result
                    .as_mut()
                    .expect("set output chain")
                    .push(&mut ctx.heap, value, self.lhs_remaining)
                    .map_err(|_| BifError::SystemLimit)?;
            }
            self.iterator = next;
            self.lhs_remaining -= 1;
            checks += 1;
        }
        if self.iterator != Term::NIL && self.iterator.classify() != arinsal_term::TermKind::List {
            return Err(BADARG);
        }
        self.result.as_ref().expect("set output chain").suspend();
        ctx.charge_reductions(checks.min(budget) / 8);
        if self.iterator == Term::NIL {
            debug_assert_eq!(self.lhs_remaining, 0);
            return Ok(Some(
                self.result
                    .take()
                    .expect("set output chain")
                    .finish(Term::NIL),
            ));
        }
        Ok(None)
    }
}

// Port of the stage budgets and `BUMP_REDS` accounting in `erl_bif_lists.c:575-918`.
fn subtract_budget(ctx: &Ctx<'_>, reductions_left: usize, units_per_red: usize) -> usize {
    reductions_left
        .saturating_sub(ctx.reductions() as usize)
        .saturating_mul(units_per_red)
}

/// Append retained cells in input order with `HAllocX` fragment slack.
/// Port of `erl_bif_lists.c:748-770` and `:881-916`, OTP-29.1.1.
struct SubtractResultBuilder<'a, H: HeapAlloc + ?Sized> {
    heap: &'a mut H,
    chain: ConsHeapChain,
}

impl<'a, H: HeapAlloc + ?Sized> SubtractResultBuilder<'a, H> {
    fn new(heap: &'a mut H) -> Self {
        Self {
            heap,
            chain: ConsHeapChain::new(),
        }
    }

    fn push(&mut self, value: Term, max_cells: usize) -> Result<(), BifError> {
        self.chain
            .push(self.heap, value, max_cells)
            .map_err(|_| BifError::SystemLimit)
    }

    fn finish(self, tail: Term) -> Term {
        self.chain.finish(tail)
    }
}

/// Build the small-LHS result backwards in one reserved heap block.
/// Port of `erl_bif_lists.c:665-684` (`subtract_naive_lhs`), OTP-29.1.1.
fn subtract_list_from_slice(
    ctx: &mut Ctx<'_>,
    items: &[Term],
    tail: Term,
) -> Result<Term, BifError> {
    if items.is_empty() {
        return Ok(tail);
    }
    let words = items.len().checked_mul(2).ok_or(BifError::SystemLimit)?;
    let mut reservation =
        HeapReservation::new(&mut ctx.heap, words).map_err(|_| BifError::SystemLimit)?;
    let mut builder = TermBuilder::new(&mut reservation);
    let mut result = tail;
    for item in items.iter().rev() {
        result = builder
            .cons(*item, result)
            .map_err(|_| BifError::SystemLimit)?;
    }
    Ok(result)
}

/// Count and validate one input list.
///
/// Port of `subtract_get_length` at `erl_bif_lists.c:575-604`, OTP-29.1.1.
fn subtract_get_length(ctx: &mut Ctx<'_>, list: Term) -> Result<usize, BifError> {
    let mut iterator = list;
    let mut count = 0usize;
    while let Some((_, tail)) = cons_cell(iterator) {
        count += 1;
        iterator = tail;
    }
    if iterator != Term::NIL {
        return Err(BADARG);
    }
    ctx.charge_reductions(count / 32);
    Ok(count)
}

/// Scan one reduction-sized portion of an input list.
///
/// Port of `subtract_get_length` at `erl_bif_lists.c:574-604`, OTP-29.1.1.
fn subtract_get_length_chunk(
    ctx: &mut Ctx<'_>,
    iterator: &mut Term,
    count: &mut usize,
    budget: usize,
) -> Result<bool, BifError> {
    let mut scanned = 0usize;
    while scanned < budget {
        let Some((_, tail)) = cons_cell(*iterator) else {
            break;
        };
        *iterator = tail;
        *count += 1;
        scanned += 1;
    }
    if *iterator != Term::NIL && iterator.classify() != arinsal_term::TermKind::List {
        return Err(BADARG);
    }
    ctx.charge_reductions(scanned / 32);
    Ok(*iterator == Term::NIL)
}

/// Cons cells one reduction may reverse on the alloc path.
/// Port of `CELLS_PER_RED` at `erl_bif_lists.c:1148`, OTP-29.1.1.
pub const REVERSE_CELLS_PER_RED: usize = 40;
/// Cons cells one reduction may reverse on the young heap.
/// Port of `CELLS_PER_RED` at `erl_bif_lists.c:1193`, OTP-29.1.1.
pub const REVERSE_ONHEAP_CELLS_PER_RED: usize = 60;

/// Arguments a `lists:reverse/2` trap resumes with.
///
/// Port of the `BIF_TRAP2` pair at `erl_bif_lists.c:1191` and `:1240`, OTP-29.1.1:
/// the cells still to walk, and the reversed prefix built so far.
pub struct ReverseCont {
    list: Term,
    tail: Term,
}

impl ReverseCont {
    /// List cells not yet consed onto the result.
    pub fn list(&self) -> Term {
        self.list
    }

    /// Reversed prefix, the continuation's second argument.
    pub fn tail(&self) -> Term {
        self.tail
    }
}

/// One chunk of `lists:reverse/2`.
pub enum ReverseStep {
    /// The input list was consumed.
    Done(Term),
    /// `BIF_TRAP2` to `lists:reverse/2` with this state.
    Trap(ReverseCont),
}

/// Fill at most `max_cells` conses of `lists:reverse/2`.
///
/// Port of `lists_reverse_2`, `lists_reverse_onheap`, and `lists_reverse_alloc`
/// (`erl_bif_lists.c:1144-1263`), OTP-29.1.1. `usize::MAX` finishes a finite
/// list in this call (the direct BIF). A reduction-sized budget stops and
/// returns [`ReverseStep::Trap`]. The on-heap loop and the exact-remainder
/// alloc are one fill: `CONS(hp, CAR, tail)` with a raw heap-top bump.
pub fn lists_reverse(
    ctx: &mut Ctx<'_>,
    list: Term,
    tail: Term,
    max_cells: usize,
) -> Result<ReverseStep, BifError> {
    if list == Term::NIL {
        return Ok(ReverseStep::Done(tail));
    }
    if cons_cell(list).is_none() {
        return Err(BADARG);
    }
    let mut current = list;
    let mut result_tail = tail;
    let mut built_onheap = 0usize;
    let mut onheap_cells_left = ctx
        .reduction_budget()
        .saturating_mul(REVERSE_ONHEAP_CELLS_PER_RED)
        .min(max_cells);
    let cursor = ctx.heap.bounded_cursor(onheap_cells_left);
    let onheap_available = cursor.is_some();
    if let Some(mut cursor) = cursor {
        while cursor.has_room() {
            let Some((head, next)) = cons_cell(current) else {
                break;
            };
            result_tail = cursor
                .push_cons(head, result_tail)
                .expect("bounded cursor has room");
            current = next;
            built_onheap += 1;
            onheap_cells_left -= 1;
        }
        cursor.finish();
        // Port of `BUMP_REDS(c_p, cells / 60)` in lists_reverse_onheap.
        ctx.charge_reductions(built_onheap / REVERSE_ONHEAP_CELLS_PER_RED);
    }
    if current == Term::NIL {
        return Ok(ReverseStep::Done(result_tail));
    }
    if cons_cell(current).is_none() {
        return Err(BADARG);
    }
    let cells_left = max_cells.saturating_sub(built_onheap);
    if onheap_available && onheap_cells_left <= REVERSE_ONHEAP_CELLS_PER_RED {
        // Port of `BUMP_ALL_REDS` before `BIF_TRAP2` in lists_reverse_onheap.
        ctx.bump_all_reds();
        return Ok(ReverseStep::Trap(ReverseCont {
            list: current,
            tail: result_tail,
        }));
    }
    let alloc_budget = cells_left.min(ctx.reduction_budget().saturating_mul(REVERSE_CELLS_PER_RED));
    // Young-heap window is full (or was too small). Count at most the
    // cells still in this chunk, then allocate that exact remainder.
    let mut count = 0usize;
    let mut scan = current;
    while count < alloc_budget {
        let Some((_, next)) = cons_cell(scan) else {
            break;
        };
        count += 1;
        scan = next;
    }
    if scan != Term::NIL && cons_cell(scan).is_none() {
        // Port of the pre-allocation `BUMP_REDS(c_p, cells / 40)`.
        ctx.charge_reductions(count / REVERSE_CELLS_PER_RED);
        return Err(BADARG);
    }
    let words = count.checked_mul(2).ok_or(BifError::SystemLimit)?;
    {
        let mut reservation =
            HeapReservation::new(&mut ctx.heap, words).map_err(|_| BifError::SystemLimit)?;
        let mut builder = TermBuilder::new(&mut reservation);
        for _ in 0..count {
            let (head, next) = cons_cell(current).expect("validated list chunk");
            result_tail = builder
                .cons(head, result_tail)
                .map_err(|_| BifError::SystemLimit)?;
            current = next;
        }
    }
    // Port of `BUMP_REDS(c_p, cells / 40)` in lists_reverse_alloc.
    ctx.charge_reductions(count / REVERSE_CELLS_PER_RED);
    if current == Term::NIL {
        Ok(ReverseStep::Done(result_tail))
    } else {
        Ok(ReverseStep::Trap(ReverseCont {
            list: current,
            tail: result_tail,
        }))
    }
}

fn reverse(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    match lists_reverse(ctx, args[0], args[1], usize::MAX)? {
        ReverseStep::Done(value) => Ok(value),
        ReverseStep::Trap(cont) => {
            ctx.defer_trap(DeferredTrap::Reverse(cont));
            Ok(Term::NIL)
        }
    }
}

/// Scan at most `max_iter` conses of `lists:member/2`.
///
/// `max_iter` is `16 * ERTS_BIF_REDS_LEFT` (`erl_bif_lists.c:1115`). `usize::MAX`
/// finishes a finite list. A full chunk charges `div_ceil(scanned, 16)`, which is
/// `BUMP_ALL_REDS` when the chunk is exactly one reduction budget and
/// `BIF_RET2`'s `reds_left - max_iter/16` otherwise.
#[inline(always)]
pub fn lists_member(
    ctx: &mut Ctx<'_>,
    term: Term,
    list: Term,
    max_iter: usize,
) -> Result<MemberStep, BifError> {
    if list == Term::NIL {
        return Ok(MemberStep::Done(false));
    } // SAFETY: a list tag denotes two live words. Offsets -1 and +7 are CAR/CDR.
    unsafe {
        let term_bits = term.raw_bits();
        let mut list_bits = list.raw_bits();
        let nil_bits = Term::NIL.raw_bits();
        if !is_list_bits(list_bits) {
            return Err(BADARG);
        }
        let finite = max_iter != usize::MAX;
        let charge = |ctx: &mut Ctx<'_>, scanned: usize| {
            if finite {
                ctx.charge_reductions(scanned.div_ceil(MEMBER_PER_RED));
            }
        };
        let mut scanned = 0usize;
        let step = if term_bits & 3 == 3 {
            let mut found = false;
            while is_list_bits(list_bits) {
                if scanned >= max_iter {
                    charge(ctx, scanned);
                    return Ok(MemberStep::More(MemberCont {
                        term,
                        list: Term::from_raw_bits(list_bits),
                    }));
                }
                scanned += 1;
                let (car, next) = car_cdr!(list_bits);
                if car == term_bits {
                    found = true;
                    break;
                }
                list_bits = next;
            }
            found
        } else {
            let mut found = false;
            while is_list_bits(list_bits) {
                if scanned >= max_iter {
                    charge(ctx, scanned);
                    return Ok(MemberStep::More(MemberCont {
                        term,
                        list: Term::from_raw_bits(list_bits),
                    }));
                }
                scanned += 1;
                let (car, next) = car_cdr!(list_bits);
                if car == term_bits || exact_eq(Term::from_raw_bits(car), term) {
                    found = true;
                    break;
                }
                list_bits = next;
            }
            found
        };
        if !step && list_bits != nil_bits {
            charge(ctx, scanned);
            return Err(BADARG);
        }
        charge(ctx, scanned);
        Ok(MemberStep::Done(step))
    }
}

fn member(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    lists_member_bif(ctx, args)
}

/// Run the process BIF body for `lists:member/2` with its live FCALLS context.
// Port of erts/emulator/beam/erl_bif_lists.c:1108-1142, OTP-29.1.1.
pub fn lists_member_bif(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    // Port of erts/emulator/beam/erl_bif_lists.c:1108 (lists_member_2), OTP-29.1.1.
    // Two loops, as in the C: an immediate compares by word. Only a boxed term
    // falls through to `eq`. The counter traps only when `16 * reds_left` runs out.
    let max_iter = ctx.reduction_budget().saturating_mul(MEMBER_PER_RED);
    match lists_member(ctx, args[0], args[1], max_iter)? {
        MemberStep::Done(found) => Ok(bool_term(found)),
        MemberStep::More(cont) => {
            ctx.defer_trap(DeferredTrap::Member(cont));
            Ok(Term::NIL)
        }
    }
}

#[inline]
fn key_search(args: &[Term], max_iter: usize) -> Result<KeyfindStep, BifError> {
    // Port of erts/emulator/beam/erl_bif_lists.c:1302 (keyfind), OTP-29.1.1.
    // Three loops: a small key also matches a float of the same value, any other
    // immediate compares by word, and a boxed key uses `==`. `max_iter` is
    // `10 * CONTEXT_REDS` (not scaled by reductions left). A hit returns the
    // tuple without reading the rest and without bumping reductions.
    let pos = args[1].as_small().ok_or(BADARG)?;
    if pos < 1 {
        return Err(BADARG);
    }
    let key = args[0];
    let list = args[2];
    // SAFETY: list, tuple, and float words stay on the live process heap.
    // Boxed tag 2: the header is at tagged-2 and element `pos` (1-based) is
    // `header[pos]`, matching `tuple_val` / `arityval` in keyfind.
    unsafe {
        let pos_u = pos as u64;
        let key_bits = key.raw_bits();
        let mut list_bits = list.raw_bits();
        let nil_bits = Term::NIL.raw_bits();
        let mut scanned = 0usize;
        let found = if let Some(small) = key.as_small() {
            let float_key = small as f64;
            let mut found = None;
            while is_list_bits(list_bits) {
                if scanned >= max_iter {
                    return Ok(KeyfindStep::More(KeyfindCont {
                        key,
                        pos: args[1],
                        list: Term::from_raw_bits(list_bits),
                    }));
                }
                scanned += 1;
                let (car, next) = car_cdr!(list_bits);
                list_bits = next;
                if car & 1 != 0 {
                    continue;
                }
                let hdr = (car as usize - 2) as *const u64;
                let header = hdr.read();
                if header & 63 != 0 || pos_u > header >> 6 {
                    continue;
                }
                let element = hdr.add(pos as usize).read();
                if element == key_bits {
                    found = Some(car);
                    break;
                }
                // is_float: boxed, header word 0x58 (one-word FLOAT subtag 0x18).
                if element & 1 != 0 {
                    continue;
                }
                let fhdr = (element as usize - 2) as *const u64;
                if fhdr.read() != 0x58 {
                    continue;
                }
                let payload = (element as *const u8).add(6).cast::<u64>().read_unaligned();
                if f64::from_bits(payload) == float_key {
                    found = Some(car);
                    break;
                }
            }
            found
        } else if key_bits & 3 == 3 {
            let mut found = None;
            while is_list_bits(list_bits) {
                if scanned >= max_iter {
                    return Ok(KeyfindStep::More(KeyfindCont {
                        key,
                        pos: args[1],
                        list: Term::from_raw_bits(list_bits),
                    }));
                }
                scanned += 1;
                let (car, next) = car_cdr!(list_bits);
                list_bits = next;
                if car & 1 != 0 {
                    continue;
                }
                let hdr = (car as usize - 2) as *const u64;
                let header = hdr.read();
                if header & 63 != 0 || pos_u > header >> 6 {
                    continue;
                }
                if hdr.add(pos as usize).read() == key_bits {
                    found = Some(car);
                    break;
                }
            }
            found
        } else {
            let mut found = None;
            while is_list_bits(list_bits) {
                if scanned >= max_iter {
                    return Ok(KeyfindStep::More(KeyfindCont {
                        key,
                        pos: args[1],
                        list: Term::from_raw_bits(list_bits),
                    }));
                }
                scanned += 1;
                let (car, next) = car_cdr!(list_bits);
                list_bits = next;
                if car & 1 != 0 {
                    continue;
                }
                let hdr = (car as usize - 2) as *const u64;
                let header = hdr.read();
                if header & 63 != 0 || pos_u > header >> 6 {
                    continue;
                }
                let element = Term::from_raw_bits(hdr.add(pos as usize).read());
                if loose_eq(key, element) {
                    found = Some(car);
                    break;
                }
            }
            found
        };
        if found.is_none() && list_bits != nil_bits {
            return Err(BADARG);
        }
        if let Some(bits) = found {
            Ok(KeyfindStep::Done(Some(Term::from_raw_bits(bits))))
        } else {
            Ok(KeyfindStep::Done(None))
        }
    }
}

/// One reduction-budget slice of keyfind, keymember, or keysearch.
pub fn lists_key(
    ctx: &mut Ctx<'_>,
    op: KeyOp,
    key: Term,
    pos: Term,
    list: Term,
    max_iter: usize,
) -> Result<KeyOutcome, BifError> {
    match key_search(&[key, pos, list], max_iter)? {
        KeyfindStep::More(cont) => Ok(KeyOutcome::More(cont)),
        KeyfindStep::Done(found) => {
            let value = match op {
                KeyOp::Find => found.unwrap_or(bool_term(false)),
                KeyOp::Member => bool_term(found.is_some()),
                KeyOp::Search => match found {
                    Some(tuple) => tuple_build(ctx, &[Term::atom(atoms::VALUE), tuple]),
                    None => bool_term(false),
                },
            };
            Ok(KeyOutcome::Done(value))
        }
    }
}

fn key_limit(ctx: &Ctx<'_>) -> usize {
    // `10 * CONTEXT_REDS`, not scaled by reductions left (erl_bif_lists.c:1304).
    if ctx.reduction_budget() == usize::MAX {
        usize::MAX
    } else {
        KEYFIND_MAX_ITER
    }
}

fn keyfind(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    match key_search(args, key_limit(ctx))? {
        KeyfindStep::Done(found) => Ok(found.unwrap_or(bool_term(false))),
        KeyfindStep::More(cont) => {
            ctx.defer_trap(DeferredTrap::Key(cont));
            Ok(Term::NIL)
        }
    }
}

fn keymember(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    match key_search(args, key_limit(ctx))? {
        KeyfindStep::Done(found) => Ok(bool_term(found.is_some())),
        KeyfindStep::More(cont) => {
            ctx.defer_trap(DeferredTrap::Key(cont));
            Ok(Term::NIL)
        }
    }
}

fn keysearch(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    match key_search(args, key_limit(ctx))? {
        KeyfindStep::Done(found) => Ok(match found {
            Some(tuple) => tuple_build(ctx, &[Term::atom(atoms::VALUE), tuple]),
            None => bool_term(false),
        }),
        KeyfindStep::More(cont) => {
            ctx.defer_trap(DeferredTrap::Key(cont));
            Ok(Term::NIL)
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{Ctx, ProcessHeapHandle};
    use arinsal_term::{ProcessHeap, Term, TermBuilder};

    #[test]
    fn append_empty_right_keeps_the_left_list() {
        let mut heap = ProcessHeap::with_words(64);
        let mut alloc = ProcessHeapHandle(&mut heap);
        let list = TermBuilder::new(&mut alloc)
            .list_from_slice(&[Term::small(1).unwrap(), Term::small(2).unwrap()])
            .unwrap();
        let mut ctx = Ctx::new(&mut alloc);
        let out = crate::lookup("erlang", "++", 2).unwrap()(&mut ctx, &[list, Term::NIL]).unwrap();
        assert_eq!(out, list);
    }

    #[test]
    fn integer_to_list_is_one_allocation_even_when_the_heap_is_nearly_full() {
        let mut heap = ProcessHeap::with_words(64);
        let left = heap.halloc_words_left().unwrap();
        assert!(heap.alloc_halloc(left - 3).is_some());
        let used = heap.used_words();
        let mut alloc = ProcessHeapHandle(&mut heap);
        let mut ctx = Ctx::new(&mut alloc);
        let bif = crate::lookup("erlang", "integer_to_list", 1).unwrap();
        bif(&mut ctx, &[Term::small(5555).unwrap()]).unwrap();
        assert_eq!(heap.used_words(), used);
        assert_eq!(heap.fragment_words(), 8);
    }
}

#[cfg(test)]
mod subtract_tests {
    use super::*;
    use crate::ProcessHeapHandle;
    use arinsal_difftest::{CallResult, CompareMode, RefErl, compare};
    use arinsal_etf::OwnedTerm as O;
    use arinsal_term::{ProcessHeap, from_owned, to_owned};

    fn local_call(args: &[O]) -> CallResult {
        let bif = crate::lookup("erlang", "--", 2).unwrap();
        let mut heap = ProcessHeap::with_words(4096);
        let mut allocator = ProcessHeapHandle(&mut heap);
        let terms = args
            .iter()
            .map(|value| from_owned(value, &mut allocator).unwrap())
            .collect::<Vec<_>>();
        let result = {
            let mut ctx = Ctx::new(&mut allocator);
            bif(&mut ctx, &terms)
        };
        match result {
            Ok(term) => CallResult::Ok(to_owned(term).unwrap()),
            Err(BifError::Badarg { .. }) => CallResult::Exception {
                class: "error".to_owned(),
                reason: O::atom("badarg"),
                stack_top: None,
            },
            Err(error) => panic!("unexpected subtraction error: {error:?}"),
        }
    }

    fn assert_matches_otp(lhs: O, rhs: O) {
        let args = [lhs, rhs];
        let local = local_call(&args);
        let expected = RefErl::shared().unwrap().call("erlang", "--", &args);
        compare(&local, &expected, CompareMode::Exact)
            .unwrap_or_else(|error| panic!("subtract mismatch for {args:?}: {error}"));
    }

    fn local_walk_call(args: &[O], budget: usize) -> CallResult {
        let mut heap = ProcessHeap::with_words(4096);
        let mut allocator = ProcessHeapHandle(&mut heap);
        let terms = args
            .iter()
            .map(|value| from_owned(value, &mut allocator).unwrap())
            .collect::<Vec<_>>();
        assert!(allocator.0.reserve_stack(3200));
        let mut walk = SubtractWalk::new(terms[0], terms[1]).unwrap();
        let result = loop {
            let step = {
                let mut ctx = Ctx::new(&mut allocator);
                walk.step(&mut ctx, budget)
            };
            match step {
                Ok(Some(term)) => break Ok(term),
                Ok(None) => continue,
                Err(error) => break Err(error),
            }
        };
        match result {
            Ok(term) => CallResult::Ok(to_owned(term).unwrap()),
            Err(BifError::Badarg { .. }) => CallResult::Exception {
                class: "error".to_owned(),
                reason: O::atom("badarg"),
                stack_top: None,
            },
            Err(error) => panic!("unexpected subtraction error: {error:?}"),
        }
    }

    #[test]
    fn subtract_matches_otp_across_stages_and_invalid_inputs() {
        let a = O::atom("a");
        let duplicates = O::list(vec![
            O::Int(1),
            a.clone(),
            O::Int(1),
            O::Int(1),
            O::atom("z"),
        ]);
        assert_matches_otp(
            duplicates,
            O::list(vec![O::Int(1), O::atom("missing"), O::Int(1)]),
        );

        let mixed_lhs = O::list(vec![
            O::Int(1),
            O::Float(1.0),
            O::Tuple(vec![a.clone(), O::Int(2)]),
            O::list(vec![O::Int(3)]),
            O::Binary(vec![0, 255]),
            O::Map(vec![(a.clone(), O::Int(4))]),
        ]);
        assert_matches_otp(
            mixed_lhs,
            O::list(vec![
                O::Float(1.0),
                O::Tuple(vec![a.clone(), O::Int(2)]),
                O::Int(1),
            ]),
        );

        for (lhs_len, rhs_len) in [(1, 17), (16, 32), (17, 16), (40, 41), (128, 97)] {
            let lhs = O::list(
                (0..lhs_len)
                    .map(|index| match index % 7 {
                        0 => O::Float((index % 13) as f64),
                        1 => O::Tuple(vec![a.clone(), O::Int((index % 29) as i64)]),
                        2 => O::Int((index % 31) as i64),
                        3 => O::atom(if index % 2 == 0 { "a" } else { "z" }),
                        4 => O::Binary(vec![(index % 7) as u8]),
                        5 => O::list(vec![O::Int((index % 11) as i64)]),
                        _ => O::Map(vec![(a.clone(), O::Int((index % 9) as i64))]),
                    })
                    .collect(),
            );
            let rhs = O::list(
                (0..rhs_len)
                    .map(|index| match index % 6 {
                        0 => O::Float((index % 13) as f64),
                        1 => O::Tuple(vec![a.clone(), O::Int((index % 29) as i64)]),
                        2 => O::Int((index % 31) as i64),
                        3 => O::atom(if index % 2 == 0 { "a" } else { "z" }),
                        4 => O::list(vec![O::Int((index % 11) as i64)]),
                        _ => O::Map(vec![(a.clone(), O::Int((index % 9) as i64))]),
                    })
                    .collect(),
            );
            assert_matches_otp(lhs, rhs);
        }

        let improper_lhs = O::List {
            elems: vec![O::Int(1)],
            tail: Box::new(O::atom("tail")),
        };
        let improper_rhs = O::List {
            elems: vec![O::Int(1), O::Int(2)],
            tail: Box::new(O::atom("tail")),
        };
        assert_matches_otp(improper_lhs, O::Nil);
        assert_matches_otp(O::list(vec![O::Int(1)]), improper_rhs);
        assert_matches_otp(O::Int(1), O::Nil);
    }

    #[test]
    fn subtract_walk_resumes_each_stage_against_otp() {
        for (lhs, rhs) in [
            (
                O::list((0..258).map(O::Int).collect()),
                O::list((0..258).step_by(2).map(O::Int).collect()),
            ),
            (
                O::list((0..9).map(O::Int).collect()),
                O::list((1..302).step_by(2).map(O::Int).collect()),
            ),
        ] {
            let args = [lhs, rhs];
            let local = local_walk_call(&args, 1);
            let expected = RefErl::shared().unwrap().call("erlang", "--", &args);
            compare(&local, &expected, CompareMode::Exact)
                .unwrap_or_else(|error| panic!("resumed subtract mismatch for {args:?}: {error}"));
        }
    }
}

#[cfg(test)]
mod reverse_chunk_tests {
    use super::{ReverseStep, lists_reverse};
    use crate::{Ctx, ProcessHeapHandle};
    use arinsal_term::{HeapAlloc, ProcessHeap, Term, TermBuilder, exact_eq};

    fn list_of(heap: &mut ProcessHeapHandle<'_>, n: usize) -> Term {
        let values: Vec<_> = (0..n)
            .map(|i| Term::small(i64::try_from(i).unwrap()).unwrap())
            .collect();
        TermBuilder::new(heap).list_from_slice(&values).unwrap()
    }

    fn chunked(ctx: &mut Ctx<'_>, source: Term, tail: Term, max_cells: usize) -> Term {
        let mut list = source;
        let mut acc = tail;
        for _ in 0..64 {
            match lists_reverse(ctx, list, acc, max_cells).unwrap() {
                ReverseStep::Done(value) => return value,
                ReverseStep::Trap(cont) => {
                    assert_ne!(cont.list(), list, "chunk did not consume a cell");
                    list = cont.list();
                    acc = cont.tail();
                }
            }
        }
        panic!("reverse chunk made no progress");
    }

    #[test]
    fn chunks_match_one_shot_reverse() {
        let mut heap = ProcessHeap::with_words(4096);
        let mut alloc = ProcessHeapHandle(&mut heap);
        let source = list_of(&mut alloc, 20);
        let tail = Term::small(99).unwrap();
        let mut ctx = Ctx::new(&mut alloc);
        let ReverseStep::Done(one_shot) =
            lists_reverse(&mut ctx, source, tail, usize::MAX).unwrap()
        else {
            panic!("unbounded reverse trapped");
        };
        assert!(matches!(
            lists_reverse(&mut ctx, source, tail, 3).unwrap(),
            ReverseStep::Trap(_)
        ));
        let chunked = chunked(&mut ctx, source, tail, 3);
        assert!(exact_eq(chunked, one_shot));
    }

    #[test]
    fn alloc_path_chunk_matches_one_shot() {
        let mut heap = ProcessHeap::with_words(512);
        let mut alloc = ProcessHeapHandle(&mut heap);
        let source = list_of(&mut alloc, 10);
        let tail = Term::small(1).unwrap();
        let left = HeapAlloc::words_left(&alloc).unwrap_or(0);
        if left > 8 {
            HeapAlloc::alloc(&mut alloc, left - 8).unwrap();
        }
        assert!(HeapAlloc::words_left(&alloc).unwrap_or(0) <= 8);
        let mut ctx = Ctx::new(&mut alloc);
        let ReverseStep::Done(one_shot) =
            lists_reverse(&mut ctx, source, tail, usize::MAX).unwrap()
        else {
            panic!("unbounded reverse trapped");
        };
        assert!(matches!(
            lists_reverse(&mut ctx, source, tail, 4).unwrap(),
            ReverseStep::Trap(_)
        ));
        let chunked = chunked(&mut ctx, source, tail, 4);
        assert!(exact_eq(chunked, one_shot));
    }

    #[test]
    fn empty_list_keeps_the_tail() {
        let mut heap = ProcessHeap::with_words(64);
        let mut alloc = ProcessHeapHandle(&mut heap);
        let mut ctx = Ctx::new(&mut alloc);
        let tail = Term::small(7).unwrap();
        let ReverseStep::Done(value) = lists_reverse(&mut ctx, Term::NIL, tail, 1).unwrap() else {
            panic!("empty reverse trapped");
        };
        assert_eq!(value, tail);
    }

    #[test]
    fn improper_list_is_badarg() {
        let mut heap = ProcessHeap::with_words(256);
        let mut alloc = ProcessHeapHandle(&mut heap);
        let bad = TermBuilder::new(&mut alloc)
            .cons(Term::small(1).unwrap(), Term::small(2).unwrap())
            .unwrap();
        let mut ctx = Ctx::new(&mut alloc);
        assert!(matches!(
            lists_reverse(&mut ctx, bad, Term::NIL, 10),
            Err(crate::BifError::Badarg { .. })
        ));
    }
}

#[cfg(test)]
mod trap_budget_tests {
    use super::{
        AppendCont, AppendStep, KeyOp, KeyOutcome, MemberStep, lists_append, lists_key,
        lists_member,
    };
    use crate::{Ctx, ProcessHeapHandle};
    use arinsal_term::{ProcessHeap, Term, TermBuilder, exact_eq};

    fn list_of(heap: &mut ProcessHeapHandle<'_>, n: i64) -> Term {
        let values: Vec<_> = (1..=n).map(|i| Term::small(i).unwrap()).collect();
        TermBuilder::new(heap).list_from_slice(&values).unwrap()
    }

    #[test]
    fn member_chunks_match_one_shot_and_charge_per_sixteen() {
        let mut heap = ProcessHeap::with_words(4096);
        let mut alloc = ProcessHeapHandle(&mut heap);
        let list = list_of(&mut alloc, 20);
        let miss = Term::small(99).unwrap();
        let mut ctx = Ctx::new(&mut alloc);
        let MemberStep::Done(found) = lists_member(&mut ctx, miss, list, usize::MAX).unwrap()
        else {
            panic!("unbounded member trapped");
        };
        assert!(!found);
        assert_eq!(ctx.reductions(), 0);

        let mut ctx = Ctx::new(&mut alloc);
        let mut rest = list;
        let mut steps = 0u32;
        loop {
            match lists_member(&mut ctx, miss, rest, 16).unwrap() {
                MemberStep::Done(found) => {
                    assert!(!found);
                    break;
                }
                MemberStep::More(cont) => {
                    assert_ne!(cont.list(), rest);
                    rest = cont.list();
                    steps += 1;
                }
            }
        }
        assert_eq!(steps, 1);
        // 16 cells then 4: ceil(16/16) + ceil(4/16) = 2, the same as one 20-cell call.
        assert_eq!(ctx.reductions(), 2);

        let mut ctx = Ctx::new(&mut alloc);
        let MemberStep::Done(true) =
            lists_member(&mut ctx, Term::small(7).unwrap(), list, 16).unwrap()
        else {
            panic!("hit inside the first chunk");
        };
        assert_eq!(ctx.reductions(), 1);
    }

    #[test]
    fn keyfind_chunk_stops_at_the_budget_and_a_short_hit_is_free() {
        let mut heap = ProcessHeap::with_words(4096);
        let mut alloc = ProcessHeapHandle(&mut heap);
        let mut tuples = Vec::new();
        {
            let mut builder = TermBuilder::new(&mut alloc);
            for i in 1..=10 {
                let n = Term::small(i).unwrap();
                tuples.push(builder.tuple(&[n, n]).unwrap());
            }
        }
        let list = TermBuilder::new(&mut alloc)
            .list_from_slice(&tuples)
            .unwrap();
        let key = Term::small(8).unwrap();
        let pos = Term::small(1).unwrap();
        let mut ctx = Ctx::new(&mut alloc);
        let mut rest = list;
        let mut steps = 0u32;
        let found = loop {
            match lists_key(&mut ctx, KeyOp::Find, key, pos, rest, 3).unwrap() {
                KeyOutcome::Done(value) => break value,
                KeyOutcome::More(cont) => {
                    rest = cont.list();
                    steps += 1;
                }
            }
        };
        assert_eq!(steps, 2);
        assert!(exact_eq(found, tuples[7]));
        assert_eq!(ctx.reductions(), 0);

        let five = TermBuilder::new(&mut alloc)
            .list_from_slice(&tuples[..5])
            .unwrap();
        let mut ctx = Ctx::new(&mut alloc);
        let KeyOutcome::Done(hit) = lists_key(
            &mut ctx,
            KeyOp::Find,
            Term::small(1).unwrap(),
            pos,
            five,
            10 * 4_000,
        )
        .unwrap() else {
            panic!("five-element keyfind trapped");
        };
        assert!(exact_eq(hit, tuples[0]));
        assert_eq!(ctx.reductions(), 0);
    }

    #[test]
    fn append_chunks_match_one_shot() {
        let mut heap = ProcessHeap::with_words(4096);
        let mut alloc = ProcessHeapHandle(&mut heap);
        let lhs = list_of(&mut alloc, 20);
        let rhs = Term::small(7).unwrap();
        let mut ctx = Ctx::new(&mut alloc);
        let AppendStep::Done(one_shot) = lists_append(
            &mut ctx,
            AppendCont::start(lhs, rhs),
            usize::MAX,
            usize::MAX,
        )
        .unwrap() else {
            panic!("unbounded append trapped");
        };
        let mut state = AppendCont::start(lhs, rhs);
        let chunked = loop {
            match lists_append(&mut ctx, state, 5, 5).unwrap() {
                AppendStep::Done(value) => break value,
                AppendStep::More(next) => state = next,
            }
        };
        assert!(exact_eq(one_shot, chunked));

        let mut ctx = Ctx::new(&mut alloc);
        let mut state = AppendCont::start(lhs, Term::NIL);
        let same = loop {
            match lists_append(&mut ctx, state, 4, 0).unwrap() {
                AppendStep::Done(value) => break value,
                AppendStep::More(next) => state = next,
            }
        };
        assert_eq!(same, lhs);
    }
}

crate::process_bif_bodies!(
    length, append, subtract, reverse, member, keyfind, keymember, keysearch,
);
