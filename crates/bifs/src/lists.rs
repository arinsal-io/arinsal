//! List BIFs. The per-element loops follow `erl_bif_lists.c` and `erl_bif_guard.c`.
//!
//! `erlang:'++'/2`, `erlang:'--'/2`, `lists:member/2`, `lists:keyfind/3`
//! (and keymember/keysearch), and `lists:reverse/2` stop on the same reduction
//! budget as erts and resume through the same continuations.

use arinsal_term::raw::UninitTermArray;
use arinsal_term::{
    ConsHeapChain, HeapAlloc, HeapReservation, ProcessHeap, Term, TermBuilder, atoms, exact_eq,
    exact_eq_after_word_mismatch, loose_eq,
};

#[path = "rbtree.rs"]
mod rbtree;

use crate::pure::{bool_term, integer};
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
        ("erlang", "length", 1) => v.entry::<word_bodies::length>(),
        _ => return None,
    };
    arinsal_spec::bif_lookup(module, name, arity).map(|_| f)
}

/// CAR/CDR of a cons cell.
#[inline(always)]
pub(crate) fn cons_cell(term: Term) -> Option<(Term, Term)> {
    // SAFETY: BIF arguments stay on the live process heap for this call.
    unsafe { term.cons_ref() }
}

/// Elements of `length/1` walked per reduction left.
// Port of `ERTS_BIF_REDS_LEFT(p) * 16` in `erts_trapping_length_1`,
// erts/emulator/beam/erl_bif_guard.c, OTP-29.1.1.
pub const LENGTH_PER_RED: usize = 16;

/// Resume arguments of `erlang:length/3`, the hidden trap target of `length/1`.
pub struct LengthCont {
    list: Term,
    acc: usize,
}

impl LengthCont {
    /// The cons not yet counted.
    pub fn list(&self) -> Term {
        self.list
    }

    /// The length counted so far.
    pub fn acc(&self) -> usize {
        self.acc
    }
}

/// One slice of `length/1`.
pub enum LengthStep {
    /// The length.
    Done(Term),
    /// `BIF_TRAP3` with the rest of the list and the length so far.
    More(LengthCont),
}

/// Count `list` for the reductions left, starting from `acc`.
// Port of erts/emulator/beam/erl_bif_guard.c:270-320 (erts_trapping_length_1), OTP-29.1.1.
pub fn length_slice(ctx: &mut Ctx<'_>, mut list: Term, acc: usize) -> Result<LengthStep, BifError> {
    let budget = ctx.reduction_budget();
    let saved_max_iter = if budget == usize::MAX {
        usize::MAX
    } else {
        budget.saturating_mul(LENGTH_PER_RED)
    };
    let mut max_iter = saved_max_iter;
    let mut count = acc;
    while max_iter != 0 {
        let Some((_, tail)) = cons_cell(list) else {
            break;
        };
        list = tail;
        count += 1;
        max_iter -= 1;
    }
    if cons_cell(list).is_some() {
        ctx.bump_all_reds();
        return Ok(LengthStep::More(LengthCont { list, acc: count }));
    }
    if list != Term::NIL {
        return Err(BADARG);
    }
    if saved_max_iter != usize::MAX {
        ctx.charge_reductions((saved_max_iter - max_iter) / LENGTH_PER_RED);
    }
    Ok(LengthStep::Done(integer(ctx, count)?))
}

fn length(ctx: &mut Ctx<'_>, args: &[Term]) -> Term {
    // Port of erts/emulator/beam/erl_bif_guard.c:210-224 (length_1), OTP-29.1.1.
    let &[list] = args else {
        return ctx.badarg();
    };
    match length_slice(ctx, list, 0) {
        Ok(LengthStep::Done(value)) => value,
        Ok(LengthStep::More(cont)) => ctx.trap(DeferredTrap::Length(cont)),
        Err(error) => ctx.fail(error),
    }
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
    /// Address of the final CDR slot, or zero while the result is still empty.
    last_cdr: usize,
}

impl AppendCont {
    /// Start from the two arguments of `++`.
    pub fn start(lhs: Term, rhs: Term) -> Self {
        Self {
            lhs_original: lhs,
            rhs,
            iterator: lhs,
            result: Term::NIL,
            last_cdr: 0,
        }
    }

    /// List cells not yet copied.
    pub fn iterator(&self) -> Term {
        self.iterator
    }

    /// `lhs_original`: the left argument of the first call.
    pub fn lhs_original(&self) -> Term {
        self.lhs_original
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

#[inline(always)]
fn keysearch_result(ctx: &mut Ctx<'_>, tuple: Term) -> Term {
    // Port of lists_keysearch_3's HAlloc(3) and TUPLE2 at
    // erts/emulator/beam/erl_bif_lists.c:1280-1291, OTP-29.1.1.
    TermBuilder::new(&mut ctx.heap)
        .tuple2(Term::atom(atoms::VALUE), tuple)
        .expect("infallible BIF heap")
}

/// Continuation built only after a slice's counter runs out.
pub enum DeferredTrap {
    /// `erlang:binary_to_list/1` and `/3`.
    BinaryToList(crate::pure::BinaryToListWalk),
    /// `erlang:crc32/1,2`, `adler32/1,2` or `md5/1`.
    Chksum(crate::checksum::ChksumCont),
    /// `unicode:characters_to_binary/2` and `characters_to_list/2`.
    Unicode(crate::unicode::UnicodeCont),
    /// `erlang:length/1`.
    Length(LengthCont),
    /// `erlang:phash2/1,2`.
    Phash2(Box<crate::pure::Phash2Cont>),
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
        let mut last_cdr: *mut u64 = if state.last_cdr == 0 {
            std::ptr::null_mut()
        } else {
            state.last_cdr as *mut u64
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
            // erts folds the reduction budget and heap limit into alloc_end before the copy loop.
            let available_words = words - 1;
            let alloc_words = if onheap_cells == usize::MAX {
                available_words
            } else {
                onheap_cells.saturating_mul(2).min(available_words)
            };
            let alloc_end = alloc_top.wrapping_add(alloc_words);
            while alloc_top < alloc_end && is_list_bits(list_bits) {
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
            AppendStep::More(AppendCont {
                lhs_original,
                rhs: rhs_term,
                iterator: Term::from_raw_bits(list_bits),
                result: Term::from_raw_bits(head_bits),
                last_cdr: last_cdr as usize,
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
    Lhs(UninitTermArray<16>),
    Rhs(UninitTermArray<16>),
    Set(RbTree),
}

enum SubtractNaiveLhsResult {
    Complete(Term),
    Trapped {
        elements: UninitTermArray<16>,
        iterator: Term,
        remaining: usize,
    },
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

    /// `(lhs_original, rhs_original)`: the arguments of the first call.
    pub fn originals(&self) -> (Term, Term) {
        (self.lhs, self.rhs)
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
                        let mut elements = UninitTermArray::new();
                        let mut iterator = self.lhs;
                        if !elements.fill_with(self.lhs_remaining, || {
                            let (head, tail) = cons_cell(iterator)?;
                            iterator = tail;
                            Some(head)
                        }) {
                            return Err(BADARG);
                        }
                        let budget = subtract_budget(ctx, reductions_left, 16);
                        match subtract_naive_lhs_step(ctx, elements, self.rhs, budget)? {
                            SubtractNaiveLhsResult::Complete(result) => return Ok(Some(result)),
                            SubtractNaiveLhsResult::Trapped {
                                elements,
                                iterator,
                                remaining,
                            } => {
                                self.iterator = iterator;
                                self.lhs_remaining = remaining;
                                self.scratch = SubtractScratch::Lhs(elements);
                                self.stage = SubtractStage::NaiveLhs;
                                return Ok(None);
                            }
                        }
                    } else {
                        self.iterator = self.rhs;
                        self.stage = SubtractStage::LenRhs;
                    }
                }
                SubtractStage::NaiveLhs => {
                    let budget = subtract_budget(ctx, reductions_left, 16);
                    let SubtractScratch::Lhs(elements) =
                        std::mem::replace(&mut self.scratch, SubtractScratch::Empty)
                    else {
                        unreachable!("naive LHS stage owns its fixed array")
                    };
                    match subtract_naive_lhs_step(ctx, elements, self.iterator, budget)? {
                        SubtractNaiveLhsResult::Complete(result) => return Ok(Some(result)),
                        SubtractNaiveLhsResult::Trapped {
                            elements,
                            iterator,
                            remaining,
                        } => {
                            self.iterator = iterator;
                            self.lhs_remaining = remaining;
                            self.scratch = SubtractScratch::Lhs(elements);
                            return Ok(None);
                        }
                    }
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
                        let mut elements = UninitTermArray::new();
                        let mut iterator = self.rhs;
                        if !elements.fill_with(self.rhs_remaining, || {
                            let (head, tail) = cons_cell(iterator)?;
                            iterator = tail;
                            Some(head)
                        }) {
                            return Err(BADARG);
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
                .find(|&i| exact_eq(value, elements.get(i)));
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
                elements.set(found_at, elements.get(self.rhs_remaining));
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

/// Runs the short-LHS scan with its working values held in stack locals.
///
/// Port of `subtract_naive_lhs` in `erl_bif_lists.c:632-684`, OTP-29.1.1.
#[inline(always)]
fn subtract_naive_lhs_step(
    ctx: &mut Ctx<'_>,
    mut elements: UninitTermArray<16>,
    mut iterator: Term,
    budget: usize,
) -> Result<SubtractNaiveLhsResult, BifError> {
    let mut checks = 0usize;
    while checks < budget {
        let Some((value, next)) = cons_cell(iterator) else {
            break;
        };
        let found_at = elements
            .as_slice()
            .iter()
            .position(|&element| subtract_term_eq(value, element));
        if let Some(index) = found_at {
            elements.shift_down(index);
        }
        checks += elements.len().max(1);
        iterator = next;
    }
    ctx.charge_reductions(checks.min(budget) / 16);
    if iterator != Term::NIL {
        if iterator.classify() != arinsal_term::TermKind::List {
            return Err(BADARG);
        }
        let remaining = elements.len();
        return Ok(SubtractNaiveLhsResult::Trapped {
            elements,
            iterator,
            remaining,
        });
    }
    subtract_list_from_slice(ctx, elements.as_slice(), Term::NIL)
        .map(SubtractNaiveLhsResult::Complete)
}

/// Mirrors erts `EQ`: equal words match directly; non-identical immediates cannot match.
#[inline(always)]
fn subtract_term_eq(left: Term, right: Term) -> bool {
    left == right
        || (!(left.is_immed() && right.is_immed()) && exact_eq_after_word_mismatch(left, right))
}

/// Build the small-LHS result backwards in one reserved heap block.
/// Port of `erl_bif_lists.c:665-684` (`subtract_naive_lhs`), OTP-29.1.1.
#[inline(always)]
fn subtract_list_from_slice(
    ctx: &mut Ctx<'_>,
    items: &[Term],
    tail: Term,
) -> Result<Term, BifError> {
    if items.is_empty() {
        return Ok(tail);
    }
    let builder = TermBuilder::new(&mut ctx.heap)
        .reserve_cons_list(items.len())
        .map_err(|_| BifError::SystemLimit)?;
    builder
        .prepend_exact_with_tail(items.iter().rev().copied(), tail)
        .map_err(|_| BifError::SystemLimit)
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
        while let Some((reversed, next)) = cursor.push_cons_with(|| {
            let (head, next) = cons_cell(current)?;
            Some((head, result_tail, next))
        }) {
            result_tail = reversed;
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
    let builder = TermBuilder::new(&mut ctx.heap)
        .reserve_cons_list(count)
        .map_err(|_| BifError::SystemLimit)?;
    let mut list = current;
    result_tail = builder
        .prepend_exact_with_tail(
            std::iter::from_fn(|| {
                let (head, next) = cons_cell(list)?;
                list = next;
                Some(head)
            })
            .take(count),
            result_tail,
        )
        .map_err(|_| BifError::SystemLimit)?;
    current = list;
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

/// `lists_reverse_2` for a list that fits the free young heap and the reduction budget: the
/// whole reversal is built in `[HEAP_TOP, HEAP_LIMIT - 2)` with raw cons writes and `HEAP_TOP`
/// is published once. Anything else (budget or window exhausted, improper list) returns `None`
/// with nothing committed, and the general path redoes the call.
// Port of erts/emulator/beam/erl_bif_lists.c:1194-1262 (lists_reverse_2, lists_reverse_onheap),
// OTP-29.1.1.
#[inline(always)]
pub fn reverse_onheap_direct(heap: &mut ProcessHeap, list: Term, tail: Term) -> Option<Term> {
    if list == Term::NIL {
        return Some(tail);
    }
    let reds = heap.abi.fcalls.clamp(0, 4000) as usize;
    let window = heap.halloc_window()?;
    // HeapWordsLeft(c_p) > 8
    if window.len() <= 8 {
        return None;
    }
    // Don't process more cells than there are reductions for, and keep HEAP_LIMIT - 2 free.
    let max_cells = (reds * REVERSE_ONHEAP_CELLS_PER_RED).min((window.len() - 2).div_ceil(2));
    let (mut cur, mut tail_bits) = (list, tail.word());
    let window_cells = window.as_chunks_mut::<2>().0.get_mut(..max_cells)?;
    let base = window_cells.as_ptr() as usize;
    for cell in window_cells.iter_mut() {
        let Some((car, cdr)) = cons_cell(cur) else {
            break;
        };
        cell[0] = car.word();
        cell[1] = tail_bits;
        tail_bits = (cell.as_mut_ptr() as u64) | 1;
        cur = cdr;
    }
    if cur != Term::NIL {
        return None;
    }
    let cells = (((tail_bits as usize) & !7) - base) / 16 + 1;
    // The result is the last cell written, the first one above HEAP_TOP's new position.
    let result = heap.window_list_term((cells - 1) * 2);
    heap.commit_window(cells * 2);
    // BUMP_REDS(c_p, cells / CELLS_PER_RED)
    let reds_used = cells / REVERSE_ONHEAP_CELLS_PER_RED;
    if reds_used != 0 {
        heap.abi.fcalls = (heap.abi.fcalls - reds_used as i32).max(0);
    }
    Some(result)
}

/// `'++'/2` for a left list that fits the free young heap and the reduction budget, with a
/// right side that is not nil: the copy is built in `[HEAP_TOP, HEAP_LIMIT - 2)`, the last CDR
/// is the right side, and `HEAP_TOP` is published once. Nothing is committed when the window
/// or budget runs out first (`None`).
// Port of erts/emulator/beam/erl_bif_lists.c:211-251 (lists_append_onheap) and :273-290
// (append), OTP-29.1.1.
#[inline(always)]
pub fn append_onheap_direct(heap: &mut ProcessHeap, lhs: Term, rhs: Term) -> Option<Term> {
    if lhs == Term::NIL {
        // `[] ++ X` is X, whatever X is.
        return Some(rhs);
    }
    if rhs == Term::NIL || cons_cell(lhs).is_none() {
        return None;
    }
    let reds = heap.abi.fcalls.clamp(0, 4000) as usize;
    let window = heap.halloc_window()?;
    // HeapWordsLeft(c_p) > 8
    if window.len() <= 8 {
        return None;
    }
    let max_cells = (reds * APPEND_ONHEAP_PER_RED).min((window.len() - 2).div_ceil(2));
    let base = window.as_ptr() as u64;
    let (mut cur, mut cells) = (lhs, 0usize);
    for cell in window.as_chunks_mut::<2>().0.iter_mut().take(max_cells) {
        let Some((car, cdr)) = cons_cell(cur) else {
            break;
        };
        cell[0] = car.word();
        // Each CDR links the following cell, except the last one: the right side. An improper
        // left list leaves a bogus link in the unpublished window and is rejected below.
        cell[1] = if cdr == Term::NIL {
            rhs.word()
        } else {
            (base + ((cells as u64) + 1) * 16) | 1
        };
        cur = cdr;
        cells += 1;
    }
    if cur != Term::NIL {
        return None;
    }
    let result = heap.window_list_term(0);
    heap.commit_window(cells * 2);
    // BUMP_REDS(c_p, cells / CELLS_PER_RED)
    let reds_used = cells / APPEND_ONHEAP_PER_RED;
    if reds_used != 0 {
        heap.abi.fcalls = (heap.abi.fcalls - reds_used as i32).max(0);
    }
    Some(result)
}

/// Scan at most `max_iter` conses of `lists:member/2`.
///
/// `max_iter` is `16 * ERTS_BIF_REDS_LEFT` (`erl_bif_lists.c:1115`). `usize::MAX`
/// finishes a finite list. A full chunk charges `div_ceil(scanned, 16)`, which is
/// `BUMP_ALL_REDS` when the chunk is exactly one reduction budget and
/// `BIF_RET2`'s `reds_left - max_iter/16` otherwise.
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
        if term_bits & 3 == 3 {
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
                    charge(ctx, scanned);
                    return Ok(MemberStep::Done(true));
                }
                list_bits = next;
            }
        } else {
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
                if car == term_bits || exact_eq_after_word_mismatch(Term::from_raw_bits(car), term)
                {
                    charge(ctx, scanned);
                    return Ok(MemberStep::Done(true));
                }
                list_bits = next;
            }
        }
        if list_bits != nil_bits {
            charge(ctx, scanned);
            return Err(BADARG);
        }
        charge(ctx, scanned);
        Ok(MemberStep::Done(false))
    }
}

#[inline]
fn key_search(args: &[Term], max_iter: usize) -> Result<KeyfindStep, BifError> {
    // Port of erts/emulator/beam/erl_bif_lists.c:1302 (keyfind), OTP-29.1.1.
    // Three loops: a small key also matches a float of the same value, any other
    // immediate compares by word, and a boxed key uses `==`. `max_iter` is
    // `10 * CONTEXT_REDS` (not scaled by reductions left). A hit returns the
    // tuple without reading the rest and without bumping reductions.
    let &[key, pos_term, list] = args else {
        return Err(BADARG);
    };
    let pos = pos_term.as_small().ok_or(BADARG)?;
    if pos < 1 {
        return Err(BADARG);
    }
    // SAFETY: list, tuple, and float words stay on the live process heap.
    // Boxed tag 2: the header is at tagged-2 and element `pos` (1-based) is
    // `header[pos]`, matching `tuple_val` / `arityval` in keyfind.
    unsafe {
        let pos_u = pos as u64;
        let key_bits = key.raw_bits();
        let mut list_bits = list.raw_bits();
        let nil_bits = Term::NIL.raw_bits();
        let mut remaining = max_iter;
        if let Some(small) = key.as_small() {
            let float_key = small as f64;
            while is_list_bits(list_bits) {
                if remaining == 0 {
                    return Ok(KeyfindStep::More(KeyfindCont {
                        key,
                        pos: pos_term,
                        list: Term::from_raw_bits(list_bits),
                    }));
                }
                remaining -= 1;
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
                    return Ok(KeyfindStep::Done(Some(Term::from_raw_bits(car))));
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
                    return Ok(KeyfindStep::Done(Some(Term::from_raw_bits(car))));
                }
            }
        } else if key_bits & 3 == 3 {
            while is_list_bits(list_bits) {
                if remaining == 0 {
                    return Ok(KeyfindStep::More(KeyfindCont {
                        key,
                        pos: pos_term,
                        list: Term::from_raw_bits(list_bits),
                    }));
                }
                remaining -= 1;
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
                    return Ok(KeyfindStep::Done(Some(Term::from_raw_bits(car))));
                }
            }
        } else {
            while is_list_bits(list_bits) {
                if remaining == 0 {
                    return Ok(KeyfindStep::More(KeyfindCont {
                        key,
                        pos: pos_term,
                        list: Term::from_raw_bits(list_bits),
                    }));
                }
                remaining -= 1;
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
                    return Ok(KeyfindStep::Done(Some(Term::from_raw_bits(car))));
                }
            }
        }
        if list_bits != nil_bits {
            return Err(BADARG);
        }
        Ok(KeyfindStep::Done(None))
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
                    Some(tuple) => keysearch_result(ctx, tuple),
                    None => bool_term(false),
                },
            };
            Ok(KeyOutcome::Done(value))
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
        let mut bif_state = crate::BifState::default();
        let mut ctx = Ctx::new(&mut alloc, &mut bif_state);
        let step = super::lists_append(
            &mut ctx,
            super::AppendCont::start(list, Term::NIL),
            usize::MAX,
            usize::MAX,
        );
        let Ok(super::AppendStep::Done(out)) = step else {
            panic!("append did not finish");
        };
        assert_eq!(out, list);
    }

    fn small_list(heap: &mut ProcessHeap, n: usize) -> Term {
        let items: Vec<Term> = (0..n).map(|i| Term::small(i as i64).unwrap()).collect();
        let mut alloc = ProcessHeapHandle(heap);
        TermBuilder::new(&mut alloc)
            .list_from_slice(&items)
            .unwrap()
    }

    fn elements(term: Term) -> (Vec<i64>, Term) {
        let mut out = Vec::new();
        let mut cur = term;
        while let Some((head, tail)) = super::cons_cell(cur) {
            out.push(head.as_small().unwrap());
            cur = tail;
        }
        (out, cur)
    }

    #[test]
    fn reverse_onheap_direct_matches_the_general_reverse() {
        for n in [0usize, 1, 2, 3, 10, 100] {
            let mut heap = ProcessHeap::with_words(4096);
            heap.abi.fcalls = 4000;
            let list = small_list(&mut heap, n);
            let tail = Term::small(777).unwrap();
            let htop = heap.abi.htop;
            let fcalls = heap.abi.fcalls;
            let out = super::reverse_onheap_direct(&mut heap, list, tail).expect("fits");
            let (got, end) = elements(out);
            let mut want: Vec<i64> = (0..n as i64).collect();
            want.reverse();
            assert_eq!(got, want, "n = {n}");
            assert_eq!(end, tail);
            // Cells come from the young heap and HEAP_TOP moves by exactly 2 words per cell.
            let moved = (heap.abi.htop as usize - htop as usize) / 8;
            assert_eq!(moved, if n == 0 { 0 } else { 2 * n });
            assert!(heap.abi.fcalls <= fcalls);
        }
    }

    #[test]
    fn reverse_onheap_direct_commits_nothing_when_it_cannot_finish() {
        // An improper list, a non-list, and a list longer than the free window.
        let mut heap = ProcessHeap::with_words(64);
        heap.abi.fcalls = 4000;
        let improper = {
            let mut alloc = ProcessHeapHandle(&mut heap);
            TermBuilder::new(&mut alloc)
                .cons(Term::small(1).unwrap(), Term::small(2).unwrap())
                .unwrap()
        };
        let htop = heap.abi.htop;
        assert!(super::reverse_onheap_direct(&mut heap, improper, Term::NIL).is_none());
        assert!(
            super::reverse_onheap_direct(&mut heap, Term::small(5).unwrap(), Term::NIL).is_none()
        );
        let long = small_list(&mut heap, 20);
        let htop_after = heap.abi.htop;
        assert!(super::reverse_onheap_direct(&mut heap, long, Term::NIL).is_none());
        assert_eq!(heap.abi.htop, htop_after);
        assert!(htop <= htop_after);
    }

    #[test]
    fn onheap_direct_paths_stop_at_the_reduction_budget() {
        // One reduction pays for 60 cells: a longer list is left to the trapping path.
        let mut heap = ProcessHeap::with_words(4096);
        heap.abi.fcalls = 1;
        let list = small_list(&mut heap, 100);
        let htop = heap.abi.htop;
        assert!(super::reverse_onheap_direct(&mut heap, list, Term::NIL).is_none());
        assert!(super::append_onheap_direct(&mut heap, list, Term::small(1).unwrap()).is_none());
        assert_eq!(heap.abi.htop, htop);
        let short = small_list(&mut heap, 50);
        assert!(super::reverse_onheap_direct(&mut heap, short, Term::NIL).is_some());
    }

    #[test]
    fn append_onheap_direct_copies_the_left_list_and_shares_the_right() {
        for n in [1usize, 2, 5, 10, 100] {
            let mut heap = ProcessHeap::with_words(4096);
            heap.abi.fcalls = 4000;
            let left = small_list(&mut heap, n);
            let right = Term::small(9).unwrap();
            let htop = heap.abi.htop;
            let out = super::append_onheap_direct(&mut heap, left, right).expect("fits");
            let (got, end) = elements(out);
            assert_eq!(got, (0..n as i64).collect::<Vec<_>>());
            assert_eq!(
                end, right,
                "an improper right side is kept as the last tail"
            );
            assert_ne!(out, left, "the left list is copied");
            let moved = (heap.abi.htop as usize - htop as usize) / 8;
            assert_eq!(moved, 2 * n);
        }
        let mut heap = ProcessHeap::with_words(256);
        heap.abi.fcalls = 4000;
        let list = small_list(&mut heap, 3);
        // `[] ++ X` is X; a nil right side and non-lists are left to the general path.
        assert_eq!(
            super::append_onheap_direct(&mut heap, Term::NIL, list),
            Some(list)
        );
        assert!(super::append_onheap_direct(&mut heap, list, Term::NIL).is_none());
        assert!(super::append_onheap_direct(&mut heap, Term::small(1).unwrap(), list).is_none());
        let htop = heap.abi.htop;
        let improper = {
            let mut alloc = ProcessHeapHandle(&mut heap);
            TermBuilder::new(&mut alloc)
                .cons(Term::small(1).unwrap(), Term::small(2).unwrap())
                .unwrap()
        };
        let before = heap.abi.htop;
        assert!(super::append_onheap_direct(&mut heap, improper, list).is_none());
        assert_eq!(heap.abi.htop, before);
        assert!(htop <= before);
    }

    #[test]
    fn integer_to_list_is_one_allocation_even_when_the_heap_is_nearly_full() {
        let mut heap = ProcessHeap::with_words(64);
        let left = heap.halloc_words_left().unwrap();
        assert!(heap.alloc_halloc(left - 3).is_some());
        let used = heap.used_words();
        let mut alloc = ProcessHeapHandle(&mut heap);
        let mut bif_state = crate::BifState::default();
        let mut ctx = Ctx::new(&mut alloc, &mut bif_state);
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
        let mut heap = ProcessHeap::with_words(4096);
        let mut allocator = ProcessHeapHandle(&mut heap);
        let terms = args
            .iter()
            .map(|value| from_owned(value, &mut allocator).unwrap())
            .collect::<Vec<_>>();
        let result = {
            let mut bif_state = crate::BifState::default();
            let mut ctx = Ctx::new(&mut allocator, &mut bif_state);
            // `subtract` with an unbounded budget: the stages run to completion.
            SubtractWalk::new(terms[0], terms[1]).and_then(|mut walk| {
                loop {
                    if let Some(value) = walk.step(&mut ctx, usize::MAX)? {
                        break Ok(value);
                    }
                }
            })
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
                let mut bif_state = crate::BifState::default();
                let mut ctx = Ctx::new(&mut allocator, &mut bif_state);
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
        let mut bif_state = crate::BifState::default();
        let mut ctx = Ctx::new(&mut alloc, &mut bif_state);
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
        let mut bif_state = crate::BifState::default();
        let mut ctx = Ctx::new(&mut alloc, &mut bif_state);
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
        let mut bif_state = crate::BifState::default();
        let mut ctx = Ctx::new(&mut alloc, &mut bif_state);
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
        let mut bif_state = crate::BifState::default();
        let mut ctx = Ctx::new(&mut alloc, &mut bif_state);
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
        let mut bif_state = crate::BifState::default();
        let mut ctx = Ctx::new(&mut alloc, &mut bif_state);
        let MemberStep::Done(found) = lists_member(&mut ctx, miss, list, usize::MAX).unwrap()
        else {
            panic!("unbounded member trapped");
        };
        assert!(!found);
        assert_eq!(ctx.reductions(), 0);

        let mut bif_state = crate::BifState::default();
        let mut ctx = Ctx::new(&mut alloc, &mut bif_state);
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

        let mut bif_state = crate::BifState::default();
        let mut ctx = Ctx::new(&mut alloc, &mut bif_state);
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
        let mut bif_state = crate::BifState::default();
        let mut ctx = Ctx::new(&mut alloc, &mut bif_state);
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
        let mut bif_state = crate::BifState::default();
        let mut ctx = Ctx::new(&mut alloc, &mut bif_state);
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
        let mut bif_state = crate::BifState::default();
        let (one_shot, chunked) = {
            let mut ctx = Ctx::new(&mut alloc, &mut bif_state);
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
            (one_shot, chunked)
        };
        assert!(exact_eq(one_shot, chunked));

        let same = {
            let mut ctx = Ctx::new(&mut alloc, &mut bif_state);
            let mut state = AppendCont::start(lhs, Term::NIL);
            loop {
                match lists_append(&mut ctx, state, 4, 0).unwrap() {
                    AppendStep::Done(value) => break value,
                    AppendStep::More(next) => state = next,
                }
            }
        };
        assert_eq!(same, lhs);
    }
}

crate::word_bif_bodies_in!(word_bodies; length);
