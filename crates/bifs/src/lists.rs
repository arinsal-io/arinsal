//! List BIFs. The per-element loops follow `erl_bif_lists.c` and `erl_bif_guard.c`.
//!
//! Most loops finish in one call; `erlang:'--'/2` exposes its staged walk to the
//! VM so the scheduler can resume it through the same continuation as erts.

use arinsal_term::{
    ConsHeapChain, HeapAlloc, HeapReservation, Term, TermBuilder, atoms, exact_eq, loose_eq,
};

#[path = "rbtree.rs"]
mod rbtree;

use crate::pure::{bool_term, integer, tuple_build};
use crate::{BifError, BifFn, Ctx};
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

pub(super) fn lookup(module: &str, name: &str, arity: u8) -> Option<BifFn> {
    let f: BifFn = match (module, name, arity) {
        ("erlang", "length", 1) => length,
        ("erlang", "++" | "append", 2) => append,
        ("erlang", "--" | "subtract", 2) => subtract,
        ("lists", "reverse", 2) => reverse,
        ("lists", "member", 2) => member,
        ("lists", "keyfind", 3) => keyfind,
        ("lists", "keymember", 3) => keymember,
        ("lists", "keysearch", 3) => keysearch,
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

fn append(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    // Port of erts/emulator/beam/erl_bif_lists.c:176 (lists_append_onheap) and
    // :111 (lists_append_alloc), OTP-29.1.1. The reduction trap is a later task;
    // a list that fits is copied with one bump of the free window.
    let list = args[0];
    let rhs = args[1];
    if list == Term::NIL {
        return Ok(rhs);
    }
    if rhs == Term::NIL {
        proper_len(list)?;
        return Ok(list);
    }
    // SAFETY: source cons cells stay live. Destination words come from one
    // HAlloc of the young-heap window (or of the exact remainder). CAR/CDR use
    // the tagged offsets from lists_append_onheap; the previous CDR slot is
    // linked with make_list, and the right-hand side is stored once at the end.
    unsafe {
        let mut list_bits = list.raw_bits();
        let rhs_bits = rhs.raw_bits();
        if !is_list_bits(list_bits) {
            return Err(BADARG);
        }
        let nil_bits = Term::NIL.raw_bits();
        let mut head_bits = nil_bits;
        let mut last_cdr: *mut u64 = std::ptr::null_mut();
        if let Some(left) = ctx.heap.words_left()
            && left > 8
        {
            let words = left - 2;
            let mut reserved = HeapReservation::new(ctx.heap, words).expect("infallible BIF heap");
            let mut alloc_top = reserved.cursor();
            // Two words per cell; `limit` is exclusive, so stop one word early.
            let alloc_end = reserved.limit().wrapping_sub(1);
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
            }
            reserved.set_cursor(alloc_top);
        }
        if !is_list_bits(list_bits) {
            if list_bits != nil_bits {
                // An improper list must not leave the last tail slot uninitialized.
                if !last_cdr.is_null() {
                    last_cdr.write(nil_bits);
                }
                return Err(BADARG);
            }
            if last_cdr.is_null() {
                return Ok(rhs);
            }
            last_cdr.write(rhs_bits);
            return Ok(Term::from_raw_bits(head_bits));
        }
        let mut count = 0usize;
        let mut scan = list_bits;
        while is_list_bits(scan) {
            let (_, next) = car_cdr!(scan);
            count += 1;
            scan = next;
        }
        if scan != nil_bits {
            if !last_cdr.is_null() {
                last_cdr.write(nil_bits);
            }
            return Err(BADARG);
        }
        let words = count.checked_mul(2).ok_or(BifError::SystemLimit)?;
        let alloc_top = HeapAlloc::alloc(ctx.heap, words).expect("infallible BIF heap");
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
        last_cdr.write(rhs_bits);
        Ok(Term::from_raw_bits(head_bits))
    }
}

fn subtract(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    // Port of erts/emulator/beam/erl_bif_lists.c:367-1020 (subtract stages),
    // OTP-29.1.1. Runtime dispatch uses `SubtractWalk` to retain this state on trap.
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
                let mut result = SubtractResultBuilder::new(ctx.heap);
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
                let mut result = SubtractResultBuilder::new(ctx.heap);
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
                    .push(ctx.heap, value, self.lhs_remaining)
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
                    .push(ctx.heap, value, self.lhs_remaining)
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
struct SubtractResultBuilder<'a> {
    heap: &'a mut (dyn HeapAlloc + 'a),
    chain: ConsHeapChain,
}

impl<'a> SubtractResultBuilder<'a> {
    fn new(heap: &'a mut (dyn HeapAlloc + 'a)) -> Self {
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
        HeapReservation::new(ctx.heap, words).map_err(|_| BifError::SystemLimit)?;
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

fn reverse(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    // Port of erts/emulator/beam/erl_bif_lists.c:1246 (lists_reverse_2),
    // lists_reverse_onheap, and lists_reverse_alloc, OTP-29.1.1.
    // The reduction trap is a later task. The fill is CONS(hp, CAR, tail)
    // with a raw heap-top bump, the same stores as the on-heap loop.
    let list = args[0];
    let tail = args[1];
    if list == Term::NIL {
        return Ok(tail);
    }
    // SAFETY: source cons cells stay live. Destination words come from one
    // HAlloc of the young-heap window (or of the exact remainder).
    unsafe {
        let mut list_bits = list.raw_bits();
        let mut tail_bits = tail.raw_bits();
        if !is_list_bits(list_bits) {
            return Err(BADARG);
        }
        let nil_bits = Term::NIL.raw_bits();
        if let Some(left) = ctx.heap.words_left()
            && left > 8
        {
            let words = left - 2;
            let mut reserved = HeapReservation::new(ctx.heap, words).expect("infallible BIF heap");
            let mut alloc_top = reserved.cursor();
            // Two words per cell; `limit` is exclusive, so stop one word early.
            let alloc_end = reserved.limit().wrapping_sub(1);
            while alloc_top < alloc_end && is_list_bits(list_bits) {
                let (car, next) = car_cdr!(list_bits);
                alloc_top.write(car);
                alloc_top.add(1).write(tail_bits);
                tail_bits = (alloc_top as u64) | 1;
                alloc_top = alloc_top.add(2);
                list_bits = next;
            }
            reserved.set_cursor(alloc_top);
        }
        if !is_list_bits(list_bits) {
            if list_bits != nil_bits {
                return Err(BADARG);
            }
            return Ok(Term::from_raw_bits(tail_bits));
        }
        let mut count = 0usize;
        let mut scan = list_bits;
        while is_list_bits(scan) {
            let (_, next) = car_cdr!(scan);
            count += 1;
            scan = next;
        }
        if scan != nil_bits {
            return Err(BADARG);
        }
        let words = count.checked_mul(2).ok_or(BifError::SystemLimit)?;
        let mut alloc_top = HeapAlloc::alloc(ctx.heap, words).expect("infallible BIF heap");
        for _ in 0..count {
            let (car, next) = car_cdr!(list_bits);
            alloc_top.write(car);
            alloc_top.add(1).write(tail_bits);
            tail_bits = (alloc_top as u64) | 1;
            alloc_top = alloc_top.add(2);
            list_bits = next;
        }
        Ok(Term::from_raw_bits(tail_bits))
    }
}

fn member(_: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    // Port of erts/emulator/beam/erl_bif_lists.c:1108 (lists_member_2), OTP-29.1.1.
    // Two loops, as in the C: an immediate compares by word (`ldur` CAR, `cmp`,
    // `ldur` CDR, test list bit 1). Only a boxed term falls through to `eq`.
    // The reduction counter is a later task.
    let term = args[0];
    let list = args[1];
    // SAFETY: a list tag denotes two live words. Offsets -1 and +7 are CAR/CDR.
    unsafe {
        let term_bits = term.raw_bits();
        let mut list_bits = list.raw_bits();
        let nil_bits = Term::NIL.raw_bits();
        if term_bits & 3 == 3 {
            while is_list_bits(list_bits) {
                let (car, next) = car_cdr!(list_bits);
                if car == term_bits {
                    return Ok(bool_term(true));
                }
                list_bits = next;
            }
        } else {
            while is_list_bits(list_bits) {
                let (car, next) = car_cdr!(list_bits);
                if car == term_bits || exact_eq(Term::from_raw_bits(car), term) {
                    return Ok(bool_term(true));
                }
                list_bits = next;
            }
        }
        if list_bits != nil_bits {
            return Err(BADARG);
        }
    }
    Ok(bool_term(false))
}

fn key_search(args: &[Term]) -> Result<Option<Term>, BifError> {
    // Port of erts/emulator/beam/erl_bif_lists.c:1302 (keyfind), OTP-29.1.1.
    // Three loops: a small key also matches a float of the same value, any other
    // immediate compares by word, and a boxed key uses `==`. The reduction trap
    // is a later task. A hit returns the tuple without reading the rest.
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
        let found = if let Some(small) = key.as_small() {
            let float_key = small as f64;
            let mut found = None;
            while is_list_bits(list_bits) {
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
            Ok(Some(Term::from_raw_bits(bits)))
        } else {
            Ok(None)
        }
    }
}

fn keyfind(_: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    Ok(key_search(args)?.unwrap_or(bool_term(false)))
}

fn keymember(_: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    Ok(bool_term(key_search(args)?.is_some()))
}

fn keysearch(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    Ok(match key_search(args)? {
        Some(value) => tuple_build(ctx, &[Term::atom(atoms::VALUE), value]),
        None => bool_term(false),
    })
}

#[cfg(test)]
mod tests {
    use super::lookup;
    use crate::{Ctx, FragmentingHeap};
    use arinsal_term::{ProcessHeap, Term, TermBuilder};

    #[test]
    fn append_empty_right_keeps_the_left_list() {
        let mut heap = ProcessHeap::with_words(64);
        let mut alloc = FragmentingHeap(&mut heap);
        let list = TermBuilder::new(&mut alloc)
            .list_from_slice(&[Term::small(1).unwrap(), Term::small(2).unwrap()])
            .unwrap();
        let mut ctx = Ctx::new(&mut alloc);
        let out = lookup("erlang", "++", 2).unwrap()(&mut ctx, &[list, Term::NIL]).unwrap();
        assert_eq!(out, list);
    }
}

#[cfg(test)]
mod subtract_tests {
    use super::*;
    use crate::FragmentingHeap;
    use arinsal_difftest::{CallResult, CompareMode, RefErl, compare};
    use arinsal_etf::OwnedTerm as O;
    use arinsal_term::{ProcessHeap, from_owned, to_owned};

    fn local_call(args: &[O]) -> CallResult {
        let bif = crate::lookup("erlang", "--", 2).unwrap();
        let mut heap = ProcessHeap::with_words(4096);
        let mut allocator = FragmentingHeap(&mut heap);
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
        let mut allocator = FragmentingHeap(&mut heap);
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
