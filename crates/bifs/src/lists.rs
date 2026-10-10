//! List BIFs. The per-element loops follow `erl_bif_lists.c` and `erl_bif_guard.c`.
//!
//! Reduction traps (`BIF_TRAP` / `ERTS_BIF_PREP_TRAP` once the list exceeds the
//! remaining reductions) are a later task. These implementations finish the
//! whole list, using the same on-heap bump and single `HAlloc` as erts does
//! when the list fits in the budget.

use arinsal_term::{
    ConsHeapBuilder, HeapAlloc, HeapReservation, Term, TermBuilder, atoms, exact_eq, loose_eq,
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
    // OTP-29.1.1. The BIF interface cannot retain trap state, so each stage
    // runs to completion in this call while preserving the erts algorithm.
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

/// Reserve the remaining output area at the first retained LHS cell and fill
/// it in input order. Port of `erl_bif_lists.c:748-770` and `:881-916`, where
/// `HAllocX` and `result_cdr` build retained cells, OTP-29.1.1.
struct SubtractResultBuilder<'a> {
    heap: Option<&'a mut (dyn HeapAlloc + 'a)>,
    builder: Option<ConsHeapBuilder<'a, dyn HeapAlloc + 'a>>,
}

impl<'a> SubtractResultBuilder<'a> {
    fn new(heap: &'a mut (dyn HeapAlloc + 'a)) -> Self {
        Self {
            heap: Some(heap),
            builder: None,
        }
    }

    fn push(&mut self, value: Term, max_cells: usize) -> Result<(), BifError> {
        if self.builder.is_none() {
            let heap = self
                .heap
                .take()
                .expect("first retained cell owns the heap borrow");
            self.builder =
                Some(ConsHeapBuilder::new(heap, max_cells).map_err(|_| BifError::SystemLimit)?);
        }
        self.builder
            .as_mut()
            .expect("a retained cell owns its heap reservation")
            .push(value)
            .expect("the result reservation covers all remaining LHS cells");
        Ok(())
    }

    fn finish(self, tail: Term) -> Term {
        self.builder.map_or(tail, |builder| builder.finish(tail))
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
}
