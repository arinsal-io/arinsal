//! List BIFs. The per-element loops follow `erl_bif_lists.c` and `erl_bif_guard.c`.
//!
//! Reduction traps (`BIF_TRAP` / `ERTS_BIF_PREP_TRAP` once the list exceeds the
//! remaining reductions) are a later task. These implementations finish the
//! whole list, using the same on-heap bump and single `HAlloc` as erts does
//! when the list fits in the budget.

use arinsal_term::{HeapAlloc, HeapReservation, Term, atoms, exact_eq, loose_eq};

use crate::pure::{bool_term, integer, list, make_list, tuple_build};
use crate::{BifError, BifFn, Ctx};

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
    // Moved with the other list BIFs. The erts multiset (`SUBTRACT_STAGE_SET_*`)
    // is the long-list path and stays with the trapping work.
    let mut left = list(args[0])?;
    for removed in list(args[1])? {
        if let Some(index) = left.iter().position(|&item| exact_eq(item, removed)) {
            left.remove(index);
        }
    }
    Ok(make_list(ctx, left, Term::NIL))
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
